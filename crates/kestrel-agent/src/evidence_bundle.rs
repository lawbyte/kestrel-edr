//! Building one evidence bundle (blocking; runs on a blocking thread).
//!
//! Layout: a `KEB1` container ([`kestrel_common::evidence::container`])
//! sealed with `KSE1` ([`kestrel_common::seal`]) under the PC's bundle key
//! ([`EvidenceHost::bundle_key`]), context = the bundle id bytes, random
//! 8-byte nonce prefix. Entries in order: staged files, credential-store
//! copies, `capture.pcapng`, `manifest.json` (last, complete). Written to
//! `<bundles>/<id>.kev.partial` and renamed to `<id>.kev` once sealed; the
//! partial file is removed on any failure. The plaintext pcapng is always
//! deleted.
//!
//! Collection scope (hostile review 2026-10-25, H1): the agent runs as
//! SYSTEM and the journal's store reads come from open attempts, so a
//! stealer could otherwise make Kestrel copy files it could not read
//! itself. [`collect_refusal`] has the rules (tightened by the review of
//! the 1.1.7 integration, M1 / M2 / L2): files in the alerting process
//! user's own profile (the exact folder from the account's SID when the
//! platform resolves it, else the exact folder name) are copied; other
//! profiles and, for an unknown user, everything under `\Users\` never;
//! machine secrets ([`PROTECTED_PREFIXES`]) never; elsewhere only staged
//! files whose creation by the tree the sensor confirmed, never a
//! credential store (the journal sees open attempts, not successes). Every
//! decision is made on the path the file system resolves (8.3 short names
//! expanded, [`EvidenceHost::resolve_path`]) and checked again on the
//! opened handle's path before anything is read. Refused files stay listed
//! (metadata) with status `Error` and a plain detail.
//!
//! Deadlines (H2): the copy loop checks a cancel flag between chunks and
//! files (the agent sets it when the overall build deadline passes, then
//! abandons the thread), and each file copy stops at
//! [`Limits::file_deadline`] (recorded as `Truncated`). A single blocked
//! `open` / `read` call cannot be interrupted; the overall deadline covers
//! it. A cancelled build never renames its partial file into place.
//!
//! Disk (M2): when the platform reports free space, a bundle whose
//! estimated size would leave less than [`Limits::min_free_bytes`] free is
//! refused.
//!
//! Manifest size (M3): every path / image / detail string is clipped to
//! [`MAX_MANIFEST_STRING`] bytes; if the manifest is still over
//! `MAX_MANIFEST_BYTES`, list tails are dropped (entries without data
//! first) with a note. The bundle never fails for its manifest size.
//!
//! Never logs or returns file content; file names at most.

use kestrel_common::evidence::{
    container::ContainerWriter, entry_name, file_name, CopyStatus, EvidenceManifest,
    EvidencePolicy, EvidenceProcess, EvidenceTotals, FileCopy, PcapInfo, PcapStatus, SecretRead,
    StagedFile, MAX_ENTRY_BYTES, MAX_MANIFEST_BYTES, MAX_SECRET_BYTES, MAX_SECRET_FILE_BYTES,
    MAX_SKIPPED_LISTED, MAX_STAGED_BYTES, MAX_STAGED_FILES, MAX_STAGED_FILE_BYTES,
};
use kestrel_common::seal::SealWriter;
use kestrel_detect::evidence::JournalSnapshot;
use kestrel_platform::{CapturedFile, EvidenceHost, SourceError};
use std::io::{self, BufWriter, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Machine secrets never copied, whoever read them (driveless, lower-case):
/// machine / user crypto keys and DPAPI system keys, Credential Vault,
/// Wi-Fi profiles (with keys), OpenSSH host keys, Group Policy history
/// (cached GPP passwords), Windows Error Reporting dumps (memory of other
/// processes), the registry hives (SAM / SECURITY / SYSTEM), their repair
/// copies and the AD database.
pub const PROTECTED_PREFIXES: &[&str] = &[
    r"\programdata\microsoft\crypto\",
    r"\programdata\microsoft\vault\",
    r"\programdata\microsoft\wlansvc\",
    r"\programdata\microsoft\windows\wer\",
    r"\programdata\microsoft\group policy\",
    r"\programdata\ssh\",
    r"\windows\system32\config\",
    r"\windows\system32\microsoft\protect\",
    r"\windows\syswow64\config\",
    r"\windows\ntds\",
    r"\windows\repair\",
    // Review of the 1.1.7 integration (M2): service accounts' profiles
    // (LocalService / NetworkService credentials, DPAPI keys, tokens),
    // setup answer files (`unattend.xml` can hold local administrator
    // passwords), the security database, the SCCM client (network access
    // account policy), crash dumps of the kernel (all memory) and of
    // processes, shadow copies / restore points, and the paging,
    // hibernation and swap files (other processes' memory).
    r"\windows\serviceprofiles\",
    r"\windows\panther\",
    r"\windows\system32\sysprep\",
    r"\windows\security\",
    r"\windows\ccm\",
    r"\windows\minidump\",
    r"\windows\livekernelreports\",
    r"\windows\memory.dmp",
    r"\system volume information\",
    r"\pagefile.sys",
    r"\hiberfil.sys",
    r"\swapfile.sys",
];

/// Longest string kept in a manifest field (bytes); longer ones are cut
/// at a character boundary and end with `…`.
pub const MAX_MANIFEST_STRING: usize = 1024;

/// Detail of a file in another user's profile.
pub const OTHER_PROFILE: &str = "another user's profile; not collected";
/// Detail of a profile file when the process's user is unknown.
pub const UNKNOWN_USER: &str = "the process's user is unknown; user profiles are not collected";
/// Detail of a protected machine secret.
pub const PROTECTED_SECRET: &str = "a protected Windows secret; never collected";
/// Detail of a credential store outside the user's own profile (M2).
pub const OUTSIDE_PROFILE: &str =
    "outside the user's own profile; the sensor cannot tell whether the program could read it, so it was not collected";
/// Detail of a staged file outside the user's own profile whose creation
/// the sensor did not confirm (M2).
pub const NOT_CREATED: &str =
    "outside the user's own profile and not created by the program as far as the sensor saw; not collected";
/// Detail of a path still in 8.3 short-name form after resolution (M1).
pub const SHORT_NAME: &str = "an 8.3 short path that could not be resolved; not collected";

/// Profile folder name of a process user (`DOMAIN\name`, `name@domain`
/// or `name`), lower-case. `None` for SIDs and empty names.
pub fn profile_of(user: &str) -> Option<String> {
    let u = user.trim();
    let u = u.rsplit('\\').next().unwrap_or(u);
    let u = u.split('@').next().unwrap_or(u).trim().to_lowercase();
    if u.is_empty() || u.starts_with("s-1-") {
        return None;
    }
    Some(u)
}

/// Lower-case, `\`-separated, without `\\?\` and trailing `\`.
fn norm_full(path: &str) -> String {
    let p = path.trim().replace('/', "\\").to_lowercase();
    let p = p.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(p);
    p.trim_end_matches('\\').to_string()
}

/// Does a path component look like an 8.3 short name (`PROGRA~3`,
/// `ABCDEF~12.TXT`): a `~` followed by digits, then the end or a `.`?
pub fn has_short_component(path: &str) -> bool {
    path.split(['\\', '/']).any(|c| {
        let Some(i) = c.find('~') else {
            return false;
        };
        let tail = &c[i + 1..];
        let digits = tail.bytes().take_while(u8::is_ascii_digit).count();
        i > 0 && digits > 0 && (digits == tail.len() || tail.as_bytes()[digits] == b'.')
    })
}

/// Whose files a tree may have Kestrel copy (review of the 1.1.7
/// integration, M2 / L2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeScope {
    /// Profile folder name from the account name ([`profile_of`]).
    pub folder: Option<String>,
    /// The account's real profile folder from its SID
    /// ([`EvidenceHost::profile_dir`]), normalised (`c:\users\bob.corp`).
    pub dir: Option<String>,
}

impl TreeScope {
    pub fn new(user: Option<&str>, profile_dir: Option<&str>) -> Self {
        TreeScope {
            folder: user.and_then(profile_of),
            dir: profile_dir
                .map(norm_full)
                .filter(|d| d.len() > 3 && !has_short_component(d)),
        }
    }

    /// Is the normalised path `p` inside the tree user's own profile?
    /// `None` = the user is unknown.
    fn owns(&self, p: &str, users_folder: Option<&str>) -> Option<bool> {
        if let Some(d) = &self.dir {
            return Some(
                p.strip_prefix(d.as_str())
                    .is_some_and(|t| t.starts_with('\\')),
            );
        }
        // No SID-resolved folder: the exact folder name only (never a
        // `name.<suffix>` prefix match, which crosses users: local `bob`
        // vs `CORP\bob` in `bob.CORP`).
        let me = self.folder.as_deref()?;
        Some(users_folder.is_some_and(|f| f == me))
    }
}

/// What a candidate is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// A staged file; `confirmed` = the sensor saw a tree member create it.
    Staged { confirmed: bool },
    /// A credential store the tree opened (open attempts: the sensor does
    /// not see whether the open succeeded).
    Secret,
}

/// Why `path` must not be copied for a tree with `scope` (`None` = it may
/// be copied). `path` must be the resolved path ([`EvidenceHost::resolve_path`]);
/// a path still holding an 8.3 short component is refused (M1).
///
/// Rules (hostile reviews 2026-10-25, H1, and of the 1.1.7 integration,
/// M1 / M2 / L2): machine secrets ([`PROTECTED_PREFIXES`]) never; inside
/// the tree user's own profile (exact folder from the SID when known,
/// else the exact folder name) yes; another profile under `\Users\` never;
/// an unknown user nothing under `\Users\`; everywhere else (`\Users\Public`,
/// `ProgramData`, `\Windows\Temp`, other folders) only staged files whose
/// creation by the tree the sensor confirmed. Credential stores outside
/// the own profile are listed, never copied: the journal only knows open
/// attempts, and Kestrel copies as SYSTEM.
pub fn collect_refusal(path: &str, scope: &TreeScope, kind: Candidate) -> Option<&'static str> {
    let p = norm_full(path);
    let rest = if p.len() >= 2 && p.as_bytes()[1] == b':' {
        &p[2..]
    } else {
        p.as_str()
    };
    if PROTECTED_PREFIXES.iter().any(|x| rest.starts_with(x)) {
        return Some(PROTECTED_SECRET);
    }
    if has_short_component(&p) {
        return Some(SHORT_NAME);
    }
    let users_folder = rest
        .strip_prefix(r"\users\")
        .map(|a| a.split('\\').next().unwrap_or(""));
    match scope.owns(&p, users_folder) {
        Some(true) => return None,
        None if users_folder.is_some() => return Some(UNKNOWN_USER),
        _ => {}
    }
    if users_folder.is_some_and(|f| f != "public") {
        return Some(OTHER_PROFILE);
    }
    match kind {
        Candidate::Staged { confirmed: true } => None,
        Candidate::Staged { confirmed: false } => Some(NOT_CREATED),
        Candidate::Secret => Some(OUTSIDE_PROFILE),
    }
}

/// Scope decision for a journal path: on the path the file system
/// resolves it to ([`EvidenceHost::resolve_path`], 8.3 names expanded) when
/// the platform resolves it, else on the raw path (which then refuses short
/// names). A protected raw spelling is refused as well. Returns the refusal
/// and the path decided on.
fn decide(
    host: &dyn EvidenceHost,
    own: &OwnPaths,
    raw: &str,
    scope: &TreeScope,
    kind: Candidate,
) -> Decision {
    let resolved = host.resolve_path(raw);
    let eff = resolved.as_deref().unwrap_or(raw);
    if own.contains(raw) || own.contains(eff) {
        return Decision::Kestrel;
    }
    let why = collect_refusal(eff, scope, kind).or_else(|| {
        // The raw spelling must not be protected either (defence in depth).
        resolved
            .is_some()
            .then(|| collect_refusal(raw, scope, kind))
            .flatten()
            .filter(|w| *w == PROTECTED_SECRET)
    });
    match why {
        Some(w) => Decision::Refuse(w),
        None => Decision::Copy,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Copy,
    Kestrel,
    Refuse(&'static str),
}

/// Is this copy record a collection-scope refusal ([`collect_refusal`])?
fn is_scope_refusal(c: &FileCopy) -> bool {
    c.status == CopyStatus::Error
        && [
            OTHER_PROFILE,
            UNKNOWN_USER,
            PROTECTED_SECRET,
            OUTSIDE_PROFILE,
            NOT_CREATED,
            SHORT_NAME,
        ]
        .contains(&c.detail.as_str())
}

fn refused_copy(detail: &str) -> FileCopy {
    FileCopy {
        status: CopyStatus::Error,
        detail: detail.into(),
        ..Default::default()
    }
}

/// Cut `s` to at most [`MAX_MANIFEST_STRING`] bytes (character-safe).
fn clip(s: &mut String) {
    if s.len() <= MAX_MANIFEST_STRING {
        return;
    }
    let mut end = MAX_MANIFEST_STRING - '…'.len_utf8();
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s.push('…');
}

/// Extension of a finished bundle.
pub const BUNDLE_EXT: &str = "kev";
/// Extension of a bundle being written.
pub const PARTIAL_EXT: &str = "kev.partial";

/// Byte budgets of one bundle (tests shrink them).
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub staged_file: u64,
    pub staged_total: u64,
    pub staged_files: usize,
    pub secret_file: u64,
    pub secret_total: u64,
    /// One file copy stops after this long (`Truncated`).
    pub file_deadline: Duration,
    /// Refuse a bundle that would leave less free disk space than this
    /// (only when the platform reports free space).
    pub min_free_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            staged_file: MAX_STAGED_FILE_BYTES,
            staged_total: MAX_STAGED_BYTES,
            staged_files: MAX_STAGED_FILES,
            secret_file: MAX_SECRET_FILE_BYTES,
            secret_total: MAX_SECRET_BYTES,
            file_deadline: Duration::from_secs(120),
            min_free_bytes: 2 << 30,
        }
    }
}

/// Everything the builder needs (collected by the agent).
#[derive(Debug)]
pub struct BundleInput {
    pub bundle_id: Uuid,
    pub alert_id: Uuid,
    pub alert_ids: Vec<Uuid>,
    pub rule_id: String,
    pub hostname: String,
    pub agent_version: String,
    pub started_at: i64,
    pub window_start: i64,
    pub window_end: i64,
    pub parts: EvidencePolicy,
    pub processes: Vec<EvidenceProcess>,
    pub snapshot: JournalSnapshot,
    /// Connection capture result (status etc.); `None` = not part of the
    /// capture (policy off is reported as `Some(Disabled)` by the agent).
    pub pcap: Option<PcapInfo>,
    /// The plaintext pcapng to seal (deleted afterwards in every case).
    pub pcap_file: Option<CapturedFile>,
    pub limits: Limits,
    /// User of the alerting process (`DOMAIN\name`): profiles of other
    /// users are never copied.
    pub tree_user: Option<String>,
    /// Set by the agent when the build deadline passed: the build stops
    /// at the next chunk and fails.
    pub cancel: Arc<AtomicBool>,
}

/// A finished bundle.
#[derive(Debug, Clone)]
pub struct BuiltBundle {
    /// Unfiltered manifest (as stored inside the bundle).
    pub manifest: EvidenceManifest,
    pub path: PathBuf,
    /// Container (plaintext) bytes = what an upload delivers.
    pub size: u64,
    /// SHA-256 of the container bytes.
    pub sha256: String,
}

/// `<dir>/<id>.kev`.
pub fn bundle_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.{BUNDLE_EXT}"))
}

fn partial_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.{PARTIAL_EXT}"))
}

/// Lower-case, `\`-separated, trailing `\` (prefix comparison form).
fn norm_prefix(p: &str) -> String {
    let mut s = p.trim().replace('/', "\\").to_lowercase();
    let s2 = s
        .strip_prefix(r"\\?\")
        .map(str::to_string)
        .unwrap_or_else(|| s.clone());
    s = s2;
    if !s.ends_with('\\') {
        s.push('\\');
    }
    s
}

/// Paths Kestrel never collects: the platform's own prefixes and the
/// evidence folder itself.
pub struct OwnPaths(Vec<String>);

impl OwnPaths {
    pub fn new(host: &dyn EvidenceHost) -> Self {
        let mut v: Vec<String> = host
            .own_prefixes()
            .iter()
            .map(|p| norm_prefix(p))
            .filter(|p| p.len() > 1)
            .collect();
        v.push(norm_prefix(&host.evidence_dir().to_string_lossy()));
        OwnPaths(v)
    }

    pub fn contains(&self, path: &str) -> bool {
        let n = norm_prefix(path);
        self.0.iter().any(|p| n.starts_with(p.as_str()))
    }
}

/// `SourceError` → copy record (`size` = known size, if any).
fn source_error_copy(e: &SourceError) -> FileCopy {
    let (status, size, detail) = match e {
        SourceError::NotFound => (CopyStatus::Missing, 0, "gone before the copy".to_string()),
        SourceError::Link(d) => (CopyStatus::Link, 0, short(d)),
        SourceError::Locked => (
            CopyStatus::Locked,
            0,
            "locked by another program, not copied".to_string(),
        ),
        SourceError::TooLarge(n) => (CopyStatus::TooLarge, *n, "over the per-file limit".into()),
        SourceError::NotAFile => (CopyStatus::NotAFile, 0, "not a regular file".into()),
        SourceError::Other(d) => (CopyStatus::Error, 0, short(d)),
    };
    FileCopy {
        status,
        entry: None,
        size,
        sha256: None,
        detail,
    }
}

/// At most 200 characters of an error detail.
fn short(s: &str) -> String {
    let s = s.trim();
    if s.chars().count() <= 200 {
        s.to_string()
    } else {
        s.chars().take(200).collect::<String>() + "…"
    }
}

/// Reader that turns a read error (or the per-file deadline) into EOF and
/// remembers it (the entry is then closed cleanly and recorded as
/// truncated); a cancelled build fails the read.
struct ErrStop<R> {
    r: R,
    err: Option<String>,
    cancel: Arc<AtomicBool>,
    deadline: Instant,
}

impl<R: Read> Read for ErrStop<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(io::Error::other("the bundle build was cancelled"));
        }
        if self.err.is_some() {
            return Ok(0);
        }
        if Instant::now() >= self.deadline {
            self.err = Some("the copy took too long".into());
            return Ok(0);
        }
        loop {
            match self.r.read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    self.err = Some(e.kind().to_string());
                    return Ok(0);
                }
            }
        }
    }
}

type Sink = ContainerWriter<SealWriter<BufWriter<std::fs::File>>>;

/// Copy one source file into a new entry. `remaining` = bytes left in this
/// part's budget. `verify` re-checks the collection scope on the path the
/// opened handle resolves to ([`SourceFile::path`], M1) before anything is
/// read; a `Some` copy record is returned as is. Returns the copy record and
/// bytes added.
#[allow(clippy::too_many_arguments)]
fn copy_file(
    host: &dyn EvidenceHost,
    w: &mut Sink,
    name: &str,
    path: &str,
    per_file: u64,
    remaining: u64,
    lim: &Limits,
    cancel: &Arc<AtomicBool>,
    verify: &dyn Fn(&str) -> Option<FileCopy>,
) -> io::Result<(FileCopy, u64)> {
    if cancel.load(Ordering::Relaxed) {
        return Err(io::Error::other("the bundle build was cancelled"));
    }
    if remaining == 0 {
        return Ok((
            FileCopy {
                status: CopyStatus::BundleFull,
                detail: "the bundle size limit was reached".into(),
                size: host.file_size(path).unwrap_or(0),
                ..Default::default()
            },
            0,
        ));
    }
    let src = match host.open_source(path, per_file) {
        Ok(s) => s,
        Err(e) => return Ok((source_error_copy(&e), 0)),
    };
    if let Some(refused) = verify(&src.path) {
        return Ok((refused, 0));
    }
    if src.size > per_file {
        return Ok((
            FileCopy {
                status: CopyStatus::TooLarge,
                size: src.size,
                detail: "over the per-file limit".into(),
                ..Default::default()
            },
            0,
        ));
    }
    if src.size > remaining {
        return Ok((
            FileCopy {
                status: CopyStatus::BundleFull,
                size: src.size,
                detail: "the bundle size limit was reached".into(),
                ..Default::default()
            },
            0,
        ));
    }
    let cap = per_file.min(remaining);
    let mut r = ErrStop {
        r: src.reader,
        err: None,
        cancel: cancel.clone(),
        deadline: Instant::now() + lim.file_deadline,
    };
    let (n, sha, more) = w.entry_from_reader(name, &mut r, cap)?;
    let (status, detail) = match (&r.err, more) {
        (Some(e), _) => (
            CopyStatus::Truncated,
            format!("stopped after {n} bytes ({e})"),
        ),
        (None, true) if cap < per_file => (
            CopyStatus::Truncated,
            "the file grew while it was copied; cut at the bundle size limit".into(),
        ),
        (None, true) => (
            CopyStatus::Truncated,
            "the file grew past the per-file limit while it was copied".into(),
        ),
        (None, false) => (CopyStatus::Copied, String::new()),
    };
    Ok((
        FileCopy {
            status,
            entry: Some(name.to_string()),
            size: n,
            sha256: Some(sha),
            detail,
        },
        n,
    ))
}

fn kestrel_copy() -> FileCopy {
    FileCopy {
        status: CopyStatus::Kestrel,
        detail: "inside a Kestrel folder; never collected".into(),
        ..Default::default()
    }
}

/// Build and seal the bundle. Blocking.
pub fn build_bundle(
    host: &dyn EvidenceHost,
    input: BundleInput,
    bundles_dir: &Path,
) -> Result<BuiltBundle, String> {
    let pcap_plain = input.pcap_file.as_ref().map(|f| f.path.clone());
    let partial = partial_path(bundles_dir, input.bundle_id);
    let r = build_inner(host, input, bundles_dir, &partial);
    if let Some(p) = pcap_plain {
        let _ = std::fs::remove_file(p);
    }
    if r.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    r
}

fn build_inner(
    host: &dyn EvidenceHost,
    input: BundleInput,
    bundles_dir: &Path,
    partial: &Path,
) -> Result<BuiltBundle, String> {
    let cancelled = || {
        input
            .cancel
            .load(Ordering::Relaxed)
            .then(|| "the bundle build was cancelled".to_string())
    };
    let own = OwnPaths::new(host);
    let lim = input.limits;
    let parts = input.parts.clone();
    // L2: the account's real profile folder from its SID when the platform
    // knows it, else the exact folder name.
    let profile_dir = input.tree_user.as_deref().and_then(|u| host.profile_dir(u));
    let scope = TreeScope::new(input.tree_user.as_deref(), profile_dir.as_deref());
    // M1: decided on the resolved path; re-checked on the opened handle's
    // path in `copy_file`.
    let staged_kind = |c: &kestrel_detect::evidence::StagedCandidate| Candidate::Staged {
        confirmed: c.confirmed,
    };
    let verify_with = |kind: Candidate| {
        let own = &own;
        let scope = &scope;
        move |opened: &str| -> Option<FileCopy> {
            if own.contains(opened) {
                return Some(kestrel_copy());
            }
            collect_refusal(opened, scope, kind).map(refused_copy)
        }
    };

    // Free disk space: estimated size of what would be copied.
    if let Some(free) = host.free_bytes() {
        let mut est: u64 = 1 << 20;
        if parts.staged_files {
            let s: u64 = input
                .snapshot
                .staged
                .iter()
                .filter(|c| decide(host, &own, &c.path, &scope, staged_kind(c)) == Decision::Copy)
                .filter_map(|c| host.file_size(&c.path))
                .map(|n| n.min(lim.staged_file))
                .sum();
            est += s.min(lim.staged_total);
        }
        if parts.copies_secrets() {
            let s: u64 = input
                .snapshot
                .secrets
                .iter()
                .filter(|c| {
                    decide(host, &own, &c.path, &scope, Candidate::Secret) == Decision::Copy
                })
                .filter_map(|c| host.file_size(&c.path))
                .map(|n| n.min(lim.secret_file))
                .sum();
            est += s.min(lim.secret_total);
        }
        est += input.pcap_file.as_ref().map_or(0, |f| f.bytes);
        if free < est.saturating_add(lim.min_free_bytes) {
            return Err(format!(
                "not enough free disk space for the bundle (about {} MB needed, {} MB free, {} GB are kept free)",
                est >> 20,
                free >> 20,
                lim.min_free_bytes >> 30
            ));
        }
    }
    let key = host
        .bundle_key()
        .map_err(|e| format!("bundle key unavailable: {}", short(&e)))?;
    std::fs::create_dir_all(bundles_dir).map_err(|e| format!("evidence folder: {e}"))?;
    let _ = std::fs::remove_file(partial);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(partial)
        .map_err(|e| format!("cannot create the bundle file: {e}"))?;
    let nonce: [u8; 8] = rand::random();
    let seal = SealWriter::new(
        BufWriter::with_capacity(1 << 20, file),
        &key,
        nonce,
        input.bundle_id.as_bytes(),
    )
    .map_err(|e| format!("seal: {e}"))?;
    let mut w = ContainerWriter::new(seal).map_err(|e| format!("container: {e}"))?;
    let cancel = input.cancel.clone();
    let io = |e: io::Error| {
        if cancel.load(Ordering::Relaxed) {
            "the bundle build was cancelled".to_string()
        } else {
            format!("writing the bundle failed: {e}")
        }
    };

    let mut totals = EvidenceTotals {
        staged_unlisted: input
            .snapshot
            .staged_unlisted
            .saturating_add(input.snapshot.staged_evicted),
        ..Default::default()
    };
    let mut notes: Vec<String> = Vec::new();
    let mut refused = 0usize;

    // ---- staged files
    let mut staged: Vec<StagedFile> = Vec::new();
    if parts.staged_files {
        let mut remaining = lim.staged_total;
        let mut copied_files = 0usize;
        for (i, c) in input.snapshot.staged.iter().enumerate() {
            let decision = decide(host, &own, &c.path, &scope, staged_kind(c));
            let copy = if decision == Decision::Kestrel {
                kestrel_copy()
            } else if let Decision::Refuse(why) = decision {
                refused_copy(why)
            } else if copied_files >= lim.staged_files {
                FileCopy {
                    status: CopyStatus::BundleFull,
                    detail: "the bundle file limit was reached".into(),
                    ..Default::default()
                }
            } else {
                let name = entry_name("staged", i + 1, &c.path);
                let (copy, n) = copy_file(
                    host,
                    &mut w,
                    &name,
                    &c.path,
                    lim.staged_file,
                    remaining,
                    &lim,
                    &cancel,
                    &verify_with(staged_kind(c)),
                )
                .map_err(io)?;
                remaining -= n.min(remaining);
                if copy.status.has_data() {
                    copied_files += 1;
                }
                copy
            };
            if is_scope_refusal(&copy) {
                refused += 1;
            }
            tracing::debug!(file = file_name(&c.path), status = ?copy.status, "evidence: staged file");
            staged.push(StagedFile {
                path: c.path.clone(),
                written_at: c.written_at,
                op: c.op,
                process_guid: c.guid.clone(),
                image: c.image.clone(),
                copy,
            });
        }
        // Skipped files beyond MAX_SKIPPED_LISTED are only counted.
        let mut skipped_seen = 0usize;
        let before = staged.len();
        staged.retain(|s| {
            let skipped = matches!(
                s.copy.status,
                CopyStatus::Missing
                    | CopyStatus::Kestrel
                    | CopyStatus::Link
                    | CopyStatus::NotAFile
                    | CopyStatus::Error
            );
            if !skipped {
                return true;
            }
            skipped_seen += 1;
            skipped_seen <= MAX_SKIPPED_LISTED
        });
        let dropped = before - staged.len();
        totals.staged_unlisted += dropped as u32;
        if dropped > 0 {
            notes.push(format!(
                "{dropped} skipped file(s) (missing, links, Kestrel folders, errors) beyond the first {MAX_SKIPPED_LISTED} were not listed."
            ));
        }
        totals.staged_listed = staged.len() as u32;
        totals.staged_copied = staged.iter().filter(|s| s.copy.status.has_data()).count() as u32;
        totals.staged_bytes = staged
            .iter()
            .filter(|s| s.copy.status.has_data())
            .map(|s| s.copy.size)
            .sum();
        if input.snapshot.staged_unlisted > 0 {
            notes.push(format!(
                "{} candidate file(s) beyond the {MAX_STAGED_FILES}-file cap were not listed.",
                input.snapshot.staged_unlisted
            ));
        }
        if input.snapshot.staged_evicted > 0 {
            notes.push(format!(
                "{} written file(s) were forgotten before the capture because the process wrote too many files (low-value files such as caches and libraries are forgotten first).",
                input.snapshot.staged_evicted
            ));
        }
        let full = staged
            .iter()
            .filter(|s| s.copy.status == CopyStatus::BundleFull)
            .count();
        if full > 0 {
            notes.push(format!(
                "The staged-file size limit ({} MB) was reached: {full} file(s) are listed but not copied.",
                lim.staged_total >> 20
            ));
        }
        notes.push(
            "Staged files are copies taken at the end of the follow-up window; files written by appending to an existing file are not seen by the sensor.".into(),
        );
    }

    // ---- credential stores
    let mut secrets: Vec<SecretRead> = Vec::new();
    if parts.secrets_list {
        let copy_secrets = parts.copies_secrets();
        let mut remaining = lim.secret_total;
        for (i, s) in input.snapshot.secrets.iter().enumerate() {
            let mut s = s.clone();
            let decision = decide(host, &own, &s.path, &scope, Candidate::Secret);
            if decision == Decision::Kestrel {
                s.copy = copy_secrets.then(kestrel_copy);
            } else if let Decision::Refuse(why) = decision {
                // Listed (useful metadata), never copied or even sized.
                refused += 1;
                s.size = None;
                s.copy = Some(refused_copy(why));
            } else if copy_secrets {
                let name = entry_name("secrets", i + 1, &s.path);
                let (copy, n) = copy_file(
                    host,
                    &mut w,
                    &name,
                    &s.path,
                    lim.secret_file,
                    remaining,
                    &lim,
                    &cancel,
                    &verify_with(Candidate::Secret),
                )
                .map_err(io)?;
                remaining -= n.min(remaining);
                if is_scope_refusal(&copy) {
                    refused += 1;
                    s.size = None;
                } else {
                    s.size = if copy.status.has_data() || copy.size > 0 {
                        Some(copy.size)
                    } else {
                        host.file_size(&s.path)
                    };
                }
                s.copy = Some(copy);
            } else {
                s.size = host.file_size(&s.path);
                s.copy = None;
            }
            secrets.push(s);
        }
        totals.secrets_listed = secrets.len() as u32;
        let data: Vec<&FileCopy> = secrets
            .iter()
            .filter_map(|s| s.copy.as_ref())
            .filter(|c| c.status.has_data())
            .collect();
        totals.secrets_copied = data.len() as u32;
        totals.secret_bytes = data.iter().map(|c| c.size).sum();
        let locked = secrets
            .iter()
            .filter(|s| {
                s.copy
                    .as_ref()
                    .is_some_and(|c| c.status == CopyStatus::Locked)
            })
            .count();
        if locked > 0 {
            notes.push(format!(
                "{locked} credential store(s) were locked by their application (e.g. a running browser holds its Cookies database) and could not be copied."
            ));
        }
        if input.snapshot.secrets_unlisted > 0 {
            notes.push(format!(
                "{} credential store(s) beyond the listing cap were not listed.",
                input.snapshot.secrets_unlisted
            ));
        }
        if !copy_secrets {
            notes.push(
                "Credential stores are listed only (copies are turned off by policy).".into(),
            );
        }
    }

    // ---- connection capture
    let mut pcap = input.pcap.clone();
    if let (Some(info), Some(f)) = (pcap.as_mut(), input.pcap_file.as_ref()) {
        match std::fs::File::open(&f.path) {
            Ok(file) => {
                let mut r = ErrStop {
                    r: io::BufReader::new(file),
                    err: None,
                    cancel: cancel.clone(),
                    deadline: Instant::now() + lim.file_deadline,
                };
                let (n, sha, more) = w
                    .entry_from_reader("capture.pcapng", &mut r, MAX_ENTRY_BYTES)
                    .map_err(io)?;
                info.bytes = n;
                info.sha256 = Some(sha);
                info.entry = Some("capture.pcapng".into());
                info.truncated = f.truncated || more;
                if let Some(e) = r.err {
                    info.detail =
                        short(&format!("reading the capture failed after {n} bytes ({e})"));
                }
                totals.pcap_bytes = n;
            }
            Err(e) => {
                info.status = PcapStatus::Failed;
                info.detail = short(&format!("capture file unreadable: {}", e.kind()));
            }
        }
    }
    if let Some(info) = pcap.as_ref() {
        if info.entry.is_some() {
            notes.push(
                "The connection capture matches the listed remote addresses for every program on this PC (shared addresses such as CDNs may include other apps' traffic); TLS and VPN traffic stays encrypted; loopback traffic is not captured; connections opened after the capture started may be missing.".into(),
            );
            if info.truncated {
                notes.push("The connection capture reached its size limit; the oldest packets were overwritten.".into());
            }
        }
    }
    if input.snapshot.net_excluded > 0 && parts.pcap {
        notes.push(format!(
            "{} connection(s) to Windows infrastructure ports (DNS, Kerberos, RPC, NetBIOS, LDAP, SMB) were not used as capture filters.",
            input.snapshot.net_excluded
        ));
    }
    if refused > 0 {
        notes.push(format!(
            "{refused} file(s) in other users' profiles, in protected Windows locations or outside the user's own profile (credential stores, and files the program did not create) are listed but were not collected."
        ));
    }
    totals.data_bytes = totals.staged_bytes + totals.secret_bytes + totals.pcap_bytes;
    if let Some(e) = cancelled() {
        return Err(e);
    }

    let mut manifest = EvidenceManifest {
        format: 1,
        bundle_id: input.bundle_id,
        alert_id: input.alert_id,
        alert_ids: input.alert_ids,
        rule_id: input.rule_id,
        hostname: input.hostname,
        agent_version: input.agent_version,
        started_at: input.started_at,
        window_start: input.window_start,
        window_end: input.window_end,
        completed_at: kestrel_common::now_ms(),
        parts,
        processes: input.processes,
        staged,
        secrets,
        pcap,
        totals,
        notes,
    };
    let json = fit_manifest(&mut manifest)?;
    w.entry("manifest.json", &json).map_err(io)?;
    let seal = w.finish().map_err(io)?;
    let (buf, sealed) = seal.finish().map_err(io)?;
    let file = buf
        .into_inner()
        .map_err(|e| format!("writing the bundle failed: {}", e.error()))?;
    file.sync_all().map_err(io)?;
    drop(file);
    if let Some(e) = cancelled() {
        return Err(e);
    }
    let path = bundle_path(bundles_dir, manifest.bundle_id);
    std::fs::rename(partial, &path).map_err(|e| format!("finishing the bundle failed: {e}"))?;
    Ok(BuiltBundle {
        manifest,
        path,
        size: sealed.plaintext_len,
        sha256: sealed.sha256,
    })
}

/// Clip strings and, if needed, drop list tails until the manifest fits
/// `MAX_MANIFEST_BYTES`. Returns its JSON.
pub fn fit_manifest(m: &mut EvidenceManifest) -> Result<Vec<u8>, String> {
    fit_manifest_to(m, MAX_MANIFEST_BYTES)
}

/// [`fit_manifest`] with an explicit limit (tests).
pub fn fit_manifest_to(m: &mut EvidenceManifest, max: u64) -> Result<Vec<u8>, String> {
    for p in &mut m.processes {
        clip(&mut p.image);
    }
    for s in &mut m.staged {
        clip(&mut s.path);
        clip(&mut s.image);
        clip(&mut s.copy.detail);
    }
    for s in &mut m.secrets {
        clip(&mut s.path);
        clip(&mut s.image);
        clip(&mut s.store);
        clip(&mut s.noun);
        if let Some(c) = s.copy.as_mut() {
            clip(&mut c.detail);
        }
    }
    if let Some(p) = m.pcap.as_mut() {
        clip(&mut p.detail);
    }
    for n in &mut m.notes {
        clip(n);
    }
    let mut dropped = 0usize;
    loop {
        if dropped > 0 {
            m.notes.push(format!(
                "{dropped} list entries were left out to keep the manifest within its size limit."
            ));
        }
        let json = serde_json::to_vec(&*m).map_err(|e| format!("manifest: {e}"))?;
        if json.len() as u64 <= max {
            return Ok(json);
        }
        if dropped > 0 {
            m.notes.pop();
        }
        // Drop about a tenth per round: entries without data first.
        let total = m.staged.len() + m.secrets.len() + m.processes.len();
        let step = (total / 10).max(1);
        let mut removed = 0usize;
        while removed < step {
            if let Some(i) = m.staged.iter().rposition(|s| !s.copy.status.has_data()) {
                m.staged.remove(i);
            } else if let Some(i) = m
                .secrets
                .iter()
                .rposition(|s| !s.copy.as_ref().is_some_and(|c| c.status.has_data()))
            {
                m.secrets.remove(i);
            } else if m.staged.pop().is_some() || m.secrets.pop().is_some() {
            } else if m.processes.len() > 1 {
                m.processes.pop();
            } else {
                // Only clipped strings and counters left: cannot happen
                // with the real limit.
                return Err("the manifest is over its size limit".into());
            }
            removed += 1;
        }
        dropped += removed;
        m.totals.staged_listed = m.staged.len() as u32;
        m.totals.secrets_listed = m.secrets.len() as u32;
    }
}

/// Read a whole bundle file back (tests, diagnostics): container bytes.
pub fn open_bundle(path: &Path, key: &[u8; 32], bundle_id: Uuid) -> io::Result<Vec<u8>> {
    let f = std::fs::File::open(path)?;
    let mut r =
        kestrel_common::seal::SealReader::new(io::BufReader::new(f), key, bundle_id.as_bytes())?;
    let mut out = Vec::new();
    r.read_to_end(&mut out)?;
    Ok(out)
}
