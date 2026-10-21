//! Remote file manager: every `FileOp` implemented on top of the platform's
//! [`RemoteFs`] (portable, unit-tested on any OS).
//!
//! **Pre-checks** (defence in depth, on the admin-supplied path):
//! 1. `kestrel_common::remote::validate_remote_path` (absolute `X:\…`, no
//!    `.`/`..`, no streams, no UNC/device paths);
//! 2. `RemoteFs::check_path` (Windows: no network drives);
//! 3. the target (its deepest existing ancestor canonicalised, so 8.3 names,
//!    junctions and symlinks are resolved, then the remaining components
//!    re-appended) must resolve to a local drive, must not be equal to or
//!    inside a protected root or a blocked path, and for rename, delete and
//!    upload targets must not be an ancestor of one either.
//!
//! **Enforcement at use** (security review H1 / M3 / M4): every open,
//! create, rename, delete, mkdir and folder enumeration goes through the
//! platform's hardened [`RemoteFs`] operations with a guard ([`Rules`]) that
//! sees the *final* path of each object the platform is about to act on
//! (Windows: `GetFinalPathNameByHandleW` of the handle it then uses). The
//! guard applies the same rules (local drive only, protected roots, blocked
//! paths, ancestors for rename / delete / overwrite), so a folder swapped
//! for a junction after the pre-check is still refused. The only direct
//! `std::fs` calls on admin paths are metadata reads of entries inside a
//! folder the platform already verified (listing / stat).
//!
//! Transfers are per live session ([`FsSession`]): a download keeps the file
//! open and hashes as it reads sequentially; an upload writes a temp file
//! `.<name>.kestrel-upload-<hex>.tmp` (created exclusively) in the verified
//! target folder and renames it over the target only after size + SHA-256
//! match. The temp file is deleted (through the platform, with the guard)
//! on abort, error, idle timeout and when the session is dropped.
//!
//! Never logs file contents; paths only at debug level.

// The error type is the reply sent to the server (`FileReply::Error`);
// boxing it would only add an allocation on a cold path.
#![allow(clippy::result_large_err)]

use base64::Engine as _;
use kestrel_common::remote::{
    file_name_of, parent_of, path_is_within, validate_remote_path, FileEntry, FileKind, FileOp,
    FileReply, RemoteErrorCode, FILE_CHUNK_MAX, LIST_MAX_ENTRIES, LIVE_MAX_MESSAGE, TRANSFER_MAX,
};
use kestrel_platform::{FsOpError, RemoteFs};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

/// JSON budget for one `List` reply (stays well below `LIVE_MAX_MESSAGE`
/// with the envelope around it).
const LIST_JSON_BUDGET: usize = LIVE_MAX_MESSAGE - 64 * 1024;

type OpResult<T> = Result<T, FileReply>;

fn err<T>(code: RemoteErrorCode, msg: impl Into<String>) -> OpResult<T> {
    Err(FileReply::error(code, msg))
}

/// Map an I/O error to a reply (short message, never file contents).
pub fn io_reply(e: &io::Error) -> FileReply {
    let code = match e.kind() {
        io::ErrorKind::NotFound => RemoteErrorCode::NotFound,
        io::ErrorKind::PermissionDenied => RemoteErrorCode::AccessDenied,
        io::ErrorKind::AlreadyExists => RemoteErrorCode::AlreadyExists,
        _ => RemoteErrorCode::Io,
    };
    let mut msg = e.to_string();
    if msg.len() > 200 {
        let mut cut = 200;
        while !msg.is_char_boundary(cut) {
            cut -= 1;
        }
        msg.truncate(cut);
    }
    FileReply::error(code, msg)
}

fn io_err<T>(e: io::Error) -> OpResult<T> {
    Err(io_reply(&e))
}

/// Map a platform error (refusal codes pass through).
fn op_reply(e: FsOpError) -> FileReply {
    match e {
        FsOpError::Refused { code, message } => FileReply::error(code, message),
        FsOpError::Io(e) => io_reply(&e),
    }
}

/// What the effective profile allows beyond the operation class
/// (computed by the live gate).
#[derive(Debug, Clone, Default)]
pub struct OpPolicy {
    /// The profile's `blocked_paths`.
    pub blocked: Vec<String>,
    /// Refusal for an upload that would overwrite an existing file
    /// (overwrite = destroy: needs `allow_delete` as well as
    /// `allow_upload`). `None` = overwriting is allowed.
    pub overwrite_refusal: Option<(RemoteErrorCode, String)>,
}

impl OpPolicy {
    /// Nothing blocked, overwrite allowed (tests).
    pub fn open() -> OpPolicy {
        OpPolicy::default()
    }
}

// ---------------------------------------------------------------- sessions

/// Transfer state of one live session.
#[derive(Default)]
pub struct FsSession {
    download: Option<Download>,
    upload: Option<Upload>,
}

struct Download {
    /// Normalised Windows path the download was opened with.
    path: String,
    file: File,
    size: u64,
    pos: u64,
    hasher: Sha256,
}

struct Upload {
    fs: Arc<dyn RemoteFs>,
    rules: Arc<Rules>,
    target_win: String,
    /// Final path of the target (verified folder + name).
    target: PathBuf,
    tmp: PathBuf,
    file: Option<File>,
    size: u64,
    written: u64,
    hasher: Sha256,
    last_chunk: Instant,
    committed: bool,
    /// The target existed at `WriteBegin` (an overwrite).
    overwrite_allowed: bool,
}

impl Drop for Upload {
    fn drop(&mut self) {
        // Close before deleting (Windows refuses to delete an open file).
        self.file.take();
        if !self.committed {
            let rules = self.rules.clone();
            let guard = move |p: &Path| rules.check(p, false);
            match self.fs.remove(&self.tmp, false, &guard) {
                Ok(_) => tracing::debug!(tmp = %self.tmp.display(), "upload temp file removed"),
                Err(FsOpError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => tracing::warn!("could not remove an upload temp file: {e}"),
            }
        }
    }
}

impl FsSession {
    /// A download or upload is open (the session's worker must stay alive).
    pub fn has_transfer(&self) -> bool {
        self.download.is_some() || self.upload.is_some()
    }

    /// When the open upload expires for lack of chunks.
    pub fn upload_deadline(&self, idle: Duration) -> Option<Instant> {
        self.upload.as_ref().map(|u| u.last_chunk + idle)
    }

    /// Abort an upload idle for `idle` or longer. Returns true if aborted.
    pub fn expire_idle(&mut self, now: Instant, idle: Duration) -> bool {
        if self
            .upload
            .as_ref()
            .is_some_and(|u| now.duration_since(u.last_chunk) >= idle)
        {
            tracing::info!("remote upload aborted: no data for {idle:?}");
            self.upload = None;
            return true;
        }
        false
    }

    /// Drop every transfer (temp files deleted, files closed).
    pub fn abort_all(&mut self) {
        self.upload = None;
        self.download = None;
    }
}

// ------------------------------------------------------------ path rules

/// Lower-cased path components with any verbatim / NT prefix (`\\?\`,
/// `\??\`, `\\?\UNC\`) normalised, for component-wise comparison.
fn components(p: &Path) -> Vec<String> {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = if let Some(rest) = s
        .strip_prefix(r"\\?\UNC\")
        .or_else(|| s.strip_prefix(r"\??\UNC\"))
    {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\").or_else(|| s.strip_prefix(r"\??\")) {
        rest.to_string()
    } else {
        s
    };
    s.split('\\')
        .filter(|c| !c.is_empty())
        .map(|c| c.to_lowercase())
        .collect()
}

/// Does a final (resolved) path live on a local drive? Windows: `X:\…`,
/// optionally behind `\\?\` / `\??\`; anything UNC (`\\server`, `\\?\UNC\`),
/// `\Device\…` (e.g. `\Device\Mup`) or another verbatim form
/// (`\\?\Volume{…}`, `\\.\…`) is refused (M3). Elsewhere (simulator / tests
/// on Unix): an absolute path that is not `//host` style.
pub fn is_local_final(p: &Path) -> bool {
    let s = p.to_string_lossy();
    if cfg!(windows) {
        let s = s.replace('/', "\\");
        let rest = s
            .strip_prefix(r"\\?\")
            .or_else(|| s.strip_prefix(r"\??\"))
            .unwrap_or(&s);
        let b = rest.as_bytes();
        b.len() >= 2
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && (b.len() == 2 || b[2] == b'\\')
    } else {
        s.starts_with('/') && !s.starts_with("//")
    }
}

/// Canonicalise the deepest existing ancestor of `p` (resolving 8.3 names,
/// junctions and symlinks) and re-append the remaining components.
fn canonical_lenient(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    let mut rest: Vec<std::ffi::OsString> = vec![];
    loop {
        if let Ok(c) = fs::canonicalize(&cur) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return out;
        }
        let name = cur.file_name().map(|n| n.to_os_string());
        match (name, cur.parent()) {
            (Some(n), Some(parent)) if !parent.as_os_str().is_empty() => {
                rest.push(n);
                cur = parent.to_path_buf();
            }
            _ => return p.to_path_buf(),
        }
    }
}

fn starts_with(path: &[String], prefix: &[String]) -> bool {
    !prefix.is_empty() && path.len() >= prefix.len() && path[..prefix.len()] == *prefix
}

/// Protected roots and blocked paths in canonical component form: the rule
/// set both the pre-checks and the platform guard apply.
pub struct Rules {
    /// Canonical (or literal, when missing) protected roots.
    protected: Vec<Vec<String>>,
    /// Blocked prefixes: (as configured, canonical local components).
    blocked: Vec<(String, Vec<String>)>,
}

impl Rules {
    pub fn new(fs_: &dyn RemoteFs, blocked: &[String]) -> Rules {
        let protected = fs_
            .protected_roots()
            .iter()
            .map(|r| match fs::canonicalize(r) {
                Ok(c) => components(&c),
                Err(_) => components(r),
            })
            .collect();
        let blocked = blocked
            .iter()
            .filter(|b| !b.trim().is_empty())
            .filter_map(|b| {
                let bw = validate_remote_path(b).ok()?;
                Some((
                    b.clone(),
                    components(&canonical_lenient(&fs_.local_path(&bw))),
                ))
            })
            .collect();
        Rules { protected, blocked }
    }

    /// Apply the rules to a final path. `ancestors`: also refuse ancestors
    /// of protected roots and blocked paths (rename, delete, overwrite).
    pub fn check(&self, fin: &Path, ancestors: bool) -> Result<(), FsOpError> {
        if !is_local_final(fin) {
            return Err(FsOpError::refused(
                RemoteErrorCode::InvalidPath,
                "the path resolves to a network or device path",
            ));
        }
        let t = components(fin);
        for r in &self.protected {
            if starts_with(&t, r) {
                return Err(FsOpError::refused(
                    RemoteErrorCode::ProtectedPath,
                    "Kestrel's own folders cannot be accessed remotely",
                ));
            }
            if ancestors && starts_with(r, &t) {
                return Err(FsOpError::refused(
                    RemoteErrorCode::ProtectedPath,
                    "this folder contains Kestrel's own folders",
                ));
            }
        }
        for (b, bc) in &self.blocked {
            if starts_with(&t, bc) || (ancestors && starts_with(bc, &t)) {
                return Err(FsOpError::refused(
                    RemoteErrorCode::BlockedPath,
                    format!("blocked by this device's remote-access profile ({b})"),
                ));
            }
        }
        Ok(())
    }
}

/// A path that passed every pre-check.
#[derive(Debug, Clone)]
pub struct Resolved {
    /// Normalised Windows path (`C:\a\b`).
    pub win: String,
    /// Local path for the platform.
    pub local: PathBuf,
}

impl Resolved {
    fn is_drive_root(&self) -> bool {
        self.win.len() == 3 && self.win.ends_with(":\\")
    }
}

/// Validate, platform-check and rule-check a remote path. `ancestors`: also
/// refuse ancestors of protected roots and blocked paths (rename, delete,
/// upload target).
pub fn resolve(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    raw: &str,
    ancestors: bool,
    blocked: &[String],
) -> OpResult<Resolved> {
    let win = match validate_remote_path(raw) {
        Ok(w) => w,
        Err(e) => return err(RemoteErrorCode::InvalidPath, e.0),
    };
    if let Err(m) = fs_.check_path(&win) {
        return err(RemoteErrorCode::InvalidPath, m);
    }
    // Blocked prefixes on the validated path itself (and, for destructive
    // operations, its descendants being blocked).
    for b in blocked.iter().filter(|b| !b.trim().is_empty()) {
        let bw = validate_remote_path(b).unwrap_or_else(|_| b.clone());
        if path_is_within(&win, &bw) || (ancestors && path_is_within(&bw, &win)) {
            tracing::debug!(path = %win, "remote file manager: blocked path refused");
            return err(
                RemoteErrorCode::BlockedPath,
                format!("blocked by this device's remote-access profile ({b})"),
            );
        }
    }
    let local = fs_.local_path(&win);
    if let Err(e) = rules.check(&canonical_lenient(&local), ancestors) {
        tracing::debug!(path = %win, "remote file manager: path refused by the rules");
        return Err(op_reply(e));
    }
    Ok(Resolved { win, local })
}

/// A drive root (`X:` + backslash) after validation: never renamed, deleted
/// or uploaded to (checked before the protected-folder rule).
fn is_drive_root_raw(raw: &str) -> bool {
    validate_remote_path(raw).is_ok_and(|w| w.len() == 3)
}

fn join_win(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

// -------------------------------------------------------------- metadata

fn attributes_of(m: &fs::Metadata) -> u32 {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes()
    }
    #[cfg(not(windows))]
    {
        let _ = m;
        0
    }
}

fn is_reparse(m: &fs::Metadata) -> bool {
    m.file_type().is_symlink() || attributes_of(m) & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn entry_from(m: &fs::Metadata, name: String, path: String) -> FileEntry {
    let ft = m.file_type();
    let attributes = attributes_of(m);
    let kind = if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Link
    };
    let hidden = if cfg!(windows) {
        attributes & FILE_ATTRIBUTE_HIDDEN != 0
    } else {
        name.starts_with('.')
    };
    let modified = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64);
    FileEntry {
        name,
        path,
        kind,
        size: if ft.is_file() { m.len() } else { 0 },
        modified,
        attributes,
        hidden,
        readonly: m.permissions().readonly() || attributes & FILE_ATTRIBUTE_READONLY != 0,
        reparse: is_reparse(m),
        free_bytes: None,
        total_bytes: None,
        label: None,
    }
}

// ------------------------------------------------------------- operations

/// Execute one file operation for `sess`. Exactly one reply.
pub fn handle(
    fs_: &Arc<dyn RemoteFs>,
    sess: &mut FsSession,
    op: FileOp,
    pol: &OpPolicy,
) -> FileReply {
    let name = op.name();
    let f: &dyn RemoteFs = &**fs_;
    let rules = Arc::new(Rules::new(f, &pol.blocked));
    let b = &pol.blocked[..];
    let r = match op {
        FileOp::List { path } => list(f, &rules, &path, LIST_MAX_ENTRIES, b),
        FileOp::Stat { path } => stat(f, &rules, &path, b),
        FileOp::ReadChunk { path, offset, len } => {
            read_chunk(f, &rules, sess, &path, offset, len, b)
        }
        FileOp::WriteBegin { path, size } => write_begin(fs_, &rules, sess, &path, size, pol),
        FileOp::WriteChunk { offset, data_b64 } => write_chunk(sess, offset, &data_b64),
        FileOp::WriteEnd { sha256 } => write_end(f, sess, &sha256, b),
        FileOp::WriteAbort => {
            sess.upload = None;
            Ok(FileReply::Done { count: 0 })
        }
        FileOp::Rename {
            from,
            to,
            overwrite,
        } => rename(f, &rules, &from, &to, overwrite, pol),
        FileOp::Delete { path, recursive } => delete(f, &rules, &path, recursive, b),
        FileOp::Mkdir { path } => mkdir(f, &rules, &path, b),
        FileOp::Unknown => err(
            RemoteErrorCode::InvalidOperation,
            "operation not supported by this agent",
        ),
    };
    match r {
        Ok(rep) => rep,
        Err(e) => {
            if let FileReply::Error { code, .. } = &e {
                tracing::debug!(op = name, code = code.as_str(), "remote file op failed");
            }
            e
        }
    }
}

/// `List` with an explicit entry cap (tests use a small one).
pub fn list(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    path: &str,
    max_entries: usize,
    blocked: &[String],
) -> OpResult<FileReply> {
    if path.trim().is_empty() {
        return Ok(FileReply::List {
            path: String::new(),
            entries: fs_.drives(),
            truncated: false,
        });
    }
    let r = resolve(fs_, rules, path, false, blocked)?;
    let guard = |p: &Path| rules.check(p, false);
    let dir = fs_.verify_dir(&r.local, &guard).map_err(op_reply)?;
    // Enumerate the verified folder; entries' metadata never follows links.
    let rd = fs::read_dir(&dir).or_else(io_err)?;
    let mut entries = vec![];
    let mut truncated = false;
    let mut budget = LIST_JSON_BUDGET.saturating_sub(r.win.len() * 2 + 256);
    for de in rd {
        let Ok(de) = de else { continue };
        let Ok(m) = fs::symlink_metadata(de.path()) else {
            continue;
        };
        let name = de.file_name().to_string_lossy().into_owned();
        let e = entry_from(&m, name.clone(), join_win(&r.win, &name));
        let cost = serde_json::to_vec(&e).map(|v| v.len() + 1).unwrap_or(512);
        if entries.len() >= max_entries || cost > budget {
            truncated = true;
            break;
        }
        budget -= cost;
        entries.push(e);
    }
    Ok(FileReply::List {
        path: r.win,
        entries,
        truncated,
    })
}

/// Final path of `win`'s parent folder (verified by the platform) joined
/// with its name, after the guard approved that final path.
fn verified_child(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    win: &str,
    ancestors: bool,
) -> OpResult<PathBuf> {
    let Some(parent_win) = parent_of(win) else {
        return err(RemoteErrorCode::InvalidPath, "path has no parent folder");
    };
    let guard = |p: &Path| rules.check(p, false);
    let parent = match fs_.verify_dir(&fs_.local_path(&parent_win), &guard) {
        Ok(p) => p,
        Err(FsOpError::Io(e)) if e.kind() == io::ErrorKind::NotFound => {
            return err(RemoteErrorCode::NotFound, "the folder does not exist")
        }
        Err(e) => return Err(op_reply(e)),
    };
    let child = parent.join(file_name_of(win));
    rules.check(&child, ancestors).map_err(op_reply)?;
    Ok(child)
}

fn stat(fs_: &dyn RemoteFs, rules: &Rules, path: &str, blocked: &[String]) -> OpResult<FileReply> {
    let r = resolve(fs_, rules, path, false, blocked)?;
    if r.is_drive_root() {
        return match fs_
            .drives()
            .into_iter()
            .find(|d| d.path.eq_ignore_ascii_case(&r.win))
        {
            Some(d) => Ok(FileReply::Stat(d)),
            None => err(RemoteErrorCode::NotFound, "no such drive"),
        };
    }
    let child = verified_child(fs_, rules, &r.win, false)?;
    let m = fs::symlink_metadata(&child).or_else(io_err)?;
    let name = file_name_of(&r.win).to_string();
    Ok(FileReply::Stat(entry_from(&m, name, r.win)))
}

fn read_chunk(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    sess: &mut FsSession,
    path: &str,
    offset: u64,
    len: u32,
    blocked: &[String],
) -> OpResult<FileReply> {
    let r = read_chunk_inner(fs_, rules, sess, path, offset, len, blocked);
    if r.is_err() {
        // Any failure ends the download; the server must start over.
        sess.download = None;
    }
    r
}

fn read_chunk_inner(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    sess: &mut FsSession,
    path: &str,
    offset: u64,
    len: u32,
    blocked: &[String],
) -> OpResult<FileReply> {
    if sess.download.is_none() {
        if offset != 0 {
            return err(
                RemoteErrorCode::IntegrityError,
                "a download must start at offset 0",
            );
        }
        let r = resolve(fs_, rules, path, false, blocked)?;
        let guard = |p: &Path| rules.check(p, false);
        let file = fs_.open_read(&r.local, &guard).map_err(op_reply)?;
        let md = file.metadata().or_else(io_err)?;
        if md.is_dir() {
            return err(
                RemoteErrorCode::InvalidOperation,
                "cannot download a folder",
            );
        }
        let size = md.len();
        if size > TRANSFER_MAX {
            return err(
                RemoteErrorCode::TooLarge,
                "file is larger than the transfer limit",
            );
        }
        tracing::debug!(path = %r.win, size, "remote download opened");
        sess.download = Some(Download {
            path: r.win,
            file,
            size,
            pos: 0,
            hasher: Sha256::new(),
        });
    }
    let Some(d) = sess.download.as_mut() else {
        return err(RemoteErrorCode::Io, "download state lost");
    };
    // Same file for the whole session.
    match validate_remote_path(path) {
        Ok(p) if p.eq_ignore_ascii_case(&d.path) => {}
        _ => {
            return err(
                RemoteErrorCode::InvalidOperation,
                "another download is open in this session",
            )
        }
    }
    if offset != d.pos {
        return err(
            RemoteErrorCode::IntegrityError,
            "chunks must be read sequentially",
        );
    }
    let want = (len.min(FILE_CHUNK_MAX) as u64).min(d.size - d.pos) as usize;
    let mut buf = vec![0u8; want];
    let mut n = 0;
    while n < want {
        match d.file.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return io_err(e),
        }
    }
    if n < want {
        return err(
            RemoteErrorCode::IntegrityError,
            "the file got smaller during the download",
        );
    }
    buf.truncate(n);
    d.hasher.update(&buf);
    d.pos += n as u64;
    let eof = d.pos == d.size;
    let mut sha = None;
    if eof {
        let now_len = d.file.metadata().map(|m| m.len()).unwrap_or(d.size);
        let mut probe = [0u8; 1];
        let grew = now_len != d.size || matches!(d.file.read(&mut probe), Ok(k) if k > 0);
        if grew {
            return err(
                RemoteErrorCode::IntegrityError,
                "the file changed during the download",
            );
        }
        sha = Some(hex::encode(d.hasher.clone().finalize()));
    }
    let size = d.size;
    if eof {
        sess.download = None;
    }
    Ok(FileReply::Data {
        offset,
        data_b64: base64::engine::general_purpose::STANDARD.encode(&buf),
        size,
        eof,
        sha256: sha,
    })
}

/// Temp file name for an upload of `name` (bounded length).
fn temp_name(name: &str) -> String {
    let short: String = name.chars().take(100).collect();
    let rnd: [u8; 8] = rand::random();
    format!(".{short}.kestrel-upload-{}.tmp", hex::encode(rnd))
}

fn write_begin(
    fs_: &Arc<dyn RemoteFs>,
    rules: &Arc<Rules>,
    sess: &mut FsSession,
    path: &str,
    size: u64,
    pol: &OpPolicy,
) -> OpResult<FileReply> {
    if sess.upload.is_some() {
        return err(
            RemoteErrorCode::InvalidOperation,
            "an upload is already in progress in this session",
        );
    }
    if size > TRANSFER_MAX {
        return err(
            RemoteErrorCode::TooLarge,
            "file is larger than the transfer limit",
        );
    }
    if is_drive_root_raw(path) {
        return err(
            RemoteErrorCode::InvalidOperation,
            "cannot upload to a drive root",
        );
    }
    let f: &dyn RemoteFs = &**fs_;
    let r = resolve(f, rules, path, true, &pol.blocked)?;
    let target = verified_child(f, rules, &r.win, true)?;
    let exists = match fs::symlink_metadata(&target) {
        Ok(m) if m.is_dir() => {
            return err(
                RemoteErrorCode::InvalidOperation,
                "a folder exists at this path",
            )
        }
        Ok(_) => true,
        Err(_) => false,
    };
    if exists {
        if let Some((code, msg)) = &pol.overwrite_refusal {
            return err(*code, msg.clone());
        }
    }
    let Some(dir) = target.parent() else {
        return err(RemoteErrorCode::InvalidPath, "path has no parent folder");
    };
    let tmp = dir.join(temp_name(file_name_of(&r.win)));
    let guard = |p: &Path| rules.check(p, false);
    let file = fs_.create_new(&tmp, &guard).map_err(op_reply)?;
    tracing::debug!(path = %r.win, size, "remote upload started");
    sess.upload = Some(Upload {
        fs: fs_.clone(),
        rules: rules.clone(),
        target_win: r.win,
        target,
        tmp,
        file: Some(file),
        size,
        written: 0,
        hasher: Sha256::new(),
        last_chunk: Instant::now(),
        committed: false,
        overwrite_allowed: pol.overwrite_refusal.is_none(),
    });
    Ok(FileReply::Done { count: 0 })
}

fn write_chunk(sess: &mut FsSession, offset: u64, data_b64: &str) -> OpResult<FileReply> {
    let r = write_chunk_inner(sess, offset, data_b64);
    if r.is_err() {
        sess.upload = None;
    }
    r
}

fn write_chunk_inner(sess: &mut FsSession, offset: u64, data_b64: &str) -> OpResult<FileReply> {
    let Some(u) = sess.upload.as_mut() else {
        return err(RemoteErrorCode::InvalidOperation, "no upload in progress");
    };
    let max_b64 = (FILE_CHUNK_MAX as usize).div_ceil(3) * 4 + 4;
    if data_b64.len() > max_b64 {
        return err(RemoteErrorCode::TooLarge, "chunk is larger than the limit");
    }
    if offset != u.written {
        return err(
            RemoteErrorCode::IntegrityError,
            "chunks must be written sequentially",
        );
    }
    let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
        Ok(d) => d,
        Err(_) => return err(RemoteErrorCode::IntegrityError, "chunk is not valid base64"),
    };
    if data.len() > FILE_CHUNK_MAX as usize {
        return err(RemoteErrorCode::TooLarge, "chunk is larger than the limit");
    }
    if u.written + data.len() as u64 > u.size {
        return err(
            RemoteErrorCode::IntegrityError,
            "more data than the announced size",
        );
    }
    let Some(f) = u.file.as_mut() else {
        return err(RemoteErrorCode::Io, "upload file closed");
    };
    f.write_all(&data).or_else(io_err)?;
    u.hasher.update(&data);
    u.written += data.len() as u64;
    u.last_chunk = Instant::now();
    Ok(FileReply::Done { count: u.written })
}

fn write_end(
    fs_: &dyn RemoteFs,
    sess: &mut FsSession,
    sha256: &str,
    blocked: &[String],
) -> OpResult<FileReply> {
    // Whatever happens, the upload is over (Drop deletes the temp file
    // unless it was committed).
    let Some(mut u) = sess.upload.take() else {
        return err(RemoteErrorCode::InvalidOperation, "no upload in progress");
    };
    if u.written != u.size {
        return err(
            RemoteErrorCode::IntegrityError,
            format!("received {} of {} bytes", u.written, u.size),
        );
    }
    let got = hex::encode(u.hasher.clone().finalize());
    if !got.eq_ignore_ascii_case(sha256.trim()) {
        return err(RemoteErrorCode::IntegrityError, "SHA-256 does not match");
    }
    if let Some(mut f) = u.file.take() {
        f.flush().or_else(io_err)?;
        f.sync_all().or_else(io_err)?;
    }
    // Re-check with the current rules, then rename through the platform:
    // its guard sees the final destination (a folder swapped for a link to
    // a protected folder while the upload ran is refused there).
    let rules = Rules::new(fs_, blocked);
    resolve(fs_, &rules, &u.target_win, true, blocked)?;
    let guard = |p: &Path| rules.check(p, true);
    fs_.rename(&u.tmp, &u.target, u.overwrite_allowed, &guard)
        .map_err(op_reply)?;
    u.committed = true;
    tracing::debug!(path = %u.target_win, size = u.size, "remote upload written");
    Ok(FileReply::Written {
        path: u.target_win.clone(),
        size: u.size,
        sha256: got,
    })
}

fn rename(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    from: &str,
    to: &str,
    overwrite: bool,
    pol: &OpPolicy,
) -> OpResult<FileReply> {
    if is_drive_root_raw(from) || is_drive_root_raw(to) {
        return err(
            RemoteErrorCode::InvalidOperation,
            "drive roots cannot be renamed",
        );
    }
    let f = resolve(fs_, rules, from, true, &pol.blocked)?;
    let t = resolve(fs_, rules, to, true, &pol.blocked)?;
    // A case-only rename of the same item (Windows names are case-insensitive).
    let same = f.win.eq_ignore_ascii_case(&t.win);
    let guard = |p: &Path| rules.check(p, true);
    fs_.rename(&f.local, &t.local, overwrite || same, &guard)
        .map_err(op_reply)?;
    tracing::debug!(from = %f.win, to = %t.win, "remote rename");
    Ok(FileReply::Done { count: 1 })
}

fn delete(
    fs_: &dyn RemoteFs,
    rules: &Rules,
    path: &str,
    recursive: bool,
    blocked: &[String],
) -> OpResult<FileReply> {
    if is_drive_root_raw(path) {
        return err(
            RemoteErrorCode::InvalidOperation,
            "drive roots cannot be deleted",
        );
    }
    let r = resolve(fs_, rules, path, true, blocked)?;
    let guard = |p: &Path| rules.check(p, true);
    let count = fs_.remove(&r.local, recursive, &guard).map_err(op_reply)?;
    tracing::debug!(path = %r.win, count, "remote delete");
    Ok(FileReply::Done { count })
}

fn mkdir(fs_: &dyn RemoteFs, rules: &Rules, path: &str, blocked: &[String]) -> OpResult<FileReply> {
    let r = resolve(fs_, rules, path, false, blocked)?;
    match fs::symlink_metadata(&r.local) {
        Ok(m) if m.is_dir() => return Ok(FileReply::Done { count: 0 }),
        Ok(_) => return err(RemoteErrorCode::AlreadyExists, "a file exists at this path"),
        Err(_) => {}
    }
    let guard = |p: &Path| rules.check(p, false);
    fs_.create_dir_all(&r.local, &guard).map_err(op_reply)?;
    tracing::debug!(path = %r.win, "remote mkdir");
    Ok(FileReply::Done { count: 1 })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::remote::FileOp;

    /// Maps `X:\…` into `<root>/X/…`.
    struct TestFs {
        root: PathBuf,
        protected: Vec<PathBuf>,
    }

    impl RemoteFs for TestFs {
        fn local_path(&self, win_path: &str) -> PathBuf {
            let mut p = self.root.clone();
            for part in win_path.split('\\').filter(|s| !s.is_empty()) {
                p.push(part.replace(':', ""));
            }
            p
        }
        fn drives(&self) -> Vec<FileEntry> {
            vec![FileEntry {
                name: "C:".into(),
                path: "C:\\".into(),
                kind: FileKind::Drive,
                ..Default::default()
            }]
        }
        fn check_path(&self, win_path: &str) -> Result<(), String> {
            if win_path.starts_with("C:") {
                Ok(())
            } else {
                Err("no such drive".into())
            }
        }
        fn protected_roots(&self) -> Vec<PathBuf> {
            self.protected.clone()
        }
    }

    fn setup() -> (tempfile::TempDir, Arc<dyn RemoteFs>) {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_path_buf();
        let fs_ = TestFs {
            root: root.clone(),
            protected: vec![root.join("C").join("Program Files").join("Kestrel")],
        };
        fs::create_dir_all(root.join("C/Program Files/Kestrel")).unwrap();
        fs::write(root.join("C/Program Files/Kestrel/agent.exe"), b"x").unwrap();
        fs::create_dir_all(root.join("C/Users/bob")).unwrap();
        (d, Arc::new(fs_))
    }

    fn code(r: &FileReply) -> Option<RemoteErrorCode> {
        match r {
            FileReply::Error { code, .. } => Some(*code),
            _ => None,
        }
    }

    fn run(fs_: &Arc<dyn RemoteFs>, s: &mut FsSession, op: FileOp) -> FileReply {
        handle(fs_, s, op, &OpPolicy::open())
    }

    fn pol_blocked(b: &[&str]) -> OpPolicy {
        OpPolicy {
            blocked: b.iter().map(|s| s.to_string()).collect(),
            overwrite_refusal: None,
        }
    }

    fn b64(b: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(b)
    }

    #[test]
    fn validation_and_platform_refusals() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        for bad in [
            "relative\\x",
            "\\\\server\\share",
            "C:\\a\\..\\b",
            "C:\\x:ads",
        ] {
            let r = run(&f, &mut s, FileOp::Stat { path: bad.into() });
            assert_eq!(code(&r), Some(RemoteErrorCode::InvalidPath), "{bad}");
        }
        let r = run(
            &f,
            &mut s,
            FileOp::List {
                path: "D:\\".into(),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidPath));
        let r = run(&f, &mut s, FileOp::Unknown);
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        // Drives.
        match run(
            &f,
            &mut s,
            FileOp::List {
                path: String::new(),
            },
        ) {
            FileReply::List { entries, .. } => assert_eq!(entries[0].path, "C:\\"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn protected_root_and_ancestors() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        for p in [
            "C:\\Program Files\\Kestrel",
            "c:\\PROGRAM FILES\\kestrel\\agent.exe",
            "C:\\Program Files\\Kestrel\\new",
        ] {
            for op in [
                FileOp::List { path: p.into() },
                FileOp::Stat { path: p.into() },
                FileOp::ReadChunk {
                    path: p.into(),
                    offset: 0,
                    len: 10,
                },
                FileOp::Mkdir { path: p.into() },
                FileOp::Delete {
                    path: p.into(),
                    recursive: true,
                },
                FileOp::WriteBegin {
                    path: p.into(),
                    size: 1,
                },
            ] {
                let r = run(&f, &mut s, op.clone());
                assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath), "{op:?}");
            }
        }
        // Ancestors: listing is fine, deleting / renaming is not.
        assert!(code(&run(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Program Files".into()
            }
        ))
        .is_none());
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\Program Files".into(),
                recursive: true,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath));
        let r = run(
            &f,
            &mut s,
            FileOp::Rename {
                from: "C:\\Program Files".into(),
                to: "C:\\PF".into(),
                overwrite: false,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath));
        // Moving something *into* the protected folder.
        fs::write(f.local_path("C:\\Users\\bob\\x.txt"), b"1").unwrap();
        let r = run(
            &f,
            &mut s,
            FileOp::Rename {
                from: "C:\\Users\\bob\\x.txt".into(),
                to: "C:\\Program Files\\Kestrel\\x.txt".into(),
                overwrite: true,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath));
        // Drive roots.
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\".into(),
                recursive: true,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        assert!(f
            .local_path("C:\\Program Files\\Kestrel\\agent.exe")
            .exists());
    }

    /// Create a directory link at `link` pointing to `target`. Unix: a
    /// symlink. Windows: a junction (`mklink /J`, no privilege needed).
    fn dir_link(target: &Path, link: &Path) -> bool {
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            std::process::Command::new("cmd")
                .arg("/c")
                .arg("mklink")
                .arg("/J")
                .arg(link)
                .arg(target)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
                && link.exists()
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (target, link);
            false
        }
    }

    #[test]
    fn link_into_protected_root_is_refused() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        let link = f.local_path("C:\\Users\\bob\\sneaky");
        if !dir_link(&f.local_path("C:\\Program Files\\Kestrel"), &link) {
            eprintln!("skipping: cannot create a directory link here");
            return;
        }
        for op in [
            FileOp::List {
                path: "C:\\Users\\bob\\sneaky".into(),
            },
            FileOp::ReadChunk {
                path: "C:\\Users\\bob\\sneaky\\agent.exe".into(),
                offset: 0,
                len: 1,
            },
            FileOp::WriteBegin {
                path: "C:\\Users\\bob\\sneaky\\evil.dll".into(),
                size: 1,
            },
            FileOp::Delete {
                path: "C:\\Users\\bob\\sneaky\\agent.exe".into(),
                recursive: false,
            },
        ] {
            let r = run(&f, &mut s, op.clone());
            assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath), "{op:?}");
        }
        assert!(f
            .local_path("C:\\Program Files\\Kestrel\\agent.exe")
            .exists());
    }

    fn sha(b: &[u8]) -> String {
        hex::encode(Sha256::digest(b))
    }

    #[test]
    fn upload_happy_path_overwrite_and_mismatch() {
        let (_d, f) = setup();
        let target = "C:\\Users\\bob\\report.txt";
        let data = b"hello kestrel upload".repeat(100);
        let up = |s: &mut FsSession, data: &[u8], claimed_sha: &str| -> FileReply {
            let r = run(
                &f,
                s,
                FileOp::WriteBegin {
                    path: target.into(),
                    size: data.len() as u64,
                },
            );
            assert_eq!(r, FileReply::Done { count: 0 });
            let (a, b) = data.split_at(data.len() / 2);
            assert_eq!(
                run(
                    &f,
                    s,
                    FileOp::WriteChunk {
                        offset: 0,
                        data_b64: b64(a)
                    }
                ),
                FileReply::Done {
                    count: a.len() as u64
                }
            );
            run(
                &f,
                s,
                FileOp::WriteChunk {
                    offset: a.len() as u64,
                    data_b64: b64(b),
                },
            );
            run(
                &f,
                s,
                FileOp::WriteEnd {
                    sha256: claimed_sha.into(),
                },
            )
        };
        let tmp_count = || {
            fs::read_dir(f.local_path("C:\\Users\\bob"))
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .contains("kestrel-upload")
                })
                .count()
        };
        let mut s = FsSession::default();
        let r = up(&mut s, &data, &sha(&data));
        assert_eq!(
            r,
            FileReply::Written {
                path: target.into(),
                size: data.len() as u64,
                sha256: sha(&data)
            }
        );
        assert_eq!(fs::read(f.local_path(target)).unwrap(), data);
        assert_eq!(tmp_count(), 0);
        // Overwrite with new content.
        let data2 = b"second version".to_vec();
        let r = up(&mut s, &data2, &sha(&data2).to_uppercase());
        assert!(matches!(r, FileReply::Written { .. }), "{r:?}");
        assert_eq!(fs::read(f.local_path(target)).unwrap(), data2);
        // SHA mismatch: target untouched, temp removed.
        let r = up(&mut s, b"third", &sha(b"other"));
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
        assert_eq!(fs::read(f.local_path(target)).unwrap(), data2);
        assert_eq!(tmp_count(), 0);
        assert!(!s.has_transfer());
        // Out-of-order chunk aborts; too much data aborts; abort removes temp.
        run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: 4,
            },
        );
        assert_eq!(tmp_count(), 1);
        let r = run(
            &f,
            &mut s,
            FileOp::WriteChunk {
                offset: 2,
                data_b64: b64(b"ab"),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
        assert_eq!(tmp_count(), 0);
        run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: 2,
            },
        );
        let r = run(
            &f,
            &mut s,
            FileOp::WriteChunk {
                offset: 0,
                data_b64: b64(b"abc"),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
        assert_eq!(tmp_count(), 0);
        run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: 2,
            },
        );
        assert_eq!(
            run(&f, &mut s, FileOp::WriteAbort),
            FileReply::Done { count: 0 }
        );
        assert_eq!(tmp_count(), 0);
        // Idle expiry and session drop delete the temp file.
        run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: 2,
            },
        );
        assert!(s.expire_idle(
            Instant::now() + Duration::from_secs(5),
            Duration::from_secs(1)
        ));
        assert_eq!(tmp_count(), 0);
        run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: 2,
            },
        );
        drop(s);
        assert_eq!(tmp_count(), 0);
        // Folder at target / missing parent / too large.
        let mut s = FsSession::default();
        let r = run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: "C:\\Users\\bob".into(),
                size: 1,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        let r = run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: "C:\\Users\\nobody\\x".into(),
                size: 1,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::NotFound));
        let r = run(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: target.into(),
                size: TRANSFER_MAX + 1,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::TooLarge));
    }

    #[test]
    fn download_sequential_with_hash() {
        let (_d, f) = setup();
        let p = "C:\\Users\\bob\\big.bin";
        let data: Vec<u8> = (0..(FILE_CHUNK_MAX as usize * 2 + 77))
            .map(|i| (i % 251) as u8)
            .collect();
        fs::write(f.local_path(p), &data).unwrap();
        let mut s = FsSession::default();
        // Must start at 0.
        let r = run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: p.into(),
                offset: 5,
                len: 10,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
        let mut got = vec![];
        let mut off = 0u64;
        loop {
            match run(
                &f,
                &mut s,
                FileOp::ReadChunk {
                    path: p.into(),
                    offset: off,
                    len: u32::MAX,
                },
            ) {
                FileReply::Data {
                    offset,
                    data_b64,
                    size,
                    eof,
                    sha256,
                } => {
                    assert_eq!(offset, off);
                    assert_eq!(size, data.len() as u64);
                    let b = base64::engine::general_purpose::STANDARD
                        .decode(data_b64)
                        .unwrap();
                    assert!(b.len() <= FILE_CHUNK_MAX as usize);
                    off += b.len() as u64;
                    got.extend(b);
                    if eof {
                        assert_eq!(sha256.as_deref(), Some(sha(&data).as_str()));
                        break;
                    }
                    assert!(sha256.is_none());
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(got, data);
        assert!(!s.has_transfer());
        // Out of order in a new download.
        run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: p.into(),
                offset: 0,
                len: 10,
            },
        );
        let r = run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: p.into(),
                offset: 20,
                len: 10,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
        assert!(!s.has_transfer());
        // Folders cannot be downloaded; empty file is a single eof chunk.
        let r = run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: "C:\\Users\\bob".into(),
                offset: 0,
                len: 10,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        fs::write(f.local_path("C:\\Users\\bob\\empty"), b"").unwrap();
        match run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: "C:\\Users\\bob\\empty".into(),
                offset: 0,
                len: 10,
            },
        ) {
            FileReply::Data { eof, sha256, .. } => {
                assert!(eof);
                assert_eq!(sha256, Some(sha(b"")));
            }
            other => panic!("{other:?}"),
        }
        // A file that grew during the download is refused.
        fs::write(f.local_path(p), b"0123456789").unwrap();
        run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: p.into(),
                offset: 0,
                len: 5,
            },
        );
        fs::OpenOptions::new()
            .append(true)
            .open(f.local_path(p))
            .unwrap()
            .write_all(b"more")
            .unwrap();
        let r = run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: p.into(),
                offset: 5,
                len: 5,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::IntegrityError));
    }

    #[test]
    fn recursive_delete_does_not_follow_links() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        // Outside folder with content that must survive.
        let outside = f.local_path("C:\\Data\\keep");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("precious.txt"), b"keep me").unwrap();
        let victim = f.local_path("C:\\Users\\bob\\tmp");
        fs::create_dir_all(victim.join("sub/deeper")).unwrap();
        fs::write(victim.join("a.txt"), b"a").unwrap();
        fs::write(victim.join("sub/deeper/b.txt"), b"b").unwrap();
        let linked = dir_link(&outside, &victim.join("sub/link"));
        // Non-recursive on a non-empty folder.
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\Users\\bob\\tmp".into(),
                recursive: false,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\Users\\bob\\tmp".into(),
                recursive: true,
            },
        );
        // tmp, a.txt, sub, deeper, b.txt (+ link)
        assert_eq!(
            r,
            FileReply::Done {
                count: 5 + linked as u64
            }
        );
        assert!(!victim.exists());
        assert_eq!(fs::read(outside.join("precious.txt")).unwrap(), b"keep me");
        // Deleting a link directly removes only the link.
        if dir_link(&outside, &f.local_path("C:\\Users\\bob\\l2")) {
            let r = run(
                &f,
                &mut s,
                FileOp::Delete {
                    path: "C:\\Users\\bob\\l2".into(),
                    recursive: false,
                },
            );
            assert_eq!(r, FileReply::Done { count: 1 });
            assert!(!f.local_path("C:\\Users\\bob\\l2").exists());
            assert!(outside.join("precious.txt").exists());
        }
        // Single file, read-only.
        let ro = f.local_path("C:\\Users\\bob\\ro.txt");
        fs::write(&ro, b"x").unwrap();
        let mut perm = fs::metadata(&ro).unwrap().permissions();
        perm.set_readonly(true);
        fs::set_permissions(&ro, perm).unwrap();
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\Users\\bob\\ro.txt".into(),
                recursive: false,
            },
        );
        assert_eq!(r, FileReply::Done { count: 1 });
        let r = run(
            &f,
            &mut s,
            FileOp::Delete {
                path: "C:\\Users\\bob\\ro.txt".into(),
                recursive: false,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::NotFound));
    }

    #[test]
    fn list_entries_and_truncation() {
        let (_d, f) = setup();
        let dir = f.local_path("C:\\Users\\bob");
        for i in 0..7 {
            fs::write(dir.join(format!("f{i}.txt")), b"12345").unwrap();
        }
        fs::create_dir(dir.join("Sub")).unwrap();
        match list(&*f, &Rules::new(&*f, &[]), "c:/Users/bob/", 100, &[]).unwrap() {
            FileReply::List {
                path,
                entries,
                truncated,
            } => {
                assert_eq!(path, "C:\\Users\\bob");
                assert!(!truncated);
                assert_eq!(entries.len(), 8);
                let e = entries.iter().find(|e| e.name == "f3.txt").unwrap();
                assert_eq!(e.path, "C:\\Users\\bob\\f3.txt");
                assert_eq!(e.kind, FileKind::File);
                assert_eq!(e.size, 5);
                assert!(e.modified.is_some());
                let d = entries.iter().find(|e| e.name == "Sub").unwrap();
                assert_eq!(d.kind, FileKind::Dir);
            }
            other => panic!("{other:?}"),
        }
        match list(&*f, &Rules::new(&*f, &[]), "C:\\Users\\bob", 3, &[]).unwrap() {
            FileReply::List {
                entries, truncated, ..
            } => {
                assert_eq!(entries.len(), 3);
                assert!(truncated);
            }
            other => panic!("{other:?}"),
        }
        let mut s = FsSession::default();
        let r = run(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Users\\bob\\f1.txt".into(),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidOperation));
        let r = run(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Nope".into(),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::NotFound));
    }

    #[test]
    fn blocked_paths_refuse_path_and_descendants_only() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        fs::create_dir_all(f.local_path("C:\\Windows\\System32\\config")).unwrap();
        fs::write(f.local_path("C:\\Windows\\System32\\config\\SAM"), b"x").unwrap();
        let blocked = pol_blocked(&["c:/Windows/System32/config"]);
        for p in [
            "C:\\Windows\\System32\\config",
            "C:\\WINDOWS\\system32\\CONFIG\\SAM",
        ] {
            let r = handle(&f, &mut s, FileOp::Stat { path: p.into() }, &blocked);
            assert_eq!(code(&r), Some(RemoteErrorCode::BlockedPath), "{p}");
        }
        // Ancestors are fine for blocked paths.
        let r = handle(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Windows\\System32".into(),
            },
            &blocked,
        );
        assert!(code(&r).is_none(), "{r:?}");
        // A link into the blocked folder is refused through its canonical form.
        let link = f.local_path("C:\\Users\\bob\\cfg");
        if dir_link(&f.local_path("C:\\Windows\\System32\\config"), &link) {
            let r = handle(
                &f,
                &mut s,
                FileOp::ReadChunk {
                    path: "C:\\Users\\bob\\cfg\\SAM".into(),
                    offset: 0,
                    len: 1,
                },
                &blocked,
            );
            assert_eq!(code(&r), Some(RemoteErrorCode::BlockedPath));
        }
    }

    #[test]
    fn blocked_paths_refuse_ancestors_for_destructive_ops() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        fs::create_dir_all(f.local_path("C:\\Users\\ceo\\Docs")).unwrap();
        fs::write(f.local_path("C:\\Users\\ceo\\Docs\\plan.txt"), b"x").unwrap();
        let pol = pol_blocked(&["C:\\Users\\ceo\\Docs"]);
        for op in [
            FileOp::Rename {
                from: "C:\\Users\\ceo".into(),
                to: "C:\\Users\\ceo2".into(),
                overwrite: false,
            },
            FileOp::Delete {
                path: "C:\\Users\\ceo".into(),
                recursive: true,
            },
            FileOp::Delete {
                path: "C:\\Users".into(),
                recursive: true,
            },
        ] {
            let r = handle(&f, &mut s, op.clone(), &pol);
            assert_eq!(code(&r), Some(RemoteErrorCode::BlockedPath), "{op:?}");
        }
        assert!(f.local_path("C:\\Users\\ceo\\Docs\\plan.txt").exists());
        // Listing the ancestor is still fine.
        let r = handle(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Users\\ceo".into(),
            },
            &pol,
        );
        assert!(code(&r).is_none(), "{r:?}");
    }

    #[test]
    fn final_path_rules() {
        let (_d, f) = setup();
        let rules = Rules::new(&*f, &["C:\\Users\\ceo\\Docs".to_string()]);
        // Network / device final paths are refused.
        let net: &[&str] = if cfg!(windows) {
            &[
                r"\\?\UNC\server\share\x",
                r"\\server\share\x",
                r"\Device\Mup\server\share",
                r"\\?\Volume{0b1c2d3e-0000-0000-0000-000000000000}\x",
                r"\\.\PhysicalDrive0",
            ]
        } else {
            &["//server/share/x", "relative/x"]
        };
        for p in net {
            match rules.check(Path::new(p), false) {
                Err(FsOpError::Refused { code, .. }) => {
                    assert_eq!(code, RemoteErrorCode::InvalidPath, "{p}")
                }
                other => panic!("{p}: {other:?}"),
            }
        }
        let local = if cfg!(windows) { r"\\?\C:\x\y" } else { "/x/y" };
        assert!(rules.check(Path::new(local), true).is_ok());
        // Protected root and ancestors, on the final path.
        let prot = fs::canonicalize(f.local_path("C:\\Program Files\\Kestrel")).unwrap();
        assert!(rules.check(&prot.join("agent.exe"), false).is_err());
        let anc = prot.parent().unwrap();
        assert!(rules.check(anc, false).is_ok());
        assert!(rules.check(anc, true).is_err());
    }

    /// A platform whose hardened open reports a network final path (what
    /// `GetFinalPathNameByHandleW` returns for a symlink to a share).
    struct NetFinalFs(Arc<dyn RemoteFs>);
    impl RemoteFs for NetFinalFs {
        fn local_path(&self, w: &str) -> PathBuf {
            self.0.local_path(w)
        }
        fn drives(&self) -> Vec<FileEntry> {
            self.0.drives()
        }
        fn protected_roots(&self) -> Vec<PathBuf> {
            self.0.protected_roots()
        }
        fn verify_dir(
            &self,
            _p: &Path,
            guard: kestrel_platform::FsGuard<'_>,
        ) -> Result<PathBuf, FsOpError> {
            let fin = if cfg!(windows) {
                PathBuf::from(r"\\?\UNC\evil\share\dir")
            } else {
                PathBuf::from("//evil/share/dir")
            };
            guard(&fin)?;
            Ok(fin)
        }
        fn open_read(
            &self,
            _p: &Path,
            guard: kestrel_platform::FsGuard<'_>,
        ) -> Result<File, FsOpError> {
            // Final path inside the protected folder (a swapped junction).
            let fin = fs::canonicalize(self.0.local_path("C:\\Program Files\\Kestrel"))?
                .join("agent.exe");
            guard(&fin)?;
            Err(FsOpError::Io(io::Error::other("must not get here")))
        }
    }

    #[test]
    fn guard_sees_final_paths_of_hardened_ops() {
        let (_d, inner) = setup();
        let f: Arc<dyn RemoteFs> = Arc::new(NetFinalFs(inner.clone()));
        let mut s = FsSession::default();
        let r = run(
            &f,
            &mut s,
            FileOp::List {
                path: "C:\\Users\\bob".into(),
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::InvalidPath));
        fs::write(inner.local_path("C:\\Users\\bob\\x.txt"), b"x").unwrap();
        let r = run(
            &f,
            &mut s,
            FileOp::ReadChunk {
                path: "C:\\Users\\bob\\x.txt".into(),
                offset: 0,
                len: 1,
            },
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::ProtectedPath));
    }

    #[test]
    fn overwrite_needs_its_own_permission() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        let pol = OpPolicy {
            blocked: vec![],
            overwrite_refusal: Some((RemoteErrorCode::NotPermitted, "no overwrite".into())),
        };
        fs::write(f.local_path("C:\\Users\\bob\\old.txt"), b"keep").unwrap();
        let r = handle(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: "C:\\Users\\bob\\old.txt".into(),
                size: 1,
            },
            &pol,
        );
        assert_eq!(code(&r), Some(RemoteErrorCode::NotPermitted));
        // A new file is fine.
        let r = handle(
            &f,
            &mut s,
            FileOp::WriteBegin {
                path: "C:\\Users\\bob\\new.txt".into(),
                size: 1,
            },
            &pol,
        );
        assert_eq!(r, FileReply::Done { count: 0 });
        handle(
            &f,
            &mut s,
            FileOp::WriteChunk {
                offset: 0,
                data_b64: b64(b"n"),
            },
            &pol,
        );
        // The target appearing meanwhile is not overwritten.
        fs::write(f.local_path("C:\\Users\\bob\\new.txt"), b"theirs").unwrap();
        let r = handle(&f, &mut s, FileOp::WriteEnd { sha256: sha(b"n") }, &pol);
        assert!(code(&r).is_some(), "{r:?}");
        assert_eq!(
            fs::read(f.local_path("C:\\Users\\bob\\new.txt")).unwrap(),
            b"theirs"
        );
        assert_eq!(
            fs::read(f.local_path("C:\\Users\\bob\\old.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn rename_rules_and_mkdir() {
        let (_d, f) = setup();
        let mut s = FsSession::default();
        let a = "C:\\Users\\bob\\a.txt";
        let b = "C:\\Users\\bob\\b.txt";
        fs::write(f.local_path(a), b"A").unwrap();
        fs::write(f.local_path(b), b"B").unwrap();
        let ren = |s: &mut FsSession, from: &str, to: &str, ow: bool| {
            run(
                &f,
                s,
                FileOp::Rename {
                    from: from.into(),
                    to: to.into(),
                    overwrite: ow,
                },
            )
        };
        assert_eq!(
            code(&ren(&mut s, a, b, false)),
            Some(RemoteErrorCode::AlreadyExists)
        );
        assert_eq!(ren(&mut s, a, b, true), FileReply::Done { count: 1 });
        assert_eq!(fs::read(f.local_path(b)).unwrap(), b"A");
        assert_eq!(
            code(&ren(&mut s, a, b, true)),
            Some(RemoteErrorCode::NotFound)
        );
        // Never over a folder, even with overwrite.
        assert_eq!(
            run(
                &f,
                &mut s,
                FileOp::Mkdir {
                    path: "C:\\Users\\bob\\New Folder\\x".into()
                }
            ),
            FileReply::Done { count: 1 }
        );
        assert_eq!(
            code(&ren(&mut s, b, "C:\\Users\\bob\\New Folder", true)),
            Some(RemoteErrorCode::InvalidOperation)
        );
        // Mkdir over a file / existing dir.
        assert_eq!(
            code(&run(&f, &mut s, FileOp::Mkdir { path: b.into() })),
            Some(RemoteErrorCode::AlreadyExists)
        );
        assert_eq!(
            run(
                &f,
                &mut s,
                FileOp::Mkdir {
                    path: "C:\\Users\\bob\\New Folder".into()
                }
            ),
            FileReply::Done { count: 0 }
        );
        // Folder rename.
        assert_eq!(
            ren(
                &mut s,
                "C:\\Users\\bob\\New Folder",
                "C:\\Users\\bob\\Renamed",
                false
            ),
            FileReply::Done { count: 1 }
        );
        assert!(f.local_path("C:\\Users\\bob\\Renamed\\x").is_dir());
    }
}
