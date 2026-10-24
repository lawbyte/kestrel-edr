//! File and identity enrichment with caches: SHA-256, Authenticode (embedded
//! and catalog), revocation, Mark-of-the-Web, size, SID → account name.
//!
//! * Hot paths (the ETW translator) only call the non-blocking `lookup_*`
//!   functions; misses are queued to worker threads that fill the caches.
//! * H7: first-seen process images get a **priority** job (dedicated worker):
//!   signature first, then the hash (files ≤ [`MAX_HASH_BYTES`]). The
//!   translator holds the `ProcessStart` for up to [`FIRST_RUN_BUDGET_MS`]
//!   waiting for it ([`super::translate`]).
//! * Late facts are delivered to the agent as `LateEnrichment`s for every
//!   process registered with [`Enricher::watch`] (start emitted before the
//!   facts were known, or a revocation check still pending).
//! * M12: images in user-writable / external locations are verified with
//!   revocation checking of the whole chain — cache-only on the hot path; if
//!   the result is unknown (offline / no cached CRL), an online check runs on
//!   a background worker with a timeout. Revoked → `Invalid`, cached.
//! * `snapshot_processes` uses the blocking variants.

use super::util::*;
use crate::vault::sha256_stream;
use kestrel_common::{PathClass, ProcessGuid, SignatureState};
use kestrel_platform::{LateEnrichment, ProcessFacts};
use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{
    CERT_E_REVOKED, CRYPT_E_NO_REVOCATION_CHECK, CRYPT_E_REVOCATION_OFFLINE, CRYPT_E_REVOKED,
    HANDLE, INVALID_HANDLE_VALUE, TRUST_E_BAD_DIGEST, TRUST_E_NOSIGNATURE,
    TRUST_E_PROVIDER_UNKNOWN, TRUST_E_SUBJECT_FORM_UNKNOWN,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CryptCATClose,
    CryptCATEnumerateMember, CryptCATGetMemberInfo, CryptCATOpen, CATALOG_INFO, CRYPTCATMEMBER,
    CRYPTCAT_OPEN_EXISTING,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, CertVerifyCertificateChainPolicy, CERT_CHAIN_POLICY_MICROSOFT_ROOT,
    CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};

/// Files larger than this are not hashed (still signature-checked).
pub const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;
/// First-run budget: the translator waits this long for priority facts.
pub const FIRST_RUN_BUDGET_MS: i64 = 750;
/// Images up to this size are hashed within the first-run budget; larger
/// ones are emitted once the signature is known and hashed later.
pub const FIRST_RUN_HASH_MAX: u64 = 100 * 1024 * 1024;
/// Online revocation check timeout.
const REVOCATION_TIMEOUT: Duration = Duration::from_secs(20);
/// Late-enrichment watchers live this long.
const WATCH_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_CACHE: usize = 20_000;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileFacts {
    pub sha256: Option<String>,
    pub signer: Option<String>,
    pub signed: SignatureState,
    pub motw_zone: Option<u8>,
    pub file_size: Option<u64>,
    /// Whether sha256 was attempted (an image-load-only entry may lack it).
    pub hashed: bool,
    /// The signing chain ends in a Microsoft root.
    pub microsoft_root: bool,
    /// Valid signature whose revocation status is still being checked online.
    pub revocation_pending: bool,
    /// Where the signature verdict came from (embedded, system catalog,
    /// MSIX package catalog).
    pub sig_source: SigSource,
}

/// Source of a signature verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SigSource {
    /// No signature found / not checked.
    #[default]
    None,
    /// Authenticode signature embedded in the file.
    Embedded,
    /// A catalog of the system catalog database (catroot): OS files that
    /// are signed only by catalog.
    SystemCatalog,
    /// The MSIX / AppX package's `AppxMetadata\CodeIntegrity.cat` (signed
    /// with the package certificate; packaged executables usually carry no
    /// embedded signature).
    PackageCatalog,
}

impl FileFacts {
    /// Good enough to emit a first-run `ProcessStart` (H7).
    pub fn ready_for_start(&self) -> bool {
        self.signed != SignatureState::Unknown
            && (self.hashed
                || self.sha256.is_some()
                || self.file_size.is_some_and(|s| s > FIRST_RUN_HASH_MAX))
    }

    fn as_process_facts(&self) -> ProcessFacts {
        ProcessFacts {
            sha256: self.sha256.clone(),
            signer: self.signer.clone(),
            signed: self.signed,
        }
    }
}

#[derive(Clone)]
struct Cached {
    size: u64,
    mtime: u64,
    facts: FileFacts,
}

enum Job {
    File { path: String, hash: bool },
    Sid(String),
}

struct Watch {
    guid: ProcessGuid,
    pid: u32,
    since: Instant,
    /// Facts already delivered (avoid repeats).
    sent: Option<FileFacts>,
}

pub struct Enricher {
    files: RwLock<HashMap<String, Cached>>,
    users: RwLock<HashMap<String, String>>,
    pending: Mutex<HashSet<String>>,
    tx: SyncSender<Job>,
    prio_tx: SyncSender<String>,
    rev_tx: SyncSender<String>,
    watchers: Mutex<HashMap<String, Vec<Watch>>>,
    sink: Mutex<Option<tokio::sync::mpsc::Sender<LateEnrichment>>>,
    /// Late facts produced before a sink was attached (bounded).
    ready: Mutex<Vec<LateEnrichment>>,
    pub dropped_jobs: std::sync::atomic::AtomicU64,
}

fn meta(path: &str) -> Option<(u64, u64)> {
    // V-M1: no SYSTEM file access to network paths (NTLM coercion).
    if super::scan::is_remote(path) {
        return None;
    }
    let m = std::fs::metadata(path).ok()?;
    let mtime = m
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;
    Some((m.len(), mtime))
}

fn user_writable(path: &str) -> bool {
    PathClass::of(path).is_user_writable()
}

impl Enricher {
    pub fn new() -> Arc<Enricher> {
        let (tx, rx) = sync_channel::<Job>(4096);
        let (prio_tx, prio_rx) = sync_channel::<String>(1024);
        let (rev_tx, rev_rx) = sync_channel::<String>(1024);
        let e = Arc::new(Enricher {
            files: RwLock::new(HashMap::new()),
            users: RwLock::new(HashMap::new()),
            pending: Mutex::new(HashSet::new()),
            tx,
            prio_tx,
            rev_tx,
            watchers: Mutex::new(HashMap::new()),
            sink: Mutex::new(None),
            ready: Mutex::new(Vec::new()),
            dropped_jobs: Default::default(),
        });
        let rx = Arc::new(Mutex::new(rx));
        for i in 0..2 {
            let weak = Arc::downgrade(&e);
            let rx = rx.clone();
            let _ = std::thread::Builder::new()
                .name(format!("kestrel-enrich-{i}"))
                .spawn(move || {
                    // Hashing / Authenticode of binaries already running:
                    // below normal + EcoQoS (the first-run worker that a
                    // held process start waits for stays normal).
                    super::prio::current_thread(super::prio::Background::Light);
                    worker(weak, rx)
                });
        }
        {
            let weak = Arc::downgrade(&e);
            let _ = std::thread::Builder::new()
                .name("kestrel-enrich-first-run".into())
                .spawn(move || prio_worker(weak, prio_rx));
        }
        {
            let weak = Arc::downgrade(&e);
            let _ = std::thread::Builder::new()
                .name("kestrel-revocation".into())
                .spawn(move || {
                    super::prio::current_thread(super::prio::Background::Full);
                    revocation_worker(weak, rev_rx)
                });
        }
        e
    }

    /// Attach (or detach) the late-enrichment sink; delivers anything that
    /// became ready before it was attached.
    pub fn set_sink(&self, tx: Option<tokio::sync::mpsc::Sender<LateEnrichment>>) {
        let pending: Vec<LateEnrichment> = self
            .ready
            .lock()
            .map(|mut r| std::mem::take(&mut *r))
            .unwrap_or_default();
        if let Ok(mut s) = self.sink.lock() {
            *s = tx;
        }
        for le in pending {
            self.deliver(le);
        }
    }

    fn deliver(&self, le: LateEnrichment) {
        let sink = self.sink.lock().ok().and_then(|s| s.clone());
        match sink {
            Some(tx) => {
                if tx.try_send(le).is_err() {
                    self.dropped_jobs
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            }
            None => {
                if let Ok(mut r) = self.ready.lock() {
                    if r.len() < 1024 {
                        r.push(le);
                    }
                }
            }
        }
    }

    /// Deliver late facts for `guid` (image `path`) whenever the cache learns
    /// something new about the file (H7 / M12).
    pub fn watch(&self, path: &str, guid: ProcessGuid, pid: u32, already: Option<FileFacts>) {
        if path.is_empty() {
            return;
        }
        let key = crate::ntpath::norm_key(path);
        if let Ok(mut w) = self.watchers.lock() {
            if w.len() > 4096 {
                w.retain(|_, v| {
                    v.retain(|x| x.since.elapsed() < WATCH_TTL);
                    !v.is_empty()
                });
            }
            let list = w.entry(key.clone()).or_default();
            if !list.iter().any(|x| x.guid == guid) && list.len() < 64 {
                list.push(Watch {
                    guid,
                    pid,
                    since: Instant::now(),
                    sent: already,
                });
            }
        }
        // The facts may already be complete (raced with the worker).
        if let Some(c) = self.files.read().ok().and_then(|m| m.get(&key).cloned()) {
            self.notify(&key, &c.facts);
        }
    }

    fn notify(&self, key: &str, facts: &FileFacts) {
        let mut out = Vec::new();
        if let Ok(mut w) = self.watchers.lock() {
            if let Some(list) = w.get_mut(key) {
                for x in list.iter_mut() {
                    let changed = match &x.sent {
                        None => facts.signed != SignatureState::Unknown || facts.sha256.is_some(),
                        Some(prev) => {
                            prev.signed != facts.signed
                                || prev.sha256 != facts.sha256
                                || prev.signer != facts.signer
                        }
                    };
                    if changed {
                        out.push(LateEnrichment {
                            guid: x.guid.clone(),
                            pid: x.pid,
                            facts: facts.as_process_facts(),
                        });
                        x.sent = Some(facts.clone());
                    }
                }
                // Done when the facts are final (hashed or too big, no pending revocation).
                let fin = facts.signed != SignatureState::Unknown
                    && (facts.hashed || facts.sha256.is_some())
                    && !facts.revocation_pending;
                list.retain(|x| !fin && x.since.elapsed() < WATCH_TTL);
                if list.is_empty() {
                    w.remove(key);
                }
            }
        }
        for le in out {
            self.deliver(le);
        }
    }

    /// Cached facts for `path` if still valid (size + mtime unchanged).
    /// Network paths are not stat'ed on the hot path.
    pub fn lookup_file(&self, path: &str) -> Option<FileFacts> {
        let key = crate::ntpath::norm_key(path);
        let cached = self.files.read().ok()?.get(&key).cloned()?;
        if path.starts_with(r"\\") {
            return Some(cached.facts);
        }
        match meta(path) {
            Some((size, mtime)) if size == cached.size && mtime == cached.mtime => {
                Some(cached.facts)
            }
            _ => None,
        }
    }

    /// Queue `path` for enrichment (deduplicated, never blocks).
    pub fn request_file(&self, path: &str, hash: bool) {
        if path.is_empty() {
            return;
        }
        let key = format!("f:{}", crate::ntpath::norm_key(path));
        if let Ok(mut p) = self.pending.lock() {
            if !p.insert(key.clone()) {
                return;
            }
        }
        if let Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) =
            self.tx.try_send(Job::File {
                path: path.to_string(),
                hash,
            })
        {
            self.dropped_jobs
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if let Ok(mut p) = self.pending.lock() {
                p.remove(&key);
            }
        }
    }

    /// First-run priority enrichment (H7): signature, then hash, on the
    /// dedicated worker. Deduplicated; falls back to the normal queue.
    pub fn request_priority(&self, path: &str) {
        if path.is_empty() {
            return;
        }
        let key = format!("p:{}", crate::ntpath::norm_key(path));
        if let Ok(mut p) = self.pending.lock() {
            if !p.insert(key.clone()) {
                return;
            }
        }
        if self.prio_tx.try_send(path.to_string()).is_err() {
            if let Ok(mut p) = self.pending.lock() {
                p.remove(&key);
            }
            self.request_file(path, true);
        }
    }

    /// Non-blocking cache lookup; queues a miss.
    pub fn file_or_request(&self, path: &str, hash: bool) -> Option<FileFacts> {
        match self.lookup_file(path) {
            Some(f) if f.hashed || !hash => Some(f),
            other => {
                self.request_file(path, hash);
                other
            }
        }
    }

    /// Compute now (blocking) and cache.
    pub fn file_blocking(&self, path: &str, hash: bool) -> FileFacts {
        if let Some(f) = self.lookup_file(path) {
            if f.hashed || !hash {
                return f;
            }
        }
        let (facts, size, mtime) = compute(path, hash);
        self.store(path, facts.clone(), size, mtime);
        facts
    }

    fn store(&self, path: &str, facts: FileFacts, size: u64, mtime: u64) {
        let key = crate::ntpath::norm_key(path);
        if facts.revocation_pending {
            if let Err(TrySendError::Full(_)) = self.rev_tx.try_send(path.to_string()) {
                self.dropped_jobs
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if let Ok(mut m) = self.files.write() {
            if m.len() >= MAX_CACHE {
                m.clear(); // crude but bounded; repopulates quickly
            }
            m.insert(
                key.clone(),
                Cached {
                    size,
                    mtime,
                    facts: facts.clone(),
                },
            );
        }
        self.notify(&key, &facts);
    }

    /// Update the cached facts of `path` in place (revocation result).
    fn update_cached(&self, path: &str, f: impl FnOnce(&mut FileFacts)) {
        let key = crate::ntpath::norm_key(path);
        let facts = {
            let Ok(mut m) = self.files.write() else {
                return;
            };
            let Some(c) = m.get_mut(&key) else { return };
            f(&mut c.facts);
            c.facts.clone()
        };
        self.notify(&key, &facts);
    }

    /// Cached account name for a SID; queues a lookup on miss.
    pub fn user_or_request(&self, sid: &str) -> Option<String> {
        if let Some(n) = self.users.read().ok().and_then(|m| m.get(sid).cloned()) {
            return Some(n);
        }
        let key = format!("s:{sid}");
        if let Ok(mut p) = self.pending.lock() {
            if !p.insert(key.clone()) {
                return None;
            }
        }
        if self.tx.try_send(Job::Sid(sid.to_string())).is_err() {
            if let Ok(mut p) = self.pending.lock() {
                p.remove(&key);
            }
        }
        None
    }

    pub fn user_blocking(&self, sid: &str) -> Option<String> {
        if let Some(n) = self.users.read().ok().and_then(|m| m.get(sid).cloned()) {
            return Some(n);
        }
        let n = lookup_sid_string(sid)?;
        if let Ok(mut m) = self.users.write() {
            m.insert(sid.to_string(), n.clone());
        }
        Some(n)
    }
}

fn worker(e: std::sync::Weak<Enricher>, rx: Arc<Mutex<Receiver<Job>>>) {
    loop {
        let job = {
            let Ok(r) = rx.lock() else { return };
            match r.recv() {
                Ok(j) => j,
                Err(_) => return,
            }
        };
        let Some(e) = e.upgrade() else { return };
        match job {
            Job::File { path, hash } => {
                let (facts, size, mtime) = compute(&path, hash);
                e.store(&path, facts, size, mtime);
                if let Ok(mut p) = e.pending.lock() {
                    p.remove(&format!("f:{}", crate::ntpath::norm_key(&path)));
                }
            }
            Job::Sid(sid) => {
                if let Some(n) = lookup_sid_string(&sid) {
                    if let Ok(mut m) = e.users.write() {
                        m.insert(sid.clone(), n);
                    }
                }
                if let Ok(mut p) = e.pending.lock() {
                    p.remove(&format!("s:{sid}"));
                }
            }
        }
    }
}

/// First-run worker: signature first (stored immediately so the translator
/// can release a held start), then the hash.
fn prio_worker(e: std::sync::Weak<Enricher>, rx: Receiver<String>) {
    while let Ok(path) = rx.recv() {
        let Some(e) = e.upgrade() else { return };
        let (mut facts, size, mtime) = compute(&path, false);
        if size <= MAX_HASH_BYTES {
            if size > FIRST_RUN_HASH_MAX {
                // Release the start with the signature; hash afterwards.
                e.store(&path, facts.clone(), size, mtime);
            }
            facts.sha256 = hash_file(&path);
            facts.hashed = true;
        }
        e.store(&path, facts, size, mtime);
        if let Ok(mut p) = e.pending.lock() {
            p.remove(&format!("p:{}", crate::ntpath::norm_key(&path)));
        };
    }
}

/// Online revocation checks (M12), one at a time, each bounded by
/// [`REVOCATION_TIMEOUT`]; results are cached with the file facts.
fn revocation_worker(e: std::sync::Weak<Enricher>, rx: Receiver<String>) {
    let mut done: HashMap<String, Instant> = HashMap::new();
    while let Ok(path) = rx.recv() {
        let Some(e) = e.upgrade() else { return };
        let key = crate::ntpath::norm_key(&path);
        if done
            .get(&key)
            .is_some_and(|t| t.elapsed() < Duration::from_secs(3600))
        {
            e.update_cached(&path, |f| f.revocation_pending = false);
            continue;
        }
        let (tx, rrx) = std::sync::mpsc::channel();
        let p2 = path.clone();
        let _ = std::thread::Builder::new()
            .name("kestrel-revocation-check".into())
            .spawn(move || {
                super::prio::current_thread(super::prio::Background::Full);
                let _ = tx.send(verify_ex(&p2, RevMode::Online));
            });
        let verdict = rrx.recv_timeout(REVOCATION_TIMEOUT).ok();
        done.insert(key, Instant::now());
        if done.len() > 10_000 {
            done.clear();
        }
        e.update_cached(&path, |f| {
            f.revocation_pending = false;
            if let Some(v) = &verdict {
                if v.revocation == Revocation::Revoked {
                    tracing::warn!(path = %path, signer = ?f.signer, "signing certificate is revoked");
                    f.signed = SignatureState::Invalid;
                }
            }
        });
    }
}

fn hash_file(path: &str) -> Option<String> {
    if super::scan::is_remote(path) {
        return None; // V-M1
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(path)
        .ok()?;
    sha256_stream(std::io::BufReader::with_capacity(256 * 1024, file))
        .ok()
        .map(|(h, _)| h)
}

/// Compute facts for one file. Never panics; missing data stays None.
pub fn compute(path: &str, hash: bool) -> (FileFacts, u64, u64) {
    let mut f = FileFacts {
        hashed: hash,
        ..Default::default()
    };
    // V-M1: never open UNC / WebDAV / mapped-network images as SYSTEM (no
    // metadata, hash, Authenticode or Zone.Identifier read): facts stay
    // unknown. Rules see the network location through the image path.
    if super::scan::is_remote(path) {
        f.hashed = false;
        return (f, 0, 0);
    }
    let Some((size, mtime)) = meta(path) else {
        // Not readable / gone (self-deleting images, unmapped device paths):
        // the signature is *unknown*, never "invalid".
        f.hashed = false;
        return (f, 0, 0);
    };
    f.file_size = Some(size);
    if hash && size <= MAX_HASH_BYTES {
        f.sha256 = hash_file(path);
    }
    // M12: revocation for images users can plant; cache-only here.
    let mode = if user_writable(path) {
        RevMode::CacheOnly
    } else {
        RevMode::None
    };
    let v = verify_ex(path, mode);
    f.signed = v.state;
    f.signer = v.signer;
    f.microsoft_root = v.microsoft_root;
    f.sig_source = v.source;
    match v.revocation {
        Revocation::Revoked => f.signed = SignatureState::Invalid,
        Revocation::Unknown if f.signed == SignatureState::Valid => f.revocation_pending = true,
        _ => {}
    }
    f.motw_zone = std::fs::read_to_string(format!("{path}:Zone.Identifier"))
        .ok()
        .and_then(|s| crate::etwparse::parse_zone_identifier(&s));
    (f, size, mtime)
}

unsafe fn signer_from_state(state: HANDLE) -> Option<String> {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return None;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
        return None;
    }
    let cert = (*(*sgnr).pasCertChain).pCert;
    if cert.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 512];
    let n = CertGetNameStringW(
        cert,
        CERT_NAME_SIMPLE_DISPLAY_TYPE,
        0,
        std::ptr::null(),
        buf.as_mut_ptr(),
        buf.len() as u32,
    );
    if n <= 1 {
        return None;
    }
    Some(from_wide(&buf))
}

/// Does the signer's chain (from WinVerifyTrust state) end in a Microsoft root?
unsafe fn microsoft_root_from_state(state: HANDLE) -> bool {
    let prov = WTHelperProvDataFromStateData(state);
    if prov.is_null() {
        return false;
    }
    let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
    if sgnr.is_null() || (*sgnr).pChainContext.is_null() {
        return false;
    }
    let mut para: CERT_CHAIN_POLICY_PARA = std::mem::zeroed();
    para.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_PARA>() as u32;
    let mut status: CERT_CHAIN_POLICY_STATUS = std::mem::zeroed();
    status.cbSize = std::mem::size_of::<CERT_CHAIN_POLICY_STATUS>() as u32;
    CertVerifyCertificateChainPolicy(
        CERT_CHAIN_POLICY_MICROSOFT_ROOT,
        (*sgnr).pChainContext,
        &para,
        &mut status,
    ) != 0
        && status.dwError == 0
}

fn state_from_hresult(hr: i32) -> SignatureState {
    if hr == 0 {
        SignatureState::Valid
    } else if hr == TRUST_E_NOSIGNATURE
        || hr == TRUST_E_SUBJECT_FORM_UNKNOWN
        || hr == TRUST_E_PROVIDER_UNKNOWN
    {
        SignatureState::Unsigned
    } else {
        SignatureState::Invalid
    }
}

/// Revocation checking mode for [`verify_ex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevMode {
    /// No revocation checks.
    None,
    /// Whole chain, cached CRL/OCSP only (no network).
    CacheOnly,
    /// Whole chain, network retrieval allowed (background only).
    Online,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revocation {
    NotChecked,
    Good,
    Revoked,
    /// Offline / no cached revocation information.
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SigVerdict {
    pub state: SignatureState,
    pub signer: Option<String>,
    pub microsoft_root: bool,
    pub revocation: Revocation,
    pub source: SigSource,
}

/// Embedded Authenticode check with the given revocation mode, falling back
/// to the system catalogs (no revocation) for catalog-signed OS files, then
/// to the MSIX / AppX package catalog for files of an installed package.
pub fn verify_ex(path: &str, mode: RevMode) -> SigVerdict {
    // V-M1: WinVerifyTrust opens the file as SYSTEM; a network path would
    // make the machine account authenticate to that host. Unknown, not
    // invalid.
    if super::scan::is_remote(path) {
        return SigVerdict {
            state: SignatureState::Unknown,
            signer: None,
            microsoft_root: false,
            revocation: Revocation::NotChecked,
            source: SigSource::None,
        };
    }
    let wpath = wide(path);
    unsafe {
        let mut fi = WINTRUST_FILE_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: wpath.as_ptr(),
            hFile: std::ptr::null_mut(),
            pgKnownSubject: std::ptr::null_mut(),
        };
        let mut wd: WINTRUST_DATA = std::mem::zeroed();
        wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
        wd.dwUIChoice = WTD_UI_NONE;
        wd.dwUnionChoice = WTD_CHOICE_FILE;
        wd.Anonymous.pFile = &mut fi;
        wd.dwStateAction = WTD_STATEACTION_VERIFY;
        match mode {
            RevMode::None => {
                wd.fdwRevocationChecks = WTD_REVOKE_NONE;
                wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
            }
            RevMode::CacheOnly => {
                wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
                wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN;
            }
            RevMode::Online => {
                wd.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
                wd.dwProvFlags = WTD_REVOCATION_CHECK_CHAIN;
            }
        }
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        let hr = WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut c_void,
        );
        let signer = signer_from_state(wd.hWVTStateData);
        let ms_root = microsoft_root_from_state(wd.hWVTStateData);
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            std::ptr::null_mut(),
            &mut action,
            &mut wd as *mut _ as *mut c_void,
        );
        if mode != RevMode::None
            && (hr == CERT_E_REVOKED
                || hr == CRYPT_E_REVOKED
                || hr == CRYPT_E_REVOCATION_OFFLINE
                || hr == CRYPT_E_NO_REVOCATION_CHECK)
        {
            let revocation = if hr == CERT_E_REVOKED || hr == CRYPT_E_REVOKED {
                Revocation::Revoked
            } else {
                Revocation::Unknown
            };
            // The signature itself verified; only revocation is in question.
            return SigVerdict {
                state: if revocation == Revocation::Revoked {
                    SignatureState::Invalid
                } else {
                    SignatureState::Valid
                },
                signer,
                microsoft_root: ms_root,
                revocation,
                source: SigSource::Embedded,
            };
        }
        let state = state_from_hresult(hr);
        if state != SignatureState::Unsigned {
            return SigVerdict {
                state,
                signer,
                microsoft_root: ms_root && state == SignatureState::Valid,
                revocation: match (mode, state) {
                    (RevMode::None, _) => Revocation::NotChecked,
                    (_, SignatureState::Valid) => Revocation::Good,
                    _ => Revocation::NotChecked,
                },
                source: SigSource::Embedded,
            };
        }
        // Catalog fallback (OS files).
        for alg in ["SHA256", "SHA1"] {
            if let Some((state, signer, ms)) = verify_catalog(path, alg) {
                return SigVerdict {
                    state,
                    signer,
                    microsoft_root: ms && state == SignatureState::Valid,
                    revocation: Revocation::NotChecked,
                    source: SigSource::SystemCatalog,
                };
            }
        }
        // MSIX / AppX: the package's code-integrity catalog (owner PC
        // 2026-10-22: WhatsApp.Root.exe from the Store was "unsigned").
        if let Some(cat) = crate::filters::msix_code_integrity_catalog(path) {
            if let Some((state, signer)) = verify_package_catalog(path, &cat) {
                return SigVerdict {
                    state,
                    signer,
                    // A Store publisher certificate chains to a Microsoft
                    // root (Microsoft Marketplace CA) without the file being
                    // Microsoft's: never a Microsoft-root verdict here.
                    microsoft_root: false,
                    revocation: Revocation::NotChecked,
                    source: SigSource::PackageCatalog,
                };
            }
        }
        SigVerdict {
            state: SignatureState::Unsigned,
            signer: None,
            microsoft_root: false,
            revocation: Revocation::NotChecked,
            source: SigSource::None,
        }
    }
}

/// (state, signer, chains to a Microsoft root) — used by response safety
/// checks (protected processes, quarantine of OS files).
pub fn verify_signature_ms(path: &str) -> (SignatureState, Option<String>, bool) {
    let v = verify_ex(path, RevMode::None);
    (v.state, v.signer, v.microsoft_root)
}

/// WinVerifyTrust of `member` (file handle + its catalog hash) against the
/// catalog file `catalog` (NUL-terminated wide path), no revocation.
/// Returns (HRESULT, signer, chains to a Microsoft root).
unsafe fn verify_catalog_member(
    catalog: *const u16,
    member_tag: *const u16,
    path: &str,
    hfile: HANDLE,
    hash: &mut [u8],
    admin: isize,
) -> (i32, Option<String>, bool) {
    let wpath = wide(path);
    let mut wci: WINTRUST_CATALOG_INFO = std::mem::zeroed();
    wci.cbStruct = std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32;
    wci.pcwszCatalogFilePath = catalog;
    wci.pcwszMemberTag = member_tag;
    wci.pcwszMemberFilePath = wpath.as_ptr();
    wci.hMemberFile = hfile;
    wci.pbCalculatedFileHash = hash.as_mut_ptr();
    wci.cbCalculatedFileHash = hash.len() as u32;
    wci.hCatAdmin = admin;
    let mut wd: WINTRUST_DATA = std::mem::zeroed();
    wd.cbStruct = std::mem::size_of::<WINTRUST_DATA>() as u32;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.Anonymous.pCatalog = &mut wci;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let hr = WinVerifyTrust(
        std::ptr::null_mut(),
        &mut action,
        &mut wd as *mut _ as *mut c_void,
    );
    let signer = signer_from_state(wd.hWVTStateData);
    let ms_root = microsoft_root_from_state(wd.hWVTStateData);
    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(
        std::ptr::null_mut(),
        &mut action,
        &mut wd as *mut _ as *mut c_void,
    );
    (hr, signer, ms_root)
}

fn hex_upper(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02X}")).collect()
}

unsafe fn verify_catalog(path: &str, alg: &str) -> Option<(SignatureState, Option<String>, bool)> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(path)
        .ok()?;
    use std::os::windows::io::AsRawHandle;
    let hfile = file.as_raw_handle() as HANDLE;
    let walg = wide(alg);
    let mut admin: isize = 0;
    if CryptCATAdminAcquireContext2(
        &mut admin,
        std::ptr::null(),
        walg.as_ptr(),
        std::ptr::null(),
        0,
    ) == 0
    {
        return None;
    }
    let mut result = None;
    let mut hash = vec![0u8; 64];
    let mut cb = hash.len() as u32;
    if CryptCATAdminCalcHashFromFileHandle2(admin, hfile, &mut cb, hash.as_mut_ptr(), 0) != 0 {
        hash.truncate(cb as usize);
        let mut prev: isize = 0;
        let cat = CryptCATAdminEnumCatalogFromHash(admin, hash.as_ptr(), cb, 0, &mut prev);
        if cat != 0 {
            let mut ci: CATALOG_INFO = std::mem::zeroed();
            ci.cbStruct = std::mem::size_of::<CATALOG_INFO>() as u32;
            if CryptCATCatalogInfoFromContext(cat, &mut ci, 0) != 0 {
                let wtag = wide(&hex_upper(&hash));
                let (hr, signer, ms_root) = verify_catalog_member(
                    ci.wszCatalogFile.as_ptr(),
                    wtag.as_ptr(),
                    path,
                    hfile,
                    &mut hash,
                    admin,
                );
                result = Some((
                    if hr == 0 {
                        SignatureState::Valid
                    } else {
                        SignatureState::Invalid
                    },
                    signer,
                    ms_root,
                ));
            }
            CryptCATAdminReleaseCatalogContext(admin, cat, 0);
        }
    }
    CryptCATAdminReleaseContext(admin, 0);
    drop(file);
    result
}

/// Copy a NUL-terminated wide string (bounded) including the terminator.
unsafe fn wide_copy(p: *const u16) -> Option<Vec<u16>> {
    if p.is_null() {
        return None;
    }
    let mut v = Vec::new();
    for i in 0..4096 {
        let c = *p.add(i);
        v.push(c);
        if c == 0 {
            return Some(v);
        }
    }
    None
}

/// Reference tag of the member of catalog `wcat` whose digest is `hash`:
/// by the conventional tag (hex of the hash) first, else by comparing every
/// member's indirect-data digest (tags of package catalogs are not
/// guaranteed to follow the convention).
unsafe fn catalog_member_tag(wcat: &[u16], hash: &[u8]) -> Option<Vec<u16>> {
    let hcat = CryptCATOpen(wcat.as_ptr(), CRYPTCAT_OPEN_EXISTING, 0, 0, 0);
    if hcat.is_null() || hcat == INVALID_HANDLE_VALUE {
        return None;
    }
    let wtag = wide(&hex_upper(hash));
    let mut found = None;
    if !CryptCATGetMemberInfo(hcat, wtag.as_ptr()).is_null() {
        found = Some(wtag);
    } else {
        let mut prev: *mut CRYPTCATMEMBER = std::ptr::null_mut();
        // Bounded walk (a package catalog lists the package's PE files).
        for _ in 0..1_000_000 {
            let m = CryptCATEnumerateMember(hcat, prev);
            if m.is_null() {
                break;
            }
            let ind = (*m).pIndirectData;
            if !ind.is_null() {
                let d = &(*ind).Digest;
                if !d.pbData.is_null()
                    && d.cbData as usize == hash.len()
                    && std::slice::from_raw_parts(d.pbData, d.cbData as usize) == hash
                {
                    found = wide_copy((*m).pwszReferenceTag);
                    break;
                }
            }
            prev = m;
        }
    }
    CryptCATClose(hcat);
    found
}

/// Verify a file of an installed MSIX / AppX package against the package's
/// `AppxMetadata\CodeIntegrity.cat` (Authenticode hashes of the package's PE
/// files, signed with the package certificate). Some(Valid) only when the
/// file's hash is a member and WinVerifyTrust accepts the catalog signature;
/// Some(Invalid) for a bad digest / revoked certificate; None (no verdict:
/// the caller keeps "unsigned") when the file is not in the catalog or the
/// catalog's chain is not trusted on this machine (e.g. a sideloaded
/// developer package): never "valid" for something WinVerifyTrust rejected.
unsafe fn verify_package_catalog(
    path: &str,
    catalog: &str,
) -> Option<(SignatureState, Option<String>)> {
    if !std::path::Path::new(catalog).is_file() {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(7)
        .open(path)
        .ok()?;
    use std::os::windows::io::AsRawHandle;
    let hfile = file.as_raw_handle() as HANDLE;
    let wcat = wide(catalog);
    for alg in ["SHA256", "SHA1"] {
        let walg = wide(alg);
        let mut admin: isize = 0;
        if CryptCATAdminAcquireContext2(
            &mut admin,
            std::ptr::null(),
            walg.as_ptr(),
            std::ptr::null(),
            0,
        ) == 0
        {
            continue;
        }
        let mut verdict = None;
        let mut hash = vec![0u8; 64];
        let mut cb = hash.len() as u32;
        if CryptCATAdminCalcHashFromFileHandle2(admin, hfile, &mut cb, hash.as_mut_ptr(), 0) != 0 {
            hash.truncate(cb as usize);
            if let Some(tag) = catalog_member_tag(&wcat, &hash) {
                let (hr, signer, _) = verify_catalog_member(
                    wcat.as_ptr(),
                    tag.as_ptr(),
                    path,
                    hfile,
                    &mut hash,
                    admin,
                );
                verdict = match package_catalog_state(hr) {
                    Some(state) => Some((state, signer)),
                    None => {
                        tracing::debug!(
                            path,
                            hr = format_args!("{hr:#010x}"),
                            "package catalog signature not trusted"
                        );
                        None
                    }
                };
            }
        }
        CryptCATAdminReleaseContext(admin, 0);
        if verdict.is_some() {
            return verdict;
        }
    }
    drop(file);
    None
}

/// Verdict of a package-catalog WinVerifyTrust result: valid, definitely
/// invalid (digest mismatch, revoked), or no verdict (chain / policy
/// failures: not trusted here, which is not proof of tampering).
fn package_catalog_state(hr: i32) -> Option<SignatureState> {
    if hr == 0 {
        Some(SignatureState::Valid)
    } else if hr == TRUST_E_BAD_DIGEST || hr == CERT_E_REVOKED || hr == CRYPT_E_REVOKED {
        Some(SignatureState::Invalid)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_catalog_verdicts() {
        assert_eq!(package_catalog_state(0), Some(SignatureState::Valid));
        assert_eq!(
            package_catalog_state(TRUST_E_BAD_DIGEST),
            Some(SignatureState::Invalid)
        );
        assert_eq!(
            package_catalog_state(CERT_E_REVOKED),
            Some(SignatureState::Invalid)
        );
        // Untrusted root / wrong usage: no verdict (stays unsigned), never valid.
        assert_eq!(package_catalog_state(0x800B0109_u32 as i32), None);
        assert_eq!(package_catalog_state(0x800B0110_u32 as i32), None);
        assert_eq!(package_catalog_state(TRUST_E_NOSIGNATURE), None);
    }

    /// Lab / developer check against a real packaged executable (read-only
    /// signature verification). Set `KESTREL_TEST_MSIX_EXE` to e.g.
    /// `C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_…\WhatsApp.Root.exe`.
    #[test]
    fn msix_packaged_exe_is_package_catalog_signed() {
        let Ok(p) = std::env::var("KESTREL_TEST_MSIX_EXE") else {
            return;
        };
        let v = verify_ex(&p, RevMode::None);
        eprintln!("{p}: {v:?}");
        assert_eq!(v.state, SignatureState::Valid);
        assert_eq!(v.source, SigSource::PackageCatalog);
        assert!(v.signer.is_some());
        assert!(!v.microsoft_root);
    }

    /// An OS binary signed only by catalog keeps verifying (system catalog).
    #[test]
    fn os_binary_still_verifies() {
        let p = format!(r"{}\System32\cmd.exe", super::super::util::system_root());
        if !std::path::Path::new(&p).is_file() {
            return;
        }
        let v = verify_ex(&p, RevMode::None);
        assert_eq!(v.state, SignatureState::Valid, "{v:?}");
        assert_ne!(v.source, SigSource::PackageCatalog);
    }
}
