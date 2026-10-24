//! `EvidenceHost` for Windows (evidence capture for suspected data theft,
//! `docs/DECISIONS.md` 2026-10-25): private evidence folder, DPAPI-protected
//! bundle key, link-safe read-only opens of source files, and the
//! `PktMon.exe` packet capture ([`super::pktmon`]).
//!
//! Source files are opened with the same link checks as quarantine
//! ([`super::safefs`]): every ancestor directory opened with
//! `FILE_OPEN_REPARSE_POINT` and refused when it is a junction / symbolic
//! link / mount point, the file itself not a name surrogate, exactly one
//! hard link, and `GetFinalPathNameByHandleW` equal to the request. The
//! errors are kept structured here (NTSTATUS) instead of
//! `safefs::open_verified_file`'s strings, and the returned reader owns the
//! verified handle (never a re-open by path). Read-only, sharing read /
//! write / delete: the owner of the file is never blocked.
//!
//! Never stalled by an unprivileged process (security review 2026-10-25,
//! H2): opens use `NtCreateFile` with `FILE_COMPLETE_IF_OPLOCKED` (an oplock
//! whose break is never acknowledged gives `Locked`, nothing waits), cloud
//! placeholders are never hydrated as SYSTEM (refused, not collected), and
//! every read is cancelled (`CancelSynchronousIo`) after [`READ_DEADLINE`]
//! without completing.

use super::quarantine::dpapi;
use super::safefs::{attr_tag, final_path, is_name_surrogate, link_count, long_path};
use super::util::*;
use crate::evidence_plan::{
    check_source_path, classify_ntstatus, nt_object_path, own_prefixes, reparse_action,
    ReparseAction, STATUS_OPLOCK_BREAK_IN_PROGRESS,
};
use crate::qpolicy;
use kestrel_platform::{EvidenceHost, PacketCapture, SourceError, SourceFile};
use std::collections::HashMap;
use std::io::{self, Read};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_COMPLETE_IF_OPLOCKED, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{HANDLE, UNICODE_STRING};
use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetFileSizeEx, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::{GetCurrentThreadId, OpenThread, THREAD_TERMINATE};
use windows_sys::Win32::System::IO::{CancelSynchronousIo, IO_STATUS_BLOCK};

const KEY_FILE: &str = "key.dpapi";
const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

pub struct WinEvidence {
    dir: PathBuf,
    own: Vec<String>,
    dir_ready: Mutex<bool>,
    key: Mutex<Option<[u8; 32]>>,
    pcap: OnceLock<Option<Arc<super::pktmon::PktMon>>>,
}

impl WinEvidence {
    /// `own_dirs`: the agent's state folder and install folder.
    pub fn new(state_dir: &Path, own_dirs: &[String]) -> Self {
        WinEvidence {
            dir: state_dir.join("evidence"),
            own: own_prefixes(own_dirs),
            dir_ready: Mutex::new(false),
            key: Mutex::new(None),
            pcap: OnceLock::new(),
        }
    }

    /// Create the evidence folder (SYSTEM + Administrators only, protected
    /// DACL, like the quarantine folder) once.
    fn ensure_dir(&self) -> io::Result<()> {
        let mut ready = self
            .dir_ready
            .lock()
            .map_err(|_| io::Error::other("evidence folder lock poisoned"))?;
        if !*ready {
            ensure_private_dir(&self.dir)?;
            *ready = true;
        }
        Ok(())
    }
}

/// `NtCreateFile(FILE_OPEN)` of an absolute, checked `C:\…` path, with
/// backup intent and `FILE_COMPLETE_IF_OPLOCKED`: an oplock held by another
/// program (even one that never acknowledges the break) never makes the
/// open wait. Returns the handle and whether an oplock break is in
/// progress (`STATUS_OPLOCK_BREAK_IN_PROGRESS`).
fn nt_open(dos: &str, access: u32, open_reparse: bool) -> Result<(Handle, bool), SourceError> {
    let name: Vec<u16> = nt_object_path(dos).encode_utf16().collect();
    let bytes = name.len() * 2;
    if bytes > u16::MAX as usize - 2 {
        return Err(SourceError::Other("path too long".into()));
    }
    let us = UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: bytes as u16,
        Buffer: name.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE as _,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    let mut options =
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_FOR_BACKUP_INTENT | FILE_COMPLETE_IF_OPLOCKED;
    if open_reparse {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: all pointers reference live locals for the duration of the call.
    let st = unsafe {
        NtCreateFile(
            &mut h,
            access | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            0,
            SHARE_ALL,
            FILE_OPEN,
            options,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 {
        return Err(classify_ntstatus(st as u32));
    }
    let h = Handle::new(h).ok_or_else(|| SourceError::Other("no handle".into()))?;
    Ok((h, st as u32 == STATUS_OPLOCK_BREAK_IN_PROGRESS))
}

/// Open an existing file without following links anywhere on its path
/// (see the module docs). `access` is added to `FILE_READ_ATTRIBUTES`.
/// `for_read`: the data will be read, so an oplock break in progress is
/// `Locked` (never waited for) and cloud placeholders / unknown reparse
/// points are refused ([`reparse_action`]); attribute-only opens
/// (`file_size`) accept both.
fn open_checked(path: &str, access: u32, for_read: bool) -> Result<(Handle, String), SourceError> {
    let p = check_source_path(path)?;
    let req = long_path(&p);
    // GetLongPathNameW may return another spelling; check it again.
    check_source_path(&req)?;
    for dir in qpolicy::ancestors(&req) {
        // Attribute queries only: an oplock break in progress is harmless.
        let (h, _) = nt_open(&dir, 0, true).map_err(|e| match e {
            SourceError::NotAFile => SourceError::NotFound,
            e => e,
        })?;
        let (attrs, tag) = attr_tag(&h)
            .ok_or_else(|| SourceError::Other("cannot query a parent folder".into()))?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate(tag) {
            return Err(SourceError::Link(format!(
                "{dir} is a junction / symbolic link; not followed"
            )));
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(SourceError::NotFound);
        }
    }
    let (mut h, mut breaking) = nt_open(&req, access, true)?;
    let (attrs, tag) =
        attr_tag(&h).ok_or_else(|| SourceError::Other("cannot query the file".into()))?;
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(SourceError::NotAFile);
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        match reparse_action(tag) {
            ReparseAction::Refuse(e @ SourceError::Link(_)) => return Err(e),
            // Size / attributes of a placeholder are fine without hydrating.
            ReparseAction::Refuse(_) if !for_read => {}
            ReparseAction::Refuse(e) => return Err(e),
            ReparseAction::ReopenDedup => {
                // The dedup filter serves the data; the final-path check
                // below still applies to the new handle.
                (h, breaking) = nt_open(&req, access, false)?;
                let (attrs, _) = attr_tag(&h)
                    .ok_or_else(|| SourceError::Other("cannot query the file".into()))?;
                if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
                    return Err(SourceError::NotAFile);
                }
            }
        }
    }
    if breaking && for_read {
        return Err(SourceError::Locked);
    }
    match link_count(&h) {
        Some(1) => {}
        Some(n) => {
            return Err(SourceError::Link(format!(
                "the file has {n} hard links; not collected"
            )))
        }
        None => return Err(SourceError::Other("cannot query the link count".into())),
    }
    let fp = final_path(&h).ok_or_else(|| SourceError::Other("cannot resolve the path".into()))?;
    if !qpolicy::same_path(&req, &fp) {
        return Err(SourceError::Link(format!(
            "the path resolves to {fp}; not followed"
        )));
    }
    Ok((h, req))
}

/// SID string of an account name (`DOMAIN\name`). May block on a domain
/// lookup: called on the bundle builder's blocking thread only.
fn account_sid(user: &str) -> Option<String> {
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};
    let user = user.trim();
    if user.is_empty() || user.contains('\0') || user.len() > 512 {
        return None;
    }
    let name = wide(user);
    let mut sid = vec![0u8; 256];
    let mut dom = vec![0u16; 256];
    for _ in 0..2 {
        let mut sid_len = sid.len() as u32;
        let mut dom_len = dom.len() as u32;
        let mut use_: SID_NAME_USE = 0;
        // SAFETY: NUL-terminated name; buffers and lengths match.
        let ok = unsafe {
            LookupAccountNameW(
                std::ptr::null(),
                name.as_ptr(),
                sid.as_mut_ptr() as _,
                &mut sid_len,
                dom.as_mut_ptr(),
                &mut dom_len,
                &mut use_,
            )
        };
        if ok != 0 {
            return sid_to_string(sid.as_mut_ptr() as _);
        }
        // ERROR_INSUFFICIENT_BUFFER: retry once with the reported sizes.
        if (sid_len as usize) <= sid.len() && (dom_len as usize) <= dom.len() {
            return None;
        }
        sid.resize((sid_len as usize).clamp(256, 4096), 0);
        dom.resize((dom_len as usize).clamp(256, 4096), 0);
    }
    None
}

/// `ProfileImagePath` of a SID (environment variables expanded).
fn profile_of_sid(sid: &str) -> Option<String> {
    use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
    if !sid.starts_with("S-1-") || sid.contains('\\') {
        return None;
    }
    let k = reg_open(
        HKEY_LOCAL_MACHINE,
        &format!(r"{}\{sid}", crate::consts::reg::PROFILE_LIST),
        false,
    )?;
    let p = reg_get_string(&k, "ProfileImagePath")?;
    let p = crate::ntpath::expand_env(p.trim(), |n| std::env::var(n).ok());
    (!p.is_empty()).then_some(p)
}

fn handle_size(h: &Handle) -> Option<u64> {
    let mut size: i64 = 0;
    let ok = unsafe { GetFileSizeEx(h.raw(), &mut size) };
    (ok != 0 && size >= 0).then_some(size as u64)
}

// ------------------------------------------------------------ read deadline

/// A single read of a source file that makes no progress for this long is
/// cancelled (`CancelSynchronousIo`) and fails: a stuck file system filter /
/// provider never stalls the bundle builder.
pub const READ_DEADLINE: Duration = Duration::from_secs(30);

struct Armed {
    thread: Handle,
    since: Instant,
    fired: bool,
}

/// Watches reads in progress (one thread for the process, started on first
/// use).
struct ReadWatchdog {
    reads: Mutex<HashMap<u64, Armed>>,
    next: AtomicU64,
}

fn watchdog() -> &'static ReadWatchdog {
    static WD: OnceLock<&'static ReadWatchdog> = OnceLock::new();
    WD.get_or_init(|| {
        let wd: &'static ReadWatchdog = Box::leak(Box::new(ReadWatchdog {
            reads: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
        }));
        let spawned = std::thread::Builder::new()
            .name("kestrel-evidence-read-watchdog".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(500));
                if let Ok(mut m) = wd.reads.lock() {
                    for a in m.values_mut() {
                        // Cancelled under the lock: the reading thread
                        // cannot have moved on to other I/O (it removes its
                        // entry under the same lock first).
                        if !a.fired && a.since.elapsed() >= READ_DEADLINE {
                            // SAFETY: valid thread handle with THREAD_TERMINATE.
                            if unsafe { CancelSynchronousIo(a.thread.raw()) } != 0 {
                                a.fired = true;
                            }
                        }
                    }
                }
            });
        if let Err(e) = spawned {
            tracing::warn!("evidence read watchdog not started: {e}");
        }
        wd
    })
}

impl ReadWatchdog {
    fn arm(&self) -> Option<u64> {
        // SAFETY: plain Win32 calls; the handle is owned by `Armed`.
        let h = unsafe { OpenThread(THREAD_TERMINATE, 0, GetCurrentThreadId()) };
        let thread = Handle::new(h)?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.reads.lock().ok()?.insert(
            id,
            Armed {
                thread,
                since: Instant::now(),
                fired: false,
            },
        );
        Some(id)
    }

    /// Remove the entry; whether the read was cancelled.
    fn disarm(&self, id: u64) -> bool {
        self.reads
            .lock()
            .ok()
            .and_then(|mut m| m.remove(&id))
            .is_some_and(|a| a.fired)
    }
}

/// Reader of a verified source file: owns the handle (never a re-open by
/// path); every read has the [`READ_DEADLINE`].
struct DeadlineReader {
    file: std::fs::File,
    failed: bool,
}

impl Read for DeadlineReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "an earlier read of this file stalled and was cancelled",
            ));
        }
        let wd = watchdog();
        let Some(id) = wd.arm() else {
            return Err(io::Error::other("cannot arm the read deadline"));
        };
        let r = self.file.read(buf);
        if wd.disarm(id) {
            self.failed = true;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "read made no progress for 30 s; cancelled",
            ));
        }
        r
    }
}

impl EvidenceHost for WinEvidence {
    fn evidence_dir(&self) -> PathBuf {
        if let Err(e) = self.ensure_dir() {
            tracing::warn!("evidence folder {}: {e}", self.dir.display());
        }
        self.dir.clone()
    }

    fn bundle_key(&self) -> Result<[u8; 32], String> {
        let mut g = self
            .key
            .lock()
            .map_err(|_| "evidence key lock poisoned".to_string())?;
        if let Some(k) = *g {
            return Ok(k);
        }
        self.ensure_dir()
            .map_err(|e| format!("evidence folder: {e}"))?;
        let path = self.dir.join(KEY_FILE);
        let key: [u8; 32] = match std::fs::read(&path) {
            Ok(blob) => {
                let k = dpapi(&blob, false).map_err(|e| format!("evidence key: {e}"))?;
                k.try_into()
                    .map_err(|_| "evidence key: bad length".to_string())?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut k = [0u8; 32];
                getrandom::getrandom(&mut k).map_err(|e| format!("random: {e}"))?;
                let blob = dpapi(&k, true).map_err(|e| format!("evidence key: {e}"))?;
                write_atomic(&path, &blob).map_err(|e| format!("evidence key: {e}"))?;
                k
            }
            Err(e) => return Err(format!("evidence key: {e}")),
        };
        *g = Some(key);
        Ok(key)
    }

    fn own_prefixes(&self) -> Vec<String> {
        self.own.clone()
    }

    fn open_source(&self, path: &str, max_bytes: u64) -> Result<SourceFile, SourceError> {
        let (h, verified) = open_checked(path, FILE_GENERIC_READ, true)?;
        let size =
            handle_size(&h).ok_or_else(|| SourceError::Other("cannot read the size".into()))?;
        if size > max_bytes {
            return Err(SourceError::TooLarge(size));
        }
        // The reader owns the verified handle (synchronous, no re-open).
        let raw = h.0;
        std::mem::forget(h);
        // SAFETY: `raw` is an open file handle we exclusively own from here.
        let file = unsafe { std::fs::File::from_raw_handle(raw as _) };
        Ok(SourceFile {
            reader: Box::new(DeadlineReader {
                file,
                failed: false,
            }),
            size,
            path: verified,
        })
    }

    fn file_size(&self, path: &str) -> Option<u64> {
        // Attributes-only open (FILE_COMPLETE_IF_OPLOCKED, no hydration):
        // works on files a browser holds without read sharing.
        let (h, _) = open_checked(path, 0, false).ok()?;
        handle_size(&h)
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        // Attributes-only open with every link check; the returned path is
        // the long form that equals the handle's final path (M1).
        let (_, verified) = open_checked(path, 0, false).ok()?;
        Some(verified)
    }

    fn profile_dir(&self, user: &str) -> Option<String> {
        profile_of_sid(&account_sid(user)?)
    }

    fn free_bytes(&self) -> Option<u64> {
        self.ensure_dir().ok()?;
        let w = wide_path(&self.dir);
        let mut avail = 0u64;
        // SAFETY: NUL-terminated path, out pointers to locals.
        let ok = unsafe {
            GetDiskFreeSpaceExW(
                w.as_ptr(),
                &mut avail,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(avail)
    }

    fn packet_capture(&self) -> Option<Arc<dyn PacketCapture>> {
        let p = self
            .pcap
            .get_or_init(|| super::pktmon::PktMon::detect().map(Arc::new));
        p.clone().map(|p| p as Arc<dyn PacketCapture>)
    }
}
