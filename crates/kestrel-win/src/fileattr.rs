//! Kernel-File open attribution and the own-profile `Local State` forward
//! (pure, Linux-testable). `docs/DETECTION-QUALITY.md` FP-01 / FP-04,
//! `docs/DECISIONS.md` 2026-10-25 "Sensor: file-open attribution and
//! `Local State` opens".
//!
//! ## Issuing thread (FP-01 hardening)
//! Microsoft-Windows-Kernel-File Create (12) and CreateNewFile (30) carry the
//! thread that issued the I/O: `IssuingThreadId` (UInt32, template version 1)
//! or `ThreadId` (Pointer, version 0) — manifest on build 26200
//! (`(Get-WinEvent -ListProvider Microsoft-Windows-Kernel-File).Events`). The
//! event header's ProcessId / ThreadId describe the context the event was
//! *logged* in. They agree for a synchronous create; when they do not (an I/O
//! logged from a worker or another context), the header pid names the wrong
//! process. [`issuer`] decides which pid an open belongs to: the header's
//! when the threads agree (no syscall on the hot path), otherwise the
//! issuing thread's process, and nothing when that cannot be resolved (the
//! open is dropped and counted rather than blamed on whoever's context
//! logged it).
//!
//! ## File-object names
//! With first-read events on, the translator remembers the name of each
//! (pid, FileObject) from its Create. A FileObject address is reused after
//! close and a pid after exit, so a stale entry could name a later read of a
//! different process / file. [`FileObjects`] only resolves a read to the
//! name recorded at the create when both belong to the same process
//! instance (checked by the caller against the pid tracker).
//!
//! ## `Local State` (FP-04)
//! Chromium / Electron apps (Discord, VS Code, Slack, Xeno, Teams, …) read
//! their own profile's `Local State` (the DPAPI-wrapped `os_crypt` key)
//! right before the DPAPI "Chromium" decrypt. Only known browser / app stores
//! passed the source filter, so the engine could not tell an app decrypting
//! its own key from a stealer reading a browser's. Opens of any file named
//! `Local State` now pass the callback filter ([`is_local_state`]), and the
//! translator forwards those not already sensitive when they are under a
//! user profile ([`under_user_profile`]) or under the process's last
//! `--user-data-dir` ([`user_data_dir`]), once per (process instance, path)
//! and at most [`LOCAL_STATE_PER_PROCESS`] paths per instance
//! ([`LocalStateSeen`]).

use kestrel_common::ProcessGuid;
use std::collections::HashMap;

/// Which process an open belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issuer {
    /// The event header's pid (issuing thread = logging thread, or the
    /// event carried no issuing thread).
    Header,
    /// The issuing thread belongs to this other process.
    Other(u32),
    /// The issuing thread differs from the logging thread and its process
    /// could not be determined (thread gone, or created after the event).
    Unresolved,
}

/// Attribute a Kernel-File open. `issuing_tid` = the event's
/// `IssuingThreadId` / `ThreadId` field (None or 0 = absent); `resolve`
/// maps a thread id to its process id (called only when the threads differ).
pub fn issuer(
    header_pid: u32,
    header_tid: u32,
    issuing_tid: Option<u32>,
    resolve: impl FnOnce(u32) -> Option<u32>,
) -> Issuer {
    let Some(tid) = issuing_tid.filter(|t| *t != 0) else {
        return Issuer::Header;
    };
    if tid == header_tid {
        return Issuer::Header;
    }
    match resolve(tid) {
        Some(p) if p == header_pid => Issuer::Header,
        Some(p) => Issuer::Other(p),
        None => Issuer::Unresolved,
    }
}

/// Slack when checking that a resolved thread already existed at the
/// event's time: ETW timestamps are QPC-based and drift slightly from the
/// wall clock that `GetThreadTimes` reports.
pub const THREAD_CREATE_SLACK_MS: i64 = 2_000;

/// Is a thread created at `thread_create_ms` (wall clock) a plausible
/// issuer of an event at `event_ts_ms`? A thread id reused after the event
/// (created later) is not.
pub fn thread_existed_at(thread_create_ms: i64, event_ts_ms: i64) -> bool {
    thread_create_ms <= event_ts_ms.saturating_add(THREAD_CREATE_SLACK_MS)
}

#[derive(Debug, Clone)]
struct FoEntry {
    path: String,
    create_ts: i64,
    reported: bool,
}

/// (pid, FileObject) → name from the Create, for first-read events.
#[derive(Debug, Default)]
pub struct FileObjects {
    map: HashMap<(u32, u64), FoEntry>,
}

/// Bound on remembered file objects (cleared past it: reads are only a
/// secondary signal).
pub const MAX_FILE_OBJECTS: usize = 100_000;

/// Entries older than this are forgotten by [`FileObjects::gc`].
pub const FILE_OBJECT_TTL_MS: i64 = 10 * 60_000;

impl FileObjects {
    /// A Create of `fo` by `pid`: any older name for that pair is replaced.
    pub fn on_create(&mut self, pid: u32, fo: u64, path: String, ts: i64) {
        if fo == 0 {
            return;
        }
        if self.map.len() >= MAX_FILE_OBJECTS {
            self.map.clear();
        }
        self.map.insert(
            (pid, fo),
            FoEntry {
                path,
                create_ts: ts,
                reported: false,
            },
        );
    }

    /// Forget the name of (pid, fo) (a create that will not be tracked).
    pub fn forget(&mut self, pid: u32, fo: u64) {
        self.map.remove(&(pid, fo));
    }

    /// First read of (pid, fo) at `ts`: the name from its Create, once.
    /// `same_instance(create_ts, read_ts)` must say whether the process that
    /// owned `pid` at the create is the one that owns it at the read; if not
    /// (pid reused, FileObject address reused by the new owner whose Create
    /// was not seen) the entry is stale: it is removed and nothing is named.
    pub fn first_read(
        &mut self,
        pid: u32,
        fo: u64,
        ts: i64,
        same_instance: impl FnOnce(i64, i64) -> bool,
    ) -> Option<String> {
        let e = self.map.get_mut(&(pid, fo))?;
        if ts < e.create_ts || !same_instance(e.create_ts, ts) {
            self.map.remove(&(pid, fo));
            return None;
        }
        if e.reported {
            return None;
        }
        e.reported = true;
        Some(e.path.clone())
    }

    pub fn gc(&mut self, now: i64) {
        self.map
            .retain(|_, e| now - e.create_ts < FILE_OBJECT_TTL_MS);
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Is the last component of `path` (NT or Win32, any case, either slash)
/// `Local State`?
pub fn is_local_state(path: &str) -> bool {
    let p = path.trim_end_matches(['\\', '/']);
    if p.len() < path.len() {
        return false; // a directory spelled with a trailing separator
    }
    let name = p.rsplit(['\\', '/']).next().unwrap_or(p);
    name.eq_ignore_ascii_case("local state")
}

/// Volume-relative, lower-cased, backslash form of a Win32 path
/// (`C:\x` → `\x`, `\\?\C:\x` → `\x`, `\\srv\share\x` → `\srv\share\x`).
fn rel_lower(path: &str) -> String {
    let p = path.replace('/', "\\");
    let p = p
        .strip_prefix(r"\\?\")
        .or_else(|| p.strip_prefix(r"\??\"))
        .unwrap_or(&p);
    let b = p.as_bytes();
    let r = if b.len() >= 2 && b[1] == b':' {
        &p[2..]
    } else if p.starts_with(r"\\") {
        &p[1..]
    } else {
        p
    };
    r.to_ascii_lowercase()
}

/// Is `path` (Win32) inside a user profile, i.e. `<volume>:\Users\<name>\…`
/// with a real name component? Local disks only (no UNC paths), no `..`.
pub fn under_user_profile(path: &str) -> bool {
    let raw = path.replace('/', "\\");
    if raw.starts_with(r"\\") && !raw.starts_with(r"\\?\") {
        return false;
    }
    let rel = rel_lower(path);
    let Some(rest) = rel.strip_prefix(r"\users\") else {
        return false;
    };
    let mut comps = rest.split('\\');
    let user = comps.next().unwrap_or("");
    !user.is_empty() && user != "." && comps.next().is_some() && !rel.split('\\').any(|c| c == "..")
}

/// The last `--user-data-dir` value on a command line (Chromium honours the
/// last one), without quotes or trailing separators. Accepts
/// `--user-data-dir=C:\x`, `--user-data-dir="C:\x y"`,
/// `"--user-data-dir=C:\x y"` and the space-separated form
/// `--user-data-dir C:\x` some launchers use.
pub fn user_data_dir(cmdline: &str) -> Option<String> {
    const SW: &str = "--user-data-dir";
    let lower = cmdline.to_ascii_lowercase();
    let b = cmdline.as_bytes();
    let mut found = None;
    let mut from = 0;
    while let Some(i) = lower[from..].find(SW).map(|i| i + from) {
        from = i + SW.len();
        let at_token = i == 0 || b[i - 1].is_ascii_whitespace() || b[i - 1] == b'"';
        if !at_token {
            continue;
        }
        let quoted_token = i > 0 && b[i - 1] == b'"';
        let mut j = i + SW.len();
        match b.get(j) {
            Some(b'=') => j += 1,
            Some(c) if c.is_ascii_whitespace() && !quoted_token => {
                while j < b.len() && b[j].is_ascii_whitespace() {
                    j += 1;
                }
            }
            _ => continue,
        }
        let (start, until_quote) = if b.get(j) == Some(&b'"') {
            (j + 1, true)
        } else {
            (j, quoted_token)
        };
        let mut k = start;
        while k < b.len() && b[k] != b'"' && (until_quote || !b[k].is_ascii_whitespace()) {
            k += 1;
        }
        let v = cmdline[start..k].trim().trim_end_matches(['\\', '/']);
        if !v.is_empty() && !v.starts_with('-') {
            found = Some(v.to_string());
        }
        from = k.max(from);
    }
    found
}

/// Is `path` inside directory `dir` (both Win32, any case)? `..` in either
/// never matches.
pub fn under_dir(path: &str, dir: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let d = dir.replace('/', "\\").to_ascii_lowercase();
    let d = d.trim_end_matches('\\');
    if d.is_empty() || p.split('\\').any(|c| c == "..") || d.split('\\').any(|c| c == "..") {
        return false;
    }
    p.len() > d.len() + 1 && p.starts_with(d) && p.as_bytes()[d.len()] == b'\\'
}

/// Distinct `Local State` paths forwarded per process instance.
pub const LOCAL_STATE_PER_PROCESS: usize = 16;
/// Process instances remembered (cleared past it: at worst an app's own
/// `Local State` is reported once more).
pub const LOCAL_STATE_MAX_PROCESSES: usize = 4_096;

/// Once-per-instance de-duplication of the extra `Local State` opens.
#[derive(Debug, Default)]
pub struct LocalStateSeen {
    map: HashMap<ProcessGuid, Vec<String>>,
}

impl LocalStateSeen {
    /// Should the open of `path` by `guid` be forwarded? True the first time
    /// for each (instance, path), up to [`LOCAL_STATE_PER_PROCESS`] paths.
    pub fn admit(&mut self, guid: &ProcessGuid, path: &str) -> bool {
        let key = path.replace('/', "\\").to_ascii_lowercase();
        if !self.map.contains_key(guid) && self.map.len() >= LOCAL_STATE_MAX_PROCESSES {
            self.map.clear();
        }
        let seen = self.map.entry(guid.clone()).or_default();
        if seen.contains(&key) || seen.len() >= LOCAL_STATE_PER_PROCESS {
            return false;
        }
        seen.push(key);
        true
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// `--user-data-dir` of process instances that had one (from their
/// ProcessStart), for [`LocalStateSeen`]'s scope check. Bounded.
#[derive(Debug, Default)]
pub struct UserDataDirs {
    map: HashMap<ProcessGuid, String>,
}

impl UserDataDirs {
    pub fn record(&mut self, guid: &ProcessGuid, cmdline: &str) {
        let Some(d) = user_data_dir(cmdline) else {
            return;
        };
        if !self.map.contains_key(guid) && self.map.len() >= LOCAL_STATE_MAX_PROCESSES {
            self.map.clear();
        }
        self.map.insert(guid.clone(), d);
    }

    pub fn get(&self, guid: &ProcessGuid) -> Option<&str> {
        self.map.get(guid).map(String::as_str)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Is an open of `path` (a `Local State` that is not otherwise sensitive)
/// by a process whose `--user-data-dir` is `udd` in scope for forwarding?
pub fn local_state_in_scope(path: &str, udd: Option<&str>) -> bool {
    is_local_state(path) && (under_user_profile(path) || udd.is_some_and(|d| under_dir(path, d)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issuer_uses_header_when_threads_agree_or_field_absent() {
        let never = |_| -> Option<u32> { panic!("no lookup on the hot path") };
        assert_eq!(issuer(100, 7, Some(7), never), Issuer::Header);
        assert_eq!(issuer(100, 7, None, never), Issuer::Header);
        assert_eq!(issuer(100, 7, Some(0), never), Issuer::Header);
    }

    #[test]
    fn issuer_follows_the_issuing_thread() {
        // Logged in rustc's context (pid 100, thread 7) for an open issued
        // by docker.exe's thread 55 (pid 200).
        assert_eq!(
            issuer(100, 7, Some(55), |t| (t == 55).then_some(200)),
            Issuer::Other(200)
        );
        // Different thread of the same process.
        assert_eq!(issuer(100, 7, Some(8), |_| Some(100)), Issuer::Header);
        // System worker context (pid 4) for a user thread.
        assert_eq!(issuer(4, 12, Some(55), |_| Some(200)), Issuer::Other(200));
        // Issuing thread gone: never blamed on the logging context.
        assert_eq!(issuer(100, 7, Some(55), |_| None), Issuer::Unresolved);
    }

    #[test]
    fn reused_thread_ids_are_not_issuers() {
        assert!(thread_existed_at(1_000, 1_000));
        assert!(thread_existed_at(2_500, 1_000)); // clock slack
        assert!(!thread_existed_at(10_000, 1_000));
    }

    /// pid 100 = A (creates FileObject F named config.json), A exits, B gets
    /// pid 100 and reads through a FileObject at the same address whose
    /// Create was lost: the read is not named after A's file.
    #[test]
    fn file_object_name_not_reused_across_instances() {
        let mut fo = FileObjects::default();
        fo.on_create(100, 0xF, r"C:\Users\u\.docker\config.json".into(), 10);
        // Interleaved: another process uses the same FileObject address.
        fo.on_create(200, 0xF, r"C:\x\other.txt".into(), 11);
        let owner = |ts: i64| if ts < 50 { "A" } else { "B" };
        assert_eq!(
            fo.first_read(100, 0xF, 60, |c, r| owner(c) == owner(r)),
            None
        );
        // The stale entry is gone for good.
        assert_eq!(fo.first_read(100, 0xF, 61, |_, _| true), None);
        // pid 200's own read is named after its own create, once.
        assert_eq!(
            fo.first_read(200, 0xF, 12, |_, _| true).as_deref(),
            Some(r"C:\x\other.txt")
        );
        assert_eq!(fo.first_read(200, 0xF, 13, |_, _| true), None);
    }

    #[test]
    fn file_object_same_instance_and_recreate() {
        let mut fo = FileObjects::default();
        fo.on_create(100, 0xA, "a".into(), 10);
        assert_eq!(
            fo.first_read(100, 0xA, 11, |_, _| true).as_deref(),
            Some("a")
        );
        // Closed and the address reused by the same process for another file.
        fo.on_create(100, 0xA, "b".into(), 20);
        assert_eq!(
            fo.first_read(100, 0xA, 21, |_, _| true).as_deref(),
            Some("b")
        );
        // A read stamped before the create it would be named after.
        fo.on_create(100, 0xB, "c".into(), 30);
        assert_eq!(fo.first_read(100, 0xB, 29, |_, _| true), None);
        fo.on_create(100, 0, "zero".into(), 40);
        assert!(fo.len() <= 2);
        fo.gc(30 + FILE_OBJECT_TTL_MS);
        assert!(fo.is_empty());
    }

    #[test]
    fn local_state_names() {
        assert!(is_local_state(
            r"C:\Users\u\AppData\Roaming\Code\Local State"
        ));
        assert!(is_local_state(
            r"\Device\HarddiskVolume3\Users\u\AppData\Roaming\discord\LOCAL STATE"
        ));
        assert!(is_local_state(
            "C:/Users/u/AppData/Roaming/xeno/local state"
        ));
        assert!(!is_local_state(
            r"C:\Users\u\AppData\Roaming\Code\Local State\"
        ));
        assert!(!is_local_state(
            r"C:\Users\u\AppData\Roaming\Code\Local State~RF1a2b.TMP"
        ));
        assert!(!is_local_state(
            r"C:\Users\u\AppData\Roaming\Code\Local Storage"
        ));
        assert!(!is_local_state(r"C:\x\NotLocal State"));
    }

    #[test]
    fn user_profile_scope() {
        assert!(under_user_profile(
            r"C:\Users\u\AppData\Roaming\Code\Local State"
        ));
        assert!(under_user_profile(r"D:\Users\u\x\Local State"));
        assert!(under_user_profile(r"\\?\C:\Users\u\x\Local State"));
        assert!(!under_user_profile(r"C:\Users\Local State"));
        assert!(!under_user_profile(r"C:\ProgramData\x\Local State"));
        assert!(!under_user_profile(r"\\srv\share\Users\u\Local State"));
        assert!(!under_user_profile(r"C:\Users\u\..\..\Windows\Local State"));
    }

    #[test]
    fn user_data_dir_forms() {
        assert_eq!(
            user_data_dir(r#""C:\a\app.exe" --type=renderer --user-data-dir=D:\Data\App"#)
                .as_deref(),
            Some(r"D:\Data\App")
        );
        assert_eq!(
            user_data_dir(r#"app.exe --user-data-dir="C:\My Data\App\" --x"#).as_deref(),
            Some(r"C:\My Data\App")
        );
        assert_eq!(
            user_data_dir(r#"app.exe "--user-data-dir=C:\My Data\App" --x"#).as_deref(),
            Some(r"C:\My Data\App")
        );
        assert_eq!(
            user_data_dir(r#"app.exe --user-data-dir C:\D\App --x"#).as_deref(),
            Some(r"C:\D\App")
        );
        // Chromium honours the last one.
        assert_eq!(
            user_data_dir(r"a.exe --user-data-dir=C:\one --user-data-dir=C:\two").as_deref(),
            Some(r"C:\two")
        );
        assert_eq!(user_data_dir(r"a.exe --no-user-data-dir=C:\x"), None);
        assert_eq!(user_data_dir(r"a.exe --user-data-dir= --x"), None);
        assert_eq!(user_data_dir(r"a.exe --user-data-directory=C:\x"), None);
        assert_eq!(user_data_dir("a.exe"), None);
    }

    #[test]
    fn local_state_scope_with_user_data_dir() {
        let p = r"E:\Portable\Xeno\Data\Local State";
        assert!(!local_state_in_scope(p, None));
        assert!(local_state_in_scope(p, Some(r"E:\Portable\Xeno\Data")));
        assert!(local_state_in_scope(p, Some(r"e:\portable\xeno\")));
        assert!(!local_state_in_scope(p, Some(r"E:\Portable\Xen")));
        assert!(!local_state_in_scope(
            p,
            Some(r"E:\Portable\..\Portable\Xeno\Data")
        ));
        assert!(local_state_in_scope(
            r"C:\Users\u\AppData\Roaming\Code\Local State",
            None
        ));
        assert!(!local_state_in_scope(
            r"C:\Users\u\AppData\Roaming\Code\Cookies",
            None
        ));
    }

    #[test]
    fn local_state_dedup_per_instance_and_bounded() {
        let a = ProcessGuid::derive("b", 1, 1);
        let b = ProcessGuid::derive("b", 1, 2); // same pid, later instance
        let mut s = LocalStateSeen::default();
        let p = r"C:\Users\u\AppData\Roaming\Code\Local State";
        assert!(s.admit(&a, p));
        assert!(!s.admit(&a, &p.to_uppercase()));
        assert!(s.admit(&b, p), "a reused pid is a new instance");
        for i in 1..LOCAL_STATE_PER_PROCESS {
            assert!(s.admit(&a, &format!(r"C:\Users\u\x{i}\Local State")));
        }
        assert!(!s.admit(&a, r"C:\Users\u\one-more\Local State"));
        for i in 0..LOCAL_STATE_MAX_PROCESSES as u32 + 5 {
            s.admit(&ProcessGuid::derive("b", 9, i as i64), p);
        }
        assert!(s.len() <= LOCAL_STATE_MAX_PROCESSES);
    }

    #[test]
    fn user_data_dirs_recorded_per_instance() {
        let mut u = UserDataDirs::default();
        let g = ProcessGuid::derive("b", 5, 1);
        u.record(&g, "code.exe");
        assert!(u.get(&g).is_none());
        u.record(&g, r"code.exe --user-data-dir=C:\D");
        assert_eq!(u.get(&g), Some(r"C:\D"));
    }
}
