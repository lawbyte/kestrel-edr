//! Registry watcher (fixes known risk 2): `RegNotifyChangeKeyValue` on the
//! curated keys in [`crate::regdiff::WATCH_TABLE`] for HKLM and every loaded
//! user hive (`HKU\<SID>` and `HKU\<SID>_Classes`, re-scanned every 60 s).
//!
//! One dedicated thread. Each watched key has an auto-reset event armed with
//! `REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET` (subtree when the
//! spec has depth > 0, thread-agnostic). The thread polls the events every
//! 200 ms (`WaitForSingleObject(…, 0)`, ~5 calls per key per second),
//! re-arms, and after a short debounce re-reads the key tree and diffs it
//! against the snapshot ([`crate::regdiff::diff_tree`]). Each change becomes
//! [`Raw::RegChange`]; the translator joins it with Kernel-Registry
//! event 5/6 for the writer.
//!
//! Re-reads reuse a key's snapshot when its last-write time is unchanged, so
//! a rescan of the Services subtree (a few thousand keys) costs one
//! enumeration plus value reads only for keys that changed.
//!
//! Keys that do not exist yet (e.g. `SilentProcessExit`, `AppCertDlls`) are
//! retried every second (access-denied ones every 60 s); when one appears its
//! values are reported as new.
//!
//! Known limits: a set-then-revert faster than the debounce is invisible;
//! holding handles in a user hive can delay its unload at logoff (User
//! Profile Service event 1530) until the next 60 s hive rescan drops it.

use super::etw::{Raw, Sink};
use super::util::*;
use crate::regdiff::{
    classify_hku_subkey, diff_tree, display_key, value_wanted, Hive, KeySnap, TreeSnap, ValueSnap,
    WatchSpec, MAX_KEYS_PER_TREE, MAX_VALUES_PER_KEY, WATCH_TABLE,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS,
    FILETIME, HANDLE, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::Registry::{
    RegEnumKeyExW, RegEnumValueW, RegNotifyChangeKeyValue, RegOpenKeyExW, RegQueryInfoKeyW, HKEY,
    HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_READ, KEY_WOW64_64KEY, REG_NOTIFY_CHANGE_LAST_SET,
    REG_NOTIFY_CHANGE_NAME, REG_NOTIFY_THREAD_AGNOSTIC,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

const POLL: Duration = Duration::from_millis(200);
const HIVE_RESCAN: Duration = Duration::from_secs(60);
const MISSING_RETRY: Duration = Duration::from_secs(1);
const DENIED_RETRY: Duration = Duration::from_secs(60);

struct Watch {
    spec: &'static WatchSpec,
    /// Bare SID for user hives ("" for HKLM).
    sid: String,
    /// Subkey of HKEY_USERS that holds the hive ("S-…" or "S-…_Classes").
    hku_sub: String,
    key: Option<RegKey>,
    event: Option<Handle>,
    snap: TreeSnap,
    due: Option<Instant>,
    retry_at: Instant,
}

impl Watch {
    fn root(&self) -> (HKEY, String) {
        match self.spec.hive {
            Hive::Machine => (HKEY_LOCAL_MACHINE, self.spec.path.to_string()),
            _ => (HKEY_USERS, format!(r"{}\{}", self.hku_sub, self.spec.path)),
        }
    }

    fn base(&self) -> String {
        display_key(self.spec.hive, &self.sid, self.spec.path)
    }

    fn debounce(&self) -> Duration {
        match self.spec.depth {
            // Short: a value set and reverted within the debounce is invisible
            // (lab VM: a 2 s AMSI FeatureBits / service-key set+revert was
            // missed with 1 s / 3 s). The Services subtree is large, so it
            // still coalesces bursts a little longer.
            0 => Duration::from_millis(50),
            1 => Duration::from_millis(100),
            _ if self.spec.path.ends_with(r"CurrentControlSet\Services") => {
                Duration::from_millis(750)
            }
            _ => Duration::from_millis(250),
        }
    }
}

fn open_key(root: HKEY, path: &str) -> Result<RegKey, u32> {
    let w = wide(path);
    let mut h: HKEY = std::ptr::null_mut();
    let rc = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, KEY_READ | KEY_WOW64_64KEY, &mut h) };
    if rc == ERROR_SUCCESS {
        Ok(RegKey(h))
    } else {
        Err(rc)
    }
}

fn arm(key: &RegKey, ev: HANDLE, subtree: bool) -> bool {
    let rc = unsafe {
        RegNotifyChangeKeyValue(
            key.0,
            subtree as i32,
            REG_NOTIFY_CHANGE_NAME | REG_NOTIFY_CHANGE_LAST_SET | REG_NOTIFY_THREAD_AGNOSTIC,
            ev,
            1,
        )
    };
    rc == ERROR_SUCCESS
}

fn last_write(k: &RegKey) -> u64 {
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let rc = unsafe {
        RegQueryInfoKeyW(
            k.0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut ft,
        )
    };
    if rc == ERROR_SUCCESS {
        ft_u64(&ft)
    } else {
        0
    }
}

fn read_values(
    k: &RegKey,
    spec: &WatchSpec,
) -> std::collections::BTreeMap<String, (String, ValueSnap)> {
    let mut out = std::collections::BTreeMap::new();
    let mut i = 0u32;
    let mut name = vec![0u16; 16_384];
    let mut data = vec![0u8; 4096];
    loop {
        let mut nlen = name.len() as u32;
        let mut ty = 0u32;
        let mut dlen = data.len() as u32;
        let rc = unsafe {
            RegEnumValueW(
                k.0,
                i,
                name.as_mut_ptr(),
                &mut nlen,
                std::ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut dlen,
            )
        };
        if rc == ERROR_MORE_DATA && (dlen as usize) > data.len() && dlen <= 1 << 20 {
            data.resize(dlen as usize, 0);
            continue; // retry the same index with a larger buffer
        }
        if rc != ERROR_SUCCESS {
            break;
        }
        let n = String::from_utf16_lossy(&name[..nlen as usize]);
        if value_wanted(spec, &n) {
            let d = &data[..(dlen as usize).min(data.len())];
            out.insert(n.to_ascii_lowercase(), (n, ValueSnap::new(ty, d)));
            if out.len() >= MAX_VALUES_PER_KEY {
                break;
            }
        }
        i += 1;
        if i > 100_000 {
            break;
        }
    }
    out
}

fn subkeys(k: &RegKey) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0u32;
    let mut name = vec![0u16; 256];
    loop {
        let mut len = name.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                k.0,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS || rc != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&name[..len as usize]));
        i += 1;
        if out.len() >= MAX_KEYS_PER_TREE {
            break;
        }
    }
    out
}

/// Walk `root` to the spec's depth, reusing `old` snapshots of keys whose
/// last-write time did not change.
fn walk(root: &RegKey, spec: &WatchSpec, old: &TreeSnap) -> TreeSnap {
    let mut snap = TreeSnap::default();
    let mut stack: Vec<(String, u8, Option<RegKey>)> = vec![(String::new(), 0, None)];
    while let Some((rel, depth, owned)) = stack.pop() {
        if snap.keys.len() >= MAX_KEYS_PER_TREE {
            snap.truncated = true;
            break;
        }
        let k: &RegKey = owned.as_ref().unwrap_or(root);
        let lw = last_write(k);
        let lc = rel.to_ascii_lowercase();
        let ks = match old.keys.get(&lc) {
            Some(o) if lw != 0 && o.last_write == lw => o.clone(),
            _ => KeySnap {
                rel: rel.clone(),
                last_write: lw,
                values: read_values(k, spec),
            },
        };
        snap.keys.insert(lc, ks);
        if depth < spec.depth {
            for sub in subkeys(k) {
                let w = wide(&sub);
                let mut h: HKEY = std::ptr::null_mut();
                let rc = unsafe { RegOpenKeyExW(k.0, w.as_ptr(), 0, KEY_READ, &mut h) };
                if rc != ERROR_SUCCESS {
                    continue;
                }
                let child_rel = if rel.is_empty() {
                    sub
                } else {
                    format!(r"{rel}\{sub}")
                };
                stack.push((child_rel, depth + 1, Some(RegKey(h))));
            }
        }
    }
    snap
}

fn new_event() -> Option<Handle> {
    Handle::new(unsafe { CreateEventW(std::ptr::null(), 0, 0, std::ptr::null()) })
}

/// Loaded user hives: (HKU subkey, hive kind, bare SID).
fn loaded_hives() -> Vec<(String, Hive, String)> {
    let Some(k) = (unsafe {
        let mut h: HKEY = std::ptr::null_mut();
        (RegOpenKeyExW(HKEY_USERS, std::ptr::null(), 0, KEY_READ, &mut h) == ERROR_SUCCESS)
            .then_some(RegKey(h))
    }) else {
        return vec![];
    };
    subkeys(&k)
        .into_iter()
        .filter_map(|s| {
            let (hive, sid) = classify_hku_subkey(&s)?;
            let sid = sid.to_string();
            Some((s, hive, sid))
        })
        .collect()
}

struct Watcher {
    sink: Sink,
    watches: Vec<Watch>,
}

impl Watcher {
    /// Open (or re-open) a watch. `report_new`: the key appeared after start,
    /// so its current values are reported as changes.
    fn try_open(&mut self, i: usize, report_new: bool) {
        let (root, path) = self.watches[i].root();
        let w = &mut self.watches[i];
        match open_key(root, &path) {
            Ok(key) => {
                let Some(ev) = new_event() else { return };
                if !arm(&key, ev.raw(), w.spec.depth > 0) {
                    w.retry_at = Instant::now() + DENIED_RETRY;
                    return;
                }
                let snap = walk(&key, w.spec, &TreeSnap::default());
                w.key = Some(key);
                w.event = Some(ev);
                let changes = if report_new {
                    diff_tree(&TreeSnap::default(), &snap)
                } else {
                    Vec::new()
                };
                w.snap = snap;
                let base = w.base();
                for c in changes {
                    self.emit(&base, c, true);
                }
            }
            Err(rc) => {
                w.retry_at = Instant::now()
                    + if rc == ERROR_ACCESS_DENIED {
                        DENIED_RETRY
                    } else if rc == ERROR_FILE_NOT_FOUND {
                        MISSING_RETRY
                    } else {
                        DENIED_RETRY
                    };
            }
        }
    }

    fn emit(&self, base: &str, c: crate::regdiff::Change, reopened: bool) {
        let key = if c.rel.is_empty() {
            base.to_string()
        } else {
            format!(r"{base}\{}", c.rel)
        };
        self.sink
            .send(Raw::RegChange(Box::new(super::etw::RegChangeRaw {
                ts: kestrel_common::now_ms(),
                key,
                value_name: c.value_name,
                op: c.op,
                ty: c.ty,
                data: c.data,
                reopened,
            })));
    }

    fn add_hives(&mut self) {
        let hives = loaded_hives();
        // Drop watches of unloaded hives.
        self.watches.retain(|w| {
            w.spec.hive == Hive::Machine || hives.iter().any(|(s, _, _)| *s == w.hku_sub)
        });
        for (sub, hive, sid) in hives {
            for spec in WATCH_TABLE.iter().filter(|s| s.hive == hive) {
                if self
                    .watches
                    .iter()
                    .any(|w| w.hku_sub == sub && std::ptr::eq(w.spec, spec))
                {
                    continue;
                }
                self.watches.push(Watch {
                    spec,
                    sid: sid.clone(),
                    hku_sub: sub.clone(),
                    key: None,
                    event: None,
                    snap: TreeSnap::default(),
                    due: None,
                    retry_at: Instant::now(),
                });
                let i = self.watches.len() - 1;
                self.try_open(i, false);
            }
        }
    }

    fn poll(&mut self) {
        let now = Instant::now();
        let mut out: Vec<(String, crate::regdiff::Change)> = Vec::new();
        let mut reopen = Vec::new();
        for (i, w) in self.watches.iter_mut().enumerate() {
            let (Some(key), Some(ev)) = (&w.key, &w.event) else {
                if w.retry_at <= now {
                    reopen.push(i);
                }
                continue;
            };
            if unsafe { WaitForSingleObject(ev.raw(), 0) } == WAIT_OBJECT_0 {
                // Re-arm first so nothing between now and the re-read is lost.
                if !arm(key, ev.raw(), w.spec.depth > 0) {
                    // Key deleted (or hive unloaded): report and retry later.
                    let old = std::mem::take(&mut w.snap);
                    w.key = None;
                    w.event = None;
                    w.due = None;
                    w.retry_at = now + MISSING_RETRY;
                    let base = w.base();
                    out.extend(
                        diff_tree(&old, &TreeSnap::default())
                            .into_iter()
                            .map(|c| (base.clone(), c)),
                    );
                    continue;
                }
                if w.due.is_none() {
                    w.due = Some(now + w.debounce());
                }
            }
            if w.due.is_some_and(|d| d <= now) {
                w.due = None;
                let new = walk(key, w.spec, &w.snap);
                let changes = diff_tree(&w.snap, &new);
                w.snap = new;
                let base = w.base();
                out.extend(changes.into_iter().map(|c| (base.clone(), c)));
            }
        }
        for (base, c) in out {
            self.emit(&base, c, false);
        }
        for i in reopen {
            self.try_open(i, true);
        }
    }

    fn stats(&self) -> (usize, usize, usize) {
        let open = self.watches.iter().filter(|w| w.key.is_some()).count();
        let values = self.watches.iter().map(|w| w.snap.value_count()).sum();
        (self.watches.len(), open, values)
    }
}

/// Start the watcher thread. Returns once the initial snapshots are taken
/// (so changes made right after sensor start are diffed, not baselined).
pub fn start(sink: Sink, stop: Arc<AtomicBool>) -> std::io::Result<std::thread::JoinHandle<()>> {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    let h = std::thread::Builder::new()
        .name("kestrel-regwatch".into())
        .spawn(move || {
            let mut w = Watcher {
                sink,
                watches: Vec::new(),
            };
            for spec in WATCH_TABLE.iter().filter(|s| s.hive == Hive::Machine) {
                w.watches.push(Watch {
                    spec,
                    sid: String::new(),
                    hku_sub: String::new(),
                    key: None,
                    event: None,
                    snap: TreeSnap::default(),
                    due: None,
                    retry_at: Instant::now(),
                });
                let i = w.watches.len() - 1;
                w.try_open(i, false);
            }
            w.add_hives();
            let (n, open, values) = w.stats();
            tracing::info!(watches = n, open, values, "registry watcher started");
            w.sink
                .counters
                .reg_watch_keys
                .store(open as u64, Ordering::Relaxed);
            let _ = tx.send(());
            let mut last_hives = Instant::now();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(POLL);
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    w.poll();
                    if last_hives.elapsed() >= HIVE_RESCAN {
                        last_hives = Instant::now();
                        w.add_hives();
                        let (_, open, _) = w.stats();
                        w.sink
                            .counters
                            .reg_watch_keys
                            .store(open as u64, Ordering::Relaxed);
                    }
                }));
                if r.is_err() {
                    tracing::error!("registry watcher panic caught; continuing");
                }
            }
        })?;
    let _ = rx.recv_timeout(Duration::from_secs(30));
    Ok(h)
}
