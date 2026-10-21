//! Registry watcher logic (pure): the curated key table, snapshot diffing,
//! key-name normalisation, Sysmon-style value rendering and the join that
//! attributes a watcher-observed change to the process that made it.
//!
//! Why: on Windows 11 25H2 (build 26200) Microsoft-Windows-Kernel-Registry
//! SetValueKey (event 5) arrives with an **empty** `KeyName` and empty
//! `CapturedData` (measured, see `docs/DECISIONS.md`). Only `KeyObject`,
//! `ValueName`, `Type` and `DataSize` are usable. The Windows glue
//! (`win/regwatch.rs`) therefore watches the curated keys below with
//! `RegNotifyChangeKeyValue`, re-reads them on change and diffs against a
//! snapshot ([`diff_tree`]); [`RegJoin`] then attributes each change to the
//! writer seen in ETW event 5 / 6 for the same value name within
//! [`JOIN_WINDOW_MS`].

use crate::etwparse::{
    le_u32, le_u64, utf16le, REG_DWORD, REG_EXPAND_SZ, REG_MULTI_SZ, REG_QWORD, REG_SZ,
};
use kestrel_common::{Attribution, RegistryOp};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Which hive a watch spec applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Hive {
    /// `HKLM\…`
    Machine,
    /// `HKU\<SID>\…` for every loaded user hive.
    User,
    /// `HKU\<SID>_Classes\…` (reported as `HKU\<SID>\Software\Classes\…`).
    UserClasses,
}

/// One watched key.
#[derive(Debug, Clone, Copy)]
pub struct WatchSpec {
    pub hive: Hive,
    /// Path below the hive root (no leading `\`).
    pub path: &'static str,
    /// Subkey depth snapshotted below `path` (0 = the key only). Depth > 0
    /// also means the notification is registered for the whole subtree.
    pub depth: u8,
    /// Only these value names (case-insensitive) are snapshotted / reported;
    /// `None` = every value.
    pub values: Option<&'static [&'static str]>,
}

const fn m(path: &'static str, depth: u8) -> WatchSpec {
    WatchSpec {
        hive: Hive::Machine,
        path,
        depth,
        values: None,
    }
}
const fn mv(path: &'static str, depth: u8, values: &'static [&'static str]) -> WatchSpec {
    WatchSpec {
        hive: Hive::Machine,
        path,
        depth,
        values: Some(values),
    }
}
const fn u(path: &'static str, depth: u8) -> WatchSpec {
    WatchSpec {
        hive: Hive::User,
        path,
        depth,
        values: None,
    }
}
const fn uv(path: &'static str, depth: u8, values: &'static [&'static str]) -> WatchSpec {
    WatchSpec {
        hive: Hive::User,
        path,
        depth,
        values: Some(values),
    }
}

const IFEO_VALUES: &[&str] = &[
    "Debugger",
    "GlobalFlag",
    "VerifierDlls",
    "MonitorProcess",
    "ReportingMode",
];
const SERVICE_VALUES: &[&str] = &[
    "ImagePath",
    "ServiceDll",
    "Type",
    "Start",
    "FailureCommand",
    "ObjectName",
];
const SESSION_MANAGER_VALUES: &[&str] =
    &["BootExecute", "SetupExecute", "Execute", "S0InitialCommand"];
const AUTOLOGGER_VALUES: &[&str] = &["Start", "Enabled", "EnableLevel", "EnableFlags"];
const TASK_TREE_VALUES: &[&str] = &["Id", "Index", "SD"];
const CLSID_VALUES: &[&str] = &[""]; // default value of InprocServer32 / LocalServer32 / TreatAs …
const DESKTOP_VALUES: &[&str] = &["Wallpaper", "SCRNSAVE.EXE"];
const ENV_VALUES: &[&str] = &["UserInitMprLogonScript"];
const WINLOGON_USER_VALUES: &[&str] = &["Shell", "Userinit"];

/// Curated watch table, from the persistence, credential-dumping and
/// ransomware research notes (§ "Sensor changes"). HKLM `Software\Classes\
/// CLSID` is deliberately absent (tens of thousands of keys; the 6-hourly
/// autoruns inventory is the backstop); the per-user `_Classes\CLSID` is
/// small and is where COM hijacks land.
pub const WATCH_TABLE: &[WatchSpec] = &[
    // --- Run family (machine) ---
    m(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", 0),
    m(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", 0),
    m(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", 2),
    m(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        0,
    ),
    m(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        0,
    ),
    m(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        1,
    ),
    m(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        0,
    ),
    m(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        0,
    ),
    m(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        0,
    ),
    // --- Winlogon / Windows / debuggers ---
    m(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", 0),
    m(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", 0),
    m(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows",
        0,
    ),
    mv(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        1,
        IFEO_VALUES,
    ),
    mv(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        1,
        IFEO_VALUES,
    ),
    m(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit",
        1,
    ),
    m(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug", 0),
    m(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug",
        0,
    ),
    mv(
        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree",
        4,
        TASK_TREE_VALUES,
    ),
    // --- Session Manager / LSA / credential providers ---
    mv(
        r"SYSTEM\CurrentControlSet\Control\Session Manager",
        0,
        SESSION_MANAGER_VALUES,
    ),
    m(
        r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls",
        0,
    ),
    m(r"SYSTEM\CurrentControlSet\Control\Lsa", 1),
    m(r"SYSTEM\CurrentControlSet\Control\SecurityProviders", 0),
    m(
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
        0,
    ),
    m(r"SYSTEM\CurrentControlSet\Control\DeviceGuard", 1),
    m(r"SYSTEM\CurrentControlSet\Control\SafeBoot", 2),
    // --- AMSI / Defender ---
    m(r"SOFTWARE\Microsoft\AMSI", 2),
    m(r"SOFTWARE\Microsoft\Windows Defender\Exclusions", 1),
    m(r"SOFTWARE\Policies\Microsoft\Windows Defender", 2),
    // --- Services (diff only changed subkeys, filtered values) ---
    mv(r"SYSTEM\CurrentControlSet\Services", 2, SERVICE_VALUES),
    m(r"SYSTEM\CurrentControlSet\Services\KestrelAgent", 1),
    // --- ETW autologgers (tamper: disabling providers / sessions) ---
    mv(
        r"SYSTEM\CurrentControlSet\Control\WMI\Autologger",
        2,
        AUTOLOGGER_VALUES,
    ),
    // --- Per-user ---
    u(r"Software\Microsoft\Windows\CurrentVersion\Run", 0),
    u(r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 0),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        0,
    ),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
        0,
    ),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        1,
    ),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System",
        0,
    ),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        0,
    ),
    u(
        r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
        0,
    ),
    uv(
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        0,
        WINLOGON_USER_VALUES,
    ),
    u(r"Software\Microsoft\Windows NT\CurrentVersion\Windows", 0),
    uv(r"Control Panel\Desktop", 0, DESKTOP_VALUES),
    uv(r"Environment", 0, ENV_VALUES),
    WatchSpec {
        hive: Hive::UserClasses,
        path: "CLSID",
        depth: 2,
        values: Some(CLSID_VALUES),
    },
];

/// Is `sid` (a subkey name of `HKEY_USERS`) a user hive we watch? Returns
/// the hive kind and the bare SID.
pub fn classify_hku_subkey(name: &str) -> Option<(Hive, &str)> {
    let (hive, sid) = match name.strip_suffix("_Classes") {
        Some(s) => (Hive::UserClasses, s),
        None => (Hive::User, name),
    };
    let ok = sid.starts_with("S-1-5-21-")
        || sid.starts_with("S-1-12-1-")
        // Well-known service accounts: malware running as SYSTEM writes their HKCU.
        || (hive == Hive::User && matches!(sid, "S-1-5-18" | "S-1-5-19" | "S-1-5-20"));
    ok.then_some((hive, sid))
}

/// Display form of a watched key: `HKLM\…`, `HKU\<SID>\…`, and
/// `HKU\<SID>\Software\Classes\…` for the `_Classes` hive.
pub fn display_key(hive: Hive, sid: &str, rel: &str) -> String {
    let rel = rel.trim_matches('\\');
    let base = match hive {
        Hive::Machine => "HKLM".to_string(),
        Hive::User => format!(r"HKU\{sid}"),
        Hive::UserClasses => format!(r"HKU\{sid}\Software\Classes"),
    };
    if rel.is_empty() {
        base
    } else {
        format!(r"{base}\{rel}")
    }
}

/// Is `name` one of the spec's reported values?
pub fn value_wanted(spec: &WatchSpec, name: &str) -> bool {
    match spec.values {
        None => true,
        Some(list) => list.iter().any(|v| v.eq_ignore_ascii_case(name)),
    }
}

// ------------------------------------------------------------------ snapshots

/// Stored bytes per value (change detection beyond that uses the hash).
pub const MAX_VALUE_BYTES: usize = 2048;
/// Keys per watched tree (the Services subtree is ~1-2k on a workstation).
pub const MAX_KEYS_PER_TREE: usize = 6000;
/// Values per key.
pub const MAX_VALUES_PER_KEY: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueSnap {
    pub ty: u32,
    /// First [`MAX_VALUE_BYTES`] bytes.
    pub data: Vec<u8>,
    pub len: u32,
    /// FNV-1a of the full data.
    pub hash: u64,
}

impl ValueSnap {
    pub fn new(ty: u32, full: &[u8]) -> Self {
        ValueSnap {
            ty,
            data: full[..full.len().min(MAX_VALUE_BYTES)].to_vec(),
            len: full.len() as u32,
            hash: fnv1a(full),
        }
    }
}

pub fn fnv1a(b: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for x in b {
        h ^= *x as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySnap {
    /// Display form of the relative subpath ("" for the watched key itself).
    pub rel: String,
    /// Key last-write FILETIME (from enumeration); 0 = unknown.
    pub last_write: u64,
    /// Lower-cased value name → (original name, value).
    pub values: BTreeMap<String, (String, ValueSnap)>,
}

/// Snapshot of one watched tree: lower-cased relative subpath → key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TreeSnap {
    pub keys: BTreeMap<String, KeySnap>,
    /// True when the walk hit [`MAX_KEYS_PER_TREE`].
    pub truncated: bool,
}

impl TreeSnap {
    pub fn value_count(&self) -> usize {
        self.keys.values().map(|k| k.values.len()).sum()
    }
}

/// One observed change, relative to a watched tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// Relative subpath (display case), "" = the watched key itself.
    pub rel: String,
    pub value_name: String,
    pub op: RegistryOp,
    pub ty: u32,
    /// New data (Set only).
    pub data: Option<Vec<u8>>,
}

/// Diff two snapshots of the same tree. New keys report each of their
/// values as `Set`; deleted keys report one `DeleteKey` (value name empty);
/// a truncated walk never reports deletions of keys it did not reach.
pub fn diff_tree(old: &TreeSnap, new: &TreeSnap) -> Vec<Change> {
    let mut out = Vec::new();
    for (k, nk) in &new.keys {
        match old.keys.get(k) {
            None => {
                for (name, v) in nk.values.values() {
                    out.push(Change {
                        rel: nk.rel.clone(),
                        value_name: name.clone(),
                        op: RegistryOp::Set,
                        ty: v.ty,
                        data: Some(v.data.clone()),
                    });
                }
            }
            Some(ok) => {
                for (lk, (name, v)) in &nk.values {
                    let changed = match ok.values.get(lk) {
                        None => true,
                        Some((_, ov)) => ov.ty != v.ty || ov.len != v.len || ov.hash != v.hash,
                    };
                    if changed {
                        out.push(Change {
                            rel: nk.rel.clone(),
                            value_name: name.clone(),
                            op: RegistryOp::Set,
                            ty: v.ty,
                            data: Some(v.data.clone()),
                        });
                    }
                }
                for (lk, (name, v)) in &ok.values {
                    if !nk.values.contains_key(lk) {
                        out.push(Change {
                            rel: nk.rel.clone(),
                            value_name: name.clone(),
                            op: RegistryOp::DeleteValue,
                            ty: v.ty,
                            data: None,
                        });
                    }
                }
            }
        }
    }
    if !new.truncated {
        for (k, ok) in &old.keys {
            if new.keys.contains_key(k) {
                continue;
            }
            // Report only the topmost deleted key of a deleted subtree.
            let parent_gone = parent_rel(k).is_some_and(|p| {
                !p.is_empty() && old.keys.contains_key(p) && !new.keys.contains_key(p)
            });
            if parent_gone {
                continue;
            }
            out.push(Change {
                rel: ok.rel.clone(),
                value_name: String::new(),
                op: RegistryOp::DeleteKey,
                ty: 0,
                data: None,
            });
        }
    }
    out
}

fn parent_rel(k: &str) -> Option<&str> {
    if k.is_empty() {
        return None;
    }
    Some(k.rsplit_once('\\').map(|(p, _)| p).unwrap_or(""))
}

// ------------------------------------------------------------------ rendering

/// Render registry data the way Sysmon does (so SigmaHQ `Details` matches):
/// `DWORD (0x00000001)`, `QWORD (0xHHHHHHHH-0xLLLLLLLL)`, strings as-is,
/// REG_MULTI_SZ joined with a space, binary as lower-case hex (≤ 256 bytes,
/// `…` when cut). Empty data → `None`.
pub fn render_sysmon(ty: u32, data: &[u8]) -> Option<String> {
    match ty {
        REG_DWORD => le_u32(data).map(|v| format!("DWORD (0x{v:08x})")),
        REG_QWORD => {
            le_u64(data).map(|v| format!("QWORD (0x{:08x}-0x{:08x})", v >> 32, v & 0xffff_ffff))
        }
        REG_SZ | REG_EXPAND_SZ => Some(utf16le(data)),
        REG_MULTI_SZ => {
            let units: Vec<u16> = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            Some(
                units
                    .split(|&u| u == 0)
                    .filter(|s| !s.is_empty())
                    .map(String::from_utf16_lossy)
                    .collect::<Vec<_>>()
                    .join(" "),
            )
        }
        _ if data.is_empty() => None,
        _ => {
            let n = data.len().min(256);
            let mut s: String = data[..n].iter().map(|b| format!("{b:02x}")).collect();
            if data.len() > n {
                s.push('…');
            }
            Some(s)
        }
    }
}

// ------------------------------------------------------------------ attribution

/// Window for joining a watcher change with an ETW write by value name.
pub const JOIN_WINDOW_MS: i64 = 2_000;
/// How long a watcher change waits for its ETW event before it is emitted
/// unattributed (ETW Core session flushes every second).
pub const PENDING_WAIT_MS: i64 = 2_500;
const MAX_WRITES: usize = 8192;
const MAX_KEYOBJ: usize = 4096;

/// A Kernel-Registry write seen in ETW (event 5 SetValueKey / 6 DeleteValueKey).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EtwWrite {
    pub ts: i64,
    pub pid: u32,
    pub key_object: u64,
    /// Lower-cased value name.
    pub value_lc: String,
    pub delete: bool,
    /// Already used to attribute a change (still usable, but less preferred).
    pub used: bool,
}

/// Joins watcher changes to ETW writers.
///
/// Security review v1.1 V-H6: the value name alone does not identify the
/// writer (an attacker can write the same value name elsewhere at the same
/// moment, e.g. with the signed `reg.exe`, to choose who gets blamed). So:
/// * every candidate in the window is collected;
/// * a write whose `KeyObject` (per-handle kernel object, so per process) was
///   learnt — from an earlier **unambiguous** join by the **same pid** — to
///   be this key is [`Attribution::Exact`];
/// * otherwise the value-name match is only [`Attribution::Heuristic`] (the
///   closest candidate in time is reported; the engine never kills on it);
/// * no candidate → `None` (pid 0).
///
/// A KeyObject → key mapping is learnt only from a join with exactly one
/// distinct candidate pid (the real writer of a watched value is always a
/// candidate unless ETW lost the event, so a single candidate is the writer).
#[derive(Debug, Default)]
pub struct RegJoin {
    writes: VecDeque<EtwWrite>,
    /// KeyObject → (lower-cased normalised key, pid that used the handle).
    key_objects: HashMap<u64, (String, u32)>,
    pub attributed: u64,
    pub unattributed: u64,
}

/// Result of [`RegJoin::attribute`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Writer {
    pub pid: u32,
    pub attribution: Attribution,
}

impl RegJoin {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, ts: i64, pid: u32, key_object: u64, value_name: &str, delete: bool) {
        if self.writes.len() >= MAX_WRITES {
            self.writes.pop_front();
        }
        self.writes.push_back(EtwWrite {
            ts,
            pid,
            key_object,
            value_lc: value_name.to_ascii_lowercase(),
            delete,
            used: false,
        });
    }

    /// Drop writes older than `now - 2 × JOIN_WINDOW_MS - PENDING_WAIT_MS`.
    pub fn expire(&mut self, now: i64) {
        let horizon = now - 2 * JOIN_WINDOW_MS - PENDING_WAIT_MS;
        while self.writes.front().is_some_and(|w| w.ts < horizon) {
            self.writes.pop_front();
        }
    }

    /// Find the writer of a change to `key` / `value_name` observed at `ts`
    /// (see the type docs for the ranking). `exact_only` (a re-created or
    /// renamed watched key, V-H7): only a KeyObject match counts; a mere
    /// value-name match is not used at all.
    pub fn attribute(
        &mut self,
        key: &str,
        value_name: &str,
        op: RegistryOp,
        ts: i64,
        exact_only: bool,
    ) -> Option<Writer> {
        let key_lc = key.to_ascii_lowercase();
        let (best_exact, best_heur, heur_pids) = self.rank(&key_lc, value_name, op, ts)?;
        let (i, attribution) = match (best_exact, best_heur) {
            (Some(i), _) => (i, Attribution::Exact),
            (None, Some(i)) if !exact_only => (i, Attribution::Heuristic),
            _ => return None,
        };
        let w = &mut self.writes[i];
        w.used = true;
        let (pid, kobj) = (w.pid, w.key_object);
        // Learn the handle only from an unambiguous join.
        if kobj != 0 && attribution == Attribution::Heuristic && heur_pids.len() == 1 {
            if self.key_objects.len() >= MAX_KEYOBJ {
                self.key_objects.clear();
            }
            // Never re-assign a handle learnt for another process.
            match self.key_objects.get(&kobj) {
                Some((_, p)) if *p != pid => {}
                _ => {
                    self.key_objects.insert(kobj, (key_lc, pid));
                }
            }
        }
        self.attributed += 1;
        Some(Writer { pid, attribution })
    }

    /// Is there already a KeyObject-exact writer for this change? (No side
    /// effects: used while a change waits for late ETW events.)
    pub fn has_exact(&self, key: &str, value_name: &str, op: RegistryOp, ts: i64) -> bool {
        self.rank(&key.to_ascii_lowercase(), value_name, op, ts)
            .is_some_and(|(e, _, _)| e.is_some())
    }

    /// (best exact index, best heuristic index, distinct heuristic pids).
    #[allow(clippy::type_complexity)]
    fn rank(
        &self,
        key_lc: &str,
        value_name: &str,
        op: RegistryOp,
        ts: i64,
    ) -> Option<(Option<usize>, Option<usize>, Vec<u32>)> {
        let value_lc = value_name.to_ascii_lowercase();
        let want_delete = op == RegistryOp::DeleteValue;
        if op == RegistryOp::DeleteKey {
            return None;
        }
        // (index, (used, distance))
        let mut best_exact: Option<(usize, (bool, i64))> = None;
        let mut best_heur: Option<(usize, (bool, i64))> = None;
        let mut heur_pids: Vec<u32> = Vec::new();
        for (i, w) in self.writes.iter().enumerate() {
            if w.value_lc != value_lc
                || w.delete != want_delete
                || (w.ts - ts).abs() > JOIN_WINDOW_MS
            {
                continue;
            }
            let score = (w.used, (w.ts - ts).abs());
            match self.key_objects.get(&w.key_object) {
                Some((k, p)) if *p == w.pid && *k == key_lc => {
                    if best_exact.as_ref().is_none_or(|(_, b)| score < *b) {
                        best_exact = Some((i, score));
                    }
                }
                // That handle is known to belong to another key (same process).
                Some((_, p)) if *p == w.pid => {}
                _ => {
                    if !heur_pids.contains(&w.pid) {
                        heur_pids.push(w.pid);
                    }
                    if best_heur.as_ref().is_none_or(|(_, b)| score < *b) {
                        best_heur = Some((i, score));
                    }
                }
            }
        }
        Some((
            best_exact.map(|(i, _)| i),
            best_heur.map(|(i, _)| i),
            heur_pids,
        ))
    }

    /// A change could not be attributed (counted for health).
    pub fn note_unattributed(&mut self) {
        self.unattributed += 1;
    }

    pub fn len(&self) -> usize {
        self.writes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.writes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w16(s: &str) -> Vec<u8> {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .flat_map(|u| u.to_le_bytes())
            .collect()
    }

    fn key(rel: &str, values: &[(&str, u32, &[u8])]) -> (String, KeySnap) {
        (
            rel.to_ascii_lowercase(),
            KeySnap {
                rel: rel.to_string(),
                last_write: 1,
                values: values
                    .iter()
                    .map(|(n, t, d)| {
                        (
                            n.to_ascii_lowercase(),
                            (n.to_string(), ValueSnap::new(*t, d)),
                        )
                    })
                    .collect(),
            },
        )
    }

    #[test]
    fn hku_classification() {
        assert_eq!(
            classify_hku_subkey("S-1-5-21-1-2-3-1001"),
            Some((Hive::User, "S-1-5-21-1-2-3-1001"))
        );
        assert_eq!(
            classify_hku_subkey("S-1-5-21-1-2-3-1001_Classes"),
            Some((Hive::UserClasses, "S-1-5-21-1-2-3-1001"))
        );
        assert_eq!(
            classify_hku_subkey("S-1-5-18"),
            Some((Hive::User, "S-1-5-18"))
        );
        assert_eq!(classify_hku_subkey(".DEFAULT"), None);
        assert_eq!(classify_hku_subkey("S-1-5-18_Classes"), None);
        assert_eq!(
            display_key(Hive::UserClasses, "S-1-5-21-9", r"CLSID\{x}\InprocServer32"),
            r"HKU\S-1-5-21-9\Software\Classes\CLSID\{x}\InprocServer32"
        );
        assert_eq!(
            display_key(Hive::Machine, "", r"SOFTWARE\X\"),
            r"HKLM\SOFTWARE\X"
        );
        assert_eq!(display_key(Hive::User, "S-1-5-18", ""), r"HKU\S-1-5-18");
    }

    #[test]
    fn table_is_sane() {
        for s in WATCH_TABLE {
            assert!(
                !s.path.starts_with('\\') && !s.path.ends_with('\\'),
                "{}",
                s.path
            );
            assert!(s.depth <= 4);
        }
        let ifeo = WATCH_TABLE
            .iter()
            .find(|s| s.path.ends_with("Image File Execution Options"))
            .unwrap();
        assert!(value_wanted(ifeo, "debugger"));
        assert!(!value_wanted(ifeo, "UseFilter"));
        assert!(WATCH_TABLE
            .iter()
            .any(|s| s.path.ends_with(r"Explorer\RunMRU") && s.hive == Hive::User));
        assert!(WATCH_TABLE
            .iter()
            .any(|s| s.path.ends_with(r"SecurityProviders\WDigest")));
    }

    #[test]
    fn diff_values_and_keys() {
        let old = TreeSnap {
            keys: [
                key(
                    "",
                    &[
                        ("Keep", REG_SZ, &w16("a")),
                        ("Gone", REG_SZ, &w16("b")),
                        ("Chg", REG_DWORD, &[0, 0, 0, 0]),
                    ],
                ),
                key("Sub", &[("x", REG_SZ, &w16("1"))]),
                key(r"Sub\Deeper", &[]),
            ]
            .into_iter()
            .collect(),
            truncated: false,
        };
        let new = TreeSnap {
            keys: [
                key(
                    "",
                    &[
                        ("Keep", REG_SZ, &w16("a")),
                        ("Chg", REG_DWORD, &[1, 0, 0, 0]),
                        ("New", REG_SZ, &w16("n")),
                    ],
                ),
                key("Added", &[("Debugger", REG_SZ, &w16("cmd.exe"))]),
            ]
            .into_iter()
            .collect(),
            truncated: false,
        };
        let d = diff_tree(&old, &new);
        let find = |rel: &str, v: &str| {
            d.iter()
                .find(|c| c.rel == rel && c.value_name == v)
                .cloned()
        };
        assert_eq!(find("", "Chg").unwrap().op, RegistryOp::Set);
        assert_eq!(find("", "New").unwrap().op, RegistryOp::Set);
        assert_eq!(find("", "Gone").unwrap().op, RegistryOp::DeleteValue);
        assert!(find("", "Keep").is_none());
        assert_eq!(
            find("Added", "Debugger").unwrap().data.unwrap(),
            w16("cmd.exe")
        );
        assert_eq!(find("Sub", "").unwrap().op, RegistryOp::DeleteKey);
        // Only the topmost deleted key is reported.
        assert!(find(r"Sub\Deeper", "").is_none());
        assert_eq!(d.len(), 5, "{d:?}");
        // A truncated walk never reports deletions.
        let mut t = new.clone();
        t.truncated = true;
        assert!(diff_tree(&old, &t)
            .iter()
            .all(|c| c.op != RegistryOp::DeleteKey));
        // No change → nothing.
        assert!(diff_tree(&new, &new).is_empty());
    }

    #[test]
    fn long_values_compare_by_hash() {
        let a = vec![1u8; MAX_VALUE_BYTES + 10];
        let mut b = a.clone();
        *b.last_mut().unwrap() = 2;
        let (va, vb) = (ValueSnap::new(3, &a), ValueSnap::new(3, &b));
        assert_eq!(va.data, vb.data);
        assert_ne!(va.hash, vb.hash);
    }

    #[test]
    fn sysmon_rendering() {
        assert_eq!(
            render_sysmon(REG_DWORD, &1u32.to_le_bytes()).unwrap(),
            "DWORD (0x00000001)"
        );
        assert_eq!(
            render_sysmon(REG_DWORD, &0u32.to_le_bytes()).unwrap(),
            "DWORD (0x00000000)"
        );
        assert_eq!(
            render_sysmon(REG_QWORD, &0x01d9_a8e3_5c1f_2a80u64.to_le_bytes()).unwrap(),
            "QWORD (0x01d9a8e3-0x5c1f2a80)"
        );
        assert_eq!(
            render_sysmon(REG_SZ, &w16("notepad.exe")).unwrap(),
            "notepad.exe"
        );
        let mut ms = w16("a");
        ms.extend(w16("b"));
        ms.extend([0, 0]);
        assert_eq!(render_sysmon(REG_MULTI_SZ, &ms).unwrap(), "a b");
        assert_eq!(render_sysmon(3, &[0xde, 0xad]).unwrap(), "dead");
        assert_eq!(render_sysmon(3, &[]), None);
        assert_eq!(render_sysmon(REG_DWORD, &[1]), None);
        assert_eq!(render_sysmon(REG_SZ, &[]).unwrap(), "");
    }

    fn w(pid: u32, attribution: Attribution) -> Option<Writer> {
        Some(Writer { pid, attribution })
    }

    #[test]
    fn join_attributes_by_value_name_and_key_object() {
        use Attribution::{Exact, Heuristic};
        let mut j = RegJoin::new();
        let k_run = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run";
        let k_mru = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU";
        j.record(1_000, 111, 0xA, "KestrelProbe", false);
        j.record(1_100, 222, 0xB, "Other", false);
        // Watcher saw the change slightly after the write: a value-name match
        // is heuristic (single candidate: KeyObject 0xA is learnt).
        assert_eq!(
            j.attribute(k_run, "kestrelprobe", RegistryOp::Set, 1_050, false),
            w(111, Heuristic)
        );
        // Op must match: a delete is not attributed to a set.
        assert_eq!(
            j.attribute(k_run, "KestrelProbe", RegistryOp::DeleteValue, 1_050, false),
            None
        );
        // Out of window.
        assert_eq!(
            j.attribute(k_run, "Other", RegistryOp::Set, 9_000, false),
            None
        );
        // KeyObject 0xA (pid 111) is now known to be the Run key: a write
        // through it is Exact; it is never attributed to RunMRU.
        j.record(5_000, 111, 0xA, "a", false);
        j.record(5_010, 333, 0xC, "a", false);
        assert_eq!(
            j.attribute(k_mru, "a", RegistryOp::Set, 5_020, false),
            w(333, Heuristic)
        );
        assert_eq!(
            j.attribute(k_run, "a", RegistryOp::Set, 5_020, false),
            w(111, Exact)
        );
        // Delete value joins on event 6.
        j.record(7_000, 444, 0xD, "KestrelProbe", true);
        assert_eq!(
            j.attribute(k_run, "KestrelProbe", RegistryOp::DeleteValue, 7_400, false),
            w(444, Heuristic)
        );
        assert_eq!(
            j.attribute(k_run, "", RegistryOp::DeleteKey, 7_400, false),
            None
        );
        assert_eq!(j.attributed, 4);
        j.expire(100_000);
        assert!(j.is_empty());
    }

    #[test]
    fn join_prefers_unused_closest_write() {
        use Attribution::Heuristic;
        let mut j = RegJoin::new();
        j.record(1_000, 1, 0, "v", false);
        j.record(1_900, 2, 0, "v", false);
        assert_eq!(
            j.attribute("HKLM\\A", "v", RegistryOp::Set, 2_000, false),
            w(2, Heuristic)
        );
        assert_eq!(
            j.attribute("HKLM\\B", "v", RegistryOp::Set, 2_000, false),
            w(1, Heuristic)
        );
        // Both used: still attributes (closest).
        assert_eq!(
            j.attribute("HKLM\\C", "v", RegistryOp::Set, 2_000, false),
            w(2, Heuristic)
        );
    }

    /// V-H6: malware writes `HKCU\Junk\Upd` with the signed reg.exe and its
    /// own `Run\Upd` at the same moment. Two candidates: heuristic only, and
    /// neither handle is learnt (so the decoy can never become "exact").
    #[test]
    fn ambiguous_value_name_is_heuristic_and_not_learnt() {
        let run = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run";
        let mut j = RegJoin::new();
        j.record(1_000, 50, 0x50, "Upd", false); // reg.exe -> HKCU\Junk
        j.record(1_010, 66, 0x66, "Upd", false); // malware -> Run
        let r = j
            .attribute(run, "Upd", RegistryOp::Set, 1_020, false)
            .unwrap();
        assert_eq!(r.attribution, Attribution::Heuristic);
        assert!(
            j.key_objects.is_empty(),
            "nothing learnt from an ambiguous join"
        );
        // Same pid, same handle later: still only heuristic.
        j.record(3_000, 50, 0x50, "Upd", false);
        assert_eq!(
            j.attribute(run, "Upd", RegistryOp::Set, 3_010, false)
                .unwrap()
                .attribution,
            Attribution::Heuristic
        );
    }

    /// A learnt handle does not make another process "exact" (handle
    /// addresses are per process; reuse by another pid is not trusted).
    #[test]
    fn learnt_handle_is_per_pid() {
        let run = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let mut j = RegJoin::new();
        j.record(1_000, 7, 0x70, "A", false);
        assert_eq!(
            j.attribute(run, "A", RegistryOp::Set, 1_000, false)
                .unwrap()
                .attribution,
            Attribution::Heuristic
        );
        j.record(2_000, 8, 0x70, "B", false); // same address, other process
        assert_eq!(
            j.attribute(run, "B", RegistryOp::Set, 2_000, false),
            w(8, Attribution::Heuristic)
        );
        j.record(3_000, 7, 0x70, "C", false);
        assert_eq!(
            j.attribute(run, "C", RegistryOp::Set, 3_000, false),
            w(7, Attribution::Exact)
        );
    }

    /// V-H7: values of a re-created / renamed watched key only join on a
    /// known handle; a same-named decoy write elsewhere is ignored.
    #[test]
    fn exact_only_for_recreated_keys() {
        let run = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run";
        let mut j = RegJoin::new();
        j.record(1_000, 66, 0x66, "Upd", false);
        assert_eq!(j.attribute(run, "Upd", RegistryOp::Set, 1_010, true), None);
    }
}
