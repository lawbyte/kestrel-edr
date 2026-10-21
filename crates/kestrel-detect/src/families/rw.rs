//! RW-xx ransomware preparation and impact rules.
//!
//! * RW-01…RW-05: preparation commands (shadow copies, boot recovery, Safe
//!   Mode staging, log clearing, service / process kill sprees).
//! * RW-06…RW-08: impact, from the aggregated `FileActivity` event of the
//!   ransomware file sensor (mass encryption, canary tamper, note fan-out).
//! * RW-12: host-level kill-chain correlation over distinct RW-01…05 alerts.
//!
//! RW-09/10/11/13 are deferred (see `docs/research/general-malware-report.md`).
//!
//! "Lineage" is the acting process plus its ancestors up to (excluding) the
//! first protected, trusted-system, Explorer, agent or signed Program Files
//! tool. Containment kills that lineage; it never walks past those stops.
//!
//! All state is bounded (per-map caps with oldest-first eviction, per-entry
//! deques capped and trimmed by time in `tick`) and every parser tolerates
//! arbitrary input.

use super::{Ctx, Family, FamilyHit};
use crate::catalog::meta;
use kestrel_common::{
    file_name_lower, Alert, Event, EventData, FileActivity, Integrity, PathClass, ProcessGuid,
    ProcessInfo, ProcessStart, RegistryOp, ResponseAction, RuleCategory, RuleMeta, RuleMode,
    Severity, SignatureState, TargetProcess, TimestampMs,
};
use std::collections::{HashMap, HashSet, VecDeque};

pub const RW01: &str = "RW-01";
pub const RW02: &str = "RW-02";
pub const RW03: &str = "RW-03";
pub const RW04: &str = "RW-04";
pub const RW05: &str = "RW-05";
pub const RW06: &str = "RW-06";
pub const RW07: &str = "RW-07";
pub const RW08: &str = "RW-08";
pub const RW12: &str = "RW-12";

/// Inputs of the RW-12 correlation.
const PREP_RULES: &[&str] = &[RW01, RW02, RW03, RW04, RW05];

const MIN: i64 = 60_000;
/// RW-05 command-line spree window and threshold (distinct targets).
const RW05_CMD_WINDOW_MS: i64 = 120_000;
const RW05_CMD_MIN: usize = 5;
/// RW-05 TerminateProcess spree window and threshold (distinct targets).
const RW05_TERM_WINDOW_MS: i64 = 10_000;
const RW05_TERM_MIN: usize = 10;
/// RW-04 escalation: same lineage fired RW-01/02/03/05 within this window.
const RW04_ESCALATE_MS: i64 = 30 * MIN;
/// RW-03 autologon correlation window after a Safe Mode staging hit.
const RW03_AUTOLOGON_MS: i64 = 10 * MIN;
/// RW-08: kill when the same process fired RW-06/07 within this window.
const RW08_COMBINE_MS: i64 = 10 * MIN;
/// RW-12 correlation window and cool-down.
const RW12_WINDOW_MS: i64 = 60 * MIN;
/// "Ransomware alert" state after RW-12: RW-06 thresholds halved.
const RANSOM_ALERT_MS: i64 = 120 * MIN;

/// RW-06 thresholds (halved while the host is in ransomware-alert state).
const RW06_TOUCHED: u64 = 30;
const RW06_DIRS: u64 = 3;
const RW06_EXT: u64 = 20;
const RW06_OVERWRITES: u64 = 50;
const RW06_OVERWRITE_PCT: u64 = 80;
/// RW-08 thresholds.
const RW08_NOTE_DIRS: u32 = 5;
const RW08_FALLBACK_DIRS: u32 = 20;

/// Bounds.
const MAX_KEYS: usize = 1024;
const MAX_PER_KEY: usize = 64;
const MAX_GUID_MARKS: usize = 4096;
const MAX_HOST_HITS: usize = 64;
const LINEAGE_DEPTH: usize = 8;

/// Kestrel's own service name (`kestrel_win::SERVICE_NAME`, lower-case): its
/// `SafeBoot\Network` registration must never trip RW-03.
const KESTREL_SERVICE: &str = "kestrelagent";

/// Interactive shells: an admin typing in one of these under Explorer is
/// "admin context" (only the tool is contained, never the shell).
const SHELLS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "windowsterminal.exe",
    "wt.exe",
    "openconsole.exe",
];

const POWERSHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "powershell_ise.exe"];

/// Validly signed sync / backup / archiver clients: RW-06/07 alert only.
const SYNC_BACKUP_ARCHIVERS: &[&str] = &[
    "onedrive.exe",
    "filecoauth.exe",
    "dropbox.exe",
    "googledrivefs.exe",
    "box.exe",
    "boxsync.exe",
    "7z.exe",
    "7zg.exe",
    "7zfm.exe",
    "winrar.exe",
    "rar.exe",
    "unrar.exe",
    "bandizip.exe",
    "peazip.exe",
    "wbengine.exe",
    "sdclt.exe",
];
/// Same, by name prefix (vendor agents with many binaries).
const SYNC_BACKUP_PREFIXES: &[&str] =
    &["veeam", "acronis", "cyberprotect", "backblaze", "carbonite"];

/// RW-05 curated targets (service or image names, lower-case).
const KILL_TARGET_PREFIXES: &[&str] = &[
    "sql",
    "mssql",
    "vss",
    "veeam",
    "sophos",
    "sap",
    "msexchange",
    "oracle",
    "acronis",
];
const KILL_TARGET_SUBSTRINGS: &[&str] = &[
    "sql",
    "veeam",
    "backup",
    "sophos",
    "msmpeng",
    "windefend",
    "exchange",
    "oracle",
    "memtas",
    "mepocs",
    "acronis",
    "arcserve",
    "veritas",
    "bedbg",
    "dbsnmp",
    "ocssd",
    "wbengine",
    "swprv",
];
const KILL_TARGET_EXACT: &[&str] = &["vss", "sense", "sap"];

/// RW-08 note extensions (the 5-folder, kill-capable name check).
const NOTE_EXTS: &[&str] = &["txt", "hta", "html", "htm", "rtf", "url"];
/// Further text formats that count as a note only for the 20-folder,
/// alert-only fallback: `README.md` lands in hundreds of folders on every
/// `npm install`, so it must never reach the kill path.
const NOTE_FALLBACK_TEXT_EXTS: &[&str] = &["md", "pdf", "nfo"];
/// Images some families drop as the note (wallpaper copies): only with a
/// note-like name.
const NOTE_IMAGE_EXTS: &[&str] = &["bmp", "jpg", "jpeg", "png"];
/// Build artefacts compilers write once per output folder (triage
/// 2026-10-22: rustc's `tmp.a` in 24 folders): never a note. `.tmp` only
/// counts with a note-like name.
const BUILD_ARTEFACT_EXTS: &[&str] = &[
    "a",
    "o",
    "obj",
    "rlib",
    "rmeta",
    "d",
    "pdb",
    "lib",
    "exp",
    "ilk",
    "idb",
    "pch",
    "tlog",
    "lastbuildstate",
    "res",
    "manifest",
    "map",
    "class",
    "pyc",
    "pyo",
    "dll",
    "exe",
    "so",
    "dylib",
    "wasm",
    "bin",
    "timestamp",
    "stamp",
    "fingerprint",
    "lock",
    "json",
];

#[derive(Default)]
pub(crate) struct Ransomware {
    /// RW-05 command-line spree: lineage head → (ts, target).
    kill_cmds: HashMap<ProcessGuid, VecDeque<(TimestampMs, String)>>,
    /// RW-05 TerminateProcess spree: actor → (ts, target key).
    terminates: HashMap<ProcessGuid, VecDeque<(TimestampMs, String)>>,
    /// Lineage members of RW-01/02/03/05 alerts (RW-04 escalation).
    prep_marks: HashMap<ProcessGuid, TimestampMs>,
    /// Lineage members of RW-03 alerts (autologon correlation).
    safeboot_marks: HashMap<ProcessGuid, TimestampMs>,
    /// Subjects of RW-06/07 alerts (RW-08 combination).
    impact_marks: HashMap<ProcessGuid, TimestampMs>,
    /// Subjects of RW-06 alerts (RW-07 in-place escalation, V-H9).
    rw06_marks: HashMap<ProcessGuid, TimestampMs>,
    /// Subjects of alert-only, in-place RW-07 hits (heuristic actor): their
    /// RW-07 alert does not count as an impact mark.
    inplace_marks: HashMap<ProcessGuid, TimestampMs>,
    /// Processes that exited with a non-zero code (RW-12, V-M4).
    failed: HashMap<ProcessGuid, TimestampMs>,
    /// RW-12 inputs: (ts, rule, subject, lineage key set at alert time).
    host_hits: VecDeque<(TimestampMs, &'static str, ProcessInfo, HashSet<ProcessGuid>)>,
    /// Last RW-12 hit (host-level cool-down).
    last_rw12: Option<TimestampMs>,
    /// Ransomware-alert state (RW-06 thresholds halved) until this time.
    ransom_alert_until: TimestampMs,
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Quote-aware, lower-cased argument split. `-x` / `–x` / `—x` become `/x`.
fn args(cmdline: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for c in cmdline.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
        if out.len() >= 256 {
            break;
        }
    }
    if !cur.is_empty() && out.len() < 256 {
        out.push(cur);
    }
    out.into_iter()
        .map(|t| {
            let t = t.to_lowercase();
            let t = t.trim_matches('\'').to_string();
            match t.chars().next() {
                Some('-' | '\u{2013}' | '\u{2014}' | '\u{2015}') => {
                    let first = t.chars().next().map(char::len_utf8).unwrap_or(1);
                    format!("/{}", &t[first..])
                }
                _ => t,
            }
        })
        .filter(|t| !t.is_empty())
        .collect()
}

fn has(a: &[String], tok: &str) -> bool {
    a.iter().any(|t| t == tok)
}

fn has_prefix(a: &[String], p: &str) -> bool {
    a.iter().any(|t| t.starts_with(p))
}

fn idx(a: &[String], tok: &str) -> Option<usize> {
    a.iter().position(|t| t == tok)
}

/// Collapse whitespace and lower-case (for substring checks).
fn flat(s: &str) -> String {
    s.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// `a` immediately followed by `b`, optionally with one character between
/// (the `a.?b` of the rule spec).
fn near(s: &str, a: &str, b: &str) -> bool {
    let mut from = 0;
    while let Some(i) = s[from..].find(a) {
        let after = from + i + a.len();
        let rest = &s[after..];
        if rest.starts_with(b) {
            return true;
        }
        let mut ch = rest.chars();
        if ch.next().is_some() && ch.as_str().starts_with(b) {
            return true;
        }
        from = after;
        if from >= s.len() {
            break;
        }
    }
    false
}

fn name_of(p: &ProcessInfo) -> String {
    file_name_lower(&p.image)
}

fn is_real_explorer(ctx: &Ctx, p: &ProcessInfo) -> bool {
    name_of(p) == "explorer.exe" && ctx.path_class(&p.image) == PathClass::Windows
}

/// Validly signed, non-LOLBin binary in Program Files (admin, RMM, backup tool).
fn trusted_tool(ctx: &Ctx, p: &ProcessInfo) -> bool {
    p.signed == SignatureState::Valid
        && ctx.path_class(&p.image) == PathClass::ProgramFiles
        && !ctx.is_lolbin(&name_of(p))
}

/// Unsigned / invalid / unknown signature, or a user-writable location.
fn untrusted_image(ctx: &Ctx, p: &ProcessInfo) -> bool {
    p.image.is_empty()
        || p.signed != SignatureState::Valid
        || ctx.path_class(&p.image).is_user_writable()
}

fn sync_backup_client(p: &ProcessInfo) -> bool {
    let n = name_of(p);
    p.signed == SignatureState::Valid
        && (SYNC_BACKUP_ARCHIVERS.contains(&n.as_str())
            || SYNC_BACKUP_PREFIXES.iter().any(|x| n.starts_with(x)))
}

struct Lineage {
    /// Subject first, then its untrusted ancestors (nearest first).
    members: Vec<ProcessInfo>,
    /// The ancestor the walk stopped at, if any.
    stop: Option<ProcessInfo>,
}

impl Lineage {
    fn head(&self) -> Option<&ProcessInfo> {
        self.members.last()
    }
    fn guids(&self) -> impl Iterator<Item = &ProcessGuid> {
        self.members.iter().map(|p| &p.guid)
    }
}

/// Validly signed program that is not a LOLBin / script host, wherever it
/// is installed (per-user VS Code, Teams, Slack in AppData included).
fn signed_program(ctx: &Ctx, p: &ProcessInfo) -> bool {
    p.signed == SignatureState::Valid && !p.image.is_empty() && !ctx.is_lolbin(&name_of(p))
}

/// Lineage stop (V-M5): protected, agent, trusted system binary, Explorer,
/// or any validly signed non-LOLBin program (a signed app that launched a
/// shell is not the ransomware).
fn is_stop(ctx: &Ctx, p: &ProcessInfo) -> bool {
    ctx.protected(p)
        || ctx.is_agent(p)
        || ctx.system_trusted(p)
        || is_real_explorer(ctx, p)
        || trusted_tool(ctx, p)
        || signed_program(ctx, p)
}

fn lineage(ctx: &Ctx, guid: &ProcessGuid) -> Lineage {
    let Some(subject) = ctx.process(guid) else {
        return Lineage {
            members: vec![],
            stop: None,
        };
    };
    let mut members = vec![subject.clone()];
    let mut stop = None;
    for a in ctx.ancestry(guid, LINEAGE_DEPTH) {
        if is_stop(ctx, &a) {
            stop = Some(a);
            break;
        }
        members.push(a);
    }
    Lineage { members, stop }
}

/// The tool was typed by an administrator: everything between it and an
/// Explorer / signed admin-tool stop is an interactive shell.
fn admin_context(ctx: &Ctx, lin: &Lineage) -> bool {
    let shells_only = lin
        .members
        .iter()
        .skip(1)
        .all(|p| SHELLS.contains(&name_of(p).as_str()));
    shells_only
        && lin.stop.as_ref().is_some_and(|s| {
            is_real_explorer(ctx, s) || trusted_tool(ctx, s) || signed_program(ctx, s)
        })
}

/// Kill each process (tree) and quarantine user-writable, non-LOLBin images
/// that are not validly signed (V-M5).
fn contain(ctx: &Ctx, procs: &[ProcessInfo]) -> Vec<ResponseAction> {
    let mut out = Vec::new();
    for p in procs {
        if ctx.protected(p) || ctx.is_agent(p) || p.pid == 0 || p.pid == 4 {
            continue;
        }
        out.push(ResponseAction::KillProcess {
            pid: p.pid,
            guid: Some(p.guid.clone()),
            tree: true,
        });
        if !p.image.is_empty()
            && p.signed != SignatureState::Valid
            && ctx.path_class(&p.image).is_user_writable()
            && !ctx.is_lolbin(&name_of(p))
        {
            out.push(ResponseAction::QuarantineFile {
                path: p.image.clone(),
                sha256: p.sha256.clone(),
            });
        }
    }
    out
}

/// Prep-rule containment: the tool always, the rest of the lineage unless an
/// administrator typed it.
fn contain_prep(ctx: &Ctx, lin: &Lineage) -> Vec<ResponseAction> {
    if admin_context(ctx, lin) {
        contain(ctx, &lin.members[..lin.members.len().min(1)])
    } else {
        contain(ctx, &lin.members)
    }
}

fn mark(map: &mut HashMap<ProcessGuid, TimestampMs>, g: &ProcessGuid, ts: TimestampMs) {
    if !map.contains_key(g) && map.len() >= MAX_GUID_MARKS {
        if let Some(old) = map.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
            map.remove(&old);
        }
    }
    let e = map.entry(g.clone()).or_insert(ts);
    *e = (*e).max(ts);
}

fn marked(
    map: &HashMap<ProcessGuid, TimestampMs>,
    g: &ProcessGuid,
    now: TimestampMs,
    window: i64,
) -> bool {
    map.get(g).is_some_and(|t| now >= *t && now - *t <= window)
}

/// Append `(ts, v)` to the deque of `key` (bounded keys and entries).
fn push_keyed(
    map: &mut HashMap<ProcessGuid, VecDeque<(TimestampMs, String)>>,
    key: &ProcessGuid,
    ts: TimestampMs,
    v: String,
    window: i64,
) -> usize {
    if !map.contains_key(key) && map.len() >= MAX_KEYS {
        let old = map
            .iter()
            .min_by_key(|(_, d)| d.back().map(|x| x.0).unwrap_or(i64::MIN))
            .map(|(k, _)| k.clone());
        if let Some(old) = old {
            map.remove(&old);
        }
    }
    let d = map.entry(key.clone()).or_default();
    while d.front().is_some_and(|(t, _)| ts - *t > window) {
        d.pop_front();
    }
    if d.len() >= MAX_PER_KEY {
        d.pop_front();
    }
    d.push_back((ts, v));
    let distinct: HashSet<&str> = d
        .iter()
        .filter(|(t, _)| *t <= ts && ts - *t <= window)
        .map(|(_, v)| v.as_str())
        .collect();
    distinct.len()
}

fn kill_target_curated(t: &str) -> bool {
    let t = t.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    let t = t.strip_suffix(".exe").unwrap_or(t);
    !t.is_empty()
        && (KILL_TARGET_EXACT.contains(&t)
            || KILL_TARGET_PREFIXES.iter().any(|p| t.starts_with(p))
            || KILL_TARGET_SUBSTRINGS.iter().any(|s| t.contains(s)))
}

// ---------------------------------------------------------------------------
// command-line classifiers (pure, unit-tested)
// ---------------------------------------------------------------------------

/// RW-01 on a process start. Returns a short description of the variant.
fn rw01_cmd(ctx: &Ctx, name: &str, a: &[String], cmd_flat: &str) -> Option<&'static str> {
    match name {
        "vssadmin.exe" => {
            if has(a, "delete") && has_prefix(a, "shadows") {
                return Some("deleted the Volume Shadow Copies");
            }
            if has(a, "resize")
                && has(a, "shadowstorage")
                && (has_prefix(a, "/maxsize=") || cmd_flat.contains("unbounded"))
            {
                return Some("shrank the shadow-copy storage (which silently deletes snapshots)");
            }
            None
        }
        "wmic.exe" => (cmd_flat.contains("shadowcopy") && has(a, "delete"))
            .then_some("deleted the Volume Shadow Copies through WMI"),
        "diskshadow.exe" => {
            if cmd_flat.contains("delete") && cmd_flat.contains("shadow") {
                return Some("deleted the Volume Shadow Copies with DiskShadow");
            }
            let script = idx(a, "/s").and_then(|i| a.get(i + 1));
            script
                .filter(|p| ctx.path_class(p).is_user_writable())
                .map(|_| "ran a DiskShadow script from a user-writable folder")
        }
        "wbadmin.exe" => {
            if !has(a, "delete") {
                return None;
            }
            if has(a, "catalog") {
                Some("deleted the Windows Backup catalog")
            } else if has(a, "systemstatebackup") {
                Some("deleted the system-state backups")
            } else if has(a, "backup") && has(a, "/keepversions:0") {
                Some("deleted all Windows Backup versions")
            } else {
                None
            }
        }
        n if POWERSHELLS.contains(&n) => (cmd_flat.contains("shadow")
            && cmd_flat.contains("delete"))
        .then_some("deleted the Volume Shadow Copies from PowerShell"),
        _ => None,
    }
}

/// RW-01 on PowerShell script content.
fn rw01_script(content_flat: &str) -> bool {
    let c = content_flat;
    c.contains("win32_shadowcopy")
        && ["get-wmiobject", "gwmi", "get-ciminstance", "gcim"]
            .iter()
            .any(|g| c.contains(g))
        && [
            ".delete()",
            "remove-wmiobject",
            "rwmi",
            "remove-ciminstance",
            "rcim",
        ]
        .iter()
        .any(|d| c.contains(d))
}

/// RW-02: (variant, protect-worthy).
fn rw02_cmd(name: &str, a: &[String]) -> Option<(&'static str, bool)> {
    match name {
        "bcdedit.exe" => {
            let after =
                |k: &str, v: &str| idx(a, k).is_some_and(|i| a.get(i + 1).is_some_and(|x| x == v));
            if has(a, "/set") && after("recoveryenabled", "no") {
                return Some(("disabled Windows boot recovery", true));
            }
            if has(a, "/set") && after("bootstatuspolicy", "ignoreallfailures") {
                return Some(("told Windows to ignore boot failures", true));
            }
            if has(a, "/deletevalue") && has(a, "recoverysequence") {
                return Some(("removed the boot recovery sequence", true));
            }
            if has(a, "/delete") && (has(a, "{default}") || has(a, "{current}")) {
                return Some(("deleted the default boot entry", true));
            }
            None
        }
        "reagentc.exe" => {
            has(a, "/disable").then_some(("disabled the Windows Recovery Environment", false))
        }
        _ => None,
    }
}

/// RW-03 on a process start: (variant, protect-worthy).
fn rw03_cmd(name: &str, a: &[String], cmd_flat: &str) -> Option<(&'static str, bool)> {
    match name {
        "bcdedit.exe" => {
            if has(a, "/set") && (has(a, "safeboot") || has(a, "safebootalternateshell")) {
                return Some(("set the next boot to Safe Mode", true));
            }
            None
        }
        "reg.exe" => {
            let sb = cmd_flat.contains(r"\control\safeboot");
            if sb && has(a, "delete") {
                return Some(("deleted Safe Mode service registrations", false));
            }
            if sb
                && has(a, "add")
                && (cmd_flat.contains(r"\safeboot\minimal\")
                    || cmd_flat.contains(r"\safeboot\network\"))
            {
                return Some(("registered a service to start in Safe Mode", false));
            }
            None
        }
        _ => None,
    }
}

/// RW-04 on a process start.
fn rw04_cmd(name: &str, a: &[String], cmd_flat: &str) -> Option<&'static str> {
    match name {
        "wevtutil.exe" => {
            if has(a, "cl") || has(a, "clear-log") {
                return Some("cleared a Windows event log");
            }
            if (has(a, "sl") || has(a, "set-log"))
                && (has_prefix(a, "/ms:")
                    || has_prefix(a, "/maxsize:")
                    || has_prefix(a, "/lfn:")
                    || has(a, "/e:false")
                    || has(a, "/enabled:false"))
            {
                return Some("shrank, redirected or disabled a Windows event log");
            }
            None
        }
        "wmic.exe" => cmd_flat
            .contains("cleareventlog")
            .then_some("cleared a Windows event log through WMI"),
        n if POWERSHELLS.contains(&n) => rw04_script(cmd_flat),
        _ => None,
    }
}

fn rw04_script(c: &str) -> Option<&'static str> {
    if ["clear-eventlog", "remove-eventlog", "clear-winevent"]
        .iter()
        .any(|k| c.contains(k))
        || (c.contains("eventlogsession") && c.contains("clearlog"))
        || c.contains("cleareventlog")
    {
        Some("cleared Windows event logs from PowerShell")
    } else if c.contains("limit-eventlog") {
        Some("shrank a Windows event log from PowerShell")
    } else {
        None
    }
}

/// RW-05: curated kill/stop targets of one command (empty = not a kill command).
fn rw05_targets(name: &str, a: &[String], cmd_flat: &str) -> Vec<String> {
    let mut out = Vec::new();
    match name {
        "net.exe" | "net1.exe" => {
            if let Some(i) = idx(a, "stop") {
                let t: Vec<&str> = a[i + 1..]
                    .iter()
                    .filter(|x| !x.starts_with('/'))
                    .map(String::as_str)
                    .collect();
                out.push(t.join(" "));
            }
        }
        "sc.exe" => {
            if let Some(i) = idx(a, "stop") {
                if let Some(t) = a.get(i + 1) {
                    out.push(t.clone());
                }
            } else if let Some(i) = idx(a, "config") {
                let disabled = a.iter().any(|x| x == "disabled" || x == "start=disabled");
                if disabled {
                    if let Some(t) = a.get(i + 1) {
                        out.push(t.clone());
                    }
                }
            }
        }
        "taskkill.exe" => {
            if has(a, "/f") {
                for (i, t) in a.iter().enumerate() {
                    if t == "/im" {
                        if let Some(n) = a.get(i + 1) {
                            out.push(n.clone());
                        }
                    }
                }
            }
        }
        n if POWERSHELLS.contains(&n) => {
            let stop = cmd_flat.contains("stop-service") || cmd_flat.contains("spsv ");
            let disable = cmd_flat.contains("set-service") && cmd_flat.contains("disabled");
            if stop || disable {
                // One logical target per curated keyword named on the line.
                for t in a.iter().filter(|t| !t.starts_with('/')) {
                    let t = t.trim_matches(|c: char| c == ',' || c == ';' || c == '\'');
                    if kill_target_curated(t) {
                        out.push(t.to_string());
                    }
                }
            }
        }
        _ => {}
    }
    out.into_iter()
        .map(|t| t.trim_matches(|c: char| c == '"' || c == '\'').to_string())
        .filter(|t| kill_target_curated(t))
        .collect()
}

fn note_like(name: &str) -> bool {
    let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(name);
    near(stem, "read", "me")
        || near(stem, "how", "to")
        || [
            "restore",
            "recover",
            "decrypt",
            "help",
            "instruction",
            "unlock",
            "ransom",
            "files",
            "!!!",
            "_info",
        ]
        .iter()
        .any(|k| stem.contains(k))
}

/// Extension of a note candidate (lower-case), `None` when the name has no
/// extension.
fn note_extension(name: &str) -> Option<&str> {
    name.rsplit_once('.')
        .filter(|(stem, e)| !stem.is_empty() && !e.is_empty())
        .map(|(_, e)| e)
}

/// A note extension of the kill-capable 5-folder check.
fn note_ext(name: &str) -> bool {
    note_extension(name).is_some_and(|e| NOTE_EXTS.contains(&e))
}

/// A text / document note (incl. `.md`), or an image note (bmp / jpg / png)
/// with a note-like name: the 20-folder fallback.
fn fallback_note_ext(name: &str) -> bool {
    match note_extension(name) {
        Some(e) if NOTE_EXTS.contains(&e) || NOTE_FALLBACK_TEXT_EXTS.contains(&e) => true,
        Some(e) if NOTE_IMAGE_EXTS.contains(&e) => note_like(name),
        _ => false,
    }
}

/// Triage 2026-10-22 item 3 (cargo's OUT_DIR "out" in 38 folders, rustc's
/// "tmp.a" in 24): does a name newly created in many folders look like a
/// ransom note at all? It needs an extension (the aggregator cannot tell a
/// new directory from a new file, and directories are never notes), must
/// not be a build artefact (`.tmp` only with a note-like name), and needs a
/// document / text extension or a note-like name.
fn note_characteristics(name: &str) -> bool {
    let Some(e) = note_extension(name) else {
        return false;
    };
    if e == "tmp" {
        return note_like(name);
    }
    if BUILD_ARTEFACT_EXTS.contains(&e) {
        return false;
    }
    fallback_note_ext(name) || (note_like(name) && !NOTE_IMAGE_EXTS.contains(&e))
}

// ---------------------------------------------------------------------------
// rule bodies
// ---------------------------------------------------------------------------

impl Ransomware {
    fn on_start(&mut self, ctx: &Ctx, e: &Event, ps: &ProcessStart, out: &mut Vec<FamilyHit>) {
        let Some(subject) = ctx.process(&e.guid) else {
            return;
        };
        if ctx.is_agent(subject) || ctx.protected(subject) {
            return;
        }
        let name = file_name_lower(&ps.image);
        let a = args(&ps.cmdline);
        let cf = flat(&ps.cmdline);
        let shown = shown_name(&name);

        if let Some(what) = rw01_cmd(ctx, &name, &a, &cf) {
            let lin = lineage(ctx, &e.guid);
            let actions = contain_prep(ctx, &lin);
            out.push(
                FamilyHit::new(
                    RW01,
                    &e.guid,
                    Severity::Critical,
                    format!(
                        "{shown} {what}, a typical step right before ransomware encrypts files; the snapshots may already be gone, so check that offline backups are intact."
                    ),
                )
                .with_actions(actions),
            );
        }
        if let Some((what, strong)) = rw02_cmd(&name, &a) {
            let lin = lineage(ctx, &e.guid);
            let actions = if strong {
                contain_prep(ctx, &lin)
            } else {
                vec![]
            };
            let fix = if name == "reagentc.exe" {
                "re-enable it with `reagentc /enable`"
            } else {
                "restore it with `bcdedit /set {default} recoveryenabled yes` and `bcdedit /set {default} bootstatuspolicy displayallfailures`"
            };
            out.push(
                FamilyHit::new(
                    RW02,
                    &e.guid,
                    if strong {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    format!(
                        "{shown} {what}, which ransomware does so the PC cannot be repaired after encryption; an administrator should {fix}."
                    ),
                )
                .with_actions(actions),
            );
        }
        if let Some((what, strong)) = rw03_cmd(&name, &a, &cf) {
            let lin = lineage(ctx, &e.guid);
            let actions = if strong && !admin_context(ctx, &lin) {
                contain(ctx, &lin.members)
            } else {
                vec![]
            };
            let fix = if strong {
                " (undo with `bcdedit /deletevalue {default} safeboot`)"
            } else {
                ""
            };
            out.push(
                FamilyHit::new(
                    RW03,
                    &e.guid,
                    if strong {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    format!(
                        "{shown} {what}{fix}; ransomware reboots into Safe Mode to encrypt files while security software is not running."
                    ),
                )
                .with_actions(actions),
            );
        }
        if let Some(what) = rw04_cmd(&name, &a, &cf) {
            self.rw04(ctx, e, &shown, what, out);
        }
        let targets = rw05_targets(&name, &a, &cf);
        if !targets.is_empty() {
            self.rw05_cmd(ctx, e, targets, out);
        }
    }

    fn rw04(&self, ctx: &Ctx, e: &Event, shown: &str, what: &str, out: &mut Vec<FamilyHit>) {
        let lin = lineage(ctx, &e.guid);
        let escalated = lin
            .guids()
            .any(|g| marked(&self.prep_marks, g, ctx.now, RW04_ESCALATE_MS));
        let (sev, actions, tail) = if escalated {
            (
                Severity::High,
                contain_prep(ctx, &lin),
                " right after other ransomware preparation steps from the same program",
            )
        } else {
            (Severity::Medium, vec![], "")
        };
        out.push(
            FamilyHit::new(
                RW04,
                &e.guid,
                sev,
                format!(
                    "{shown} {what}{tail}, which hides the traces of an attack; the cleared entries cannot be recovered on this PC."
                ),
            )
            .with_actions(actions),
        );
    }

    fn rw05_cmd(&mut self, ctx: &Ctx, e: &Event, targets: Vec<String>, out: &mut Vec<FamilyHit>) {
        let lin = lineage(ctx, &e.guid);
        // Aggregate per launching chain: the topmost untrusted ancestor, or
        // the non-protected system / admin tool the walk stopped at (PsExec
        // service, WMI provider host, RMM agent) so one-shell-per-command
        // fan-out still counts together.
        let head = match &lin.stop {
            Some(s) if !ctx.protected(s) && !is_real_explorer(ctx, s) => Some(s.clone()),
            _ => lin.head().cloned(),
        };
        let Some(head) = head else {
            return;
        };
        let mut n = 0;
        for t in targets {
            n = push_keyed(&mut self.kill_cmds, &head.guid, e.ts, t, RW05_CMD_WINDOW_MS);
        }
        if n >= RW05_CMD_MIN {
            out.push(FamilyHit::new(
                RW05,
                &head.guid,
                Severity::High,
                if head.guid == e.guid {
                    format!(
                        "{} stopped or disabled {n} database, backup or security services within two minutes, as ransomware does to unlock files before encrypting them.",
                        shown_name(&name_of(&head))
                    )
                } else {
                    format!(
                        "Commands launched under {} stopped or disabled {n} database, backup or security services within two minutes, as ransomware does to unlock files before encrypting them.",
                        shown_name(&name_of(&head))
                    )
                },
            ));
        }
    }

    fn on_terminate(&mut self, ctx: &Ctx, e: &Event, t: &TargetProcess, out: &mut Vec<FamilyHit>) {
        // A TerminateProcess call arrives as access == PROCESS_TERMINATE exactly
        // (see `TargetProcess::is_termination`); an open whose desired mask
        // merely includes 0x1 (OneDrive asks for 0x100411) is not a kill.
        if !t.is_termination() || t.return_code != 0 {
            return;
        }
        let Some(actor) = ctx.process(&e.guid) else {
            return;
        };
        if ctx.is_agent(actor)
            || ctx.protected(actor)
            || ctx.system_trusted(actor)
            || t.target_pid == e.pid
        {
            return;
        }
        // Killing one's own process tree (browsers closing renderers, test
        // runners, launchers) or other instances of the same program is not a
        // spree (lab VM: msedge.exe and an admin's Stop-Process msedge).
        if let Some(tp) = t.target_guid.as_ref().and_then(|g| ctx.process(g)) {
            if name_of(tp) == name_of(actor)
                || ctx
                    .ancestry(&tp.guid, LINEAGE_DEPTH)
                    .iter()
                    .any(|a| a.guid == actor.guid)
            {
                return;
            }
        }
        let key = match &t.target_guid {
            Some(g) => g.0.clone(),
            None => format!("pid:{}", t.target_pid),
        };
        let n = push_keyed(
            &mut self.terminates,
            &e.guid,
            e.ts,
            key,
            RW05_TERM_WINDOW_MS,
        );
        if n >= RW05_TERM_MIN {
            let untrusted = untrusted_image(ctx, actor);
            let actions = if untrusted {
                contain(ctx, &lineage(ctx, &e.guid).members)
            } else {
                vec![]
            };
            out.push(
                FamilyHit::new(
                    RW05,
                    &e.guid,
                    if untrusted {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    format!(
                        "{} terminated {n} other programs within ten seconds, as ransomware does to free locked files and stop security or backup software.",
                        shown_name(&name_of(actor))
                    ),
                )
                .with_actions(actions),
            );
        }
    }

    fn on_script(&mut self, ctx: &Ctx, e: &Event, content: &str, out: &mut Vec<FamilyHit>) {
        let Some(subject) = ctx.process(&e.guid) else {
            return;
        };
        if ctx.is_agent(subject) || ctx.protected(subject) {
            return;
        }
        // Bound the work on huge script blocks.
        let content = match content.char_indices().nth(64 * 1024) {
            Some((i, _)) => &content[..i],
            None => content,
        };
        let c = flat(content);
        let shown = shown_name(&name_of(subject));
        if rw01_script(&c) {
            let lin = lineage(ctx, &e.guid);
            out.push(
                FamilyHit::new(
                    RW01,
                    &e.guid,
                    Severity::Critical,
                    format!(
                        "{shown} ran a PowerShell script that deletes the Volume Shadow Copies, a typical step right before ransomware encrypts files; check that offline backups are intact."
                    ),
                )
                .with_actions(contain_prep(ctx, &lin)),
            );
        }
        if let Some(what) = rw04_script(&c) {
            self.rw04(ctx, e, &shown, what, out);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn on_registry(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        key: &str,
        value_name: &str,
        data: Option<&str>,
        op: RegistryOp,
        out: &mut Vec<FamilyHit>,
    ) {
        let Some(actor) = ctx.process(&e.guid) else {
            return;
        };
        if ctx.is_agent(actor) || ctx.protected(actor) {
            return;
        }
        let k = key.replace('/', "\\").to_lowercase();
        let vn = value_name.to_lowercase();
        let shown = shown_name(&name_of(actor));
        let installer = name_of(actor) == "msiexec.exe" || trusted_tool(ctx, actor);

        // Safe Mode service registration.
        let sb_sub = [r"\control\safeboot\minimal\", r"\control\safeboot\network\"]
            .iter()
            .find_map(|p| k.find(p).map(|i| &k[i + p.len()..]));
        if let Some(sub) = sb_sub {
            let svc = sub.split('\\').next().unwrap_or("");
            let is_default = vn.is_empty() || vn == "(default)";
            if op == RegistryOp::Set
                && is_default
                && !svc.is_empty()
                && !(svc == KESTREL_SERVICE && actor.signed == SignatureState::Valid)
                && !installer
                && data.is_some_and(|d| d.trim().eq_ignore_ascii_case("service"))
            {
                out.push(
                    FamilyHit::new(
                        RW03,
                        &e.guid,
                        Severity::High,
                        format!(
                            "{shown} registered the service \"{svc}\" to start in Safe Mode, which ransomware does before rebooting into Safe Mode to encrypt files without security software."
                        ),
                    ),
                );
                return;
            }
        }
        if op == RegistryOp::DeleteKey && k.contains(r"\control\safeboot") && !installer {
            out.push(FamilyHit::new(
                RW03,
                &e.guid,
                Severity::High,
                format!(
                    "{shown} deleted Safe Mode registry entries, which stops security software from starting in Safe Mode."
                ),
            ));
            return;
        }
        // Autologon set by a lineage that just staged a Safe Mode boot.
        if op == RegistryOp::Set
            && k.contains(r"\microsoft\windows nt\currentversion\winlogon")
            && (vn == "autoadminlogon" || vn == "defaultpassword")
        {
            let lin = lineage(ctx, &e.guid);
            if lin
                .guids()
                .any(|g| marked(&self.safeboot_marks, g, ctx.now, RW03_AUTOLOGON_MS))
            {
                let mut h = FamilyHit::new(
                    RW03,
                    &e.guid,
                    Severity::High,
                    format!(
                        "{shown} turned on automatic logon right after staging a Safe Mode boot, so the PC would come back up unattended for encryption."
                    ),
                );
                h.dedup_key = Some(format!("{RW03}:autologon"));
                out.push(h);
            }
        }
    }

    fn on_file_activity(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        fa: &FileActivity,
        out: &mut Vec<FamilyHit>,
    ) {
        // V-H9: writes by the System process are a remote SMB client; no
        // local process may be blamed or acted on (remote encryption is
        // RW-09, deferred). Decoy tamper is still reported.
        if fa.remote_writer || e.pid == 4 {
            if !fa.canary_hits.is_empty() {
                let path = fa.canary_hits.first().map(String::as_str).unwrap_or("");
                let mut h = FamilyHit::new(
                    RW07,
                    &e.guid,
                    Severity::Critical,
                    format!(
                        "A remote client over SMB modified Kestrel ransomware decoy files ({path}); another computer on the network may be encrypting this PC's shared folders. Find the client in the file server's session list."
                    ),
                );
                h.dedup_key = Some(format!("{RW07}:remote"));
                // Alert only, with the synthetic "unknown writer" subject
                // (the engine refuses pid 4 subjects and any action on it).
                let mut subject = crate::engine::unknown_subject(e.ts, "rw07:smb-remote-writer");
                subject.cmdline = "(remote client over SMB, via the System process)".into();
                h.guid = subject.guid.clone();
                h.process = Some(subject);
                h.remediation_only = true;
                out.push(h);
            }
            return;
        }
        let Some(actor) = ctx.process(&e.guid).cloned() else {
            // The process table has not seen it (sensor raced the start
            // event): still alert, without actions.
            self.file_activity_unknown(ctx, e, fa, out);
            return;
        };
        if ctx.is_agent(&actor) {
            return;
        }
        let shown = shown_name(&name_of(&actor));
        let allowed = sync_backup_client(&actor);
        let explorer = is_real_explorer(ctx, &actor);
        let lin = lineage(ctx, &e.guid);
        let isolate = fa.net_paths > 0;
        let containment = |extra_isolate: bool| {
            let mut a = contain(ctx, &lin.members);
            if extra_isolate {
                a.push(ResponseAction::IsolateHost { allow_ips: vec![] });
            }
            a
        };
        let secs = (fa.window_ms / 1000).max(1);

        let rw06_level = rw06_triggers(fa, ctx.now < self.ransom_alert_until);
        let mut rw07_in_place_only = false;

        // RW-07: canary.
        if !fa.canary_hits.is_empty() {
            let soft = allowed || explorer;
            // V-H9: an in-place write found by content polling is blamed on
            // the last process that opened the decoy for writing (a guess:
            // malware can make Word/Acrobat that process). Alert only, unless
            // the same process also shows an RW-06-level aggregate.
            let in_place_only = fa.canary_in_place
                && !rw06_level
                && !marked(&self.rw06_marks, &e.guid, ctx.now, RW08_COMBINE_MS);
            let path = fa.canary_hits.first().map(String::as_str).unwrap_or("");
            let mut h = FamilyHit::new(
                RW07,
                &e.guid,
                if soft {
                    Severity::High
                } else {
                    Severity::Critical
                },
                if fa.canary_in_place {
                    format!(
                        "A Kestrel ransomware decoy file ({path}) was rewritten in place; {shown} was the last program seen opening it for writing{}. Check that the file and its neighbours were not encrypted.",
                        if in_place_only {
                            " (inferred, so no action was taken against it)"
                        } else {
                            " and it is also rewriting many other files"
                        }
                    )
                } else if explorer {
                    // Fresh-install lab 2026-10-21: the signed-in user moving
                    // or deleting a decoy in File Explorer.
                    format!(
                        "Explorer (the signed-in user's file manager) moved, renamed or deleted a hidden Kestrel ransomware decoy file ({path}); this is usually a person tidying up folders, so no action was taken. Check that the file was not encrypted."
                    )
                } else if soft {
                    format!(
                        "{shown} changed a Kestrel ransomware decoy file ({path}); this is usually a person or sync tool, but check that the file was not encrypted."
                    )
                } else {
                    format!(
                        "{shown} changed a Kestrel ransomware decoy file ({path}), which only ransomware or a wiper does; files it touched before Kestrel reacted may already be encrypted."
                    )
                },
            );
            if !soft && !in_place_only {
                h.actions = containment(isolate);
                h.strong = true;
            }
            if in_place_only {
                // Never feeds RW-08's "combined" escalation either.
                rw07_in_place_only = true;
                mark(&mut self.inplace_marks, &e.guid, ctx.now);
            } else {
                self.inplace_marks.remove(&e.guid);
            }
            out.push(h);
        }

        // RW-06: mass encryption.
        if rw06_level {
            let ext = fa
                .top_new_ext
                .as_deref()
                .filter(|x| !x.is_empty())
                .map(|x| format!(", most renamed to .{x}"))
                .unwrap_or_default();
            let net = if isolate {
                format!(", {} of them on network shares", fa.net_paths)
            } else {
                String::new()
            };
            let mut h = FamilyHit::new(
                RW06,
                &e.guid,
                if allowed {
                    Severity::High
                } else {
                    Severity::Critical
                },
                format!(
                    "{shown} rewrote or renamed {} existing files in {} folders within {secs} s{ext}{net}, which looks like ransomware encryption; Kestrel works from user mode and cannot guarantee that no files were encrypted before it reacted.",
                    preexisting_files(fa), fa.dirs
                ),
            );
            if !allowed && !explorer {
                h.actions = containment(isolate);
                h.strong = true;
            }
            out.push(h);
        }

        // RW-08: note fan-out.
        if let Some(note) = fa.note_name.as_deref() {
            let note = note.to_lowercase();
            let name_hit = fa.note_dirs >= RW08_NOTE_DIRS && note_ext(&note) && note_like(&note);
            let fallback = fa.note_dirs >= RW08_FALLBACK_DIRS
                && note_characteristics(&note)
                && note != "desktop.ini"
                && note != "thumbs.db";
            if name_hit || fallback {
                let combined = marked(&self.impact_marks, &e.guid, ctx.now, RW08_COMBINE_MS)
                    || out.iter().any(|h| {
                        (h.rule == RW06 || (h.rule == RW07 && !rw07_in_place_only))
                            && h.guid == e.guid
                    });
                let act = (name_hit || combined) && !allowed && !explorer;
                let mut h = FamilyHit::new(
                    RW08,
                    &e.guid,
                    if name_hit || combined {
                        Severity::Critical
                    } else {
                        Severity::High
                    },
                    format!(
                        "{shown} wrote the same file \"{note}\" into {} folders, the way ransomware leaves its ransom note; files in those folders may already be encrypted.",
                        fa.note_dirs
                    ),
                );
                if act {
                    h.actions = containment(isolate);
                }
                out.push(h);
            }
        }
    }

    fn file_activity_unknown(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        fa: &FileActivity,
        out: &mut Vec<FamilyHit>,
    ) {
        if e.pid == 0 || e.pid == 4 {
            return; // Remote (SMB) encryption is RW-09 (deferred).
        }
        if !fa.canary_hits.is_empty() {
            out.push(FamilyHit::new(
                RW07,
                &e.guid,
                Severity::Critical,
                format!(
                    "Process {} changed a Kestrel ransomware decoy file; files it touched may already be encrypted.",
                    e.pid
                ),
            ));
        }
        if rw06_triggers(fa, ctx.now < self.ransom_alert_until) {
            out.push(FamilyHit::new(
                RW06,
                &e.guid,
                Severity::Critical,
                format!(
                    "Process {} rewrote or renamed {} existing files in {} folders, which looks like ransomware encryption; Kestrel cannot guarantee that no files were encrypted.",
                    e.pid, preexisting_files(fa), fa.dirs
                ),
            ));
        }
    }

    /// Lineage key set of an alert subject for RW-12 grouping: its lineage
    /// members plus the launcher the walk stopped at (unless that is
    /// Explorer or a protected process, which everything shares).
    fn lineage_keys(ctx: &Ctx, subject: &ProcessInfo) -> HashSet<ProcessGuid> {
        let lin = lineage(ctx, &subject.guid);
        let mut keys: HashSet<ProcessGuid> = lin.guids().cloned().collect();
        keys.insert(subject.guid.clone());
        if let Some(s) = &lin.stop {
            if !is_real_explorer(ctx, s) && !ctx.protected(s) {
                keys.insert(s.guid.clone());
            }
        }
        keys
    }

    fn rw12(&mut self, ctx: &Ctx, a: &Alert, rule: &'static str, out: &mut Vec<FamilyHit>) {
        let now = a.ts;
        while self
            .host_hits
            .front()
            .is_some_and(|(t, _, _, _)| now - *t > RW12_WINDOW_MS)
        {
            self.host_hits.pop_front();
        }
        // V-M4: only Protect-mode alerts or the high-confidence variants
        // (Critical; RW-04 only when escalated) count. A failed
        // `vssadmin delete shadows` plus `wevtutil cl x` by a standard user
        // must not isolate the host.
        // RW-04's own escalation is already a same-lineage correlation:
        // only an RW-04 alert in Protect mode counts.
        let high_conf =
            a.mode == RuleMode::Protect || (rule != RW04 && a.severity == Severity::Critical);
        // Shadow-copy deletion, bcdedit, SafeBoot keys and log clearing need
        // an elevated token: a known non-elevated subject cannot have
        // succeeded, so it is not a kill-chain step.
        let not_elevated = matches!(
            a.process.integrity,
            Some(Integrity::Untrusted | Integrity::Low | Integrity::Medium)
        );
        if !high_conf || (not_elevated && rule != RW05) {
            return;
        }
        if self.host_hits.len() >= MAX_HOST_HITS {
            self.host_hits.pop_front();
        }
        let keys = Self::lineage_keys(ctx, &a.process);
        self.host_hits
            .push_back((now, rule, a.process.clone(), keys));
        // Hits whose process is known to have failed do not count; the
        // rest must share a lineage with at least one other hit (exit codes
        // are often unknown, so the same launching chain is required).
        let live: Vec<usize> = (0..self.host_hits.len())
            .filter(|&i| !self.failed.contains_key(&self.host_hits[i].2.guid))
            .collect();
        let mut group: Vec<usize> = Vec::new();
        for &i in &live {
            let g: Vec<usize> = live
                .iter()
                .copied()
                .filter(|&j| {
                    j == i
                        || self.host_hits[i]
                            .3
                            .intersection(&self.host_hits[j].3)
                            .next()
                            .is_some()
                })
                .collect();
            let distinct: HashSet<&str> = g.iter().map(|&j| self.host_hits[j].1).collect();
            if distinct.len() >= 2 && g.len() > group.len() {
                group = g;
            }
        }
        if group.is_empty() {
            return;
        }
        let distinct: HashSet<&str> = group.iter().map(|&j| self.host_hits[j].1).collect();
        if self
            .last_rw12
            .is_some_and(|t| now >= t && now - t < RW12_WINDOW_MS)
        {
            return;
        }
        self.last_rw12 = Some(now);
        if ctx.mode(RW12) != RuleMode::Off {
            self.ransom_alert_until = now + RANSOM_ALERT_MS;
        }
        let mut rules: Vec<&str> = distinct.into_iter().collect();
        rules.sort_unstable();
        let mut actions = Vec::new();
        let mut seen: HashSet<ProcessGuid> = HashSet::new();
        for p in group.iter().map(|&j| &self.host_hits[j].2) {
            if !seen.insert(p.guid.clone()) {
                continue;
            }
            let lin = lineage(ctx, &p.guid);
            let members = if lin.members.is_empty() {
                vec![p.clone()]
            } else {
                lin.members
            };
            for x in contain(ctx, &members) {
                if !actions.contains(&x) {
                    actions.push(x);
                }
            }
        }
        actions.push(ResponseAction::IsolateHost { allow_ips: vec![] });
        let mut h = FamilyHit::new(
            RW12,
            &a.process.guid,
            Severity::Critical,
            format!(
                "Several ransomware preparation steps ({}) happened on this PC within an hour, which matches a hands-on ransomware attack; Kestrel can isolate the PC but cannot guarantee that encryption has not already started.",
                rules.join(", ")
            ),
        )
        .with_actions(actions);
        h.strong = true;
        h.process = Some(a.process.clone());
        out.push(h);
    }
}

fn shown_name(name_lower: &str) -> String {
    if name_lower.is_empty() {
        "An unknown program".to_string()
    } else {
        name_lower.to_string()
    }
}

/// Triage 2026-10-22 item 2: files of a `FileActivity` summary that existed
/// before the actor's activity. The aggregator counts files by their
/// original path (a rename is keyed on the old name). Since 1.1.6 it also
/// reports `self_created`: touched files this process created itself, even
/// when the create is older than the window (a compiler writing `foo.tmp`
/// and renaming it to `foo.rlib` 15 s later), and `new_files` counts a file
/// only when its first operation in the window is a create of a file the
/// process did not know before (delete-then-recreate of a document is a
/// rewrite, not a new file). Older agents send `self_created = 0` and count
/// every CreateNewFile in `new_files`, so the larger of the two bounds the
/// self-made files for both. Ransomware rewrites or renames documents that
/// were there before, or writes an encrypted copy and deletes the original
/// (the originals remain).
pub(crate) fn preexisting_files(fa: &FileActivity) -> u32 {
    fa.files_touched
        .saturating_sub(fa.new_files.max(fa.self_created))
}

/// RW-06 thresholds over one `FileActivity` summary, counted over the
/// pre-existing files only ([`preexisting_files`]): extension changes and
/// overwrites of files the process created in the window do not count.
fn rw06_triggers(fa: &FileActivity, halved: bool) -> bool {
    let d = if halved { 2 } else { 1 };
    let pre = preexisting_files(fa);
    let touched = pre as u64 + (fa.net_paths.min(pre)) as u64;
    let overwrites = fa.overwrites.min(pre) as u64;
    let ext = fa.ext_changes.min(pre) as u64;
    touched >= RW06_TOUCHED / d
        && fa.dirs as u64 >= (RW06_DIRS / d).max(2)
        && (ext >= RW06_EXT / d
            || (overwrites >= RW06_OVERWRITES / d
                && overwrites * 100 >= RW06_OVERWRITE_PCT * pre as u64))
}

impl Family for Ransomware {
    fn on_event(&mut self, ctx: &Ctx, e: &Event, out: &mut Vec<FamilyHit>) {
        let start = out.len();
        match &e.data {
            EventData::ProcessStart(ps) => self.on_start(ctx, e, ps, out),
            EventData::ScriptBlock { content, .. } => self.on_script(ctx, e, content, out),
            EventData::ProcessAccess(t) => self.on_terminate(ctx, e, t, out),
            EventData::RegistrySet {
                key,
                value_name,
                data,
                op,
                ..
            } => self.on_registry(ctx, e, key, value_name, data.as_deref(), *op, out),
            EventData::FileActivity(fa) => self.on_file_activity(ctx, e, fa, out),
            // RW-12 (V-M4): a prep command that failed does not count.
            EventData::ProcessStop {
                exit_code: Some(code),
            } if *code != 0 => mark(&mut self.failed, &e.guid, e.ts),
            _ => {}
        }
        // A guessed or unknown registry writer is never acted on (V-H6/H7).
        if matches!(e.data, EventData::RegistrySet { .. }) {
            let attr = ctx.attribution(e);
            for h in out[start..].iter_mut() {
                h.apply_attribution(attr, e);
            }
        }
    }

    fn tick(&mut self, ctx: &Ctx, _out: &mut Vec<FamilyHit>) {
        let now = ctx.now;
        for (map, w) in [
            (&mut self.kill_cmds, RW05_CMD_WINDOW_MS),
            (&mut self.terminates, RW05_TERM_WINDOW_MS),
        ] {
            map.retain(|_, d| {
                while d.front().is_some_and(|(t, _)| now - *t > w) {
                    d.pop_front();
                }
                !d.is_empty()
            });
        }
        self.prep_marks.retain(|_, t| now - *t <= RW04_ESCALATE_MS);
        self.safeboot_marks
            .retain(|_, t| now - *t <= RW03_AUTOLOGON_MS);
        self.impact_marks.retain(|_, t| now - *t <= RW08_COMBINE_MS);
        self.rw06_marks.retain(|_, t| now - *t <= RW08_COMBINE_MS);
        self.inplace_marks
            .retain(|_, t| now - *t <= RW08_COMBINE_MS);
        self.failed.retain(|_, t| now - *t <= RW12_WINDOW_MS);
        while self
            .host_hits
            .front()
            .is_some_and(|(t, _, _, _)| now - *t > RW12_WINDOW_MS)
        {
            self.host_hits.pop_front();
        }
    }

    fn on_alert(&mut self, ctx: &Ctx, a: &Alert, out: &mut Vec<FamilyHit>) {
        let rule: &'static str = match a.rule_id.as_str() {
            RW01 => RW01,
            RW02 => RW02,
            RW03 => RW03,
            RW04 => RW04,
            RW05 => RW05,
            RW06 => RW06,
            RW07 => RW07,
            _ => return,
        };
        let ts = a.ts;
        match rule {
            RW06 | RW07 => {
                // An alert-only in-place RW-07 (heuristic actor) is not an
                // impact mark (V-H9).
                if rule == RW06 || !self.inplace_marks.contains_key(&a.process.guid) {
                    mark(&mut self.impact_marks, &a.process.guid, ts);
                }
                if rule == RW06 {
                    mark(&mut self.rw06_marks, &a.process.guid, ts);
                }
                return;
            }
            RW04 => {}
            _ => {
                let lin = lineage(ctx, &a.process.guid);
                mark(&mut self.prep_marks, &a.process.guid, ts);
                for g in lin.guids() {
                    mark(&mut self.prep_marks, g, ts);
                }
                if rule == RW03 {
                    mark(&mut self.safeboot_marks, &a.process.guid, ts);
                    for g in lin.guids() {
                        mark(&mut self.safeboot_marks, g, ts);
                    }
                }
            }
        }
        if PREP_RULES.contains(&rule) {
            self.rw12(ctx, a, rule, out);
        }
    }

    fn forget(&mut self, guid: &ProcessGuid) {
        self.kill_cmds.remove(guid);
        self.terminates.remove(guid);
        self.prep_marks.remove(guid);
        self.safeboot_marks.remove(guid);
        self.impact_marks.remove(guid);
        self.rw06_marks.remove(guid);
        self.inplace_marks.remove(guid);
        // `failed` expires by time only: the exit code must outlive the
        // table entry for the whole RW-12 window.
    }
}

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

const SIGMA_SHADOW: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml";
const SIGMA_SHADOW_PS: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml";
const SIGMA_WBADMIN: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml";
const SIGMA_BCDEDIT: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml";
const SIGMA_REAGENTC: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml";
const SIGMA_SAFEBOOT: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml";
const SIGMA_EVTLOG: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml";
const SIGMA_EXT: &str =
    "https://detection.fyi/sigmahq/sigma/windows/file/file_rename/file_rename_win_ransomware/";
const CISA_PLAY: &str = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a";
const CISA_AKIRA: &str = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a";
const CISA_MEDUSA: &str = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a";
const ATTACKIQ_QILIN: &str = "https://www.attackiq.com/2025/10/02/emulating-qilin-ransomware/";
const ELASTIC_HONEYPOT: &str =
    "https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys";
const DEFEAT: &str = "https://arxiv.org/html/2609.21426v1";
const SPLUNK_SPEED: &str = "https://securityweek.com/analysis-shows-how-fast-various-ransomware-strains-encrypt-100000-files";
const S1_INTERMITTENT: &str = "https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/";
const ATTACK_V19: &str = "https://attack.mitre.org/resources/updates/updates-april-2026/";

pub(crate) fn catalog() -> Vec<RuleMeta> {
    use RuleCategory::Ransomware as R;
    use Severity::*;
    vec![
        meta(RW01, "Shadow copy / backup catalog deletion",
            "vssadmin, wmic, DiskShadow or PowerShell deleted Volume Shadow Copies or shrank their storage; wbadmin deleted the backup catalog, system-state backups or all backup versions; or a PowerShell script block enumerated Win32_ShadowCopy and deleted the objects. Derived from SigmaHQ c947b146, 639c9081 and c1337eb8 (DRL 1.1).",
            R, Critical, &["T1490"], true,
            "Kill the tool; also kill (tree) and quarantine its unsigned or user-writable launcher chain up to the first protected, system, Explorer or signed Program Files process, unless an administrator typed the command in an interactive shell",
            &[SIGMA_SHADOW, SIGMA_SHADOW_PS, SIGMA_WBADMIN, CISA_AKIRA],
            &["Administrators cleaning up shadow storage by hand", "Backup products that call vssadmin (most use the VSS API)", "LANDesk / Ivanti PowerShell modules (per SigmaHQ)"]),
        meta(RW02, "Boot recovery disabled",
            "bcdedit set recoveryenabled No or bootstatuspolicy IgnoreAllFailures, deleted the recovery sequence or the default boot entry; or reagentc /disable switched off the Windows Recovery Environment. The alert names the command that restores the setting. Derived from SigmaHQ 1444443e and db1c21e4 (DRL 1.1).",
            R, Critical, &["T1490"], true,
            "bcdedit variants: kill bcdedit and its untrusted launcher chain (tree) and quarantine user-writable launchers; reagentc /disable: alert only (imaging and OEM tools use it)",
            &[SIGMA_BCDEDIT, SIGMA_REAGENTC, CISA_PLAY],
            &["OS imaging and OEM provisioning tools (reagentc)", "Kiosk or lab images that disable automatic repair on purpose"]),
        meta(RW03, "Safe-mode boot staging",
            "bcdedit set safeboot (minimal/network) or safebootalternateshell; a non-installer registered a service under Control\\SafeBoot\\{Minimal,Network} (Kestrel's own KestrelAgent key excluded); reg delete under Control\\SafeBoot; or Winlogon AutoAdminLogon/DefaultPassword set by the same lineage within 10 minutes of a Safe Mode staging hit. Derived from SigmaHQ c9fbe8e9, 1547e27c and fc0e89b5 (DRL 1.1). ATT&CK v19 renumbering of T1562.009 is unverified.",
            R, Critical, &["T1490", "T1562.009", "T1685"], true,
            "bcdedit safeboot from a non-admin context: kill bcdedit and its untrusted launcher chain (tree), quarantine user-writable launchers, and show the revert command (bcdedit /deletevalue {default} safeboot); registry and reg.exe variants: alert only",
            &[SIGMA_BCDEDIT, SIGMA_SAFEBOOT, ATTACKIQ_QILIN, ATTACK_V19],
            &["IT staff booting into Safe Mode for repair (interactive)", "AV / EDR installers registering Safe Mode services (Sophos, Malwarebytes, Hexnode)"]),
        meta(RW04, "Event log cleared or shrunk",
            "wevtutil cl/clear-log, or sl/set-log with /ms:, /lfn: or /e:false; PowerShell Clear-EventLog, Remove-EventLog, Limit-EventLog or EventLogSession.ClearLog; WMI ClearEventLog. Semantics of SigmaHQ cc36992a (DRL 1.1). ATT&CK v19 ids for log clearing are unverified.",
            R, Medium, &["T1070.001", "T1685"], false,
            "Alert only; when the same lineage fired RW-01/02/03/05 in the last 30 minutes, kill the tool and its untrusted launcher chain (tree)",
            &[SIGMA_EVTLOG, ATTACKIQ_QILIN, ATTACK_V19],
            &["Administrators clearing logs during troubleshooting", "Golden-image preparation scripts", "Installers resizing their own log (wevtutil sl from msiexec)"]),
        meta(RW05, "Service / process kill spree",
            "Within 120 s one lineage ran net/sc stop, sc config start= disabled, Stop-Service/Set-Service -StartupType Disabled or taskkill /f /im against five or more distinct database, backup, Exchange or security targets from a curated list; or one non-system process terminated ten or more distinct other processes (not its own children) within 10 s.",
            R, High, &["T1489", "T1685", "T1562.001"], true,
            "TerminateProcess variant from an unsigned or user-writable image: kill its lineage (tree) and quarantine the image; command-line variant and signed actors: alert only",
            &[CISA_MEDUSA, CISA_AKIRA, CISA_PLAY],
            &["Patch tools and installers stopping database or backup services", "Developer scripts restarting local SQL instances", "MDM / RMM maintenance jobs", "Process managers used by administrators"]),
        meta(RW06, "Mass file encryption behaviour",
            "The ransomware file sensor saw one process touch at least 30 pre-existing user-data files (network paths count double) in at least 3 folders within its window, with at least 20 changes to unknown extensions, or at least 50 overwrites making up 80% or more of those files. Files the same process created in the window (new_files) are not pre-existing and never count: a compiler renaming its own temporary files is not encryption. Thresholds are halved for two hours after RW-12.",
            R, Critical, &["T1486"], true,
            "Kill the process lineage (tree), quarantine user-writable images and isolate the host when network paths were touched; validly signed sync, backup and archiver clients (OneDrive, Dropbox, Google Drive, 7-Zip, WinRAR, Veeam, Acronis…) and Explorer alert only. User mode cannot guarantee that no file is encrypted first",
            &[SIGMA_EXT, DEFEAT, SPLUNK_SPEED, S1_INTERMITTENT],
            &["First sync or restore of OneDrive / Dropbox / Google Drive", "Bulk photo or media conversion to an uncommon format", "File encryption tools (AxCrypt, AESCrypt)", "Large git checkouts or build outputs inside user folders", "Not raised for (owner PC 2026-10-22): compilers renaming or rewriting files they created in the same window (rustc writing .rlib / .rmeta via temporary files: 101 alerts). A build step that renames files it created more than about 10 s earlier can still fire until the sensor reports self-created files across windows"]),
        meta(RW07, "Ransomware canary tampered",
            "A process other than the Kestrel agent overwrote, renamed or deleted one of the hidden decoy documents Kestrel planted in the Documents and Pictures folders for ransomware detection.",
            R, Critical, &["T1486", "T1485"], true,
            "Kill the process lineage (tree), quarantine user-writable images and isolate the host when network paths were touched; Explorer (the user) and signed sync/backup clients alert only",
            &[ELASTIC_HONEYPOT, "https://arxiv.org/pdf/2508.00293"],
            &["The user deleting or moving the decoy file in Explorer (alert only; the decoys are hidden so this is rare unless hidden files are shown)", "OneDrive conflict renames", "Backup restore jobs and disk-cleanup tools"]),
        meta(RW08, "Ransom-note fan-out",
            "One process created the same file name in at least 5 folders, with a note extension (txt, hta, html, htm, rtf, url) and a ransom-note-like name (read me, restore, recover, decrypt, how to, help, instruction, unlock, ransom, files, !!!, _info); or the same name in at least 20 folders when it still looks like a note: it has an extension, is not a build artefact (.a, .o, .obj, .rlib, .rmeta, .d, .pdb, .lib, .exp and similar; .tmp only with a note-like name) and has a note extension (the list above plus md, or a bmp / jpg / png image with a note-like name) or a note-like name.",
            R, Critical, &["T1486", "T1491.001"], true,
            "Note-like name, or the same process also tripped RW-06/07: kill the lineage (tree) and quarantine user-writable images; name-agnostic fallback: alert only",
            &["https://www.elastic.co/guide/en/security/current/potential-ransomware-note-file-dropped-via-smb.html", CISA_AKIRA],
            &["Installers dropping readme.txt into many folders", "Sync clients restoring many folders", "Scripts seeding project templates", "Not raised for (owner PC 2026-10-22): names without an extension (cargo's OUT_DIR folder \"out\" in 38 folders: the sensor cannot tell a new folder from a new file) and build artefacts (rustc's \"tmp.a\" in 24 folders)"]),
        meta(RW12, "Ransomware kill-chain correlation",
            "Two or more distinct ransomware preparation rules (RW-01 to RW-05) fired on this host within 60 minutes, in the same lineage or not (affiliates run tools from separate shells and PsExec).",
            R, Critical, &["T1486", "T1490"], true,
            "Isolate the host (the Kestrel server stays reachable), kill the participating lineages (tree) and halve the RW-06 thresholds for two hours",
            &[ATTACKIQ_QILIN, CISA_MEDUSA, CISA_AKIRA],
            &["Penetration tests and red-team exercises", "An administrator doing shadow-copy and event-log maintenance in one session"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_normalise() {
        let a = args(r#"VSSADMIN.EXE  "Delete"   Shadows –All -Quiet"#);
        assert_eq!(
            a,
            vec!["vssadmin.exe", "delete", "shadows", "/all", "/quiet"]
        );
        assert!(args("").is_empty());
        assert_eq!(args(r#""unterminated"#), vec!["unterminated"]);
        assert_eq!(args("-"), vec!["/"]);
    }

    #[test]
    fn near_and_notes() {
        assert!(note_like("read_me.txt"));
        assert!(note_like("readme.txt"));
        assert!(note_like("how-to-decrypt.hta"));
        assert!(note_like("!!!_files_.txt"));
        assert!(!note_like("report.txt"));
        assert!(note_ext("x.hta"));
        assert!(!note_ext("x.docx"));
        assert!(!near("re", "read", "me"));
        assert!(!near("readx", "read", "me"));
    }

    #[test]
    fn rw05_parsers() {
        let t = |n: &str, c: &str| rw05_targets(n, &args(c), &flat(c));
        assert_eq!(t("net.exe", "net stop MSSQLSERVER /y"), vec!["mssqlserver"]);
        assert_eq!(t("net.exe", "net stop spooler"), Vec::<String>::new());
        assert_eq!(t("sc.exe", "sc config VSS start= disabled"), vec!["vss"]);
        assert_eq!(
            t("sc.exe", "sc config VSS start= auto"),
            Vec::<String>::new()
        );
        assert_eq!(
            t(
                "taskkill.exe",
                "taskkill /F /IM sqlservr.exe /IM notepad.exe"
            ),
            vec!["sqlservr.exe"]
        );
        assert_eq!(
            t("taskkill.exe", "taskkill /IM sqlservr.exe"),
            Vec::<String>::new()
        );
        assert_eq!(
            t(
                "powershell.exe",
                "powershell Stop-Service -Name VeeamBackupSvc -Force"
            ),
            vec!["veeambackupsvc"]
        );
    }

    #[test]
    fn rw06_threshold_shape() {
        let mut fa = FileActivity {
            window_ms: 10_000,
            files_touched: 30,
            dirs: 3,
            ext_changes: 20,
            ..Default::default()
        };
        assert!(rw06_triggers(&fa, false));
        fa.ext_changes = 19;
        assert!(!rw06_triggers(&fa, false));
        fa.files_touched = 70;
        fa.overwrites = 50;
        assert!(!rw06_triggers(&fa, false), "50/70 < 80%");
        fa.overwrites = 48;
        fa.files_touched = 15;
        fa.net_paths = 15;
        assert!(!rw06_triggers(&fa, false));
        fa.overwrites = 50;
        fa.files_touched = 50;
        assert!(rw06_triggers(&fa, false));
        let half = FileActivity {
            files_touched: 15,
            dirs: 2,
            ext_changes: 10,
            ..Default::default()
        };
        assert!(!rw06_triggers(&half, false));
        assert!(rw06_triggers(&half, true));
        let huge = FileActivity {
            files_touched: u32::MAX,
            dirs: u32::MAX,
            overwrites: u32::MAX,
            net_paths: u32::MAX,
            ..Default::default()
        };
        assert!(rw06_triggers(&huge, false));
    }
}
