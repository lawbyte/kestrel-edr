//! PS-xx persistence rules (autoruns, tasks, services, WMI, COM, IFEO).
//!
//! Every rule follows the same shape: find the autostart location, resolve
//! what it will run ([`super::autorun::resolve`]), classify the payload
//! (path class, signature when the payload is a known process image,
//! Mark-of-the-Web, "just dropped" by a process we saw writing it) and the
//! writer (untrusted actor, already alerted), then decide:
//!
//! * nothing (baseline / trusted payload),
//! * an alert without actions ("Audit-level" sub-case — also for rules that
//!   run in Protect, e.g. a `.lnk` in Startup or an AppInit_DLLs value), or
//! * an alert with Protect actions (`RemoveAutorun`, `QuarantineFile` for
//!   user-writable payloads, `KillProcess` of an untrusted writer's tree).
//!   The engine drops them when the rule runs in Audit.
//!
//! The engine has no file-signature lookup for arbitrary paths: a payload's
//! signature is known only when it equals the image of a process in the
//! table, otherwise it is `Unknown` and the hit stays at Audit level.
//!
//! PS-15 remembers every autorun attributed to a process (bounded) and
//! removes them when a Protect-mode alert that kills that process tree fires.
//!
//! Rule ids: PS-01, 02, 03, 04, 05, 07, 08, 09, 10, 11, 15 (PS-06/12/13/14
//! are deferred, see `docs/research/general-malware-report.md`).

use super::autorun::{self, Env, Resolved};
use super::{Ctx, Family, FamilyHit};
use crate::catalog::meta;
use kestrel_common::{
    file_name_lower, Alert, Attribution, AutorunKind, Event, EventData, FileOp, PathClass,
    ProcessGuid, ProcessInfo, ProcessStart, RegistryOp, ResponseAction, RuleCategory, RuleMeta,
    RuleMode, Severity, SignatureState, TaskChange, TaskOp, TimestampMs, WmiBinding,
};
use std::collections::HashMap;

pub const PS01: &str = "PS-01";
pub const PS02: &str = "PS-02";
pub const PS03: &str = "PS-03";
pub const PS04: &str = "PS-04";
pub const PS05: &str = "PS-05";
pub const PS07: &str = "PS-07";
pub const PS08: &str = "PS-08";
pub const PS09: &str = "PS-09";
pub const PS10: &str = "PS-10";
pub const PS11: &str = "PS-11";
pub const PS15: &str = "PS-15";

/// "Just dropped": the payload was created this recently.
const JUST_DROPPED_MS: TimestampMs = 10 * 60_000;
const ALERTED_TTL_MS: TimestampMs = 30 * 60_000;
const ROLLED_TTL_MS: TimestampMs = 10 * 60_000;
const RECORD_TTL_MS: TimestampMs = 2 * 60 * 60_000;
const PRUNE_EVERY_MS: TimestampMs = 30_000;
const MAX_DROPS: usize = 2048;
const MAX_CREATORS: usize = 512;
const MAX_RECS_PER_CREATOR: usize = 32;
const MAX_GUIDS: usize = 1024;
const MAX_GLOBAL_FLAG: usize = 256;

/// Kestrel's own service: never a removal target (TP-04 covers tampering).
const KESTREL_SERVICE: &str = "kestrelagent";

/// Rules whose Protect-mode alert kills the subject's process tree (PS-15
/// trigger). `Alert` does not carry the proposed actions at `on_alert` time
/// (they live in `Detection.actions`), so the set is static; RW-xx and CD-xx
/// Protect alerts count as killing too.
const KILL_RULES: &[&str] = &[
    "ST-02", "ST-04", "ST-05", "ST-06", "ST-07", "ST-08", "ST-10", "ST-11", "ST-13", "ST-15",
    "ST-16", "IOC-HASH",
];

/// Per-user software that legitimately autostarts from the user profile.
/// Suppressed only when the payload matches **and** the writer is not an
/// untrusted / already-alerted process **and** the payload is not known to be
/// unsigned. Paths are lower-case substrings of the resolved payload path;
/// `file` / `arg` narrow the match. Sources: research notes
/// `persistence.md` §3.4 (Sigma currentversion ASEP filters, Elastic Run-key
/// rule exclusions); entries marked [UNVERIFIED] need confirming in the lab.
struct Baseline {
    app: &'static str,
    dir: &'static str,
    file: Option<&'static str>,
    arg: Option<&'static str>,
}

const BASELINE: &[Baseline] = &[
    // OneDrive per-user client, its standalone updater task and FileSyncShell64.dll COM server.
    Baseline {
        app: "Microsoft OneDrive",
        dir: r"\appdata\local\microsoft\onedrive\",
        file: None,
        arg: None,
    },
    // Teams classic (Squirrel): Update.exe --processStart Teams.exe
    Baseline {
        app: "Microsoft Teams (classic)",
        dir: r"\appdata\local\microsoft\teams\",
        file: None,
        arg: None,
    },
    // Discord (Squirrel): Update.exe --processStart Discord.exe
    Baseline {
        app: "Discord",
        dir: r"\appdata\local\discord\",
        file: Some("update.exe"),
        arg: Some("--processstart"),
    },
    // Any other Squirrel app (Slack, GitHub Desktop, WhatsApp desktop…) [UNVERIFIED per app]
    Baseline {
        app: "Squirrel updater",
        dir: r"\appdata\local\",
        file: Some("update.exe"),
        arg: Some("--processstart"),
    },
    // Spotify per-user install
    Baseline {
        app: "Spotify",
        dir: r"\appdata\roaming\spotify\",
        file: Some("spotify.exe"),
        arg: None,
    },
    // Zoom per-user install (also its RunOnce repair)
    Baseline {
        app: "Zoom",
        dir: r"\appdata\roaming\zoom\bin\",
        file: None,
        arg: None,
    },
    // GoogleUpdater per-user (tasks "GoogleUpdaterTaskUser…") and legacy Google Update
    Baseline {
        app: "Google Updater",
        dir: r"\appdata\local\google\googleupdater\",
        file: None,
        arg: None,
    },
    Baseline {
        app: "Google Update",
        dir: r"\appdata\local\google\update\",
        file: None,
        arg: None,
    },
    // Per-user Chrome install
    Baseline {
        app: "Google Chrome (per-user)",
        dir: r"\appdata\local\google\chrome\application\",
        file: None,
        arg: None,
    },
    // Edge per-user updater tasks
    Baseline {
        app: "Microsoft Edge Update",
        dir: r"\appdata\local\microsoft\edgeupdate\",
        file: None,
        arg: None,
    },
    // WiX Burn bundles (python.org installer, VC++ redistributables): RunOnce "/burn.runonce"
    Baseline {
        app: "WiX Burn bundle (e.g. Python installer)",
        dir: r"\appdata\local\package cache\",
        file: None,
        arg: Some("/burn.runonce"),
    },
    // MSIX app execution aliases (new Teams, Store apps): reparse stubs to signed packages
    Baseline {
        app: "Store app execution alias",
        dir: r"\appdata\local\microsoft\windowsapps\",
        file: None,
        arg: None,
    },
    // Telegram Desktop autostart [UNVERIFIED flag]
    Baseline {
        app: "Telegram Desktop",
        dir: r"\appdata\roaming\telegram desktop\",
        file: Some("telegram.exe"),
        arg: None,
    },
    // Google Drive / Dropbox per-user shell extensions (COM) [UNVERIFIED paths]
    Baseline {
        app: "Google Drive",
        dir: r"\appdata\local\google\drivefs\",
        file: None,
        arg: None,
    },
    Baseline {
        app: "Dropbox",
        dir: r"\appdata\roaming\dropbox\",
        file: None,
        arg: None,
    },
];

/// Accessibility binaries reachable from the logon screen (sticky-keys backdoor).
const ACCESSIBILITY: &[&str] = &[
    "sethc.exe",
    "utilman.exe",
    "osk.exe",
    "magnify.exe",
    "narrator.exe",
    "displayswitch.exe",
    "atbroker.exe",
];
/// Other high-value IFEO targets (security tools, browsers).
const HIGH_VALUE_TARGETS: &[&str] = &[
    "msmpeng.exe",
    "mpcmdrun.exe",
    "msascui.exe",
    "securityhealthservice.exe",
    "mrt.exe",
    "kestrel-agent.exe",
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
];

const SCRIPT_EXTS: &[&str] = &[
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "hta", "bat", "cmd", "ps1", "url", "a3x", "au3", "py",
    "scf",
];
const PE_EXTS: &[&str] = &["exe", "dll", "scr", "com", "pif", "cpl"];
/// File types whose creation is remembered for "just dropped".
const TRACKED_EXTS: &[&str] = &[
    "exe", "dll", "scr", "com", "pif", "cpl", "sys", "ocx", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "bat", "cmd", "ps1", "a3x", "au3", "py", "msi", "jar", "lnk", "url", "sct",
];

/// A tracked file creation ("just dropped").
#[derive(Debug, Clone)]
struct Dropped {
    ts: TimestampMs,
    /// The process that created it (kernel-attributed file event).
    by: ProcessGuid,
}

/// One autorun attributed to a process (PS-15 rollback).
#[derive(Debug, Clone)]
struct Rec {
    ts: TimestampMs,
    what: String,
    remove: ResponseAction,
    quarantine: Option<String>,
}

#[derive(Default)]
pub(crate) struct Persistence {
    /// Lower-case path → who created it and when (bounded, 10 min).
    drops: HashMap<String, Dropped>,
    /// Autoruns per creating process (bounded).
    created: HashMap<ProcessGuid, Vec<Rec>>,
    /// Processes another rule alerted on (writer context).
    alerted: HashMap<ProcessGuid, TimestampMs>,
    /// Writers a PS hit proposed to kill (their Protect alert triggers PS-15).
    killing: HashMap<ProcessGuid, TimestampMs>,
    /// Members of trees already rolled back: late autoruns are removed at once.
    rolled: HashMap<ProcessGuid, TimestampMs>,
    /// IFEO executables with GlobalFlag 0x200 (silent-exit monitoring).
    global_flag: HashMap<String, TimestampMs>,
    /// `LoadAppInit_DLLs` was set to 1.
    appinit_loaded: bool,
    /// Autoruns of already rolled-back trees seen during the current event.
    pending_late: Vec<(ProcessGuid, Rec)>,
    last_prune: TimestampMs,
}

/// Who wrote the autorun.
struct Writer {
    info: Option<ProcessInfo>,
    /// Real creator (not the Task Scheduler / SCM / WMI host standing in).
    attributed: bool,
    untrusted: bool,
    alerted: bool,
    /// Valid Microsoft Windows binary (not a LOLBin).
    system: bool,
    /// Validly signed non-LOLBin installed program (RMM agents, updaters).
    signed_program: bool,
    /// Known unsigned / invalid signature, or a LOLBin / script host.
    unsigned_or_lolbin: bool,
    /// How the sensor determined the writer (V-H5/H6/H7).
    attribution: Attribution,
    /// The writer's parent is not an untrusted actor and not alerted (or is
    /// unknown). A signed tool (`reg.exe`, `schtasks.exe`) run by malware
    /// must not launder the write (V-H6).
    parent_trusted: bool,
}

impl Writer {
    fn suspicious(&self) -> bool {
        self.attributed && (self.untrusted || self.alerted)
    }

    /// Windows component writer that exempts a change: exact attribution
    /// and a trusted parent.
    fn trusted_system(&self) -> bool {
        self.system && self.exempt_ok()
    }

    /// Validly signed management tool writer that lowers a hit to Audit
    /// level: exact attribution and a trusted parent.
    fn trusted_signed_program(&self) -> bool {
        self.signed_program && self.exempt_ok()
    }

    fn exempt_ok(&self) -> bool {
        self.attribution == Attribution::Exact && self.parent_trusted && !self.alerted
    }

    fn describe(&self) -> String {
        match &self.info {
            Some(p) if self.attribution == Attribution::Heuristic => format!(
                "{} (writer inferred by correlation)",
                crate::util::describe_proc(p)
            ),
            Some(p) if self.attributed => crate::util::describe_proc(p),
            Some(p) => format!(
                "{} (creator not attributed)",
                kestrel_common::file_name_lower(&p.image)
            ),
            None => "An unidentified process".into(),
        }
    }
}

/// What the autorun will run.
#[derive(Debug, Default)]
struct Payload {
    path: Option<String>,
    url: bool,
    class: Option<PathClass>,
    user_writable: bool,
    signed: SignatureState,
    motw: bool,
    just_dropped: bool,
    /// Creator of the payload file when it was seen being dropped.
    dropped_by: Option<ProcessGuid>,
    running: Vec<ProcessInfo>,
}

impl Payload {
    fn known_unsigned(&self) -> bool {
        matches!(
            self.signed,
            SignatureState::Unsigned | SignatureState::Invalid
        )
    }

    fn quarantinable(&self) -> Option<String> {
        match (&self.path, self.url, self.user_writable) {
            // never a path with an unexpanded variable (`%USERNAME%`)
            (Some(p), false, true) if p.contains('\\') && !p.contains('%') => Some(p.clone()),
            _ => None,
        }
    }

    fn describe(&self) -> String {
        let Some(p) = &self.path else {
            return "an inline command".into();
        };
        if self.url {
            return format!("the remote payload {p}");
        }
        let mut tags = Vec::new();
        match self.signed {
            SignatureState::Unsigned => tags.push("unsigned"),
            SignatureState::Invalid => tags.push("invalid signature"),
            SignatureState::Valid => tags.push("signed"),
            SignatureState::Unknown => {}
        }
        if self.user_writable {
            tags.push("in a user-writable folder");
        }
        if self.motw {
            tags.push("downloaded from the Internet");
        }
        if self.just_dropped {
            tags.push("created minutes ago");
        }
        if tags.is_empty() {
            p.clone()
        } else {
            format!("{p} ({})", tags.join(", "))
        }
    }
}

/// Where the autorun lives.
struct Loc {
    kind: AutorunKind,
    location: String,
    value_name: Option<String>,
    restore: Option<String>,
    /// Plain-language label: `Run key value "Updater"`.
    what: String,
}

impl Loc {
    fn remove(&self) -> ResponseAction {
        ResponseAction::RemoveAutorun {
            kind: self.kind,
            location: self.location.clone(),
            value_name: self.value_name.clone(),
            restore_data: self.restore.clone(),
        }
    }

    fn dedup(&self, rule: &str) -> String {
        format!(
            "{rule}:{}\\{}",
            self.location.to_ascii_lowercase(),
            self.value_name
                .as_deref()
                .unwrap_or("")
                .to_ascii_lowercase()
        )
    }

    /// Kestrel's own service / service key.
    fn is_kestrel(&self) -> bool {
        let l = self.location.to_ascii_lowercase();
        (self.kind == AutorunKind::Service && l == KESTREL_SERVICE)
            || l.contains(r"\services\kestrelagent")
    }
}

// ---------------------------------------------------------------------------
// registry key normalisation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hive {
    Machine,
    User,
}

/// `HKLM\…`, `HKU\<SID>\…` (also `_Classes`), `HKCU\…` and long / kernel
/// forms → (hive, lower-case rest with `Wow6432Node` and `ControlSet00N`
/// folded).
fn split_key(key: &str) -> Option<(Hive, String)> {
    let k = key.trim().trim_start_matches('\\').to_ascii_lowercase();
    let (hive, rest) = if let Some(r) = k
        .strip_prefix(r"hklm\")
        .or_else(|| k.strip_prefix(r"hkey_local_machine\"))
        .or_else(|| k.strip_prefix(r"registry\machine\"))
    {
        (Hive::Machine, r.to_string())
    } else if let Some(r) = k
        .strip_prefix(r"hkcu\")
        .or_else(|| k.strip_prefix(r"hkey_current_user\"))
    {
        (Hive::User, r.to_string())
    } else {
        let r = k
            .strip_prefix(r"hku\")
            .or_else(|| k.strip_prefix(r"hkey_users\"))
            .or_else(|| k.strip_prefix(r"registry\user\"))?;
        let (sid, rest) = r.split_once('\\')?;
        if sid.ends_with("_classes") {
            (Hive::User, format!(r"software\classes\{rest}"))
        } else {
            (Hive::User, rest.to_string())
        }
    };
    let mut rest = rest;
    if let Some(r) = rest.strip_prefix(r"software\wow6432node\") {
        rest = format!(r"software\{r}");
    }
    if let Some(r) = rest.strip_prefix(r"software\classes\wow6432node\") {
        rest = format!(r"software\classes\{r}");
    }
    if let Some(r) = rest.strip_prefix(r"system\") {
        if let Some((cs, tail)) = r.split_once('\\') {
            if cs.starts_with("controlset") {
                rest = format!(r"system\currentcontrolset\{tail}");
            }
        }
    }
    Some((hive, rest.trim_end_matches('\\').to_string()))
}

const CV: &str = r"software\microsoft\windows\currentversion";
const NTCV: &str = r"software\microsoft\windows nt\currentversion";

fn is_run_family(rest: &str, value_lower: &str) -> bool {
    let run_keys = [
        "run",
        "runonce",
        "runservices",
        "runservicesonce",
        r"policies\explorer\run",
    ];
    if let Some(tail) = rest.strip_prefix(CV).and_then(|t| t.strip_prefix('\\')) {
        if run_keys.contains(&tail) {
            return true;
        }
        if tail.starts_with(r"runonceex\") {
            return true;
        }
    }
    rest == format!(r"{NTCV}\windows") && matches!(value_lower, "load" | "run")
}

fn hive_label(h: Hive) -> &'static str {
    match h {
        Hive::Machine => "HKLM",
        Hive::User => "HKCU",
    }
}

fn parse_number(s: &str) -> Option<u64> {
    crate::util::reg_number(s)
}

fn same_path(a: &str, b: &str) -> bool {
    let n = |s: &str| {
        let l = s
            .trim()
            .trim_matches('"')
            .replace('/', "\\")
            .to_ascii_lowercase();
        l.trim_start_matches(r"\\?\")
            .trim_start_matches(r"\??\")
            .to_string()
    };
    n(a) == n(b)
}

fn ext_of(path_lower: &str) -> &str {
    let f = path_lower.rsplit('\\').next().unwrap_or(path_lower);
    match f.rsplit_once('.') {
        Some((_, e)) => e,
        None => "",
    }
}

fn kill_tree(p: &ProcessInfo) -> ResponseAction {
    ResponseAction::KillProcess {
        pid: p.pid,
        guid: Some(p.guid.clone()),
        tree: true,
    }
}

fn quarantine(path: &str) -> ResponseAction {
    ResponseAction::QuarantineFile {
        path: path.to_string(),
        sha256: None,
    }
}

/// Shells a person types in. Launched by Explorer or hosted by a terminal,
/// they are the user's interactive session, not part of a malicious tree.
const INTERACTIVE_SHELLS: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "windowsterminal.exe",
    "wt.exe",
    "openconsole.exe",
];

fn interactive_shell(ctx: &Ctx, p: &ProcessInfo) -> bool {
    if !INTERACTIVE_SHELLS.contains(&file_name_lower(&p.image).as_str()) {
        return false;
    }
    match ctx.table().parent_of(p) {
        Some(pp) => matches!(
            file_name_lower(&pp.image).as_str(),
            "explorer.exe" | "windowsterminal.exe" | "wt.exe" | "openconsole.exe"
        ),
        // Parent gone or never seen: assume the user's shell (never roll back).
        None => true,
    }
}

fn bounded_insert(m: &mut HashMap<ProcessGuid, TimestampMs>, g: &ProcessGuid, ts: TimestampMs) {
    if m.len() >= MAX_GUIDS && !m.contains_key(g) {
        if let Some(oldest) = m.iter().min_by_key(|(_, t)| **t).map(|(k, _)| k.clone()) {
            m.remove(&oldest);
        }
    }
    m.insert(g.clone(), ts);
}

impl Persistence {
    fn prune(&mut self, now: TimestampMs) {
        if now - self.last_prune < PRUNE_EVERY_MS && self.drops.len() < MAX_DROPS {
            return;
        }
        self.last_prune = now;
        self.drops.retain(|_, d| now - d.ts < JUST_DROPPED_MS);
        self.alerted.retain(|_, t| now - *t < ALERTED_TTL_MS);
        self.killing.retain(|_, t| now - *t < ROLLED_TTL_MS);
        self.rolled.retain(|_, t| now - *t < ROLLED_TTL_MS);
        self.global_flag.retain(|_, t| now - *t < RECORD_TTL_MS);
        self.created
            .retain(|_, v| v.last().is_some_and(|r| now - r.ts < RECORD_TTL_MS));
        if self.drops.len() >= MAX_DROPS {
            // still full of fresh entries: keep the newest half
            let mut ts: Vec<TimestampMs> = self.drops.values().map(|d| d.ts).collect();
            ts.sort_unstable();
            let cut = ts[ts.len() / 2];
            self.drops.retain(|_, d| d.ts > cut);
        }
    }

    // ---- context ----

    fn writer(&self, ctx: &Ctx, e: &Event) -> Writer {
        let attribution = ctx.attribution(e);
        let info = match attribution {
            // pid 0: nobody to look up, never the table entry of guid "".
            Attribution::None => None,
            _ => ctx.process(&e.guid).cloned(),
        };
        let Some(p) = info else {
            return Writer {
                info: None,
                attributed: false,
                untrusted: false,
                alerted: false,
                system: false,
                signed_program: false,
                unsigned_or_lolbin: false,
                attribution: Attribution::None,
                parent_trusted: false,
            };
        };
        // Task Scheduler / SCM / WMI hosts stand in when the creator is unknown.
        let host = matches!(
            file_name_lower(&p.image).as_str(),
            "svchost.exe" | "services.exe" | "wmiprvse.exe" | "taskhostw.exe" | "taskeng.exe"
        ) && ctx.system_trusted(&p);
        // Only a kernel-attributed writer is "the" writer: a heuristic guess
        // is never recorded for PS-15, never killed and never exempts.
        let attributed = !host && !ctx.is_agent(&p) && attribution == Attribution::Exact;
        let parent_trusted = match ctx.table().parent_of(&p) {
            Some(pp) => !ctx.untrusted_actor(pp) && !self.tree_alerted(ctx, &pp.guid),
            None => true,
        };
        let untrusted = ctx.untrusted_actor(&p);
        let alerted = self.tree_alerted(ctx, &p.guid);
        let system = ctx.system_trusted(&p);
        let signed_program = Ctx::validly_signed(&p)
            && matches!(
                p.path_class,
                PathClass::ProgramFiles | PathClass::System | PathClass::Windows
            )
            && !ctx.is_lolbin(&file_name_lower(&p.image));
        let unsigned_or_lolbin =
            matches!(p.signed, SignatureState::Unsigned | SignatureState::Invalid)
                || ctx.is_lolbin(&file_name_lower(&p.image));
        Writer {
            info: Some(p),
            attributed,
            untrusted,
            alerted,
            system,
            signed_program,
            unsigned_or_lolbin,
            attribution,
            parent_trusted,
        }
    }

    fn tree_alerted(&self, ctx: &Ctx, g: &ProcessGuid) -> bool {
        self.alerted.contains_key(g)
            || ctx
                .ancestry(g, 3)
                .iter()
                .any(|a| self.alerted.contains_key(&a.guid) && ctx.untrusted_actor(a))
    }

    fn env_for(ctx: &Ctx, w: &Writer) -> Env {
        Self::env_for_user(ctx, w.info.as_ref().and_then(|p| p.user.as_deref()))
    }

    /// Per-user variables for an account name (the domain prefix is ignored).
    fn env_for_user(ctx: &Ctx, account: Option<&str>) -> Env {
        let d = ctx.system_drive().to_ascii_uppercase();
        let user = account
            .map(|u| u.rsplit('\\').next().unwrap_or(u).to_string())
            .filter(|u| {
                let l = u.to_ascii_lowercase();
                !u.is_empty()
                    && !matches!(l.as_str(), "system" | "local service" | "network service")
                    && !l.ends_with('$')
                    && !l.starts_with("s-1-5-1")
            });
        match user {
            Some(u) => Env::new(d, Some(&format!(r"{d}:\Users\{u}"))),
            None => Env::new(d, None),
        }
    }

    fn classify(&self, ctx: &Ctx, r: &Resolved) -> Payload {
        let Some(path) = r.payload.clone() else {
            return Payload::default();
        };
        if r.payload_is_url {
            return Payload {
                path: Some(path),
                url: true,
                ..Default::default()
            };
        }
        let class = ctx.path_class(&path);
        let mut p = Payload {
            user_writable: class.is_user_writable(),
            class: Some(class),
            ..Default::default()
        };
        // signature / MOTW only when the payload is a known process image
        // (image index: no full table scan per event, V-L14)
        let mut procs: Vec<&ProcessInfo> = ctx.table().by_image(&path);
        procs.sort_by_key(|q| std::cmp::Reverse(q.start_ts));
        if let Some(q) = procs.first() {
            p.signed = q.signed;
            p.motw = q.motw_zone.is_some_and(|z| z >= 3);
        }
        p.running = procs
            .iter()
            .filter(|q| q.exit_ts.is_none())
            .take(4)
            .map(|q| (*q).clone())
            .collect();
        let key = path.replace('/', "\\").to_ascii_lowercase();
        let drop = self
            .drops
            .get(&key)
            .filter(|d| ctx.now - d.ts < JUST_DROPPED_MS);
        p.just_dropped = drop.is_some();
        p.dropped_by = drop.map(|d| d.by.clone());
        p.path = Some(path);
        p
    }

    fn baseline(r: &Resolved, p: &Payload, w: &Writer, cmd: &str) -> Option<&'static str> {
        // A validly signed installer running from Temp/Downloads (WiX Burn,
        // Squirrel setup) is "untrusted" by location only: allow it here.
        if w.unsigned_or_lolbin || w.alerted || p.known_unsigned() || p.url {
            return None;
        }
        let path = p.path.as_deref()?.to_ascii_lowercase();
        if !path.contains(r"\users\") || !r.chain.is_empty() {
            return None;
        }
        let cmd = cmd.to_ascii_lowercase();
        let file = file_name_lower(&path);
        BASELINE
            .iter()
            .find(|b| {
                path.contains(b.dir)
                    && b.file.is_none_or(|f| f == file)
                    && b.arg.is_none_or(|a| cmd.contains(a))
            })
            .map(|b| b.app)
    }

    /// PS-02 condition: a script host / LOLBin chain with tradecraft.
    /// Domain logon script on SYSVOL / NETLOGON written by a non-untrusted
    /// process (gpsvc, gpscript): normal in AD estates.
    fn domain_script(p: &Payload, w: &Writer) -> bool {
        let l = p.path.as_deref().unwrap_or("").to_ascii_lowercase();
        l.starts_with(r"\\")
            && (l.contains(r"\netlogon\") || l.contains(r"\sysvol\"))
            && !w.untrusted
            && !w.alerted
    }

    fn lolbin_reason(r: &Resolved, p: &Payload, w: &Writer) -> Option<String> {
        let f = &r.flags;
        if Self::domain_script(p, w) {
            return None;
        }
        let flags = f.describe().join(", ");
        if r.via("powershell.exe")
            && (f.encoded || f.hidden || f.download || f.iex || (f.bypass && p.user_writable))
        {
            return Some(format!("PowerShell ({flags})"));
        }
        if r.via("mshta.exe") && (f.remote || f.script_proto || p.user_writable) {
            return Some(
                "mshta (HTML application host) running a remote or user-folder script".into(),
            );
        }
        if (r.via("rundll32.exe") || r.via("regsvr32.exe"))
            && (f.remote || f.script_proto || p.user_writable)
        {
            return Some(if f.script_proto {
                "rundll32 executing script code (javascript:/mshtml)".into()
            } else {
                "rundll32/regsvr32 loading a DLL or scriptlet from a user folder or URL".into()
            });
        }
        if (r.via("wscript.exe") || r.via("cscript.exe")) && (p.user_writable || f.remote) {
            return Some("Windows Script Host running a script from a user-writable folder".into());
        }
        if f.headless {
            return Some("a headless console (conhost --headless) hiding the command".into());
        }
        let interp = [
            "autoit3.exe",
            "autoit3_x64.exe",
            "python.exe",
            "pythonw.exe",
            "py.exe",
            "pyw.exe",
            "node.exe",
            "java.exe",
            "javaw.exe",
        ];
        if interp.iter().any(|i| r.via(i)) && p.user_writable {
            return Some(
                "a script interpreter (AutoIt/Python/Node/Java) running a user-folder script"
                    .into(),
            );
        }
        if ["curl.exe", "bitsadmin.exe", "certutil.exe", "wget.exe"]
            .iter()
            .any(|i| r.via(i))
            && f.download
        {
            return Some("a download tool (curl/bitsadmin/certutil)".into());
        }
        if r.via("msiexec.exe") && f.remote {
            return Some("msiexec installing a package straight from a URL".into());
        }
        if !r.chain.is_empty() && (f.encoded || f.script_proto) {
            return Some(format!("a command-line chain ({flags})"));
        }
        None
    }

    // ---- PS-15 bookkeeping ----

    fn record(&mut self, ctx: &Ctx, w: &Writer, loc: &Loc, p: &Payload, _out: &mut Vec<FamilyHit>) {
        let Some(info) = w.info.as_ref().filter(|_| w.attributed) else {
            return;
        };
        if loc.is_kestrel() {
            return;
        }
        let quarantine = Self::owned_payload(p, w)
            .filter(|q| loc.kind != AutorunKind::StartupFile || !same_path(q, &loc.location));
        let rec = Rec {
            ts: ctx.now,
            what: loc.what.clone(),
            remove: loc.remove(),
            quarantine,
        };
        // Tree already rolled back: remove this late arrival (after this
        // event's own hits, see `flush_late`).
        if self
            .rolled
            .get(&info.guid)
            .is_some_and(|t| ctx.now - *t < ROLLED_TTL_MS)
        {
            if self.pending_late.len() < MAX_RECS_PER_CREATOR {
                self.pending_late.push((info.guid.clone(), rec));
            }
            return;
        }
        if self.created.len() >= MAX_CREATORS && !self.created.contains_key(&info.guid) {
            if let Some(oldest) = self
                .created
                .iter()
                .min_by_key(|(_, v)| v.last().map(|r| r.ts).unwrap_or(0))
                .map(|(k, _)| k.clone())
            {
                self.created.remove(&oldest);
            }
        }
        let v = self.created.entry(info.guid.clone()).or_default();
        v.retain(|r| r.remove != rec.remove);
        if v.len() >= MAX_RECS_PER_CREATOR {
            v.remove(0);
        }
        v.push(rec);
    }

    fn rollback_hit(
        subject: &ProcessGuid,
        process: Option<ProcessInfo>,
        trigger: &str,
        recs: Vec<Rec>,
        dedup: Option<String>,
    ) -> FamilyHit {
        let mut actions = Vec::new();
        let mut whats: Vec<String> = Vec::new();
        for r in &recs {
            if !actions.contains(&r.remove) {
                actions.push(r.remove.clone());
            }
            if let Some(q) = &r.quarantine {
                let a = quarantine(q);
                if !actions.contains(&a) {
                    actions.push(a);
                }
            }
            if whats.len() < 6 && !whats.contains(&r.what) {
                whats.push(r.what.clone());
            }
        }
        let n = recs.len();
        let summary = format!(
            "Persistence rollback: {trigger} stopped this process tree, so the {n} autostart entr{} it created {} removed ({}). Originals are backed up and can be restored.",
            if n == 1 { "y" } else { "ies" },
            if n == 1 { "is" } else { "are" },
            crate::util::join_and(&whats)
        );
        let mut h = FamilyHit::new(PS15, subject, Severity::High, summary).with_actions(actions);
        h.process = process;
        h.dedup_key = dedup;
        h
    }

    /// Actions for a Protect-level hit.
    fn actions(
        &mut self,
        rule: &str,
        ctx: &Ctx,
        loc: &Loc,
        p: &Payload,
        w: &Writer,
        kill_payload: bool,
    ) -> Vec<ResponseAction> {
        if loc.is_kestrel() {
            return vec![];
        }
        let mut v = vec![loc.remove()];
        if let Some(q) = Self::owned_payload(p, w) {
            if loc.kind != AutorunKind::StartupFile || !same_path(&q, &loc.location) {
                v.push(quarantine(&q));
            }
        }
        let writer_guid = w.info.as_ref().map(|i| i.guid.clone());
        let writer_user = w
            .info
            .as_ref()
            .and_then(|i| i.user.as_deref())
            .map(str::to_ascii_lowercase);
        // V-M11: only a payload the writer owns (its own profile, or a file
        // it was seen creating), and only instances run by the same account.
        if kill_payload && Self::owned_payload(p, w).is_some() {
            for r in &p.running {
                let same_user = match (&writer_user, r.user.as_deref()) {
                    (Some(wu), Some(ru)) => wu == &ru.to_ascii_lowercase(),
                    _ => false,
                };
                if Some(&r.guid) != writer_guid.as_ref()
                    && same_user
                    && !ctx.protected(r)
                    && !ctx.is_agent(r)
                    && r.path_class.is_user_writable()
                {
                    v.push(ResponseAction::KillProcess {
                        pid: r.pid,
                        guid: Some(r.guid.clone()),
                        tree: false,
                    });
                }
            }
        }
        if let Some(info) = &w.info {
            if w.attributed
                && (w.untrusted || w.alerted)
                && !w.system
                && !ctx.protected(info)
                && !ctx.is_agent(info)
            {
                v.push(kill_tree(info));
                bounded_insert(&mut self.killing, &info.guid, ctx.now);
            }
            // This hit removes the entry itself: PS-15 must not repeat it.
            if ctx.protect(rule) {
                self.forget_rec(&info.guid, &v[0]);
            }
        }
        v
    }

    /// The quarantinable payload path when the (exactly attributed) writer
    /// owns it (V-H4 / V-M11): the path came from autorun text the writer
    /// chose, so it is only acted on inside the writer's own profile, or
    /// when the writer was seen creating that very file (never under
    /// `\Windows\` or `\ProgramData\Microsoft\`).
    fn owned_payload(p: &Payload, w: &Writer) -> Option<String> {
        let q = p.quarantinable()?;
        let info = w.info.as_ref()?;
        if w.attribution != Attribution::Exact || !w.attributed {
            return None;
        }
        if super::attacker_named_quarantinable(&q, info.user.as_deref()) {
            return Some(q);
        }
        let created_by_writer = p.dropped_by.as_ref() == Some(&info.guid);
        let n = crate::paths::normalize_path(&q);
        let rest = crate::util::strip_drive(&n);
        let sensitive = rest.starts_with(r"\windows\")
            || rest.starts_with(r"\programdata\microsoft\")
            || rest.split('\\').any(|c| c == "..");
        (created_by_writer && !sensitive).then_some(q)
    }

    fn forget_rec(&mut self, g: &ProcessGuid, remove: &ResponseAction) {
        if let Some(v) = self.created.get_mut(g) {
            v.retain(|r| &r.remove != remove);
        }
    }

    /// Emit PS-15 for late autoruns of rolled-back trees that this event's
    /// own Protect hits do not already remove.
    fn flush_late(&mut self, ctx: &Ctx, start: usize, out: &mut Vec<FamilyHit>) {
        if self.pending_late.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending_late);
        let mut by_guid: Vec<(ProcessGuid, Vec<Rec>)> = Vec::new();
        for (g, rec) in pending {
            let handled = out[start.min(out.len())..]
                .iter()
                .any(|h| ctx.protect(h.rule) && h.actions.contains(&rec.remove));
            if handled {
                continue;
            }
            match by_guid.iter_mut().find(|(x, _)| *x == g) {
                Some((_, v)) => v.push(rec),
                None => by_guid.push((g, vec![rec])),
            }
        }
        for (g, recs) in by_guid {
            let key = recs
                .iter()
                .map(|r| format!("{:?}", r.remove))
                .collect::<Vec<_>>()
                .join("|");
            out.push(Self::rollback_hit(
                &g,
                None,
                "an earlier Protect-mode detection",
                recs,
                Some(format!("{PS15}:late:{key}")),
            ));
        }
    }

    // ---- generic autorun judgement (Run family, tasks, Startup .lnk targets) ----

    #[allow(clippy::too_many_arguments)]
    fn judge(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        rule: &'static str,
        loc: Loc,
        cmd: &str,
        hidden_logon_task: bool,
        env_user: Option<&str>,
        out: &mut Vec<FamilyHit>,
    ) {
        if loc.is_kestrel() || cmd.trim().is_empty() {
            return;
        }
        let w = self.writer(ctx, e);
        let env = match env_user {
            Some(u) => Self::env_for_user(ctx, Some(u)),
            None => Self::env_for(ctx, &w),
        };
        let r = autorun::resolve(cmd, &env);
        let p = self.classify(ctx, &r);
        self.record(ctx, &w, &loc, &p, out);
        if let Some(reason) = Self::lolbin_reason(&r, &p, &w) {
            self.ps02(ctx, e, &loc, &r, &p, &w, &reason, out);
            return;
        }
        if p.url || Self::domain_script(&p, &w) {
            return;
        }
        let trusted_place = matches!(
            p.class,
            Some(PathClass::System | PathClass::Windows | PathClass::ProgramFiles) | None
        );
        let candidate = (p.user_writable || (hidden_logon_task && !trusted_place))
            && p.signed != SignatureState::Valid;
        if !candidate || Self::baseline(&r, &p, &w, cmd).is_some() {
            return;
        }
        let strong_ctx = p.motw || p.just_dropped || w.suspicious();
        let severity = if strong_ctx || hidden_logon_task {
            Severity::High
        } else {
            Severity::Medium
        };
        let protect_level = p.known_unsigned() && (p.motw || p.just_dropped) && w.suspicious();
        let actions = if protect_level {
            self.actions(rule, ctx, &loc, &p, &w, true)
        } else {
            vec![]
        };
        let mut why = Vec::new();
        if hidden_logon_task {
            why.push("hidden task with a logon/boot trigger".to_string());
        }
        if r.flags.unquoted_spaces {
            why.push("unquoted path with spaces".to_string());
        }
        let summary = format!(
            "{} set {} to start {} automatically{}{}",
            w.describe(),
            loc.what,
            p.describe(),
            if why.is_empty() {
                String::new()
            } else {
                format!(" ({})", why.join("; "))
            },
            if protect_level {
                "."
            } else {
                " — payload signature not confirmed, alert only."
            }
        );
        let mut h = FamilyHit::new(rule, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(rule));
        out.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn ps02(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        loc: &Loc,
        r: &Resolved,
        p: &Payload,
        w: &Writer,
        reason: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let f = &r.flags;
        let severity = if f.remote || f.script_proto || (f.encoded && f.download) || f.headless {
            Severity::Critical
        } else {
            Severity::High
        };
        // A validly signed management tool (RMM, updater) writing it: Audit level.
        let audit_level = w.attributed && w.trusted_signed_program();
        let actions = if audit_level {
            vec![]
        } else {
            self.actions(PS02, ctx, loc, p, w, false)
        };
        let chain = r.chain.join(" → ");
        let summary = format!(
            "{} set {} to run {} via {}{}{}",
            w.describe(),
            loc.what,
            reason,
            if chain.is_empty() {
                "a script file".into()
            } else {
                chain
            },
            match &p.path {
                Some(_) => format!(", payload {}", p.describe()),
                None => String::new(),
            },
            if audit_level {
                " — written by a signed management tool, alert only."
            } else {
                "."
            }
        );
        let mut h = FamilyHit::new(PS02, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS02));
        out.push(h);
    }

    // ---- per-source handlers ----

    fn on_file(&mut self, ctx: &Ctx, e: &Event, path: &str, op: FileOp, out: &mut Vec<FamilyHit>) {
        if !matches!(op, FileOp::Create | FileOp::Rename) {
            return;
        }
        let lower = path.replace('/', "\\").to_ascii_lowercase();
        let ext = ext_of(&lower).to_string();
        if TRACKED_EXTS.contains(&ext.as_str()) {
            if self.drops.len() >= MAX_DROPS {
                self.prune(ctx.now);
            }
            if self.drops.len() < MAX_DROPS {
                self.drops.insert(
                    lower.clone(),
                    Dropped {
                        ts: ctx.now,
                        by: e.guid.clone(),
                    },
                );
            }
        }
        // PS-03: top-level item of a user or common Startup folder.
        const STARTUP: &str = r"\microsoft\windows\start menu\programs\startup\";
        let Some(i) = lower.find(STARTUP) else {
            return;
        };
        let name = &lower[i + STARTUP.len()..];
        if name.is_empty() || name.contains('\\') || name == "desktop.ini" {
            return;
        }
        let is_script = SCRIPT_EXTS.contains(&ext.as_str());
        let is_pe = PE_EXTS.contains(&ext.as_str());
        let is_lnk = ext == "lnk";
        if !(is_script || is_pe || is_lnk) {
            return;
        }
        let w = self.writer(ctx, e);
        if let Some(info) = &w.info {
            let fname = file_name_lower(&info.image);
            // user drag-and-drop / signed installers
            if w.trusted_system() && fname == "explorer.exe" {
                return;
            }
            if w.trusted_signed_program() {
                return;
            }
            if fname == "msiexec.exe"
                && matches!(info.path_class, PathClass::System)
                && info.signed == SignatureState::Valid
                && w.exempt_ok()
            {
                return;
            }
        }
        let loc = Loc {
            kind: AutorunKind::StartupFile,
            location: path.to_string(),
            value_name: None,
            restore: None,
            what: format!(
                "the Startup-folder file \"{}\"",
                path.rsplit(['\\', '/']).next().unwrap_or(path)
            ),
        };
        let p = Payload {
            path: Some(path.to_string()),
            class: Some(ctx.path_class(path)),
            user_writable: ctx.path_class(path).is_user_writable(),
            just_dropped: true,
            ..Default::default()
        };
        self.record(ctx, &w, &loc, &p, out);
        let kind = if is_script {
            "a script"
        } else if is_pe {
            "a program"
        } else {
            "a shortcut"
        };
        let protect_level = !is_lnk && w.suspicious();
        let severity = if protect_level {
            Severity::High
        } else if is_lnk && !w.suspicious() {
            Severity::Low
        } else {
            Severity::Medium
        };
        let actions = if protect_level {
            self.actions(PS03, ctx, &loc, &p, &w, false)
        } else {
            vec![]
        };
        let summary = format!(
            "{} placed {kind} in the Startup folder ({path}), so it runs at every logon{}",
            w.describe(),
            if protect_level {
                "."
            } else if is_lnk {
                " — shortcut targets are not resolved yet, alert only."
            } else {
                " — alert only."
            }
        );
        let mut h = FamilyHit::new(PS03, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS03));
        out.push(h);
    }

    fn on_registry(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        key: &str,
        value_name: &str,
        data: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let Some((hive, rest)) = split_key(key) else {
            return;
        };
        let v = value_name.to_ascii_lowercase();
        let v = if v == "(default)" { String::new() } else { v };
        let reg = |what: String, restore: Option<String>| Loc {
            kind: AutorunKind::RegistryValue,
            location: key.to_string(),
            value_name: Some(value_name.to_string()),
            restore,
            what,
        };

        if is_run_family(&rest, &v) {
            let sub = rest.rsplit('\\').next().unwrap_or("run");
            let label = match sub {
                "runonce" => "RunOnce",
                "runservices" => "RunServices",
                "runservicesonce" => "RunServicesOnce",
                "windows" => "Windows Load/Run",
                _ if rest.contains("runonceex") => "RunOnceEx",
                _ if rest.contains(r"policies\explorer") => "policy Run",
                _ => "Run",
            };
            let loc = reg(
                format!(
                    "the {} {label} key value \"{value_name}\"",
                    hive_label(hive)
                ),
                None,
            );
            // RunOnceEx: `DllFile|Function|Args`, `||cmdline`
            let cmd = data.trim_start_matches('|');
            self.judge(ctx, e, PS01, loc, cmd, false, None, out);
            return;
        }

        // PS-04 Startup folder redirection
        if (rest == format!(r"{CV}\explorer\user shell folders")
            || rest == format!(r"{CV}\explorer\shell folders"))
            && (v == "startup" || v == "common startup")
        {
            self.ps04(ctx, e, hive, &rest, key, value_name, &v, data, out);
            return;
        }

        // PS-09 IFEO Debugger / GlobalFlag, SilentProcessExit MonitorProcess
        let ifeo = format!(r"{NTCV}\image file execution options\");
        if let Some(exe) = rest.strip_prefix(&ifeo) {
            if exe.contains('\\') || exe == "lsass.exe" {
                return; // per-path filter keys; lsass belongs to CD-07
            }
            if v == "globalflag" {
                if parse_number(data).is_some_and(|n| n & 0x200 != 0) {
                    if self.global_flag.len() >= MAX_GLOBAL_FLAG {
                        self.global_flag.clear();
                    }
                    self.global_flag.insert(exe.to_string(), ctx.now);
                }
                return;
            }
            if v == "debugger" && !data.trim().is_empty() {
                let loc = reg(
                    format!("an Image File Execution Options debugger for {exe}"),
                    None,
                );
                self.ps09(ctx, e, exe, loc, data, false, out);
            }
            return;
        }
        let spe = format!(r"{NTCV}\silentprocessexit\");
        if let Some(exe) = rest.strip_prefix(&spe) {
            if exe.contains('\\') || exe.starts_with("lsass") {
                return;
            }
            if v == "monitorprocess" && !data.trim().is_empty() {
                let loc = reg(format!("a silent-process-exit monitor for {exe}"), None);
                self.ps09(ctx, e, exe, loc, data, true, out);
            }
            return;
        }

        // PS-10 Winlogon / AppInit / AppCert / BootExecute
        let winlogon = rest == format!(r"{NTCV}\winlogon");
        let pol_system = rest == format!(r"{CV}\policies\system");
        if (winlogon && (v == "userinit" || v == "shell")) || (pol_system && v == "shell") {
            self.ps10_winlogon(ctx, e, hive, winlogon, key, value_name, &v, data, out);
            return;
        }
        if rest == format!(r"{NTCV}\windows") && (v == "appinit_dlls" || v == "loadappinit_dlls") {
            if v == "loadappinit_dlls" {
                self.appinit_loaded = parse_number(data).is_some_and(|n| n != 0);
                return;
            }
            if data.trim().is_empty() {
                return;
            }
            let loc = reg("AppInit_DLLs".into(), Some(String::new()));
            self.ps10_dll_list(ctx, e, loc, data, "AppInit_DLLs", self.appinit_loaded, out);
            return;
        }
        if rest.starts_with(r"system\currentcontrolset\control\session manager\appcertdlls")
            && !data.trim().is_empty()
        {
            let loc = reg(format!("the AppCertDlls entry \"{value_name}\""), None);
            self.ps10_dll_list(ctx, e, loc, data, "AppCertDlls", true, out);
            return;
        }
        if rest == r"system\currentcontrolset\control\session manager" && v == "bootexecute" {
            self.ps10_bootexecute(ctx, e, key, value_name, data, out);
            return;
        }

        // PS-07 service ImagePath written directly
        if let Some(svc) = rest.strip_prefix(r"system\currentcontrolset\services\") {
            if !svc.contains('\\') && v == "imagepath" && !data.trim().is_empty() {
                let w = self.writer(ctx, e);
                let by_scm = w.info.as_ref().is_some_and(|p| {
                    file_name_lower(&p.image) == "services.exe" && w.trusted_system()
                });
                if !by_scm {
                    let name = key.rsplit('\\').next().unwrap_or(svc).to_string();
                    self.ps07(ctx, e, &name, data, None, None, out);
                }
            }
            return;
        }

        // PS-11 COM hijack in the user hive
        if hive == Hive::User {
            if let Some(tail) = rest.strip_prefix(r"software\classes\clsid\") {
                let (clsid, sub) = match tail.split_once('\\') {
                    Some((c, s)) => (c, s),
                    None => (tail, ""),
                };
                let kind = match (sub, v.as_str()) {
                    ("inprocserver32" | "inprochandler32", "") => Some("in-process server"),
                    ("localserver32", "") => Some("local server"),
                    ("treatas", "") => Some("TreatAs redirection"),
                    ("", "scriptleturl") => Some("scriptlet URL"),
                    _ => None,
                };
                if let Some(kind) = kind {
                    if !data.trim().is_empty() {
                        let loc = reg(format!("a per-user COM {kind} for {clsid}"), None);
                        self.ps11(ctx, e, sub, kind, loc, data, out);
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ps04(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        hive: Hive,
        rest: &str,
        key: &str,
        value_name: &str,
        v: &str,
        data: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let expanded = env.expand(data.trim().trim_matches('"'));
        let l = expanded.trim_end_matches('\\').to_ascii_lowercase();
        if l.is_empty() || l.ends_with(r"\microsoft\windows\start menu\programs\startup") {
            return; // default location (also when redirected with the profile)
        }
        // Group Policy folder redirection (gpsvc in svchost, gpscript)
        if w.trusted_system() {
            return;
        }
        let common = v == "common startup";
        let default = if common {
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"
        } else {
            r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        };
        // Only User Shell Folders is authoritative (Explorer regenerates Shell
        // Folders from it), so only that key is restored.
        let restorable = rest.ends_with("user shell folders");
        let loc = Loc {
            kind: AutorunKind::RegistryValue,
            location: key.to_string(),
            value_name: Some(value_name.to_string()),
            restore: Some(default.to_string()),
            what: format!(
                "the {} {} folder location",
                hive_label(hive),
                if common { "Common Startup" } else { "Startup" }
            ),
        };
        let class = ctx.path_class(&expanded);
        let p = Payload {
            path: Some(expanded.clone()),
            class: Some(class),
            user_writable: class.is_user_writable(),
            ..Default::default()
        };
        self.record_if(ctx, &w, &loc, restorable, out);
        let actions = if restorable && !loc.is_kestrel() {
            let mut a = vec![loc.remove()];
            if let Some(info) = &w.info {
                if w.suspicious() && !ctx.protected(info) && !ctx.is_agent(info) {
                    a.push(kill_tree(info));
                    bounded_insert(&mut self.killing, &info.guid, ctx.now);
                }
                if ctx.protect(PS04) {
                    self.forget_rec(&info.guid, &a[0]);
                }
            }
            a
        } else {
            vec![]
        };
        let summary = format!(
            "{} redirected {} to {}{} — anything placed there now starts at every logon.",
            w.describe(),
            loc.what,
            expanded,
            if p.user_writable {
                " (a user-writable folder)"
            } else {
                ""
            }
        );
        let mut h = FamilyHit::new(PS04, &e.guid, Severity::High, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS04));
        out.push(h);
    }

    fn record_if(
        &mut self,
        ctx: &Ctx,
        w: &Writer,
        loc: &Loc,
        cond: bool,
        out: &mut Vec<FamilyHit>,
    ) {
        if cond {
            self.record(ctx, w, loc, &Payload::default(), out);
        }
    }

    fn on_task(&mut self, ctx: &Ctx, e: &Event, t: &TaskChange, out: &mut Vec<FamilyHit>) {
        if t.op == TaskOp::Deleted {
            return;
        }
        let name_l = t.name.to_ascii_lowercase();
        let logon = t
            .triggers
            .iter()
            .any(|x| matches!(x.to_ascii_lowercase().as_str(), "logon" | "boot"));
        let hidden_logon = t.hidden && logon && !name_l.starts_with(r"\microsoft\");
        for a in t.actions.iter().take(8) {
            let loc = Loc {
                kind: AutorunKind::ScheduledTask,
                location: t.name.clone(),
                value_name: None,
                restore: None,
                what: format!("the scheduled task \"{}\"", t.name),
            };
            self.judge(ctx, e, PS05, loc, a, hidden_logon, t.user.as_deref(), out);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn ps07(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        name: &str,
        image_path: &str,
        start_type: Option<u32>,
        service_type: Option<u32>,
        out: &mut Vec<FamilyHit>,
    ) {
        if name.eq_ignore_ascii_case(KESTREL_SERVICE) || image_path.trim().is_empty() {
            return;
        }
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let r = autorun::resolve(image_path, &env);
        let p = self.classify(ctx, &r);
        let loc = Loc {
            kind: AutorunKind::Service,
            location: name.to_string(),
            value_name: None,
            restore: None,
            what: format!("the service \"{name}\""),
        };
        if loc.is_kestrel() {
            return;
        }
        self.record(ctx, &w, &loc, &p, out);
        let path_l = p.path.as_deref().unwrap_or("").to_ascii_lowercase();
        let rest = crate::util::strip_drive(&path_l);
        let users_or_temp = !p.url
            && (rest.starts_with(r"\users\")
                || rest.starts_with(r"\windows\temp\")
                || matches!(p.class, Some(PathClass::Temp | PathClass::Downloads)));
        let interp = [
            "cmd.exe",
            "powershell.exe",
            "mshta.exe",
            "rundll32.exe",
            "wscript.exe",
            "cscript.exe",
            "regsvr32.exe",
        ]
        .iter()
        .any(|i| r.via(i));
        let driver = matches!(service_type, Some(1 | 2)) || path_l.ends_with(".sys");
        let lolbin = Self::lolbin_reason(&r, &p, &w);
        let strong = users_or_temp || interp || p.url || (driver && p.user_writable);
        let weak = p.user_writable || p.known_unsigned();
        if !strong && !weak {
            return;
        }
        let severity = if strong && (lolbin.is_some() || driver || p.url) {
            Severity::Critical
        } else if strong {
            Severity::High
        } else {
            Severity::Medium
        };
        let actions = if strong {
            self.actions(PS07, ctx, &loc, &p, &w, false)
        } else {
            vec![]
        };
        let mut why = Vec::new();
        if users_or_temp {
            why.push("its binary lives in a user profile or Temp folder".to_string());
        }
        if interp {
            why.push(format!("it wraps {}", r.chain.join(" → ")));
        }
        if let Some(l) = &lolbin {
            why.push(l.clone());
        }
        if driver {
            why.push(format!(
                "it is a driver{}",
                match start_type {
                    Some(0) => " loaded at boot",
                    Some(1) => " loaded at system start",
                    _ => "",
                }
            ));
        }
        if why.is_empty() {
            why.push(p.describe());
        }
        let summary = format!(
            "{} installed {} that runs {}: {}{}",
            w.describe(),
            loc.what,
            p.describe(),
            why.join("; "),
            if strong { "." } else { " — alert only." }
        );
        let mut h = FamilyHit::new(PS07, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS07));
        out.push(h);
    }

    fn ps08(&mut self, ctx: &Ctx, e: &Event, b: &WmiBinding, out: &mut Vec<FamilyHit>) {
        let cl = b.consumer.to_ascii_lowercase();
        let fl = b.filter.to_ascii_lowercase();
        // SCM Event Log Filter / Consumer pair shipped with Windows.
        if cl.contains("scm event log") || fl.contains("scm event log") {
            return;
        }
        let strong = cl.contains("commandlineeventconsumer")
            || cl.contains("activescripteventconsumer")
            || cl.contains("commandlinetemplate");
        // `CommandLineEventConsumer="name"` [+ command]
        let (name, tail) = match b.consumer.find("=\"") {
            Some(i) => {
                let after = &b.consumer[i + 2..];
                match after.find('"') {
                    Some(j) => (after[..j].to_string(), after[j + 1..].to_string()),
                    None => (after.to_string(), String::new()),
                }
            }
            None => (b.consumer.trim().to_string(), String::new()),
        };
        let w = self.writer(ctx, e);
        let loc = Loc {
            kind: AutorunKind::WmiSubscription,
            location: name.clone(),
            value_name: None,
            restore: None,
            what: format!("the WMI event subscription \"{name}\" ({})", b.namespace),
        };
        let cmd = tail
            .trim()
            .trim_start_matches([',', ';', ':', ' '])
            .trim_start_matches("CommandLineTemplate")
            .trim_start_matches(['=', ' ', ':'])
            .to_string();
        let (r, p) = if cmd.is_empty() {
            (Resolved::default(), Payload::default())
        } else {
            let env = Self::env_for(ctx, &w);
            let r = autorun::resolve(&cmd, &env);
            let p = self.classify(ctx, &r);
            (r, p)
        };
        self.record(ctx, &w, &loc, &p, out);
        let severity = if strong {
            Severity::Critical
        } else {
            Severity::Medium
        };
        let actions = if strong {
            self.actions(PS08, ctx, &loc, &p, &w, false)
        } else {
            vec![]
        };
        let flags = r.flags.describe();
        let summary = format!(
            "{} bound a permanent WMI event subscription ({}) that {}{}{}",
            w.describe(),
            name,
            if strong {
                "runs a command or script whenever its trigger fires"
            } else {
                "uses a non-executing consumer"
            },
            if flags.is_empty() {
                String::new()
            } else {
                format!(" ({})", flags.join(", "))
            },
            if strong { "." } else { " — alert only." }
        );
        let mut h = FamilyHit::new(PS08, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS08));
        out.push(h);
    }

    /// `wmic … CommandLineEventConsumer create` / PowerShell `__FilterToConsumerBinding`.
    fn ps08_tooling(&mut self, e: &Event, text: &str, how: &str, out: &mut Vec<FamilyHit>) {
        let l = text.to_ascii_lowercase();
        let consumer =
            l.contains("commandlineeventconsumer") || l.contains("activescripteventconsumer");
        let binding = l.contains("__filtertoconsumerbinding") || l.contains("__eventfilter");
        let create = [
            "create",
            "set-wmiinstance",
            "new-ciminstance",
            "createinstance",
            ".put(",
        ]
        .iter()
        .any(|k| l.contains(k));
        if !(consumer && (binding || create)) {
            return;
        }
        let summary = format!(
            "{how} creates a WMI event consumer that runs commands (permanent WMI subscription) — alert only; the subscription itself is removed when it is registered."
        );
        let mut h = FamilyHit::new(PS08, &e.guid, Severity::High, summary);
        h.dedup_key = Some(format!("{PS08}:tooling"));
        out.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn ps09(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        target: &str,
        loc: Loc,
        data: &str,
        silent_exit: bool,
        out: &mut Vec<FamilyHit>,
    ) {
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let r = autorun::resolve(data, &env);
        let p = self.classify(ctx, &r);
        self.record(ctx, &w, &loc, &p, out);
        let access = !silent_exit && ACCESSIBILITY.contains(&target);
        let high_value = access || HIGH_VALUE_TARGETS.contains(&target);
        // Known-signed debugger in a protected folder on an ordinary target
        // (Process Explorer replacing Task Manager, VS JIT): benign.
        if !high_value
            && p.signed == SignatureState::Valid
            && !p.user_writable
            && !p.url
            && Self::lolbin_reason(&r, &p, &w).is_none()
        {
            return;
        }
        let lolbin = Self::lolbin_reason(&r, &p, &w);
        let strong = access
            || (p.user_writable && !p.url)
            || p.url
            || p.known_unsigned()
            || lolbin.is_some();
        let flagged = silent_exit && self.global_flag.contains_key(target);
        let severity = if access || (strong && (high_value || flagged)) {
            Severity::Critical
        } else if strong || high_value {
            Severity::High
        } else {
            Severity::Medium
        };
        let actions = if strong {
            self.actions(PS09, ctx, &loc, &p, &w, false)
        } else {
            vec![]
        };
        let summary = if silent_exit {
            format!(
                "{} registered {} that runs {} whenever {target} exits{}{}",
                w.describe(),
                loc.what,
                p.describe(),
                if flagged {
                    " (GlobalFlag 0x200 set)"
                } else {
                    ""
                },
                if strong { "." } else { " — alert only." }
            )
        } else {
            format!(
                "{} hijacked {target}: starting it now runs {} instead{}{}",
                w.describe(),
                p.describe(),
                if access {
                    " — reachable from the logon screen (accessibility backdoor)"
                } else {
                    ""
                },
                if strong { "." } else { " — alert only." }
            )
        };
        let mut h = FamilyHit::new(PS09, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS09));
        out.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn ps10_winlogon(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        hive: Hive,
        winlogon: bool,
        key: &str,
        value_name: &str,
        v: &str,
        data: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let d = ctx.system_drive().to_ascii_lowercase();
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let expanded = env.expand(data);
        let parts: Vec<String> = expanded
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let (default_name, restore_default) = if v == "userinit" {
            (
                "userinit.exe",
                format!(
                    r"{}:\Windows\system32\userinit.exe,",
                    d.to_ascii_uppercase()
                ),
            )
        } else {
            ("explorer.exe", "explorer.exe".to_string())
        };
        let is_default = |s: &str| {
            let s = s.to_ascii_lowercase();
            s == default_name
                || s == format!(r"{d}:\windows\system32\{default_name}")
                || s == format!(r"{d}:\windows\{default_name}")
        };
        let foreign: Vec<&String> = parts.iter().filter(|s| !is_default(s)).collect();
        if foreign.is_empty() {
            // default (or empty) value; an HKCU copy of the default is harmless too
            return;
        }
        let restore = (hive == Hive::Machine && winlogon).then_some(restore_default.clone());
        let loc = Loc {
            kind: AutorunKind::RegistryValue,
            location: key.to_string(),
            value_name: Some(value_name.to_string()),
            restore,
            what: format!("the {} Winlogon {value_name} value", hive_label(hive)),
        };
        let extra = foreign.first().map(|s| s.to_string()).unwrap_or_default();
        let r = autorun::resolve(&extra, &env);
        let p = self.classify(ctx, &r);
        self.record(ctx, &w, &loc, &p, out);
        // Kiosk / Shell Launcher configuration by a Windows component: Audit level.
        let audit_level = w.trusted_system() || w.trusted_signed_program();
        let actions = if audit_level {
            vec![]
        } else {
            self.actions(PS10, ctx, &loc, &p, &w, false)
        };
        let summary = format!(
            "{} changed {} from the Windows default to \"{}\", so {} runs at every logon{}",
            w.describe(),
            loc.what,
            data.trim(),
            p.describe(),
            if audit_level {
                " — written by a Windows/signed component (kiosk or VDI shell?), alert only."
            } else {
                "."
            }
        );
        let mut h =
            FamilyHit::new(PS10, &e.guid, Severity::Critical, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS10));
        out.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn ps10_dll_list(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        loc: Loc,
        data: &str,
        label: &str,
        active: bool,
        out: &mut Vec<FamilyHit>,
    ) {
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let first = data
            .split([',', ' ', ';'])
            .map(|s| s.trim().trim_matches('"'))
            .find(|s| !s.is_empty())
            .unwrap_or("");
        let r = autorun::resolve(first, &env);
        let p = self.classify(ctx, &r);
        self.record(ctx, &w, &loc, &p, out);
        let severity = if active || p.user_writable || w.suspicious() {
            Severity::High
        } else {
            Severity::Medium
        };
        let summary = format!(
            "{} added {} to {label}, which loads it into {} — alert only (security and kiosk products also use this).",
            w.describe(),
            p.describe(),
            if label == "AppCertDlls" {
                "every process that creates processes"
            } else {
                "every process that loads user32.dll"
            }
        );
        let mut h = FamilyHit::new(PS10, &e.guid, severity, summary);
        h.dedup_key = Some(loc.dedup(PS10));
        out.push(h);
    }

    fn ps10_bootexecute(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        key: &str,
        value_name: &str,
        data: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let entries: Vec<String> = data
            .split(['\0', '\n', '\r'])
            .map(|s| s.split_whitespace().collect::<Vec<_>>().join(" "))
            .filter(|s| !s.is_empty())
            .collect();
        // `autocheck autochk *` and chkdsk-scheduled `autocheck autochk /p \??\C:`
        let foreign: Vec<&String> = entries
            .iter()
            .filter(|s| !s.to_ascii_lowercase().starts_with("autocheck autochk"))
            .collect();
        if foreign.is_empty() {
            return;
        }
        let w = self.writer(ctx, e);
        let loc = Loc {
            kind: AutorunKind::RegistryValue,
            location: key.to_string(),
            value_name: Some(value_name.to_string()),
            restore: Some("autocheck autochk *".into()),
            what: "the Session Manager BootExecute value".into(),
        };
        self.record(ctx, &w, &loc, &Payload::default(), out);
        let audit_level = w.trusted_system() || w.trusted_signed_program();
        let actions = if audit_level {
            vec![]
        } else {
            self.actions(PS10, ctx, &loc, &Payload::default(), &w, false)
        };
        let summary = format!(
            "{} added \"{}\" to {}, which runs before Windows starts{}",
            w.describe(),
            foreign[0],
            loc.what,
            if audit_level {
                " — written by a Windows/signed component, alert only."
            } else {
                "."
            }
        );
        let mut h =
            FamilyHit::new(PS10, &e.guid, Severity::Critical, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS10));
        out.push(h);
    }

    #[allow(clippy::too_many_arguments)]
    fn ps11(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        sub: &str,
        kind: &str,
        loc: Loc,
        data: &str,
        out: &mut Vec<FamilyHit>,
    ) {
        let w = self.writer(ctx, e);
        let env = Self::env_for(ctx, &w);
        let scriptlet = kind == "scriptlet URL";
        let treat_as = kind == "TreatAs redirection";
        let r = if sub == "inprocserver32" || sub == "inprochandler32" {
            // a bare (possibly unquoted) DLL path, not a command line
            let path = env.expand(data.trim().trim_matches('"'));
            Resolved {
                image: path.clone(),
                payload: Some(path),
                ..Default::default()
            }
        } else if scriptlet || treat_as {
            let t = data.trim().to_string();
            let url = autorun::is_url(&t);
            Resolved {
                payload: (!treat_as).then_some(t),
                payload_is_url: url,
                ..Default::default()
            }
        } else {
            autorun::resolve(data, &env)
        };
        let p = self.classify(ctx, &r);
        self.record(ctx, &w, &loc, &p, out);
        let lolbin = if sub == "localserver32" {
            Self::lolbin_reason(&r, &p, &w)
        } else {
            None
        };
        let untrusted_server = p.user_writable && p.signed != SignatureState::Valid;
        if !(scriptlet || treat_as || untrusted_server || lolbin.is_some() || p.url) {
            return;
        }
        if !scriptlet && !treat_as && lolbin.is_none() && Self::baseline(&r, &p, &w, data).is_some()
        {
            return;
        }
        let protect_level =
            untrusted_server && p.known_unsigned() && (p.motw || p.just_dropped) && w.suspicious();
        let severity = if scriptlet || lolbin.is_some() || protect_level {
            Severity::High
        } else if treat_as && !w.suspicious() {
            Severity::Low
        } else if p.just_dropped || p.motw || w.suspicious() {
            Severity::High
        } else {
            Severity::Medium
        };
        let actions = if protect_level {
            self.actions(PS11, ctx, &loc, &p, &w, false)
        } else {
            vec![]
        };
        let summary = format!(
            "{} registered {} pointing at {}{} — per-user COM entries override the machine-wide ones, so programs that load this object run it{}",
            w.describe(),
            loc.what,
            if treat_as {
                data.trim().to_string()
            } else {
                p.describe()
            },
            match &lolbin {
                Some(l) => format!(" via {l}"),
                None => String::new(),
            },
            if protect_level { "." } else { " (alert only)." }
        );
        let mut h = FamilyHit::new(PS11, &e.guid, severity, summary).with_actions(actions);
        h.dedup_key = Some(loc.dedup(PS11));
        out.push(h);
    }

    fn on_process_start(&mut self, e: &Event, ps: &ProcessStart, out: &mut Vec<FamilyHit>) {
        if file_name_lower(&ps.image) == "wmic.exe" {
            self.ps08_tooling(e, &ps.cmdline, "wmic.exe", out);
        }
    }
}

impl Family for Persistence {
    fn on_event(&mut self, ctx: &Ctx, e: &Event, out: &mut Vec<FamilyHit>) {
        self.prune(ctx.now);
        let start = out.len();
        match &e.data {
            EventData::FileAccess { path, op } => self.on_file(ctx, e, path, *op, out),
            EventData::RegistrySet {
                key,
                value_name,
                data,
                op,
                ..
            } => {
                if *op == RegistryOp::Set {
                    self.on_registry(ctx, e, key, value_name, data.as_deref().unwrap_or(""), out);
                }
            }
            EventData::TaskRegistered(t) => self.on_task(ctx, e, t, out),
            EventData::ServiceInstalled(s) => self.ps07(
                ctx,
                e,
                &s.name,
                &s.image_path,
                s.start_type,
                s.service_type,
                out,
            ),
            EventData::WmiSubscription(b) => self.ps08(ctx, e, b, out),
            EventData::ProcessStart(ps) => self.on_process_start(e, ps, out),
            EventData::ScriptBlock { content, .. } => {
                self.ps08_tooling(e, content, "A PowerShell script", out)
            }
            _ => {}
        }
        // V-H5/H6/H7: a guessed or unknown writer is never acted on; the
        // persistence object itself is still removed.
        if super::carries_attribution(e) {
            let attr = ctx.attribution(e);
            for h in out[start..].iter_mut() {
                h.apply_attribution(attr, e.ts);
            }
        }
        self.flush_late(ctx, start, out);
    }

    fn tick(&mut self, ctx: &Ctx, _out: &mut Vec<FamilyHit>) {
        self.prune(ctx.now);
    }

    fn on_alert(&mut self, ctx: &Ctx, alert: &Alert, out: &mut Vec<FamilyHit>) {
        let rule = alert.rule_id.as_str();
        if rule == PS15 {
            return;
        }
        let subj = &alert.process;
        if !rule.starts_with("PS-") {
            bounded_insert(&mut self.alerted, &subj.guid, ctx.now);
        }
        if alert.mode != RuleMode::Protect {
            return;
        }
        let kills = KILL_RULES.contains(&rule)
            || rule.starts_with("RW-")
            || rule.starts_with("CD-")
            || (rule.starts_with("PS-") && self.killing.contains_key(&subj.guid));
        if !kills || ctx.protected(subj) || ctx.system_trusted(subj) || ctx.is_agent(subj) {
            return;
        }
        // The killed tree: subject, its descendants, and untrusted ancestors
        // up to the first trusted one (the loader that dropped it).
        let mut tree = vec![subj.guid.clone()];
        tree.extend(
            ctx.table()
                .descendants(&subj.guid)
                .into_iter()
                .map(|p| p.guid),
        );
        // V-L15: never an interactive shell the user typed in (an
        // Explorer- or terminal-launched cmd / PowerShell / terminal): its
        // other autoruns are the user's own work.
        for a in ctx.ancestry(&subj.guid, 3) {
            if interactive_shell(ctx, &a) {
                break;
            }
            if ctx.untrusted_actor(&a) && !ctx.system_trusted(&a) && !ctx.protected(&a) {
                tree.push(a.guid);
            } else {
                break;
            }
        }
        // In Audit the engine drops the actions: keep the records so a later
        // policy switch to Protect can still roll the tree back.
        let consume = ctx.protect(PS15);
        let mut recs = Vec::new();
        for g in &tree {
            if consume {
                // Bounded with oldest-first eviction (V-L15: never stop
                // recording once full).
                bounded_insert(&mut self.rolled, g, ctx.now);
            }
            let v = if consume {
                self.created.remove(g)
            } else {
                self.created.get(g).cloned()
            };
            if let Some(v) = v {
                recs.extend(v);
            }
        }
        if recs.is_empty() {
            return;
        }
        let trigger = format!("{} ({})", alert.rule_name, rule);
        out.push(Self::rollback_hit(
            &subj.guid,
            Some(subj.clone()),
            &trigger,
            recs,
            Some(format!("{PS15}:{}", alert.id)),
        ));
    }

    fn forget(&mut self, guid: &ProcessGuid) {
        self.created.remove(guid);
        self.alerted.remove(guid);
        self.killing.remove(guid);
    }
}

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

const MITRE_RUN: &str = "https://attack.mitre.org/techniques/T1547/001/";
const MITRE_TASK: &str = "https://attack.mitre.org/techniques/T1053/005/";
const MITRE_SVC: &str = "https://attack.mitre.org/techniques/T1543/003/";
const MITRE_WMI: &str = "https://attack.mitre.org/techniques/T1546/003/";
const MITRE_IFEO: &str = "https://attack.mitre.org/techniques/T1546/012/";
const MITRE_WINLOGON: &str = "https://attack.mitre.org/techniques/T1547/004/";
const MITRE_COM: &str = "https://attack.mitre.org/techniques/T1546/015/";
const ELASTIC_RUN: &str =
    "https://www.elastic.co/guide/en/security/current/startup-or-run-key-registry-modification.html";
const SIGMA_ASEP: &str = "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml";
const PICUS_2026: &str =
    "https://www.picussecurity.com/resource/press-release/red-report-2026-rise-of-digital-parasite";
const RELIAQUEST_CLICKFIX: &str =
    "https://www.reliaquest.com/blog/threat-spotlight-clickfix-evolves-with-pysoxy-proxying/";
const ZSCALER_HIJACK: &str =
    "https://www.zscaler.com/blogs/security-research/analyzing-new-hijackloader-evasion-tactics";
const MS_TARRASK: &str = "https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/";
const SIGMA_WMI: &str = "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/wmi/win_wmi_persistence.yml";
const CYBERTRIAGE_WMI: &str = "https://cybertriage.com/?p=27530";
const SPECTEROPS_COM: &str = "https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/";

pub(crate) fn catalog() -> Vec<RuleMeta> {
    use RuleCategory::Persistence as P;
    use Severity::*;
    vec![
        meta(PS01, "Run key to untrusted payload",
            "A Run-family registry value (Run, RunOnce, RunOnceEx, RunServices, policy Run, Windows Load/Run) was set to a program in a user-writable folder that is not validly signed and not a known per-user application. Severity is raised when the payload carries Mark-of-the-Web, was created in the last 10 minutes, or the writer is untrusted or already alerted.",
            P, Medium, &["T1547.001"], false,
            "Remove the value (backed up), quarantine the payload, kill the payload if running and the writer's tree — only when the payload is known unsigned, was just dropped or downloaded, and the writer is untrusted",
            &[MITRE_RUN, ELASTIC_RUN, SIGMA_ASEP, PICUS_2026],
            &["Per-user apps (OneDrive, Teams, Discord, Spotify, Zoom, Squirrel updaters) — suppressed by the built-in baseline", "Developer tools or unsigned in-house utilities started from Documents", "Portable applications"]),
        meta(PS02, "Autorun via script host or LOLBin",
            "An autostart entry (Run key, Startup folder, scheduled task, service, WMI consumer, IFEO) resolves to a script host or LOLBin chain with tradecraft: PowerShell with an encoded command, hidden window, download cradle or Invoke-Expression; mshta with a URL or vbscript:/javascript:; rundll32/regsvr32 on a user-folder DLL, a URL or script code; wscript/cscript on a user-folder script; conhost --headless; AutoIt/Python/Node on a user-folder script; download tools. Domain logon scripts on SYSVOL/NETLOGON are excluded.",
            P, High, &["T1547.001", "T1053.005", "T1059.001", "T1059.005", "T1218.005", "T1218.010", "T1218.011"], true,
            "Remove the autostart entry (backed up), quarantine the user-folder script/DLL and kill the writer's tree when it is untrusted; alert only when a validly signed management tool wrote it",
            &[MITRE_RUN, RELIAQUEST_CLICKFIX, ZSCALER_HIJACK, SIGMA_ASEP],
            &["RMM / management agents that schedule PowerShell (signed writer → alert only)", "Enterprise logon scripts outside SYSVOL/NETLOGON"]),
        meta(PS03, "Startup-folder drop",
            "A script, program or shortcut was created in a user or the common Startup folder by a process other than Explorer (user drag-and-drop) or a validly signed installer. Scripts and programs written by an untrusted or already-alerted process are high severity; shortcuts are alert-only until LNK targets are resolved.",
            P, Medium, &["T1547.001", "T1547.009"], true,
            "Move the file to the quarantine vault and kill the writer's tree (scripts/programs from an untrusted writer only)",
            &[MITRE_RUN, "https://attack.mitre.org/techniques/T1547/009/", PICUS_2026],
            &["Applications that add their own shortcut to Startup from an unsigned helper", "Users copying scripts into Startup with a script host"]),
        meta(PS04, "Startup folder redirection",
            "The Startup or Common Startup location under User Shell Folders / Shell Folders was changed to a non-default path. Group Policy folder redirection (written by Windows components) is ignored.",
            P, High, &["T1547.001"], false,
            "Restore the default User Shell Folders value and kill an untrusted writer's tree",
            &[MITRE_RUN, SIGMA_ASEP],
            &["Folder Redirection or roaming-profile tools not running as Windows components"]),
        meta(PS05, "Scheduled task with untrusted action",
            "A scheduled task was created or updated whose action runs a program in a user-writable folder that is not validly signed and not a known per-user updater, or a hidden task with a logon/boot trigger outside the Microsoft folder runs an untrusted program. Script-host/LOLBin actions are reported as PS-02.",
            P, Medium, &["T1053.005"], false,
            "Export and delete the task, quarantine the payload and kill the creator's tree — only when the payload is known unsigned, was just dropped or downloaded, and the creator is untrusted or already alerted",
            &[MITRE_TASK, MS_TARRASK, ZSCALER_HIJACK],
            &["Per-user updater tasks (GoogleUpdater, Edge, OneDrive, Zoom) — suppressed by the baseline", "Admin or developer scripts scheduled from a user folder"]),
        meta(PS07, "Suspicious service install",
            "A service was installed (or its ImagePath written by something other than the Service Control Manager) whose binary lives in a user profile or Temp folder, that wraps cmd/PowerShell/mshta/rundll32/script hosts, that is a driver in a user-writable folder, or (alert only) that is unsigned or in ProgramData. Kestrel's own service is never targeted.",
            P, High, &["T1543.003", "T1569.002"], true,
            "Export the configuration, stop and disable the service, quarantine the binary and kill an untrusted creator's tree (user/Temp paths and interpreter wrappers only)",
            &[MITRE_SVC, "https://attack.mitre.org/techniques/T1569/002/"],
            &["PsExec (PSEXESVC in %WINDIR%, not flagged)", "RMM agents, game anti-cheat and OEM utilities under ProgramData (alert only)"]),
        meta(PS08, "WMI permanent event subscription",
            "A permanent WMI event subscription was bound to a CommandLineEventConsumer or ActiveScriptEventConsumer (other consumer types are alert-only), or wmic / a PowerShell script created such a consumer. The built-in SCM Event Log consumer is ignored.",
            P, Critical, &["T1546.003"], true,
            "Export the subscription (MOF), delete the binding, consumer and filter, quarantine a user-folder payload and kill an untrusted creator's tree",
            &[MITRE_WMI, SIGMA_WMI, CYBERTRIAGE_WMI],
            &["OEM management agents (HP, Dell) and SCCM that use command-line consumers — add a per-tenant exclusion"]),
        meta(PS09, "IFEO / SilentProcessExit hijack",
            "An Image File Execution Options Debugger value or a SilentProcessExit MonitorProcess was set, so starting (or exiting) a program runs another one. Accessibility binaries (sethc, utilman, osk, …), security tools and browsers are high value; user-folder, unsigned or script-host debuggers are acted on. LSASS targets belong to CD-07.",
            P, High, &["T1546.012", "T1546.008"], true,
            "Delete the value (backed up), quarantine a user-folder debugger and kill an untrusted writer's tree",
            &[MITRE_IFEO, "https://attack.mitre.org/techniques/T1546/008/"],
            &["Process Explorer replacing Task Manager (signed, not flagged)", "Visual Studio JIT debugging", "Application-control tools that block programs through IFEO"]),
        meta(PS10, "Winlogon / AppInit / AppCert / BootExecute change",
            "Winlogon Userinit or Shell (HKLM or HKCU, or the policy Shell) differs from the Windows default, BootExecute contains an entry other than autocheck autochk, or a DLL was added to AppInit_DLLs / AppCertDlls (alert only). Defaults: Userinit = <drive>:\\Windows\\system32\\userinit.exe, Shell = explorer.exe, BootExecute = autocheck autochk * [verify on a clean VM].",
            P, Critical, &["T1547.004", "T1546.010", "T1546.009", "T1547.001"], true,
            "Restore the Windows default (Userinit, Shell, BootExecute) or delete the HKCU override, and kill an untrusted writer's tree; AppInit/AppCert alert only",
            &[MITRE_WINLOGON, "https://attack.mitre.org/techniques/T1546/010/", "https://attack.mitre.org/techniques/T1546/009/"],
            &["Kiosk / Shell Launcher shells and Citrix/VDI Userinit additions (exclude via policy)", "Security products using AppInit_DLLs", "Disk tools adding BootExecute entries"]),
        meta(PS11, "COM hijack in user hive",
            "A per-user COM registration (HKCU\\Software\\Classes\\CLSID\\{…}\\InprocServer32/LocalServer32/TreatAs or ScriptletURL) points at a server in a user-writable folder that is not validly signed, at a LOLBin chain or at a scriptlet URL. Per-user entries override machine-wide ones. Whether the CLSID also exists in HKLM is not checked yet.",
            P, Medium, &["T1546.015"], false,
            "Delete the per-user COM value (backed up), quarantine the DLL and kill an untrusted writer's tree — only for a known-unsigned, just-dropped or downloaded server written by an untrusted process",
            &[MITRE_COM, SPECTEROPS_COM],
            &["OneDrive, Dropbox, Google Drive and Teams per-user shell extensions (signed / baseline)", "Developer COM registrations (regsvr32 /n /i:user)"]),
        meta(PS15, "Persistence rollback",
            "Kestrel remembers the autostart entries each process creates. When a Protect-mode detection that kills a process tree fires (e.g. ST-02, ST-04, ST-16, RW/CD rules, or a PS rule that killed the writer), every autostart entry created by that tree is removed, even if the PS rule alone only alerted. Entries the tree creates afterwards are removed as they appear.",
            P, High, &["T1547", "T1053"], true,
            "Remove every autostart entry the stopped tree created (backed up) and quarantine their user-folder payloads",
            &[MITRE_RUN, MITRE_TASK],
            &["Attribution of tasks/services/WMI subscriptions depends on the sensor; unattributed entries are never rolled back"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rolled_set_evicts_oldest_instead_of_filling_up_v_l15() {
        let mut m: HashMap<ProcessGuid, TimestampMs> = HashMap::new();
        for i in 0..(MAX_GUIDS as i64 + 50) {
            bounded_insert(&mut m, &ProcessGuid(format!("g{i}")), i);
        }
        assert_eq!(m.len(), MAX_GUIDS);
        let last = ProcessGuid(format!("g{}", MAX_GUIDS + 49));
        assert!(m.contains_key(&last), "late entries are still recorded");
        assert!(!m.contains_key(&ProcessGuid("g0".into())));
    }

    #[test]
    fn key_normalisation() {
        let (h, r) =
            split_key(r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run")
                .unwrap();
        assert_eq!(h, Hive::User);
        assert!(is_run_family(&r, ""));
        let (h, r) =
            split_key(r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{X}\InprocServer32").unwrap();
        assert_eq!(h, Hive::User);
        assert_eq!(r, r"software\classes\clsid\{x}\inprocserver32");
        let (h, r) = split_key(
            r"HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        )
        .unwrap();
        assert_eq!(h, Hive::Machine);
        assert!(is_run_family(&r, ""));
        let (_, r) = split_key(r"HKLM\SYSTEM\ControlSet001\Services\Evil").unwrap();
        assert_eq!(r, r"system\currentcontrolset\services\evil");
        let (_, r) =
            split_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnceEx\0001").unwrap();
        assert!(is_run_family(&r, ""));
        let (_, r) =
            split_key(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU").unwrap();
        assert!(!is_run_family(&r, ""));
        assert!(split_key(r"Software\x").is_none());
        let (_, r) =
            split_key(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows").unwrap();
        assert!(is_run_family(&r, "load") && !is_run_family(&r, "appinit_dlls"));
    }

    #[test]
    fn numbers() {
        assert_eq!(parse_number("512"), Some(512));
        assert_eq!(parse_number("0x200"), Some(0x200));
        assert_eq!(parse_number("dword:0x00000200"), Some(0x200));
        assert_eq!(parse_number("x"), None);
    }

    #[test]
    fn catalog_complete() {
        let c = catalog();
        assert_eq!(c.len(), 11);
        for m in &c {
            assert_eq!(m.category, RuleCategory::Persistence);
            assert!(
                !m.attack.is_empty() && !m.references.is_empty() && !m.false_positives.is_empty(),
                "{}",
                m.id
            );
        }
    }
}
