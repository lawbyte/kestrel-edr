//! Rule families beyond the stealer core: RW-xx (ransomware), CD-xx
//! (credential dumping) and PS-xx (persistence).
//!
//! Each family is a small state machine behind [`Family`]. The engine feeds it
//! every event (after its own ST/TP handlers), calls [`Family::tick`] on every
//! engine tick and [`Family::on_alert`] for every alert any rule emitted. A
//! family returns [`FamilyHit`]s; the engine turns them into alerts through the
//! one shared emission path (policy mode, agent self-suppression, allow IOCs,
//! exclusions, 10-minute de-duplication, protected-process and server-IP action
//! filters). Families never execute anything themselves, and Protect-mode
//! actions they propose are dropped in Audit mode.
//!
//! Families read the engine only through [`Ctx`], so they can be built and
//! unit-tested without touching `engine.rs`.

use crate::engine::EngineState;
use crate::table::ProcessTable;
use kestrel_common::{
    Alert, Attribution, Event, EventData, PathClass, ProcessGuid, ProcessInfo, ResponseAction,
    RuleMeta, RuleMode, Severity, SignatureState, TimestampMs,
};

pub(crate) mod autorun;
pub(crate) mod cd;
pub(crate) mod ps;
pub(crate) mod rw;

/// One family rule hit, before mode / exclusion / de-dup handling.
#[derive(Debug, Clone)]
pub(crate) struct FamilyHit {
    /// Rule id (`RW-01`, …). Must exist in the family's catalog.
    pub rule: &'static str,
    /// Subject process (the alert's `process`).
    pub guid: ProcessGuid,
    pub severity: Severity,
    /// One plain-language sentence for the employee and the analyst.
    pub summary: String,
    /// Protect-mode actions (dropped in Audit mode; protected processes,
    /// the agent and server IPs are filtered by the engine).
    pub actions: Vec<ResponseAction>,
    /// Open a suspend-on-suspicion window for the subject (Protect only).
    pub suspend: bool,
    /// With `suspend`: kill instead of resume when the window expires.
    pub kill_at_expiry: bool,
    /// Escalates open suspend windows of the subject / parent / children to kills.
    pub strong: bool,
    /// Extra evidence events (other processes, earlier events).
    pub extra_evidence: Vec<Event>,
    /// De-dup key when it differs from the rule id (e.g. one alert per autorun location).
    pub dedup_key: Option<String>,
    /// Subject override when it is not (or no longer) in the process table.
    pub process: Option<ProcessInfo>,
    /// This variant of the rule only ever alerts: it runs as Audit even when
    /// the rule is in Protect (e.g. RW-08's name-agnostic fallback). `Off`
    /// still silences it.
    pub audit_only: bool,
    /// Only `RemoveAutorun` actions survive (no kill / suspend / quarantine):
    /// the actor is a guess or unknown (V-H5/H6/H7). With the synthetic
    /// [`crate::engine::unknown_subject`] as `process` this is also the only
    /// way an unattributed (pid 0) change can be emitted.
    pub remediation_only: bool,
}

impl FamilyHit {
    pub fn new(
        rule: &'static str,
        guid: &ProcessGuid,
        severity: Severity,
        summary: String,
    ) -> Self {
        FamilyHit {
            rule,
            guid: guid.clone(),
            severity,
            summary,
            actions: vec![],
            suspend: false,
            kill_at_expiry: false,
            strong: false,
            extra_evidence: vec![],
            dedup_key: None,
            process: None,
            audit_only: false,
            remediation_only: false,
        }
    }

    pub fn with_actions(mut self, actions: Vec<ResponseAction>) -> Self {
        self.actions = actions;
        self
    }

    /// Apply the actor attribution of the triggering event (V-H5/H6/H7):
    /// `Exact` changes nothing; `Heuristic` keeps the guessed actor as the
    /// subject but strips every action against processes and files (only
    /// `RemoveAutorun` of the object stays); `None` also swaps the subject
    /// for the synthetic unknown writer so the engine can emit it.
    pub fn apply_attribution(&mut self, attr: Attribution, ts: TimestampMs) {
        match attr {
            Attribution::Exact => {}
            Attribution::Heuristic => {
                self.remediation_only = true;
                self.strip_to_remediation();
                self.summary.push_str(
                    " (The writer was inferred by correlation, so no action is taken against it.)",
                );
            }
            Attribution::None => {
                self.remediation_only = true;
                self.strip_to_remediation();
                let p = crate::engine::unknown_subject(ts);
                self.guid = p.guid.clone();
                self.process = Some(p);
                self.summary.push_str(
                    " (The change could not be attributed to a process; only the entry itself is remediated.)",
                );
            }
        }
    }

    fn strip_to_remediation(&mut self) {
        self.actions
            .retain(|a| matches!(a, ResponseAction::RemoveAutorun { .. }));
        self.suspend = false;
        self.kill_at_expiry = false;
        self.strong = false;
    }
}

/// Events whose actor may be inferred or unknown (registry, task, service
/// and WMI changes).
pub(crate) fn carries_attribution(e: &Event) -> bool {
    matches!(
        e.data,
        EventData::RegistrySet { .. }
            | EventData::TaskRegistered(_)
            | EventData::ServiceInstalled(_)
            | EventData::WmiSubscription(_)
    )
}

/// Attribution of an event's actor (`pid`/`guid`). Events without an
/// attribution field are kernel-attributed (`Exact`), except pid 0.
pub(crate) fn attribution_of(e: &Event) -> Attribution {
    let a = match &e.data {
        EventData::RegistrySet { attribution, .. } => *attribution,
        EventData::TaskRegistered(t) => t.attribution,
        EventData::ServiceInstalled(s) => s.attribution,
        EventData::WmiSubscription(w) => w.attribution,
        _ => Attribution::Exact,
    };
    if e.pid == 0 {
        Attribution::None
    } else {
        a
    }
}

/// Read-only view of the engine for families.
#[allow(dead_code)] // helpers are part of the seam even when no family uses them yet
pub(crate) struct Ctx<'a> {
    pub(crate) st: &'a EngineState,
    /// Engine time (event ts, or tick time).
    pub now: TimestampMs,
}

#[allow(dead_code)]
impl<'a> Ctx<'a> {
    pub fn table(&self) -> &ProcessTable {
        self.st.table()
    }

    /// Effective actor attribution of `e`: [`attribution_of`], except that a
    /// correlation guess landing on the agent (or one of its recorded
    /// children) means "unknown" — the agent never writes autoruns, and such
    /// a guess must neither hide the change (V-H6) nor make it look exempt.
    pub fn attribution(&self, e: &Event) -> Attribution {
        let a = attribution_of(e);
        if a == Attribution::Heuristic && self.process(&e.guid).is_some_and(|p| self.is_agent(p)) {
            Attribution::None
        } else {
            a
        }
    }

    pub fn process(&self, guid: &ProcessGuid) -> Option<&ProcessInfo> {
        self.st.table().get(guid)
    }

    /// Parent chain, nearest first (bounded depth).
    pub fn ancestry(&self, guid: &ProcessGuid, depth: usize) -> Vec<ProcessInfo> {
        self.st.table().ancestry(guid, depth)
    }

    /// Effective mode of a rule under the current policy.
    pub fn mode(&self, rule: &str) -> RuleMode {
        self.st.rule_mode(rule)
    }

    pub fn protect(&self, rule: &str) -> bool {
        self.mode(rule) == RuleMode::Protect
    }

    /// Never act on these: PID 0/4, the agent, critical OS processes and
    /// Microsoft security products at their exact location with a valid
    /// Microsoft signature (shared list in [`crate::protect`]).
    pub fn protected(&self, p: &ProcessInfo) -> bool {
        self.st.is_protected(p)
    }

    /// The Kestrel agent itself (never a subject).
    pub fn is_agent(&self, p: &ProcessInfo) -> bool {
        self.st.is_agent_process(p)
    }

    /// Windows binary in System/Windows on the system volume with a valid
    /// Microsoft signature, and not a LOLBin / script host.
    pub fn system_trusted(&self, p: &ProcessInfo) -> bool {
        EngineState::system_trusted(p)
    }

    /// Unsigned / invalid / unknown signature, Temp/Downloads/external,
    /// user-writable without a valid signature, or a LOLBin / script host.
    pub fn untrusted_actor(&self, p: &ProcessInfo) -> bool {
        EngineState::untrusted_actor(p)
    }

    /// LOLBin / script host by lower-case file name (`powershell.exe`, `mshta.exe`, …).
    pub fn is_lolbin(&self, file_name_lower: &str) -> bool {
        crate::engine::is_lolbin(file_name_lower)
    }

    /// Path class with the engine's system drive.
    pub fn path_class(&self, path: &str) -> PathClass {
        PathClass::of_with_system_drive(path, self.st.system_drive())
    }

    pub fn system_drive(&self) -> char {
        self.st.system_drive()
    }

    /// The live genuine lsass.exe: System32 on the system volume *and*
    /// started by System32 wininit.exe (V-L1). Cached by the engine, so this
    /// is a single lookup per event (V-L14).
    pub fn lsass(&self) -> Option<&ProcessInfo> {
        let g = self.st.lsass_guid()?;
        self.process(g).filter(|p| p.exit_ts.is_none())
    }

    /// May the engine propose quarantining `path` when the path itself came
    /// from attacker-controlled text (a command-line argument, registry data)
    /// rather than from a kernel-observed write by the subject? See
    /// [`attacker_named_quarantinable`].
    pub fn attacker_path_ok(&self, path: &str, subject_user: Option<&str>) -> bool {
        attacker_named_quarantinable(path, subject_user)
    }

    /// Valid signature (any trusted publisher).
    pub fn validly_signed(p: &ProcessInfo) -> bool {
        p.signed == SignatureState::Valid
    }
}

/// V-H4: engine-origin quarantine of a path named in attacker-controlled text
/// (CD-01 dump path, CD-10 `reg save` output, PS-02 / PS-10 payloads, …).
/// Allowed only inside the subject user's own profile (`C:\Users\<name>\…`,
/// also `<name>.<DOMAIN>`), which includes the user's own `%TEMP%`. Never
/// under `\Windows\` (System32\Tasks and Windows\Temp included — other
/// accounts' files live there), `\ProgramData\` (Microsoft\Crypto keys,
/// other products' data), shared roots such as `C:\Temp`, another user's
/// profile, a UNC / device path, or a path with `.` / `..` / stream / wildcard
/// components. Unknown or service user → nothing is "own". The agent's own
/// quarantine policy re-checks the file before acting.
pub(crate) fn attacker_named_quarantinable(path: &str, subject_user: Option<&str>) -> bool {
    let p = path.trim().trim_matches('"');
    if p.is_empty() {
        return false;
    }
    let n = crate::paths::normalize_path(p);
    let b = n.as_bytes();
    // Drive-letter absolute paths only.
    if !(b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\') {
        return false;
    }
    let dl = &n[2..];
    let odd_component = dl
        .split('\\')
        .skip(1)
        .any(|c| c.is_empty() || c == "." || c == ".." || c.ends_with(' ') || c.ends_with('.'));
    if odd_component || dl.contains([':', '*', '?', '~']) {
        return false;
    }
    let Some(rest) = dl.strip_prefix(r"\users\") else {
        return false;
    };
    let Some((profile, tail)) = rest.split_once('\\') else {
        return false;
    };
    !tail.is_empty() && own_profile(profile, subject_user)
}

/// Is `profile` (lower-case folder name under `\Users\`) the profile of
/// `user` (`DOMAIN\name`, `name@domain` or `name`)?
fn own_profile(profile: &str, user: Option<&str>) -> bool {
    let Some(u) = user.map(str::trim).filter(|u| !u.is_empty()) else {
        return false;
    };
    let u = u.to_ascii_lowercase();
    let (domain, name) = match u.rsplit_once('\\') {
        Some((d, n)) => (Some(d.to_string()), n.to_string()),
        None => match u.split_once('@') {
            Some((n, d)) => (
                Some(d.split('.').next().unwrap_or(d).to_string()),
                n.to_string(),
            ),
            None => (None, u.clone()),
        },
    };
    if name.is_empty()
        || matches!(
            name.as_str(),
            "system" | "local service" | "network service" | "public" | "default" | "all users"
        )
        || name.starts_with("s-1-")
    {
        return false;
    }
    if profile == name {
        return true;
    }
    // `alice.CORP` / `alice.CORP.000` style profile folders.
    match (
        profile
            .strip_prefix(name.as_str())
            .and_then(|r| r.strip_prefix('.')),
        domain,
    ) {
        (Some(rest), Some(d)) if !d.is_empty() => {
            let first = rest.split('.').next().unwrap_or("");
            first == d
                && rest[first.len()..]
                    .trim_start_matches('.')
                    .bytes()
                    .all(|c| c.is_ascii_digit())
        }
        _ => false,
    }
}

/// A rule family.
pub(crate) trait Family: Send {
    /// Every event, after the engine's own handlers.
    fn on_event(&mut self, ctx: &Ctx, e: &Event, out: &mut Vec<FamilyHit>);
    /// Every engine tick (~250 ms).
    fn tick(&mut self, _ctx: &Ctx, _out: &mut Vec<FamilyHit>) {}
    /// Every alert emitted by any rule (including other families), with the
    /// mode it ran in. Hits returned here are emitted but do not re-enter
    /// `on_alert` (no cascades).
    fn on_alert(&mut self, _ctx: &Ctx, _alert: &Alert, _out: &mut Vec<FamilyHit>) {}
    /// Drop state for processes the table evicted.
    fn forget(&mut self, _guid: &ProcessGuid) {}
}

pub(crate) fn all() -> Vec<Box<dyn Family>> {
    vec![
        Box::new(rw::Ransomware::default()),
        Box::new(cd::CredDump::default()),
        Box::new(ps::Persistence::default()),
    ]
}

/// Catalog entries of every family rule (`Engine::catalog()` includes them).
pub(crate) fn catalog() -> Vec<RuleMeta> {
    let mut v = rw::catalog();
    v.extend(cd::catalog());
    v.extend(ps::catalog());
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attacker_named_paths_v_h4() {
        let alice = Some(r"CORP\alice");
        let ok = |p: &str, u: Option<&str>| attacker_named_quarantinable(p, u);
        assert!(ok(r"C:\Users\alice\AppData\Local\Temp\l.dmp", alice));
        assert!(ok(r"c:/users/ALICE/Documents/x.exe", alice));
        assert!(ok(r"C:\Users\alice.CORP\Desktop\x.js", alice));
        assert!(ok(r"C:\Users\alice.CORP.001\Desktop\x.js", alice));
        assert!(ok(r"C:\Users\alice\x.exe", Some("alice@corp.example")));
        // other users, shared and system locations
        assert!(!ok(r"C:\Users\bob\Documents\thesis.docx", alice));
        assert!(!ok(r"C:\Users\alice.EVIL\x.exe", alice));
        assert!(!ok(r"C:\Users\Public\sam.save", alice));
        assert!(!ok(
            r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\k",
            alice
        ));
        assert!(!ok(r"C:\ProgramData\Vendor\cfg.xml", alice));
        assert!(!ok(r"C:\Windows\System32\Tasks\Microsoft\Windows\X", alice));
        assert!(!ok(r"C:\Windows\Temp\x.tmp", alice));
        assert!(!ok(r"C:\Temp\x.tmp", alice));
        // traversal, streams, wildcards, UNC / device paths
        assert!(!ok(r"C:\Users\alice\..\bob\x.docx", alice));
        assert!(!ok(r"C:\Users\alice\.\..\bob\x", alice));
        assert!(!ok(r"C:\Users\alice\x.docx:stream", alice));
        assert!(!ok(r"C:\Users\alice\*.docx", alice));
        assert!(!ok(r"C:\Users\alice\x.docx.", alice));
        assert!(!ok(r"\\server\share\Users\alice\x", alice));
        assert!(!ok(r"\Device\HarddiskVolume3\Users\alice\x", alice));
        assert!(!ok(r"C:\Users\alice", alice));
        // unknown / service users own nothing
        assert!(!ok(r"C:\Users\alice\x.exe", None));
        assert!(!ok(r"C:\Users\system\x.exe", Some(r"NT AUTHORITY\SYSTEM")));
        assert!(!ok(r"C:\Users\Public\x.exe", Some("Public")));
    }
}
