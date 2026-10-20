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
    Alert, Event, PathClass, ProcessGuid, ProcessInfo, ResponseAction, RuleMeta, RuleMode,
    Severity, SignatureState, TimestampMs,
};

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
        }
    }

    pub fn with_actions(mut self, actions: Vec<ResponseAction>) -> Self {
        self.actions = actions;
        self
    }
}

/// Read-only view of the engine for families.
pub(crate) struct Ctx<'a> {
    pub(crate) st: &'a EngineState,
    /// Engine time (event ts, or tick time).
    pub now: TimestampMs,
}

impl<'a> Ctx<'a> {
    pub fn table(&self) -> &ProcessTable {
        self.st.table()
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

    /// The live lsass.exe (System32 path on the system volume), if known.
    pub fn lsass(&self) -> Option<&ProcessInfo> {
        self.st.table().iter().find(|p| {
            p.exit_ts.is_none()
                && kestrel_common::file_name_lower(&p.image) == "lsass.exe"
                && self.path_class(&p.image) == PathClass::System
        })
    }

    /// Valid signature (any trusted publisher).
    pub fn validly_signed(p: &ProcessInfo) -> bool {
        p.signed == SignatureState::Valid
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
