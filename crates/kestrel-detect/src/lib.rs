//! Kestrel detection engine (platform independent).
//!
//! CONTRACT — the agent and server compile against the items in this file.
//! Implementations may change; signatures below must not without updating
//! `docs/contracts.md` and both callers.
//!
//! Flow on the endpoint:
//! ```text
//! sensor → Event → Engine::process(&event) → Vec<Output>
//!                  Engine::tick(now)       → Vec<Output>   (every ~250 ms)
//! Output::Alert(Detection)  → agent executes detection.actions, records
//!                             outcomes into alert.actions, uploads alert
//! Output::Action(action)    → agent executes (e.g. resume after suspend window)
//! ```

use kestrel_common::{
    Alert, DataCategory, Event, Policy, ProcessGuid, ProcessInfo, ResponseAction, RuleBundle,
    RuleMeta, TimestampMs,
};

pub mod catalog;
pub mod paths;
pub mod protect;
pub mod table;

mod canary;
mod sigma;
mod util;

pub use canary::{decoy_profile_name, is_conditional_canary, DECOY_WALLET_EXTENSION};
pub use sigma::{validate_sigma, SigmaRuleInfo};
pub use table::ProcessTable;

#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    #[error("invalid rule {id}: {reason}")]
    InvalidRule { id: String, reason: String },
}

/// Engine output.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)] // contract type; boxing would change the public API
pub enum Output {
    /// A rule fired. `actions` are the response actions to execute now
    /// (empty when the rule is in Audit mode or the process is excluded from response).
    Alert(Detection),
    /// A standalone action not tied to a new alert (e.g. resume a process
    /// whose suspend window expired without a verdict).
    Action(ResponseAction),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Detection {
    /// Alert with `actions` empty; the agent fills in outcomes after executing.
    pub alert: Alert,
    pub actions: Vec<ResponseAction>,
}

/// Static facts about the host the engine needs.
#[derive(Debug, Clone, Default)]
pub struct HostContext {
    pub boot_id: String,
    pub hostname: String,
    /// Full path of the agent executable (never alert on / respond against it).
    pub agent_image: String,
    /// PID of the running agent process (`std::process::id()`); 0 = unknown
    /// (tests, simulation). When set, only the process with this pid *and*
    /// the agent image is the agent (V-H1): another process started from the
    /// same file (a user launching `kestrel-agent.exe`, possibly suspended
    /// and injected) is an ordinary process, and so are its children.
    pub agent_pid: u32,
    /// Kestrel server IPs (never blocked by isolation / destination blocks).
    pub server_ips: Vec<String>,
    /// System drive letter (from `%SystemRoot%`); `None` = `C`. Only images on
    /// this volume can be System / Windows / Program Files and protected.
    pub system_drive: Option<char>,
}

/// Hash / signature facts that became available after a process started
/// (first-run enrichment that missed its budget, or a revocation check).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcessFacts {
    pub sha256: Option<String>,
    pub signer: Option<String>,
    pub signed: kestrel_common::SignatureState,
}

/// A decoy file/folder the agent plants for ST-16.
#[derive(Debug, Clone, PartialEq)]
pub struct CanarySpec {
    pub path: String,
    pub category: DataCategory,
    /// File content to write (small, realistic-looking decoy).
    pub content: Vec<u8>,
    pub is_dir: bool,
}

pub struct Engine {
    inner: engine::EngineState,
}

impl Engine {
    pub fn new(
        host: HostContext,
        policy: Policy,
        bundle: RuleBundle,
    ) -> Result<Engine, DetectError> {
        Ok(Engine {
            inner: engine::EngineState::new(host, policy, bundle)?,
        })
    }

    /// Replace the active policy (rule modes, exclusions, IOCs, …).
    pub fn update_policy(&mut self, policy: Policy) {
        self.inner.update_policy(policy)
    }

    /// Replace custom (Sigma/YARA) rules. Builtin rules are always present.
    pub fn update_rules(&mut self, bundle: RuleBundle) -> Result<(), DetectError> {
        self.inner.update_rules(bundle)
    }

    /// Feed one event (in timestamp order per process).
    pub fn process(&mut self, event: &Event) -> Vec<Output> {
        self.inner.process(event)
    }

    /// Advance time: expire correlation state and resolve suspend windows.
    pub fn tick(&mut self, now: TimestampMs) -> Vec<Output> {
        self.inner.tick(now)
    }

    pub fn processes(&self) -> &ProcessTable {
        self.inner.table()
    }

    /// Seed the process table with processes running at agent start.
    pub fn seed_process(&mut self, info: ProcessInfo) {
        self.inner.seed_process(info)
    }

    /// Canary files to plant under a user profile directory (e.g. `C:\Users\alice`).
    pub fn canaries(&self, user_profile: &str) -> Vec<CanarySpec> {
        self.inner.canaries(user_profile)
    }

    /// Catalog of all builtin rules (shown in the console, seeded by the server).
    pub fn catalog() -> Vec<RuleMeta> {
        engine::catalog()
    }

    /// Lookup helper for agents: is this GUID currently tracked?
    pub fn process_info(&self, guid: &ProcessGuid) -> Option<&ProcessInfo> {
        self.inner.table().get(guid)
    }

    // ----- additions (not part of the original contract) -----

    /// Arm a decoy path for ST-16 after the agent planted it. Required for
    /// conditional decoys (`.aws\credentials`, see [`is_conditional_canary`]);
    /// the decoy Chrome profile is armed by [`Engine::canaries`] itself.
    pub fn arm_canary(&mut self, path: &str) {
        self.inner.arm_canary(path)
    }

    /// Disarm a decoy path (e.g. the agent skipped it because a real file exists there).
    pub fn disarm_canary(&mut self, path: &str) {
        self.inner.disarm_canary(path)
    }

    /// Currently armed decoy paths (normalised: lower-case, no drive letter).
    pub fn armed_canaries(&self) -> Vec<String> {
        self.inner.armed_canaries()
    }

    /// Late enrichment for a running (or recently exited) process: fills in
    /// a missing sha256, resolves an `Unknown` signature, or downgrades a
    /// `Valid` signature to `Invalid` (revoked certificate). When anything
    /// changed, hash / certificate IOCs, ST-12 and ST-08(b) are evaluated
    /// again and open suspend windows of the process are re-judged.
    /// `now` is the alert timestamp for anything that fires.
    pub fn enrich_process(
        &mut self,
        guid: &ProcessGuid,
        facts: ProcessFacts,
        now: TimestampMs,
    ) -> Vec<Output> {
        self.inner.enrich_process(guid, facts, now)
    }
}

mod engine;
mod families;
