//! OS abstraction for the Kestrel agent.
//!
//! CONTRACT: `kestrel-agent` (portable core: transport, outbox, engine loop,
//! tray protocol) talks to the operating system only through [`Platform`].
//! `kestrel-win` provides `WindowsPlatform`; `kestrel-agent` ships a
//! `SimPlatform` (replays JSONL telemetry, logs actions) for Linux testing.

use kestrel_common::{
    tray::{TrayRequest, TrayResponse},
    wire::OsInfo,
    ActionOutcome, Event, Hardening, ProcessInfo, ResponseAction,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;

pub use detect::{CanarySpec, ProcessFacts};

/// Sensor configuration derived from policy + host context.
#[derive(Debug, Clone)]
pub struct SensorConfig {
    pub boot_id: String,
    /// Capture DNS-Client events.
    pub dns: bool,
    /// Capture PowerShell 4104 / AMSI script content.
    pub script_content: bool,
    /// Read the Sysmon operational channel if present.
    pub sysmon: bool,
    /// Agent's own PID (sensors drop self-generated events).
    pub self_pid: u32,
    /// Optional sensor groups from the policy (file activity, persistence, …).
    pub groups: kestrel_common::SensorSettings,
    /// Late enrichment sink: hash / signature facts for processes whose
    /// `ProcessStart` was emitted before they were known (first-run budget
    /// exceeded, or a background revocation check demoted the signature).
    /// The agent feeds them to `Engine::enrich_process`.
    pub enrich_tx: Option<mpsc::Sender<LateEnrichment>>,
}

/// Facts that arrived after a process's `ProcessStart` was emitted.
#[derive(Debug, Clone, PartialEq)]
pub struct LateEnrichment {
    pub guid: kestrel_common::ProcessGuid,
    pub pid: u32,
    pub facts: ProcessFacts,
}

/// Identity of a tray-pipe client, established by the transport (Windows:
/// `GetNamedPipeClientProcessId` → process token user + session). `None`
/// fields mean the identity could not be established; such clients only see
/// public items and cannot request reviews.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrayClient {
    /// Token user SID string (`S-1-5-21-…`).
    pub user_sid: Option<String>,
    /// `DOMAIN\user` account name of the token user.
    pub user: Option<String>,
    pub session_id: Option<u32>,
    pub pid: Option<u32>,
}

impl TrayClient {
    /// Owner keys this client matches (lower-case SID and account name).
    pub fn owner_keys(&self) -> Vec<String> {
        let mut v = Vec::new();
        for k in [&self.user_sid, &self.user].into_iter().flatten() {
            let k = k.trim().to_ascii_lowercase();
            if !k.is_empty() && !v.contains(&k) {
                v.push(k);
            }
        }
        v
    }

    pub fn is_identified(&self) -> bool {
        !self.owner_keys().is_empty()
    }
}

/// Who may see a pushed tray notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Audience {
    /// Machine-wide (isolation notices, IT commands).
    Public,
    /// Only the owner (lower-case SID or `DOMAIN\user`).
    Owner(String),
}

/// A push notification with its audience.
#[derive(Debug, Clone, PartialEq)]
pub struct TrayPush {
    pub audience: Audience,
    pub resp: TrayResponse,
}

impl TrayPush {
    pub fn visible_to(&self, c: &TrayClient) -> bool {
        match &self.audience {
            Audience::Public => true,
            Audience::Owner(o) => c.owner_keys().iter().any(|k| k == o),
        }
    }
}

/// Where a response action came from. The platform applies stricter safety
/// rules to engine-originated actions (e.g. quarantine only user-writable
/// locations) than to explicit commands from the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionOrigin {
    /// Automatic response by the local detection engine.
    Engine,
    /// A command an administrator issued from the console.
    ServerCommand,
    /// A local request (tray quick check, break-glass CLI).
    Local,
}

/// Counters reported in heartbeats.
#[derive(Debug, Clone, Default)]
pub struct SensorStats {
    pub etw_ok: bool,
    pub events_lost: u64,
    pub buffers_lost: u64,
    pub events_total: u64,
    pub sysmon_present: bool,
    pub dpapi_channel_enabled: bool,
    pub amsi_ok: bool,
}

/// Live sensors; dropping or calling `stop` ends all sessions.
pub trait SensorHandle: Send + Sync {
    fn stats(&self) -> SensorStats;
    fn stop(&self);
}

/// Handles tray requests (implemented by the agent core).
#[async_trait::async_trait]
pub trait TrayHandler: Send + Sync {
    /// Answer one request from `client` (identity established by the transport).
    async fn handle(&self, req: TrayRequest, client: &TrayClient) -> TrayResponse;
    /// Receiver of push notifications; transports forward only those
    /// [`TrayPush::visible_to`] the connection's client.
    fn subscribe(&self) -> tokio::sync::broadcast::Receiver<TrayPush>;
}

#[async_trait::async_trait]
pub trait Platform: Send + Sync {
    /// Host facts.
    fn os_info(&self) -> OsInfo;
    fn hostname(&self) -> String;
    /// Unique per boot (Windows: derived from boot time).
    fn boot_id(&self) -> String;
    /// Currently logged-on interactive user, if any.
    fn logged_on_user(&self) -> Option<String>;
    fn ip_addresses(&self) -> Vec<String>;
    /// Active AV product name (Security Center), if known.
    fn av_product(&self) -> Option<String>;
    /// Agent process CPU % and working set MB.
    fn self_usage(&self) -> (f32, u64);
    /// Directory for agent state (keys, outbox, quarantine).
    fn state_dir(&self) -> std::path::PathBuf;

    /// Snapshot of running processes at startup (enriched), to seed the engine.
    fn snapshot_processes(&self, boot_id: &str) -> Vec<ProcessInfo>;

    /// Start telemetry sensors; events are sent to `tx` (bounded channel —
    /// sensors must drop, not block, when full, and count drops in stats).
    fn start_sensors(
        &self,
        cfg: SensorConfig,
        tx: mpsc::Sender<Event>,
    ) -> anyhow::Result<Box<dyn SensorHandle>>;

    /// Execute a response action. Must never panic; failures go in the outcome.
    /// Equivalent to [`Platform::execute_as`] with [`ActionOrigin::Engine`]
    /// (the most restrictive safety rules).
    async fn execute(&self, action: &ResponseAction) -> ActionOutcome;

    /// Execute a response action on behalf of `origin`.
    async fn execute_as(&self, action: &ResponseAction, origin: ActionOrigin) -> ActionOutcome {
        let _ = origin;
        self.execute(action).await
    }

    /// System drive letter (from `%SystemRoot%`), for volume-aware path trust.
    fn system_drive(&self) -> char {
        'c'
    }

    /// When the current network isolation started (ms), if isolated.
    fn isolated_since(&self) -> Option<kestrel_common::TimestampMs> {
        None
    }

    /// Apply (Enforce) or check (Audit) hardening controls. Returns control id → in effect.
    async fn apply_hardening(&self, hardening: &Hardening) -> BTreeMap<String, bool>;

    /// Whether the host is currently network-isolated (WFP state).
    fn is_isolated(&self) -> bool;

    /// M10: lift the network blocks created for IOC hits
    /// (`BlockDestination.ioc_id`) whose IOC is not in `block_iocs` (the ids of
    /// the Block IOCs in the policy just applied). Blocks created by other
    /// rules or by analysts carry no IOC id and are never touched. Returns a
    /// description of each block removed. Default: nothing to lift.
    async fn reconcile_ioc_blocks(
        &self,
        block_iocs: &std::collections::BTreeSet<String>,
    ) -> Vec<String> {
        let _ = block_iocs;
        Vec::new()
    }

    /// User profile directories to plant canaries into.
    fn user_profiles(&self) -> Vec<String>;
    /// Plant (or refresh) canary files; returns paths successfully written.
    fn plant_canaries(&self, specs: &[CanarySpec]) -> Vec<String>;

    /// Serve the tray protocol (Windows: `\\.\pipe\kestrel-tray` with a
    /// restricted DACL; simulator: a Unix socket in the state dir). Runs until
    /// the process exits.
    async fn serve_tray(&self, handler: Arc<dyn TrayHandler>) -> anyhow::Result<()>;
}
