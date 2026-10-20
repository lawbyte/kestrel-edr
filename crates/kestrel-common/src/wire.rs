//! Agent <-> server payloads.
//!
//! Transport is gRPC over mTLS (`proto/kestrel.proto`). Each envelope carries
//! one of these payloads serialised as JSON (zstd-compressed when the
//! envelope's `compressed` flag is set). Keeping payload types here, in Rust,
//! lets agent and server share one definition.

use crate::{
    alert::Alert,
    event::Event,
    policy::Policy,
    response::{ActionOutcome, ResponseAction},
    rules::RuleBundle,
    TimestampMs,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Agent → server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentPayload {
    /// First message on every stream.
    Hello(Hello),
    Heartbeat(Heartbeat),
    Events {
        events: Vec<Event>,
    },
    Alert(Box<Alert>),
    ActionResult {
        command_id: Uuid,
        outcome: ActionOutcome,
    },
    /// Employee asked IT to review a block (from the tray app).
    ReviewRequest(ReviewRequest),
    Inventory(Inventory),
    /// Acknowledge a server message by seq.
    Ack {
        seq: u64,
    },
    /// Certificate renewal over the existing mTLS stream. Sent when the
    /// client certificate has < 30 days left, or when the server asks via
    /// `ServerPayload::RenewCertificate`. The server signs with CN = the
    /// stream's authenticated device id (never a CN from the CSR).
    RenewCertificate {
        csr_pem: String,
    },
}

/// Server → agent.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerPayload {
    Welcome {
        device_id: Uuid,
        server_time: TimestampMs,
    },
    Policy(Box<Policy>),
    Rules(RuleBundle),
    Command {
        command_id: Uuid,
        action: ResponseAction,
    },
    /// Update the agent; the agent verifies `signature` (Ed25519 over
    /// `kestrel-update-v1\n{version}\n{url}\n{sha256}`) before installing.
    Update(UpdateManifest),
    /// Server acknowledges agent messages up to and including `seq` (outbox can drop them).
    Ack {
        seq: u64,
    },
    ReviewDecision {
        alert_id: Uuid,
        approved: bool,
        message: String,
    },
    /// Server asks the agent to renew now (e.g. CA rotation, revocation planned).
    RenewCertificate,
    /// New client certificate in reply to `AgentPayload::RenewCertificate`.
    /// The agent swaps it in atomically and reconnects; the old serial is
    /// revoked by the server once the agent connects with the new one.
    Certificate {
        cert_pem: String,
        ca_pem: String,
    },
    /// New per-device uninstall token (rotated by an admin in the console).
    /// The agent replaces its stored Argon2id hash atomically and only then
    /// acks the message; the server promotes the token from pending to
    /// current when that ack arrives. Re-sent on every connect while the
    /// rotation is pending. Never logged.
    SetUninstallToken {
        token: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Hello {
    pub device_id: Uuid,
    pub agent_version: String,
    pub hostname: String,
    pub os: OsInfo,
    pub boot_id: String,
    pub policy_version: u64,
    pub rules_version: u64,
    /// Random id generated when the agent's outbox database is created. If it
    /// changes (outbox deleted/recreated), the server resets its per-device
    /// seq high-water mark instead of discarding new messages as duplicates.
    #[serde(default)]
    pub outbox_epoch: Option<Uuid>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct OsInfo {
    /// e.g. "Windows 11 Pro"
    pub name: String,
    /// e.g. "10.0.26100.4652"
    pub build: String,
    pub arch: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub hw_uuid: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Heartbeat {
    /// Strictly increasing; a gap or reset without a reboot is a tamper signal.
    pub seq: u64,
    pub ts: TimestampMs,
    pub health: AgentHealth,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct AgentHealth {
    pub etw_ok: bool,
    #[serde(default)]
    pub etw_events_lost: u64,
    #[serde(default)]
    pub etw_buffers_lost: u64,
    #[serde(default)]
    pub events_per_min: u64,
    #[serde(default)]
    pub outbox_depth: u64,
    #[serde(default)]
    pub sysmon_present: bool,
    #[serde(default)]
    pub dpapi_channel_enabled: bool,
    #[serde(default)]
    pub amsi_ok: bool,
    #[serde(default)]
    pub isolated: bool,
    /// Hardening controls currently in effect, control id → applied.
    #[serde(default)]
    pub hardening: std::collections::BTreeMap<String, bool>,
    #[serde(default)]
    pub cpu_pct: f32,
    #[serde(default)]
    pub mem_mb: u64,
    #[serde(default)]
    pub uptime_s: u64,
    #[serde(default)]
    pub logged_on_user: Option<String>,
    #[serde(default)]
    pub ip_addresses: Vec<String>,
    #[serde(default)]
    pub av_product: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ReviewRequest {
    pub alert_id: Uuid,
    pub user: String,
    pub justification: String,
    pub ts: TimestampMs,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Inventory {
    #[serde(default)]
    pub software: Vec<Software>,
    #[serde(default)]
    pub local_admins: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Software {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub publisher: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UpdateManifest {
    pub version: String,
    pub url: String,
    pub sha256: String,
    /// Base64 Ed25519 signature over the UTF-8 bytes of
    /// `kestrel-update-v1\n{version}\n{url}\n{sha256}` (fields trimmed,
    /// sha256 as lower-case hex), so a signed package cannot be replayed under
    /// another version or URL.
    pub signature: String,
}

/// Body of the unary `Enroll` call (no client cert yet; protected by the token).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnrollRequest {
    pub token: String,
    pub csr_pem: String,
    pub hostname: String,
    pub os: OsInfo,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EnrollResponse {
    pub device_id: Uuid,
    /// Client certificate (CN = device id) signed by the server's agent CA.
    pub cert_pem: String,
    pub ca_pem: String,
    /// Per-device uninstall token generated by the server (stored encrypted
    /// server-side and shown to admins on the device page). The agent stores
    /// only its Argon2id hash. Empty from old servers.
    #[serde(default)]
    pub uninstall_token: String,
}
