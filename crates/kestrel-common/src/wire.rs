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
    remote::{LiveAgentMsg, LiveServerMsg, RemoteAccessProfile},
    response::{ActionOutcome, ResponseAction},
    rules::RuleBundle,
    TimestampMs,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Repeat summary of one event in an `AgentPayload::Events` batch.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRepeat {
    /// Index into the batch's `events`.
    pub index: u32,
    /// Identical events this row stands for (itself included), >= 1.
    pub count: u32,
    /// Time of the first of them (the row's own `ts` is the last).
    pub first_ts: TimestampMs,
}

/// Agent → server.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentPayload {
    /// First message on every stream.
    Hello(Hello),
    Heartbeat(Heartbeat),
    Events {
        events: Vec<Event>,
        /// Repeat summaries (agents from 1.1.7, `kestrel_agent::uploader`):
        /// `events[index]` stands for `count` identical events (same
        /// process, kind and target) seen from `first_ts` to its own `ts`,
        /// after a first copy that was uploaded on its own. Older servers
        /// ignore the field and store the summary as a plain event.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        repeats: Vec<EventRepeat>,
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
    /// Outcome of a `ServerPayload::Update` the agent could not complete
    /// (signature, download, hash or installer start failed). Success is not
    /// reported here: the server sees the new `agent_version` in the next
    /// `Hello`. Older servers drop this message as malformed (and ack it).
    UpdateResult {
        version: String,
        ok: bool,
        #[serde(default)]
        error: String,
    },
    /// Remote-access live session traffic (remote desktop frames, file
    /// manager replies). Ephemeral: envelope seq 0, never in the outbox,
    /// never acked, never stored server-side. Older servers drop it as
    /// malformed. See `kestrel_common::remote`.
    Live {
        session_id: Uuid,
        msg: LiveAgentMsg,
    },
    /// Protection turned off / back on locally, a pause shortened by policy,
    /// or a wrong uninstall token entered in the tray (never the token).
    /// Older servers drop it as malformed (and ack it); the state is also in
    /// `AgentHealth.pause`.
    Pause(crate::pause::PauseReport),
    /// Lifecycle of an evidence bundle (capturing, ready with its
    /// privacy-filtered manifest, failed, deleted, expired). Metadata only:
    /// the bundle itself is uploaded only when an administrator collects it.
    /// Stored by the server outside telemetry. Older servers drop it as
    /// malformed (and ack it).
    Evidence(Box<crate::evidence::EvidenceReport>),
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
        /// Secrets the action needs, attached by the server at delivery time
        /// only (never stored with the action, never in the REST API). Today:
        /// the uninstall token(s) for `UninstallAgent`. Absent for every
        /// other action; older agents ignore it. `Debug` redacts it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        secret: Option<CommandSecret>,
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
    /// Remote-access live session traffic (desktop start/stop/input, file
    /// manager requests). Not acked by the agent and not tracked by the
    /// server; only sent to agents whose `Hello.capabilities` list the
    /// feature. See `kestrel_common::remote`.
    Live {
        session_id: Uuid,
        msg: LiveServerMsg,
    },
}

/// Secret part of a `ServerPayload::Command` (see there). Never logged:
/// `Debug` prints only how many tokens there are.
#[derive(Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct CommandSecret {
    /// Candidate uninstall tokens for `UninstallAgent`: the device's current
    /// token and, while a rotation is unconfirmed, the pending one. The agent
    /// uses the one that matches its stored Argon2id hash.
    #[serde(default)]
    pub uninstall_tokens: Vec<String>,
}

impl std::fmt::Debug for CommandSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSecret")
            .field(
                "uninstall_tokens",
                &format_args!("[redacted; {}]", self.uninstall_tokens.len()),
            )
            .finish()
    }
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
    /// Optional features this agent supports (`remote::CAP_LIVE_FILES`,
    /// `remote::CAP_LIVE_DESKTOP`). Empty for older agents.
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Remote-access ceiling pinned on this agent at enrollment (`None` from
    /// agents older than profiles = no remote access).
    #[serde(default)]
    pub remote_ceiling: Option<RemoteAccessProfile>,
    /// Protection turned off locally (tray switch), if it is now.
    #[serde(default)]
    pub pause: Option<crate::pause::PauseState>,
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
    /// Part of `etw_events_lost` discarded inside ETW (kernel session
    /// buffers full: the consumer could not keep up). `None` from agents
    /// older than 2026-10-22, which only report the total.
    #[serde(default)]
    pub etw_kernel_events_lost: Option<u64>,
    /// Part of `etw_events_lost` dropped by the agent's own sensor queues
    /// and caps (internal queue / agent channel full, aggregator caps).
    #[serde(default)]
    pub sensor_internal_dropped: Option<u64>,
    /// Part of `sensor_internal_dropped` that may blind a detection
    /// (high-value records lost to a full queue, persistence records,
    /// processes the file-activity aggregator could not track); the rest
    /// are low-value records shed under pressure. `None` from agents older
    /// than 1.1.7. Cumulative since the agent started.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_high_value_dropped: Option<u64>,
    /// Events the sensors handed to the engine since the agent started
    /// (the denominator of the loss ratio). `None` from agents older than
    /// 1.1.7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensor_events_total: Option<u64>,
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
    /// Remote-access ceiling pinned at enrollment (see `Hello.remote_ceiling`).
    #[serde(default)]
    pub remote_ceiling: Option<RemoteAccessProfile>,
    /// Effective remote-access profile the agent enforces now
    /// (ceiling ∩ policy).
    #[serde(default)]
    pub remote_effective: Option<RemoteAccessProfile>,
    /// Protection turned off locally (tray switch); `None` = protection on.
    #[serde(default)]
    pub pause: Option<crate::pause::PauseState>,
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
    /// Remote-access profile bound to the enrollment token. The agent pins it
    /// as its ceiling; later server messages never change it (only a new
    /// enrollment does). Absent from older servers = no remote access.
    #[serde(default)]
    pub remote_profile: RemoteAccessProfile,
}

/// Replace NUL characters in every string (and object key) of a JSON value
/// with U+FFFD. PostgreSQL `text`/`jsonb` cannot store `\u0000`; one event
/// whose command line carried a NUL (seen on a real Windows host) made every
/// insert of that batch fail, and the agent re-sent it forever. Returns the
/// number of strings changed.
pub fn strip_nul(v: &mut serde_json::Value) -> usize {
    use serde_json::Value;
    fn fix(s: &mut String) -> bool {
        if s.contains('\0') {
            *s = s.replace('\0', "\u{FFFD}");
            true
        } else {
            false
        }
    }
    match v {
        Value::String(s) => usize::from(fix(s)),
        Value::Array(a) => a.iter_mut().map(strip_nul).sum(),
        Value::Object(m) => {
            let mut n = 0;
            if m.keys().any(|k| k.contains('\0')) {
                let old = std::mem::take(m);
                for (mut k, val) in old {
                    n += usize::from(fix(&mut k));
                    m.insert(k, val);
                }
            }
            n + m.values_mut().map(strip_nul).sum::<usize>()
        }
        _ => 0,
    }
}

#[cfg(test)]
mod command_secret_tests {
    use super::*;
    use crate::ResponseAction;

    #[test]
    fn secret_is_optional_and_redacted() {
        let id = Uuid::nil();
        // Older servers / every other action: no `secret` on the wire.
        let p = ServerPayload::Command {
            command_id: id,
            action: ResponseAction::ApplyHardening,
            secret: None,
        };
        let j = serde_json::to_string(&p).unwrap();
        assert!(!j.contains("secret"), "{j}");
        let back: ServerPayload = serde_json::from_str(&j).unwrap();
        assert_eq!(back, p);
        let p = ServerPayload::Command {
            command_id: id,
            action: ResponseAction::UninstallAgent { purge_data: false },
            secret: Some(CommandSecret {
                uninstall_tokens: vec!["kun_supersecret".into()],
            }),
        };
        let dbg = format!("{p:?}");
        assert!(!dbg.contains("kun_supersecret"), "{dbg}");
        assert!(dbg.contains("redacted; 1"), "{dbg}");
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(serde_json::from_str::<ServerPayload>(&j).unwrap(), p);
    }
}

#[cfg(test)]
mod nul_tests {
    use super::*;

    #[test]
    fn nul_characters_are_replaced_everywhere() {
        let mut v =
            serde_json::json!({"cmdline": "a\u{0}b", "list": ["x\u{0}"], "k\u{0}": 1, "n": 2});
        assert_eq!(strip_nul(&mut v), 3);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains(r"\u0000"), "{s}");
        assert_eq!(v["cmdline"], "a\u{FFFD}b");
        assert_eq!(v["n"], 2);
    }
}
