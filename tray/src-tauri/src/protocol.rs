//! Mirror of `kestrel_common::tray` + `policy::ItContact` + `alert::Severity`.
//!
//! The tray is a separate Cargo workspace (it must build without the agent's
//! dependency tree), so the contract types are mirrored here. `tests/contract.rs`
//! round-trips every variant through the real `kestrel-common` types to catch drift.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub type TimestampMs = i64;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TrayRequest {
    Status,
    Activity {
        #[serde(default = "default_limit")]
        limit: u32,
    },
    QuickCheck,
    RequestReview {
        alert_id: Uuid,
        justification: String,
    },
    Subscribe,
    /// `Subscribe` plus opt-in push kinds (e.g. [`FEATURE_REMOTE_SESSION`]).
    /// Older agents answer `Error`; the tray then falls back to `Subscribe`.
    SubscribeWith {
        #[serde(default)]
        features: Vec<String>,
    },
    /// The employee's answer to a `ConsentRequest` push (mirrored for the
    /// contract; this tray doesn't opt into consent prompts yet).
    ConsentResponse {
        request_id: Uuid,
        allow: bool,
    },
}

/// `SubscribeWith.features` value enabling `TrayResponse::RemoteSession` pushes.
pub const FEATURE_REMOTE_SESSION: &str = "remote_session";
/// `SubscribeWith.features` value enabling `TrayResponse::ConsentRequest` pushes.
pub const FEATURE_REMOTE_CONSENT: &str = "remote_consent";

fn default_limit() -> u32 {
    50
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrayResponse {
    Status(TrayStatus),
    Activity {
        items: Vec<ActivityItem>,
    },
    Ack {
        ok: bool,
        message: String,
    },
    Notification(ActivityItem),
    Error {
        message: String,
    },
    /// Remote-desktop session state changed (only pushed to connections that
    /// subscribed with [`FEATURE_REMOTE_SESSION`]). `active: false` = ended.
    RemoteSession(RemoteSessionNotice),
    /// IT asks to connect; only pushed to `remote_consent` subscribers.
    ConsentRequest(ConsentRequest),
}

/// What the admin wants to do (consent prompt / session notice).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RemoteKind {
    #[default]
    Desktop,
    Files,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConsentRequest {
    pub request_id: Uuid,
    pub kind: RemoteKind,
    pub admin_name: String,
    #[serde(default)]
    pub view_only: bool,
    #[serde(default)]
    pub reason: String,
    pub timeout_secs: u32,
    pub expires_at: TimestampMs,
}

/// An admin's remote-desktop session on this PC, as shown to the employee.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RemoteSessionNotice {
    pub active: bool,
    /// Desktop session or file-manager session.
    #[serde(default)]
    pub kind: RemoteKind,
    /// Display name of the admin ("Jane Doe").
    pub admin_name: String,
    /// `true` = the admin can only see the screen.
    pub view_only: bool,
    #[serde(default)]
    pub reason: String,
    pub started_at: TimestampMs,
    #[serde(default)]
    pub ended_at: Option<TimestampMs>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    Protected,
    Attention,
    Isolated,
    Degraded,
    Offline,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ItContact {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TrayStatus {
    pub state: ProtectionState,
    pub agent_version: String,
    pub server_connected: bool,
    #[serde(default)]
    pub last_policy_sync: Option<TimestampMs>,
    pub policy_name: String,
    pub org_name: String,
    pub it_contact: ItContact,
    pub privacy_notice_md: String,
    pub hostname: String,
    #[serde(default)]
    pub last_check: Option<TimestampMs>,
    /// Remote-desktop session in progress, if any (absent from older agents).
    #[serde(default)]
    pub remote_session: Option<RemoteSessionNotice>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ActivityItem {
    pub id: Uuid,
    pub ts: TimestampMs,
    pub title: String,
    pub body: String,
    pub severity: Severity,
    #[serde(default)]
    pub alert_id: Option<Uuid>,
    #[serde(default)]
    pub file: Option<String>,
    pub action_taken: String,
    #[serde(default)]
    pub review: Option<ReviewState>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewState {
    Requested,
    Approved,
    Denied,
}

pub fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
