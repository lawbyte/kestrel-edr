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
}

fn default_limit() -> u32 {
    50
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TrayResponse {
    Status(TrayStatus),
    Activity { items: Vec<ActivityItem> },
    Ack { ok: bool, message: String },
    Notification(ActivityItem),
    Error { message: String },
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
