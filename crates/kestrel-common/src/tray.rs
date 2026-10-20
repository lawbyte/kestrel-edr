//! Tray app <-> agent protocol over the named pipe `\\.\pipe\kestrel-tray`.
//!
//! Framing: one JSON object per line (UTF-8, `\n` terminated). The tray sends
//! [`TrayRequest`]s; the agent answers each with exactly one [`TrayResponse`],
//! and after `Subscribe` it also pushes `Notification`s on the same pipe.
//! The tray runs unprivileged; the pipe DACL allows Authenticated Users to
//! connect, and the agent only exposes the data below (no response actions).

use crate::{alert::Severity, policy::ItContact, TimestampMs};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TrayRequest {
    Status,
    Activity {
        #[serde(default = "default_limit")]
        limit: u32,
    },
    /// Quick scan of running processes from user-writable paths.
    QuickCheck,
    RequestReview {
        alert_id: Uuid,
        justification: String,
    },
    /// Start receiving `Notification` pushes on this connection.
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

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionState {
    /// Running, sensors healthy, connected.
    Protected,
    /// Something was blocked recently or needs the user's attention.
    Attention,
    /// Host is network-isolated by IT.
    Isolated,
    /// Running but sensors degraded (e.g. ETW session lost).
    Degraded,
    /// Running but can't reach the server (still protecting locally).
    Offline,
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
    /// Plain-language title, e.g. "Blocked an app from reading your browser passwords".
    pub title: String,
    pub body: String,
    pub severity: Severity,
    #[serde(default)]
    pub alert_id: Option<Uuid>,
    #[serde(default)]
    pub file: Option<String>,
    /// e.g. "Stopped and quarantined".
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
