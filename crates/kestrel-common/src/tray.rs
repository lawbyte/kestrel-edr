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
    /// `Subscribe` plus opt-in push kinds (`features`), e.g.
    /// [`FEATURE_REMOTE_SESSION`] for `RemoteSession` pushes. Newer trays send
    /// this first and fall back to `Subscribe` when an older agent answers
    /// `Error`. Pushes a client did not opt into are never sent to it, so an
    /// older tray never sees a response type it cannot parse.
    SubscribeWith {
        #[serde(default)]
        features: Vec<String>,
    },
    /// The employee's answer to a `ConsentRequest` push. Accepted only from
    /// a tray running in the active console session.
    ConsentResponse {
        request_id: Uuid,
        allow: bool,
    },
}

/// `SubscribeWith.features` value enabling `TrayResponse::RemoteSession` pushes.
pub const FEATURE_REMOTE_SESSION: &str = "remote_session";
/// `SubscribeWith.features` value enabling `TrayResponse::ConsentRequest`
/// pushes (the tray can show an Allow/Deny prompt).
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
    /// Remote-desktop session state changed (pushed only to connections that
    /// subscribed with [`FEATURE_REMOTE_SESSION`]). `active: false` = ended.
    RemoteSession(RemoteSessionNotice),
    /// IT asks to connect (guardrail `require_consent`); answer with
    /// `TrayRequest::ConsentResponse`. Pushed only to connections that
    /// subscribed with [`FEATURE_REMOTE_CONSENT`] from the active console
    /// session. No answer by `expires_at` = deny.
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
    /// Desktop: the admin asked for view-only. Files: always false.
    #[serde(default)]
    pub view_only: bool,
    #[serde(default)]
    pub reason: String,
    pub timeout_secs: u32,
    pub expires_at: TimestampMs,
}

/// An admin's remote-desktop session on this PC, as shown to the employee.
/// There is no consent step (owner decision); the employee is always told.
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
    /// Remote-desktop session in progress, if any.
    #[serde(default)]
    pub remote_session: Option<RemoteSessionNotice>,
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
