//! Mirror of `kestrel_common::tray` + `pause` + `policy::ItContact` + `alert::Severity`.
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
    /// Turn protection off with the device's uninstall token. `mode` and
    /// `minutes` must be allowed by `TrayStatus.local_pause`; `minutes: None` =
    /// until turned back on. Answered with `PauseResult` (older agents: `Error`).
    PauseProtection {
        token: TokenInput,
        #[serde(default)]
        mode: PauseMode,
        #[serde(default)]
        minutes: Option<u32>,
    },
    /// Turn protection back on. Never needs a token. Answered with `PauseResult`.
    ResumeProtection,
}

impl TrayRequest {
    /// Wire name of the request (`op`). Safe to log: it never carries a field
    /// value, so the uninstall token can't end up in a log or error message.
    pub fn op(&self) -> &'static str {
        match self {
            TrayRequest::Status => "status",
            TrayRequest::Activity { .. } => "activity",
            TrayRequest::QuickCheck => "quick_check",
            TrayRequest::RequestReview { .. } => "request_review",
            TrayRequest::Subscribe => "subscribe",
            TrayRequest::SubscribeWith { .. } => "subscribe_with",
            TrayRequest::ConsentResponse { .. } => "consent_response",
            TrayRequest::PauseProtection { .. } => "pause_protection",
            TrayRequest::ResumeProtection => "resume_protection",
        }
    }
}

/// `SubscribeWith.features` value enabling `TrayResponse::RemoteSession` pushes.
pub const FEATURE_REMOTE_SESSION: &str = "remote_session";
/// `SubscribeWith.features` value enabling `TrayResponse::ConsentRequest` pushes.
pub const FEATURE_REMOTE_CONSENT: &str = "remote_consent";

fn default_limit() -> u32 {
    50
}

// Status grew with the pause fields; one response per request, so the size
// doesn't matter and the variant shape must mirror the contract.
#[allow(clippy::large_enum_variant)]
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
    /// Answer to `PauseProtection` / `ResumeProtection` (never pushed).
    PauseResult(PauseResult),
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
    /// Protection turned off on this PC (tray switch), if it is now. `state`
    /// keeps its normal value; the tray derives "off" from this field.
    #[serde(default)]
    pub pause: Option<PauseState>,
    /// What the "Turn off protection" dialog may offer (`None` from older
    /// agents: the button is hidden).
    #[serde(default)]
    pub local_pause: Option<PauseOffer>,
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

// ---- Local "turn protection off" switch (mirror of `kestrel_common::pause`) --

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PauseMode {
    /// Detect and report only: no automatic response, hardening not enforced.
    #[default]
    DetectionOnly,
    /// Sensors stopped: only heartbeat, health and the tray keep running.
    Full,
}

/// An active pause (`TrayStatus.pause`, `PauseResult.state`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PauseState {
    pub mode: PauseMode,
    pub since_ms: TimestampMs,
    /// Automatic turn-on time; `None` = until turned back on.
    #[serde(default)]
    pub until_ms: Option<TimestampMs>,
    /// Windows account that turned protection off (`DOMAIN\user`).
    #[serde(default)]
    pub by_user: String,
}

/// What the tray may offer right now (`TrayStatus.local_pause`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PauseOffer {
    pub enabled: bool,
    #[serde(default)]
    pub allow_full: bool,
    /// Timed durations in minutes (ascending).
    #[serde(default)]
    pub minutes: Vec<u32>,
    #[serde(default)]
    pub allow_until_resumed: bool,
    /// Wrong-token lockout in force until this time.
    #[serde(default)]
    pub locked_until_ms: Option<TimestampMs>,
}

/// The uninstall token as typed in the tray. Serialises as a plain string;
/// `Debug` never prints it, so a logged request can't leak it.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
#[serde(transparent)]
pub struct TokenInput(pub String);

impl std::fmt::Debug for TokenInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TokenInput(<redacted>)")
    }
}

/// Why a pause request was refused by policy.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseDenied {
    /// `local_pause.enabled` is false.
    Disabled,
    /// `full` requested but not allowed.
    ModeNotAllowed,
    /// Duration too long, zero, or "until turned back on" not allowed.
    DurationNotAllowed,
}

/// Why a `PauseProtection` / `ResumeProtection` request failed.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseError {
    WrongToken,
    LockedOut,
    NotAllowed,
    AlreadyOff,
    NotOff,
    Unidentified,
    Internal,
}

/// Outcome of `PauseProtection` / `ResumeProtection`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PauseResult {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<PauseError>,
    /// Plain-language message for the employee.
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub attempts_left: Option<u32>,
    #[serde(default)]
    pub locked_until_ms: Option<TimestampMs>,
    #[serde(default)]
    pub denied: Option<PauseDenied>,
    /// Pause in force after the request (`None` = protection on).
    #[serde(default)]
    pub state: Option<PauseState>,
}

pub fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_never_debug_printed() {
        let req = TrayRequest::PauseProtection {
            token: TokenInput("kun_secret_value".into()),
            mode: PauseMode::Full,
            minutes: Some(60),
        };
        let dbg = format!("{req:?}");
        assert!(!dbg.contains("kun_secret_value"), "{dbg}");
        assert!(dbg.contains("<redacted>"));
        assert_eq!(req.op(), "pause_protection");
        // It is on the wire, as a plain string.
        assert_eq!(
            serde_json::to_value(&req).unwrap(),
            serde_json::json!({"op":"pause_protection","token":"kun_secret_value","mode":"full","minutes":60})
        );
    }

    #[test]
    fn pause_wire_shapes() {
        let r: TrayRequest =
            serde_json::from_str(r#"{"op":"pause_protection","token":"t"}"#).unwrap();
        assert_eq!(
            r,
            TrayRequest::PauseProtection {
                token: TokenInput("t".into()),
                mode: PauseMode::DetectionOnly,
                minutes: None
            }
        );
        assert_eq!(
            serde_json::to_string(&TrayRequest::ResumeProtection).unwrap(),
            r#"{"op":"resume_protection"}"#
        );
        let res: TrayResponse = serde_json::from_str(
            r#"{"type":"pause_result","ok":false,"error":"wrong_token","attempts_left":3}"#,
        )
        .unwrap();
        let TrayResponse::PauseResult(p) = res else {
            panic!("variant")
        };
        assert_eq!(
            (p.error, p.attempts_left, p.state, p.message.as_str()),
            (Some(PauseError::WrongToken), Some(3), None, "")
        );
    }
}
