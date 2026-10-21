//! Local "turn protection off" switch (owner decision 2026-10-21, see
//! `docs/DECISIONS.md`).
//!
//! An employee or on-site technician turns protection off from the tray with
//! the device's uninstall token; turning it back on never needs a token (tray,
//! or `ResponseAction::ResumeProtection` from the console). What "off" means
//! and for how long is set by the policy ([`LocalPause`]) and enforced by the
//! agent, not only by the tray UI.
//!
//! * [`PauseMode::DetectionOnly`] (default): sensors, detection, alerts and
//!   telemetry continue; no automatic response action of any kind runs and
//!   every alert is forced to Audit (`Alert::protection_off`); hardening is
//!   neither (re)enforced nor reverted; analyst actions from the console run.
//! * [`PauseMode::Full`]: sensors stopped, only heartbeat / health / tray run.
//!   Offered only when `LocalPause::allow_full`.
//!
//! Every turn-off raises `TP-06`; every turn-on and every rejected token is
//! reported too ([`PauseReport`]).

use crate::TimestampMs;
use serde::{Deserialize, Serialize};

/// Durations (minutes) the tray offers, each capped by `LocalPause::max_minutes`.
pub const PAUSE_DURATIONS_MIN: [u32; 4] = [15, 60, 240, 480];
/// Wrong tokens allowed before the first lockout.
pub const PAUSE_MAX_FAILURES: u32 = 5;
/// First lockout; doubles with every further lockout up to [`PAUSE_LOCKOUT_MAX_MS`].
pub const PAUSE_LOCKOUT_BASE_MS: i64 = 60_000;
pub const PAUSE_LOCKOUT_MAX_MS: i64 = 3_600_000;
/// Upper bound accepted for `LocalPause::max_minutes` (7 days).
pub const PAUSE_MAX_MINUTES_CAP: u32 = 7 * 24 * 60;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PauseMode {
    /// Detect and report only: no automatic response, hardening not enforced.
    #[default]
    DetectionOnly,
    /// Sensors stopped: only heartbeat, health and the tray keep running.
    Full,
}

impl PauseMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PauseMode::DetectionOnly => "detection_only",
            PauseMode::Full => "full",
        }
    }

    /// Plain-language label ("detection only" / "completely off").
    pub fn label(&self) -> &'static str {
        match self {
            PauseMode::DetectionOnly => "detection only",
            PauseMode::Full => "completely off",
        }
    }
}

/// An active pause, as persisted by the agent and reported in
/// `AgentHealth.pause`, `Hello.pause` and `TrayStatus.pause`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PauseState {
    pub mode: PauseMode,
    pub since_ms: TimestampMs,
    /// Automatic turn-on time; `None` = until turned back on.
    #[serde(default)]
    pub until_ms: Option<TimestampMs>,
    /// Windows account that turned protection off (`DOMAIN\user`; the
    /// policy's username pseudonymisation applies to what is uploaded).
    #[serde(default)]
    pub by_user: String,
}

impl PauseState {
    /// Has the pause run out at `now`?
    pub fn expired(&self, now: TimestampMs) -> bool {
        self.until_ms.is_some_and(|u| now >= u)
    }
}

/// Policy: may protection be turned off locally from the tray, and how.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct LocalPause {
    /// The tray offers "Turn off protection" (with the uninstall token).
    #[serde(default = "yes")]
    pub enabled: bool,
    /// `PauseMode::Full` (sensors stopped) may be chosen.
    #[serde(default)]
    pub allow_full: bool,
    /// Longest timed pause, minutes.
    #[serde(default = "default_max_minutes")]
    pub max_minutes: u32,
    /// "Until turned back on" (no automatic turn-on) may be chosen.
    #[serde(default)]
    pub allow_until_resumed: bool,
}

fn yes() -> bool {
    true
}
fn default_max_minutes() -> u32 {
    480
}

impl Default for LocalPause {
    fn default() -> Self {
        LocalPause {
            enabled: true,
            allow_full: false,
            max_minutes: default_max_minutes(),
            allow_until_resumed: false,
        }
    }
}

/// The uninstall token as typed in the tray. Serialises as a plain string;
/// `Debug` never prints it, so a logged request cannot leak it.
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
    /// `full` requested but `allow_full` is false.
    ModeNotAllowed,
    /// Duration above `max_minutes`, zero, or "until turned back on" without
    /// `allow_until_resumed`.
    DurationNotAllowed,
}

impl LocalPause {
    /// `max_minutes` clamped to a sane range (1 minute ..= 7 days).
    pub fn max_minutes(&self) -> u32 {
        self.max_minutes.clamp(1, PAUSE_MAX_MINUTES_CAP)
    }

    /// Timed durations the tray offers: the standard steps up to
    /// `max_minutes`, plus `max_minutes` itself when it is not a step (so a
    /// policy of 30 minutes offers 15 and 30).
    pub fn offered_minutes(&self) -> Vec<u32> {
        if !self.enabled {
            return vec![];
        }
        let max = self.max_minutes();
        let mut v: Vec<u32> = PAUSE_DURATIONS_MIN
            .iter()
            .copied()
            .filter(|m| *m <= max)
            .collect();
        if !v.contains(&max) && max < PAUSE_DURATIONS_MIN[PAUSE_DURATIONS_MIN.len() - 1] {
            v.push(max);
        }
        v
    }

    /// Check a request. `minutes: None` = until turned back on.
    pub fn check(&self, mode: PauseMode, minutes: Option<u32>) -> Result<(), PauseDenied> {
        if !self.enabled {
            return Err(PauseDenied::Disabled);
        }
        if mode == PauseMode::Full && !self.allow_full {
            return Err(PauseDenied::ModeNotAllowed);
        }
        match minutes {
            None if !self.allow_until_resumed => Err(PauseDenied::DurationNotAllowed),
            Some(0) => Err(PauseDenied::DurationNotAllowed),
            Some(m) if m > self.max_minutes() => Err(PauseDenied::DurationNotAllowed),
            _ => Ok(()),
        }
    }

    /// What an active pause becomes under this (new) policy at `now`:
    /// `None` = it must end now (switch disabled, `full` no longer allowed,
    /// or "until turned back on" no longer allowed and the timed cap has
    /// already passed); otherwise the state, with `until_ms` clamped to
    /// `now + max_minutes` when it ended later (or had no end).
    pub fn reconcile(&self, s: &PauseState, now: TimestampMs) -> Option<PauseState> {
        if !self.enabled || (s.mode == PauseMode::Full && !self.allow_full) {
            return None;
        }
        let cap = now + self.max_minutes() as i64 * 60_000;
        let mut out = s.clone();
        match s.until_ms {
            None if self.allow_until_resumed => {}
            None => out.until_ms = Some(cap),
            Some(u) if u > cap => out.until_ms = Some(cap),
            Some(_) => {}
        }
        if out.expired(now) {
            return None;
        }
        Some(out)
    }
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

/// Outcome of a tray `PauseProtection` / `ResumeProtection` request.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseError {
    /// The uninstall token did not match. `attempts_left` before a lockout.
    WrongToken,
    /// Too many wrong tokens; retry after `locked_until_ms`.
    LockedOut,
    /// Refused by the policy (`denied` says why).
    NotAllowed,
    /// Protection is already off (`state` is the active pause).
    AlreadyOff,
    /// Protection is already on (resume without a pause).
    NotOff,
    /// The caller's Windows identity could not be established.
    Unidentified,
    /// Agent-side failure (e.g. the state could not be saved).
    Internal,
}

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

/// What happened (agent → server, `AgentPayload::Pause`).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseEvent {
    /// Protection turned off (`state` = the new pause).
    Off,
    /// Protection turned back on (`state` = the pause that ended, `reason`).
    On,
    /// A policy change shortened an active pause (`state` = the new pause).
    Clamped,
    /// A wrong uninstall token was entered (`failures`, `locked_until_ms`).
    Denied,
}

/// Why protection came back on.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PauseEndReason {
    /// "Turn protection back on" in the tray.
    Manual,
    /// The chosen duration ran out (also when it ran out while the agent was down).
    Expired,
    /// `ResponseAction::ResumeProtection` from the console.
    Console,
    /// A policy change disabled the switch or the chosen mode.
    Policy,
}

impl PauseEndReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            PauseEndReason::Manual => "manual",
            PauseEndReason::Expired => "expired",
            PauseEndReason::Console => "console",
            PauseEndReason::Policy => "policy",
        }
    }
}

/// Agent report of a pause change or a rejected token (`AgentPayload::Pause`).
/// The token itself is never part of it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PauseReport {
    pub event: PauseEvent,
    pub ts: TimestampMs,
    #[serde(default)]
    pub state: Option<PauseState>,
    #[serde(default)]
    pub reason: Option<PauseEndReason>,
    /// Who acted (tray user; empty for expiry / console / policy).
    #[serde(default)]
    pub by_user: String,
    /// `Denied`: consecutive wrong tokens so far.
    #[serde(default)]
    pub failures: u32,
    /// `Denied`: lockout now in force, if any.
    #[serde(default)]
    pub locked_until_ms: Option<TimestampMs>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_old_policies() {
        let d: LocalPause = serde_json::from_str("{}").unwrap();
        assert_eq!(d, LocalPause::default());
        assert!(d.enabled && !d.allow_full && !d.allow_until_resumed);
        assert_eq!(d.max_minutes, 480);
        assert_eq!(d.offered_minutes(), vec![15, 60, 240, 480]);
    }

    #[test]
    fn offered_minutes_capped() {
        let p = |m| LocalPause {
            max_minutes: m,
            ..Default::default()
        };
        assert_eq!(p(60).offered_minutes(), vec![15, 60]);
        assert_eq!(p(30).offered_minutes(), vec![15, 30]);
        assert_eq!(p(5).offered_minutes(), vec![5]);
        assert_eq!(p(1000).offered_minutes(), vec![15, 60, 240, 480]);
        assert!(LocalPause {
            enabled: false,
            ..Default::default()
        }
        .offered_minutes()
        .is_empty());
    }

    #[test]
    fn check_enforces_policy() {
        let d = LocalPause::default();
        assert_eq!(d.check(PauseMode::DetectionOnly, Some(60)), Ok(()));
        assert_eq!(d.check(PauseMode::DetectionOnly, Some(480)), Ok(()));
        assert_eq!(
            d.check(PauseMode::DetectionOnly, Some(481)),
            Err(PauseDenied::DurationNotAllowed)
        );
        assert_eq!(
            d.check(PauseMode::DetectionOnly, Some(0)),
            Err(PauseDenied::DurationNotAllowed)
        );
        assert_eq!(
            d.check(PauseMode::DetectionOnly, None),
            Err(PauseDenied::DurationNotAllowed)
        );
        assert_eq!(
            d.check(PauseMode::Full, Some(15)),
            Err(PauseDenied::ModeNotAllowed)
        );
        let open = LocalPause {
            allow_full: true,
            allow_until_resumed: true,
            ..Default::default()
        };
        assert_eq!(open.check(PauseMode::Full, None), Ok(()));
        let off = LocalPause {
            enabled: false,
            ..open
        };
        assert_eq!(
            off.check(PauseMode::DetectionOnly, Some(15)),
            Err(PauseDenied::Disabled)
        );
    }

    #[test]
    fn reconcile_on_policy_change() {
        let s = PauseState {
            mode: PauseMode::DetectionOnly,
            since_ms: 0,
            until_ms: Some(480 * 60_000),
            by_user: "W\\e".into(),
        };
        let d = LocalPause::default();
        assert_eq!(d.reconcile(&s, 1000), Some(s.clone()));
        // Lowered cap clamps from now.
        let p60 = LocalPause {
            max_minutes: 60,
            ..Default::default()
        };
        let r = p60.reconcile(&s, 10 * 60_000).unwrap();
        assert_eq!(r.until_ms, Some(70 * 60_000));
        // Disabled ends it.
        assert_eq!(
            LocalPause {
                enabled: false,
                ..Default::default()
            }
            .reconcile(&s, 0),
            None
        );
        // Full no longer allowed ends a full pause.
        let full = PauseState {
            mode: PauseMode::Full,
            ..s.clone()
        };
        assert_eq!(d.reconcile(&full, 0), None);
        // Until-resumed no longer allowed: becomes timed.
        let open = PauseState {
            until_ms: None,
            ..s.clone()
        };
        assert_eq!(
            d.reconcile(&open, 5).unwrap().until_ms,
            Some(5 + 480 * 60_000)
        );
        // Expired already.
        assert_eq!(d.reconcile(&s, 480 * 60_000), None);
    }

    #[test]
    fn token_never_debug_printed() {
        let t = TokenInput("kun_secret".into());
        assert!(!format!("{t:?}").contains("kun_secret"));
        assert_eq!(serde_json::to_string(&t).unwrap(), "\"kun_secret\"");
    }

    #[test]
    fn wire_names() {
        assert_eq!(
            serde_json::to_string(&PauseMode::DetectionOnly).unwrap(),
            "\"detection_only\""
        );
        let s: PauseState = serde_json::from_str(r#"{"mode":"full","since_ms":1}"#).unwrap();
        assert_eq!(s.until_ms, None);
        assert_eq!(s.by_user, "");
    }
}
