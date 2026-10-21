//! Local "turn protection off" switch (tray, uninstall token) — agent side.
//!
//! Contract and policy semantics: `kestrel_common::pause`. Here:
//! * [`Lockout`]: wrong-token brute-force protection (5 failures → 1 min
//!   lockout, doubling up to 1 h), counted per device and persisted in the
//!   agent store (protected state dir) so restarting the agent or opening a
//!   new pipe connection never resets it;
//! * the [`Core`] methods that turn protection off and back on, apply the
//!   pause to the engine / sensors / hardening, persist it, auto-resume it
//!   (also when `until` passed while the agent was down) and reconcile it
//!   with a new policy;
//! * reporting: `TP-06` alert, `AgentPayload::Pause`, tray activity item.
//!
//! The token is verified with Argon2id (`AgentConfig::verify_uninstall_token`,
//! constant-time), never logged, never stored, never sent to the server.

use kestrel_common::{
    pause::{
        PauseDenied, PauseEndReason, PauseError, PauseEvent, PauseOffer, PauseReport, PauseResult,
        PAUSE_LOCKOUT_BASE_MS, PAUSE_LOCKOUT_MAX_MS, PAUSE_MAX_FAILURES,
    },
    tray::ActivityItem,
    wire::AgentPayload,
    PauseMode, PauseState, ProcessGuid, ProcessInfo, Severity, TimestampMs,
};
use kestrel_detect::catalog::{protection_alert, ProtectionSwitch};
use kestrel_platform::TrayClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::agent::Core;
use crate::detection::EngineCtl;

/// Store key of the active pause (`Option<PauseState>` as JSON).
pub const KV_PAUSE: &str = "pause_state";
/// Store key of the wrong-token lockout state ([`Lockout`]).
pub const KV_PAUSE_LOCKOUT: &str = "pause_lockout";
/// Wrong-token reports to the server: at most one per this interval, except
/// that the start of a lockout is always reported.
pub const DENIED_REPORT_INTERVAL_MS: i64 = 60_000;
/// After this long without a wrong token the lockout escalation starts over.
pub const LOCKOUT_FORGET_MS: i64 = 24 * 3_600_000;

/// Wrong-token state, per device.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Lockout {
    /// Wrong tokens since the last lockout (or success).
    #[serde(default)]
    pub failures: u32,
    /// Wrong tokens since the last success (reported to the server).
    #[serde(default)]
    pub total_failures: u32,
    /// Lockouts so far (each doubles the next one).
    #[serde(default)]
    pub lockouts: u32,
    #[serde(default)]
    pub locked_until: Option<TimestampMs>,
    #[serde(default)]
    pub last_failure: Option<TimestampMs>,
    #[serde(default)]
    pub last_report: Option<TimestampMs>,
}

/// Result of recording one wrong token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure {
    /// Wrong tokens left before a lockout (`0` when one just started).
    pub attempts_left: u32,
    /// Lockout that just started.
    pub locked_until: Option<TimestampMs>,
    /// Report this failure to the server now.
    pub report: bool,
}

impl Lockout {
    /// Lockout in force at `now`. A clock set back never extends it beyond
    /// the longest lockout.
    pub fn locked(&self, now: TimestampMs) -> Option<TimestampMs> {
        self.locked_until
            .filter(|u| now < *u)
            .map(|u| u.min(now + PAUSE_LOCKOUT_MAX_MS))
    }

    fn lockout_ms(lockouts: u32) -> i64 {
        PAUSE_LOCKOUT_BASE_MS
            .saturating_mul(1i64 << lockouts.min(16))
            .min(PAUSE_LOCKOUT_MAX_MS)
    }

    pub fn record_failure(&mut self, now: TimestampMs) -> Failure {
        // (A clock set back never resets the escalation.)
        if self
            .last_failure
            .is_some_and(|t| now >= t && now - t >= LOCKOUT_FORGET_MS)
        {
            self.failures = 0;
            self.lockouts = 0;
        }
        self.last_failure = Some(now);
        self.failures += 1;
        self.total_failures = self.total_failures.saturating_add(1);
        let mut locked_until = None;
        if self.failures >= PAUSE_MAX_FAILURES {
            let until = now + Self::lockout_ms(self.lockouts);
            self.lockouts = self.lockouts.saturating_add(1);
            self.failures = 0;
            self.locked_until = Some(until);
            locked_until = Some(until);
        }
        let report = locked_until.is_some()
            || self
                .last_report
                .is_none_or(|t| now < t || now - t >= DENIED_REPORT_INTERVAL_MS);
        if report {
            self.last_report = Some(now);
        }
        Failure {
            attempts_left: if locked_until.is_some() {
                0
            } else {
                PAUSE_MAX_FAILURES - self.failures
            },
            locked_until,
            report,
        }
    }

    /// A correct token ends the escalation.
    pub fn record_success(&mut self) {
        *self = Lockout {
            last_report: self.last_report,
            ..Lockout::default()
        };
    }
}

/// Synthetic subject of `TP-06` alerts: the agent, acting for `user`.
pub fn switch_subject(user: Option<String>, now: TimestampMs) -> ProcessInfo {
    ProcessInfo {
        guid: ProcessGuid("kestrel-agent:protection-switch".into()),
        pid: std::process::id(),
        ppid: 0,
        parent_guid: None,
        image: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "kestrel-agent.exe".into()),
        cmdline: String::new(),
        user,
        integrity: None,
        start_ts: now,
        exit_ts: None,
        signer: None,
        signed: kestrel_common::SignatureState::Unknown,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: kestrel_common::PathClass::ProgramFiles,
    }
}

/// "15 minutes", "1 hour", "4 hours", "1 h 30 min".
pub fn minutes_label(m: u32) -> String {
    match (m / 60, m % 60) {
        (0, m) => format!("{m} minute{}", if m == 1 { "" } else { "s" }),
        (h, 0) => format!("{h} hour{}", if h == 1 { "" } else { "s" }),
        (h, m) => format!("{h} h {m} min"),
    }
}

fn denied_message(d: PauseDenied) -> &'static str {
    match d {
        PauseDenied::Disabled => {
            "Your organisation's policy does not allow turning protection off on this PC."
        }
        PauseDenied::ModeNotAllowed => {
            "Your organisation's policy does not allow turning protection completely off. Choose detection only."
        }
        PauseDenied::DurationNotAllowed => {
            "Your organisation's policy does not allow that duration. Choose a shorter one."
        }
    }
}

fn result_err(error: PauseError, message: impl Into<String>) -> PauseResult {
    PauseResult {
        ok: false,
        error: Some(error),
        message: message.into(),
        attempts_left: None,
        locked_until_ms: None,
        denied: None,
        state: None,
    }
}

fn wait_phrase(ms: i64) -> String {
    let secs = (ms.max(0) + 999) / 1000;
    if secs < 60 {
        format!("{secs} s")
    } else {
        minutes_label(((secs + 59) / 60) as u32)
    }
}

impl Core {
    // ------------------------------------------------------------ queries

    /// The pause in force (`None` = protection on).
    pub fn pause_state(&self) -> Option<PauseState> {
        self.pause.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn pause_mode(&self) -> Option<PauseMode> {
        self.pause_state().map(|p| p.mode)
    }

    /// Sensors must stay stopped (protection completely off).
    pub fn sensors_paused(&self) -> bool {
        self.pause_mode() == Some(PauseMode::Full)
    }

    /// The pause as uploaded (policy username pseudonymisation applied).
    pub fn pause_for_upload(&self) -> Option<PauseState> {
        self.pause_state().map(|mut p| {
            if !p.by_user.is_empty() {
                p.by_user = self.filter().user(&p.by_user);
            }
            p
        })
    }

    fn lockout(&self) -> std::sync::MutexGuard<'_, Lockout> {
        self.pause_lockout.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// What the tray dialog may offer now.
    pub fn pause_offer(&self) -> PauseOffer {
        let lp = self.policy().local_pause;
        PauseOffer {
            enabled: lp.enabled,
            allow_full: lp.enabled && lp.allow_full,
            minutes: lp.offered_minutes(),
            allow_until_resumed: lp.enabled && lp.allow_until_resumed,
            locked_until_ms: self.lockout().locked(kestrel_common::now_ms()),
        }
    }

    // ------------------------------------------------------------ startup

    /// Load the persisted pause and wrong-token state (agent start). The
    /// pause is applied by [`Core::apply_pause_at_start`] once the engine
    /// runs.
    pub(crate) fn load_pause(&self) {
        let st: Option<PauseState> = self
            .store
            .kv_get_json::<Option<PauseState>>(KV_PAUSE)
            .unwrap_or_else(|e| {
                tracing::warn!("persisted pause state unreadable: {e:#}");
                None
            })
            .flatten();
        *self.pause.write().unwrap_or_else(|e| e.into_inner()) = st;
        let lo: Lockout = self
            .store
            .kv_get_json(KV_PAUSE_LOCKOUT)
            .ok()
            .flatten()
            .unwrap_or_default();
        *self.lockout() = lo;
    }

    /// Agent start: resume a pause that ran out while the agent was down,
    /// reconcile it with the cached policy, and tell the engine.
    pub(crate) async fn apply_pause_at_start(&self) {
        let Some(st) = self.pause_state() else {
            return;
        };
        let now = kestrel_common::now_ms();
        if st.expired(now) {
            tracing::info!(
                "protection turn-off ran out while the agent was down; turning protection back on"
            );
            self.resume_protection(PauseEndReason::Expired, String::new())
                .await;
            return;
        }
        tracing::warn!(
            mode = st.mode.as_str(),
            until = ?st.until_ms,
            "protection is turned off on this PC (tray switch)"
        );
        let _ = self.engine_ctl.send(EngineCtl::Pause(Some(st.mode)));
        // Every start while off is visible to IT (a crash between saving the
        // pause and queuing its report, or a state written by someone else,
        // would otherwise only show as a status).
        self.raise_switch_alert(
            ProtectionSwitch::StillOff(st.clone()),
            Some(&st.by_user),
            now,
        );
        self.reconcile_pause_with_policy().await;
    }

    fn persist_pause(&self, st: &Option<PauseState>) -> anyhow::Result<()> {
        self.store.kv_set_json(KV_PAUSE, st)?;
        *self.pause.write().unwrap_or_else(|e| e.into_inner()) = st.clone();
        Ok(())
    }

    fn persist_lockout(&self) {
        let lo = self.lockout().clone();
        if let Err(e) = self.store.kv_set_json(KV_PAUSE_LOCKOUT, &lo) {
            tracing::warn!("persisting the wrong-token lockout failed: {e:#}");
        }
    }

    // ------------------------------------------------------------ turn off

    /// Tray `PauseProtection`. Order: identity, already off, lockout, policy,
    /// token (Argon2id on a blocking thread). Wrong tokens are counted per
    /// device and persisted before answering.
    pub async fn pause_protection(
        &self,
        token: &str,
        mode: PauseMode,
        minutes: Option<u32>,
        client: &TrayClient,
    ) -> PauseResult {
        let _g = self.pause_op.lock().await;
        let Some(user) = client.user.clone().or_else(|| client.user_sid.clone()) else {
            return result_err(
                PauseError::Unidentified,
                "Your Windows identity could not be verified, so protection was not turned off.",
            );
        };
        if let Some(st) = self.pause_state() {
            let mut r = result_err(PauseError::AlreadyOff, "Protection is already turned off.");
            r.state = Some(st);
            return r;
        }
        let now = kestrel_common::now_ms();
        if let Some(until) = self.lockout().locked(now) {
            let mut r = result_err(
                PauseError::LockedOut,
                format!(
                    "Too many wrong tokens. Try again in {}.",
                    wait_phrase(until - now)
                ),
            );
            r.locked_until_ms = Some(until);
            r.attempts_left = Some(0);
            return r;
        }
        let lp = self.policy().local_pause;
        if let Err(d) = lp.check(mode, minutes) {
            let mut r = result_err(PauseError::NotAllowed, denied_message(d));
            r.denied = Some(d);
            return r;
        }
        let cfg = self.config();
        let token = token.trim().to_string();
        let ok = token.len() <= 512
            && tokio::task::spawn_blocking(move || cfg.verify_uninstall_token(&token))
                .await
                .unwrap_or(false);
        let now = kestrel_common::now_ms();
        if !ok {
            let (f, total) = {
                let mut lo = self.lockout();
                let f = lo.record_failure(now);
                (f, lo.total_failures)
            };
            self.persist_lockout();
            tracing::warn!(
                failures = total,
                locked = f.locked_until.is_some(),
                "wrong uninstall token entered to turn protection off"
            );
            if f.report {
                self.report_denied(&user, total, f.locked_until, now);
            }
            return match f.locked_until {
                Some(until) => {
                    let mut r = result_err(
                        PauseError::LockedOut,
                        format!(
                            "Wrong token. Too many wrong tokens: try again in {}.",
                            wait_phrase(until - now)
                        ),
                    );
                    r.locked_until_ms = Some(until);
                    r.attempts_left = Some(0);
                    r
                }
                None => {
                    let mut r = result_err(
                        PauseError::WrongToken,
                        format!(
                            "Wrong token. {} attempt{} left before a lockout.",
                            f.attempts_left,
                            if f.attempts_left == 1 { "" } else { "s" }
                        ),
                    );
                    r.attempts_left = Some(f.attempts_left);
                    r
                }
            };
        }
        self.lockout().record_success();
        self.persist_lockout();
        let st = PauseState {
            mode,
            since_ms: now,
            until_ms: minutes.map(|m| now + m as i64 * 60_000),
            by_user: user.clone(),
        };
        if let Err(e) = self.persist_pause(&Some(st.clone())) {
            tracing::error!("saving the pause failed: {e:#}");
            return result_err(
                PauseError::Internal,
                "Kestrel could not save the change; protection stays on.",
            );
        }
        tracing::warn!(
            mode = mode.as_str(),
            until = ?st.until_ms,
            user = %user,
            "protection turned off from the tray (uninstall token verified)"
        );
        self.enter_pause(mode);
        self.raise_switch_alert(ProtectionSwitch::Off(st.clone()), Some(&user), now);
        self.enqueue(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::Off,
            ts: now,
            state: self.pause_for_upload(),
            reason: None,
            by_user: self.filter().user(&user),
            failures: 0,
            locked_until_ms: None,
        }));
        self.notify_tray(
            ActivityItem {
                id: Uuid::new_v4(),
                ts: now,
                title: format!("Protection turned off ({})", mode.label()),
                body: match (mode, minutes) {
                    (PauseMode::DetectionOnly, _) => {
                        "Kestrel still watches and reports to IT but will not stop anything."
                    }
                    (PauseMode::Full, _) => "Kestrel is not watching this PC.",
                }
                .to_string()
                    + &match minutes {
                        Some(m) => {
                            format!(" It turns back on automatically in {}.", minutes_label(m))
                        }
                        None => " It stays off until it is turned back on.".into(),
                    },
                severity: Severity::Medium,
                alert_id: None,
                file: None,
                action_taken: "Protection turned off".into(),
                review: None,
            },
            true,
            None,
        );
        self.send_heartbeat();
        PauseResult {
            ok: true,
            error: None,
            message: match minutes {
                Some(m) => format!(
                    "Protection is off ({}) for {}. IT has been notified.",
                    mode.label(),
                    minutes_label(m)
                ),
                None => format!(
                    "Protection is off ({}) until it is turned back on. IT has been notified.",
                    mode.label()
                ),
            },
            attempts_left: None,
            locked_until_ms: None,
            denied: None,
            state: Some(st),
        }
    }

    /// Apply a pause to the engine, sensors and (implicitly) hardening.
    fn enter_pause(&self, mode: PauseMode) {
        let _ = self.engine_ctl.send(EngineCtl::Pause(Some(mode)));
        if mode == PauseMode::Full {
            self.stop_sensors_now();
        }
    }

    fn report_denied(
        &self,
        user: &str,
        failures: u32,
        locked_until: Option<TimestampMs>,
        now: TimestampMs,
    ) {
        let filtered = self.filter().user(user);
        self.raise_switch_alert(
            ProtectionSwitch::WrongToken {
                failures,
                locked_until_ms: locked_until,
                by_user: filtered.clone(),
            },
            Some(user),
            now,
        );
        self.enqueue(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::Denied,
            ts: now,
            state: None,
            reason: None,
            by_user: filtered,
            failures,
            locked_until_ms: locked_until,
        }));
    }

    /// Build, scrub and queue a `TP-06` alert. `user` is the raw tray user
    /// (the subject's `user`, pseudonymised by the privacy filter).
    fn raise_switch_alert(&self, sw: ProtectionSwitch, user: Option<&str>, now: TimestampMs) {
        // Summaries name the user: use the uploaded (pseudonymised) form.
        let filter = self.filter();
        let sw = match sw {
            ProtectionSwitch::Off(mut s) => {
                s.by_user = if s.by_user.is_empty() {
                    s.by_user
                } else {
                    filter.user(&s.by_user)
                };
                ProtectionSwitch::Off(s)
            }
            ProtectionSwitch::StillOff(mut s) => {
                if !s.by_user.is_empty() {
                    s.by_user = filter.user(&s.by_user);
                }
                ProtectionSwitch::StillOff(s)
            }
            ProtectionSwitch::On { mut state, reason } => {
                if !state.by_user.is_empty() {
                    state.by_user = filter.user(&state.by_user);
                }
                ProtectionSwitch::On { state, reason }
            }
            other => other,
        };
        let mut alert = protection_alert(&sw, switch_subject(user.map(str::to_string), now), now);
        self.stats
            .alerts
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        filter.scrub_alert(&mut alert);
        self.enqueue(&AgentPayload::Alert(Box::new(alert)));
    }

    // ------------------------------------------------------------- turn on

    /// End the pause (tray, console, expiry or policy). Never needs a token.
    /// Returns the pause that ended (`None` = protection was already on).
    pub async fn resume_protection(
        &self,
        reason: PauseEndReason,
        by_user: String,
    ) -> Option<PauseState> {
        let _g = self.pause_op.lock().await;
        self.resume_locked(reason, by_user).await
    }

    async fn resume_locked(&self, reason: PauseEndReason, by_user: String) -> Option<PauseState> {
        let prev = self.pause_state()?;
        if let Err(e) = self.persist_pause(&None) {
            // Memory is updated by persist only on success: force it, a
            // stale file is re-checked at the next start (and expires).
            tracing::error!("clearing the persisted pause failed: {e:#}");
            *self.pause.write().unwrap_or_else(|e| e.into_inner()) = None;
        }
        let now = kestrel_common::now_ms();
        tracing::warn!(
            reason = reason.as_str(),
            mode = prev.mode.as_str(),
            "protection turned back on"
        );
        let _ = self.engine_ctl.send(EngineCtl::Pause(None));
        if prev.mode == PauseMode::Full || !self.sensors_running() {
            self.restart_sensors();
        }
        // Hardening was not enforced while off: enforce it again now.
        // (In the background: applying it can take a while and the tray waits.)
        self.hardening_kick.notify_one();
        let actor = if by_user.is_empty() {
            None
        } else {
            Some(by_user.as_str())
        };
        self.raise_switch_alert(
            ProtectionSwitch::On {
                state: prev.clone(),
                reason,
            },
            actor.or(Some(prev.by_user.as_str())),
            now,
        );
        let mut up = prev.clone();
        if !up.by_user.is_empty() {
            up.by_user = self.filter().user(&up.by_user);
        }
        self.enqueue(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::On,
            ts: now,
            state: Some(up),
            reason: Some(reason),
            by_user: if by_user.is_empty() {
                String::new()
            } else {
                self.filter().user(&by_user)
            },
            failures: 0,
            locked_until_ms: None,
        }));
        self.notify_tray(
            ActivityItem {
                id: Uuid::new_v4(),
                ts: now,
                title: "Protection turned back on".into(),
                body: match reason {
                    PauseEndReason::Manual => "Protection was turned back on from this app.",
                    PauseEndReason::Expired => {
                        "The time chosen when protection was turned off ran out."
                    }
                    PauseEndReason::Console => "Your IT team turned protection back on.",
                    PauseEndReason::Policy => {
                        "Your organisation's policy no longer allows protection to be off."
                    }
                }
                .into(),
                severity: Severity::Info,
                alert_id: None,
                file: None,
                action_taken: "Protection on".into(),
                review: None,
            },
            true,
            None,
        );
        self.send_heartbeat();
        Some(prev)
    }

    /// Tray `ResumeProtection`.
    pub async fn resume_from_tray(&self, client: &TrayClient) -> PauseResult {
        let user = client
            .user
            .clone()
            .or_else(|| client.user_sid.clone())
            .unwrap_or_default();
        match self.resume_protection(PauseEndReason::Manual, user).await {
            Some(_) => PauseResult {
                ok: true,
                error: None,
                message: "Protection is on again.".into(),
                attempts_left: None,
                locked_until_ms: None,
                denied: None,
                state: None,
            },
            None => result_err(PauseError::NotOff, "Protection is already on."),
        }
    }

    // ---------------------------------------------------- expiry / policy

    /// Turn protection back on when the chosen time has run out.
    pub async fn check_pause_expiry(&self) -> bool {
        let due = self
            .pause_state()
            .is_some_and(|p| p.expired(kestrel_common::now_ms()));
        if due {
            self.resume_protection(PauseEndReason::Expired, String::new())
                .await
                .is_some()
        } else {
            false
        }
    }

    /// A new policy may disable the switch, the chosen mode or shorten the
    /// allowed duration: end or clamp an active pause accordingly.
    pub async fn reconcile_pause_with_policy(&self) {
        let _g = self.pause_op.lock().await;
        let Some(st) = self.pause_state() else {
            return;
        };
        let now = kestrel_common::now_ms();
        match self.policy().local_pause.reconcile(&st, now) {
            None => {
                let reason = if st.expired(now) {
                    PauseEndReason::Expired
                } else {
                    PauseEndReason::Policy
                };
                self.resume_locked(reason, String::new()).await;
            }
            Some(n) if n != st => {
                if let Err(e) = self.persist_pause(&Some(n.clone())) {
                    tracing::error!("saving the shortened pause failed: {e:#}");
                    *self.pause.write().unwrap_or_else(|e| e.into_inner()) = Some(n.clone());
                }
                tracing::warn!(until = ?n.until_ms, "policy change shortened the protection turn-off");
                self.raise_switch_alert(
                    ProtectionSwitch::Clamped(n.clone()),
                    Some(&n.by_user),
                    now,
                );
                self.enqueue(&AgentPayload::Pause(PauseReport {
                    event: PauseEvent::Clamped,
                    ts: now,
                    state: self.pause_for_upload(),
                    reason: Some(PauseEndReason::Policy),
                    by_user: String::new(),
                    failures: 0,
                    locked_until_ms: None,
                }));
                self.send_heartbeat();
            }
            Some(_) => {}
        }
    }
}

/// `Arc` helper used by the policy path (spawned task).
pub(crate) fn spawn_reconcile(core: &Arc<Core>) {
    let c = core.clone();
    tokio::spawn(async move { c.reconcile_pause_with_policy().await });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lockout_escalates_and_persists_shape() {
        let mut l = Lockout::default();
        for i in 1..PAUSE_MAX_FAILURES {
            let f = l.record_failure(1000 + i as i64);
            assert_eq!(f.attempts_left, PAUSE_MAX_FAILURES - i);
            assert!(f.locked_until.is_none());
        }
        // Rate limit: first failure reported, the next ones within a minute not.
        let f = l.record_failure(2000);
        assert_eq!(f.locked_until, Some(2000 + 60_000));
        assert!(f.report, "a lockout start is always reported");
        assert_eq!(l.locked(2000 + 59_999), Some(62_000));
        assert_eq!(l.locked(62_000), None);
        // Second lockout doubles.
        let mut last = None;
        for i in 0..PAUSE_MAX_FAILURES {
            last = l.record_failure(70_000 + i as i64).locked_until;
        }
        assert_eq!(last, Some(70_004 + 120_000));
        // Capped at one hour.
        for round in 0..10 {
            for i in 0..PAUSE_MAX_FAILURES {
                last = l
                    .record_failure(1_000_000 + round * 10_000 + i as i64)
                    .locked_until;
            }
        }
        let start = 1_000_000 + 9 * 10_000 + 4;
        assert_eq!(last, Some(start + PAUSE_LOCKOUT_MAX_MS));
        // Survives a JSON round trip (persisted in the store).
        let back: Lockout = serde_json::from_str(&serde_json::to_string(&l).unwrap()).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.locked(start + 1), Some(start + PAUSE_LOCKOUT_MAX_MS));
        // Success resets the escalation.
        l.record_success();
        assert_eq!(l.failures, 0);
        assert_eq!(l.lockouts, 0);
        assert_eq!(l.locked(start + 1), None);
    }

    #[test]
    fn denied_reports_rate_limited() {
        let mut l = Lockout::default();
        assert!(l.record_failure(0).report);
        assert!(!l.record_failure(10_000).report);
        assert!(l.record_failure(60_000).report);
        assert_eq!(l.total_failures, 3);
    }

    #[test]
    fn escalation_forgotten_after_a_day() {
        let mut l = Lockout::default();
        for i in 0..PAUSE_MAX_FAILURES {
            l.record_failure(i as i64);
        }
        assert_eq!(l.lockouts, 1);
        l.record_failure(LOCKOUT_FORGET_MS + 10);
        assert_eq!(l.lockouts, 0);
        assert_eq!(l.failures, 1);
    }

    #[test]
    fn labels() {
        assert_eq!(minutes_label(15), "15 minutes");
        assert_eq!(minutes_label(60), "1 hour");
        assert_eq!(minutes_label(240), "4 hours");
        assert_eq!(minutes_label(90), "1 h 30 min");
        assert_eq!(wait_phrase(30_000), "30 s");
        assert_eq!(wait_phrase(61_000), "2 minutes");
    }
}

#[cfg(test)]
#[path = "pause_tests.rs"]
mod flow_tests;
