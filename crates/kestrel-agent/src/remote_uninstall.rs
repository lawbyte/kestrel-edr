//! "Remove device" on the agent (`ResponseAction::UninstallAgent`).
//!
//! Only reachable from the authenticated server stream
//! (`ServerPayload::Command` with its delivery-time `secret`):
//! `Core::execute_action_as` refuses the action for every origin, so neither
//! the detection engine nor the tray can start it.
//!
//! 1. Verify one of the delivered tokens against the stored Argon2id hash.
//!    No match (the token was rotated while the PC was offline, or the
//!    server holds an old one) → failure outcome, nothing else happens.
//! 2. Record the "uninstall started" outcome (command ledger + a marker in
//!    the store), tell the employee in the tray, queue the outcome and wait
//!    (bounded) for the server to ack it, so the console sees "removing"
//!    before the service goes away.
//! 3. Start the detached helper (`Platform::start_uninstall_helper`) with
//!    the token on its stdin. While this agent still runs it watches the
//!    helper; a non-zero exit is reported as a failure outcome with the
//!    helper's result file. If the installer rolled back and restarted the
//!    service, the next agent finds the marker and reports the result then.

use crate::agent::Core;
use kestrel_common::{
    tray::ActivityItem,
    wire::{AgentPayload, CommandSecret},
    ActionOutcome, ResponseAction, Severity, UNINSTALL_FAILED, UNINSTALL_STARTED,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Store key of the removal in progress ([`Marker`]).
pub const KV_REMOTE_UNINSTALL: &str = "remote_uninstall";
/// Helper exit / result-file poll interval.
const POLL: Duration = Duration::from_secs(2);
/// After a restart with a removal marker: wait this long for the helper's
/// result file before reporting that the removal did not finish.
const RESULT_WAIT_AFTER_RESTART: Duration = Duration::from_secs(10 * 60);

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Marker {
    pub command_id: Uuid,
    pub started_ms: i64,
    pub purge_data: bool,
}

/// `kestrel-uninstall --quiet` result file (see `kestrel_uninstall::result_json`).
#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct HelperResult {
    #[serde(default)]
    pub exit_code: i32,
    #[serde(default)]
    pub outcome: String,
    #[serde(default)]
    pub msi_code: Option<u32>,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub log: Option<String>,
}

impl HelperResult {
    /// Outcome detail shown in the console.
    pub fn detail(&self) -> String {
        let mut d = format!("uninstall failed: {}", clip(&self.message, 300));
        if let Some(c) = self.msi_code {
            if !d.contains(&c.to_string()) {
                d.push_str(&format!(" (Windows Installer {c})"));
            }
        }
        if let Some(l) = self.log.as_deref().filter(|l| !l.is_empty()) {
            d.push_str(&format!("; installer log on the PC: {}", clip(l, 300)));
        }
        d
    }
}

fn clip(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

fn outcome(purge_data: bool, ok: bool, detail: String, artifact: &str) -> ActionOutcome {
    ActionOutcome {
        action: ResponseAction::UninstallAgent { purge_data },
        ok,
        detail,
        ts: kestrel_common::now_ms(),
        artifact: Some(artifact.to_string()),
    }
}

/// Failure outcome for a helper exit code without (readable) result file.
pub fn exit_detail(code: i32) -> String {
    match code {
        1 => "uninstall failed: the Kestrel package refused the uninstall token".into(),
        c => format!("uninstall failed: the uninstall helper exited with code {c}"),
    }
}

fn report(core: &Core, command_id: Uuid, o: ActionOutcome) {
    if let Err(e) = core.store.record_command(command_id, &o) {
        tracing::warn!("command ledger write failed: {e:#}");
    }
    core.enqueue(&AgentPayload::ActionResult {
        command_id,
        outcome: o,
    });
}

/// Run a remote removal (called once per command id by `Core::run_command`).
/// Returns the outcome recorded for the command.
pub async fn run(
    core: &Arc<Core>,
    command_id: Uuid,
    purge_data: bool,
    secret: Option<CommandSecret>,
) -> ActionOutcome {
    let fail = |d: String| outcome(purge_data, false, d, UNINSTALL_FAILED);
    if !core.platform.supports_remote_uninstall() {
        let o = fail("unsupported: remote removal is not available on this platform".into());
        report(core, command_id, o.clone());
        return o;
    }
    let tokens = secret.map(|s| s.uninstall_tokens).unwrap_or_default();
    if tokens.is_empty() {
        let o = fail("refused: the server sent no uninstall token".into());
        report(core, command_id, o.clone());
        return o;
    }
    let cfg = core.config();
    let matched = tokio::task::spawn_blocking(move || {
        tokens
            .into_iter()
            .find(|t| cfg.verify_uninstall_token(t.trim()))
    })
    .await
    .ok()
    .flatten();
    let Some(mut token) = matched else {
        tracing::warn!(%command_id, "remote removal refused: uninstall token mismatch");
        let o = fail(
            "refused: uninstall token mismatch (the token the server holds does not match this PC; it may have been rotated while the PC was offline). Rotate the token on the device page and try again, or use the uninstall tool on the PC."
                .into(),
        );
        report(core, command_id, o.clone());
        return o;
    };
    let started = outcome(
        purge_data,
        true,
        if purge_data {
            "uninstall token verified; Kestrel is uninstalling itself and will delete its data folder".into()
        } else {
            "uninstall token verified; Kestrel is uninstalling itself".into()
        },
        UNINSTALL_STARTED,
    );
    if let Err(e) = core.store.record_command(command_id, &started) {
        tracing::warn!("command ledger write failed: {e:#}");
    }
    let marker = Marker {
        command_id,
        started_ms: kestrel_common::now_ms(),
        purge_data,
    };
    if let Err(e) = core.store.kv_set_json(KV_REMOTE_UNINSTALL, &marker) {
        tracing::warn!("removal marker not saved: {e:#}");
    }
    core.notify_tray(
        ActivityItem {
            id: Uuid::new_v4(),
            ts: kestrel_common::now_ms(),
            title: "IT is removing Kestrel from this PC".into(),
            body: "Your IT team is uninstalling Kestrel EDR. Kestrel's protection stops when this finishes.".into(),
            severity: Severity::Medium,
            alert_id: None,
            file: None,
            action_taken: "Removing".into(),
            review: None,
        },
        true,
        None,
    );
    let seq = core
        .store
        .enqueue(&AgentPayload::ActionResult {
            command_id,
            outcome: started.clone(),
        })
        .ok();
    core.outbox_notify.notify_one();
    // The server must know the removal started before the agent goes away
    // (it only marks a device removed after a confirmed start). No ack in
    // time → do not start; the PC stays protected and the console shows
    // the failure once the outcome gets through.
    let confirmed = match seq {
        Some(seq) => wait_acked(core, seq, core.tuning.removal_ack_wait).await,
        None => false,
    };
    if !confirmed {
        kestrel_wipe(&mut token);
        let _ = core.store.kv_set(KV_REMOTE_UNINSTALL, "");
        let o = fail(
            "uninstall not started: the server did not confirm the removal in time; request it again"
                .into(),
        );
        report(core, command_id, o.clone());
        return o;
    }
    tracing::info!(%command_id, purge_data, "starting the remote uninstall");
    let r = core.platform.start_uninstall_helper(&token, purge_data);
    kestrel_wipe(&mut token);
    match r {
        Ok(helper) => {
            let c = core.clone();
            tokio::spawn(async move { watch(c, command_id, purge_data, helper).await });
            started
        }
        Err(e) => {
            tracing::error!(%command_id, "uninstall helper not started: {e}");
            let _ = core.store.kv_set(KV_REMOTE_UNINSTALL, "");
            let o = fail(format!("uninstall failed: {}", clip(&e, 500)));
            report(core, command_id, o.clone());
            o
        }
    }
}

fn kestrel_wipe(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8.
    for b in unsafe { s.as_bytes_mut() } {
        // SAFETY: valid, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    s.clear();
}

/// Wait until outbox row `seq` was acked by the server (bounded). True =
/// acked.
async fn wait_acked(core: &Core, seq: u64, max: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < max {
        match core.store.is_pending(seq) {
            Ok(false) => return true,
            Ok(true) => {}
            Err(_) => return false,
        }
        tokio::select! {
            _ = core.shutdown.cancelled() => return false,
            _ = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
    }
    tracing::warn!(
        seq,
        "server did not confirm the removal in time; not starting it"
    );
    false
}

/// Read and delete the helper's result file.
fn take_result(core: &Core) -> Option<HelperResult> {
    let p = core.platform.uninstall_result_path();
    let bytes = std::fs::read(&p).ok()?;
    let _ = std::fs::remove_file(&p);
    serde_json::from_slice::<HelperResult>(&bytes)
        .ok()
        .or_else(|| {
            Some(HelperResult {
                exit_code: 2,
                outcome: "failed".into(),
                msi_code: None,
                message: "the uninstall helper's result could not be read".into(),
                log: None,
            })
        })
}

/// Watch the helper while this agent still runs.
async fn watch(
    core: Arc<Core>,
    command_id: Uuid,
    purge_data: bool,
    mut helper: Box<dyn kestrel_platform::UninstallHelper>,
) {
    loop {
        tokio::select! {
            _ = core.shutdown.cancelled() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
        let Some(code) = helper.try_exit_code() else {
            continue;
        };
        if code == 0 {
            // Removed (the service is normally stopped before this).
            tracing::info!(%command_id, "uninstall helper finished");
            return;
        }
        let detail = take_result(&core)
            .map(|r| r.detail())
            .unwrap_or_else(|| exit_detail(code));
        tracing::error!(%command_id, code, "remote uninstall failed: {detail}");
        let _ = core.store.kv_set(KV_REMOTE_UNINSTALL, "");
        report(
            &core,
            command_id,
            outcome(purge_data, false, detail, UNINSTALL_FAILED),
        );
        return;
    }
}

/// At agent start: a removal marker means the service came back after a
/// remote removal started (installer rollback, failed removal). Report the
/// helper's result (or that none came) for that command.
pub async fn resume_after_restart(core: Arc<Core>) {
    let marker = match core.store.kv_get(KV_REMOTE_UNINSTALL) {
        Ok(Some(s)) if !s.trim().is_empty() => serde_json::from_str::<Marker>(&s).ok(),
        _ => None,
    };
    let Some(m) = marker else {
        return;
    };
    tracing::warn!(command_id = %m.command_id, "agent started after a remote removal began; waiting for its result");
    let start = Instant::now();
    let detail = loop {
        if let Some(r) = take_result(&core) {
            break r.detail();
        }
        if start.elapsed() >= RESULT_WAIT_AFTER_RESTART {
            break "uninstall did not finish: the Kestrel agent started again and the uninstall helper reported no result".to_string();
        }
        tokio::select! {
            _ = core.shutdown.cancelled() => return,
            _ = tokio::time::sleep(POLL) => {}
        }
    };
    let _ = core.store.kv_set(KV_REMOTE_UNINSTALL, "");
    report(
        &core,
        m.command_id,
        outcome(m.purge_data, false, detail, UNINSTALL_FAILED),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_result_detail() {
        let r: HelperResult = serde_json::from_str(
            r#"{"exit_code":1,"outcome":"wrong_token","msi_code":1603,"message":"the Kestrel package refused the uninstall token (token mismatch)","log":"C:\\Windows\\SystemTemp\\k\\a.log"}"#,
        )
        .unwrap();
        let d = r.detail();
        assert!(
            d.starts_with("uninstall failed: the Kestrel package refused"),
            "{d}"
        );
        assert!(d.contains("Windows Installer 1603"), "{d}");
        assert!(d.contains(r"C:\Windows\SystemTemp\k\a.log"), "{d}");
        let r: HelperResult =
            serde_json::from_str(r#"{"exit_code":2,"outcome":"failed","msi_code":1618,"message":"another installation was in progress (Windows Installer error 1618); try again later","log":null}"#)
                .unwrap();
        // The code is not repeated when the message already has it.
        assert_eq!(r.detail().matches("1618").count(), 1, "{}", r.detail());
        assert!(exit_detail(1).contains("refused"));
        assert!(exit_detail(7).contains("code 7"));
    }

    #[test]
    fn marker_round_trip() {
        let m = Marker {
            command_id: Uuid::new_v4(),
            started_ms: 5,
            purge_data: true,
        };
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Marker>(&s).unwrap(), m);
    }
}

#[cfg(test)]
#[path = "remote_uninstall_tests.rs"]
mod flow_tests;
