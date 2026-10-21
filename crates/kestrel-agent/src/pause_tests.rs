//! The whole local protection switch on a running agent core (SimPlatform,
//! no server). Included from `pause.rs` (`flow_tests`).

use super::*;
use crate::agent::{self, AgentHandle, Tuning};
use crate::config::AgentConfig;
use crate::sim::{SimOptions, SimPlatform, SIM_USER};
use kestrel_common::{Policy, ResponseAction};
use kestrel_platform::{ActionOrigin, Platform};
use std::path::Path;
use std::time::Duration;

const TOKEN: &str = "kun_flow_test_token_0123";

fn tuning() -> Tuning {
    Tuning {
        heartbeat: Duration::from_millis(300),
        tick: Duration::from_millis(50),
        housekeeping: Duration::from_millis(100),
        ..Tuning::default()
    }
}

fn setup(state: &Path, policy: Option<Policy>) {
    let mut cfg = AgentConfig {
        // Nothing listens here: the transport just keeps retrying.
        server: "127.0.0.1:9".into(),
        hostname: Some("SIM-PAUSE".into()),
        ..AgentConfig::default()
    };
    cfg.set_uninstall_token(TOKEN).unwrap();
    cfg.save(state).unwrap();
    if let Some(p) = policy {
        let st = crate::store::Store::open(state).unwrap();
        st.kv_set_json(crate::store::KV_POLICY, &p).unwrap();
    }
}

async fn start(state: &Path) -> (AgentHandle, Arc<SimPlatform>) {
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: None,
        speed: 1.0,
        hostname: "SIM-PAUSE".into(),
        user: SIM_USER.into(),
    }));
    let h = agent::start(sim.clone(), state.to_path_buf(), tuning())
        .await
        .unwrap();
    (h, sim)
}

fn client() -> TrayClient {
    TrayClient {
        user_sid: Some("S-1-5-21-1-2-3-1001".into()),
        user: Some(r"W\employee".into()),
        session_id: Some(1),
        pid: Some(4242),
    }
}

fn outbox(core: &Core) -> Vec<AgentPayload> {
    core.store
        .pending_after(0, 10_000)
        .unwrap()
        .into_iter()
        .filter_map(|i| crate::codec::decode(&i.payload, i.compressed).ok())
        .collect()
}

fn reports(core: &Core) -> Vec<PauseReport> {
    outbox(core)
        .into_iter()
        .filter_map(|p| match p {
            AgentPayload::Pause(r) => Some(r),
            _ => None,
        })
        .collect()
}

fn tp06(core: &Core) -> Vec<kestrel_common::Alert> {
    outbox(core)
        .into_iter()
        .filter_map(|p| match p {
            AgentPayload::Alert(a) if a.rule_id == "TP-06" => Some(*a),
            _ => None,
        })
        .collect()
}

fn policy(lp: kestrel_common::LocalPause, version: u64) -> Policy {
    Policy {
        version,
        local_pause: lp,
        ..Policy::default()
    }
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    for _ in 0..200 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("timed out waiting for {what}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_tokens_lock_out_per_device_and_persist() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    for left in (1..PAUSE_MAX_FAILURES).rev() {
        let r = core
            .pause_protection("wrong", PauseMode::DetectionOnly, Some(15), &client())
            .await;
        assert_eq!(r.error, Some(PauseError::WrongToken));
        assert_eq!(r.attempts_left, Some(left));
    }
    // Another pipe client (other user): the same device-wide counter.
    let other = TrayClient {
        user: Some(r"W\other".into()),
        ..client()
    };
    let r = core
        .pause_protection("wrong", PauseMode::DetectionOnly, Some(15), &other)
        .await;
    assert_eq!(r.error, Some(PauseError::LockedOut));
    let until = r.locked_until_ms.unwrap();
    assert!(until > kestrel_common::now_ms() + 50_000);
    // Even the right token is refused while locked out.
    let r = core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, Some(15), &client())
        .await;
    assert_eq!(r.error, Some(PauseError::LockedOut));
    assert!(core.pause_state().is_none());
    assert_eq!(core.pause_offer().locked_until_ms, Some(until));
    // Reports: the first failure and the lockout start (rate-limited).
    let rs = reports(&core);
    assert_eq!(rs.len(), 2, "{rs:?}");
    assert!(rs.iter().all(|r| r.event == PauseEvent::Denied));
    assert_eq!(rs[1].failures, PAUSE_MAX_FAILURES);
    assert_eq!(rs[1].locked_until_ms, Some(until));
    assert_eq!(tp06(&core).len(), 2);
    // The token never reaches the outbox.
    for i in core.store.pending_after(0, 10_000).unwrap() {
        let s: serde_json::Value = crate::codec::decode(&i.payload, i.compressed).unwrap();
        assert!(!s.to_string().contains(TOKEN));
    }
    h.stop().await;
    // Restart: still locked out.
    let (h, _) = start(dir.path()).await;
    let r = h
        .core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, Some(15), &client())
        .await;
    assert_eq!(r.error, Some(PauseError::LockedOut));
    h.stop().await;
    // Lockout over (moved into the past): the right token works.
    {
        let st = crate::store::Store::open(dir.path()).unwrap();
        let mut lo: Lockout = st.kv_get_json(KV_PAUSE_LOCKOUT).unwrap().unwrap();
        assert_eq!(lo.lockouts, 1);
        lo.locked_until = Some(kestrel_common::now_ms() - 1);
        st.kv_set_json(KV_PAUSE_LOCKOUT, &lo).unwrap();
    }
    let (h, _) = start(dir.path()).await;
    let r = h
        .core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, Some(15), &client())
        .await;
    assert!(r.ok, "{r:?}");
    assert_eq!(
        h.core.lockout().lockouts,
        0,
        "success resets the escalation"
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_is_enforced_by_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    let c = client();
    // Defaults: detection only, up to 8 h, no "until turned back on".
    let r = core
        .pause_protection(TOKEN, PauseMode::Full, Some(15), &c)
        .await;
    assert_eq!(r.denied, Some(PauseDenied::ModeNotAllowed));
    let r = core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, None, &c)
        .await;
    assert_eq!(r.denied, Some(PauseDenied::DurationNotAllowed));
    let r = core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, Some(481), &c)
        .await;
    assert_eq!(r.denied, Some(PauseDenied::DurationNotAllowed));
    assert_eq!(r.error, Some(PauseError::NotAllowed));
    // Refusals by policy never count as wrong tokens.
    assert_eq!(core.lockout().failures, 0);
    let offer = core.pause_offer();
    assert_eq!(offer.minutes, vec![15, 60, 240, 480]);
    assert!(!offer.allow_full && !offer.allow_until_resumed && offer.enabled);
    // Unidentified callers are refused.
    let r = core
        .pause_protection(
            TOKEN,
            PauseMode::DetectionOnly,
            Some(15),
            &TrayClient::default(),
        )
        .await;
    assert_eq!(r.error, Some(PauseError::Unidentified));
    // A policy allowing more.
    assert!(core.apply_policy(policy(
        kestrel_common::LocalPause {
            enabled: true,
            allow_full: true,
            max_minutes: 60,
            allow_until_resumed: true,
        },
        10,
    )));
    assert_eq!(core.pause_offer().minutes, vec![15, 60]);
    let r = core
        .pause_protection(TOKEN, PauseMode::Full, Some(240), &c)
        .await;
    assert_eq!(r.denied, Some(PauseDenied::DurationNotAllowed));
    let r = core
        .pause_protection(TOKEN, PauseMode::Full, None, &c)
        .await;
    assert!(r.ok, "{r:?}");
    assert_eq!(r.state.as_ref().unwrap().until_ms, None);
    let again = core
        .pause_protection(TOKEN, PauseMode::Full, None, &c)
        .await;
    assert_eq!(again.error, Some(PauseError::AlreadyOff));
    // Disabled switch.
    core.resume_protection(PauseEndReason::Manual, String::new())
        .await
        .unwrap();
    assert!(core.apply_policy(policy(
        kestrel_common::LocalPause {
            enabled: false,
            ..Default::default()
        },
        11,
    )));
    let r = core
        .pause_protection(TOKEN, PauseMode::DetectionOnly, Some(15), &c)
        .await;
    assert_eq!(r.denied, Some(PauseDenied::Disabled));
    assert!(core.pause_offer().minutes.is_empty());
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn detection_only_refuses_engine_actions_and_resumes_without_token() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, sim) = start(dir.path()).await;
    let core = h.core.clone();
    let padded = format!("  {TOKEN} ");
    let r = core
        .pause_protection(&padded, PauseMode::DetectionOnly, Some(60), &client())
        .await;
    assert!(r.ok, "{r:?}");
    let st = core.pause_state().unwrap();
    assert_eq!(st.by_user, r"W\employee");
    assert_eq!(st.until_ms, Some(st.since_ms + 3_600_000));
    assert!(core.sensors_running(), "detection only keeps the sensors");
    assert_eq!(
        core.health().pause.as_ref().map(|p| p.mode),
        Some(PauseMode::DetectionOnly)
    );
    // Every automatic response type is refused by the agent gate.
    let exe = r"C:\Users\a\Downloads\x.exe";
    let all = [
        ResponseAction::KillProcess {
            pid: 4321,
            guid: None,
            tree: true,
        },
        ResponseAction::SuspendProcess {
            pid: 4321,
            guid: None,
        },
        ResponseAction::QuarantineFile {
            path: exe.into(),
            sha256: None,
        },
        ResponseAction::BlockDestination {
            ip: "203.0.113.9".into(),
            port: None,
            image: None,
            ttl_secs: None,
            ioc_id: None,
        },
        ResponseAction::BlockImageNetwork {
            image: exe.into(),
            ttl_secs: None,
        },
        ResponseAction::IsolateHost { allow_ips: vec![] },
        ResponseAction::RemoveAutorun {
            kind: kestrel_common::AutorunKind::RegistryValue,
            location: r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: Some("x".into()),
            restore_data: None,
        },
        ResponseAction::ApplyHardening,
        ResponseAction::Scan { path: None },
    ];
    let before = sim.executed().len();
    for a in &all {
        let o = core.execute_action(a).await;
        assert!(!o.ok, "{} ran while protection was off", a.name());
        assert!(
            o.detail.contains("protection is turned off"),
            "{}",
            o.detail
        );
    }
    assert_eq!(sim.executed().len(), before, "nothing reached the platform");
    assert!(!sim.is_isolated());
    // Resuming a process is never containment.
    assert!(
        core.execute_action(&ResponseAction::ResumeProcess {
            pid: 4321,
            guid: None
        })
        .await
        .ok
    );
    // Analyst actions still run.
    let o = core
        .execute_action_as(
            &ResponseAction::Scan { path: None },
            ActionOrigin::ServerCommand,
        )
        .await;
    assert!(o.ok, "{}", o.detail);
    // TP-06 (medium, Audit) and the report, both without the token.
    let a = tp06(&core);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].severity, Severity::Medium);
    assert_eq!(a[0].mode, kestrel_common::RuleMode::Audit);
    assert_eq!(a[0].protection_off, Some(PauseMode::DetectionOnly));
    let rs = reports(&core);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].event, PauseEvent::Off);
    // Turn back on from the tray: no token.
    let r = core.resume_from_tray(&client()).await;
    assert!(r.ok, "{r:?}");
    assert!(core.pause_state().is_none());
    assert_eq!(
        core.resume_from_tray(&client()).await.error,
        Some(PauseError::NotOff)
    );
    // Engine actions run again.
    assert!(
        core.execute_action(&ResponseAction::BlockImageNetwork {
            image: exe.into(),
            ttl_secs: None
        })
        .await
        .ok
    );
    let a = tp06(&core);
    assert_eq!(a.len(), 2);
    assert_eq!(a[1].severity, Severity::Info);
    let rs = reports(&core);
    assert_eq!(rs[1].event, PauseEvent::On);
    assert_eq!(rs[1].reason, Some(PauseEndReason::Manual));
    // Tray activity on both changes.
    let items = core.store.activity(10).unwrap();
    assert!(items
        .iter()
        .any(|i| i.title.starts_with("Protection turned off")));
    assert!(items.iter().any(|i| i.title == "Protection turned back on"));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_stops_sensors_and_restarts_them_on_resume() {
    let dir = tempfile::tempdir().unwrap();
    setup(
        dir.path(),
        Some(policy(
            kestrel_common::LocalPause {
                allow_full: true,
                ..Default::default()
            },
            5,
        )),
    );
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    assert!(core.sensors_running());
    let r = core
        .pause_protection(TOKEN, PauseMode::Full, Some(15), &client())
        .await;
    assert!(r.ok, "{r:?}");
    assert!(!core.sensors_running());
    assert_eq!(tp06(&core)[0].severity, Severity::High);
    // Housekeeping (every 100 ms here) must not bring them back.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!core.sensors_running());
    core.restart_sensors();
    assert!(
        !core.sensors_running(),
        "restart refused while completely off"
    );
    // Restart while paused: sensors stay off.
    h.stop().await;
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    assert_eq!(core.pause_mode(), Some(PauseMode::Full));
    assert!(!core.sensors_running());
    // A console command turns it back on.
    let id = Uuid::new_v4();
    core.run_command(id, ResponseAction::ResumeProtection).await;
    assert!(core.pause_state().is_none());
    assert!(core.sensors_running());
    let outcome = outbox(&core)
        .into_iter()
        .find_map(|p| match p {
            AgentPayload::ActionResult {
                command_id,
                outcome,
            } if command_id == id => Some(outcome),
            _ => None,
        })
        .unwrap();
    assert!(
        outcome.ok && outcome.detail.contains("turned back on"),
        "{outcome:?}"
    );
    let on = reports(&core)
        .into_iter()
        .find(|r| r.event == PauseEvent::On)
        .unwrap();
    assert_eq!(on.reason, Some(PauseEndReason::Console));
    // A second command is a harmless no-op.
    let o = core
        .execute_action_as(
            &ResponseAction::ResumeProtection,
            ActionOrigin::ServerCommand,
        )
        .await;
    assert!(o.ok && o.detail.contains("nothing to do"));
    // The engine can never issue it.
    assert!(
        !core
            .execute_action(&ResponseAction::ResumeProtection)
            .await
            .ok
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn auto_resume_live_and_after_downtime() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    assert!(
        core.pause_protection(TOKEN, PauseMode::DetectionOnly, Some(15), &client())
            .await
            .ok
    );
    // Live expiry: move `until` to now (as if 15 minutes passed).
    {
        let mut st = core.pause_state().unwrap();
        st.until_ms = Some(kestrel_common::now_ms());
        core.persist_pause(&Some(st)).unwrap();
    }
    wait_for("automatic turn-on", || core.pause_state().is_none()).await;
    wait_for("on report", || {
        reports(&core)
            .iter()
            .any(|r| r.event == PauseEvent::On && r.reason == Some(PauseEndReason::Expired))
    })
    .await;
    // Expiry while the agent was down.
    assert!(
        core.pause_protection(TOKEN, PauseMode::DetectionOnly, Some(60), &client())
            .await
            .ok
    );
    h.stop().await;
    {
        let st = crate::store::Store::open(dir.path()).unwrap();
        let mut p: PauseState = st
            .kv_get_json::<Option<PauseState>>(KV_PAUSE)
            .unwrap()
            .flatten()
            .unwrap();
        p.until_ms = Some(kestrel_common::now_ms() - 1000);
        st.kv_set_json(KV_PAUSE, &Some(p)).unwrap();
    }
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    assert!(core.pause_state().is_none(), "ran out while down");
    assert!(core.sensors_running());
    let on: Vec<_> = reports(&core)
        .into_iter()
        .filter(|r| r.event == PauseEvent::On)
        .collect();
    assert_eq!(on.len(), 2);
    assert_eq!(on[1].reason, Some(PauseEndReason::Expired));
    // A running pause survives a restart.
    assert!(
        core.pause_protection(TOKEN, PauseMode::DetectionOnly, Some(60), &client())
            .await
            .ok
    );
    let st = core.pause_state();
    h.stop().await;
    let (h, _) = start(dir.path()).await;
    assert_eq!(h.core.pause_state(), st);
    assert_eq!(h.core.pause_mode(), Some(PauseMode::DetectionOnly));
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_change_clamps_or_ends_the_pause() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, _) = start(dir.path()).await;
    let core = h.core.clone();
    assert!(
        core.pause_protection(TOKEN, PauseMode::DetectionOnly, Some(240), &client())
            .await
            .ok
    );
    let since = core.pause_state().unwrap().since_ms;
    // Lower cap: clamped to now + 60 min.
    assert!(core.apply_policy(policy(
        kestrel_common::LocalPause {
            max_minutes: 60,
            ..Default::default()
        },
        20,
    )));
    wait_for("clamp", || {
        core.pause_state()
            .and_then(|p| p.until_ms)
            .is_some_and(|u| u <= kestrel_common::now_ms() + 3_600_000)
    })
    .await;
    let u = core.pause_state().unwrap().until_ms.unwrap();
    assert!(u >= since + 3_590_000 && u < since + 240 * 60_000);
    wait_for("clamped report", || {
        reports(&core)
            .iter()
            .any(|r| r.event == PauseEvent::Clamped)
    })
    .await;
    // Switch disabled: ends now.
    assert!(core.apply_policy(policy(
        kestrel_common::LocalPause {
            enabled: false,
            ..Default::default()
        },
        21,
    )));
    wait_for("policy end", || core.pause_state().is_none()).await;
    wait_for("policy on report", || {
        reports(&core)
            .iter()
            .any(|r| r.event == PauseEvent::On && r.reason == Some(PauseEndReason::Policy))
    })
    .await;
    h.stop().await;
}

/// The tray protocol end to end: JSON over the connection, the answer type.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tray_protocol_round_trip() {
    use kestrel_common::tray::{TrayRequest, TrayResponse};
    use kestrel_platform::TrayHandler;
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, sim) = start(dir.path()).await;
    let svc = crate::tray::TrayService::new(h.core.clone());
    let me = client();
    let req: TrayRequest = serde_json::from_str(&format!(
        r#"{{"op":"pause_protection","token":"{TOKEN}","mode":"detection_only","minutes":15}}"#
    ))
    .unwrap();
    assert!(
        !format!("{req:?}").contains(TOKEN),
        "Debug never prints the token"
    );
    match svc.handle(req, &me).await {
        TrayResponse::PauseResult(r) => assert!(r.ok, "{r:?}"),
        other => panic!("{other:?}"),
    }
    match svc.handle(TrayRequest::Status, &me).await {
        TrayResponse::Status(s) => {
            assert_eq!(s.pause.map(|p| p.mode), Some(PauseMode::DetectionOnly));
            assert!(s.local_pause.unwrap().enabled);
        }
        other => panic!("{other:?}"),
    }
    match svc.handle(TrayRequest::ResumeProtection, &me).await {
        TrayResponse::PauseResult(r) => assert!(r.ok && r.state.is_none(), "{r:?}"),
        other => panic!("{other:?}"),
    }
    let _ = sim.is_isolated();
    h.stop().await;
}
