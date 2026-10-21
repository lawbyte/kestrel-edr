//! Remote removal on a running agent core (SimPlatform, no server).
//! Included from `remote_uninstall.rs`.

use super::*;
use crate::agent::{self, AgentHandle, Tuning};
use crate::config::AgentConfig;
use crate::sim::{SimOptions, SimPlatform, SIM_USER};
use kestrel_platform::{ActionOrigin, Platform};
use std::path::Path;

const TOKEN: &str = "kun_removal_test_token_0123";

fn tuning() -> Tuning {
    Tuning {
        heartbeat: Duration::from_millis(300),
        tick: Duration::from_millis(50),
        housekeeping: Duration::from_millis(100),
        // `auto_ack` plays the server.
        removal_ack_wait: Duration::from_secs(5),
        ..Tuning::default()
    }
}

fn setup(state: &Path) {
    let mut cfg = AgentConfig {
        // Nothing listens here: the transport just keeps retrying.
        server: "127.0.0.1:9".into(),
        hostname: Some("SIM-REMOVE".into()),
        ..AgentConfig::default()
    };
    cfg.set_uninstall_token(TOKEN).unwrap();
    cfg.save(state).unwrap();
}

async fn start(state: &Path) -> (AgentHandle, Arc<SimPlatform>) {
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: None,
        speed: 1.0,
        hostname: "SIM-REMOVE".into(),
        user: SIM_USER.into(),
    }));
    let h = agent::start(sim.clone(), state.to_path_buf(), tuning())
        .await
        .unwrap();
    (h, sim)
}

fn results(core: &Core, id: Uuid) -> Vec<ActionOutcome> {
    core.store
        .pending_after(0, 10_000)
        .unwrap()
        .into_iter()
        .filter_map(|i| crate::codec::decode::<AgentPayload>(&i.payload, i.compressed).ok())
        .filter_map(|p| match p {
            AgentPayload::ActionResult {
                command_id,
                outcome,
            } if command_id == id => Some(outcome),
            _ => None,
        })
        .collect()
}

/// Play the server: ack everything in the outbox.
fn auto_ack(core: &Arc<Core>) {
    let c = core.clone();
    tokio::spawn(async move {
        while !c.shutdown.is_cancelled() {
            let _ = c.store.ack(u64::MAX >> 1);
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
}

/// Outcome recorded in the command ledger (what a redelivery re-sends).
fn ledger(core: &Core, id: Uuid) -> Option<ActionOutcome> {
    core.store.command_outcome(id).unwrap()
}

fn secret(tokens: &[&str]) -> Option<CommandSecret> {
    Some(CommandSecret {
        uninstall_tokens: tokens.iter().map(|t| t.to_string()).collect(),
    })
}

fn marker(core: &Core) -> Option<Marker> {
    core.store
        .kv_get(KV_REMOTE_UNINSTALL)
        .unwrap()
        .filter(|s| !s.is_empty())
        .and_then(|s| serde_json::from_str(&s).ok())
}

#[tokio::test]
async fn verified_token_starts_the_helper() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let (h, sim) = start(dir.path()).await;
    let core = h.core.clone();
    auto_ack(&core);
    let id = Uuid::new_v4();
    // The pending (rotated) token is tried too: the matching one is used.
    core.run_command_with(
        id,
        ResponseAction::UninstallAgent { purge_data: true },
        secret(&["kun_old_token_that_does_not_match", TOKEN]),
    )
    .await;
    assert_eq!(sim.uninstalls(), vec![true]);
    let r = ledger(&core, id).unwrap();
    assert!(r.ok, "{r:?}");
    assert_eq!(r.artifact.as_deref(), Some(UNINSTALL_STARTED));
    assert!(!r.detail.contains(TOKEN));
    assert_eq!(marker(&core).map(|m| m.command_id), Some(id));
    // The employee is told before the helper starts.
    let act = core.store.activity(50).unwrap();
    assert!(
        act.iter()
            .any(|a| a.title == "IT is removing Kestrel from this PC"),
        "{act:?}"
    );
    // A redelivered command never starts a second removal.
    core.run_command_with(
        id,
        ResponseAction::UninstallAgent { purge_data: true },
        secret(&[TOKEN]),
    )
    .await;
    assert_eq!(sim.uninstalls().len(), 1);
    h.stop().await;
}

#[tokio::test]
async fn token_mismatch_is_refused_with_an_outcome() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let (h, sim) = start(dir.path()).await;
    let core = h.core.clone();
    let id = Uuid::new_v4();
    core.run_command_with(
        id,
        ResponseAction::UninstallAgent { purge_data: false },
        secret(&["kun_rotated_meanwhile"]),
    )
    .await;
    assert!(sim.uninstalls().is_empty());
    let r = results(&core, id);
    assert_eq!(r.len(), 1);
    assert!(!r[0].ok);
    assert_eq!(r[0].artifact.as_deref(), Some(UNINSTALL_FAILED));
    assert!(r[0].detail.contains("token mismatch"), "{}", r[0].detail);
    assert!(!r[0].detail.contains("kun_rotated_meanwhile"));
    assert!(marker(&core).is_none());
    // No secret at all (e.g. a forged / replayed command without it).
    let id2 = Uuid::new_v4();
    core.run_command_with(
        id2,
        ResponseAction::UninstallAgent { purge_data: false },
        None,
    )
    .await;
    assert!(sim.uninstalls().is_empty());
    assert!(!results(&core, id2)[0].ok);
    h.stop().await;
}

#[tokio::test]
async fn never_from_the_engine_or_locally() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let (h, sim) = start(dir.path()).await;
    let core = h.core.clone();
    let a = ResponseAction::UninstallAgent { purge_data: true };
    for origin in [
        ActionOrigin::Engine,
        ActionOrigin::Local,
        ActionOrigin::ServerCommand,
    ] {
        let o = core.execute_action_as(&a, origin).await;
        assert!(!o.ok && o.detail.starts_with("refused"), "{o:?}");
    }
    // `run_command` without the delivery-time secret cannot remove either.
    let id = Uuid::new_v4();
    core.run_command(id, a).await;
    assert!(!results(&core, id)[0].ok);
    assert!(sim.uninstalls().is_empty());
    assert!(sim.supports_remote_uninstall());
    h.stop().await;
}

#[tokio::test]
async fn helper_failure_is_reported_with_its_result() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let (h, sim) = start(dir.path()).await;
    let core = h.core.clone();
    auto_ack(&core);
    let id = Uuid::new_v4();
    core.run_command_with(
        id,
        ResponseAction::UninstallAgent { purge_data: false },
        secret(&[TOKEN]),
    )
    .await;
    assert_eq!(sim.uninstalls().len(), 1);
    std::fs::write(
        sim.uninstall_result_path(),
        r#"{"exit_code":2,"outcome":"failed","msi_code":1618,"message":"another installation was in progress (Windows Installer error 1618); try again later","log":null}"#,
    )
    .unwrap();
    sim.set_uninstall_exit(Some(2));
    let start = Instant::now();
    let failed = loop {
        if let Some(f) = ledger(&core, id).filter(|o| !o.ok) {
            break f;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "no failure outcome"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(failed.artifact.as_deref(), Some(UNINSTALL_FAILED));
    assert!(failed.detail.contains("1618"), "{}", failed.detail);
    assert!(marker(&core).is_none());
    assert!(!sim.uninstall_result_path().exists());
    h.stop().await;
}

#[tokio::test]
async fn result_after_restart_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let id = Uuid::new_v4();
    {
        let st = crate::store::Store::open(dir.path()).unwrap();
        st.kv_set_json(
            KV_REMOTE_UNINSTALL,
            &Marker {
                command_id: id,
                started_ms: 1,
                purge_data: false,
            },
        )
        .unwrap();
    }
    std::fs::write(
        dir.path().join(kestrel_platform::UNINSTALL_RESULT_FILE),
        r#"{"exit_code":1,"outcome":"wrong_token","msi_code":1603,"message":"the Kestrel package refused the uninstall token (token mismatch)","log":"C:\\x.log"}"#,
    )
    .unwrap();
    let (h, _sim) = start(dir.path()).await;
    let core = h.core.clone();
    let start = Instant::now();
    let failed = loop {
        if let Some(f) = results(&core, id).into_iter().next() {
            break f;
        }
        assert!(start.elapsed() < Duration::from_secs(15), "not reported");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert!(!failed.ok);
    assert!(failed.detail.contains("refused the uninstall token"));
    assert!(marker(&core).is_none());
    h.stop().await;
}

#[tokio::test]
async fn not_started_without_the_servers_ack() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path());
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: dir.path().to_path_buf(),
        replay: None,
        speed: 1.0,
        hostname: "SIM-REMOVE".into(),
        user: SIM_USER.into(),
    }));
    let h = agent::start(
        sim.clone(),
        dir.path().to_path_buf(),
        Tuning {
            removal_ack_wait: Duration::from_millis(300),
            ..tuning()
        },
    )
    .await
    .unwrap();
    let core = h.core.clone();
    let id = Uuid::new_v4();
    core.run_command_with(
        id,
        ResponseAction::UninstallAgent { purge_data: false },
        secret(&[TOKEN]),
    )
    .await;
    assert!(sim.uninstalls().is_empty(), "never started unconfirmed");
    let r = results(&core, id);
    assert!(
        r.iter().any(|o| o.ok),
        "started outcome still queued: {r:?}"
    );
    let last = r.last().unwrap();
    assert!(!last.ok && last.detail.contains("did not confirm"), "{r:?}");
    assert!(marker(&core).is_none());
    h.stop().await;
}
