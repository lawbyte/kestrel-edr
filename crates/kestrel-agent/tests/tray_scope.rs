//! M3: tray requests are answered for the calling user only (activity,
//! review requests, notifications) and rate limited.

use kestrel_agent::{
    agent::{self, Tuning},
    commands,
    sim::{SimOptions, SimPlatform, SIM_USER},
    store,
    tray::{TrayService, REVIEWS_PER_HOUR},
};
use kestrel_common::{
    tray::{ActivityItem, ReviewState, TrayRequest, TrayResponse},
    wire::AgentPayload,
    Severity,
};
use kestrel_platform::{TrayClient, TrayHandler};
use std::sync::Arc;
use uuid::Uuid;

fn item(title: &str, alert: Option<Uuid>) -> ActivityItem {
    ActivityItem {
        id: Uuid::new_v4(),
        ts: kestrel_common::now_ms(),
        title: title.into(),
        body: String::new(),
        severity: Severity::High,
        alert_id: alert,
        file: None,
        action_taken: "Stopped the app".into(),
        review: None,
    }
}

fn client(sid: &str, user: &str) -> TrayClient {
    TrayClient {
        user_sid: Some(sid.into()),
        user: Some(user.into()),
        session_id: Some(2),
        pid: Some(4242),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tray_requests_are_scoped_to_the_caller() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let ca = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
    commands::write_install_config(
        state,
        &commands::InstallOpts {
            server: "127.0.0.1:1".into(),
            ca: ca.cert.pem(),
            token: "kst_x".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: None,
        speed: 1.0,
        hostname: "SIM-TRAY".into(),
        user: SIM_USER.into(),
    }));
    let handle = agent::start(sim, state.to_path_buf(), Tuning::default())
        .await
        .unwrap();
    let core = handle.core.clone();
    let alice_alert = Uuid::new_v4();
    let bob_alert = Uuid::new_v4();
    let public_alert = Uuid::new_v4();
    core.notify_tray(
        item("alice", Some(alice_alert)),
        false,
        Some("CORP\\alice".into()),
    );
    core.notify_tray(
        item("bob", Some(bob_alert)),
        false,
        Some("S-1-5-21-9-1002".into()),
    );
    core.notify_tray(item("machine", Some(public_alert)), false, None);

    let svc = TrayService::new(core.clone());
    let alice = client("S-1-5-21-9-1001", "CORP\\alice");
    let bob = client("S-1-5-21-9-1002", "CORP\\bob");
    let anon = TrayClient::default();

    let titles = |r: TrayResponse| match r {
        TrayResponse::Activity { items } => {
            let mut t: Vec<String> = items.into_iter().map(|i| i.title).collect();
            t.sort();
            t
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(
        titles(
            svc.handle(TrayRequest::Activity { limit: 50 }, &alice)
                .await
        ),
        ["alice", "machine"]
    );
    assert_eq!(
        titles(svc.handle(TrayRequest::Activity { limit: 50 }, &bob).await),
        ["bob", "machine"]
    );
    assert_eq!(
        titles(svc.handle(TrayRequest::Activity { limit: 50 }, &anon).await),
        ["machine"]
    );

    let review = |id: Uuid| TrayRequest::RequestReview {
        alert_id: id,
        justification: "please".into(),
    };
    // Someone else's alert looks unknown; anonymous callers cannot request.
    assert!(matches!(
        svc.handle(review(bob_alert), &alice).await,
        TrayResponse::Error { .. }
    ));
    assert!(matches!(
        svc.handle(review(public_alert), &anon).await,
        TrayResponse::Error { .. }
    ));
    // Own alert: accepted once, then "already requested" until IT decides.
    assert!(matches!(
        svc.handle(review(alice_alert), &alice).await,
        TrayResponse::Ack { ok: true, .. }
    ));
    assert_eq!(
        core.store.review_state(alice_alert),
        Some(ReviewState::Requested)
    );
    let again = svc.handle(review(alice_alert), &alice).await;
    assert!(matches!(&again, TrayResponse::Ack { message, .. } if message.contains("already")));
    // The queued review request names the pipe client, not the console user.
    let rows = core.store.pending_after(0, 100).unwrap();
    let users: Vec<String> = rows
        .iter()
        .filter(|r| r.kind == "review_request")
        .filter_map(|r| {
            match kestrel_agent::codec::decode::<AgentPayload>(&r.payload, r.compressed).ok()? {
                AgentPayload::ReviewRequest(rr) => Some(rr.user),
                _ => None,
            }
        })
        .collect();
    assert_eq!(users, ["CORP\\alice"]);
    // Per-user hourly cap.
    let mut accepted = 1;
    for _ in 0..REVIEWS_PER_HOUR + 2 {
        let id = Uuid::new_v4();
        core.notify_tray(item("x", Some(id)), false, Some("corp\\alice".into()));
        if matches!(
            svc.handle(review(id), &alice).await,
            TrayResponse::Ack { ok: true, .. }
        ) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, REVIEWS_PER_HOUR);
    // Quick check: the second request within 5 minutes returns the cached result.
    let first = svc.handle(TrayRequest::QuickCheck, &bob).await;
    assert!(matches!(first, TrayResponse::Ack { ok: true, .. }));
    let second = svc.handle(TrayRequest::QuickCheck, &alice).await;
    assert!(
        matches!(&second, TrayResponse::Ack { message, .. } if message.contains("already ran")),
        "{second:?}"
    );
    assert!(core.store.kv_get_i64(store::KV_LAST_CHECK).is_some());
    handle.stop().await;
}
