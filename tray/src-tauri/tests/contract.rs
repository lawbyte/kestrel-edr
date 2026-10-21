//! Contract test: the tray's mirrored protocol types must serialise exactly like
//! `kestrel_common::tray` (the agent's source of truth), in both directions.

use kestrel_common::tray as agent;
use kestrel_tray_lib::{mock, protocol as tray};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;

fn same<A: Serialize + DeserializeOwned, B: Serialize + DeserializeOwned>(a: &A) {
    let ja = serde_json::to_value(a).unwrap();
    let b: B = serde_json::from_value(ja.clone())
        .unwrap_or_else(|e| panic!("tray can't parse agent JSON {ja}: {e}"));
    let jb = serde_json::to_value(&b).unwrap();
    assert_eq!(ja, jb, "JSON differs after round trip");
    let _: A = serde_json::from_value(jb).unwrap();
}

#[test]
fn responses_match_agent() {
    let status = mock::sample_status(tray::ProtectionState::Degraded);
    let items = mock::sample_activity();
    let tray_msgs: Vec<tray::TrayResponse> = vec![
        tray::TrayResponse::Status(status.clone()),
        tray::TrayResponse::Activity {
            items: items.clone(),
        },
        tray::TrayResponse::Ack {
            ok: true,
            message: "ok".into(),
        },
        tray::TrayResponse::Notification(items[0].clone()),
        tray::TrayResponse::Error {
            message: "nope".into(),
        },
        tray::TrayResponse::RemoteSession(mock::sample_remote_session(true)),
        tray::TrayResponse::RemoteSession(tray::RemoteSessionNotice {
            active: false,
            kind: tray::RemoteKind::Files,
            admin_name: "Jane Doe".into(),
            view_only: false,
            reason: String::new(),
            started_at: 1_760_000_000_000,
            ended_at: Some(1_760_000_600_000),
        }),
        tray::TrayResponse::Status(tray::TrayStatus {
            remote_session: Some(mock::sample_remote_session(false)),
            ..status.clone()
        }),
        tray::TrayResponse::ConsentRequest(tray::ConsentRequest {
            request_id: uuid::Uuid::new_v4(),
            kind: tray::RemoteKind::Desktop,
            admin_name: "Jane Doe".into(),
            view_only: true,
            reason: "VPN".into(),
            timeout_secs: 60,
            expires_at: 1_760_000_060_000,
        }),
    ];
    for m in &tray_msgs {
        same::<tray::TrayResponse, agent::TrayResponse>(m);
    }
    for s in ["protected", "attention", "isolated", "degraded", "offline"] {
        let mut v = serde_json::to_value(tray::TrayResponse::Status(status.clone())).unwrap();
        v["state"] = Value::from(s);
        let a: agent::TrayResponse = serde_json::from_value(v.clone()).unwrap();
        let _: tray::TrayResponse =
            serde_json::from_value(serde_json::to_value(a).unwrap()).unwrap();
    }
}

#[test]
fn requests_match_agent() {
    let reqs = vec![
        tray::TrayRequest::Status,
        tray::TrayRequest::Activity { limit: 7 },
        tray::TrayRequest::QuickCheck,
        tray::TrayRequest::RequestReview {
            alert_id: uuid::Uuid::new_v4(),
            justification: "needed for work".into(),
        },
        tray::TrayRequest::Subscribe,
        tray::TrayRequest::SubscribeWith {
            features: vec![tray::FEATURE_REMOTE_SESSION.into()],
        },
        tray::TrayRequest::SubscribeWith { features: vec![] },
        tray::TrayRequest::ConsentResponse {
            request_id: uuid::Uuid::new_v4(),
            allow: false,
        },
    ];
    for r in &reqs {
        same::<tray::TrayRequest, agent::TrayRequest>(r);
    }
    // Defaults: activity without a limit is 50 on both sides.
    let a: agent::TrayRequest = serde_json::from_str(r#"{"op":"activity"}"#).unwrap();
    let t: tray::TrayRequest = serde_json::from_str(r#"{"op":"activity"}"#).unwrap();
    assert_eq!(
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(t).unwrap()
    );
}

#[test]
fn remote_session_contract() {
    assert_eq!(tray::FEATURE_REMOTE_SESSION, agent::FEATURE_REMOTE_SESSION);
    assert_eq!(tray::FEATURE_REMOTE_CONSENT, agent::FEATURE_REMOTE_CONSENT);

    // Exact wire shapes from the contract.
    let req = serde_json::to_value(tray::TrayRequest::SubscribeWith {
        features: vec![tray::FEATURE_REMOTE_SESSION.into()],
    })
    .unwrap();
    assert_eq!(
        req,
        serde_json::json!({"op":"subscribe_with","features":["remote_session"]})
    );
    // `features` defaults to empty on both sides.
    let a: agent::TrayRequest = serde_json::from_str(r#"{"op":"subscribe_with"}"#).unwrap();
    let t: tray::TrayRequest = serde_json::from_str(r#"{"op":"subscribe_with"}"#).unwrap();
    assert_eq!(
        serde_json::to_value(a).unwrap(),
        serde_json::to_value(t).unwrap()
    );

    // Minimal push (serde defaults for reason / ended_at) parses on both sides.
    let minimal = r#"{"type":"remote_session","active":true,"admin_name":"Jane","view_only":true,"started_at":5}"#;
    let a: agent::TrayResponse = serde_json::from_str(minimal).unwrap();
    let t: tray::TrayResponse = serde_json::from_str(minimal).unwrap();
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&t).unwrap()
    );
    let tray::TrayResponse::RemoteSession(n) = t else {
        panic!("variant")
    };
    assert_eq!(
        (n.reason.as_str(), n.ended_at, n.kind),
        ("", None, tray::RemoteKind::Desktop)
    );

    // Status from an older agent (no remote_session field) still parses.
    let mut v = serde_json::to_value(tray::TrayResponse::Status(mock::sample_status(
        tray::ProtectionState::Protected,
    )))
    .unwrap();
    v.as_object_mut().unwrap().remove("remote_session");
    let t: tray::TrayResponse = serde_json::from_value(v).unwrap();
    assert!(matches!(t, tray::TrayResponse::Status(ref s) if s.remote_session.is_none()));
}
