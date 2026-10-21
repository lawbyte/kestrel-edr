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
