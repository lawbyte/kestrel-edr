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
        tray::TrayResponse::Status(tray::TrayStatus {
            pause: Some(mock::sample_pause(tray::PauseMode::Full, true)),
            local_pause: Some(tray::PauseOffer {
                locked_until_ms: Some(1_760_000_060_000),
                ..mock::sample_pause_offer(true)
            }),
            ..status.clone()
        }),
        tray::TrayResponse::Status(tray::TrayStatus {
            pause: Some(mock::sample_pause(tray::PauseMode::DetectionOnly, false)),
            local_pause: Some(tray::PauseOffer::default()),
            ..status.clone()
        }),
        tray::TrayResponse::PauseResult(tray::PauseResult {
            ok: true,
            error: None,
            message: "Protection is off.".into(),
            attempts_left: None,
            locked_until_ms: None,
            denied: None,
            state: Some(mock::sample_pause(tray::PauseMode::DetectionOnly, false)),
        }),
    ];
    let errors = [
        (tray::PauseError::WrongToken, None),
        (tray::PauseError::LockedOut, None),
        (
            tray::PauseError::NotAllowed,
            Some(tray::PauseDenied::Disabled),
        ),
        (
            tray::PauseError::NotAllowed,
            Some(tray::PauseDenied::ModeNotAllowed),
        ),
        (
            tray::PauseError::NotAllowed,
            Some(tray::PauseDenied::DurationNotAllowed),
        ),
        (tray::PauseError::AlreadyOff, None),
        (tray::PauseError::NotOff, None),
        (tray::PauseError::Unidentified, None),
        (tray::PauseError::Internal, None),
    ];
    let tray_msgs: Vec<tray::TrayResponse> = tray_msgs
        .into_iter()
        .chain(errors.into_iter().map(|(error, denied)| {
            tray::TrayResponse::PauseResult(tray::PauseResult {
                ok: false,
                error: Some(error),
                message: "m".into(),
                attempts_left: Some(3),
                locked_until_ms: Some(1_760_000_060_000),
                denied,
                state: None,
            })
        }))
        .collect();
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
        tray::TrayRequest::PauseProtection {
            token: tray::TokenInput("kun_abc".into()),
            mode: tray::PauseMode::Full,
            minutes: None,
        },
        tray::TrayRequest::PauseProtection {
            token: tray::TokenInput("kun_abc".into()),
            mode: tray::PauseMode::DetectionOnly,
            minutes: Some(60),
        },
        tray::TrayRequest::ResumeProtection,
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

#[test]
fn pause_contract() {
    // Minimal shapes (serde defaults) parse the same on both sides.
    for line in [
        "{\"op\":\"pause_protection\",\"token\":\"kun_x\"}",
        "{\"op\":\"pause_protection\",\"token\":\"kun_x\",\"mode\":\"full\",\"minutes\":15}",
        "{\"op\":\"resume_protection\"}",
    ] {
        let a: agent::TrayRequest = serde_json::from_str(line).unwrap();
        let t: tray::TrayRequest = serde_json::from_str(line).unwrap();
        assert_eq!(
            serde_json::to_value(a).unwrap(),
            serde_json::to_value(t).unwrap()
        );
    }
    let minimal = "{\"type\":\"pause_result\",\"ok\":false}";
    let a: agent::TrayResponse = serde_json::from_str(minimal).unwrap();
    let t: tray::TrayResponse = serde_json::from_str(minimal).unwrap();
    assert_eq!(
        serde_json::to_value(&a).unwrap(),
        serde_json::to_value(&t).unwrap()
    );
    // Status from an older agent (no pause fields) still parses.
    let mut v = serde_json::to_value(tray::TrayResponse::Status(mock::sample_status(
        tray::ProtectionState::Protected,
    )))
    .unwrap();
    let o = v.as_object_mut().unwrap();
    o.remove("pause");
    o.remove("local_pause");
    let t: tray::TrayResponse = serde_json::from_value(v).unwrap();
    assert!(
        matches!(t, tray::TrayResponse::Status(ref s) if s.pause.is_none() && s.local_pause.is_none())
    );
    // Neither side prints the token.
    let a = agent::TrayRequest::PauseProtection {
        token: kestrel_common::pause::TokenInput("kun_secret".into()),
        mode: Default::default(),
        minutes: None,
    };
    let t = tray::TrayRequest::PauseProtection {
        token: tray::TokenInput("kun_secret".into()),
        mode: Default::default(),
        minutes: None,
    };
    assert!(!format!("{a:?}{t:?}").contains("kun_secret"));
}
