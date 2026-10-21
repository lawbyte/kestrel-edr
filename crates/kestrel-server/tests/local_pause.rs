//! Local "turn protection off" switch, server side: device status `paused`,
//! `pause` in the device API, audit entries from agent reports, the
//! `resume_protection` command, `protection_off` on alerts, sensor-health
//! heuristics quiet while protection is completely off, policy validation.

mod common;

use common::*;
use kestrel_common::{
    now_ms,
    pause::{PauseEndReason, PauseEvent, PauseReport},
    wire::{AgentHealth, AgentPayload, Heartbeat, ServerPayload},
    Alert, PathClass, PauseMode, PauseState, ProcessGuid, ProcessInfo, ResponseAction, RuleMode,
    Severity, SignatureState,
};
use reqwest::Method;
use serde_json::json;
use uuid::Uuid;

fn hb(seq: u64, etw_ok: bool, pause: Option<PauseState>) -> AgentPayload {
    AgentPayload::Heartbeat(Heartbeat {
        seq,
        ts: now_ms(),
        health: AgentHealth {
            etw_ok,
            amsi_ok: true,
            ip_addresses: vec!["10.0.0.8".into()],
            pause,
            ..Default::default()
        },
    })
}

fn state(mode: PauseMode, until: Option<i64>) -> PauseState {
    PauseState {
        mode,
        since_ms: now_ms() - 60_000,
        until_ms: until,
        by_user: r"W\employee".into(),
    }
}

fn tp06_alert(off: Option<PauseMode>) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        ts: now_ms(),
        rule_id: "ST-12".into(),
        rule_name: "Untrusted execution from a user path".into(),
        rule_author: None,
        severity: Severity::High,
        attack: vec![],
        mode: RuleMode::Audit,
        summary: "x.exe ran from Downloads".into(),
        process: ProcessInfo {
            guid: ProcessGuid("g-x".into()),
            pid: 77,
            ppid: 1,
            parent_guid: None,
            image: r"C:\Users\a\Downloads\x.exe".into(),
            cmdline: String::new(),
            user: Some(r"W\employee".into()),
            integrity: None,
            start_ts: now_ms() - 1000,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::Downloads,
        },
        ancestry: vec![],
        data_at_risk: vec![],
        evidence: vec![],
        actions: vec![],
        protection_off: off,
    }
}

#[tokio::test]
async fn paused_status_audit_and_resume_command() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    let agent = enroll(
        ts.grpc_port,
        &ca,
        tok["token"].as_str().unwrap(),
        "W-PAUSE-01",
    )
    .await
    .unwrap();
    let dev_path = format!("/api/devices/{}", agent.device_id);

    // Hello already carries a pause (the agent restarted while paused).
    let mut h = hello(&agent, "W-PAUSE-01");
    h.pause = Some(state(PauseMode::DetectionOnly, Some(now_ms() + 3_600_000)));
    let mut st = connect(ts.grpc_port, &agent, h).await.unwrap();
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { .. }));
    let (pseq, _) = st.recv().await.unwrap();
    st.ack(pseq).await;
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["device"]["status"], "paused", "{d}");
    assert_eq!(d["device"]["pause"]["mode"], "detection_only");

    // Heartbeat with sensors healthy and a pause: paused beats online.
    let p = state(PauseMode::DetectionOnly, Some(now_ms() + 3_600_000));
    let s = st.send(&hb(1, true, Some(p.clone()))).await;
    st.wait_ack(s).await;
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["device"]["status"], "paused");
    assert_eq!(d["device"]["pause"]["by_user"], r"W\employee");
    assert_eq!(d["device"]["health"]["pause"]["mode"], "detection_only");
    let (_, list) = ts.get("/api/devices?status=paused").await;
    assert_eq!(list["total"], 1, "{list}");
    let (_, dash) = ts.get("/api/dashboard").await;
    assert_eq!(dash["devices"]["paused"], 1, "{dash}");

    // Completely off: sensors stopped on purpose. Still `paused` (not
    // degraded) and no TP-SRV-ETW tamper alert.
    let full = state(PauseMode::Full, None);
    let s = st.send(&hb(2, false, Some(full.clone()))).await;
    st.wait_ack(s).await;
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["device"]["status"], "paused");
    let (_, alerts) = ts.get("/api/alerts?limit=100").await;
    assert!(
        !alerts["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["rule_id"] == "TP-SRV-ETW"),
        "{alerts}"
    );

    // Agent reports: off, denied, on → audit entries; status follows at once.
    let s = st
        .send(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::Denied,
            ts: now_ms(),
            state: None,
            reason: None,
            by_user: r"W\other".into(),
            failures: 5,
            locked_until_ms: Some(now_ms() + 60_000),
        }))
        .await;
    st.wait_ack(s).await;
    let s = st
        .send(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::Off,
            ts: now_ms(),
            state: Some(full.clone()),
            reason: None,
            by_user: r"W\employee".into(),
            failures: 0,
            locked_until_ms: None,
        }))
        .await;
    st.wait_ack(s).await;
    let (_, log) = ts
        .get("/api/audit-log?action=device.protection_off_denied")
        .await;
    assert_eq!(log["total"], 1, "{log}");
    assert_eq!(log["items"][0]["details"]["failures"], 5);
    let (_, log) = ts.get("/api/audit-log?action=device.protection_off").await;
    // (The filter is a prefix: `device.protection_off_denied` matches too.)
    let off: Vec<_> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["action"] == "device.protection_off")
        .collect();
    assert_eq!(off.len(), 1, "{log}");
    assert_eq!(off[0]["target"], agent.device_id.to_string());
    assert_eq!(off[0]["details"]["mode"], "full");
    assert_eq!(off[0]["details"]["hostname"], "W-PAUSE-01");
    assert!(!log.to_string().contains("kun_"), "no token in audit");

    // Alerts carry the note.
    let s = st
        .send(&AgentPayload::Alert(Box::new(tp06_alert(Some(
            PauseMode::Full,
        )))))
        .await;
    st.wait_ack(s).await;
    let (_, alerts) = ts.get("/api/alerts?limit=100").await;
    let a = alerts["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["rule_id"] == "ST-12")
        .unwrap()
        .clone();
    assert_eq!(a["protection_off"], "full", "{a}");
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["recent_alerts"][0]["protection_off"], "full");

    // The console turns protection back on: a normal response command.
    let (s, act) = ts
        .post(
            &format!("{dev_path}/actions"),
            json!({"action": {"type": "resume_protection"}, "comment": "done installing"}),
        )
        .await;
    assert_eq!(s, 200, "{act}");
    let (_, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    let ServerPayload::Command { action, .. } = cmd else {
        unreachable!()
    };
    assert_eq!(action, ResponseAction::ResumeProtection);
    let s = st
        .send(&AgentPayload::Pause(PauseReport {
            event: PauseEvent::On,
            ts: now_ms(),
            state: Some(full),
            reason: Some(PauseEndReason::Console),
            by_user: String::new(),
            failures: 0,
            locked_until_ms: None,
        }))
        .await;
    st.wait_ack(s).await;
    let (_, d) = ts.get(&dev_path).await;
    assert!(d["device"]["pause"].is_null(), "{d}");
    assert_ne!(d["device"]["status"], "paused");
    let (_, log) = ts.get("/api/audit-log?action=device.protection_on").await;
    assert_eq!(log["total"], 1, "{log}");
    assert_eq!(log["items"][0]["details"]["reason"], "console");

    // A pause still reported long after its end raises TP-SRV-PAUSE-OVERDUE.
    let s = st
        .send(&hb(
            3,
            true,
            Some(state(PauseMode::DetectionOnly, Some(now_ms() - 3_600_000))),
        ))
        .await;
    st.wait_ack(s).await;
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["device"]["status"], "paused", "{d}");
    let (_, alerts) = ts.get("/api/alerts?limit=100").await;
    assert!(
        alerts["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["rule_id"] == "TP-SRV-PAUSE-OVERDUE"),
        "{alerts}"
    );
    // Back on: online.
    let s = st.send(&hb(4, true, None)).await;
    st.wait_ack(s).await;
    let (_, d) = ts.get(&dev_path).await;
    assert_eq!(d["device"]["status"], "online", "{d}");

    // Policy validation of the new section.
    let (_, mut p) = ts.get("/api/policies/default").await;
    assert_eq!(
        p["local_pause"]["enabled"], true,
        "defaults for old policies"
    );
    assert_eq!(p["local_pause"]["max_minutes"], 480);
    p["local_pause"]["max_minutes"] = json!(0);
    let (s, _) = ts
        .send(Method::PUT, "/api/policies/default", p.clone())
        .await;
    assert_eq!(s, 400);
    p["local_pause"]["max_minutes"] = json!(60);
    p["local_pause"]["allow_full"] = json!(true);
    let (s, np) = ts.send(Method::PUT, "/api/policies/default", p).await;
    assert_eq!(s, 200, "{np}");
    assert_eq!(np["local_pause"]["max_minutes"], 60);
    assert_eq!(np["local_pause"]["allow_full"], true);

    // TP-06 is in the rule catalog.
    let (_, rules) = ts.get("/api/rules?limit=500").await;
    let items = rules["items"].as_array().or(rules.as_array()).unwrap();
    assert!(items.iter().any(|r| r["id"] == "TP-06"), "{rules}");
    drop(st);
    ts.cleanup().await;
}
