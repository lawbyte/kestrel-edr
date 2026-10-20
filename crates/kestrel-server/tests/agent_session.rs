//! Enrollment (token → CSR → cert) and a full gRPC agent session:
//! hello → policy/rules push → alert → incident with checklist → command
//! round-trip → acks, outbox dedupe, tamper heuristics, policy push, revocation.

mod common;

use common::*;
use kestrel_common::{
    now_ms,
    wire::{AgentHealth, AgentPayload, Heartbeat, ReviewRequest, ServerPayload},
    ActionOutcome, Alert, DataCategory, Event, EventData, NetProto, PathClass, ProcessGuid,
    ProcessInfo, ProcessStart, ResponseAction, RuleMode, Severity, SignatureState,
};
use reqwest::Method;
use serde_json::{json, Value};
use uuid::Uuid;

fn proc_info(guid: &str, image: &str, parent: Option<&str>, pid: u32) -> ProcessInfo {
    ProcessInfo {
        guid: ProcessGuid(guid.into()),
        pid,
        ppid: 1,
        parent_guid: parent.map(|p| ProcessGuid(p.into())),
        image: image.into(),
        cmdline: format!("\"{image}\""),
        user: Some("ACME\\alice".into()),
        integrity: None,
        start_ts: now_ms() - 5000,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unsigned,
        sha256: Some("a".repeat(64)),
        motw_zone: Some(3),
        file_size: Some(1_234_567),
        path_class: PathClass::of(image),
    }
}

pub fn stealer_alert(rule: &str, sev: Severity) -> Alert {
    let now = now_ms();
    Alert {
        id: Uuid::new_v4(),
        ts: now,
        rule_id: rule.into(),
        rule_name: "Browser credential store read by untrusted process".into(),
        rule_author: None,
        severity: sev,
        attack: vec!["T1555.003".into()],
        mode: RuleMode::Protect,
        summary: "setup_x64.exe read Chrome 'Login Data' and connected to 203.0.113.7".into(),
        process: proc_info(
            "g-setup",
            r"C:\Users\alice\Downloads\setup_x64.exe",
            Some("g-explorer"),
            4242,
        ),
        ancestry: vec![proc_info(
            "g-explorer",
            r"C:\Windows\explorer.exe",
            None,
            900,
        )],
        data_at_risk: vec![DataCategory::BrowserPasswords, DataCategory::BrowserCookies],
        evidence: vec![Event {
            ts: now,
            pid: 4242,
            guid: ProcessGuid("g-setup".into()),
            data: EventData::NetConnect {
                proto: NetProto::Tcp,
                dst_ip: "203.0.113.7".into(),
                dst_port: 443,
                src_port: 50123,
                dst_host: Some("api.telegram.org".into()),
                bytes_sent: Some(2_200_000),
            },
        }],
        actions: vec![ActionOutcome {
            action: ResponseAction::KillProcess {
                pid: 4242,
                guid: Some(ProcessGuid("g-setup".into())),
                tree: true,
            },
            ok: true,
            detail: String::new(),
            ts: now,
            artifact: None,
        }],
    }
}

fn hb(seq: u64, etw_ok: bool, lost: u64) -> AgentPayload {
    AgentPayload::Heartbeat(Heartbeat {
        seq,
        ts: now_ms(),
        health: AgentHealth {
            etw_ok,
            etw_events_lost: lost,
            amsi_ok: true,
            ip_addresses: vec!["10.0.0.7".into()],
            logged_on_user: Some("ACME\\alice".into()),
            hardening: [("block_mshta".to_string(), true)].into_iter().collect(),
            ..Default::default()
        },
    })
}

#[tokio::test]
async fn full_agent_session() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;

    // Installer metadata exposes the CA the MSI pins.
    let (s, inst) = ts.get("/api/agent/installer").await;
    assert_eq!(s, 200);
    let ca_pem = inst["ca_pem"].as_str().unwrap().to_string();
    assert!(ca_pem.contains("BEGIN CERTIFICATE"));
    assert_eq!(inst["server_addr"], "localhost:8443");

    // Enrollment token for a group.
    let (_, g) = ts.post("/api/groups", json!({"name": "Finance"})).await;
    let gid = g["id"].as_str().unwrap().to_string();
    let (s, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"group_id": gid, "expires_in_days": 7, "max_uses": 1}),
        )
        .await;
    assert_eq!(s, 200, "{tok}");
    let token = tok["token"].as_str().unwrap().to_string();
    assert!(tok["install_command"].as_str().unwrap().contains("msiexec"));
    let (_, toks) = ts.get("/api/enrollment-tokens").await;
    assert!(
        toks[0].get("token").is_none(),
        "full token is shown once only"
    );

    // Bad token is rejected; good token yields a cert with CN = device id.
    let err = enroll(ts.grpc_port, &ca_pem, "kte_bogus", "FIN-LAPTOP-07")
        .await
        .err()
        .unwrap();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let agent = enroll(ts.grpc_port, &ca_pem, &token, "FIN-LAPTOP-07")
        .await
        .expect("enroll");
    let der = rustls_pemfile::certs(&mut agent.cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (cn, _) = kestrel_server::pki::cert_cn_serial(&der).unwrap();
    assert_eq!(cn, agent.device_id.to_string());
    // max_uses = 1
    let err = enroll(ts.grpc_port, &ca_pem, &token, "OTHER")
        .await
        .err()
        .unwrap();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // Connect requires a client certificate.
    let no_cert = TestAgent {
        device_id: agent.device_id,
        cert_pem: String::new(),
        key_pem: String::new(),
        ca_pem: ca_pem.clone(),
    };
    let ch = channel(ts.grpc_port, &ca_pem, None).await.unwrap();
    let mut client = kestrel_server::grpc::pb::agent_service_client::AgentServiceClient::new(ch);
    let (txx, rxx) = tokio::sync::mpsc::channel(1);
    txx.send(kestrel_server::grpc::pb::AgentEnvelope {
        seq: 0,
        compressed: false,
        payload: serde_json::to_vec(&AgentPayload::Hello(hello(&no_cert, "x"))).unwrap(),
    })
    .await
    .unwrap();
    let err = client
        .connect(tokio_stream::wrappers::ReceiverStream::new(rxx))
        .await
        .err()
        .unwrap();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);

    // ---- live session
    let mut st = connect(ts.grpc_port, &agent, hello(&agent, "FIN-LAPTOP-07"))
        .await
        .expect("connect");
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { device_id, .. } if device_id == agent.device_id));
    let (pseq, p) = st.recv().await.unwrap();
    let pol = match p {
        ServerPayload::Policy(p) => p,
        other => panic!("expected Policy, got {other:?}"),
    };
    assert_eq!(pol.id, "default");
    assert_eq!(pol.branding.org_name, "Acme Pte Ltd");
    let (_, r) = st.recv().await.unwrap();
    assert!(matches!(r, ServerPayload::Rules(_)), "{r:?}");
    st.ack(pseq).await;

    let s1 = st.send(&hb(1, true, 0)).await;
    st.wait_ack(s1).await;
    let (_, dev) = ts.get(&format!("/api/devices/{}", agent.device_id)).await;
    assert_eq!(dev["device"]["status"], "online", "{dev}");
    assert_eq!(dev["device"]["group_name"], "Finance");
    assert_eq!(dev["device"]["ip_addresses"][0], "10.0.0.7");
    assert_eq!(
        dev["device"]["policy_version_applied"].as_u64().unwrap(),
        pol.version,
        "policy ack recorded"
    );
    assert!(dev["hardening"]
        .as_array()
        .unwrap()
        .iter()
        .any(|h| h["control"] == "block_mshta" && h["applied"] == true));

    // Events land in the telemetry store.
    let ev = vec![
        Event {
            ts: now_ms() - 3000,
            pid: 4242,
            guid: ProcessGuid("g-setup".into()),
            data: EventData::ProcessStart(ProcessStart {
                ppid: 900,
                parent_guid: Some(ProcessGuid("g-explorer".into())),
                image: r"C:\Users\alice\Downloads\setup_x64.exe".into(),
                cmdline: "setup_x64.exe /S".into(),
                ..Default::default()
            }),
        },
        Event {
            ts: now_ms() - 2000,
            pid: 4242,
            guid: ProcessGuid("g-setup".into()),
            data: EventData::DnsQuery {
                qname: "api.telegram.org".into(),
                answers: vec!["203.0.113.7".into()],
            },
        },
    ];
    let s2 = st.send(&AgentPayload::Events { events: ev }).await;
    st.wait_ack(s2).await;
    let (s, evs) = ts
        .get(&format!(
            "/api/devices/{}/events?kinds=dns_query",
            agent.device_id
        ))
        .await;
    assert_eq!(s, 200);
    assert_eq!(evs["items"].as_array().unwrap().len(), 1);
    assert_eq!(evs["items"][0]["qname"], "api.telegram.org");
    assert_eq!(
        evs["items"][0]["process_image"],
        r"C:\Users\alice\Downloads\setup_x64.exe"
    );
    let (_, procs) = ts
        .get(&format!("/api/devices/{}/processes", agent.device_id))
        .await;
    assert_eq!(
        procs["items"][0]["image"],
        r"C:\Users\alice\Downloads\setup_x64.exe"
    );

    // Outbox replay of an already-stored seq is deduped but still acked.
    st.send_seq(s2, &AgentPayload::Events { events: vec![] })
        .await;
    st.wait_ack(s2).await;

    // Alert → incident with storyline + checklist.
    let alert = stealer_alert("ST-04", Severity::High);
    let s3 = st.send(&AgentPayload::Alert(Box::new(alert.clone()))).await;
    st.wait_ack(s3).await;
    let (_, incs) = ts.get("/api/incidents?status=open,in_progress").await;
    assert_eq!(incs["total"], 1, "{incs}");
    let inc = &incs["items"][0];
    assert_eq!(
        inc["title"],
        "Credential theft by setup_x64.exe on FIN-LAPTOP-07"
    );
    assert_eq!(inc["severity"], "high");
    assert_eq!(inc["contained"], true, "auto-kill contains it");
    // 70 + 10 (data) + 10 (exfil rule ST-04) + 0 (contained)
    assert_eq!(inc["priority"], 90);
    let iid = inc["id"].as_str().unwrap().to_string();
    let (s, det) = ts.get(&format!("/api/incidents/{iid}")).await;
    assert_eq!(s, 200);
    assert!(det["storyline"].as_str().unwrap().contains("setup_x64.exe"));
    assert_eq!(det["alerts"].as_array().unwrap().len(), 1);
    assert!(det["process_tree"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["guid"] == "g-setup" && n["is_root"] == true));
    assert!(det["network"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["dst_ip"] == "203.0.113.7" && n["blocked"] == false));
    let checklist = det["checklist"].as_array().unwrap();
    assert!(checklist
        .iter()
        .any(|c| c["kind"] == "done" && c["done"] == true));
    assert!(checklist.iter().any(|c| c["kind"] == "manual"
        && c["text"]
            .as_str()
            .unwrap()
            .contains("Revoke all active web sessions")));
    let block = checklist
        .iter()
        .find(|c| c["kind"] == "approve" && c["text"] == "Block destination 203.0.113.7")
        .expect("block item");
    assert!(checklist
        .iter()
        .any(|c| c["kind"] == "approve" && c["text"] == "Isolate host FIN-LAPTOP-07"));
    // The automatic kill is listed as a ResponseActionRow with requested_by = null.
    assert!(det["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["requested_by"].is_null() && a["status"] == "succeeded"));

    // Approve "Block destination" → Command delivered on the stream.
    let (s, item) = ts
        .post(
            &format!(
                "/api/incidents/{iid}/checklist/{}",
                block["id"].as_str().unwrap()
            ),
            json!({"done": true}),
        )
        .await;
    assert_eq!(s, 200, "{item}");
    assert_eq!(item["done"], true);
    let (cseq, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    let (command_id, action) = match cmd {
        ServerPayload::Command { command_id, action } => (command_id, action),
        _ => unreachable!(),
    };
    assert_eq!(
        action,
        ResponseAction::BlockDestination {
            ip: "203.0.113.7".into(),
            port: None,
            image: None,
            ttl_secs: None
        }
    );
    st.ack(cseq).await;
    let s4 = st
        .send(&AgentPayload::ActionResult {
            command_id,
            outcome: ActionOutcome {
                action: action.clone(),
                ok: true,
                detail: "WFP filter added".into(),
                ts: now_ms(),
                artifact: Some("wfp-filter-77".into()),
            },
        })
        .await;
    st.wait_ack(s4).await;
    let (_, acts) = ts
        .get(&format!("/api/actions?device_id={}", agent.device_id))
        .await;
    let row = acts["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == command_id.to_string())
        .expect("action row")
        .clone();
    assert_eq!(row["status"], "succeeded");
    assert_eq!(row["result_detail"], "WFP filter added");
    assert_eq!(row["artifact"], "wfp-filter-77");
    assert_eq!(row["requested_by"]["email"], "admin@acme.test");
    let (_, det) = ts.get(&format!("/api/incidents/{iid}")).await;
    assert!(det["network"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n["dst_ip"] == "203.0.113.7" && n["blocked"] == true));

    // Manual console action (privilege-checked) → command.
    let (s, row) = ts
        .post(
            &format!("/api/devices/{}/actions", agent.device_id),
            json!({"action": {"type": "collect_triage"}, "comment": "triage"}),
        )
        .await;
    assert_eq!(s, 200, "{row}");
    assert_eq!(row["status"], "sent");
    let (_, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    assert!(matches!(
        cmd,
        ServerPayload::Command {
            action: ResponseAction::CollectTriage,
            ..
        }
    ));

    // A second alert in the same tree joins the incident.
    let mut a2 = stealer_alert("ST-14", Severity::Critical);
    a2.actions.clear();
    let s5 = st.send(&AgentPayload::Alert(Box::new(a2))).await;
    st.wait_ack(s5).await;
    let (_, incs) = ts.get("/api/incidents").await;
    assert_eq!(incs["total"], 1);
    assert_eq!(incs["items"][0]["alert_count"], 2);
    assert_eq!(incs["items"][0]["severity"], "critical");

    // Review request from the tray → decision is sent back.
    let s6 = st
        .send(&AgentPayload::ReviewRequest(ReviewRequest {
            alert_id: alert.id,
            user: "alice".into(),
            justification: "it's our installer".into(),
            ts: now_ms(),
        }))
        .await;
    st.wait_ack(s6).await;
    let (_, rr) = ts.get("/api/review-requests?state=requested").await;
    assert_eq!(rr.as_array().unwrap().len(), 1);
    assert_eq!(rr[0]["rule_name"], alert.rule_name.as_str());
    let (s, dec) = ts
        .post(
            &format!(
                "/api/review-requests/{}/decision",
                rr[0]["id"].as_str().unwrap()
            ),
            json!({"approved": true, "message": "ok", "create_exclusion": true}),
        )
        .await;
    assert_eq!(s, 200, "{dec}");
    assert_eq!(dec["state"], "approved");
    let (_, d, others) = st
        .recv_until(|p| matches!(p, ServerPayload::ReviewDecision { .. }))
        .await;
    assert!(matches!(
        d,
        ServerPayload::ReviewDecision { approved: true, .. }
    ));
    // Exclusion creation bumped the Finance policy (default) and pushed it.
    let (_, ex) = ts.get("/api/exclusions").await;
    assert_eq!(ex[0]["kind"], "sha256");
    assert_eq!(ex[0]["created_by"], "admin@acme.test");
    let pushed = others
        .iter()
        .any(|p| matches!(p, ServerPayload::Policy(pp) if pp.exclusions.len() == 1));
    let pushed = pushed
        || matches!(st.recv_until(|p| matches!(p, ServerPayload::Policy(_))).await.1, ServerPayload::Policy(pp) if pp.exclusions.len() == 1);
    assert!(pushed);

    // Policy edit → version bump → pushed to the connected agent.
    let (_, mut p) = ts.get("/api/policies/default").await;
    let old_version = p["version"].as_u64().unwrap();
    assert_eq!(p["isolation_auto_release_hours"], 72);
    assert_eq!(p["ioc_block_ttl_secs"], 86_400);
    assert_eq!(p["ioc_block_host_wide"], false);
    for (k, v) in [
        ("ioc_block_ttl_secs", json!(10)),
        ("isolation_auto_release_hours", json!(10_000)),
    ] {
        let mut bad = p.clone();
        bad[k] = v;
        let (s, e) = ts.send(Method::PUT, "/api/policies/default", bad).await;
        assert_eq!(s, 400, "{k}: {e}");
    }
    p["rules"] = json!({"ST-04": "protect"});
    p["isolation_auto_release_hours"] = json!(24);
    let (s, newp) = ts.send(Method::PUT, "/api/policies/default", p).await;
    assert_eq!(s, 200, "{newp}");
    assert!(newp["version"].as_u64().unwrap() > old_version);
    let (_, pp, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Policy(pp) if pp.rules.contains_key("ST-04")))
        .await;
    if let ServerPayload::Policy(pp) = pp {
        assert_eq!(pp.version, newp["version"].as_u64().unwrap());
        assert_eq!(pp.isolation_auto_release_hours, 24);
    }

    // Tamper heuristics: ETW down → server-side TP alert.
    let s7 = st.send(&hb(2, false, 0)).await;
    st.wait_ack(s7).await;
    let (_, al) = ts.get("/api/alerts?rule_id=TP-SRV-ETW").await;
    assert_eq!(al["total"], 1, "{al}");
    let (_, dev) = ts.get(&format!("/api/devices/{}", agent.device_id)).await;
    assert_eq!(dev["device"]["status"], "degraded");
    // Heartbeat counter reset without reboot.
    let s8 = st.send(&hb(1, true, 0)).await;
    st.wait_ack(s8).await;
    let (_, al) = ts.get("/api/alerts?rule_id=TP-SRV-SEQ-RESET").await;
    assert_eq!(al["total"], 1, "{al}");

    // Dashboard aggregates.
    let (s, dash) = ts.get("/api/dashboard").await;
    assert_eq!(s, 200);
    assert_eq!(dash["devices"]["total"], 1);
    assert!(dash["alerts_24h"].as_i64().unwrap() >= 3);
    assert_eq!(dash["alert_trend"].as_array().unwrap().len(), 14);
    assert!(dash["data_at_risk_30d"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["category"] == "browser_passwords"));

    // Decommission revokes the cert and drops the stream; reconnect is refused.
    let (s, _) = ts
        .send(
            Method::DELETE,
            &format!("/api/devices/{}", agent.device_id),
            json!({}),
        )
        .await;
    assert_eq!(s, 204);
    let ended = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Ok(Some(_)) = st.rx.message().await {}
    })
    .await;
    assert!(ended.is_ok(), "stream should end after decommission");
    let err = connect(ts.grpc_port, &agent, hello(&agent, "FIN-LAPTOP-07"))
        .await
        .err()
        .expect("revoked cert must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");

    ts.cleanup().await;
}

#[tokio::test]
async fn certificate_renewal() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 5}),
        )
        .await;
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap();
    let agent = enroll(ts.grpc_port, ca, tok["token"].as_str().unwrap(), "HOST-1")
        .await
        .unwrap();
    // Renew with the current client cert and no token.
    let ch = channel(ts.grpc_port, ca, Some((&agent.cert_pem, &agent.key_pem)))
        .await
        .unwrap();
    let mut client = kestrel_server::grpc::pb::agent_service_client::AgentServiceClient::new(ch);
    let (csr, _key) = csr();
    let req = kestrel_common::wire::EnrollRequest {
        token: String::new(),
        csr_pem: csr,
        hostname: "HOST-1".into(),
        os: os(),
    };
    let resp = client
        .enroll(kestrel_server::grpc::pb::EnrollEnvelope {
            json: serde_json::to_vec(&req).unwrap(),
        })
        .await
        .unwrap();
    let er: kestrel_common::wire::EnrollResponse =
        serde_json::from_slice(&resp.into_inner().json).unwrap();
    assert_eq!(er.device_id, agent.device_id);
    assert_ne!(er.cert_pem, agent.cert_pem);
    // Without a cert, an empty token is refused.
    let err = enroll(ts.grpc_port, ca, "", "HOST-1").await.err().unwrap();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    let _: Value = Value::Null;
    ts.cleanup().await;
}

/// M5 follow-up: a rotated uninstall token is sent to the agent
/// (`SetUninstallToken`) live or on the next connect, and becomes current only
/// when the agent acks that message; a superseded rotation is never promoted.
#[tokio::test]
async fn uninstall_token_rotation_over_stream() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();
    let (agent, er) = enroll_full(
        ts.grpc_port,
        &ca,
        tok["token"].as_str().unwrap(),
        "ROT-01",
        os(),
    )
    .await
    .unwrap();
    let t0 = er.uninstall_token.clone();
    let reveal_path = format!("/api/devices/{}/uninstall-token/reveal", agent.device_id);
    let rotate_path = format!("/api/devices/{}/uninstall-token/rotate", agent.device_id);
    let device_path = format!("/api/devices/{}", agent.device_id);

    // Offline rotation: kept pending, delivered on the next connect.
    let (s, r1) = ts.post(&rotate_path, json!({})).await;
    assert_eq!(s, 200, "{r1}");
    assert_eq!(r1["sent"], false);
    let t1 = r1["pending_token"].as_str().unwrap().to_string();
    assert_ne!(t1, t0);
    let (_, d) = ts.get(&device_path).await;
    assert_eq!(d["device"]["uninstall_token_pending"], true, "{d}");

    let mut st = connect(ts.grpc_port, &agent, hello(&agent, "ROT-01"))
        .await
        .unwrap();
    let (seq1, p, _) = st
        .recv_until(|p| matches!(p, ServerPayload::SetUninstallToken { .. }))
        .await;
    assert_eq!(p, ServerPayload::SetUninstallToken { token: t1.clone() });

    // A second rotation while connected is sent live and supersedes the first.
    let (s, r2) = ts.post(&rotate_path, json!({})).await;
    assert_eq!(s, 200, "{r2}");
    assert_eq!(r2["sent"], true);
    let t2 = r2["pending_token"].as_str().unwrap().to_string();
    let (seq2, p, _) = st
        .recv_until(|p| matches!(p, ServerPayload::SetUninstallToken { .. }))
        .await;
    assert_eq!(p, ServerPayload::SetUninstallToken { token: t2.clone() });

    // Ack of the superseded token: nothing is promoted.
    st.ack(seq1).await;
    let s1 = st.send(&hb(1, true, 0)).await;
    st.wait_ack(s1).await; // inbound messages are handled in order
    let (_, rv) = ts.post(&reveal_path, json!({})).await;
    assert_eq!(rv["token"], t0.as_str(), "{rv}");
    assert_eq!(rv["pending_token"], t2.as_str());

    // Ack of the current rotation: promoted.
    st.ack(seq2).await;
    let s2 = st.send(&hb(2, true, 0)).await;
    st.wait_ack(s2).await;
    let (_, rv) = ts.post(&reveal_path, json!({})).await;
    assert_eq!(rv["token"], t2.as_str(), "{rv}");
    assert!(rv["pending_token"].is_null());
    let (_, d) = ts.get(&device_path).await;
    assert_eq!(d["device"]["uninstall_token_pending"], false);
    assert_eq!(d["device"]["uninstall_token_set"], true);
    let (_, log) = ts
        .get("/api/audit-log?action=device.uninstall_token_activated")
        .await;
    assert_eq!(log["total"], 1, "{log}");
    assert_eq!(log["items"][0]["target"], agent.device_id.to_string());

    // Nothing pending any more: a reconnect does not resend a token.
    drop(st);
    let mut st = connect(ts.grpc_port, &agent, hello(&agent, "ROT-01"))
        .await
        .unwrap();
    st.seq = s2; // the agent outbox continues its seq numbering
    let s3 = st.send(&hb(3, true, 0)).await;
    let initial = st.wait_ack(s3).await;
    assert!(
        initial
            .iter()
            .all(|p| !matches!(p, ServerPayload::SetUninstallToken { .. })),
        "{initial:?}"
    );
    drop(st);
    ts.cleanup().await;
}
