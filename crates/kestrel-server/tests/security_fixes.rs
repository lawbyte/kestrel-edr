//! Regression tests for the server-side findings of the 2026-10-21 security review.

mod common;

use common::*;
use kestrel_common::{
    now_ms,
    wire::{AgentHealth, AgentPayload, Heartbeat, OsInfo, ReviewRequest, ServerPayload},
    ActionOutcome, Alert, DataCategory, Event, EventData, PathClass, ProcessGuid, ProcessInfo,
    ProcessStart, RuleMode, Severity, SignatureState,
};
use reqwest::Method;
use serde_json::{json, Value};
use uuid::Uuid;

async fn token(ts: &TestServer, uses: i32) -> String {
    let (s, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": uses}),
        )
        .await;
    assert_eq!(s, 200, "{tok}");
    tok["token"].as_str().unwrap().to_string()
}

async fn ca(ts: &TestServer) -> String {
    let (_, inst) = ts.get("/api/agent/installer").await;
    inst["ca_pem"].as_str().unwrap().to_string()
}

fn os_with(hw: &str) -> OsInfo {
    OsInfo {
        hw_uuid: Some(hw.into()),
        ..os()
    }
}

/// Connect and consume the initial Welcome/Policy/Rules burst.
async fn session(ts: &TestServer, agent: &TestAgent, host: &str) -> AgentStream {
    let mut st = connect(ts.grpc_port, agent, hello(agent, host))
        .await
        .expect("connect");
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { .. }), "{w:?}");
    st
}

fn heartbeat(seq: u64, ts: i64, user: Option<&str>) -> AgentPayload {
    AgentPayload::Heartbeat(Heartbeat {
        seq,
        ts,
        health: AgentHealth {
            etw_ok: true,
            logged_on_user: user.map(String::from),
            ..Default::default()
        },
    })
}

fn pinfo(guid: &str, image: &str, user: &str) -> ProcessInfo {
    ProcessInfo {
        guid: ProcessGuid(guid.into()),
        pid: 4242,
        ppid: 1,
        parent_guid: None,
        image: image.into(),
        cmdline: format!("{image} /S"),
        user: Some(user.into()),
        integrity: None,
        start_ts: now_ms() - 5000,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unsigned,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: PathClass::of(image),
    }
}

fn alert(rule: &str) -> Alert {
    Alert {
        id: Uuid::new_v4(),
        ts: now_ms(),
        rule_id: rule.into(),
        rule_name: "Browser credential store read".into(),
        rule_author: None,
        severity: Severity::High,
        attack: vec![],
        mode: RuleMode::Audit,
        summary: "tool.exe read Login Data".into(),
        process: pinfo(
            "g-tool",
            r"C:\Users\alice\Downloads\tool.exe",
            r"CORP\alice",
        ),
        ancestry: vec![],
        data_at_risk: vec![DataCategory::BrowserPasswords],
        evidence: vec![],
        actions: vec![],
    }
}

// ---------------------------------------------------------------- H2 / M5

#[tokio::test]
async fn hw_uuid_reenrollment_creates_new_device_and_flags_duplicate() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let ca = ca(&ts).await;
    let tok = token(&ts, 5).await;
    let hw = Uuid::new_v4().to_string();
    let (victim, er1) = enroll_full(ts.grpc_port, &ca, &tok, "VICTIM-01", os_with(&hw))
        .await
        .unwrap();
    // M5: the server issues the uninstall token at enrollment.
    assert!(
        er1.uninstall_token.starts_with("kun_"),
        "{}",
        er1.uninstall_token
    );
    let mut vs = session(&ts, &victim, "VICTIM-01").await;
    let s1 = vs.send(&heartbeat(1, now_ms(), None)).await;
    vs.wait_ack(s1).await;

    // Attacker with a token and the victim's SMBIOS UUID.
    let (attacker, _) = enroll_full(ts.grpc_port, &ca, &tok, "VICTIM-01", os_with(&hw))
        .await
        .unwrap();
    assert_ne!(
        attacker.device_id, victim.device_id,
        "identity must never be re-bound"
    );

    // The victim keeps working: its certificate was not revoked.
    let s2 = vs.send(&heartbeat(2, now_ms(), None)).await;
    vs.wait_ack(s2).await;
    drop(vs);
    let again = connect(ts.grpc_port, &victim, hello(&victim, "VICTIM-01")).await;
    assert!(again.is_ok(), "victim certificate must stay valid");

    // Both are flagged, and a TP alert was raised on the live victim.
    let (_, d1) = ts.get(&format!("/api/devices/{}", victim.device_id)).await;
    assert_eq!(
        d1["device"]["possible_duplicates"][0],
        attacker.device_id.to_string(),
        "{d1}"
    );
    assert_eq!(d1["duplicates"][0]["id"], attacker.device_id.to_string());
    let (_, d2) = ts
        .get(&format!("/api/devices/{}", attacker.device_id))
        .await;
    assert_eq!(
        d2["device"]["possible_duplicates"][0],
        victim.device_id.to_string()
    );
    let (_, al) = ts.get("/api/alerts?rule_id=TP-SRV-DUP-ENROLL").await;
    assert_eq!(al["total"], 1, "{al}");
    assert_eq!(al["items"][0]["device_id"], victim.device_id.to_string());

    // M5: reveal is privileged and audited.
    let (s, rv) = ts
        .post(
            &format!("/api/devices/{}/uninstall-token/reveal", victim.device_id),
            json!({}),
        )
        .await;
    assert_eq!(s, 200, "{rv}");
    assert_eq!(rv["token"], er1.uninstall_token.as_str());
    assert_eq!(d1["device"]["uninstall_token_set"], true);
    let (s, rot) = ts
        .post(
            &format!("/api/devices/{}/uninstall-token/rotate", victim.device_id),
            json!({}),
        )
        .await;
    assert_eq!(s, 200, "{rot}");
    let (_, rv2) = ts
        .post(
            &format!("/api/devices/{}/uninstall-token/reveal", victim.device_id),
            json!({}),
        )
        .await;
    assert_eq!(rv2["token"], er1.uninstall_token.as_str());
    assert_eq!(rv2["pending_token"], rot["pending_token"]);
    let (_, log) = ts
        .get("/api/audit-log?action=device.uninstall_token_revealed")
        .await;
    assert_eq!(log["total"], 2, "{log}");
    let (s, _) = ts
        .post(
            "/api/users",
            json!({"email": "ro@acme.test", "name": "ro", "role": "readonly", "password": "readonly password"}),
        )
        .await;
    assert_eq!(s, 200);
    let ro = http_client(&ts.web_ca_pem);
    let r = ro
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "ro@acme.test", "password": "readonly password"}))
        .send()
        .await
        .unwrap();
    let lv: Value = r.json().await.unwrap();
    let r = ro
        .post(ts.url(&format!(
            "/api/devices/{}/uninstall-token/reveal",
            victim.device_id
        )))
        .header("X-CSRF-Token", lv["csrf_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // Admin merges the impostor's (empty) history into the victim and retires it.
    let (s, merged) = ts
        .post(
            &format!("/api/devices/{}/merge", victim.device_id),
            json!({"device_id": attacker.device_id}),
        )
        .await;
    assert_eq!(s, 200, "{merged}");
    assert_eq!(merged["possible_duplicates"].as_array().unwrap().len(), 0);
    let err = connect(ts.grpc_port, &attacker, hello(&attacker, "x"))
        .await
        .err()
        .expect("merged device is decommissioned");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
    ts.cleanup().await;
}

// ---------------------------------------------------------------- H3

#[tokio::test]
async fn certificate_renewal_on_stream() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let ca = ca(&ts).await;
    let tok = token(&ts, 2).await;
    let agent = enroll(ts.grpc_port, &ca, &tok, "RENEW-01").await.unwrap();
    let (_, d) = ts.get(&format!("/api/devices/{}", agent.device_id)).await;
    let exp = d["device"]["cert_expires_at"].as_i64().unwrap();
    assert!(exp > now_ms() + 364 * 86_400_000, "{d}");

    // Near expiry → the server asks for renewal on Hello.
    sqlx::query("UPDATE agent_certs SET not_after = $2 WHERE device_id = $1")
        .bind(agent.device_id)
        .bind(now_ms() + 10 * 86_400_000)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let mut st = session(&ts, &agent, "RENEW-01").await;
    let (_, _, _) = st
        .recv_until(|p| matches!(p, ServerPayload::RenewCertificate))
        .await;

    // Renew over the authenticated stream: CN is the stream's device id.
    let (csr_pem, key_pem) = csr();
    let seq = st.send(&AgentPayload::RenewCertificate { csr_pem }).await;
    let (_, cert, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Certificate { .. }))
        .await;
    st.wait_ack(seq).await;
    let ServerPayload::Certificate { cert_pem, ca_pem } = cert else {
        unreachable!()
    };
    let der = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let (cn, _) = kestrel_server::pki::cert_cn_serial(&der).unwrap();
    assert_eq!(cn, agent.device_id.to_string());
    let (_, x) = x509_parser::parse_x509_certificate(&der).unwrap();
    let eku = x.extended_key_usage().unwrap().unwrap().value;
    assert!(eku.client_auth && !eku.server_auth);
    drop(st);

    // Old cert still works until the new one is used…
    let st_old = connect(ts.grpc_port, &agent, hello(&agent, "RENEW-01")).await;
    assert!(
        st_old.is_ok(),
        "old certificate valid until the new one connects"
    );
    drop(st_old);
    let renewed = TestAgent {
        device_id: agent.device_id,
        cert_pem,
        key_pem,
        ca_pem,
    };
    let st_new = session(&ts, &renewed, "RENEW-01").await;
    drop(st_new);
    // …then it is revoked.
    let err = connect(ts.grpc_port, &agent, hello(&agent, "RENEW-01"))
        .await
        .err()
        .expect("superseded certificate must be refused");
    assert_eq!(err.code(), tonic::Code::PermissionDenied, "{err:?}");
    let (_, d) = ts.get(&format!("/api/devices/{}", agent.device_id)).await;
    assert!(d["device"]["cert_expires_at"].as_i64().unwrap() > now_ms() + 364 * 86_400_000);
    ts.cleanup().await;
}

// ---------------------------------------------------------------- M7 / M8 / M9 / M6 / L8 / M2

#[tokio::test]
async fn ingest_hardening() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    // Hash user names in the default policy (M9).
    let (_, mut pol) = ts.get("/api/policies/default").await;
    pol["privacy"]["hash_usernames"] = json!(true);
    let (s, _) = ts.send(Method::PUT, "/api/policies/default", pol).await;
    assert_eq!(s, 200);
    let ca = ca(&ts).await;
    let tok = token(&ts, 3).await;
    let agent = enroll(ts.grpc_port, &ca, &tok, "INGEST-01").await.unwrap();
    let other = enroll(ts.grpc_port, &ca, &tok, "OTHER-02").await.unwrap();
    let mut st = session(&ts, &agent, "INGEST-01").await;

    // M7: a heartbeat from the far future does not freeze processing.
    let s1 = st
        .send(&heartbeat(
            1,
            now_ms() + 30 * 86_400_000,
            Some(r"CORP\alice"),
        ))
        .await;
    st.wait_ack(s1).await;
    let s2 = st.send(&heartbeat(2, now_ms(), Some(r"CORP\bob"))).await;
    st.wait_ack(s2).await;
    let (seq, hb_ts, user): (Option<i64>, Option<i64>, Option<String>) =
        sqlx::query_as("SELECT last_hb_seq, last_hb_ts, logged_on_user FROM devices WHERE id = $1")
            .bind(agent.device_id)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(seq, Some(2), "second heartbeat processed");
    assert!(hb_ts.unwrap() <= now_ms(), "agent timestamp clamped");
    // M9: logged-on user pseudonymised server-side.
    let user = user.unwrap();
    assert!(kestrel_server::crypto::is_pseudonym(&user), "{user}");
    let (_, d) = ts.get(&format!("/api/devices/{}", agent.device_id)).await;
    assert_eq!(d["device"]["health"]["logged_on_user"], user.as_str());

    // M6: enrollment tokens in command lines never reach storage.
    let ev = Event {
        ts: now_ms(),
        pid: 77,
        guid: ProcessGuid("g-msi".into()),
        data: EventData::ProcessStart(ProcessStart {
            ppid: 1,
            parent_guid: None,
            image: r"C:\Windows\System32\msiexec.exe".into(),
            cmdline: format!(
                "msiexec.exe /i KestrelAgent.msi /qn SERVER=x:8443 TOKEN={tok} CA_B64=AAAA"
            ),
            user: None,
            integrity: None,
            session_id: 1,
            signer: None,
            signed: SignatureState::Valid,
            sha256: None,
            motw_zone: None,
            file_size: None,
            agent_spawned: false,
        }),
    };
    let s3 = st.send(&AgentPayload::Events { events: vec![ev] }).await;
    st.wait_ack(s3).await;
    let (_, evs) = ts
        .get(&format!(
            "/api/devices/{}/events?kinds=process_start",
            agent.device_id
        ))
        .await;
    let dump = evs.to_string();
    assert!(dump.contains("msiexec"), "{dump}");
    assert!(
        !dump.contains(&tok[4..]),
        "token leaked into telemetry: {dump}"
    );

    // M9: alert users hashed; summary/cmdline tokens redacted.
    let mut a = alert("ST-01");
    a.summary = format!("tool.exe --token {tok} read Login Data");
    let s4 = st.send(&AgentPayload::Alert(Box::new(a.clone()))).await;
    st.wait_ack(s4).await;
    let (_, ad) = ts.get(&format!("/api/alerts/{}", a.id)).await;
    let au = ad["process"]["user"].as_str().unwrap();
    assert!(kestrel_server::crypto::is_pseudonym(au), "{ad}");
    assert!(!ad.to_string().contains(&tok[4..]));
    let (_, incs) = ts.get("/api/incidents").await;
    assert!(kestrel_server::crypto::is_pseudonym(
        incs["items"][0]["user"].as_str().unwrap()
    ));

    // L8: a review request for another device's alert is ignored…
    let mut so = session(&ts, &other, "OTHER-02").await;
    let s5 = so
        .send(&AgentPayload::ReviewRequest(ReviewRequest {
            alert_id: a.id,
            user: "mallory".into(),
            justification: "please".into(),
            ts: now_ms(),
        }))
        .await;
    so.wait_ack(s5).await;
    let (_, rr) = ts.get("/api/review-requests").await;
    assert_eq!(rr.as_array().unwrap().len(), 0, "{rr}");
    // …its own is stored (user pseudonymised).
    let s6 = st
        .send(&AgentPayload::ReviewRequest(ReviewRequest {
            alert_id: a.id,
            user: r"CORP\alice".into(),
            justification: "it's our tool".into(),
            ts: now_ms(),
        }))
        .await;
    st.wait_ack(s6).await;
    let (_, rr) = ts.get("/api/review-requests").await;
    assert_eq!(rr.as_array().unwrap().len(), 1);
    assert!(kestrel_server::crypto::is_pseudonym(
        rr[0]["user"].as_str().unwrap()
    ));
    // M2: no hash and no valid signer → no exclusion can be offered or created.
    assert!(rr[0]["exclusion_scope"].is_null(), "{rr}");
    let rid = rr[0]["id"].as_str().unwrap();
    let (s, e) = ts
        .post(
            &format!("/api/review-requests/{rid}/decision"),
            json!({"approved": true, "message": "ok", "create_exclusion": true}),
        )
        .await;
    assert_eq!(s, 400, "{e}");
    let (_, ex) = ts.get("/api/exclusions").await;
    assert_eq!(
        ex.as_array().unwrap().len(),
        0,
        "no path exclusion from a review"
    );

    // With a hash: sha256 exclusion, scoped to the device's policy, expiring.
    let mut b = alert("ST-01");
    b.process.sha256 = Some("AB".repeat(32));
    b.process.guid = ProcessGuid("g-tool-2".into());
    let s7 = st.send(&AgentPayload::Alert(Box::new(b.clone()))).await;
    st.wait_ack(s7).await;
    let s8 = st
        .send(&AgentPayload::ReviewRequest(ReviewRequest {
            alert_id: b.id,
            user: "alice".into(),
            justification: "ours".into(),
            ts: now_ms(),
        }))
        .await;
    st.wait_ack(s8).await;
    let (_, rr) = ts.get("/api/review-requests?state=requested").await;
    let scope = &rr[0]["exclusion_scope"];
    assert_eq!(scope["kind"], "sha256", "{rr}");
    assert_eq!(scope["value"], "ab".repeat(32));
    assert_eq!(scope["policy_id"], "default");
    assert_eq!(scope["rule_id"], "ST-01");
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
    let (_, ex) = ts.get("/api/exclusions").await;
    assert_eq!(ex[0]["kind"], "sha256");
    assert_eq!(ex[0]["policy_id"], "default");
    assert!(ex[0]["expires_at"].as_i64().unwrap() > now_ms());

    // M8: a new outbox epoch resets the seq high-water mark.
    drop(st);
    let mut h = hello(&agent, "INGEST-01");
    h.outbox_epoch = Some(Uuid::new_v4());
    let mut st = connect(ts.grpc_port, &agent, h.clone()).await.unwrap();
    st.seq = 100; // first epoch: seqs up to 100
    let s9 = st.send(&heartbeat(3, now_ms(), None)).await;
    st.wait_ack(s9).await;
    drop(st);
    h.outbox_epoch = Some(Uuid::new_v4()); // outbox deleted: seqs restart at 1
    let mut st = connect(ts.grpc_port, &agent, h).await.unwrap();
    let mut late = alert("ST-02");
    late.process.guid = ProcessGuid("g-after-reset".into());
    let s10 = st.send(&AgentPayload::Alert(Box::new(late.clone()))).await;
    assert_eq!(s10, 1);
    st.wait_ack(s10).await;
    let (s, _) = ts.get(&format!("/api/alerts/{}", late.id)).await;
    assert_eq!(
        s, 200,
        "alert after an outbox reset must not be dropped as a duplicate"
    );
    let (_, al) = ts.get("/api/alerts?rule_id=TP-SRV-OUTBOX-RESET").await;
    assert_eq!(al["total"], 1, "{al}");

    // Structured artifact: quarantine id from ActionOutcome.artifact.
    let (_, row) = ts
        .post(
            &format!("/api/devices/{}/actions", agent.device_id),
            json!({"action": {"type": "quarantine_file", "path": r"C:\Users\alice\Downloads\tool.exe"}}),
        )
        .await;
    let (_, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    let ServerPayload::Command { command_id, action } = cmd else {
        unreachable!()
    };
    assert_eq!(command_id.to_string(), row["id"].as_str().unwrap());
    let s11 = st
        .send(&AgentPayload::ActionResult {
            command_id,
            outcome: ActionOutcome {
                action,
                ok: true,
                detail: "done".into(),
                ts: now_ms(),
                artifact: Some("q-artifact-1".into()),
            },
        })
        .await;
    st.wait_ack(s11).await;
    let (_, q) = ts.get("/api/quarantine").await;
    assert_eq!(q[0]["id"], "q-artifact-1", "{q}");
    ts.cleanup().await;
}

// ---------------------------------------------------------------- API validation (L10, L11, M10, M6, L2, L3, L5, L7, H6)

#[tokio::test]
async fn api_guardrails() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    // L3: setup needs the one-time code.
    let (s, v) = ts
        .post(
            "/api/auth/setup",
            json!({"org_name": "x", "email": "a@acme.test", "password": "correct horse battery", "name": "a"}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["setup_code_required"], true);
    let (s, _) = ts
        .post(
            "/api/auth/setup",
            json!({"setup_code": "WRONG", "org_name": "x", "email": "a@acme.test", "password": "correct horse battery", "name": "a"}),
        )
        .await;
    assert_eq!(s, 403);
    ts.setup_admin().await;

    // M6: default enrollment token limits.
    let (_, tok) = ts.post("/api/enrollment-tokens", json!({})).await;
    assert_eq!(tok["max_uses"], 50);
    let ttl = tok["expires_at"].as_i64().unwrap() - tok["created_at"].as_i64().unwrap();
    assert_eq!(ttl, 7 * 86_400_000);
    let (s, _) = ts
        .post("/api/enrollment-tokens", json!({"expires_in_days": 365}))
        .await;
    assert_eq!(s, 400);

    // L11: process actions need a guid.
    let ca = ca(&ts).await;
    let agent = enroll(ts.grpc_port, &ca, tok["token"].as_str().unwrap(), "API-01")
        .await
        .unwrap();
    let (s, e) = ts
        .post(
            &format!("/api/devices/{}/actions", agent.device_id),
            json!({"action": {"type": "kill_process", "pid": 4, "tree": true}}),
        )
        .await;
    assert_eq!(s, 400, "{e}");
    let (s, _) = ts
        .post(
            &format!("/api/devices/{}/actions", agent.device_id),
            json!({"action": {"type": "suspend_process", "pid": 4}}),
        )
        .await;
    assert_eq!(s, 400);
    let (s, _) = ts
        .post(
            &format!("/api/devices/{}/actions", agent.device_id),
            json!({"action": {"type": "kill_process", "pid": 4, "guid": "{abc}-1", "tree": false}}),
        )
        .await;
    assert_eq!(s, 200);

    // L10: exclusion guardrails.
    for body in [
        json!({"kind": "path", "value": "*", "policy_id": "default"}),
        json!({"kind": "path", "value": "C:\\Users\\*", "policy_id": "default"}),
        json!({"kind": "image", "value": "*.exe", "policy_id": "default"}),
        json!({"kind": "sha256", "value": "ab".repeat(32), "rule_id": "TP-01", "policy_id": "default"}),
    ] {
        let (s, e) = ts.post("/api/exclusions", body.clone()).await;
        assert_eq!(s, 400, "{body} → {e}");
    }
    let (s, e) = ts
        .post(
            "/api/exclusions",
            json!({"kind": "path", "value": "C:\\Program Files\\Vendor\\*", "policy_id": "default"}),
        )
        .await;
    assert_eq!(s, 200, "{e}");
    // Global scope needs policies.write: an analyst cannot.
    let (s, _) = ts
        .post(
            "/api/users",
            json!({"email": "an@acme.test", "name": "an", "role": "analyst", "password": "analyst password"}),
        )
        .await;
    assert_eq!(s, 200);
    let an = http_client(&ts.web_ca_pem);
    let r = an
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "an@acme.test", "password": "analyst password"}))
        .send()
        .await
        .unwrap();
    let lv: Value = r.json().await.unwrap();
    let csrf = lv["csrf_token"].as_str().unwrap().to_string();
    let post_an = |path: &str, body: Value| {
        an.post(ts.url(path))
            .header("X-CSRF-Token", &csrf)
            .json(&body)
            .send()
    };
    let r = post_an(
        "/api/exclusions",
        json!({"kind": "sha256", "value": "cd".repeat(32)}),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 403, "global exclusion needs policies.write");
    let r = post_an(
        "/api/exclusions",
        json!({"kind": "sha256", "value": "cd".repeat(32), "policy_id": "default"}),
    )
    .await
    .unwrap();
    assert_eq!(r.status(), 200);

    // M10: IOC ranges.
    let (s, _) = ts
        .post(
            "/api/iocs",
            json!({"kind": "ip", "value": "0.0.0.0/0", "action": "block"}),
        )
        .await;
    assert_eq!(s, 400);
    let (s, _) = ts
        .post(
            "/api/iocs",
            json!({"kind": "ip", "value": "10.0.0.0/8", "action": "block"}),
        )
        .await;
    assert_eq!(s, 400);
    let (s, _) = ts
        .post(
            "/api/iocs",
            json!({"kind": "ip", "value": "44.0.0.0/12", "action": "block"}),
        )
        .await;
    assert_eq!(s, 400);
    let (s, _) = ts
        .post(
            "/api/iocs",
            json!({"kind": "ip", "value": "44.0.0.0/12", "action": "block", "confirm_broad": true}),
        )
        .await;
    assert_eq!(s, 200);
    let (s, _) = ts
        .post(
            "/api/iocs",
            json!({"kind": "ip", "value": "203.0.113.7", "action": "block"}),
        )
        .await;
    assert_eq!(s, 200);

    // L2: API tokens cannot touch /me/* and expire.
    let (_, t) = ts
        .post(
            "/api/api-tokens",
            json!({"name": "siem", "privileges": ["read"]}),
        )
        .await;
    assert!(t["expires_at"].as_i64().unwrap() > now_ms());
    let bare = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ts.web_ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let tk = t["token"].as_str().unwrap();
    let r = bare
        .post(ts.url("/api/me/mfa/setup"))
        .bearer_auth(tk)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = bare
        .get(ts.url("/api/alerts"))
        .bearer_auth(tk)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    sqlx::query("UPDATE api_tokens SET expires_at = $1")
        .bind(now_ms() - 1)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let r = bare
        .get(ts.url("/api/alerts"))
        .bearer_auth(tk)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // H6 / L7: settings validation.
    let (_, mut set) = ts.get("/api/settings").await;
    set["oidc"] = json!({"enabled": true, "issuer": "https://login.example.com/tenant/v2.0", "client_id": "c", "allowed_domains": [], "default_role": "readonly"});
    let (s, e) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 400, "empty allow-list must be refused: {e}");
    set["oidc"]["allowed_domains"] = json!(["acme.test"]);
    set["oidc"]["default_role"] = json!("admin");
    let (s, _) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 400, "admin default role refused");
    set["oidc"]["default_role"] = json!("readonly");
    set["oidc"]["enabled"] = json!(false);
    set["notifications"]["webhook"]["url"] = json!("http://169.254.169.254/latest/meta-data");
    let (s, _) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 400, "metadata webhook refused");
    set["notifications"]["webhook"]["url"] = json!("http://10.1.2.3/hook");
    let (s, _) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 400, "private webhook refused");
    set["notifications"]["syslog"]["host"] = json!("10.0.0.5");
    set["notifications"]["webhook"]["url"] = json!("https://siem.example.com/hook?key=s3cret");
    let (s, _) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 400, "private syslog needs allow_private");
    set["notifications"]["syslog"]["allow_private"] = json!(true);
    let (s, e) = ts.send(Method::PUT, "/api/settings", set.clone()).await;
    assert_eq!(s, 200, "{e}");
    // Generic webhook URL is masked for users without settings.write.
    let r = an.get(ts.url("/api/settings")).send().await.unwrap();
    let sv: Value = r.json().await.unwrap();
    assert_eq!(sv["notifications"]["webhook"]["url"], "");
    assert_eq!(sv["notifications"]["webhook"]["url_set"], true);

    // L5: live streams re-validate their session (logout / disable / expiry).
    let (th,): (String,) = sqlx::query_as("SELECT token_hash FROM sessions WHERE user_id = (SELECT id FROM users WHERE email = 'an@acme.test')")
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert!(
        kestrel_server::auth::session_still_valid(&ts.state, &th, "read")
            .await
            .unwrap()
    );
    assert!(
        !kestrel_server::auth::session_still_valid(&ts.state, &th, "settings.write")
            .await
            .unwrap()
    );
    // L5: absolute session lifetime.
    sqlx::query("UPDATE sessions SET created_at = $1 WHERE user_id = (SELECT id FROM users WHERE email = 'an@acme.test')")
        .bind(now_ms() - 8 * 86_400_000)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let r = an.get(ts.url("/api/me")).send().await.unwrap();
    assert_eq!(r.status(), 401, "session older than session_max_days");
    assert!(
        !kestrel_server::auth::session_still_valid(&ts.state, &th, "read")
            .await
            .unwrap()
    );
    ts.cleanup().await;
}

// ---------------------------------------------------------------- H5 / H6 account binding

#[tokio::test]
async fn oidc_binds_by_subject_only() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let cfg = kestrel_server::settings::Oidc {
        enabled: true,
        issuer: "https://idp.example.com".into(),
        client_id: "c".into(),
        allowed_domains: vec!["acme.test".into()],
        default_role: "readonly".into(),
    };
    use kestrel_server::api::oidc::resolve_user;
    // Same email as the local admin: never linked by email.
    let err = resolve_user(
        &ts.state,
        &cfg,
        "admin@acme.test",
        Some(true),
        "sub-1",
        "",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden", "{}", err.message);
    // Missing email_verified is not verified.
    let err = resolve_user(&ts.state, &cfg, "new@acme.test", None, "sub-2", "", None)
        .await
        .unwrap_err();
    assert_eq!(err.code, "unauthorized");
    // Domain allow-list; empty list denies everyone.
    let err = resolve_user(
        &ts.state,
        &cfg,
        "x@evil.test",
        Some(true),
        "sub-3",
        "",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");
    let empty = kestrel_server::settings::Oidc {
        allowed_domains: vec![],
        ..cfg.clone()
    };
    let err = resolve_user(
        &ts.state,
        &empty,
        "new@acme.test",
        Some(true),
        "sub-4",
        "",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");
    // First login → new SSO-only readonly user; second login → same user.
    let u1 = resolve_user(
        &ts.state,
        &cfg,
        "new@acme.test",
        Some(true),
        "sub-5",
        "New",
        None,
    )
    .await
    .unwrap();
    let u2 = resolve_user(
        &ts.state,
        &cfg,
        "NEW@acme.test",
        Some(true),
        "sub-5",
        "",
        None,
    )
    .await
    .unwrap();
    assert_eq!(u1, u2);
    let (role, pw): (String, Option<String>) =
        sqlx::query_as("SELECT role, password_hash FROM users WHERE id = $1")
            .bind(u1)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(role, "readonly");
    assert!(pw.is_none());
    // A different subject with that email does not get that account.
    let err = resolve_user(
        &ts.state,
        &cfg,
        "new@acme.test",
        Some(true),
        "sub-6",
        "",
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");

    // An admin links the local admin explicitly; then SSO works for it.
    let (s, settings) = ts.get("/api/settings").await;
    assert_eq!(s, 200);
    let mut settings = settings;
    settings["oidc"] = json!({"enabled": false, "issuer": "https://idp.example.com", "client_id": "c", "allowed_domains": ["acme.test"], "default_role": "readonly"});
    let (s, e) = ts.send(Method::PUT, "/api/settings", settings).await;
    assert_eq!(s, 200, "{e}");
    let (_, me) = ts.get("/api/me").await;
    let admin_id = me["user"]["id"].as_str().unwrap().to_string();
    let (s, u) = ts
        .send(
            Method::PATCH,
            &format!("/api/users/{admin_id}"),
            json!({"oidc_subject": "sub-admin"}),
        )
        .await;
    assert_eq!(s, 200, "{u}");
    assert_eq!(u["sso_linked"], true);
    let uid = resolve_user(
        &ts.state,
        &cfg,
        "admin@acme.test",
        Some(true),
        "sub-admin",
        "",
        None,
    )
    .await
    .unwrap();
    assert_eq!(uid.to_string(), admin_id);
    ts.cleanup().await;
}
