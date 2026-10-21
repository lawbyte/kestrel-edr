//! "Remove device" (remote uninstall + removal from the device list), server
//! side: RBAC / session / typed hostname / MFA step-up / capability / rate
//! limit checks, queue while offline and delivery on connect with the token
//! attached only then, cancel, agent outcomes (started, token mismatch),
//! unsupported older agents, and removing → removed with revoked
//! certificates and the device hidden from the list by default.

mod common;

use common::*;
use kestrel_common::{
    now_ms,
    wire::{AgentPayload, ServerPayload},
    ActionOutcome, ResponseAction, CAP_REMOTE_UNINSTALL, UNINSTALL_FAILED, UNINSTALL_STARTED,
};
use reqwest::Method;
use serde_json::{json, Value};
use std::time::Duration;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "admin@acme.test";

async fn new_agent(ts: &TestServer, host: &str) -> (TestAgent, String) {
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    let (agent, er) = enroll_full(
        ts.grpc_port,
        &ca,
        tok["token"].as_str().unwrap(),
        host,
        os(),
    )
    .await
    .unwrap();
    assert!(er.uninstall_token.starts_with("kun_"));
    (agent, er.uninstall_token)
}

async fn online(ts: &TestServer, agent: &TestAgent, host: &str, caps: &[&str]) -> AgentStream {
    let mut h = hello(agent, host);
    h.capabilities = caps.iter().map(|c| c.to_string()).collect();
    let mut st = connect(ts.grpc_port, agent, h).await.unwrap();
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { .. }));
    st
}

async fn offline(ts: &TestServer, st: AgentStream, id: Uuid) {
    drop(st);
    for _ in 0..200 {
        if !ts.state.agents.is_connected(&id) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("agent still registered");
}

async fn audit_rows(ts: &TestServer, action: &str) -> Vec<Value> {
    let rows: Vec<(Value,)> =
        sqlx::query_as("SELECT details FROM audit_log WHERE action = $1 ORDER BY id")
            .bind(action)
            .fetch_all(&ts.state.db)
            .await
            .unwrap();
    rows.into_iter().map(|r| r.0).collect()
}

/// The token must never appear in the actions table, the audit log or any
/// API answer.
async fn assert_token_nowhere(ts: &TestServer, token: &str, apis: &[Value]) {
    for v in apis {
        assert!(!v.to_string().contains(token), "token in API output: {v}");
    }
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM response_actions WHERE action::text LIKE $1 OR result_detail LIKE $1 OR COALESCE(artifact,'') LIKE $1 OR comment LIKE $1",
    )
    .bind(format!("%{token}%"))
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(n, 0, "token stored with an action");
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log WHERE details::text LIKE $1")
        .bind(format!("%{token}%"))
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "token in the audit log");
    let (n,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM pending_messages WHERE payload::text LIKE $1")
            .bind(format!("%{token}%"))
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(n, 0, "token queued in pending_messages");
}

fn outcome(ok: bool, detail: &str, artifact: &str) -> AgentPayload {
    AgentPayload::ActionResult {
        command_id: Uuid::nil(),
        outcome: ActionOutcome {
            action: ResponseAction::UninstallAgent { purge_data: false },
            ok,
            detail: detail.into(),
            ts: now_ms(),
            artifact: Some(artifact.into()),
        },
    }
}

fn with_id(p: AgentPayload, id: Uuid) -> AgentPayload {
    match p {
        AgentPayload::ActionResult { outcome, .. } => AgentPayload::ActionResult {
            command_id: id,
            outcome,
        },
        other => other,
    }
}

#[tokio::test]
async fn remove_device_lifecycle() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (agent, token) = new_agent(&ts, "FIN-LT-01").await;
    let dev = agent.device_id;
    let path = format!("/api/devices/{dev}/remove");
    let st = online(&ts, &agent, "FIN-LT-01", &[CAP_REMOTE_UNINSTALL]).await;
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["capabilities"], json!([CAP_REMOTE_UNINSTALL]));
    assert_eq!(d["device"]["removal"], Value::Null);

    // The typed hostname must match (case-insensitive).
    let (s, v) = ts
        .post(
            &path,
            json!({"purge_data": true, "confirm_hostname": "FIN-LT-02"}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["error"]["reason"], "confirm_mismatch");
    // Never through the generic action endpoint.
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/actions"),
            json!({"action": {"type": "uninstall_agent", "purge_data": false}}),
        )
        .await;
    assert_eq!(s, 400, "{v}");

    // Queued while the PC is offline.
    offline(&ts, st, dev).await;
    let (s, v) = ts
        .post(
            &path,
            json!({"purge_data": true, "confirm_hostname": "fin-lt-01", "comment": "laptop returned"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["removal"]["state"], "pending", "{v}");
    assert_eq!(v["device"]["removal"]["purge_data"], true);
    assert_eq!(v["device"]["removal"]["requested_by"], "Ada Admin");
    assert_eq!(v["action"]["action"]["type"], "uninstall_agent");
    assert_eq!(v["action"]["status"], "pending");
    // 90 days, not the usual 7.
    let (exp, created): (i64, i64) =
        sqlx::query_as("SELECT expires_at, created_at FROM response_actions WHERE device_id = $1 AND action_type = 'uninstall_agent'")
            .bind(dev)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(exp - created, 90 * 86_400_000);
    let first = v.clone();
    let (s, v) = ts
        .post(
            &path,
            json!({"purge_data": true, "confirm_hostname": "FIN-LT-01"}),
        )
        .await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"]["reason"], "removal_pending");

    // Cancel while not delivered; then nothing is left to cancel.
    let (s, v) = ts.send(Method::DELETE, &path, json!({})).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["device"]["removal"], Value::Null, "{v}");
    let (s, v) = ts.send(Method::DELETE, &path, json!({})).await;
    assert_eq!(s, 404, "{v}");
    assert_eq!(v["error"]["reason"], "no_pending_removal");
    assert_eq!(audit_rows(&ts, "device.remove.cancelled").await.len(), 1);
    let (status,): (String,) = sqlx::query_as("SELECT status FROM response_actions WHERE id = $1")
        .bind(Uuid::parse_str(first["action"]["id"].as_str().unwrap()).unwrap())
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(status, "cancelled");

    // Queue again; delivered when the agent connects, token attached only now.
    let (s, v) = ts
        .post(
            &path,
            json!({"purge_data": true, "confirm_hostname": "FIN-LT-01"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let aid = Uuid::parse_str(v["action"]["id"].as_str().unwrap()).unwrap();
    let mut st = online(&ts, &agent, "FIN-LT-01", &[CAP_REMOTE_UNINSTALL]).await;
    let (cseq, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    let ServerPayload::Command {
        command_id,
        action,
        secret,
    } = cmd
    else {
        unreachable!()
    };
    assert_eq!(command_id, aid);
    assert_eq!(action, ResponseAction::UninstallAgent { purge_data: true });
    assert_eq!(secret.unwrap().uninstall_tokens, vec![token.clone()]);
    st.ack(cseq).await;
    // Once received it can no longer be cancelled.
    let mut cancel = (0, Value::Null);
    for _ in 0..100 {
        cancel = ts.send(Method::DELETE, &path, json!({})).await;
        if cancel.0 == 409 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert_eq!(cancel.0, 409, "{}", cancel.1);
    assert_eq!(cancel.1["error"]["reason"], "already_started");

    // Agent: token verified, uninstall started → removing.
    let s1 = st
        .send(&with_id(
            outcome(
                true,
                "uninstall token verified; Kestrel is uninstalling itself",
                UNINSTALL_STARTED,
            ),
            aid,
        ))
        .await;
    st.wait_ack(s1).await;
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "removing", "{d}");
    assert!(d["device"]["removal"]["started_at"].as_i64().is_some());
    assert_eq!(audit_rows(&ts, "device.remove.started").await.len(), 1);
    let (_, actions) = ts.get("/api/actions?limit=50").await;
    let (_, audit) = ts.get("/api/audit-log?limit=200").await;
    assert_token_nowhere(&ts, &token, &[first, d.clone(), actions, audit]).await;

    // Still connected: never finalised, however old last_seen looks.
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "removing");

    // The PC goes away and stays away for 10 minutes → removed.
    offline(&ts, st, dev).await;
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "removing", "not yet: {d}");
    sqlx::query("UPDATE devices SET last_seen = $2 WHERE id = $1")
        .bind(dev)
        .bind(now_ms() - 11 * 60_000)
        .execute(&ts.state.db)
        .await
        .unwrap();
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    let (s, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(s, 200, "removed devices keep a readable page: {d}");
    let r = &d["device"]["removal"];
    assert_eq!(r["state"], "removed", "{d}");
    assert_eq!(r["requested_by"], "Ada Admin");
    assert!(r["removed_at"].as_i64().is_some());
    let done = audit_rows(&ts, "device.remove.completed").await;
    assert_eq!(done.len(), 1);
    assert_eq!(done[0]["hostname"], "FIN-LT-01");
    let (status,): (String,) = sqlx::query_as("SELECT status FROM response_actions WHERE id = $1")
        .bind(aid)
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(status, "succeeded");
    // Certificates stay valid for the grace period (a PC whose uninstall
    // did not complete can still report back), then they are revoked.
    let live = |db: sqlx::PgPool| async move {
        let (n,): (i64,) = sqlx::query_as(
            "SELECT count(*) FROM agent_certs WHERE device_id = $1 AND revoked_at IS NULL",
        )
        .bind(dev)
        .fetch_one(&db)
        .await
        .unwrap();
        n
    };
    assert!(live(ts.state.db.clone()).await > 0);
    // Hidden by default; listed with include_removed.
    let (_, list) = ts.get("/api/devices").await;
    assert!(
        !list["items"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["id"] == dev.to_string()),
        "{list}"
    );
    let (_, list) = ts.get("/api/devices?include_removed=true").await;
    let row = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["id"] == dev.to_string())
        .cloned()
        .expect("removed device listed on request");
    assert_eq!(row["removal"]["state"], "removed");
    // Nothing more can be done to a removed device.
    let (s, _) = ts
        .post(
            &path,
            json!({"purge_data": false, "confirm_hostname": "FIN-LT-01"}),
        )
        .await;
    assert_eq!(s, 404);
    assert_token_nowhere(&ts, &token, &[d, list]).await;

    // After the grace period the certificates are revoked: the identity can
    // no longer connect, and the device stays removed.
    sqlx::query("UPDATE devices SET removed_at = removed_at - $2, decommissioned_at = decommissioned_at - $2 WHERE id = $1")
        .bind(dev)
        .bind(8 * 86_400_000i64)
        .execute(&ts.state.db)
        .await
        .unwrap();
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    assert_eq!(live(ts.state.db.clone()).await, 0);
    let h = hello(&agent, "FIN-LT-01");
    match connect(ts.grpc_port, &agent, h).await {
        Err(_) => {}
        Ok(mut st) => {
            let r = tokio::time::timeout(Duration::from_secs(10), st.rx.message()).await;
            assert!(
                !matches!(r, Ok(Ok(Some(_)))),
                "a removed device must not get a session"
            );
        }
    }
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "removed");
    ts.cleanup().await;
}

/// The uninstall did not complete (PC shut down mid-way, installer rolled
/// back) and the PC comes back after it was marked removed: the device is
/// restored, the removal is failed and the exposed token rotated.
#[tokio::test]
async fn removed_pc_that_comes_back_is_restored() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (agent, token) = new_agent(&ts, "HR-LT-03").await;
    let dev = agent.device_id;
    let mut st = online(&ts, &agent, "HR-LT-03", &[CAP_REMOTE_UNINSTALL]).await;
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/remove"),
            json!({"purge_data": false, "confirm_hostname": "HR-LT-03"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let aid = Uuid::parse_str(v["action"]["id"].as_str().unwrap()).unwrap();
    let (cseq, _, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    st.ack(cseq).await;
    let s1 = st
        .send(&with_id(
            outcome(true, "uninstall token verified", UNINSTALL_STARTED),
            aid,
        ))
        .await;
    st.wait_ack(s1).await;
    offline(&ts, st, dev).await;
    sqlx::query("UPDATE devices SET last_seen = $2 WHERE id = $1")
        .bind(dev)
        .bind(now_ms() - 11 * 60_000)
        .execute(&ts.state.db)
        .await
        .unwrap();
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "removed", "{d}");

    // Kestrel is still there and connects again.
    let mut st = online(&ts, &agent, "HR-LT-03", &[CAP_REMOTE_UNINSTALL]).await;
    let (_, rot, _) = st
        .recv_until(|p| matches!(p, ServerPayload::SetUninstallToken { .. }))
        .await;
    let ServerPayload::SetUninstallToken { token: new_token } = rot else {
        unreachable!()
    };
    assert_ne!(new_token, token, "the token sent to the PC is rotated");
    let (s, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(s, 200);
    assert_eq!(d["device"]["removal"]["state"], "failed", "{d}");
    assert!(d["device"]["removal"]["error"]
        .as_str()
        .unwrap()
        .contains("still installed"));
    assert!(d["device"]["uninstall_token_pending"].as_bool().unwrap());
    let (_, list) = ts.get("/api/devices").await;
    assert!(list["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == dev.to_string()));
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM audit_log WHERE action = 'device.uninstall_token_rotated'",
    )
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(n, 1);
    drop(st);
    ts.cleanup().await;
}

#[tokio::test]
async fn remove_device_guards() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (agent, _token) = new_agent(&ts, "OPS-DT-07").await;
    let dev = agent.device_id;
    let path = format!("/api/devices/{dev}/remove");
    let body = json!({"purge_data": false, "confirm_hostname": "OPS-DT-07"});

    // An older agent (no capability) → agent_too_old.
    let st = online(&ts, &agent, "OPS-DT-07", &[]).await;
    let (s, v) = ts.post(&path, body.clone()).await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"]["reason"], "agent_too_old");
    offline(&ts, st, dev).await;
    let st = online(&ts, &agent, "OPS-DT-07", &[CAP_REMOTE_UNINSTALL]).await;

    // RBAC: analyst / readonly 403; API tokens 403 even with `*`.
    for role in ["analyst", "readonly"] {
        let email = format!("{role}@acme.test");
        let (s, u) = ts
            .post("/api/users", json!({"email": email, "name": role, "role": role, "password": "role password 123"}))
            .await;
        assert_eq!(s, 200, "{u}");
        let c = http_client(&ts.web_ca_pem);
        let r = c
            .post(ts.url("/api/auth/login"))
            .json(&json!({"email": email, "password": "role password 123"}))
            .send()
            .await
            .unwrap();
        let csrf = r.json::<Value>().await.unwrap()["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
        let r = c
            .post(ts.url(&path))
            .header("X-CSRF-Token", csrf)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{role} must not remove devices");
    }
    let (s, t) = ts
        .post(
            "/api/api-tokens",
            json!({"name": "automation", "privileges": ["*"]}),
        )
        .await;
    assert_eq!(s, 200, "{t}");
    let bare = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ts.web_ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let r = bare
        .post(ts.url(&path))
        .bearer_auth(t["token"].as_str().unwrap())
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "API tokens cannot remove devices");
    let (_, me) = ts.get("/api/me").await;
    assert!(me.to_string().contains("devices.remove"), "{me}");

    // MFA step-up: an admin with MFA needs a fresh /me/reauth.
    let (s, setup) = ts.post("/api/me/mfa/setup", json!({})).await;
    assert_eq!(s, 200, "{setup}");
    let totp =
        kestrel_server::crypto::totp_for(setup["secret"].as_str().unwrap(), ADMIN_EMAIL).unwrap();
    let now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let (s, v) = ts
        .post(
            "/api/me/mfa/enable",
            json!({"totp": totp.generate(now() - 30)}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = ts.post(&path, body.clone()).await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "reauth_required");
    let (s, v) = ts
        .post("/api/me/reauth", json!({"totp": totp.generate(now())}))
        .await;
    assert_eq!(s, 200, "{v}");

    // Delivered at once to the connected agent, which reports a token
    // mismatch → failed, device stays listed with the error.
    let mut st = st;
    let (s, v) = ts.post(&path, body.clone()).await;
    assert_eq!(s, 200, "{v}");
    let aid = Uuid::parse_str(v["action"]["id"].as_str().unwrap()).unwrap();
    let (cseq, cmd, _) = st
        .recv_until(|p| matches!(p, ServerPayload::Command { .. }))
        .await;
    assert!(matches!(cmd, ServerPayload::Command { command_id, .. } if command_id == aid));
    st.ack(cseq).await;
    let s1 = st
        .send(&with_id(
            outcome(
                false,
                "refused: uninstall token mismatch (rotated meanwhile)",
                UNINSTALL_FAILED,
            ),
            aid,
        ))
        .await;
    let seen = st.wait_ack(s1).await;
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "failed", "{d}");
    assert!(d["device"]["removal"]["error"]
        .as_str()
        .unwrap()
        .contains("token mismatch"));
    let (_, list) = ts.get("/api/devices").await;
    assert!(list["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|x| x["id"] == dev.to_string()));
    assert_eq!(audit_rows(&ts, "device.remove.failed").await.len(), 1);
    // The token went to the PC and the removal failed: it is rotated.
    assert!(
        seen.iter()
            .any(|p| matches!(p, ServerPayload::SetUninstallToken { .. })),
        "{seen:?}"
    );
    let (_, d2) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d2["device"]["uninstall_token_pending"], true);
    kestrel_server::jobs::fast_jobs(&ts.state).await.unwrap();
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "failed", "failed is final");

    // Queued, then the PC comes back with an agent that does not support it
    // (downgraded): nothing is sent, the removal fails as unsupported.
    offline(&ts, st, dev).await;
    let (s, v) = ts.post(&path, body.clone()).await;
    assert_eq!(s, 200, "{v}");
    let aid2 = Uuid::parse_str(v["action"]["id"].as_str().unwrap()).unwrap();
    let mut st = online(&ts, &agent, "OPS-DT-07", &[]).await;
    let hb = st
        .send(&AgentPayload::Heartbeat(kestrel_common::wire::Heartbeat {
            seq: 1,
            ts: now_ms(),
            health: Default::default(),
        }))
        .await;
    let seen = st.wait_ack(hb).await;
    assert!(
        !seen
            .iter()
            .any(|p| matches!(p, ServerPayload::Command { .. })),
        "{seen:?}"
    );
    let (status, detail): (String, String) =
        sqlx::query_as("SELECT status, result_detail FROM response_actions WHERE id = $1")
            .bind(aid2)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!(status, "failed");
    assert!(detail.starts_with("unsupported"), "{detail}");
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["device"]["removal"]["state"], "failed");

    // Rate limit: at most 20 removal requests per admin per hour.
    offline(&ts, st, dev).await;
    sqlx::query("UPDATE devices SET capabilities = ARRAY[$2] WHERE id = $1")
        .bind(dev)
        .bind(CAP_REMOTE_UNINSTALL)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let (admin_id,): (Uuid,) = sqlx::query_as("SELECT id FROM users WHERE email = $1")
        .bind(ADMIN_EMAIL)
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    for _ in 0..18 {
        sqlx::query(
            "INSERT INTO response_actions (id, device_id, action, action_type, status, requested_by, created_at, expires_at, completed_at) \
             VALUES ($1, $2, '{\"type\":\"uninstall_agent\"}', 'uninstall_agent', 'cancelled', $3, $4, $4, $4)",
        )
        .bind(Uuid::new_v4())
        .bind(dev)
        .bind(admin_id)
        .bind(now_ms())
        .execute(&ts.state.db)
        .await
        .unwrap();
    }
    let (s, v) = ts.post(&path, body.clone()).await;
    assert_eq!(s, 429, "{v}");
    assert_eq!(v["error"]["reason"], "rate_limited");
    assert_eq!(audit_rows(&ts, "device.remove.requested").await.len(), 2);
    ts.cleanup().await;
}
