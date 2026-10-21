//! Security review v1.1 server fixes: V-H2 (remove_autorun privilege and
//! allow-list on every path), V-L3 (TP-SRV-VERSION and catch-up rate limit),
//! V-L4 (dead letters, narrowed SQLSTATEs) and V-L7 (update ring governance).

mod common;

use common::*;
use kestrel_common::wire::ServerPayload;
use serde_json::{json, Value};
use uuid::Uuid;

async fn enrolled(ts: &TestServer, host: &str) -> TestAgent {
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();
    let (s, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    assert_eq!(s, 200, "{tok}");
    enroll(ts.grpc_port, &ca, tok["token"].as_str().unwrap(), host)
        .await
        .expect("enroll")
}

/// Log in as a new user with `role`; returns a closure-friendly client + csrf.
async fn login_as(ts: &TestServer, email: &str, role: &str) -> (reqwest::Client, String) {
    let (s, v) = ts
        .post(
            "/api/users",
            json!({"email": email, "name": "u", "role": role, "password": "a long enough password"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let c = http_client(&ts.web_ca_pem);
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": email, "password": "a long enough password"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let lv: Value = r.json().await.unwrap();
    (c, lv["csrf_token"].as_str().unwrap().to_string())
}

async fn send_as(
    ts: &TestServer,
    c: &reqwest::Client,
    csrf: &str,
    method: reqwest::Method,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let r = c
        .request(method, ts.url(path))
        .header("X-CSRF-Token", csrf)
        .json(&body)
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

const RUN: &str = r"HKU\S-1-5-21-1111111111-2222222222-3333333333-1001\Software\Microsoft\Windows\CurrentVersion\Run";

#[tokio::test]
async fn remove_autorun_privilege_and_allow_list() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let agent = enrolled(&ts, "PERSIST-PC").await;
    let dev = agent.device_id;
    let path = format!("/api/devices/{dev}/actions");
    let good = json!({"action": {"type": "remove_autorun", "kind": "registry_value", "location": RUN, "value_name": "Updater"}});

    // The built-in analyst role no longer holds response.persistence.
    let (an, an_csrf) = login_as(&ts, "an@acme.test", "analyst").await;
    let (s, me) = send_as(
        &ts,
        &an,
        &an_csrf,
        reqwest::Method::GET,
        "/api/me",
        Value::Null,
    )
    .await;
    assert_eq!(s, 200);
    let privs: Vec<String> = serde_json::from_value(me["privileges"].clone()).unwrap_or_default();
    assert!(
        !privs
            .iter()
            .any(|p| p == "response.persistence" || p == "*"),
        "{me}"
    );
    let (s, v) = send_as(
        &ts,
        &an,
        &an_csrf,
        reqwest::Method::POST,
        &path,
        good.clone(),
    )
    .await;
    assert_eq!(s, 403, "{v}");
    assert!(v.to_string().contains("response.persistence"), "{v}");
    // ... but still has response.file.
    let (s, v) = send_as(
        &ts,
        &an,
        &an_csrf,
        reqwest::Method::POST,
        &path,
        json!({"action": {"type": "quarantine_file", "path": r"C:\Users\a\x.exe"}}),
    )
    .await;
    assert_eq!(s, 200, "{v}");

    // Admin (`*`): allow-listed delete accepted.
    let (s, v) = ts.post(&path, good).await;
    assert_eq!(s, 200, "{v}");
    // Review exploit shapes are refused.
    for bad in [
        json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SOFTWARE\Classes\exefile\shell\open\command", "value_name": "", "restore_data": r#"C:\Users\Public\x.exe "%1" %*"#}),
        json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SYSTEM\CurrentControlSet\Services\Sense", "value_name": "Start", "restore_data": "dword:4"}),
        json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "value_name": "Userinit", "restore_data": r"C:\Windows\system32\userinit.exe,\\host\s\x.exe"}),
        json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "value_name": "UseLogonCredential", "restore_data": "dword:1"}),
        json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems", "value_name": "Windows"}),
        json!({"type": "remove_autorun", "kind": "startup_file", "location": r"C:\Users\bob\Documents\thesis.docx"}),
        json!({"type": "remove_autorun", "kind": "scheduled_task", "location": "\\up\u{202E}fdp"}),
    ] {
        let (s, v) = ts.post(&path, json!({"action": bad})).await;
        assert_eq!(s, 400, "{bad} -> {v}");
    }
    // The canonical default is accepted as a restore.
    let (s, v) = ts
        .post(
            &path,
            json!({"action": {"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "value_name": "UseLogonCredential", "restore_data": "dword:0"}}),
        )
        .await;
    assert_eq!(s, 200, "{v}");

    // Checklist approval runs the same validation: plant an approve item
    // carrying a non-allow-listed action (as an agent-reported retry could).
    let inc = Uuid::new_v4();
    let now = kestrel_common::now_ms();
    sqlx::query(
        "INSERT INTO incidents (id, title, severity, severity_rank, priority, status, device_id, root_guid, first_alert_at, last_alert_at, created_at, updated_at) \
         VALUES ($1,'t','high',3,50,'open',$2,'g',$3,$3,$3,$3)",
    )
    .bind(inc)
    .bind(dev)
    .bind(now)
    .execute(&ts.state.db)
    .await
    .unwrap();
    let mut item_ids = vec![];
    for (key, action) in [
        (
            "bad",
            json!({"type": "remove_autorun", "kind": "registry_value", "location": r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler", "value_name": "ImagePath", "restore_data": "cmd /c x"}),
        ),
        (
            "good",
            json!({"type": "remove_autorun", "kind": "registry_value", "location": RUN, "value_name": "Other"}),
        ),
    ] {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO incident_checklist (id, incident_id, position, kind, text, action, dedupe_key) VALUES ($1,$2,1,'approve','x',$3,$4)")
            .bind(id)
            .bind(inc)
            .bind(action)
            .bind(key)
            .execute(&ts.state.db)
            .await
            .unwrap();
        item_ids.push(id);
    }
    let (s, v) = ts
        .post(
            &format!("/api/incidents/{inc}/checklist/{}", item_ids[0]),
            json!({"done": true}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    let (done,): (bool,) = sqlx::query_as("SELECT done FROM incident_checklist WHERE id = $1")
        .bind(item_ids[0])
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert!(!done, "a refused approval leaves the item open");
    // Analyst cannot approve a remove_autorun even when it is allow-listed.
    let (s, v) = send_as(
        &ts,
        &an,
        &an_csrf,
        reqwest::Method::POST,
        &format!("/api/incidents/{inc}/checklist/{}", item_ids[1]),
        json!({"done": true}),
    )
    .await;
    assert_eq!(s, 403, "{v}");
    let (s, v) = ts
        .post(
            &format!("/api/incidents/{inc}/checklist/{}", item_ids[1]),
            json!({"done": true}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    ts.cleanup().await;
}

#[tokio::test]
async fn agent_version_ahead_raises_tamper_and_is_rate_limited() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let agent = enrolled(&ts, "VER-PC").await;
    let policy_version = || async {
        let (v,): (i64,) = sqlx::query_as("SELECT version FROM policies WHERE id = 'default'")
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
        v
    };
    let before = policy_version().await;
    let mut h = hello(&agent, "VER-PC");
    h.policy_version = (before + 500) as u64;
    let st = connect(ts.grpc_port, &agent, h.clone())
        .await
        .expect("connect");
    drop(st);
    let after_first = policy_version().await;
    assert!(after_first > before + 500, "first report catches up");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM alerts WHERE device_id = $1 AND rule_id = 'TP-SRV-VERSION'",
    )
    .bind(agent.device_id)
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(n, 1);
    // A second, higher report within 10 minutes: no catch-up, no new alert
    // (one per device per hour).
    h.policy_version = (after_first + 500) as u64;
    let mut st = connect(ts.grpc_port, &agent, h).await.expect("connect");
    let (_, w) = st.recv().await.unwrap();
    assert!(matches!(w, ServerPayload::Welcome { .. }));
    drop(st);
    assert_eq!(policy_version().await, after_first, "catch-up rate limited");
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM alerts WHERE device_id = $1 AND rule_id = 'TP-SRV-VERSION'",
    )
    .bind(agent.device_id)
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(n, 1);
    ts.cleanup().await;
}

#[tokio::test]
async fn dead_letters_and_narrow_sqlstates() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    // Real database errors: only the listed SQLSTATEs count as permanent.
    let e = sqlx::query("SELECT 'abc'::int")
        .execute(&ts.state.db)
        .await
        .unwrap_err();
    let code = match &e {
        sqlx::Error::Database(d) => d.code().map(|c| c.to_string()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("22P02"));
    assert!(kestrel_server::grpc::is_permanent_sqlstate("22P02"));
    let e = sqlx::query("SELECT 1/0")
        .execute(&ts.state.db)
        .await
        .unwrap_err();
    let code = match &e {
        sqlx::Error::Database(d) => d.code().map(|c| c.to_string()),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("22012"));
    assert!(!kestrel_server::grpc::is_permanent_sqlstate("22012"));

    let agent = enrolled(&ts, "DL-PC").await;
    // NEW-5: the payload is unscrubbed, so only metadata is stored; the
    // database error is redacted where PostgreSQL echoes the input value.
    let secret = br#"{"cmdline":"curl -u alice:Hunter2 https://x"}"#;
    let mut big = secret.to_vec();
    big.resize(70 * 1024, b'x');
    for seq in [7u64, 8] {
        kestrel_server::ingest::dead_letter(
            &ts.state,
            agent.device_id,
            "DL-PC",
            seq,
            "alert",
            r#"error returned from database: invalid input syntax for type integer: "alice:Hunter2""#,
            &big,
        )
        .await;
    }
    let cols: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name::text FROM information_schema.columns WHERE table_name = 'ingest_dead_letters' ORDER BY column_name",
    )
    .fetch_all(&ts.state.db)
    .await
    .unwrap();
    let cols: Vec<String> = cols.into_iter().map(|c| c.0).collect();
    assert!(!cols.iter().any(|c| c == "payload"), "{cols:?}");
    let rows: Vec<(i64, String, String, i64, String)> = sqlx::query_as(
        "SELECT seq, payload_type, error, payload_bytes, payload_sha256 FROM ingest_dead_letters WHERE device_id = $1 ORDER BY seq",
    )
    .bind(agent.device_id)
    .fetch_all(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].0, 7);
    assert_eq!(rows[0].1, "alert");
    assert!(!rows[0].2.contains("Hunter2"), "{}", rows[0].2);
    assert!(rows[0].2.contains("invalid input syntax"), "{}", rows[0].2);
    assert_eq!(rows[0].3, 70 * 1024);
    {
        use sha2::{Digest, Sha256};
        assert_eq!(rows[0].4, hex::encode(Sha256::digest(&big)));
    }
    assert_eq!(
        kestrel_server::ingest::redact_db_error(r#"bad "x" and "y"#),
        r#"bad "<redacted>" and "<redacted>""#
    );
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM alerts WHERE device_id = $1 AND rule_id = 'TP-SRV-INGEST'",
    )
    .bind(agent.device_id)
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    assert_eq!(n, 1, "TP-SRV-INGEST at most once per device per hour");

    // NEW-5: per-device row cap (newest 1000 kept) and 30-day retention.
    let now = kestrel_common::now_ms();
    sqlx::query(
        "INSERT INTO ingest_dead_letters (device_id, seq, payload_type, error, payload_bytes, payload_sha256, received_at)          SELECT $1, 100 + g, 'event', 'e', 1, 'h', $2 + g FROM generate_series(1, 1100) g",
    )
    .bind(agent.device_id)
    .bind(now - 60_000)
    .execute(&ts.state.db)
    .await
    .unwrap();
    let other = enrolled(&ts, "DL-PC2").await;
    sqlx::query(
        "INSERT INTO ingest_dead_letters (device_id, seq, payload_type, error, payload_bytes, payload_sha256, received_at)          VALUES ($1, 1, 'event', 'e', 1, 'h', $2), ($1, 2, 'event', 'e', 1, 'h', $3)",
    )
    .bind(other.device_id)
    .bind(now - 31 * 86_400_000)
    .bind(now)
    .execute(&ts.state.db)
    .await
    .unwrap();
    kestrel_server::jobs::retention(&ts.state).await.unwrap();
    let count = |d: Uuid| {
        let db = ts.state.db.clone();
        async move {
            let (n,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM ingest_dead_letters WHERE device_id = $1")
                    .bind(d)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            n
        }
    };
    assert_eq!(count(agent.device_id).await, 1000);
    let (min_seq,): (i64,) = sqlx::query_as(
        "SELECT min(seq) FROM ingest_dead_letters WHERE device_id = $1 AND seq >= 100",
    )
    .bind(agent.device_id)
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    // 1102 rows: seq 7 and 8 (newest) plus the 998 newest generated ones.
    assert_eq!(min_seq, 203, "the newest rows are kept");
    assert_eq!(
        count(other.device_id).await,
        1,
        "rows older than 30 days expire"
    );
    // The cap also applies on insert.
    kestrel_server::ingest::dead_letter(
        &ts.state,
        agent.device_id,
        "DL-PC",
        5000,
        "event",
        "x",
        b"{}",
    )
    .await;
    assert_eq!(count(agent.device_id).await, 1000);
    ts.cleanup().await;
}

#[tokio::test]
async fn update_ring_needs_updates_write() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    sqlx::query("INSERT INTO roles (name, description, privileges, builtin) VALUES ('fleet-ops', 'devices only', ARRAY['read','devices.write'], false)")
        .execute(&ts.state.db)
        .await
        .unwrap();
    let (ops, csrf) = login_as(&ts, "ops@acme.test", "fleet-ops").await;
    let (s, g) = send_as(
        &ts,
        &ops,
        &csrf,
        reqwest::Method::POST,
        "/api/groups",
        json!({"name": "Finance"}),
    )
    .await;
    assert_eq!(s, 200, "{g}");
    let gid = g["id"].as_str().unwrap().to_string();
    let (s, v) = send_as(
        &ts,
        &ops,
        &csrf,
        reqwest::Method::POST,
        "/api/groups",
        json!({"name": "Canaries", "update_ring": "canary"}),
    )
    .await;
    assert_eq!(s, 403, "{v}");
    let (s, v) = send_as(
        &ts,
        &ops,
        &csrf,
        reqwest::Method::PATCH,
        &format!("/api/groups/{gid}"),
        json!({"name": "Finance 2", "update_ring": "canary"}),
    )
    .await;
    assert_eq!(s, 403, "{v}");
    let (_, groups) = ts.get("/api/groups").await;
    let g = groups
        .as_array()
        .or_else(|| groups["items"].as_array())
        .unwrap()
        .iter()
        .find(|x| x["id"] == gid.as_str())
        .unwrap()
        .clone();
    assert_eq!(g["name"], "Finance", "refused request changed nothing");
    assert_eq!(g["update_ring"], "broad");
    // Renaming alone still works; an admin may change the ring.
    let (s, _) = send_as(
        &ts,
        &ops,
        &csrf,
        reqwest::Method::PATCH,
        &format!("/api/groups/{gid}"),
        json!({"name": "Finance 3", "update_ring": "broad"}),
    )
    .await;
    assert_eq!(s, 200);
    let (s, v) = ts
        .send(
            reqwest::Method::PATCH,
            &format!("/api/groups/{gid}"),
            json!({"update_ring": "canary"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    ts.cleanup().await;
}
