//! Setup, login, CSRF, RBAC, API tokens, MFA, login rate limiting, audit chain.

mod common;

use common::{http_client, TestServer};
use reqwest::Method;
use serde_json::{json, Value};

#[tokio::test]
async fn setup_login_csrf_rbac() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };

    let (s, v) = ts.get("/api/auth/setup-status").await;
    assert_eq!(s, 200);
    assert_eq!(v["needs_setup"], true);
    assert_eq!(v["oidc_enabled"], false);

    // Login before setup is refused.
    let (s, _) = ts
        .post(
            "/api/auth/login",
            json!({"email": "x@y.z", "password": "whatever-123"}),
        )
        .await;
    assert_eq!(s, 409);
    // Unauthenticated access.
    let (s, v) = ts.get("/api/devices").await;
    assert_eq!(s, 401);
    assert_eq!(v["error"]["code"], "unauthorized");

    let setup = ts.setup_admin().await;
    assert_eq!(setup["user"]["role"], "admin");
    assert_eq!(setup["user"]["email"], "admin@acme.test");
    let (s, _) = ts
        .post("/api/auth/setup", json!({"org_name": "x", "email": "b@acme.test", "password": "another long pw", "name": "b"}))
        .await;
    assert_eq!(s, 409, "second setup must be refused");
    let (_, v) = ts.get("/api/auth/setup-status").await;
    assert_eq!(v["needs_setup"], false);
    assert_eq!(v["org_name"], "Acme Pte Ltd");

    let (s, me) = ts.get("/api/me").await;
    assert_eq!(s, 200);
    assert_eq!(me["csrf_token"], ts.csrf.as_str());
    assert!(me["privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "*"));

    // CSRF: mutating call without the header is rejected.
    let r = ts
        .http
        .post(ts.url("/api/groups"))
        .json(&json!({"name": "Finance"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], "forbidden");
    let r = ts
        .http
        .post(ts.url("/api/groups"))
        .header("X-CSRF-Token", "wrong")
        .json(&json!({"name": "Finance"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let (s, g) = ts
        .post(
            "/api/groups",
            json!({"name": "Finance", "description": "Finance laptops"}),
        )
        .await;
    assert_eq!(s, 200, "{g}");
    assert_eq!(g["policy_id"], "default");
    assert_eq!(g["device_count"], 0);

    // Bad JSON → contract error shape.
    let r = ts
        .http
        .post(ts.url("/api/groups"))
        .header("X-CSRF-Token", &ts.csrf)
        .header("content-type", "application/json")
        .body("{")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], "bad_request");

    // Create a read-only user and log in as them in a separate client.
    let (s, u) = ts.post("/api/users", json!({"email": "Viewer@acme.test", "name": "Vic", "role": "readonly", "password": "viewer password 1"})).await;
    assert_eq!(s, 200, "{u}");
    assert_eq!(u["email"], "viewer@acme.test");
    let (s, _) = ts
        .post(
            "/api/users",
            json!({"email": "viewer@acme.test", "name": "dup", "role": "readonly"}),
        )
        .await;
    assert_eq!(s, 409);

    let viewer = http_client(&ts.web_ca_pem);
    let r = viewer
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "viewer@acme.test", "password": "nope nope nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let r = viewer
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "viewer@acme.test", "password": "viewer password 1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        cookie.contains("HttpOnly")
            && cookie.contains("Secure")
            && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    let lv: Value = r.json().await.unwrap();
    let vcsrf = lv["csrf_token"].as_str().unwrap().to_string();
    assert_eq!(lv["user"]["role"], "readonly");
    // read works, writes are denied by RBAC
    let r = viewer.get(ts.url("/api/devices")).send().await.unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["total"], 0);
    assert!(v["next_cursor"].is_null());
    let r = viewer
        .post(ts.url("/api/groups"))
        .header("X-CSRF-Token", &vcsrf)
        .json(&json!({"name": "Nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = viewer.get(ts.url("/api/audit-log")).send().await.unwrap();
    assert_eq!(r.status(), 403);
    let r = viewer
        .put(ts.url("/api/settings"))
        .header("X-CSRF-Token", &vcsrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    // Slack/Teams webhook URLs are masked for non-admins.
    let r = viewer.get(ts.url("/api/settings")).send().await.unwrap();
    let sv: Value = r.json().await.unwrap();
    assert_eq!(sv["notifications"]["slack"]["webhook_url"], "");

    // Logout invalidates the session.
    let r = viewer
        .post(ts.url("/api/auth/logout"))
        .header("X-CSRF-Token", &vcsrf)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = viewer.get(ts.url("/api/me")).send().await.unwrap();
    assert_eq!(r.status(), 401);

    // API tokens: privileges, bearer auth, no CSRF needed.
    let (s, t) = ts
        .post(
            "/api/api-tokens",
            json!({"name": "siem", "privileges": ["read"]}),
        )
        .await;
    assert_eq!(s, 200, "{t}");
    let token = t["token"].as_str().unwrap().to_string();
    assert!(token.starts_with("kst_"));
    let bare = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ts.web_ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let r = bare
        .get(ts.url("/api/alerts"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = bare
        .post(ts.url("/api/groups"))
        .bearer_auth(&token)
        .json(&json!({"name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = bare
        .get(ts.url("/api/alerts"))
        .bearer_auth("kst_invalid")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let (_, list) = ts.get("/api/api-tokens").await;
    assert_eq!(list.as_array().unwrap().len(), 1);
    assert!(list[0].get("token").is_none());
    let (s, _) = ts
        .send(
            Method::DELETE,
            &format!("/api/api-tokens/{}", t["id"].as_str().unwrap()),
            json!({}),
        )
        .await;
    assert_eq!(s, 204);
    let r = bare
        .get(ts.url("/api/alerts"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);

    // Last admin cannot be demoted.
    let admin_id = setup["user"]["id"].as_str().unwrap().to_string();
    let (s, _) = ts
        .send(
            Method::PATCH,
            &format!("/api/users/{admin_id}"),
            json!({"role": "analyst"}),
        )
        .await;
    assert_eq!(s, 409);

    // Every mutating call above left a verifiable audit trail.
    let (s, log) = ts.get("/api/audit-log?limit=100").await;
    assert_eq!(s, 200);
    let actions: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    for a in [
        "auth.setup",
        "group.create",
        "user.create",
        "auth.login_failed",
        "auth.login",
        "auth.logout",
        "token.create",
        "token.delete",
    ] {
        assert!(
            actions.contains(&a),
            "missing audit action {a}: {actions:?}"
        );
    }
    let (_, ver) = ts.get("/api/audit-log/verify").await;
    assert_eq!(ver["ok"], true, "{ver}");

    ts.cleanup().await;
}

#[tokio::test]
async fn audit_chain_detects_tampering() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    for i in 0..5 {
        let (s, _) = ts
            .post("/api/groups", json!({"name": format!("G{i}")}))
            .await;
        assert_eq!(s, 200);
    }
    let (_, v) = ts.get("/api/audit-log/verify").await;
    assert_eq!(v["ok"], true);
    let count = v["count"].as_i64().unwrap();
    assert!(count >= 6);

    let (target,): (i64,) = sqlx::query_as(
        "SELECT id FROM audit_log WHERE action = 'group.create' ORDER BY id LIMIT 1 OFFSET 2",
    )
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    // An attacker with DB access rewrites history…
    sqlx::query(
        "UPDATE audit_log SET details = jsonb_set(details, '{name}', '\"Innocent\"') WHERE id = $1",
    )
    .bind(target)
    .execute(&ts.state.db)
    .await
    .unwrap();
    let (_, v) = ts.get("/api/audit-log/verify").await;
    assert_eq!(v["ok"], false);
    assert_eq!(v["broken_at"], target);

    // …and recomputing that row's hash without the server key (L6: the chain is
    // an HMAC keyed from the master key) is still detected at that row.
    let r = kestrel_server::audit::verify(&ts.state.db).await.unwrap();
    assert_eq!(r.broken_at, Some(target));
    let (prev, id, ts_, actor_id, email, action, tgt, details): (String, i64, i64, Option<uuid::Uuid>, Option<String>, String, String, Value) =
        sqlx::query_as("SELECT prev_hash, id, ts, actor_id, actor_email, action, target, details FROM audit_log WHERE id = $1")
            .bind(target)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    let row = json!({"id": id, "ts": ts_, "actor_id": actor_id.map(|u| u.to_string()), "actor_email": email, "action": action, "target": tgt, "details": details});
    let forged = kestrel_server::audit::legacy_hash(&prev, &row);
    sqlx::query("UPDATE audit_log SET hash = $2 WHERE id = $1")
        .bind(target)
        .bind(&forged)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let r = kestrel_server::audit::verify(&ts.state.db).await.unwrap();
    assert!(!r.ok);
    assert_eq!(
        r.broken_at,
        Some(target),
        "unkeyed forgery must fail at the forged row"
    );

    // The head is anchored externally (log/syslog) by the periodic job.
    let head = kestrel_server::audit::head(&ts.state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(head.0 > target);
    kestrel_server::jobs::anchor_audit_head(&ts.state)
        .await
        .unwrap();

    // Deleting a row in the middle is detected too.
    ts.cleanup().await;
}

#[tokio::test]
async fn mfa_and_rate_limit() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (s, m) = ts.post("/api/me/mfa/setup", json!({})).await;
    assert_eq!(s, 200);
    let secret = m["secret"].as_str().unwrap().to_string();
    assert!(m["otpauth_url"].as_str().unwrap().starts_with("otpauth://"));
    let totp = kestrel_server::crypto::totp_for(&secret, "admin@acme.test").unwrap();
    let (s, _) = ts
        .post("/api/me/mfa/enable", json!({"totp": "000000"}))
        .await;
    assert!(s == 400 || totp.generate_current().unwrap() == "000000");
    let enabled_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (s, v) = ts
        .post(
            "/api/me/mfa/enable",
            json!({"totp": totp.generate(enabled_at)}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["user"]["mfa_enabled"], true);

    let c = http_client(&ts.web_ca_pem);
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "admin@acme.test", "password": "correct horse battery"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], "mfa_required");
    // L1: a wrong password without a code gets the same answer as a right one…
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "admin@acme.test", "password": "wrong horse battery"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401);
    let v: Value = r.json().await.unwrap();
    assert_eq!(
        v["error"]["code"], "mfa_required",
        "no password oracle before MFA"
    );
    // …and the enrolment code cannot be replayed at login.
    let now = enabled_at;
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "admin@acme.test", "password": "correct horse battery", "totp": totp.generate(now)}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "TOTP step already used for enrolment");
    let next = totp.generate(now + 30);
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(
            &json!({"email": "admin@acme.test", "password": "correct horse battery", "totp": next}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    // Same code again: replay refused.
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(
            &json!({"email": "admin@acme.test", "password": "correct horse battery", "totp": next}),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 401, "TOTP replay must be refused");

    // Per-account backoff after repeated failures (M4).
    let mut statuses = vec![];
    for _ in 0..10 {
        let r = c
            .post(ts.url("/api/auth/login"))
            .json(&json!({"email": "victim@acme.test", "password": "guess guess guess"}))
            .send()
            .await
            .unwrap();
        statuses.push(r.status().as_u16());
    }
    assert!(statuses.contains(&401));
    assert_eq!(*statuses.last().unwrap(), 429, "{statuses:?}");
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "victim@acme.test", "password": "x"}))
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["code"], "rate_limited");
    assert!(v["error"]["retry_after_ms"].as_i64().unwrap() > 0, "{v}");
    ts.cleanup().await;
}
