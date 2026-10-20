//! Signed agent auto-update with staged rings: registration checks (key,
//! signature, URL, server-hosted package hash), ring-by-ring promotion,
//! delivery on Hello and on promotion, outcomes, halt, pinned groups, RBAC,
//! audit, and package download on the agent port.

mod common;

use base64::Engine as _;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use kestrel_common::{
    update::signed_message,
    wire::{AgentHealth, AgentPayload, Heartbeat, ServerPayload, UpdateManifest},
};
use serde_json::{json, Value};

const PKG: &[u8] = b"pretend this is KestrelAgent-9.9.9.msi";

fn key() -> SigningKey {
    SigningKey::from_bytes(&[9u8; 32])
}

fn pubkey_b64() -> String {
    base64::engine::general_purpose::STANDARD.encode(key().verifying_key().to_bytes())
}

fn sha_hex(b: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(b))
}

fn manifest(sk: &SigningKey, version: &str, url: &str, sha: &str) -> UpdateManifest {
    let mut m = UpdateManifest {
        version: version.into(),
        url: url.into(),
        sha256: sha.into(),
        signature: String::new(),
    };
    m.signature =
        base64::engine::general_purpose::STANDARD.encode(sk.sign(&signed_message(&m)).to_bytes());
    m
}

fn ring<'a>(rel: &'a Value, name: &str) -> &'a Value {
    rel["rings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ring"] == name)
        .unwrap()
}

async fn release(ts: &TestServer, id: &str) -> Value {
    let (s, list) = ts.get("/api/updates/releases").await;
    assert_eq!(s, 200, "{list}");
    list.as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .cloned()
        .unwrap()
}

async fn enroll_in(ts: &TestServer, ca: &str, group: &str, host: &str) -> TestAgent {
    let (s, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"group_id": group, "max_uses": 1}),
        )
        .await;
    assert_eq!(s, 200, "{tok}");
    enroll(ts.grpc_port, ca, tok["token"].as_str().unwrap(), host)
        .await
        .expect("enroll")
}

fn hello_v(agent: &TestAgent, host: &str, version: &str) -> kestrel_common::wire::Hello {
    let mut h = hello(agent, host);
    h.agent_version = version.into();
    h
}

/// Agent outbox seqs are persistent: keep them increasing across reconnects.
static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn bump(st: &mut AgentStream) {
    st.seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
}

/// Everything the server sent before the ack of a fresh heartbeat.
async fn drain(st: &mut AgentStream) -> Vec<ServerPayload> {
    bump(st);
    let seq = st
        .send(&AgentPayload::Heartbeat(Heartbeat {
            seq: st.seq + 1,
            ts: kestrel_common::now_ms(),
            health: AgentHealth::default(),
        }))
        .await;
    st.wait_ack(seq).await
}

fn updates_in(msgs: &[ServerPayload]) -> Vec<UpdateManifest> {
    msgs.iter()
        .filter_map(|m| match m {
            ServerPayload::Update(u) => Some(u.clone()),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn staged_rollout_end_to_end() {
    let pkgs = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(pkgs.path().join("updates")).unwrap();
    std::fs::write(pkgs.path().join("updates/KestrelAgent-9.9.9.msi"), PKG).unwrap();
    let agent_dir = pkgs.path().to_path_buf();
    let Some(mut ts) = TestServer::start_custom(false, move |c| {
        c.update_pubkey = Some(pubkey_b64());
        c.agent_dir = agent_dir;
    })
    .await
    else {
        return;
    };
    ts.setup_admin().await;
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();

    let (s, st) = ts.get("/api/updates/status").await;
    assert_eq!(s, 200, "{st}");
    assert_eq!(st["signing_key_configured"], true);
    assert_eq!(st["public_key"], pubkey_b64());
    assert_eq!(
        st["package_base_url"],
        "https://localhost:8443/downloads/updates/"
    );

    // Groups: IT in canary, Sales default (broad), Lab pinned.
    let (s, it) = ts
        .post(
            "/api/groups",
            json!({"name": "IT", "update_ring": "canary"}),
        )
        .await;
    assert_eq!(s, 200, "{it}");
    assert_eq!(it["update_ring"], "canary");
    let (_, sales) = ts.post("/api/groups", json!({"name": "Sales"})).await;
    assert_eq!(sales["update_ring"], "broad");
    let (s, _) = ts
        .post(
            "/api/groups",
            json!({"name": "Bad", "update_ring": "ring9"}),
        )
        .await;
    assert_eq!(s, 400);
    let it_id = it["id"].as_str().unwrap().to_string();
    let sales_id = sales["id"].as_str().unwrap().to_string();

    let a = enroll_in(&ts, &ca, &it_id, "IT-01").await;
    let b = enroll_in(&ts, &ca, &sales_id, "SALES-01").await;

    // ---- registration checks
    let sha = sha_hex(PKG);
    let ext_url = "https://cdn.example.com/kestrel/KestrelAgent-9.9.9.msi";
    let good = manifest(&key(), "9.9.9", ext_url, &sha);
    let mut tampered = good.clone();
    tampered.url = "https://evil.example.com/KestrelAgent-9.9.9.msi".into();
    let (s, e) = ts
        .post("/api/updates/releases", json!({"manifest": tampered}))
        .await;
    assert_eq!(s, 400, "{e}");
    assert!(e["error"]["message"]
        .as_str()
        .unwrap()
        .contains("does not verify"));
    let other = SigningKey::from_bytes(&[1u8; 32]);
    let (s, _) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": manifest(&other, "9.9.9", ext_url, &sha)}),
        )
        .await;
    assert_eq!(s, 400, "signed with another key");
    let (s, _) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": manifest(&key(), "9.9.9", "http://cdn.example.com/x.msi", &sha)}),
        )
        .await;
    assert_eq!(s, 400, "plain http");
    // Server-hosted: web port refused; wrong hash / missing file refused.
    let (s, e) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": manifest(&key(), "9.9.9", "https://localhost/downloads/updates/KestrelAgent-9.9.9.msi", &sha)}),
        )
        .await;
    assert_eq!(s, 400, "{e}");
    assert!(e["error"]["message"]
        .as_str()
        .unwrap()
        .contains("agent port"));
    let (s, e) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": manifest(&key(), "9.9.9", "https://localhost:8443/downloads/updates/KestrelAgent-9.9.9.msi", &"ab".repeat(32))}),
        )
        .await;
    assert_eq!(s, 400, "{e}");
    let (s, _) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": manifest(&key(), "9.9.9", "https://localhost:8443/downloads/updates/missing.msi", &sha)}),
        )
        .await;
    assert_eq!(s, 400);

    // A matching server-hosted package registers; so does the manifest as a
    // JSON string (what an admin pastes).
    let local_url = "https://localhost:8443/downloads/updates/KestrelAgent-9.9.9.msi";
    let m = manifest(&key(), "9.9.9", local_url, &sha);
    let (s, rel) = ts
        .post(
            "/api/updates/releases",
            json!({"manifest": serde_json::to_string_pretty(&m).unwrap(), "notes": "Fixes ETW watchdog"}),
        )
        .await;
    assert_eq!(s, 200, "{rel}");
    assert_eq!(rel["state"], "staged");
    assert_eq!(rel["next_ring"], "canary");
    assert_eq!(rel["created_by_name"], "Ada Admin");
    assert_eq!(ring(&rel, "canary")["devices"], 1);
    assert_eq!(ring(&rel, "broad")["devices"], 1);
    let rid = rel["id"].as_str().unwrap().to_string();
    let (s, _) = ts
        .post("/api/updates/releases", json!({"manifest": m.clone()}))
        .await;
    assert_eq!(s, 409, "duplicate version");

    // The package is served on the agent port (HTTP/2, agent CA).
    let dl = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ca.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let r = dl
        .get(format!(
            "https://localhost:{}/downloads/updates/KestrelAgent-9.9.9.msi",
            ts.grpc_port
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(&r.bytes().await.unwrap()[..], PKG);
    let r = dl
        .get(format!(
            "https://localhost:{}/downloads/updates/../KestrelAgent-9.9.9.msi",
            ts.grpc_port
        ))
        .send()
        .await
        .unwrap();
    assert_ne!(r.status(), 200);

    // ---- nothing is enabled yet: no Update on Hello
    let mut sa = connect(ts.grpc_port, &a, hello_v(&a, "IT-01", "0.1.0"))
        .await
        .unwrap();
    assert!(updates_in(&drain(&mut sa).await).is_empty());

    // Out-of-order promotion is refused.
    let (s, _) = ts
        .post(
            &format!("/api/updates/releases/{rid}/promote"),
            json!({"ring": "early"}),
        )
        .await;
    assert_eq!(s, 409);
    let (s, _) = ts
        .post(
            &format!("/api/updates/releases/{rid}/promote"),
            json!({"ring": "ring0"}),
        )
        .await;
    assert_eq!(s, 400);

    // ---- promote canary: the connected canary agent gets it immediately
    let (s, rel) = ts
        .post(
            &format!("/api/updates/releases/{rid}/promote"),
            json!({"ring": "canary"}),
        )
        .await;
    assert_eq!(s, 200, "{rel}");
    assert_eq!(rel["delivered_now"], 1);
    assert_eq!(rel["state"], "rolling");
    assert_eq!(rel["next_ring"], "early");
    let (_, p, _) = sa
        .recv_until(|p| matches!(p, ServerPayload::Update(_)))
        .await;
    assert_eq!(p, ServerPayload::Update(m.clone()));
    let (s, _) = ts
        .post(
            &format!("/api/updates/releases/{rid}/promote"),
            json!({"ring": "canary"}),
        )
        .await;
    assert_eq!(s, 409, "already enabled");

    // A broad-ring agent does not get it.
    let mut sb = connect(ts.grpc_port, &b, hello_v(&b, "SALES-01", "0.1.0"))
        .await
        .unwrap();
    assert!(updates_in(&drain(&mut sb).await).is_empty());

    // The canary agent reports a failure; reconnecting re-offers the release.
    bump(&mut sa);
    sa.send(&AgentPayload::UpdateResult {
        version: "9.9.9".into(),
        ok: false,
        error: "downloaded package hash 00 does not match manifest".into(),
    })
    .await;
    drain(&mut sa).await;
    let rel = release(&ts, &rid).await;
    assert_eq!(ring(&rel, "canary")["delivered"], 1);
    assert_eq!(ring(&rel, "canary")["failed"], 1);
    assert_eq!(rel["recent_failures"][0]["hostname"], "IT-01");
    drop(sa);
    let mut sa = connect(ts.grpc_port, &a, hello_v(&a, "IT-01", "0.1.0"))
        .await
        .unwrap();
    assert_eq!(updates_in(&drain(&mut sa).await), vec![m.clone()]);
    drop(sa);

    // The agent comes back on 9.9.9: success, and no further offer.
    let mut sa = connect(ts.grpc_port, &a, hello_v(&a, "IT-01", "9.9.9"))
        .await
        .unwrap();
    assert!(updates_in(&drain(&mut sa).await).is_empty());
    let rel = release(&ts, &rid).await;
    let canary = ring(&rel, "canary");
    assert_eq!(canary["succeeded"], 1, "{rel}");
    assert_eq!(canary["failed"], 0);
    assert_eq!(canary["on_target"], 1);
    assert_eq!(canary["pending"], 0);
    let (_, st) = ts.get("/api/updates/status").await;
    let canary_status = st["rings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["ring"] == "canary")
        .unwrap()
        .clone();
    assert_eq!(canary_status["target"]["version"], "9.9.9");
    assert_eq!(canary_status["versions"][0]["version"], "9.9.9");

    // ---- pinned groups never update, even when broad is enabled
    let (s, g) = ts
        .send(
            reqwest::Method::PATCH,
            &format!("/api/groups/{sales_id}"),
            json!({"update_ring": "pinned"}),
        )
        .await;
    assert_eq!(s, 200, "{g}");
    assert_eq!(g["update_ring"], "pinned");
    for r in ["early", "broad"] {
        let (s, v) = ts
            .post(
                &format!("/api/updates/releases/{rid}/promote"),
                json!({"ring": r}),
            )
            .await;
        assert_eq!(s, 200, "{v}");
        assert_eq!(v["delivered_now"], 0);
    }
    assert!(updates_in(&drain(&mut sb).await).is_empty());
    // Back to broad: the connected agent gets the release right away.
    let (s, _) = ts
        .send(
            reqwest::Method::PATCH,
            &format!("/api/groups/{sales_id}"),
            json!({"update_ring": "broad"}),
        )
        .await;
    assert_eq!(s, 200);
    let (_, p, _) = sb
        .recv_until(|p| matches!(p, ServerPayload::Update(_)))
        .await;
    assert_eq!(p, ServerPayload::Update(m.clone()));
    let rel = release(&ts, &rid).await;
    assert_eq!(rel["state"], "complete");
    assert!(rel["next_ring"].is_null());

    // ---- halt: a newer release enabled for canary stops being offered
    let m2 = manifest(&key(), "9.9.10", ext_url, &sha);
    let (s, rel2) = ts
        .post("/api/updates/releases", json!({"manifest": m2}))
        .await;
    assert_eq!(s, 200, "{rel2}");
    let rid2 = rel2["id"].as_str().unwrap().to_string();
    let (s, _) = ts
        .post(
            &format!("/api/updates/releases/{rid2}/promote"),
            json!({"ring": "canary"}),
        )
        .await;
    assert_eq!(s, 200);
    let (_, p, _) = sa
        .recv_until(|p| matches!(p, ServerPayload::Update(_)))
        .await;
    assert!(matches!(p, ServerPayload::Update(u) if u.version == "9.9.10"));
    let (s, h) = ts
        .post(
            &format!("/api/updates/releases/{rid2}/halt"),
            json!({"reason": "crash loop on canary"}),
        )
        .await;
    assert_eq!(s, 200, "{h}");
    assert_eq!(h["state"], "halted");
    assert_eq!(h["halt_reason"], "crash loop on canary");
    assert!(h["next_ring"].is_null());
    let (s, _) = ts
        .post(&format!("/api/updates/releases/{rid2}/halt"), json!({}))
        .await;
    assert_eq!(s, 409);
    let (s, _) = ts
        .post(
            &format!("/api/updates/releases/{rid2}/promote"),
            json!({"ring": "early"}),
        )
        .await;
    assert_eq!(s, 409, "halted releases cannot be promoted");
    drop(sa);
    let mut sa = connect(ts.grpc_port, &a, hello_v(&a, "IT-01", "9.9.9"))
        .await
        .unwrap();
    assert!(
        updates_in(&drain(&mut sa).await).is_empty(),
        "halted release is no longer delivered"
    );
    drop(sa);
    drop(sb);

    // ---- RBAC: analysts can read, not write
    let (s, _) = ts
        .post(
            "/api/users",
            json!({"email": "ana@acme.test", "name": "Ana", "role": "analyst", "password": "analyst password 1"}),
        )
        .await;
    assert_eq!(s, 200);
    let ana = http_client(&ts.web_ca_pem);
    let r = ana
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": "ana@acme.test", "password": "analyst password 1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let csrf = r.json::<Value>().await.unwrap()["csrf_token"]
        .as_str()
        .unwrap()
        .to_string();
    let r = ana
        .get(ts.url("/api/updates/releases"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    for (path, body) in [
        (
            "/api/updates/releases".to_string(),
            json!({"manifest": manifest(&key(), "9.9.11", ext_url, &sha)}),
        ),
        (format!("/api/updates/releases/{rid2}/halt"), json!({})),
    ] {
        let r = ana
            .post(ts.url(&path))
            .header("X-CSRF-Token", &csrf)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{path}");
    }
    let (_, me) = ts.get("/api/me").await;
    assert!(me["privileges"]
        .as_array()
        .unwrap()
        .iter()
        .any(|p| p == "updates.write"));

    // ---- every write is audited
    let (_, log) = ts.get("/api/audit-log?limit=200").await;
    let actions: Vec<&str> = log["items"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str())
        .collect();
    for a in [
        "update.release_register",
        "update.release_rejected",
        "update.release_promote",
        "update.release_halt",
    ] {
        assert!(actions.contains(&a), "{a} missing from {actions:?}");
    }
    ts.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn registration_refused_without_public_key() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (s, st) = ts.get("/api/updates/status").await;
    assert_eq!(s, 200);
    assert_eq!(st["signing_key_configured"], false);
    let m = manifest(
        &key(),
        "9.9.9",
        "https://cdn.example.com/KestrelAgent-9.9.9.msi",
        &sha_hex(PKG),
    );
    let (s, e) = ts
        .post("/api/updates/releases", json!({"manifest": m}))
        .await;
    assert_eq!(s, 400);
    assert!(e["error"]["message"]
        .as_str()
        .unwrap()
        .contains("KESTREL_UPDATE_PUBKEY"));
    let (_, list) = ts.get("/api/updates/releases").await;
    assert_eq!(list, json!([]));
    ts.cleanup().await;
}
