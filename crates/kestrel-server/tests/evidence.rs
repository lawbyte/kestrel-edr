//! Evidence capture for suspected data theft, server side: ingest of agent
//! reports (metadata only, never telemetry / hunt), RBAC (admin interactive
//! sessions only), collection pulled over the live channel with integrity
//! checks, sealed at-rest storage, password-protected one-time downloads,
//! deletion, retention and settings / policy validation.

mod common;

use base64::Engine;
use common::*;
use kestrel_common::{
    evidence::{
        container::ContainerWriter, sha256_hex, EvidenceReport, EvidenceState, CAP_EVIDENCE,
    },
    now_ms,
    remote::{FileReply, LiveAgentMsg, LiveServerMsg, RemoteErrorCode},
    seal,
    wire::{AgentPayload, ServerPayload},
    ActionOutcome, Alert, DataCategory, PathClass, ProcessGuid, ProcessInfo, ResponseAction,
    RuleMode, Severity, SignatureState,
};
use kestrel_server::grpc::pb::AgentEnvelope;
use reqwest::Method;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "admin@acme.test";
const ADMIN_PASSWORD: &str = "correct horse battery";
const HOST: &str = "FIN-LT-042";
/// In the manifest (metadata): visible to `read`, never in telemetry / hunt.
const PATH_MARKER: &str = "PRIVACY-MARKER-7731";
/// In the bundle content: never readable on the server's disk.
const CONTENT_MARKER: &[u8] = b"PLAINTEXT-MARKER-4242";

// ------------------------------------------------------------ fake agent

/// Bundles the fake agent serves (container bytes by bundle id).
type Served = Arc<Mutex<HashMap<Uuid, Vec<u8>>>>;

struct Agent {
    tx: mpsc::Sender<AgentEnvelope>,
    msgs: mpsc::UnboundedReceiver<(u64, ServerPayload)>,
    seq: u64,
    task: tokio::task::JoinHandle<()>,
}

impl Agent {
    async fn send(&mut self, p: &AgentPayload) -> u64 {
        self.seq += 1;
        self.tx
            .send(AgentEnvelope {
                seq: self.seq,
                compressed: false,
                payload: serde_json::to_vec(p).unwrap(),
            })
            .await
            .unwrap();
        self.seq
    }

    async fn ack(&self, server_seq: u64) {
        self.tx
            .send(AgentEnvelope {
                seq: 0,
                compressed: false,
                payload: serde_json::to_vec(&AgentPayload::Ack { seq: server_seq }).unwrap(),
            })
            .await
            .unwrap();
    }

    async fn next(&mut self, pred: impl Fn(&ServerPayload) -> bool) -> (u64, ServerPayload) {
        loop {
            let (seq, p) = tokio::time::timeout(Duration::from_secs(15), self.msgs.recv())
                .await
                .expect("timed out waiting for a server message")
                .expect("stream closed");
            if pred(&p) {
                return (seq, p);
            }
        }
    }

    async fn wait_ack(&mut self, seq: u64) {
        self.next(|p| matches!(p, ServerPayload::Ack { seq: s } if *s >= seq))
            .await;
    }

    /// Next `Command` (acked): its id and action.
    async fn command(&mut self) -> (Uuid, ResponseAction) {
        let (seq, p) = self
            .next(|p| matches!(p, ServerPayload::Command { .. }))
            .await;
        self.ack(seq).await;
        match p {
            ServerPayload::Command {
                command_id, action, ..
            } => (command_id, action),
            _ => unreachable!(),
        }
    }

    async fn result(&mut self, command_id: Uuid, action: ResponseAction, ok: bool) {
        let artifact = match &action {
            ResponseAction::CollectEvidence { bundle_id } => Some(bundle_id.to_string()),
            _ => None,
        };
        let s = self
            .send(&AgentPayload::ActionResult {
                command_id,
                outcome: ActionOutcome {
                    action,
                    ok,
                    detail: if ok {
                        String::new()
                    } else {
                        "bundle not found on the PC".into()
                    },
                    ts: now_ms(),
                    artifact,
                },
            })
            .await;
        self.wait_ack(s).await;
    }

    async fn report(&mut self, r: EvidenceReport) {
        let s = self.send(&AgentPayload::Evidence(Box::new(r))).await;
        self.wait_ack(s).await;
    }

    async fn disconnect(self, ts: &TestServer, id: Uuid) -> u64 {
        let seq = self.seq;
        self.task.abort();
        drop(self.tx);
        for _ in 0..200 {
            if !ts.state.agents.is_connected(&id) {
                return seq;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("agent still registered");
    }
}

/// Connect a fake agent: `EvidenceRead` is answered from `served` (SHA-256
/// of every byte read in the live session on `eof`, like the real agent);
/// every other server message is handed to the test.
async fn connect_agent(
    ts: &TestServer,
    agent: &TestAgent,
    caps: &[&str],
    served: Served,
    seq: u64,
) -> Agent {
    let mut h = hello(agent, HOST);
    h.capabilities = caps.iter().map(|c| c.to_string()).collect();
    let mut stream = connect(ts.grpc_port, agent, h).await.unwrap();
    let (mtx, msgs) = mpsc::unbounded_channel();
    let tx = stream.tx.clone();
    let live_tx = stream.tx.clone();
    let task = tokio::spawn(async move {
        let mut hashes: HashMap<Uuid, Sha256> = HashMap::new();
        while let Ok(Some(env)) = stream.rx.message().await {
            let raw = kestrel_server::grpc::decode_payload(env.compressed, &env.payload).unwrap();
            let p: ServerPayload = serde_json::from_slice(&raw).unwrap();
            match p {
                ServerPayload::Live {
                    session_id,
                    msg:
                        LiveServerMsg::EvidenceRead {
                            request_id,
                            bundle_id,
                            offset,
                            len,
                        },
                } => {
                    assert!(len <= kestrel_common::evidence::READ_CHUNK_MAX);
                    let reply = match served.lock().unwrap().get(&bundle_id) {
                        None => FileReply::error(RemoteErrorCode::NotFound, "no such bundle"),
                        Some(data) => {
                            let start = (offset as usize).min(data.len());
                            let end = (start + len as usize).min(data.len());
                            let h = hashes.entry(session_id).or_default();
                            h.update(&data[start..end]);
                            let eof = end >= data.len();
                            FileReply::Data {
                                offset,
                                data_b64: base64::engine::general_purpose::STANDARD
                                    .encode(&data[start..end]),
                                size: data.len() as u64,
                                eof,
                                sha256: eof.then(|| hex::encode(h.clone().finalize())),
                            }
                        }
                    };
                    let env = AgentEnvelope {
                        seq: 0,
                        compressed: false,
                        payload: serde_json::to_vec(&AgentPayload::Live {
                            session_id,
                            msg: LiveAgentMsg::EvidenceData { request_id, reply },
                        })
                        .unwrap(),
                    };
                    if live_tx.send(env).await.is_err() {
                        break;
                    }
                }
                other => {
                    if mtx.send((env.seq, other)).is_err() {
                        break;
                    }
                }
            }
        }
    });
    let mut a = Agent {
        tx,
        msgs,
        seq,
        task,
    };
    a.next(|p| matches!(p, ServerPayload::Welcome { .. })).await;
    a
}

// ------------------------------------------------------------ fixtures

fn proc_info(guid: &str, image: &str) -> ProcessInfo {
    ProcessInfo {
        guid: ProcessGuid(guid.into()),
        pid: 4242,
        ppid: 1,
        parent_guid: None,
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

fn st02_alert() -> Alert {
    Alert {
        id: Uuid::new_v4(),
        ts: now_ms(),
        rule_id: "ST-02".into(),
        rule_name: "Browser credential store read by untrusted process".into(),
        rule_author: None,
        severity: Severity::High,
        attack: vec!["T1555.003".into()],
        mode: RuleMode::Audit,
        summary: "setup_x64.exe read Chrome 'Login Data'".into(),
        process: proc_info("g-setup", r"C:\Users\alice\Downloads\setup_x64.exe"),
        ancestry: vec![],
        data_at_risk: vec![DataCategory::BrowserPasswords],
        evidence: vec![],
        actions: vec![],
        protection_off: None,
    }
}

fn manifest(bundle: Uuid, alert: Uuid) -> Value {
    let now = now_ms();
    json!({
        "format": 1, "bundle_id": bundle, "alert_id": alert, "alert_ids": [alert], "rule_id": "ST-02",
        "hostname": HOST, "agent_version": "1.2.0", "started_at": now - 60_000,
        "window_start": now - 180_000, "window_end": now, "completed_at": now,
        "parts": {"staged_files": true, "secrets_list": true, "secrets_copy": true, "pcap": true, "local_retention_days": 14},
        "processes": [{"guid": "g-setup", "pid": 4242, "image": "C:\\Users\\alice\\Downloads\\setup_x64.exe", "role": "alerting"}],
        "staged": [{"path": format!("C:\\Users\\alice\\AppData\\Local\\Temp\\stg\\{PATH_MARKER}.zip"), "written_at": now - 30_000,
                    "op": "created", "process_guid": "g-setup", "image": "C:\\Users\\alice\\Downloads\\setup_x64.exe",
                    "copy": {"status": "copied", "entry": format!("staged/0001-{PATH_MARKER}.zip"), "size": 10}}],
        "secrets": [],
        "pcap": {"status": "captured", "mechanism": "pktmon", "filters": [{"ip": "203.0.113.7", "port": 443, "proto": "tcp"}]},
        "notes": ["Login Data copied", "token=kte_SECRETSECRET1234"]
    })
}

/// A real KEB1 container (> 2 chunks, so the pull window is exercised).
fn container(bundle: Uuid, alert: Uuid) -> Vec<u8> {
    let mut staged = Vec::new();
    while staged.len() < 1_300_000 {
        staged.extend_from_slice(CONTENT_MARKER);
        staged.extend_from_slice(b" stolen-passwords.txt line\n");
    }
    let mut w = ContainerWriter::new(Vec::new()).unwrap();
    w.entry(&format!("staged/0001-{PATH_MARKER}.zip"), &staged)
        .unwrap();
    w.entry("capture.pcapng", b"\x0a\x0d\x0d\x0a fake pcapng")
        .unwrap();
    w.entry(
        "manifest.json",
        serde_json::to_vec(&manifest(bundle, alert))
            .unwrap()
            .as_slice(),
    )
    .unwrap();
    w.finish().unwrap()
}

/// A container whose (hand-made) entry name escapes the bundle folder.
fn traversal_container() -> Vec<u8> {
    let mut v = b"KEB1".to_vec();
    let name = b"staged/../../etc/x";
    v.push(1);
    v.extend_from_slice(&(name.len() as u16).to_be_bytes());
    v.extend_from_slice(name);
    v.extend_from_slice(&2u32.to_be_bytes());
    v.extend_from_slice(b"hi");
    v.extend_from_slice(&0u32.to_be_bytes());
    v.push(0);
    v
}

fn ready(bundle: Uuid, alert: Uuid, size: u64, sha: &str) -> EvidenceReport {
    EvidenceReport {
        bundle_id: bundle,
        alert_id: alert,
        alert_ids: vec![alert],
        rule_id: "ST-02".into(),
        state: EvidenceState::Ready,
        ts: now_ms(),
        manifest: Some(serde_json::from_value(manifest(bundle, alert)).unwrap()),
        bundle_size: size,
        bundle_sha256: Some(sha.into()),
        local_expires_at: Some(now_ms() + 14 * 86_400_000),
        detail: String::new(),
    }
}

// ------------------------------------------------------------ helpers

async fn new_agent(ts: &TestServer, host: &str) -> TestAgent {
    let (_, inst) = ts.get("/api/agent/installer").await;
    let ca = inst["ca_pem"].as_str().unwrap().to_string();
    let (_, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 1, "max_uses": 1}),
        )
        .await;
    enroll(ts.grpc_port, &ca, tok["token"].as_str().unwrap(), host)
        .await
        .unwrap()
}

async fn audit_rows(ts: &TestServer, action: &str) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as("SELECT actor_id, details FROM audit_log WHERE action = $1 ORDER BY id")
        .bind(action)
        .fetch_all(&ts.state.db)
        .await
        .unwrap()
}

async fn wait_audit(ts: &TestServer, action: &str, bundle: Uuid) -> (Option<Uuid>, Value) {
    for _ in 0..200 {
        if let Some(r) = audit_rows(ts, action)
            .await
            .into_iter()
            .rev()
            .find(|r| r.1["bundle_id"] == bundle.to_string())
        {
            return r;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no audit row {action} for {bundle}");
}

async fn bundle(ts: &TestServer, id: Uuid) -> Value {
    let (s, v) = ts.get(&format!("/api/evidence/{id}")).await;
    assert_eq!(s, 200, "{v}");
    v
}

/// Poll until the bundle leaves `collecting`.
async fn settled(ts: &TestServer, id: Uuid) -> Value {
    for _ in 0..300 {
        let v = bundle(ts, id).await;
        if v["status"] != "collecting" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("bundle {id} still collecting");
}

async fn login(ts: &TestServer, email: &str, password: &str) -> (reqwest::Client, String) {
    let c = http_client(&ts.web_ca_pem);
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": email, "password": password}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: Value = r.json().await.unwrap();
    (c, v["csrf_token"].as_str().unwrap().to_string())
}

async fn call(c: &reqwest::Client, csrf: &str, m: Method, url: String) -> (u16, Value) {
    let r = c
        .request(m, url)
        .header("X-CSRF-Token", csrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
}

/// Send the alert and a Ready report; returns the incident id.
async fn alert_and_ready(
    ag: &mut Agent,
    ts: &TestServer,
    alert: &Alert,
    r: EvidenceReport,
) -> Uuid {
    let s = ag.send(&AgentPayload::Alert(Box::new(alert.clone()))).await;
    ag.wait_ack(s).await;
    ag.report(r).await;
    let (inc,): (Option<Uuid>,) = sqlx::query_as("SELECT incident_id FROM alerts WHERE id = $1")
        .bind(alert.id)
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    inc.expect("incident")
}

/// Admin clicks Collect; the agent prepares the bundle and answers ok.
async fn collect(ts: &TestServer, ag: &mut Agent, id: Uuid) {
    let (s, v) = ts
        .post(
            &format!("/api/evidence/{id}/collect"),
            json!({"reason": "IR-2026-117 \u{202e}stealer"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "collecting");
    let (cid, action) = ag.command().await;
    assert_eq!(action, ResponseAction::CollectEvidence { bundle_id: id });
    ag.result(cid, action, true).await;
}

// ------------------------------------------------------------ tests

#[tokio::test]
async fn evidence_collect_download_delete_retention() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let agent = new_agent(&ts, HOST).await;
    let dev = agent.device_id;
    let served: Served = Default::default();
    let mut ag = connect_agent(&ts, &agent, &[CAP_EVIDENCE], served.clone(), 0).await;

    // ---- ingest: Capturing then Ready (manifest scrubbed, metadata only).
    let alert = st02_alert();
    let id = Uuid::new_v4();
    let bytes = container(id, alert.id);
    let sha = sha256_hex(&bytes);
    served.lock().unwrap().insert(id, bytes.clone());
    let s = ag.send(&AgentPayload::Alert(Box::new(alert.clone()))).await;
    ag.wait_ack(s).await;
    ag.report(EvidenceReport {
        state: EvidenceState::Capturing,
        manifest: None,
        bundle_size: 0,
        bundle_sha256: None,
        local_expires_at: None,
        ..ready(id, alert.id, 0, "")
    })
    .await;
    assert_eq!(bundle(&ts, id).await["status"], "capturing");
    let inc = {
        ag.report(ready(id, alert.id, bytes.len() as u64, &sha.to_uppercase()))
            .await;
        let (inc,): (Option<Uuid>,) =
            sqlx::query_as("SELECT incident_id FROM alerts WHERE id = $1")
                .bind(alert.id)
                .fetch_one(&ts.state.db)
                .await
                .unwrap();
        inc.unwrap()
    };
    let b = bundle(&ts, id).await;
    assert_eq!(b["status"], "ready_on_device", "{b}");
    assert_eq!(b["bundle_sha256"], sha);
    assert_eq!(b["bundle_size"], bytes.len());
    assert_eq!(b["hostname"], HOST);
    assert_eq!(b["incident_id"], inc.to_string());
    assert_eq!(b["device_online"], true);
    assert_eq!(b["agent_supports_evidence"], true);
    assert!(b["manifest"].to_string().contains(PATH_MARKER), "{b}");
    assert!(
        !b["manifest"].to_string().contains("SECRETSECRET1234"),
        "secret not redacted: {b}"
    );
    let (s, list) = ts.get(&format!("/api/incidents/{inc}/evidence")).await;
    assert_eq!(s, 200, "{list}");
    assert_eq!(list["items"][0]["id"], id.to_string());
    let (s, list) = ts
        .get(&format!(
            "/api/evidence?device_id={dev}&status=ready_on_device,stored"
        ))
        .await;
    assert_eq!(s, 200, "{list}");
    assert_eq!(list["total"], 1);
    let (s, _) = ts.get("/api/evidence?status=bogus").await;
    assert_eq!(s, 400);

    // ---- privacy: nothing of the manifest in telemetry or hunt.
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM events e WHERE e::text LIKE $1")
        .bind(format!("%{PATH_MARKER}%"))
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0, "manifest data reached the telemetry store");
    let now = now_ms();
    let (s, h) = ts
        .post(
            "/api/hunt",
            json!({"query": format!("device_id = {dev}"), "from": now - 3_600_000, "to": now + 1000, "limit": 500}),
        )
        .await;
    assert_eq!(s, 200, "{h}");
    assert!(!h.to_string().contains(PATH_MARKER), "{h}");

    // ---- RBAC: analyst / readonly read but cannot collect / download / delete.
    for role in ["analyst", "readonly"] {
        let email = format!("{role}@acme.test");
        let (s, u) = ts
            .post("/api/users", json!({"email": email, "name": role, "role": role, "password": "role password 123"}))
            .await;
        assert_eq!(s, 200, "{u}");
        let (c, csrf) = login(&ts, &email, "role password 123").await;
        let r = c
            .get(ts.url(&format!("/api/evidence/{id}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "{role} reads evidence metadata");
        let r = c
            .get(ts.url(&format!("/api/incidents/{inc}/evidence")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        for (m, path) in [
            (Method::POST, format!("/api/evidence/{id}/collect")),
            (Method::POST, format!("/api/evidence/{id}/download")),
            (Method::DELETE, format!("/api/evidence/{id}")),
        ] {
            let (s, v) = call(&c, &csrf, m, ts.url(&path)).await;
            assert_eq!(s, 403, "{role} {path}: {v}");
        }
        let r = c.get(ts.url("/api/me")).send().await.unwrap();
        let me: Value = r.json().await.unwrap();
        assert!(
            !me.to_string().contains("evidence.download"),
            "{role}: {me}"
        );
    }
    let (_, me) = ts.get("/api/me").await;
    assert!(me.to_string().contains("evidence.download"), "{me}");
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
    for (m, path) in [
        (Method::POST, format!("/api/evidence/{id}/collect")),
        (Method::POST, format!("/api/evidence/{id}/download")),
        (Method::DELETE, format!("/api/evidence/{id}")),
    ] {
        let r = bare
            .request(m, ts.url(&path))
            .bearer_auth(t["token"].as_str().unwrap())
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "API token {path}");
    }
    let r = bare
        .get(ts.url(&format!("/api/evidence/{id}")))
        .bearer_auth(t["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "API tokens may read metadata");

    // ---- generic action endpoint / download before stored refuse.
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/actions"),
            json!({"action": {"type": "collect_evidence", "bundle_id": id}}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/actions"),
            json!({"action": {"type": "delete_evidence", "bundle_id": id}}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    let (s, v) = ts
        .post(&format!("/api/evidence/{id}/download"), json!({}))
        .await;
    assert_eq!(s, 409);
    assert_eq!(v["error"]["reason"], "not_ready");
    let (s, _) = ts
        .post(
            &format!("/api/evidence/{}/collect", Uuid::new_v4()),
            json!({}),
        )
        .await;
    assert_eq!(s, 404);

    // ---- collect → pull → stored, sealed at rest, PC told to delete.
    collect(&ts, &mut ag, id).await;
    let b = settled(&ts, id).await;
    assert_eq!(b["status"], "stored", "{b}");
    assert_eq!(b["collect_requested_by"], "Ada Admin");
    assert!(b["expires_at"].as_i64().unwrap() > now_ms() + 13 * 86_400_000);
    let (_, d) = ts.get("/api/me").await;
    let admin_id = d["user"]["id"]
        .as_str()
        .map(|s| Uuid::parse_str(s).unwrap());
    let (actor, a) = wait_audit(&ts, "evidence.collected", id).await;
    assert_eq!(a["sha256"], sha);
    assert_eq!(a["bytes"], bytes.len());
    assert_eq!(a["hostname"], HOST);
    if admin_id.is_some() {
        assert_eq!(
            actor, admin_id,
            "collected is attributed to the admin who asked"
        );
    }
    let (_, a) = wait_audit(&ts, "evidence.collect_requested", id).await;
    assert_eq!(
        a["reason"], "IR-2026-117 stealer",
        "reason cleaned and audited"
    );
    let (_, del) = ag.command().await;
    assert_eq!(del, ResponseAction::DeleteEvidence { bundle_id: id });
    let blob = ts.state.cfg.evidence_dir.join(format!("{id}.kes"));
    let raw = std::fs::read(&blob).unwrap();
    assert!(
        !raw.windows(CONTENT_MARKER.len())
            .any(|w| w == CONTENT_MARKER),
        "plaintext on the server's disk"
    );
    // Per-bundle data key, wrapped with the master key in the row.
    let (wrapped,): (Option<String>,) =
        sqlx::query_as("SELECT data_key_enc FROM evidence_bundles WHERE id = $1")
            .bind(id)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    let key = kestrel_server::evidence::unwrap_key(&ts.state, &wrapped.unwrap()).unwrap();
    assert_ne!(key, ts.state.mk.subkey("evidence-at-rest-v1"));
    let mut plain = Vec::new();
    let o = seal::open_stream(&key, id.as_bytes(), &raw[..], &mut plain).unwrap();
    assert_eq!(plain, bytes);
    assert_eq!(o.sha256, sha);
    assert!(seal::open_stream(&key, Uuid::new_v4().as_bytes(), &raw[..], std::io::sink()).is_err());
    // A late duplicate Ready / Deleted from the PC keeps it stored.
    ag.report(ready(id, alert.id, bytes.len() as u64, &sha))
        .await;
    ag.report(EvidenceReport {
        state: EvidenceState::Deleted,
        ..ready(id, alert.id, 0, "")
    })
    .await;
    assert_eq!(bundle(&ts, id).await["status"], "stored");
    let (s, v) = ts
        .post(&format!("/api/evidence/{id}/collect"), json!({}))
        .await;
    assert_eq!(s, 409, "already stored");
    assert_eq!(v["error"]["reason"], "not_ready");

    // ---- download: one-time ticket, AES zip, bound to the session.
    let (s, v) = ts
        .post(
            &format!("/api/evidence/{id}/download"),
            json!({"reason": "x".repeat(201)}),
        )
        .await;
    assert_eq!(s, 400, "reason too long: {v}");
    let (s, t1) = ts
        .post(
            &format!("/api/evidence/{id}/download"),
            json!({"reason": "case 117"}),
        )
        .await;
    assert_eq!(s, 200, "{t1}");
    let pw = t1["password"].as_str().unwrap().to_string();
    assert_eq!(pw.len(), 24);
    assert_eq!(
        t1["url"],
        format!(
            "/api/evidence/downloads/{}",
            t1["download_id"].as_str().unwrap()
        )
    );
    assert!(t1["file_name"]
        .as_str()
        .unwrap()
        .starts_with("evidence-FIN-LT-042-"));
    assert!(t1["expires_at"].as_i64().unwrap() > now_ms());
    let url = t1["url"].as_str().unwrap().to_string();
    // Another admin session (same user) cannot use it, and does not burn it.
    let (other, _) = login(&ts, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    let r = other.get(ts.url(&url)).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let r = ts.http.get(ts.url(&url)).send().await.unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.headers()["content-type"], "application/zip");
    assert_eq!(r.headers()["x-content-type-options"], "nosniff");
    assert_eq!(r.headers()["cache-control"], "no-store");
    assert!(r.headers()["content-disposition"]
        .to_str()
        .unwrap()
        .starts_with("attachment; filename=\"evidence-FIN-LT-042-"));
    let zip_bytes = r.bytes().await.unwrap().to_vec();
    assert_eq!(zip_bytes.len() as u64, t1["size"].as_u64().unwrap());
    assert!(!zip_bytes
        .windows(CONTENT_MARKER.len())
        .any(|w| w == CONTENT_MARKER));
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes.clone())).unwrap();
    let names: Vec<String> = z.file_names().map(|n| n.unwrap().to_string()).collect();
    let top = t1["file_name"]
        .as_str()
        .unwrap()
        .trim_end_matches(".zip")
        .to_string();
    for n in [
        format!("{top}/README.txt"),
        format!("{top}/staged/0001-{PATH_MARKER}.zip.bin"),
        format!("{top}/capture.pcapng"),
        format!("{top}/manifest.json"),
    ] {
        assert!(names.contains(&n), "{n} missing from {names:?}");
    }
    let mut got = Vec::new();
    z.by_name_decrypt(
        &format!("{top}/staged/0001-{PATH_MARKER}.zip.bin"),
        pw.as_bytes(),
    )
    .unwrap()
    .read_to_end(&mut got)
    .unwrap();
    assert!(got.starts_with(CONTENT_MARKER));
    assert!(z
        .by_name_decrypt(
            &format!("{top}/capture.pcapng"),
            b"wrong password 123456789"
        )
        .is_err());
    // Single use.
    let r = ts.http.get(ts.url(&url)).send().await.unwrap();
    assert_eq!(r.status(), 404);
    let (_, a) = wait_audit(&ts, "evidence.download_started", id).await;
    assert_eq!(a["download_id"], t1["download_id"]);
    assert_eq!(a["reason"], "case 117");
    let (_, a) = wait_audit(&ts, "evidence.downloaded", id).await;
    assert_eq!(a["download_id"], t1["download_id"]);
    assert_eq!(a["complete"], true);
    assert!(!a.to_string().contains(&pw), "password in the audit log");
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log WHERE details::text LIKE $1")
        .bind(format!("%{pw}%"))
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(n, 0);
    for _ in 0..100 {
        if std::fs::read_dir(ts.state.cfg.evidence_dir.join("downloads"))
            .unwrap()
            .count()
            == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        std::fs::read_dir(ts.state.cfg.evidence_dir.join("downloads"))
            .unwrap()
            .count(),
        0,
        "download archive left behind"
    );
    let b = bundle(&ts, id).await;
    assert_eq!(b["downloads"], 1);
    assert!(b["last_downloaded_at"].is_number());

    // ---- retention: lowering the setting applies to stored bundles (from
    // collected_at); the expired one loses its blob and its data key.
    let collected = now_ms() - 2 * 86_400_000;
    sqlx::query("UPDATE evidence_bundles SET collected_at = $2 WHERE id = $1")
        .bind(id)
        .bind(collected)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let (_, mut set) = ts.get("/api/settings").await;
    set["retention_days"]["evidence"] = json!(1);
    let (s, v) = ts.send(Method::PUT, "/api/settings", set).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(
        bundle(&ts, id).await["expires_at"],
        collected + 86_400_000,
        "expires_at follows the new setting"
    );
    kestrel_server::jobs::retention(&ts.state).await.unwrap();
    let (k,): (Option<String>,) =
        sqlx::query_as("SELECT data_key_enc FROM evidence_bundles WHERE id = $1")
            .bind(id)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert!(k.is_none(), "data key kept after expiry");
    assert!(!blob.exists(), "expired blob still on disk");
    assert_eq!(bundle(&ts, id).await["status"], "expired");
    let (actor, a) = wait_audit(&ts, "evidence.expired", id).await;
    assert_eq!(actor, None, "expiry is a system action");
    assert_eq!(a["hostname"], HOST);
    let (s, _) = ts
        .post(&format!("/api/evidence/{id}/download"), json!({}))
        .await;
    assert_eq!(s, 409);

    // ---- delete: a bundle still on the PC → PC told to delete, audited.
    let alert2 = st02_alert();
    let id2 = Uuid::new_v4();
    let b2 = container(id2, alert2.id);
    alert_and_ready(
        &mut ag,
        &ts,
        &alert2,
        ready(id2, alert2.id, b2.len() as u64, &sha256_hex(&b2)),
    )
    .await;
    let (s, v) = ts
        .send(Method::DELETE, &format!("/api/evidence/{id2}"), json!({}))
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "deleted");
    assert_eq!(v["deleted_by"], "Ada Admin");
    let (_, del) = ag.command().await;
    assert_eq!(del, ResponseAction::DeleteEvidence { bundle_id: id2 });
    wait_audit(&ts, "evidence.deleted", id2).await;
    // Idempotent; a late Ready does not bring it back.
    let (s, v) = ts
        .send(Method::DELETE, &format!("/api/evidence/{id2}"), json!({}))
        .await;
    assert_eq!(s, 200, "{v}");
    ag.report(ready(id2, alert2.id, b2.len() as u64, &sha256_hex(&b2)))
        .await;
    assert_eq!(bundle(&ts, id2).await["status"], "deleted");

    // ---- delete a stored bundle: blob gone.
    let alert3 = st02_alert();
    let id3 = Uuid::new_v4();
    let b3 = container(id3, alert3.id);
    served.lock().unwrap().insert(id3, b3.clone());
    alert_and_ready(
        &mut ag,
        &ts,
        &alert3,
        ready(id3, alert3.id, b3.len() as u64, &sha256_hex(&b3)),
    )
    .await;
    collect(&ts, &mut ag, id3).await;
    assert_eq!(settled(&ts, id3).await["status"], "stored");
    let blob3 = ts.state.cfg.evidence_dir.join(format!("{id3}.kes"));
    assert!(blob3.exists());
    // An outstanding ticket dies with the bundle.
    let (s, t3) = ts
        .post(&format!("/api/evidence/{id3}/download"), json!({}))
        .await;
    assert_eq!(s, 200, "{t3}");
    let (s, v) = ts
        .send(
            Method::DELETE,
            &format!("/api/evidence/{id3}"),
            json!({"reason": "duplicate"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert!(!blob3.exists(), "deleted blob still on disk");
    let r = ts
        .http
        .get(ts.url(t3["url"].as_str().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "ticket of a deleted bundle still works");
    let (_, a) = wait_audit(&ts, "evidence.deleted", id3).await;
    assert_eq!(a["previous_status"], "stored");
    assert_eq!(a["reason"], "duplicate");
    let (k,): (Option<String>,) =
        sqlx::query_as("SELECT data_key_enc FROM evidence_bundles WHERE id = $1")
            .bind(id3)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert!(k.is_none(), "data key kept after deletion");

    ts.cleanup().await;
}

#[tokio::test]
async fn evidence_integrity_failures_and_retry() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let agent = new_agent(&ts, HOST).await;
    let dev = agent.device_id;
    let served: Served = Default::default();
    let mut ag = connect_agent(&ts, &agent, &[CAP_EVIDENCE], served.clone(), 0).await;

    // 1. Wrong SHA: the PC serves other bytes than it reported.
    let alert = st02_alert();
    let id = Uuid::new_v4();
    let good = container(id, alert.id);
    let mut other = good.clone();
    let last = other.len() - 30;
    other[last] ^= 0x55;
    served.lock().unwrap().insert(id, other);
    alert_and_ready(
        &mut ag,
        &ts,
        &alert,
        ready(id, alert.id, good.len() as u64, &sha256_hex(&good)),
    )
    .await;
    collect(&ts, &mut ag, id).await;
    let b = settled(&ts, id).await;
    assert_eq!(b["status"], "ready_on_device", "{b}");
    assert!(b["last_error"].as_str().unwrap().contains("SHA-256"), "{b}");
    let (_, a) = wait_audit(&ts, "evidence.collect_failed", id).await;
    assert_eq!(a["hostname"], HOST);
    assert!(!ts.state.cfg.evidence_dir.join(format!("{id}.kes")).exists());
    assert!(!ts
        .state
        .cfg
        .evidence_dir
        .join(format!("{id}.kes.partial"))
        .exists());

    // The first failure is retried once automatically when the PC reconnects.
    let seq = ag.disconnect(&ts, dev).await;
    served.lock().unwrap().insert(id, good.clone());
    let mut ag = connect_agent(&ts, &agent, &[CAP_EVIDENCE], served.clone(), seq).await;
    let (cid, action) = ag.command().await;
    assert_eq!(action, ResponseAction::CollectEvidence { bundle_id: id });
    ag.result(cid, action, true).await;
    let b = settled(&ts, id).await;
    assert_eq!(b["status"], "stored", "{b}");
    assert!(b["last_error"].is_null());
    ag.command().await; // DeleteEvidence

    // 2. Wrong size.
    let alert2 = st02_alert();
    let id2 = Uuid::new_v4();
    let b2 = container(id2, alert2.id);
    served.lock().unwrap().insert(id2, b2.clone());
    alert_and_ready(
        &mut ag,
        &ts,
        &alert2,
        ready(id2, alert2.id, b2.len() as u64 + 10, &sha256_hex(&b2)),
    )
    .await;
    collect(&ts, &mut ag, id2).await;
    let b = settled(&ts, id2).await;
    assert_eq!(b["status"], "ready_on_device", "{b}");
    assert!(b["last_error"].as_str().unwrap().contains("size"), "{b}");
    wait_audit(&ts, "evidence.collect_failed", id2).await;
    // The admin may retry; a second failure is not retried automatically.
    let (s, v) = ts
        .post(&format!("/api/evidence/{id2}/collect"), json!({}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (cid, action) = ag.command().await;
    ag.result(cid, action, false).await;
    let b = settled(&ts, id2).await;
    assert_eq!(b["status"], "ready_on_device", "{b}");
    assert!(
        b["last_error"]
            .as_str()
            .unwrap()
            .contains("could not prepare"),
        "{b}"
    );
    let (attempts, auto): (i32, bool) =
        sqlx::query_as("SELECT attempts, auto_retry FROM evidence_bundles WHERE id = $1")
            .bind(id2)
            .fetch_one(&ts.state.db)
            .await
            .unwrap();
    assert_eq!((attempts, auto), (2, false));
    // collect_failed: system actor, requester and agent text labelled.
    let rows = audit_rows(&ts, "evidence.collect_failed").await;
    let (actor, a) = rows
        .iter()
        .rev()
        .find(|r| r.1["bundle_id"] == id2.to_string())
        .unwrap();
    assert_eq!(*actor, None);
    assert!(a["requested_by"].is_string(), "{a}");
    assert_eq!(a["agent_error"], "bundle not found on the PC");
    assert_eq!(a["error"], "the PC could not prepare the upload");

    // 3. Malformed container (traversal entry name) with a matching hash.
    let alert3 = st02_alert();
    let id3 = Uuid::new_v4();
    let evil = traversal_container();
    served.lock().unwrap().insert(id3, evil.clone());
    alert_and_ready(
        &mut ag,
        &ts,
        &alert3,
        ready(id3, alert3.id, evil.len() as u64, &sha256_hex(&evil)),
    )
    .await;
    collect(&ts, &mut ag, id3).await;
    let b = settled(&ts, id3).await;
    assert_eq!(b["status"], "ready_on_device", "{b}");
    assert!(
        b["last_error"].as_str().unwrap().contains("container"),
        "{b}"
    );
    wait_audit(&ts, "evidence.collect_failed", id3).await;
    assert!(!ts
        .state
        .cfg
        .evidence_dir
        .join(format!("{id3}.kes"))
        .exists());

    // 4. Reports for another device's bundle are ignored.
    let other_agent = new_agent(&ts, "OTHER-PC").await;
    let mut ag2 = connect_agent(&ts, &other_agent, &[CAP_EVIDENCE], Default::default(), 0).await;
    ag2.report(EvidenceReport {
        state: EvidenceState::Deleted,
        ..ready(id3, alert3.id, 0, "")
    })
    .await;
    let b = bundle(&ts, id3).await;
    assert_eq!(b["status"], "ready_on_device");
    assert_eq!(b["device_id"], dev.to_string());

    // 5. An agent without evidence.v1 → 409 agent_too_old.
    let old_agent = new_agent(&ts, "OLD-PC").await;
    let mut ag3 = connect_agent(&ts, &old_agent, &[], Default::default(), 0).await;
    let alert4 = st02_alert();
    let id4 = Uuid::new_v4();
    alert_and_ready(
        &mut ag3,
        &ts,
        &alert4,
        ready(id4, alert4.id, 100, &"a".repeat(64)),
    )
    .await;
    let (s, v) = ts
        .post(&format!("/api/evidence/{id4}/collect"), json!({}))
        .await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"]["reason"], "agent_too_old");
    assert_eq!(bundle(&ts, id4).await["agent_supports_evidence"], false);

    // 6. An invalid Ready (bad hash) is recorded as failed.
    let alert5 = st02_alert();
    let id5 = Uuid::new_v4();
    alert_and_ready(
        &mut ag3,
        &ts,
        &alert5,
        ready(id5, alert5.id, 100, "not-a-hash"),
    )
    .await;
    assert_eq!(bundle(&ts, id5).await["status"], "failed");

    // 7. M7: admins with MFA need a fresh re-check to collect / download.
    let (s, setup) = ts.post("/api/me/mfa/setup", json!({})).await;
    assert_eq!(s, 200, "{setup}");
    let totp =
        kestrel_server::crypto::totp_for(setup["secret"].as_str().unwrap(), ADMIN_EMAIL).unwrap();
    let secs = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let (s, v) = ts
        .post(
            "/api/me/mfa/enable",
            json!({"totp": totp.generate(secs() - 30)}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    for path in [
        format!("/api/evidence/{id3}/collect"),
        format!("/api/evidence/{id}/download"),
    ] {
        let (s, v) = ts.post(&path, json!({})).await;
        assert_eq!(s, 403, "{path}: {v}");
        assert_eq!(v["error"]["reason"], "reauth_required");
    }
    // Review of the 1.1.7 integration, L3: delete needs the same step-up.
    let (s, v) = ts
        .send(Method::DELETE, &format!("/api/evidence/{id5}"), json!({}))
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "reauth_required");
    assert_eq!(bundle(&ts, id5).await["status"], "failed");
    let (s, v) = ts
        .post("/api/me/reauth", json!({"totp": totp.generate(secs())}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = ts
        .send(Method::DELETE, &format!("/api/evidence/{id5}"), json!({}))
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["status"], "deleted");
    let (s, t) = ts
        .post(&format!("/api/evidence/{id}/download"), json!({}))
        .await;
    assert_eq!(s, 200, "{t}");
    let (s, v) = ts
        .post(&format!("/api/evidence/{id3}/collect"), json!({}))
        .await;
    assert_eq!(s, 200, "{v}");

    ts.cleanup().await;
}

/// Review of the 1.1.7 integration, M4: a (compromised) agent cannot create
/// bundle rows for alerts it does not have, for non-trigger alerts, beyond
/// the per-device / per-alert caps, or store an oversized manifest.
#[tokio::test]
async fn evidence_report_bounds_m4() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let agent = new_agent(&ts, HOST).await;
    let dev = agent.device_id;
    let mut ag = connect_agent(&ts, &agent, &[CAP_EVIDENCE], Default::default(), 0).await;
    let rows = |ts: &TestServer| {
        let db = ts.state.db.clone();
        async move {
            let (n,): (i64,) =
                sqlx::query_as("SELECT count(*) FROM evidence_bundles WHERE device_id = $1")
                    .bind(dev)
                    .fetch_one(&db)
                    .await
                    .unwrap();
            n
        }
    };
    let capturing = |bundle: Uuid, alert: Uuid| EvidenceReport {
        state: EvidenceState::Capturing,
        manifest: None,
        bundle_size: 0,
        bundle_sha256: None,
        local_expires_at: None,
        ..ready(bundle, alert, 0, "")
    };
    let sha = "a".repeat(64);

    // A Ready report for an alert the server does not have: nothing stored.
    ag.report(ready(Uuid::new_v4(), Uuid::new_v4(), 100, &sha))
        .await;
    assert_eq!(rows(&ts).await, 0);

    // An alert of a rule that never starts a capture: ignored.
    let mut st01 = st02_alert();
    st01.rule_id = "ST-01".into();
    let s = ag.send(&AgentPayload::Alert(Box::new(st01.clone()))).await;
    ag.wait_ack(s).await;
    ag.report(ready(Uuid::new_v4(), st01.id, 100, &sha)).await;
    ag.report(capturing(Uuid::new_v4(), st01.id)).await;
    assert_eq!(rows(&ts).await, 0);

    // Per alert: at most 4 bundles.
    let alert = st02_alert();
    let s = ag.send(&AgentPayload::Alert(Box::new(alert.clone()))).await;
    ag.wait_ack(s).await;
    for _ in 0..6 {
        ag.report(capturing(Uuid::new_v4(), alert.id)).await;
    }
    assert_eq!(rows(&ts).await, 4);

    // Capturing before the alert arrives is accepted (the agent queues it
    // first), but bundles that are open or name unknown alerts are capped
    // per device: random ids stop at 32 rows.
    for _ in 0..40 {
        ag.report(capturing(Uuid::new_v4(), Uuid::new_v4())).await;
    }
    assert_eq!(rows(&ts).await, 32);
    // Terminal reports for unknown alerts do not free the cap.
    let (orphan,): (Uuid,) = sqlx::query_as(
        "SELECT id FROM evidence_bundles WHERE device_id = $1 AND alert_id <> $2 LIMIT 1",
    )
    .bind(dev)
    .bind(alert.id)
    .fetch_one(&ts.state.db)
    .await
    .unwrap();
    ag.report(EvidenceReport {
        state: EvidenceState::Failed,
        ..capturing(orphan, Uuid::new_v4())
    })
    .await;
    ag.report(capturing(Uuid::new_v4(), Uuid::new_v4())).await;
    assert_eq!(rows(&ts).await, 32);

    // A huge manifest is shortened to the stored cap.
    let mut m: kestrel_common::evidence::EvidenceManifest =
        serde_json::from_value(manifest(Uuid::new_v4(), alert.id)).unwrap();
    let one = m.staged[0].clone();
    m.staged = (0..500)
        .map(|i| {
            let mut s = one.clone();
            s.path = format!(
                "C:\\Users\\alice\\AppData\\Local\\Temp\\{i}\\{}",
                "x".repeat(1000)
            );
            s.image = "y".repeat(1000);
            s
        })
        .collect();
    let sc = kestrel_server::scrub::Scrub::NONE;
    kestrel_server::evidence::scrub_manifest(&mut m, &sc);
    let n = serde_json::to_vec(&m).unwrap().len();
    assert!(
        n <= kestrel_server::evidence::MANIFEST_MAX_JSON + 512,
        "{n}"
    );
    assert!(m.staged.len() < 500);
    assert!(m
        .notes
        .iter()
        .any(|n| n.starts_with("The server shortened")));
    ts.cleanup().await;
}

#[tokio::test]
async fn evidence_settings_and_policy_validation() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    let (_, set) = ts.get("/api/settings").await;
    assert_eq!(set["retention_days"]["evidence"], 14, "{set}");
    for bad in [0, 366] {
        let mut s2 = set.clone();
        s2["retention_days"]["evidence"] = json!(bad);
        let (s, v) = ts.send(Method::PUT, "/api/settings", s2).await;
        assert_eq!(s, 400, "{bad}: {v}");
    }
    let mut s2 = set.clone();
    s2["retention_days"]["evidence"] = json!(30);
    let (s, v) = ts.send(Method::PUT, "/api/settings", s2).await;
    assert_eq!(s, 200, "{v}");
    // An older console that does not know the field keeps the stored value.
    let mut s3 = set.clone();
    s3["retention_days"]
        .as_object_mut()
        .unwrap()
        .remove("evidence");
    let (s, v) = ts.send(Method::PUT, "/api/settings", s3).await;
    assert_eq!(s, 200, "{v}");
    let (_, now) = ts.get("/api/settings").await;
    assert_eq!(now["retention_days"]["evidence"], 30);

    let (_, pol) = ts.get("/api/policies/default").await;
    assert_eq!(pol["evidence"]["local_retention_days"], 14, "{pol}");
    let mut p2 = pol.clone();
    p2["evidence"]["local_retention_days"] = json!(0);
    let (s, v) = ts.send(Method::PUT, "/api/policies/default", p2).await;
    assert_eq!(s, 400, "{v}");
    let mut p3 = pol.clone();
    p3["evidence"]["pcap"] = json!(false);
    let (s, v) = ts.send(Method::PUT, "/api/policies/default", p3).await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["evidence"]["pcap"], false);

    ts.cleanup().await;
}
