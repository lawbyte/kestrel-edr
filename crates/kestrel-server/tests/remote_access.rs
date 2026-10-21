//! Remote access (remote desktop + file manager) end to end: RBAC, profiles
//! (install-time ceiling ∩ policy), guardrails (reason, MFA re-auth, consent),
//! the file REST API against a fake agent with an in-memory file tree, the
//! per-profile installer script, and the remote-desktop WebSocket relay.

mod common;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use common::*;
use kestrel_common::remote::{
    DesktopFrame, DesktopInfo, FileContext, FileEntry, FileKind, FileOp, FileReply, LiveAgentMsg,
    LiveServerMsg, RemoteAccessProfile, RemoteErrorCode, CAP_LIVE_DESKTOP, CAP_LIVE_FILES,
};
use kestrel_common::wire::{AgentPayload, ServerPayload};
use kestrel_server::grpc::pb::AgentEnvelope;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::mpsc;
use uuid::Uuid;

const ADMIN_EMAIL: &str = "admin@acme.test";
const ADMIN_PASSWORD: &str = "correct horse battery";
const PROTECTED: &str = r"C:\Program Files\Kestrel";

// ------------------------------------------------------------ fake agent

#[derive(Clone)]
enum Node {
    Dir,
    File(Vec<u8>),
}

#[derive(Clone, Copy, PartialEq)]
enum Consent {
    /// No consent prompt.
    Off,
    /// Ask (ConsentPending), then allow after a short delay.
    Allow,
    /// Ask, then deny.
    Deny,
}

#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::enum_variant_names)]
enum Ev {
    DesktopStart {
        view_only: bool,
        admin: String,
        reason: String,
    },
    DesktopStop(String),
    DesktopAck(u64),
    DesktopInput,
}

struct FakeState {
    fs: BTreeMap<String, Node>,
    consent: Consent,
    contexts: Vec<Option<FileContext>>,
    reads: HashMap<Uuid, Sha256>,
    uploads: HashMap<Uuid, (String, u64, Vec<u8>)>,
    /// Delay before answering each file request (aborted-request tests).
    delay_ms: u64,
    /// Answer to a mid-session switch to control (`None` = no prompt).
    control_consent: Option<bool>,
    /// Send an oversized frame (dropped by the server) before the real one.
    oversize_frame: bool,
}

struct Fake {
    state: Arc<Mutex<FakeState>>,
    events: mpsc::UnboundedReceiver<Ev>,
    task: tokio::task::JoinHandle<()>,
}

impl Fake {
    async fn next_event(&mut self, pred: impl Fn(&Ev) -> bool) -> Ev {
        loop {
            let ev = tokio::time::timeout(Duration::from_secs(15), self.events.recv())
                .await
                .expect("timed out waiting for an agent event")
                .expect("agent gone");
            if pred(&ev) {
                return ev;
            }
        }
    }
}

fn key(p: &str) -> String {
    p.to_lowercase()
}

fn big_file() -> Vec<u8> {
    // 9 MiB + a bit, above the 8 MiB API body limit; not chunk-aligned.
    (0..(9 * 1024 * 1024 + 12_345u32))
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

fn initial_fs() -> BTreeMap<String, Node> {
    let mut fs = BTreeMap::new();
    for d in [r"C:\", r"C:\Users", r"C:\Users\bob", PROTECTED] {
        fs.insert(key(d), Node::Dir);
    }
    fs.insert(
        key(r"C:\Users\bob\report.pdf"),
        Node::File(b"%PDF-1.7 quarterly report".to_vec()),
    );
    fs.insert(key(r"C:\Users\bob\big.bin"), Node::File(big_file()));
    fs
}

fn entry(path: &str, node: &Node) -> FileEntry {
    FileEntry {
        name: kestrel_common::remote::file_name_of(path).to_string(),
        path: path.to_string(),
        kind: match node {
            Node::Dir if path.len() == 3 => FileKind::Drive,
            Node::Dir => FileKind::Dir,
            Node::File(_) => FileKind::File,
        },
        size: match node {
            Node::File(b) => b.len() as u64,
            Node::Dir => 0,
        },
        ..Default::default()
    }
}

fn err(code: RemoteErrorCode, m: &str) -> FileReply {
    FileReply::error(code, m)
}

fn protected(p: &str) -> bool {
    kestrel_common::remote::path_is_within(p, PROTECTED)
}

fn is_mutation(op: &FileOp) -> bool {
    !matches!(
        op,
        FileOp::List { .. } | FileOp::Stat { .. } | FileOp::ReadChunk { .. }
    )
}

/// Answer one file request against the in-memory tree.
fn handle_file(st: &mut FakeState, session: Uuid, op: FileOp) -> FileReply {
    let fs = &mut st.fs;
    match op {
        FileOp::List { path } => {
            if path.is_empty() {
                return FileReply::List {
                    path,
                    entries: vec![entry(r"C:\", &Node::Dir)],
                    truncated: false,
                };
            }
            if protected(&path) {
                return err(RemoteErrorCode::ProtectedPath, "Kestrel's own folder");
            }
            match fs.get(&key(&path)) {
                Some(Node::Dir) => {}
                Some(_) => return err(RemoteErrorCode::InvalidOperation, "not a folder"),
                None => return err(RemoteErrorCode::NotFound, "no such folder"),
            }
            let prefix = format!("{}\\", key(&path).trim_end_matches('\\'));
            let entries = fs
                .iter()
                .filter(|(k, _)| {
                    k.starts_with(&prefix)
                        && !k[prefix.len()..].contains('\\')
                        && k.len() > prefix.len()
                })
                .map(|(k, n)| entry(k, n))
                .collect();
            FileReply::List {
                path,
                entries,
                truncated: false,
            }
        }
        FileOp::Stat { path } => match fs.get(&key(&path)) {
            Some(n) => FileReply::Stat(entry(&path, n)),
            None => err(RemoteErrorCode::NotFound, "not found"),
        },
        FileOp::ReadChunk { path, offset, len } => {
            let Some(Node::File(data)) = fs.get(&key(&path)) else {
                return err(RemoteErrorCode::NotFound, "not found");
            };
            let h = st.reads.entry(session).or_default();
            let start = (offset as usize).min(data.len());
            let end = (start + len as usize).min(data.len());
            let chunk = &data[start..end];
            h.update(chunk);
            let eof = end >= data.len();
            let sha = eof.then(|| hex::encode(h.clone().finalize()));
            FileReply::Data {
                offset,
                data_b64: B64.encode(chunk),
                size: data.len() as u64,
                eof,
                sha256: sha,
            }
        }
        FileOp::WriteBegin { path, size } => {
            if protected(&path) {
                return err(RemoteErrorCode::ProtectedPath, "Kestrel's own folder");
            }
            st.uploads.insert(session, (path, size, vec![]));
            FileReply::Done { count: 0 }
        }
        FileOp::WriteChunk { offset, data_b64 } => {
            let Some((_, _, buf)) = st.uploads.get_mut(&session) else {
                return err(RemoteErrorCode::InvalidOperation, "no upload");
            };
            if offset != buf.len() as u64 {
                return err(RemoteErrorCode::IntegrityError, "offset");
            }
            buf.extend(B64.decode(data_b64).unwrap());
            FileReply::Done {
                count: buf.len() as u64,
            }
        }
        FileOp::WriteEnd { sha256 } => {
            let Some((path, size, buf)) = st.uploads.remove(&session) else {
                return err(RemoteErrorCode::InvalidOperation, "no upload");
            };
            let ours = hex::encode(Sha256::digest(&buf));
            if buf.len() as u64 != size || ours != sha256 {
                return err(RemoteErrorCode::IntegrityError, "mismatch");
            }
            fs.insert(key(&path), Node::File(buf));
            FileReply::Written {
                path,
                size,
                sha256: ours,
            }
        }
        FileOp::WriteAbort => {
            st.uploads.remove(&session);
            FileReply::Done { count: 0 }
        }
        FileOp::Rename {
            from,
            to,
            overwrite,
        } => {
            if protected(&from) || protected(&to) {
                return err(RemoteErrorCode::ProtectedPath, "Kestrel's own folder");
            }
            if fs.contains_key(&key(&to)) && !overwrite {
                return err(RemoteErrorCode::AlreadyExists, "target exists");
            }
            let Some(n) = fs.remove(&key(&from)) else {
                return err(RemoteErrorCode::NotFound, "not found");
            };
            fs.insert(key(&to), n);
            FileReply::Done { count: 1 }
        }
        FileOp::Delete { path, recursive } => {
            if protected(&path) {
                return err(RemoteErrorCode::ProtectedPath, "Kestrel's own folder");
            }
            let k = key(&path);
            let children: Vec<String> = fs
                .keys()
                .filter(|c| c.starts_with(&format!("{k}\\")))
                .cloned()
                .collect();
            if !fs.contains_key(&k) {
                return err(RemoteErrorCode::NotFound, "not found");
            }
            if !children.is_empty() && !recursive {
                return err(RemoteErrorCode::InvalidOperation, "folder not empty");
            }
            for c in &children {
                fs.remove(c);
            }
            fs.remove(&k);
            FileReply::Done {
                count: children.len() as u64 + 1,
            }
        }
        FileOp::Mkdir { path } => {
            fs.insert(key(&path), Node::Dir);
            FileReply::Done { count: 1 }
        }
        FileOp::Unknown => err(RemoteErrorCode::Other, "unknown"),
    }
}

fn live(tx: &mpsc::Sender<AgentEnvelope>, session_id: Uuid, msg: LiveAgentMsg) {
    let env = AgentEnvelope {
        seq: 0,
        compressed: false,
        payload: serde_json::to_vec(&AgentPayload::Live { session_id, msg }).unwrap(),
    };
    // In order (try_send keeps the sequence the fake produced).
    tx.try_send(env).expect("fake agent queue full");
}

/// Run the fake agent's receive loop on an open stream.
fn spawn_fake(mut stream: AgentStream) -> Fake {
    let state = Arc::new(Mutex::new(FakeState {
        fs: initial_fs(),
        consent: Consent::Off,
        contexts: vec![],
        reads: HashMap::new(),
        uploads: HashMap::new(),
        delay_ms: 0,
        control_consent: None,
        oversize_frame: false,
    }));
    let (ev_tx, events) = mpsc::unbounded_channel();
    let st = state.clone();
    let task = tokio::spawn(async move {
        let tx = stream.tx.clone();
        while let Ok(Some(env)) = stream.rx.message().await {
            let raw = kestrel_server::grpc::decode_payload(env.compressed, &env.payload).unwrap();
            let Ok(ServerPayload::Live { session_id, msg }) = serde_json::from_slice(&raw) else {
                continue;
            };
            match msg {
                LiveServerMsg::FileRequest {
                    request_id,
                    op,
                    context,
                } => {
                    let consent = {
                        let mut s = st.lock().unwrap();
                        s.contexts.push(context);
                        s.consent
                    };
                    if consent != Consent::Off && is_mutation(&op) {
                        // Ask the employee, answer later (off the receive loop).
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::ConsentPending {
                                request_id: Some(request_id),
                                timeout_secs: 5,
                            },
                        );
                        let (st2, tx2) = (st.clone(), tx.clone());
                        tokio::spawn(async move {
                            tokio::time::sleep(Duration::from_millis(1500)).await;
                            let reply = if consent == Consent::Deny {
                                err(RemoteErrorCode::ConsentDenied, "the employee clicked Deny")
                            } else {
                                handle_file(&mut st2.lock().unwrap(), session_id, op)
                            };
                            live(
                                &tx2,
                                session_id,
                                LiveAgentMsg::FileReply { request_id, reply },
                            );
                        });
                        continue;
                    }
                    let delay = st.lock().unwrap().delay_ms;
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    let reply = handle_file(&mut st.lock().unwrap(), session_id, op);
                    live(
                        &tx,
                        session_id,
                        LiveAgentMsg::FileReply { request_id, reply },
                    );
                }
                LiveServerMsg::DesktopStart(start) => {
                    let _ = ev_tx.send(Ev::DesktopStart {
                        view_only: start.view_only,
                        admin: start.admin_name.clone(),
                        reason: start.reason.clone(),
                    });
                    let consent = st.lock().unwrap().consent;
                    if consent == Consent::Deny {
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::ConsentPending {
                                request_id: None,
                                timeout_secs: 5,
                            },
                        );
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::DesktopEnded {
                                reason: "the employee declined".into(),
                                code: Some(RemoteErrorCode::ConsentDenied),
                            },
                        );
                        continue;
                    }
                    let info = DesktopInfo {
                        width: 1920,
                        height: 1080,
                        monitors: 1,
                        view_only: start.view_only,
                        ..Default::default()
                    };
                    live(&tx, session_id, LiveAgentMsg::DesktopStarted(info));
                    let mut seq = 1;
                    if st.lock().unwrap().oversize_frame {
                        // Above LIVE_MAX_MESSAGE: dropped before parsing.
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::DesktopFrame(DesktopFrame {
                                seq: 1,
                                width: 1,
                                height: 1,
                                ts: 1,
                                jpeg_b64: B64.encode(vec![0u8; 1_200_000]),
                            }),
                        );
                        seq = 2;
                    }
                    live(
                        &tx,
                        session_id,
                        LiveAgentMsg::DesktopFrame(DesktopFrame {
                            seq,
                            width: 1920,
                            height: 1080,
                            ts: 1_700_000_000_000,
                            jpeg_b64: B64.encode(b"\xff\xd8fake-jpeg\xff\xd9"),
                        }),
                    );
                }
                LiveServerMsg::DesktopStop { reason } => {
                    let _ = ev_tx.send(Ev::DesktopStop(reason));
                }
                LiveServerMsg::DesktopSettings(set) if set.view_only == Some(false) => {
                    let answer = st.lock().unwrap().control_consent;
                    if let Some(allowed) = answer {
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::ConsentPending {
                                request_id: None,
                                timeout_secs: 5,
                            },
                        );
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::ConsentResult {
                                request_id: None,
                                allowed,
                                code: (!allowed).then_some(RemoteErrorCode::ConsentDenied),
                            },
                        );
                        live(
                            &tx,
                            session_id,
                            LiveAgentMsg::DesktopInfo(DesktopInfo {
                                width: 1920,
                                height: 1080,
                                view_only: !allowed,
                                ..Default::default()
                            }),
                        );
                    }
                }
                LiveServerMsg::DesktopAck { seq } => {
                    let _ = ev_tx.send(Ev::DesktopAck(seq));
                }
                LiveServerMsg::DesktopInput { .. } => {
                    let _ = ev_tx.send(Ev::DesktopInput);
                }
                _ => {}
            }
        }
    });
    Fake {
        state,
        events,
        task,
    }
}

// ------------------------------------------------------------ helpers

async fn ca_pem(ts: &TestServer) -> String {
    let (_, inst) = ts.get("/api/agent/installer").await;
    inst["ca_pem"].as_str().unwrap().to_string()
}

async fn make_token(ts: &TestServer, profile: Value) -> Value {
    let (s, tok) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"expires_in_days": 7, "max_uses": 10, "remote_profile": profile}),
        )
        .await;
    assert_eq!(s, 200, "{tok}");
    tok
}

async fn set_policy_remote(ts: &TestServer, profile: Value) {
    let (s, mut pol) = ts.get("/api/policies/default").await;
    assert_eq!(s, 200);
    pol["remote_access"] = profile;
    let (s, v) = ts
        .send(reqwest::Method::PUT, "/api/policies/default", pol)
        .await;
    assert_eq!(s, 200, "{v}");
}

fn unrestricted() -> Value {
    serde_json::to_value(RemoteAccessProfile::unrestricted()).unwrap()
}

struct Enrolled {
    agent: TestAgent,
    ceiling: RemoteAccessProfile,
}

async fn enroll_with(ts: &TestServer, token: &str, host: &str) -> Enrolled {
    let ca = ca_pem(ts).await;
    let (agent, er) = enroll_full(ts.grpc_port, &ca, token, host, os())
        .await
        .expect("enroll");
    Enrolled {
        agent,
        ceiling: er.remote_profile,
    }
}

async fn connect_fake(ts: &TestServer, e: &Enrolled, caps: &[&str]) -> Fake {
    let mut h = hello(&e.agent, "FIN-LAPTOP-07");
    h.capabilities = caps.iter().map(|c| c.to_string()).collect();
    h.remote_ceiling = Some(e.ceiling.clone());
    let stream = connect(ts.grpc_port, &e.agent, h).await.expect("connect");
    for _ in 0..100 {
        if ts.state.agents.is_connected(&e.agent.device_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ts.state.agents.is_connected(&e.agent.device_id));
    spawn_fake(stream)
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

/// Wait for an audit row matching `pred` (some rows are written by tasks
/// that finish just after the HTTP response).
async fn wait_audit(ts: &TestServer, action: &str, pred: impl Fn(&Value) -> bool) -> Value {
    for _ in 0..100 {
        if let Some(v) = audit_rows(ts, action)
            .await
            .into_iter()
            .rev()
            .find(|v| pred(v))
        {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no audit row {action}: {:?}", audit_rows(ts, action).await);
}

fn files_url(ts: &TestServer, dev: Uuid, rest: &str) -> String {
    ts.url(&format!("/api/devices/{dev}/files{rest}"))
}

async fn get_files(
    ts: &TestServer,
    client: &reqwest::Client,
    dev: Uuid,
    rest: &str,
    path: &str,
) -> (u16, Value) {
    let r = client
        .get(files_url(ts, dev, rest))
        .query(&[("path", path)])
        .send()
        .await
        .unwrap();
    let s = r.status().as_u16();
    (s, r.json().await.unwrap_or(Value::Null))
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

// ------------------------------------------------------------ files

#[tokio::test]
async fn file_manager_end_to_end() {
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    set_policy_remote(&ts, unrestricted()).await;
    let tok = make_token(&ts, unrestricted()).await;
    let e = enroll_with(&ts, tok["token"].as_str().unwrap(), "FIN-LAPTOP-07").await;
    assert_eq!(e.ceiling, RemoteAccessProfile::unrestricted());
    let dev = e.agent.device_id;
    let fake = connect_fake(&ts, &e, &[CAP_LIVE_FILES, CAP_LIVE_DESKTOP]).await;

    // Device detail: availability and profiles.
    let (s, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(s, 200);
    let ra = &d["remote_access"];
    assert_eq!(
        ra["files"],
        json!({"available": true, "reason": null}),
        "{ra}"
    );
    assert_eq!(ra["desktop"]["available"], true);
    assert_eq!(
        ra["effective_summary"],
        RemoteAccessProfile::unrestricted().summary()
    );
    assert_eq!(ra["agent_reported_ceiling"]["files"], "full");

    // RBAC: analyst and readonly → 403; admin API token → 403.
    for role in ["analyst", "readonly"] {
        let email = format!("{role}@acme.test");
        let (s, u) = ts
            .post("/api/users", json!({"email": email, "name": role, "role": role, "password": "role password 123"}))
            .await;
        assert_eq!(s, 200, "{u}");
        let (c, _) = login(&ts, &email, "role password 123").await;
        let (s, _) = get_files(&ts, &c, dev, "", "").await;
        assert_eq!(s, 403, "{role} must not list files");
        let r = c
            .get(ts.url(&format!("/api/devices/{dev}/remote-desktop/status")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "{role} must not see desktop status");
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
        .get(files_url(&ts, dev, ""))
        .bearer_auth(t["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "API tokens cannot use remote access");

    // Drives and a folder; fm_session + reason travel in the FileContext.
    let fm = Uuid::new_v4();
    let r = ts
        .http
        .get(files_url(&ts, dev, ""))
        .query(&[
            ("fm_session", fm.to_string().as_str()),
            ("reason", "INC-42 cleanup"),
        ])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let drives: Value = r.json().await.unwrap();
    assert_eq!(drives["path"], "");
    assert_eq!(drives["parent"], Value::Null);
    assert_eq!(drives["entries"][0]["kind"], "drive");
    {
        let s = fake.state.lock().unwrap();
        let ctx = s.contexts.last().unwrap().as_ref().unwrap();
        assert_eq!(ctx.fm_session, fm);
        assert_eq!(ctx.reason, "INC-42 cleanup");
        assert_eq!(ctx.admin_name, "Ada Admin");
    }
    let (s, folder) = get_files(&ts, &ts.http, dev, "", "c:/users/bob/").await;
    assert_eq!(s, 200, "{folder}");
    assert_eq!(folder["path"], r"C:\users\bob");
    assert_eq!(folder["parent"], r"C:\users");
    let names: Vec<&str> = folder["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["name"].as_str().unwrap())
        .collect();
    assert!(
        names.contains(&"report.pdf") && names.contains(&"big.bin"),
        "{names:?}"
    );
    let list = wait_audit(&ts, "remote.files.list", |v| v["path"] == r"C:\users\bob").await;
    assert_eq!(list["ok"], true);
    assert_eq!(list["hostname"], "FIN-LAPTOP-07");

    // Path validation → 400.
    for bad in [
        r"Users\bob",
        r"\\server\share\x",
        r"C:\a\..\Windows",
        "C:\\a\u{0}b",
        r"C:\a\f.txt:stream",
        r"\\?\C:\x",
    ] {
        let (s, v) = get_files(&ts, &ts.http, dev, "", bad).await;
        assert_eq!(s, 400, "{bad:?}: {v}");
    }
    // Agent error mapping: protected_path → 403 with remote_code; not_found → 404.
    let (s, v) = get_files(&ts, &ts.http, dev, "", PROTECTED).await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["remote_code"], "protected_path");
    let (s, v) = get_files(&ts, &ts.http, dev, "/stat", r"C:\nope.txt").await;
    assert_eq!(s, 404, "{v}");
    assert_eq!(v["error"]["remote_code"], "not_found");
    let (s, v) = get_files(&ts, &ts.http, dev, "/stat", r"C:\Users\bob\report.pdf").await;
    assert_eq!(s, 200);
    assert_eq!(v["kind"], "file");

    // Download: small file, headers, audit with sha256.
    let r = ts
        .http
        .get(files_url(&ts, dev, "/download"))
        .query(&[("path", r"C:\Users\bob\report.pdf")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let h = r.headers().clone();
    assert_eq!(h["content-type"], "application/octet-stream");
    assert_eq!(h["x-content-type-options"], "nosniff");
    assert_eq!(h["content-length"], "25");
    assert_eq!(
        h["content-disposition"],
        "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
    );
    let body = r.bytes().await.unwrap();
    assert_eq!(&body[..], b"%PDF-1.7 quarterly report");
    let sha = hex::encode(Sha256::digest(&body));
    let a = wait_audit(&ts, "remote.files.download", |v| v["sha256"] == sha).await;
    assert_eq!(a["ok"], true);
    assert_eq!(a["bytes"], 25);

    // Download larger than the 8 MiB API body limit (19 chunks, 4 in flight).
    let big = big_file();
    let r = ts
        .http
        .get(files_url(&ts, dev, "/download"))
        .query(&[("path", r"C:\Users\bob\big.bin")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let body = r.bytes().await.unwrap();
    assert_eq!(body.len(), big.len());
    assert!(body[..] == big[..], "downloaded bytes differ");
    let big_sha = hex::encode(Sha256::digest(&big));
    wait_audit(&ts, "remote.files.download", |v| {
        v["sha256"] == big_sha && v["bytes"] == big.len()
    })
    .await;
    // A folder cannot be downloaded.
    let r = ts
        .http
        .get(files_url(&ts, dev, "/download"))
        .query(&[("path", r"C:\Users")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Upload > 8 MiB (escapes the API body limit) round-trips.
    let up: Vec<u8> = big.iter().rev().copied().collect();
    let r = ts
        .http
        .post(files_url(&ts, dev, "/upload"))
        .query(&[("path", r"C:\Users\bob\upload.bin")])
        .header("X-CSRF-Token", &ts.csrf)
        .header("content-type", "application/octet-stream")
        .body(up.clone())
        .send()
        .await
        .unwrap();
    let s = r.status();
    let v: Value = r.json().await.unwrap();
    assert_eq!(s, 200, "{v}");
    let up_sha = hex::encode(Sha256::digest(&up));
    assert_eq!(v["sha256"], up_sha);
    assert_eq!(v["size"], up.len());
    match fake
        .state
        .lock()
        .unwrap()
        .fs
        .get(&key(r"C:\Users\bob\upload.bin"))
    {
        Some(Node::File(b)) => assert!(b[..] == up[..]),
        _ => panic!("upload not stored"),
    }
    let a = wait_audit(&ts, "remote.files.upload", |v| v["sha256"] == up_sha).await;
    assert_eq!(a["ok"], true);
    // Upload without CSRF → 403; without Content-Length → 411; onto a folder → 409.
    let r = ts
        .http
        .post(files_url(&ts, dev, "/upload"))
        .query(&[("path", r"C:\Users\bob\x.bin")])
        .body(b"abc".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let stream = futures::stream::iter(vec![Ok::<_, std::io::Error>(b"abc".to_vec())]);
    let r = ts
        .http
        .post(files_url(&ts, dev, "/upload"))
        .query(&[("path", r"C:\Users\bob\x.bin")])
        .header("X-CSRF-Token", &ts.csrf)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 411);
    let r = ts
        .http
        .post(files_url(&ts, dev, "/upload"))
        .query(&[("path", r"C:\Users\bob")])
        .header("X-CSRF-Token", &ts.csrf)
        .body(b"abc".to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // Rename / mkdir / delete + audit.
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/rename"),
            json!({"from": r"C:\Users\bob\upload.bin", "to": r"C:\Users\bob\renamed.bin"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["to"], r"C:\Users\bob\renamed.bin");
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/rename"),
            json!({"from": r"C:\Users\bob\renamed.bin", "to": r"C:\Users\bob\report.pdf"}),
        )
        .await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"]["remote_code"], "already_exists");
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/mkdir"),
            json!({"path": r"C:\Users\bob\new\deeper"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/delete"),
            json!({"path": r"C:\Users\bob", "recursive": false}),
        )
        .await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["error"]["remote_code"], "invalid_operation");
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/delete"),
            json!({"path": r"C:\Users\bob\renamed.bin"}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["removed"], 1);
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/delete"),
            json!({"path": PROTECTED, "recursive": true}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["remote_code"], "protected_path");
    assert_eq!(
        wait_audit(&ts, "remote.files.rename", |v| v["ok"] == true).await["to"],
        r"C:\Users\bob\renamed.bin"
    );
    wait_audit(&ts, "remote.files.mkdir", |v| {
        v["path"] == r"C:\Users\bob\new\deeper"
    })
    .await;
    let del = wait_audit(&ts, "remote.files.delete", |v| v["ok"] == true).await;
    assert_eq!(del["removed"], 1);
    let failed = wait_audit(&ts, "remote.files.delete", |v| {
        v["ok"] == false && v["path"] == PROTECTED
    })
    .await;
    assert!(failed["error"].as_str().unwrap().contains("protected_path"));
    // Never any file content in the audit log.
    let all: Vec<(String,)> = sqlx::query_as("SELECT details::text FROM audit_log")
        .fetch_all(&ts.state.db)
        .await
        .unwrap();
    assert!(!all.iter().any(|r| r.0.contains("quarterly report")));

    // stat is audited too.
    wait_audit(&ts, "remote.files.stat", |v| {
        v["path"] == r"C:\Users\bob\report.pdf" && v["ok"] == true
    })
    .await;

    // H3: a client that aborts the request after the operation reached the
    // agent cannot skip the audit row.
    fake.state.lock().unwrap().delay_ms = 1000;
    let r = tokio::time::timeout(
        Duration::from_millis(250),
        ts.http
            .post(files_url(&ts, dev, "/mkdir"))
            .header("X-CSRF-Token", &ts.csrf)
            .json(&json!({"path": r"C:\Users\bob\aborted"}))
            .send(),
    )
    .await;
    assert!(
        r.is_err(),
        "the request was abandoned before the agent answered"
    );
    let a = wait_audit(&ts, "remote.files.mkdir", |v| {
        v["path"] == r"C:\Users\bob\aborted"
    })
    .await;
    assert_eq!(a["ok"], true);

    // H3 for downloads: the client disconnects mid-stream → audited failure.
    fake.state.lock().unwrap().delay_ms = 100;
    let mut r = ts
        .http
        .get(files_url(&ts, dev, "/download"))
        .query(&[("path", r"C:\Users\bob\big.bin")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert!(r.chunk().await.unwrap().is_some());
    drop(r);
    let a = wait_audit(&ts, "remote.files.download", |v| {
        v["ok"] == false && v["error"].as_str().unwrap_or("").contains("cancelled")
    })
    .await;
    assert!(a["bytes"].as_u64().unwrap() > 0);

    // L1: the console session ends during a transfer → aborted and audited.
    let (other, other_csrf) = login(&ts, ADMIN_EMAIL, ADMIN_PASSWORD).await;
    fake.state.lock().unwrap().delay_ms = 150;
    let r = other
        .get(files_url(&ts, dev, "/download"))
        .query(&[("path", r"C:\Users\bob\big.bin")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let lo = other
        .post(ts.url("/api/auth/logout"))
        .header("X-CSRF-Token", &other_csrf)
        .send()
        .await
        .unwrap();
    assert!(lo.status().is_success());
    assert!(r.bytes().await.is_err(), "the body must be aborted");
    let a = wait_audit(&ts, "remote.files.download", |v| {
        v["ok"] == false
            && v["error"]
                .as_str()
                .unwrap_or("")
                .contains("no longer valid")
    })
    .await;
    assert!(a["bytes"].as_u64().unwrap() < big_file().len() as u64);
    fake.state.lock().unwrap().delay_ms = 0;

    // Consent: allowed after ConsentPending (the wait is extended), audited.
    fake.state.lock().unwrap().consent = Consent::Allow;
    let fm2 = Uuid::new_v4().to_string();
    let r = ts
        .http
        .post(files_url(&ts, dev, "/mkdir"))
        .query(&[("fm_session", fm2.as_str())])
        .header("X-CSRF-Token", &ts.csrf)
        .json(&json!({"path": r"C:\Users\bob\consented"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let c = wait_audit(&ts, "remote.consent", |v| v["fm_session"] == fm2).await;
    assert_eq!(c["result"], "allowed");
    assert_eq!(c["kind"], "files");
    // Denied → 403 consent_denied, audited.
    fake.state.lock().unwrap().consent = Consent::Deny;
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/mkdir"),
            json!({"path": r"C:\Users\bob\denied"}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["remote_code"], "consent_denied");
    wait_audit(&ts, "remote.consent", |v| v["result"] == "denied").await;
    // Reads never ask.
    let (s, _) = get_files(&ts, &ts.http, dev, "", r"C:\Users").await;
    assert_eq!(s, 200);
    fake.state.lock().unwrap().consent = Consent::Off;

    // Agent without the capability → 409; offline → 409.
    let e2 = enroll_with(&ts, tok["token"].as_str().unwrap(), "OLD-AGENT").await;
    let old = connect_fake(&ts, &e2, &[]).await;
    let (s, v) = get_files(&ts, &ts.http, e2.agent.device_id, "", "").await;
    assert_eq!(s, 409, "{v}");
    assert!(v["error"]["message"].as_str().unwrap().contains("too old"));
    let (_, d2) = ts
        .get(&format!("/api/devices/{}", e2.agent.device_id))
        .await;
    assert_eq!(d2["remote_access"]["files"]["reason"], "agent_too_old");
    old.task.abort();
    drop(old);
    for _ in 0..100 {
        if !ts.state.agents.is_connected(&e2.agent.device_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (s, v) = get_files(&ts, &ts.http, e2.agent.device_id, "", "").await;
    assert_eq!(s, 409, "{v}");
    assert_eq!(v["error"]["message"], "device is offline");
    let (_, d2) = ts
        .get(&format!("/api/devices/{}", e2.agent.device_id))
        .await;
    assert_eq!(d2["remote_access"]["files"]["reason"], "offline");
    let off = wait_audit(&ts, "remote.files.list", |v| {
        v["ok"] == false && v["error"] == "device is offline"
    })
    .await;
    assert_eq!(off["error"], "device is offline");

    // Policy switches files off → 403 disabled_by_policy (audited).
    let mut pol = RemoteAccessProfile::unrestricted();
    pol.files = kestrel_common::remote::FileMode::Off;
    set_policy_remote(&ts, serde_json::to_value(&pol).unwrap()).await;
    let (s, v) = get_files(&ts, &ts.http, dev, "", "").await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "disabled_by_policy");
    assert_eq!(v["error"]["remote_code"], "disabled_by_policy");
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["remote_access"]["files"]["reason"], "disabled_by_policy");
    assert_eq!(d["remote_access"]["desktop"]["available"], true);
    // Read-only policy: list works, delete refused by policy.
    pol.files = kestrel_common::remote::FileMode::ReadOnly;
    set_policy_remote(&ts, serde_json::to_value(&pol).unwrap()).await;
    let (s, _) = get_files(&ts, &ts.http, dev, "", r"C:\Users").await;
    assert_eq!(s, 200);
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/delete"),
            json!({"path": r"C:\Users\bob\report.pdf"}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "disabled_by_policy");
    // An invalid profile in a policy is refused.
    let mut bad = serde_json::to_value(RemoteAccessProfile::unrestricted()).unwrap();
    bad["guardrails"]["blocked_paths"] = json!([r"\\srv\share"]);
    let (_, mut p) = ts.get("/api/policies/default").await;
    p["remote_access"] = bad;
    let (s, _) = ts
        .send(reqwest::Method::PUT, "/api/policies/default", p)
        .await;
    assert_eq!(s, 400);

    fake.task.abort();
    ts.cleanup().await;
}

// ------------------------------------------------------------ profiles

#[tokio::test]
async fn profiles_ceiling_installer_and_guardrails() {
    let msi_dir = tempfile::tempdir().unwrap();
    std::fs::write(msi_dir.path().join("KestrelAgent.msi"), b"dummy msi bytes").unwrap();
    let msi_sha = hex::encode(Sha256::digest(b"dummy msi bytes"));
    let dir = msi_dir.path().to_path_buf();
    let Some(mut ts) = TestServer::start_custom(false, move |c| c.agent_dir = dir).await else {
        return;
    };
    ts.setup_admin().await;

    // Default token: no remote access; list shows the preset.
    let (s, plain) = ts.post("/api/enrollment-tokens", json!({})).await;
    assert_eq!(s, 200, "{plain}");
    assert_eq!(plain["remote_preset"], "none");
    assert_eq!(plain["remote_summary"], "No remote access");
    assert_eq!(plain["installer_filename"], "Install-Kestrel-none.cmd");

    // Guarded token with the installer script.
    let guarded = serde_json::to_value(RemoteAccessProfile::guarded_default()).unwrap();
    let tok = make_token(&ts, guarded.clone()).await;
    assert_eq!(tok["remote_preset"], "guarded");
    assert_eq!(tok["installer_filename"], "Install-Kestrel-guarded.cmd");
    let cmd = tok["installer_cmd"].as_str().unwrap();
    let token = tok["token"].as_str().unwrap();
    assert!(
        cmd.contains("\r\n") && !cmd.replace("\r\n", "").contains('\n'),
        "CRLF only"
    );
    assert!(cmd.contains(&format!("set \"KESTREL_TOKEN={token}\"")));
    assert!(cmd.contains("set \"KESTREL_SERVER=localhost:8443\""));
    assert!(cmd.contains(&format!("set \"KESTREL_MSI_SHA256={msi_sha}\"")));
    assert!(cmd.contains(&B64.encode(ts.state.ca.cert_pem.as_bytes())));
    assert!(cmd.contains("/downloads/KestrelAgent.msi"));
    assert!(
        cmd.contains(
            &RemoteAccessProfile::guarded_default()
                .summary()
                .replace(';', " ")
        ) || cmd.contains("Remote control + full file manager")
    );
    assert!(!cmd.contains(&ts.state.cfg.master_key), "no master key");
    assert!(!cmd.contains("PRIVATE KEY"), "no private keys");
    // Listing never shows the script or the token.
    let (_, toks) = ts.get("/api/enrollment-tokens").await;
    let listed = toks
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["id"] == tok["id"])
        .unwrap();
    assert!(listed.get("installer_cmd").is_none() && listed.get("token").is_none());
    assert_eq!(listed["remote_profile"], guarded);
    let created = wait_audit(&ts, "enrollment_token.created", |v| {
        v["remote_profile"] == guarded
    })
    .await;
    assert_eq!(
        created["remote_summary"],
        RemoteAccessProfile::guarded_default().summary()
    );

    // Invalid profile → 400; analyst cannot create a non-none token (403).
    let mut bad = guarded.clone();
    bad["guardrails"]["allowed_hours"] = json!({"days": [9], "start_minute": 0, "end_minute": 60});
    let (s, _) = ts
        .post("/api/enrollment-tokens", json!({"remote_profile": bad}))
        .await;
    assert_eq!(s, 400);
    sqlx::query("UPDATE roles SET privileges = array_append(privileges, 'devices.write') WHERE name = 'analyst'")
        .execute(&ts.state.db)
        .await
        .unwrap();
    let (s, _) = ts
        .post("/api/users", json!({"email": "ann@acme.test", "name": "Ann", "role": "analyst", "password": "analyst password 1"}))
        .await;
    assert_eq!(s, 200);
    let (ann, ann_csrf) = login(&ts, "ann@acme.test", "analyst password 1").await;
    let r = ann
        .post(ts.url("/api/enrollment-tokens"))
        .header("X-CSRF-Token", &ann_csrf)
        .json(&json!({"remote_profile": unrestricted()}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = ann
        .post(ts.url("/api/enrollment-tokens"))
        .header("X-CSRF-Token", &ann_csrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "none() tokens only need devices.write");

    // Enroll with the guarded token: EnrollResponse + device detail ceiling.
    let e = enroll_with(&ts, token, "HR-DESKTOP-02").await;
    assert_eq!(e.ceiling, RemoteAccessProfile::guarded_default());
    let dev = e.agent.device_id;
    let (stored,): (Value,) = sqlx::query_as("SELECT remote_ceiling FROM devices WHERE id = $1")
        .bind(dev)
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    assert_eq!(stored, guarded);
    // Before the agent reports a ceiling: nothing is permitted.
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["remote_access"]["files"]["reason"], "not_permitted");
    assert_eq!(d["remote_access"]["agent_reported_ceiling"], Value::Null);

    // An old policy body without remote_access = none(): disabled by policy.
    let (body,): (Value,) = sqlx::query_as("SELECT body FROM policies WHERE id = 'default'")
        .fetch_one(&ts.state.db)
        .await
        .unwrap();
    let mut body = body;
    body.as_object_mut().unwrap().remove("remote_access");
    sqlx::query("UPDATE policies SET body = $1 WHERE id = 'default'")
        .bind(&body)
        .execute(&ts.state.db)
        .await
        .unwrap();
    let mut fake = connect_fake(&ts, &e, &[CAP_LIVE_FILES, CAP_LIVE_DESKTOP]).await;
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    let ra = &d["remote_access"];
    assert_eq!(
        ra["policy"],
        serde_json::to_value(RemoteAccessProfile::none()).unwrap()
    );
    assert_eq!(ra["files"]["reason"], "disabled_by_policy", "{ra}");
    assert_eq!(ra["ceiling"], guarded);
    let (s, v) = get_files(&ts, &ts.http, dev, "", "").await;
    assert_eq!(s, 403);
    assert_eq!(v["error"]["reason"], "disabled_by_policy");

    // Policy unrestricted: effective = guarded ceiling ∩ unrestricted = guarded.
    set_policy_remote(&ts, unrestricted()).await;
    let (_, d) = ts.get(&format!("/api/devices/{dev}")).await;
    assert_eq!(d["remote_access"]["effective"], guarded);
    assert_eq!(
        d["remote_access"]["effective_summary"],
        RemoteAccessProfile::guarded_default().summary()
    );
    assert_eq!(d["remote_access"]["files"]["available"], true);
    // The ceiling forbids delete (guarded: allow_delete false) → not_permitted.
    let (s, v) = ts
        .post(
            &format!("/api/devices/{dev}/files/delete?reason=cleanup"),
            json!({"path": r"C:\Users\bob\report.pdf"}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "not_permitted");
    assert_eq!(v["error"]["remote_code"], "not_permitted");
    // Reason required.
    let (s, v) = get_files(&ts, &ts.http, dev, "", "").await;
    assert_eq!(s, 400, "{v}");
    assert_eq!(v["error"]["reason"], "reason_required");
    // MFA re-auth: admin without MFA → mfa_not_enabled.
    let r = ts
        .http
        .get(files_url(&ts, dev, ""))
        .query(&[("reason", "INC-7")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["reason"], "mfa_not_enabled");
    let (s, v) = ts.post("/api/me/reauth", json!({"totp": "123456"})).await;
    assert_eq!(s, 403);
    assert_eq!(v["error"]["reason"], "mfa_not_enabled");

    // Enable MFA (code from the previous step so the next one stays unused).
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
    let r = ts
        .http
        .get(files_url(&ts, dev, ""))
        .query(&[("reason", "INC-7")])
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    assert_eq!(v["error"]["reason"], "reauth_required", "{v}");
    // Wrong code → 401 (audited), right code → reauth_until, then access.
    let (s, v) = ts.post("/api/me/reauth", json!({"totp": "000000"})).await;
    assert_eq!(s, 400, "a wrong code must not look like a logout: {v}");
    assert_eq!(v["error"]["reason"], "invalid_totp");
    let r = ts
        .http
        .post(ts.url("/api/me/reauth"))
        .json(&json!({"totp": totp.generate(now())}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403, "CSRF is required");
    let (s, v) = ts
        .post("/api/me/reauth", json!({"totp": totp.generate(now())}))
        .await;
    assert_eq!(s, 200, "{v}");
    assert!(v["reauth_until"].as_i64().unwrap() > kestrel_common::now_ms() + 9 * 60_000);
    let ok = audit_rows(&ts, "auth.reauth").await;
    assert!(ok.iter().any(|v| v["ok"] == false) && ok.iter().any(|v| v["ok"] == true));
    let r = ts
        .http
        .get(files_url(&ts, dev, ""))
        .query(&[("reason", "INC-7")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let ctx = fake
        .state
        .lock()
        .unwrap()
        .contexts
        .last()
        .cloned()
        .flatten()
        .unwrap();
    assert_eq!(ctx.reason, "INC-7");
    // The re-auth expires after 10 minutes.
    sqlx::query("UPDATE sessions SET reauth_at = reauth_at - 600001")
        .execute(&ts.state.db)
        .await
        .unwrap();
    let r = ts
        .http
        .get(files_url(&ts, dev, ""))
        .query(&[("reason", "INC-7")])
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // L2: a token that grants remote access needs a fresh MFA step-up when
    // the admin has MFA, and is never created with an API token.
    let (s, v) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"remote_profile": unrestricted()}),
        )
        .await;
    assert_eq!(s, 403, "{v}");
    assert_eq!(v["error"]["reason"], "reauth_required");
    let (s, v) = ts
        .post("/api/me/reauth", json!({"totp": totp.generate(now() + 30)}))
        .await;
    assert_eq!(s, 200, "{v}");
    let (s, v) = ts
        .post(
            "/api/enrollment-tokens",
            json!({"remote_profile": unrestricted()}),
        )
        .await;
    assert_eq!(s, 200, "{v}");
    let (_, t) = ts
        .post(
            "/api/api-tokens",
            json!({"name": "ci", "privileges": ["*"]}),
        )
        .await;
    let bare = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ts.web_ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let r = bare
        .post(ts.url("/api/enrollment-tokens"))
        .bearer_auth(t["token"].as_str().unwrap())
        .json(&json!({"remote_profile": unrestricted()}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
    let r = bare
        .post(ts.url("/api/enrollment-tokens"))
        .bearer_auth(t["token"].as_str().unwrap())
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "none() tokens still work with API tokens");

    // Server without an MSI: token is created, no script (reason given).
    let tok2 = {
        let mut ts2 = TestServer::start().await.unwrap();
        ts2.setup_admin().await;
        let t = make_token(&ts2, unrestricted()).await;
        ts2.cleanup().await;
        t
    };
    assert_eq!(tok2["installer_cmd"], Value::Null);
    assert!(tok2["installer_unavailable"]
        .as_str()
        .unwrap()
        .contains("MSI"));

    fake.task.abort();
    let _ = fake.events.try_recv();
    ts.cleanup().await;
}

// ------------------------------------------------------------ desktop

struct Ws {
    port: u16,
    cookie: String,
    csrf: String,
}

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

async fn ws_connect(
    ts: &TestServer,
    w: &Ws,
    dev: Uuid,
    query: &str,
    origin: Option<&str>,
) -> Result<WsStream, u16> {
    use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest};
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pemfile::certs(&mut ts.web_ca_pem.as_bytes()) {
        roots.add(c.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", w.port))
        .await
        .unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect("localhost".try_into().unwrap(), tcp)
        .await
        .unwrap();
    let url = format!(
        "wss://localhost:{}/api/devices/{dev}/remote-desktop?{query}",
        w.port
    );
    let mut req = url.into_client_request().unwrap();
    req.headers_mut()
        .insert("cookie", w.cookie.parse().unwrap());
    if let Some(o) = origin {
        req.headers_mut().insert("origin", o.parse().unwrap());
    }
    match tokio_tungstenite::client_async(req, tls).await {
        Ok((s, _)) => Ok(s),
        Err(tungstenite::Error::Http(r)) => Err(r.status().as_u16()),
        Err(e) => panic!("websocket error: {e}"),
    }
}

async fn ws_next(s: &mut WsStream) -> tokio_tungstenite::tungstenite::Message {
    use futures::StreamExt;
    tokio::time::timeout(Duration::from_secs(15), s.next())
        .await
        .expect("timed out waiting for the websocket")
        .expect("websocket closed")
        .expect("websocket error")
}

async fn ws_json(s: &mut WsStream) -> Value {
    loop {
        if let tokio_tungstenite::tungstenite::Message::Text(t) = ws_next(s).await {
            return serde_json::from_str(&t).unwrap();
        }
    }
}

#[tokio::test]
async fn remote_desktop_websocket() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;
    let Some(mut ts) = TestServer::start().await else {
        return;
    };
    ts.setup_admin().await;
    set_policy_remote(&ts, unrestricted()).await;
    let tok = make_token(&ts, unrestricted()).await;
    let e = enroll_with(&ts, tok["token"].as_str().unwrap(), "FIN-LAPTOP-07").await;
    let dev = e.agent.device_id;
    let mut fake = connect_fake(&ts, &e, &[CAP_LIVE_FILES, CAP_LIVE_DESKTOP]).await;

    // Raw session cookie + CSRF for the WebSocket client.
    let c = reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(ts.web_ca_pem.as_bytes()).unwrap())
        .no_proxy()
        .build()
        .unwrap();
    let r = c
        .post(ts.url("/api/auth/login"))
        .json(&json!({"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}))
        .send()
        .await
        .unwrap();
    let cookie = r.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let v: Value = r.json().await.unwrap();
    let port = ts.base.rsplit(':').next().unwrap().parse().unwrap();
    let w = Ws {
        port,
        cookie,
        csrf: v["csrf_token"].as_str().unwrap().to_string(),
    };
    let origin = format!("https://localhost:{port}");
    let q = format!("csrf={}&reason=Fix%20printer&quality=75", w.csrf);

    assert_eq!(
        ws_connect(&ts, &w, dev, &q, None).await.err(),
        Some(403),
        "Origin required"
    );
    assert_eq!(
        ws_connect(&ts, &w, dev, &q, Some("https://evil.example"))
            .await
            .err(),
        Some(403),
        "foreign Origin"
    );
    assert_eq!(
        ws_connect(&ts, &w, dev, "csrf=nope", Some(&origin))
            .await
            .err(),
        Some(403),
        "bad csrf"
    );

    let mut s = ws_connect(&ts, &w, dev, &q, Some(&origin))
        .await
        .expect("upgrade");
    let starting = ws_json(&mut s).await;
    assert_eq!(starting["type"], "starting");
    assert_eq!(starting["view_only"], false);
    let sid = starting["session_id"].as_str().unwrap().to_string();
    let ev = fake
        .next_event(|e| matches!(e, Ev::DesktopStart { .. }))
        .await;
    assert_eq!(
        ev,
        Ev::DesktopStart {
            view_only: false,
            admin: "Ada Admin".into(),
            reason: "Fix printer".into()
        }
    );
    let started = ws_json(&mut s).await;
    assert_eq!(started["type"], "started");
    assert_eq!(started["width"], 1920);
    let frame = loop {
        if let Message::Binary(b) = ws_next(&mut s).await {
            break b;
        }
    };
    assert_eq!(&frame[0..4], &1u32.to_be_bytes());
    assert_eq!(u16::from_be_bytes([frame[4], frame[5]]), 1920);
    assert_eq!(u16::from_be_bytes([frame[6], frame[7]]), 1080);
    assert_eq!(
        u64::from_be_bytes(frame[8..16].try_into().unwrap()),
        1_700_000_000_000
    );
    assert_eq!(&frame[16..], b"\xff\xd8fake-jpeg\xff\xd9");
    assert_eq!(
        fake.next_event(|e| matches!(e, Ev::DesktopAck(_))).await,
        Ev::DesktopAck(1)
    );

    // Status shows the session; a second session → 409 naming the admin.
    let (st_code, status) = ts
        .get(&format!("/api/devices/{dev}/remote-desktop/status"))
        .await;
    assert_eq!(st_code, 200);
    assert_eq!(status["active"], true);
    assert_eq!(status["session"]["session_id"], sid);
    assert_eq!(status["session"]["admin_email"], ADMIN_EMAIL);
    let r = c
        .get(ts.url(&format!("/api/devices/{dev}/remote-desktop?{q}")))
        .header("cookie", &w.cookie)
        .header("origin", &origin)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("Ada Admin"));
    assert_eq!(
        ws_connect(&ts, &w, dev, &q, Some(&origin)).await.err(),
        Some(409)
    );

    // Input, ping, view-only switch (audited), stop.
    s.send(Message::Text(
        json!({"type":"input","event":{"kind":"mouse_move","x":0.5,"y":0.5}}).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(
        fake.next_event(|e| matches!(e, Ev::DesktopInput)).await,
        Ev::DesktopInput
    );
    s.send(Message::Text("{not json".into())).await.unwrap();
    s.send(Message::Text(json!({"type":"ping"}).to_string()))
        .await
        .unwrap();
    assert_eq!(ws_json(&mut s).await["type"], "pong");
    s.send(Message::Text(
        json!({"type":"settings","quality":50,"scale_pct":50,"max_fps":5,"view_only":true})
            .to_string(),
    ))
    .await
    .unwrap();
    let mode = wait_audit(&ts, "remote.desktop.mode", |v| v["session_id"] == sid).await;
    assert_eq!(mode["view_only"], true);
    s.send(Message::Text(json!({"type":"stop"}).to_string()))
        .await
        .unwrap();
    assert_eq!(
        fake.next_event(|e| matches!(e, Ev::DesktopStop(_))).await,
        Ev::DesktopStop("admin".into())
    );
    let ended = ws_json(&mut s).await;
    assert_eq!(ended["type"], "ended");
    let stop = wait_audit(&ts, "remote.desktop.stop", |v| v["session_id"] == sid).await;
    assert_eq!(stop["ended_by"], "admin");
    assert!(stop["duration_ms"].as_i64().unwrap() >= 0);
    let start = wait_audit(&ts, "remote.desktop.start", |v| v["session_id"] == sid).await;
    assert_eq!(start["ok"], true);
    assert_eq!(start["reason"], "Fix printer");
    assert!(start["profile"].as_str().is_some());
    // The slot is released.
    for _ in 0..100 {
        if ts
            .get(&format!("/api/devices/{dev}/remote-desktop/status"))
            .await
            .1["active"]
            == false
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        ts.get(&format!("/api/devices/{dev}/remote-desktop/status"))
            .await
            .1["active"],
        false
    );

    // View-only effective profile forces view_only.
    let mut vo = RemoteAccessProfile::unrestricted();
    vo.desktop = kestrel_common::remote::DesktopMode::ViewOnly;
    set_policy_remote(&ts, serde_json::to_value(&vo).unwrap()).await;
    let mut s = ws_connect(&ts, &w, dev, &q, Some(&origin))
        .await
        .expect("upgrade");
    assert_eq!(ws_json(&mut s).await["view_only"], true);
    assert!(matches!(
        fake.next_event(|e| matches!(e, Ev::DesktopStart { .. }))
            .await,
        Ev::DesktopStart {
            view_only: true,
            ..
        }
    ));
    s.send(Message::Text(
        json!({"type":"settings","quality":60,"scale_pct":100,"max_fps":8,"view_only":false})
            .to_string(),
    ))
    .await
    .unwrap();
    loop {
        let m = ws_json(&mut s).await;
        if m["type"] == "error" {
            assert!(m["message"].as_str().unwrap().contains("view-only"));
            break;
        }
    }
    drop(s); // browser goes away → session ends (ended_by admin)
    assert!(matches!(
        fake.next_event(|e| matches!(e, Ev::DesktopStop(_))).await,
        Ev::DesktopStop(_)
    ));

    // M5: an oversized live message is dropped before parsing; consent for a
    // mid-session switch to control (require_consent) gates control.
    let mut guarded = RemoteAccessProfile::unrestricted();
    guarded.guardrails.require_consent = true;
    set_policy_remote(&ts, serde_json::to_value(&guarded).unwrap()).await;
    {
        let mut st = fake.state.lock().unwrap();
        st.oversize_frame = true;
        st.control_consent = Some(false);
    }
    let qv = format!("{q}&view_only=1");
    let mut s = ws_connect(&ts, &w, dev, &qv, Some(&origin))
        .await
        .expect("upgrade");
    let sid2 = ws_json(&mut s).await["session_id"]
        .as_str()
        .unwrap()
        .to_string();
    let frame = loop {
        if let Message::Binary(b) = ws_next(&mut s).await {
            break b;
        }
    };
    assert_eq!(
        &frame[0..4],
        &2u32.to_be_bytes(),
        "the oversized frame never arrives"
    );
    // Denied: stays view-only, input is dropped.
    s.send(Message::Text(
        json!({"type":"settings","quality":60,"scale_pct":100,"max_fps":8,"view_only":false})
            .to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(ws_json(&mut s).await["type"], "consent_pending");
    let cr = ws_json(&mut s).await;
    assert_eq!(cr["type"], "consent_result");
    assert_eq!(cr["allowed"], false);
    wait_audit(&ts, "remote.consent", |v| {
        v["session_id"] == sid2 && v["result"] == "denied"
    })
    .await;
    s.send(Message::Text(
        json!({"type":"input","event":{"kind":"mouse_move","x":0.1,"y":0.1}}).to_string(),
    ))
    .await
    .unwrap();
    s.send(Message::Text(json!({"type":"ping"}).to_string()))
        .await
        .unwrap();
    loop {
        if ws_json(&mut s).await["type"] == "pong" {
            break;
        }
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    while let Ok(ev) = fake.events.try_recv() {
        assert_ne!(
            ev,
            Ev::DesktopInput,
            "input must be dropped while view-only"
        );
    }
    // Allowed: control after the agent confirms; audited as a mode change.
    fake.state.lock().unwrap().control_consent = Some(true);
    s.send(Message::Text(
        json!({"type":"settings","quality":60,"scale_pct":100,"max_fps":8,"view_only":false})
            .to_string(),
    ))
    .await
    .unwrap();
    loop {
        let m = ws_json(&mut s).await;
        if m["type"] == "consent_result" {
            assert_eq!(m["allowed"], true);
            break;
        }
    }
    let mode = wait_audit(&ts, "remote.desktop.mode", |v| v["session_id"] == sid2).await;
    assert_eq!(mode["view_only"], false);
    wait_audit(&ts, "remote.consent", |v| {
        v["session_id"] == sid2 && v["result"] == "allowed"
    })
    .await;
    s.send(Message::Text(
        json!({"type":"input","event":{"kind":"mouse_move","x":0.2,"y":0.2}}).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(
        fake.next_event(|e| matches!(e, Ev::DesktopInput)).await,
        Ev::DesktopInput
    );
    s.send(Message::Text(json!({"type":"stop"}).to_string()))
        .await
        .unwrap();
    assert!(matches!(
        fake.next_event(|e| matches!(e, Ev::DesktopStop(_))).await,
        Ev::DesktopStop(_)
    ));
    {
        let mut st = fake.state.lock().unwrap();
        st.oversize_frame = false;
        st.control_consent = None;
    }

    // Consent denied on the device: consent_pending, then ended with the code.
    set_policy_remote(&ts, unrestricted()).await;
    fake.state.lock().unwrap().consent = Consent::Deny;
    let mut s = ws_connect(&ts, &w, dev, &q, Some(&origin))
        .await
        .expect("upgrade");
    assert_eq!(ws_json(&mut s).await["type"], "starting");
    let p = ws_json(&mut s).await;
    assert_eq!(p["type"], "consent_pending", "{p}");
    assert_eq!(p["timeout_secs"], 5);
    let ended = ws_json(&mut s).await;
    assert_eq!(ended["type"], "ended");
    assert_eq!(ended["code"], "consent_denied");
    wait_audit(&ts, "remote.consent", |v| {
        v["kind"] == "desktop" && v["result"] == "denied"
    })
    .await;
    let failed = wait_audit(&ts, "remote.desktop.start", |v| {
        v["ok"] == false && v["error"].as_str().unwrap_or("").contains("declined")
    })
    .await;
    assert!(failed["error"].as_str().unwrap().contains("declined"));

    // Desktop status needs a session too (API token → 403).
    let (_, t) = ts
        .post(
            "/api/api-tokens",
            json!({"name": "auto", "privileges": ["*"]}),
        )
        .await;
    let r = c
        .get(ts.url(&format!("/api/devices/{dev}/remote-desktop/status")))
        .bearer_auth(t["token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    fake.task.abort();
    ts.cleanup().await;
}
