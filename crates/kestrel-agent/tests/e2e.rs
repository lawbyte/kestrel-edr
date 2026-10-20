//! End-to-end: the real agent core (SimPlatform) against an in-process mock
//! gRPC server over TLS/mTLS.
//!
//! Covers enroll → connect (mTLS) → Hello first → Welcome/Policy applied →
//! replayed telemetry uploaded as event batches → heartbeats → cumulative
//! acks drain the outbox → idempotent commands → outbox and heartbeat seq
//! survive an agent restart → `status` over the tray socket.
//!
//! Detection output depends on the engine (built in parallel), so this test
//! asserts transport-level behaviour only.

use kestrel_agent::{
    agent::{self, Tuning},
    codec, commands,
    proto::{
        agent_service_server::{AgentService, AgentServiceServer},
        AgentEnvelope, EnrollEnvelope, ServerEnvelope,
    },
    sim::{SimOptions, SimPlatform, SIM_USER},
    store,
};
use kestrel_common::{
    wire::{AgentPayload, EnrollRequest, EnrollResponse, ServerPayload},
    Branding, Policy, ResponseAction,
};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream, StreamExt};
use tonic::{transport::Server, Request, Response, Status, Streaming};
use uuid::Uuid;

const SERVER_NAME: &str = "kestrel-test-server";
const TOKEN: &str = "kst_enroll_test_123";

struct Pki {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    server_cert_pem: String,
    server_key_pem: String,
}

fn pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    p.distinguished_name
        .push(rcgen::DnType::CommonName, "Kestrel Test CA");
    p.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
    ];
    let ca_cert = p.self_signed(&ca_key).unwrap();
    let skey = rcgen::KeyPair::generate().unwrap();
    let mut sp = rcgen::CertificateParams::new(vec![SERVER_NAME.to_string()]).unwrap();
    sp.distinguished_name
        .push(rcgen::DnType::CommonName, SERVER_NAME);
    let scert = sp.signed_by(&skey, &ca_cert, &ca_key).unwrap();
    Pki {
        server_cert_pem: scert.pem(),
        server_key_pem: skey.serialize_pem(),
        ca_cert,
        ca_key,
    }
}

const SERVER_UNINSTALL_TOKEN: &str = "kun_server_issued_0123456789";

#[derive(Default)]
struct Recorded {
    /// (envelope seq, payload) for every agent message, in arrival order, per session.
    sessions: Vec<Vec<(u64, AgentPayload)>>,
    /// DER of the client certificate presented on each session.
    peer_certs: Vec<Vec<u8>>,
    enrolls: u32,
    renewals: u32,
    /// Server seqs of the `SetUninstallToken` messages sent (invalid, valid).
    token_seqs: Vec<u64>,
}

struct Mock {
    ca_cert: rcgen::Certificate,
    ca_key: rcgen::KeyPair,
    device_id: Uuid,
    command_id: Uuid,
    rec: Arc<Mutex<Recorded>>,
    /// Validity of certificates issued at enrollment (days).
    enroll_days: i64,
    /// Send `ServerPayload::RenewCertificate` on this session index.
    ask_renew_on_session: Option<usize>,
    /// Skip the scripted policy/command traffic (renewal test).
    quiet: bool,
    /// Rotate the uninstall token on the first session: an invalid
    /// `SetUninstallToken` (must not be acked) followed by this token.
    set_token: Option<String>,
}

fn sign_csr(
    csr_pem: &str,
    device_id: Uuid,
    days: i64,
    ca: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
) -> Result<String, String> {
    let mut csr =
        rcgen::CertificateSigningRequestParams::from_pem(csr_pem).map_err(|e| e.to_string())?;
    csr.params.distinguished_name = rcgen::DistinguishedName::new();
    csr.params
        .distinguished_name
        .push(rcgen::DnType::CommonName, device_id.to_string());
    csr.params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    csr.params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    csr.signed_by(ca, ca_key)
        .map(|c| c.pem())
        .map_err(|e| e.to_string())
}

type SStream = Pin<Box<dyn Stream<Item = Result<ServerEnvelope, Status>> + Send>>;

fn env(seq: u64, p: &ServerPayload) -> ServerEnvelope {
    let (payload, compressed) = codec::encode(p, false).unwrap();
    ServerEnvelope {
        seq,
        compressed,
        payload,
    }
}

#[tonic::async_trait]
impl AgentService for Mock {
    async fn enroll(
        &self,
        req: Request<EnrollEnvelope>,
    ) -> Result<Response<EnrollEnvelope>, Status> {
        let r: EnrollRequest = serde_json::from_slice(&req.into_inner().json)
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        if r.token != TOKEN {
            return Err(Status::unauthenticated("bad token"));
        }
        let cert = sign_csr(
            &r.csr_pem,
            self.device_id,
            self.enroll_days,
            &self.ca_cert,
            &self.ca_key,
        )
        .map_err(Status::invalid_argument)?;
        self.rec.lock().unwrap().enrolls += 1;
        let resp = EnrollResponse {
            device_id: self.device_id,
            cert_pem: cert,
            ca_pem: self.ca_cert.pem(),
            uninstall_token: SERVER_UNINSTALL_TOKEN.into(),
        };
        Ok(Response::new(EnrollEnvelope {
            json: serde_json::to_vec(&resp).unwrap(),
        }))
    }

    type ConnectStream = SStream;

    async fn connect(
        &self,
        req: Request<Streaming<AgentEnvelope>>,
    ) -> Result<Response<SStream>, Status> {
        let peer = match req.peer_certs() {
            Some(c) if !c.is_empty() => c[0].as_ref().to_vec(),
            _ => return Err(Status::unauthenticated("client certificate required")),
        };
        let mut inbound = req.into_inner();
        let (tx, rx) = mpsc::channel(64);
        let rec = self.rec.clone();
        let device_id = self.device_id;
        let command_id = self.command_id;
        let quiet = self.quiet;
        let ask_renew = self.ask_renew_on_session;
        let set_token = self.set_token.clone();
        let ca_pem = self.ca_cert.pem();
        // rcgen types are not Clone/Send-friendly across tasks: re-sign through a channel.
        let (sign_tx, mut sign_rx) =
            mpsc::channel::<(String, tokio::sync::oneshot::Sender<Result<String, String>>)>(4);
        let session = {
            let mut r = rec.lock().unwrap();
            r.sessions.push(vec![]);
            r.peer_certs.push(peer);
            r.sessions.len() - 1
        };
        {
            // Signer task owning a copy of the CA (re-parsed from PEM).
            let ca_key_pem = self.ca_key.serialize_pem();
            let ca_cert_pem = ca_pem.clone();
            tokio::spawn(async move {
                let key = rcgen::KeyPair::from_pem(&ca_key_pem).unwrap();
                let params = rcgen::CertificateParams::from_ca_cert_pem(&ca_cert_pem).unwrap();
                let ca = params.self_signed(&key).unwrap();
                while let Some((csr, reply)) = sign_rx.recv().await {
                    let _ = reply.send(sign_csr(&csr, device_id, 365, &ca, &key));
                }
            });
        }
        tokio::spawn(async move {
            let mut sseq = 0u64;
            let mut next = |p: ServerPayload| {
                sseq += 1;
                env(sseq, &p)
            };
            let mut first = true;
            while let Some(Ok(e)) = inbound.next().await {
                let p: AgentPayload = codec::decode(&e.payload, e.compressed).unwrap();
                rec.lock().unwrap().sessions[session].push((e.seq, p.clone()));
                if let AgentPayload::RenewCertificate { csr_pem } = &p {
                    assert_eq!(e.seq, 0, "renewal requests are ephemeral");
                    let (rtx, rrx) = tokio::sync::oneshot::channel();
                    sign_tx.send((csr_pem.clone(), rtx)).await.unwrap();
                    let cert_pem = rrx.await.unwrap().expect("CSR signs");
                    rec.lock().unwrap().renewals += 1;
                    let _ = tx
                        .send(Ok(next(ServerPayload::Certificate {
                            cert_pem,
                            ca_pem: ca_pem.clone(),
                        })))
                        .await;
                    continue;
                }
                if first {
                    assert!(
                        matches!(p, AgentPayload::Hello(_)),
                        "first message must be Hello"
                    );
                    first = false;
                    let _ = tx
                        .send(Ok(next(ServerPayload::Welcome {
                            device_id,
                            server_time: kestrel_common::now_ms(),
                        })))
                        .await;
                    if ask_renew == Some(session) {
                        let _ = tx.send(Ok(next(ServerPayload::RenewCertificate))).await;
                    }
                    if let (Some(t), 0) = (&set_token, session) {
                        for token in ["  ".to_string(), t.clone()] {
                            let m = next(ServerPayload::SetUninstallToken { token });
                            rec.lock().unwrap().token_seqs.push(m.seq);
                            let _ = tx.send(Ok(m)).await;
                        }
                    }
                    if quiet {
                        continue;
                    }
                    let policy = Policy {
                        id: "pol-1".into(),
                        name: "Finance laptops".into(),
                        version: 5,
                        branding: Branding {
                            org_name: "Acme Pte Ltd".into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    let _ = tx
                        .send(Ok(next(ServerPayload::Policy(Box::new(policy)))))
                        .await;
                    // Same command twice: must execute once, result reported for both.
                    let cmd = ServerPayload::Command {
                        command_id,
                        action: ResponseAction::Scan {
                            path: Some(r"C:\Users\j.doe\Downloads".into()),
                        },
                    };
                    let _ = tx.send(Ok(next(cmd.clone()))).await;
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    let _ = tx.send(Ok(next(cmd))).await;
                    continue;
                }
                if e.seq > 0 {
                    let _ = tx.send(Ok(next(ServerPayload::Ack { seq: e.seq }))).await;
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx)) as SStream))
    }
}

fn tuning() -> Tuning {
    Tuning {
        heartbeat: Duration::from_millis(400),
        batch_max_delay: Duration::from_millis(150),
        tick: Duration::from_millis(50),
        ..Tuning::default()
    }
}

fn sim(state: &Path, replay: Option<&str>) -> Arc<SimPlatform> {
    Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: replay.map(|f| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("replays")
                .join(f)
        }),
        speed: 40.0,
        hostname: "SIM-E2E-01".into(),
        user: SIM_USER.into(),
    }))
}

async fn wait_for<F: FnMut() -> bool>(what: &str, timeout: Duration, mut f: F) {
    let deadline = tokio::time::Instant::now() + timeout;
    while !f() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn all_msgs(rec: &Arc<Mutex<Recorded>>) -> Vec<(u64, AgentPayload)> {
    rec.lock()
        .unwrap()
        .sessions
        .iter()
        .flatten()
        .cloned()
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn enroll_connect_replay_ack_restart() {
    kestrel_agent::pki::install_crypto_provider();
    let pki = pki();
    let ca_pem = pki.ca_cert.pem();
    let rec = Arc::new(Mutex::new(Recorded::default()));
    let device_id = Uuid::new_v4();
    let command_id = Uuid::new_v4();
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            &pki.server_cert_pem,
            &pki.server_key_pem,
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca_pem))
        .client_auth_optional(true);
    let mock = Mock {
        ca_cert: pki.ca_cert,
        ca_key: pki.ca_key,
        device_id,
        command_id,
        rec: rec.clone(),
        enroll_days: 365,
        ask_renew_on_session: None,
        quiet: false,
        set_token: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentServiceServer::new(mock))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });

    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();

    // --- install + enroll (as `kestrel-agent install --no-service` would)
    let opts = commands::InstallOpts {
        server: addr.to_string(),
        ca: ca_pem.clone(),
        token: TOKEN.into(),
        server_name: Some(SERVER_NAME.into()),
        ..Default::default()
    };
    commands::write_install_config(state, &opts).unwrap();
    // Wrong token is rejected and leaves the agent unenrolled.
    assert!(
        commands::enroll(state, Some("nope"), "SIM-E2E-01", Default::default())
            .await
            .is_err()
    );
    let id = commands::enroll(state, None, "SIM-E2E-01", Default::default())
        .await
        .unwrap();
    assert_eq!(id, device_id);
    let cfg = kestrel_agent::config::AgentConfig::load(state).unwrap();
    assert_eq!(cfg.device_id, Some(device_id));
    assert!(
        cfg.pending_enroll_token.is_none(),
        "enroll token must be dropped after use"
    );
    // M5: the uninstall token comes from the server; only its hash is stored.
    assert!(cfg.verify_uninstall_token(SERVER_UNINSTALL_TOKEN));
    assert!(
        !std::fs::read_to_string(kestrel_agent::config::AgentConfig::path(state))
            .unwrap()
            .contains(SERVER_UNINSTALL_TOKEN)
    );
    assert!(commands::ensure_uninstall_token(state).unwrap().is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(kestrel_agent::pki::key_path(state))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o077, 0, "private key must not be group/world readable");
    }

    // --- run the agent with a replay
    let replay_len = kestrel_agent::sim::load_replay(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("replays/lumma_clickfix.jsonl"),
    )
    .unwrap()
    .len();
    let platform = sim(state, Some("lumma_clickfix.jsonl"));
    let handle = agent::start(platform.clone(), state.to_path_buf(), tuning())
        .await
        .unwrap();
    let core = handle.core.clone();

    wait_for(
        "all replayed events uploaded",
        Duration::from_secs(30),
        || {
            let n: usize = all_msgs(&rec)
                .iter()
                .map(|(_, p)| {
                    if let AgentPayload::Events { events } = p {
                        events.len()
                    } else {
                        0
                    }
                })
                .sum();
            n >= replay_len
        },
    )
    .await;
    wait_for("two action results", Duration::from_secs(10), || {
        all_msgs(&rec)
            .iter()
            .filter(|(_, p)| matches!(p, AgentPayload::ActionResult { .. }))
            .count()
            >= 2
    })
    .await;
    wait_for("heartbeats", Duration::from_secs(10), || {
        all_msgs(&rec)
            .iter()
            .filter(|(_, p)| matches!(p, AgentPayload::Heartbeat(_)))
            .count()
            >= 2
    })
    .await;

    let msgs = all_msgs(&rec);
    // Hello first, with seq 0 and our identity.
    let epoch = match &msgs[0] {
        (0, AgentPayload::Hello(h)) => {
            assert_eq!(h.device_id, device_id);
            assert_eq!(h.hostname, "SIM-E2E-01");
            assert_eq!(h.boot_id, kestrel_agent::sim::SIM_BOOT_ID);
            h.outbox_epoch.expect("M8: Hello carries the outbox epoch")
        }
        other => panic!("first message was {other:?}"),
    };
    // Durable messages carry strictly increasing seqs within a session.
    let durable: Vec<u64> = rec.lock().unwrap().sessions[0]
        .iter()
        .map(|(s, _)| *s)
        .filter(|s| *s > 0)
        .collect();
    assert!(
        durable.windows(2).all(|w| w[0] < w[1]),
        "seqs not increasing: {durable:?}"
    );
    // Events: exactly the replay, in order, with ts rewritten to ~now.
    let events: Vec<_> = msgs
        .iter()
        .flat_map(|(_, p)| {
            if let AgentPayload::Events { events } = p {
                events.clone()
            } else {
                vec![]
            }
        })
        .collect();
    assert_eq!(events.len(), replay_len, "no duplicates or losses");
    let now = kestrel_common::now_ms();
    assert!(
        events.iter().all(|e| (now - e.ts).abs() < 120_000),
        "ts not rewritten to wall clock"
    );
    // Batches ≤ 500 events.
    assert!(msgs
        .iter()
        .all(|(_, p)| !matches!(p, AgentPayload::Events { events } if events.len() > 500)));
    // Command executed once, result sent twice with the same id.
    let results: Vec<_> = msgs
        .iter()
        .filter_map(|(_, p)| {
            if let AgentPayload::ActionResult {
                command_id,
                outcome,
            } = p
            {
                Some((*command_id, outcome.clone()))
            } else {
                None
            }
        })
        .collect();
    assert!(results.iter().all(|(c, o)| *c == command_id && o.ok));
    let scans = platform
        .executed()
        .iter()
        .filter(|o| matches!(o.action, ResponseAction::Scan { .. }))
        .count();
    assert_eq!(scans, 1, "duplicate command must not re-execute");
    // Policy applied and persisted.
    assert_eq!(core.policy_version(), 5);
    assert_eq!(
        core.store
            .kv_get_json::<Policy>(store::KV_POLICY)
            .unwrap()
            .unwrap()
            .name,
        "Finance laptops"
    );
    // Heartbeats strictly increasing.
    let hb: Vec<u64> = msgs
        .iter()
        .filter_map(|(_, p)| {
            if let AgentPayload::Heartbeat(h) = p {
                Some(h.seq)
            } else {
                None
            }
        })
        .collect();
    assert!(hb.windows(2).all(|w| w[0] < w[1]));
    let last_hb = *hb.last().unwrap();
    // Health is populated from the sim sensors + hardening.
    if let Some((_, AgentPayload::Heartbeat(h))) = msgs
        .iter()
        .rev()
        .find(|(_, p)| matches!(p, AgentPayload::Heartbeat(_)))
    {
        assert!(h.health.etw_ok);
        assert_eq!(h.health.logged_on_user.as_deref(), Some(SIM_USER));
    }
    // Acks drain the outbox.
    wait_for("outbox drained", Duration::from_secs(10), || {
        core.outbox_depth() == 0
    })
    .await;

    // Tray endpoint answers `status` with the policy branding.
    #[cfg(unix)]
    {
        let v = commands::status(state).await.unwrap();
        assert_eq!(v["running"], true, "{v}");
        assert_eq!(v["status"]["org_name"], "Acme Pte Ltd");
        assert_eq!(v["status"]["policy_name"], "Finance laptops");
        assert_eq!(v["status"]["server_connected"], true);
        assert_eq!(v["device_id"], device_id.to_string());
    }

    handle.stop().await;

    // --- offline: queue an alert-priority row while the agent is down; restart must deliver it
    {
        let st = store::Store::open(state).unwrap();
        st.enqueue(&AgentPayload::ReviewRequest(
            kestrel_common::wire::ReviewRequest {
                alert_id: Uuid::nil(),
                user: SIM_USER.into(),
                justification: "queued while offline".into(),
                ts: 1,
            },
        ))
        .unwrap();
    }
    let sessions_before = rec.lock().unwrap().sessions.len();
    let handle = agent::start(sim(state, None), state.to_path_buf(), tuning())
        .await
        .unwrap();
    wait_for("reconnect replays queued row", Duration::from_secs(20), || {
        let r = rec.lock().unwrap();
        r.sessions.len() > sessions_before
            && r.sessions.last().unwrap().iter().any(|(_, p)| matches!(p, AgentPayload::ReviewRequest(rr) if rr.justification == "queued while offline"))
    })
    .await;
    wait_for("heartbeat after restart", Duration::from_secs(10), || {
        rec.lock()
            .unwrap()
            .sessions
            .last()
            .unwrap()
            .iter()
            .any(|(_, p)| matches!(p, AgentPayload::Heartbeat(_)))
    })
    .await;
    {
        let r = rec.lock().unwrap();
        let s = r.sessions.last().unwrap();
        match &s[0].1 {
            AgentPayload::Hello(h) => {
                assert_eq!(h.policy_version, 5, "cached policy version reported");
                assert_eq!(h.outbox_epoch, Some(epoch), "epoch survives restarts");
            }
            other => panic!("expected Hello, got {other:?}"),
        }
        let hb2 = s
            .iter()
            .find_map(|(_, p)| {
                if let AgentPayload::Heartbeat(h) = p {
                    Some(h.seq)
                } else {
                    None
                }
            })
            .unwrap();
        assert!(
            hb2 > last_hb,
            "heartbeat seq must persist across restarts ({hb2} <= {last_hb})"
        );
        assert_eq!(r.enrolls, 1, "restart must not re-enroll");
    }
    handle.stop().await;
}

/// H3: certificate renewal over the mTLS stream — at Welcome when < 30 days
/// are left, and when the server asks — with an atomic key/cert swap, a
/// reconnect with the new identity, and clean-up of the previous pair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn certificate_renewal() {
    let _ = tracing_subscriber::fmt()
        .with_test_writer()
        .with_env_filter("kestrel_agent=info")
        .try_init();
    kestrel_agent::pki::install_crypto_provider();
    let pki = pki();
    let ca_pem = pki.ca_cert.pem();
    let rec = Arc::new(Mutex::new(Recorded::default()));
    let device_id = Uuid::new_v4();
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            &pki.server_cert_pem,
            &pki.server_key_pem,
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca_pem))
        .client_auth_optional(true);
    let mock = Mock {
        ca_cert: pki.ca_cert,
        ca_key: pki.ca_key,
        device_id,
        command_id: Uuid::new_v4(),
        rec: rec.clone(),
        // Enrollment certificate expires in 10 days → renewal at first Welcome.
        enroll_days: 10,
        // The server explicitly asks for another renewal on the second session
        // (whose certificate has a year left, so only the request triggers it).
        ask_renew_on_session: Some(1),
        quiet: true,
        set_token: None,
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentServiceServer::new(mock))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    commands::write_install_config(
        state,
        &commands::InstallOpts {
            server: addr.to_string(),
            ca: ca_pem.clone(),
            token: TOKEN.into(),
            server_name: Some(SERVER_NAME.into()),
            ..Default::default()
        },
    )
    .unwrap();
    commands::enroll(state, None, "SIM-E2E-02", Default::default())
        .await
        .unwrap();
    let (cert0, _) = kestrel_agent::pki::load_identity(state).unwrap();
    let not_after0 = kestrel_agent::pki::cert_not_after(&cert0).unwrap();
    assert!(kestrel_agent::pki::needs_renewal(
        &cert0,
        kestrel_agent::pki::now_secs()
    ));

    let handle = agent::start(sim(state, None), state.to_path_buf(), tuning())
        .await
        .unwrap();
    // Session 0: < 30 days left → renewal → Certificate → reconnect.
    // Session 1: a year left, but the server asks → renewal → reconnect.
    // Session 2: no renewal.
    wait_for(
        "three sessions and two renewals",
        Duration::from_secs(30),
        || {
            let r = rec.lock().unwrap();
            r.peer_certs.len() >= 3 && r.renewals >= 2
        },
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let r = rec.lock().unwrap();
        assert_eq!(r.enrolls, 1, "renewal never re-enrolls with a token");
        assert_eq!(r.renewals, 2, "no renewal while > 30 days are left");
        assert_eq!(r.peer_certs.len(), 3);
        assert_ne!(
            r.peer_certs[0], r.peer_certs[1],
            "reconnected with the renewed certificate"
        );
        assert_ne!(r.peer_certs[1], r.peer_certs[2], "server-requested renewal");
        // Hello carries the same outbox epoch on every session.
        let epochs: Vec<_> = r
            .sessions
            .iter()
            .filter_map(|s| match s.first() {
                Some((_, AgentPayload::Hello(h))) => h.outbox_epoch,
                _ => None,
            })
            .collect();
        assert!(epochs.len() >= 3 && epochs.windows(2).all(|w| w[0] == w[1]));
    }
    let (cert, key) = kestrel_agent::pki::load_identity(state).unwrap();
    assert!(kestrel_agent::pki::cert_matches_key(&cert, &key).unwrap());
    assert!(kestrel_agent::pki::cert_not_after(&cert).unwrap() > not_after0 + 300 * 86_400);
    wait_for(
        "previous identity cleaned up",
        Duration::from_secs(10),
        || {
            !kestrel_agent::pki::renewal_unconfirmed(state)
                && !kestrel_agent::pki::pending_key_path(state).exists()
        },
    )
    .await;
    handle.stop().await;
}

/// M5 follow-up: the server rotates the uninstall token over the stream
/// (`SetUninstallToken`). The agent replaces the stored hash atomically and
/// acks only once it is saved; an invalid token is never acked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn uninstall_token_rotation() {
    kestrel_agent::pki::install_crypto_provider();
    const ROTATED: &str = "kun_rotated_by_admin_9876543210";
    let pki = pki();
    let ca_pem = pki.ca_cert.pem();
    let rec = Arc::new(Mutex::new(Recorded::default()));
    let device_id = Uuid::new_v4();
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            &pki.server_cert_pem,
            &pki.server_key_pem,
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(&ca_pem))
        .client_auth_optional(true);
    let mock = Mock {
        ca_cert: pki.ca_cert,
        ca_key: pki.ca_key,
        device_id,
        command_id: Uuid::new_v4(),
        rec: rec.clone(),
        enroll_days: 365,
        ask_renew_on_session: None,
        quiet: true,
        set_token: Some(ROTATED.into()),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        Server::builder()
            .tls_config(tls)
            .unwrap()
            .add_service(AgentServiceServer::new(mock))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
            .unwrap();
    });
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    commands::write_install_config(
        state,
        &commands::InstallOpts {
            server: addr.to_string(),
            ca: ca_pem.clone(),
            token: TOKEN.into(),
            server_name: Some(SERVER_NAME.into()),
            ..Default::default()
        },
    )
    .unwrap();
    commands::enroll(state, None, "SIM-E2E-03", Default::default())
        .await
        .unwrap();
    assert!(commands::verify_uninstall(state, SERVER_UNINSTALL_TOKEN).is_ok());

    let handle = agent::start(sim(state, None), state.to_path_buf(), tuning())
        .await
        .unwrap();
    let acked = |rec: &Arc<Mutex<Recorded>>, seq: u64| {
        all_msgs(rec)
            .iter()
            .any(|(s, p)| *s == 0 && matches!(p, AgentPayload::Ack { seq: a } if *a == seq))
    };
    wait_for("token message sent", Duration::from_secs(20), || {
        rec.lock().unwrap().token_seqs.len() == 2
    })
    .await;
    let (bad_seq, good_seq) = {
        let r = rec.lock().unwrap();
        (r.token_seqs[0], r.token_seqs[1])
    };
    wait_for("rotation acked", Duration::from_secs(20), || {
        acked(&rec, good_seq)
    })
    .await;
    // Acked only after the new hash is on disk.
    let cfg = kestrel_agent::config::AgentConfig::load(state).unwrap();
    assert!(cfg.verify_uninstall_token(ROTATED));
    assert!(
        !cfg.verify_uninstall_token(SERVER_UNINSTALL_TOKEN),
        "previous token must stop working"
    );
    assert!(commands::verify_uninstall(state, ROTATED).is_ok());
    assert!(commands::verify_uninstall(state, SERVER_UNINSTALL_TOKEN).is_err());
    let raw = std::fs::read_to_string(kestrel_agent::config::AgentConfig::path(state)).unwrap();
    assert!(!raw.contains(ROTATED), "only the hash is stored");
    assert!(
        !kestrel_agent::config::AgentConfig::path(state)
            .with_extension("toml.tmp")
            .exists(),
        "temp file renamed over agent.toml"
    );
    // Identity and server settings survive the rewrite.
    assert_eq!(cfg.device_id, Some(device_id));
    assert_eq!(cfg.server, addr.to_string());
    // The invalid token is never acked (the server keeps it pending).
    assert!(!acked(&rec, bad_seq), "invalid token must not be acked");
    // In-memory config follows the file.
    assert!(handle.core.config().verify_uninstall_token(ROTATED));
    handle.stop().await;
}
