//! Integration-test harness: a fresh Postgres database per test, the real
//! HTTPS + gRPC servers on ephemeral ports, and helper clients.
//!
//! Requires `DATABASE_URL` (or `KESTREL_TEST_DATABASE_URL`) pointing at a Postgres
//! server where the user may `CREATE DATABASE`. Tests are skipped when unset.
//! ClickHouse tests additionally need `KESTREL_TEST_CLICKHOUSE_URL`.
#![allow(dead_code)]

use kestrel_common::wire::{
    AgentPayload, EnrollRequest, EnrollResponse, Hello, OsInfo, ServerPayload,
};
use kestrel_server::{
    config::{ClickHouseConfig, Config},
    grpc::pb::{
        agent_service_client::AgentServiceClient, AgentEnvelope, EnrollEnvelope, ServerEnvelope,
    },
    state::AppState,
};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::sync::mpsc;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use uuid::Uuid;

pub fn admin_db_url() -> Option<String> {
    std::env::var("KESTREL_TEST_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .filter(|s| !s.is_empty())
}

pub fn clickhouse_url() -> Option<String> {
    std::env::var("KESTREL_TEST_CLICKHOUSE_URL")
        .ok()
        .filter(|s| !s.is_empty())
}

pub const TEST_SETUP_CODE: &str = "TEST-SETUP-CODE";

pub struct TestServer {
    pub state: AppState,
    pub base: String,
    pub grpc_port: u16,
    pub http: reqwest::Client,
    pub web_ca_pem: String,
    pub db_name: String,
    admin_url: String,
    pub csrf: String,
    running: kestrel_server::Running,
}

fn with_db(url: &str, db: &str) -> String {
    let (base, query) = match url.split_once('?') {
        Some((b, q)) => (b.to_string(), format!("?{q}")),
        None => (url.to_string(), String::new()),
    };
    let idx = base.rfind('/').expect("db url has a path");
    format!("{}/{}{}", &base[..idx], db, query)
}

pub fn http_client(web_ca_pem: &str) -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(web_ca_pem.as_bytes()).unwrap())
        .cookie_store(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

impl TestServer {
    pub async fn start() -> Option<TestServer> {
        Self::start_with(false).await
    }

    pub async fn start_with(clickhouse: bool) -> Option<TestServer> {
        let admin_url = match admin_db_url() {
            Some(u) => u,
            None => {
                eprintln!("SKIP: DATABASE_URL not set");
                return None;
            }
        };
        let ch = if clickhouse {
            match clickhouse_url() {
                Some(u) => Some(u),
                None => {
                    eprintln!("SKIP: KESTREL_TEST_CLICKHOUSE_URL not set");
                    return None;
                }
            }
        } else {
            None
        };
        let db_name = format!("kt_{}", Uuid::new_v4().simple());
        let admin = sqlx::PgPool::connect(&admin_url)
            .await
            .expect("connect admin db");
        sqlx::query(&format!("CREATE DATABASE {db_name}"))
            .execute(&admin)
            .await
            .expect("create test database");
        admin.close().await;

        let cfg = Config {
            database_url: with_db(&admin_url, &db_name),
            master_key: "test-master-key-0123456789abcdef".into(),
            public_hostnames: vec!["localhost".into()],
            https_addr: "127.0.0.1:0".parse().unwrap(),
            grpc_addr: "127.0.0.1:0".parse().unwrap(),
            grpc_public_port: 8443,
            tls_cert: None,
            tls_key: None,
            console_dir: "/nonexistent-console".into(),
            agent_dir: "/nonexistent-agent".into(),
            agent_msi_url: None,
            clickhouse: ch.map(|url| ClickHouseConfig {
                url,
                user: std::env::var("KESTREL_TEST_CLICKHOUSE_USER")
                    .unwrap_or_else(|_| "default".into()),
                password: std::env::var("KESTREL_TEST_CLICKHOUSE_PASSWORD").unwrap_or_default(),
                database: db_name.clone(),
            }),
            heartbeat_interval_ms: 60_000,
            trusted_proxies: vec![],
            setup_code: Some(TEST_SETUP_CODE.into()),
            outbound_allow: vec![],
            run_jobs: false,
        };
        let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let grpc = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let state = kestrel_server::build_state(cfg).await.expect("build state");
        let running = kestrel_server::serve(state.clone(), https, grpc)
            .await
            .expect("serve");
        let web =
            kestrel_server::pki::web_identity(&state.db, &state.mk, &state.cfg.public_hostnames)
                .await
                .unwrap();
        let base = format!("https://localhost:{}", running.https_addr.port());
        Some(TestServer {
            http: http_client(&web.cert_pem),
            web_ca_pem: web.cert_pem,
            grpc_port: running.grpc_addr.port(),
            base,
            state,
            db_name,
            admin_url,
            csrf: String::new(),
            running,
        })
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    /// Run first-run setup and keep the admin session (cookie + CSRF).
    pub async fn setup_admin(&mut self) -> Value {
        let r = self
            .http
            .post(self.url("/api/auth/setup"))
            .json(&json!({"setup_code": TEST_SETUP_CODE, "org_name": "Acme Pte Ltd", "email": "admin@acme.test", "password": "correct horse battery", "name": "Ada Admin"}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "setup failed");
        let v: Value = r.json().await.unwrap();
        self.csrf = v["csrf_token"].as_str().unwrap().to_string();
        v
    }

    pub async fn get(&self, path: &str) -> (u16, Value) {
        let r = self.http.get(self.url(path)).send().await.unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    pub async fn send(&self, method: reqwest::Method, path: &str, body: Value) -> (u16, Value) {
        let r = self
            .http
            .request(method, self.url(path))
            .header("X-CSRF-Token", &self.csrf)
            .json(&body)
            .send()
            .await
            .unwrap();
        let s = r.status().as_u16();
        (s, r.json().await.unwrap_or(Value::Null))
    }

    pub async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        self.send(reqwest::Method::POST, path, body).await
    }

    pub async fn cleanup(self) {
        self.running.handle.shutdown();
        self.running.grpc.abort();
        self.state.db.close().await;
        if let Ok(admin) = sqlx::PgPool::connect(&self.admin_url).await {
            let _ = sqlx::query(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
        if let Some(ch) = &self.state.cfg.clickhouse {
            let _ = reqwest::Client::builder()
                .no_proxy()
                .build()
                .unwrap()
                .post(format!("{}/", ch.url))
                .body(format!("DROP DATABASE IF EXISTS {}", ch.database))
                .send()
                .await;
        }
    }
}

// ---------------------------------------------------------------- agent test client

pub struct TestAgent {
    pub device_id: Uuid,
    pub cert_pem: String,
    pub key_pem: String,
    pub ca_pem: String,
}

pub fn csr() -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "pending");
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    (csr, key.serialize_pem())
}

pub async fn channel(
    port: u16,
    ca_pem: &str,
    identity: Option<(&str, &str)>,
) -> Result<Channel, tonic::transport::Error> {
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name("localhost");
    if let Some((c, k)) = identity {
        tls = tls.identity(Identity::from_pem(c, k));
    }
    Endpoint::from_shared(format!("https://127.0.0.1:{port}"))?
        .tls_config(tls)?
        .connect()
        .await
}

pub fn os() -> OsInfo {
    OsInfo {
        name: "Windows 11 Pro".into(),
        build: "10.0.26100.4652".into(),
        arch: "x86_64".into(),
        domain: Some("ACME".into()),
        hw_uuid: Some(Uuid::new_v4().to_string()),
    }
}

pub async fn enroll(
    port: u16,
    ca_pem: &str,
    token: &str,
    hostname: &str,
) -> Result<TestAgent, tonic::Status> {
    let ch = channel(port, ca_pem, None).await.expect("channel");
    let mut client = AgentServiceClient::new(ch);
    let (csr, key) = csr();
    let req = EnrollRequest {
        token: token.into(),
        csr_pem: csr,
        hostname: hostname.into(),
        os: os(),
    };
    let resp = client
        .enroll(EnrollEnvelope {
            json: serde_json::to_vec(&req).unwrap(),
        })
        .await?;
    let er: EnrollResponse = serde_json::from_slice(&resp.into_inner().json).unwrap();
    Ok(TestAgent {
        device_id: er.device_id,
        cert_pem: er.cert_pem,
        key_pem: key,
        ca_pem: er.ca_pem,
    })
}

pub struct AgentStream {
    pub tx: mpsc::Sender<AgentEnvelope>,
    pub rx: tonic::Streaming<ServerEnvelope>,
    pub seq: u64,
}

impl AgentStream {
    /// Send with an explicit seq (to test outbox replays).
    pub async fn send_seq(&mut self, seq: u64, p: &AgentPayload) {
        self.tx
            .send(AgentEnvelope {
                seq,
                compressed: false,
                payload: serde_json::to_vec(p).unwrap(),
            })
            .await
            .unwrap();
    }

    /// Acknowledge a server message (agent Acks use seq 0).
    pub async fn ack(&mut self, server_seq: u64) {
        self.send_seq(0, &AgentPayload::Ack { seq: server_seq })
            .await;
    }

    pub async fn send(&mut self, p: &AgentPayload) -> u64 {
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

    /// Next server message (decoded) with its seq.
    pub async fn recv(&mut self) -> Option<(u64, ServerPayload)> {
        let env = tokio::time::timeout(Duration::from_secs(15), self.rx.message())
            .await
            .expect("timed out waiting for server")
            .ok()??;
        let raw = kestrel_server::grpc::decode_payload(env.compressed, &env.payload).unwrap();
        Some((env.seq, serde_json::from_slice(&raw).unwrap()))
    }

    /// Receive until `pred` matches (other messages are collected and returned too).
    pub async fn recv_until(
        &mut self,
        mut pred: impl FnMut(&ServerPayload) -> bool,
    ) -> (u64, ServerPayload, Vec<ServerPayload>) {
        let mut others = vec![];
        loop {
            let (seq, p) = self.recv().await.expect("stream closed");
            if pred(&p) {
                return (seq, p, others);
            }
            others.push(p);
        }
    }

    pub async fn wait_ack(&mut self, seq: u64) -> Vec<ServerPayload> {
        let (_, _, others) = self
            .recv_until(|p| matches!(p, ServerPayload::Ack { seq: s } if *s == seq))
            .await;
        others
    }
}

pub async fn connect(
    port: u16,
    agent: &TestAgent,
    hello: Hello,
) -> Result<AgentStream, tonic::Status> {
    let ch = channel(port, &agent.ca_pem, Some((&agent.cert_pem, &agent.key_pem)))
        .await
        .map_err(|e| tonic::Status::unavailable(e.to_string()))?;
    let mut client = AgentServiceClient::new(ch);
    let (tx, rx) = mpsc::channel::<AgentEnvelope>(64);
    // Hello (like the agent's own Acks) travels with seq 0.
    tx.send(AgentEnvelope {
        seq: 0,
        compressed: false,
        payload: serde_json::to_vec(&AgentPayload::Hello(hello)).unwrap(),
    })
    .await
    .unwrap();
    let resp = client
        .connect(tokio_stream::wrappers::ReceiverStream::new(rx))
        .await?;
    Ok(AgentStream {
        tx,
        rx: resp.into_inner(),
        seq: 0,
    })
}

pub fn hello(agent: &TestAgent, hostname: &str) -> Hello {
    Hello {
        device_id: agent.device_id,
        agent_version: "0.1.0".into(),
        hostname: hostname.into(),
        os: os(),
        boot_id: "boot-1".into(),
        policy_version: 0,
        rules_version: 0,
        outbox_epoch: None,
    }
}

/// Enroll and also return the server-issued uninstall token.
pub async fn enroll_full(
    port: u16,
    ca_pem: &str,
    token: &str,
    hostname: &str,
    os: OsInfo,
) -> Result<(TestAgent, EnrollResponse), tonic::Status> {
    let ch = channel(port, ca_pem, None).await.expect("channel");
    let mut client = AgentServiceClient::new(ch);
    let (csr, key) = csr();
    let req = EnrollRequest {
        token: token.into(),
        csr_pem: csr,
        hostname: hostname.into(),
        os,
    };
    let resp = client
        .enroll(EnrollEnvelope {
            json: serde_json::to_vec(&req).unwrap(),
        })
        .await?;
    let er: EnrollResponse = serde_json::from_slice(&resp.into_inner().json).unwrap();
    Ok((
        TestAgent {
            device_id: er.device_id,
            cert_pem: er.cert_pem.clone(),
            key_pem: key,
            ca_pem: er.ca_pem.clone(),
        },
        er,
    ))
}
