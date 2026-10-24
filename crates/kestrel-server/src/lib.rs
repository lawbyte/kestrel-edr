//! Kestrel EDR self-hosted server.
//!
//! * HTTPS (axum + rustls) on :443 — REST API under `/api`, console static bundle, `/downloads`.
//! * Agent gRPC (tonic, mTLS with `client_auth_optional`) on :8443.
//! * PostgreSQL control plane; ClickHouse (or Postgres fallback) telemetry.

pub mod api;
pub mod audit;
pub mod auth;
pub mod autorun_policy;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod evidence;
pub mod grpc;
pub mod incidents;
pub mod ingest;
pub mod installer_script;
pub mod jobs;
pub mod mdsafe;
pub mod models;
pub mod netguard;
pub mod notify;
pub mod pki;
pub mod policy_svc;
pub mod registry;
pub mod remote;
pub mod removal;
pub mod scrub;
pub mod settings;
pub mod sigmapack;
pub mod state;
pub mod telemetry;
pub mod updates;

use crate::{
    auth::{LoginThrottle, RateLimiter},
    config::Config,
    crypto::MasterKey,
    grpc::{pb::agent_service_server::AgentServiceServer, AgentSvc},
    notify::Notifier,
    pki::AgentCa,
    registry::AgentRegistry,
    state::{AppState, Inner},
    telemetry::{clickhouse::ClickHouseStore, postgres::PgEventStore, EventStore},
};
use axum::{
    http::{header, HeaderValue, StatusCode},
    response::{Html, IntoResponse},
    Router,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{sync::broadcast, task::JoinHandle};
use tower_http::{
    limit::RequestBodyLimitLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Connect to databases, run migrations, load the CA and build shared state.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    install_crypto_provider();
    let db = db::connect(&cfg.database_url).await?;
    db::migrate_and_seed(&db).await?;
    sigmapack::seed(&db).await?;
    let mk = MasterKey::new(&cfg.master_key);
    let s = settings::load(&db).await?;
    // Fail fast on a wrong master key rather than at first use.
    settings::load_secrets(&db, &mk)
        .await
        .map_err(|e| anyhow::anyhow!("cannot decrypt stored secrets: {e}"))?;
    let ca = AgentCa::load_or_create(&db, &mk, &s.org_name).await?;
    audit::set_key(&mk);
    audit::upgrade_legacy(&db).await?;
    let setup_code = setup_code(&db, &cfg).await?;
    let events: Arc<dyn EventStore> = match &cfg.clickhouse {
        Some(ch) => {
            let store = ClickHouseStore::new(ch.clone())?;
            store.init(s.retention_days.events).await?;
            tracing::info!(url = %ch.url, "telemetry store: ClickHouse");
            Arc::new(store)
        }
        None => {
            tracing::info!(
                "telemetry store: PostgreSQL fallback (CLICKHOUSE_URL unset, 7-day retention)"
            );
            Arc::new(PgEventStore::new(db.clone()))
        }
    };
    // Evidence store: restrictive permissions, leftovers of a previous run
    // (unfinished uploads, unused download archives) removed. A missing or
    // unwritable directory only disables collection (logged), never startup.
    evidence::init(&cfg);
    let (live, _) = broadcast::channel(4096);
    let outbound = netguard::Policy::new(&cfg.outbound_allow);
    let notifier = Notifier::start(
        db.clone(),
        mk.clone(),
        cfg.public_base_url(),
        outbound.clone(),
    );
    Ok(AppState(Arc::new(Inner {
        cfg,
        db,
        mk,
        ca,
        agents: AgentRegistry::default(),
        events,
        live,
        notifier,
        login_limiter: RateLimiter::default(),
        login_throttle: LoginThrottle::default(),
        oidc_pending: Default::default(),
        oidc_discovery: Default::default(),
        setup_code,
        outbound,
        remote: remote::Hub::default(),
        evidence: evidence::Hub::default(),
    })))
}

/// First-run setup code: `KESTREL_SETUP_CODE`, or a random one printed to the log
/// while no user exists (whoever reaches the console first must also read the log).
async fn setup_code(db: &sqlx::PgPool, cfg: &Config) -> anyhow::Result<String> {
    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(db)
        .await?;
    let code = match &cfg.setup_code {
        Some(c) => c.trim().to_string(),
        None => {
            let raw = crypto::random_token(9).replace(['-', '_'], "x");
            format!("{}-{}-{}", &raw[0..4], &raw[4..8], &raw[8..12]).to_uppercase()
        }
    };
    if users == 0 {
        if cfg.setup_code.is_some() {
            tracing::warn!("first-run setup pending: use the setup code from KESTREL_SETUP_CODE");
        } else {
            tracing::warn!(setup_code = %code, "first-run setup pending: enter this one-time setup code in the console (KESTREL SETUP CODE: {code})");
        }
    }
    Ok(code)
}

const PLACEHOLDER: &str = "<!doctype html><html><head><meta charset=utf-8><title>Kestrel EDR</title></head>\
<body style=\"font-family:system-ui;margin:3rem\"><h1>Kestrel EDR server is running</h1>\
<p>The web console bundle is not installed (<code>CONSOLE_DIR</code>). The REST API is available under <code>/api</code>.</p></body></html>";

/// HTTP router: `/api`, `/downloads`, console SPA.
pub fn http_router(state: AppState) -> Router {
    let console = state.cfg.console_dir.clone();
    let index = console.join("index.html");
    let no_store = SetResponseHeaderLayer::overriding(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    // The remote file-manager upload streams up to 4 GiB, so it is merged in
    // after the 8 MiB body limit (which only wraps the routes added before it).
    let api = api::router()
        .layer(no_store.clone())
        .layer(RequestBodyLimitLayer::new(8 * 1024 * 1024))
        .merge(api::upload_router().layer(no_store));
    let mut app = Router::new()
        .nest("/api", api)
        .nest_service("/downloads", ServeDir::new(&state.cfg.agent_dir));
    if index.exists() {
        app = app.fallback_service(ServeDir::new(&console).fallback(ServeFile::new(index)));
    } else {
        app = app.fallback(|| async { (StatusCode::OK, Html(PLACEHOLDER)).into_response() });
    }
    app.layer(SetResponseHeaderLayer::if_not_present(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    ))
    .layer(SetResponseHeaderLayer::if_not_present(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
    .layer(SetResponseHeaderLayer::if_not_present(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")))
    .layer(SetResponseHeaderLayer::if_not_present(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
    .layer(SetResponseHeaderLayer::if_not_present(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000"),
    ))
    .with_state(state)
}

fn load_pem_pair(
    cert_pem: &[u8],
    key_pem: &[u8],
) -> anyhow::Result<(
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let certs = rustls_pemfile::certs(&mut &cert_pem[..]).collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &key_pem[..])?
        .ok_or_else(|| anyhow::anyhow!("no private key in PEM"))?;
    Ok((certs, key))
}

/// Web TLS: operator certificate (`TLS_CERT`/`TLS_KEY`) or a persisted self-signed one.
pub async fn web_tls_config(state: &AppState) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let (cert, key) = match (&state.cfg.tls_cert, &state.cfg.tls_key) {
        (Some(c), Some(k)) => (tokio::fs::read(c).await?, tokio::fs::read(k).await?),
        _ => {
            let id = pki::web_identity(&state.db, &state.mk, &state.cfg.public_hostnames).await?;
            (id.cert_pem.into_bytes(), id.key_pem.into_bytes())
        }
    };
    let (certs, key) = load_pem_pair(&cert, &key)?;
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

pub struct Running {
    pub https_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    pub https: JoinHandle<std::io::Result<()>>,
    pub grpc: JoinHandle<Result<(), tonic::transport::Error>>,
    pub handle: axum_server::Handle,
}

/// Start the HTTPS and gRPC servers on the given listeners.
pub async fn serve(
    state: AppState,
    https: std::net::TcpListener,
    grpc: tokio::net::TcpListener,
) -> anyhow::Result<Running> {
    let https_addr = https.local_addr()?;
    let grpc_addr = grpc.local_addr()?;
    https.set_nonblocking(true)?;
    let tls = web_tls_config(&state).await?;
    let handle = axum_server::Handle::new();
    let app = http_router(state.clone());
    let h = handle.clone();
    let https_task = tokio::spawn(async move {
        axum_server::from_tcp_rustls(
            https,
            axum_server::tls_rustls::RustlsConfig::from_config(tls),
        )
        .handle(h)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
    });

    let ident = state.ca.server_identity(&state.cfg.public_hostnames)?;
    let tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(
            ident.cert_pem,
            ident.key_pem,
        ))
        .client_ca_root(tonic::transport::Certificate::from_pem(
            state.ca.cert_pem.clone(),
        ))
        .client_auth_optional(true);
    let svc = AgentServiceServer::new(AgentSvc {
        state: state.clone(),
    })
    .max_decoding_message_size(grpc::MAX_PAYLOAD + 1024 * 1024)
    .max_encoding_message_size(grpc::MAX_PAYLOAD)
    // Transport compression (2026-10-25): responses are zstd-compressed
    // only when the agent advertises it (`grpc-accept-encoding`, agents
    // 1.1.7+); older agents keep plain frames. Compressed *requests* are
    // refused (tonic answers Unimplemented): tonic 0.12 inflates them with
    // no bound on the decompressed size, before any handler runs, and
    // `Enroll` needs no client certificate, so accepting them would let
    // anyone exhaust the server's memory with a small frame (review
    // 2026-10-25 H1). Agent payloads are zstd-compressed inside the
    // envelope instead (`compressed`, bounded by `MAX_PAYLOAD`).
    .send_compressed(tonic::codec::CompressionEncoding::Zstd);
    // Signed update packages placed in `<AGENT_DIR>/updates/` are also served
    // on the agent port (`GET /downloads/updates/<file>`, HTTP/2): agents pin
    // the agent CA, which only this listener presents. Read-only, no
    // directory listing, path-safe (tower-http ServeDir).
    let packages = Router::new().nest_service(
        updates::PACKAGE_PATH.trim_end_matches('/'),
        ServeDir::new(state.cfg.agent_dir.join("updates")),
    );
    let routes = tonic::service::Routes::from(packages).add_service(svc);
    let router = tonic::transport::Server::builder()
        .tls_config(tls)?
        .http2_keepalive_interval(Some(Duration::from_secs(30)))
        .http2_keepalive_timeout(Some(Duration::from_secs(20)))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .add_routes(routes);
    let grpc_task = tokio::spawn(async move {
        router
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(grpc))
            .await
    });
    if state.cfg.run_jobs {
        jobs::spawn(state.clone());
    }
    Ok(Running {
        https_addr,
        grpc_addr,
        https: https_task,
        grpc: grpc_task,
        handle,
    })
}

/// Entry point used by `main`.
pub async fn run(cfg: Config) -> anyhow::Result<()> {
    let https = std::net::TcpListener::bind(cfg.https_addr)?;
    let grpc = tokio::net::TcpListener::bind(cfg.grpc_addr).await?;
    let state = build_state(cfg).await?;
    let r = serve(state.clone(), https, grpc).await?;
    tracing::info!(https = %r.https_addr, grpc = %r.grpc_addr, agent_ca_sha256 = %state.ca.ca_sha256(), "Kestrel server listening");
    tokio::select! {
        res = r.https => { res??; }
        res = r.grpc => { res??; }
        _ = shutdown_signal() => {
            tracing::info!("shutting down");
            r.handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}
