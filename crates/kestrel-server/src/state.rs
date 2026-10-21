//! Shared application state.

use crate::{
    auth::{LoginThrottle, RateLimiter},
    config::Config,
    crypto::MasterKey,
    notify::Notifier,
    pki::AgentCa,
    registry::AgentRegistry,
    telemetry::EventStore,
};
use dashmap::DashMap;
use serde::Serialize;
use sqlx::PgPool;
use std::{ops::Deref, sync::Arc};
use tokio::sync::broadcast;

/// SSE notification: `event: <entity>` with `{id, type}`.
#[derive(Clone, Debug, Serialize)]
pub struct LiveEvent {
    #[serde(skip)]
    pub entity: &'static str,
    pub id: String,
    #[serde(rename = "type")]
    pub kind: &'static str,
}

/// Cached OIDC discovery document (L4).
pub struct OidcDiscovery {
    pub issuer: String,
    pub fetched_at: i64,
    pub meta: openidconnect::core::CoreProviderMetadata,
}

pub struct OidcPending {
    pub nonce: String,
    pub pkce_verifier: String,
    pub created: i64,
}

pub struct Inner {
    pub cfg: Config,
    pub db: PgPool,
    pub mk: MasterKey,
    pub ca: AgentCa,
    pub agents: AgentRegistry,
    pub events: Arc<dyn EventStore>,
    pub live: broadcast::Sender<LiveEvent>,
    pub notifier: Notifier,
    /// Sliding-window limits (setup attempts, OIDC starts).
    pub login_limiter: RateLimiter,
    /// Failed-login exponential backoff.
    pub login_throttle: LoginThrottle,
    pub oidc_pending: DashMap<String, OidcPending>,
    pub oidc_discovery: tokio::sync::Mutex<Option<OidcDiscovery>>,
    /// One-time first-run setup code (L3): from `KESTREL_SETUP_CODE` or generated
    /// at startup and printed to the log. Only accepted while no user exists.
    pub setup_code: String,
    /// Outbound HTTP guard (webhooks, chat, OIDC).
    pub outbound: crate::netguard::Policy,
    /// Remote-access live sessions (remote desktop, file manager).
    pub remote: crate::remote::Hub,
}

#[derive(Clone)]
pub struct AppState(pub Arc<Inner>);

impl Deref for AppState {
    type Target = Inner;
    fn deref(&self) -> &Inner {
        &self.0
    }
}

impl AppState {
    pub fn publish(&self, entity: &'static str, id: impl ToString, kind: &'static str) {
        let _ = self.live.send(LiveEvent {
            entity,
            id: id.to_string(),
            kind,
        });
    }
}
