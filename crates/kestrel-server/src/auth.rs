//! Console authentication: session cookies + CSRF, bearer API tokens, RBAC,
//! login rate limiting.

use crate::{
    audit::Actor,
    crypto::{ct_eq, random_token, sha256_hex},
    error::{ApiError, ApiResult},
    models::UserRow,
    state::AppState,
};
use axum::{
    async_trait,
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts, HeaderMap, Method},
};
use dashmap::DashMap;
use kestrel_common::now_ms;
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
};
use uuid::Uuid;

pub const SESSION_COOKIE: &str = "kestrel_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const API_TOKEN_PREFIX: &str = "kst_";

#[derive(Clone, Debug)]
pub enum Via {
    Session { token_hash: String, csrf: String },
    Token { id: Uuid, name: String },
}

#[derive(Clone, Debug)]
pub struct Principal {
    pub user: UserRow,
    pub privileges: Vec<String>,
    pub via: Via,
    pub ip: Option<String>,
    /// Password login while `require_mfa` is on and the user has no TOTP yet.
    pub mfa_setup_required: bool,
}

impl Principal {
    pub fn has(&self, p: &str) -> bool {
        self.privileges.iter().any(|x| x == "*" || x == p)
    }

    pub fn require(&self, p: &str) -> ApiResult<()> {
        if self.has(p) {
            Ok(())
        } else if self.mfa_setup_required {
            Err(
                ApiError::forbidden("multi-factor authentication must be set up first")
                    .with_extra(serde_json::json!({"mfa_setup_required": true})),
            )
        } else {
            Err(ApiError::forbidden(format!("missing privilege '{p}'")))
        }
    }

    pub fn actor(&self) -> Actor {
        Actor {
            id: Some(self.user.id),
            email: Some(self.user.email.clone()),
        }
    }

    /// Account self-service (`/me/*` mutations) needs an interactive session:
    /// a leaked API token must not be able to enrol MFA or change the password.
    pub fn require_session(&self) -> ApiResult<()> {
        match self.via {
            Via::Session { .. } => Ok(()),
            Via::Token { .. } => Err(ApiError::forbidden(
                "API tokens cannot manage the account; sign in to the console",
            )),
        }
    }

    pub fn csrf(&self) -> String {
        match &self.via {
            Via::Session { csrf, .. } => csrf.clone(),
            Via::Token { .. } => String::new(),
        }
    }

    /// Effective privileges list for `/me` (expanded `*`).
    pub fn privilege_list(&self) -> Vec<String> {
        if self.privileges.iter().any(|p| p == "*") {
            let mut v = vec!["*".to_string()];
            v.extend(crate::db::ALL_PRIVILEGES.iter().map(|s| s.to_string()));
            v
        } else {
            self.privileges.clone()
        }
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for h in headers.get_all(header::COOKIE) {
        let Ok(s) = h.to_str() else { continue };
        for part in s.split(';') {
            let mut kv = part.trim().splitn(2, '=');
            if kv.next() == Some(name) {
                return kv.next().map(|v| v.to_string());
            }
        }
    }
    None
}

/// Client address for rate limiting and audit. `X-Forwarded-For` is honoured
/// only when the TCP peer is a listed trusted proxy; the right-most entry that is
/// not itself a trusted proxy is used (left-most entries are client-controlled).
pub fn client_ip(state: &AppState, parts: &Parts) -> Option<String> {
    let peer = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    resolve_client_ip(
        &state.cfg.trusted_proxies,
        peer,
        parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok()),
    )
    .map(|ip| ip.to_string())
}

pub fn resolve_client_ip<'a>(
    trusted: &[ipnet::IpNet],
    peer: Option<IpAddr>,
    xff: impl Iterator<Item = &'a str>,
) -> Option<IpAddr> {
    let peer = peer?;
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|n| n.contains(ip));
    if !is_trusted(&peer) {
        return Some(peer);
    }
    let hops: Vec<&str> = xff.flat_map(|h| h.split(',')).map(str::trim).collect();
    for hop in hops.iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) if is_trusted(&ip) => continue,
            Ok(ip) => return Some(ip),
            // Garbage in the chain: stop trusting anything to its left.
            Err(_) => return Some(peer),
        }
    }
    Some(peer)
}

pub async fn role_privileges(db: &sqlx::PgPool, role: &str) -> ApiResult<Vec<String>> {
    let r: Option<(Vec<String>,)> = sqlx::query_as("SELECT privileges FROM roles WHERE name = $1")
        .bind(role)
        .fetch_optional(db)
        .await?;
    Ok(r.map(|r| r.0).unwrap_or_default())
}

#[async_trait]
impl FromRequestParts<AppState> for Principal {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        if let Some(p) = parts.extensions.get::<Principal>() {
            return Ok(p.clone());
        }
        let ip = client_ip(state, parts);
        let now = now_ms();
        // Bearer API token.
        if let Some(auth) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let token = auth
                .strip_prefix("Bearer ")
                .or_else(|| auth.strip_prefix("bearer "))
                .ok_or_else(|| ApiError::unauthorized("unsupported authorization scheme"))?
                .trim();
            if !token.starts_with(API_TOKEN_PREFIX) {
                return Err(ApiError::unauthorized("invalid API token"));
            }
            #[allow(clippy::type_complexity)]
            let row: Option<(Uuid, String, Vec<String>, Option<i64>, Option<Uuid>, Option<i64>)> = sqlx::query_as(
                "SELECT id, name, privileges, last_used, created_by, expires_at FROM api_tokens WHERE token_hash = $1",
            )
            .bind(sha256_hex(token))
            .fetch_optional(&state.db)
            .await?;
            let Some((id, name, privs, last_used, Some(creator), expires_at)) = row else {
                return Err(ApiError::unauthorized("invalid API token"));
            };
            if expires_at.map(|e| e <= now).unwrap_or(false) {
                return Err(ApiError::unauthorized("API token expired"));
            }
            let user: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
                .bind(creator)
                .fetch_optional(&state.db)
                .await?
                .ok_or_else(|| ApiError::unauthorized("invalid API token"))?;
            if user.disabled {
                return Err(ApiError::unauthorized("token owner is disabled"));
            }
            // A token never exceeds its owner's current role.
            let role_privs = role_privileges(&state.db, &user.role).await?;
            let owner_all = role_privs.iter().any(|p| p == "*");
            let privileges: Vec<String> = privs
                .into_iter()
                .filter(|p| owner_all || role_privs.contains(p) || (p == "*" && owner_all))
                .collect();
            if last_used.map(|t| now - t > 60_000).unwrap_or(true) {
                let _ = sqlx::query("UPDATE api_tokens SET last_used = $2 WHERE id = $1")
                    .bind(id)
                    .bind(now)
                    .execute(&state.db)
                    .await;
            }
            let p = Principal {
                user,
                privileges,
                via: Via::Token { id, name },
                ip,
                mfa_setup_required: false,
            };
            parts.extensions.insert(p.clone());
            return Ok(p);
        }

        // Session cookie.
        let token = cookie_value(&parts.headers, SESSION_COOKIE)
            .ok_or_else(|| ApiError::unauthorized("not signed in"))?;
        let th = sha256_hex(&token);
        let row: Option<(Uuid, String, String, i64, i64, i64)> = sqlx::query_as(
            "SELECT user_id, csrf_token, auth_method, last_seen, expires_at, created_at FROM sessions WHERE token_hash = $1",
        )
        .bind(&th)
        .fetch_optional(&state.db)
        .await?;
        let Some((user_id, csrf, method, last_seen, expires_at, created_at)) = row else {
            return Err(ApiError::unauthorized("session expired"));
        };
        // Sliding idle timeout (expires_at) plus an absolute lifetime (L5).
        let max_age = crate::settings::load(&state.db).await?.session_max_age_ms();
        if expires_at < now || now - created_at > max_age {
            let _ = sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
                .bind(&th)
                .execute(&state.db)
                .await;
            return Err(ApiError::unauthorized("session expired"));
        }
        let user: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.db)
            .await?
            .ok_or_else(|| ApiError::unauthorized("session expired"))?;
        if user.disabled {
            return Err(ApiError::unauthorized("account disabled"));
        }
        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let sent = parts
                .headers
                .get(CSRF_HEADER)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if sent.is_empty() || !ct_eq(sent, &csrf) {
                return Err(ApiError::forbidden("missing or invalid CSRF token"));
            }
        }
        if now - last_seen > 60_000 {
            let s = crate::settings::load(&state.db).await?;
            let ttl = s.session_timeout_minutes.max(5) as i64 * 60_000;
            let _ = sqlx::query(
                "UPDATE sessions SET last_seen = $2, expires_at = $3 WHERE token_hash = $1",
            )
            .bind(&th)
            .bind(now)
            .bind((now + ttl).min(created_at + s.session_max_age_ms()))
            .execute(&state.db)
            .await;
        }
        let mfa_setup_required = method == "password_mfa_setup" && !user.mfa_enabled;
        let privileges = if mfa_setup_required {
            vec![]
        } else {
            role_privileges(&state.db, &user.role).await?
        };
        let p = Principal {
            user,
            privileges,
            via: Via::Session {
                token_hash: th,
                csrf,
            },
            ip,
            mfa_setup_required,
        };
        parts.extensions.insert(p.clone());
        Ok(p)
    }
}

/// Re-check a session (SSE re-validation, L5): still present, inside both
/// lifetimes, user enabled and still holding `privilege`.
pub async fn session_still_valid(
    state: &AppState,
    token_hash: &str,
    privilege: &str,
) -> anyhow::Result<bool> {
    let now = now_ms();
    let row: Option<(i64, i64, String, bool, String, bool)> = sqlx::query_as(
        "SELECT s.expires_at, s.created_at, s.auth_method, u.disabled, u.role, u.mfa_enabled \
         FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(&state.db)
    .await?;
    let Some((expires_at, created_at, method, disabled, role, mfa_enabled)) = row else {
        return Ok(false);
    };
    let max_age = crate::settings::load(&state.db).await?.session_max_age_ms();
    if disabled || expires_at < now || now - created_at > max_age {
        return Ok(false);
    }
    if method == "password_mfa_setup" && !mfa_enabled {
        return Ok(false);
    }
    let privs = role_privileges(&state.db, &role)
        .await
        .map_err(|e| anyhow::anyhow!(e.message))?;
    Ok(privs.iter().any(|p| p == "*" || p == privilege))
}

/// Create a session row; returns (cookie token, csrf token, max_age_secs).
pub async fn create_session(
    state: &AppState,
    user_id: Uuid,
    method: &str,
    ip: Option<String>,
    user_agent: Option<String>,
) -> ApiResult<(String, String, i64)> {
    let s = crate::settings::load(&state.db).await?;
    let ttl_min = s.session_timeout_minutes.max(5) as i64;
    let token = random_token(32);
    let csrf = random_token(24);
    let now = now_ms();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, auth_method, ip, user_agent, created_at, last_seen, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$7,$8)",
    )
    .bind(sha256_hex(&token))
    .bind(user_id)
    .bind(&csrf)
    .bind(method)
    .bind(ip)
    .bind(user_agent.map(|u| u.chars().take(256).collect::<String>()))
    .bind(now)
    .bind(now + (ttl_min * 60_000).min(s.session_max_age_ms()))
    .execute(&state.db)
    .await?;
    sqlx::query("UPDATE users SET last_login = $2 WHERE id = $1")
        .bind(user_id)
        .bind(now)
        .execute(&state.db)
        .await?;
    Ok((token, csrf, ttl_min * 60))
}

pub fn session_cookie(token: &str, max_age: i64) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}"
    )
}

pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0")
}

/// Per-key exponential backoff for failed logins (M4). Nothing is ever locked
/// for longer than `cap`; only *failed* password checks count, and a correct
/// login clears the key. Entries are forgotten after an hour without failures.
#[derive(Default)]
pub struct LoginThrottle {
    fails: DashMap<String, (u32, i64)>,
}

#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    /// Failures allowed before any delay applies.
    pub free: u32,
    pub base_ms: i64,
    pub cap_ms: i64,
}

/// Same account from the same address: 5 free attempts, then 1 s, 2 s, … ≤ 15 min.
pub const BACKOFF_EMAIL_IP: Backoff = Backoff {
    free: 5,
    base_ms: 1_000,
    cap_ms: 15 * 60_000,
};
/// Same account from anywhere (distributed guessing): delay capped at 60 s so a
/// remote attacker cannot keep the real user out for long.
pub const BACKOFF_EMAIL: Backoff = Backoff {
    free: 20,
    base_ms: 1_000,
    cap_ms: 60_000,
};
/// One address across accounts (spraying).
pub const BACKOFF_IP: Backoff = Backoff {
    free: 20,
    base_ms: 1_000,
    cap_ms: 5 * 60_000,
};
const THROTTLE_FORGET_MS: i64 = 3_600_000;

impl LoginThrottle {
    /// Milliseconds the caller must still wait, if any.
    pub fn wait_ms(&self, key: &str, b: Backoff, now: i64) -> Option<i64> {
        let (n, last) = *self.fails.get(key)?;
        if now - last > THROTTLE_FORGET_MS || n < b.free {
            return None;
        }
        let exp = (n - b.free).min(30);
        let delay = b.base_ms.saturating_mul(1i64 << exp).min(b.cap_ms);
        let left = delay - (now - last);
        (left > 0).then_some(left)
    }

    pub fn fail(&self, key: &str, now: i64) {
        let mut e = self.fails.entry(key.to_string()).or_insert((0, now));
        if now - e.1 > THROTTLE_FORGET_MS {
            e.0 = 0;
        }
        e.0 = e.0.saturating_add(1);
        e.1 = now;
    }

    pub fn clear(&self, key: &str) {
        self.fails.remove(key);
    }

    pub fn prune(&self, now: i64) {
        self.fails
            .retain(|_, (_, last)| now - *last <= THROTTLE_FORGET_MS);
        if self.fails.len() > 200_000 {
            self.fails.clear();
        }
    }
}

/// Sliding-window rate limiter keyed by string.
#[derive(Default)]
pub struct RateLimiter {
    hits: DashMap<String, VecDeque<i64>>,
}

/// Unauthenticated OIDC starts / setup attempts per address.
pub const OIDC_START_PER_MIN: usize = 30;
pub const SETUP_PER_10_MIN: usize = 10;

impl RateLimiter {
    pub fn count(&self, key: &str, window_ms: i64) -> usize {
        let now = now_ms();
        match self.hits.get_mut(key) {
            Some(mut q) => {
                while q.front().map(|t| now - *t > window_ms).unwrap_or(false) {
                    q.pop_front();
                }
                q.len()
            }
            None => 0,
        }
    }

    pub fn record(&self, key: &str) {
        let mut q = self.hits.entry(key.to_string()).or_default();
        q.push_back(now_ms());
        while q.len() > 1000 {
            q.pop_front();
        }
    }

    pub fn clear(&self, key: &str) {
        self.hits.remove(key);
    }

    /// Drop stale keys (called by the housekeeping job).
    pub fn prune(&self, window_ms: i64) {
        let now = now_ms();
        self.hits
            .retain(|_, q| q.back().map(|t| now - *t <= window_ms).unwrap_or(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xff_only_from_trusted_proxies() {
        let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer_proxy: IpAddr = "10.0.0.5".parse().unwrap();
        let peer_direct: IpAddr = "198.51.100.9".parse().unwrap();
        // Not from a trusted proxy: header ignored.
        assert_eq!(
            resolve_client_ip(&trusted, Some(peer_direct), ["1.2.3.4"].into_iter()),
            Some(peer_direct)
        );
        // From the proxy: right-most untrusted hop, spoofed left-most entries ignored.
        assert_eq!(
            resolve_client_ip(
                &trusted,
                Some(peer_proxy),
                ["6.6.6.6, 203.0.113.7, 10.0.0.2"].into_iter()
            ),
            Some("203.0.113.7".parse().unwrap())
        );
        // No trusted proxies configured: never honoured.
        assert_eq!(
            resolve_client_ip(&[], Some(peer_proxy), ["1.2.3.4"].into_iter()),
            Some(peer_proxy)
        );
        // Garbage hop: fall back to the peer.
        assert_eq!(
            resolve_client_ip(&trusted, Some(peer_proxy), ["1.2.3.4, nope"].into_iter()),
            Some(peer_proxy)
        );
    }

    #[test]
    fn backoff_grows_and_caps() {
        let t = LoginThrottle::default();
        let b = BACKOFF_EMAIL_IP;
        for _ in 0..5 {
            t.fail("k", 1_000);
        }
        // 5 failures: first delay 1 s.
        assert_eq!(t.wait_ms("k", b, 1_000), Some(1_000));
        assert_eq!(t.wait_ms("k", b, 2_000), None);
        for _ in 0..3 {
            t.fail("k", 10_000);
        }
        assert_eq!(t.wait_ms("k", b, 10_000), Some(8_000));
        for _ in 0..40 {
            t.fail("k", 20_000);
        }
        assert_eq!(t.wait_ms("k", b, 20_000), Some(b.cap_ms));
        assert_eq!(t.wait_ms("k", BACKOFF_EMAIL, 20_000), Some(60_000));
        t.clear("k");
        assert_eq!(t.wait_ms("k", b, 20_000), None);
        // Forgotten after an hour of quiet.
        t.fail("q", 0);
        for _ in 0..10 {
            t.fail("q", 0);
        }
        assert!(t.wait_ms("q", b, 3_600_001).is_none());
    }
}
