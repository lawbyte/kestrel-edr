//! OIDC login (authorization code + PKCE).
//!
//! * Accounts are bound by `(issuer, subject)` only (H5). A first SSO login never
//!   attaches to an existing account by email: it creates a new SSO-only user, or
//!   is refused when a local account already uses that email (an administrator
//!   links the identity explicitly with `PATCH /users/:id {oidc_subject}`).
//! * `email_verified` must be explicitly true, and the email domain must be on the
//!   allow-list; an empty allow-list denies everyone (H6).
//! * Discovery is cached, pending logins are capped and `/start` is rate-limited
//!   per client address (L4). Outbound requests go through the SSRF guard (L7).

use super::ApiQuery;
use crate::{
    audit::{self, Actor},
    auth::{client_ip, create_session, session_cookie, OIDC_START_PER_MIN},
    error::{ApiError, ApiResult},
    settings,
    state::{AppState, OidcDiscovery, OidcPending},
};
use axum::{
    extract::{Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use kestrel_common::now_ms;
use openidconnect::{
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

const STATE_COOKIE: &str = "kestrel_oidc_state";
const PENDING_TTL_MS: i64 = 10 * 60_000;
/// Upper bound on concurrent unfinished logins (memory DoS guard).
pub const MAX_PENDING: usize = 10_000;
const DISCOVERY_TTL_MS: i64 = 3_600_000;

fn http_client(st: &AppState) -> reqwest::Client {
    crate::netguard::client(&st.outbound, std::time::Duration::from_secs(15))
}

/// Provider metadata, cached for an hour per issuer.
async fn discover(st: &AppState, issuer_url: &str) -> ApiResult<CoreProviderMetadata> {
    let mut cache = st.oidc_discovery.lock().await;
    let now = now_ms();
    if let Some(c) = cache.as_ref() {
        if c.issuer == issuer_url && now - c.fetched_at < DISCOVERY_TTL_MS {
            return Ok(c.meta.clone());
        }
    }
    st.outbound
        .check_url(issuer_url)
        .map_err(|e| ApiError::bad_request(format!("OIDC issuer not allowed: {e}")))?;
    let issuer = IssuerUrl::new(issuer_url.to_string())
        .map_err(|_| ApiError::bad_request("invalid OIDC issuer URL"))?;
    let meta = CoreProviderMetadata::discover_async(issuer, &http_client(st))
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "OIDC discovery failed");
            ApiError::internal("OIDC discovery failed")
        })?;
    *cache = Some(OidcDiscovery {
        issuer: issuer_url.to_string(),
        fetched_at: now,
        meta: meta.clone(),
    });
    Ok(meta)
}

fn redirect(to: &str, extra_cookie: Option<String>) -> Response {
    let mut h = HeaderMap::new();
    if let Ok(v) = to.parse() {
        h.insert(header::LOCATION, v);
    }
    if let Some(c) = extra_cookie.and_then(|c| c.parse().ok()) {
        h.append(header::SET_COOKIE, c);
    }
    (StatusCode::FOUND, h).into_response()
}

fn login_error(msg: &str) -> Response {
    let enc: String = msg
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    redirect(&format!("/login?error={enc}"), None)
}

async fn oidc_config(st: &AppState) -> ApiResult<(settings::Oidc, String)> {
    let s = settings::load(&st.db).await?;
    if !s.oidc.enabled || s.oidc.issuer.is_empty() || s.oidc.client_id.is_empty() {
        return Err(ApiError::not_found("single sign-on is not configured"));
    }
    let secrets = settings::load_secrets(&st.db, &st.mk).await?;
    Ok((s.oidc, secrets.oidc_client_secret))
}

pub async fn start(State(st): State<AppState>, req: Request) -> ApiResult<Response> {
    let (parts, _) = req.into_parts();
    let ip = client_ip(&st, &parts).unwrap_or_default();
    let key = format!("oidc:{ip}");
    if st.login_limiter.count(&key, 60_000) >= OIDC_START_PER_MIN {
        return Err(ApiError::rate_limited(
            "too many sign-in attempts, try again later",
        ));
    }
    st.login_limiter.record(&key);
    let (cfg, secret) = oidc_config(&st).await?;
    let meta = discover(&st, &cfg.issuer).await?;
    let redirect_uri = format!("{}/api/auth/oidc/callback", st.cfg.public_base_url());
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(cfg.client_id.clone()),
        if secret.is_empty() {
            None
        } else {
            Some(ClientSecret::new(secret))
        },
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_uri).map_err(|_| ApiError::internal("bad redirect URI"))?,
    );
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".into()))
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(challenge)
        .url();
    let now = now_ms();
    st.oidc_pending
        .retain(|_, p| now - p.created < PENDING_TTL_MS);
    if st.oidc_pending.len() >= MAX_PENDING {
        tracing::warn!("too many pending OIDC logins; refusing new ones");
        return Err(ApiError::rate_limited(
            "too many sign-ins in progress, try again shortly",
        ));
    }
    st.oidc_pending.insert(
        csrf.secret().clone(),
        OidcPending {
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
            created: now,
        },
    );
    // Binds the flow to this browser (Lax: sent on the IdP's top-level redirect back).
    let cookie = format!(
        "{STATE_COOKIE}={}; Path=/api/auth/oidc; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
        csrf.secret()
    );
    Ok(redirect(url.as_str(), Some(cookie)))
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn callback(
    State(st): State<AppState>,
    ApiQuery(q): ApiQuery<CallbackQuery>,
    req: Request,
) -> Response {
    match callback_inner(&st, q, req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e.message, "OIDC login failed");
            login_error(&e.message)
        }
    }
}

async fn callback_inner(st: &AppState, q: CallbackQuery, req: Request) -> ApiResult<Response> {
    if let Some(e) = q.error {
        return Err(ApiError::unauthorized(format!(
            "identity provider error: {}",
            e.chars().take(100).collect::<String>()
        )));
    }
    let (parts, _) = req.into_parts();
    let ip = client_ip(st, &parts);
    let ua = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let state_param = q
        .state
        .ok_or_else(|| ApiError::bad_request("missing state"))?;
    let cookie_state = crate::auth::cookie_value(&parts.headers, STATE_COOKIE).unwrap_or_default();
    if !crate::crypto::ct_eq(&cookie_state, &state_param) {
        return Err(ApiError::unauthorized(
            "login session mismatch, please retry",
        ));
    }
    let (_, pending) = st
        .oidc_pending
        .remove(&state_param)
        .ok_or_else(|| ApiError::unauthorized("login expired, please retry"))?;
    if now_ms() - pending.created > PENDING_TTL_MS {
        return Err(ApiError::unauthorized("login expired, please retry"));
    }
    let code = q
        .code
        .ok_or_else(|| ApiError::bad_request("missing code"))?;
    let (cfg, secret) = oidc_config(st).await?;
    let http = http_client(st);
    let meta = discover(st, &cfg.issuer).await?;
    let redirect_uri = format!("{}/api/auth/oidc/callback", st.cfg.public_base_url());
    let client = CoreClient::from_provider_metadata(
        meta,
        ClientId::new(cfg.client_id.clone()),
        if secret.is_empty() {
            None
        } else {
            Some(ClientSecret::new(secret))
        },
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_uri).map_err(|_| ApiError::internal("bad redirect URI"))?,
    );
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| ApiError::internal("provider has no token endpoint"))?
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&http)
        .await
        .map_err(|e| ApiError::unauthorized(format!("token exchange failed: {e}")))?;
    let id_token = token
        .id_token()
        .ok_or_else(|| ApiError::unauthorized("provider returned no ID token"))?;
    let verifier = client.id_token_verifier();
    let claims = id_token
        .claims(&verifier, &Nonce::new(pending.nonce))
        .map_err(|e| ApiError::unauthorized(format!("invalid ID token: {e}")))?;
    let email = claims
        .email()
        .map(|e| e.as_str().to_ascii_lowercase())
        .ok_or_else(|| ApiError::unauthorized("ID token has no email claim"))?;
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.as_str().to_string())
        .unwrap_or_default();
    let user_id = resolve_user(
        st,
        &cfg,
        &email,
        claims.email_verified(),
        claims.subject().as_str(),
        &name,
        ip.clone(),
    )
    .await?;
    let (tok, _csrf, max_age) = create_session(st, user_id, "oidc", ip.clone(), ua).await?;
    audit::log(
        &st.db,
        &Actor {
            id: Some(user_id),
            email: Some(email),
        },
        "auth.login",
        user_id.to_string(),
        json!({"ip": ip, "method": "oidc"}),
    )
    .await;
    let mut h = HeaderMap::new();
    h.insert(header::LOCATION, "/".parse().unwrap());
    if let Ok(v) = session_cookie(&tok, max_age).parse() {
        h.append(header::SET_COOKIE, v);
    }
    if let Ok(v) =
        format!("{STATE_COOKIE}=; Path=/api/auth/oidc; HttpOnly; Secure; SameSite=Lax; Max-Age=0")
            .parse()
    {
        h.append(header::SET_COOKIE, v);
    }
    Ok((StatusCode::FOUND, h).into_response())
}

/// Stored account binding: `<issuer>|<sub>`.
pub fn oidc_subject_key(issuer: &str, sub: &str) -> String {
    format!("{issuer}|{sub}")
}

/// Map a verified ID token to a Kestrel user (H5/H6). Binding is by
/// `(issuer, subject)` only; a first login creates a new SSO-only user with the
/// configured default role, and is refused when a local account already has the
/// email (an administrator must link it explicitly).
pub async fn resolve_user(
    st: &AppState,
    cfg: &settings::Oidc,
    email: &str,
    email_verified: Option<bool>,
    subject: &str,
    name: &str,
    ip: Option<String>,
) -> ApiResult<Uuid> {
    let email = email.trim().to_ascii_lowercase();
    let deny = |reason: &'static str| {
        let email = email.clone();
        let ip = ip.clone();
        async move {
            audit::log(
                &st.db,
                &Actor {
                    id: None,
                    email: Some(email.clone()),
                },
                "auth.oidc_denied",
                &email,
                json!({"reason": reason, "ip": ip}),
            )
            .await;
        }
    };
    // The email decides the allow-list, so it must be verified by the IdP; a
    // missing claim (common with Entra ID) is not "verified".
    if email_verified != Some(true) {
        deny("email_not_verified").await;
        return Err(ApiError::unauthorized(
            "the identity provider did not mark this email address as verified",
        ));
    }
    if !cfg.domain_allowed(&email) {
        deny("domain_not_allowed").await;
        let domain = email.rsplit('@').next().unwrap_or("");
        return Err(ApiError::forbidden(if cfg.allowed_domains.is_empty() {
            "single sign-on has no allowed email domains configured".to_string()
        } else {
            format!("accounts from {domain} are not allowed")
        }));
    }
    let sub = oidc_subject_key(&cfg.issuer, subject);
    let name = if name.trim().is_empty() {
        email.split('@').next().unwrap_or("").to_string()
    } else {
        name.trim().to_string()
    };
    let existing: Option<(Uuid, bool)> =
        sqlx::query_as("SELECT id, disabled FROM users WHERE oidc_sub = $1")
            .bind(&sub)
            .fetch_optional(&st.db)
            .await?;
    let user_id = match existing {
        Some((_, true)) => return Err(ApiError::forbidden("account disabled")),
        Some((id, false)) => id,
        None => {
            let taken: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM users WHERE lower(email) = $1")
                    .bind(&email)
                    .fetch_optional(&st.db)
                    .await?;
            if taken.is_some() {
                deny("email_belongs_to_unlinked_account").await;
                return Err(ApiError::forbidden(
                    "an account with this email already exists; ask an administrator to link it to your single sign-on identity",
                ));
            }
            let mut role = if cfg.default_role.is_empty() {
                "readonly".to_string()
            } else {
                cfg.default_role.clone()
            };
            let privs = crate::auth::role_privileges(&st.db, &role).await?;
            if privs.iter().any(|p| p == "*") {
                role = "readonly".into();
            }
            let id = Uuid::new_v4();
            sqlx::query("INSERT INTO users (id, email, name, role, oidc_sub, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
                .bind(id)
                .bind(&email)
                .bind(&name)
                .bind(&role)
                .bind(&sub)
                .bind(now_ms())
                .execute(&st.db)
                .await?;
            audit::log(
                &st.db,
                &Actor::system(),
                "user.provisioned",
                id.to_string(),
                json!({"email": email, "role": role, "via": "oidc", "oidc_sub": sub}),
            )
            .await;
            id
        }
    };
    Ok(user_id)
}
