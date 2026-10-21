use super::ApiJson;
use crate::{
    audit::{self, Actor},
    auth::{
        self, clear_session_cookie, client_ip, create_session, session_cookie, Principal, Via,
        BACKOFF_EMAIL, BACKOFF_EMAIL_IP, BACKOFF_IP, SETUP_PER_10_MIN,
    },
    crypto,
    error::{ApiError, ApiResult},
    models::UserRow,
    settings,
    state::AppState,
};
use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use kestrel_common::now_ms;
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

pub const MIN_PASSWORD_LEN: usize = 10;

pub fn validate_password(p: &str) -> ApiResult<()> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        return Err(ApiError::bad_request(format!(
            "password must be at least {MIN_PASSWORD_LEN} characters"
        )));
    }
    if p.len() > 1024 {
        return Err(ApiError::bad_request("password too long"));
    }
    Ok(())
}

pub fn validate_email(e: &str) -> ApiResult<String> {
    let e = e.trim().to_ascii_lowercase();
    let ok = e.len() <= 254
        && e.split('@').count() == 2
        && e.split('@').all(|p| !p.is_empty())
        && !e.contains(char::is_whitespace);
    if !ok {
        return Err(ApiError::bad_request("invalid email address"));
    }
    Ok(e)
}

pub async fn setup_status(State(st): State<AppState>) -> ApiResult<Json<serde_json::Value>> {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    let s = settings::load(&st.db).await?;
    Ok(Json(json!({
        "needs_setup": n == 0,
        "oidc_enabled": s.oidc.enabled && !s.oidc.issuer.is_empty() && !s.oidc.client_id.is_empty(),
        "org_name": s.org_name,
    })))
}

#[derive(Deserialize)]
pub struct SetupBody {
    /// One-time code printed to the server log at startup (or `KESTREL_SETUP_CODE`).
    #[serde(default)]
    setup_code: String,
    org_name: String,
    email: String,
    password: String,
    name: String,
}

fn login_response(user: &UserRow, csrf: &str, cookie: String, privileges: Vec<String>) -> Response {
    let mut h = HeaderMap::new();
    if let Ok(v) = cookie.parse() {
        h.insert(header::SET_COOKIE, v);
    }
    (
        h,
        Json(json!({"user": user.to_api(), "csrf_token": csrf, "privileges": privileges})),
    )
        .into_response()
}

fn request_meta(st: &AppState, req: Request) -> (Option<String>, Option<String>, axum::body::Body) {
    let (parts, body) = req.into_parts();
    let ip = client_ip(st, &parts);
    let ua = parts
        .headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    (ip, ua, body)
}

async fn read_json<T: serde::de::DeserializeOwned>(body: axum::body::Body) -> ApiResult<T> {
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| ApiError::bad_request("body too large"))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| ApiError::bad_request(format!("invalid JSON body: {e}")))
}

pub async fn setup(State(st): State<AppState>, req: Request) -> ApiResult<Response> {
    let (ip, ua, body) = request_meta(&st, req);
    let b: SetupBody = read_json(body).await?;
    let (users,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    if users > 0 {
        return Err(ApiError::conflict("setup already completed"));
    }
    // L3: whoever reaches the port first must also hold the setup code.
    let key = format!("setup:{}", ip.clone().unwrap_or_default());
    if st.login_limiter.count(&key, 10 * 60_000) >= SETUP_PER_10_MIN {
        return Err(ApiError::rate_limited(
            "too many setup attempts, try again later",
        ));
    }
    let given = b.setup_code.trim().to_uppercase();
    if given.is_empty() || !crypto::ct_eq(&given, &st.setup_code.to_uppercase()) {
        st.login_limiter.record(&key);
        tracing::warn!(ip = ?ip, "first-run setup refused: wrong setup code");
        return Err(ApiError::forbidden(
            "invalid setup code (it is printed in the server log at startup, or set with KESTREL_SETUP_CODE)",
        )
        .with_extra(json!({"setup_code_required": true})));
    }
    let email = validate_email(&b.email)?;
    validate_password(&b.password)?;
    let org = b.org_name.trim();
    if org.is_empty() || org.len() > 200 {
        return Err(ApiError::bad_request("org_name is required"));
    }
    let hash = crypto::hash_password(&b.password)?;
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7413003)")
        .execute(&mut *tx)
        .await?;
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if n > 0 {
        return Err(ApiError::conflict("setup already completed"));
    }
    sqlx::query("INSERT INTO users (id, email, name, password_hash, role, created_at) VALUES ($1,$2,$3,$4,'admin',$5)")
        .bind(id)
        .bind(&email)
        .bind(b.name.trim())
        .bind(&hash)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
    let mut s: settings::Settings = settings::load(&st.db).await?;
    s.org_name = org.to_string();
    if s.branding.org_name.is_empty() {
        s.branding.org_name = org.to_string();
    }
    sqlx::query("UPDATE settings SET org_name = $1, body = $2, updated_at = $3 WHERE id = 1")
        .bind(org)
        .bind(serde_json::to_value(&s)?)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE policies SET body = jsonb_set(body, '{branding,org_name}', to_jsonb($1::text)) WHERE body->'branding'->>'org_name' = ''")
        .bind(org)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let user: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    audit::log(
        &st.db,
        &Actor {
            id: Some(id),
            email: Some(email.clone()),
        },
        "auth.setup",
        id.to_string(),
        json!({"org_name": org, "ip": ip}),
    )
    .await;
    let (token, csrf, max_age) = create_session(&st, id, "password", ip, ua).await?;
    let privs = vec!["*".to_string()];
    let _ = crate::policy_svc::bump_and_push(&st, None).await;
    Ok(login_response(
        &user,
        &csrf,
        session_cookie(&token, max_age),
        privs,
    ))
}

#[derive(Deserialize)]
pub struct LoginBody {
    email: String,
    password: String,
    #[serde(default)]
    totp: Option<String>,
}

pub async fn login(State(st): State<AppState>, req: Request) -> ApiResult<Response> {
    let (ip, ua, body) = request_meta(&st, req);
    let b: LoginBody = read_json(body).await?;
    let email = b.email.trim().to_ascii_lowercase();
    let ip_s = ip.clone().unwrap_or_default();
    let keys = [
        (format!("ei:{email}|{ip_s}"), BACKOFF_EMAIL_IP),
        (format!("e:{email}"), BACKOFF_EMAIL),
        (format!("ip:{ip_s}"), BACKOFF_IP),
    ];
    let now = now_ms();
    let thr = &st.login_throttle;
    // M4: exponential backoff after repeated *failed* verifications (never a
    // hard lockout). Checked before verifying so a throttled guess learns nothing.
    if let Some(wait) = keys
        .iter()
        .filter_map(|(k, b)| thr.wait_ms(k, *b, now))
        .max()
    {
        audit::log(
            &st.db,
            &Actor {
                id: None,
                email: Some(email.clone()),
            },
            "auth.login_rate_limited",
            &email,
            json!({"ip": ip, "retry_after_ms": wait}),
        )
        .await;
        return Err(ApiError::rate_limited(format!(
            "too many failed sign-in attempts, try again in {} s",
            (wait + 999) / 1000
        ))
        .with_extra(json!({"retry_after_ms": wait})));
    }
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM users")
        .fetch_one(&st.db)
        .await?;
    if n == 0 {
        return Err(ApiError::conflict("setup required").with_extra(json!({"needs_setup": true})));
    }
    let user: Option<UserRow> = sqlx::query_as("SELECT * FROM users WHERE lower(email) = $1")
        .bind(&email)
        .fetch_optional(&st.db)
        .await?;
    let fail = |reason: &'static str| {
        let st = st.clone();
        let email = email.clone();
        let ip = ip.clone();
        let keys = keys.clone();
        async move {
            let now = now_ms();
            for (k, _) in &keys {
                st.login_throttle.fail(k, now);
            }
            audit::log(
                &st.db,
                &Actor {
                    id: None,
                    email: Some(email.clone()),
                },
                "auth.login_failed",
                &email,
                json!({"ip": ip, "reason": reason}),
            )
            .await;
            ApiError::unauthorized("invalid email, password or code")
        }
    };
    let Some(user) = user else {
        crypto::dummy_password_check(&b.password);
        return Err(fail("unknown_user").await);
    };
    let password_ok = user
        .password_hash
        .as_deref()
        .map(|h| crypto::verify_password(&b.password, h))
        .unwrap_or_else(|| {
            crypto::dummy_password_check(&b.password);
            false
        });
    if user.mfa_enabled && !user.disabled {
        // L1: the answer to a request without a code is the same whether or not
        // the password was right, so the password cannot be guessed separately.
        let code = b.totp.as_deref().map(str::trim).unwrap_or("");
        if code.is_empty() {
            if !password_ok {
                for (k, _) in &keys {
                    st.login_throttle.fail(k, now_ms());
                }
                audit::log(
                    &st.db,
                    &Actor {
                        id: None,
                        email: Some(email.clone()),
                    },
                    "auth.login_failed",
                    &email,
                    json!({"ip": ip, "reason": "bad_password"}),
                )
                .await;
            }
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "mfa_required",
                "TOTP code required",
            )
            .with_extra(json!({"mfa_required": true})));
        }
        if !password_ok {
            return Err(fail("bad_password").await);
        }
        let secret = user
            .totp_secret_enc
            .as_deref()
            .map(|e| st.mk.open_str(e))
            .transpose()?
            .unwrap_or_default();
        let step = crypto::totp_for(&secret, &user.email).ok().and_then(|t| {
            crypto::totp_verify_step(&t, code, (now_ms() / 1000) as u64, user.totp_last_step)
        });
        let Some(step) = step else {
            return Err(fail("bad_totp").await);
        };
        if !consume_totp_step(&st, user.id, step).await? {
            return Err(fail("totp_replay").await);
        }
    } else if !password_ok {
        return Err(fail("bad_password").await);
    }
    if user.disabled {
        return Err(fail("disabled").await);
    }
    st.login_throttle.clear(&keys[0].0);
    st.login_throttle.clear(&keys[1].0);
    let s = settings::load(&st.db).await?;
    let method = if s.require_mfa && !user.mfa_enabled {
        "password_mfa_setup"
    } else {
        "password"
    };
    let (token, csrf, max_age) = create_session(&st, user.id, method, ip.clone(), ua).await?;
    audit::log(
        &st.db,
        &Actor {
            id: Some(user.id),
            email: Some(user.email.clone()),
        },
        "auth.login",
        user.id.to_string(),
        json!({"ip": ip, "method": method}),
    )
    .await;
    let privileges = if method == "password_mfa_setup" {
        vec![]
    } else {
        auth::role_privileges(&st.db, &user.role).await?
    };
    let user: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(user.id)
        .fetch_one(&st.db)
        .await?;
    Ok(login_response(
        &user,
        &csrf,
        session_cookie(&token, max_age),
        expand(privileges),
    ))
}

/// Atomically record `step` as the last accepted TOTP step; false on replay.
async fn consume_totp_step(st: &AppState, user_id: Uuid, step: i64) -> ApiResult<bool> {
    let r = sqlx::query(
        "UPDATE users SET totp_last_step = $2 WHERE id = $1 AND (totp_last_step IS NULL OR totp_last_step < $2)",
    )
    .bind(user_id)
    .bind(step)
    .execute(&st.db)
    .await?;
    Ok(r.rows_affected() == 1)
}

fn expand(privs: Vec<String>) -> Vec<String> {
    if privs.iter().any(|p| p == "*") {
        let mut v = vec!["*".to_string()];
        v.extend(crate::db::ALL_PRIVILEGES.iter().map(|s| s.to_string()));
        v
    } else {
        privs
    }
}

pub async fn logout(State(st): State<AppState>, req: Request) -> ApiResult<Response> {
    let (mut parts, _body) = req.into_parts();
    let p = Principal::from_request_parts(&mut parts, &st).await?;
    if let Via::Session { token_hash, .. } = &p.via {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&st.db)
            .await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "auth.logout",
        p.user.id.to_string(),
        json!({}),
    )
    .await;
    let mut h = HeaderMap::new();
    if let Ok(v) = clear_session_cookie().parse() {
        h.insert(header::SET_COOKIE, v);
    }
    Ok((StatusCode::NO_CONTENT, h).into_response())
}

pub async fn me(p: Principal) -> ApiResult<Json<serde_json::Value>> {
    let mut v =
        json!({"user": p.user.to_api(), "csrf_token": p.csrf(), "privileges": p.privilege_list()});
    if p.mfa_setup_required {
        v["mfa_setup_required"] = true.into();
    }
    Ok(Json(v))
}

#[derive(Deserialize)]
pub struct PasswordBody {
    current_password: String,
    new_password: String,
}

pub async fn change_password(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<PasswordBody>,
) -> ApiResult<StatusCode> {
    p.require_session()?;
    let hash = p
        .user
        .password_hash
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("account uses single sign-on"))?;
    if !crypto::verify_password(&b.current_password, hash) {
        return Err(ApiError::forbidden("current password is wrong"));
    }
    validate_password(&b.new_password)?;
    sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
        .bind(p.user.id)
        .bind(crypto::hash_password(&b.new_password)?)
        .execute(&st.db)
        .await?;
    // Sign out other sessions.
    if let Via::Session { token_hash, .. } = &p.via {
        sqlx::query("DELETE FROM sessions WHERE user_id = $1 AND token_hash != $2")
            .bind(p.user.id)
            .bind(token_hash)
            .execute(&st.db)
            .await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "user.password_changed",
        p.user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// Start TOTP enrolment: returns a new secret (stored, not yet active).
pub async fn mfa_setup(
    State(st): State<AppState>,
    p: Principal,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_session()?;
    if p.user.mfa_enabled {
        return Err(ApiError::conflict("MFA already enabled"));
    }
    let secret = crypto::new_totp_secret();
    let totp = crypto::totp_for(&secret, &p.user.email)?;
    sqlx::query("UPDATE users SET totp_secret_enc = $2 WHERE id = $1")
        .bind(p.user.id)
        .bind(st.mk.seal_str(&secret))
        .execute(&st.db)
        .await?;
    Ok(Json(
        json!({"secret": secret, "otpauth_url": totp.get_url()}),
    ))
}

#[derive(Deserialize)]
pub struct TotpBody {
    totp: String,
}

pub async fn mfa_enable(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<TotpBody>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_session()?;
    let enc = p
        .user
        .totp_secret_enc
        .as_deref()
        .ok_or_else(|| ApiError::bad_request("call /api/me/mfa/setup first"))?;
    let secret = st.mk.open_str(enc)?;
    let step = crypto::totp_verify_step(
        &crypto::totp_for(&secret, &p.user.email)?,
        &b.totp,
        (now_ms() / 1000) as u64,
        None,
    )
    .ok_or_else(|| ApiError::bad_request("invalid TOTP code"))?;
    // The enrolment code is consumed too: it cannot be replayed at login.
    sqlx::query("UPDATE users SET mfa_enabled = true, totp_last_step = $2 WHERE id = $1")
        .bind(p.user.id)
        .bind(step)
        .execute(&st.db)
        .await?;
    if let Via::Session { token_hash, .. } = &p.via {
        sqlx::query("UPDATE sessions SET auth_method = 'password' WHERE token_hash = $1")
            .bind(token_hash)
            .execute(&st.db)
            .await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "user.mfa_enabled",
        p.user.id.to_string(),
        json!({}),
    )
    .await;
    let user: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(p.user.id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({"user": user.to_api()})))
}

#[derive(Deserialize)]
pub struct MfaDisableBody {
    password: String,
}

pub async fn mfa_disable(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<MfaDisableBody>,
) -> ApiResult<StatusCode> {
    p.require_session()?;
    let s = settings::load(&st.db).await?;
    if s.require_mfa {
        return Err(ApiError::forbidden("MFA is required by policy"));
    }
    let ok = p
        .user
        .password_hash
        .as_deref()
        .map(|h| crypto::verify_password(&b.password, h))
        .unwrap_or(false);
    if !ok {
        return Err(ApiError::forbidden("password is wrong"));
    }
    sqlx::query("UPDATE users SET mfa_enabled = false, totp_secret_enc = NULL, totp_last_step = NULL WHERE id = $1")
        .bind(p.user.id)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "user.mfa_disabled",
        p.user.id.to_string(),
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /me/reauth {totp}` — MFA step-up for remote access guardrails
/// (`require_mfa_reauth`): valid for 10 minutes on this console session.
/// Session only (CSRF checked by the extractor); failures are throttled like
/// login (exponential backoff per account) and audited as `auth.reauth`.
pub async fn reauth(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<TotpBody>,
) -> ApiResult<Json<serde_json::Value>> {
    p.require_session()?;
    let Via::Session { token_hash, .. } = &p.via else {
        return Err(ApiError::forbidden("sign in to the console"));
    };
    if !p.user.mfa_enabled {
        return Err(ApiError::forbidden(
            "multi-factor authentication is not enabled for this account",
        )
        .with_extra(json!({"reason": "mfa_not_enabled"})));
    }
    let key = format!("reauth:{}", p.user.id);
    let now = now_ms();
    if let Some(wait) = st.login_throttle.wait_ms(&key, BACKOFF_EMAIL_IP, now) {
        return Err(ApiError::rate_limited(format!(
            "too many wrong codes, try again in {} s",
            (wait + 999) / 1000
        ))
        .with_extra(json!({"retry_after_ms": wait})));
    }
    let secret = p
        .user
        .totp_secret_enc
        .as_deref()
        .map(|e| st.mk.open_str(e))
        .transpose()?
        .unwrap_or_default();
    let step = crypto::totp_for(&secret, &p.user.email).ok().and_then(|t| {
        crypto::totp_verify_step(
            &t,
            b.totp.trim(),
            (now / 1000) as u64,
            p.user.totp_last_step,
        )
    });
    let ok = match step {
        Some(step) => consume_totp_step(&st, p.user.id, step).await?,
        None => false,
    };
    audit::log(
        &st.db,
        &p.actor(),
        "auth.reauth",
        p.user.id.to_string(),
        json!({"ok": ok, "ip": p.ip}),
    )
    .await;
    if !ok {
        st.login_throttle.fail(&key, now_ms());
        // 400, not 401: the console treats 401 as "signed out".
        return Err(
            ApiError::bad_request("invalid code").with_extra(json!({"reason": "invalid_totp"}))
        );
    }
    st.login_throttle.clear(&key);
    let at = now_ms();
    sqlx::query("UPDATE sessions SET reauth_at = $2 WHERE token_hash = $1")
        .bind(token_hash)
        .bind(at)
        .execute(&st.db)
        .await?;
    Ok(Json(
        json!({"reauth_until": at + crate::remote::REAUTH_VALID_MS}),
    ))
}
