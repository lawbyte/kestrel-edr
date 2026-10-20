use super::{
    auth_routes::{validate_email, validate_password},
    parse_uuid, ApiJson, ApiPath,
};
use crate::{
    audit,
    auth::{role_privileges, Principal, API_TOKEN_PREFIX},
    crypto::{hash_password, random_token, sha256_hex},
    db::ALL_PRIVILEGES,
    error::{ApiError, ApiResult},
    models::UserRow,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use kestrel_common::now_ms;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let rows: Vec<UserRow> = sqlx::query_as("SELECT * FROM users ORDER BY lower(email)")
        .fetch_all(&st.db)
        .await?;
    Ok(Json(Value::Array(
        rows.iter().map(|u| u.to_api()).collect(),
    )))
}

async fn role_exists(st: &AppState, role: &str) -> ApiResult<()> {
    let r: Option<(String,)> = sqlx::query_as("SELECT name FROM roles WHERE name = $1")
        .bind(role)
        .fetch_optional(&st.db)
        .await?;
    r.map(|_| ())
        .ok_or_else(|| ApiError::bad_request(format!("unknown role '{role}'")))
}

#[derive(Deserialize)]
pub struct CreateUser {
    email: String,
    #[serde(default)]
    name: String,
    role: String,
    password: Option<String>,
}

pub async fn create(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateUser>,
) -> ApiResult<Json<Value>> {
    p.require("users.write")?;
    let email = validate_email(&b.email)?;
    role_exists(&st, &b.role).await?;
    let hash = match b.password.as_deref().filter(|s| !s.is_empty()) {
        Some(pw) => {
            validate_password(pw)?;
            Some(hash_password(pw)?)
        }
        None => None,
    };
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, name, password_hash, role, created_at) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(id)
        .bind(&email)
        .bind(b.name.trim())
        .bind(hash)
        .bind(&b.role)
        .bind(now_ms())
        .execute(&st.db)
        .await
        .map_err(|e| match ApiError::from(e) {
            e if e.code == "conflict" => ApiError::conflict("a user with this email already exists"),
            e => e,
        })?;
    audit::log(
        &st.db,
        &p.actor(),
        "user.create",
        id.to_string(),
        json!({"email": email, "role": b.role, "password_set": b.password.is_some()}),
    )
    .await;
    let u: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(u.to_api()))
}

#[derive(Deserialize)]
pub struct PatchUser {
    role: Option<String>,
    disabled: Option<bool>,
    name: Option<String>,
    /// Admin password reset (extension).
    password: Option<String>,
    /// Link (string: the IdP `sub` claim, bound to the configured issuer) or
    /// unlink (null) a single sign-on identity. The only way an existing account
    /// gets SSO access (H5).
    #[serde(default, deserialize_with = "super::double_option")]
    oidc_subject: Option<Option<String>>,
}

async fn active_admins_excluding(st: &AppState, id: Uuid) -> ApiResult<i64> {
    let (n,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM users u JOIN roles r ON r.name = u.role WHERE '*' = ANY(r.privileges) AND NOT u.disabled AND u.id != $1",
    )
    .bind(id)
    .fetch_one(&st.db)
    .await?;
    Ok(n)
}

pub async fn update(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PatchUser>,
) -> ApiResult<Json<Value>> {
    p.require("users.write")?;
    let id = parse_uuid(&id)?;
    let u: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    let demoting =
        b.role.as_ref().map(|r| r != &u.role).unwrap_or(false) || b.disabled == Some(true);
    if demoting
        && role_privileges(&st.db, &u.role)
            .await?
            .iter()
            .any(|p| p == "*")
        && active_admins_excluding(&st, id).await? == 0
    {
        return Err(ApiError::conflict(
            "cannot remove or disable the last admin",
        ));
    }
    if let Some(r) = &b.role {
        role_exists(&st, r).await?;
        sqlx::query("UPDATE users SET role = $2 WHERE id = $1")
            .bind(id)
            .bind(r)
            .execute(&st.db)
            .await?;
    }
    if let Some(n) = &b.name {
        sqlx::query("UPDATE users SET name = $2 WHERE id = $1")
            .bind(id)
            .bind(n.trim())
            .execute(&st.db)
            .await?;
    }
    if let Some(pw) = b.password.as_deref().filter(|s| !s.is_empty()) {
        validate_password(pw)?;
        sqlx::query("UPDATE users SET password_hash = $2 WHERE id = $1")
            .bind(id)
            .bind(hash_password(pw)?)
            .execute(&st.db)
            .await?;
        sqlx::query("DELETE FROM sessions WHERE user_id = $1")
            .bind(id)
            .execute(&st.db)
            .await?;
    }
    if let Some(link) = &b.oidc_subject {
        let key = match link.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            None => None,
            Some(sub) => {
                if sub.len() > 255 {
                    return Err(ApiError::bad_request("oidc_subject too long"));
                }
                let s = crate::settings::load(&st.db).await?;
                if s.oidc.issuer.is_empty() {
                    return Err(ApiError::bad_request("configure single sign-on first"));
                }
                Some(super::oidc::oidc_subject_key(&s.oidc.issuer, sub))
            }
        };
        sqlx::query("UPDATE users SET oidc_sub = $2 WHERE id = $1")
            .bind(id)
            .bind(&key)
            .execute(&st.db)
            .await
            .map_err(|e| match ApiError::from(e) {
                e if e.code == "conflict" => {
                    ApiError::conflict("this identity is already linked to another user")
                }
                e => e,
            })?;
        audit::log(
            &st.db,
            &p.actor(),
            "user.sso_link",
            id.to_string(),
            json!({"email": u.email, "oidc_sub": key}),
        )
        .await;
    }
    if let Some(d) = b.disabled {
        sqlx::query("UPDATE users SET disabled = $2 WHERE id = $1")
            .bind(id)
            .bind(d)
            .execute(&st.db)
            .await?;
        if d {
            sqlx::query("DELETE FROM sessions WHERE user_id = $1")
                .bind(id)
                .execute(&st.db)
                .await?;
        }
    }
    audit::log(&st.db, &p.actor(), "user.update", id.to_string(), json!({"email": u.email, "role": b.role, "disabled": b.disabled, "name": b.name, "password_reset": b.password.is_some()})).await;
    let u: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(u.to_api()))
}

pub async fn remove(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("users.write")?;
    let id = parse_uuid(&id)?;
    if id == p.user.id {
        return Err(ApiError::conflict("you cannot delete your own account"));
    }
    let u: UserRow = sqlx::query_as("SELECT * FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if role_privileges(&st.db, &u.role)
        .await?
        .iter()
        .any(|p| p == "*")
        && active_admins_excluding(&st, id).await? == 0
    {
        return Err(ApiError::conflict("cannot delete the last admin"));
    }
    // Tokens die with their owner.
    sqlx::query("DELETE FROM api_tokens WHERE created_by = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "user.delete",
        id.to_string(),
        json!({"email": u.email}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- API tokens

pub const DEFAULT_TOKEN_DAYS: i64 = 90;
pub const MAX_TOKEN_DAYS: i64 = 730;

#[allow(clippy::type_complexity)]
pub async fn list_tokens(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("tokens.write")?;
    let rows: Vec<(Uuid, String, String, i64, Option<i64>, Vec<String>, Option<String>, Option<i64>)> = sqlx::query_as(
        "SELECT t.id, t.name, t.prefix, t.created_at, t.last_used, t.privileges, u.email, t.expires_at FROM api_tokens t LEFT JOIN users u ON u.id = t.created_by ORDER BY t.created_at DESC",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|(id, name, prefix, created_at, last_used, privileges, by, expires_at)| {
                json!({"id": id, "name": name, "prefix": prefix, "created_at": created_at, "last_used": last_used, "privileges": privileges, "created_by": by, "expires_at": expires_at})
            })
            .collect(),
    )))
}

#[derive(Deserialize)]
pub struct CreateToken {
    name: String,
    #[serde(default)]
    privileges: Vec<String>,
    /// Lifetime in days (default 90, max 730).
    expires_in_days: Option<i64>,
}

pub async fn create_token(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateToken>,
) -> ApiResult<Json<Value>> {
    p.require("tokens.write")?;
    let name = b.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name is required"));
    }
    let mut privs: Vec<String> = if b.privileges.is_empty() {
        vec!["read".into()]
    } else {
        b.privileges.clone()
    };
    privs.sort();
    privs.dedup();
    for pr in &privs {
        if pr != "*" && !ALL_PRIVILEGES.contains(&pr.as_str()) {
            return Err(ApiError::bad_request(format!("unknown privilege '{pr}'")));
        }
        if !p.has(pr) || (pr == "*" && !p.privileges.iter().any(|x| x == "*")) {
            return Err(ApiError::forbidden(format!("you cannot grant '{pr}'")));
        }
    }
    let days = b.expires_in_days.unwrap_or(DEFAULT_TOKEN_DAYS);
    if !(1..=MAX_TOKEN_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "expires_in_days must be 1-{MAX_TOKEN_DAYS}"
        )));
    }
    let token = format!("{API_TOKEN_PREFIX}{}", random_token(32));
    let prefix: String = token.chars().take(API_TOKEN_PREFIX.len() + 6).collect();
    let id = Uuid::new_v4();
    let now = now_ms();
    let expires_at = now + days * 86_400_000;
    sqlx::query("INSERT INTO api_tokens (id, name, token_hash, prefix, privileges, created_by, created_at, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)")
        .bind(id)
        .bind(name)
        .bind(sha256_hex(&token))
        .bind(&prefix)
        .bind(&privs)
        .bind(p.user.id)
        .bind(now)
        .bind(expires_at)
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "token.create",
        id.to_string(),
        json!({"name": name, "privileges": privs, "prefix": prefix, "expires_at": expires_at}),
    )
    .await;
    Ok(Json(
        json!({"id": id, "name": name, "prefix": prefix, "created_at": now, "last_used": null, "privileges": privs, "expires_at": expires_at, "token": token}),
    ))
}

pub async fn delete_token(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("tokens.write")?;
    let id = parse_uuid(&id)?;
    let r: Option<(String,)> =
        sqlx::query_as("DELETE FROM api_tokens WHERE id = $1 RETURNING name")
            .bind(id)
            .fetch_optional(&st.db)
            .await?;
    let (name,) = r.ok_or_else(|| ApiError::not_found("token not found"))?;
    audit::log(
        &st.db,
        &p.actor(),
        "token.delete",
        id.to_string(),
        json!({"name": name}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}
