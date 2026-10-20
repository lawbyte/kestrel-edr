use super::{double_option, parse_uuid, ApiJson, ApiPath};
use crate::{
    audit,
    auth::Principal,
    crypto::{random_token, sha256_hex},
    error::{ApiError, ApiResult},
    policy_svc,
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use kestrel_common::now_ms;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub const ENROLL_TOKEN_PREFIX: &str = "kte_";
/// M6: enrollment tokens are short-lived and use-limited by default.
pub const DEFAULT_TOKEN_DAYS: i64 = 7;
pub const MAX_TOKEN_DAYS: i64 = 90;
pub const DEFAULT_TOKEN_USES: i32 = 50;
pub const MAX_TOKEN_USES: i32 = 10_000;

#[derive(sqlx::FromRow)]
struct GroupRow {
    id: Uuid,
    name: String,
    description: String,
    policy_id: String,
    is_default: bool,
    device_count: i64,
}

impl GroupRow {
    fn to_api(&self) -> Value {
        json!({"id": self.id, "name": self.name, "description": self.description, "policy_id": self.policy_id,
               "device_count": self.device_count, "is_default": self.is_default})
    }
}

const GROUP_SELECT: &str = "SELECT g.id, g.name, g.description, g.policy_id, g.is_default, \
    (SELECT count(*) FROM devices d WHERE d.group_id = g.id AND d.decommissioned_at IS NULL) AS device_count FROM groups g";

async fn load_group(st: &AppState, id: Uuid) -> ApiResult<GroupRow> {
    Ok(sqlx::query_as(&format!("{GROUP_SELECT} WHERE g.id = $1"))
        .bind(id)
        .fetch_one(&st.db)
        .await?)
}

pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let rows: Vec<GroupRow> = sqlx::query_as(&format!(
        "{GROUP_SELECT} ORDER BY g.is_default DESC, g.name"
    ))
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Value::Array(
        rows.iter().map(|g| g.to_api()).collect(),
    )))
}

#[derive(Deserialize)]
pub struct CreateGroup {
    name: String,
    #[serde(default)]
    description: String,
    policy_id: Option<String>,
}

async fn policy_exists(st: &AppState, id: &str) -> ApiResult<()> {
    let r: Option<(String,)> = sqlx::query_as("SELECT id FROM policies WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    r.map(|_| ())
        .ok_or_else(|| ApiError::bad_request("policy does not exist"))
}

pub async fn create(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateGroup>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let name = b.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name is required"));
    }
    let policy_id = b
        .policy_id
        .unwrap_or_else(|| crate::db::DEFAULT_POLICY_ID.to_string());
    policy_exists(&st, &policy_id).await?;
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO groups (id, name, description, policy_id, created_at) VALUES ($1,$2,$3,$4,$5)",
    )
    .bind(id)
    .bind(name)
    .bind(&b.description)
    .bind(&policy_id)
    .bind(now_ms())
    .execute(&st.db)
    .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "group.create",
        id.to_string(),
        json!({"name": name, "policy_id": policy_id}),
    )
    .await;
    Ok(Json(load_group(&st, id).await?.to_api()))
}

#[derive(Deserialize)]
pub struct PatchGroup {
    name: Option<String>,
    description: Option<String>,
    #[serde(default, deserialize_with = "double_option")]
    policy_id: Option<Option<String>>,
}

pub async fn update(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PatchGroup>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let g = load_group(&st, id).await?;
    if let Some(n) = &b.name {
        let n = n.trim();
        if n.is_empty() || n.len() > 100 {
            return Err(ApiError::bad_request("invalid name"));
        }
        sqlx::query("UPDATE groups SET name = $2 WHERE id = $1")
            .bind(id)
            .bind(n)
            .execute(&st.db)
            .await?;
    }
    if let Some(d) = &b.description {
        sqlx::query("UPDATE groups SET description = $2 WHERE id = $1")
            .bind(id)
            .bind(d)
            .execute(&st.db)
            .await?;
    }
    if let Some(pid) = &b.policy_id {
        let pid = pid
            .clone()
            .unwrap_or_else(|| crate::db::DEFAULT_POLICY_ID.to_string());
        policy_exists(&st, &pid).await?;
        if pid != g.policy_id {
            sqlx::query("UPDATE groups SET policy_id = $2 WHERE id = $1")
                .bind(id)
                .bind(&pid)
                .execute(&st.db)
                .await?;
            policy_svc::bump_and_push(&st, Some(&pid)).await?;
        }
    }
    audit::log(
        &st.db,
        &p.actor(),
        "group.update",
        id.to_string(),
        json!({"name": b.name, "description": b.description, "policy_id": b.policy_id}),
    )
    .await;
    Ok(Json(load_group(&st, id).await?.to_api()))
}

pub async fn remove(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let g = load_group(&st, id).await?;
    if g.is_default {
        return Err(ApiError::conflict("the default group cannot be deleted"));
    }
    // Members move to the default group (and its policy).
    let moved: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE devices SET group_id = (SELECT id FROM groups WHERE is_default LIMIT 1) WHERE group_id = $1 RETURNING id",
    )
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    sqlx::query("DELETE FROM groups WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    if !moved.is_empty() {
        let (pid,): (String,) =
            sqlx::query_as("SELECT policy_id FROM groups WHERE is_default LIMIT 1")
                .fetch_one(&st.db)
                .await?;
        policy_svc::bump_and_push(&st, Some(&pid)).await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "group.delete",
        id.to_string(),
        json!({"name": g.name, "devices_moved": moved.len()}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- enrollment tokens

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: Uuid,
    group_id: Uuid,
    group_name: String,
    token_prefix: String,
    created_at: i64,
    expires_at: i64,
    max_uses: i32,
    uses: i32,
    revoked: bool,
}

impl TokenRow {
    fn to_api(&self) -> Value {
        json!({"id": self.id, "group_id": self.group_id, "group_name": self.group_name, "token_prefix": self.token_prefix,
               "created_at": self.created_at, "expires_at": self.expires_at, "max_uses": self.max_uses, "uses": self.uses,
               "revoked": self.revoked})
    }
}

const TOKEN_SELECT: &str = "SELECT t.id, t.group_id, g.name AS group_name, t.token_prefix, t.created_at, t.expires_at, t.max_uses, t.uses, t.revoked \
    FROM enrollment_tokens t JOIN groups g ON g.id = t.group_id";

pub async fn list_tokens(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let rows: Vec<TokenRow> = sqlx::query_as(&format!("{TOKEN_SELECT} ORDER BY t.created_at DESC"))
        .fetch_all(&st.db)
        .await?;
    Ok(Json(Value::Array(
        rows.iter().map(|t| t.to_api()).collect(),
    )))
}

#[derive(Deserialize)]
pub struct CreateToken {
    group_id: Option<Uuid>,
    expires_in_days: Option<i64>,
    max_uses: Option<i32>,
}

pub fn msi_url(st: &AppState) -> String {
    st.cfg
        .agent_msi_url
        .clone()
        .unwrap_or_else(|| format!("{}/downloads/KestrelAgent.msi", st.cfg.public_base_url()))
}

/// Silent-install command matching `installer/Kestrel.wxs` (properties SERVER,
/// TOKEN, CA_B64). Works unchanged in GPO/Intune/RMM: download the MSI from
/// the console (or `msi_url`) and run this from the folder that contains it.
/// The CA PEM is passed base64-encoded so the agent pins the internal agent CA
/// without trusting any system roots.
pub fn install_command(st: &AppState, token: &str) -> String {
    use base64::Engine as _;
    let ca_b64 = base64::engine::general_purpose::STANDARD.encode(st.ca.cert_pem.as_bytes());
    format!(
        "msiexec.exe /i KestrelAgent.msi /qn SERVER={addr} TOKEN={token} CA_B64={ca_b64}",
        addr = st.cfg.agent_server_addr(),
    )
}

pub async fn create_token(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateToken>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let group_id = match b.group_id {
        Some(g) => g,
        None => {
            sqlx::query_as::<_, (Uuid,)>("SELECT id FROM groups WHERE is_default LIMIT 1")
                .fetch_one(&st.db)
                .await?
                .0
        }
    };
    load_group(&st, group_id)
        .await
        .map_err(|_| ApiError::bad_request("group does not exist"))?;
    let days = b.expires_in_days.unwrap_or(DEFAULT_TOKEN_DAYS);
    if !(1..=MAX_TOKEN_DAYS).contains(&days) {
        return Err(ApiError::bad_request(format!(
            "expires_in_days must be 1-{MAX_TOKEN_DAYS}"
        )));
    }
    let max_uses = b.max_uses.unwrap_or(DEFAULT_TOKEN_USES);
    if !(1..=MAX_TOKEN_USES).contains(&max_uses) {
        return Err(ApiError::bad_request(format!(
            "max_uses must be 1-{MAX_TOKEN_USES}"
        )));
    }
    let token = format!("{ENROLL_TOKEN_PREFIX}{}", random_token(24));
    let prefix: String = token.chars().take(ENROLL_TOKEN_PREFIX.len() + 6).collect();
    let id = Uuid::new_v4();
    let now = now_ms();
    sqlx::query(
        "INSERT INTO enrollment_tokens (id, group_id, token_hash, token_prefix, created_by, created_at, expires_at, max_uses) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(group_id)
    .bind(sha256_hex(&token))
    .bind(&prefix)
    .bind(p.user.id)
    .bind(now)
    .bind(now + days * 86_400_000)
    .bind(max_uses)
    .execute(&st.db)
    .await?;
    audit::log(&st.db, &p.actor(), "enrollment_token.create", id.to_string(), json!({"group_id": group_id, "expires_in_days": days, "max_uses": max_uses, "prefix": prefix})).await;
    let row: TokenRow = sqlx::query_as(&format!("{TOKEN_SELECT} WHERE t.id = $1"))
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    let mut v = row.to_api();
    v["token"] = token.clone().into();
    v["install_command"] = install_command(&st, &token).into();
    v["server_addr"] = st.cfg.agent_server_addr().into();
    Ok(Json(v))
}

pub async fn revoke_token(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let r = sqlx::query("UPDATE enrollment_tokens SET revoked = true WHERE id = $1")
        .bind(id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("enrollment token not found"));
    }
    audit::log(
        &st.db,
        &p.actor(),
        "enrollment_token.revoke",
        id.to_string(),
        json!({}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn installer(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let path = st.cfg.agent_dir.join("KestrelAgent.msi");
    let (sha, size) = match tokio::fs::read(&path).await {
        Ok(bytes) => (Some(sha256_hex(&bytes)), Some(bytes.len())),
        Err(_) => (None, None),
    };
    let version = tokio::fs::read_to_string(st.cfg.agent_dir.join("VERSION"))
        .await
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| kestrel_common::VERSION.to_string());
    let available = sha.is_some() || st.cfg.agent_msi_url.is_some();
    Ok(Json(json!({
        "version": version,
        "msi_url": if available { Some(msi_url(&st)) } else { None },
        "sha256": sha,
        "size": size,
        "server_addr": st.cfg.agent_server_addr(),
        "ca_pem": st.ca.cert_pem,
        "ca_sha256": st.ca.ca_sha256(),
    })))
}
