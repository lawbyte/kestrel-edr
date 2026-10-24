use super::{ApiJson, ApiPath, ApiQuery};
use crate::{
    api::devices::like_escape,
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    models::{AlertRow, ALERT_SELECT},
    policy_svc::{self, ExclusionRow, IocRow},
    state::AppState,
};
use axum::{extract::State, http::StatusCode, Json};
use kestrel_common::{now_ms, Alert, ExclusionKind, IocAction, IocKind, Policy};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use uuid::Uuid;

pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let rows: Vec<(String, String, i64, i64, i64, i64)> = sqlx::query_as(
        "SELECT p.id, p.name, p.version, p.updated_at, \
           (SELECT count(*) FROM groups g WHERE g.policy_id = p.id), \
           (SELECT count(*) FROM devices d LEFT JOIN groups g ON g.id = d.group_id \
              WHERE d.decommissioned_at IS NULL AND COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) = p.id) \
         FROM policies p ORDER BY (p.id = 'default') DESC, p.name",
    )
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Value::Array(
        rows.into_iter()
            .map(|(id, name, version, updated_at, gc, dc)| {
                json!({"id": id, "name": name, "version": version, "updated_at": updated_at, "group_count": gc, "device_count": dc})
            })
            .collect(),
    )))
}

pub async fn get_one(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Policy>> {
    p.require("read")?;
    policy_svc::effective(&st.db, &id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("policy not found"))
}

#[derive(Deserialize)]
pub struct CreatePolicy {
    name: String,
    clone_from: Option<String>,
}

pub async fn create(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreatePolicy>,
) -> ApiResult<Json<Policy>> {
    p.require("policies.write")?;
    let name = b.name.trim();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("name is required"));
    }
    let mut pol = match &b.clone_from {
        Some(src) => policy_svc::load_stored(&st.db, src)
            .await?
            .ok_or_else(|| ApiError::bad_request("clone_from policy not found"))?,
        None => Policy {
            branding: crate::settings::load(&st.db).await?.branding,
            ..Default::default()
        },
    };
    let id = Uuid::new_v4().to_string();
    let version = policy_svc::next_version(&st.db).await?;
    pol.id = id.clone();
    pol.name = name.to_string();
    pol.version = version as u64;
    pol.exclusions.clear();
    pol.iocs.clear();
    pol.remote_access
        .validate()
        .map_err(|e| ApiError::bad_request(format!("invalid remote_access: {e}")))?;
    pol.evidence
        .validate()
        .map_err(|e| ApiError::bad_request(format!("invalid evidence settings: {e}")))?;
    let now = now_ms();
    sqlx::query("INSERT INTO policies (id, name, version, body, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$5)")
        .bind(&id)
        .bind(name)
        .bind(version)
        .bind(serde_json::to_value(&pol)?)
        .bind(now)
        .execute(&st.db)
        .await?;
    // Policy-scoped exclusions/IOCs are copied with the clone.
    if let Some(src) = &b.clone_from {
        sqlx::query(
            "INSERT INTO exclusions (id, policy_id, kind, value, rule_id, expires_at, reason, created_by, created_at) \
             SELECT gen_random_uuid()::text, $2, kind, value, rule_id, expires_at, reason, $3, $4 FROM exclusions WHERE policy_id = $1",
        )
        .bind(src)
        .bind(&id)
        .bind(p.user.id)
        .bind(now)
        .execute(&st.db)
        .await?;
        sqlx::query(
            "INSERT INTO iocs (id, policy_id, kind, value, action, description, created_by, created_at) \
             SELECT gen_random_uuid()::text, $2, kind, value, action, description, $3, $4 FROM iocs WHERE policy_id = $1",
        )
        .bind(src)
        .bind(&id)
        .bind(p.user.id)
        .bind(now)
        .execute(&st.db)
        .await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "policy.create",
        &id,
        json!({"name": name, "clone_from": b.clone_from}),
    )
    .await;
    policy_svc::effective(&st.db, &id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::internal("policy vanished"))
}

pub async fn replace(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(body): ApiJson<Value>,
) -> ApiResult<Json<Policy>> {
    p.require("policies.write")?;
    let old = policy_svc::load_stored(&st.db, &id)
        .await?
        .ok_or_else(|| ApiError::not_found("policy not found"))?;
    let mut pol: Policy = serde_json::from_value(body)
        .map_err(|e| ApiError::bad_request(format!("invalid policy: {e}")))?;
    let name = pol.name.trim().to_string();
    if name.is_empty() || name.len() > 100 {
        return Err(ApiError::bad_request("policy name is required"));
    }
    if pol.suspend_window_ms > 60_000 {
        return Err(ApiError::bad_request("suspend_window_ms must be ≤ 60000"));
    }
    if pol.isolation_auto_release_hours > 720 {
        return Err(ApiError::bad_request(
            "isolation_auto_release_hours must be between 0 (never) and 720",
        ));
    }
    if !(60..=30 * 86_400).contains(&pol.ioc_block_ttl_secs) {
        return Err(ApiError::bad_request(
            "ioc_block_ttl_secs must be between 60 and 2592000 (30 days)",
        ));
    }
    pol.remote_access
        .validate()
        .map_err(|e| ApiError::bad_request(format!("invalid remote_access: {e}")))?;
    pol.evidence
        .validate()
        .map_err(|e| ApiError::bad_request(format!("invalid evidence settings: {e}")))?;
    if !(1..=kestrel_common::pause::PAUSE_MAX_MINUTES_CAP).contains(&pol.local_pause.max_minutes) {
        return Err(ApiError::bad_request(format!(
            "local_pause.max_minutes must be between 1 and {}",
            kestrel_common::pause::PAUSE_MAX_MINUTES_CAP
        )));
    }
    // Exclusions and IOCs are managed through /exclusions and /iocs.
    pol.exclusions.clear();
    pol.iocs.clear();
    pol.id = id.clone();
    pol.name = name.clone();
    let version = policy_svc::next_version(&st.db).await?;
    pol.version = version as u64;
    sqlx::query(
        "UPDATE policies SET name = $2, version = $3, body = $4, updated_at = $5 WHERE id = $1",
    )
    .bind(&id)
    .bind(&name)
    .bind(version)
    .bind(serde_json::to_value(&pol)?)
    .bind(now_ms())
    .execute(&st.db)
    .await?;
    let pushed = policy_svc::push_policy(&st, &id).await?;
    let changes = diff_keys(&serde_json::to_value(&old)?, &serde_json::to_value(&pol)?);
    audit::log(
        &st.db,
        &p.actor(),
        "policy.update",
        &id,
        json!({"name": name, "version": version, "changed": changes, "pushed_to": pushed}),
    )
    .await;
    policy_svc::effective(&st.db, &id)
        .await?
        .map(Json)
        .ok_or_else(|| ApiError::internal("policy vanished"))
}

fn diff_keys(a: &Value, b: &Value) -> Vec<String> {
    let mut out = vec![];
    if let (Some(a), Some(b)) = (a.as_object(), b.as_object()) {
        for (k, v) in b {
            if k == "version" {
                continue;
            }
            if a.get(k) != Some(v) {
                out.push(k.clone());
            }
        }
    }
    out
}

pub async fn remove(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("policies.write")?;
    if id == crate::db::DEFAULT_POLICY_ID {
        return Err(ApiError::conflict("the default policy cannot be deleted"));
    }
    let (assigned,): (i64,) = sqlx::query_as("SELECT count(*) FROM groups WHERE policy_id = $1")
        .bind(&id)
        .fetch_one(&st.db)
        .await?;
    if assigned > 0 {
        return Err(ApiError::conflict(
            "policy is assigned to one or more groups",
        ));
    }
    let r = sqlx::query("DELETE FROM policies WHERE id = $1")
        .bind(&id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("policy not found"));
    }
    audit::log(&st.db, &p.actor(), "policy.delete", &id, json!({})).await;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------- exclusions

async fn emails(
    st: &AppState,
    ids: impl Iterator<Item = Option<Uuid>>,
) -> ApiResult<HashMap<Uuid, String>> {
    let ids: Vec<Uuid> = ids.flatten().collect();
    if ids.is_empty() {
        return Ok(HashMap::new());
    }
    let rows: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, email FROM users WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(&st.db)
            .await?;
    Ok(rows.into_iter().collect())
}

fn exclusion_api(e: &ExclusionRow, users: &HashMap<Uuid, String>) -> Value {
    json!({
        "id": e.id, "kind": e.kind, "value": e.value, "rule_id": e.rule_id, "expires_at": e.expires_at, "reason": e.reason,
        "policy_id": e.policy_id, "created_by": e.created_by.and_then(|u| users.get(&u).cloned()), "created_at": e.created_at,
    })
}

#[derive(Deserialize)]
pub struct ExclusionFilter {
    policy_id: Option<String>,
}

pub async fn list_exclusions(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<ExclusionFilter>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let rows: Vec<ExclusionRow> = match q.policy_id.as_deref() {
        Some("global") | Some("null") => {
            sqlx::query_as(
                "SELECT * FROM exclusions WHERE policy_id IS NULL ORDER BY created_at DESC",
            )
            .fetch_all(&st.db)
            .await?
        }
        Some(pid) if !pid.is_empty() => {
            sqlx::query_as("SELECT * FROM exclusions WHERE policy_id = $1 ORDER BY created_at DESC")
                .bind(pid)
                .fetch_all(&st.db)
                .await?
        }
        _ => {
            sqlx::query_as("SELECT * FROM exclusions ORDER BY created_at DESC")
                .fetch_all(&st.db)
                .await?
        }
    };
    let users = emails(&st, rows.iter().map(|r| r.created_by)).await?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| exclusion_api(r, &users)).collect(),
    )))
}

#[derive(Deserialize)]
pub struct CreateExclusion {
    kind: Option<ExclusionKind>,
    value: Option<String>,
    rule_id: Option<String>,
    expires_at: Option<i64>,
    #[serde(default)]
    reason: String,
    policy_id: Option<String>,
    from_alert_id: Option<Uuid>,
}

fn kind_str(k: ExclusionKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Exclusion prefilled from an alert: sha256 when known, else a valid signer,
/// else the exact image path.
pub fn exclusion_from_alert(a: &Alert) -> (ExclusionKind, String) {
    review_exclusion(
        a.process.sha256.as_deref(),
        a.process.signer.as_deref(),
        a.process.signed == kestrel_common::SignatureState::Valid,
    )
    .unwrap_or((ExclusionKind::Path, a.process.image.clone()))
}

/// The only exclusion a review approval may create (M2): the file's sha256, or
/// its signer when the signature is valid. `None` when neither is known.
pub fn review_exclusion(
    sha256: Option<&str>,
    signer: Option<&str>,
    signature_valid: bool,
) -> Option<(ExclusionKind, String)> {
    match (sha256.map(str::trim), signer.map(str::trim)) {
        (Some(h), _) if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
            Some((ExclusionKind::Sha256, h.to_ascii_lowercase()))
        }
        (_, Some(sg)) if signature_valid && sg.len() >= 3 => {
            Some((ExclusionKind::Signer, sg.to_string()))
        }
        _ => None,
    }
}

/// Exclusion a review approval would create, shown to the approver first.
pub struct ExclusionScope {
    pub kind: ExclusionKind,
    pub value: String,
    pub rule_id: String,
    pub policy_id: String,
    pub policy_name: String,
}

impl ExclusionScope {
    pub fn to_api(&self) -> Value {
        json!({"kind": kind_str(self.kind), "value": self.value, "rule_id": self.rule_id,
               "policy_id": self.policy_id, "policy_name": self.policy_name,
               "expires_in_days": crate::api::quarantine::REVIEW_EXCLUSION_TTL_MS / 86_400_000})
    }
}

/// Top-level folders whose whole subtree must never be excluded.
const BROAD_DIRS: &[&str] = &[
    "windows",
    "windows\\system32",
    "windows\\syswow64",
    "windows\\temp",
    "users",
    "users\\public",
    "programdata",
    "program files",
    "program files (x86)",
    "temp",
    "tmp",
];

/// L10 guardrails for path exclusions: no leading or bare wildcards, no drive
/// roots or well-known broad folders, and wildcards only below two literal folders.
pub fn check_path_exclusion(value: &str) -> Result<(), String> {
    let v = value.trim().replace('/', "\\");
    let wild = |s: &str| s.contains(['*', '?']);
    if v.starts_with(['*', '?']) {
        return Err("path exclusions must not start with a wildcard".into());
    }
    // Drop `C:` / `\\?\` / UNC host+share; keep the folder segments.
    let mut segs: Vec<&str> = v
        .split('\\')
        .filter(|s| !s.is_empty() && *s != "?")
        .collect();
    if segs
        .first()
        .map(|s| s.len() == 2 && s.ends_with(':'))
        .unwrap_or(false)
    {
        segs.remove(0);
    } else if v.starts_with("\\\\") && segs.len() >= 2 {
        segs.drain(..2);
    }
    if segs.is_empty() || segs.iter().all(|s| s.chars().all(|c| c == '*' || c == '?')) {
        return Err("path exclusion is too broad (a drive root or a bare wildcard)".into());
    }
    if wild(segs[0]) {
        return Err("the first folder of a path exclusion must not contain a wildcard".into());
    }
    let literal = segs.iter().filter(|s| !wild(s)).count();
    let lower: Vec<String> = segs.iter().map(|s| s.to_ascii_lowercase()).collect();
    let literal_prefix = lower
        .iter()
        .take_while(|s| !wild(s))
        .cloned()
        .collect::<Vec<_>>()
        .join("\\");
    if wild(&v) && literal < 2 {
        return Err(
            "path exclusion is too broad: wildcards need at least two literal folders".into(),
        );
    }
    if !wild(&v) && BROAD_DIRS.contains(&literal_prefix.as_str()) {
        return Err(format!("excluding everything under {value} is not allowed"));
    }
    if wild(&v) && BROAD_DIRS.iter().any(|b| literal_prefix == *b) && literal < 3 {
        return Err(format!(
            "path exclusion {value} covers a whole system or user folder"
        ));
    }
    if lower[0] == "users" && literal < 4 {
        return Err(
            "exclusions under C:\\Users must name a specific application folder or file".into(),
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn insert_exclusion(
    st: &AppState,
    p: &Principal,
    policy_id: Option<String>,
    kind: ExclusionKind,
    value: &str,
    rule_id: Option<String>,
    expires_at: Option<i64>,
    reason: &str,
) -> ApiResult<ExclusionRow> {
    let created_by = Some(p.user.id);
    let value = value.trim();
    if value.is_empty() || value.len() > 2048 {
        return Err(ApiError::bad_request("value is required"));
    }
    if kind == ExclusionKind::Sha256
        && !(value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return Err(ApiError::bad_request(
            "sha256 exclusions need a 64-character hex hash",
        ));
    }
    // L10: tamper rules can never be excluded.
    let rule_id = rule_id
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());
    if rule_id
        .as_deref()
        .map(|r| r.to_ascii_uppercase().starts_with("TP-"))
        .unwrap_or(false)
    {
        return Err(ApiError::bad_request(
            "tamper-protection rules (TP-*) cannot be excluded",
        ));
    }
    match kind {
        ExclusionKind::Path => check_path_exclusion(value).map_err(ApiError::bad_request)?,
        ExclusionKind::Image | ExclusionKind::Signer => {
            if value.contains(['*', '?']) || value.len() < 3 {
                return Err(ApiError::bad_request(
                    "image and signer exclusions must be exact (no wildcards)",
                ));
            }
            if kind == ExclusionKind::Image && value.contains(['\\', '/']) {
                return Err(ApiError::bad_request(
                    "image exclusions take a file name; use a path exclusion for a location",
                ));
            }
        }
        ExclusionKind::Sha256 => {}
    }
    // Global exclusions reach every device: they need policy rights (L10).
    if policy_id.is_none() {
        p.require("policies.write")?;
    }
    if let Some(pid) = &policy_id {
        if policy_svc::load_stored(&st.db, pid).await?.is_none() {
            return Err(ApiError::bad_request("policy does not exist"));
        }
    }
    let id = Uuid::new_v4().to_string();
    let row: ExclusionRow = sqlx::query_as(
        "INSERT INTO exclusions (id, policy_id, kind, value, rule_id, expires_at, reason, created_by, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *",
    )
    .bind(&id)
    .bind(&policy_id)
    .bind(kind_str(kind))
    .bind(if kind == ExclusionKind::Sha256 { value.to_ascii_lowercase() } else { value.to_string() })
    .bind(rule_id)
    .bind(expires_at)
    .bind(reason)
    .bind(created_by)
    .bind(now_ms())
    .fetch_one(&st.db)
    .await?;
    policy_svc::bump_and_push(st, policy_id.as_deref()).await?;
    Ok(row)
}

pub async fn create_exclusion(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<CreateExclusion>,
) -> ApiResult<Json<Value>> {
    p.require("exclusions.write")?;
    let (mut kind, mut value, mut rule_id) = (b.kind, b.value.clone(), b.rule_id.clone());
    if let Some(aid) = b.from_alert_id {
        let (body,): (Value,) = sqlx::query_as("SELECT body FROM alerts WHERE id = $1")
            .bind(aid)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(|| ApiError::bad_request("from_alert_id not found"))?;
        let a: Alert = serde_json::from_value(body)
            .map_err(|_| ApiError::internal("stored alert unreadable"))?;
        let (k, v) = exclusion_from_alert(&a);
        if kind.is_none() {
            kind = Some(k);
            if value.is_none() {
                value = Some(v);
            }
        } else if value.is_none() {
            value = Some(match kind {
                Some(ExclusionKind::Sha256) => a.process.sha256.clone().unwrap_or_default(),
                Some(ExclusionKind::Signer) => a.process.signer.clone().unwrap_or_default(),
                Some(ExclusionKind::Image) => kestrel_common::file_name_lower(&a.process.image),
                _ => a.process.image.clone(),
            });
        }
        if rule_id.is_none() {
            rule_id = Some(a.rule_id.clone());
        }
    }
    let kind = kind.ok_or_else(|| ApiError::bad_request("kind is required"))?;
    let value = value.ok_or_else(|| ApiError::bad_request("value is required"))?;
    let policy_id = b.policy_id.filter(|s| !s.is_empty());
    let row = insert_exclusion(
        &st,
        &p,
        policy_id,
        kind,
        &value,
        rule_id,
        b.expires_at,
        &b.reason,
    )
    .await?;
    audit::log(&st.db, &p.actor(), "exclusion.create", &row.id, json!({"kind": row.kind, "value": row.value, "rule_id": row.rule_id, "policy_id": row.policy_id, "reason": row.reason, "from_alert_id": b.from_alert_id})).await;
    let users = emails(&st, std::iter::once(row.created_by)).await?;
    Ok(Json(exclusion_api(&row, &users)))
}

pub async fn delete_exclusion(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("exclusions.write")?;
    let row: ExclusionRow = sqlx::query_as("DELETE FROM exclusions WHERE id = $1 RETURNING *")
        .bind(&id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("exclusion not found"))?;
    policy_svc::bump_and_push(&st, row.policy_id.as_deref()).await?;
    audit::log(
        &st.db,
        &p.actor(),
        "exclusion.delete",
        &id,
        json!({"kind": row.kind, "value": row.value, "policy_id": row.policy_id}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct PreviewQuery {
    kind: ExclusionKind,
    value: String,
    rule_id: Option<String>,
}

pub async fn preview_exclusion(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<PreviewQuery>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let v = q.value.trim().to_string();
    if v.is_empty() {
        return Err(ApiError::bad_request("value is required"));
    }
    let since = now_ms() - 30 * 86_400_000;
    let cond = match q.kind {
        // `*` wildcard → LIKE; other LIKE metacharacters are escaped.
        ExclusionKind::Path => "lower(a.image) LIKE lower($2)",
        ExclusionKind::Sha256 => "lower(COALESCE(a.sha256,'')) = lower($2)",
        ExclusionKind::Signer => "lower(COALESCE(a.signer,'')) = lower($2)",
        ExclusionKind::Image => "(lower(a.image) = lower($2) OR lower(a.image) LIKE '%\\' || lower($2) OR lower(a.image) LIKE '%/' || lower($2))",
    };
    let param = match q.kind {
        ExclusionKind::Path => like_escape(&v).replace('*', "%"),
        _ => v.clone(),
    };
    let rule_cond = if q.rule_id.as_deref().map(|r| !r.is_empty()).unwrap_or(false) {
        " AND a.rule_id = $3"
    } else {
        " AND ($3::text IS NULL OR TRUE)"
    };
    let rule = q.rule_id.filter(|r| !r.is_empty());
    let (count,): (i64,) = sqlx::query_as(&format!(
        "SELECT count(*) FROM alerts a WHERE a.ts >= $1 AND {cond}{rule_cond}"
    ))
    .bind(since)
    .bind(&param)
    .bind(&rule)
    .fetch_one(&st.db)
    .await?;
    let sample: Vec<AlertRow> = sqlx::query_as(&format!(
        "{ALERT_SELECT} WHERE a.ts >= $1 AND {cond}{rule_cond} ORDER BY a.ts DESC LIMIT 10"
    ))
    .bind(since)
    .bind(&param)
    .bind(&rule)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(
        json!({"matching_alerts_30d": count, "sample": sample.iter().map(|a| a.to_api()).collect::<Vec<_>>()}),
    ))
}

// ---------------------------------------------------------------- IOCs

fn ioc_api(i: &IocRow, users: &HashMap<Uuid, String>) -> Value {
    json!({
        "id": i.id, "kind": i.kind, "value": i.value, "action": i.action, "description": i.description, "policy_id": i.policy_id,
        "created_by": i.created_by.and_then(|u| users.get(&u).cloned()), "created_at": i.created_at, "hits": i.hits,
    })
}

pub async fn list_iocs(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<ExclusionFilter>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let rows: Vec<IocRow> = match q.policy_id.as_deref() {
        Some("global") | Some("null") => {
            sqlx::query_as("SELECT * FROM iocs WHERE policy_id IS NULL ORDER BY created_at DESC")
                .fetch_all(&st.db)
                .await?
        }
        Some(pid) if !pid.is_empty() => {
            sqlx::query_as("SELECT * FROM iocs WHERE policy_id = $1 ORDER BY created_at DESC")
                .bind(pid)
                .fetch_all(&st.db)
                .await?
        }
        _ => {
            sqlx::query_as("SELECT * FROM iocs ORDER BY created_at DESC")
                .fetch_all(&st.db)
                .await?
        }
    };
    let users = emails(&st, rows.iter().map(|r| r.created_by)).await?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| ioc_api(r, &users)).collect(),
    )))
}

#[derive(Deserialize)]
pub struct NewIoc {
    kind: IocKind,
    value: String,
    action: IocAction,
    #[serde(default)]
    description: String,
    policy_id: Option<String>,
    /// Explicit confirmation for wide or private/loopback IP ranges (M10).
    #[serde(default)]
    confirm_broad: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum IocBody {
    Bulk {
        items: Vec<NewIoc>,
        #[serde(default)]
        confirm_broad: bool,
    },
    One(NewIoc),
}

/// Prefix limits for IP IOCs: wider than these needs `confirm_broad`; wider
/// than the hard floor is always refused.
pub const IOC_V4_MIN_PREFIX: u8 = 16;
pub const IOC_V6_MIN_PREFIX: u8 = 48;
pub const IOC_V4_FLOOR: u8 = 8;
pub const IOC_V6_FLOOR: u8 = 32;

/// M10: IP / CIDR IOC check. Returns the canonical value.
pub fn validate_ip_ioc(v: &str, confirmed: bool) -> Result<String, String> {
    let net: ipnet::IpNet = match v.parse::<ipnet::IpNet>() {
        Ok(n) => n.trunc(),
        Err(_) => v
            .parse::<std::net::IpAddr>()
            .map(ipnet::IpNet::from)
            .map_err(|_| format!("invalid IP IOC: {v}"))?,
    };
    let (min, floor) = match net {
        ipnet::IpNet::V4(_) => (IOC_V4_MIN_PREFIX, IOC_V4_FLOOR),
        ipnet::IpNet::V6(_) => (IOC_V6_MIN_PREFIX, IOC_V6_FLOOR),
    };
    if net.prefix_len() < floor {
        return Err(format!(
            "IP IOC {v} is far too broad (shorter than /{floor}); it would block a large part of the internet"
        ));
    }
    if net.prefix_len() < min && !confirmed {
        return Err(format!(
            "IP IOC {v} is wider than /{min}: every matching connection is blocked and the process killed. Resend with confirm_broad=true if this is intended"
        ));
    }
    let non_public = crate::netguard::is_non_public(&net.network())
        || crate::netguard::is_non_public(&net.broadcast());
    if non_public && !confirmed {
        return Err(format!(
            "IP IOC {v} is a private, loopback or link-local range (internal servers would be blocked). Resend with confirm_broad=true if this is intended"
        ));
    }
    Ok(if net.max_prefix_len() == net.prefix_len() {
        net.addr().to_string()
    } else {
        net.to_string()
    })
}

fn validate_ioc(i: &NewIoc, confirmed: bool) -> ApiResult<String> {
    let v = i.value.trim();
    if v.is_empty() || v.len() > 2048 {
        return Err(ApiError::bad_request("IOC value is required"));
    }
    Ok(match i.kind {
        IocKind::Sha256 => {
            if !(v.len() == 64 && v.chars().all(|c| c.is_ascii_hexdigit())) {
                return Err(ApiError::bad_request(format!("invalid sha256 IOC: {v}")));
            }
            v.to_ascii_lowercase()
        }
        IocKind::Ip => {
            validate_ip_ioc(v, confirmed || i.confirm_broad).map_err(ApiError::bad_request)?
        }
        IocKind::Domain => v.trim_end_matches('.').to_ascii_lowercase(),
        _ => v.to_string(),
    })
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

pub async fn create_iocs(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<IocBody>,
) -> ApiResult<Json<Value>> {
    p.require("iocs.write")?;
    let (items, bulk, confirmed) = match b {
        IocBody::Bulk {
            items,
            confirm_broad,
        } => (items, true, confirm_broad),
        IocBody::One(i) => (vec![i], false, false),
    };
    if items.is_empty() || items.len() > 15_000 {
        return Err(ApiError::bad_request("1-15000 IOCs per request"));
    }
    let mut values = vec![];
    for i in &items {
        values.push(validate_ioc(i, confirmed)?);
        if let Some(pid) = i.policy_id.as_ref().filter(|s| !s.is_empty()) {
            if policy_svc::load_stored(&st.db, pid).await?.is_none() {
                return Err(ApiError::bad_request("policy does not exist"));
            }
        }
    }
    let now = now_ms();
    let mut tx = st.db.begin().await?;
    let mut rows = vec![];
    let mut policies: Vec<Option<String>> = vec![];
    for (i, v) in items.iter().zip(values) {
        let pid = i.policy_id.clone().filter(|s| !s.is_empty());
        let row: IocRow = sqlx::query_as(
            "INSERT INTO iocs (id, policy_id, kind, value, action, description, created_by, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&pid)
        .bind(enum_str(&i.kind))
        .bind(&v)
        .bind(enum_str(&i.action))
        .bind(&i.description)
        .bind(p.user.id)
        .bind(now)
        .fetch_one(&mut *tx)
        .await?;
        if !policies.contains(&pid) {
            policies.push(pid);
        }
        rows.push(row);
    }
    tx.commit().await?;
    if policies.iter().any(|p| p.is_none()) {
        policy_svc::bump_and_push(&st, None).await?;
    } else {
        for pid in policies.iter().flatten() {
            policy_svc::bump_and_push(&st, Some(pid)).await?;
        }
    }
    audit::log(&st.db, &p.actor(), "ioc.create", format!("{} IOCs", rows.len()), json!({"ids": rows.iter().map(|r| r.id.clone()).collect::<Vec<_>>(), "sample": rows.iter().take(20).map(|r| json!({"kind": r.kind, "value": r.value, "action": r.action})).collect::<Vec<_>>()})).await;
    let users = emails(&st, std::iter::once(Some(p.user.id))).await?;
    let out: Vec<Value> = rows.iter().map(|r| ioc_api(r, &users)).collect();
    if bulk {
        Ok(Json(json!({"items": out})))
    } else {
        Ok(Json(out.into_iter().next().unwrap_or(Value::Null)))
    }
}

pub async fn delete_ioc(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("iocs.write")?;
    let row: IocRow = sqlx::query_as("DELETE FROM iocs WHERE id = $1 RETURNING *")
        .bind(&id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("IOC not found"))?;
    policy_svc::bump_and_push(&st, row.policy_id.as_deref()).await?;
    audit::log(
        &st.db,
        &p.actor(),
        "ioc.delete",
        &id,
        json!({"kind": row.kind, "value": row.value}),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_guardrails() {
        for bad in [
            "*",
            "**",
            "C:\\*",
            "C:\\",
            "*\\evil.exe",
            "C:\\*\\x.exe",
            "C:\\Users\\*",
            "C:\\Users\\bob\\Downloads\\*",
            "C:\\Windows",
            "C:\\Windows\\System32\\*",
            "C:\\Program Files\\*",
            "C:\\Tools\\*",
            "C:\\Users\\bob",
        ] {
            assert!(check_path_exclusion(bad).is_err(), "{bad} must be rejected");
        }
        for ok in [
            "C:\\Program Files\\Vendor\\*",
            "C:\\Tools\\Backup\\backup.exe",
            "C:\\Tools\\Backup\\*",
            "C:\\Users\\*\\AppData\\Local\\Vendor\\app.exe",
            "D:\\Builds\\ci\\runner.exe",
        ] {
            assert!(
                check_path_exclusion(ok).is_ok(),
                "{ok} must be accepted: {:?}",
                check_path_exclusion(ok)
            );
        }
    }

    #[test]
    fn ip_ioc_limits() {
        assert_eq!(
            validate_ip_ioc("203.0.113.7", false).unwrap(),
            "203.0.113.7"
        );
        assert_eq!(
            validate_ip_ioc("198.51.0.0/16", false).unwrap(),
            "198.51.0.0/16"
        );
        assert!(validate_ip_ioc("0.0.0.0/0", true).is_err());
        assert!(validate_ip_ioc("44.0.0.0/8", false).is_err());
        assert!(validate_ip_ioc("44.0.0.0/8", true).is_ok());
        assert!(validate_ip_ioc("44.0.0.0/7", true).is_err());
        assert!(validate_ip_ioc("10.0.0.0/24", false).is_err());
        assert!(validate_ip_ioc("127.0.0.1", false).is_err());
        assert!(validate_ip_ioc("10.0.0.0/24", true).is_ok());
        assert!(validate_ip_ioc("2001:4860::/32", false).is_err());
        assert!(validate_ip_ioc("2001:4860:4860::/48", false).is_ok());
        assert!(validate_ip_ioc("::/0", true).is_err());
        assert!(validate_ip_ioc("fd00::/64", false).is_err());
        assert!(validate_ip_ioc("not-an-ip", true).is_err());
    }

    #[test]
    fn review_exclusions_are_hash_or_signer() {
        let h = "a".repeat(64);
        assert_eq!(
            review_exclusion(Some(&h), None, false),
            Some((ExclusionKind::Sha256, h.clone()))
        );
        assert_eq!(
            review_exclusion(None, Some("Vendor Ltd"), true),
            Some((ExclusionKind::Signer, "Vendor Ltd".into()))
        );
        assert_eq!(review_exclusion(None, Some("Vendor Ltd"), false), None);
        assert_eq!(review_exclusion(Some("short"), None, true), None);
    }
}
