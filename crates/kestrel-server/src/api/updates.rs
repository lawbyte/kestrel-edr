//! Agent updates: releases (offline-signed manifests), ring promotion, halt.

use super::{parse_uuid, ApiJson, ApiPath};
use crate::{
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    state::AppState,
    updates::{self, Scope},
};
use axum::{extract::State, Json};
use kestrel_common::{now_ms, update::UpdateRing, wire::UpdateManifest};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

const MAX_NOTES: usize = 4000;

pub async fn status(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    Ok(Json(updates::status_view(&st).await?))
}

pub async fn list(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    Ok(Json(Value::Array(
        updates::releases_view(&st.db, None).await?,
    )))
}

async fn one(st: &AppState, id: Uuid) -> ApiResult<Value> {
    updates::releases_view(&st.db, Some(id))
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| ApiError::not_found("release not found"))
}

#[derive(Deserialize)]
pub struct RegisterBody {
    /// The manifest object printed by `kestrel-agent update-sign` (a JSON
    /// string holding it is accepted too).
    manifest: Value,
    #[serde(default)]
    notes: String,
}

fn parse_manifest(v: Value) -> Result<UpdateManifest, ApiError> {
    let v = match v {
        Value::String(s) => serde_json::from_str::<Value>(&s)
            .map_err(|_| ApiError::bad_request("manifest is not valid JSON"))?,
        other => other,
    };
    // Accept `{ "manifest": {...} }` wrappers as well.
    let v = match v {
        Value::Object(mut o) if o.contains_key("manifest") && !o.contains_key("version") => {
            o.remove("manifest").unwrap_or(Value::Null)
        }
        other => other,
    };
    serde_json::from_value(v).map_err(|e| {
        ApiError::bad_request(format!(
            "manifest must be {{version, url, sha256, signature}} as printed by `kestrel-agent update-sign`: {e}"
        ))
    })
}

pub async fn register(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<RegisterBody>,
) -> ApiResult<Json<Value>> {
    p.require("updates.write")?;
    let m = parse_manifest(b.manifest)?;
    if b.notes.chars().count() > MAX_NOTES {
        return Err(ApiError::bad_request(format!(
            "notes must be at most {MAX_NOTES} characters"
        )));
    }
    if let Err(e) = updates::validate_release(&st, &m).await {
        audit::log(
            &st.db,
            &p.actor(),
            "update.release_rejected",
            m.version.chars().take(64).collect::<String>(),
            json!({"url": m.url.chars().take(300).collect::<String>(), "sha256": m.sha256.chars().take(80).collect::<String>(), "reason": e}),
        )
        .await;
        return Err(ApiError::bad_request(e));
    }
    let id = Uuid::new_v4();
    let r = sqlx::query(
        "INSERT INTO agent_releases (id, version, url, sha256, signature, notes, created_by, created_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (version) DO NOTHING",
    )
    .bind(id)
    .bind(m.version.trim())
    .bind(m.url.trim())
    .bind(m.sha256.trim().to_ascii_lowercase())
    .bind(m.signature.trim())
    .bind(b.notes.trim())
    .bind(p.user.id)
    .bind(now_ms())
    .execute(&st.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(ApiError::conflict(format!(
            "release {} is already registered",
            m.version.trim()
        )));
    }
    audit::log(
        &st.db,
        &p.actor(),
        "update.release_register",
        id.to_string(),
        json!({"version": m.version, "url": m.url, "sha256": m.sha256, "key_fingerprint": updates::key_fingerprint(&st)}),
    )
    .await;
    st.publish("update_release", id, "created");
    Ok(Json(one(&st, id).await?))
}

#[derive(Deserialize)]
pub struct PromoteBody {
    ring: String,
}

pub async fn promote(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PromoteBody>,
) -> ApiResult<Json<Value>> {
    p.require("updates.write")?;
    let id = parse_uuid(&id)?;
    let ring = UpdateRing::parse(&b.ring)
        .ok_or_else(|| ApiError::bad_request("ring must be canary, early or broad"))?;
    let mut tx = st.db.begin().await?;
    // Serialise promotions of one release.
    let rel: Option<(String, Option<i64>)> =
        sqlx::query_as("SELECT version, halted_at FROM agent_releases WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((version, halted)) = rel else {
        return Err(ApiError::not_found("release not found"));
    };
    if halted.is_some() {
        return Err(ApiError::conflict(
            "this release was halted; register a newer release instead",
        ));
    }
    let enabled: Vec<(String,)> =
        sqlx::query_as("SELECT ring FROM agent_release_rings WHERE release_id = $1")
            .bind(id)
            .fetch_all(&mut *tx)
            .await?;
    let has = |r: UpdateRing| enabled.iter().any(|e| e.0 == r.as_str());
    if has(ring) {
        return Err(ApiError::conflict(format!(
            "release {version} is already enabled for the {} ring",
            ring.as_str()
        )));
    }
    if let Some(missing) = UpdateRing::ALL[..ring.index()].iter().find(|r| !has(**r)) {
        return Err(ApiError::conflict(format!(
            "promote rings in order: enable the {} ring before {}",
            missing.as_str(),
            ring.as_str()
        )));
    }
    sqlx::query(
        "INSERT INTO agent_release_rings (release_id, ring, enabled_at, enabled_by) VALUES ($1,$2,$3,$4)",
    )
    .bind(id)
    .bind(ring.as_str())
    .bind(now_ms())
    .bind(p.user.id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    let delivered = updates::deliver_to_connected(&st, Scope::Ring(ring)).await?;
    audit::log(
        &st.db,
        &p.actor(),
        "update.release_promote",
        id.to_string(),
        json!({"version": version, "ring": ring.as_str(), "delivered_now": delivered}),
    )
    .await;
    st.publish("update_release", id, "updated");
    let mut v = one(&st, id).await?;
    v["delivered_now"] = delivered.into();
    Ok(Json(v))
}

#[derive(Deserialize, Default)]
pub struct HaltBody {
    #[serde(default)]
    reason: String,
}

pub async fn halt(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    body: Option<ApiJson<HaltBody>>,
) -> ApiResult<Json<Value>> {
    p.require("updates.write")?;
    let id = parse_uuid(&id)?;
    let reason: String = body
        .map(|b| b.0.reason)
        .unwrap_or_default()
        .trim()
        .chars()
        .take(1000)
        .collect();
    let r: Option<(String,)> = sqlx::query_as(
        "UPDATE agent_releases SET halted_at = $2, halted_by = $3, halt_reason = $4 \
         WHERE id = $1 AND halted_at IS NULL RETURNING version",
    )
    .bind(id)
    .bind(now_ms())
    .bind(p.user.id)
    .bind(&reason)
    .fetch_optional(&st.db)
    .await?;
    let Some((version,)) = r else {
        return match updates::load_release(&st.db, id).await? {
            Some(_) => Err(ApiError::conflict("release is already halted")),
            None => Err(ApiError::not_found("release not found")),
        };
    };
    audit::log(
        &st.db,
        &p.actor(),
        "update.release_halt",
        id.to_string(),
        json!({"version": version, "reason": reason}),
    )
    .await;
    st.publish("update_release", id, "updated");
    Ok(Json(one(&st, id).await?))
}
