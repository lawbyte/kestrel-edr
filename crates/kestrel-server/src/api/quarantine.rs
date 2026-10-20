use super::{csv, parse_uuid, ApiJson, ApiPath, ApiQuery};
use crate::{
    api::policies::{insert_exclusion, review_exclusion, ExclusionScope},
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    ingest, models,
    state::AppState,
};
use axum::{extract::State, Json};
use kestrel_common::{now_ms, wire::ServerPayload, Alert, ResponseAction};

/// Review-approval exclusions expire unless renewed (M2).
pub const REVIEW_EXCLUSION_TTL_MS: i64 = 90 * 86_400_000;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct QRow {
    id: String,
    device_id: Uuid,
    hostname: String,
    sha256: Option<String>,
    original_path: String,
    alert_id: Option<Uuid>,
    state: String,
    created_at: i64,
}

impl QRow {
    fn to_api(&self) -> Value {
        json!({"id": self.id, "device_id": self.device_id, "hostname": self.hostname, "sha256": self.sha256,
               "original_path": self.original_path, "alert_id": self.alert_id, "state": self.state, "created_at": self.created_at})
    }
}

const Q_SELECT: &str = "SELECT q.id, q.device_id, d.hostname, q.sha256, q.original_path, q.alert_id, q.state, q.created_at \
    FROM quarantine_items q JOIN devices d ON d.id = q.device_id";

#[derive(Deserialize)]
pub struct QFilter {
    state: Option<String>,
    device_id: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<QFilter>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let states = csv(&q.state);
    let device = q
        .device_id
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(parse_uuid)
        .transpose()?;
    let rows: Vec<QRow> = sqlx::query_as(&format!(
        "{Q_SELECT} WHERE (cardinality($1::text[]) = 0 OR q.state = ANY($1)) AND ($2::uuid IS NULL OR q.device_id = $2) ORDER BY q.created_at DESC LIMIT 5000"
    ))
    .bind(&states)
    .bind(device)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| r.to_api()).collect(),
    )))
}

async fn quarantine_cmd(
    st: &AppState,
    p: &Principal,
    id: &str,
    restore: bool,
) -> ApiResult<Json<Value>> {
    p.require("response.file")?;
    let item: QRow = sqlx::query_as(&format!("{Q_SELECT} WHERE q.id = $1"))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("quarantine item not found"))?;
    if item.state != "held" {
        return Err(ApiError::conflict(format!(
            "item is already {}",
            item.state
        )));
    }
    let action = if restore {
        ResponseAction::RestoreFile {
            quarantine_id: item.id.clone(),
        }
    } else {
        ResponseAction::DeleteQuarantined {
            quarantine_id: item.id.clone(),
        }
    };
    let incident: Option<(Option<Uuid>,)> = match item.alert_id {
        Some(a) => {
            sqlx::query_as("SELECT incident_id FROM alerts WHERE id = $1")
                .bind(a)
                .fetch_optional(&st.db)
                .await?
        }
        None => None,
    };
    let comment = format!(
        "{} {}",
        if restore { "Restore" } else { "Delete" },
        item.original_path
    );
    let aid = ingest::enqueue_command(
        st,
        item.device_id,
        incident.and_then(|i| i.0),
        &action,
        Some(p.user.id),
        &comment,
    )
    .await?;
    audit::log(&st.db, &p.actor(), if restore { "quarantine.restore" } else { "quarantine.delete" }, &item.id, json!({"device_id": item.device_id, "path": item.original_path, "sha256": item.sha256, "action_id": aid})).await;
    Ok(Json(models::load_action(&st.db, aid).await?.to_api()))
}

pub async fn restore(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    quarantine_cmd(&st, &p, &id, true).await
}

pub async fn delete_item(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    quarantine_cmd(&st, &p, &id, false).await
}

// ---------------------------------------------------------------- review requests

#[derive(sqlx::FromRow)]
struct RRow {
    id: Uuid,
    device_id: Uuid,
    hostname: String,
    user_name: String,
    alert_id: Uuid,
    rule_name: Option<String>,
    file: Option<String>,
    justification: String,
    state: String,
    decided_by: Option<String>,
    decided_at: Option<i64>,
    decision_message: Option<String>,
    created_at: i64,
    rule_id: Option<String>,
    sha256: Option<String>,
    signer: Option<String>,
    signed: Option<String>,
    policy_id: Option<String>,
    policy_name: Option<String>,
}

impl RRow {
    /// What approving with `create_exclusion` would create (null: not possible).
    fn scope(&self) -> Option<ExclusionScope> {
        let (kind, value) = review_exclusion(
            self.sha256.as_deref(),
            self.signer.as_deref(),
            self.signed.as_deref() == Some("valid"),
        )?;
        let rule_id = self.rule_id.clone()?;
        if rule_id.starts_with("TP-") {
            return None;
        }
        Some(ExclusionScope {
            kind,
            value,
            rule_id,
            policy_id: self.policy_id.clone()?,
            policy_name: self.policy_name.clone().unwrap_or_default(),
        })
    }

    fn to_api(&self) -> Value {
        json!({"id": self.id, "device_id": self.device_id, "hostname": self.hostname, "user": self.user_name, "alert_id": self.alert_id,
               "rule_name": self.rule_name, "file": self.file, "justification": self.justification, "state": self.state,
               "decided_by": self.decided_by, "decided_at": self.decided_at, "decision_message": self.decision_message,
               "created_at": self.created_at, "exclusion_scope": self.scope().map(|s| s.to_api())})
    }
}

const R_SELECT: &str = "SELECT r.id, r.device_id, d.hostname, r.user_name, r.alert_id, a.rule_name, a.image AS file, r.justification, r.state, \
    u.email AS decided_by, r.decided_at, r.decision_message, r.created_at, \
    a.rule_id, a.sha256, a.signer, a.body->'process'->>'signed' AS signed, p.id AS policy_id, p.name AS policy_name \
    FROM review_requests r JOIN devices d ON d.id = r.device_id \
    LEFT JOIN alerts a ON a.id = r.alert_id AND a.device_id = r.device_id \
    LEFT JOIN groups g ON g.id = d.group_id \
    LEFT JOIN policies p ON p.id = COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) \
    LEFT JOIN users u ON u.id = r.decided_by";

#[derive(Deserialize)]
pub struct RFilter {
    state: Option<String>,
}

pub async fn list_reviews(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<RFilter>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let states = csv(&q.state);
    let rows: Vec<RRow> = sqlx::query_as(&format!(
        "{R_SELECT} WHERE cardinality($1::text[]) = 0 OR r.state = ANY($1) ORDER BY r.created_at DESC LIMIT 5000"
    ))
    .bind(&states)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(Value::Array(
        rows.iter().map(|r| r.to_api()).collect(),
    )))
}

#[derive(Deserialize)]
pub struct Decision {
    approved: bool,
    #[serde(default)]
    message: String,
    #[serde(default)]
    create_exclusion: bool,
}

pub async fn decide(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<Decision>,
) -> ApiResult<Json<Value>> {
    p.require("exclusions.write")?;
    let id = parse_uuid(&id)?;
    let rr: RRow = sqlx::query_as(&format!("{R_SELECT} WHERE r.id = $1"))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("review request not found"))?;
    if rr.state != "requested" {
        return Err(ApiError::conflict(format!("request already {}", rr.state)));
    }
    let mut exclusion_id = None;
    if b.approved && b.create_exclusion {
        // M2: only a hash (or valid signer) of this specific file, for this rule,
        // in the requesting device's group policy — never a path a user can write.
        let (body,): (Value,) =
            sqlx::query_as("SELECT body FROM alerts WHERE id = $1 AND device_id = $2")
                .bind(rr.alert_id)
                .bind(rr.device_id)
                .fetch_optional(&st.db)
                .await?
                .ok_or_else(|| {
                    ApiError::bad_request(
                "the alert for this request is not on the server; create the exclusion manually",
            )
                })?;
        let a: Alert = serde_json::from_value(body)
            .map_err(|_| ApiError::internal("stored alert unreadable"))?;
        let scope = rr.scope().ok_or_else(|| {
            ApiError::bad_request(
                "this file has no known hash or valid signature, so no safe exclusion can be created; approve without an exclusion",
            )
        })?;
        let reason = format!(
            "Review request from {} on {}: {}",
            rr.user_name,
            rr.hostname,
            rr.justification.chars().take(500).collect::<String>()
        );
        let ex = insert_exclusion(
            &st,
            &p,
            Some(scope.policy_id.clone()),
            scope.kind,
            &scope.value,
            Some(a.rule_id.clone()),
            Some(now_ms() + REVIEW_EXCLUSION_TTL_MS),
            &reason,
        )
        .await?;
        exclusion_id = Some(ex.id);
    }
    sqlx::query("UPDATE review_requests SET state = $2, decided_by = $3, decided_at = $4, decision_message = $5 WHERE id = $1")
        .bind(id)
        .bind(if b.approved { "approved" } else { "denied" })
        .bind(p.user.id)
        .bind(now_ms())
        .bind(&b.message)
        .execute(&st.db)
        .await?;
    ingest::deliver_or_queue(
        &st,
        rr.device_id,
        ServerPayload::ReviewDecision {
            alert_id: rr.alert_id,
            approved: b.approved,
            message: b.message.clone(),
        },
    )
    .await?;
    audit::log(&st.db, &p.actor(), "review.decision", id.to_string(), json!({"approved": b.approved, "message": b.message, "exclusion_id": exclusion_id, "device_id": rr.device_id, "alert_id": rr.alert_id})).await;
    st.publish("alert", rr.alert_id, "updated");
    let row: RRow = sqlx::query_as(&format!("{R_SELECT} WHERE r.id = $1"))
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    let mut v = row.to_api();
    v["exclusion_id"] = json!(exclusion_id);
    Ok(Json(v))
}
