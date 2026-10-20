use super::{csv, list_response, page, parse_uuid, ApiJson, ApiPath, ApiQuery, Arg, Filter};
use crate::{
    api::devices::like_escape,
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    models::{action_select, ActionRow, AlertRow, ALERT_SELECT},
    state::AppState,
};
use axum::{extract::State, Json};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct AlertFilters {
    status: Option<String>,
    severity: Option<String>,
    device_id: Option<String>,
    incident_id: Option<String>,
    rule_id: Option<String>,
    assignee: Option<String>,
    q: Option<String>,
    sort: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<i64>,
    cursor: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<AlertFilters>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    let s = csv(&q.status);
    if !s.is_empty() {
        f.push("a.status = ANY(?)", vec![Arg::Strs(s)]);
    }
    let sev = csv(&q.severity);
    if !sev.is_empty() {
        f.push("a.severity = ANY(?)", vec![Arg::Strs(sev)]);
    }
    if let Some(d) = q.device_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("a.device_id = ?", vec![Arg::Uuid(parse_uuid(d)?)]);
    }
    if let Some(i) = q.incident_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("a.incident_id = ?", vec![Arg::Uuid(parse_uuid(i)?)]);
    }
    let rules = csv(&q.rule_id);
    if !rules.is_empty() {
        f.push("a.rule_id = ANY(?)", vec![Arg::Strs(rules)]);
    }
    match q.assignee.as_deref() {
        None | Some("") => {}
        Some("me") => f.push(
            "a.incident_id IN (SELECT id FROM incidents WHERE assignee_id = ?)",
            vec![Arg::Uuid(p.user.id)],
        ),
        Some(id) => f.push(
            "a.incident_id IN (SELECT id FROM incidents WHERE assignee_id = ?)",
            vec![Arg::Uuid(parse_uuid(id)?)],
        ),
    }
    if let Some(from) = q.from {
        f.push("a.ts >= ?", vec![Arg::Int(from)]);
    }
    if let Some(to) = q.to {
        f.push("a.ts <= ?", vec![Arg::Int(to)]);
    }
    if let Some(text) = q.q.as_ref().filter(|s| !s.trim().is_empty()) {
        let pat = format!("%{}%", like_escape(text.trim()));
        f.push(
            "(a.rule_name ILIKE ? OR a.rule_id ILIKE ? OR a.summary ILIKE ? OR a.image ILIKE ? OR d.hostname ILIKE ?)",
            vec![Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat)],
        );
    }
    let order = match q.sort.as_deref() {
        Some("severity") | Some("priority") => "a.severity_rank DESC, a.ts DESC, a.id",
        _ => "a.ts DESC, a.id",
    };
    let w = f.where_sql();
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM ({ALERT_SELECT} WHERE {w}) x"
        )))
        .fetch_one(&st.db)
        .await?;
    let rows: Vec<AlertRow> = f
        .bind(sqlx::query_as(&format!(
            "{ALERT_SELECT} WHERE {w} ORDER BY {order} LIMIT {} OFFSET {}",
            pg.limit, pg.offset
        )))
        .fetch_all(&st.db)
        .await?;
    Ok(Json(list_response(
        rows.iter().map(|a| a.to_api()).collect(),
        total,
        &pg,
    )))
}

pub async fn detail(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    let row: Option<(Value, Option<Uuid>, Uuid, String, String)> = sqlx::query_as(
        "SELECT a.body, a.incident_id, a.device_id, d.hostname, a.status FROM alerts a JOIN devices d ON d.id = a.device_id WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    let (mut body, incident_id, device_id, hostname, status) =
        row.ok_or_else(|| ApiError::not_found("alert not found"))?;
    if let Some(o) = body.as_object_mut() {
        o.insert("incident_id".into(), json!(incident_id));
        o.insert("device_id".into(), json!(device_id));
        o.insert("hostname".into(), json!(hostname));
        o.insert("status".into(), json!(status));
    }
    Ok(Json(body))
}

#[derive(Deserialize)]
pub struct BulkBody {
    ids: Vec<Uuid>,
    status: String,
}

pub async fn bulk_update(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(b): ApiJson<BulkBody>,
) -> ApiResult<Json<Value>> {
    p.require("incidents.write")?;
    if !["new", "acknowledged", "closed"].contains(&b.status.as_str()) {
        return Err(ApiError::bad_request("invalid status"));
    }
    if b.ids.is_empty() || b.ids.len() > 1000 {
        return Err(ApiError::bad_request("ids must contain 1-1000 alert ids"));
    }
    let updated: Vec<(Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE alerts SET status = $2 WHERE id = ANY($1) RETURNING id, incident_id",
    )
    .bind(&b.ids)
    .bind(&b.status)
    .fetch_all(&st.db)
    .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "alert.bulk_update",
        format!("{} alerts", updated.len()),
        json!({"ids": b.ids, "status": b.status}),
    )
    .await;
    for (id, _) in &updated {
        st.publish("alert", id, "updated");
    }
    Ok(Json(json!({"updated": updated.len()})))
}

#[derive(Deserialize)]
pub struct ActionFilters {
    device_id: Option<String>,
    incident_id: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

pub async fn list_actions(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<ActionFilters>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    if let Some(d) = q.device_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("r.device_id = ?", vec![Arg::Uuid(parse_uuid(d)?)]);
    }
    if let Some(i) = q.incident_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("r.incident_id = ?", vec![Arg::Uuid(parse_uuid(i)?)]);
    }
    let s = csv(&q.status);
    if !s.is_empty() {
        f.push("r.status = ANY(?)", vec![Arg::Strs(s)]);
    }
    let w = f.where_sql();
    let base = action_select();
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM ({base} WHERE {w}) x"
        )))
        .fetch_one(&st.db)
        .await?;
    let rows: Vec<ActionRow> = f
        .bind(sqlx::query_as(&format!(
            "{base} WHERE {w} ORDER BY r.created_at DESC, r.id LIMIT {} OFFSET {}",
            pg.limit, pg.offset
        )))
        .fetch_all(&st.db)
        .await?;
    Ok(Json(list_response(
        rows.iter().map(|a| a.to_api()).collect(),
        total,
        &pg,
    )))
}
