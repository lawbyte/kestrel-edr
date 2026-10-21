use super::{csv, list_response, page, parse_uuid, ApiJson, ApiPath, ApiQuery, Arg, Filter};
use crate::{
    api::dashboard::{HARDENING_CONTROLS, REPORT_ONLY_CONTROLS},
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    ingest,
    models::{self, load_device, AlertRow, DeviceRow, ALERT_SELECT, DEVICE_SELECT},
    policy_svc,
    state::AppState,
    telemetry::{reconstruct_processes, EventQuery},
};
use axum::{extract::State, http::StatusCode, Json};
use kestrel_common::{now_ms, wire::AgentHealth, ResponseAction};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct ListQuery {
    q: Option<String>,
    status: Option<String>,
    group_id: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    f.push("TRUE", vec![]);
    if let Some(text) = q.q.as_ref().filter(|s| !s.trim().is_empty()) {
        let pat = format!("%{}%", like_escape(text.trim()));
        f.push(
            "(d.hostname ILIKE ? OR COALESCE(d.logged_on_user,'') ILIKE ? OR array_to_string(d.ip_addresses, ' ') ILIKE ? OR array_to_string(d.tags, ' ') ILIKE ?)",
            vec![Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat.clone()), Arg::Str(pat)],
        );
    }
    let statuses = csv(&q.status);
    if !statuses.is_empty() {
        f.push(
            "device_status(d.health, d.last_seen, d.etw_lost_increased_at) = ANY(?)",
            vec![Arg::Strs(statuses)],
        );
    }
    if let Some(g) = q.group_id.as_ref().filter(|s| !s.is_empty()) {
        f.push("d.group_id = ?", vec![Arg::Uuid(parse_uuid(g)?)]);
    }
    let w = f.where_sql();
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM ({DEVICE_SELECT} AND {w}) x"
        )))
        .fetch_one(&st.db)
        .await?;
    let rows: Vec<DeviceRow> = f
        .bind(sqlx::query_as(&format!(
            "{DEVICE_SELECT} AND {w} ORDER BY d.hostname, d.id LIMIT {} OFFSET {}",
            pg.limit, pg.offset
        )))
        .fetch_all(&st.db)
        .await?;
    Ok(Json(list_response(
        rows.iter().map(|d| d.to_api()).collect(),
        total,
        &pg,
    )))
}

pub fn like_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

pub async fn detail(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    let d = load_device(&st.db, id).await?;
    let (inventory,): (Value,) = sqlx::query_as("SELECT inventory FROM devices WHERE id = $1")
        .bind(id)
        .fetch_one(&st.db)
        .await?;
    let inv: kestrel_common::wire::Inventory =
        serde_json::from_value(inventory).unwrap_or_default();
    let alerts: Vec<AlertRow> = sqlx::query_as(&format!(
        "{ALERT_SELECT} WHERE a.device_id = $1 ORDER BY a.ts DESC LIMIT 20"
    ))
    .bind(id)
    .fetch_all(&st.db)
    .await?;
    let pid = policy_svc::device_policy_id(&st.db, id).await?;
    let policy = policy_svc::effective(&st.db, &pid).await?;
    let health: AgentHealth = serde_json::from_value(d.health.clone()).unwrap_or_default();
    let mut hardening = vec![];
    if let Some(pol) = &policy {
        let hv = serde_json::to_value(&pol.hardening)?;
        let mode = hv
            .get("mode")
            .and_then(|m| m.as_str())
            .unwrap_or("audit")
            .to_string();
        for c in HARDENING_CONTROLS {
            let desired = hv.get(*c).and_then(|v| v.as_bool()).unwrap_or(false) && mode != "off";
            let mut row = json!({
                "control": c,
                "desired": desired,
                "applied": health.hardening.get(*c).copied(),
                "source": format!("policy:{} ({})", pol.name, mode),
            });
            if REPORT_ONLY_CONTROLS.contains(c) {
                row["report_only"] = true.into();
            }
            // Agents report a control that is configured but waits for a
            // reboot (LSA protection) as `<control>_pending_reboot`.
            if health
                .hardening
                .get(&format!("{c}_pending_reboot"))
                .copied()
                .unwrap_or(false)
            {
                row["pending_reboot"] = true.into();
            }
            hardening.push(row);
        }
    }
    let dups: Vec<(Uuid, String, i64, i64, Option<i64>)> = sqlx::query_as(
        "SELECT id, hostname, first_seen, last_seen, decommissioned_at FROM devices WHERE id = ANY($1) ORDER BY first_seen",
    )
    .bind(&d.possible_duplicate_ids)
    .fetch_all(&st.db)
    .await?;
    let duplicates: Vec<Value> = dups
        .into_iter()
        .map(|(id, hostname, first_seen, last_seen, decom)| json!({"id": id, "hostname": hostname, "first_seen": first_seen, "last_seen": last_seen, "decommissioned": decom.is_some()}))
        .collect();
    Ok(Json(json!({
        "device": d.to_api(),
        "duplicates": duplicates,
        "inventory": inv,
        "recent_alerts": alerts.iter().map(|a| a.to_api()).collect::<Vec<_>>(),
        "effective_policy": policy,
        "hardening": hardening,
    })))
}

#[derive(Deserialize)]
pub struct PatchDevice {
    group_id: Option<Uuid>,
    tags: Option<Vec<String>>,
}

pub async fn update(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<PatchDevice>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let before = load_device(&st.db, id).await?;
    if let Some(tags) = &b.tags {
        let tags: Vec<String> = tags
            .iter()
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty() && t.len() <= 64)
            .take(50)
            .collect();
        sqlx::query("UPDATE devices SET tags = $2 WHERE id = $1")
            .bind(id)
            .bind(&tags)
            .execute(&st.db)
            .await?;
    }
    if let Some(g) = b.group_id {
        let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE id = $1")
            .bind(g)
            .fetch_optional(&st.db)
            .await?;
        if exists.is_none() {
            return Err(ApiError::bad_request("group does not exist"));
        }
        if before.group_id != Some(g) {
            sqlx::query("UPDATE devices SET group_id = $2 WHERE id = $1")
                .bind(id)
                .bind(g)
                .execute(&st.db)
                .await?;
            // A fresh version guarantees the agent accepts the (possibly older) new policy.
            let pid = policy_svc::device_policy_id(&st.db, id).await?;
            policy_svc::bump_and_push(&st, Some(&pid)).await?;
        }
    }
    audit::log(
        &st.db,
        &p.actor(),
        "device.update",
        id.to_string(),
        json!({"group_id": b.group_id, "tags": b.tags, "hostname": before.hostname}),
    )
    .await;
    st.publish("device", id, "updated");
    Ok(Json(load_device(&st.db, id).await?.to_api()))
}

pub async fn decommission(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<StatusCode> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let d = load_device(&st.db, id).await?;
    let now = now_ms();
    let mut tx = st.db.begin().await?;
    sqlx::query(
        "UPDATE agent_certs SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "UPDATE devices SET decommissioned_at = $2, possible_duplicate_ids = '{}' WHERE id = $1",
    )
    .bind(id)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET possible_duplicate_ids = array_remove(possible_duplicate_ids, $1) WHERE $1 = ANY(possible_duplicate_ids)")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE response_actions SET status = 'expired', completed_at = $2, result_detail = 'device decommissioned' WHERE device_id = $1 AND status IN ('pending','sent')")
        .bind(id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    st.agents.disconnect(id);
    audit::log(
        &st.db,
        &p.actor(),
        "device.decommission",
        id.to_string(),
        json!({"hostname": d.hostname}),
    )
    .await;
    st.publish("device", id, "updated");
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct EventsQuery {
    kinds: Option<String>,
    q: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<u32>,
}

pub async fn events(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<EventsQuery>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    load_device(&st.db, id).await?;
    let eq = EventQuery {
        device_id: Some(id),
        kinds: csv(&q.kinds),
        text: q.q.clone(),
        from: q.from,
        to: q.to,
        limit: q.limit.unwrap_or(200).clamp(1, 5000),
        ..Default::default()
    };
    let rows = st.events.query(&eq).await.map_err(|e| {
        tracing::error!(error = %e, "event query failed");
        ApiError::internal("telemetry query failed")
    })?;
    let items = crate::telemetry::events_to_api(st.events.as_ref(), &rows, false).await;
    Ok(Json(json!({ "items": items })))
}

#[derive(Deserialize)]
pub struct ProcQuery {
    at: Option<i64>,
}

pub async fn processes(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<ProcQuery>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    load_device(&st.db, id).await?;
    let at = q.at.unwrap_or_else(now_ms);
    let eq = EventQuery {
        device_id: Some(id),
        kinds: vec!["process_start".into(), "process_stop".into()],
        to: Some(at),
        limit: 10_000,
        ..Default::default()
    };
    let rows = st.events.query(&eq).await.map_err(|e| {
        tracing::error!(error = %e, "process query failed");
        ApiError::internal("telemetry query failed")
    })?;
    Ok(Json(json!({"items": reconstruct_processes(&rows, at)})))
}

#[derive(Deserialize)]
pub struct ActionBody {
    action: ResponseAction,
    incident_id: Option<Uuid>,
    #[serde(default)]
    comment: Option<String>,
}

pub async fn create_action(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<ActionBody>,
) -> ApiResult<Json<Value>> {
    p.require(b.action.privilege())?;
    validate_manual_action(&b.action)?;
    let id = parse_uuid(&id)?;
    let d = load_device(&st.db, id).await?;
    if let Some(inc) = b.incident_id {
        let ok: Option<(Uuid,)> =
            sqlx::query_as("SELECT id FROM incidents WHERE id = $1 AND device_id = $2")
                .bind(inc)
                .bind(id)
                .fetch_optional(&st.db)
                .await?;
        if ok.is_none() {
            return Err(ApiError::bad_request(
                "incident does not belong to this device",
            ));
        }
    }
    let comment = b.comment.unwrap_or_default();
    let aid = ingest::enqueue_command(&st, id, b.incident_id, &b.action, Some(p.user.id), &comment)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "device.action",
        id.to_string(),
        json!({"action": b.action, "incident_id": b.incident_id, "comment": comment, "hostname": d.hostname, "action_id": aid}),
    )
    .await;
    Ok(Json(models::load_action(&st.db, aid).await?.to_api()))
}

/// L11: process actions are addressed by process GUID (PID + start time), never
/// by a bare PID that may be reused during the command's 7-day lifetime.
pub fn validate_manual_action(a: &ResponseAction) -> ApiResult<()> {
    match a {
        ResponseAction::KillProcess { guid, .. }
        | ResponseAction::SuspendProcess { guid, .. }
        | ResponseAction::ResumeProcess { guid, .. } => {
            if guid.as_ref().map(|g| g.0.trim().is_empty()).unwrap_or(true) {
                return Err(ApiError::bad_request(
                    "process actions need the process guid (a PID alone may be reused)",
                ));
            }
        }
        ResponseAction::BlockDestination { ip, .. } if ip.parse::<std::net::IpAddr>().is_err() => {
            return Err(ApiError::bad_request(
                "block_destination needs a single IP address",
            ));
        }
        ResponseAction::RemoveAutorun {
            kind,
            location,
            value_name,
            restore_data,
        } => validate_remove_autorun(
            *kind,
            location,
            value_name.as_deref(),
            restore_data.as_deref(),
        )?,
        _ => {}
    }
    Ok(())
}

/// V-H2: `remove_autorun` is limited to known autorun locations and, for
/// writes, to the canonical Windows default of that exact value (see
/// [`crate::autorun_policy`]). The agent re-checks everything itself.
fn validate_remove_autorun(
    kind: kestrel_common::AutorunKind,
    location: &str,
    value_name: Option<&str>,
    restore_data: Option<&str>,
) -> ApiResult<()> {
    crate::autorun_policy::validate(kind, location, value_name, restore_data)
        .map_err(ApiError::bad_request)
}

// ---------------------------------------------------------------- uninstall token (M5)

async fn sealed_tokens(
    st: &AppState,
    id: Uuid,
) -> ApiResult<(Option<String>, Option<String>, String)> {
    let row: Option<(Option<String>, Option<String>, String)> = sqlx::query_as(
        "SELECT uninstall_token_enc, uninstall_token_pending_enc, hostname FROM devices WHERE id = $1 AND decommissioned_at IS NULL",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    row.ok_or_else(|| ApiError::not_found("device not found"))
}

/// `POST /devices/:id/uninstall-token/reveal` — show the device's uninstall token
/// (`devices.write`); every reveal is audit-logged.
pub async fn reveal_uninstall_token(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let (cur, pending, hostname) = sealed_tokens(&st, id).await?;
    let open = |v: Option<String>| -> ApiResult<Option<String>> {
        Ok(v.map(|e| st.mk.open_str(&e)).transpose()?)
    };
    let (cur, pending) = (open(cur)?, open(pending)?);
    if cur.is_none() && pending.is_none() {
        return Err(ApiError::not_found(
            "this device has no server-issued uninstall token (enrolled by an older server); rotate to create one",
        ));
    }
    audit::log(
        &st.db,
        &p.actor(),
        "device.uninstall_token_revealed",
        id.to_string(),
        json!({"hostname": hostname, "ip": p.ip, "pending": pending.is_some()}),
    )
    .await;
    Ok(Json(json!({"token": cur, "pending_token": pending})))
}

/// `POST /devices/:id/uninstall-token/rotate` — generate a new uninstall token.
/// It is held as `pending_token` and sent to the agent
/// (`ServerPayload::SetUninstallToken`) now if it is connected, otherwise on its
/// next connect. When the agent acks that message the token becomes current;
/// until then the previous token keeps working on the endpoint.
pub async fn rotate_uninstall_token(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    let (_, _, hostname) = sealed_tokens(&st, id).await?;
    let token = crate::grpc::new_uninstall_token();
    sqlx::query("UPDATE devices SET uninstall_token_pending_enc = $2 WHERE id = $1")
        .bind(id)
        .bind(st.mk.seal_str(&token))
        .execute(&st.db)
        .await?;
    audit::log(
        &st.db,
        &p.actor(),
        "device.uninstall_token_rotated",
        id.to_string(),
        json!({"hostname": hostname}),
    )
    .await;
    let sent = st.agents.send(
        &id,
        kestrel_common::wire::ServerPayload::SetUninstallToken {
            token: token.clone(),
        },
    );
    st.publish("device", id, "updated");
    let message = if sent {
        "New token sent to the agent. It becomes current as soon as the agent confirms it; until then the previous token keeps working."
    } else {
        "The device is offline: the new token is sent when the agent next connects. Until the agent confirms it, the previous token keeps working."
    };
    Ok(Json(
        json!({"pending_token": token, "token_active": false, "sent": sent,
        "message": message}),
    ))
}

// ---------------------------------------------------------------- duplicates (H2)

#[derive(Deserialize)]
pub struct OtherDevice {
    device_id: Uuid,
}

/// `POST /devices/:id/merge {device_id}` — fold the other device's history
/// (alerts, incidents, actions, quarantine, reviews) into this one and
/// decommission the other device (its certificates are revoked).
pub async fn merge(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<OtherDevice>,
) -> ApiResult<Json<Value>> {
    p.require("devices.write")?;
    let keep = parse_uuid(&id)?;
    let from = b.device_id;
    if keep == from {
        return Err(ApiError::bad_request("cannot merge a device into itself"));
    }
    let k = load_device(&st.db, keep).await?;
    let f: Option<(String,)> = sqlx::query_as("SELECT hostname FROM devices WHERE id = $1")
        .bind(from)
        .fetch_optional(&st.db)
        .await?;
    let (from_host,) = f.ok_or_else(|| ApiError::not_found("device to merge not found"))?;
    let now = now_ms();
    let mut tx = st.db.begin().await?;
    for table in [
        "alerts",
        "incidents",
        "response_actions",
        "quarantine_items",
        "review_requests",
    ] {
        sqlx::query(&format!(
            "UPDATE {table} SET device_id = $1 WHERE device_id = $2"
        ))
        .bind(keep)
        .bind(from)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("DELETE FROM pending_messages WHERE device_id = $1")
        .bind(from)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE agent_certs SET revoked_at = $2 WHERE device_id = $1 AND revoked_at IS NULL",
    )
    .bind(from)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET decommissioned_at = COALESCE(decommissioned_at, $2), possible_duplicate_ids = '{}' WHERE id = $1")
        .bind(from)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE devices SET possible_duplicate_ids = array_remove(possible_duplicate_ids, $1) WHERE $1 = ANY(possible_duplicate_ids)")
        .bind(from)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE devices SET first_seen = LEAST(first_seen, (SELECT first_seen FROM devices WHERE id = $2)) WHERE id = $1")
        .bind(keep)
        .bind(from)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    st.agents.disconnect(from);
    audit::log(
        &st.db,
        &p.actor(),
        "device.merge",
        keep.to_string(),
        json!({"kept": keep, "kept_hostname": k.hostname, "merged": from, "merged_hostname": from_host}),
    )
    .await;
    st.publish("device", keep, "updated");
    st.publish("device", from, "updated");
    Ok(Json(load_device(&st.db, keep).await?.to_api()))
}

/// `POST /devices/:id/duplicates/dismiss {device_id}` — the two devices are
/// distinct machines (e.g. cloned VM templates); clear the flag on both.
pub async fn dismiss_duplicate(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiJson(b): ApiJson<OtherDevice>,
) -> ApiResult<StatusCode> {
    p.require("devices.write")?;
    let id = parse_uuid(&id)?;
    load_device(&st.db, id).await?;
    for (a, other) in [(id, b.device_id), (b.device_id, id)] {
        sqlx::query("UPDATE devices SET possible_duplicate_ids = array_remove(possible_duplicate_ids, $2) WHERE id = $1")
            .bind(a)
            .bind(other)
            .execute(&st.db)
            .await?;
    }
    audit::log(
        &st.db,
        &p.actor(),
        "device.duplicate_dismissed",
        id.to_string(),
        json!({"other": b.device_id}),
    )
    .await;
    st.publish("device", id, "updated");
    st.publish("device", b.device_id, "updated");
    Ok(StatusCode::NO_CONTENT)
}
