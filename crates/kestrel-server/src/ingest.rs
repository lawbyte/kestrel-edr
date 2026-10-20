//! Handling of agent → server payloads on the live stream.

use crate::{
    audit::{self, Actor},
    incidents::{self, server_tamper_alert, COMMAND_TTL_MS},
    policy_svc,
    registry::{AgentConn, Outbound},
    state::AppState,
    telemetry::EventRow,
};
use kestrel_common::{
    now_ms,
    wire::{AgentHealth, Heartbeat, Hello, Inventory, ReviewRequest, ServerPayload},
    ActionOutcome, Alert, Event, ResponseAction, Severity,
};
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

/// Per-stream context.
pub struct Session {
    pub device_id: Uuid,
    pub hostname: String,
    pub conn: Arc<AgentConn>,
    /// Serial of the client certificate this stream authenticated with.
    pub serial: String,
}

/// Privacy settings of the device's effective policy.
pub async fn device_privacy(
    state: &AppState,
    device_id: Uuid,
) -> anyhow::Result<kestrel_common::Privacy> {
    let pid = policy_svc::device_policy_id(&state.db, device_id).await?;
    Ok(policy_svc::load_stored(&state.db, &pid)
        .await?
        .map(|p| p.privacy)
        .unwrap_or_default())
}

/// Key used to pseudonymise user names for this device, if its policy asks for it (M9).
pub async fn user_hasher(
    state: &AppState,
    device_id: Uuid,
) -> anyhow::Result<Option<&crate::crypto::MasterKey>> {
    Ok(device_privacy(state, device_id)
        .await?
        .hash_usernames
        .then_some(&state.mk))
}

/// ETW events lost between two heartbeats that raise a server-side tamper alert.
pub const EVENTS_LOST_ALERT_THRESHOLD: u64 = 500;
/// Minimum spacing between two server-side tamper alerts of the same kind.
pub const TAMPER_DEDUPE_MS: i64 = 3_600_000;

/// Process Hello: upsert device facts and build the initial messages
/// (Welcome, Policy/Rules when stale, pending commands and messages).
pub async fn hello(
    state: &AppState,
    device_id: Uuid,
    h: &Hello,
    peer_ip: Option<String>,
) -> anyhow::Result<Vec<Outbound>> {
    let now = now_ms();
    let prev: Option<(Option<String>, String, Option<Uuid>, i64)> =
        sqlx::query_as("SELECT boot_id, device_status(health, last_seen, etw_lost_increased_at), outbox_epoch, last_agent_seq FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
    let Some((prev_boot, prev_status, prev_epoch, prev_hwm)) = prev else {
        anyhow::bail!("unknown device {device_id}")
    };
    let rebooted = prev_boot.as_deref() != Some(h.boot_id.as_str());
    // M8: a new outbox (deleted / recreated database) restarts its seqs at 1.
    // Reset the high-water mark instead of discarding everything as duplicates.
    if let Some(epoch) = h.outbox_epoch {
        if prev_epoch != Some(epoch) {
            sqlx::query("UPDATE devices SET outbox_epoch = $2, last_agent_seq = CASE WHEN $3 THEN 0 ELSE last_agent_seq END WHERE id = $1")
                .bind(device_id)
                .bind(epoch)
                .bind(prev_epoch.is_some())
                .execute(&state.db)
                .await?;
            if prev_epoch.is_some() {
                raise_tamper(
                    state,
                    device_id,
                    "TP-SRV-OUTBOX-RESET",
                    "Agent outbox was reset",
                    Severity::High,
                    format!(
                        "The Kestrel agent on {} started a new outbox (its local queue database was deleted or recreated; {} messages had been received). \
                         Anything queued but not yet uploaded is lost: the agent state may have been tampered with.",
                        h.hostname, prev_hwm
                    ),
                )
                .await;
            }
        }
    }
    sqlx::query(
        "UPDATE devices SET hostname = $2, os_name = $3, os_build = $4, arch = $5, domain = $6, hw_uuid = COALESCE(hw_uuid, $7), \
         agent_version = $8, boot_id = $9, policy_version_applied = $10, rules_version_applied = $11, last_seen = $12, \
         last_hb_seq = CASE WHEN $13 THEN NULL ELSE last_hb_seq END, \
         ip_addresses = CASE WHEN cardinality(ip_addresses) = 0 AND $14::text IS NOT NULL THEN ARRAY[$14::text] ELSE ip_addresses END \
         WHERE id = $1",
    )
    .bind(device_id)
    .bind(&h.hostname)
    .bind(&h.os.name)
    .bind(&h.os.build)
    .bind(&h.os.arch)
    .bind(&h.os.domain)
    .bind(&h.os.hw_uuid)
    .bind(&h.agent_version)
    .bind(&h.boot_id)
    .bind(h.policy_version as i64)
    .bind(h.rules_version as i64)
    .bind(now)
    .bind(rebooted)
    .bind(peer_ip)
    .execute(&state.db)
    .await?;
    if prev_status == "offline" {
        state.publish("device", device_id, "updated");
    }

    let mut out = vec![ServerPayload::Welcome {
        device_id,
        server_time: now,
    }];
    let pid = policy_svc::device_policy_id(&state.db, device_id).await?;
    // Database restored from a backup? Never let agents ignore later changes.
    policy_svc::catch_up_versions(&state.db, &pid, h.policy_version, h.rules_version).await?;
    if let Some(p) = policy_svc::effective(&state.db, &pid).await? {
        if p.version != h.policy_version {
            out.push(ServerPayload::Policy(Box::new(p)));
        }
    }
    let bundle = policy_svc::rules_bundle(&state.db).await?;
    if bundle.version != h.rules_version {
        out.push(ServerPayload::Rules(bundle));
    }
    out.extend(pending_commands(state, device_id).await?);
    let msgs: Vec<(i64, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM pending_messages WHERE device_id = $1 AND expires_at > $2 RETURNING id, payload",
    )
    .bind(device_id)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let mut msgs = msgs;
    msgs.sort_by_key(|m| m.0);
    for (_, p) in msgs {
        if let Ok(p) = serde_json::from_value::<ServerPayload>(p) {
            out.push(p);
        }
    }
    // A rotated uninstall token stays pending until the agent acks it: re-send
    // it on every connect (never queued as plaintext in pending_messages).
    match pending_uninstall_token(state, device_id).await {
        Ok(Some((_, token))) => out.push(ServerPayload::SetUninstallToken { token }),
        Ok(None) => {}
        Err(e) => tracing::warn!(%device_id, error = %e, "pending uninstall token unreadable"),
    }
    Ok(out)
}

/// The device's pending (rotated, not yet confirmed) uninstall token:
/// `(sealed value, plaintext)`.
pub async fn pending_uninstall_token(
    state: &AppState,
    device_id: Uuid,
) -> anyhow::Result<Option<(String, String)>> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT uninstall_token_pending_enc FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
    match row.and_then(|r| r.0) {
        Some(enc) => {
            let token = state.mk.open_str(&enc)?;
            Ok(Some((enc, token)))
        }
        None => Ok(None),
    }
}

/// The agent acked `SetUninstallToken { token }`: it now verifies against
/// that token, so promote it from pending to current — unless the token was
/// rotated again in the meantime (the newer one stays pending).
async fn uninstall_token_confirmed(
    state: &AppState,
    device_id: Uuid,
    token: &str,
) -> anyhow::Result<()> {
    let Some((enc, pending)) = pending_uninstall_token(state, device_id).await? else {
        return Ok(());
    };
    if pending != token {
        return Ok(());
    }
    let promoted = sqlx::query(
        "UPDATE devices SET uninstall_token_enc = uninstall_token_pending_enc, uninstall_token_pending_enc = NULL \
         WHERE id = $1 AND uninstall_token_pending_enc = $2",
    )
    .bind(device_id)
    .bind(&enc)
    .execute(&state.db)
    .await?
    .rows_affected();
    if promoted == 1 {
        audit::log(
            &state.db,
            &Actor::system(),
            "device.uninstall_token_activated",
            device_id.to_string(),
            json!({}),
        )
        .await;
        state.publish("device", device_id, "updated");
    }
    Ok(())
}

/// Commands not yet delivered (pending, or sent on a stream that dropped before the Ack).
pub async fn pending_commands(state: &AppState, device_id: Uuid) -> anyhow::Result<Vec<Outbound>> {
    let now = now_ms();
    let rows: Vec<(Uuid, serde_json::Value)> = sqlx::query_as(
        "UPDATE response_actions SET status = 'sent', sent_at = $2 WHERE device_id = $1 AND status IN ('pending','sent') \
         AND delivered_at IS NULL AND completed_at IS NULL AND expires_at > $2 RETURNING id, action",
    )
    .bind(device_id)
    .bind(now)
    .fetch_all(&state.db)
    .await?;
    let mut out = vec![];
    for (id, action) in rows {
        if let Ok(action) = serde_json::from_value::<ResponseAction>(action) {
            out.push(ServerPayload::Command {
                command_id: id,
                action,
            });
            state.publish("action", id, "updated");
        }
    }
    Ok(out)
}

/// Queue a command for a device and deliver it now if the agent is connected.
pub async fn enqueue_command(
    state: &AppState,
    device_id: Uuid,
    incident_id: Option<Uuid>,
    action: &ResponseAction,
    requested_by: Option<Uuid>,
    comment: &str,
) -> anyhow::Result<Uuid> {
    let id = Uuid::new_v4();
    let now = now_ms();
    sqlx::query(
        "INSERT INTO response_actions (id, device_id, incident_id, action, action_type, status, requested_by, comment, created_at, expires_at) \
         VALUES ($1,$2,$3,$4,$5,'pending',$6,$7,$8,$9)",
    )
    .bind(id)
    .bind(device_id)
    .bind(incident_id)
    .bind(serde_json::to_value(action)?)
    .bind(action.name())
    .bind(requested_by)
    .bind(comment)
    .bind(now)
    .bind(now + COMMAND_TTL_MS)
    .execute(&state.db)
    .await?;
    if let Some(inc) = incident_id {
        sqlx::query("INSERT INTO incident_activity (incident_id, ts, kind, title, detail, actor_id) VALUES ($1,$2,'action',$3,$4,$5)")
            .bind(inc)
            .bind(now)
            .bind(format!("Requested: {}", incidents::describe_action(action)))
            .bind(comment)
            .bind(requested_by)
            .execute(&state.db)
            .await?;
        state.publish("incident", inc, "updated");
    }
    if state.agents.is_connected(&device_id) {
        let updated = sqlx::query("UPDATE response_actions SET status = 'sent', sent_at = $2 WHERE id = $1 AND status = 'pending'")
            .bind(id)
            .bind(now)
            .execute(&state.db)
            .await?
            .rows_affected();
        if updated == 1
            && !state.agents.send(
                &device_id,
                ServerPayload::Command {
                    command_id: id,
                    action: action.clone(),
                },
            )
        {
            // Channel full or just disconnected: leave for redelivery on the next connect.
            sqlx::query(
                "UPDATE response_actions SET status = 'pending', sent_at = NULL WHERE id = $1",
            )
            .bind(id)
            .execute(&state.db)
            .await?;
        }
    }
    state.publish("action", id, "created");
    Ok(id)
}

/// Deliver a non-command message now, or keep it for the next connect.
pub async fn deliver_or_queue(
    state: &AppState,
    device_id: Uuid,
    payload: ServerPayload,
) -> anyhow::Result<()> {
    if state.agents.send(&device_id, payload.clone()) {
        return Ok(());
    }
    let now = now_ms();
    sqlx::query("INSERT INTO pending_messages (device_id, payload, created_at, expires_at) VALUES ($1,$2,$3,$4)")
        .bind(device_id)
        .bind(serde_json::to_value(&payload)?)
        .bind(now)
        .bind(now + COMMAND_TTL_MS)
        .execute(&state.db)
        .await?;
    Ok(())
}

/// Agent acknowledged a server message we sent with this payload.
pub async fn server_message_acked(
    state: &AppState,
    device_id: Uuid,
    payload: &ServerPayload,
) -> anyhow::Result<()> {
    match payload {
        ServerPayload::Command { command_id, .. } => {
            sqlx::query("UPDATE response_actions SET delivered_at = $2 WHERE id = $1 AND delivered_at IS NULL")
                .bind(command_id)
                .bind(now_ms())
                .execute(&state.db)
                .await?;
        }
        ServerPayload::Policy(p) => {
            sqlx::query("UPDATE devices SET policy_version_applied = $2 WHERE id = $1")
                .bind(device_id)
                .bind(p.version as i64)
                .execute(&state.db)
                .await?;
        }
        ServerPayload::Rules(b) => {
            sqlx::query("UPDATE devices SET rules_version_applied = $2 WHERE id = $1")
                .bind(device_id)
                .bind(b.version as i64)
                .execute(&state.db)
                .await?;
        }
        ServerPayload::SetUninstallToken { token } => {
            uninstall_token_confirmed(state, device_id, token).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn tamper_due(state: &AppState, device_id: Uuid, rule: &str) -> anyhow::Result<bool> {
    let now = now_ms();
    // Atomically claim the alert slot for this rule.
    let r = sqlx::query(
        "UPDATE devices SET tamper_state = tamper_state || jsonb_build_object($2::text, $3::bigint) \
         WHERE id = $1 AND COALESCE((tamper_state->>$2)::bigint, 0) < $4",
    )
    .bind(device_id)
    .bind(rule)
    .bind(now)
    .bind(now - TAMPER_DEDUPE_MS)
    .execute(&state.db)
    .await?;
    Ok(r.rows_affected() == 1)
}

pub async fn raise_tamper(
    state: &AppState,
    device_id: Uuid,
    rule: &str,
    name: &str,
    sev: Severity,
    summary: String,
) {
    match tamper_due(state, device_id, rule).await {
        Ok(true) => {
            let alert = server_tamper_alert(rule, name, sev, summary);
            if let Err(e) = incidents::ingest_alert(state, device_id, alert).await {
                tracing::error!(error = %e, "failed to store server-side tamper alert");
            }
        }
        Ok(false) => {}
        Err(e) => tracing::error!(error = %e, "tamper dedupe failed"),
    }
}

pub async fn heartbeat(state: &AppState, s: &Session, hb: &Heartbeat) -> anyhow::Result<()> {
    let now = now_ms();
    let prev_hb = s.conn.touch_heartbeat(now);
    let prev: (Option<i64>, Option<i64>, serde_json::Value, String) = sqlx::query_as(
        "SELECT last_hb_seq, last_hb_ts, health, device_status(health, last_seen, etw_lost_increased_at) FROM devices WHERE id = $1",
    )
    .bind(s.device_id)
    .fetch_one(&state.db)
    .await?;
    let (prev_seq, _prev_ts, prev_health_v, prev_status) = prev;
    // M7: never trust the agent clock for ordering. Exact re-delivery of the same
    // heartbeat (same seq within a boot) is a duplicate; everything else is
    // processed on server receive time, and the agent timestamp is clamped.
    if prev_seq == Some(hb.seq as i64) {
        return Ok(());
    }
    let hb_ts = hb.ts.min(now);
    let mut health_in = hb.health.clone();
    if let Some(mk) = user_hasher(state, s.device_id).await? {
        if let Some(u) = health_in.logged_on_user.as_mut() {
            *u = mk.hash_username(u);
        }
    }
    let prev_health: Option<AgentHealth> = if prev_health_v
        .as_object()
        .map(|o| o.is_empty())
        .unwrap_or(true)
    {
        None
    } else {
        serde_json::from_value(prev_health_v).ok()
    };
    let lost_rising = prev_health
        .as_ref()
        .map(|p| hb.health.etw_events_lost > p.etw_events_lost)
        .unwrap_or(false);
    let health = serde_json::to_value(&health_in)?;
    let new_status: (String,) = sqlx::query_as(
        "UPDATE devices SET health = $2, last_seen = $3, last_hb_seq = $4, last_hb_ts = $5, \
         ip_addresses = CASE WHEN cardinality($6::text[]) > 0 THEN $6 ELSE ip_addresses END, \
         logged_on_user = COALESCE($7, logged_on_user), \
         etw_lost_increased_at = CASE WHEN $8 THEN $3 ELSE etw_lost_increased_at END \
         WHERE id = $1 RETURNING device_status(health, last_seen, etw_lost_increased_at)",
    )
    .bind(s.device_id)
    .bind(&health)
    .bind(now)
    .bind(hb.seq as i64)
    .bind(hb_ts)
    .bind(&hb.health.ip_addresses)
    .bind(&health_in.logged_on_user)
    .bind(lost_rising)
    .fetch_one(&state.db)
    .await?;
    if new_status.0 != prev_status {
        state.publish("device", s.device_id, "updated");
    }

    // ---- tamper heuristics (server-side TP alerts)
    if let Some(ps) = prev_seq {
        if (hb.seq as i64) < ps {
            raise_tamper(
                state,
                s.device_id,
                "TP-SRV-SEQ-RESET",
                "Agent heartbeat sequence reset without reboot",
                Severity::High,
                format!(
                    "The Kestrel agent on {} restarted its heartbeat counter ({} → {}) without a reboot: the agent service was stopped, reinstalled or its state was wiped.",
                    s.hostname, ps, hb.seq
                ),
            )
            .await;
        }
    }
    let interval = state.cfg.heartbeat_interval_ms;
    if prev_hb > 0 && now - prev_hb > 3 * interval {
        raise_tamper(
            state,
            s.device_id,
            "TP-SRV-HEARTBEAT",
            "Agent heartbeat gap while connected",
            Severity::Medium,
            format!(
                "The Kestrel agent on {} stayed connected but sent no heartbeat for {} s (expected every {} s): the agent may have been suspended or throttled.",
                s.hostname,
                (now - prev_hb) / 1000,
                interval / 1000
            ),
        )
        .await;
    }
    if let Some(p) = &prev_health {
        let delta = hb.health.etw_events_lost.saturating_sub(p.etw_events_lost);
        if delta >= EVENTS_LOST_ALERT_THRESHOLD {
            raise_tamper(
                state,
                s.device_id,
                "TP-SRV-EVENTS-LOST",
                "Agent telemetry loss rising",
                Severity::Medium,
                format!("ETW dropped {delta} events on {} since the previous heartbeat; detections may be blind.", s.hostname),
            )
            .await;
        }
    }
    let etw_was_ok = prev_health.as_ref().map(|p| p.etw_ok).unwrap_or(true);
    if !hb.health.etw_ok && etw_was_ok {
        raise_tamper(
            state,
            s.device_id,
            "TP-SRV-ETW",
            "Agent telemetry session not healthy",
            Severity::High,
            format!("The Kestrel agent on {} reports its ETW session is not running: telemetry and detections are degraded.", s.hostname),
        )
        .await;
    }
    Ok(())
}

pub async fn events(state: &AppState, s: &Session, events: &[Event]) -> anyhow::Result<()> {
    let rows: Vec<EventRow> = events
        .iter()
        .map(|e| {
            let mut e = e.clone();
            crate::scrub::scrub_event(&mut e, None);
            EventRow::from_event(s.device_id, &s.hostname, &e)
        })
        .collect();
    state.events.insert(rows).await?;
    sqlx::query("UPDATE devices SET last_seen = $2 WHERE id = $1")
        .bind(s.device_id)
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(())
}

pub async fn alert(state: &AppState, s: &Session, mut a: Alert) -> anyhow::Result<()> {
    crate::scrub::scrub_alert(&mut a, user_hasher(state, s.device_id).await?);
    // Evidence also lands in the telemetry store so hunting sees it — but only
    // events the agent does not already upload as raw telemetry (otherwise
    // every alert sharing an event would store another copy of it).
    if !a.evidence.is_empty() {
        match evidence_to_store(state, s.device_id, &a.evidence).await {
            Ok(evidence) if !evidence.is_empty() => {
                let rows: Vec<EventRow> = evidence
                    .iter()
                    .map(|e| EventRow::from_event(s.device_id, &s.hostname, e))
                    .collect();
                if let Err(e) = state.events.insert(rows).await {
                    tracing::warn!(error = %e, "failed to store alert evidence as events");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::warn!(error = %e, "failed to dedupe alert evidence"),
        }
    }
    incidents::ingest_alert(state, s.device_id, a).await?;
    Ok(())
}

/// Evidence events that are neither covered by the device's raw-telemetry
/// upload policy nor already stored (by an earlier alert).
async fn evidence_to_store(
    state: &AppState,
    device_id: Uuid,
    evidence: &[Event],
) -> anyhow::Result<Vec<Event>> {
    let pid = policy_svc::device_policy_id(&state.db, device_id).await?;
    let policy = policy_svc::load_stored(&state.db, &pid)
        .await?
        .unwrap_or_default();
    let uploaded_as_telemetry = |e: &Event| {
        let t = &policy.telemetry;
        t.upload_events
            && (t.event_kinds.is_empty() || t.event_kinds.iter().any(|k| k == e.kind().as_str()))
            && (policy.privacy.capture_dns
                || !matches!(e.data, kestrel_common::EventData::DnsQuery { .. }))
    };
    let mut out: Vec<Event> = vec![];
    for e in evidence {
        if !uploaded_as_telemetry(e) && !out.contains(e) {
            out.push(e.clone());
        }
    }
    if out.is_empty() {
        return Ok(out);
    }
    let mut guids: Vec<String> = out.iter().map(|e| e.guid.0.clone()).collect();
    guids.sort();
    guids.dedup();
    let q = crate::telemetry::EventQuery {
        device_id: Some(device_id),
        guids,
        from: out.iter().map(|e| e.ts).min(),
        to: out.iter().map(|e| e.ts).max(),
        limit: 5000,
        ..Default::default()
    };
    let existing: Vec<Event> = state
        .events
        .query(&q)
        .await?
        .iter()
        .filter_map(|r| r.event())
        .collect();
    out.retain(|e| !existing.contains(e));
    Ok(out)
}

pub async fn action_result(
    state: &AppState,
    s: &Session,
    command_id: Uuid,
    outcome: &ActionOutcome,
) -> anyhow::Result<()> {
    let now = now_ms();
    let detail = crate::scrub::redact_secrets(&outcome.detail);
    let row: Option<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "UPDATE response_actions SET status = $3, completed_at = $4, result_detail = $5, artifact = $6, delivered_at = COALESCE(delivered_at, $4) \
         WHERE id = $1 AND device_id = $2 AND (completed_at IS NULL OR status IN ('pending','sent','expired')) RETURNING incident_id, action",
    )
    .bind(command_id)
    .bind(s.device_id)
    .bind(if outcome.ok { "succeeded" } else { "failed" })
    .bind(now)
    .bind(&detail)
    .bind(outcome.artifact.as_deref().map(|a| a.chars().take(1024).collect::<String>()))
    .fetch_optional(&state.db)
    .await?;
    let Some((incident_id, action_v)) = row else {
        tracing::debug!(%command_id, "action result for unknown or already completed command");
        return Ok(());
    };
    let action: ResponseAction = serde_json::from_value(action_v).unwrap_or(outcome.action.clone());
    let mut tx = state.db.begin().await?;
    if outcome.ok {
        match &action {
            ResponseAction::QuarantineFile { path, sha256 } => {
                incidents::upsert_quarantine(
                    &mut tx,
                    s.device_id,
                    None,
                    path,
                    sha256.as_deref(),
                    outcome.artifact.as_deref(),
                    &detail,
                )
                .await?;
            }
            ResponseAction::RestoreFile { quarantine_id }
            | ResponseAction::DeleteQuarantined { quarantine_id } => {
                let st = if matches!(action, ResponseAction::RestoreFile { .. }) {
                    "restored"
                } else {
                    "deleted"
                };
                sqlx::query("UPDATE quarantine_items SET state = $3, updated_at = $4 WHERE id = $1 AND device_id = $2")
                    .bind(quarantine_id)
                    .bind(s.device_id)
                    .bind(st)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
            }
            ResponseAction::IsolateHost { .. } | ResponseAction::ReleaseHost => {
                let iso = matches!(action, ResponseAction::IsolateHost { .. });
                sqlx::query("UPDATE devices SET health = jsonb_set(health, '{isolated}', to_jsonb($2::boolean)) WHERE id = $1")
                    .bind(s.device_id)
                    .bind(iso)
                    .execute(&mut *tx)
                    .await?;
            }
            _ => {}
        }
    }
    if let Some(inc) = incident_id {
        sqlx::query("INSERT INTO incident_activity (incident_id, ts, kind, title, detail) VALUES ($1,$2,'action',$3,$4)")
            .bind(inc)
            .bind(now)
            .bind(format!(
                "{}: {}",
                if outcome.ok { "Succeeded" } else { "Failed" },
                incidents::describe_action(&action)
            ))
            .bind(&detail)
            .execute(&mut *tx)
            .await?;
        if outcome.ok {
            incidents::supersede_approvals(&mut tx, inc, &action).await?;
            if matches!(action, ResponseAction::IsolateHost { .. }) {
                // Releasing is only offered once the host was actually isolated.
                let hostname = s.hostname.clone();
                incidents::insert_checklist(&mut tx, inc, &incidents::release_seed(&hostname))
                    .await?;
            }
        }
        incidents::recompute_incident(&mut tx, inc).await?;
    }
    tx.commit().await?;
    state.publish("action", command_id, "updated");
    if let Some(inc) = incident_id {
        state.publish("incident", inc, "updated");
    }
    if matches!(
        action,
        ResponseAction::IsolateHost { .. } | ResponseAction::ReleaseHost
    ) {
        state.publish("device", s.device_id, "updated");
    }
    Ok(())
}

pub async fn review_request(
    state: &AppState,
    s: &Session,
    rr: &ReviewRequest,
) -> anyhow::Result<()> {
    // L8: a device may only ask for review of its own alerts.
    let owner: Option<(Uuid,)> = sqlx::query_as("SELECT device_id FROM alerts WHERE id = $1")
        .bind(rr.alert_id)
        .fetch_optional(&state.db)
        .await?;
    if owner.map(|o| o.0) != Some(s.device_id) {
        tracing::warn!(device_id = %s.device_id, alert_id = %rr.alert_id, "review request for an alert of another (or no) device ignored");
        return Ok(());
    }
    let user = match user_hasher(state, s.device_id).await? {
        Some(mk) => mk.hash_username(&rr.user),
        None => rr.user.chars().take(256).collect(),
    };
    let justification: String = rr.justification.chars().take(4000).collect();
    let id = Uuid::new_v4();
    // Idempotent on (device, alert, ts) so outbox replays don't duplicate requests.
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM review_requests WHERE device_id = $1 AND alert_id = $2 AND created_at = $3",
    )
    .bind(s.device_id)
    .bind(rr.alert_id)
    .bind(rr.ts)
    .fetch_optional(&state.db)
    .await?;
    if exists.is_some() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO review_requests (id, device_id, user_name, alert_id, justification, state, created_at) VALUES ($1,$2,$3,$4,$5,'requested',$6)",
    )
    .bind(id)
    .bind(s.device_id)
    .bind(&user)
    .bind(rr.alert_id)
    .bind(&justification)
    .bind(rr.ts)
    .execute(&state.db)
    .await?;
    audit::log(
        &state.db,
        &Actor::system(),
        "review_request.created",
        id.to_string(),
        json!({"device_id": s.device_id, "alert_id": rr.alert_id, "user": user}),
    )
    .await;
    state.publish("alert", rr.alert_id, "updated");
    Ok(())
}

pub async fn inventory(state: &AppState, s: &Session, inv: &Inventory) -> anyhow::Result<()> {
    sqlx::query("UPDATE devices SET inventory = $2, inventory_updated_at = $3 WHERE id = $1")
        .bind(s.device_id)
        .bind(serde_json::to_value(inv)?)
        .bind(now_ms())
        .execute(&state.db)
        .await?;
    Ok(())
}
