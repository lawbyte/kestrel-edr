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

/// A reported pause this long past its `until_ms` raises `TP-SRV-PAUSE-OVERDUE`.
pub const PAUSE_OVERDUE_GRACE_MS: i64 = 10 * 60_000;
/// ETW events lost between two heartbeats that raise a server-side tamper alert.
pub const EVENTS_LOST_ALERT_THRESHOLD: u64 = 500;
/// Minimum spacing between two server-side tamper alerts of the same kind.
pub const TAMPER_DEDUPE_MS: i64 = 3_600_000;
/// V-L3: policy / rules version catch-up runs at most this often per device.
pub const CATCH_UP_INTERVAL_MS: i64 = 10 * 60_000;
/// NEW-5: dead letters (metadata only) older than this are deleted.
pub const DEAD_LETTER_RETENTION_DAYS: i64 = 30;
/// NEW-5: each device keeps at most its newest this-many dead letters.
pub const DEAD_LETTER_MAX_PER_DEVICE: i64 = 1000;

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
    // Remembered for offline devices too (the console disables "Remove
    // device" for agents without `agent.uninstall`).
    let caps: Vec<String> = h
        .capabilities
        .iter()
        .filter(|c| !c.is_empty() && c.len() <= 64)
        .take(32)
        .cloned()
        .collect();
    sqlx::query("UPDATE devices SET capabilities = $2 WHERE id = $1")
        .bind(device_id)
        .bind(&caps)
        .execute(&state.db)
        .await?;
    // Local pause state (tray switch) as of this connect; heartbeats keep it current.
    let mut pause = h.pause.clone();
    if let (Some(p), Some(mk)) = (pause.as_mut(), user_hasher(state, device_id).await?) {
        if !p.by_user.is_empty() {
            p.by_user = mk.hash_username(&p.by_user);
        }
    }
    sqlx::query(
        "UPDATE devices SET health = jsonb_set(CASE WHEN jsonb_typeof(health) = 'object' THEN health ELSE '{}'::jsonb END, '{pause}', $2) WHERE id = $1",
    )
    .bind(device_id)
    .bind(serde_json::to_value(&pause)?)
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
    // V-L3: an agent reporting versions above the server's is also how a
    // compromised agent would run the counters up, so it raises
    // TP-SRV-VERSION, and catch-up runs at most once per device per 10 minutes.
    if let Some(what) =
        policy_svc::agent_ahead(&state.db, &pid, h.policy_version, h.rules_version).await?
    {
        raise_tamper(
            state,
            device_id,
            "TP-SRV-VERSION",
            "Agent reports a newer policy or rules version than the server",
            Severity::Medium,
            format!(
                "The Kestrel agent on {} reports {what}. This is expected once after the server database was restored from a backup; otherwise the agent's state was tampered with or the agent is not genuine.",
                h.hostname
            ),
        )
        .await;
        if claim_slot(state, device_id, "catch_up_versions", CATCH_UP_INTERVAL_MS).await? {
            policy_svc::catch_up_versions(&state.db, &pid, h.policy_version, h.rules_version)
                .await?;
        } else {
            tracing::warn!(%device_id, "version catch-up already ran for this device in the last 10 minutes; skipped");
        }
    }
    if let Some(p) = policy_svc::effective(&state.db, &pid).await? {
        if p.version != h.policy_version {
            out.push(ServerPayload::Policy(Box::new(p)));
        }
    }
    let bundle = policy_svc::rules_bundle(&state.db).await?;
    if bundle.version != h.rules_version {
        out.push(ServerPayload::Rules(bundle));
    }
    out.extend(pending_commands(state, device_id, &caps, &h.agent_version).await?);
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
    // Staged agent update: settle earlier deliveries and offer the newest
    // release enabled for this device's ring (never blocks the session).
    match crate::updates::on_hello(state, device_id, &h.agent_version).await {
        Ok(Some(p)) => out.push(p),
        Ok(None) => {}
        Err(e) => tracing::warn!(%device_id, error = %e, "agent update offer failed"),
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
/// `caps` / `agent_version`: what the connecting agent announced in Hello.
pub async fn pending_commands(
    state: &AppState,
    device_id: Uuid,
    caps: &[String],
    agent_version: &str,
) -> anyhow::Result<Vec<Outbound>> {
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
        let Ok(action) = serde_json::from_value::<ResponseAction>(action) else {
            continue;
        };
        match command_payload(state, device_id, id, action, caps, agent_version).await? {
            Some(p) => out.push(p),
            None => continue,
        }
        state.publish("action", id, "updated");
    }
    Ok(out)
}

/// The `Command` to send for action `id`, with its secret attached (only
/// here, at delivery time). `None` = the action cannot be delivered to this
/// agent and was failed instead (remote removal on an agent without
/// `agent.uninstall`, or no uninstall token on file).
pub async fn command_payload(
    state: &AppState,
    device_id: Uuid,
    id: Uuid,
    action: ResponseAction,
    caps: &[String],
    agent_version: &str,
) -> anyhow::Result<Option<ServerPayload>> {
    let mut secret = None;
    if matches!(action, ResponseAction::UninstallAgent { .. }) {
        if !caps
            .iter()
            .any(|c| c == kestrel_common::CAP_REMOTE_UNINSTALL)
        {
            crate::removal::fail(
                state,
                device_id,
                id,
                &format!(
                    "unsupported: the agent on this PC (version {}) does not support remote removal; update the agent or use the uninstall tool on the PC",
                    crate::mdsafe::plain(agent_version, 64)
                ),
            )
            .await?;
            return Ok(None);
        }
        // An unreadable sealed token (master key changed, damaged row) must
        // never break the agent's session: fail this command instead.
        let tokens = match crate::removal::delivery_tokens(state, device_id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(%device_id, error = %e, "uninstall token unreadable; removal failed");
                crate::removal::fail(
                    state,
                    device_id,
                    id,
                    "the server could not read its stored uninstall token for this device; rotate the token on the device page, then try again",
                )
                .await?;
                return Ok(None);
            }
        };
        if tokens.is_empty() {
            crate::removal::fail(
                state,
                device_id,
                id,
                "the server holds no uninstall token for this device; rotate the token on the device page, then try again",
            )
            .await?;
            return Ok(None);
        }
        secret = Some(kestrel_common::wire::CommandSecret {
            uninstall_tokens: tokens,
        });
    }
    Ok(Some(ServerPayload::Command {
        command_id: id,
        action,
        secret,
    }))
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
    deliver_now(state, device_id, id, action).await?;
    state.publish("action", id, "created");
    Ok(id)
}

/// Send a queued command now if the agent is connected (else it waits for
/// the next connect: [`pending_commands`]).
pub async fn deliver_now(
    state: &AppState,
    device_id: Uuid,
    id: Uuid,
    action: &ResponseAction,
) -> anyhow::Result<()> {
    let now = now_ms();
    if let Some(conn) = state.agents.get(&device_id) {
        let updated = sqlx::query("UPDATE response_actions SET status = 'sent', sent_at = $2 WHERE id = $1 AND status = 'pending'")
            .bind(id)
            .bind(now)
            .execute(&state.db)
            .await?
            .rows_affected();
        let payload = if updated == 1 {
            command_payload(
                state,
                device_id,
                id,
                action.clone(),
                &conn.capabilities,
                &conn.agent_version,
            )
            .await?
        } else {
            None
        };
        let delivered = match payload {
            Some(p) => state.agents.send(&device_id, p),
            // Failed instead (agent too old / no token) or already taken.
            None => true,
        };
        if !delivered {
            // Channel full or just disconnected: leave for redelivery on the next connect.
            sqlx::query(
                "UPDATE response_actions SET status = 'pending', sent_at = NULL WHERE id = $1",
            )
            .bind(id)
            .execute(&state.db)
            .await?;
        }
    }
    Ok(())
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
    claim_slot(state, device_id, rule, TAMPER_DEDUPE_MS).await
}

/// Atomically claim a per-device rate-limit slot `key` (stored in
/// `devices.tamper_state`): true when it was last claimed more than
/// `window_ms` ago (or never).
pub async fn claim_slot(
    state: &AppState,
    device_id: Uuid,
    key: &str,
    window_ms: i64,
) -> anyhow::Result<bool> {
    let now = now_ms();
    let (rule, dedupe) = (key, window_ms);
    let r = sqlx::query(
        "UPDATE devices SET tamper_state = tamper_state || jsonb_build_object($2::text, $3::bigint) \
         WHERE id = $1 AND COALESCE((tamper_state->>$2)::bigint, 0) < $4",
    )
    .bind(device_id)
    .bind(rule)
    .bind(now)
    .bind(now - dedupe)
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

/// Database error text with every double-quoted part (where PostgreSQL
/// echoes the offending input value) redacted, capped at 2000 chars. NEW-5:
/// nothing of the unscrubbed payload may reach the dead-letter table.
pub fn redact_db_error(error: &str) -> String {
    let mut out = String::with_capacity(error.len().min(2000));
    let mut quoted = false;
    for c in error.chars() {
        if c == '"' {
            if !quoted {
                out.push_str("\"<redacted>\"");
            }
            quoted = !quoted;
        } else if !quoted && !c.is_control() {
            out.push(c);
        }
        if out.chars().count() >= 2000 {
            break;
        }
    }
    out
}

/// V-L4: an agent message the database rejected for its content is acked (it
/// can never succeed and would block the outbox) but recorded as a dead
/// letter, and `TP-SRV-INGEST` is raised (at most once per device per hour).
///
/// Re-review NEW-5: the payload was decoded but never went through the
/// server-side privacy scrub, so only metadata is stored — type, seq, the
/// (redacted) error, the payload's byte length and SHA-256 — never the
/// content. Each device keeps its newest [`DEAD_LETTER_MAX_PER_DEVICE`] rows;
/// rows expire after [`DEAD_LETTER_RETENTION_DAYS`] (see `jobs::retention`).
pub async fn dead_letter(
    state: &AppState,
    device_id: Uuid,
    hostname: &str,
    seq: u64,
    payload_type: &str,
    error: &str,
    raw: &[u8],
) {
    use sha2::{Digest, Sha256};
    let error = redact_db_error(error);
    let sha = hex::encode(Sha256::digest(raw));
    let payload_type: String = payload_type.chars().take(64).collect();
    if let Err(e) = sqlx::query(
        "INSERT INTO ingest_dead_letters (device_id, seq, payload_type, error, payload_bytes, payload_sha256, received_at)          VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(device_id)
    .bind(i64::try_from(seq).unwrap_or(i64::MAX))
    .bind(&payload_type)
    .bind(&error)
    .bind(i64::try_from(raw.len()).unwrap_or(i64::MAX))
    .bind(&sha)
    .bind(now_ms())
    .execute(&state.db)
    .await
    {
        tracing::error!(%device_id, seq, error = %e, "failed to store dead letter");
    }
    if let Err(e) = cap_dead_letters(&state.db, Some(device_id)).await {
        tracing::error!(%device_id, error = %e, "failed to cap dead letters");
    }
    raise_tamper(
        state,
        device_id,
        "TP-SRV-INGEST",
        "Agent message rejected by the server database",
        Severity::Medium,
        format!(
            "A {payload_type} message from the Kestrel agent on {hostname} (seq {seq}) was rejected by the database because of its content and was dropped. \
             Its metadata (type, sequence number, size, SHA-256, database error) is kept in the ingest dead-letter table for review; the content is not stored. Repeated rejections can hide alerts: check the agent version and what the endpoint is sending."
        ),
    )
    .await;
}

/// Keep only the newest [`DEAD_LETTER_MAX_PER_DEVICE`] dead letters of one
/// device (or of every device). Returns the number of rows deleted.
pub async fn cap_dead_letters(db: &sqlx::PgPool, device_id: Option<Uuid>) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM ingest_dead_letters d USING (              SELECT id FROM (                  SELECT id, row_number() OVER (PARTITION BY device_id ORDER BY received_at DESC, id DESC) AS rn                  FROM ingest_dead_letters WHERE $1::uuid IS NULL OR device_id = $1              ) r WHERE r.rn > $2          ) old WHERE d.id = old.id",
    )
    .bind(device_id)
    .bind(DEAD_LETTER_MAX_PER_DEVICE)
    .execute(db)
    .await?
    .rows_affected())
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
        if let Some(p) = health_in.pause.as_mut().filter(|p| !p.by_user.is_empty()) {
            p.by_user = mk.hash_username(&p.by_user);
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
    // Protection completely off (tray switch, `PauseMode::Full`): the agent
    // stopped its sensors on purpose and TP-06 already reported it. The
    // sensor-health heuristics below would only repeat that as tampering.
    let full_pause = |h: Option<&AgentHealth>| {
        h.and_then(|h| h.pause.as_ref())
            .is_some_and(|p| p.mode == kestrel_common::PauseMode::Full)
    };
    let sensors_off_on_purpose = full_pause(Some(&hb.health));
    let was_off_on_purpose = full_pause(prev_health.as_ref());
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
    if let Some(p) = prev_health
        .as_ref()
        .filter(|_| !sensors_off_on_purpose && !was_off_on_purpose)
    {
        let delta = hb.health.etw_events_lost.saturating_sub(p.etw_events_lost);
        if delta >= EVENTS_LOST_ALERT_THRESHOLD {
            raise_tamper(
                state,
                s.device_id,
                "TP-SRV-EVENTS-LOST",
                "Agent telemetry loss rising",
                Severity::Medium,
                events_lost_summary(&s.hostname, delta, &hb.health, p),
            )
            .await;
        }
    }
    // After a full pause the sensors must come back: treat the paused
    // heartbeat as healthy so a failed restart still raises TP-SRV-ETW.
    // A pause the agent still reports long after its end: the agent clock
    // was set back, or the automatic turn-on failed.
    if let Some(until) = hb.health.pause.as_ref().and_then(|p| p.until_ms) {
        if until < now - PAUSE_OVERDUE_GRACE_MS {
            raise_tamper(
                state,
                s.device_id,
                "TP-SRV-PAUSE-OVERDUE",
                "Protection still turned off after its end time",
                Severity::Medium,
                format!(
                    "The Kestrel agent on {} still reports protection turned off {} minutes after the chosen end time (server clock). Check the device clock and turn protection back on from the device page.",
                    s.hostname,
                    (now - until) / 60_000
                ),
            )
            .await;
        }
    }
    let etw_was_ok = prev_health
        .as_ref()
        .map(|p| p.etw_ok || full_pause(Some(p)))
        .unwrap_or(true);
    if !hb.health.etw_ok && etw_was_ok && !sensors_off_on_purpose {
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
    let privacy = device_privacy(state, s.device_id).await?;
    let prefixes = crate::scrub::norm_prefixes(&privacy);
    let sc = scrub_for(state, &privacy, &prefixes);
    let rows: Vec<EventRow> = events
        .iter()
        .map(|e| {
            let mut e = e.clone();
            crate::scrub::scrub_event(&mut e, &sc);
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
    let privacy = device_privacy(state, s.device_id).await?;
    let prefixes = crate::scrub::norm_prefixes(&privacy);
    crate::scrub::scrub_alert(&mut a, &scrub_for(state, &privacy, &prefixes));
    // V-L4: the alert, its incident, actions and checklist are written in one
    // transaction (`ingest_alert`) *before* anything else, so a data error
    // can never leave a partial alert behind.
    incidents::ingest_alert(state, s.device_id, a.clone()).await?;
    // Evidence also lands in the telemetry store so hunting sees it — but only
    // events the agent does not already upload as raw telemetry (otherwise
    // every alert sharing an event would store another copy of it). Best
    // effort: the alert itself is already stored.
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
    Ok(())
}

/// Server-side scrub settings for a device's privacy policy (V-L5).
fn scrub_for<'a>(
    state: &'a AppState,
    privacy: &kestrel_common::Privacy,
    prefixes: &'a [String],
) -> crate::scrub::Scrub<'a> {
    crate::scrub::Scrub {
        users: privacy.hash_usernames.then_some(&state.mk),
        prefixes,
        capture_cmdline: privacy.capture_cmdline,
    }
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
    // Remote removal has its own lifecycle (started → removed / failed).
    let kind: Option<(String,)> =
        sqlx::query_as("SELECT action_type FROM response_actions WHERE id = $1 AND device_id = $2")
            .bind(command_id)
            .bind(s.device_id)
            .fetch_optional(&state.db)
            .await?;
    if kind.is_some_and(|k| k.0 == "uninstall_agent") {
        return crate::removal::on_outcome(state, s, command_id, outcome).await;
    }
    let now = now_ms();
    let detail = crate::scrub::redact_secrets(&outcome.detail);
    // V-L4: the status update and its side effects commit together.
    let mut tx = state.db.begin().await?;
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
    .fetch_optional(&mut *tx)
    .await?;
    let Some((incident_id, action_v)) = row else {
        tracing::debug!(%command_id, "action result for unknown or already completed command");
        return Ok(());
    };
    let action: ResponseAction = serde_json::from_value(action_v).unwrap_or(outcome.action.clone());
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
            .bind(crate::mdsafe::plain(&detail, 2000))
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
            // Likewise lifting an image-scoped block once it is in place.
            if let Some(img) = incidents::blocked_image(&action) {
                incidents::insert_checklist(&mut tx, inc, &incidents::unblock_seed(img)).await?;
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

/// Audit action for an agent pause report.
pub fn pause_audit_action(e: kestrel_common::pause::PauseEvent) -> &'static str {
    use kestrel_common::pause::PauseEvent;
    match e {
        PauseEvent::Off => "device.protection_off",
        PauseEvent::On => "device.protection_on",
        PauseEvent::Clamped => "device.protection_off_clamped",
        PauseEvent::Denied => "device.protection_off_denied",
    }
}

/// Local "turn protection off" switch: the agent reports turn-off / turn-on
/// / a pause shortened by policy / a wrong uninstall token (never the token).
/// Writes the audit entry and updates `health.pause` at once, so the device
/// status does not wait for the next heartbeat. The TP-06 alert arrives as a
/// normal alert.
pub async fn pause_report(
    state: &AppState,
    s: &Session,
    mut r: kestrel_common::pause::PauseReport,
) -> anyhow::Result<()> {
    use kestrel_common::pause::PauseEvent;
    let clip = |u: &mut String| {
        if u.len() > 256 {
            let mut cut = 256;
            while !u.is_char_boundary(cut) {
                cut -= 1;
            }
            u.truncate(cut);
        }
    };
    let mk = user_hasher(state, s.device_id).await?;
    clip(&mut r.by_user);
    if let Some(st) = r.state.as_mut() {
        clip(&mut st.by_user);
    }
    if let Some(mk) = mk {
        if !r.by_user.is_empty() {
            r.by_user = mk.hash_username(&r.by_user);
        }
        if let Some(st) = r.state.as_mut().filter(|st| !st.by_user.is_empty()) {
            st.by_user = mk.hash_username(&st.by_user);
        }
    }
    let new_pause = match r.event {
        PauseEvent::Off | PauseEvent::Clamped => Some(r.state.clone()),
        PauseEvent::On => Some(None),
        PauseEvent::Denied => None,
    };
    if let Some(p) = new_pause {
        sqlx::query(
            "UPDATE devices SET health = jsonb_set(CASE WHEN jsonb_typeof(health) = 'object' THEN health ELSE '{}'::jsonb END, '{pause}', $2) WHERE id = $1",
        )
        .bind(s.device_id)
        .bind(serde_json::to_value(&p)?)
        .execute(&state.db)
        .await?;
        state.publish("device", s.device_id, "updated");
    }
    let st = r.state.as_ref();
    audit::log(
        &state.db,
        &audit::Actor::system(),
        pause_audit_action(r.event),
        s.device_id.to_string(),
        json!({
            "hostname": s.hostname,
            "ts": r.ts.min(now_ms()),
            "mode": st.map(|x| x.mode),
            "since_ms": st.map(|x| x.since_ms),
            "until_ms": st.and_then(|x| x.until_ms),
            "by_user": if r.by_user.is_empty() { st.map(|x| x.by_user.clone()).unwrap_or_default() } else { r.by_user.clone() },
            "reason": r.reason,
            "failures": r.failures,
            "locked_until_ms": r.locked_until_ms,
        }),
    )
    .await;
    Ok(())
}

/// `TP-SRV-EVENTS-LOST` summary. Agents from 1.1.6 split the total into
/// events Windows lost (ETW buffers full) and events Kestrel's own sensor
/// queues dropped; the split is named when both heartbeats carry it.
fn events_lost_summary(host: &str, delta: u64, cur: &AgentHealth, prev: &AgentHealth) -> String {
    let side = |c: Option<u64>, p: Option<u64>| c.zip(p).map(|(c, p)| c.saturating_sub(p));
    match (
        side(cur.etw_kernel_events_lost, prev.etw_kernel_events_lost),
        side(cur.sensor_internal_dropped, prev.sensor_internal_dropped),
    ) {
        (Some(k), Some(d)) => {
            let cause = if k >= d {
                "mostly Windows: the PC produced events faster than ETW could hand them over (heavy load, such as large builds)"
            } else {
                "mostly Kestrel: the agent's own queues were full (the agent could not keep up, or was slowed down on purpose)"
            };
            format!(
                "{delta} events were lost on {host} since the previous heartbeat ({k} lost by Windows, {d} dropped by Kestrel), {cause}; detections may be blind."
            )
        }
        _ => format!(
            "ETW dropped {delta} events on {host} since the previous heartbeat; detections may be blind."
        ),
    }
}

#[cfg(test)]
mod events_lost_tests {
    use super::*;

    fn h(total: u64, k: Option<u64>, d: Option<u64>) -> AgentHealth {
        AgentHealth {
            etw_ok: true,
            etw_events_lost: total,
            etw_kernel_events_lost: k,
            sensor_internal_dropped: d,
            ..Default::default()
        }
    }

    #[test]
    fn summary_names_the_side_when_both_heartbeats_split_it() {
        let s = events_lost_summary(
            "FIN-LT-003",
            900,
            &h(1000, Some(850), Some(150)),
            &h(100, Some(50), Some(50)),
        );
        assert_eq!(
            s,
            "900 events were lost on FIN-LT-003 since the previous heartbeat (800 lost by Windows, 100 dropped by Kestrel), mostly Windows: the PC produced events faster than ETW could hand them over (heavy load, such as large builds); detections may be blind."
        );
        let s = events_lost_summary(
            "PC",
            600,
            &h(600, Some(0), Some(600)),
            &h(0, Some(0), Some(0)),
        );
        assert!(
            s.contains("(0 lost by Windows, 600 dropped by Kestrel), mostly Kestrel"),
            "{s}"
        );
    }

    #[test]
    fn summary_without_split_is_unchanged() {
        let old =
            "ETW dropped 600 events on PC since the previous heartbeat; detections may be blind.";
        assert_eq!(
            events_lost_summary("PC", 600, &h(600, None, None), &h(0, None, None)),
            old
        );
        // Agent upgraded between the two heartbeats: no reliable split.
        assert_eq!(
            events_lost_summary("PC", 600, &h(600, Some(500), Some(100)), &h(0, None, None)),
            old
        );
    }
}
