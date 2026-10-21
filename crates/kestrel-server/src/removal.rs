//! "Remove device": remote uninstall + removal from the device list.
//!
//! Lifecycle (state derived from the device's `removal_action_id` command):
//!
//! 1. `POST /devices/:id/remove` (admin, interactive session, typed hostname,
//!    MFA step-up when the admin has MFA, rate limited) queues
//!    `ResponseAction::UninstallAgent` with a 90-day lifetime → **pending**.
//! 2. On delivery (now, or when the agent next connects) the server attaches
//!    the device's escrowed uninstall token(s) in `Command.secret`. Agents
//!    without the `agent.uninstall` capability never get it: the command is
//!    failed as unsupported instead.
//! 3. The agent verifies the token, answers `ok` + `uninstall_started` and
//!    starts the detached uninstall helper → **removing** (status `running`).
//!    A failure outcome (token mismatch, helper / Windows Installer error) →
//!    **failed**; the device stays listed.
//! 4. A removing device that stays disconnected for
//!    [`REMOVED_AFTER_SILENCE_MS`] is **removed**: decommissioned, its
//!    certificates revoked, `removed_at` / `removed_by` recorded; hidden from
//!    the device list unless `include_removed=true`.
//!
//! The token is never stored with the command, never returned by the API and
//! never logged.

use crate::{
    audit::{self, Actor},
    auth::{Principal, Via},
    error::{ApiError, ApiResult},
    ingest::Session,
    models::DeviceRow,
    state::AppState,
};
use kestrel_common::{now_ms, ActionOutcome, ResponseAction, CAP_REMOTE_UNINSTALL};
use serde_json::json;
use uuid::Uuid;

/// A queued removal waits this long for an offline PC (normal commands: 7 days).
pub const REMOVAL_TTL_MS: i64 = 90 * 86_400_000;
/// A device whose uninstall started is marked removed after staying
/// disconnected this long.
pub const REMOVED_AFTER_SILENCE_MS: i64 = 10 * 60_000;
/// Removal requests per admin per hour.
pub const MAX_REMOVALS_PER_HOUR: i64 = 20;
const HOUR_MS: i64 = 3_600_000;

/// Remote removal needs an interactive console session: API tokens are
/// refused even with `*` (like remote access).
pub fn require_interactive(p: &Principal) -> ApiResult<()> {
    if matches!(p.via, Via::Session { .. }) {
        Ok(())
    } else {
        Err(ApiError::forbidden(
            "removing a device needs an interactive console session; API tokens cannot do it",
        ))
    }
}

/// Uninstall tokens to attach at delivery: the current one and, while a
/// rotation is unconfirmed, the pending one (the agent uses whichever its
/// stored hash matches). Empty = none on file.
pub async fn delivery_tokens(state: &AppState, device_id: Uuid) -> anyhow::Result<Vec<String>> {
    let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT uninstall_token_enc, uninstall_token_pending_enc FROM devices WHERE id = $1 AND decommissioned_at IS NULL",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let mut out: Vec<String> = Vec::new();
    if let Some((cur, pending)) = row {
        for enc in [cur, pending].into_iter().flatten() {
            let t = state.mk.open_str(&enc)?;
            if !t.trim().is_empty() && !out.contains(&t) {
                out.push(t);
            }
        }
    }
    Ok(out)
}

async fn hostname(state: &AppState, device_id: Uuid) -> String {
    sqlx::query_as::<_, (String,)>("SELECT hostname FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten()
        .map(|h| h.0)
        .unwrap_or_default()
}

fn clip(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Validate and queue a removal. Returns the new command id.
pub async fn request(
    st: &AppState,
    p: &Principal,
    d: &DeviceRow,
    purge_data: bool,
    confirm_hostname: &str,
    comment: &str,
) -> ApiResult<Uuid> {
    if !confirm_hostname
        .trim()
        .eq_ignore_ascii_case(d.hostname.trim())
        || d.hostname.trim().is_empty()
    {
        return Err(ApiError::bad_request(
            "type the device's hostname exactly to confirm the removal",
        )
        .with_field("reason", "confirm_mismatch"));
    }
    if p.user.mfa_enabled && !crate::remote::reauth_recent(st, p).await? {
        return Err(ApiError::forbidden(
            "confirm your MFA code again (POST /api/me/reauth) to remove a device",
        )
        .with_field("reason", "reauth_required"));
    }
    if !d.capabilities.iter().any(|c| c == CAP_REMOTE_UNINSTALL) {
        return Err(ApiError::conflict(format!(
            "the agent on this PC (version {}) has not reported support for remote removal; update the agent, or use the uninstall tool on the PC",
            d.agent_version
        ))
        .with_field("reason", "agent_too_old"));
    }
    if !d.uninstall_token_set && !d.uninstall_token_pending {
        return Err(ApiError::conflict(
            "the server holds no uninstall token for this device; rotate the token on the device page first",
        )
        .with_field("reason", "no_uninstall_token"));
    }
    let comment = clip(comment.trim(), 500);
    let action = ResponseAction::UninstallAgent { purge_data };
    let now = now_ms();
    let id = Uuid::new_v4();
    let mut tx = st.db.begin().await?;
    // One removal request at a time per admin (rate limit) and per device.
    sqlx::query("SELECT pg_advisory_xact_lock(7413002, hashtext($1))")
        .bind(p.user.id.to_string())
        .execute(&mut *tx)
        .await?;
    let cur: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT removal_action_id FROM devices WHERE id = $1 AND decommissioned_at IS NULL FOR UPDATE",
    )
    .bind(d.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((cur,)) = cur else {
        return Err(ApiError::not_found("device not found"));
    };
    if let Some(cur) = cur {
        let busy: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM response_actions WHERE id = $1 AND status IN ('pending','sent','running') AND expires_at > $2",
        )
        .bind(cur)
        .bind(now)
        .fetch_optional(&mut *tx)
        .await?;
        if busy.is_some() {
            return Err(ApiError::conflict(
                "a removal of this device is already queued or running",
            )
            .with_field("reason", "removal_pending"));
        }
    }
    let (recent,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM response_actions WHERE action_type = 'uninstall_agent' AND requested_by = $1 AND created_at > $2",
    )
    .bind(p.user.id)
    .bind(now - HOUR_MS)
    .fetch_one(&mut *tx)
    .await?;
    if recent >= MAX_REMOVALS_PER_HOUR {
        return Err(ApiError::rate_limited(format!(
            "at most {MAX_REMOVALS_PER_HOUR} device removals per hour per administrator; try again later"
        ))
        .with_field("reason", "rate_limited"));
    }
    sqlx::query(
        "INSERT INTO response_actions (id, device_id, action, action_type, status, requested_by, comment, created_at, expires_at) \
         VALUES ($1,$2,$3,$4,'pending',$5,$6,$7,$8)",
    )
    .bind(id)
    .bind(d.id)
    .bind(serde_json::to_value(&action)?)
    .bind(action.name())
    .bind(p.user.id)
    .bind(&comment)
    .bind(now)
    .bind(now + REMOVAL_TTL_MS)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET removal_action_id = $2 WHERE id = $1")
        .bind(d.id)
        .bind(id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::log(
        &st.db,
        &p.actor(),
        "device.remove.requested",
        d.id.to_string(),
        json!({"hostname": d.hostname, "action_id": id, "purge_data": purge_data,
               "comment": comment, "ip": p.ip, "online": st.agents.is_connected(&d.id)}),
    )
    .await;
    crate::ingest::deliver_now(st, d.id, id, &action).await?;
    st.publish("action", id, "created");
    st.publish("device", d.id, "updated");
    Ok(id)
}

/// Cancel a removal the agent has not received yet.
pub async fn cancel(st: &AppState, p: &Principal, d: &DeviceRow) -> ApiResult<()> {
    let now = now_ms();
    let mut tx = st.db.begin().await?;
    let cur: Option<(Option<Uuid>,)> = sqlx::query_as(
        "SELECT removal_action_id FROM devices WHERE id = $1 AND decommissioned_at IS NULL FOR UPDATE",
    )
    .bind(d.id)
    .fetch_optional(&mut *tx)
    .await?;
    let none = || {
        ApiError::not_found("no queued removal to cancel")
            .with_field("reason", "no_pending_removal")
    };
    let Some((Some(aid),)) = cur else {
        return Err(none());
    };
    let row: Option<(String,)> =
        sqlx::query_as("SELECT status FROM response_actions WHERE id = $1")
            .bind(aid)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((status,)) = row else {
        return Err(none());
    };
    let started = || {
        ApiError::conflict(
            "the removal was already sent to the agent; it can no longer be cancelled",
        )
        .with_field("reason", "already_started")
    };
    match status.as_str() {
        "running" | "sent" => return Err(started()),
        "pending" => {}
        _ => return Err(none()),
    }
    // Only while the command (and its token) never left the server: once
    // it was sent, even on a stream that dropped before the ack, the agent
    // may be acting on it. The status check and the update are one atomic
    // statement, so a concurrent delivery (`pending_commands` /
    // `deliver_now` flip `pending` → `sent` first) wins or loses cleanly.
    let n = sqlx::query(
        "UPDATE response_actions SET status = 'cancelled', completed_at = $2, result_detail = $3 \
         WHERE id = $1 AND status = 'pending' AND sent_at IS NULL AND delivered_at IS NULL",
    )
    .bind(aid)
    .bind(now)
    .bind(format!("cancelled by {}", p.user.email))
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n != 1 {
        return Err(started());
    }
    sqlx::query("UPDATE devices SET removal_action_id = NULL WHERE id = $1")
        .bind(d.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    audit::log(
        &st.db,
        &p.actor(),
        "device.remove.cancelled",
        d.id.to_string(),
        json!({"hostname": d.hostname, "action_id": aid}),
    )
    .await;
    st.publish("action", aid, "updated");
    st.publish("device", d.id, "updated");
    Ok(())
}

/// Fail a removal command that was not completed (server-side reasons:
/// agent too old, no token on file).
pub async fn fail(
    state: &AppState,
    device_id: Uuid,
    action_id: Uuid,
    detail: &str,
) -> anyhow::Result<()> {
    let n = sqlx::query(
        "UPDATE response_actions SET status = 'failed', completed_at = $3, result_detail = $4 \
         WHERE id = $1 AND device_id = $2 AND completed_at IS NULL",
    )
    .bind(action_id)
    .bind(device_id)
    .bind(now_ms())
    .bind(detail)
    .execute(&state.db)
    .await?
    .rows_affected();
    if n == 1 {
        audit::log(
            &state.db,
            &Actor::system(),
            "device.remove.failed",
            device_id.to_string(),
            json!({"hostname": hostname(state, device_id).await, "action_id": action_id, "error": detail}),
        )
        .await;
        state.publish("action", action_id, "updated");
        state.publish("device", device_id, "updated");
    }
    Ok(())
}

/// Agent outcome of `UninstallAgent`: started → removing; failure → failed.
pub async fn on_outcome(
    state: &AppState,
    s: &Session,
    command_id: Uuid,
    outcome: &ActionOutcome,
) -> anyhow::Result<()> {
    let now = now_ms();
    let detail = clip(&crate::scrub::redact_secrets(&outcome.detail), 2000);
    let artifact = outcome.artifact.as_deref().map(|a| clip(a, 128));
    let audit_action;
    let n = if outcome.ok {
        audit_action = "device.remove.started";
        sqlx::query(
            "UPDATE response_actions SET status = 'running', completed_at = NULL, delivered_at = COALESCE(delivered_at, $3), \
             result_detail = $4, artifact = $5 \
             WHERE id = $1 AND device_id = $2 AND status IN ('pending','sent','cancelled')",
        )
        .bind(command_id)
        .bind(s.device_id)
        .bind(now)
        .bind(&detail)
        .bind(&artifact)
        .execute(&state.db)
        .await?
        .rows_affected()
    } else {
        audit_action = "device.remove.failed";
        sqlx::query(
            "UPDATE response_actions SET status = 'failed', completed_at = $3, delivered_at = COALESCE(delivered_at, $3), \
             result_detail = $4, artifact = $5 \
             WHERE id = $1 AND device_id = $2 AND status IN ('pending','sent','running','cancelled')",
        )
        .bind(command_id)
        .bind(s.device_id)
        .bind(now)
        .bind(&detail)
        .bind(&artifact)
        .execute(&state.db)
        .await?
        .rows_affected()
    };
    if n == 0 {
        tracing::debug!(%command_id, "removal outcome for unknown or finished command");
        return Ok(());
    }
    // A removal cancelled while the agent was already acting on it really
    // happened: point the device back at it.
    sqlx::query(
        "UPDATE devices SET removal_action_id = $2 WHERE id = $1 AND (removal_action_id IS NULL OR removal_action_id = $2)",
    )
    .bind(s.device_id)
    .bind(command_id)
    .execute(&state.db)
    .await?;
    audit::log(
        &state.db,
        &Actor::system(),
        audit_action,
        s.device_id.to_string(),
        json!({"hostname": s.hostname, "action_id": command_id, "detail": detail}),
    )
    .await;
    if !outcome.ok {
        // The token travelled to the PC and Kestrel is still installed.
        rotate_exposed_token(state, s.device_id, command_id).await;
    }
    state.publish("action", command_id, "updated");
    state.publish("device", s.device_id, "updated");
    Ok(())
}

/// A removal failed after its token was sent to the PC (where a local
/// administrator could have captured it from the helper's input): rotate the
/// uninstall token like `POST /devices/:id/uninstall-token/rotate` does. The
/// new token is held as pending and sent to the agent (now, or on its next
/// connect); the old one keeps working until the agent confirms.
pub async fn rotate_exposed_token(state: &AppState, device_id: Uuid, action_id: Uuid) {
    let r: anyhow::Result<()> = async {
        let token = crate::grpc::new_uninstall_token();
        let n = sqlx::query(
            "UPDATE devices SET uninstall_token_pending_enc = $2 WHERE id = $1 AND decommissioned_at IS NULL",
        )
        .bind(device_id)
        .bind(state.mk.seal_str(&token))
        .execute(&state.db)
        .await?
        .rows_affected();
        if n == 1 {
            audit::log(
                &state.db,
                &Actor::system(),
                "device.uninstall_token_rotated",
                device_id.to_string(),
                json!({"hostname": hostname(state, device_id).await, "reason": "remote removal failed after the token was sent to the PC", "action_id": action_id}),
            )
            .await;
            state
                .agents
                .send(&device_id, kestrel_common::wire::ServerPayload::SetUninstallToken { token });
        }
        Ok(())
    }
    .await;
    if let Err(e) = r {
        tracing::warn!(%device_id, error = %e, "rotating the uninstall token after a failed removal failed");
    }
}

/// Periodic: devices whose uninstall started (the agent's `uninstall_started`
/// outcome; the agent starts the helper only after the server acked it) and
/// that stayed disconnected for [`REMOVED_AFTER_SILENCE_MS`] are removed:
/// decommissioned and hidden. Their certificates are revoked only after
/// [`REVOKE_AFTER_REMOVED_MS`] ([`revoke_removed`]): until then a PC whose
/// uninstall did not complete (shut down mid-way, installer rollback) can
/// still connect, which undoes the removal ([`reappeared`]) instead of
/// leaving a running agent locked out. Returns how many.
pub async fn finalize_silent(state: &AppState) -> anyhow::Result<usize> {
    let now = now_ms();
    let rows: Vec<(Uuid, Uuid, String, Option<Uuid>)> = sqlx::query_as(
        "SELECT d.id, ra.id, d.hostname, ra.requested_by FROM devices d \
         JOIN response_actions ra ON ra.id = d.removal_action_id \
         WHERE ra.status = 'running' AND d.removed_at IS NULL AND d.decommissioned_at IS NULL AND d.last_seen < $1",
    )
    .bind(now - REMOVED_AFTER_SILENCE_MS)
    .fetch_all(&state.db)
    .await?;
    let mut done = 0;
    for (device_id, action_id, host, by) in rows {
        if state.agents.is_connected(&device_id) {
            continue;
        }
        if finalize(state, device_id, action_id, by).await? {
            done += 1;
            audit::log(
                &state.db,
                &Actor::system(),
                "device.remove.completed",
                device_id.to_string(),
                json!({"hostname": host, "action_id": action_id, "requested_by": by}),
            )
            .await;
        }
    }
    Ok(done)
}

async fn finalize(
    state: &AppState,
    device_id: Uuid,
    action_id: Uuid,
    by: Option<Uuid>,
) -> anyhow::Result<bool> {
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    let n = sqlx::query(
        "UPDATE response_actions SET status = 'succeeded', completed_at = $2, \
         result_detail = 'Kestrel was uninstalled from the PC; the device was removed from the device list' \
         WHERE id = $1 AND status = 'running'",
    )
    .bind(action_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if n != 1 {
        return Ok(false);
    }
    sqlx::query(
        "UPDATE devices SET decommissioned_at = $2, removed_at = $2, removed_by = $3, possible_duplicate_ids = '{}' WHERE id = $1",
    )
    .bind(device_id)
    .bind(now)
    .bind(by)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET possible_duplicate_ids = array_remove(possible_duplicate_ids, $1) WHERE $1 = ANY(possible_duplicate_ids)")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE response_actions SET status = 'expired', completed_at = $2, result_detail = 'device removed' WHERE device_id = $1 AND status IN ('pending','sent')")
        .bind(device_id)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM pending_messages WHERE device_id = $1")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    state.agents.disconnect(device_id);
    state.publish("action", action_id, "updated");
    state.publish("device", device_id, "updated");
    Ok(true)
}

/// Certificates of a removed device stay valid this long, so a PC whose
/// uninstall did not complete can still report back.
pub const REVOKE_AFTER_REMOVED_MS: i64 = 7 * 86_400_000;

/// Periodic: revoke the certificates of devices removed more than
/// [`REVOKE_AFTER_REMOVED_MS`] ago. Returns how many certificates.
pub async fn revoke_removed(state: &AppState) -> anyhow::Result<u64> {
    let now = now_ms();
    let n = sqlx::query(
        "UPDATE agent_certs c SET revoked_at = $1 FROM devices d \
         WHERE d.id = c.device_id AND c.revoked_at IS NULL AND d.removed_at IS NOT NULL AND d.removed_at < $2",
    )
    .bind(now)
    .bind(now - REVOKE_AFTER_REMOVED_MS)
    .execute(&state.db)
    .await?
    .rows_affected();
    Ok(n)
}

/// May a device that was removed still connect? Only within the grace
/// period (certificates not yet revoked, checked by the caller) and only
/// when the removal, not an admin's decommission, took it out.
pub fn may_reappear(removed_at: Option<i64>, decommissioned_at: Option<i64>) -> bool {
    matches!((removed_at, decommissioned_at), (Some(r), Some(d)) if r == d)
}

/// A removed device connected again with a still-valid certificate: Kestrel
/// is still installed there, so the removal did not happen. Put the device
/// back in the list, mark the removal failed and rotate the uninstall token
/// (it was sent to the PC).
pub async fn reappeared(state: &AppState, device_id: Uuid) -> anyhow::Result<()> {
    let row: Option<(Option<Uuid>, String)> = sqlx::query_as(
        "UPDATE devices SET decommissioned_at = NULL, removed_at = NULL, removed_by = NULL \
         WHERE id = $1 AND removed_at IS NOT NULL AND decommissioned_at = removed_at \
         RETURNING removal_action_id, hostname",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let Some((aid, host)) = row else {
        return Ok(());
    };
    let detail = "the PC connected again after the removal: Kestrel is still installed there (the uninstall did not complete)";
    if let Some(aid) = aid {
        sqlx::query(
            "UPDATE response_actions SET status = 'failed', completed_at = $2, result_detail = $3 WHERE id = $1",
        )
        .bind(aid)
        .bind(now_ms())
        .bind(detail)
        .execute(&state.db)
        .await?;
        state.publish("action", aid, "updated");
    }
    audit::log(
        &state.db,
        &Actor::system(),
        "device.remove.failed",
        device_id.to_string(),
        json!({"hostname": host, "action_id": aid, "error": detail}),
    )
    .await;
    if let Some(aid) = aid {
        rotate_exposed_token(state, device_id, aid).await;
    }
    state.publish("device", device_id, "updated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits() {
        assert_eq!(REMOVAL_TTL_MS, 90 * 24 * 3600 * 1000);
        const { assert!(REMOVED_AFTER_SILENCE_MS >= 5 * 60_000) };
        const { assert!(MAX_REMOVALS_PER_HOUR > 0) };
    }
}
