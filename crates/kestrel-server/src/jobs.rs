//! Background jobs: device status, silent-agent detection, command expiry, retention.

use crate::{ingest, settings, state::AppState, telemetry::postgres::MAX_RETENTION_DAYS};
use kestrel_common::{now_ms, Severity};
use std::{sync::atomic::Ordering, time::Duration};
use uuid::Uuid;

pub fn spawn(state: AppState) {
    let s = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            if let Err(e) = fast_jobs(&s).await {
                tracing::warn!(error = %e, "periodic job failed");
            }
        }
    });
    let a = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(AUDIT_ANCHOR_EVERY);
        loop {
            tick.tick().await;
            if let Err(e) = anchor_audit_head(&a).await {
                tracing::warn!(error = %e, "audit anchor job failed");
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(3600));
        loop {
            tick.tick().await;
            if let Err(e) = retention(&state).await {
                tracing::warn!(error = %e, "retention job failed");
            }
        }
    });
}

pub async fn fast_jobs(st: &AppState) -> anyhow::Result<()> {
    // Status transitions (online → offline etc.) for SSE consumers.
    let changed: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE devices SET status = device_status(health, last_seen, etw_lost_increased_at) \
         WHERE decommissioned_at IS NULL AND status IS DISTINCT FROM device_status(health, last_seen, etw_lost_increased_at) RETURNING id",
    )
    .fetch_all(&st.db)
    .await?;
    for (id,) in changed {
        st.publish("device", id, "updated");
    }

    // Agents that keep the stream open but stop heartbeating (suspended / hung).
    let now = now_ms();
    let limit = 3 * st.cfg.heartbeat_interval_ms;
    for (id, conn) in st.agents.connected() {
        let last = conn.last_hb.load(Ordering::Relaxed);
        let reference = if last > 0 { last } else { conn.connected_at };
        if now - reference > limit && !conn.silence_alerted.swap(true, Ordering::Relaxed) {
            let host: Option<(String,)> =
                sqlx::query_as("SELECT hostname FROM devices WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&st.db)
                    .await?;
            ingest::raise_tamper(
                st,
                id,
                "TP-SRV-HEARTBEAT",
                "Agent connected but silent",
                Severity::Medium,
                format!(
                    "The Kestrel agent on {} keeps its connection open but has sent no heartbeat for {} s: it may be suspended or hung.",
                    host.map(|h| h.0).unwrap_or_default(),
                    (now - reference) / 1000
                ),
            )
            .await;
        }
    }

    let expired: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE response_actions SET status = 'expired', completed_at = $1, \
         result_detail = CASE WHEN action_type = 'uninstall_agent' THEN 'not delivered within 90 days (the PC did not connect)' ELSE 'not delivered within 7 days' END \
         WHERE status IN ('pending','sent') AND completed_at IS NULL AND expires_at < $1 RETURNING id, device_id, action_type",
    )
    .bind(now)
    .fetch_all(&st.db)
    .await?;
    for (id, device_id, kind) in expired {
        st.publish("action", id, "updated");
        if kind == "uninstall_agent" {
            crate::audit::log(
                &st.db,
                &crate::audit::Actor::system(),
                "device.remove.expired",
                device_id.to_string(),
                serde_json::json!({"action_id": id}),
            )
            .await;
            st.publish("device", device_id, "updated");
        }
    }
    // "Remove device": uninstall started and the PC stayed away → removed.
    let removed = crate::removal::finalize_silent(st).await?;
    if removed > 0 {
        tracing::info!(removed, "devices removed after their remote uninstall");
    }
    if let Err(e) = crate::evidence::fast_job(st).await {
        tracing::warn!(error = %e, "evidence housekeeping failed");
    }
    let revoked = crate::removal::revoke_removed(st).await?;
    if revoked > 0 {
        tracing::info!(revoked, "certificates of removed devices revoked");
    }
    Ok(())
}

/// How often the audit-chain head is written to the log / syslog (L6).
pub const AUDIT_ANCHOR_EVERY: Duration = Duration::from_secs(15 * 60);

/// External anchor for the audit chain: the head (id, hash) goes to the server
/// log and, when configured, syslog. Rewriting or truncating the chain later no
/// longer matches what the SIEM recorded.
pub async fn anchor_audit_head(st: &AppState) -> anyhow::Result<()> {
    let Some((id, hash)) = crate::audit::head(&st.db).await? else {
        return Ok(());
    };
    tracing::info!(target: "kestrel::audit_anchor", audit_head_id = id, audit_head_hash = %hash, "audit chain head");
    let s = settings::load(&st.db).await?;
    if s.notifications.syslog.enabled && !s.notifications.syslog.host.is_empty() {
        crate::notify::send_audit_anchor(
            &s.notifications.syslog,
            &st.cfg.outbound_allow,
            id,
            &hash,
        )
        .await?;
    }
    Ok(())
}

pub async fn retention(st: &AppState) -> anyhow::Result<()> {
    let s = settings::load(&st.db).await?;
    let now = now_ms();
    let ev_days = if st.events.backend() == "postgres" {
        s.retention_days.events.min(MAX_RETENTION_DAYS)
    } else {
        s.retention_days.events
    };
    let purged = st.events.apply_retention(ev_days).await?;
    let alert_cutoff = now - s.retention_days.alerts as i64 * 86_400_000;
    let a = sqlx::query("DELETE FROM alerts WHERE ts < $1")
        .bind(alert_cutoff)
        .execute(&st.db)
        .await?
        .rows_affected();
    let i = sqlx::query(
        "DELETE FROM incidents i WHERE i.last_alert_at < $1 AND i.status IN ('resolved','dismissed') AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.incident_id = i.id)",
    )
    .bind(alert_cutoff)
    .execute(&st.db)
    .await?
    .rows_affected();
    sqlx::query("DELETE FROM response_actions WHERE created_at < $1 AND status IN ('succeeded','failed','expired','cancelled')").bind(alert_cutoff).execute(&st.db).await?;
    let audit_cutoff = now - s.retention_days.audit as i64 * 86_400_000;
    let au = sqlx::query("DELETE FROM audit_log WHERE ts < $1")
        .bind(audit_cutoff)
        .execute(&st.db)
        .await?
        .rows_affected();
    sqlx::query("DELETE FROM sessions WHERE expires_at < $1")
        .bind(now)
        .execute(&st.db)
        .await?;
    sqlx::query("DELETE FROM pending_messages WHERE expires_at < $1")
        .bind(now)
        .execute(&st.db)
        .await?;
    // NEW-5: dead letters (metadata only) expire and are capped per device.
    let dl = sqlx::query("DELETE FROM ingest_dead_letters WHERE received_at < $1")
        .bind(now - ingest::DEAD_LETTER_RETENTION_DAYS * 86_400_000)
        .execute(&st.db)
        .await?
        .rows_affected()
        + ingest::cap_dead_letters(&st.db, None).await?;
    // Evidence: stored bundles past their retention, uncollected bundles the
    // PC has deleted, metadata of alerts that are gone, orphaned files.
    let ev = crate::evidence::retention(st, &s).await?;
    st.oidc_pending.retain(|_, p| now - p.created < 600_000);
    st.login_limiter.prune(15 * 60_000);
    st.login_throttle.prune(now);
    tracing::info!(
        events = purged,
        alerts = a,
        incidents = i,
        audit = au,
        dead_letters = dl,
        evidence_expired = ev,
        "retention applied"
    );
    Ok(())
}
