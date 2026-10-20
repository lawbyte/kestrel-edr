use crate::{
    auth::Principal,
    error::ApiResult,
    models::{incident_select, IncidentRow},
    state::AppState,
};
use axum::{extract::State, Json};
use kestrel_common::now_ms;
use serde_json::{json, Value};

pub const HARDENING_CONTROLS: &[&str] = &[
    "block_mshta",
    "block_user_path_exec",
    "disable_run_dialog",
    "terminal_paste_warning",
    "script_block_logging",
    "dpapi_debug_channel",
    "asr_rules",
    "browser_disable_remote_debugging",
    "wdigest_off",
    "asr_lsass",
    "lsa_protection",
    "report_vulnerable_driver_blocklist",
    "task_scheduler_log",
];

/// Controls Kestrel only reports on and never changes.
pub const REPORT_ONLY_CONTROLS: &[&str] = &["report_vulnerable_driver_blocklist"];

/// Default of a hardening control when a stored policy predates it.
pub fn hardening_default(control: &str) -> bool {
    serde_json::to_value(kestrel_common::Hardening::default())
        .ok()
        .and_then(|v| v.get(control).and_then(|b| b.as_bool()))
        .unwrap_or(false)
}

pub async fn get_dashboard(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let now = now_ms();
    let db = &st.db;

    let dev: Vec<(String, i64)> = sqlx::query_as(
        "SELECT device_status(health, last_seen, etw_lost_increased_at) s, count(*) FROM devices WHERE decommissioned_at IS NULL GROUP BY 1",
    )
    .fetch_all(db)
    .await?;
    let get = |k: &str| dev.iter().find(|(s, _)| s == k).map(|x| x.1).unwrap_or(0);
    let total: i64 = dev.iter().map(|x| x.1).sum();

    let (open, critical, high): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE severity = 'critical'), count(*) FILTER (WHERE severity = 'high') \
         FROM incidents WHERE status IN ('open','in_progress')",
    )
    .fetch_one(db)
    .await?;
    let (mttr,): (Option<f64>,) = sqlx::query_as(
        "SELECT avg((resolved_at - created_at)::float8) / 3600000.0 FROM incidents WHERE resolved_at IS NOT NULL AND resolved_at >= $1",
    )
    .bind(now - 30 * 86_400_000)
    .fetch_one(db)
    .await?;

    let day_ago = now - 86_400_000;
    let (alerts_24h, blocked_24h): (i64, i64) = sqlx::query_as(
        "SELECT count(*), count(*) FILTER (WHERE jsonb_path_exists(actions, '$[*] ? (@.ok == true)')) FROM alerts WHERE ts >= $1",
    )
    .bind(day_ago)
    .fetch_one(db)
    .await?;

    let trend: Vec<(String, i64, i64, i64, i64)> = sqlx::query_as(
        "WITH days AS (SELECT generate_series((now() AT TIME ZONE 'UTC')::date - 13, (now() AT TIME ZONE 'UTC')::date, '1 day')::date AS d) \
         SELECT to_char(days.d, 'YYYY-MM-DD'), \
           count(a.id) FILTER (WHERE a.severity = 'critical'), count(a.id) FILTER (WHERE a.severity = 'high'), \
           count(a.id) FILTER (WHERE a.severity = 'medium'), count(a.id) FILTER (WHERE a.severity IN ('low','info')) \
         FROM days LEFT JOIN alerts a ON (to_timestamp(a.ts / 1000.0) AT TIME ZONE 'UTC')::date = days.d AND a.ts >= $1 \
         GROUP BY days.d ORDER BY days.d",
    )
    .bind(now - 15 * 86_400_000)
    .fetch_all(db)
    .await?;
    let alert_trend: Vec<Value> = trend
        .into_iter()
        .map(|(day, c, h, m, l)| json!({"day": day, "critical": c, "high": h, "medium": m, "low": l}))
        .collect();

    let top: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT rule_id, max(rule_name), count(*) FROM alerts WHERE ts >= $1 GROUP BY rule_id ORDER BY 3 DESC, 1 LIMIT 5",
    )
    .bind(now - 30 * 86_400_000)
    .fetch_all(db)
    .await?;
    let top_rules: Vec<Value> = top
        .into_iter()
        .map(|(r, n, c)| json!({"rule_id": r, "name": n, "count": c}))
        .collect();

    let dar: Vec<(String, i64)> = sqlx::query_as(
        "SELECT c, count(*) FROM incidents, unnest(data_at_risk) c WHERE created_at >= $1 GROUP BY c ORDER BY 2 DESC, 1",
    )
    .bind(now - 30 * 86_400_000)
    .fetch_all(db)
    .await?;
    let data_at_risk: Vec<Value> = dar
        .into_iter()
        .map(|(c, n)| json!({"category": c, "count": n}))
        .collect();

    let mut hardening = vec![];
    for control in HARDENING_CONTROLS {
        let (applied, total_desired): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE COALESCE((d.health->'hardening'->>$1)::boolean, false)), count(*) \
             FROM devices d LEFT JOIN groups g ON g.id = d.group_id \
             JOIN policies p ON p.id = COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) \
             WHERE d.decommissioned_at IS NULL AND COALESCE((p.body->'hardening'->>$1)::boolean, $2) \
               AND COALESCE(p.body->'hardening'->>'mode', 'audit') != 'off'",
        )
        .bind(control)
        .bind(hardening_default(control))
        .fetch_one(db)
        .await?;
        hardening.push(json!({"control": control, "applied": applied, "total": total_desired}));
    }

    let versions: Vec<(String, i64)> = sqlx::query_as(
        "SELECT agent_version, count(*) FROM devices WHERE decommissioned_at IS NULL GROUP BY 1 ORDER BY 2 DESC",
    )
    .fetch_all(db)
    .await?;
    let agent_versions: Vec<Value> = versions
        .into_iter()
        .map(|(v, c)| json!({"version": v, "count": c}))
        .collect();

    let recent: Vec<IncidentRow> = sqlx::query_as(&format!(
        "{} ORDER BY i.created_at DESC LIMIT 5",
        incident_select()
    ))
    .fetch_all(db)
    .await?;

    Ok(Json(json!({
        "devices": {"total": total, "online": get("online"), "offline": get("offline"), "isolated": get("isolated"), "degraded": get("degraded")},
        "incidents": {"open": open, "critical": critical, "high": high, "mttr_hours_30d": mttr.map(|m| (m * 10.0).round() / 10.0)},
        "alerts_24h": alerts_24h,
        "blocked_24h": blocked_24h,
        "alert_trend": alert_trend,
        "top_rules": top_rules,
        "data_at_risk_30d": data_at_risk,
        "hardening_coverage": hardening,
        "agent_versions": agent_versions,
        "recent_incidents": recent.iter().map(|i| i.to_api()).collect::<Vec<_>>(),
    })))
}
