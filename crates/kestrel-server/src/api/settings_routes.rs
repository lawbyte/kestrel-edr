use super::{list_response, page, ApiJson, ApiQuery, Arg, Filter};
use crate::{
    api::devices::like_escape,
    audit,
    auth::Principal,
    error::{ApiError, ApiResult},
    policy_svc,
    settings::{self, Settings},
    state::AppState,
};
use axum::{extract::State, Json};
use kestrel_common::now_ms;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

pub async fn get_settings(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let s = settings::load(&st.db).await?;
    let sec = settings::load_secrets(&st.db, &st.mk).await?;
    Ok(Json(settings::to_api(&s, &sec, p.has("settings.write"))))
}

/// Pull a write-only secret out of the body. Absent or empty → keep the stored value.
fn take_secret(body: &mut Value, path: &[&str]) -> Option<String> {
    let mut cur = body;
    for k in &path[..path.len() - 1] {
        cur = cur.get_mut(*k)?;
    }
    let obj = cur.as_object_mut()?;
    let v = obj.remove(path[path.len() - 1])?;
    v.as_str().filter(|s| !s.is_empty()).map(String::from)
}

pub async fn put_settings(
    State(st): State<AppState>,
    p: Principal,
    ApiJson(mut body): ApiJson<Value>,
) -> ApiResult<Json<Value>> {
    p.require("settings.write")?;
    let old = settings::load(&st.db).await?;
    let mut sec = settings::load_secrets(&st.db, &st.mk).await?;
    let old_sec = sec.clone();
    if let Some(s) = take_secret(&mut body, &["oidc", "client_secret"]) {
        sec.oidc_client_secret = s;
    }
    if let Some(s) = take_secret(&mut body, &["notifications", "email", "password"]) {
        sec.smtp_password = s;
    }
    if let Some(s) = take_secret(&mut body, &["notifications", "webhook", "secret"]) {
        sec.webhook_secret = s;
    }
    let mut new: Settings = serde_json::from_value(body)
        .map_err(|e| ApiError::bad_request(format!("invalid settings: {e}")))?;
    new.org_name = new.org_name.trim().to_string();
    if new.org_name.is_empty() {
        return Err(ApiError::bad_request("org_name is required"));
    }
    let r = &new.retention_days;
    if !(1..=3650).contains(&r.events)
        || !(1..=3650).contains(&r.alerts)
        || !(30..=3650).contains(&r.audit)
    {
        return Err(ApiError::bad_request(
            "retention_days out of range (events/alerts 1-3650, audit 30-3650)",
        ));
    }
    if !(5..=10_080).contains(&new.session_timeout_minutes) {
        return Err(ApiError::bad_request(
            "session_timeout_minutes must be 5-10080",
        ));
    }
    if !(1..=90).contains(&new.session_max_days) {
        return Err(ApiError::bad_request("session_max_days must be 1-90"));
    }
    new.oidc.allowed_domains = new
        .oidc
        .allowed_domains
        .iter()
        .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
        .filter(|d| !d.is_empty())
        .collect();
    for d in &new.oidc.allowed_domains {
        if d.contains(['@', '*', '/', ' ']) || !d.contains('.') {
            return Err(ApiError::bad_request(format!(
                "oidc.allowed_domains: '{d}' is not a domain name"
            )));
        }
    }
    if new.oidc.enabled {
        if !new.oidc.issuer.starts_with("https://") {
            return Err(ApiError::bad_request("oidc.issuer must be an https URL"));
        }
        st.outbound
            .check_url(&new.oidc.issuer)
            .map_err(|e| ApiError::bad_request(format!("oidc.issuer: {e}")))?;
        if new.oidc.client_id.is_empty() {
            return Err(ApiError::bad_request("oidc.client_id is required"));
        }
        // H6: an empty allow-list would admit every account at the IdP.
        if new.oidc.allowed_domains.is_empty() {
            return Err(ApiError::bad_request(
                "oidc.allowed_domains must list at least one email domain; single sign-on denies everyone when it is empty",
            ));
        }
    }
    let role: Option<(Vec<String>,)> =
        sqlx::query_as("SELECT privileges FROM roles WHERE name = $1")
            .bind(&new.oidc.default_role)
            .fetch_optional(&st.db)
            .await?;
    match role {
        None => return Err(ApiError::bad_request("oidc.default_role does not exist")),
        Some((privs,)) if privs.iter().any(|p| p == "*") => {
            return Err(ApiError::bad_request(
                "oidc.default_role cannot be an administrator role; promote SSO users explicitly",
            ))
        }
        Some(_) => {}
    }
    for (name, url) in [
        ("slack", &new.notifications.slack.webhook_url),
        ("teams", &new.notifications.teams.webhook_url),
        ("webhook", &new.notifications.webhook.url),
    ] {
        if !url.is_empty() {
            st.outbound
                .check_url(url)
                .map_err(|e| ApiError::bad_request(format!("{name} URL: {e}")))?;
        }
    }
    let sys = &new.notifications.syslog;
    if !sys.host.is_empty() {
        if sys.host.contains(['/', ' ', '@']) {
            return Err(ApiError::bad_request(
                "syslog host must be a host name or IP",
            ));
        }
        let pol = crate::netguard::Policy {
            allow: st.cfg.outbound_allow.clone(),
            allow_private: sys.allow_private,
        };
        if let Ok(ip) = sys
            .host
            .trim_matches(['[', ']'])
            .parse::<std::net::IpAddr>()
        {
            if !pol.permits(&ip) {
                return Err(ApiError::bad_request(
                    "syslog host is a private or link-local address; set notifications.syslog.allow_private to use an internal collector",
                ));
            }
        }
    }
    sqlx::query("UPDATE settings SET org_name = $1, body = $2, updated_at = $3 WHERE id = 1")
        .bind(&new.org_name)
        .bind(serde_json::to_value(&new)?)
        .bind(now_ms())
        .execute(&st.db)
        .await?;
    if sec != old_sec {
        settings::save_secrets(&st.db, &st.mk, &sec).await?;
    }
    if new.branding != old.branding || new.org_name != old.org_name {
        policy_svc::bump_and_push(&st, None).await?;
    }
    if new.retention_days.events != old.retention_days.events {
        if let Err(e) = st.events.apply_retention(new.retention_days.events).await {
            tracing::warn!(error = %e, "applying event retention failed");
        }
    }
    let changed = changed_keys(
        &serde_json::to_value(&old)?,
        &serde_json::to_value(&new)?,
        "",
    );
    let secrets_changed: Vec<&str> = [
        (
            "oidc.client_secret",
            sec.oidc_client_secret != old_sec.oidc_client_secret,
        ),
        (
            "notifications.email.password",
            sec.smtp_password != old_sec.smtp_password,
        ),
        (
            "notifications.webhook.secret",
            sec.webhook_secret != old_sec.webhook_secret,
        ),
    ]
    .iter()
    .filter(|(_, c)| *c)
    .map(|(k, _)| *k)
    .collect();
    audit::log(
        &st.db,
        &p.actor(),
        "settings.update",
        "settings",
        json!({"changed": changed, "secrets_changed": secrets_changed}),
    )
    .await;
    Ok(Json(settings::to_api(&new, &sec, true)))
}

fn changed_keys(a: &Value, b: &Value, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    match (a.as_object(), b.as_object()) {
        (Some(ao), Some(bo)) => {
            for (k, bv) in bo {
                let path = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                match ao.get(k) {
                    Some(av) if av == bv => {}
                    Some(av) if av.is_object() && bv.is_object() => {
                        out.extend(changed_keys(av, bv, &path))
                    }
                    _ => out.push(path),
                }
            }
        }
        _ => {
            if a != b {
                out.push(prefix.to_string());
            }
        }
    }
    out
}

#[derive(Deserialize)]
pub struct AuditQuery {
    actor: Option<String>,
    action: Option<String>,
    target: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    limit: Option<i64>,
    cursor: Option<String>,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    ts: i64,
    actor_id: Option<Uuid>,
    actor_email: Option<String>,
    action: String,
    target: String,
    details: Value,
    hash: String,
    prev_hash: String,
}

pub async fn audit_log(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<AuditQuery>,
) -> ApiResult<Json<Value>> {
    p.require("audit.read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    if let Some(a) = q.actor.as_ref().filter(|s| !s.is_empty()) {
        match Uuid::parse_str(a) {
            Ok(id) => f.push("actor_id = ?", vec![Arg::Uuid(id)]),
            Err(_) => f.push(
                "actor_email ILIKE ?",
                vec![Arg::Str(format!("%{}%", like_escape(a)))],
            ),
        }
    }
    if let Some(a) = q.action.as_ref().filter(|s| !s.is_empty()) {
        f.push(
            "action LIKE ?",
            vec![Arg::Str(format!("{}%", like_escape(a)))],
        );
    }
    if let Some(t) = q.target.as_ref().filter(|s| !s.is_empty()) {
        f.push("target = ?", vec![Arg::Str(t.clone())]);
    }
    if let Some(v) = q.from {
        f.push("ts >= ?", vec![Arg::Int(v)]);
    }
    if let Some(v) = q.to {
        f.push("ts <= ?", vec![Arg::Int(v)]);
    }
    let w = f.where_sql();
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM audit_log WHERE {w}"
        )))
        .fetch_one(&st.db)
        .await?;
    let rows: Vec<AuditRow> = f
        .bind(sqlx::query_as(&format!(
            "SELECT id, ts, actor_id, actor_email, action, target, details, hash, prev_hash FROM audit_log WHERE {w} ORDER BY id DESC LIMIT {} OFFSET {}",
            pg.limit, pg.offset
        )))
        .fetch_all(&st.db)
        .await?;
    let items = rows
        .into_iter()
        .map(|r| {
            let actor = if r.actor_id.is_some() || r.actor_email.is_some() { json!({"id": r.actor_id, "email": r.actor_email}) } else { Value::Null };
            json!({"id": r.id, "ts": r.ts, "actor": actor, "action": r.action, "target": r.target, "details": r.details, "hash": r.hash, "prev_hash": r.prev_hash})
        })
        .collect();
    Ok(Json(list_response(items, total, &pg)))
}

pub async fn audit_verify(State(st): State<AppState>, p: Principal) -> ApiResult<Json<Value>> {
    p.require("audit.read")?;
    let r = audit::verify(&st.db).await?;
    Ok(Json(
        json!({"ok": r.ok, "broken_at": r.broken_at, "count": r.count}),
    ))
}
