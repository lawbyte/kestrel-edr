//! REST API (`/api`) per docs/contracts.md.

mod alerts;
mod auth_routes;
mod dashboard;
mod devices;
mod groups;
mod hunt;
mod incidents;
pub mod oidc;
mod policies;
mod quarantine;
mod rules;
mod settings_routes;
mod sse;
mod updates;
mod users;

use crate::{error::ApiError, state::AppState};
use axum::{
    extract::{FromRequest, FromRequestParts},
    routing::{delete, get, patch, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};

/// `Json` extractor whose rejection uses the contract error format.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

/// `Option<Option<T>>` field helper: absent → None, null → Some(None).
pub fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
}

#[derive(Deserialize, Default)]
pub struct PageQuery {
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

pub struct Page {
    pub limit: i64,
    pub offset: i64,
}

pub fn page(limit: Option<i64>, cursor: Option<&str>) -> Result<Page, ApiError> {
    let limit = limit.unwrap_or(50).clamp(1, 500);
    let offset = match cursor.filter(|c| !c.is_empty()) {
        None => 0,
        Some(c) => {
            let raw = B64URL
                .decode(c)
                .map_err(|_| ApiError::bad_request("invalid cursor"))?;
            let s = String::from_utf8(raw).map_err(|_| ApiError::bad_request("invalid cursor"))?;
            s.strip_prefix("o:")
                .and_then(|n| n.parse::<i64>().ok())
                .filter(|n| *n >= 0)
                .ok_or_else(|| ApiError::bad_request("invalid cursor"))?
        }
    };
    Ok(Page { limit, offset })
}

pub fn list_response(items: Vec<Value>, total: i64, p: &Page) -> Value {
    let next = p.offset + items.len() as i64;
    let next_cursor = if next < total && !items.is_empty() {
        Some(B64URL.encode(format!("o:{next}")))
    } else {
        None
    };
    json!({"items": items, "next_cursor": next_cursor, "total": total})
}

/// Split a comma-separated filter value.
pub fn csv(v: &Option<String>) -> Vec<String> {
    v.as_deref()
        .unwrap_or("")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Dynamic WHERE builder with positional parameters.
#[derive(Default)]
pub struct Filter {
    pub conds: Vec<String>,
    pub args: Vec<Arg>,
}

#[derive(Clone, Debug)]
pub enum Arg {
    Str(String),
    Strs(Vec<String>),
    Int(i64),
    Uuid(uuid::Uuid),
}

impl Filter {
    /// Add a condition; `?` placeholders are replaced by `$n` in order.
    pub fn push(&mut self, cond: &str, args: Vec<Arg>) {
        let mut out = String::new();
        let mut it = args.into_iter();
        for ch in cond.chars() {
            if ch == '?' {
                let a = it.next().expect("placeholder without argument");
                self.args.push(a);
                out.push_str(&format!("${}", self.args.len()));
            } else {
                out.push(ch);
            }
        }
        self.conds.push(out);
    }

    pub fn where_sql(&self) -> String {
        if self.conds.is_empty() {
            "TRUE".into()
        } else {
            self.conds.join(" AND ")
        }
    }

    pub fn next_idx(&self) -> usize {
        self.args.len() + 1
    }

    pub fn bind<'q, O>(
        &self,
        mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryAs<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        for a in &self.args {
            q = match a.clone() {
                Arg::Str(s) => q.bind(s),
                Arg::Strs(v) => q.bind(v),
                Arg::Int(i) => q.bind(i),
                Arg::Uuid(u) => q.bind(u),
            };
        }
        q
    }

    pub fn bind_scalar<'q, O>(
        &self,
        mut q: sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments>,
    ) -> sqlx::query::QueryScalar<'q, sqlx::Postgres, O, sqlx::postgres::PgArguments> {
        for a in &self.args {
            q = match a.clone() {
                Arg::Str(s) => q.bind(s),
                Arg::Strs(v) => q.bind(v),
                Arg::Int(i) => q.bind(i),
                Arg::Uuid(u) => q.bind(u),
            };
        }
        q
    }
}

pub fn parse_uuid(s: &str) -> Result<uuid::Uuid, ApiError> {
    uuid::Uuid::parse_str(s).map_err(|_| ApiError::bad_request("invalid id"))
}

async fn not_found() -> ApiError {
    ApiError::not_found("no such API endpoint")
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/healthz",
            get(|| async { axum::Json(json!({"ok": true})) }),
        )
        // auth
        .route("/auth/setup-status", get(auth_routes::setup_status))
        .route("/auth/setup", post(auth_routes::setup))
        .route("/auth/login", post(auth_routes::login))
        .route("/auth/logout", post(auth_routes::logout))
        .route("/auth/oidc/start", get(oidc::start))
        .route("/auth/oidc/callback", get(oidc::callback))
        .route("/me", get(auth_routes::me))
        .route("/me/password", post(auth_routes::change_password))
        .route("/me/mfa/setup", post(auth_routes::mfa_setup))
        .route("/me/mfa/enable", post(auth_routes::mfa_enable))
        .route("/me/mfa/disable", post(auth_routes::mfa_disable))
        // dashboard
        .route("/dashboard", get(dashboard::get_dashboard))
        // devices
        .route("/devices", get(devices::list))
        .route(
            "/devices/:id",
            get(devices::detail)
                .patch(devices::update)
                .delete(devices::decommission),
        )
        .route("/devices/:id/events", get(devices::events))
        .route("/devices/:id/processes", get(devices::processes))
        .route("/devices/:id/actions", post(devices::create_action))
        .route(
            "/devices/:id/uninstall-token/reveal",
            post(devices::reveal_uninstall_token),
        )
        .route(
            "/devices/:id/uninstall-token/rotate",
            post(devices::rotate_uninstall_token),
        )
        .route("/devices/:id/merge", post(devices::merge))
        .route(
            "/devices/:id/duplicates/dismiss",
            post(devices::dismiss_duplicate),
        )
        // groups & enrollment
        .route("/groups", get(groups::list).post(groups::create))
        .route("/groups/:id", patch(groups::update).delete(groups::remove))
        .route(
            "/enrollment-tokens",
            get(groups::list_tokens).post(groups::create_token),
        )
        .route("/enrollment-tokens/:id", delete(groups::revoke_token))
        .route("/agent/installer", get(groups::installer))
        // incidents & alerts
        .route("/incidents", get(incidents::list))
        .route(
            "/incidents/:id",
            get(incidents::detail).patch(incidents::update),
        )
        .route("/incidents/:id/comments", post(incidents::comment))
        .route(
            "/incidents/:id/checklist/:item_id",
            post(incidents::checklist),
        )
        .route("/alerts", get(alerts::list).patch(alerts::bulk_update))
        .route("/alerts/:id", get(alerts::detail))
        .route("/actions", get(alerts::list_actions))
        // policies, rules, exclusions, iocs
        .route("/policies", get(policies::list).post(policies::create))
        .route(
            "/policies/:id",
            get(policies::get_one)
                .put(policies::replace)
                .delete(policies::remove),
        )
        .route("/rules", get(rules::list).post(rules::create))
        .route("/rules/:id", patch(rules::update).delete(rules::remove))
        .route(
            "/exclusions",
            get(policies::list_exclusions).post(policies::create_exclusion),
        )
        .route("/exclusions/preview", get(policies::preview_exclusion))
        .route("/exclusions/:id", delete(policies::delete_exclusion))
        .route(
            "/iocs",
            get(policies::list_iocs).post(policies::create_iocs),
        )
        .route("/iocs/:id", delete(policies::delete_ioc))
        // quarantine & reviews
        .route("/quarantine", get(quarantine::list))
        .route("/quarantine/:id/restore", post(quarantine::restore))
        .route("/quarantine/:id/delete", post(quarantine::delete_item))
        .route("/review-requests", get(quarantine::list_reviews))
        .route("/review-requests/:id/decision", post(quarantine::decide))
        // hunt
        .route("/hunt", post(hunt::hunt))
        // users, tokens, settings, audit
        .route("/users", get(users::list).post(users::create))
        .route("/users/:id", patch(users::update).delete(users::remove))
        .route(
            "/api-tokens",
            get(users::list_tokens).post(users::create_token),
        )
        .route("/api-tokens/:id", delete(users::delete_token))
        .route(
            "/settings",
            get(settings_routes::get_settings).put(settings_routes::put_settings),
        )
        .route("/audit-log", get(settings_routes::audit_log))
        .route("/audit-log/verify", get(settings_routes::audit_verify))
        // agent updates (offline-signed releases, staged rings)
        .route("/updates/status", get(updates::status))
        .route(
            "/updates/releases",
            get(updates::list).post(updates::register),
        )
        .route("/updates/releases/:id/promote", post(updates::promote))
        .route("/updates/releases/:id/halt", post(updates::halt))
        // live updates
        .route("/events/stream", get(sse::stream))
        .fallback(not_found)
}
