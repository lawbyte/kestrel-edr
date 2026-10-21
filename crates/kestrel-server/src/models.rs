//! Row types and their REST JSON representations (docs/contracts.md).

use serde_json::{json, Value};
use uuid::Uuid;

// ---------------------------------------------------------------- users

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct UserRow {
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub password_hash: Option<String>,
    pub role: String,
    pub disabled: bool,
    pub mfa_enabled: bool,
    pub totp_secret_enc: Option<String>,
    pub oidc_sub: Option<String>,
    pub last_login: Option<i64>,
    pub created_at: i64,
    pub totp_last_step: Option<i64>,
}

impl UserRow {
    pub fn to_api(&self) -> Value {
        json!({
            "id": self.id,
            "email": self.email,
            "name": self.name,
            "role": self.role,
            "last_login": self.last_login,
            "created_at": self.created_at,
            "disabled": self.disabled,
            "mfa_enabled": self.mfa_enabled,
            "sso_linked": self.oidc_sub.is_some(),
            "local_password": self.password_hash.is_some(),
        })
    }
}

/// User columns aliased with a prefix, for LEFT JOINs.
pub fn user_cols(alias: &str, prefix: &str) -> String {
    [
        "id",
        "email",
        "name",
        "role",
        "last_login",
        "created_at",
        "disabled",
        "mfa_enabled",
    ]
    .iter()
    .map(|c| format!("{alias}.{c} AS {prefix}{c}"))
    .collect::<Vec<_>>()
    .join(", ")
}

#[derive(sqlx::FromRow, Clone, Debug, Default)]
pub struct JoinedUser {
    pub id: Option<Uuid>,
    pub email: Option<String>,
    pub name: Option<String>,
    pub role: Option<String>,
    pub last_login: Option<i64>,
    pub created_at: Option<i64>,
    pub disabled: Option<bool>,
    pub mfa_enabled: Option<bool>,
}

impl JoinedUser {
    pub fn to_api(&self) -> Value {
        match self.id {
            None => Value::Null,
            Some(id) => json!({
                "id": id,
                "email": self.email,
                "name": self.name,
                "role": self.role,
                "last_login": self.last_login,
                "created_at": self.created_at,
                "disabled": self.disabled.unwrap_or(false),
                "mfa_enabled": self.mfa_enabled.unwrap_or(false),
            }),
        }
    }
}

/// Build a `JoinedUser` from `a_*` columns of a row.
macro_rules! joined_user {
    ($row:expr) => {
        $crate::models::JoinedUser {
            id: $row.a_id,
            email: $row.a_email.clone(),
            name: $row.a_name.clone(),
            role: $row.a_role.clone(),
            last_login: $row.a_last_login,
            created_at: $row.a_created_at,
            disabled: $row.a_disabled,
            mfa_enabled: $row.a_mfa_enabled,
        }
    };
}
pub(crate) use joined_user;

// ---------------------------------------------------------------- devices

pub const DEVICE_SELECT: &str = "SELECT d.id, d.hostname, d.os_name, d.os_build, d.arch, d.domain, d.agent_version, \
    device_status(d.health, d.last_seen, d.etw_lost_increased_at) AS status, \
    d.last_seen, d.first_seen, d.ip_addresses, d.logged_on_user, d.group_id, g.name AS group_name, \
    p.id AS policy_id, p.name AS policy_name, d.policy_version_applied, d.tags, d.health, \
    (SELECT count(*) FROM incidents i WHERE i.device_id = d.id AND i.status IN ('open','in_progress')) AS open_incidents, \
    (SELECT c.not_after FROM agent_certs c WHERE c.device_id = d.id AND c.revoked_at IS NULL \
       ORDER BY c.last_used_at DESC NULLS LAST, c.issued_at DESC LIMIT 1) AS cert_expires_at, \
    d.possible_duplicate_ids, (d.uninstall_token_enc IS NOT NULL) AS uninstall_token_set, \
    (d.uninstall_token_pending_enc IS NOT NULL) AS uninstall_token_pending \
    FROM devices d \
    LEFT JOIN groups g ON g.id = d.group_id \
    LEFT JOIN policies p ON p.id = COALESCE(g.policy_id, (SELECT policy_id FROM groups WHERE is_default LIMIT 1)) \
    WHERE d.decommissioned_at IS NULL";

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct DeviceRow {
    pub id: Uuid,
    pub hostname: String,
    pub os_name: String,
    pub os_build: String,
    pub arch: String,
    pub domain: Option<String>,
    pub agent_version: String,
    pub status: String,
    pub last_seen: i64,
    pub first_seen: i64,
    pub ip_addresses: Vec<String>,
    pub logged_on_user: Option<String>,
    pub group_id: Option<Uuid>,
    pub group_name: Option<String>,
    pub policy_id: Option<String>,
    pub policy_name: Option<String>,
    pub policy_version_applied: i64,
    pub tags: Vec<String>,
    pub health: Value,
    pub open_incidents: i64,
    pub cert_expires_at: Option<i64>,
    pub possible_duplicate_ids: Vec<Uuid>,
    pub uninstall_token_set: bool,
    /// A rotated token was not yet confirmed by the agent.
    pub uninstall_token_pending: bool,
}

impl DeviceRow {
    pub fn to_api(&self) -> Value {
        let health: kestrel_common::wire::AgentHealth =
            serde_json::from_value(self.health.clone()).unwrap_or_default();
        json!({
            "id": self.id,
            "hostname": self.hostname,
            "os_name": self.os_name,
            "os_build": self.os_build,
            "arch": self.arch,
            "domain": self.domain,
            "agent_version": self.agent_version,
            "status": self.status,
            "last_seen": self.last_seen,
            "first_seen": self.first_seen,
            "ip_addresses": self.ip_addresses,
            "logged_on_user": self.logged_on_user,
            "group_id": self.group_id,
            "group_name": self.group_name,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "policy_version_applied": self.policy_version_applied,
            "tags": self.tags,
            "health": health,
            "open_incidents": self.open_incidents,
            "cert_expires_at": self.cert_expires_at,
            "possible_duplicates": self.possible_duplicate_ids,
            "uninstall_token_set": self.uninstall_token_set,
            "uninstall_token_pending": self.uninstall_token_pending,
            // Protection turned off locally (tray switch), if it is now.
            // Read raw: right after a Hello `health` may hold only `pause`.
            "pause": self
                .health
                .get("pause")
                .and_then(|p| serde_json::from_value::<kestrel_common::PauseState>(p.clone()).ok()),
        })
    }
}

// ---------------------------------------------------------------- alerts

pub const ALERT_SELECT: &str = "SELECT a.id, a.incident_id, a.device_id, d.hostname, a.ts, a.rule_id, a.rule_name, a.rule_author, \
    a.severity, a.attack, a.mode, a.summary, a.process_guid, a.image, a.data_at_risk, a.actions, a.status, \
    a.body->>'protection_off' AS protection_off \
    FROM alerts a JOIN devices d ON d.id = a.device_id";

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct AlertRow {
    pub id: Uuid,
    pub incident_id: Option<Uuid>,
    pub device_id: Uuid,
    pub hostname: String,
    pub ts: i64,
    pub rule_id: String,
    pub rule_name: String,
    pub rule_author: Option<String>,
    pub severity: String,
    pub attack: Vec<String>,
    pub mode: String,
    pub summary: String,
    pub process_guid: String,
    pub image: String,
    pub data_at_risk: Vec<String>,
    pub actions: Value,
    pub status: String,
    /// `Alert::protection_off` ("detection_only" / "full") from the stored body.
    pub protection_off: Option<String>,
}

impl AlertRow {
    pub fn to_api(&self) -> Value {
        json!({
            "id": self.id,
            "incident_id": self.incident_id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "ts": self.ts,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "rule_author": self.rule_author,
            "severity": self.severity,
            "attack": self.attack,
            "mode": self.mode,
            "summary": self.summary,
            "process_guid": self.process_guid,
            "image": self.image,
            "data_at_risk": self.data_at_risk,
            "actions": self.actions,
            "status": self.status,
            "protection_off": self.protection_off,
        })
    }
}

// ---------------------------------------------------------------- incidents

pub fn incident_select() -> String {
    format!(
        "SELECT i.id, i.title, i.severity, i.priority, i.status, i.classification, i.device_id, d.hostname, i.user_name, \
         i.created_at, i.updated_at, i.alert_count, i.rule_ids, i.attack, i.data_at_risk, i.contained, i.storyline, i.root_guid, \
         i.first_alert_at, i.last_alert_at, {} \
         FROM incidents i JOIN devices d ON d.id = i.device_id LEFT JOIN users u ON u.id = i.assignee_id",
        user_cols("u", "a_")
    )
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct IncidentRow {
    pub id: Uuid,
    pub title: String,
    pub severity: String,
    pub priority: i32,
    pub status: String,
    pub classification: Option<String>,
    pub device_id: Uuid,
    pub hostname: String,
    pub user_name: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub alert_count: i32,
    pub rule_ids: Vec<String>,
    pub attack: Vec<String>,
    pub data_at_risk: Vec<String>,
    pub contained: bool,
    pub storyline: String,
    pub root_guid: String,
    pub first_alert_at: i64,
    pub last_alert_at: i64,
    pub a_id: Option<Uuid>,
    pub a_email: Option<String>,
    pub a_name: Option<String>,
    pub a_role: Option<String>,
    pub a_last_login: Option<i64>,
    pub a_created_at: Option<i64>,
    pub a_disabled: Option<bool>,
    pub a_mfa_enabled: Option<bool>,
}

impl IncidentRow {
    pub fn to_api(&self) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "priority": self.priority,
            "status": self.status,
            "classification": self.classification,
            "assignee": joined_user!(self).to_api(),
            "device_id": self.device_id,
            "hostname": self.hostname,
            "user": self.user_name,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "alert_count": self.alert_count,
            "rule_ids": self.rule_ids,
            "attack": self.attack,
            "data_at_risk": self.data_at_risk,
            "contained": self.contained,
        })
    }
}

// ---------------------------------------------------------------- response actions

pub fn action_select() -> String {
    format!(
        "SELECT r.id, r.device_id, d.hostname, r.incident_id, r.action, r.status, r.comment, r.created_at, r.completed_at, \
         r.result_detail, r.artifact, {} FROM response_actions r JOIN devices d ON d.id = r.device_id LEFT JOIN users u ON u.id = r.requested_by",
        user_cols("u", "a_")
    )
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct ActionRow {
    pub id: Uuid,
    pub device_id: Uuid,
    pub hostname: String,
    pub incident_id: Option<Uuid>,
    pub action: Value,
    pub status: String,
    pub comment: String,
    pub created_at: i64,
    pub completed_at: Option<i64>,
    pub result_detail: String,
    pub artifact: Option<String>,
    pub a_id: Option<Uuid>,
    pub a_email: Option<String>,
    pub a_name: Option<String>,
    pub a_role: Option<String>,
    pub a_last_login: Option<i64>,
    pub a_created_at: Option<i64>,
    pub a_disabled: Option<bool>,
    pub a_mfa_enabled: Option<bool>,
}

impl ActionRow {
    pub fn to_api(&self) -> Value {
        json!({
            "id": self.id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "incident_id": self.incident_id,
            "action": self.action,
            "status": self.status,
            "requested_by": joined_user!(self).to_api(),
            "comment": self.comment,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "result_detail": self.result_detail,
            "artifact": self.artifact,
        })
    }
}

pub async fn load_action(db: &sqlx::PgPool, id: Uuid) -> Result<ActionRow, sqlx::Error> {
    sqlx::query_as::<_, ActionRow>(&format!("{} WHERE r.id = $1", action_select()))
        .bind(id)
        .fetch_one(db)
        .await
}

pub async fn load_incident(db: &sqlx::PgPool, id: Uuid) -> Result<IncidentRow, sqlx::Error> {
    sqlx::query_as::<_, IncidentRow>(&format!("{} WHERE i.id = $1", incident_select()))
        .bind(id)
        .fetch_one(db)
        .await
}

pub async fn load_device(db: &sqlx::PgPool, id: Uuid) -> Result<DeviceRow, sqlx::Error> {
    sqlx::query_as::<_, DeviceRow>(&format!("{DEVICE_SELECT} AND d.id = $1"))
        .bind(id)
        .fetch_one(db)
        .await
}
