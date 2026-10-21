//! Postgres pool, migrations and first-run seed.

use crate::settings::Settings;
use kestrel_common::{now_ms, Policy};
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::time::Duration;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub const ALL_PRIVILEGES: &[&str] = &[
    "read",
    "incidents.write",
    "response.process",
    "response.file",
    "response.persistence",
    "response.network",
    "response.collect",
    "exclusions.write",
    "iocs.write",
    "policies.write",
    "rules.write",
    "devices.write",
    "users.write",
    "settings.write",
    "audit.read",
    "tokens.write",
    "updates.write",
    // Remote desktop / remote file manager: admin only (via `*`), and only
    // from an interactive console session (never API tokens).
    "remote.desktop",
    "remote.files",
    // "Remove device" (remote uninstall): admin only (via `*`), interactive
    // console session only.
    "devices.remove",
];

pub const DEFAULT_POLICY_ID: &str = "default";

pub async fn connect(url: &str) -> anyhow::Result<PgPool> {
    let mut last_err = None;
    for attempt in 0..30 {
        match PgPoolOptions::new()
            .max_connections(32)
            .acquire_timeout(Duration::from_secs(10))
            .connect(url)
            .await
        {
            Ok(p) => return Ok(p),
            Err(e) => {
                tracing::warn!(attempt, error = %e, "waiting for postgres");
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("postgres unavailable")))
}

pub async fn migrate_and_seed(db: &PgPool) -> anyhow::Result<()> {
    MIGRATOR.run(db).await?;
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7413001)")
        .execute(&mut *tx)
        .await?;

    sqlx::query(
        "INSERT INTO settings (id, org_name, body) VALUES (1, '', $1) ON CONFLICT (id) DO NOTHING",
    )
    .bind(serde_json::to_value(Settings::default())?)
    .execute(&mut *tx)
    .await?;

    let roles: [(&str, &str, Vec<&str>); 3] = [
        ("admin", "Full access", vec!["*"]),
        (
            "analyst",
            "Triage incidents, respond, manage exclusions and IOCs",
            vec![
                "read",
                "incidents.write",
                "response.process",
                "response.file",
                "response.network",
                "response.collect",
                "exclusions.write",
                "iocs.write",
            ],
        ),
        ("readonly", "View only", vec!["read"]),
    ];
    for (name, desc, privs) in roles {
        sqlx::query(
            "INSERT INTO roles (name, description, privileges, builtin) VALUES ($1, $2, $3, true) ON CONFLICT (name) DO NOTHING",
        )
        .bind(name)
        .bind(desc)
        .bind(privs.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .execute(&mut *tx)
        .await?;
    }

    let has_policy: Option<(String,)> = sqlx::query_as("SELECT id FROM policies WHERE id = $1")
        .bind(DEFAULT_POLICY_ID)
        .fetch_optional(&mut *tx)
        .await?;
    if has_policy.is_none() {
        let (version,): (i64,) = sqlx::query_as("SELECT nextval('policy_version_seq')")
            .fetch_one(&mut *tx)
            .await?;
        let mut p = Policy {
            id: DEFAULT_POLICY_ID.into(),
            version: version as u64,
            ..Default::default()
        };
        let (org,): (String,) = sqlx::query_as("SELECT org_name FROM settings WHERE id = 1")
            .fetch_one(&mut *tx)
            .await?;
        p.branding.org_name = org;
        let now = now_ms();
        sqlx::query("INSERT INTO policies (id, name, version, body, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5)")
            .bind(&p.id)
            .bind(&p.name)
            .bind(version)
            .bind(serde_json::to_value(&p)?)
            .bind(now)
            .execute(&mut *tx)
            .await?;
    }
    let has_group: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM groups WHERE is_default")
        .fetch_optional(&mut *tx)
        .await?;
    if has_group.is_none() {
        sqlx::query(
            "INSERT INTO groups (id, name, description, policy_id, is_default, created_at) VALUES ($1, 'Default', 'Devices enrolled without a specific group', $2, true, $3)",
        )
        .bind(uuid::Uuid::new_v4())
        .bind(DEFAULT_POLICY_ID)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}
