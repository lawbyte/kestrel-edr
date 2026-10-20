//! Hash-chained audit log: `hash = HMAC-SHA256(k, prev_hash || canonical_json(row))`
//! where `k` is derived from the master key, so someone with database write access
//! alone cannot recompute the chain. The head hash is also written to the server
//! log (and syslog when configured) periodically as an external anchor.

use crate::crypto::{canonical_json, hmac_sha256_hex, sha256_hex, MasterKey};
use kestrel_common::now_ms;
use serde_json::{json, Value};
use sqlx::PgPool;
use std::sync::RwLock;
use uuid::Uuid;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Default)]
pub struct Actor {
    pub id: Option<Uuid>,
    pub email: Option<String>,
}

impl Actor {
    pub fn system() -> Actor {
        Actor::default()
    }
}

fn row_json(id: i64, ts: i64, actor: &Actor, action: &str, target: &str, details: &Value) -> Value {
    json!({
        "id": id,
        "ts": ts,
        "actor_id": actor.id.map(|u| u.to_string()),
        "actor_email": actor.email,
        "action": action,
        "target": target,
        "details": details,
    })
}

static KEY: RwLock<Option<[u8; 32]>> = RwLock::new(None);

/// Install the chain key (derived from the master key) — called once at startup.
pub fn set_key(mk: &MasterKey) {
    *KEY.write().unwrap_or_else(|e| e.into_inner()) = Some(mk.subkey("audit-chain"));
}

fn key() -> anyhow::Result<[u8; 32]> {
    KEY.read()
        .unwrap_or_else(|e| e.into_inner())
        .ok_or_else(|| anyhow::anyhow!("audit key not initialised"))
}

fn chain_input(prev_hash: &str, row: &Value) -> String {
    let mut s = String::with_capacity(prev_hash.len() + 256);
    s.push_str(prev_hash);
    s.push_str(&canonical_json(row));
    s
}

/// Keyed chain hash of one row.
pub fn compute_hash(key: &[u8], prev_hash: &str, row: &Value) -> String {
    hmac_sha256_hex(key, chain_input(prev_hash, row).as_bytes())
}

/// Pre-HMAC (v1) chain hash; only used to verify and upgrade old databases.
pub fn legacy_hash(prev_hash: &str, row: &Value) -> String {
    sha256_hex(chain_input(prev_hash, row))
}

/// Append an entry. Serialised with a transaction-scoped advisory lock so the chain stays linear.
pub async fn append(
    db: &PgPool,
    actor: &Actor,
    action: &str,
    target: &str,
    details: Value,
) -> anyhow::Result<i64> {
    // Round-trip through jsonb normalisation rules we rely on: only canonical JSON is hashed.
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7413002)")
        .execute(&mut *tx)
        .await?;
    let prev: Option<(String,)> =
        sqlx::query_as("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?;
    let prev_hash = prev.map(|p| p.0).unwrap_or_else(|| GENESIS.to_string());
    let (id,): (i64,) = sqlx::query_as("SELECT nextval('audit_log_id_seq')")
        .fetch_one(&mut *tx)
        .await?;
    let ts = now_ms();
    let row = row_json(id, ts, actor, action, target, &details);
    let hash = compute_hash(&key()?, &prev_hash, &row);
    sqlx::query(
        "INSERT INTO audit_log (id, ts, actor_id, actor_email, action, target, details, prev_hash, hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(id)
    .bind(ts)
    .bind(actor.id)
    .bind(&actor.email)
    .bind(action)
    .bind(target)
    .bind(&details)
    .bind(&prev_hash)
    .bind(&hash)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(id)
}

/// Fire-and-forget wrapper that logs failures (audit must not silently vanish).
pub async fn log(
    db: &PgPool,
    actor: &Actor,
    action: &str,
    target: impl AsRef<str>,
    details: Value,
) {
    if let Err(e) = append(db, actor, action, target.as_ref(), details).await {
        tracing::error!(error = %e, action, "failed to write audit log entry");
    }
}

#[derive(sqlx::FromRow)]
struct Row {
    id: i64,
    ts: i64,
    actor_id: Option<Uuid>,
    actor_email: Option<String>,
    action: String,
    target: String,
    details: Value,
    prev_hash: String,
    hash: String,
}

pub struct VerifyResult {
    pub ok: bool,
    pub broken_at: Option<i64>,
    pub count: i64,
}

/// Walk the chain in id order. The oldest remaining row anchors the chain
/// (older rows may have been removed by retention).
pub async fn verify(db: &PgPool) -> anyhow::Result<VerifyResult> {
    verify_with(db, &|prev, row| Ok(compute_hash(&key()?, prev, row))).await
}

type HashFn<'a> = &'a (dyn Fn(&str, &Value) -> anyhow::Result<String> + Sync);

async fn verify_with(db: &PgPool, hash: HashFn<'_>) -> anyhow::Result<VerifyResult> {
    let mut last_id = i64::MIN;
    let mut prev_hash: Option<String> = None;
    let mut count = 0i64;
    loop {
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, ts, actor_id, actor_email, action, target, details, prev_hash, hash FROM audit_log WHERE id > $1 ORDER BY id LIMIT 5000",
        )
        .bind(last_id)
        .fetch_all(db)
        .await?;
        if rows.is_empty() {
            break;
        }
        for r in rows {
            count += 1;
            last_id = r.id;
            if let Some(p) = &prev_hash {
                if &r.prev_hash != p {
                    return Ok(VerifyResult {
                        ok: false,
                        broken_at: Some(r.id),
                        count,
                    });
                }
            }
            let actor = Actor {
                id: r.actor_id,
                email: r.actor_email.clone(),
            };
            let row = row_json(r.id, r.ts, &actor, &r.action, &r.target, &r.details);
            if hash(&r.prev_hash, &row)? != r.hash {
                return Ok(VerifyResult {
                    ok: false,
                    broken_at: Some(r.id),
                    count,
                });
            }
            prev_hash = Some(r.hash);
        }
    }
    Ok(VerifyResult {
        ok: true,
        broken_at: None,
        count,
    })
}

/// Latest (id, hash) of the chain, if any.
pub async fn head(db: &PgPool) -> anyhow::Result<Option<(i64, String)>> {
    Ok(
        sqlx::query_as("SELECT id, hash FROM audit_log ORDER BY id DESC LIMIT 1")
            .fetch_optional(db)
            .await?,
    )
}

/// One-time upgrade of a pre-HMAC chain: if the unkeyed chain verifies, every row
/// is re-chained with the keyed hash. A broken legacy chain is left as is (so
/// verification keeps reporting it) instead of being laundered.
pub async fn upgrade_legacy(db: &PgPool) -> anyhow::Result<()> {
    let key = key()?;
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7413002)")
        .execute(&mut *tx)
        .await?;
    let marker: Option<(Value,)> =
        sqlx::query_as("SELECT data FROM server_secrets WHERE name = 'audit_hmac'")
            .fetch_optional(&mut *tx)
            .await?;
    if marker.is_some() {
        return Ok(());
    }
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM audit_log")
        .fetch_one(&mut *tx)
        .await?;
    let mut upgraded = false;
    if count > 0 {
        let legacy = verify_with(db, &|p, r| Ok(legacy_hash(p, r))).await?;
        if legacy.ok {
            let rows: Vec<Row> = sqlx::query_as(
                "SELECT id, ts, actor_id, actor_email, action, target, details, prev_hash, hash FROM audit_log ORDER BY id",
            )
            .fetch_all(&mut *tx)
            .await?;
            let mut prev: Option<String> = None;
            for r in rows {
                let prev_hash = prev.clone().unwrap_or(r.prev_hash.clone());
                let actor = Actor {
                    id: r.actor_id,
                    email: r.actor_email.clone(),
                };
                let row = row_json(r.id, r.ts, &actor, &r.action, &r.target, &r.details);
                let h = compute_hash(&key, &prev_hash, &row);
                sqlx::query("UPDATE audit_log SET prev_hash = $2, hash = $3 WHERE id = $1")
                    .bind(r.id)
                    .bind(&prev_hash)
                    .bind(&h)
                    .execute(&mut *tx)
                    .await?;
                prev = Some(h);
            }
            upgraded = true;
        } else {
            tracing::error!(
                broken_at = ?legacy.broken_at,
                "legacy audit chain does not verify; it is NOT upgraded to the keyed chain"
            );
        }
    }
    sqlx::query("INSERT INTO server_secrets (name, data) VALUES ('audit_hmac', $1) ON CONFLICT (name) DO NOTHING")
        .bind(json!({"since": now_ms(), "upgraded_rows": if upgraded { count } else { 0 }}))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if upgraded {
        tracing::warn!(
            rows = count,
            "audit log re-chained with the keyed (HMAC) hash"
        );
    }
    Ok(())
}
