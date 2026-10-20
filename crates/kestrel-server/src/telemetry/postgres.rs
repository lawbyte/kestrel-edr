//! Postgres fallback event store (small deployments / dev). Retention is capped at 7 days.

use super::{build_where, hunt, EventQuery, EventRow, EventStore, StoredEvent};
use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

pub const MAX_RETENTION_DAYS: u32 = 7;

pub struct PgEventStore {
    db: PgPool,
}

impl PgEventStore {
    pub fn new(db: PgPool) -> Self {
        PgEventStore { db }
    }
}

#[async_trait::async_trait]
impl EventStore for PgEventStore {
    fn backend(&self) -> &'static str {
        "postgres"
    }

    async fn init(&self, _retention_days: u32) -> anyhow::Result<()> {
        Ok(())
    }

    async fn insert(&self, rows: Vec<EventRow>) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut tx = self.db.begin().await?;
        // 26 binds per row; stay well below the 65535 bind limit.
        for chunk in rows.chunks(1000) {
            let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
                "INSERT INTO events (ts, device_id, hostname, event_type, process_guid, pid, ppid, parent_guid, image, cmdline, \
                 user_name, signer, signed, sha256, file_path, file_op, reg_key, dst_ip, dst_port, dst_host, dns_qname, \
                 target_guid, target_image, dpapi_desc, raw) ",
            );
            qb.push_values(chunk, |mut b, r| {
                let raw: serde_json::Value = serde_json::from_str(&r.raw).unwrap_or_default();
                b.push_bind(r.ts)
                    .push_bind(r.device_id)
                    .push_bind(&r.hostname)
                    .push_bind(&r.event_type)
                    .push_bind(&r.process_guid)
                    .push_bind(r.pid as i64)
                    .push_bind(r.ppid as i64)
                    .push_bind(&r.parent_guid)
                    .push_bind(&r.image)
                    .push_bind(&r.cmdline)
                    .push_bind(&r.user_name)
                    .push_bind(&r.signer)
                    .push_bind(&r.signed)
                    .push_bind(&r.sha256)
                    .push_bind(&r.file_path)
                    .push_bind(&r.file_op)
                    .push_bind(&r.reg_key)
                    .push_bind(&r.dst_ip)
                    .push_bind(r.dst_port as i32)
                    .push_bind(&r.dst_host)
                    .push_bind(&r.dns_qname)
                    .push_bind(&r.target_guid)
                    .push_bind(&r.target_image)
                    .push_bind(&r.dpapi_desc)
                    .push_bind(raw);
            });
            qb.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn query(&self, q: &EventQuery) -> anyhow::Result<Vec<StoredEvent>> {
        let (w, params) = build_where(q, hunt::Dialect::Postgres);
        let order = if q.ascending { "ASC" } else { "DESC" };
        let limit = q.limit.clamp(1, 10_000);
        let sql = format!("SELECT device_id, hostname, raw FROM events WHERE {w} ORDER BY ts {order}, id {order} LIMIT {limit}");
        let mut query = sqlx::query_as::<_, (Uuid, String, serde_json::Value)>(&sql);
        for p in params {
            query = match p {
                hunt::Param::Str(s) => query.bind(s),
                hunt::Param::Int(i) => query.bind(i),
            };
        }
        let rows = query.fetch_all(&self.db).await?;
        Ok(rows
            .into_iter()
            .map(|(device_id, hostname, raw)| StoredEvent {
                device_id,
                hostname,
                raw,
            })
            .collect())
    }

    async fn apply_retention(&self, days: u32) -> anyhow::Result<u64> {
        let days = days.clamp(1, MAX_RETENTION_DAYS) as i64;
        let cutoff = kestrel_common::now_ms() - days * 86_400_000;
        let r = sqlx::query("DELETE FROM events WHERE ts < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await?;
        Ok(r.rows_affected())
    }
}
