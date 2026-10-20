//! ClickHouse event store over the HTTP interface (JSONEachRow inserts, typed
//! query parameters for every user-supplied value).

use super::{build_where, hunt, EventQuery, EventRow, EventStore, StoredEvent};
use crate::config::ClickHouseConfig;
use anyhow::Context;
use uuid::Uuid;

pub struct ClickHouseStore {
    cfg: ClickHouseConfig,
    http: reqwest::Client,
}

/// Escape a value for ClickHouse's `param_*` (TSV escaped format).
pub fn escape_param(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\0' => out.push_str("\\0"),
            c => out.push(c),
        }
    }
    out
}

fn valid_ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

impl ClickHouseStore {
    pub fn new(cfg: ClickHouseConfig) -> anyhow::Result<Self> {
        if !valid_ident(&cfg.database) {
            anyhow::bail!("CLICKHOUSE_DB must match [A-Za-z0-9_]+");
        }
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .no_proxy()
            .build()?;
        Ok(ClickHouseStore { cfg, http })
    }

    fn req(&self) -> reqwest::RequestBuilder {
        self.http
            .post(format!("{}/", self.cfg.url))
            .header("X-ClickHouse-User", &self.cfg.user)
            .header("X-ClickHouse-Key", &self.cfg.password)
    }

    async fn exec(&self, sql: &str) -> anyhow::Result<String> {
        let resp = self
            .req()
            .body(sql.to_string())
            .send()
            .await
            .context("clickhouse request")?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!(
                "clickhouse error {status}: {}",
                text.chars().take(500).collect::<String>()
            );
        }
        Ok(text)
    }

    fn table(&self) -> String {
        format!("{}.events", self.cfg.database)
    }
}

fn fmt_ts(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .unwrap_or_default()
        .format("%Y-%m-%d %H:%M:%S%.3f")
        .to_string()
}

#[async_trait::async_trait]
impl EventStore for ClickHouseStore {
    fn backend(&self) -> &'static str {
        "clickhouse"
    }

    async fn init(&self, retention_days: u32) -> anyhow::Result<()> {
        let mut last = None;
        for attempt in 0..30 {
            match self.exec("SELECT 1").await {
                Ok(_) => {
                    last = None;
                    break;
                }
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "waiting for clickhouse");
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                }
            }
        }
        if let Some(e) = last {
            return Err(e);
        }
        self.exec(&format!(
            "CREATE DATABASE IF NOT EXISTS {}",
            self.cfg.database
        ))
        .await?;
        let days = retention_days.max(1);
        self.exec(&format!(
            "CREATE TABLE IF NOT EXISTS {t} (
                ts DateTime64(3, 'UTC'),
                device_id UUID,
                hostname LowCardinality(String),
                event_type LowCardinality(String),
                process_guid String,
                pid UInt32,
                ppid UInt32,
                parent_guid String,
                image String,
                cmdline String CODEC(ZSTD(3)),
                user_name LowCardinality(String),
                integrity LowCardinality(String),
                signer LowCardinality(String),
                signed LowCardinality(String),
                sha256 String,
                file_path String,
                file_op LowCardinality(String),
                reg_key String,
                reg_value String,
                dst_ip String,
                dst_port UInt16,
                dst_host String,
                dns_qname String,
                target_guid String,
                target_image String,
                granted_access UInt32,
                dpapi_desc String,
                raw String CODEC(ZSTD(3)),
                INDEX idx_image image TYPE ngrambf_v1(3, 4096, 2, 0) GRANULARITY 4,
                INDEX idx_guid process_guid TYPE bloom_filter GRANULARITY 4
            ) ENGINE = MergeTree
            PARTITION BY toDate(ts)
            ORDER BY (device_id, event_type, ts)
            TTL toDateTime(ts) + INTERVAL {days} DAY",
            t = self.table()
        ))
        .await?;
        Ok(())
    }

    async fn insert(&self, rows: Vec<EventRow>) -> anyhow::Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let mut body = Vec::with_capacity(rows.len() * 512);
        for r in &rows {
            let mut v = serde_json::to_value(r)?;
            v["ts"] = fmt_ts(r.ts).into();
            serde_json::to_writer(&mut body, &v)?;
            body.push(b'\n');
        }
        let q = format!("INSERT INTO {} FORMAT JSONEachRow", self.table());
        // async_insert lets ClickHouse coalesce many small agent batches; waiting
        // for it keeps the agent Ack semantics ("durably stored").
        let resp = self
            .req()
            .query(&[
                ("query", q.as_str()),
                ("async_insert", "1"),
                ("wait_for_async_insert", "1"),
                ("input_format_skip_unknown_fields", "1"),
            ])
            .body(body)
            .send()
            .await
            .context("clickhouse insert")?;
        if !resp.status().is_success() {
            let s = resp.status();
            let t = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "clickhouse insert failed {s}: {}",
                t.chars().take(500).collect::<String>()
            );
        }
        Ok(())
    }

    async fn query(&self, q: &EventQuery) -> anyhow::Result<Vec<StoredEvent>> {
        let (w, params) = build_where(q, hunt::Dialect::ClickHouse);
        let order = if q.ascending { "ASC" } else { "DESC" };
        let limit = q.limit.clamp(1, 10_000);
        let sql = format!(
            "SELECT toString(device_id) AS device_id_str, hostname, raw FROM {} WHERE {w} ORDER BY ts {order} LIMIT {limit} FORMAT JSONEachRow",
            self.table()
        );
        let mut qp: Vec<(String, String)> = vec![("max_execution_time".into(), "60".into())];
        for (i, p) in params.iter().enumerate() {
            let v = match p {
                hunt::Param::Str(s) => escape_param(s),
                hunt::Param::Int(n) => n.to_string(),
            };
            qp.push((format!("param_p{}", i + 1), v));
        }
        let resp = self
            .req()
            .query(&qp)
            .body(sql)
            .send()
            .await
            .context("clickhouse query")?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            anyhow::bail!(
                "clickhouse query failed {status}: {}",
                text.chars().take(500).collect::<String>()
            );
        }
        #[derive(serde::Deserialize)]
        struct Row {
            device_id_str: String,
            hostname: String,
            raw: String,
        }
        let mut out = vec![];
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let r: Row = serde_json::from_str(line)?;
            out.push(StoredEvent {
                device_id: Uuid::parse_str(&r.device_id_str).unwrap_or_default(),
                hostname: r.hostname,
                raw: serde_json::from_str(&r.raw).unwrap_or(serde_json::Value::Null),
            });
        }
        Ok(out)
    }

    async fn apply_retention(&self, days: u32) -> anyhow::Result<u64> {
        let days = days.max(1);
        self.exec(&format!(
            "ALTER TABLE {} MODIFY TTL toDateTime(ts) + INTERVAL {days} DAY",
            self.table()
        ))
        .await?;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn escapes() {
        assert_eq!(super::escape_param("C:\\a\tb\n"), "C:\\\\a\\tb\\n");
    }
}
