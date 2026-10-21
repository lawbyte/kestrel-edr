//! Telemetry store: ClickHouse (preferred) or the Postgres `events` fallback.

pub mod clickhouse;
pub mod hunt;
pub mod postgres;

use kestrel_common::{Event, EventData, ProcessInfo, SignatureState};
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

/// Flattened columns shared by both backends.
#[derive(Serialize, Debug, Default, Clone)]
pub struct EventRow {
    pub ts: i64,
    pub device_id: Uuid,
    pub hostname: String,
    pub event_type: String,
    pub process_guid: String,
    pub pid: u32,
    pub ppid: u32,
    pub parent_guid: String,
    pub image: String,
    pub cmdline: String,
    pub user_name: String,
    pub integrity: String,
    pub signer: String,
    pub signed: String,
    pub sha256: String,
    pub file_path: String,
    pub file_op: String,
    pub reg_key: String,
    pub reg_value: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub dst_host: String,
    pub dns_qname: String,
    pub target_guid: String,
    pub target_image: String,
    pub granted_access: u32,
    pub dpapi_desc: String,
    pub raw: String,
}

fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

impl EventRow {
    pub fn from_event(device_id: Uuid, hostname: &str, e: &Event) -> EventRow {
        let mut r = EventRow {
            ts: e.ts,
            device_id,
            hostname: hostname.to_string(),
            event_type: e.kind().as_str().to_string(),
            process_guid: e.guid.0.clone(),
            pid: e.pid,
            raw: serde_json::to_string(e).unwrap_or_default(),
            ..Default::default()
        };
        match &e.data {
            EventData::ProcessStart(p) => {
                r.ppid = p.ppid;
                r.parent_guid = p
                    .parent_guid
                    .as_ref()
                    .map(|g| g.0.clone())
                    .unwrap_or_default();
                r.image = p.image.clone();
                r.cmdline = p.cmdline.clone();
                r.user_name = p.user.clone().unwrap_or_default();
                r.integrity = p.integrity.as_ref().map(enum_str).unwrap_or_default();
                r.signer = p.signer.clone().unwrap_or_default();
                r.signed = enum_str(&p.signed);
                r.sha256 = p.sha256.clone().unwrap_or_default().to_ascii_lowercase();
            }
            EventData::ProcessStop { .. } => {}
            EventData::ImageLoad {
                path,
                signer,
                signed,
            } => {
                r.file_path = path.clone();
                r.signer = signer.clone().unwrap_or_default();
                r.signed = enum_str(signed);
            }
            EventData::FileAccess { path, op } => {
                r.file_path = path.clone();
                r.file_op = enum_str(op);
            }
            EventData::RegistrySet {
                key,
                value_name,
                data,
                op,
                ..
            } => {
                r.reg_key = key.clone();
                r.reg_value = value_name.clone();
                // `op` column: set / delete_value / delete_key.
                r.file_op = enum_str(op);
                // Autorun-style values often hold a command line; make it
                // searchable through `cmdline`.
                r.cmdline = data.clone().unwrap_or_default();
            }
            EventData::NetConnect {
                dst_ip,
                dst_port,
                dst_host,
                ..
            } => {
                r.dst_ip = dst_ip.clone();
                r.dst_port = *dst_port;
                r.dst_host = dst_host.clone().unwrap_or_default();
            }
            EventData::DnsQuery { qname, .. } => r.dns_qname = qname.clone(),
            EventData::DpapiUnprotect { description } => r.dpapi_desc = description.clone(),
            EventData::ProcessAccess(t)
            | EventData::RemoteThread(t)
            | EventData::ThreadContext(t)
            | EventData::DebugAttach(t) => {
                r.target_guid = t
                    .target_guid
                    .as_ref()
                    .map(|g| g.0.clone())
                    .unwrap_or_default();
                r.target_image = t.target_image.clone();
                r.granted_access = t.granted_access;
            }
            EventData::ScriptBlock { .. } | EventData::Tamper { .. } => {}
            EventData::FileActivity(f) => {
                // A canary hit is the most telling path; else the first sample.
                r.file_path = f
                    .canary_hits
                    .first()
                    .or_else(|| f.sample_paths.first())
                    .cloned()
                    .unwrap_or_default();
                r.file_op = "activity".into();
            }
            EventData::TaskRegistered(t) => {
                // Task path in `file_path` (tasks live under System32\Tasks),
                // its Exec actions in `cmdline`, run-as principal in `user`.
                r.file_path = t.name.clone();
                r.file_op = enum_str(&t.op);
                r.cmdline = t.actions.join(" | ");
                r.user_name = t.user.clone().unwrap_or_default();
            }
            EventData::ServiceInstalled(sv) => {
                r.reg_key = format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{}", sv.name);
                r.file_path = sv.image_path.clone();
                r.cmdline = sv.image_path.clone();
                r.file_op = "install".into();
                r.user_name = sv.account.clone().unwrap_or_default();
            }
            EventData::WmiSubscription(w) => {
                r.reg_key = format!(r"{}\{}", w.namespace, w.filter);
                r.cmdline = w.consumer.clone();
                r.file_op = "bind".into();
            }
        }
        r
    }
}

/// A stored event as returned to the API: the original `Event` JSON plus
/// `device_id` and `hostname`.
#[derive(Debug, Clone)]
pub struct StoredEvent {
    pub device_id: Uuid,
    pub hostname: String,
    pub raw: serde_json::Value,
}

impl StoredEvent {
    pub fn to_api(&self, with_hostname: bool) -> serde_json::Value {
        let mut v = self.raw.clone();
        if let Some(o) = v.as_object_mut() {
            o.insert("device_id".into(), self.device_id.to_string().into());
            if with_hostname {
                o.insert("hostname".into(), self.hostname.clone().into());
            }
        }
        v
    }
    pub fn event(&self) -> Option<Event> {
        serde_json::from_value(self.raw.clone()).ok()
    }
}

#[derive(Debug, Clone, Default)]
pub struct EventQuery {
    pub device_id: Option<Uuid>,
    pub kinds: Vec<String>,
    /// Free text, case-insensitive contains over the main string columns.
    pub text: Option<String>,
    pub from: Option<i64>,
    pub to: Option<i64>,
    pub limit: u32,
    pub filter: Option<hunt::Expr>,
    pub guids: Vec<String>,
    pub ascending: bool,
}

/// Columns covered by free-text search.
pub const TEXT_COLUMNS: &[&str] = &[
    "image",
    "cmdline",
    "file_path",
    "dst_ip",
    "dst_host",
    "dns_qname",
    "reg_key",
    "target_image",
    "dpapi_desc",
    "user_name",
];

/// Valid `event_type` values.
pub const EVENT_KINDS: &[&str] = &[
    "process_start",
    "process_stop",
    "image_load",
    "file_access",
    "registry_set",
    "net_connect",
    "dns_query",
    "dpapi_unprotect",
    "process_access",
    "remote_thread",
    "thread_context",
    "debug_attach",
    "script_block",
    "tamper",
    "file_activity",
    "task_registered",
    "service_installed",
    "wmi_subscription",
];

/// Build the WHERE clause (never containing user values) plus its parameters.
pub fn build_where(q: &EventQuery, dialect: hunt::Dialect) -> (String, Vec<hunt::Param>) {
    use hunt::{Dialect, Param, SqlParams};
    let mut sp = SqlParams::new(dialect, 0);
    let mut conds: Vec<String> = vec![];
    if let Some(d) = q.device_id {
        let ph = sp.push(Param::Str(d.to_string()));
        conds.push(match dialect {
            Dialect::Postgres => format!("device_id = {ph}::uuid"),
            Dialect::ClickHouse => format!("device_id = toUUID({ph})"),
        });
    }
    let kinds: Vec<&String> = q
        .kinds
        .iter()
        .filter(|k| EVENT_KINDS.contains(&k.as_str()))
        .collect();
    if !kinds.is_empty() {
        let phs: Vec<String> = kinds
            .iter()
            .map(|k| sp.push(Param::Str((*k).clone())))
            .collect();
        conds.push(format!("event_type IN ({})", phs.join(", ")));
    }
    let ts_expr = match dialect {
        Dialect::Postgres => "ts",
        Dialect::ClickHouse => "ts",
    };
    if let Some(from) = q.from {
        let ph = sp.push(Param::Int(from));
        conds.push(match dialect {
            Dialect::Postgres => format!("{ts_expr} >= {ph}"),
            Dialect::ClickHouse => format!("ts >= fromUnixTimestamp64Milli({ph}, 'UTC')"),
        });
    }
    if let Some(to) = q.to {
        let ph = sp.push(Param::Int(to));
        conds.push(match dialect {
            Dialect::Postgres => format!("{ts_expr} <= {ph}"),
            Dialect::ClickHouse => format!("ts <= fromUnixTimestamp64Milli({ph}, 'UTC')"),
        });
    }
    if let Some(t) = q.text.as_ref().filter(|t| !t.trim().is_empty()) {
        let t: String = t.chars().take(hunt::MAX_VALUE_LEN).collect();
        let ph = sp.push(Param::Str(t));
        let parts: Vec<String> = TEXT_COLUMNS
            .iter()
            .map(|c| match dialect {
                Dialect::Postgres => format!("strpos(lower({c}), lower({ph})) > 0"),
                Dialect::ClickHouse => format!("positionCaseInsensitiveUTF8({c}, {ph}) > 0"),
            })
            .collect();
        conds.push(format!("({})", parts.join(" OR ")));
    }
    if !q.guids.is_empty() {
        let phs: Vec<String> = q
            .guids
            .iter()
            .take(1000)
            .map(|g| sp.push(Param::Str(g.clone())))
            .collect();
        conds.push(format!("process_guid IN ({})", phs.join(", ")));
    }
    if let Some(f) = &q.filter {
        conds.push(hunt::render(f, &mut sp));
    }
    let w = if conds.is_empty() {
        "1 = 1".to_string()
    } else {
        conds.join(" AND ")
    };
    (w, sp.params)
}

#[async_trait::async_trait]
pub trait EventStore: Send + Sync {
    fn backend(&self) -> &'static str;
    async fn init(&self, retention_days: u32) -> anyhow::Result<()>;
    async fn insert(&self, rows: Vec<EventRow>) -> anyhow::Result<()>;
    async fn query(&self, q: &EventQuery) -> anyhow::Result<Vec<StoredEvent>>;
    /// Apply event retention (ClickHouse: TTL; Postgres: delete).
    async fn apply_retention(&self, days: u32) -> anyhow::Result<u64>;
}

/// API JSON for events, with `process_image` (image of the acting process,
/// looked up from its process_start) added to non-process_start events.
pub async fn events_to_api(
    store: &dyn EventStore,
    rows: &[StoredEvent],
    with_hostname: bool,
) -> Vec<serde_json::Value> {
    let mut wanted: HashMap<Uuid, Vec<String>> = HashMap::new();
    for r in rows {
        let ty = r.raw.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if ty != "process_start" {
            if let Some(g) = r.raw.get("guid").and_then(|g| g.as_str()) {
                let v = wanted.entry(r.device_id).or_default();
                if !v.iter().any(|x| x == g) {
                    v.push(g.to_string());
                }
            }
        }
    }
    let mut images: HashMap<(Uuid, String), String> = HashMap::new();
    for r in rows {
        if r.raw.get("type").and_then(|t| t.as_str()) == Some("process_start") {
            if let (Some(g), Some(img)) = (
                r.raw.get("guid").and_then(|g| g.as_str()),
                r.raw.get("image").and_then(|i| i.as_str()),
            ) {
                images.insert((r.device_id, g.to_string()), img.to_string());
            }
        }
    }
    for (device, guids) in wanted {
        let missing: Vec<String> = guids
            .into_iter()
            .filter(|g| !images.contains_key(&(device, g.clone())))
            .collect();
        for chunk in missing.chunks(500) {
            let q = EventQuery {
                device_id: Some(device),
                kinds: vec!["process_start".into()],
                guids: chunk.to_vec(),
                limit: 1000,
                ..Default::default()
            };
            match store.query(&q).await {
                Ok(found) => {
                    for f in found {
                        if let (Some(g), Some(img)) = (
                            f.raw.get("guid").and_then(|g| g.as_str()),
                            f.raw.get("image").and_then(|i| i.as_str()),
                        ) {
                            images.insert((device, g.to_string()), img.to_string());
                        }
                    }
                }
                Err(e) => tracing::warn!(error = %e, "process_image lookup failed"),
            }
        }
    }
    rows.iter()
        .map(|r| {
            let mut v = r.to_api(with_hostname);
            let ty = r.raw.get("type").and_then(|t| t.as_str()).unwrap_or("");
            if ty != "process_start" {
                if let Some(g) = r.raw.get("guid").and_then(|g| g.as_str()) {
                    if let (Some(img), Some(o)) =
                        (images.get(&(r.device_id, g.to_string())), v.as_object_mut())
                    {
                        o.insert("process_image".into(), img.clone().into());
                    }
                }
            }
            v
        })
        .collect()
}

/// Rebuild the set of processes alive at `at` from process_start/stop events.
pub fn reconstruct_processes(events: &[StoredEvent], at: i64) -> Vec<ProcessInfo> {
    let mut procs: HashMap<String, ProcessInfo> = HashMap::new();
    let mut stops: HashMap<String, i64> = HashMap::new();
    for se in events {
        let Some(e) = se.event() else { continue };
        if e.ts > at {
            continue;
        }
        match &e.data {
            EventData::ProcessStart(p) => {
                procs.insert(
                    e.guid.0.clone(),
                    ProcessInfo {
                        guid: e.guid.clone(),
                        pid: e.pid,
                        ppid: p.ppid,
                        parent_guid: p.parent_guid.clone(),
                        image: p.image.clone(),
                        cmdline: p.cmdline.clone(),
                        user: p.user.clone(),
                        integrity: p.integrity,
                        start_ts: e.ts,
                        exit_ts: None,
                        signer: p.signer.clone(),
                        signed: p.signed,
                        sha256: p.sha256.clone(),
                        motw_zone: p.motw_zone,
                        file_size: p.file_size,
                        path_class: kestrel_common::PathClass::of(&p.image),
                    },
                );
            }
            EventData::ProcessStop { .. } => {
                stops.insert(e.guid.0.clone(), e.ts);
            }
            _ => {}
        }
    }
    let mut out: Vec<ProcessInfo> = procs
        .into_values()
        .filter(|p| !stops.contains_key(&p.guid.0))
        .collect();
    out.sort_by_key(|p| p.start_ts);
    out
}

pub fn signed_from_str(s: &str) -> SignatureState {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or_default()
}
