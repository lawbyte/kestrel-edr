//! Durable local state in SQLite (WAL): the upload outbox, policy/rule caches,
//! counters, the tray activity log and the executed-command ledger.
//!
//! Outbox semantics:
//! * `seq` is the envelope seq sent to the server (strictly increasing,
//!   AUTOINCREMENT so it is never reused even after deletes).
//! * Rows are (re)sent in `seq` order; the server's cumulative
//!   `Ack { seq }` deletes every row with `seq <= ack`.
//! * Priorities only govern what is dropped when the outbox exceeds
//!   `policy.telemetry.max_outbox_mb`: oldest events first, then inventory,
//!   then heartbeats. High-priority rows (alerts, action results, review
//!   requests) are never dropped.

use anyhow::{Context, Result};
use kestrel_common::{
    tray::{ActivityItem, ReviewState},
    wire::AgentPayload,
    TimestampMs,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{de::DeserializeOwned, Serialize};
use std::path::Path;
use std::sync::Mutex;
use uuid::Uuid;

use crate::codec;

pub const DB_FILE: &str = "agent.db";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Events = 0,
    Inventory = 1,
    Heartbeat = 2,
    /// Alerts, action results, review requests: never dropped.
    High = 3,
}

impl Priority {
    pub fn of(p: &AgentPayload) -> Priority {
        match p {
            AgentPayload::Events { .. } => Priority::Events,
            AgentPayload::Inventory(_) => Priority::Inventory,
            AgentPayload::Heartbeat(_)
            | AgentPayload::Hello(_)
            | AgentPayload::Ack { .. }
            | AgentPayload::RenewCertificate { .. } => Priority::Heartbeat,
            AgentPayload::Alert(_)
            | AgentPayload::ActionResult { .. }
            | AgentPayload::ReviewRequest(_) => Priority::High,
        }
    }
}

pub fn payload_kind(p: &AgentPayload) -> &'static str {
    match p {
        AgentPayload::Hello(_) => "hello",
        AgentPayload::Heartbeat(_) => "heartbeat",
        AgentPayload::Events { .. } => "events",
        AgentPayload::Alert(_) => "alert",
        AgentPayload::ActionResult { .. } => "action_result",
        AgentPayload::ReviewRequest(_) => "review_request",
        AgentPayload::Inventory(_) => "inventory",
        AgentPayload::Ack { .. } => "ack",
        AgentPayload::RenewCertificate { .. } => "renew_certificate",
    }
}

/// One outbox row ready to send.
#[derive(Debug, Clone, PartialEq)]
pub struct OutboxItem {
    pub seq: u64,
    pub priority: i64,
    pub kind: String,
    pub payload: Vec<u8>,
    pub compressed: bool,
    pub created: TimestampMs,
}

pub struct Store {
    conn: Mutex<Connection>,
}

// kv keys
pub const KV_POLICY: &str = "policy";
pub const KV_RULES: &str = "rules";
pub const KV_HEARTBEAT_SEQ: &str = "heartbeat_seq";
pub const KV_LAST_POLICY_SYNC: &str = "last_policy_sync";
pub const KV_LAST_INVENTORY: &str = "last_inventory";
pub const KV_LAST_CHECK: &str = "last_check";
pub const KV_SERVER_IPS: &str = "server_ips";
pub const KV_USER_SALT: &str = "user_hash_salt";
pub const KV_LAST_UPDATE: &str = "last_update_version";
pub const KV_LAST_HEALTH: &str = "last_health";
pub const KV_LAST_HEARTBEAT: &str = "last_heartbeat";
/// Random id created together with the outbox (M8, sent in `Hello`).
pub const KV_OUTBOX_EPOCH: &str = "outbox_epoch";
/// Last time (ms) a session with the server was established (Welcome).
pub const KV_LAST_CONNECTED: &str = "last_connected";
/// Review requests per user (tray rate limit), JSON map.
pub const KV_TRAY_LIMITS: &str = "tray_limits";

impl Store {
    pub fn open(state_dir: &Path) -> Result<Store> {
        std::fs::create_dir_all(state_dir)?;
        let path = state_dir.join(DB_FILE);
        let conn =
            Connection::open(&path).with_context(|| format!("opening {}", path.display()))?;
        Self::init(conn)
    }

    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store> {
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS outbox (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                priority INTEGER NOT NULL,
                kind TEXT NOT NULL,
                payload BLOB NOT NULL,
                compressed INTEGER NOT NULL,
                created INTEGER NOT NULL
             );
             CREATE INDEX IF NOT EXISTS outbox_prio ON outbox(priority, seq);
             CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS activity (
                id TEXT PRIMARY KEY,
                ts INTEGER NOT NULL,
                alert_id TEXT,
                item TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS activity_ts ON activity(ts);
             CREATE TABLE IF NOT EXISTS commands (
                command_id TEXT PRIMARY KEY,
                ts INTEGER NOT NULL,
                outcome TEXT NOT NULL
             );",
        )?;
        // M3: activity items carry their owner (lower-case user SID or
        // DOMAIN\\user); NULL = machine-wide (visible to every tray user).
        let has_owner: bool = conn
            .prepare("SELECT 1 FROM pragma_table_info('activity') WHERE name = 'owner'")?
            .exists([])?;
        if !has_owner {
            conn.execute_batch("ALTER TABLE activity ADD COLUMN owner TEXT;")?;
        }
        // M8: the outbox epoch is created with the database and never changes
        // while the database exists.
        conn.execute(
            "INSERT OR IGNORE INTO kv(k, v) VALUES (?1, ?2)",
            params![KV_OUTBOX_EPOCH, Uuid::new_v4().to_string()],
        )?;
        Ok(Store {
            conn: Mutex::new(conn),
        })
    }

    /// Random id of this outbox database (see [`KV_OUTBOX_EPOCH`]).
    pub fn outbox_epoch(&self) -> Option<Uuid> {
        self.kv_get(KV_OUTBOX_EPOCH)
            .ok()
            .flatten()
            .and_then(|s| s.parse().ok())
    }

    fn db(&self) -> std::sync::MutexGuard<'_, Connection> {
        // A poisoned lock only means another thread panicked mid-call; SQLite
        // itself is still consistent, so keep going.
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---------------------------------------------------------------- outbox

    /// Append a payload; returns its seq. Event batches are always compressed.
    pub fn enqueue(&self, payload: &AgentPayload) -> Result<u64> {
        let force = matches!(payload, AgentPayload::Events { .. });
        let (bytes, compressed) = codec::encode(payload, force)?;
        let prio = Priority::of(payload) as i64;
        let db = self.db();
        db.execute(
            "INSERT INTO outbox(priority, kind, payload, compressed, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![prio, payload_kind(payload), bytes, compressed as i64, kestrel_common::now_ms()],
        )?;
        Ok(db.last_insert_rowid() as u64)
    }

    /// Unacked rows with `seq > after`, in seq order.
    pub fn pending_after(&self, after: u64, limit: usize) -> Result<Vec<OutboxItem>> {
        let db = self.db();
        let mut st = db.prepare_cached(
            "SELECT seq, priority, kind, payload, compressed, created FROM outbox WHERE seq > ?1 ORDER BY seq LIMIT ?2",
        )?;
        let rows = st
            .query_map(params![after as i64, limit as i64], |r| {
                Ok(OutboxItem {
                    seq: r.get::<_, i64>(0)? as u64,
                    priority: r.get(1)?,
                    kind: r.get(2)?,
                    payload: r.get(3)?,
                    compressed: r.get::<_, i64>(4)? != 0,
                    created: r.get(5)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    /// Cumulative ack: drop every row with `seq <= seq`. Returns rows removed.
    pub fn ack(&self, seq: u64) -> Result<usize> {
        Ok(self
            .db()
            .execute("DELETE FROM outbox WHERE seq <= ?1", params![seq as i64])?)
    }

    pub fn depth(&self) -> Result<u64> {
        Ok(self
            .db()
            .query_row("SELECT COUNT(*) FROM outbox", [], |r| r.get::<_, i64>(0))?
            as u64)
    }

    /// Approximate outbox size in bytes (payload bytes + row overhead).
    pub fn outbox_bytes(&self) -> Result<u64> {
        let v: i64 = self.db().query_row(
            "SELECT COALESCE(SUM(LENGTH(payload) + 64), 0) FROM outbox",
            [],
            |r| r.get(0),
        )?;
        Ok(v as u64)
    }

    /// Enforce the size cap. Drops oldest low-priority rows first; never drops
    /// [`Priority::High`]. Returns number of rows dropped.
    pub fn enforce_cap(&self, max_bytes: u64) -> Result<u64> {
        let mut dropped = 0u64;
        let mut size = self.outbox_bytes()?;
        if size <= max_bytes {
            return Ok(0);
        }
        let db = self.db();
        for prio in [Priority::Events, Priority::Inventory, Priority::Heartbeat] {
            loop {
                if size <= max_bytes {
                    return Ok(dropped);
                }
                // Delete in chunks of oldest rows of this priority.
                let rows: Vec<(i64, i64)> = {
                    let mut st = db.prepare_cached(
                        "SELECT seq, LENGTH(payload) + 64 FROM outbox WHERE priority = ?1 ORDER BY seq LIMIT 256",
                    )?;
                    let v = st
                        .query_map(params![prio as i64], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<Result<Vec<_>, _>>()?;
                    v
                };
                if rows.is_empty() {
                    break;
                }
                let mut last = 0i64;
                for (seq, len) in rows {
                    last = seq;
                    size = size.saturating_sub(len as u64);
                    dropped += 1;
                    if size <= max_bytes {
                        break;
                    }
                }
                db.execute(
                    "DELETE FROM outbox WHERE priority = ?1 AND seq <= ?2",
                    params![prio as i64, last],
                )?;
            }
        }
        Ok(dropped)
    }

    // -------------------------------------------------------------------- kv

    pub fn kv_get(&self, k: &str) -> Result<Option<String>> {
        Ok(self
            .db()
            .query_row("SELECT v FROM kv WHERE k = ?1", params![k], |r| r.get(0))
            .optional()?)
    }

    pub fn kv_set(&self, k: &str, v: &str) -> Result<()> {
        self.db().execute(
            "INSERT INTO kv(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            params![k, v],
        )?;
        Ok(())
    }

    pub fn kv_get_json<T: DeserializeOwned>(&self, k: &str) -> Result<Option<T>> {
        match self.kv_get(k)? {
            Some(s) => Ok(Some(serde_json::from_str(&s)?)),
            None => Ok(None),
        }
    }

    pub fn kv_set_json<T: Serialize>(&self, k: &str, v: &T) -> Result<()> {
        self.kv_set(k, &serde_json::to_string(v)?)
    }

    pub fn kv_get_i64(&self, k: &str) -> Option<i64> {
        self.kv_get(k).ok().flatten().and_then(|s| s.parse().ok())
    }

    /// Atomically increment and return a persisted counter (heartbeat seq).
    pub fn next_counter(&self, k: &str) -> Result<u64> {
        let db = self.db();
        db.execute(
            "INSERT INTO kv(k, v) VALUES (?1, '1')
             ON CONFLICT(k) DO UPDATE SET v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)",
            params![k],
        )?;
        let v: String = db.query_row("SELECT v FROM kv WHERE k = ?1", params![k], |r| r.get(0))?;
        Ok(v.parse()?)
    }

    // -------------------------------------------------------------- activity

    /// Store an activity item. `owner` = lower-case user SID or
    /// `domain\\user` of the user it concerns; `None` = machine-wide.
    pub fn add_activity(&self, item: &ActivityItem, owner: Option<&str>) -> Result<()> {
        let db = self.db();
        db.execute(
            "INSERT OR REPLACE INTO activity(id, ts, alert_id, item, owner) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                item.id.to_string(),
                item.ts,
                item.alert_id.map(|a| a.to_string()),
                serde_json::to_string(item)?,
                owner.map(|o| o.trim().to_ascii_lowercase())
            ],
        )?;
        // Keep the log bounded.
        db.execute(
            "DELETE FROM activity WHERE id NOT IN (SELECT id FROM activity ORDER BY ts DESC LIMIT 1000)",
            [],
        )?;
        Ok(())
    }

    /// Newest first (all owners; agent-internal use).
    pub fn activity(&self, limit: u32) -> Result<Vec<ActivityItem>> {
        let db = self.db();
        let mut st = db.prepare_cached("SELECT item FROM activity ORDER BY ts DESC LIMIT ?1")?;
        let rows = st
            .query_map(params![limit as i64], |r| r.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        Ok(rows)
    }

    /// Newest first: machine-wide items plus items owned by any of `owners`
    /// (lower-case SID / account name).
    pub fn activity_for(&self, owners: &[String], limit: u32) -> Result<Vec<ActivityItem>> {
        let db = self.db();
        let mut st =
            db.prepare_cached("SELECT item, owner FROM activity ORDER BY ts DESC LIMIT ?1")?;
        // Scan a bounded window (the table holds at most 1000 rows).
        let rows = st
            .query_map(params![1000i64], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
            })?
            .filter_map(|r| r.ok())
            .filter(|(_, o)| o.as_ref().is_none_or(|o| owners.iter().any(|k| k == o)))
            .filter_map(|(s, _)| serde_json::from_str(&s).ok())
            .take(limit as usize)
            .collect();
        Ok(rows)
    }

    /// Owner of the activity items of `alert_id`: `Some(None)` = machine-wide,
    /// `None` = no such alert.
    pub fn alert_owner(&self, alert_id: Uuid) -> Option<Option<String>> {
        self.db()
            .query_row(
                "SELECT owner FROM activity WHERE alert_id = ?1 LIMIT 1",
                params![alert_id.to_string()],
                |r| r.get::<_, Option<String>>(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Review state recorded on the alert's activity items.
    pub fn review_state(&self, alert_id: Uuid) -> Option<ReviewState> {
        let db = self.db();
        let mut st = db
            .prepare_cached("SELECT item FROM activity WHERE alert_id = ?1")
            .ok()?;
        let items: Vec<ActivityItem> = st
            .query_map(params![alert_id.to_string()], |r| r.get::<_, String>(0))
            .ok()?
            .filter_map(|r| r.ok())
            .filter_map(|s| serde_json::from_str(&s).ok())
            .collect();
        items.into_iter().find_map(|i| i.review)
    }

    /// Set the review state of activity items for `alert_id`; returns the updated items.
    pub fn set_review_state(
        &self,
        alert_id: Uuid,
        state: ReviewState,
    ) -> Result<Vec<ActivityItem>> {
        let items: Vec<(ActivityItem, Option<String>)> = {
            let db = self.db();
            let mut st =
                db.prepare_cached("SELECT item, owner FROM activity WHERE alert_id = ?1")?;
            let v = st
                .query_map(params![alert_id.to_string()], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
                })?
                .filter_map(|r| r.ok())
                .filter_map(|(s, o)| {
                    serde_json::from_str::<ActivityItem>(&s)
                        .ok()
                        .map(|i| (i, o))
                })
                .collect();
            v
        };
        let mut out = vec![];
        for (mut it, owner) in items {
            it.review = Some(state);
            self.add_activity(&it, owner.as_deref())?;
            out.push(it);
        }
        Ok(out)
    }

    pub fn has_alert_activity(&self, alert_id: Uuid) -> bool {
        self.db()
            .query_row(
                "SELECT 1 FROM activity WHERE alert_id = ?1",
                params![alert_id.to_string()],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    // -------------------------------------------------------------- commands

    pub fn command_outcome(&self, id: Uuid) -> Result<Option<kestrel_common::ActionOutcome>> {
        let s: Option<String> = self
            .db()
            .query_row(
                "SELECT outcome FROM commands WHERE command_id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        Ok(match s {
            Some(s) => Some(serde_json::from_str(&s)?),
            None => None,
        })
    }

    pub fn record_command(&self, id: Uuid, outcome: &kestrel_common::ActionOutcome) -> Result<()> {
        let db = self.db();
        db.execute(
            "INSERT OR REPLACE INTO commands(command_id, ts, outcome) VALUES (?1, ?2, ?3)",
            params![
                id.to_string(),
                kestrel_common::now_ms(),
                serde_json::to_string(outcome)?
            ],
        )?;
        // Remember 30 days of command ids.
        db.execute(
            "DELETE FROM commands WHERE ts < ?1",
            params![kestrel_common::now_ms() - 30 * 24 * 3600 * 1000],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{
        wire::{AgentHealth, Heartbeat},
        ActionOutcome, Event, EventData, FileOp, ProcessGuid, ResponseAction, Severity,
    };

    fn ev(i: u32) -> Event {
        Event {
            ts: i as i64,
            pid: i,
            guid: ProcessGuid::derive("b", i, 0),
            data: EventData::FileAccess {
                path: format!("C:\\Users\\a\\file{i}.txt"),
                op: FileOp::Read,
            },
        }
    }

    fn events(n: u32) -> AgentPayload {
        AgentPayload::Events {
            events: (0..n).map(ev).collect(),
        }
    }

    fn result() -> AgentPayload {
        AgentPayload::ActionResult {
            command_id: Uuid::new_v4(),
            outcome: ActionOutcome {
                action: ResponseAction::ReleaseHost,
                ok: true,
                detail: String::new(),
                ts: 1,
                artifact: None,
            },
        }
    }

    fn hb(seq: u64) -> AgentPayload {
        AgentPayload::Heartbeat(Heartbeat {
            seq,
            ts: 1,
            health: AgentHealth::default(),
        })
    }

    #[test]
    fn seq_order_and_ack() {
        let s = Store::open_in_memory().unwrap();
        let a = s.enqueue(&events(3)).unwrap();
        let b = s.enqueue(&result()).unwrap();
        let c = s.enqueue(&hb(1)).unwrap();
        assert!(a < b && b < c);
        let p = s.pending_after(0, 100).unwrap();
        assert_eq!(p.iter().map(|i| i.seq).collect::<Vec<_>>(), vec![a, b, c]);
        assert_eq!(p[0].kind, "events");
        assert!(p[0].compressed, "event batches are always compressed");
        let back: AgentPayload = codec::decode(&p[0].payload, p[0].compressed).unwrap();
        assert_eq!(back, events(3));
        assert_eq!(s.pending_after(a, 100).unwrap().len(), 2);
        assert_eq!(s.ack(b).unwrap(), 2);
        assert_eq!(s.depth().unwrap(), 1);
        // seq never reused after deletes
        s.ack(c).unwrap();
        let d = s.enqueue(&hb(2)).unwrap();
        assert!(d > c);
    }

    #[test]
    fn priorities() {
        assert_eq!(Priority::of(&events(1)), Priority::Events);
        assert_eq!(Priority::of(&result()), Priority::High);
        assert_eq!(Priority::of(&hb(1)), Priority::Heartbeat);
        assert!(Priority::High > Priority::Heartbeat && Priority::Heartbeat > Priority::Events);
    }

    #[test]
    fn cap_drops_oldest_events_never_high() {
        let s = Store::open_in_memory().unwrap();
        let mut high = vec![];
        let mut ev_seqs = vec![];
        for i in 0..20 {
            ev_seqs.push(s.enqueue(&events(200)).unwrap());
            if i % 5 == 0 {
                high.push(s.enqueue(&result()).unwrap());
            }
        }
        let hb_seq = s.enqueue(&hb(1)).unwrap();
        let total = s.outbox_bytes().unwrap();
        // Cap to ~half: only oldest events should go.
        let dropped = s.enforce_cap(total / 2).unwrap();
        assert!(dropped > 0);
        assert!(s.outbox_bytes().unwrap() <= total / 2);
        let left: Vec<u64> = s
            .pending_after(0, 1000)
            .unwrap()
            .iter()
            .map(|i| i.seq)
            .collect();
        for h in &high {
            assert!(left.contains(h), "high-priority row dropped");
        }
        assert!(
            left.contains(&hb_seq),
            "heartbeat dropped before events exhausted"
        );
        assert!(
            !left.contains(&ev_seqs[0]),
            "oldest event should be dropped first"
        );
        assert!(
            left.contains(ev_seqs.last().unwrap()),
            "newest event should survive"
        );

        // Impossible cap: everything but high-priority rows goes.
        s.enforce_cap(1).unwrap();
        let left: Vec<OutboxItem> = s.pending_after(0, 1000).unwrap();
        assert_eq!(left.len(), high.len());
        assert!(left.iter().all(|i| i.priority == Priority::High as i64));
    }

    #[test]
    fn counters_and_kv() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.next_counter(KV_HEARTBEAT_SEQ).unwrap(), 1);
        assert_eq!(s.next_counter(KV_HEARTBEAT_SEQ).unwrap(), 2);
        s.kv_set_json("x", &vec![1, 2]).unwrap();
        assert_eq!(s.kv_get_json::<Vec<i32>>("x").unwrap(), Some(vec![1, 2]));
    }

    #[test]
    fn persisted_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        {
            let s = Store::open(dir.path()).unwrap();
            s.enqueue(&result()).unwrap();
            s.next_counter(KV_HEARTBEAT_SEQ).unwrap();
        }
        let s = Store::open(dir.path()).unwrap();
        assert_eq!(s.depth().unwrap(), 1);
        assert_eq!(s.next_counter(KV_HEARTBEAT_SEQ).unwrap(), 2);
    }

    #[test]
    fn activity_and_review() {
        let s = Store::open_in_memory().unwrap();
        let alert = Uuid::new_v4();
        for i in 0..3 {
            s.add_activity(
                &ActivityItem {
                    id: Uuid::new_v4(),
                    ts: i,
                    title: format!("t{i}"),
                    body: String::new(),
                    severity: Severity::High,
                    alert_id: if i == 1 { Some(alert) } else { None },
                    file: None,
                    action_taken: String::new(),
                    review: None,
                },
                match i {
                    0 => None,
                    1 => Some("S-1-5-21-1-1001"),
                    _ => Some("CORP\\bob"),
                },
            )
            .unwrap();
        }
        let a = s.activity(10).unwrap();
        assert_eq!(a.iter().map(|x| x.ts).collect::<Vec<_>>(), vec![2, 1, 0]);
        let upd = s.set_review_state(alert, ReviewState::Requested).unwrap();
        assert_eq!(upd.len(), 1);
        assert_eq!(
            s.activity(10).unwrap()[1].review,
            Some(ReviewState::Requested)
        );
        assert!(s.has_alert_activity(alert));
        // M3: per-user view = own items + machine-wide items.
        let alice = vec!["s-1-5-21-1-1001".to_string(), "corp\\alice".to_string()];
        let mine = s.activity_for(&alice, 10).unwrap();
        assert_eq!(mine.iter().map(|x| x.ts).collect::<Vec<_>>(), vec![1, 0]);
        let bob = s.activity_for(&["corp\\bob".to_string()], 10).unwrap();
        assert_eq!(bob.iter().map(|x| x.ts).collect::<Vec<_>>(), vec![2, 0]);
        assert_eq!(s.activity_for(&[], 10).unwrap().len(), 1);
        // owner survives a review-state update
        assert_eq!(s.alert_owner(alert), Some(Some("s-1-5-21-1-1001".into())));
        assert_eq!(s.review_state(alert), Some(ReviewState::Requested));
        assert_eq!(s.alert_owner(Uuid::new_v4()), None);
    }

    #[test]
    fn outbox_epoch_is_stable_per_database() {
        let dir = tempfile::tempdir().unwrap();
        let e1 = Store::open(dir.path()).unwrap().outbox_epoch().unwrap();
        let e2 = Store::open(dir.path()).unwrap().outbox_epoch().unwrap();
        assert_eq!(e1, e2, "epoch persists across restarts");
        std::fs::remove_file(dir.path().join(DB_FILE)).unwrap();
        let _ = std::fs::remove_file(dir.path().join(format!("{DB_FILE}-wal")));
        let _ = std::fs::remove_file(dir.path().join(format!("{DB_FILE}-shm")));
        let e3 = Store::open(dir.path()).unwrap().outbox_epoch().unwrap();
        assert_ne!(e1, e3, "a recreated outbox gets a new epoch");
    }

    #[test]
    fn command_ledger() {
        let s = Store::open_in_memory().unwrap();
        let id = Uuid::new_v4();
        assert!(s.command_outcome(id).unwrap().is_none());
        let o = ActionOutcome {
            action: ResponseAction::ApplyHardening,
            ok: true,
            detail: "x".into(),
            ts: 5,
            artifact: None,
        };
        s.record_command(id, &o).unwrap();
        assert_eq!(s.command_outcome(id).unwrap(), Some(o));
    }
}
