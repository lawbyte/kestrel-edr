//! Registry of connected agents: device id → outbound channel of the live stream.

use dashmap::DashMap;
use kestrel_common::wire::ServerPayload;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, Ordering},
    Arc,
};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Messages queued for an agent's live stream. The stream assigns server `seq`
/// numbers and maps the agent's Acks back to commands / policy versions.
pub type Outbound = ServerPayload;

pub struct AgentConn {
    pub session: Uuid,
    pub tx: mpsc::Sender<Outbound>,
    pub connected_at: i64,
    /// Server-receive time of the last heartbeat on this stream.
    pub last_hb: AtomicI64,
    /// Silence alert already raised for the current gap.
    pub silence_alerted: AtomicBool,
    /// Signalled to terminate the stream (decommission / revocation).
    pub kill: tokio::sync::Notify,
}

#[derive(Default)]
pub struct AgentRegistry {
    map: DashMap<Uuid, Arc<AgentConn>>,
}

impl AgentRegistry {
    pub fn register(&self, device_id: Uuid, conn: Arc<AgentConn>) -> Option<Arc<AgentConn>> {
        self.map.insert(device_id, conn)
    }

    /// Remove only if the registered session is still `session` (a newer stream may have replaced it).
    pub fn unregister(&self, device_id: Uuid, session: Uuid) {
        self.map.remove_if(&device_id, |_, c| c.session == session);
    }

    /// Drop the connection (e.g. decommissioned device); the stream ends when its sender is gone.
    pub fn disconnect(&self, device_id: Uuid) {
        if let Some((_, c)) = self.map.remove(&device_id) {
            c.kill.notify_one();
        }
    }

    pub fn get(&self, device_id: &Uuid) -> Option<Arc<AgentConn>> {
        self.map.get(device_id).map(|c| c.clone())
    }

    pub fn is_connected(&self, device_id: &Uuid) -> bool {
        self.map.contains_key(device_id)
    }

    /// Non-blocking send; false if not connected or the channel is full.
    pub fn send(&self, device_id: &Uuid, msg: Outbound) -> bool {
        match self.get(device_id) {
            Some(c) => c.tx.try_send(msg).is_ok(),
            None => false,
        }
    }

    pub fn connected(&self) -> Vec<(Uuid, Arc<AgentConn>)> {
        self.map
            .iter()
            .map(|e| (*e.key(), e.value().clone()))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl AgentConn {
    pub fn touch_heartbeat(&self, now: i64) -> i64 {
        self.silence_alerted.store(false, Ordering::Relaxed);
        self.last_hb.swap(now, Ordering::Relaxed)
    }
}
