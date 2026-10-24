//! Translator side of the evidence write hints ([`super::super::writehint`]):
//! NT → Win32 path, duplicate suppression (same pid and path at most once
//! per second), pid → process GUID with the same pid-reuse-safe attribution
//! as file events (decided at once when the owner is known, otherwise held
//! until the attribution deadline), then `try_send` to
//! `SensorConfig.write_tx`. Drops are counted in
//! `Counters::write_hints_dropped` (not a sensor loss). Hints never become
//! `Event`s.

use super::{Translator, ATTR_HOLD_MS, MAX_PENDING_ATTR};
use crate::evidence_plan::{is_drive_path, HintDedup};
use crate::proctrack::{Decision, PendingAttr};
use kestrel_common::evidence::WriteOp;
use kestrel_common::{now_ms, ProcessGuid};
use kestrel_platform::WriteHint;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;

/// (pid, ts, Win32 path, op) of a hint whose pid owner is not known yet.
type Item = (u32, i64, String, WriteOp);

pub struct WriteHints {
    tx: Option<mpsc::Sender<WriteHint>>,
    dedup: HintDedup,
    pending: PendingAttr<Item>,
}

impl Default for WriteHints {
    fn default() -> Self {
        WriteHints {
            tx: None,
            dedup: HintDedup::default(),
            pending: PendingAttr::new(MAX_PENDING_ATTR),
        }
    }
}

impl Translator {
    /// Where write hints go (`SensorConfig.write_tx`; `None` = not wanted).
    pub fn set_write_tx(&mut self, tx: Option<mpsc::Sender<WriteHint>>) {
        self.write_hints.tx = tx;
    }

    pub(super) fn on_write_hint(&mut self, ts: i64, pid: u32, name_nt: String, op: WriteOp) {
        if self.write_hints.tx.is_none() || pid == self.s.self_pid || pid == 0 || pid == 4 {
            return;
        }
        let path = self.dos(&name_nt);
        if !is_drive_path(&path) {
            return;
        }
        if !self
            .write_hints
            .dedup
            .admit(pid, path.to_ascii_lowercase(), ts)
        {
            return;
        }
        match self.decide(pid, ts, false) {
            Decision::Hold => {
                let now = now_ms();
                let mut q = std::mem::replace(&mut self.write_hints.pending, PendingAttr::new(1));
                let forced = q.push(
                    now + ATTR_HOLD_MS,
                    pid,
                    ts,
                    (pid, ts, path, op),
                    |p, t, f| self.decide(p, t, f),
                );
                self.write_hints.pending = q;
                for (d, it) in forced {
                    self.finish_write_hint(d, it);
                }
            }
            d => self.finish_write_hint(d, (pid, ts, path, op)),
        }
    }

    /// Decide held hints whose deadline passed (`i64::MAX` = all).
    pub(super) fn expire_write_hints(&mut self, now: i64) {
        if self.write_hints.pending.is_empty() {
            return;
        }
        let mut q = std::mem::replace(&mut self.write_hints.pending, PendingAttr::new(1));
        let out = q.expire(now, |p, t, f| self.decide(p, t, f));
        self.write_hints.pending = q;
        for (d, it) in out {
            self.finish_write_hint(d, it);
        }
    }

    fn finish_write_hint(&mut self, d: Decision, (pid, ts, path, op): Item) {
        let guid = match d {
            Decision::Emit(g) => g,
            Decision::EmitUnlinked => ProcessGuid::derive(&self.s.boot_id, pid, 0),
            Decision::Drop | Decision::Hold => return,
        };
        let Some(tx) = &self.write_hints.tx else {
            return;
        };
        let c = &self.s.counters;
        match tx.try_send(WriteHint {
            ts,
            pid,
            guid,
            path,
            op,
        }) {
            Ok(()) => {
                c.write_hints_sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                c.write_hints_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
