//! PID → (start time, image) tracker used to stamp every event with the right
//! [`ProcessGuid`]. Seeded from the startup snapshot, updated from
//! Kernel-Process start/stop events. Exited processes are kept for a grace
//! period because late events (network, DPAPI) may still reference them.

use kestrel_common::{ProcessGuid, TimestampMs};
use std::collections::HashMap;

/// How long an exited process stays resolvable.
pub const EXIT_GRACE_MS: i64 = 60_000;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcEntry {
    pub start_ts: TimestampMs,
    pub image: String,
    pub ppid: u32,
    pub exited_at: Option<TimestampMs>,
    pub guid: ProcessGuid,
}

#[derive(Debug)]
pub struct ProcTracker {
    boot_id: String,
    live: HashMap<u32, ProcEntry>,
    /// Exited entries whose pid has since been reused.
    ghosts: Vec<(u32, ProcEntry)>,
}

impl ProcTracker {
    pub fn new(boot_id: &str) -> Self {
        ProcTracker {
            boot_id: boot_id.to_string(),
            live: HashMap::new(),
            ghosts: Vec::new(),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn guid(&self, pid: u32, start_ts: TimestampMs) -> ProcessGuid {
        ProcessGuid::derive(&self.boot_id, pid, start_ts)
    }

    /// Record a process start (or snapshot entry). Returns its GUID.
    pub fn on_start(
        &mut self,
        pid: u32,
        start_ts: TimestampMs,
        image: &str,
        ppid: u32,
    ) -> ProcessGuid {
        let guid = self.guid(pid, start_ts);
        let entry = ProcEntry {
            start_ts,
            image: image.to_string(),
            ppid,
            exited_at: None,
            guid: guid.clone(),
        };
        if let Some(old) = self.live.insert(pid, entry) {
            if old.start_ts != start_ts {
                self.ghosts.push((pid, old));
            }
        }
        guid
    }

    pub fn on_stop(&mut self, pid: u32, start_ts: Option<TimestampMs>, now: TimestampMs) {
        if let Some(e) = self.live.get_mut(&pid) {
            if start_ts.map(|s| s == e.start_ts).unwrap_or(true) {
                e.exited_at = Some(now);
            }
        }
    }

    /// Current (or recently exited) process with this pid.
    pub fn get(&self, pid: u32) -> Option<&ProcEntry> {
        self.live.get(&pid)
    }

    /// Process that owned `pid` at time `ts` (handles PID reuse for late events).
    pub fn at(&self, pid: u32, ts: TimestampMs) -> Option<&ProcEntry> {
        if let Some(e) = self.live.get(&pid) {
            if e.start_ts <= ts + 1_000 {
                return Some(e);
            }
        }
        self.ghosts
            .iter()
            .rev()
            .find(|(p, e)| {
                *p == pid
                    && e.start_ts <= ts
                    && e.exited_at.map(|x| ts <= x + EXIT_GRACE_MS).unwrap_or(true)
            })
            .map(|(_, e)| e)
            .or_else(|| self.live.get(&pid))
    }

    /// GUID for an acting pid; unknown pids get a GUID derived with start 0
    /// (stable but unlinkable) and `false`.
    pub fn guid_for(&self, pid: u32, ts: TimestampMs) -> (ProcessGuid, bool) {
        match self.at(pid, ts) {
            Some(e) => (e.guid.clone(), true),
            None => (self.guid(pid, 0), false),
        }
    }

    pub fn image_of(&self, pid: u32) -> Option<&str> {
        self.live.get(&pid).map(|e| e.image.as_str())
    }

    /// Drop exited entries past the grace period.
    pub fn gc(&mut self, now: TimestampMs) {
        self.live
            .retain(|_, e| e.exited_at.map(|x| now - x < EXIT_GRACE_MS).unwrap_or(true));
        self.ghosts.retain(|(_, e)| {
            e.exited_at
                .map(|x| now - x < EXIT_GRACE_MS)
                .unwrap_or(false)
                || e.exited_at.is_none()
        });
        // Ghosts without an exit time (stop event lost) are bounded by count.
        if self.ghosts.len() > 4096 {
            let drop = self.ghosts.len() - 4096;
            self.ghosts.drain(..drop);
        }
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

/// Descendants of `root` given (pid, ppid, start_ts) rows. A child only counts
/// if it started after its parent (guards against PID reuse creating false
/// edges). Returned in depth-first order, deepest last.
pub fn descendants(rows: &[(u32, u32, TimestampMs)], root: u32) -> Vec<u32> {
    let start: HashMap<u32, TimestampMs> = rows.iter().map(|&(p, _, s)| (p, s)).collect();
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(parent) = stack.pop() {
        let pstart = start.get(&parent).copied().unwrap_or(i64::MIN);
        for &(pid, ppid, s) in rows {
            if ppid == parent && pid != parent && pid != root && s >= pstart && !out.contains(&pid)
            {
                out.push(pid);
                stack.push(pid);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reuse_and_grace() {
        let mut t = ProcTracker::new("boot");
        let g1 = t.on_start(100, 1_000, "a.exe", 4);
        assert_eq!(t.guid_for(100, 2_000), (g1.clone(), true));
        t.on_stop(100, Some(1_000), 5_000);
        // Late event inside the grace period still resolves.
        assert_eq!(t.guid_for(100, 6_000).0, g1);
        // PID reused.
        let g2 = t.on_start(100, 10_000, "b.exe", 4);
        assert_ne!(g1, g2);
        assert_eq!(t.guid_for(100, 11_000).0, g2);
        // An event stamped before the reuse resolves to the ghost.
        assert_eq!(t.guid_for(100, 4_000).0, g1);
        t.gc(10_000 + EXIT_GRACE_MS * 2);
        assert_eq!(t.image_of(100), Some("b.exe"));
        let (_, known) = t.guid_for(999, 1);
        assert!(!known);
    }

    #[test]
    fn tree() {
        // 10 -> 11 -> 12 ; 13 has ppid 10 but started before 10 (pid reuse) → excluded
        let rows = vec![
            (10, 1, 100),
            (11, 10, 200),
            (12, 11, 300),
            (13, 10, 50),
            (14, 99, 400),
        ];
        let d = descendants(&rows, 10);
        assert_eq!(d, vec![11, 12]);
        assert!(descendants(&rows, 14).is_empty());
    }
}
