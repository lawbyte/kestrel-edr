//! PID → process-instance tracker used to stamp every event with the right
//! [`ProcessGuid`]. Seeded from the startup snapshot, updated from
//! Kernel-Process start/stop events. Exited processes are kept for a grace
//! period because late events (network, DPAPI, file) may still reference them.
//!
//! ## PID reuse (owner-PC triage 2026-10-22)
//!
//! A large parallel build creates and destroys thousands of processes, so a
//! pid is reused within milliseconds, while the ETW sessions (`Kestrel-Core`
//! for process start/stop, `Kestrel-File` for file opens, `Kestrel-IO`) are
//! delivered independently. The old lookup returned the *current* owner of a
//! pid for any event stamped up to 1 s before its start, and fell back to the
//! current owner when nothing matched, so a Docker CLI plugin's open of
//! `.docker\config.json` was blamed on the rustc / link.exe that got its pid.
//!
//! Now an event is attributed to the instance that owned the pid **at the
//! event's timestamp** ([`ProcTracker::owner_at`]):
//! * every entry has an `order_ts` in the ETW clock domain (the timestamp of
//!   its Kernel-Process start event; for snapshot / live-query sightings the
//!   wall-clock create time shifted by the measured ETW−wall offset, because
//!   ETW timestamps are QPC-based and drift from the system clock);
//! * an event belongs to the latest instance with `order_ts <= ts` that had
//!   not exited before `ts`;
//! * an event older than a known start whose own instance is unknown is
//!   [`Owner::Stale`] (the core session is ordered, so that start cannot
//!   arrive any more): dropped and counted, never given to the new owner;
//! * an event whose owner may simply not have been delivered yet is
//!   [`Owner::Pending`] and is held ([`PendingAttr`]) until the core session
//!   catches up or a deadline passes.

use kestrel_common::{ProcessGuid, TimestampMs};
use std::collections::{HashMap, VecDeque};

/// How long an exited process stays resolvable.
pub const EXIT_GRACE_MS: i64 = 60_000;

/// Bound on remembered exited-and-reused instances.
pub const MAX_GHOSTS: usize = 4096;

#[derive(Debug, Clone, PartialEq)]
pub struct ProcEntry {
    /// Wall-clock create time (ms): input of the GUID, stable across sources.
    pub start_ts: TimestampMs,
    /// Start in the ETW clock domain, used to order events against it.
    pub order_ts: TimestampMs,
    /// Learned from a Kernel-Process start event (delivered in order with
    /// all other starts), not from a snapshot / live query.
    pub authoritative: bool,
    pub image: String,
    pub ppid: u32,
    /// ETW timestamp of the stop event (or the implied latest exit time
    /// when the pid was reused without a stop being seen).
    pub exited_at: Option<TimestampMs>,
    pub guid: ProcessGuid,
}

impl ProcEntry {
    /// No tolerance on either boundary: the sessions convert the same QPC
    /// clock, and at millisecond resolution any slack re-opens the
    /// pid-reuse window (a pid is reused within a few ms during a build).
    /// A sensitive file open in the first or last milliseconds of a
    /// process is implausible; a misattribution is not acceptable.
    fn alive_at(&self, ts: TimestampMs) -> bool {
        self.exited_at.is_none_or(|x| ts <= x)
    }
}

/// Who owned a pid at a given time.
#[derive(Debug, Clone, PartialEq)]
pub enum Owner {
    Known(ProcessGuid),
    /// The owner may not have been delivered yet (all known instances exited
    /// before the event, or only an unordered sighting started after it).
    Pending,
    /// The event predates a known (ordered) start and no instance that owned
    /// the pid at that time is known: it can no longer be attributed.
    Stale,
    /// Nothing is known about this pid.
    Unknown,
}

/// What to do with an event, given its pid and timestamp.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Emit(ProcessGuid),
    /// Wait for the owner's start (core session lagging).
    Hold,
    /// Attribution impossible (pid reused): drop and count.
    Drop,
    /// Never seen at all: emit with the unlinkable GUID (start 0), as before.
    EmitUnlinked,
}

#[derive(Debug)]
pub struct ProcTracker {
    boot_id: String,
    live: HashMap<u32, ProcEntry>,
    /// Older instances of a pid (exited, or displaced by a newer instance).
    ghosts: HashMap<u32, Vec<ProcEntry>>,
    ghost_count: usize,
    /// ETW timestamp − wall-clock create time, measured on the last
    /// Kernel-Process start that carried a create time.
    etw_offset: i64,
}

impl ProcTracker {
    pub fn new(boot_id: &str) -> Self {
        ProcTracker {
            boot_id: boot_id.to_string(),
            live: HashMap::new(),
            ghosts: HashMap::new(),
            ghost_count: 0,
            etw_offset: 0,
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn guid(&self, pid: u32, start_ts: TimestampMs) -> ProcessGuid {
        ProcessGuid::derive(&self.boot_id, pid, start_ts)
    }

    /// Measured ETW − wall clock offset (ms).
    pub fn etw_offset(&self) -> i64 {
        self.etw_offset
    }

    /// Record a sighting of a live process (startup snapshot, live query of
    /// a pid whose start event was not seen). Returns its GUID.
    pub fn on_start(
        &mut self,
        pid: u32,
        start_ts: TimestampMs,
        image: &str,
        ppid: u32,
    ) -> ProcessGuid {
        let order_ts = start_ts.saturating_add(self.etw_offset);
        self.insert(pid, start_ts, order_ts, false, image, ppid)
    }

    /// Record a Kernel-Process start event: `start_ts` is the wall-clock
    /// create time (GUID input), `etw_ts` the event's ETW timestamp.
    /// `create_known` = `start_ts` came from the event's CreateTime (then the
    /// clock offset is re-measured).
    pub fn on_etw_start(
        &mut self,
        pid: u32,
        start_ts: TimestampMs,
        etw_ts: TimestampMs,
        create_known: bool,
        image: &str,
        ppid: u32,
    ) -> ProcessGuid {
        if create_known {
            self.etw_offset = etw_ts - start_ts;
        }
        self.insert(pid, start_ts, etw_ts, true, image, ppid)
    }

    fn insert(
        &mut self,
        pid: u32,
        start_ts: TimestampMs,
        order_ts: TimestampMs,
        authoritative: bool,
        image: &str,
        ppid: u32,
    ) -> ProcessGuid {
        let guid = self.guid(pid, start_ts);
        let refine = |e: &mut ProcEntry| {
            if authoritative && !e.authoritative {
                e.order_ts = order_ts;
                e.authoritative = true;
            }
            if !image.is_empty() && (authoritative || e.image.is_empty()) {
                e.image = image.to_string();
            }
            if ppid != 0 && (authoritative || e.ppid == 0) {
                e.ppid = ppid;
            }
        };
        // The same instance seen again (sighting, then its start event).
        if let Some(e) = self.live.get_mut(&pid).filter(|e| e.start_ts == start_ts) {
            refine(e);
            return guid;
        }
        if let Some(e) = self
            .ghosts
            .get_mut(&pid)
            .and_then(|v| v.iter_mut().find(|e| e.start_ts == start_ts))
        {
            refine(e);
            return guid;
        }
        let entry = ProcEntry {
            start_ts,
            order_ts,
            authoritative,
            image: image.to_string(),
            ppid,
            exited_at: None,
            guid: guid.clone(),
        };
        let newer_live = self
            .live
            .get(&pid)
            .filter(|cur| cur.order_ts > order_ts)
            .map(|cur| cur.order_ts);
        match newer_live {
            // An older instance reported late (its start arrived after a
            // sighting of the current owner): it exited before that one
            // started.
            Some(next_start) => {
                let mut e = entry;
                e.exited_at = Some(next_start);
                self.push_ghost(pid, e);
            }
            None => {
                if let Some(mut old) = self.live.insert(pid, entry) {
                    // A pid is only reused after its previous owner is gone.
                    if old.exited_at.is_none_or(|x| x > order_ts) {
                        old.exited_at = Some(order_ts);
                    }
                    self.push_ghost(pid, old);
                }
            }
        }
        guid
    }

    fn push_ghost(&mut self, pid: u32, e: ProcEntry) {
        self.ghosts.entry(pid).or_default().push(e);
        self.ghost_count += 1;
    }

    /// Kernel-Process stop (`ts` = ETW timestamp). `start_ts` (wall-clock
    /// create time from the event) selects the instance when known.
    pub fn on_stop(&mut self, pid: u32, start_ts: Option<TimestampMs>, ts: TimestampMs) {
        if let Some(e) = self
            .live
            .get_mut(&pid)
            .filter(|e| start_ts.is_none_or(|s| s == e.start_ts))
        {
            e.exited_at = Some(ts);
            return;
        }
        if let Some(s) = start_ts {
            if let Some(e) = self
                .ghosts
                .get_mut(&pid)
                .and_then(|v| v.iter_mut().find(|e| e.start_ts == s))
            {
                e.exited_at = Some(ts);
            }
        }
    }

    /// Is this instance (pid + wall-clock create time) already known?
    pub fn has_instance(&self, pid: u32, start_ts: TimestampMs) -> bool {
        self.instances(pid).any(|e| e.start_ts == start_ts)
    }

    /// Current (or recently exited) process with this pid.
    pub fn get(&self, pid: u32) -> Option<&ProcEntry> {
        self.live.get(&pid)
    }

    fn instances(&self, pid: u32) -> impl Iterator<Item = &ProcEntry> {
        self.live
            .get(&pid)
            .into_iter()
            .chain(self.ghosts.get(&pid).into_iter().flatten())
    }

    /// The instance that owned `pid` at `ts` (ETW clock), if known.
    pub fn at(&self, pid: u32, ts: TimestampMs) -> Option<&ProcEntry> {
        // Latest instance started at or before the event and still alive.
        self.instances(pid)
            .filter(|e| e.order_ts <= ts && e.alive_at(ts))
            .max_by_key(|e| e.order_ts)
    }

    /// Who owned `pid` at `ts` (see the module docs).
    pub fn owner_at(&self, pid: u32, ts: TimestampMs) -> Owner {
        if let Some(e) = self.at(pid, ts) {
            return Owner::Known(e.guid.clone());
        }
        let mut any = false;
        let mut later_ordered = false;
        for e in self.instances(pid) {
            any = true;
            if e.authoritative && e.order_ts > ts {
                later_ordered = true;
            }
        }
        if !any {
            Owner::Unknown
        } else if later_ordered {
            Owner::Stale
        } else {
            Owner::Pending
        }
    }

    /// Attribution decision; `deadline` = the hold time is over.
    pub fn decide(&self, pid: u32, ts: TimestampMs, deadline: bool) -> Decision {
        match self.owner_at(pid, ts) {
            Owner::Known(g) => Decision::Emit(g),
            Owner::Stale => Decision::Drop,
            Owner::Pending if deadline => Decision::Drop,
            Owner::Unknown if deadline => Decision::EmitUnlinked,
            Owner::Pending | Owner::Unknown => Decision::Hold,
        }
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
            .retain(|_, e| e.exited_at.is_none_or(|x| now - x < EXIT_GRACE_MS));
        let mut count = 0usize;
        self.ghosts.retain(|_, v| {
            v.retain(|e| e.exited_at.is_none_or(|x| now - x < EXIT_GRACE_MS));
            count += v.len();
            !v.is_empty()
        });
        // Bounded by count: the oldest instances go first.
        if count > MAX_GHOSTS {
            let mut starts: Vec<i64> = self.ghosts.values().flatten().map(|e| e.order_ts).collect();
            starts.sort_unstable();
            let cut = starts[count - MAX_GHOSTS];
            self.ghosts.retain(|_, v| {
                v.retain(|e| e.order_ts >= cut);
                !v.is_empty()
            });
            count = self.ghosts.values().map(Vec::len).sum();
        }
        self.ghost_count = count;
    }

    pub fn len(&self) -> usize {
        self.live.len()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }

    pub fn ghost_count(&self) -> usize {
        self.ghost_count
    }
}

/// Items (events) waiting for their pid's owner to become known. Indexed
/// per pid so a process start only re-examines its own pid; expiry is FIFO
/// by deadline. Bounded: past `cap` the oldest items are decided at once.
#[derive(Debug)]
pub struct PendingAttr<T> {
    by_pid: HashMap<u32, VecDeque<(i64, TimestampMs, T)>>,
    order: VecDeque<(i64, u32)>,
    len: usize,
    cap: usize,
}

impl<T> PendingAttr<T> {
    pub fn new(cap: usize) -> Self {
        PendingAttr {
            by_pid: HashMap::new(),
            order: VecDeque::new(),
            len: 0,
            cap: cap.max(1),
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Queue `item` (event of `pid` at `ts`) until `deadline`. Returns the
    /// items forced out by the bound, decided with `deadline = true`.
    pub fn push(
        &mut self,
        deadline: i64,
        pid: u32,
        ts: TimestampMs,
        item: T,
        mut decide: impl FnMut(u32, TimestampMs, bool) -> Decision,
    ) -> Vec<(Decision, T)> {
        self.by_pid
            .entry(pid)
            .or_default()
            .push_back((deadline, ts, item));
        self.order.push_back((deadline, pid));
        self.len += 1;
        let mut out = Vec::new();
        while self.len > self.cap {
            let Some((_, p)) = self.order.pop_front() else {
                break;
            };
            if let Some((_, ts, it)) = self.pop_front_of(p) {
                out.push((decide(p, ts, true), it));
            }
        }
        out
    }

    fn pop_front_of(&mut self, pid: u32) -> Option<(i64, TimestampMs, T)> {
        let q = self.by_pid.get_mut(&pid)?;
        let r = q.pop_front();
        if q.is_empty() {
            self.by_pid.remove(&pid);
        }
        if r.is_some() {
            self.len -= 1;
        }
        r
    }

    /// Re-examine the items of `pid` (its start / stop just arrived). Items
    /// still undecided stay queued, in order.
    pub fn retry_pid(
        &mut self,
        pid: u32,
        now: i64,
        mut decide: impl FnMut(u32, TimestampMs, bool) -> Decision,
    ) -> Vec<(Decision, T)> {
        let Some(q) = self.by_pid.remove(&pid) else {
            return Vec::new();
        };
        let mut keep = VecDeque::new();
        let mut out = Vec::new();
        for (deadline, ts, it) in q {
            match decide(pid, ts, deadline <= now) {
                Decision::Hold => keep.push_back((deadline, ts, it)),
                d => {
                    self.len -= 1;
                    out.push((d, it));
                }
            }
        }
        if !keep.is_empty() {
            self.by_pid.insert(pid, keep);
        }
        out
    }

    /// Decide every item whose deadline has passed (`now = i64::MAX`
    /// flushes everything).
    pub fn expire(
        &mut self,
        now: i64,
        mut decide: impl FnMut(u32, TimestampMs, bool) -> Decision,
    ) -> Vec<(Decision, T)> {
        let mut out = Vec::new();
        while let Some(&(deadline, pid)) = self.order.front() {
            if deadline > now {
                break;
            }
            self.order.pop_front();
            // The per-pid queue is in deadline order; the entry may already
            // have been decided by `retry_pid`.
            while self
                .by_pid
                .get(&pid)
                .and_then(|q| q.front())
                .is_some_and(|(d, _, _)| *d <= now)
            {
                if let Some((_, ts, it)) = self.pop_front_of(pid) {
                    out.push((decide(pid, ts, true), it));
                }
            }
        }
        out
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
        let g1 = t.on_etw_start(100, 1_000, 1_000, true, "a.exe", 4);
        assert_eq!(t.guid_for(100, 2_000), (g1.clone(), true));
        t.on_stop(100, Some(1_000), 5_000);
        // Late event inside the grace period still resolves.
        assert_eq!(t.guid_for(100, 4_000).0, g1);
        // PID reused.
        let g2 = t.on_etw_start(100, 10_000, 10_000, true, "b.exe", 4);
        assert_ne!(g1, g2);
        assert_eq!(t.guid_for(100, 11_000).0, g2);
        // An event stamped before the reuse resolves to the ghost.
        assert_eq!(t.guid_for(100, 4_000).0, g1);
        // Between A's exit and B's start the pid had no owner.
        assert!(!t.guid_for(100, 7_000).1);
        t.gc(10_000 + EXIT_GRACE_MS * 2);
        assert_eq!(t.image_of(100), Some("b.exe"));
        let (_, known) = t.guid_for(999, 1);
        assert!(!known);
    }

    /// Owner-PC triage: A (a Docker CLI plugin) opens config.json at t=5,
    /// exits at t=6, B (rustc) gets pid 100 at t=7; the file event for t=5
    /// is delivered after B's start. It belongs to A, never to B.
    #[test]
    fn late_file_event_after_pid_reuse_goes_to_previous_owner() {
        let mut t = ProcTracker::new("boot");
        let a = t.on_etw_start(100, 4, 4, true, "docker-buildx.exe", 1);
        t.on_stop(100, Some(4), 6);
        let b = t.on_etw_start(100, 7, 7, true, "rustc.exe", 2);
        assert_eq!(t.owner_at(100, 5), Owner::Known(a.clone()));
        assert_eq!(t.decide(100, 5, false), Decision::Emit(a));
        assert_eq!(t.owner_at(100, 7), Owner::Known(b.clone()));
        assert_eq!(t.owner_at(100, 8), Owner::Known(b));
    }

    /// Same, but A's start was never seen (lost / before the session):
    /// the event cannot be attributed and is dropped — never given to B.
    #[test]
    fn stale_event_is_dropped_not_given_to_new_owner() {
        let mut t = ProcTracker::new("boot");
        let _b = t.on_etw_start(100, 7, 7, true, "rustc.exe", 2);
        assert_eq!(t.owner_at(100, 5), Owner::Stale);
        assert_eq!(t.decide(100, 5, false), Decision::Drop);
    }

    /// The old 1 s slack: an event 100 ms (or 1 ms) before the new owner's
    /// start was attributed to it.
    #[test]
    fn no_start_slack() {
        let mut t = ProcTracker::new("boot");
        let b = t.on_etw_start(100, 10_000, 10_000, true, "rustc.exe", 2);
        assert_eq!(t.owner_at(100, 9_900), Owner::Stale);
        assert_eq!(t.owner_at(100, 9_999), Owner::Stale);
        assert_eq!(t.owner_at(100, 10_000), Owner::Known(b));
    }

    /// File session ahead of the core session: the file event of A (t=5)
    /// arrives before A's start / stop and B's start. The live query sees
    /// only B (created at 7): the event is held, then attributed to A once
    /// the core session delivers.
    #[test]
    fn early_file_event_waits_for_core_session() {
        let mut t = ProcTracker::new("boot");
        assert_eq!(t.owner_at(100, 5), Owner::Unknown);
        assert_eq!(t.decide(100, 5, false), Decision::Hold);
        // ensure_known: sighting of the current owner B.
        let b = t.on_start(100, 7, "rustc.exe", 0);
        assert_eq!(t.owner_at(100, 5), Owner::Pending);
        let mut q: PendingAttr<&str> = PendingAttr::new(16);
        let forced = q.push(1_000, 100, 5, "config.json", |p, ts, f| t.decide(p, ts, f));
        assert!(forced.is_empty());
        // Core session catches up.
        let a = t.on_etw_start(100, 4, 4, true, "docker-buildx.exe", 1);
        t.on_stop(100, Some(4), 6);
        let b2 = t.on_etw_start(100, 7, 7, true, "rustc.exe", 2);
        assert_eq!(b, b2);
        let out = q.retry_pid(100, 10, |p, ts, f| t.decide(p, ts, f));
        assert_eq!(out, vec![(Decision::Emit(a), "config.json")]);
        assert!(q.is_empty());
        // B's own events still resolve to B.
        assert_eq!(t.owner_at(100, 8), Owner::Known(b));
    }

    /// The existing early-event case: B's own event arrives before B's
    /// start event; the live query (sighting) already identifies B.
    #[test]
    fn own_early_event_resolves_to_sighting_with_same_guid() {
        let mut t = ProcTracker::new("boot");
        let b = t.on_start(100, 7, "rustc.exe", 0);
        assert_eq!(t.decide(100, 9, false), Decision::Emit(b.clone()));
        let b2 = t.on_etw_start(100, 7, 7, true, "rustc.exe", 2);
        assert_eq!(b, b2);
        assert_eq!(t.decide(100, 9, false), Decision::Emit(b));
    }

    /// The previous owner exited and the successor's start has not been
    /// delivered: hold; at the deadline drop rather than guess.
    #[test]
    fn successor_not_seen_is_held_then_dropped() {
        let mut t = ProcTracker::new("boot");
        t.on_etw_start(100, 1, 1, true, "a.exe", 1);
        t.on_stop(100, Some(1), 2);
        assert_eq!(t.owner_at(100, 50), Owner::Pending);
        let mut q: PendingAttr<u32> = PendingAttr::new(16);
        assert!(q
            .push(100, 100, 50, 7, |p, ts, f| t.decide(p, ts, f))
            .is_empty());
        assert!(q.expire(99, |p, ts, f| t.decide(p, ts, f)).is_empty());
        let out = q.expire(100, |p, ts, f| t.decide(p, ts, f));
        assert_eq!(out, vec![(Decision::Drop, 7)]);
        // A pid never seen at all keeps the legacy unlinkable GUID.
        assert_eq!(t.decide(555, 50, true), Decision::EmitUnlinked);
    }

    /// Sightings use the measured ETW−wall offset (QPC-based ETW
    /// timestamps drift from the system clock).
    #[test]
    fn sightings_are_shifted_into_the_etw_clock() {
        let mut t = ProcTracker::new("boot");
        // ETW runs 3 s behind the wall clock.
        t.on_etw_start(10, 100_000, 97_000, true, "x.exe", 1);
        assert_eq!(t.etw_offset(), -3_000);
        // A process created at wall 200_000 = ETW 197_000.
        let g = t.on_start(20, 200_000, "y.exe", 0);
        assert_eq!(t.owner_at(20, 197_500), Owner::Known(g));
        assert_eq!(t.owner_at(20, 196_000), Owner::Pending);
    }

    /// A late start of an older instance never displaces the current owner.
    #[test]
    fn out_of_order_start_goes_to_history() {
        let mut t = ProcTracker::new("boot");
        let b = t.on_start(100, 7, "b.exe", 0);
        let a = t.on_etw_start(100, 4, 4, true, "a.exe", 0);
        assert_eq!(t.get(100).map(|e| e.guid.clone()), Some(b.clone()));
        assert_eq!(t.owner_at(100, 5), Owner::Known(a));
        assert_eq!(t.owner_at(100, 8), Owner::Known(b));
    }

    #[test]
    fn pending_queue_bound_and_order() {
        let t = ProcTracker::new("boot");
        let mut q: PendingAttr<u32> = PendingAttr::new(2);
        assert!(q
            .push(10, 1, 0, 1, |p, ts, f| t.decide(p, ts, f))
            .is_empty());
        assert!(q
            .push(10, 2, 0, 2, |p, ts, f| t.decide(p, ts, f))
            .is_empty());
        let forced = q.push(10, 3, 0, 3, |p, ts, f| t.decide(p, ts, f));
        assert_eq!(forced, vec![(Decision::EmitUnlinked, 1)]);
        assert_eq!(q.len(), 2);
        let rest = q.expire(i64::MAX, |p, ts, f| t.decide(p, ts, f));
        assert_eq!(rest.into_iter().map(|(_, i)| i).collect::<Vec<_>>(), [2, 3]);
        assert!(q.is_empty());
    }

    #[test]
    fn gc_bounds_ghosts() {
        let mut t = ProcTracker::new("boot");
        for i in 0..(MAX_GHOSTS as i64 + 10) {
            // No stop events: every reuse leaves an implied-exit ghost.
            t.on_etw_start(7, i * 10, i * 10, true, "x.exe", 1);
        }
        t.gc((MAX_GHOSTS as i64 + 10) * 10);
        assert!(t.ghost_count() <= MAX_GHOSTS);
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
