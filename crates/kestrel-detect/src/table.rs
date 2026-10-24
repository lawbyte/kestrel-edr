//! Process table keyed by stable process GUID.
//!
//! * `by_pid` returns the most recently started *live* process with that pid
//!   (pids are reused; GUIDs are not).
//! * `ancestry` walks `parent_guid` links (falling back to the live process with
//!   `ppid` that started before the child), nearest first, bounded and cycle-safe.
//! * Memory is bounded: exited processes are evicted after a retention window
//!   (default 10 min, they are still needed for alert ancestry), and the table
//!   is capped (default 50 000 entries; oldest exited entries go first, then
//!   the oldest live ones).
use kestrel_common::{ProcessGuid, ProcessInfo, TimestampMs};
use std::collections::{HashMap, HashSet};

/// Default retention of exited processes.
pub const DEFAULT_EXIT_RETENTION_MS: i64 = 10 * 60 * 1000;
/// Default cap on tracked processes.
pub const DEFAULT_MAX_ENTRIES: usize = 50_000;

#[derive(Debug)]
pub struct ProcessTable {
    procs: HashMap<ProcessGuid, ProcessInfo>,
    by_pid: HashMap<u32, Vec<ProcessGuid>>,
    children: HashMap<ProcessGuid, Vec<ProcessGuid>>,
    /// Normalised image path → processes with that image (V-L14).
    by_image: HashMap<String, Vec<ProcessGuid>>,
    retention_ms: i64,
    max_entries: usize,
}

impl Default for ProcessTable {
    fn default() -> Self {
        ProcessTable::with_limits(DEFAULT_EXIT_RETENTION_MS, DEFAULT_MAX_ENTRIES)
    }
}

impl ProcessTable {
    pub fn get(&self, guid: &ProcessGuid) -> Option<&ProcessInfo> {
        self.procs.get(guid)
    }

    /// Most recent live process with this pid.
    pub fn by_pid(&self, pid: u32) -> Option<&ProcessInfo> {
        self.by_pid
            .get(&pid)?
            .iter()
            .filter_map(|g| self.procs.get(g))
            .filter(|p| p.exit_ts.is_none())
            .max_by_key(|p| p.start_ts)
    }

    /// Parent chain, nearest first, up to `depth`.
    pub fn ancestry(&self, guid: &ProcessGuid, depth: usize) -> Vec<ProcessInfo> {
        let mut out = Vec::new();
        let mut seen: HashSet<&ProcessGuid> = HashSet::new();
        let Some(mut cur) = self.procs.get(guid) else {
            return out;
        };
        seen.insert(&cur.guid);
        while out.len() < depth {
            let Some(parent) = self.parent_of(cur) else {
                break;
            };
            if !seen.insert(&parent.guid) {
                break; // cycle
            }
            out.push(parent.clone());
            cur = parent;
        }
        out
    }

    /// Live descendants (for kill-tree).
    pub fn descendants(&self, guid: &ProcessGuid) -> Vec<ProcessInfo> {
        let mut out = Vec::new();
        let mut seen: HashSet<&ProcessGuid> = HashSet::new();
        seen.insert(guid);
        let mut stack: Vec<&ProcessGuid> = vec![guid];
        while let Some(g) = stack.pop() {
            if let Some(kids) = self.children.get(g) {
                for k in kids {
                    if seen.insert(k) {
                        if let Some(p) = self.procs.get(k) {
                            if p.exit_ts.is_none() {
                                out.push(p.clone());
                            }
                        }
                        // Walk through exited intermediates too: their live children still belong to the tree.
                        stack.push(k);
                    }
                }
            }
        }
        out
    }

    /// Descendants including exited ones still in the table (ST-04 reader
    /// search: a child that read the stores and exited before its parent
    /// sent them), at most `limit`.
    pub fn descendants_all(&self, guid: &ProcessGuid, limit: usize) -> Vec<ProcessInfo> {
        let mut out = Vec::new();
        let mut seen: HashSet<&ProcessGuid> = HashSet::new();
        seen.insert(guid);
        let mut stack: Vec<&ProcessGuid> = vec![guid];
        while let Some(g) = stack.pop() {
            if let Some(kids) = self.children.get(g) {
                for k in kids {
                    if out.len() >= limit {
                        return out;
                    }
                    if seen.insert(k) {
                        if let Some(p) = self.procs.get(k) {
                            out.push(p.clone());
                        }
                        stack.push(k);
                    }
                }
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &ProcessInfo> {
        self.procs.values()
    }

    // ----- additions (not part of the frozen contract) -----

    /// Table with explicit limits.
    pub fn with_limits(retention_ms: i64, max_entries: usize) -> Self {
        ProcessTable {
            procs: HashMap::new(),
            by_pid: HashMap::new(),
            children: HashMap::new(),
            by_image: HashMap::new(),
            retention_ms,
            max_entries: max_entries.max(16),
        }
    }

    /// Processes (live or retained) whose image is `path` (case-insensitive,
    /// `/` or `\`, `\\?\` / `\??\` prefixes and quotes ignored).
    pub fn by_image(&self, path: &str) -> Vec<&ProcessInfo> {
        let k = image_key(path);
        if k.is_empty() {
            return vec![];
        }
        self.by_image
            .get(&k)
            .map(|v| v.iter().filter_map(|g| self.procs.get(g)).collect())
            .unwrap_or_default()
    }

    /// Parent of a process: by `parent_guid` when known, else the live (or most
    /// recent) process with `ppid` that started no later than the child.
    pub fn parent_of(&self, p: &ProcessInfo) -> Option<&ProcessInfo> {
        if let Some(pg) = &p.parent_guid {
            if let Some(pp) = self.procs.get(pg) {
                return Some(pp);
            }
            return None;
        }
        if p.ppid == 0 || p.ppid == p.pid {
            return None;
        }
        self.by_pid
            .get(&p.ppid)?
            .iter()
            .filter_map(|g| self.procs.get(g))
            .filter(|c| {
                c.guid != p.guid
                    && c.start_ts <= p.start_ts
                    && c.exit_ts.is_none_or(|e| e >= p.start_ts)
            })
            .max_by_key(|c| c.start_ts)
    }

    /// Insert or replace a process. A different live process holding the same
    /// pid is marked exited (the pid was reused, so it must be gone).
    pub fn insert(&mut self, info: ProcessInfo) {
        let guid = info.guid.clone();
        if let Some(old) = self.procs.get(&guid) {
            // Replace: unlink from old parent's child list if the parent changed.
            if old.parent_guid != info.parent_guid {
                if let Some(pg) = old.parent_guid.clone() {
                    if let Some(v) = self.children.get_mut(&pg) {
                        v.retain(|g| g != &guid);
                    }
                }
            }
        }
        // pid reuse
        if let Some(list) = self.by_pid.get(&info.pid) {
            let stale: Vec<ProcessGuid> = list
                .iter()
                .filter(|g| **g != guid)
                .filter(|g| {
                    self.procs
                        .get(*g)
                        .is_some_and(|p| p.exit_ts.is_none() && p.start_ts <= info.start_ts)
                })
                .cloned()
                .collect();
            for g in stale {
                if let Some(p) = self.procs.get_mut(&g) {
                    p.exit_ts = Some(info.start_ts);
                }
            }
        }
        let list = self.by_pid.entry(info.pid).or_default();
        if !list.contains(&guid) {
            list.push(guid.clone());
        }
        let parent = info
            .parent_guid
            .clone()
            .or_else(|| self.parent_of(&info).map(|p| p.guid.clone()));
        if let Some(pg) = parent {
            if pg != guid {
                let kids = self.children.entry(pg).or_default();
                if !kids.contains(&guid) {
                    kids.push(guid.clone());
                }
            }
        }
        let ik = image_key(&info.image);
        if let Some(old) = self.procs.get(&guid) {
            let ok = image_key(&old.image);
            if ok != ik {
                self.unindex_image(&ok, &guid);
            }
        }
        if !ik.is_empty() {
            let v = self.by_image.entry(ik).or_default();
            if !v.contains(&guid) {
                v.push(guid.clone());
            }
        }
        self.procs.insert(guid, info);
        if self.procs.len() > self.max_entries {
            self.enforce_cap();
        }
    }

    fn unindex_image(&mut self, key: &str, guid: &ProcessGuid) {
        if let Some(v) = self.by_image.get_mut(key) {
            v.retain(|g| g != guid);
            if v.is_empty() {
                self.by_image.remove(key);
            }
        }
    }

    /// Mutable access for late enrichment (hash / signature facts only;
    /// callers must not change identity fields).
    pub(crate) fn get_mut(&mut self, guid: &ProcessGuid) -> Option<&mut ProcessInfo> {
        self.procs.get_mut(guid)
    }

    /// Record process exit.
    pub fn mark_exit(&mut self, guid: &ProcessGuid, ts: TimestampMs) {
        if let Some(p) = self.procs.get_mut(guid) {
            if p.exit_ts.is_none() {
                p.exit_ts = Some(ts);
            }
        }
    }

    /// Live direct children.
    pub fn children_of(&self, guid: &ProcessGuid) -> Vec<&ProcessInfo> {
        self.children
            .get(guid)
            .map(|v| v.iter().filter_map(|g| self.procs.get(g)).collect())
            .unwrap_or_default()
    }

    /// Evict exited processes older than the retention window. Returns evicted GUIDs.
    pub fn evict(&mut self, now: TimestampMs) -> Vec<ProcessGuid> {
        let cutoff = now - self.retention_ms;
        let dead: Vec<ProcessGuid> = self
            .procs
            .values()
            .filter(|p| p.exit_ts.is_some_and(|e| e < cutoff))
            .map(|p| p.guid.clone())
            .collect();
        for g in &dead {
            self.remove(g);
        }
        dead
    }

    fn enforce_cap(&mut self) {
        let target = self.max_entries - self.max_entries / 10; // drop ~10% at once
        let excess = self.procs.len().saturating_sub(target);
        if excess == 0 {
            return;
        }
        let mut order: Vec<(bool, TimestampMs, ProcessGuid)> = self
            .procs
            .values()
            .map(|p| {
                (
                    p.exit_ts.is_none(),
                    p.exit_ts.unwrap_or(p.start_ts),
                    p.guid.clone(),
                )
            })
            .collect();
        // exited (false) first, then oldest
        order.sort_by_key(|a| (a.0, a.1));
        for (_, _, g) in order.into_iter().take(excess) {
            self.remove(&g);
        }
    }

    fn remove(&mut self, guid: &ProcessGuid) {
        let Some(p) = self.procs.remove(guid) else {
            return;
        };
        self.unindex_image(&image_key(&p.image), guid);
        if let Some(v) = self.by_pid.get_mut(&p.pid) {
            v.retain(|g| g != guid);
            if v.is_empty() {
                self.by_pid.remove(&p.pid);
            }
        }
        if let Some(pg) = &p.parent_guid {
            if let Some(v) = self.children.get_mut(pg) {
                v.retain(|g| g != guid);
                if v.is_empty() {
                    self.children.remove(pg);
                }
            }
        } else {
            for v in self.children.values_mut() {
                v.retain(|g| g != guid);
            }
            self.children.retain(|_, v| !v.is_empty());
        }
        // Keep the removed node's child list: live descendants are still
        // reachable through it until they are evicted themselves.
        if self
            .children
            .get(guid)
            .is_some_and(|v| v.iter().all(|g| !self.procs.contains_key(g)))
        {
            self.children.remove(guid);
        }
    }
}

/// Comparison key of an image path for [`ProcessTable::by_image`].
pub fn image_key(path: &str) -> String {
    let l = path
        .trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase();
    l.trim_start_matches(r"\\?\")
        .trim_start_matches(r"\??\")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{PathClass, SignatureState};

    pub(crate) fn info(
        guid: &str,
        pid: u32,
        parent: Option<&str>,
        ppid: u32,
        start: i64,
        image: &str,
    ) -> ProcessInfo {
        ProcessInfo {
            guid: ProcessGuid(guid.into()),
            pid,
            ppid,
            parent_guid: parent.map(|p| ProcessGuid(p.into())),
            image: image.into(),
            cmdline: image.into(),
            user: None,
            integrity: None,
            start_ts: start,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unknown,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::of(image),
        }
    }

    fn g(s: &str) -> ProcessGuid {
        ProcessGuid(s.into())
    }

    #[test]
    fn by_pid_prefers_most_recent_live() {
        let mut t = ProcessTable::default();
        t.insert(info("a", 100, None, 1, 10, "a.exe"));
        t.insert(info("b", 100, None, 1, 20, "b.exe"));
        assert_eq!(t.by_pid(100).unwrap().guid, g("b"));
        assert_eq!(
            t.get(&g("a")).unwrap().exit_ts,
            Some(20),
            "pid reuse marks old exited"
        );
        t.mark_exit(&g("b"), 30);
        assert!(t.by_pid(100).is_none());
    }

    #[test]
    fn ancestry_and_cycles() {
        let mut t = ProcessTable::default();
        t.insert(info("root", 1, None, 0, 0, "explorer.exe"));
        t.insert(info("ps", 2, Some("root"), 1, 1, "powershell.exe"));
        t.insert(info("mshta", 3, Some("ps"), 2, 2, "mshta.exe"));
        t.insert(info("x", 4, Some("mshta"), 3, 3, "x.exe"));
        let a = t.ancestry(&g("x"), 10);
        let names: Vec<_> = a.iter().map(|p| p.image.as_str()).collect();
        assert_eq!(names, vec!["mshta.exe", "powershell.exe", "explorer.exe"]);
        assert_eq!(t.ancestry(&g("x"), 2).len(), 2);
        // cycle
        let mut t2 = ProcessTable::default();
        t2.insert(info("c1", 1, Some("c2"), 2, 0, "a.exe"));
        t2.insert(info("c2", 2, Some("c1"), 1, 0, "b.exe"));
        assert_eq!(t2.ancestry(&g("c1"), 10).len(), 1);
        // ppid fallback
        let mut t3 = ProcessTable::default();
        t3.insert(info("p", 50, None, 0, 0, "parent.exe"));
        t3.insert(info("c", 51, None, 50, 5, "child.exe"));
        assert_eq!(t3.ancestry(&g("c"), 4)[0].guid, g("p"));
    }

    #[test]
    fn descendants_live_only() {
        let mut t = ProcessTable::default();
        t.insert(info("r", 1, None, 0, 0, "r.exe"));
        t.insert(info("c1", 2, Some("r"), 1, 1, "c1.exe"));
        t.insert(info("c2", 3, Some("c1"), 2, 2, "c2.exe"));
        t.insert(info("c3", 4, Some("r"), 1, 3, "c3.exe"));
        t.mark_exit(&g("c1"), 5);
        let mut d: Vec<_> = t
            .descendants(&g("r"))
            .into_iter()
            .map(|p| p.guid.0)
            .collect();
        d.sort();
        assert_eq!(d, vec!["c2".to_string(), "c3".to_string()]);
        assert_eq!(t.children_of(&g("r")).len(), 2);
    }

    #[test]
    fn eviction_and_cap() {
        let mut t = ProcessTable::with_limits(1000, 100);
        for i in 0..50u32 {
            t.insert(info(&format!("p{i}"), i + 10, None, 0, i as i64, "a.exe"));
        }
        for i in 0..25u32 {
            t.mark_exit(&g(&format!("p{i}")), 100);
        }
        assert!(t.evict(1000).is_empty());
        assert_eq!(t.evict(1101).len(), 25);
        assert_eq!(t.len(), 25);
        for i in 0..200u32 {
            t.insert(info(
                &format!("q{i}"),
                i + 1000,
                None,
                0,
                2000 + i as i64,
                "b.exe",
            ));
        }
        assert!(t.len() <= 100);
        // the newest survive
        assert!(t.get(&g("q199")).is_some());
    }
}

#[cfg(test)]
mod image_index_tests {
    use super::tests::info;
    use super::*;

    #[test]
    fn by_image_tracks_insert_replace_and_removal() {
        let mut t = ProcessTable::with_limits(1000, 100);
        t.insert(info("a", 1, None, 0, 0, r"C:\Tools\x.exe"));
        t.insert(info("b", 2, None, 0, 1, r"c:/tools/X.EXE"));
        t.insert(info("c", 3, None, 0, 2, r"C:\Tools\y.exe"));
        assert_eq!(t.by_image(r"\\?\C:\TOOLS\x.exe").len(), 2);
        assert_eq!(t.by_image(r#""C:\Tools\y.exe""#).len(), 1);
        // replace with a different image re-indexes
        t.insert(info("c", 3, None, 0, 2, r"C:\Tools\x.exe"));
        assert_eq!(t.by_image(r"C:\Tools\x.exe").len(), 3);
        assert!(t.by_image(r"C:\Tools\y.exe").is_empty());
        t.mark_exit(&ProcessGuid("a".into()), 5);
        t.evict(2000);
        assert_eq!(t.by_image(r"C:\Tools\x.exe").len(), 2);
        assert!(t.by_image("").is_empty());
    }
}
