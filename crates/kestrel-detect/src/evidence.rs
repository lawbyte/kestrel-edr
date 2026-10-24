//! Evidence journal for suspected data theft (owner decision 2026-10-25,
//! `kestrel_common::evidence`).
//!
//! Pure, platform independent and bounded: the agent feeds every engine
//! [`Event`] ([`EvidenceJournal::observe`]) and the sensors' write hints
//! ([`EvidenceJournal::observe_write`]); when ST-02 / ST-04 fires it asks,
//! for the alerting process tree ([`tree_members`]) and a time window, which
//! files the tree staged, which credential stores it read and which remote
//! endpoints it talked to ([`EvidenceJournal::snapshot`]).
//!
//! Scope:
//! * **staged-file candidates**: files created / written under
//!   [`PathClass::Temp`], [`PathClass::Downloads`] or
//!   [`PathClass::UserWritable`] (user profiles, `ProgramData`,
//!   `\Windows\Temp`, …); never System / Windows / Program Files / external
//!   / other locations;
//! * **credential-store reads**: `FileAccess` Open / Read of a path
//!   [`crate::paths::match_sensitive_path`] knows;
//! * **network tuples**: `NetConnect` remote IP / port / protocol, only
//!   unicast addresses a packet capture can filter on.
//!
//! Bounds (see the constants): per process 512 written paths (oldest out,
//! the same path updates in place), 64 stores and 32 tuples; 1024 processes
//! (least recently active out) and 32 768 written paths overall. Entries
//! older than [`JOURNAL_RETENTION_MS`] are dropped by
//! [`EvidenceJournal::evict`] unless their process is pinned by a running
//! capture ([`EvidenceJournal::pin`]).

use kestrel_common::{
    evidence::{
        PcapFilter, ProcessRole, SecretRead, WriteOp, MAX_SECRETS, MAX_STAGED_FILES,
        MAX_TREE_PROCESSES, PCAP_MAX_FILTERS,
    },
    DataCategory, Event, EventData, FileOp, NetProto, PathClass, ProcessGuid, ProcessInfo,
    TimestampMs,
};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::table::ProcessTable;

/// Written paths remembered per process.
pub const MAX_WRITES_PER_PROCESS: usize = 512;
/// Credential stores remembered per process.
pub const MAX_STORES_PER_PROCESS: usize = 64;
/// Network tuples remembered per process.
pub const MAX_NET_PER_PROCESS: usize = 32;
/// Processes tracked.
pub const MAX_PROCESSES: usize = 1024;
/// Written paths remembered over all processes (memory bound: a build tool
/// writing thousands of files in many processes must not grow the agent).
pub const MAX_TOTAL_WRITES: usize = 32_768;
/// Entries older than this are dropped (unless pinned).
pub const JOURNAL_RETENTION_MS: i64 = 10 * 60_000;
/// Longer paths are ignored (never a staging location worth copying).
pub const MAX_PATH_CHARS: usize = 1024;

/// Remote ports never used as packet-capture filters: Windows
/// infrastructure (DNS, Kerberos, RPC, NetBIOS, LDAP, SMB, kpasswd, global
/// catalog). A stealer's tuple to a domain controller would otherwise
/// capture the PC's whole authentication and file-share traffic.
pub const INFRA_PORTS: &[u16] = &[53, 88, 135, 139, 389, 445, 464, 636, 3268, 3269];

/// Extensions (lower-case, no dot) of staged files worth keeping when a
/// process's ring is full: archives, text / data dumps, databases,
/// screenshots and documents. Other writes (caches, DLLs, temp files) are
/// evicted first, so 512 junk files cannot push the archive out.
pub const HIGH_VALUE_EXTENSIONS: &[&str] = &[
    "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "xz", "cab", "txt", "csv", "json", "log", "db",
    "sqlite", "sqlite3", "ldb", "dat", "xml", "png", "jpg", "jpeg", "bmp", "gif", "webp", "doc",
    "docx", "xls", "xlsx", "pdf", "kdbx", "wallet",
];

/// Is this staged path high-value (see [`HIGH_VALUE_EXTENSIONS`])?
pub fn is_high_value(path: &str) -> bool {
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    match name.rsplit_once('.') {
        Some((stem, ext)) if !stem.is_empty() => {
            let ext = ext.to_ascii_lowercase();
            HIGH_VALUE_EXTENSIONS.contains(&ext.as_str())
        }
        _ => false,
    }
}

/// A staged-file candidate in a [`JournalSnapshot`].
#[derive(Debug, Clone, PartialEq)]
pub struct StagedCandidate {
    /// Path as last written (original case).
    pub path: String,
    pub written_at: TimestampMs,
    pub op: WriteOp,
    /// Writer of the last write.
    pub guid: ProcessGuid,
    /// Writer image (from the tree members; empty when unknown).
    pub image: String,
    /// The sensor confirmed that a tree member created the file (Kernel-File
    /// CreateNewFile, a sensor write hint). `false` for writes known only
    /// from open attempts (`FileAccess` create / write, file-activity
    /// samples), which are logged for failed opens too (review of the 1.1.7
    /// integration, M2): such a file may belong to someone the tree could
    /// not read, so the agent copies it only from the tree user's own
    /// profile.
    pub confirmed: bool,
}

/// What the tree did in a window.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct JournalSnapshot {
    /// Newest first, de-duplicated case-insensitively (latest write wins),
    /// at most [`MAX_STAGED_FILES`].
    pub staged: Vec<StagedCandidate>,
    /// Candidates beyond [`MAX_STAGED_FILES`] (not listed).
    pub staged_unlisted: u32,
    /// Merged per path over the tree (counts summed, earliest first read,
    /// latest last read; the reader is the earliest one), earliest first,
    /// at most [`MAX_SECRETS`]. `size` / `copy` are `None` (filled when the
    /// bundle is built).
    pub secrets: Vec<SecretRead>,
    /// Stores beyond [`MAX_SECRETS`] (not listed).
    pub secrets_unlisted: u32,
    /// De-duplicated, most recent first, at most [`PCAP_MAX_FILTERS`].
    pub net: Vec<PcapFilter>,
    /// Written paths the tree's processes had to forget (ring full or
    /// global memory cap) before the snapshot.
    pub staged_evicted: u32,
    /// Tuples left out of `net` because their port is an infrastructure
    /// port ([`INFRA_PORTS`]).
    pub net_excluded: u32,
}

#[derive(Debug, Clone)]
struct Written {
    path: String,
    ts: TimestampMs,
    op: WriteOp,
    /// A sensor-confirmed creation by this process (sticky).
    confirmed: bool,
}

#[derive(Debug, Clone)]
struct StoreRead {
    path: String,
    store: &'static str,
    noun: &'static str,
    category: DataCategory,
    first: TimestampMs,
    last: TimestampMs,
    count: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct NetKey {
    ip: IpAddr,
    port: u16,
    proto: NetProto,
}

#[derive(Debug, Clone, Copy)]
struct NetSeen {
    first: TimestampMs,
    last: TimestampMs,
}

#[derive(Debug, Default)]
struct ProcJournal {
    /// Normalised (lower-case, `\`) path → last write.
    writes: HashMap<String, Written>,
    stores: HashMap<String, StoreRead>,
    net: HashMap<NetKey, NetSeen>,
    last_active: TimestampMs,
    /// Written paths evicted from this process (ring full / global cap).
    evicted: u32,
}

impl ProcJournal {
    fn is_empty(&self) -> bool {
        self.writes.is_empty() && self.stores.is_empty() && self.net.is_empty()
    }
}

/// Bounded per-process journal of staged writes, credential-store reads and
/// connections (see the module docs).
#[derive(Debug, Default)]
pub struct EvidenceJournal {
    procs: HashMap<ProcessGuid, ProcJournal>,
    /// Pinned GUIDs (reference counted: one per running capture).
    pinned: HashMap<ProcessGuid, u32>,
    total_writes: usize,
}

/// Normalised comparison key of a path (lower-case, `\`).
fn path_key(path: &str) -> String {
    crate::paths::normalize_path(path)
}

/// Is `path` a location whose writes are staged-file candidates?
pub fn in_staging_scope(path: &str) -> bool {
    matches!(
        PathClass::of(path),
        PathClass::Temp | PathClass::Downloads | PathClass::UserWritable
    )
}

/// A remote address a capture may filter on: unicast, not loopback,
/// unspecified, multicast, link-local or broadcast. IPv4-mapped IPv6
/// addresses are returned as IPv4.
pub fn capture_ip(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_start_matches('[').trim_end_matches(']');
    // Zone ids (`fe80::1%12`) are link-local anyway.
    if s.contains('%') {
        return None;
    }
    let ip: IpAddr = s.parse().ok()?;
    let ip = match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    let ok = match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.octets()[0] == 0)
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xffc0) == 0xfe80)
        }
    };
    ok.then_some(ip)
}

impl EvidenceJournal {
    pub fn new() -> Self {
        Self::default()
    }

    /// Processes tracked.
    pub fn len(&self) -> usize {
        self.procs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.procs.is_empty()
    }

    /// Written paths remembered over all processes.
    pub fn total_writes(&self) -> usize {
        self.total_writes
    }

    /// Written paths remembered for one process.
    pub fn writes_of(&self, guid: &ProcessGuid) -> usize {
        self.procs.get(guid).map_or(0, |p| p.writes.len())
    }

    /// Credential stores remembered for one process.
    pub fn stores_of(&self, guid: &ProcessGuid) -> usize {
        self.procs.get(guid).map_or(0, |p| p.stores.len())
    }

    /// Network tuples remembered for one process.
    pub fn net_of(&self, guid: &ProcessGuid) -> usize {
        self.procs.get(guid).map_or(0, |p| p.net.len())
    }

    pub fn is_pinned(&self, guid: &ProcessGuid) -> bool {
        self.pinned.contains_key(guid)
    }

    /// Keep these processes' entries while a capture runs (reference counted).
    pub fn pin(&mut self, guids: &[ProcessGuid]) {
        for g in guids {
            *self.pinned.entry(g.clone()).or_insert(0) += 1;
        }
    }

    /// Undo one [`EvidenceJournal::pin`].
    pub fn unpin(&mut self, guids: &[ProcessGuid]) {
        for g in guids {
            if let Some(n) = self.pinned.get_mut(g) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.pinned.remove(g);
                }
            }
        }
    }

    /// Observe one engine event (cheap; anything irrelevant is ignored).
    pub fn observe(&mut self, e: &Event) {
        match &e.data {
            EventData::FileAccess { path, op } => match op {
                FileOp::Create => self.observe_write(e.ts, &e.guid, path, WriteOp::Created),
                FileOp::Write => self.observe_write(e.ts, &e.guid, path, WriteOp::Written),
                FileOp::Open | FileOp::Read => self.observe_read(e.ts, &e.guid, path),
                FileOp::Delete | FileOp::Rename => {}
            },
            EventData::FileActivity(f) => {
                for p in &f.sample_paths {
                    self.observe_write(e.ts, &e.guid, p, WriteOp::Written);
                }
            }
            EventData::NetConnect {
                proto,
                dst_ip,
                dst_port,
                ..
            } => self.observe_net(e.ts, &e.guid, *proto, dst_ip, *dst_port),
            _ => {}
        }
    }

    /// A file `guid` created / overwrote / renamed into place, known from an
    /// open attempt (`FileAccess` write, `file_activity` sample path): not
    /// confirmed ([`StagedCandidate::confirmed`]). Ignored outside the
    /// staging scope.
    pub fn observe_write(&mut self, ts: TimestampMs, guid: &ProcessGuid, path: &str, op: WriteOp) {
        self.record_write(ts, guid, path, op, false);
    }

    /// A file creation the sensor confirmed (`kestrel_platform::WriteHint`,
    /// Kernel-File CreateNewFile): [`StagedCandidate::confirmed`].
    pub fn observe_sensor_write(
        &mut self,
        ts: TimestampMs,
        guid: &ProcessGuid,
        path: &str,
        op: WriteOp,
    ) {
        self.record_write(ts, guid, path, op, true);
    }

    fn record_write(
        &mut self,
        ts: TimestampMs,
        guid: &ProcessGuid,
        path: &str,
        op: WriteOp,
        confirmed: bool,
    ) {
        if path.is_empty() || path.chars().count() > MAX_PATH_CHARS || !in_staging_scope(path) {
            return;
        }
        let key = path_key(path);
        let Some(pj) = self.proc_mut(guid, ts) else {
            return;
        };
        let added = match pj.writes.get_mut(&key) {
            Some(w) => {
                if ts >= w.ts {
                    w.ts = ts;
                    w.op = op;
                    w.path = path.to_string();
                }
                w.confirmed |= confirmed;
                false
            }
            None => {
                let mut removed = 0usize;
                if pj.writes.len() >= MAX_WRITES_PER_PROCESS {
                    // Oldest low-value write first; the oldest of all only
                    // when every remembered write is high-value.
                    if let Some(old) = pj
                        .writes
                        .iter()
                        .min_by_key(|(_, w)| (is_high_value(&w.path), w.ts))
                        .map(|(k, _)| k.clone())
                    {
                        pj.writes.remove(&old);
                        pj.evicted = pj.evicted.saturating_add(1);
                        removed = 1;
                    }
                }
                pj.writes.insert(
                    key,
                    Written {
                        path: path.to_string(),
                        ts,
                        op,
                        confirmed,
                    },
                );
                self.total_writes -= removed;
                true
            }
        };
        if added {
            self.total_writes += 1;
            if self.total_writes > MAX_TOTAL_WRITES {
                self.shed_writes(guid);
            }
        }
    }

    fn observe_read(&mut self, ts: TimestampMs, guid: &ProcessGuid, path: &str) {
        if path.chars().count() > MAX_PATH_CHARS {
            return;
        }
        let Some(s) = crate::paths::match_sensitive_path(path) else {
            return;
        };
        let key = path_key(path);
        let Some(pj) = self.proc_mut(guid, ts) else {
            return;
        };
        if let Some(r) = pj.stores.get_mut(&key) {
            r.first = r.first.min(ts);
            r.last = r.last.max(ts);
            r.count = r.count.saturating_add(1);
            return;
        }
        if pj.stores.len() >= MAX_STORES_PER_PROCESS {
            if let Some(old) = pj
                .stores
                .iter()
                .min_by_key(|(_, r)| r.last)
                .map(|(k, _)| k.clone())
            {
                pj.stores.remove(&old);
            }
        }
        pj.stores.insert(
            key,
            StoreRead {
                path: path.to_string(),
                store: s.app,
                noun: s.noun,
                category: s.category,
                first: ts,
                last: ts,
                count: 1,
            },
        );
    }

    fn observe_net(
        &mut self,
        ts: TimestampMs,
        guid: &ProcessGuid,
        proto: NetProto,
        ip: &str,
        port: u16,
    ) {
        let Some(ip) = capture_ip(ip) else {
            return;
        };
        let k = NetKey { ip, port, proto };
        let Some(pj) = self.proc_mut(guid, ts) else {
            return;
        };
        if let Some(n) = pj.net.get_mut(&k) {
            n.first = n.first.min(ts);
            n.last = n.last.max(ts);
            return;
        }
        if pj.net.len() >= MAX_NET_PER_PROCESS {
            if let Some(old) = pj.net.iter().min_by_key(|(_, n)| n.last).map(|(k, _)| *k) {
                pj.net.remove(&old);
            }
        }
        pj.net.insert(
            k,
            NetSeen {
                first: ts,
                last: ts,
            },
        );
    }

    /// The journal of `guid`, created (evicting the least recently active
    /// unpinned process at capacity). `None` when every slot is pinned.
    fn proc_mut(&mut self, guid: &ProcessGuid, ts: TimestampMs) -> Option<&mut ProcJournal> {
        if !self.procs.contains_key(guid) && self.procs.len() >= MAX_PROCESSES {
            let victim = self
                .procs
                .iter()
                .filter(|(g, _)| !self.pinned.contains_key(*g))
                .min_by_key(|(_, p)| p.last_active)
                .map(|(g, _)| g.clone())?;
            self.remove_proc(&victim);
        }
        let pj = self.procs.entry(guid.clone()).or_default();
        pj.last_active = pj.last_active.max(ts);
        Some(pj)
    }

    fn remove_proc(&mut self, guid: &ProcessGuid) {
        if let Some(p) = self.procs.remove(guid) {
            self.total_writes -= p.writes.len();
        }
    }

    /// Over the global write cap: drop the older half of the writes of the
    /// least recently active unpinned process (never `current`, unless it is
    /// the only candidate).
    fn shed_writes(&mut self, current: &ProcessGuid) {
        while self.total_writes > MAX_TOTAL_WRITES {
            let pick = |skip_current: bool| {
                self.procs
                    .iter()
                    .filter(|(g, p)| {
                        !p.writes.is_empty()
                            && !self.pinned.contains_key(*g)
                            && !(skip_current && *g == current)
                    })
                    .min_by_key(|(_, p)| p.last_active)
                    .map(|(g, _)| g.clone())
            };
            let Some(victim) = pick(true).or_else(|| pick(false)) else {
                return; // everything pinned: allow the overshoot
            };
            let Some(pj) = self.procs.get_mut(&victim) else {
                return;
            };
            // Low-value writes first, oldest first.
            let mut by_age: Vec<(bool, TimestampMs, String)> = pj
                .writes
                .iter()
                .map(|(k, w)| (is_high_value(&w.path), w.ts, k.clone()))
                .collect();
            by_age.sort();
            let drop_n = by_age.len().div_ceil(2).max(1);
            for (_, _, k) in by_age.into_iter().take(drop_n) {
                pj.writes.remove(&k);
            }
            pj.evicted = pj.evicted.saturating_add(drop_n as u32);
            self.total_writes -= drop_n;
            if pj.is_empty() {
                self.procs.remove(&victim);
            }
        }
    }

    /// Drop entries older than [`JOURNAL_RETENTION_MS`] (pinned processes
    /// keep everything) and processes left empty.
    pub fn evict(&mut self, now: TimestampMs) {
        let cutoff = now - JOURNAL_RETENTION_MS;
        let mut removed_writes = 0usize;
        let pinned = &self.pinned;
        self.procs.retain(|g, p| {
            if pinned.contains_key(g) {
                return true;
            }
            let before = p.writes.len();
            p.writes.retain(|_, w| w.ts >= cutoff);
            removed_writes += before - p.writes.len();
            p.stores.retain(|_, r| r.last >= cutoff);
            p.net.retain(|_, n| n.last >= cutoff);
            !p.is_empty()
        });
        self.total_writes -= removed_writes;
    }

    /// What `members` did between `from_ts` and `to_ts` (inclusive).
    pub fn snapshot(
        &self,
        members: &[(ProcessInfo, ProcessRole)],
        from_ts: TimestampMs,
        to_ts: TimestampMs,
    ) -> JournalSnapshot {
        let images: HashMap<&ProcessGuid, &str> = members
            .iter()
            .map(|(p, _)| (&p.guid, p.image.as_str()))
            .collect();
        let mut seen_guid: HashSet<&ProcessGuid> = HashSet::new();
        let mut staged: HashMap<&str, StagedCandidate> = HashMap::new();
        let mut secrets: HashMap<&str, SecretRead> = HashMap::new();
        let mut net: HashMap<NetKey, NetSeen> = HashMap::new();
        let mut staged_evicted = 0u32;
        for (p, _) in members {
            if !seen_guid.insert(&p.guid) {
                continue;
            }
            let Some(pj) = self.procs.get(&p.guid) else {
                continue;
            };
            staged_evicted = staged_evicted.saturating_add(pj.evicted);
            for (k, w) in &pj.writes {
                if w.ts < from_ts || w.ts > to_ts {
                    continue;
                }
                let prev = staged.get(k.as_str());
                let newer = prev.is_none_or(|c| w.ts > c.written_at);
                // Confirmed when any tree member's creation was confirmed.
                let confirmed = w.confirmed || prev.is_some_and(|c| c.confirmed);
                if newer {
                    staged.insert(
                        k.as_str(),
                        StagedCandidate {
                            path: w.path.clone(),
                            written_at: w.ts,
                            op: w.op,
                            guid: p.guid.clone(),
                            image: images.get(&p.guid).copied().unwrap_or_default().to_string(),
                            confirmed,
                        },
                    );
                } else if let Some(c) = staged.get_mut(k.as_str()) {
                    c.confirmed = confirmed;
                }
            }
            for (k, r) in &pj.stores {
                if r.last < from_ts || r.first > to_ts {
                    continue;
                }
                match secrets.get_mut(k.as_str()) {
                    Some(s) => {
                        if r.first < s.first_read {
                            s.process_guid = p.guid.clone();
                            s.image = p.image.clone();
                        }
                        s.first_read = s.first_read.min(r.first);
                        s.last_read = s.last_read.max(r.last);
                        s.open_count = s.open_count.saturating_add(r.count);
                    }
                    None => {
                        secrets.insert(
                            k.as_str(),
                            SecretRead {
                                path: r.path.clone(),
                                store: r.store.to_string(),
                                noun: r.noun.to_string(),
                                category: r.category,
                                first_read: r.first,
                                last_read: r.last,
                                open_count: r.count,
                                process_guid: p.guid.clone(),
                                image: p.image.clone(),
                                size: None,
                                copy: None,
                            },
                        );
                    }
                }
            }
            for (k, n) in &pj.net {
                if n.last < from_ts || n.first > to_ts {
                    continue;
                }
                let e = net.entry(*k).or_insert(*n);
                e.first = e.first.min(n.first);
                e.last = e.last.max(n.last);
            }
        }

        let mut staged: Vec<StagedCandidate> = staged.into_values().collect();
        staged.sort_by(|a, b| {
            b.written_at
                .cmp(&a.written_at)
                .then_with(|| a.path.cmp(&b.path))
        });
        let staged_unlisted = staged.len().saturating_sub(MAX_STAGED_FILES) as u32;
        staged.truncate(MAX_STAGED_FILES);

        let mut secrets: Vec<SecretRead> = secrets.into_values().collect();
        secrets.sort_by(|a, b| {
            a.first_read
                .cmp(&b.first_read)
                .then_with(|| a.path.cmp(&b.path))
        });
        let secrets_unlisted = secrets.len().saturating_sub(MAX_SECRETS) as u32;
        secrets.truncate(MAX_SECRETS);

        let before = net.len();
        let mut net: Vec<(NetKey, NetSeen)> = net
            .into_iter()
            .filter(|(k, _)| !INFRA_PORTS.contains(&k.port))
            .collect();
        let net_excluded = (before - net.len()) as u32;
        net.sort_by(|a, b| {
            b.1.last
                .cmp(&a.1.last)
                .then_with(|| a.0.ip.cmp(&b.0.ip))
                .then_with(|| a.0.port.cmp(&b.0.port))
        });
        let net = net
            .into_iter()
            .take(PCAP_MAX_FILTERS)
            .map(|(k, _)| PcapFilter {
                ip: k.ip.to_string(),
                port: (k.port != 0).then_some(k.port),
                proto: Some(k.proto),
            })
            .collect();

        JournalSnapshot {
            staged,
            staged_unlisted,
            secrets,
            secrets_unlisted,
            net,
            staged_evicted,
            net_excluded,
        }
    }
}

/// May an ancestor join the evidence tree? Only an unsigned / invalid /
/// unknown-signature program in a user-writable location (the loader that
/// started a stealer from `%TEMP%`). A validly signed program (Telegram,
/// Discord, per-user Chrome / VS Code that launched a download) or anything
/// in System32 / Windows / Program Files / other volumes is not, and stops
/// the walk.
fn ancestor_joins(p: &ProcessInfo) -> bool {
    p.path_class.is_user_writable() && p.signed != kestrel_common::SignatureState::Valid
}

/// The evidence tree of `guid`: the process itself ([`ProcessRole::Alerting`],
/// first), its descendants (live or exited, still in the table), and its
/// ancestors up to (not including) the first one that is validly signed or
/// not in a user-writable location (see `ancestor_joins`). At most [`MAX_TREE_PROCESSES`]; ancestors are listed
/// before descendants are cut. Empty when `guid` is not in the table.
pub fn tree_members(table: &ProcessTable, guid: &ProcessGuid) -> Vec<(ProcessInfo, ProcessRole)> {
    let Some(me) = table.get(guid) else {
        return Vec::new();
    };
    let mut out = vec![(me.clone(), ProcessRole::Alerting)];
    let mut seen: HashSet<ProcessGuid> = HashSet::from([me.guid.clone()]);

    // Ancestors (nearest first) while outside trusted locations.
    let mut ancestors = Vec::new();
    let mut cur = me;
    while out.len() + ancestors.len() < MAX_TREE_PROCESSES {
        let Some(parent) = table.parent_of(cur) else {
            break;
        };
        if !ancestor_joins(parent) || !seen.insert(parent.guid.clone()) {
            break;
        }
        ancestors.push((parent.clone(), ProcessRole::Ancestor));
        cur = parent;
    }

    // Descendants (breadth first, exited ones too).
    let mut descendants = Vec::new();
    let mut queue: std::collections::VecDeque<ProcessGuid> =
        std::collections::VecDeque::from([me.guid.clone()]);
    'walk: while let Some(g) = queue.pop_front() {
        for child in table.children_of(&g) {
            if !seen.insert(child.guid.clone()) {
                continue;
            }
            if out.len() + ancestors.len() + descendants.len() >= MAX_TREE_PROCESSES {
                break 'walk;
            }
            descendants.push((child.clone(), ProcessRole::Descendant));
            queue.push_back(child.guid.clone());
        }
    }
    out.extend(ancestors);
    out.extend(descendants);
    out.truncate(MAX_TREE_PROCESSES);
    out
}
