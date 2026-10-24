//! Telemetry upload path between the engine and the outbox: de-duplication,
//! batching and the outbox writer thread.
//!
//! Detection always sees every event (the engine runs before this); only
//! the copy uploaded for hunting is reduced.
//!
//! * **De-duplication with a count.** Owner-PC telemetry (2026-10-21..24,
//!   4.76 M events) showed most volume is the same thing over and over:
//!   OneDrive opening `explorer.exe` with the same access mask 1.36 M
//!   times, NordVPN calling DPAPI 26,000 times, `docker.exe` re-reading
//!   `config.json`. Per (process, kind, target) the first event is uploaded
//!   at once; identical ones inside [`UploadConfig::window_ms`] are counted,
//!   and when the window ends one summary row is uploaded: the last of them
//!   with an [`EventRepeat`] (`count`, `first_ts`). Process start / stop,
//!   tamper, file-activity summaries, persistence and script blocks are
//!   never merged. Window: 5 minutes. On three idle hours of the owner's
//!   PC (177,926 events) it removes 41 % of the rows (1 minute: 13 %,
//!   10 minutes: 51 %); a summary reaches the console at most 5 minutes
//!   after the repeats started, the first occurrence at once.
//! * **Batching.** A batch is sealed at [`UploadConfig::max_events`] or
//!   [`UploadConfig::max_delay_ms`] after its first event (alerts do not
//!   wait: they are separate payloads).
//! * **Writer thread.** JSON + zstd encoding and the SQLite insert run on
//!   `kestrel-outbox` at below-normal priority + EcoQoS, not on the engine
//!   thread; if that thread falls behind (its queue is full) the engine
//!   thread writes the batch itself, so telemetry is slowed down, never
//!   dropped here.

use kestrel_common::wire::{AgentPayload, EventRepeat};
use kestrel_common::{Event, EventData};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::Arc;

use crate::agent::Core;

#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub max_events: usize,
    pub max_delay_ms: i64,
    /// De-duplication window (arrival time). 0 disables de-duplication.
    pub window_ms: i64,
    /// Bound on open de-duplication windows (each holds at most one event).
    pub max_keys: usize,
}

impl Default for UploadConfig {
    fn default() -> Self {
        UploadConfig {
            max_events: 500,
            max_delay_ms: 5_000,
            window_ms: 300_000,
            max_keys: 8_192,
        }
    }
}

/// A sealed batch, ready for the outbox.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Batch {
    pub events: Vec<Event>,
    pub repeats: Vec<EventRepeat>,
}

impl Batch {
    pub fn into_payload(self) -> AgentPayload {
        AgentPayload::Events {
            events: self.events,
            repeats: self.repeats,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UploadStats {
    /// Events handed to the uploader (after the privacy filter).
    pub events_in: u64,
    /// Events merged into a repeat summary instead of being uploaded.
    pub suppressed: u64,
    /// Summary rows uploaded.
    pub summaries: u64,
    /// Rows uploaded (events + summaries).
    pub rows_out: u64,
    pub batches: u64,
}

struct Slot {
    /// Arrival time the window opened.
    opened: i64,
    /// Identical events merged so far (not counting the first, uploaded one).
    count: u32,
    first_ts: i64,
    last: Option<Event>,
}

pub struct Uploader {
    cfg: UploadConfig,
    batch: Vec<Event>,
    repeats: Vec<EventRepeat>,
    started: Option<i64>,
    slots: HashMap<u64, Slot>,
    order: VecDeque<(u64, i64)>,
    pub stats: UploadStats,
}

impl Uploader {
    pub fn new(cfg: UploadConfig) -> Self {
        Uploader {
            cfg,
            batch: Vec::new(),
            repeats: Vec::new(),
            started: None,
            slots: HashMap::new(),
            order: VecDeque::new(),
            stats: UploadStats::default(),
        }
    }

    /// Open de-duplication windows (memory bound check).
    pub fn open_windows(&self) -> usize {
        self.slots.len()
    }

    /// Queue one event (`now` = arrival time, ms). Returns the batches it
    /// sealed (at most a couple).
    pub fn push(&mut self, ev: Event, now: i64) -> Vec<Batch> {
        self.stats.events_in += 1;
        let mut out = Vec::new();
        if self.cfg.window_ms > 0 {
            if let Some(k) = dedupe_key(&ev) {
                if let Some(slot) = self.slots.get_mut(&k) {
                    if now - slot.opened < self.cfg.window_ms && now >= slot.opened {
                        slot.count += 1;
                        if slot.count == 1 {
                            slot.first_ts = ev.ts;
                        }
                        let mut ev = ev;
                        if let Some(prev) = slot.last.take() {
                            keep_max_bytes(&mut ev, &prev);
                        }
                        slot.last = Some(ev);
                        self.stats.suppressed += 1;
                        return out;
                    }
                    self.close(k, now, &mut out);
                }
                while self.slots.len() >= self.cfg.max_keys.max(1) {
                    match self.order.pop_front() {
                        Some((old, opened)) => {
                            if self.slots.get(&old).is_some_and(|s| s.opened == opened) {
                                self.close(old, now, &mut out);
                            }
                        }
                        None => {
                            self.slots.clear();
                            break;
                        }
                    }
                }
                self.slots.insert(
                    k,
                    Slot {
                        opened: now,
                        count: 0,
                        first_ts: 0,
                        last: None,
                    },
                );
                self.order.push_back((k, now));
            }
        }
        self.add(ev, None, now, &mut out);
        out
    }

    /// Close windows that ended and seal the batch if it is old enough.
    pub fn tick(&mut self, now: i64) -> Vec<Batch> {
        let mut out = Vec::new();
        while let Some(&(k, opened)) = self.order.front() {
            if now - opened < self.cfg.window_ms {
                break;
            }
            self.order.pop_front();
            if self.slots.get(&k).is_some_and(|s| s.opened == opened) {
                self.close(k, now, &mut out);
            }
        }
        if self
            .started
            .is_some_and(|s| now - s >= self.cfg.max_delay_ms)
        {
            out.extend(self.take());
        }
        out
    }

    /// Flush everything (shutdown): pending summaries and the open batch.
    pub fn finish(&mut self, now: i64) -> Vec<Batch> {
        let mut out = Vec::new();
        while let Some((k, opened)) = self.order.pop_front() {
            if self.slots.get(&k).is_some_and(|s| s.opened == opened) {
                self.close(k, now, &mut out);
            }
        }
        self.slots.clear();
        out.extend(self.take());
        out
    }

    fn close(&mut self, k: u64, now: i64, out: &mut Vec<Batch>) {
        let Some(slot) = self.slots.remove(&k) else {
            return;
        };
        if let Some(ev) = slot.last {
            self.stats.summaries += 1;
            self.add(ev, Some((slot.count, slot.first_ts)), now, out);
        }
    }

    fn add(&mut self, ev: Event, rep: Option<(u32, i64)>, now: i64, out: &mut Vec<Batch>) {
        if self.batch.is_empty() {
            self.started = Some(now);
        }
        if let Some((count, first_ts)) = rep {
            self.repeats.push(EventRepeat {
                index: self.batch.len() as u32,
                count,
                first_ts,
            });
        }
        self.batch.push(ev);
        self.stats.rows_out += 1;
        if self.batch.len() >= self.cfg.max_events.max(1) {
            out.extend(self.take());
        }
    }

    fn take(&mut self) -> Option<Batch> {
        self.started = None;
        if self.batch.is_empty() {
            return None;
        }
        self.stats.batches += 1;
        Some(Batch {
            events: std::mem::take(&mut self.batch),
            repeats: std::mem::take(&mut self.repeats),
        })
    }
}

/// A summary of network connects keeps the largest byte count seen.
fn keep_max_bytes(ev: &mut Event, prev: &Event) {
    if let (
        EventData::NetConnect { bytes_sent: b, .. },
        EventData::NetConnect {
            bytes_sent: Some(p),
            ..
        },
    ) = (&mut ev.data, &prev.data)
    {
        *b = Some(b.unwrap_or(0).max(*p));
    }
}

/// Identity of "the same thing again": process instance, kind and target.
/// `None` = never merged (process start / stop, tamper, file activity,
/// persistence, script blocks).
pub fn dedupe_key(ev: &Event) -> Option<u64> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    ev.guid.hash(&mut h);
    ev.pid.hash(&mut h);
    ev.kind().as_str().hash(&mut h);
    match &ev.data {
        EventData::ProcessAccess(t)
        | EventData::RemoteThread(t)
        | EventData::ThreadContext(t)
        | EventData::DebugAttach(t) => {
            t.target_pid.hash(&mut h);
            t.target_guid.hash(&mut h);
            t.granted_access.hash(&mut h);
            t.return_code.hash(&mut h);
        }
        EventData::FileAccess { path, op } => {
            path.to_ascii_lowercase().hash(&mut h);
            format!("{op:?}").hash(&mut h);
        }
        EventData::DpapiUnprotect { description } => description.hash(&mut h),
        EventData::NetConnect {
            proto,
            dst_ip,
            dst_port,
            dst_host,
            ..
        } => {
            format!("{proto:?}").hash(&mut h);
            dst_ip.hash(&mut h);
            dst_port.hash(&mut h);
            // A shared CDN address must not merge a C2 host into a benign
            // one (review 2026-10-25 M4).
            dst_host
                .as_deref()
                .map(str::to_ascii_lowercase)
                .hash(&mut h);
        }
        EventData::DnsQuery { qname, answers } => {
            qname.to_ascii_lowercase().hash(&mut h);
            let mut a = answers.clone();
            a.sort();
            a.hash(&mut h);
        }
        EventData::ImageLoad {
            path,
            signer,
            signed,
        } => {
            path.to_ascii_lowercase().hash(&mut h);
            signer.hash(&mut h);
            format!("{signed:?}").hash(&mut h);
        }
        EventData::RegistrySet {
            key,
            value_name,
            data,
            op,
            ..
        } => {
            key.to_ascii_lowercase().hash(&mut h);
            value_name.hash(&mut h);
            data.hash(&mut h);
            format!("{op:?}").hash(&mut h);
        }
        EventData::ProcessStart(_)
        | EventData::ProcessStop { .. }
        | EventData::ScriptBlock { .. }
        | EventData::Tamper { .. }
        | EventData::FileActivity(_)
        | EventData::TaskRegistered(_)
        | EventData::ServiceInstalled(_)
        | EventData::WmiSubscription(_) => return None,
    }
    Some(h.finish())
}

/// Queue depth of the writer thread, in batches (500 events each at most).
const WRITER_QUEUE: usize = 64;

/// Writes sealed batches to the outbox on a low-priority thread.
pub struct OutboxWriter {
    core: Arc<Core>,
    tx: Option<SyncSender<Batch>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl OutboxWriter {
    pub fn spawn(core: Arc<Core>) -> Self {
        let (tx, rx) = sync_channel::<Batch>(WRITER_QUEUE);
        let c = core.clone();
        let handle = std::thread::Builder::new()
            .name("kestrel-outbox".into())
            .spawn(move || {
                lower_priority();
                while let Ok(b) = rx.recv() {
                    c.enqueue(&b.into_payload());
                }
            })
            .ok();
        if handle.is_none() {
            tracing::warn!("outbox writer thread unavailable; writing from the engine thread");
        }
        OutboxWriter {
            core,
            tx: handle.as_ref().map(|_| tx),
            handle,
        }
    }

    /// Hand a batch to the writer; written inline if it is behind.
    pub fn submit(&self, b: Batch) {
        let b = match &self.tx {
            Some(tx) => match tx.try_send(b) {
                Ok(()) => return,
                Err(TrySendError::Full(b)) | Err(TrySendError::Disconnected(b)) => b,
            },
            None => b,
        };
        self.core.enqueue(&b.into_payload());
    }

    /// Write what is queued and stop the thread.
    pub fn finish(mut self) {
        self.tx.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Below-normal CPU priority + EcoQoS for the writer (not background mode:
/// it holds the store lock that alerts and the transport also take, and a
/// thread starved of I/O while holding it would delay them).
fn lower_priority() {
    #[cfg(all(windows, feature = "win-platform"))]
    {
        kestrel_win::lower_current_thread_priority(kestrel_win::Background::Light);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{FileOp, NetProto, ProcessGuid, ProcessStart, TargetProcess};

    fn ev(ts: i64, pid: u32, data: EventData) -> Event {
        Event {
            ts,
            pid,
            guid: ProcessGuid(format!("g{pid}")),
            data,
        }
    }
    fn access(ts: i64, pid: u32, target: u32, mask: u32) -> Event {
        ev(
            ts,
            pid,
            EventData::ProcessAccess(TargetProcess {
                target_pid: target,
                target_guid: None,
                target_image: r"C:\Windows\explorer.exe".into(),
                granted_access: mask,
                return_code: 0,
            }),
        )
    }
    fn cfg() -> UploadConfig {
        UploadConfig {
            max_events: 500,
            max_delay_ms: 5_000,
            window_ms: 60_000,
            max_keys: 64,
        }
    }
    fn rows(batches: &[Batch]) -> usize {
        batches.iter().map(|b| b.events.len()).sum()
    }

    #[test]
    fn identical_events_become_one_row_plus_a_counted_summary() {
        let mut u = Uploader::new(cfg());
        let mut out = vec![];
        for i in 0..10_000i64 {
            out.extend(u.push(access(1_000 + i, 4242, 1000, 0x40), i / 10));
        }
        // Window still open: only the first one so far.
        out.extend(u.tick(5_999));
        assert_eq!(rows(&out), 1);
        out.extend(u.tick(60_000));
        out.extend(u.tick(65_000));
        assert_eq!(rows(&out), 2);
        let all: Vec<&Batch> = out.iter().collect();
        let summary_batch = all.iter().find(|b| !b.repeats.is_empty()).unwrap();
        let r = summary_batch.repeats[0];
        assert_eq!(r.count, 9_999);
        assert_eq!(r.first_ts, 1_001);
        assert_eq!(summary_batch.events[r.index as usize].ts, 1_000 + 9_999);
        assert_eq!(u.stats.suppressed, 9_999);
        assert_eq!(u.stats.summaries, 1);
        // Nothing is lost: first row + count.
        assert_eq!(1 + r.count as u64, u.stats.events_in);
    }

    #[test]
    fn different_targets_kinds_and_high_value_kinds_are_never_merged() {
        let mut u = Uploader::new(cfg());
        let mut out = vec![];
        out.extend(u.push(access(1, 1, 10, 0x40), 0));
        out.extend(u.push(access(2, 1, 11, 0x40), 0)); // other target
        out.extend(u.push(access(3, 1, 10, 0x1410), 0)); // other mask
        out.extend(u.push(access(4, 2, 10, 0x40), 0)); // other actor
        for i in 0..3 {
            let start = ev(
                10 + i,
                9,
                EventData::ProcessStart(ProcessStart {
                    image: r"C:\x.exe".into(),
                    ..Default::default()
                }),
            );
            out.extend(u.push(start, 1));
            out.extend(u.push(ev(20 + i, 9, EventData::ProcessStop { exit_code: None }), 1));
        }
        out.extend(u.finish(2));
        assert_eq!(rows(&out), 4 + 6);
        assert!(out.iter().all(|b| b.repeats.is_empty()));
    }

    #[test]
    fn dpapi_file_and_net_are_merged_per_target() {
        let mut u = Uploader::new(cfg());
        let mut out = vec![];
        for i in 0..100 {
            out.extend(u.push(
                ev(
                    i,
                    7,
                    EventData::DpapiUnprotect {
                        description: String::new(),
                    },
                ),
                i,
            ));
            out.extend(u.push(
                ev(
                    i,
                    7,
                    EventData::FileAccess {
                        path: r"C:\Users\a\.docker\config.json".into(),
                        op: FileOp::Open,
                    },
                ),
                i,
            ));
            out.extend(u.push(
                ev(
                    i,
                    7,
                    EventData::NetConnect {
                        proto: NetProto::Tcp,
                        dst_ip: "192.0.2.1".into(),
                        dst_port: 443,
                        src_port: 50_000 + i as u16,
                        dst_host: None,
                        bytes_sent: Some(i as u64 * 10),
                    },
                ),
                i,
            ));
        }
        out.extend(u.finish(200));
        assert_eq!(rows(&out), 6, "3 first rows + 3 summaries");
        let b: Vec<&Event> = out.iter().flat_map(|b| b.events.iter()).collect();
        let net = b
            .iter()
            .rev()
            .find(|e| matches!(e.data, EventData::NetConnect { .. }))
            .unwrap();
        // The summary keeps the largest byte count.
        assert!(matches!(
            net.data,
            EventData::NetConnect {
                bytes_sent: Some(990),
                ..
            }
        ));
        let counts: Vec<u32> = out
            .iter()
            .flat_map(|b| b.repeats.iter().map(|r| r.count))
            .collect();
        assert_eq!(counts, vec![99, 99, 99]);
    }

    /// Review 2026-10-25 M4: same address, different host names / answers /
    /// signatures are different things.
    #[test]
    fn host_answers_and_signature_are_part_of_the_identity() {
        let net = |host: &str| {
            ev(
                1,
                5,
                EventData::NetConnect {
                    proto: NetProto::Tcp,
                    dst_ip: "203.0.113.9".into(),
                    dst_port: 443,
                    src_port: 1,
                    dst_host: Some(host.into()),
                    bytes_sent: None,
                },
            )
        };
        assert_ne!(
            dedupe_key(&net("cdn.example")),
            dedupe_key(&net("c2.example"))
        );
        assert_eq!(
            dedupe_key(&net("cdn.example")),
            dedupe_key(&net("CDN.example"))
        );
        let dns = |a: &[&str]| {
            ev(
                1,
                5,
                EventData::DnsQuery {
                    qname: "x.example".into(),
                    answers: a.iter().map(|s| s.to_string()).collect(),
                },
            )
        };
        assert_ne!(
            dedupe_key(&dns(&["192.0.2.1"])),
            dedupe_key(&dns(&["192.0.2.2"]))
        );
        assert_eq!(
            dedupe_key(&dns(&["192.0.2.1", "192.0.2.2"])),
            dedupe_key(&dns(&["192.0.2.2", "192.0.2.1"]))
        );
        let img = |signed| {
            ev(
                1,
                5,
                EventData::ImageLoad {
                    path: r"C:\Users\a\x.dll".into(),
                    signer: None,
                    signed,
                },
            )
        };
        assert_ne!(
            dedupe_key(&img(kestrel_common::SignatureState::Valid)),
            dedupe_key(&img(kestrel_common::SignatureState::Unsigned))
        );
    }

    #[test]
    fn batches_seal_on_size_and_on_delay() {
        let mut u = Uploader::new(UploadConfig {
            window_ms: 0,
            ..cfg()
        });
        let mut out = vec![];
        for i in 0..1_200 {
            out.extend(u.push(access(i, 1, 2, 0x40), 0));
        }
        assert_eq!(out.len(), 2);
        assert!(out.iter().all(|b| b.events.len() == 500));
        assert!(u.tick(4_999).is_empty());
        let late = u.tick(5_000);
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].events.len(), 200);
        assert!(u.tick(20_000).is_empty());
    }

    #[test]
    fn open_windows_are_bounded() {
        let mut u = Uploader::new(cfg());
        let mut out = vec![];
        for t in 0..1_000u32 {
            out.extend(u.push(access(1, 1, t, 0x40), 0));
            out.extend(u.push(access(2, 1, t, 0x40), 0));
            assert!(u.open_windows() <= 64);
        }
        out.extend(u.finish(1));
        // Every target: its first row and, once its window was closed
        // early by the bound, its summary.
        assert_eq!(rows(&out), 2_000);
        assert_eq!(u.stats.events_in, 2_000);
    }

    #[test]
    fn repeat_index_points_into_its_own_batch() {
        let mut u = Uploader::new(UploadConfig {
            max_events: 3,
            ..cfg()
        });
        let mut out = vec![];
        for t in 0..5 {
            out.extend(u.push(access(1, 1, t, 0x40), 0));
            out.extend(u.push(access(2, 1, t, 0x40), 0));
        }
        out.extend(u.finish(1));
        for b in &out {
            for r in &b.repeats {
                assert!((r.index as usize) < b.events.len());
            }
        }
        assert_eq!(out.iter().map(|b| b.repeats.len()).sum::<usize>(), 5);
    }

    /// Network budget: serialized (JSON + zstd, as stored in the outbox and
    /// sent) bytes per uploaded event, before (2 s / 500 batches, no
    /// de-duplication) and after (this module), for the bundled replays and,
    /// when `KESTREL_UPLOAD_SAMPLE` names a JSONL file of events, for that
    /// sample. Prints a table; asserts the after path never costs more.
    #[test]
    fn upload_budget_report() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("replays");
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
            .collect();
        files.sort();
        if let Ok(p) = std::env::var("KESTREL_UPLOAD_SAMPLE") {
            files.push(p.into());
        }
        for f in files {
            let events = crate::sim::load_replay(&f).unwrap();
            let r = budget(&events);
            eprintln!(
                "UPLOAD_BUDGET {}: events {} | before rows {} bytes {} ({:.1} B/event) | after rows {} bytes {} ({:.1} B/event) | span {:.1} min",
                f.file_name().unwrap().to_string_lossy(),
                events.len(),
                r.before_rows,
                r.before_bytes,
                r.before_bytes as f64 / events.len().max(1) as f64,
                r.after_rows,
                r.after_bytes,
                r.after_bytes as f64 / events.len().max(1) as f64,
                r.span_min,
            );
            assert!(r.after_rows <= r.before_rows);
        }
    }

    struct Budget {
        before_rows: usize,
        before_bytes: usize,
        after_rows: usize,
        after_bytes: usize,
        span_min: f64,
    }

    fn encoded(b: Batch) -> usize {
        crate::codec::encode(&b.into_payload(), true)
            .unwrap()
            .0
            .len()
    }

    /// Event timestamps stand in for arrival times.
    fn budget(events: &[Event]) -> Budget {
        let mut sorted = events.to_vec();
        sorted.sort_by_key(|e| e.ts);
        // Before: no de-duplication, 2 s / 500.
        let mut old = Uploader::new(UploadConfig {
            max_events: 500,
            max_delay_ms: 2_000,
            window_ms: 0,
            max_keys: 1,
        });
        let mut new = Uploader::new(UploadConfig::default());
        let (mut ob, mut nb) = (vec![], vec![]);
        for e in &sorted {
            ob.extend(old.tick(e.ts));
            ob.extend(old.push(e.clone(), e.ts));
            nb.extend(new.tick(e.ts));
            nb.extend(new.push(e.clone(), e.ts));
        }
        let end = sorted.last().map_or(0, |e| e.ts);
        ob.extend(old.finish(end));
        nb.extend(new.finish(end));
        let span = sorted.first().map_or(0, |e| end - e.ts);
        Budget {
            before_rows: rows(&ob),
            before_bytes: ob.into_iter().map(encoded).sum(),
            after_rows: rows(&nb),
            after_bytes: nb.into_iter().map(encoded).sum(),
            span_min: span as f64 / 60_000.0,
        }
    }
}
