//! Evidence capture for suspected data theft (owner decision 2026-10-25,
//! `docs/DECISIONS.md`; contracts in `kestrel_common::evidence`).
//!
//! **Detection thread** ([`EvidenceTracker`], owned by the detection loop):
//! every engine event and every sensor [`WriteHint`] feed a bounded
//! [`EvidenceJournal`]. An ST-02 / ST-04 alert (any mode, protection turned
//! off included) starts a capture for the alerting process tree, or joins a
//! capture of the same tree started within `MERGE_MS`. At `alert.ts +
//! Tuning::evidence_follow` (checked on engine ticks) the tree is recomputed
//! (descendants started meanwhile join), the journal is snapshotted for
//! `[alert.ts - LOOKBACK_MS, now]` and the capture is finished.
//!
//! **Runtime** ([`EvidenceManager`], `Core::evidence`): reports
//! `Capturing`, runs the packet capture (one Kestrel capture at a time; a
//! second concurrent bundle records `Busy`), stops it at the finish, builds
//! and seals the bundle on a blocking thread (one build at a time, see
//! [`crate::evidence_bundle`]) and reports `Ready` with the privacy-filtered
//! manifest, or `Failed`. A small index of bundles lives in the store
//! (`KV_EVIDENCE_INDEX`).
//!
//! **Commands** (`Core::execute_action_as`, server commands only):
//! `CollectEvidence` marks a `Ready` bundle authorized for upload for 24 h,
//! tells the employee in the tray and answers `ok` with
//! `artifact = bundle id`; `DeleteEvidence` deletes it and reports
//! `Deleted`.
//!
//! **Upload** (`LiveServerMsg::EvidenceRead`, routed by the transport before
//! the remote-access live manager, so it is not subject to the remote-access
//! profile): one sequential reader per live session, chunks of at most
//! `READ_CHUNK_MAX` bytes of the container plaintext, the `eof` reply
//! carrying the SHA-256 of every byte served (equal to `bundle_sha256`).
//! Sessions end on eof, error, idle (`Tuning::evidence_read_idle`), stream
//! loss and agent shutdown.
//!
//! **Housekeeping**: bundles nobody collected are deleted after
//! `policy.evidence.retention_days()` (`Expired`). At start: partial files
//! and plaintext capture files are deleted, captures that were running are
//! reported `Failed` ("the agent restarted during the capture") and the
//! platform cleans up a packet capture a crashed agent left behind. At
//! shutdown (bounded to ~8 s): running packet captures are stopped and their
//! files deleted, unfinished captures are reported `Failed` ("the agent
//! stopped during the capture"); building a bundle is not attempted.
//!
//! Never logs file contents; file names at most.

use base64::Engine as _;
use kestrel_common::{
    evidence::{
        is_trigger_rule, EvidencePolicy, EvidenceProcess, EvidenceReport, EvidenceState,
        PcapFilter, PcapInfo, PcapStatus, ProcessRole, LOOKBACK_MS, MERGE_MS, PCAP_MAX_BYTES,
        READ_CHUNK_MAX, TRAY_COLLECTED_BODY, TRAY_COLLECTED_TITLE,
    },
    remote::{FileReply, LiveAgentMsg, RemoteErrorCode},
    tray::ActivityItem,
    wire::AgentPayload,
    Alert, Event, ProcessGuid, ProcessInfo, Severity,
};
use kestrel_detect::evidence::{tree_members, EvidenceJournal, JournalSnapshot};
use kestrel_detect::{Output, ProcessTable};
use kestrel_platform::{CaptureSession, CaptureStartError, EvidenceHost, WriteHint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::agent::Core;
use crate::evidence_bundle::{self, BundleInput, Limits, BUNDLE_EXT, PARTIAL_EXT};

/// Store key of the bundle index (JSON list of [`IndexEntry`]).
pub const KV_EVIDENCE_INDEX: &str = "evidence_index";
/// Index entries kept (oldest finished / failed / deleted ones go first).
pub const INDEX_MAX: usize = 256;
/// Uncollected bundles (ready or capturing) kept on the PC; past this new
/// captures are refused (an attacker triggering alerts must not be able to
/// flush older evidence or fill the disk).
pub const MAX_LOCAL_BUNDLES: usize = 32;
/// Uncollected bundles per program (same image SHA-256, else same image
/// path): one noisy program cannot take every slot. Residual: an attacker
/// with 16+ distinct binaries can still fill the global slots.
pub const MAX_BUNDLES_PER_PROGRAM: usize = 2;
/// Total size of uncollected bundles kept on the PC.
pub const MAX_UNCOLLECTED_BYTES: u64 = 2 << 30;
/// A collected bundle may be uploaded for this long.
pub const AUTHORIZED_FOR_MS: i64 = 24 * 3600 * 1000;
/// Queued reads per upload session before `Busy`.
const READ_QUEUE: usize = 16;
/// Shutdown never waits longer than this for packet captures to stop.
const SHUTDOWN_BUDGET: Duration = Duration::from_secs(8);
/// Journal eviction period (detection thread).
const EVICT_EVERY_MS: i64 = 10_000;
const DAY_MS: i64 = 86_400_000;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// `<evidence_dir>/bundles`.
pub fn bundles_dir(host: &dyn EvidenceHost) -> PathBuf {
    host.evidence_dir().join("bundles")
}

/// `<evidence_dir>/work` (packet-capture work folders, plaintext).
pub fn work_root(host: &dyn EvidenceHost) -> PathBuf {
    host.evidence_dir().join("work")
}

/// One bundle in the local index.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct IndexEntry {
    pub bundle_id: Uuid,
    pub alert_id: Uuid,
    #[serde(default)]
    pub alert_ids: Vec<Uuid>,
    pub rule_id: String,
    pub state: EvidenceState,
    pub created_at: i64,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: Option<String>,
    /// Deleted locally at this time when nobody collected it.
    #[serde(default)]
    pub expires_at: Option<i64>,
    /// `CollectEvidence` received: uploads allowed until then.
    #[serde(default)]
    pub authorized_until: Option<i64>,
    /// Tray audience of the alert (lower-case user), `None` = machine-wide.
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub detail: String,
    /// Program of the alerting process (`sha256:<hex>` or `path:<lower
    /// image>`), for the per-program cap.
    #[serde(default)]
    pub program: Option<String>,
}

/// Per-program key of an alerting process.
pub fn program_key(p: &ProcessInfo) -> Option<String> {
    if let Some(h) = p.sha256.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
        return Some(format!("sha256:{}", h.to_ascii_lowercase()));
    }
    let img = p.image.trim();
    (!img.is_empty()).then(|| format!("path:{}", img.replace('/', "\\").to_lowercase()))
}

impl IndexEntry {
    fn terminal(&self) -> bool {
        matches!(
            self.state,
            EvidenceState::Failed | EvidenceState::Deleted | EvidenceState::Expired
        )
    }
}

// ================================================================ detection

/// A capture started on the detection thread, waiting for its follow-up.
struct Active {
    bundle_id: Uuid,
    alert_ts: i64,
    finish_at: i64,
    root: ProcessGuid,
    members: Vec<(ProcessInfo, ProcessRole)>,
    pinned: Vec<ProcessGuid>,
}

/// A finished capture (alerts for its tree within `MERGE_MS` join it).
struct Recent {
    bundle_id: Uuid,
    alert_ts: i64,
    guids: Vec<ProcessGuid>,
}

/// Detection-thread half: journal, triggers and follow-up timers.
pub struct EvidenceTracker {
    enabled: bool,
    journal: EvidenceJournal,
    active: Vec<Active>,
    recent: Vec<Recent>,
    last_evict: i64,
    follow_ms: i64,
    rt: Handle,
}

impl EvidenceTracker {
    pub fn new(core: &Core, rt: Handle) -> Self {
        EvidenceTracker {
            enabled: core.platform.evidence().is_some(),
            journal: EvidenceJournal::new(),
            active: Vec::new(),
            recent: Vec::new(),
            last_evict: 0,
            follow_ms: core.tuning.evidence_follow.as_millis() as i64,
            rt,
        }
    }

    /// Feed one engine event (before the engine sees it).
    pub fn observe(&mut self, e: &Event) {
        if self.enabled {
            self.journal.observe(e);
        }
    }

    /// Feed one sensor write hint (never an event, never uploaded).
    pub fn observe_write(&mut self, h: &WriteHint) {
        if self.enabled {
            self.journal
                .observe_sensor_write(h.ts, &h.guid, &h.path, h.op);
        }
    }

    /// Look at the engine's outputs for trigger alerts.
    pub fn on_outputs(&mut self, core: &Arc<Core>, table: &ProcessTable, outs: &[Output]) {
        if !self.enabled {
            return;
        }
        for o in outs {
            if let Output::Alert(d) = o {
                if is_trigger_rule(&d.alert.rule_id) {
                    self.trigger(core, table, &d.alert);
                }
            }
        }
    }

    fn trigger(&mut self, core: &Arc<Core>, table: &ProcessTable, alert: &Alert) {
        let policy = core.policy().evidence;
        if !policy.any() {
            return;
        }
        let guid = &alert.process.guid;
        if let Some(a) = self
            .active
            .iter()
            .find(|a| a.pinned.contains(guid) && (alert.ts - a.alert_ts).abs() <= MERGE_MS)
        {
            core.evidence.merge(core, a.bundle_id, alert.id);
            return;
        }
        if let Some(r) = self
            .recent
            .iter()
            .find(|r| r.guids.contains(guid) && (alert.ts - r.alert_ts).abs() <= MERGE_MS)
        {
            core.evidence.merge(core, r.bundle_id, alert.id);
            return;
        }
        let mut members = tree_members(table, guid);
        if members.is_empty() {
            members.push((alert.process.clone(), ProcessRole::Alerting));
        }
        let pinned: Vec<ProcessGuid> = members.iter().map(|(p, _)| p.guid.clone()).collect();
        self.journal.pin(&pinned);
        let now = kestrel_common::now_ms();
        let snap = self
            .journal
            .snapshot(&members, alert.ts - LOOKBACK_MS, now.max(alert.ts));
        let bundle_id = Uuid::new_v4();
        tracing::warn!(
            %bundle_id,
            rule = %alert.rule_id,
            processes = members.len(),
            "evidence capture started for the alerting process tree"
        );
        core.evidence.start(
            core,
            &self.rt,
            StartReq {
                bundle_id,
                alert_id: alert.id,
                rule_id: alert.rule_id.clone(),
                alert_ts: alert.ts,
                owner: crate::detection::activity_owner(alert),
                user: alert.process.user.clone(),
                program: program_key(&alert.process),
                policy,
                filters: snap.net,
            },
        );
        self.active.push(Active {
            bundle_id,
            alert_ts: alert.ts,
            finish_at: alert.ts + self.follow_ms,
            root: guid.clone(),
            members,
            pinned,
        });
    }

    /// Engine tick: finish captures whose follow-up ended, evict the journal.
    pub fn tick(&mut self, core: &Arc<Core>, table: &ProcessTable, now: i64) {
        if !self.enabled {
            return;
        }
        let (due, keep): (Vec<Active>, Vec<Active>) = std::mem::take(&mut self.active)
            .into_iter()
            .partition(|a| a.finish_at <= now);
        self.active = keep;
        for a in due {
            // Recompute: descendants started during the follow-up join.
            let mut members = tree_members(table, &a.root);
            for (p, r) in a.members {
                if !members.iter().any(|(m, _)| m.guid == p.guid) {
                    members.push((p, r));
                }
            }
            members.truncate(kestrel_common::evidence::MAX_TREE_PROCESSES);
            let window_start = a.alert_ts - LOOKBACK_MS;
            let snapshot = self.journal.snapshot(&members, window_start, now);
            self.journal.unpin(&a.pinned);
            let processes = members
                .iter()
                .map(|(p, r)| EvidenceProcess {
                    guid: p.guid.clone(),
                    pid: p.pid,
                    image: p.image.clone(),
                    start_ts: p.start_ts,
                    role: *r,
                })
                .collect();
            self.recent.push(Recent {
                bundle_id: a.bundle_id,
                alert_ts: a.alert_ts,
                guids: members.iter().map(|(p, _)| p.guid.clone()).collect(),
            });
            let core2 = core.clone();
            let req = FinishReq {
                bundle_id: a.bundle_id,
                processes,
                snapshot,
                window_start,
                window_end: now,
            };
            self.rt.spawn(async move { finish(core2, req).await });
        }
        self.recent.retain(|r| now - r.alert_ts <= MERGE_MS);
        if now - self.last_evict >= EVICT_EVERY_MS {
            self.last_evict = now;
            self.journal.evict(now);
        }
    }

    /// Captures waiting for their follow-up (tests).
    pub fn active_captures(&self) -> usize {
        self.active.len()
    }
}

// ================================================================== manager

/// Start of a capture (from the detection thread).
#[derive(Debug, Clone)]
pub struct StartReq {
    pub bundle_id: Uuid,
    pub alert_id: Uuid,
    pub rule_id: String,
    pub alert_ts: i64,
    pub owner: Option<String>,
    /// User of the alerting process (`DOMAIN\name`): only that user's
    /// profile is collected.
    pub user: Option<String>,
    /// [`program_key`] of the alerting process.
    pub program: Option<String>,
    pub policy: EvidencePolicy,
    /// Remote tuples of the tree so far.
    pub filters: Vec<PcapFilter>,
}

/// End of the follow-up (from the detection thread).
#[derive(Debug)]
pub struct FinishReq {
    pub bundle_id: Uuid,
    pub processes: Vec<EvidenceProcess>,
    pub snapshot: JournalSnapshot,
    pub window_start: i64,
    pub window_end: i64,
}

struct PcapStarted {
    session: Option<Box<dyn CaptureSession>>,
    status: PcapStatus,
    detail: String,
    started_at: Option<i64>,
}

struct Capture {
    alert_id: Uuid,
    alert_ids: Vec<Uuid>,
    rule_id: String,
    started_at: i64,
    policy: EvidencePolicy,
    user: Option<String>,
    pcap: Option<PcapInfo>,
    pcap_task: Option<JoinHandle<PcapStarted>>,
    /// Deleted by an administrator while capturing: discard the result.
    cancelled: bool,
    /// The finish is running (shutdown leaves it alone).
    finishing: bool,
}

#[derive(Default)]
struct MgrState {
    caps: HashMap<Uuid, Capture>,
    /// Ready reports of the last `MERGE_MS` (late merges re-send them).
    ready: HashMap<Uuid, (EvidenceReport, i64)>,
    /// The capture currently owning the packet capture.
    pcap_owner: Option<Uuid>,
}

struct ReadReq {
    request_id: u64,
    offset: u64,
    len: u32,
}

struct ReadWorker {
    wid: u64,
    bundle_id: Uuid,
    tx: mpsc::Sender<ReadReq>,
    cancel: CancellationToken,
}

/// Runtime half (lives in `Core::evidence`).
pub struct EvidenceManager {
    st: Mutex<MgrState>,
    /// Serialises index read-modify-write.
    index_lock: Mutex<()>,
    /// One bundle build at a time.
    build: tokio::sync::Semaphore,
    reads: Mutex<HashMap<Uuid, ReadWorker>>,
    wid: AtomicU64,
    /// Byte budgets of a bundle (tests shrink them).
    limits: Mutex<Limits>,
}

impl Default for EvidenceManager {
    fn default() -> Self {
        EvidenceManager {
            st: Mutex::default(),
            index_lock: Mutex::new(()),
            build: tokio::sync::Semaphore::new(1),
            reads: Mutex::default(),
            wid: AtomicU64::new(0),
            limits: Mutex::new(Limits::default()),
        }
    }
}

/// Why a new capture is refused given the index (local caps, M2).
pub fn capture_refusal(index: &[IndexEntry], program: Option<&str>) -> Option<String> {
    let live: Vec<&IndexEntry> = index
        .iter()
        .filter(|e| matches!(e.state, EvidenceState::Ready | EvidenceState::Capturing))
        .collect();
    if live.len() >= MAX_LOCAL_BUNDLES {
        return Some(format!(
            "{MAX_LOCAL_BUNDLES} uncollected evidence bundles are already on this PC; collect or delete them first"
        ));
    }
    if let Some(p) = program {
        let same = live
            .iter()
            .filter(|e| e.program.as_deref() == Some(p))
            .count();
        if same >= MAX_BUNDLES_PER_PROGRAM {
            return Some(format!(
                "{MAX_BUNDLES_PER_PROGRAM} uncollected evidence bundles of this program are already on this PC; collect or delete them first"
            ));
        }
    }
    let bytes: u64 = live.iter().map(|e| e.size).sum();
    if bytes >= MAX_UNCOLLECTED_BYTES {
        return Some(format!(
            "uncollected evidence bundles on this PC already take {} MB (limit {} MB); collect or delete them first",
            bytes >> 20,
            MAX_UNCOLLECTED_BYTES >> 20
        ));
    }
    None
}

fn report_of(e: &IndexEntry, state: EvidenceState, detail: &str) -> EvidenceReport {
    EvidenceReport {
        bundle_id: e.bundle_id,
        alert_id: e.alert_id,
        alert_ids: e.alert_ids.clone(),
        rule_id: e.rule_id.clone(),
        state,
        ts: kestrel_common::now_ms(),
        manifest: None,
        bundle_size: 0,
        bundle_sha256: None,
        local_expires_at: None,
        detail: detail.to_string(),
    }
}

fn enqueue_report(core: &Core, r: EvidenceReport) {
    tracing::info!(bundle_id = %r.bundle_id, state = ?r.state, "evidence report queued");
    core.enqueue(&AgentPayload::Evidence(Box::new(r)));
}

fn file_exists(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.is_file())
}

impl EvidenceManager {
    /// Replace the bundle byte budgets (tests).
    pub fn set_limits(&self, l: Limits) {
        *lock(&self.limits) = l;
    }

    // ------------------------------------------------------------- index

    pub fn index(&self, core: &Core) -> Vec<IndexEntry> {
        core.store
            .kv_get_json::<Vec<IndexEntry>>(KV_EVIDENCE_INDEX)
            .unwrap_or_else(|e| {
                tracing::warn!("evidence index unreadable ({e}); starting empty");
                None
            })
            .unwrap_or_default()
    }

    pub fn entry(&self, core: &Core, id: Uuid) -> Option<IndexEntry> {
        self.index(core).into_iter().find(|e| e.bundle_id == id)
    }

    /// Read-modify-write the index (bounded to [`INDEX_MAX`]: the oldest
    /// terminal entries are dropped first).
    fn update_index<T>(&self, core: &Core, f: impl FnOnce(&mut Vec<IndexEntry>) -> T) -> T {
        let _g = lock(&self.index_lock);
        let mut v = self.index(core);
        let out = f(&mut v);
        if v.len() > INDEX_MAX {
            let mut terminal: Vec<(i64, Uuid)> = v
                .iter()
                .filter(|e| e.terminal())
                .map(|e| (e.created_at, e.bundle_id))
                .collect();
            terminal.sort();
            let excess = v.len() - INDEX_MAX;
            let drop: Vec<Uuid> = terminal.into_iter().take(excess).map(|x| x.1).collect();
            v.retain(|e| !drop.contains(&e.bundle_id));
        }
        if let Err(e) = core.store.kv_set_json(KV_EVIDENCE_INDEX, &v) {
            tracing::error!("evidence index write failed: {e:#}");
        }
        out
    }

    fn update_entry(
        &self,
        core: &Core,
        id: Uuid,
        f: impl FnOnce(&mut IndexEntry),
    ) -> Option<IndexEntry> {
        self.update_index(core, |v| {
            v.iter_mut().find(|e| e.bundle_id == id).map(|e| {
                f(e);
                e.clone()
            })
        })
    }

    // ------------------------------------------------------------- start

    /// Register a capture, report `Capturing` and start the packet capture
    /// (non-blocking; runs on the detection thread).
    pub fn start(&self, core: &Arc<Core>, rt: &Handle, req: StartReq) {
        let Some(host) = core.platform.evidence() else {
            return;
        };
        let now = kestrel_common::now_ms();
        let entry = IndexEntry {
            bundle_id: req.bundle_id,
            alert_id: req.alert_id,
            alert_ids: vec![req.alert_id],
            rule_id: req.rule_id.clone(),
            state: EvidenceState::Capturing,
            created_at: now,
            size: 0,
            sha256: None,
            expires_at: None,
            authorized_until: None,
            owner: req.owner.clone(),
            detail: String::new(),
            program: req.program.clone(),
        };
        let refusal = self.update_index(core, |v| {
            let refusal = capture_refusal(v, req.program.as_deref());
            let mut e = entry.clone();
            if let Some(why) = &refusal {
                e.state = EvidenceState::Failed;
                e.detail = why.clone();
            }
            v.push(e);
            refusal
        });
        if let Some(why) = refusal {
            tracing::warn!(bundle_id = %req.bundle_id, "evidence capture refused: {why}");
            enqueue_report(core, report_of(&entry, EvidenceState::Failed, &why));
            return;
        }
        enqueue_report(core, report_of(&entry, EvidenceState::Capturing, ""));

        let filters: Vec<PcapFilter> = {
            let server = core.server_ips();
            req.filters
                .into_iter()
                .filter(|f| !server.iter().any(|s| s.trim() == f.ip))
                .collect()
        };
        let mut st = lock(&self.st);
        let mut pcap_task = None;
        let pcap = if !req.policy.pcap {
            Some(PcapInfo {
                status: PcapStatus::Disabled,
                ..Default::default()
            })
        } else {
            let mut info = PcapInfo {
                filters: filters.clone(),
                ..Default::default()
            };
            match host.packet_capture() {
                None => {
                    info.status = PcapStatus::Unsupported;
                    info.detail = "packet capture is not available on this platform".into();
                }
                Some(pc) => {
                    info.mechanism = pc.mechanism().to_string();
                    if filters.is_empty() {
                        info.status = PcapStatus::NoConnections;
                        info.detail = "the process tree made no connections Kestrel saw".into();
                    } else if st.pcap_owner.is_some() {
                        info.status = PcapStatus::Busy;
                        info.detail = "another Kestrel capture is running".into();
                    } else {
                        st.pcap_owner = Some(req.bundle_id);
                        info.status = PcapStatus::Captured;
                        let work = work_root(&*host).join(req.bundle_id.to_string());
                        pcap_task = Some(rt.spawn_blocking(move || {
                            if let Err(e) = std::fs::create_dir_all(&work) {
                                return PcapStarted {
                                    session: None,
                                    status: PcapStatus::Failed,
                                    detail: format!("work folder: {}", e.kind()),
                                    started_at: None,
                                };
                            }
                            let started = kestrel_common::now_ms();
                            match pc.start(&filters, &work, PCAP_MAX_BYTES) {
                                Ok(s) => PcapStarted {
                                    session: Some(s),
                                    status: PcapStatus::Captured,
                                    detail: String::new(),
                                    started_at: Some(started),
                                },
                                Err(e) => {
                                    let (status, d) = match e {
                                        CaptureStartError::Busy(d) => (PcapStatus::Busy, d),
                                        CaptureStartError::Unsupported(d) => {
                                            (PcapStatus::Unsupported, d)
                                        }
                                        CaptureStartError::Failed(d) => (PcapStatus::Failed, d),
                                    };
                                    PcapStarted {
                                        session: None,
                                        status,
                                        detail: d.chars().take(200).collect(),
                                        started_at: None,
                                    }
                                }
                            }
                        }));
                    }
                }
            }
            Some(info)
        };
        st.caps.insert(
            req.bundle_id,
            Capture {
                alert_id: req.alert_id,
                alert_ids: vec![req.alert_id],
                rule_id: req.rule_id,
                started_at: req.alert_ts,
                policy: req.policy,
                user: req.user,
                pcap,
                pcap_task,
                cancelled: false,
                finishing: false,
            },
        );
    }

    /// A further trigger alert for a tree already captured (non-blocking).
    pub fn merge(&self, core: &Core, bundle_id: Uuid, alert_id: Uuid) {
        let resend = {
            let mut st = lock(&self.st);
            if let Some(c) = st.caps.get_mut(&bundle_id) {
                if !c.alert_ids.contains(&alert_id) {
                    c.alert_ids.push(alert_id);
                }
                None
            } else if let Some((r, _)) = st.ready.get_mut(&bundle_id) {
                if r.alert_ids.contains(&alert_id) {
                    return;
                }
                r.alert_ids.push(alert_id);
                r.ts = kestrel_common::now_ms();
                Some(r.clone())
            } else {
                return;
            }
        };
        tracing::info!(%bundle_id, %alert_id, "alert joined a running evidence capture");
        self.update_entry(core, bundle_id, |e| {
            if !e.alert_ids.contains(&alert_id) {
                e.alert_ids.push(alert_id);
            }
        });
        if let Some(r) = resend {
            enqueue_report(core, r);
        }
    }

    // ---------------------------------------------------------- commands

    /// `CollectEvidence` (server command only; the caller checks the origin).
    pub fn collect(&self, core: &Core, bundle_id: Uuid) -> (bool, String) {
        let now = kestrel_common::now_ms();
        let Some(host) = core.platform.evidence() else {
            return (false, "evidence capture is not supported on this PC".into());
        };
        let Some(e) = self.entry(core, bundle_id) else {
            return (false, "no such evidence bundle on this PC".into());
        };
        match e.state {
            EvidenceState::Ready => {}
            EvidenceState::Capturing => {
                return (
                    false,
                    "the capture is still running; try again in a minute".into(),
                )
            }
            EvidenceState::Failed => {
                return (false, format!("the capture failed: {}", e.detail));
            }
            EvidenceState::Deleted | EvidenceState::Expired => {
                return (false, "the bundle was already deleted from this PC".into());
            }
        }
        if e.expires_at.is_some_and(|x| x <= now) {
            return (false, "the bundle expired on this PC".into());
        }
        let path = evidence_bundle::bundle_path(&bundles_dir(&*host), bundle_id);
        if !file_exists(&path) {
            return (false, "the bundle file is missing on this PC".into());
        }
        let e = self
            .update_entry(core, bundle_id, |e| {
                e.authorized_until = Some(now + AUTHORIZED_FOR_MS);
            })
            .unwrap_or(e);
        core.notify_tray(
            ActivityItem {
                id: Uuid::new_v4(),
                ts: now,
                title: TRAY_COLLECTED_TITLE.into(),
                body: TRAY_COLLECTED_BODY.into(),
                severity: Severity::Info,
                alert_id: Some(e.alert_id),
                file: None,
                action_taken: "Evidence collected by IT".into(),
                review: None,
            },
            true,
            e.owner.clone(),
        );
        tracing::warn!(%bundle_id, bytes = e.size, "evidence bundle authorized for upload");
        (true, format!("bundle ready for upload ({} bytes)", e.size))
    }

    /// `DeleteEvidence` (server command only).
    pub fn delete(&self, core: &Core, bundle_id: Uuid) -> (bool, String) {
        self.end_reads(Some(bundle_id));
        let Some(e) = self.entry(core, bundle_id) else {
            return (true, "already deleted".into());
        };
        match e.state {
            EvidenceState::Deleted | EvidenceState::Expired => {
                return (true, "already deleted".into())
            }
            EvidenceState::Failed => {
                return (true, "nothing to delete (the capture failed)".into())
            }
            EvidenceState::Capturing => {
                if let Some(c) = lock(&self.st).caps.get_mut(&bundle_id) {
                    c.cancelled = true;
                }
            }
            EvidenceState::Ready => {
                if let Some(host) = core.platform.evidence() {
                    let path = evidence_bundle::bundle_path(&bundles_dir(&*host), bundle_id);
                    match std::fs::remove_file(&path) {
                        Ok(()) => {}
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                        Err(err) => {
                            return (
                                false,
                                format!("could not delete the bundle: {}", err.kind()),
                            )
                        }
                    }
                }
            }
        }
        let was_capturing = e.state == EvidenceState::Capturing;
        lock(&self.st).ready.remove(&bundle_id);
        let e = self
            .update_entry(core, bundle_id, |e| {
                e.state = EvidenceState::Deleted;
                e.authorized_until = None;
                e.size = 0;
            })
            .unwrap_or(e);
        enqueue_report(
            core,
            report_of(&e, EvidenceState::Deleted, "deleted by an administrator"),
        );
        tracing::info!(%bundle_id, "evidence bundle deleted");
        if was_capturing {
            (true, "capture cancelled and deleted".into())
        } else {
            (true, "bundle deleted from this PC".into())
        }
    }

    // ------------------------------------------------------------- reads

    /// `LiveServerMsg::EvidenceRead` (non-blocking; replies on the live
    /// stream).
    pub fn handle_read(
        &self,
        core: &Arc<Core>,
        session_id: Uuid,
        request_id: u64,
        bundle_id: Uuid,
        offset: u64,
        len: u32,
    ) {
        let mut reads = lock(&self.reads);
        let stale = reads
            .get(&session_id)
            .is_some_and(|w| w.tx.is_closed() || w.cancel.is_cancelled());
        if stale {
            reads.remove(&session_id);
        }
        let w = reads.entry(session_id).or_insert_with(|| {
            let (tx, rx) = mpsc::channel(READ_QUEUE);
            let cancel = CancellationToken::new();
            let wid = self.wid.fetch_add(1, Ordering::Relaxed) + 1;
            tokio::spawn(read_worker(
                core.clone(),
                session_id,
                bundle_id,
                rx,
                cancel.clone(),
                wid,
            ));
            ReadWorker {
                wid,
                bundle_id,
                tx,
                cancel,
            }
        });
        let refuse = |code: RemoteErrorCode, message: &str| {
            let core = core.clone();
            let message = message.to_string();
            tokio::spawn(async move {
                core.live
                    .send_message(
                        session_id,
                        LiveAgentMsg::EvidenceData {
                            request_id,
                            reply: FileReply::Error { code, message },
                        },
                    )
                    .await;
            });
        };
        if w.bundle_id != bundle_id {
            refuse(
                RemoteErrorCode::InvalidOperation,
                "another bundle is being read in this session",
            );
            return;
        }
        match w.tx.try_send(ReadReq {
            request_id,
            offset,
            len,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                refuse(RemoteErrorCode::Busy, "too many reads in flight")
            }
            Err(mpsc::error::TrySendError::Closed(_)) => refuse(
                RemoteErrorCode::InvalidOperation,
                "the upload session ended",
            ),
        }
    }

    /// End upload sessions (all, or those of one bundle).
    pub fn end_reads(&self, bundle: Option<Uuid>) {
        let mut reads = lock(&self.reads);
        reads.retain(|_, w| {
            let hit = bundle.is_none_or(|b| b == w.bundle_id);
            if hit {
                w.cancel.cancel();
            }
            !hit
        });
    }

    /// Upload sessions open (tests).
    pub fn read_sessions(&self) -> usize {
        lock(&self.reads).len()
    }

    fn worker_done(&self, session_id: Uuid, wid: u64) {
        let mut reads = lock(&self.reads);
        if reads.get(&session_id).is_some_and(|w| w.wid == wid) {
            reads.remove(&session_id);
        }
    }

    // ------------------------------------------------------ housekeeping

    /// Delete bundles nobody collected within the retention (`Expired`).
    pub fn housekeep(&self, core: &Core) {
        let Some(host) = core.platform.evidence() else {
            return;
        };
        let now = kestrel_common::now_ms();
        lock(&self.st)
            .ready
            .retain(|_, (_, at)| now - *at <= MERGE_MS);
        let due: Vec<IndexEntry> = self
            .index(core)
            .into_iter()
            .filter(|e| e.state == EvidenceState::Ready && e.expires_at.is_some_and(|x| x <= now))
            .collect();
        for e in due {
            self.end_reads(Some(e.bundle_id));
            let path = evidence_bundle::bundle_path(&bundles_dir(&*host), e.bundle_id);
            if let Err(err) = std::fs::remove_file(&path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    tracing::warn!(bundle_id = %e.bundle_id, "expired bundle not deleted: {}", err.kind());
                    continue;
                }
            }
            let e = self
                .update_entry(core, e.bundle_id, |x| {
                    x.state = EvidenceState::Expired;
                    x.authorized_until = None;
                })
                .unwrap_or(e);
            tracing::info!(bundle_id = %e.bundle_id, "uncollected evidence bundle expired and was deleted");
            enqueue_report(
                core,
                report_of(
                    &e,
                    EvidenceState::Expired,
                    "nobody collected it within the retention period",
                ),
            );
        }
    }
}

// ================================================================== finish

async fn finish(core: Arc<Core>, req: FinishReq) {
    let mgr = &core.evidence;
    let Some(host) = core.platform.evidence() else {
        return;
    };
    let id = req.bundle_id;
    let taken = {
        let mut st = lock(&mgr.st);
        st.caps.get_mut(&id).map(|c| {
            c.finishing = true;
            (
                c.pcap_task.take(),
                c.pcap.clone(),
                c.policy.clone(),
                c.alert_id,
                c.alert_ids.clone(),
                c.rule_id.clone(),
                c.started_at,
                c.user.clone(),
            )
        })
    };
    let Some((task, mut pcap, policy, alert_id, alert_ids, rule_id, started_at, user)) = taken
    else {
        return; // refused at start, or the agent is stopping
    };

    // Stop the connection capture.
    let mut pcap_file = None;
    if let (Some(task), Some(info)) = (task, pcap.as_mut()) {
        match task.await {
            Ok(started) => {
                info.status = started.status;
                info.detail = started.detail;
                info.started_at = started.started_at;
                if let Some(sess) = started.session {
                    match tokio::task::spawn_blocking(move || sess.stop()).await {
                        Ok(Ok(f)) => {
                            info.status = PcapStatus::Captured;
                            info.truncated = f.truncated;
                            pcap_file = Some(f);
                        }
                        Ok(Err(e)) => {
                            info.status = PcapStatus::Failed;
                            info.detail = e.chars().take(200).collect();
                        }
                        Err(_) => {
                            info.status = PcapStatus::Failed;
                            info.detail = "the capture task failed".into();
                        }
                    }
                    info.ended_at = Some(kestrel_common::now_ms());
                }
            }
            Err(_) => {
                info.status = PcapStatus::Failed;
                info.detail = "the capture task failed".into();
            }
        }
    }
    {
        let mut st = lock(&mgr.st);
        if st.pcap_owner == Some(id) {
            st.pcap_owner = None;
        }
    }

    // Build (one at a time).
    let permit = mgr.build.acquire().await;
    let cancel_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let limits = *lock(&mgr.limits);
    let input = BundleInput {
        bundle_id: id,
        alert_id,
        alert_ids,
        rule_id,
        hostname: core.hostname.clone(),
        agent_version: kestrel_common::VERSION.into(),
        started_at,
        window_start: req.window_start,
        window_end: req.window_end,
        parts: policy.clone(),
        processes: req.processes,
        snapshot: req.snapshot,
        pcap,
        pcap_file,
        limits,
        tree_user: user,
        cancel: cancel_flag.clone(),
    };
    let dir = bundles_dir(&*host);
    let h2 = host.clone();
    let task =
        tokio::task::spawn_blocking(move || evidence_bundle::build_bundle(&*h2, input, &dir));
    // H2: a copy blocked by an oplock / cloud placeholder must not hold the
    // build slot forever. Past the deadline the build is cancelled (it
    // stops at its next chunk and deletes its partial file) and abandoned.
    let built = match tokio::time::timeout(core.tuning.evidence_build_deadline, task).await {
        Ok(r) => r.unwrap_or_else(|_| Err("the bundle builder failed".into())),
        Err(_) => {
            cancel_flag.store(true, std::sync::atomic::Ordering::Relaxed);
            let partial = bundles_dir(&*host).join(format!("{id}.{PARTIAL_EXT}"));
            let _ = std::fs::remove_file(partial);
            tracing::error!(bundle_id = %id, "evidence bundle build timed out; abandoned");
            Err("timed out copying files".into())
        }
    };
    drop(permit);
    // Plaintext capture work folder (the pcapng itself is already deleted).
    let _ = std::fs::remove_dir_all(work_root(&*host).join(id.to_string()));
    let cap = lock(&mgr.st).caps.remove(&id);
    let cancelled = cap.as_ref().is_some_and(|c| c.cancelled);
    let alert_ids = cap.map(|c| c.alert_ids);
    match built {
        Ok(b) if cancelled => {
            let _ = std::fs::remove_file(&b.path);
            tracing::info!(bundle_id = %id, "evidence capture finished after it was deleted; discarded");
        }
        Ok(b) => {
            let now = kestrel_common::now_ms();
            let expires = now + policy.retention_days() as i64 * DAY_MS;
            let Some(e) = mgr.update_entry(&core, id, |e| {
                e.state = EvidenceState::Ready;
                e.size = b.size;
                e.sha256 = Some(b.sha256.clone());
                e.expires_at = Some(expires);
                if let Some(a) = &alert_ids {
                    e.alert_ids = a.clone();
                }
            }) else {
                let _ = std::fs::remove_file(&b.path);
                return;
            };
            let mut manifest = b.manifest;
            manifest.alert_ids = e.alert_ids.clone();
            core.filter().scrub_evidence_manifest(&mut manifest);
            let r = EvidenceReport {
                manifest: Some(manifest),
                bundle_size: b.size,
                bundle_sha256: Some(b.sha256),
                local_expires_at: Some(expires),
                ..report_of(&e, EvidenceState::Ready, "")
            };
            tracing::warn!(bundle_id = %id, bytes = b.size, "evidence bundle ready (kept encrypted on this PC)");
            lock(&mgr.st).ready.insert(id, (r.clone(), now));
            enqueue_report(&core, r);
        }
        Err(detail) => {
            tracing::error!(bundle_id = %id, "evidence bundle failed: {detail}");
            if let Some(e) = mgr.update_entry(&core, id, |e| {
                e.state = EvidenceState::Failed;
                e.detail = detail.clone();
            }) {
                if !cancelled {
                    enqueue_report(&core, report_of(&e, EvidenceState::Failed, &detail));
                }
            }
        }
    }
}

// =================================================================== reads

struct ReadState {
    reader: kestrel_common::seal::SealReader<std::io::BufReader<std::fs::File>>,
    served: u64,
    hasher: Sha256,
    size: u64,
    sha256: String,
}

type ReadErr = (RemoteErrorCode, String);
/// One chunk: (data, eof, SHA-256 of the whole upload on eof).
type ChunkResult = Result<(Vec<u8>, bool, Option<String>), ReadErr>;

fn read_error(e: &std::io::Error) -> ReadErr {
    match e.kind() {
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::UnexpectedEof => (
            RemoteErrorCode::IntegrityError,
            "the evidence bundle failed authentication on this PC".into(),
        ),
        k => (
            RemoteErrorCode::Io,
            format!("reading the bundle failed: {k}"),
        ),
    }
}

/// Open the upload of `bundle_id` (first read).
async fn open_read(core: &Core, bundle_id: Uuid) -> Result<Box<ReadState>, ReadErr> {
    let now = kestrel_common::now_ms();
    let Some(host) = core.platform.evidence() else {
        return Err((
            RemoteErrorCode::NotFound,
            "evidence is not supported here".into(),
        ));
    };
    let e = core
        .evidence
        .entry(core, bundle_id)
        .filter(|e| e.state == EvidenceState::Ready)
        .ok_or((
            RemoteErrorCode::NotFound,
            "no such evidence bundle on this PC".to_string(),
        ))?;
    if !e.authorized_until.is_some_and(|t| t > now) {
        return Err((
            RemoteErrorCode::NotFound,
            "the bundle was not prepared for upload (collect it first)".into(),
        ));
    }
    let Some(sha) = e.sha256.clone() else {
        return Err((RemoteErrorCode::NotFound, "the bundle is incomplete".into()));
    };
    let path = evidence_bundle::bundle_path(&bundles_dir(&*host), bundle_id);
    if !file_exists(&path) {
        return Err((
            RemoteErrorCode::NotFound,
            "the bundle file is missing".into(),
        ));
    }
    let size = e.size;
    tokio::task::spawn_blocking(move || {
        let key = host.bundle_key().map_err(|_| {
            (
                RemoteErrorCode::Io,
                "the bundle key is unavailable".to_string(),
            )
        })?;
        let f = std::fs::File::open(&path).map_err(|e| read_error(&e))?;
        let reader = kestrel_common::seal::SealReader::new(
            std::io::BufReader::with_capacity(1 << 20, f),
            &key,
            bundle_id.as_bytes(),
        )
        .map_err(|e| read_error(&e))?;
        Ok(Box::new(ReadState {
            reader,
            served: 0,
            hasher: Sha256::new(),
            size,
            sha256: sha,
        }))
    })
    .await
    .unwrap_or_else(|_| Err((RemoteErrorCode::Io, "the read task failed".into())))
}

/// Read the next chunk. Returns the state back with (data, eof, sha on eof).
fn read_chunk(mut st: Box<ReadState>, len: usize) -> (Box<ReadState>, ChunkResult) {
    let mut buf = vec![0u8; len];
    let mut n = 0;
    while n < len {
        match st.reader.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return (st, Err(read_error(&e))),
        }
    }
    buf.truncate(n);
    st.hasher.update(&buf);
    st.served += n as u64;
    let integrity = || {
        (
            RemoteErrorCode::IntegrityError,
            "the evidence bundle does not match its recorded size / hash".to_string(),
        )
    };
    if st.served > st.size {
        return (st, Err(integrity()));
    }
    let mut eof = n < len;
    if !eof && st.served == st.size {
        // Confirm the end (authenticates the last sealed chunk).
        let mut one = [0u8; 1];
        match st.reader.read(&mut one) {
            Ok(0) => eof = true,
            Ok(_) => return (st, Err(integrity())),
            Err(e) => return (st, Err(read_error(&e))),
        }
    }
    if !eof {
        return (st, Ok((buf, false, None)));
    }
    let sha = kestrel_common::evidence::hex_lower(&st.hasher.clone().finalize());
    if st.served != st.size || sha != st.sha256 {
        return (st, Err(integrity()));
    }
    (st, Ok((buf, true, Some(sha))))
}

async fn read_worker(
    core: Arc<Core>,
    session_id: Uuid,
    bundle_id: Uuid,
    mut rx: mpsc::Receiver<ReadReq>,
    cancel: CancellationToken,
    wid: u64,
) {
    let idle = core.tuning.evidence_read_idle;
    let mut state: Option<Box<ReadState>> = None;
    loop {
        let req = tokio::select! {
            _ = cancel.cancelled() => break,
            _ = core.shutdown.cancelled() => break,
            r = tokio::time::timeout(idle, rx.recv()) => match r {
                Ok(Some(r)) => r,
                _ => break,
            },
        };
        let (reply, done) = serve_read(&core, &mut state, bundle_id, &req).await;
        if cancel.is_cancelled() {
            break;
        }
        core.live
            .send_message(
                session_id,
                LiveAgentMsg::EvidenceData {
                    request_id: req.request_id,
                    reply,
                },
            )
            .await;
        if done {
            break;
        }
    }
    // Every read gets exactly one reply: reads the server pipelined behind
    // the end of this session (error, eof, cancel, idle) are refused.
    core.evidence.worker_done(session_id, wid);
    rx.close();
    while let Ok(req) = rx.try_recv() {
        core.live
            .send_message(
                session_id,
                LiveAgentMsg::EvidenceData {
                    request_id: req.request_id,
                    reply: FileReply::Error {
                        code: RemoteErrorCode::InvalidOperation,
                        message: "the upload session ended".into(),
                    },
                },
            )
            .await;
    }
}

async fn serve_read(
    core: &Core,
    state: &mut Option<Box<ReadState>>,
    bundle_id: Uuid,
    req: &ReadReq,
) -> (FileReply, bool) {
    let err = |(code, message): ReadErr| (FileReply::Error { code, message }, true);
    if state.is_none() {
        if req.offset != 0 {
            return err((
                RemoteErrorCode::InvalidOperation,
                "an upload starts at offset 0".into(),
            ));
        }
        match open_read(core, bundle_id).await {
            Ok(s) => *state = Some(s),
            Err(e) => return err(e),
        }
    }
    let Some(st) = state.take() else {
        return err((RemoteErrorCode::Io, "no read state".into()));
    };
    if req.offset != st.served {
        return err((
            RemoteErrorCode::InvalidOperation,
            format!(
                "reads must be sequential (expected offset {}, got {})",
                st.served, req.offset
            ),
        ));
    }
    let len = req.len.clamp(1, READ_CHUNK_MAX) as usize;
    let offset = st.served;
    let size = st.size;
    let r = tokio::task::spawn_blocking(move || read_chunk(st, len)).await;
    match r {
        Ok((st, Ok((data, eof, sha)))) => {
            *state = Some(st);
            (
                FileReply::Data {
                    offset,
                    data_b64: base64::engine::general_purpose::STANDARD.encode(&data),
                    size,
                    eof,
                    sha256: sha,
                },
                eof,
            )
        }
        Ok((_, Err(e))) => {
            tracing::warn!(%bundle_id, "evidence upload refused: {}", e.1);
            err(e)
        }
        Err(_) => err((RemoteErrorCode::Io, "the read task failed".into())),
    }
}

// ======================================================= start / shutdown

/// Agent start: delete partial bundles and plaintext capture leftovers,
/// clean up a packet capture a crashed agent left running, report captures
/// that were running as `Failed`, and drop bundle files the index does not
/// know as ready.
pub async fn startup(core: Arc<Core>) {
    let Some(host) = core.platform.evidence() else {
        return;
    };
    let bdir = bundles_dir(&*host);
    let wroot = work_root(&*host);
    if let Some(pc) = host.packet_capture() {
        let w = wroot.clone();
        let _ = tokio::task::spawn_blocking(move || pc.cleanup_stale(&w)).await;
    }
    let index = core.evidence.index(&core);
    let ready: std::collections::HashSet<String> = index
        .iter()
        .filter(|e| e.state == EvidenceState::Ready)
        .map(|e| format!("{}.{BUNDLE_EXT}", e.bundle_id))
        .collect();
    let (b2, w2) = (bdir.clone(), wroot.clone());
    let _ = tokio::task::spawn_blocking(move || {
        if let Ok(rd) = std::fs::read_dir(&b2) {
            for ent in rd.flatten() {
                let name = ent.file_name().to_string_lossy().to_string();
                let partial = name.ends_with(&format!(".{PARTIAL_EXT}"));
                let orphan = name.ends_with(&format!(".{BUNDLE_EXT}")) && !ready.contains(&name);
                if partial || orphan {
                    let _ = std::fs::remove_file(ent.path());
                }
            }
        }
        // Plaintext capture work folders of earlier runs.
        if let Ok(rd) = std::fs::read_dir(&w2) {
            for ent in rd.flatten() {
                let p = ent.path();
                let is_dir = ent.file_type().is_ok_and(|t| t.is_dir());
                let _ = if is_dir {
                    std::fs::remove_dir_all(&p)
                } else {
                    std::fs::remove_file(&p)
                };
            }
        }
    })
    .await;
    for e in index {
        let (state, detail) = match e.state {
            EvidenceState::Capturing => (
                EvidenceState::Failed,
                "the agent restarted during the capture",
            ),
            EvidenceState::Ready
                if !file_exists(&evidence_bundle::bundle_path(&bdir, e.bundle_id)) =>
            {
                (
                    EvidenceState::Deleted,
                    "the bundle file is missing on this PC",
                )
            }
            _ => continue,
        };
        if let Some(e) = core.evidence.update_entry(&core, e.bundle_id, |x| {
            x.state = state;
            x.detail = detail.into();
            x.authorized_until = None;
        }) {
            enqueue_report(&core, report_of(&e, state, detail));
        }
    }
}

/// Agent shutdown (bounded): stop running packet captures (their plaintext
/// files are deleted), report unfinished captures `Failed`, end uploads.
pub async fn shutdown(core: &Arc<Core>) {
    core.evidence.end_reads(None);
    let pending: Vec<(Uuid, Option<JoinHandle<PcapStarted>>)> = {
        let mut st = lock(&core.evidence.st);
        let ids: Vec<Uuid> = st
            .caps
            .iter()
            .filter(|(_, c)| !c.finishing)
            .map(|(id, _)| *id)
            .collect();
        let mut v = Vec::new();
        for id in ids {
            if let Some(c) = st.caps.remove(&id) {
                v.push((id, c.pcap_task));
            }
        }
        st.pcap_owner = None;
        v
    };
    let deadline = tokio::time::Instant::now() + SHUTDOWN_BUDGET;
    for (id, task) in pending {
        if let Some(task) = task {
            if let Ok(Ok(started)) = tokio::time::timeout_at(deadline, task).await {
                if let Some(sess) = started.session {
                    let stop = tokio::task::spawn_blocking(move || sess.stop());
                    if let Ok(Ok(Ok(f))) = tokio::time::timeout_at(deadline, stop).await {
                        let _ = std::fs::remove_file(&f.path);
                    }
                }
            }
        }
        if let Some(host) = core.platform.evidence() {
            let _ = std::fs::remove_dir_all(work_root(&*host).join(id.to_string()));
        }
        let detail = "the agent stopped during the capture";
        if let Some(e) = core.evidence.update_entry(core, id, |e| {
            e.state = EvidenceState::Failed;
            e.detail = detail.into();
        }) {
            enqueue_report(core, report_of(&e, EvidenceState::Failed, detail));
        }
    }
}
