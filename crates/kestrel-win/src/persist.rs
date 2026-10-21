//! Persistence sensors (pure): Task Scheduler 106/140/141, SCM 7045 and
//! WMI-Activity 5861 records from either a private ETW session (named
//! fields) or an event-log subscription (rendered XML), the creator
//! correlation used to attribute them, and de-duplication between the two
//! sources.
//!
//! Field names were checked against this host's manifests (`Get-WinEvent
//! -ListProvider`, Windows 11 25H2 build 26200):
//! * TaskScheduler {DE7B24EA-73C8-4A09-985D-5BDADCFA9017}: 106 `TaskName,
//!   UserContext`; 140 / 141 `TaskName, UserName`. Operational channel is
//!   disabled by default.
//! * Service Control Manager {555908D1-A6D7-4695-8E1E-26931D2012F4}: 7045 is
//!   a classic event-log event (no manifest template); the System-log XML
//!   carries `ServiceName, ImagePath, ServiceType, StartType, AccountName`
//!   and the installer's SID in `System/Security/@UserID` (real sample in
//!   `tests/fixtures/scm_7045.xml`).
//! * WMI-Activity {1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}: 5861 `Namespace,
//!   ESS, CONSUMER, PossibleCause` (UserData in the rendered XML).

use crate::evtxml::parse_iso8601_ms;
use kestrel_common::{ServiceInstall, TaskOp, WmiBinding};
use std::collections::{HashMap, VecDeque};

pub mod eid {
    pub const TASK_REGISTERED: u16 = 106;
    pub const TASK_UPDATED: u16 = 140;
    pub const TASK_DELETED: u16 = 141;
    pub const SCM_SERVICE_INSTALLED: u16 = 7045;
    pub const WMI_ESS_TO_CONSUMER_BINDING: u16 = 5861;
}

/// Event-log channels used as fall-back sources.
pub mod channel {
    pub const TASK_SCHEDULER: &str = "Microsoft-Windows-TaskScheduler/Operational";
    pub const SYSTEM: &str = "System";
    pub const WMI_ACTIVITY: &str = "Microsoft-Windows-WMI-Activity/Operational";
}

/// Generic record (before the task XML is read / the creator is attributed).
#[derive(Debug, Clone, PartialEq)]
pub enum PersistRecord {
    Task {
        name: String,
        op: TaskOp,
        user: Option<String>,
    },
    Service(ServiceInstall),
    Wmi(WmiBinding),
}

impl PersistRecord {
    pub fn kind(&self) -> HintKind {
        match self {
            PersistRecord::Task { .. } => HintKind::Task,
            PersistRecord::Service(_) => HintKind::Service,
            PersistRecord::Wmi(_) => HintKind::Wmi,
        }
    }

    /// De-duplication key (ETW and event-log copies of the same event). V-M8:
    /// besides the name and operation it carries the task XML hash (and the
    /// service image path), and [`Dedup`] only matches copies whose
    /// timestamps agree to [`DEDUP_MS`]: a real create → delete → create of
    /// the same name with new content is never merged.
    pub fn dedup_key(&self) -> String {
        self.dedup_key_with(None)
    }

    pub fn dedup_key_with(&self, task: Option<&crate::taskxml::TaskInfo>) -> String {
        match self {
            PersistRecord::Task { name, op, .. } => format!(
                "task|{op:?}|{}|{:016x}",
                name.to_ascii_lowercase(),
                task.map_or(0, |t| t.xml_hash)
            ),
            PersistRecord::Service(s) => format!(
                "svc|{}|{:016x}",
                s.name.to_ascii_lowercase(),
                crate::regdiff::fnv1a(s.image_path.to_ascii_lowercase().as_bytes())
            ),
            PersistRecord::Wmi(w) => format!(
                "wmi|{}|{}|{}",
                w.namespace.to_ascii_lowercase(),
                w.filter.to_ascii_lowercase(),
                w.consumer.to_ascii_lowercase()
            ),
        }
    }
}

/// A parsed event: record + timing + logging process.
#[derive(Debug, Clone, PartialEq)]
pub struct Parsed {
    pub ts: Option<i64>,
    /// Process that logged the event (Schedule svchost, services.exe, WmiPrvSE/winmgmt).
    pub logger_pid: Option<u32>,
    /// `System/Security/@UserID` (7045: the installing user).
    pub user_sid: Option<String>,
    pub record: PersistRecord,
}

fn get<'a>(f: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    f.iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(k))
        .map(|(_, v)| v.trim())
        .filter(|v| !v.is_empty())
}

/// SCM 7045 `ServiceType` string → SERVICE_* type.
pub fn service_type_from_str(s: &str) -> Option<u32> {
    let s = s.trim().to_ascii_lowercase();
    if let Some(n) = parse_num(&s) {
        return Some(n);
    }
    Some(match s.as_str() {
        "kernel mode driver" => 0x1,
        "file system driver" => 0x2,
        "user mode service" => 0x10,
        "share process" | "shared process" => 0x20,
        _ => return None,
    })
}

/// SCM 7045 `StartType` string → 0..4.
pub fn start_type_from_str(s: &str) -> Option<u32> {
    let s = s.trim().to_ascii_lowercase();
    if let Some(n) = parse_num(&s) {
        return Some(n);
    }
    Some(match s.as_str() {
        "boot start" => 0,
        "system start" => 1,
        "auto start" => 2,
        "demand start" => 3,
        "disabled" => 4,
        _ => return None,
    })
}

fn parse_num(s: &str) -> Option<u32> {
    match s.strip_prefix("0x") {
        Some(h) => u32::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Extract `Key = "value";` from a MOF instance dump (WMI PossibleCause),
/// unescaping `\\` and `\"`.
pub fn mof_value(text: &str, key: &str) -> Option<String> {
    let mut search = text;
    while let Some(i) = search.find(key) {
        let before_ok = i == 0 || !search.as_bytes()[i - 1].is_ascii_alphanumeric();
        let rest = search[i + key.len()..].trim_start();
        if before_ok {
            if let Some(r) = rest.strip_prefix('=') {
                let r = r.trim_start();
                if let Some(r) = r.strip_prefix('"') {
                    let mut out = String::new();
                    let mut chars = r.chars().peekable();
                    while let Some(c) = chars.next() {
                        match c {
                            // MOF escapes only `\\` and `\"`; any other
                            // backslash is kept literally.
                            '\\' if matches!(chars.peek(), Some('\\' | '"')) => {
                                if let Some(n) = chars.next() {
                                    out.push(n);
                                }
                            }
                            '"' => return Some(out),
                            c => out.push(c),
                        }
                        if out.len() > 2048 {
                            return Some(out);
                        }
                    }
                    return Some(out);
                }
            }
        }
        search = &search[i + key.len()..];
    }
    None
}

/// Build a record from named fields (ETW decode or XML), by provider event id.
pub fn record_from_fields(event_id: u16, f: &HashMap<String, String>) -> Option<PersistRecord> {
    match event_id {
        eid::TASK_REGISTERED | eid::TASK_UPDATED | eid::TASK_DELETED => {
            let name = get(f, "TaskName")?.to_string();
            let op = match event_id {
                eid::TASK_REGISTERED => TaskOp::Created,
                eid::TASK_UPDATED => TaskOp::Updated,
                _ => TaskOp::Deleted,
            };
            let user = get(f, "UserContext")
                .or_else(|| get(f, "UserName"))
                .map(str::to_string);
            Some(PersistRecord::Task { name, op, user })
        }
        eid::SCM_SERVICE_INSTALLED => {
            let name = get(f, "ServiceName")?.to_string();
            Some(PersistRecord::Service(ServiceInstall {
                attribution: Default::default(),
                name,
                image_path: get(f, "ImagePath").unwrap_or_default().to_string(),
                start_type: get(f, "StartType").and_then(start_type_from_str),
                service_type: get(f, "ServiceType").and_then(service_type_from_str),
                account: get(f, "AccountName").map(str::to_string),
            }))
        }
        eid::WMI_ESS_TO_CONSUMER_BINDING => {
            let cause = get(f, "PossibleCause").unwrap_or_default();
            let ess = get(f, "ESS").unwrap_or_default();
            let filter = match mof_value(cause, "Query") {
                Some(q) if !ess.is_empty() => format!("{ess}: {q}"),
                Some(q) => q,
                None => ess.to_string(),
            };
            let mut consumer = get(f, "CONSUMER").unwrap_or_default().to_string();
            for k in [
                "CommandLineTemplate",
                "ExecutablePath",
                "ScriptText",
                "ScriptFileName",
            ] {
                if let Some(v) = mof_value(cause, k) {
                    let v: String = v.chars().take(1024).collect();
                    consumer = format!("{consumer} | {v}");
                    break;
                }
            }
            Some(PersistRecord::Wmi(WmiBinding {
                attribution: Default::default(),
                namespace: get(f, "Namespace").unwrap_or_default().to_string(),
                filter,
                consumer,
            }))
        }
        _ => None,
    }
}

/// Parse an EvtRender XML event from one of the persistence channels.
/// Handles both `EventData/Data[@Name]` and `UserData/*/<Field>` layouts.
pub fn parse_persist_xml(xml: &str) -> Option<Parsed> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let mut event_id: Option<u16> = None;
    let (mut ts, mut logger_pid, mut user_sid) = (None, None, None);
    let mut fields: HashMap<String, String> = HashMap::new();
    for sect in root.children().filter(|n| n.is_element()) {
        match sect.tag_name().name() {
            "System" => {
                for n in sect.children().filter(|n| n.is_element()) {
                    match n.tag_name().name() {
                        "EventID" => event_id = n.text().and_then(|t| t.trim().parse().ok()),
                        "TimeCreated" => ts = n.attribute("SystemTime").and_then(parse_iso8601_ms),
                        "Execution" => {
                            logger_pid = n.attribute("ProcessID").and_then(|p| p.parse().ok())
                        }
                        "Security" => user_sid = n.attribute("UserID").map(str::to_string),
                        _ => {}
                    }
                }
            }
            "EventData" => {
                for d in sect
                    .children()
                    .filter(|n| n.is_element() && n.has_tag_name("Data"))
                {
                    if let Some(name) = d.attribute("Name") {
                        fields.insert(name.to_string(), d.text().unwrap_or_default().to_string());
                    }
                }
            }
            "UserData" => {
                for d in sect.descendants().filter(|n| n.is_element()) {
                    let leaf = !d.children().any(|c| c.is_element());
                    if leaf && d.parent().is_some_and(|p| p != sect) {
                        fields.insert(
                            d.tag_name().name().to_string(),
                            d.text().unwrap_or_default().to_string(),
                        );
                    }
                }
            }
            _ => {}
        }
    }
    let record = record_from_fields(event_id?, &fields)?;
    Some(Parsed {
        ts,
        logger_pid,
        user_sid,
        record,
    })
}

// ------------------------------------------------------------------ creator correlation

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HintKind {
    Task,
    Service,
    Wmi,
}

/// How far back (and forward, for clock skew between sources) a hint counts.
pub const HINT_BEFORE_MS: i64 = 5_000;
pub const HINT_AFTER_MS: i64 = 1_000;
const MAX_HINTS: usize = 1024;

/// Recent "this process is creating persistence" hints: `schtasks /create`,
/// `sc create`, `Register-ScheduledTask`, a `taskschd.dll` load, … The
/// Task Scheduler / SCM / WMI events carry the service's pid, not the
/// creator's, so the creator is the most recent matching hint.
#[derive(Debug, Default)]
pub struct Hints {
    ring: VecDeque<(i64, u32, HintKind)>,
}

fn contains_ci(hay: &str, needles: &[&str]) -> bool {
    let h = hay.to_ascii_lowercase();
    needles.iter().any(|n| h.contains(n))
}

impl Hints {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, ts: i64, pid: u32, k: HintKind) {
        if self.ring.len() >= MAX_HINTS {
            self.ring.pop_front();
        }
        self.ring.push_back((ts, pid, k));
    }

    /// `image` is a full path or file name; `cmdline` the command line.
    pub fn on_process_start(&mut self, ts: i64, pid: u32, image: &str, cmdline: &str) {
        let name = image
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(image)
            .to_ascii_lowercase();
        let k = match name.as_str() {
            "schtasks.exe"
                if contains_ci(
                    cmdline,
                    &[
                        "/create", "-create", "/change", "-change", "/delete", "-delete",
                    ],
                ) =>
            {
                Some(HintKind::Task)
            }
            "at.exe" => Some(HintKind::Task),
            "sc.exe" if contains_ci(cmdline, &[" create", " config"]) => Some(HintKind::Service),
            "wmic.exe"
                if contains_ci(
                    cmdline,
                    &[
                        "__eventfilter",
                        "eventconsumer",
                        "__filtertoconsumerbinding",
                    ],
                ) =>
            {
                Some(HintKind::Wmi)
            }
            "mofcomp.exe" => Some(HintKind::Wmi),
            _ => None,
        };
        if let Some(k) = k {
            self.push(ts, pid, k);
        }
    }

    pub fn on_script(&mut self, ts: i64, pid: u32, text: &str) {
        let t: String = text.chars().take(64 * 1024).collect();
        if contains_ci(
            &t,
            &[
                "register-scheduledtask",
                "set-scheduledtask",
                "schedule.service",
                "unregister-scheduledtask",
            ],
        ) {
            self.push(ts, pid, HintKind::Task);
        }
        if contains_ci(
            &t,
            &["new-service", "set-service", "sc.exe create", "sc create"],
        ) {
            self.push(ts, pid, HintKind::Service);
        }
        if contains_ci(
            &t,
            &[
                "__eventfilter",
                "__filtertoconsumerbinding",
                "commandlineeventconsumer",
                "activescripteventconsumer",
                "register-wmievent",
            ],
        ) {
            self.push(ts, pid, HintKind::Wmi);
        }
    }

    /// `taskschd.dll` loaded by a non-system process (COM task creation).
    pub fn on_image_load(&mut self, ts: i64, pid: u32, path: &str) {
        let name = path
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(path)
            .to_ascii_lowercase();
        if name == "taskschd.dll" {
            self.push(ts, pid, HintKind::Task);
        }
    }

    /// Most recent hint of `kind` within [ts − 5 s, ts + 1 s].
    pub fn creator(&self, kind: HintKind, ts: i64) -> Option<u32> {
        self.creator_where(kind, ts, |_| true)
    }

    /// Most recent hint of `kind` in the window whose process `plausible`
    /// accepts (V-H5: e.g. only High / System integrity for services).
    ///
    /// Every answer is a correlation, never proof: callers must mark the
    /// event `Attribution::Heuristic`. A `taskschd.dll` load is only a hint
    /// because a task event must follow it within the same 5 s window to be
    /// attributed at all (the window is anchored on the task event).
    pub fn creator_where(
        &self,
        kind: HintKind,
        ts: i64,
        plausible: impl Fn(u32) -> bool,
    ) -> Option<u32> {
        self.ring
            .iter()
            .rev()
            .filter(|(t, _, k)| *k == kind && *t >= ts - HINT_BEFORE_MS && *t <= ts + HINT_AFTER_MS)
            .filter(|(_, p, _)| plausible(*p))
            .max_by_key(|(t, _, _)| *t)
            .map(|(_, p, _)| *p)
    }

    pub fn expire(&mut self, now: i64) {
        while self
            .ring
            .front()
            .is_some_and(|(t, _, _)| *t < now - 4 * HINT_BEFORE_MS)
        {
            self.ring.pop_front();
        }
    }
}

/// Drops the second copy of an event seen through both ETW and the event log.
#[derive(Debug, Default)]
pub struct Dedup {
    recent: VecDeque<(i64, String)>,
}

/// Both copies carry the timestamp of the same provider write (ETW header /
/// event-log `TimeCreated`), so they agree to the millisecond; a little slack
/// covers rounding.
pub const DEDUP_MS: i64 = 50;
/// How long keys are remembered (the event-log copy can lag the ETW one).
const DEDUP_KEEP_MS: i64 = 60_000;

impl Dedup {
    /// True when `key` was already seen within ±[`DEDUP_MS`]; records it otherwise.
    pub fn seen(&mut self, key: &str, ts: i64) -> bool {
        while self
            .recent
            .front()
            .is_some_and(|(t, _)| *t < ts - DEDUP_KEEP_MS)
        {
            self.recent.pop_front();
        }
        if self
            .recent
            .iter()
            .any(|(t, k)| k == key && (t - ts).abs() <= DEDUP_MS)
        {
            return true;
        }
        if self.recent.len() >= 1024 {
            self.recent.pop_front();
        }
        self.recent.push_back((ts, key.to_string()));
        false
    }
}

// ------------------------------------------------------------ enrichment queue

/// Records waiting for enrichment (re-review V-M9: was 512).
pub const ENRICH_QUEUE_CAP: usize = 4096;
/// Task names remembered as "seen created" (FIFO-bounded).
const SEEN_CREATED_CAP: usize = 16_384;

/// Drop priority of a queued record: the lowest is dropped first when the
/// queue is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DropRank {
    /// Delete of a task never seen created (the cheapest flood: register and
    /// delete junk tasks).
    UnseenDelete = 0,
    /// Update of a task never seen created.
    UnseenUpdate = 1,
    /// Delete of a task seen created.
    Delete = 2,
    /// Task create, update of a task seen created, service install, WMI
    /// binding: never dropped in favour of the above.
    Keep = 3,
}

struct Queued<T> {
    seq: u64,
    rank: DropRank,
    /// Lower-cased task name (tasks only).
    task_lc: Option<String>,
    delete: bool,
    item: T,
}

/// Bounded, prioritised queue between the persistence callbacks and the
/// enrichment worker (re-review V-M9). Pure logic (unit-tested on Linux).
///
/// * Records that need enrichment (task create / update, service) are
///   *heavy*; the others (task delete, WMI) need no XML and are *light*.
/// * [`pop`](Self::pop) serves heavy records first, except that a light
///   record for the same task name that was queued earlier is released
///   first, so per-task order (delete → re-create) is preserved.
/// * When full, the record with the lowest [`DropRank`] (incoming one on a
///   tie) is dropped and counted in [`dropped`](Self::dropped).
/// * [`delete_pending`](Self::delete_pending) lets the worker skip the
///   retry sleep / COM fallback for a task whose delete is already queued.
pub struct EnrichQueue<T> {
    cap: usize,
    next_seq: u64,
    heavy: VecDeque<Queued<T>>,
    light: VecDeque<Queued<T>>,
    seen_created: std::collections::HashSet<String>,
    seen_order: VecDeque<String>,
    pub dropped: u64,
}

impl<T> EnrichQueue<T> {
    pub fn new(cap: usize) -> Self {
        Self {
            cap: cap.max(1),
            next_seq: 0,
            heavy: VecDeque::new(),
            light: VecDeque::new(),
            seen_created: Default::default(),
            seen_order: VecDeque::new(),
            dropped: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.heavy.len() + self.light.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn note_created(&mut self, name_lc: &str) {
        if self.seen_created.contains(name_lc) {
            return;
        }
        if self.seen_order.len() >= SEEN_CREATED_CAP {
            if let Some(old) = self.seen_order.pop_front() {
                self.seen_created.remove(&old);
            }
        }
        self.seen_created.insert(name_lc.to_string());
        self.seen_order.push_back(name_lc.to_string());
    }

    /// Queue `item` (described by `record`). Returns the record that was
    /// dropped to make room (the incoming one or a queued one), if any.
    pub fn push(&mut self, record: &PersistRecord, item: T) -> Option<T> {
        let (task_lc, op) = match record {
            PersistRecord::Task { name, op, .. } => (Some(name.to_ascii_lowercase()), Some(*op)),
            _ => (None, None),
        };
        if let (Some(n), Some(TaskOp::Created)) = (&task_lc, op) {
            self.note_created(n);
        }
        let seen = task_lc
            .as_deref()
            .is_some_and(|n| self.seen_created.contains(n));
        let rank = match op {
            Some(TaskOp::Deleted) if !seen => DropRank::UnseenDelete,
            Some(TaskOp::Updated) if !seen => DropRank::UnseenUpdate,
            Some(TaskOp::Deleted) => DropRank::Delete,
            _ => DropRank::Keep,
        };
        let delete = op == Some(TaskOp::Deleted);
        let heavy = matches!(
            record,
            PersistRecord::Service(_) | PersistRecord::Task { .. }
        ) && !delete;
        let mut evicted = None;
        if self.len() >= self.cap {
            // Lowest rank in the queue (oldest on a tie).
            let victim = self
                .heavy
                .iter()
                .enumerate()
                .map(|(i, q)| (q.rank, q.seq, true, i))
                .chain(
                    self.light
                        .iter()
                        .enumerate()
                        .map(|(i, q)| (q.rank, q.seq, false, i)),
                )
                .min();
            self.dropped += 1;
            match victim {
                Some((r, _, is_heavy, i)) if r < rank => {
                    let q = if is_heavy {
                        self.heavy.remove(i)
                    } else {
                        self.light.remove(i)
                    };
                    evicted = q.map(|q| q.item);
                }
                _ => return Some(item),
            }
        }
        let q = Queued {
            seq: self.next_seq,
            rank,
            task_lc,
            delete,
            item,
        };
        self.next_seq += 1;
        if heavy {
            self.heavy.push_back(q);
        } else {
            self.light.push_back(q);
        }
        evicted
    }

    /// Next record to process: heavy first (see the type docs).
    pub fn pop(&mut self) -> Option<T> {
        let Some(h) = self.heavy.front() else {
            return self.light.pop_front().map(|q| q.item);
        };
        let (seq, name) = (h.seq, h.task_lc.clone());
        if let Some(name) = name {
            if let Some(i) = self
                .light
                .iter()
                .position(|q| q.seq < seq && q.task_lc.as_deref() == Some(name.as_str()))
            {
                return self.light.remove(i).map(|q| q.item);
            }
        }
        self.heavy.pop_front().map(|q| q.item)
    }

    /// Is a delete of `task_name` waiting in the queue?
    pub fn delete_pending(&self, task_name: &str) -> bool {
        self.light.iter().any(|q| {
            q.delete
                && q.task_lc
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(task_name))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(p).unwrap()
    }

    /// Real System 7045 (Windows 11 25H2), scrubbed.
    #[test]
    fn scm_7045_real() {
        let p = parse_persist_xml(&fixture("scm_7045.xml")).unwrap();
        assert_eq!(p.logger_pid, Some(2248));
        assert_eq!(
            p.user_sid.as_deref(),
            Some("S-1-5-21-1000000000-1000000000-1000000000-1001")
        );
        assert!(p.ts.is_some());
        match p.record {
            PersistRecord::Service(s) => {
                assert_eq!(s.name, "Visual Studio Installer Elevation Service");
                assert!(s
                    .image_path
                    .ends_with(r#"VSInstallerElevationService.exe""#));
                assert_eq!(s.start_type, Some(3));
                assert_eq!(s.service_type, Some(0x10));
                assert_eq!(s.account.as_deref(), Some("LocalSystem"));
            }
            other => panic!("{other:?}"),
        }
    }

    /// Synthetic 5861 shaped after the manifest (no 5861 existed on the host).
    #[test]
    fn wmi_5861_userdata() {
        let p = parse_persist_xml(&fixture("wmi_5861.xml")).unwrap();
        assert_eq!(p.logger_pid, Some(3104));
        match p.record {
            PersistRecord::Wmi(w) => {
                assert_eq!(w.namespace, "//./root/subscription");
                assert!(
                    w.filter.starts_with(
                        "KestrelProbeFilter: SELECT * FROM __InstanceModificationEvent"
                    ),
                    "{}",
                    w.filter
                );
                assert_eq!(
                    w.consumer,
                    r#"CommandLineEventConsumer="KestrelProbeConsumer" | C:\Windows\System32\cmd.exe /c exit"#
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn task_events_from_fields() {
        let mut f = HashMap::new();
        f.insert("TaskName".to_string(), r"\KestrelProbe".to_string());
        f.insert("UserContext".to_string(), r"LABPC\labuser".to_string());
        assert_eq!(
            record_from_fields(106, &f),
            Some(PersistRecord::Task {
                name: r"\KestrelProbe".into(),
                op: TaskOp::Created,
                user: Some(r"LABPC\labuser".into())
            })
        );
        let mut g = HashMap::new();
        g.insert("TaskName".to_string(), r"\KestrelProbe".to_string());
        g.insert("UserName".to_string(), r"LABPC\labuser".to_string());
        assert!(matches!(
            record_from_fields(141, &g),
            Some(PersistRecord::Task {
                op: TaskOp::Deleted,
                ..
            })
        ));
        assert!(record_from_fields(106, &HashMap::new()).is_none());
        assert!(record_from_fields(4624, &g).is_none());
        // TaskScheduler/Operational XML form (EventData).
        let xml = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-TaskScheduler'/><EventID>140</EventID><TimeCreated SystemTime='2026-10-21T08:00:00.5Z'/><Execution ProcessID='1840' ThreadID='1'/></System><EventData Name='TaskUpdated'><Data Name='TaskName'>\KestrelProbe</Data><Data Name='UserName'>LABPC\labuser</Data></EventData></Event>"#;
        let p = parse_persist_xml(xml).unwrap();
        assert_eq!(p.logger_pid, Some(1840));
        assert!(matches!(
            p.record,
            PersistRecord::Task {
                op: TaskOp::Updated,
                ..
            }
        ));
    }

    #[test]
    fn scm_strings() {
        assert_eq!(service_type_from_str("kernel mode driver"), Some(1));
        assert_eq!(service_type_from_str("0x10"), Some(0x10));
        assert_eq!(start_type_from_str("auto start"), Some(2));
        assert_eq!(start_type_from_str("disabled"), Some(4));
        assert_eq!(start_type_from_str("start on Tuesdays"), None);
    }

    #[test]
    fn mof_values() {
        let t = r#"instance of X { Name = "a\"b"; CommandLineTemplate = "C:\\x.exe -y"; };"#;
        assert_eq!(mof_value(t, "Name").as_deref(), Some(r#"a"b"#));
        assert_eq!(
            mof_value(t, "CommandLineTemplate").as_deref(),
            Some(r"C:\x.exe -y")
        );
        assert_eq!(mof_value(t, "Query"), None);
        assert_eq!(mof_value("XName = \"no\"", "Name"), None);
    }

    #[test]
    fn creator_hints() {
        let mut h = Hints::new();
        h.on_process_start(
            1_000,
            10,
            r"C:\Windows\System32\schtasks.exe",
            "schtasks /create /tn x /tr y",
        );
        h.on_process_start(
            1_100,
            11,
            r"C:\Windows\System32\schtasks.exe",
            "schtasks /query",
        );
        h.on_process_start(
            1_200,
            12,
            r"C:\Windows\System32\sc.exe",
            "sc.exe create svc binPath= x",
        );
        h.on_script(1_300, 13, "Register-ScheduledTask -TaskName t -Action $a");
        h.on_image_load(1_400, 14, r"C:\Windows\System32\taskschd.dll");
        h.on_script(
            1_500,
            15,
            "Set-WmiInstance -Class __EventFilter -Namespace root\\subscription",
        );
        assert_eq!(h.creator(HintKind::Task, 2_000), Some(14));
        // Hints up to 1 s after the event count (clock skew between sources).
        assert_eq!(h.creator(HintKind::Task, 1_350), Some(14));
        assert_eq!(h.creator(HintKind::Task, 250), Some(10));
        assert_eq!(h.creator(HintKind::Service, 2_000), Some(12));
        assert_eq!(h.creator(HintKind::Wmi, 2_000), Some(15));
        assert_eq!(h.creator(HintKind::Task, 20_000), None);
        assert_eq!(h.creator(HintKind::Task, 0), Some(10)); // 1 s forward skew allowed
        h.expire(100_000);
        assert_eq!(h.creator(HintKind::Service, 1_300), None);
    }

    /// V-H5: an implausible hint (a Medium-integrity process for a service
    /// install) is skipped in favour of an older plausible one, or none.
    #[test]
    fn implausible_hints_are_rejected() {
        let mut h = Hints::new();
        h.on_process_start(1_000, 20, "sc.exe", "sc.exe create a binPath= x"); // elevated
        h.on_script(1_500, 21, "New-Service -Name x"); // medium-integrity implant
        let high = |p: u32| p == 20;
        assert_eq!(h.creator(HintKind::Service, 2_000), Some(21));
        assert_eq!(h.creator_where(HintKind::Service, 2_000, high), Some(20));
        assert_eq!(h.creator_where(HintKind::Service, 2_000, |_| false), None);
    }

    #[test]
    fn dedup() {
        let mut d = Dedup::default();
        let r = PersistRecord::Task {
            name: r"\X".into(),
            op: TaskOp::Created,
            user: None,
        };
        // ETW + event-log copy of one event: same timestamp.
        assert!(!d.seen(&r.dedup_key(), 1_000));
        assert!(d.seen(&r.dedup_key(), 1_000));
        assert!(d.seen(&r.dedup_key(), 1_020));
        // A later event with the same name is not a copy.
        assert!(!d.seen(&r.dedup_key(), 3_000));
        let del = PersistRecord::Task {
            name: r"\x".into(),
            op: TaskOp::Deleted,
            user: None,
        };
        assert!(!d.seen(&del.dedup_key(), 3_000));
    }

    /// V-M8: create (benign) → delete → create (malicious) within 5 s keeps
    /// every event; the malicious create differs in XML hash anyway.
    #[test]
    fn dedup_keeps_quick_recreate() {
        let mut d = Dedup::default();
        let create = PersistRecord::Task {
            name: r"\Updater".into(),
            op: TaskOp::Created,
            user: None,
        };
        let del = PersistRecord::Task {
            name: r"\Updater".into(),
            op: TaskOp::Deleted,
            user: None,
        };
        let benign = crate::taskxml::TaskInfo {
            xml_hash: 1,
            ..Default::default()
        };
        let evil = crate::taskxml::TaskInfo {
            xml_hash: 2,
            ..Default::default()
        };
        assert!(!d.seen(&create.dedup_key_with(Some(&benign)), 1_000));
        assert!(!d.seen(&del.dedup_key_with(None), 1_200));
        assert!(!d.seen(&create.dedup_key_with(Some(&evil)), 1_210));
        // Even identical content in the same millisecond window counts as a
        // copy only when the hash matches too.
        assert!(!d.seen(&create.dedup_key_with(Some(&benign)), 1_220));
        assert!(d.seen(&create.dedup_key_with(Some(&evil)), 1_215));
    }

    fn task(name: &str, op: TaskOp) -> PersistRecord {
        PersistRecord::Task {
            name: name.to_string(),
            op,
            user: None,
        }
    }

    fn push(q: &mut EnrichQueue<String>, name: &str, op: TaskOp) -> Option<String> {
        let tag = format!("{op:?}:{name}");
        q.push(&task(name, op), tag)
    }

    /// V-M9: creates are processed first, but per-task order is kept.
    #[test]
    fn enrich_queue_serves_creates_first_in_task_order() {
        let mut q = EnrichQueue::new(16);
        assert!(push(&mut q, r"\Junk1", TaskOp::Deleted).is_none());
        assert!(push(&mut q, r"\Evil", TaskOp::Deleted).is_none());
        assert!(push(&mut q, r"\Junk2", TaskOp::Deleted).is_none());
        assert!(push(&mut q, r"\EVIL", TaskOp::Created).is_none());
        q.push(&PersistRecord::Wmi(WmiBinding::default()), "wmi".into());
        assert!(push(&mut q, r"\Other", TaskOp::Created).is_none());
        // The earlier delete of \Evil is released before its re-create.
        assert_eq!(q.pop().unwrap(), r"Deleted:\Evil");
        assert_eq!(q.pop().unwrap(), r"Created:\EVIL");
        assert_eq!(q.pop().unwrap(), r"Created:\Other");
        assert_eq!(q.pop().unwrap(), r"Deleted:\Junk1");
        assert_eq!(q.pop().unwrap(), r"Deleted:\Junk2");
        assert_eq!(q.pop().unwrap(), "wmi");
        assert!(q.pop().is_none() && q.is_empty());
    }

    /// V-M9: a full queue drops deletes / updates of never-seen tasks before
    /// creates; a create is never displaced by them.
    #[test]
    fn enrich_queue_overflow_policy() {
        let mut q = EnrichQueue::new(4);
        assert!(push(&mut q, r"\Seen", TaskOp::Created).is_none());
        assert!(push(&mut q, r"\J1", TaskOp::Deleted).is_none());
        assert!(push(&mut q, r"\J2", TaskOp::Updated).is_none());
        assert!(push(&mut q, r"\Seen", TaskOp::Deleted).is_none());
        assert_eq!(q.len(), 4);
        // Full. A create evicts the unseen delete first...
        assert_eq!(
            push(&mut q, r"\Evil", TaskOp::Created).as_deref(),
            Some(r"Deleted:\J1")
        );
        // ...then the unseen update...
        assert_eq!(
            push(&mut q, r"\Evil2", TaskOp::Created).as_deref(),
            Some(r"Updated:\J2")
        );
        // ...then the delete of a seen task.
        assert_eq!(
            push(&mut q, r"\Evil3", TaskOp::Created).as_deref(),
            Some(r"Deleted:\Seen")
        );
        // Only creates left: the incoming one is dropped (never a queued
        // create), and junk deletes never get in.
        assert_eq!(
            push(&mut q, r"\Evil4", TaskOp::Created).as_deref(),
            Some(r"Created:\Evil4")
        );
        assert_eq!(
            push(&mut q, r"\J3", TaskOp::Deleted).as_deref(),
            Some(r"Deleted:\J3")
        );
        assert_eq!(
            push(&mut q, r"\J4", TaskOp::Updated).as_deref(),
            Some(r"Updated:\J4")
        );
        assert_eq!(q.dropped, 6);
        let mut out = Vec::new();
        while let Some(x) = q.pop() {
            out.push(x);
        }
        assert_eq!(
            out,
            [
                r"Created:\Seen",
                r"Created:\Evil",
                r"Created:\Evil2",
                r"Created:\Evil3"
            ]
        );
        // An update of a task seen created ranks with creates.
        let mut q = EnrichQueue::new(1);
        assert!(push(&mut q, r"\Seen", TaskOp::Created).is_none());
        q.pop();
        assert!(push(&mut q, r"\Junk", TaskOp::Deleted).is_none());
        assert_eq!(
            push(&mut q, r"\SEEN", TaskOp::Updated).as_deref(),
            Some(r"Deleted:\Junk")
        );
    }

    /// V-M9: the worker skips the retry sleep for a task whose delete is
    /// already queued; deletes themselves need no enrichment.
    #[test]
    fn enrich_queue_reports_pending_delete() {
        let mut q = EnrichQueue::new(8);
        push(&mut q, r"\Flood\T1", TaskOp::Created);
        assert!(!q.delete_pending(r"\Flood\T1"));
        push(&mut q, r"\Flood\T1", TaskOp::Deleted);
        assert!(q.delete_pending(r"\flood\t1"));
        assert!(!q.delete_pending(r"\Flood\T2"));
        assert_eq!(q.pop().unwrap(), r"Created:\Flood\T1");
        assert!(q.delete_pending(r"\Flood\T1"));
        assert_eq!(q.pop().unwrap(), r"Deleted:\Flood\T1");
        assert!(!q.delete_pending(r"\Flood\T1"));
    }
}
