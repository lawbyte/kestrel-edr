//! Translator thread: [`Raw`] sensor records → `kestrel_common::Event`.
//!
//! Responsibilities: process GUIDs (pid tracker), NT → Win32 paths, file
//! sensitivity filter (`kestrel_detect::paths::may_be_sensitive` + canary
//! paths), DNS → IP correlation per process, flow byte accounting,
//! SetContextThread target resolution, enrichment cache lookups, and the
//! short hold-back of a ProcessStart whose command line is still unknown
//! (at most [`CMDLINE_WAIT_MS`]) or whose image was never enriched (H7: at
//! most [`super::enrich::FIRST_RUN_BUDGET_MS`] for the priority hash +
//! Authenticode job). Later events of that process and its children are held
//! with it so ordering per lineage is preserved. A start released without
//! complete facts is registered for late enrichment (`Engine::enrich_process`).

use super::enrich::Enricher;
use super::etw::{Counters, Raw};
use super::util::*;
use crate::etwparse::*;
use crate::evtxml::SysmonKind;
use crate::filters;
use crate::ntpath::{norm_key, DeviceMap};
use crate::persist::{Dedup, Hints, PersistRecord};
use crate::proctrack::ProcTracker;
use crate::regdiff::{render_sysmon, RegJoin, PENDING_WAIT_MS};
use kestrel_common::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

pub const CMDLINE_WAIT_MS: i64 = 1_000;
const FILE_DEDUP_MS: i64 = 10_000;
const DNS_TTL_MS: i64 = 15 * 60_000;
const THREAD_OPEN_WINDOW_MS: i64 = 5_000;
/// Persistence events wait this long (arrival time) for the creator's
/// process-start / script / image-load events from the other sessions.
const PERSIST_HOLD_MS: i64 = 1_500;
/// A pid created this recently whose ProcessStart has not arrived is "early".
const EARLY_START_MS: i64 = 3_000;
/// How long events of an early pid wait for its ProcessStart.
const EARLY_HOLD_MS: i64 = 2_000;
const MAX_PENDING_REG: usize = 4096;
const MAX_PENDING_PERSIST: usize = 1024;

pub struct Shared {
    pub boot_id: String,
    pub self_pid: u32,
    pub tracker: Arc<RwLock<ProcTracker>>,
    pub enricher: Arc<Enricher>,
    pub devmap: Arc<RwLock<DeviceMap>>,
    pub canaries: Arc<RwLock<HashSet<String>>>,
    pub counters: Arc<Counters>,
    /// Agent state directory (ransomware decoy registry).
    pub state_dir: std::path::PathBuf,
}

struct PendingReg {
    deadline: i64,
    ts: i64,
    key: String,
    value_name: String,
    op: RegistryOp,
    ty: u32,
    data: Option<Vec<u8>>,
    reopened: bool,
}

struct PendingPersist {
    release_at: i64,
    ts: i64,
    logger_pid: u32,
    record: PersistRecord,
    task: Option<crate::taskxml::TaskInfo>,
}

struct Held {
    ev: Event,
    pid: u32,
    deadline: i64,
    waiting_cmdline: bool,
    /// Image whose first-run facts are awaited (H7).
    waiting_facts: Option<String>,
    facts_deadline: i64,
}

pub struct Translator {
    s: Arc<Shared>,
    out: mpsc::Sender<Event>,
    flows: FlowTable,
    dns: HashMap<u32, HashMap<IpAddr, (String, i64)>>,
    file_objects: HashMap<(u32, u64), (String, bool, i64)>,
    file_seen: HashMap<(u32, String, u8), i64>,
    thread_opens: HashMap<u32, (u32, i64)>,
    cmdlines: HashMap<u32, (String, i64)>,
    held: VecDeque<Held>,
    held_pids: HashMap<u32, usize>,
    /// Pids first seen through another event within [`EARLY_START_MS`] of
    /// their creation, whose ProcessStart has not arrived yet (the sessions
    /// flush independently). Their events wait for it so the engine never
    /// judges a process it does not know (pid → hold deadline).
    early_pids: HashMap<u32, i64>,
    last_devmap_refresh: Instant,
    last_gc: Instant,
    reg_join: RegJoin,
    pending_reg: VecDeque<PendingReg>,
    /// (ts, key lc, value lc) of registry events already emitted with a full
    /// key from ETW (older builds) -- the watcher copy is then dropped.
    reg_full_recent: VecDeque<(i64, String, String)>,
    hints: Hints,
    persist_dedup: Dedup,
    pending_persist: VecDeque<PendingPersist>,
    /// Direct children of the agent with an unspoofed creator, pending the
    /// spawn-registry check at send time: pid → (create FILETIME, creator, seen).
    agent_child_candidates: HashMap<u32, (u64, u32, i64)>,
    /// Integrity level of live processes from their ProcessStart (V-H5).
    integrities: HashMap<u32, Integrity>,
}

/// `kestrel_detect::paths::may_be_sensitive`, guarded: if the detection crate
/// panics (not yet implemented in a dev build) a built-in substring list is
/// used instead so the sensor keeps working.
fn may_be_sensitive(path: &str) -> bool {
    static DETECT_OK: OnceLock<bool> = OnceLock::new();
    let ok = *DETECT_OK.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(|| {
            kestrel_detect::paths::may_be_sensitive(r"C:\Windows\x.txt")
        })
        .is_ok();
        std::panic::set_hook(prev);
        r
    });
    if ok {
        return std::panic::catch_unwind(|| kestrel_detect::paths::may_be_sensitive(path))
            .unwrap_or(false);
    }
    let p = path.to_ascii_lowercase();
    const FALLBACK: &[&str] = &[
        "\\login data",
        "\\cookies",
        "\\web data",
        "\\local state",
        "\\key4.db",
        "\\key3.db",
        "\\logins.json",
        "\\cookies.sqlite",
        "\\local extension settings\\",
        "\\tdata\\",
        "\\discord\\local storage\\",
        "\\.aws\\",
        "\\.azure\\",
        "\\.ssh\\",
        "\\filezilla\\",
        "\\wallets\\",
        "\\steam\\ssfn",
    ];
    FALLBACK.iter().any(|f| p.contains(f))
}

impl Translator {
    pub fn new(s: Arc<Shared>, out: mpsc::Sender<Event>) -> Self {
        Translator {
            s,
            out,
            flows: FlowTable::new(50_000, 10 * 60_000),
            dns: HashMap::new(),
            file_objects: HashMap::new(),
            file_seen: HashMap::new(),
            thread_opens: HashMap::new(),
            cmdlines: HashMap::new(),
            held: VecDeque::new(),
            held_pids: HashMap::new(),
            early_pids: HashMap::new(),
            last_devmap_refresh: Instant::now(),
            last_gc: Instant::now(),
            reg_join: RegJoin::new(),
            pending_reg: VecDeque::new(),
            reg_full_recent: VecDeque::new(),
            hints: Hints::new(),
            persist_dedup: Dedup::default(),
            pending_persist: VecDeque::new(),
            agent_child_candidates: HashMap::new(),
            integrities: HashMap::new(),
        }
    }

    pub fn run(mut self, rx: Receiver<Raw>, stop: Arc<std::sync::atomic::AtomicBool>) {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(r) => {
                    if let Err(e) =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.handle(r)))
                    {
                        tracing::error!("translator panic: {:?}", e.downcast_ref::<String>());
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            let now = now_ms();
            self.release(now);
            self.flush_reg(now, false);
            self.flush_persist(now, false);
            if self.last_gc.elapsed() > Duration::from_secs(10) {
                self.gc();
            }
        }
        // Flush whatever is held.
        self.release(i64::MAX);
        self.flush_reg(now_ms(), true);
        self.flush_persist(i64::MAX, true);
    }

    fn send(&mut self, mut ev: Event) {
        if let EventData::ProcessStart(p) = &mut ev.data {
            if let Some((create_ft, creator, _)) = self.agent_child_candidates.remove(&ev.pid) {
                p.agent_spawned = crate::spawnreg::is_agent_spawned(
                    ev.pid,
                    create_ft,
                    p.ppid,
                    creator,
                    self.s.self_pid,
                );
            }
        }
        match self.out.try_send(ev) {
            Ok(()) => {
                self.s.counters.emitted.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                self.s.counters.out_dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn emit(&mut self, ev: Event) {
        if let EventData::ProcessStart(_) = &ev.data {
            if self.early_pids.remove(&ev.pid).is_some() && self.place_before_early(&ev) {
                return;
            }
        } else if let Some(&until) = self.early_pids.get(&ev.pid) {
            let pid = ev.pid;
            *self.held_pids.entry(pid).or_default() += 1;
            self.held.push_back(Held {
                ev,
                pid,
                deadline: until,
                waiting_cmdline: true,
                waiting_facts: None,
                facts_deadline: 0,
            });
            return;
        }
        let hold_parent = match &ev.data {
            EventData::ProcessStart(p) => self.held_pids.contains_key(&p.ppid),
            _ => false,
        };
        if self.held_pids.contains_key(&ev.pid) || hold_parent {
            let pid = ev.pid;
            *self.held_pids.entry(pid).or_default() += 1;
            self.held.push_back(Held {
                ev,
                pid,
                deadline: 0,
                waiting_cmdline: false,
                waiting_facts: None,
                facts_deadline: 0,
            });
        } else {
            self.send(ev);
        }
    }

    fn hold_start(&mut self, ev: Event, now: i64, cmdline: bool, facts: Option<String>) {
        let pid = ev.pid;
        self.early_pids.remove(&pid);
        *self.held_pids.entry(pid).or_default() += 1;
        let h = Held {
            ev,
            pid,
            deadline: now + CMDLINE_WAIT_MS,
            waiting_cmdline: cmdline,
            facts_deadline: now + super::enrich::FIRST_RUN_BUDGET_MS,
            waiting_facts: facts,
        };
        // Ahead of any events of this pid that arrived before its start.
        match self.held.iter().position(|x| x.pid == pid) {
            Some(i) => {
                self.held.insert(i, h);
                self.release_early_waits(pid);
            }
            None => self.held.push_back(h),
        }
    }

    /// A ProcessStart for a pid whose earlier events are held: queue the start
    /// in front of them and let them go once it does. False if none are held.
    fn place_before_early(&mut self, ev: &Event) -> bool {
        let Some(i) = self.held.iter().position(|x| x.pid == ev.pid) else {
            return false;
        };
        *self.held_pids.entry(ev.pid).or_default() += 1;
        self.held.insert(
            i,
            Held {
                ev: ev.clone(),
                pid: ev.pid,
                deadline: 0,
                waiting_cmdline: false,
                waiting_facts: None,
                facts_deadline: 0,
            },
        );
        self.release_early_waits(ev.pid);
        true
    }

    /// Events of `pid` held only for its (now arrived) ProcessStart.
    fn release_early_waits(&mut self, pid: u32) {
        for h in self.held.iter_mut() {
            if h.pid == pid && !matches!(h.ev.data, EventData::ProcessStart(_)) {
                h.waiting_cmdline = false;
            }
        }
    }

    /// Patch enrichment facts into a held ProcessStart.
    fn apply_facts(ev: &mut Event, f: &super::enrich::FileFacts) {
        if let EventData::ProcessStart(p) = &mut ev.data {
            p.signer = f.signer.clone();
            p.signed = f.signed;
            p.sha256 = f.sha256.clone();
            p.motw_zone = f.motw_zone;
            p.file_size = f.file_size;
        }
    }

    fn release(&mut self, now: i64) {
        loop {
            let enricher = self.s.enricher.clone();
            let Some(front) = self.held.front_mut() else {
                break;
            };
            if let Some(img) = front.waiting_facts.clone() {
                let facts = enricher.lookup_file(&img);
                let ready = facts.as_ref().is_some_and(|f| f.ready_for_start());
                if ready || front.facts_deadline <= now {
                    if let Some(f) = &facts {
                        Self::apply_facts(&mut front.ev, f);
                    }
                    let complete = facts.as_ref().is_some_and(|f| {
                        f.ready_for_start() && f.sha256.is_some() && !f.revocation_pending
                    });
                    if !complete {
                        // Late facts (hash, signature, revocation) reach the engine later.
                        enricher.watch(&img, front.ev.guid.clone(), front.pid, facts.clone());
                    }
                    front.waiting_facts = None;
                } else {
                    break;
                }
            }
            if front.waiting_cmdline && front.deadline > now {
                break;
            }
            let h = self.held.pop_front().expect("front exists");
            if let Some(c) = self.held_pids.get_mut(&h.pid) {
                *c -= 1;
                if *c == 0 {
                    self.held_pids.remove(&h.pid);
                }
            }
            self.send(h.ev);
        }
    }

    fn gc(&mut self) {
        let now = now_ms();
        self.last_gc = Instant::now();
        if let Ok(mut t) = self.s.tracker.write() {
            t.gc(now);
        }
        self.flows.expire(now);
        self.early_pids.retain(|_, until| *until > now);
        self.dns.retain(|_, m| {
            m.retain(|_, (_, ts)| now - *ts < DNS_TTL_MS);
            !m.is_empty()
        });
        self.file_objects
            .retain(|_, (_, _, ts)| now - *ts < 10 * 60_000);
        self.file_seen.retain(|_, ts| now - *ts < FILE_DEDUP_MS);
        self.thread_opens
            .retain(|_, (_, ts)| now - *ts < THREAD_OPEN_WINDOW_MS);
        self.cmdlines.retain(|_, (_, ts)| now - *ts < 30_000);
        self.agent_child_candidates
            .retain(|_, (_, _, seen)| now - *seen < 60_000);
        self.reg_join.expire(now);
        self.hints.expire(now);
        while self
            .reg_full_recent
            .front()
            .is_some_and(|(t, _, _)| now - *t > 10_000)
        {
            self.reg_full_recent.pop_front();
        }
        if self.file_objects.len() > 100_000 {
            self.file_objects.clear();
        }
    }

    fn dos(&mut self, nt: &str) -> String {
        let (p, known) = self
            .s
            .devmap
            .read()
            .map(|m| m.to_dos(nt))
            .unwrap_or((nt.to_string(), true));
        if !known && self.last_devmap_refresh.elapsed() > Duration::from_secs(30) {
            self.last_devmap_refresh = Instant::now();
            let fresh = super::devmap::build();
            let p2 = fresh.to_dos(nt).0;
            if let Ok(mut m) = self.s.devmap.write() {
                *m = fresh;
            }
            return p2;
        }
        p
    }

    fn guid(&self, pid: u32, ts: i64) -> ProcessGuid {
        self.s
            .tracker
            .read()
            .map(|t| t.guid_for(pid, ts).0)
            .unwrap_or_else(|_| ProcessGuid::derive(&self.s.boot_id, pid, 0))
    }

    fn image_of(&self, pid: u32) -> Option<String> {
        if let Some(i) = self
            .s
            .tracker
            .read()
            .ok()
            .and_then(|t| t.get(pid).map(|e| e.image.clone()))
        {
            if !i.is_empty() {
                return Some(i);
            }
        }
        let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        process_image(&h)
    }

    /// Ensure an unknown live pid gets registered (missed start event).
    fn ensure_known(&mut self, pid: u32) {
        if pid == 0 || pid == 4 {
            return;
        }
        let known = self
            .s
            .tracker
            .read()
            .map(|t| t.get(pid).is_some())
            .unwrap_or(true);
        if known {
            return;
        }
        if let Some(lp) = live_proc(pid) {
            let created = filetime_to_ms(lp.create_ft);
            if let Ok(mut t) = self.s.tracker.write() {
                t.on_start(pid, created, lp.image.as_deref().unwrap_or(""), 0);
            }
            let now = now_ms();
            if now - created <= EARLY_START_MS {
                self.early_pids.insert(pid, now + EARLY_HOLD_MS);
            }
        }
    }

    /// Integrity of a live process: from its ProcessStart, else its token.
    fn integrity_of(&self, pid: u32) -> Option<Integrity> {
        if pid == 4 {
            return Some(Integrity::System);
        }
        if let Some(i) = self.integrities.get(&pid) {
            return Some(*i);
        }
        let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
        process_token_info(&h).1
    }

    fn base(&self, ts: i64, pid: u32, data: EventData) -> Event {
        Event {
            ts,
            pid,
            guid: self.guid(pid, ts),
            data,
        }
    }

    fn actor_is_noise(&self, pid: u32) -> bool {
        if pid == self.s.self_pid || pid == 0 || pid == 4 {
            return true;
        }
        match self
            .s
            .tracker
            .read()
            .ok()
            .and_then(|t| t.get(pid).map(|e| e.image.clone()))
        {
            // Location-only (exact path on the system volume): this only
            // drops high-volume noise; response safety re-checks signatures.
            Some(img) => {
                let sd = kestrel_common::system_drive();
                filters::is_critical_location(&img, sd)
                    && !img.to_ascii_lowercase().ends_with("svchost.exe")
                    || filters::is_security_product_location(&img, sd)
            }
            None => false,
        }
    }

    fn target(&mut self, target_pid: u32, access: u32, ts: i64) -> TargetProcess {
        self.target_rc(target_pid, access, ts, 0)
    }

    fn target_rc(
        &mut self,
        target_pid: u32,
        access: u32,
        ts: i64,
        return_code: u32,
    ) -> TargetProcess {
        self.ensure_known(target_pid);
        let (g, known) = self
            .s
            .tracker
            .read()
            .map(|t| t.guid_for(target_pid, ts))
            .unwrap_or((ProcessGuid::derive(&self.s.boot_id, target_pid, 0), false));
        TargetProcess {
            target_pid,
            target_guid: if known { Some(g) } else { None },
            target_image: self.image_of(target_pid).unwrap_or_default(),
            granted_access: access,
            return_code,
        }
    }

    fn sensitive(&self, path: &str) -> bool {
        let k = norm_key(path);
        if let Ok(c) = self.s.canaries.read() {
            if c.iter()
                .any(|p| k == *p || k.starts_with(&format!("{p}\\")))
            {
                return true;
            }
        }
        may_be_sensitive(path) || filters::is_extra_sensitive(path)
    }

    pub fn handle(&mut self, r: Raw) {
        let now = now_ms();
        match r {
            Raw::ProcStart {
                ts,
                pid,
                ppid,
                creator_pid,
                create_ft,
                session,
                label_sid,
                image_nt,
                cmdline,
                user_sid,
                token_integrity,
            } => {
                let create_ft = if create_ft == 0 {
                    live_proc(pid).map(|l| l.create_ft).unwrap_or(0)
                } else {
                    create_ft
                };
                // V-H1: a direct child of the agent whose real creator (event
                // header) is the agent too. Whether the agent recorded it is
                // checked when the start is sent (the spawning thread records
                // it right after CreateProcess returns, possibly after the
                // ETW event got here).
                let agent_child =
                    pid != self.s.self_pid && ppid == self.s.self_pid && creator_pid == ppid;
                if agent_child {
                    if self.agent_child_candidates.len() > 1024 {
                        self.agent_child_candidates.clear();
                    }
                    self.agent_child_candidates
                        .insert(pid, (create_ft, creator_pid, now));
                }
                let start_ts = if create_ft == 0 {
                    ts
                } else {
                    filetime_to_ms(create_ft)
                };
                let image = self.dos(&image_nt);
                let guid = self
                    .s
                    .tracker
                    .write()
                    .map(|mut t| t.on_start(pid, start_ts, &image, ppid))
                    .unwrap_or_default();
                let parent_guid = self.s.tracker.read().ok().and_then(|t| {
                    t.at(ppid, start_ts)
                        .filter(|e| e.start_ts <= start_ts)
                        .map(|e| e.guid.clone())
                });
                let cmdline = cmdline.or_else(|| self.cmdlines.remove(&pid).map(|(c, _)| c));
                // H7: never emit a first-seen image with unknown facts if
                // they can be had within the budget.
                let cached = self.s.enricher.lookup_file(&image);
                let wait_facts =
                    image.contains('\\') && !cached.as_ref().is_some_and(|f| f.ready_for_start());
                if wait_facts {
                    self.s.enricher.request_priority(&image);
                }
                let facts = cached.clone().unwrap_or_default();
                let user = user_sid.as_deref().map(|sid| {
                    self.s
                        .enricher
                        .user_or_request(sid)
                        .unwrap_or_else(|| sid.to_string())
                });
                let integrity = label_sid
                    .as_deref()
                    .and_then(integrity_from_label_sid)
                    .or(token_integrity);
                if let Some(i) = integrity {
                    if self.integrities.len() > 65_536 {
                        self.integrities.clear();
                    }
                    self.integrities.insert(pid, i);
                }
                let waiting = cmdline.is_none();
                let guid_for_watch = guid.clone();
                self.hints.on_process_start(
                    start_ts,
                    pid,
                    &image,
                    cmdline.as_deref().unwrap_or(""),
                );
                if image.to_ascii_lowercase().ends_with(r"\system32\lsass.exe")
                    && filters::is_critical_location(&image, kestrel_common::system_drive())
                {
                    self.s.counters.lsass_pid.store(pid, Ordering::Relaxed);
                }
                let ev = Event {
                    ts: start_ts,
                    pid,
                    guid,
                    data: EventData::ProcessStart(ProcessStart {
                        ppid,
                        parent_guid,
                        image: image.clone(),
                        cmdline: cmdline.unwrap_or_default(),
                        user,
                        integrity,
                        session_id: session,
                        signer: facts.signer,
                        signed: facts.signed,
                        sha256: facts.sha256,
                        motw_zone: facts.motw_zone,
                        file_size: facts.file_size,
                        agent_spawned: false,
                    }),
                };
                if pid == self.s.self_pid {
                    return;
                }
                // Not recorded yet: hold briefly (as if waiting for the
                // command line) so the registry check at send time sees it.
                let wait_registry = agent_child && !crate::spawnreg::is_recorded(pid, create_ft);
                if waiting || wait_facts || wait_registry {
                    self.hold_start(
                        ev,
                        now,
                        waiting || wait_registry,
                        wait_facts.then(|| image.clone()),
                    );
                } else {
                    if let Some(f) = cached.filter(|f| f.revocation_pending || f.sha256.is_none()) {
                        self.s.enricher.watch(&image, guid_for_watch, pid, Some(f));
                    }
                    self.emit(ev);
                }
            }
            Raw::CmdLine { pid, cmdline } => {
                let mut patched = false;
                for h in self.held.iter_mut() {
                    if h.pid == pid && h.waiting_cmdline {
                        if let EventData::ProcessStart(p) = &mut h.ev.data {
                            if p.cmdline.is_empty() {
                                p.cmdline = cmdline.clone();
                                self.hints
                                    .on_process_start(h.ev.ts, pid, &p.image, &cmdline);
                            }
                        }
                        h.waiting_cmdline = false;
                        patched = true;
                    }
                }
                if !patched {
                    self.cmdlines.insert(pid, (cmdline, now));
                }
            }
            Raw::ProcStop {
                ts,
                pid,
                create_ft,
                exit_code,
            } => {
                let start = if create_ft != 0 {
                    Some(filetime_to_ms(create_ft))
                } else {
                    None
                };
                let guid = match start {
                    Some(s) => ProcessGuid::derive(&self.s.boot_id, pid, s),
                    None => self.guid(pid, ts),
                };
                if let Ok(mut t) = self.s.tracker.write() {
                    t.on_stop(pid, start, ts);
                }
                // `integrities` keeps the entry: hint processes (sc.exe,
                // schtasks.exe) exit before their persistence event arrives.
                self.flows.forget_pid(pid);
                self.dns.remove(&pid);
                self.thread_opens.remove(&pid);
                if pid == self.s.self_pid {
                    return;
                }
                self.emit(Event {
                    ts,
                    pid,
                    guid,
                    data: EventData::ProcessStop {
                        exit_code: exit_code.map(|c| c as i32),
                    },
                });
            }
            Raw::ImageLoad { ts, pid, image_nt } => {
                if pid == self.s.self_pid {
                    return;
                }
                let path = self.dos(&image_nt);
                if !filters::should_emit_image_load(&path) {
                    return;
                }
                if !self.actor_is_noise(pid) {
                    self.hints.on_image_load(ts, pid, &path);
                }
                let facts = self
                    .s
                    .enricher
                    .file_or_request(&path, false)
                    .unwrap_or_default();
                let ev = self.base(
                    ts,
                    pid,
                    EventData::ImageLoad {
                        path,
                        signer: facts.signer,
                        signed: facts.signed,
                    },
                );
                self.emit(ev);
            }
            Raw::FileCreate {
                ts,
                pid,
                file_object,
                name_nt,
                create_options,
            } => {
                if file_object != 0 {
                    self.file_objects.remove(&(pid, file_object));
                }
                if pid == self.s.self_pid || pid == 4 {
                    return;
                }
                let path = self.dos(&name_nt);
                if !self.sensitive(&path) {
                    return;
                }
                let op = file_op_for_path(create_options, filters::is_persistence_drop_path(&path));
                if file_object != 0 {
                    self.file_objects
                        .insert((pid, file_object), (path.clone(), false, ts));
                }
                let key = (pid, norm_key(&path), op as u8);
                if let Some(prev) = self.file_seen.get(&key) {
                    if ts - prev < FILE_DEDUP_MS {
                        return;
                    }
                }
                self.file_seen.insert(key, ts);
                self.ensure_known(pid);
                let ev = self.base(ts, pid, EventData::FileAccess { path, op });
                self.emit(ev);
            }
            Raw::FileRead {
                ts,
                pid,
                file_object,
            } => {
                let Some((path, reported, _)) = self.file_objects.get_mut(&(pid, file_object))
                else {
                    return;
                };
                if *reported {
                    return;
                }
                *reported = true;
                let path = path.clone();
                let ev = self.base(
                    ts,
                    pid,
                    EventData::FileAccess {
                        path,
                        op: FileOp::Read,
                    },
                );
                self.emit(ev);
            }
            Raw::NetConnect {
                ts,
                pid,
                dst,
                dport,
                sport,
            } => {
                if pid == self.s.self_pid || pid == 0 || pid == 4 {
                    return;
                }
                let k = FlowKey {
                    pid,
                    tcp: true,
                    dst,
                    dport,
                    sport,
                };
                if let FlowEmit::New(b) = self.flows.on_connect(k, ts) {
                    self.net_event(ts, pid, NetProto::Tcp, dst, dport, sport, b);
                }
            }
            Raw::NetSend {
                ts,
                pid,
                tcp,
                dst,
                dport,
                sport,
                size,
            } => {
                if pid == self.s.self_pid || pid == 0 || pid == 4 {
                    return;
                }
                if !tcp && dst.is_loopback() {
                    return;
                }
                let k = FlowKey {
                    pid,
                    tcp,
                    dst,
                    dport,
                    sport: if tcp { sport } else { 0 },
                };
                match self.flows.on_send(k, size, ts) {
                    FlowEmit::New(b) => self.net_event(
                        ts,
                        pid,
                        if tcp { NetProto::Tcp } else { NetProto::Udp },
                        dst,
                        dport,
                        sport,
                        b,
                    ),
                    FlowEmit::Update(total) => self.net_event(
                        ts,
                        pid,
                        if tcp { NetProto::Tcp } else { NetProto::Udp },
                        dst,
                        dport,
                        sport,
                        Some(total),
                    ),
                    FlowEmit::Nothing => {}
                }
            }
            Raw::NetClose {
                pid,
                dst,
                dport,
                sport,
            } => {
                self.flows.on_close(&FlowKey {
                    pid,
                    tcp: true,
                    dst,
                    dport,
                    sport,
                });
            }
            Raw::OpenProcess {
                ts,
                pid,
                target_pid,
                access,
                return_code,
            } => {
                if self.actor_is_noise(pid) {
                    return;
                }
                self.ensure_known(pid);
                let t = self.target_rc(target_pid, access, ts, return_code);
                let ev = self.base(ts, pid, EventData::ProcessAccess(t));
                self.emit(ev);
            }
            Raw::OpenThread {
                ts,
                pid,
                target_pid,
                access,
            } => {
                if access & THREAD_SET_CONTEXT != 0 && pid != self.s.self_pid {
                    self.thread_opens.insert(pid, (target_pid, ts));
                }
            }
            Raw::SetContext { ts, pid } => {
                let Some(&(target_pid, ots)) = self.thread_opens.get(&pid) else {
                    return;
                };
                if ts - ots > THREAD_OPEN_WINDOW_MS || target_pid == pid || self.actor_is_noise(pid)
                {
                    return;
                }
                let t = self.target(target_pid, THREAD_SET_CONTEXT, ts);
                let ev = self.base(ts, pid, EventData::ThreadContext(t));
                self.emit(ev);
            }
            Raw::Terminate {
                ts,
                pid,
                target_pid,
            } => {
                if self.actor_is_noise(pid) {
                    return;
                }
                let t = self.target(target_pid, PROCESS_TERMINATE, ts);
                let ev = self.base(ts, pid, EventData::ProcessAccess(t));
                self.emit(ev);
            }
            Raw::RegEtw {
                ts,
                pid,
                key_object,
                key,
                value_name,
                op,
                ty,
                data,
            } => {
                self.reg_join.record(
                    ts,
                    pid,
                    key_object,
                    &value_name,
                    op == RegistryOp::DeleteValue,
                );
                self.flush_reg(now, false);
                if key.is_empty() {
                    return;
                }
                // Older builds: the event names the key; emit it directly.
                if self.reg_full_recent.len() > 4096 {
                    self.reg_full_recent.pop_front();
                }
                self.reg_full_recent.push_back((
                    ts,
                    key.to_ascii_lowercase(),
                    value_name.to_ascii_lowercase(),
                ));
                self.ensure_known(pid);
                let ev = self.base(
                    ts,
                    pid,
                    EventData::RegistrySet {
                        attribution: Default::default(),
                        key,
                        value_name,
                        data: if op == RegistryOp::Set {
                            render_sysmon(ty, &data)
                        } else {
                            None
                        },
                        op,
                    },
                );
                self.emit(ev);
            }
            Raw::RegChange {
                ts,
                key,
                value_name,
                op,
                ty,
                data,
                reopened,
            } => {
                if self.pending_reg.len() >= MAX_PENDING_REG {
                    // Bounded: emit everything pending instead of growing.
                    self.flush_reg(now, true);
                }
                self.pending_reg.push_back(PendingReg {
                    deadline: now + PENDING_WAIT_MS,
                    ts,
                    key,
                    value_name,
                    op,
                    ty,
                    data,
                    reopened,
                });
                self.flush_reg(now, false);
            }
            Raw::FileActivity { ts, pid, mut act } => {
                if pid == self.s.self_pid {
                    return;
                }
                act.sample_paths = act.sample_paths.iter().map(|p| self.dos(p)).collect();
                act.canary_hits = act.canary_hits.iter().map(|p| self.dos(p)).collect();
                if pid == 4 {
                    // System process: a remote SMB client wrote these files.
                    // No local process may be blamed (V-H9).
                    act.remote_writer = true;
                }
                if pid == 0 || pid == 4 {
                    // Decoy modified with no attributable local writer, or a
                    // remote writer: telemetry only.
                    self.send(Event {
                        ts,
                        pid: 0,
                        guid: ProcessGuid::default(),
                        data: EventData::FileActivity(act),
                    });
                    return;
                }
                self.ensure_known(pid);
                let ev = self.base(ts, pid, EventData::FileActivity(act));
                self.emit(ev);
            }
            Raw::Persist {
                ts,
                logger_pid,
                record,
                task,
            } => {
                if self
                    .persist_dedup
                    .seen(&record.dedup_key_with(task.as_ref()), ts)
                {
                    return;
                }
                if self.pending_persist.len() >= MAX_PENDING_PERSIST {
                    self.flush_persist(i64::MAX, true);
                }
                self.pending_persist.push_back(PendingPersist {
                    release_at: now + PERSIST_HOLD_MS,
                    ts,
                    logger_pid,
                    record,
                    task,
                });
            }
            Raw::Dns {
                ts,
                pid,
                qname,
                results,
            } => {
                if pid == self.s.self_pid {
                    return;
                }
                let answers = parse_dns_results(&results);
                let m = self.dns.entry(pid).or_default();
                for a in &answers {
                    if let Ok(ip) = a.parse::<IpAddr>() {
                        m.insert(ip, (qname.clone(), ts));
                    }
                }
                if m.len() > 4096 {
                    m.clear();
                }
                let ev = self.base(ts, pid, EventData::DnsQuery { qname, answers });
                self.emit(ev);
            }
            Raw::Dpapi {
                ts,
                caller_pid,
                caller_create_ft,
                description,
            } => {
                if caller_pid == self.s.self_pid {
                    return;
                }
                let guid = match caller_create_ft.filter(|&f| f > 0) {
                    Some(ft) => {
                        ProcessGuid::derive(&self.s.boot_id, caller_pid, filetime_to_ms(ft))
                    }
                    None => self.guid(caller_pid, ts),
                };
                self.emit(Event {
                    ts,
                    pid: caller_pid,
                    guid,
                    data: EventData::DpapiUnprotect { description },
                });
            }
            Raw::Script { ts, pid, text } => {
                if pid == self.s.self_pid {
                    return;
                }
                self.hints.on_script(ts, pid, &text);
                let ev = self.base(
                    ts,
                    pid,
                    EventData::ScriptBlock {
                        engine: "powershell".into(),
                        content: text,
                    },
                );
                self.emit(ev);
            }
            Raw::Sysmon(c) => {
                if c.source_pid == self.s.self_pid {
                    return;
                }
                let ts = c.time_ms.unwrap_or(now);
                self.ensure_known(c.source_pid);
                let mut t = self.target(c.target_pid, c.granted_access, ts);
                if t.target_image.is_empty() {
                    t.target_image = c.target_image.clone();
                }
                let data = match c.kind {
                    SysmonKind::ProcessAccess => EventData::ProcessAccess(t),
                    SysmonKind::RemoteThread => EventData::RemoteThread(t),
                };
                let ev = self.base(ts, c.source_pid, data);
                self.emit(ev);
            }
            Raw::Tamper { kind, detail } => {
                let pid = self.s.self_pid;
                let ev = self.base(now, pid, EventData::Tamper { kind, detail });
                // Tamper events are never held.
                self.send(ev);
            }
        }
    }

    /// Emit registry-watcher changes that found their writer, and (when
    /// `force` or past their deadline) those that did not, with pid 0.
    fn flush_reg(&mut self, now: i64, force: bool) {
        if self.pending_reg.is_empty() {
            return;
        }
        let mut keep = VecDeque::with_capacity(self.pending_reg.len());
        while let Some(p) = self.pending_reg.pop_front() {
            let key_lc = p.key.to_ascii_lowercase();
            let value_lc = p.value_name.to_ascii_lowercase();
            if self
                .reg_full_recent
                .iter()
                .any(|(t, k, v)| *k == key_lc && *v == value_lc && (t - p.ts).abs() < 5_000)
            {
                continue; // already emitted from ETW with the full key
            }
            // V-H6 / NEW-1: all candidates in the window are ranked; one
            // distinct writer pid is Exact, two or more Heuristic. Always wait
            // for the deadline: a competing write delivered late must still
            // be counted, or the first (decoy) write would look unambiguous.
            // V-H7: a re-created / renamed watched key joins exact-only.
            if !force && p.deadline > now {
                keep.push_back(p);
                continue;
            }
            let premature = p.deadline > now;
            let mut writer = self
                .reg_join
                .attribute(&p.key, &p.value_name, p.op, p.ts, p.reopened);
            // A forced flush (pending queue full — attacker-inducible) decides
            // before the window closed: never Exact then.
            if premature {
                if let Some(w) = writer.as_mut() {
                    w.attribution = Attribution::Heuristic;
                }
            }
            let data = match p.op {
                RegistryOp::Set => p.data.as_deref().and_then(|d| render_sysmon(p.ty, d)),
                _ => None,
            };
            let attribution = writer.map_or(Attribution::None, |w| w.attribution);
            let ev_data = EventData::RegistrySet {
                attribution,
                key: p.key,
                value_name: p.value_name,
                data,
                op: p.op,
            };
            match writer {
                // Never dropped, even when the agent wrote it (hardening):
                // emitted as telemetry with the agent as the writer, so a
                // spoofed join can no longer hide a change (V-H6).
                Some(w) => {
                    self.s
                        .counters
                        .reg_attributed
                        .fetch_add(1, Ordering::Relaxed);
                    self.ensure_known(w.pid);
                    let ev = self.base(p.ts, w.pid, ev_data);
                    if w.pid == self.s.self_pid {
                        self.send(ev);
                    } else {
                        self.emit(ev);
                    }
                }
                None => {
                    self.reg_join.note_unattributed();
                    self.s
                        .counters
                        .reg_unattributed
                        .fetch_add(1, Ordering::Relaxed);
                    // Unknown writer: pid 0 / empty guid, Attribution::None.
                    // The engine may remediate the value but never blames a
                    // process for it.
                    self.send(Event {
                        ts: p.ts,
                        pid: 0,
                        guid: ProcessGuid::default(),
                        data: ev_data,
                    });
                }
            }
        }
        self.pending_reg = keep;
    }

    /// Emit held persistence events, attributed to the most recent creator
    /// hint (schtasks / sc / PowerShell / taskschd.dll load) within 5 s,
    /// else to the logging service process.
    fn flush_persist(&mut self, now: i64, force: bool) {
        while self
            .pending_persist
            .front()
            .is_some_and(|p| force || p.release_at <= now)
        {
            let Some(p) = self.pending_persist.pop_front() else {
                break;
            };
            // V-H5: the creator is a correlation (most recent plausible
            // hint), so it is Heuristic. A service install needs High or
            // System integrity: hints from lower-integrity processes are
            // skipped. Without a hint the event stays on the logging
            // service (Task Scheduler / services.exe / WMI host) and the
            // creator is unknown (`Attribution::None`). None of these events
            // names the creating pid itself, so nothing here is Exact.
            let kind = p.record.kind();
            let hint = match kind {
                crate::persist::HintKind::Service => {
                    let hints = std::mem::take(&mut self.hints);
                    let r = hints.creator_where(kind, p.ts, |pid| {
                        matches!(
                            self.integrity_of(pid),
                            Some(Integrity::High | Integrity::System)
                        )
                    });
                    self.hints = hints;
                    r
                }
                _ => self.hints.creator(kind, p.ts),
            };
            let (pid, attribution) = match hint {
                Some(pid) => (pid, Attribution::Heuristic),
                None => (p.logger_pid, Attribution::None),
            };
            let data = match p.record {
                PersistRecord::Task { name, op, user } => {
                    let t = p.task.unwrap_or_default();
                    EventData::TaskRegistered(TaskChange {
                        attribution,
                        name,
                        op,
                        user: user.or(t.user),
                        actions: t.actions,
                        hidden: t.hidden,
                        triggers: t.triggers,
                    })
                }
                PersistRecord::Service(mut s) => {
                    s.attribution = attribution;
                    EventData::ServiceInstalled(s)
                }
                PersistRecord::Wmi(mut w) => {
                    w.attribution = attribution;
                    EventData::WmiSubscription(w)
                }
            };
            if pid == self.s.self_pid {
                // The agent's own change (hardening): telemetry, never held.
                let ev = self.base(p.ts, pid, data);
                self.send(ev);
                continue;
            }
            self.s
                .counters
                .persist_events
                .fetch_add(1, Ordering::Relaxed);
            self.ensure_known(pid);
            let ev = self.base(p.ts, pid, data);
            self.emit(ev);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn net_event(
        &mut self,
        ts: i64,
        pid: u32,
        proto: NetProto,
        dst: IpAddr,
        dport: u16,
        sport: u16,
        bytes: Option<u64>,
    ) {
        let dst_host = self
            .dns
            .get(&pid)
            .and_then(|m| m.get(&dst))
            .map(|(q, _)| q.clone());
        let ev = self.base(
            ts,
            pid,
            EventData::NetConnect {
                proto,
                dst_ip: dst.to_string(),
                dst_port: dport,
                src_port: sport,
                dst_host,
                bytes_sent: bytes,
            },
        );
        self.emit(ev);
    }
}
