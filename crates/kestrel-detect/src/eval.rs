//! Detection evaluation harness (offline, deterministic, platform independent).
//!
//! Replays event streams through a fresh [`Engine`] and reports what fired:
//!
//! * [`Replayer`] feeds events in stream order, drives [`Engine::tick`] on a
//!   250 ms grid of *event* time (never wall time) and drains open suspend
//!   windows at the end, so a replay gives the same result on every run.
//! * [`RunReport`] counts per rule: alerts, distinct processes and images,
//!   severities and the response actions the engine asked for (the
//!   "would-be" actions when the policy is Protect).
//! * Corpus scenarios ([`load_corpus`], [`evaluate`]) are judged against a
//!   sidecar `<name>.expect.json` ([`Expectation`]): `malicious/` must raise
//!   the expected alerts, `benign/` and `benign-lookalike/` must stay at or
//!   below Low with no Protect-mode action except what the expect file lists.
//!
//! Input lines are [`Event`] JSON (the fixture format, which is also the
//! `raw` column of the server's telemetry store). A telemetry row that
//! carries `repeat_count` (agents 1.1.7+ upload one summary row for N
//! identical events) is expanded back into N events (see [`parse_line`]).
//!
//! See `docs/DETECTION-QUALITY.md` for how to run it and the expect format.

use crate::{Engine, HostContext, Output};
use kestrel_common::{Event, EventData, Policy, ResponseAction, RuleBundle, RuleMode, Severity};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

/// Tick grid (the agent ticks the engine about every 250 ms).
pub const TICK_MS: i64 = 250;
/// Event time the replay advances past the last event to resolve open
/// suspend windows and correlation timers.
pub const DRAIN_MS: i64 = 10 * 60_000;
/// Upper bound on events re-created from one `repeat_count` row.
pub const MAX_REPEAT_EXPANSION: u32 = 100_000;
/// Alerts kept verbatim per run (statistics always count all of them).
pub const DEFAULT_KEEP_ALERTS: usize = 200_000;

/// Host context used for replays: a neutral host name and the agent's
/// default install path (so the agent's own events are recognised).
pub fn eval_host() -> HostContext {
    HostContext {
        boot_id: "eval".into(),
        hostname: "WS-01".into(),
        agent_image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
        agent_pid: 0,
        server_ips: vec![],
        system_drive: Some('c'),
    }
}

/// Default policy with every builtin rule forced to `mode`.
pub fn policy_all(mode: RuleMode) -> Policy {
    let mut p = Policy::default();
    for m in Engine::catalog() {
        p.rules.insert(m.id.clone(), mode);
    }
    p
}

/// The policies the harness knows by name: `audit` (every rule Audit),
/// `protect` (every rule Protect) and `default` (shipped default modes).
pub fn named_policy(name: &str) -> Option<Policy> {
    match name {
        "audit" => Some(policy_all(RuleMode::Audit)),
        "protect" => Some(policy_all(RuleMode::Protect)),
        "default" => Some(Policy::default()),
        _ => None,
    }
}

// ---------------------------------------------------------------- input

/// Parse one input line. Returns `Ok(None)` for blank lines and `#` / `//`
/// comments, else the event and how many identical events it stands for
/// (`repeat_count`, at least 1, capped at [`MAX_REPEAT_EXPANSION`]).
pub fn parse_line(line: &str) -> Result<Option<(Event, u32)>, String> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
        return Ok(None);
    }
    if !t.contains("\"repeat_count\"") {
        return serde_json::from_str::<Event>(t)
            .map(|e| Some((e, 1)))
            .map_err(|e| e.to_string());
    }
    let mut v: serde_json::Value = serde_json::from_str(t).map_err(|e| e.to_string())?;
    let mut count = 1u32;
    if let Some(m) = v.as_object_mut() {
        if let Some(c) = m.remove("repeat_count").and_then(|c| c.as_u64()) {
            count = c.clamp(1, MAX_REPEAT_EXPANSION as u64) as u32;
        }
        m.remove("repeat_first_ts");
    }
    serde_json::from_value::<Event>(v)
        .map(|e| Some((e, count)))
        .map_err(|e| e.to_string())
}

/// Read a scenario / fixture file (`.jsonl`) into events. Repeat rows are
/// expanded (all copies at the row's timestamp: the stream stays ordered).
pub fn load_events_file(path: &Path) -> Result<Vec<Event>, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (i, line) in s.lines().enumerate() {
        match parse_line(line) {
            Ok(Some((e, n))) => {
                for _ in 1..n {
                    out.push(e.clone());
                }
                out.push(e);
            }
            Ok(None) => {}
            Err(err) => return Err(format!("{}:{}: {err}", path.display(), i + 1)),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------- seeding

/// Approximates the agent's start-up process snapshot for a telemetry
/// stream. Processes that were already running when the agent (re)started
/// have no `process_start` in telemetry; the live agent seeds them from a
/// snapshot (image, Authenticode), the replay would otherwise see them as
/// processes with an empty image. Learned from the stream itself (first
/// pass): the image from other processes' `target_guid` / `target_image`
/// (handle opens, injections), the signature from any `process_start` of
/// the same image path. Unresolved orphans stay unknown.
#[derive(Debug, Default)]
pub struct SeedBuilder {
    started: HashSet<String>,
    /// guid → (first ts, pid)
    first_seen: HashMap<String, (i64, u32)>,
    /// guid → image named by another process's event
    target_images: HashMap<String, String>,
    /// lower-case image → (signer, signed, sha256, user)
    by_image: HashMap<String, kestrel_common::ProcessStart>,
    /// Facts from [Self::know_image] (external sources), for late enrichment.
    external: HashMap<String, (Option<String>, kestrel_common::SignatureState)>,
}

/// Result of [`SeedBuilder::finish`].
#[derive(Debug, Default)]
pub struct Seeds {
    pub map: HashMap<String, kestrel_common::ProcessInfo>,
    /// Processes seen without a `process_start`.
    pub orphans: usize,
    /// Of those, processes whose image was resolved.
    pub resolved: usize,
    /// Of those, processes whose signature came from a start of the same image.
    pub with_signature: usize,
    /// Of those, `%SystemRoot%` images without a start of the same image,
    /// assumed signed by "Microsoft Windows" (what the snapshot's catalog
    /// check reports on a healthy system; lsass.exe, csrss.exe, …).
    pub assumed_windows_signed: usize,
    /// Signature facts known from outside the stream (lower-case image →
    /// signer, state): applied to a process_start whose signature is
    /// unknown, the way the live agent's late enrichment
    /// (Engine::enrich_process) does (fix round 2026-10-25).
    pub late_facts: HashMap<String, (Option<String>, kestrel_common::SignatureState)>,
}

impl SeedBuilder {
    /// Signature facts of an image known from another source (e.g. the
    /// live agent's alerts, which carry the snapshot's Authenticode result).
    /// A `process_start` of the same image in the stream takes precedence.
    pub fn know_image(
        &mut self,
        image: &str,
        signer: Option<String>,
        signed: kestrel_common::SignatureState,
    ) {
        if signed == kestrel_common::SignatureState::Unknown {
            return;
        }
        self.external
            .insert(image.to_ascii_lowercase(), (signer.clone(), signed));
        self.by_image
            .entry(image.to_ascii_lowercase())
            .or_insert_with(|| kestrel_common::ProcessStart {
                image: image.to_string(),
                signer,
                signed,
                ..Default::default()
            });
    }

    pub fn learn(&mut self, e: &Event) {
        self.first_seen
            .entry(e.guid.0.clone())
            .or_insert((e.ts, e.pid));
        match &e.data {
            EventData::ProcessStart(p) => {
                self.started.insert(e.guid.0.clone());
                if p.signed != kestrel_common::SignatureState::Unknown {
                    self.by_image
                        .insert(p.image.to_ascii_lowercase(), p.clone());
                }
            }
            EventData::ProcessAccess(t)
            | EventData::RemoteThread(t)
            | EventData::ThreadContext(t)
            | EventData::DebugAttach(t) => {
                if let Some(g) = &t.target_guid {
                    if !t.target_image.is_empty() && !self.target_images.contains_key(&g.0) {
                        self.target_images
                            .insert(g.0.clone(), t.target_image.clone());
                    }
                }
            }
            _ => {}
        }
    }

    pub fn finish(self) -> Seeds {
        let mut s = Seeds {
            late_facts: self.external.clone(),
            ..Default::default()
        };
        for (g, (ts, pid)) in &self.first_seen {
            if self.started.contains(g) {
                continue;
            }
            s.orphans += 1;
            let Some(image) = self.target_images.get(g) else {
                continue;
            };
            s.resolved += 1;
            let known = self.by_image.get(&image.to_ascii_lowercase());
            let class = kestrel_common::PathClass::of(image);
            let assume_windows = known.is_none()
                && matches!(
                    class,
                    kestrel_common::PathClass::System | kestrel_common::PathClass::Windows
                );
            if known.is_some() {
                s.with_signature += 1;
            } else if assume_windows {
                s.assumed_windows_signed += 1;
            }
            s.map.insert(
                g.clone(),
                kestrel_common::ProcessInfo {
                    guid: kestrel_common::ProcessGuid(g.clone()),
                    pid: *pid,
                    ppid: 0,
                    parent_guid: None,
                    image: image.clone(),
                    cmdline: image.clone(),
                    user: known.and_then(|k| k.user.clone()),
                    integrity: known.and_then(|k| k.integrity),
                    // Started before the agent: one minute before first seen.
                    start_ts: ts - 60_000,
                    exit_ts: None,
                    signer: match known {
                        Some(k) => k.signer.clone(),
                        None if assume_windows => Some("Microsoft Windows".into()),
                        None => None,
                    },
                    signed: match known {
                        Some(k) => k.signed,
                        None if assume_windows => kestrel_common::SignatureState::Valid,
                        None => kestrel_common::SignatureState::Unknown,
                    },
                    sha256: known.and_then(|k| k.sha256.clone()),
                    motw_zone: None,
                    file_size: None,
                    path_class: class,
                },
            );
        }
        s
    }
}

// ---------------------------------------------------------------- replay

/// One alert as seen by the harness.
#[derive(Debug, Clone, Serialize)]
pub struct AlertRecord {
    pub ts: i64,
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub mode: RuleMode,
    pub pid: u32,
    pub guid: String,
    pub image: String,
    pub cmdline: String,
    pub signer: Option<String>,
    pub signed: kestrel_common::SignatureState,
    pub parent_image: Option<String>,
    pub summary: String,
    /// Response actions the engine asked for with this alert (by name).
    pub actions: Vec<String>,
    pub data_at_risk: Vec<String>,
    /// Up to 8 evidence events, one line each (`kind: object`).
    pub evidence: Vec<String>,
}

/// One-line description of an event's object (path, target, host, …).
pub fn brief(e: &Event) -> String {
    let what = match &e.data {
        EventData::ProcessStart(p) => p.image.clone(),
        EventData::ProcessStop { exit_code } => format!("exit {exit_code:?}"),
        EventData::ImageLoad { path, .. } => path.clone(),
        EventData::FileAccess { path, op } => format!("{op:?} {path}"),
        EventData::RegistrySet {
            key, value_name, ..
        } => format!(r"{key}\{value_name}"),
        EventData::NetConnect {
            dst_ip,
            dst_port,
            dst_host,
            ..
        } => format!(
            "{dst_ip}:{dst_port} {}",
            dst_host.as_deref().unwrap_or_default()
        ),
        EventData::DnsQuery { qname, .. } => qname.clone(),
        EventData::DpapiUnprotect { description } => format!("{description:?}"),
        EventData::ProcessAccess(t)
        | EventData::RemoteThread(t)
        | EventData::ThreadContext(t)
        | EventData::DebugAttach(t) => format!("{} 0x{:x}", t.target_image, t.granted_access),
        EventData::ScriptBlock { content, .. } => content.chars().take(120).collect(),
        EventData::Tamper { detail, .. } => detail.chars().take(160).collect(),
        EventData::FileActivity(f) => format!(
            "{} files, {} renames, {} new, {} self-created, ext {:?}",
            f.files_touched, f.renames, f.new_files, f.self_created, f.top_new_ext
        ),
        EventData::TaskRegistered(t) => t.name.clone(),
        EventData::ServiceInstalled(s) => format!("{} {}", s.name, s.image_path),
        EventData::WmiSubscription(w) => w.consumer.clone(),
    };
    format!("{}: {what}", e.kind().as_str())
}

/// Per-rule statistics of one run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RuleStats {
    pub rule_id: String,
    pub rule_name: String,
    pub alerts: u64,
    /// Distinct process GUIDs alerted on.
    pub processes: u64,
    /// Alerts per image path (lower-case).
    pub images: BTreeMap<String, u64>,
    /// Alerts per severity.
    pub severities: BTreeMap<String, u64>,
    /// Response actions asked for, by name (Protect: would-be actions).
    pub actions: BTreeMap<String, u64>,
    pub first_ts: i64,
    pub last_ts: i64,
    #[serde(skip)]
    guids: HashSet<String>,
}

/// Result of one replay.
#[derive(Debug, Clone, Default, Serialize)]
pub struct RunReport {
    pub label: String,
    /// Events fed (after repeat expansion).
    pub events: u64,
    pub events_by_kind: BTreeMap<String, u64>,
    /// Events whose process had no `process_start` earlier in the stream
    /// (running before the agent started, or a lost start event).
    pub orphan_events: u64,
    pub orphan_processes: u64,
    /// Orphan processes seeded from [`Seeds`] (image known) when first seen.
    pub seeded_processes: u64,
    pub first_ts: i64,
    pub last_ts: i64,
    /// Engine panics caught (each one is a bug).
    pub panics: u64,
    pub alerts_total: u64,
    pub rules: BTreeMap<String, RuleStats>,
    /// Standalone actions (`Output::Action`), by name.
    pub standalone_actions: BTreeMap<String, u64>,
    /// Alerts kept verbatim (bounded, see [`Replayer::keep_alerts`]).
    pub alerts: Vec<AlertRecord>,
    /// Standalone actions with time and target.
    pub standalone: Vec<StandaloneAction>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StandaloneAction {
    pub ts: i64,
    pub action: String,
    pub guid: Option<String>,
}

impl RunReport {
    /// Alerts with severity above `sev`.
    pub fn alerts_above(&self, sev: Severity) -> impl Iterator<Item = &AlertRecord> {
        self.alerts.iter().filter(move |a| a.severity > sev)
    }

    /// Containment actions (everything except `resume_process`) asked for
    /// with alerts or standalone.
    pub fn containment_actions(&self) -> u64 {
        let with_alerts: u64 = self
            .rules
            .values()
            .flat_map(|r| r.actions.iter())
            .filter(|(k, _)| k.as_str() != "resume_process")
            .map(|(_, v)| *v)
            .sum();
        let standalone: u64 = self
            .standalone_actions
            .iter()
            .filter(|(k, _)| k.as_str() != "resume_process")
            .map(|(_, v)| *v)
            .sum();
        with_alerts + standalone
    }

    /// Human-readable summary table.
    pub fn render_text(&self, top_images: usize) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(
            s,
            "== {} == events {} | orphan events {} ({} processes, {} seeded) | alerts {} | containment actions {} | panics {}",
            self.label,
            self.events,
            self.orphan_events,
            self.orphan_processes,
            self.seeded_processes,
            self.alerts_total,
            self.containment_actions(),
            self.panics
        );
        let _ = writeln!(
            s,
            "{:<14} {:>7} {:>6} {:>6}  {:<34} actions",
            "rule", "alerts", "procs", "images", "severities"
        );
        let mut rules: Vec<&RuleStats> = self.rules.values().collect();
        rules.sort_by(|a, b| b.alerts.cmp(&a.alerts).then(a.rule_id.cmp(&b.rule_id)));
        for r in &rules {
            let sev = r
                .severities
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(" ");
            let act = r
                .actions
                .iter()
                .map(|(k, v)| format!("{k}:{v}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = writeln!(
                s,
                "{:<14} {:>7} {:>6} {:>6}  {:<34} {}",
                r.rule_id,
                r.alerts,
                r.processes,
                r.images.len(),
                sev,
                if act.is_empty() { "-".into() } else { act }
            );
            if top_images > 0 {
                let mut imgs: Vec<(&String, &u64)> = r.images.iter().collect();
                imgs.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                for (img, n) in imgs.into_iter().take(top_images) {
                    let _ = writeln!(s, "{:<14} {:>7}   {}", "", n, img);
                }
            }
        }
        if !self.standalone_actions.is_empty() {
            let _ = writeln!(
                s,
                "standalone actions: {}",
                self.standalone_actions
                    .iter()
                    .map(|(k, v)| format!("{k}:{v}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            );
        }
        s
    }
}

/// Feeds a stream into one engine with deterministic time.
pub struct Replayer {
    engine: Engine,
    next_tick: Option<i64>,
    started: HashSet<String>,
    orphans: HashSet<String>,
    names: HashMap<String, String>,
    seeds: HashMap<String, kestrel_common::ProcessInfo>,
    late_facts: HashMap<String, (Option<String>, kestrel_common::SignatureState)>,
    /// Alerts kept verbatim in the report.
    pub keep_alerts: usize,
    report: RunReport,
}

impl Replayer {
    /// A fresh engine with `policy`, no custom rules.
    pub fn new(label: &str, policy: Policy, host: HostContext) -> Result<Replayer, String> {
        let engine = Engine::new(host, policy, RuleBundle::default()).map_err(|e| e.to_string())?;
        Ok(Self::with_engine(label, engine))
    }

    /// Use an engine prepared by the caller (custom rules, seeded processes, …).
    pub fn with_engine(label: &str, engine: Engine) -> Replayer {
        Replayer {
            engine,
            next_tick: None,
            started: HashSet::new(),
            orphans: HashSet::new(),
            names: Engine::catalog()
                .into_iter()
                .map(|m| (m.id, m.name))
                .collect(),
            seeds: HashMap::new(),
            late_facts: HashMap::new(),
            keep_alerts: DEFAULT_KEEP_ALERTS,
            report: RunReport {
                label: label.into(),
                ..Default::default()
            },
        }
    }

    /// Seed orphan processes (see [`SeedBuilder`]) when their first event arrives.
    pub fn with_seeds(mut self, seeds: HashMap<String, kestrel_common::ProcessInfo>) -> Replayer {
        self.seeds = seeds;
        self
    }

    /// Late enrichment of process_start events with an unknown signature
    /// (see [Seeds::late_facts]).
    pub fn with_late_facts(
        mut self,
        facts: HashMap<String, (Option<String>, kestrel_common::SignatureState)>,
    ) -> Replayer {
        self.late_facts = facts;
        self
    }

    pub fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Feed one event: tick the engine on the 250 ms grid up to the event's
    /// time first, then process the event.
    pub fn feed(&mut self, e: &Event) {
        let r = &mut self.report;
        if r.events == 0 {
            r.first_ts = e.ts;
        }
        r.events += 1;
        r.last_ts = r.last_ts.max(e.ts);
        *r.events_by_kind
            .entry(e.kind().as_str().to_string())
            .or_default() += 1;
        if matches!(e.data, EventData::ProcessStart(_)) {
            self.started.insert(e.guid.0.clone());
        } else if !self.started.contains(&e.guid.0) {
            r.orphan_events += 1;
            if self.orphans.insert(e.guid.0.clone()) {
                r.orphan_processes += 1;
                if let Some(info) = self.seeds.remove(&e.guid.0) {
                    r.seeded_processes += 1;
                    let engine = &mut self.engine;
                    if catch_unwind(AssertUnwindSafe(|| engine.seed_process(info))).is_err() {
                        self.report.panics += 1;
                    }
                }
            }
        }
        match self.next_tick {
            None => self.next_tick = Some(e.ts - e.ts.rem_euclid(TICK_MS) + TICK_MS),
            Some(t) if e.ts >= t => {
                let now = e.ts - e.ts.rem_euclid(TICK_MS);
                self.tick(now);
                self.next_tick = Some(now + TICK_MS);
            }
            _ => {}
        }
        let engine = &mut self.engine;
        match catch_unwind(AssertUnwindSafe(|| engine.process(e))) {
            Ok(outs) => self.record(e.ts, outs),
            Err(_) => self.report.panics += 1,
        }
        if let EventData::ProcessStart(ps) = &e.data {
            if ps.signed == kestrel_common::SignatureState::Unknown {
                if let Some((signer, signed)) =
                    self.late_facts.get(&ps.image.to_ascii_lowercase()).cloned()
                {
                    let facts = crate::ProcessFacts {
                        sha256: None,
                        signer,
                        signed,
                    };
                    let engine = &mut self.engine;
                    match catch_unwind(AssertUnwindSafe(|| {
                        engine.enrich_process(&e.guid, facts, e.ts)
                    })) {
                        Ok(outs) => self.record(e.ts, outs),
                        Err(_) => self.report.panics += 1,
                    }
                }
            }
        }
    }

    fn tick(&mut self, now: i64) {
        let engine = &mut self.engine;
        match catch_unwind(AssertUnwindSafe(|| engine.tick(now))) {
            Ok(outs) => self.record(now, outs),
            Err(_) => self.report.panics += 1,
        }
    }

    fn record(&mut self, ts: i64, outs: Vec<Output>) {
        for o in outs {
            match o {
                Output::Alert(d) => {
                    let a = &d.alert;
                    let r = &mut self.report;
                    r.alerts_total += 1;
                    let st = r
                        .rules
                        .entry(a.rule_id.clone())
                        .or_insert_with(|| RuleStats {
                            rule_id: a.rule_id.clone(),
                            rule_name: self
                                .names
                                .get(&a.rule_id)
                                .cloned()
                                .unwrap_or_else(|| a.rule_name.clone()),
                            first_ts: a.ts,
                            ..Default::default()
                        });
                    st.alerts += 1;
                    st.last_ts = a.ts;
                    if st.guids.insert(a.process.guid.0.clone()) {
                        st.processes += 1;
                    }
                    *st.images
                        .entry(a.process.image.to_ascii_lowercase())
                        .or_default() += 1;
                    *st.severities
                        .entry(a.severity.as_str().to_string())
                        .or_default() += 1;
                    for act in &d.actions {
                        *st.actions.entry(act.name().to_string()).or_default() += 1;
                    }
                    if r.alerts.len() < self.keep_alerts {
                        r.alerts.push(AlertRecord {
                            ts: a.ts,
                            rule_id: a.rule_id.clone(),
                            rule_name: a.rule_name.clone(),
                            severity: a.severity,
                            mode: a.mode,
                            pid: a.process.pid,
                            guid: a.process.guid.0.clone(),
                            image: a.process.image.clone(),
                            cmdline: a.process.cmdline.chars().take(400).collect(),
                            signer: a.process.signer.clone(),
                            signed: a.process.signed,
                            parent_image: a.ancestry.first().map(|p| p.image.clone()),
                            summary: a.summary.clone(),
                            actions: d.actions.iter().map(|x| x.name().to_string()).collect(),
                            data_at_risk: a
                                .data_at_risk
                                .iter()
                                .map(|c| {
                                    serde_json::to_value(c)
                                        .ok()
                                        .and_then(|v| v.as_str().map(String::from))
                                        .unwrap_or_default()
                                })
                                .collect(),
                            evidence: a.evidence.iter().take(8).map(brief).collect(),
                        });
                    }
                }
                Output::Action(act) => {
                    let r = &mut self.report;
                    *r.standalone_actions
                        .entry(act.name().to_string())
                        .or_default() += 1;
                    if r.standalone.len() < self.keep_alerts {
                        r.standalone.push(StandaloneAction {
                            ts,
                            action: act.name().to_string(),
                            guid: action_guid(&act),
                        });
                    }
                }
            }
        }
    }

    /// Drain: advance time past the last event so suspend windows resolve.
    pub fn finish(mut self) -> RunReport {
        if self.report.events > 0 {
            let end = self.report.last_ts + DRAIN_MS;
            let mut t = self.report.last_ts - self.report.last_ts.rem_euclid(TICK_MS) + TICK_MS;
            // A coarse grid is enough here: nothing new arrives.
            while t <= end {
                self.tick(t);
                t += 1_000;
            }
        }
        self.report
    }
}

fn action_guid(a: &ResponseAction) -> Option<String> {
    match a {
        ResponseAction::KillProcess { guid, .. }
        | ResponseAction::SuspendProcess { guid, .. }
        | ResponseAction::ResumeProcess { guid, .. } => guid.as_ref().map(|g| g.0.clone()),
        _ => None,
    }
}

/// Replay `events` under `policy` (fresh engine, [`eval_host`]).
pub fn replay(label: &str, policy: Policy, events: &[Event]) -> Result<RunReport, String> {
    let mut r = Replayer::new(label, policy, eval_host())?;
    for e in events {
        r.feed(e);
    }
    Ok(r.finish())
}

// ---------------------------------------------------------------- expectations

/// Which part of the corpus a scenario belongs to (its top-level folder).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusClass {
    Malicious,
    Benign,
    BenignLookalike,
}

impl CorpusClass {
    pub const ALL: [CorpusClass; 3] = [
        CorpusClass::Malicious,
        CorpusClass::Benign,
        CorpusClass::BenignLookalike,
    ];

    pub fn dir(&self) -> &'static str {
        match self {
            CorpusClass::Malicious => "malicious",
            CorpusClass::Benign => "benign",
            CorpusClass::BenignLookalike => "benign-lookalike",
        }
    }
}

/// One required alert: any rule matching one of `any_of` (exact id, or a
/// prefix ending in `*`, case-insensitive) at `min_severity` or above.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct AlertReq {
    pub any_of: Vec<String>,
    pub min_severity: Option<Severity>,
}

/// A permitted alert on benign data.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Allowance {
    pub rule: String,
    /// Highest permitted severity (`None` = any).
    pub max_severity: Option<Severity>,
    /// May the Protect run ask for containment actions with this alert?
    pub actions: bool,
    pub note: String,
}

/// Parsed `<scenario>.expect.json`. Unknown keys are ignored.
///
/// ```json
/// {
///   "description": "free text",
///   "must_alert": ["ST-02", ["ST-04", "ST-05"], {"any_of": ["CD-*"], "min_severity": "high"}],
///   "min_severity": "medium",
///   "must_not_alert": ["ST-12"],
///   "must_act": ["kill_process"],
///   "max_severity": "low",
///   "strict": true,
///   "allow": ["ST-12", {"rule": "ST-01", "max_severity": "medium"}],
///   "known_false_positives": [{"rule": "ST-04", "note": "FP-3"}]
/// }
/// ```
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Expectation {
    pub description: String,
    /// Every group must be satisfied (Audit run).
    pub must_alert: Vec<AlertReq>,
    /// Default minimum severity for `must_alert` groups.
    pub min_severity: Option<Severity>,
    /// No alert of these rules may fire (any severity, Audit run).
    pub must_not_alert: Vec<String>,
    /// At least one of these action names must be asked for in the Protect run.
    pub must_act: Vec<String>,
    /// Soft expectations: a miss is reported as a note, never a failure.
    pub should_alert: Vec<AlertReq>,
    /// Benign classes: highest severity an unlisted alert may have (default Low).
    pub max_severity: Option<Severity>,
    /// Benign classes: every alert must be listed in `allow` or
    /// `known_false_positives` (default: true when the file has an `allow`
    /// or `known_false_positives` list, i.e. it enumerates the expected
    /// alerts; otherwise anything up to `max_severity` passes).
    pub strict: Option<bool>,
    pub allow: Vec<Allowance>,
    /// Alerts that are false positives today, tracked until a rule fix
    /// lands. They pass the gate (actions included) but are reported, and
    /// an entry that no longer fires is reported as stale.
    pub known_false_positives: Vec<Allowance>,
}

fn parse_sev(v: &serde_json::Value) -> Result<Option<Severity>, String> {
    match v {
        serde_json::Value::Null => Ok(None),
        serde_json::Value::String(s) => {
            serde_json::from_value::<Severity>(serde_json::json!(s.to_ascii_lowercase()))
                .map(Some)
                .map_err(|_| format!("bad severity {s:?}"))
        }
        other => Err(format!("bad severity {other}")),
    }
}

fn str_list(v: &serde_json::Value) -> Vec<String> {
    match v {
        serde_json::Value::String(s) => vec![s.clone()],
        serde_json::Value::Array(a) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        _ => vec![],
    }
}

fn parse_req(v: &serde_json::Value) -> Result<AlertReq, String> {
    match v {
        serde_json::Value::String(_) | serde_json::Value::Array(_) => {
            let any_of = str_list(v);
            if any_of.is_empty() {
                return Err(format!("empty must_alert group {v}"));
            }
            Ok(AlertReq {
                any_of,
                min_severity: None,
            })
        }
        serde_json::Value::Object(m) => {
            let mut any_of = Vec::new();
            for k in ["any_of", "anyOf", "rules", "rule", "id"] {
                if let Some(x) = m.get(k) {
                    any_of.extend(str_list(x));
                }
            }
            if any_of.is_empty() {
                return Err(format!("must_alert group without rules {v}"));
            }
            Ok(AlertReq {
                any_of,
                min_severity: parse_sev(m.get("min_severity").unwrap_or(&serde_json::Value::Null))?,
            })
        }
        other => Err(format!("bad must_alert entry {other}")),
    }
}

fn parse_allow(v: &serde_json::Value) -> Result<Allowance, String> {
    match v {
        serde_json::Value::String(s) => Ok(Allowance {
            rule: s.clone(),
            ..Default::default()
        }),
        serde_json::Value::Object(m) => Ok(Allowance {
            rule: m
                .get("rule")
                .or_else(|| m.get("id"))
                .and_then(|x| x.as_str())
                .ok_or_else(|| format!("allowance without rule {v}"))?
                .to_string(),
            max_severity: parse_sev(m.get("max_severity").unwrap_or(&serde_json::Value::Null))?,
            actions: m.get("actions").and_then(|x| x.as_bool()).unwrap_or(false),
            note: m
                .get("note")
                .or_else(|| m.get("reason"))
                .and_then(|x| x.as_str())
                .unwrap_or_default()
                .to_string(),
        }),
        other => Err(format!("bad allowance {other}")),
    }
}

/// Parse an expect file (tolerant: strings, arrays or objects for groups).
pub fn parse_expectation(json: &str) -> Result<Expectation, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let m = v.as_object().ok_or("expect file is not a JSON object")?;
    let null = serde_json::Value::Null;
    let list = |k: &str| -> Vec<serde_json::Value> {
        match m.get(k) {
            Some(serde_json::Value::Array(a)) => a.clone(),
            Some(serde_json::Value::Null) | None => vec![],
            Some(x) => vec![x.clone()],
        }
    };
    let mut x = Expectation {
        description: m
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or_default()
            .to_string(),
        min_severity: parse_sev(m.get("min_severity").unwrap_or(&null))?,
        max_severity: parse_sev(m.get("max_severity").unwrap_or(&null))?,
        strict: m.get("strict").and_then(|s| s.as_bool()),
        must_not_alert: list("must_not_alert").iter().flat_map(str_list).collect(),
        must_act: list("must_act").iter().flat_map(str_list).collect(),
        ..Default::default()
    };
    for g in list("must_alert") {
        x.must_alert.push(parse_req(&g)?);
    }
    for g in list("should_alert") {
        x.should_alert.push(parse_req(&g)?);
    }
    for a in list("allow") {
        x.allow.push(parse_allow(&a)?);
    }
    for k in ["known_false_positives", "known_fp"] {
        for a in list(k) {
            let mut a = parse_allow(&a)?;
            a.actions = true;
            x.known_false_positives.push(a);
        }
    }
    Ok(x)
}

/// Rule pattern match: exact id or `PREFIX*`, case-insensitive.
pub fn rule_matches(pattern: &str, rule_id: &str) -> bool {
    let p = pattern.trim();
    match p.strip_suffix('*') {
        Some(prefix) => rule_id
            .to_ascii_lowercase()
            .starts_with(&prefix.to_ascii_lowercase()),
        None => p.eq_ignore_ascii_case(rule_id),
    }
}

/// One corpus scenario.
#[derive(Debug, Clone)]
pub struct Scenario {
    /// Path relative to the corpus root, `/`-separated, without `.jsonl`.
    pub name: String,
    pub class: CorpusClass,
    pub path: PathBuf,
    pub events: Vec<Event>,
    pub expect: Option<Expectation>,
}

fn collect_jsonl(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_jsonl(&p, out)?;
        } else if p.extension().is_some_and(|x| x == "jsonl") {
            out.push(p);
        }
    }
    Ok(())
}

/// Load every `*.jsonl` under `root/{malicious,benign,benign-lookalike}`
/// with its sidecar `*.expect.json` (missing sidecar = `expect: None`).
pub fn load_corpus(root: &Path) -> Result<Vec<Scenario>, String> {
    let mut out = Vec::new();
    for class in CorpusClass::ALL {
        let dir = root.join(class.dir());
        let mut files = Vec::new();
        collect_jsonl(&dir, &mut files)?;
        for f in files {
            let events = load_events_file(&f)?;
            let stem = f.with_extension("");
            let sidecar = PathBuf::from(format!("{}.expect.json", stem.display()));
            let expect = if sidecar.exists() {
                let s = std::fs::read_to_string(&sidecar)
                    .map_err(|e| format!("{}: {e}", sidecar.display()))?;
                Some(parse_expectation(&s).map_err(|e| format!("{}: {e}", sidecar.display()))?)
            } else {
                None
            };
            let rel = stem
                .strip_prefix(root)
                .unwrap_or(&stem)
                .to_string_lossy()
                .replace('\\', "/");
            out.push(Scenario {
                name: rel,
                class,
                path: f,
                events,
                expect,
            });
        }
    }
    Ok(out)
}

/// Read a known-failures baseline: a JSON object `{"<scenario name>":
/// "reason"}`; keys starting with `_` are comments. A missing file is an
/// empty baseline.
pub fn load_baseline(path: &Path) -> Result<BTreeMap<String, String>, String> {
    let s = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let v: serde_json::Value =
        serde_json::from_str(&s).map_err(|e| format!("{}: {e}", path.display()))?;
    let m = v
        .as_object()
        .ok_or_else(|| format!("{}: not a JSON object", path.display()))?;
    Ok(m.iter()
        .filter(|(k, _)| !k.starts_with('_'))
        .map(|(k, v)| {
            (
                k.clone(),
                v.as_str()
                    .map(String::from)
                    .unwrap_or_else(|| v.to_string()),
            )
        })
        .collect())
}

/// Verdict for one scenario.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioOutcome {
    pub name: String,
    pub class: CorpusClass,
    pub passed: bool,
    pub events: u64,
    pub failures: Vec<String>,
    pub notes: Vec<String>,
    /// Audit run: (rule, severity) of every alert, in order.
    pub audit_alerts: Vec<(String, Severity)>,
    /// Protect run: (rule or "-" for standalone, action name), resume excluded.
    pub protect_actions: Vec<(String, String)>,
    /// Known false positives that fired.
    pub known_fp_hits: Vec<String>,
    /// Reason from the known-failures baseline when the scenario is listed
    /// there (see [`CorpusReport::apply_baseline`]).
    pub baseline: Option<String>,
}

fn allowed<'a>(list: &'a [Allowance], rule: &str, sev: Severity) -> Option<&'a Allowance> {
    list.iter()
        .find(|a| rule_matches(&a.rule, rule) && a.max_severity.map(|m| sev <= m).unwrap_or(true))
}

/// Replay a scenario under all-Audit and all-Protect policies and judge it.
pub fn evaluate(sc: &Scenario) -> ScenarioOutcome {
    let mut o = ScenarioOutcome {
        name: sc.name.clone(),
        class: sc.class,
        passed: true,
        events: sc.events.len() as u64,
        failures: vec![],
        notes: vec![],
        audit_alerts: vec![],
        protect_actions: vec![],
        known_fp_hits: vec![],
        baseline: None,
    };
    let audit = match replay("audit", policy_all(RuleMode::Audit), &sc.events) {
        Ok(r) => r,
        Err(e) => {
            o.failures.push(format!("engine: {e}"));
            o.passed = false;
            return o;
        }
    };
    let protect = match replay("protect", policy_all(RuleMode::Protect), &sc.events) {
        Ok(r) => r,
        Err(e) => {
            o.failures.push(format!("engine: {e}"));
            o.passed = false;
            return o;
        }
    };
    if audit.panics + protect.panics > 0 {
        o.failures.push(format!(
            "engine panicked {} time(s)",
            audit.panics + protect.panics
        ));
    }
    o.audit_alerts = audit
        .alerts
        .iter()
        .map(|a| (a.rule_id.clone(), a.severity))
        .collect();
    for a in &protect.alerts {
        for act in a.actions.iter().filter(|x| x.as_str() != "resume_process") {
            o.protect_actions.push((a.rule_id.clone(), act.clone()));
        }
    }
    for s in protect
        .standalone
        .iter()
        .filter(|s| s.action != "resume_process")
    {
        o.protect_actions.push(("-".into(), s.action.clone()));
    }
    let fired = || {
        o.audit_alerts
            .iter()
            .map(|(r, s)| format!("{r}/{}", s.as_str()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let default_expect = Expectation::default();
    let x = sc.expect.as_ref().unwrap_or(&default_expect);
    let mut failures = Vec::new();
    let mut notes = Vec::new();

    if sc.class == CorpusClass::Malicious && sc.expect.is_none() {
        failures.push("malicious scenario without an .expect.json".into());
    }
    if sc.class == CorpusClass::Malicious
        && sc.expect.is_some()
        && x.must_alert.is_empty()
        && x.must_act.is_empty()
    {
        failures.push("malicious expect file has no must_alert / must_act".into());
    }
    // Required alerts.
    for g in &x.must_alert {
        let min = g.min_severity.or(x.min_severity).unwrap_or(Severity::Info);
        let hit = o
            .audit_alerts
            .iter()
            .any(|(r, s)| *s >= min && g.any_of.iter().any(|p| rule_matches(p, r)));
        if !hit {
            failures.push(format!(
                "missing alert any_of [{}] at >= {} (fired: {})",
                g.any_of.join(", "),
                min.as_str(),
                fired()
            ));
        }
    }
    // Soft expectations.
    for g in &x.should_alert {
        let min = g.min_severity.unwrap_or(Severity::Info);
        if !o
            .audit_alerts
            .iter()
            .any(|(r, s)| *s >= min && g.any_of.iter().any(|p| rule_matches(p, r)))
        {
            notes.push(format!("should_alert [{}] not raised", g.any_of.join(", ")));
        }
    }
    // Forbidden alerts.
    for p in &x.must_not_alert {
        for (r, s) in &o.audit_alerts {
            if rule_matches(p, r) {
                failures.push(format!(
                    "forbidden alert {r}/{} (must_not_alert {p})",
                    s.as_str()
                ));
            }
        }
    }
    // Required Protect actions.
    if !x.must_act.is_empty()
        && !o
            .protect_actions
            .iter()
            .any(|(_, a)| x.must_act.iter().any(|m| m.eq_ignore_ascii_case(a)))
    {
        failures.push(format!(
            "no Protect action any_of [{}] (asked: {:?})",
            x.must_act.join(", "),
            o.protect_actions
        ));
    }
    // Benign classes: severity ceiling, allow-list, no containment.
    if sc.class != CorpusClass::Malicious {
        let ceiling = x.max_severity.unwrap_or(Severity::Low);
        let strict = x
            .strict
            .unwrap_or(!x.allow.is_empty() || !x.known_false_positives.is_empty());
        let mut fp_seen: HashSet<String> = HashSet::new();
        for (r, s) in &o.audit_alerts {
            if let Some(k) = allowed(&x.known_false_positives, r, *s) {
                fp_seen.insert(k.rule.clone());
                let tag = format!("{r}/{}", s.as_str());
                if !o.known_fp_hits.contains(&tag) {
                    o.known_fp_hits.push(tag);
                }
            } else if allowed(&x.allow, r, *s).is_some() {
            } else if *s > ceiling {
                failures.push(format!(
                    "alert {r}/{} above {} on benign data",
                    s.as_str(),
                    ceiling.as_str()
                ));
            } else if strict {
                failures.push(format!(
                    "unexpected alert {r}/{} (not in allow / known_false_positives)",
                    s.as_str()
                ));
            } else {
                notes.push(format!("low alert {r}/{}", s.as_str()));
            }
        }
        for k in &x.known_false_positives {
            if !fp_seen.contains(&k.rule) {
                notes.push(format!(
                    "known false positive {} no longer fires: remove it from the expect file",
                    k.rule
                ));
            }
        }
        for (rule, act) in &o.protect_actions {
            let ok = if rule == "-" {
                // Standalone (suspend-window expiry): fine only if a listed
                // alert that may act fired.
                x.known_false_positives
                    .iter()
                    .chain(x.allow.iter().filter(|a| a.actions))
                    .any(|a| o.audit_alerts.iter().any(|(r, _)| rule_matches(&a.rule, r)))
            } else {
                x.known_false_positives
                    .iter()
                    .chain(x.allow.iter().filter(|a| a.actions))
                    .any(|a| rule_matches(&a.rule, rule))
            };
            if !ok {
                failures.push(format!("Protect-mode action {act} ({rule}) on benign data"));
            }
        }
    }
    failures.dedup();
    o.passed = failures.is_empty();
    o.failures = failures;
    o.notes = notes;
    o
}

/// Outcome of a whole corpus.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CorpusReport {
    pub outcomes: Vec<ScenarioOutcome>,
}

impl CorpusReport {
    pub fn run(scenarios: &[Scenario]) -> CorpusReport {
        CorpusReport {
            outcomes: scenarios.iter().map(evaluate).collect(),
        }
    }

    pub fn count(&self, class: CorpusClass) -> (usize, usize) {
        let all = self.outcomes.iter().filter(|o| o.class == class);
        let n = all.clone().count();
        (n, all.filter(|o| o.passed).count())
    }

    pub fn all_passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.passed)
    }

    /// Mark scenarios listed in a known-failures baseline (`{"<scenario
    /// name>": "reason", …}`, names as in [`Scenario::name`]). Returns the
    /// baseline entries that name no scenario.
    pub fn apply_baseline(&mut self, baseline: &BTreeMap<String, String>) -> Vec<String> {
        let mut unknown = Vec::new();
        for (name, reason) in baseline {
            match self.outcomes.iter_mut().find(|o| &o.name == name) {
                Some(o) => o.baseline = Some(reason.clone()),
                None => unknown.push(name.clone()),
            }
        }
        unknown
    }

    /// Failed scenarios that the baseline does not excuse: the gate.
    pub fn gate_failures(&self) -> Vec<&ScenarioOutcome> {
        self.outcomes
            .iter()
            .filter(|o| !o.passed && o.baseline.is_none())
            .collect()
    }

    /// Baselined scenarios that pass now: remove them from the baseline.
    pub fn stale_baseline(&self) -> Vec<&ScenarioOutcome> {
        self.outcomes
            .iter()
            .filter(|o| o.passed && o.baseline.is_some())
            .collect()
    }

    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        for c in CorpusClass::ALL {
            let (n, p) = self.count(c);
            let _ = writeln!(s, "{:<17} {p}/{n} passed", c.dir());
        }
        for o in &self.outcomes {
            let alerts = o
                .audit_alerts
                .iter()
                .map(|(r, sv)| format!("{r}/{}", sv.as_str()))
                .collect::<Vec<_>>();
            let _ = writeln!(
                s,
                "[{}] {} ({} events) alerts: {}{}",
                match (o.passed, o.baseline.is_some()) {
                    (true, false) => "pass",
                    (true, true) => "pass, baselined: remove",
                    (false, true) => "known failure",
                    (false, false) => "FAIL",
                },
                o.name,
                o.events,
                if alerts.is_empty() {
                    "-".into()
                } else {
                    alerts.join(", ")
                },
                if o.protect_actions.is_empty() {
                    String::new()
                } else {
                    format!(" | protect actions: {}", o.protect_actions.len())
                }
            );
            for f in &o.failures {
                let _ = writeln!(s, "    FAIL: {f}");
            }
            if let Some(b) = &o.baseline {
                let _ = writeln!(s, "    baseline: {b}");
            }
            if !o.known_fp_hits.is_empty() {
                let _ = writeln!(s, "    known FP: {}", o.known_fp_hits.join(", "));
            }
            for n in &o.notes {
                let _ = writeln!(s, "    note: {n}");
            }
        }
        s
    }
}

// ---------------------------------------------------------------- tests

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{FileOp, ProcessGuid, ProcessStart, SignatureState};

    const T0: i64 = 1_760_000_000_000;

    fn start(ts: i64, guid: &str, pid: u32, image: &str, signed: SignatureState) -> Event {
        Event {
            ts: T0 + ts,
            pid,
            guid: ProcessGuid(guid.into()),
            data: EventData::ProcessStart(ProcessStart {
                ppid: 1,
                image: image.into(),
                cmdline: image.into(),
                signed,
                ..Default::default()
            }),
        }
    }

    fn read(ts: i64, guid: &str, pid: u32, path: &str) -> Event {
        Event {
            ts: T0 + ts,
            pid,
            guid: ProcessGuid(guid.into()),
            data: EventData::FileAccess {
                path: path.into(),
                op: FileOp::Read,
            },
        }
    }

    /// Unsigned Temp binary reading Chrome's credential stores: a stealer.
    fn stealer() -> Vec<Event> {
        let base = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data";
        vec![
            start(
                0,
                "s",
                900,
                r"C:\Users\alice\AppData\Local\Temp\x\svc.exe",
                SignatureState::Unsigned,
            ),
            read(100, "s", 900, &format!(r"{base}\Local State")),
            read(110, "s", 900, &format!(r"{base}\Default\Login Data")),
            read(120, "s", 900, &format!(r"{base}\Default\Network\Cookies")),
            read(130, "s", 900, &format!(r"{base}\Default\Web Data")),
        ]
    }

    fn scenario(class: CorpusClass, events: Vec<Event>, expect: Option<&str>) -> Scenario {
        Scenario {
            name: "t".into(),
            class,
            path: PathBuf::new(),
            events,
            expect: expect.map(|s| parse_expectation(s).unwrap()),
        }
    }

    #[test]
    fn parse_line_expands_repeats_and_skips_comments() {
        assert!(parse_line("").unwrap().is_none());
        assert!(parse_line("# note").unwrap().is_none());
        let (e, n) = parse_line(
            r#"{"ts":5,"pid":2,"guid":"g","type":"dpapi_unprotect","description":"x","repeat_count":41,"repeat_first_ts":1}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(n, 41);
        assert_eq!(e.ts, 5);
        let (_, n) = parse_line(
            r#"{"ts":5,"pid":2,"guid":"g","type":"dpapi_unprotect","description":"x","repeat_count":4000000000}"#,
        )
        .unwrap()
        .unwrap();
        assert_eq!(n, MAX_REPEAT_EXPANSION);
        assert!(parse_line("{not json").is_err());
    }

    #[test]
    fn expectation_parsing_is_tolerant() {
        let x = parse_expectation(
            r#"{"must_alert":["ST-02",["ST-04","ST-05"],{"any_of":["CD-*"],"min_severity":"HIGH"}],
                "min_severity":"medium","must_not_alert":"ST-12",
                "allow":["ST-12",{"rule":"ST-01","max_severity":"medium"}],
                "known_false_positives":[{"rule":"ST-04","note":"FP-3"}],"other":1}"#,
        )
        .unwrap();
        assert_eq!(x.must_alert.len(), 3);
        assert_eq!(x.must_alert[1].any_of, vec!["ST-04", "ST-05"]);
        assert_eq!(x.must_alert[2].min_severity, Some(Severity::High));
        assert_eq!(x.min_severity, Some(Severity::Medium));
        assert_eq!(x.must_not_alert, vec!["ST-12"]);
        assert_eq!(x.allow[1].max_severity, Some(Severity::Medium));
        assert!(x.known_false_positives[0].actions);
        assert!(parse_expectation("[]").is_err());
        assert!(parse_expectation(r#"{"min_severity":"huge"}"#).is_err());
        assert!(rule_matches("cd-*", "CD-06"));
        assert!(!rule_matches("CD-0", "CD-06"));
    }

    #[test]
    fn replay_is_deterministic_and_counts() {
        let a = replay("a", policy_all(RuleMode::Audit), &stealer()).unwrap();
        let b = replay("a", policy_all(RuleMode::Audit), &stealer()).unwrap();
        assert!(a.alerts_total > 0, "{}", a.render_text(3));
        assert_eq!(
            a.alerts.iter().map(|x| &x.rule_id).collect::<Vec<_>>(),
            b.alerts.iter().map(|x| &x.rule_id).collect::<Vec<_>>()
        );
        assert_eq!(a.events, 5);
        assert_eq!(a.orphan_events, 0);
        assert_eq!(a.containment_actions(), 0, "Audit never acts");
        let p = replay("p", policy_all(RuleMode::Protect), &stealer()).unwrap();
        assert!(p.containment_actions() > 0, "{}", p.render_text(3));
    }

    #[test]
    fn malicious_and_benign_verdicts() {
        let audit = replay("a", policy_all(RuleMode::Audit), &stealer()).unwrap();
        let rule = audit.alerts[0].rule_id.clone();
        // Malicious: expected alert present.
        let ok = evaluate(&scenario(
            CorpusClass::Malicious,
            stealer(),
            Some(&format!(
                r#"{{"must_alert":[["{rule}","XX-99"]],"must_act":["kill_process","suspend_process"]}}"#
            )),
        ));
        assert!(ok.passed, "{:?}", ok.failures);
        // Malicious: missing alert, missing expect file.
        let miss = evaluate(&scenario(
            CorpusClass::Malicious,
            stealer(),
            Some(r#"{"must_alert":["XX-99"]}"#),
        ));
        assert!(!miss.passed);
        assert!(!evaluate(&scenario(CorpusClass::Malicious, stealer(), None)).passed);
        // Same events as "benign": fails (above Low, Protect actions)…
        let b = evaluate(&scenario(CorpusClass::Benign, stealer(), None));
        assert!(!b.passed);
        // …unless every rule is a known false positive.
        let rules: Vec<String> = audit.rules.keys().cloned().collect();
        let fp = rules
            .iter()
            .map(|r| format!(r#"{{"rule":"{r}","note":"test"}}"#))
            .collect::<Vec<_>>()
            .join(",");
        let k = evaluate(&scenario(
            CorpusClass::Benign,
            stealer(),
            Some(&format!(
                r#"{{"known_false_positives":[{fp},{{"rule":"ZZ-01"}}]}}"#
            )),
        ));
        assert!(k.passed, "{:?}", k.failures);
        assert!(!k.known_fp_hits.is_empty());
        assert!(k.notes.iter().any(|n| n.contains("ZZ-01")), "{:?}", k.notes);
        // must_not_alert applies to every class.
        let f = evaluate(&scenario(
            CorpusClass::BenignLookalike,
            stealer(),
            Some(&format!(
                r#"{{"must_not_alert":["{rule}"],"known_false_positives":[{fp}]}}"#
            )),
        ));
        assert!(!f.passed);
    }

    #[test]
    fn quiet_benign_passes_and_counts_orphans() {
        let ev = vec![
            start(
                0,
                "n",
                10,
                r"C:\Windows\System32\notepad.exe",
                SignatureState::Valid,
            ),
            read(5, "orphan", 11, r"C:\Users\alice\Documents\a.txt"),
        ];
        let o = evaluate(&scenario(CorpusClass::Benign, ev.clone(), None));
        assert!(o.passed, "{:?}", o.failures);
        let r = replay("a", policy_all(RuleMode::Audit), &ev).unwrap();
        assert_eq!((r.orphan_events, r.orphan_processes), (1, 1));
        assert!(named_policy("default").is_some() && named_policy("x").is_none());
    }

    #[test]
    fn seeds_resolve_orphans_from_targets_and_known_images() {
        let img = r"C:\Program Files\App\app.exe";
        let ev = [
            start(0, "known", 5, img, SignatureState::Valid),
            Event {
                ts: T0 + 10,
                pid: 6,
                guid: ProcessGuid("other".into()),
                data: EventData::ProcessAccess(kestrel_common::TargetProcess {
                    target_pid: 7,
                    target_guid: Some(ProcessGuid("orphan".into())),
                    target_image: img.into(),
                    granted_access: 0x10,
                    return_code: 0,
                }),
            },
            read(20, "orphan", 7, r"C:\x.txt"),
        ];
        let mut b = SeedBuilder::default();
        ev.iter().for_each(|e| b.learn(e));
        let s = b.finish();
        // "other" and "orphan" have no start; only "orphan" is resolvable.
        assert_eq!((s.orphans, s.resolved, s.with_signature), (2, 1, 1));
        let info = &s.map["orphan"];
        assert_eq!(info.signed, SignatureState::Valid);
        assert_eq!(info.pid, 7);
        let mut r = Replayer::new("a", policy_all(RuleMode::Audit), eval_host())
            .unwrap()
            .with_seeds(s.map);
        ev.iter().for_each(|e| r.feed(e));
        let rep = r.finish();
        assert_eq!(rep.seeded_processes, 1);
        assert_eq!(rep.orphan_processes, 2);
    }

    #[test]
    fn corpus_loader_reads_sidecars() {
        let dir = std::env::temp_dir().join(format!("kestrel-eval-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("malicious/sub")).unwrap();
        std::fs::create_dir_all(dir.join("benign")).unwrap();
        let lines: Vec<String> = stealer()
            .iter()
            .map(|e| serde_json::to_string(e).unwrap())
            .collect();
        std::fs::write(dir.join("malicious/sub/a.jsonl"), lines.join("\n")).unwrap();
        std::fs::write(
            dir.join("malicious/sub/a.expect.json"),
            r#"{"must_alert":["ST-*"]}"#,
        )
        .unwrap();
        std::fs::write(dir.join("benign/b.jsonl"), "# empty\n").unwrap();
        let sc = load_corpus(&dir).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(sc.len(), 2);
        assert_eq!(sc[0].name, "malicious/sub/a");
        assert!(sc[0].expect.is_some());
        assert_eq!(sc[1].class, CorpusClass::Benign);
        let rep = CorpusReport::run(&sc);
        assert!(rep.all_passed(), "{}", rep.render_text());
        assert_eq!(rep.count(CorpusClass::Malicious), (1, 1));
    }
}
