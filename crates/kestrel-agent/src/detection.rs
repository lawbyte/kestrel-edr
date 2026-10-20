//! Detection loop: one dedicated thread owns the [`Engine`]; it pulls sensor
//! events, runs rules, hands response actions to per-process workers (actions
//! for one process run strictly in order; different processes run
//! concurrently), batches telemetry for upload and ticks the engine.

use anyhow::Result;
use kestrel_common::{
    tray::ActivityItem, wire::AgentPayload, ActionOutcome, Alert, DataCategory, Event, Policy,
    ProcessInfo, ResponseAction, RuleBundle, RuleMode, Severity,
};
use kestrel_detect::{Detection, Engine, HostContext, Output};
use kestrel_platform::LateEnrichment;
use std::collections::HashMap;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::agent::Core;

pub enum EngineCtl {
    Policy(Box<Policy>),
    Rules(RuleBundle, oneshot::Sender<Result<(), String>>),
    PlantCanaries,
}

enum Job {
    Detection(Box<Detection>),
    Action(ResponseAction),
}

/// Routes jobs to per-key sequential workers on the main runtime.
struct Dispatcher {
    core: Arc<Core>,
    rt: tokio::runtime::Handle,
    workers: HashMap<String, mpsc::UnboundedSender<Job>>,
}

impl Dispatcher {
    fn dispatch(&mut self, key: String, mut job: Job) {
        if let Some(tx) = self.workers.get(&key) {
            match tx.send(job) {
                Ok(()) => return,
                Err(mpsc::error::SendError(j)) => job = j,
            }
        }
        let (tx, mut rx) = mpsc::unbounded_channel::<Job>();
        let _ = tx.send(job);
        let core = self.core.clone();
        self.rt.spawn(async move {
            loop {
                let job = match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
                    Ok(Some(j)) => j,
                    Ok(None) => break,
                    Err(_) => {
                        // Idle: stop accepting, then drain anything that raced in.
                        rx.close();
                        while let Ok(j) = rx.try_recv() {
                            run_job(&core, j).await;
                        }
                        break;
                    }
                };
                run_job(&core, job).await;
            }
        });
        self.workers.insert(key, tx);
    }

    fn gc(&mut self) {
        self.workers.retain(|_, tx| !tx.is_closed());
    }
}

fn action_key(a: &ResponseAction) -> String {
    match a {
        ResponseAction::KillProcess { pid, guid, .. }
        | ResponseAction::SuspendProcess { pid, guid }
        | ResponseAction::ResumeProcess { pid, guid } => match guid {
            Some(g) => g.0.clone(),
            None => format!("pid:{pid}"),
        },
        _ => "host".into(),
    }
}

async fn run_job(core: &Arc<Core>, job: Job) {
    match job {
        Job::Detection(d) => handle_detection(core, *d).await,
        Job::Action(a) => {
            let o = core.execute_action(&a).await;
            if o.ok {
                tracing::info!(action = a.name(), detail = %o.detail, "engine action executed");
            } else {
                tracing::warn!(action = a.name(), detail = %o.detail, "engine action failed");
            }
        }
    }
}

async fn handle_detection(core: &Arc<Core>, d: Detection) {
    let mut alert = d.alert;
    let mut outcomes = Vec::with_capacity(d.actions.len());
    for a in &d.actions {
        let o = core.execute_action(a).await;
        if !o.ok {
            tracing::warn!(rule = %alert.rule_id, action = a.name(), detail = %o.detail, "response action failed");
        }
        outcomes.push(o);
    }
    alert.actions = outcomes;
    core.stats.alerts.fetch_add(1, Ordering::Relaxed);
    tracing::warn!(
        rule = %alert.rule_id,
        severity = alert.severity.as_str(),
        pid = alert.process.pid,
        image = %alert.process.image,
        actions = alert.actions.len(),
        "{}",
        alert.summary
    );
    let acted = alert.actions.iter().any(|o| o.ok);
    // The employee's activity log shows what Kestrel did and anything notable;
    // low-signal audit-only detections stay in the console.
    if acted || alert.severity >= Severity::Medium {
        let item = alert_activity(&alert);
        core.notify_tray(
            item,
            crate::agent::should_push(alert.severity, acted) && alert.mode != RuleMode::Off,
            activity_owner(&alert),
        );
    }
    let mut upload = alert;
    core.filter().scrub_alert(&mut upload);
    core.enqueue(&AgentPayload::Alert(Box::new(upload)));
}

/// Who an alert's tray item belongs to (M3): the interactive user that ran
/// the process, as a lower-case account name or SID. Service accounts and
/// unknown users make it machine-wide.
pub fn activity_owner(a: &Alert) -> Option<String> {
    let u = a.process.user.as_deref()?.trim().to_ascii_lowercase();
    const SERVICE: &[&str] = &[
        "nt authority\\system",
        "nt authority\\local service",
        "nt authority\\network service",
        "s-1-5-18",
        "s-1-5-19",
        "s-1-5-20",
    ];
    if u.is_empty()
        || SERVICE.contains(&u.as_str())
        || u.starts_with("window manager\\")
        || u.starts_with("font driver host\\")
        || u.starts_with("nt service\\")
    {
        return None;
    }
    Some(u)
}

/// Spawn the detection thread.
#[allow(clippy::too_many_arguments)]
pub fn spawn(
    core: Arc<Core>,
    host: HostContext,
    policy: Policy,
    bundle: RuleBundle,
    seeds: Vec<ProcessInfo>,
    events: mpsc::Receiver<Event>,
    enrich: mpsc::Receiver<LateEnrichment>,
    ctl: mpsc::UnboundedReceiver<EngineCtl>,
    rt: tokio::runtime::Handle,
) -> Result<std::thread::JoinHandle<()>> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(), String>>();
    let h = std::thread::Builder::new()
        .name("kestrel-detect".into())
        .spawn(move || {
            let local = match tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            let engine = match Engine::new(host.clone(), policy.clone(), bundle.clone()) {
                Ok(e) => Ok(e),
                Err(e) => {
                    // A bad cached custom bundle must not disable builtin rules.
                    tracing::error!(
                        "engine rejected cached rules ({e}); starting with builtin rules only"
                    );
                    Engine::new(host, policy, RuleBundle::default())
                }
            };
            let mut engine = match engine {
                Ok(e) => e,
                Err(e) => {
                    let _ = ready_tx.send(Err(e.to_string()));
                    return;
                }
            };
            for s in seeds {
                engine.seed_process(s);
            }
            let _ = ready_tx.send(Ok(()));
            local.block_on(detect_loop(core, engine, events, enrich, ctl, rt));
        })?;
    match ready_rx.recv() {
        Ok(Ok(())) => Ok(h),
        Ok(Err(e)) => Err(anyhow::anyhow!("detection engine failed to start: {e}")),
        Err(_) => Err(anyhow::anyhow!("detection thread exited during startup")),
    }
}

/// Plant decoys and keep the engine's armed set in sync with what is really on disk.
///
/// The platform never overwrites a file it didn't plant (contract shared with
/// `kestrel-win`'s canary registry) and returns only the paths that now hold
/// Kestrel decoys. So: returned → `arm_canary`; requested but not returned
/// (a real file already exists there, e.g. a genuine `.aws\credentials`, or
/// the write failed) → `disarm_canary`, so touching a real file never fires ST-16.
fn plant_canaries(core: &Core, engine: &mut Engine) {
    if !core.policy().canaries {
        for p in engine.armed_canaries() {
            engine.disarm_canary(&p);
        }
        return;
    }
    let mut specs = vec![];
    for profile in core.platform.user_profiles() {
        match std::panic::catch_unwind(AssertUnwindSafe(|| engine.canaries(&profile))) {
            Ok(s) => specs.extend(s),
            Err(_) => tracing::error!("engine panicked building canaries"),
        }
    }
    if specs.is_empty() {
        return;
    }
    let planted = core.platform.plant_canaries(&specs);
    let norm = |p: &str| p.replace('/', "\\").to_ascii_lowercase();
    let planted_set: std::collections::HashSet<String> = planted.iter().map(|p| norm(p)).collect();
    let mut skipped = 0usize;
    for s in &specs {
        if planted_set.contains(&norm(&s.path)) {
            engine.arm_canary(&s.path);
        } else {
            skipped += 1;
            engine.disarm_canary(&s.path);
            if kestrel_detect::is_conditional_canary(&s.path) {
                tracing::debug!(path = %s.path, "real file present; conditional decoy not planted");
            }
        }
    }
    tracing::info!(
        planted = planted.len(),
        skipped,
        armed = engine.armed_canaries().len(),
        "canaries planted"
    );
}

async fn detect_loop(
    core: Arc<Core>,
    mut engine: Engine,
    mut events: mpsc::Receiver<Event>,
    mut enrich: mpsc::Receiver<LateEnrichment>,
    mut ctl: mpsc::UnboundedReceiver<EngineCtl>,
    rt: tokio::runtime::Handle,
) {
    let mut disp = Dispatcher {
        core: core.clone(),
        rt,
        workers: HashMap::new(),
    };
    let mut batch: Vec<Event> = Vec::new();
    let mut batch_started: Option<Instant> = None;
    let mut tick = tokio::time::interval(core.tuning.tick);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let max_batch = core.tuning.batch_max_events.max(1);
    let max_delay = core.tuning.batch_max_delay;
    let mut ticks: u64 = 0;
    plant_canaries(&core, &mut engine);

    let flush = |batch: &mut Vec<Event>, started: &mut Option<Instant>| {
        if !batch.is_empty() {
            let events = std::mem::take(batch);
            core.enqueue(&AgentPayload::Events { events });
        }
        *started = None;
    };

    loop {
        tokio::select! {
            biased;
            _ = core.shutdown.cancelled() => break,
            Some(c) = ctl.recv() => match c {
                EngineCtl::Policy(p) => {
                    let canaries = p.canaries;
                    if std::panic::catch_unwind(AssertUnwindSafe(|| engine.update_policy(*p))).is_err() {
                        tracing::error!("engine panicked applying policy");
                    }
                    if canaries { plant_canaries(&core, &mut engine); }
                }
                EngineCtl::Rules(b, tx) => {
                    let r = std::panic::catch_unwind(AssertUnwindSafe(|| engine.update_rules(b)))
                        .unwrap_or_else(|_| Err(kestrel_detect::DetectError::InvalidRule { id: "*".into(), reason: "engine panicked".into() }));
                    let _ = tx.send(r.map_err(|e| e.to_string()));
                }
                EngineCtl::PlantCanaries => plant_canaries(&core, &mut engine),
            },
            Some(le) = enrich.recv() => {
                // H7 / M12: facts that missed the first-run budget, or a
                // revoked signature found by the background check.
                let now = kestrel_common::now_ms();
                match std::panic::catch_unwind(AssertUnwindSafe(|| engine.enrich_process(&le.guid, le.facts, now))) {
                    Ok(outs) => route(&mut disp, outs),
                    Err(_) => {
                        core.stats.engine_panics.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(pid = le.pid, "engine panicked on late enrichment");
                    }
                }
            },
            ev = events.recv() => {
                let Some(ev) = ev else { break };
                // Drain whatever is already queued to amortise wakeups.
                let mut chunk = vec![ev];
                while chunk.len() < 1024 {
                    match events.try_recv() { Ok(e) => chunk.push(e), Err(_) => break }
                }
                let filter = core.filter();
                for ev in chunk {
                    core.stats.events_seen.fetch_add(1, Ordering::Relaxed);
                    match std::panic::catch_unwind(AssertUnwindSafe(|| engine.process(&ev))) {
                        Ok(outs) => route(&mut disp, outs),
                        Err(_) => {
                            core.stats.engine_panics.fetch_add(1, Ordering::Relaxed);
                            tracing::error!(kind = ev.kind().as_str(), pid = ev.pid, "engine panicked on event; skipped");
                        }
                    }
                    if let Some(up) = filter.filter_event(&ev) {
                        batch.push(up);
                        batch_started.get_or_insert_with(Instant::now);
                        if batch.len() >= max_batch {
                            flush(&mut batch, &mut batch_started);
                        }
                    }
                }
            },
            _ = tick.tick() => {
                ticks += 1;
                match std::panic::catch_unwind(AssertUnwindSafe(|| engine.tick(kestrel_common::now_ms()))) {
                    Ok(outs) => route(&mut disp, outs),
                    Err(_) => {
                        core.stats.engine_panics.fetch_add(1, Ordering::Relaxed);
                        tracing::error!("engine panicked on tick");
                    }
                }
                if batch_started.is_some_and(|s| s.elapsed() >= max_delay) {
                    flush(&mut batch, &mut batch_started);
                }
                if ticks.is_multiple_of(240) {
                    disp.gc();
                }
            }
        }
    }
    flush(&mut batch, &mut batch_started);
}

fn route(disp: &mut Dispatcher, outs: Vec<Output>) {
    for o in outs {
        match o {
            Output::Alert(d) => {
                let key = d.alert.process.guid.0.clone();
                disp.dispatch(key, Job::Detection(Box::new(d)));
            }
            Output::Action(a) => {
                let key = action_key(&a);
                disp.dispatch(key, Job::Action(a));
            }
        }
    }
}

// ------------------------------------------------------------- tray wording

fn data_phrase(cats: &[DataCategory]) -> Option<&'static str> {
    use DataCategory::*;
    let first = cats.iter().min()?;
    Some(match first {
        BrowserPasswords => "your saved passwords",
        BrowserCookies | BrowserMasterKey => "your browser logins",
        BrowserAutofill => "your saved cards and autofill data",
        CryptoWallet => "your crypto wallets",
        Discord => "your Discord account",
        Telegram => "your Telegram account",
        Steam => "your Steam account",
        FtpClient => "your saved FTP logins",
        Vpn => "your VPN profile",
        CloudToken => "your cloud sign-in tokens",
        PasswordManager => "your password manager",
        Email => "your email",
        SshKeys => "your SSH keys",
    })
}

fn action_phrase(outcomes: &[ActionOutcome]) -> Option<String> {
    let ok: Vec<&ResponseAction> = outcomes
        .iter()
        .filter(|o| o.ok)
        .map(|o| &o.action)
        .collect();
    if ok.is_empty() {
        return None;
    }
    let mut parts: Vec<&str> = vec![];
    let mut push = |s: &'static str| {
        if !parts.contains(&s) {
            parts.push(s)
        }
    };
    for a in ok {
        match a {
            ResponseAction::KillProcess { .. } => push("Stopped the app"),
            ResponseAction::SuspendProcess { .. } => push("Paused the app"),
            ResponseAction::QuarantineFile { .. } => push("quarantined the file"),
            ResponseAction::BlockDestination { .. } | ResponseAction::BlockImageNetwork { .. } => {
                push("blocked its internet access")
            }
            ResponseAction::IsolateHost { .. } => push("disconnected this PC from the network"),
            _ => {}
        }
    }
    if parts.is_empty() {
        return None;
    }
    let mut s = parts.join(", ");
    if let Some(f) = s.get_mut(0..1) {
        f.make_ascii_uppercase();
    }
    Some(s)
}

fn file_name(p: &str) -> &str {
    p.rsplit(['\\', '/']).next().unwrap_or(p)
}

/// Plain-language activity item for the tray.
pub fn alert_activity(a: &Alert) -> ActivityItem {
    let acted = action_phrase(&a.actions);
    let stopped = a.actions.iter().any(|o| {
        o.ok && matches!(
            o.action,
            ResponseAction::KillProcess { .. }
                | ResponseAction::SuspendProcess { .. }
                | ResponseAction::BlockDestination { .. }
                | ResponseAction::BlockImageNetwork { .. }
                | ResponseAction::IsolateHost { .. }
                | ResponseAction::QuarantineFile { .. }
        )
    });
    let rid = a.rule_id.as_str();
    let title = match (stopped, data_phrase(&a.data_at_risk)) {
        (true, Some(d)) => format!("Kestrel stopped an app from stealing {d}"),
        (false, Some(d)) => format!("Kestrel noticed an app reaching for {d} and alerted IT"),
        (true, None) if matches!(rid, "ST-10" | "ST-11") => {
            "Kestrel blocked a suspicious command you may have been tricked into running".into()
        }
        (true, None) if rid.starts_with("TP-") => {
            "Kestrel blocked an attempt to switch off its protection".into()
        }
        (true, None) => "Kestrel stopped a suspicious app".into(),
        (false, None) if rid.starts_with("TP-") => {
            "Kestrel noticed an attempt to tamper with its protection".into()
        }
        (false, None) => "Kestrel noticed suspicious activity and alerted IT".into(),
    };
    let image = file_name(&a.process.image).to_string();
    let mut body = if image.is_empty()
        || a.summary
            .to_ascii_lowercase()
            .starts_with(&image.to_ascii_lowercase())
    {
        a.summary.clone()
    } else {
        format!("{} — {}", image, a.summary)
    };
    if !a.data_at_risk.is_empty() {
        let labels: Vec<&str> = a.data_at_risk.iter().map(|c| c.label()).collect();
        body.push_str(&format!(" (at risk: {})", labels.join(", ")));
    }
    if stopped {
        body.push_str(" If you think this was a mistake, you can ask IT to review it.");
    }
    ActivityItem {
        id: Uuid::new_v4(),
        ts: a.ts,
        title,
        body,
        severity: a.severity,
        alert_id: Some(a.id),
        file: if a.process.image.is_empty() {
            None
        } else {
            Some(a.process.image.clone())
        },
        action_taken: acted.unwrap_or_else(|| "Reported to IT".into()),
        review: None,
    }
}

/// Activity item for a command executed on IT's request (only the visible ones).
pub fn command_activity(action: &ResponseAction, o: &ActionOutcome) -> Option<ActivityItem> {
    if !o.ok {
        return None;
    }
    let (title, body, sev) = match action {
        ResponseAction::IsolateHost { .. } => (
            "IT disconnected this PC from the network",
            "Your IT team isolated this computer while they investigate. Kestrel can still reach IT.",
            Severity::High,
        ),
        ResponseAction::ReleaseHost => {
            ("Network access restored", "Your IT team reconnected this computer to the network.", Severity::Info)
        }
        ResponseAction::KillProcess { .. } => ("IT stopped an app on this PC", "", Severity::Medium),
        ResponseAction::QuarantineFile { path, .. } => {
            return Some(ActivityItem {
                id: Uuid::new_v4(),
                ts: o.ts,
                title: "IT quarantined a file on this PC".into(),
                body: file_name(path).to_string(),
                severity: Severity::Medium,
                alert_id: None,
                file: Some(path.clone()),
                action_taken: "Quarantined".into(),
                review: None,
            })
        }
        ResponseAction::RestoreFile { .. } => ("IT restored a quarantined file", "", Severity::Info),
        _ => return None,
    };
    Some(ActivityItem {
        id: Uuid::new_v4(),
        ts: o.ts,
        title: title.into(),
        body: body.into(),
        severity: sev,
        alert_id: None,
        file: None,
        action_taken: action.name().replace('_', " "),
        review: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{PathClass, ProcessGuid, SignatureState};

    fn alert(cats: Vec<DataCategory>, actions: Vec<ActionOutcome>) -> Alert {
        Alert {
            id: Uuid::new_v4(),
            ts: 1,
            rule_id: "ST-04".into(),
            rule_name: "Steal-then-send".into(),
            rule_author: None,
            severity: Severity::Critical,
            attack: vec![],
            mode: RuleMode::Protect,
            summary: "read Chrome Login Data then connected to 203.0.113.7".into(),
            process: ProcessInfo {
                guid: ProcessGuid("g".into()),
                pid: 1,
                ppid: 0,
                parent_guid: None,
                image: r"C:\Users\a\Downloads\setup_x64.exe".into(),
                cmdline: String::new(),
                user: None,
                integrity: None,
                start_ts: 0,
                exit_ts: None,
                signer: None,
                signed: SignatureState::Unsigned,
                sha256: None,
                motw_zone: None,
                file_size: None,
                path_class: PathClass::Downloads,
            },
            ancestry: vec![],
            data_at_risk: cats,
            evidence: vec![],
            actions,
        }
    }

    #[test]
    fn plain_language_titles() {
        let kill = ActionOutcome {
            action: ResponseAction::KillProcess {
                pid: 1,
                guid: None,
                tree: true,
            },
            ok: true,
            detail: String::new(),
            ts: 1,
            artifact: None,
        };
        let a = alert(
            vec![DataCategory::BrowserCookies, DataCategory::BrowserPasswords],
            vec![kill],
        );
        let it = alert_activity(&a);
        assert_eq!(
            it.title,
            "Kestrel stopped an app from stealing your saved passwords"
        );
        assert_eq!(it.action_taken, "Stopped the app");
        assert!(it.body.starts_with("setup_x64.exe — read Chrome"));
        let mut b = a.clone();
        b.summary = "setup_x64.exe read Chrome Login Data".into();
        assert_eq!(alert_activity(&b).body.matches("setup_x64.exe").count(), 1);
        assert_eq!(it.alert_id, Some(a.id));
        let audit = alert(vec![DataCategory::CryptoWallet], vec![]);
        assert_eq!(
            alert_activity(&audit).title,
            "Kestrel noticed an app reaching for your crypto wallets and alerted IT"
        );
        assert_eq!(alert_activity(&audit).action_taken, "Reported to IT");
    }

    #[test]
    fn activity_owners() {
        let mut a = alert(vec![], vec![]);
        a.process.user = Some("CORP\\Alice".into());
        assert_eq!(activity_owner(&a).as_deref(), Some("corp\\alice"));
        a.process.user = Some("NT AUTHORITY\\SYSTEM".into());
        assert_eq!(activity_owner(&a), None);
        a.process.user = Some("S-1-5-21-1-2-3-1001".into());
        assert_eq!(activity_owner(&a).as_deref(), Some("s-1-5-21-1-2-3-1001"));
        a.process.user = None;
        assert_eq!(activity_owner(&a), None);
    }
}
