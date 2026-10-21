//! Sensor orchestration: translator thread, ETW sessions, event-log
//! subscriptions and the watchdog that restarts stopped sessions and emits
//! tamper events (TP-01 signals).

use super::etw::{self, Counters, FileState, Raw, SensorOpts, Session, SessionKind, Sink};
use super::evtsub::{self, Subscription};
use super::translate::{Shared, Translator};
use crate::consts;
use crate::fileagg::FileScope;
use kestrel_common::{Event, TamperKind};
use kestrel_platform::{SensorConfig, SensorHandle, SensorStats};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct Sensors {
    /// Producers (ETW sessions, subscriptions, watchers) stop.
    stop: Arc<AtomicBool>,
    /// The translator drains its queue and exits (set after the producers
    /// were joined; see [`crate::pump`]).
    drain: Arc<AtomicBool>,
    counters: Arc<Counters>,
    dpapi_channel: Arc<AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    translator: Mutex<Option<JoinHandle<()>>>,
}

impl SensorHandle for Sensors {
    fn stats(&self) -> SensorStats {
        let c = &self.counters;
        SensorStats {
            etw_ok: c.sessions_ok.load(Ordering::Relaxed),
            // ETW EventsLost + events Kestrel had to drop (internal queue / agent channel full).
            // + file-activity operations dropped by the aggregator's caps
            // + persistence records dropped by the enrichment queue (V-M9).
            // Not counted: `raw_discarded_shutdown` (stragglers of sessions
            // being torn down during an orderly sensor restart, crate::pump).
            events_lost: c.kernel_lost() + c.internal_dropped(),
            // Owner-PC triage 2026-10-22: the two causes need different
            // fixes (consumer too slow / buffers too small vs Kestrel's own
            // queues), so they are also reported separately.
            kernel_events_lost: c.kernel_lost(),
            internal_dropped: c.internal_dropped(),
            buffers_lost: c.etw_buffers_lost.load(Ordering::Relaxed),
            events_total: c.emitted.load(Ordering::Relaxed),
            sysmon_present: c.sysmon_present.load(Ordering::Relaxed),
            dpapi_channel_enabled: self.dpapi_channel.load(Ordering::Relaxed),
            // v1 ships no AMSI provider DLL; script content comes from PowerShell 4104.
            amsi_ok: false,
        }
    }

    fn stop(&self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // Producers first (the watchdog stops the ETW sessions and drops the
        // event-log subscriptions), then the translator drains what they
        // delivered. Stopping the translator first turned every event of
        // the still-running sessions into a "lost" event (fresh-install
        // lab, 2026-10-21).
        if let Ok(mut t) = self.threads.lock() {
            for h in t.drain(..) {
                let _ = h.join();
            }
        }
        self.drain.store(true, Ordering::SeqCst);
        if let Some(h) = self.translator.lock().ok().and_then(|mut t| t.take()) {
            let _ = h.join();
        }
        let c = &self.counters;
        tracing::info!(
            etw_events_lost = c.etw_events_lost.load(Ordering::Relaxed),
            raw_dropped = c.raw_dropped.load(Ordering::Relaxed),
            out_dropped = c.out_dropped.load(Ordering::Relaxed),
            discarded_at_stop = c.raw_discarded_shutdown.load(Ordering::Relaxed),
            "sensors stopped"
        );
    }
}

impl Drop for Sensors {
    fn drop(&mut self) {
        SensorHandle::stop(self);
    }
}

pub fn start(
    shared: Arc<Shared>,
    cfg: SensorConfig,
    out: mpsc::Sender<Event>,
    wfp_keys: Arc<RwLock<Vec<String>>>,
) -> anyhow::Result<Sensors> {
    let counters = shared.counters.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let drain = Arc::new(AtomicBool::new(false));
    let (tx, rx) = sync_channel::<Raw>(65_536);
    let sink = Sink {
        tx,
        counters: counters.clone(),
        self_pid: cfg.self_pid,
        closing: stop.clone(),
    };
    // lsass pid for the Audit-API failed-open filter (updated on ProcessStart).
    counters
        .lsass_pid
        .store(find_lsass_pid().unwrap_or(0), Ordering::Relaxed);
    let g = &cfg.groups;
    let system_device = shared
        .devmap
        .read()
        .ok()
        .and_then(|m| m.device_for_drive(kestrel_common::system_drive()))
        .unwrap_or_default();
    let file_state = Arc::new(Mutex::new(FileState::new(FileScope::new(&system_device))));
    let opts = SensorOpts {
        dns: cfg.dns,
        script_content: cfg.script_content,
        file_activity: g.file_activity,
        persistence: g.persistence,
        credential_access: g.credential_access,
        file_state: file_state.clone(),
        canaries: shared.canaries.clone(),
    };

    let mut threads: Vec<JoinHandle<()>> = Vec::new();
    let translator = {
        let tr = Translator::new(shared.clone(), out);
        let dr = drain.clone();
        std::thread::Builder::new()
            .name("kestrel-translate".into())
            .spawn(move || tr.run(rx, dr))?
    };

    // Ransomware decoys: planted only by the installed service (LocalSystem),
    // never by an interactive `sensors-test`; already-planted ones are
    // always matched.
    let mut decoys = Vec::new();
    if g.file_activity {
        decoys = if g.ransomware_canaries && super::rcanary::running_as_system() {
            super::rcanary::plant(&shared.state_dir, &super::host::user_profiles())
        } else {
            super::rcanary::planted(&shared.state_dir)
        };
        let nt: Vec<String> = shared
            .devmap
            .read()
            .map(|m| decoys.iter().filter_map(|p| m.to_nt_lower(p)).collect())
            .unwrap_or_default();
        if let Ok(mut st) = file_state.lock() {
            st.agg.set_canaries(nt);
        }
        tracing::info!(decoys = decoys.len(), "ransomware decoys watched");
    }

    // Start sessions now so configuration errors surface to the caller.
    let mut sessions: Vec<Session> = Vec::new();
    let mut errors = Vec::new();
    for kind in SessionKind::required(&opts) {
        match etw::start_session(kind, &sink, &opts) {
            Ok(s) => sessions.push(s),
            Err(e) => errors.push(format!("{}: {e}", kind.name())),
        }
    }
    if sessions.is_empty() {
        stop.store(true, Ordering::SeqCst);
        for t in threads {
            let _ = t.join();
        }
        drain.store(true, Ordering::SeqCst);
        let _ = translator.join();
        anyhow::bail!(
            "no ETW session could be started (agent must run as SYSTEM/admin): {}",
            errors.join("; ")
        );
    }
    for e in &errors {
        tracing::warn!("ETW session failed to start, watchdog will retry: {e}");
    }
    let cmd_session = match etw::start_session(SessionKind::ProcCmd, &sink, &opts) {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::warn!("command-line fallback session unavailable: {e}");
            None
        }
    };
    counters
        .sessions_ok
        .store(errors.is_empty(), Ordering::Relaxed);

    let dpapi_channel = Arc::new(AtomicBool::new(
        evtsub::channel_enabled(consts::channel::DPAPI_DEBUG).unwrap_or(false),
    ));
    if !evtsub::enable_wfp_policy_audit() {
        tracing::warn!("could not enable WFP policy-change auditing (5446-5450)");
    }

    if g.persistence {
        match super::regwatch::start(sink.clone(), stop.clone()) {
            Ok(h) => threads.push(h),
            Err(e) => tracing::warn!("registry watcher failed to start: {e}"),
        }
    }
    if g.file_activity && !decoys.is_empty() {
        match super::rcanary::start_poller(
            decoys,
            shared.devmap.clone(),
            file_state.clone(),
            sink.clone(),
            stop.clone(),
        ) {
            Ok(h) => threads.push(h),
            Err(e) => tracing::warn!("decoy poller failed to start: {e}"),
        }
    }

    {
        let st = stop.clone();
        let dp = dpapi_channel.clone();
        let sysmon_wanted = cfg.sysmon;
        threads.push(
            std::thread::Builder::new()
                .name("kestrel-etw-watchdog".into())
                .spawn(move || {
                    watchdog(
                        sink,
                        opts,
                        sessions,
                        cmd_session,
                        st,
                        dp,
                        sysmon_wanted,
                        wfp_keys,
                    );
                })?,
        );
    }

    Ok(Sensors {
        stop,
        drain,
        counters,
        dpapi_channel,
        threads: Mutex::new(threads),
        translator: Mutex::new(Some(translator)),
    })
}

#[allow(clippy::too_many_arguments)]
fn watchdog(
    sink: Sink,
    opts: SensorOpts,
    mut sessions: Vec<Session>,
    mut cmd: Option<Session>,
    stop: Arc<AtomicBool>,
    dpapi_channel: Arc<AtomicBool>,
    sysmon_wanted: bool,
    wfp_keys: Arc<RwLock<Vec<String>>>,
) {
    let counters = sink.counters.clone();
    let mut sysmon: Option<Subscription> = None;
    let persist_subs: Vec<Subscription> = if opts.persistence {
        evtsub::subscribe_persistence(sink.clone())
    } else {
        Vec::new()
    };
    let mut last_health = Instant::now();
    let mut wfp_sub: Option<Subscription> =
        evtsub::subscribe_wfp_audit(sink.clone(), wfp_keys.clone());
    let mut last_check = Instant::now() - Duration::from_secs(60);
    let mut last_slow = Instant::now() - Duration::from_secs(600);
    let mut lost_base: (u64, u64) = (0, 0);
    let mut last_lost_total = 0u64;
    let mut last_lost_tamper = Instant::now() - Duration::from_secs(3600);
    let mut backoff: std::collections::HashMap<&'static str, (Instant, u64)> = Default::default();
    let required = SessionKind::required(&opts);

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        if last_check.elapsed() < Duration::from_secs(5) {
            continue;
        }
        last_check = Instant::now();

        // 1. Session liveness (ProcessTrace returned or QUERY fails → stopped).
        let mut all_ok = true;
        for &kind in &required {
            let idx = sessions.iter().position(|s| s.kind == kind);
            let alive = idx
                .map(|i| {
                    sessions[i].alive.load(Ordering::SeqCst)
                        && etw::query_session(kind.name()).is_some()
                })
                .unwrap_or(false);
            if alive {
                continue;
            }
            all_ok = false;
            if let Some(i) = idx {
                let mut s = sessions.remove(i);
                // Fold the dead session's loss counters into the base.
                lost_base.0 += s.last_lost.0;
                lost_base.1 += s.last_lost.1;
                s.stop();
                sink.send(Raw::Tamper {
                    kind: TamperKind::EtwSessionStopped,
                    detail: format!(
                        "ETW session {} stopped unexpectedly after {}s; restarting",
                        kind.name(),
                        s.started.elapsed().as_secs()
                    ),
                });
            }
            let (next, delay) = backoff
                .get(kind.name())
                .copied()
                .unwrap_or((Instant::now(), 2));
            if Instant::now() < next {
                continue;
            }
            match etw::start_session(kind, &sink, &opts) {
                Ok(s) => {
                    backoff.remove(kind.name());
                    sessions.push(s);
                }
                Err(e) => {
                    tracing::warn!("restart of {} failed: {e}", kind.name());
                    backoff.insert(
                        kind.name(),
                        (
                            Instant::now() + Duration::from_secs(delay),
                            (delay * 2).min(60),
                        ),
                    );
                }
            }
        }
        if let Some(c) = cmd.as_mut() {
            if !c.alive.load(Ordering::SeqCst) {
                c.stop();
                cmd = etw::start_session(SessionKind::ProcCmd, &sink, &opts).ok();
            }
        }

        // 2. Loss counters (cumulative over sensor restarts: `carry`).
        let carry = (
            counters.etw_events_lost_carry.load(Ordering::Relaxed),
            counters.etw_buffers_lost_carry.load(Ordering::Relaxed),
        );
        let lost = session_loss(&mut sessions, lost_base);
        counters
            .etw_events_lost
            .store(carry.0 + lost.0, Ordering::Relaxed);
        counters
            .etw_buffers_lost
            .store(carry.1 + lost.1, Ordering::Relaxed);
        let total = lost.0 + lost.1;
        if total > last_lost_total && last_lost_tamper.elapsed() > Duration::from_secs(300) {
            sink.send(Raw::Tamper {
                kind: TamperKind::EventsLost,
                detail: format!(
                    "ETW lost {} events / {} buffers since start (+{} in the last interval)",
                    lost.0,
                    lost.1,
                    total - last_lost_total
                ),
            });
            last_lost_tamper = Instant::now();
        }
        last_lost_total = total;

        if last_health.elapsed() >= Duration::from_secs(300) {
            last_health = Instant::now();
            tracing::info!(
                raw_dropped = counters.raw_dropped.load(Ordering::Relaxed),
                out_dropped = counters.out_dropped.load(Ordering::Relaxed),
                file_agg_dropped = counters.file_agg_dropped.load(Ordering::Relaxed),
                file_activity = counters.file_activity_emitted.load(Ordering::Relaxed),
                reg_attributed = counters.reg_attributed.load(Ordering::Relaxed),
                reg_unattributed = counters.reg_unattributed.load(Ordering::Relaxed),
                reg_watch_keys = counters.reg_watch_keys.load(Ordering::Relaxed),
                persist_events = counters.persist_events.load(Ordering::Relaxed),
                persist_dropped = counters.persist_dropped.load(Ordering::Relaxed),
                kernel_events_lost = counters.kernel_lost(),
                internal_dropped = counters.internal_dropped(),
                file_prefiltered = counters.file_prefiltered.load(Ordering::Relaxed),
                pid_reuse_dropped = counters.pid_reuse_dropped.load(Ordering::Relaxed),
                "sensor health"
            );
        }

        // 3. Slow checks: provider still enabled on our sessions, Sysmon, DPAPI channel.
        if last_slow.elapsed() >= Duration::from_secs(30) {
            last_slow = Instant::now();
            let mut restart: Vec<SessionKind> = Vec::new();
            for s in &sessions {
                let Some(q) = etw::query_session(s.kind.name()) else {
                    continue;
                };
                for p in etw::watched_providers(s.kind, &opts) {
                    if etw::provider_enabled_for(p, q.logger_id) == Some(false) {
                        sink.send(Raw::Tamper {
                            kind: TamperKind::EtwProviderDisabled,
                            detail: format!("provider {{{p}}} no longer enabled on ETW session {}; restarting session", s.kind.name()),
                        });
                        restart.push(s.kind);
                        break;
                    }
                }
            }
            for kind in restart {
                if let Some(i) = sessions.iter().position(|s| s.kind == kind) {
                    let mut s = sessions.remove(i);
                    lost_base.0 += s.last_lost.0;
                    lost_base.1 += s.last_lost.1;
                    s.stop();
                }
                if let Ok(s) = etw::start_session(kind, &sink, &opts) {
                    sessions.push(s);
                }
            }
            if sysmon_wanted && sysmon.is_none() {
                sysmon = evtsub::subscribe_sysmon(sink.clone());
            }
            counters
                .sysmon_present
                .store(sysmon.is_some(), Ordering::Relaxed);
            if wfp_sub.is_none() {
                wfp_sub = evtsub::subscribe_wfp_audit(sink.clone(), wfp_keys.clone());
            }
            dpapi_channel.store(
                evtsub::channel_enabled(consts::channel::DPAPI_DEBUG).unwrap_or(false),
                Ordering::Relaxed,
            );
        }
        counters.sessions_ok.store(
            all_ok
                && required
                    .iter()
                    .all(|k| sessions.iter().any(|s| s.kind == *k)),
            Ordering::Relaxed,
        );
    }

    // Orderly shutdown: drop subscriptions, stop sessions (by name as well).
    drop(sysmon);
    drop(wfp_sub);
    drop(persist_subs);
    // Keep the kernel loss of these sessions for the next sensor instance
    // (a restart must not reset the reported counter).
    let lost = session_loss(&mut sessions, lost_base);
    counters
        .etw_events_lost_carry
        .fetch_add(lost.0, Ordering::Relaxed);
    counters
        .etw_buffers_lost_carry
        .fetch_add(lost.1, Ordering::Relaxed);
    for mut s in sessions {
        s.stop();
    }
    if let Some(mut c) = cmd {
        c.stop();
    }
    counters.sessions_ok.store(false, Ordering::Relaxed);
}

/// Kernel-side loss (`EventsLost`, buffers lost) of the running sessions
/// plus `base` (sessions of this instance that died and were restarted).
fn session_loss(sessions: &mut [Session], base: (u64, u64)) -> (u64, u64) {
    let mut lost = base;
    for s in sessions.iter_mut() {
        if let Some(q) = etw::query_session(s.kind.name()) {
            s.last_lost = (q.events_lost, q.buffers_lost);
        }
        lost.0 += s.last_lost.0;
        lost.1 += s.last_lost.1;
    }
    lost
}

/// lsass.exe in System32 whose parent is wininit.exe (falls back to the
/// only lsass.exe when the parent cannot be matched).
fn find_lsass_pid() -> Option<u32> {
    let rows = super::snapshot::toolhelp_rows();
    let wininit: Vec<u32> = rows
        .iter()
        .filter(|r| r.exe.eq_ignore_ascii_case("wininit.exe"))
        .map(|r| r.pid)
        .collect();
    let lsass: Vec<&super::snapshot::Row> = rows
        .iter()
        .filter(|r| r.exe.eq_ignore_ascii_case("lsass.exe"))
        .collect();
    lsass
        .iter()
        .find(|r| wininit.contains(&r.ppid))
        .or_else(|| (lsass.len() == 1).then(|| &lsass[0]))
        .map(|r| r.pid)
}
