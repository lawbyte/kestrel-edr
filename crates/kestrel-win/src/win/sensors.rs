//! Sensor orchestration: translator thread, ETW sessions, event-log
//! subscriptions and the watchdog that restarts stopped sessions and emits
//! tamper events (TP-01 signals).

use super::etw::{self, Counters, Raw, SensorOpts, Session, SessionKind, Sink};
use super::evtsub::{self, Subscription};
use super::translate::{Shared, Translator};
use crate::consts;
use kestrel_common::{Event, TamperKind};
use kestrel_platform::{SensorConfig, SensorHandle, SensorStats};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct Sensors {
    stop: Arc<AtomicBool>,
    counters: Arc<Counters>,
    dpapi_channel: Arc<AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl SensorHandle for Sensors {
    fn stats(&self) -> SensorStats {
        let c = &self.counters;
        SensorStats {
            etw_ok: c.sessions_ok.load(Ordering::Relaxed),
            // ETW EventsLost + events Kestrel had to drop (internal queue / agent channel full).
            events_lost: c.etw_events_lost.load(Ordering::Relaxed)
                + c.raw_dropped.load(Ordering::Relaxed)
                + c.out_dropped.load(Ordering::Relaxed),
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
        if let Ok(mut t) = self.threads.lock() {
            for h in t.drain(..) {
                let _ = h.join();
            }
        }
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
    let (tx, rx) = sync_channel::<Raw>(65_536);
    let sink = Sink {
        tx,
        counters: counters.clone(),
        self_pid: cfg.self_pid,
    };
    let opts = SensorOpts {
        dns: cfg.dns,
        script_content: cfg.script_content,
    };

    let mut threads = Vec::new();
    {
        let tr = Translator::new(shared.clone(), out);
        let st = stop.clone();
        threads.push(
            std::thread::Builder::new()
                .name("kestrel-translate".into())
                .spawn(move || tr.run(rx, st))?,
        );
    }

    // Start sessions now so configuration errors surface to the caller.
    let mut sessions: Vec<Session> = Vec::new();
    let mut errors = Vec::new();
    for kind in [SessionKind::Core, SessionKind::Io] {
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
        counters,
        dpapi_channel,
        threads: Mutex::new(threads),
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
    let mut wfp_sub: Option<Subscription> =
        evtsub::subscribe_wfp_audit(sink.clone(), wfp_keys.clone());
    let mut last_check = Instant::now() - Duration::from_secs(60);
    let mut last_slow = Instant::now() - Duration::from_secs(600);
    let mut lost_base: (u64, u64) = (0, 0);
    let mut last_lost_total = 0u64;
    let mut last_lost_tamper = Instant::now() - Duration::from_secs(3600);
    let mut backoff: std::collections::HashMap<&'static str, (Instant, u64)> = Default::default();
    let required = [SessionKind::Core, SessionKind::Io];

    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(500));
        if last_check.elapsed() < Duration::from_secs(5) {
            continue;
        }
        last_check = Instant::now();

        // 1. Session liveness (ProcessTrace returned or QUERY fails → stopped).
        let mut all_ok = true;
        for kind in required {
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

        // 2. Loss counters.
        let mut lost = lost_base;
        for s in sessions.iter_mut() {
            if let Some(q) = etw::query_session(s.kind.name()) {
                s.last_lost = (q.events_lost, q.buffers_lost);
            }
            lost.0 += s.last_lost.0;
            lost.1 += s.last_lost.1;
        }
        counters.etw_events_lost.store(lost.0, Ordering::Relaxed);
        counters.etw_buffers_lost.store(lost.1, Ordering::Relaxed);
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
    for mut s in sessions {
        s.stop();
    }
    if let Some(mut c) = cmd {
        c.stop();
    }
    counters.sessions_ok.store(false, Ordering::Relaxed);
}
