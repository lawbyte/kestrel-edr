//! `WindowsPlatform`: the `kestrel_platform::Platform` implementation.

use super::enrich::Enricher;
use super::etw::Counters;
use super::hardening::Hardener;
use super::host::{self, AvCache, SelfUsage};
use super::quarantine::Vault;
use super::translate::Shared;
use super::util::*;
use super::wfp::Wfp;
use super::{autorun_resp, devmap, respond, scan, sensors, snapshot, tray_server, triage};
use crate::canary::{self, CanaryRegistry};
use crate::hostfacts::BootRecord;
use crate::ntpath::{norm_key, DeviceMap};
use crate::proctrack::ProcTracker;
use crate::wfp_plan;
use kestrel_common::wire::OsInfo;
use kestrel_common::*;
use kestrel_platform::{
    ActionOrigin, CanarySpec, Platform, SensorConfig, SensorHandle, TrayHandler,
};
use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub struct WindowsPlatform {
    inner: Arc<Inner>,
}

struct Inner {
    state_dir: PathBuf,
    system_drive: char,
    /// Kestrel's own install + state directories (never quarantined).
    own_dirs: Vec<String>,
    server_ips: Vec<String>,
    boot: BootRecord,
    self_pid: u32,
    tracker: RwLock<Arc<RwLock<ProcTracker>>>,
    enricher: Arc<Enricher>,
    devmap: Arc<RwLock<DeviceMap>>,
    canaries: Arc<RwLock<HashSet<String>>>,
    canary_reg: Mutex<CanaryRegistry>,
    counters: Arc<Counters>,
    wfp: Arc<Wfp>,
    vault: Result<Vault, String>,
    hardener: Hardener,
    last_hardening: Mutex<Option<Hardening>>,
    av: Arc<AvCache>,
    usage: SelfUsage,
    bg_stop: Arc<AtomicBool>,
}

fn resolve(host: &str) -> Vec<IpAddr> {
    format!("{host}:0")
        .to_socket_addrs()
        .map(|it| it.map(|a| a.ip()).collect())
        .unwrap_or_default()
}

/// Resolve `host` with the agent's own stub resolver against the adapters'
/// DNS servers (packets leave from this process, so the isolation DNS permit
/// — agent app id only, H10 — applies). Used while isolated, when the DNS
/// Client service (`getaddrinfo`) is cut off.
pub fn resolve_host_direct(host: &str) -> Vec<IpAddr> {
    let (_, dns) = host::adapters();
    crate::dnswire::resolve_via(host, &dns, Duration::from_secs(2), 16)
}

/// Server-name resolution: while isolated the agent's own queries first
/// (the OS resolver is blocked), otherwise the OS resolver first (hosts
/// file, split DNS, DoH policy) with the direct query as fallback.
fn resolve_server(host: &str, isolated: bool) -> Vec<IpAddr> {
    if isolated {
        let d = resolve_host_direct(host);
        if d.is_empty() {
            resolve(host)
        } else {
            d
        }
    } else {
        let r = resolve(host);
        if r.is_empty() {
            resolve_host_direct(host)
        } else {
            r
        }
    }
}

impl WindowsPlatform {
    /// `state_dir`: agent state (quarantine vault, WFP state, canary registry,
    /// triage output). `server_ips`: Kestrel server addresses (IP, host or
    /// host:port) that must stay reachable — used for isolation allow-lists and
    /// the always-on hard permits for the agent's own traffic.
    pub fn new(state_dir: PathBuf, server_ips: Vec<String>) -> anyhow::Result<WindowsPlatform> {
        // Volume-aware path trust for this process (H1).
        let system_drive = system_root()
            .chars()
            .next()
            .filter(|c| c.is_ascii_alphabetic())
            .unwrap_or('C');
        kestrel_common::set_system_drive(system_drive);
        // H4: owner SYSTEM, protected DACL, no reparse point.
        match super::statedir::secure_state_dir(&state_dir) {
            Ok(r) => {
                if let Some(m) = r.moved_aside {
                    tracing::error!(
                        "untrusted state directory moved to {}; starting with an empty one",
                        m.display()
                    );
                }
            }
            Err(e) => {
                tracing::error!("could not secure {}: {e:#}", state_dir.display());
                std::fs::create_dir_all(&state_dir)?;
            }
        }
        let mut own_dirs = vec![state_dir.to_string_lossy().into_owned()];
        if let Some(d) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        {
            own_dirs.push(d.to_string_lossy().into_owned());
        }
        for p in [
            "SeDebugPrivilege",
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeTakeOwnershipPrivilege",
            "SeSecurityPrivilege",
        ] {
            if !enable_privilege(p) {
                tracing::warn!("{p} could not be enabled (not running as SYSTEM?)");
            }
        }
        let boot = host::boot_record(&state_dir);
        let wfp = Arc::new(Wfp::load(&state_dir));
        let canary_reg: CanaryRegistry = std::fs::read(state_dir.join("canaries.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let canaries: HashSet<String> = canary_reg.planted.keys().cloned().collect();
        let vault =
            Vault::open(&state_dir).map_err(|e| format!("quarantine vault unavailable: {e}"));
        if let Err(e) = &vault {
            tracing::error!("{e}");
        }
        let inner = Arc::new(Inner {
            hardener: Hardener::new(&state_dir),
            state_dir,
            system_drive: system_drive.to_ascii_lowercase(),
            own_dirs,
            server_ips,
            self_pid: std::process::id(),
            tracker: RwLock::new(Arc::new(RwLock::new(ProcTracker::new(&boot.boot_id)))),
            boot,
            enricher: Enricher::new(),
            devmap: Arc::new(RwLock::new(devmap::build())),
            canaries: Arc::new(RwLock::new(canaries)),
            canary_reg: Mutex::new(canary_reg),
            counters: Arc::new(Counters::default()),
            wfp,
            vault,
            last_hardening: Mutex::new(None),
            av: AvCache::new(),
            usage: SelfUsage::new(),
            bg_stop: Arc::new(AtomicBool::new(false)),
        });
        inner.ensure_server_permits();
        if let Some(r) = inner.wfp.repair() {
            tracing::warn!("WFP: {r}");
        }
        let _ = inner.av.get(); // warm the AV cache in the background
        let bg = Arc::downgrade(&inner);
        let stop = inner.bg_stop.clone();
        std::thread::Builder::new()
            .name("kestrel-platform-bg".into())
            .spawn(move || background(bg, stop))?;
        Ok(WindowsPlatform { inner })
    }
}

impl Drop for WindowsPlatform {
    fn drop(&mut self) {
        self.inner.bg_stop.store(true, Ordering::SeqCst);
    }
}

/// TTL expiry, isolation self-repair and re-planning, device-map refresh.
fn background(inner: std::sync::Weak<Inner>, stop: Arc<AtomicBool>) {
    let mut last_devmap = Instant::now();
    let mut last_permits = Instant::now();
    let mut last_replan = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        std::thread::sleep(Duration::from_secs(10));
        let Some(i) = inner.upgrade() else { return };
        for d in i.wfp.expire() {
            tracing::info!("WFP block expired and removed: {d}");
        }
        if let Some(r) = i.wfp.repair() {
            tracing::warn!("WFP: {r}");
        }
        if last_devmap.elapsed() > Duration::from_secs(300) {
            last_devmap = Instant::now();
            if let Ok(mut m) = i.devmap.write() {
                *m = devmap::build();
            }
        }
        if last_permits.elapsed() > Duration::from_secs(600) {
            last_permits = Instant::now();
            i.ensure_server_permits();
        }
        // H10: while isolated, follow server address and DNS server changes
        // (roaming laptop) so the agent can always reach the server.
        if last_replan.elapsed() > Duration::from_secs(60) {
            last_replan = Instant::now();
            if let Some(note) = i.replan_isolation() {
                tracing::warn!("isolation: {note}");
            }
        }
    }
}

impl Inner {
    fn server_addrs(&self) -> (Vec<IpAddr>, Vec<String>) {
        let isolated = self.wfp.isolated.load(Ordering::SeqCst);
        wfp_plan::parse_ips(&self.server_ips, |h| resolve_server(h, isolated))
    }

    fn agent_exe() -> Option<String> {
        std::env::current_exe()
            .ok()
            .map(|p| p.to_string_lossy().into_owned())
            .filter(|s| !s.is_empty())
    }

    /// Re-resolve the server and re-read the adapters' DNS servers; replace
    /// the isolation filters when the plan changed. Never drops a server
    /// address that worked before (failed lookups keep the old ones).
    fn replan_isolation(&self) -> Option<String> {
        let (_, servers, allow_ips, current) = self.wfp.isolation_inputs()?;
        let (fresh, _) = self.server_addrs();
        let (prev, _) = wfp_plan::parse_ips(&servers, |_| vec![]);
        let merged = wfp_plan::merge_server_ips(&fresh, &prev, 16);
        if merged.is_empty() {
            return None;
        }
        let (mut allow, _) = wfp_plan::parse_ips(&allow_ips, |_| vec![]);
        allow.retain(|a| !merged.contains(a));
        let (_, dns) = host::adapters();
        let exe = Self::agent_exe();
        let specs = wfp_plan::plan_isolation(&merged, &allow, &dns, exe.as_deref());
        if !wfp_plan::isolation_plan_changed(&current, &specs) {
            return None;
        }
        let mut desc: Vec<String> = merged.iter().map(|s| format!("server {s}")).collect();
        desc.extend(allow.iter().map(|a| a.to_string()));
        let merged_s: Vec<String> = merged.iter().map(|i| i.to_string()).collect();
        match self.wfp.isolate(specs, desc, merged_s, allow_ips, true) {
            Ok(_) => Some(format!(
                "re-planned for server {:?} and DNS {:?}",
                merged, dns
            )),
            Err(e) => Some(format!("re-plan failed: {e}")),
        }
    }

    fn ensure_server_permits(&self) {
        let (ips, _) = self.server_addrs();
        if ips.is_empty() {
            return;
        }
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        if exe.is_empty() {
            return;
        }
        if let Err(e) = self
            .wfp
            .ensure_server_permits(wfp_plan::plan_server_permits(&ips, &exe))
        {
            tracing::warn!("could not install server hard-permit filters: {e}");
        }
    }

    fn tracker_for(&self, boot_id: &str) -> Arc<RwLock<ProcTracker>> {
        let cur = self
            .tracker
            .read()
            .map(|t| t.clone())
            .expect("tracker lock");
        if cur.read().map(|t| t.boot_id() == boot_id).unwrap_or(true) {
            return cur;
        }
        let fresh = Arc::new(RwLock::new(ProcTracker::new(boot_id)));
        if let Ok(mut w) = self.tracker.write() {
            *w = fresh.clone();
        }
        fresh
    }

    fn guid_expect<'a>(
        &'a self,
        guid: &'a Option<ProcessGuid>,
    ) -> Option<(&'a str, &'a ProcessGuid)> {
        guid.as_ref().map(|g| (self.boot.boot_id.as_str(), g))
    }

    /// Execute; returns (ok, detail, artifact).
    fn execute_blocking(
        &self,
        action: &ResponseAction,
        origin: ActionOrigin,
    ) -> (bool, String, Option<String>) {
        let plain = |(ok, d): (bool, String)| (ok, d, None);
        match action {
            ResponseAction::KillProcess { pid, guid, tree } => plain(respond::kill(
                *pid,
                self.guid_expect(guid),
                *tree,
                self.self_pid,
            )),
            ResponseAction::SuspendProcess { pid, guid } => plain(respond::suspend(
                *pid,
                self.guid_expect(guid),
                self.self_pid,
            )),
            ResponseAction::ResumeProcess { pid, guid } => {
                plain(respond::resume(*pid, self.guid_expect(guid), self.self_pid))
            }
            ResponseAction::QuarantineFile { path, sha256 } => match &self.vault {
                Ok(v) => match v.quarantine(
                    path,
                    sha256.as_deref(),
                    origin,
                    self.system_drive,
                    &self.own_dirs,
                ) {
                    Ok((id, d)) => (true, d, Some(id)),
                    Err(e) => (false, e, None),
                },
                Err(e) => (false, e.clone(), None),
            },
            ResponseAction::RestoreFile { quarantine_id } => match &self.vault {
                Ok(v) => v.restore(quarantine_id, self.system_drive).map_or_else(
                    |e| (false, e, None),
                    |d| (true, d, Some(quarantine_id.clone())),
                ),
                Err(e) => (false, e.clone(), None),
            },
            ResponseAction::DeleteQuarantined { quarantine_id } => match &self.vault {
                Ok(v) => v.delete(quarantine_id).map_or_else(
                    |e| (false, e, None),
                    |d| (true, d, Some(quarantine_id.clone())),
                ),
                Err(e) => (false, e.clone(), None),
            },
            ResponseAction::BlockDestination {
                ip,
                port,
                image,
                ttl_secs,
                ioc_id,
            } => {
                let Ok(addr) = ip.trim().parse::<IpAddr>() else {
                    return (false, format!("not an IP address: {ip}"), None);
                };
                let (servers, _) = self.server_addrs();
                if servers.contains(&addr) {
                    return (
                        false,
                        format!("refusing to block the Kestrel server {addr}"),
                        None,
                    );
                }
                let specs = wfp_plan::plan_block_destination(addr, *port, image.as_deref());
                let what = match (port, image) {
                    (Some(p), Some(i)) => format!("blocked outbound {addr}:{p} for {i}"),
                    (Some(p), None) => format!("blocked outbound {addr}:{p}"),
                    (None, Some(i)) => format!("blocked outbound {addr} for {i}"),
                    (None, None) => format!("blocked outbound {addr}"),
                };
                // Only engine IOC hits tag blocks for M10 reconciliation; an
                // analyst command carrying a tag is treated as untagged so
                // policy changes never lift a manual block.
                let tag = ioc_id
                    .clone()
                    .filter(|t| !t.is_empty() && origin == ActionOrigin::Engine);
                self.wfp
                    .block_tagged(specs, what, *ttl_secs, tag)
                    .map_or_else(|e| (false, e, None), |(id, d)| (true, d, Some(id)))
            }
            ResponseAction::BlockImageNetwork { image, ttl_secs } => {
                if !std::path::Path::new(image).exists() {
                    return (
                        false,
                        format!(
                            "{image} does not exist (WFP app ids are derived from the file path)"
                        ),
                        None,
                    );
                }
                let specs = wfp_plan::plan_block_image(image);
                self.wfp
                    .block(
                        specs,
                        format!("blocked all network traffic for {image}"),
                        *ttl_secs,
                    )
                    .map_or_else(|e| (false, e, None), |(id, d)| (true, d, Some(id)))
            }
            ResponseAction::IsolateHost { allow_ips } => {
                let (servers, bad) = self.server_addrs();
                if servers.is_empty() {
                    return (false, format!("refusing to isolate: no resolvable Kestrel server address (configured: {:?})", self.server_ips), None);
                }
                let (mut allow, bad_allow) = wfp_plan::parse_ips(allow_ips, |_| vec![]);
                // Server addresses are permitted for the agent only (H10);
                // they must not come back as any-process permits.
                allow.retain(|a| !servers.contains(a));
                let (_, dns) = host::adapters();
                let exe = Self::agent_exe();
                let specs = wfp_plan::plan_isolation(&servers, &allow, &dns, exe.as_deref());
                let mut desc: Vec<String> = servers.iter().map(|s| format!("server {s}")).collect();
                desc.extend(allow.iter().map(|a| a.to_string()));
                let servers_s: Vec<String> = servers.iter().map(|i| i.to_string()).collect();
                let allow_s: Vec<String> = allow.iter().map(|i| i.to_string()).collect();
                match self.wfp.isolate(specs, desc, servers_s, allow_s, false) {
                    Ok(mut d) => {
                        if !bad.is_empty() || !bad_allow.is_empty() {
                            d.push_str(&format!(
                                "; ignored unresolvable entries: {:?}",
                                [bad, bad_allow].concat()
                            ));
                        }
                        (true, d, None)
                    }
                    Err(e) => (false, e, None),
                }
            }
            ResponseAction::ReleaseHost => self
                .wfp
                .release()
                .map_or_else(|e| (false, e, None), |d| (true, d, None)),
            ResponseAction::ApplyHardening => {
                let h = self.last_hardening.lock().ok().and_then(|g| g.clone());
                match h {
                    Some(h) => {
                        let m = self.run_hardening(&h);
                        let on: Vec<_> = m
                            .iter()
                            .filter(|(_, v)| **v)
                            .map(|(k, _)| k.as_str())
                            .collect();
                        let off: Vec<_> = m
                            .iter()
                            .filter(|(_, v)| !**v)
                            .map(|(k, _)| k.as_str())
                            .collect();
                        (
                            true,
                            format!(
                                "hardening ({:?}) in effect: [{}]; not in effect: [{}]",
                                h.mode,
                                on.join(", "),
                                off.join(", ")
                            ),
                            None,
                        )
                    }
                    None => (false, "no hardening policy received yet".into(), None),
                }
            }
            ResponseAction::Scan { path } => {
                let targets = match path {
                    Some(p) => scan::expand_targets(p),
                    None => {
                        let mut v: Vec<String> = snapshot::toolhelp_rows()
                            .iter()
                            .filter_map(|r| live_proc(r.pid).and_then(|l| l.image))
                            .filter(|img| PathClass::of(img).is_user_writable())
                            .collect();
                        v.sort();
                        v.dedup();
                        v
                    }
                };
                plain(scan::scan(&self.state_dir, &targets))
            }
            // Backup to the vault first, re-read, then remove (see autorun_resp).
            ResponseAction::RemoveAutorun {
                kind,
                location,
                value_name,
                restore_data,
            } => match &self.vault {
                Ok(v) => autorun_resp::remove_autorun(
                    &autorun_resp::Ctx {
                        vault: v,
                        origin,
                        system_drive: self.system_drive,
                        own_dirs: &self.own_dirs,
                    },
                    *kind,
                    location,
                    value_name.as_deref(),
                    restore_data.as_deref(),
                ),
                Err(e) => (
                    false,
                    format!("{e}; autoruns are never removed without a backup"),
                    None,
                ),
            },
            ResponseAction::CollectTriage => {
                let tracker = self.tracker_for(&self.boot.boot_id);
                let procs = snapshot::snapshot(
                    &self.boot.boot_id,
                    self.boot.boot_time_ms,
                    &self.enricher,
                    &tracker,
                );
                let hostname = host::hostname();
                let extra = serde_json::json!({
                    "hostname": hostname,
                    "os": host::os_info(),
                    "boot_id": self.boot.boot_id,
                    "isolated": self.wfp.isolated.load(Ordering::Relaxed),
                    "logged_on_user": host::logged_on_user(),
                    "ip_addresses": host::adapters().0.iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                    "collected_at": now_ms(),
                });
                match triage::collect(
                    &self.state_dir,
                    &hostname,
                    &procs,
                    &host::user_profiles(),
                    extra,
                ) {
                    Ok(p) => {
                        let p = p.to_string_lossy().into_owned();
                        (true, p.clone(), Some(p))
                    }
                    Err(e) => (false, format!("triage collection failed: {e}"), None),
                }
            }
        }
    }

    fn run_hardening(&self, h: &Hardening) -> BTreeMap<String, bool> {
        let av = self.av.get().or_else(AvCache::query_blocking);
        self.hardener.run(h, &host::user_profiles(), av.as_deref())
    }
}

#[async_trait::async_trait]
impl Platform for WindowsPlatform {
    fn os_info(&self) -> OsInfo {
        host::os_info()
    }

    fn hostname(&self) -> String {
        host::hostname()
    }

    fn boot_id(&self) -> String {
        self.inner.boot.boot_id.clone()
    }

    fn logged_on_user(&self) -> Option<String> {
        host::logged_on_user()
    }

    fn ip_addresses(&self) -> Vec<String> {
        host::adapters().0.iter().map(|i| i.to_string()).collect()
    }

    fn av_product(&self) -> Option<String> {
        self.inner.av.get()
    }

    fn self_usage(&self) -> (f32, u64) {
        self.inner.usage.sample()
    }

    fn state_dir(&self) -> PathBuf {
        self.inner.state_dir.clone()
    }

    fn snapshot_processes(&self, boot_id: &str) -> Vec<ProcessInfo> {
        let i = &self.inner;
        let tracker = i.tracker_for(boot_id);
        snapshot::snapshot(boot_id, i.boot.boot_time_ms, &i.enricher, &tracker)
    }

    fn start_sensors(
        &self,
        cfg: SensorConfig,
        tx: mpsc::Sender<Event>,
    ) -> anyhow::Result<Box<dyn SensorHandle>> {
        let i = &self.inner;
        let tracker = i.tracker_for(&cfg.boot_id);
        // H7: late facts (first-run budget exceeded, revocation) → engine.
        i.enricher.set_sink(cfg.enrich_tx.clone());
        let shared = Arc::new(Shared {
            boot_id: cfg.boot_id.clone(),
            self_pid: cfg.self_pid,
            tracker,
            enricher: i.enricher.clone(),
            devmap: i.devmap.clone(),
            canaries: i.canaries.clone(),
            counters: i.counters.clone(),
            state_dir: i.state_dir.clone(),
        });
        let s = sensors::start(shared, cfg, tx, i.wfp.keys.clone())?;
        Ok(Box::new(s))
    }

    async fn execute(&self, action: &ResponseAction) -> ActionOutcome {
        self.execute_as(action, ActionOrigin::Engine).await
    }

    async fn execute_as(&self, action: &ResponseAction, origin: ActionOrigin) -> ActionOutcome {
        let inner = self.inner.clone();
        let a = action.clone();
        let (ok, detail, artifact) = match tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inner.execute_blocking(&a, origin)
            }))
        })
        .await
        {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => (
                false,
                "internal error while executing action (panic caught)".into(),
                None,
            ),
            Err(e) => (false, format!("action task failed: {e}"), None),
        };
        ActionOutcome {
            action: action.clone(),
            ok,
            detail,
            ts: now_ms(),
            artifact,
        }
    }

    fn system_drive(&self) -> char {
        self.inner.system_drive
    }

    fn isolated_since(&self) -> Option<i64> {
        self.inner.wfp.isolated_since()
    }

    async fn apply_hardening(&self, hardening: &Hardening) -> BTreeMap<String, bool> {
        if let Ok(mut g) = self.inner.last_hardening.lock() {
            *g = Some(hardening.clone());
        }
        let inner = self.inner.clone();
        let h = hardening.clone();
        tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| inner.run_hardening(&h)))
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    fn is_isolated(&self) -> bool {
        self.inner.wfp.isolated.load(Ordering::SeqCst)
    }

    async fn reconcile_ioc_blocks(
        &self,
        block_iocs: &std::collections::BTreeSet<String>,
    ) -> Vec<String> {
        let inner = self.inner.clone();
        let keep = block_iocs.clone();
        tokio::task::spawn_blocking(move || {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                inner.wfp.lift_ioc_blocks(&keep)
            }))
            .unwrap_or_default()
        })
        .await
        .unwrap_or_default()
    }

    fn user_profiles(&self) -> Vec<String> {
        host::user_profiles()
    }

    fn plant_canaries(&self, specs: &[CanarySpec]) -> Vec<String> {
        let i = &self.inner;
        let Ok(mut reg) = i.canary_reg.lock() else {
            return vec![];
        };
        let ok = canary::plant(specs, &mut reg, &|p| set_hidden(p));
        if let Ok(mut c) = i.canaries.write() {
            *c = reg.planted.keys().cloned().collect();
            for p in &ok {
                c.insert(norm_key(p));
            }
        }
        if let Ok(b) = serde_json::to_vec_pretty(&*reg) {
            let _ = write_atomic(&i.state_dir.join("canaries.json"), &b);
        }
        ok
    }

    async fn serve_tray(&self, handler: Arc<dyn TrayHandler>) -> anyhow::Result<()> {
        tray_server::serve(handler).await
    }
}
