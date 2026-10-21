//! `SimPlatform`: a [`Platform`] that replays recorded telemetry instead of
//! reading ETW. Used by `kestrel-agent simulate`, demos and end-to-end tests
//! on any OS.
//!
//! * Events come from a JSONL file of [`kestrel_common::Event`]; `ts` is
//!   rewritten to wall-clock time keeping relative offsets, divided by `speed`.
//! * Response actions are appended to `<state>/sim-actions.jsonl` and succeed.
//! * Isolation and network blocks are in-memory; hardening reports every enabled control applied.
//! * Canary files are written under `<state>/sim-fs/` (Windows paths mapped).
//! * The tray protocol is served on `<state>/tray.sock` (Unix) or a localhost
//!   TCP port written to `<state>/tray.port` (Windows).

use anyhow::{Context, Result};
use kestrel_common::{
    wire::OsInfo, ActionOutcome, Event, EventData, Hardening, HardeningMode, Integrity, PathClass,
    ProcessGuid, ProcessInfo, ResponseAction, SignatureState,
};
use kestrel_platform::{
    BlockSelector, CanarySpec, Platform, SensorConfig, SensorHandle, SensorStats, TrayClient,
    TrayHandler,
};
use sha2::Digest as _;
use std::collections::BTreeMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

pub const TRAY_SOCK: &str = "tray.sock";
pub const TRAY_PORT_FILE: &str = "tray.port";
pub const ACTIONS_LOG: &str = "sim-actions.jsonl";
pub const CANARY_REGISTRY: &str = "sim-canaries.json";
/// Boot id the sample replays were recorded against (their GUIDs derive from it).
pub const SIM_BOOT_ID: &str = "sim-boot-7f3a";
/// Start time used to derive baseline process GUIDs.
pub const BASELINE_START: i64 = 1_760_000_000_000;
pub const SIM_USER: &str = r"CORP\j.doe";

#[derive(Debug, Clone)]
pub struct SimOptions {
    pub state_dir: PathBuf,
    pub replay: Option<PathBuf>,
    pub speed: f64,
    pub hostname: String,
    pub user: String,
}

#[derive(Default)]
struct Shared {
    sink: Mutex<Option<(mpsc::Sender<Event>, SensorConfig)>>,
    sent: AtomicU64,
    lost: AtomicU64,
    done: AtomicBool,
    started: AtomicBool,
}

pub struct SimPlatform {
    opts: SimOptions,
    isolated: AtomicBool,
    isolated_at: Mutex<Option<i64>>,
    shared: Arc<Shared>,
    actions: Mutex<Vec<ActionOutcome>>,
    qid: AtomicU64,
    /// Network blocks in effect (in memory): id, scoped image, description.
    blocks: Mutex<Vec<SimBlock>>,
    /// Quarantine id → original path (restore lifts that image's blocks).
    quarantined: Mutex<BTreeMap<String, String>>,
}

#[derive(Debug, Clone)]
struct SimBlock {
    id: String,
    image: Option<String>,
    description: String,
}

impl SimPlatform {
    pub fn new(opts: SimOptions) -> SimPlatform {
        SimPlatform {
            opts,
            isolated: AtomicBool::new(false),
            isolated_at: Mutex::new(None),
            shared: Arc::default(),
            actions: Mutex::default(),
            qid: AtomicU64::new(0),
            blocks: Mutex::default(),
            quarantined: Mutex::default(),
        }
    }

    /// True once the replay file has been fully delivered.
    pub fn replay_done(&self) -> bool {
        self.shared.done.load(Ordering::Relaxed)
    }

    pub fn events_replayed(&self) -> u64 {
        self.shared.sent.load(Ordering::Relaxed)
    }

    /// Actions executed so far (in order).
    pub fn executed(&self) -> Vec<ActionOutcome> {
        self.actions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Block ids currently in effect (in creation order).
    pub fn active_blocks(&self) -> Vec<String> {
        self.blocks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|b| b.id.clone())
            .collect()
    }

    fn lift(&self, sel: &BlockSelector) -> Vec<String> {
        let mut g = self.blocks.lock().unwrap_or_else(|e| e.into_inner());
        let (lifted, keep): (Vec<SimBlock>, Vec<SimBlock>) = g
            .drain(..)
            .partition(|b| sel.matches(&b.id, b.image.as_deref()));
        *g = keep;
        lifted
            .into_iter()
            .map(|b| format!("{} (block {})", b.description, b.id))
            .collect()
    }

    fn log_action(&self, o: &ActionOutcome) {
        self.actions
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(o.clone());
        let path = self.opts.state_dir.join(ACTIONS_LOG);
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            if let Ok(s) = serde_json::to_string(o) {
                let _ = writeln!(f, "{s}");
            }
        }
    }

    /// Map a Windows path into `<state>/sim-fs/…`.
    pub fn map_path(&self, win_path: &str) -> PathBuf {
        let mut p = self.opts.state_dir.join("sim-fs");
        for part in win_path.split(['\\', '/']).filter(|s| !s.is_empty()) {
            let part = part.replace(':', "");
            if part == ".." || part == "." {
                continue;
            }
            p.push(part);
        }
        p
    }

    fn baseline(&self, boot_id: &str) -> Vec<ProcessInfo> {
        let user = Some(self.opts.user.clone());
        let mk = |pid: u32,
                  ppid: u32,
                  parent: Option<u32>,
                  image: &str,
                  cmd: &str,
                  user: Option<String>,
                  integ: Integrity,
                  signer: &str| {
            ProcessInfo {
                guid: ProcessGuid::derive(boot_id, pid, BASELINE_START),
                pid,
                ppid,
                parent_guid: parent.map(|pp| ProcessGuid::derive(boot_id, pp, BASELINE_START)),
                image: image.into(),
                cmdline: cmd.into(),
                user,
                integrity: Some(integ),
                start_ts: BASELINE_START,
                exit_ts: None,
                signer: Some(signer.into()),
                signed: SignatureState::Valid,
                sha256: None,
                motw_zone: None,
                file_size: None,
                path_class: PathClass::of(image),
            }
        };
        let ms = "Microsoft Windows";
        let sys = Some(r"NT AUTHORITY\SYSTEM".to_string());
        vec![
            mk(4, 0, None, "System", "", sys.clone(), Integrity::System, ms),
            mk(
                612,
                4,
                Some(4),
                r"C:\Windows\System32\smss.exe",
                r"\SystemRoot\System32\smss.exe",
                sys.clone(),
                Integrity::System,
                ms,
            ),
            mk(
                804,
                612,
                None,
                r"C:\Windows\System32\wininit.exe",
                "wininit.exe",
                sys.clone(),
                Integrity::System,
                ms,
            ),
            mk(
                912,
                804,
                Some(804),
                r"C:\Windows\System32\services.exe",
                r"C:\Windows\system32\services.exe",
                sys.clone(),
                Integrity::System,
                ms,
            ),
            mk(
                928,
                804,
                Some(804),
                r"C:\Windows\System32\lsass.exe",
                r"C:\Windows\system32\lsass.exe",
                sys.clone(),
                Integrity::System,
                ms,
            ),
            mk(
                1184,
                912,
                Some(912),
                r"C:\Windows\System32\svchost.exe",
                r"C:\Windows\system32\svchost.exe -k DcomLaunch -p",
                sys.clone(),
                Integrity::System,
                ms,
            ),
            mk(
                2216,
                912,
                Some(912),
                r"C:\Windows\System32\svchost.exe",
                r"C:\Windows\system32\svchost.exe -k NetworkService -p -s Dnscache",
                Some(r"NT AUTHORITY\NETWORK SERVICE".into()),
                Integrity::System,
                ms,
            ),
            mk(
                5124,
                5060,
                None,
                r"C:\Windows\explorer.exe",
                r"C:\Windows\Explorer.EXE",
                user.clone(),
                Integrity::Medium,
                ms,
            ),
            mk(
                6320,
                5124,
                Some(5124),
                r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                r#""C:\Program Files\Google\Chrome\Application\chrome.exe""#,
                user.clone(),
                Integrity::Medium,
                "Google LLC",
            ),
            mk(
                7408,
                5124,
                Some(5124),
                r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
                r#""C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE""#,
                user,
                Integrity::Medium,
                "Microsoft Corporation",
            ),
        ]
    }

    fn start_replay(&self) {
        if self.shared.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(path) = self.opts.replay.clone() else {
            self.shared.done.store(true, Ordering::Relaxed);
            return;
        };
        let shared = self.shared.clone();
        let speed = if self.opts.speed > 0.0 {
            self.opts.speed
        } else {
            1.0
        };
        let r = std::thread::Builder::new()
            .name("sim-replay".into())
            .spawn(move || {
                if let Err(e) = replay(&path, speed, &shared) {
                    tracing::error!("replay of {} failed: {e:#}", path.display());
                }
                shared.done.store(true, Ordering::Relaxed);
                tracing::info!(
                    events = shared.sent.load(Ordering::Relaxed),
                    "replay finished"
                );
            });
        if r.is_err() {
            self.shared.done.store(true, Ordering::Relaxed);
        }
    }
}

/// Parse a replay file (skips blank lines and `#`/`//` comments).
pub fn load_replay(path: &Path) -> Result<Vec<Event>> {
    let f =
        std::fs::File::open(path).with_context(|| format!("opening replay {}", path.display()))?;
    let mut out = vec![];
    for (i, line) in std::io::BufReader::new(f).lines().enumerate() {
        let line = line?;
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') || t.starts_with("//") {
            continue;
        }
        let e: Event = serde_json::from_str(t)
            .with_context(|| format!("{}:{}: invalid event", path.display(), i + 1))?;
        out.push(e);
    }
    Ok(out)
}

fn replay(path: &Path, speed: f64, shared: &Shared) -> Result<()> {
    let mut events = load_replay(path)?;
    events.sort_by_key(|e| e.ts);
    let Some(t0) = events.first().map(|e| e.ts) else {
        return Ok(());
    };
    let wall0 = kestrel_common::now_ms();
    let start = Instant::now();
    tracing::info!(events = events.len(), speed, file = %path.display(), "replay started");
    for mut e in events {
        let offset_ms = ((e.ts - t0) as f64 / speed) as u64;
        let due = Duration::from_millis(offset_ms);
        let el = start.elapsed();
        if due > el {
            std::thread::sleep(due - el);
        }
        e.ts = wall0 + offset_ms as i64;
        let sink = shared
            .sink
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let Some((tx, cfg)) = sink else {
            shared.lost.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        if e.pid == cfg.self_pid
            || (!cfg.dns && matches!(e.data, EventData::DnsQuery { .. }))
            || (!cfg.script_content && matches!(e.data, EventData::ScriptBlock { .. }))
        {
            continue;
        }
        match tx.try_send(e) {
            Ok(()) => {
                shared.sent.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                shared.lost.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    Ok(())
}

struct SimSensors {
    shared: Arc<Shared>,
}

impl SensorHandle for SimSensors {
    fn stats(&self) -> SensorStats {
        SensorStats {
            etw_ok: true,
            events_lost: self.shared.lost.load(Ordering::Relaxed),
            buffers_lost: 0,
            events_total: self.shared.sent.load(Ordering::Relaxed),
            sysmon_present: false,
            dpapi_channel_enabled: true,
            amsi_ok: true,
        }
    }
    fn stop(&self) {
        *self.shared.sink.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

#[async_trait::async_trait]
impl Platform for SimPlatform {
    fn os_info(&self) -> OsInfo {
        OsInfo {
            name: "Windows 11 Pro (simulated)".into(),
            build: "10.0.26100.4652".into(),
            arch: "x86_64".into(),
            domain: Some("CORP".into()),
            hw_uuid: Some(format!("SIM-{}", self.opts.hostname)),
        }
    }
    fn hostname(&self) -> String {
        self.opts.hostname.clone()
    }
    fn boot_id(&self) -> String {
        SIM_BOOT_ID.into()
    }
    fn logged_on_user(&self) -> Option<String> {
        Some(self.opts.user.clone())
    }
    fn ip_addresses(&self) -> Vec<String> {
        vec!["192.0.2.10".into()]
    }
    fn av_product(&self) -> Option<String> {
        Some("Microsoft Defender Antivirus".into())
    }
    fn self_usage(&self) -> (f32, u64) {
        (0.0, rss_mb())
    }
    fn state_dir(&self) -> PathBuf {
        self.opts.state_dir.clone()
    }
    fn snapshot_processes(&self, boot_id: &str) -> Vec<ProcessInfo> {
        self.baseline(boot_id)
    }
    fn start_sensors(
        &self,
        cfg: SensorConfig,
        tx: mpsc::Sender<Event>,
    ) -> Result<Box<dyn SensorHandle>> {
        *self.shared.sink.lock().unwrap_or_else(|p| p.into_inner()) = Some((tx, cfg));
        self.start_replay();
        Ok(Box::new(SimSensors {
            shared: self.shared.clone(),
        }))
    }

    async fn execute(&self, action: &ResponseAction) -> ActionOutcome {
        let mut artifact = None;
        let detail = match action {
            ResponseAction::IsolateHost { allow_ips } => {
                self.isolated.store(true, Ordering::Relaxed);
                *self.isolated_at.lock().unwrap_or_else(|e| e.into_inner()) =
                    Some(kestrel_common::now_ms());
                format!(
                    "simulated: host isolated (allowed: {})",
                    allow_ips.join(", ")
                )
            }
            ResponseAction::ReleaseHost => {
                self.isolated.store(false, Ordering::Relaxed);
                *self.isolated_at.lock().unwrap_or_else(|e| e.into_inner()) = None;
                "simulated: host released".into()
            }
            ResponseAction::QuarantineFile { path, .. } => {
                let id = self.qid.fetch_add(1, Ordering::Relaxed) + 1;
                artifact = Some(format!("q-{id:04}"));
                self.quarantined
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(format!("q-{id:04}"), path.clone());
                format!("simulated: quarantined {path} as q-{id:04}")
            }
            ResponseAction::RestoreFile { quarantine_id } => {
                let path = self
                    .quarantined
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(quarantine_id);
                let mut d = format!("simulated: restored {quarantine_id}");
                if let Some(p) = path {
                    let lifted = self.lift(&BlockSelector::new(Some(&p), None));
                    if !lifted.is_empty() {
                        d.push_str(&format!(
                            "; lifted {} network block(s) for {p}",
                            lifted.len()
                        ));
                    }
                }
                d
            }
            ResponseAction::BlockDestination { .. } | ResponseAction::BlockImageNetwork { .. } => {
                let id = self.qid.fetch_add(1, Ordering::Relaxed) + 1;
                let image = match action {
                    ResponseAction::BlockDestination { image, .. } => image.clone(),
                    ResponseAction::BlockImageNetwork { image, .. } => Some(image.clone()),
                    _ => None,
                };
                let description = format!("simulated: {}", action.name());
                self.blocks
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(SimBlock {
                        id: format!("blk-{id:04}"),
                        image,
                        description: description.clone(),
                    });
                artifact = Some(format!("blk-{id:04}"));
                format!("{description} (block blk-{id:04})")
            }
            ResponseAction::UnblockNetwork { .. } => {
                let sel = BlockSelector::from_action(action).unwrap_or_default();
                sel.outcome_detail(&self.lift(&sel))
            }
            ResponseAction::CollectTriage => {
                let p = self.opts.state_dir.join("triage").join("sim-triage.zip");
                artifact = Some(p.display().to_string());
                format!("simulated: triage collected to {}", p.display())
            }
            ResponseAction::Scan { path } => {
                format!(
                    "simulated scan of {}: 0 findings",
                    path.as_deref().unwrap_or("running processes")
                )
            }
            other => format!("simulated: {}", other.name()),
        };
        let o = ActionOutcome {
            action: action.clone(),
            ok: true,
            detail,
            ts: kestrel_common::now_ms(),
            artifact,
        };
        tracing::info!(action = action.name(), "{}", o.detail);
        self.log_action(&o);
        o
    }

    async fn apply_hardening(&self, h: &Hardening) -> BTreeMap<String, bool> {
        let mut m = BTreeMap::new();
        if h.mode == HardeningMode::Off {
            return m;
        }
        for (k, on) in [
            ("block_mshta", h.block_mshta),
            ("block_user_path_exec", h.block_user_path_exec),
            ("disable_run_dialog", h.disable_run_dialog),
            ("terminal_paste_warning", h.terminal_paste_warning),
            ("script_block_logging", h.script_block_logging),
            ("dpapi_debug_channel", h.dpapi_debug_channel),
            ("asr_rules", h.asr_rules),
            (
                "browser_disable_remote_debugging",
                h.browser_disable_remote_debugging,
            ),
        ] {
            if on {
                m.insert(k.to_string(), true);
            }
        }
        m
    }

    fn is_isolated(&self) -> bool {
        self.isolated.load(Ordering::Relaxed)
    }

    async fn lift_network_blocks(&self, sel: &BlockSelector) -> Result<Vec<String>, String> {
        Ok(self.lift(sel))
    }

    fn isolated_since(&self) -> Option<i64> {
        *self.isolated_at.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn user_profiles(&self) -> Vec<String> {
        let name = self.opts.user.rsplit('\\').next().unwrap_or("user");
        vec![format!(r"C:\Users\{name}")]
    }

    /// Same contract as kestrel-win: never overwrite a file Kestrel didn't
    /// plant; return only paths that now hold Kestrel decoys.
    fn plant_canaries(&self, specs: &[CanarySpec]) -> Vec<String> {
        let reg_path = self.opts.state_dir.join(CANARY_REGISTRY);
        let mut reg: BTreeMap<String, String> = std::fs::read(&reg_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let mut ok = vec![];
        for s in specs {
            let p = self.map_path(&s.path);
            let key = s.path.to_ascii_lowercase();
            let digest = if s.is_dir {
                "dir".to_string()
            } else {
                hex::encode(sha2::Sha256::digest(&s.content))
            };
            if p.exists() {
                let ours = match reg.get(&key) {
                    Some(d) if s.is_dir => d == "dir",
                    Some(d) => std::fs::read(&p)
                        .map(|b| hex::encode(sha2::Sha256::digest(&b)) == *d)
                        .unwrap_or(false),
                    None => false,
                };
                if !ours {
                    tracing::debug!(path = %s.path, "not planting canary over an existing file");
                    continue;
                }
            }
            let r = if s.is_dir {
                std::fs::create_dir_all(&p)
            } else {
                p.parent()
                    .map(std::fs::create_dir_all)
                    .unwrap_or(Ok(()))
                    .and_then(|_| std::fs::write(&p, &s.content))
            };
            match r {
                Ok(()) => {
                    reg.insert(key, digest);
                    ok.push(s.path.clone());
                }
                Err(e) => tracing::warn!(path = %s.path, "canary write failed: {e}"),
            }
        }
        if let Ok(b) = serde_json::to_vec(&reg) {
            let _ = std::fs::write(&reg_path, b);
        }
        ok
    }

    async fn serve_tray(&self, handler: Arc<dyn TrayHandler>) -> Result<()> {
        #[cfg(unix)]
        {
            let path = self.opts.state_dir.join(TRAY_SOCK);
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)
                .with_context(|| format!("binding {}", path.display()))?;
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
            }
            tracing::info!(socket = %path.display(), "tray endpoint listening");
            loop {
                let (s, _) = listener.accept().await?;
                // The socket is 0660 in the agent's state dir: the simulated
                // host has one interactive user.
                tokio::spawn(crate::tray::serve_connection(
                    s,
                    handler.clone(),
                    self.sim_client(),
                ));
            }
        }
        #[cfg(not(unix))]
        {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
            let port = listener.local_addr()?.port();
            std::fs::write(self.opts.state_dir.join(TRAY_PORT_FILE), port.to_string())?;
            tracing::info!(port, "tray endpoint listening on localhost");
            loop {
                let (s, _) = listener.accept().await?;
                tokio::spawn(crate::tray::serve_connection(
                    s,
                    handler.clone(),
                    self.sim_client(),
                ));
            }
        }
    }
}

impl SimPlatform {
    /// Tray client identity for the simulated single-user host.
    pub fn sim_client(&self) -> TrayClient {
        TrayClient {
            user_sid: None,
            user: Some(self.opts.user.clone()),
            session_id: Some(1),
            pid: None,
        }
    }
}

fn rss_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for l in s.lines() {
                if let Some(v) = l.strip_prefix("VmRSS:") {
                    return v
                        .trim()
                        .trim_end_matches("kB")
                        .trim()
                        .parse::<u64>()
                        .unwrap_or(0)
                        / 1024;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replay_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("replays")
    }

    #[test]
    fn sample_replays_parse() {
        for f in [
            "lumma_clickfix.jsonl",
            "vidar_smash_grab.jsonl",
            "benign_workday.jsonl",
        ] {
            let ev = load_replay(&replay_dir().join(f)).unwrap();
            assert!(ev.len() >= 10, "{f} too short");
            assert!(
                ev.windows(2).all(|w| w[0].ts <= w[1].ts),
                "{f} not time-ordered"
            );
        }
    }

    #[test]
    fn replay_parents_resolve() {
        // Every ProcessStart's parent is either baseline or started earlier in the file.
        let dir = tempfile::tempdir().unwrap();
        let sim = SimPlatform::new(SimOptions {
            state_dir: dir.path().into(),
            replay: None,
            speed: 1.0,
            hostname: "H".into(),
            user: SIM_USER.into(),
        });
        let mut known: std::collections::HashSet<ProcessGuid> = sim
            .snapshot_processes(SIM_BOOT_ID)
            .into_iter()
            .map(|p| p.guid)
            .collect();
        for f in [
            "lumma_clickfix.jsonl",
            "vidar_smash_grab.jsonl",
            "benign_workday.jsonl",
        ] {
            for e in load_replay(&replay_dir().join(f)).unwrap() {
                if let EventData::ProcessStart(ps) = &e.data {
                    if let Some(pg) = &ps.parent_guid {
                        assert!(known.contains(pg), "{f}: unknown parent of pid {}", e.pid);
                    }
                    known.insert(e.guid.clone());
                } else {
                    assert!(
                        known.contains(&e.guid),
                        "{f}: event from unknown process pid {} ({:?})",
                        e.pid,
                        e.kind()
                    );
                }
            }
        }
    }

    #[tokio::test]
    async fn actions_and_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let sim = SimPlatform::new(SimOptions {
            state_dir: dir.path().into(),
            replay: None,
            speed: 1.0,
            hostname: "H".into(),
            user: SIM_USER.into(),
        });
        assert!(!sim.is_isolated());
        assert!(
            sim.execute(&ResponseAction::IsolateHost { allow_ips: vec![] })
                .await
                .ok
        );
        assert!(sim.is_isolated());
        sim.execute(&ResponseAction::ReleaseHost).await;
        assert!(!sim.is_isolated());
        let log = std::fs::read_to_string(dir.path().join(ACTIONS_LOG)).unwrap();
        assert_eq!(log.lines().count(), 2);
        let planted = sim.plant_canaries(&[CanarySpec {
            path: r"C:\Users\j.doe\AppData\Local\Google\Chrome\User Data\Profile 9\Login Data"
                .into(),
            category: kestrel_common::DataCategory::BrowserPasswords,
            content: b"decoy".to_vec(),
            is_dir: false,
        }]);
        assert_eq!(planted.len(), 1);
        // Re-planting our own decoy is fine; a real file is never overwritten.
        let real = sim.map_path(r"C:\Users\j.doe\.aws\credentials");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, b"[default]\naws_access_key_id=REAL").unwrap();
        let specs = vec![
            CanarySpec {
                path: r"C:\Users\j.doe\AppData\Local\Google\Chrome\User Data\Profile 9\Login Data"
                    .into(),
                category: kestrel_common::DataCategory::BrowserPasswords,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: r"C:\Users\j.doe\.aws\credentials".into(),
                category: kestrel_common::DataCategory::CloudToken,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
        ];
        assert_eq!(sim.plant_canaries(&specs), vec![specs[0].path.clone()]);
        assert_eq!(
            std::fs::read(&real).unwrap(),
            b"[default]\naws_access_key_id=REAL"
        );
        assert!(dir
            .path()
            .join("sim-fs/C/Users/j.doe/AppData/Local/Google/Chrome/User Data/Profile 9/Login Data")
            .is_file());
        assert_eq!(
            sim.map_path(r"C:\..\..\etc\passwd"),
            dir.path().join("sim-fs/C/etc/passwd")
        );
    }
}

#[cfg(test)]
mod unblock_tests {
    use super::*;

    fn sim(dir: &Path) -> SimPlatform {
        SimPlatform::new(SimOptions {
            state_dir: dir.into(),
            replay: None,
            speed: 1.0,
            hostname: "H".into(),
            user: SIM_USER.into(),
        })
    }

    #[tokio::test]
    async fn unblock_network_lifts_matching_blocks_only() {
        let dir = tempfile::tempdir().unwrap();
        let sim = sim(dir.path());
        let crm = r"C:\Apps\CRM.exe";
        let img = |i: &str| ResponseAction::BlockImageNetwork {
            image: i.into(),
            ttl_secs: None,
        };
        let b1 = sim.execute(&img(crm)).await.artifact.unwrap();
        let b2 = sim
            .execute(&ResponseAction::BlockDestination {
                ip: "203.0.113.7".into(),
                port: None,
                image: Some(r"c:\apps\crm.exe".into()),
                ttl_secs: None,
                ioc_id: None,
            })
            .await
            .artifact
            .unwrap();
        let b3 = sim
            .execute(&img(r"C:\Users\a\Downloads\evil.exe"))
            .await
            .artifact
            .unwrap();
        sim.execute(&ResponseAction::IsolateHost { allow_ips: vec![] })
            .await;
        assert_eq!(sim.active_blocks(), [b1, b2, b3.clone()]);

        // By image (case-insensitive): both CRM blocks, not evil.exe.
        let o = sim
            .execute(&ResponseAction::UnblockNetwork {
                image: Some("C:/apps/crm.EXE".into()),
                block_id: None,
            })
            .await;
        assert!(o.ok);
        assert!(
            o.detail.starts_with("lifted 2 network block(s)"),
            "{}",
            o.detail
        );
        assert_eq!(sim.active_blocks(), [b3]);

        // Nothing left to match: still success.
        let o = sim
            .lift_network_blocks(&BlockSelector::new(Some(crm), None))
            .await
            .unwrap();
        assert!(o.is_empty());
        let o = sim
            .execute(&ResponseAction::UnblockNetwork {
                image: None,
                block_id: Some("blk-nope".into()),
            })
            .await;
        assert!(o.ok);
        assert!(o.detail.starts_with("no matching block"), "{}", o.detail);

        // Everything: blocks gone, isolation untouched.
        let o = sim
            .execute(&ResponseAction::UnblockNetwork {
                image: None,
                block_id: None,
            })
            .await;
        assert!(o.detail.starts_with("lifted 1 network block(s)"));
        assert!(sim.active_blocks().is_empty());
        assert!(sim.is_isolated());
    }

    #[tokio::test]
    async fn restore_lifts_image_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let sim = sim(dir.path());
        let p = r"C:\Users\a\Downloads\tool.exe";
        sim.execute(&ResponseAction::BlockImageNetwork {
            image: p.into(),
            ttl_secs: None,
        })
        .await;
        let other = sim
            .execute(&ResponseAction::BlockImageNetwork {
                image: r"C:\x.exe".into(),
                ttl_secs: None,
            })
            .await
            .artifact
            .unwrap();
        let q = sim
            .execute(&ResponseAction::QuarantineFile {
                path: p.into(),
                sha256: None,
            })
            .await
            .artifact
            .unwrap();
        let o = sim
            .execute(&ResponseAction::RestoreFile { quarantine_id: q })
            .await;
        assert!(
            o.detail.contains("lifted 1 network block(s)"),
            "{}",
            o.detail
        );
        assert_eq!(sim.active_blocks(), [other]);
    }
}
