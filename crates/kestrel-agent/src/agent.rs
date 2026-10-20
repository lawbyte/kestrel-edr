//! Agent core: owns state, wires the platform, engine, outbox, transport and tray.

use anyhow::{Context, Result};
use kestrel_common::{
    tray::{ActivityItem, TrayResponse},
    wire::{AgentHealth, AgentPayload, Heartbeat, Inventory, Software},
    ActionOutcome, Event, Policy, ResponseAction, RuleBundle, Severity,
};
use kestrel_detect::HostContext;
use kestrel_platform::{
    ActionOrigin, Audience, LateEnrichment, Platform, SensorConfig, SensorHandle, TrayPush,
};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::sync::{broadcast, mpsc, Notify};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::config::AgentConfig;
use crate::detection::{self, EngineCtl};
use crate::privacy::PrivacyFilter;
use crate::store::{self, Store};

/// Timing knobs (defaults are production values; tests shrink them).
#[derive(Debug, Clone)]
pub struct Tuning {
    pub heartbeat: Duration,
    pub batch_max_events: usize,
    pub batch_max_delay: Duration,
    pub tick: Duration,
    pub inventory_every: Duration,
    pub event_channel: usize,
    pub housekeeping: Duration,
    pub hardening_recheck: Duration,
    pub action_timeout: Duration,
}

impl Default for Tuning {
    fn default() -> Self {
        Tuning {
            heartbeat: Duration::from_secs(30),
            batch_max_events: 500,
            batch_max_delay: Duration::from_secs(2),
            tick: Duration::from_millis(250),
            inventory_every: Duration::from_secs(24 * 3600),
            event_channel: 65_536,
            housekeeping: Duration::from_secs(60),
            hardening_recheck: Duration::from_secs(15 * 60),
            action_timeout: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    pub events_seen: AtomicU64,
    pub events_per_min: AtomicU64,
    pub alerts: AtomicU64,
    pub actions: AtomicU64,
    pub engine_panics: AtomicU64,
}

/// Shared agent state.
pub struct Core {
    pub state_dir: PathBuf,
    pub cfg: RwLock<AgentConfig>,
    pub store: Arc<Store>,
    pub platform: Arc<dyn Platform>,
    pub tuning: Tuning,
    pub boot_id: String,
    pub hostname: String,
    pub started: Instant,
    pub stats: Stats,
    pub shutdown: CancellationToken,
    /// Policy in force; `None` until the server sends one (built-in defaults apply).
    policy: RwLock<Option<Policy>>,
    rules_version: AtomicU64,
    filter: RwLock<Arc<PrivacyFilter>>,
    connected: AtomicBool,
    pub(crate) outbox_notify: Notify,
    tray_tx: broadcast::Sender<TrayPush>,
    hardening: RwLock<BTreeMap<String, bool>>,
    sensors: Mutex<Option<Box<dyn SensorHandle>>>,
    sensor_cfg: Mutex<Option<SensorConfig>>,
    event_tx: mpsc::Sender<Event>,
    enrich_tx: mpsc::Sender<LateEnrichment>,
    pub(crate) engine_ctl: mpsc::UnboundedSender<EngineCtl>,
    server_ips: RwLock<Vec<String>>,
    inflight_cmds: Mutex<HashSet<Uuid>>,
    salt: String,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}
fn read<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|e| e.into_inner())
}
fn write<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|e| e.into_inner())
}

impl Core {
    // ------------------------------------------------------------- accessors

    pub fn config(&self) -> AgentConfig {
        read(&self.cfg).clone()
    }

    /// Replace the uninstall token (server rotation, `ServerPayload::SetUninstallToken`).
    /// Only the Argon2id hash is stored; `agent.toml` is rewritten atomically
    /// (temp file, flushed, renamed over) under the config lock, so a crash
    /// leaves either the old or the new hash, never a torn file. Returns only
    /// once the new hash is on disk (the caller acks after that).
    pub fn set_uninstall_token(&self, token: &str) -> Result<()> {
        let token = token.trim();
        if token.is_empty() || token.len() > 512 || token.chars().any(char::is_control) {
            anyhow::bail!("server sent an invalid uninstall token");
        }
        let hash = crate::config::hash_secret(token)?;
        let mut guard = write(&self.cfg);
        // Start from the file (another writer may have changed it), else memory.
        let mut cfg = AgentConfig::load(&self.state_dir).unwrap_or_else(|_| guard.clone());
        cfg.uninstall_token_hash = Some(hash);
        cfg.save(&self.state_dir)
            .context("saving the new uninstall token")?;
        *guard = cfg;
        Ok(())
    }

    pub fn policy(&self) -> Policy {
        read(&self.policy).clone().unwrap_or_default()
    }

    /// Version of the server-provided policy in force (0 = none yet).
    pub fn policy_version(&self) -> u64 {
        read(&self.policy).as_ref().map(|p| p.version).unwrap_or(0)
    }

    pub fn rules_version(&self) -> u64 {
        self.rules_version.load(Ordering::Relaxed)
    }

    pub fn filter(&self) -> Arc<PrivacyFilter> {
        read(&self.filter).clone()
    }

    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub(crate) fn set_connected(&self, v: bool) {
        self.connected.store(v, Ordering::Relaxed);
    }

    pub fn server_ips(&self) -> Vec<String> {
        read(&self.server_ips).clone()
    }

    /// Sensor health without the cost of a full [`AgentHealth`].
    pub fn health_snapshot_etw_ok(&self) -> bool {
        lock(&self.sensors)
            .as_ref()
            .map(|s| s.stats().etw_ok)
            .unwrap_or(false)
    }

    pub fn hardening_state(&self) -> BTreeMap<String, bool> {
        read(&self.hardening).clone()
    }

    pub fn subscribe_tray(&self) -> broadcast::Receiver<TrayPush> {
        self.tray_tx.subscribe()
    }

    // --------------------------------------------------------------- outbox

    /// Durably queue a payload for upload and wake the sender.
    pub fn enqueue(&self, p: &AgentPayload) {
        match self.store.enqueue(p) {
            Ok(seq) => tracing::trace!(seq, kind = store::payload_kind(p), "queued"),
            Err(e) => tracing::error!("outbox write failed ({}): {e:#}", store::payload_kind(p)),
        }
        self.outbox_notify.notify_one();
    }

    pub fn outbox_depth(&self) -> u64 {
        self.store.depth().unwrap_or(0)
    }

    // ----------------------------------------------------------------- tray

    /// Persist an activity item and push it to subscribed tray apps.
    /// `owner` (lower-case user SID or `domain\\user`) limits who sees it;
    /// `None` = machine-wide.
    pub fn notify_tray(&self, item: ActivityItem, push: bool, owner: Option<String>) {
        let owner = owner
            .map(|o| o.trim().to_ascii_lowercase())
            .filter(|o| !o.is_empty());
        if let Err(e) = self.store.add_activity(&item, owner.as_deref()) {
            tracing::warn!("activity log write failed: {e:#}");
        }
        if push {
            let _ = self.tray_tx.send(TrayPush {
                audience: match owner {
                    Some(o) => Audience::Owner(o),
                    None => Audience::Public,
                },
                resp: TrayResponse::Notification(item),
            });
        }
    }

    // ------------------------------------------------------------- actions

    /// Execute an engine-originated response action with agent-side guards.
    pub async fn execute_action(&self, action: &ResponseAction) -> ActionOutcome {
        self.execute_action_as(action, ActionOrigin::Engine).await
    }

    /// Execute a response action on behalf of `origin` with agent-side guards.
    pub async fn execute_action_as(
        &self,
        action: &ResponseAction,
        origin: ActionOrigin,
    ) -> ActionOutcome {
        let now = kestrel_common::now_ms();
        let action = match action {
            // Never cut ourselves off from the server.
            ResponseAction::IsolateHost { allow_ips } => {
                let mut ips = allow_ips.clone();
                for ip in self.server_ips() {
                    if !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
                ResponseAction::IsolateHost { allow_ips: ips }
            }
            ResponseAction::KillProcess { pid, .. }
            | ResponseAction::SuspendProcess { pid, .. }
                if *pid == std::process::id() =>
            {
                return ActionOutcome {
                    action: action.clone(),
                    ok: false,
                    detail: "refused: target is the Kestrel agent".into(),
                    ts: now,
                    artifact: None,
                };
            }
            // Platform::execute has no access to policy; the agent applies the pack.
            ResponseAction::ApplyHardening => {
                let map = self.apply_hardening().await;
                let failed: Vec<_> = map
                    .iter()
                    .filter(|(_, v)| !**v)
                    .map(|(k, _)| k.as_str())
                    .collect();
                let mode = self.policy().hardening.mode;
                return ActionOutcome {
                    action: action.clone(),
                    ok: failed.is_empty() || mode != kestrel_common::HardeningMode::Enforce,
                    detail: if failed.is_empty() {
                        format!("{} controls in effect", map.len())
                    } else {
                        format!("not in effect: {}", failed.join(", "))
                    },
                    ts: kestrel_common::now_ms(),
                    artifact: None,
                };
            }
            other => other.clone(),
        };
        self.stats.actions.fetch_add(1, Ordering::Relaxed);
        match tokio::time::timeout(
            self.tuning.action_timeout,
            self.platform.execute_as(&action, origin),
        )
        .await
        {
            Ok(o) => o,
            Err(_) => ActionOutcome {
                action,
                ok: false,
                detail: format!("timed out after {:?}", self.tuning.action_timeout),
                ts: kestrel_common::now_ms(),
                artifact: None,
            },
        }
    }

    /// Run a server command once per `command_id` and queue its result.
    pub async fn run_command(self: &Arc<Self>, command_id: Uuid, action: ResponseAction) {
        if let Ok(Some(prev)) = self.store.command_outcome(command_id) {
            tracing::info!(%command_id, "duplicate command; re-sending stored result");
            self.enqueue(&AgentPayload::ActionResult {
                command_id,
                outcome: prev,
            });
            return;
        }
        if !lock(&self.inflight_cmds).insert(command_id) {
            tracing::info!(%command_id, "command already running");
            return;
        }
        tracing::info!(%command_id, action = action.name(), "executing server command");
        let outcome = self
            .execute_action_as(&action, ActionOrigin::ServerCommand)
            .await;
        if let Err(e) = self.store.record_command(command_id, &outcome) {
            tracing::warn!("command ledger write failed: {e:#}");
        }
        lock(&self.inflight_cmds).remove(&command_id);
        if let Some(item) = detection::command_activity(&action, &outcome) {
            self.notify_tray(item, true, None);
        }
        self.enqueue(&AgentPayload::ActionResult {
            command_id,
            outcome,
        });
    }

    pub async fn apply_hardening(&self) -> BTreeMap<String, bool> {
        let h = self.policy().hardening;
        let map = self.platform.apply_hardening(&h).await;
        *write(&self.hardening) = map.clone();
        map
    }

    // -------------------------------------------------------------- policy

    /// Apply a server policy if newer. Returns true if applied.
    pub fn apply_policy(self: &Arc<Self>, p: Policy) -> bool {
        let _ = self.store.kv_set(
            store::KV_LAST_POLICY_SYNC,
            &kestrel_common::now_ms().to_string(),
        );
        let cur = self.policy_version();
        if cur != 0 && p.version <= cur {
            tracing::debug!(have = cur, got = p.version, "policy not newer; ignored");
            return false;
        }
        tracing::info!(id = %p.id, name = %p.name, version = p.version, "applying policy");
        if let Err(e) = self.store.kv_set_json(store::KV_POLICY, &p) {
            tracing::warn!("persisting policy failed: {e:#}");
        }
        // M10: a server-delivered policy is authoritative for IOCs. Lift the
        // WFP blocks earlier IOC hits created for indicators that are no
        // longer Block IOCs (deleted, demoted to Audit/Allow, or out of scope
        // after a group move). Blocks from other rules / analysts are untagged
        // and never touched.
        let keep = block_ioc_ids(&p);
        let me = self.clone();
        tokio::spawn(async move {
            for d in me.platform.reconcile_ioc_blocks(&keep).await {
                tracing::info!("IOC no longer blocked by policy; lifted: {d}");
            }
        });
        self.install_policy(p);
        true
    }

    fn install_policy(self: &Arc<Self>, p: Policy) {
        let old = read(&self.policy).clone();
        *write(&self.filter) = Arc::new(PrivacyFilter::new(&p.privacy, &p.telemetry, &self.salt));
        *write(&self.policy) = Some(p.clone());
        let _ = self.engine_ctl.send(EngineCtl::Policy(Box::new(p.clone())));
        // Hardening (async: may touch registry / AppLocker).
        let me = self.clone();
        tokio::spawn(async move {
            let map = me.apply_hardening().await;
            tracing::info!(
                controls = map.len(),
                in_effect = map.values().filter(|v| **v).count(),
                "hardening evaluated"
            );
        });
        // Sensors: restart only if their config changed.
        let sensors_changed = match &old {
            Some(o) => {
                o.privacy.capture_dns != p.privacy.capture_dns
                    || o.privacy.capture_script_content != p.privacy.capture_script_content
                    // Optional sensor groups (file activity, persistence, …).
                    || o.sensors != p.sensors
            }
            None => true,
        };
        if sensors_changed && lock(&self.sensors).is_some() {
            self.restart_sensors();
        }
        self.enforce_cap();
    }

    pub async fn apply_rules(&self, bundle: RuleBundle) -> bool {
        if bundle.version <= self.rules_version() && self.rules_version() != 0 {
            return false;
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let v = bundle.version;
        if self
            .engine_ctl
            .send(EngineCtl::Rules(bundle.clone(), tx))
            .is_err()
        {
            return false;
        }
        match tokio::time::timeout(Duration::from_secs(30), rx).await {
            Ok(Ok(Ok(()))) => {
                self.rules_version.store(v, Ordering::Relaxed);
                if let Err(e) = self.store.kv_set_json(store::KV_RULES, &bundle) {
                    tracing::warn!("persisting rules failed: {e:#}");
                }
                tracing::info!(version = v, rules = bundle.rules.len(), "rules updated");
                true
            }
            Ok(Ok(Err(e))) => {
                tracing::error!(version = v, "rule bundle rejected by engine: {e}");
                false
            }
            _ => {
                tracing::error!(version = v, "engine did not answer rule update");
                false
            }
        }
    }

    pub fn enforce_cap(&self) {
        let mb = self.policy().telemetry.max_outbox_mb.max(16);
        match self.store.enforce_cap(mb * 1024 * 1024) {
            Ok(0) => {}
            Ok(n) => tracing::warn!(
                dropped = n,
                cap_mb = mb,
                "outbox over cap; dropped oldest low-priority rows"
            ),
            Err(e) => tracing::warn!("outbox cap enforcement failed: {e:#}"),
        }
    }

    // ------------------------------------------------------------- sensors

    fn sensor_config(&self) -> SensorConfig {
        let p = self.policy();
        SensorConfig {
            boot_id: self.boot_id.clone(),
            dns: p.privacy.capture_dns || !p.exfil_domains.is_empty(),
            script_content: true,
            sysmon: true,
            self_pid: std::process::id(),
            groups: p.sensors.clone(),
            enrich_tx: Some(self.enrich_tx.clone()),
        }
    }

    /// Start (or restart) sensors. Errors are logged; health reports etw_ok=false.
    pub fn restart_sensors(&self) {
        let cfg = self.sensor_config();
        let mut guard = lock(&self.sensors);
        if let Some(old) = guard.take() {
            old.stop();
        }
        match self
            .platform
            .start_sensors(cfg.clone(), self.event_tx.clone())
        {
            Ok(h) => {
                tracing::info!(dns = cfg.dns, "sensors started");
                *guard = Some(h);
                *lock(&self.sensor_cfg) = Some(cfg);
            }
            Err(e) => tracing::error!("starting sensors failed: {e:#}"),
        }
    }

    fn stop_sensors(&self) {
        if let Some(h) = lock(&self.sensors).take() {
            h.stop();
        }
    }

    // -------------------------------------------------------------- health

    pub fn health(&self) -> AgentHealth {
        let stats = lock(&self.sensors)
            .as_ref()
            .map(|s| s.stats())
            .unwrap_or_default();
        let (cpu, mem) = self.platform.self_usage();
        AgentHealth {
            etw_ok: stats.etw_ok,
            etw_events_lost: stats.events_lost,
            etw_buffers_lost: stats.buffers_lost,
            events_per_min: self.stats.events_per_min.load(Ordering::Relaxed),
            outbox_depth: self.outbox_depth(),
            sysmon_present: stats.sysmon_present,
            dpapi_channel_enabled: stats.dpapi_channel_enabled,
            amsi_ok: stats.amsi_ok,
            isolated: self.platform.is_isolated(),
            hardening: self.hardening_state(),
            cpu_pct: cpu,
            mem_mb: mem,
            uptime_s: self.started.elapsed().as_secs(),
            // M9: same pseudonymisation as telemetry.
            logged_on_user: self
                .platform
                .logged_on_user()
                .map(|u| self.filter().user(&u)),
            ip_addresses: self.platform.ip_addresses(),
            av_product: self.platform.av_product(),
        }
    }

    pub fn send_heartbeat(&self) {
        let seq = match self.store.next_counter(store::KV_HEARTBEAT_SEQ) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("heartbeat counter failed: {e:#}");
                return;
            }
        };
        let health = self.health();
        let _ = self.store.kv_set_json(store::KV_LAST_HEALTH, &health);
        let ts = kestrel_common::now_ms();
        let _ = self.store.kv_set(store::KV_LAST_HEARTBEAT, &ts.to_string());
        self.enqueue(&AgentPayload::Heartbeat(Heartbeat { seq, ts, health }));
    }

    /// Record that the server is reachable now (used by isolation auto-release).
    pub fn mark_server_contact(&self) {
        let _ = self.store.kv_set(
            store::KV_LAST_CONNECTED,
            &kestrel_common::now_ms().to_string(),
        );
    }

    /// H10: release network isolation when the server has been unreachable
    /// for `policy.isolation_auto_release_hours` (default 72 h) since the
    /// later of the isolation start and the last successful contact.
    pub async fn check_isolation_auto_release(&self) -> bool {
        if !self.platform.is_isolated() {
            return false;
        }
        let hours = self.policy().isolation_auto_release_hours;
        let since = self.platform.isolated_since();
        let last = self.store.kv_get_i64(store::KV_LAST_CONNECTED);
        if !auto_release_due(since, last, kestrel_common::now_ms(), hours) {
            return false;
        }
        tracing::warn!(
            hours,
            isolated_since = ?since,
            last_server_contact = ?last,
            "server unreachable while isolated for too long; releasing isolation automatically"
        );
        let o = self
            .execute_action_as(&ResponseAction::ReleaseHost, ActionOrigin::Local)
            .await;
        if o.ok {
            self.notify_tray(
                ActivityItem {
                    id: Uuid::new_v4(),
                    ts: kestrel_common::now_ms(),
                    title: "Network access restored automatically".into(),
                    body: format!(
                        "This PC was isolated by IT but could not reach Kestrel for {hours} hours, so the isolation was lifted. Contact IT if you were told to keep it offline."
                    ),
                    severity: Severity::Medium,
                    alert_id: None,
                    file: None,
                    action_taken: "Isolation released".into(),
                    review: None,
                },
                true,
                None,
            );
        } else {
            tracing::error!(detail = %o.detail, "automatic isolation release failed");
        }
        o.ok
    }

    fn maybe_send_inventory(&self) {
        let last = self.store.kv_get_i64(store::KV_LAST_INVENTORY).unwrap_or(0);
        let now = kestrel_common::now_ms();
        if now - last < self.tuning.inventory_every.as_millis() as i64 {
            return;
        }
        // CONTRACT GAP: `Platform` has no inventory source yet; report what the
        // agent itself knows so the server's per-device inventory is populated.
        let inv = Inventory {
            software: vec![Software {
                name: "Kestrel EDR Agent".into(),
                version: kestrel_common::VERSION.into(),
                publisher: "Kestrel".into(),
            }],
            local_admins: vec![],
        };
        self.enqueue(&AgentPayload::Inventory(inv));
        let _ = self
            .store
            .kv_set(store::KV_LAST_INVENTORY, &now.to_string());
    }
}

/// A running agent.
pub struct AgentHandle {
    pub core: Arc<Core>,
    tasks: Vec<JoinHandle<()>>,
    detect_thread: Option<std::thread::JoinHandle<()>>,
}

impl AgentHandle {
    pub fn shutdown_token(&self) -> CancellationToken {
        self.core.shutdown.clone()
    }

    /// Stop all tasks and wait for them.
    pub async fn stop(mut self) {
        self.core.shutdown.cancel();
        self.core.stop_sensors();
        for t in self.tasks.drain(..) {
            let _ = tokio::time::timeout(Duration::from_secs(10), t).await;
        }
        if let Some(t) = self.detect_thread.take() {
            let _ = tokio::task::spawn_blocking(move || t.join()).await;
        }
        tracing::info!("agent stopped");
    }

    /// Run until the shutdown token is cancelled.
    pub async fn wait(self) {
        self.core.shutdown.cancelled().await;
        self.stop().await;
    }
}

/// Resolve server IPs (cached for offline starts).
async fn resolve_server_ips(store: &Store, cfg: &AgentConfig) -> Vec<String> {
    let mut ips: Vec<String> = vec![];
    if let Ok((host, port)) = cfg.host_port() {
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ips.push(ip.to_string());
        } else if let Ok(Ok(addrs)) = tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        {
            for a in addrs {
                let s = a.ip().to_string();
                if !ips.contains(&s) {
                    ips.push(s);
                }
            }
        }
    }
    if ips.is_empty() {
        ips = store
            .kv_get_json(store::KV_SERVER_IPS)
            .ok()
            .flatten()
            .unwrap_or_default();
    } else {
        let _ = store.kv_set_json(store::KV_SERVER_IPS, &ips);
    }
    ips
}

/// Start the agent: engine, sensors, transport, heartbeats and tray.
pub async fn start(
    platform: Arc<dyn Platform>,
    state_dir: PathBuf,
    tuning: Tuning,
) -> Result<AgentHandle> {
    crate::pki::install_crypto_provider();
    let cfg = AgentConfig::load(&state_dir)
        .context("agent is not installed (no agent.toml); run `kestrel-agent install`")?;
    let store = Arc::new(Store::open(&state_dir)?);
    let policy: Option<Policy> = store.kv_get_json(store::KV_POLICY).unwrap_or_else(|e| {
        tracing::warn!("cached policy unreadable: {e:#}");
        None
    });
    let bundle: RuleBundle = store
        .kv_get_json(store::KV_RULES)
        .ok()
        .flatten()
        .unwrap_or_default();
    let salt = match store.kv_get(store::KV_USER_SALT)? {
        Some(s) => s,
        None => {
            let s = crate::config::random_token();
            store.kv_set(store::KV_USER_SALT, &s)?;
            s
        }
    };
    let server_ips = resolve_server_ips(&store, &cfg).await;
    let boot_id = platform.boot_id();
    let hostname = platform.hostname();
    let eff_policy = policy.clone().unwrap_or_default();

    let (event_tx, event_rx) = mpsc::channel(tuning.event_channel);
    let (enrich_tx, enrich_rx) = mpsc::channel::<LateEnrichment>(4096);
    let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
    // Volume-aware path trust for everything in this process (H1).
    let system_drive = platform.system_drive();
    kestrel_common::set_system_drive(system_drive);
    let (tray_tx, _) = broadcast::channel(256);

    let core = Arc::new(Core {
        state_dir: state_dir.clone(),
        cfg: RwLock::new(cfg),
        store: store.clone(),
        platform: platform.clone(),
        tuning: tuning.clone(),
        boot_id: boot_id.clone(),
        hostname: hostname.clone(),
        started: Instant::now(),
        stats: Stats::default(),
        shutdown: CancellationToken::new(),
        filter: RwLock::new(Arc::new(PrivacyFilter::new(
            &eff_policy.privacy,
            &eff_policy.telemetry,
            &salt,
        ))),
        policy: RwLock::new(policy.clone()),
        rules_version: AtomicU64::new(bundle.version),
        connected: AtomicBool::new(false),
        outbox_notify: Notify::new(),
        tray_tx,
        hardening: RwLock::new(BTreeMap::new()),
        sensors: Mutex::new(None),
        sensor_cfg: Mutex::new(None),
        event_tx,
        enrich_tx,
        engine_ctl: ctl_tx,
        server_ips: RwLock::new(server_ips.clone()),
        inflight_cmds: Mutex::new(HashSet::new()),
        salt,
    });

    tracing::info!(
        version = kestrel_common::VERSION,
        %hostname,
        %boot_id,
        device_id = ?core.config().device_id,
        policy_version = core.policy_version(),
        rules_version = bundle.version,
        outbox = core.outbox_depth(),
        "Kestrel agent starting"
    );

    // Engine on a dedicated thread.
    let host = HostContext {
        boot_id: boot_id.clone(),
        hostname: hostname.clone(),
        agent_image: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        server_ips,
        system_drive: Some(system_drive),
    };
    let seeds = platform.snapshot_processes(&boot_id);
    tracing::info!(processes = seeds.len(), "seeding process table");
    let detect_thread = detection::spawn(
        core.clone(),
        host,
        eff_policy,
        bundle,
        seeds,
        event_rx,
        enrich_rx,
        ctl_rx,
        tokio::runtime::Handle::current(),
    )?;

    // Sensors after the engine is ready to drain them.
    core.restart_sensors();
    // H10: a host that stayed isolated without reaching the server (e.g. it
    // roamed to a network whose DNS is not permitted) is released at boot.
    {
        let c = core.clone();
        tokio::spawn(async move {
            c.check_isolation_auto_release().await;
        });
    }
    // Initial hardening check / apply with the cached (or default) policy.
    {
        let c = core.clone();
        tokio::spawn(async move {
            c.apply_hardening().await;
        });
    }

    let mut tasks = vec![];
    tasks.push(tokio::spawn(crate::transport::run(core.clone())));
    tasks.push(tokio::spawn(housekeeping(core.clone())));
    {
        let handler: Arc<dyn kestrel_platform::TrayHandler> =
            Arc::new(crate::tray::TrayService::new(core.clone()));
        let p = platform.clone();
        let cancel = core.shutdown.clone();
        tasks.push(tokio::spawn(async move {
            tokio::select! {
                r = p.serve_tray(handler) => if let Err(e) = r { tracing::error!("tray server stopped: {e:#}") },
                _ = cancel.cancelled() => {}
            }
        }));
    }

    Ok(AgentHandle {
        core,
        tasks,
        detect_thread: Some(detect_thread),
    })
}

async fn housekeeping(core: Arc<Core>) {
    let mut hb = tokio::time::interval(core.tuning.heartbeat);
    hb.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut minute = tokio::time::interval(core.tuning.housekeeping);
    minute.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut harden = tokio::time::interval_at(
        tokio::time::Instant::now() + core.tuning.hardening_recheck,
        core.tuning.hardening_recheck,
    );
    let mut last_seen = 0u64;
    let mut last_minute = Instant::now();
    loop {
        tokio::select! {
            _ = core.shutdown.cancelled() => break,
            _ = hb.tick() => core.send_heartbeat(),
            _ = minute.tick() => {
                let seen = core.stats.events_seen.load(Ordering::Relaxed);
                let secs = last_minute.elapsed().as_secs_f64().max(1.0);
                core.stats.events_per_min.store(((seen - last_seen) as f64 * 60.0 / secs) as u64, Ordering::Relaxed);
                last_seen = seen;
                last_minute = Instant::now();
                core.enforce_cap();
                core.maybe_send_inventory();
                if core.is_connected() {
                    core.mark_server_contact();
                } else {
                    core.check_isolation_auto_release().await;
                }
                if lock(&core.sensors).is_none() {
                    core.restart_sensors();
                }
            }
            _ = harden.tick() => {
                let before = core.hardening_state();
                let after = core.apply_hardening().await;
                if before != after {
                    tracing::warn!(?after, "hardening state changed");
                }
                // Refresh canaries (they may have been deleted).
                let _ = core.engine_ctl.send(EngineCtl::PlantCanaries);
            }
        }
    }
}

/// Is an automatic isolation release due? `hours == 0` disables it. The
/// clock starts at the later of the isolation start and the last time the
/// server was reached; an unknown isolation start never auto-releases.
pub fn auto_release_due(
    isolated_since: Option<i64>,
    last_server_contact: Option<i64>,
    now: i64,
    hours: u64,
) -> bool {
    if hours == 0 {
        return false;
    }
    let Some(since) = isolated_since else {
        return false;
    };
    let reference = last_server_contact.map_or(since, |c| c.max(since));
    now - reference >= (hours as i64).saturating_mul(3_600_000)
}

/// Ids of the Block IOCs in `p`: IOC-created WFP blocks whose id is not in
/// this set are lifted when the policy is applied (M10).
pub fn block_ioc_ids(p: &Policy) -> std::collections::BTreeSet<String> {
    p.iocs
        .iter()
        .filter(|i| i.action == kestrel_common::IocAction::Block && !i.id.is_empty())
        .map(|i| i.id.clone())
        .collect()
}

/// Plain-language severity → whether to pop a tray notification.
pub(crate) fn should_push(sev: Severity, acted: bool) -> bool {
    acted || sev >= Severity::Critical
}

#[cfg(test)]
mod tests {
    use super::auto_release_due;

    const H: i64 = 3_600_000;

    #[test]
    fn isolation_auto_release() {
        // isolated at t=0, never reached the server since
        assert!(!auto_release_due(Some(0), None, 71 * H, 72));
        assert!(auto_release_due(Some(0), None, 72 * H, 72));
        // server reached after isolation: the clock restarts from that contact
        assert!(!auto_release_due(Some(0), Some(10 * H), 72 * H, 72));
        assert!(auto_release_due(Some(0), Some(10 * H), 82 * H, 72));
        // a contact *before* the isolation does not shorten the window
        assert!(!auto_release_due(Some(100 * H), Some(0), 150 * H, 72));
        // disabled / unknown isolation start
        assert!(!auto_release_due(Some(0), None, 1000 * H, 0));
        assert!(!auto_release_due(None, None, 1000 * H, 72));
    }

    #[test]
    fn block_ioc_ids_only_block_iocs() {
        use kestrel_common::{Ioc, IocAction, IocKind, Policy};
        let ioc = |id: &str, action| Ioc {
            id: id.into(),
            kind: IocKind::Domain,
            value: format!("{id}.example"),
            action,
            description: String::new(),
        };
        let p = Policy {
            iocs: vec![
                ioc("b1", IocAction::Block),
                ioc("a1", IocAction::Audit),
                ioc("w1", IocAction::Allow),
                ioc("b2", IocAction::Block),
                ioc("", IocAction::Block),
            ],
            ..Policy::default()
        };
        let ids: Vec<String> = super::block_ioc_ids(&p).into_iter().collect();
        assert_eq!(ids, ["b1", "b2"]);
        assert!(super::block_ioc_ids(&Policy::default()).is_empty());
    }
}
