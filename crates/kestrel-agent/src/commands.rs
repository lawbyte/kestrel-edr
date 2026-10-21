//! CLI command implementations (kept in the library so tests can drive them).

use anyhow::{bail, Context, Result};
use kestrel_common::tray::{TrayRequest, TrayResponse};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::agent::{self, Tuning};
use crate::config::{self, AgentConfig};
use crate::sim::{SimOptions, SimPlatform};
use crate::store::{self, Store};

#[derive(Debug, Clone, Default)]
pub struct InstallOpts {
    pub server: String,
    pub ca: String,
    pub token: String,
    pub tags: Vec<String>,
    pub server_name: Option<String>,
    pub uninstall_token: Option<String>,
    pub hostname: Option<String>,
}

/// Write `agent.toml` for a new install. Keeps an existing device's identity
/// only when the server is unchanged.
///
/// The uninstall token is issued by the server at enrollment (M5,
/// `EnrollResponse.uninstall_token`, stored as an Argon2id hash). An explicit
/// `uninstall_token` (CLI / env, for servers that do not issue one) is still
/// honoured; otherwise an existing hash from a previous install is kept until
/// the server sends a new token. Callers must have secured the state directory
/// first ([`crate::platform_win::secure_state_dir`]): a pre-existing
/// `agent.toml` is only read when the directory was trustworthy.
pub fn write_install_config(state_dir: &Path, o: &InstallOpts) -> Result<AgentConfig> {
    config::split_host_port(&o.server)?;
    let ca_pem = config::load_ca_arg(&o.ca)?;
    let prev = AgentConfig::load(state_dir).ok();
    let mut cfg = AgentConfig {
        server: o.server.trim().to_string(),
        server_name: o.server_name.clone().filter(|s| !s.is_empty()),
        ca_pem,
        device_id: None,
        uninstall_token_hash: None,
        pending_enroll_token: Some(o.token.trim().to_string()).filter(|t| !t.is_empty()),
        tags: o.tags.clone(),
        hostname: o.hostname.clone(),
        remote_ceiling: None,
    };
    if let Some(p) = &prev {
        if p.server == cfg.server && p.ca_pem == cfg.ca_pem {
            cfg.device_id = p.device_id;
            cfg.uninstall_token_hash = p.uninstall_token_hash.clone();
            // The identity is kept (see `keep_existing_enrollment`), and so is
            // the remote-access ceiling pinned when it was enrolled.
            cfg.remote_ceiling = p.remote_ceiling.clone();
        }
    }
    if let Some(t) = o
        .uninstall_token
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    {
        cfg.set_uninstall_token(t)?;
    }
    cfg.save(state_dir)?;
    Ok(cfg)
}

/// After [`write_install_config`]: when this device already holds an identity
/// for the same server and CA (re-install, repair, or an MSI upgrade that ran
/// the install action anyway), keep it and do not enroll again (V-M3). The
/// enrollment token just supplied is not kept in the config then. Returns
/// true when enrollment should be skipped.
pub fn keep_existing_enrollment(state_dir: &Path, cfg: &mut AgentConfig) -> Result<bool> {
    if !crate::pki::is_enrolled(state_dir, cfg) {
        return Ok(false);
    }
    if cfg.pending_enroll_token.take().is_some() {
        cfg.save(state_dir)?;
    }
    Ok(true)
}

/// File holding a locally generated uninstall token (only when the server
/// did not issue one). Lives in the SYSTEM/Administrators-only state dir and
/// is removed as soon as a server-issued token replaces it.
pub const LOCAL_UNINSTALL_TOKEN_FILE: &str = "uninstall-token.txt";

/// After an install-time enrollment attempt: make sure an uninstall token
/// exists. Never prints the token (MSI custom-action output can reach the
/// MSI log); a locally generated one is written to
/// [`LOCAL_UNINSTALL_TOKEN_FILE`] instead. Returns that file's path when a
/// local token had to be generated.
pub fn ensure_uninstall_token(state_dir: &Path) -> Result<Option<PathBuf>> {
    let mut cfg = AgentConfig::load(state_dir)?;
    if cfg.uninstall_token_hash.is_some() {
        return Ok(None);
    }
    let t = config::random_token();
    cfg.set_uninstall_token(&t)?;
    let path = state_dir.join(LOCAL_UNINSTALL_TOKEN_FILE);
    config::write_secret(
        &path,
        format!(
            "{t}\n# Kestrel uninstall token generated locally because the server did not issue one.\n# It is replaced by the server-issued token at the next enrollment.\n"
        )
        .as_bytes(),
    )?;
    cfg.save(state_dir)?;
    Ok(Some(path))
}

/// Enroll using the token in the config (or `token`), updating the config.
pub async fn enroll(
    state_dir: &Path,
    token: Option<&str>,
    hostname: &str,
    os: kestrel_common::wire::OsInfo,
) -> Result<uuid::Uuid> {
    let mut cfg = AgentConfig::load(state_dir)?;
    let token = match token {
        Some(t) => t.to_string(),
        None => cfg
            .pending_enroll_token
            .clone()
            .context("no enrollment token given")?,
    };
    let er = crate::pki::enroll(state_dir, &mut cfg, &token, hostname, os).await?;
    cfg.save(state_dir)?;
    if !er.uninstall_token.trim().is_empty() {
        let _ = std::fs::remove_file(state_dir.join(LOCAL_UNINSTALL_TOKEN_FILE));
    }
    Ok(er.device_id)
}

/// Best-effort hostname for enrollment before a platform exists.
pub fn local_hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "unknown-host".into())
}

/// Status JSON: tray status from the running agent + last heartbeat health from the DB.
pub async fn status(state_dir: &Path) -> Result<serde_json::Value> {
    let cfg = AgentConfig::load(state_dir).ok();
    let live = crate::tray::query(state_dir, &TrayRequest::Status).await;
    let db = Store::open(state_dir).ok();
    let health: Option<kestrel_common::wire::AgentHealth> = db
        .as_ref()
        .and_then(|s| s.kv_get_json(store::KV_LAST_HEALTH).ok().flatten());
    let last_hb = db
        .as_ref()
        .and_then(|s| s.kv_get_i64(store::KV_LAST_HEARTBEAT));
    let policy: Option<kestrel_common::Policy> = db
        .as_ref()
        .and_then(|s| s.kv_get_json(store::KV_POLICY).ok().flatten());
    let depth = db.as_ref().and_then(|s| s.depth().ok());
    let (running, tray_status, err) = match live {
        Ok(TrayResponse::Status(s)) => (true, Some(s), None),
        Ok(other) => (true, None, Some(format!("unexpected response: {other:?}"))),
        Err(e) => (false, None, Some(format!("{e:#}"))),
    };
    Ok(serde_json::json!({
        "agent_version": kestrel_common::VERSION,
        "running": running,
        "error": err,
        "server": cfg.as_ref().map(|c| c.server.clone()),
        "device_id": cfg.as_ref().and_then(|c| c.device_id),
        "enrolled": cfg.as_ref().map(|c| crate::pki::is_enrolled(state_dir, c)).unwrap_or(false),
        "status": tray_status,
        "policy": policy.map(|p| serde_json::json!({"id": p.id, "name": p.name, "version": p.version})),
        "outbox_depth": depth,
        "last_heartbeat": last_hb,
        "health": health,
    }))
}

#[derive(Debug, Clone)]
pub struct SimulateOpts {
    pub install: InstallOpts,
    pub replay: PathBuf,
    pub speed: f64,
    pub hostname: String,
    /// Exit this long after the replay completes (once the outbox drains).
    pub exit_after_replay: Option<Duration>,
    /// How the simulated employee answers remote-access consent prompts.
    pub consent: crate::sim::SimConsent,
}

/// Configure (if needed), enroll, then run the full agent on `SimPlatform`.
pub async fn simulate(state_dir: &Path, o: SimulateOpts, tuning: Tuning) -> Result<()> {
    std::fs::create_dir_all(state_dir)?;
    let need_cfg = match AgentConfig::load(state_dir) {
        Ok(c) => c.server != o.install.server.trim() || !crate::pki::is_enrolled(state_dir, &c),
        Err(_) => true,
    };
    if need_cfg {
        let mut io = o.install.clone();
        io.hostname = Some(o.hostname.clone());
        if io.uninstall_token.is_none() {
            io.uninstall_token = Some(config::random_token());
        }
        write_install_config(state_dir, &io)?;
    }
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state_dir.to_path_buf(),
        replay: Some(o.replay.clone()),
        speed: o.speed,
        hostname: o.hostname.clone(),
        user: crate::sim::SIM_USER.into(),
    }));
    sim.set_consent(o.consent);
    let cfg = AgentConfig::load(state_dir)?;
    if !crate::pki::is_enrolled(state_dir, &cfg) {
        use kestrel_platform::Platform;
        match enroll(state_dir, None, &o.hostname, sim.os_info()).await {
            Ok(id) => tracing::info!(device_id = %id, "enrolled"),
            Err(e) => tracing::warn!(
                "enrollment failed ({e:#}); the agent will keep retrying while protecting locally"
            ),
        }
    }
    let handle = agent::start(sim.clone(), state_dir.to_path_buf(), tuning).await?;
    let cancel = handle.shutdown_token();
    let core = handle.core.clone();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("interrupted; shutting down");
            cancel.cancel();
        }
    });
    if let Some(grace) = o.exit_after_replay {
        let sim = sim.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            while !sim.replay_done() {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            let deadline = tokio::time::Instant::now() + grace;
            // Let the batcher flush, then wait for the outbox to drain (or the grace to expire).
            tokio::time::sleep(core.tuning.batch_max_delay + Duration::from_millis(500)).await;
            while tokio::time::Instant::now() < deadline {
                let only_hb = core
                    .store
                    .pending_after(0, 10)
                    .map(|r| r.iter().all(|i| i.kind == "heartbeat"))
                    .unwrap_or(false);
                if core.outbox_depth() == 0 || (only_hb && core.is_connected()) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            tracing::info!(
                replayed = sim.events_replayed(),
                actions = sim.executed().len(),
                outbox = core.outbox_depth(),
                "replay complete; exiting"
            );
            cancel.cancel();
        });
    }
    handle.wait().await;
    Ok(())
}

/// Run the real (Windows) agent until `stop` fires.
pub async fn run_real(
    state_dir: PathBuf,
    stop: impl std::future::Future<Output = ()>,
) -> Result<()> {
    // H4: verify (or re-create) the state directory before trusting anything in it.
    let check = crate::platform_win::secure_state_dir(&state_dir)?;
    if let Some(moved) = &check.moved_aside {
        bail!(
            "the state directory {} was not owned/protected by SYSTEM or Administrators; it was moved to {} and re-created empty. Reinstall the agent.",
            state_dir.display(),
            moved.display()
        );
    }
    let cfg = AgentConfig::load(&state_dir).context("agent is not installed")?;
    // The host name (re-resolved while isolated, H10) plus the IPs it has now.
    let mut ips = vec![cfg.server.clone()];
    ips.extend(server_ips_hint(&cfg).await);
    let platform = crate::platform_win::platform(state_dir.clone(), ips)?;
    let handle = agent::start(platform, state_dir, Tuning::default()).await?;
    // V-M3: report the outcome of an update the previous process installed.
    crate::update::on_startup(&handle.core);
    let cancel = handle.shutdown_token();
    tokio::select! {
        _ = stop => {}
        _ = cancel.cancelled() => {}
    }
    handle.stop().await;
    Ok(())
}

async fn server_ips_hint(cfg: &AgentConfig) -> Vec<String> {
    let Ok((host, port)) = cfg.host_port() else {
        return vec![];
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return vec![ip.to_string()];
    }
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host((host.as_str(), port)),
    )
    .await;
    match r {
        Ok(Ok(a)) => a.map(|s| s.ip().to_string()).collect(),
        _ => vec![],
    }
}

/// Local break-glass (H10): release network isolation without the server.
/// Requires the uninstall token and administrator rights (the WFP engine and
/// the state directory are admin-only). The running service notices the
/// release and does not re-apply the filters.
pub fn release_isolation(state_dir: &Path, token: &str) -> Result<String> {
    verify_uninstall(state_dir, token)?;
    crate::platform_win::release_isolation_offline(state_dir)
}

pub fn verify_uninstall(state_dir: &Path, token: &str) -> Result<AgentConfig> {
    let cfg = AgentConfig::load(state_dir).context("agent is not installed")?;
    if !cfg.verify_uninstall_token(token) {
        bail!("invalid uninstall token");
    }
    Ok(cfg)
}

/// After a real uninstall (never a verified major upgrade, which does not run
/// `uninstall`): forget the enrolled identity, so a later install with a new
/// enrollment token enrolls as a new device and pins that token's
/// remote-access ceiling. Removes the client key and certificate, the config
/// (device id, pinned ceiling, uninstall-token hash) and the outbox of the
/// old device. Keeps evidence and restore state: `quarantine/`, `logs/`,
/// `triage/`, and the hardening/WFP/canary state files the next agent needs
/// to undo what this one changed. Returns the names removed.
pub fn retire_identity(state_dir: &Path) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    let keys = state_dir.join(config::KEYS_DIR);
    if keys.is_dir() {
        std::fs::remove_dir_all(&keys).with_context(|| format!("removing {}", keys.display()))?;
        removed.push(config::KEYS_DIR.to_string());
    }
    let wal = format!("{}-wal", store::DB_FILE);
    let shm = format!("{}-shm", store::DB_FILE);
    for name in [
        config::CONFIG_FILE,
        store::DB_FILE,
        wal.as_str(),
        shm.as_str(),
    ] {
        let p = state_dir.join(name);
        if p.is_file() {
            std::fs::remove_file(&p).with_context(|| format!("removing {}", p.display()))?;
            removed.push(name.to_string());
        }
    }
    Ok(removed)
}

/// Upper bound on events written by `sensors-test --events-out`.
pub const SENSORS_TEST_MAX_EVENTS: u64 = 500_000;

/// Engine with the default policy, every catalog rule forced to Audit (so no
/// `Output` ever carries an action) and canaries off.
fn audit_only_engine(boot_id: String) -> Result<kestrel_detect::Engine> {
    use kestrel_common::{Policy, RuleBundle, RuleMode};
    let mut policy = Policy {
        canaries: false,
        ..Policy::default()
    };
    for m in kestrel_detect::Engine::catalog() {
        policy.rules.insert(m.id.clone(), RuleMode::Audit);
    }
    let host = kestrel_detect::HostContext {
        boot_id,
        hostname: hostname_or_default(),
        agent_image: std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        agent_pid: std::process::id(),
        server_ips: vec![],
        system_drive: std::env::var("SystemDrive")
            .ok()
            .and_then(|d| d.chars().next()),
    };
    kestrel_detect::Engine::new(host, policy, RuleBundle::default())
        .map_err(|e| anyhow::anyhow!("engine: {e}"))
}

fn hostname_or_default() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "localhost".into())
}

fn collect_alerts(alerts: &mut Vec<serde_json::Value>, outs: Vec<kestrel_detect::Output>) {
    for o in outs {
        if let kestrel_detect::Output::Alert(d) = o {
            debug_assert!(d.actions.is_empty(), "audit-only engine produced actions");
            alerts.push(serde_json::json!({
                "ts": d.alert.ts,
                "rule_id": d.alert.rule_id,
                "severity": d.alert.severity,
                "summary": d.alert.summary,
                "image": d.alert.process.image,
                "pid": d.alert.process.pid,
            }));
        }
    }
}

/// `kestrel-agent sensors-test`: start only the platform sensors (Windows:
/// ETW/event-log sessions via `WindowsPlatform::start_sensors`) for `seconds`
/// and summarise what was observed. No server, no engine, no response — a CI
/// smoke test that the sensors produce events on a real Windows host.
///
/// `ready` is called once the sensors are running (the smoke script waits for
/// it before generating activity).
///
/// Optional, still read-only extras for lab work:
/// * `events_out`: write every observed event as JSON lines (capped at
///   [`SENSORS_TEST_MAX_EVENTS`]) — raw material for regression fixtures.
/// * `detect`: run the detection engine on the stream with **every rule forced
///   to Audit** and report the alerts. No action is ever executed.
pub async fn sensors_test(
    state_dir: &Path,
    seconds: u64,
    events_out: Option<&Path>,
    detect: bool,
    ready: impl FnOnce(),
) -> Result<serde_json::Value> {
    use kestrel_common::EventData;
    use kestrel_platform::SensorConfig;
    use std::collections::{BTreeMap, BTreeSet};
    use std::io::Write as _;

    std::fs::create_dir_all(state_dir)?;
    let platform = crate::platform_win::platform(state_dir.to_path_buf(), vec![])?;
    let boot_id = platform.boot_id();
    let (tx, mut rx) = tokio::sync::mpsc::channel(65_536);
    let cfg = SensorConfig {
        boot_id: boot_id.clone(),
        dns: true,
        script_content: true,
        sysmon: false,
        self_pid: std::process::id(),
        groups: kestrel_common::SensorSettings::default(),
        enrich_tx: None,
    };
    let handle = platform
        .start_sensors(cfg, tx)
        .context("starting sensors")?;
    ready();

    let started = std::time::Instant::now();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds.max(1));
    let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut images: BTreeSet<String> = BTreeSet::new();
    let mut qnames: BTreeSet<String> = BTreeSet::new();
    let mut total = 0u64;
    let mut out = match events_out {
        Some(p) => Some(std::io::BufWriter::new(
            std::fs::File::create(p).with_context(|| format!("creating {}", p.display()))?,
        )),
        None => None,
    };
    let mut engine = if detect {
        let mut e = audit_only_engine(boot_id.clone())?;
        // Same as the service: processes that predate the sensors are known.
        for info in platform.snapshot_processes(&boot_id) {
            e.seed_process(info);
        }
        Some(e)
    } else {
        None
    };
    let mut alerts: Vec<serde_json::Value> = Vec::new();
    let mut next_tick = tokio::time::Instant::now() + Duration::from_millis(250);
    loop {
        let wake = next_tick.min(deadline);
        let ev = match tokio::time::timeout_at(wake, rx.recv()).await {
            Ok(Some(ev)) => ev,
            Ok(None) => break,
            Err(_) => {
                if tokio::time::Instant::now() >= deadline {
                    break;
                }
                if let Some(e) = engine.as_mut() {
                    let outs = e.tick(kestrel_common::now_ms());
                    collect_alerts(&mut alerts, outs);
                }
                next_tick = tokio::time::Instant::now() + Duration::from_millis(250);
                continue;
            }
        };
        total += 1;
        if let Some(w) = out.as_mut() {
            if total <= SENSORS_TEST_MAX_EVENTS {
                serde_json::to_writer(&mut *w, &ev)?;
                w.write_all(
                    b"
",
                )?;
            }
        }
        if let Some(e) = engine.as_mut() {
            let outs = e.process(&ev);
            collect_alerts(&mut alerts, outs);
        }
        *counts.entry(ev.kind().as_str()).or_default() += 1;
        match &ev.data {
            EventData::ProcessStart(p) if images.len() < 200 => {
                let name = p
                    .image
                    .rsplit(['\\', '/'])
                    .next()
                    .unwrap_or(&p.image)
                    .to_ascii_lowercase();
                images.insert(name);
            }
            EventData::DnsQuery { qname, .. } if qnames.len() < 200 => {
                qnames.insert(qname.to_ascii_lowercase());
            }
            _ => {}
        }
    }
    if let Some(mut w) = out {
        w.flush()?;
    }
    let s = handle.stats();
    handle.stop();
    Ok(serde_json::json!({
        "alerts": alerts,
        "seconds": started.elapsed().as_secs_f64(),
        "total": total,
        "counts": counts,
        "process_images": images,
        "dns_qnames": qnames,
        "stats": {
            "etw_ok": s.etw_ok,
            "events_lost": s.events_lost,
            "buffers_lost": s.buffers_lost,
            "events_total": s.events_total,
            "sysmon_present": s.sysmon_present,
            "dpapi_channel_enabled": s.dpapi_channel_enabled,
            "amsi_ok": s.amsi_ok,
        },
    }))
}

#[cfg(test)]
mod retire_tests {
    use super::*;

    #[test]
    fn retire_identity_forgets_enrollment_but_keeps_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path();
        for sub in [config::KEYS_DIR, "quarantine", "logs", "triage"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
        }
        std::fs::write(d.join(config::KEYS_DIR).join("client.key"), "k").unwrap();
        std::fs::write(d.join("quarantine").join("item.bin"), "q").unwrap();
        for f in [
            config::CONFIG_FILE,
            store::DB_FILE,
            "agent.db-wal",
            "agent.db-shm",
            "hardening_state.json",
            "wfp_state.json",
        ] {
            std::fs::write(d.join(f), "x").unwrap();
        }
        let removed = retire_identity(d).unwrap();
        assert_eq!(
            removed,
            vec![
                "keys",
                "agent.toml",
                "agent.db",
                "agent.db-wal",
                "agent.db-shm"
            ]
        );
        assert!(!d.join(config::KEYS_DIR).exists());
        assert!(!d.join(config::CONFIG_FILE).exists());
        assert!(d.join("quarantine").join("item.bin").is_file());
        assert!(d.join("logs").is_dir() && d.join("triage").is_dir());
        assert!(d.join("hardening_state.json").is_file() && d.join("wfp_state.json").is_file());
        // Idempotent.
        assert!(retire_identity(d).unwrap().is_empty());
    }
}
