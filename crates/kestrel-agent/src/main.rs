//! `kestrel-agent` command line.

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use kestrel_agent::{
    agent::Tuning,
    commands::{self, InstallOpts, SimulateOpts},
    config, logging, platform_win,
};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser, Debug)]
#[command(name = "kestrel-agent", version, about = "Kestrel EDR endpoint agent")]
struct Cli {
    /// Agent state directory (default: C:\ProgramData\Kestrel on Windows, ./kestrel-state elsewhere).
    #[arg(long, global = true, env = "KESTREL_STATE_DIR")]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the agent (as a Windows service unless --console).
    /// `service` is accepted as an alias: kestrel-win registers the service as `<exe> service`.
    #[command(alias = "service")]
    Run {
        /// Run in the foreground with logs on stderr.
        #[arg(long)]
        console: bool,
    },
    /// Write config, enroll with the server and install the service.
    Install {
        #[command(flatten)]
        server: ServerArgs,
        /// Device tag(s) reported to the server (repeatable).
        #[arg(long = "group-tag")]
        group_tag: Vec<String>,
        /// Uninstall token for servers that do not issue one at enrollment
        /// (stored as an Argon2id hash). Normally omitted: the server issues a
        /// per-device token and shows it to admins on the device page.
        #[arg(long, env = "KESTREL_UNINSTALL_TOKEN", hide_env_values = true)]
        uninstall_token: Option<String>,
        /// Only write config and enroll; don't register the service.
        #[arg(long)]
        no_service: bool,
    },
    /// Re-enroll this device (new key + certificate).
    Enroll {
        /// Enrollment token (defaults to a pending token from install).
        #[arg(long)]
        token: Option<String>,
    },
    /// Print agent health as JSON (queries the running agent).
    Status,
    /// Stop and remove the agent service (requires the uninstall token).
    Uninstall {
        #[arg(
            long,
            env = "KESTREL_UNINSTALL_TOKEN",
            hide_env_values = true,
            required_unless_present = "token_stdin"
        )]
        token: Option<String>,
        /// Read the uninstall token from the first line of stdin (used by the MSI).
        #[arg(long)]
        token_stdin: bool,
        /// Also delete the state directory (keys, outbox, logs).
        #[arg(long)]
        purge: bool,
    },
    /// Break-glass: release network isolation locally (run as administrator;
    /// requires the device's uninstall token). Use when an isolated host can
    /// no longer reach the Kestrel server.
    ReleaseIsolation {
        #[arg(long, env = "KESTREL_UNINSTALL_TOKEN", hide_env_values = true)]
        token: String,
    },
    /// Run the full agent against recorded telemetry (any OS).
    Simulate {
        #[command(flatten)]
        server: ServerArgs,
        /// JSONL file of kestrel_common::Event to replay.
        #[arg(long)]
        replay: PathBuf,
        /// Replay speed multiplier (2 = twice as fast).
        #[arg(long, default_value_t = 1.0)]
        speed: f64,
        #[arg(long, default_value = "SIM-WKS-01")]
        hostname: String,
        /// Exit N seconds after the replay finishes (once uploads drain). Runs until Ctrl-C if omitted.
        #[arg(long)]
        exit_after_replay: Option<u64>,
        /// Heartbeat interval in seconds (default 30).
        #[arg(long)]
        heartbeat_secs: Option<u64>,
        /// How the simulated employee answers remote-access consent prompts:
        /// allow, deny or ignore (let them time out).
        #[arg(long, default_value = "allow")]
        sim_consent: kestrel_agent::sim::SimConsent,
    },
    /// Remote desktop capture helper (Windows): started by the agent service
    /// in the interactive session; talks to it over the named pipe `--pipe`
    /// and exits with the parent `--parent`. Not for manual use.
    #[command(hide = true)]
    DesktopHelper {
        #[arg(long)]
        pipe: String,
        #[arg(long)]
        parent: u32,
    },
    /// CI smoke test (Windows): start only the sensors for N seconds and print
    /// observed event counts as JSON. No server connection, no detection or response.
    #[command(hide = true)]
    SensorsTest {
        #[arg(long, default_value_t = 20)]
        seconds: u64,
        /// Write every observed event as JSON lines to this file (lab fixtures).
        #[arg(long)]
        events_out: Option<PathBuf>,
        /// Also run the detection engine with every rule forced to Audit and
        /// print its alerts (never executes a response action).
        #[arg(long)]
        detect: bool,
    },
    /// Release signing (owner, offline): create an Ed25519 update signing key.
    /// Writes the private key (owner-only permissions) and public key files
    /// and prints the base64 public key for KESTREL_UPDATE_PUBKEY.
    #[command(hide = true)]
    UpdateKeygen {
        /// Directory for kestrel-update-signing.key / .pub (keep it offline).
        #[arg(long)]
        out: PathBuf,
    },
    /// Release signing (owner, offline): print the signed manifest JSON for
    /// an agent MSI, to paste into the console (Agent updates → Register).
    #[command(hide = true)]
    UpdateSign {
        /// Private key file from `update-keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Version of the agent inside the MSI (e.g. 1.4.0).
        #[arg(long)]
        version: String,
        /// HTTPS URL agents download the MSI from, e.g.
        /// https://<server>:8443/downloads/updates/KestrelAgent-1.4.0.msi
        #[arg(long)]
        url: String,
        /// The MSI file (its SHA-256 goes into the manifest).
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Args, Debug, Clone)]
struct ServerArgs {
    /// Server gRPC address host:port.
    #[arg(long, env = "KESTREL_SERVER")]
    server: String,
    /// Server CA: PEM file path, PEM text, or base64.
    #[arg(long, env = "KESTREL_CA")]
    ca: String,
    /// Enrollment token. Avoid on shared hosts: command lines are visible to
    /// every process-creation sensor; prefer `--token-stdin` (the MSI does).
    #[arg(
        long,
        env = "KESTREL_ENROLL_TOKEN",
        hide_env_values = true,
        required_unless_present = "token_stdin"
    )]
    token: Option<String>,
    /// Read the enrollment token from the first line of stdin (M6: never on a
    /// command line; the MSI custom action pipes it in).
    #[arg(long)]
    token_stdin: bool,
    /// TLS name to verify on the server certificate (default: host from --server).
    #[arg(long)]
    server_name: Option<String>,
}

/// First line of stdin, trimmed; an empty line is an error.
fn read_stdin_token() -> Result<String> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading the token from stdin")?;
    let t = line.trim().to_string();
    if t.is_empty() {
        bail!("no token on stdin");
    }
    Ok(t)
}

impl ServerArgs {
    fn install_opts(&self) -> Result<InstallOpts> {
        let token = match (&self.token, self.token_stdin) {
            (_, true) => read_stdin_token()?,
            (Some(t), false) => t.clone(),
            (None, false) => bail!("--token or --token-stdin is required"),
        };
        Ok(InstallOpts {
            server: self.server.clone(),
            ca: self.ca.clone(),
            token,
            server_name: self.server_name.clone(),
            ..Default::default()
        })
    }
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    let state_dir = cli
        .state_dir
        .clone()
        .unwrap_or_else(config::default_state_dir);
    match cli.cmd {
        Cmd::Run { console } => run(state_dir, console),
        Cmd::DesktopHelper { pipe, parent } => desktop_helper(&pipe, parent),
        Cmd::UpdateKeygen { out } => {
            let g = kestrel_agent::update::keygen(&out)?;
            eprintln!(
                "Private key: {} (keep it offline and backed up; anyone holding it can push code to every agent)",
                g.key_file.display()
            );
            eprintln!("Public key file: {}", g.pub_file.display());
            eprintln!("Set KESTREL_UPDATE_PUBKEY to this value when building the agent and on the server:");
            println!("{}", g.public_key);
            Ok(())
        }
        Cmd::UpdateSign {
            key,
            version,
            url,
            file,
        } => {
            let sk = kestrel_agent::update::load_signing_key(&key)?;
            let sha = kestrel_agent::update::sha256_file(&file)?;
            let m = kestrel_agent::update::sign_release(&sk, &version, &url, &sha)?;
            println!("{}", serde_json::to_string_pretty(&m)?);
            Ok(())
        }
        other => {
            let _log = logging::init(None, true);
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            rt.block_on(dispatch(state_dir, other))
        }
    }
}

/// Remote desktop helper (runs in the user's session, spawned by the service).
fn desktop_helper(pipe: &str, parent: u32) -> Result<()> {
    #[cfg(all(windows, feature = "win-platform"))]
    {
        kestrel_win::run_desktop_helper(pipe, parent)
    }
    #[cfg(not(all(windows, feature = "win-platform")))]
    {
        let _ = (pipe, parent);
        bail!("the remote desktop helper is only available in the Windows build of the agent")
    }
}

/// Runtime of the long-running agent (`run`). Tokio defaults to one worker
/// per logical CPU (32 on the owner's PC, 60 agent threads in total); the
/// agent's async work (transport, tray pipe, housekeeping, action
/// dispatch) needs a few. Detection and the sensors run on their own
/// threads. Blocking threads (SQLite, file hashing for actions) are capped
/// and exit after 10 s idle (tokio default).
fn agent_runtime() -> Result<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_multi_thread()
        .worker_threads(kestrel_agent::agent::worker_threads())
        .max_blocking_threads(64)
        .thread_name("kestrel-rt")
        .enable_all()
        .build()?)
}

fn run(state_dir: PathBuf, console: bool) -> Result<()> {
    if cfg!(windows) && !console {
        let sd = state_dir.clone();
        return platform_win::run_service(move |stop| {
            let _log = logging::init(Some(&sd), false);
            let rt = agent_runtime()?;
            rt.block_on(async move {
                let (tx, rx) = tokio::sync::oneshot::channel::<()>();
                std::thread::spawn(move || {
                    let _ = stop.recv();
                    let _ = tx.send(());
                });
                commands::run_real(sd, async move {
                    let _ = rx.await;
                })
                .await
            })
        });
    }
    let _log = logging::init(Some(&state_dir), true);
    let rt = agent_runtime()?;
    rt.block_on(commands::run_real(state_dir, async {
        let _ = tokio::signal::ctrl_c().await;
    }))
}

async fn dispatch(state_dir: PathBuf, cmd: Cmd) -> Result<()> {
    match cmd {
        Cmd::Run { .. }
        | Cmd::UpdateKeygen { .. }
        | Cmd::UpdateSign { .. }
        | Cmd::DesktopHelper { .. } => unreachable!(),
        Cmd::Install {
            server,
            group_tag,
            uninstall_token,
            no_service,
        } => {
            let mut o = server.install_opts()?;
            o.tags = group_tag;
            o.uninstall_token = uninstall_token;
            // H4: never trust a state directory a standard user could have
            // pre-created; re-create it SYSTEM-owned with a protected DACL.
            let check = platform_win::secure_state_dir(&state_dir)?;
            if let Some(moved) = &check.moved_aside {
                eprintln!(
                    "warning: {} was not protected (owner/DACL); moved to {} and re-created",
                    state_dir.display(),
                    moved.display()
                );
            }
            let mut cfg = commands::write_install_config(&state_dir, &o)?;
            println!(
                "Configuration written to {}",
                config::AgentConfig::path(&state_dir).display()
            );
            if commands::keep_existing_enrollment(&state_dir, &mut cfg)? {
                // V-M3: re-install / upgrade of an enrolled device keeps its identity.
                println!(
                    "Already enrolled as device {}; keeping the existing identity",
                    cfg.device_id.map(|d| d.to_string()).unwrap_or_default()
                );
            } else {
                let host = commands::local_hostname();
                match commands::enroll(&state_dir, None, &host, kestrel_platform_os()).await {
                    Ok(id) => println!("Enrolled as device {id}"),
                    Err(e) => eprintln!("warning: enrollment failed now ({e:#}); the service will retry with the saved token"),
                }
            }
            // M5: the token is never printed (custom-action output can reach
            // the MSI log). Server-issued tokens are shown in the console.
            if let Some(p) = commands::ensure_uninstall_token(&state_dir)? {
                println!(
                    "The server did not issue an uninstall token; a local one was written to {} (administrators only)",
                    p.display()
                );
            }
            if !no_service {
                let exe = std::env::current_exe()?;
                platform_win::install_service(&exe).context("installing the service")?;
                println!(
                    "Service {} installed and started",
                    platform_win::SERVICE_NAME
                );
            }
            Ok(())
        }
        Cmd::Enroll { token } => {
            platform_win::secure_state_dir(&state_dir)?;
            let host = commands::local_hostname();
            let id = commands::enroll(&state_dir, token.as_deref(), &host, kestrel_platform_os())
                .await?;
            println!("Enrolled as device {id}. A running agent picks up the new certificate on its next reconnect.");
            Ok(())
        }
        Cmd::Status => {
            let v = commands::status(&state_dir).await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            if v["running"] != serde_json::Value::Bool(true) {
                std::process::exit(3);
            }
            Ok(())
        }
        Cmd::Uninstall {
            token,
            token_stdin,
            purge,
        } => {
            let token = match (token, token_stdin) {
                (_, true) => read_stdin_token()?,
                (Some(t), false) => t,
                (None, false) => bail!("--token or --token-stdin is required"),
            };
            if !config::AgentConfig::path(&state_dir).is_file()
                && !platform_win::service_installed()
            {
                // Nothing left to protect (an earlier uninstall already removed
                // the service and the identity): let the package go.
                println!("Kestrel agent is not installed; nothing to remove");
                return Ok(());
            }
            commands::verify_uninstall(&state_dir, &token)?;
            if cfg!(windows) {
                platform_win::uninstall_service().context("removing the service")?;
                println!("Service {} removed", platform_win::SERVICE_NAME);
                // Only after the service is gone: a running agent would see its
                // own decoys change and raise RW-07 (seen in the lab VM).
                let removed = platform_win::remove_ransomware_canaries(&state_dir);
                if !removed.is_empty() {
                    println!("Removed {} ransomware decoy file(s)", removed.len());
                }
            }
            if purge {
                std::fs::remove_dir_all(&state_dir)
                    .with_context(|| format!("removing {}", state_dir.display()))?;
                println!("Removed {}", state_dir.display());
            } else {
                // A reinstall must enroll afresh (new device, the new token's
                // remote-access ceiling); quarantine and logs are kept.
                let removed = commands::retire_identity(&state_dir);
                if !removed.is_empty() {
                    println!("Device identity removed ({})", removed.join(", "));
                }
            }
            Ok(())
        }
        Cmd::ReleaseIsolation { token } => {
            let d = commands::release_isolation(&state_dir, &token)?;
            println!("{d}");
            Ok(())
        }
        Cmd::Simulate {
            server,
            replay,
            speed,
            hostname,
            exit_after_replay,
            heartbeat_secs,
            sim_consent,
        } => {
            if !(speed > 0.0 && speed.is_finite()) {
                bail!("--speed must be > 0");
            }
            if !replay.is_file() {
                bail!("replay file {} not found", replay.display());
            }
            let mut tuning = Tuning::default();
            if let Some(h) = heartbeat_secs {
                tuning.heartbeat = Duration::from_secs(h.max(1));
            }
            let o = SimulateOpts {
                install: server.install_opts()?,
                replay,
                speed,
                hostname,
                exit_after_replay: exit_after_replay.map(Duration::from_secs),
                consent: sim_consent,
            };
            commands::simulate(&state_dir, o, tuning).await
        }
        Cmd::SensorsTest {
            seconds,
            events_out,
            detect,
        } => {
            let v =
                commands::sensors_test(&state_dir, seconds, events_out.as_deref(), detect, || {
                    eprintln!("KESTREL-SENSORS-READY collecting for {seconds}s");
                })
                .await?;
            println!("{}", serde_json::to_string_pretty(&v)?);
            Ok(())
        }
    }
}

/// OS facts for enrollment before the platform layer is up.
fn kestrel_platform_os() -> kestrel_common::wire::OsInfo {
    kestrel_common::wire::OsInfo {
        name: std::env::consts::OS.to_string(),
        build: String::new(),
        arch: std::env::consts::ARCH.to_string(),
        domain: std::env::var("USERDOMAIN").ok(),
        hw_uuid: None,
    }
}
