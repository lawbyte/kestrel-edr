//! Thin shim over `kestrel-win` so the agent core compiles (and cross-checks)
//! while the Windows platform crate is being built in parallel.
//!
//! ASSUMED `kestrel-win` API (coordinate if it differs):
//! ```ignore
//! impl WindowsPlatform {
//!     pub fn new(state_dir: PathBuf, server_ips: Vec<String>) -> anyhow::Result<WindowsPlatform>;
//! }
//! impl kestrel_platform::Platform for WindowsPlatform { … }
//! /// Run under the SCM. Blocks until the service stops. `body` runs on the
//! /// service thread after SERVICE_RUNNING is reported and must return when
//! /// `stop` yields (SCM Stop/Shutdown).
//! pub fn run_service<F>(body: F) -> anyhow::Result<()>
//! where F: FnOnce(std::sync::mpsc::Receiver<()>) -> anyhow::Result<()> + Send + 'static;
//! /// Register `KestrelAgent` (auto start, LocalSystem, recovery actions) running
//! /// `"<exe>" service` (kestrel_win::SERVICE_ARG; the CLI accepts it as an alias of `run`).
//! pub fn install_service(exe_path: &std::path::Path) -> anyhow::Result<()>;
//! /// Stop and delete the service.
//! pub fn uninstall_service() -> anyhow::Result<()>;
//! ```
//!
//! With the `win-platform` feature off, Windows builds fall back to `sc.exe`
//! for service registration and cannot run the real agent.

#![allow(dead_code)]

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub const SERVICE_NAME: &str = "KestrelAgent";

/// Result of [`secure_state_dir`].
#[derive(Debug, Clone, Default)]
pub struct StateDirCheck {
    /// The directory was untrustworthy and has been renamed to this path; a
    /// fresh, empty, SYSTEM-owned directory replaced it.
    pub moved_aside: Option<PathBuf>,
    /// The directory did not exist and was created.
    pub created: bool,
}

#[cfg(all(windows, feature = "win-platform"))]
mod imp {
    use super::*;

    pub fn platform(
        state_dir: PathBuf,
        server_ips: Vec<String>,
    ) -> Result<Arc<dyn kestrel_platform::Platform>> {
        let p = kestrel_win::WindowsPlatform::new(state_dir, server_ips)?;
        Ok(Arc::new(p))
    }

    pub fn run_service<F>(body: F) -> Result<()>
    where
        F: FnOnce(std::sync::mpsc::Receiver<()>) -> Result<()> + Send + 'static,
    {
        kestrel_win::run_service(body)
    }

    pub fn install_service(exe: &Path) -> Result<()> {
        kestrel_win::install_service(exe)
    }

    pub fn uninstall_service() -> Result<()> {
        kestrel_win::uninstall_service()
    }

    pub fn secure_state_dir(dir: &Path) -> Result<StateDirCheck> {
        let r = kestrel_win::secure_state_dir(dir)?;
        Ok(StateDirCheck {
            moved_aside: r.moved_aside,
            created: r.created,
        })
    }

    pub fn release_isolation_offline(state_dir: &Path) -> Result<String> {
        kestrel_win::release_isolation_offline(state_dir)
    }
}

#[cfg(all(windows, not(feature = "win-platform")))]
mod imp {
    use super::*;
    use anyhow::{bail, Context};

    pub fn platform(
        _state_dir: PathBuf,
        _server_ips: Vec<String>,
    ) -> Result<Arc<dyn kestrel_platform::Platform>> {
        bail!("this build has no Windows platform layer (built without the `win-platform` feature)")
    }

    pub fn run_service<F>(_body: F) -> Result<()>
    where
        F: FnOnce(std::sync::mpsc::Receiver<()>) -> Result<()> + Send + 'static,
    {
        bail!("service mode requires the `win-platform` feature; use `run --console`")
    }

    fn sc(args: &[&str]) -> Result<()> {
        let st = std::process::Command::new("sc.exe")
            .args(args)
            .status()
            .context("running sc.exe")?;
        if !st.success() {
            bail!("sc.exe {:?} failed with {st}", args);
        }
        Ok(())
    }

    pub fn install_service(exe: &Path) -> Result<()> {
        let bin = format!("\"{}\" service", exe.display());
        sc(&[
            "create",
            SERVICE_NAME,
            "binPath=",
            &bin,
            "start=",
            "auto",
            "DisplayName=",
            "Kestrel EDR Agent",
        ])?;
        sc(&[
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/5000/restart/30000",
        ])?;
        sc(&["start", SERVICE_NAME])
    }

    pub fn uninstall_service() -> Result<()> {
        let _ = sc(&["stop", SERVICE_NAME]);
        sc(&["delete", SERVICE_NAME])
    }

    pub fn secure_state_dir(dir: &Path) -> Result<StateDirCheck> {
        let created = !dir.exists();
        std::fs::create_dir_all(dir)?;
        Ok(StateDirCheck {
            moved_aside: None,
            created,
        })
    }

    pub fn release_isolation_offline(_state_dir: &Path) -> Result<String> {
        bail!("release-isolation requires the `win-platform` feature")
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use anyhow::bail;

    pub fn platform(
        _state_dir: PathBuf,
        _server_ips: Vec<String>,
    ) -> Result<Arc<dyn kestrel_platform::Platform>> {
        bail!("the real platform layer is Windows-only; use `kestrel-agent simulate` on this OS")
    }

    pub fn run_service<F>(_body: F) -> Result<()>
    where
        F: FnOnce(std::sync::mpsc::Receiver<()>) -> Result<()> + Send + 'static,
    {
        bail!("service mode is Windows-only")
    }

    pub fn install_service(_exe: &Path) -> Result<()> {
        bail!("service installation is Windows-only")
    }

    pub fn uninstall_service() -> Result<()> {
        bail!("service removal is Windows-only")
    }

    /// Non-Windows (simulator / tests): plain directory, 0700 on Unix.
    pub fn secure_state_dir(dir: &Path) -> Result<StateDirCheck> {
        let created = !dir.exists();
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(StateDirCheck {
            moved_aside: None,
            created,
        })
    }

    pub fn release_isolation_offline(_state_dir: &Path) -> Result<String> {
        bail!("release-isolation is Windows-only (the simulator isolates in memory)")
    }
}

pub use imp::*;
