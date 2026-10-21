//! Remote removal ("Remove device"): start `kestrel-uninstall.exe --quiet
//! --token-stdin [--purge]` detached from the agent service.
//!
//! * The installed tool (next to `kestrel-agent.exe`, in the admin-only
//!   install folder) is copied into a new folder
//!   `%SystemRoot%\SystemTemp\kestrel-remote-uninstall-<uuid>` (or `Temp`
//!   on older Windows) created atomically with a protected
//!   SYSTEM / Administrators-only DACL, so no standard user can swap the
//!   executable or plant a link between the copy and the start. The copy
//!   runs from there because Windows Installer removes the install folder
//!   (a running image there would force a restart).
//! * Started as SYSTEM (the service's own token) with `DETACHED_PROCESS`,
//!   `CREATE_NO_WINDOW`, `CREATE_NEW_PROCESS_GROUP` and
//!   `CREATE_BREAKAWAY_FROM_JOB` (retried without it when the agent's job
//!   does not allow breakaway), so the helper outlives the service stop.
//! * The token goes to the helper's stdin pipe and nowhere else (no command
//!   line, no environment, no file).

use super::util::{sd_from_sddl, wide_path};
use kestrel_platform::UninstallHelper;
use std::io::Write;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

const DETACHED_PROCESS: u32 = 0x0000_0008;
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
/// Owner SYSTEM; SYSTEM + Administrators full control, protected.
const PRIVATE_DIR_SDDL: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
pub const HELPER_EXE: &str = "kestrel-uninstall.exe";
pub const HELPER_DIR_PREFIX: &str = "kestrel-remote-uninstall-";

struct Helper(std::process::Child);

impl UninstallHelper for Helper {
    fn try_exit_code(&mut self) -> Option<i32> {
        match self.0.try_wait() {
            Ok(Some(st)) => Some(st.code().unwrap_or(2)),
            Ok(None) => None,
            Err(_) => Some(2),
        }
    }
}

/// The installed `kestrel-uninstall.exe` (next to the running agent).
fn installed_helper() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("agent path unknown: {e}"))?;
    let dir = exe
        .parent()
        .ok_or_else(|| "agent folder unknown".to_string())?;
    let h = dir.join(HELPER_EXE);
    if !h.is_file() {
        return Err(format!(
            "{} not found next to the agent ({}); this agent was not installed from the MSI",
            HELPER_EXE,
            dir.display()
        ));
    }
    Ok(h)
}

/// Create `path` (must not exist) with the private DACL in one call.
fn create_private_dir(path: &Path) -> Result<(), String> {
    let sd = sd_from_sddl(PRIVATE_DIR_SDDL).ok_or("security descriptor")?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let w = wide_path(path);
    // SAFETY: valid NUL-terminated path and security attributes. Fails if
    // anything (including a planted link) already has this name.
    if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
        return Err(format!(
            "creating {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn temp_root() -> PathBuf {
    let win = crate::windows_dir();
    let sys_temp = win.join("SystemTemp");
    if sys_temp.is_dir() {
        sys_temp
    } else {
        win.join("Temp")
    }
}

pub fn start(token: &str, purge_data: bool) -> Result<Box<dyn UninstallHelper>, String> {
    let src = installed_helper()?;
    let dir = temp_root().join(format!(
        "{HELPER_DIR_PREFIX}{}",
        uuid::Uuid::new_v4().simple()
    ));
    create_private_dir(&dir)?;
    let exe = dir.join(HELPER_EXE);
    std::fs::copy(&src, &exe).map_err(|e| format!("copying the uninstall helper: {e}"))?;
    let mut args = vec!["--quiet", "--token-stdin"];
    if purge_data {
        args.push("--purge");
    }
    let spawn = |flags: u32| {
        std::process::Command::new(&exe)
            .args(&args)
            .current_dir(&dir)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .creation_flags(flags)
            .spawn()
    };
    let base = DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
    let mut child = match spawn(base | CREATE_BREAKAWAY_FROM_JOB) {
        Ok(c) => c,
        // ERROR_ACCESS_DENIED: in a job that does not allow breakaway.
        Err(e) if e.raw_os_error() == Some(5) => {
            spawn(base).map_err(|e| format!("starting the uninstall helper: {e}"))?
        }
        Err(e) => return Err(format!("starting the uninstall helper: {e}")),
    };
    crate::spawnreg::record_child(&child);
    let mut line = Vec::with_capacity(token.len() + 2);
    line.extend_from_slice(token.as_bytes());
    line.extend_from_slice(b"\r\n");
    let written = match child.stdin.take() {
        Some(mut stdin) => {
            let r = stdin.write_all(&line).and_then(|_| stdin.flush());
            drop(stdin);
            r
        }
        None => Err(std::io::Error::other("no stdin pipe")),
    };
    for b in line.iter_mut() {
        // SAFETY: valid, exclusive reference (best-effort wipe).
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    if let Err(e) = written {
        let _ = child.kill();
        return Err(format!("handing the token to the uninstall helper: {e}"));
    }
    tracing::info!(helper = %exe.display(), pid = child.id(), purge_data, "uninstall helper started");
    Ok(Box::new(Helper(child)))
}
