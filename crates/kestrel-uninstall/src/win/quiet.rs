//! Quiet mode (`--quiet --token-stdin [--purge]`): remote removal started by
//! the agent ("Remove device" in the console). No window, no message box.
//!
//! The agent copies this executable into a private SYSTEM / Administrators
//! folder under the Windows temp directory, starts it as SYSTEM outside its
//! job object (so it survives the service stop) and writes the already
//! verified token to its stdin. The removal is the same as the dialog's
//! ([`super::gui::work`]): `MsiConfigureProductExW` with `UNINSTALL_TOKEN`,
//! then the optional link-safe purge of `%ProgramData%\Kestrel`.
//!
//! On failure the result goes to `%ProgramData%\Kestrel\
//! remote-uninstall-result.json` ([`crate::result_json`]); the agent (still
//! running, or restarted by the installer's rollback) reports it to the
//! console. Either way this copy and its folder are deleted at the next
//! restart (a running image cannot delete itself).

use super::{gui, system, wide};
use crate::{
    exit_code, outcome_kind, quiet_message, read_token_line, result_json, Outcome, TokenError,
};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

/// Name of the result file in the agent state directory (same as
/// `kestrel_platform::UNINSTALL_RESULT_FILE`).
pub const RESULT_FILE: &str = "remote-uninstall-result.json";
/// Prefix of the private folder the agent copies this executable into.
pub const HELPER_DIR_PREFIX: &str = "kestrel-remote-uninstall-";

pub fn main(purge: bool) -> i32 {
    let state_dir = system::state_dir();
    let token = match read_token_line(std::io::stdin().lock()) {
        Ok(t) => t,
        Err(e) => {
            let msg = match e {
                TokenError::Empty => "no uninstall token on the helper's input",
                TokenError::TooLong | TokenError::BadCharacter => {
                    "the uninstall token handed to the helper is malformed"
                }
            };
            write_result(state_dir.as_deref(), 2, "bad_token", None, msg, None);
            delete_self_on_reboot();
            return 2;
        }
    };
    let r = gui::work(token, purge, state_dir.clone());
    let code = exit_code(Some(&r.outcome));
    if !matches!(r.outcome, Outcome::Removed { .. }) {
        let msi = match r.outcome {
            Outcome::WrongToken => Some(crate::rc::INSTALL_FAILURE),
            Outcome::NotInstalled => Some(crate::rc::UNKNOWN_PRODUCT),
            Outcome::Failed { code } => Some(code),
            _ => None,
        };
        let log = r.log.as_ref().map(|l| l.display().to_string());
        write_result(
            state_dir.as_deref(),
            code,
            outcome_kind(&r.outcome),
            msi,
            &quiet_message(&r.outcome),
            log.as_deref(),
        );
    }
    drop(r);
    delete_self_on_reboot();
    code
}

/// Write the result into the (SYSTEM / Administrators only) state folder,
/// through a temporary file renamed over the final name.
fn write_result(
    state_dir: Option<&Path>,
    exit: i32,
    kind: &str,
    msi: Option<u32>,
    message: &str,
    log: Option<&str>,
) {
    let Some(dir) = state_dir.filter(|d| d.is_dir()) else {
        return;
    };
    let body = result_json(exit, kind, msi, message, log);
    let tmp = dir.join(format!("{RESULT_FILE}.tmp"));
    if std::fs::write(&tmp, body.as_bytes()).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join(RESULT_FILE));
    }
}

/// Schedule this copy (and its private folder, when it is the agent's
/// `kestrel-remote-uninstall-*` folder) for deletion at the next restart.
fn delete_self_on_reboot() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let dir: Option<PathBuf> = exe
        .parent()
        .filter(|d| {
            d.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.to_ascii_lowercase().starts_with(HELPER_DIR_PREFIX))
        })
        .map(Path::to_path_buf);
    // Only the private copy deletes itself; the installed tool is the
    // package's to remove.
    let Some(dir) = dir else {
        return;
    };
    for p in [exe.as_path(), dir.as_path()] {
        let w = wide(&p.to_string_lossy());
        // SAFETY: valid NUL-terminated string; NULL destination = delete.
        unsafe { MoveFileExW(w.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
    }
}
