//! H4: the agent state directory (`C:\ProgramData\Kestrel`) is (re)created
//! securely at install and at every service start.
//!
//! * A reparse point at (or above) the state directory is never trusted.
//! * An existing directory is trusted only when its owner is SYSTEM or
//!   Administrators and its DACL grants no write / delete / ownership rights
//!   to anybody else ([`crate::sddl::state_dir_trusted`]); it then gets the
//!   canonical descriptor again (owner SYSTEM, protected DACL SYSTEM +
//!   Administrators, propagated to inherited ACEs of its children).
//! * Anything else is renamed aside (`<dir>.untrusted-<ms>`) and a fresh,
//!   empty directory is created with [`crate::sddl::STATE_DIR_SDDL`] in one
//!   step (`CreateDirectoryW` with the security descriptor), so nothing in it
//!   — keys, `agent.toml`, outbox, vault, updates — is ever inherited.

use super::safefs::{self, open_raw};
use super::util::*;
use crate::sddl::{state_dir_trusted, STATE_DIR_SDDL};
use anyhow::{anyhow, bail, Context, Result};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, READ_CONTROL,
};

/// Outcome of [`secure_state_dir`].
#[derive(Debug, Clone, Default)]
pub struct StateDirResult {
    /// The untrusted directory was moved here (and a fresh one created).
    pub moved_aside: Option<PathBuf>,
    pub created: bool,
}

fn inspect(path: &str) -> Result<Option<Result<(), String>>> {
    let h = match open_raw(
        path,
        READ_CONTROL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    ) {
        Ok(h) => h,
        Err(e)
            if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND as i32)
                || e.raw_os_error() == Some(ERROR_PATH_NOT_FOUND as i32) =>
        {
            return Ok(None)
        }
        Err(e) => return Err(anyhow!("cannot open {path}: {e}")),
    };
    let (attrs, _) = safefs::attr_tag(&h).ok_or_else(|| anyhow!("cannot query {path}"))?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(Some(Err(
            "the state directory is a reparse point (junction / link)".into(),
        )));
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Ok(Some(
            Err("the state path is a file, not a directory".into()),
        ));
    }
    let sddl =
        sddl_of_handle(h.raw()).ok_or_else(|| anyhow!("cannot read the security of {path}"))?;
    Ok(Some(state_dir_trusted(&sddl)))
}

/// Verify (or re-create) the agent state directory. See the module docs.
pub fn secure_state_dir(dir: &Path) -> Result<StateDirResult> {
    for p in [
        "SeRestorePrivilege",
        "SeTakeOwnershipPrivilege",
        "SeBackupPrivilege",
    ] {
        let _ = enable_privilege(p);
    }
    let path = dir.to_string_lossy().trim_end_matches('\\').to_string();
    if let Some(parent) = dir.parent() {
        let parent = parent.to_string_lossy().to_string();
        safefs::check_ancestors(&format!("{parent}\\x"))
            .map_err(|e| anyhow!("the state directory's parent is not trustworthy: {e}"))?;
    }
    let mut out = StateDirResult::default();
    for _attempt in 0..4 {
        match inspect(&path)? {
            None => {
                match safefs::create_dir_with_sddl(&path, STATE_DIR_SDDL) {
                    Ok(()) => out.created = true,
                    // Raced with someone creating it: inspect again.
                    Err(e) if e.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) => continue,
                    Err(e) => return Err(anyhow!("cannot create {path}: {e}")),
                }
            }
            Some(Ok(())) => {
                // Trusted: (re)assert the canonical descriptor, propagating to
                // inherited ACEs of the children.
                apply_sddl(dir, STATE_DIR_SDDL, true)
                    .with_context(|| format!("securing {path}"))?;
                return Ok(out);
            }
            Some(Err(reason)) => {
                let aside = format!("{path}.untrusted-{}", kestrel_common::now_ms());
                tracing::error!(
                    "state directory {path} is not trustworthy ({reason}); moving it to {aside} and starting fresh"
                );
                let (wf, wt) = (wide(&path), wide(&aside));
                if unsafe { MoveFileExW(wf.as_ptr(), wt.as_ptr(), 0) } == 0 {
                    bail!(
                        "the state directory {path} is not trustworthy ({reason}) and could not be moved aside: {}",
                        last_err()
                    );
                }
                out.moved_aside = Some(PathBuf::from(aside));
            }
        }
    }
    bail!("could not establish a trustworthy state directory at {path}")
}
