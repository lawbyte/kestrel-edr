//! On-demand YARA-X scanning for the `Scan` action.
//!
//! The YARA-X engine lives in the separate `kestrel-scan.exe` (crate
//! `kestrel-scan`) installed next to the agent, so the always-running agent
//! does not carry wasmtime. The agent writes the target list into its
//! SYSTEM-only state directory and runs the scanner with a timeout; custom
//! YARA rules from the `RuleBundle` are in `<state>\rules\`.

use super::util::run_cmd;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A scan of up to 5000 files may take a while; never longer than this.
const SCAN_TIMEOUT: Duration = Duration::from_secs(15 * 60);

pub fn rules_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("rules")
}

/// `kestrel-scan.exe` in the agent's own (Program Files, admin-only) folder.
fn scanner_exe() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let p = exe.parent()?.join("kestrel-scan.exe");
    p.is_file().then_some(p)
}

/// `GetDriveTypeW` value for a network (mapped) drive.
const DRIVE_REMOTE: u32 = 4;

/// Is `path` a network location that must never be opened as SYSTEM
/// (V-M1: UNC / WebDAV / `\Device\Mup` forms, or a drive letter that is a
/// mapped network drive)? Opening it would make the machine account
/// authenticate to the remote host (NTLM coercion).
pub fn is_remote(path: &str) -> bool {
    if kestrel_scan::is_remote_path(path) {
        return true;
    }
    let p = path.trim();
    let b = p.as_bytes();
    let drive = if b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':' {
        Some(b[0] as char)
    } else if let Some(r) = p.strip_prefix(r"\\?\").or_else(|| p.strip_prefix(r"\??\")) {
        let rb = r.as_bytes();
        (rb.len() >= 2 && rb[0].is_ascii_alphabetic() && rb[1] == b':').then(|| rb[0] as char)
    } else {
        None
    };
    match drive {
        Some(d) => {
            let root = super::util::wide(&format!("{d}:\\"));
            // SAFETY: NUL-terminated root path; no file is opened.
            unsafe {
                windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(root.as_ptr())
                    == DRIVE_REMOTE
            }
        }
        None => false,
    }
}

pub fn scan(state_dir: &Path, targets: &[String]) -> (bool, String) {
    let Some(exe) = scanner_exe() else {
        return (
            false,
            "YARA scanning unavailable: kestrel-scan.exe is not installed next to the agent".into(),
        );
    };
    // V-M1: network paths are never handed to the SYSTEM scanner.
    let (local, remote): (Vec<&String>, Vec<&String>) = targets
        .iter()
        .take(kestrel_scan::MAX_TARGETS)
        .partition(|t| !is_remote(t));
    let body: String = local.iter().map(|t| format!("{t}\n")).collect();
    // V-L11: a fresh, unique targets file per run (create_new), so concurrent
    // scans never share or clobber a list.
    let list = match create_targets_file(state_dir, body.as_bytes()) {
        Ok(p) => p,
        Err(e) => return (false, format!("writing the scan target list: {e}")),
    };
    let rules = rules_dir(state_dir);
    let (exe_s, rules_s, list_s) = (
        exe.display().to_string(),
        rules.display().to_string(),
        list.display().to_string(),
    );
    let out = run_cmd(
        &exe_s,
        &["--rules-dir", &rules_s, "--targets-file", &list_s],
        SCAN_TIMEOUT,
    );
    let _ = std::fs::remove_file(&list);
    match out {
        Ok(o) if o.code == 0 => {
            match serde_json::from_str::<kestrel_scan::ScanReport>(o.stdout.trim()) {
                Ok(mut r) => {
                    r.errors.extend(
                        remote.iter().map(|t| {
                            format!("{t}: skipped (network path; never opened as SYSTEM)")
                        }),
                    );
                    (true, r.render())
                }
                Err(e) => (
                    false,
                    format!("kestrel-scan returned unreadable output: {e}"),
                ),
            }
        }
        Ok(o) => (
            false,
            format!("kestrel-scan failed (exit {}): {}", o.code, o.stderr.trim()),
        ),
        Err(e) => (false, format!("running kestrel-scan: {e}")),
    }
}

/// `<state>\scan-targets-<random>.txt`, created with `create_new` (never an
/// existing file or link) in the SYSTEM-only state directory.
fn create_targets_file(state_dir: &Path, body: &[u8]) -> std::io::Result<PathBuf> {
    use std::io::Write;
    for _ in 0..4 {
        let mut rnd = [0u8; 12];
        getrandom::getrandom(&mut rnd).map_err(std::io::Error::other)?;
        let name: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
        let p = state_dir.join(format!("scan-targets-{name}.txt"));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
        {
            Ok(mut f) => {
                if let Err(e) = f.write_all(body).and_then(|_| f.sync_all()) {
                    drop(f);
                    let _ = std::fs::remove_file(&p);
                    return Err(e);
                }
                return Ok(p);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(
        "could not create a unique targets file",
    ))
}

/// Expand a directory target into files (non-recursive beyond depth 3).
/// Network paths (V-M1) expand to nothing: they are never opened as SYSTEM.
pub fn expand_targets(path: &str) -> Vec<String> {
    if is_remote(path) {
        return vec![path.to_string()]; // reported as skipped by `scan`
    }
    let p = Path::new(path);
    if !p.is_dir() {
        return vec![path.to_string()];
    }
    let mut out = Vec::new();
    let mut stack = vec![(p.to_path_buf(), 0)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let ep = e.path();
            // Never descend through junctions / links (they may point at a
            // network location or out of the requested tree).
            if e.file_type().is_ok_and(|t| t.is_symlink()) {
                continue;
            }
            if ep.is_dir() {
                if depth < 3 {
                    stack.push((ep, depth + 1));
                }
            } else if out.len() < 5000 {
                out.push(ep.to_string_lossy().into_owned());
            }
        }
    }
    out
}
