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

pub fn scan(state_dir: &Path, targets: &[String]) -> (bool, String) {
    let Some(exe) = scanner_exe() else {
        return (
            false,
            "YARA scanning unavailable: kestrel-scan.exe is not installed next to the agent".into(),
        );
    };
    let list = state_dir.join("scan-targets.txt");
    let body: String = targets
        .iter()
        .take(kestrel_scan::MAX_TARGETS)
        .map(|t| {
            format!(
                "{t}
"
            )
        })
        .collect();
    if let Err(e) = std::fs::write(&list, body) {
        return (false, format!("writing {}: {e}", list.display()));
    }
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
                Ok(r) => (true, r.render()),
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

/// Expand a directory target into files (non-recursive beyond depth 3).
pub fn expand_targets(path: &str) -> Vec<String> {
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
