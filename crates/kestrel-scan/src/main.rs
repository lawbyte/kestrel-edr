//! `kestrel-scan --rules-dir <dir> --targets-file <file>`: scan the listed
//! files with the baseline + custom YARA-X rules and print one JSON
//! `ScanReport` on stdout. Started by the agent for the `Scan` action.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

fn main() {
    background_priority();
    match run() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String> {
    let mut rules_dir: Option<PathBuf> = None;
    let mut targets_file: Option<PathBuf> = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--rules-dir") => rules_dir = args.next().map(PathBuf::from),
            Some("--targets-file") => targets_file = args.next().map(PathBuf::from),
            Some("--version") => return Ok(format!("kestrel-scan {}", env!("CARGO_PKG_VERSION"))),
            _ => bail!("usage: kestrel-scan --rules-dir <dir> --targets-file <file>"),
        }
    }
    let (Some(rules_dir), Some(targets_file)) = (rules_dir, targets_file) else {
        bail!("usage: kestrel-scan --rules-dir <dir> --targets-file <file>");
    };
    let targets = kestrel_scan::parse_targets(
        &std::fs::read_to_string(&targets_file)
            .with_context(|| format!("reading {}", targets_file.display()))?,
    );
    let report = kestrel_scan::scan(&rules_dir, &targets)?;
    Ok(serde_json::to_string(&report)?)
}

/// A scan is analyst-requested but never urgent: run the whole process in
/// background mode (lower CPU, I/O and memory priority; Windows never
/// starves it) and EcoQoS so it does not compete with the employee's work
/// or the agent's detection threads. Best effort: a failure only means the
/// scan runs at normal priority. APIs: `SetPriorityClass(GetCurrentProcess(),
/// PROCESS_MODE_BACKGROUND_BEGIN)` and `SetProcessInformation(..,
/// ProcessPowerThrottling, PROCESS_POWER_THROTTLING_STATE { Version: 1,
/// ControlMask: EXECUTION_SPEED, StateMask: EXECUTION_SPEED })` (Microsoft
/// Learn, processthreadsapi.h).
#[cfg(windows)]
fn background_priority() {
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, ProcessPowerThrottling, SetPriorityClass, SetProcessInformation,
        PROCESS_MODE_BACKGROUND_BEGIN, PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        PROCESS_POWER_THROTTLING_EXECUTION_SPEED, PROCESS_POWER_THROTTLING_STATE,
    };
    // SAFETY: pseudo-handle of this process; the state struct outlives the
    // call and its size is passed.
    unsafe {
        let p = GetCurrentProcess();
        let _ = SetPriorityClass(p, PROCESS_MODE_BACKGROUND_BEGIN);
        let state = PROCESS_POWER_THROTTLING_STATE {
            Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask: PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
        };
        let _ = SetProcessInformation(
            p,
            ProcessPowerThrottling,
            &state as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        );
    }
}

#[cfg(not(windows))]
fn background_priority() {}
