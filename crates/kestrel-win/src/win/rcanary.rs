//! Ransomware decoys on Windows: planting (only when the agent runs as
//! LocalSystem — never from an interactive `sensors-test`), the NT-path set
//! the Kernel-File aggregator matches, and a 2 s poller that catches
//! in-place encryption of a decoy (open + write without rename / overwrite
//! disposition, which Kernel-File Create/Rename/Delete cannot see without
//! the very high-volume Write keyword).

use super::etw::{FileState, Raw, Sink};
use super::util::*;
use crate::canary::CanaryRegistry;
use crate::ntpath::DeviceMap;
use crate::rcanary;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

/// Is this process running as LocalSystem (the installed service)?
pub fn running_as_system() -> bool {
    open_process(std::process::id(), PROCESS_QUERY_LIMITED_INFORMATION)
        .map(|h| process_token_info(&h).0.as_deref() == Some("S-1-5-18"))
        .unwrap_or(false)
}

/// Plant decoys for every profile (SYSTEM only). Returns the decoy paths
/// (Win32) now in place, including ones planted earlier.
pub fn plant(state_dir: &Path, profiles: &[String]) -> Vec<String> {
    let mut reg: CanaryRegistry = rcanary::load_registry(state_dir);
    let ok = rcanary::plant(profiles, &mut reg);
    if let Err(e) = rcanary::save_registry(state_dir, &reg) {
        tracing::warn!("saving ransomware canary registry: {e}");
    }
    ok
}

/// Decoys already planted (from the registry), without planting.
pub fn planted(state_dir: &Path) -> Vec<String> {
    rcanary::load_registry(state_dir)
        .planted
        .values()
        .map(|r| r.path.clone())
        .collect()
}

fn stamp(p: &Path) -> Option<(u64, SystemTime)> {
    let m = std::fs::symlink_metadata(p).ok()?;
    Some((m.len(), m.modified().ok()?))
}

/// Start the in-place-modification poller.
pub fn start_poller(
    paths: Vec<String>,
    devmap: Arc<RwLock<DeviceMap>>,
    file_state: Arc<Mutex<FileState>>,
    sink: Sink,
    stop: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("kestrel-rcanary".into())
        .spawn(move || {
            let mut base: HashMap<PathBuf, Option<(u64, SystemTime)>> = paths
                .iter()
                .map(|p| (PathBuf::from(p), stamp(Path::new(p))))
                .collect();
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(2));
                for (p, old) in base.iter_mut() {
                    let now_stamp = stamp(p);
                    if now_stamp == *old {
                        continue;
                    }
                    let was_there = old.is_some();
                    *old = now_stamp;
                    if !was_there {
                        continue; // (re)appeared: not a hit
                    }
                    let win32 = p.to_string_lossy().into_owned();
                    let nt = devmap
                        .read()
                        .ok()
                        .and_then(|m| m.to_nt_lower(&win32))
                        .unwrap_or_else(|| win32.to_ascii_lowercase());
                    let ts = kestrel_common::now_ms();
                    let emit = file_state.lock().ok().map(|mut fs| {
                        let pid = fs.last_opener(&nt, ts).unwrap_or(0);
                        fs.agg.canary_modified(ts, pid, &nt)
                    });
                    if let Some(e) = emit {
                        sink.send(Raw::FileActivity {
                            ts: e.ts,
                            pid: e.pid,
                            act: e.activity,
                        });
                    }
                }
            }
        })
}
