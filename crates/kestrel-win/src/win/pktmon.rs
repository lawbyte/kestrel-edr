//! Packet capture of an evidence tree's connections with the in-box
//! `PktMon.exe` (Windows 10 2004 / build 19041 and later). Follows the
//! Decision section of `docs/research/notes/evidence-pcap.md`; every command
//! line comes from [`crate::evidence_plan::pktmon`] (parsed `IpAddr` / `u16`
//! / protocol enum only, fixed filter names, paths only from the work
//! directory the agent passed in).
//!
//! * The binary is `<GetSystemWindowsDirectoryW>\System32\PktMon.exe`
//!   (never PATH, never the environment), Microsoft-signed, started with
//!   explicit arguments (no shell), no window, output captured, each call
//!   killed after a timeout ([`super::util::run_cmd`], which also records
//!   the child as the agent's own).
//! * Packet Monitor is a machine-wide singleton: any running session or any
//!   filter that is not Kestrel's makes the capture `Busy`; Kestrel never
//!   takes over, never runs `pktmon unload`.
//! * A marker (`pktmon-active.json`) in the work root (the parent of the
//!   capture's work folder) is written before `start`; `cleanup_stale`
//!   stops a capture only when the marker exists and the running session's
//!   log file is inside the work root.
//! * Filters are fixed before `start`: adding filters to a running capture
//!   is not verified to work, so `add_filters` adds none (lab check).

use super::util::*;
use crate::evidence_plan::os_build;
use crate::evidence_plan::pktmon::{self as plan, CleanupPlan, Marker, Paths, StartCheck};
use kestrel_common::evidence::PcapFilter;
use kestrel_platform::{CaptureSession, CaptureStartError, CapturedFile, PacketCapture};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(30);
/// Conversion of up to 50 MB of ETL.
const CONVERT_TIMEOUT: Duration = Duration::from_secs(120);

pub struct PktMon {
    exe: String,
    /// One Kestrel capture at a time per host.
    active: Arc<AtomicBool>,
}

impl PktMon {
    /// `PktMon.exe` in System32, OS build ≥ 19041 and a valid Microsoft
    /// signature; `None` otherwise (packet capture unsupported).
    pub fn detect() -> Option<PktMon> {
        let build = os_build(&super::host::os_info().build).unwrap_or(0);
        if build < plan::MIN_BUILD {
            tracing::info!(
                build,
                "packet capture: PktMon needs Windows build 19041 or later"
            );
            return None;
        }
        let exe = format!(r"{}\System32\PktMon.exe", system_root());
        if !Path::new(&exe).is_file() {
            tracing::info!("packet capture: {exe} not found");
            return None;
        }
        let v = super::enrich::verify_ex(&exe, super::enrich::RevMode::None);
        if v.state != kestrel_common::SignatureState::Valid || !v.microsoft_root {
            tracing::warn!(state = ?v.state, "packet capture: {exe} is not Microsoft-signed; not used");
            return None;
        }
        Some(PktMon {
            exe,
            active: Arc::new(AtomicBool::new(false)),
        })
    }

    fn run(&self, args: &[String], timeout: Duration) -> Result<CmdOutput, String> {
        let a: Vec<&str> = args.iter().map(String::as_str).collect();
        run_cmd(&self.exe, &a, timeout).map_err(|e| format!("pktmon {}: {e}", args.join(" ")))
    }

    /// Run and require exit code 0.
    fn run_ok(&self, args: &[String], timeout: Duration) -> Result<CmdOutput, String> {
        let o = self.run(args, timeout)?;
        if o.code != 0 {
            return Err(format!(
                "pktmon {} failed (exit {}): {}",
                args.first().map(String::as_str).unwrap_or(""),
                o.code,
                short(&o)
            ));
        }
        Ok(o)
    }

    fn status(&self) -> Result<plan::Status, String> {
        let o = self.run(&plan::status_args(), CMD_TIMEOUT)?;
        if o.stdout.trim().is_empty() && o.stderr.trim().is_empty() {
            return Err(format!("pktmon status gave no output (exit {})", o.code));
        }
        Ok(plan::parse_status(&o.stdout))
    }

    fn filters(&self) -> Result<plan::FilterList, String> {
        let o = self.run(&plan::filter_list_args(), CMD_TIMEOUT)?;
        Ok(plan::parse_filter_list(&o.stdout))
    }

    fn remove_filters(&self) {
        if let Err(e) = self.run_ok(&plan::filter_remove_args(), CMD_TIMEOUT) {
            tracing::warn!("{e}");
        }
    }

    fn stop_capture(&self) {
        if let Err(e) = self.run_ok(&plan::stop_args(), CMD_TIMEOUT) {
            tracing::warn!("{e}");
        }
    }

    /// Filters are removed only while every configured filter is ours:
    /// `filter list` is run immediately before `filter remove` (the only
    /// documented removal is all-or-nothing). Residual race: an
    /// administrator who adds a filter in the gap between the two process
    /// launches (milliseconds) loses it; pktmon offers no atomic
    /// "remove these names" (research notes, section 1).
    fn remove_filters_if_ours(&self) {
        match self.filters() {
            Ok(l) if l.foreign == 0 && !l.ours.is_empty() => self.remove_filters(),
            Ok(l) if l.foreign > 0 => tracing::warn!(
                foreign = l.foreign,
                "packet capture: filters of someone else are configured; Kestrel's are left in place"
            ),
            Ok(_) => {}
            Err(e) => tracing::warn!("{e}"),
        }
    }

    fn start_inner(
        &self,
        filters: &[PcapFilter],
        work_dir: &Path,
        max_bytes: u64,
    ) -> Result<PktSession, CaptureStartError> {
        let paths = plan::paths(&work_dir.to_string_lossy()).map_err(CaptureStartError::Failed)?;
        let (planned, dropped) = plan::plan_filters(filters);
        if planned.is_empty() {
            return Err(CaptureStartError::Failed(
                "no eligible remote address to capture".into(),
            ));
        }
        if dropped > 0 {
            tracing::debug!(dropped, "packet capture: filters dropped");
        }
        let status = self.status().map_err(CaptureStartError::Failed)?;
        let list = self.filters().map_err(CaptureStartError::Failed)?;
        match plan::assess_start(&status, &list) {
            StartCheck::Busy(why) => return Err(CaptureStartError::Busy(why)),
            StartCheck::Go { remove_ours: true } => self.remove_filters(),
            StartCheck::Go { remove_ours: false } => {}
        }
        for f in &planned {
            if let Err(e) = self.run_ok(&f.args, CMD_TIMEOUT) {
                self.remove_filters_if_ours();
                return Err(CaptureStartError::Failed(e));
            }
        }
        // Someone may have added filters meanwhile: never start then.
        match self.filters() {
            Ok(l) if l.foreign > 0 => {
                return Err(CaptureStartError::Busy(
                    "Packet Monitor filters of someone else appeared".into(),
                ))
            }
            Ok(l) if l.ours.len() < planned.len() => {
                self.remove_filters_if_ours();
                return Err(CaptureStartError::Failed(format!(
                    "pktmon lists {} of {} filters",
                    l.ours.len(),
                    planned.len()
                )));
            }
            Ok(_) => {}
            Err(e) => {
                self.remove_filters_if_ours();
                return Err(CaptureStartError::Failed(e));
            }
        }
        let marker = Marker {
            etl: paths.etl.clone(),
            work_dir: paths.work_dir.clone(),
            started_at: kestrel_common::now_ms(),
            filters: planned.iter().map(|f| f.args.join(" ")).collect(),
        };
        let mb = plan::file_size_mb(max_bytes);
        let write = serde_json::to_vec_pretty(&marker)
            .map_err(std::io::Error::other)
            .and_then(|b| write_atomic(Path::new(&paths.marker), &b));
        if let Err(e) = write {
            self.remove_filters_if_ours();
            return Err(CaptureStartError::Failed(format!("marker: {e}")));
        }
        if let Err(e) = self.run_ok(&plan::start_args(&paths.etl, mb), CMD_TIMEOUT) {
            // A session may have started anyway: stop it only if it is ours.
            self.cleanup_paths(&paths);
            return Err(CaptureStartError::Failed(e));
        }
        // Confirm the running session is ours.
        match self.status() {
            Ok(s)
                if s.running
                    && s.log_file
                        .as_deref()
                        .is_some_and(|f| plan::path_inside(f, &paths.work_dir)) => {}
            Ok(s) => {
                tracing::warn!(
                    ?s,
                    "packet capture: pktmon status does not show Kestrel's capture"
                );
                self.cleanup_paths(&paths);
                return Err(CaptureStartError::Failed(
                    "pktmon did not report Kestrel's capture as running".into(),
                ));
            }
            Err(e) => {
                self.cleanup_paths(&paths);
                return Err(CaptureStartError::Failed(e));
            }
        }
        Ok(PktSession {
            exe: PktMon {
                exe: self.exe.clone(),
                active: self.active.clone(),
            },
            paths,
            file_size_mb: mb,
            max_bytes,
            done: false,
        })
    }

    /// Stop / remove filters per [`plan::assess_cleanup`] for the marker in
    /// `work_root`, then delete the marker.
    fn cleanup_root(&self, work_root: &str) {
        let marker = format!(
            r"{}\{}",
            work_root.trim_end_matches('\\'),
            plan::MARKER_FILE
        );
        let exists = Path::new(&marker).is_file();
        if !exists {
            return;
        }
        let status = match self.status() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("packet capture cleanup: {e}");
                return;
            }
        };
        let list = self.filters().unwrap_or_default();
        let CleanupPlan {
            stop,
            remove_filters,
        } = plan::assess_cleanup(true, &status, &list, work_root);
        if stop {
            tracing::info!("packet capture: stopping a capture an earlier agent left running");
            self.stop_capture();
        }
        if remove_filters || stop {
            // After our stop the filters are re-checked (never someone else's).
            self.remove_filters_if_ours();
        }
        let _ = std::fs::remove_file(&marker);
    }

    fn cleanup_paths(&self, p: &Paths) {
        self.cleanup_root(&p.work_root);
    }
}

/// First line of the output, bounded (never more than a short message).
fn short(o: &CmdOutput) -> String {
    let t = if o.stdout.trim().is_empty() {
        &o.stderr
    } else {
        &o.stdout
    };
    let line = t
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    line.chars().take(200).collect()
}

impl PacketCapture for PktMon {
    fn start(
        &self,
        filters: &[PcapFilter],
        work_dir: &Path,
        max_bytes: u64,
    ) -> Result<Box<dyn CaptureSession>, CaptureStartError> {
        if self
            .active
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(CaptureStartError::Busy(
                "a Kestrel packet capture is already running".into(),
            ));
        }
        match self.start_inner(filters, work_dir, max_bytes) {
            Ok(s) => Ok(Box::new(s)),
            Err(e) => {
                self.active.store(false, Ordering::SeqCst);
                Err(e)
            }
        }
    }

    fn cleanup_stale(&self, work_root: &Path) {
        match plan::validate_dir(&work_root.to_string_lossy()) {
            Ok(root) => self.cleanup_root(&root),
            Err(e) => tracing::warn!("packet capture cleanup: {e}"),
        }
    }

    fn mechanism(&self) -> &'static str {
        "pktmon"
    }
}

struct PktSession {
    exe: PktMon,
    paths: Paths,
    file_size_mb: u64,
    max_bytes: u64,
    done: bool,
}

impl PktSession {
    /// `stop` + filter removal, only while the running session is ours.
    fn halt(&mut self) -> plan::HaltPlan {
        if self.done {
            return plan::assess_halt(None, "");
        }
        self.done = true;
        let status = self.exe.status();
        if let Err(e) = &status {
            tracing::warn!("packet capture: {e}");
        }
        let h = plan::assess_halt(status.ok().as_ref(), &self.paths.work_dir);
        if h.stop {
            self.exe.stop_capture();
        } else {
            tracing::warn!(
                "packet capture: the pktmon session is unknown or not Kestrel's; not stopped"
            );
        }
        if h.remove_filters {
            self.exe.remove_filters_if_ours();
        }
        if !h.keep_marker {
            let _ = std::fs::remove_file(&self.paths.marker);
        }
        self.exe.active.store(false, Ordering::SeqCst);
        h
    }

    fn remove_etl(&self) {
        let _ = std::fs::remove_file(&self.paths.etl);
        // The live file of a running capture (`capture_1.etl`).
        let live = self.paths.etl.trim_end_matches(".etl").to_string() + "_1.etl";
        let _ = std::fs::remove_file(live);
    }
}

impl CaptureSession for PktSession {
    fn stop(mut self: Box<Self>) -> Result<CapturedFile, String> {
        if !self.halt().convert {
            // Left for `cleanup_stale` (marker kept); files untouched.
            return Err("pktmon state unknown or not Kestrel's; capture not stopped".into());
        }
        let etl_bytes = std::fs::metadata(&self.paths.etl).map(|m| m.len());
        let etl_bytes = match etl_bytes {
            Ok(n) => n,
            Err(e) => {
                self.remove_etl();
                return Err(format!("no capture file: {e}"));
            }
        };
        let conv = self.exe.run_ok(
            &plan::etl2pcap_args(&self.paths.etl, &self.paths.pcapng),
            CONVERT_TIMEOUT,
        );
        self.remove_etl();
        conv?;
        let bytes = std::fs::metadata(&self.paths.pcapng)
            .map(|m| m.len())
            .map_err(|e| format!("no pcapng after conversion: {e}"))?;
        // The circular cap is approximate and pcapng framing differs from
        // ETL: past the cap plus the slack the capture is discarded.
        if !plan::pcapng_size_ok(bytes, self.max_bytes) {
            let _ = std::fs::remove_file(&self.paths.pcapng);
            return Err(format!("pcapng of {bytes} bytes is over the cap"));
        }
        Ok(CapturedFile {
            path: self.paths.pcapng.clone().into(),
            bytes,
            truncated: plan::etl_reached_cap(etl_bytes, self.file_size_mb),
        })
    }
}

impl Drop for PktSession {
    fn drop(&mut self) {
        // Dropped without `stop` (agent error path): never leave the capture
        // running. No conversion.
        if !self.done && self.halt().convert {
            self.remove_etl();
        }
    }
}
