//! Process containment: kill (tree), suspend, resume.
//!
//! Safety rules:
//! * The target is opened first and its creation time is read **from the
//!   same handle** and checked against the GUID, so a reused PID is never
//!   touched (no TOCTOU window: the handle pins the process object).
//! * Never the agent itself, PID 0/4, `IsProcessCritical` processes, or the
//!   shared protected list ([`kestrel_detect::protect`]): critical OS
//!   processes / Defender **at their exact location on the system volume
//!   with a valid Microsoft signature** — never by name or folder alone.

use super::snapshot::rows_with_start;
use super::util::*;
use crate::etwparse::filetime_to_ms;
use crate::filters;
use crate::proctrack::descendants;
use kestrel_common::ProcessGuid;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::{
    IsProcessCritical, TerminateProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SUSPEND_RESUME, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
};

/// Exit code used for processes Kestrel terminates.
pub const KILL_EXIT_CODE: u32 = 0xE0DE_0001;

type NtProcFn = unsafe extern "system" fn(HANDLE) -> i32;

fn nt_fn(name: &str) -> Option<NtProcFn> {
    // SAFETY: both NtSuspendProcess and NtResumeProcess take one HANDLE and return NTSTATUS.
    sys_proc("ntdll.dll", name).map(|f| unsafe {
        std::mem::transmute::<unsafe extern "system" fn() -> isize, NtProcFn>(f)
    })
}

pub struct Target {
    pub h: Handle,
    pub pid: u32,
    pub start_ms: i64,
    pub image: String,
}

/// Open and validate a target. `expect` = (boot_id, guid) to verify against.
pub fn open_target(
    pid: u32,
    access: u32,
    expect: Option<(&str, &ProcessGuid)>,
    self_pid: u32,
) -> Result<Target, String> {
    if pid == 0 || pid == 4 {
        return Err(format!("refusing to act on system pid {pid}"));
    }
    if pid == self_pid {
        return Err("refusing to act on the Kestrel agent".into());
    }
    let h = open_process(pid, access | PROCESS_QUERY_LIMITED_INFORMATION)
        .ok_or_else(|| format!("cannot open pid {pid}: {}", last_err()))?;
    let ft =
        process_create_time(&h).ok_or_else(|| format!("cannot read start time of pid {pid}"))?;
    let start_ms = filetime_to_ms(ft);
    if let Some((boot, guid)) = expect {
        let actual = ProcessGuid::derive(boot, pid, start_ms);
        if &actual != guid {
            return Err(format!("pid {pid} now belongs to a different process (GUID mismatch: PID reused); not touched"));
        }
    }
    let image = process_image(&h).unwrap_or_default();
    // H1 / L11: the shared protected list, exact location on the system
    // volume (short names resolved) AND a valid Microsoft signature,
    // verified now on the image file (embedded or catalog).
    let long = if image.contains('\\') {
        super::safefs::long_path(&image)
    } else {
        image.clone()
    };
    if filters::is_protected_target(&long, kestrel_common::system_drive(), |p| {
        super::enrich::verify_signature_ms(p)
    }) {
        return Err(format!(
            "refusing to act on protected system / security process {image} (pid {pid})"
        ));
    }
    let mut crit = 0;
    if unsafe { IsProcessCritical(h.raw(), &mut crit) } != 0 && crit != 0 {
        return Err(format!(
            "refusing to act on critical process {image} (pid {pid})"
        ));
    }
    Ok(Target {
        h,
        pid,
        start_ms,
        image,
    })
}

fn suspend_handle(h: &Handle) -> Result<(), String> {
    let f = nt_fn("NtSuspendProcess").ok_or("NtSuspendProcess unavailable")?;
    let st = unsafe { f(h.raw()) };
    if st >= 0 {
        Ok(())
    } else {
        Err(format!(
            "NtSuspendProcess failed: NTSTATUS 0x{:08X}",
            st as u32
        ))
    }
}

fn resume_handle(h: &Handle) -> Result<(), String> {
    let f = nt_fn("NtResumeProcess").ok_or("NtResumeProcess unavailable")?;
    let st = unsafe { f(h.raw()) };
    if st >= 0 {
        Ok(())
    } else {
        Err(format!(
            "NtResumeProcess failed: NTSTATUS 0x{:08X}",
            st as u32
        ))
    }
}

pub fn suspend(pid: u32, expect: Option<(&str, &ProcessGuid)>, self_pid: u32) -> (bool, String) {
    match open_target(pid, PROCESS_SUSPEND_RESUME, expect, self_pid) {
        Ok(t) => match suspend_handle(&t.h) {
            Ok(()) => (true, format!("suspended {} (pid {pid})", t.image)),
            Err(e) => (false, e),
        },
        Err(e) => (false, e),
    }
}

pub fn resume(pid: u32, expect: Option<(&str, &ProcessGuid)>, self_pid: u32) -> (bool, String) {
    match open_target(pid, PROCESS_SUSPEND_RESUME, expect, self_pid) {
        Ok(t) => match resume_handle(&t.h) {
            Ok(()) => (true, format!("resumed {} (pid {pid})", t.image)),
            Err(e) => (false, e),
        },
        Err(e) => (false, e),
    }
}

fn terminate(t: &Target) -> Result<(), String> {
    if unsafe { TerminateProcess(t.h.raw(), KILL_EXIT_CODE) } == 0 {
        return Err(format!(
            "TerminateProcess({}) failed: {}",
            t.pid,
            last_err()
        ));
    }
    unsafe { WaitForSingleObject(t.h.raw(), 2_000) };
    Ok(())
}

/// Kill a process (and optionally its descendants). Descendants are found
/// from a Toolhelp parent map, accepting only children that started after
/// their parent, and each is re-validated by start time on its own handle.
/// The whole tree is suspended first so nothing can respawn mid-kill.
pub fn kill(
    pid: u32,
    expect: Option<(&str, &ProcessGuid)>,
    tree: bool,
    self_pid: u32,
) -> (bool, String) {
    let access = PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME | PROCESS_SYNCHRONIZE;
    let root = match open_target(pid, access, expect, self_pid) {
        Ok(t) => t,
        Err(e) => return (false, e),
    };
    if !tree {
        return match terminate(&root) {
            Ok(()) => (true, format!("terminated {} (pid {pid})", root.image)),
            Err(e) => (false, e),
        };
    }
    let rows = rows_with_start();
    let desc = descendants(&rows, pid);
    let start_of: std::collections::HashMap<u32, i64> =
        rows.iter().map(|&(p, _, s)| (p, s)).collect();
    let mut targets = Vec::new();
    let mut skipped = Vec::new();
    for d in desc {
        // Re-validate: the handle's start time must equal the snapshot's.
        let snap_start = start_of.get(&d).copied().unwrap_or(-1);
        match open_target(d, access, None, self_pid) {
            Ok(t) if t.start_ms == snap_start && t.start_ms >= root.start_ms => targets.push(t),
            Ok(t) => skipped.push(format!("{} (pid {d}: start time changed)", t.image)),
            Err(e) => skipped.push(e),
        }
    }
    let _ = suspend_handle(&root.h);
    for t in &targets {
        let _ = suspend_handle(&t.h);
    }
    let mut killed = Vec::new();
    let mut failed = Vec::new();
    // Deepest descendants first, root last.
    for t in targets.iter().rev() {
        match terminate(t) {
            Ok(()) => killed.push(format!(
                "{} ({})",
                kestrel_common::file_name_lower(&t.image),
                t.pid
            )),
            Err(e) => failed.push(e),
        }
    }
    let root_ok = terminate(&root);
    let mut detail = match &root_ok {
        Ok(()) => format!("terminated {} (pid {pid})", root.image),
        Err(e) => format!("root kill failed: {e}"),
    };
    if !killed.is_empty() {
        detail.push_str(&format!("; descendants killed: {}", killed.join(", ")));
    }
    if !failed.is_empty() {
        detail.push_str(&format!("; failures: {}", failed.join("; ")));
    }
    if !skipped.is_empty() {
        detail.push_str(&format!("; skipped: {}", skipped.join("; ")));
    }
    (root_ok.is_ok() && failed.is_empty(), detail)
}
