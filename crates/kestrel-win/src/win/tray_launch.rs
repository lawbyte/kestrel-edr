//! Start the employee tray app in signed-in user sessions when the service
//! starts. The MSI registers the tray in the HKLM Run key, which only fires
//! at the next logon, and an upgrade closes the running tray: without this
//! the tray stays missing until the user signs out and in again.
//!
//! Sequence (Win32 docs): `WTSEnumerateSessionsW` → sessions in `WTSActive`
//! → skip sessions that already run `kestrel-tray.exe` (Toolhelp snapshot +
//! `ProcessIdToSessionId`) → `WTSQueryUserToken` (needs SeTcbPrivilege:
//! LocalSystem; returns the user's filtered token, so the tray never runs
//! elevated) → `CreateEnvironmentBlock` (the user's environment) →
//! `CreateProcessAsUserW(lpDesktop = "winsta0\default")`. No job object:
//! the tray outlives agent restarts. The tray's single-instance guard covers
//! the race with the Run key at logon (a `--background` second start does
//! not open the window).
//!
//! The tray is deliberately **not** recorded as the agent's own child
//! (`spawnreg`): agent children are exempt from detection for their
//! lifetime, and the tray is a long-lived process under the user's token
//! that any program of that user can open and inject into (review
//! 2026-10-25). It is watched like the tray the Run key starts.

use super::util::*;
use std::ffi::c_void;
use std::path::Path;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::RemoteDesktop::{
    ProcessIdToSessionId, WTSActive, WTSDisconnected, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQueryUserToken, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, STARTUPINFOW,
};

/// User sessions on this machine (console and RDP), including disconnected
/// ones (fast user switching, a dropped RDP connection): the Run key does not
/// fire when the user returns to them. Sessions without a signed-in user fail
/// `WTSQueryUserToken` and are skipped.
fn active_sessions() -> Vec<u32> {
    let mut out = Vec::new();
    let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
    let mut count = 0u32;
    // WTS_CURRENT_SERVER_HANDLE is the null handle.
    if unsafe { WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut info, &mut count) } == 0 {
        tracing::debug!("WTSEnumerateSessionsW failed: {}", last_err());
        return out;
    }
    if !info.is_null() {
        // SAFETY: WTSEnumerateSessionsW returned `count` entries at `info`.
        let rows = unsafe { std::slice::from_raw_parts(info, count as usize) };
        out.extend(
            rows.iter()
                .filter(|r| r.State == WTSActive || r.State == WTSDisconnected)
                .map(|r| r.SessionId),
        );
        unsafe { WTSFreeMemory(info as *mut c_void) };
    }
    out
}

/// Sessions that already run *this* tray (full image path, so a program
/// merely named `kestrel-tray.exe` cannot keep the real one away).
fn tray_sessions(exe: &Path) -> Vec<u32> {
    let want = exe.to_string_lossy().to_ascii_lowercase();
    super::snapshot::toolhelp_rows()
        .into_iter()
        .filter(|r| r.exe.eq_ignore_ascii_case(crate::tray::TRAY_EXE))
        .filter(|r| {
            open_process(r.pid, PROCESS_QUERY_LIMITED_INFORMATION)
                .and_then(|h| process_image(&h))
                .is_some_and(|p| p.to_ascii_lowercase() == want)
        })
        .filter_map(|r| {
            let mut s = 0u32;
            (unsafe { ProcessIdToSessionId(r.pid, &mut s) } != 0).then_some(s)
        })
        .collect()
}

/// Start the tray next to the agent binary in every user session that
/// does not run it yet. Best effort: failures are logged, never fatal.
pub fn start_in_user_sessions() {
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    else {
        return;
    };
    let exe = dir.join(crate::tray::TRAY_EXE);
    if !exe.is_file() {
        return;
    }
    for s in crate::tray::sessions_needing_tray(&active_sessions(), &tray_sessions(&exe)) {
        match launch(s, &exe, &dir) {
            Ok(pid) => tracing::info!(session = s, pid, "started the tray app"),
            Err(e) => tracing::debug!(session = s, "did not start the tray app: {e}"),
        }
    }
}

fn launch(session: u32, exe: &Path, dir: &Path) -> Result<u32, String> {
    let exe_s = exe.to_string_lossy().into_owned();
    if exe_s.contains('"') {
        return Err("tray path contains a quote character".into());
    }
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { WTSQueryUserToken(session, &mut tok) } == 0 {
        return Err(format!("WTSQueryUserToken failed: {}", last_err()));
    }
    let tok = Handle(tok);
    // The user's own environment, never the service's (APPDATA, TEMP).
    let mut env: *mut c_void = std::ptr::null_mut();
    if unsafe { CreateEnvironmentBlock(&mut env, tok.raw(), 0) } == 0 || env.is_null() {
        return Err(format!("CreateEnvironmentBlock failed: {}", last_err()));
    }
    let app = wide(&exe_s);
    let mut cmd = wide(&crate::tray::tray_command_line(&exe_s));
    let mut desktop = wide("winsta0\\default");
    let cwd = wide_path(dir);
    // SAFETY: plain C structs, all-zero is valid.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        CreateProcessAsUserW(
            tok.raw(),
            app.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            CREATE_UNICODE_ENVIRONMENT,
            env as *const c_void,
            cwd.as_ptr(),
            &si,
            &mut pi,
        )
    };
    unsafe { DestroyEnvironmentBlock(env) };
    if ok == 0 {
        return Err(format!("CreateProcessAsUserW failed: {}", last_err()));
    }
    drop((Handle(pi.hProcess), Handle(pi.hThread)));
    Ok(pi.dwProcessId)
}
