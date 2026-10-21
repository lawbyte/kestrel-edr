//! Start the desktop helper in the active console session.
//!
//! Sequence (all verified against windows-sys 0.61 and the Win32 docs):
//! `WTSGetActiveConsoleSessionId` → `OpenProcessToken(GetCurrentProcess(),
//! TOKEN_DUPLICATE | TOKEN_QUERY)` → `DuplicateTokenEx(…, TOKEN_ALL_ACCESS,
//! SecurityImpersonation, TokenPrimary)` → `SetTokenInformation(TokenSessionId)`
//! (needs SeTcbPrivilege: the service runs as LocalSystem) →
//! `CreateEnvironmentBlock` (SYSTEM's environment) → `CreateJobObjectW` +
//! `SetInformationJobObject(JobObjectExtendedLimitInformation,
//! JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)` → `CreateProcessAsUserW(lpDesktop =
//! "winsta0\default", CREATE_SUSPENDED | CREATE_NO_WINDOW |
//! CREATE_UNICODE_ENVIRONMENT)` → `AssignProcessToJobObject` → `ResumeThread`.
//! The job handle lives in [`HelperProcess`]: when the agent exits (or the
//! session object is dropped) the handle closes and the kernel kills the
//! helper.

use super::super::util::*;
use std::ffi::c_void;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Security::{
    DuplicateTokenEx, SecurityImpersonation, SetTokenInformation, TokenPrimary, TokenSessionId,
    TOKEN_ALL_ACCESS, TOKEN_DUPLICATE, TOKEN_QUERY,
};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows_sys::Win32::System::Threading::{
    CreateProcessAsUserW, GetExitCodeProcess, OpenProcessToken, ResumeThread, TerminateProcess,
    WaitForSingleObject, CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    PROCESS_INFORMATION, STARTUPINFOW,
};

/// The interactive console session, `None` when there is none
/// (`WTSGetActiveConsoleSessionId` returns `0xFFFFFFFF` during session
/// transitions or when no session is attached to the console).
pub fn active_console_session() -> Option<u32> {
    let s = unsafe { WTSGetActiveConsoleSessionId() };
    (s != 0xFFFF_FFFF).then_some(s)
}

/// A running helper: process handle + the kill-on-close job.
pub struct HelperProcess {
    pub pid: u32,
    process: Handle,
    _job: Handle,
}

impl HelperProcess {
    /// Exit code once the process has exited.
    pub fn exit_code(&self) -> Option<u32> {
        if unsafe { WaitForSingleObject(self.process.raw(), 0) } != WAIT_OBJECT_0 {
            return None;
        }
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(self.process.raw(), &mut code) } != 0).then_some(code)
    }

    /// Wait up to `ms` for the process to exit.
    pub fn wait(&self, ms: u32) -> bool {
        unsafe { WaitForSingleObject(self.process.raw(), ms) == WAIT_OBJECT_0 }
    }

    pub fn terminate(&self) {
        unsafe {
            TerminateProcess(self.process.raw(), 1);
        }
    }
}

/// Environment block from `CreateEnvironmentBlock`.
struct EnvBlock(*mut c_void);

impl Drop for EnvBlock {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                DestroyEnvironmentBlock(self.0);
            }
        }
    }
}

fn os_err(what: &str) -> String {
    format!("{what} failed: {}", last_err())
}

/// Primary SYSTEM token (copy of the agent's own) moved to `session`.
fn session_token(session: u32) -> Result<Handle, String> {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(current_process(), TOKEN_DUPLICATE | TOKEN_QUERY, &mut tok) } == 0
    {
        return Err(os_err("OpenProcessToken"));
    }
    let tok = Handle(tok);
    let mut prim: HANDLE = std::ptr::null_mut();
    if unsafe {
        DuplicateTokenEx(
            tok.raw(),
            TOKEN_ALL_ACCESS,
            std::ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut prim,
        )
    } == 0
    {
        return Err(os_err("DuplicateTokenEx"));
    }
    let prim = Handle(prim);
    let sid = session;
    if unsafe {
        SetTokenInformation(
            prim.raw(),
            TokenSessionId,
            &sid as *const u32 as *const c_void,
            std::mem::size_of::<u32>() as u32,
        )
    } == 0
    {
        return Err(os_err(
            "SetTokenInformation(TokenSessionId) (the agent must run as LocalSystem)",
        ));
    }
    Ok(prim)
}

fn kill_on_close_job() -> Result<Handle, String> {
    let job = Handle::new(unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) })
        .ok_or_else(|| os_err("CreateJobObjectW"))?;
    // SAFETY: plain C struct, all-zero is a valid value.
    let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
    info.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
    if unsafe {
        SetInformationJobObject(
            job.raw(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(os_err("SetInformationJobObject"));
    }
    Ok(job)
}

/// Command line of the helper (the agent CLI's hidden subcommand).
pub fn helper_command_line(exe: &str, pipe: &str, parent_pid: u32) -> String {
    format!("\"{exe}\" desktop-helper --pipe {pipe} --parent {parent_pid}")
}

/// Start `<current exe> desktop-helper --pipe <pipe> --parent <agent pid>`
/// as SYSTEM in `session`, on `winsta0\default`, inside a kill-on-close job.
pub fn spawn_helper(session: u32, pipe: &str) -> Result<HelperProcess, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("cannot locate the agent binary: {e}"))?;
    let exe_s = exe.to_string_lossy().into_owned();
    if exe_s.contains('"') {
        return Err("agent path contains a quote character".into());
    }
    let token = session_token(session)?;
    let job = kill_on_close_job()?;
    let mut env: *mut c_void = std::ptr::null_mut();
    let env = if unsafe { CreateEnvironmentBlock(&mut env, token.raw(), 0) } != 0 {
        EnvBlock(env)
    } else {
        tracing::debug!("CreateEnvironmentBlock failed: {}", last_err());
        EnvBlock(std::ptr::null_mut())
    };
    let app = wide(&exe_s);
    let mut cmd = wide(&helper_command_line(&exe_s, pipe, std::process::id()));
    let mut desktop = wide("winsta0\\default");
    let cwd = exe.parent().map(wide_path);
    // SAFETY: plain C structs, all-zero is valid.
    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    si.lpDesktop = desktop.as_mut_ptr();
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let mut flags = CREATE_SUSPENDED | CREATE_NO_WINDOW;
    if !env.0.is_null() {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    let ok = unsafe {
        CreateProcessAsUserW(
            token.raw(),
            app.as_ptr(),
            cmd.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            0,
            flags,
            env.0 as *const c_void,
            cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr()),
            &si,
            &mut pi,
        )
    };
    if ok == 0 {
        return Err(os_err("CreateProcessAsUserW"));
    }
    // V-H1 / re-review N8: the agent's own child (created suspended, so the
    // record lands before it runs; the sensor waits for it).
    // SAFETY: `pi.hProcess` is the live handle CreateProcessAsUserW returned.
    unsafe { crate::spawnreg::record_handle(pi.dwProcessId, pi.hProcess) };
    let process = Handle(pi.hProcess);
    let thread = Handle(pi.hThread);
    if unsafe { AssignProcessToJobObject(job.raw(), process.raw()) } == 0 {
        let e = os_err("AssignProcessToJobObject");
        unsafe {
            TerminateProcess(process.raw(), 1);
        }
        return Err(e);
    }
    if unsafe { ResumeThread(thread.raw()) } == u32::MAX {
        let e = os_err("ResumeThread");
        unsafe {
            TerminateProcess(process.raw(), 1);
        }
        return Err(e);
    }
    Ok(HelperProcess {
        pid: pi.dwProcessId,
        process,
        _job: job,
    })
}
