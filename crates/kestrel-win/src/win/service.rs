//! Service helpers used by `kestrel-agent`'s `main`.
//!
//! * [`run_service`] — run `body` under the SCM as `KestrelAgent`.
//! * [`install_service`] — register `"<exe>" service`: LocalSystem, auto
//!   start, restart-on-failure ×3 (also on non-crash failures), unrestricted
//!   service SID, description, and a DACL that leaves Administrators only
//!   query/interrogate/start rights (stop, change-config, delete, WRITE_DAC
//!   are SYSTEM-only).
//! * [`uninstall_service`] — restores a default DACL (works as SYSTEM, i.e.
//!   from the agent's token-checked `uninstall` path running in the service;
//!   as an administrator it falls back to taking ownership first), stops and
//!   deletes the service, removes Kestrel's WFP objects (otherwise an
//!   isolated host would stay isolated) and stops leftover ETW sessions.

use super::util::*;
use crate::consts::{SERVICE_ARG, SERVICE_DESCRIPTION, SERVICE_DISPLAY_NAME, SERVICE_NAME};
use anyhow::{anyhow, Context, Result};
use std::ffi::OsString;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept,
    ServiceErrorControl, ServiceExitCode, ServiceFailureActions, ServiceFailureResetPeriod,
    ServiceInfo, ServiceSidType, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION};
use windows_sys::Win32::System::Services::SetServiceObjectSecurity;

/// Hardened service DACL: SYSTEM full; Administrators query/status/enum/
/// interrogate/start/read-control; interactive/service/authenticated users read.
pub const SERVICE_SDDL: &str =
    "D:(A;;CCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWLORPRC;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLORC;;;AU)";
/// Windows default service DACL (restored before uninstall).
pub const DEFAULT_SERVICE_SDDL: &str =
    "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)";

type Body = Box<dyn FnOnce(Receiver<()>) -> Result<()> + Send>;

static BODY: Mutex<Option<Body>> = Mutex::new(None);
static STATUS: OnceLock<ServiceStatusHandle> = OnceLock::new();

windows_service::define_windows_service!(ffi_service_main, service_main);

fn status(state: ServiceState, exit: u32, wait: Duration) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: if state == ServiceState::Running {
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN
        } else {
            ServiceControlAccept::empty()
        },
        exit_code: if exit == 0 {
            ServiceExitCode::Win32(0)
        } else {
            ServiceExitCode::ServiceSpecific(exit)
        },
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    }
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_inner() {
        tracing::error!("service failed: {e:#}");
    }
}

fn service_inner() -> Result<()> {
    let body = BODY
        .lock()
        .map_err(|_| anyhow!("poisoned"))?
        .take()
        .ok_or_else(|| anyhow!("service body missing"))?;
    let (tx, rx): (Sender<()>, Receiver<()>) = channel();
    let tx = Mutex::new(Some(tx));
    let handle = service_control_handler::register(SERVICE_NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
            if let Some(h) = STATUS.get() {
                let _ = h.set_service_status(status(
                    ServiceState::StopPending,
                    0,
                    Duration::from_secs(30),
                ));
            }
            if let Some(t) = tx.lock().ok().and_then(|mut g| g.take()) {
                let _ = t.send(());
            }
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let _ = STATUS.set(handle);
    handle.set_service_status(status(ServiceState::Running, 0, Duration::default()))?;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || body(rx)));
    let code = match &r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            tracing::error!("agent exited with error: {e:#}");
            1
        }
        Err(_) => 2,
    };
    // A non-zero exit triggers the configured recovery (restart) actions.
    handle.set_service_status(status(ServiceState::Stopped, code, Duration::default()))?;
    Ok(())
}

/// Run `body` as the `KestrelAgent` service. Blocks until the service stops.
/// `body` runs on the service thread after SERVICE_RUNNING is reported; the
/// receiver yields once when the SCM asks the service to stop (Stop/Shutdown).
pub fn run_service<F>(body: F) -> Result<()>
where
    F: FnOnce(Receiver<()>) -> Result<()> + Send + 'static,
{
    *BODY.lock().map_err(|_| anyhow!("poisoned"))? = Some(Box::new(body));
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("StartServiceCtrlDispatcher (is this running under the SCM?)")?;
    Ok(())
}

fn set_dacl(svc: &windows_service::service::Service, sddl: &str, owner: bool) -> Result<()> {
    let sd = sd_from_sddl(sddl).ok_or_else(|| anyhow!("bad SDDL"))?;
    let info = if owner {
        OWNER_SECURITY_INFORMATION
    } else {
        DACL_SECURITY_INFORMATION
    };
    let ok = unsafe { SetServiceObjectSecurity(svc.raw_handle(), info, sd.0) };
    if ok == 0 {
        return Err(anyhow!("SetServiceObjectSecurity: {}", last_err()));
    }
    Ok(())
}

/// Register and start the service (`"<exe>" service`).
pub fn install_service(exe_path: &Path) -> Result<()> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("open service manager (run as administrator)")?;
    let info = ServiceInfo {
        name: SERVICE_NAME.into(),
        display_name: SERVICE_DISPLAY_NAME.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path.to_path_buf(),
        launch_arguments: vec![SERVICE_ARG.into()],
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::START
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::WRITE_DAC;
    let svc = match mgr.create_service(&info, access) {
        Ok(s) => s,
        Err(_) => {
            // Already installed (upgrade/re-install): update its config.
            let s = mgr.open_service(SERVICE_NAME, access).context("service exists but cannot be opened (installed DACL is SYSTEM-only; run as SYSTEM)")?;
            s.change_config(&info)?;
            s
        }
    };
    svc.set_description(SERVICE_DESCRIPTION)?;
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(5),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(10),
            },
            ServiceAction {
                action_type: ServiceActionType::Restart,
                delay: Duration::from_secs(30),
            },
        ]),
    })?;
    svc.set_failure_actions_on_non_crash_failures(true)?;
    svc.set_config_service_sid_info(ServiceSidType::Unrestricted)?;
    // Lock the service down last (after this, only SYSTEM can change it).
    set_dacl(&svc, SERVICE_SDDL, false)?;
    if let Err(e) = svc.start::<&str>(&[]) {
        tracing::warn!("service installed but could not be started: {e}");
    }
    Ok(())
}

/// Is the agent service registered with the SCM (whatever its DACL)?
pub fn service_installed() -> bool {
    let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return true; // cannot tell: assume it exists (the safe answer)
    };
    match mgr.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) {
        Ok(_) => true,
        // ERROR_SERVICE_DOES_NOT_EXIST (1060) is the only "not installed".
        Err(windows_service::Error::Winapi(e)) => e.raw_os_error() != Some(1060),
        Err(_) => true,
    }
}

/// Stop and delete the service; remove WFP objects and ETW sessions.
pub fn uninstall_service() -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("open service manager")?;
    let svc = match mgr.open_service(SERVICE_NAME, ServiceAccess::WRITE_DAC) {
        Ok(s) => s,
        Err(_) => {
            // Not SYSTEM: an administrator can take ownership, then rewrite the DACL.
            enable_privilege("SeTakeOwnershipPrivilege");
            let s = mgr
                .open_service(SERVICE_NAME, ServiceAccess::WRITE_OWNER)
                .context("cannot open service (not installed?)")?;
            set_dacl(&s, "O:BA", true)?;
            drop(s);
            mgr.open_service(SERVICE_NAME, ServiceAccess::WRITE_DAC)
                .context("cannot open service for WRITE_DAC")?
        }
    };
    set_dacl(&svc, DEFAULT_SERVICE_SDDL, false)?;
    drop(svc);
    let svc = mgr.open_service(
        SERVICE_NAME,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    // Delete first (marks for deletion), then stop; if this process *is* the
    // service, the SCM removes it once it stops.
    svc.delete()?;
    if let Ok(st) = svc.query_status() {
        if st.current_state != ServiceState::Stopped
            && std::process::id() != st.process_id.unwrap_or(0)
        {
            let _ = svc.stop();
            // Wait (up to 30 s) until the agent process has exited, so its
            // files (outbox database, keys) are no longer open.
            for _ in 0..120 {
                match svc.query_status() {
                    Ok(st) if st.current_state != ServiceState::Stopped => {
                        std::thread::sleep(std::time::Duration::from_millis(250))
                    }
                    _ => break,
                }
            }
        }
    }
    if let Err(e) = super::wfp::remove_all_wfp_objects() {
        tracing::warn!("WFP cleanup failed: {e:#}");
    }
    for s in [
        crate::consts::SESSION_CORE,
        crate::consts::SESSION_IO,
        crate::consts::SESSION_PROC_CMDLINE,
    ] {
        let _ = ferrisetw::trace::stop_trace_by_name(s);
    }
    Ok(())
}
