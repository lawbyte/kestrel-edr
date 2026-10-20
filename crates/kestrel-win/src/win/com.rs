//! Minimal COM clients (WMI and Task Scheduler 2.0) on top of the `windows`
//! crate. No PowerShell / `wmic` / `schtasks` subprocesses: everything goes
//! through the documented COM interfaces
//! (<https://learn.microsoft.com/en-us/windows/win32/wmisdk/example--getting-wmi-data-from-the-local-computer>,
//! <https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-objects>).
//!
//! Callers run on the `spawn_blocking` thread of one action, so [`ComInit`]
//! initialises the multithreaded apartment for the duration of that call.

use windows::core::{BSTR, PCWSTR, VARIANT};
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoSetProxyBlanket, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_MULTITHREADED, EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WbemLocator, WBEM_FLAG_FORWARD_ONLY,
    WBEM_FLAG_RETURN_IMMEDIATELY, WBEM_FLAG_RETURN_WBEM_COMPLETE, WBEM_INFINITE,
};

/// COM initialised on this thread for the guard's lifetime.
pub struct ComInit {
    uninit: bool,
}

impl ComInit {
    pub fn new() -> Result<ComInit, String> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr.is_ok() {
            Ok(ComInit { uninit: true })
        } else if hr == RPC_E_CHANGED_MODE {
            // Already initialised as STA on this thread: usable, not ours to undo.
            Ok(ComInit { uninit: false })
        } else {
            Err(format!("CoInitializeEx failed: {hr:?}"))
        }
    }
}

impl Drop for ComInit {
    fn drop(&mut self) {
        if self.uninit {
            unsafe { CoUninitialize() };
        }
    }
}

pub fn err(ctx: &str, e: windows::core::Error) -> String {
    format!("{ctx}: 0x{:08X} {}", e.code().0 as u32, e.message())
}

/// Connect to a local WMI namespace (e.g. `root\subscription`).
pub fn wmi_connect(namespace: &str) -> Result<IWbemServices, String> {
    unsafe {
        let loc: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| err("WbemLocator", e))?;
        let svc = loc
            .ConnectServer(
                &BSTR::from(namespace),
                &BSTR::new(),
                &BSTR::new(),
                &BSTR::new(),
                0,
                &BSTR::new(),
                None,
            )
            .map_err(|e| err(&format!("ConnectServer({namespace})"), e))?;
        CoSetProxyBlanket(
            &svc,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            PCWSTR::null(),
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
        .map_err(|e| err("CoSetProxyBlanket", e))?;
        Ok(svc)
    }
}

/// Run a WQL query; at most `cap` objects are returned.
pub fn wmi_query(
    svc: &IWbemServices,
    wql: &str,
    cap: usize,
) -> Result<Vec<IWbemClassObject>, String> {
    let mut out = Vec::new();
    unsafe {
        let en = svc
            .ExecQuery(
                &BSTR::from("WQL"),
                &BSTR::from(wql),
                WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                None,
            )
            .map_err(|e| err(&format!("ExecQuery({wql})"), e))?;
        while out.len() < cap {
            let mut row = [None];
            let mut n = 0u32;
            let hr = en.Next(WBEM_INFINITE, &mut row, &mut n);
            if hr.is_err() {
                return Err(format!("IEnumWbemClassObject::Next: {hr:?}"));
            }
            match row[0].take() {
                Some(o) if n == 1 => out.push(o),
                _ => break,
            }
        }
    }
    Ok(out)
}

/// String rendering of a property (`None` when missing / NULL).
pub fn prop_string(obj: &IWbemClassObject, name: &str) -> Option<String> {
    let w: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut v = VARIANT::default();
    unsafe { obj.Get(PCWSTR(w.as_ptr()), 0, &mut v, None, None) }.ok()?;
    if v.is_empty() {
        return None;
    }
    BSTR::try_from(&v).ok().map(|b| b.to_string())
}

/// MOF text of an object (`IWbemClassObject::GetObjectText`).
pub fn object_text(obj: &IWbemClassObject) -> Result<String, String> {
    unsafe { obj.GetObjectText(0) }
        .map(|b| b.to_string())
        .map_err(|e| err("GetObjectText", e))
}

/// Fetch one object by path.
pub fn wmi_get(svc: &IWbemServices, path: &str) -> Result<IWbemClassObject, String> {
    let mut obj = None;
    unsafe {
        svc.GetObject(
            &BSTR::from(path),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            None,
            Some(&mut obj),
            None,
        )
    }
    .map_err(|e| err(&format!("GetObject({path})"), e))?;
    obj.ok_or_else(|| format!("GetObject({path}) returned nothing"))
}

pub fn wmi_delete(svc: &IWbemServices, path: &str) -> Result<(), String> {
    unsafe {
        svc.DeleteInstance(
            &BSTR::from(path),
            WBEM_FLAG_RETURN_WBEM_COMPLETE,
            None,
            None,
        )
    }
    .map_err(|e| err(&format!("DeleteInstance({path})"), e))
}

/// Connected local Task Scheduler service.
pub fn task_service() -> Result<ITaskService, String> {
    unsafe {
        let ts: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| err("TaskScheduler", e))?;
        let none = VARIANT::default();
        ts.Connect(&none, &none, &none, &none)
            .map_err(|e| err("ITaskService::Connect", e))?;
        Ok(ts)
    }
}
