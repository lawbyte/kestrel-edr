//! `RemoveAutorun` executor (Windows). Decisions live in
//! [`crate::autorun_plan`]; this module only performs them.
//!
//! Guarantees (every kind):
//! 1. **Validate first** ([`crate::autorun_plan`]): registry keys only under
//!    `HKLM\SOFTWARE`, `HKLM\SYSTEM\CurrentControlSet`, `HKU\<SID>`; never
//!    Kestrel's own keys / service / tasks; no wildcards or empty input;
//!    OS-critical values only rewritten with a sane default, never deleted.
//! 2. **Back up the exact original first** into the encrypted quarantine
//!    vault ([`Vault::store_backup`], JSON [`AutorunBackup`]): registry value
//!    name + type + data; task XML (Task Scheduler 2.0 `IRegisteredTask::Xml`);
//!    service config (SCM config + every value of the service key and its
//!    `Parameters` subkey); WMI consumer + bindings + filters as MOF
//!    (`GetObjectText`). Startup files go through the normal quarantine
//!    (which is its own backup). The vault id is returned as `artifact`.
//!    **No backup → no change.**
//! 3. **Re-read immediately before acting** and abort if the entry is gone
//!    or differs from what was just backed up (TOCTOU window = backup write).
//!    The alert's view of the data is not available to the agent, so a change
//!    between alert and command is not detected beyond "still present".
//! 4. **Least destructive action**: tasks are disabled, then deleted;
//!    services are set to Disabled and stopped, **never deleted**; WMI:
//!    binding(s), the consumer, and only filters no other binding uses.
//! 5. File operations reuse the quarantine path ([`super::safefs`]): no
//!    reparse points are followed, one hard link, final path == request.

use super::com::{self, ComInit};
use super::quarantine::Vault;
use super::util::*;
use crate::autorun_plan::{
    self, encode_restore, AutorunBackup, BackupData, RegLocation, RegOp, RegRoot, RegValueDump,
    WmiObjectDump, BACKUP_FORMAT,
};
use kestrel_common::AutorunKind;
use kestrel_platform::ActionOrigin;
use windows::core::BSTR;
use windows::Win32::Foundation::VARIANT_FALSE;
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegDeleteValueW, RegEnumValueW, RegOpenKeyExW, RegQueryInfoKeyW, RegQueryValueExW,
    RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS, KEY_QUERY_VALUE, KEY_SET_VALUE,
    KEY_WOW64_64KEY, REG_OPTION_OPEN_LINK,
};
use windows_sys::Win32::System::Services::{
    ChangeServiceConfigW, CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
    QueryServiceConfigW, QueryServiceStatus, QUERY_SERVICE_CONFIGW, SC_HANDLE, SC_MANAGER_CONNECT,
    SERVICE_BOOT_START, SERVICE_CHANGE_CONFIG, SERVICE_CONTROL_STOP, SERVICE_DISABLED,
    SERVICE_FILE_SYSTEM_DRIVER, SERVICE_KERNEL_DRIVER, SERVICE_NO_CHANGE, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, SERVICE_SYSTEM_START,
};

pub struct Ctx<'a> {
    pub vault: &'a Vault,
    pub origin: ActionOrigin,
    pub system_drive: char,
    pub own_dirs: &'a [String],
}

/// (ok, detail, artifact = vault backup id)
pub type Outcome = (bool, String, Option<String>);

pub fn remove_autorun(
    ctx: &Ctx,
    kind: AutorunKind,
    location: &str,
    value_name: Option<&str>,
    restore_data: Option<&str>,
) -> Outcome {
    let r = match kind {
        AutorunKind::RegistryValue => registry(ctx, location, value_name, restore_data),
        AutorunKind::StartupFile => startup_file(ctx, location),
        AutorunKind::ScheduledTask => task(ctx, location),
        AutorunKind::Service => service(ctx, location),
        AutorunKind::WmiSubscription => wmi(ctx, location),
    };
    match r {
        Ok(o) => o,
        Err(e) => (false, e, None),
    }
}

fn backup(
    ctx: &Ctx,
    kind: AutorunKind,
    location: &str,
    value_name: Option<&str>,
    data: BackupData,
) -> Result<String, String> {
    let b = AutorunBackup {
        format: BACKUP_FORMAT,
        kind,
        location: location.to_string(),
        value_name: value_name.map(str::to_string),
        captured_at: kestrel_common::now_ms(),
        data,
    };
    ctx.vault
        .store_backup(&b.label(), &b.to_bytes())
        .map_err(|e| format!("backup failed, nothing changed: {e}"))
}

// ------------------------------------------------------------------ registry

struct Key(HKEY);

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

fn open_key(loc: &RegLocation, access: u32) -> Result<Key, String> {
    let root = match loc.root {
        RegRoot::Hklm => HKEY_LOCAL_MACHINE,
        RegRoot::Hku => HKEY_USERS,
    };
    let w = wide(&loc.subkey);
    let mut h: HKEY = std::ptr::null_mut();
    // REG_OPTION_OPEN_LINK: if the final key is a registry symbolic link,
    // open the link itself (whose only value is SymbolicLinkValue), so a
    // planted link cannot redirect the removal to another key.
    let rc = unsafe {
        RegOpenKeyExW(
            root,
            w.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access | KEY_WOW64_64KEY,
            &mut h,
        )
    };
    if rc == ERROR_SUCCESS {
        Ok(Key(h))
    } else if rc == ERROR_FILE_NOT_FOUND {
        Err(format!(
            "{} does not exist (or the user hive is not loaded)",
            loc.display()
        ))
    } else {
        Err(format!("cannot open {}: {}", loc.display(), win32_err(rc)))
    }
}

/// Exact (type, bytes) of a value; `Ok(None)` when it does not exist.
fn query_raw(k: &Key, name: &str) -> Result<Option<(u32, Vec<u8>)>, String> {
    let w = wide(name);
    let mut size = 256u32;
    for _ in 0..8 {
        let mut buf = vec![0u8; size as usize];
        let mut ty = 0u32;
        let mut len = size;
        let rc = unsafe {
            RegQueryValueExW(
                k.0,
                w.as_ptr(),
                std::ptr::null(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if rc == ERROR_SUCCESS {
            buf.truncate(len as usize);
            return Ok(Some((ty, buf)));
        }
        if rc == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if rc == ERROR_MORE_DATA {
            size = len.max(size.saturating_mul(2)).min(16 << 20);
            continue;
        }
        return Err(format!("cannot read value {name:?}: {}", win32_err(rc)));
    }
    Err(format!("value {name:?} keeps changing size"))
}

/// Every value of an open key (bounded), for service backups.
fn dump_values(k: &Key) -> Vec<RegValueDump> {
    let mut out = Vec::new();
    let (mut n_values, mut max_name, mut max_data) = (0u32, 0u32, 0u32);
    let rc = unsafe {
        RegQueryInfoKeyW(
            k.0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut n_values,
            &mut max_name,
            &mut max_data,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if rc != ERROR_SUCCESS {
        return out;
    }
    for i in 0..n_values.min(1024) {
        let mut name = vec![0u16; max_name as usize + 2];
        let mut nlen = name.len() as u32;
        let mut data = vec![0u8; (max_data as usize + 2).min(16 << 20)];
        let mut dlen = data.len() as u32;
        let mut ty = 0u32;
        let rc = unsafe {
            RegEnumValueW(
                k.0,
                i,
                name.as_mut_ptr(),
                &mut nlen,
                std::ptr::null(),
                &mut ty,
                data.as_mut_ptr(),
                &mut dlen,
            )
        };
        if rc != ERROR_SUCCESS {
            continue;
        }
        let n = String::from_utf16_lossy(&name[..nlen as usize]);
        out.push(RegValueDump::new(&n, ty, &data[..dlen as usize]));
    }
    out
}

/// Text view of string-typed registry data (for the own-dirs check).
fn reg_text(ty: u32, data: &[u8]) -> String {
    match ty {
        autorun_plan::REG_SZ | autorun_plan::REG_EXPAND_SZ | autorun_plan::REG_MULTI_SZ => {
            let (pairs, _) = data.as_chunks::<2>();
            let u: Vec<u16> = pairs.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&u).replace('\0', " ")
        }
        _ => String::new(),
    }
}

fn registry(
    ctx: &Ctx,
    location: &str,
    value_name: Option<&str>,
    restore_data: Option<&str>,
) -> Result<Outcome, String> {
    let plan = autorun_plan::plan_registry(location, value_name, restore_data)?;
    let loc = plan.location.clone();
    let shown = if plan.value_name.is_empty() {
        format!(r"{}\(default)", loc.display())
    } else {
        format!(r"{}\{}", loc.display(), plan.value_name)
    };
    let key = open_key(&loc, KEY_QUERY_VALUE | KEY_SET_VALUE)?;
    let Some((ty, data)) = query_raw(&key, &plan.value_name)? else {
        return Err(format!(
            "{shown} is not present (already removed?); nothing changed"
        ));
    };
    if autorun_plan::references_own_dirs(&reg_text(ty, &data), ctx.own_dirs) {
        return Err(format!(
            "refusing to change {shown}: it points into Kestrel's own installation"
        ));
    }
    let target = match &plan.op {
        RegOp::Delete => None,
        RegOp::Write(r) => Some(encode_restore(ty, r)),
    };
    if let Some((tt, tb)) = &target {
        if *tt == ty && *tb == data {
            return Ok((true, format!("{shown} already has the restore value"), None));
        }
    }
    let id = backup(
        ctx,
        AutorunKind::RegistryValue,
        &loc.display(),
        Some(&plan.value_name),
        BackupData::Registry {
            value: RegValueDump::new(&plan.value_name, ty, &data),
        },
    )?;
    // TOCTOU: re-read right before acting.
    match query_raw(&key, &plan.value_name)? {
        Some((t2, d2)) if t2 == ty && d2 == data => {}
        Some(_) => {
            return Ok((
                false,
                format!("{shown} changed after the backup; not touched (backup {id})"),
                Some(id),
            ))
        }
        None => {
            return Ok((
                false,
                format!("{shown} disappeared before removal; nothing changed (backup {id})"),
                Some(id),
            ))
        }
    }
    let w = wide(&plan.value_name);
    let rc = match &target {
        None => unsafe { RegDeleteValueW(key.0, w.as_ptr()) },
        Some((tt, tb)) => unsafe {
            RegSetValueExW(key.0, w.as_ptr(), 0, *tt, tb.as_ptr(), tb.len() as u32)
        },
    };
    if rc != ERROR_SUCCESS {
        return Ok((
            false,
            format!("could not change {shown}: {} (backup {id})", win32_err(rc)),
            Some(id),
        ));
    }
    let after = query_raw(&key, &plan.value_name).ok().flatten();
    let verified = match &target {
        None => after.is_none(),
        Some((tt, tb)) => after.as_ref().is_some_and(|(a, b)| a == tt && b == tb),
    };
    let what = match &plan.op {
        RegOp::Delete => "removed".to_string(),
        RegOp::Write(r) => format!("restored to {r:?}"),
    };
    Ok((
        verified,
        format!(
            "{shown} ({}) {what}{}; original backed up as {id}",
            autorun_plan::reg_type_name(ty),
            if verified {
                ""
            } else {
                " but verification failed"
            }
        ),
        Some(id),
    ))
}

// ------------------------------------------------------------------ startup file

fn startup_file(ctx: &Ctx, path: &str) -> Result<Outcome, String> {
    autorun_plan::plan_startup_file(path)?;
    let (id, d) = ctx
        .vault
        .quarantine(path, None, ctx.origin, ctx.system_drive, ctx.own_dirs)?;
    Ok((true, format!("startup item {d}"), Some(id)))
}

// ------------------------------------------------------------------ tasks

fn task(ctx: &Ctx, path: &str) -> Result<Outcome, String> {
    let engine = !matches!(ctx.origin, ActionOrigin::ServerCommand);
    let (folder_path, name) = autorun_plan::plan_task(path, engine)?;
    let _com = ComInit::new()?;
    let ts = com::task_service()?;
    unsafe {
        let folder = ts
            .GetFolder(&BSTR::from(folder_path.as_str()))
            .map_err(|e| com::err(&format!("task folder {folder_path}"), e))?;
        let t = folder
            .GetTask(&BSTR::from(name.as_str()))
            .map_err(|e| com::err(&format!("task {path} (not present?)"), e))?;
        let xml = t
            .Xml()
            .map_err(|e| com::err("IRegisteredTask::Xml", e))?
            .to_string();
        if xml.trim().is_empty() {
            return Err(format!(
                "task {path}: empty XML, cannot back up; nothing changed"
            ));
        }
        let enabled = t.Enabled().map(|b| b.as_bool()).unwrap_or(true);
        let id = backup(
            ctx,
            AutorunKind::ScheduledTask,
            path,
            None,
            BackupData::Task {
                xml: xml.clone(),
                enabled,
            },
        )?;
        // Re-read (fresh object) right before acting.
        let t2 = match folder.GetTask(&BSTR::from(name.as_str())) {
            Ok(t2) => t2,
            Err(_) => {
                return Ok((
                    false,
                    format!(
                        "task {path} disappeared before removal; nothing changed (backup {id})"
                    ),
                    Some(id),
                ))
            }
        };
        if t2.Xml().map(|x| x.to_string()).ok().as_deref() != Some(xml.as_str()) {
            return Ok((
                false,
                format!("task {path} changed after the backup; not touched (backup {id})"),
                Some(id),
            ));
        }
        let disabled = t2.SetEnabled(VARIANT_FALSE).is_ok();
        match folder.DeleteTask(&BSTR::from(name.as_str()), 0) {
            Ok(()) => Ok((
                true,
                format!("task {path} disabled and deleted; XML backed up as {id}"),
                Some(id),
            )),
            Err(e) => Ok((
                false,
                format!(
                    "task {path} {}; delete failed: {} (backup {id})",
                    if disabled {
                        "disabled"
                    } else {
                        "could not be disabled"
                    },
                    com::err("DeleteTask", e)
                ),
                Some(id),
            )),
        }
    }
}

// ------------------------------------------------------------------ services

struct Sc(SC_HANDLE);

impl Drop for Sc {
    fn drop(&mut self) {
        unsafe { CloseServiceHandle(self.0) };
    }
}

fn pwstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0usize;
    unsafe {
        while *p.add(n) != 0 && n < 32768 {
            n += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
    }
}

fn multi_sz(p: *const u16) -> Vec<String> {
    let mut out = Vec::new();
    if p.is_null() {
        return out;
    }
    let mut cur = p;
    for _ in 0..256 {
        let s = pwstr(cur);
        if s.is_empty() {
            break;
        }
        let len = s.encode_utf16().count();
        out.push(s);
        cur = unsafe { cur.add(len + 1) };
    }
    out
}

#[derive(Clone, PartialEq)]
struct SvcConfig {
    service_type: u32,
    start_type: u32,
    error_control: u32,
    binary_path: String,
    load_order_group: String,
    dependencies: Vec<String>,
    start_name: String,
    display_name: String,
}

fn query_config(h: &Sc) -> Result<SvcConfig, String> {
    let mut need = 0u32;
    unsafe { QueryServiceConfigW(h.0, std::ptr::null_mut(), 0, &mut need) };
    if need == 0 {
        return Err(format!("QueryServiceConfigW: {}", last_err()));
    }
    // u64 buffer for alignment.
    let mut buf = vec![0u64; (need as usize).div_ceil(8) + 1];
    let cfg = buf.as_mut_ptr() as *mut QUERY_SERVICE_CONFIGW;
    let ok = unsafe { QueryServiceConfigW(h.0, cfg, (buf.len() * 8) as u32, &mut need) };
    if ok == 0 {
        return Err(format!("QueryServiceConfigW: {}", last_err()));
    }
    let c = unsafe { &*cfg };
    Ok(SvcConfig {
        service_type: c.dwServiceType,
        start_type: c.dwStartType,
        error_control: c.dwErrorControl,
        binary_path: pwstr(c.lpBinaryPathName),
        load_order_group: pwstr(c.lpLoadOrderGroup),
        dependencies: multi_sz(c.lpDependencies),
        start_name: pwstr(c.lpServiceStartName),
        display_name: pwstr(c.lpDisplayName),
    })
}

fn ms_signed(path: &str) -> bool {
    let (st, signer, ms_root) = super::enrich::verify_signature_ms(path);
    st == kestrel_common::SignatureState::Valid
        && (ms_root
            || signer
                .as_deref()
                .is_some_and(kestrel_detect::protect::is_microsoft_signer))
}

/// Refuse services that are part of the OS / a security product even when
/// they are not on the static list (needs the live config).
fn service_is_os(
    cfg: &SvcConfig,
    params: &[RegValueDump],
    key: &[RegValueDump],
    ctx: &Ctx,
) -> Option<String> {
    if autorun_plan::references_own_dirs(&cfg.binary_path, ctx.own_dirs) {
        return Some("its binary is part of Kestrel".into());
    }
    let driver = cfg.service_type & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER) != 0;
    if driver && (cfg.start_type == SERVICE_BOOT_START || cfg.start_type == SERVICE_SYSTEM_START) {
        return Some("boot/system-start drivers are never disabled by Kestrel".into());
    }
    let sr = system_root();
    let bin = autorun_plan::service_binary(&cfg.binary_path, &sr)?;
    let bin = super::safefs::long_path(&bin);
    if autorun_plan::is_svchost(&bin) {
        let dll = params
            .iter()
            .chain(key.iter())
            .find(|v| v.name.eq_ignore_ascii_case("ServiceDll"))
            .and_then(|v| hex_utf16(&v.data_hex))
            .map(|s| crate::ntpath::expand_env(&s, |n| std::env::var(n).ok()));
        return match dll {
            None => Some("shared svchost service without a readable ServiceDll".into()),
            Some(d) if autorun_plan::under_system_root(&d, &sr) && ms_signed(&d) => {
                Some(format!("ServiceDll {d} is a Microsoft-signed OS component"))
            }
            Some(_) => None,
        };
    }
    if !autorun_plan::is_wrapper_binary(&bin)
        && autorun_plan::under_system_root(&bin, &sr)
        && ms_signed(&bin)
    {
        return Some(format!("{bin} is a Microsoft-signed OS binary"));
    }
    if crate::filters::is_protected_target(&bin, ctx.system_drive, |p| {
        super::enrich::verify_signature_ms(p)
    }) {
        return Some(format!("{bin} is a protected OS / security-product image"));
    }
    None
}

fn hex_utf16(hex: &str) -> Option<String> {
    let bytes: Vec<u8> = (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok())
        .collect::<Option<_>>()?;
    Some(crate::etwparse::utf16le(&bytes))
}

fn service(ctx: &Ctx, name: &str) -> Result<Outcome, String> {
    let name = autorun_plan::plan_service(name)?;
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return Err(format!("OpenSCManager: {}", last_err()));
    }
    let scm = Sc(scm);
    let wn = wide(&name);
    let h = unsafe {
        OpenServiceW(
            scm.0,
            wn.as_ptr(),
            SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_STOP | SERVICE_QUERY_STATUS,
        )
    };
    if h.is_null() {
        return Err(format!(
            "cannot open service {name} (not present?): {}",
            last_err()
        ));
    }
    let h = Sc(h);
    let cfg = query_config(&h)?;
    let key_loc = RegLocation {
        root: RegRoot::Hklm,
        subkey: format!(r"SYSTEM\CurrentControlSet\Services\{name}"),
    };
    let key_vals = open_key(&key_loc, KEY_QUERY_VALUE)
        .map(|k| dump_values(&k))
        .unwrap_or_default();
    let par_loc = RegLocation {
        root: RegRoot::Hklm,
        subkey: format!(r"SYSTEM\CurrentControlSet\Services\{name}\Parameters"),
    };
    let par_vals = open_key(&par_loc, KEY_QUERY_VALUE)
        .map(|k| dump_values(&k))
        .unwrap_or_default();
    if let Some(why) = service_is_os(&cfg, &par_vals, &key_vals, ctx) {
        return Err(format!("refusing to disable service {name}: {why}"));
    }
    if cfg.start_type == SERVICE_DISABLED && service_stopped(&h) {
        return Ok((
            true,
            format!("service {name} is already disabled and stopped"),
            None,
        ));
    }
    let was_running = !service_stopped(&h);
    let id = backup(
        ctx,
        AutorunKind::Service,
        &name,
        None,
        BackupData::Service {
            service_type: cfg.service_type,
            start_type: cfg.start_type,
            error_control: cfg.error_control,
            binary_path: cfg.binary_path.clone(),
            load_order_group: cfg.load_order_group.clone(),
            dependencies: cfg.dependencies.clone(),
            start_name: cfg.start_name.clone(),
            display_name: cfg.display_name.clone(),
            registry: key_vals,
            parameters: par_vals,
            was_running,
        },
    )?;
    match query_config(&h) {
        Ok(c2) if c2 == cfg => {}
        _ => {
            return Ok((
                false,
                format!("service {name} changed after the backup; not touched (backup {id})"),
                Some(id),
            ))
        }
    }
    let ok = unsafe {
        ChangeServiceConfigW(
            h.0,
            SERVICE_NO_CHANGE,
            SERVICE_DISABLED,
            SERVICE_NO_CHANGE,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if ok == 0 {
        return Ok((
            false,
            format!(
                "could not disable service {name}: {} (backup {id})",
                last_err()
            ),
            Some(id),
        ));
    }
    let stop_note = if was_running {
        let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
        if unsafe { ControlService(h.0, SERVICE_CONTROL_STOP, &mut st) } != 0 {
            "stop requested".to_string()
        } else {
            format!("stop failed: {}", last_err())
        }
    } else {
        "was not running".to_string()
    };
    Ok((
        true,
        format!(
            "service {name} ({}) set to Disabled ({stop_note}; not deleted); config backed up as {id}",
            cfg.binary_path
        ),
        Some(id),
    ))
}

fn service_stopped(h: &Sc) -> bool {
    let mut st: SERVICE_STATUS = unsafe { std::mem::zeroed() };
    unsafe { QueryServiceStatus(h.0, &mut st) != 0 && st.dwCurrentState == SERVICE_STOPPED }
}

// ------------------------------------------------------------------ WMI

fn wmi(ctx: &Ctx, consumer_name: &str) -> Result<Outcome, String> {
    let name = autorun_plan::plan_wmi_consumer(consumer_name)?;
    let _com = ComInit::new()?;
    let svc = com::wmi_connect(r"root\subscription")?;
    let q = format!(
        "SELECT * FROM __EventConsumer WHERE Name = {}",
        autorun_plan::wql_quote(&name)
    );
    let consumers = com::wmi_query(&svc, &q, 8)?;
    let consumer = match consumers.as_slice() {
        [] => {
            return Err(format!(
                "WMI consumer {name:?} not found in root\\subscription"
            ))
        }
        [c] => c,
        _ => {
            return Err(format!(
                "{} consumers named {name:?} (different classes); refusing to guess",
                consumers.len()
            ))
        }
    };
    let cpath = com::prop_string(consumer, "__RELPATH").ok_or("consumer has no __RELPATH")?;
    let cmof = com::object_text(consumer)?;
    let ckey = autorun_plan::wmi_ref_key(&cpath);
    let all = com::wmi_query(&svc, "SELECT * FROM __FilterToConsumerBinding", 4096)?;
    let mut bindings = Vec::new();
    let mut other_filter_refs = Vec::new();
    let mut our_filter_refs: Vec<String> = Vec::new();
    for b in &all {
        let cref = com::prop_string(b, "Consumer").unwrap_or_default();
        let fref = com::prop_string(b, "Filter").unwrap_or_default();
        if autorun_plan::wmi_ref_key(&cref) == ckey {
            let path = com::prop_string(b, "__RELPATH").ok_or("binding has no __RELPATH")?;
            bindings.push(WmiObjectDump {
                path,
                mof: com::object_text(b)?,
                deleted: true,
            });
            if !fref.is_empty()
                && !our_filter_refs
                    .iter()
                    .any(|f| autorun_plan::wmi_ref_key(f) == autorun_plan::wmi_ref_key(&fref))
            {
                our_filter_refs.push(fref);
            }
        } else if !fref.is_empty() {
            other_filter_refs.push(autorun_plan::wmi_ref_key(&fref));
        }
    }
    let mut filters = Vec::new();
    for fref in &our_filter_refs {
        let shared = other_filter_refs.contains(&autorun_plan::wmi_ref_key(fref));
        match com::wmi_get(&svc, fref) {
            Ok(f) => filters.push(WmiObjectDump {
                path: com::prop_string(&f, "__RELPATH").unwrap_or_else(|| fref.clone()),
                mof: com::object_text(&f)?,
                deleted: !shared,
            }),
            Err(_) => filters.push(WmiObjectDump {
                path: fref.clone(),
                mof: String::new(),
                deleted: false,
            }),
        }
    }
    let id = backup(
        ctx,
        AutorunKind::WmiSubscription,
        &name,
        None,
        BackupData::Wmi {
            consumer: WmiObjectDump {
                path: cpath.clone(),
                mof: cmof.clone(),
                deleted: true,
            },
            bindings: bindings.clone(),
            filters: filters.clone(),
        },
    )?;
    // Re-read the consumer right before acting.
    match com::wmi_get(&svc, &cpath).and_then(|c| com::object_text(&c)) {
        Ok(m) if m == cmof => {}
        _ => {
            return Ok((
                false,
                format!("WMI consumer {cpath} changed or disappeared after the backup; not touched (backup {id})"),
                Some(id),
            ))
        }
    }
    let mut errs = Vec::new();
    let mut done = Vec::new();
    for b in &bindings {
        match com::wmi_delete(&svc, &b.path) {
            Ok(()) => done.push(format!("binding {}", b.path)),
            Err(e) => errs.push(e),
        }
    }
    // Only delete the consumer once nothing points at it any more.
    if errs.is_empty() {
        match com::wmi_delete(&svc, &cpath) {
            Ok(()) => done.push(format!("consumer {cpath}")),
            Err(e) => errs.push(e),
        }
    }
    let mut kept = Vec::new();
    for f in filters.iter() {
        if !f.deleted {
            kept.push(f.path.clone());
            continue;
        }
        if errs.is_empty() {
            match com::wmi_delete(&svc, &f.path) {
                Ok(()) => done.push(format!("filter {}", f.path)),
                Err(e) => errs.push(e),
            }
        }
    }
    let mut d = format!("WMI subscription removed: [{}]", done.join(", "));
    if !kept.is_empty() {
        d.push_str(&format!(
            "; filters kept (used by other bindings): [{}]",
            kept.join(", ")
        ));
    }
    if !errs.is_empty() {
        d.push_str(&format!("; errors: {}", errs.join("; ")));
    }
    d.push_str(&format!("; MOF backed up as {id}"));
    Ok((errs.is_empty(), d, Some(id)))
}
