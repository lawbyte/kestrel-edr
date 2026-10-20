//! Host facts: OS info, hostname, boot time, IPs/DNS servers, AV product,
//! logged-on user, agent CPU/memory, user profiles.

use super::util::*;
use crate::consts::reg;
use crate::hostfacts::{self, BootRecord};
use kestrel_common::wire::OsInfo;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::Networking::WinSock::SOCKET_ADDRESS;
use windows_sys::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows_sys::Win32::System::RemoteDesktop::{
    WTSActive, WTSDomainName, WTSEnumerateSessionsW, WTSFreeMemory, WTSGetActiveConsoleSessionId,
    WTSQuerySessionInformationW, WTSUserName, WTS_SESSION_INFOW,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNameDnsDomain, ComputerNamePhysicalDnsHostname, GetComputerNameExW,
    GetNativeSystemInfo, GetSystemFirmwareTable, GetSystemTimeAsFileTime, GetTickCount64,
    OSVERSIONINFOW, SYSTEM_INFO,
};

fn computer_name(kind: i32) -> Option<String> {
    let mut buf = vec![0u16; 512];
    let mut n = buf.len() as u32;
    if unsafe { GetComputerNameExW(kind, buf.as_mut_ptr(), &mut n) } == 0 {
        return None;
    }
    let s = String::from_utf16_lossy(&buf[..n as usize]);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

pub fn hostname() -> String {
    computer_name(ComputerNamePhysicalDnsHostname)
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .unwrap_or_default()
}

fn rtl_version() -> Option<(u32, u32, u32)> {
    type F = unsafe extern "system" fn(*mut OSVERSIONINFOW) -> i32;
    let f = sys_proc("ntdll.dll", "RtlGetVersion")?;
    let f: F = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, F>(f) };
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    if unsafe { f(&mut v) } != 0 {
        return None;
    }
    Some((v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber))
}

pub fn ncpu() -> u32 {
    let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut si) };
    si.dwNumberOfProcessors.max(1)
}

pub fn os_info() -> OsInfo {
    let (maj, min, build) = rtl_version().unwrap_or((10, 0, 0));
    let cv = reg_open(HKEY_LOCAL_MACHINE, reg::CURRENT_VERSION, false);
    let product = cv
        .as_ref()
        .and_then(|k| reg_get_string(k, "ProductName"))
        .unwrap_or_else(|| "Windows".into());
    let ubr = cv
        .as_ref()
        .and_then(|k| reg_get_dword(k, "UBR"))
        .unwrap_or(0);
    let mut si: SYSTEM_INFO = unsafe { std::mem::zeroed() };
    unsafe { GetNativeSystemInfo(&mut si) };
    let arch = match unsafe { si.Anonymous.Anonymous.wProcessorArchitecture } {
        9 => "x86_64",
        12 => "aarch64",
        0 => "x86",
        5 => "arm",
        _ => "unknown",
    };
    OsInfo {
        name: hostfacts::product_name(&product, build),
        build: format!("{maj}.{min}.{build}.{ubr}"),
        arch: arch.into(),
        domain: computer_name(ComputerNameDnsDomain),
        hw_uuid: hw_uuid(),
    }
}

fn hw_uuid() -> Option<String> {
    const RSMB: u32 = u32::from_be_bytes(*b"RSMB");
    let n = unsafe { GetSystemFirmwareTable(RSMB, 0, std::ptr::null_mut(), 0) };
    if n > 0 {
        let mut buf = vec![0u8; n as usize];
        let got = unsafe { GetSystemFirmwareTable(RSMB, 0, buf.as_mut_ptr(), n) };
        if got > 0 {
            buf.truncate(got as usize);
            if let Some(u) = hostfacts::smbios_uuid(&buf) {
                return Some(u);
            }
        }
    }
    reg_open(HKEY_LOCAL_MACHINE, reg::MACHINE_GUID_KEY, false)
        .and_then(|k| reg_get_string(&k, "MachineGuid"))
}

/// Kernel boot time (ms since epoch) from SystemTimeOfDayInformation, with a
/// GetTickCount64 fallback.
pub fn boot_time_ms() -> i64 {
    #[repr(C)]
    struct TimeOfDay {
        boot_time: i64,
        current_time: i64,
        tz_bias: i64,
        tz_id: u32,
        reserved: u32,
        boot_time_bias: u64,
        sleep_time_bias: u64,
    }
    type F = unsafe extern "system" fn(i32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
    if let Some(f) = sys_proc("ntdll.dll", "NtQuerySystemInformation") {
        let f: F = unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, F>(f) };
        let mut t: TimeOfDay = unsafe { std::mem::zeroed() };
        let mut ret = 0u32;
        let st = unsafe {
            f(
                3,
                &mut t as *mut _ as *mut std::ffi::c_void,
                std::mem::size_of::<TimeOfDay>() as u32,
                &mut ret,
            )
        };
        if st == 0 && t.boot_time > 0 {
            return crate::etwparse::filetime_to_ms(t.boot_time as u64);
        }
    }
    let mut ft = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    unsafe { GetSystemTimeAsFileTime(&mut ft) };
    crate::etwparse::filetime_to_ms(ft_u64(&ft)) - unsafe { GetTickCount64() } as i64
}

pub fn boot_record(state_dir: &Path) -> BootRecord {
    let path = state_dir.join("boot.json");
    let prev = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<BootRecord>(&b).ok());
    let rec = hostfacts::resolve_boot_id(prev.clone(), boot_time_ms());
    if prev.as_ref() != Some(&rec) {
        if let Ok(b) = serde_json::to_vec(&rec) {
            let _ = write_atomic(&path, &b);
        }
    }
    rec
}

unsafe fn sockaddr_ip(sa: &SOCKET_ADDRESS) -> Option<IpAddr> {
    if sa.lpSockaddr.is_null() {
        return None;
    }
    let p = sa.lpSockaddr as *const u8;
    let family = u16::from_le_bytes([*p, *p.add(1)]);
    match family {
        2 if sa.iSockaddrLength >= 8 => Some(IpAddr::V4(Ipv4Addr::new(
            *p.add(4),
            *p.add(5),
            *p.add(6),
            *p.add(7),
        ))),
        23 if sa.iSockaddrLength >= 24 => {
            let mut b = [0u8; 16];
            std::ptr::copy_nonoverlapping(p.add(8), b.as_mut_ptr(), 16);
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// (unicast addresses of up adapters, DNS servers of up adapters)
pub fn adapters() -> (Vec<IpAddr>, Vec<IpAddr>) {
    let mut ips = Vec::new();
    let mut dns = Vec::new();
    let mut size = 32 * 1024u32;
    for _ in 0..3 {
        let mut buf = vec![0u64; (size as usize).div_ceil(8)];
        let rc = unsafe {
            GetAdaptersAddresses(
                0,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH,
                &mut size,
            )
        };
        if rc == 111 {
            continue; // ERROR_BUFFER_OVERFLOW: size updated
        }
        if rc != 0 {
            break;
        }
        unsafe {
            let mut a = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
            while !a.is_null() {
                let ad = &*a;
                if ad.OperStatus == 1 && ad.IfType != 24 {
                    let mut u = ad.FirstUnicastAddress;
                    while !u.is_null() {
                        if let Some(ip) = sockaddr_ip(&(*u).Address) {
                            let skip = ip.is_loopback()
                                || matches!(ip, IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfe80);
                            if !skip && !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                        u = (*u).Next;
                    }
                    let mut d = ad.FirstDnsServerAddress;
                    while !d.is_null() {
                        if let Some(ip) = sockaddr_ip(&(*d).Address) {
                            // fec0:0:0:ffff::1-3 are the obsolete site-local defaults; skip.
                            let site_local =
                                matches!(ip, IpAddr::V6(v6) if v6.segments()[0] == 0xfec0);
                            if !site_local && !dns.contains(&ip) {
                                dns.push(ip);
                            }
                        }
                        d = (*d).Next;
                    }
                }
                a = ad.Next;
            }
        }
        break;
    }
    (ips, dns)
}

unsafe fn wts_string(session: u32, class: i32) -> Option<String> {
    let mut p: *mut u16 = std::ptr::null_mut();
    let mut n = 0u32;
    if WTSQuerySessionInformationW(std::ptr::null_mut(), session, class, &mut p, &mut n) == 0
        || p.is_null()
    {
        return None;
    }
    let s = from_wide_ptr(p);
    WTSFreeMemory(p as *mut std::ffi::c_void);
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn session_user(session: u32) -> Option<String> {
    unsafe {
        let user = wts_string(session, WTSUserName)?;
        Some(match wts_string(session, WTSDomainName) {
            Some(d) => format!("{d}\\{user}"),
            None => user,
        })
    }
}

/// User on the active console session, else the first active (RDP) session.
pub fn logged_on_user() -> Option<String> {
    let console = unsafe { WTSGetActiveConsoleSessionId() };
    if console != 0xFFFF_FFFF {
        if let Some(u) = session_user(console) {
            return Some(u);
        }
    }
    unsafe {
        let mut p: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut n = 0u32;
        if WTSEnumerateSessionsW(std::ptr::null_mut(), 0, 1, &mut p, &mut n) == 0 {
            return None;
        }
        let mut out = None;
        for i in 0..n as usize {
            let s = &*p.add(i);
            if s.State == WTSActive {
                if let Some(u) = session_user(s.SessionId) {
                    out = Some(u);
                    break;
                }
            }
        }
        WTSFreeMemory(p as *mut std::ffi::c_void);
        out
    }
}

/// Profile directories of real users (local, domain and Entra ID accounts).
pub fn user_profiles() -> Vec<String> {
    let Some(k) = reg_open(HKEY_LOCAL_MACHINE, reg::PROFILE_LIST, false) else {
        return vec![];
    };
    let mut out = Vec::new();
    for sid in reg_subkeys(&k) {
        if !(sid.starts_with("S-1-5-21-") || sid.starts_with("S-1-12-1-")) || sid.ends_with(".bak")
        {
            continue;
        }
        let Some(sk) = reg_open(
            HKEY_LOCAL_MACHINE,
            &format!(r"{}\{sid}", reg::PROFILE_LIST),
            false,
        ) else {
            continue;
        };
        let Some(p) = reg_get_string(&sk, "ProfileImagePath") else {
            continue;
        };
        let p = crate::ntpath::expand_env(&p, |n| std::env::var(n).ok());
        if Path::new(&p).is_dir() && !out.contains(&p) {
            out.push(p);
        }
    }
    out
}

/// Active AV from Security Center (PowerShell CIM query), cached 10 min and
/// refreshed in the background so callers never block.
pub struct AvCache {
    value: RwLock<Option<String>>,
    fetched: Mutex<Option<Instant>>,
    refreshing: AtomicBool,
}

impl AvCache {
    pub fn new() -> Arc<AvCache> {
        Arc::new(AvCache {
            value: RwLock::new(None),
            fetched: Mutex::new(None),
            refreshing: AtomicBool::new(false),
        })
    }

    pub fn query_blocking() -> Option<String> {
        let script = "$ErrorActionPreference='SilentlyContinue'; \
            $p=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | ForEach-Object { @{n=[string]$_.displayName; s=[uint32]$_.productState} }); \
            ConvertTo-Json -Compress -InputObject $p";
        let rows: Vec<(String, u32)> = run_powershell(script, Duration::from_secs(60))
            .ok()
            .and_then(|o| serde_json::from_str::<serde_json::Value>(o.stdout.trim()).ok())
            .map(|v| {
                let arr = match v {
                    serde_json::Value::Array(a) => a,
                    other => vec![other],
                };
                arr.iter()
                    .filter_map(|e| {
                        Some((
                            e.get("n")?.as_str()?.to_string(),
                            e.get("s")?.as_u64()? as u32,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(av) = hostfacts::pick_active_av(&rows) {
            return Some(av);
        }
        // Servers have no Security Center: fall back to the Defender service.
        let sc = format!(r"{}\System32\sc.exe", system_root());
        match run_cmd(&sc, &["query", "WinDefend"], Duration::from_secs(15)) {
            Ok(o) if o.stdout.contains("RUNNING") => Some("Microsoft Defender Antivirus".into()),
            _ => None,
        }
    }

    pub fn get(self: &Arc<Self>) -> Option<String> {
        let stale = self
            .fetched
            .lock()
            .map(|f| {
                f.map(|t| t.elapsed() > Duration::from_secs(600))
                    .unwrap_or(true)
            })
            .unwrap_or(true);
        if stale && !self.refreshing.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            let _ = std::thread::Builder::new()
                .name("kestrel-av".into())
                .spawn(move || {
                    let v = AvCache::query_blocking();
                    if let Ok(mut w) = me.value.write() {
                        *w = v;
                    }
                    if let Ok(mut f) = me.fetched.lock() {
                        *f = Some(Instant::now());
                    }
                    me.refreshing.store(false, Ordering::SeqCst);
                });
        }
        self.value.read().ok().and_then(|v| v.clone())
    }
}

/// CPU % (normalised to all CPUs) and working set MB of this process.
pub struct SelfUsage {
    last: Mutex<Option<(u64, Instant)>>,
    ncpu: u32,
}

impl SelfUsage {
    pub fn new() -> SelfUsage {
        SelfUsage {
            last: Mutex::new(None),
            ncpu: ncpu(),
        }
    }

    pub fn sample(&self) -> (f32, u64) {
        let h = current_process();
        let cpu = process_cpu_time(h).unwrap_or(0);
        let now = Instant::now();
        let pct = match self.last.lock() {
            Ok(mut l) => {
                let p = match *l {
                    Some((prev_cpu, prev_t)) => {
                        let wall = now.duration_since(prev_t).as_nanos() as u64 / 100;
                        hostfacts::cpu_pct(prev_cpu, 0, cpu, wall, self.ncpu)
                    }
                    None => 0.0,
                };
                *l = Some((cpu, now));
                p
            }
            Err(_) => 0.0,
        };
        let mut pmc: PROCESS_MEMORY_COUNTERS = unsafe { std::mem::zeroed() };
        pmc.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        let mb = if unsafe { K32GetProcessMemoryInfo(h, &mut pmc, pmc.cb) } != 0 {
            (pmc.WorkingSetSize / (1024 * 1024)) as u64
        } else {
            0
        };
        (pct, mb)
    }
}
