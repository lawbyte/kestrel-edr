//! Small Win32 helpers shared by the Windows modules.

#![allow(clippy::missing_safety_doc)]

use kestrel_common::Integrity;
use std::ffi::c_void;
use std::io;
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SUCCESS, FILETIME, HANDLE, INVALID_HANDLE_VALUE, LUID,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    LookupAccountSidW, LookupPrivilegeValueW, TokenIntegrityLevel, TokenUser, LUID_AND_ATTRIBUTES,
    PSID, SE_PRIVILEGE_ENABLED, SID_NAME_USE, TOKEN_ADJUST_PRIVILEGES, TOKEN_MANDATORY_LABEL,
    TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegEnumKeyExW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW, HKEY, KEY_READ, KEY_WOW64_64KEY, KEY_WRITE, REG_DWORD, REG_EXPAND_SZ,
    REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// UTF-16, NUL-terminated.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn wide_path(p: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

pub unsafe fn from_wide_ptr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut n = 0;
    while *p.add(n) != 0 {
        n += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
}

pub fn last_err() -> io::Error {
    io::Error::last_os_error()
}

pub fn win32_err(code: u32) -> io::Error {
    io::Error::from_raw_os_error(code as i32)
}

pub fn ft_u64(ft: &FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | ft.dwLowDateTime as u64
}

/// Owned kernel handle.
pub struct Handle(pub HANDLE);

impl Handle {
    pub fn new(h: HANDLE) -> Option<Handle> {
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Handle(h))
        }
    }
    pub fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

// SAFETY: kernel handles may be used from any thread.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

/// Resolve an export from an already-loaded system DLL (ntdll/kernel32).
pub fn sys_proc(module: &str, name: &str) -> Option<unsafe extern "system" fn() -> isize> {
    let m = wide(module);
    let cname = std::ffi::CString::new(name).ok()?;
    unsafe {
        let h = GetModuleHandleW(m.as_ptr());
        if h.is_null() {
            return None;
        }
        GetProcAddress(h, cname.as_ptr() as *const u8)
    }
}

// ------------------------------------------------------------- processes

pub fn open_process(pid: u32, access: u32) -> Option<Handle> {
    Handle::new(unsafe { OpenProcess(access, 0, pid) })
}

/// Process creation time as FILETIME u64.
pub fn process_create_time(h: &Handle) -> Option<u64> {
    let mut c = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut e = c;
    let mut k = c;
    let mut u = c;
    let ok = unsafe { GetProcessTimes(h.raw(), &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 {
        None
    } else {
        Some(ft_u64(&c))
    }
}

/// (kernel + user) CPU time in 100 ns.
pub fn process_cpu_time(h: HANDLE) -> Option<u64> {
    let mut c = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut e = c;
    let mut k = c;
    let mut u = c;
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 {
        None
    } else {
        Some(ft_u64(&k) + ft_u64(&u))
    }
}

pub fn current_process() -> HANDLE {
    unsafe { GetCurrentProcess() }
}

pub fn process_image(h: &Handle) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe {
        QueryFullProcessImageNameW(h.raw(), PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len)
    };
    if ok == 0 {
        None
    } else {
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}

/// Command line via NtQueryInformationProcess(ProcessCommandLineInformation)
/// (Windows 8.1+, works with PROCESS_QUERY_LIMITED_INFORMATION).
pub fn process_cmdline(h: &Handle) -> Option<String> {
    use windows_sys::Wdk::System::Threading::{
        NtQueryInformationProcess, ProcessCommandLineInformation,
    };
    let mut buf = vec![0u8; 4096];
    for _ in 0..4 {
        let mut ret = 0u32;
        let st = unsafe {
            NtQueryInformationProcess(
                h.raw(),
                ProcessCommandLineInformation,
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                &mut ret,
            )
        };
        if st == 0 {
            // UNICODE_STRING { Length: u16, MaximumLength: u16, (pad), Buffer: *const u16 } followed by the data.
            #[repr(C)]
            struct Us {
                len: u16,
                max: u16,
                buf: *const u16,
            }
            let us = unsafe { &*(buf.as_ptr() as *const Us) };
            if us.buf.is_null() || us.len == 0 {
                return Some(String::new());
            }
            let s = unsafe { std::slice::from_raw_parts(us.buf, (us.len / 2) as usize) };
            return Some(String::from_utf16_lossy(s));
        }
        // STATUS_INFO_LENGTH_MISMATCH / BUFFER_OVERFLOW / BUFFER_TOO_SMALL
        if (st as u32 == 0xC000_0004 || st as u32 == 0x8000_0005 || st as u32 == 0xC000_0023)
            && ret as usize > buf.len()
        {
            buf.resize(ret as usize + 16, 0);
            continue;
        }
        return None;
    }
    None
}

/// Token user SID string + integrity of a process.
pub fn process_token_info(h: &Handle) -> (Option<String>, Option<Integrity>) {
    let mut tok: HANDLE = std::ptr::null_mut();
    if unsafe { OpenProcessToken(h.raw(), TOKEN_QUERY, &mut tok) } == 0 {
        return (None, None);
    }
    let tok = Handle(tok);
    let sid = token_info(&tok, TokenUser).and_then(|b| {
        let tu = unsafe { &*(b.as_ptr() as *const TOKEN_USER) };
        sid_to_string(tu.User.Sid)
    });
    let integ = token_info(&tok, TokenIntegrityLevel).and_then(|b| {
        let ml = unsafe { &*(b.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
        sid_rid(ml.Label.Sid).map(crate::etwparse::integrity_from_rid)
    });
    (sid, integ)
}

fn token_info(tok: &Handle, class: i32) -> Option<Vec<u64>> {
    let mut need = 0u32;
    unsafe { GetTokenInformation(tok.raw(), class, std::ptr::null_mut(), 0, &mut need) };
    if need == 0 {
        return None;
    }
    // u64 storage for alignment.
    let mut buf = vec![0u64; (need as usize).div_ceil(8)];
    let ok = unsafe {
        GetTokenInformation(
            tok.raw(),
            class,
            buf.as_mut_ptr() as *mut c_void,
            need,
            &mut need,
        )
    };
    if ok == 0 {
        None
    } else {
        Some(buf)
    }
}

pub fn sid_rid(sid: PSID) -> Option<u32> {
    unsafe {
        if sid.is_null() {
            return None;
        }
        let cnt = *GetSidSubAuthorityCount(sid);
        if cnt == 0 {
            return None;
        }
        Some(*GetSidSubAuthority(sid, (cnt - 1) as u32))
    }
}

pub fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_null() {
        return None;
    }
    let mut p: *mut u16 = std::ptr::null_mut();
    unsafe {
        if ConvertSidToStringSidW(sid, &mut p) == 0 {
            return None;
        }
        let s = from_wide_ptr(p);
        LocalFree(p as *mut c_void);
        Some(s)
    }
}

/// SID string → "DOMAIN\user" (may block on domain lookups: call off hot paths).
pub fn lookup_sid_string(sid: &str) -> Option<String> {
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    let w = wide(sid);
    let mut psid: PSID = std::ptr::null_mut();
    unsafe {
        if ConvertStringSidToSidW(w.as_ptr(), &mut psid) == 0 {
            return None;
        }
        let r = lookup_account(psid);
        LocalFree(psid);
        r
    }
}

pub fn lookup_account(sid: PSID) -> Option<String> {
    let mut name = vec![0u16; 256];
    let mut dom = vec![0u16; 256];
    let mut nl = name.len() as u32;
    let mut dl = dom.len() as u32;
    let mut use_: SID_NAME_USE = 0;
    let ok = unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut nl,
            dom.as_mut_ptr(),
            &mut dl,
            &mut use_,
        )
    };
    if ok == 0 {
        return None;
    }
    let n = from_wide(&name);
    let d = from_wide(&dom);
    Some(if d.is_empty() { n } else { format!("{d}\\{n}") })
}

/// Enable a privilege (e.g. "SeBackupPrivilege") in the current process token.
pub fn enable_privilege(name: &str) -> bool {
    let mut tok: HANDLE = std::ptr::null_mut();
    unsafe {
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut tok,
        ) == 0
        {
            return false;
        }
        let tok = Handle(tok);
        let w = wide(name);
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        if LookupPrivilegeValueW(std::ptr::null(), w.as_ptr(), &mut luid) == 0 {
            return false;
        }
        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        if AdjustTokenPrivileges(
            tok.raw(),
            0,
            &tp,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        ) == 0
        {
            return false;
        }
        // ERROR_NOT_ALL_ASSIGNED is reported via GetLastError with success return.
        windows_sys::Win32::Foundation::GetLastError() == ERROR_SUCCESS
    }
}

/// Basic info about a live process (for snapshot / response checks).
pub struct LiveProc {
    pub create_ft: u64,
    pub image: Option<String>,
}

pub fn live_proc(pid: u32) -> Option<LiveProc> {
    let h = open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let create_ft = process_create_time(&h)?;
    Some(LiveProc {
        create_ft,
        image: process_image(&h),
    })
}

// ------------------------------------------------------------- files

/// The system Windows directory (`C:\Windows`) from
/// `GetSystemWindowsDirectoryW`. Never `%SystemRoot%`: the environment is
/// caller-controlled for the CLI and any child we build paths for (V-H1).
pub fn system_root() -> String {
    use windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW;
    static ROOT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| {
        let mut buf = vec![0u16; 512];
        let n = unsafe { GetSystemWindowsDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 || n as usize >= buf.len() {
            return r"C:\Windows".to_string();
        }
        String::from_utf16_lossy(&buf[..n as usize])
            .trim_end_matches('\\')
            .to_string()
    })
    .clone()
}

// ------------------------------------------------------------- registry

pub struct RegKey(pub HKEY);

impl Drop for RegKey {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

pub fn reg_open(root: HKEY, path: &str, write: bool) -> Option<RegKey> {
    let w = wide(path);
    let mut h: HKEY = std::ptr::null_mut();
    let access = if write {
        KEY_READ | KEY_WRITE
    } else {
        KEY_READ
    } | KEY_WOW64_64KEY;
    let rc = unsafe { RegOpenKeyExW(root, w.as_ptr(), 0, access, &mut h) };
    if rc == ERROR_SUCCESS {
        Some(RegKey(h))
    } else {
        None
    }
}

pub fn reg_create(root: HKEY, path: &str) -> io::Result<RegKey> {
    let w = wide(path);
    let mut h: HKEY = std::ptr::null_mut();
    let rc = unsafe {
        RegCreateKeyExW(
            root,
            w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE | KEY_WOW64_64KEY,
            std::ptr::null(),
            &mut h,
            std::ptr::null_mut(),
        )
    };
    if rc == ERROR_SUCCESS {
        Ok(RegKey(h))
    } else {
        Err(win32_err(rc))
    }
}

fn reg_query_raw(k: &RegKey, name: &str) -> Option<(REG_VALUE_TYPE, Vec<u8>)> {
    let w = wide(name);
    let mut ty: REG_VALUE_TYPE = 0;
    let mut len = 0u32;
    unsafe {
        if RegQueryValueExW(
            k.0,
            w.as_ptr(),
            std::ptr::null(),
            &mut ty,
            std::ptr::null_mut(),
            &mut len,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        let mut buf = vec![0u8; len as usize + 2];
        len = buf.len() as u32;
        if RegQueryValueExW(
            k.0,
            w.as_ptr(),
            std::ptr::null(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        ) != ERROR_SUCCESS
        {
            return None;
        }
        buf.truncate(len as usize);
        Some((ty, buf))
    }
}

pub fn reg_get_dword(k: &RegKey, name: &str) -> Option<u32> {
    let (ty, b) = reg_query_raw(k, name)?;
    if ty == REG_DWORD && b.len() >= 4 {
        Some(u32::from_le_bytes(b[..4].try_into().ok()?))
    } else if ty == REG_SZ {
        crate::etwparse::utf16le(&b).trim().parse().ok()
    } else {
        None
    }
}

pub fn reg_get_string(k: &RegKey, name: &str) -> Option<String> {
    let (ty, b) = reg_query_raw(k, name)?;
    if ty == REG_SZ || ty == REG_EXPAND_SZ {
        Some(crate::etwparse::utf16le(&b))
    } else {
        None
    }
}

pub fn reg_set_dword(k: &RegKey, name: &str, v: u32) -> io::Result<()> {
    let w = wide(name);
    let rc = unsafe { RegSetValueExW(k.0, w.as_ptr(), 0, REG_DWORD, v.to_le_bytes().as_ptr(), 4) };
    if rc == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(win32_err(rc))
    }
}

pub fn reg_delete_value(k: &RegKey, name: &str) -> bool {
    let w = wide(name);
    unsafe { RegDeleteValueW(k.0, w.as_ptr()) == ERROR_SUCCESS }
}

pub fn reg_subkeys(k: &RegKey) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut name = vec![0u16; 512];
        let mut len = name.len() as u32;
        let rc = unsafe {
            RegEnumKeyExW(
                k.0,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc != ERROR_SUCCESS {
            break;
        }
        out.push(String::from_utf16_lossy(&name[..len as usize]));
        i += 1;
    }
    out
}

/// Value names + string rendering of every value in a key (for triage).
pub fn reg_values(k: &RegKey) -> Vec<(String, String)> {
    use windows_sys::Win32::System::Registry::RegEnumValueW;
    let mut out = Vec::new();
    let mut i = 0u32;
    loop {
        let mut name = vec![0u16; 16384];
        let mut nlen = name.len() as u32;
        let mut ty: REG_VALUE_TYPE = 0;
        let mut data = vec![0u8; 8192];
        let mut dlen = data.len() as u32;
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
            break;
        }
        data.truncate(dlen as usize);
        let n = String::from_utf16_lossy(&name[..nlen as usize]);
        out.push((
            n,
            crate::etwparse::render_reg_data(ty, &data).unwrap_or_default(),
        ));
        i += 1;
    }
    out
}

// ------------------------------------------------------------- child processes

pub struct CmdOutput {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Run a program without a window, with a timeout (killed on expiry). The
/// child is recorded in [`crate::spawnreg`] (pid + creation time) so its
/// ProcessStart is recognised as the agent's own (V-H1). `exe` must be an
/// absolute path built from [`system_root`] or the agent's own folder.
pub fn run_cmd(exe: &str, args: &[&str], timeout: Duration) -> io::Result<CmdOutput> {
    let mut child = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    crate::spawnreg::record_child(&child);
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let t_out = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(o) = out.as_mut() {
            let _ = std::io::Read::read_to_end(o, &mut s);
        }
        s
    });
    let t_err = std::thread::spawn(move || {
        let mut s = Vec::new();
        if let Some(e) = err.as_mut() {
            let _ = std::io::Read::read_to_end(e, &mut s);
        }
        s
    });
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("{exe} timed out"),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    Ok(CmdOutput {
        code: status.code().unwrap_or(-1),
        stdout,
        stderr,
    })
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[(n >> 18) as usize & 63] as char);
        s.push(T[(n >> 12) as usize & 63] as char);
        s.push(if c.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        s.push(if c.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    s
}

/// Run a PowerShell script (Windows PowerShell 5.1, by absolute path) via
/// -EncodedCommand so no quoting issues and no script file on disk.
pub fn run_powershell(script: &str, timeout: Duration) -> io::Result<CmdOutput> {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let exe = format!(
        r"{}\System32\WindowsPowerShell\v1.0\powershell.exe",
        system_root()
    );
    let enc = base64(&utf16);
    run_cmd(
        &exe,
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &enc,
        ],
        timeout,
    )
}

/// Single-quote a string for PowerShell.
pub fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

// ------------------------------------------------------------- security descriptors

/// Security descriptor allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
pub struct LocalSd(pub windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

impl Drop for LocalSd {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

unsafe impl Send for LocalSd {}
unsafe impl Sync for LocalSd {}

pub fn sd_from_sddl(sddl: &str) -> Option<LocalSd> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    let w = wide(sddl);
    let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        None
    } else {
        Some(LocalSd(sd))
    }
}

/// Owner + group + DACL of an open handle as SDDL.
pub fn sddl_of_handle(h: HANDLE) -> Option<String> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    };
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    unsafe {
        let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(
            h,
            SE_FILE_OBJECT,
            info,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS || sd.is_null() {
            return None;
        }
        let sd = LocalSd(sd);
        let mut s: *mut u16 = std::ptr::null_mut();
        if ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.0,
            SDDL_REVISION_1,
            info,
            &mut s,
            std::ptr::null_mut(),
        ) == 0
        {
            return None;
        }
        let out = from_wide_ptr(s);
        LocalFree(s as *mut c_void);
        Some(out)
    }
}

/// Apply owner/group/DACL from SDDL to a file or directory. With `protect`,
/// the DACL is marked protected (no inheritance from the parent).
pub fn apply_sddl(path: &Path, sddl: &str, protect: bool) -> io::Result<()> {
    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, ACL,
        DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sd = sd_from_sddl(sddl)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SDDL"))?;
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut group: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted);
        GetSecurityDescriptorGroup(sd.0, &mut group, &mut defaulted);
        GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted);
        let mut info = 0;
        if !owner.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        if !group.is_null() {
            info |= GROUP_SECURITY_INFORMATION;
        }
        if present != 0 {
            info |= DACL_SECURITY_INFORMATION;
            if protect {
                info |= PROTECTED_DACL_SECURITY_INFORMATION;
            }
        }
        let w = wide_path(path);
        let rc = SetNamedSecurityInfoW(
            w.as_ptr(),
            SE_FILE_OBJECT,
            info,
            owner,
            group,
            dacl,
            std::ptr::null(),
        );
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32_err(rc))
        }
    }
}

/// Owner SYSTEM; SYSTEM + Administrators full control only (protected) —
/// agent state dirs (H4: the owner is set explicitly, so a pre-existing
/// user-owned directory does not keep WRITE_DAC through ownership).
pub const SDDL_ADMIN_ONLY_DIR: &str = "O:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub fn ensure_private_dir(path: &Path) -> io::Result<()> {
    std::fs::create_dir_all(path)?;
    apply_sddl(path, SDDL_ADMIN_ONLY_DIR, true)
}

/// Write a file atomically (temp + rename).
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp-kestrel");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}
