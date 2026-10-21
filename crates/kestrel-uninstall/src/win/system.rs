//! System queries and the Windows Installer call.

use super::{from_wide, purge, wide, Handle};
use crate::{find_product, is_guid, log_file_name, msi_properties_wide, wipe_wide, UPGRADE_CODE};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{
    ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS, HANDLE, SYSTEMTIME,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetTempPathW, MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT,
};
use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
    MsiConfigureProductExW, MsiEnableLogW, MsiEnumRelatedProductsW, MsiQueryProductStateW,
    MsiSetInternalUI, INSTALLLEVEL_DEFAULT, INSTALLLOGATTRIBUTES_FLUSHEACHLINE,
    INSTALLLOGMODE_ACTIONDATA, INSTALLLOGMODE_ACTIONSTART, INSTALLLOGMODE_COMMONDATA,
    INSTALLLOGMODE_ERROR, INSTALLLOGMODE_FATALEXIT, INSTALLLOGMODE_INFO,
    INSTALLLOGMODE_OUTOFDISKSPACE, INSTALLLOGMODE_PROPERTYDUMP, INSTALLLOGMODE_RESOLVESOURCE,
    INSTALLLOGMODE_USER, INSTALLLOGMODE_VERBOSE, INSTALLLOGMODE_WARNING, INSTALLSTATE_ABSENT,
    INSTALLSTATE_DEFAULT, INSTALLUILEVEL_NONE,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegEnumKeyExW, RegGetValueW, RegOpenKeyExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ,
    KEY_WOW64_64KEY, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY,
};
use windows_sys::Win32::System::SystemInformation::GetLocalTime;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

/// Does this process run with a full administrator token?
pub fn is_elevated() -> bool {
    let mut t: HANDLE = std::ptr::null_mut();
    // SAFETY: pseudo-handle of the current process; out pointer is valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut t) } == 0 {
        return false;
    }
    let Some(t) = Handle::new(t) else {
        return false;
    };
    let mut e = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut len = 0u32;
    // SAFETY: buffer is a TOKEN_ELEVATION of the size passed.
    let ok = unsafe {
        GetTokenInformation(
            t.raw(),
            TokenElevation,
            &mut e as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    } != 0;
    ok && e.TokenIsElevated != 0
}

const UNINSTALL_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

/// `(subkey name, DisplayName)` of every entry in the 64-bit HKLM
/// Uninstall key.
fn uninstall_entries() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut key: HKEY = std::ptr::null_mut();
    let path = wide(UNINSTALL_KEY);
    // SAFETY: valid strings and out pointer.
    let rc = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            path.as_ptr(),
            0,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if rc != ERROR_SUCCESS {
        return out;
    }
    let value = wide("DisplayName");
    for i in 0..10_000u32 {
        let mut name = [0u16; 256];
        let mut len = name.len() as u32;
        // SAFETY: buffer and length match.
        let rc = unsafe {
            RegEnumKeyExW(
                key,
                i,
                name.as_mut_ptr(),
                &mut len,
                std::ptr::null(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        if rc == ERROR_NO_MORE_ITEMS {
            break;
        }
        if rc != ERROR_SUCCESS {
            continue;
        }
        let sub = String::from_utf16_lossy(&name[..len as usize]);
        let subw = wide(&sub);
        let mut buf = [0u16; 512];
        let mut cb = (buf.len() * 2) as u32;
        // SAFETY: buffer size in bytes is passed.
        let rc = unsafe {
            RegGetValueW(
                key,
                subw.as_ptr(),
                value.as_ptr(),
                RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
                std::ptr::null_mut(),
                buf.as_mut_ptr() as *mut _,
                &mut cb,
            )
        };
        if rc == ERROR_SUCCESS {
            out.push((sub, from_wide(&buf)));
        } else if rc == ERROR_MORE_DATA {
            // Longer than any Kestrel display name: not ours.
            continue;
        }
    }
    // SAFETY: opened above.
    unsafe { RegCloseKey(key) };
    out
}

/// Products registered under Kestrel's UpgradeCode.
fn related_products() -> Vec<String> {
    let uc = wide(UPGRADE_CODE);
    let mut out = Vec::new();
    for i in 0..64u32 {
        let mut buf = [0u16; 39];
        // SAFETY: 39-character buffer as the API requires.
        let rc = unsafe { MsiEnumRelatedProductsW(uc.as_ptr(), 0, i, buf.as_mut_ptr()) };
        if rc != ERROR_SUCCESS {
            break;
        }
        let pc = from_wide(&buf);
        if is_guid(&pc) {
            out.push(pc);
        }
    }
    out
}

/// Product code of the installed Kestrel agent, if any: the Uninstall entry
/// named "Kestrel EDR Agent" whose product code is also registered under
/// Kestrel's UpgradeCode (another product with the same name never gets
/// the token).
pub fn installed_product() -> Option<String> {
    let related = related_products();
    let entries = uninstall_entries();
    find_product(
        entries
            .iter()
            .filter(|(k, _)| related.iter().any(|r| r.eq_ignore_ascii_case(k)))
            .map(|(k, n)| (k.as_str(), n.as_str())),
    )
}

/// Is `product_code` still installed (Windows Installer state or the
/// Uninstall entry)?
pub fn still_installed(product_code: &str) -> bool {
    let pc = wide(product_code);
    // SAFETY: valid NUL-terminated string.
    let state = unsafe { MsiQueryProductStateW(pc.as_ptr()) };
    state == INSTALLSTATE_DEFAULT || installed_product().is_some()
}

/// `%ProgramData%\Kestrel` from the known-folder API (not the environment,
/// which the caller controls).
pub fn state_dir() -> Option<PathBuf> {
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: out pointer is valid; freed with CoTaskMemFree.
    let hr = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramData,
            KF_FLAG_DEFAULT as u32,
            std::ptr::null_mut(),
            &mut p,
        )
    };
    if hr < 0 || p.is_null() {
        return None;
    }
    // SAFETY: NUL-terminated string from the shell.
    let s = unsafe {
        let mut n = 0usize;
        while *p.add(n) != 0 {
            n += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
        CoTaskMemFree(p as *const _);
        s
    };
    (!s.is_empty()).then(|| PathBuf::from(s).join("Kestrel"))
}

/// Private work folder `%TEMP%\kestrel-uninstall-<yyyyMMdd-HHmmss>` holding
/// the installer log (`kestrel-uninstall-<yyyyMMdd-HHmmss>.log`) and, during
/// the removal, this executable. Only SYSTEM and Administrators can open it
/// and it cannot be renamed while this value lives (see
/// [`purge::create_private_dir`]), so an unelevated program of the same
/// user cannot plant a link where the elevated installer writes its log or
/// swap the executable that is moved back into Program Files.
pub struct WorkDir {
    pub dir: PathBuf,
    pub log: PathBuf,
    _pin: Handle,
}

pub fn work_dir() -> Option<WorkDir> {
    let mut buf = [0u16; 1024];
    // SAFETY: buffer length passed.
    let n = unsafe { GetTempPathW(buf.len() as u32, buf.as_mut_ptr()) } as usize;
    let temp = if n > 0 && n < buf.len() {
        PathBuf::from(String::from_utf16_lossy(&buf[..n]))
    } else {
        std::env::temp_dir()
    };
    // SAFETY: plain out struct.
    let mut t: SYSTEMTIME = unsafe { std::mem::zeroed() };
    unsafe { GetLocalTime(&mut t) };
    let log_name = log_file_name(t.wYear, t.wMonth, t.wDay, t.wHour, t.wMinute, t.wSecond);
    let stem = log_name.trim_end_matches(".log").to_string();
    // A name that already exists (anything, including a planted link) is
    // never reused: try the next one.
    for i in 0..20 {
        let name = if i == 0 {
            stem.clone()
        } else {
            format!("{stem}-{i}")
        };
        let dir = temp.join(&name);
        if let Ok(pin) = purge::create_private_dir(&dir) {
            return Some(WorkDir {
                log: dir.join(&log_name),
                dir,
                _pin: pin,
            });
        }
    }
    None
}

/// Remove `product_code` through Windows Installer with no UI and a
/// verbose log. The token travels only in the in-process property string
/// (never a command line); the string is wiped afterwards. Returns the
/// Windows Installer result code.
pub fn uninstall(product_code: &str, token: &str, log: Option<&Path>) -> u32 {
    let mode = (INSTALLLOGMODE_FATALEXIT
        | INSTALLLOGMODE_ERROR
        | INSTALLLOGMODE_WARNING
        | INSTALLLOGMODE_USER
        | INSTALLLOGMODE_INFO
        | INSTALLLOGMODE_RESOLVESOURCE
        | INSTALLLOGMODE_OUTOFDISKSPACE
        | INSTALLLOGMODE_ACTIONSTART
        | INSTALLLOGMODE_ACTIONDATA
        | INSTALLLOGMODE_COMMONDATA
        | INSTALLLOGMODE_PROPERTYDUMP
        | INSTALLLOGMODE_VERBOSE) as u32;
    let logw = log.map(|l| wide(&l.to_string_lossy()));
    let pc = wide(product_code);
    let mut propsw = msi_properties_wide(token);
    // SAFETY: valid NUL-terminated strings for the duration of the calls.
    let rc = unsafe {
        MsiSetInternalUI(INSTALLUILEVEL_NONE, std::ptr::null_mut());
        if let Some(l) = &logw {
            MsiEnableLogW(mode, l.as_ptr(), INSTALLLOGATTRIBUTES_FLUSHEACHLINE as u32);
        }
        let rc = MsiConfigureProductExW(
            pc.as_ptr(),
            INSTALLLEVEL_DEFAULT,
            INSTALLSTATE_ABSENT,
            propsw.as_ptr(),
        );
        MsiEnableLogW(0, std::ptr::null(), 0);
        rc
    };
    wipe_wide(&mut propsw);
    rc
}

/// Read the installer log (bounded; the interesting lines are near the end
/// but a removal log is a few hundred KB at most).
pub fn read_log(log: &Path) -> Vec<u8> {
    use std::io::Read;
    let mut v = Vec::new();
    if let Ok(f) = std::fs::File::open(log) {
        let _ = f.take(64 * 1024 * 1024).read_to_end(&mut v);
    }
    v
}

/// The running `kestrel-uninstall.exe`, moved out of the install folder
/// for the duration of the removal. A running image cannot be deleted, so
/// Windows Installer would otherwise leave it for a restart (and report
/// 3010); it can be renamed, so it is moved to the private work folder under `%TEMP%`
/// (same volume in a standard install) and either deleted at the next restart (removed) or
/// put back (removal failed). It stays inside the private work folder the
/// whole time.
pub struct MovedSelf {
    from: PathBuf,
    to: PathBuf,
    /// Settled (restored or scheduled for deletion); otherwise Drop
    /// restores it, so a panic in between never loses the file.
    settled: bool,
}

/// Move this executable into the private work folder when it runs from the
/// Kestrel install folder (`kestrel-agent.exe` next to it). `None`: not the
/// installed copy, or the move failed (another volume): Windows Installer
/// then handles the in-use file itself.
pub fn move_self_aside(work: &WorkDir) -> Option<MovedSelf> {
    let from = std::env::current_exe().ok()?;
    let dir = from.parent()?;
    if !dir.join("kestrel-agent.exe").is_file() {
        return None;
    }
    let to = work.dir.join("kestrel-uninstall.exe");
    let (f, t) = (wide(&from.to_string_lossy()), wide(&to.to_string_lossy()));
    // SAFETY: valid strings. No MOVEFILE_COPY_ALLOWED: a running image
    // can only be renamed on its own volume.
    (unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), 0) } != 0).then_some(MovedSelf {
        from,
        to,
        settled: false,
    })
}
impl MovedSelf {
    /// Put the executable back (the product is still installed).
    pub fn restore(&mut self) -> bool {
        self.settled = true;
        let (t, f) = (
            wide(&self.to.to_string_lossy()),
            wide(&self.from.to_string_lossy()),
        );
        // SAFETY: valid strings.
        unsafe { MoveFileExW(t.as_ptr(), f.as_ptr(), 0) != 0 }
    }

    /// The product is gone: delete the moved copy at the next restart.
    pub fn delete_on_reboot(&mut self) {
        self.settled = true;
        let t = wide(&self.to.to_string_lossy());
        // SAFETY: valid string; NULL destination means delete.
        unsafe { MoveFileExW(t.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) };
    }
}

impl Drop for MovedSelf {
    fn drop(&mut self) {
        if !self.settled {
            self.restore();
        }
    }
}
