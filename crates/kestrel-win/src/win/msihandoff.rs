//! Enrollment-token hand-off from the MSI (security review M6).
//!
//! A deferred MSI custom action can only start a process with a command line,
//! and anything on a command line is visible to every process-creation sensor
//! on the host (ours, Defender, Sysmon, another EDR). So the MSI writes the
//! token (a hidden property, masked in verbose logs) to
//! `HKLM\SOFTWARE\Kestrel\Setup\EnrollToken` on a key whose DACL grants access
//! to SYSTEM and Administrators only, and runs `kestrel-agent install
//! --token-from-msi`. The agent checks the key's owner and DACL (no write or
//! read for anyone else), takes the token and deletes the value and the key.

use super::util::*;
use anyhow::{bail, Context, Result};
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_REGISTRY_KEY,
};
use windows_sys::Win32::Security::{
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
use windows_sys::Win32::System::Registry::{RegDeleteKeyExW, HKEY_LOCAL_MACHINE, KEY_WOW64_64KEY};

pub const SETUP_KEY: &str = r"SOFTWARE\Kestrel\Setup";
pub const TOKEN_VALUE: &str = "EnrollToken";

/// Read and delete the token the MSI left for us. Fails if the key is missing,
/// empty, or readable/writable by anyone but SYSTEM and Administrators.
pub fn take_enroll_token() -> Result<String> {
    let key = reg_open(HKEY_LOCAL_MACHINE, SETUP_KEY, true)
        .with_context(|| format!(r"HKLM\{SETUP_KEY} not found (was the MSI run with TOKEN=…?)"))?;
    let sddl = key_sddl(&key).context("reading the setup key's security descriptor")?;
    if let Err(why) = crate::sddl::handoff_key_trusted(&sddl) {
        // Never use a token a standard user could have planted or read.
        let _ = reg_delete_value(&key, TOKEN_VALUE);
        bail!(r"refusing HKLM\{SETUP_KEY}: {why}");
    }
    let token = reg_get_string(&key, TOKEN_VALUE)
        .unwrap_or_default()
        .trim()
        .to_string();
    let _ = reg_delete_value(&key, TOKEN_VALUE);
    drop(key);
    delete_setup_key();
    if token.is_empty() {
        bail!(r"HKLM\{SETUP_KEY}\{TOKEN_VALUE} is empty");
    }
    Ok(token)
}

/// Remove the hand-off key (also called on uninstall; ignores "not found").
pub fn delete_setup_key() {
    let w = wide(SETUP_KEY);
    unsafe {
        let _ = RegDeleteKeyExW(HKEY_LOCAL_MACHINE, w.as_ptr(), KEY_WOW64_64KEY, 0);
    }
}

fn key_sddl(k: &RegKey) -> Option<String> {
    let info = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    unsafe {
        let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(
            k.0 as _,
            SE_REGISTRY_KEY,
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
        let mut s: *mut u16 = std::ptr::null_mut();
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            info,
            &mut s,
            std::ptr::null_mut(),
        );
        LocalFree(sd as _);
        if ok == 0 || s.is_null() {
            return None;
        }
        let mut n = 0usize;
        while *s.add(n) != 0 {
            n += 1;
        }
        let out = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as _);
        Some(out)
    }
}
