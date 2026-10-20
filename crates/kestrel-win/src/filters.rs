//! Source-side filtering and safety decisions (pure).

use kestrel_common::{file_name_lower, PathClass, SignatureState};
use kestrel_detect::protect;

/// DLLs whose load is interesting wherever they live (credential/crypto
/// libraries stealers load into foreign processes, sideloading targets,
/// dump helpers).
pub const INTERESTING_DLLS: &[&str] = &[
    "nss3.dll",
    "mozglue.dll",
    "softokn3.dll",
    "freebl3.dll",
    "vaultcli.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "mpclient.dll",
    "msedge_elf.dll",
    "chrome_elf.dll",
    "winscard.dll",
    "samlib.dll",
];

/// Image loads are the noisiest Kernel-Process event; emit only loads from
/// outside Windows/Program Files plus the interesting DLL list anywhere.
pub fn should_emit_image_load(path: &str) -> bool {
    match PathClass::of(path) {
        PathClass::System | PathClass::Windows | PathClass::ProgramFiles => {
            INTERESTING_DLLS.contains(&file_name_lower(path).as_str())
        }
        _ => true,
    }
}

/// Exact location of a critical OS process (or kernel pseudo-process) on the
/// system volume — the shared list in [`kestrel_detect::protect`] (L11).
/// Location only: used to drop high-volume noise in the sensor translator.
/// Response decisions use [`is_protected_target`], which also requires a
/// valid Microsoft signature (H1).
pub fn is_critical_location(path: &str, system_drive: char) -> bool {
    protect::is_pseudo_process(path) || protect::critical_location_ok(path, system_drive)
}

/// Exact Defender / MDE install location on the system volume (location only).
pub fn is_security_product_location(path: &str, system_drive: char) -> bool {
    protect::security_product_location_ok(path, system_drive)
}

/// Response safety (H1): never kill / suspend this target. `signature` is
/// evaluated lazily (only for images at a protected location) and returns
/// (state, signer, chains to a Microsoft root).
pub fn is_protected_target(
    image: &str,
    system_drive: char,
    signature: impl FnOnce(&str) -> (SignatureState, Option<String>, bool),
) -> bool {
    if protect::is_pseudo_process(image) {
        return true;
    }
    if !(protect::critical_location_ok(image, system_drive)
        || protect::security_product_location_ok(image, system_drive))
    {
        return false;
    }
    let (state, signer, ms_root) = signature(image);
    state == SignatureState::Valid
        && (ms_root || signer.as_deref().is_some_and(protect::is_microsoft_signer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_loads() {
        assert!(!should_emit_image_load(r"C:\Windows\System32\kernel32.dll"));
        assert!(should_emit_image_load(
            r"C:\Program Files\Mozilla Firefox\nss3.dll"
        ));
        assert!(!should_emit_image_load(
            r"C:\Program Files\Mozilla Firefox\xul.dll"
        ));
        assert!(should_emit_image_load(
            r"C:\Users\a\AppData\Local\Temp\x\MpClient.dll"
        ));
        assert!(should_emit_image_load(r"C:\Windows\System32\dbghelp.dll"));
    }

    #[test]
    fn critical() {
        assert!(is_critical_location(r"C:\Windows\System32\lsass.exe", 'c'));
        assert!(!is_critical_location(
            r"C:\Users\a\AppData\Local\Temp\lsass.exe",
            'c'
        ));
        assert!(is_critical_location("System", 'c'));
        assert!(!is_critical_location(
            r"C:\Windows\System32\notepad.exe",
            'c'
        ));
        assert!(!is_critical_location(r"E:\Windows\System32\lsass.exe", 'c'));
        assert!(is_security_product_location(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1\MsMpEng.exe",
            'c'
        ));
        assert!(!is_security_product_location(
            r"C:\Users\a\AppData\Local\Temp\Windows Defender\setup.exe",
            'c'
        ));
        assert!(!is_security_product_location(r"C:\Temp\x\MsMpEng.exe", 'c'));
    }

    #[test]
    fn protection_needs_microsoft_signature() {
        let valid_ms = |_: &str| {
            (
                SignatureState::Valid,
                Some("Microsoft Windows".to_string()),
                true,
            )
        };
        let unsigned = |_: &str| (SignatureState::Unsigned, None, false);
        let other = |_: &str| (SignatureState::Valid, Some("Evil Ltd".to_string()), false);
        let p = r"C:\Windows\System32\winlogon.exe";
        assert!(is_protected_target(p, 'c', valid_ms));
        assert!(!is_protected_target(p, 'c', unsigned));
        assert!(!is_protected_target(p, 'c', other));
        // look-alike location: signature never even evaluated
        assert!(!is_protected_target(
            r"C:\Windows\System32\spool\drivers\color\svchost.exe",
            'c',
            |_| panic!("not evaluated")
        ));
        assert!(!is_protected_target(
            r"C:\Users\a\Temp\x\MsMpEng.exe",
            'c',
            |_| panic!()
        ));
        assert!(is_protected_target("Registry", 'c', |_| panic!()));
        // Microsoft root without a known signer name still counts
        assert!(is_protected_target(
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
            'c',
            |_| (SignatureState::Valid, Some("Something".into()), true)
        ));
    }
}
