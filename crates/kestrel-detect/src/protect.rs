//! Which processes Kestrel must never kill or suspend (system stability and
//! other security products). Shared by the detection engine (action
//! filtering) and `kestrel-win` (the last check before `TerminateProcess` /
//! `NtSuspendProcess`), so both layers protect exactly the same set.
//!
//! A process is protected only when **all** of these hold:
//! * its image file name is on [`CRITICAL_PROCESSES`] (or it is a security
//!   product binary in one of [`SECURITY_PRODUCT_DIRS`]);
//! * its full normalised image path, **including the drive**, is the exact
//!   expected location on the system volume (`%SystemRoot%\System32\<name>`,
//!   `%SystemRoot%\<name>` for `explorer.exe`, …), not merely "somewhere
//!   under a Windows-looking folder";
//! * it carries a valid Microsoft / Windows Authenticode signature
//!   (embedded or catalog). `Unknown` never counts.
//!
//! Name or folder alone never grants protection: `%TEMP%\x\MsMpEng.exe`,
//! `E:\Windows\System32\lsass.exe` (a mounted ISO) and an unsigned
//! `C:\Windows\System32\spool\drivers\color\svchost.exe` are all killable.

use crate::paths::normalize_path;
use kestrel_common::SignatureState;

/// Critical OS processes (lower-case image file names).
pub const CRITICAL_PROCESSES: &[&str] = &[
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "lsaiso.exe",
    "svchost.exe",
    "dwm.exe",
    "fontdrvhost.exe",
    "explorer.exe",
    "sihost.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "ctfmon.exe",
    "spoolsv.exe",
    "searchindexer.exe",
    "searchhost.exe",
    "wudfhost.exe",
    "logonui.exe",
    "userinit.exe",
    "startmenuexperiencehost.exe",
    "shellexperiencehost.exe",
    "textinputhost.exe",
    "audiodg.exe",
    "conhost.exe",
    "securityhealthservice.exe",
    "lsm.exe",
];

/// Kernel pseudo-processes (no image file): never touched.
pub const PSEUDO_PROCESSES: &[&str] = &[
    "system",
    "registry",
    "memcompression",
    "memory compression",
    "secure system",
    "system idle process",
];

/// Install directories of Microsoft Defender / MDE (driveless, lower-case,
/// relative to the system volume). Binaries directly inside them (or inside
/// one version folder for the platform directory) are security products.
pub const SECURITY_PRODUCT_DIRS: &[&str] = &[
    r"\program files\windows defender\",
    r"\program files (x86)\windows defender\",
    r"\program files\windows defender advanced threat protection\",
    r"\programdata\microsoft\windows defender\platform\",
    r"\programdata\microsoft\windows defender advanced threat protection\platform\",
];

/// Signer display names of Microsoft's Windows / product signing certificates.
const MICROSOFT_SIGNERS: &[&str] = &[
    "microsoft windows",
    "microsoft windows publisher",
    "microsoft corporation",
    "microsoft windows production pca 2011",
    "microsoft windows hardware compatibility publisher",
];

/// Is `signer` (Authenticode display name) a Microsoft Windows / product signer?
pub fn is_microsoft_signer(signer: &str) -> bool {
    let s = signer.trim().to_ascii_lowercase();
    MICROSOFT_SIGNERS.contains(&s.as_str())
}

/// Valid signature by a Microsoft signer.
pub fn microsoft_signed(signed: SignatureState, signer: Option<&str>) -> bool {
    signed == SignatureState::Valid && signer.is_some_and(is_microsoft_signer)
}

/// Normalised path split into (drive letter if any, driveless rest).
/// `\Device\…` paths that were not mapped to a drive yield `None` drive and
/// `known_volume = false`.
fn split_volume(image: &str) -> (Option<char>, String, bool) {
    let raw = image.trim().replace('/', "\\").to_ascii_lowercase();
    let raw = raw.trim_start_matches(r"\\?\").trim_start_matches(r"\??\");
    if raw.starts_with(r"\device\") || raw.starts_with(r"\\") {
        // Unmapped device path or UNC: volume unknown / remote.
        let n = normalize_path(raw);
        return (None, n, false);
    }
    if raw.starts_with(r"\systemroot\") {
        return (None, normalize_path(raw), true);
    }
    let n = normalize_path(raw);
    let b = n.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        (Some(b[0] as char), n[2..].to_string(), true)
    } else {
        // Driveless rooted path: assumed system volume (tests, %SystemRoot% forms).
        let rooted = n.starts_with('\\');
        (None, n, rooted)
    }
}

/// Driveless normalised rest of `image` when it is on the system volume
/// (or a driveless rooted / `\SystemRoot\` path); `None` otherwise.
pub(crate) fn on_system_volume(image: &str, system_drive: char) -> Option<String> {
    let (drive, rest, known) = split_volume(image);
    if !known {
        return None;
    }
    match drive {
        Some(d) if d != system_drive.to_ascii_lowercase() => None,
        _ => Some(rest),
    }
}

/// Is `rest` exactly `<dir><one file name>` (no further subdirectory)?
fn direct_child_of<'a>(rest: &'a str, dir: &str) -> Option<&'a str> {
    let name = rest.strip_prefix(dir)?;
    (!name.is_empty() && !name.contains('\\')).then_some(name)
}

/// Is this the exact expected location of a critical OS process on the system
/// volume? (`%SystemRoot%\System32\<name>`, `%SystemRoot%\SysWOW64\<name>`,
/// `%SystemRoot%\<name>` for explorer.exe, `%SystemRoot%\SystemApps\<pkg>\<name>`
/// for the shell hosts.) Name must be on [`CRITICAL_PROCESSES`].
pub fn critical_location_ok(image: &str, system_drive: char) -> bool {
    let Some(rest) = on_system_volume(image, system_drive) else {
        return false;
    };
    let name = match rest.rsplit_once('\\') {
        Some((_, n)) => n,
        None => return false,
    };
    if !CRITICAL_PROCESSES.contains(&name) {
        return false;
    }
    if direct_child_of(&rest, r"\windows\system32\").is_some()
        || direct_child_of(&rest, r"\windows\syswow64\").is_some()
    {
        return true;
    }
    if name == "explorer.exe" && direct_child_of(&rest, r"\windows\").is_some() {
        return true;
    }
    if matches!(
        name,
        "startmenuexperiencehost.exe"
            | "shellexperiencehost.exe"
            | "textinputhost.exe"
            | "searchhost.exe"
    ) {
        if let Some(sub) = rest.strip_prefix(r"\windows\systemapps\") {
            // exactly <package dir>\<name>
            let mut parts = sub.split('\\');
            return matches!((parts.next(), parts.next(), parts.next()), (Some(p), Some(_), None) if !p.is_empty());
        }
    }
    false
}

/// Is this the exact install location of a Microsoft security product
/// (Defender / MDE) on the system volume?
pub fn security_product_location_ok(image: &str, system_drive: char) -> bool {
    let Some(rest) = on_system_volume(image, system_drive) else {
        return false;
    };
    for dir in SECURITY_PRODUCT_DIRS {
        let Some(sub) = rest.strip_prefix(dir) else {
            continue;
        };
        if dir.ends_with(r"\platform\") {
            // <version>\<file>
            let mut parts = sub.split('\\');
            if let (Some(v), Some(f), None) = (parts.next(), parts.next(), parts.next()) {
                if !v.is_empty() && !f.is_empty() {
                    return true;
                }
            }
        } else if !sub.is_empty() && !sub.contains('\\') {
            return true;
        }
    }
    false
}

/// Kernel pseudo-process (image is just a name such as `System` / `Registry`).
pub fn is_pseudo_process(image: &str) -> bool {
    let t = image.trim();
    !t.contains('\\')
        && !t.contains('/')
        && PSEUDO_PROCESSES.contains(&t.to_ascii_lowercase().as_str())
}

/// Critical OS process at its exact location with a valid Microsoft signature.
pub fn is_protected_system_process(
    image: &str,
    signed: SignatureState,
    signer: Option<&str>,
    system_drive: char,
) -> bool {
    is_pseudo_process(image)
        || (critical_location_ok(image, system_drive) && microsoft_signed(signed, signer))
}

/// Microsoft security product in its real install directory with a valid
/// Microsoft signature.
pub fn is_protected_security_product(
    image: &str,
    signed: SignatureState,
    signer: Option<&str>,
    system_drive: char,
) -> bool {
    security_product_location_ok(image, system_drive) && microsoft_signed(signed, signer)
}

/// Either of the above: never kill or suspend.
pub fn is_protected_process(
    image: &str,
    signed: SignatureState,
    signer: Option<&str>,
    system_drive: char,
) -> bool {
    is_protected_system_process(image, signed, signer, system_drive)
        || is_protected_security_product(image, signed, signer, system_drive)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SignatureState::*;

    const MS: Option<&str> = Some("Microsoft Windows");

    #[test]
    fn exact_locations_only() {
        assert!(critical_location_ok(r"C:\Windows\System32\lsass.exe", 'c'));
        assert!(critical_location_ok(r"c:\windows\explorer.exe", 'C'));
        assert!(critical_location_ok(
            r"\\?\C:\Windows\System32\svchost.exe",
            'c'
        ));
        assert!(critical_location_ok(r"\SystemRoot\System32\smss.exe", 'c'));
        assert!(critical_location_ok(
            r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe",
            'c'
        ));
        // other volume (mounted ISO / USB)
        assert!(!critical_location_ok(r"E:\Windows\System32\lsass.exe", 'c'));
        // system drive is D:
        assert!(critical_location_ok(r"D:\Windows\System32\lsass.exe", 'd'));
        assert!(!critical_location_ok(r"C:\Windows\System32\lsass.exe", 'd'));
        // user-writable System32 subdirectory
        assert!(!critical_location_ok(
            r"C:\Windows\System32\spool\drivers\color\svchost.exe",
            'c'
        ));
        assert!(!critical_location_ok(r"C:\Windows\Tasks\svchost.exe", 'c'));
        // explorer only directly in %SystemRoot%
        assert!(!critical_location_ok(r"C:\Windows\Temp\explorer.exe", 'c'));
        assert!(!critical_location_ok(r"C:\Users\a\explorer.exe", 'c'));
        // not a critical name
        assert!(!critical_location_ok(
            r"C:\Windows\System32\notepad.exe",
            'c'
        ));
        // unmapped device path: volume unknown
        assert!(!critical_location_ok(
            r"\Device\HarddiskVolume9\Windows\System32\lsass.exe",
            'c'
        ));
    }

    #[test]
    fn signature_required() {
        let p = r"C:\Windows\System32\csrss.exe";
        assert!(is_protected_system_process(p, Valid, MS, 'c'));
        assert!(!is_protected_system_process(p, Unknown, MS, 'c'));
        assert!(!is_protected_system_process(p, Unsigned, None, 'c'));
        assert!(!is_protected_system_process(p, Invalid, MS, 'c'));
        assert!(!is_protected_system_process(
            p,
            Valid,
            Some("Evil Corp"),
            'c'
        ));
        assert!(is_protected_system_process("System", Unknown, None, 'c'));
        assert!(is_protected_system_process("Registry", Unknown, None, 'c'));
        assert!(!is_pseudo_process(r"C:\Users\a\System"));
    }

    #[test]
    fn security_products() {
        let real = r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe";
        assert!(is_protected_security_product(
            real,
            Valid,
            Some("Microsoft Corporation"),
            'c'
        ));
        assert!(!is_protected_security_product(real, Unknown, None, 'c'));
        assert!(is_protected_security_product(
            r"C:\Program Files\Windows Defender\MsMpEng.exe",
            Valid,
            MS,
            'c'
        ));
        // look-alikes
        for fake in [
            r"C:\Users\a\AppData\Local\Temp\Windows Defender\setup.exe",
            r"C:\Users\a\AppData\Local\Temp\x\MsMpEng.exe",
            r"E:\Program Files\Windows Defender\MsMpEng.exe",
            r"C:\Program Files\Windows Defender\sub\dir\x.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\MsMpEng.exe",
        ] {
            assert!(
                !is_protected_security_product(fake, Valid, MS, 'c'),
                "{fake} must not be protected"
            );
        }
        assert!(is_protected_process(real, Valid, MS, 'c'));
    }

    #[test]
    fn microsoft_signers() {
        assert!(is_microsoft_signer("Microsoft Windows Publisher"));
        assert!(is_microsoft_signer(" microsoft corporation "));
        assert!(!is_microsoft_signer("Microsoft Windows Evil"));
        assert!(!is_microsoft_signer("Not Microsoft Corporation"));
    }
}
