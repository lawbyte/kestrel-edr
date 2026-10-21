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
    // COM task creation (persistence attribution, PS-05).
    "taskschd.dll",
];

/// Extra paths the Kernel-File source filter keeps on top of
/// `kestrel_detect::paths::may_be_sensitive` (credential dumping and
/// persistence): Startup folders, `System32\Tasks\`, memory dumps in user /
/// temp / CrashDumps locations, copies of the SAM / SECURITY / SYSTEM hives
/// (including shadow-copy paths), `ntds.dit`, DPAPI master keys and the
/// Credentials / Vault stores, and the mimikatz SSP / memssp log names.
/// Input: Win32 path (any case).
pub fn is_extra_sensitive(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    let name = file_name_lower(&p);
    const CONTAINS: &[&str] = &[
        r"\microsoft\windows\start menu\programs\startup\",
        r"\windows\system32\tasks\",
        r"\windows\syswow64\tasks\",
        r"\appdata\roaming\microsoft\protect\",
        r"\appdata\local\microsoft\credentials\",
        r"\appdata\roaming\microsoft\credentials\",
        r"\appdata\local\microsoft\vault\",
        r"\programdata\microsoft\vault\",
        r"\system32\microsoft\protect\",
    ];
    if CONTAINS.iter().any(|c| p.contains(c)) {
        return true;
    }
    if matches!(name.as_str(), "ntds.dit" | "mimilsa.log" | "kiwissp.log") {
        return true;
    }
    // Hive copies: \config\SAM on any volume (incl. HarddiskVolumeShadowCopyN)
    // and the usual `reg save` output names elsewhere.
    let hive_names = ["sam", "security", "system"];
    if p.contains(r"\config\") && hive_names.contains(&name.as_str()) {
        return true;
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        if hive_names.contains(&stem) && matches!(ext, "save" | "hiv" | "bak" | "dmp" | "reg") {
            return true;
        }
        if matches!(ext, "dmp" | "mdmp" | "dump") {
            return name.starts_with("lsass")
                || p.contains(r"\users\")
                || p.contains(r"\windows\temp\")
                || p.contains(r"\crashdumps\");
        }
    }
    false
}

/// Persistence drop locations (Startup folders, task XML stores) where an
/// open-or-create (`FILE_OPEN_IF`) of a file is reported as a create: the
/// open itself cannot say whether the file existed, and a missed drop is
/// worse than a duplicate "create" of an existing autostart file.
pub fn is_persistence_drop_path(path: &str) -> bool {
    let p = path.replace('/', "\\").to_ascii_lowercase();
    [
        r"\microsoft\windows\start menu\programs\startup\",
        r"\windows\system32\tasks\",
        r"\windows\syswow64\tasks\",
    ]
    .iter()
    .any(|c| p.contains(c))
}

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

/// Soak 2026-10-21 (PS-01, WiX Burn reboot continuation): the file an
/// **HKLM** `RunOnce` value starts when it lies directly in
/// `%ProgramData%\Package Cache\<one folder>\` on the system volume — the
/// only registry target whose on-disk signature the sensor verifies and
/// attaches to the event (`RegistrySet.target`). `key` is the normalised
/// key (`HKLM\…`), `data` the value data. Pure.
pub fn package_cache_runonce_target(key: &str, data: &str, system_drive: char) -> Option<String> {
    let k = key.to_ascii_lowercase().replace('/', "\\");
    let hklm = k.starts_with(r"hklm\") || k.starts_with(r"\registry\machine\");
    let runonce = k.ends_with(r"\currentversion\runonce");
    if !hklm || !runonce {
        return None;
    }
    let d = data.trim();
    let path = if let Some(rest) = d.strip_prefix('"') {
        rest.split('"').next()?.to_string()
    } else {
        let l = d.to_ascii_lowercase();
        let end = l.find(".exe")? + 4;
        d[..end].to_string()
    };
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    let b = lower.as_bytes();
    if b.len() < 3 || b[1] != b':' || (b[0] as char) != system_drive.to_ascii_lowercase() {
        return None;
    }
    let rest = lower[2..].strip_prefix(r"\programdata\package cache\")?;
    let mut parts = rest.split('\\');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(dir), Some(file), None)
            if !dir.is_empty() && dir != ".." && dir != "." && file.ends_with(".exe") =>
        {
            Some(path)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn package_cache_runonce_targets() {
        let k = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
        let d = r#""C:\ProgramData\Package Cache\{5393BF16-0B4D-4C7B-9E2C-6C2E0F1A2B3C}\PowerToysSetup-0.101.2362.0-x64.exe" /burn.runonce"#;
        assert_eq!(
            package_cache_runonce_target(k, d, 'c').as_deref(),
            Some(
                r"C:\ProgramData\Package Cache\{5393BF16-0B4D-4C7B-9E2C-6C2E0F1A2B3C}\PowerToysSetup-0.101.2362.0-x64.exe"
            )
        );
        // unquoted with spaces
        assert!(package_cache_runonce_target(
            k,
            r"C:\ProgramData\Package Cache\{G}\setup.exe /burn.runonce",
            'c'
        )
        .is_some());
        for (key, data, drive) in [
            (
                r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\RunOnce",
                d,
                'c',
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                d,
                'c',
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx",
                d,
                'c',
            ),
            (k, d, 'd'),
            (k, r#""D:\ProgramData\Package Cache\{G}\s.exe""#, 'c'),
            (k, r#""C:\ProgramData\Package Cache\{G}\sub\s.exe""#, 'c'),
            (k, r#""C:\ProgramData\Package Cache\..\s.exe""#, 'c'),
            (k, r#""C:\ProgramData\Other\{G}\s.exe""#, 'c'),
            (k, r#""C:\ProgramData\Package Cache\{G}\s.dll""#, 'c'),
        ] {
            assert!(
                package_cache_runonce_target(key, data, drive).is_none(),
                "{key} {data} {drive}"
            );
        }
    }

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
        assert!(should_emit_image_load(r"C:\Windows\System32\dbgcore.dll"));
        assert!(should_emit_image_load(r"C:\Windows\System32\taskschd.dll"));
    }

    #[test]
    fn extra_sensitive_paths() {
        for p in [
            r"C:\Users\labuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\y.bat",
            r"C:\Windows\System32\Tasks\KestrelProbe",
            r"C:\Users\labuser\AppData\Local\Temp\lsass.dmp",
            r"C:\Users\labuser\AppData\Local\CrashDumps\notepad.exe.1234.dmp",
            r"C:\Windows\Temp\x.mdmp",
            r"D:\out\lsass_0917.dmp",
            r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM",
            r"C:\Windows\System32\config\SECURITY",
            r"C:\temp\system.save",
            r"C:\Windows\NTDS\ntds.dit",
            r"C:\Users\labuser\AppData\Roaming\Microsoft\Protect\S-1-5-21-1\abc",
            r"C:\Users\labuser\AppData\Local\Microsoft\Credentials\DFBE70A7",
            r"C:\Users\labuser\AppData\Local\Microsoft\Vault\4BF4C442\x.vcrd",
            r"C:\Windows\System32\mimilsa.log",
        ] {
            assert!(is_extra_sensitive(p), "{p}");
        }
        for p in [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\x\memory.dmp",
            r"C:\Users\labuser\Documents\system.docx",
            r"C:\Windows\System32\config\systemprofile\x.txt",
        ] {
            assert!(!is_extra_sensitive(p), "{p}");
        }
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
