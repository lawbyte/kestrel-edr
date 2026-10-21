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

/// `kestrel_detect::paths::may_be_sensitive`, guarded: if the detection
/// crate panics (not implemented in a dev build) a built-in substring list
/// is used instead so the sensor keeps working. Accepts Win32 or NT paths
/// (the detection prefilter is drive-independent substring matching).
pub fn may_be_sensitive(path: &str) -> bool {
    use std::sync::OnceLock;
    static DETECT_OK: OnceLock<bool> = OnceLock::new();
    let ok = *DETECT_OK.get_or_init(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let r = std::panic::catch_unwind(|| {
            kestrel_detect::paths::may_be_sensitive(r"C:\Windows\x.txt")
        })
        .is_ok();
        std::panic::set_hook(prev);
        r
    });
    if ok {
        return std::panic::catch_unwind(|| kestrel_detect::paths::may_be_sensitive(path))
            .unwrap_or(false);
    }
    let p = path.to_ascii_lowercase();
    const FALLBACK: &[&str] = &[
        "\\login data",
        "\\cookies",
        "\\web data",
        "\\local state",
        "\\key4.db",
        "\\key3.db",
        "\\logins.json",
        "\\cookies.sqlite",
        "\\local extension settings\\",
        "\\tdata\\",
        "\\discord\\local storage\\",
        "\\.aws\\",
        "\\.azure\\",
        "\\.ssh\\",
        "\\filezilla\\",
        "\\wallets\\",
        "\\steam\\ssfn",
    ];
    FALLBACK.iter().any(|f| p.contains(f))
}

/// Volume-relative form of a lower-cased NT path (`\device\harddiskvolume3\x`
/// → `\x`, `\device\mup\srv\share\x` → `\srv\share\x`, `\??\c:\x` → `\x`).
fn nt_relative(nt_lower: &str) -> &str {
    if let Some(after) = nt_lower.strip_prefix(r"\device\") {
        return after.find('\\').map_or("", |i| &after[i..]);
    }
    let p = nt_lower
        .strip_prefix(r"\??\")
        .or_else(|| nt_lower.strip_prefix(r"\\?\"))
        .unwrap_or(nt_lower);
    win32_relative(p)
}

/// Volume-relative form of a lower-cased Win32 path (`c:\x` → `\x`,
/// `\\srv\share\x` → `\srv\share\x`).
fn win32_relative(p: &str) -> &str {
    let b = p.as_bytes();
    if b.len() >= 2 && b[1] == b':' {
        &p[2..]
    } else if p.starts_with(r"\\") {
        &p[1..]
    } else {
        p
    }
}

/// Kernel-File source filter, run in the ETW callback before an open is
/// queued for the translator (event-loss fix, owner PC 2026-10-22: a large
/// build opens thousands of files per second and only credential stores,
/// decoys and persistence / dump paths are ever looked at). Must be a
/// **superset** of the translator's `sensitive()` check, which still runs on
/// the Win32 path: the detection prefilter and [`is_extra_sensitive`] are
/// substring matches that do not depend on the drive, and canaries
/// (`canary_keys`: lower-cased Win32 paths, as in the translator) are
/// compared volume-relative, i.e. ignoring which volume — never narrower.
pub fn kernel_file_candidate<'a>(
    nt_path: &str,
    canary_keys: impl IntoIterator<Item = &'a String>,
) -> bool {
    if may_be_sensitive(nt_path) || is_extra_sensitive(nt_path) {
        return true;
    }
    let lower = nt_path.replace('/', "\\").to_ascii_lowercase();
    let rel = nt_relative(&lower);
    if rel.is_empty() {
        return false;
    }
    canary_keys.into_iter().any(|c| {
        let c = win32_relative(c);
        !c.is_empty()
            && (rel == c
                || (rel.len() > c.len() && rel.starts_with(c) && rel.as_bytes()[c.len()] == b'\\'))
    })
}

/// MSIX / AppX package code-integrity catalog for a file inside an
/// installed package (`…\WindowsApps\<PackageFullName>\…` on any volume, or
/// `…\SystemApps\<package>\…`): `<package root>\AppxMetadata\CodeIntegrity.cat`.
/// Packaged executables usually carry no embedded Authenticode signature;
/// that catalog (signed with the package certificate) holds their
/// Authenticode hashes. Pure path logic; None for anything else.
pub fn msix_code_integrity_catalog(path: &str) -> Option<String> {
    let p = path.replace('/', "\\");
    let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
    if p.starts_with(r"\\") {
        return None; // network paths are never opened as SYSTEM (V-M1)
    }
    let lower = p.to_ascii_lowercase();
    let mut search = 0usize;
    while let Some(i) = lower[search..]
        .find(r"\windowsapps\")
        .map(|i| (i + search, r"\windowsapps\".len()))
        .or_else(|| {
            lower[search..]
                .find(r"\systemapps\")
                .map(|i| (i + search, r"\systemapps\".len()))
        })
    {
        let (at, len) = i;
        let root_start = at + len;
        let rest = &lower[root_start..];
        let end = rest.find('\\')?;
        let pkg = &rest[..end];
        let inner = &rest[end + 1..];
        let valid_pkg = !pkg.is_empty() && pkg != "." && pkg != ".." && !pkg.contains(':');
        if valid_pkg && !inner.is_empty() && !inner.split('\\').any(|c| c == "..") {
            return Some(format!(
                r"{}\AppxMetadata\CodeIntegrity.cat",
                &p[..root_start + end]
            ));
        }
        search = root_start;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_file_prefilter_is_superset_on_nt_paths() {
        let none: Vec<String> = Vec::new();
        // Credential stores (detection catalog) on any volume.
        for p in [
            r"\Device\HarddiskVolume3\Users\azka\.docker\config.json",
            r"\Device\HarddiskVolume3\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            r"\Device\HarddiskVolume7\Users\a\AppData\Roaming\Mozilla\Firefox\Profiles\x\key4.db",
            r"\Device\HarddiskVolume3\Users\a\.ssh\id_ed25519",
            // Persistence drops and dump / hive paths (is_extra_sensitive).
            r"\Device\HarddiskVolume3\Windows\System32\Tasks\Evil",
            r"\Device\HarddiskVolume3\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
            r"\Device\HarddiskVolumeShadowCopy2\Windows\System32\config\SAM",
            r"\Device\HarddiskVolume3\Users\a\AppData\Local\Temp\lsass.dmp",
            r"\Device\HarddiskVolume3\Users\a\AppData\Roaming\Microsoft\Protect\S-1-5-21\key",
        ] {
            assert!(kernel_file_candidate(p, &none), "{p}");
        }
        // Build noise never reaches the translator.
        for p in [
            r"\Device\HarddiskVolume5\kestrel-build2\t\debug\deps\libserde-1234.rmeta",
            r"\Device\HarddiskVolume3\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44\include\vector",
            r"\Device\HarddiskVolume3\Windows\System32\kernel32.dll",
            r"\Device\HarddiskVolume3\Users\azka\.cargo\registry\src\x\lib.rs",
        ] {
            assert!(!kernel_file_candidate(p, &none), "{p}");
        }
    }

    #[test]
    fn kernel_file_prefilter_matches_canaries_volume_relative() {
        let canaries = vec![
            r"c:\users\a\documents\finance\passwords-old.xlsx".to_string(),
            r"\\srv\share\decoy".to_string(),
        ];
        assert!(kernel_file_candidate(
            r"\Device\HarddiskVolume3\Users\A\Documents\Finance\Passwords-old.xlsx",
            &canaries
        ));
        assert!(kernel_file_candidate(
            r"\Device\Mup\srv\share\decoy\x.txt",
            &canaries
        ));
        assert!(!kernel_file_candidate(
            r"\Device\HarddiskVolume3\Users\A\Documents\Finance\Passwords-old.xlsx.bak",
            &canaries
        ));
        assert!(!kernel_file_candidate(
            r"\Device\HarddiskVolume3",
            &canaries
        ));
        // The translator's own (Win32) form passes as well.
        assert!(kernel_file_candidate(
            r"C:\Users\A\Documents\Finance\Passwords-old.xlsx",
            &canaries
        ));
    }

    #[test]
    fn msix_catalog_paths() {
        assert_eq!(
            msix_code_integrity_catalog(
                r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe"
            )
            .as_deref(),
            Some(r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\AppxMetadata\CodeIntegrity.cat")
        );
        assert_eq!(
            msix_code_integrity_catalog(r"D:\WindowsApps\Pkg_1.0_x64__abc\sub\dir\x.dll")
                .as_deref(),
            Some(r"D:\WindowsApps\Pkg_1.0_x64__abc\AppxMetadata\CodeIntegrity.cat")
        );
        assert_eq!(
            msix_code_integrity_catalog(
                r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"
            )
            .as_deref(),
            Some(r"C:\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\AppxMetadata\CodeIntegrity.cat")
        );
        assert_eq!(
            msix_code_integrity_catalog(r"\\?\C:\Program Files\WindowsApps\P\a.exe").as_deref(),
            Some(r"C:\Program Files\WindowsApps\P\AppxMetadata\CodeIntegrity.cat")
        );
        for p in [
            r"C:\Program Files\WindowsApps\P",
            r"C:\Program Files\WindowsApps\x.exe",
            r"C:\Program Files\WindowsApps\..\x.exe",
            r"C:\Program Files\WindowsApps\P\..\..\Users\x.exe",
            r"\\srv\share\WindowsApps\P\a.exe",
            r"C:\Users\a\Downloads\a.exe",
        ] {
            assert_eq!(msix_code_integrity_catalog(p), None, "{p}");
        }
    }

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
