//! Server-side allow-list for `RemoveAutorun` (security review v1.1 V-H2).
//!
//! `remove_autorun` makes the SYSTEM agent delete or rewrite a persistence
//! entry. The agent has its own planner; this module is the server's
//! independent gate, applied to **every** path that queues the action
//! (`POST /devices/:id/actions` and checklist approval), so that a stolen
//! console session cannot turn the action into an arbitrary SYSTEM registry
//! write:
//!
//! * **Deletes** are accepted only for well-known autorun locations
//!   ([`registry_delete_allowed`]): Run / RunOnce / RunOnceEx /
//!   `Policies\Explorer\Run` (HKLM and HKU, incl. `Wow6432Node`),
//!   `Windows NT\CurrentVersion\Windows` `Load`/`Run`, IFEO
//!   `Debugger`/`GlobalFlag`/`VerifierDlls`, `SilentProcessExit\*`, HKU
//!   Winlogon `Shell`/`Userinit` overrides, HKU COM server keys
//!   (`InprocServer32`, `LocalServer32`, `TreatAs`, `ScriptletURL`),
//!   `AppInit_DLLs` and `AppCertDlls`.
//! * **Writes** (`restore_data`) are accepted only when the data equals the
//!   canonical OS default for that exact key and value ([`canonical_default`]).
//! * Startup files must be directly inside a Startup folder; task, service and
//!   WMI names must be plain, printable names.

use kestrel_common::AutorunKind;

/// Max length of a location / value name accepted from the console.
const MAX_LOCATION: usize = 1024;

/// Bidirectional-override and invisible formatting characters that can make a
/// name read differently from what it is (U+202E etc.).
pub fn is_bidi_or_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{061C}' | '\u{FEFF}'
    )
}

fn unprintable(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_bidi_or_invisible(c))
}

/// Registry hive of a parsed location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hive {
    Hklm,
    Hku,
}

/// A parsed registry key: hive plus the canonical lower-case subkey (HKU SID
/// removed, `<SID>_Classes` mapped to `software\classes`, `Wow6432Node`
/// folded, `ControlSet00N` folded to `CurrentControlSet`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegKey {
    pub hive: Hive,
    pub canonical: String,
}

fn is_sid(s: &str) -> bool {
    let base = s
        .strip_suffix("_Classes")
        .or_else(|| s.strip_suffix("_classes"))
        .unwrap_or(s);
    let up = base.to_ascii_uppercase();
    let Some(rest) = up.strip_prefix("S-1-") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Parse `HKLM\…` / `HKEY_LOCAL_MACHINE\…` / `HKU\<SID>\…` / `HKEY_USERS\<SID>\…`.
pub fn parse_key(location: &str) -> Option<RegKey> {
    let t = location.trim().trim_end_matches('\\');
    if t.is_empty() || t.contains('/') || unprintable(t) {
        return None;
    }
    let (head, rest) = t.split_once('\\')?;
    let hive = match head.to_ascii_uppercase().as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => Hive::Hklm,
        "HKU" | "HKEY_USERS" => Hive::Hku,
        _ => return None,
    };
    let segs: Vec<&str> = rest.split('\\').collect();
    if segs.iter().any(|s| {
        s.is_empty() || *s == "." || *s == ".." || s.contains(['*', '?']) || s.trim() != *s
    }) {
        return None;
    }
    let lower = rest.to_ascii_lowercase();
    let mut canonical = match hive {
        Hive::Hklm => lower,
        Hive::Hku => {
            if !is_sid(segs[0]) || segs.len() < 2 {
                return None;
            }
            let (sid, after) = lower.split_once('\\')?;
            if sid.ends_with("_classes") {
                format!(r"software\classes\{after}")
            } else {
                after.to_string()
            }
        }
    };
    for (from, to) in [
        (r"software\wow6432node\", r"software\"),
        (r"software\classes\wow6432node\", r"software\classes\"),
    ] {
        if canonical.starts_with(from) {
            canonical = format!("{to}{}", &canonical[from.len()..]);
        }
    }
    if let Some(r) = canonical.strip_prefix(r"system\controlset") {
        // ControlSet001 … ControlSet999 → CurrentControlSet
        let digits: String = r.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty() && r[digits.len()..].starts_with('\\') {
            canonical = format!(r"system\currentcontrolset{}", &r[digits.len()..]);
        }
    }
    Some(RegKey { hive, canonical })
}

const CV: &str = r"software\microsoft\windows\currentversion\";
const NT_CV: &str = r"software\microsoft\windows nt\currentversion\";

/// Is deleting `value` under `key` (an autorun location) allowed?
pub fn registry_delete_allowed(key: &RegKey, value: &str) -> bool {
    let k = key.canonical.as_str();
    let v = value.to_ascii_lowercase();
    // Run keys (machine and per-user).
    if let Some(r) = k.strip_prefix(CV) {
        if matches!(
            r,
            "run" | "runonce" | "runonceex" | r"policies\explorer\run"
        ) {
            return true;
        }
        // RunOnceEx\<entry> subkeys hold the commands.
        if let Some(sub) = r.strip_prefix(r"runonceex\") {
            return !sub.is_empty() && !sub.contains('\\');
        }
    }
    if let Some(r) = k.strip_prefix(NT_CV) {
        // Windows\Load / Windows\Run (legacy per-user autostart) and AppInit_DLLs.
        if r == "windows" {
            return match key.hive {
                Hive::Hku => matches!(v.as_str(), "load" | "run"),
                Hive::Hklm => matches!(v.as_str(), "load" | "run" | "appinit_dlls"),
            };
        }
        if key.hive == Hive::Hklm {
            if let Some(exe) = r.strip_prefix(r"image file execution options\") {
                return !exe.is_empty()
                    && !exe.contains('\\')
                    && matches!(v.as_str(), "debugger" | "globalflag" | "verifierdlls");
            }
            if let Some(exe) = r.strip_prefix(r"silentprocessexit\") {
                return !exe.is_empty() && !exe.contains('\\');
            }
        }
        // Per-user Winlogon overrides (the HKLM values are restored, never deleted).
        if r == "winlogon" && key.hive == Hive::Hku {
            return matches!(v.as_str(), "shell" | "userinit");
        }
    }
    if key.hive == Hive::Hklm
        && k == r"system\currentcontrolset\control\session manager\appcertdlls"
    {
        return true;
    }
    // Per-user COM hijacks: HKU\<SID>\Software\Classes\CLSID\{x}\<server key>.
    if key.hive == Hive::Hku {
        if let Some(r) = k.strip_prefix(r"software\classes\clsid\") {
            let parts: Vec<&str> = r.split('\\').collect();
            if parts.len() == 2 && !parts[0].is_empty() {
                let server_key = matches!(
                    parts[1],
                    "inprocserver32" | "localserver32" | "treatas" | "scriptleturl"
                );
                return server_key && (v.is_empty() || v == "scriptleturl");
            }
        }
    }
    false
}

/// Canonical OS default for `(key, value)` when Kestrel may write it back
/// instead of deleting the value.
pub fn canonical_default(key: &RegKey, value: &str) -> Option<&'static str> {
    if key.hive != Hive::Hklm {
        return None;
    }
    let k = key.canonical.as_str();
    let v = value.to_ascii_lowercase();
    if k == r"software\microsoft\windows nt\currentversion\winlogon" {
        return match v.as_str() {
            "userinit" => Some(r"C:\Windows\system32\userinit.exe,"),
            "shell" => Some("explorer.exe"),
            _ => None,
        };
    }
    if k == r"system\currentcontrolset\control\session manager" && v == "bootexecute" {
        return Some("autocheck autochk *");
    }
    if k == r"system\currentcontrolset\control\securityproviders\wdigest"
        && v == "uselogoncredential"
    {
        return Some("dword:0");
    }
    None
}

/// Does `data` equal the canonical default (case-insensitive, exact otherwise)?
pub fn is_canonical_default(location: &str, value_name: Option<&str>, data: &str) -> bool {
    parse_key(location)
        .and_then(|k| canonical_default(&k, value_name.unwrap_or("")))
        .is_some_and(|d| d.eq_ignore_ascii_case(data))
}

/// Core OS / security services never disabled from the console (lower case).
const CRITICAL_SERVICES: &[&str] = &[
    "appidsvc",
    "appinfo",
    "bfe",
    "brokerinfrastructure",
    "cryptsvc",
    "dcomlaunch",
    "dhcp",
    "dnscache",
    "eventlog",
    "gpsvc",
    "keyiso",
    "lanmanserver",
    "lanmanworkstation",
    "lsm",
    "mdcoresvc",
    "mpssvc",
    "msiserver",
    "netlogon",
    "nsi",
    "plugplay",
    "power",
    "profsvc",
    "rpceptmapper",
    "rpcss",
    "samss",
    "schedule",
    "securityhealthservice",
    "sense",
    "sgrmbroker",
    "systemeventsbroker",
    "termservice",
    "trustedinstaller",
    "usermanager",
    "vaultsvc",
    "wdboot",
    "wdfilter",
    "wdnisdrv",
    "wdnissvc",
    "windefend",
    "winmgmt",
    "wscsvc",
    "wuauserv",
    "sysmon",
    "sysmon64",
    "sysmondrv",
    "kestrelagent",
];

/// Startup-folder file: `X:\…\Microsoft\Windows\Start Menu\Programs\Startup\<file>`.
fn startup_file_ok(path: &str) -> bool {
    let n = path.trim().replace('/', "\\").to_ascii_lowercase();
    const MARK: &str = r"\microsoft\windows\start menu\programs\startup\";
    let b = n.as_bytes();
    let drive = b.len() > 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\';
    if !drive || n.contains(r"\..\") || n.contains(r"\.\") {
        return false;
    }
    let Some(i) = n.find(MARK) else {
        return false;
    };
    let name = &n[i + MARK.len()..];
    !name.is_empty() && !name.contains('\\') && name != "." && name != ".." && name != "desktop.ini"
}

fn task_ok(path: &str) -> bool {
    let p = path.trim();
    if !p.starts_with('\\') || p.len() < 2 || p.ends_with('\\') || p.len() > 512 {
        return false;
    }
    p[1..].split('\\').all(|s| {
        !s.is_empty() && s != "." && s != ".." && s.trim() == s && !s.contains(['*', '?', '/'])
    })
}

fn plain_name_ok(n: &str) -> bool {
    let t = n.trim();
    !t.is_empty() && t == n && t.len() <= 256 && !t.contains(['\\', '/', '*', '?', '"'])
}

/// Full validation of a console-issued `remove_autorun`. Returns the reason
/// for a refusal.
pub fn validate(
    kind: AutorunKind,
    location: &str,
    value_name: Option<&str>,
    restore_data: Option<&str>,
) -> Result<(), String> {
    let loc = location.trim();
    if loc.is_empty() || loc.len() > MAX_LOCATION || unprintable(loc) {
        return Err("remove_autorun needs a location (1-1024 printable characters)".into());
    }
    for v in [value_name, restore_data].into_iter().flatten() {
        if v.len() > 2048 || unprintable(v) {
            return Err(
                "remove_autorun value_name/restore_data too long or contains control characters"
                    .into(),
            );
        }
    }
    if loc.to_ascii_lowercase().contains("kestrel") {
        return Err("remove_autorun never targets Kestrel's own entries".into());
    }
    if restore_data.is_some() && kind != AutorunKind::RegistryValue {
        return Err("restore_data only applies to registry_value".into());
    }
    if value_name.is_some() && kind != AutorunKind::RegistryValue {
        return Err("value_name only applies to registry_value".into());
    }
    match kind {
        AutorunKind::RegistryValue => {
            let key = parse_key(loc).ok_or_else(|| {
                r"registry_value location must be an absolute HKLM\ or HKU\<SID>\ key without wildcards or relative segments".to_string()
            })?;
            let value = value_name.unwrap_or("");
            match restore_data {
                Some(data) => match canonical_default(&key, value) {
                    Some(d) if d.eq_ignore_ascii_case(data) => Ok(()),
                    Some(d) => Err(format!(
                        "restore_data for this value may only be its Windows default ({d})"
                    )),
                    None => Err(
                        "restore_data is only accepted for values with a known Windows default (Winlogon Userinit/Shell, BootExecute, WDigest UseLogonCredential)"
                            .into(),
                    ),
                },
                None if registry_delete_allowed(&key, value) => Ok(()),
                None if canonical_default(&key, value).is_some() => Err(
                    "this OS value is never deleted; restore its Windows default instead".into(),
                ),
                None => Err(
                    "registry_value is limited to known autorun locations (Run/RunOnce, IFEO, SilentProcessExit, per-user Winlogon and COM server keys, AppInit_DLLs, AppCertDlls)"
                        .into(),
                ),
            }
        }
        AutorunKind::StartupFile => startup_file_ok(loc).then_some(()).ok_or_else(|| {
            "startup_file location must be a file directly inside a Startup folder".into()
        }),
        AutorunKind::ScheduledTask => task_ok(loc).then_some(()).ok_or_else(|| {
            r"scheduled_task location must be a task path such as \Folder\Name".into()
        }),
        AutorunKind::Service => {
            if !plain_name_ok(location) {
                return Err("service location is a bare service name".into());
            }
            if CRITICAL_SERVICES.contains(&loc.to_ascii_lowercase().as_str()) {
                return Err("refusing to disable a core OS / security service".into());
            }
            Ok(())
        }
        AutorunKind::WmiSubscription => {
            if !plain_name_ok(location) {
                return Err("wmi_subscription location is a bare consumer name".into());
            }
            if loc.eq_ignore_ascii_case("SCM Event Log Consumer") {
                return Err("built-in Windows consumer, not removed".into());
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AutorunKind as K;

    const SID: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    fn reg(loc: &str, v: &str, data: Option<&str>) -> Result<(), String> {
        validate(K::RegistryValue, loc, Some(v), data)
    }

    #[test]
    fn review_exploits_refused() {
        // V-H2 scenarios from the review.
        assert!(reg(
            r"HKLM\SOFTWARE\Classes\exefile\shell\open\command",
            "",
            Some(r#"C:\Users\Public\x.exe "%1" %*"#)
        )
        .is_err());
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler",
            "ImagePath",
            Some("cmd /c x")
        )
        .is_err());
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
            Some(r"C:\Windows\system32\userinit.exe,\\host\s\x.exe")
        )
        .is_err());
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            Some("dword:1")
        )
        .is_err());
        for svc in ["Sense", "EventLog", "BFE", "mpssvc", "Sysmon64"] {
            assert!(reg(
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{svc}"),
                "Start",
                Some("dword:4")
            )
            .is_err());
            assert!(reg(
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{svc}"),
                "Start",
                None
            )
            .is_err());
        }
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems",
            "Windows",
            None
        )
        .is_err());
        assert!(reg(r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules", "x", None).is_err());
        // HKLM Winlogon values are never deleted.
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "Userinit",
            None
        )
        .is_err());
        // Restore data on a Run key is a free-form write: refused.
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "x",
            Some("evil.exe")
        )
        .is_err());
    }

    #[test]
    fn autorun_deletes_allowed() {
        for (loc, v) in [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".to_string(), "Updater"),
            (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce".to_string(), "x"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\0001".to_string(), "x"),
            (format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run"), "x"),
            (format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"), "x"),
            (format!(r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Windows"), "Load"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe".to_string(), "Debugger"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe".to_string(), "GlobalFlag"),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe".to_string(), "MonitorProcess"),
            (format!(r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"), "Shell"),
            (format!(r"HKU\{SID}\Software\Classes\CLSID\{{0000-1}}\InprocServer32"), ""),
            (format!(r"HKU\{SID}_Classes\CLSID\{{0000-1}}\LocalServer32"), ""),
            (format!(r"HKU\{SID}\Software\Classes\CLSID\{{0000-1}}\TreatAs"), ""),
            (r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows".to_string(), "AppInit_DLLs"),
            (r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCertDlls".to_string(), "x"),
        ] {
            assert!(reg(&loc, v, None).is_ok(), "{loc}\\{v}");
        }
        // Not autorun values in otherwise-known keys.
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe",
            "MitigationOptions",
            None
        )
        .is_err());
        assert!(reg(
            &format!(r"HKU\{SID}\Software\Classes\CLSID\{{0000-1}}\InprocServer32"),
            "ThreadingModel",
            None
        )
        .is_err());
        assert!(reg(
            r"HKLM\SOFTWARE\Classes\CLSID\{0000-1}\InprocServer32",
            "",
            None
        )
        .is_err());
        assert!(reg(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            "x",
            None
        )
        .is_err());
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\..\RunServices",
            "x",
            None
        )
        .is_err());
        assert!(reg(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*",
            "x",
            None
        )
        .is_err());
        assert!(reg(
            r"HKU\notasid\Software\Microsoft\Windows\CurrentVersion\Run",
            "x",
            None
        )
        .is_err());
    }

    #[test]
    fn canonical_restores_only() {
        let wl = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        assert!(reg(wl, "Userinit", Some(r"C:\Windows\system32\userinit.exe,")).is_ok());
        assert!(reg(wl, "Shell", Some("explorer.exe")).is_ok());
        assert!(reg(wl, "Shell", Some("explorer.exe evil.exe")).is_err());
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute",
            Some("autocheck autochk *")
        )
        .is_ok());
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
            "BootExecute",
            Some("autocheck autochk * evil")
        )
        .is_err());
        assert!(reg(
            r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            Some("dword:0")
        )
        .is_ok());
        assert!(is_canonical_default(wl, Some("shell"), "Explorer.exe"));
        assert!(!is_canonical_default(wl, Some("shell"), "cmd.exe"));
        assert!(!is_canonical_default(
            r"HKLM\SOFTWARE\x",
            Some("shell"),
            "explorer.exe"
        ));
    }

    #[test]
    fn other_kinds() {
        let su =
            r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk";
        assert!(validate(K::StartupFile, su, None, None).is_ok());
        assert!(validate(
            K::StartupFile,
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
            None,
            None
        )
        .is_err());
        assert!(validate(
            K::StartupFile,
            r"C:\Users\bob\Documents\thesis.docx",
            None,
            None
        )
        .is_err());
        assert!(validate(K::StartupFile, r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\..\..\x.lnk", None, None).is_err());
        assert!(validate(
            K::StartupFile,
            r"\\host\share\Microsoft\Windows\Start Menu\Programs\Startup\x.lnk",
            None,
            None
        )
        .is_err());
        assert!(validate(K::StartupFile, su, None, Some("x")).is_err());
        assert!(validate(K::ScheduledTask, r"\Updater", None, None).is_ok());
        assert!(validate(K::ScheduledTask, r"\Vendor\Updater", None, None).is_ok());
        assert!(validate(K::ScheduledTask, "Updater", None, None).is_err());
        assert!(validate(K::ScheduledTask, r"\a\..\b", None, None).is_err());
        assert!(validate(K::ScheduledTask, "\\up\u{202E}fdp.exe", None, None).is_err());
        assert!(validate(K::Service, "EvilSvc", None, None).is_ok());
        assert!(validate(K::Service, "WinDefend", None, None).is_err());
        assert!(validate(K::Service, r"x\y", None, None).is_err());
        assert!(validate(K::WmiSubscription, "PdfToolsSync", None, None).is_ok());
        assert!(validate(K::WmiSubscription, "SCM Event Log Consumer", None, None).is_err());
        assert!(validate(K::Service, "x", Some("v"), None).is_err());
    }
}
