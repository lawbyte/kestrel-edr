//! `RemoveAutorun` planning (pure, platform independent).
//!
//! The Windows executor (`win::autorun_resp`) runs as SYSTEM and can delete
//! registry values, scheduled tasks and WMI subscriptions and disable
//! services, so every *decision* about what it may touch lives here, where it
//! is unit-tested on every OS:
//!
//! * **Registry locations** are accepted only under `HKLM\SOFTWARE\…`,
//!   `HKLM\SYSTEM\CurrentControlSet\…` and `HKU\<SID>\…` (at least one key
//!   below those roots). `HKCU` is refused (the agent runs as SYSTEM, so
//!   `HKCU` would be SYSTEM's own hive — callers must name `HKU\<SID>`).
//!   Wildcards (`*`, `?`), empty segments, `.`/`..` segments, control
//!   characters and Kestrel's own keys (`HKLM\SOFTWARE\Kestrel\…`,
//!   `Services\KestrelAgent\…`) are refused; the executor also refuses any
//!   value whose data points into Kestrel's install / state directories
//!   (e.g. the `KestrelTray` Run value). Kestrel objects are recognised by
//!   exact name / location, never by a name prefix, so malware cannot dodge
//!   removal by calling itself "Kestrel…".
//! * **Registry values (V-H2)**: a value may be *deleted* only when it is in
//!   the autorun allow-list ([`plan_registry`]: Run-family keys, Windows
//!   Load/Run, IFEO Debugger/GlobalFlag/VerifierDlls, SilentProcessExit,
//!   per-user Winlogon and COM overrides, AppInit_DLLs, AppCertDlls), and
//!   *written* only with the canonical Windows default for that exact value
//!   from a fixed table ([`os_default`]: HKLM Winlogon Userinit/Shell,
//!   BootExecute, WDigest, Startup shell folders, AppInit_DLLs), with the
//!   table's type, which the live value must already have (a value's type is
//!   never changed). Service `ImagePath`/`Start`, the LSA package lists and
//!   hardening-owned settings (`Lsa\RunAsPPL`) are never written or deleted.
//! * **Scheduled tasks** must be a full `\Folder\Name` path; tasks under
//!   `\Microsoft\Windows\` are refused for automatic (engine / local)
//!   actions; analyst commands may remove them.
//! * **Services**: never `KestrelAgent` (or a service whose binary lives in
//!   Kestrel's directories), never a core OS / security service
//!   ([`CRITICAL_SERVICES`]); boot/system-start drivers and services whose
//!   binary is a Microsoft-signed OS file are refused by the executor (it
//!   needs the live config for that, see [`service_binary`]).
//! * **WMI**: the consumer name must be a plain name; the built-in
//!   `SCM Event Log Consumer` is refused.
//! * **Startup files** must be a direct child of a `…\Start Menu\Programs\Startup`
//!   folder; the file itself goes through the normal quarantine path.
//!
//! Every removal is preceded by a backup ([`AutorunBackup`], stored encrypted
//! in the quarantine vault) and an immediate re-read; if the entry is gone or
//! differs from the backup, nothing is changed.

use kestrel_common::AutorunKind;
use serde::{Deserialize, Serialize};

/// Registry root accepted by [`parse_reg_location`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegRoot {
    Hklm,
    Hku,
}

/// A validated registry key: root + subkey (no leading/trailing `\`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegLocation {
    pub root: RegRoot,
    pub subkey: String,
}

impl RegLocation {
    pub fn display(&self) -> String {
        match self.root {
            RegRoot::Hklm => format!(r"HKLM\{}", self.subkey),
            RegRoot::Hku => format!(r"HKU\{}", self.subkey),
        }
    }

    /// Subkey below the hive, lower-case, with `Wow6432Node\` removed and,
    /// for `HKU`, the `<SID>\` (or `<SID>_Classes\` → `Software\Classes\`)
    /// prefix normalised away. Used for critical-value matching only.
    pub fn canonical(&self) -> String {
        let lower = self.subkey.to_ascii_lowercase();
        let s = match self.root {
            RegRoot::Hklm => lower,
            RegRoot::Hku => {
                let (sid, rest) = lower.split_once('\\').unwrap_or((&lower, ""));
                if sid.ends_with("_classes") {
                    format!(r"software\classes\{rest}")
                } else {
                    rest.to_string()
                }
            }
        };
        s.replace(r"software\wow6432node\", r"software\")
    }
}

fn bad_segment(seg: &str) -> bool {
    seg.is_empty()
        || seg == "."
        || seg == ".."
        || seg.trim() != seg && seg.trim().is_empty()
        || seg.chars().any(|c| c.is_control() || c == '*' || c == '?')
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

/// Kestrel's own keys (exact locations): `SOFTWARE\Kestrel\…` (also under
/// Wow6432Node) and `SYSTEM\CurrentControlSet\Services\KestrelAgent\…`.
fn is_kestrel_key(subkey_lower: &str) -> bool {
    let s = subkey_lower.replace(r"software\wow6432node\", r"software\");
    let svc = format!(
        r"system\currentcontrolset\services\{}",
        crate::consts::SERVICE_NAME.to_ascii_lowercase()
    );
    s == r"software\kestrel"
        || s.starts_with(r"software\kestrel\")
        || s == svc
        || s.starts_with(&format!(r"{svc}\"))
}

/// Does registry / service data reference one of Kestrel's directories?
pub fn references_own_dirs(data: &str, own_dirs: &[String]) -> bool {
    let d = data.to_ascii_lowercase().replace('/', r"\");
    own_dirs
        .iter()
        .map(|p| crate::qpolicy::normalize_for_compare(p))
        .filter(|p| p.len() > 3)
        .any(|p| d.contains(&format!(r"{p}\")))
}

/// `SYSTEM\ControlSet001\x` → `SYSTEM\CurrentControlSet\x` (any 3-digit set).
fn normalise_control_set(rest: &str) -> String {
    let mut parts = rest.splitn(3, '\\');
    let (a, b, c) = (parts.next(), parts.next(), parts.next());
    if let (Some(a), Some(b)) = (a, b) {
        let bl = b.to_ascii_lowercase();
        if a.eq_ignore_ascii_case("SYSTEM")
            && bl.len() == "controlset001".len()
            && bl.starts_with("controlset")
            && bl["controlset".len()..].bytes().all(|x| x.is_ascii_digit())
        {
            return match c {
                Some(c) => format!(r"{a}\CurrentControlSet\{c}"),
                None => format!(r"{a}\CurrentControlSet"),
            };
        }
    }
    rest.to_string()
}

/// Parse and validate a registry key for `RemoveAutorun`.
pub fn parse_reg_location(loc: &str) -> Result<RegLocation, String> {
    let t = loc.trim().trim_end_matches('\\');
    if t.is_empty() {
        return Err("empty registry location".into());
    }
    if t.contains('/') {
        return Err(format!("{loc}: '/' is not a registry separator"));
    }
    let (head, rest) = t.split_once('\\').unwrap_or((t, ""));
    let head_u = head.to_ascii_uppercase();
    let (root, rest) = match head_u.as_str() {
        "HKLM" | "HKEY_LOCAL_MACHINE" => (RegRoot::Hklm, rest),
        "HKU" | "HKEY_USERS" => (RegRoot::Hku, rest),
        "HKCU" | "HKEY_CURRENT_USER" => {
            return Err(format!(
                "{loc}: HKCU is ambiguous for a SYSTEM service; use HKU\\<SID>\\…"
            ))
        }
        "" => {
            // \REGISTRY\MACHINE\… / \REGISTRY\USER\… (kernel form)
            let (r, more) = rest.split_once('\\').unwrap_or((rest, ""));
            if !r.eq_ignore_ascii_case("REGISTRY") {
                return Err(format!("{loc}: unsupported registry root"));
            }
            let (h, more2) = more.split_once('\\').unwrap_or((more, ""));
            if h.eq_ignore_ascii_case("MACHINE") {
                (RegRoot::Hklm, more2)
            } else if h.eq_ignore_ascii_case("USER") {
                (RegRoot::Hku, more2)
            } else {
                return Err(format!("{loc}: unsupported registry root"));
            }
        }
        _ => return Err(format!("{loc}: unsupported registry root {head}")),
    };
    // `SYSTEM\ControlSet00N\…` → `SYSTEM\CurrentControlSet\…` (the engine
    // normalises the same way; the live control set is what is acted on).
    let normalised;
    let rest = match root {
        RegRoot::Hklm => {
            normalised = normalise_control_set(rest);
            normalised.as_str()
        }
        RegRoot::Hku => rest,
    };
    let segs: Vec<&str> = rest.split('\\').collect();
    if segs.iter().any(|s| bad_segment(s)) {
        return Err(format!(
            "{loc}: empty, relative or wildcard key segments are not accepted"
        ));
    }
    let lower = rest.to_ascii_lowercase();
    match root {
        RegRoot::Hklm => {
            let ok = (lower.starts_with(r"software\") && segs.len() >= 2)
                || (lower.starts_with(r"system\currentcontrolset\") && segs.len() >= 3);
            if !ok {
                return Err(format!(
                    "{loc}: only keys under HKLM\\SOFTWARE\\ or HKLM\\SYSTEM\\CurrentControlSet\\ are accepted"
                ));
            }
        }
        RegRoot::Hku => {
            if segs.len() < 2 || !is_sid(segs[0]) {
                return Err(format!("{loc}: only keys under HKU\\<SID>\\ are accepted"));
            }
        }
    }
    let after_root = match root {
        RegRoot::Hku => lower.split_once('\\').map(|x| x.1).unwrap_or(""),
        RegRoot::Hklm => lower.as_str(),
    };
    if is_kestrel_key(after_root) {
        return Err(format!(
            "{loc}: refusing to touch Kestrel's own configuration"
        ));
    }
    Ok(RegLocation {
        root,
        subkey: rest.to_string(),
    })
}

/// Data to write instead of deleting (`restore_data`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreData {
    Dword(u32),
    String(String),
}

/// `dword:N` (decimal or `0x` hex) → DWORD, anything else → string.
pub fn parse_restore_data(s: &str) -> Result<RestoreData, String> {
    if let Some(n) = s
        .strip_prefix("dword:")
        .or_else(|| s.strip_prefix("DWORD:"))
    {
        let n = n.trim();
        let v = if let Some(h) = n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
            u32::from_str_radix(h, 16)
        } else {
            n.parse::<u32>()
        };
        return v
            .map(RestoreData::Dword)
            .map_err(|_| format!("invalid dword restore value {s:?}"));
    }
    if s.chars().any(|c| c == '\0') {
        return Err("restore data contains NUL".into());
    }
    Ok(RestoreData::String(s.to_string()))
}

/// What to do with the registry value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegOp {
    Delete,
    /// Write the canonical OS default. `reg_type` is the type the value must
    /// already have (and is written with): the type is never changed.
    Write {
        reg_type: u32,
        data: RestoreData,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegPlan {
    pub location: RegLocation,
    /// "" = the key's default value.
    pub value_name: String,
    pub op: RegOp,
}

const CV: &str = r"software\microsoft\windows\currentversion";
const NTCV: &str = r"software\microsoft\windows nt\currentversion";

/// Values Kestrel never writes or deletes, whatever the request (V-H2):
/// service `ImagePath` / `Start` (SYSTEM code execution, disabling security
/// services past the service guards), the LSA package lists, and security
/// settings Kestrel's hardening owns (`RunAsPPL`, `LsaCfgFlags`).
fn forbidden_value(loc: &RegLocation, value: &str) -> Option<&'static str> {
    if loc.root != RegRoot::Hklm {
        return None;
    }
    let k = loc.canonical();
    let v = value.to_ascii_lowercase();
    if let Some(svc) = k.strip_prefix(r"system\currentcontrolset\services\") {
        if !svc.contains('\\') && matches!(v.as_str(), "imagepath" | "start") {
            return Some("service ImagePath / Start values are never written or deleted (disable the service with kind=service instead)");
        }
    }
    if k == r"system\currentcontrolset\control\lsa" {
        if matches!(
            v.as_str(),
            "security packages" | "authentication packages" | "notification packages"
        ) {
            return Some("LSA package lists are never written or deleted");
        }
        if matches!(v.as_str(), "runasppl" | "lsacfgflags") {
            return Some("security setting managed by hardening");
        }
    }
    if k == r"system\currentcontrolset\control\lsa\osconfig" && v == "security packages" {
        return Some("LSA package lists are never written or deleted");
    }
    None
}

/// Is `k` exactly `<prefix>\<one segment>`? Returns the segment.
fn one_below<'a>(k: &'a str, prefix: &str) -> Option<&'a str> {
    k.strip_prefix(prefix)
        .and_then(|r| r.strip_prefix('\\'))
        .filter(|s| !s.is_empty() && !s.contains('\\'))
}

/// Allow-list of autorun values that may be **deleted** (V-H2). `k` and `v`
/// are lower-case; `k` is [`RegLocation::canonical`] (Wow6432Node folded,
/// HKU SID / `_Classes` normalised).
fn deletable(root: RegRoot, k: &str, v: &str) -> bool {
    // Run-family keys, HKLM and HKU (incl. Wow6432Node via `canonical`).
    for run in [
        "run",
        "runonce",
        "runservices",
        "runservicesonce",
        r"policies\explorer\run",
    ] {
        if k == format!(r"{CV}\{run}") {
            return true;
        }
    }
    let rox = format!(r"{CV}\runonceex");
    if k == rox || k.starts_with(&format!(r"{rox}\")) {
        return true;
    }
    if k == format!(r"{NTCV}\windows") && matches!(v, "load" | "run") {
        return true;
    }
    if one_below(k, &format!(r"{NTCV}\image file execution options")).is_some()
        && matches!(v, "debugger" | "globalflag" | "verifierdlls")
    {
        return true;
    }
    if one_below(k, &format!(r"{NTCV}\silentprocessexit")).is_some() {
        return true;
    }
    // Shell override through policy (falls back to Winlogon).
    if k == format!(r"{CV}\policies\system") && v == "shell" {
        return true;
    }
    match root {
        RegRoot::Hku => {
            // Per-user Winlogon overrides (HKLM Winlogon is restore-only).
            if k == format!(r"{NTCV}\winlogon") && matches!(v, "shell" | "userinit") {
                return true;
            }
            // Per-user COM hijacks.
            if let Some(tail) = k.strip_prefix(r"software\classes\clsid\") {
                match tail.split_once('\\') {
                    Some((clsid, sub)) => {
                        return !clsid.is_empty()
                            && v.is_empty()
                            && matches!(
                                sub,
                                "inprocserver32" | "inprochandler32" | "localserver32" | "treatas"
                            );
                    }
                    None => return !tail.is_empty() && v == "scriptleturl",
                }
            }
            false
        }
        RegRoot::Hklm => {
            (k == format!(r"{NTCV}\windows") && v == "appinit_dlls")
                || k == r"system\currentcontrolset\control\session manager\appcertdlls"
        }
    }
}

/// One canonical OS default (V-H2 restore table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultValue {
    pub reg_type: u32,
    pub data: RestoreData,
}

/// The canonical Windows default for (root, canonical key, value), if this
/// value is restorable. `system_root` is the executor's Windows directory
/// (`GetSystemWindowsDirectoryW`, e.g. `C:\Windows`).
///
/// Sources (checked 2026-10-21):
/// * Winlogon `Userinit` = `C:\Windows\system32\userinit.exe,` and `Shell` =
///   `explorer.exe` (REG_SZ): Microsoft Learn, "Winlogon registry entries"
///   / MITRE ATT&CK T1547.004; the trailing comma is part of the default.
/// * Session Manager `BootExecute` = `autocheck autochk *` (REG_MULTI_SZ):
///   Microsoft Learn, "BootExecute" (Windows registry reference) / Sysinternals
///   Autoruns default.
/// * WDigest `UseLogonCredential` / `Negotiate` = 0 (REG_DWORD): KB2871997
///   (0 = no cleartext credentials in LSASS; also the effective default).
/// * User Shell Folders `Startup` (HKU) =
///   `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`
///   and `Common Startup` (HKLM) =
///   `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp`
///   (REG_EXPAND_SZ): Known Folder defaults (FOLDERID_Startup /
///   FOLDERID_CommonStartup, Microsoft Learn "KNOWNFOLDERID"). Compared
///   case-insensitively (paths), written exactly as listed here.
/// * `AppInit_DLLs` (HKLM `Windows NT\CurrentVersion\Windows`) = "" (REG_SZ):
///   the shipped value is an empty string (Microsoft Learn, "AppInit DLLs
///   and Secure Boot").
pub fn os_default(root: RegRoot, k: &str, v: &str, system_root: &str) -> Option<DefaultValue> {
    let s = |reg_type: u32, d: &str| {
        Some(DefaultValue {
            reg_type,
            data: RestoreData::String(d.to_string()),
        })
    };
    match root {
        RegRoot::Hklm => {
            if k == format!(r"{NTCV}\winlogon") {
                return match v {
                    "userinit" => s(
                        REG_SZ,
                        &format!(
                            r"{}\system32\userinit.exe,",
                            system_root.trim_end_matches('\\')
                        ),
                    ),
                    "shell" => s(REG_SZ, "explorer.exe"),
                    _ => None,
                };
            }
            if k == r"system\currentcontrolset\control\session manager" && v == "bootexecute" {
                return s(REG_MULTI_SZ, "autocheck autochk *");
            }
            if k == r"system\currentcontrolset\control\securityproviders\wdigest"
                && matches!(v, "uselogoncredential" | "negotiate")
            {
                return Some(DefaultValue {
                    reg_type: REG_DWORD,
                    data: RestoreData::Dword(0),
                });
            }
            if k == format!(r"{CV}\explorer\user shell folders") && v == "common startup" {
                return s(
                    REG_EXPAND_SZ,
                    r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp",
                );
            }
            if k == format!(r"{NTCV}\windows") && v == "appinit_dlls" {
                return s(REG_SZ, "");
            }
            None
        }
        RegRoot::Hku => {
            if k == format!(r"{CV}\explorer\user shell folders") && v == "startup" {
                return s(
                    REG_EXPAND_SZ,
                    r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
                );
            }
            None
        }
    }
}

fn same_restore(a: &RestoreData, b: &RestoreData) -> bool {
    match (a, b) {
        (RestoreData::Dword(x), RestoreData::Dword(y)) => x == y,
        (RestoreData::String(x), RestoreData::String(y)) => x.eq_ignore_ascii_case(y),
        _ => false,
    }
}

/// Validate a `RemoveAutorun { kind: RegistryValue, .. }` (V-H2).
///
/// * Deletes only for the autorun allow-list ([`deletable`]).
/// * `restore_data` only when it equals the canonical OS default for that
///   exact value ([`os_default`]); the table's data and type are written,
///   and the executor refuses if the live value has another type.
/// * Never: service ImagePath / Start, LSA package lists, hardening settings.
pub fn plan_registry(
    location: &str,
    value_name: Option<&str>,
    restore_data: Option<&str>,
    system_root: &str,
) -> Result<RegPlan, String> {
    let loc = parse_reg_location(location)?;
    let value = value_name.unwrap_or("").to_string();
    if value.chars().any(|c| c.is_control()) || value.contains('*') || value.contains('?') {
        return Err("invalid value name".into());
    }
    let shown = || {
        if value.is_empty() {
            format!(r"{}\(default)", loc.display())
        } else {
            format!(r"{}\{value}", loc.display())
        }
    };
    if let Some(why) = forbidden_value(&loc, &value) {
        return Err(format!("refusing to change {}: {why}", shown()));
    }
    let k = loc.canonical();
    let v = value.to_ascii_lowercase();
    let op = match restore_data {
        None => {
            if !deletable(loc.root, &k, &v) {
                return Err(format!(
                    "refusing to delete {}: not a recognised autorun location (Run/RunOnce/RunOnceEx/policy Run, Windows Load/Run, IFEO Debugger/GlobalFlag/VerifierDlls, SilentProcessExit, per-user Winlogon/COM overrides, AppInit_DLLs, AppCertDlls); OS defaults are restored, never deleted",
                    shown()
                ));
            }
            RegOp::Delete
        }
        Some(r) => {
            let want = parse_restore_data(r)?;
            let Some(def) = os_default(loc.root, &k, &v, system_root) else {
                return Err(format!(
                    "refusing to write {}: restore is only allowed for values with a fixed Windows default (Winlogon Userinit/Shell, BootExecute, WDigest, Startup shell folders, AppInit_DLLs)",
                    shown()
                ));
            };
            if !same_restore(&want, &def.data) {
                return Err(format!(
                    "refusing to write {r:?} to {}: only the Windows default {:?} may be restored",
                    shown(),
                    def.data
                ));
            }
            RegOp::Write {
                reg_type: def.reg_type,
                data: def.data,
            }
        }
    };
    Ok(RegPlan {
        location: loc,
        value_name: value,
        op,
    })
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

/// Encode a replacement: (registry type, bytes). `original_type` is the
/// plan's type ([`RegOp::Write`]), which the live value must already have.
/// Strings: `REG_EXPAND_SZ` stays expandable; `REG_MULTI_SZ` takes elements
/// separated by a literal `\0`; anything else is `REG_SZ`.
pub fn encode_restore(original_type: u32, data: &RestoreData) -> (u32, Vec<u8>) {
    match data {
        RestoreData::Dword(n) => (REG_DWORD, n.to_le_bytes().to_vec()),
        RestoreData::String(s) => match original_type {
            REG_EXPAND_SZ => (REG_EXPAND_SZ, utf16z(s)),
            REG_MULTI_SZ => {
                let mut b = Vec::new();
                for part in s.split("\\0").filter(|p| !p.is_empty()) {
                    b.extend(utf16z(part));
                }
                b.extend([0u8, 0u8]);
                (REG_MULTI_SZ, b)
            }
            _ => (REG_SZ, utf16z(s)),
        },
    }
}

/// For a restore, the live value must already have the table's type: the
/// executor checks this on the value it backed up and again right before
/// writing (a value's type is never changed). Deletes accept any type.
pub fn check_live_type(op: &RegOp, live_type: u32) -> Result<(), String> {
    match op {
        RegOp::Delete => Ok(()),
        RegOp::Write { reg_type, .. } if *reg_type == live_type => Ok(()),
        RegOp::Write { reg_type, .. } => Err(format!(
            "the value is {} but its Windows default is {}; refusing to change a value's type",
            reg_type_name(live_type),
            reg_type_name(*reg_type)
        )),
    }
}

pub fn reg_type_name(t: u32) -> &'static str {
    match t {
        0 => "REG_NONE",
        REG_SZ => "REG_SZ",
        REG_EXPAND_SZ => "REG_EXPAND_SZ",
        REG_BINARY => "REG_BINARY",
        REG_DWORD => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        REG_MULTI_SZ => "REG_MULTI_SZ",
        REG_QWORD => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

// ------------------------------------------------------------------ tasks

/// Validate a task path; returns (folder, name). `engine` = automatic action.
pub fn plan_task(path: &str, engine: bool) -> Result<(String, String), String> {
    let p = path.trim();
    if !p.starts_with('\\') || p.len() < 2 || p.ends_with('\\') {
        return Err(format!("{path}: task path must be \\Folder\\Name"));
    }
    let segs: Vec<&str> = p[1..].split('\\').collect();
    if segs.iter().any(|s| bad_segment(s) || s.contains('/')) {
        return Err(format!(
            "{path}: empty, relative or wildcard task path segments"
        ));
    }
    let lower = p.to_ascii_lowercase();
    if engine && lower.starts_with(r"\microsoft\windows\") {
        return Err(format!(
            "{path}: automatic removal of tasks under \\Microsoft\\Windows\\ is not allowed (use an analyst command)"
        ));
    }
    let name = segs[segs.len() - 1].to_string();
    let folder = if segs.len() == 1 {
        "\\".to_string()
    } else {
        format!("\\{}", segs[..segs.len() - 1].join("\\"))
    };
    Ok((folder, name))
}

// ------------------------------------------------------------------ services

/// Core OS / security services never disabled (lower-case service names).
pub const CRITICAL_SERVICES: &[&str] = &[
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
];

pub fn plan_service(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty()
        || n.len() > 256
        || n.contains('\\')
        || n.contains('/')
        || n.chars().any(|c| c.is_control() || c == '*' || c == '?')
    {
        return Err(format!("{name:?}: invalid service name"));
    }
    let l = n.to_ascii_lowercase();
    if l == crate::consts::SERVICE_NAME.to_ascii_lowercase() {
        return Err(format!("{n}: refusing to touch the Kestrel service"));
    }
    if CRITICAL_SERVICES.contains(&l.as_str()) {
        return Err(format!(
            "{n}: refusing to disable a core OS / security service"
        ));
    }
    Ok(n.to_string())
}

/// Executable path from a service `ImagePath` / `lpBinaryPathName`
/// (quotes, `\SystemRoot\`, `system32\…`, `\??\` forms).
pub fn service_binary(image_path: &str, system_root: &str) -> Option<String> {
    let t = image_path.trim();
    if t.is_empty() {
        return None;
    }
    let raw = if let Some(r) = t.strip_prefix('"') {
        r.split('"').next().unwrap_or(r).to_string()
    } else {
        let lower = t.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(i) => t[..i + 4].to_string(),
            None => match lower.find(".sys") {
                Some(i) => t[..i + 4].to_string(),
                None => t.split_whitespace().next().unwrap_or(t).to_string(),
            },
        }
    };
    let raw = raw.strip_prefix(r"\??\").unwrap_or(&raw).to_string();
    let lower = raw.to_ascii_lowercase();
    let sr = system_root.trim_end_matches('\\');
    let out = if let Some(r) = lower.strip_prefix(r"\systemroot\") {
        format!(r"{sr}\{}", &raw[raw.len() - r.len()..])
    } else if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        format!(r"{sr}\{raw}")
    } else if let Some(r) = lower.strip_prefix(r"%systemroot%\") {
        format!(r"{sr}\{}", &raw[raw.len() - r.len()..])
    } else if let Some(r) = lower.strip_prefix(r"%windir%\") {
        format!(r"{sr}\{}", &raw[raw.len() - r.len()..])
    } else {
        raw
    };
    Some(out)
}

/// Interpreters / proxies that malware wraps a service command in; a
/// service using one of them as its binary is never treated as "an OS
/// service" just because the binary is Microsoft-signed.
pub fn is_wrapper_binary(path: &str) -> bool {
    let name = path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    matches!(
        name.as_str(),
        "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "mshta.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "conhost.exe"
            | "msbuild.exe"
            | "installutil.exe"
            | "regasm.exe"
            | "regsvcs.exe"
            | "forfiles.exe"
            | "certutil.exe"
            | "bitsadmin.exe"
    )
}

pub fn is_svchost(path: &str) -> bool {
    path.rsplit(['\\', '/'])
        .next()
        .is_some_and(|n| n.eq_ignore_ascii_case("svchost.exe"))
}

/// Is `path` under `%SystemRoot%`?
pub fn under_system_root(path: &str, system_root: &str) -> bool {
    let p = crate::qpolicy::normalize_for_compare(path);
    let r = crate::qpolicy::normalize_for_compare(system_root);
    !r.is_empty() && p.starts_with(&format!("{r}\\"))
}

// ------------------------------------------------------------------ WMI

pub fn plan_wmi_consumer(name: &str) -> Result<String, String> {
    let n = name.trim();
    if n.is_empty() || n.len() > 256 || n.chars().any(|c| c.is_control()) {
        return Err(format!("{name:?}: invalid WMI consumer name"));
    }
    let l = n.to_ascii_lowercase();
    // Built-in consumer shipped with Windows (SCM event log → NTEventLog).
    if l == "scm event log consumer" {
        return Err(format!("{n}: built-in Windows consumer, not removed"));
    }
    Ok(n.to_string())
}

/// Escape a string for a single-quoted WQL literal.
pub fn wql_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('\'');
    for c in s.chars() {
        if c == '\\' || c == '\'' {
            o.push('\\');
        }
        o.push(c);
    }
    o.push('\'');
    o
}

/// Normalise a WMI object path / reference for comparison: drop the
/// `\\SERVER\namespace:` prefix, lower-case, unify quote styles.
pub fn wmi_ref_key(r: &str) -> String {
    let t = r.trim();
    let t = if t.starts_with("\\\\") {
        t.split_once(':').map(|x| x.1).unwrap_or(t)
    } else {
        t
    };
    t.replace('\'', "\"").to_ascii_lowercase()
}

/// Parse `Prop = {1, 2};` / `Prop = 2;` from MOF text (`GetObjectText`).
pub fn mof_u32_list(mof: &str, prop: &str) -> Option<Vec<u32>> {
    for line in mof.lines() {
        let l = line.trim();
        let Some((k, v)) = l.split_once('=') else {
            continue;
        };
        if !k.trim().eq_ignore_ascii_case(prop) {
            continue;
        }
        let v = v.trim().trim_end_matches(';').trim();
        let v = v.trim_start_matches('{').trim_end_matches('}');
        let mut out = Vec::new();
        for p in v.split(',') {
            let p = p.trim();
            if p.is_empty() {
                continue;
            }
            out.push(p.parse().ok()?);
        }
        return Some(out);
    }
    None
}

// ------------------------------------------------------------------ startup files

/// The file must sit directly in a `…\Start Menu\Programs\Startup` folder.
pub fn plan_startup_file(path: &str) -> Result<(), String> {
    let n = crate::qpolicy::normalize_for_compare(path);
    const MARK: &str = r"\microsoft\windows\start menu\programs\startup\";
    let Some(i) = n.find(MARK) else {
        return Err(format!("{path}: not in a Startup folder"));
    };
    let name = &n[i + MARK.len()..];
    if name.is_empty() || name.contains('\\') || name == "." || name == ".." {
        return Err(format!(
            "{path}: only files directly inside a Startup folder are accepted"
        ));
    }
    if name.eq_ignore_ascii_case("desktop.ini") {
        return Err(format!("{path}: desktop.ini is not an autorun"));
    }
    Ok(())
}

// ------------------------------------------------------------------ backup format

/// One registry value as captured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegValueDump {
    pub name: String,
    pub reg_type: u32,
    pub type_name: String,
    pub data_hex: String,
}

impl RegValueDump {
    pub fn new(name: &str, reg_type: u32, data: &[u8]) -> RegValueDump {
        RegValueDump {
            name: name.to_string(),
            reg_type,
            type_name: reg_type_name(reg_type).to_string(),
            data_hex: crate::vault::hex(data),
        }
    }
}

/// A WMI object exported as MOF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WmiObjectDump {
    pub path: String,
    pub mof: String,
    /// Was it deleted (filters shared with other bindings are kept).
    #[serde(default)]
    pub deleted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum BackupData {
    Registry {
        value: RegValueDump,
    },
    Task {
        xml: String,
        enabled: bool,
    },
    Service {
        service_type: u32,
        start_type: u32,
        error_control: u32,
        binary_path: String,
        load_order_group: String,
        dependencies: Vec<String>,
        start_name: String,
        display_name: String,
        /// Values of `Services\<name>` and `Services\<name>\Parameters`.
        registry: Vec<RegValueDump>,
        #[serde(default)]
        parameters: Vec<RegValueDump>,
        was_running: bool,
    },
    Wmi {
        consumer: WmiObjectDump,
        bindings: Vec<WmiObjectDump>,
        filters: Vec<WmiObjectDump>,
    },
}

/// What the vault stores for a `RemoveAutorun` (JSON, then AES-GCM sealed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutorunBackup {
    pub format: u32,
    pub kind: AutorunKind,
    pub location: String,
    #[serde(default)]
    pub value_name: Option<String>,
    pub captured_at: i64,
    pub data: BackupData,
}

pub const BACKUP_FORMAT: u32 = 1;

impl AutorunBackup {
    /// Label stored as the vault entry's `original_path`.
    pub fn label(&self) -> String {
        let kind = serde_json::to_value(self.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
        match &self.value_name {
            Some(v) => format!("autorun:{kind}:{}!{v}", self.location),
            None => format!("autorun:{kind}:{}", self.location),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    pub fn from_bytes(b: &[u8]) -> Result<AutorunBackup, String> {
        let a: AutorunBackup =
            serde_json::from_slice(b).map_err(|e| format!("bad autorun backup: {e}"))?;
        if a.format != BACKUP_FORMAT {
            return Err(format!("unsupported autorun backup format {}", a.format));
        }
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_locations() {
        let l = parse_reg_location(r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run").unwrap();
        assert_eq!(l.root, RegRoot::Hklm);
        assert_eq!(
            l.display(),
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        );
        let l = parse_reg_location(
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run",
        )
        .unwrap();
        assert_eq!(l.root, RegRoot::Hku);
        assert_eq!(
            l.canonical(),
            r"software\microsoft\windows\currentversion\run"
        );
        let l = parse_reg_location(r"HKU\S-1-5-21-1-2-3-1001_Classes\CLSID\{x}\InprocServer32")
            .unwrap();
        assert_eq!(l.canonical(), r"software\classes\clsid\{x}\inprocserver32");
        assert!(parse_reg_location(
            r"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Evil\Parameters"
        )
        .is_ok());
        assert_eq!(
            parse_reg_location(r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")
                .unwrap()
                .canonical(),
            r"software\microsoft\windows\currentversion\run"
        );
        // prefix look-alikes are NOT Kestrel's (no evasion by naming)
        assert!(parse_reg_location(r"HKLM\SOFTWARE\KestrelUpdate\Run").is_ok());
        // ControlSet00N is folded to CurrentControlSet.
        assert_eq!(
            parse_reg_location(r"HKLM\SYSTEM\ControlSet001\Services\x")
                .unwrap()
                .subkey,
            r"SYSTEM\CurrentControlSet\Services\x"
        );
        assert!(parse_reg_location(r"HKLM\SYSTEM\ControlSet002\Services\KestrelAgent").is_err());
        assert!(
            parse_reg_location(r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent2").is_ok()
        );
        let own = vec![r"C:\Program Files\Kestrel".to_string()];
        assert!(references_own_dirs(
            r#""C:\Program Files\Kestrel\kestrel-tray.exe" --background"#,
            &own
        ));
        assert!(!references_own_dirs(
            r"C:\Users\a\AppData\Kestrel\x.exe",
            &own
        ));
        assert!(!references_own_dirs(
            r"C:\Program Files\KestrelX\x.exe",
            &own
        ));
        // refused
        for bad in [
            "",
            "   ",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM\SAM\SAM",
            r"HKLM\SECURITY\Policy",
            r"HKLM\SOFTWARE",
            r"HKLM\SYSTEM\ControlSet001",
            r"HKLM\SYSTEM\Select\x",
            r"HKLM\SYSTEM\CurrentControlSet",
            r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent",
            r"HKLM\SYSTEM\CurrentControlSet\Services\kestrelagent\Parameters",
            r"HKLM\SOFTWARE\Kestrel\Setup",
            r"HKLM\SOFTWARE\Kestrel",
            r"HKLM\SOFTWARE\WOW6432Node\Kestrel\Setup",
            r"HKLM\SOFTWARE\Microsoft\*\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Ru?",
            r"HKLM\SOFTWARE\\Microsoft",
            r"HKLM\SOFTWARE\..\SAM",
            r"HKU\.DEFAULT\Software\Run",
            r"HKU\S-1-5-21-1-2-3-1001",
            r"HKU\S-1-x\Software\Run",
            r"HKCR\CLSID\x",
            "HKLM/SOFTWARE/Run",
        ] {
            assert!(parse_reg_location(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn restore_data() {
        assert_eq!(
            parse_restore_data("dword:0").unwrap(),
            RestoreData::Dword(0)
        );
        assert_eq!(
            parse_restore_data("dword:0x10").unwrap(),
            RestoreData::Dword(16)
        );
        assert!(parse_restore_data("dword:-1").is_err());
        assert!(parse_restore_data("dword:abc").is_err());
        assert_eq!(
            parse_restore_data(r"C:\Windows\system32\userinit.exe,").unwrap(),
            RestoreData::String(r"C:\Windows\system32\userinit.exe,".into())
        );
        assert!(parse_restore_data("a\0b").is_err());
        let (t, b) = encode_restore(REG_SZ, &RestoreData::Dword(1));
        assert_eq!((t, b), (REG_DWORD, vec![1, 0, 0, 0]));
        let (t, b) = encode_restore(REG_EXPAND_SZ, &RestoreData::String("a".into()));
        assert_eq!((t, b), (REG_EXPAND_SZ, vec![b'a', 0, 0, 0]));
        let (t, b) = encode_restore(REG_MULTI_SZ, &RestoreData::String("a\\0b".into()));
        assert_eq!(t, REG_MULTI_SZ);
        assert_eq!(b, vec![b'a', 0, 0, 0, b'b', 0, 0, 0, 0, 0]);
        let (t, _) = encode_restore(REG_BINARY, &RestoreData::String("x".into()));
        assert_eq!(t, REG_SZ);
    }

    const SR: &str = r"C:\Windows";
    const SID: &str = "S-1-5-21-1-2-3-1001";

    fn del(loc: &str, v: &str) -> Result<RegPlan, String> {
        plan_registry(loc, Some(v), None, SR)
    }

    fn put(loc: &str, v: &str, data: &str) -> Result<RegPlan, String> {
        plan_registry(loc, Some(v), Some(data), SR)
    }

    #[test]
    fn registry_delete_allow_list() {
        let hku = |rest: &str| format!(r"HKU\{SID}\{rest}");
        let mut ok: Vec<(String, &str)> = Vec::new();
        for base in [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion".to_string(),
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion".to_string(),
            hku(r"Software\Microsoft\Windows\CurrentVersion"),
            hku(r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion"),
        ] {
            for k in [
                "Run",
                "RunOnce",
                "RunServices",
                "RunServicesOnce",
                r"Policies\Explorer\Run",
                "RunOnceEx",
                r"RunOnceEx\0001",
                r"RunOnceEx\0001\Depend",
            ] {
                ok.push((format!(r"{base}\{k}"), "Updater"));
            }
            ok.push((format!(r"{base}\Policies\System"), "Shell"));
        }
        for base in [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion".to_string(),
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion".to_string(),
            hku(r"Software\Microsoft\Windows NT\CurrentVersion"),
        ] {
            ok.push((format!(r"{base}\Windows"), "Load"));
            ok.push((format!(r"{base}\Windows"), "Run"));
            for v in ["Debugger", "GlobalFlag", "VerifierDlls"] {
                ok.push((format!(r"{base}\Image File Execution Options\sethc.exe"), v));
            }
            ok.push((
                format!(r"{base}\SilentProcessExit\lsass.exe"),
                "MonitorProcess",
            ));
            ok.push((
                format!(r"{base}\SilentProcessExit\notepad.exe"),
                "ReportingMode",
            ));
        }
        ok.push((
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows".into(),
            "AppInit_DLLs",
        ));
        ok.push((
            r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows".into(),
            "AppInit_DLLs",
        ));
        ok.push((
            r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls".into(),
            "evil",
        ));
        ok.push((
            r"HKLM\SYSTEM\ControlSet001\Control\Session Manager\AppCertDlls".into(),
            "evil",
        ));
        ok.push((
            hku(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            "Shell",
        ));
        ok.push((
            hku(r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            "Userinit",
        ));
        for sub in [
            "InprocServer32",
            "LocalServer32",
            "TreatAs",
            "InprocHandler32",
        ] {
            ok.push((hku(&format!(r"Software\Classes\CLSID\{{AAAA}}\{sub}")), ""));
            ok.push((format!(r"HKU\{SID}_Classes\CLSID\{{AAAA}}\{sub}"), ""));
        }
        ok.push((hku(r"Software\Classes\CLSID\{AAAA}"), "ScriptletURL"));
        for (loc, v) in &ok {
            let p = del(loc, v).unwrap_or_else(|e| panic!("{loc}\\{v}: {e}"));
            assert_eq!(p.op, RegOp::Delete);
        }
        // Default value of a Run key.
        assert_eq!(
            plan_registry(&ok[0].0, None, None, SR).unwrap().value_name,
            ""
        );

        // Refused deletes.
        for (loc, v) in [
            // OS defaults are restored, never deleted.
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Userinit",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "Shell",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager",
                "BootExecute",
            ),
            // Bricks the host.
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems",
                "Windows",
            ),
            (r"HKLM\SYSTEM\CurrentControlSet\Services\disk", "Start"),
            (r"HKLM\SYSTEM\CurrentControlSet\Services\Evil", "ImagePath"),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\Evil\Parameters",
                "ServiceDll",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "Notification Packages",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
                "Security Packages",
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig",
                "Security Packages",
            ),
            (r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
            // Kestrel's hardening (ASR / AppLocker / Defender policy values).
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
                "d4f940ab-401b-4efc-aadc-ad5f3c50688a",
            ),
            (
                r"HKLM\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe\abc",
                "Value",
            ),
            // exefile handler, CLSID in HKLM, IFEO other values / per-path keys.
            (r"HKLM\SOFTWARE\Classes\exefile\shell\open\command", ""),
            (r"HKLM\SOFTWARE\Classes\CLSID\{AAAA}\InprocServer32", ""),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe",
                "UseFilter",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe\Filter1",
                "Debugger",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
                "Debugger",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
                "Device",
            ),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunX", "a"),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Sub",
                "a",
            ),
            // COM: only the server default value / ScriptletURL.
            (
                r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{AAAA}\InprocServer32",
                "ThreadingModel",
            ),
            (r"HKU\S-1-5-21-1-2-3-1001\Software\Classes\CLSID\{AAAA}", ""),
            // AppInit / AppCert are machine-wide only.
            (
                r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows NT\CurrentVersion\Windows",
                "AppInit_DLLs",
            ),
        ] {
            assert!(del(loc, v).is_err(), "delete {loc}\\{v} should be refused");
        }
        let run = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run");
        assert!(del(&run, "a*").is_err());
        assert!(del(&run, "a?").is_err());
    }

    #[test]
    fn registry_restore_table() {
        let wl = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        let wd = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        let sm = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager";
        let usf_u = format!(
            r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        );
        let usf_m = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders";
        let win = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";

        // Canonical defaults (the engine's constants included) are accepted
        // and carry the table's type.
        let p = put(wd, "UseLogonCredential", "dword:0").unwrap();
        assert_eq!(
            p.op,
            RegOp::Write {
                reg_type: REG_DWORD,
                data: RestoreData::Dword(0)
            }
        );
        assert!(put(wd, "Negotiate", "dword:0").is_ok());
        let p = put(wl, "Userinit", r"C:\Windows\system32\userinit.exe,").unwrap();
        assert_eq!(
            p.op,
            RegOp::Write {
                reg_type: REG_SZ,
                data: RestoreData::String(r"C:\Windows\system32\userinit.exe,".into())
            }
        );
        // Case-insensitive (engine upper-cases the drive letter).
        assert!(put(wl, "Userinit", r"c:\WINDOWS\System32\userinit.exe,").is_ok());
        // ...but the drive must be the system root's.
        assert!(plan_registry(
            wl,
            Some("Userinit"),
            Some(r"C:\Windows\system32\userinit.exe,"),
            r"D:\Windows"
        )
        .is_err());
        assert!(put(wl, "Shell", "explorer.exe").is_ok());
        let p = put(sm, "BootExecute", "autocheck autochk *").unwrap();
        assert!(matches!(
            p.op,
            RegOp::Write {
                reg_type: REG_MULTI_SZ,
                ..
            }
        ));
        let p = put(
            &usf_u,
            "Startup",
            r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        )
        .unwrap();
        assert!(matches!(
            p.op,
            RegOp::Write {
                reg_type: REG_EXPAND_SZ,
                ..
            }
        ));
        // The engine sends "Startup"; the shipped HKLM value is "StartUp".
        let p = put(
            usf_m,
            "Common Startup",
            r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup",
        )
        .unwrap();
        assert_eq!(
            p.op,
            RegOp::Write {
                reg_type: REG_EXPAND_SZ,
                data: RestoreData::String(
                    r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp".into()
                )
            }
        );
        let p = put(win, "AppInit_DLLs", "").unwrap();
        assert_eq!(
            p.op,
            RegOp::Write {
                reg_type: REG_SZ,
                data: RestoreData::String(String::new())
            }
        );

        // The review's exploit examples.
        assert!(put(
            r"HKLM\SOFTWARE\Classes\exefile\shell\open\command",
            "",
            "C:\\Users\\Public\\x.exe \"%1\" %*"
        )
        .is_err());
        assert!(put(
            r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler",
            "ImagePath",
            "cmd /c calc"
        )
        .is_err());
        for svc in ["Sense", "EventLog", "BFE", "mpssvc", "Sysmon64"] {
            assert!(put(
                &format!(r"HKLM\SYSTEM\CurrentControlSet\Services\{svc}"),
                "Start",
                "dword:4"
            )
            .is_err());
        }
        assert!(put(
            r"HKLM\SYSTEM\ControlSet001\Services\Sense",
            "Start",
            "dword:4"
        )
        .is_err());
        assert!(put(
            wl,
            "Userinit",
            r"C:\Windows\system32\userinit.exe,\\host\s\x.exe"
        )
        .is_err());
        assert!(put(wl, "Userinit", r"C:\evil.exe").is_err());
        assert!(put(wl, "Userinit", "dword:0").is_err());
        assert!(put(wl, "Shell", "explorer.exe, evil.exe").is_err());
        assert!(put(wl, "Shell", "").is_err());
        assert!(put(wd, "UseLogonCredential", "dword:1").is_err());
        assert!(
            put(wd, "UseLogonCredential", "0").is_err(),
            "string for a dword"
        );
        assert!(put(sm, "BootExecute", "autocheck autochk * evil").is_err());
        assert!(put(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "Security Packages",
            "kerberos"
        )
        .is_err());
        assert!(put(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            "dword:0"
        )
        .is_err());
        assert!(put(&usf_u, "Startup", r"C:\Users\Public\evil").is_err());
        // Restores are per hive: Startup is HKU, Common Startup HKLM; HKU
        // Winlogon overrides are deleted, not restored.
        assert!(put(
            usf_m,
            "Startup",
            r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        )
        .is_err());
        assert!(put(
            &format!(r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"),
            "Shell",
            "explorer.exe"
        )
        .is_err());
        // A Run value may be deleted but never written.
        assert!(put(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "x",
            "notepad.exe"
        )
        .is_err());
        assert!(put(win, "AppInit_DLLs", r"C:\x.dll").is_err());

        // Type mismatch: never change a value's type.
        let p = put(wd, "UseLogonCredential", "dword:0").unwrap();
        assert!(check_live_type(&p.op, REG_DWORD).is_ok());
        assert!(check_live_type(&p.op, REG_SZ).is_err());
        let p = put(sm, "BootExecute", "autocheck autochk *").unwrap();
        assert!(check_live_type(&p.op, REG_MULTI_SZ).is_ok());
        assert!(check_live_type(&p.op, REG_SZ).is_err());
        let p = put(wl, "Userinit", r"C:\Windows\system32\userinit.exe,").unwrap();
        assert!(check_live_type(&p.op, REG_EXPAND_SZ).is_err());
        assert!(check_live_type(&RegOp::Delete, REG_BINARY).is_ok());
        // Encoding uses the table type.
        if let RegOp::Write { reg_type, data } =
            &put(sm, "BootExecute", "autocheck autochk *").unwrap().op
        {
            let (t, b) = encode_restore(*reg_type, data);
            assert_eq!(t, REG_MULTI_SZ);
            assert!(b.ends_with(&[0, 0, 0, 0]));
        }
    }

    #[test]
    fn tasks() {
        assert_eq!(
            plan_task(r"\Updater", true).unwrap(),
            ("\\".to_string(), "Updater".to_string())
        );
        assert_eq!(
            plan_task(r"\Vendor\Sub\Task One", true).unwrap(),
            (r"\Vendor\Sub".to_string(), "Task One".to_string())
        );
        assert!(plan_task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", true).is_err());
        assert!(plan_task(r"\Microsoft\Windows\Defrag\ScheduledDefrag", false).is_ok());
        assert!(plan_task(r"\KestrelUpdate", true).is_ok());
        for bad in ["", "Updater", r"\", r"\a\", r"\a\\b", r"\a\..\b", r"\*"] {
            assert!(plan_task(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn services() {
        assert_eq!(plan_service(" EvilSvc ").unwrap(), "EvilSvc");
        for bad in [
            "",
            "KestrelAgent",
            "kestrelagent",
            " KESTRELAGENT ",
            "WinDefend",
            "EventLog",
            "a\\b",
            "a*",
            "Schedule",
        ] {
            assert!(plan_service(bad).is_err(), "{bad}");
        }
        let sr = r"C:\Windows";
        assert_eq!(
            service_binary(r#""C:\Program Files\X\x.exe" -k run"#, sr).unwrap(),
            r"C:\Program Files\X\x.exe"
        );
        assert_eq!(
            service_binary(r"C:\Windows\system32\svchost.exe -k netsvcs -p", sr).unwrap(),
            r"C:\Windows\system32\svchost.exe"
        );
        assert_eq!(
            service_binary(r"\SystemRoot\System32\drivers\x.sys", sr).unwrap(),
            r"C:\Windows\System32\drivers\x.sys"
        );
        assert_eq!(
            service_binary(r"System32\drivers\y.sys", sr).unwrap(),
            r"C:\Windows\System32\drivers\y.sys"
        );
        assert_eq!(
            service_binary(r"\??\C:\Users\a\AppData\x.exe", sr).unwrap(),
            r"C:\Users\a\AppData\x.exe"
        );
        assert_eq!(
            service_binary(r"%SystemRoot%\x.exe /a", sr).unwrap(),
            r"C:\Windows\x.exe"
        );
        assert!(service_binary("  ", sr).is_none());
        assert!(is_wrapper_binary(r"C:\Windows\System32\cmd.exe"));
        assert!(!is_wrapper_binary(r"C:\Windows\System32\spoolsv.exe"));
        assert!(is_svchost(r"C:\Windows\System32\SVCHOST.EXE"));
        assert!(under_system_root(
            r"c:\windows\system32\x.dll",
            r"C:\Windows"
        ));
        assert!(!under_system_root(r"c:\windowsx\x.dll", r"C:\Windows"));
    }

    #[test]
    fn wmi() {
        assert!(plan_wmi_consumer("EvilConsumer").is_ok());
        assert!(plan_wmi_consumer("SCM Event Log Consumer").is_err());
        assert!(plan_wmi_consumer("").is_err());
        assert!(plan_wmi_consumer("KestrelProbeConsumer").is_ok());
        assert_eq!(wql_quote(r"a'b\c"), r"'a\'b\\c'");
        assert_eq!(
            wmi_ref_key(r#"\\HOST\ROOT\subscription:CommandLineEventConsumer.Name="Evil""#),
            wmi_ref_key(r#"CommandLineEventConsumer.Name="evil""#)
        );
        let mof = "instance of Win32_DeviceGuard\n{\n\tSecurityServicesRunning = {1, 2};\n\tVersion = \"1.0\";\n\tVirtualizationBasedSecurityStatus = 2;\n};";
        assert_eq!(
            mof_u32_list(mof, "SecurityServicesRunning"),
            Some(vec![1, 2])
        );
        assert_eq!(
            mof_u32_list(mof, "VirtualizationBasedSecurityStatus"),
            Some(vec![2])
        );
        assert_eq!(mof_u32_list(mof, "Nope"), None);
        assert_eq!(mof_u32_list("X = {\"a\"};", "X"), None);
    }

    #[test]
    fn startup_files() {
        assert!(plan_startup_file(
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.lnk"
        )
        .is_ok());
        assert!(plan_startup_file(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\x.vbs"
        )
        .is_ok());
        for bad in [
            r"C:\Users\a\Downloads\x.exe",
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\",
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\sub\x.exe",
            r"C:\Users\a\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini",
        ] {
            assert!(plan_startup_file(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn backup_roundtrip() {
        let b = AutorunBackup {
            format: BACKUP_FORMAT,
            kind: AutorunKind::RegistryValue,
            location: r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: Some("Evil".into()),
            captured_at: 1,
            data: BackupData::Registry {
                value: RegValueDump::new("Evil", REG_SZ, &[b'x', 0, 0, 0]),
            },
        };
        assert_eq!(
            b.label(),
            r"autorun:registry_value:HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run!Evil"
        );
        let back = AutorunBackup::from_bytes(&b.to_bytes()).unwrap();
        assert_eq!(back, b);
        let j = String::from_utf8(b.to_bytes()).unwrap();
        assert!(j.contains("\"type\": \"registry\""));
        assert!(j.contains("\"type_name\": \"REG_SZ\""));
        let mut bad = b.clone();
        bad.format = 9;
        assert!(AutorunBackup::from_bytes(&bad.to_bytes()).is_err());
        assert!(AutorunBackup::from_bytes(b"nope").is_err());
    }
}
