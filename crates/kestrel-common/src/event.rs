//! Normalised endpoint telemetry.
//!
//! Sensors (ETW, Sysmon channel, AMSI, registry/WFP audit) translate raw OS
//! events into [`Event`]. The detection engine and the server only ever see
//! this schema, which keeps rules independent of the underlying sensor.

use crate::TimestampMs;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Stable process identity. PIDs are reused, so the agent derives a GUID from
/// (boot id, pid, process start time) and every event carries it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[serde(transparent)]
pub struct ProcessGuid(pub String);

impl ProcessGuid {
    pub fn derive(boot_id: &str, pid: u32, start_ts: TimestampMs) -> Self {
        // FNV-1a 128-bit over the triple: stable, cheap, no crypto needed.
        let mut h: u128 = 0x6c62272e07bb014262b821756295c58d;
        let prime: u128 = 0x0000000001000000000000000000013B;
        for b in boot_id
            .as_bytes()
            .iter()
            .chain(pid.to_le_bytes().iter())
            .chain(start_ts.to_le_bytes().iter())
        {
            h ^= *b as u128;
            h = h.wrapping_mul(prime);
        }
        ProcessGuid(format!("{h:032x}"))
    }
}

impl fmt::Display for ProcessGuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One telemetry record.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    /// Event time (ms since epoch).
    pub ts: TimestampMs,
    /// Acting process id.
    pub pid: u32,
    /// Acting process GUID (see [`ProcessGuid`]).
    pub guid: ProcessGuid,
    #[serde(flatten)]
    pub data: EventData,
}

impl Event {
    pub fn kind(&self) -> EventKind {
        self.data.kind()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ProcessStart,
    ProcessStop,
    ImageLoad,
    FileAccess,
    RegistrySet,
    NetConnect,
    DnsQuery,
    DpapiUnprotect,
    ProcessAccess,
    RemoteThread,
    ThreadContext,
    DebugAttach,
    ScriptBlock,
    Tamper,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::ProcessStart => "process_start",
            EventKind::ProcessStop => "process_stop",
            EventKind::ImageLoad => "image_load",
            EventKind::FileAccess => "file_access",
            EventKind::RegistrySet => "registry_set",
            EventKind::NetConnect => "net_connect",
            EventKind::DnsQuery => "dns_query",
            EventKind::DpapiUnprotect => "dpapi_unprotect",
            EventKind::ProcessAccess => "process_access",
            EventKind::RemoteThread => "remote_thread",
            EventKind::ThreadContext => "thread_context",
            EventKind::DebugAttach => "debug_attach",
            EventKind::ScriptBlock => "script_block",
            EventKind::Tamper => "tamper",
        }
    }
}

/// Event payloads. Serialised with an internal `type` tag, flattened into [`Event`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventData {
    ProcessStart(ProcessStart),
    ProcessStop {
        #[serde(default)]
        exit_code: Option<i32>,
    },
    ImageLoad {
        path: String,
        #[serde(default)]
        signer: Option<String>,
        #[serde(default)]
        signed: SignatureState,
    },
    FileAccess {
        path: String,
        op: FileOp,
    },
    RegistrySet {
        key: String,
        value_name: String,
        #[serde(default)]
        data: Option<String>,
    },
    NetConnect {
        proto: NetProto,
        dst_ip: String,
        dst_port: u16,
        #[serde(default)]
        src_port: u16,
        /// Hostname this IP was resolved from by the same process (DNS correlation), if known.
        #[serde(default)]
        dst_host: Option<String>,
        #[serde(default)]
        bytes_sent: Option<u64>,
    },
    DnsQuery {
        qname: String,
        #[serde(default)]
        answers: Vec<String>,
    },
    /// Crypto-DPAPI/Debug event 16385 (SPCryptUnprotect).
    DpapiUnprotect {
        /// DataDescription, e.g. "Google Chrome".
        description: String,
    },
    /// Handle opened to another process (Audit-API-Calls PsOpenProcess / Sysmon EID 10).
    ProcessAccess(TargetProcess),
    /// Remote thread creation / APC injection (Sysmon EID 8, Audit-API-Calls).
    RemoteThread(TargetProcess),
    /// NtSetContextThread on another process's thread.
    ThreadContext(TargetProcess),
    /// Debugger attached to another process.
    DebugAttach(TargetProcess),
    /// PowerShell 4104 / AMSI content.
    ScriptBlock {
        engine: String,
        content: String,
    },
    /// Agent self-protection signal.
    Tamper {
        kind: TamperKind,
        detail: String,
    },
}

impl EventData {
    pub fn kind(&self) -> EventKind {
        match self {
            EventData::ProcessStart(_) => EventKind::ProcessStart,
            EventData::ProcessStop { .. } => EventKind::ProcessStop,
            EventData::ImageLoad { .. } => EventKind::ImageLoad,
            EventData::FileAccess { .. } => EventKind::FileAccess,
            EventData::RegistrySet { .. } => EventKind::RegistrySet,
            EventData::NetConnect { .. } => EventKind::NetConnect,
            EventData::DnsQuery { .. } => EventKind::DnsQuery,
            EventData::DpapiUnprotect { .. } => EventKind::DpapiUnprotect,
            EventData::ProcessAccess(_) => EventKind::ProcessAccess,
            EventData::RemoteThread(_) => EventKind::RemoteThread,
            EventData::ThreadContext(_) => EventKind::ThreadContext,
            EventData::DebugAttach(_) => EventKind::DebugAttach,
            EventData::ScriptBlock { .. } => EventKind::ScriptBlock,
            EventData::Tamper { .. } => EventKind::Tamper,
        }
    }
}

/// Process creation with enrichment the agent fills in from its hash/signer cache.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ProcessStart {
    pub ppid: u32,
    #[serde(default)]
    pub parent_guid: Option<ProcessGuid>,
    pub image: String,
    pub cmdline: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub integrity: Option<Integrity>,
    #[serde(default)]
    pub session_id: u32,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub signed: SignatureState,
    #[serde(default)]
    pub sha256: Option<String>,
    /// Mark-of-the-Web zone id (3 = Internet) from Zone.Identifier, if present.
    #[serde(default)]
    pub motw_zone: Option<u8>,
    #[serde(default)]
    pub file_size: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct TargetProcess {
    pub target_pid: u32,
    #[serde(default)]
    pub target_guid: Option<ProcessGuid>,
    pub target_image: String,
    /// Access mask granted on the handle (0 when not applicable).
    #[serde(default)]
    pub granted_access: u32,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SignatureState {
    #[default]
    Unknown,
    Unsigned,
    /// Valid Authenticode signature chaining to a trusted root.
    Valid,
    /// Signature present but invalid, revoked, or self-signed.
    Invalid,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    Untrusted,
    Low,
    Medium,
    High,
    System,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileOp {
    Open,
    Read,
    Write,
    Create,
    Delete,
    Rename,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NetProto {
    Tcp,
    Udp,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TamperKind {
    EtwSessionStopped,
    EtwProviderDisabled,
    EventsLost,
    WfpFilterChange,
    AmsiProviderChange,
    ServiceConfigChange,
    AgentFileModified,
    UninstallAttempt,
}

/// Where an executable lives; a strong prior for stealer detection.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathClass {
    /// %WINDIR%\System32, SysWOW64, WinSxS
    System,
    /// %WINDIR% (other)
    Windows,
    /// Program Files / Program Files (x86)
    ProgramFiles,
    /// %TEMP%, %LOCALAPPDATA%\Temp
    Temp,
    /// User Downloads folder
    Downloads,
    /// Other user-writable profile locations (AppData, Desktop, Public…)
    UserWritable,
    /// Removable / network share
    External,
    Other,
}

/// System drive letter (lower-case) used by [`PathClass::of`]. Defaults to
/// `c`; the Windows agent sets it from `%SystemRoot%` at start-up.
static SYSTEM_DRIVE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(b'c');

/// Set the system drive letter used by [`PathClass::of`] (e.g. from
/// `%SystemRoot%` = `D:\Windows` → `'d'`). Ignored unless ASCII alphabetic.
pub fn set_system_drive(letter: char) {
    if letter.is_ascii_alphabetic() {
        SYSTEM_DRIVE.store(
            letter.to_ascii_lowercase() as u8,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// Current system drive letter (lower-case), see [`set_system_drive`].
pub fn system_drive() -> char {
    SYSTEM_DRIVE.load(std::sync::atomic::Ordering::Relaxed) as char
}

/// Directories under `%SystemRoot%` that standard users can write to (and
/// often execute from). Paths below them are never "System" / "Windows".
/// Driveless, lower-case, trailing `\`.
pub const USER_WRITABLE_SYSTEM_DIRS: &[&str] = &[
    r"\windows\tasks\",
    r"\windows\temp\",
    r"\windows\tracing\",
    r"\windows\debug\wia\",
    r"\windows\registration\crmlog\",
    r"\windows\system32\tasks\",
    r"\windows\system32\tasks_migrated\",
    r"\windows\system32\spool\drivers\color\",
    r"\windows\system32\spool\printers\",
    r"\windows\system32\spool\servers\",
    r"\windows\system32\com\dmp\",
    r"\windows\system32\fxstmp\",
    r"\windows\system32\microsoft\crypto\rsa\machinekeys\",
    r"\windows\syswow64\tasks\",
    r"\windows\syswow64\com\dmp\",
    r"\windows\syswow64\fxstmp\",
];

impl PathClass {
    /// Classify a Windows path. Matching is case-insensitive and works with
    /// either separator; it does not touch the filesystem. Volume-aware:
    /// only paths on the system drive ([`system_drive`]) can be `System`,
    /// `Windows` or `ProgramFiles` (see [`PathClass::of_with_system_drive`]).
    pub fn of(path: &str) -> PathClass {
        Self::of_with_system_drive(path, system_drive())
    }

    /// Classify a Windows path given the system drive letter.
    ///
    /// * `X:\…` on a drive other than `system_drive`: Windows / Program Files
    ///   look-alikes (`E:\Windows\System32\lsass.exe` on a mounted ISO) are
    ///   `Other` — never trusted locations.
    /// * Driveless rooted paths (`\Windows\…`, `\SystemRoot\…` already
    ///   normalised) are assumed to be on the system drive.
    /// * Device paths that were not mapped to a drive letter
    ///   (`\Device\HarddiskVolumeN\…`) are `Other` for system-looking paths:
    ///   their volume is unknown.
    /// * Known user-writable directories inside `%SystemRoot%`
    ///   ([`USER_WRITABLE_SYSTEM_DIRS`]) are `UserWritable` (or `Temp`).
    pub fn of_with_system_drive(path: &str, system_drive: char) -> PathClass {
        let p = path.replace('/', "\\").to_ascii_lowercase();
        let p = p.trim_start_matches(r"\\?\").trim_start_matches(r"\??\");
        if p.starts_with(r"unc\") || p.starts_with(r"\\") || p.starts_with(r"\device\mup\") {
            return PathClass::External;
        }
        let sys = system_drive.to_ascii_lowercase();
        // (driveless rest, on the system volume?)
        let (rest, on_system) = if p.len() >= 2 && p.as_bytes()[1] == b':' {
            let d = p.as_bytes()[0] as char;
            (&p[2..], d == sys)
        } else if let Some(r) = p.strip_prefix(r"\systemroot\") {
            // Kernel form of %SystemRoot%: always the system volume.
            return Self::classify_rest(&format!(r"\windows\{r}"), true);
        } else if let Some(dev) = p.strip_prefix(r"\device\") {
            match dev.find('\\') {
                Some(i) => (&dev[i..], false),
                None => (p, false),
            }
        } else {
            (p, true)
        };
        Self::classify_rest(rest, on_system)
    }

    fn classify_rest(rest: &str, on_system: bool) -> PathClass {
        if USER_WRITABLE_SYSTEM_DIRS
            .iter()
            .any(|d| rest.starts_with(d))
        {
            return if rest.starts_with(r"\windows\temp\") {
                PathClass::Temp
            } else {
                PathClass::UserWritable
            };
        }
        let system_like = rest.starts_with(r"\windows\")
            || rest.starts_with(r"\program files\")
            || rest.starts_with(r"\program files (x86)\");
        if system_like && !on_system {
            return PathClass::Other;
        }
        if rest.starts_with(r"\windows\system32\")
            || rest.starts_with(r"\windows\syswow64\")
            || rest.starts_with(r"\windows\winsxs\")
        {
            return PathClass::System;
        }
        if rest.starts_with(r"\windows\") {
            if rest.starts_with(r"\windows\temp\") {
                return PathClass::Temp;
            }
            return PathClass::Windows;
        }
        if rest.starts_with(r"\program files\") || rest.starts_with(r"\program files (x86)\") {
            return PathClass::ProgramFiles;
        }
        if rest.starts_with(r"\users\") {
            if rest.contains(r"\appdata\local\temp\") {
                return PathClass::Temp;
            }
            if rest.contains(r"\downloads\") {
                return PathClass::Downloads;
            }
            return PathClass::UserWritable;
        }
        if rest.starts_with(r"\programdata\")
            || rest.starts_with(r"\temp\")
            || rest.starts_with(r"\tmp\")
        {
            return PathClass::UserWritable;
        }
        PathClass::Other
    }

    /// True for locations a normal user can write to.
    pub fn is_user_writable(&self) -> bool {
        matches!(
            self,
            PathClass::Temp | PathClass::Downloads | PathClass::UserWritable | PathClass::External
        )
    }
}

/// Lower-cased file name of a Windows path.
pub fn file_name_lower(path: &str) -> String {
    path.rsplit(['\\', '/'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_classes() {
        assert_eq!(
            PathClass::of(r"C:\Windows\System32\cmd.exe"),
            PathClass::System
        );
        assert_eq!(
            PathClass::of(r"C:\Users\a\AppData\Local\Temp\x.exe"),
            PathClass::Temp
        );
        assert_eq!(
            PathClass::of(r"c:\users\a\downloads\setup.exe"),
            PathClass::Downloads
        );
        assert_eq!(
            PathClass::of(r"C:\Program Files\Google\Chrome\Application\chrome.exe"),
            PathClass::ProgramFiles
        );
        assert_eq!(
            PathClass::of(r"\\?\C:\Users\a\AppData\Roaming\z.exe"),
            PathClass::UserWritable
        );
        assert_eq!(PathClass::of(r"\\server\share\a.exe"), PathClass::External);
        assert_eq!(
            PathClass::of(r"\\?\UNC\server\share\a.exe"),
            PathClass::External
        );
        assert!(PathClass::Temp.is_user_writable());
    }

    #[test]
    fn path_class_is_volume_aware() {
        let of = |p: &str| PathClass::of_with_system_drive(p, 'c');
        // A Windows look-alike on another volume (mounted ISO / USB) is never trusted.
        assert_eq!(of(r"E:\Windows\System32\lsass.exe"), PathClass::Other);
        assert_eq!(
            of(r"E:\Program Files\Windows Defender\MsMpEng.exe"),
            PathClass::Other
        );
        assert_eq!(of(r"E:\Users\bob\Downloads\x.exe"), PathClass::Downloads);
        // System drive other than C.
        assert_eq!(
            PathClass::of_with_system_drive(r"D:\Windows\System32\lsass.exe", 'D'),
            PathClass::System
        );
        assert_eq!(
            PathClass::of_with_system_drive(r"C:\Windows\System32\lsass.exe", 'd'),
            PathClass::Other
        );
        // Unmapped device paths: volume unknown → not trusted.
        assert_eq!(
            of(r"\Device\HarddiskVolume7\Windows\System32\lsass.exe"),
            PathClass::Other
        );
        assert_eq!(
            of(r"\Device\HarddiskVolume3\Users\a\AppData\Local\Temp\x.exe"),
            PathClass::Temp
        );
        // Kernel %SystemRoot% form and driveless paths are the system volume.
        assert_eq!(of(r"\SystemRoot\System32\smss.exe"), PathClass::System);
        assert_eq!(of(r"\Windows\explorer.exe"), PathClass::Windows);
        // User-writable directories inside %SystemRoot%.
        assert_eq!(
            of(r"C:\Windows\System32\spool\drivers\color\svchost.exe"),
            PathClass::UserWritable
        );
        assert_eq!(of(r"C:\Windows\Tasks\x.exe"), PathClass::UserWritable);
        assert_eq!(
            of(r"C:\Windows\SysWOW64\Tasks\x.exe"),
            PathClass::UserWritable
        );
        assert_eq!(of(r"C:\Windows\Temp\x.exe"), PathClass::Temp);
        assert_eq!(of(r"C:\Windows\System32\svchost.exe"), PathClass::System);
    }

    #[test]
    fn event_roundtrip() {
        let e = Event {
            ts: 1,
            pid: 4,
            guid: ProcessGuid::derive("boot", 4, 1),
            data: EventData::FileAccess {
                path: "C:\\x".into(),
                op: FileOp::Read,
            },
        };
        let s = serde_json::to_string(&e).unwrap();
        assert!(s.contains("\"type\":\"file_access\""));
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.kind(), EventKind::FileAccess);
    }

    #[test]
    fn guid_stable() {
        assert_eq!(
            ProcessGuid::derive("b", 1, 2),
            ProcessGuid::derive("b", 1, 2)
        );
        assert_ne!(
            ProcessGuid::derive("b", 1, 2),
            ProcessGuid::derive("b", 1, 3)
        );
    }
}
