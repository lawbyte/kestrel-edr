//! Identifiers used by the Windows layer, collected in one place so each can be
//! reviewed against its source.
//!
//! Verification status (see crate docs / final report):
//! * ETW manifests were checked against the Windows 10 build 18990 manifest
//!   dumps in `repnz/etw-providers-docs` (generated from the OS's own
//!   manifests). Field names below match those dumps exactly.
//! * DPAPI 16385 fields come from Google's "Detecting browser data theft using
//!   Windows Event Logs" (2024); the 18990 manifest predates the event.
//! * ASR GUIDs and mode values: Microsoft Learn ASR rules reference and
//!   "Enable attack surface reduction rules" (mode table).

/// ETW real-time session names owned by the agent. Stale sessions with these
/// names are stopped at sensor start.
pub const SESSION_CORE: &str = "Kestrel-Core";
pub const SESSION_IO: &str = "Kestrel-IO";
/// Private system-logger session (NT kernel logger semantics, Win8+) used only
/// as a command-line source for short-lived processes.
pub const SESSION_PROC_CMDLINE: &str = "Kestrel-ProcCmd";
/// Kernel-File (1 s flush): sensitive-path opens + ransomware aggregation.
pub const SESSION_FILE: &str = "Kestrel-File";
/// Task Scheduler / SCM / WMI-Activity persistence providers.
pub const SESSION_PERSIST: &str = "Kestrel-Persist";

/// ETW buffer plan per session: `(MinimumBuffers, MaximumBuffers)` of
/// [`buffers::SIZE_KB`] buffers (EVENT_TRACE_PROPERTIES, Microsoft Learn).
/// ETW reserves the minimum at start and allocates more, up to the maximum,
/// only "if the buffers are filled more quickly than they can be processed";
/// beyond the maximum it discards events (`EventsLost`).
///
/// Owner-PC triage 2026-10-22 (`ETW dropped 14241 events` during a parallel
/// Rust build): every session used Minimum = Maximum (Core 32, File 128,
/// IO 128 = 19 MB fixed), so a burst had no headroom. Now the sessions that
/// see build bursts (Core: process start/stop/image load; File: opens) can
/// grow; the idle reservation is lower than before (15 MB) and the worst
/// case under a sustained burst is 65 MB (+46 MB), see the test below.
/// Kernel-Network may log at DISPATCH_LEVEL where ETW cannot allocate on
/// demand, so IO keeps its previous preallocated minimum.
pub mod buffers {
    pub const SIZE_KB: u32 = 64;
    pub const CORE: (u32, u32) = (32, 256);
    pub const FILE: (u32, u32) = (64, 512);
    pub const IO: (u32, u32) = (128, 256);
    pub const PERSIST: (u32, u32) = (8, 8);
    pub const PROC_CMD: (u32, u32) = (8, 8);
    /// All sessions, for the memory budget.
    pub const ALL: [(u32, u32); 5] = [CORE, FILE, IO, PERSIST, PROC_CMD];
    /// Fixed plan before 2026-10-22 (Minimum = Maximum).
    pub const BEFORE: [u32; 5] = [32, 128, 128, 8, 8];
    /// Documented ceiling on the extra memory a burst may take.
    pub const MAX_EXTRA_MB: u32 = 64;

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn memory_budget() {
            let mb = |n: u32| n * SIZE_KB / 1024;
            let before: u32 = BEFORE.iter().sum();
            let max: u32 = ALL.iter().map(|b| b.1).sum();
            let min: u32 = ALL.iter().map(|b| b.0).sum();
            assert!(ALL.iter().all(|(lo, hi)| lo <= hi && *lo >= 2));
            assert!(
                mb(max - before) <= MAX_EXTRA_MB,
                "{} MB extra",
                mb(max - before)
            );
            assert!(min <= before, "idle reservation must not grow");
            assert_eq!(mb(max), 65);
        }
    }
}

pub mod provider {
    /// Microsoft-Windows-Kernel-Process
    pub const KERNEL_PROCESS: &str = "22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716";
    /// Microsoft-Windows-Kernel-File
    pub const KERNEL_FILE: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
    /// Microsoft-Windows-Kernel-Network
    pub const KERNEL_NETWORK: &str = "7DD42A49-5329-4832-8DFD-43D979153A88";
    /// Microsoft-Windows-Kernel-Audit-API-Calls
    pub const KERNEL_AUDIT_API: &str = "E02A841C-75A3-4FA7-AFC8-AE09CF9B7F23";
    /// Microsoft-Windows-Kernel-Registry
    pub const KERNEL_REGISTRY: &str = "70EB4F03-C1DE-4F73-A051-33D13D5413BD";
    /// Microsoft-Windows-DNS-Client
    pub const DNS_CLIENT: &str = "1C95126E-7EEA-49A9-A3FE-A378B03DDB4D";
    /// Microsoft-Windows-Crypto-DPAPI
    pub const CRYPTO_DPAPI: &str = "89FE8F40-CDCE-464E-8217-15EF97D4C7C3";
    /// Microsoft-Windows-PowerShell
    pub const POWERSHELL: &str = "A0C1853B-5C40-4B15-8766-3CF1C58F985A";
    /// Classic kernel "Process" MOF class (EventTraceGuid for process events
    /// delivered by a system-logger session).
    pub const MOF_PROCESS: &str = "3D6FA8D0-FE05-11D0-9DDA-00C04FD7BA7C";
    /// Microsoft-Windows-TaskScheduler (GUID from `Get-WinEvent -ListProvider`, build 26200)
    pub const TASK_SCHEDULER: &str = "DE7B24EA-73C8-4A09-985D-5BDADCFA9017";
    /// Service Control Manager (classic event-log provider; 7045 has no template)
    pub const SCM: &str = "555908D1-A6D7-4695-8E1E-26931D2012F4";
    /// Microsoft-Windows-WMI-Activity
    pub const WMI_ACTIVITY: &str = "1418EF04-B0B4-4623-BF7E-D74AB47BBDAA";
}

/// Event ids per provider (manifest `value`).
pub mod eid {
    // Kernel-Process (keywords: PROCESS 0x10, IMAGE 0x40)
    pub const PROC_START: u16 = 1;
    pub const PROC_STOP: u16 = 2;
    pub const IMAGE_LOAD: u16 = 5;
    // Kernel-File
    pub const FILE_CREATE: u16 = 12;
    pub const FILE_CLOSE: u16 = 14;
    pub const FILE_READ: u16 = 15;
    pub const FILE_WRITE: u16 = 16;
    pub const FILE_NAME_CREATE: u16 = 10;
    pub const FILE_NAME_DELETE: u16 = 11;
    pub const FILE_DELETE_PATH: u16 = 26;
    pub const FILE_RENAME_PATH: u16 = 27;
    pub const FILE_CREATE_NEW: u16 = 30;
    // Kernel-Network
    pub const TCP4_SEND: u16 = 10;
    pub const TCP4_CONNECT: u16 = 12;
    pub const TCP4_DISCONNECT: u16 = 13;
    pub const TCP6_SEND: u16 = 26;
    pub const TCP6_CONNECT: u16 = 28;
    pub const TCP6_DISCONNECT: u16 = 29;
    pub const UDP4_SEND: u16 = 42;
    pub const UDP6_SEND: u16 = 58;
    // Kernel-Audit-API-Calls (no keywords in the manifest)
    pub const API_TERMINATE_PROCESS: u16 = 2;
    pub const API_SET_CONTEXT_THREAD: u16 = 4;
    pub const API_OPEN_PROCESS: u16 = 5;
    pub const API_OPEN_THREAD: u16 = 6;
    // Kernel-Registry
    pub const REG_DELETE_KEY: u16 = 3;
    pub const REG_SET_VALUE: u16 = 5;
    pub const REG_DELETE_VALUE: u16 = 6;
    // DNS-Client
    pub const DNS_QUERY_COMPLETED: u16 = 3008;
    // Crypto-DPAPI (Debug channel)
    pub const DPAPI_DEF_INFORMATION: u16 = 16385;
    // PowerShell
    pub const PS_SCRIPT_BLOCK: u16 = 4104;
    // Sysmon
    pub const SYSMON_CREATE_REMOTE_THREAD: u32 = 8;
    pub const SYSMON_PROCESS_ACCESS: u32 = 10;
}

/// Keyword masks (manifest `<keyword mask=…>`).
pub mod kw {
    pub const PROC_PROCESS: u64 = 0x10;
    pub const PROC_IMAGE: u64 = 0x40;
    pub const FILE_CREATE: u64 = 0x80;
    pub const FILE_READ: u64 = 0x100;
    /// Manifest keyword masks verified with `wevtutil gp Microsoft-Windows-Kernel-File /ge /gm`
    /// on build 26200: 26 DeletePath = 0x400, 27 RenamePath = 0x800 (also 28
    /// SetLinkPath), 30 CreateNewFile = 0x1000, 10/11 NameCreate/Delete = 0x10,
    /// 16 Write = 0x200 (never enabled: volume).
    pub const FILE_FILENAME: u64 = 0x10;
    pub const FILE_WRITE: u64 = 0x200;
    pub const FILE_DELETE_PATH: u64 = 0x400;
    pub const FILE_RENAME_SETLINK_PATH: u64 = 0x800;
    pub const FILE_CREATE_NEW_FILE: u64 = 0x1000;
    pub const NET_IPV4: u64 = 0x10;
    pub const NET_IPV6: u64 = 0x20;
    pub const REG_SET_VALUE: u64 = 0x100;
    /// Kernel-Registry keywords (manifest, build 26200): DeleteValueKey 0x200, DeleteKey 0x4000.
    pub const REG_DELETE_VALUE: u64 = 0x200;
    pub const REG_DELETE_KEY: u64 = 0x4000;
    /// Providers whose events carry no keyword (Audit-API, DNS-Client) or
    /// whose keyword for the wanted event is not documented (DPAPI 16385):
    /// enable everything and narrow with an event-id filter.
    pub const ALL: u64 = u64::MAX;
}

/// Field names (exactly as in the manifests).
pub mod field {
    // Kernel-Process ProcessStart (v3 template ProcessRundownArgs_V1)
    pub const PROCESS_ID: &str = "ProcessID";
    pub const CREATE_TIME: &str = "CreateTime";
    pub const PARENT_PROCESS_ID: &str = "ParentProcessID";
    pub const SESSION_ID: &str = "SessionID";
    pub const MANDATORY_LABEL: &str = "MandatoryLabel";
    pub const IMAGE_NAME: &str = "ImageName";
    pub const EXIT_CODE: &str = "ExitCode";
    // Kernel-File
    pub const FILE_OBJECT: &str = "FileObject";
    pub const FILE_NAME: &str = "FileName";
    pub const FILE_PATH: &str = "FilePath";
    pub const CREATE_OPTIONS: &str = "CreateOptions";
    pub const FILE_KEY: &str = "FileKey";
    pub const INFO_CLASS: &str = "InfoClass";
    pub const ISSUING_THREAD_ID: &str = "IssuingThreadId";
    /// Kernel-File version-0 templates (Pointer): the issuing thread.
    pub const FILE_THREAD_ID: &str = "ThreadId";
    // Kernel-Network
    pub const NET_PID: &str = "PID";
    pub const NET_SIZE: &str = "size";
    pub const NET_DADDR: &str = "daddr";
    pub const NET_SADDR: &str = "saddr";
    pub const NET_DPORT: &str = "dport";
    pub const NET_SPORT: &str = "sport";
    // Kernel-Audit-API-Calls
    pub const TARGET_PROCESS_ID: &str = "TargetProcessId";
    /// Sic: the manifest spells it "TargetThreatId".
    pub const TARGET_THREAD_ID: &str = "TargetThreatId";
    pub const DESIRED_ACCESS: &str = "DesiredAccess";
    pub const RETURN_CODE: &str = "ReturnCode";
    // Kernel-Registry SetValueKey
    pub const KEY_NAME: &str = "KeyName";
    pub const KEY_OBJECT: &str = "KeyObject";
    pub const VALUE_NAME: &str = "ValueName";
    pub const REG_TYPE: &str = "Type";
    pub const CAPTURED_DATA: &str = "CapturedData";
    pub const STATUS: &str = "Status";
    // DNS-Client 3008
    pub const QUERY_NAME: &str = "QueryName";
    pub const QUERY_STATUS: &str = "QueryStatus";
    pub const QUERY_RESULTS: &str = "QueryResults";
    // DPAPI 16385
    pub const OPERATION_TYPE: &str = "OperationType";
    pub const DATA_DESCRIPTION: &str = "DataDescription";
    pub const CALLER_PROCESS_ID: &str = "CallerProcessID";
    pub const CALLER_PROCESS_CREATION_TIME: &str = "CallerProcessCreationTime";
    // PowerShell 4104
    pub const SCRIPT_BLOCK_TEXT: &str = "ScriptBlockText";
    // MOF Process (system logger)
    pub const MOF_PROCESS_ID: &str = "ProcessId";
    pub const MOF_COMMAND_LINE: &str = "CommandLine";
}

/// Defender ASR rule GUIDs (Microsoft Learn ASR reference).
pub mod asr {
    /// Block executable files from running unless they meet a prevalence, age, or trusted list criterion.
    pub const PREVALENCE: &str = "01443614-cd74-433a-b99e-2ecdc07bfc25";
    /// Block execution of potentially obfuscated scripts.
    pub const OBFUSCATED_SCRIPTS: &str = "5beb7efe-fd9a-4556-801d-275e5ffc04cc";
    /// Block use of copied or impersonated system tools.
    pub const IMPERSONATED_TOOLS: &str = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb";
    /// Block credential stealing from the Windows local security authority subsystem.
    pub const LSASS: &str = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2";
    pub const ALL: [&str; 4] = [PREVALENCE, OBFUSCATED_SCRIPTS, IMPERSONATED_TOOLS, LSASS];
    /// Rule action values (Set-MpPreference / GPO): 0 off, 1 block, 2 audit, 5 not configured, 6 warn.
    pub const ACTION_OFF: u32 = 0;
    pub const ACTION_BLOCK: u32 = 1;
    pub const ACTION_AUDIT: u32 = 2;
    pub const ACTION_WARN: u32 = 6;
}

/// Registry locations touched by hardening / triage.
pub mod reg {
    pub const POLICIES_EXPLORER: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer";
    pub const PS_SCRIPT_BLOCK_LOGGING: &str =
        r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";
    pub const PWSH_SCRIPT_BLOCK_LOGGING: &str =
        r"SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging";
    pub const CHROME_POLICIES: &str = r"SOFTWARE\Policies\Google\Chrome";
    pub const EDGE_POLICIES: &str = r"SOFTWARE\Policies\Microsoft\Edge";
    pub const BRAVE_POLICIES: &str = r"SOFTWARE\Policies\BraveSoftware\Brave";
    pub const REMOTE_DEBUGGING_ALLOWED: &str = "RemoteDebuggingAllowed";
    pub const PROFILE_LIST: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList";
    pub const CURRENT_VERSION: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    pub const MACHINE_GUID_KEY: &str = r"SOFTWARE\Microsoft\Cryptography";
}

/// Event-log channels.
pub mod channel {
    pub const DPAPI_DEBUG: &str = "Microsoft-Windows-Crypto-DPAPI/Debug";
    pub const SYSMON: &str = "Microsoft-Windows-Sysmon/Operational";
    pub const SECURITY: &str = "Security";
    pub const SYSTEM: &str = "System";
    pub const TASK_SCHEDULER: &str = "Microsoft-Windows-TaskScheduler/Operational";
    pub const WMI_ACTIVITY: &str = "Microsoft-Windows-WMI-Activity/Operational";
}

/// Agent identity in WFP. Fixed GUIDs so state survives reinstall/reboot and
/// tamper checks can recognise our objects in Security events 5446-5450.
pub mod wfp {
    /// {6B3F1C2E-5A4D-4E8B-9C21-4B4553545231}
    pub const PROVIDER_KEY: (u32, u16, u16, [u8; 8]) = (
        0x6B3F1C2E,
        0x5A4D,
        0x4E8B,
        [0x9C, 0x21, 0x4B, 0x45, 0x53, 0x54, 0x52, 0x31],
    );
    /// {6B3F1C2E-5A4D-4E8B-9C21-4B4553545232}
    pub const SUBLAYER_KEY: (u32, u16, u16, [u8; 8]) = (
        0x6B3F1C2E,
        0x5A4D,
        0x4E8B,
        [0x9C, 0x21, 0x4B, 0x45, 0x53, 0x54, 0x52, 0x32],
    );
    pub const PROVIDER_KEY_STR: &str = "6b3f1c2e-5a4d-4e8b-9c21-4b4553545231";
    pub const SUBLAYER_KEY_STR: &str = "6b3f1c2e-5a4d-4e8b-9c21-4b4553545232";
    pub const SUBLAYER_WEIGHT: u16 = 0xFFFF;
}

/// Service identity used by `install_service` / `run_service`.
pub const SERVICE_NAME: &str = "KestrelAgent";
pub const SERVICE_DISPLAY_NAME: &str = "Kestrel EDR Agent";
pub const SERVICE_DESCRIPTION: &str =
    "Kestrel EDR endpoint agent: detects and contains infostealer activity. Managed by your IT department.";
/// Command-line argument the service is registered with (`<exe> service`).
pub const SERVICE_ARG: &str = "service";
