//! Response actions: issued automatically by rules in Protect mode, or by an
//! analyst from the console (delivered to the agent as a `Command`).

use crate::{event::ProcessGuid, TimestampMs};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ResponseAction {
    /// Terminate a process (and optionally all descendants).
    KillProcess {
        pid: u32,
        #[serde(default)]
        guid: Option<ProcessGuid>,
        #[serde(default)]
        tree: bool,
    },
    /// Freeze all threads of a process (NtSuspendProcess).
    SuspendProcess {
        pid: u32,
        #[serde(default)]
        guid: Option<ProcessGuid>,
    },
    ResumeProcess {
        pid: u32,
        #[serde(default)]
        guid: Option<ProcessGuid>,
    },
    /// Move a file into the encrypted quarantine vault.
    QuarantineFile {
        path: String,
        #[serde(default)]
        sha256: Option<String>,
    },
    RestoreFile {
        quarantine_id: String,
    },
    DeleteQuarantined {
        quarantine_id: String,
    },
    /// Block outbound traffic to an IP (optionally only for one image) via WFP.
    BlockDestination {
        ip: String,
        #[serde(default)]
        port: Option<u16>,
        #[serde(default)]
        image: Option<String>,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    /// Block all network traffic for one executable image via WFP.
    BlockImageNetwork {
        image: String,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    /// Network-isolate the host: only the Kestrel server (and listed IPs) reachable.
    IsolateHost {
        #[serde(default)]
        allow_ips: Vec<String>,
    },
    ReleaseHost,
    /// Re-apply the hardening pack from current policy.
    ApplyHardening,
    /// Scan a path (or all running user-path images) with YARA-X.
    Scan {
        #[serde(default)]
        path: Option<String>,
    },
    /// Collect a triage package (process list, recent events, autoruns) and upload it.
    CollectTriage,
    /// Remove (or restore to its OS default) one persistence entry. The agent
    /// backs the original up to the quarantine vault first (the outcome's
    /// `artifact` names the backup), re-reads the entry before acting (TOCTOU)
    /// and never touches Kestrel's own service or protected OS entries.
    RemoveAutorun {
        kind: AutorunKind,
        /// Registry key (`HKLM\…` / `HKU\<SID>\…`), file path, task path
        /// (`\Folder\Name`), service name or WMI consumer name.
        location: String,
        /// Registry value name (RegistryValue only; empty = default value).
        #[serde(default)]
        value_name: Option<String>,
        /// RegistryValue only: write this REG_SZ/REG_DWORD (`dword:N`) data
        /// instead of deleting the value (e.g. Winlogon `Userinit` default,
        /// WDigest `UseLogonCredential` = `dword:0`).
        #[serde(default)]
        restore_data: Option<String>,
    },
}

/// Persistence mechanism targeted by [`ResponseAction::RemoveAutorun`].
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AutorunKind {
    /// Registry value (Run keys, IFEO Debugger, Winlogon, COM server, …).
    RegistryValue,
    /// File in a Startup folder (moved to the quarantine vault).
    StartupFile,
    /// Scheduled task (XML exported, then deleted).
    ScheduledTask,
    /// Service (config exported, then stopped and set to disabled; not deleted).
    Service,
    /// WMI filter-to-consumer binding plus its consumer (MOF exported, then deleted).
    WmiSubscription,
}

impl ResponseAction {
    pub fn name(&self) -> &'static str {
        match self {
            ResponseAction::KillProcess { .. } => "kill_process",
            ResponseAction::SuspendProcess { .. } => "suspend_process",
            ResponseAction::ResumeProcess { .. } => "resume_process",
            ResponseAction::QuarantineFile { .. } => "quarantine_file",
            ResponseAction::RestoreFile { .. } => "restore_file",
            ResponseAction::DeleteQuarantined { .. } => "delete_quarantined",
            ResponseAction::BlockDestination { .. } => "block_destination",
            ResponseAction::BlockImageNetwork { .. } => "block_image_network",
            ResponseAction::IsolateHost { .. } => "isolate_host",
            ResponseAction::ReleaseHost => "release_host",
            ResponseAction::ApplyHardening => "apply_hardening",
            ResponseAction::Scan { .. } => "scan",
            ResponseAction::CollectTriage => "collect_triage",
            ResponseAction::RemoveAutorun { .. } => "remove_autorun",
        }
    }

    /// RBAC privilege required to issue this action from the console.
    pub fn privilege(&self) -> &'static str {
        match self {
            ResponseAction::KillProcess { .. }
            | ResponseAction::SuspendProcess { .. }
            | ResponseAction::ResumeProcess { .. } => "response.process",
            ResponseAction::QuarantineFile { .. }
            | ResponseAction::RestoreFile { .. }
            | ResponseAction::DeleteQuarantined { .. }
            | ResponseAction::RemoveAutorun { .. } => "response.file",
            ResponseAction::BlockDestination { .. }
            | ResponseAction::BlockImageNetwork { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::ReleaseHost => "response.network",
            ResponseAction::ApplyHardening
            | ResponseAction::Scan { .. }
            | ResponseAction::CollectTriage => "response.collect",
        }
    }
}

/// Result of executing an action on the endpoint.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ActionOutcome {
    pub action: ResponseAction,
    pub ok: bool,
    #[serde(default)]
    pub detail: String,
    pub ts: TimestampMs,
    /// Structured result handle: quarantine id for `QuarantineFile`, triage
    /// zip path for `CollectTriage`, WFP filter id for blocks. Servers fall
    /// back to parsing `detail` when absent.
    #[serde(default)]
    pub artifact: Option<String>,
}
