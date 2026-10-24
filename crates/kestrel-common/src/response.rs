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
        /// Id of the Block IOC whose hit created this block (set by the
        /// detection engine only). When a new policy no longer contains that
        /// id as a Block IOC, the agent lifts the block (M10). Blocks without
        /// it (other rules, analysts) are never lifted by reconciliation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ioc_id: Option<String>,
    },
    /// Block all network traffic for one executable image via WFP.
    BlockImageNetwork {
        image: String,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    /// Lift Kestrel network blocks (WFP) set by `BlockImageNetwork` /
    /// `BlockDestination`. `image` = lift every block scoped to that
    /// executable (case-insensitive full path); `block_id` = lift one block
    /// (id from the block's `ActionOutcome.artifact` / agent block state);
    /// both set = only blocks matching both; both `None` = lift every block.
    /// Never touches the isolation filters (use `ReleaseHost`). Analyst /
    /// console only: the detection engine never proposes it.
    UnblockNetwork {
        #[serde(default)]
        image: Option<String>,
        #[serde(default)]
        block_id: Option<String>,
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
    /// Turn protection back on after it was turned off locally with the
    /// tray switch. Handled by the agent itself (no-op when not off).
    ResumeProtection,
    /// Remove Kestrel from the PC ("Remove device" in the console). Only
    /// from the authenticated server stream: the agent refuses it from the
    /// detection engine and the tray. The device's uninstall token is never
    /// part of the action (actions are stored in the actions table and shown
    /// in the API, so the token must not be); the server attaches it at
    /// delivery time only, in
    /// `ServerPayload::Command.secret`. Agents announce support with
    /// [`CAP_REMOTE_UNINSTALL`] in `Hello.capabilities`; the server never
    /// sends it to agents without that capability.
    UninstallAgent {
        /// Also delete `%ProgramData%\Kestrel` (quarantine, logs) after a
        /// successful removal.
        #[serde(default)]
        purge_data: bool,
    },
    /// Prepare the evidence bundle `bundle_id` (captured after an ST-02 /
    /// ST-04 alert) for upload. The agent checks the bundle is complete,
    /// tells the employee in the tray (`evidence::TRAY_COLLECTED_TITLE`) and
    /// answers `ok` with `artifact` = the bundle id; the server then pulls it
    /// with `LiveServerMsg::EvidenceRead`. Admin only (`evidence.download`),
    /// queued only by `POST /evidence/:id/collect` (never the generic action
    /// endpoint); the agent refuses it from the engine and the tray. Agents
    /// announce support with `evidence::CAP_EVIDENCE`.
    CollectEvidence {
        bundle_id: uuid::Uuid,
    },
    /// Delete the evidence bundle `bundle_id` on the PC (after the server
    /// stored it, or when an admin deletes the evidence). Succeeds when the
    /// bundle is already gone. Server-issued only, like `CollectEvidence`.
    DeleteEvidence {
        bundle_id: uuid::Uuid,
    },
}

/// `Hello.capabilities` entry of agents that understand
/// [`ResponseAction::UninstallAgent`].
pub const CAP_REMOTE_UNINSTALL: &str = "agent.uninstall";

/// `ActionOutcome.artifact` of an `UninstallAgent` that passed the token
/// check and started the detached uninstall helper (`ok = true`). The
/// command stays open server-side ("removing") until the device stays
/// disconnected, or a later failure outcome arrives.
pub const UNINSTALL_STARTED: &str = "uninstall_started";
/// `ActionOutcome.artifact` of a failed `UninstallAgent` (`ok = false`):
/// token mismatch, helper missing, Windows Installer error.
pub const UNINSTALL_FAILED: &str = "uninstall_failed";

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
            ResponseAction::UnblockNetwork { .. } => "unblock_network",
            ResponseAction::IsolateHost { .. } => "isolate_host",
            ResponseAction::ReleaseHost => "release_host",
            ResponseAction::ApplyHardening => "apply_hardening",
            ResponseAction::Scan { .. } => "scan",
            ResponseAction::CollectTriage => "collect_triage",
            ResponseAction::RemoveAutorun { .. } => "remove_autorun",
            ResponseAction::ResumeProtection => "resume_protection",
            ResponseAction::UninstallAgent { .. } => "uninstall_agent",
            ResponseAction::CollectEvidence { .. } => "collect_evidence",
            ResponseAction::DeleteEvidence { .. } => "delete_evidence",
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
            | ResponseAction::DeleteQuarantined { .. } => "response.file",
            // Writes / deletes persistence entries as SYSTEM: admin-only
            // (security review v1.1 V-H2).
            ResponseAction::RemoveAutorun { .. } => "response.persistence",
            ResponseAction::BlockDestination { .. }
            | ResponseAction::BlockImageNetwork { .. }
            | ResponseAction::UnblockNetwork { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::ReleaseHost => "response.network",
            ResponseAction::ApplyHardening
            | ResponseAction::Scan { .. }
            | ResponseAction::CollectTriage
            | ResponseAction::ResumeProtection => "response.collect",
            // Uninstalls the product: admin only, and only through
            // `POST /devices/:id/remove` (never the generic action endpoint).
            ResponseAction::UninstallAgent { .. } => "devices.remove",
            // May contain the employee's real secrets: admin only, and only
            // through the `/evidence` endpoints (interactive sessions).
            ResponseAction::CollectEvidence { .. } | ResponseAction::DeleteEvidence { .. } => {
                "evidence.download"
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uninstall_agent_wire_format() {
        let a: ResponseAction = serde_json::from_str(r#"{"type":"uninstall_agent"}"#).unwrap();
        assert_eq!(a, ResponseAction::UninstallAgent { purge_data: false });
        assert_eq!(a.name(), "uninstall_agent");
        assert_eq!(a.privilege(), "devices.remove");
        let j =
            serde_json::to_string(&ResponseAction::UninstallAgent { purge_data: true }).unwrap();
        assert_eq!(j, r#"{"type":"uninstall_agent","purge_data":true}"#);
    }

    #[test]
    fn evidence_actions_wire_format() {
        let id = uuid::Uuid::nil();
        let a = ResponseAction::CollectEvidence { bundle_id: id };
        let j = serde_json::to_string(&a).unwrap();
        assert_eq!(
            j,
            r#"{"type":"collect_evidence","bundle_id":"00000000-0000-0000-0000-000000000000"}"#
        );
        assert_eq!(serde_json::from_str::<ResponseAction>(&j).unwrap(), a);
        assert_eq!(a.name(), "collect_evidence");
        assert_eq!(a.privilege(), "evidence.download");
        let d = ResponseAction::DeleteEvidence { bundle_id: id };
        assert_eq!(d.name(), "delete_evidence");
        assert_eq!(d.privilege(), "evidence.download");
    }

    #[test]
    fn unblock_network_wire_format() {
        // Both fields default: `{"type":"unblock_network"}` = lift every block.
        let a: ResponseAction = serde_json::from_str(r#"{"type":"unblock_network"}"#).unwrap();
        assert_eq!(
            a,
            ResponseAction::UnblockNetwork {
                image: None,
                block_id: None
            }
        );
        assert_eq!(a.name(), "unblock_network");
        assert_eq!(a.privilege(), "response.network");
        let a = ResponseAction::UnblockNetwork {
            image: Some(r"C:\Apps\crm.exe".into()),
            block_id: None,
        };
        let j = serde_json::to_string(&a).unwrap();
        assert!(j.contains(r#""type":"unblock_network""#), "{j}");
        assert_eq!(serde_json::from_str::<ResponseAction>(&j).unwrap(), a);
        let b: ResponseAction =
            serde_json::from_str(r#"{"type":"unblock_network","block_id":"b-1"}"#).unwrap();
        assert!(
            matches!(b, ResponseAction::UnblockNetwork { block_id: Some(ref id), image: None } if id == "b-1")
        );
    }
}
