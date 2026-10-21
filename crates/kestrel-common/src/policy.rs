//! Endpoint policy pushed from the server. One policy per device group.

use crate::{rules::RuleMode, TimestampMs};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Policy {
    pub id: String,
    pub name: String,
    /// Monotonic; agents apply only newer versions.
    pub version: u64,
    /// Per-rule mode overrides (rule id → mode). Rules not listed use their default.
    #[serde(default)]
    pub rules: BTreeMap<String, RuleMode>,
    /// "Suspend on suspicion" window: how long a suspended process may wait for
    /// a verdict before it is resumed (or killed if a Protect rule fires).
    #[serde(default = "default_suspend_window")]
    pub suspend_window_ms: u64,
    #[serde(default)]
    pub exclusions: Vec<Exclusion>,
    #[serde(default)]
    pub iocs: Vec<Ioc>,
    #[serde(default)]
    pub hardening: Hardening,
    #[serde(default)]
    pub privacy: Privacy,
    #[serde(default)]
    pub telemetry: Telemetry,
    /// Plant decoy credential stores (ST-16 tripwires).
    #[serde(default = "yes")]
    pub canaries: bool,
    /// Org branding and employee notice shown by the tray app.
    #[serde(default)]
    pub branding: Branding,
    /// Domains whose resolution/connection by non-browser processes is suspicious (ST-14).
    #[serde(default = "default_exfil_domains")]
    pub exfil_domains: Vec<String>,
    /// Release network isolation automatically when the agent has not been
    /// able to reach the server for this many hours (also checked at boot),
    /// so a roaming laptop can never be stranded. `0` disables auto-release.
    #[serde(default = "default_isolation_auto_release_hours")]
    pub isolation_auto_release_hours: u64,
    /// Lifetime of WFP blocks created by IOC network/DNS hits (seconds).
    #[serde(default = "default_ioc_block_ttl_secs")]
    pub ioc_block_ttl_secs: u64,
    /// IOC network/DNS hits block the destination for every process (host
    /// wide) instead of only for the offending image.
    #[serde(default)]
    pub ioc_block_host_wide: bool,
    /// Optional sensor groups (general-malware coverage).
    #[serde(default)]
    pub sensors: SensorSettings,
    /// Admin remote access (remote desktop, file manager) allowed by this
    /// policy. Devices are additionally capped by the ceiling pinned at
    /// install (`remote::RemoteAccessProfile::intersect`). Default (and for
    /// policies saved before this field existed): no remote access.
    #[serde(default)]
    pub remote_access: crate::remote::RemoteAccessProfile,
}

/// Optional sensor groups. Defaults are on; each can be turned off per policy
/// if it costs too much on a given fleet.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SensorSettings {
    /// Kernel-File create/rename/delete aggregation on user-data and network
    /// paths (RW-06/07/08) plus ransomware canary documents.
    #[serde(default = "yes")]
    pub file_activity: bool,
    /// Plant ransomware canary documents in Documents/Desktop/Pictures roots.
    #[serde(default = "yes")]
    pub ransomware_canaries: bool,
    /// Task Scheduler, Service Control Manager and WMI-Activity providers plus
    /// the registry autorun watcher (PS-xx).
    #[serde(default = "yes")]
    pub persistence: bool,
    /// Failed-open and dump-follow-up telemetry for lsass (CD-xx).
    #[serde(default = "yes")]
    pub credential_access: bool,
}

impl Default for SensorSettings {
    fn default() -> Self {
        SensorSettings {
            file_activity: true,
            ransomware_canaries: true,
            persistence: true,
            credential_access: true,
        }
    }
}

fn default_suspend_window() -> u64 {
    3000
}
pub fn default_isolation_auto_release_hours() -> u64 {
    72
}
pub fn default_ioc_block_ttl_secs() -> u64 {
    24 * 3600
}
fn yes() -> bool {
    true
}

pub fn default_exfil_domains() -> Vec<String> {
    [
        "api.telegram.org",
        "steamcommunity.com",
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",
        "ip-api.com",
        "ipinfo.io",
        "api.ipify.org",
        "r2.dev",
        "pastebin.com",
        "gofile.io",
        "transfer.sh",
        "file.io",
        "trycloudflare.com",
        "bsc-dataseed.binance.org",
        "bsc-dataseed1.binance.org",
        "rpc.ankr.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            id: "default".into(),
            name: "Default".into(),
            version: 1,
            rules: BTreeMap::new(),
            suspend_window_ms: default_suspend_window(),
            exclusions: vec![],
            iocs: vec![],
            hardening: Hardening::default(),
            privacy: Privacy::default(),
            telemetry: Telemetry::default(),
            canaries: true,
            branding: Branding::default(),
            exfil_domains: default_exfil_domains(),
            isolation_auto_release_hours: default_isolation_auto_release_hours(),
            ioc_block_ttl_secs: default_ioc_block_ttl_secs(),
            ioc_block_host_wide: false,
            sensors: SensorSettings::default(),
            remote_access: crate::remote::RemoteAccessProfile::none(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Exclusion {
    pub id: String,
    pub kind: ExclusionKind,
    /// Path prefix / glob, sha256, signer subject, or image file name.
    pub value: String,
    /// Limit to one rule; `None` = all rules.
    #[serde(default)]
    pub rule_id: Option<String>,
    #[serde(default)]
    pub expires_at: Option<TimestampMs>,
    #[serde(default)]
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionKind {
    /// Image path; supports `*` wildcards, case-insensitive.
    Path,
    Sha256,
    /// Authenticode signer subject (exact, case-insensitive).
    Signer,
    /// Image file name, e.g. "keepass.exe".
    Image,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Ioc {
    pub id: String,
    pub kind: IocKind,
    pub value: String,
    pub action: IocAction,
    #[serde(default)]
    pub description: String,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    Sha256,
    Ip,
    Domain,
    Url,
    /// Signer subject or certificate thumbprint.
    Certificate,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocAction {
    Allow,
    Audit,
    Block,
}

/// OS-native controls the agent deploys and verifies (the kernel does the blocking).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Hardening {
    pub mode: HardeningMode,
    /// AppLocker/App Control: deny mshta.exe for standard users.
    pub block_mshta: bool,
    /// AppLocker: deny executables from %TEMP% and Downloads for standard users.
    pub block_user_path_exec: bool,
    /// Policy: remove Win+R Run dialog (NoRun) — strongest anti-ClickFix control.
    pub disable_run_dialog: bool,
    /// Windows Terminal multi-line paste warning.
    pub terminal_paste_warning: bool,
    /// PowerShell script-block logging (4104).
    pub script_block_logging: bool,
    /// Enable Microsoft-Windows-Crypto-DPAPI/Debug channel (needed by ST-03).
    pub dpapi_debug_channel: bool,
    /// Defender ASR rules relevant to stealers (only when Defender is active AV).
    pub asr_rules: bool,
    /// Chrome/Edge policy: RemoteDebuggingAllowed = false.
    pub browser_disable_remote_debugging: bool,
    /// WDigest `UseLogonCredential` = 0 (no cleartext passwords in LSASS).
    #[serde(default = "yes")]
    pub wdigest_off: bool,
    /// Defender ASR "Block credential stealing from LSASS"
    /// (9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2), added without touching other rules.
    #[serde(default = "yes")]
    pub asr_lsass: bool,
    /// LSA protection (`RunAsPPL` = 2, no UEFI lock). Takes effect after a
    /// reboot, which the agent never triggers; reported as "pending reboot".
    #[serde(default)]
    pub lsa_protection: bool,
    /// Report (never toggle) the Microsoft vulnerable-driver blocklist state.
    #[serde(default = "yes")]
    pub report_vulnerable_driver_blocklist: bool,
    /// Enable the `Microsoft-Windows-TaskScheduler/Operational` channel.
    #[serde(default = "yes")]
    pub task_scheduler_log: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HardeningMode {
    Off,
    /// Report drift only.
    Audit,
    /// Apply and keep applied.
    Enforce,
}

impl Default for Hardening {
    fn default() -> Self {
        Hardening {
            mode: HardeningMode::Audit,
            block_mshta: true,
            block_user_path_exec: false,
            disable_run_dialog: false,
            terminal_paste_warning: true,
            script_block_logging: true,
            dpapi_debug_channel: true,
            asr_rules: true,
            browser_disable_remote_debugging: true,
            wdigest_off: true,
            asr_lsass: true,
            lsa_protection: false,
            report_vulnerable_driver_blocklist: true,
            task_scheduler_log: true,
        }
    }
}

/// Data-minimisation switches (PDPA / UU PDP).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Privacy {
    /// Upload full command lines (else truncated to the image + flags).
    pub capture_cmdline: bool,
    /// Replace user names with a salted hash in uploaded telemetry.
    pub hash_usernames: bool,
    /// Never upload file paths under these prefixes (e.g. personal folders).
    #[serde(default)]
    pub redact_path_prefixes: Vec<String>,
    pub capture_dns: bool,
    /// Upload script-block content (PowerShell 4104 / AMSI).
    pub capture_script_content: bool,
}

impl Default for Privacy {
    fn default() -> Self {
        Privacy {
            capture_cmdline: true,
            hash_usernames: false,
            redact_path_prefixes: vec![],
            capture_dns: true,
            capture_script_content: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Telemetry {
    /// Upload raw events for hunting (alerts are always uploaded).
    pub upload_events: bool,
    /// Event kinds uploaded (empty = all).
    #[serde(default)]
    pub event_kinds: Vec<String>,
    /// Max local outbox size before oldest low-priority events are dropped.
    pub max_outbox_mb: u64,
}

impl Default for Telemetry {
    fn default() -> Self {
        Telemetry {
            upload_events: true,
            event_kinds: vec![],
            max_outbox_mb: 1024,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Branding {
    pub org_name: String,
    #[serde(default)]
    pub it_contact: ItContact,
    /// Markdown notice shown to employees (what is monitored and why).
    #[serde(default)]
    pub privacy_notice_md: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ItContact {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub url: String,
}
