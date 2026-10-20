//! Detections produced by the agent's engine and stored/grouped by the server.

use crate::{
    event::{Event, Integrity, PathClass, ProcessGuid, SignatureState},
    response::ActionOutcome,
    rules::RuleMode,
    TimestampMs,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    /// Base score used by the incident priority model (0-100).
    pub fn base_score(&self) -> u8 {
        match self {
            Severity::Info => 5,
            Severity::Low => 20,
            Severity::Medium => 45,
            Severity::High => 70,
            Severity::Critical => 90,
        }
    }
}

/// Category of secret a stealer touched. Drives the console's "data at risk"
/// panel and the remediation checklist (which sessions to revoke).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    BrowserPasswords,
    BrowserCookies,
    BrowserAutofill,
    BrowserMasterKey,
    CryptoWallet,
    Discord,
    Telegram,
    Steam,
    FtpClient,
    Vpn,
    CloudToken,
    PasswordManager,
    Email,
    SshKeys,
}

impl DataCategory {
    pub fn label(&self) -> &'static str {
        match self {
            DataCategory::BrowserPasswords => "Saved browser passwords",
            DataCategory::BrowserCookies => "Browser cookies / sessions",
            DataCategory::BrowserAutofill => "Autofill & payment cards",
            DataCategory::BrowserMasterKey => "Browser encryption key",
            DataCategory::CryptoWallet => "Crypto wallets",
            DataCategory::Discord => "Discord token",
            DataCategory::Telegram => "Telegram session",
            DataCategory::Steam => "Steam session",
            DataCategory::FtpClient => "FTP/SFTP client credentials",
            DataCategory::Vpn => "VPN profiles",
            DataCategory::CloudToken => "Cloud / SSO tokens",
            DataCategory::PasswordManager => "Password manager vault",
            DataCategory::Email => "Email client data",
            DataCategory::SshKeys => "SSH keys",
        }
    }

    /// Remediation step the console shows when this category was exposed.
    pub fn remediation(&self) -> &'static str {
        match self {
            DataCategory::BrowserPasswords => "Rotate every password saved in the browser, starting with email, SSO and banking",
            DataCategory::BrowserCookies | DataCategory::BrowserMasterKey => {
                "Revoke all active web sessions for the user (Microsoft 365 / Google Workspace / SaaS) — a password reset alone does not kill stolen cookies"
            }
            DataCategory::BrowserAutofill => "Ask the user to review saved cards and notify the card issuer",
            DataCategory::CryptoWallet => "Move funds to a new wallet with a fresh seed immediately",
            DataCategory::Discord => "Change the Discord password (invalidates tokens) and review authorised apps",
            DataCategory::Telegram => "Terminate all other Telegram sessions (Settings → Devices)",
            DataCategory::Steam => "Deauthorize all Steam devices and change the password",
            DataCategory::FtpClient => "Rotate FTP/SFTP credentials stored in the client",
            DataCategory::Vpn => "Revoke and reissue the VPN profile / certificate",
            DataCategory::CloudToken => "Revoke cloud CLI tokens and access keys (AWS/Azure/GCP) and review recent API activity",
            DataCategory::PasswordManager => "Lock the vault, rotate the master password and high-value entries",
            DataCategory::Email => "Rotate the mail account password and check for forwarding rules",
            DataCategory::SshKeys => "Remove the exposed public keys from authorized_keys everywhere and issue new keys",
        }
    }
}

/// Process snapshot attached to alerts (and maintained by the agent's process table).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ProcessInfo {
    pub guid: ProcessGuid,
    pub pid: u32,
    pub ppid: u32,
    #[serde(default)]
    pub parent_guid: Option<ProcessGuid>,
    pub image: String,
    pub cmdline: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub integrity: Option<Integrity>,
    pub start_ts: TimestampMs,
    #[serde(default)]
    pub exit_ts: Option<TimestampMs>,
    #[serde(default)]
    pub signer: Option<String>,
    #[serde(default)]
    pub signed: SignatureState,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub motw_zone: Option<u8>,
    #[serde(default)]
    pub file_size: Option<u64>,
    pub path_class: PathClass,
}

/// A detection.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Alert {
    pub id: Uuid,
    pub ts: TimestampMs,
    pub rule_id: String,
    pub rule_name: String,
    /// Required attribution when the rule came from SigmaHQ (DRL 1.1).
    #[serde(default)]
    pub rule_author: Option<String>,
    pub severity: Severity,
    /// MITRE ATT&CK technique ids, e.g. "T1555.003".
    #[serde(default)]
    pub attack: Vec<String>,
    /// Mode the rule ran in when it fired.
    pub mode: RuleMode,
    /// One-sentence, plain-language description of what happened.
    pub summary: String,
    /// The acting process.
    pub process: ProcessInfo,
    /// Parent chain, nearest first (bounded depth).
    #[serde(default)]
    pub ancestry: Vec<ProcessInfo>,
    #[serde(default)]
    pub data_at_risk: Vec<DataCategory>,
    /// Events that matched (bounded).
    #[serde(default)]
    pub evidence: Vec<Event>,
    /// Response actions taken automatically by the agent.
    #[serde(default)]
    pub actions: Vec<ActionOutcome>,
}
