//! Rule metadata and distributable rule bundles.

use crate::alert::Severity;
use serde::{Deserialize, Serialize};

/// How a rule behaves on an endpoint.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    Off,
    /// Alert only.
    #[default]
    Audit,
    /// Alert and take the rule's response actions.
    Protect,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RuleKind {
    /// Compiled into the engine (ST-xx stealer rules, TP-xx tamper rules).
    Builtin,
    /// Sigma YAML evaluated on the endpoint.
    Sigma,
    /// YARA-X source used by on-demand and new-executable scans.
    Yara,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum RuleCategory {
    Delivery,
    Execution,
    CredentialAccess,
    BrowserTampering,
    Exfiltration,
    Tripwire,
    Tamper,
    Custom,
}

/// Catalog entry shown in the console's rule list.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RuleMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub kind: RuleKind,
    pub category: RuleCategory,
    pub severity: Severity,
    #[serde(default)]
    pub attack: Vec<String>,
    /// Mode used when the policy doesn't override it.
    pub default_mode: RuleMode,
    /// Whether Protect mode is safe from day one (else recommend 2-week Audit baseline).
    #[serde(default)]
    pub protect_day_one: bool,
    /// What the agent does in Protect mode, human readable.
    #[serde(default)]
    pub protect_action: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    /// Known benign triggers, shown to admins writing exclusions.
    #[serde(default)]
    pub false_positives: Vec<String>,
}

/// A custom (non-builtin) rule distributed to agents.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RuleDef {
    pub meta: RuleMeta,
    /// Sigma YAML or YARA-X source, depending on `meta.kind`.
    pub source: String,
}

/// Versioned set of custom rules pushed to agents.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct RuleBundle {
    pub version: u64,
    #[serde(default)]
    pub rules: Vec<RuleDef>,
}
