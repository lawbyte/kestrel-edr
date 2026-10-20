//! Custom Sigma rules (`RuleKind::Sigma` in a `RuleBundle`).
//!
//! Parsing and matching use `rsigma-parser` / `rsigma-eval` (MIT), which
//! implement the full Sigma detection language (field modifiers `contains`,
//! `startswith`, `endswith`, `all`, `re`, `cidr`, `windash`, `base64`, …,
//! value lists, `1 of` / `all of` with wildcards, `not`, `and` / `or`,
//! parentheses). Sigma matching is case-insensitive unless `|cased`.
//!
//! Each Kestrel [`Event`] is exposed to the rule through a lazy field view
//! ([`SigmaEvent`]) using Sysmon field names, and each rule is routed by its
//! `logsource.category`:
//!
//! | category | Kestrel event |
//! |---|---|
//! | `process_creation` | `process_start` |
//! | `file_access` | `file_access` with op open/read |
//! | `file_event` | `file_access` with op create/write/rename |
//! | `file_delete` | `file_access` with op delete |
//! | `file_rename` | `file_access` with op rename |
//! | `network_connection` | `net_connect` |
//! | `dns_query` | `dns_query` |
//! | `registry_set` | `registry_set` with op `set` |
//! | `registry_delete` | `registry_set` with op `delete_value` / `delete_key` |
//! | `registry_event` | `registry_set`, any op |
//! | `process_access` | `process_access` with `return_code` 0 (successful opens, as Sysmon EID 10) |
//! | `create_remote_thread` | `remote_thread` |
//! | `image_load` | `image_load` |
//! | `ps_script` | `script_block` |
//!
//! Not routed (such rules are rejected): `registry_add` (the sensor reports
//! no CreateKey), `pipe_created`, `driver_load`, `wmi_event`, `ps_module`,
//! `ps_classic_*`, `process_tampering`, … and every `service:`-only
//! (event-log) logsource. Kestrel's aggregated `file_activity` (ransomware
//! sensor) and its `task_registered` / `service_installed` /
//! `wmi_subscription` events have no Sysmon-schema category: their Sigma
//! equivalents are event-log (`service: security` / `system`) rules, and the
//! aggregated `sample_paths` are not individual file events, so these are
//! left to the builtin RW-/PS- rules.
//!
//! `logsource.product` must be absent or `windows`. Correlation rules are not
//! supported on the endpoint (the engine has its own builtin correlations).
//!
//! Fields: `Image`, `CommandLine`, `OriginalFileName`, `ParentImage`,
//! `ParentCommandLine`, `User`, `IntegrityLevel`, `ProcessId`,
//! `ParentProcessId`, `ProcessGuid`, `Hashes` (`SHA256=…`), `sha256`, `Signed`,
//! `Signature`, `SignatureStatus`, `TargetFilename`, `DestinationIp`,
//! `DestinationPort`, `DestinationHostname`, `SourcePort`, `Protocol`,
//! `Initiated`, `QueryName`, `QueryResults`, `TargetObject`, `Details`,
//! `EventType`, `GrantedAccess`, `SourceImage`, `TargetImage`,
//! `TargetProcessId`, `ImageLoaded`, `ScriptBlockText`.
//!
//! Mapping notes (where Kestrel differs from Sysmon):
//!
//! * **Unknown values never match.** Kestrel never reports a field as `null`.
//!   A value it did not collect (a parent process that started before the
//!   agent or already exited, registry data that was not captured, fields it
//!   never collects such as `Company`, `CallTrace` or `ParentUser`) is exposed
//!   as "present but unknown": it matches no value, not even `null` or `''`.
//!   So a selection is never satisfied by missing data, and a filter
//!   (`… and not filter_*`) on missing data never suppresses an alert.
//!   Upstream filters such as `filter_main_null: ParentImage: null` cannot
//!   silently drop a detection; the cost is an occasional extra Audit alert
//!   when a `ParentImage` filter cannot be evaluated. Rules whose negated
//!   selections use parent fields get [`NOTE_PARENT_FILTER`] in
//!   `RuleMeta.false_positives`. (`|neq` on an unknown value is true, and no
//!   SigmaHQ Windows rule uses `|exists`.)
//! * `OriginalFileName` is the **file name of `Image`**, not the PE
//!   VERSIONINFO OriginalFilename (no version-resource enrichment yet). It
//!   behaves correctly in the usual `Image|endswith OR OriginalFileName`
//!   selections; `*_renamed_*` rules (which need the real PE value) cannot
//!   fire, and values that differ from the file name (`pwsh.dll`) miss.
//! * `GrantedAccess` is rendered Sysmon-style as hex (`0x1410`). From
//!   Kernel-Audit-API-Calls it is the access the caller **requested**
//!   (DesiredAccess), not the granted mask; they differ for
//!   `MAXIMUM_ALLOWED`. Failed opens (`return_code` ≠ 0) are not routed to
//!   `process_access`. `process_access` rules get [`NOTE_GRANTED_ACCESS`].
//! * `Details` for numeric registry data is offered in both forms, Sysmon
//!   style (`DWORD (0x00000001)`, `QWORD (0x00000000-0x00000001)`) and plain
//!   decimal (`1`), whichever of the two the agent sent; a rule matches if
//!   either form matches.
//! * `EventType` is `SetValue`, `DeleteValue` or `DeleteKey`; `TargetObject`
//!   is `key\value_name` (just the key when there is no value name).
//! * `Initiated` is always `true` (outbound connections only).

use crate::DetectError;
use kestrel_common::{
    Event, EventData, EventKind, FileOp, Integrity, ProcessInfo, RegistryOp, RuleDef, RuleKind,
    RuleMeta, Severity, SignatureState,
};
use rsigma_eval::event::{Event as SigEvent, EventValue};
use rsigma_eval::CompiledRule;
use serde_json::{Map, Value};
use std::borrow::Cow;

/// Event-kind routing for one compiled rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Route {
    Kind(EventKind),
    FileOps(&'static [FileOp]),
    RegOps(&'static [RegistryOp]),
    /// `process_access` with a successful open only.
    ProcessAccessOk,
}

const FILE_ACCESS_OPS: &[FileOp] = &[FileOp::Open, FileOp::Read];
const FILE_EVENT_OPS: &[FileOp] = &[FileOp::Create, FileOp::Write, FileOp::Rename];
const FILE_DELETE_OPS: &[FileOp] = &[FileOp::Delete];
const FILE_RENAME_OPS: &[FileOp] = &[FileOp::Rename];
const REG_SET_OPS: &[RegistryOp] = &[RegistryOp::Set];
const REG_DELETE_OPS: &[RegistryOp] = &[RegistryOp::DeleteValue, RegistryOp::DeleteKey];
const REG_ANY_OPS: &[RegistryOp] = &[
    RegistryOp::Set,
    RegistryOp::DeleteValue,
    RegistryOp::DeleteKey,
];

/// Added to `RuleMeta.false_positives` of `process_access` rules.
pub const NOTE_GRANTED_ACCESS: &str = "Kestrel mapping: GrantedAccess is the access mask the caller requested (Kernel-Audit-API-Calls DesiredAccess), an approximation of Sysmon's granted mask; the two differ for MAXIMUM_ALLOWED requests.";
/// Added to `RuleMeta.false_positives` of rules that filter on parent fields.
pub const NOTE_PARENT_FILTER: &str = "Kestrel mapping: when the parent process is unknown (started before the agent or already exited), filters on ParentImage/ParentCommandLine cannot apply, so this rule may alert where Sysmon-based tooling would not.";

impl Route {
    pub fn matches(&self, e: &Event) -> bool {
        match self {
            Route::Kind(k) => e.kind() == *k,
            Route::FileOps(ops) => {
                matches!(&e.data, EventData::FileAccess { op, .. } if ops.contains(op))
            }
            Route::RegOps(ops) => {
                matches!(&e.data, EventData::RegistrySet { op, .. } if ops.contains(op))
            }
            Route::ProcessAccessOk => {
                matches!(&e.data, EventData::ProcessAccess(t) if t.return_code == 0)
            }
        }
    }
    pub fn kind(&self) -> EventKind {
        match self {
            Route::Kind(k) => *k,
            Route::FileOps(_) => EventKind::FileAccess,
            Route::RegOps(_) => EventKind::RegistrySet,
            Route::ProcessAccessOk => EventKind::ProcessAccess,
        }
    }
}

/// A compiled custom rule.
pub(crate) struct SigmaRule {
    pub meta: RuleMeta,
    pub route: Route,
    pub compiled: CompiledRule,
}

/// Summary of a validated Sigma rule (for the server's `POST /rules`).
#[derive(Debug, Clone, PartialEq)]
pub struct SigmaRuleInfo {
    pub title: String,
    pub sigma_id: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
    pub severity: Severity,
    /// ATT&CK technique ids derived from `attack.tXXXX` tags.
    pub attack: Vec<String>,
    pub references: Vec<String>,
    pub false_positives: Vec<String>,
    pub license: Option<String>,
    /// Sigma logsource category.
    pub category: String,
    /// Kestrel field-mapping caveats for this rule (`NOTE_*`), merged into
    /// `RuleMeta.false_positives` when the rule is compiled.
    pub notes: Vec<String>,
}

fn invalid(id: &str, reason: impl Into<String>) -> DetectError {
    DetectError::InvalidRule {
        id: id.to_string(),
        reason: reason.into(),
    }
}

fn route_for(category: &str) -> Option<Route> {
    Some(match category {
        "process_creation" => Route::Kind(EventKind::ProcessStart),
        "file_access" => Route::FileOps(FILE_ACCESS_OPS),
        "file_event" => Route::FileOps(FILE_EVENT_OPS),
        "file_delete" => Route::FileOps(FILE_DELETE_OPS),
        "file_rename" => Route::FileOps(FILE_RENAME_OPS),
        "network_connection" => Route::Kind(EventKind::NetConnect),
        "dns_query" | "dns" => Route::Kind(EventKind::DnsQuery),
        "registry_set" => Route::RegOps(REG_SET_OPS),
        "registry_delete" => Route::RegOps(REG_DELETE_OPS),
        "registry_event" => Route::RegOps(REG_ANY_OPS),
        "process_access" => Route::ProcessAccessOk,
        "create_remote_thread" => Route::Kind(EventKind::RemoteThread),
        "image_load" => Route::Kind(EventKind::ImageLoad),
        "ps_script" => Route::Kind(EventKind::ScriptBlock),
        _ => return None,
    })
}

fn level_to_severity(l: Option<rsigma_parser::Level>) -> Severity {
    use rsigma_parser::Level::*;
    match l {
        Some(Informational) => Severity::Info,
        Some(Low) => Severity::Low,
        Some(Medium) | None => Severity::Medium,
        Some(High) => Severity::High,
        Some(Critical) => Severity::Critical,
    }
}

/// `attack.t1059.001` → `T1059.001`.
fn attack_from_tags(tags: &[String]) -> Vec<String> {
    tags.iter()
        .filter_map(|t| {
            let t = t.to_ascii_lowercase();
            let rest = t.strip_prefix("attack.t")?;
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                Some(format!("T{}", rest.to_ascii_uppercase()))
            } else {
                None
            }
        })
        .collect()
}

/// Parse and compile one Sigma YAML document. Returns the compiled rule plus its info.
pub(crate) fn compile_source(
    id: &str,
    source: &str,
) -> Result<(CompiledRule, Route, SigmaRuleInfo), DetectError> {
    if source.trim().is_empty() {
        return Err(invalid(id, "empty Sigma source"));
    }
    let coll = rsigma_parser::parse_sigma_yaml(source)
        .map_err(|e| invalid(id, format!("YAML/Sigma parse error: {e}")))?;
    if let Some(d) = coll.errors().next() {
        return Err(invalid(id, format!("Sigma error: {}", d.message)));
    }
    if !coll.correlations.is_empty() {
        return Err(invalid(
            id,
            "correlation rules are not supported on the endpoint",
        ));
    }
    if !coll.filters.is_empty() {
        return Err(invalid(
            id,
            "Sigma filter documents are not supported; use Kestrel exclusions",
        ));
    }
    if coll.rules.len() != 1 {
        return Err(invalid(
            id,
            format!(
                "expected exactly one detection rule, found {}",
                coll.rules.len()
            ),
        ));
    }
    let rule = &coll.rules[0];
    if let Some(p) = &rule.logsource.product {
        if !p.eq_ignore_ascii_case("windows") {
            return Err(invalid(
                id,
                format!("unsupported logsource product '{p}' (only windows)"),
            ));
        }
    }
    let category = rule
        .logsource
        .category
        .as_deref()
        .ok_or_else(|| invalid(id, "logsource.category is required"))?
        .to_ascii_lowercase();
    let route = route_for(&category)
        .ok_or_else(|| invalid(id, format!("unsupported logsource category '{category}'")))?;
    let compiled =
        rsigma_eval::compile_rule(rule).map_err(|e| invalid(id, format!("compile error: {e}")))?;
    let mut notes = Vec::new();
    if route == Route::ProcessAccessOk {
        notes.push(NOTE_GRANTED_ACCESS.to_string());
    }
    if negated_fields(&rule.detection).iter().any(|f| {
        f.eq_ignore_ascii_case("ParentImage") || f.eq_ignore_ascii_case("ParentCommandLine")
    }) {
        notes.push(NOTE_PARENT_FILTER.to_string());
    }
    let info = SigmaRuleInfo {
        title: rule.title.clone(),
        sigma_id: rule.id.clone(),
        author: rule.author.clone(),
        description: rule.description.clone(),
        severity: level_to_severity(rule.level),
        attack: attack_from_tags(&rule.tags),
        references: rule.references.clone(),
        false_positives: rule.falsepositives.clone(),
        license: rule.license.clone(),
        category,
        notes,
    };
    Ok((compiled, route, info))
}

/// Field names used by detections that appear under a `not` in the condition.
fn negated_fields(det: &rsigma_parser::Detections) -> Vec<String> {
    use rsigma_parser::{ConditionExpr as C, Detection as D};
    fn names(c: &C, negated: bool, det: &rsigma_parser::Detections, out: &mut Vec<String>) {
        match c {
            C::And(v) | C::Or(v) => v.iter().for_each(|x| names(x, negated, det, out)),
            C::Not(x) => names(x, !negated, det, out),
            C::Identifier(n) if negated => out.push(n.clone()),
            C::Selector { pattern, .. } if negated => out.extend(
                det.named
                    .keys()
                    .filter(|n| pattern.matches_detection_name(n))
                    .cloned(),
            ),
            _ => {}
        }
    }
    fn fields(d: &D, out: &mut Vec<String>) {
        match d {
            D::AllOf(items) => out.extend(items.iter().filter_map(|i| i.field.name.clone())),
            D::AnyOf(v) | D::And(v) => v.iter().for_each(|x| fields(x, out)),
            D::ArrayMatch { field, .. } => out.push(field.clone()),
            D::Conditional { named, .. } => named.values().for_each(|x| fields(x, out)),
            D::Keywords(_) => {}
        }
    }
    let mut negated = Vec::new();
    for c in &det.conditions {
        names(c, false, det, &mut negated);
    }
    let mut out = Vec::new();
    for n in negated {
        if let Some(d) = det.named.get(&n) {
            fields(d, &mut out);
        }
    }
    out
}

/// Validate a Sigma rule and return its metadata (used by the server).
pub fn validate_sigma(source: &str) -> Result<SigmaRuleInfo, DetectError> {
    compile_source("sigma", source).map(|(_, _, i)| i)
}

/// Compile the Sigma rules of a bundle. Non-Sigma rules are ignored (YARA is
/// handled by the agent's scanner). All-or-nothing: the first error is returned.
pub(crate) fn compile_bundle(rules: &[RuleDef]) -> Result<Vec<SigmaRule>, DetectError> {
    let mut out = Vec::new();
    for def in rules {
        if def.meta.kind != RuleKind::Sigma {
            continue;
        }
        let (compiled, route, info) = compile_source(&def.meta.id, &def.source)?;
        let mut meta = def.meta.clone();
        if meta.name.is_empty() {
            meta.name = info.title.clone();
        }
        if meta.author.is_none() {
            meta.author = info.author.clone();
        }
        if meta.attack.is_empty() {
            meta.attack = info.attack.clone();
        }
        if meta.description.is_empty() {
            meta.description = info.description.clone().unwrap_or_default();
        }
        if meta.references.is_empty() {
            meta.references = info.references.clone();
        }
        for n in &info.notes {
            if !meta.false_positives.contains(n) {
                meta.false_positives.push(n.clone());
            }
        }
        out.push(SigmaRule {
            meta,
            route,
            compiled,
        });
    }
    Ok(out)
}

/// Lazy Sigma view of a Kestrel event.
pub(crate) struct SigmaEvent<'a> {
    pub event: &'a Event,
    pub proc_: Option<&'a ProcessInfo>,
    pub parent: Option<&'a ProcessInfo>,
}

const FIELD_NAMES: &[&str] = &[
    "Image",
    "CommandLine",
    "OriginalFileName",
    "ParentImage",
    "ParentCommandLine",
    "User",
    "IntegrityLevel",
    "ProcessId",
    "ParentProcessId",
    "ProcessGuid",
    "Hashes",
    "sha256",
    "Signed",
    "Signature",
    "SignatureStatus",
    "TargetFilename",
    "DestinationIp",
    "DestinationPort",
    "DestinationHostname",
    "SourcePort",
    "Protocol",
    "Initiated",
    "QueryName",
    "QueryResults",
    "TargetObject",
    "Details",
    "EventType",
    "GrantedAccess",
    "SourceImage",
    "TargetImage",
    "TargetProcessId",
    "ImageLoaded",
    "ScriptBlockText",
];

/// "Present but unknown": an empty list matches no value (not even `null` or
/// `''`), so missing data can neither satisfy a selection nor a filter.
fn unknown<'a>() -> EventValue<'a> {
    EventValue::Array(Vec::new())
}

/// Registry `Details` in both the Sysmon (`DWORD (0x00000001)`) and plain
/// decimal (`1`) renderings when the data is numeric; otherwise as sent.
fn registry_details(data: &str) -> EventValue<'_> {
    let t = data.trim();
    let sysmon = |prefix: &str| {
        t.strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(')'))
            .map(str::to_string)
    };
    if let Ok(n) = t.parse::<u64>() {
        let styled = match u32::try_from(n) {
            Ok(d) => format!("DWORD (0x{d:08x})"),
            Err(_) => format!("QWORD (0x{:08x}-0x{:08x})", n >> 32, n & 0xffff_ffff),
        };
        return EventValue::Array(vec![
            EventValue::Str(Cow::Borrowed(data)),
            EventValue::Str(Cow::Owned(styled)),
        ]);
    }
    let decimal = if let Some(h) = sysmon("DWORD (0x") {
        u32::from_str_radix(&h, 16).ok().map(u64::from)
    } else if let Some(hl) = sysmon("QWORD (0x") {
        hl.split_once("-0x").and_then(|(h, l)| {
            let h = u64::from(u32::from_str_radix(h, 16).ok()?);
            let l = u64::from(u32::from_str_radix(l, 16).ok()?);
            Some((h << 32) | l)
        })
    } else {
        None
    };
    match decimal {
        Some(n) => EventValue::Array(vec![
            EventValue::Str(Cow::Borrowed(data)),
            EventValue::Str(Cow::Owned(n.to_string())),
        ]),
        None => EventValue::Str(Cow::Borrowed(data)),
    }
}

fn s<'a>(v: &'a str) -> Option<EventValue<'a>> {
    Some(EventValue::Str(Cow::Borrowed(v)))
}
fn so<'a>(v: String) -> Option<EventValue<'a>> {
    Some(EventValue::Str(Cow::Owned(v)))
}

fn integrity_str(i: Integrity) -> &'static str {
    match i {
        Integrity::Untrusted => "Untrusted",
        Integrity::Low => "Low",
        Integrity::Medium => "Medium",
        Integrity::High => "High",
        Integrity::System => "System",
    }
}

fn sig_status(s: SignatureState) -> &'static str {
    match s {
        SignatureState::Unknown => "Unknown",
        SignatureState::Unsigned => "Unsigned",
        SignatureState::Valid => "Valid",
        SignatureState::Invalid => "Invalid",
    }
}

impl SigmaEvent<'_> {
    fn field(&self, name: &str) -> Option<EventValue<'_>> {
        let e = self.event;
        let p = self.proc_;
        // Canonicalise case once (Sigma field names are case-insensitive here).
        let n = FIELD_NAMES
            .iter()
            .find(|f| f.eq_ignore_ascii_case(name))
            .copied()?;
        match (n, &e.data) {
            ("Image" | "SourceImage", _) => p.map(|p| p.image.as_str()).and_then(s),
            ("CommandLine", _) => p.map(|p| p.cmdline.as_str()).and_then(s),
            ("OriginalFileName", _) => p.map(|p| crate::paths::file_name(&p.image)).and_then(s),
            ("ParentImage", _) => self.parent.map(|p| p.image.as_str()).and_then(s),
            ("ParentCommandLine", _) => self.parent.map(|p| p.cmdline.as_str()).and_then(s),
            ("User", _) => p.and_then(|p| p.user.as_deref()).and_then(s),
            ("IntegrityLevel", _) => p.and_then(|p| p.integrity).map(integrity_str).and_then(s),
            ("ProcessId", _) => Some(EventValue::Int(e.pid as i64)),
            ("ParentProcessId", _) => p.map(|p| EventValue::Int(p.ppid as i64)),
            ("ProcessGuid", _) => s(&e.guid.0),
            ("Hashes", _) => p
                .and_then(|p| p.sha256.as_deref())
                .and_then(|h| so(format!("SHA256={}", h.to_ascii_uppercase()))),
            ("sha256", _) => p.and_then(|p| p.sha256.as_deref()).and_then(s),
            ("Signed", EventData::ImageLoad { signed, .. }) => {
                s(if *signed == SignatureState::Valid {
                    "true"
                } else {
                    "false"
                })
            }
            ("Signed", _) => p
                .map(|p| {
                    if p.signed == SignatureState::Valid {
                        "true"
                    } else {
                        "false"
                    }
                })
                .and_then(s),
            ("Signature", EventData::ImageLoad { signer, .. }) => signer.as_deref().and_then(s),
            ("Signature", _) => p.and_then(|p| p.signer.as_deref()).and_then(s),
            ("SignatureStatus", EventData::ImageLoad { signed, .. }) => s(sig_status(*signed)),
            ("SignatureStatus", _) => p.map(|p| sig_status(p.signed)).and_then(s),
            ("TargetFilename", EventData::FileAccess { path, .. }) => s(path),
            ("DestinationIp", EventData::NetConnect { dst_ip, .. }) => s(dst_ip),
            ("DestinationPort", EventData::NetConnect { dst_port, .. }) => {
                Some(EventValue::Int(*dst_port as i64))
            }
            ("DestinationHostname", EventData::NetConnect { dst_host, .. }) => {
                dst_host.as_deref().and_then(s)
            }
            ("SourcePort", EventData::NetConnect { src_port, .. }) => {
                Some(EventValue::Int(*src_port as i64))
            }
            ("Protocol", EventData::NetConnect { proto, .. }) => s(match proto {
                kestrel_common::NetProto::Tcp => "tcp",
                kestrel_common::NetProto::Udp => "udp",
            }),
            ("Initiated", EventData::NetConnect { .. }) => s("true"),
            ("QueryName", EventData::DnsQuery { qname, .. }) => s(qname),
            ("QueryResults", EventData::DnsQuery { answers, .. }) => so(answers.join(";")),
            (
                "TargetObject",
                EventData::RegistrySet {
                    key, value_name, ..
                },
            ) => {
                if value_name.is_empty() {
                    s(key)
                } else {
                    so(format!("{}\\{}", key.trim_end_matches('\\'), value_name))
                }
            }
            ("Details", EventData::RegistrySet { data, .. }) => {
                data.as_deref().map(registry_details)
            }
            ("EventType", EventData::RegistrySet { op, .. }) => s(match op {
                RegistryOp::Set => "SetValue",
                RegistryOp::DeleteValue => "DeleteValue",
                RegistryOp::DeleteKey => "DeleteKey",
            }),
            (
                "GrantedAccess",
                EventData::ProcessAccess(t)
                | EventData::RemoteThread(t)
                | EventData::ThreadContext(t)
                | EventData::DebugAttach(t),
            ) => so(format!("0x{:x}", t.granted_access)),
            (
                "TargetImage",
                EventData::ProcessAccess(t)
                | EventData::RemoteThread(t)
                | EventData::ThreadContext(t)
                | EventData::DebugAttach(t),
            ) => s(&t.target_image),
            (
                "TargetProcessId",
                EventData::ProcessAccess(t)
                | EventData::RemoteThread(t)
                | EventData::ThreadContext(t)
                | EventData::DebugAttach(t),
            ) => Some(EventValue::Int(t.target_pid as i64)),
            ("ImageLoaded", EventData::ImageLoad { path, .. }) => s(path),
            ("ScriptBlockText", EventData::ScriptBlock { content, .. }) => s(content),
            _ => None,
        }
    }
}

impl SigEvent for SigmaEvent<'_> {
    fn get_field(&self, path: &str) -> Option<EventValue<'_>> {
        // Never "absent": see the module notes on unknown values.
        Some(self.field(path).unwrap_or_else(unknown))
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        FIELD_NAMES.iter().any(|f| match self.field(f) {
            Some(v) => flat_strings(v).iter().any(|s| pred(s)),
            None => false,
        })
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        FIELD_NAMES
            .iter()
            .filter_map(|f| self.field(f))
            .flat_map(flat_strings)
            .collect()
    }

    fn to_json(&self) -> Value {
        let mut m = Map::new();
        for f in FIELD_NAMES {
            match self.field(f) {
                Some(EventValue::Str(v)) => {
                    m.insert((*f).to_string(), Value::String(v.into_owned()));
                }
                Some(EventValue::Int(i)) => {
                    m.insert((*f).to_string(), Value::from(i));
                }
                // Registry Details: the form the agent sent comes first.
                Some(EventValue::Array(a)) => {
                    if let Some(EventValue::Str(v)) = a.into_iter().next() {
                        m.insert((*f).to_string(), Value::String(v.into_owned()));
                    }
                }
                _ => {}
            }
        }
        Value::Object(m)
    }
}

fn flat_strings(v: EventValue<'_>) -> Vec<Cow<'_, str>> {
    match v {
        EventValue::Str(s) => vec![s],
        EventValue::Int(i) => vec![Cow::Owned(i.to_string())],
        EventValue::Array(a) => a.into_iter().flat_map(flat_strings).collect(),
        _ => vec![],
    }
}

/// Evaluate one rule against an event view.
pub(crate) fn matches(rule: &SigmaRule, ev: &SigmaEvent<'_>) -> bool {
    rsigma_eval::evaluate_rule(&rule.compiled, ev).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{PathClass, ProcessGuid, ProcessStart, TargetProcess};

    fn pinfo(image: &str, cmd: &str) -> ProcessInfo {
        ProcessInfo {
            guid: ProcessGuid("g".into()),
            pid: 10,
            ppid: 1,
            parent_guid: None,
            image: image.into(),
            cmdline: cmd.into(),
            user: Some("CORP\\alice".into()),
            integrity: Some(Integrity::Medium),
            start_ts: 0,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: Some("ab".into()),
            motw_zone: None,
            file_size: None,
            path_class: PathClass::of(image),
        }
    }

    fn eval(src: &str, e: &Event, p: &ProcessInfo, parent: Option<&ProcessInfo>) -> bool {
        let (c, route, _) = compile_source("t", src).unwrap();
        let r = SigmaRule {
            meta: crate::catalog::builtin_catalog().remove(0),
            route,
            compiled: c,
        };
        route.matches(e)
            && matches(
                &r,
                &SigmaEvent {
                    event: e,
                    proc_: Some(p),
                    parent,
                },
            )
    }

    fn ev(data: EventData) -> Event {
        Event {
            ts: 1,
            pid: 10,
            guid: ProcessGuid("g".into()),
            data,
        }
    }

    #[test]
    fn process_creation_modifiers() {
        let src = r#"
title: ClickFix
author: Test Author
level: high
tags: [attack.execution, attack.t1204.004]
logsource: {product: windows, category: process_creation}
detection:
  parent:
    ParentImage|endswith: '\explorer.exe'
  sel_img:
    Image|endswith: ['\powershell.exe', '\pwsh.exe']
  sel_flags:
    CommandLine|windash|contains: ' -w h'
  sel_kw:
    CommandLine|contains|all: ['iex', 'irm']
  filter:
    User|startswith: 'NT AUTHORITY'
  condition: parent and 1 of sel_* and not filter
"#;
        let info = validate_sigma(src).unwrap();
        assert_eq!(info.attack, vec!["T1204.004".to_string()]);
        assert_eq!(info.severity, Severity::High);
        assert_eq!(info.author.as_deref(), Some("Test Author"));
        let p = pinfo(
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "powershell /w h -c iex(irm x)",
        );
        let parent = pinfo(r"C:\Windows\explorer.exe", "explorer.exe");
        let e = ev(EventData::ProcessStart(ProcessStart {
            image: p.image.clone(),
            cmdline: p.cmdline.clone(),
            ..Default::default()
        }));
        assert!(eval(src, &e, &p, Some(&parent)));
        let other_parent = pinfo(r"C:\Windows\System32\svchost.exe", "svchost");
        assert!(!eval(src, &e, &p, Some(&other_parent)));
    }

    #[test]
    fn network_cidr_and_ints() {
        let src = r#"
title: RPC
logsource: {category: network_connection}
detection:
  sel:
    DestinationPort: 8545
  ext:
    DestinationIp|cidr: ['10.0.0.0/8', '192.168.0.0/16']
  condition: sel and not ext
"#;
        let p = pinfo(r"C:\Users\a\AppData\Local\Temp\x.exe", "x");
        let mk = |ip: &str, port: u16| {
            ev(EventData::NetConnect {
                proto: kestrel_common::NetProto::Tcp,
                dst_ip: ip.into(),
                dst_port: port,
                src_port: 1,
                dst_host: None,
                bytes_sent: None,
            })
        };
        assert!(eval(src, &mk("1.2.3.4", 8545), &p, None));
        assert!(!eval(src, &mk("10.2.3.4", 8545), &p, None));
        assert!(!eval(src, &mk("1.2.3.4", 443), &p, None));
    }

    #[test]
    fn process_access_and_re() {
        let src = r#"
title: Access
logsource: {category: process_access}
detection:
  sel:
    TargetImage|endswith: '\chrome.exe'
    GrantedAccess: ['0x143a', '0x1010']
  re:
    SourceImage|re: '(?i)\\temp\\[^\\]+\.exe$'
  condition: all of them
"#;
        let p = pinfo(r"C:\Users\a\AppData\Local\Temp\x.exe", "x");
        let e = ev(EventData::ProcessAccess(TargetProcess {
            target_pid: 5,
            target_guid: None,
            target_image: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
            granted_access: 0x143a,
            return_code: 0,
        }));
        assert!(eval(src, &e, &p, None));
    }

    #[test]
    fn file_ops_routing() {
        let src = "title: f\nlogsource: {category: file_access}\ndetection:\n  sel:\n    TargetFilename|endswith: '\\Login Data'\n  condition: sel\n";
        let p = pinfo(r"C:\x.exe", "x");
        let read = ev(EventData::FileAccess {
            path: r"C:\u\Login Data".into(),
            op: FileOp::Read,
        });
        let write = ev(EventData::FileAccess {
            path: r"C:\u\Login Data".into(),
            op: FileOp::Write,
        });
        assert!(eval(src, &read, &p, None));
        assert!(!eval(src, &write, &p, None));
    }

    fn reg(key: &str, value: &str, data: Option<&str>, op: RegistryOp) -> Event {
        ev(EventData::RegistrySet {
            key: key.into(),
            value_name: value.into(),
            data: data.map(String::from),
            op,
        })
    }

    #[test]
    fn registry_dword_both_renderings() {
        let src = r#"
title: WDigest
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|endswith: '\WDigest\UseLogonCredential'
    Details: 'DWORD (0x00000001)'
  condition: sel
"#;
        let plain = r#"
title: plain
logsource: {category: registry_set}
detection:
  sel:
    Details: '1'
  condition: sel
"#;
        let p = pinfo(r"C:\Windows\System32\reg.exe", "reg add");
        let key = r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
        for data in ["1", "DWORD (0x00000001)"] {
            let e = reg(key, "UseLogonCredential", Some(data), RegistryOp::Set);
            assert!(eval(src, &e, &p, None), "sysmon form, agent sent {data}");
            assert!(eval(plain, &e, &p, None), "plain form, agent sent {data}");
        }
        let zero = reg(key, "UseLogonCredential", Some("0"), RegistryOp::Set);
        assert!(!eval(src, &zero, &p, None));
        // Strings are untouched; QWORD renders high-low.
        assert_eq!(
            registry_details("C:\\x.exe"),
            EventValue::Str(Cow::Borrowed("C:\\x.exe"))
        );
        let EventValue::Array(q) = registry_details("4294967297") else {
            panic!("qword")
        };
        assert_eq!(
            q[1],
            EventValue::Str(Cow::Owned("QWORD (0x00000001-0x00000001)".into()))
        );
        let EventValue::Array(q) = registry_details("QWORD (0x00000001-0x00000001)") else {
            panic!("qword back")
        };
        assert_eq!(q[1], EventValue::Str(Cow::Owned("4294967297".into())));
    }

    #[test]
    fn registry_ops_routing() {
        let set = "title: s\nlogsource: {category: registry_set}\ndetection:\n  sel:\n    TargetObject|contains: '\\Run'\n  condition: sel\n";
        let del = "title: d\nlogsource: {category: registry_delete}\ndetection:\n  sel:\n    TargetObject|contains: '\\Run'\n    EventType: DeleteValue\n  condition: sel\n";
        let any = "title: a\nlogsource: {category: registry_event}\ndetection:\n  sel:\n    TargetObject|contains: '\\Run'\n  condition: sel\n";
        let p = pinfo(r"C:\x.exe", "x");
        let key = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run";
        let s_ev = reg(key, "x", Some("C:\\x.exe"), RegistryOp::Set);
        let d_ev = reg(key, "x", None, RegistryOp::DeleteValue);
        assert!(eval(set, &s_ev, &p, None));
        assert!(!eval(set, &d_ev, &p, None));
        assert!(eval(del, &d_ev, &p, None));
        assert!(!eval(del, &s_ev, &p, None));
        assert!(eval(any, &s_ev, &p, None) && eval(any, &d_ev, &p, None));
        assert!(validate_sigma(&set.replace("registry_set", "registry_add")).is_err());
    }

    #[test]
    fn unknown_parent_never_satisfies_filters() {
        // Upstream pattern: `filter_main_null: ParentImage: null` must not
        // suppress the alert when Kestrel simply doesn't know the parent.
        let src = r#"
title: null filter
logsource: {category: process_creation}
detection:
  sel:
    Image|endswith: '\wevtutil.exe'
  filter_main_null:
    ParentImage: null
  filter_main_empty:
    ParentImage: ''
  filter_main_msi:
    ParentImage|endswith: '\msiexec.exe'
  filter_optional_company:
    Company: null
  condition: sel and not 1 of filter_*
"#;
        let info = validate_sigma(src).unwrap();
        assert!(info.notes.iter().any(|n| n == NOTE_PARENT_FILTER));
        let p = pinfo(r"C:\Windows\System32\wevtutil.exe", "wevtutil cl System");
        let e = ev(EventData::ProcessStart(ProcessStart::default()));
        assert!(eval(src, &e, &p, None), "unknown parent must not filter");
        let msi = pinfo(r"C:\Windows\System32\msiexec.exe", "msiexec");
        assert!(
            !eval(src, &e, &p, Some(&msi)),
            "known parent filter applies"
        );
        // Positive selections on an unknown parent still miss.
        let pos = "title: p\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    ParentImage|endswith: '\\winword.exe'\n  condition: sel\n";
        assert!(!eval(pos, &e, &p, None));
        let pos_null = "title: p\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    ParentImage: null\n  condition: sel\n";
        assert!(!eval(pos_null, &e, &p, None));
        assert!(validate_sigma(pos).unwrap().notes.is_empty());
    }

    #[test]
    fn process_access_requested_access_and_failed_opens() {
        let src = r#"
title: lsass
logsource: {category: process_access}
detection:
  sel:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess|endswith: ['10', '1fffff']
  condition: sel
"#;
        let info = validate_sigma(src).unwrap();
        assert_eq!(info.notes, vec![NOTE_GRANTED_ACCESS.to_string()]);
        let p = pinfo(r"C:\Users\a\Downloads\dumper.exe", "dumper");
        let mk = |rc: u32| {
            ev(EventData::ProcessAccess(TargetProcess {
                target_pid: 700,
                target_guid: None,
                target_image: r"C:\Windows\System32\lsass.exe".into(),
                granted_access: 0x1F_FFFF,
                return_code: rc,
            }))
        };
        assert!(eval(src, &mk(0), &p, None));
        assert!(!eval(src, &mk(0xC000_0022), &p, None), "failed open");
    }

    #[test]
    fn invalid_rules() {
        for bad in [
            "",
            "title: x\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    Image: a\n  condition: sel and nope\n",
            "this: is: not: yaml: [",
            "title: x\nlogsource: {category: firewall}\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
            "title: x\nlogsource: {product: linux, category: process_creation}\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
            "title: x\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
            "title: x\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    Image|badmod: a\n  condition: sel\n",
        ] {
            assert!(validate_sigma(bad).is_err(), "should reject: {bad}");
        }
    }
}
