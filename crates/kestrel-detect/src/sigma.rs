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
//! | `registry_set`, `registry_event` | `registry_set` |
//! | `process_access` | `process_access` |
//! | `create_remote_thread` | `remote_thread` |
//! | `image_load` | `image_load` |
//! | `ps_script` | `script_block` |
//!
//! `logsource.product` must be absent or `windows`. Correlation rules are not
//! supported on the endpoint (the engine has its own builtin correlations).
//!
//! Fields: `Image`, `CommandLine`, `OriginalFileName` (= file name of Image),
//! `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `ProcessId`,
//! `ParentProcessId`, `ProcessGuid`, `Hashes` (`SHA256=…`), `sha256`, `Signed`,
//! `Signature`, `SignatureStatus`, `TargetFilename`, `DestinationIp`,
//! `DestinationPort`, `DestinationHostname`, `SourcePort`, `Protocol`,
//! `Initiated`, `QueryName`, `QueryResults`, `TargetObject`, `Details`,
//! `EventType`, `GrantedAccess` (`0x143a`), `SourceImage`, `TargetImage`,
//! `TargetProcessId`, `ImageLoaded`, `ScriptBlockText`.

use crate::DetectError;
use kestrel_common::{
    Event, EventData, EventKind, FileOp, Integrity, ProcessInfo, RuleDef, RuleKind, RuleMeta,
    Severity, SignatureState,
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
}

const FILE_ACCESS_OPS: &[FileOp] = &[FileOp::Open, FileOp::Read];
const FILE_EVENT_OPS: &[FileOp] = &[FileOp::Create, FileOp::Write, FileOp::Rename];
const FILE_DELETE_OPS: &[FileOp] = &[FileOp::Delete];
const FILE_RENAME_OPS: &[FileOp] = &[FileOp::Rename];

impl Route {
    pub fn matches(&self, e: &Event) -> bool {
        match self {
            Route::Kind(k) => e.kind() == *k,
            Route::FileOps(ops) => {
                matches!(&e.data, EventData::FileAccess { op, .. } if ops.contains(op))
            }
        }
    }
    pub fn kind(&self) -> EventKind {
        match self {
            Route::Kind(k) => *k,
            Route::FileOps(_) => EventKind::FileAccess,
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
        "registry_set" | "registry_event" => Route::Kind(EventKind::RegistrySet),
        "process_access" => Route::Kind(EventKind::ProcessAccess),
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
    };
    Ok((compiled, route, info))
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
            ("Details", EventData::RegistrySet { data, .. }) => data.as_deref().and_then(s),
            ("EventType", EventData::RegistrySet { .. }) => s("SetValue"),
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
        self.field(path)
    }

    fn any_string_value(&self, pred: &dyn Fn(&str) -> bool) -> bool {
        FIELD_NAMES.iter().any(|f| match self.field(f) {
            Some(EventValue::Str(v)) => pred(&v),
            Some(EventValue::Int(i)) => pred(&i.to_string()),
            _ => false,
        })
    }

    fn all_string_values(&self) -> Vec<Cow<'_, str>> {
        FIELD_NAMES
            .iter()
            .filter_map(|f| match self.field(f) {
                Some(EventValue::Str(v)) => Some(v),
                Some(EventValue::Int(i)) => Some(Cow::Owned(i.to_string())),
                _ => None,
            })
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
                _ => {}
            }
        }
        Value::Object(m)
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
