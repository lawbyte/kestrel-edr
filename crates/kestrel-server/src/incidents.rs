//! Alert storage, incident grouping, priority, titles, storylines and
//! Huntress-style remediation checklists.

use crate::{
    autorun_policy,
    mdsafe::{md_code, md_text, plain},
    notify::NotifyJob,
    state::AppState,
};
use kestrel_common::{
    file_name_lower, now_ms, ActionOutcome, Alert, Attribution, AutorunKind, DataCategory, Event,
    EventData, FileActivity, FileOp, PathClass, ProcessInfo, RegistryOp, ResponseAction, Severity,
    SignatureState, TaskOp,
};
use sqlx::{Postgres, Transaction};
use std::collections::{BTreeSet, HashSet};
use uuid::Uuid;

/// Alerts on the same device and process tree within this window share an incident.
pub const GROUP_WINDOW_MS: i64 = 30 * 60 * 1000;
pub const EXFIL_RULES: &[&str] = &["ST-04", "ST-14"];
pub const COMMAND_TTL_MS: i64 = 7 * 86_400_000;

/// Rule families with their own storyline and remediation steps (by rule-id
/// prefix; SigmaHQ pack hits only corroborate and do not set a family).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Families {
    /// RW-xx: ransomware preparation or impact.
    pub ransomware: bool,
    /// CD-xx: OS credential dumping.
    pub credential_dumping: bool,
    /// PS-xx: persistence.
    pub persistence: bool,
}

impl Families {
    pub fn of<'a>(rule_ids: impl IntoIterator<Item = &'a str>) -> Families {
        let mut f = Families::default();
        for r in rule_ids {
            f.ransomware |= r.starts_with("RW-");
            f.credential_dumping |= r.starts_with("CD-");
            f.persistence |= r.starts_with("PS-");
        }
        f
    }

    /// Impact-stage families weigh like an exfiltration-stage rule (ST-04/ST-14)
    /// in the priority score: encryption and dumped OS credentials are the
    /// point where damage is done, like stolen data leaving the device.
    pub fn impact_stage(&self) -> bool {
        self.ransomware || self.credential_dumping
    }
}

pub fn severity_rank(s: Severity) -> i32 {
    match s {
        Severity::Info => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

pub fn parse_severity(s: &str) -> Option<Severity> {
    serde_json::from_value(serde_json::Value::String(s.to_ascii_lowercase())).ok()
}

fn is_system(p: &ProcessInfo) -> bool {
    matches!(p.path_class, PathClass::System | PathClass::Windows)
}

/// Topmost non-system ancestor GUID (the alert's process if the whole chain is system).
pub fn root_guid(alert: &Alert) -> String {
    let mut root = alert.process.guid.0.clone();
    let mut chain: Vec<&ProcessInfo> = vec![&alert.process];
    chain.extend(alert.ancestry.iter());
    for p in chain.iter() {
        if !is_system(p) {
            root = p.guid.0.clone();
        }
    }
    root
}

/// Plain-text description of an action (checklist items, activity, and —
/// escaped with [`md_text`] — storylines). Endpoint-supplied parts are
/// stripped of control / bidi characters and clipped.
pub fn describe_action(a: &ResponseAction) -> String {
    let p = |s: &str| plain(s, 300);
    match a {
        ResponseAction::KillProcess { pid, tree, .. } => {
            if *tree {
                format!("killed process tree (pid {pid})")
            } else {
                format!("killed process (pid {pid})")
            }
        }
        ResponseAction::SuspendProcess { pid, .. } => format!("suspended process (pid {pid})"),
        ResponseAction::ResumeProcess { pid, .. } => format!("resumed process (pid {pid})"),
        ResponseAction::QuarantineFile { path, .. } => format!("quarantined {}", p(path)),
        ResponseAction::RestoreFile { quarantine_id } => {
            format!("restored quarantined file {quarantine_id}")
        }
        ResponseAction::DeleteQuarantined { quarantine_id } => {
            format!("deleted quarantined file {quarantine_id}")
        }
        ResponseAction::BlockDestination { ip, port, .. } => match port {
            Some(p) => format!("blocked destination {ip}:{p}"),
            None => format!("blocked destination {ip}"),
        },
        ResponseAction::BlockImageNetwork { image, .. } => {
            format!("blocked network access for {}", p(image))
        }
        ResponseAction::IsolateHost { .. } => "isolated the host from the network".into(),
        ResponseAction::ReleaseHost => "released host isolation".into(),
        ResponseAction::ApplyHardening => "re-applied the hardening pack".into(),
        ResponseAction::Scan { path } => match path {
            Some(path) => format!("scanned {}", p(path)),
            None => "scanned running user-path executables".into(),
        },
        ResponseAction::CollectTriage => "collected a triage package".into(),
        ResponseAction::RemoveAutorun {
            location,
            value_name,
            restore_data,
            ..
        } => {
            let what = match value_name {
                Some(v) if !v.is_empty() => p(&format!("{location}\\{v}")),
                _ => p(location),
            };
            match restore_data {
                // V-H2: only a write of the canonical Windows default is
                // described as a restore; anything else says what was written.
                Some(d)
                    if autorun_policy::is_canonical_default(location, value_name.as_deref(), d) =>
                {
                    format!("restored the Windows default value of {what}")
                }
                Some(d) => format!("wrote \"{}\" to {what}", plain(d, 160)),
                None => format!("removed persistence entry {what}"),
            }
        }
    }
}

fn containing(a: &ResponseAction) -> bool {
    matches!(
        a,
        ResponseAction::KillProcess { .. }
            | ResponseAction::QuarantineFile { .. }
            | ResponseAction::IsolateHost { .. }
            | ResponseAction::BlockImageNetwork { .. }
    )
}

pub const CONTAINING_TYPES: &[&str] = &[
    "kill_process",
    "quarantine_file",
    "isolate_host",
    "block_image_network",
];

fn path_phrase(pc: PathClass) -> &'static str {
    match pc {
        PathClass::Downloads => "from the Downloads folder",
        PathClass::Temp => "from a temp folder",
        PathClass::UserWritable => "from a user-writable folder",
        PathClass::External => "from removable media or a network share",
        PathClass::ProgramFiles => "from Program Files",
        PathClass::System => "a Windows system binary",
        PathClass::Windows => "from the Windows directory",
        PathClass::Other => "from an unusual location",
    }
}

fn signer_phrase(p: &ProcessInfo) -> String {
    match (p.signed, p.signer.as_deref()) {
        (SignatureState::Valid, Some(s)) => format!("signed by {s}"),
        (SignatureState::Valid, None) => "validly signed".into(),
        (SignatureState::Unsigned, _) => "unsigned".into(),
        (SignatureState::Invalid, _) => "with an invalid signature".into(),
        (SignatureState::Unknown, _) => "signature unknown".into(),
    }
}

fn hhmmss(ts: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ts)
        .map(|d| d.format("%H:%M:%S UTC").to_string())
        .unwrap_or_default()
}

fn human_delta(ms: i64) -> String {
    let s = ms / 1000;
    if s < 60 {
        format!("{s} s")
    } else if s < 3600 {
        format!("{} min {} s", s / 60, s % 60)
    } else {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    }
}

fn cat_str(c: &DataCategory) -> String {
    serde_json::to_value(c)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

fn enum_str<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default()
}

/// Root process of the incident (from the alerts' process/ancestry chains).
fn find_process<'a>(alerts: &'a [Alert], guid: &str) -> Option<&'a ProcessInfo> {
    alerts
        .iter()
        .flat_map(|a| std::iter::once(&a.process).chain(a.ancestry.iter()))
        .find(|p| p.guid.0 == guid)
}

pub struct Summary {
    pub title: String,
    pub severity: Severity,
    pub priority: i32,
    pub storyline: String,
    pub rule_ids: Vec<String>,
    pub attack: Vec<String>,
    pub data_at_risk: Vec<String>,
    pub user: Option<String>,
    /// Non-system process the incident is about (for the "where did it come from" step).
    pub origin_image: Option<String>,
    pub first: i64,
    pub last: i64,
}

/// Priority = max severity base + 10 (data at risk) + 10 (impact stage: an
/// exfiltration-stage rule ST-04/ST-14, or any ransomware RW-xx or credential
/// dumping CD-xx rule) + 5 (not contained), ≤ 100.
pub fn priority(max_sev: Severity, any_data: bool, exfil: bool, contained: bool) -> i32 {
    let mut p = max_sev.base_score() as i32;
    if any_data {
        p += 10;
    }
    if exfil {
        p += 10;
    }
    if !contained {
        p += 5;
    }
    p.min(100)
}

/// The most telling process of an incident: the root if it is not a system
/// binary, else the first non-system actor (e.g. the payload behind a ClickFix
/// explorer → powershell chain, which may only appear in a later alert's
/// ancestry), else the most severe alert's actor.
fn subject_process<'a>(
    sorted: &[&'a Alert],
    root_proc: Option<&'a ProcessInfo>,
) -> Option<&'a ProcessInfo> {
    root_proc
        .filter(|p| !is_system(p))
        .or_else(|| sorted.iter().map(|a| &a.process).find(|p| !is_system(p)))
        .or_else(|| {
            sorted
                .iter()
                .flat_map(|a| a.ancestry.iter())
                .find(|p| !is_system(p))
        })
        .or_else(|| {
            sorted
                .iter()
                .max_by_key(|a| severity_rank(a.severity))
                .map(|a| &a.process)
        })
        .or(root_proc)
}

pub fn summarize(
    alerts: &[Alert],
    root: &str,
    hostname: &str,
    contained: bool,
    blocked: &[String],
) -> Summary {
    let mut sorted: Vec<&Alert> = alerts.iter().collect();
    sorted.sort_by_key(|a| a.ts);
    let max_sev = sorted
        .iter()
        .map(|a| a.severity)
        .max()
        .unwrap_or(Severity::Low);
    let rule_ids: BTreeSet<String> = sorted.iter().map(|a| a.rule_id.clone()).collect();
    let attack: BTreeSet<String> = sorted
        .iter()
        .flat_map(|a| a.attack.iter().cloned())
        .collect();
    let cats: BTreeSet<DataCategory> = sorted
        .iter()
        .flat_map(|a| a.data_at_risk.iter().copied())
        .collect();
    let exfil = rule_ids.iter().any(|r| EXFIL_RULES.contains(&r.as_str()));
    let fam = Families::of(rule_ids.iter().map(String::as_str));
    let tamper = rule_ids.iter().all(|r| r.starts_with("TP-"));
    let root_proc = find_process(alerts, root).or_else(|| sorted.first().map(|a| &a.process));
    let title_proc = subject_process(&sorted, root_proc);
    // V-M6: the title is plain text, the storyline markdown; every
    // endpoint-controlled value is stripped (title) or escaped (storyline).
    let image_name = title_proc
        .map(|p| plain(&file_name_lower(&p.image), 120))
        .unwrap_or_else(|| "unknown process".into());
    // Unattributed changes (synthetic subject, no image): no "by <actor>".
    let by = if image_name.is_empty() {
        String::new()
    } else {
        format!(" by {image_name}")
    };
    let host_title = plain(hostname, 255);
    let host = md_text(hostname, 255);
    let user = sorted
        .iter()
        .find_map(|a| a.process.user.clone())
        .or_else(|| root_proc.and_then(|p| p.user.clone()));

    let title = if tamper {
        format!("Agent tampering on {host_title}")
    } else if fam.ransomware {
        format!("Ransomware activity{by} on {host_title}")
    } else if !cats.is_empty() {
        format!("Credential theft{by} on {host_title}")
    } else if fam.credential_dumping {
        format!("Credential dumping{by} on {host_title}")
    } else if exfil {
        format!("Possible data exfiltration{by} on {host_title}")
    } else if fam.persistence {
        format!("Persistence planted{by} on {host_title}")
    } else {
        let top = sorted
            .iter()
            .max_by_key(|a| severity_rank(a.severity))
            .map(|a| plain(&a.rule_name, 160))
            .unwrap_or_default();
        if image_name.is_empty() {
            format!("{top} on {host_title}")
        } else {
            format!("{top}: {image_name} on {host_title}")
        }
    };

    // ---- storyline (markdown)
    let mut s = String::new();
    // The storyline opens with the same process the title names (the first
    // non-system actor), not a system root such as explorer.exe.
    if let Some(rp) = title_proc {
        s.push_str(&format!(
            "{} ({}, {}) ran on **{}**{}.",
            md_code(&file_name_lower(&rp.image), 120),
            path_phrase(rp.path_class),
            signer_phrase(rp),
            host,
            user.as_ref()
                .map(|u| format!(" as {}", md_code(u, 120)))
                .unwrap_or_default()
        ));
        if let Some(parent) = sorted
            .iter()
            .flat_map(|a| a.ancestry.iter())
            .find(|p| Some(&p.guid) == rp.parent_guid.as_ref())
        {
            s.push_str(&format!(
                " It was started by {}.",
                md_code(&file_name_lower(&parent.image), 120)
            ));
        }
        if rp.motw_zone == Some(3) {
            s.push_str(" The file carries a Mark-of-the-Web from the Internet zone.");
        }
        s.push_str("\n\n");
    }
    s.push_str("**What happened**\n\n");
    let mut prev: Option<i64> = None;
    for a in &sorted {
        let delta = prev
            .map(|p| format!(" (+{})", human_delta(a.ts - p)))
            .unwrap_or_default();
        s.push_str(&format!(
            "- {}{} — {} *({} · {} · {})*\n",
            hhmmss(a.ts),
            delta,
            md_text(&a.summary, 600),
            md_text(&a.rule_id, 64),
            a.severity.as_str(),
            enum_str(&a.mode)
        ));
        // Notable network evidence
        let mut seen = HashSet::new();
        for e in &a.evidence {
            if let EventData::NetConnect {
                dst_ip,
                dst_port,
                dst_host,
                bytes_sent,
                ..
            } = &e.data
            {
                if seen.insert(dst_ip.clone()) {
                    let dhost = dst_host
                        .as_ref()
                        .map(|h| format!(" ({})", md_code(h, 120)))
                        .unwrap_or_default();
                    let bytes = bytes_sent
                        .map(|b| format!(", {} sent", human_bytes(b)))
                        .unwrap_or_default();
                    s.push_str(&format!(
                        "  - connected to {}{dhost}{bytes}\n",
                        md_code(&format!("{dst_ip}:{dst_port}"), 80)
                    ));
                }
            }
        }
        // Ransomware / credential-dumping / persistence evidence in plain words.
        let mut lines: Vec<String> = vec![];
        for e in &a.evidence {
            for l in evidence_lines(e) {
                if !lines.contains(&l) {
                    lines.push(l);
                }
            }
        }
        for l in lines.into_iter().take(6) {
            s.push_str(&format!("  - {l}\n"));
        }
        prev = Some(a.ts);
    }
    if !cats.is_empty() {
        s.push_str("\n**Data at risk:** ");
        s.push_str(
            &cats
                .iter()
                .map(|c| c.label())
                .collect::<Vec<_>>()
                .join(", "),
        );
        s.push_str(".\n");
    }
    let outcomes: Vec<&ActionOutcome> = sorted.iter().flat_map(|a| a.actions.iter()).collect();
    s.push('\n');
    if outcomes.is_empty() {
        s.push_str("**Response:** no automatic response was taken (rules ran in Audit mode). Use the checklist to contain the threat.\n");
    } else {
        let ok: Vec<String> = outcomes
            .iter()
            .filter(|o| o.ok)
            .map(|o| md_text(&describe_action(&o.action), 600))
            .collect();
        let failed: Vec<String> = outcomes
            .iter()
            .filter(|o| !o.ok)
            .map(|o| md_text(&describe_action(&o.action), 600))
            .collect();
        if !ok.is_empty() {
            s.push_str(&format!("**Response:** the agent {}.", join_human(&ok)));
        }
        if !failed.is_empty() {
            s.push_str(&format!(" These actions failed: {}.", join_human(&failed)));
        }
        s.push('\n');
        let backups: Vec<String> = outcomes
            .iter()
            .filter(|o| o.ok && matches!(o.action, ResponseAction::RemoveAutorun { .. }))
            .filter_map(|o| o.artifact.as_ref().map(|b| md_code(b, 80)))
            .collect();
        if !backups.is_empty() {
            s.push_str(&format!(
                "\nThe removed persistence entries were backed up to the quarantine vault first ({}).\n",
                backups.join(", ")
            ));
        }
    }
    if !blocked.is_empty() {
        s.push_str(&format!(
            "\nBlocked destinations: {}.\n",
            blocked
                .iter()
                .map(|b| md_text(b, 120))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if fam.ransomware {
        s.push_str(&format!(
            "\n> Treat this as **active ransomware**. Kestrel works in user mode and cannot guarantee it stopped every encrypting process, \
             or files encrypted over the network from another machine. Keep **{host}** isolated, check every file share it could write to, \
             confirm your backups are intact before restoring, and do not pay or contact the attackers.\n"
        ));
    }
    if fam.credential_dumping {
        s.push_str(&format!(
            "\n> Treat every account that logged on to **{host}** as **compromised**: a dump of LSASS, SAM or NTDS contains reusable password hashes \
             and Kerberos tickets. Killing the dumper does not undo a dump that already finished. Reset those passwords and look for logons from {host} to other machines.\n"
        ));
    }
    if (exfil || !cats.is_empty()) && !fam.credential_dumping {
        s.push_str(
            "\n> Treat this as a **probable credential compromise**: user-mode containment cannot guarantee nothing left the device. \
             Revoke sessions and rotate the exposed secrets even if the process was killed.\n",
        );
    }
    if fam.persistence {
        let removed: Vec<String> = outcomes
            .iter()
            .filter(|o| o.ok && matches!(o.action, ResponseAction::RemoveAutorun { .. }))
            .map(|o| md_text(&describe_action(&o.action), 600))
            .collect();
        if removed.is_empty() {
            s.push_str("\n**Persistence:** the entry is still in place (rules ran in Audit mode). Remove it from the checklist, then check the program it starts.\n");
        } else {
            s.push_str(&format!(
                "\n**Persistence:** the agent {}. Malware usually installs more than one autorun: collect a triage package (it lists every autorun) and compare it with a clean device.\n",
                join_human(&removed)
            ));
        }
    }
    if !contained && !(exfil || !cats.is_empty() || fam.ransomware || fam.credential_dumping) {
        s.push_str("\nThe threat is **not contained** yet.\n");
    }

    let data: Vec<String> = cats.iter().map(cat_str).collect();
    Summary {
        title,
        severity: max_sev,
        priority: priority(
            max_sev,
            !data.is_empty(),
            exfil || fam.impact_stage(),
            contained,
        ),
        storyline: s,
        rule_ids: rule_ids.into_iter().collect(),
        attack: attack.into_iter().collect(),
        data_at_risk: data,
        user,
        origin_image: title_proc
            .filter(|p| !is_system(p))
            .map(|p| file_name_lower(&p.image)),
        first: sorted.first().map(|a| a.ts).unwrap_or(0),
        last: sorted.last().map(|a| a.ts).unwrap_or(0),
    }
}

/// "renamed 412 files in 37 folders in 10 s, new extension `.k3str` (95%)" plus
/// note / canary / network-share / remote-writer clauses (markdown; endpoint
/// values are code spans built with [`md_code`]).
pub fn describe_file_activity(f: &FileActivity) -> String {
    let verb = if f.renames >= f.overwrites && f.renames >= f.new_files && f.renames > 0 {
        "renamed"
    } else if f.overwrites >= f.new_files && f.overwrites > 0 {
        "overwrote"
    } else {
        "changed"
    };
    let n = match verb {
        "renamed" => f.renames,
        "overwrote" => f.overwrites,
        _ => f.files_touched,
    };
    let mut out = format!(
        "{verb} {n} file{} in {} folder{} within {}",
        if n == 1 { "" } else { "s" },
        f.dirs,
        if f.dirs == 1 { "" } else { "s" },
        human_delta(f.window_ms as i64)
    );
    if let Some(ext) = f.top_new_ext.as_deref().filter(|e| !e.is_empty()) {
        out.push_str(&format!(
            ", new extension {}",
            md_code(&format!(".{ext}"), 40)
        ));
        if f.top_ext_pct > 0 {
            out.push_str(&format!(" ({}%)", f.top_ext_pct.min(100)));
        }
    }
    if f.net_paths > 0 {
        out.push_str(&format!(", {} on network shares", f.net_paths));
    }
    if let Some(note) = f.note_name.as_deref().filter(|n| !n.is_empty()) {
        out.push_str(&format!(
            "; created {} in {} folder{} (likely ransom note)",
            md_code(note, 80),
            f.note_dirs,
            if f.note_dirs == 1 { "" } else { "s" }
        ));
    }
    if !f.canary_hits.is_empty() {
        out.push_str(&format!(
            "; touched {} ransomware canary file{}",
            f.canary_hits.len(),
            if f.canary_hits.len() == 1 { "" } else { "s" }
        ));
        if f.canary_in_place {
            out.push_str(" (in-place write found by polling: writer inferred)");
        }
    }
    if f.remote_writer {
        out.push_str(
            " — the writes came from a **remote client over SMB**, not a local program; check the machines with write access to this device's shares",
        );
    }
    out
}

fn is_lsass(image: &str) -> bool {
    file_name_lower(image) == "lsass.exe"
}

/// Suffix for an evidence line whose actor was not reported by the kernel.
fn attribution_note(a: Attribution) -> &'static str {
    match a {
        Attribution::Exact => "",
        Attribution::Heuristic => " (writer inferred)",
        Attribution::None => " (writer unknown)",
    }
}

/// Plain-language lines for the evidence kinds the RW/CD/PS families rely on.
/// Markdown: every endpoint-controlled value goes through [`md_code`] (V-M6).
fn evidence_lines(e: &Event) -> Vec<String> {
    match &e.data {
        EventData::FileActivity(f) => vec![describe_file_activity(f)],
        EventData::TaskRegistered(t) => {
            let verb = match t.op {
                TaskOp::Created => "created",
                TaskOp::Updated => "changed",
                TaskOp::Deleted => "deleted",
            };
            let mut flags = vec![];
            if t.hidden {
                flags.push("hidden".to_string());
            }
            if !t.triggers.is_empty() {
                flags.push(format!(
                    "runs at {}",
                    t.triggers
                        .iter()
                        .take(8)
                        .map(|x| md_text(x, 24))
                        .collect::<Vec<_>>()
                        .join("/")
                ));
            }
            if let Some(u) = &t.user {
                flags.push(format!("as {}", md_code(u, 80)));
            }
            let flags = if flags.is_empty() {
                String::new()
            } else {
                format!(" ({})", flags.join(", "))
            };
            let run = t
                .actions
                .first()
                .map(|a| format!(" running {}", md_code(a, 160)))
                .unwrap_or_default();
            vec![format!(
                "scheduled task {} {verb}{flags}{run}{}",
                md_code(&t.name, 160),
                attribution_note(t.attribution)
            )]
        }
        EventData::ServiceInstalled(sv) => {
            let start = match sv.start_type {
                Some(0) => " (boot start)",
                Some(1) => " (system start)",
                Some(2) => " (starts automatically)",
                Some(3) => " (manual start)",
                Some(4) => " (disabled)",
                _ => "",
            };
            let driver = if sv.service_type == Some(1) {
                "kernel driver"
            } else {
                "service"
            };
            vec![format!(
                "{driver} {} installed{start} running {}{}",
                md_code(&sv.name, 120),
                md_code(&sv.image_path, 160),
                attribution_note(sv.attribution)
            )]
        }
        EventData::WmiSubscription(w) => vec![format!(
            "WMI subscription in {}: filter {} runs {}{}",
            md_code(&w.namespace, 80),
            md_code(&w.filter, 120),
            md_code(&w.consumer, 160),
            attribution_note(w.attribution)
        )],
        EventData::RegistrySet {
            key,
            value_name,
            data,
            op,
            attribution,
        } => {
            let at = if value_name.is_empty() {
                md_code(key, 200)
            } else {
                md_code(&format!("{key}\\{value_name}"), 200)
            };
            let note = attribution_note(*attribution);
            vec![match op {
                RegistryOp::Set => match data {
                    Some(d) if !d.is_empty() => {
                        format!("registry value {at} set to {}{note}", md_code(d, 160))
                    }
                    _ => format!("registry value {at} set{note}"),
                },
                RegistryOp::DeleteValue => format!("registry value {at} deleted{note}"),
                RegistryOp::DeleteKey => {
                    format!("registry key {} deleted{note}", md_code(key, 200))
                }
            }]
        }
        EventData::ProcessAccess(t) if is_lsass(&t.target_image) => {
            let mut l = format!("opened `lsass.exe` with access `{:#x}`", t.granted_access);
            if t.return_code != 0 {
                l.push_str(&format!(
                    " — **refused** by Windows (status `{:#010x}`), as LSA protection does",
                    t.return_code
                ));
            }
            vec![l]
        }
        EventData::FileAccess { path, op } if is_dump_path(path) => {
            vec![format!(
                "{} {} (memory dump file)",
                enum_str(op),
                md_code(path, 200)
            )]
        }
        _ => vec![],
    }
}

fn is_dump_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    l.ends_with(".dmp") || l.ends_with(".mdmp") || l.ends_with(".dump") || l.contains("lsass")
}

/// Persistence entries in an alert's evidence, with the `RemoveAutorun` that
/// would take each one out when it is safe to offer as a one-click approval.
/// Only well-understood locations get an action; anything else is a manual step.
pub fn autorun_targets(alert: &Alert) -> Vec<(String, Option<ResponseAction>)> {
    let mut out: Vec<(String, Option<ResponseAction>)> = vec![];
    let remove = |kind, location: &str, value_name: Option<&str>, restore: Option<&str>| {
        // Only offer what the approval path will accept (V-H2).
        autorun_policy::validate(kind, location, value_name, restore).ok()?;
        Some(ResponseAction::RemoveAutorun {
            kind,
            location: location.to_string(),
            value_name: value_name.map(String::from),
            restore_data: restore.map(String::from),
        })
    };
    for e in &alert.evidence {
        let item = match &e.data {
            EventData::TaskRegistered(t) if t.op != TaskOp::Deleted => Some((
                format!("scheduled task {}", t.name),
                remove(AutorunKind::ScheduledTask, &t.name, None, None)
                    .filter(|_| t.name.starts_with('\\')),
            )),
            EventData::ServiceInstalled(sv) => Some((
                format!("service {}", sv.name),
                remove(AutorunKind::Service, &sv.name, None, None)
                    .filter(|_| !sv.name.contains('\\')),
            )),
            EventData::WmiSubscription(w) => {
                let name = quoted_name(&w.consumer);
                Some((
                    format!("WMI subscription {}", name.as_deref().unwrap_or(&w.filter)),
                    name.and_then(|n| remove(AutorunKind::WmiSubscription, &n, None, None)),
                ))
            }
            EventData::RegistrySet {
                key,
                value_name,
                op: RegistryOp::Set,
                ..
            } => {
                let what = format!("registry value {key}\\{value_name}");
                // The same allow-list the server enforces when the action is
                // queued (V-H2): delete autorun values, write back only the
                // canonical Windows default.
                let action = autorun_policy::parse_key(key).and_then(|k| {
                    if autorun_policy::registry_delete_allowed(&k, value_name) {
                        remove(AutorunKind::RegistryValue, key, Some(value_name), None)
                    } else if value_name.eq_ignore_ascii_case("UseLogonCredential") {
                        // Only the WDigest default is offered as one click;
                        // Winlogon / BootExecute stay manual steps (their
                        // default path depends on where Windows is installed).
                        autorun_policy::canonical_default(&k, value_name).and_then(|d| {
                            remove(AutorunKind::RegistryValue, key, Some(value_name), Some(d))
                        })
                    } else {
                        None
                    }
                });
                Some((what, action))
            }
            EventData::FileAccess { path, op }
                if matches!(op, FileOp::Create | FileOp::Write | FileOp::Rename)
                    && path
                        .to_ascii_uppercase()
                        .contains("\\START MENU\\PROGRAMS\\STARTUP\\") =>
            {
                Some((
                    format!("Startup-folder file {path}"),
                    remove(AutorunKind::StartupFile, path, None, None),
                ))
            }
            _ => None,
        };
        if let Some(it) = item {
            if !out.iter().any(|(w, _)| *w == it.0) {
                out.push(it);
            }
        }
    }
    out
}

/// `CommandLineEventConsumer="evil"` → `evil`.
fn quoted_name(s: &str) -> Option<String> {
    let start = s.find('"')? + 1;
    let len = s[start..].find('"')?;
    let n = &s[start..start + len];
    (!n.is_empty() && !n.contains('\\')).then(|| n.to_string())
}

fn manual(key: &str, text: String) -> ChecklistSeed {
    ChecklistSeed {
        kind: "manual",
        text,
        done: false,
        action: None,
        key: format!("manual:{key}"),
    }
}

/// Family-specific checklist steps for one alert (deduplicated per incident by key).
fn family_checklist(alert: &Alert, hostname: &str) -> Vec<ChecklistSeed> {
    let mut out = vec![];
    let id = alert.rule_id.as_str();
    if id.starts_with("RW-") {
        let note = alert.evidence.iter().find_map(|e| match &e.data {
            EventData::FileActivity(f) => f.note_name.clone(),
            _ => None,
        });
        let ext = alert.evidence.iter().find_map(|e| match &e.data {
            EventData::FileActivity(f) => f.top_new_ext.clone(),
            _ => None,
        });
        out.push(manual(
            "rw:isolate",
            format!("Keep {hostname} isolated and powered on until you know the scope — unplugging it destroys memory evidence, and rebooting may let the ransomware run again"),
        ));
        out.push(manual(
            "rw:backups",
            "Check backups before restoring anything: confirm the latest offline or immutable backup is intact, and whether Volume Shadow Copies survived (`vssadmin list shadows`) — most ransomware deletes them first".into(),
        ));
        out.push(manual(
            "rw:shares",
            format!(
                "Check every file share {hostname} could write to for encrypted files{}, and take affected shares offline",
                ext.map(|e| format!(" (extension .{e})")).unwrap_or_default()
            ),
        ));
        out.push(manual(
            "rw:note",
            format!(
                "Do not pay or contact the attackers. Preserve the ransom note{} and one encrypted sample file to identify the family (e.g. No More Ransom) and for the police report",
                note.map(|n| format!(" ({n})")).unwrap_or_default()
            ),
        ));
        out.push(manual(
            "rw:creds",
            format!("Reset the passwords of accounts used on {hostname}: ransomware operators usually hold domain credentials before they encrypt"),
        ));
        out.push(manual(
            "rw:notify",
            "If personal data was affected, assess your breach-notification duty (Singapore PDPA: notify the PDPC within 3 days of deciding a breach is notifiable; Indonesia UU PDP: within 3 × 24 hours)".into(),
        ));
    }
    if id.starts_with("CD-") {
        out.push(manual(
            "cd:reset",
            format!("Reset the passwords of every account that logged on to {hostname} (interactive, RDP, services and scheduled tasks), administrators first"),
        ));
        out.push(manual(
            "cd:service",
            format!("Rotate service-account credentials used on {hostname} and the local administrator password (with LAPS, force an immediate rotation)"),
        ));
        out.push(manual(
            "cd:lateral",
            format!("Look for lateral movement: logons from {hostname} to servers and other PCs since the alert (RDP, SMB/PsExec, WMI, WinRM)"),
        ));
        out.push(manual(
            "cd:domain",
            format!("If a domain or enterprise admin had logged on to {hostname}, treat the domain as compromised: reset the krbtgt account twice (allowing replication in between) and review privileged groups"),
        ));
        out.push(manual(
            "cd:dumpfile",
            "Make sure no dump file is left on the device or a share (Kestrel quarantines the ones it sees): a dump is a full export of the credentials".into(),
        ));
        out.push(manual(
            "cd:harden",
            "Turn on LSA protection and WDigest-off in the device's policy (Windows hardening); LSA protection takes effect after the next reboot".into(),
        ));
    }
    if id.starts_with("PS-") || id.starts_with("CD-") {
        for (what, action) in autorun_targets(alert) {
            let removed = alert.actions.iter().any(|o| {
                o.ok && matches!(&o.action, ResponseAction::RemoveAutorun { location, .. }
                    if what.contains(location.as_str()))
            });
            // Plain text shown in the checklist and the approval dialog:
            // no control / bidi characters (V-M6), clipped.
            let what = plain(&what, 400);
            match action {
                Some(a) if !removed => out.push(ChecklistSeed {
                    kind: "approve",
                    text: format!("Remove {what} (the agent backs it up to the quarantine vault first)"),
                    done: false,
                    key: format!("approve:{}", action_key(&a)),
                    action: Some(a),
                }),
                None if !removed => out.push(manual(
                    &format!("ps:remove:{}", crate::crypto::sha256_hex(&what)),
                    format!("Remove {what} by hand after checking what it starts (Kestrel does not remove this kind of entry automatically)"),
                )),
                _ => {}
            }
        }
    }
    if id.starts_with("PS-") {
        let triage = ResponseAction::CollectTriage;
        if !alert
            .actions
            .iter()
            .any(|o| o.ok && o.action == ResponseAction::CollectTriage)
        {
            out.push(ChecklistSeed {
                kind: "approve",
                text: format!(
                    "Collect a triage package from {hostname} to check for other autoruns"
                ),
                done: false,
                key: format!("approve:{}", action_key(&triage)),
                action: Some(triage),
            });
        }
        out.push(manual(
            "ps:verify",
            "Compare the triage package's autoruns list with a clean device: malware usually installs more than one autorun".into(),
        ));
    }
    out
}

fn human_bytes(b: u64) -> String {
    if b >= 1 << 20 {
        format!("{:.1} MB", b as f64 / (1u64 << 20) as f64)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

fn join_human(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        n => format!("{} and {}", items[..n - 1].join(", "), items[n - 1]),
    }
}

/// A failed automatic action reported by the agent is offered for one-click
/// retry only when the approval path would accept it (V-H2: a reported
/// `remove_autorun` outside the allow-list is never offered).
fn retry_offerable(a: &ResponseAction) -> bool {
    match a {
        ResponseAction::RemoveAutorun {
            kind,
            location,
            value_name,
            restore_data,
        } => autorun_policy::validate(
            *kind,
            location,
            value_name.as_deref(),
            restore_data.as_deref(),
        )
        .is_ok(),
        _ => true,
    }
}

pub struct ChecklistSeed {
    pub kind: &'static str,
    pub text: String,
    pub done: bool,
    pub action: Option<ResponseAction>,
    pub key: String,
}

/// Checklist items contributed by one alert.
pub fn checklist_for(alert: &Alert, hostname: &str, user: Option<&str>) -> Vec<ChecklistSeed> {
    let mut out = vec![];
    // Checklist text is plain text: strip control / bidi characters (V-M6).
    let hostname = &plain(hostname, 255);
    let image = plain(&file_name_lower(&alert.process.image), 120);
    let done_keys: HashSet<String> = alert
        .actions
        .iter()
        .filter(|o| o.ok)
        .map(|o| action_key(&o.action))
        .collect();

    for o in alert.actions.iter() {
        if o.ok {
            let backup = match (&o.action, o.artifact.as_deref()) {
                (ResponseAction::RemoveAutorun { .. }, Some(b)) if !b.is_empty() => {
                    format!(" (backup {} in the quarantine vault)", plain(b, 80))
                }
                _ => String::new(),
            };
            out.push(ChecklistSeed {
                kind: "done",
                text: format!("Agent {}{backup} — {}", describe_action(&o.action), image),
                done: true,
                action: Some(o.action.clone()),
                key: format!("done:{}", action_key(&o.action)),
            });
        } else if retry_offerable(&o.action) {
            out.push(ChecklistSeed {
                kind: "approve",
                text: format!(
                    "Retry: {} (automatic attempt failed{})",
                    describe_action(&o.action),
                    if o.detail.is_empty() {
                        String::new()
                    } else {
                        format!(": {}", plain(&o.detail, 300))
                    }
                ),
                done: false,
                action: Some(o.action.clone()),
                key: format!("approve:{}", action_key(&o.action)),
            });
        }
    }

    let tamper = alert.rule_id.starts_with("TP-");
    if !tamper && !is_system(&alert.process) && severity_rank(alert.severity) >= 2 {
        let kill = ResponseAction::KillProcess {
            pid: alert.process.pid,
            guid: Some(alert.process.guid.clone()),
            tree: true,
        };
        if !alert
            .actions
            .iter()
            .any(|o| o.ok && matches!(o.action, ResponseAction::KillProcess { .. }))
        {
            out.push(ChecklistSeed {
                kind: "approve",
                text: format!(
                    "Kill {image} (pid {}) and its child processes",
                    alert.process.pid
                ),
                done: false,
                key: format!("approve:{}", action_key(&kill)),
                action: Some(kill),
            });
        }
        if alert.process.path_class.is_user_writable() {
            let q = ResponseAction::QuarantineFile {
                path: alert.process.image.clone(),
                sha256: alert.process.sha256.clone(),
            };
            if !done_keys.contains(&action_key(&q)) {
                out.push(ChecklistSeed {
                    kind: "approve",
                    text: format!("Quarantine {}", alert.process.image),
                    done: false,
                    key: format!("approve:{}", action_key(&q)),
                    action: Some(q),
                });
            }
        }
    }
    let mut ips = vec![];
    for e in &alert.evidence {
        if let EventData::NetConnect { dst_ip, .. } = &e.data {
            if !ips.contains(dst_ip) && is_public_ip(dst_ip) {
                ips.push(dst_ip.clone());
            }
        }
    }
    for ip in ips.into_iter().take(5) {
        let b = ResponseAction::BlockDestination {
            ip: ip.clone(),
            port: None,
            image: None,
            ttl_secs: None,
            ioc_id: None,
        };
        let already = alert.actions.iter().any(|o| {
            o.ok && matches!(&o.action, ResponseAction::BlockDestination { ip: i, .. } if *i == ip)
        });
        if !already {
            out.push(ChecklistSeed {
                kind: "approve",
                text: format!("Block destination {ip}"),
                done: false,
                key: format!("approve:block:{ip}"),
                action: Some(b),
            });
        }
    }
    let isolated = alert
        .actions
        .iter()
        .any(|o| o.ok && matches!(o.action, ResponseAction::IsolateHost { .. }));
    if !tamper && severity_rank(alert.severity) >= 3 && !isolated {
        out.push(ChecklistSeed {
            kind: "approve",
            text: format!("Isolate host {hostname}"),
            done: false,
            key: "approve:isolate".into(),
            action: Some(ResponseAction::IsolateHost { allow_ips: vec![] }),
        });
    }
    // Release is only offered once the host is actually isolated (here by the
    // agent; analyst isolations add it when their result comes back).
    if isolated {
        out.push(release_seed(hostname));
    }
    let who = user.map(|u| format!(" for {u}")).unwrap_or_default();
    for c in &alert.data_at_risk {
        out.push(ChecklistSeed {
            kind: "manual",
            text: format!("{}{who}", c.remediation()),
            done: false,
            action: None,
            key: format!("manual:{}", crate::crypto::sha256_hex(c.remediation())),
        });
    }
    if tamper {
        out.push(ChecklistSeed {
            kind: "manual",
            text: format!("Check that the Kestrel agent on {hostname} is running and healthy, and find out who changed it"),
            done: false,
            action: None,
            key: "manual:tamper".into(),
        });
    }
    out.extend(family_checklist(alert, hostname));
    // The "where did it come from" step is maintained per incident by
    // `recompute_incident` (it must name the incident's non-system subject).
    out
}

pub fn release_seed(hostname: &str) -> ChecklistSeed {
    ChecklistSeed {
        kind: "approve",
        text: format!("Release isolation of {hostname} once every step above is complete"),
        done: false,
        key: "approve:release".into(),
        action: Some(ResponseAction::ReleaseHost),
    }
}

pub fn origin_seed(image: &str, user: Option<&str>) -> ChecklistSeed {
    ChecklistSeed {
        kind: "manual",
        text: format!(
            "Ask {} where {image} came from (download link, email, chat) and block that source",
            user.unwrap_or("the user")
        ),
        done: false,
        action: None,
        key: "manual:origin".into(),
    }
}

fn is_public_ip(ip: &str) -> bool {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            !(v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00)
        }
        Err(_) => false,
    }
}

fn action_key(a: &ResponseAction) -> String {
    match a {
        ResponseAction::KillProcess { guid, pid, .. } => {
            format!(
                "kill:{}",
                guid.as_ref()
                    .map(|g| g.0.clone())
                    .unwrap_or_else(|| pid.to_string())
            )
        }
        ResponseAction::QuarantineFile { path, .. } => {
            format!("quarantine:{}", path.to_ascii_lowercase())
        }
        ResponseAction::BlockDestination { ip, .. } => format!("block:{ip}"),
        ResponseAction::IsolateHost { .. } => "isolate".into(),
        ResponseAction::ReleaseHost => "release".into(),
        other => format!(
            "{}:{}",
            other.name(),
            crate::crypto::sha256_hex(serde_json::to_vec(other).unwrap_or_default())
        ),
    }
}

pub struct IngestOutcome {
    pub incident_id: Option<Uuid>,
    pub incident_created: bool,
    pub duplicate: bool,
}

/// Store an alert, attach it to an incident, refresh the incident and its checklist.
pub async fn ingest_alert(
    state: &AppState,
    device_id: Uuid,
    alert: Alert,
) -> anyhow::Result<IngestOutcome> {
    let now = now_ms();
    let root = root_guid(&alert);
    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(format!("incident:{device_id}"))
        .execute(&mut *tx)
        .await?;
    let (hostname, logged_on): (String, Option<String>) =
        sqlx::query_as("SELECT hostname, logged_on_user FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&mut *tx)
            .await?;

    let inserted = sqlx::query(
        "INSERT INTO alerts (id, device_id, ts, rule_id, rule_name, rule_author, severity, severity_rank, attack, mode, summary, \
         process_guid, root_guid, image, sha256, signer, user_name, data_at_risk, actions, body, received_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) ON CONFLICT (id) DO NOTHING",
    )
    .bind(alert.id)
    .bind(device_id)
    .bind(alert.ts)
    .bind(&alert.rule_id)
    .bind(&alert.rule_name)
    .bind(&alert.rule_author)
    .bind(alert.severity.as_str())
    .bind(severity_rank(alert.severity))
    .bind(&alert.attack)
    .bind(enum_str(&alert.mode))
    .bind(&alert.summary)
    .bind(&alert.process.guid.0)
    .bind(&root)
    .bind(&alert.process.image)
    .bind(alert.process.sha256.as_ref().map(|s| s.to_ascii_lowercase()))
    .bind(&alert.process.signer)
    .bind(&alert.process.user)
    .bind(alert.data_at_risk.iter().map(cat_str).collect::<Vec<_>>())
    .bind(serde_json::to_value(&alert.actions)?)
    .bind(serde_json::to_value(&alert)?)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected();
    if inserted == 0 {
        tx.commit().await?;
        return Ok(IngestOutcome {
            incident_id: None,
            incident_created: false,
            duplicate: true,
        });
    }

    // Same root tree, or an open incident rooted at one of this process's
    // ancestors (e.g. ClickFix: explorer.exe RunMRU → powershell.exe → payload,
    // where explorer/powershell are system-path and would otherwise each get
    // their own incident). An exact root match wins.
    let mut chain: Vec<String> = vec![root.clone(), alert.process.guid.0.clone()];
    chain.extend(alert.ancestry.iter().map(|p| p.guid.0.clone()));
    chain.dedup();
    let existing: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM incidents WHERE device_id = $1 AND root_guid = ANY($5) AND status IN ('open','in_progress') \
         AND $3 BETWEEN first_alert_at - $4 AND last_alert_at + $4 \
         ORDER BY (root_guid = $2) DESC, last_alert_at DESC LIMIT 1",
    )
    .bind(device_id)
    .bind(&root)
    .bind(alert.ts)
    .bind(GROUP_WINDOW_MS)
    .bind(&chain)
    .fetch_optional(&mut *tx)
    .await?;
    let (incident_id, created) = match existing {
        Some((id,)) => (id, false),
        None => {
            let id = Uuid::new_v4();
            sqlx::query(
                "INSERT INTO incidents (id, title, severity, severity_rank, priority, status, device_id, root_guid, user_name, \
                 first_alert_at, last_alert_at, created_at, updated_at) VALUES ($1,'',$2,$3,0,'open',$4,$5,$6,$7,$7,$8,$8)",
            )
            .bind(id)
            .bind(alert.severity.as_str())
            .bind(severity_rank(alert.severity))
            .bind(device_id)
            .bind(&root)
            .bind(alert.process.user.clone().or(logged_on.clone()))
            .bind(alert.ts)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            (id, true)
        }
    };
    sqlx::query("UPDATE alerts SET incident_id = $2 WHERE id = $1")
        .bind(alert.id)
        .bind(incident_id)
        .execute(&mut *tx)
        .await?;

    // Automatic actions become ResponseActionRows with requested_by = null.
    for o in &alert.actions {
        sqlx::query(
            "INSERT INTO response_actions (id, device_id, incident_id, action, action_type, status, requested_by, comment, \
             created_at, sent_at, delivered_at, completed_at, expires_at, result_detail, artifact) \
             VALUES ($1,$2,$3,$4,$5,$6,NULL,$7,$8,$8,$8,$8,$8,$9,$10)",
        )
        .bind(Uuid::new_v4())
        .bind(device_id)
        .bind(incident_id)
        .bind(serde_json::to_value(&o.action)?)
        .bind(o.action.name())
        .bind(if o.ok { "succeeded" } else { "failed" })
        .bind(format!("Automatic response by rule {}", alert.rule_id))
        .bind(o.ts)
        .bind(&o.detail)
        .bind(&o.artifact)
        .execute(&mut *tx)
        .await?;
        if o.ok {
            if let ResponseAction::QuarantineFile { path, sha256 } = &o.action {
                upsert_quarantine(
                    &mut tx,
                    device_id,
                    Some(alert.id),
                    path,
                    sha256.as_deref(),
                    o.artifact.as_deref(),
                    &o.detail,
                )
                .await?;
            }
        }
    }

    sqlx::query("INSERT INTO incident_activity (incident_id, ts, kind, title, detail) VALUES ($1,$2,'alert',$3,$4)")
        .bind(incident_id)
        .bind(alert.ts)
        .bind(format!(
            "{} ({})",
            plain(&alert.rule_name, 160),
            plain(&alert.rule_id, 64)
        ))
        .bind(plain(&alert.summary, 2000))
        .execute(&mut *tx)
        .await?;

    let user = alert.process.user.clone().or(logged_on);
    for seed in checklist_for(&alert, &hostname, user.as_deref()) {
        insert_checklist(&mut tx, incident_id, &seed).await?;
    }
    for o in alert.actions.iter().filter(|o| o.ok) {
        supersede_approvals(&mut tx, incident_id, &o.action).await?;
    }
    count_ioc_hits(&mut tx, &alert).await?;
    recompute_incident(&mut tx, incident_id).await?;
    tx.commit().await?;

    state.publish("alert", alert.id, "created");
    state.publish(
        "incident",
        incident_id,
        if created { "created" } else { "updated" },
    );
    state.notifier.submit(NotifyJob {
        alert: alert.clone(),
        device_id,
        hostname,
        incident_id,
        incident_created: created,
    });
    Ok(IngestOutcome {
        incident_id: Some(incident_id),
        incident_created: created,
        duplicate: false,
    })
}

pub async fn insert_checklist(
    tx: &mut Transaction<'_, Postgres>,
    incident_id: Uuid,
    seed: &ChecklistSeed,
) -> anyhow::Result<()> {
    let base = match seed.kind {
        "done" => 0,
        "approve" => 1_000_000,
        _ => 2_000_000,
    };
    sqlx::query(
        "INSERT INTO incident_checklist (id, incident_id, position, kind, text, done, action, dedupe_key, done_at) \
         VALUES ($1, $2, $3 + (SELECT count(*) FROM incident_checklist WHERE incident_id = $2), $4, $5, $6, $7, $8, $9) \
         ON CONFLICT (incident_id, dedupe_key) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(incident_id)
    .bind(base)
    .bind(seed.kind)
    .bind(&seed.text)
    .bind(seed.done)
    .bind(seed.action.as_ref().map(serde_json::to_value).transpose()?)
    .bind(&seed.key)
    .bind(if seed.done { Some(now_ms()) } else { None })
    .execute(&mut **tx)
    .await?;
    Ok(())
}

fn id_chars(s: &str) -> String {
    s.chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}

/// An action that already succeeded closes the matching one-click approval.
pub async fn supersede_approvals(
    tx: &mut Transaction<'_, Postgres>,
    incident_id: Uuid,
    action: &ResponseAction,
) -> anyhow::Result<()> {
    // Kill approvals match any process of the incident; others match exactly.
    let (cond, key) = match action {
        ResponseAction::KillProcess { .. } => {
            ("starts_with(dedupe_key, $2)", "approve:kill:".to_string())
        }
        other => ("dedupe_key = $2", format!("approve:{}", action_key(other))),
    };
    sqlx::query(&format!(
        "UPDATE incident_checklist SET done = true, done_at = $3 WHERE incident_id = $1 AND kind = 'approve' AND NOT done AND {cond}"
    ))
    .bind(incident_id)
    .bind(key)
    .bind(now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Parse the quarantine id an agent reports in `ActionOutcome.detail`. The agent
/// writes `quarantined <path> as <id> (…)` or `already quarantined as <id>; …`;
/// `{"quarantine_id": "..."}` JSON, `quarantine_id=<id>` and a bare id are accepted too.
pub fn quarantine_id_from_detail(detail: &str, path: &str, fallback_seed: &str) -> String {
    for marker in [format!("{path} as "), "already quarantined as ".to_string()] {
        if let Some(i) = detail.find(&marker) {
            let id = id_chars(&detail[i + marker.len()..]);
            if !id.is_empty() {
                return id;
            }
        }
    }
    if detail.starts_with("quarantined ") || detail.contains(": quarantined ") {
        if let Some(i) = detail.rfind(" as ") {
            let id = id_chars(&detail[i + 4..]);
            if !id.is_empty() {
                return id;
            }
        }
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(detail) {
        if let Some(id) = v.get("quarantine_id").and_then(|x| x.as_str()) {
            return id.to_string();
        }
    }
    if let Some(rest) = detail.split("quarantine_id=").nth(1) {
        let id: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if !id.is_empty() {
            return id;
        }
    }
    let d = detail.trim();
    if !d.is_empty()
        && d.len() <= 64
        && d.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return d.to_string();
    }
    crate::crypto::sha256_hex(fallback_seed)[..32].to_string()
}

/// Quarantine id of a successful `QuarantineFile`: the structured
/// `ActionOutcome.artifact` when the agent sent one, else parsed from `detail`.
pub fn quarantine_id(artifact: Option<&str>, detail: &str, path: &str, seed: &str) -> String {
    if let Some(a) = artifact.map(str::trim) {
        let id = id_chars(a);
        if !id.is_empty() && id.len() == a.len() && id.len() <= 128 {
            return id;
        }
    }
    quarantine_id_from_detail(detail, path, seed)
}

pub async fn upsert_quarantine(
    tx: &mut Transaction<'_, Postgres>,
    device_id: Uuid,
    alert_id: Option<Uuid>,
    path: &str,
    sha256: Option<&str>,
    artifact: Option<&str>,
    detail: &str,
) -> anyhow::Result<()> {
    let id = quarantine_id(
        artifact,
        detail,
        path,
        &format!("{device_id}|{path}|{}", sha256.unwrap_or("")),
    );
    let now = now_ms();
    sqlx::query(
        "INSERT INTO quarantine_items (id, device_id, sha256, original_path, alert_id, state, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,'held',$6,$6) ON CONFLICT (id) DO UPDATE SET state = 'held', updated_at = EXCLUDED.updated_at",
    )
    .bind(id)
    .bind(device_id)
    .bind(sha256.map(|s| s.to_ascii_lowercase()))
    .bind(path)
    .bind(alert_id)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn count_ioc_hits(tx: &mut Transaction<'_, Postgres>, alert: &Alert) -> anyhow::Result<()> {
    let mut values: Vec<String> = vec![];
    if let Some(h) = &alert.process.sha256 {
        values.push(h.to_ascii_lowercase());
    }
    if let Some(s) = &alert.process.signer {
        values.push(s.to_ascii_lowercase());
    }
    for e in &alert.evidence {
        match &e.data {
            EventData::NetConnect {
                dst_ip, dst_host, ..
            } => {
                values.push(dst_ip.to_ascii_lowercase());
                if let Some(h) = dst_host {
                    values.push(h.to_ascii_lowercase());
                }
            }
            EventData::DnsQuery { qname, .. } => values.push(qname.to_ascii_lowercase()),
            EventData::ProcessStart(p) => {
                if let Some(h) = &p.sha256 {
                    values.push(h.to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    if values.is_empty() {
        return Ok(());
    }
    values.sort();
    values.dedup();
    sqlx::query("UPDATE iocs SET hits = hits + 1 WHERE lower(value) = ANY($1)")
        .bind(&values)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Recompute aggregates, title, priority and storyline from the incident's alerts.
pub async fn recompute_incident(
    tx: &mut Transaction<'_, Postgres>,
    incident_id: Uuid,
) -> anyhow::Result<()> {
    let bodies: Vec<(serde_json::Value,)> =
        sqlx::query_as("SELECT body FROM alerts WHERE incident_id = $1 ORDER BY ts")
            .bind(incident_id)
            .fetch_all(&mut **tx)
            .await?;
    let alerts: Vec<Alert> = bodies
        .into_iter()
        .filter_map(|(b,)| serde_json::from_value(b).ok())
        .collect();
    if alerts.is_empty() {
        return Ok(());
    }
    let (root, hostname, user_name): (String, String, Option<String>) = sqlx::query_as(
        "SELECT i.root_guid, d.hostname, i.user_name FROM incidents i JOIN devices d ON d.id = i.device_id WHERE i.id = $1",
    )
    .bind(incident_id)
    .fetch_one(&mut **tx)
    .await?;
    let (contained,): (bool,) = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM response_actions WHERE incident_id = $1 AND status = 'succeeded' AND action_type = ANY($2))",
    )
    .bind(incident_id)
    .bind(CONTAINING_TYPES.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    .fetch_one(&mut **tx)
    .await?;
    let blocked: Vec<(serde_json::Value,)> = sqlx::query_as(
        "SELECT action FROM response_actions WHERE incident_id = $1 AND status = 'succeeded' AND action_type = 'block_destination'",
    )
    .bind(incident_id)
    .fetch_all(&mut **tx)
    .await?;
    let blocked: Vec<String> = blocked
        .into_iter()
        .filter_map(|(a,)| a.get("ip").and_then(|i| i.as_str()).map(String::from))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let contained = contained
        || alerts
            .iter()
            .flat_map(|a| a.actions.iter())
            .any(|o| o.ok && containing(&o.action));
    let s = summarize(&alerts, &root, &hostname, contained, &blocked);
    if let Some(img) = &s.origin_image {
        if alerts.iter().any(|a| {
            ["ST-", "RW-", "CD-", "PS-"]
                .iter()
                .any(|p| a.rule_id.starts_with(p))
        }) {
            let seed = origin_seed(img, s.user.as_deref().or(user_name.as_deref()));
            insert_checklist(tx, incident_id, &seed).await?;
            // Keep the text on the incident's subject as later alerts refine it.
            sqlx::query("UPDATE incident_checklist SET text = $3 WHERE incident_id = $1 AND dedupe_key = $2 AND NOT done")
                .bind(incident_id)
                .bind(&seed.key)
                .bind(&seed.text)
                .execute(&mut **tx)
                .await?;
        }
    }
    sqlx::query(
        "UPDATE incidents SET title = $2, severity = $3, severity_rank = $4, priority = $5, storyline = $6, alert_count = $7, \
         rule_ids = $8, attack = $9, data_at_risk = $10, contained = $11, first_alert_at = $12, last_alert_at = $13, \
         user_name = COALESCE(user_name, $14), updated_at = $15 WHERE id = $1",
    )
    .bind(incident_id)
    .bind(&s.title)
    .bind(s.severity.as_str())
    .bind(severity_rank(s.severity))
    .bind(s.priority)
    .bind(&s.storyline)
    .bind(alerts.len() as i32)
    .bind(&s.rule_ids)
    .bind(&s.attack)
    .bind(&s.data_at_risk)
    .bind(contained)
    .bind(s.first)
    .bind(s.last)
    .bind(s.user.or(user_name))
    .bind(now_ms())
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// Server-side synthetic process for tamper alerts raised from heartbeat analysis.
pub fn agent_process(now: i64) -> ProcessInfo {
    ProcessInfo {
        guid: kestrel_common::ProcessGuid("kestrel-agent".into()),
        pid: 0,
        ppid: 0,
        parent_guid: None,
        image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
        cmdline: String::new(),
        user: Some("NT AUTHORITY\\SYSTEM".into()),
        integrity: None,
        start_ts: now,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unknown,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: PathClass::ProgramFiles,
    }
}

pub fn server_tamper_alert(
    rule_id: &str,
    name: &str,
    severity: Severity,
    summary: String,
) -> Alert {
    let now = now_ms();
    Alert {
        id: Uuid::new_v4(),
        ts: now,
        rule_id: rule_id.into(),
        rule_name: name.into(),
        rule_author: Some("Kestrel server".into()),
        severity,
        attack: vec!["T1562.001".into()],
        mode: kestrel_common::RuleMode::Audit,
        summary,
        process: agent_process(now),
        ancestry: vec![],
        data_at_risk: vec![],
        evidence: vec![],
        actions: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{Event, ProcessGuid, RuleMode};

    fn proc(guid: &str, image: &str, parent: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            guid: ProcessGuid(guid.into()),
            pid: 100,
            ppid: 1,
            parent_guid: parent.map(|p| ProcessGuid(p.into())),
            image: image.into(),
            cmdline: image.into(),
            user: Some("CORP\\alice".into()),
            integrity: None,
            start_ts: 1,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: Some("AB".into()),
            motw_zone: Some(3),
            file_size: None,
            path_class: PathClass::of(image),
        }
    }

    pub fn sample_alert(rule: &str, sev: Severity) -> Alert {
        Alert {
            id: Uuid::new_v4(),
            ts: 1_760_000_000_000,
            rule_id: rule.into(),
            rule_name: "Browser credential store read".into(),
            rule_author: None,
            severity: sev,
            attack: vec!["T1555.003".into()],
            mode: RuleMode::Protect,
            summary: "setup_x64.exe read Chrome Login Data".into(),
            process: proc("p3", r"C:\Windows\System32\cmd.exe", Some("p2")),
            ancestry: vec![
                proc("p2", r"C:\Users\alice\Downloads\setup_x64.exe", Some("p1")),
                proc("p1", r"C:\Windows\explorer.exe", None),
            ],
            data_at_risk: vec![DataCategory::BrowserPasswords],
            evidence: vec![Event {
                ts: 1_760_000_000_000,
                pid: 100,
                guid: ProcessGuid("p3".into()),
                data: EventData::NetConnect {
                    proto: kestrel_common::NetProto::Tcp,
                    dst_ip: "203.0.113.7".into(),
                    dst_port: 443,
                    src_port: 5000,
                    dst_host: Some("api.telegram.org".into()),
                    bytes_sent: Some(2_200_000),
                },
            }],
            actions: vec![],
        }
    }

    #[test]
    fn root_is_topmost_non_system() {
        let a = sample_alert("ST-04", Severity::High);
        assert_eq!(root_guid(&a), "p2");
        let mut sys = a.clone();
        sys.ancestry = vec![];
        assert_eq!(root_guid(&sys), "p3");
    }

    #[test]
    fn quarantine_ids() {
        let p = r"C:\Users\a b\x as y.exe";
        assert_eq!(
            quarantine_id_from_detail(
                &format!("quarantined {p} as 0f3a-12 (sha256 ab, 3 bytes); ok"),
                p,
                "s"
            ),
            "0f3a-12"
        );
        assert_eq!(
            quarantine_id_from_detail("already quarantined as q-0002; same hash", p, "s"),
            "q-0002"
        );
        assert_eq!(
            quarantine_id_from_detail(&format!("simulated: quarantined {p} as q-0001"), p, "s"),
            "q-0001"
        );
        assert_eq!(
            quarantine_id_from_detail(r#"{"quarantine_id":"abc"}"#, p, "s"),
            "abc"
        );
        assert_eq!(quarantine_id_from_detail("", p, "s").len(), 32);
    }

    #[test]
    fn priority_model() {
        assert_eq!(priority(Severity::High, true, true, false), 95);
        assert_eq!(priority(Severity::Critical, true, true, false), 100);
        assert_eq!(priority(Severity::Medium, false, false, true), 45);
    }

    #[test]
    fn title_and_checklist() {
        let a = sample_alert("ST-04", Severity::High);
        let s = summarize(std::slice::from_ref(&a), "p2", "FIN-LAPTOP-07", false, &[]);
        assert_eq!(
            s.title,
            "Credential theft by setup_x64.exe on FIN-LAPTOP-07"
        );
        assert!(s.storyline.contains("setup_x64.exe"));
        assert!(s.storyline.contains("203.0.113.7"));
        assert_eq!(s.priority, 95);
        let items = checklist_for(&a, "FIN-LAPTOP-07", Some("alice"));
        assert!(items
            .iter()
            .any(|i| i.kind == "approve" && i.text == "Isolate host FIN-LAPTOP-07"));
        assert!(items
            .iter()
            .any(|i| i.kind == "approve" && i.text == "Block destination 203.0.113.7"));
        assert!(items
            .iter()
            .any(|i| i.kind == "manual" && i.text.starts_with("Rotate every password")));
        // Never isolated → no release step.
        assert!(!items.iter().any(|i| i.key == "approve:release"));
        let mut iso = a.clone();
        iso.actions.push(ActionOutcome {
            action: ResponseAction::IsolateHost { allow_ips: vec![] },
            ok: true,
            detail: String::new(),
            ts: 1,
            artifact: None,
        });
        let items = checklist_for(&iso, "FIN-LAPTOP-07", Some("alice"));
        assert!(items.iter().any(|i| i.key == "approve:release"));
        assert!(!items.iter().any(|i| i.key == "approve:isolate"));
    }

    #[test]
    fn clickfix_story_names_payload_not_explorer() {
        // ST-10 alert on explorer.exe (RunMRU), later ST-01 by the payload whose
        // ancestry is explorer → powershell → vcredist_x64.exe.
        let mut first = sample_alert("ST-10", Severity::High);
        first.process = proc("e", r"C:\Windows\explorer.exe", None);
        first.process.signed = SignatureState::Valid;
        first.process.signer = Some("Microsoft Windows".into());
        first.ancestry = vec![];
        first.data_at_risk = vec![];
        let mut second = sample_alert("ST-01", Severity::Critical);
        second.ts += 5_000;
        second.process = proc(
            "v",
            r"C:\Users\jd\AppData\Local\Temp\vcredist_x64.exe",
            Some("ps"),
        );
        second.ancestry = vec![
            proc(
                "ps",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                Some("e"),
            ),
            proc("e", r"C:\Windows\explorer.exe", None),
        ];
        let alerts = vec![first, second];
        let s = summarize(&alerts, "e", "E2E-LUMMA-01", false, &[]);
        assert!(s.title.contains("vcredist_x64.exe"), "{}", s.title);
        assert!(
            s.storyline.starts_with("`vcredist_x64.exe`"),
            "{}",
            s.storyline
        );
        assert_eq!(s.origin_image.as_deref(), Some("vcredist_x64.exe"));
        // The explorer alert alone contributes no origin step naming explorer.
        let items = checklist_for(&alerts[0], "E2E-LUMMA-01", Some("CORP\\j.doe"));
        assert!(!items
            .iter()
            .any(|i| i.text.contains("explorer.exe came from")));
        assert!(origin_seed("vcredist_x64.exe", Some("CORP\\j.doe"))
            .text
            .contains("where vcredist_x64.exe came from"));
    }

    #[test]
    fn quarantine_artifact_preferred() {
        assert_eq!(
            quarantine_id(Some("q-77"), "quarantined x as other", "x", "s"),
            "q-77"
        );
        // Garbage artifact → fall back to detail parsing.
        assert_eq!(
            quarantine_id(Some("../../x"), "quarantined x as q-1", "x", "s"),
            "q-1"
        );
        assert_eq!(quarantine_id(None, "quarantined x as q-1", "x", "s"), "q-1");
    }

    fn ev(data: EventData) -> Event {
        Event {
            ts: 1_760_000_000_000,
            pid: 100,
            guid: ProcessGuid("p3".into()),
            data,
        }
    }

    #[test]
    fn ransomware_story_priority_and_steps() {
        let mut a = sample_alert("RW-06", Severity::Critical);
        a.rule_name = "Mass file encryption".into();
        a.summary = "update.exe encrypted user files".into();
        a.data_at_risk = vec![];
        a.evidence = vec![ev(EventData::FileActivity(kestrel_common::FileActivity {
            window_ms: 10_000,
            files_touched: 430,
            dirs: 37,
            renames: 412,
            ext_changes: 400,
            top_new_ext: Some("k3str".into()),
            top_ext_pct: 95,
            note_name: Some("readme_k3str.txt".into()),
            note_dirs: 37,
            net_paths: 12,
            ..Default::default()
        }))];
        let s = summarize(std::slice::from_ref(&a), "p2", "FIN-LT-003", false, &[]);
        assert_eq!(
            s.title,
            "Ransomware activity by setup_x64.exe on FIN-LT-003"
        );
        assert!(
            s.storyline.contains(
                "renamed 412 files in 37 folders within 10 s, new extension `.k3str` (95%)"
            ),
            "{}",
            s.storyline
        );
        assert!(s.storyline.contains("readme_k3str.txt"));
        assert!(s.storyline.contains("do not pay"));
        // critical 90 + impact 10 + not contained 5 → capped at 100
        assert_eq!(s.priority, 100);
        let mut high = a.clone();
        high.severity = Severity::High;
        let s = summarize(std::slice::from_ref(&high), "p2", "H", true, &[]);
        assert_eq!(s.priority, 80, "high 70 + impact 10");
        let items = checklist_for(&a, "FIN-LT-003", Some("alice"));
        assert!(items.iter().any(|i| i.key == "manual:rw:backups"));
        assert!(items
            .iter()
            .any(|i| i.key == "manual:rw:note" && i.text.contains("readme_k3str.txt")));
        assert!(items.iter().any(|i| i.key == "approve:isolate"));
    }

    #[test]
    fn credential_dumping_story_and_steps() {
        let mut a = sample_alert("CD-06", Severity::High);
        a.data_at_risk = vec![];
        a.evidence = vec![ev(EventData::ProcessAccess(
            kestrel_common::TargetProcess {
                target_pid: 700,
                target_guid: None,
                target_image: r"C:\Windows\System32\lsass.exe".into(),
                granted_access: 0x1fffff,
                return_code: 0xC000_0022,
            },
        ))];
        let s = summarize(std::slice::from_ref(&a), "p2", "SRV-01", false, &[]);
        assert_eq!(s.title, "Credential dumping by setup_x64.exe on SRV-01");
        assert!(s.storyline.contains("`0x1fffff`"), "{}", s.storyline);
        assert!(s.storyline.contains("0xc0000022"), "{}", s.storyline);
        assert!(s.storyline.contains("as **compromised**"));
        assert_eq!(s.priority, 85);
        let items = checklist_for(&a, "SRV-01", None);
        for k in ["manual:cd:reset", "manual:cd:service", "manual:cd:lateral"] {
            assert!(items.iter().any(|i| i.key == k), "{k}");
        }
    }

    #[test]
    fn persistence_removals() {
        let mut a = sample_alert("PS-05", Severity::High);
        a.data_at_risk = vec![];
        a.evidence = vec![
            ev(EventData::TaskRegistered(kestrel_common::TaskChange {
                attribution: Default::default(),
                name: r"\OneDrive Updater".into(),
                op: TaskOp::Created,
                actions: vec![r#""C:\Users\a\AppData\Roaming\u.exe" -s"#.into()],
                hidden: true,
                triggers: vec!["logon".into()],
                user: None,
            })),
            ev(EventData::RegistrySet {
                attribution: Default::default(),
                key: r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run".into(),
                value_name: "Updater".into(),
                data: Some(r"C:\Users\a\u.exe".into()),
                op: RegistryOp::Set,
            }),
            ev(EventData::RegistrySet {
                attribution: Default::default(),
                key: r"HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest".into(),
                value_name: "UseLogonCredential".into(),
                data: Some("1".into()),
                op: RegistryOp::Set,
            }),
            ev(EventData::ServiceInstalled(
                kestrel_common::ServiceInstall {
                    name: "KestrelAgent".into(),
                    image_path: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
                    ..Default::default()
                },
            )),
            ev(EventData::RegistrySet {
                attribution: Default::default(),
                key: r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon".into(),
                value_name: "Userinit".into(),
                data: Some("x".into()),
                op: RegistryOp::Set,
            }),
        ];
        let t = autorun_targets(&a);
        assert!(matches!(
            &t[0].1,
            Some(ResponseAction::RemoveAutorun { kind: AutorunKind::ScheduledTask, location, .. }) if location == r"\OneDrive Updater"
        ));
        assert!(matches!(
            &t[1].1,
            Some(ResponseAction::RemoveAutorun { kind: AutorunKind::RegistryValue, value_name: Some(v), restore_data: None, .. }) if v == "Updater"
        ));
        assert!(matches!(
            &t[2].1,
            Some(ResponseAction::RemoveAutorun { restore_data: Some(d), .. }) if d == "dword:0"
        ));
        // Never offers to remove Kestrel's own service; Winlogon is manual only.
        assert!(t[3].1.is_none());
        assert!(t[4].1.is_none());
        let s = summarize(std::slice::from_ref(&a), "p2", "HR-LT-1", false, &[]);
        assert_eq!(s.title, "Persistence planted by setup_x64.exe on HR-LT-1");
        assert!(s
            .storyline
            .contains(r"scheduled task `\OneDrive Updater` created (hidden, runs at logon)"));
        assert!(s.storyline.contains("still in place"));
        let items = checklist_for(&a, "HR-LT-1", None);
        assert!(items.iter().any(|i| i.kind == "approve"
            && i.text
                .starts_with(r"Remove scheduled task \OneDrive Updater")));
        assert!(items.iter().any(
            |i| i.kind == "approve" && matches!(i.action, Some(ResponseAction::CollectTriage))
        ));

        // Protect mode removed the task: done item names the backup, no approval left.
        let mut done = a.clone();
        done.actions.push(ActionOutcome {
            action: ResponseAction::RemoveAutorun {
                kind: AutorunKind::ScheduledTask,
                location: r"\OneDrive Updater".into(),
                value_name: None,
                restore_data: None,
            },
            ok: true,
            detail: "task exported and deleted".into(),
            ts: 2,
            artifact: Some("q-77".into()),
        });
        let items = checklist_for(&done, "HR-LT-1", None);
        assert!(items
            .iter()
            .any(|i| i.kind == "done" && i.text.contains("backup q-77")));
        assert!(!items
            .iter()
            .any(|i| i.kind == "approve" && i.text.contains("OneDrive Updater")));
        let s = summarize(std::slice::from_ref(&done), "p2", "HR-LT-1", false, &[]);
        assert!(s.storyline.contains("`q-77`"), "{}", s.storyline);
    }

    #[test]
    fn endpoint_text_cannot_inject_markdown() {
        // V-M6: link / quote / emphasis injection through task, service,
        // registry, WMI, file-activity fields and the alert summary.
        let mut a = sample_alert("PS-05", Severity::High);
        a.data_at_risk = vec![];
        a.summary = "x [Kestrel: re-authenticate](https://evil.example/sso)\n> **Verified benign by Kestrel**".into();
        let link = "x` [Kestrel: re-authenticate to view evidence](https://evil.example/sso) `y";
        a.evidence = vec![
            ev(EventData::TaskRegistered(kestrel_common::TaskChange {
                name: format!("\\{link}"),
                op: TaskOp::Created,
                actions: vec![link.into()],
                user: Some(link.into()),
                triggers: vec!["[x](https://evil.example)".into()],
                attribution: Attribution::Heuristic,
                ..Default::default()
            })),
            ev(EventData::ServiceInstalled(
                kestrel_common::ServiceInstall {
                    name: link.into(),
                    image_path: link.into(),
                    ..Default::default()
                },
            )),
            ev(EventData::RegistrySet {
                key: r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run".into(),
                value_name: link.into(),
                data: Some("a\n> **Verified benign by Kestrel**".into()),
                op: RegistryOp::Set,
                attribution: Attribution::None,
            }),
            ev(EventData::WmiSubscription(kestrel_common::WmiBinding {
                namespace: link.into(),
                filter: link.into(),
                consumer: link.into(),
                attribution: Attribution::Exact,
            })),
            ev(EventData::FileActivity(FileActivity {
                files_touched: 50,
                renames: 50,
                dirs: 3,
                top_new_ext: Some("`[x](https://evil.example)".into()),
                note_name: Some(link.into()),
                note_dirs: 3,
                remote_writer: true,
                ..Default::default()
            })),
        ];
        let s = summarize(
            std::slice::from_ref(&a),
            "p2",
            "HR\n> [pc](https://evil)",
            false,
            &[],
        );
        let st = &s.storyline;
        // No markdown link can survive: every `](` is escaped or inside a code span.
        for line in st.lines() {
            let mut in_code = false;
            let mut prev = ' ';
            let chars: Vec<char> = line.chars().collect();
            for (i, c) in chars.iter().enumerate() {
                if *c == '`' && prev != '\\' {
                    in_code = !in_code;
                }
                if !in_code && *c == ']' && chars.get(i + 1) == Some(&'(') {
                    assert_eq!(prev, '\\', "unescaped link in: {line}");
                }
                prev = *c;
            }
            assert!(!in_code, "unbalanced code span in: {line}");
            // Only the server's own fixed callouts start a quote.
            if line.starts_with('>') {
                assert!(line.starts_with("> Treat"), "{line}");
            }
        }
        assert!(!s.title.contains('\n'));
        assert!(st.contains("(writer inferred)") && st.contains("(writer unknown)"));
        assert!(st.contains("remote client over SMB"));
    }

    #[test]
    fn restore_described_only_for_canonical_default() {
        let wl = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".to_string();
        let act = |d: &str| ResponseAction::RemoveAutorun {
            kind: AutorunKind::RegistryValue,
            location: wl.clone(),
            value_name: Some("Userinit".into()),
            restore_data: Some(d.into()),
        };
        assert!(describe_action(&act(r"C:\Windows\system32\userinit.exe,"))
            .starts_with("restored the Windows default value"));
        let evil = describe_action(&act(r"C:\Windows\system32\userinit.exe,\\host\s\x.exe"));
        assert!(evil.starts_with("wrote \""), "{evil}");
        // A non-allow-listed failed outcome reported by an agent is never
        // offered for one-click retry.
        let mut a = sample_alert("PS-10", Severity::High);
        a.actions.push(ActionOutcome {
            action: ResponseAction::RemoveAutorun {
                kind: AutorunKind::RegistryValue,
                location: r"HKLM\SYSTEM\CurrentControlSet\Services\Sense".into(),
                value_name: Some("Start".into()),
                restore_data: Some("dword:4".into()),
            },
            ok: false,
            detail: "x".into(),
            ts: 0,
            artifact: None,
        });
        let items = checklist_for(&a, "pc", None);
        assert!(!items
            .iter()
            .any(|i| matches!(i.action, Some(ResponseAction::RemoveAutorun { .. }))));
        // Service ImagePath writes are never offered from evidence.
        let mut b = sample_alert("PS-05", Severity::High);
        b.evidence = vec![ev(EventData::RegistrySet {
            key: r"HKLM\SYSTEM\CurrentControlSet\Services\Spooler".into(),
            value_name: "ImagePath".into(),
            data: Some("cmd /c x".into()),
            op: RegistryOp::Set,
            attribution: Attribution::Exact,
        })];
        assert!(autorun_targets(&b)[0].1.is_none());
    }

    #[test]
    fn families_from_rule_ids() {
        let f = Families::of(["ST-01", "PS-02"]);
        assert!(f.persistence && !f.ransomware && !f.impact_stage());
        assert!(Families::of(["CD-01"]).impact_stage());
        assert_eq!(
            quoted_name(r#"CommandLineEventConsumer="evil" cmd"#).as_deref(),
            Some("evil")
        );
        assert_eq!(quoted_name("x"), None);
    }
}
