//! Server-side data hygiene applied to everything agents upload, as defence in
//! depth on top of the agent's own privacy filter:
//!
//! * M6: enrollment / uninstall secrets that leak into command lines (MSI
//!   `TOKEN=…`, `--token …`, `kte_…`, `kun_…`) are redacted before storage.
//! * M9: when the device's policy has `privacy.hash_usernames`, user names the
//!   server stores or shows (alert process/ancestry users, health
//!   `logged_on_user`, review-request users) are pseudonymised.
//! * V-L5: every event kind gets the agent privacy filter's rules again —
//!   task principals, service accounts, task actions, service image paths,
//!   WMI filter/consumer text and registry data are hashed, truncated or
//!   prefix-redacted as the device's privacy policy says.

use crate::crypto::MasterKey;
use kestrel_common::{Alert, Event, EventData, ProcessInfo};

pub const REDACTED: &str = "[REDACTED]";

/// Token prefixes that are always secrets.
const SECRET_PREFIXES: &[&str] = &["kte_", "kun_", "kst_"];

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// Redact secrets in a command line or script text. Returns the input unchanged
/// (no allocation of a different value) when nothing matched.
pub fn redact_secrets(s: &str) -> String {
    let mut out = redact_prefixed(s);
    out = redact_after_key(&out);
    out
}

/// `kte_abc…` → `kte_[REDACTED]`.
fn redact_prefixed(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let rest = &s[i..];
        let boundary = i == 0 || !is_token_char(s[..i].chars().next_back().unwrap_or(' '));
        if boundary {
            if let Some(p) = SECRET_PREFIXES.iter().find(|p| {
                // Byte comparison: `rest` may start with multi-byte characters.
                rest.len() > p.len()
                    && rest.as_bytes()[..p.len()].eq_ignore_ascii_case(p.as_bytes())
            }) {
                let body: usize = rest[p.len()..]
                    .chars()
                    .take_while(|c| is_token_char(*c))
                    .map(char::len_utf8)
                    .sum();
                if body >= 4 {
                    out.push_str(&rest[..p.len()]);
                    out.push_str(REDACTED);
                    i += p.len() + body;
                    continue;
                }
            }
        }
        let Some(ch) = rest.chars().next() else {
            break;
        };
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Value after `…TOKEN=` (MSI property, env assignment) or `--…token[= ]` (CLI flag).
fn redact_after_key(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let Some(rel) = lower[i..].find("token") else {
            out.push_str(&s[i..]);
            break;
        };
        let start = i + rel;
        let end_kw = start + "token".len();
        out.push_str(&s[i..end_kw]);
        i = end_kw;
        // What precedes: `--token`, `--uninstall-token`, `TOKEN=`, `UNINSTALL_TOKEN=`.
        let before = &lower[..start];
        let is_flag = before
            .rsplit(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .next()
            .map(|w| w.starts_with('-') || w.starts_with('/'))
            .unwrap_or(false);
        let after = &s[i..];
        let (sep_len, quoted) = if let Some(r) = after.strip_prefix('=') {
            (1, r.starts_with('"') || r.starts_with('\''))
        } else if is_flag && after.starts_with([' ', ':']) {
            let ws: usize = after
                .chars()
                .take_while(|c| *c == ' ' || *c == ':')
                .map(char::len_utf8)
                .sum();
            let r = &after[ws..];
            (ws, r.starts_with('"') || r.starts_with('\''))
        } else {
            continue;
        };
        // Must be a key, not a word like "tokenizer".
        if after.starts_with(is_token_char) {
            continue;
        }
        out.push_str(&after[..sep_len]);
        let val = &after[sep_len..];
        let val_len = if quoted {
            let q = val.chars().next().unwrap_or('"');
            1 + val[1..].find(q).map(|p| p + 1).unwrap_or(val.len() - 1)
        } else {
            val.chars()
                .take_while(|c| !c.is_whitespace() && *c != '"' && *c != '\'' && *c != ';')
                .map(char::len_utf8)
                .sum()
        };
        if val_len == 0 || &val[..val_len] == REDACTED {
            i += sep_len;
            continue;
        }
        out.push_str(REDACTED);
        i += sep_len + val_len;
    }
    out
}

fn redact_in_place(s: &mut String) {
    let r = redact_secrets(s);
    if r != *s {
        *s = r;
    }
}

/// Privacy settings applied server-side (V-L5: the same rules as the agent's
/// privacy filter, as defence in depth for older or misbehaving agents).
#[derive(Clone, Copy)]
pub struct Scrub<'a> {
    /// Pseudonymise user names (`privacy.hash_usernames`).
    pub users: Option<&'a MasterKey>,
    /// Lower-case, `\`-normalised `privacy.redact_path_prefixes`.
    pub prefixes: &'a [String],
    /// `privacy.capture_cmdline`: when false, command lines (incl. task
    /// actions and service image paths) keep only the image and first flag.
    pub capture_cmdline: bool,
}

impl Scrub<'static> {
    /// Secret redaction only.
    pub const NONE: Scrub<'static> = Scrub {
        users: None,
        prefixes: &[],
        capture_cmdline: true,
    };
}

impl<'a> Scrub<'a> {
    pub fn user(&self, u: &mut String) {
        if let Some(mk) = self.users {
            *u = mk.hash_username(u);
        }
    }

    fn opt_user(&self, u: &mut Option<String>) {
        if let Some(u) = u.as_mut() {
            self.user(u);
        }
    }

    fn is_redacted(&self, s: &str) -> bool {
        if self.prefixes.is_empty() {
            return false;
        }
        let n = norm_path(s.trim_start_matches('"'));
        self.prefixes.iter().any(|p| n.starts_with(p.as_str()))
    }

    /// A path field: `[REDACTED]` when it starts with a redacted prefix.
    fn path(&self, p: &mut String) {
        if self.is_redacted(p) {
            *p = REDACTED.into();
        }
    }

    /// Free text that may embed paths: every redacted-prefix path is replaced.
    fn text(&self, t: &mut String) {
        for p in self.prefixes {
            let r = redact_prefixed_paths(t, p);
            if r != *t {
                *t = r;
            }
        }
    }

    /// A command line: secrets, optional truncation, path prefixes.
    fn cmdline(&self, c: &mut String) {
        redact_in_place(c);
        if !self.capture_cmdline {
            *c = truncate_cmdline(c);
        }
        if self.is_redacted(c) {
            *c = REDACTED.into();
        } else {
            self.text(c);
        }
    }
}

/// Normalised prefixes from a policy's privacy settings.
pub fn norm_prefixes(p: &kestrel_common::Privacy) -> Vec<String> {
    p.redact_path_prefixes
        .iter()
        .map(|x| norm_path(x))
        .filter(|x| !x.is_empty())
        .collect()
}

fn norm_path(p: &str) -> String {
    let p = p.replace('/', "\\").to_ascii_lowercase();
    p.trim_start_matches(r"\\?\").to_string()
}

/// Replace every path in `t` that starts with `prefix` (lower-case,
/// `\`-normalised) by `[REDACTED]`. The path ends at a quote, parenthesis,
/// comma, semicolon, line break or " — " (same rule as the agent).
fn redact_prefixed_paths(t: &str, prefix: &str) -> String {
    if prefix.is_empty() {
        return t.to_string();
    }
    // ASCII-only lower-casing keeps byte offsets identical to `t`.
    let lower = t.replace('/', "\\").to_ascii_lowercase();
    if lower.len() != t.len() || !lower.contains(prefix) {
        return t.to_string();
    }
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
        // Advance at least one whole character.
        let min = tail.chars().next().map(char::len_utf8).unwrap_or(1);
        i = start + end.max(min).min(tail.len());
    }
    out.push_str(&t[i..]);
    out
}

/// Keep the image and the first flag-like argument only (agent rule):
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
        Some(f) => {
            let f = f.split([':', '=']).next().unwrap_or(f);
            format!("{image} {f}")
        }
        None => image.to_string(),
    }
}

fn scrub_process(p: &mut ProcessInfo, sc: &Scrub) {
    sc.cmdline(&mut p.cmdline);
    sc.opt_user(&mut p.user);
    sc.path(&mut p.image);
}

/// Telemetry event: secrets out of command lines, script blocks, registry
/// data, task actions, service image paths and WMI text; user names hashed
/// and path prefixes redacted when the device's privacy policy says so.
pub fn scrub_event(e: &mut Event, sc: &Scrub) {
    match &mut e.data {
        EventData::ProcessStart(ps) => {
            sc.cmdline(&mut ps.cmdline);
            sc.opt_user(&mut ps.user);
            sc.path(&mut ps.image);
        }
        EventData::ImageLoad { path, .. } | EventData::FileAccess { path, .. } => sc.path(path),
        EventData::ScriptBlock { content, .. } => {
            redact_in_place(content);
            sc.text(content);
        }
        EventData::RegistrySet { data, .. } => {
            if let Some(d) = data.as_mut() {
                redact_in_place(d);
                sc.text(d);
            }
        }
        EventData::ProcessAccess(t)
        | EventData::RemoteThread(t)
        | EventData::ThreadContext(t)
        | EventData::DebugAttach(t) => sc.path(&mut t.target_image),
        EventData::FileActivity(f) => {
            for p in f.sample_paths.iter_mut().chain(f.canary_hits.iter_mut()) {
                sc.path(p);
            }
            f.sample_paths.retain(|p| p != REDACTED);
        }
        EventData::TaskRegistered(t) => {
            for a in t.actions.iter_mut() {
                sc.cmdline(a);
            }
            sc.opt_user(&mut t.user);
        }
        EventData::ServiceInstalled(s) => {
            sc.cmdline(&mut s.image_path);
            sc.opt_user(&mut s.account);
        }
        EventData::WmiSubscription(w) => {
            for t in [&mut w.consumer, &mut w.filter] {
                redact_in_place(t);
                sc.text(t);
            }
        }
        EventData::DnsQuery { .. }
        | EventData::NetConnect { .. }
        | EventData::ProcessStop { .. }
        | EventData::DpapiUnprotect { .. }
        | EventData::Tamper { .. } => {}
    }
}

/// Alert: process, ancestry, evidence and summary.
pub fn scrub_alert(a: &mut Alert, sc: &Scrub) {
    scrub_process(&mut a.process, sc);
    for p in a.ancestry.iter_mut() {
        scrub_process(p, sc);
    }
    for e in a.evidence.iter_mut() {
        scrub_event(e, sc);
    }
    redact_in_place(&mut a.summary);
    sc.text(&mut a.summary);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_and_cli_tokens() {
        let c = r#"msiexec.exe /i KestrelAgent.msi /qn SERVER=edr:8443 TOKEN=kte_AbCdEf123456 CA_B64=LS0t"#;
        let r = redact_secrets(c);
        assert!(!r.contains("AbCdEf123456"), "{r}");
        assert!(
            r.contains("SERVER=edr:8443") && r.contains("CA_B64=LS0t"),
            "{r}"
        );
        let c = r#""C:\Program Files\Kestrel\kestrel-agent.exe" install --token "secret value" --server x"#;
        let r = redact_secrets(c);
        assert!(
            !r.contains("secret value") && r.contains("--server x"),
            "{r}"
        );
        let r = redact_secrets("kestrel-agent.exe enroll --token=abcdef123 --x");
        assert!(!r.contains("abcdef123"), "{r}");
        let r = redact_secrets("kestrel-agent.exe uninstall --uninstall-token kun_zzzzzzzzzz");
        assert!(!r.contains("zzzzzzzzzz"), "{r}");
        let r = redact_secrets("UNINSTALL_TOKEN=hunter2hunter2 msiexec /x");
        assert!(!r.contains("hunter2"), "{r}");
        let r = redact_secrets("echo kte_0123456789abcdef");
        assert_eq!(r, "echo kte_[REDACTED]");
    }

    #[test]
    fn multibyte_text_never_panics() {
        for s in [
            "→ kte_ab",
            "é",
            "ké→",
            "setup.exe → api.telegram.org (2.1 MB) — TOKEN=ü",
            "日本語 --token 値 kte_日本語日本語",
            "ⓚⓣⓔ_abcdef",
            "x TOKEN=\"ü",
        ] {
            let _ = redact_secrets(s);
        }
        assert_eq!(redact_secrets("→ kte_abcdef →"), "→ kte_[REDACTED] →");
        // Pseudo-random mixes of keys, separators, quotes and multi-byte text.
        let parts = [
            "kte_", "kun_", "TOKEN", "token", "=", " ", "--", "-", "\"", "'", "é", "→", "日",
            "abc", "123", ":", ";",
        ];
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..20_000 {
            let mut t = String::new();
            for _ in 0..(x % 12) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                t.push_str(parts[(x % parts.len() as u64) as usize]);
            }
            x = x.wrapping_add(1);
            let _ = redact_secrets(&t);
        }
        assert_eq!(redact_secrets("ünïcode → fine"), "ünïcode → fine");
    }

    #[test]
    fn leaves_ordinary_text() {
        for s in [
            "python tokenizer.py --tokens 5",
            "notepad.exe C:\\docs\\token list.txt",
            "git log --oneline",
            "cmd /c set TOKENS",
            "",
        ] {
            assert_eq!(redact_secrets(s), s);
        }
        assert_eq!(redact_secrets("x TOKEN= y"), "x TOKEN= y");
    }

    #[test]
    fn alert_users_hashed() {
        let mk = MasterKey::new("0123456789abcdef0123456789abcdef");
        let mut a = crate::incidents::server_tamper_alert(
            "TP-X",
            "x",
            kestrel_common::Severity::Low,
            "ran setup --token kte_abcdef0123".into(),
        );
        a.process.user = Some("CORP\\alice".into());
        a.process.cmdline = "x.exe /TOKEN=kte_abcdefgh".into();
        let sc = Scrub {
            users: Some(&mk),
            ..Scrub::NONE
        };
        scrub_alert(&mut a, &sc);
        assert!(crate::crypto::is_pseudonym(
            a.process.user.as_deref().unwrap()
        ));
        assert!(!a.process.cmdline.contains("abcdefgh"));
        assert!(!a.summary.contains("abcdef0123"));
        let mut b = a.clone();
        scrub_alert(&mut b, &Scrub::NONE);
        assert_eq!(a.process.user, b.process.user);
    }

    #[test]
    fn persistence_events_follow_privacy_policy() {
        use kestrel_common::{
            Attribution, ProcessGuid, ServiceInstall, TaskChange, TaskOp, WmiBinding,
        };
        let mk = MasterKey::new("0123456789abcdef0123456789abcdef");
        let prefixes = vec![r"c:\users\alice\documents".to_string()];
        let sc = Scrub {
            users: Some(&mk),
            prefixes: &prefixes,
            capture_cmdline: false,
        };
        let ev = |data| Event {
            ts: 1,
            pid: 1,
            guid: ProcessGuid("g".into()),
            data,
        };
        let mut t = ev(EventData::TaskRegistered(TaskChange {
            name: r"\Updater".into(),
            op: TaskOp::Created,
            user: Some("CORP\\alice".into()),
            actions: vec![r#"powershell.exe -enc AAAA --token kte_secretsecret"#.into()],
            hidden: false,
            triggers: vec![],
            attribution: Attribution::Heuristic,
        }));
        scrub_event(&mut t, &sc);
        let EventData::TaskRegistered(tc) = &t.data else {
            unreachable!()
        };
        assert!(crate::crypto::is_pseudonym(tc.user.as_deref().unwrap()));
        assert_eq!(tc.actions[0], "powershell.exe -enc");
        let mut s = ev(EventData::ServiceInstalled(ServiceInstall {
            name: "x".into(),
            image_path: r#""C:\Users\alice\Documents\svc.exe" -k TOKEN=kun_zzzzzzzzzz"#.into(),
            start_type: Some(2),
            service_type: Some(16),
            account: Some("CORP\\svc_backup".into()),
            attribution: Attribution::Exact,
        }));
        scrub_event(&mut s, &sc);
        let EventData::ServiceInstalled(si) = &s.data else {
            unreachable!()
        };
        assert_eq!(si.image_path, REDACTED);
        assert!(crate::crypto::is_pseudonym(si.account.as_deref().unwrap()));
        let mut w = ev(EventData::WmiSubscription(WmiBinding {
            namespace: "root\\subscription".into(),
            filter: "SELECT * FROM x".into(),
            consumer:
                r#"CommandLineEventConsumer="c" C:\Users\alice\Documents\p.exe --token=abcdef123"#
                    .into(),
            attribution: Attribution::None,
        }));
        scrub_event(&mut w, &sc);
        let EventData::WmiSubscription(wb) = &w.data else {
            unreachable!()
        };
        assert!(
            !wb.consumer.contains("abcdef123") && !wb.consumer.contains("p.exe"),
            "{}",
            wb.consumer
        );
        let mut r = ev(EventData::RegistrySet {
            key: r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "x".into(),
            data: Some(r#"C:\Users\alice\Documents\a.exe /TOKEN=kte_abcdefgh"#.into()),
            op: Default::default(),
            attribution: Attribution::Exact,
        });
        scrub_event(&mut r, &sc);
        let EventData::RegistrySet { data: Some(d), .. } = &r.data else {
            unreachable!()
        };
        assert!(
            !d.contains("abcdefgh") && !d.to_ascii_lowercase().contains("documents"),
            "{d}"
        );
        // Without a policy only secrets are redacted.
        let mut t2 = ev(EventData::TaskRegistered(TaskChange {
            name: r"\U".into(),
            user: Some("bob".into()),
            actions: vec!["a.exe -x y".into()],
            ..Default::default()
        }));
        scrub_event(&mut t2, &Scrub::NONE);
        let EventData::TaskRegistered(tc) = &t2.data else {
            unreachable!()
        };
        assert_eq!(tc.user.as_deref(), Some("bob"));
        assert_eq!(tc.actions[0], "a.exe -x y");
        // Non-ASCII text never panics in the prefix redactor.
        let mut sb = ev(EventData::ScriptBlock {
            engine: "ps".into(),
            content: "日本 c:\\users\\alice\\documents\\x é".into(),
        });
        scrub_event(&mut sb, &sc);
    }
}
