//! Server-side data hygiene applied to everything agents upload, as defence in
//! depth on top of the agent's own privacy filter:
//!
//! * M6: enrollment / uninstall secrets that leak into command lines (MSI
//!   `TOKEN=…`, `--token …`, `kte_…`, `kun_…`) are redacted before storage.
//! * M9: when the device's policy has `privacy.hash_usernames`, user names the
//!   server stores or shows (alert process/ancestry users, health
//!   `logged_on_user`, review-request users) are pseudonymised.

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

fn scrub_process(p: &mut ProcessInfo, users: Option<&MasterKey>) {
    redact_in_place(&mut p.cmdline);
    if let (Some(mk), Some(u)) = (users, p.user.as_mut()) {
        *u = mk.hash_username(u);
    }
}

/// Telemetry event: secrets out of command lines and script blocks.
pub fn scrub_event(e: &mut Event, users: Option<&MasterKey>) {
    match &mut e.data {
        EventData::ProcessStart(ps) => {
            redact_in_place(&mut ps.cmdline);
            if let (Some(mk), Some(u)) = (users, ps.user.as_mut()) {
                *u = mk.hash_username(u);
            }
        }
        EventData::ScriptBlock { content, .. } => redact_in_place(content),
        EventData::RegistrySet { data: Some(d), .. } => redact_in_place(d),
        _ => {}
    }
}

/// Alert: process, ancestry, evidence and summary. `users` = hash user names.
pub fn scrub_alert(a: &mut Alert, users: Option<&MasterKey>) {
    scrub_process(&mut a.process, users);
    for p in a.ancestry.iter_mut() {
        scrub_process(p, users);
    }
    for e in a.evidence.iter_mut() {
        scrub_event(e, users);
    }
    redact_in_place(&mut a.summary);
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
        scrub_alert(&mut a, Some(&mk));
        assert!(crate::crypto::is_pseudonym(
            a.process.user.as_deref().unwrap()
        ));
        assert!(!a.process.cmdline.contains("abcdefgh"));
        assert!(!a.summary.contains("abcdef0123"));
        let mut b = a.clone();
        scrub_alert(&mut b, None);
        assert_eq!(a.process.user, b.process.user);
    }
}
