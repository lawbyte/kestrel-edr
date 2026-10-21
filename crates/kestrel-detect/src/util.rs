//! Small helpers shared by the rules: IP classification, domain matching,
//! command-line tokenisation and plain-language process descriptions.

use crate::paths::{file_name, normalize_path};
use kestrel_common::{PathClass, ProcessInfo, SignatureState};
use std::net::IpAddr;

/// Normalised path without a drive letter (`c:\users\a` → `\users\a`), so that
/// Win32 paths and `\Device\HarddiskVolumeN` paths compare equal.
pub fn driveless(path: &str) -> String {
    let n = normalize_path(path);
    strip_drive(&n).to_string()
}

pub fn strip_drive(n: &str) -> &str {
    let b = n.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        &n[2..]
    } else {
        n
    }
}

/// True for routable public addresses (not loopback / RFC1918 / CGNAT /
/// link-local / multicast / unspecified / ULA). Unparseable → false.
pub fn is_external_ip(ip: &str) -> bool {
    match parse_ip(ip) {
        Some(IpAddr::V4(v4)) => is_external_v4(v4),
        Some(IpAddr::V6(v6)) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_external_v4(v4);
            }
            let seg0 = v6.segments()[0];
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (seg0 & 0xfe00) == 0xfc00 // ULA
                || (seg0 & 0xffc0) == 0xfe80) // link-local
        }
        None => false,
    }
}

fn is_external_v4(v4: std::net::Ipv4Addr) -> bool {
    let o = v4.octets();
    !(v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_multicast()
        || v4.is_broadcast()
        || v4.is_unspecified()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64)) // CGNAT 100.64/10
}

pub fn is_loopback_ip(ip: &str) -> bool {
    match parse_ip(ip) {
        Some(IpAddr::V4(v4)) => v4.is_loopback(),
        Some(IpAddr::V6(v6)) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v| v.is_loopback())
        }
        None => ip.eq_ignore_ascii_case("localhost"),
    }
}

pub fn parse_ip(ip: &str) -> Option<IpAddr> {
    let t = ip.trim().trim_start_matches('[').trim_end_matches(']');
    // strip IPv6 zone id
    let t = t.split('%').next().unwrap_or(t);
    t.parse().ok()
}

/// Normalise a domain / URL-ish policy entry to its host part:
/// `https://discord.com/api/webhooks` → `discord.com`, `*.r2.dev` → `r2.dev`.
pub fn entry_host(entry: &str) -> String {
    let e = entry.trim().to_ascii_lowercase();
    let e = e.split("://").nth(1).map(str::to_string).unwrap_or(e);
    let host = e.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.rsplit('@').next().unwrap_or(host);
    let host = if host.starts_with('[') {
        host
    } else {
        host.split(':').next().unwrap_or(host)
    };
    host.trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_string()
}

/// `host` equals `suffix` or is a subdomain of it (both lower-case, no trailing dot).
pub fn host_matches(host: &str, suffix: &str) -> bool {
    if suffix.is_empty() {
        return false;
    }
    let host = host.trim_end_matches('.');
    host.len() >= suffix.len()
        && host.ends_with(suffix)
        && (host.len() == suffix.len() || host.as_bytes()[host.len() - suffix.len() - 1] == b'.')
}

/// Whole-word containment (neighbours are not ASCII alphanumerics). `hay` and `w` lower-case.
pub fn contains_word(hay: &str, w: &str) -> bool {
    let hb = hay.as_bytes();
    let mut start = 0;
    while let Some(i) = hay[start..].find(w) {
        let s = start + i;
        let e = s + w.len();
        let before_ok = s == 0 || !hb[s - 1].is_ascii_alphanumeric();
        let after_ok = e >= hb.len() || !hb[e].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        start = s + 1;
        if start >= hay.len() {
            break;
        }
    }
    false
}

/// Strip PowerShell / cmd parameter prefixes (`-`, `/`, en/em dashes).
fn strip_param_prefix(t: &str) -> Option<&str> {
    let mut chars = t.chars();
    match chars.next() {
        Some('-') | Some('/') | Some('\u{2013}') | Some('\u{2014}') | Some('\u{2015}') => {
            Some(chars.as_str().trim_start_matches('-'))
        }
        _ => None,
    }
}

/// PowerShell-style hidden window: `-w h`, `-win hidden`, `-WindowStyle 1`, …
pub fn has_hidden_window(cmd_lower: &str) -> bool {
    let toks: Vec<&str> = cmd_lower.split_whitespace().collect();
    for (i, t) in toks.iter().enumerate() {
        if let Some(p) = strip_param_prefix(t) {
            if !p.is_empty() && "windowstyle".starts_with(p) {
                if let Some(next) = toks.get(i + 1) {
                    let v = next.trim_matches(|c| c == '"' || c == '\'');
                    if v.starts_with('h') || v == "1" {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// PowerShell `-EncodedCommand` (any unambiguous prefix, incl. `-e`, `-ec`).
pub fn has_encoded_command(cmd_lower: &str) -> bool {
    cmd_lower.split_whitespace().any(|t| {
        strip_param_prefix(t)
            .is_some_and(|p| !p.is_empty() && (p == "ec" || "encodedcommand".starts_with(p)))
    })
}

/// Does the command line carry any arguments after the image?
pub fn has_arguments(cmdline: &str) -> bool {
    let c = cmdline.trim();
    let rest = if let Some(stripped) = c.strip_prefix('"') {
        match stripped.find('"') {
            Some(i) => &stripped[i + 1..],
            None => "",
        }
    } else {
        match c.find(char::is_whitespace) {
            Some(i) => &c[i..],
            None => "",
        }
    };
    !rest.trim().is_empty()
}

/// IPv4 literals appearing as standalone tokens in a command line.
pub fn ipv4_tokens(cmd: &str) -> Vec<String> {
    cmd.split(|c: char| {
        c.is_whitespace() || c == '"' || c == '\'' || c == '|' || c == '&' || c == '(' || c == ')'
    })
    .filter(|t| t.split('.').count() == 4 && t.parse::<std::net::Ipv4Addr>().is_ok())
    .map(str::to_string)
    .collect()
}

/// "setup_x64.exe (unsigned, from Downloads)".
pub fn describe_proc(p: &ProcessInfo) -> String {
    let name = file_name(&p.image);
    let name = if name.is_empty() {
        "unknown process"
    } else {
        name
    };
    let mut tags: Vec<String> = Vec::new();
    match p.signed {
        SignatureState::Unsigned => tags.push("unsigned".into()),
        SignatureState::Invalid => tags.push("invalid signature".into()),
        _ => {}
    }
    let loc = match p.path_class {
        PathClass::Temp => Some("from Temp"),
        PathClass::Downloads => Some("from Downloads"),
        PathClass::External => Some("from a removable or network drive"),
        PathClass::UserWritable => {
            let l = p.image.to_ascii_lowercase();
            if l.contains("\\appdata\\") || l.contains("/appdata/") {
                Some("from AppData")
            } else {
                Some("from a user-writable folder")
            }
        }
        _ => None,
    };
    if let Some(l) = loc {
        tags.push(l.into());
    }
    if p.motw_zone == Some(3) {
        tags.push("downloaded from the Internet".into());
    }
    if tags.is_empty() {
        name.to_string()
    } else {
        format!("{name} ({})", tags.join(", "))
    }
}

/// SYSTEM account by SID or name (`S-1-5-18`, `NT AUTHORITY\SYSTEM`, `SYSTEM`).
pub fn is_system_user(user: Option<&str>) -> bool {
    user.map(|u| u.trim().to_ascii_lowercase())
        .is_some_and(|u| u == "s-1-5-18" || u == r"nt authority\system" || u == "system")
}

/// Join with commas and a final "and".
pub fn join_and(items: &[String]) -> String {
    match items.len() {
        0 => String::new(),
        1 => items[0].clone(),
        _ => format!(
            "{} and {}",
            items[..items.len() - 1].join(", "),
            items[items.len() - 1]
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ips() {
        assert!(is_external_ip("185.10.20.30"));
        assert!(!is_external_ip("10.1.2.3"));
        assert!(!is_external_ip("192.168.1.1"));
        assert!(!is_external_ip("172.20.0.1"));
        assert!(!is_external_ip("127.0.0.1"));
        assert!(!is_external_ip("100.64.0.1"));
        assert!(!is_external_ip("169.254.1.1"));
        assert!(!is_external_ip("::1"));
        assert!(!is_external_ip("fe80::1%12"));
        assert!(!is_external_ip("fd00::1"));
        assert!(is_external_ip("2606:4700::1111"));
        assert!(is_external_ip("::ffff:8.8.8.8"));
        assert!(!is_external_ip("garbage"));
        assert!(is_loopback_ip("127.0.0.1"));
        assert!(is_loopback_ip("::1"));
    }

    #[test]
    fn domains() {
        assert_eq!(entry_host("discord.com/api/webhooks"), "discord.com");
        assert_eq!(entry_host("https://user@Example.com:443/x"), "example.com");
        assert_eq!(entry_host("*.r2.dev"), "r2.dev");
        assert!(host_matches("api.telegram.org", "api.telegram.org"));
        assert!(host_matches("pub-123.r2.dev", "r2.dev"));
        assert!(!host_matches("notr2.dev", "r2.dev"));
        assert!(host_matches("api.telegram.org.", "api.telegram.org"));
    }

    #[test]
    fn cmdline_helpers() {
        assert!(has_hidden_window("powershell -w h -c iex"));
        assert!(has_hidden_window("powershell.exe -windowstyle hidden -nop"));
        assert!(has_hidden_window("powershell \u{2013}win 1 x"));
        assert!(!has_hidden_window("powershell -nop -c write-host w h"));
        assert!(has_encoded_command("powershell -enc aqbmaa=="));
        assert!(has_encoded_command("pwsh -e aqbm"));
        assert!(!has_encoded_command("powershell -executionpolicy bypass"));
        assert!(contains_word("powershell irm x | iex", "iex"));
        assert!(!contains_word("please confirm you are human", "irm"));
        assert!(!has_arguments(
            "\"C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\RegAsm.exe\""
        ));
        assert!(!has_arguments("regasm.exe  "));
        assert!(has_arguments("msbuild.exe app.csproj"));
        assert_eq!(
            ipv4_tokens("nslookup -q=txt x.example 45.9.1.2 | findstr Name"),
            vec!["45.9.1.2".to_string()]
        );
        assert_eq!(driveless(r"\Device\HarddiskVolume3\Users\A"), r"\users\a");
        assert_eq!(driveless(r"C:\Users\A"), r"\users\a");
        assert_eq!(
            join_and(&["a".into(), "b".into(), "c".into()]),
            "a, b and c"
        );
    }
}

/// Registry number data in any rendering a sensor may send: decimal (`1`),
/// hex (`0x1`), `dword:00000001` / `qword:…`, or the Sysmon style
/// `DWORD (0x00000001)` / `QWORD (0x00000001-0x00000000)` (high-low halves).
pub(crate) fn reg_number(d: &str) -> Option<u64> {
    let t = d.trim().to_ascii_lowercase();
    if let Some(inner) = t
        .strip_prefix("dword (")
        .or_else(|| t.strip_prefix("qword ("))
        .and_then(|r| r.strip_suffix(')'))
    {
        let mut parts = inner.split('-');
        let hi = parts.next()?;
        let parse = |h: &str| u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok();
        return match parts.next() {
            // Sysmon renders QWORD as high-low.
            Some(lo) => Some((parse(hi)? << 32) | parse(lo)?),
            None => parse(hi),
        };
    }
    if let Some(h) = t
        .strip_prefix("dword:")
        .or_else(|| t.strip_prefix("qword:"))
    {
        return u64::from_str_radix(h.trim().trim_start_matches("0x"), 16).ok();
    }
    if let Some(h) = t.strip_prefix("0x") {
        return u64::from_str_radix(h, 16).ok();
    }
    t.parse().ok()
}

#[cfg(test)]
mod reg_number_tests {
    use super::reg_number;

    #[test]
    fn every_rendering() {
        assert_eq!(reg_number("1"), Some(1));
        assert_eq!(reg_number(" 0x200 "), Some(0x200));
        assert_eq!(reg_number("dword:00000200"), Some(0x200));
        assert_eq!(reg_number("DWORD (0x00000000)"), Some(0));
        assert_eq!(reg_number("DWORD (0x00000004)"), Some(4));
        assert_eq!(
            reg_number("QWORD (0x00000001-0x00000002)"),
            Some((1 << 32) | 2)
        );
        assert_eq!(reg_number("explorer.exe"), None);
    }
}
