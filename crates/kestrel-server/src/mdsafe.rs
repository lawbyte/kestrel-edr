//! Markdown hygiene for endpoint-controlled text (security review v1.1 V-M6).
//!
//! Incident storylines are markdown rendered by the console. Every string an
//! endpoint controls (task names and actions, service image paths, registry
//! keys and data, WMI text, file names, user names, alert summaries …) goes
//! through one of these helpers before it is placed in markdown:
//!
//! * [`md_code`] — a code span: control / bidi characters and newlines are
//!   removed, backticks are replaced by `ˋ` (U+02CB) so the span can never be
//!   closed early, and the text is clipped.
//! * [`md_text`] — running text: the same stripping plus a backslash before
//!   every markdown-significant character (`\ ` * _ [ ] < > # |`).
//! * [`plain`] — titles and other plain-text fields: stripping and clipping only.
//!
//! The console renderer understands backslash escapes and never renders links
//! in storylines, so endpoint text cannot create links, quotes or emphasis.

use crate::autorun_policy::is_bidi_or_invisible;

/// Remove control characters (incl. newlines and tabs, which become a space),
/// bidi overrides and invisible formatting characters.
fn strip(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\n' || c == '\r' || c == '\t' {
            if !out.ends_with(' ') {
                out.push(' ');
            }
        } else if !(c.is_control() || is_bidi_or_invisible(c)) {
            out.push(c);
        }
    }
    out
}

fn clip_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

/// Plain text (titles, activity lines): stripped and clipped.
pub fn plain(s: &str, max: usize) -> String {
    clip_chars(strip(s).trim(), max)
}

/// Endpoint text as a markdown code span, including the surrounding backticks.
pub fn md_code(s: &str, max: usize) -> String {
    let t = clip_chars(strip(s).trim(), max).replace('`', "\u{02CB}");
    if t.is_empty() {
        "`(empty)`".to_string()
    } else {
        format!("`{t}`")
    }
}

/// Endpoint text in running markdown text: stripped, clipped and escaped.
pub fn md_text(s: &str, max: usize) -> String {
    let t = clip_chars(strip(s).trim(), max);
    let mut out = String::with_capacity(t.len() + 8);
    for c in t.chars() {
        if matches!(
            c,
            '\\' | '`' | '*' | '_' | '[' | ']' | '<' | '>' | '#' | '|'
        ) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_span_cannot_break_out() {
        let evil = "x` [Kestrel: re-authenticate](https://evil.example/sso) `y";
        let c = md_code(evil, 200);
        assert!(c.starts_with('`') && c.ends_with('`'));
        assert_eq!(c.matches('`').count(), 2, "{c}");
        let c = md_code("a\n> **Verified benign by Kestrel**\r\nb", 200);
        assert!(!c.contains('\n') && !c.contains('\r'), "{c}");
        assert_eq!(md_code("", 10), "`(empty)`");
        assert_eq!(md_code(r"C:\Users\x", 50), r"`C:\Users\x`");
        assert!(md_code(&"a".repeat(500), 10).chars().count() <= 13);
        assert!(!md_code("up\u{202E}fdp.exe", 50).contains('\u{202E}'));
    }

    #[test]
    fn text_is_escaped() {
        let t = md_text("[click](https://evil) *b* # x > y | z _u_ <b> `c` \\", 200);
        assert_eq!(
            t,
            r"\[click\](https://evil) \*b\* \# x \> y \| z \_u\_ \<b\> \`c\` \\"
        );
        assert!(!md_text("a\nb", 10).contains('\n'));
        assert_eq!(plain("host\u{202E}x\n1", 50), "hostx 1");
    }
}
