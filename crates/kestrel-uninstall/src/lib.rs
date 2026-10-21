//! Kestrel EDR uninstaller (`kestrel-uninstall.exe`): platform-independent
//! logic, unit-tested on every platform. The Win32 dialog, the Windows
//! Installer call and the link-safe purge live in `main.rs` and its modules
//! (Windows only).
//!
//! Flow: the administrator pastes the device's uninstall token; the tool
//! finds the installed "Kestrel EDR Agent" product (HKLM Uninstall keys,
//! 64-bit view) and removes it through Windows Installer with
//! `UNINSTALL_TOKEN` set. The package's `KestrelUninstall` custom action
//! still verifies the token (V-M2); this tool is only a front end.
//!
//! The token never goes on a process command line: the removal is requested
//! with `MsiConfigureProductExW` in this process instead of starting
//! `msiexec.exe /x ... UNINSTALL_TOKEN=...` (process-creation telemetry such
//! as Sysmon event 1 or Security 4688 would otherwise write it to a log).
//! `UNINSTALL_TOKEN` is a hidden MSI property, so the verbose log masks it.

#[cfg(windows)]
pub mod win;

/// `DisplayName` of the installed product in the Uninstall registry key
/// (the MSI `Package/@Name`).
pub const PRODUCT_DISPLAY_NAME: &str = "Kestrel EDR Agent";
/// Kestrel's UpgradeCode (`installer/Kestrel.wxs`); the product found by
/// name must also be registered under it.
pub const UPGRADE_CODE: &str = "{6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D10}";
/// Server-issued uninstall tokens start with this prefix.
pub const TOKEN_PREFIX: &str = "kun_";
/// Anything longer is not a Kestrel token.
pub const MAX_TOKEN_LEN: usize = 512;
/// Text the agent prints when the token is wrong
/// (`kestrel-agent uninstall`, `commands::verify_uninstall`); the MSI custom
/// action copies the agent's output into the installer log.
pub const AGENT_INVALID_TOKEN: &str = "invalid uninstall token";

/// Windows Installer return codes this tool distinguishes.
pub mod rc {
    pub const SUCCESS: u32 = 0;
    pub const SUCCESS_REBOOT_REQUIRED: u32 = 3010;
    pub const INSTALL_FAILURE: u32 = 1603;
    pub const INSTALL_USEREXIT: u32 = 1602;
    pub const UNKNOWN_PRODUCT: u32 = 1605;
    pub const INSTALL_ALREADY_RUNNING: u32 = 1618;
    /// ERROR_FUNCTION_FAILED: used when the tool itself failed unexpectedly.
    pub const FUNCTION_FAILED: u32 = 1627;
}

// ------------------------------------------------------------------ token

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenError {
    Empty,
    TooLong,
    /// Spaces, control characters, non-ASCII, `|` or `"` inside the token.
    BadCharacter,
}

impl TokenError {
    pub fn message(self) -> &'static str {
        match self {
            TokenError::Empty => "Paste this PC's uninstall token first.",
            TokenError::TooLong => {
                "That is too long to be an uninstall token. Copy only the token from the console."
            }
            TokenError::BadCharacter => {
                "The token contains spaces or characters a token never has. Copy it again from the console."
            }
        }
    }
}

/// Result of the local plausibility check (the agent does the real check).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenCheck {
    /// The token does not start with `kun_` (allowed: older servers or a
    /// locally generated token; the user is told, not blocked).
    pub unusual_prefix: bool,
}

pub const UNUSUAL_PREFIX_WARNING: &str =
    "Note: Kestrel uninstall tokens normally start with \"kun_\". Trying it anyway.";

/// `token` must already be trimmed. Non-empty, at most [`MAX_TOKEN_LEN`],
/// printable ASCII without spaces, `|` or `"`. Real tokens are `kun_` +
/// base64url; `|` separates the MSI custom-action data fields and `"`
/// would need quoting in the property string, so neither can be part of a
/// token that works.
pub fn check_token(token: &str) -> Result<TokenCheck, TokenError> {
    if token.is_empty() {
        return Err(TokenError::Empty);
    }
    if token.len() > MAX_TOKEN_LEN {
        return Err(TokenError::TooLong);
    }
    if !token
        .bytes()
        .all(|b| b.is_ascii_graphic() && b != b'|' && b != b'"')
    {
        return Err(TokenError::BadCharacter);
    }
    Ok(TokenCheck {
        unusual_prefix: !token.starts_with(TOKEN_PREFIX),
    })
}

/// Windows Installer property string for the removal, as UTF-16 with a
/// trailing NUL, built in one allocation (no intermediate copies of the
/// token to wipe). `token` has passed [`check_token`] (no space, `"` or
/// `|`), so quoting the value is enough. `REBOOT=ReallySuppress`: the tool
/// reports 3010 ("restart to finish") instead of letting a silent removal
/// restart the PC.
pub fn msi_properties_wide(token: &str) -> Vec<u16> {
    const HEAD: &str = "UNINSTALL_TOKEN=\"";
    const TAIL: &str = "\" REBOOT=ReallySuppress";
    let mut w = Vec::with_capacity(HEAD.len() + token.len() + TAIL.len() + 1);
    w.extend(HEAD.encode_utf16());
    w.extend(token.encode_utf16());
    w.extend(TAIL.encode_utf16());
    w.push(0);
    w
}

/// Best-effort wipe of a secret held in a `String`.
pub fn wipe_string(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8.
    let bytes = unsafe { s.as_bytes_mut() };
    wipe_bytes(bytes);
    s.clear();
}

/// Best-effort wipe of a byte buffer (volatile writes, not optimised away).
pub fn wipe_bytes(b: &mut [u8]) {
    for x in b.iter_mut() {
        // SAFETY: valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Best-effort wipe of a UTF-16 buffer.
pub fn wipe_wide(b: &mut [u16]) {
    for x in b.iter_mut() {
        // SAFETY: valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(x, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ---------------------------------------------------------------- outcome

/// Result of one uninstall attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Removed {
        reboot_required: bool,
    },
    WrongToken,
    NotInstalled,
    Failed {
        code: u32,
    },
    /// Started without administrator rights (only possible when the
    /// manifest's elevation was bypassed, e.g. `__COMPAT_LAYER=RunAsInvoker`).
    NotElevated,
}

/// Classify the Windows Installer result. `log_invalid_token`: the log has
/// the agent's "invalid uninstall token"; `still_installed`: the product is
/// still registered afterwards.
pub fn classify(code: u32, log_invalid_token: bool, still_installed: bool) -> Outcome {
    match code {
        rc::SUCCESS | rc::SUCCESS_REBOOT_REQUIRED if !still_installed => Outcome::Removed {
            reboot_required: code == rc::SUCCESS_REBOOT_REQUIRED,
        },
        rc::INSTALL_FAILURE if log_invalid_token => Outcome::WrongToken,
        rc::UNKNOWN_PRODUCT => Outcome::NotInstalled,
        c => Outcome::Failed { code: c },
    }
}

/// Process exit code for scripted use: 0 removed, 1 wrong token, 2 anything else.
pub fn exit_code(o: Option<&Outcome>) -> i32 {
    match o {
        Some(Outcome::Removed { .. }) => 0,
        Some(Outcome::WrongToken) => 1,
        _ => 2,
    }
}

pub const MSG_NOT_INSTALLED: &str = "Kestrel is not installed on this PC.";
pub const MSG_WRONG_TOKEN: &str =
    "That token is not valid for this PC. Check that you copied the whole token for this device.";
pub const MSG_REMOVED: &str = "Kestrel was removed from this PC.";
pub const MSG_DECOMMISSION: &str = "In the Kestrel console, use Decommission device on this PC's page to remove it from the device list.";
pub const MSG_REBOOT: &str = "Restart the PC to finish removing Kestrel.";
pub const MSG_NOT_ELEVATED: &str =
    "Kestrel can only be removed by an administrator. Start Uninstall Kestrel EDR again and accept the Windows prompt.";

/// Text for a failed removal.
pub fn failure_message(code: u32, log: &str) -> String {
    let what = match code {
        rc::INSTALL_ALREADY_RUNNING => {
            "Another installation is in progress on this PC. Wait for it to finish, then try again."
                .to_string()
        }
        rc::INSTALL_USEREXIT => "The removal was cancelled.".to_string(),
        c => format!("Kestrel could not be removed (Windows Installer error {c})."),
    };
    if log.is_empty() {
        what
    } else {
        format!("{what}\n\nThe log has the details:\n{log}")
    }
}

/// Does the installer log contain the agent's "invalid uninstall token"?
/// Windows Installer writes ANSI logs by default and UTF-16 when Unicode
/// logging is enabled, so both are handled.
pub fn log_mentions_invalid_token(log: &[u8]) -> bool {
    let utf16 = log.starts_with(&[0xFF, 0xFE]) || (log.len() >= 4 && log[1] == 0 && log[3] == 0);
    let text = if utf16 {
        let w: Vec<u16> = log
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&w)
    } else {
        String::from_utf8_lossy(log).into_owned()
    };
    text.to_ascii_lowercase().contains(AGENT_INVALID_TOKEN)
}

/// The last `max_bytes` of an installer log as text (ANSI or UTF-16),
/// with Windows line ends, for the read-only log view.
pub fn log_tail_text(log: &[u8], max_bytes: usize) -> String {
    let utf16 = log.starts_with(&[0xFF, 0xFE]) || (log.len() >= 4 && log[1] == 0 && log[3] == 0);
    let start = log.len().saturating_sub(max_bytes);
    let start = if utf16 { start & !1 } else { start };
    let tail = &log[start..];
    let text = if utf16 {
        let w: Vec<u16> = tail
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        String::from_utf16_lossy(&w)
    } else {
        String::from_utf8_lossy(tail).into_owned()
    };
    let text = text.trim_start_matches('\u{feff}');
    // Start at a line boundary when the tail was cut.
    let text = if start > 0 {
        text.split_once('\n').map(|(_, r)| r).unwrap_or(text)
    } else {
        text
    };
    text.replace("\r\n", "\n").replace('\n', "\r\n")
}

/// `kestrel-uninstall-<yyyyMMdd-HHmmss>.log`.
pub fn log_file_name(y: u16, mo: u16, d: u16, h: u16, mi: u16, s: u16) -> String {
    format!("kestrel-uninstall-{y:04}{mo:02}{d:02}-{h:02}{mi:02}{s:02}.log")
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (Windows Installer product code).
pub fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 38 || b[0] != b'{' || b[37] != b'}' {
        return false;
    }
    b[1..37].iter().enumerate().all(|(i, c)| match i {
        8 | 13 | 18 | 23 => *c == b'-',
        _ => c.is_ascii_hexdigit(),
    })
}

/// Pick the product code from Uninstall-key entries `(subkey name,
/// DisplayName)`: the key name must be a product code and the display name
/// must match exactly.
pub fn find_product<'a, I>(entries: I) -> Option<String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    entries
        .into_iter()
        .find(|(key, name)| is_guid(key) && *name == PRODUCT_DISPLAY_NAME)
        .map(|(key, _)| key.to_string())
}

// ------------------------------------------------------------------- args

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Run,
    /// Show the window without elevation and without changing anything.
    Preview,
    /// No window (`--quiet --token-stdin [--purge]`): remote removal started
    /// by the agent ("Remove device" in the console). The token is read from
    /// the first line of stdin only, never from the command line.
    Quiet {
        purge: bool,
    },
    Help,
    BadArgs(String),
}

pub const USAGE: &str = "Uninstall Kestrel EDR\n\n\
kestrel-uninstall.exe\n    Opens the uninstall window (asks for administrator rights).\n\n\
kestrel-uninstall.exe --preview\n    Shows the window for screenshots and documentation and walks through\n    the screens. Nothing is changed or deleted.\n    \
To run it without the administrator prompt, start it with the environment\n    \
variable __COMPAT_LAYER=RunAsInvoker.\n\n\
kestrel-uninstall.exe /?\n    Shows this help.\n\n\
kestrel-uninstall.exe --quiet --token-stdin [--purge]\n    No window: reads the uninstall token from the first line of standard\n    \
input and removes Kestrel (used by the agent for Remove device in the\n    \
console). --purge also deletes the Kestrel data folder afterwards.\n\n\
Exit codes: 0 removed, 1 wrong uninstall token, 2 anything else.\n\n\
For scripts without a window:\n    \
msiexec /x <product code> /qn UNINSTALL_TOKEN=<token>";

pub fn parse_args<I, S>(args: I) -> Mode
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut mode = Mode::Run;
    let (mut quiet, mut stdin, mut purge) = (false, false, false);
    let mut first_quiet_only: Option<String> = None;
    for a in args {
        let a = a.as_ref().to_ascii_lowercase();
        match a.as_str() {
            "/?" | "-?" | "-h" | "--help" | "/help" | "/h" => return Mode::Help,
            "--preview" | "/preview" => mode = Mode::Preview,
            "--quiet" | "/quiet" => quiet = true,
            "--token-stdin" | "/token-stdin" => {
                stdin = true;
                first_quiet_only.get_or_insert(a.clone());
            }
            "--purge" | "/purge" => {
                purge = true;
                first_quiet_only.get_or_insert(a.clone());
            }
            other => return Mode::BadArgs(other.to_string()),
        }
    }
    if quiet {
        if mode == Mode::Preview {
            return Mode::BadArgs("--preview".into());
        }
        // The token only ever comes from stdin (never argv).
        if !stdin {
            return Mode::BadArgs("--quiet needs --token-stdin".into());
        }
        return Mode::Quiet { purge };
    }
    if let Some(a) = first_quiet_only {
        return Mode::BadArgs(a);
    }
    mode
}

/// Read the token from the first line of `r` (quiet mode's stdin), reading
/// at most a little more than [`MAX_TOKEN_LEN`] bytes; trimmed and checked
/// with [`check_token`]. The read buffer is wiped.
pub fn read_token_line<R: std::io::Read>(mut r: R) -> Result<String, TokenError> {
    let mut buf = Vec::with_capacity(MAX_TOKEN_LEN + 2);
    let mut byte = [0u8; 1];
    let mut too_long = false;
    loop {
        match r.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() > MAX_TOKEN_LEN + 1 {
                    too_long = true;
                    break;
                }
                buf.push(byte[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    let result = if too_long {
        Err(TokenError::TooLong)
    } else {
        match std::str::from_utf8(&buf) {
            Ok(s) => {
                let t = s.trim();
                check_token(t).map(|_| t.to_string())
            }
            Err(_) => Err(TokenError::BadCharacter),
        }
    };
    wipe_bytes(&mut buf);
    result
}

/// Short machine-readable name of an outcome (quiet-mode result file).
pub fn outcome_kind(o: &Outcome) -> &'static str {
    match o {
        Outcome::Removed { .. } => "removed",
        Outcome::WrongToken => "wrong_token",
        Outcome::NotInstalled => "not_installed",
        Outcome::Failed { .. } => "failed",
        Outcome::NotElevated => "not_elevated",
    }
}

/// One-line explanation of an outcome for the console (quiet mode).
pub fn quiet_message(o: &Outcome) -> String {
    match o {
        Outcome::Removed {
            reboot_required: false,
        } => "Kestrel was removed".into(),
        Outcome::Removed {
            reboot_required: true,
        } => "Kestrel was removed; a restart finishes the removal".into(),
        Outcome::WrongToken => {
            "the Kestrel package refused the uninstall token (token mismatch)".into()
        }
        Outcome::NotInstalled => {
            "no installed Kestrel EDR Agent package was found (installed without the MSI?)".into()
        }
        Outcome::Failed { code } => match *code {
            rc::INSTALL_ALREADY_RUNNING => {
                "another installation was in progress (Windows Installer error 1618); try again later"
                    .into()
            }
            c => format!("Windows Installer error {c}"),
        },
        Outcome::NotElevated => "the uninstall helper did not run with administrator rights".into(),
    }
}

fn json_str(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Result file written by quiet mode after a failed removal
/// (`%ProgramData%\Kestrel\remote-uninstall-result.json`, read and deleted by
/// the agent, which reports it to the console):
/// `{"exit_code":1,"outcome":"wrong_token","msi_code":1603,"message":"…","log":"…"}`.
/// Never contains the token.
pub fn result_json(
    exit: i32,
    kind: &str,
    msi_code: Option<u32>,
    message: &str,
    log: Option<&str>,
) -> String {
    format!(
        "{{\"exit_code\":{exit},\"outcome\":{},\"msi_code\":{},\"message\":{},\"log\":{}}}",
        json_str(kind),
        msi_code
            .map(|c| c.to_string())
            .unwrap_or_else(|| "null".into()),
        json_str(message),
        log.map(json_str).unwrap_or_else(|| "null".into()),
    )
}

// ------------------------------------------------------------------ purge

/// What the optional purge of `%ProgramData%\Kestrel` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PurgeReport {
    pub files: u64,
    pub folders: u64,
    /// Junctions / symbolic links removed as links (targets untouched).
    pub links: u64,
    pub bytes: u64,
    /// Items that could not be deleted (in use, access denied).
    pub failed: u64,
    pub first_error: Option<String>,
}

impl PurgeReport {
    pub fn summary(&self, path: &str) -> String {
        let mut s = format!(
            "Deleted {} ({}) from {path}",
            counted(&[
                (self.files, "file", "files"),
                (self.folders, "folder", "folders"),
                (self.links, "link", "links"),
            ]),
            human_bytes(self.bytes)
        );
        if self.links > 0 {
            s.push_str("; links were removed without touching their targets");
        }
        s.push('.');
        if self.failed > 0 {
            s.push_str(&format!(
                " {} could not be deleted{}.",
                counted(&[(self.failed, "item", "items")]),
                self.first_error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ));
        }
        s
    }
}

fn counted(parts: &[(u64, &str, &str)]) -> String {
    let v: Vec<String> = parts
        .iter()
        .filter(|(n, _, _)| *n > 0)
        .map(|(n, one, many)| format!("{n} {}", if *n == 1 { one } else { many }))
        .collect();
    if v.is_empty() {
        "nothing".into()
    } else {
        v.join(", ")
    }
}

pub fn human_bytes(b: u64) -> String {
    const U: [&str; 4] = ["KB", "MB", "GB", "TB"];
    if b < 1024 {
        return format!("{b} bytes");
    }
    let mut v = b as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

/// Is `final_path` (from `GetFinalPathNameByHandleW`, possibly `\\?\`
/// prefixed) the expected folder? Case-insensitive, trailing separators
/// ignored. A junction anywhere on the path makes them differ.
pub fn same_final_path(final_path: &str, expected: &str) -> bool {
    let norm = |p: &str| {
        p.strip_prefix(r"\\?\")
            .unwrap_or(p)
            .trim_end_matches(['\\', '/'])
            .to_lowercase()
    };
    let (a, b) = (norm(final_path), norm(expected));
    !a.is_empty() && a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_checks() {
        assert_eq!(check_token(""), Err(TokenError::Empty));
        assert_eq!(check_token("kun_abc DEF"), Err(TokenError::BadCharacter));
        assert_eq!(check_token("kun_\tx"), Err(TokenError::BadCharacter));
        assert_eq!(check_token("kun_é"), Err(TokenError::BadCharacter));
        assert_eq!(
            check_token(&"a".repeat(MAX_TOKEN_LEN + 1)),
            Err(TokenError::TooLong)
        );
        assert_eq!(
            check_token("kun_AbC-_09"),
            Ok(TokenCheck {
                unusual_prefix: false
            })
        );
        assert_eq!(
            check_token("Zx9_local"),
            Ok(TokenCheck {
                unusual_prefix: true
            })
        );
        for e in [
            TokenError::Empty,
            TokenError::TooLong,
            TokenError::BadCharacter,
        ] {
            assert!(!e.message().is_empty());
        }
    }

    #[test]
    fn property_string_quotes_the_token() {
        let w = msi_properties_wide("kun_x");
        assert_eq!(w.last(), Some(&0));
        assert_eq!(
            String::from_utf16_lossy(&w[..w.len() - 1]),
            "UNINSTALL_TOKEN=\"kun_x\" REBOOT=ReallySuppress"
        );
        // No reallocation happened (one buffer to wipe).
        assert_eq!(w.capacity(), w.len());
    }

    #[test]
    fn separators_and_quotes_are_not_token_characters() {
        // H1 (security review 2026-10-22): `|` would split the custom-action data.
        assert_eq!(
            check_token("x|{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"),
            Err(TokenError::BadCharacter)
        );
        assert_eq!(check_token("kun_a\"b"), Err(TokenError::BadCharacter));
        assert_eq!(
            check_token("kun_a\" REMOVE=x"),
            Err(TokenError::BadCharacter)
        );
    }

    #[test]
    fn wiping() {
        let mut s = String::from("kun_secret");
        wipe_string(&mut s);
        assert!(s.is_empty());
        let mut w: Vec<u16> = "kun_x".encode_utf16().collect();
        wipe_wide(&mut w);
        assert!(w.iter().all(|&c| c == 0));
    }

    #[test]
    fn classification_and_exit_codes() {
        assert_eq!(
            classify(0, false, false),
            Outcome::Removed {
                reboot_required: false
            }
        );
        assert_eq!(
            classify(3010, false, false),
            Outcome::Removed {
                reboot_required: true
            }
        );
        // "Success" but the product is still registered: not a success.
        assert_eq!(classify(0, false, true), Outcome::Failed { code: 0 });
        assert_eq!(classify(1603, true, true), Outcome::WrongToken);
        assert_eq!(classify(1603, false, true), Outcome::Failed { code: 1603 });
        assert_eq!(classify(1605, false, false), Outcome::NotInstalled);
        assert_eq!(classify(1618, true, true), Outcome::Failed { code: 1618 });
        assert_eq!(
            exit_code(Some(&Outcome::Removed {
                reboot_required: true
            })),
            0
        );
        assert_eq!(exit_code(Some(&Outcome::WrongToken)), 1);
        assert_eq!(exit_code(Some(&Outcome::NotInstalled)), 2);
        assert_eq!(exit_code(Some(&Outcome::Failed { code: 1 })), 2);
        assert_eq!(exit_code(None), 2);
    }

    #[test]
    fn failure_text() {
        let m = failure_message(1603, r"C:\T\k.log");
        assert!(
            m.contains("error 1603") && m.ends_with(r"C:\T\k.log"),
            "{m}"
        );
        assert!(failure_message(1618, "").contains("Another installation"));
    }

    #[test]
    fn log_scan_ansi_and_utf16() {
        let ansi =
            b"MSI (s) (A8:3C) ...\r\nCustomAction: kestrel: Error: invalid uninstall token\r\n";
        assert!(log_mentions_invalid_token(ansi));
        assert!(!log_mentions_invalid_token(
            b"kestrel: Service KestrelAgent removed"
        ));
        let mut u = vec![0xFF, 0xFE];
        for c in "kestrel: Error: Invalid Uninstall Token".encode_utf16() {
            u.extend_from_slice(&c.to_le_bytes());
        }
        assert!(log_mentions_invalid_token(&u));
        // UTF-16 without a BOM.
        assert!(log_mentions_invalid_token(&u[2..]));
        assert!(!log_mentions_invalid_token(b""));
    }

    #[test]
    fn log_tail() {
        let log = b"line1\r\nline2\nline3\r\n";
        assert_eq!(log_tail_text(log, 1000), "line1\r\nline2\r\nline3\r\n");
        assert_eq!(log_tail_text(log, 10), "line3\r\n");
        let mut u = vec![0xFF, 0xFE];
        for c in "a\r\nb\r\n".encode_utf16() {
            u.extend_from_slice(&c.to_le_bytes());
        }
        assert_eq!(log_tail_text(&u, 1000), "a\r\nb\r\n");
    }

    #[test]
    fn names_and_guids() {
        assert_eq!(
            log_file_name(2026, 10, 2, 9, 5, 7),
            "kestrel-uninstall-20261002-090507.log"
        );
        assert!(is_guid("{6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D10}"));
        assert!(!is_guid("6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D10"));
        assert!(!is_guid("{6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D1G}"));
        let pc = "{11111111-2222-3333-4444-555555555555}";
        let entries = [
            ("Kestrel EDR Agent", "Kestrel EDR Agent"),
            (
                "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
                "Kestrel EDR Agent Tools",
            ),
            (pc, "Kestrel EDR Agent"),
        ];
        assert_eq!(find_product(entries), Some(pc.to_string()));
        assert_eq!(find_product([("{x}", "Kestrel EDR Agent")]), None);
    }

    #[test]
    fn args() {
        assert_eq!(parse_args(Vec::<String>::new()), Mode::Run);
        assert_eq!(parse_args(["--preview"]), Mode::Preview);
        assert_eq!(parse_args(["/?"]), Mode::Help);
        assert_eq!(parse_args(["--preview", "-h"]), Mode::Help);
        assert_eq!(parse_args(["--purge"]), Mode::BadArgs("--purge".into()));
        assert!(USAGE.contains("--preview") && USAGE.contains("Exit codes"));
    }

    #[test]
    fn quiet_args() {
        assert_eq!(
            parse_args(["--quiet", "--token-stdin"]),
            Mode::Quiet { purge: false }
        );
        assert_eq!(
            parse_args(["--token-stdin", "--purge", "--quiet"]),
            Mode::Quiet { purge: true }
        );
        // The token never comes from argv; quiet needs stdin.
        assert!(matches!(parse_args(["--quiet"]), Mode::BadArgs(_)));
        assert!(matches!(
            parse_args(["--quiet", "--token-stdin", "kun_x"]),
            Mode::BadArgs(a) if a == "kun_x"
        ));
        assert!(matches!(
            parse_args(["--quiet", "--token", "kun_x"]),
            Mode::BadArgs(_)
        ));
        assert_eq!(
            parse_args(["--token-stdin"]),
            Mode::BadArgs("--token-stdin".into())
        );
        assert!(matches!(
            parse_args(["--quiet", "--token-stdin", "--preview"]),
            Mode::BadArgs(_)
        ));
        assert!(USAGE.contains("--quiet --token-stdin"));
    }

    #[test]
    fn token_from_stdin() {
        assert_eq!(
            read_token_line(&b"kun_abc\r\nignored"[..]),
            Ok("kun_abc".to_string())
        );
        assert_eq!(read_token_line(&b"  kun_abc  "[..]), Ok("kun_abc".into()));
        assert_eq!(read_token_line(&b"\n"[..]), Err(TokenError::Empty));
        assert_eq!(read_token_line(&b""[..]), Err(TokenError::Empty));
        assert_eq!(
            read_token_line(&b"kun_a|b\n"[..]),
            Err(TokenError::BadCharacter)
        );
        let long = vec![b'a'; MAX_TOKEN_LEN + 50];
        assert_eq!(read_token_line(&long[..]), Err(TokenError::TooLong));
        assert_eq!(
            read_token_line(&[0xffu8, 0xfe][..]),
            Err(TokenError::BadCharacter)
        );
    }

    #[test]
    fn quiet_result_file() {
        let j = result_json(
            1,
            outcome_kind(&Outcome::WrongToken),
            Some(1603),
            &quiet_message(&Outcome::WrongToken),
            Some(r"C:\Windows\SystemTemp\k\a.log"),
        );
        let v: Vec<&str> = vec![
            r#""exit_code":1"#,
            r#""outcome":"wrong_token""#,
            r#""msi_code":1603"#,
            r#""log":"C:\\Windows\\SystemTemp\\k\\a.log""#,
        ];
        for part in v {
            assert!(j.contains(part), "{j}");
        }
        let j = result_json(2, "failed", None, "a \"b\"\n", None);
        assert!(
            j.contains(r#""msi_code":null"#) && j.contains(r#""log":null"#),
            "{j}"
        );
        assert!(j.contains(r#""message":"a \"b\"\u000a""#), "{j}");
        assert_eq!(
            outcome_kind(&Outcome::Removed {
                reboot_required: true
            }),
            "removed"
        );
        assert!(quiet_message(&Outcome::Failed { code: 1618 }).contains("1618"));
        assert!(quiet_message(&Outcome::Failed { code: 1603 }).contains("1603"));
    }

    #[test]
    fn purge_summary() {
        let r = PurgeReport {
            files: 12,
            folders: 3,
            links: 1,
            bytes: 5 * 1024 * 1024 + 300 * 1024,
            failed: 0,
            first_error: None,
        };
        assert_eq!(
            r.summary(r"C:\ProgramData\Kestrel"),
            r"Deleted 12 files, 3 folders, 1 link (5.3 MB) from C:\ProgramData\Kestrel; links were removed without touching their targets."
        );
        let r = PurgeReport {
            files: 1,
            failed: 2,
            first_error: Some("access denied".into()),
            ..Default::default()
        };
        assert_eq!(
            r.summary("D"),
            "Deleted 1 file (0 bytes) from D. 2 items could not be deleted (access denied)."
        );
        assert_eq!(human_bytes(1023), "1023 bytes");
        assert_eq!(human_bytes(1536), "1.5 KB");
    }

    #[test]
    fn final_paths() {
        assert!(same_final_path(
            r"\\?\C:\ProgramData\Kestrel",
            r"C:\programdata\kestrel\"
        ));
        assert!(!same_final_path(
            r"\\?\D:\elsewhere",
            r"C:\ProgramData\Kestrel"
        ));
        assert!(!same_final_path("", ""));
    }
}
