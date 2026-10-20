//! MSI custom actions for the Kestrel installer (security review M6).
//!
//! Anything on a process command line is visible to every process-creation
//! sensor on the host (Kestrel's own, Defender, Sysmon, another EDR), and
//! Windows Installer logs formatted Registry/IniFile values in verbose logs
//! even when the property is hidden. So the tokens travel only inside
//! `CustomActionData` (hidden, so masked in logs) of a deferred action, and
//! this DLL hands them to `kestrel-agent.exe` on **stdin**:
//!
//! * `KestrelInstall`: `CustomActionData` = `<installdir>|<server>|<ca_b64>|<token>`
//!   → `kestrel-agent.exe install --server <server> --ca <ca_b64> --token-stdin`
//! * `KestrelUninstall`: `CustomActionData` = `<installdir>|<uninstall token>`
//!   → `kestrel-agent.exe uninstall --token-stdin`
//!
//! The agent's output (which never contains a token) goes to the MSI log.
//! A non-zero exit fails the action (1603), so a wrong uninstall token aborts
//! the uninstall.

/// Parsed `CustomActionData` of the install action.
#[derive(Debug, PartialEq, Eq)]
pub struct InstallData<'a> {
    pub dir: &'a str,
    pub server: &'a str,
    pub ca_b64: &'a str,
    pub token: &'a str,
}

/// `<installdir>|<server>|<ca_b64>|<token>`; `|` never occurs in a Windows
/// path, a `host:port`, base64 or a Kestrel token.
pub fn parse_install(data: &str) -> Option<InstallData<'_>> {
    let mut it = data.splitn(4, '|');
    let d = InstallData {
        dir: it.next()?.trim(),
        server: it.next()?.trim(),
        ca_b64: it.next()?.trim(),
        token: it.next()?.trim(),
    };
    (!d.dir.is_empty() && !d.server.is_empty() && !d.ca_b64.is_empty() && !d.token.is_empty())
        .then_some(d)
}

/// `<installdir>|<token>` (the token may be empty: the agent then refuses).
pub fn parse_uninstall(data: &str) -> Option<(&str, &str)> {
    let (dir, token) = data.split_once('|')?;
    let dir = dir.trim();
    (!dir.is_empty()).then_some((dir, token.trim()))
}

/// Path of the agent next to the installed files.
pub fn agent_exe(dir: &str) -> String {
    let d = dir.trim_end_matches(['\\', '/']);
    format!("{d}\\kestrel-agent.exe")
}

#[cfg(windows)]
mod ca {
    use super::*;
    use std::io::Write;
    use std::os::windows::process::CommandExt;
    use std::process::{Command, Stdio};
    use windows_sys::Win32::Foundation::{ERROR_INSTALL_FAILURE, ERROR_SUCCESS};
    use windows_sys::Win32::System::ApplicationInstallationAndServicing::{
        MsiCreateRecord, MsiGetPropertyW, MsiProcessMessage, MsiRecordSetStringW,
        INSTALLMESSAGE_INFO, MSIHANDLE,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn property(h: MSIHANDLE, name: &str) -> String {
        let n = wide(name);
        let mut len: u32 = 0;
        let mut empty = [0u16; 1];
        unsafe {
            // First call returns ERROR_MORE_DATA and the length without the NUL.
            MsiGetPropertyW(h, n.as_ptr(), empty.as_mut_ptr(), &mut len);
            let mut buf = vec![0u16; len as usize + 1];
            let mut cap = buf.len() as u32;
            if MsiGetPropertyW(h, n.as_ptr(), buf.as_mut_ptr(), &mut cap) != ERROR_SUCCESS {
                return String::new();
            }
            buf.truncate(cap as usize);
            String::from_utf16_lossy(&buf)
        }
    }

    fn log(h: MSIHANDLE, msg: &str) {
        unsafe {
            let rec = MsiCreateRecord(1);
            let m = wide(&format!("kestrel: {msg}"));
            MsiRecordSetStringW(rec, 0, m.as_ptr());
            MsiProcessMessage(h, INSTALLMESSAGE_INFO, rec);
            windows_sys::Win32::System::ApplicationInstallationAndServicing::MsiCloseHandle(rec);
        }
    }

    /// Run the agent with `secret` on stdin; log its output; 0 on success.
    fn run(h: MSIHANDLE, exe: &str, args: &[&str], secret: &str) -> u32 {
        let child = Command::new(exe)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn();
        let mut child = match child {
            Ok(c) => c,
            Err(e) => {
                log(h, &format!("cannot start {exe}: {e}"));
                return ERROR_INSTALL_FAILURE;
            }
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = writeln!(stdin, "{secret}");
        }
        match child.wait_with_output() {
            Ok(out) => {
                for line in String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .chain(String::from_utf8_lossy(&out.stderr).lines())
                {
                    log(h, line);
                }
                if out.status.success() {
                    ERROR_SUCCESS
                } else {
                    log(
                        h,
                        &format!(
                            "{} {} failed: {}",
                            exe,
                            args.first().unwrap_or(&""),
                            out.status
                        ),
                    );
                    ERROR_INSTALL_FAILURE
                }
            }
            Err(e) => {
                log(h, &format!("waiting for {exe}: {e}"));
                ERROR_INSTALL_FAILURE
            }
        }
    }

    /// Deferred, no impersonation: enrol and register the service.
    #[no_mangle]
    pub extern "system" fn KestrelInstall(h: MSIHANDLE) -> u32 {
        let data = property(h, "CustomActionData");
        let Some(d) = parse_install(&data) else {
            log(h, "install: SERVER, CA_B64 and TOKEN are required");
            return ERROR_INSTALL_FAILURE;
        };
        run(
            h,
            &agent_exe(d.dir),
            &[
                "install",
                "--server",
                d.server,
                "--ca",
                d.ca_b64,
                "--token-stdin",
            ],
            d.token,
        )
    }

    /// Deferred, no impersonation: verify the uninstall token, remove the service.
    #[no_mangle]
    pub extern "system" fn KestrelUninstall(h: MSIHANDLE) -> u32 {
        let data = property(h, "CustomActionData");
        let Some((dir, token)) = parse_uninstall(&data) else {
            log(h, "uninstall: bad custom action data");
            return ERROR_INSTALL_FAILURE;
        };
        run(h, &agent_exe(dir), &["uninstall", "--token-stdin"], token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_data() {
        let d =
            parse_install(r"C:\Program Files\Kestrel\|10.0.2.2:8443|LS0tLS1C|kte_abc-_x").unwrap();
        assert_eq!(d.dir, r"C:\Program Files\Kestrel\");
        assert_eq!(d.server, "10.0.2.2:8443");
        assert_eq!(d.token, "kte_abc-_x");
        assert_eq!(
            agent_exe(d.dir),
            r"C:\Program Files\Kestrel\kestrel-agent.exe"
        );
        assert!(parse_install(r"C:\K\|srv:1|ca|").is_none(), "empty token");
        assert!(parse_install("only|three|parts").is_none());
    }

    #[test]
    fn uninstall_data() {
        assert_eq!(parse_uninstall(r"C:\K\|kun_x"), Some((r"C:\K\", "kun_x")));
        assert_eq!(parse_uninstall(r"C:\K\|"), Some((r"C:\K\", "")));
        assert_eq!(parse_uninstall("|x"), None);
    }
}
