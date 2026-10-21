//! MSI custom actions for the Kestrel installer (security review M6, v1.1
//! V-M2 / V-M3).
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
//!   (the agent keeps an existing identity instead of enrolling again).
//! * `KestrelUninstall`: `CustomActionData` =
//!   `<installdir>|<uninstall token>|<UPGRADINGPRODUCTCODE>|<UpgradeCode>|<ProductVersion>|<ProductCode>`
//!   → `kestrel-agent.exe uninstall --token-stdin`, unless this removal is
//!   verifiably part of a major upgrade to a newer Kestrel product.
//!
//! V-M2: `UPGRADINGPRODUCTCODE` is set by Windows Installer on the old
//! product's removal during a major upgrade, but it is an ordinary property
//! that can also be passed on the `msiexec /x` command line. It is therefore
//! never trusted on its own: the token is waived only when the named product
//! is registered under Kestrel's UpgradeCode (`MsiEnumRelatedProducts`), is
//! installed (`MsiQueryProductState` = default) and has a higher version than
//! this product. The installer schedules `RemoveExistingProducts` after
//! `InstallExecute` (`<MajorUpgrade Schedule="afterInstallExecute">`), so the
//! new product is already registered when the old one is removed.
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

/// Parsed `CustomActionData` of the uninstall action.
#[derive(Debug, PartialEq, Eq, Default)]
pub struct UninstallData<'a> {
    pub dir: &'a str,
    /// May be empty: the agent then refuses.
    pub token: &'a str,
    /// `UPGRADINGPRODUCTCODE` as seen by this session (untrusted).
    pub upgrading: &'a str,
    pub upgrade_code: &'a str,
    pub version: &'a str,
    pub product_code: &'a str,
}

/// `<installdir>|<token>[|<upgrading>|<upgrade code>|<version>|<product code>]`.
/// The token is the second field; the four trailing fields are product
/// codes / a version and never contain `|`.
pub fn parse_uninstall(data: &str) -> Option<UninstallData<'_>> {
    let mut it = data.splitn(6, '|');
    let dir = it.next()?.trim();
    if dir.is_empty() {
        return None;
    }
    let token = it.next()?.trim();
    Some(UninstallData {
        dir,
        token,
        upgrading: it.next().unwrap_or("").trim(),
        upgrade_code: it.next().unwrap_or("").trim(),
        version: it.next().unwrap_or("").trim(),
        product_code: it.next().unwrap_or("").trim(),
    })
}

/// `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}` (Windows Installer GUID form).
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

/// Dotted numeric version compare: is `a` newer than `b`?
pub fn version_newer(a: &str, b: &str) -> bool {
    let p = |s: &str| -> Option<Vec<u64>> {
        s.trim()
            .split('.')
            .map(|x| x.parse::<u64>().ok())
            .collect::<Option<Vec<_>>>()
    };
    match (p(a), p(b)) {
        (Some(mut x), Some(mut y)) => {
            let n = x.len().max(y.len());
            x.resize(n, 0);
            y.resize(n, 0);
            x > y
        }
        _ => false,
    }
}

/// What the system says about the product named by `UPGRADINGPRODUCTCODE`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UpgradeFacts {
    /// Products registered under this package's UpgradeCode.
    pub related: Vec<String>,
    /// `MsiQueryProductState(upgrading) == INSTALLSTATE_DEFAULT`.
    pub upgrading_installed: bool,
    /// `MsiGetProductInfo(upgrading, VersionString)`.
    pub upgrading_version: Option<String>,
}

/// Is this removal a genuine major upgrade to a newer Kestrel product (so
/// the uninstall token is not required)? Pure decision over `facts`.
pub fn upgrade_verified(d: &UninstallData<'_>, facts: &UpgradeFacts) -> Result<(), String> {
    if d.upgrading.is_empty() {
        return Err("not an upgrade".into());
    }
    if !is_guid(d.upgrading) {
        return Err(format!(
            "UPGRADINGPRODUCTCODE {:?} is not a product code",
            d.upgrading
        ));
    }
    if d.upgrading.eq_ignore_ascii_case(d.product_code) {
        return Err("UPGRADINGPRODUCTCODE names this product".into());
    }
    if !facts
        .related
        .iter()
        .any(|r| r.eq_ignore_ascii_case(d.upgrading))
    {
        return Err(format!(
            "{} is not a Kestrel product registered on this machine",
            d.upgrading
        ));
    }
    if !facts.upgrading_installed {
        return Err(format!("{} is not installed", d.upgrading));
    }
    match facts.upgrading_version.as_deref() {
        Some(v) if version_newer(v, d.version) => Ok(()),
        Some(v) => Err(format!(
            "{} has version {v}, not newer than {}",
            d.upgrading, d.version
        )),
        None => Err(format!("version of {} unknown", d.upgrading)),
    }
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
        MsiCreateRecord, MsiEnumRelatedProductsW, MsiGetProductInfoW, MsiGetPropertyW,
        MsiProcessMessage, MsiQueryProductStateW, MsiRecordSetStringW, INSTALLMESSAGE_INFO,
        INSTALLPROPERTY_VERSIONSTRING, INSTALLSTATE_DEFAULT, MSIHANDLE,
    };

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn from_wide(buf: &[u16]) -> String {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
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

    /// Facts about `upgrading` from the Windows Installer registration.
    fn upgrade_facts(upgrade_code: &str, upgrading: &str) -> UpgradeFacts {
        let mut f = UpgradeFacts::default();
        if is_guid(upgrade_code) {
            let uc = wide(upgrade_code);
            for i in 0..64u32 {
                let mut buf = [0u16; 39];
                let rc = unsafe { MsiEnumRelatedProductsW(uc.as_ptr(), 0, i, buf.as_mut_ptr()) };
                if rc != ERROR_SUCCESS {
                    break;
                }
                f.related.push(from_wide(&buf));
            }
        }
        if is_guid(upgrading) {
            let pc = wide(upgrading);
            f.upgrading_installed =
                unsafe { MsiQueryProductStateW(pc.as_ptr()) } == INSTALLSTATE_DEFAULT;
            let mut buf = vec![0u16; 64];
            let mut cap = buf.len() as u32;
            let rc = unsafe {
                MsiGetProductInfoW(
                    pc.as_ptr(),
                    INSTALLPROPERTY_VERSIONSTRING,
                    buf.as_mut_ptr(),
                    &mut cap,
                )
            };
            if rc == ERROR_SUCCESS {
                f.upgrading_version = Some(from_wide(&buf));
            }
        }
        f
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

    /// Deferred, no impersonation: enrol (unless already enrolled) and
    /// register the service.
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

    /// Deferred, no impersonation: verify the uninstall token, remove the
    /// service. Skipped only for a verified major upgrade (V-M2).
    #[no_mangle]
    pub extern "system" fn KestrelUninstall(h: MSIHANDLE) -> u32 {
        let data = property(h, "CustomActionData");
        let Some(d) = parse_uninstall(&data) else {
            log(h, "uninstall: bad custom action data");
            return ERROR_INSTALL_FAILURE;
        };
        if !d.upgrading.is_empty() {
            let facts = upgrade_facts(d.upgrade_code, d.upgrading);
            match upgrade_verified(&d, &facts) {
                Ok(()) => {
                    log(
                        h,
                        &format!(
                            "upgrade to {} (version {}): the agent service is kept; no uninstall token needed",
                            d.upgrading,
                            facts.upgrading_version.as_deref().unwrap_or("?")
                        ),
                    );
                    return ERROR_SUCCESS;
                }
                Err(why) => log(
                    h,
                    &format!(
                        "UPGRADINGPRODUCTCODE not accepted ({why}); the uninstall token is required"
                    ),
                ),
            }
        }
        run(
            h,
            &agent_exe(d.dir),
            &["uninstall", "--token-stdin"],
            d.token,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UC: &str = "{6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D10}";
    const OLD: &str = "{11111111-2222-3333-4444-555555555555}";
    const NEW: &str = "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}";

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
        let d = parse_uninstall(r"C:\K\|kun_x").unwrap();
        assert_eq!((d.dir, d.token, d.upgrading), (r"C:\K\", "kun_x", ""));
        assert_eq!(parse_uninstall(r"C:\K\|").unwrap().token, "");
        assert_eq!(parse_uninstall("|x"), None);
        let full = format!(r"C:\K\|kun_x|{NEW}|{UC}|0.1.0|{OLD}");
        let d = parse_uninstall(&full).unwrap();
        assert_eq!(d.token, "kun_x");
        assert_eq!(d.upgrading, NEW);
        assert_eq!(d.upgrade_code, UC);
        assert_eq!(d.version, "0.1.0");
        assert_eq!(d.product_code, OLD);
        // Empty token + no upgrade (plain msiexec /x without the token).
        let s = format!(r"C:\K\|||{UC}|0.1.0|{OLD}");
        let d = parse_uninstall(&s).unwrap();
        assert_eq!((d.token, d.upgrading), ("", ""));
    }

    #[test]
    fn guids_and_versions() {
        assert!(is_guid(UC));
        assert!(!is_guid("{x}"));
        assert!(!is_guid("6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D10"));
        assert!(!is_guid("{6E3A0F43-8A1B-4C55-9B5D-2F4C7E1A9D1G}"));
        assert!(version_newer("0.1.1", "0.1.0"));
        assert!(version_newer("1.0", "0.9.9"));
        assert!(!version_newer("0.1.0", "0.1.0"));
        assert!(!version_newer("0.1.0.5", "0.1.1"));
        assert!(!version_newer("x", "0.1.0"));
    }

    fn data(upgrading: &str) -> String {
        format!(r"C:\K\||{upgrading}|{UC}|0.1.0|{OLD}")
    }

    #[test]
    fn genuine_upgrade_skips_the_token() {
        let s = data(NEW);
        let d = parse_uninstall(&s).unwrap();
        let facts = UpgradeFacts {
            related: vec![OLD.into(), NEW.to_ascii_lowercase()],
            upgrading_installed: true,
            upgrading_version: Some("0.1.1".into()),
        };
        assert_eq!(upgrade_verified(&d, &facts), Ok(()));
    }

    /// V-M2: `msiexec /x {PC} UPGRADINGPRODUCTCODE={x}` must still need the token.
    #[test]
    fn forged_upgrade_claims_are_refused() {
        let genuine = UpgradeFacts {
            related: vec![OLD.into(), NEW.into()],
            upgrading_installed: true,
            upgrading_version: Some("0.1.1".into()),
        };
        // Not a Kestrel product.
        let s = data("{99999999-9999-9999-9999-999999999999}");
        assert!(upgrade_verified(&parse_uninstall(&s).unwrap(), &genuine).is_err());
        // Our own product code.
        let s = data(OLD);
        assert!(upgrade_verified(&parse_uninstall(&s).unwrap(), &genuine).is_err());
        // Garbage.
        let s = data("1");
        assert!(upgrade_verified(&parse_uninstall(&s).unwrap(), &genuine).is_err());
        let s = data(NEW);
        let d = parse_uninstall(&s).unwrap();
        // Related but not installed (e.g. only advertised / unknown).
        let mut f = genuine.clone();
        f.upgrading_installed = false;
        assert!(upgrade_verified(&d, &f).is_err());
        // Not newer.
        let mut f = genuine.clone();
        f.upgrading_version = Some("0.1.0".into());
        assert!(upgrade_verified(&d, &f).is_err());
        let mut f = genuine.clone();
        f.upgrading_version = None;
        assert!(upgrade_verified(&d, &f).is_err());
        // No upgrade claimed at all.
        let s = data("");
        assert!(upgrade_verified(&parse_uninstall(&s).unwrap(), &genuine).is_err());
    }
}
