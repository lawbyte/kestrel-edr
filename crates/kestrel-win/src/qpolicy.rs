//! Quarantine / restore path policy (pure). H8.
//!
//! The Windows quarantine runs as SYSTEM with backup semantics, so the
//! *decision* of what it may touch must not depend on anything the user
//! controls:
//! * engine-originated (automatic) quarantine is limited to user-writable /
//!   external locations;
//! * a server command may reach further, but never a Microsoft-signed file
//!   under `%SystemRoot%` / Program Files, never a protected OS process or
//!   security-product image, and never Kestrel's own files;
//! * a restore only goes back to the recorded original path, never into
//!   `%SystemRoot%` / Program Files, and only when the parent directory is
//!   still owned by the same principal class as at quarantine time.
//!
//! The Windows module enforces the filesystem side (no reparse points or hard
//! links on the path, `GetFinalPathNameByHandleW` == requested path, all I/O
//! through the verified handle).

use kestrel_common::PathClass;
use kestrel_detect::protect;
use kestrel_platform::ActionOrigin;

/// Normalise a Win32 path for equality checks: `\`, lower-case, without the
/// `\\?\` / `\\?\UNC\` prefixes and trailing separators.
pub fn normalize_for_compare(p: &str) -> String {
    let p = p.trim().replace('/', "\\");
    let lower = p.to_ascii_lowercase();
    let s = if let Some(r) = lower.strip_prefix(r"\\?\unc\") {
        format!(r"\\{r}")
    } else if let Some(r) = lower.strip_prefix(r"\\?\") {
        r.to_string()
    } else if let Some(r) = lower.strip_prefix(r"\??\") {
        r.to_string()
    } else {
        lower
    };
    let t = s.trim_end_matches('\\');
    if t.len() == 2 && t.as_bytes()[1] == b':' {
        format!("{t}\\")
    } else {
        t.to_string()
    }
}

/// Does the final path of an opened handle name the same file as requested?
pub fn same_path(requested: &str, final_path: &str) -> bool {
    !requested.trim().is_empty()
        && normalize_for_compare(requested) == normalize_for_compare(final_path)
}

/// Every ancestor directory of `path` from the volume root down (excluding
/// `path` itself): `C:\a\b\c.exe` → `C:\`, `C:\a`, `C:\a\b`.
pub fn ancestors(path: &str) -> Vec<String> {
    let p = path.replace('/', "\\");
    let p = p.trim_end_matches('\\');
    let (prefix, rest) = if let Some(r) = p.strip_prefix(r"\\?\") {
        (r"\\?\", r)
    } else {
        ("", p)
    };
    let parts: Vec<&str> = rest.split('\\').collect();
    let mut out = Vec::new();
    if parts.len() < 2 {
        return out;
    }
    let mut cur = String::new();
    for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
        if i == 0 {
            cur = format!("{prefix}{part}\\");
        } else if cur.ends_with('\\') {
            cur.push_str(part);
        } else {
            cur.push('\\');
            cur.push_str(part);
        }
        out.push(cur.clone());
    }
    out
}

/// Can `path` be quarantined on behalf of `origin`?
///
/// `microsoft_signed`: the file carries a valid Microsoft signature
/// (computed by the caller only when needed). `own_prefixes`: Kestrel's
/// install / state directories (lower-case is not required).
pub fn quarantine_allowed(
    path: &str,
    origin: ActionOrigin,
    microsoft_signed: bool,
    system_drive: char,
    own_prefixes: &[String],
) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("empty path".into());
    }
    let n = normalize_for_compare(path);
    if n.starts_with(r"\device\") || n.starts_with(r"\\.\") || n.starts_with(r"\\?\") {
        return Err(format!("{path}: device paths are not accepted"));
    }
    if own_prefixes
        .iter()
        .map(|p| normalize_for_compare(p))
        .filter(|p| !p.is_empty())
        .any(|p| n == p || n.starts_with(&format!("{p}\\")))
    {
        return Err(format!("{path} belongs to Kestrel itself"));
    }
    if protect::critical_location_ok(path, system_drive)
        || protect::security_product_location_ok(path, system_drive)
    {
        return Err(format!(
            "{path} is a protected operating-system or security-product image"
        ));
    }
    let class = PathClass::of_with_system_drive(path, system_drive);
    match origin {
        ActionOrigin::Engine | ActionOrigin::Local => {
            if !class.is_user_writable() {
                return Err(format!(
                    "automatic quarantine is limited to user-writable or external locations ({path} is {class:?})"
                ));
            }
        }
        ActionOrigin::ServerCommand => {
            if matches!(
                class,
                PathClass::System | PathClass::Windows | PathClass::ProgramFiles
            ) && microsoft_signed
            {
                return Err(format!(
                    "refusing to quarantine the Microsoft-signed file {path} under %SystemRoot% / Program Files"
                ));
            }
        }
    }
    Ok(())
}

/// Does quarantining `path` for `origin` need the Microsoft-signature check?
pub fn needs_signature_check(path: &str, origin: ActionOrigin, system_drive: char) -> bool {
    origin == ActionOrigin::ServerCommand
        && matches!(
            PathClass::of_with_system_drive(path, system_drive),
            PathClass::System | PathClass::Windows | PathClass::ProgramFiles
        )
}

/// Can a quarantined file go back to `original`?
pub fn restore_allowed(original: &str, system_drive: char) -> Result<(), String> {
    let class = PathClass::of_with_system_drive(original, system_drive);
    if matches!(
        class,
        PathClass::System | PathClass::Windows | PathClass::ProgramFiles
    ) {
        return Err(format!(
            "refusing to restore into {original}: %SystemRoot% and Program Files are never restore targets"
        ));
    }
    let n = normalize_for_compare(original);
    if n.starts_with(r"\device\") || n.starts_with(r"\\.\") {
        return Err("device paths are not restore targets".into());
    }
    Ok(())
}

/// Who owns a directory, for the restore re-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerClass {
    /// SYSTEM, Administrators, TrustedInstaller.
    Privileged,
    /// A specific user / group SID.
    Principal(String),
}

pub fn owner_class(sid: &str) -> OwnerClass {
    let s = crate::sddl::resolve_sid(sid.trim());
    if crate::sddl::is_admin_sid(&s)
        || s.eq_ignore_ascii_case("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
    {
        OwnerClass::Privileged
    } else {
        OwnerClass::Principal(s.to_ascii_uppercase())
    }
}

/// The parent directory may receive the restored file when its owner class
/// is unchanged since quarantine (a directory now owned by someone else was
/// replaced). Entries without a recorded owner (older vaults) only restore
/// into directories owned by a non-privileged principal — the normal case for
/// user folders — never into a privileged one.
pub fn restore_parent_ok(recorded_owner: Option<&str>, current_owner: &str) -> Result<(), String> {
    let cur = owner_class(current_owner);
    match recorded_owner {
        Some(r) => {
            let rec = owner_class(r);
            if rec == cur {
                Ok(())
            } else {
                Err(format!(
                    "the parent directory's owner changed since quarantine ({rec:?} → {cur:?})"
                ))
            }
        }
        None => match cur {
            OwnerClass::Principal(_) => Ok(()),
            OwnerClass::Privileged => Err(
                "the parent directory is owned by SYSTEM/Administrators and no owner was recorded at quarantine time".into(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ActionOrigin::*;

    const OWN: &[String] = &[];

    #[test]
    fn final_path_comparison() {
        assert!(same_path(
            r"C:\Users\bob\Downloads\x.exe",
            r"\\?\C:\Users\Bob\Downloads\X.EXE"
        ));
        assert!(!same_path(
            r"C:\Users\bob\Downloads\x\explorer.exe",
            r"\\?\C:\Windows\explorer.exe"
        ));
        assert!(same_path(r"\\srv\share\a.exe", r"\\?\UNC\srv\share\a.exe"));
        assert!(!same_path("", r"\\?\C:\x"));
        assert_eq!(normalize_for_compare(r"C:\"), r"c:\");
    }

    #[test]
    fn ancestor_chain() {
        assert_eq!(
            ancestors(r"C:\Users\bob\Downloads\x.exe"),
            [
                r"C:\",
                r"C:\Users",
                r"C:\Users\bob",
                r"C:\Users\bob\Downloads"
            ]
        );
        assert_eq!(ancestors(r"C:\x.exe"), [r"C:\"]);
        assert!(ancestors("x.exe").is_empty());
    }

    #[test]
    fn engine_quarantine_is_user_paths_only() {
        let ok = r"C:\Users\bob\Downloads\x\explorer.exe";
        assert!(quarantine_allowed(ok, Engine, false, 'c', OWN).is_ok());
        for bad in [
            r"C:\Windows\explorer.exe",
            r"C:\Windows\System32\winlogon.exe",
            r"C:\Program Files\App\app.exe",
            r"D:\Data\x.exe",
        ] {
            assert!(
                quarantine_allowed(bad, Engine, false, 'c', OWN).is_err(),
                "{bad}"
            );
        }
        // a USB stick / mounted ISO counts as external only via UNC; other volumes are Other
        assert!(quarantine_allowed(r"\\srv\share\x.exe", Engine, false, 'c', OWN).is_ok());
    }

    #[test]
    fn server_commands_reach_further_but_not_os_files() {
        assert!(quarantine_allowed(
            r"C:\Program Files\Evil\evil.exe",
            ServerCommand,
            false,
            'c',
            OWN
        )
        .is_ok());
        assert!(quarantine_allowed(r"D:\Data\x.exe", ServerCommand, false, 'c', OWN).is_ok());
        assert!(quarantine_allowed(
            r"C:\Windows\System32\drivers\x.sys",
            ServerCommand,
            true,
            'c',
            OWN
        )
        .is_err());
        assert!(quarantine_allowed(
            r"C:\Program Files\Microsoft Office\x.dll",
            ServerCommand,
            true,
            'c',
            OWN
        )
        .is_err());
        // never a protected process image, signed or not
        assert!(quarantine_allowed(
            r"C:\Windows\System32\lsass.exe",
            ServerCommand,
            false,
            'c',
            OWN
        )
        .is_err());
        assert!(quarantine_allowed(
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe",
            ServerCommand,
            false,
            'c',
            OWN
        )
        .is_err());
        // never Kestrel itself
        let own = vec![
            r"C:\Program Files\Kestrel".to_string(),
            r"C:\ProgramData\Kestrel".to_string(),
        ];
        assert!(quarantine_allowed(
            r"c:\program files\kestrel\kestrel-agent.exe",
            ServerCommand,
            false,
            'c',
            &own
        )
        .is_err());
        assert!(quarantine_allowed(
            r"C:\ProgramData\Kestrel\agent.toml",
            ServerCommand,
            false,
            'c',
            &own
        )
        .is_err());
        assert!(quarantine_allowed(
            r"C:\ProgramData\KestrelX\a.exe",
            ServerCommand,
            false,
            'c',
            &own
        )
        .is_ok());
        assert!(quarantine_allowed(
            r"\Device\HarddiskVolume3\x.exe",
            ServerCommand,
            false,
            'c',
            OWN
        )
        .is_err());
        assert!(needs_signature_check(
            r"C:\Windows\x.dll",
            ServerCommand,
            'c'
        ));
        assert!(!needs_signature_check(
            r"C:\Users\a\x.dll",
            ServerCommand,
            'c'
        ));
        assert!(!needs_signature_check(r"C:\Windows\x.dll", Engine, 'c'));
    }

    #[test]
    fn restore_targets() {
        assert!(restore_allowed(r"C:\Users\bob\Downloads\x.exe", 'c').is_ok());
        assert!(restore_allowed(r"C:\Windows\System32\version.dll", 'c').is_err());
        assert!(restore_allowed(r"C:\Program Files\App\x.dll", 'c').is_err());
        assert!(restore_allowed(r"C:\Program Files (x86)\App\x.dll", 'c').is_err());
        let bob = "S-1-5-21-1-2-3-1001";
        assert!(restore_parent_ok(Some(bob), bob).is_ok());
        assert!(restore_parent_ok(Some(bob), "S-1-5-21-1-2-3-1002").is_err());
        assert!(restore_parent_ok(Some(bob), "S-1-5-18").is_err());
        assert!(restore_parent_ok(Some("BA"), "S-1-5-32-544").is_ok());
        assert!(restore_parent_ok(None, bob).is_ok());
        assert!(restore_parent_ok(None, "S-1-5-18").is_err());
    }
}
