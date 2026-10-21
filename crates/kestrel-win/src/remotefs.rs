//! Pure helpers for the Windows remote file manager (`RemoteFs`): drive
//! enumeration rules, labels, protected roots. Platform independent and
//! unit-tested everywhere; the Win32 calls are in `win::remote_fs`.

use std::path::{Path, PathBuf};

// GetDriveTypeW results (winbase.h; verified against windows-sys 0.61
// `Win32::Storage::FileSystem::DRIVE_*`).
pub const DRIVE_UNKNOWN: u32 = 0;
pub const DRIVE_NO_ROOT_DIR: u32 = 1;
pub const DRIVE_REMOVABLE: u32 = 2;
pub const DRIVE_FIXED: u32 = 3;
pub const DRIVE_REMOTE: u32 = 4;
pub const DRIVE_CDROM: u32 = 5;
pub const DRIVE_RAMDISK: u32 = 6;

/// Drive letters present in a `GetLogicalDrives` bit mask (bit 0 = A:).
pub fn drive_letters(mask: u32) -> Vec<char> {
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| (b'A' + i) as char)
        .collect()
}

/// Listed in the file manager? Network drives and letters without a root
/// directory are omitted.
pub fn include_drive(drive_type: u32) -> bool {
    !matches!(drive_type, DRIVE_REMOTE | DRIVE_NO_ROOT_DIR)
}

/// Media that may be empty / slow to spin up: their volume and size queries
/// run with a timeout and errors are ignored.
pub fn is_slow_media(drive_type: u32) -> bool {
    matches!(drive_type, DRIVE_REMOVABLE | DRIVE_CDROM | DRIVE_UNKNOWN)
}

/// Generic label for a drive type.
pub fn drive_type_label(drive_type: u32) -> &'static str {
    match drive_type {
        DRIVE_FIXED => "Local Disk",
        DRIVE_REMOVABLE => "Removable",
        DRIVE_CDROM => "CD-ROM",
        DRIVE_RAMDISK => "RAM Disk",
        DRIVE_REMOTE => "Network Drive",
        _ => "Drive",
    }
}

/// The label shown for a drive: its volume label when it has one, else the
/// generic type label.
pub fn drive_label(drive_type: u32, volume_label: Option<&str>) -> String {
    match volume_label.map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v.chars().filter(|c| !c.is_control()).take(64).collect(),
        None => drive_type_label(drive_type).to_string(),
    }
}

/// Drive letter of a validated remote path (`X:\…`), upper-case.
pub fn drive_of(win_path: &str) -> Option<char> {
    let b = win_path.as_bytes();
    (b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':')
        .then(|| (b[0] as char).to_ascii_uppercase())
}

/// Refusal message for a path on a drive of `drive_type` (`None` = allowed).
pub fn drive_refusal(drive: char, drive_type: u32) -> Option<String> {
    match drive_type {
        DRIVE_REMOTE => Some(format!(
            "{drive}: is a network drive; the agent does not open network paths"
        )),
        DRIVE_NO_ROOT_DIR => Some(format!("drive {drive}: does not exist on this device")),
        _ => None,
    }
}

/// Is `p` a drive root or shorter (`C:\`, `C:`, `\`)? Such a folder is never
/// used as a protected root (it would protect a whole volume).
fn is_root_like(p: &Path) -> bool {
    let s = p.to_string_lossy();
    let t = s.trim_end_matches(['\\', '/']);
    t.is_empty() || (t.len() == 2 && t.as_bytes()[1] == b':')
}

/// Protected roots: the agent's install folder (folder of the running exe),
/// its state folder, and the default install / state folders on the system
/// drive. De-duplicated case-insensitively; root-like entries dropped.
pub fn protected_roots_from(
    exe_dir: Option<&Path>,
    state_dir: &Path,
    system_drive: char,
) -> Vec<PathBuf> {
    let d = system_drive.to_ascii_uppercase();
    let mut cands: Vec<PathBuf> = Vec::new();
    if let Some(e) = exe_dir {
        cands.push(e.to_path_buf());
    }
    cands.push(state_dir.to_path_buf());
    cands.push(PathBuf::from(format!(r"{d}:\Program Files\Kestrel")));
    cands.push(PathBuf::from(format!(r"{d}:\ProgramData\Kestrel")));
    let mut out: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for c in cands {
        if is_root_like(&c) {
            continue;
        }
        let key = c
            .to_string_lossy()
            .replace('/', "\\")
            .trim_end_matches('\\')
            .to_lowercase();
        if seen.insert(key) {
            out.push(c);
        }
    }
    out
}

/// Why a final path is refused by [`normalize_final_path`].
pub const NOT_LOCAL: &str = "resolves to a network or device path";

/// Normalise the output of `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` to a
/// plain `X:\…` path. Only local drive-letter paths are accepted: `\\?\UNC\…`,
/// `\\server\…`, volume GUID paths without a drive letter
/// (`\\?\Volume{…}\…`), NT device paths (`\Device\…`, `\??\…`) and anything
/// else are refused (M3: SYSTEM must never act on a network object reached
/// through a link).
pub fn normalize_final_path(raw: &str) -> Result<String, String> {
    let s = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    let b = s.as_bytes();
    let drive_ok = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
    if !drive_ok || (b.len() > 2 && b[2] != b'\\') {
        return Err(NOT_LOCAL.to_string());
    }
    if s.contains('/') || s[2..].split('\\').any(|c| c == "." || c == "..") {
        return Err(NOT_LOCAL.to_string());
    }
    let mut out = format!("{}:", (b[0] as char).to_ascii_uppercase());
    let rest = s[2..].trim_end_matches('\\');
    if rest.is_empty() {
        out.push('\\');
    } else {
        out.push_str(rest);
    }
    Ok(out)
}

/// Split a validated `X:\a\b` path into its drive letter and components.
/// `None` for anything that is not an absolute drive path or that contains
/// `.` / `..` / empty components after the root.
pub fn split_drive_path(p: &str) -> Option<(char, Vec<String>)> {
    let b = p.as_bytes();
    if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return None;
    }
    let rest = &p[2..];
    if !rest.is_empty() && !rest.starts_with('\\') {
        return None;
    }
    let mut comps = Vec::new();
    for c in rest.split('\\').skip(1) {
        if c.is_empty() {
            continue;
        }
        if c == "." || c == ".." || c.contains([':', '/']) {
            return None;
        }
        comps.push(c.to_string());
    }
    Some(((b[0] as char).to_ascii_uppercase(), comps))
}

/// Join a final directory path and a child name (`C:\` + `x` → `C:\x`).
pub fn join_final(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn letters_from_mask() {
        assert_eq!(drive_letters(0), Vec::<char>::new());
        assert_eq!(drive_letters(0b1100), vec!['C', 'D']);
        assert_eq!(drive_letters(1 | (1 << 25)), vec!['A', 'Z']);
        assert_eq!(drive_letters(u32::MAX).len(), 26);
    }

    #[test]
    fn types_and_labels() {
        assert!(include_drive(DRIVE_FIXED));
        assert!(include_drive(DRIVE_REMOVABLE));
        assert!(include_drive(DRIVE_CDROM));
        assert!(include_drive(DRIVE_RAMDISK));
        assert!(include_drive(DRIVE_UNKNOWN));
        assert!(!include_drive(DRIVE_REMOTE));
        assert!(!include_drive(DRIVE_NO_ROOT_DIR));
        assert_eq!(drive_label(DRIVE_FIXED, None), "Local Disk");
        assert_eq!(drive_label(DRIVE_REMOVABLE, Some("  ")), "Removable");
        assert_eq!(drive_label(DRIVE_CDROM, None), "CD-ROM");
        assert_eq!(drive_label(DRIVE_RAMDISK, None), "RAM Disk");
        assert_eq!(drive_label(DRIVE_UNKNOWN, None), "Drive");
        assert_eq!(drive_label(DRIVE_FIXED, Some("Data\u{1}")), "Data");
        assert!(is_slow_media(DRIVE_CDROM));
        assert!(!is_slow_media(DRIVE_FIXED));
    }

    #[test]
    fn refusals() {
        assert_eq!(drive_of(r"c:\x"), Some('C'));
        assert_eq!(drive_of("C:"), Some('C'));
        assert_eq!(drive_of(r"\\srv\x"), None);
        assert!(drive_refusal('Z', DRIVE_REMOTE)
            .unwrap()
            .contains("network"));
        assert!(drive_refusal('Q', DRIVE_NO_ROOT_DIR)
            .unwrap()
            .contains("does not exist"));
        assert!(drive_refusal('C', DRIVE_FIXED).is_none());
        assert!(drive_refusal('E', DRIVE_REMOVABLE).is_none());
    }

    #[test]
    fn protected() {
        let r = protected_roots_from(
            Some(Path::new(r"C:\Program Files\Kestrel")),
            Path::new(r"C:\ProgramData\Kestrel"),
            'c',
        );
        assert_eq!(
            r,
            vec![
                PathBuf::from(r"C:\Program Files\Kestrel"),
                PathBuf::from(r"C:\ProgramData\Kestrel")
            ]
        );
        let r = protected_roots_from(
            Some(Path::new(r"D:\tools\kestrel\")),
            Path::new(r"D:\state"),
            'C',
        );
        assert_eq!(r.len(), 4);
        assert_eq!(r[0], PathBuf::from(r"D:\tools\kestrel\"));
        // A drive root is never a protected root.
        let r = protected_roots_from(
            Some(Path::new(r"E:\")),
            Path::new(r"C:\ProgramData\Kestrel"),
            'C',
        );
        assert!(!r.iter().any(|p| p == Path::new(r"E:\")));
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn final_path_normalisation() {
        assert_eq!(normalize_final_path(r"\\?\C:\x").unwrap(), r"C:\x");
        assert_eq!(
            normalize_final_path(r"\\?\c:\Users\bob\").unwrap(),
            r"C:\Users\bob"
        );
        assert_eq!(normalize_final_path(r"\\?\D:\").unwrap(), r"D:\");
        assert_eq!(normalize_final_path(r"\\?\D:").unwrap(), r"D:\");
        assert_eq!(
            normalize_final_path(r"E:\a b\c.txt").unwrap(),
            r"E:\a b\c.txt"
        );
        for bad in [
            r"\\?\UNC\attacker\share\x",
            r"\\attacker\share\x",
            r"\\?\Volume{8d3c0f5e-1111-2222-3333-444455556666}\x",
            r"\Device\Mup\attacker\share",
            r"\Device\HarddiskVolume3\x",
            r"\??\C:\x",
            r"\\.\C:\x",
            r"C:x",
            r"\\?\C:\a\..\b",
            "",
        ] {
            assert!(
                normalize_final_path(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn split_paths() {
        assert_eq!(split_drive_path(r"C:\"), Some(('C', vec![])));
        assert_eq!(split_drive_path("c:"), Some(('C', vec![])));
        assert_eq!(
            split_drive_path(r"d:\a\b c\d.txt"),
            Some(('D', vec!["a".into(), "b c".into(), "d.txt".into()]))
        );
        assert_eq!(
            split_drive_path(r"C:\a\\b\"),
            Some(('C', vec!["a".into(), "b".into()]))
        );
        assert_eq!(split_drive_path(r"C:\a\..\b"), None);
        assert_eq!(split_drive_path(r"C:\a\b:s"), None);
        assert_eq!(split_drive_path(r"C:a"), None);
        assert_eq!(split_drive_path(r"\\srv\x"), None);
        assert_eq!(join_final(r"C:\", "x"), r"C:\x");
        assert_eq!(join_final(r"C:\a", "x"), r"C:\a\x");
    }
}
