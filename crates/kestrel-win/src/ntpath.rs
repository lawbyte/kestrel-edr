//! NT object-manager paths → Win32 paths.
//!
//! Kernel ETW reports file and image names as `\Device\HarddiskVolume3\…`.
//! The agent builds a device table once (QueryDosDeviceW for every drive
//! letter, refreshed periodically and on misses) and maps paths with
//! [`DeviceMap::to_dos`]. Everything here is pure so it can be unit-tested.

use std::collections::HashMap;

/// Drive-letter table: lower-cased NT device name (e.g. `\device\harddiskvolume3`) → `C:`.
#[derive(Debug, Clone, Default)]
pub struct DeviceMap {
    devices: HashMap<String, String>,
    /// `%SystemRoot%` as a Win32 path (for `\SystemRoot\…`).
    system_root: String,
}

impl DeviceMap {
    pub fn new(system_root: &str) -> Self {
        DeviceMap {
            devices: HashMap::new(),
            system_root: system_root.trim_end_matches('\\').to_string(),
        }
    }

    /// Register `drive` (e.g. "C:") for `device` (e.g. `\Device\HarddiskVolume3`).
    pub fn insert(&mut self, device: &str, drive: &str) {
        self.devices.insert(
            device.trim_end_matches('\\').to_ascii_lowercase(),
            drive.to_string(),
        );
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Lower-cased NT device for a drive (`'C'` → `\device\harddiskvolume3`).
    pub fn device_for_drive(&self, drive: char) -> Option<String> {
        let want = format!("{}:", drive.to_ascii_uppercase());
        self.devices
            .iter()
            .find(|(_, d)| d.eq_ignore_ascii_case(&want))
            .map(|(dev, _)| dev.clone())
    }

    /// Win32 path → lower-cased NT path (`C:\Users\x` →
    /// `\device\harddiskvolume3\users\x`, `\\srv\share\x` →
    /// `\device\mup\srv\share\x`). None when the drive is unknown.
    pub fn to_nt_lower(&self, win32: &str) -> Option<String> {
        let p = win32.replace('/', "\\");
        let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
        if let Some(unc) = p.strip_prefix(r"\\") {
            return Some(format!(r"\device\mup\{}", unc.to_ascii_lowercase()));
        }
        let b = p.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            let dev = self.device_for_drive(b[0] as char)?;
            return Some(format!("{dev}{}", p[2..].to_ascii_lowercase()));
        }
        None
    }

    /// Convert an NT path to a Win32 path. Returns the input unchanged when no
    /// rule applies (so callers never lose information). The boolean is false
    /// when the device prefix was unknown (caller may refresh the table).
    pub fn to_dos(&self, nt: &str) -> (String, bool) {
        if nt.is_empty() {
            return (String::new(), true);
        }
        // Already Win32.
        if nt.len() >= 2 && nt.as_bytes()[1] == b':' {
            return (nt.to_string(), true);
        }
        let lower = nt.to_ascii_lowercase();
        for prefix in [r"\??\unc\", r"\\?\unc\"] {
            if lower.starts_with(prefix) {
                return (format!(r"\\{}", &nt[prefix.len()..]), true);
            }
        }
        for prefix in [r"\??\", r"\\?\", r"\dosdevices\", r"\global??\"] {
            if lower.starts_with(prefix) {
                return (nt[prefix.len()..].to_string(), true);
            }
        }
        if lower.starts_with(r"\systemroot\") || lower == r"\systemroot" {
            let rest = &nt[r"\systemroot".len()..];
            return (format!("{}{}", self.system_root, rest), true);
        }
        // Network redirectors: \Device\Mup\server\share\…, \Device\LanmanRedirector\…
        for prefix in [
            r"\device\mup\",
            r"\device\lanmanredirector\",
            r"\device\webdavredirector\",
        ] {
            if lower.starts_with(prefix) {
                let mut rest = &nt[prefix.len()..];
                // \Device\LanmanRedirector\;Z:000000000001a2b3\server\share
                if rest.starts_with(';') {
                    if let Some(i) = rest.find('\\') {
                        rest = &rest[i + 1..];
                    }
                }
                return (format!(r"\\{rest}"), true);
            }
        }
        if let Some(after) = lower.strip_prefix(r"\device\") {
            // Longest device-name match: \Device\HarddiskVolume1 vs …Volume12.
            let dev_end = after
                .find('\\')
                .map(|i| i + r"\device\".len())
                .unwrap_or(lower.len());
            let dev = &lower[..dev_end];
            if let Some(drive) = self.devices.get(dev) {
                return (format!("{}{}", drive, &nt[dev_end..]), true);
            }
            return (nt.to_string(), false);
        }
        (nt.to_string(), true)
    }
}

/// Normalise a Win32 path for comparisons: backslashes, no `\\?\`, lower-case.
pub fn norm_key(path: &str) -> String {
    let p = path.replace('/', "\\");
    let p = p.strip_prefix(r"\\?\").unwrap_or(&p);
    p.to_ascii_lowercase()
}

/// Expand `%VAR%` references using `lookup` (used for ProfileImagePath etc.).
pub fn expand_env(s: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('%') {
            let name = &after[..end];
            match lookup(name) {
                Some(v) if !name.is_empty() => out.push_str(&v),
                _ => {
                    out.push('%');
                    out.push_str(name);
                    out.push('%');
                }
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map() -> DeviceMap {
        let mut m = DeviceMap::new(r"C:\Windows");
        m.insert(r"\Device\HarddiskVolume3", "C:");
        m.insert(r"\Device\HarddiskVolume12", "D:");
        m
    }

    #[test]
    fn volume_paths() {
        let m = map();
        assert_eq!(
            m.to_dos(r"\Device\HarddiskVolume3\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data"),
            (r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data".to_string(), true)
        );
        assert_eq!(
            m.to_dos(r"\device\harddiskvolume12\x.exe"),
            (r"D:\x.exe".to_string(), true)
        );
        // Prefix of a longer device must not match.
        assert!(!m.to_dos(r"\Device\HarddiskVolume1\x").1);
        // Reverse direction.
        assert_eq!(
            m.device_for_drive('c').as_deref(),
            Some(r"\device\harddiskvolume3")
        );
        assert_eq!(
            m.to_nt_lower(r"C:\Users\A\Documents\X.docx").as_deref(),
            Some(r"\device\harddiskvolume3\users\a\documents\x.docx")
        );
        assert_eq!(
            m.to_nt_lower(r"\\Srv\Share\a.txt").as_deref(),
            Some(r"\device\mup\srv\share\a.txt")
        );
        assert_eq!(m.to_nt_lower(r"Q:\x"), None);
        assert_eq!(m.to_dos(r"\Device\HarddiskVolume3").0, "C:");
    }

    #[test]
    fn special_prefixes() {
        let m = map();
        assert_eq!(m.to_dos(r"\??\C:\Windows\x.dll").0, r"C:\Windows\x.dll");
        assert_eq!(
            m.to_dos(r"\SystemRoot\System32\ntdll.dll").0,
            r"C:\Windows\System32\ntdll.dll"
        );
        assert_eq!(
            m.to_dos(r"\Device\Mup\srv\share\a.exe").0,
            r"\\srv\share\a.exe"
        );
        assert_eq!(
            m.to_dos(r"\Device\LanmanRedirector\;Z:0000000000012345\srv\share\a.exe")
                .0,
            r"\\srv\share\a.exe"
        );
        assert_eq!(m.to_dos(r"\??\UNC\srv\share\b").0, r"\\srv\share\b");
        assert_eq!(m.to_dos(r"C:\already\win32").0, r"C:\already\win32");
    }

    #[test]
    fn env_expansion() {
        let f = |n: &str| match n {
            "SystemDrive" => Some("C:".to_string()),
            _ => None,
        };
        assert_eq!(expand_env(r"%SystemDrive%\Users\bob", f), r"C:\Users\bob");
        assert_eq!(expand_env(r"%NOPE%\x", f), r"%NOPE%\x");
        assert_eq!(expand_env("100%", f), "100%");
        assert_eq!(norm_key(r"\\?\C:/Users/A"), r"c:\users\a");
    }
}
