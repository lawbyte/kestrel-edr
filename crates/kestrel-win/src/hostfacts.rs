//! Pure helpers for host facts: SMBIOS UUID, boot id, Security Center AV
//! state, product naming, CPU usage.

use serde::{Deserialize, Serialize};

/// Parse the SMBIOS System UUID (type 1, offset 8) from the buffer returned by
/// `GetSystemFirmwareTable('RSMB', 0, …)` (RawSMBIOSData: 8-byte header then
/// the structure table). Formatted like `wmic csproduct get uuid` (SMBIOS
/// ≥ 2.6 byte order: first three fields little-endian).
pub fn smbios_uuid(raw: &[u8]) -> Option<String> {
    if raw.len() < 8 {
        return None;
    }
    let major = raw[1];
    let minor = raw[2];
    let len = u32::from_le_bytes(raw[4..8].try_into().ok()?) as usize;
    let table = raw.get(8..8 + len.min(raw.len() - 8))?;
    let mut i = 0;
    while i + 4 <= table.len() {
        let ty = table[i];
        let flen = table[i + 1] as usize;
        if flen < 4 || i + flen > table.len() {
            return None;
        }
        if ty == 1 && flen >= 0x18 {
            let u = &table[i + 8..i + 24];
            if u.iter().all(|&b| b == 0) || u.iter().all(|&b| b == 0xff) {
                return None;
            }
            let le = (major, minor) >= (2, 6);
            let (a, b, c) = if le {
                (
                    u32::from_le_bytes(u[0..4].try_into().ok()?),
                    u16::from_le_bytes(u[4..6].try_into().ok()?),
                    u16::from_le_bytes(u[6..8].try_into().ok()?),
                )
            } else {
                (
                    u32::from_be_bytes(u[0..4].try_into().ok()?),
                    u16::from_be_bytes(u[4..6].try_into().ok()?),
                    u16::from_be_bytes(u[6..8].try_into().ok()?),
                )
            };
            return Some(format!(
                "{a:08X}-{b:04X}-{c:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
                u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
            ));
        }
        if ty == 127 {
            break;
        }
        // Skip formatted area, then the string set (terminated by "\0\0").
        let mut j = i + flen;
        while j + 1 < table.len() && !(table[j] == 0 && table[j + 1] == 0) {
            j += 1;
        }
        i = j + 2;
    }
    None
}

/// Persisted boot identity (`<state>\boot.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootRecord {
    pub boot_id: String,
    pub boot_time_ms: i64,
}

/// Boot id stable across agent restarts within one boot. The kernel boot time
/// can shift slightly when the clock is corrected, so a previous record is
/// reused when it is within two minutes.
pub fn resolve_boot_id(prev: Option<BootRecord>, boot_time_ms: i64) -> BootRecord {
    if let Some(p) = prev {
        if (p.boot_time_ms - boot_time_ms).abs() < 120_000 {
            return p;
        }
    }
    BootRecord {
        boot_id: format!("b{:x}", boot_time_ms / 1000),
        boot_time_ms,
    }
}

/// Security Center `productState`: bits 12-15 = 1 means real-time protection on.
pub fn av_enabled(product_state: u32) -> bool {
    (product_state >> 12) & 0xF == 1
}

pub fn is_defender_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.contains("windows defender") || n.contains("microsoft defender")
}

/// Pick the active AV from (displayName, productState) rows: enabled products,
/// third-party first.
pub fn pick_active_av(rows: &[(String, u32)]) -> Option<String> {
    let mut on: Vec<&String> = rows
        .iter()
        .filter(|(_, s)| av_enabled(*s))
        .map(|(n, _)| n)
        .collect();
    on.sort_by_key(|n| is_defender_name(n));
    on.dedup();
    if on.is_empty() {
        None
    } else {
        Some(on.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
    }
}

/// The registry ProductName still says "Windows 10" on Windows 11.
pub fn product_name(registry_name: &str, build: u32) -> String {
    if build >= 22000 {
        if let Some(rest) = registry_name.strip_prefix("Windows 10") {
            return format!("Windows 11{rest}");
        }
    }
    registry_name.to_string()
}

/// CPU % of one process between two samples (100-ns units), normalised to all CPUs.
pub fn cpu_pct(prev_cpu: u64, prev_wall: u64, cur_cpu: u64, cur_wall: u64, ncpu: u32) -> f32 {
    let wall = cur_wall.saturating_sub(prev_wall);
    if wall == 0 || ncpu == 0 {
        return 0.0;
    }
    let cpu = cur_cpu.saturating_sub(prev_cpu);
    ((cpu as f64 / wall as f64) * 100.0 / ncpu as f64).clamp(0.0, 100.0) as f32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smbios_with_uuid(major: u8, minor: u8, uuid: [u8; 16]) -> Vec<u8> {
        let mut t = Vec::new();
        // type 0 (BIOS) with one string
        t.extend_from_slice(&[0, 0x18, 0, 0]);
        t.extend_from_slice(&[0u8; 0x14]);
        t.extend_from_slice(b"Vendor\0\0");
        // type 1
        t.extend_from_slice(&[1, 0x1b, 1, 0]);
        t.extend_from_slice(&[1, 2, 3, 4]);
        t.extend_from_slice(&uuid);
        t.extend_from_slice(&[6, 5, 6]);
        t.extend_from_slice(b"Maker\0Model\0\0");
        t.extend_from_slice(&[127, 4, 2, 0, 0, 0]);
        let mut raw = vec![0, major, minor, 0];
        raw.extend_from_slice(&(t.len() as u32).to_le_bytes());
        raw.extend_from_slice(&t);
        raw
    }

    #[test]
    fn smbios() {
        let u = [
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34,
            0x56, 0x78,
        ];
        assert_eq!(
            smbios_uuid(&smbios_with_uuid(3, 4, u)).unwrap(),
            "12345678-1234-5678-9ABC-DEF012345678"
        );
        assert_eq!(
            smbios_uuid(&smbios_with_uuid(2, 4, u)).unwrap(),
            "78563412-3412-7856-9ABC-DEF012345678"
        );
        assert_eq!(smbios_uuid(&smbios_with_uuid(3, 4, [0; 16])), None);
        assert_eq!(smbios_uuid(&[0, 1]), None);
    }

    #[test]
    fn boot() {
        let a = resolve_boot_id(None, 1_700_000_000_000);
        let b = resolve_boot_id(Some(a.clone()), 1_700_000_003_000);
        assert_eq!(a, b);
        let c = resolve_boot_id(Some(a.clone()), 1_700_100_000_000);
        assert_ne!(a.boot_id, c.boot_id);
    }

    #[test]
    fn av() {
        // 397568 = 0x61100 → on (Defender, up to date); 393472 = 0x60100 → off
        assert!(av_enabled(397_568));
        assert!(!av_enabled(393_472));
        let rows = vec![
            ("Windows Defender".to_string(), 397_568),
            ("Sophos Anti-Virus".to_string(), 266_240),
        ];
        assert_eq!(
            pick_active_av(&rows).unwrap(),
            "Sophos Anti-Virus, Windows Defender"
        );
        assert_eq!(pick_active_av(&[("X".into(), 393_472)]), None);
        assert!(is_defender_name("Windows Defender"));
    }

    #[test]
    fn naming() {
        assert_eq!(product_name("Windows 10 Pro", 26100), "Windows 11 Pro");
        assert_eq!(product_name("Windows 10 Pro", 19045), "Windows 10 Pro");
        assert_eq!(
            product_name("Windows Server 2022 Standard", 20348),
            "Windows Server 2022 Standard"
        );
        assert!((cpu_pct(0, 0, 5_000_000, 10_000_000, 2) - 25.0).abs() < 0.01);
        assert_eq!(cpu_pct(0, 5, 1, 5, 4), 0.0);
    }
}
