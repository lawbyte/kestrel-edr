//! SDDL parsing and the state-directory trust decision (pure).
//!
//! H4: `C:\ProgramData\Kestrel` holds the agent's private key, config,
//! outbox, quarantine vault and downloaded updates. Standard users can
//! create folders under `C:\ProgramData`, so a directory that already exists
//! at install / start-up is only trusted when
//! * its owner is SYSTEM or Administrators, and
//! * its DACL (present, not NULL) grants no write / delete / WRITE_DAC /
//!   WRITE_OWNER right to anybody else (including inherit-only ACEs that
//!   would apply to new children).
//!
//! The Windows module reads the descriptor as SDDL
//! (`ConvertSecurityDescriptorToStringSecurityDescriptorW`) and calls
//! [`state_dir_trusted`]; untrusted directories are renamed aside and
//! re-created with [`STATE_DIR_SDDL`].

/// Owner SYSTEM, protected DACL: SYSTEM + Administrators full control,
/// inherited by files and subdirectories; nothing for anybody else.
pub const STATE_DIR_SDDL: &str = "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

pub const SID_SYSTEM: &str = "S-1-5-18";
pub const SID_ADMINS: &str = "S-1-5-32-544";

/// One ACE.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `A` (allow) / `D` (deny) / other type codes kept verbatim.
    pub ace_type: String,
    pub flags: String,
    /// Access mask (codes resolved to bits); `None` if unparseable.
    pub mask: Option<u32>,
    pub sid: String,
}

/// Parsed security descriptor (only what the trust decision needs).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sd {
    pub owner: Option<String>,
    pub group: Option<String>,
    /// `None` = no DACL section; `Some(None)` = NULL DACL (`NO_ACCESS_CONTROL`).
    pub dacl: Option<Option<Vec<Ace>>>,
    pub dacl_protected: bool,
}

/// Bits that let a principal modify the directory, its contents or its security.
pub const WRITE_MASK: u32 = 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100 // FILE_WRITE_ATTRIBUTES
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000 // GENERIC_WRITE
    | 0x0200_0000; // MAXIMUM_ALLOWED

fn code_bits(code: &str) -> Option<u32> {
    Some(match code {
        "GA" => 0x1000_0000,
        "GR" => 0x8000_0000,
        "GW" => 0x4000_0000,
        "GX" => 0x2000_0000,
        "RC" => 0x0002_0000,
        "SD" => 0x0001_0000,
        "WD" => 0x0004_0000,
        "WO" => 0x0008_0000,
        "RP" => 0x0000_0010,
        "WP" => 0x0000_0020,
        "CC" => 0x0000_0001,
        "DC" => 0x0000_0002,
        "LC" => 0x0000_0004,
        "SW" => 0x0000_0008,
        "LO" => 0x0000_0080,
        "DT" => 0x0000_0040,
        "CR" => 0x0000_0100,
        "FA" => 0x001F_01FF,
        "FR" => 0x0012_0089,
        "FW" => 0x0012_0116,
        "FX" => 0x0012_00A0,
        "KA" => 0x000F_003F,
        "KR" => 0x0002_0019,
        "KW" => 0x0002_0006,
        "KX" => 0x0002_0019,
        "NR" | "NW" | "NX" => 0,
        _ => return None,
    })
}

/// Rights field → access mask (`0x1f01ff` or concatenated two-letter codes).
pub fn rights_mask(s: &str) -> Option<u32> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(h, 16).ok();
    }
    if s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty() {
        return s.parse().ok();
    }
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut m = 0u32;
    for i in (0..s.len()).step_by(2) {
        m |= code_bits(s.get(i..i + 2)?)?;
    }
    Some(m)
}

/// SDDL SID alias → SID string (only the aliases that matter here).
pub fn resolve_sid(s: &str) -> String {
    match s {
        "SY" => SID_SYSTEM.into(),
        "BA" => SID_ADMINS.into(),
        "BU" => "S-1-5-32-545".into(),
        "AU" => "S-1-5-11".into(),
        "WD" => "S-1-1-0".into(),
        "IU" => "S-1-5-4".into(),
        "CO" => "S-1-3-0".into(),
        "OW" => "S-1-3-4".into(),
        "LS" => "S-1-5-19".into(),
        "NS" => "S-1-5-20".into(),
        other => other.to_string(),
    }
}

/// SYSTEM or the local Administrators group.
pub fn is_admin_sid(s: &str) -> bool {
    let r = resolve_sid(s.trim());
    r.eq_ignore_ascii_case(SID_SYSTEM) || r.eq_ignore_ascii_case(SID_ADMINS)
}

fn parse_aces(s: &str) -> Result<Vec<Ace>, String> {
    let mut out = Vec::new();
    let mut rest = s;
    while let Some(start) = rest.find('(') {
        let end = rest[start..]
            .find(')')
            .map(|e| start + e)
            .ok_or("unterminated ACE")?;
        let body = &rest[start + 1..end];
        let f: Vec<&str> = body.split(';').collect();
        if f.len() < 6 {
            return Err(format!("malformed ACE ({body})"));
        }
        out.push(Ace {
            ace_type: f[0].to_string(),
            flags: f[1].to_string(),
            mask: rights_mask(f[2]),
            sid: resolve_sid(f[5]),
        });
        rest = &rest[end + 1..];
    }
    Ok(out)
}

/// Parse `O:…G:…D:…S:…` (SACL ignored).
pub fn parse(sddl: &str) -> Result<Sd, String> {
    let mut sd = Sd::default();
    // Split on section markers at the top level (outside parentheses).
    let b = sddl.as_bytes();
    let mut marks: Vec<(usize, u8)> = Vec::new();
    let mut depth = 0i32;
    for i in 0..b.len() {
        match b[i] {
            b'(' => depth += 1,
            b')' => depth -= 1,
            c @ (b'O' | b'G' | b'D' | b'S') if depth == 0 && b.get(i + 1) == Some(&b':') => {
                marks.push((i, c))
            }
            _ => {}
        }
    }
    for (k, &(pos, c)) in marks.iter().enumerate() {
        let end = marks.get(k + 1).map(|m| m.0).unwrap_or(b.len());
        let val = &sddl[pos + 2..end];
        match c {
            b'O' => sd.owner = Some(resolve_sid(val.trim())),
            b'G' => sd.group = Some(resolve_sid(val.trim())),
            b'D' => {
                let flags_end = val.find('(').unwrap_or(val.len());
                let flags = &val[..flags_end];
                sd.dacl_protected = flags.contains('P');
                if flags.contains("NO_ACCESS_CONTROL") {
                    sd.dacl = Some(None);
                } else {
                    sd.dacl = Some(Some(parse_aces(&val[flags_end..])?));
                }
            }
            _ => {}
        }
    }
    Ok(sd)
}

/// Is a directory with this descriptor safe to hold agent state?
/// `Err` explains why not.
pub fn state_dir_trusted(sddl: &str) -> Result<(), String> {
    let sd = parse(sddl)?;
    match sd.owner.as_deref() {
        Some(o) if is_admin_sid(o) => {}
        Some(o) => return Err(format!("owner {o} is not SYSTEM or Administrators")),
        None => return Err("owner unknown".into()),
    }
    let aces = match sd.dacl {
        None => return Err("no DACL".into()),
        Some(None) => return Err("NULL DACL (everyone has full control)".into()),
        Some(Some(a)) => a,
    };
    for a in &aces {
        // Deny ACEs never grant anything; audit/alarm/mandatory-label types are
        // not access grants either.
        if !(a.ace_type == "A" || a.ace_type == "OA") {
            continue;
        }
        if is_admin_sid(&a.sid) {
            continue;
        }
        let mask = a.mask.unwrap_or(u32::MAX);
        if mask & WRITE_MASK != 0 {
            return Err(format!(
                "DACL grants write/delete/ownership rights (0x{mask:x}) to {}",
                a.sid
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn our_descriptor_is_trusted() {
        assert!(state_dir_trusted(STATE_DIR_SDDL).is_ok());
        assert!(state_dir_trusted("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)").is_ok());
        // read-only for users is fine
        assert!(state_dir_trusted(
            "O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
        )
        .is_ok());
        assert!(state_dir_trusted("O:S-1-5-18G:SYD:P(A;OICI;FA;;;S-1-5-32-544)").is_ok());
    }

    #[test]
    fn user_created_directory_is_untrusted() {
        // Pre-created by a standard user: user is the owner (keeps WRITE_DAC).
        let user = "O:S-1-5-21-1-2-3-1001G:S-1-5-21-1-2-3-513D:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;FA;;;S-1-5-21-1-2-3-1001)";
        assert!(state_dir_trusted(user).unwrap_err().contains("owner"));
        // Admin-owned but users may write (default ProgramData inheritance).
        let users_write = "O:BAG:SYD:AI(A;OICIID;FA;;;SY)(A;OICIID;FA;;;BA)(A;OICIID;0x1200a9;;;BU)(A;CIID;DCLCRPCR;;;BU)";
        assert!(state_dir_trusted(users_write)
            .unwrap_err()
            .contains("S-1-5-32-545"));
        // Creator-owner inherit-only full control applies to new children.
        let co = "O:SYD:(A;OICIIO;GA;;;CO)(A;OICI;FA;;;SY)";
        assert!(state_dir_trusted(co).is_err());
        // NULL DACL / no DACL
        assert!(state_dir_trusted("O:SYD:NO_ACCESS_CONTROL").is_err());
        assert!(state_dir_trusted("O:SYG:SY").is_err());
        // Everyone WRITE_DAC
        assert!(state_dir_trusted("O:SYD:P(A;;WD;;;WD)").is_err());
        // Unparseable rights fail closed
        assert!(state_dir_trusted("O:SYD:P(A;;ZZ;;;BU)").is_err());
        // Deny ACEs are fine
        assert!(state_dir_trusted("O:SYD:P(D;;FA;;;BU)(A;;FA;;;SY)").is_ok());
    }

    #[test]
    fn masks() {
        assert_eq!(rights_mask("FA"), Some(0x1f01ff));
        assert_eq!(rights_mask("0x1200a9"), Some(0x1200a9));
        assert_eq!(rights_mask("GRGW"), Some(0xC000_0000));
        assert_eq!(rights_mask("XYZ"), None);
        assert_eq!(rights_mask("0x1200a9").unwrap() & WRITE_MASK, 0);
    }
}
