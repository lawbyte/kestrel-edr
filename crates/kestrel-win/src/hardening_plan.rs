//! Pure decisions for the credential-protection hardening controls
//! (`win::hardening`). Sources (verified 2026-10-21):
//!
//! * LSA protection: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL`,
//!   `1` = with UEFI lock, `2` = without UEFI lock, "only enforced on
//!   Windows 11 build 22H2 and later"; needs a restart; verify with WinInit
//!   event 12 — <https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection>.
//!   Running state: `GetProcessInformation(ProcessProtectionLevelInfo)` →
//!   `PROTECTION_LEVEL_LSA_LIGHT` —
//!   <https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_protection_level_information>.
//! * WDigest: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`
//!   `UseLogonCredential` (DWORD); absent = 0 on Windows 8.1 / 2012 R2 and
//!   later — MSRC "An Overview of KB2871997"
//!   (<https://msrc.microsoft.com/blog/2014/06/an-overview-of-kb2871997>),
//!   CISA CM0087.
//! * ASR "Block credential stealing from LSASS"
//!   `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`: not applicable when LSA
//!   protection is on / Defender is not the active AV —
//!   <https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference>.
//! * Vulnerable driver blocklist: "enabled by default for all devices since
//!   the Windows 11 2022 update … also enforced when either memory integrity
//!   (HVCI), Smart App Control, or S mode is active" —
//!   <https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules>.
//!   Microsoft Learn documents **no registry value** for the user toggle
//!   (`CI\Config\VulnerableDriverBlocklistEnable` appears only in third-party
//!   write-ups), so Kestrel reports "enforced" only when HVCI is running
//!   (`Win32_DeviceGuard.SecurityServicesRunning` contains 2 —
//!   <https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity>)
//!   and "unknown" otherwise.

/// First Windows 11 22H2 build (RunAsPPL = 2 is enforced from here on).
pub const BUILD_WIN11_22H2: u32 = 22621;
/// Windows 8.1 / Server 2012 R2 (WDigest cleartext off by default).
pub const BUILD_WIN81: u32 = 9600;

pub const WDIGEST_KEY: &str = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest";
pub const WDIGEST_VALUE: &str = "UseLogonCredential";
pub const LSA_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Lsa";
pub const RUN_AS_PPL: &str = "RunAsPPL";
pub const TASK_SCHEDULER_OPERATIONAL: &str = "Microsoft-Windows-TaskScheduler/Operational";
pub const DEVICE_GUARD_NS: &str = r"root\Microsoft\Windows\DeviceGuard";
/// `SecurityServicesRunning` value for memory integrity (HVCI).
pub const SECURITY_SERVICE_HVCI: u32 = 2;

/// Build number from `OsInfo.build` ("10.0.26100.4652" → 26100).
pub fn parse_build(build: &str) -> u32 {
    build
        .split('.')
        .nth(2)
        .and_then(|b| b.parse().ok())
        .unwrap_or(0)
}

/// Is cleartext WDigest caching off?
pub fn wdigest_in_effect(value: Option<u32>, build: u32) -> bool {
    match value {
        Some(v) => v == 0,
        None => build >= BUILD_WIN81,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LsaWrite {
    /// Already configured (1 or 2): never touch (never downgrade a UEFI lock).
    Keep,
    /// Write `RunAsPPL = 2` (no UEFI lock, reversible).
    Write2,
    /// OS too old for value 2; the agent never sets the UEFI-locked 1 itself.
    Unsupported,
}

pub fn lsa_write(current: Option<u32>, build: u32) -> LsaWrite {
    match current {
        Some(1) | Some(2) => LsaWrite::Keep,
        _ if build < BUILD_WIN11_22H2 => LsaWrite::Unsupported,
        _ => LsaWrite::Write2,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LsaStatus {
    /// LSASS runs as PPL right now.
    pub in_effect: bool,
    /// Configured but not running yet (a reboot is needed; never triggered by Kestrel).
    pub pending_reboot: bool,
    /// The running state could not be read.
    pub unknown: bool,
}

/// `running`: `Some(PPL?)` from the process query, `None` if unavailable.
pub fn lsa_status(running: Option<bool>, configured: Option<u32>, build: u32) -> LsaStatus {
    let effective_cfg = match configured {
        Some(1) => true,
        Some(2) => build >= BUILD_WIN11_22H2,
        _ => false,
    };
    match running {
        Some(true) => LsaStatus {
            in_effect: true,
            ..Default::default()
        },
        Some(false) => LsaStatus {
            pending_reboot: effective_cfg,
            ..Default::default()
        },
        None => LsaStatus {
            unknown: true,
            ..Default::default()
        },
    }
}

/// The LSASS ASR rule is only meaningful with Defender as the active AV and
/// LSA protection not already running.
pub fn asr_lsass_applicable(defender_active: bool, lsa_ppl_running: bool) -> bool {
    defender_active && !lsa_ppl_running
}

/// `Some(true)` = blocklist enforced (HVCI running); `None` = unknown.
pub fn driver_blocklist(security_services_running: Option<&[u32]>) -> Option<bool> {
    match security_services_running {
        Some(v) if v.contains(&SECURITY_SERVICE_HVCI) => Some(true),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds() {
        assert_eq!(parse_build("10.0.26100.4652"), 26100);
        assert_eq!(parse_build("10.0.19045"), 19045);
        assert_eq!(parse_build("garbage"), 0);
    }

    #[test]
    fn wdigest() {
        assert!(wdigest_in_effect(Some(0), 19045));
        assert!(!wdigest_in_effect(Some(1), 26100));
        assert!(wdigest_in_effect(None, 26100));
        assert!(!wdigest_in_effect(None, 7601));
    }

    #[test]
    fn lsa() {
        assert_eq!(lsa_write(Some(1), 26100), LsaWrite::Keep);
        assert_eq!(lsa_write(Some(2), 26100), LsaWrite::Keep);
        assert_eq!(lsa_write(None, 26100), LsaWrite::Write2);
        assert_eq!(lsa_write(Some(0), 22621), LsaWrite::Write2);
        assert_eq!(lsa_write(None, 19045), LsaWrite::Unsupported);
        // configured, not yet running → pending reboot
        let s = lsa_status(Some(false), Some(2), 26100);
        assert!(s.pending_reboot && !s.in_effect);
        // value 2 on an OS that ignores it is not "pending"
        assert!(!lsa_status(Some(false), Some(2), 19045).pending_reboot);
        assert!(lsa_status(Some(false), Some(1), 19045).pending_reboot);
        assert!(lsa_status(Some(true), None, 26100).in_effect);
        assert!(lsa_status(None, Some(2), 26100).unknown);
        assert_eq!(lsa_status(Some(false), None, 26100), LsaStatus::default());
    }

    #[test]
    fn asr_and_blocklist() {
        assert!(asr_lsass_applicable(true, false));
        assert!(!asr_lsass_applicable(true, true));
        assert!(!asr_lsass_applicable(false, false));
        assert_eq!(driver_blocklist(Some(&[1, 2])), Some(true));
        assert_eq!(driver_blocklist(Some(&[1])), None);
        assert_eq!(driver_blocklist(Some(&[])), None);
        assert_eq!(driver_blocklist(None), None);
    }
}
