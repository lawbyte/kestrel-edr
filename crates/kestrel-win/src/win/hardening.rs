//! Hardening pack: deploy (Enforce) or verify (Audit/Off) OS-native controls.
//!
//! Semantics per control:
//! * `Enforce` + flag on  → apply, then verify.
//! * `Enforce` + flag off → revert what Kestrel applied earlier (tracked in
//!   `<state>\hardening_state.json`), then verify.
//! * `Audit` / `Off`      → verify only (no changes), except ASR in `Audit`,
//!   which configures the four rules in Defender's own AuditMode (never
//!   downgrading a rule that is already Block/Warn), as the policy intends.
//!
//! The returned map is control id → *protective control actually in effect*.
//! Credential-protection controls ([`crate::hardening_plan`] has the sources):
//! `wdigest_off`, `lsa_protection` (RunAsPPL=2, never rebooted; in effect
//! only once lsass really runs as PPL), `asr_lsass` (Add-MpPreference, other
//! rules untouched), `vulnerable_driver_blocklist` (report only) and
//! `task_scheduler_log`. Tri-state information is carried by extra keys
//! present only when true: `lsa_protection_pending_reboot`,
//! `lsa_protection_unknown`, `asr_lsass_not_applicable`,
//! `vulnerable_driver_blocklist_unknown`.

use super::evtsub;
use super::util::*;
use crate::applocker::{self, Edit, Want};
use crate::consts::{asr, channel, reg};
use crate::hardening_plan as hp;
use crate::hostfacts::is_defender_name;
use crate::jsonc;
use kestrel_common::{Hardening, HardeningMode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::System::Registry::{
    RegLoadKeyW, RegUnLoadKeyW, HKEY_LOCAL_MACHINE, HKEY_USERS,
};

pub const CONTROLS: [&str; 12] = [
    "block_mshta",
    "block_user_path_exec",
    "disable_run_dialog",
    "terminal_paste_warning",
    "script_block_logging",
    "dpapi_debug_channel",
    "asr_rules",
    "browser_disable_remote_debugging",
    "wdigest_off",
    "asr_lsass",
    "lsa_protection",
    "task_scheduler_log",
];

#[derive(Debug, Default, Serialize, Deserialize)]
struct HState {
    applied: BTreeSet<String>,
    #[serde(default)]
    notes: BTreeMap<String, String>,
}

pub struct Hardener {
    state_path: PathBuf,
    state_dir: PathBuf,
}

const PS_TIMEOUT: Duration = Duration::from_secs(90);

impl Hardener {
    pub fn new(state_dir: &Path) -> Hardener {
        Hardener {
            state_path: state_dir.join("hardening_state.json"),
            state_dir: state_dir.to_path_buf(),
        }
    }

    fn load(&self) -> HState {
        std::fs::read(&self.state_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save(&self, s: &HState) {
        if let Ok(b) = serde_json::to_vec_pretty(s) {
            let _ = write_atomic(&self.state_path, &b);
        }
    }

    /// Apply/verify. `profiles` = user profile dirs; `av` = active AV name.
    pub fn run(
        &self,
        h: &Hardening,
        profiles: &[String],
        av: Option<&str>,
    ) -> BTreeMap<String, bool> {
        let enforce = h.mode == HardeningMode::Enforce;
        let mut st = self.load();
        let mut out = BTreeMap::new();

        // --- AppLocker (block_mshta, block_user_path_exec)
        let want = Want {
            block_mshta: h.block_mshta,
            block_user_path_exec: h.block_user_path_exec,
        };
        let applocker_touched =
            st.applied.contains("block_mshta") || st.applied.contains("block_user_path_exec");
        if enforce && (want.any() || applocker_touched) {
            match self.applocker_apply(want) {
                Ok(()) => {
                    for (k, v) in [
                        ("block_mshta", want.block_mshta),
                        ("block_user_path_exec", want.block_user_path_exec),
                    ] {
                        if v {
                            st.applied.insert(k.into());
                        } else {
                            st.applied.remove(k);
                        }
                    }
                    st.notes.remove("applocker");
                }
                Err(e) => {
                    tracing::warn!("AppLocker: {e}");
                    st.notes.insert("applocker".into(), e);
                }
            }
        }
        let (eff, svc_ok) = applocker_effective();
        out.insert(
            "block_mshta".into(),
            svc_ok
                && applocker::in_effect(
                    &eff,
                    Want {
                        block_mshta: true,
                        block_user_path_exec: false,
                    },
                ),
        );
        out.insert(
            "block_user_path_exec".into(),
            svc_ok
                && applocker::in_effect(
                    &eff,
                    Want {
                        block_mshta: false,
                        block_user_path_exec: true,
                    },
                ),
        );

        // --- NoRun
        if enforce {
            if h.disable_run_dialog {
                set_norun(profiles, true);
                st.applied.insert("disable_run_dialog".into());
            } else if st.applied.remove("disable_run_dialog") {
                set_norun(profiles, false);
            }
        }
        out.insert("disable_run_dialog".into(), norun_in_effect());

        // --- Windows Terminal paste warning
        if enforce && h.terminal_paste_warning {
            terminal_apply(profiles);
            st.applied.insert("terminal_paste_warning".into());
        }
        out.insert(
            "terminal_paste_warning".into(),
            terminal_in_effect(profiles),
        );

        // --- Script block logging
        if enforce {
            if h.script_block_logging {
                for k in [reg::PS_SCRIPT_BLOCK_LOGGING, reg::PWSH_SCRIPT_BLOCK_LOGGING] {
                    if let Ok(key) = reg_create(HKEY_LOCAL_MACHINE, k) {
                        let _ = reg_set_dword(&key, "EnableScriptBlockLogging", 1);
                    }
                }
                st.applied.insert("script_block_logging".into());
            } else if st.applied.remove("script_block_logging") {
                for k in [reg::PS_SCRIPT_BLOCK_LOGGING, reg::PWSH_SCRIPT_BLOCK_LOGGING] {
                    if let Some(key) = reg_open(HKEY_LOCAL_MACHINE, k, true) {
                        reg_delete_value(&key, "EnableScriptBlockLogging");
                    }
                }
            }
        }
        out.insert(
            "script_block_logging".into(),
            reg_open(HKEY_LOCAL_MACHINE, reg::PS_SCRIPT_BLOCK_LOGGING, false)
                .and_then(|k| reg_get_dword(&k, "EnableScriptBlockLogging"))
                == Some(1),
        );

        // --- DPAPI debug channel
        if enforce {
            if h.dpapi_debug_channel {
                if let Err(e) = evtsub::set_channel_enabled(channel::DPAPI_DEBUG, true) {
                    st.notes.insert("dpapi_debug_channel".into(), e.to_string());
                }
                st.applied.insert("dpapi_debug_channel".into());
            } else if st.applied.remove("dpapi_debug_channel") {
                let _ = evtsub::set_channel_enabled(channel::DPAPI_DEBUG, false);
            }
        }
        out.insert(
            "dpapi_debug_channel".into(),
            evtsub::channel_enabled(channel::DPAPI_DEBUG).unwrap_or(false),
        );

        // --- ASR (Defender only)
        let defender = av
            .map(|a| a.split(", ").next().map(is_defender_name).unwrap_or(false))
            .unwrap_or(false)
            || (av.is_none() && defender_running());
        if defender {
            if h.asr_rules && h.mode != HardeningMode::Off {
                match asr_apply(enforce) {
                    Ok(()) => {
                        st.applied.insert("asr_rules".into());
                        st.notes.remove("asr_rules");
                    }
                    Err(e) => {
                        st.notes.insert("asr_rules".into(), e);
                    }
                }
            }
            out.insert("asr_rules".into(), asr_in_effect());
        } else {
            st.notes.insert(
                "asr_rules".into(),
                "not applicable: Microsoft Defender is not the active antivirus".into(),
            );
            out.insert("asr_rules".into(), false);
        }

        // --- Browser remote debugging policy
        let browsers = [
            reg::CHROME_POLICIES,
            reg::EDGE_POLICIES,
            reg::BRAVE_POLICIES,
        ];
        if enforce {
            if h.browser_disable_remote_debugging {
                for k in browsers {
                    if let Ok(key) = reg_create(HKEY_LOCAL_MACHINE, k) {
                        let _ = reg_set_dword(&key, reg::REMOTE_DEBUGGING_ALLOWED, 0);
                    }
                }
                st.applied.insert("browser_disable_remote_debugging".into());
            } else if st.applied.remove("browser_disable_remote_debugging") {
                for k in browsers {
                    if let Some(key) = reg_open(HKEY_LOCAL_MACHINE, k, true) {
                        reg_delete_value(&key, reg::REMOTE_DEBUGGING_ALLOWED);
                    }
                }
            }
        }
        let rd = |k: &str| {
            reg_open(HKEY_LOCAL_MACHINE, k, false)
                .and_then(|key| reg_get_dword(&key, reg::REMOTE_DEBUGGING_ALLOWED))
                == Some(0)
        };
        out.insert(
            "browser_disable_remote_debugging".into(),
            rd(reg::CHROME_POLICIES) && rd(reg::EDGE_POLICIES),
        );

        self.credential_controls(h, defender, &mut st, &mut out);

        for c in CONTROLS {
            out.entry(c.to_string()).or_insert(false);
        }
        self.save(&st);
        out
    }

    /// WDigest, LSA protection, ASR LSASS, vulnerable-driver blocklist
    /// (report only) and the TaskScheduler Operational channel. Same
    /// Audit/Enforce semantics as above. Extra status flags (inserted only
    /// when true): `lsa_protection_pending_reboot`, `lsa_protection_unknown`,
    /// `asr_lsass_not_applicable`, `vulnerable_driver_blocklist_unknown`.
    fn credential_controls(
        &self,
        h: &Hardening,
        defender: bool,
        st: &mut HState,
        out: &mut BTreeMap<String, bool>,
    ) {
        let enforce = h.mode == HardeningMode::Enforce;
        let build = hp::parse_build(&super::host::os_info().build);

        // --- WDigest UseLogonCredential = 0
        let wdigest = || {
            reg_open(HKEY_LOCAL_MACHINE, hp::WDIGEST_KEY, false)
                .and_then(|k| reg_get_dword(&k, hp::WDIGEST_VALUE))
        };
        if enforce {
            if h.wdigest_off {
                if wdigest() != Some(0) {
                    match reg_create(HKEY_LOCAL_MACHINE, hp::WDIGEST_KEY)
                        .and_then(|k| reg_set_dword(&k, hp::WDIGEST_VALUE, 0))
                    {
                        Ok(()) => {
                            st.notes.remove("wdigest_off");
                        }
                        Err(e) => {
                            st.notes.insert("wdigest_off".into(), e.to_string());
                        }
                    }
                }
                st.applied.insert("wdigest_off".into());
            } else if st.applied.remove("wdigest_off") && wdigest() == Some(0) {
                // Back to the OS default (absent = 0 on 8.1+): no security change.
                if let Some(k) = reg_open(HKEY_LOCAL_MACHINE, hp::WDIGEST_KEY, true) {
                    reg_delete_value(&k, hp::WDIGEST_VALUE);
                }
            }
        }
        out.insert(
            "wdigest_off".into(),
            hp::wdigest_in_effect(wdigest(), build),
        );

        // --- LSA protection (RunAsPPL = 2; never rebooted by Kestrel)
        let run_as_ppl = || {
            reg_open(HKEY_LOCAL_MACHINE, hp::LSA_KEY, false)
                .and_then(|k| reg_get_dword(&k, hp::RUN_AS_PPL))
        };
        if enforce {
            if h.lsa_protection {
                match hp::lsa_write(run_as_ppl(), build) {
                    hp::LsaWrite::Keep => {}
                    hp::LsaWrite::Write2 => {
                        match reg_open(HKEY_LOCAL_MACHINE, hp::LSA_KEY, true)
                            .ok_or_else(|| "cannot open the Lsa key".to_string())
                            .and_then(|k| {
                                reg_set_dword(&k, hp::RUN_AS_PPL, 2).map_err(|e| e.to_string())
                            }) {
                            Ok(()) => {
                                st.applied.insert("lsa_protection".into());
                                st.notes.insert(
                                    "lsa_protection".into(),
                                    "RunAsPPL=2 set; takes effect at the next reboot".into(),
                                );
                            }
                            Err(e) => {
                                st.notes.insert("lsa_protection".into(), e);
                            }
                        }
                    }
                    hp::LsaWrite::Unsupported => {
                        st.notes.insert(
                            "lsa_protection".into(),
                            format!("RunAsPPL=2 needs Windows 11 22H2+ (build {build}); the UEFI-locked value 1 is never set automatically"),
                        );
                    }
                }
            } else if st.applied.remove("lsa_protection") && run_as_ppl() == Some(2) {
                // Only undo what Kestrel set (2); never touch an admin's 1.
                if let Some(k) = reg_open(HKEY_LOCAL_MACHINE, hp::LSA_KEY, true) {
                    reg_delete_value(&k, hp::RUN_AS_PPL);
                }
            }
        }
        let lsa = hp::lsa_status(lsass_ppl_running(), run_as_ppl(), build);
        out.insert("lsa_protection".into(), lsa.in_effect);
        if lsa.pending_reboot {
            out.insert("lsa_protection_pending_reboot".into(), true);
        }
        if lsa.unknown {
            out.insert("lsa_protection_unknown".into(), true);
        }

        // --- ASR LSASS rule (Add semantics: other rules untouched)
        if hp::asr_lsass_applicable(defender, lsa.in_effect) {
            let cur = asr_current();
            let action = cur
                .as_ref()
                .ok()
                .and_then(|m| m.get(asr::LSASS).copied())
                .unwrap_or(asr::ACTION_OFF);
            let mut changed = false;
            if enforce {
                if h.asr_lsass {
                    if cur.is_ok() && action != asr::ACTION_BLOCK {
                        changed = true;
                        match asr_add(&[asr::LSASS], "Enabled") {
                            Ok(()) => {
                                st.applied.insert("asr_lsass".into());
                                st.notes.remove("asr_lsass");
                            }
                            Err(e) => {
                                st.notes.insert("asr_lsass".into(), e);
                            }
                        }
                    }
                } else if st.applied.remove("asr_lsass") && !h.asr_rules {
                    changed = true;
                    let _ = asr_remove(asr::LSASS);
                }
            }
            let now = if changed {
                asr_current().ok().and_then(|m| m.get(asr::LSASS).copied())
            } else {
                cur.ok().and_then(|m| m.get(asr::LSASS).copied())
            };
            out.insert("asr_lsass".into(), now == Some(asr::ACTION_BLOCK));
        } else {
            // Microsoft: not applicable with LSA protection on / another AV.
            out.insert("asr_lsass".into(), false);
            out.insert("asr_lsass_not_applicable".into(), true);
        }

        // --- Vulnerable driver blocklist (report only, never toggled)
        if h.report_vulnerable_driver_blocklist {
            match hp::driver_blocklist(hvci_services_running().as_deref()) {
                Some(on) => {
                    out.insert("vulnerable_driver_blocklist".into(), on);
                }
                None => {
                    out.insert("vulnerable_driver_blocklist".into(), false);
                    out.insert("vulnerable_driver_blocklist_unknown".into(), true);
                }
            }
        }

        // --- TaskScheduler Operational channel (persistence telemetry)
        if enforce {
            if h.task_scheduler_log {
                // Only record (and later revert) what Kestrel itself enabled.
                if evtsub::channel_enabled(hp::TASK_SCHEDULER_OPERATIONAL) != Some(true) {
                    match evtsub::set_channel_enabled(hp::TASK_SCHEDULER_OPERATIONAL, true) {
                        Ok(()) => {
                            st.applied.insert("task_scheduler_log".into());
                            st.notes.remove("task_scheduler_log");
                        }
                        Err(e) => {
                            st.notes.insert("task_scheduler_log".into(), e.to_string());
                        }
                    }
                }
            } else if st.applied.remove("task_scheduler_log") {
                let _ = evtsub::set_channel_enabled(hp::TASK_SCHEDULER_OPERATIONAL, false);
            }
        }
        out.insert(
            "task_scheduler_log".into(),
            evtsub::channel_enabled(hp::TASK_SCHEDULER_OPERATIONAL).unwrap_or(false),
        );
    }

    fn write_local_policy(&self, xml: &str) -> Result<(), String> {
        let path = self.state_dir.join("applocker-policy.xml");
        std::fs::write(&path, xml.as_bytes()).map_err(|e| e.to_string())?;
        let script = format!(
            "$ErrorActionPreference='Stop'; Import-Module AppLocker; Set-AppLockerPolicy -XmlPolicy {}",
            ps_quote(&path.to_string_lossy())
        );
        let r =
            run_powershell(&script, PS_TIMEOUT).map_err(|e| format!("Set-AppLockerPolicy: {e}"));
        let _ = std::fs::remove_file(&path);
        let r = r?;
        if r.code != 0 {
            return Err(format!("Set-AppLockerPolicy failed: {}", r.stderr.trim()));
        }
        Ok(())
    }

    /// H9: inspect the *effective* policy (local + GPO + MDM) before touching
    /// the local one; never widen a centrally managed allowlist.
    fn applocker_apply(&self, want: Want) -> Result<(), String> {
        let o = run_powershell(
            "$ErrorActionPreference='Stop'; Import-Module AppLocker; ConvertTo-Json -Compress @{local=[string](Get-AppLockerPolicy -Local -Xml); effective=[string](Get-AppLockerPolicy -Effective -Xml)}",
            PS_TIMEOUT,
        )
        .map_err(|e| format!("Get-AppLockerPolicy: {e}"))?;
        if o.code != 0 {
            return Err(format!("Get-AppLockerPolicy failed: {}", o.stderr.trim()));
        }
        #[derive(Deserialize)]
        struct P {
            #[serde(default)]
            local: Option<String>,
            #[serde(default)]
            effective: Option<String>,
        }
        let p: P = serde_json::from_str(o.stdout.trim())
            .map_err(|e| format!("Get-AppLockerPolicy output: {e}"))?;
        let local = p.local.unwrap_or_default();
        // Fail closed: without the effective policy we cannot tell whether
        // a domain policy exists.
        let effective = p
            .effective
            .ok_or("Get-AppLockerPolicy -Effective returned nothing; not changing AppLocker")?;
        let (edit, cleanup) = applocker::plan_edit(local.trim(), effective.trim(), want);
        if let Some(Edit::Write(xml)) = cleanup {
            self.write_local_policy(&xml)?;
        }
        match edit {
            Edit::Unchanged => {}
            Edit::Refused(r) => return Err(r),
            Edit::Write(xml) => self.write_local_policy(&xml)?,
        }
        if want.any() {
            // AppLocker is enforced by the Application Identity service.
            let sc = format!(r"{}\System32\sc.exe", system_root());
            let _ = run_cmd(
                &sc,
                &["config", "AppIDSvc", "start=", "auto"],
                Duration::from_secs(30),
            );
            let _ = run_cmd(&sc, &["start", "AppIDSvc"], Duration::from_secs(30));
        }
        Ok(())
    }
}

/// (effective policy XML, AppIDSvc running)
fn applocker_effective() -> (String, bool) {
    let script = "$ErrorActionPreference='SilentlyContinue'; Import-Module AppLocker; \
        $x=[string](Get-AppLockerPolicy -Effective -Xml); $s=(Get-Service AppIDSvc).Status; \
        ConvertTo-Json -Compress @{xml=$x; svc=[string]$s}";
    match run_powershell(script, PS_TIMEOUT) {
        Ok(o) => {
            #[derive(Deserialize)]
            struct R {
                #[serde(default)]
                xml: Option<String>,
                #[serde(default)]
                svc: Option<String>,
            }
            match serde_json::from_str::<R>(o.stdout.trim()) {
                Ok(r) => (
                    r.xml.unwrap_or_default(),
                    r.svc.as_deref() == Some("Running"),
                ),
                Err(_) => (String::new(), false),
            }
        }
        Err(_) => (String::new(), false),
    }
}

// ------------------------------------------------------------------ NoRun

fn user_hive_sids() -> Vec<String> {
    let Some(k) = reg_open(HKEY_USERS, "", false) else {
        return vec![];
    };
    reg_subkeys(&k)
        .into_iter()
        .filter(|s| {
            (s.starts_with("S-1-5-21-") || s.starts_with("S-1-12-1-")) && !s.ends_with("_Classes")
        })
        .collect()
}

fn set_norun_at(root: windows_sys::Win32::System::Registry::HKEY, base: &str, on: bool) {
    let path = if base.is_empty() {
        reg::POLICIES_EXPLORER.to_string()
    } else {
        format!(r"{base}\{}", reg::POLICIES_EXPLORER)
    };
    if on {
        if let Ok(k) = reg_create(root, &path) {
            let _ = reg_set_dword(&k, "NoRun", 1);
        }
    } else if let Some(k) = reg_open(root, &path, true) {
        if reg_get_dword(&k, "NoRun") == Some(1) {
            reg_delete_value(&k, "NoRun");
        }
    }
}

/// NoRun in HKLM (honoured machine-wide by SHRestricted), every loaded user
/// hive, and the Default profile (so new users get it).
fn set_norun(_profiles: &[String], on: bool) {
    set_norun_at(HKEY_LOCAL_MACHINE, "", on);
    for sid in user_hive_sids() {
        set_norun_at(HKEY_USERS, &sid, on);
    }
    // Default profile hive.
    let default = reg_open(HKEY_LOCAL_MACHINE, reg::PROFILE_LIST, false)
        .and_then(|k| reg_get_string(&k, "Default"))
        .map(|p| crate::ntpath::expand_env(&p, |n| std::env::var(n).ok()))
        .unwrap_or_else(|| r"C:\Users\Default".to_string());
    let hive = format!(r"{default}\NTUSER.DAT");
    if Path::new(&hive).exists()
        && enable_privilege("SeRestorePrivilege")
        && enable_privilege("SeBackupPrivilege")
    {
        let mount = "KestrelDefaultProfile";
        let wm = wide(mount);
        let wh = wide(&hive);
        let rc = unsafe { RegLoadKeyW(HKEY_USERS, wm.as_ptr(), wh.as_ptr()) };
        if rc == ERROR_SUCCESS {
            set_norun_at(HKEY_USERS, mount, on);
            unsafe { RegUnLoadKeyW(HKEY_USERS, wm.as_ptr()) };
        }
    }
}

fn norun_in_effect() -> bool {
    let at = |root, base: &str| {
        let path = if base.is_empty() {
            reg::POLICIES_EXPLORER.to_string()
        } else {
            format!(r"{base}\{}", reg::POLICIES_EXPLORER)
        };
        reg_open(root, &path, false).and_then(|k| reg_get_dword(&k, "NoRun")) == Some(1)
    };
    if at(HKEY_LOCAL_MACHINE, "") {
        return true;
    }
    let sids = user_hive_sids();
    !sids.is_empty() && sids.iter().all(|s| at(HKEY_USERS, s))
}

// ------------------------------------------------------------------ Windows Terminal

const TERMINAL_PACKAGES: [&str; 2] = [
    "Microsoft.WindowsTerminal_8wekyb3d8bbwe",
    "Microsoft.WindowsTerminalPreview_8wekyb3d8bbwe",
];

/// Candidate settings.json paths for a profile whose Terminal state dir exists.
fn terminal_settings(profile: &str) -> Vec<PathBuf> {
    let local = Path::new(profile).join("AppData").join("Local");
    let mut v = Vec::new();
    for p in TERMINAL_PACKAGES {
        let dir = local.join("Packages").join(p).join("LocalState");
        if dir.is_dir() {
            v.push(dir.join("settings.json"));
        }
    }
    let unpackaged = local.join("Microsoft").join("Windows Terminal");
    if unpackaged.is_dir() {
        v.push(unpackaged.join("settings.json"));
    }
    v
}

fn terminal_apply(profiles: &[String]) {
    for prof in profiles {
        for f in terminal_settings(prof) {
            let src = std::fs::read_to_string(&f).unwrap_or_default();
            match jsonc::enforce_paste_warning(&src) {
                Ok(Some(new)) => {
                    if !src.is_empty() {
                        let bak = f.with_extension("json.kestrel-bak");
                        if !bak.exists() {
                            let _ = std::fs::write(&bak, src.as_bytes());
                        }
                    }
                    // Overwrite in place (keeps the file's ACL/owner).
                    if let Err(e) = std::fs::write(&f, new.as_bytes()) {
                        tracing::warn!("cannot update {}: {e}", f.display());
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("{}: {e}", f.display()),
            }
        }
    }
}

fn terminal_in_effect(profiles: &[String]) -> bool {
    profiles.iter().flat_map(|p| terminal_settings(p)).all(|f| {
        std::fs::read_to_string(&f)
            .map(|s| jsonc::paste_warning_in_effect(&s))
            .unwrap_or(false)
    })
}

// ------------------------------------------------------------------ ASR

fn defender_running() -> bool {
    let sc = format!(r"{}\System32\sc.exe", system_root());
    run_cmd(&sc, &["query", "WinDefend"], Duration::from_secs(15))
        .map(|o| o.stdout.contains("RUNNING"))
        .unwrap_or(false)
}

/// Current local ASR configuration: rule id (lower-case) → action.
fn asr_current() -> Result<BTreeMap<String, u32>, String> {
    let script = "$ErrorActionPreference='Stop'; $p=Get-MpPreference; \
        ConvertTo-Json -Compress @{ids=@($p.AttackSurfaceReductionRules_Ids); actions=@($p.AttackSurfaceReductionRules_Actions)}";
    let o = run_powershell(script, PS_TIMEOUT).map_err(|e| format!("Get-MpPreference: {e}"))?;
    if o.code != 0 {
        return Err(format!("Get-MpPreference failed: {}", o.stderr.trim()));
    }
    #[derive(Deserialize)]
    struct R {
        #[serde(default)]
        ids: Vec<Option<String>>,
        #[serde(default)]
        actions: Vec<Option<serde_json::Value>>,
    }
    let r: R = serde_json::from_str(o.stdout.trim())
        .map_err(|e| format!("unexpected Get-MpPreference output: {e}"))?;
    let mut m = BTreeMap::new();
    for (i, id) in r.ids.iter().enumerate() {
        let Some(id) = id else { continue };
        let a = r
            .actions
            .get(i)
            .cloned()
            .flatten()
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;
        m.insert(id.to_ascii_lowercase(), a);
    }
    // Group Policy / MDM values override local preferences.
    if let Some(k) = reg_open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules",
        false,
    ) {
        for (name, val) in reg_values(&k) {
            if let Ok(a) = val.trim().parse::<u32>() {
                m.insert(name.to_ascii_lowercase(), a);
            }
        }
    }
    Ok(m)
}

fn asr_apply(enforce: bool) -> Result<(), String> {
    let cur = asr_current()?;
    let mut ids = Vec::new();
    for id in asr::ALL {
        let a = cur.get(id).copied().unwrap_or(asr::ACTION_OFF);
        let strong = a == asr::ACTION_BLOCK || a == asr::ACTION_WARN;
        let needs = if enforce {
            a != asr::ACTION_BLOCK
        } else {
            !strong && a != asr::ACTION_AUDIT
        };
        if needs {
            ids.push(id);
        }
    }
    if ids.is_empty() {
        return Ok(());
    }
    asr_add(&ids, if enforce { "Enabled" } else { "AuditMode" })
}

/// `Add-MpPreference` (never `Set-`): adds/updates only the given rule ids,
/// leaving every other ASR rule as configured.
fn asr_add(ids: &[&str], action: &str) -> Result<(), String> {
    let list = ids
        .iter()
        .map(|i| ps_quote(i))
        .collect::<Vec<_>>()
        .join(",");
    let acts = ids.iter().map(|_| action).collect::<Vec<_>>().join(",");
    let script = format!(
        "$ErrorActionPreference='Stop'; Add-MpPreference -AttackSurfaceReductionRules_Ids @({list}) -AttackSurfaceReductionRules_Actions @({acts})"
    );
    let o = run_powershell(&script, PS_TIMEOUT).map_err(|e| format!("Add-MpPreference: {e}"))?;
    if o.code != 0 {
        return Err(format!(
            "Add-MpPreference failed (managed by GPO/Intune or Tamper Protection?): {}",
            o.stderr.trim()
        ));
    }
    Ok(())
}

fn asr_in_effect() -> bool {
    match asr_current() {
        Ok(m) => asr::ALL
            .iter()
            .all(|id| m.get(*id).copied() == Some(asr::ACTION_BLOCK)),
        Err(_) => false,
    }
}

/// `Remove-MpPreference` for one rule Kestrel added (only on revert).
fn asr_remove(id: &str) -> Result<(), String> {
    let script = format!(
        "$ErrorActionPreference='Stop'; Remove-MpPreference -AttackSurfaceReductionRules_Ids @({})",
        ps_quote(id)
    );
    let o = run_powershell(&script, PS_TIMEOUT).map_err(|e| format!("Remove-MpPreference: {e}"))?;
    if o.code != 0 {
        return Err(format!("Remove-MpPreference failed: {}", o.stderr.trim()));
    }
    Ok(())
}

// ------------------------------------------------------------------ LSA / HVCI status

/// Does `%SystemRoot%\System32\lsass.exe` run as PPL (LSA signer) now?
/// `GetProcessInformation(ProcessProtectionLevelInfo)` needs only
/// `PROCESS_QUERY_LIMITED_INFORMATION`, which PPL processes still grant.
/// `None` when lsass cannot be found / queried.
fn lsass_ppl_running() -> Option<bool> {
    use windows_sys::Win32::System::Threading::{
        GetProcessInformation, ProcessProtectionLevelInfo, PROCESS_PROTECTION_LEVEL_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, PROTECTION_LEVEL_LSA_LIGHT,
    };
    let want =
        crate::qpolicy::normalize_for_compare(&format!(r"{}\System32\lsass.exe", system_root()));
    let rows = super::snapshot::toolhelp_rows();
    let row = rows
        .iter()
        .find(|r| r.exe.eq_ignore_ascii_case("lsass.exe"))?;
    let h = open_process(row.pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let img = process_image(&h)?;
    if crate::qpolicy::normalize_for_compare(&super::safefs::long_path(&img)) != want {
        return None;
    }
    let mut info = PROCESS_PROTECTION_LEVEL_INFORMATION { ProtectionLevel: 0 };
    let ok = unsafe {
        GetProcessInformation(
            h.raw(),
            ProcessProtectionLevelInfo,
            &mut info as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        )
    };
    if ok == 0 {
        return None;
    }
    Some(info.ProtectionLevel == PROTECTION_LEVEL_LSA_LIGHT)
}

/// `Win32_DeviceGuard.SecurityServicesRunning` (WMI, COM — no PowerShell).
fn hvci_services_running() -> Option<Vec<u32>> {
    let _com = super::com::ComInit::new().ok()?;
    let svc = super::com::wmi_connect(hp::DEVICE_GUARD_NS).ok()?;
    let objs = super::com::wmi_query(&svc, "SELECT * FROM Win32_DeviceGuard", 1).ok()?;
    let mof = super::com::object_text(objs.first()?).ok()?;
    crate::autorun_plan::mof_u32_list(&mof, "SecurityServicesRunning")
}
