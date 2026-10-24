//! RW-xx ransomware family: fixtures (positive and benign) for every rule,
//! Audit vs Protect actions, protected-process safety, bounded state and the
//! catalog entries.

use kestrel_common::*;
use kestrel_detect::*;
use std::path::PathBuf;

// ----- helpers (copied from tests/common to keep this file self-contained) -----

const T0: i64 = 1_760_000_000_000;
const AGENT: &str = r"C:\Program Files\Kestrel\kestrel-agent.exe";
const LOCKER_IMG: &str = r"C:\Users\alice\AppData\Local\Temp\svc_upd.exe";

fn host() -> HostContext {
    HostContext {
        boot_id: "boot-1".into(),
        hostname: "FIN-LAPTOP-07".into(),
        agent_image: AGENT.into(),
        agent_pid: 0,
        server_ips: vec!["203.0.113.10".into()],
        system_drive: Some('c'),
    }
}

fn fixture(name: &str) -> Vec<Event> {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{name}: bad line {l}: {e}")))
        .collect()
}

fn policy_all(mode: RuleMode) -> Policy {
    let mut p = Policy::default();
    for m in Engine::catalog() {
        p.rules.insert(m.id.clone(), mode);
    }
    p
}

fn engine(policy: Policy) -> Engine {
    Engine::new(host(), policy, RuleBundle::default()).unwrap()
}

fn run(policy: Policy, name: &str) -> Vec<Output> {
    let mut e = engine(policy);
    fixture(name).iter().flat_map(|ev| e.process(ev)).collect()
}

fn alerts(out: &[Output]) -> Vec<&Detection> {
    out.iter()
        .filter_map(|o| match o {
            Output::Alert(d) => Some(d),
            _ => None,
        })
        .collect()
}

/// RW alerts only (ST-12 etc. may also fire on the synthetic payloads).
fn rw(out: &[Output]) -> Vec<&Detection> {
    alerts(out)
        .into_iter()
        .filter(|d| d.alert.rule_id.starts_with("RW-"))
        .collect()
}

fn rw_ids(out: &[Output]) -> Vec<String> {
    rw(out).iter().map(|d| d.alert.rule_id.clone()).collect()
}

fn kills(actions: &[ResponseAction]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::KillProcess { guid, tree, .. } => {
                assert!(*tree, "RW kills are tree kills: {a:?}");
                Some(guid.clone().map(|g| g.0).unwrap_or_default())
            }
            _ => None,
        })
        .collect()
}

fn quarantined(actions: &[ResponseAction]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::QuarantineFile { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect()
}

fn isolates(actions: &[ResponseAction]) -> bool {
    actions
        .iter()
        .any(|a| matches!(a, ResponseAction::IsolateHost { allow_ips } if allow_ips.is_empty()))
}

fn all_actions(out: &[Output]) -> Vec<ResponseAction> {
    let mut v = Vec::new();
    for o in out {
        match o {
            Output::Alert(d) => v.extend(d.actions.iter().cloned()),
            Output::Action(a) => v.push(a.clone()),
        }
    }
    v
}

fn g(s: &str) -> ProcessGuid {
    ProcessGuid(s.into())
}

fn ev(ts: i64, guid: &str, pid: u32, data: EventData) -> Event {
    Event {
        ts: T0 + ts,
        pid,
        guid: g(guid),
        data,
    }
}

fn start(
    ts: i64,
    guid: &str,
    pid: u32,
    image: &str,
    cmdline: &str,
    parent: Option<(&str, u32)>,
    signer: Option<&str>,
) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ProcessStart(ProcessStart {
            ppid: parent.map(|p| p.1).unwrap_or(3900),
            parent_guid: parent.map(|p| g(p.0)),
            image: image.into(),
            cmdline: cmdline.into(),
            signed: if signer.is_some() {
                SignatureState::Valid
            } else {
                SignatureState::Unsigned
            },
            signer: signer.map(Into::into),
            ..Default::default()
        }),
    )
}

fn explorer() -> Event {
    start(
        -600_000,
        "explorer-1",
        4000,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        Some("Microsoft Windows"),
    )
}

fn file_activity(ts: i64, guid: &str, pid: u32, fa: FileActivity) -> Event {
    ev(ts, guid, pid, EventData::FileActivity(fa))
}

fn mass(files: u32, dirs: u32, ext: u32) -> FileActivity {
    FileActivity {
        window_ms: 10_000,
        files_touched: files,
        dirs,
        renames: files,
        ext_changes: ext,
        top_new_ext: Some("k3str".into()),
        top_ext_pct: 95,
        ..Default::default()
    }
}

const RW_IDS: &[&str] = &[
    "RW-01", "RW-02", "RW-03", "RW-04", "RW-05", "RW-06", "RW-07", "RW-08", "RW-12",
];

// ---------------------------------------------------------------- catalog

#[test]
fn catalog_has_every_rw_rule_with_full_meta() {
    let c = Engine::catalog();
    for id in RW_IDS {
        let m = c
            .iter()
            .find(|m| m.id == *id)
            .unwrap_or_else(|| panic!("{id} missing from Engine::catalog()"));
        assert_eq!(m.category, RuleCategory::Ransomware, "{id}");
        assert_eq!(m.kind, RuleKind::Builtin, "{id}");
        assert!(!m.attack.is_empty(), "{id} attack");
        assert!(!m.references.is_empty(), "{id} references");
        assert!(!m.false_positives.is_empty(), "{id} false positives");
        assert!(!m.protect_action.is_empty(), "{id} protect action");
        assert!(!m.description.is_empty() && !m.name.is_empty(), "{id}");
        let day_one = *id != "RW-04";
        assert_eq!(m.protect_day_one, day_one, "{id}");
        assert_eq!(
            m.default_mode,
            if day_one {
                RuleMode::Protect
            } else {
                RuleMode::Audit
            },
            "{id}"
        );
        // No Elastic (ELv2) rule text is shipped; Elastic pages are at most references.
        assert!(!m.description.to_lowercase().contains("elastic"), "{id}");
    }
    for deferred in ["RW-09", "RW-10", "RW-11", "RW-13"] {
        assert!(c.iter().all(|m| m.id != deferred), "{deferred} is deferred");
    }
    let t1490 = |id: &str| {
        c.iter()
            .find(|m| m.id == id)
            .is_some_and(|m| m.attack.iter().any(|a| a == "T1490"))
    };
    assert!(t1490("RW-01") && t1490("RW-02") && t1490("RW-03") && t1490("RW-12"));
    let rw06 = c.iter().find(|m| m.id == "RW-06").unwrap();
    assert!(rw06.attack.contains(&"T1486".to_string()));
}

// ---------------------------------------------------------------- RW-01

#[test]
fn rw01_vssadmin_protect_kills_tool_and_lineage() {
    let out = run(Policy::default(), "rw01_vssadmin.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-01"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(d.alert.process.guid, g("vssadmin-1"));
    assert_eq!(kills(&d.actions), vec!["vssadmin-1", "cmd-1", "locker-1"]);
    assert_eq!(quarantined(&d.actions), vec![LOCKER_IMG.to_string()]);
    // Never Explorer, never the system cmd.exe image.
    assert!(!kills(&all_actions(&out)).contains(&"explorer-1".to_string()));
    assert!(
        d.alert.summary.contains("vssadmin.exe"),
        "{}",
        d.alert.summary
    );
}

#[test]
fn rw01_audit_mode_has_no_actions() {
    let out = run(policy_all(RuleMode::Audit), "rw01_vssadmin.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-01"]);
    assert_eq!(rw(&out)[0].alert.mode, RuleMode::Audit);
    assert!(all_actions(&out).is_empty(), "{:?}", all_actions(&out));
}

#[test]
fn rw01_script_block_shadowcopy_delete() {
    let out = run(Policy::default(), "rw01_script_block.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-01"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.process.guid, g("ps-1"));
    assert_eq!(kills(&d.actions), vec!["ps-1", "locker-1"]);
    // powershell.exe is a System32 LOLBin: never quarantined.
    assert_eq!(quarantined(&d.actions), vec![LOCKER_IMG.to_string()]);
}

#[test]
fn rw01_benign_admin_and_backup_listing() {
    let out = run(policy_all(RuleMode::Protect), "rw01_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn rw01_admin_shell_kills_only_the_tool() {
    let mut e = engine(Policy::default());
    e.process(&explorer());
    e.process(&start(
        0,
        "cmd-a",
        5000,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        Some(("explorer-1", 4000)),
        Some("Microsoft Windows"),
    ));
    let out = e.process(&start(
        10,
        "vss-a",
        5001,
        r"C:\Windows\System32\vssadmin.exe",
        "vssadmin delete shadows /for=c: /oldest",
        Some(("cmd-a", 5000)),
        Some("Microsoft Windows"),
    ));
    assert_eq!(rw_ids(&out), vec!["RW-01"]);
    assert_eq!(kills(&rw(&out)[0].actions), vec!["vss-a"]);
}

#[test]
fn rw01_never_acts_on_protected_parent() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "svchost-1",
        900,
        r"C:\Windows\System32\svchost.exe",
        "svchost.exe -k netsvcs",
        None,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&start(
        10,
        "wmic-1",
        901,
        r"C:\Windows\System32\wbem\WMIC.exe",
        "wmic.exe shadowcopy delete /nointeractive",
        Some(("svchost-1", 900)),
        Some("Microsoft Windows"),
    ));
    assert_eq!(rw_ids(&out), vec!["RW-01"]);
    let k = kills(&all_actions(&out));
    assert_eq!(k, vec!["wmic-1"]);
}

#[test]
fn rw01_wbadmin_and_resize_variants() {
    let cases = [
        ("wbadmin.exe", "wbadmin DELETE CATALOG -quiet", true),
        (
            "wbadmin.exe",
            "wbadmin delete systemstatebackup -keepversions:0",
            true,
        ),
        ("wbadmin.exe", "wbadmin delete backup -keepVersions:0", true),
        (
            "wbadmin.exe",
            "wbadmin delete backup -keepVersions:3",
            false,
        ),
        (
            "vssadmin.exe",
            "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            true,
        ),
        ("vssadmin.exe", "vssadmin list shadowstorage", false),
        (
            "diskshadow.exe",
            r"diskshadow.exe /s C:\Users\bob\AppData\Local\Temp\x.txt",
            true,
        ),
        (
            "diskshadow.exe",
            r"diskshadow.exe /s C:\Scripts\nightly.txt",
            false,
        ),
    ];
    for (i, (img, cmd, want)) in cases.iter().enumerate() {
        let mut e = engine(Policy::default());
        let out = e.process(&start(
            i as i64,
            &format!("t{i}"),
            100 + i as u32,
            &format!(r"C:\Windows\System32\{img}"),
            cmd,
            None,
            Some("Microsoft Windows"),
        ));
        assert_eq!(rw_ids(&out) == vec!["RW-01"], *want, "{cmd}");
    }
}

// ---------------------------------------------------------------- RW-02

#[test]
fn rw02_bcdedit_recovery_disabled() {
    let out = run(Policy::default(), "rw02_bcdedit.jsonl");
    // Same rule twice is one distinct signal: no RW-12.
    assert_eq!(rw_ids(&out), vec!["RW-02", "RW-02"]);
    for d in rw(&out) {
        assert_eq!(d.alert.severity, Severity::Critical);
        assert!(kills(&d.actions).contains(&"locker-1".to_string()));
        assert!(
            d.alert.summary.contains("recoveryenabled yes"),
            "{}",
            d.alert.summary
        );
    }
}

#[test]
fn rw02_reagentc_is_alert_only() {
    let out = run(policy_all(RuleMode::Protect), "rw02_reagentc.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-02"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::High);
    assert!(d.actions.is_empty(), "{:?}", d.actions);
    assert!(kills(&all_actions(&out)).is_empty());
}

#[test]
fn rw02_benign_enum_and_repair() {
    let out = run(policy_all(RuleMode::Protect), "rw02_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-03

#[test]
fn rw03_safeboot_staging_and_autologon() {
    let out = run(Policy::default(), "rw03_safeboot.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-03", "RW-03", "RW-03"]);
    let ds = rw(&out);
    assert_eq!(ds[0].alert.process.guid, g("bcdedit-1"));
    assert_eq!(
        kills(&ds[0].actions),
        vec!["bcdedit-1", "cmd-1", "locker-1"]
    );
    assert!(ds[0]
        .alert
        .summary
        .contains("deletevalue {default} safeboot"));
    // reg.exe variants are alert-only.
    assert_eq!(ds[1].alert.process.guid, g("reg-1"));
    assert!(ds[1].actions.is_empty());
    assert_eq!(ds[2].alert.process.guid, g("reg-2"));
    assert!(ds[2].alert.summary.contains("automatic logon"));
    assert!(ds[2].actions.is_empty());
}

#[test]
fn rw03_admin_safeboot_alerts_without_actions() {
    let out = run(Policy::default(), "rw03_admin_safeboot.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-03"]);
    assert!(rw(&out)[0].actions.is_empty());
}

#[test]
fn rw03_benign_installers_kestrel_key_and_revert() {
    let out = run(policy_all(RuleMode::Protect), "rw03_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn rw03_unsigned_process_cannot_hide_behind_kestrel_service_name() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "x",
        10,
        r"C:\Users\alice\AppData\Local\Temp\x.exe",
        "x.exe",
        None,
        None,
    ));
    let out = e.process(&ev(
        5,
        "x",
        10,
        EventData::RegistrySet {
            attribution: Default::default(),
            target: None,
            key: r"HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Network\KestrelAgent".into(),
            value_name: String::new(),
            data: Some("Service".into()),
            op: RegistryOp::Set,
        },
    ));
    assert_eq!(rw_ids(&out), vec!["RW-03"]);
}

// ---------------------------------------------------------------- RW-04

#[test]
fn rw04_log_clear_is_audit_level_without_escalation() {
    let out = run(policy_all(RuleMode::Protect), "rw04_wevtutil.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-04", "RW-04"]);
    for d in rw(&out) {
        assert_eq!(d.alert.severity, Severity::Medium);
        assert!(d.actions.is_empty(), "{:?}", d.actions);
    }
    // Default policy: Audit.
    let out = run(Policy::default(), "rw04_wevtutil.jsonl");
    assert!(rw(&out).iter().all(|d| d.alert.mode == RuleMode::Audit));
}

#[test]
fn rw04_benign_queries_and_installer_enable() {
    let out = run(policy_all(RuleMode::Protect), "rw04_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-05

#[test]
fn rw05_service_spree_alerts_on_lineage_head_without_actions() {
    let out = run(policy_all(RuleMode::Protect), "rw05_service_spree.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-05"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.process.guid, g("locker-1"));
    assert!(d.actions.is_empty(), "command-line variant is alert-only");
    assert!(d.alert.summary.contains("5 "), "{}", d.alert.summary);
}

#[test]
fn rw05_terminate_spree_from_untrusted_image_is_killed() {
    let out = run(Policy::default(), "rw05_terminate_spree.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-05"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), vec!["killer-1"]);
    assert_eq!(
        quarantined(&d.actions),
        vec![r"C:\Users\alice\Downloads\kill.exe".to_string()]
    );
}

#[test]
fn rw05_terminate_spree_outside_window_is_ignored() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "k",
        10,
        r"C:\Users\alice\Downloads\k.exe",
        "k.exe",
        None,
        None,
    ));
    let mut out = Vec::new();
    for i in 0..15u32 {
        out.extend(e.process(&ev(
            1000 + i as i64 * 2_000,
            "k",
            10,
            EventData::ProcessAccess(TargetProcess {
                target_pid: 500 + i,
                target_image: "x.exe".into(),
                granted_access: 0x1,
                ..Default::default()
            }),
        )));
    }
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn rw05_benign_installer_and_own_children() {
    let out = run(policy_all(RuleMode::Protect), "rw05_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-06

#[test]
fn rw06_mass_encryption_kills_and_quarantines() {
    let out = run(Policy::default(), "rw06_mass_encrypt.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-06"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), vec!["locker-1"]);
    assert_eq!(quarantined(&d.actions), vec![LOCKER_IMG.to_string()]);
    assert!(!isolates(&d.actions), "no network paths touched");
    assert!(
        d.alert.summary.contains("cannot guarantee"),
        "{}",
        d.alert.summary
    );
}

#[test]
fn rw06_intermittent_overwrite_on_shares_isolates() {
    let out = run(Policy::default(), "rw06_intermittent_network.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-06"]);
    let d = rw(&out)[0];
    assert!(kills(&d.actions).contains(&"locker-1".to_string()));
    assert!(isolates(&d.actions), "{:?}", d.actions);
}

#[test]
fn rw06_audit_has_no_actions() {
    let out = run(
        policy_all(RuleMode::Audit),
        "rw06_intermittent_network.jsonl",
    );
    assert_eq!(rw_ids(&out), vec!["RW-06"]);
    assert!(all_actions(&out).is_empty());
}

#[test]
fn rw06_benign_sync_extract_git_office() {
    let out = run(policy_all(RuleMode::Protect), "rw06_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn rw06_signed_sync_client_over_threshold_alerts_only() {
    let out = run(
        policy_all(RuleMode::Protect),
        "rw06_onedrive_threshold.jsonl",
    );
    assert_eq!(rw_ids(&out), vec!["RW-06"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::High);
    assert!(d.actions.is_empty(), "{:?}", d.actions);
}

#[test]
fn rw06_protected_process_is_never_acted_on() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "svchost-1",
        900,
        r"C:\Windows\System32\svchost.exe",
        "svchost.exe -k LocalService",
        None,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&file_activity(10, "svchost-1", 900, mass(100, 10, 90)));
    assert_eq!(rw_ids(&out), vec!["RW-06"]);
    let acts = all_actions(&out);
    assert!(kills(&acts).is_empty(), "{acts:?}");
    assert!(quarantined(&acts).is_empty(), "{acts:?}");
}

#[test]
fn rw06_agent_and_system_pid_are_silent() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "agent",
        50,
        AGENT,
        "kestrel-agent.exe run",
        None,
        Some("Kestrel"),
    ));
    let mut out = e.process(&file_activity(10, "agent", 50, mass(500, 50, 400)));
    // PID 4 (remote SMB encryption) is RW-09, deferred: no alert here.
    out.extend(e.process(&file_activity(20, "system", 4, mass(500, 50, 400))));
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-07

#[test]
fn rw07_canary_tamper_kills() {
    let out = run(Policy::default(), "rw07_canary.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-07"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), vec!["locker-1"]);
    assert_eq!(quarantined(&d.actions), vec![LOCKER_IMG.to_string()]);
}

#[test]
fn rw07_explorer_alerts_only() {
    let out = run(Policy::default(), "rw07_explorer.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-07"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::High);
    assert!(all_actions(&out).is_empty());
}

/// Fresh-install lab 2026-10-21: an employee tidying up in Explorer
/// (recycling one hidden decoy, then two at once with "show hidden files"
/// on, and an in-place change inferred to Explorer) in **Protect**: RW-07
/// alerts, never Critical, never an action, Explorer (protected) is never
/// killed, and the wording says it was the signed-in user's file manager.
#[test]
fn rw07_explorer_tidying_up_in_protect_is_alert_only() {
    let out = run(
        policy_all(RuleMode::Protect),
        "rw07_explorer_tidy_protect.jsonl",
    );
    let ds = rw(&out);
    assert!(!ds.is_empty(), "no RW alert");
    assert!(
        ds.iter().all(|d| d.alert.rule_id == "RW-07"),
        "{:?}",
        rw_ids(&out)
    );
    for d in &ds {
        assert_eq!(d.alert.severity, Severity::High, "{}", d.alert.summary);
        assert!(d.actions.is_empty(), "{:?}", d.actions);
    }
    assert!(all_actions(&out).is_empty(), "{:?}", all_actions(&out));
    assert!(
        ds[0].alert.summary.contains("Explorer"),
        "{}",
        ds[0].alert.summary
    );
    assert!(
        ds[0].alert.summary.contains("signed-in user"),
        "{}",
        ds[0].alert.summary
    );
    // Explorer is on the protected list as well: even a direct decision
    // to contain it could never kill it.
    assert!(kestrel_detect::protect::is_protected_process(
        r"C:\WINDOWS\explorer.exe",
        SignatureState::Valid,
        Some("Microsoft Windows"),
        'c'
    ));
}

#[test]
fn rw07_benign_agent_planting_and_plain_explorer() {
    let out = run(Policy::default(), "rw07_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-08

#[test]
fn rw08_ransom_note_fan_out_kills() {
    let out = run(Policy::default(), "rw08_notes.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-08"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), vec!["locker-1"]);
}

#[test]
fn rw08_name_agnostic_fallback_alerts_only() {
    let out = run(Policy::default(), "rw08_fallback.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-08"]);
    let d = rw(&out)[0];
    assert_eq!(d.alert.severity, Severity::High);
    assert!(d.actions.is_empty());
}

#[test]
fn rw08_fallback_combined_with_rw06_kills() {
    let mut e = engine(Policy::default());
    e.process(&explorer());
    e.process(&start(
        0,
        "enc",
        10,
        r"C:\Users\alice\AppData\Local\Temp\enc.exe",
        "enc.exe",
        Some(("explorer-1", 4000)),
        None,
    ));
    let mut fa = mass(60, 25, 50);
    fa.note_name = Some("x8k2q.txt".into());
    fa.note_dirs = 25;
    let out = e.process(&file_activity(10, "enc", 10, fa));
    assert_eq!(rw_ids(&out), vec!["RW-06", "RW-08"]);
    // RW-06 already killed it; RW-08 re-proposes nothing new but stays Critical.
    assert_eq!(rw(&out)[1].alert.severity, Severity::Critical);
    assert!(kills(&all_actions(&out)).contains(&"enc".to_string()));
}

#[test]
fn rw08_benign_desktop_ini_and_plain_names() {
    let out = run(Policy::default(), "rw08_benign.jsonl");
    assert!(rw_ids(&out).is_empty(), "{:?}", rw_ids(&out));
}

// ---------------------------------------------------------------- RW-12

#[test]
fn rw12_kill_chain_isolates_and_halves_rw06() {
    let out = run(Policy::default(), "rw12_killchain.jsonl");
    assert_eq!(
        rw_ids(&out),
        vec!["RW-01", "RW-02", "RW-12", "RW-04", "RW-06"]
    );
    let ds = rw(&out);
    let rw12 = ds[2];
    assert_eq!(rw12.alert.severity, Severity::Critical);
    assert!(isolates(&rw12.actions), "{:?}", rw12.actions);
    assert!(rw12.alert.summary.contains("RW-01, RW-02"));
    // RW-04 escalated by the earlier prep hits of the same lineage; it is
    // Audit by default, so the escalation raises severity only.
    let rw04 = ds[3];
    assert_eq!(rw04.alert.severity, Severity::High);
    assert_eq!(rw04.alert.mode, RuleMode::Audit);
    assert!(rw04.actions.is_empty());
    // RW-06 fired below the normal threshold (20 files) because RW-12 halved it.
    assert_eq!(ds[4].alert.process.guid, g("locker-1"));
    assert!(!kills(&all_actions(&out)).contains(&"explorer-1".to_string()));
}

#[test]
fn rw04_escalated_in_protect_kills_lineage() {
    let out = run(policy_all(RuleMode::Protect), "rw12_killchain.jsonl");
    let rw04 = rw(&out)
        .into_iter()
        .find(|d| d.alert.rule_id == "RW-04")
        .expect("RW-04");
    assert_eq!(rw04.alert.severity, Severity::High);
    assert_eq!(
        kills(&rw04.actions),
        vec!["wevtutil-3", "cmd-3", "locker-1"]
    );
}

#[test]
fn rw12_audit_mode_still_correlates_without_actions() {
    let out = run(policy_all(RuleMode::Audit), "rw12_killchain.jsonl");
    assert_eq!(
        rw_ids(&out),
        vec!["RW-01", "RW-02", "RW-12", "RW-04", "RW-06"]
    );
    assert!(all_actions(&out).is_empty());
}

#[test]
fn rw12_benign_single_signal_and_normal_thresholds() {
    let out = run(Policy::default(), "rw12_benign.jsonl");
    assert_eq!(rw_ids(&out), vec!["RW-04", "RW-04"]);
}

#[test]
fn rw12_off_mode_suppresses_alert() {
    let mut p = Policy::default();
    p.rules.insert("RW-12".into(), RuleMode::Off);
    let out = run(p, "rw12_killchain.jsonl");
    let ids = rw_ids(&out);
    assert!(!ids.contains(&"RW-12".to_string()), "{ids:?}");
    // Without RW-12 the RW-06 thresholds stay normal: 20 files is not enough.
    assert!(!ids.contains(&"RW-06".to_string()), "{ids:?}");
}

// ---------------------------------------------------------------- robustness

#[test]
fn odd_input_never_panics_and_state_is_bounded() {
    let mut e = engine(Policy::default());
    // Unknown actors, absurd counters, hostile command lines.
    e.process(&file_activity(
        0,
        "ghost",
        77,
        FileActivity {
            files_touched: u32::MAX,
            dirs: u32::MAX,
            overwrites: u32::MAX,
            net_paths: u32::MAX,
            ext_changes: u32::MAX,
            note_name: Some("ÄÖÜ.\u{202e}txt".into()),
            note_dirs: u32::MAX,
            canary_hits: vec![String::new()],
            ..Default::default()
        },
    ));
    let long = format!("vssadmin \"{}", "\"x –".repeat(50_000));
    e.process(&start(
        1,
        "v",
        78,
        r"C:\Windows\System32\vssadmin.exe",
        &long,
        None,
        None,
    ));
    e.process(&start(2, "n", 79, "", "", None, None));
    e.process(&ev(
        3,
        "ps",
        80,
        EventData::ScriptBlock {
            engine: "powershell".into(),
            content: "é".repeat(200_000),
        },
    ));
    e.process(&ev(
        4,
        "nobody",
        81,
        EventData::RegistrySet {
            attribution: Default::default(),
            target: None,
            key: String::new(),
            value_name: String::new(),
            data: None,
            op: RegistryOp::DeleteKey,
        },
    ));
    // Thousands of distinct terminate targets from one untrusted actor: one alert.
    e.process(&start(
        5,
        "k",
        82,
        r"C:\Users\alice\Downloads\k.exe",
        "k.exe",
        None,
        None,
    ));
    let mut out = Vec::new();
    for i in 0..5_000u32 {
        out.extend(e.process(&ev(
            10 + i as i64,
            "k",
            82,
            EventData::ProcessAccess(TargetProcess {
                target_pid: 10_000 + i,
                target_image: "x.exe".into(),
                granted_access: 0x1,
                ..Default::default()
            }),
        )));
    }
    assert_eq!(rw_ids(&out), vec!["RW-05"]);
    // Many lineages of kill commands, then a far-future tick.
    for i in 0..3_000u32 {
        let gid = format!("p{i}");
        e.process(&start(
            20_000 + i as i64,
            &gid,
            20_000 + i,
            r"C:\Users\alice\AppData\Local\Temp\p.exe",
            "p.exe",
            None,
            None,
        ));
        e.process(&start(
            20_000 + i as i64,
            &format!("n{i}"),
            40_000 + i,
            r"C:\Windows\System32\net.exe",
            "net stop MSSQLSERVER",
            Some((&gid, 20_000 + i)),
            Some("Microsoft Windows"),
        ));
    }
    e.tick(T0 + 10 * 3_600_000);
    e.tick(T0 + 20 * 3_600_000);
}

// ---------------------------------------------------------------- RW-06 corpus finding 9 / FP-07 (2026-10-25)

/// RW-06 alerts of `out`.
fn rw06(out: &[Output]) -> Vec<&Detection> {
    rw(out)
        .into_iter()
        .filter(|d| d.alert.rule_id == "RW-06")
        .collect()
}

/// Engine with Explorer and an unsigned Temp locker (`locker-1`, pid 6000).
fn with_locker(policy: Policy) -> Engine {
    let mut e = engine(policy);
    e.process(&explorer());
    e.process(&start(
        0,
        "locker-1",
        6000,
        LOCKER_IMG,
        "svc_upd.exe",
        Some(("explorer-1", 4000)),
        None,
    ));
    e
}

#[test]
fn fam2_rw06_rename_over_original_fires_and_kills() {
    // Corpus finding 9: encrypted copy in a self-created temp file renamed
    // over the original document with the same extension.
    for (policy, acts) in [
        (Policy::default(), true),
        (policy_all(RuleMode::Protect), true),
        (policy_all(RuleMode::Audit), false),
    ] {
        let out = run(policy, "fam2_rw06_rename_over_original.jsonl");
        let hits = rw06(&out);
        assert_eq!(hits.len(), 1, "{:?}", rw_ids(&out));
        let d = hits[0];
        assert_eq!(d.alert.severity, Severity::Critical);
        assert!(
            d.alert.summary.contains("60 existing files"),
            "{}",
            d.alert.summary
        );
        if acts {
            assert_eq!(kills(&d.actions), vec!["locker-1"]);
        } else {
            assert!(all_actions(&out).is_empty());
        }
    }
}

#[test]
fn fam2_rw06_rename_over_needs_same_extension_self_renames() {
    let mut e = with_locker(Policy::default());
    // Self-created files renamed to a changed extension in a build tree (a
    // compiler): no rename-over credit, and the extension changes are
    // build artefacts.
    let fa = FileActivity {
        window_ms: 10_000,
        files_touched: 120,
        dirs: 8,
        renames: 60,
        ext_changes: 60,
        new_files: 60,
        self_created: 60,
        top_new_ext: Some("rlib".into()),
        top_ext_pct: 100,
        sample_paths: vec![r"C:\Users\alice\src\app\target\debug\deps\liba.rlib".into()],
        ..Default::default()
    };
    let out = e.process(&file_activity(10_000, "locker-1", 6000, fa.clone()));
    assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
    // Fewer than 50 replaced originals: below the rewrite threshold.
    let few = FileActivity {
        files_touched: 80,
        renames: 40,
        ext_changes: 0,
        new_files: 40,
        self_created: 40,
        top_new_ext: None,
        top_ext_pct: 0,
        sample_paths: vec![],
        ..fa
    };
    let out = e.process(&file_activity(20_000, "locker-1", 6000, few));
    assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn fam2_rw06_rustc_current_and_old_agents_never_fire() {
    // FP-07: the three current-format summaries from the owner PC (100
    // files, 50 renames to .rlib, 50 self-created, 50 deleted temp folders)
    // and an agent before 1.1.6 (500 files, 186 renames to .rlib, no
    // self_created): no RW alert and no kill in any policy.
    for name in [
        "fam2_rw06_rustc_current.jsonl",
        "fam2_rw06_rustc_old_agent.jsonl",
    ] {
        for policy in [
            Policy::default(),
            policy_all(RuleMode::Protect),
            policy_all(RuleMode::Audit),
        ] {
            let out = run(policy, name);
            assert!(rw_ids(&out).is_empty(), "{name}: {:?}", rw_ids(&out));
        }
    }
}

#[test]
fn fam2_rw06_ransomware_choosing_rlib_still_fires() {
    // Stacked (`q3.xlsx.rlib`) and replaced (`q3.rlib` in Documents)
    // extensions: the samples are user documents, not a build tree.
    let out = run(Policy::default(), "fam2_rw06_rlib_ransomware.jsonl");
    let hits = rw06(&out);
    let subjects: Vec<&str> = hits
        .iter()
        .map(|d| d.alert.process.guid.0.as_str())
        .collect();
    assert_eq!(subjects, vec!["locker-1", "locker-2"], "{:?}", rw_ids(&out));
    for d in hits {
        assert_eq!(d.alert.severity, Severity::Critical);
        assert_eq!(kills(&d.actions), vec![d.alert.process.guid.0.clone()]);
    }
}

#[test]
fn fam2_rw06_compiler_discount_needs_clean_build_samples() {
    let fa = FileActivity {
        window_ms: 10_000,
        files_touched: 100,
        dirs: 6,
        renames: 100,
        ext_changes: 100,
        top_new_ext: Some("rlib".into()),
        top_ext_pct: 100,
        sample_paths: vec![
            r"C:\Users\alice\src\target\deps\a.rlib".into(),
            r"C:\Users\alice\src\target\deps\report.docx.rlib".into(),
        ],
        ..Default::default()
    };
    let variants = [
        // One renamed document among build-looking samples.
        fa.clone(),
        // No samples at all.
        FileActivity {
            sample_paths: vec![],
            ..fa.clone()
        },
        // A non-compiler extension (`lock`) in a build tree.
        FileActivity {
            top_new_ext: Some("lock".into()),
            sample_paths: vec![r"C:\Users\alice\src\target\deps\a.lock".into()],
            ..fa.clone()
        },
        // A build-tree sample next to one in Documents.
        FileActivity {
            sample_paths: vec![
                r"C:\Users\alice\src\target\deps\a.rlib".into(),
                r"C:\Users\alice\Documents\q3.rlib".into(),
            ],
            ..fa.clone()
        },
        // Mostly other extensions (pct below 80).
        FileActivity {
            top_ext_pct: 50,
            sample_paths: vec![r"C:\Users\alice\src\target\deps\a.rlib".into()],
            ..fa.clone()
        },
    ];
    for (i, v) in variants.into_iter().enumerate() {
        let mut e = with_locker(Policy::default());
        let out = e.process(&file_activity(10_000, "locker-1", 6000, v));
        assert_eq!(rw06(&out).len(), 1, "variant {i}: {:?}", rw_ids(&out));
    }
    // The same shape with clean build samples is a compiler.
    let mut e = with_locker(Policy::default());
    let clean = FileActivity {
        sample_paths: vec![
            r"C:\Users\alice\src\target\deps\a.rlib".into(),
            r"C:\Users\alice\src\target\deps\.tmpabc.temp-archive\tmp.a".into(),
        ],
        ..fa
    };
    let out = e.process(&file_activity(10_000, "locker-1", 6000, clean));
    assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
}

#[test]
fn fam2_rw06_slow_paced_bursts_accumulate() {
    // Corpus finding 9: 11 files every 30 s; each summary is far below the
    // per-window threshold, five minutes of them are not.
    let out = run(Policy::default(), "fam2_rw06_slow_paced.jsonl");
    let hits = rw06(&out);
    assert!(!hits.is_empty(), "{:?}", rw_ids(&out));
    let d = hits[0];
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), vec!["locker-1"]);
    assert!(d.alert.summary.contains("bursts"), "{}", d.alert.summary);
    // It fires on the 6th burst (66 files, 66 extension changes).
    let mut e = engine(policy_all(RuleMode::Audit));
    let mut fired_at = None;
    for (i, ev) in fixture("fam2_rw06_slow_paced.jsonl").iter().enumerate() {
        if !rw06(&e.process(ev)).is_empty() && fired_at.is_none() {
            fired_at = Some(i);
        }
    }
    assert_eq!(fired_at, Some(2 + 5), "explorer + start + 6 bursts");
}

#[test]
fn fam2_rw06_slow_benign_shapes_stay_silent() {
    // Renames to known extensions, bursts too far apart, and a compiler
    // re-emitting one overlapping, growing sliding-window summary.
    for policy in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run(policy, "fam2_rw06_slow_benign.jsonl");
        assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
    }
}

#[test]
fn fam2_rw06_slow_overlapping_summaries_count_once() {
    let burst = |window_ms: u64| FileActivity {
        window_ms,
        files_touched: 25,
        dirs: 3,
        renames: 25,
        ext_changes: 15,
        top_new_ext: Some("k3str".into()),
        top_ext_pct: 100,
        ..Default::default()
    };
    // The same 25-file burst re-emitted 10 times inside one window must not
    // add up to 250.
    let mut e = with_locker(Policy::default());
    let mut out = Vec::new();
    for i in 0..10 {
        out.extend(e.process(&file_activity(
            1_000 + i * 500,
            "locker-1",
            6000,
            burst(9_000),
        )));
    }
    assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
    // Old bursts expire: 2 bursts, a 6-minute pause, 2 more bursts.
    let mut e = with_locker(Policy::default());
    let mut out = Vec::new();
    for ts in [10_000, 40_000, 400_000, 430_000] {
        out.extend(e.process(&file_activity(ts, "locker-1", 6000, burst(10_000))));
    }
    assert!(rw06(&out).is_empty(), "{:?}", rw_ids(&out));
    // A third burst within 5 minutes completes it (75 files, 45 changes).
    let out = e.process(&file_activity(460_000, "locker-1", 6000, burst(10_000)));
    assert_eq!(rw06(&out).len(), 1, "{:?}", rw_ids(&out));
    // Same bursts by a validly signed sync client: High, no action.
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&explorer());
    e.process(&start(
        0,
        "od-1",
        7300,
        r"C:\Users\alice\AppData\Local\Microsoft\OneDrive\OneDrive.exe",
        "OneDrive.exe /background",
        Some(("explorer-1", 4000)),
        Some("Microsoft Corporation"),
    ));
    let mut out = Vec::new();
    for ts in [10_000, 40_000, 70_000] {
        out.extend(e.process(&file_activity(ts, "od-1", 7300, burst(10_000))));
    }
    let hits = rw06(&out);
    assert_eq!(hits.len(), 1, "{:?}", rw_ids(&out));
    assert_eq!(hits[0].alert.severity, Severity::High);
    assert!(hits[0].actions.is_empty());
}

#[test]
fn fam2_rw06_slow_state_is_bounded_and_odd_input_is_safe() {
    let mut e = engine(policy_all(RuleMode::Audit));
    for i in 0..3_000u32 {
        e.process(&file_activity(
            i as i64,
            &format!("g{i}"),
            10_000 + i,
            FileActivity {
                window_ms: 10_000,
                files_touched: 5,
                dirs: 1,
                ext_changes: 5,
                ..Default::default()
            },
        ));
    }
    e.process(&file_activity(
        5_000,
        "g1",
        10_001,
        FileActivity {
            window_ms: u64::MAX,
            files_touched: u32::MAX,
            self_created: u32::MAX,
            renames: u32::MAX,
            sample_paths: vec![String::new(), "\\".into(), ".".into()],
            top_new_ext: Some(String::new()),
            top_ext_pct: 255,
            ..Default::default()
        },
    ));
    e.tick(T0 + 3_600_000);
}
