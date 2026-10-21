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
    fa.note_name = Some("x8k2q.log".into());
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
