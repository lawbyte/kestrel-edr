//! CD-xx credential-dumping family: fixture replays (positive and benign),
//! Audit vs Protect actions, protected-target safety and catalog completeness.

use kestrel_common::*;
use kestrel_detect::*;
use std::collections::BTreeSet;
use std::path::PathBuf;

// ----- helpers (copied from tests/common so this file stays self-contained) -----

const T0: i64 = 1_760_000_000_000;
const LSASS_GUID: &str = "lsass-1";
const LSASS_PID: u32 = 624;

fn host() -> HostContext {
    HostContext {
        boot_id: "boot-1".into(),
        hostname: "FIN-LAPTOP-07".into(),
        agent_image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
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

fn replay(engine: &mut Engine, events: &[Event]) -> Vec<Output> {
    events.iter().flat_map(|e| engine.process(e)).collect()
}

fn run(name: &str, policy: Policy) -> Vec<Output> {
    let mut e = engine(policy);
    replay(&mut e, &fixture(&format!("{name}.jsonl")))
}

fn protect(name: &str) -> Vec<Output> {
    run(name, policy_all(RuleMode::Protect))
}

fn audit(name: &str) -> Vec<Output> {
    run(name, policy_all(RuleMode::Audit))
}

fn cd_alerts(out: &[Output]) -> Vec<&Detection> {
    out.iter()
        .filter_map(|o| match o {
            Output::Alert(d) if d.alert.rule_id.starts_with("CD-") => Some(d),
            _ => None,
        })
        .collect()
}

/// Distinct CD rule ids that fired.
fn cd_ids(out: &[Output]) -> BTreeSet<String> {
    cd_alerts(out)
        .iter()
        .map(|d| d.alert.rule_id.clone())
        .collect()
}

fn ids(v: &[&str]) -> BTreeSet<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn alert_for<'a>(out: &'a [Output], rule: &str, guid: &str) -> &'a Detection {
    cd_alerts(out)
        .into_iter()
        .find(|d| d.alert.rule_id == rule && d.alert.process.guid.0 == guid)
        .unwrap_or_else(|| panic!("no {rule} alert for {guid}:\n{}", dump(out)))
}

fn dump(out: &[Output]) -> String {
    let mut s = String::new();
    for o in out {
        match o {
            Output::Alert(d) => s.push_str(&format!(
                "ALERT {} {:?} {:?} proc={} [{}] :: {}\n",
                d.alert.rule_id,
                d.alert.mode,
                d.alert.severity,
                d.alert.process.guid,
                d.actions
                    .iter()
                    .map(|a| format!("{a:?}"))
                    .collect::<Vec<_>>()
                    .join("; "),
                d.alert.summary
            )),
            Output::Action(a) => s.push_str(&format!("ACTION {a:?}\n")),
        }
    }
    s
}

fn killed(actions: &[ResponseAction]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::KillProcess {
                guid: Some(g),
                tree,
                ..
            } => {
                assert!(*tree, "CD kills are tree kills");
                Some(g.0.clone())
            }
            _ => None,
        })
        .collect()
}

fn suspended(actions: &[ResponseAction]) -> Vec<String> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::SuspendProcess { guid: Some(g), .. } => Some(g.0.clone()),
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

fn ev(ts: i64, guid: &str, pid: u32, data: EventData) -> Event {
    Event {
        ts: T0 + ts,
        pid,
        guid: ProcessGuid(guid.into()),
        data,
    }
}

fn start(
    ts: i64,
    guid: &str,
    pid: u32,
    image: &str,
    signed: SignatureState,
    signer: Option<&str>,
) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ProcessStart(ProcessStart {
            ppid: 4000,
            image: image.into(),
            cmdline: kestrel_common::file_name_lower(image),
            signed,
            signer: signer.map(Into::into),
            ..Default::default()
        }),
    )
}

fn open_lsass(ts: i64, guid: &str, pid: u32, mask: u32, rc: u32) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ProcessAccess(TargetProcess {
            target_pid: LSASS_PID,
            target_guid: Some(ProcessGuid(LSASS_GUID.into())),
            target_image: r"C:\Windows\System32\lsass.exe".into(),
            granted_access: mask,
            return_code: rc,
        }),
    )
}

fn create(ts: i64, guid: &str, pid: u32, path: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::FileAccess {
            path: path.into(),
            op: FileOp::Create,
        },
    )
}

/// Engine with wininit + lsass + explorer already started (fixture prelude).
fn with_lsass(policy: Policy) -> Engine {
    let mut e = engine(policy);
    let pre = fixture("cd_wdigest_benign.jsonl");
    replay(&mut e, &pre[..4]);
    e
}

const POSITIVE: &[&str] = &[
    "cd_comsvcs_minidump",
    "cd_procdump_lsass",
    "cd_procdump_renamed",
    "cd_werfaultsecure_copy",
    "cd_wer_shtinkering",
    "cd_lsass_handle_unsigned",
    "cd_taskmgr_dump",
    "cd_dbghelp_dumper",
    "cd_ppl_attempt",
    "cd_silentprocessexit",
    "cd_ssp",
    "cd_reg_save",
    "cd_shadow_hive",
    "cd_ntds",
    "cd_wdigest",
    "cd_lsa_tamper",
];

const BENIGN: &[&str] = &[
    "cd_procdump_notepad_benign",
    "cd_wer_benign",
    "cd_lsass_openers_benign",
    "cd_dbghelp_benign",
    "cd_ifeo_benign",
    "cd_ssp_benign",
    "cd_reg_save_benign",
    "cd_shadow_hive_benign",
    "cd_wdigest_benign",
    "cd_lsa_tamper_benign",
];

// ---------------------------------------------------------------- catalog

#[test]
fn catalog_is_complete() {
    let c = Engine::catalog();
    let cd: Vec<&RuleMeta> = c.iter().filter(|m| m.id.starts_with("CD-")).collect();
    let expected: BTreeSet<String> = (1..=13).map(|i| format!("CD-{i:02}")).collect();
    assert_eq!(
        cd.iter().map(|m| m.id.clone()).collect::<BTreeSet<_>>(),
        expected
    );
    let day_one = ids(&[
        "CD-01", "CD-02", "CD-04", "CD-05", "CD-07", "CD-08", "CD-10", "CD-12",
    ]);
    for m in &cd {
        assert_eq!(m.category, RuleCategory::CredentialDumping, "{}", m.id);
        assert_eq!(m.kind, RuleKind::Builtin);
        assert!(!m.name.is_empty() && m.description.len() > 60, "{}", m.id);
        assert!(
            !m.attack.is_empty() && m.attack.iter().all(|a| a.starts_with('T')),
            "{}",
            m.id
        );
        assert!(
            !m.references.is_empty() && m.references.iter().all(|r| r.starts_with("https://")),
            "{}",
            m.id
        );
        assert!(!m.false_positives.is_empty(), "{}", m.id);
        assert!(!m.protect_action.is_empty(), "{}", m.id);
        assert_eq!(m.protect_day_one, day_one.contains(&m.id), "{}", m.id);
        let mode = if m.protect_day_one {
            RuleMode::Protect
        } else {
            RuleMode::Audit
        };
        assert_eq!(m.default_mode, mode, "{}", m.id);
    }
    let cd11 = cd.iter().find(|m| m.id == "CD-11").unwrap();
    assert!(cd11.description.contains("DCSync") && cd11.description.contains("out of scope"));
    assert!(cd
        .iter()
        .all(|m| m.attack.iter().any(|a| a.starts_with("T1003")
            || a.starts_with("T1547")
            || a.starts_with("T1562")
            || a.starts_with("T1112"))));
}

// ---------------------------------------------------------------- fixtures: exact ids

#[test]
fn positive_fixtures_fire_exact_rules() {
    let expect: &[(&str, &[&str])] = &[
        ("cd_comsvcs_minidump", &["CD-01", "CD-04"]),
        ("cd_procdump_lsass", &["CD-02", "CD-03", "CD-04"]),
        ("cd_procdump_renamed", &["CD-02"]),
        ("cd_werfaultsecure_copy", &["CD-02", "CD-08"]),
        ("cd_wer_shtinkering", &["CD-08"]),
        ("cd_lsass_handle_unsigned", &["CD-03"]),
        ("cd_taskmgr_dump", &["CD-03", "CD-04"]),
        ("cd_dbghelp_dumper", &["CD-05"]),
        ("cd_ppl_attempt", &["CD-06"]),
        ("cd_silentprocessexit", &["CD-07"]),
        ("cd_ssp", &["CD-09"]),
        ("cd_reg_save", &["CD-10"]),
        ("cd_shadow_hive", &["CD-10"]),
        ("cd_ntds", &["CD-11"]),
        ("cd_wdigest", &["CD-12"]),
        ("cd_lsa_tamper", &["CD-13"]),
    ];
    assert_eq!(expect.len(), POSITIVE.len());
    for (name, rules) in expect {
        for out in [audit(name), protect(name)] {
            assert_eq!(cd_ids(&out), ids(rules), "{name}:\n{}", dump(&out));
        }
    }
}

#[test]
fn benign_fixtures_are_silent() {
    for name in BENIGN {
        for out in [audit(name), protect(name)] {
            assert!(cd_ids(&out).is_empty(), "{name}:\n{}", dump(&out));
        }
    }
}

#[test]
fn audit_mode_never_acts() {
    for name in POSITIVE {
        let out = audit(name);
        assert!(!cd_alerts(&out).is_empty(), "{name}");
        for d in cd_alerts(&out) {
            assert_eq!(d.alert.mode, RuleMode::Audit);
            assert!(d.actions.is_empty(), "{name}: {:?}", d.actions);
        }
        // No registry revert, kill or quarantine leaks out as a standalone action.
        assert!(
            all_actions(&out)
                .iter()
                .all(|a| !matches!(a, ResponseAction::RemoveAutorun { .. })),
            "{name}"
        );
    }
}

#[test]
fn lsass_and_protected_processes_never_targeted() {
    for name in POSITIVE.iter().chain(BENIGN) {
        let out = protect(name);
        for a in all_actions(&out) {
            match &a {
                ResponseAction::KillProcess { pid, guid, .. }
                | ResponseAction::SuspendProcess { pid, guid } => {
                    assert_ne!(*pid, LSASS_PID, "{name}: {a:?}");
                    let g = guid.clone().map(|g| g.0).unwrap_or_default();
                    for p in [
                        "lsass-1",
                        "wininit-1",
                        "csrss-1",
                        "svchost-1",
                        "svchost-wer",
                        "msmpeng-1",
                        "explorer-1",
                    ] {
                        assert_ne!(g, p, "{name}: {a:?}");
                    }
                }
                ResponseAction::QuarantineFile { path, .. } => {
                    assert!(
                        !path.to_ascii_lowercase().contains(r"\windows\system32\"),
                        "{name}: {path}"
                    );
                }
                _ => {}
            }
        }
    }
}

// ---------------------------------------------------------------- per-rule actions

#[test]
fn cd01_comsvcs_kills_and_quarantines_dump() {
    let out = protect("cd_comsvcs_minidump");
    let d = alert_for(&out, "CD-01", "rundll-1");
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(killed(&d.actions), vec!["rundll-1"]);
    assert_eq!(
        quarantined(&d.actions),
        vec![r"C:\Users\alice\AppData\Local\Temp\out.dmp"]
    );
    // CD-03 is not raised on top of the stronger CD-01 for the same handle.
    assert!(!cd_ids(&out).contains("CD-03"));
    // Default policy: CD-01 is Protect from day one.
    let out = run("cd_comsvcs_minidump", Policy::default());
    assert!(!alert_for(&out, "CD-01", "rundll-1").actions.is_empty());
}

#[test]
fn cd01_ordinal_variants_and_non_lsass_target() {
    for cmd in [
        r"rundll32 C:\windows\system32\comsvcs.dll #+0000024 624 C:\Users\Public\l.bin full",
        r"rundll32.exe comsvcs.dll,#65560 624 C:\Users\Public\l.bin full",
        r#"rundll32.exe "C:\Windows\System32\comsvcs.dll",MiniDump 624 "C:\Users\Public\a b.dmp" full"#,
    ] {
        let mut e = with_lsass(policy_all(RuleMode::Protect));
        let out = e.process(&ev(
            1000,
            "r",
            900,
            EventData::ProcessStart(ProcessStart {
                ppid: 4000,
                image: r"C:\Windows\System32\rundll32.exe".into(),
                cmdline: cmd.into(),
                signed: SignatureState::Valid,
                signer: Some("Microsoft Windows".into()),
                ..Default::default()
            }),
        ));
        let d = alert_for(&out, "CD-01", "r");
        assert_eq!(killed(&d.actions), vec!["r"], "{cmd}");
    }
    // A cmd.exe wrapper is not the dumper (its rundll32 child is).
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    let out = e.process(&ev(
        1000,
        "c",
        901,
        EventData::ProcessStart(ProcessStart {
            ppid: 4000,
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: r"cmd /c rundll32 comsvcs.dll MiniDump 624 C:\Users\Public\l.dmp full".into(),
            signed: SignatureState::Valid,
            signer: Some("Microsoft Windows".into()),
            ..Default::default()
        }),
    ));
    assert!(cd_ids(&out).is_empty(), "{}", dump(&out));
    // comsvcs MiniDump of notepad: medium, no response.
    let out = protect("cd_comsvcs_notepad_benign");
    let d = alert_for(&out, "CD-01", "rundll-2");
    assert_eq!(d.alert.severity, Severity::Medium);
    assert!(d.actions.is_empty());
    assert_eq!(cd_ids(&out), ids(&["CD-01"]));
}

#[test]
fn cd02_signed_procdump_alerts_renamed_is_killed() {
    let out = protect("cd_procdump_lsass");
    let d = alert_for(&out, "CD-02", "procdump-1");
    assert!(d.actions.is_empty(), "signed procdump only alerts");
    // The handle (CD-03) suspends; the dump file (CD-04) kills.
    assert_eq!(
        suspended(&alert_for(&out, "CD-03", "procdump-1").actions),
        vec!["procdump-1"]
    );
    let d4 = alert_for(&out, "CD-04", "procdump-1");
    assert_eq!(killed(&d4.actions), vec!["procdump-1"]);
    assert!(
        quarantined(&d4.actions).contains(&r"C:\Users\alice\Downloads\Procdump\l.dmp".to_string())
    );

    let out = protect("cd_procdump_renamed");
    let d = alert_for(&out, "CD-02", "svc-1");
    assert_eq!(killed(&d.actions), vec!["svc-1"]);
    assert_eq!(quarantined(&d.actions), vec![r"C:\Users\Public\svc.exe"]);
}

#[test]
fn cd02_cd08_werfaultsecure_outside_system32() {
    let out = protect("cd_werfaultsecure_copy");
    for rule in ["CD-02", "CD-08"] {
        let d = alert_for(&out, rule, "wfs-1");
        assert_eq!(d.alert.severity, Severity::Critical);
        assert_eq!(killed(&d.actions), vec!["wfs-1"], "{rule}");
        // V-H4 / V-M5: a validly signed (Microsoft) copy is never
        // quarantined, wherever it sits; the process is still killed.
        assert!(quarantined(&d.actions).is_empty(), "{rule}");
    }
}

#[test]
fn cd02_mimikatz_syntax_and_tool_names() {
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    let out = e.process(&ev(
        1000,
        "ps",
        910,
        EventData::ProcessStart(ProcessStart {
            ppid: 4000,
            image: r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe".into(),
            cmdline: r#"powershell -c "Invoke-Mimikatz -Command 'sekurlsa::logonpasswords'""#
                .into(),
            signed: SignatureState::Valid,
            signer: Some("Microsoft Windows".into()),
            ..Default::default()
        }),
    ));
    assert_eq!(killed(&alert_for(&out, "CD-02", "ps").actions), vec!["ps"]);
    let out = e.process(&start(
        2000,
        "nano",
        911,
        r"C:\Users\Public\nanodump.x64.exe",
        SignatureState::Unsigned,
        None,
    ));
    assert_eq!(
        killed(&alert_for(&out, "CD-02", "nano").actions),
        vec!["nano"]
    );
    // `cmd /c procdump -ma lsass` does not kill the shell.
    let out = e.process(&ev(
        3000,
        "cmdw",
        912,
        EventData::ProcessStart(ProcessStart {
            ppid: 4000,
            image: r"C:\Windows\System32\cmd.exe".into(),
            cmdline: "cmd /c procdump64 -accepteula -ma lsass.exe l.dmp".into(),
            signed: SignatureState::Valid,
            signer: Some("Microsoft Windows".into()),
            ..Default::default()
        }),
    ));
    assert!(cd_ids(&out).is_empty(), "{}", dump(&out));
}

#[test]
fn cd03_suspends_only_in_protect_and_defaults_to_audit() {
    let out = protect("cd_lsass_handle_unsigned");
    let d = alert_for(&out, "CD-03", "tool-1");
    assert_eq!(d.alert.severity, Severity::High);
    // Suspended (by CD-03, or already by an earlier suspend window, e.g. ST-12
    // for an unsigned Temp binary: the engine never double-suspends).
    assert_eq!(suspended(&all_actions(&out)), vec!["tool-1"]);
    assert!(killed(&d.actions).is_empty());
    let out = run("cd_lsass_handle_unsigned", Policy::default());
    let d = alert_for(&out, "CD-03", "tool-1");
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert!(d.actions.is_empty());
}

#[test]
fn cd03_name_alone_is_not_trust() {
    let mut e = with_lsass(policy_all(RuleMode::Audit));
    // A "MsMpEng.exe" in a user folder, an unsigned "svchost.exe" in System32.
    e.process(&start(
        100,
        "fake-av",
        920,
        r"C:\Users\Public\MsMpEng.exe",
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    e.process(&start(
        110,
        "fake-svc",
        921,
        r"C:\Windows\System32\svchost.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        120,
        "fake-falcon",
        922,
        r"C:\Users\Public\CSFalconService.exe",
        SignatureState::Valid,
        Some("CrowdStrike, Inc."),
    ));
    for (g, pid) in [("fake-av", 920), ("fake-svc", 921), ("fake-falcon", 922)] {
        let out = e.process(&open_lsass(1000, g, pid, 0x1410, 0));
        alert_for(&out, "CD-03", g);
    }
    // A third-party signed process in Program Files not on the list: medium.
    e.process(&start(
        130,
        "vendor",
        923,
        r"C:\Program Files\Contoso\agent.exe",
        SignatureState::Valid,
        Some("Contoso Ltd"),
    ));
    let out = e.process(&open_lsass(1100, "vendor", 923, 0x1410, 0));
    assert_eq!(
        alert_for(&out, "CD-03", "vendor").alert.severity,
        Severity::Medium
    );
    // procexp asking for more than DUP_HANDLE is not covered by its allow-list entry.
    e.process(&start(
        140,
        "procexp",
        924,
        r"C:\Users\alice\Downloads\procexp64.exe",
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&open_lsass(1200, "procexp", 924, 0x1410, 0));
    alert_for(&out, "CD-03", "procexp");
}

#[test]
fn cd03_target_must_be_the_real_lsass() {
    let mut e = with_lsass(policy_all(RuleMode::Audit));
    e.process(&start(
        100,
        "t",
        930,
        r"C:\Users\Public\t.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        110,
        "fake-lsass",
        931,
        r"C:\Users\Public\lsass.exe",
        SignatureState::Unsigned,
        None,
    ));
    for (pid, guid, image) in [
        (931, Some("fake-lsass"), r"C:\Users\Public\lsass.exe"),
        (4_294_967_295, None, ""),
        (931, None, r"E:\Windows\System32\lsass.exe"),
    ] {
        let out = e.process(&ev(
            1000,
            "t",
            930,
            EventData::ProcessAccess(TargetProcess {
                target_pid: pid,
                target_guid: guid.map(|g| ProcessGuid(g.into())),
                target_image: image.into(),
                granted_access: 0x1FFFFF,
                return_code: 0,
            }),
        ));
        assert!(cd_ids(&out).is_empty(), "{image}: {}", dump(&out));
    }
    // Query-only rights on the real lsass are not dangerous.
    for mask in [0x1000, 0x1400, 0x400, 0x100000, 0x1200] {
        let out = e.process(&open_lsass(2000, "t", 930, mask, 0));
        assert!(cd_ids(&out).is_empty(), "0x{mask:x}");
    }
    // Real lsass by pid only (no target guid): fires.
    let out = e.process(&ev(
        3000,
        "t",
        930,
        EventData::ProcessAccess(TargetProcess {
            target_pid: LSASS_PID,
            target_guid: None,
            target_image: String::new(),
            granted_access: 0x0200_0000,
            return_code: 0,
        }),
    ));
    alert_for(&out, "CD-03", "t");
}

#[test]
fn cd04_window_and_taskmgr_dump() {
    let out = protect("cd_taskmgr_dump");
    let d3 = alert_for(&out, "CD-03", "taskmgr-1");
    assert_eq!(d3.alert.severity, Severity::High);
    let d4 = alert_for(&out, "CD-04", "taskmgr-1");
    assert_eq!(killed(&d4.actions), vec!["taskmgr-1"]);
    assert_eq!(
        quarantined(&d4.actions),
        vec![r"C:\Users\alice\AppData\Local\Temp\lsass.DMP"]
    );
    // Evidence carries the LSASS handle event as well as the file event.
    assert!(d4
        .alert
        .evidence
        .iter()
        .any(|e| matches!(e.data, EventData::ProcessAccess(_))));

    // Dump file 121 s after the open: outside the window.
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    e.process(&start(
        100,
        "late",
        940,
        r"C:\Users\Public\late.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&open_lsass(1000, "late", 940, 0x1410, 0));
    let out = e.process(&create(122_000, "late", 940, r"C:\Users\Public\x.dmp"));
    assert!(!cd_ids(&out).contains("CD-04"), "{}", dump(&out));
    // Dump-file evidence from the ransomware sensor summary also counts.
    e.process(&start(
        130_000,
        "fa",
        941,
        r"C:\Users\Public\fa.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&open_lsass(131_000, "fa", 941, 0x1410, 0));
    let out = e.process(&ev(
        132_000,
        "fa",
        941,
        EventData::FileActivity(FileActivity {
            window_ms: 1000,
            files_touched: 1,
            dirs: 1,
            new_files: 1,
            sample_paths: vec![r"C:\Users\Public\out.mdmp".into()],
            ..Default::default()
        }),
    ));
    assert_eq!(killed(&alert_for(&out, "CD-04", "fa").actions), vec!["fa"]);
}

#[test]
fn cd05_needs_both_facts() {
    let out = protect("cd_dbghelp_dumper");
    let d = alert_for(&out, "CD-05", "upd-1");
    assert_eq!(killed(&d.actions), vec!["upd-1"]);
    assert_eq!(
        quarantined(&d.actions),
        vec![r"C:\Users\alice\AppData\Roaming\upd\upd.exe"]
    );
    // Open first, library later (within 60 s) also counts; beyond 60 s it does not.
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    e.process(&start(
        100,
        "a",
        950,
        r"C:\Users\Public\a.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&open_lsass(1000, "a", 950, 0x1410, 0));
    let load = |ts| {
        ev(
            ts,
            "a",
            950,
            EventData::ImageLoad {
                path: r"C:\Windows\System32\dbgcore.dll".into(),
                signer: Some("Microsoft Windows".into()),
                signed: SignatureState::Valid,
            },
        )
    };
    let out = e.process(&load(30_000));
    alert_for(&out, "CD-05", "a");
    e.process(&start(
        100,
        "b",
        951,
        r"C:\Users\Public\b.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&open_lsass(100_000, "b", 951, 0x1410, 0));
    let out = e.process(&ev(
        170_000,
        "b",
        951,
        EventData::ImageLoad {
            path: r"C:\Windows\System32\dbghelp.dll".into(),
            signer: Some("Microsoft Windows".into()),
            signed: SignatureState::Valid,
        },
    ));
    assert!(!cd_ids(&out).contains("CD-05"));
}

#[test]
fn cd06_failed_attempt_is_audit_hunting_alert() {
    let out = run("cd_ppl_attempt", Policy::default());
    let d = alert_for(&out, "CD-06", "tool-2");
    assert_eq!(d.alert.severity, Severity::High);
    assert!(d.actions.is_empty());
    assert!(d.alert.summary.contains("0xC0000022"));
    // A failed open never arms CD-04.
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    replay(&mut e, &fixture("cd_ppl_attempt.jsonl")[4..]);
    let out = e.process(&create(5000, "tool-2", 5900, r"C:\Users\Public\lsass.dmp"));
    assert!(!cd_ids(&out).contains("CD-04"), "{}", dump(&out));
    // Protect (if an admin enables it): suspend, never kill.
    let out = protect("cd_ppl_attempt");
    let d = alert_for(&out, "CD-06", "tool-2");
    assert_eq!(suspended(&all_actions(&out)), vec!["tool-2"]);
    assert!(killed(&d.actions).is_empty());
}

#[test]
fn cd07_kills_writer_and_deletes_value() {
    let out = protect("cd_silentprocessexit");
    let d = alert_for(&out, "CD-07", "reg-1");
    assert_eq!(killed(&d.actions), vec!["reg-1"]);
    assert!(d.actions.contains(&ResponseAction::RemoveAutorun {
        kind: AutorunKind::RegistryValue,
        location: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe"
            .into(),
        value_name: Some("ReportingMode".into()),
        restore_data: None,
    }));
    let d = alert_for(&out, "CD-07", "reg-2");
    assert!(d.actions.iter().any(|a| matches!(a,
        ResponseAction::RemoveAutorun { value_name: Some(v), restore_data: None, .. } if v == "GlobalFlag")));
}

#[test]
fn cd07_protected_writer_is_not_killed_but_value_is_reverted() {
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    e.process(&start(
        100,
        "svc",
        1210,
        r"C:\Windows\System32\svchost.exe",
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&ev(
        1000,
        "svc",
        1210,
        EventData::RegistrySet {
            attribution: Default::default(),
            target: None,
            key: r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe"
                .into(),
            value_name: "LocalDumpFolder".into(),
            data: Some(r"C:\Users\Public".into()),
            op: RegistryOp::Set,
        },
    ));
    let d = alert_for(&out, "CD-07", "svc");
    assert!(killed(&d.actions).is_empty(), "{:?}", d.actions);
    assert!(d
        .actions
        .iter()
        .any(|a| matches!(a, ResponseAction::RemoveAutorun { .. })));
}

#[test]
fn cd08_wer_lsass_dump() {
    let out = protect("cd_wer_shtinkering");
    let d = alert_for(&out, "CD-08", "werfault-1");
    assert_eq!(killed(&d.actions), vec!["werfault-1"]);
    // The dump arrives later: the re-hit still quarantines it (dedup keeps one alert).
    assert_eq!(cd_alerts(&out).len(), 1);
    assert!(all_actions(&out).iter().any(|a| matches!(a,
        ResponseAction::QuarantineFile { path, .. } if path.ends_with(r"CrashDumps\lsass.exe.624.dmp"))));
}

#[test]
fn cd09_ssp_never_kills_lsass() {
    let out = protect("cd_ssp");
    let reg = alert_for(&out, "CD-09", "reg-4");
    assert!(reg.alert.summary.contains("mimilib"));
    assert!(killed(&reg.actions).is_empty());
    assert!(
        !reg.actions
            .iter()
            .any(|a| matches!(a, ResponseAction::RemoveAutorun { .. })),
        "LSA package values are not reverted automatically"
    );
    let lsass: Vec<&Detection> = cd_alerts(&out)
        .into_iter()
        .filter(|d| d.alert.process.guid.0 == LSASS_GUID)
        .collect();
    assert_eq!(lsass.len(), 2, "DLL load + kiwissp.log:\n{}", dump(&out));
    for d in lsass {
        assert!(killed(&d.actions).is_empty() && suspended(&d.actions).is_empty());
    }
    assert_eq!(cd_ids(&out), ids(&["CD-09"]));
    // CD-09 defaults to Audit.
    let out = run("cd_ssp", Policy::default());
    assert!(cd_alerts(&out)
        .iter()
        .all(|d| d.alert.mode == RuleMode::Audit && d.actions.is_empty()));
}

#[test]
fn cd10_reg_save_sam_kills_system_alerts() {
    let out = protect("cd_reg_save");
    let sam = alert_for(&out, "CD-10", "reg-5");
    assert_eq!(sam.alert.severity, Severity::Critical);
    assert_eq!(killed(&sam.actions), vec!["reg-5"]);
    // V-H4: the output path is attacker text and C:\Users\Public is not the
    // subject's own profile, so it is not quarantined (only the kill stays).
    assert!(quarantined(&sam.actions).is_empty(), "{:?}", sam.actions);
    let sys = alert_for(&out, "CD-10", "reg-6");
    assert_eq!(sys.alert.severity, Severity::High);
    assert!(sys.actions.is_empty());
    // Shadow-copy access is Audit evidence only, even in Protect.
    let out = protect("cd_shadow_hive");
    for g in ["hc-1", "cmd-3"] {
        assert!(alert_for(&out, "CD-10", g).actions.is_empty(), "{g}");
    }
}

#[test]
fn cd11_ntds_variants() {
    let out = protect("cd_ntds");
    for g in ["ntdsutil-1", "cmd-4", "nd-1"] {
        alert_for(&out, "CD-11", g);
    }
    let nd = alert_for(&out, "CD-11", "nd-1");
    assert_eq!(killed(&nd.actions), vec!["nd-1"]);
    assert_eq!(
        quarantined(&nd.actions),
        vec![r"C:\Users\Public\loot\ntds.dit"]
    );
    // Defaults to Audit (IFM is a legitimate DC admin action).
    let out = run("cd_ntds", Policy::default());
    assert!(cd_alerts(&out)
        .iter()
        .all(|d| d.alert.mode == RuleMode::Audit && d.actions.is_empty()));
}

#[test]
fn cd12_wdigest_revert_only() {
    let out = run("cd_wdigest", Policy::default());
    let d = alert_for(&out, "CD-12", "reg-9");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(
        d.actions,
        vec![ResponseAction::RemoveAutorun {
            kind: AutorunKind::RegistryValue,
            location: r"HKLM\SYSTEM\ControlSet001\Control\SecurityProviders\WDigest".into(),
            value_name: Some("UseLogonCredential".into()),
            restore_data: Some("dword:0".into()),
        }]
    );
    assert!(killed(&d.actions).is_empty());
}

#[test]
fn cd13_tamper_is_alert_only() {
    let out = protect("cd_lsa_tamper");
    let n = cd_alerts(&out).len();
    assert_eq!(n, 5, "{}", dump(&out));
    for d in cd_alerts(&out) {
        assert_eq!(d.alert.rule_id, "CD-13");
        assert!(d.actions.is_empty(), "{:?}", d.actions);
    }
    let ksl: Vec<String> = cd_alerts(&out)
        .iter()
        .filter(|d| d.alert.process.guid.0 == "ksl-1")
        .map(|d| d.alert.summary.clone())
        .collect();
    assert_eq!(
        ksl.len(),
        3,
        "KslD + DisableRestrictedAdmin + driver: {ksl:?}"
    );
}

#[test]
fn state_is_bounded_and_engine_survives_floods() {
    let mut e = with_lsass(policy_all(RuleMode::Audit));
    for i in 0..5000u32 {
        let g = format!("p{i}");
        e.process(&ev(
            1000 + i as i64,
            &g,
            20_000 + i,
            EventData::ImageLoad {
                path: r"C:\Windows\System32\dbghelp.dll".into(),
                signer: None,
                signed: SignatureState::Valid,
            },
        ));
    }
    // Ticks prune; a later legit sequence still works.
    e.tick(T0 + 400_000);
    e.process(&start(
        400_100,
        "z",
        990,
        r"C:\Users\Public\z.exe",
        SignatureState::Unsigned,
        None,
    ));
    e.process(&open_lsass(400_200, "z", 990, 0x1010, 0));
    let out = e.process(&create(400_300, "z", 990, r"C:\Users\Public\z.dmp"));
    alert_for(&out, "CD-04", "z");
}

// ---------------------------------------------------------------- corpus finding 10, FP-09 / FP-11 / FP-12 (2026-10-25)

/// (rule, severity) of every CD alert on `guid`.
fn cd_on(out: &[Output], guid: &str) -> Vec<(String, Severity)> {
    cd_alerts(out)
        .iter()
        .filter(|d| d.alert.process.guid.0 == guid)
        .map(|d| (d.alert.rule_id.clone(), d.alert.severity))
        .collect()
}

#[test]
fn fam2_cd_wbadmin_ntds_and_hives() {
    // Corpus finding 10 (Akira): wbadmin start backup -include: NTDS.dit and
    // the SYSTEM / SECURITY hives.
    for out in [
        audit("fam2_cd_wbadmin_ntds"),
        protect("fam2_cd_wbadmin_ntds"),
        run("fam2_cd_wbadmin_ntds", Policy::default()),
    ] {
        let wb1 = cd_on(&out, "wb-1");
        assert!(
            wb1.contains(&("CD-11".into(), Severity::High))
                && wb1.contains(&("CD-10".into(), Severity::High)),
            "{}",
            dump(&out)
        );
        assert_eq!(
            cd_on(&out, "wb-2"),
            vec![("CD-10".to_string(), Severity::High)],
            "{}",
            dump(&out)
        );
        assert_eq!(
            cd_on(&out, "wb-3"),
            vec![("CD-11".to_string(), Severity::High)],
            "{}",
            dump(&out)
        );
    }
    // Protect: CD-11 kills wbadmin; the hive variant alerts only.
    let out = protect("fam2_cd_wbadmin_ntds");
    assert_eq!(
        killed(&alert_for(&out, "CD-11", "wb-1").actions),
        vec!["wb-1"]
    );
    assert!(alert_for(&out, "CD-10", "wb-2").actions.is_empty());
    // Default policy: CD-11 stays Audit.
    let out = run("fam2_cd_wbadmin_ntds", Policy::default());
    assert!(alert_for(&out, "CD-11", "wb-1").actions.is_empty());
}

#[test]
fn fam2_cd_wbadmin_and_ntdsutil_benign_are_silent() {
    for out in [
        audit("fam2_cd_wbadmin_benign"),
        protect("fam2_cd_wbadmin_benign"),
    ] {
        assert!(cd_ids(&out).is_empty(), "{}", dump(&out));
    }
}

#[test]
fn fam2_cd_ntdsutil_ifm_spellings() {
    for out in [
        audit("fam2_cd_ntdsutil_ifm"),
        protect("fam2_cd_ntdsutil_ifm"),
    ] {
        for g in ["ifm-1", "ifm-2", "ifm-3"] {
            assert_eq!(
                cd_on(&out, g),
                vec![("CD-11".to_string(), Severity::High)],
                "{g}: {}",
                dump(&out)
            );
        }
    }
}

#[test]
fn fam2_cd02_text_tools_with_lsass_in_a_pattern_are_silent() {
    // FP-09: grep / rg / findstr / git grep / a tool whose pattern merely
    // contains "lsass".
    for out in [
        audit("fam2_cd_text_tools_benign"),
        protect("fam2_cd_text_tools_benign"),
        run("fam2_cd_text_tools_benign", Policy::default()),
    ] {
        assert!(cd_ids(&out).is_empty(), "{}", dump(&out));
    }
}

#[test]
fn fam2_cd02_needs_dump_flag_and_lsass_target_argument() {
    // A procdump renamed grep.exe (-ma), an unsigned clone (-r, path to
    // lsass.exe) and a PID target (-mm 624) are still CD-02 and killed.
    let out = protect("fam2_cd_procdump_target_args");
    for g in ["fakegrep-1", "clone-1", "pid-1"] {
        let d = alert_for(&out, "CD-02", g);
        assert_eq!(d.alert.severity, Severity::Critical, "{g}");
        assert_eq!(killed(&d.actions), vec![g.to_string()]);
    }
    let out = audit("fam2_cd_procdump_target_args");
    assert_eq!(cd_ids(&out), ids(&["CD-02"]), "{}", dump(&out));
    // The existing renamed-procdump fixture still fires.
    assert!(cd_ids(&protect("cd_procdump_renamed")).contains("CD-02"));
}

/// Roblox-like process start with explicit user, signature and signer.
fn roblox_start(
    ts: i64,
    guid: &str,
    pid: u32,
    image: &str,
    user: &str,
    signed: SignatureState,
    signer: Option<&str>,
) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ProcessStart(ProcessStart {
            ppid: 4000,
            parent_guid: Some(ProcessGuid("explorer-1".into())),
            image: image.into(),
            cmdline: format!("\"{image}\""),
            user: Some(user.into()),
            signed,
            signer: signer.map(Into::into),
            ..Default::default()
        }),
    )
}

const ROBLOX: &str =
    r"C:\Users\alice\AppData\Local\Roblox\Versions\version-9ac8595712b447a7\RobloxPlayerBeta.exe";
const DENIED: u32 = 0xC000_0022;

#[test]
fn fam2_cd06_genuine_roblox_refused_probe_is_low_audit() {
    // FP-11: the owner-PC sequence (0x40A on LSASS, refused).
    for out in [
        run("fam2_cd_roblox_refused", Policy::default()),
        protect("fam2_cd_roblox_refused"),
    ] {
        assert_eq!(
            cd_on(&out, "roblox-1"),
            vec![("CD-06".to_string(), Severity::Low)],
            "{}",
            dump(&out)
        );
        let d = alert_for(&out, "CD-06", "roblox-1");
        assert_eq!(d.alert.mode, RuleMode::Audit);
        assert!(all_actions(&out).is_empty(), "{:?}", all_actions(&out));
    }
    // Per-machine install under Program Files (x86): also Low.
    let mut e = with_lsass(policy_all(RuleMode::Protect));
    e.process(&roblox_start(
        1_000,
        "rb-pf",
        4800,
        r"C:\Program Files (x86)\Roblox\Versions\version-0123abcd\RobloxPlayerBeta.exe",
        r"CORP\alice",
        SignatureState::Valid,
        Some("Roblox Corporation"),
    ));
    let out = e.process(&open_lsass(1_100, "rb-pf", 4800, 0x40A, DENIED));
    assert_eq!(
        cd_on(&out, "rb-pf"),
        vec![("CD-06".to_string(), Severity::Low)]
    );
}

/// (guid, image, user, signature, signer, requested mask).
type ProbeCase<'a> = (
    &'a str,
    &'a str,
    &'a str,
    SignatureState,
    Option<&'a str>,
    u32,
);

#[test]
fn fam2_cd06_roblox_lookalikes_and_dangerous_masks_stay_high() {
    let cases: &[ProbeCase] = &[
        // dangerous masks from the genuine client
        (
            "m-read",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x1410,
        ),
        (
            "m-write",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A | 0x20,
        ),
        (
            "m-dup",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x440,
        ),
        (
            "m-full",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x1F_FFFF,
        ),
        (
            "m-max",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x0200_000A,
        ),
        // wrong identity
        (
            "unsigned",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Unsigned,
            None,
            0x40A,
        ),
        (
            "invalid",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Invalid,
            Some("Roblox Corporation"),
            0x40A,
        ),
        (
            "signer-ltd",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation Ltd"),
            0x40A,
        ),
        (
            "signer-sub",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("Not Roblox Corporation"),
            0x40A,
        ),
        (
            "signer-case",
            ROBLOX,
            r"CORP\alice",
            SignatureState::Valid,
            Some("roblox corporation"),
            0x40A,
        ),
        // relocated copies
        (
            "temp",
            r"C:\Users\alice\AppData\Local\Temp\RobloxPlayerBeta.exe",
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A,
        ),
        (
            "other-user",
            r"C:\Users\bob\AppData\Local\Roblox\Versions\version-9ac8595712b447a7\RobloxPlayerBeta.exe",
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A,
        ),
        (
            "bad-version",
            r"C:\Users\alice\AppData\Local\Roblox\Versions\version-..\RobloxPlayerBeta.exe",
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A,
        ),
        (
            "other-drive",
            r"D:\Users\alice\AppData\Local\Roblox\Versions\version-9ac8\RobloxPlayerBeta.exe",
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A,
        ),
        (
            "renamed",
            r"C:\Users\alice\AppData\Local\Roblox\Versions\version-9ac8\RobloxPlayer.exe",
            r"CORP\alice",
            SignatureState::Valid,
            Some("Roblox Corporation"),
            0x40A,
        ),
    ];
    for (i, (g, image, user, signed, signer, mask)) in cases.iter().enumerate() {
        let mut e = with_lsass(policy_all(RuleMode::Audit));
        let pid = 6000 + i as u32;
        e.process(&roblox_start(1_000, g, pid, image, user, *signed, *signer));
        let out = e.process(&open_lsass(1_100, g, pid, *mask, DENIED));
        assert_eq!(
            cd_on(&out, g),
            vec![("CD-06".to_string(), Severity::High)],
            "{g}: {}",
            dump(&out)
        );
    }
    // A successful open by the genuine client is CD-03, not a Low CD-06.
    let mut e = with_lsass(policy_all(RuleMode::Audit));
    e.process(&roblox_start(
        1_000,
        "ok-open",
        7100,
        ROBLOX,
        r"CORP\alice",
        SignatureState::Valid,
        Some("Roblox Corporation"),
    ));
    let out = e.process(&open_lsass(1_100, "ok-open", 7100, 0x40A, 0));
    let got = cd_on(&out, "ok-open");
    assert!(
        got.iter().any(|(r, _)| r == "CD-03") && got.iter().all(|(r, _)| r != "CD-06"),
        "{}",
        dump(&out)
    );
}

#[test]
fn fam2_cd13_nordvpn_own_drivers_are_low() {
    // FP-12: NordVPN (re)installing travis.sys / NDivert.sys from its
    // versioned Program Files folders (unattributed, no signer).
    for out in [
        audit("fam2_cd_nordvpn_drivers"),
        protect("fam2_cd_nordvpn_drivers"),
    ] {
        let alerts = cd_alerts(&out);
        assert!(!alerts.is_empty(), "{}", dump(&out));
        for d in alerts {
            assert_eq!(d.alert.rule_id, "CD-13");
            assert_eq!(d.alert.severity, Severity::Low, "{}", dump(&out));
            assert!(d.actions.is_empty());
        }
    }
}

#[test]
fn fam2_cd13_nordvpn_lookalike_drivers_stay_medium() {
    // Wrong folder, wrong service name for the path, wrong file for the
    // service name, `..` traversal, another drive.
    for out in [
        audit("fam2_cd_nordvpn_lookalike_drivers"),
        protect("fam2_cd_nordvpn_lookalike_drivers"),
    ] {
        let alerts = cd_alerts(&out);
        assert_eq!(alerts.len(), 6, "{}", dump(&out));
        for d in alerts {
            assert_eq!(d.alert.rule_id, "CD-13");
            assert_eq!(d.alert.severity, Severity::Medium, "{}", dump(&out));
            assert!(d.actions.is_empty());
        }
    }
}
