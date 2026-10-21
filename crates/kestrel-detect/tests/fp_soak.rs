//! False positives from the 2026-10-21 soak in the Windows 11 lab VM (all
//! rules in Audit; Chrome, Firefox, VS Code, Notepad++, 7-Zip, KeePassXC,
//! Bitwarden, Zoom, Git, Python and PowerToys installed and used). Each is
//! fixed narrowly per rule; every test also asserts that the malicious
//! variant still fires. Item 5 (Sigma on the agent's own PowerShell) is in
//! `sigma_pack.rs` and `kestrel-win/src/spawnreg.rs`.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

fn run_all(name: &str, mode: RuleMode) -> Vec<Output> {
    let mut e = engine(policy_all(mode));
    replay(&mut e, &fixture(name))
}

// ------------------------------------------------- 1. Chrome's updater helper

#[test]
fn chrome_os_update_handler_reading_local_state_is_benign() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("soak_chrome_updater_benign.jsonl", mode);
        assert!(out.is_empty(), "{mode:?}: {}", dump(&out));
    }
    // Malicious look-alike (same names, Temp, unsigned): ST-01 + ST-04.
    let out = run_all("soak_chrome_updater_fake.jsonl", RuleMode::Protect);
    let ids = rule_ids(&out);
    assert!(ids.contains(&"ST-01".to_string()), "{}", dump(&out));
    assert!(ids.contains(&"ST-04".to_string()), "{}", dump(&out));
}

#[test]
fn browser_install_tree_owner_is_narrow() {
    let osupd = r"C:\Program Files\Google\Chrome\Application\156.0.8078.48\os_update_handler.exe";
    let read_state = |image: &str, cmd: &str, signer: Option<&str>, path: &str| {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(
            0,
            "h",
            90,
            image,
            cmd,
            None,
            SignatureState::Valid,
            signer,
        ));
        e.process(&read(10, "h", 90, path))
    };
    let chrome_state = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Local State";
    let edge_state = r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Local State";
    // Genuine helper, own browser's store: silent.
    assert!(read_state(
        osupd,
        "os_update_handler.exe --system",
        Some("Google LLC"),
        chrome_state
    )
    .is_empty());
    // Edge's WebView2 reading Edge's own store: silent.
    assert!(read_state(
        r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\141.0.3537.71\msedgewebview2.exe",
        "msedgewebview2.exe --embedded-browser-webview=1",
        Some("Microsoft Corporation"),
        edge_state
    )
    .is_empty());
    // Another browser's store: fires (owner of its own browser only).
    let out = read_state(
        osupd,
        "os_update_handler.exe",
        Some("Google LLC"),
        edge_state,
    );
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    // Wrong signer / remote-control switch / per-user copy: fires.
    for (img, cmd, signer) in [
        (osupd, "os_update_handler.exe", Some("Evil Ltd")),
        (
            osupd,
            "os_update_handler.exe --remote-debugging-port=9222",
            Some("Google LLC"),
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\Application\156.0.8078.48\os_update_handler.exe",
            "os_update_handler.exe",
            Some("Google LLC"),
        ),
    ] {
        let out = read_state(img, cmd, signer, chrome_state);
        assert_eq!(rule_ids(&out), ["ST-01"], "{img} {cmd}: {}", dump(&out));
    }
}

// --------------------------------------------------- 2. VS Code and WAM cache

/// The token-cache read by genuine VS Code is recorded and alerted Low /
/// Audit (re-review N2: never silent); the following send is ST-04 Audit,
/// so VS Code is not killed.
#[test]
fn vscode_reading_the_wam_cache_is_audit_only() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("soak_vscode_wam_benign.jsonl", mode);
        let st01 = first(&out, "ST-01");
        assert_eq!(st01.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st01.alert.mode, RuleMode::Audit);
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.mode, RuleMode::Audit, "{}", dump(&out));
        assert!(
            alerts(&out).iter().all(|d| d.actions.is_empty()),
            "{}",
            dump(&out)
        );
        assert!(standalone(&out).is_empty(), "{}", dump(&out));
    }
    // ELECTRON_RUN_AS_NODE style: Code.exe running a script → ST-04 kill.
    let out = run_all("soak_vscode_wam_script.jsonl", RuleMode::Protect);
    let st04 = first(&out, "ST-04");
    assert_eq!(
        kills(&st04.actions),
        [("code".to_string(), true)],
        "{}",
        dump(&out)
    );
}

/// Re-review N2: hosts that run arbitrary code without a script-file
/// argument never get the WAM-client treatment: their token-cache read is
/// a normal ST-01 (suspend) and the send a full ST-04.
#[test]
fn wam_exemption_excludes_macro_eval_and_node_hosts() {
    let code = r"C:\Program Files\Microsoft VS Code\Code.exe";
    let tbres = r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres";
    for (img, cmd, signer) in [
        (code, "Code.exe", "Evil Ltd"),
        (
            r"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            "Code.exe",
            "Microsoft Corporation",
        ),
        (code, "Code.exe --inspect=9229", "Microsoft Corporation"),
        (
            code,
            r#"Code.exe "resources\app\out\cli.js""#,
            "Microsoft Corporation",
        ),
        // ELECTRON_RUN_AS_NODE with an extension-less script / eval / stdin
        (
            code,
            r"Code.exe C:\Users\alice\AppData\Local\Temp\p.dat",
            "Microsoft Corporation",
        ),
        (
            code,
            r#"Code.exe -e "require('fs')""#,
            "Microsoft Corporation",
        ),
        (code, "Code.exe --eval=x", "Microsoft Corporation"),
        (code, "Code.exe -", "Microsoft Corporation"),
        (code, "Code.exe -p 1", "Microsoft Corporation"),
        // .NET / C# script hosts
        (
            r"C:\Program Files\dotnet\dotnet.exe",
            "dotnet.exe x.dll",
            "Microsoft Corporation",
        ),
    ] {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(
            0,
            "c",
            61,
            img,
            cmd,
            None,
            SignatureState::Valid,
            Some(signer),
        ));
        let out = e.process(&read(10, "c", 61, tbres));
        assert!(!alerts(&out).is_empty(), "{img} {cmd}: no alert");
        let st01 = first(&out, "ST-01");
        assert_ne!(
            st01.alert.severity,
            Severity::Low,
            "{img} {cmd}: {}",
            dump(&out)
        );
        assert!(
            action_names(&st01.actions).contains(&"suspend_process"),
            "{img} {cmd}: {}",
            dump(&out)
        );
        let out = e.process(&connect(20, "c", 61, "45.61.136.10", 443));
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.mode, RuleMode::Protect, "{img} {cmd}");
        assert!(
            !kills(&st04.actions).is_empty(),
            "{img} {cmd}: {}",
            dump(&out)
        );
    }
    // Browser credential stores stay owner-only for genuine VS Code.
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "code",
        60,
        code,
        "Code.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&read(10, "code", 60, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low);
}

/// Re-review N2, Office: a WAM client, so its token-cache read is never
/// silent (Low / Audit, recorded); a macro that also reads a browser store
/// and sends is killed by ST-04.
#[test]
fn office_token_cache_read_is_recorded_and_escalates() {
    let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    let tbres = r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres";
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "w",
        62,
        word,
        r#"WINWORD.EXE /n "C:\Users\alice\Downloads\x.docm""#,
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&read(10, "w", 62, tbres));
    let st01 = first(&out, "ST-01");
    assert_eq!(st01.alert.severity, Severity::Low);
    assert_eq!(st01.alert.mode, RuleMode::Audit);
    // tbres only, then a send: ST-04 Audit.
    let out = e.process(&connect(20, "w", 62, "52.109.0.1", 443));
    assert_eq!(
        first(&out, "ST-04").alert.mode,
        RuleMode::Audit,
        "{}",
        dump(&out)
    );
    // Macro reads Chrome cookies too, then sends: ST-04 Protect, killed.
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "w",
        62,
        word,
        "WINWORD.EXE",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    e.process(&read(10, "w", 62, tbres));
    e.process(&read(11, "w", 62, CHROME_COOKIES));
    let out = e.process(&connect(20, "w", 62, "45.61.136.10", 443));
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
    assert_eq!(kills(&st04.actions), [("w".to_string(), true)]);
}

/// WAM + another store → ST-04 is no longer WAM-only: full response.
#[test]
fn wam_read_still_counts_for_correlation() {
    let code = r"C:\Program Files\Microsoft VS Code\Code.exe";
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "code",
        60,
        code,
        "Code.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    e.process(&read(
        10,
        "code",
        60,
        r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres",
    ));
    e.process(&read(11, "code", 60, CHROME_LOGIN));
    let out = e.process(&connect(20, "code", 60, "45.61.136.10", 443));
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
    assert!(!kills(&st04.actions).is_empty());
}

/// Fresh-install lab 2026-10-21: Windows Widgets (`WindowsApps\
/// MicrosoftWindows.Client.WebExperience_*\Dashboard\Widgets.exe`, signed
/// `CN=Microsoft Windows` like every Windows inbox component) read the WAM
/// cache and got a Medium ST-01 with a suspend. "Microsoft Windows" is a
/// WAM-client signer under the same constraints as "Microsoft Corporation".
#[test]
fn windows_widgets_reading_the_wam_cache_is_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("fresh_widgets_wam_benign.jsonl", mode);
        let st01 = first(&out, "ST-01");
        assert_eq!(st01.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st01.alert.mode, RuleMode::Audit);
        assert!(
            alerts(&out).iter().all(|d| d.actions.is_empty()),
            "{}",
            dump(&out)
        );
        assert!(standalone(&out).is_empty(), "{}", dump(&out));
    }
    let widgets = r"C:\Program Files\WindowsApps\MicrosoftWindows.Client.WebExperience_526.21100.40.0_x64__cw5n1h2txyewy\Dashboard\Widgets.exe";
    let tbres = r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres";
    // Still narrow: a copy outside Program Files, a look-alike signer, an
    // invalid signature, a script argument and a "Microsoft Windows"-signed
    // LOLBin / script host in Program Files all keep the full ST-01.
    for (img, cmd, signer, sig) in [
        (
            r"C:\Users\alice\AppData\Local\Temp\Widgets.exe",
            "Widgets.exe -ServerName:Microsoft.Windows.DashboardServer",
            "Microsoft Windows",
            SignatureState::Valid,
        ),
        (
            widgets,
            "Widgets.exe",
            "Microsoft Windows Inc",
            SignatureState::Valid,
        ),
        (
            widgets,
            "Widgets.exe",
            "Microsoft Windows",
            SignatureState::Invalid,
        ),
        (
            widgets,
            r"Widgets.exe C:\Users\alice\AppData\Local\Temp\x.js",
            "Microsoft Windows",
            SignatureState::Valid,
        ),
        (
            r"C:\Program Files\WindowsApps\Evil_1.0.0.0_x64__abc\rundll32.exe",
            "rundll32.exe x.dll,Run",
            "Microsoft Windows",
            SignatureState::Valid,
        ),
        (
            r"C:\Program Files\WindowsApps\PythonSoftwareFoundation.Python.3.13_3.13.0.0_x64__qbz5n2kfra8p0\python.exe",
            "python.exe",
            "Microsoft Windows",
            SignatureState::Valid,
        ),
    ] {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(0, "w", 71, img, cmd, None, sig, Some(signer)));
        let out = e.process(&read(10, "w", 71, tbres));
        let st01 = first(&out, "ST-01");
        assert_ne!(
            st01.alert.severity,
            Severity::Low,
            "{img} {cmd} {signer}: {}",
            dump(&out)
        );
        assert!(
            action_names(&st01.actions).contains(&"suspend_process"),
            "{img} {cmd}: {}",
            dump(&out)
        );
    }
    // A Widgets read of a browser store stays a normal ST-01 (WAM only).
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "w",
        71,
        widgets,
        "Widgets.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&read(10, "w", 71, CHROME_LOGIN));
    assert_ne!(first(&out, "ST-01").alert.severity, Severity::Low);
}

// ------------------------------------------- 3. Restart Manager (msiexec) ST-07

fn msiexec_open(cmd: &str, user: &str, parent_services: bool, mask: u32) -> Vec<Output> {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&as_user(
        start(
            0,
            "services",
            700,
            r"C:\Windows\System32\services.exe",
            "services.exe",
            None,
            SignatureState::Valid,
            Some("Microsoft Windows Publisher"),
        ),
        r"NT AUTHORITY\SYSTEM",
    ));
    e.process(&as_user(
        start(
            1,
            "msi",
            70,
            r"C:\Windows\System32\msiexec.exe",
            cmd,
            parent_services.then_some(("services", 700)),
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        user,
    ));
    e.process(&ev(
        10,
        "msi",
        70,
        EventData::ProcessAccess(TargetProcess {
            target_pid: 80,
            target_guid: Some(g("edge")),
            target_image: r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe".into(),
            granted_access: mask,
            ..Default::default()
        }),
    ))
}

#[test]
fn msiexec_restart_manager_read_only_open_is_benign() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("soak_msiexec_rm_benign.jsonl", mode);
        assert!(out.is_empty(), "{mode:?}: {}", dump(&out));
    }
    for mask in [0x411, 0x1410, 0x1411] {
        let out = msiexec_open(
            r"C:\Windows\system32\msiexec.exe /V",
            r"NT AUTHORITY\SYSTEM",
            true,
            mask,
        );
        assert!(out.is_empty(), "{mask:#x}: {}", dump(&out));
    }
    // An unsigned user-path process reading a browser's memory still fires.
    let out = run_all("soak_msiexec_rm_malicious.jsonl", RuleMode::Protect);
    let d = first(&out, "ST-07");
    assert_eq!(kills(&d.actions), [("reader".to_string(), true)]);
}

/// Re-review N1: only the service instance and only the RM masks.
#[test]
fn msiexec_other_instances_and_masks_get_the_full_response() {
    for (cmd, user, svc_parent, mask) in [
        // msiexec /y <dll> (DllRegisterServer of an attacker DLL), ChromeKatz mask
        (
            r"msiexec.exe /y C:\Users\alice\AppData\Local\Temp\k.dll",
            r"LAB\employee",
            false,
            0x410,
        ),
        (
            r"msiexec.exe /z C:\Users\alice\AppData\Local\Temp\k.dll",
            r"LAB\employee",
            false,
            0x411,
        ),
        // client-side install (custom actions run here)
        (r"msiexec.exe /i C:\x.msi", r"LAB\employee", false, 0x411),
        // custom-action server child of the service
        (
            r"C:\Windows\System32\MsiExec.exe -Embedding 1A2B3C",
            r"NT AUTHORITY\SYSTEM",
            true,
            0x411,
        ),
        // the service itself, but another mask
        (
            r"C:\Windows\system32\msiexec.exe /V",
            r"NT AUTHORITY\SYSTEM",
            true,
            0x410,
        ),
        (
            r"C:\Windows\system32\msiexec.exe /V",
            r"NT AUTHORITY\SYSTEM",
            true,
            0x1F_FFFF,
        ),
        // the service command line but not SYSTEM / not started by services.exe
        (
            r"C:\Windows\system32\msiexec.exe /V",
            r"LAB\employee",
            true,
            0x411,
        ),
        (
            r"C:\Windows\system32\msiexec.exe /V",
            r"NT AUTHORITY\SYSTEM",
            false,
            0x411,
        ),
    ] {
        let out = msiexec_open(cmd, user, svc_parent, mask);
        let d = first(&out, "ST-07");
        assert_eq!(d.alert.mode, RuleMode::Protect, "{cmd} {mask:#x}");
        assert_eq!(d.alert.severity, Severity::Critical, "{cmd} {mask:#x}");
        assert_eq!(
            kills(&d.actions),
            [("msi".to_string(), true)],
            "{cmd} {mask:#x}"
        );
    }
}

// ------------------------------------------------ 4. WiX Burn RunOnce (PS-01)

#[test]
fn burn_reboot_continuation_runonce_is_benign() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("soak_burn_runonce_benign.jsonl", mode);
        assert!(out.is_empty(), "{mode:?}: {}", dump(&out));
    }
    // Same bundle but the cached file is not validly signed on disk, and
    // regedit.exe writing RunOnce to an implant named regedit.exe: PS-01.
    let out = run_all("soak_burn_runonce_malicious.jsonl", RuleMode::Audit);
    let subjects: Vec<String> = alerts(&out)
        .iter()
        .filter(|d| d.alert.rule_id == "PS-01")
        .map(|d| d.alert.process.guid.0.clone())
        .collect();
    assert_eq!(subjects, ["burn", "regedit"], "{}", dump(&out));
}

/// Re-review N3: every proof is required.
#[test]
fn burn_exemption_needs_on_disk_facts_engine_path_and_same_signer() {
    let base = fixture("soak_burn_runonce_benign.jsonl");
    let variant = |f: &dyn Fn(&mut Vec<Event>)| {
        let mut evs = base.clone();
        f(&mut evs);
        let mut e = engine(Policy::default());
        let out = replay(&mut e, &evs);
        rule_ids(&out).contains(&"PS-01".to_string())
    };
    let set_target = |evs: &mut Vec<Event>, t: Option<TargetFileFacts>| {
        if let EventData::RegistrySet { target, .. } = &mut evs[3].data {
            *target = t;
        }
    };
    // Baseline is silent.
    assert!(!variant(&|_| {}));
    // No on-disk facts (older agent).
    assert!(variant(&|evs| set_target(evs, None)));
    // Another signer on disk.
    assert!(variant(&|evs| {
        let mut t = match &evs[3].data {
            EventData::RegistrySet {
                target: Some(t), ..
            } => t.clone(),
            _ => unreachable!(),
        };
        t.signer = Some("Evil Ltd".into());
        set_target(evs, Some(t))
    }));
    // Hash known on both sides and different.
    assert!(variant(&|evs| {
        let mut t = match &evs[3].data {
            EventData::RegistrySet {
                target: Some(t), ..
            } => t.clone(),
            _ => unreachable!(),
        };
        t.sha256 = Some("aa".repeat(32));
        set_target(evs, Some(t));
        if let EventData::ProcessStart(ps) = &mut evs[2].data {
            ps.sha256 = Some("bb".repeat(32));
        }
    }));
    // Writer is not a Burn engine copy (same name, Program Files).
    assert!(variant(&|evs| {
        if let EventData::ProcessStart(ps) = &mut evs[2].data {
            ps.image = r"C:\Program Files\PowerToys\PowerToysSetup-0.101.2362.0-x64.exe".into();
        }
    }));
    // Writer's parent is an unrelated untrusted program.
    assert!(variant(&|evs| {
        if let EventData::ProcessStart(ps) = &mut evs[1].data {
            ps.image = r"C:\Users\employee\AppData\Local\Temp\x\dropper.exe".into();
            ps.signed = SignatureState::Unsigned;
            ps.signer = None;
        }
    }));
    // HKCU RunOnce.
    assert!(variant(&|evs| {
        if let EventData::RegistrySet { key, .. } = &mut evs[3].data {
            *key = r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\RunOnce".into();
        }
    }));
}

// ------------------------------- lab 2026-10-21 (build 1.1.1): VS Code killed

/// VS Code's NodeService utility (`--inspect-port=0`,
/// `--experimental-network-inspection`, its own `--user-data-dir`) read the
/// WAM cache and sent telemetry: Audit at most, never a kill or a block.
#[test]
fn vscode_nodeservice_wam_read_and_telemetry_is_not_killed() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("lab_vscode_nodeservice_wam.jsonl", mode);
        for d in alerts(&out) {
            assert_eq!(d.alert.mode, RuleMode::Audit, "{}", dump(&out));
            assert!(d.actions.is_empty(), "{}", dump(&out));
        }
        assert!(standalone(&out).is_empty(), "{}", dump(&out));
        assert_eq!(first(&out, "ST-01").alert.severity, Severity::Low);
    }
    // The same process with a real inspector switch is not a WAM client.
    let mut evs = fixture("lab_vscode_nodeservice_wam.jsonl");
    if let EventData::ProcessStart(ps) = &mut evs[2].data {
        ps.cmdline = ps.cmdline.replace("--inspect-port=0", "--inspect=9229");
    }
    let mut e = engine(policy_all(RuleMode::Protect));
    let out = replay(&mut e, &evs);
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect, "{}", dump(&out));
    assert!(!kills(&st04.actions).is_empty());
}

/// Electron's own safeStorage key ("Chromium" DPAPI description) from a
/// signed Program Files app: ST-03 Low / Audit, and the telemetry send that
/// follows is ST-04 Audit.
#[test]
fn electron_own_safestorage_dpapi_is_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run_all("lab_vscode_dpapi_chromium.jsonl", mode);
        let st03 = first(&out, "ST-03");
        assert_eq!(st03.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st03.alert.mode, RuleMode::Audit);
        for d in alerts(&out) {
            assert!(d.actions.is_empty(), "{}", dump(&out));
        }
        assert!(standalone(&out).is_empty(), "{}", dump(&out));
    }
    // After reading a browser store first: normal ST-03 and a full ST-04.
    let out = run_all("lab_vscode_dpapi_chromium_stealer.jsonl", RuleMode::Protect);
    assert_ne!(
        first(&out, "ST-03").alert.severity,
        Severity::Low,
        "{}",
        dump(&out)
    );
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect);
    assert_eq!(kills(&st04.actions), [("code".to_string(), true)]);
    // A user-path or unsigned app with the same description: normal ST-03.
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "x",
        90,
        r"C:\Users\alice\AppData\Local\Programs\x\x.exe",
        "x.exe",
        None,
        SignatureState::Valid,
        Some("Some Vendor"),
    ));
    let out = e.process(&ev(
        5,
        "x",
        90,
        EventData::DpapiUnprotect {
            description: "Chromium".into(),
        },
    ));
    assert_ne!(
        first(&out, "ST-03").alert.severity,
        Severity::Low,
        "{}",
        dump(&out)
    );
}
