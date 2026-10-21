//! Replay scenarios from `tests/fixtures/*.jsonl` and assert exact rule ids,
//! modes and response actions (Audit vs Protect, suspend → kill escalation,
//! suspend → resume / kill at window expiry).

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

fn run(name: &str, policy: Policy) -> (Engine, Vec<Output>) {
    let mut e = engine(policy);
    let _ = e.canaries(r"C:\Users\alice");
    let out = replay(&mut e, &fixture(name));
    (e, out)
}

#[test]
fn fixtures_parse() {
    for f in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures")).unwrap() {
        let p = f.unwrap().path();
        let n = p.file_name().unwrap().to_str().unwrap().to_string();
        assert!(!fixture(&n).is_empty(), "{n}");
    }
}

// ---------------------------------------------------------------- Lumma ClickFix

#[test]
fn lumma_clickfix_default_policy() {
    let (_, out) = run("lumma_clickfix.jsonl", Policy::default());
    assert_eq!(
        rule_ids(&out),
        ["ST-11", "ST-10", "ST-11", "ST-12", "ST-01", "ST-02", "ST-03", "ST-14", "ST-04"],
        "{}",
        dump(&out)
    );
    // Audit-default rules carry no actions
    for d in alerts(&out) {
        match d.alert.rule_id.as_str() {
            "ST-02" | "ST-04" => assert_eq!(d.alert.mode, RuleMode::Protect),
            _ => {
                assert_eq!(d.alert.mode, RuleMode::Audit, "{}", d.alert.rule_id);
                assert!(d.actions.is_empty(), "{}", d.alert.rule_id);
            }
        }
        assert!(d.alert.evidence.len() <= 20);
        assert!(d.alert.ancestry.len() <= 6);
        assert!(d.alert.actions.is_empty(), "agent fills outcomes");
    }
    let st10 = first(&out, "ST-10");
    assert_eq!(
        st10.alert.process.guid,
        g("ps-clickfix"),
        "ST-10 points at the spawned shell"
    );
    assert!(st10.alert.attack.contains(&"T1204.004".to_string()));

    let st02 = first(&out, "ST-02");
    assert_eq!(st02.alert.severity, Severity::Critical);
    assert_eq!(kills(&st02.actions), [("stealer-1".to_string(), true)]);
    assert_eq!(
        action_names(&st02.actions),
        ["kill_process", "block_image_network", "quarantine_file"]
    );
    assert_eq!(
        st02.alert.data_at_risk,
        [
            DataCategory::BrowserPasswords,
            DataCategory::BrowserCookies,
            DataCategory::BrowserMasterKey
        ]
    );

    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.severity, Severity::Critical);
    assert_eq!(
        st04.actions,
        vec![
            ResponseAction::KillProcess {
                pid: 6100,
                guid: Some(g("stealer-1")),
                tree: true
            },
            ResponseAction::BlockDestination {
                ip: "149.154.167.220".into(),
                port: None,
                image: None,
                ttl_secs: Some(86400),
                ioc_id: None
            },
            ResponseAction::QuarantineFile {
                path: r"C:\Users\alice\AppData\Local\Temp\x7f3a\svc_upd.exe".into(),
                sha256: Some(
                    "9f2c1a0d5e3b7c6a4f8e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a".into()
                )
            },
        ]
    );
    assert!(st04
        .alert
        .data_at_risk
        .contains(&DataCategory::CryptoWallet));
    assert!(
        st04.alert
            .summary
            .starts_with("svc_upd.exe (unsigned, from Temp"),
        "{}",
        st04.alert.summary
    );
    assert!(
        st04.alert
            .summary
            .contains("then connected to 149.154.167.220:443 (api.telegram.org) 0.7 s later"),
        "{}",
        st04.alert.summary
    );
    let anc: Vec<_> = st04
        .alert
        .ancestry
        .iter()
        .map(|p| p.guid.0.as_str())
        .collect();
    assert_eq!(anc, ["mshta-1", "ps-clickfix", "explorer-0001"]);
    let kinds: Vec<_> = st04.alert.evidence.iter().map(|e| e.kind()).collect();
    assert!(
        kinds.contains(&EventKind::FileAccess)
            && kinds.contains(&EventKind::DpapiUnprotect)
            && kinds.contains(&EventKind::NetConnect)
    );
    let st12 = first(&out, "ST-12");
    assert_eq!(
        st12.alert.severity,
        Severity::High,
        "MOTW + 512 MB raises ST-12"
    );
}

#[test]
fn lumma_clickfix_protect_suspend_then_kill() {
    let (mut e, out) = run("lumma_clickfix.jsonl", policy_all(RuleMode::Protect));
    let ids = rule_ids(&out);
    assert_eq!(
        ids,
        ["ST-11", "ST-10", "ST-11", "ST-12", "ST-01", "ST-02", "ST-03", "ST-14", "ST-04"],
        "{}",
        dump(&out)
    );
    assert_eq!(
        kills(&first(&out, "ST-11").actions),
        [("ps-clickfix".to_string(), true)]
    );
    assert_eq!(
        kills(&first(&out, "ST-10").actions),
        [("ps-clickfix".to_string(), true)]
    );
    // ST-12 suspends the dropped payload at start
    let st12 = first(&out, "ST-12");
    assert_eq!(
        st12.actions,
        vec![ResponseAction::SuspendProcess {
            pid: 6100,
            guid: Some(g("stealer-1"))
        }]
    );
    // ST-01 within the window does not suspend twice
    assert!(first(&out, "ST-01").actions.is_empty());
    // ST-02 (strong) escalates: kill tree + quarantine
    let st02 = first(&out, "ST-02");
    assert_eq!(kills(&st02.actions), [("stealer-1".to_string(), true)]);
    assert!(action_names(&st02.actions).contains(&"quarantine_file"));
    // killed: ST-03 must not suspend it again, and no resume is pending
    assert!(first(&out, "ST-03").actions.is_empty());
    assert_eq!(
        action_names(&first(&out, "ST-14").actions),
        ["block_image_network"]
    );
    assert!(standalone(&e.tick(T0 + 60_000)).is_empty());
}

// ---------------------------------------------------------------- Vidar smash & grab

#[test]
fn vidar_smash_and_grab() {
    let (_, out) = run("vidar_smash_grab.jsonl", Policy::default());
    assert_eq!(
        rule_ids(&out),
        ["ST-12", "ST-01", "ST-02", "ST-14", "ST-04"],
        "{}",
        dump(&out)
    );
    let st04 = first(&out, "ST-04");
    for c in [
        DataCategory::BrowserPasswords,
        DataCategory::BrowserCookies,
        DataCategory::BrowserMasterKey,
        DataCategory::Telegram,
        DataCategory::Discord,
        DataCategory::CryptoWallet,
        DataCategory::CloudToken,
        DataCategory::FtpClient,
    ] {
        assert!(st04.alert.data_at_risk.contains(&c), "{c:?}");
    }
    assert!(st04.alert.summary.contains("(steamcommunity.com)"));
    assert_eq!(
        first(&out, "ST-01").alert.severity,
        Severity::High,
        "invalid signature from Downloads"
    );
}

#[test]
fn vidar_protect_st01_suspend_escalates_to_kill() {
    // Only ST-01 and ST-02 in Protect; ST-12 off so ST-01 opens the window.
    let mut p = policy_all(RuleMode::Audit);
    p.rules.insert("ST-12".into(), RuleMode::Off);
    p.rules.insert("ST-01".into(), RuleMode::Protect);
    p.rules.insert("ST-02".into(), RuleMode::Protect);
    let (mut e, out) = run("vidar_smash_grab.jsonl", p);
    let st01 = first(&out, "ST-01");
    assert_eq!(st01.alert.mode, RuleMode::Protect);
    assert_eq!(
        st01.actions,
        vec![ResponseAction::SuspendProcess {
            pid: 8800,
            guid: Some(g("vidar-1"))
        }]
    );
    assert!(st01.alert.summary.contains("suspended for 3.0 s"));
    let st02 = first(&out, "ST-02");
    assert_eq!(
        st02.actions,
        vec![
            ResponseAction::KillProcess {
                pid: 8800,
                guid: Some(g("vidar-1")),
                tree: true
            },
            ResponseAction::BlockImageNetwork {
                image: r"C:\Users\bob\Downloads\NeoHub_Setup.exe".into(),
                ttl_secs: None
            },
            ResponseAction::QuarantineFile {
                path: r"C:\Users\bob\Downloads\NeoHub_Setup.exe".into(),
                sha256: Some("1".repeat(64))
            },
        ]
    );
    // ST-04 in Audit: alert only
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Audit);
    assert!(st04.actions.is_empty());
    // window closed by the escalation: nothing resumes
    assert!(standalone(&e.tick(T0 + 10_000)).is_empty());
}

// ---------------------------------------------------------------- ABE bypasses

#[test]
fn abe_headless_remote_debugging() {
    let (_, out) = run("abe_headless_debug.jsonl", Policy::default());
    assert_eq!(
        rule_ids(&out),
        ["ST-12", "ST-05", "ST-06"],
        "{}",
        dump(&out)
    );
    assert!(alerts(&out)
        .iter()
        .all(|d| d.alert.mode == RuleMode::Audit && d.actions.is_empty()));
    let (_, out) = run("abe_headless_debug.jsonl", policy_all(RuleMode::Protect));
    let st05 = first(&out, "ST-05");
    assert_eq!(st05.alert.process.guid, g("chrome-headless"));
    assert_eq!(
        kills(&st05.actions),
        [
            ("chrome-headless".to_string(), true),
            ("cdp-loader".to_string(), false)
        ]
    );
    assert!(action_names(&st05.actions).contains(&"quarantine_file"));
    assert_eq!(
        kills(&first(&out, "ST-06").actions),
        [("cdp-loader".to_string(), false)]
    );
}

#[test]
fn abe_elevation_service_abuse() {
    let (_, out) = run("abe_elevation_service.jsonl", policy_all(RuleMode::Protect));
    assert_eq!(rule_ids(&out), ["ST-12", "ST-08"], "{}", dump(&out));
    let st08 = first(&out, "ST-08");
    assert_eq!(
        st08.alert.process.guid,
        g("meta-1"),
        "attributed to the process that ran taskkill"
    );
    assert_eq!(kills(&st08.actions), [("meta-1".to_string(), false)]);
    assert!(st08
        .alert
        .summary
        .contains("terminated the browser 3 times"));
}

#[test]
fn chrome_injection_and_dotnet_hollowing() {
    let (_, out) = run("chrome_injection.jsonl", Policy::default());
    assert_eq!(
        rule_ids(&out),
        ["ST-12", "ST-07", "ST-13"],
        "{}",
        dump(&out)
    );
    let st07 = first(&out, "ST-07");
    assert_eq!(st07.alert.mode, RuleMode::Protect, "ST-07 protects day one");
    assert_eq!(st07.alert.process.guid, g("regasm-1"));
    // RegAsm lives in C:\Windows: never quarantined
    assert_eq!(
        st07.actions,
        vec![ResponseAction::KillProcess {
            pid: 6900,
            guid: Some(g("regasm-1")),
            tree: true
        }]
    );
    assert!(st07.alert.summary.contains("0x143a"));
    assert_eq!(first(&out, "ST-13").alert.mode, RuleMode::Audit);
}

#[test]
fn injection_escalates_suspended_parent() {
    // The dropper is suspended by ST-12; its child (hollowed RegAsm) then injects into chrome:
    // the strong rule kills the child and escalates the parent's window to a kill.
    let (mut e, out) = run("chrome_injection.jsonl", policy_all(RuleMode::Protect));
    assert_eq!(
        first(&out, "ST-12").actions,
        vec![ResponseAction::SuspendProcess {
            pid: 6800,
            guid: Some(g("drop-1"))
        }]
    );
    let st07 = first(&out, "ST-07");
    assert_eq!(
        kills(&st07.actions),
        [("regasm-1".to_string(), true), ("drop-1".to_string(), true)]
    );
    assert!(st07.actions.contains(&ResponseAction::QuarantineFile {
        path: r"C:\Users\alice\AppData\Roaming\Intel\gfxupd.exe".into(),
        sha256: None
    }));
    assert!(
        standalone(&e.tick(T0 + 60_000)).is_empty(),
        "no resume after escalation"
    );
}

#[test]
fn voidstealer_debugger_attach() {
    let (_, out) = run("voidstealer_debug.jsonl", Policy::default());
    assert_eq!(rule_ids(&out), ["ST-12", "ST-07"], "{}", dump(&out));
    let st07 = first(&out, "ST-07");
    assert!(st07.alert.summary.contains("attached a debugger"));
    assert_eq!(
        action_names(&st07.actions),
        ["kill_process", "quarantine_file"]
    );
    assert_eq!(st07.alert.evidence.len(), 2, "process start + debug attach");
}

// ---------------------------------------------------------------- benign

#[test]
fn benign_chrome_reads_own_stores() {
    for p in [Policy::default(), policy_all(RuleMode::Protect)] {
        let (_, out) = run("benign_chrome_own_stores.jsonl", p);
        assert!(out.is_empty(), "{}", dump(&out));
    }
}

#[test]
fn benign_keepass_veeam_and_excluded_backup() {
    let mut p = policy_all(RuleMode::Protect);
    p.exclusions.push(Exclusion {
        id: "ex-1".into(),
        kind: ExclusionKind::Path,
        value: r"C:\Program Files\AcmeBackup\*".into(),
        rule_id: None,
        expires_at: None,
        reason: "nightly backup".into(),
    });
    let (_, out) = run("benign_keepass_backup.jsonl", p.clone());
    assert!(out.is_empty(), "{}", dump(&out));
    // without the exclusion the unknown backup agent is caught (KeePass / Veeam stay silent)
    p.exclusions.clear();
    let (_, out) = run("benign_keepass_backup.jsonl", p.clone());
    assert!(
        alerts(&out)
            .iter()
            .all(|d| d.alert.process.guid == g("acmebk")),
        "{}",
        dump(&out)
    );
    assert_eq!(rule_ids(&out), ["ST-01", "ST-02", "ST-04"]);
    // signer exclusion scoped to ST-01 also silences ST-02/ST-04 (they build on ST-01's condition)
    p.exclusions.push(Exclusion {
        id: "ex-2".into(),
        kind: ExclusionKind::Signer,
        value: "acme backup ltd".into(),
        rule_id: Some("ST-01".into()),
        expires_at: None,
        reason: String::new(),
    });
    let (_, out) = run("benign_keepass_backup.jsonl", p.clone());
    assert!(out.is_empty(), "{}", dump(&out));
    // expired exclusion no longer applies
    p.exclusions[0].expires_at = Some(T0);
    p.exclusions[0].rule_id = None;
    let (_, out) = run("benign_keepass_backup.jsonl", p);
    assert_eq!(rule_ids(&out), ["ST-01", "ST-02", "ST-04"]);
}

#[test]
fn benign_search_indexer_and_defender_including_canaries() {
    for p in [Policy::default(), policy_all(RuleMode::Protect)] {
        let (_, out) = run("benign_search_defender.jsonl", p);
        assert!(out.is_empty(), "{}", dump(&out));
    }
}

// ---------------------------------------------------------------- canaries (ST-16)

#[test]
fn canary_tripwire_kills_and_isolates() {
    let (_, out) = run("canary_trip.jsonl", Policy::default());
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
    let d = first(&out, "ST-16");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(
        d.actions,
        vec![
            ResponseAction::KillProcess {
                pid: 8100,
                guid: Some(g("util-1")),
                tree: true
            },
            ResponseAction::BlockImageNetwork {
                image: r"C:\Program Files\FreeUtility\util.exe".into(),
                ttl_secs: Some(24 * 3600)
            },
        ],
        "M11: a signed Program Files reader is killed and cut off, not quarantined, and the host is not isolated"
    );
    // An untrusted reader from a user-writable path isolates the host (server stays reachable).
    let mut evs = fixture("canary_trip.jsonl");
    if let EventData::ProcessStart(ps) = &mut evs[1].data {
        ps.image = r"C:\Users\alice\AppData\Local\Temp\util.exe".into();
        ps.signed = SignatureState::Unknown;
        ps.signer = None;
    }
    let mut e = engine(Policy::default());
    let _ = e.canaries(r"C:\Users\alice");
    let out = replay(&mut e, &evs);
    let d = first(&out, "ST-16");
    assert!(
        d.actions.contains(&ResponseAction::IsolateHost {
            allow_ips: vec![SERVER_IP.to_string()]
        }),
        "{}",
        dump(&out)
    );
    assert!(action_names(&d.actions).contains(&"quarantine_file"));
    assert!(
        d.alert.data_at_risk.is_empty(),
        "decoys are not real data at risk"
    );
    // Audit: alert only
    let mut p = Policy::default();
    p.rules.insert("ST-16".into(), RuleMode::Audit);
    let (_, out) = run("canary_trip.jsonl", p);
    assert!(first(&out, "ST-16").actions.is_empty());
    // canaries disabled by policy: nothing armed, no ST-16 (the decoy profile is not a real store)
    let p = Policy {
        canaries: false,
        ..Default::default()
    };
    let (e, out) = run("canary_trip.jsonl", p);
    assert!(e.armed_canaries().is_empty());
    assert!(
        !rule_ids(&out).contains(&"ST-16".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn canary_specs_and_conditional_aws_decoy() {
    let mut e = engine(Policy::default());
    let specs = e.canaries(r"C:\Users\alice");
    assert_eq!(decoy_profile_name("FIN-LAPTOP-07"), "Profile 88");
    assert!(specs.iter().any(|s| s.path.ends_with(&format!(
        r"Local Extension Settings\{DECOY_WALLET_EXTENSION}"
    )) && s.is_dir));
    let aws = specs.last().unwrap();
    assert!(is_conditional_canary(&aws.path));
    assert_eq!(aws.category, DataCategory::CloudToken);
    // not armed until the agent plants it (the two decoy `User Data` folders are)
    assert_eq!(e.armed_canaries().len(), DECOY_BROWSER_ROOTS.len());
    e.process(&start(
        0,
        "agent",
        900,
        AGENT,
        "kestrel-agent.exe",
        None,
        SignatureState::Valid,
        Some("Kestrel"),
    ));
    e.process(&start(
        0,
        "reader",
        901,
        r"C:\Users\alice\AppData\Local\Temp\r.exe",
        "r.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(10, "reader", 901, r"C:\Users\alice\.aws\credentials"));
    assert_eq!(
        rule_ids(&out),
        ["ST-01"],
        "unarmed decoy path is treated as a real store"
    );
    // agent writes the decoy → armed
    assert!(e
        .process(&write(20, "agent", 900, r"C:\Users\alice\.aws\credentials"))
        .is_empty());
    assert_eq!(e.armed_canaries().len(), DECOY_BROWSER_ROOTS.len() + 1);
    e.process(&start(
        30,
        "reader2",
        902,
        r"C:\Users\alice\AppData\Local\Temp\r2.exe",
        "r2.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(
        40,
        "reader2",
        902,
        r"\Device\HarddiskVolume3\Users\alice\.aws\credentials",
    ));
    assert_eq!(rule_ids(&out), ["ST-16"]);
    assert!(action_names(&first(&out, "ST-16").actions).contains(&"quarantine_file"));
    // the user configures real credentials → decoy disarmed
    e.process(&start(
        50,
        "awscli",
        903,
        r"C:\Program Files\Amazon\AWSCLIV2\aws.exe",
        "aws configure",
        None,
        SignatureState::Valid,
        Some("Amazon.com Services LLC"),
    ));
    assert!(e
        .process(&write(
            60,
            "awscli",
            903,
            r"C:\Users\alice\.aws\credentials"
        ))
        .is_empty());
    assert_eq!(e.armed_canaries().len(), DECOY_BROWSER_ROOTS.len());
    // explicit API
    e.arm_canary(&aws.path);
    assert_eq!(e.armed_canaries().len(), DECOY_BROWSER_ROOTS.len() + 1);
    e.disarm_canary(&aws.path);
    assert_eq!(e.armed_canaries().len(), DECOY_BROWSER_ROOTS.len());
}

#[test]
fn canary_genuine_browser_import_is_audit_only() {
    let mut e = engine(Policy::default());
    e.canaries(r"C:\Users\alice");
    e.process(&start(
        0,
        "chrome",
        700,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        Some("Google LLC"),
    ));
    let out = e.process(&read(
        10,
        "chrome",
        700,
        r"C:\Users\alice\AppData\Local\Kometa\User Data\Default\Login Data",
    ));
    let d = first(&out, "ST-16");
    assert_eq!(d.alert.severity, Severity::Medium);
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert!(d.actions.is_empty());
    // A browser-named binary that is not a known genuine install (here a
    // signed Yandex browser in a per-user folder) is not an importer.
    e.process(&start(
        20,
        "yb",
        701,
        r"C:\Users\alice\AppData\Local\Yandex\YandexBrowser\Application\browser.exe",
        "browser.exe",
        None,
        SignatureState::Valid,
        Some("YANDEX LLC"),
    ));
    let out = e.process(&read(
        30,
        "yb",
        701,
        r"C:\Users\alice\AppData\Local\Kometa\User Data\Default\Login Data",
    ));
    let d = first(&out, "ST-16");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(kills(&d.actions), [("yb".to_string(), true)]);
}

// ---------------------------------------------------------------- suspend windows

#[test]
fn suspend_then_resume_on_expiry() {
    let mut p = Policy::default();
    p.rules.insert("ST-01".into(), RuleMode::Protect);
    p.suspend_window_ms = 2000;
    let mut e = engine(p);
    let tool = r"C:\Users\alice\AppData\Local\Programs\CookieSync\cookiesync.exe";
    e.process(&start(
        0,
        "tool",
        3000,
        tool,
        "cookiesync.exe",
        None,
        SignatureState::Valid,
        Some("Cookie Sync Ltd"),
    ));
    let out = e.process(&read(100, "tool", 3000, CHROME_COOKIES));
    let d = first(&out, "ST-01");
    assert_eq!(d.alert.severity, Severity::Medium);
    assert_eq!(
        d.actions,
        vec![ResponseAction::SuspendProcess {
            pid: 3000,
            guid: Some(g("tool"))
        }]
    );
    assert!(e.tick(T0 + 1000).is_empty(), "window still open");
    let out = e.tick(T0 + 2100);
    assert_eq!(
        out,
        vec![Output::Action(ResponseAction::ResumeProcess {
            pid: 3000,
            guid: Some(g("tool"))
        })]
    );
    assert!(e.tick(T0 + 5000).is_empty());
}

#[test]
fn suspend_then_kill_on_expiry_for_unsigned_user_path() {
    let mut p = Policy::default();
    p.rules.insert("ST-01".into(), RuleMode::Protect);
    let mut e = engine(p);
    let img = r"C:\Users\alice\Downloads\crack_v2.exe";
    e.process(&start(
        0,
        "crk",
        3100,
        img,
        "crack_v2.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(100, "crk", 3100, CHROME_LOGIN));
    assert_eq!(
        first(&out, "ST-01").actions,
        vec![ResponseAction::SuspendProcess {
            pid: 3100,
            guid: Some(g("crk"))
        }]
    );
    let out = e.tick(T0 + 3100);
    assert_eq!(
        out,
        vec![
            Output::Action(ResponseAction::KillProcess {
                pid: 3100,
                guid: Some(g("crk")),
                tree: true
            }),
            Output::Action(ResponseAction::QuarantineFile {
                path: img.into(),
                sha256: None
            }),
        ]
    );
}

#[test]
fn st03_dpapi_suspends_and_exit_drops_window() {
    let mut p = Policy::default();
    p.rules.insert("ST-03".into(), RuleMode::Protect);
    let mut e = engine(p);
    e.process(&start(
        0,
        "py",
        3200,
        r"C:\Users\alice\AppData\Local\Programs\Python\Python312\python.exe",
        "python dump.py",
        None,
        SignatureState::Valid,
        Some("Python Software Foundation"),
    ));
    let out = e.process(&ev(
        10,
        "py",
        3200,
        EventData::DpapiUnprotect {
            description: "Google Chrome".into(),
        },
    ));
    let d = first(&out, "ST-03");
    assert_eq!(
        d.actions,
        vec![ResponseAction::SuspendProcess {
            pid: 3200,
            guid: Some(g("py"))
        }]
    );
    assert_eq!(d.alert.data_at_risk, [DataCategory::BrowserMasterKey]);
    e.process(&ev(
        20,
        "py",
        3200,
        EventData::ProcessStop { exit_code: Some(0) },
    ));
    assert!(
        e.tick(T0 + 10_000).is_empty(),
        "exited process is neither resumed nor killed"
    );
}

#[test]
fn st04_parent_uploads_for_suspended_child() {
    // The child reads credentials and is suspended; its loader parent then uploads:
    // ST-04 fires for the reader, kills both and blocks the destination.
    let mut p = Policy::default();
    p.rules.insert("ST-01".into(), RuleMode::Protect);
    let mut e = engine(p);
    e.process(&start(
        0,
        "ldr",
        4000,
        r"C:\Users\alice\AppData\Roaming\svc\ldr.exe",
        "ldr.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        10,
        "child",
        4001,
        r"C:\Users\alice\AppData\Roaming\svc\grab.exe",
        "grab.exe",
        Some(("ldr", 4000)),
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(100, "child", 4001, CHROME_LOGIN));
    assert_eq!(
        action_names(&first(&out, "ST-01").actions),
        ["suspend_process"]
    );
    let out = e.process(&connect(14_100, "ldr", 4000, "185.234.72.19", 443));
    let d = first(&out, "ST-04");
    assert_eq!(d.alert.process.guid, g("child"));
    assert!(
        d.alert
            .summary
            .contains("then its parent ldr.exe connected to 185.234.72.19:443 14 s later"),
        "{}",
        d.alert.summary
    );
    assert_eq!(
        kills(&d.actions),
        [("child".to_string(), true), ("ldr".to_string(), true)]
    );
    assert!(d.actions.contains(&ResponseAction::BlockDestination {
        ip: "185.234.72.19".into(),
        port: None,
        image: None,
        ttl_secs: Some(86400),
        ioc_id: None
    }));
    assert!(
        d.alert.evidence.iter().any(|x| x.guid == g("ldr")),
        "the parent's connection is evidence"
    );
    assert!(e.tick(T0 + 60_000).is_empty());
}

#[test]
fn st04_ignores_private_and_server_destinations_and_old_reads() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "x",
        4100,
        r"C:\Users\alice\AppData\Local\Temp\x.exe",
        "x.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&read(0, "x", 4100, CHROME_LOGIN));
    for ip in ["10.0.0.5", "192.168.1.10", "127.0.0.1", SERVER_IP] {
        assert!(
            !rule_ids(&e.process(&connect(1000, "x", 4100, ip, 443)))
                .contains(&"ST-04".to_string()),
            "{ip}"
        );
    }
    assert!(
        !rule_ids(&e.process(&connect(301_000, "x", 4100, "8.8.8.8", 443)))
            .contains(&"ST-04".to_string()),
        "outside 300 s"
    );
}

#[test]
fn st04_trusted_parent_connection_is_not_attributed_to_child() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "exp",
        1,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    e.process(&start(
        1,
        "kid",
        2,
        r"C:\Users\alice\Downloads\kid.exe",
        "kid.exe",
        Some(("exp", 1)),
        SignatureState::Unsigned,
        None,
    ));
    e.process(&read(2, "kid", 2, CHROME_LOGIN));
    let out = e.process(&connect(3, "exp", 1, "52.96.10.10", 443));
    assert!(out.is_empty(), "{}", dump(&out));
    assert_eq!(
        rule_ids(&e.process(&connect(4, "kid", 2, "52.96.10.11", 443))),
        ["ST-04"]
    );
}

/// Lab VM (2026-10-21): the Optimize Drives service (`svchost.exe -k
/// defragsvc`) opened a decoy Chrome profile; it is a Windows maintenance
/// host, not a thief. Another svchost group, or a look-alike outside
/// System32, still trips ST-16.
#[test]
fn defragsvc_reading_a_decoy_is_ignored() {
    let mut e = engine(Policy::default());
    let decoy = e
        .canaries(r"C:\Users\alice")
        .into_iter()
        .find(|s| s.path.ends_with("Login Data"))
        .expect("decoy Login Data")
        .path;
    e.arm_canary(&decoy);
    let svchost = r"C:\Windows\System32\svchost.exe";
    let ms = Some("Microsoft Windows Publisher");
    // V-M12: the exemption needs SYSTEM and a services.exe parent.
    e.process(&as_user(
        start(
            -10,
            "scm",
            60,
            r"C:\Windows\System32\services.exe",
            r"C:\Windows\system32\services.exe",
            None,
            SignatureState::Valid,
            ms,
        ),
        r"NT AUTHORITY\SYSTEM",
    ));
    e.process(&as_user(
        start(
            0,
            "defrag",
            70,
            svchost,
            r"C:\Windows\system32\svchost.exe -k defragsvc",
            Some(("scm", 60)),
            SignatureState::Valid,
            ms,
        ),
        "S-1-5-18",
    ));
    let out = e.process(&read(10, "defrag", 70, &decoy));
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
    e.process(&start(
        20,
        "other",
        71,
        svchost,
        r"C:\Windows\system32\svchost.exe -k netsvcs -p",
        None,
        SignatureState::Valid,
        ms,
    ));
    let out = e.process(&read(30, "other", 71, &decoy));
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
    e.process(&start(
        40,
        "fake",
        72,
        r"C:\Users\alice\AppData\Local\Temp\svchost.exe",
        "svchost.exe -k defragsvc",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(50, "fake", 72, &decoy));
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
}
