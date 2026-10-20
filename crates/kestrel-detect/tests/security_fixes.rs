//! Regression tests for the 2026-10-21 security review (engine side):
//! H1/L11 (protected processes), H7 (Unknown = untrusted + late enrichment),
//! M1 (exclusion paths), M11 (ST-16 actions), L9 (ST-11 nslookup, dedup
//! bypass for new actions), L10 (exclusions never silence TP rules).

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

fn protect() -> Engine {
    engine(policy_all(RuleMode::Protect))
}

/// Run a smash-and-grab (3 stores) for `guid` and return the ST-02 kill list.
fn st02_kills(e: &mut Engine, guid: &str, pid: u32) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        out.extend(e.process(&read(10 + i as i64, guid, pid, p)));
    }
    kills(&first(&out, "ST-02").actions)
}

// ------------------------------------------------------------------ H1 / L11

#[test]
fn lookalikes_of_protected_processes_are_killable() {
    // (image, signed, signer) that must NOT be protected
    let cases: &[(&str, SignatureState, Option<&str>)] = &[
        // user-writable System32 subdirectory, "valid" signer name
        (
            r"C:\Windows\System32\spool\drivers\color\svchost.exe",
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        // mounted ISO / USB with a Windows tree
        (
            r"E:\Windows\System32\lsass.exe",
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        // Defender look-alikes by folder or name
        (
            r"C:\Users\alice\AppData\Local\Temp\Windows Defender\setup.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        ),
        (
            r"C:\Users\alice\AppData\Local\Temp\x\MsMpEng.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        ),
        // exact location but unknown signature (enrichment pending)
        (
            r"C:\Windows\System32\csrss.exe",
            SignatureState::Unknown,
            None,
        ),
        // exact location, valid but not Microsoft
        (
            r"C:\Windows\System32\winlogon.exe",
            SignatureState::Valid,
            Some("Evil Corp"),
        ),
    ];
    for (i, (img, signed, signer)) in cases.iter().enumerate() {
        let mut e = protect();
        let guid = format!("x{i}");
        e.process(&start(
            0,
            &guid,
            2000 + i as u32,
            img,
            "x",
            None,
            *signed,
            *signer,
        ));
        let k = st02_kills(&mut e, &guid, 2000 + i as u32);
        assert_eq!(
            k,
            [(guid.clone(), true)],
            "{img} ({signed:?}) must be killable"
        );
    }
}

#[test]
fn genuine_critical_processes_and_defender_stay_protected() {
    for (img, signer) in [
        (r"C:\Windows\System32\svchost.exe", "Microsoft Windows"),
        (r"C:\Windows\explorer.exe", "Microsoft Windows"),
        (r"C:\Windows\System32\sihost.exe", "Microsoft Windows"),
        (r"C:\Windows\System32\spoolsv.exe", "Microsoft Windows"),
        (r"C:\Windows\System32\conhost.exe", "Microsoft Windows"),
        (
            r"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25070.5-0\MsMpEng.exe",
            "Microsoft Corporation",
        ),
    ] {
        let mut e = protect();
        e.process(&start(
            0,
            "p",
            3000,
            img,
            "x",
            None,
            SignatureState::Valid,
            Some(signer),
        ));
        let mut out = Vec::new();
        for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
            .iter()
            .enumerate()
        {
            out.extend(e.process(&read(10 + i as i64, "p", 3000, p)));
        }
        for d in alerts(&out) {
            assert!(
                kills(&d.actions).is_empty(),
                "{img} must not be killed: {}",
                dump(&out)
            );
            assert!(
                !d.actions
                    .iter()
                    .any(|a| matches!(a, ResponseAction::SuspendProcess { .. })),
                "{img} must not be suspended"
            );
        }
    }
}

#[test]
fn system_drive_other_than_c() {
    let mut h = host();
    h.system_drive = Some('D');
    let mut e = Engine::new(h, policy_all(RuleMode::Protect), RuleBundle::default()).unwrap();
    // C:\Windows on a D:-installed system is just a folder: killable.
    e.process(&start(
        0,
        "c",
        10,
        r"C:\Windows\System32\lsass.exe",
        "x",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    assert_eq!(st02_kills(&mut e, "c", 10), [("c".to_string(), true)]);
    assert_eq!(
        e.process_info(&g("c")).unwrap().path_class,
        PathClass::Other
    );
}

// ------------------------------------------------------------------ H7

#[test]
fn unknown_signature_is_never_trusted_as_owner() {
    // A stealer renamed chrome.exe in LOCALAPPDATA with no enrichment yet is not
    // the owner of the Chrome stores: ST-01 fires.
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "fake",
        40,
        r"C:\Users\alice\AppData\Local\Chromium\chrome.exe",
        "chrome.exe",
        None,
        SignatureState::Unknown,
        None,
    ));
    let out = e.process(&read(1, "fake", 40, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    // … while the same image with a valid signature is the owner.
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "real",
        41,
        r"C:\Users\alice\AppData\Local\Chromium\chrome.exe",
        "chrome.exe",
        None,
        SignatureState::Valid,
        Some("The Chromium Authors"),
    ));
    assert!(e.process(&read(1, "real", 41, CHROME_LOGIN)).is_empty());
}

#[test]
fn late_enrichment_reruns_hash_iocs_and_st12() {
    let mut p = policy_all(RuleMode::Protect);
    p.iocs.push(Ioc {
        id: "bad-hash".into(),
        kind: IocKind::Sha256,
        value: "ABCDEF".into(),
        action: IocAction::Block,
        description: "LummaC2 build".into(),
    });
    let mut e = engine(p);
    let img = r"C:\Users\alice\Downloads\invoice.exe";
    // First run: no hash, signature unknown → nothing can fire yet.
    let out = e.process(&start(
        0,
        "new",
        50,
        img,
        "invoice.exe",
        None,
        SignatureState::Unknown,
        None,
    ));
    assert!(
        !rule_ids(&out)
            .iter()
            .any(|r| r == "IOC-HASH" || r == "ST-12"),
        "{}",
        dump(&out)
    );
    // The platform's enrichment arrives late.
    let out = e.enrich_process(
        &g("new"),
        ProcessFacts {
            sha256: Some("abcdef".into()),
            signer: None,
            signed: SignatureState::Unsigned,
        },
        T0 + 900,
    );
    let ids = rule_ids(&out);
    assert!(ids.contains(&"IOC-HASH".to_string()), "{}", dump(&out));
    assert!(ids.contains(&"ST-12".to_string()), "{}", dump(&out));
    let ioc = first(&out, "IOC-HASH");
    assert_eq!(ioc.alert.process.sha256.as_deref(), Some("abcdef"));
    assert!(ioc.actions.contains(&ResponseAction::QuarantineFile {
        path: img.into(),
        sha256: Some("abcdef".into())
    }));
    // Table updated; a second identical enrichment is a no-op.
    assert_eq!(
        e.process_info(&g("new")).unwrap().signed,
        SignatureState::Unsigned
    );
    assert!(e
        .enrich_process(
            &g("new"),
            ProcessFacts {
                sha256: Some("abcdef".into()),
                signer: None,
                signed: SignatureState::Unsigned,
            },
            T0 + 1000,
        )
        .is_empty());
}

#[test]
fn revocation_demotes_valid_signature() {
    let mut e = engine(policy_all(RuleMode::Audit));
    let img = r"C:\Users\alice\AppData\Roaming\Updater\upd.exe";
    let out = e.process(&start(
        0,
        "rv",
        60,
        img,
        "upd.exe",
        None,
        SignatureState::Valid,
        Some("Stolen Cert LLC"),
    ));
    assert!(out.is_empty(), "{}", dump(&out));
    let out = e.enrich_process(
        &g("rv"),
        ProcessFacts {
            sha256: None,
            signer: Some("Stolen Cert LLC".into()),
            signed: SignatureState::Invalid,
        },
        T0 + 5_000,
    );
    assert_eq!(rule_ids(&out), ["ST-12"], "{}", dump(&out));
    assert!(first(&out, "ST-12")
        .alert
        .summary
        .contains("invalid signature"));
}

#[test]
fn suspend_window_rejudged_by_late_enrichment() {
    let mut e = protect();
    let img = r"C:\Users\alice\AppData\Local\Vendor\tool.exe";
    e.process(&start(
        0,
        "w",
        70,
        img,
        "tool.exe",
        None,
        SignatureState::Unknown,
        None,
    ));
    // ST-01 on an Unknown user-path image: suspended, would be killed at expiry.
    let out = e.process(&read(10, "w", 70, CHROME_LOGIN));
    let st01 = first(&out, "ST-01");
    assert!(matches!(
        st01.actions[0],
        ResponseAction::SuspendProcess { .. }
    ));
    // Enrichment proves a valid signature → resume instead of kill.
    e.enrich_process(
        &g("w"),
        ProcessFacts {
            sha256: Some("11".into()),
            signer: Some("Vendor Inc".into()),
            signed: SignatureState::Valid,
        },
        T0 + 500,
    );
    let out = e.tick(T0 + 60_000);
    let acts = standalone(&out);
    assert!(
        acts.iter()
            .any(|a| matches!(a, ResponseAction::ResumeProcess { .. })),
        "{}",
        dump(&out)
    );
    assert!(!acts
        .iter()
        .any(|a| matches!(a, ResponseAction::KillProcess { .. })));
}

#[test]
fn st08b_waits_for_enrichment_instead_of_firing_on_unknown() {
    let mut e = protect();
    let img = r"C:\Program Files\Google\Chrome\Application\chrome_proxy.exe";
    let out = e.process(&start(
        0,
        "b",
        80,
        img,
        "x",
        None,
        SignatureState::Unknown,
        None,
    ));
    assert!(!rule_ids(&out).contains(&"ST-08".to_string()));
    let out = e.enrich_process(
        &g("b"),
        ProcessFacts {
            sha256: None,
            signer: None,
            signed: SignatureState::Unsigned,
        },
        T0 + 100,
    );
    assert!(
        rule_ids(&out).contains(&"ST-08".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn allow_iocs_and_signer_exclusions_need_valid_signatures() {
    let mut p = Policy::default();
    p.iocs.push(Ioc {
        id: "allow".into(),
        kind: IocKind::Certificate,
        value: "Acme Backup Ltd".into(),
        action: IocAction::Allow,
        description: String::new(),
    });
    let mut e = engine(p);
    e.process(&start(
        0,
        "u",
        90,
        r"C:\Users\alice\AppData\Local\Acme\backup.exe",
        "backup.exe",
        None,
        SignatureState::Unknown,
        Some("Acme Backup Ltd"),
    ));
    assert_eq!(
        rule_ids(&e.process(&read(1, "u", 90, CHROME_LOGIN))),
        ["ST-01"]
    );
}

// ------------------------------------------------------------------ L9

#[test]
fn nslookup_staging_kills_only_the_child() {
    let mut e = protect();
    e.process(&start(
        0,
        "explorer",
        100,
        r"C:\Windows\explorer.exe",
        "explorer.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    e.process(&start(
        1,
        "ps",
        101,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe",
        Some(("explorer", 100)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&start(
        2,
        "ns",
        102,
        r"C:\Windows\System32\nslookup.exe",
        "nslookup example.com 8.8.8.8",
        Some(("ps", 101)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let d = first(&out, "ST-11");
    assert_eq!(kills(&d.actions), [("ns".to_string(), false)]);
}

#[test]
fn deduplicated_rehit_still_blocks_new_destinations() {
    let mut e = protect();
    unsigned_temp(&mut e, "s", 110);
    for (i, p) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
        .iter()
        .enumerate()
    {
        e.process(&read(i as i64, "s", 110, p));
    }
    let out = e.process(&connect(100, "s", 110, "203.0.113.50", 443));
    assert!(first(&out, "ST-04").actions.iter().any(|a| matches!(a,
        ResponseAction::BlockDestination { ip, .. } if ip == "203.0.113.50")));
    // Same rule within the dedup window, new destination: no second alert,
    // but the new block is still ordered.
    let out = e.process(&connect(200, "s", 110, "198.51.100.77", 443));
    assert!(
        alerts(&out).iter().all(|d| d.alert.rule_id != "ST-04"),
        "{}",
        dump(&out)
    );
    let acts = standalone(&out);
    assert!(
        acts.iter().any(|a| matches!(a,
            ResponseAction::BlockDestination { ip, .. } if ip == "198.51.100.77")),
        "{}",
        dump(&out)
    );
    // Actions already ordered are not repeated.
    let out = e.process(&connect(300, "s", 110, "198.51.100.77", 443));
    assert!(standalone(&out).is_empty(), "{}", dump(&out));
}

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

// ------------------------------------------------------------------ L10 / M1

#[test]
fn exclusions_never_silence_tamper_rules() {
    let mut p = Policy::default();
    p.exclusions.push(Exclusion {
        id: "all".into(),
        kind: ExclusionKind::Path,
        value: r"C:\**".into(),
        rule_id: None,
        expires_at: None,
        reason: String::new(),
    });
    let mut e = engine(p);
    e.process(&start(
        0,
        "r",
        120,
        r"C:\Windows\System32\reg.exe",
        "reg add",
        None,
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = e.process(&ev(
        1,
        "r",
        120,
        EventData::RegistrySet {
            key: r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"
                .into(),
            value_name: "".into(),
            data: None,
            op: Default::default(),
        },
    ));
    assert_eq!(rule_ids(&out), ["TP-03"], "{}", dump(&out));
    // the same exclusion does silence stealer rules
    unsigned_temp(&mut e, "s", 121);
    assert!(e.process(&read(1, "s", 121, CHROME_LOGIN)).is_empty());
}

#[test]
fn path_exclusion_on_c_does_not_cover_usb_copy() {
    let mut p = Policy::default();
    p.exclusions.push(Exclusion {
        id: "tools".into(),
        kind: ExclusionKind::Path,
        value: r"C:\Tools\backup.exe".into(),
        rule_id: None,
        expires_at: None,
        reason: String::new(),
    });
    let mut e = engine(p);
    for (guid, pid, img) in [
        ("c", 130, r"C:\Tools\backup.exe"),
        ("e", 131, r"E:\Tools\backup.exe"),
    ] {
        e.process(&start(
            0,
            guid,
            pid,
            img,
            "backup.exe",
            None,
            SignatureState::Unsigned,
            None,
        ));
    }
    assert!(e.process(&read(1, "c", 130, CHROME_LOGIN)).is_empty());
    assert_eq!(
        rule_ids(&e.process(&read(1, "e", 131, CHROME_LOGIN))),
        ["ST-01"]
    );
}

// ------------------------------------------------------------------ M11

#[test]
fn canary_backup_and_av_readers_are_ignored() {
    for (img, signer) in [
        (
            r"C:\Program Files\Veeam\Endpoint Backup\Veeam.EndPoint.Service.exe",
            "Veeam Software Group GmbH",
        ),
        (r"C:\Windows\System32\scanstate.exe", "Microsoft Windows"),
        (
            r"C:\Program Files\ESET\ESET Security\ekrn.exe",
            "ESET, spol. s r.o.",
        ),
    ] {
        let mut e = engine(Policy::default());
        let _ = e.canaries(r"C:\Users\alice");
        e.process(&start(
            0,
            "bk",
            140,
            img,
            "x",
            None,
            SignatureState::Valid,
            Some(signer),
        ));
        let decoy = e.armed_canaries()[0].clone();
        let out = e.process(&read(1, "bk", 140, &format!("C:{decoy}\\Login Data")));
        assert!(out.is_empty(), "{img}: {}", dump(&out));
    }
}
