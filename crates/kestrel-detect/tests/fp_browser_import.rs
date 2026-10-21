//! Lab false positive 2026-10-21 (Windows 11 VM, ST-16 in Protect):
//! Microsoft Edge's "import from Chrome" opened
//! `…\Google\Chrome\User Data\Profile 68\Google Profile Picture.png` inside
//! a decoy Chrome profile Kestrel had planted; ST-16 killed the Edge tree and
//! blocked Edge's network for 24 h. Regression tests for the fix:
//! * ST-16 fires only on decoy secret material, never on incidental files /
//!   directory opens;
//! * a genuine Program Files browser / password manager (valid signature by
//!   the exact vendor, no remote-control / dev switches, never injected
//!   into) reading decoy secrets is an Audit alert without actions;
//! * there is **no** global "known app" exemption (withdrawn after hostile
//!   review): every other rule still kills Office, VS Code, browsers, ….

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

const EDGE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
const WORD: &str = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
const CODE: &str = r"C:\Program Files\Microsoft VS Code\Code.exe";
const KOMETA_LOGIN: &str = r"C:\Users\alice\AppData\Local\Kometa\User Data\Default\Login Data";
const LEGACY_PROFILE: &str = r"C:\Users\employee\AppData\Local\Google\Chrome\User Data\Profile 68";

fn protect_engine() -> Engine {
    let e = engine(policy_all(RuleMode::Protect));
    let _ = e.canaries(r"C:\Users\alice");
    let _ = e.canaries(r"C:\Users\employee");
    e
}

fn all_actions(out: &[Output]) -> Vec<ResponseAction> {
    let mut v: Vec<ResponseAction> = alerts(out).iter().flat_map(|d| d.actions.clone()).collect();
    v.extend(standalone(out).into_iter().cloned());
    v
}

/// One process `img` (cmdline `cmd`, signer) reads the Kometa decoy Login Data.
fn decoy_reader(img: &str, cmd: &str, signed: SignatureState, signer: Option<&str>) -> Vec<Output> {
    let mut e = protect_engine();
    e.process(&start(0, "x", 70, img, cmd, None, signed, signer));
    e.process(&read(10, "x", 70, KOMETA_LOGIN))
}

fn assert_full_response(out: &[Output], what: &str) {
    let d = first(out, "ST-16");
    assert_eq!(d.alert.mode, RuleMode::Protect, "{what}: {}", dump(out));
    assert_eq!(d.alert.severity, Severity::Critical, "{what}");
    assert_eq!(
        kills(&d.actions),
        [("x".to_string(), true)],
        "{what}: {}",
        dump(out)
    );
    assert!(
        action_names(&d.actions).contains(&"block_image_network"),
        "{what}"
    );
}

#[test]
fn lab_event_edge_import_scan_is_silent() {
    // The exact lab replay, plus the same scan pattern against the new
    // decoy location, with every rule in Protect.
    let mut e = protect_engine();
    let out = replay(&mut e, &fixture("fp_edge_import_lab.jsonl"));
    assert!(out.is_empty(), "{}", dump(&out));

    // Upgrade window: the legacy decoy profile is still armed. Incidental
    // files and directory opens still never fire.
    let mut e = protect_engine();
    e.arm_canary(LEGACY_PROFILE);
    let out = replay(&mut e, &fixture("fp_edge_import_lab.jsonl"));
    assert!(out.is_empty(), "{}", dump(&out));
    assert!(all_actions(&out).is_empty());
}

#[test]
fn new_decoys_do_not_make_mainstream_browsers_look_installed() {
    let e = engine(Policy::default());
    for s in e.canaries(r"C:\Users\alice") {
        let p = s.path.to_ascii_lowercase();
        for b in [
            r"\google\chrome",
            r"\microsoft\edge",
            r"\bravesoftware",
            r"\mozilla",
            r"\opera software",
            r"\vivaldi",
        ] {
            assert!(!p.contains(b), "{}", s.path);
        }
    }
}

#[test]
fn genuine_program_files_edge_import_is_audit_only() {
    let mut e = protect_engine();
    e.process(&start(
        0,
        "edge",
        5120,
        EDGE,
        r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default"#,
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&read(10, "edge", 5120, KOMETA_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
    let d = first(&out, "ST-16");
    assert_eq!(d.alert.mode, RuleMode::Audit);
    assert_eq!(d.alert.severity, Severity::Medium);
    assert!(d.actions.is_empty(), "{}", dump(&out));
    assert!(d.alert.summary.contains("import data from other browsers"));
    assert!(!d.alert.summary.contains("no legitimate program"));
    // The legacy Chrome decoy (upgrade window): same.
    e.arm_canary(LEGACY_PROFILE);
    e.process(&start(
        20,
        "edge2",
        5121,
        EDGE,
        "msedge.exe",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let out = e.process(&read(
        30,
        "edge2",
        5121,
        &format!(r"{LEGACY_PROFILE}\Login Data"),
    ));
    assert!(all_actions(&out).is_empty(), "{}", dump(&out));
}

#[test]
fn renamed_edge_copy_in_temp_still_fires_with_actions() {
    let mut e = engine(policy_all(RuleMode::Protect));
    let _ = e.canaries(r"C:\Users\employee");
    let out = replay(&mut e, &fixture("canary_renamed_edge_temp.jsonl"));
    let d = first(&out, "ST-16");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(d.alert.severity, Severity::Critical);
    assert_eq!(kills(&d.actions), [("fake-edge".to_string(), true)]);
    assert!(action_names(&d.actions).contains(&"block_image_network"));
}

#[test]
fn look_alikes_and_per_user_installs_get_the_full_response() {
    let ms = Some("Microsoft Corporation");
    for (img, signed, signer) in [
        (EDGE, SignatureState::Unsigned, None),
        (EDGE, SignatureState::Invalid, ms),
        (EDGE, SignatureState::Valid, Some("Evil Ltd")),
        (
            r"C:\Users\alice\AppData\Roaming\Edge\msedge.exe",
            SignatureState::Valid,
            ms,
        ),
        // Review F3: per-user installs are user-writable, never exempt.
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\Application\chrome.exe",
            SignatureState::Valid,
            Some("Google LLC"),
        ),
    ] {
        let out = decoy_reader(img, "x.exe", signed, signer);
        assert_full_response(&out, &format!("{img} {signed:?}"));
    }
}

/// Review F5 / F6: remote-control and dev switches, with any prefix.
#[test]
fn remote_controlled_program_files_edge_gets_the_full_response() {
    for cmd in [
        "msedge.exe -headless",
        "msedge.exe --headless=new --remote-debugging-port=9222",
        "msedge.exe /remote-debugging-port=9222",
        "msedge.exe -remote-debugging-pipe",
        r"msedge.exe --load-extension=C:\Users\alice\AppData\Local\x",
        r#"msedge.exe "--user-data-dir=C:\Users\alice\AppData\Local\Temp\ud""#,
    ] {
        let out = decoy_reader(
            EDGE,
            cmd,
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        );
        assert_full_response(&out, cmd);
    }
}

/// A genuine Edge that something injected into is not an importer.
#[test]
fn injected_edge_gets_the_full_response() {
    let mut e = protect_engine();
    e.process(&start(
        0,
        "x",
        70,
        EDGE,
        "msedge.exe --profile-directory=Default",
        None,
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    e.process(&start(
        1,
        "inj",
        71,
        r"C:\Users\alice\AppData\Local\Temp\inj.exe",
        "inj.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&ev(
        5,
        "inj",
        71,
        EventData::RemoteThread(TargetProcess {
            target_pid: 70,
            target_guid: Some(g("x")),
            target_image: EDGE.into(),
            ..Default::default()
        }),
    ));
    assert_eq!(
        kills(&first(&out, "ST-07").actions),
        [("inj".to_string(), true)]
    );
    let out = e.process(&read(10, "x", 70, KOMETA_LOGIN));
    assert_full_response(&out, "injected edge");
}

/// No global exemption (review F1 / F4): ST-02 credential collection by
/// genuine Office, or by genuine VS Code running a script
/// (`ELECTRON_RUN_AS_NODE` style), is killed like anything else.
#[test]
fn no_global_exemption_for_office_or_electron_hosts() {
    for (img, cmd) in [
        (WORD, "WINWORD.EXE /n"),
        (
            CODE,
            r#""C:\Program Files\Microsoft VS Code\Code.exe" C:\Users\alice\AppData\Local\Temp\s.js"#,
        ),
    ] {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(
            0,
            "p",
            80,
            img,
            cmd,
            None,
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        ));
        let mut out = Vec::new();
        for (i, path) in [CHROME_LOGIN, CHROME_COOKIES, CHROME_STATE]
            .iter()
            .enumerate()
        {
            out.extend(e.process(&read(10 + i as i64, "p", 80, path)));
        }
        let st02 = first(&out, "ST-02");
        assert_eq!(st02.alert.mode, RuleMode::Protect, "{img}");
        assert_eq!(
            kills(&st02.actions),
            [("p".to_string(), true)],
            "{img}: {}",
            dump(&out)
        );
        assert!(!st02.alert.summary.contains("did not stop"));
        // ST-16 on a decoy as well.
        let out = decoy_reader(
            img,
            cmd,
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        );
        assert_full_response(&out, img);
    }
}

/// Review F2: ST-07 kills the injector's whole tree, including the browser
/// it launched and injected (no descendant sparing anywhere).
#[test]
fn st07_kills_the_injector_tree_including_its_browser_child() {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "inj",
        701,
        r"C:\Users\alice\AppData\Local\Temp\inj.exe",
        "inj.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        1,
        "chrome-child",
        702,
        CHROME_EXE,
        "chrome.exe --profile-directory=Default",
        Some(("inj", 701)),
        SignatureState::Valid,
        Some("Google LLC"),
    ));
    let out = e.process(&ev(
        10,
        "inj",
        701,
        EventData::RemoteThread(TargetProcess {
            target_pid: 702,
            target_guid: Some(g("chrome-child")),
            target_image: CHROME_EXE.into(),
            ..Default::default()
        }),
    ));
    let d = first(&out, "ST-07");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert_eq!(
        d.actions.first(),
        Some(&ResponseAction::KillProcess {
            pid: 701,
            guid: Some(g("inj")),
            tree: true
        }),
        "{}",
        dump(&out)
    );
    assert!(!d.alert.summary.contains("did not stop"));
}

/// Re-review N4: a browser-named, validly signed binary in a folder any
/// user can create at the drive root (`C:\x\`, PathClass::Other) is not a
/// store owner: full ST-16 response.
#[test]
fn browser_named_binary_in_a_root_folder_is_not_an_owner() {
    for img in [
        r"C:\x\browser.exe",
        r"C:\x\kometa.exe",
        r"C:\Tools\chrome.exe",
    ] {
        let out = decoy_reader(
            img,
            "browser.exe",
            SignatureState::Valid,
            Some("Any Valid Signer Ltd"),
        );
        assert_full_response(&out, img);
    }
}

/// Re-review N5: ST-05 sees `-` and `/` switch prefixes, and the debug port
/// it records feeds ST-06.
#[test]
fn st05_and_st06_accept_dash_and_slash_prefixes() {
    for cmd in [
        r"chrome.exe -headless -remote-debugging-port=9333 -user-data-dir=C:\Users\alice\AppData\Local\Temp\p",
        r"chrome.exe /headless /remote-debugging-port=9333 /user-data-dir=C:\Users\alice\AppData\Local\Temp\p",
    ] {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(
            0,
            "loader",
            65,
            r"C:\Users\alice\AppData\Local\Temp\cdp\loader.exe",
            "loader.exe",
            None,
            SignatureState::Unsigned,
            None,
        ));
        let out = e.process(&start(
            1,
            "hl",
            66,
            CHROME_EXE,
            cmd,
            Some(("loader", 65)),
            SignatureState::Valid,
            Some("Google LLC"),
        ));
        assert!(
            rule_ids(&out).contains(&"ST-05".to_string()),
            "{cmd}: {}",
            dump(&out)
        );
        let out = e.process(&connect(10, "loader", 65, "127.0.0.1", 9333));
        assert!(
            rule_ids(&out).contains(&"ST-06".to_string()),
            "{cmd}: {}",
            dump(&out)
        );
    }
}

/// Re-review N6: an injected password manager (Program Files KeePass) is
/// not an importer either.
#[test]
fn injected_password_manager_gets_the_full_response() {
    let keepass = r"C:\Program Files\KeePass Password Safe 2\KeePass.exe";
    // Genuine and untouched: Audit (importer).
    let out = decoy_reader(
        keepass,
        "KeePass.exe",
        SignatureState::Valid,
        Some("Dominik Reichl"),
    );
    assert_eq!(
        first(&out, "ST-16").alert.mode,
        RuleMode::Audit,
        "{}",
        dump(&out)
    );
    // Injected first: full response.
    let mut e = protect_engine();
    e.process(&start(
        0,
        "x",
        70,
        keepass,
        "KeePass.exe",
        None,
        SignatureState::Valid,
        Some("Dominik Reichl"),
    ));
    e.process(&start(
        1,
        "inj",
        71,
        r"C:\Users\alice\AppData\Local\Temp\kt.exe",
        "kt.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&ev(
        5,
        "inj",
        71,
        EventData::RemoteThread(TargetProcess {
            target_pid: 70,
            target_guid: Some(g("x")),
            target_image: keepass.into(),
            ..Default::default()
        }),
    ));
    let out = e.process(&read(10, "x", 70, KOMETA_LOGIN));
    assert_full_response(&out, "injected keepass");
}
