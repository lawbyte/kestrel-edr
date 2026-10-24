//! Fix round 2026-10-25 (docs/DETECTION-QUALITY.md, docs/DECISIONS.md):
//! identity-bound allowances, taint, process-tree correlation, own-profile
//! keys and the false-positive fixes FP-03 / 05 / 08 / 10 / 13 / 14 / 15 /
//! 16 / 18. Every benign case has a malicious twin that must still fire.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::Output;

const UNSIGNED: SignatureState = SignatureState::Unsigned;
const VALID: SignatureState = SignatureState::Valid;
const TEMP_EXE: &str = r"C:\Users\alice\AppData\Local\Temp\x\Xeno-v1.3.65.exe";
const OWN_LS: &str = r"C:\Users\alice\AppData\Roaming\Xeno\Local State";
const TDATA: &str = r"C:\Users\alice\AppData\Roaming\Telegram Desktop\tdata\key_datas";
const EXPLORER: &str = r"C:\Windows\explorer.exe";

fn explorer() -> Event {
    start(
        -60_000,
        "explorer",
        4000,
        EXPLORER,
        EXPLORER,
        None,
        VALID,
        Some("Microsoft Windows"),
    )
}

fn open(ts: i64, guid: &str, pid: u32, path: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::FileAccess {
            path: path.into(),
            op: FileOp::Open,
        },
    )
}

fn dpapi(ts: i64, guid: &str, pid: u32, d: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::DpapiUnprotect {
            description: d.into(),
        },
    )
}

fn net(
    ts: i64,
    guid: &str,
    pid: u32,
    ip: &str,
    host: Option<&str>,
    udp: bool,
    bytes: Option<u64>,
) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::NetConnect {
            proto: if udp { NetProto::Udp } else { NetProto::Tcp },
            dst_ip: ip.into(),
            dst_port: 443,
            src_port: 50000,
            dst_host: host.map(Into::into),
            bytes_sent: bytes,
        },
    )
}

#[allow(clippy::too_many_arguments)]
fn target(
    kind: &str,
    ts: i64,
    guid: &str,
    pid: u32,
    tguid: &str,
    tpid: u32,
    timg: &str,
    mask: u32,
) -> Event {
    let t = TargetProcess {
        target_pid: tpid,
        target_guid: Some(g(tguid)),
        target_image: timg.into(),
        granted_access: mask,
        return_code: 0,
    };
    let data = match kind {
        "thread_context" => EventData::ThreadContext(t),
        "remote_thread" => EventData::RemoteThread(t),
        _ => EventData::ProcessAccess(t),
    };
    ev(ts, guid, pid, data)
}

fn stop(ts: i64, guid: &str, pid: u32) -> Event {
    ev(ts, guid, pid, EventData::ProcessStop { exit_code: Some(0) })
}

fn run(policy: Policy, events: &[Event]) -> Vec<Output> {
    let mut e = engine(policy);
    replay(&mut e, events)
}

fn has(out: &[Output], rule: &str) -> bool {
    rule_ids(out).iter().any(|r| r == rule)
}

fn sev(out: &[Output], rule: &str) -> Severity {
    first(out, rule).alert.severity
}

fn any_kill(out: &[Output]) -> bool {
    alerts(out).iter().any(|d| !kills(&d.actions).is_empty())
        || standalone(out)
            .iter()
            .any(|a| matches!(a, ResponseAction::KillProcess { .. }))
}

// ------------------------------------------------- own-profile key (FP-04)

#[test]
fn own_profile_local_state_then_chromium_key_is_info_only() {
    let ev = vec![
        explorer(),
        start(
            0,
            "x",
            10,
            TEMP_EXE,
            TEMP_EXE,
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        open(100, "x", 10, OWN_LS),
        dpapi(200, "x", 10, "Chromium"),
        net(800, "x", 10, "198.51.100.9", None, false, None),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(!has(&out, "ST-01") && !has(&out, "ST-04"), "{}", dump(&out));
    let st03 = first(&out, "ST-03");
    assert_eq!(st03.alert.severity, Severity::Info, "{}", dump(&out));
    assert_eq!(st03.alert.mode, RuleMode::Audit);
    assert!(!any_kill(&out), "{}", dump(&out));
}

#[test]
fn a_non_store_local_state_open_alone_raises_nothing() {
    let ev = vec![
        explorer(),
        start(
            0,
            "x",
            10,
            TEMP_EXE,
            TEMP_EXE,
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        open(
            100,
            "x",
            10,
            r"C:\Users\alice\AppData\Roaming\Slack\Local State",
        ),
        open(110, "x", 10, OWN_LS),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(
        rule_ids(&out).iter().all(|r| r == "ST-12"),
        "{}",
        dump(&out)
    );
}

#[test]
fn foreign_local_state_before_the_key_keeps_the_full_response() {
    for foreign in [
        CHROME_STATE,
        r"C:\Users\alice\AppData\Roaming\Slack\Local State",
    ] {
        let ev = vec![
            explorer(),
            start(
                0,
                "x",
                10,
                TEMP_EXE,
                TEMP_EXE,
                Some(("explorer", 4000)),
                UNSIGNED,
                None,
            ),
            open(100, "x", 10, OWN_LS),
            open(150, "x", 10, foreign),
            dpapi(200, "x", 10, "Chromium"),
            net(800, "x", 10, "198.51.100.9", None, false, None),
        ];
        let out = run(policy_all(RuleMode::Audit), &ev);
        assert_eq!(
            sev(&out, "ST-03"),
            Severity::High,
            "{foreign}: {}",
            dump(&out)
        );
    }
    // With a real store read the key decrypt is theft: ST-04 critical.
    let ev = vec![
        explorer(),
        start(
            0,
            "x",
            10,
            TEMP_EXE,
            TEMP_EXE,
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        open(100, "x", 10, OWN_LS),
        read(150, "x", 10, CHROME_COOKIES),
        dpapi(200, "x", 10, "Chromium"),
        net(800, "x", 10, "198.51.100.9", None, false, None),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert_eq!(sev(&out, "ST-04"), Severity::Critical, "{}", dump(&out));
    assert!(any_kill(&out));
}

#[test]
fn chromium_key_without_any_store_read_is_high_audit_and_quic_is_no_send() {
    let ev = vec![
        explorer(),
        start(
            0,
            "x",
            10,
            TEMP_EXE,
            TEMP_EXE,
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        dpapi(200, "x", 10, "Chromium"),
        // QUIC Initial: not a send.
        net(500, "x", 10, "172.66.44.125", None, true, Some(1250)),
        net(
            800,
            "x",
            10,
            "198.51.100.9",
            Some("pastebin.com"),
            false,
            None,
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.severity, Severity::High, "{}", dump(&out));
    assert_eq!(st04.alert.mode, RuleMode::Audit);
    assert!(
        st04.alert.summary.contains("pastebin.com"),
        "{}",
        dump(&out)
    );
    // A later store read and send is the full response (own dedup key).
    let mut ev2 = ev.clone();
    ev2.push(read(900, "x", 10, CHROME_LOGIN));
    ev2.push(net(1_000, "x", 10, "198.51.100.10", None, false, None));
    let out = run(policy_all(RuleMode::Protect), &ev2);
    assert!(
        alerts(&out)
            .iter()
            .any(|d| d.alert.rule_id == "ST-04" && d.alert.severity == Severity::Critical),
        "{}",
        dump(&out)
    );
}

// ----------------------------------------------------- taint and identity

#[test]
fn windows_binaries_reading_browser_stores_alert_and_taint_removes_allowances() {
    // Untainted explorer reading a browser store: alert (not skipped).
    let ev = vec![explorer(), read(10, "explorer", 4000, CHROME_LOGIN)];
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(has(&out, "ST-01"), "{}", dump(&out));
    // Untainted svchost reading the Vault: the Credential Manager's own reader.
    let svc = r"C:\Windows\System32\svchost.exe";
    let vault = r"C:\Users\alice\AppData\Local\Microsoft\Vault\4BF4C442-9B8A-41A0-B380-DD4A704DDB28\Policy.vpol";
    let ev = vec![
        start(
            0,
            "svc",
            900,
            svc,
            "svchost.exe -k LocalSystemNetworkRestricted -p -s VaultSvc",
            None,
            VALID,
            Some("Microsoft Windows Publisher"),
        ),
        read(10, "svc", 900, vault),
    ];
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
    // The same svchost written to by an unsigned loader: no longer exempt.
    let ev = vec![
        explorer(),
        start(
            0,
            "ld",
            20,
            r"C:\Users\alice\Downloads\ld.exe",
            "ld.exe",
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        start(
            5,
            "svc",
            900,
            svc,
            "svchost.exe -k netsvcs",
            Some(("ld", 20)),
            VALID,
            Some("Microsoft Windows Publisher"),
        ),
        target("process_access", 6, "ld", 20, "svc", 900, svc, 0x1F_FFFF),
        read(10, "svc", 900, vault),
    ];
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(has(&out, "ST-01"), "{}", dump(&out));
}

#[test]
fn sideloaded_genuine_browser_is_no_longer_an_owner() {
    let edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
    let base = vec![
        explorer(),
        start(
            0,
            "e",
            30,
            edge,
            "msedge.exe",
            Some(("explorer", 4000)),
            VALID,
            Some("Microsoft Corporation"),
        ),
    ];
    // Edge importing from Chrome: owner, silent.
    let mut ev = base.clone();
    ev.push(read(10, "e", 30, CHROME_LOGIN));
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
    // After loading an unsigned DLL from the profile: not Edge any more.
    let mut ev = base;
    ev.push(ev_image(
        5,
        "e",
        30,
        r"C:\Users\alice\AppData\Roaming\x\version.dll",
        UNSIGNED,
    ));
    ev.push(read(10, "e", 30, CHROME_LOGIN));
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(has(&out, "ST-01"), "{}", dump(&out));
}

fn ev_image(ts: i64, guid: &str, pid: u32, path: &str, signed: SignatureState) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ImageLoad {
            path: path.into(),
            signer: None,
            signed,
        },
    )
}

// ---------------------------------------------------------- process trees

#[test]
fn weak_single_dev_store_read_does_not_link_across_the_tree() {
    // A build child "reads" the Docker config (FP-01 shape); a sibling
    // uploads 100 KB a minute later: no ST-04 (one dev store is not
    // linkable beyond direct relatives), no tree ST-02.
    let cargo = r"C:\Users\alice\.cargo\bin\cargo.exe";
    let rustc = r"C:\Users\alice\.rustup\toolchains\stable\bin\rustc.exe";
    let git = r"C:\Program Files\Git\mingw64\bin\git.exe";
    let ev = vec![
        explorer(),
        start(
            0,
            "cargo",
            50,
            cargo,
            "cargo build",
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        start(
            10,
            "rustc",
            51,
            rustc,
            "rustc",
            Some(("cargo", 50)),
            UNSIGNED,
            None,
        ),
        read(20, "rustc", 51, r"C:\Users\alice\.docker\config.json"),
        start(
            30,
            "git",
            52,
            git,
            "git push",
            Some(("cargo", 50)),
            VALID,
            Some("Johannes Schindelin"),
        ),
        net(
            60_000,
            "git",
            52,
            "140.82.112.3",
            Some("github.com"),
            false,
            Some(100_000),
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(!has(&out, "ST-04") && !has(&out, "ST-02"), "{}", dump(&out));
}

#[test]
fn bits_service_without_a_job_from_a_reader_tree_is_not_st04() {
    let svc = r"C:\Windows\System32\svchost.exe";
    let ev = vec![
        explorer(),
        start(
            0,
            "bits",
            70,
            svc,
            r"C:\Windows\System32\svchost.exe -k netsvcs -p -s BITS",
            None,
            VALID,
            Some("Microsoft Windows"),
        ),
        start(
            5,
            "x",
            10,
            TEMP_EXE,
            TEMP_EXE,
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        ),
        read(10, "x", 10, CHROME_LOGIN),
        net(
            1_000,
            "bits",
            70,
            "192.0.2.199",
            None,
            false,
            Some(4_000_000),
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(!has(&out, "ST-04"), "{}", dump(&out));
}

#[test]
fn slow_send_needs_upload_volume() {
    let mk = |bytes: Option<u64>| {
        vec![
            explorer(),
            start(
                0,
                "x",
                10,
                TEMP_EXE,
                TEMP_EXE,
                Some(("explorer", 4000)),
                UNSIGNED,
                None,
            ),
            read(10, "x", 10, CHROME_LOGIN),
            read(20, "x", 10, TDATA),
            net(10 * 60_000, "x", 10, "192.0.2.45", None, false, bytes),
        ]
    };
    let out = run(policy_all(RuleMode::Audit), &mk(None));
    assert!(!has(&out, "ST-04"), "{}", dump(&out));
    let out = run(policy_all(RuleMode::Audit), &mk(Some(2_400_000)));
    assert_eq!(sev(&out, "ST-04"), Severity::Critical, "{}", dump(&out));
}

// -------------------------------------------------------------- FP-13 dirs

#[test]
fn store_folder_opens_are_not_reads() {
    let dllhost = r"C:\Windows\System32\dllhost.exe";
    let ext = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn";
    let base = vec![start(
        0,
        "d",
        60,
        dllhost,
        "DllHost.exe /Processid:{X}",
        None,
        VALID,
        Some("Microsoft Windows"),
    )];
    let mut ev = base.clone();
    ev.push(open(10, "d", 60, ext));
    ev.push(open(11, "d", 60, r"C:\ProgramData\Microsoft\Vault"));
    ev.push(open(12, "d", 60, r"C:\Users\alice\.aws\cli\cache"));
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
    let mut ev = base;
    ev.push(open(10, "d", 60, &format!(r"{ext}\000003.log")));
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(has(&out, "ST-01"), "{}", dump(&out));
    // `.aws\credentials` is a file, never a folder.
    let ev = vec![
        start(
            0,
            "d",
            60,
            dllhost,
            "DllHost.exe",
            None,
            VALID,
            Some("Microsoft Windows"),
        ),
        open(10, "d", 60, r"C:\Users\alice\.aws\credentials"),
    ];
    let out = run(policy_all(RuleMode::Audit), &ev);
    assert!(has(&out, "ST-01"), "{}", dump(&out));
}

// ------------------------------------------------------- FP-05 WhatsApp

#[test]
fn packaged_app_opening_webview2_is_hosting_unsigned_tool_is_not() {
    let wa = r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe";
    let wv = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\155.0.4283.62\msedgewebview2.exe";
    let ev = vec![
        start(
            0,
            "wa",
            80,
            wa,
            "WhatsApp.Root.exe -RegisterForBGTaskServer",
            None,
            UNSIGNED,
            None,
        ),
        target(
            "process_access",
            10,
            "wa",
            80,
            "wv-unknown",
            81,
            wv,
            0x1F_0FFF,
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(!has(&out, "ST-07"), "{}", dump(&out));
    let ev = vec![
        start(
            0,
            "t",
            82,
            r"C:\Users\alice\AppData\Local\Temp\t.exe",
            "t.exe",
            None,
            UNSIGNED,
            None,
        ),
        target(
            "process_access",
            10,
            "t",
            82,
            "wv-unknown",
            81,
            wv,
            0x1F_0FFF,
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(has(&out, "ST-07"), "{}", dump(&out));
}

// ------------------------------------------------------- FP-08 Playwright

#[test]
fn playwright_temp_profile_is_low_real_profile_is_high() {
    let node = r"C:\Program Files\nodejs\node.exe";
    let mk = |udd: &str| {
        vec![
            explorer(),
            start(
                0,
                "n",
                90,
                node,
                "node.exe cli.js test",
                Some(("explorer", 4000)),
                VALID,
                Some("OpenJS Foundation"),
            ),
            start(
                10,
                "c",
                91,
                CHROME_EXE,
                &format!("chrome.exe --headless --remote-debugging-pipe --user-data-dir={udd}"),
                Some(("n", 90)),
                VALID,
                Some("Google LLC"),
            ),
        ]
    };
    let out = run(
        policy_all(RuleMode::Protect),
        &mk(r"C:\Users\alice\AppData\Local\Temp\playwright_chromiumdev_profile-AbC123"),
    );
    assert_eq!(sev(&out, "ST-05"), Severity::Low, "{}", dump(&out));
    assert!(!any_kill(&out), "{}", dump(&out));
    let out = run(
        policy_all(RuleMode::Protect),
        &mk(r"C:\Users\alice\AppData\Local\Google\Chrome\User Data"),
    );
    assert_eq!(sev(&out, "ST-05"), Severity::High, "{}", dump(&out));
    assert!(any_kill(&out));
    // A "playwright_" folder after the launching tree read the real profile.
    let mut ev = mk(r"C:\Users\alice\AppData\Local\Temp\playwright_x");
    ev.insert(2, read(5, "n", 90, CHROME_COOKIES));
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert_eq!(sev(&out, "ST-05"), Severity::High, "{}", dump(&out));
}

// ---------------------------------------------------------- FP-10 TP-02

#[test]
fn firewall_refresh_is_low_custom_filter_is_critical() {
    let agent = start(0, "agent", 5, AGENT, AGENT, None, VALID, Some("Kestrel"));
    let tamper = |d: &str| {
        ev(
            10,
            "agent",
            5,
            EventData::Tamper {
                kind: TamperKind::WfpFilterChange,
                detail: d.into(),
            },
        )
    };
    let out = run(
        policy_all(RuleMode::Audit),
        &[agent.clone(), tamper("WFP filter 'PrivateNetwork Inbound Default Rule' changed at ALE Receive/Accept v4 Layer by pid 72904 (provider '@bfe.dll,-1217' {4b153735-1049-4480-aab4-d1b9bdc03710}, change %%16384, action %%16390)")],
    );
    assert_eq!(sev(&out, "TP-02"), Severity::Low, "{}", dump(&out));
    let out = run(
        policy_all(RuleMode::Audit),
        &[agent, tamper("WFP filter 'block kestrel' changed at ALE Connect v4 Layer by pid 666 (provider '-' {00000000-0000-0000-0000-000000000000}, change %%16384, action %%16391)")],
    );
    assert_eq!(sev(&out, "TP-02"), Severity::Critical, "{}", dump(&out));
}

// ------------------------------------------------------ FP-14 ST-12 Protect

#[test]
fn st12_protect_stops_suspending_a_hash_after_three_resumes() {
    let rustc = r"C:\Users\alice\.rustup\toolchains\stable\bin\rustc.exe";
    let mut evs = vec![explorer()];
    for i in 0..5u32 {
        let guid = format!("r{i}");
        let mut s = start(
            i as i64 * 10_000,
            &guid,
            100 + i,
            rustc,
            "rustc --crate-name x",
            Some(("explorer", 4000)),
            UNSIGNED,
            None,
        );
        if let EventData::ProcessStart(p) = &mut s.data {
            p.sha256 = Some("ab".repeat(32));
        }
        evs.push(s);
        evs.push(stop(i as i64 * 10_000 + 2_000, &guid, 100 + i));
    }
    let out = run(policy_all(RuleMode::Protect), &evs);
    let suspends = alerts(&out)
        .iter()
        .filter(|d| {
            d.actions
                .iter()
                .any(|a| matches!(a, ResponseAction::SuspendProcess { .. }))
        })
        .count();
    assert_eq!(suspends, 3, "{}", dump(&out));
}

// ---------------------------------------------------- FP-18 browser update

#[test]
fn browser_update_flow_is_not_st08() {
    let brave = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe";
    let setup =
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\156.1.98.60\Installer\setup.exe";
    let elev = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\156.1.98.60\elevation_service.exe";
    let mk = |with_setup: bool| {
        let mut v = vec![
            start(
                0,
                "b1",
                200,
                brave,
                "brave.exe",
                None,
                VALID,
                Some("Brave Software, Inc."),
            ),
            start(
                1,
                "b2",
                201,
                brave,
                "brave.exe --type=renderer",
                Some(("b1", 200)),
                VALID,
                Some("Brave Software, Inc."),
            ),
        ];
        if with_setup {
            v.push(start(
                100,
                "s",
                202,
                setup,
                "setup.exe --rename-chrome-exe --system-level",
                None,
                VALID,
                Some("Brave Software, Inc."),
            ));
        }
        v.push(stop(1_000, "b2", 201));
        v.push(stop(1_010, "b1", 200));
        v.push(start(
            1_200,
            "el",
            203,
            elev,
            "elevation_service.exe",
            None,
            VALID,
            Some("Brave Software, Inc."),
        ));
        v
    };
    let out = run(policy_all(RuleMode::Audit), &mk(true));
    assert!(!has(&out, "ST-08"), "{}", dump(&out));
    let out = run(policy_all(RuleMode::Audit), &mk(false));
    assert!(has(&out, "ST-08"), "{}", dump(&out));
}

// ------------------------------------------------ FP-03 VS Code + GitHub

#[test]
fn per_user_vscode_wam_to_github() {
    let code = r"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe";
    let tb = r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres";
    let mk = |host: &str| {
        vec![
            explorer(),
            start(
                0,
                "code",
                300,
                code,
                "Code.exe",
                Some(("explorer", 4000)),
                VALID,
                Some("Microsoft Corporation"),
            ),
            read(10, "code", 300, tb),
            net(500, "code", 300, "140.82.112.3", Some(host), false, None),
        ]
    };
    for h in [
        "github.com",
        "api.individual.githubcopilot.com",
        "copilot-telemetry.githubusercontent.com",
    ] {
        let out = run(policy_all(RuleMode::Protect), &mk(h));
        assert_eq!(sev(&out, "ST-04"), Severity::Low, "{h}: {}", dump(&out));
        assert!(!any_kill(&out));
    }
    let out = run(
        policy_all(RuleMode::Protect),
        &mk("westus-0.in.applicationinsights.azure.com"),
    );
    assert_eq!(sev(&out, "ST-04"), Severity::High, "{}", dump(&out));
    assert!(!any_kill(&out));
    let out = run(policy_all(RuleMode::Protect), &mk("api.github.com"));
    assert_eq!(sev(&out, "ST-04"), Severity::High, "{}", dump(&out));
    assert_eq!(first(&out, "ST-04").alert.mode, RuleMode::Audit);
    for h in [
        "gist.github.com",
        "uploads.github.com",
        "raw.githubusercontent.com",
        "evil.example",
    ] {
        let out = run(policy_all(RuleMode::Protect), &mk(h));
        assert_eq!(
            sev(&out, "ST-04"),
            Severity::Critical,
            "{h}: {}",
            dump(&out)
        );
        assert!(any_kill(&out), "{h}");
    }
}

// ------------------------------------------- FP-15 IDM, FP-16 Claude

#[test]
fn browser_integrations_are_identity_and_scope_bound() {
    let idm = r"C:\Program Files (x86)\Internet Download Manager\IDMan.exe";
    let ev = vec![
        start(
            0,
            "i",
            400,
            idm,
            "IDMan.exe",
            None,
            VALID,
            Some("Tonec Inc."),
        ),
        read(10, "i", 400, CHROME_COOKIES),
        read(11, "i", 400, CHROME_STATE),
    ];
    assert!(rule_ids(&run(policy_all(RuleMode::Audit), &ev)).is_empty());
    // Not a browser store, or not Tonec: alerts.
    let ev = vec![
        start(
            0,
            "i",
            400,
            idm,
            "IDMan.exe",
            None,
            VALID,
            Some("Tonec Inc."),
        ),
        read(10, "i", 400, TDATA),
    ];
    assert!(has(&run(policy_all(RuleMode::Audit), &ev), "ST-01"));
    let ev = vec![
        start(
            0,
            "i",
            400,
            idm,
            "IDMan.exe",
            None,
            VALID,
            Some("Tonec Holdings Ltd"),
        ),
        read(10, "i", 400, CHROME_COOKIES),
    ];
    assert!(has(&run(policy_all(RuleMode::Audit), &ev), "ST-01"));
    let claude =
        r"C:\Program Files\WindowsApps\Claude_3.6556.2.0_x64__pzs8sxrjxfjjc\app\claude.exe";
    let ev = vec![
        start(
            0,
            "cl",
            401,
            claude,
            "claude.exe",
            None,
            VALID,
            Some("Anthropic, PBC"),
        ),
        read(10, "cl", 401, CHROME_STATE),
    ];
    assert!(rule_ids(&run(policy_all(RuleMode::Audit), &ev)).is_empty());
    let ev = vec![
        start(
            0,
            "cl",
            401,
            claude,
            "claude.exe",
            None,
            VALID,
            Some("Anthropic, PBC"),
        ),
        read(10, "cl", 401, CHROME_COOKIES),
    ];
    assert!(has(&run(policy_all(RuleMode::Audit), &ev), "ST-01"));
}

// ------------------------------------------- red-team round: unpinned owners

#[test]
fn unpinned_owner_in_its_own_folder_is_alert_only_and_destination_bound() {
    let coinomi = r"C:\Users\alice\AppData\Local\Coinomi\Coinomi.exe";
    let wallet = r"C:\Users\alice\AppData\Local\Coinomi\Coinomi\wallets\w.wallet";
    let mk = |host: Option<&str>| {
        vec![
            explorer(),
            start(
                0,
                "c",
                500,
                coinomi,
                "Coinomi.exe",
                Some(("explorer", 4000)),
                VALID,
                Some("Coinomi Ltd"),
            ),
            read(10, "c", 500, wallet),
            net(500, "c", 500, "198.51.100.9", host, false, Some(120_000)),
        ]
    };
    // A legitimate sync to its own named host: Low ST-01, High Audit ST-04.
    let out = run(policy_all(RuleMode::Protect), &mk(Some("api.coinomi.com")));
    if has(&out, "ST-01") {
        assert_eq!(sev(&out, "ST-01"), Severity::Low, "{}", dump(&out));
    }
    assert_eq!(sev(&out, "ST-04"), Severity::High, "{}", dump(&out));
    assert!(!any_kill(&out), "{}", dump(&out));
    // A raw IP: the full response.
    let out = run(policy_all(RuleMode::Protect), &mk(None));
    assert_eq!(sev(&out, "ST-04"), Severity::Critical, "{}", dump(&out));
    assert!(any_kill(&out));
}

#[test]
fn unpinned_browser_names_are_not_browsers_anywhere() {
    for img in [
        r"C:\Program Files\Thorium\Application\thorium.exe",
        r"C:\Users\alice\AppData\Local\Thorium\Application\thorium.exe",
    ] {
        let ev = vec![
            explorer(),
            start(
                0,
                "t",
                600,
                img,
                "thorium.exe",
                Some(("explorer", 4000)),
                VALID,
                Some("Any Ltd"),
            ),
            read(10, "t", 600, CHROME_LOGIN),
            read(11, "t", 600, CHROME_COOKIES),
            read(12, "t", 600, TDATA),
            net(500, "t", 600, "198.51.100.9", None, false, None),
        ];
        let out = run(policy_all(RuleMode::Protect), &ev);
        assert!(
            has(&out, "ST-02") && has(&out, "ST-04"),
            "{img}: {}",
            dump(&out)
        );
    }
    // Its own profile is not theft.
    let ev = vec![
        explorer(),
        start(
            0,
            "t",
            600,
            r"C:\Users\alice\AppData\Local\Thorium\Application\thorium.exe",
            "thorium.exe",
            Some(("explorer", 4000)),
            VALID,
            Some("Any Ltd"),
        ),
        read(
            10,
            "t",
            600,
            r"C:\Users\alice\AppData\Local\Thorium\User Data\Default\Login Data",
        ),
    ];
    let out = run(policy_all(RuleMode::Protect), &ev);
    assert!(!any_kill(&out), "{}", dump(&out));
    if has(&out, "ST-01") {
        assert_eq!(sev(&out, "ST-01"), Severity::Low, "{}", dump(&out));
    }
}

// --------------------------------------------------------- path forms

#[test]
fn short_names_and_shadow_copies_are_the_stores() {
    use kestrel_detect::paths::{
        match_sensitive_path, match_short_names, may_be_sensitive_short, normalize_path,
    };
    let n = normalize_path(r"C:\Users\alice\AppData\Local\Google\Chrome\USERDA~1\Default\LOGIND~1");
    let (s, long) = match_short_names(&n).expect("short name store");
    assert_eq!(s.noun, "saved passwords");
    assert!(long.ends_with(r"user data\default\login data"), "{long}");
    assert!(match_short_names(&normalize_path(r"C:\PROGRA~1\Foo\bar.exe")).is_none());
    assert!(!may_be_sensitive_short(r"C:\PROGRA~1\Foo\bar.exe"));
    assert!(may_be_sensitive_short(
        r"C:\Users\a\AppData\Roaming\TELEGR~1\tdata\x"
    ));
    let shadow = r"\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy7\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    assert!(match_sensitive_path(shadow).is_some());
    assert_eq!(
        normalize_path(shadow),
        r"\users\alice\appdata\local\google\chrome\user data\default\login data"
    );
}
