//! Evidence journal (`kestrel_detect::evidence`): scope, bounds, windows,
//! de-duplication and process-tree membership.

mod common;

use common::*;
use kestrel_common::evidence::{ProcessRole, WriteOp, MAX_STAGED_FILES, MAX_TREE_PROCESSES};
use kestrel_common::*;
use kestrel_detect::evidence::*;
use kestrel_detect::{Output, ProcessTable};

fn g(s: &str) -> ProcessGuid {
    ProcessGuid(s.into())
}

fn proc(guid: &str, pid: u32, parent: Option<&str>, image: &str) -> ProcessInfo {
    ProcessInfo {
        guid: g(guid),
        pid,
        ppid: 0,
        parent_guid: parent.map(g),
        image: image.into(),
        cmdline: image.into(),
        user: Some(r"CORP\j.doe".into()),
        integrity: None,
        start_ts: T0,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unsigned,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: PathClass::of(image),
    }
}

fn ev(ts: i64, guid: &str, data: EventData) -> Event {
    Event {
        ts,
        pid: 1,
        guid: g(guid),
        data,
    }
}

fn fa(ts: i64, guid: &str, path: &str, op: FileOp) -> Event {
    ev(
        ts,
        guid,
        EventData::FileAccess {
            path: path.into(),
            op,
        },
    )
}

fn net(ts: i64, guid: &str, ip: &str, port: u16) -> Event {
    ev(
        ts,
        guid,
        EventData::NetConnect {
            proto: NetProto::Tcp,
            dst_ip: ip.into(),
            dst_port: port,
            src_port: 50_000,
            dst_host: None,
            bytes_sent: None,
        },
    )
}

fn members(guids: &[&str]) -> Vec<(ProcessInfo, ProcessRole)> {
    guids
        .iter()
        .map(|s| {
            (
                proc(s, 1, None, r"C:\Users\j.doe\AppData\Local\Temp\x.exe"),
                ProcessRole::Alerting,
            )
        })
        .collect()
}

/// explorer (Windows) â†’ loader (Temp) â†’ stealer (AppData) â†’ cmd (System32)
/// â†’ grandchild; plus an unrelated sibling of the loader.
fn tree_table() -> ProcessTable {
    let mut t = ProcessTable::default();
    t.insert(proc("svc", 600, None, r"C:\Windows\System32\services.exe"));
    t.insert(proc(
        "explorer",
        4100,
        Some("svc"),
        r"C:\Windows\explorer.exe",
    ));
    t.insert(proc(
        "loader",
        7100,
        Some("explorer"),
        r"C:\Users\j.doe\AppData\Local\Temp\7zS1\setup.exe",
    ));
    t.insert(proc(
        "stealer",
        7200,
        Some("loader"),
        r"C:\Users\j.doe\AppData\Roaming\svcupd\svcupd.exe",
    ));
    let mut cmd = proc("cmd", 7300, Some("stealer"), r"C:\Windows\System32\cmd.exe");
    cmd.exit_ts = Some(T0 + 10);
    t.insert(cmd);
    t.insert(proc(
        "grandchild",
        7400,
        Some("cmd"),
        r"C:\Windows\System32\timeout.exe",
    ));
    t.insert(proc(
        "notepad",
        7500,
        Some("explorer"),
        r"C:\Windows\System32\notepad.exe",
    ));
    t
}

#[test]
fn tree_membership() {
    let t = tree_table();
    let m = tree_members(&t, &g("stealer"));
    let ids: Vec<(&str, ProcessRole)> = m.iter().map(|(p, r)| (p.guid.0.as_str(), *r)).collect();
    assert_eq!(ids[0], ("stealer", ProcessRole::Alerting), "alerting first");
    assert!(ids.contains(&("loader", ProcessRole::Ancestor)), "{ids:?}");
    // Exited intermediates and their children are part of the tree.
    assert!(ids.contains(&("cmd", ProcessRole::Descendant)), "{ids:?}");
    assert!(
        ids.contains(&("grandchild", ProcessRole::Descendant)),
        "{ids:?}"
    );
    for not in ["explorer", "svc", "notepad"] {
        assert!(!ids.iter().any(|(i, _)| *i == not), "{not} in {ids:?}");
    }
    assert_eq!(ids.len(), 4);
    // Unknown process: empty.
    assert!(tree_members(&t, &g("nope")).is_empty());
    // A Program Files parent stops the walk too.
    let mut t2 = ProcessTable::default();
    t2.insert(proc("pf", 1, None, r"C:\Program Files\7-Zip\7zFM.exe"));
    t2.insert(proc("x", 2, Some("pf"), r"C:\Users\a\Downloads\x.exe"));
    let m2 = tree_members(&t2, &g("x"));
    assert_eq!(m2.len(), 1);
}

#[test]
fn tree_is_bounded() {
    let mut t = ProcessTable::default();
    t.insert(proc("root", 1, None, r"C:\Users\a\Downloads\root.exe"));
    for i in 0..200 {
        t.insert(proc(
            &format!("c{i}"),
            100 + i,
            Some("root"),
            r"C:\Users\a\AppData\Local\Temp\c.exe",
        ));
    }
    let m = tree_members(&t, &g("root"));
    assert_eq!(m.len(), MAX_TREE_PROCESSES);
    assert_eq!(m[0].1, ProcessRole::Alerting);
}

#[test]
fn staging_scope() {
    let mut j = EvidenceJournal::new();
    for (p, keep) in [
        (r"C:\Users\j.doe\AppData\Local\Temp\a\out.zip", true),
        (r"C:\Users\j.doe\AppData\Roaming\x\pw.txt", true),
        (r"C:\Users\j.doe\Downloads\loot.7z", true),
        (r"C:\ProgramData\XGBK\8E3K.zip", true),
        (r"C:\Windows\Temp\dump.bin", true),
        (r"C:\Users\Public\Documents\s.png", true),
        (r"C:\Windows\System32\drivers\etc\hosts", false),
        (r"C:\Windows\notepad.bak", false),
        (r"C:\Program Files\App\cache.dat", false),
        (r"\\server\share\x.zip", false),
        (r"D:\Windows\System32\x.zip", false),
        ("", false),
    ] {
        let before = j.total_writes();
        j.observe(&fa(T0, "p", p, FileOp::Write));
        assert_eq!(j.total_writes() > before, keep, "{p}");
    }
    // Reads / deletes are never staged candidates.
    j.observe(&fa(
        T0,
        "q",
        r"C:\Users\j.doe\AppData\Local\Temp\b.zip",
        FileOp::Read,
    ));
    j.observe(&fa(
        T0,
        "q",
        r"C:\Users\j.doe\AppData\Local\Temp\b.zip",
        FileOp::Delete,
    ));
    assert_eq!(j.writes_of(&g("q")), 0);
    // file_activity sample paths count, with the same scope.
    j.observe(&ev(
        T0,
        "fa",
        EventData::FileActivity(FileActivity {
            sample_paths: vec![
                r"C:\Users\j.doe\Documents\a.docx".into(),
                r"C:\Windows\System32\x.dll".into(),
            ],
            ..Default::default()
        }),
    ));
    assert_eq!(j.writes_of(&g("fa")), 1);
    let s = j.snapshot(&members(&["fa"]), T0, T0);
    assert_eq!(s.staged[0].op, WriteOp::Written);
}

#[test]
fn write_hints_and_ops() {
    let mut j = EvidenceJournal::new();
    let p = r"C:\Users\a\AppData\Local\Temp\x\screen.png";
    j.observe_write(T0, &g("p"), p, WriteOp::Created);
    j.observe_write(T0 + 5, &g("p"), p, WriteOp::Overwritten);
    j.observe(&fa(
        T0 + 1,
        "p",
        r"C:\Users\a\AppData\Local\Temp\x\n.txt",
        FileOp::Create,
    ));
    let s = j.snapshot(&members(&["p"]), T0, T0 + 10);
    assert_eq!(s.staged.len(), 2);
    assert_eq!(s.staged[0].path, p, "newest first");
    assert_eq!(s.staged[0].op, WriteOp::Overwritten);
    assert_eq!(s.staged[1].op, WriteOp::Created);
    assert_eq!(
        s.staged[0].image,
        r"C:\Users\j.doe\AppData\Local\Temp\x.exe"
    );
}

#[test]
fn per_process_bounds() {
    let mut j = EvidenceJournal::new();
    for i in 0..(MAX_WRITES_PER_PROCESS + 50) {
        j.observe_write(
            T0 + i as i64,
            &g("w"),
            &format!(r"C:\Users\a\AppData\Local\Temp\f{i}.bin"),
            WriteOp::Created,
        );
    }
    assert_eq!(j.writes_of(&g("w")), MAX_WRITES_PER_PROCESS);
    assert_eq!(j.total_writes(), MAX_WRITES_PER_PROCESS);
    // Oldest out: f0 is gone, the last one is there.
    let s = j.snapshot(&members(&["w"]), 0, i64::MAX);
    assert!(!s.staged.iter().any(|c| c.path.ends_with(r"\f0.bin")));
    assert!(s.staged[0]
        .path
        .ends_with(&format!(r"\f{}.bin", MAX_WRITES_PER_PROCESS + 49)));
    // Same path updates in place.
    let last = format!(
        r"C:\Users\a\AppData\Local\Temp\f{}.bin",
        MAX_WRITES_PER_PROCESS + 49
    );
    j.observe_write(
        T0 + 10_000,
        &g("w"),
        &last.to_uppercase(),
        WriteOp::Overwritten,
    );
    assert_eq!(j.writes_of(&g("w")), MAX_WRITES_PER_PROCESS);

    // Stores.
    for i in 0..(MAX_STORES_PER_PROCESS + 10) {
        j.observe(&fa(
            T0 + i as i64,
            "s",
            &format!(
                r"C:\Users\a\AppData\Roaming\Mozilla\Firefox\Profiles\p{i}.default\logins.json"
            ),
            FileOp::Read,
        ));
    }
    assert_eq!(j.stores_of(&g("s")), MAX_STORES_PER_PROCESS);
    // Net tuples.
    for i in 0..(MAX_NET_PER_PROCESS + 10) {
        j.observe(&net(
            T0 + i as i64,
            "n",
            &format!("198.51.100.{}", i + 1),
            443,
        ));
    }
    assert_eq!(j.net_of(&g("n")), MAX_NET_PER_PROCESS);
}

#[test]
fn global_bounds() {
    let mut j = EvidenceJournal::new();
    for i in 0..(MAX_PROCESSES + 20) {
        j.observe(&net(T0 + i as i64, &format!("p{i}"), "198.51.100.1", 443));
    }
    assert_eq!(j.len(), MAX_PROCESSES);
    // Least recently active went first.
    assert_eq!(j.net_of(&g("p0")), 0);
    assert_eq!(j.net_of(&g(&format!("p{}", MAX_PROCESSES + 19))), 1);

    // Pinned processes are never evicted for capacity.
    let mut j = EvidenceJournal::new();
    j.observe(&net(T0, "keep", "198.51.100.1", 443));
    j.pin(&[g("keep")]);
    for i in 0..(MAX_PROCESSES + 20) {
        j.observe(&net(
            T0 + 1 + i as i64,
            &format!("p{i}"),
            "198.51.100.1",
            443,
        ));
    }
    assert_eq!(j.net_of(&g("keep")), 1);

    // Total writes cap.
    let mut j = EvidenceJournal::new();
    let procs = MAX_TOTAL_WRITES / MAX_WRITES_PER_PROCESS + 4;
    for p in 0..procs {
        for i in 0..MAX_WRITES_PER_PROCESS {
            j.observe_write(
                T0 + (p * 1000 + i) as i64,
                &g(&format!("b{p}")),
                &format!(r"C:\Users\a\AppData\Local\Temp\b{p}\f{i}.o"),
                WriteOp::Created,
            );
        }
    }
    assert!(j.total_writes() <= MAX_TOTAL_WRITES, "{}", j.total_writes());
    // The most recent writer kept its writes.
    assert_eq!(
        j.writes_of(&g(&format!("b{}", procs - 1))),
        MAX_WRITES_PER_PROCESS
    );
}

#[test]
fn eviction_and_pinning() {
    let mut j = EvidenceJournal::new();
    j.observe_write(
        T0,
        &g("old"),
        r"C:\Users\a\Downloads\a.zip",
        WriteOp::Created,
    );
    j.observe_write(
        T0,
        &g("pinned"),
        r"C:\Users\a\Downloads\b.zip",
        WriteOp::Created,
    );
    j.observe(&fa(
        T0,
        "pinned",
        r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        FileOp::Read,
    ));
    j.observe_write(
        T0 + JOURNAL_RETENTION_MS,
        &g("new"),
        r"C:\Users\a\Downloads\c.zip",
        WriteOp::Created,
    );
    j.pin(&[g("pinned")]);
    j.evict(T0 + JOURNAL_RETENTION_MS + 1);
    assert_eq!(j.writes_of(&g("old")), 0);
    assert_eq!(j.writes_of(&g("pinned")), 1);
    assert_eq!(j.stores_of(&g("pinned")), 1);
    assert_eq!(j.writes_of(&g("new")), 1);
    assert_eq!(j.total_writes(), 2);
    // Pins are reference counted.
    j.pin(&[g("pinned")]);
    j.unpin(&[g("pinned")]);
    assert!(j.is_pinned(&g("pinned")));
    j.unpin(&[g("pinned")]);
    assert!(!j.is_pinned(&g("pinned")));
    j.evict(T0 + JOURNAL_RETENTION_MS + 1);
    assert_eq!(j.writes_of(&g("pinned")), 0);
    assert_eq!(j.total_writes(), 1);
}

#[test]
fn window_and_case_insensitive_dedup() {
    let mut j = EvidenceJournal::new();
    j.observe_write(
        T0,
        &g("a"),
        r"C:\Users\a\AppData\Local\Temp\Out.ZIP",
        WriteOp::Created,
    );
    j.observe_write(
        T0 + 50,
        &g("b"),
        r"c:/users/a/appdata/local/temp/out.zip",
        WriteOp::Overwritten,
    );
    j.observe_write(
        T0 - 1000,
        &g("a"),
        r"C:\Users\a\Downloads\early.txt",
        WriteOp::Created,
    );
    j.observe_write(
        T0 + 5000,
        &g("a"),
        r"C:\Users\a\Downloads\late.txt",
        WriteOp::Created,
    );
    j.observe_write(
        T0,
        &g("other"),
        r"C:\Users\a\Downloads\other.txt",
        WriteOp::Created,
    );
    let s = j.snapshot(&members(&["a", "b"]), T0 - 10, T0 + 100);
    assert_eq!(s.staged.len(), 1, "{:?}", s.staged);
    assert_eq!(s.staged[0].guid, g("b"), "latest write wins");
    assert_eq!(s.staged[0].op, WriteOp::Overwritten);
    let s = j.snapshot(&members(&["a"]), T0 - 2000, T0 + 6000);
    assert_eq!(s.staged.len(), 3);
    assert_eq!(s.staged[0].path, r"C:\Users\a\Downloads\late.txt");
    assert_eq!(s.staged[2].path, r"C:\Users\a\Downloads\early.txt");
}

#[test]
fn staged_listing_cap() {
    let mut j = EvidenceJournal::new();
    // Two processes, 300 + 300 distinct files: 600 candidates.
    for p in ["x", "y"] {
        for i in 0..300 {
            j.observe_write(
                T0 + i,
                &g(p),
                &format!(r"C:\Users\a\AppData\Local\Temp\{p}\f{i}.txt"),
                WriteOp::Created,
            );
        }
    }
    let s = j.snapshot(&members(&["x", "y"]), 0, i64::MAX);
    assert_eq!(s.staged.len(), MAX_STAGED_FILES);
    assert_eq!(s.staged_unlisted, 100);
}

#[test]
fn store_classification_and_merge() {
    let mut j = EvidenceJournal::new();
    let chrome = r"C:\Users\j.doe\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    let ff =
        r"C:\Users\j.doe\AppData\Roaming\Mozilla\Firefox\Profiles\ab12.default-release\logins.json";
    let ordinary = r"C:\Users\j.doe\Documents\report.docx";
    j.observe(&fa(T0 + 10, "a", chrome, FileOp::Read));
    j.observe(&fa(T0 + 20, "a", chrome, FileOp::Open));
    j.observe(&fa(T0 + 5, "b", &chrome.to_uppercase(), FileOp::Read));
    j.observe(&fa(T0 + 30, "b", ff, FileOp::Read));
    j.observe(&fa(T0 + 30, "b", ordinary, FileOp::Read));
    // A write to a store is not a read.
    j.observe(&fa(T0 + 40, "c", chrome, FileOp::Write));
    let s = j.snapshot(&members(&["a", "b", "c"]), T0, T0 + 100);
    assert_eq!(s.secrets.len(), 2, "{:?}", s.secrets);
    let c = &s.secrets[0];
    assert_eq!(c.store, "Chrome");
    assert_eq!(c.category, DataCategory::BrowserPasswords);
    assert_eq!(c.open_count, 3);
    assert_eq!((c.first_read, c.last_read), (T0 + 5, T0 + 20));
    assert_eq!(c.process_guid, g("b"), "earliest reader");
    assert!(c.size.is_none() && c.copy.is_none());
    let f = &s.secrets[1];
    assert_eq!(f.category, DataCategory::BrowserPasswords);
    assert!(f.store.contains("Firefox"), "{}", f.store);
    // Outside the window: nothing.
    assert!(j
        .snapshot(&members(&["a", "b"]), T0 + 50, T0 + 60)
        .secrets
        .is_empty());
}

#[test]
fn net_tuple_filtering() {
    let mut j = EvidenceJournal::new();
    for (i, (ip, port)) in [
        ("203.0.113.7", 443),
        ("127.0.0.1", 443),
        ("0.0.0.0", 80),
        ("224.0.0.251", 5353),
        ("169.254.10.1", 80),
        ("255.255.255.255", 67),
        ("::1", 443),
        ("fe80::1", 443),
        ("ff02::fb", 5353),
        ("fe80::1%12", 443),
        ("not-an-ip", 443),
        ("10.0.0.5", 0),
        ("::ffff:198.51.100.9", 8080),
        ("2001:db8::7", 443),
        ("203.0.113.7", 443),
    ]
    .iter()
    .enumerate()
    {
        j.observe(&net(T0 + i as i64, "n", ip, *port));
    }
    let s = j.snapshot(&members(&["n"]), T0, T0 + 100);
    let got: Vec<(String, Option<u16>)> = s.net.iter().map(|f| (f.ip.clone(), f.port)).collect();
    assert_eq!(
        got,
        vec![
            ("203.0.113.7".to_string(), Some(443)),
            ("2001:db8::7".to_string(), Some(443)),
            ("198.51.100.9".to_string(), Some(8080)),
            ("10.0.0.5".to_string(), None),
        ]
    );
    assert!(s.net.iter().all(|f| f.proto == Some(NetProto::Tcp)));
    // Capped.
    let mut j = EvidenceJournal::new();
    for i in 0..30 {
        j.observe(&net(T0 + i, "m", &format!("198.51.100.{}", i + 1), 443));
    }
    let s = j.snapshot(&members(&["m"]), T0, T0 + 100);
    assert_eq!(s.net.len(), kestrel_common::evidence::PCAP_MAX_FILTERS);
    assert_eq!(s.net[0].ip, "198.51.100.30", "most recent first");
}

/// The fixture through engine + journal: ST-02 fires for the stealer and
/// the snapshot of its tree holds the staged zip (not the System32 write),
/// the four stores and the C2 tuple.
#[test]
fn stealer_fixture_end_to_end() {
    let mut e = engine(Policy::default());
    e.seed_process(proc("ev-explorer", 4100, None, r"C:\Windows\explorer.exe"));
    let mut j = EvidenceJournal::new();
    let mut alert = None;
    for evt in fixture("evidence_stealer_tree.jsonl") {
        j.observe(&evt);
        for o in e.process(&evt) {
            if let Output::Alert(d) = o {
                if kestrel_common::evidence::is_trigger_rule(&d.alert.rule_id) && alert.is_none() {
                    alert = Some(d.alert);
                }
            }
        }
    }
    let a = alert.expect("ST-02 / ST-04 alert");
    assert_eq!(a.process.guid, g("ev-stealer"));
    let m = tree_members(e.processes(), &a.process.guid);
    let ids: Vec<&str> = m.iter().map(|(p, _)| p.guid.0.as_str()).collect();
    assert_eq!(ids, ["ev-stealer", "ev-loader"]);
    let s = j.snapshot(
        &m,
        a.ts - kestrel_common::evidence::LOOKBACK_MS,
        a.ts + 60_000,
    );
    let staged: Vec<&str> = s.staged.iter().map(|c| c.path.as_str()).collect();
    assert_eq!(staged, [r"C:\Users\j.doe\AppData\Local\Temp\svc\out.zip"]);
    assert_eq!(
        s.staged[0].image,
        r"C:\Users\j.doe\AppData\Roaming\svcupd\svcupd.exe"
    );
    assert_eq!(s.secrets.len(), 4, "{:?}", s.secrets);
    assert_eq!(s.net.len(), 1);
    assert_eq!(s.net[0].ip, "203.0.113.7");
}

/// M5: a validly signed user-writable ancestor (per-user Telegram that
/// launched a download) is not part of the tree and stops the walk.
#[test]
fn signed_ancestors_stop_the_walk() {
    let mut t = ProcessTable::default();
    t.insert(proc("explorer", 1, None, r"C:\Windows\explorer.exe"));
    let mut tg = proc(
        "telegram",
        2,
        Some("explorer"),
        r"C:\Users\j.doe\AppData\Roaming\Telegram Desktop\Telegram.exe",
    );
    tg.signed = SignatureState::Valid;
    t.insert(tg);
    t.insert(proc(
        "loader",
        3,
        Some("telegram"),
        r"C:\Users\j.doe\Downloads\Telegram Desktop\invoice.exe",
    ));
    t.insert(proc(
        "stealer",
        4,
        Some("loader"),
        r"C:\Users\j.doe\AppData\Local\Temp\x\s.exe",
    ));
    let ids: Vec<String> = tree_members(&t, &g("stealer"))
        .into_iter()
        .map(|(p, _)| p.guid.0)
        .collect();
    assert_eq!(ids, ["stealer", "loader"]);
    // An invalid signature is not trusted.
    let mut t2 = ProcessTable::default();
    let mut bad = proc(
        "bad",
        1,
        None,
        r"C:\Users\a\AppData\Local\Temp\fake_chrome.exe",
    );
    bad.signed = SignatureState::Invalid;
    t2.insert(bad);
    t2.insert(proc(
        "s",
        2,
        Some("bad"),
        r"C:\Users\a\AppData\Local\Temp\s.exe",
    ));
    assert_eq!(tree_members(&t2, &g("s")).len(), 2);
}

/// M1: 512 junk files do not push the archive out of the ring.
#[test]
fn high_value_writes_survive_junk() {
    assert!(is_high_value(r"C:\Users\a\AppData\Local\Temp\x\OUT.ZIP"));
    assert!(is_high_value(r"C:\x\pw.txt"));
    assert!(!is_high_value(r"C:\x\nss3.dll"));
    assert!(!is_high_value(r"C:\x\.zip"));
    assert!(!is_high_value(r"C:\x\noext"));
    let mut j = EvidenceJournal::new();
    let zip = r"C:\Users\a\AppData\Local\Temp\st\loot.zip";
    j.observe_write(T0, &g("s"), zip, WriteOp::Created);
    for i in 0..(MAX_WRITES_PER_PROCESS + 100) {
        j.observe_write(
            T0 + 1 + i as i64,
            &g("s"),
            &format!(r"C:\Users\a\AppData\Local\Temp\st\junk{i}.tmp"),
            WriteOp::Created,
        );
    }
    // (Window = the zip's write only: the listing itself is capped at 500.)
    let s = j.snapshot(&members(&["s"]), 0, T0);
    assert!(s.staged.iter().any(|c| c.path == zip));
    assert_eq!(s.staged_evicted, 101);
    // All high-value: the oldest goes.
    let mut j = EvidenceJournal::new();
    for i in 0..(MAX_WRITES_PER_PROCESS + 1) {
        j.observe_write(
            T0 + i as i64,
            &g("h"),
            &format!(r"C:\Users\a\Downloads\f{i}.txt"),
            WriteOp::Created,
        );
    }
    let s = j.snapshot(&members(&["h"]), 0, i64::MAX);
    assert!(!s.staged.iter().any(|c| c.path.ends_with(r"\f0.txt")));
    assert_eq!(s.staged_evicted, 1);
}

/// L7 + M4: infrastructure ports are never capture filters; overlong
/// paths are ignored.
#[test]
fn infra_ports_and_long_paths() {
    let mut j = EvidenceJournal::new();
    for (i, port) in [443u16, 445, 88, 389, 53, 3269, 8443].iter().enumerate() {
        j.observe(&net(T0 + i as i64, "n", "10.0.0.10", *port));
    }
    let s = j.snapshot(&members(&["n"]), 0, i64::MAX);
    let ports: Vec<Option<u16>> = s.net.iter().map(|f| f.port).collect();
    assert_eq!(ports, [Some(8443), Some(443)]);
    assert_eq!(s.net_excluded, 5);
    let long = format!(r"C:\Users\a\Downloads\{}.zip", "x".repeat(1100));
    j.observe_write(T0, &g("n"), &long, WriteOp::Created);
    assert_eq!(j.writes_of(&g("n")), 0);
}
