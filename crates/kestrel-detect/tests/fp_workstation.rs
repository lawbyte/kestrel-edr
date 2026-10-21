//! Owner's PC alert triage, 2026-10-22: 7,614 alerts from a Windows 11
//! developer workstation (policy all-Audit, agent 1.1.4 / 1.1.5). Each fix
//! is narrow and per rule (see `docs/DECISIONS.md`); every benign fixture
//! below is built from the triage evidence and every fix has a malicious
//! variant that must still fire.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;

const DAY: i64 = 24 * 3600 * 1000;

fn run(name: &str, mode: RuleMode) -> Vec<Output> {
    let mut e = engine(policy_all(mode));
    replay(&mut e, &fixture(name))
}

fn count(out: &[Output], rule: &str) -> usize {
    rule_ids(out).iter().filter(|r| *r == rule).count()
}

fn no_actions(out: &[Output]) {
    for d in alerts(out) {
        assert!(d.actions.is_empty(), "{}", dump(out));
    }
    assert!(standalone(out).is_empty(), "{}", dump(out));
}

fn has_kill_of(d: &Detection, guid: &str) -> bool {
    kills(&d.actions).iter().any(|(g, _)| g == guid)
}

fn unsigned_start(ts: i64, guid: &str, pid: u32, image: &str, sha: Option<&str>) -> Event {
    let mut e = start(
        ts,
        guid,
        pid,
        image,
        image,
        None,
        SignatureState::Unsigned,
        None,
    );
    if let EventData::ProcessStart(p) = &mut e.data {
        p.sha256 = sha.map(Into::into);
        p.file_size = Some(4096);
    }
    e
}

// ------------------------------------------------------------ 1. ST-12

#[test]
fn st12_toolchain_alerts_once_per_binary() {
    let out = run("ws_st12_toolchain_benign.jsonl", RuleMode::Audit);
    // cargo, rustc (60 runs), clippy-driver (10), protoc (5), wix (3),
    // makensis (2): one ST-12 alert per binary.
    assert_eq!(count(&out, "ST-12"), 6, "{}", dump(&out));
    let rustc = alerts(&out)
        .into_iter()
        .filter(|d| d.alert.rule_id == "ST-12" && d.alert.summary.starts_with("rustc.exe"))
        .count();
    assert_eq!(rustc, 1, "{}", dump(&out));
    // ST-12 in Protect (opt-in) still suspends and judges every run.
    let out = run("ws_st12_toolchain_benign.jsonl", RuleMode::Protect);
    assert_eq!(count(&out, "ST-12"), 81, "{}", dump(&out));
}

#[test]
fn st12_new_unsigned_binary_in_downloads_or_temp_alerts_immediately() {
    let mut e = engine(Policy::default());
    let out = e.process(&unsigned_start(
        0,
        "dl",
        10,
        r"C:\Users\azka\Downloads\invoice_viewer.exe",
        Some(&"11".repeat(32)),
    ));
    assert_eq!(count(&out, "ST-12"), 1, "{}", dump(&out));
    let out = e.process(&unsigned_start(
        10,
        "tmp",
        11,
        r"C:\Users\azka\AppData\Local\Temp\x\setup.exe",
        Some(&"22".repeat(32)),
    ));
    assert_eq!(count(&out, "ST-12"), 1, "{}", dump(&out));
    let out = e.process(&unsigned_start(
        20,
        "roam",
        12,
        r"C:\Users\azka\AppData\Roaming\upd\upd.exe",
        Some(&"33".repeat(32)),
    ));
    assert_eq!(count(&out, "ST-12"), 1, "{}", dump(&out));
}

#[test]
fn st12_same_hash_from_a_riskier_folder_alerts_again() {
    let h = "44".repeat(32);
    let mut e = engine(Policy::default());
    let appdata = r"C:\Users\azka\AppData\Local\tool\tool.exe";
    assert_eq!(
        count(
            &e.process(&unsigned_start(0, "a", 10, appdata, Some(&h))),
            "ST-12"
        ),
        1
    );
    // Same file, another AppData copy: folded.
    let other = r"C:\Users\azka\AppData\Roaming\x\tool.exe";
    assert_eq!(
        count(
            &e.process(&unsigned_start(10, "b", 11, other, Some(&h))),
            "ST-12"
        ),
        0
    );
    // Same hash from Downloads: riskier, alerts again.
    let dl = r"C:\Users\azka\Downloads\tool.exe";
    let out = e.process(&unsigned_start(20, "c", 12, dl, Some(&h)));
    assert_eq!(count(&out, "ST-12"), 1, "{}", dump(&out));
    assert!(first(&out, "ST-12").alert.summary.contains("riskier"));
    // Then Temp (same rank as Downloads) and AppData again: folded.
    let tmp = r"C:\Users\azka\AppData\Local\Temp\tool.exe";
    assert_eq!(
        count(
            &e.process(&unsigned_start(30, "d", 13, tmp, Some(&h))),
            "ST-12"
        ),
        0
    );
    assert_eq!(
        count(
            &e.process(&unsigned_start(40, "e", 14, appdata, Some(&h))),
            "ST-12"
        ),
        0
    );
}

#[test]
fn st12_without_hash_keys_on_path_and_size_and_expires_after_7_days() {
    let img = r"C:\Users\azka\.cargo\bin\cargo-tool.exe";
    let mut e = engine(Policy::default());
    assert_eq!(
        count(&e.process(&unsigned_start(0, "a", 10, img, None)), "ST-12"),
        1
    );
    for i in 0..5 {
        let out = e.process(&unsigned_start(
            100 + i,
            &format!("r{i}"),
            20 + i as u32,
            img,
            None,
        ));
        assert_eq!(count(&out, "ST-12"), 0, "{}", dump(&out));
    }
    // A different size at the same path is a different binary.
    let mut other = unsigned_start(200, "size", 30, img, None);
    if let EventData::ProcessStart(p) = &mut other.data {
        p.file_size = Some(9999);
    }
    assert_eq!(count(&e.process(&other), "ST-12"), 1);
    // Seven days later: alerts again and says how often it ran meanwhile.
    let out = e.process(&unsigned_start(7 * DAY + 1, "later", 40, img, None));
    assert_eq!(count(&out, "ST-12"), 1, "{}", dump(&out));
    assert!(
        first(&out, "ST-12").alert.summary.contains("5 more times"),
        "{}",
        dump(&out)
    );
}

#[test]
fn st12_first_seen_state_survives_export_import_and_is_bounded() {
    let h = "55".repeat(32);
    let img = r"C:\Users\azka\.rustup\toolchains\x\bin\rustc.exe";
    let mut a = engine(Policy::default());
    assert_eq!(
        count(
            &a.process(&unsigned_start(0, "a", 10, img, Some(&h))),
            "ST-12"
        ),
        1
    );
    let json = a.st12_seen_export(T0 + 1000);
    let mut b = engine(Policy::default());
    b.st12_seen_import(&json, T0 + 5);
    assert_eq!(
        count(
            &b.process(&unsigned_start(10, "b", 11, img, Some(&h))),
            "ST-12"
        ),
        0
    );
    // Malformed input is ignored.
    b.st12_seen_import("{not json", T0 + 20);
    // Rows expired at load time, or stamped far in the future (a damaged
    // value must not silence ST-12 for good), are dropped.
    for now in [T0 + 8 * DAY, T0 - 2 * DAY] {
        let mut d = engine(Policy::default());
        d.st12_seen_import(&json, now);
        assert_eq!(d.st12_seen_export(T0 + 1000), "[]", "now {now}");
    }
    // Bounded memory.
    let mut c = engine(Policy::default());
    for i in 0..8300u32 {
        c.process(&unsigned_start(
            i as i64,
            &format!("g{i}"),
            1000 + i,
            &format!(r"C:\Users\azka\AppData\Local\t\b{i}.exe"),
            None,
        ));
    }
    let rows: Vec<serde_json::Value> =
        serde_json::from_str(&c.st12_seen_export(T0 + 10_000)).unwrap();
    assert!(rows.len() <= 8192, "{}", rows.len());
    // Path + size identities (no hash) are never persisted (review 1.1.6
    // #7: a same-size payload at the same path would inherit the entry).
    assert!(rows.is_empty(), "{}", rows.len());
}

// --------------------------------------------------- 2. / 3. RW-06, RW-08

#[test]
fn compilers_renaming_their_own_files_are_not_ransomware() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_rw_compiler_benign.jsonl", mode);
        for r in ["RW-06", "RW-07", "RW-08"] {
            assert_eq!(count(&out, r), 0, "{mode:?} {r}: {}", dump(&out));
        }
    }
}

#[test]
fn ransomware_on_preexisting_documents_and_notes_still_fires() {
    let out = run("ws_rw_ransom_malicious.jsonl", RuleMode::Protect);
    let rw06 = first(&out, "RW-06");
    assert_eq!(rw06.alert.severity, Severity::Critical);
    assert!(has_kill_of(rw06, "locker"), "{}", dump(&out));
    let rw08 = first(&out, "RW-08");
    assert_eq!(rw08.alert.severity, Severity::Critical, "{}", dump(&out));
    assert!(rw08.alert.summary.contains("readme_decrypt.txt"));
}

fn locker(e: &mut Engine) {
    e.process(&unsigned_start(
        0,
        "enc",
        10,
        r"C:\Users\azka\AppData\Local\Temp\enc.exe",
        Some(&"66".repeat(32)),
    ));
}

fn activity(ts: i64, fa: FileActivity) -> Event {
    ev(ts, "enc", 10, EventData::FileActivity(fa))
}

#[test]
fn rw06_copy_then_delete_encryption_still_counts_the_originals() {
    // Encrypted copies (new files, appended unknown extension) plus deletes
    // of the 100 originals: the originals are pre-existing.
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 200,
            dirs: 12,
            new_files: 100,
            deletes: 100,
            ext_changes: 100,
            top_new_ext: Some("locked".into()),
            top_ext_pct: 100,
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 1, "{}", dump(&out));
    // In-place overwrite of pre-existing files.
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 120,
            dirs: 9,
            overwrites: 120,
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 1, "{}", dump(&out));
}

#[test]
fn rw06_files_the_process_created_itself_do_not_count() {
    let mut e = engine(Policy::default());
    locker(&mut e);
    // Junk files created to dilute the counts do not hide renames of
    // pre-existing documents either.
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 1040,
            dirs: 20,
            new_files: 1000,
            renames: 40,
            ext_changes: 40,
            top_new_ext: Some("k3str".into()),
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 1, "{}", dump(&out));
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 300,
            dirs: 40,
            new_files: 300,
            renames: 300,
            ext_changes: 290,
            top_new_ext: Some("rlib".into()),
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 0, "{}", dump(&out));
}

/// 1.1.6 sensor fields: `self_created` covers a compiler renaming outputs it
/// created more than 10 s earlier; delete-then-recreate of documents is
/// reported as rewrites of pre-existing files (not new files).
#[test]
fn rw06_uses_self_created_and_rewrites() {
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 120,
            dirs: 8,
            renames: 120,
            ext_changes: 120,
            self_created: 120,
            top_new_ext: Some("rlib".into()),
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 0, "{}", dump(&out));
    // Only part of the touched files are the process's own.
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 8000,
            files_touched: 160,
            dirs: 8,
            renames: 160,
            ext_changes: 160,
            new_files: 20,
            self_created: 120,
            top_new_ext: Some("k3str".into()),
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 1, "{}", dump(&out));
    assert!(
        first(&out, "RW-06")
            .alert
            .summary
            .contains("40 existing files"),
        "{}",
        dump(&out)
    );
    // Delete, then re-create under the same name.
    let mut e = engine(Policy::default());
    locker(&mut e);
    let out = e.process(&activity(
        10,
        FileActivity {
            window_ms: 3000,
            files_touched: 80,
            dirs: 6,
            overwrites: 80,
            deletes: 80,
            ..Default::default()
        },
    ));
    assert_eq!(count(&out, "RW-06"), 1, "{}", dump(&out));
}

#[test]
fn rw08_requires_ransom_note_characteristics() {
    let note = |name: &str, dirs: u32| FileActivity {
        window_ms: 8000,
        files_touched: dirs,
        dirs,
        new_files: dirs,
        note_name: Some(name.into()),
        note_dirs: dirs,
        ..Default::default()
    };
    for (name, fires) in [
        ("out", false),
        ("tmp.a", false),
        ("lib.rmeta", false),
        ("foo.o", false),
        ("x.obj", false),
        ("build.tmp", false),
        ("logo.png", false),
        ("help", false),
        ("README_DECRYPT.txt", true),
        ("how_to_restore.html", true),
        ("RECOVERY_INSTRUCTIONS.md", true),
        ("decrypt_files.bmp", true),
        ("unlock_files.tmp", true),
        ("x8k2q.txt", true),
        ("!!!_read_me.rtf", true),
    ] {
        let mut e = engine(Policy::default());
        locker(&mut e);
        let out = e.process(&activity(10, note(&name.to_ascii_lowercase(), 30)));
        assert_eq!(count(&out, "RW-08") == 1, fires, "{name}: {}", dump(&out));
    }
    // The kill-capable 5-folder check keeps its original note extensions:
    // `README.md` (every npm package) and note-named images in 5 to 19
    // folders do not fire; `readme_decrypt.txt` does, Critical.
    for (name, fires) in [
        ("readme.md", false),
        ("help.png", false),
        ("readme_decrypt.txt", true),
    ] {
        let mut e = engine(Policy::default());
        locker(&mut e);
        let out = e.process(&activity(10, note(name, 8)));
        assert_eq!(count(&out, "RW-08") == 1, fires, "{name}: {}", dump(&out));
        if fires {
            assert_eq!(first(&out, "RW-08").alert.severity, Severity::Critical);
        }
    }
    // `README.md` in hundreds of folders (npm install) is the alert-only
    // fallback, never a kill.
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "node",
        20,
        r"C:\Program Files\nodejs\node.exe",
        "node.exe npm-cli.js install",
        None,
        SignatureState::Valid,
        Some("OpenJS Foundation"),
    ));
    let out = e.process(&ev(
        10,
        "node",
        20,
        EventData::FileActivity(note("readme.md", 300)),
    ));
    let rw08 = first(&out, "RW-08");
    assert_eq!(rw08.alert.severity, Severity::High, "{}", dump(&out));
    assert!(rw08.actions.is_empty(), "{}", dump(&out));
}

// --------------------------------------------- 4. store location anchoring

#[test]
fn simulated_profiles_msix_copies_and_mangled_paths_are_not_stores() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_store_anchor_benign.jsonl", mode);
        for r in ["ST-01", "ST-02", "ST-04"] {
            assert_eq!(count(&out, r), 0, "{mode:?} {r}: {}", dump(&out));
        }
    }
}

#[test]
fn stealer_reading_the_real_chrome_store_still_fires() {
    let out = run("ws_store_anchor_malicious.jsonl", RuleMode::Protect);
    let st01 = first(&out, "ST-01");
    assert_eq!(st01.alert.severity, Severity::High);
    let st02 = first(&out, "ST-02");
    assert!(has_kill_of(st02, "stealer"), "{}", dump(&out));
    // The foreign reader of an MSIX app's LocalCache copy and the profile on
    // another drive still count as stores.
    let st = alerts(&out)
        .into_iter()
        .flat_map(|d| d.alert.evidence.iter())
        .filter_map(|ev| match &ev.data {
            EventData::FileAccess { path, .. } => Some(path.to_ascii_lowercase()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(
        st.iter().any(|p| p.contains(r"\localcache\")),
        "{}",
        dump(&out)
    );
    assert!(
        st.iter().any(|p| p.starts_with(r"d:\users\")),
        "{}",
        dump(&out)
    );
    assert!(count(&out, "ST-04") >= 1, "{}", dump(&out));
}

#[test]
fn kestrel_decoys_under_the_real_profile_still_trip() {
    let mut e = engine(Policy::default());
    let specs = e.canaries(r"C:\Users\azka");
    let decoy = specs
        .iter()
        .find(|s| !s.is_dir && s.path.to_ascii_lowercase().ends_with("local state"))
        .expect("a Local State decoy");
    e.process(&unsigned_start(
        0,
        "thief",
        10,
        r"C:\Users\azka\AppData\Local\Temp\a.exe",
        None,
    ));
    let out = e.process(&read(10, "thief", 10, &decoy.path));
    assert_eq!(count(&out, "ST-16"), 1, "{}", dump(&out));
}

#[test]
fn store_anchor_unit_cases() {
    use kestrel_detect::paths::{match_normalized, normalize_path, store_location_real};
    let real = |p: &str, reader: &str| {
        let n = normalize_path(p);
        let s = match_normalized(&n).unwrap_or_else(|| panic!("no store: {p}"));
        store_location_real(&n, &s, reader, 'c', false)
    };
    let any = r"C:\Users\azka\AppData\Local\Temp\x.exe";
    assert!(real(CHROME_STATE, any));
    assert!(real(r"\Device\HarddiskVolume3\Users\bob\.kube\config", any));
    assert!(real(
        r"C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\TokenBroker\Cache\a.tbres",
        any
    ));
    assert!(real(
        r"\\fs01\profiles$\alice\AppData\Roaming\Mozilla\Firefox\Profiles\x.default\logins.json",
        any
    ));
    assert!(real(
        r"C:\ProgramData\Microsoft\Vault\AC658CB4-9126-49BD-B877-31EEDAB3F204\Policy.vpol",
        any
    ));
    assert!(real(
        r"C:\Users\bob\AppData\Roaming\Microsoft\Protect\S-1-5-21-1\abc",
        any
    ));
    // Portable stores keep matching outside profiles.
    assert!(real(r"D:\Games\Steam\ssfn123", any));
    assert!(real(r"E:\Telegram\tdata\key_datas", any));
    assert!(real(r"D:\Vault\work.kdbx", any));
    // Not real.
    assert!(!real(
        r"C:\Users\azka\AppData\Local\Temp\x\Google\Chrome\User Data\Local State",
        any
    ));
    assert!(!real(
        r"C:\Users\azka\source\fixtures\AppData\Local\Google\Chrome\User Data\Local State",
        any
    ));
    assert!(!real(r"D:\backup\azka\.aws\credentials", any));
    assert!(!real(r"C:\Users\azka\projects\x\.ssh\id_rsa", any));
    assert!(!real(
        r"C:\Users\azka\Documents\sim\C\Users\j.doe\AppData\Roaming\Telegram Desktop\tdata\key_datas",
        any
    ));
    assert!(!real(
        r"C:\Users\azka\AppData\Local\Temp\sim\C\Users\j.doe\Documents\db.kdbx",
        any
    ));
    // MSIX LocalCache: the package's own app only.
    let lc = r"C:\Users\azka\AppData\Local\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Local\Google\Chrome\User Data\Local State";
    assert!(!real(
        lc,
        r"C:\Program Files\WindowsApps\Claude_3.1623.0.0_x64__pzs8sxrjxfjjc\app\claude.exe"
    ));
    assert!(real(lc, any));
    assert!(real(
        lc,
        r"C:\Program Files\WindowsApps\Other_1.0.0.0_x64__pzs8sxrjxfjjc\app\other.exe"
    ));
    // A WindowsApps-looking folder elsewhere is not a package.
    assert!(real(
        lc,
        r"C:\Users\azka\Program Files\WindowsApps\Claude_3.1623.0.0_x64__pzs8sxrjxfjjc\claude.exe"
    ));
}

// ---------------------------------------- 5. benign-downgraded ST-04 is Low

#[test]
fn benign_audit_st04_has_low_severity() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_benign_audit_low.jsonl", mode);
        let st04: Vec<_> = alerts(&out)
            .into_iter()
            .filter(|d| d.alert.rule_id == "ST-04")
            .collect();
        assert_eq!(st04.len(), 2, "{mode:?}: {}", dump(&out));
        for d in st04 {
            assert_eq!(d.alert.severity, Severity::Low, "{}", dump(&out));
            assert_eq!(d.alert.mode, RuleMode::Audit);
        }
        no_actions(&out);
    }
}

// ------------------------------------------- 6. per-user VS Code and WAM

#[test]
fn per_user_vscode_wam_then_microsoft_telemetry_is_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_vscode_peruser_wam_benign.jsonl", mode);
        let st01 = first(&out, "ST-01");
        assert_eq!(st01.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st01.alert.mode, RuleMode::Audit);
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st04.alert.mode, RuleMode::Audit);
        assert!(st04
            .alert
            .summary
            .contains("mobile.events.data.microsoft.com"));
        no_actions(&out);
    }
}

#[test]
fn per_user_vscode_wam_then_unknown_address_gets_the_full_response() {
    let out = run("ws_vscode_peruser_wam_exfil.jsonl", RuleMode::Protect);
    let st04 = first(&out, "ST-04");
    assert_eq!(st04.alert.mode, RuleMode::Protect);
    assert_eq!(st04.alert.severity, Severity::Critical);
    assert!(has_kill_of(st04, "nodesvc"), "{}", dump(&out));
}

fn wam_then_send(
    image: &str,
    cmd: &str,
    signed: SignatureState,
    signer: Option<&str>,
    host: &str,
) -> Vec<Output> {
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(0, "r", 10, image, cmd, None, signed, signer));
    let mut out = e.process(&read(
        10,
        "r",
        10,
        r"C:\Users\azka\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres",
    ));
    let mut c = connect(20, "r", 10, "20.50.201.206", 443);
    if let EventData::NetConnect { dst_host, .. } = &mut c.data {
        *dst_host = Some(host.into());
    }
    out.extend(e.process(&c));
    out
}

#[test]
fn wam_allowance_is_bound_to_microsoft_signers_and_endpoints() {
    let code = r"C:\Users\azka\AppData\Local\Programs\Microsoft VS Code\Code.exe";
    let ms = Some("Microsoft Corporation");
    // Allowed: Microsoft endpoints.
    for host in [
        "mobile.events.data.microsoft.com",
        "login.microsoftonline.com",
        "default.exp-tas.com",
        "main.vscode-cdn.net",
        "login.live.com",
    ] {
        let out = wam_then_send(code, "Code.exe", SignatureState::Valid, ms, host);
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.mode, RuleMode::Audit, "{host}: {}", dump(&out));
        assert_eq!(st04.alert.severity, Severity::Low);
    }
    // Full response: other or customer-controlled destinations, other
    // signers, unsigned, scripts, Temp copies.
    for (img, cmd, sig, signer, host) in [
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "evilstore.blob.core.windows.net",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "x.eastus.cloudapp.azure.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "microsoft.com.evil.net",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "api.telegram.org",
        ),
        // Review H1: tenant-hostable Microsoft services.
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "evil-my.sharepoint.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "graph.microsoft.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            ms,
            "onedrive.live.com",
        ),
        (code, "Code.exe", SignatureState::Valid, ms, "dev.azure.com"),
        // Review H2: a Microsoft-signed binary renamed into the profile.
        (
            r"C:\Users\azka\AppData\Local\x\teamsupd.exe",
            "teamsupd.exe -c x",
            SignatureState::Valid,
            Some("Microsoft Windows"),
            "login.live.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Valid,
            Some("Evil Ltd"),
            "login.live.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Unsigned,
            None,
            "login.live.com",
        ),
        (
            code,
            "Code.exe",
            SignatureState::Invalid,
            ms,
            "login.live.com",
        ),
        (
            code,
            r"Code.exe C:\Users\azka\AppData\Local\Temp\p.js",
            SignatureState::Valid,
            ms,
            "login.live.com",
        ),
        (
            r"C:\Users\azka\AppData\Local\Temp\Code.exe",
            "Code.exe",
            SignatureState::Valid,
            ms,
            "login.live.com",
        ),
        (
            r"C:\Users\azka\AppData\Local\Programs\node\node.exe",
            "node.exe x",
            SignatureState::Valid,
            ms,
            "login.live.com",
        ),
    ] {
        let out = wam_then_send(img, cmd, sig, signer, host);
        let st04 = first(&out, "ST-04");
        assert_eq!(
            st04.alert.mode,
            RuleMode::Protect,
            "{img} {cmd} {host}: {}",
            dump(&out)
        );
        assert!(has_kill_of(st04, "r"), "{img} {cmd} {host}: {}", dump(&out));
    }
}

// --------------------------------------------------------- 7. WebView2

#[test]
fn app_opening_its_own_webview2_is_hosting() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_webview2_host_benign.jsonl", mode);
        assert_eq!(count(&out, "ST-07"), 0, "{mode:?}: {}", dump(&out));
    }
}

#[test]
fn opening_a_real_browser_keeps_st07() {
    let out = run("ws_webview2_real_browser.jsonl", RuleMode::Protect);
    let st07 = first(&out, "ST-07");
    assert_eq!(st07.alert.severity, Severity::Critical);
    assert!(has_kill_of(st07, "whatsapp"), "{}", dump(&out));
}

#[test]
fn webview2_of_another_app_or_with_a_browser_profile_keeps_st07() {
    let wv = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\155.0.4283.62\msedgewebview2.exe";
    let host_app = r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe";
    let ms = Some("Microsoft Corporation");
    let access = |src: &str, target_guid: &str, pid: u32| {
        ev(
            1000,
            src,
            if src == "app" { 31000 } else { 40000 },
            EventData::ProcessAccess(TargetProcess {
                target_pid: pid,
                target_guid: Some(g(target_guid)),
                target_image: wv.into(),
                granted_access: 0x1f0fff,
                return_code: 0,
            }),
        )
    };
    // (webview command line, opener) -> ST-07 expected
    for (cmd, opener) in [
        // an unrelated unsigned tool opening WhatsApp's WebView2
        (format!("\"{wv}\" --embedded-browser-webview=1 --webview-exe-name=WhatsApp.Root.exe"), "tool"),
        // the host's own WebView2 pointed at the real Edge profile
        (format!("\"{wv}\" --embedded-browser-webview=1 --webview-exe-name=WhatsApp.Root.exe --user-data-dir=\"C:\\Users\\azka\\AppData\\Local\\Microsoft\\Edge\\User Data\""), "app"),
        // under remote control
        (format!("\"{wv}\" --embedded-browser-webview=1 --webview-exe-name=WhatsApp.Root.exe --remote-debugging-port=9222"), "app"),
    ] {
        let mut e = engine(policy_all(RuleMode::Protect));
        e.process(&start(0, "app", 31000, host_app, "WhatsApp.Root.exe", None, SignatureState::Unsigned, None));
        e.process(&start(1, "tool", 40000, r"C:\Users\azka\AppData\Local\Temp\t.exe", "t.exe", None, SignatureState::Unsigned, None));
        e.process(&start(2, "wv", 31832, wv, &cmd, Some(("app", 31000)), SignatureState::Valid, ms));
        let out = e.process(&access(opener, "wv", 31832));
        assert_eq!(count(&out, "ST-07"), 1, "{cmd} by {opener}: {}", dump(&out));
    }
    // A renderer naming another host is not this app's.
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "app",
        31000,
        host_app,
        "WhatsApp.Root.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        1,
        "other",
        50000,
        r"C:\Program Files\Teams\ms-teams.exe",
        "ms-teams.exe",
        None,
        SignatureState::Valid,
        ms,
    ));
    e.process(&start(
        2,
        "wv",
        31832,
        wv,
        &format!("\"{wv}\" --type=renderer --webview-exe-name=ms-teams.exe"),
        Some(("other", 50000)),
        SignatureState::Valid,
        ms,
    ));
    let out = e.process(&access("app", "wv", 31832));
    assert_eq!(count(&out, "ST-07"), 1, "{}", dump(&out));
}

// -------------------------------------------------------------- 8. SSH

#[test]
fn git_for_windows_ssh_owns_the_ssh_keys() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_ssh_git_benign.jsonl", mode);
        assert!(alerts(&out).is_empty(), "{mode:?}: {}", dump(&out));
    }
}

#[test]
fn ssh_copy_in_temp_reading_id_rsa_still_fires() {
    let out = run("ws_ssh_copy_malicious.jsonl", RuleMode::Protect);
    assert_eq!(first(&out, "ST-01").alert.severity, Severity::High);
    let st04 = first(&out, "ST-04");
    assert!(has_kill_of(st04, "ssh-copy"), "{}", dump(&out));
}

#[test]
fn ssh_owner_scope() {
    let key = r"C:\Users\azka\.ssh\id_ed25519";
    let owner = |img: &str, cmd: &str, sig: SignatureState| {
        let mut e = engine(Policy::default());
        e.process(&start(0, "s", 10, img, cmd, None, sig, None));
        count(&e.process(&read(10, "s", 10, key)), "ST-01") == 0
    };
    let u = SignatureState::Unsigned;
    assert!(owner(
        r"C:\Program Files\Git\usr\bin\ssh.exe",
        "ssh git@github.com",
        u
    ));
    assert!(owner(
        r"C:\Program Files\Git\usr\bin\ssh-add.exe",
        "ssh-add",
        u
    ));
    assert!(owner(
        r"C:\Program Files\OpenSSH\ssh-agent.exe",
        "ssh-agent",
        u
    ));
    assert!(owner(r"C:\Program Files\PuTTY\pageant.exe", "pageant", u));
    assert!(owner(r"C:\Windows\System32\OpenSSH\scp.exe", "scp a b:", u));
    // Not owners.
    assert!(!owner(
        r"C:\Program Files\Git\usr\bin\ssh.exe",
        "ssh -o ProxyCommand=\"powershell -c iex\" x",
        u
    ));
    assert!(!owner(
        r"C:\Program Files\Git\usr\bin\ssh.exe",
        "ssh -oLocalCommand=calc -oPermitLocalCommand=yes x",
        u
    ));
    assert!(!owner(
        r"C:\Program Files\Git\usr\bin\x\ssh.exe",
        "ssh x",
        u
    ));
    assert!(!owner(r"C:\Program Files\Git\usr\bin\bash.exe", "bash", u));
    assert!(!owner(r"D:\Program Files\Git\usr\bin\ssh.exe", "ssh x", u));
    assert!(!owner(r"C:\Users\azka\Downloads\ssh.exe", "ssh x", u));
    assert!(!owner(
        r"C:\Users\azka\AppData\Local\Programs\Git\usr\bin\ssh.exe",
        "ssh x",
        u
    ));
    assert!(!owner(
        r"C:\Program Files\Git\usr\bin\..\..\..\..\Users\azka\ssh.exe",
        "ssh x",
        u
    ));
}

// ----------------------------------------------------- 9. Steam config.vdf

#[test]
fn nvidia_reading_steam_config_vdf_is_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_steam_nvidia_benign.jsonl", mode);
        let st01 = first(&out, "ST-01");
        assert_eq!(st01.alert.severity, Severity::Low, "{}", dump(&out));
        let st04 = first(&out, "ST-04");
        assert_eq!(st04.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st04.alert.mode, RuleMode::Audit);
        no_actions(&out);
    }
}

#[test]
fn steam_secrets_still_fire() {
    let out = run("ws_steam_stealer_malicious.jsonl", RuleMode::Protect);
    assert_eq!(first(&out, "ST-01").alert.severity, Severity::High);
    assert!(has_kill_of(first(&out, "ST-04"), "st"), "{}", dump(&out));
    // The signed NVIDIA service reading an ssfn file is not covered.
    let mut e = engine(Policy::default());
    e.process(&start(
        0,
        "nv",
        10,
        r"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe",
        "nvcontainer.exe",
        None,
        SignatureState::Valid,
        Some("NVIDIA Corporation"),
    ));
    let out = e.process(&read(
        10,
        "nv",
        10,
        r"C:\Program Files (x86)\Steam\ssfn1234",
    ));
    assert_eq!(
        first(&out, "ST-01").alert.severity,
        Severity::Medium,
        "{}",
        dump(&out)
    );
}

// ---------------------------------------------------------------- 10. CD-06

#[test]
fn signed_services_refused_read_only_lsass_opens_are_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_cd06_signed_services_benign.jsonl", mode);
        assert!(count(&out, "CD-06") >= 2, "{}", dump(&out));
        for d in alerts(&out) {
            assert_eq!(d.alert.rule_id, "CD-06", "{}", dump(&out));
            assert_eq!(d.alert.severity, Severity::Low);
            assert_eq!(d.alert.mode, RuleMode::Audit);
        }
        no_actions(&out);
    }
}

#[test]
fn unsigned_or_dangerous_lsass_attempts_keep_their_severity() {
    let out = run("ws_cd06_unsigned_malicious.jsonl", RuleMode::Protect);
    let cd06 = first(&out, "CD-06");
    assert_eq!(cd06.alert.severity, Severity::High);
    assert_eq!(cd06.alert.mode, RuleMode::Protect, "{}", dump(&out));
    // A signed Program Files service asking for more than read access.
    let lsass_ev = fixture("ws_cd06_signed_services_benign.jsonl");
    for (mask, rc, rule) in [
        (0x1f0fff_u32, 0xC0000022_u32, "CD-06"),
        (0x1410 | 0x40, 0xC0000022, "CD-06"),
        (0x1438, 0xC0000022, "CD-06"),
    ] {
        let mut e = engine(Policy::default());
        replay(&mut e, &lsass_ev[..6]);
        let out = e.process(&ev(
            5000,
            "nv",
            47548,
            EventData::ProcessAccess(TargetProcess {
                target_pid: 624,
                target_guid: Some(g("lsass")),
                target_image: r"C:\Windows\System32\lsass.exe".into(),
                granted_access: mask,
                return_code: rc,
            }),
        ));
        let d = first(&out, rule);
        assert_eq!(
            d.alert.severity,
            Severity::High,
            "{mask:#x}: {}",
            dump(&out)
        );
    }
}

// --------------------------------------------------------- 11. ST-14 WSL

#[test]
fn wsl_dns_proxy_lookups_are_low_audit() {
    for mode in [RuleMode::Audit, RuleMode::Protect] {
        let out = run("ws_st14_wsl_benign.jsonl", mode);
        let st14 = first(&out, "ST-14");
        assert_eq!(st14.alert.severity, Severity::Low, "{}", dump(&out));
        assert_eq!(st14.alert.mode, RuleMode::Audit);
        assert!(st14
            .alert
            .summary
            .contains("on behalf of a process inside WSL"));
        no_actions(&out);
    }
}

#[test]
fn fake_wslservice_lookup_keeps_st14() {
    let out = run("ws_st14_fake_wsl_malicious.jsonl", RuleMode::Protect);
    let st14 = first(&out, "ST-14");
    assert_eq!(st14.alert.severity, Severity::High);
    assert!(!st14.actions.is_empty(), "{}", dump(&out));
}

// -------------------------------------------- 12. Low / Info aggregation

#[test]
fn low_audit_alerts_are_aggregated_per_image_and_object_per_day() {
    let word = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE";
    let tbres = r"C:\Users\azka\AppData\Local\Microsoft\TokenBroker\Cache\x.tbres";
    let ms = Some("Microsoft Corporation");
    let mut e = engine(Policy::default());
    let mut n = 0;
    for i in 0..5u32 {
        let guid = format!("w{i}");
        e.process(&start(
            i as i64 * 1000,
            &guid,
            100 + i,
            word,
            "WINWORD.EXE",
            None,
            SignatureState::Valid,
            ms,
        ));
        n += count(
            &e.process(&read(i as i64 * 1000 + 10, &guid, 100 + i, tbres)),
            "ST-01",
        );
    }
    assert_eq!(
        n, 1,
        "five Word processes reading the same cache file: one alert"
    );
    // Another file is another object.
    e.process(&start(
        9000,
        "w9",
        199,
        word,
        "WINWORD.EXE",
        None,
        SignatureState::Valid,
        ms,
    ));
    let other = r"C:\Users\azka\AppData\Local\Microsoft\TokenBroker\Cache\y.tbres";
    assert_eq!(count(&e.process(&read(9010, "w9", 199, other)), "ST-01"), 1);
    // After 24 h the next one alerts and reports the folded repeats.
    e.process(&start(
        DAY + 1,
        "wn",
        300,
        word,
        "WINWORD.EXE",
        None,
        SignatureState::Valid,
        ms,
    ));
    let out = e.process(&read(DAY + 10, "wn", 300, tbres));
    let st01 = first(&out, "ST-01");
    assert!(
        st01.alert.summary.contains("folded 4 more times"),
        "{}",
        dump(&out)
    );
}

#[test]
fn aggregation_never_hides_medium_or_higher() {
    // An unsigned reader (High ST-01) from many processes of the same image.
    let img = r"C:\Users\azka\AppData\Local\Temp\s.exe";
    let mut e = engine(Policy::default());
    let mut n = 0;
    for i in 0..3u32 {
        let guid = format!("s{i}");
        e.process(&unsigned_start(
            i as i64 * 1000,
            &guid,
            100 + i,
            img,
            Some(&"77".repeat(32)),
        ));
        n += count(
            &e.process(&read(i as i64 * 1000 + 10, &guid, 100 + i, CHROME_LOGIN)),
            "ST-01",
        );
    }
    assert_eq!(n, 3);
}

// ------------------------------------------- hostile review follow-ups

#[test]
fn review_h3_unsigned_tool_with_its_own_webview2_keeps_st07() {
    let wv = r"C:\Program Files (x86)\Microsoft\EdgeWebView\Application\155.0.4283.62\msedgewebview2.exe";
    let mut e = engine(policy_all(RuleMode::Protect));
    e.process(&start(
        0,
        "tool",
        40000,
        r"C:\Users\azka\AppData\Local\Temp\t.exe",
        "t.exe",
        None,
        SignatureState::Unsigned,
        None,
    ));
    e.process(&start(
        1,
        "wv",
        41000,
        wv,
        &format!("\"{wv}\" --embedded-browser-webview=1 --webview-exe-name=t.exe"),
        Some(("tool", 40000)),
        SignatureState::Valid,
        Some("Microsoft Corporation"),
    ));
    let mut out = Vec::new();
    for data in [
        EventData::ProcessAccess(TargetProcess {
            target_pid: 41000,
            target_guid: Some(g("wv")),
            target_image: wv.into(),
            granted_access: 0x1f0fff,
            return_code: 0,
        }),
        EventData::RemoteThread(TargetProcess {
            target_pid: 41000,
            target_guid: Some(g("wv")),
            target_image: wv.into(),
            granted_access: 0,
            return_code: 0,
        }),
    ] {
        out.extend(e.process(&ev(1000, "tool", 40000, data)));
    }
    assert!(count(&out, "ST-07") >= 1, "{}", dump(&out));
}

#[test]
fn review_m3_ssh_library_and_config_options_are_not_owners() {
    let key = r"C:\Users\azka\.ssh\id_ed25519";
    let alerts_for = |img: &str, cmd: &str| {
        let mut e = engine(Policy::default());
        e.process(&start(
            0,
            "s",
            10,
            img,
            cmd,
            None,
            SignatureState::Unsigned,
            None,
        ));
        count(&e.process(&read(10, "s", 10, key)), "ST-01")
    };
    let git = r"C:\Program Files\Git\usr\bin";
    assert_eq!(
        alerts_for(&format!(r"{git}\ssh.exe"), r"ssh -I C:\Users\azka\p.dll x"),
        1
    );
    assert_eq!(
        alerts_for(
            &format!(r"{git}\ssh.exe"),
            r"ssh -F C:\Users\azka\AppData\Local\Temp\c x"
        ),
        1
    );
    assert_eq!(
        alerts_for(&format!(r"{git}\ssh-add.exe"), r"ssh-add -s C:\x\p.dll"),
        1
    );
    assert_eq!(
        alerts_for(&format!(r"{git}\ssh-keygen.exe"), r"ssh-keygen -D p.dll"),
        1
    );
    // Ordinary use stays silent: identity file, SOCKS forward, sftp subsystem.
    assert_eq!(
        alerts_for(
            &format!(r"{git}\ssh.exe"),
            r"ssh -i C:\Users\azka\.ssh\id_ed25519 -D 1080 x"
        ),
        0
    );
    assert_eq!(
        alerts_for(&format!(r"{git}\ssh.exe"), "ssh -oForwardX11 no -s x sftp"),
        0
    );
}
