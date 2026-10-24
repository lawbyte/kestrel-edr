//! Evidence capture: bundle building (limits, skips, seal + container round
//! trip) and the agent flow with `SimPlatform` (alert → capture → Ready
//! report → CollectEvidence → tray notice → EvidenceRead upload →
//! DeleteEvidence), upload refusals, privacy and retention.

use crate::agent::{self, AgentHandle, Core, Tuning};
use crate::config::AgentConfig;
use crate::evidence::{bundles_dir, IndexEntry, KV_EVIDENCE_INDEX};
use crate::evidence_bundle::{build_bundle, bundle_path, open_bundle, BundleInput, Limits};
use crate::proto::AgentEnvelope;
use crate::sim::{SimOptions, SimPlatform, SIM_USER};
use crate::sim_evidence::{minimal_pcapng, SimEvidence, SIM_LOCKED_SUFFIX};
use base64::Engine as _;
use kestrel_common::evidence::{
    container::{read_container, ContainerLimits},
    sha256_hex, CopyStatus, EvidencePolicy, EvidenceReport, EvidenceState, PcapInfo, PcapStatus,
    SecretRead, TRAY_COLLECTED_TITLE,
};
use kestrel_common::remote::{FileReply, LiveAgentMsg, LiveServerMsg, RemoteErrorCode};
use kestrel_common::wire::AgentPayload;
use kestrel_common::{ActionOutcome, DataCategory, Policy, ProcessGuid, ResponseAction, RuleMode};
use kestrel_detect::evidence::{JournalSnapshot, StagedCandidate};
use kestrel_platform::{
    ActionOrigin, CapturedFile, EvidenceHost, SourceError, SourceFile, WriteHint,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use uuid::Uuid;

// ----------------------------------------------------------- builder tests

fn put(sim: &SimEvidence, win: &str, data: &[u8]) -> PathBuf {
    let p = sim.map(win).unwrap();
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, data).unwrap();
    p
}

fn cand(path: &str, ts: i64) -> StagedCandidate {
    StagedCandidate {
        path: path.into(),
        written_at: ts,
        op: kestrel_common::evidence::WriteOp::Created,
        guid: ProcessGuid("g".into()),
        image: r"C:\Users\a\AppData\Local\Temp\x.exe".into(),
        confirmed: true,
    }
}

fn secret(path: &str) -> SecretRead {
    SecretRead {
        path: path.into(),
        store: "Chrome".into(),
        noun: "saved passwords".into(),
        category: DataCategory::BrowserPasswords,
        first_read: 1,
        last_read: 2,
        open_count: 1,
        process_guid: ProcessGuid("g".into()),
        image: String::new(),
        size: None,
        copy: None,
    }
}

fn input(id: Uuid, snapshot: JournalSnapshot, limits: Limits) -> BundleInput {
    BundleInput {
        bundle_id: id,
        alert_id: Uuid::new_v4(),
        alert_ids: vec![],
        rule_id: "ST-02".into(),
        hostname: "H".into(),
        agent_version: "t".into(),
        started_at: 10,
        window_start: 0,
        window_end: 20,
        parts: EvidencePolicy::default(),
        processes: vec![],
        snapshot,
        pcap: None,
        pcap_file: None,
        limits,
        tree_user: Some(r"CORP\a".into()),
        cancel: Arc::default(),
    }
}

/// Entries of a bundle: (name, bytes).
fn entries(bytes: &[u8]) -> Vec<(String, Vec<u8>)> {
    let mut out = vec![];
    read_container(bytes, ContainerLimits::default(), |name, r| {
        let mut v = vec![];
        r.read_to_end(&mut v)?;
        out.push((name.to_string(), v));
        Ok(())
    })
    .unwrap();
    out
}

/// A host whose `grow.bin` keeps growing past its opened size.
struct Growing(SimEvidence);

impl EvidenceHost for Growing {
    fn evidence_dir(&self) -> PathBuf {
        self.0.evidence_dir()
    }
    fn bundle_key(&self) -> Result<[u8; 32], String> {
        self.0.bundle_key()
    }
    fn own_prefixes(&self) -> Vec<String> {
        self.0.own_prefixes()
    }
    fn open_source(&self, path: &str, max: u64) -> Result<SourceFile, SourceError> {
        if path.ends_with("grow.bin") {
            return Ok(SourceFile {
                reader: Box::new(std::io::repeat(7).take(10_000)),
                size: 10,
                path: path.into(),
            });
        }
        self.0.open_source(path, max)
    }
    fn file_size(&self, path: &str) -> Option<u64> {
        self.0.file_size(path)
    }
}

#[test]
fn bundle_limits_skips_and_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    let t = r"C:\Users\a\AppData\Local\Temp\st";
    put(&sim, &format!(r"{t}\a.zip"), b"PK-archive-a");
    put(&sim, &format!(r"{t}\big.bin"), &vec![1u8; 300]);
    put(&sim, &format!(r"{t}\b.txt"), &[2u8; 60]);
    put(&sim, &format!(r"{t}\c.txt"), &[3u8; 60]);
    put(&sim, r"C:\ProgramData\Kestrel\agent.log", b"kestrel own");
    let chrome = r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    let cookies = r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies";
    put(&sim, chrome, b"chrome-login-db");
    let ck = put(&sim, cookies, b"cookies-db");
    let mut lock = ck.into_os_string();
    lock.push(SIM_LOCKED_SUFFIX);
    std::fs::write(&lock, b"").unwrap();
    #[cfg(unix)]
    {
        let target = sim.map(&format!(r"{t}\a.zip")).unwrap();
        std::os::unix::fs::symlink(&target, sim.map(&format!(r"{t}\link.zip")).unwrap()).unwrap();
    }
    let staged = vec![
        cand(&format!(r"{t}\a.zip"), 9),
        cand(&format!(r"{t}\big.bin"), 8),
        cand(r"C:\ProgramData\Kestrel\agent.log", 7),
        cand(&format!(r"{t}\missing.txt"), 6),
        cand(&format!(r"{t}\a.zip:hidden"), 5),
        cand(&format!(r"{t}\link.zip"), 4),
        cand(&format!(r"{t}\grow.bin"), 3),
        cand(&format!(r"{t}\b.txt"), 2),
        cand(&format!(r"{t}\c.txt"), 1),
        cand(t, 0),
    ];
    let snap = JournalSnapshot {
        staged,
        staged_unlisted: 7,
        secrets: vec![secret(chrome), secret(cookies)],
        secrets_unlisted: 0,
        net: vec![],
        staged_evicted: 0,
        net_excluded: 0,
    };
    let limits = Limits {
        staged_file: 100,
        staged_total: 160,
        staged_files: 500,
        ..Limits::default()
    };
    let id = Uuid::new_v4();
    let host = Growing(sim);
    let mut inp = input(id, snap, limits);
    // A pcap whose plaintext file must be sealed then deleted.
    let work = dir.path().join("work");
    std::fs::create_dir_all(&work).unwrap();
    let pc = work.join("capture.pcapng");
    std::fs::write(&pc, minimal_pcapng()).unwrap();
    inp.pcap = Some(PcapInfo {
        status: PcapStatus::Captured,
        ..Default::default()
    });
    inp.pcap_file = Some(CapturedFile {
        path: pc.clone(),
        bytes: 48,
        truncated: false,
    });
    let bdir = bundles_dir(&host);
    let b = build_bundle(&host, inp, &bdir).unwrap();
    assert!(!pc.exists(), "plaintext pcap deleted");
    assert!(b.path.ends_with(format!("{id}.kev")));
    assert!(!bdir.join(format!("{id}.kev.partial")).exists());

    let st = |i: usize| b.manifest.staged[i].copy.status;
    assert_eq!(st(0), CopyStatus::Copied);
    assert_eq!(st(1), CopyStatus::TooLarge);
    assert_eq!(b.manifest.staged[1].copy.size, 300);
    assert_eq!(st(2), CopyStatus::Kestrel);
    assert_eq!(st(3), CopyStatus::Missing);
    assert_eq!(st(4), CopyStatus::Link, "ADS refused");
    #[cfg(unix)]
    assert_eq!(st(5), CopyStatus::Link, "symlink refused");
    #[cfg(not(unix))]
    assert_eq!(st(5), CopyStatus::Missing);
    // Growing file: opened at 10 bytes, cut at the per-file cap.
    assert_eq!(st(6), CopyStatus::Truncated);
    assert_eq!(b.manifest.staged[6].copy.size, 100);
    // Budget 160: a.zip (12) + grow (100) = 112; b.txt (60) does not fit.
    assert_eq!(st(7), CopyStatus::BundleFull);
    assert_eq!(st(8), CopyStatus::BundleFull);
    assert_eq!(st(9), CopyStatus::NotAFile, "a folder");
    let tot = &b.manifest.totals;
    assert_eq!(tot.staged_copied, 2);
    assert_eq!(tot.staged_bytes, 112);
    assert_eq!(tot.staged_unlisted, 7);
    assert!(
        b.manifest.notes.iter().any(|n| n.contains("7 candidate")),
        "{:?}",
        b.manifest.notes
    );
    // Secrets: Login Data copied, Cookies locked (size via file_size).
    let s0 = b.manifest.secrets[0].copy.as_ref().unwrap();
    assert_eq!(s0.status, CopyStatus::Copied);
    assert_eq!(b.manifest.secrets[0].size, Some(15));
    let s1 = b.manifest.secrets[1].copy.as_ref().unwrap();
    assert_eq!(s1.status, CopyStatus::Locked);
    assert_eq!(b.manifest.secrets[1].size, Some(10));
    assert!(b.manifest.notes.iter().any(|n| n.contains("locked")));
    let pcap = b.manifest.pcap.as_ref().unwrap();
    assert_eq!(pcap.entry.as_deref(), Some("capture.pcapng"));
    assert_eq!(pcap.bytes, 48);

    // Seal + container round trip with the right key and context.
    let key = host.bundle_key().unwrap();
    let bytes = open_bundle(&b.path, &key, id).unwrap();
    assert_eq!(bytes.len() as u64, b.size);
    assert_eq!(sha256_hex(&bytes), b.sha256);
    let e = entries(&bytes);
    let names: Vec<&str> = e.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "staged/0001-a.zip",
            "staged/0007-grow.bin",
            "secrets/0001-Login_Data",
            "capture.pcapng",
            "manifest.json"
        ]
    );
    assert_eq!(e[0].1, b"PK-archive-a");
    assert_eq!(e[1].1.len(), 100);
    assert_eq!(e[2].1, b"chrome-login-db");
    assert_eq!(e[3].1, minimal_pcapng());
    let m: kestrel_common::evidence::EvidenceManifest = serde_json::from_slice(&e[4].1).unwrap();
    assert_eq!(m, b.manifest, "manifest last and complete");
    assert_eq!(
        b.manifest.staged[0].copy.sha256.as_deref(),
        Some(sha256_hex(b"PK-archive-a").as_str())
    );
    // Wrong key / wrong bundle id never open.
    assert!(open_bundle(&b.path, &[0u8; 32], id).is_err());
    assert!(open_bundle(&b.path, &key, Uuid::new_v4()).is_err());
}

#[test]
fn bundle_file_cap_and_disabled_parts() {
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    let mut staged = vec![];
    for i in 0..5 {
        let p = format!(r"C:\Users\a\Downloads\f{i}.txt");
        put(&sim, &p, b"x");
        staged.push(cand(&p, 10 - i));
    }
    let chrome = r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    put(&sim, chrome, b"0123456789");
    let snap = JournalSnapshot {
        staged,
        secrets: vec![secret(chrome)],
        ..Default::default()
    };
    let id = Uuid::new_v4();
    let mut inp = input(
        id,
        snap.clone(),
        Limits {
            staged_files: 3,
            ..Limits::default()
        },
    );
    inp.parts.secrets_copy = false;
    let b = build_bundle(&sim, inp, &bundles_dir(&sim)).unwrap();
    let full = b
        .manifest
        .staged
        .iter()
        .filter(|s| s.copy.status == CopyStatus::BundleFull)
        .count();
    assert_eq!((b.manifest.totals.staged_copied, full), (3, 2));
    // secrets_copy off: listed, size known, no copy.
    assert_eq!(b.manifest.secrets[0].copy, None);
    assert_eq!(b.manifest.secrets[0].size, Some(10));
    let key = sim.bundle_key().unwrap();
    let e = entries(&open_bundle(&b.path, &key, id).unwrap());
    assert!(!e.iter().any(|(n, _)| n.starts_with("secrets/")));

    // Everything but pcap off: nothing listed.
    let id2 = Uuid::new_v4();
    let mut inp = input(id2, snap, Limits::default());
    inp.parts = EvidencePolicy {
        pcap: true,
        ..EvidencePolicy::off()
    };
    let b = build_bundle(&sim, inp, &bundles_dir(&sim)).unwrap();
    assert!(b.manifest.staged.is_empty() && b.manifest.secrets.is_empty());
    let e = entries(&open_bundle(&b.path, &key, id2).unwrap());
    assert_eq!(e.len(), 1);
}

#[test]
fn sim_host_stays_in_its_sandbox() {
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    for bad in [
        r"\\server\share\x",
        r"\\?\C:\x",
        "relative\\x",
        r"C:\a\..\..\x",
        "",
    ] {
        assert!(sim.open_source(bad, 10).is_err(), "{bad}");
    }
    assert!(matches!(
        sim.open_source(r"C:\x\a.txt:stream", 10),
        Err(SourceError::Link(_))
    ));
    let p = put(&sim, r"C:\Users\a\Downloads\x.bin", &[0u8; 20]);
    assert!(p.starts_with(dir.path()));
    assert!(matches!(
        sim.open_source(r"C:\Users\a\Downloads\x.bin", 10),
        Err(SourceError::TooLarge(20))
    ));
    assert!(matches!(
        sim.open_source(r"C:\Users\a\Downloads", 10),
        Err(SourceError::NotAFile)
    ));
    assert_eq!(sim.bundle_key().unwrap(), sim.bundle_key().unwrap());
}

// ------------------------------------------------------------- agent flow

const STEALER: &str = "057a58fbc46027bba057e481acd9b139";
const ZIP: &str = r"C:\ProgramData\XGBKJDHJKFHIJKDH\8E3K2LQZ.zip";
const LOGIN: &str = r"C:\Users\j.doe\AppData\Local\Google\Chrome\User Data\Default\Login Data";
const FIREFOX: &str =
    r"C:\Users\j.doe\AppData\Roaming\Mozilla\Firefox\Profiles\x8k2m1qa.default-release\logins.json";
const HINT: &str = r"C:\Users\j.doe\AppData\Local\Temp\hint-secret-dir\screen.png";

fn tuning() -> Tuning {
    Tuning {
        heartbeat: Duration::from_millis(500),
        tick: Duration::from_millis(50),
        housekeeping: Duration::from_millis(200),
        batch_max_delay: Duration::from_millis(100),
        evidence_follow: Duration::from_millis(1500),
        evidence_read_idle: Duration::from_secs(5),
        ..Tuning::default()
    }
}

fn setup(state: &Path, policy: Option<Policy>) {
    let cfg = AgentConfig {
        server: "127.0.0.1:9".into(),
        hostname: Some("SIM-EVIDENCE".into()),
        ..AgentConfig::default()
    };
    cfg.save(state).unwrap();
    if let Some(p) = policy {
        let st = crate::store::Store::open(state).unwrap();
        st.kv_set_json(crate::store::KV_POLICY, &p).unwrap();
    }
}

async fn start(state: &Path, replay: Option<&str>) -> (AgentHandle, Arc<SimPlatform>) {
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: replay.map(|f| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("replays")
                .join(f)
        }),
        speed: 50.0,
        hostname: "SIM-EVIDENCE".into(),
        user: SIM_USER.into(),
    }));
    let h = agent::start(sim.clone(), state.to_path_buf(), tuning())
        .await
        .unwrap();
    (h, sim)
}

fn outbox(core: &Core) -> Vec<AgentPayload> {
    core.store
        .pending_after(0, 100_000)
        .unwrap()
        .into_iter()
        .map(|r| crate::codec::decode::<AgentPayload>(&r.payload, r.compressed).unwrap())
        .collect()
}

fn reports(core: &Core) -> Vec<EvidenceReport> {
    outbox(core)
        .into_iter()
        .filter_map(|p| match p {
            AgentPayload::Evidence(r) => Some(*r),
            _ => None,
        })
        .collect()
}

async fn wait_for(what: &str, secs: u64, mut f: impl FnMut() -> bool) {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !f() {
        assert!(
            tokio::time::Instant::now() < end,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn result_of(core: &Core, id: Uuid) -> Option<ActionOutcome> {
    outbox(core).into_iter().find_map(|p| match p {
        AgentPayload::ActionResult {
            command_id,
            outcome,
        } if command_id == id => Some(outcome),
        _ => None,
    })
}

async fn read(
    core: &Arc<Core>,
    rx: &mut mpsc::Receiver<AgentEnvelope>,
    session: Uuid,
    request_id: u64,
    bundle_id: Uuid,
    offset: u64,
    len: u32,
) -> FileReply {
    crate::transport::route_live(
        core,
        session,
        LiveServerMsg::EvidenceRead {
            request_id,
            bundle_id,
            offset,
            len,
        },
    );
    let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("no evidence reply")
        .expect("stream closed");
    assert_eq!(env.seq, 0, "live replies are ephemeral");
    match crate::codec::decode::<AgentPayload>(&env.payload, env.compressed).unwrap() {
        AgentPayload::Live {
            session_id,
            msg:
                LiveAgentMsg::EvidenceData {
                    request_id: r,
                    reply,
                },
        } => {
            assert_eq!((session_id, r), (session, request_id));
            reply
        }
        other => panic!("unexpected {other:?}"),
    }
}

fn err_code(r: &FileReply) -> Option<RemoteErrorCode> {
    match r {
        FileReply::Error { code, .. } => Some(*code),
        _ => None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stealer_alert_to_collected_upload_and_delete() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let mut policy = Policy {
        version: 3,
        ..Policy::default()
    };
    policy.privacy.redact_path_prefixes = vec![r"C:\Users\j.doe\AppData\Roaming\Mozilla".into()];
    // Containment does not matter here; keep the replay's processes alive.
    for r in ["ST-02", "ST-04"] {
        policy.rules.insert(r.into(), RuleMode::Audit);
    }
    setup(state, Some(policy));
    // Files the stealer staged / read, in the simulator's sandbox.
    let sim_fs = SimEvidence::new(state.to_path_buf());
    put(&sim_fs, ZIP, b"PK\x03\x04 loot archive content");
    put(&sim_fs, LOGIN, b"chrome-secret-content-XYZ");
    put(&sim_fs, FIREFOX, b"{\"logins\":\"firefox-secret\"}");
    put(&sim_fs, HINT, b"screenshot-bytes");

    let (h, sim) = start(state, Some("vidar_smash_grab.jsonl")).await;
    let core = h.core.clone();
    // A sensor write hint for the stealer (never an event).
    wait_for("sensors", 5, || {
        sim.send_write_hint(WriteHint {
            ts: kestrel_common::now_ms(),
            pid: 10244,
            guid: ProcessGuid(STEALER.into()),
            path: HINT.into(),
            op: kestrel_common::evidence::WriteOp::Created,
        })
    })
    .await;

    wait_for("a ready bundle", 30, || {
        reports(&core)
            .iter()
            .any(|r| r.state == EvidenceState::Ready)
    })
    .await;
    let rs = reports(&core);
    assert_eq!(rs[0].state, EvidenceState::Capturing);
    let ready = rs
        .iter()
        .find(|r| r.state == EvidenceState::Ready)
        .unwrap()
        .clone();
    assert!(
        rs.iter()
            .filter(|r| r.state == EvidenceState::Capturing)
            .count()
            == 1,
        "ST-02 + ST-04 of one tree make one bundle: {rs:?}"
    );
    let id = ready.bundle_id;
    assert!(["ST-02", "ST-04"].contains(&ready.rule_id.as_str()));
    let m = ready.manifest.clone().unwrap();
    let staged = |p: &str| m.staged.iter().find(|s| s.path == p).cloned();
    assert_eq!(
        staged(ZIP).unwrap().copy.status,
        CopyStatus::Copied,
        "{:?}",
        m.staged
    );
    assert_eq!(staged(HINT).unwrap().copy.status, CopyStatus::Copied);
    let login = m.secrets.iter().find(|s| s.path == LOGIN).unwrap();
    assert_eq!(login.copy.as_ref().unwrap().status, CopyStatus::Copied);
    // Privacy: the redacted prefix is gone from the reported manifest.
    let json = serde_json::to_string(&ready).unwrap();
    assert!(!json.contains("Mozilla"), "{json}");
    assert!(m.secrets.iter().any(|s| s.path == crate::privacy::REDACTED));
    // Never content in a report.
    for secret in [
        "chrome-secret-content",
        "firefox-secret",
        "loot archive",
        "screenshot-bytes",
    ] {
        assert!(!json.contains(secret));
    }
    // Packet capture ran with the tree's remote addresses.
    let starts = sim.sim_evidence().pcap().starts();
    assert_eq!(starts.len(), 1, "{starts:?}");
    assert!(
        starts[0].iter().any(|f| f.ip == "203.0.113.19"),
        "{starts:?}"
    );
    assert_eq!(m.pcap.as_ref().unwrap().status, PcapStatus::Captured);
    // The hint path never went into telemetry.
    for p in outbox(&core) {
        if !matches!(p, AgentPayload::Evidence(_)) {
            let s = serde_json::to_string(&p).unwrap();
            assert!(!s.contains("hint-secret-dir"), "{s}");
        }
    }
    let bundle_file = bundle_path(&bundles_dir(&*sim.sim_evidence()), id);
    assert!(bundle_file.exists());

    // Live stream for the upload.
    let (tx, mut rx) = mpsc::channel::<AgentEnvelope>(64);
    let gen = core.live.attach(tx);

    // Not collected yet: refused.
    let s0 = Uuid::new_v4();
    let r = read(&core, &mut rx, s0, 1, id, 0, 4096).await;
    assert_eq!(err_code(&r), Some(RemoteErrorCode::NotFound));

    // Collect: only as a server command.
    let o = core
        .execute_action_as(
            &ResponseAction::CollectEvidence { bundle_id: id },
            ActionOrigin::Engine,
        )
        .await;
    assert!(!o.ok);
    let o = core
        .execute_action_as(
            &ResponseAction::CollectEvidence { bundle_id: id },
            ActionOrigin::Local,
        )
        .await;
    assert!(!o.ok);
    let cmd = Uuid::new_v4();
    core.run_command(cmd, ResponseAction::CollectEvidence { bundle_id: id })
        .await;
    let o = result_of(&core, cmd).unwrap();
    assert!(o.ok, "{o:?}");
    assert_eq!(o.artifact.as_deref(), Some(id.to_string().as_str()));
    assert_eq!(
        o.detail,
        format!("bundle ready for upload ({} bytes)", ready.bundle_size)
    );
    let acts = core.store.activity(50).unwrap();
    assert!(
        acts.iter().any(|a| a.title == TRAY_COLLECTED_TITLE),
        "{acts:?}"
    );
    let unknown = core
        .execute_action_as(
            &ResponseAction::CollectEvidence {
                bundle_id: Uuid::new_v4(),
            },
            ActionOrigin::ServerCommand,
        )
        .await;
    assert!(!unknown.ok);

    // Out-of-order first read refused.
    let s1 = Uuid::new_v4();
    let r = read(&core, &mut rx, s1, 1, id, 5, 4096).await;
    assert_eq!(err_code(&r), Some(RemoteErrorCode::InvalidOperation));

    // A session that skips ahead is refused (and ends).
    let s2 = Uuid::new_v4();
    let r = read(&core, &mut rx, s2, 1, id, 0, 100).await;
    assert!(
        matches!(
            r,
            FileReply::Data {
                offset: 0,
                eof: false,
                ..
            }
        ),
        "{r:?}"
    );
    let r = read(&core, &mut rx, s2, 2, id, 500, 100).await;
    assert_eq!(err_code(&r), Some(RemoteErrorCode::InvalidOperation));

    // Pipelined reads (the server keeps up to 4 in flight) are served in
    // arrival order; reads queued behind an error still get a reply.
    let s5 = Uuid::new_v4();
    for (i, off) in [0u64, 100, 200, 999_999, 300].iter().enumerate() {
        crate::transport::route_live(
            &core,
            s5,
            LiveServerMsg::EvidenceRead {
                request_id: 100 + i as u64,
                bundle_id: id,
                offset: *off,
                len: 100,
            },
        );
    }
    let mut replies = vec![];
    for _ in 0..5 {
        let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        match crate::codec::decode::<AgentPayload>(&env.payload, env.compressed).unwrap() {
            AgentPayload::Live {
                msg: LiveAgentMsg::EvidenceData { request_id, reply },
                ..
            } => replies.push((request_id, reply)),
            other => panic!("{other:?}"),
        }
    }
    let ids: Vec<u64> = replies.iter().map(|r| r.0).collect();
    assert_eq!(ids, [100, 101, 102, 103, 104]);
    for (i, (_, r)) in replies.iter().take(3).enumerate() {
        assert!(
            matches!(r, FileReply::Data { offset, eof: false, .. } if *offset == i as u64 * 100),
            "{r:?}"
        );
    }
    assert_eq!(
        err_code(&replies[3].1),
        Some(RemoteErrorCode::InvalidOperation)
    );
    assert_eq!(
        err_code(&replies[4].1),
        Some(RemoteErrorCode::InvalidOperation)
    );

    // Full sequential upload in odd-sized chunks.
    let s3 = Uuid::new_v4();
    let mut got = Vec::new();
    let mut req = 1;
    let sha = loop {
        let r = read(&core, &mut rx, s3, req, id, got.len() as u64, 7_001).await;
        req += 1;
        match r {
            FileReply::Data {
                offset,
                data_b64,
                size,
                eof,
                sha256,
            } => {
                assert_eq!(offset, got.len() as u64);
                assert_eq!(size, ready.bundle_size);
                got.extend(
                    base64::engine::general_purpose::STANDARD
                        .decode(data_b64)
                        .unwrap(),
                );
                if eof {
                    break sha256.unwrap();
                }
            }
            other => panic!("{other:?}"),
        }
    };
    assert_eq!(got.len() as u64, ready.bundle_size);
    assert_eq!(Some(sha.clone()), ready.bundle_sha256);
    assert_eq!(sha256_hex(&got), sha);
    let e = entries(&got);
    assert_eq!(e.last().unwrap().0, "manifest.json");
    assert!(e
        .iter()
        .any(|(n, d)| n.starts_with("staged/") && d == b"PK\x03\x04 loot archive content"));
    assert!(e.iter().any(|(_, d)| d == b"chrome-secret-content-XYZ"));
    // The bundle's own manifest is unfiltered.
    let inner: kestrel_common::evidence::EvidenceManifest =
        serde_json::from_slice(&e.last().unwrap().1).unwrap();
    assert!(inner.secrets.iter().any(|s| s.path == FIREFOX));
    wait_for("upload sessions to end", 5, || {
        core.evidence.read_sessions() == 0
    })
    .await;

    // Stream loss ends sessions.
    let s4 = Uuid::new_v4();
    let _ = read(&core, &mut rx, s4, 1, id, 0, 10).await;
    assert_eq!(core.evidence.read_sessions(), 1);
    if core.live.detach(gen) {
        core.evidence.end_reads(None);
    }
    assert_eq!(core.evidence.read_sessions(), 0);

    // Delete.
    let del = Uuid::new_v4();
    core.run_command(del, ResponseAction::DeleteEvidence { bundle_id: id })
        .await;
    assert!(result_of(&core, del).unwrap().ok);
    assert!(!bundle_file.exists());
    assert!(reports(&core)
        .iter()
        .any(|r| r.bundle_id == id && r.state == EvidenceState::Deleted));
    let again = core
        .execute_action_as(
            &ResponseAction::DeleteEvidence { bundle_id: id },
            ActionOrigin::ServerCommand,
        )
        .await;
    assert!(again.ok);
    assert_eq!(again.detail, "already deleted");
    let o = core
        .execute_action_as(
            &ResponseAction::CollectEvidence { bundle_id: id },
            ActionOrigin::ServerCommand,
        )
        .await;
    assert!(!o.ok);
    h.stop().await;
}

fn fake_ready(core: &Core, host: &dyn EvidenceHost, expires_at: i64) -> Uuid {
    let id = Uuid::new_v4();
    let p = bundle_path(&bundles_dir(host), id);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, b"sealed").unwrap();
    let mut idx: Vec<IndexEntry> = core
        .store
        .kv_get_json(KV_EVIDENCE_INDEX)
        .unwrap()
        .unwrap_or_default();
    idx.push(IndexEntry {
        bundle_id: id,
        alert_id: Uuid::new_v4(),
        alert_ids: vec![],
        rule_id: "ST-02".into(),
        state: EvidenceState::Ready,
        created_at: 1,
        size: 6,
        sha256: Some(sha256_hex(b"x")),
        expires_at: Some(expires_at),
        authorized_until: None,
        owner: None,
        detail: String::new(),
        program: None,
    });
    core.store.kv_set_json(KV_EVIDENCE_INDEX, &idx).unwrap();
    id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retention_expires_uncollected_bundles() {
    let dir = tempfile::tempdir().unwrap();
    setup(dir.path(), None);
    let (h, sim) = start(dir.path(), None).await;
    let core = h.core.clone();
    let host = sim.sim_evidence();
    let old = fake_ready(&core, &*host, 1);
    let fresh = fake_ready(&core, &*host, kestrel_common::now_ms() + 3_600_000);
    core.evidence.housekeep(&core);
    assert!(!bundle_path(&bundles_dir(&*host), old).exists());
    assert!(bundle_path(&bundles_dir(&*host), fresh).exists());
    let rs = reports(&core);
    assert!(rs
        .iter()
        .any(|r| r.bundle_id == old && r.state == EvidenceState::Expired));
    assert!(!rs.iter().any(|r| r.bundle_id == fresh));
    assert_eq!(
        core.evidence.entry(&core, old).unwrap().state,
        EvidenceState::Expired
    );
    h.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn restart_fails_interrupted_captures_and_cleans_up() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    setup(state, None);
    let id = Uuid::new_v4();
    {
        let st = crate::store::Store::open(state).unwrap();
        st.kv_set_json(
            KV_EVIDENCE_INDEX,
            &vec![IndexEntry {
                bundle_id: id,
                alert_id: Uuid::new_v4(),
                alert_ids: vec![],
                rule_id: "ST-04".into(),
                state: EvidenceState::Capturing,
                created_at: 1,
                size: 0,
                sha256: None,
                expires_at: None,
                authorized_until: None,
                owner: None,
                detail: String::new(),
                program: None,
            }],
        )
        .unwrap();
    }
    let sim_fs = SimEvidence::new(state.to_path_buf());
    let bdir = bundles_dir(&sim_fs);
    std::fs::create_dir_all(&bdir).unwrap();
    std::fs::write(bdir.join(format!("{id}.kev.partial")), b"half").unwrap();
    std::fs::write(bdir.join(format!("{}.kev", Uuid::new_v4())), b"orphan").unwrap();
    let work = crate::evidence::work_root(&sim_fs).join("x");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::write(work.join("capture.pcapng"), b"plaintext").unwrap();

    let (h, sim) = start(state, None).await;
    let core = h.core.clone();
    wait_for("failed report", 5, || {
        reports(&core)
            .iter()
            .any(|r| r.bundle_id == id && r.state == EvidenceState::Failed)
    })
    .await;
    assert_eq!(std::fs::read_dir(&bdir).unwrap().count(), 0);
    assert!(!work.exists());
    assert_eq!(
        sim.sim_evidence()
            .pcap()
            .cleanups
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    let r = reports(&core)
        .into_iter()
        .find(|r| r.bundle_id == id)
        .unwrap();
    assert_eq!(r.detail, "the agent restarted during the capture");
    // Capabilities announce evidence support.
    assert!(core.platform.evidence().is_some());
    h.stop().await;
}

/// Evidence capture never runs when every part is off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn policy_off_means_no_capture() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let policy = Policy {
        version: 2,
        evidence: EvidencePolicy::off(),
        ..Policy::default()
    };
    setup(state, Some(policy));
    let (h, sim) = start(state, Some("vidar_smash_grab.jsonl")).await;
    let core = h.core.clone();
    wait_for("replay", 20, || sim.replay_done()).await;
    // An alert was raised …
    wait_for("an ST-02 alert", 10, || {
        outbox(&core).iter().any(
            |p| matches!(p, AgentPayload::Alert(a) if kestrel_common::evidence::is_trigger_rule(&a.rule_id)),
        )
    })
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    // … but nothing was captured, and the sensors got no write sink.
    assert!(reports(&core).is_empty());
    assert!(!sim.send_write_hint(WriteHint {
        ts: 1,
        pid: 1,
        guid: ProcessGuid("x".into()),
        path: HINT.into(),
        op: kestrel_common::evidence::WriteOp::Created,
    }));
    h.stop().await;
}

// ------------------------------------------- hostile review 2026-10-25

/// H1: only the tree user's own profile and never machine secrets.
#[test]
fn collection_scope_by_user() {
    use crate::evidence_bundle::{
        collect_refusal, has_short_component, profile_of, Candidate, TreeScope, NOT_CREATED,
        OTHER_PROFILE, OUTSIDE_PROFILE, PROTECTED_SECRET, SHORT_NAME, UNKNOWN_USER,
    };
    assert_eq!(profile_of(r"CORP\J.Doe").as_deref(), Some("j.doe"));
    assert_eq!(profile_of("alice@corp.example").as_deref(), Some("alice"));
    assert_eq!(profile_of("S-1-5-21-1-2-3-1001"), None);
    assert_eq!(profile_of("  "), None);
    let me = TreeScope::new(Some(r"CORP\alice"), None);
    let staged = Candidate::Staged { confirmed: true };
    let guessed = Candidate::Staged { confirmed: false };
    let store = Candidate::Secret;
    for (p, kind, want) in [
        (r"C:\Users\Alice\AppData\Local\Temp\a.zip", guessed, None),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            store,
            None,
        ),
        // L2: no `name.<suffix>` prefix match without the SID's folder.
        (
            r"c:/users/alice.CORP/Downloads/x.txt",
            staged,
            Some(OTHER_PROFILE),
        ),
        (
            r"C:\Users\alice2\Downloads\x.txt",
            staged,
            Some(OTHER_PROFILE),
        ),
        (
            r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            store,
            Some(OTHER_PROFILE),
        ),
        (r"D:\Users\bob\x.txt", staged, Some(OTHER_PROFILE)),
        (r"\\?\C:\Users\bob\x.txt", staged, Some(OTHER_PROFILE)),
        // M2: outside the own profile only confirmed creations.
        (r"C:\Users\Public\Documents\x.txt", staged, None),
        (
            r"C:\Users\Public\Documents\x.txt",
            guessed,
            Some(NOT_CREATED),
        ),
        (r"C:\ProgramData\XGBK\loot.zip", staged, None),
        (r"C:\ProgramData\XGBK\loot.zip", guessed, Some(NOT_CREATED)),
        (r"C:\Windows\Temp\x.zip", staged, None),
        (r"C:\Windows\Temp\setup.log", guessed, Some(NOT_CREATED)),
        (
            r"D:\IT\Shared\admin-passwords.kdbx",
            store,
            Some(OUTSIDE_PROFILE),
        ),
        (
            r"C:\Program Files\OpenVPN\config\site.ovpn",
            store,
            Some(OUTSIDE_PROFILE),
        ),
        (r"C:\Users\Public\wallet.dat", store, Some(OUTSIDE_PROFILE)),
        (
            r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\k",
            staged,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\x.xml",
            store,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\ProgramData\ssh\ssh_host_ed25519_key",
            store,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\ProgramData\Microsoft\Windows\WER\ReportQueue\x.dmp",
            staged,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\Windows\System32\config\SAM",
            store,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\Windows\System32\Microsoft\Protect\S-1-5-18\User\k",
            store,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials\b",
            store,
            Some(PROTECTED_SECRET),
        ),
        (
            r"C:\Windows\Panther\unattend.xml",
            staged,
            Some(PROTECTED_SECRET),
        ),
        (r"C:\pagefile.sys", staged, Some(PROTECTED_SECRET)),
        // M1: an unresolved short name is never decided on.
        (
            r"C:\PROGRA~3\Microsoft\Vault\4BF4C442\Policy.vpol",
            store,
            Some(SHORT_NAME),
        ),
        (r"C:\Users\alice\DOCUME~1\x.zip", staged, Some(SHORT_NAME)),
    ] {
        assert_eq!(collect_refusal(p, &me, kind), want, "{p} {kind:?}");
    }
    let nobody = TreeScope::new(None, None);
    assert_eq!(
        collect_refusal(r"C:\Users\alice\x.txt", &nobody, staged),
        Some(UNKNOWN_USER)
    );
    assert_eq!(
        collect_refusal(r"C:\ProgramData\x\a.zip", &nobody, staged),
        None
    );
    // L2: with the SID's profile folder, exactly that folder.
    let domain = TreeScope::new(Some(r"CORP\bob"), Some(r"C:\Users\bob.CORP"));
    assert_eq!(
        collect_refusal(r"C:\Users\bob.CORP\x.zip", &domain, staged),
        None
    );
    assert_eq!(
        collect_refusal(r"C:\Users\bob\x.zip", &domain, staged),
        Some(OTHER_PROFILE)
    );
    assert_eq!(
        collect_refusal(r"C:\Users\bob.CORP.000\x.zip", &domain, staged),
        Some(OTHER_PROFILE)
    );
    let roaming = TreeScope::new(Some(r"CORP\eve"), Some(r"D:\Profiles\eve"));
    assert_eq!(
        collect_refusal(
            r"D:\Profiles\eve\AppData\Roaming\x\Login Data",
            &roaming,
            store
        ),
        None
    );
    assert_eq!(
        collect_refusal(r"C:\Users\eve\x.zip", &roaming, staged),
        Some(OTHER_PROFILE)
    );
    assert!(has_short_component(r"C:\PROGRA~3\x"));
    assert!(has_short_component(r"C:\x\ABCDEF~12.TXT"));
    assert!(!has_short_component(r"C:\x\~$doc.docx"));
    assert!(!has_short_component(r"C:\x\a~b\c"));

    // In a bundle: listed, never copied (stores not even sized).
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    let mine = r"C:\Users\a\Downloads\mine.zip";
    let theirs = r"C:\Users\bob\Downloads\theirs.zip";
    let bob_store = r"C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data";
    let machine = r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\k1";
    put(&sim, mine, b"mine");
    put(&sim, theirs, b"bob archive");
    put(&sim, bob_store, b"bob passwords");
    put(&sim, machine, b"machine key");
    let snap = JournalSnapshot {
        staged: vec![cand(mine, 2), cand(theirs, 1)],
        secrets: vec![secret(bob_store), secret(machine)],
        ..Default::default()
    };
    let id = Uuid::new_v4();
    let b = build_bundle(&sim, input(id, snap, Limits::default()), &bundles_dir(&sim)).unwrap();
    assert_eq!(b.manifest.staged[0].copy.status, CopyStatus::Copied);
    assert_eq!(b.manifest.staged[1].copy.status, CopyStatus::Error);
    assert_eq!(b.manifest.staged[1].copy.detail, OTHER_PROFILE);
    let s0 = &b.manifest.secrets[0];
    assert_eq!(s0.copy.as_ref().unwrap().detail, OTHER_PROFILE);
    assert_eq!(s0.size, None);
    assert_eq!(
        b.manifest.secrets[1].copy.as_ref().unwrap().detail,
        PROTECTED_SECRET
    );
    let key = sim.bundle_key().unwrap();
    let e = entries(&open_bundle(&b.path, &key, id).unwrap());
    let names: Vec<&str> = e.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["staged/0001-mine.zip", "manifest.json"]);
    assert!(b.manifest.notes.iter().any(|n| n.contains("other users")));

    // Unknown user: nothing under \Users\ is copied.
    let id = Uuid::new_v4();
    let mut inp = input(
        id,
        JournalSnapshot {
            staged: vec![cand(mine, 2)],
            ..Default::default()
        },
        Limits::default(),
    );
    inp.tree_user = None;
    let b = build_bundle(&sim, inp, &bundles_dir(&sim)).unwrap();
    assert_eq!(b.manifest.staged[0].copy.detail, UNKNOWN_USER);
}

/// A host that claims every path resolves to itself while its opens expand
/// aliases (what a resolver bug or a race would look like): the check on
/// the opened handle's path must still refuse.
struct NoResolve(SimEvidence);

impl EvidenceHost for NoResolve {
    fn evidence_dir(&self) -> PathBuf {
        self.0.evidence_dir()
    }
    fn bundle_key(&self) -> Result<[u8; 32], String> {
        self.0.bundle_key()
    }
    fn own_prefixes(&self) -> Vec<String> {
        self.0.own_prefixes()
    }
    fn open_source(&self, path: &str, max: u64) -> Result<SourceFile, SourceError> {
        self.0.open_source(path, max)
    }
    fn file_size(&self, path: &str) -> Option<u64> {
        self.0.file_size(path)
    }
    fn resolve_path(&self, path: &str) -> Option<String> {
        Some(path.to_string())
    }
}

/// Review of the 1.1.7 integration, M1 / M2 / L2, end to end in a bundle.
#[test]
fn collection_scope_resolved_paths_m1_m2_l2() {
    use crate::evidence_bundle::{NOT_CREATED, OTHER_PROFILE, OUTSIDE_PROFILE, PROTECTED_SECRET};
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    sim.short_names
        .lock()
        .unwrap()
        .push((r"C:\PROGRA~3".into(), r"C:\ProgramData".into()));
    let vault = r"C:\ProgramData\Microsoft\Vault\4BF4C442\Policy.vpol";
    put(&sim, vault, b"machine vault");
    let short_vault = r"C:\PROGRA~3\Microsoft\Vault\4BF4C442\Policy.vpol";
    let shared = r"D:\IT\Shared\admin-passwords.kdbx";
    put(&sim, shared, b"it passwords");
    let guessed = r"C:\Windows\Temp\setup.log";
    put(&sim, guessed, b"someone else's log");
    let made = r"C:\ProgramData\XGBK\loot.zip";
    put(&sim, made, b"loot");
    let mine = r"C:\Users\a.CORP\Downloads\mine.zip";
    put(&sim, mine, b"mine");
    let local_a = r"C:\Users\a\Downloads\local-a.zip";
    put(&sim, local_a, b"local a");
    // L2: the account's profile folder from its SID.
    sim.profiles
        .lock()
        .unwrap()
        .push((r"CORP\a".into(), r"C:\Users\a.CORP".into()));
    let mut unconfirmed = cand(guessed, 3);
    unconfirmed.confirmed = false;
    let snap = JournalSnapshot {
        staged: vec![cand(mine, 6), cand(local_a, 5), cand(made, 4), unconfirmed],
        secrets: vec![secret(short_vault), secret(shared)],
        ..Default::default()
    };
    let id = Uuid::new_v4();
    let b = build_bundle(&sim, input(id, snap, Limits::default()), &bundles_dir(&sim)).unwrap();
    let st: Vec<(&str, CopyStatus, &str)> = b
        .manifest
        .staged
        .iter()
        .map(|s| (s.path.as_str(), s.copy.status, s.copy.detail.as_str()))
        .collect();
    assert_eq!(
        st,
        [
            (mine, CopyStatus::Copied, ""),
            (local_a, CopyStatus::Error, OTHER_PROFILE),
            (made, CopyStatus::Copied, ""),
            (guessed, CopyStatus::Error, NOT_CREATED),
        ]
    );
    let sc: Vec<&str> = b
        .manifest
        .secrets
        .iter()
        .map(|s| s.copy.as_ref().unwrap().detail.as_str())
        .collect();
    assert_eq!(sc, [PROTECTED_SECRET, OUTSIDE_PROFILE]);
    assert!(b.manifest.secrets.iter().all(|s| s.size.is_none()));
    let key = sim.bundle_key().unwrap();
    let e = entries(&open_bundle(&b.path, &key, id).unwrap());
    let names: Vec<&str> = e.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "staged/0001-mine.zip",
            "staged/0003-loot.zip",
            "manifest.json"
        ]
    );

    // The opened handle's path is checked again (resolver says "same
    // path", the open lands in the machine vault).
    let dir2 = tempfile::tempdir().unwrap();
    let host = NoResolve(SimEvidence::new(dir2.path().to_path_buf()));
    host.0
        .short_names
        .lock()
        .unwrap()
        .push((r"C:\Data".into(), r"C:\ProgramData".into()));
    put(&host.0, vault, b"machine vault");
    let alias = r"C:\Data\Microsoft\Vault\4BF4C442\Policy.vpol";
    let snap = JournalSnapshot {
        staged: vec![cand(alias, 1)],
        ..Default::default()
    };
    let id = Uuid::new_v4();
    let b = build_bundle(
        &host,
        input(id, snap, Limits::default()),
        &bundles_dir(&host.0),
    )
    .unwrap();
    assert_eq!(b.manifest.staged[0].copy.status, CopyStatus::Error);
    assert_eq!(b.manifest.staged[0].copy.detail, PROTECTED_SECRET);
    assert!(b.manifest.staged[0].copy.entry.is_none());
    let key = host.0.bundle_key().unwrap();
    let e = entries(&open_bundle(&b.path, &key, id).unwrap());
    assert_eq!(e.len(), 1, "manifest only");
}

/// A host whose `slow.bin` crawls (one byte per 20 ms) and whose free disk
/// space is configurable.
struct Slow(SimEvidence, Option<u64>);

struct Crawl(u64);

impl Read for Crawl {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.0 == 0 || buf.is_empty() {
            return Ok(0);
        }
        std::thread::sleep(Duration::from_millis(20));
        self.0 -= 1;
        buf[0] = b'x';
        Ok(1)
    }
}

impl EvidenceHost for Slow {
    fn evidence_dir(&self) -> PathBuf {
        self.0.evidence_dir()
    }
    fn bundle_key(&self) -> Result<[u8; 32], String> {
        self.0.bundle_key()
    }
    fn own_prefixes(&self) -> Vec<String> {
        self.0.own_prefixes()
    }
    fn open_source(&self, path: &str, max: u64) -> Result<SourceFile, SourceError> {
        if path.ends_with("slow.bin") {
            return Ok(SourceFile {
                reader: Box::new(Crawl(1000)),
                size: 1000,
                path: path.into(),
            });
        }
        self.0.open_source(path, max)
    }
    fn file_size(&self, path: &str) -> Option<u64> {
        if path.ends_with("slow.bin") {
            return Some(1000);
        }
        self.0.file_size(path)
    }
    fn free_bytes(&self) -> Option<u64> {
        self.1
    }
}

/// H2: per-file deadline and cancel flag; M2: free disk space.
#[test]
fn build_deadlines_cancel_and_disk_space() {
    let dir = tempfile::tempdir().unwrap();
    let host = Slow(SimEvidence::new(dir.path().to_path_buf()), None);
    let slow = r"C:\Users\a\Downloads\slow.bin";
    let snap = JournalSnapshot {
        staged: vec![cand(slow, 1)],
        ..Default::default()
    };
    let lim = Limits {
        file_deadline: Duration::from_millis(100),
        ..Limits::default()
    };
    let b = build_bundle(
        &host,
        input(Uuid::new_v4(), snap.clone(), lim),
        &bundles_dir(&host),
    )
    .unwrap();
    let c = &b.manifest.staged[0].copy;
    assert_eq!(c.status, CopyStatus::Truncated);
    assert!(c.size < 1000 && c.detail.contains("too long"), "{c:?}");

    // Cancelled: fails, nothing left behind.
    let id = Uuid::new_v4();
    let inp = input(id, snap.clone(), lim);
    inp.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    let err = build_bundle(&host, inp, &bundles_dir(&host)).unwrap_err();
    assert!(err.contains("cancelled"), "{err}");
    assert!(!bundles_dir(&host).join(format!("{id}.kev")).exists());
    assert!(!bundles_dir(&host)
        .join(format!("{id}.kev.partial"))
        .exists());

    // Not enough free space: refused before anything is written.
    let tight = Slow(SimEvidence::new(dir.path().to_path_buf()), Some(1 << 30));
    let id = Uuid::new_v4();
    let err = build_bundle(&tight, input(id, snap.clone(), lim), &bundles_dir(&tight)).unwrap_err();
    assert!(err.contains("free disk space"), "{err}");
    assert!(!bundles_dir(&tight)
        .join(format!("{id}.kev.partial"))
        .exists());
    let roomy = Slow(SimEvidence::new(dir.path().to_path_buf()), Some(3 << 30));
    assert!(build_bundle(
        &roomy,
        input(Uuid::new_v4(), snap, lim),
        &bundles_dir(&roomy)
    )
    .is_ok());
}

/// M3: long strings are clipped, oversized manifests lose list tails
/// (entries without data first) instead of failing the bundle.
#[test]
fn manifest_is_clipped_not_failed() {
    use crate::evidence_bundle::{fit_manifest_to, MAX_MANIFEST_STRING};
    use kestrel_common::evidence::{EvidenceManifest, FileCopy, StagedFile};
    let staged = |i: usize, data: bool| StagedFile {
        path: format!(r"C:\Users\a\Downloads\{}{i}.txt", "é".repeat(800)),
        written_at: 1,
        op: Default::default(),
        process_guid: ProcessGuid("g".into()),
        image: String::new(),
        copy: FileCopy {
            status: if data {
                CopyStatus::Copied
            } else {
                CopyStatus::Missing
            },
            entry: data.then(|| format!("staged/{i:04}-x.txt")),
            ..Default::default()
        },
    };
    let mut m = EvidenceManifest {
        format: 1,
        bundle_id: Uuid::nil(),
        alert_id: Uuid::nil(),
        alert_ids: vec![],
        rule_id: "ST-02".into(),
        hostname: "H".into(),
        agent_version: "t".into(),
        started_at: 0,
        window_start: 0,
        window_end: 0,
        completed_at: 0,
        parts: EvidencePolicy::default(),
        processes: vec![],
        staged: (0..40).map(|i| staged(i, i % 2 == 0)).collect(),
        secrets: vec![],
        pcap: None,
        totals: Default::default(),
        notes: vec![],
    };
    let json = fit_manifest_to(&mut m, 30_000).unwrap();
    assert!(json.len() <= 30_000);
    assert!(m.staged.iter().all(|s| s.path.len() <= MAX_MANIFEST_STRING));
    assert!(m.staged[0].path.ends_with('…'));
    // Entries without data went first: every copied entry is still listed.
    assert_eq!(
        m.staged.iter().filter(|s| s.copy.status.has_data()).count(),
        20
    );
    assert!(m.staged.len() < 40);
    assert!(
        m.notes.iter().any(|n| n.contains("left out")),
        "{:?}",
        m.notes
    );
    assert_eq!(m.totals.staged_listed as usize, m.staged.len());
}

/// M2: per-program, global and byte caps on uncollected bundles.
#[test]
fn local_bundle_caps() {
    use crate::evidence::{capture_refusal, program_key, MAX_LOCAL_BUNDLES};
    let entry = |program: &str, state: EvidenceState, size: u64| IndexEntry {
        bundle_id: Uuid::new_v4(),
        alert_id: Uuid::nil(),
        alert_ids: vec![],
        rule_id: "ST-02".into(),
        state,
        created_at: 1,
        size,
        sha256: None,
        expires_at: None,
        authorized_until: None,
        owner: None,
        detail: String::new(),
        program: Some(program.into()),
    };
    let mut idx = vec![
        entry("sha256:aa", EvidenceState::Ready, 10),
        entry("sha256:aa", EvidenceState::Capturing, 0),
        entry("sha256:bb", EvidenceState::Deleted, 10),
    ];
    assert!(capture_refusal(&idx, Some("sha256:aa"))
        .unwrap()
        .contains("this program"));
    assert_eq!(capture_refusal(&idx, Some("sha256:bb")), None);
    idx.push(entry("sha256:cc", EvidenceState::Ready, 2 << 30));
    assert!(capture_refusal(&idx, Some("sha256:dd"))
        .unwrap()
        .contains("MB"));
    let many: Vec<IndexEntry> = (0..MAX_LOCAL_BUNDLES)
        .map(|i| entry(&format!("p{i}"), EvidenceState::Ready, 1))
        .collect();
    assert!(capture_refusal(&many, Some("new")).is_some());
    // Keys: sha256 preferred, else the image path.
    let mut p = kestrel_common::ProcessInfo {
        guid: ProcessGuid("g".into()),
        pid: 1,
        ppid: 0,
        parent_guid: None,
        image: r"C:/Users/A/x.EXE".into(),
        cmdline: String::new(),
        user: None,
        integrity: None,
        start_ts: 0,
        exit_ts: None,
        signer: None,
        signed: Default::default(),
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: kestrel_common::PathClass::Downloads,
    };
    assert_eq!(program_key(&p).as_deref(), Some(r"path:c:\users\a\x.exe"));
    p.sha256 = Some("AB".into());
    assert_eq!(program_key(&p).as_deref(), Some("sha256:ab"));
}

/// Info: with hash_usernames on, profile folder names are pseudonymised in
/// the reported manifest; L7: the infrastructure-port note.
#[test]
fn manifest_pseudonymises_profiles() {
    use crate::privacy::PrivacyFilter;
    let dir = tempfile::tempdir().unwrap();
    let sim = SimEvidence::new(dir.path().to_path_buf());
    let p = r"C:\Users\a\Downloads\x.zip";
    put(&sim, p, b"x");
    let snap = JournalSnapshot {
        staged: vec![cand(p, 1)],
        secrets: vec![secret(
            r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        )],
        net_excluded: 2,
        ..Default::default()
    };
    let b = build_bundle(
        &sim,
        input(Uuid::new_v4(), snap, Limits::default()),
        &bundles_dir(&sim),
    )
    .unwrap();
    assert!(b
        .manifest
        .notes
        .iter()
        .any(|n| n.contains("infrastructure ports")));
    let privacy = kestrel_common::Privacy {
        hash_usernames: true,
        ..Default::default()
    };
    let f = PrivacyFilter::new(&privacy, &kestrel_common::Telemetry::default(), "salt");
    let mut m = b.manifest.clone();
    f.scrub_evidence_manifest(&mut m);
    let pseudo = f.user("a");
    assert_ne!(pseudo, "a");
    assert_eq!(
        m.staged[0].path,
        format!(r"C:\Users\{pseudo}\Downloads\x.zip")
    );
    assert!(m.secrets[0]
        .path
        .starts_with(&format!(r"C:\Users\{pseudo}\AppData")));
    assert!(m.staged[0]
        .image
        .starts_with(&format!(r"C:\Users\{pseudo}\")));
    // Off: unchanged.
    let f = PrivacyFilter::new(&Default::default(), &Default::default(), "salt");
    let mut m = b.manifest.clone();
    f.scrub_evidence_manifest(&mut m);
    assert_eq!(m.staged[0].path, p);
}

/// H2 in the agent: a build blocked on an open is abandoned at the
/// deadline, reported Failed, and the abandoned thread cleans up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocked_build_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path();
    let mut policy = Policy {
        version: 3,
        ..Policy::default()
    };
    for r in ["ST-02", "ST-04"] {
        policy.rules.insert(r.into(), RuleMode::Audit);
    }
    setup(state, Some(policy));
    let sim_fs = SimEvidence::new(state.to_path_buf());
    put(&sim_fs, ZIP, b"PK loot");
    let sim = Arc::new(SimPlatform::new(SimOptions {
        state_dir: state.to_path_buf(),
        replay: Some(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("replays")
                .join("vidar_smash_grab.jsonl"),
        ),
        speed: 50.0,
        hostname: "SIM-EVIDENCE".into(),
        user: SIM_USER.into(),
    }));
    sim.sim_evidence()
        .open_delay_ms
        .store(2_000, std::sync::atomic::Ordering::Relaxed);
    let h = agent::start(
        sim.clone(),
        state.to_path_buf(),
        Tuning {
            evidence_build_deadline: Duration::from_millis(300),
            ..tuning()
        },
    )
    .await
    .unwrap();
    let core = h.core.clone();
    wait_for("a failed report", 30, || {
        reports(&core)
            .iter()
            .any(|r| r.state == EvidenceState::Failed)
    })
    .await;
    let r = reports(&core)
        .into_iter()
        .find(|r| r.state == EvidenceState::Failed)
        .unwrap();
    assert_eq!(r.detail, "timed out copying files");
    assert!(!reports(&core)
        .iter()
        .any(|r| r.state == EvidenceState::Ready));
    // The abandoned thread wakes up, sees the cancel flag and leaves
    // nothing behind.
    sim.sim_evidence()
        .open_delay_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let bdir = bundles_dir(&*sim.sim_evidence());
    wait_for("the abandoned build to clean up", 15, || {
        std::fs::read_dir(&bdir).map_or(true, |d| d.count() == 0)
    })
    .await;
    h.stop().await;
}
