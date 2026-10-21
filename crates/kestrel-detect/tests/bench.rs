//! Throughput micro-benchmark (no criterion). Ignored by default; run with
//! `cargo test --release -p kestrel-detect --test bench -- --ignored --nocapture`.
//! Target: > 200k events/s in release.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;
use std::time::Instant;

fn mixed_events(n: usize) -> Vec<Event> {
    let mut v = Vec::with_capacity(n);
    let procs = 300u32;
    let images = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Windows\System32\svchost.exe",
        r"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE",
        r"C:\Users\alice\AppData\Local\Programs\Microsoft VS Code\Code.exe",
        r"C:\Windows\explorer.exe",
        r"C:\Users\alice\AppData\Local\Temp\tool.exe",
    ];
    for p in 0..procs {
        let img = images[p as usize % images.len()];
        let signed = if img.contains("Temp") {
            SignatureState::Unsigned
        } else {
            SignatureState::Valid
        };
        v.push(start(
            p as i64,
            &format!("p{p}"),
            1000 + p,
            img,
            img,
            if p > 0 { Some(("p0", 1000)) } else { None },
            signed,
            None,
        ));
    }
    let mut x: u64 = 0x9e3779b97f4a7c15;
    let mut rnd = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut ts = 1000i64;
    while v.len() < n {
        ts += 1;
        let r = rnd();
        let p = (r % procs as u64) as u32;
        let guid = format!("p{p}");
        let pid = 1000 + p;
        let kind = (r >> 16) % 100;
        let e = match kind {
            0..=54 => {
                // ordinary file I/O
                let path = format!(
                    r"C:\Users\alice\Documents\Project{}\file{}.docx",
                    r % 50,
                    (r >> 8) % 1000
                );
                ev(
                    ts,
                    &guid,
                    pid,
                    EventData::FileAccess {
                        path,
                        op: FileOp::Read,
                    },
                )
            }
            55..=59 => {
                let paths = [
                    CHROME_LOGIN,
                    CHROME_COOKIES,
                    CHROME_STATE,
                    r"\Device\HarddiskVolume3\Users\alice\AppData\Roaming\Telegram Desktop\tdata\key_datas",
                ];
                ev(
                    ts,
                    &guid,
                    pid,
                    EventData::FileAccess {
                        path: paths[(r >> 24) as usize % paths.len()].into(),
                        op: FileOp::Read,
                    },
                )
            }
            60..=74 => {
                let ip = format!(
                    "{}.{}.{}.{}",
                    20 + r % 180,
                    (r >> 8) % 255,
                    (r >> 16) % 255,
                    1 + (r >> 24) % 250
                );
                ev(
                    ts,
                    &guid,
                    pid,
                    EventData::NetConnect {
                        proto: NetProto::Tcp,
                        dst_ip: ip,
                        dst_port: 443,
                        src_port: 50000,
                        dst_host: None,
                        bytes_sent: None,
                    },
                )
            }
            75..=84 => {
                let hosts = [
                    "www.google.com",
                    "login.microsoftonline.com",
                    "api.github.com",
                    "cdn.jsdelivr.net",
                    "outlook.office365.com",
                ];
                ev(
                    ts,
                    &guid,
                    pid,
                    EventData::DnsQuery {
                        qname: hosts[(r >> 24) as usize % hosts.len()].into(),
                        answers: vec!["142.250.4.100".into()],
                    },
                )
            }
            85..=94 => ev(
                ts,
                &guid,
                pid,
                EventData::ImageLoad {
                    path: r"C:\Windows\System32\kernelbase.dll".into(),
                    signer: None,
                    signed: SignatureState::Valid,
                },
            ),
            95..=97 => ev(
                ts,
                &guid,
                pid,
                EventData::RegistrySet {
                    attribution: Default::default(),
                    key: r"HKCU\Software\Microsoft\Office\16.0\Common".into(),
                    value_name: "x".into(),
                    data: Some("1".into()),
                    op: Default::default(),
                },
            ),
            _ => ev(
                ts,
                &guid,
                pid,
                EventData::ProcessAccess(TargetProcess {
                    target_pid: 1000,
                    target_guid: Some(g("p0")),
                    target_image: CHROME_EXE.into(),
                    granted_access: 0x1000,
                    return_code: 0,
                }),
            ),
        };
        v.push(e);
    }
    v
}

#[test]
#[ignore]
fn throughput_100k_mixed_events() {
    let events = mixed_events(100_000);
    // with one custom Sigma rule loaded, too
    let sigma = r#"
title: Bench rule
logsource: {category: process_creation}
detection:
  sel:
    CommandLine|contains: 'whoami'
  condition: sel
"#;
    let def = RuleDef {
        meta: RuleMeta {
            id: "SIG-bench".into(),
            name: "bench".into(),
            description: String::new(),
            kind: RuleKind::Sigma,
            category: RuleCategory::Custom,
            severity: Severity::Low,
            attack: vec![],
            default_mode: RuleMode::Audit,
            protect_day_one: false,
            protect_action: String::new(),
            author: None,
            license: None,
            references: vec![],
            false_positives: vec![],
        },
        source: sigma.into(),
    };
    let mut best = 0f64;
    for round in 0..3 {
        let mut e = Engine::new(
            host(),
            Policy::default(),
            RuleBundle {
                version: 1,
                rules: vec![def.clone()],
            },
        )
        .unwrap();
        let _ = e.canaries(r"C:\Users\alice");
        let t = Instant::now();
        let mut outputs = 0usize;
        for (i, ev) in events.iter().enumerate() {
            outputs += e.process(ev).len();
            if i % 4096 == 0 {
                outputs += e.tick(ev.ts).len();
            }
        }
        let secs = t.elapsed().as_secs_f64();
        let rate = events.len() as f64 / secs;
        best = best.max(rate);
        println!(
            "round {round}: {} events in {:.3} s = {:.0} events/s ({outputs} outputs)",
            events.len(),
            secs,
            rate
        );
    }
    println!("best: {best:.0} events/s");
    if !cfg!(debug_assertions) {
        assert!(
            best > 200_000.0,
            "throughput {best:.0} events/s below 200k target"
        );
    }
}
