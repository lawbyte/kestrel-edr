//! The shipped sample replays drive demos: the stealer scenarios must trigger
//! the real ST rules and the benign workday must stay silent.

use kestrel_agent::sim::{self, SimOptions, SimPlatform, SIM_BOOT_ID, SIM_USER};
use kestrel_common::Policy;
use kestrel_detect::{Engine, HostContext, Output};
use kestrel_platform::Platform;
use std::collections::BTreeSet;
use std::path::Path;

fn fired(replay: &str) -> BTreeSet<String> {
    let dir = tempfile::tempdir().unwrap();
    let platform = SimPlatform::new(SimOptions {
        state_dir: dir.path().into(),
        replay: None,
        speed: 1.0,
        hostname: "SIM-WKS-01".into(),
        user: SIM_USER.into(),
    });
    let host = HostContext {
        boot_id: SIM_BOOT_ID.into(),
        hostname: "SIM-WKS-01".into(),
        agent_image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
        server_ips: vec!["192.0.2.1".into()],
        system_drive: Some('c'),
    };
    let mut engine = Engine::new(host, Policy::default(), Default::default()).unwrap();
    for p in platform.snapshot_processes(SIM_BOOT_ID) {
        engine.seed_process(p);
    }
    let events = sim::load_replay(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("replays")
            .join(replay),
    )
    .unwrap();
    let mut rules = BTreeSet::new();
    let mut collect = |outs: Vec<Output>| {
        for o in outs {
            if let Output::Alert(d) = o {
                rules.insert(d.alert.rule_id);
            }
        }
    };
    let mut last = 0;
    for e in &events {
        collect(engine.process(e));
        last = e.ts;
        collect(engine.tick(e.ts));
    }
    collect(engine.tick(last + 600_000));
    rules
}

#[test]
fn lumma_clickfix_fires_stealer_rules() {
    let r = fired("lumma_clickfix.jsonl");
    for want in ["ST-03", "ST-04", "ST-11", "ST-14"] {
        assert!(r.contains(want), "{want} missing; fired {r:?}");
    }
}

#[test]
fn vidar_smash_grab_fires_stealer_rules() {
    let r = fired("vidar_smash_grab.jsonl");
    for want in ["ST-02", "ST-03", "ST-04", "ST-09", "ST-12"] {
        assert!(r.contains(want), "{want} missing; fired {r:?}");
    }
}

#[test]
fn benign_workday_is_silent() {
    let r = fired("benign_workday.jsonl");
    assert!(r.is_empty(), "false positives on benign replay: {r:?}");
}
