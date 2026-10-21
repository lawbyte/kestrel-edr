//! Local "turn protection off" switch (`Engine::set_paused`): every fixture
//! replayed with every builtin rule in Protect must still detect the same
//! things, but no response action of any kind may leave the engine (except
//! resuming a suspended process), every alert is Audit and carries
//! `protection_off`.

mod common;
use common::*;
use kestrel_common::*;
use kestrel_detect::*;
use std::collections::BTreeSet;

fn fixtures() -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
            .unwrap()
            .map(|f| f.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".jsonl"))
            .collect();
    v.sort();
    v
}

/// Replay `name` in an engine, optionally paused, and run the clock well
/// past every suspend window.
fn run(name: &str, paused: Option<PauseMode>) -> Vec<Output> {
    let mut e = engine(policy_all(RuleMode::Protect));
    let _ = e.canaries(r"C:\Users\alice");
    let mut out = e.set_paused(paused);
    let events = fixture(name);
    out.extend(replay(&mut e, &events));
    let last = events.last().map(|e| e.ts).unwrap_or(T0);
    for i in 1..=40 {
        out.extend(e.tick(last + i * 1000));
    }
    out
}

fn action_kinds(out: &[Output]) -> BTreeSet<&'static str> {
    let mut s = BTreeSet::new();
    for o in out {
        match o {
            Output::Action(a) => {
                s.insert(a.name());
            }
            Output::Alert(d) => {
                for a in &d.actions {
                    s.insert(a.name());
                }
            }
        }
    }
    s
}

#[test]
fn detection_only_suppresses_every_action_type() {
    let mut seen_unpaused = BTreeSet::new();
    let mut alerts_total = 0;
    for name in fixtures() {
        let normal = run(&name, None);
        seen_unpaused.extend(action_kinds(&normal));
        for mode in [PauseMode::DetectionOnly, PauseMode::Full] {
            let paused = run(&name, Some(mode));
            // Detection continues: the same rules fire. PS-15 (persistence
            // rollback) only follows a Protect kill, which a pause prevents.
            let ids = |o: &[Output]| -> Vec<String> {
                rule_ids(o).into_iter().filter(|r| r != "PS-15").collect()
            };
            assert_eq!(
                ids(&paused),
                ids(&normal),
                "{name}: paused engine must detect the same things"
            );
            for o in &paused {
                match o {
                    Output::Action(a) => assert!(
                        matches!(a, ResponseAction::ResumeProcess { .. }),
                        "{name}: action {} left a paused engine",
                        a.name()
                    ),
                    Output::Alert(d) => {
                        alerts_total += 1;
                        assert!(d.actions.is_empty(), "{name}: {}", d.alert.rule_id);
                        assert_ne!(d.alert.mode, RuleMode::Protect, "{name}");
                        assert_eq!(d.alert.protection_off, Some(mode), "{name}");
                        assert!(!d.alert.summary.contains("suspended for"), "{name}");
                    }
                }
            }
        }
        // Unpaused alerts never carry the note.
        for d in alerts(&normal) {
            assert_eq!(d.alert.protection_off, None);
        }
    }
    assert!(alerts_total > 50, "fixtures produced too few alerts");
    // The fixtures exercise the response types that matter, so the check
    // above is meaningful for each of them.
    for kind in [
        "kill_process",
        "suspend_process",
        "quarantine_file",
        "block_image_network",
        "block_destination",
        "isolate_host",
        "remove_autorun",
    ] {
        assert!(
            seen_unpaused.contains(kind),
            "no fixture produced {kind} in Protect: {seen_unpaused:?}"
        );
    }
}

#[test]
fn entering_a_pause_releases_suspend_windows() {
    // lumma_clickfix in Protect opens suspend windows (ST-01 / ST-03 / ST-12).
    let mut e = engine(policy_all(RuleMode::Protect));
    let events = fixture("lumma_clickfix.jsonl");
    // Stop before the end so at least one window is still open.
    let mut suspended = BTreeSet::new();
    for ev in &events {
        for o in e.process(ev) {
            if let Output::Alert(d) = &o {
                for a in &d.actions {
                    if let ResponseAction::SuspendProcess { pid, .. } = a {
                        suspended.insert(*pid);
                    }
                }
            }
        }
        if !suspended.is_empty() {
            break;
        }
    }
    assert!(!suspended.is_empty(), "fixture opened no suspend window");
    let outs = e.set_paused(Some(PauseMode::DetectionOnly));
    let resumed: BTreeSet<u32> = outs
        .iter()
        .map(|o| match o {
            Output::Action(ResponseAction::ResumeProcess { pid, .. }) => *pid,
            other => panic!("unexpected output on pause: {other:?}"),
        })
        .collect();
    assert_eq!(resumed, suspended);
    // Nothing is killed later at window expiry.
    let last = events.last().unwrap().ts;
    let later: Vec<Output> = (1..=30).flat_map(|i| e.tick(last + i * 1000)).collect();
    assert!(
        later.iter().all(
            |o| matches!(o, Output::Action(ResponseAction::ResumeProcess { .. }))
                || matches!(o, Output::Alert(d) if d.actions.is_empty())
        ),
        "{}",
        dump(&later)
    );
    assert_eq!(e.paused(), Some(PauseMode::DetectionOnly));
    // Turning back on restores Protect behaviour.
    assert!(e.set_paused(None).is_empty());
    let again = run("lumma_clickfix.jsonl", None);
    assert!(action_kinds(&again).contains("kill_process"));
}
