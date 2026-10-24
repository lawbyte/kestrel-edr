//! Shape check of the malicious-behaviour corpus (`tests/corpus/malicious/`,
//! `tests/corpus/benign-lookalike/`): every replay line parses into
//! [`Event`], streams are time-ordered and every acting process was started
//! before it acts, and every sidecar `*.expect.json` is well-formed (rule ids
//! exist in the catalog, severities parse, sources are URLs).
//!
//! Detection pass/fail is judged by the corpus gate (`corpus_eval.rs`), not
//! here. `corpus_informative_replay` (ignored) prints what the current engine
//! raises for each scenario:
//! `cargo test -p kestrel-detect --test corpus_parse -- --ignored --nocapture`.

use kestrel_common::*;
use kestrel_detect::*;
use serde_json::Value;
use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};

const DIRS: [&str; 2] = ["malicious", "benign-lookalike"];

fn corpus_dir(sub: &str) -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "corpus", sub]
        .iter()
        .collect()
}

fn files(dir: &Path, suffix: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().ends_with(suffix))
        .collect();
    v.sort();
    v
}

fn stem(p: &Path, suffix: &str) -> String {
    let n = p.file_name().unwrap().to_string_lossy();
    n.trim_end_matches(suffix).to_string()
}

fn load_events(p: &Path) -> Vec<Event> {
    let s = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    s.lines()
        .enumerate()
        .filter(|(_, l)| !l.trim().is_empty())
        .map(|(i, l)| {
            serde_json::from_str::<Event>(l)
                .unwrap_or_else(|e| panic!("{}:{}: {e}\n{l}", p.display(), i + 1))
        })
        .collect()
}

fn rule_ids() -> HashSet<String> {
    Engine::catalog().into_iter().map(|m| m.id).collect()
}

fn severity(v: &Value, ctx: &str) -> Severity {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: severity must be a string"));
    serde_json::from_value(Value::String(s.to_string()))
        .unwrap_or_else(|_| panic!("{ctx}: bad severity {s:?}"))
}

fn check_rule(r: &Value, ids: &HashSet<String>, ctx: &str) {
    let r = r
        .as_str()
        .unwrap_or_else(|| panic!("{ctx}: rule id must be a string"));
    assert!(
        ids.contains(r) || r.starts_with("IOC-") || r.starts_with("SIG-"),
        "{ctx}: unknown rule id {r}"
    );
}

fn check_rule_list(v: &Value, ids: &HashSet<String>, ctx: &str) {
    let a = v
        .as_array()
        .unwrap_or_else(|| panic!("{ctx}: must be an array"));
    for r in a {
        check_rule(r, ids, ctx);
    }
}

/// `must_alert` group: rule id, non-empty any-of array, or
/// `{"any_of": [...], "min_severity": "..."}`.
fn check_group(g: &Value, ids: &HashSet<String>, ctx: &str) {
    match g {
        Value::String(_) => check_rule(g, ids, ctx),
        Value::Array(a) => {
            assert!(!a.is_empty(), "{ctx}: empty any-of group");
            for r in a {
                check_rule(r, ids, ctx);
            }
        }
        Value::Object(m) => {
            for k in m.keys() {
                assert!(
                    matches!(k.as_str(), "any_of" | "min_severity"),
                    "{ctx}: unknown group key {k}"
                );
            }
            let any = m
                .get("any_of")
                .unwrap_or_else(|| panic!("{ctx}: group without any_of"));
            assert!(
                any.as_array().is_some_and(|a| !a.is_empty()),
                "{ctx}: empty any_of"
            );
            check_rule_list(any, ids, ctx);
            if let Some(s) = m.get("min_severity") {
                severity(s, ctx);
            }
        }
        _ => panic!("{ctx}: bad must_alert group {g}"),
    }
}

fn check_text(m: &serde_json::Map<String, Value>, k: &str, ctx: &str) {
    let s = m
        .get(k)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{ctx}: missing string {k}"));
    assert!(!s.trim().is_empty(), "{ctx}: empty {k}");
}

fn check_sources(m: &serde_json::Map<String, Value>, ctx: &str) {
    let a = m
        .get("sources")
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("{ctx}: missing sources"));
    assert!(!a.is_empty(), "{ctx}: no sources");
    for u in a {
        let u = u
            .as_str()
            .unwrap_or_else(|| panic!("{ctx}: source must be a string"));
        assert!(
            u.starts_with("https://") || u.starts_with("http://"),
            "{ctx}: source {u} is not a URL"
        );
    }
}

fn check_expect(p: &Path, malicious: bool, ids: &HashSet<String>) -> Value {
    let ctx = p.display().to_string();
    let s = std::fs::read_to_string(p).unwrap_or_else(|e| panic!("{ctx}: {e}"));
    let v: Value = serde_json::from_str(&s).unwrap_or_else(|e| panic!("{ctx}: {e}"));
    let m = v
        .as_object()
        .unwrap_or_else(|| panic!("{ctx}: not an object"));
    let allowed: &[&str] = if malicious {
        &[
            "must_alert",
            "min_severity",
            "must_act",
            "should_alert",
            "family",
            "category",
            "evasion_targets",
            "known_gap",
            "sources",
            "notes",
        ]
    } else {
        &[
            "must_not_alert",
            "allow",
            "max_severity",
            "family",
            "category",
            "sources",
            "notes",
        ]
    };
    for k in m.keys() {
        assert!(allowed.contains(&k.as_str()), "{ctx}: unexpected key {k}");
    }
    check_text(m, "family", &ctx);
    check_text(m, "notes", &ctx);
    check_sources(m, &ctx);
    if malicious {
        let groups = m
            .get("must_alert")
            .and_then(|g| g.as_array())
            .unwrap_or_else(|| panic!("{ctx}: missing must_alert"));
        assert!(!groups.is_empty(), "{ctx}: empty must_alert");
        for g in groups {
            check_group(g, ids, &ctx);
        }
        severity(
            m.get("min_severity")
                .unwrap_or_else(|| panic!("{ctx}: missing min_severity")),
            &ctx,
        );
        if let Some(s) = m.get("should_alert") {
            check_rule_list(s, ids, &ctx);
        }
        if let Some(a) = m.get("must_act") {
            let a = a
                .as_array()
                .unwrap_or_else(|| panic!("{ctx}: must_act must be an array"));
            for x in a {
                assert!(
                    matches!(
                        x.as_str(),
                        Some(
                            "kill_process"
                                | "block_destination"
                                | "block_image_network"
                                | "quarantine_file"
                                | "isolate_host"
                                | "remove_autorun"
                                | "suspend_process"
                        )
                    ),
                    "{ctx}: unknown action {x}"
                );
            }
        }
        if let Some(e) = m.get("evasion_targets") {
            assert!(
                e.as_array()
                    .is_some_and(|a| a.iter().all(|x| x.is_string())),
                "{ctx}: evasion_targets"
            );
        }
    } else {
        check_rule_list(
            m.get("must_not_alert")
                .unwrap_or_else(|| panic!("{ctx}: missing must_not_alert")),
            ids,
            &ctx,
        );
        if let Some(a) = m.get("allow") {
            for x in a
                .as_array()
                .unwrap_or_else(|| panic!("{ctx}: allow must be an array"))
            {
                let o = x
                    .as_object()
                    .unwrap_or_else(|| panic!("{ctx}: allow entry must be an object"));
                check_rule(o.get("rule").unwrap_or(&Value::Null), ids, &ctx);
                if let Some(s) = o.get("max_severity") {
                    severity(s, &ctx);
                }
            }
        }
        if let Some(s) = m.get("max_severity") {
            severity(s, &ctx);
        }
    }
    v
}

fn check_stream(p: &Path, events: &[Event]) {
    let ctx = p.display().to_string();
    assert!(!events.is_empty(), "{ctx}: empty replay");
    let mut started: HashSet<&str> = HashSet::new();
    let mut last = i64::MIN;
    for (i, e) in events.iter().enumerate() {
        assert!(e.ts >= last, "{ctx}: event {} goes back in time", i + 1);
        last = e.ts;
        assert!(!e.guid.0.is_empty(), "{ctx}: event {} without guid", i + 1);
        match &e.data {
            EventData::ProcessStart(ps) => {
                assert!(
                    !ps.image.is_empty(),
                    "{ctx}: process_start {} without image",
                    i + 1
                );
                if let Some(pg) = &ps.parent_guid {
                    assert!(
                        started.contains(pg.0.as_str()),
                        "{ctx}: event {} names parent {} before it started",
                        i + 1,
                        pg.0
                    );
                }
                started.insert(e.guid.0.as_str());
            }
            _ => assert!(
                started.contains(e.guid.0.as_str()),
                "{ctx}: event {} ({}) by {} before its process_start",
                i + 1,
                e.kind().as_str(),
                e.guid.0
            ),
        }
    }
}

#[test]
fn corpus_files_parse_and_expectations_are_well_formed() {
    let ids = rule_ids();
    let mut total = 0;
    for sub in DIRS {
        let dir = corpus_dir(sub);
        let replays = files(&dir, ".jsonl");
        let expects = files(&dir, ".expect.json");
        let a: BTreeSet<String> = replays.iter().map(|p| stem(p, ".jsonl")).collect();
        let b: BTreeSet<String> = expects.iter().map(|p| stem(p, ".expect.json")).collect();
        assert_eq!(
            a.symmetric_difference(&b).collect::<Vec<_>>(),
            Vec::<&String>::new(),
            "{sub}: every replay needs exactly one expect file"
        );
        for p in &replays {
            check_stream(p, &load_events(p));
        }
        for p in &expects {
            check_expect(p, sub == "malicious", &ids);
        }
        total += replays.len();
        println!("{sub}: {} scenarios", replays.len());
    }
    let mal = files(&corpus_dir("malicious"), ".jsonl").len();
    assert!(mal >= 60, "at least 60 malicious scenarios (have {mal})");
    assert!(total > mal, "benign look-alikes present");
}

// ------------------------------------------------------------- informative

fn host() -> HostContext {
    HostContext {
        boot_id: "boot-1".into(),
        hostname: "CORPUS-01".into(),
        agent_image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
        agent_pid: 0,
        server_ips: vec!["203.0.113.10".into()],
        system_drive: Some('c'),
    }
}

fn policy_all(mode: RuleMode) -> Policy {
    let mut p = Policy::default();
    for m in Engine::catalog() {
        p.rules.insert(m.id.clone(), mode);
    }
    p
}

fn run(events: &[Event], mode: RuleMode) -> Vec<Output> {
    let mut e = Engine::new(host(), policy_all(mode), RuleBundle::default()).unwrap();
    let mut out: Vec<Output> = Vec::new();
    for ev in events {
        out.extend(e.process(ev));
    }
    let end = events.last().map(|e| e.ts).unwrap_or(0);
    out.extend(e.tick(end + 120_000));
    out
}

fn fired(out: &[Output]) -> Vec<(String, Severity, bool)> {
    out.iter()
        .filter_map(|o| match o {
            Output::Alert(d) => Some((
                d.alert.rule_id.clone(),
                d.alert.severity,
                d.alert.mode == RuleMode::Protect && !d.actions.is_empty(),
            )),
            _ => None,
        })
        .collect()
}

fn group_rules(g: &Value) -> (Vec<String>, Option<Severity>) {
    match g {
        Value::String(s) => (vec![s.clone()], None),
        Value::Array(a) => (
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            None,
        ),
        Value::Object(m) => (
            m["any_of"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            m.get("min_severity").map(|s| severity(s, "group")),
        ),
        _ => (vec![], None),
    }
}

/// Informative only: what the current engine raises for each scenario
/// (all rules Audit for alerts, all rules Protect for actions).
#[test]
#[ignore]
fn corpus_informative_replay() {
    let ids = rule_ids();
    let (mut ok, mut miss) = (0, Vec::new());
    for sub in DIRS {
        let malicious = sub == "malicious";
        for p in files(&corpus_dir(sub), ".jsonl") {
            let name = stem(&p, ".jsonl");
            let x = check_expect(
                &corpus_dir(sub).join(format!("{name}.expect.json")),
                malicious,
                &ids,
            );
            let ev = load_events(&p);
            let audit = fired(&run(&ev, RuleMode::Audit));
            let protect = fired(&run(&ev, RuleMode::Protect));
            let mut seen: Vec<String> = Vec::new();
            for (r, s, _) in &audit {
                let t = format!("{r}/{}", s.as_str());
                if !seen.contains(&t) {
                    seen.push(t);
                }
            }
            let killed = run(&ev, RuleMode::Protect).iter().any(|o| match o {
                Output::Alert(d) => d.actions.iter().any(|a| a.name() == "kill_process"),
                Output::Action(a) => a.name() == "kill_process",
            });
            let mut problems = Vec::new();
            if malicious {
                let top = severity(&x["min_severity"], &name);
                for g in x["must_alert"].as_array().unwrap() {
                    let (rules, min) = group_rules(g);
                    let min = min.unwrap_or(top);
                    if !audit.iter().any(|(r, s, _)| rules.contains(r) && *s >= min) {
                        problems.push(format!("missing {rules:?} >= {}", min.as_str()));
                    }
                }
                if x.get("must_act").is_some() && !killed {
                    problems.push("no kill_process in Protect run".into());
                }
            } else {
                for r in x["must_not_alert"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter_map(|r| r.as_str())
                {
                    if audit.iter().any(|(a, _, _)| a == r) {
                        problems.push(format!("forbidden {r}"));
                    }
                }
                let allow: Vec<(String, Severity)> = x
                    .get("allow")
                    .and_then(|a| a.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|o| {
                                (
                                    o["rule"].as_str().unwrap().to_string(),
                                    severity(&o["max_severity"], &name),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                for (r, s, _) in &audit {
                    if !allow.iter().any(|(a, m)| a == r && s <= m) && *s > Severity::Info {
                        problems.push(format!("unlisted {r}/{}", s.as_str()));
                    }
                }
                if protect
                    .iter()
                    .any(|(r, _, acted)| *acted && !allow.iter().any(|(a, _)| a == r))
                {
                    problems.push("Protect action on benign data".into());
                }
            }
            let verdict = if problems.is_empty() { "ok  " } else { "MISS" };
            println!(
                "{verdict} {sub}/{name}: fired [{}]{}",
                seen.join(", "),
                if problems.is_empty() {
                    String::new()
                } else {
                    format!(" -- {}", problems.join("; "))
                }
            );
            if problems.is_empty() {
                ok += 1;
            } else {
                miss.push(format!("{sub}/{name}"));
            }
        }
    }
    println!("\n{ok} as expected, {} not: {miss:#?}", miss.len());
}
