//! Detection-quality gate over `tests/corpus/` (see `docs/DETECTION-QUALITY.md`).
//!
//! * `malicious/**.jsonl` must meet their sidecar `*.expect.json`
//!   (`must_alert` any-of groups, `min_severity`, `must_not_alert`, `must_act`).
//! * `benign/**` and `benign-lookalike/**` must raise nothing above Low and
//!   ask for no Protect-mode action, except what their expect file lists
//!   (`allow`, `known_false_positives`).
//!
//! Every scenario is replayed twice through a fresh engine (all rules
//! Audit, all rules Protect) with deterministic time. An empty corpus
//! passes; the counts are printed (`cargo test -- --nocapture`).
//!
//! Ratchet: scenarios listed in `tests/corpus/harness-known-failures.json`
//! (detection gaps and false positives that are tracked but not fixed yet)
//! may fail; any other failure fails the test, and so does a listed
//! scenario that passes now or no longer exists (remove it from the list).
//! `KESTREL_CORPUS_NO_BASELINE=1` ignores the list to show the full state.

use kestrel_detect::eval::{load_baseline, load_corpus, CorpusClass, CorpusReport};
use std::path::PathBuf;

fn corpus_root() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "tests", "corpus"]
        .iter()
        .collect()
}

#[test]
fn corpus_gate() {
    let root = corpus_root();
    let scenarios = load_corpus(&root).unwrap_or_else(|e| panic!("corpus: {e}"));
    let mut report = CorpusReport::run(&scenarios);
    let use_baseline = std::env::var_os("KESTREL_CORPUS_NO_BASELINE").is_none();
    let mut unknown = Vec::new();
    if use_baseline {
        let baseline = load_baseline(&root.join("harness-known-failures.json"))
            .unwrap_or_else(|e| panic!("baseline: {e}"));
        unknown = report.apply_baseline(&baseline);
    }
    println!("{}", report.render_text());
    for c in CorpusClass::ALL {
        let (n, p) = report.count(c);
        let known = report
            .outcomes
            .iter()
            .filter(|o| o.class == c && !o.passed && o.baseline.is_some())
            .count();
        println!(
            "corpus {}: {p}/{n} passed, {known} known failure(s)",
            c.dir()
        );
    }
    let failed: Vec<String> = report
        .gate_failures()
        .iter()
        .map(|o| format!("{}: {}", o.name, o.failures.join("; ")))
        .collect();
    let stale: Vec<String> = report
        .stale_baseline()
        .iter()
        .map(|o| o.name.clone())
        .collect();
    assert!(
        failed.is_empty() && stale.is_empty() && unknown.is_empty(),
        "{} corpus scenario(s) failed:\n{}\nbaselined but passing now (remove from harness-known-failures.json): {stale:?}\nbaseline entries without a scenario: {unknown:?}",
        failed.len(),
        failed.join("\n")
    );
}

/// Expect files must not be orphaned (a typo in a scenario name would
/// silently drop its expectations).
#[test]
fn every_expect_file_has_a_scenario() {
    fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.to_string_lossy().ends_with(".expect.json") {
                out.push(p);
            }
        }
    }
    let mut files = Vec::new();
    walk(&corpus_root(), &mut files);
    let orphans: Vec<String> = files
        .iter()
        .filter(|p| {
            let s = p.to_string_lossy();
            let stem = s.trim_end_matches(".expect.json");
            !PathBuf::from(format!("{stem}.jsonl")).exists()
        })
        .map(|p| p.display().to_string())
        .collect();
    assert!(
        orphans.is_empty(),
        "expect files without a scenario: {orphans:?}"
    );
}
