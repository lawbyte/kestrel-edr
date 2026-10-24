//! Detection evaluation CLI (see `docs/DETECTION-QUALITY.md`).
//!
//! ```text
//! cargo run -p kestrel-detect --release --example eval -- run <export.jsonl[.zst]>
//!     [--policies audit,protect,default] [--json report.json] [--alerts alerts.jsonl]
//!     [--top 5] [--limit N]
//! cargo run -p kestrel-detect --example eval -- corpus [dir] [--json out.json]
//! cargo run -p kestrel-detect --release --example eval -- slice <export> --alerts alerts.jsonl
//!     --out <dir> [--max-alert-slices 32] [--max-events 200]
//!     [--replace <user>=j.doe --replace <host>=WS-01 ...] [--signatures sig.jsonl]
//!     [--sample name=guid@ts ...] [--no-samples]
//! cargo run -p kestrel-detect --example eval -- scan <dir> [--needle <user> ...]
//! ```
//!
//! Personal identifiers (user, host, account names) are passed on the
//! command line and never written into this file.
//!
//! `run` streams a telemetry export (one `Event` JSON per line, the `raw`
//! column of the server's ClickHouse table; `repeat_count` rows expanded)
//! through one fresh engine per policy and prints per-rule counts.
//! `slice` cuts short, anonymised scenario slices around alerts and around
//! samples of normal activity, and writes a draft `.expect.json` for each
//! from its own replay. `scan` flags anything in a slice folder that looks
//! like personal data or a secret. Output of `run` / `slice` contains raw
//! personal telemetry unless anonymised: keep it outside the repository.

use kestrel_common::{Event, EventData, Policy, Severity};
use kestrel_detect::eval::{
    self, eval_host, named_policy, parse_line, AlertRecord, CorpusReport, Replayer, RunReport,
    SeedBuilder, Seeds,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};

type Res<T> = Result<T, String>;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let r = match args.first().map(String::as_str) {
        Some("run") => cmd_run(&args[1..]),
        Some("corpus") => cmd_corpus(&args[1..]),
        Some("slice") => cmd_slice(&args[1..]),
        Some("scan") => cmd_scan(&args[1..]),
        _ => Err("usage: eval run|corpus|slice|scan … (see the file header)".into()),
    };
    if let Err(e) = r {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ------------------------------------------------------------------ args

struct Args {
    positional: Vec<String>,
    opts: BTreeMap<String, Vec<String>>,
    flags: HashSet<String>,
}

fn parse_args(a: &[String], with_value: &[&str]) -> Args {
    let mut out = Args {
        positional: vec![],
        opts: BTreeMap::new(),
        flags: HashSet::new(),
    };
    let mut i = 0;
    while i < a.len() {
        let s = &a[i];
        if let Some(k) = s.strip_prefix("--") {
            if with_value.contains(&k) && i + 1 < a.len() {
                out.opts
                    .entry(k.to_string())
                    .or_default()
                    .push(a[i + 1].clone());
                i += 2;
                continue;
            }
            out.flags.insert(k.to_string());
        } else {
            out.positional.push(s.clone());
        }
        i += 1;
    }
    out
}

impl Args {
    fn one(&self, k: &str) -> Option<&str> {
        self.opts.get(k).and_then(|v| v.last()).map(String::as_str)
    }
    fn num(&self, k: &str, d: usize) -> usize {
        self.one(k).and_then(|v| v.parse().ok()).unwrap_or(d)
    }
}

/// Line reader over a `.jsonl` or `.jsonl.zst` file.
fn open_lines(path: &Path) -> Res<Box<dyn BufRead>> {
    let f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let r: Box<dyn Read> = if path.extension().is_some_and(|x| x == "zst") {
        Box::new(zstd::stream::read::Decoder::new(f).map_err(|e| e.to_string())?)
    } else {
        Box::new(f)
    };
    Ok(Box::new(BufReader::with_capacity(1 << 20, r)))
}

/// Stream events (repeat rows expanded) with their sequence number.
fn for_each_event(path: &Path, limit: usize, mut f: impl FnMut(u64, &Event)) -> Res<(u64, u64)> {
    let mut lines = open_lines(path)?;
    let (mut seq, mut bad) = (0u64, 0u64);
    let mut buf = String::new();
    loop {
        buf.clear();
        let n = lines.read_line(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        match parse_line(&buf) {
            Ok(Some((e, count))) => {
                for _ in 0..count {
                    f(seq, &e);
                    seq += 1;
                }
            }
            Ok(None) => {}
            Err(_) => bad += 1,
        }
        if limit > 0 && seq as usize >= limit {
            break;
        }
    }
    Ok((seq, bad))
}

// ------------------------------------------------------------------ run

fn cmd_run(a: &[String]) -> Res<()> {
    let a = parse_args(
        a,
        &[
            "policies",
            "json",
            "alerts",
            "top",
            "limit",
            "agent-image",
            "server-ip",
            "signatures",
        ],
    );
    let input = PathBuf::from(a.positional.first().ok_or("run: missing <export>")?);
    let mut host = eval_host();
    if let Some(i) = a.one("agent-image") {
        host.agent_image = i.into();
    }
    host.server_ips = a.opts.get("server-ip").cloned().unwrap_or_default();
    let names: Vec<String> = a
        .one("policies")
        .unwrap_or("audit,protect,default")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let started = std::time::Instant::now();
    let limit = a.num("limit", 0);
    let seeds = if a.flags.contains("no-seed") {
        Seeds::default()
    } else {
        let mut b = SeedBuilder::default();
        load_signatures(a.one("signatures"), &mut b)?;
        for_each_event(&input, limit, |_, e| b.learn(e))?;
        let s = b.finish();
        eprintln!(
            "seeding: {} processes without process_start, {} images resolved, {} with signature, {} %SystemRoot% assumed Microsoft-signed ({:.1?})",
            s.orphans,
            s.resolved,
            s.with_signature,
            s.assumed_windows_signed,
            started.elapsed()
        );
        s
    };
    let mut runs: Vec<Replayer> = Vec::new();
    for n in &names {
        let p: Policy = named_policy(n).ok_or_else(|| format!("unknown policy {n}"))?;
        runs.push(
            Replayer::new(n, p, host.clone())?
                .with_seeds(seeds.map.clone())
                .with_late_facts(seeds.late_facts.clone()),
        );
    }
    let (n, bad) = for_each_event(&input, limit, |seq, e| {
        for r in runs.iter_mut() {
            r.feed(e);
        }
        if seq > 0 && seq % 1_000_000 == 0 {
            eprintln!("… {seq} events, {:.0?}", started.elapsed());
        }
    })?;
    let reports: Vec<RunReport> = runs.into_iter().map(Replayer::finish).collect();
    eprintln!(
        "{n} events ({bad} unparsable lines) in {:.1?}",
        started.elapsed()
    );
    let top = a.num("top", 5);
    for r in &reports {
        println!("{}", r.render_text(top));
    }
    if let Some(p) = a.one("json") {
        let slim: Vec<serde_json::Value> = reports
            .iter()
            .map(|r| {
                let mut v = serde_json::to_value(r).unwrap_or_default();
                if let Some(m) = v.as_object_mut() {
                    m.remove("alerts");
                    m.remove("standalone");
                }
                v
            })
            .collect();
        let doc = serde_json::json!({ "input_events": n, "unparsable_lines": bad, "runs": slim });
        std::fs::write(
            p,
            serde_json::to_vec_pretty(&doc).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("{p}: {e}"))?;
    }
    if let Some(p) = a.one("alerts") {
        let mut w =
            std::io::BufWriter::new(std::fs::File::create(p).map_err(|e| format!("{p}: {e}"))?);
        for r in &reports {
            for al in &r.alerts {
                let mut v = serde_json::to_value(al).unwrap_or_default();
                if let Some(m) = v.as_object_mut() {
                    m.insert("run".into(), serde_json::json!(r.label));
                }
                writeln!(w, "{v}").map_err(|e| e.to_string())?;
            }
            for s in &r.standalone {
                let v = serde_json::json!({"run": r.label, "standalone": s});
                writeln!(w, "{v}").map_err(|e| e.to_string())?;
            }
        }
    }
    Ok(())
}

/// Optional signature facts for images that only appear as processes
/// running before the agent started: JSON lines `{"image", "signer",
/// "signed"}` (e.g. exported from the server's alerts table).
fn load_signatures(path: Option<&str>, b: &mut SeedBuilder) -> Res<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let mut n = 0;
    for l in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else {
            continue;
        };
        let (Some(image), Some(signed)) = (
            v.get("image").and_then(|x| x.as_str()),
            v.get("signed").and_then(|x| {
                serde_json::from_value::<kestrel_common::SignatureState>(x.clone()).ok()
            }),
        ) else {
            continue;
        };
        let signer = v.get("signer").and_then(|x| x.as_str()).map(String::from);
        b.know_image(image, signer, signed);
        n += 1;
    }
    eprintln!("signatures: {n} images from {path}");
    Ok(())
}

// ------------------------------------------------------------------ corpus

fn cmd_corpus(a: &[String]) -> Res<()> {
    let a = parse_args(a, &["json", "baseline", "write-baseline"]);
    let root = a.positional.first().map(PathBuf::from).unwrap_or_else(|| {
        [env!("CARGO_MANIFEST_DIR"), "tests", "corpus"]
            .iter()
            .collect()
    });
    let sc = eval::load_corpus(&root)?;
    let mut rep = CorpusReport::run(&sc);
    // Known-failures ratchet (same file as the `corpus_eval` test).
    let baseline_path = a
        .one("baseline")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("harness-known-failures.json"));
    let unknown = if a.flags.contains("no-baseline") {
        vec![]
    } else {
        rep.apply_baseline(&eval::load_baseline(&baseline_path)?)
    };
    println!("{}", rep.render_text());
    if let Some(p) = a.one("json") {
        std::fs::write(
            p,
            serde_json::to_vec_pretty(&rep).map_err(|e| e.to_string())?,
        )
        .map_err(|e| format!("{p}: {e}"))?;
    }
    // Draft a baseline from today's failures (first failure as the reason).
    if let Some(p) = a.one("write-baseline") {
        let mut m = serde_json::Map::new();
        m.insert(
            "_comment".into(),
            serde_json::json!("Corpus scenarios that fail today and are tracked, not fixed. Remove an entry when its fix lands (the gate fails while a listed scenario passes). See docs/DETECTION-QUALITY.md."),
        );
        for o in rep.outcomes.iter().filter(|o| !o.passed) {
            let reason = o
                .baseline
                .clone()
                .unwrap_or_else(|| o.failures.first().cloned().unwrap_or_default());
            m.insert(o.name.clone(), serde_json::json!(reason));
        }
        let text = serde_json::to_string_pretty(&serde_json::Value::Object(m))
            .map_err(|e| e.to_string())?;
        std::fs::write(p, text + "\n").map_err(|e| format!("{p}: {e}"))?;
    }
    let gate = rep.gate_failures().len();
    let stale = rep.stale_baseline().len();
    println!(
        "gate: {gate} new failure(s), {stale} baselined scenario(s) passing now, {} baseline entr(ies) without a scenario",
        unknown.len()
    );
    if gate + stale + unknown.len() > 0 {
        return Err("corpus gate failed".into());
    }
    Ok(())
}

// ------------------------------------------------------------------ slice

struct StartInfo {
    parent: Option<String>,
    image: String,
    cmdline: String,
    ts: i64,
}

/// Activity samples: (name, image file names / path fragments, cmdline fragment).
const SAMPLES: &[(&str, &[&str], &str)] = &[
    ("cargo-build", &["\\cargo.exe"], " build"),
    ("cargo-test", &["\\cargo.exe"], " test"),
    ("docker-cli-plugin", &["\\cli-plugins\\"], ""),
    ("docker-cli", &["\\resources\\bin\\docker.exe"], ""),
    ("wsl", &["\\wsl.exe"], ""),
    ("vscode", &["\\code.exe"], ""),
    (
        "office",
        &[
            "\\winword.exe",
            "\\excel.exe",
            "\\powerpnt.exe",
            "\\olk.exe",
            "\\outlook.exe",
        ],
        "",
    ),
    ("brave", &["\\brave.exe"], ""),
    ("edge", &["\\msedge.exe"], ""),
    ("chrome", &["\\chrome.exe"], ""),
    ("nvidia", &["\\nvidia", "\\nvcontainer.exe"], ""),
    ("steam", &["\\steam.exe"], ""),
    ("whatsapp", &["whatsapp"], ""),
    ("discord", &["\\discord.exe"], ""),
    ("roblox", &["\\robloxplayerbeta.exe"], ""),
    ("xeno-executor", &["\\xeno-v1.3.65.exe"], ""),
];

struct Slice {
    name: String,
    anchor: String,
    anchor_ts: i64,
    lo: i64,
    hi: i64,
    members: HashSet<String>,
    ancestors: HashSet<String>,
    /// (seq, mandatory, event)
    events: Vec<(u64, bool, Event)>,
}

const SLICE_CANDIDATE_CAP: usize = 60_000;

fn file_name(p: &str) -> String {
    p.rsplit(['\\', '/'])
        .next()
        .unwrap_or(p)
        .to_ascii_lowercase()
}

fn safe_name(s: &str) -> String {
    let mut o: String = s
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    while o.contains("--") {
        o = o.replace("--", "-");
    }
    o.trim_matches('-').chars().take(48).collect()
}

fn cmd_slice(a: &[String]) -> Res<()> {
    let a = parse_args(
        a,
        &[
            "alerts",
            "out",
            "max-alert-slices",
            "max-events",
            "sample",
            "run",
            "before-ms",
            "after-ms",
            "signatures",
            "replace",
        ],
    );
    let _ = REPLACEMENTS.set(parse_replacements(&a)?);
    let input = PathBuf::from(a.positional.first().ok_or("slice: missing <export>")?);
    let out = PathBuf::from(a.one("out").ok_or("slice: missing --out")?);
    let max_events = a.num("max-events", 200);
    let before = a.num("before-ms", 120_000) as i64;
    let after = a.num("after-ms", 30_000) as i64;
    std::fs::create_dir_all(&out).map_err(|e| e.to_string())?;

    // Pass 1: process starts.
    eprintln!("pass 1: process table");
    let mut starts: HashMap<String, StartInfo> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    let mut seedb = SeedBuilder::default();
    load_signatures(a.one("signatures"), &mut seedb)?;
    let mut activity: HashMap<String, u32> = HashMap::new();
    for_each_event(&input, 0, |_, e| {
        seedb.learn(e);
        *activity.entry(e.guid.0.clone()).or_default() += 1;
        if let EventData::ProcessStart(p) = &e.data {
            if !starts.contains_key(&e.guid.0) {
                order.push(e.guid.0.clone());
            }
            starts.insert(
                e.guid.0.clone(),
                StartInfo {
                    parent: p.parent_guid.as_ref().map(|g| g.0.clone()),
                    image: p.image.to_ascii_lowercase(),
                    cmdline: p
                        .cmdline
                        .chars()
                        .take(300)
                        .collect::<String>()
                        .to_ascii_lowercase(),
                    ts: e.ts,
                },
            );
        }
    })?;
    let seeds = seedb.finish().map;
    let ancestors_of = |g: &str| -> HashSet<String> {
        let mut s = HashSet::new();
        let mut cur = starts.get(g).and_then(|i| i.parent.clone());
        while let Some(p) = cur {
            if s.len() >= 8 || !s.insert(p.clone()) {
                break;
            }
            cur = starts.get(&p).and_then(|i| i.parent.clone());
        }
        s
    };

    let mut slices: Vec<Slice> = Vec::new();
    let mk = |name: String, anchor: &str, t: i64, lo: i64, hi: i64, anc: HashSet<String>| Slice {
        name,
        anchor: anchor.to_string(),
        anchor_ts: t,
        lo,
        hi,
        members: [anchor.to_string()].into_iter().collect(),
        ancestors: anc,
        events: vec![],
    };

    // Alert slices: one per (rule, image file name), highest severity first.
    if let Some(ap) = a.one("alerts") {
        let run = a.one("run").unwrap_or("audit");
        let text = std::fs::read_to_string(ap).map_err(|e| format!("{ap}: {e}"))?;
        let mut groups: BTreeMap<(String, String), (Severity, u64, AlertRecord)> = BTreeMap::new();
        for l in text.lines() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(l) else {
                continue;
            };
            if v.get("run").and_then(|r| r.as_str()) != Some(run) || v.get("rule_id").is_none() {
                continue;
            }
            let Ok(al) = serde_json::from_value::<AlertRecordIn>(v) else {
                continue;
            };
            let key = (al.rule_id.clone(), file_name(&al.image));
            let ent = groups
                .entry(key)
                .or_insert((al.severity, 0, al.clone().into()));
            ent.1 += 1;
            if al.severity > ent.0 {
                ent.0 = al.severity;
                ent.2 = al.into();
            }
        }
        let mut g: Vec<_> = groups.into_iter().collect();
        g.sort_by(|x, y| y.1 .0.cmp(&x.1 .0).then(y.1 .1.cmp(&x.1 .1)));
        for ((rule, img), (_, _, al)) in g.into_iter().take(a.num("max-alert-slices", 32)) {
            let name = format!(
                "alert-{}-{}",
                safe_name(&rule),
                safe_name(img.trim_end_matches(".exe"))
            );
            let anc = ancestors_of(&al.guid);
            slices.push(mk(
                name,
                &al.guid,
                al.ts,
                al.ts - before,
                al.ts + after,
                anc,
            ));
        }
    }
    // Explicit samples: name=guid@ts.
    for s in a.opts.get("sample").cloned().unwrap_or_default() {
        let (name, rest) = s.split_once('=').ok_or("--sample name=guid@ts")?;
        let (guid, ts) = rest.split_once('@').ok_or("--sample name=guid@ts")?;
        let ts: i64 = ts.parse().map_err(|_| "--sample ts")?;
        let anc = ancestors_of(guid);
        slices.push(mk(
            format!("sample-{}", safe_name(name)),
            guid,
            ts,
            ts,
            ts + 30_000,
            anc,
        ));
    }
    // Built-in activity samples: first tree root matching the pattern.
    if !a.flags.contains("no-samples") {
        for (name, pats, cmd) in SAMPLES {
            let m = |g: &str| {
                starts.get(g).is_some_and(|i| {
                    pats.iter().any(|p| i.image.contains(p)) && i.cmdline.contains(cmd)
                })
            };
            // The busiest tree root matching the pattern (a short-lived
            // helper says little about the application).
            let pick = order
                .iter()
                .filter(|g| {
                    m(g) && !starts
                        .get(g.as_str())
                        .and_then(|i| i.parent.as_deref())
                        .is_some_and(m)
                })
                .max_by_key(|g| {
                    (
                        activity.get(g.as_str()).copied().unwrap_or(0).min(5_000),
                        std::cmp::Reverse(starts[g.as_str()].ts),
                    )
                });
            match pick {
                Some(g) => {
                    let t = starts[g].ts;
                    slices.push(mk(
                        format!("sample-{name}"),
                        g,
                        t,
                        t,
                        t + 60_000,
                        ancestors_of(g),
                    ));
                }
                None => eprintln!("sample {name}: no matching process"),
            }
        }
    }
    eprintln!("pass 2: {} slices", slices.len());

    // Pass 2: collect.
    let mut index: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, s) in slices.iter().enumerate() {
        for g in s.members.iter().chain(s.ancestors.iter()) {
            index.entry(g.clone()).or_default().push(i);
        }
    }
    for_each_event(&input, 0, |seq, e| {
        if let EventData::ProcessStart(p) = &e.data {
            if let Some(pg) = &p.parent_guid {
                if let Some(ids) = index.get(&pg.0).cloned() {
                    for i in ids {
                        let s = &mut slices[i];
                        if s.members.contains(&pg.0)
                            && e.ts >= s.lo
                            && e.ts <= s.hi
                            && s.members.insert(e.guid.0.clone())
                        {
                            index.entry(e.guid.0.clone()).or_default().push(i);
                        }
                    }
                }
            }
        }
        let Some(ids) = index.get(&e.guid.0) else {
            return;
        };
        for &i in ids {
            let s = &mut slices[i];
            let is_start = matches!(e.data, EventData::ProcessStart(_));
            if is_start {
                s.events.push((seq, true, e.clone()));
            } else if s.members.contains(&e.guid.0) && e.ts >= s.lo && e.ts <= s.hi {
                let near = e.guid.0 == s.anchor
                    && e.ts >= s.anchor_ts - 15_000
                    && e.ts <= s.anchor_ts + 5_000;
                let mandatory = near || matches!(e.data, EventData::ProcessStop { .. });
                if s.events.len() < SLICE_CANDIDATE_CAP {
                    s.events.push((seq, mandatory, e.clone()));
                }
            }
        }
    })?;

    // Reduce, anonymise, write, and draft expectations.
    let anon = Anon::new();
    let mut written = 0;
    let mut names_seen: HashSet<String> = HashSet::new();
    for s in slices.iter_mut() {
        let mut name = s.name.clone();
        let mut k = 2;
        while !names_seen.insert(name.clone()) {
            name = format!("{}-{k}", s.name);
            k += 1;
        }
        let mut picked = reduce(&mut s.events, max_events, s.anchor_ts);
        // Members that started before the agent: synthesise the start the
        // agent's snapshot would have provided (see `SeedBuilder`).
        let have: HashSet<String> = picked
            .iter()
            .filter(|e| matches!(e.data, EventData::ProcessStart(_)))
            .map(|e| e.guid.0.clone())
            .collect();
        let mut synth = Vec::new();
        let mut done = HashSet::new();
        for e in &picked {
            if have.contains(&e.guid.0) || !done.insert(e.guid.0.clone()) {
                continue;
            }
            if let Some(info) = seeds.get(&e.guid.0) {
                synth.push((e.ts - 1, seed_start(info)));
            }
        }
        for (ts, mut st) in synth {
            st.ts = ts;
            let pos = picked
                .iter()
                .position(|x| x.ts >= ts)
                .unwrap_or(picked.len());
            picked.insert(pos, st);
        }
        let mut lines = Vec::new();
        let mut evs = Vec::new();
        for e in picked {
            if let Some(e) = anon.event(e) {
                lines.push(serde_json::to_string(&e).map_err(|x| x.to_string())?);
                evs.push(e);
            }
        }
        if evs.len() < 2 {
            eprintln!("{name}: too few events, skipped");
            continue;
        }
        let path = out.join(format!("{name}.jsonl"));
        std::fs::write(&path, lines.join("\n") + "\n").map_err(|e| e.to_string())?;
        let expect = draft_expect(&name, &evs)?;
        std::fs::write(out.join(format!("{name}.expect.json")), expect)
            .map_err(|e| e.to_string())?;
        written += 1;
        eprintln!("{name}: {} events", evs.len());
    }
    eprintln!("{written} slices written to {}", out.display());
    Ok(())
}

fn seed_start(i: &kestrel_common::ProcessInfo) -> Event {
    Event {
        ts: i.start_ts,
        pid: i.pid,
        guid: i.guid.clone(),
        data: EventData::ProcessStart(kestrel_common::ProcessStart {
            ppid: i.ppid,
            parent_guid: i.parent_guid.clone(),
            image: i.image.clone(),
            cmdline: i.cmdline.clone(),
            user: i.user.clone(),
            integrity: i.integrity,
            signer: i.signer.clone(),
            signed: i.signed,
            sha256: i.sha256.clone(),
            ..Default::default()
        }),
    }
}

#[derive(Clone, serde::Deserialize)]
struct AlertRecordIn {
    ts: i64,
    rule_id: String,
    severity: Severity,
    guid: String,
    image: String,
}

impl From<AlertRecordIn> for AlertRecord {
    fn from(a: AlertRecordIn) -> AlertRecord {
        AlertRecord {
            ts: a.ts,
            rule_id: a.rule_id,
            rule_name: String::new(),
            severity: a.severity,
            mode: Default::default(),
            pid: 0,
            guid: a.guid,
            image: a.image,
            cmdline: String::new(),
            signer: None,
            signed: Default::default(),
            parent_image: None,
            summary: String::new(),
            actions: vec![],
            data_at_risk: vec![],
            evidence: vec![],
        }
    }
}

/// Keep mandatory events (starts, stops, the anchor's events around the
/// alert) and an even sample of the rest, in stream order.
fn reduce(ev: &mut Vec<(u64, bool, Event)>, max: usize, anchor_ts: i64) -> Vec<Event> {
    ev.sort_by_key(|x| x.0);
    ev.dedup_by_key(|x| x.0);
    let mut keep: Vec<usize> = Vec::new();
    let mut mand: Vec<usize> = (0..ev.len()).filter(|&i| ev[i].1).collect();
    let starts = mand
        .iter()
        .filter(|&&i| matches!(ev[i].2.data, EventData::ProcessStart(_)))
        .count();
    let budget = max.max(starts + 20);
    if mand.len() > budget {
        // Closest to the anchor first, starts always.
        mand.sort_by_key(|&i| {
            let st = matches!(ev[i].2.data, EventData::ProcessStart(_));
            (!st, (ev[i].2.ts - anchor_ts).abs())
        });
        mand.truncate(budget);
    }
    keep.extend(&mand);
    let rest: Vec<usize> = (0..ev.len()).filter(|&i| !ev[i].1).collect();
    let room = budget.saturating_sub(keep.len());
    if room > 0 && !rest.is_empty() {
        let step = (rest.len() as f64 / room as f64).max(1.0);
        let mut f = 0.0;
        while (f as usize) < rest.len() && keep.len() < budget {
            keep.push(rest[f as usize]);
            f += step;
        }
    }
    keep.sort_unstable();
    keep.dedup();
    keep.into_iter().map(|i| ev[i].2.clone()).collect()
}

fn draft_expect(name: &str, evs: &[Event]) -> Res<String> {
    let audit = eval::replay(
        "audit",
        eval::policy_all(kestrel_common::RuleMode::Audit),
        evs,
    )?;
    let protect = eval::replay(
        "protect",
        eval::policy_all(kestrel_common::RuleMode::Protect),
        evs,
    )?;
    let mut max: BTreeMap<String, Severity> = BTreeMap::new();
    for al in &audit.alerts {
        let m = max.entry(al.rule_id.clone()).or_insert(al.severity);
        *m = (*m).max(al.severity);
    }
    let acting: HashSet<String> = protect
        .alerts
        .iter()
        .filter(|a| a.actions.iter().any(|x| x != "resume_process"))
        .map(|a| a.rule_id.clone())
        .collect();
    let mut allow = Vec::new();
    let mut kfp = Vec::new();
    for (r, s) in &max {
        if *s > Severity::Low || acting.contains(r) {
            kfp.push(serde_json::json!({"rule": r, "max_severity": s.as_str(), "note": "TODO"}));
        } else {
            allow.push(serde_json::json!({"rule": r, "max_severity": s.as_str(), "note": "TODO"}));
        }
    }
    let v = serde_json::json!({
        "description": format!("{name}: slice of the owner-PC telemetry 2026-10 (anonymised)"),
        "allow": allow,
        "known_false_positives": kfp,
        "strict": true,
    });
    serde_json::to_string_pretty(&v).map_err(|e| e.to_string())
}

// ------------------------------------------------------------------ anonymisation

struct Anon {
    keep_domains: Vec<String>,
}

/// Infrastructure domains kept verbatim (no personal browsing signal);
/// every other host name becomes `h<hash>.example.net`.
const KEEP_DOMAINS: &[&str] = &[
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "msftconnecttest.com",
    "msftncsi.com",
    "live.com",
    "office.com",
    "office.net",
    "microsoftonline.com",
    "msn.com",
    "bing.com",
    "azure.com",
    "azureedge.net",
    "akamaized.net",
    "akamai.net",
    "akamaiedge.net",
    "trafficmanager.net",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "gvt1.com",
    "brave.com",
    "bravesoftware.com",
    "mozilla.org",
    "nvidia.com",
    "steampowered.com",
    "steamcommunity.com",
    "steamstatic.com",
    "steamserver.net",
    "discord.com",
    "discord.gg",
    "discordapp.com",
    "discordapp.net",
    "roblox.com",
    "rbxcdn.com",
    "whatsapp.net",
    "whatsapp.com",
    "docker.com",
    "docker.io",
    "github.com",
    "githubusercontent.com",
    "crates.io",
    "rust-lang.org",
    "pastebin.com",
    "visualstudio.com",
    "vscode-cdn.net",
    "digicert.com",
];

impl Anon {
    fn new() -> Anon {
        let mut keep: Vec<String> = KEEP_DOMAINS.iter().map(|s| s.to_string()).collect();
        keep.extend(
            Policy::default()
                .exfil_domains
                .iter()
                .map(|d| d.trim_start_matches("*.").to_ascii_lowercase()),
        );
        Anon { keep_domains: keep }
    }

    fn domain(&self, d: &str) -> String {
        let l = d.trim_end_matches('.').to_ascii_lowercase();
        if l.is_empty()
            || l.parse::<std::net::IpAddr>().is_ok()
            || self
                .keep_domains
                .iter()
                .any(|k| l == *k || l.ends_with(&format!(".{k}")))
        {
            return l;
        }
        format!("h{:08x}.example.net", fnv(&l) as u32)
    }

    /// Anonymise one event; `None` drops it (browsing-history paths).
    fn event(&self, mut e: Event) -> Option<Event> {
        match &mut e.data {
            EventData::ProcessStart(p) => {
                p.image = text(&p.image);
                p.cmdline = text(&cmdline(&p.cmdline));
                p.user = p.user.as_deref().map(text);
            }
            EventData::ImageLoad { path, .. } => *path = text(path),
            EventData::FileAccess { path, .. } => {
                if is_browsing_path(path) {
                    return None;
                }
                *path = text(path);
            }
            EventData::RegistrySet { key, data, .. } => {
                *key = text(key);
                *data = data.as_deref().map(|d| text(&cmdline(d)));
            }
            EventData::NetConnect { dst_host, .. } => {
                *dst_host = dst_host.as_deref().map(|h| self.domain(h));
            }
            EventData::DnsQuery { qname, .. } => *qname = self.domain(qname),
            EventData::DpapiUnprotect { description } => *description = text(description),
            EventData::ProcessAccess(t)
            | EventData::RemoteThread(t)
            | EventData::ThreadContext(t)
            | EventData::DebugAttach(t) => t.target_image = text(&t.target_image),
            EventData::ScriptBlock { content, .. } => {
                let c: String = content.chars().take(2_000).collect();
                *content = text(&cmdline(&c));
            }
            EventData::Tamper { detail, .. } => *detail = text(detail),
            EventData::FileActivity(f) => {
                f.sample_paths.retain(|p| !is_browsing_path(p));
                for p in f.sample_paths.iter_mut().chain(f.canary_hits.iter_mut()) {
                    *p = text(p);
                }
                f.note_name = f.note_name.as_deref().map(text);
            }
            EventData::TaskRegistered(t) => {
                t.name = text(&t.name);
                t.user = t.user.as_deref().map(text);
                for a in t.actions.iter_mut() {
                    *a = text(&cmdline(a));
                }
            }
            EventData::ServiceInstalled(s) => {
                s.image_path = text(&cmdline(&s.image_path));
                s.account = s.account.as_deref().map(text);
            }
            EventData::WmiSubscription(w) => {
                w.filter = text(&w.filter);
                w.consumer = text(&w.consumer);
            }
            EventData::ProcessStop { .. } => {}
        }
        Some(e)
    }
}

fn fnv(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Browser storage whose paths name the sites visited (IndexedDB origins,
/// service-worker scopes, history databases). LevelDB / cache file names and
/// credential stores carry no site names and are kept.
fn is_browsing_path(p: &str) -> bool {
    let l = p.to_ascii_lowercase();
    let marker = [
        r"\indexeddb\",
        r"\service worker\",
        r"\file system\",
        r"\blob_storage\",
        r"\shared proto db\",
        r"\sessions\",
        r"\history",
        r"\top sites",
        r"\visited links",
        r"\favicons",
        r"\shortcuts",
        r"\storage\ext\",
    ]
    .iter()
    .any(|m| l.contains(m));
    // Origin-named folders such as `https_www.example.com_0.indexeddb.leveldb`.
    let origin = l
        .split('\\')
        .any(|seg| (seg.starts_with("http_") || seg.starts_with("https_")) && seg.contains('.'));
    marker || origin
}

/// Case-insensitive replace of `from` (ASCII) in `s`.
fn replace_ci(s: &str, from: &str, to: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let f = from.to_ascii_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while let Some(off) = lower[i..].find(&f) {
        out.push_str(&s[i..i + off]);
        out.push_str(to);
        i += off + f.len();
    }
    out.push_str(&s[i..]);
    out
}

/// Personal identifiers to replace (`--replace from=to`, applied in order,
/// case-insensitive): user name, host name, account handles, private
/// folder names. Kept out of the source on purpose.
static REPLACEMENTS: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();

fn parse_replacements(a: &Args) -> Res<Vec<(String, String)>> {
    let mut v = Vec::new();
    for r in a.opts.get("replace").cloned().unwrap_or_default() {
        let (from, to) = r.split_once('=').ok_or("--replace from=to")?;
        if from.is_empty() {
            return Err("--replace: empty pattern".into());
        }
        v.push((from.to_string(), to.to_string()));
    }
    Ok(v)
}

/// Replace personal identifiers: the `--replace` list, e-mail addresses,
/// machine SIDs.
fn text(s: &str) -> String {
    let mut t = s.to_string();
    for (from, to) in REPLACEMENTS.get().map(Vec::as_slice).unwrap_or_default() {
        t = replace_ci(&t, from, to);
    }
    t = emails(&t);
    sids(&t)
}

fn emails(s: &str) -> String {
    if !s.contains('@') {
        return s.to_string();
    }
    let is_local = |c: u8| c.is_ascii_alphanumeric() || b"._%+-".contains(&c);
    let is_dom = |c: u8| c.is_ascii_alphanumeric() || b".-".contains(&c);
    let b = s.as_bytes();
    let (mut out, mut last, mut i) = (String::new(), 0, 0);
    while i < b.len() {
        if b[i] == b'@' {
            let mut k = i;
            while k > last && is_local(b[k - 1]) {
                k -= 1;
            }
            let mut j = i + 1;
            while j < b.len() && is_dom(b[j]) {
                j += 1;
            }
            let dom = s[i + 1..j].trim_end_matches('.');
            if k < i && dom.contains('.') && !dom.starts_with('.') {
                out.push_str(&s[last..k]);
                out.push_str("j.doe@example.com");
                last = j;
                i = j;
                continue;
            }
        }
        i += 1;
    }
    out.push_str(&s[last..]);
    out
}

/// `S-1-5-21-a-b-c-RID` → a fixed machine part.
fn sids(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(i) = rest.find("S-1-5-21-") {
        out.push_str(&rest[..i]);
        let tail = &rest[i + 9..];
        // three sub-authorities
        let mut j = 0;
        let mut parts = 0;
        let b = tail.as_bytes();
        while parts < 3 {
            let st = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if j == st {
                break;
            }
            parts += 1;
            if parts < 3 {
                if j < b.len() && b[j] == b'-' {
                    j += 1;
                } else {
                    break;
                }
            }
        }
        if parts == 3 {
            out.push_str("S-1-5-21-1000000001-1000000002-1000000003");
            rest = &tail[j..];
        } else {
            out.push_str("S-1-5-21-");
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// Split a command line into arguments (double quotes group).
fn split_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    for c in s.chars() {
        match c {
            '"' => {
                q = !q;
                cur.push(c);
            }
            c if c.is_whitespace() && !q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

fn looks_secret(arg: &str) -> bool {
    let l = arg.to_ascii_lowercase();
    if l.contains("://") && (l.contains('?') || l.contains('@')) {
        return true;
    }
    if [
        "token",
        "secret",
        "passw",
        "apikey",
        "api_key",
        "api-key",
        "bearer",
        "auth=",
        "sig=",
        "signature",
        "session",
        "cookie",
        "credential",
        "key=",
        "pat=",
        "kst_",
        "kun_",
        "kse_",
        "kte_",
        "eyj",
    ]
    .iter()
    .any(|m| l.contains(m))
    {
        return true;
    }
    // Long opaque runs (base64 / hex blobs).
    let mut run = 0;
    for c in arg.chars() {
        if c.is_ascii_alphanumeric() || "+/=_-".contains(c) {
            run += 1;
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

/// Drop arguments that carry tokens, URLs with query strings or opaque blobs.
fn cmdline(s: &str) -> String {
    let args = split_args(s);
    if args.len() <= 1 {
        return if args
            .first()
            .is_some_and(|a| looks_secret(a) && a.contains("://"))
        {
            String::new()
        } else {
            s.to_string()
        };
    }
    let mut out = vec![args[0].clone()];
    out.extend(args[1..].iter().filter(|a| !looks_secret(a)).cloned());
    out.join(" ")
}

// ------------------------------------------------------------------ scan

fn cmd_scan(a: &[String]) -> Res<()> {
    let a = parse_args(a, &["needle"]);
    let dir = PathBuf::from(a.positional.first().ok_or("scan: missing <dir>")?);
    let mut files = Vec::new();
    walk(&dir, &mut files);
    // Personal identifiers to look for come from the command line
    // (`--needle <user name>` …), never from the source.
    let extra: Vec<String> = a
        .opts
        .get("needle")
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|n| n.to_ascii_lowercase())
        .collect();
    let mut needles: Vec<&str> = extra.iter().map(String::as_str).collect();
    needles.extend([
        "token",
        "passw",
        "secret",
        "apikey",
        "api_key",
        "bearer",
        "authorization",
        "cookie=",
        "kst_",
        "kun_",
        "eyj",
        "-----begin",
    ]);
    let mut hits = 0;
    for f in files {
        let Ok(s) = std::fs::read_to_string(&f) else {
            continue;
        };
        for (n, line) in s.lines().enumerate() {
            let l = line.to_ascii_lowercase();
            let mut why: Vec<String> = needles
                .iter()
                .filter(|k| l.contains(*k))
                .map(|k| k.to_string())
                .collect();
            if l.contains("://") && l.contains('?') {
                why.push("url-query".into());
            }
            if emails(line) != line {
                why.push("email".into());
            }
            // Long opaque strings other than the sha256 / guid fields.
            let stripped = strip_known_hex(line);
            if looks_blob(&stripped) {
                why.push("blob".into());
            }
            if !why.is_empty() {
                hits += 1;
                let excerpt: String = line.chars().take(220).collect();
                println!("{}:{}: [{}] {excerpt}", f.display(), n + 1, why.join(","));
            }
        }
    }
    println!("{hits} line(s) flagged");
    Ok(())
}

fn walk(d: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(d) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else {
            out.push(p);
        }
    }
}

fn strip_known_hex(line: &str) -> String {
    let Ok(serde_json::Value::Object(mut m)) = serde_json::from_str::<serde_json::Value>(line)
    else {
        return line.to_string();
    };
    for k in ["sha256", "guid", "parent_guid", "target_guid"] {
        m.remove(k);
    }
    serde_json::Value::Object(m).to_string()
}

fn looks_blob(s: &str) -> bool {
    let mut run = 0;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() || "+/=".contains(c) {
            run += 1;
            if run >= 40 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}
