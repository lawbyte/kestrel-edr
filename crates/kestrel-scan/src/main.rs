//! `kestrel-scan --rules-dir <dir> --targets-file <file>`: scan the listed
//! files with the baseline + custom YARA-X rules and print one JSON
//! `ScanReport` on stdout. Started by the agent for the `Scan` action.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

fn main() {
    match run() {
        Ok(json) => println!("{json}"),
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<String> {
    let mut rules_dir: Option<PathBuf> = None;
    let mut targets_file: Option<PathBuf> = None;
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--rules-dir") => rules_dir = args.next().map(PathBuf::from),
            Some("--targets-file") => targets_file = args.next().map(PathBuf::from),
            Some("--version") => return Ok(format!("kestrel-scan {}", env!("CARGO_PKG_VERSION"))),
            _ => bail!("usage: kestrel-scan --rules-dir <dir> --targets-file <file>"),
        }
    }
    let (Some(rules_dir), Some(targets_file)) = (rules_dir, targets_file) else {
        bail!("usage: kestrel-scan --rules-dir <dir> --targets-file <file>");
    };
    let targets = kestrel_scan::parse_targets(
        &std::fs::read_to_string(&targets_file)
            .with_context(|| format!("reading {}", targets_file.display()))?,
    );
    let report = kestrel_scan::scan(&rules_dir, &targets)?;
    Ok(serde_json::to_string(&report)?)
}
