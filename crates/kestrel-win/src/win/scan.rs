#![cfg_attr(not(feature = "yara"), allow(dead_code))]
//! On-demand YARA-X scanning for the `Scan` action.
//!
//! Rules: a small embedded baseline (generic stealer traits) plus every
//! `*.yar` / `*.yara` file in `<state>\rules\` — the agent writes custom YARA
//! rules from its `RuleBundle` there (the `Platform` trait has no rule
//! channel; see report).

use std::path::{Path, PathBuf};

pub const MAX_SCAN_BYTES: u64 = 600 * 1024 * 1024;

pub const BASELINE_RULES: &str = r#"
rule Kestrel_Stealer_BrowserStoreStrings {
  meta:
    description = "PE referencing several browser credential stores and DPAPI"
    author = "Kestrel EDR"
  strings:
    $a1 = "Login Data" ascii wide
    $a2 = "Local State" ascii wide
    $a3 = "Web Data" ascii wide
    $a4 = "key4.db" ascii wide nocase
    $a5 = "logins.json" ascii wide nocase
    $a6 = "Network\\Cookies" ascii wide
    $d1 = "CryptUnprotectData" ascii
    $d2 = "encrypted_key" ascii wide
    $d3 = "app_bound_encrypted_key" ascii wide
  condition:
    uint16(0) == 0x5A4D and 3 of ($a*) and 1 of ($d*)
}

rule Kestrel_Stealer_WalletAndMessengerTargets {
  meta:
    description = "PE referencing crypto-wallet extension ids and messenger session stores"
    author = "Kestrel EDR"
  strings:
    $w1 = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
    $w2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
    $w3 = "Local Extension Settings" ascii wide
    $m1 = "\\Telegram Desktop\\tdata" ascii wide nocase
    $m2 = "discord\\Local Storage\\leveldb" ascii wide nocase
    $m3 = "ssfn" ascii wide
  condition:
    uint16(0) == 0x5A4D and (2 of ($w*)) and 1 of ($m*)
}

rule Kestrel_Exfil_DeadDrops {
  meta:
    description = "Executable or script with Telegram/Steam/Discord dead-drop or exfil endpoints"
    author = "Kestrel EDR"
  strings:
    $t = "api.telegram.org/bot" ascii wide nocase
    $s = "steamcommunity.com/profiles/" ascii wide nocase
    $d = "discord.com/api/webhooks/" ascii wide nocase
    $b = "bsc-dataseed" ascii wide nocase
  condition:
    2 of them
}

rule Kestrel_ClickFix_Script {
  meta:
    description = "Script content typical of paste-and-run (ClickFix) lures"
    author = "Kestrel EDR"
  strings:
    $c1 = "I am not a robot" ascii wide nocase
    $c2 = "verification" ascii wide nocase
    $p1 = "-w h" ascii wide nocase
    $p2 = "iex" ascii wide nocase
    $p3 = "FromBase64String" ascii wide nocase
    $p4 = "mshta" ascii wide nocase
  condition:
    filesize < 2MB and 1 of ($c*) and 2 of ($p*)
}
"#;

pub fn rules_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("rules")
}

#[cfg(feature = "yara")]
pub fn scan(state_dir: &Path, targets: &[String]) -> (bool, String) {
    use std::time::Duration;
    let mut compiler = yara_x::Compiler::new();
    if let Err(e) = compiler.add_source(BASELINE_RULES) {
        return (false, format!("baseline YARA rules failed to compile: {e}"));
    }
    let mut custom_errors = Vec::new();
    let mut custom = 0;
    if let Ok(rd) = std::fs::read_dir(rules_dir(state_dir)) {
        for e in rd.flatten() {
            let p = e.path();
            let ext = p
                .extension()
                .map(|x| x.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if ext != "yar" && ext != "yara" {
                continue;
            }
            match std::fs::read_to_string(&p) {
                Ok(src) => {
                    compiler.new_namespace(&format!("custom_{custom}"));
                    match compiler.add_source(src.as_str()) {
                        Ok(_) => custom += 1,
                        Err(er) => custom_errors.push(format!("{}: {er}", p.display())),
                    }
                }
                Err(er) => custom_errors.push(format!("{}: {er}", p.display())),
            }
        }
    }
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(30));
    let mut hits = Vec::new();
    let mut errors = Vec::new();
    let mut scanned = 0;
    for t in targets {
        match std::fs::metadata(t) {
            Ok(m) if m.is_file() && m.len() <= MAX_SCAN_BYTES => {}
            Ok(m) if m.is_file() => {
                errors.push(format!(
                    "{t}: skipped ({} MB > limit)",
                    m.len() / (1024 * 1024)
                ));
                continue;
            }
            Ok(_) => continue,
            Err(e) => {
                errors.push(format!("{t}: {e}"));
                continue;
            }
        }
        scanned += 1;
        match scanner.scan_file(t) {
            Ok(r) => {
                let names: Vec<String> = r
                    .matching_rules()
                    .map(|m| format!("{}:{}", m.namespace(), m.identifier()))
                    .collect();
                if !names.is_empty() {
                    hits.push(format!("{t} → {}", names.join(", ")));
                }
            }
            Err(e) => errors.push(format!("{t}: {e}")),
        }
    }
    let mut detail =
        format!("YARA-X scanned {scanned} file(s) with baseline + {custom} custom rule file(s): ");
    if hits.is_empty() {
        detail.push_str("no matches");
    } else {
        detail.push_str(&format!("{} match(es): {}", hits.len(), hits.join("; ")));
    }
    if !errors.is_empty() {
        detail.push_str(&format!("; errors: {}", errors.join("; ")));
    }
    if !custom_errors.is_empty() {
        detail.push_str(&format!("; rule errors: {}", custom_errors.join("; ")));
    }
    (true, detail)
}

#[cfg(not(feature = "yara"))]
pub fn scan(_state_dir: &Path, _targets: &[String]) -> (bool, String) {
    (
        false,
        "YARA scanning not available in this build (kestrel-win built without the `yara` feature)"
            .into(),
    )
}

/// Expand a directory target into files (non-recursive beyond depth 3).
pub fn expand_targets(path: &str) -> Vec<String> {
    let p = Path::new(path);
    if !p.is_dir() {
        return vec![path.to_string()];
    }
    let mut out = Vec::new();
    let mut stack = vec![(p.to_path_buf(), 0)];
    while let Some((d, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let ep = e.path();
            if ep.is_dir() {
                if depth < 3 {
                    stack.push((ep, depth + 1));
                }
            } else if out.len() < 5000 {
                out.push(ep.to_string_lossy().into_owned());
            }
        }
    }
    out
}
