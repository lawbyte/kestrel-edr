//! On-demand YARA-X scanning for the agent's `Scan` action.
//!
//! YARA-X (with wasmtime) is most of the agent's size, yet it is only needed
//! when an analyst asks for a scan. It therefore lives in a separate
//! `kestrel-scan.exe` next to the agent. The agent writes the targets to a
//! file in its SYSTEM-only state directory, runs
//! `kestrel-scan --rules-dir <state>\rules --targets-file <file>`, and reads one
//! JSON [`ScanReport`] from stdout.
//!
//! Rules: a small embedded baseline (generic stealer traits) plus every
//! `*.yar` / `*.yara` file in the rules directory (custom rules from the
//! agent's `RuleBundle`).

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Files larger than this are skipped.
pub const MAX_SCAN_BYTES: u64 = 600 * 1024 * 1024;
/// At most this many targets per run.
pub const MAX_TARGETS: usize = 5000;

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

/// Result of one scanner run (the JSON the scanner prints on stdout).
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct ScanReport {
    pub scanned: u32,
    pub custom_rule_files: u32,
    /// `"<path> → <namespace>:<rule>, …"` per matching file.
    pub hits: Vec<String>,
    pub errors: Vec<String>,
    pub rule_errors: Vec<String>,
}

impl ScanReport {
    /// One-line summary for `ActionOutcome.detail`.
    pub fn render(&self) -> String {
        let mut d = format!(
            "YARA-X scanned {} file(s) with baseline + {} custom rule file(s): ",
            self.scanned, self.custom_rule_files
        );
        if self.hits.is_empty() {
            d.push_str("no matches");
        } else {
            d.push_str(&format!(
                "{} match(es): {}",
                self.hits.len(),
                self.hits.join("; ")
            ));
        }
        if !self.errors.is_empty() {
            d.push_str(&format!("; errors: {}", self.errors.join("; ")));
        }
        if !self.rule_errors.is_empty() {
            d.push_str(&format!("; rule errors: {}", self.rule_errors.join("; ")));
        }
        d
    }
}

/// Targets file format: one path per line; blank lines ignored; capped at
/// [`MAX_TARGETS`].
pub fn parse_targets(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(MAX_TARGETS)
        .map(str::to_string)
        .collect()
}

/// Custom rule files in `dir` (`*.yar`, `*.yara`), sorted for stable namespaces.
pub fn rule_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(dir)
        .map(|rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .map(|x| x.to_string_lossy().to_ascii_lowercase())
                        .is_some_and(|x| x == "yar" || x == "yara")
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Compile the baseline + custom rules and scan `targets`.
#[cfg(feature = "engine")]
pub fn scan(rules_dir: &Path, targets: &[String]) -> anyhow::Result<ScanReport> {
    use std::time::Duration;
    let mut r = ScanReport::default();
    let mut compiler = yara_x::Compiler::new();
    compiler
        .add_source(BASELINE_RULES)
        .map_err(|e| anyhow::anyhow!("baseline YARA rules failed to compile: {e}"))?;
    for (i, p) in rule_files(rules_dir).iter().enumerate() {
        match std::fs::read_to_string(p) {
            Ok(src) => {
                compiler.new_namespace(&format!("custom_{i}"));
                match compiler.add_source(src.as_str()) {
                    Ok(_) => r.custom_rule_files += 1,
                    Err(e) => r.rule_errors.push(format!("{}: {e}", p.display())),
                }
            }
            Err(e) => r.rule_errors.push(format!("{}: {e}", p.display())),
        }
    }
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(30));
    for t in targets.iter().take(MAX_TARGETS) {
        match std::fs::metadata(t) {
            Ok(m) if m.is_file() && m.len() <= MAX_SCAN_BYTES => {}
            Ok(m) if m.is_file() => {
                r.errors.push(format!(
                    "{t}: skipped ({} MB > limit)",
                    m.len() / (1024 * 1024)
                ));
                continue;
            }
            Ok(_) => continue,
            Err(e) => {
                r.errors.push(format!("{t}: {e}"));
                continue;
            }
        }
        r.scanned += 1;
        match scanner.scan_file(t) {
            Ok(res) => {
                let names: Vec<String> = res
                    .matching_rules()
                    .map(|m| format!("{}:{}", m.namespace(), m.identifier()))
                    .collect();
                if !names.is_empty() {
                    r.hits.push(format!("{t} → {}", names.join(", ")));
                }
            }
            Err(e) => r.errors.push(format!("{t}: {e}")),
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_renders_like_the_in_process_scanner() {
        let r = ScanReport {
            scanned: 2,
            custom_rule_files: 1,
            hits: vec![r"C:\x.exe → default:Kestrel_Exfil_DeadDrops".into()],
            ..Default::default()
        };
        assert_eq!(
            r.render(),
            r"YARA-X scanned 2 file(s) with baseline + 1 custom rule file(s): 1 match(es): C:\x.exe → default:Kestrel_Exfil_DeadDrops"
        );
        let back: ScanReport = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn targets_file_is_capped_and_trimmed() {
        let s = format!("a\n\n  b  \n{}", "x\n".repeat(MAX_TARGETS + 10));
        let t = parse_targets(&s);
        assert_eq!(t.len(), MAX_TARGETS);
        assert_eq!(&t[..2], ["a", "b"]);
    }

    #[cfg(feature = "engine")]
    #[test]
    fn baseline_and_custom_rules_match() {
        let dir = std::env::temp_dir().join(format!("kestrel-scan-test-{}", std::process::id()));
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        std::fs::write(
            rules.join("custom.yar"),
            "rule Lab_Marker { strings: $m = \"KESTREL-LAB-MARKER\" condition: $m }",
        )
        .unwrap();
        std::fs::write(rules.join("broken.yara"), "rule {").unwrap();
        let f1 = dir.join("deaddrop.txt");
        // Split so this test binary itself does not carry the joined strings.
        let a = ["api.telegram", ".org/bot123"].concat();
        let b = ["discord.com/api/", "webhooks/1/x"].concat();
        std::fs::write(&f1, format!("{a}\n{b}\n")).unwrap();
        let f2 = dir.join("marker.txt");
        std::fs::write(&f2, ["KESTREL-LAB", "-MARKER"].concat()).unwrap();
        let r = scan(
            &rules,
            &[
                f1.display().to_string(),
                f2.display().to_string(),
                dir.join("missing.bin").display().to_string(),
            ],
        )
        .unwrap();
        assert_eq!(r.scanned, 2);
        assert_eq!(r.custom_rule_files, 1);
        assert_eq!(r.rule_errors.len(), 1, "{:?}", r.rule_errors);
        assert!(
            r.hits.iter().any(|h| h.contains("Kestrel_Exfil_DeadDrops")),
            "{r:?}"
        );
        assert!(r.hits.iter().any(|h| h.contains("Lab_Marker")), "{r:?}");
        assert_eq!(r.errors.len(), 1, "missing file reported");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
