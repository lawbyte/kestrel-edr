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

/// Targets file format: one path per line; blank lines ignored; remote
/// paths ([`is_remote_path`]) dropped; capped at [`MAX_TARGETS`].
pub fn parse_targets(s: &str) -> Vec<String> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !is_remote_path(l))
        .take(MAX_TARGETS)
        .map(str::to_string)
        .collect()
}

/// Is `path` a network location (UNC share, WebDAV `\\host@port\` /
/// `\\host@SSL\`, `\\?\UNC\`, `\\.\UNC\`, `\??\UNC\`, NT `\Device\Mup\`,
/// LanmanRedirector / WebDavRedirector devices, or any other `\\`-rooted
/// path except the local device namespaces `\\?\<X>:\` / `\\.\<X>:\`)?
///
/// Opening such a path as SYSTEM makes the machine account authenticate to
/// the remote host (NTLM coercion → relay to LDAP / AD CS: security review
/// v1.1 V-M1), so the agent never scans, hashes or signature-checks them.
/// Mapped network drive letters cannot be recognised from the string; the
/// Windows glue checks `GetDriveTypeW` for those.
pub fn is_remote_path(path: &str) -> bool {
    let p = path.trim().replace('/', "\\").to_ascii_lowercase();
    for pre in [
        r"\\?\unc\",
        r"\\.\unc\",
        r"\??\unc\",
        r"\device\mup\",
        r"\device\lanmanredirector\",
        r"\device\webdavredirector\",
        r"\device\mailslot\",
    ] {
        if p.starts_with(pre) {
            return true;
        }
    }
    if let Some(rest) = p.strip_prefix(r"\\?\").or_else(|| p.strip_prefix(r"\\.\")) {
        // Local device paths: `\\?\C:\…`, `\\?\Volume{…}\…`; anything else
        // under the device namespace (pipes on other hosts, GLOBALROOT
        // redirections, …) is refused.
        let b = rest.as_bytes();
        let drive = b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':';
        return !(drive || rest.starts_with("volume{"));
    }
    if let Some(rest) = p.strip_prefix(r"\??\") {
        let b = rest.as_bytes();
        return !(b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':');
    }
    // Plain UNC `\\host\share\…` (including `\\host@80\…`, `\\host@ssl\…`).
    p.starts_with(r"\\")
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

/// First line of a compiler diagnostic (`error[E001]: syntax error …`),
/// clipped: the rest of the report quotes rule source, which is never echoed
/// back (V-L10).
pub fn error_headline(diag: &str) -> String {
    let line = diag
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    let mut s: String = line.chars().filter(|c| !c.is_control()).take(160).collect();
    if line.chars().count() > 160 {
        s.push('…');
    }
    s
}

/// Compile the baseline + custom rules and scan `targets`.
#[cfg(feature = "engine")]
pub fn scan(rules_dir: &Path, targets: &[String]) -> anyhow::Result<ScanReport> {
    use std::time::Duration;
    let mut r = ScanReport::default();
    let mut compiler = yara_x::Compiler::new();
    // V-L10: `include` would let a rule author read any file SYSTEM can read
    // (through compile errors); custom rules must be self-contained.
    compiler.enable_includes(false);
    compiler.add_source(BASELINE_RULES).map_err(|e| {
        anyhow::anyhow!(
            "baseline YARA rules failed to compile: {}",
            error_headline(&e.to_string())
        )
    })?;
    for (i, p) in rule_files(rules_dir).iter().enumerate() {
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        match std::fs::read_to_string(p) {
            Ok(src) => {
                compiler.new_namespace(&format!("custom_{i}"));
                match compiler.add_source(src.as_str()) {
                    Ok(_) => r.custom_rule_files += 1,
                    Err(e) => r
                        .rule_errors
                        .push(format!("{name}: {}", error_headline(&e.to_string()))),
                }
            }
            Err(e) => r
                .rule_errors
                .push(format!("{name}: unreadable ({:?})", e.kind())),
        }
    }
    let rules = compiler.build();
    let mut scanner = yara_x::Scanner::new(&rules);
    scanner.set_timeout(Duration::from_secs(30));
    for t in targets.iter().take(MAX_TARGETS) {
        // V-M1: never open network paths as SYSTEM (defence in depth; the
        // agent filters them too).
        if is_remote_path(t) {
            r.errors.push(format!(
                "{t}: skipped (network path; never opened as SYSTEM)"
            ));
            continue;
        }
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
    fn remote_paths_are_recognised() {
        for remote in [
            r"\\attacker\share\a.exe",
            r"\\attacker@80\x\a.exe",
            r"\\attacker@SSL@443\DavWWWRoot\a.exe",
            r"//attacker/share/a.exe",
            r"\\?\UNC\attacker\share\a.exe",
            r"\\.\UNC\attacker\share\a.exe",
            r"\??\UNC\attacker\share\a.exe",
            r"\Device\Mup\attacker\share\a.exe",
            r"\device\mup\;LanmanRedirector\attacker\s\a.exe",
            r"\Device\LanmanRedirector\attacker\s\a.exe",
            r"\Device\WebDavRedirector\attacker\a.exe",
            r"\\?\GLOBALROOT\Device\Mup\attacker\a.exe",
            r"\\.\pipe\x",
            r"  \\host\s\x  ",
        ] {
            assert!(is_remote_path(remote), "{remote}");
        }
        for local in [
            r"C:\Users\bob\Downloads\a.exe",
            r"\\?\C:\Users\bob\a.exe",
            r"\\.\C:\x.exe",
            r"\??\C:\x.exe",
            r"\\?\Volume{0b7a1c2e-0000-0000-0000-100000000000}\x.exe",
            r"\Device\HarddiskVolume3\Users\x.exe",
            r"D:\tools\x.exe",
            "",
        ] {
            assert!(!is_remote_path(local), "{local}");
        }
        // The scanner drops remote entries from the targets file.
        let t =
            parse_targets("C:\\a.exe\n\\\\evil@80\\x\\b.exe\n\\\\?\\UNC\\h\\s\\c.exe\nD:\\d.exe");
        assert_eq!(t, ["C:\\a.exe", "D:\\d.exe"]);
    }

    #[test]
    fn error_headline_never_echoes_source() {
        let diag = "error[E001]: syntax error\n --> line:1:6\n  |\n1 | rule secret_source_text {\n  |      ^ here";
        assert_eq!(error_headline(diag), "error[E001]: syntax error");
        assert_eq!(error_headline(""), "");
        let long = "x".repeat(500);
        assert_eq!(error_headline(&long).chars().count(), 161);
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
        // The broken rule's source is not echoed back.
        assert!(r.rule_errors[0].starts_with("broken.yara: "), "{r:?}");
        assert!(!r.rule_errors[0].contains("rule {"), "{r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// V-L10: `include` is refused, and the included file never leaks.
    #[cfg(feature = "engine")]
    #[test]
    fn includes_are_disabled() {
        let dir = std::env::temp_dir().join(format!("kestrel-scan-inc-{}", std::process::id()));
        let rules = dir.join("rules");
        std::fs::create_dir_all(&rules).unwrap();
        let secret = dir.join("secret.txt");
        std::fs::write(&secret, "TOP-SECRET-CONTENT").unwrap();
        std::fs::write(
            rules.join("inc.yar"),
            format!(
                "include \"{}\"\nrule A {{ condition: true }}",
                secret.display().to_string().replace('\\', "\\\\")
            ),
        )
        .unwrap();
        let r = scan(&rules, &[]).unwrap();
        assert_eq!(r.custom_rule_files, 0, "{r:?}");
        assert_eq!(r.rule_errors.len(), 1, "{r:?}");
        assert!(!r.rule_errors[0].contains("TOP-SECRET"), "{r:?}");
        // Remote targets are skipped without being opened.
        let r = scan(&rules, &[r"\\192.0.2.1@80\x\a.exe".to_string()]).unwrap();
        assert_eq!(r.scanned, 0);
        assert!(r.errors[0].contains("network path"), "{r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
