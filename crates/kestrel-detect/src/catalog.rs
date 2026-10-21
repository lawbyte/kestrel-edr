//! Metadata for the builtin rules (ST-01…ST-16 stealer rules, TP-01…TP-06
//! tamper rules) and the IOC pseudo-rules. Logic lives in `engine.rs`.

use kestrel_common::{RuleCategory, RuleKind, RuleMeta, RuleMode, Severity, TimestampMs};

pub const ST01: &str = "ST-01";
pub const ST02: &str = "ST-02";
pub const ST03: &str = "ST-03";
pub const ST04: &str = "ST-04";
pub const ST05: &str = "ST-05";
pub const ST06: &str = "ST-06";
pub const ST07: &str = "ST-07";
pub const ST08: &str = "ST-08";
pub const ST09: &str = "ST-09";
pub const ST10: &str = "ST-10";
pub const ST11: &str = "ST-11";
pub const ST12: &str = "ST-12";
pub const ST13: &str = "ST-13";
pub const ST14: &str = "ST-14";
pub const ST15: &str = "ST-15";
pub const ST16: &str = "ST-16";
pub const TP01: &str = "TP-01";
pub const TP02: &str = "TP-02";
pub const TP03: &str = "TP-03";
pub const TP04: &str = "TP-04";
pub const TP05: &str = "TP-05";
pub const TP06: &str = "TP-06";

/// IOC pseudo-rule ids (alerts produced by policy IOCs).
pub const IOC_HASH: &str = "IOC-HASH";
pub const IOC_CERT: &str = "IOC-CERT";
pub const IOC_NET: &str = "IOC-NET";
pub const IOC_DNS: &str = "IOC-DNS";
pub const IOC_URL: &str = "IOC-URL";

/// Rules that escalate a "suspend on suspicion" window to a kill.
pub const STRONG_RULES: &[&str] = &[ST02, ST04, ST07, ST16];
/// Rules that start a suspend window in Protect mode.
pub const SUSPEND_RULES: &[&str] = &[ST01, ST03, ST12];

const SIGMA_CRED_FILES: &str = "https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_browser_credential_access/";
const SIGMA_CRED_FILES_BROAD: &str = "https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files/";
const ELASTIC_CRED: &str = "https://www.elastic.co/security-labs/detect-credential-access";
const ELASTIC_KATZ: &str = "https://www.elastic.co/security-labs/katz-and-mouse-game";
const CHOKEPOINTS: &str =
    "https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/";
const GOOGLE_DPAPI: &str =
    "https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html";
const SPECTEROPS_CDP: &str =
    "https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/";
const GEN_VOID: &str = "https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass";
const MS_CLICKFIX: &str = "https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/";
const KASPERSKY_TEMP: &str = "https://www.socialnews.xyz/2026/06/17/kaspersky-35-of-infostealer-infections-begin-with-users-running-files-directly-from-temporary-folders/";
const UNIT42_VIDAR: &str =
    "https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/";

#[allow(clippy::too_many_arguments)]
pub(crate) fn meta(
    id: &str,
    name: &str,
    description: &str,
    category: RuleCategory,
    severity: Severity,
    attack: &[&str],
    protect_day_one: bool,
    protect_action: &str,
    references: &[&str],
    false_positives: &[&str],
) -> RuleMeta {
    RuleMeta {
        id: id.into(),
        name: name.into(),
        description: description.into(),
        kind: RuleKind::Builtin,
        category,
        severity,
        attack: attack.iter().map(|s| s.to_string()).collect(),
        default_mode: if protect_day_one {
            RuleMode::Protect
        } else {
            RuleMode::Audit
        },
        protect_day_one,
        protect_action: protect_action.into(),
        author: Some("Kestrel EDR".into()),
        license: Some("Apache-2.0".into()),
        references: references.iter().map(|s| s.to_string()).collect(),
        false_positives: false_positives.iter().map(|s| s.to_string()).collect(),
    }
}

/// Catalog of all builtin rules.
pub fn builtin_catalog() -> Vec<RuleMeta> {
    use RuleCategory::*;
    use Severity::*;
    vec![
        meta(ST01, "Credential-store read by untrusted process",
            "A process that is not the owning application (and not on the shipped benign-reader allow-list) opened a browser, wallet, messenger, FTP, VPN, password-manager or cloud-token store. Severity is raised when the reader is unsigned or runs from Temp/Downloads.",
            CredentialAccess, Medium, &["T1555.003", "T1539", "T1552.001", "T1005"], false,
            "Suspend the process for the policy's suspend window; kill it if a stronger rule (ST-02/04/07/16) fires for it or its parent/children, or if it is unsigned and runs from a user-writable path; otherwise resume",
            &[SIGMA_CRED_FILES, SIGMA_CRED_FILES_BROAD, CHOKEPOINTS],
            &["Password managers importing browser data", "Backup and sync agents", "CCleaner / BleachBit", "SCCM / Intune inventory", "Antivirus scanners", "Browser migration tools", "Not raised for: a browser's own signed Program Files install tree reading that browser's stores (updater / elevation / WebView helpers, e.g. Chrome os_update_handler.exe), (soak 2026-10-21). Microsoft-signed Program Files / WindowsApps apps (signer Microsoft Corporation or Microsoft Windows, e.g. Office, VS Code, Windows Widgets) reading the Windows token broker (WAM) cache raise a Low Audit alert that still counts for ST-02/ST-04, unless they run a script / eval / inspector", "Developer tools reading developer-tool credential stores (kubeconfig, Docker config.json, AWS credentials and SSO cache, Azure CLI token cache, Google Cloud SDK credentials), e.g. Docker Desktop com.docker.build.exe reading the kubeconfig (owner PC 2026-10-22): a validly signed image installed under Program Files / WindowsApps on the system volume that is not an interpreter, script host or LOLBin, has no script / eval / inspector / remote-debugging argument and was not injected into raises a Low Audit alert that still counts for ST-02/ST-04. Generic interpreters (python, pythonw, node, java, javaw) are not owners of the AWS, Azure CLI or Google Cloud stores by file name: SDK scripts such as boto3 raise ST-01 (see ST-04 for the send). Owners by layout: the Azure CLI bundled python.exe (Program Files/Microsoft SDKs/Azure/CLI2, run as -m azure.cli) and the Google Cloud CLI bundled python.exe (Program Files/Google/Cloud SDK/google-cloud-sdk/platform/bundledpython, running that SDK's lib/gcloud.py)"]),
        meta(ST02, "Smash-and-grab credential collection",
            "One process touched three or more distinct categories of secrets (e.g. browser passwords, cookies, wallets, Telegram) within 60 seconds.",
            CredentialAccess, Critical, &["T1555.003", "T1539", "T1005", "T1119"], true,
            "Kill the process tree, block its network access and quarantine the image (user-writable paths only)",
            &[ELASTIC_CRED, CHOKEPOINTS],
            &["Full-profile backup tools not on the allow-list", "Forensic triage collectors"]),
        meta(ST03, "Foreign DPAPI unprotect of browser secrets",
            "A process other than the browser or its elevation service decrypted browser-protected data with DPAPI (Crypto-DPAPI/Debug 16385 SPCryptUnprotect, description Google Chrome/Edge/Opera/Brave).",
            CredentialAccess, High, &["T1555.003", "T1555.004"], false,
            "Suspend the process (same suspend-on-suspicion window as ST-01)",
            &[GOOGLE_DPAPI, "https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/"],
            &["Password managers importing Chrome passwords", "Browser migration tools", "Electron apps (VS Code, Slack, Teams classic, …) unprotecting their own safeStorage key with the description \"Chromium\": Low / Audit when the app is validly signed under Program Files / WindowsApps, is not a browser or script host, and has not read another credential store (lab 2026-10-21)"]),
        meta(ST04, "Steal-then-send",
            "A process that read credential stores (ST-01 condition) or decrypted browser secrets (ST-03 condition) connected to an external, non-private address within 300 seconds.",
            Exfiltration, Critical, &["T1555.003", "T1539", "T1041", "T1071.001", "T1567"], true,
            "Kill the process tree, block the destination with WFP and quarantine the image",
            &[CHOKEPOINTS, ELASTIC_CRED],
            &["Cloud-sync tools that read token caches and then sync (add an exclusion by signer)", "SDK / CLI use: a validly signed reader (interpreters included) outside Temp / Downloads that read only one cloud provider's developer-tool stores (AWS, Azure CLI, Google Cloud SDK or Docker; not kubeconfig) and then connects, from a validly signed untampered sender, to that provider's own service endpoint by DNS name (e.g. boto3 calling s3.ap-southeast-1.amazonaws.com) raises a High Audit alert with no kill or block. A raw IP without a name, any other destination, an unsigned reader or a read of any other store gets the full response", "Audit only (no kill, no block): every read was a WAM token-cache read by a Microsoft-signed WAM client, the app's own Electron safeStorage key, or a developer-tool credential store read by a signed Program Files developer tool (owner PC 2026-10-22, Docker Desktop)", "When the connection came from the reader's parent and that parent is validly signed under Program Files by the same signer as the reader (the app's own backend, e.g. com.docker.backend.exe), only the reader is killed: the parent, its tree and the destination are left alone. A validly signed Program Files sender gets a per-image destination block instead of a host-wide one"]),
        meta(ST05, "Browser debugging abuse",
            "A Chromium browser was launched with --remote-debugging-* together with --user-data-dir, --headless or an off-screen --window-position, or with --load-extension, by a parent other than Explorer (cookie theft through the DevTools protocol).",
            CredentialAccess, High, &["T1539", "T1185", "T1564.003"], false,
            "Kill the browser process tree and its launching parent",
            &["https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging/", "https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_browsers_unusual_parent", "https://developer.chrome.com/blog/remote-debugging-port"],
            &["Puppeteer / Playwright / Selenium test automation", "IDE JavaScript debuggers (VS Code)"]),
        meta(ST06, "Local CDP client",
            "A non-browser process connected to a loopback Chrome DevTools debugging port (9222-9229 or a port seen in a --remote-debugging-port flag).",
            CredentialAccess, High, &["T1539", "T1185"], false,
            "Kill the process",
            &[ELASTIC_KATZ],
            &["Test automation frameworks (node.exe / python.exe driving Chrome)"]),
        meta(ST07, "Browser process tampering",
            "An untrusted process opened a browser with VM_READ / VM_WRITE / CREATE_THREAD rights (e.g. 0x1010, 0x1438, 0x143a), created a remote thread or APC in it, set a browser thread's context, or attached to it as a debugger (ABE bypass, CDP enablement, VoidStealer hardware breakpoints). The Windows Installer service instance (Microsoft-signed System32 msiexec.exe /V, SYSTEM, started by services.exe) opening a process with exactly the Restart Manager masks 0x411 / 0x1410 / 0x1411 (files-in-use check) is not reported; every other msiexec instance and mask gets the full response.",
            BrowserTampering, Critical, &["T1055", "T1055.004", "T1539", "T1555.003", "T1622"], true,
            "Kill the process",
            &[SPECTEROPS_CDP, GEN_VOID, CHOKEPOINTS],
            &["Developers debugging a browser with Visual Studio / WinDbg", "Accessibility or screen-reader software that reads browser memory", "Installers using Restart Manager from a non-Windows-Installer process"]),
        meta(ST08, "Chrome elevation-service abuse",
            "A non-browser process terminated Chrome at least twice and the Chrome elevation service started within one second (IElevator COM abuse), or an unsigned image executed from a browser Application directory.",
            BrowserTampering, High, &["T1555.003", "T1559.001", "T1574"], false,
            "Kill the process",
            &[ELASTIC_KATZ],
            &["Software deployment tools that close Chrome before an update"]),
        meta(ST09, "Foreign crypto library load",
            "nss3.dll (Mozilla's credential crypto library) was loaded by a non-Mozilla process, typically to decrypt Firefox logins.",
            CredentialAccess, Medium, &["T1555.003"], false,
            "Alert only",
            &[CHOKEPOINTS],
            &["LibreOffice (soffice.bin) and other apps that bundle NSS"]),
        meta(ST10, "ClickFix Run/Address-bar artefact",
            "Explorer recorded a RunMRU or TypedPaths entry that invokes PowerShell, mshta, curl, conhost, forfiles or download-and-execute keywords (iex/irm/iwr) — the command a ClickFix/FileFix lure made the user paste.",
            RuleCategory::Delivery, High, &["T1204.004", "T1059.001", "T1218.005"], false,
            "Kill the process chain spawned from the pasted command",
            &[MS_CLICKFIX, "https://detection.fyi/elastic/detection-rules/windows/execution_windows_filefix_typedpaths/"],
            &["Administrators typing PowerShell one-liners in the Run dialog"]),
        meta(ST11, "Paste-and-run process chain",
            "Explorer, a browser or Windows Terminal started a shell or LOLBin whose command line carries a ClickFix lure comment (# … captcha/robot/verify), a hidden window, base64 or download-cradle keywords; or cmd started nslookup against a hard-coded external resolver.",
            Execution, High, &["T1204.004", "T1059.001", "T1059.003", "T1218.005", "T1105"], false,
            "Kill the process tree",
            &["https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_clickfix_filefix_execution/", "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_filefix_browsers", MS_CLICKFIX],
            &["Administrative scripts launched with hidden windows from shortcuts"]),
        meta(ST12, "Untrusted execution from user paths",
            "An unsigned or invalidly signed executable started from Temp, Downloads, AppData or removable media. Severity is raised for images over 100 MB (null-padded loaders) or with Mark-of-the-Web.",
            Execution, Low, &["T1204.002", "T1036"], false,
            "Suspend pending verdict (opt-in): resumed when the suspend window expires without a stronger detection",
            &[KASPERSKY_TEMP, UNIT42_VIDAR],
            &["Portable and developer tools run from Downloads or AppData", "Unsigned in-house software"]),
        meta(ST13, ".NET LOLBin hollowing",
            "MSBuild, RegAsm, RegSvcs, InstallUtil or a similar .NET Framework binary started without a project/assembly argument or by an unusual parent, then connected to an external address (process hollowing host).",
            Execution, High, &["T1055.012", "T1127.001", "T1218.009", "T1218.004"], false,
            "Kill the process",
            &[KASPERSKY_TEMP, "https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/"],
            &["Build servers invoking MSBuild through unusual wrappers"]),
        meta(ST14, "Dead-drop / exfil service from non-browser",
            "A non-browser process resolved or connected to a dead-drop or exfiltration service from the policy list (api.telegram.org, Steam profiles, Discord webhooks, BSC/ETH RPC, ip-api.com, r2.dev …) or to port 8545.",
            Exfiltration, High, &["T1102", "T1102.001", "T1567", "T1071.001", "T1016"], false,
            "Block network access for the image (WFP), or block the resolved destinations for system binaries",
            &["https://detection.fyi/sigmahq/sigma/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access", "https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf"],
            &["Chat/gaming clients talking to their own service", "Scripts using ipinfo/ip-api for geolocation", "Developers using blockchain RPC endpoints"]),
        meta(ST15, "Trusted-binary sideload from user path",
            "A Defender or Edge component (MpCmdRun, NisSrv, MsMpEng, msedge) running outside its install directory loaded MpClient.dll / msedge_elf.dll from a non-standard location (DLL sideloading).",
            Execution, High, &["T1574.002", "T1036.005"], false,
            "Kill the process and quarantine the side-loaded DLL",
            &[UNIT42_VIDAR, "https://www.intrinsec.com/wp-content/uploads/2026/04/TLP_CLEAR-20260424-New_Vidar.pdf"],
            &["Portable Edge builds used for testing"]),
        meta(ST16, "Canary tripwire",
            "A process read secret material in a decoy credential store planted by Kestrel: the Local State encryption key or Login Data of a decoy profile of a defunct Chromium fork stealers enumerate (Kometa, 7Star), a file of its fake wallet extension, or decoy .aws credentials. Directory listings and incidental profile files (profile pictures, Preferences, icons) never fire. A genuine browser or password manager under Program Files on the system volume (valid signature by its vendor, no remote-debugging / headless / load-extension / foreign user-data-dir switches, never the target of an injection signal) raises an Audit alert only: it may be importing from other browsers. The Kestrel agent and validly signed security, search, backup and management tools on the allow-list are ignored.",
            Tripwire, Critical, &["T1555.003", "T1552.001", "T1005"], true,
            "Kill the process tree, block its network and quarantine the image; isolate the host (Kestrel server stays reachable) only when the reader is unsigned or unknown and runs from a user-writable folder",
            &[CHOKEPOINTS, "https://cyble.com/blog/lummac2-stealer-a-potent-threat-to-crypto-users/"],
            &["Browsers and password managers importing data from other browsers (Edge, Chrome, Firefox, Brave, Opera, Vivaldi, Bitwarden, 1Password, KeePass/KeePassXC): Audit alert only when genuine and installed under Program Files; per-user installs and other importers (Dashlane, NordPass, LastPass, less common browsers) need a per-rule exclusion", "Full-profile backup / sync agents not on the allow-list (add a per-rule exclusion for ST-16)", "Manual browsing of the decoy folder by an administrator"]),
        meta(TP01, "Telemetry session tampering",
            "An ETW session used by Kestrel was stopped, a provider was disabled, or an ETW AutoLogger was switched off in the registry.",
            Tamper, Critical, &["T1562.006", "T1562.001"], false,
            "Agent restarts its sessions; alert only",
            &["https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/"],
            &["Performance tooling that stops ETW sessions (xperf, WPR)"]),
        meta(TP02, "WFP filter tampering",
            "Windows Filtering Platform filters affecting the agent were added or changed (Security events 5446-5450), e.g. to cut the agent off from its server.",
            Tamper, Critical, &["T1562.004", "T1562.001"], false,
            "Agent removes foreign filters; alert only",
            &["https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/"],
            &["Third-party firewalls and VPN clients"]),
        meta(TP03, "AMSI tampering",
            "An AMSI provider registration or AMSI FeatureBits value changed.",
            Tamper, Critical, &["T1562.001"], false,
            "Agent restores the AMSI configuration; alert only",
            &["https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider"],
            &["Antivirus installation or upgrade"]),
        meta(TP04, "Agent service or file tampering",
            "The Kestrel service configuration or agent files were modified, or an uninstall was attempted outside the management console.",
            Tamper, Critical, &["T1562.001", "T1489"], false,
            "Agent restores its configuration; alert only",
            &[],
            &["Authorised agent upgrades run outside the console"]),
        meta(TP05, "Telemetry loss",
            "The agent reported lost events or an event-rate collapse (possible sensor blinding).",
            Tamper, High, &["T1562.006"], false,
            "Alert only",
            &[],
            &["Extreme system load"]),
        meta(TP06, "Protection turned off on the device",
            "Protection was turned off locally with the tray switch and the device's uninstall token (detection only: no automatic response and hardening not enforced; completely off: sensors stopped). Also raised, at lower severity, when protection comes back on and when a wrong uninstall token is entered. Raised by the agent itself, never by an event; it cannot be excluded.",
            Tamper, Medium, &["T1562.001"], false,
            "Alert only (medium for detection only, high for completely off); IT can turn protection back on from the device page",
            &["https://attack.mitre.org/techniques/T1562/001/"],
            &["A technician turning protection off on purpose to install or troubleshoot software (check who, when and for how long)"]),
    ]
}

/// What the local protection switch did (input of [`protection_alert`]).
#[derive(Debug, Clone, PartialEq)]
pub enum ProtectionSwitch {
    /// Protection turned off (`state` = the new pause).
    Off(kestrel_common::PauseState),
    /// Protection back on (`state` = the pause that ended).
    On {
        state: kestrel_common::PauseState,
        reason: kestrel_common::pause::PauseEndReason,
    },
    /// A policy change shortened the pause.
    Clamped(kestrel_common::PauseState),
    /// The agent (re)started with protection still turned off.
    StillOff(kestrel_common::PauseState),
    /// A wrong uninstall token was entered.
    WrongToken {
        failures: u32,
        locked_until_ms: Option<TimestampMs>,
        by_user: String,
    },
}

/// "45 minutes", "2 hours", "1 minute" (rounded up to whole minutes).
fn minutes_phrase(ms: i64) -> String {
    let mins = (ms.max(0) + 59_999) / 60_000;
    if mins >= 60 && mins % 60 == 0 {
        let h = mins / 60;
        format!("{h} hour{}", if h == 1 { "" } else { "s" })
    } else {
        format!("{mins} minute{}", if mins == 1 { "" } else { "s" })
    }
}

fn duration_phrase(s: &kestrel_common::PauseState) -> String {
    match s.until_ms {
        None => "until it is turned back on".into(),
        Some(u) => format!("for {}", minutes_phrase(u - s.since_ms)),
    }
}

/// `TP-06` alert for a change of the local protection switch. Mode Audit,
/// never carries actions. `subject` is the acting process (the agent, with
/// the tray user as `user`). Severity: off = medium (detection only) /
/// high (completely off); wrong token = medium, high when a lockout starts;
/// back on and shortened = info.
pub fn protection_alert(
    sw: &ProtectionSwitch,
    subject: kestrel_common::ProcessInfo,
    now: TimestampMs,
) -> kestrel_common::Alert {
    use kestrel_common::pause::PauseEndReason;
    use kestrel_common::PauseMode;
    let by = |u: &str| {
        if u.is_empty() {
            String::new()
        } else {
            format!(" by {u}")
        }
    };
    let (severity, summary, off) = match sw {
        ProtectionSwitch::Off(s) => (
            if s.mode == PauseMode::Full {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "Protection was turned off on this PC{} ({}) {} with the uninstall token in the tray app",
                by(&s.by_user),
                s.mode.label(),
                duration_phrase(s)
            ),
            Some(s.mode),
        ),
        ProtectionSwitch::On { state, reason } => (
            Severity::Info,
            format!(
                "Protection was turned back on ({}); it had been turned off{} ({}) for {}",
                match reason {
                    PauseEndReason::Manual => "from the tray app",
                    PauseEndReason::Expired => "the chosen time ran out",
                    PauseEndReason::Console => "by IT from the console",
                    PauseEndReason::Policy => "a policy change no longer allows the turn-off",
                },
                by(&state.by_user),
                state.mode.label(),
                minutes_phrase(now - state.since_ms)
            ),
            None,
        ),
        ProtectionSwitch::StillOff(s) => (
            if s.mode == PauseMode::Full {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "The Kestrel agent started with protection still turned off on this PC ({}, turned off{} {})",
                s.mode.label(),
                by(&s.by_user),
                match s.until_ms {
                    None => "until it is turned back on".to_string(),
                    Some(u) => format!("until {} from now", minutes_phrase(u - now)),
                }
            ),
            Some(s.mode),
        ),
        ProtectionSwitch::Clamped(s) => (
            Severity::Info,
            format!(
                "A policy change shortened the turn-off of protection on this PC ({}); it now turns back on automatically in {}",
                s.mode.label(),
                minutes_phrase(s.until_ms.unwrap_or(now) - now)
            ),
            Some(s.mode),
        ),
        ProtectionSwitch::WrongToken {
            failures,
            locked_until_ms,
            by_user,
        } => (
            if locked_until_ms.is_some() {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "A wrong uninstall token was entered{} in the tray app to turn protection off ({failures} failed attempt{} in a row){}",
                by(by_user),
                if *failures == 1 { "" } else { "s" },
                if locked_until_ms.is_some() {
                    "; the switch is locked for a while"
                } else {
                    ""
                }
            ),
            None,
        ),
    };
    kestrel_common::Alert {
        id: uuid::Uuid::now_v7(),
        ts: now,
        rule_id: TP06.into(),
        rule_name: "Protection turned off on the device".into(),
        rule_author: None,
        severity,
        attack: vec!["T1562.001".into()],
        mode: RuleMode::Audit,
        summary,
        process: subject,
        ancestry: vec![],
        data_at_risk: vec![],
        evidence: vec![],
        actions: vec![],
        protection_off: off,
    }
}

/// RuleMeta for an IOC pseudo-rule (not part of the catalog).
pub fn ioc_rule_name(id: &str) -> &'static str {
    match id {
        IOC_HASH => "Known-bad file hash",
        IOC_CERT => "Known-bad code-signing certificate",
        IOC_NET => "Connection to known-bad destination",
        IOC_DNS => "Lookup of known-bad domain",
        IOC_URL => "Known-bad URL in command or script",
        _ => "Indicator of compromise",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_shape() {
        let c = builtin_catalog();
        assert_eq!(c.len(), 22);
        let ids: Vec<_> = c.iter().map(|m| m.id.as_str()).collect();
        for i in 1..=16 {
            assert!(ids.contains(&format!("ST-{i:02}").as_str()));
        }
        for i in 1..=6 {
            assert!(ids.contains(&format!("TP-{i:02}").as_str()));
        }
        for m in &c {
            let day_one = matches!(m.id.as_str(), "ST-02" | "ST-04" | "ST-07" | "ST-16");
            assert_eq!(m.protect_day_one, day_one, "{}", m.id);
            assert_eq!(
                m.default_mode,
                if day_one {
                    RuleMode::Protect
                } else {
                    RuleMode::Audit
                }
            );
            assert!(!m.attack.is_empty());
            assert!(!m.protect_action.is_empty());
        }
        let tp06 = c.iter().find(|m| m.id == "TP-06").unwrap();
        assert_eq!(tp06.default_mode, RuleMode::Audit);
        assert_eq!(tp06.category, RuleCategory::Tamper);
        let st10 = c.iter().find(|m| m.id == "ST-10").unwrap();
        assert!(st10.attack.contains(&"T1204.004".to_string()));
    }

    fn subject() -> kestrel_common::ProcessInfo {
        kestrel_common::ProcessInfo {
            guid: kestrel_common::ProcessGuid("kestrel-agent:pause".into()),
            pid: 1,
            ppid: 0,
            parent_guid: None,
            image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
            cmdline: String::new(),
            user: Some(r"W\employee".into()),
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: None,
            signed: kestrel_common::SignatureState::Unknown,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: kestrel_common::PathClass::ProgramFiles,
        }
    }

    #[test]
    fn tp06_alerts() {
        use kestrel_common::pause::PauseEndReason;
        use kestrel_common::{PauseMode, PauseState};
        let s = PauseState {
            mode: PauseMode::DetectionOnly,
            since_ms: 0,
            until_ms: Some(3_600_000),
            by_user: r"W\employee".into(),
        };
        let a = protection_alert(&ProtectionSwitch::Off(s.clone()), subject(), 0);
        assert_eq!(a.rule_id, "TP-06");
        assert_eq!(a.mode, RuleMode::Audit);
        assert_eq!(a.severity, Severity::Medium);
        assert!(a.actions.is_empty());
        assert_eq!(a.protection_off, Some(PauseMode::DetectionOnly));
        assert!(a.summary.contains("detection only"), "{}", a.summary);
        assert!(a.summary.contains("for 1 hour"), "{}", a.summary);
        let full = PauseState {
            mode: PauseMode::Full,
            until_ms: None,
            ..s.clone()
        };
        let a = protection_alert(&ProtectionSwitch::Off(full), subject(), 0);
        assert_eq!(a.severity, Severity::High);
        assert!(a.summary.contains("until it is turned back on"));
        let a = protection_alert(
            &ProtectionSwitch::On {
                state: s.clone(),
                reason: PauseEndReason::Console,
            },
            subject(),
            30 * 60_000,
        );
        assert_eq!(a.severity, Severity::Info);
        assert_eq!(a.protection_off, None);
        assert!(
            a.summary.contains("by IT") && a.summary.contains("30 minutes"),
            "{}",
            a.summary
        );
        let a = protection_alert(
            &ProtectionSwitch::WrongToken {
                failures: 5,
                locked_until_ms: Some(60_000),
                by_user: String::new(),
            },
            subject(),
            0,
        );
        assert_eq!(a.severity, Severity::High);
        assert!(a.summary.contains("5 failed attempts"));
        assert!(!a.summary.contains("kun_"));
    }
}
