//! CD-xx credential dumping rules (LSASS, SAM, NTDS, LSA).
//!
//! Design (see `docs/research/notes/credential_dumping.md` §3, §6 and
//! `docs/research/general-malware-report.md` §3):
//!
//! * LSASS handle events come from Kernel-Audit-API-Calls event 5, which
//!   reports the **desired** access (not the granted one) and an NTSTATUS
//!   `return_code`. A "dangerous" request ([`dangerous`]) alone is one fact;
//!   Protect actions need a second one (untrusted source, dump file, debug
//!   library, LOLBin), as SigmaHQ / Fibratus / Microsoft ASR all conclude.
//! * Benign openers are allow-listed by exact path **and** signer (and mask
//!   where the notes say so), never by image name alone ([`benign_opener`]).
//! * lsass itself, protected processes and the agent are never the target of
//!   a response (the engine filters again before anything executes).
//! * Registry reverts are proposed as `RemoveAutorun` actions, which the
//!   engine drops in Audit mode, so nothing is ever reverted in Audit.
//!
//! CD-14 (credential store access) and CD-15 (call-stack based) are deferred.

use super::{Ctx, Family, FamilyHit};
use crate::catalog::meta;
use crate::paths::{glob_match, normalize_path, BenignKind, BENIGN_READERS};
use crate::protect;
use kestrel_common::{
    file_name_lower, Attribution, AutorunKind, Event, EventData, FileOp, PathClass, ProcessGuid,
    ProcessInfo, ProcessStart, RegistryOp, ResponseAction, RuleCategory, RuleMeta, ServiceInstall,
    Severity, SignatureState, TargetProcess, TimestampMs,
};
use std::collections::HashMap;

pub(crate) const CD01: &str = "CD-01";
pub(crate) const CD02: &str = "CD-02";
pub(crate) const CD03: &str = "CD-03";
pub(crate) const CD04: &str = "CD-04";
pub(crate) const CD05: &str = "CD-05";
pub(crate) const CD06: &str = "CD-06";
pub(crate) const CD07: &str = "CD-07";
pub(crate) const CD08: &str = "CD-08";
pub(crate) const CD09: &str = "CD-09";
pub(crate) const CD10: &str = "CD-10";
pub(crate) const CD11: &str = "CD-11";
pub(crate) const CD12: &str = "CD-12";
pub(crate) const CD13: &str = "CD-13";

/// LSASS open → dump file correlation window (CD-04).
const DUMP_WINDOW_MS: i64 = 120_000;
/// dbghelp/dbgcore load ↔ LSASS open correlation window (CD-05).
const DBG_WINDOW_MS: i64 = 60_000;
/// Shadow copy created → ntds.dit copy window (CD-11).
const SHADOW_WINDOW_MS: i64 = 600_000;
/// Bound on per-process correlation state.
const MAX_STATE: usize = 2048;

// Process access rights (MS Learn "Process Security and Access Rights").
const PROCESS_CREATE_THREAD: u32 = 0x2;
const PROCESS_VM_OPERATION: u32 = 0x8;
const PROCESS_VM_READ: u32 = 0x10;
const PROCESS_VM_WRITE: u32 = 0x20;
const PROCESS_DUP_HANDLE: u32 = 0x40;
const PROCESS_CREATE_PROCESS: u32 = 0x80;
const PROCESS_ALL_ACCESS: u32 = 0x1F_FFFF;
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;
const DANGEROUS_BITS: u32 = PROCESS_CREATE_THREAD
    | PROCESS_VM_OPERATION
    | PROCESS_VM_READ
    | PROCESS_VM_WRITE
    | PROCESS_DUP_HANDLE
    | PROCESS_CREATE_PROCESS;
/// STATUS_INVALID_CID: open of a pid that does not exist (sentinel target).
const STATUS_INVALID_CID: u32 = 0xC000_000B;
/// Sentinel target pid of failed Audit-API opens.
const SENTINEL_PID: u32 = 0xFFFF_FFFF;

/// Access mask that can read, write, inject into, clone or duplicate handles
/// out of the target (Fibratus-style dangerous-bit test). `MAXIMUM_ALLOWED`
/// counts because it resolves to full access on a non-PPL lsass.
pub(crate) fn dangerous(mask: u32) -> bool {
    mask & DANGEROUS_BITS != 0 || mask & MAXIMUM_ALLOWED != 0 || mask == PROCESS_ALL_ACCESS
}

fn full_or_max(mask: u32) -> bool {
    mask == PROCESS_ALL_ACCESS || mask & MAXIMUM_ALLOWED != 0
}

// ---------------------------------------------------------------------------
// state
// ---------------------------------------------------------------------------

#[derive(Default, Clone)]
struct PState {
    /// Last successful dangerous LSASS open by a non-benign opener (ts, event).
    lsass_open: Option<(TimestampMs, Event)>,
    /// Last dbghelp/dbgcore load by an untrusted process (ts, event).
    dbg_load: Option<(TimestampMs, Event)>,
    /// Dump output path parsed from a comsvcs MiniDump command line.
    dump_target: Option<String>,
    touched: TimestampMs,
}

#[derive(Default)]
pub(crate) struct CredDump {
    procs: HashMap<ProcessGuid, PState>,
    /// Last `vssadmin create shadow` (or equivalent) seen on the host.
    shadow_created: Option<TimestampMs>,
}

impl CredDump {
    fn state(&mut self, g: &ProcessGuid, now: TimestampMs) -> &mut PState {
        if !self.procs.contains_key(g) && self.procs.len() >= MAX_STATE {
            self.prune(now);
            if self.procs.len() >= MAX_STATE {
                if let Some(oldest) = self
                    .procs
                    .iter()
                    .min_by_key(|(_, s)| s.touched)
                    .map(|(k, _)| k.clone())
                {
                    self.procs.remove(&oldest);
                }
            }
        }
        let s = self.procs.entry(g.clone()).or_default();
        s.touched = s.touched.max(now);
        s
    }

    fn prune(&mut self, now: TimestampMs) {
        self.procs
            .retain(|_, s| now.saturating_sub(s.touched) <= DUMP_WINDOW_MS);
    }
}

impl Family for CredDump {
    fn on_event(&mut self, ctx: &Ctx, e: &Event, out: &mut Vec<FamilyHit>) {
        // Unattributed registry / service changes (pid 0) are still judged
        // on their content (V-H7); everything else needs a real actor.
        let attributed_kind = super::carries_attribution(e);
        if (e.pid == 0 && !attributed_kind) || e.pid == 4 {
            return;
        }
        let start = out.len();
        self.dispatch(ctx, e, out);
        // V-H5/H6/H7: never act on a guessed or unknown writer; the value
        // itself is still remediated.
        if attributed_kind {
            let attr = ctx.attribution(e);
            for h in out[start..].iter_mut() {
                h.apply_attribution(attr, e);
            }
        }
    }

    fn tick(&mut self, ctx: &Ctx, _out: &mut Vec<FamilyHit>) {
        self.prune(ctx.now);
        if self
            .shadow_created
            .is_some_and(|t| ctx.now.saturating_sub(t) > SHADOW_WINDOW_MS)
        {
            self.shadow_created = None;
        }
    }

    fn forget(&mut self, guid: &ProcessGuid) {
        self.procs.remove(guid);
    }
}

impl CredDump {
    fn dispatch(&mut self, ctx: &Ctx, e: &Event, out: &mut Vec<FamilyHit>) {
        match &e.data {
            EventData::ProcessStart(ps) => self.on_start(ctx, e, ps, out),
            EventData::ProcessAccess(t) => self.on_access(ctx, e, t, out),
            EventData::ImageLoad {
                path,
                signer,
                signed,
            } => self.on_image(ctx, e, path, signer.as_deref(), *signed, out),
            EventData::FileAccess { path, op } => self.on_file(ctx, e, path, *op, out),
            EventData::FileActivity(fa) => {
                for p in fa.sample_paths.iter().take(16) {
                    self.on_file(ctx, e, p, FileOp::Create, out);
                }
            }
            EventData::RegistrySet {
                key,
                value_name,
                data,
                op,
                ..
            } => self.on_registry(ctx, e, key, value_name, data.as_deref(), *op, out),
            EventData::ServiceInstalled(s) => self.on_service(ctx, e, s, out),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// process start: CD-01, CD-02, CD-08, CD-10, CD-11
// ---------------------------------------------------------------------------

impl CredDump {
    fn on_start(&mut self, ctx: &Ctx, e: &Event, ps: &ProcessStart, out: &mut Vec<FamilyHit>) {
        let clean = ps.cmdline.replace('^', "");
        let lc = clean.to_ascii_lowercase();
        let name = file_name_lower(&ps.image);
        if lc.is_empty() && name.is_empty() {
            return;
        }
        let p = proc_of(ctx, e);
        if ctx.is_agent(&p) {
            return;
        }
        let tokens = tokenize(&clean);
        let ltokens: Vec<String> = tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
        let lsass_pid = ctx.lsass().map(|l| l.pid);

        // ---- CD-01: comsvcs MiniDump -------------------------------------
        // rundll32 itself (or a renamed copy); shells that merely launch it are
        // not the dumper.
        let wrapper = ctx.is_lolbin(&name) && name != "rundll32.exe";
        if !wrapper
            && lc.contains("comsvcs")
            && (lc.contains("minidump") || comsvcs_ordinal(&lc))
            && lc.contains("full")
        {
            let (pid_arg, file_arg) = minidump_args(&tokens, &ltokens);
            let other_target = matches!((pid_arg, lsass_pid), (Some(a), Some(l)) if a != l);
            if other_target {
                out.push(FamilyHit::new(
                    CD01,
                    &p.guid,
                    Severity::Medium,
                    format!(
                        "{} used comsvcs.dll MiniDump to dump the memory of process {} (not LSASS); the same technique dumps credentials from LSASS",
                        who(&p),
                        pid_arg.unwrap_or_default()
                    ),
                ));
            } else {
                let mut actions = vec![kill(&p)];
                if let Some(f) = &file_arg {
                    // V-H4: the path is attacker text (the dump may even
                    // fail): quarantine only inside the subject's own
                    // profile. The kernel-observed write (CD-04) still
                    // quarantines wherever the dump really lands.
                    if ctx.attacker_path_ok(f, p.user.as_deref()) {
                        actions.push(quarantine_path(f));
                    }
                    self.state(&p.guid, e.ts).dump_target = Some(f.clone());
                }
                let mut h = FamilyHit::new(
                    CD01,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} used comsvcs.dll MiniDump to dump LSASS memory{} — Windows passwords and hashes can be read from that file",
                        who(&p),
                        file_arg.as_deref().map(|f| format!(" to {f}")).unwrap_or_default()
                    ),
                )
                .with_actions(actions);
                h.strong = true;
                out.push(h);
            }
            return;
        }

        // ---- CD-08: WER-based LSASS dump (start branch) ------------------
        let is_wer = name == "werfault.exe" || name == "werfaultsecure.exe";
        if is_wer {
            let targets_lsass = lc.contains("lsass")
                || lsass_pid.is_some_and(|l| {
                    pid_after_flags(&ltokens, &["-p", "/p", "-pid", "/pid", "-i", "/i"]) == Some(l)
                });
            if targets_lsass {
                let mut actions = vec![kill(&p)];
                actions.extend(quarantine_image(&p));
                let mut h = FamilyHit::new(
                    CD08,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} was started against LSASS (Windows Error Reporting dump of the credential store)",
                        who(&p)
                    ),
                )
                .with_actions(actions);
                h.strong = true;
                out.push(h);
            }
            // ---- CD-02: WerFault(Secure) outside System32/SysWOW64 -------
            if !in_system_dir(ctx, &ps.image) {
                let mut actions = vec![kill(&p)];
                actions.extend(quarantine_image(&p));
                let mut h = FamilyHit::new(
                    CD02,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} ran from {} instead of System32 — a copied (often old, vulnerable) Windows Error Reporting binary used to dump LSASS",
                        crate::paths::file_name(&ps.image),
                        ps.image
                    ),
                )
                .with_actions(actions);
                h.strong = true;
                out.push(h);
            }
            return;
        }

        // ---- CD-02: known dumper tools ----------------------------------
        if let Some(h) = dumper_tool(ctx, &p, &name, &lc, &ltokens, lsass_pid) {
            out.push(h);
            return;
        }

        // ---- CD-11: NTDS.dit extraction ---------------------------------
        if is_shadow_create(&name, &lc) {
            self.shadow_created = Some(e.ts);
        }
        // ---- CD-10 / CD-11: wbadmin backup of NTDS.dit / hives -----------
        // Corpus finding 10 (2026-10-25, Akira via SonicWall, Huntress Aug
        // 2025): `wbadmin start backup -include:…\NTDS.dit …\config\SYSTEM
        // …\config\SECURITY` copies the AD database and the hives with the
        // boot key through Windows Backup. Only the `-include:` list of a
        // `start backup` counts; whole-volume, user-folder and system-state
        // backups (`start systemstatebackup`) are normal administration.
        let argv0 = ltokens
            .first()
            .map(|t| file_name_lower(t))
            .unwrap_or_default();
        let is_wbadmin = name == "wbadmin.exe" || argv0 == "wbadmin.exe" || argv0 == "wbadmin";
        if is_wbadmin {
            if let Some(inc) = wbadmin_include(&ltokens) {
                let ntds = inc.contains("ntds.dit");
                let hives = refs_config_hive(&inc);
                if ntds {
                    let mut h = FamilyHit::new(
                        CD11,
                        &p.guid,
                        Severity::High,
                        format!(
                            "{} started a Windows Backup of the Active Directory database (ntds.dit){} — a known way to steal every domain password hash",
                            who(&p),
                            if hives {
                                " together with the registry hives that hold its decryption key"
                            } else {
                                ""
                            }
                        ),
                    )
                    .with_actions(vec![kill(&p)]);
                    h.dedup_key = Some(format!("{CD11}:wbadmin"));
                    out.push(h);
                }
                if hives {
                    let mut h = FamilyHit::new(
                        CD10,
                        &p.guid,
                        Severity::High,
                        format!(
                            "{} started a Windows Backup that includes credential hives (SAM / SECURITY / SYSTEM) — they can be cracked offline from the backup",
                            who(&p)
                        ),
                    );
                    h.dedup_key = Some(format!("{CD10}:wbadmin"));
                    out.push(h);
                }
                if ntds || hives {
                    return;
                }
            }
        }
        // Corpus finding 10: IFM media in any spelling ntdsutil accepts
        // (`ifm "create full c:\x"`, `"ac i ntds" ifm "cr fu c:\x"`,
        // `create sysvol full`, `create rodc`).
        if (name == "ntdsutil.exe"
            || name == "dsdbutil.exe"
            || matches!(
                argv0.as_str(),
                "ntdsutil" | "ntdsutil.exe" | "dsdbutil" | "dsdbutil.exe"
            ))
            && ifm_create(&lc)
        {
            out.push(
                FamilyHit::new(
                    CD11,
                    &p.guid,
                    Severity::High,
                    format!(
                        "{} created Install-From-Media files: a full copy of the Active Directory database (ntds.dit) with every domain password hash",
                        who(&p)
                    ),
                )
                .with_actions(vec![kill(&p)]),
            );
            return;
        }
        let recent_shadow = self
            .shadow_created
            .is_some_and(|t| e.ts >= t && e.ts - t <= SHADOW_WINDOW_MS);
        if lc.contains("ntds.dit")
            && (lc.contains("harddiskvolumeshadowcopy")
                || name == "esentutl.exe"
                || (recent_shadow && (lc.contains("copy") || ctx.is_lolbin(&name))))
        {
            out.push(
                FamilyHit::new(
                    CD11,
                    &p.guid,
                    Severity::High,
                    format!(
                        "{} copied the Active Directory database (ntds.dit){}",
                        who(&p),
                        if lc.contains("harddiskvolumeshadowcopy") {
                            " out of a volume shadow copy"
                        } else {
                            ""
                        }
                    ),
                )
                .with_actions(vec![kill(&p)]),
            );
            return;
        }

        // ---- CD-10: hive save / copy -------------------------------------
        let is_reg = name == "reg.exe"
            || ltokens
                .first()
                .is_some_and(|t| file_name_lower(t) == "reg" || file_name_lower(t) == "reg.exe");
        if is_reg {
            if let Some(i) = ltokens.iter().position(|t| t == "save" || t == "export") {
                if let Some(hive) = ltokens.get(i + 1).and_then(|h| sensitive_hive(h)) {
                    let outfile = tokens.get(i + 2).cloned();
                    let strong = hive != "SYSTEM";
                    let mut h = FamilyHit::new(
                        CD10,
                        &p.guid,
                        if strong {
                            Severity::Critical
                        } else {
                            Severity::High
                        },
                        format!(
                            "{} saved the HKLM\\{hive} registry hive{} — {}",
                            who(&p),
                            outfile
                                .as_deref()
                                .map(|o| format!(" to {o}"))
                                .unwrap_or_default(),
                            if strong {
                                "local account password hashes / LSA secrets can be cracked offline from it"
                            } else {
                                "it holds the boot key needed to decrypt SAM and LSA secrets"
                            }
                        ),
                    );
                    if strong {
                        let mut actions = vec![kill(&p)];
                        // V-H4: attacker-named output path.
                        if let Some(o) = outfile
                            .as_ref()
                            .filter(|o| ctx.attacker_path_ok(o, p.user.as_deref()))
                        {
                            actions.push(quarantine_path(o));
                        }
                        h = h.with_actions(actions);
                    }
                    h.dedup_key = Some(format!("{CD10}:{hive}"));
                    out.push(h);
                    return;
                }
            }
        }
        let refs_hive = refs_config_hive(&lc);
        if name == "esentutl.exe" && (lc.contains("/vss") || lc.contains("/y")) && refs_hive {
            out.push(FamilyHit::new(
                CD10,
                &p.guid,
                Severity::High,
                format!(
                    "{} copied a locked registry hive (SAM / SECURITY / SYSTEM) with esentutl",
                    who(&p)
                ),
            ));
            return;
        }
        if refs_hive && (lc.contains("harddiskvolumeshadowcopy") || lc.contains(r"\regback\")) {
            out.push(FamilyHit::new(
                CD10,
                &p.guid,
                Severity::High,
                format!(
                    "{} referenced a shadow-copy / RegBack copy of a credential hive (SAM / SECURITY / SYSTEM)",
                    who(&p)
                ),
            ));
        }
    }
}

/// CD-02 sub-cases on a process start (not WerFault, handled by the caller).
fn dumper_tool(
    ctx: &Ctx,
    p: &ProcessInfo,
    name: &str,
    lc: &str,
    ltokens: &[String],
    lsass_pid: Option<u32>,
) -> Option<FamilyHit> {
    let ms = protect::microsoft_signed(p.signed, p.signer.as_deref());
    let kill_hit = |summary: String| {
        let mut actions = vec![kill(p)];
        actions.extend(quarantine_image(p));
        let mut h =
            FamilyHit::new(CD02, &p.guid, Severity::Critical, summary).with_actions(actions);
        h.strong = true;
        Some(h)
    };
    // Credential-theft tool syntax on the command line.
    if let Some(m) = MIMIKATZ_COMMANDS.iter().find(|m| lc.contains(*m)) {
        return kill_hit(format!(
            "{} ran a credential-dumping command (\"{m}\")",
            who(p)
        ));
    }
    if KNOWN_DUMPERS.iter().any(|k| glob_match(k, name)) {
        return kill_hit(format!("{} is a known LSASS dumping tool", who(p)));
    }
    // FP-09 (DETECTION-QUALITY.md, 2026-10-25): `grep -n lsass\|0x1410 -r
    // src/…` matched "lsass anywhere + a procdump flag (-r)". LSASS must now
    // be a target *argument* of its own (`lsass`, `lsass.exe`, a path to it,
    // or the LSASS PID as a whole token), never a substring of a pattern.
    let lsass_ref = lsass_target_arg(ltokens, lsass_pid);
    if !lsass_ref {
        return None;
    }
    // Text-search / viewer tools: only flags no such tool has (-ma / -mm /
    // -mp / -mc) make their command line a dump; `-r` is
    // "recursive" for them. A renamed procdump called grep.exe still uses
    // -ma; a text tool that really opens LSASS is judged by CD-03 / CD-04 /
    // CD-05 on its handle and dump file.
    let text_tool = TEXT_TOOLS.contains(&name);
    let dump_flag = ltokens.iter().skip(1).any(|t| {
        if text_tool {
            STRONG_DUMP_FLAGS.contains(&t.as_str())
        } else {
            PROCDUMP_FLAGS.contains(&t.as_str())
        }
    });
    let procdump_name = name.starts_with("procdump");
    // Shells / script hosts merely wrapping the tool (`cmd /c procdump …`) are
    // not the dumper: the tool's own process start is judged instead.
    let wrapper = ctx.is_lolbin(name);
    if name == "createdump.exe"
        || (dump_flag && (procdump_name || (!wrapper && !ctx.system_trusted(p))))
    {
        let tool = if name == "createdump.exe" {
            "createdump (.NET)"
        } else {
            "procdump"
        };
        // Microsoft-signed procdump / createdump under its own name: support
        // engineers use it, so alert only (CD-04 still kills on the dump file
        // when the two facts line up). Renamed or unsigned copies are killed.
        let named = procdump_name || name == "createdump.exe";
        if ms && named {
            return Some(FamilyHit::new(
                CD02,
                &p.guid,
                Severity::High,
                format!(
                    "{} ({tool}, Microsoft-signed) was started to dump LSASS memory",
                    who(p)
                ),
            ));
        }
        return kill_hit(format!(
            "{} was started with {tool}-style arguments to dump LSASS memory{}",
            who(p),
            if named { "" } else { " (renamed tool)" }
        ));
    }
    None
}

// ---------------------------------------------------------------------------
// LSASS handles: CD-01 (rundll32), CD-03, CD-05, CD-06 + CD-04 arming
// ---------------------------------------------------------------------------

impl CredDump {
    fn on_access(&mut self, ctx: &Ctx, e: &Event, t: &TargetProcess, out: &mut Vec<FamilyHit>) {
        let mask = t.granted_access;
        if !dangerous(mask) || !is_lsass_target(ctx, t) {
            return;
        }
        if ctx.lsass().is_some_and(|l| l.guid == e.guid) {
            return; // lsass opening itself
        }
        let p = proc_of(ctx, e);
        if ctx.is_agent(&p) || benign_opener(ctx, &p, mask) {
            return;
        }
        let name = file_name_lower(&p.image);
        let rights = access_desc(mask);

        if t.return_code != 0 {
            // ---- CD-06: failed attempt (LSA protection held) ---------------
            if t.return_code == STATUS_INVALID_CID || !suspicious_source(ctx, &p, mask) {
                return;
            }
            // Triage 2026-10-22 item 10: NVIDIA nvcontainer.exe and
            // BraveUpdate.exe (validly signed, Program Files) asked for
            // query + VM_READ (0x410) and LSA protection refused. A signed
            // Program Files service / updater asking only for read / query
            // rights that Windows refused: Low Audit, still recorded.
            // Unsigned or user-path openers, write / dup-handle / thread
            // masks and successful opens (CD-03) are unchanged.
            if crate::legit_apps::lsass_read_only_mask(mask)
                && crate::legit_apps::signed_program_files_service(
                    &p,
                    ctx.system_drive(),
                    ctx.tampered(&p.guid),
                )
            {
                let mut h = FamilyHit::new(
                    CD06,
                    &p.guid,
                    Severity::Low,
                    format!(
                        "{} (validly signed {} service installed under Program Files) asked LSASS for {rights} and Windows refused (status 0x{:08X}); signed services and updaters probe every process this way, so this is recorded only. LSA protection held",
                        who(&p),
                        p.signer.as_deref().unwrap_or("").trim(),
                        t.return_code
                    ),
                );
                h.audit_only = true;
                out.push(h);
                return;
            }
            // FP-11 (DETECTION-QUALITY.md, 2026-10-25): Roblox's anti-cheat
            // (Hyperion) asks every process, LSASS included, for 0x40A
            // (query + VM_OPERATION + CREATE_THREAD) and LSA protection
            // refuses it. A refused open by the genuine client (exact image
            // name, exact signer, its own per-user or per-machine
            // `Roblox\Versions\version-<hex>\` folder, not tampered) with a
            // mask inside that observed set is Low Audit. VM_READ / VM_WRITE
            // / DUP_HANDLE / CREATE_PROCESS / full / maximum-allowed, a
            // successful open (CD-03), or any other copy keep High.
            if let Some(app) = refused_probe_client(ctx, &p, mask) {
                let mut h = FamilyHit::new(
                    CD06,
                    &p.guid,
                    Severity::Low,
                    format!(
                        "{} ({app}, validly signed by {}) asked LSASS for {rights} and Windows refused (status 0x{:08X}); its anti-cheat probes every process this way, so this is recorded only. LSA protection held",
                        who(&p),
                        p.signer.as_deref().unwrap_or("").trim(),
                        t.return_code
                    ),
                );
                h.audit_only = true;
                out.push(h);
                return;
            }
            let mut h = FamilyHit::new(
                CD06,
                &p.guid,
                Severity::High,
                format!(
                    "{} tried to open LSASS with {rights} and Windows refused (status 0x{:08X}) — a blocked credential-dumping attempt; LSA protection held",
                    who(&p),
                    t.return_code
                ),
            );
            h.suspend = true;
            out.push(h);
            return;
        }

        let st = self.state(&p.guid, e.ts);
        st.lsass_open = Some((e.ts, e.clone()));
        let dbg = st
            .dbg_load
            .as_ref()
            .filter(|(ts, _)| (e.ts - *ts).abs() <= DBG_WINDOW_MS)
            .map(|(_, ev)| ev.clone());
        let dump_target = st.dump_target.clone();

        let mut strong = false;
        // ---- CD-01 (behavioural branch): rundll32 → LSASS ----------------
        if name == "rundll32.exe" {
            let mut actions = vec![kill(&p)];
            // V-H4: still a path from the command line, not an observed write.
            if let Some(f) = dump_target
                .as_ref()
                .filter(|f| ctx.attacker_path_ok(f, p.user.as_deref()))
            {
                actions.push(quarantine_path(f));
            }
            let mut h = FamilyHit::new(
                CD01,
                &p.guid,
                Severity::Critical,
                format!(
                    "{} (rundll32) opened LSASS with {rights} — the comsvcs.dll MiniDump credential dump",
                    who(&p)
                ),
            )
            .with_actions(actions);
            h.strong = true;
            out.push(h);
            strong = true;
        }
        // ---- CD-05: debug library + LSASS open ---------------------------
        if let Some(dbg_ev) = dbg {
            out.push(cd05_hit(&p, &rights, dbg_ev));
            strong = true;
        }
        // ---- CD-03: suspicious LSASS handle --------------------------------
        if !strong && suspicious_source(ctx, &p, mask) {
            let taskmgr = name == "taskmgr.exe";
            let sev = if ctx.untrusted_actor(&p) || taskmgr {
                Severity::High
            } else {
                Severity::Medium
            };
            let mut h = FamilyHit::new(
                CD03,
                &p.guid,
                sev,
                format!(
                    "{} opened LSASS (the Windows credential store) with {rights}{}",
                    who(&p),
                    if taskmgr {
                        " — Task Manager asks for full access only to create a memory dump"
                    } else {
                        ""
                    }
                ),
            );
            h.suspend = true;
            out.push(h);
        }
    }

    fn on_image(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        path: &str,
        signer: Option<&str>,
        signed: SignatureState,
        out: &mut Vec<FamilyHit>,
    ) {
        let dll = file_name_lower(path);
        let is_dbg = dll == "dbghelp.dll" || dll == "dbgcore.dll";
        let subject_is_lsass = ctx.lsass().is_some_and(|l| l.guid == e.guid);
        if !is_dbg && !subject_is_lsass {
            return;
        }
        let p = proc_of(ctx, e);
        let subject_is_lsass = subject_is_lsass
            || (file_name_lower(&p.image) == "lsass.exe"
                && sys_rest(ctx, &p.image).as_deref() == Some(r"\windows\system32\lsass.exe"));

        if subject_is_lsass {
            // ---- CD-09: non-Microsoft DLL loaded into LSASS ---------------
            let sev = match signed {
                SignatureState::Unsigned | SignatureState::Invalid => Severity::High,
                SignatureState::Valid if !signer.is_some_and(protect::is_microsoft_signer) => {
                    Severity::Medium
                }
                _ => return, // Microsoft-signed, or signature not known yet
            };
            let mut h = FamilyHit::new(
                CD09,
                &p.guid,
                sev,
                format!(
                    "LSASS loaded {} ({}) — a security support / authentication package that is not Microsoft-signed can capture every password typed at logon",
                    path,
                    match signed {
                        SignatureState::Valid => format!("signed by {}", signer.unwrap_or("?")),
                        SignatureState::Invalid => "invalid signature".into(),
                        _ => "unsigned".into(),
                    }
                ),
            )
            .with_actions(vec![quarantine_path(path)]);
            h.dedup_key = Some(format!("{CD09}:dll:{}", normalize_path(path)));
            out.push(h);
            return;
        }

        if !is_dbg || ctx.is_agent(&p) || !ctx.untrusted_actor(&p) || benign_opener(ctx, &p, 0) {
            return;
        }
        let st = self.state(&p.guid, e.ts);
        st.dbg_load = Some((e.ts, e.clone()));
        let open = st
            .lsass_open
            .as_ref()
            .filter(|(ts, _)| (e.ts - *ts).abs() <= DBG_WINDOW_MS)
            .map(|(_, ev)| ev.clone());
        if let Some(open_ev) = open {
            let mask = match &open_ev.data {
                EventData::ProcessAccess(t) => t.granted_access,
                _ => 0,
            };
            out.push(cd05_hit(&p, &access_desc(mask), open_ev));
        }
    }
}

fn cd05_hit(p: &ProcessInfo, rights: &str, other: Event) -> FamilyHit {
    let mut actions = vec![kill(p)];
    actions.extend(quarantine_image(p));
    let mut h = FamilyHit::new(
        CD05,
        &p.guid,
        Severity::Critical,
        format!(
            "{} loaded the Windows dump library (dbghelp/dbgcore) and opened LSASS with {rights} — a custom LSASS memory dumper",
            who(p)
        ),
    )
    .with_actions(actions);
    h.strong = true;
    h.extra_evidence.push(other);
    h
}

// ---------------------------------------------------------------------------
// files: CD-04, CD-08 (file branch), CD-09 (log), CD-10 (shadow), CD-11
// ---------------------------------------------------------------------------

impl CredDump {
    fn on_file(&mut self, ctx: &Ctx, e: &Event, path: &str, op: FileOp, out: &mut Vec<FamilyHit>) {
        let raw = path.replace('/', "\\").to_ascii_lowercase();
        let fname = file_name_lower(path);
        let writes = matches!(op, FileOp::Create | FileOp::Write | FileOp::Rename);
        let dumpish = fname.ends_with(".dmp")
            || fname.ends_with(".mdmp")
            || fname.ends_with(".hdmp")
            || fname.ends_with(".dump")
            || fname.contains("lsass");
        let shadow = raw.contains("harddiskvolumeshadowcopy");
        let shadow_hive = shadow
            && [
                r"\windows\system32\config\sam",
                r"\windows\system32\config\security",
                r"\windows\system32\config\system",
            ]
            .iter()
            .any(|s| raw.ends_with(s));
        let mimilog = writes
            && (raw.ends_with(r"\windows\system32\mimilsa.log")
                || raw.ends_with(r"\windows\system32\kiwissp.log"));
        let ntds = fname == "ntds.dit";
        let armed = self.procs.contains_key(&e.guid);
        let dump_candidate = writes && dumpish && (armed || raw.contains("lsass"));
        if !dump_candidate && !shadow_hive && !mimilog && !ntds {
            return;
        }
        let p = proc_of(ctx, e);
        if ctx.is_agent(&p) {
            return;
        }
        let pname = file_name_lower(&p.image);

        if writes && dumpish {
            // ---- CD-08: WerFault writes an lsass dump ------------------------
            if (pname == "werfault.exe" || pname == "werfaultsecure.exe") && raw.contains("lsass") {
                let mut actions = vec![kill(&p), quarantine_path(path)];
                actions.extend(quarantine_image(&p));
                let mut h = FamilyHit::new(
                    CD08,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} wrote an LSASS crash dump ({path}) — Windows Error Reporting abused to dump credentials",
                        who(&p)
                    ),
                )
                .with_actions(actions);
                h.strong = true;
                out.push(h);
                return;
            }
            // ---- CD-04: LSASS handle then dump file ------------------------
            let open = self
                .procs
                .get(&e.guid)
                .and_then(|s| s.lsass_open.as_ref())
                .filter(|(ts, _)| e.ts >= *ts && e.ts - *ts <= DUMP_WINDOW_MS)
                .map(|(ts, ev)| (*ts, ev.clone()));
            if let Some((ts, open_ev)) = open {
                let mut actions = vec![kill(&p), quarantine_path(path)];
                actions.extend(quarantine_image(&p));
                let mut h = FamilyHit::new(
                    CD04,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} opened LSASS and {:.0} s later wrote a memory dump file ({path}) — Windows credentials can be extracted from it",
                        who(&p),
                        (e.ts - ts) as f64 / 1000.0
                    ),
                )
                .with_actions(actions);
                h.strong = true;
                h.extra_evidence.push(open_ev);
                out.push(h);
                return;
            }
        }

        if mimilog {
            // ---- CD-09: mimikatz memssp / mimilib log ------------------------
            let mut h = FamilyHit::new(
                CD09,
                &p.guid,
                Severity::Critical,
                format!(
                    "{} wrote {path}: the log file of the mimikatz in-memory security package, which records every password typed at logon",
                    who(&p)
                ),
            );
            h.dedup_key = Some(format!("{CD09}:log"));
            out.push(h);
            return;
        }

        if ntds {
            let norm = normalize_path(path);
            let outside = shadow
                || !norm
                    .trim_start_matches(|c: char| c != '\\')
                    .starts_with(r"\windows\ntds\");
            let trusted = benign_backup(ctx, &p);
            if outside && !trusted && (writes || shadow) {
                // ---- CD-11: ntds.dit copied / read from a shadow copy -------
                let mut actions = vec![kill(&p)];
                if writes && !shadow {
                    actions.push(quarantine_path(path));
                }
                out.push(
                    FamilyHit::new(
                        CD11,
                        &p.guid,
                        Severity::High,
                        format!(
                            "{} {} the Active Directory database ({path})",
                            who(&p),
                            if shadow { "read" } else { "wrote a copy of" }
                        ),
                    )
                    .with_actions(actions),
                );
            }
            return;
        }

        if shadow_hive && !benign_backup(ctx, &p) {
            // ---- CD-10: shadow-copy hive access (Audit evidence only) -------
            let hive = fname.to_ascii_uppercase();
            let mut h = FamilyHit::new(
                CD10,
                &p.guid,
                Severity::High,
                format!(
                    "{} opened the {hive} hive inside a volume shadow copy ({path}) — a way to copy locked credential hives",
                    who(&p)
                ),
            );
            h.dedup_key = Some(format!("{CD10}:shadow"));
            out.push(h);
        }
    }
}

// ---------------------------------------------------------------------------
// registry: CD-07, CD-09, CD-12, CD-13; services: CD-13
// ---------------------------------------------------------------------------

const SPE: &str = r"hklm\software\microsoft\windows nt\currentversion\silentprocessexit\";
const IFEO_LSASS: &str =
    r"hklm\software\microsoft\windows nt\currentversion\image file execution options\lsass.exe";
const LSA: &str = r"hklm\system\currentcontrolset\control\lsa";
const LSA_OSCONFIG: &str = r"hklm\system\currentcontrolset\control\lsa\osconfig";
const WDIGEST: &str = r"hklm\system\currentcontrolset\control\securityproviders\wdigest";
const KSLD: &str = r"hklm\system\currentcontrolset\services\ksld";
const CREDGUARD: &str =
    r"hklm\system\currentcontrolset\control\deviceguard\scenarios\credentialguard";
const DG_POLICY: &str = r"hklm\software\policies\microsoft\windows\deviceguard";

/// Microsoft LSA packages (Security / Authentication / Notification Packages).
const KNOWN_LSA_PACKAGES: &[&str] = &[
    "kerberos",
    "msv1_0",
    "schannel",
    "wdigest",
    "tspkg",
    "pku2u",
    "cloudap",
    "negoexts",
    "livessp",
    "scecli",
    "rassfm",
    "credssp",
    "negotiate",
    "msoidssp",
];

impl CredDump {
    #[allow(clippy::too_many_arguments)]
    fn on_registry(
        &mut self,
        ctx: &Ctx,
        e: &Event,
        key: &str,
        value_name: &str,
        data: Option<&str>,
        op: RegistryOp,
        out: &mut Vec<FamilyHit>,
    ) {
        let nk = normalize_key(key);
        let vn = value_name.to_ascii_lowercase();
        let relevant = nk.starts_with(SPE)
            || nk == IFEO_LSASS
            || nk == LSA
            || nk == LSA_OSCONFIG
            || nk == WDIGEST
            || nk == KSLD
            || nk == CREDGUARD
            || nk == DG_POLICY;
        if !relevant {
            return;
        }
        let p = proc_of(ctx, e);
        // Only the agent as the *exact* writer is its own work; a guess that
        // lands on it is an unknown writer (V-H6).
        if ctx.attribution(e) == Attribution::Exact && ctx.is_agent(&p) {
            return;
        }
        let num = data.and_then(parse_num);
        let set = op == RegistryOp::Set;
        let deleted = op == RegistryOp::DeleteValue;
        let loc = display_key(key);
        let dedup = Some(format!("{nk}\\{vn}"));
        let remove = |restore: Option<&str>| ResponseAction::RemoveAutorun {
            kind: AutorunKind::RegistryValue,
            location: loc.clone(),
            value_name: Some(value_name.to_string()),
            restore_data: restore.map(Into::into),
        };

        // ---- CD-07: SilentProcessExit / IFEO on lsass --------------------
        if set {
            let spe_lsass = nk
                .strip_prefix(SPE)
                .is_some_and(|rest| rest.starts_with("lsass"));
            let ifeo = nk == IFEO_LSASS
                && match vn.as_str() {
                    "globalflag" => num.is_none_or(|n| n & 0x200 != 0),
                    "debugger" | "verifierdlls" => true,
                    _ => false, // AuditLevel=8 is LSA protection audit mode
                };
            if spe_lsass || ifeo {
                let mut h = FamilyHit::new(
                    CD07,
                    &p.guid,
                    Severity::Critical,
                    format!(
                        "{} set {loc}\\{value_name}{} — this makes Windows write an LSASS memory dump (credential theft) when LSASS is signalled",
                        who(&p),
                        data.map(|d| format!(" = {}", truncate(d, 80))).unwrap_or_default()
                    ),
                )
                .with_actions(vec![kill(&p), remove(None)]);
                h.strong = true;
                h.dedup_key = dedup;
                out.push(h);
                return;
            }
        }

        // ---- CD-09: LSA packages -----------------------------------------
        let pkg_value = (nk == LSA
            && matches!(
                vn.as_str(),
                "security packages" | "authentication packages" | "notification packages"
            ))
            || (nk == LSA_OSCONFIG && vn == "security packages");
        // A writer exemption needs the writer to be known exactly (V-H6).
        let exact = ctx.attribution(e) == Attribution::Exact;
        if pkg_value && set && !(exact && installer_writer(ctx, &p)) {
            let unknown: Vec<String> = data
                .unwrap_or("")
                .split(['\n', ',', ';', '\0'])
                .map(|s| s.trim().trim_matches('"').to_string())
                .filter(|s| !s.is_empty())
                .filter(|s| {
                    let n = file_name_lower(s);
                    let n = n.trim_end_matches(".dll");
                    !KNOWN_LSA_PACKAGES.contains(&n)
                })
                .collect();
            if !unknown.is_empty() {
                let actions = unknown
                    .iter()
                    .filter(|s| s.contains('\\'))
                    // V-H4: package paths are attacker text.
                    .filter(|s| ctx.attacker_path_ok(s, p.user.as_deref()))
                    .map(|s| quarantine_path(s))
                    .collect();
                let mut h = FamilyHit::new(
                    CD09,
                    &p.guid,
                    Severity::High,
                    format!(
                        "{} registered LSA package(s) {} in {value_name} — LSASS will load them at the next boot and they can capture every password typed at logon",
                        who(&p),
                        unknown.iter().map(|s| format!("\"{}\"", truncate(s, 60))).collect::<Vec<_>>().join(", ")
                    ),
                )
                .with_actions(actions);
                h.dedup_key = dedup;
                out.push(h);
            }
            return;
        }

        // ---- CD-12: WDigest cleartext downgrade --------------------------
        if nk == WDIGEST && set {
            let bad = match vn.as_str() {
                "uselogoncredential" => num != Some(0),
                "negotiate" => num == Some(1),
                _ => false,
            };
            if bad {
                let mut h = FamilyHit::new(
                    CD12,
                    &p.guid,
                    Severity::High,
                    format!(
                        "{} set WDigest {value_name} = {} — Windows will keep cleartext passwords in LSASS memory after the next logon",
                        who(&p),
                        data.unwrap_or("?")
                    ),
                )
                .with_actions(vec![remove(Some("dword:0"))]);
                h.dedup_key = dedup;
                out.push(h);
            }
            return;
        }

        // ---- CD-13: LSA protection / Credential Guard tamper -------------
        let off = (set && num == Some(0)) || deleted;
        let what: Option<&str> = if nk == LSA && vn == "runasppl" && off {
            Some("turned LSA protection (RunAsPPL) off")
        } else if nk == LSA && vn == "lsacfgflags" && off {
            Some("turned Credential Guard (LsaCfgFlags) off")
        } else if nk == CREDGUARD && vn == "enabled" && off {
            Some("turned Credential Guard off")
        } else if nk == DG_POLICY && vn == "lsacfgflags" && set && num == Some(0) {
            Some("turned the Credential Guard policy (LsaCfgFlags) off")
        } else if nk == LSA && vn == "disablerestrictedadmin" && set && num == Some(0) {
            Some("enabled RDP Restricted Admin mode (DisableRestrictedAdmin = 0), which allows pass-the-hash logons")
        } else if nk == KSLD
            && set
            && (vn == "imagepath" || vn == "allowedprocessname")
            && !(exact && defender_writer(ctx, &p))
        {
            Some("changed the Microsoft Defender KslD driver service (the KslDump technique reads LSASS memory through an old, vulnerable copy)")
        } else {
            None
        };
        if let Some(what) = what {
            let mut h = FamilyHit::new(
                CD13,
                &p.guid,
                if nk == KSLD {
                    Severity::Critical
                } else {
                    Severity::High
                },
                format!(
                    "{} {what} ({loc}\\{value_name}{})",
                    who(&p),
                    if deleted {
                        " deleted".to_string()
                    } else {
                        data.map(|d| format!(" = {}", truncate(d, 80)))
                            .unwrap_or_default()
                    }
                ),
            );
            h.dedup_key = dedup;
            out.push(h);
        }
    }

    fn on_service(&mut self, ctx: &Ctx, e: &Event, s: &ServiceInstall, out: &mut Vec<FamilyHit>) {
        if s.service_type != Some(1) {
            return;
        }
        let img = normalize_path(s.image_path.trim().trim_matches('"'));
        if img.contains(r"system32\drivers\") || img.contains(r"system32\driverstore\") {
            return;
        }
        let p = proc_of(ctx, e);
        if ctx.attribution(e) == Attribution::Exact && ctx.is_agent(&p) {
            return;
        }
        // FP-12 (DETECTION-QUALITY.md, 2026-10-25): NordVPN (re)installing
        // its own drivers (`travis.sys`, `NDivert.sys`) from its Program
        // Files folder on every update. The event carries no signer, so only
        // the exact (service name, path shape) pairs of VENDOR_DRIVERS on
        // the system volume drop to Low; any other driver, name or folder
        // keeps Medium.
        let vendor = sys_rest(ctx, s.image_path.trim().trim_matches('"'))
            .is_some_and(|rest| vendor_driver(&rest, &s.name));
        let mut h = FamilyHit::new(
            CD13,
            &p.guid,
            if vendor {
                Severity::Low
            } else {
                Severity::Medium
            },
            if vendor {
                format!(
                    "Kernel driver service \"{}\" was (re)installed from {} — a known vendor driver in its own Program Files folder (recorded only; a driver planted there by an administrator would look the same)",
                    s.name, s.image_path
                )
            } else {
                format!(
                    "Kernel driver service \"{}\" was installed from {} (outside System32\\drivers) — vulnerable signed drivers are used to switch off LSA protection and dump LSASS",
                    s.name, s.image_path
                )
            },
        );
        h.dedup_key = Some(format!("{CD13}:driver:{}", s.name.to_ascii_lowercase()));
        out.push(h);
    }
}

// ---------------------------------------------------------------------------
// trust helpers
// ---------------------------------------------------------------------------

/// Seed allow-list of LSASS openers (notes §3.2): exact path on the system
/// volume + valid Microsoft or known-vendor signature, mask-scoped where the
/// tool only legitimately needs handle duplication.
fn benign_opener(ctx: &Ctx, p: &ProcessInfo, mask: u32) -> bool {
    if ctx.is_agent(p) {
        return true;
    }
    let sd = ctx.system_drive();
    if protect::is_protected_security_product(&p.image, p.signed, p.signer.as_deref(), sd) {
        return true; // Defender / MDE at its real install location
    }
    let name = file_name_lower(&p.image);
    let ms = protect::microsoft_signed(p.signed, p.signer.as_deref());
    let rest = sys_rest(ctx, &p.image);
    if ms {
        if let Some(rest) = rest.as_deref() {
            for dir in [r"\windows\system32\", r"\windows\syswow64\"] {
                if let Some(n) = direct_child(rest, dir) {
                    if BENIGN_SYSTEM_OPENERS.contains(&n) {
                        return true;
                    }
                }
            }
            if [
                r"\windows\system32\wbem\wmiprvse.exe",
                r"\windows\syswow64\wbem\wmiprvse.exe",
                r"\windows\sysmon.exe",
                r"\windows\sysmon64.exe",
            ]
            .contains(&rest)
            {
                return true;
            }
        }
        // OneDrive (Microsoft-signed, per-user or per-machine install) opens
        // every process including LSASS with query + VM_READ (0x100411), seen
        // in the lab VM; LSA protection refuses it. Never write/inject/dup.
        let lp = p.image.to_ascii_lowercase().replace('/', "\\");
        if name == "onedrive.exe"
            && (lp.contains(r"\appdata\local\microsoft\onedrive\")
                || lp.contains(r"\program files\microsoft onedrive\"))
            && mask & (0x2 | 0x8 | 0x20 | 0x40 | 0x80) == 0
            && !full_or_max(mask)
        {
            return true;
        }
        // Process Explorer / Handle: only handle duplication (0x40) + query bits.
        if SYSINTERNALS_HANDLE_TOOLS.contains(&name.as_str())
            && mask & !PROCESS_DUP_HANDLE & DANGEROUS_BITS == 0
            && !full_or_max(mask)
        {
            return true;
        }
    }
    if p.signed != SignatureState::Valid
        || !matches!(p.path_class, PathClass::ProgramFiles | PathClass::System)
    {
        return false;
    }
    let signer = p.signer.as_deref().unwrap_or("").to_ascii_lowercase();
    if signer.is_empty() {
        return false;
    }
    // Third-party AV / EDR from the shared benign-reader list (signer required).
    if BENIGN_READERS.iter().any(|r| {
        r.kind == BenignKind::Security
            && crate::identity::signer_in(r.signers, Some(signer.as_str()))
            && glob_match(r.image, &name)
    }) {
        return true;
    }
    BENIGN_VENDOR_OPENERS
        .iter()
        .any(|(img, s)| *img == name && signer.contains(s))
}

/// Source that makes a dangerous LSASS handle suspicious (CD-03 / CD-06):
/// unsigned / unknown / user-writable / LOLBin, not Microsoft-signed,
/// a Microsoft binary outside the Windows / Program Files directories, or
/// Task Manager asking for full access (its "Create dump file").
fn suspicious_source(ctx: &Ctx, p: &ProcessInfo, mask: u32) -> bool {
    ctx.untrusted_actor(p)
        || !protect::microsoft_signed(p.signed, p.signer.as_deref())
        || !matches!(
            p.path_class,
            PathClass::System | PathClass::Windows | PathClass::ProgramFiles
        )
        || (file_name_lower(&p.image) == "taskmgr.exe" && full_or_max(mask))
}

/// FP-11 (DETECTION-QUALITY.md, 2026-10-25): a client whose anti-cheat asks
/// every process (LSASS included) for a fixed, non-reading mask that LSA
/// protection refuses. Identity is pinned by exact image name, exact signer
/// subject (no substring) and install folder; `mask` lists the only bits the
/// client was seen asking for plus the query / synchronize rights.
struct ProbeClient {
    image: &'static str,
    signer: &'static str,
    /// Bits a refused request may carry (anything else keeps High).
    mask: u32,
    app: &'static str,
}

const PROBE_CLIENTS: &[ProbeClient] = &[ProbeClient {
    image: "robloxplayerbeta.exe",
    signer: "Roblox Corporation",
    // Owner PC 2026-10-23: 0x40A (QUERY_INFORMATION | VM_OPERATION |
    // CREATE_THREAD) on lsass, taskhostw and svchost alike.
    mask: 0x400 | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD | 0x1000 | 0x10_0000,
    app: "Roblox game client",
}];

/// FP-11: the refused LSASS open of `p` with `mask` comes from a genuine
/// [`PROBE_CLIENTS`] entry: valid signature with the exact signer, exact
/// image name, not tampered with (injection / memory-write signals), mask
/// inside the client's set and never full / maximum-allowed, and the image
/// in the client's own `Roblox\Versions\version-<hex>\` folder on the system
/// volume (per-user `%LOCALAPPDATA%` of the process's own user, or Program
/// Files). Returns the client's label.
fn refused_probe_client(ctx: &Ctx, p: &ProcessInfo, mask: u32) -> Option<&'static str> {
    if p.signed != SignatureState::Valid || ctx.tampered(&p.guid) || full_or_max(mask) {
        return None;
    }
    let name = file_name_lower(&p.image);
    let signer = p.signer.as_deref().map(str::trim)?;
    let c = PROBE_CLIENTS
        .iter()
        .find(|c| c.image == name && c.signer == signer)?;
    if mask == 0 || mask & !c.mask != 0 {
        return None;
    }
    let rest = sys_rest(ctx, &p.image)?;
    roblox_install(&rest, &name, p.user.as_deref()).then_some(c.app)
}

/// `\users\<own profile>\appdata\local\roblox\versions\version-<hex>\<name>`
/// or `\program files[ (x86)]\roblox\versions\version-<hex>\<name>`
/// (`rest`: normalised, driveless, lower-case).
fn roblox_install(rest: &str, name: &str, user: Option<&str>) -> bool {
    let Some(dir) = rest.strip_suffix(name).and_then(|d| d.strip_suffix('\\')) else {
        return false;
    };
    let Some((base, version)) = dir.rsplit_once('\\') else {
        return false;
    };
    let hex = version.strip_prefix("version-").unwrap_or("");
    if hex.is_empty() || hex.len() > 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    if [
        r"\program files\roblox\versions",
        r"\program files (x86)\roblox\versions",
    ]
    .contains(&base)
    {
        return true;
    }
    let Some(profile) = base
        .strip_prefix(r"\users\")
        .and_then(|r| r.strip_suffix(r"\appdata\local\roblox\versions"))
    else {
        return false;
    };
    if profile.is_empty() || profile.contains('\\') {
        return false;
    }
    // The process's own profile (`name`, or `name.DOMAIN…`) when its user is
    // known.
    match user.map(|u| u.trim().to_ascii_lowercase()) {
        Some(u) if !u.is_empty() => {
            let n = u.rsplit('\\').next().unwrap_or(&u);
            let n = n.split('@').next().unwrap_or(n);
            !n.is_empty() && (profile == n || profile.starts_with(&format!("{n}.")))
        }
        _ => true,
    }
}

/// FP-12 (DETECTION-QUALITY.md, 2026-10-25): kernel drivers a known vendor
/// (re)installs from its own Program Files folder: (service name, path under
/// `\program files\` with `*` standing for one version folder of digits and
/// dots). The ServiceInstalled event carries no signer, so the exact service
/// name + exact path shape on the system volume is the identity (writing
/// under Program Files and creating a kernel service both need an
/// administrator already).
const VENDOR_DRIVERS: &[(&str, &str)] = &[
    (
        "travis",
        r"\program files\nordvpn\nordsec threatprotection\*\travis.sys",
    ),
    (
        "nordvpn divert driver",
        r"\program files\nordvpn\*\drivers\ndivert.sys",
    ),
];

/// FP-12: `image_path` (normalised, driveless) and `service` match a
/// [`VENDOR_DRIVERS`] entry.
fn vendor_driver(rest: &str, service: &str) -> bool {
    let service = service.trim().to_ascii_lowercase();
    VENDOR_DRIVERS.iter().any(|(svc, pat)| {
        *svc == service && {
            let (pre, post) = pat.split_once('*').unwrap_or((pat, ""));
            rest.len() > pre.len() + post.len()
                && rest.starts_with(pre)
                && rest.ends_with(post)
                && version_folder(&rest[pre.len()..rest.len() - post.len()])
        }
    })
}

/// `8.14.12.0`: digits separated by single dots (never `.` / `..`).
fn version_folder(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 32
        && v.split('.')
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Backup / VSS components and known backup vendors (CD-10 / CD-11 shadow access).
fn benign_backup(ctx: &Ctx, p: &ProcessInfo) -> bool {
    if ctx.system_trusted(p) {
        return true;
    }
    if p.signed != SignatureState::Valid
        || !matches!(p.path_class, PathClass::ProgramFiles | PathClass::System)
    {
        return false;
    }
    let signer = p.signer.as_deref().unwrap_or("").to_ascii_lowercase();
    !signer.is_empty() && BACKUP_SIGNERS.iter().any(|s| signer.contains(s))
}

/// Windows Installer / servicing writing LSA package values.
fn installer_writer(ctx: &Ctx, p: &ProcessInfo) -> bool {
    if !protect::microsoft_signed(p.signed, p.signer.as_deref()) {
        return false;
    }
    let Some(rest) = sys_rest(ctx, &p.image) else {
        return false;
    };
    rest == r"\windows\system32\msiexec.exe"
        || rest == r"\windows\syswow64\msiexec.exe"
        || rest == r"\windows\servicing\trustedinstaller.exe"
        || (rest.starts_with(r"\windows\winsxs\") && rest.ends_with(r"\tiworker.exe"))
}

/// Defender platform updates rewrite the KslD service.
fn defender_writer(ctx: &Ctx, p: &ProcessInfo) -> bool {
    protect::is_protected_security_product(
        &p.image,
        p.signed,
        p.signer.as_deref(),
        ctx.system_drive(),
    ) || installer_writer(ctx, p)
}

/// Is the target of a handle open the real LSASS?
fn is_lsass_target(ctx: &Ctx, t: &TargetProcess) -> bool {
    if t.target_pid == SENTINEL_PID || t.target_pid == 0 || t.target_pid == 4 {
        return false;
    }
    if let Some(l) = ctx.lsass() {
        match &t.target_guid {
            Some(g) => {
                if *g == l.guid {
                    return true;
                }
            }
            None => {
                if t.target_pid == l.pid {
                    return true;
                }
            }
        }
    }
    // Fallback when the table does not know LSASS (yet): the exact System32
    // path on the system volume, or an unmapped device path to it.
    let n = normalize_path(&t.target_image);
    let b = n.as_bytes();
    let rest = if b.len() >= 2 && b[1] == b':' {
        if b[0] as char != ctx.system_drive().to_ascii_lowercase() {
            return false;
        }
        &n[2..]
    } else {
        n.as_str()
    };
    rest == r"\windows\system32\lsass.exe"
}

/// Image directly inside System32 / SysWOW64 on the system volume.
fn in_system_dir(ctx: &Ctx, image: &str) -> bool {
    sys_rest(ctx, image).is_some_and(|r| {
        direct_child(&r, r"\windows\system32\").is_some()
            || direct_child(&r, r"\windows\syswow64\").is_some()
    })
}

/// Normalised driveless path when `image` is on the system volume.
fn sys_rest(ctx: &Ctx, image: &str) -> Option<String> {
    let raw = image.trim().replace('/', "\\").to_ascii_lowercase();
    let raw = raw.trim_start_matches(r"\\?\").trim_start_matches(r"\??\");
    if raw.starts_with(r"\device\") || raw.starts_with(r"\\") {
        return None;
    }
    let n = normalize_path(raw);
    let b = n.as_bytes();
    if b.len() >= 2 && b[1] == b':' {
        (b[0] as char == ctx.system_drive().to_ascii_lowercase()).then(|| n[2..].to_string())
    } else if n.starts_with('\\') {
        Some(n)
    } else {
        None
    }
}

fn direct_child<'a>(rest: &'a str, dir: &str) -> Option<&'a str> {
    let n = rest.strip_prefix(dir)?;
    (!n.is_empty() && !n.contains('\\')).then_some(n)
}

const BENIGN_SYSTEM_OPENERS: &[&str] = &[
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "smss.exe",
    "lsm.exe",
    "lsaiso.exe",
    "svchost.exe",
    "taskhostw.exe",
    "msiexec.exe",
    "mrt.exe",
];

const SYSINTERNALS_HANDLE_TOOLS: &[&str] = &[
    "procexp.exe",
    "procexp64.exe",
    "procexp64a.exe",
    "handle.exe",
    "handle64.exe",
    "handle64a.exe",
];

/// (image name, signer substring) of non-security vendors that open lsass.
const BENIGN_VENDOR_OPENERS: &[(&str, &str)] = &[
    ("vmtoolsd.exe", "vmware"),
    ("googleupdate.exe", "google"),
    ("updater.exe", "google"),
];

const BACKUP_SIGNERS: &[&str] = &[
    "veeam",
    "veritas",
    "acronis",
    "commvault",
    "cohesity",
    "rubrik",
    "arcserve",
    "datto",
    "n-able",
    "macrium",
];

const MIMIKATZ_COMMANDS: &[&str] = &[
    "sekurlsa::",
    "lsadump::",
    "misc::memssp",
    "misc::skeleton",
    "dpapi::cred",
];

/// Image names (lower-case globs) of public LSASS dumpers.
const KNOWN_DUMPERS: &[&str] = &[
    "mimikatz*.exe",
    "nanodump*.exe",
    "pplblade*.exe",
    "ppldump*.exe",
    "pplkiller*.exe",
    "pplfault*.exe",
    "safetykatz*.exe",
    "sharpkatz*.exe",
    "handlekatz*.exe",
    "pypykatz*.exe",
    "dumpert*.exe",
    "outflank-dumpert*.exe",
    "mirrordump*.exe",
    "lsassy*.exe",
];

const PROCDUMP_FLAGS: &[&str] = &[
    "-ma", "/ma", "-mm", "/mm", "-mp", "/mp", "-mc", "/mc", "-r", "/r",
];

/// FP-09: procdump dump-type flags that no text tool uses (`-r` is
/// "recursive" for grep / rg / findstr-style tools).
const STRONG_DUMP_FLAGS: &[&str] = &["-ma", "/ma", "-mm", "/mm", "-mp", "/mp", "-mc", "/mc"];

/// FP-09 (DETECTION-QUALITY.md, 2026-10-25): text-search, viewer and editor
/// tools whose arguments are search patterns or file names, not dump
/// targets. Matched by image name; they only lose the weak `-r` flag.
const TEXT_TOOLS: &[&str] = &[
    "grep.exe",
    "egrep.exe",
    "fgrep.exe",
    "rg.exe",
    "ag.exe",
    "ack.exe",
    "findstr.exe",
    "find.exe",
    "sed.exe",
    "awk.exe",
    "gawk.exe",
    "less.exe",
    "more.com",
    "cat.exe",
    "head.exe",
    "tail.exe",
    "code.exe",
    "git.exe",
];

/// FP-09: LSASS named as a target argument of its own: `lsass` /
/// `lsass.exe` / a path ending in `\lsass.exe` (quotes and a trailing comma
/// stripped), or the live LSASS PID as a whole token.
fn lsass_target_arg(ltokens: &[String], lsass_pid: Option<u32>) -> bool {
    let pid = lsass_pid.map(|l| l.to_string());
    ltokens.iter().skip(1).any(|t| {
        let t = t.trim_matches(|c: char| c == '"' || c == '\'' || c == ',');
        let leaf = t.rsplit(['\\', '/']).next().unwrap_or(t);
        leaf == "lsass" || leaf == "lsass.exe" || pid.as_deref() == Some(t)
    })
}

// ---------------------------------------------------------------------------
// parsing helpers
// ---------------------------------------------------------------------------

/// Whitespace split honouring double quotes (quotes removed).
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut q = false;
    let mut any = false;
    for c in s.chars() {
        match c {
            '"' => {
                q = !q;
                any = true;
            }
            c if c.is_whitespace() && !q => {
                if any || !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            c => cur.push(c),
        }
        if out.len() >= 64 {
            return out;
        }
    }
    if any || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// `#24`, `#+…`/`#-…` ordinal tricks and 16-bit wrap-arounds of 24 (`#65560`).
fn comsvcs_ordinal(lc: &str) -> bool {
    for (i, _) in lc.match_indices('#') {
        let rest = &lc[i + 1..];
        let (signed, digits) = match rest.as_bytes().first() {
            Some(b'+') | Some(b'-') => (true, &rest[1..]),
            _ => (false, rest),
        };
        let d: String = digits
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .take(20)
            .collect();
        if d.is_empty() {
            continue;
        }
        if signed {
            return true;
        }
        if d.parse::<u64>().is_ok_and(|n| n % 65536 == 24) {
            return true;
        }
    }
    false
}

/// (`pid`, output file) after the MiniDump export / ordinal token.
fn minidump_args(tokens: &[String], ltokens: &[String]) -> (Option<u32>, Option<String>) {
    let Some(start) = ltokens.iter().position(|t| t.contains("comsvcs")) else {
        return (None, None);
    };
    let export = ltokens
        .iter()
        .enumerate()
        .skip(start)
        .find(|(_, t)| t.contains("minidump") || t.contains('#'))
        .map(|(i, _)| i);
    let Some(i) = export else {
        return (None, None);
    };
    let pid = ltokens
        .get(i + 1)
        .and_then(|t| t.trim_matches(',').parse().ok());
    let file = tokens
        .get(i + 2)
        .map(|t| t.trim_matches(',').to_string())
        .filter(|f| !f.is_empty() && !f.eq_ignore_ascii_case("full"));
    (pid, file)
}

fn pid_after_flags(ltokens: &[String], flags: &[&str]) -> Option<u32> {
    ltokens
        .windows(2)
        .find(|w| flags.contains(&w[0].as_str()))
        .and_then(|w| w[1].parse().ok())
}

/// `SAM` / `SECURITY` / `SYSTEM` when `h` is that HKLM hive (any SAM /
/// SECURITY subkey; SYSTEM only as a whole hive).
fn sensitive_hive(h: &str) -> Option<&'static str> {
    let h = h.trim_matches('"').trim_end_matches('\\');
    let rest = h
        .strip_prefix(r"hklm\")
        .or_else(|| h.strip_prefix(r"hkey_local_machine\"))?;
    if rest == "sam" || rest.starts_with(r"sam\") {
        Some("SAM")
    } else if rest == "security" || rest.starts_with(r"security\") {
        Some("SECURITY")
    } else if rest == "system" {
        Some("SYSTEM")
    } else {
        None
    }
}

fn refs_config_hive(lc: &str) -> bool {
    [r"\config\sam", r"\config\security", r"\config\system"]
        .iter()
        .any(|h| {
            lc.match_indices(h).any(|(i, _)| {
                // not \config\systemprofile, \config\system32 …
                lc[i + h.len()..]
                    .chars()
                    .next()
                    .is_none_or(|c| !c.is_ascii_alphanumeric())
            })
        })
}

/// Corpus finding 10: the `-include:` list of `wbadmin start backup`
/// (lower-case tokens): the rest of the `-include:` / `/include:` token plus
/// the following tokens up to the next option, joined by spaces. `None` for
/// any other wbadmin verb or without `-include:`.
fn wbadmin_include(ltokens: &[String]) -> Option<String> {
    let start = ltokens.iter().position(|t| t == "start")?;
    if ltokens.get(start + 1).map(String::as_str) != Some("backup") {
        return None;
    }
    let i = ltokens
        .iter()
        .position(|t| t.starts_with("-include:") || t.starts_with("/include:"))?;
    let mut inc = ltokens[i]["-include:".len()..].to_string();
    for t in ltokens.iter().skip(i + 1) {
        if t.starts_with('-') || t.starts_with('/') {
            break;
        }
        inc.push(' ');
        inc.push_str(t);
    }
    Some(inc.replace('/', "\\"))
}

/// Corpus finding 10: ntdsutil / dsdbutil IFM media with secrets: an `ifm`
/// word followed by `create` (any abbreviation from `cr`) and then `full`
/// (any abbreviation from `fu`). `create rodc` media hold no secrets.
fn ifm_create(lc: &str) -> bool {
    let words: Vec<&str> = lc
        .split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
        .filter(|w| !w.is_empty())
        .take(64)
        .collect();
    let Some(i) = words.iter().position(|w| *w == "ifm") else {
        return false;
    };
    let rest = &words[i + 1..];
    let Some(c) = rest
        .iter()
        .position(|w| w.starts_with("cr") && "create".starts_with(*w))
    else {
        return false;
    };
    rest[c + 1..]
        .iter()
        .any(|w| w.len() >= 2 && "full".starts_with(*w))
}

fn is_shadow_create(name: &str, lc: &str) -> bool {
    (name == "vssadmin.exe" && lc.contains("create") && lc.contains("shadow"))
        || (lc.contains("shadowcopy") && lc.contains("call") && lc.contains("create"))
        || (lc.contains("win32_shadowcopy") && lc.contains("create"))
}

/// Canonical lower-case key: `HKLM\…`, `CurrentControlSet`, no `Wow6432Node`.
fn normalize_key(key: &str) -> String {
    let mut k = key.trim().replace('/', "\\").to_ascii_lowercase();
    for (from, to) in [
        (r"\registry\machine\", r"hklm\"),
        (r"hkey_local_machine\", r"hklm\"),
    ] {
        if let Some(r) = k.strip_prefix(from) {
            k = format!("{to}{r}");
        }
    }
    // Any numbered control set (`ControlSet001` … `ControlSet999`), V-L18.
    if let Some(rest) = k.strip_prefix(r"hklm\system\controlset") {
        let digits = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if digits > 0 && (rest.len() == digits || rest.as_bytes()[digits] == b'\\') {
            let tail = rest[digits..].trim_start_matches('\\');
            k = format!(r"hklm\system\currentcontrolset\{tail}");
        }
    }
    if let Some(r) = k.strip_prefix(r"hklm\software\wow6432node\") {
        k = format!(r"hklm\software\{r}");
    }
    k.trim_end_matches('\\').to_string()
}

/// Key as the agent's registry helpers expect it (`HKLM\…`, original case).
fn display_key(key: &str) -> String {
    let k = key.trim();
    let lower = k.to_ascii_lowercase();
    for from in [r"\registry\machine\", r"hkey_local_machine\"] {
        if lower.starts_with(from) {
            return format!(r"HKLM\{}", &k[from.len()..]);
        }
    }
    k.to_string()
}

/// REG_DWORD / QWORD in any rendering (see `util::reg_number`).
fn parse_num(d: &str) -> Option<u64> {
    crate::util::reg_number(d)
}

fn access_desc(mask: u32) -> String {
    let mut r = Vec::new();
    if mask == PROCESS_ALL_ACCESS {
        r.push("full");
    } else if mask & MAXIMUM_ALLOWED != 0 {
        r.push("maximum-allowed");
    } else {
        if mask & PROCESS_VM_READ != 0 {
            r.push("memory-read");
        }
        if mask & PROCESS_VM_WRITE != 0 {
            r.push("memory-write");
        }
        if mask & PROCESS_VM_OPERATION != 0 {
            r.push("vm-operation");
        }
        if mask & PROCESS_CREATE_THREAD != 0 {
            r.push("create-thread");
        }
        if mask & PROCESS_DUP_HANDLE != 0 {
            r.push("duplicate-handle");
        }
        if mask & PROCESS_CREATE_PROCESS != 0 {
            r.push("create-process (clone)");
        }
    }
    format!("{} access (0x{mask:x})", r.join("/"))
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

// ---------------------------------------------------------------------------
// process / action helpers
// ---------------------------------------------------------------------------

fn proc_of(ctx: &Ctx, e: &Event) -> ProcessInfo {
    ctx.process(&e.guid)
        .cloned()
        .unwrap_or_else(|| ProcessInfo {
            guid: e.guid.clone(),
            pid: e.pid,
            ppid: 0,
            parent_guid: None,
            image: String::new(),
            cmdline: String::new(),
            user: None,
            integrity: None,
            start_ts: e.ts,
            exit_ts: None,
            signer: None,
            signed: SignatureState::Unknown,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::Other,
        })
}

fn who(p: &ProcessInfo) -> String {
    if p.image.is_empty() {
        format!("Process {}", p.pid)
    } else {
        format!("{} (pid {})", crate::paths::file_name(&p.image), p.pid)
    }
}

fn kill(p: &ProcessInfo) -> ResponseAction {
    ResponseAction::KillProcess {
        pid: p.pid,
        guid: Some(p.guid.clone()),
        tree: true,
    }
}

fn quarantine_path(path: &str) -> ResponseAction {
    ResponseAction::QuarantineFile {
        path: path.to_string(),
        sha256: None,
    }
}

/// Quarantine the image only when it lives in a user-writable location
/// (never System32 binaries such as rundll32 / WerFault).
fn quarantine_image(p: &ProcessInfo) -> Option<ResponseAction> {
    (!p.image.is_empty() && p.path_class.is_user_writable()).then(|| {
        ResponseAction::QuarantineFile {
            path: p.image.clone(),
            sha256: p.sha256.clone(),
        }
    })
}

// ---------------------------------------------------------------------------
// catalog
// ---------------------------------------------------------------------------

const SIGMA_COMSVCS: &str = "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs";
const SIGMA_COMSVCS_ACCESS: &str = "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll";
const SIGMA_LSASS_FLAGS: &str = "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_susp_access_flag";
const SIGMA_LSASS_MEMDUMP: &str =
    "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_memdump";
const SIGMA_DUMP_FILES: &str = "https://detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_lsass_default_dump_file_names";
const SIGMA_DBGHELP: &str =
    "https://sigma.controlassurance.com/rules/proc_access_win_susp_dbgcore_dbghelp_load/";
const SIGMA_SPE: &str = "https://detection.fyi/sigmahq/sigma/windows/registry/registry_event/registry_event_silentprocessexit_lsass/";
const SIGMA_SHTINKERING: &str =
    "https://detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_lsass_shtinkering/";
const SIGMA_SSP: &str = "https://detection.fyi/sigmahq/sigma/windows/registry/registry_event/registry_event_ssp_added_lsa_config";
const SIGMA_REG_HIVES: &str = "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives";
const SIGMA_ESENTUTL: &str = "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy";
const SIGMA_WDIGEST: &str = "https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential/";
const FIBRATUS_ACCESS: &str = "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_suspicious_lsass_process_access.yml";
const FIBRATUS_DUMP: &str = "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_potential_lsass_memory_dump.yml";
const FIBRATUS_WER: &str = "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_lsass_memory_dump_via_wer.yml";
const FIBRATUS_HIVES: &str = "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_sensitive_registry_hive_dump.yml";
const CHOKEPOINTS: &str =
    "https://iimp0ster.github.io/detection-chokepoints/chokepoints/lsass-credential-dumping/";
const MS_ACCESS_RIGHTS: &str =
    "https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights";
const MS_LSA_PROTECTION: &str = "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection";
const MS_CREDGUARD: &str =
    "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works";
const RUSTINEL_302: &str = "https://github.com/Karib0u/rustinel/issues/302";
const WERFAULTSECURE: &str = "https://borncity.com/win/2025/09/28/windows-11-24h2-hackers-can-use-werfaultsecure-exe-to-steal-lsass-passwords-and-disable-security-software/";
const DEEPINSTINCT_SPE: &str =
    "https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2";
const REDCANARY_LSASS: &str =
    "https://redcanary.com/threat-detection-report/techniques/lsass-memory/";
const NTDS_SUSP_LOCATION: &str = "https://soc.cyber.wa.gov.au/guidelines/TTP_Hunt/ADS_forms/T1003.003-Creation-of-Ntds.dit-to-Suspicious-Location-in-Server/";
const MITRE_DCSYNC: &str = "https://attack.mitre.org/techniques/T1003/006/";
const CISA_WDIGEST: &str =
    "https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0087";
const ADSEC_WDIGEST: &str = "https://adsecurity.org/?p=559";
const KSLDUMP: &str = "https://www.besthub.dev/articles/how-ksldump-uses-a-microsoft-driver-to-bypass-ppl-and-dump-lsass-credentials-via-registry-edit-3c40a1c05f4a";

pub(crate) fn catalog() -> Vec<RuleMeta> {
    use RuleCategory::CredentialDumping as C;
    use Severity::*;
    vec![
        meta(CD01, "LSASS memory dump via comsvcs MiniDump",
            "rundll32 was started with comsvcs.dll and its MiniDump export (also the #24 ordinal, #+/#- ordinal tricks and 16-bit wrap-arounds such as #65560) with the 'full' argument, or rundll32 opened LSASS with memory-read / full / maximum-allowed rights. A MiniDump of a process other than LSASS is reported at medium severity without response. Logic follows SigmaHQ 646ea171 (author attribution: SigmaHQ, DRL 1.1).",
            C, Critical, &["T1003.001", "T1218.011"], true,
            "Kill rundll32 (process tree) and quarantine the dump file named on the command line",
            &[SIGMA_COMSVCS, SIGMA_COMSVCS_ACCESS, REDCANARY_LSASS],
            &["None known: no legitimate software dumps LSASS through comsvcs.dll (SigmaHQ: 'Unlikely')"]),
        meta(CD02, "Known LSASS dumping tool",
            "A known dumper ran against LSASS: procdump-style arguments (-ma/-mm/-mp/-mc/-r) with lsass / lsass.exe or the LSASS PID as a target argument of its own (also renamed copies; text-search tools such as grep, rg or findstr need -ma/-mm/-mp/-mc, since -r is their 'recursive'), createdump.exe with the LSASS PID, WerFault.exe / WerFaultSecure.exe started from outside System32/SysWOW64 (the 2025 old-WerFaultSecure technique), mimikatz command syntax (sekurlsa::, lsadump::, misc::memssp) or a known dumper image name (nanodump, PPLBlade, PPLdump, Dumpert, …). Hash/YARA hits arrive as IOC-HASH / YARA alerts.",
            C, Critical, &["T1003.001"], true,
            "Kill the tool (process tree) and quarantine its image when it runs from a user-writable folder. Microsoft-signed procdump / createdump under their own name only alert (support cases)",
            &[CHOKEPOINTS, WERFAULTSECURE, REDCANARY_LSASS],
            &["Administrators taking an LSASS dump with Microsoft-signed procdump for a Microsoft support case (alert only; add a time-boxed exclusion)", "Not raised for (FP-09, 2026-10-25): text tools searching source code for the word lsass (grep -n lsass\\|0x1410 -r src)"]),
        meta(CD03, "Suspicious LSASS handle request",
            "A process asked for a handle to LSASS with rights that allow reading, writing, cloning or duplicating it (VM_READ/VM_WRITE/VM_OPERATION/CREATE_THREAD/DUP_HANDLE/CREATE_PROCESS, PROCESS_ALL_ACCESS or MAXIMUM_ALLOWED), and the requester is not on the path + signer allow-list of known openers and is unsigned, not Microsoft-signed, user-writable, a LOLBin, or Task Manager asking for full access. Kernel-Audit-API-Calls reports the desired access, not the granted one.",
            C, High, &["T1003.001"], false,
            "Suspend the requesting process for the suspend window (a later CD-04/CD-05 hit kills it); never acts on LSASS",
            &[FIBRATUS_ACCESS, SIGMA_LSASS_FLAGS, MS_ACCESS_RIGHTS, RUSTINEL_302],
            &["Third-party antivirus / EDR not yet on the allow-list", "Backup, password-sync and SSO / smart-card middleware", "Monitoring agents that request MAXIMUM_ALLOWED", "Task Manager 'Create dump file' by an administrator"]),
        meta(CD04, "LSASS handle followed by a dump file",
            "A process that opened LSASS with dangerous rights (and is not an allow-listed opener) wrote a .dmp / .mdmp / .dump file, or a file with 'lsass' in its name, within 120 seconds. Two independent facts, mirroring the Fibratus LSASS memory-dump sequence rule.",
            C, Critical, &["T1003.001"], true,
            "Kill the process tree and quarantine the dump file (and the image when it runs from a user-writable folder)",
            &[FIBRATUS_DUMP, SIGMA_DUMP_FILES, CHOKEPOINTS],
            &["Support engineers deliberately dumping LSASS (use a time-boxed exclusion)"]),
        meta(CD05, "Debug library dump helper reading LSASS",
            "An unsigned, user-writable or LOLBin process loaded dbghelp.dll or dbgcore.dll (MiniDumpWriteDump) and opened LSASS with dangerous rights within 60 seconds. The image load alone is telemetry: debuggers, crash reporters and anti-cheat load dbghelp constantly but do not read LSASS.",
            C, Critical, &["T1003.001"], true,
            "Kill the process tree and quarantine its image when it runs from a user-writable folder",
            &[SIGMA_DBGHELP, SIGMA_LSASS_MEMDUMP, CHOKEPOINTS],
            &["Developer debugging tools run from a user folder against LSASS (rare)"]),
        meta(CD06, "Blocked LSASS access attempt",
            "A suspicious process asked for dangerous rights on LSASS and Windows refused the open (non-zero NTSTATUS, e.g. LSA protection / RunAsPPL held). Nothing was read, but a credential-dumping attempt is a strong hunting lead. Opens of non-existent PIDs (STATUS_INVALID_CID) are ignored.",
            C, High, &["T1003.001"], false,
            "Alert; in Protect mode also suspend the requesting process for the suspend window",
            &[MS_LSA_PROTECTION, RUSTINEL_302, FIBRATUS_ACCESS],
            &["Inventory / monitoring tools that request full access and fall back to query rights", "Low Audit (owner PC 2026-10-22): a validly signed native service or updater installed under Program Files on the system volume (not an interpreter, LOLBin or Electron host) whose refused request carried only read / query rights (VM_READ, QUERY_INFORMATION, QUERY_LIMITED_INFORMATION, SYNCHRONIZE; e.g. NVIDIA nvcontainer.exe and BraveUpdate.exe asking for 0x410). Unsigned or user-path openers, write / thread / dup-handle masks and successful opens (CD-03) keep their severity", "Low Audit (FP-11, 2026-10-25): the genuine Roblox client (RobloxPlayerBeta.exe signed exactly 'Roblox Corporation', in its own Roblox\\Versions\\version-<hex> folder, not tampered) whose refused request carried only query / VM_OPERATION / CREATE_THREAD (its anti-cheat asks every process for 0x40A). Other copies, VM_READ / VM_WRITE / DUP_HANDLE / full masks and successful opens keep High"]),
        meta(CD07, "LSASS dump preparation via SilentProcessExit / IFEO",
            "A value was written under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass*, or Image File Execution Options\\lsass.exe got GlobalFlag with FLG_MONITOR_SILENT_PROCESS_EXIT (0x200), Debugger or VerifierDlls. AuditLevel=8 (LSA protection audit mode) is legitimate and ignored. Logic follows SigmaHQ 55e29995 (author attribution: SigmaHQ, DRL 1.1).",
            C, Critical, &["T1003.001", "T1112", "T1546.012"], true,
            "Kill the writer (process tree) and delete the value (the agent backs it up to the quarantine vault first)",
            &[SIGMA_SPE, DEEPINSTINCT_SPE],
            &["None known (SigmaHQ: 'Unlikely')"]),
        meta(CD08, "LSASS dump via Windows Error Reporting",
            "WerFault.exe / WerFaultSecure.exe was started against the LSASS PID (or with lsass on its command line), or wrote a file with 'lsass' in its path such as CrashDumps\\lsass.exe.<pid>.dmp (LSASS Shtinkering, silent-process-exit dumps). A real LSASS crash restarts Windows instead of producing a quiet WER dump.",
            C, Critical, &["T1003.001"], true,
            "Kill WerFault (process tree) and quarantine the dump file",
            &[FIBRATUS_WER, SIGMA_SHTINKERING, WERFAULTSECURE],
            &["None expected: treat any WER dump of LSASS as an incident"]),
        meta(CD09, "Malicious LSA security package",
            "A non-installer process registered a non-Microsoft package in Lsa\\Security Packages, Authentication Packages, Notification Packages or Lsa\\OSConfig\\Security Packages; LSASS loaded a DLL that is not Microsoft-signed; or the mimikatz memssp log (mimilsa.log / kiwissp.log) was written to System32. Logic follows SigmaHQ eeb30123 (author attribution: SigmaHQ, DRL 1.1).",
            C, High, &["T1547.005", "T1556.002", "T1003.001"], false,
            "Quarantine the package DLL when it lies in a user-writable folder; the value itself is not reverted automatically (reverting LSA packages can break logon) and LSASS is never killed",
            &[SIGMA_SSP, "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_suspicious_security_package_loaded_by_lsass.yml"],
            &["Password filters (AD password sync, MFA vendors)", "Smart-card / credential-provider middleware", "Third-party SSO packages"]),
        meta(CD10, "Credential hive save or copy",
            "reg.exe save/export of HKLM\\SAM or HKLM\\SECURITY (critical) or the whole HKLM\\SYSTEM hive (high); esentutl /vss or /y copying config\\SAM|SECURITY|SYSTEM; command lines referencing shadow-copy or RegBack copies of those hives; wbadmin start backup with config\\SAM|SECURITY|SYSTEM in its -include: list (high, alert only); or a process other than Windows backup components / known backup vendors opening a hive inside a volume shadow copy. Logic follows SigmaHQ fd877b94 and e7be6119 (author attribution: SigmaHQ, DRL 1.1).",
            C, Critical, &["T1003.002", "T1003.004", "T1003.005"], true,
            "For reg save/export of SAM or SECURITY: kill reg.exe (process tree) and quarantine the output file. Other sub-cases alert only",
            &[SIGMA_REG_HIVES, SIGMA_ESENTUTL, FIBRATUS_HIVES],
            &["Backup software (wbengine, wbadmin, Veeam, Veritas, Acronis, SCCM)", "Forensic collectors (KAPE, Velociraptor)", "Administrators exporting the SYSTEM hive for troubleshooting"]),
        meta(CD11, "NTDS.dit extraction",
            "ntdsutil / dsdbutil 'ifm' + 'create full' (any abbreviation ntdsutil accepts, e.g. 'cr fu', and 'create sysvol full'); wbadmin start backup with ntds.dit in its -include: list (the Akira technique); a command line copying ntds.dit out of a volume shadow copy, with esentutl, or within 10 minutes of a shadow copy being created; or an ntds.dit file written outside %SystemRoot%\\NTDS. Mainly relevant on domain controllers. DCSync (directory replication from a non-DC) is out of scope: it leaves no credential-access trace on the endpoint and needs DC-side logs.",
            C, High, &["T1003.003"], false,
            "Kill the process tree and quarantine the copied ntds.dit when it is in a user-writable folder",
            &[NTDS_SUSP_LOCATION, SIGMA_ESENTUTL, MITRE_DCSYNC],
            &["Domain-controller administrators building IFM media for a new DC", "AD backup tools"]),
        meta(CD12, "WDigest cleartext credential downgrade",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential was set to a non-zero value (or Negotiate = 1), which makes LSASS keep cleartext passwords after the next logon. Windows 8.1+ default is 0.",
            C, High, &["T1112", "T1003.001", "T1562.001"], true,
            "Set the value back to 0 (backed up first); the writer is not killed",
            &[SIGMA_WDIGEST, CISA_WDIGEST, ADSEC_WDIGEST],
            &["Legacy applications that still need Digest authentication (rare)"]),
        meta(CD13, "LSA protection / Credential Guard tamper",
            "Lsa\\RunAsPPL set to 0 or deleted; LsaCfgFlags / Credential Guard Enabled set to 0 or deleted; DisableRestrictedAdmin set to 0; the Defender KslD driver service ImagePath / AllowedProcessName changed by anything but Defender or Windows servicing (KslDump); or a kernel-driver service installed from outside System32\\drivers (bring-your-own-vulnerable-driver).",
            C, High, &["T1562.001", "T1112", "T1068"], false,
            "Alert only (the setting is not reverted automatically, so deliberate administrator changes are not overridden)",
            &[MS_LSA_PROTECTION, MS_CREDGUARD, KSLDUMP],
            &["IT disabling LSA protection for an unsigned smart-card / password-filter plug-in", "Microsoft Defender platform updates rewriting KslD", "Antivirus, VPN or anti-cheat drivers installed under Program Files (Low for the exact NordVPN travis.sys / NDivert.sys services in their versioned Program Files folders, FP-12 2026-10-25)"]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dangerous_bits() {
        assert!(dangerous(0x1010));
        assert!(dangerous(0x1410));
        assert!(dangerous(0x1FFFFF));
        assert!(dangerous(0x0200_0000));
        assert!(dangerous(0x40));
        assert!(dangerous(0x80));
        assert!(!dangerous(0x1000));
        assert!(!dangerous(0x1400));
        assert!(!dangerous(0x401));
        assert!(!dangerous(0x100000));
        assert!(!dangerous(0x1200));
    }

    #[test]
    fn ordinals() {
        assert!(comsvcs_ordinal("rundll32 comsvcs.dll,#24 1 x full"));
        assert!(comsvcs_ordinal("rundll32 comsvcs.dll #65560 1 x full"));
        assert!(comsvcs_ordinal("rundll32 comsvcs.dll #+0024 1 x full"));
        assert!(comsvcs_ordinal(
            "rundll32 comsvcs.dll #-4294967272 1 x full"
        ));
        assert!(!comsvcs_ordinal("rundll32 comsvcs.dll #23 1 x full"));
        assert!(!comsvcs_ordinal("no ordinal here"));
    }

    #[test]
    fn minidump_parsing() {
        let c = r#"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 "C:\Users\a\AppData\Local\Temp\o.dmp" full"#;
        let t = tokenize(c);
        let l: Vec<String> = t.iter().map(|s| s.to_ascii_lowercase()).collect();
        assert_eq!(
            minidump_args(&t, &l),
            (
                Some(624),
                Some(r"C:\Users\a\AppData\Local\Temp\o.dmp".into())
            )
        );
        let c = r"rundll32 comsvcs.dll,#24 624 C:\t\o.dmp full";
        let t = tokenize(c);
        let l: Vec<String> = t.iter().map(|s| s.to_ascii_lowercase()).collect();
        assert_eq!(minidump_args(&t, &l).0, Some(624));
    }

    #[test]
    fn hives_and_keys() {
        assert_eq!(sensitive_hive(r"hklm\sam"), Some("SAM"));
        assert_eq!(
            sensitive_hive(r"hkey_local_machine\security\"),
            Some("SECURITY")
        );
        assert_eq!(sensitive_hive(r"hklm\system"), Some("SYSTEM"));
        assert_eq!(
            sensitive_hive(r"hklm\system\currentcontrolset\services\x"),
            None
        );
        assert_eq!(sensitive_hive(r"hkcu\software"), None);
        assert!(refs_config_hive(r"copy c:\windows\system32\config\sam x"));
        assert!(!refs_config_hive(
            r"c:\windows\system32\config\systemprofile\x"
        ));
        assert_eq!(
            normalize_key(r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa"),
            LSA
        );
        assert_eq!(
            normalize_key(
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\lsass.exe"
            ),
            IFEO_LSASS
        );
        assert_eq!(
            display_key(r"\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\Lsa"),
            r"HKLM\SYSTEM\ControlSet001\Control\Lsa"
        );
        assert_eq!(parse_num("1"), Some(1));
        assert_eq!(parse_num("0x200"), Some(512));
        assert_eq!(parse_num("dword:00000200"), Some(512));
        assert_eq!(parse_num("abc"), None);
    }
}

#[cfg(test)]
mod key_tests {
    use super::normalize_key;

    #[test]
    fn any_numbered_control_set_folds_v_l18() {
        for cs in [
            "ControlSet001",
            "ControlSet002",
            "ControlSet004",
            "ControlSet017",
        ] {
            assert_eq!(
                normalize_key(&format!(
                    r"\REGISTRY\MACHINE\SYSTEM\{cs}\Control\SecurityProviders\WDigest"
                )),
                r"hklm\system\currentcontrolset\control\securityproviders\wdigest",
                "{cs}"
            );
        }
        assert_eq!(
            normalize_key(r"HKLM\SYSTEM\ControlSet005"),
            r"hklm\system\currentcontrolset"
        );
        // not a control set
        assert_eq!(
            normalize_key(r"HKLM\SYSTEM\ControlSetX\Control"),
            r"hklm\system\controlsetx\control"
        );
        assert_eq!(
            normalize_key(r"HKLM\SOFTWARE\ControlSet001\x"),
            r"hklm\software\controlset001\x"
        );
    }
}
