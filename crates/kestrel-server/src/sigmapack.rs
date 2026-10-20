//! The vendored SigmaHQ Audit pack (`rules/sigmahq/`, DRL 1.1), seeded into
//! the `rules` table at startup.
//!
//! * Every pack rule becomes a custom Sigma rule `SIG-<uuid8>` with
//!   `default_mode` Audit, `enabled` true, `meta.author` = the Sigma `author`,
//!   `meta.license` = `DRL-1.1` and `meta.references` = the upstream URL pinned
//!   to the vendored commit followed by the rule's own references.
//! * Seeding is idempotent and runs under an advisory lock. The table
//!   `sigma_pack_rules` remembers which rules the server seeded and the source
//!   it last wrote, so:
//!   * an admin's `enabled` / `default_mode` choices are never overwritten;
//!   * a rule an admin deleted is not re-created;
//!   * a rule whose source an admin edited is left alone;
//!   * a rule with the same id that an admin imported before the pack existed
//!     is adopted only if its source is identical, else left alone;
//!   * a rule dropped from a newer pack is removed unless an admin edited it.
//! * `settings.rules_version` is bumped only when a row actually changed.
//! * A pack rule that fails to compile in this build's engine is skipped
//!   (logged) rather than poisoning the all-or-nothing agent bundle.

use crate::crypto::sha256_hex;
use kestrel_common::{now_ms, RuleCategory, RuleDef, RuleKind, RuleMeta, RuleMode};
use kestrel_detect::{validate_sigma, Engine, HostContext};
use serde::Deserialize;
use serde_json::Value;
use sqlx::PgPool;
use std::collections::HashSet;

/// `rules/sigmahq/pack.json`.
pub const PACK_JSON: &str = include_str!("../../../rules/sigmahq/pack.json");

/// Licence attached to every pack rule.
pub const PACK_LICENSE: &str = "DRL-1.1";

#[derive(Debug, Clone, Deserialize)]
pub struct Pack {
    pub name: String,
    pub version: String,
    pub commit: String,
    pub license: String,
    pub license_url: String,
    pub rules: Vec<PackRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PackRule {
    pub id: String,
    pub sigma_id: String,
    pub title: String,
    pub author: String,
    pub level: String,
    pub status: String,
    pub category: String,
    /// Kestrel rule family: ransomware, credential_dumping, persistence,
    /// execution, tamper, exfiltration.
    pub group: String,
    pub file: String,
    pub sha256: String,
    pub upstream: String,
}

/// Parsed manifest.
pub fn pack() -> anyhow::Result<Pack> {
    Ok(serde_json::from_str(PACK_JSON)?)
}

/// Vendored YAML of a manifest entry.
pub fn source_of(file: &str) -> Option<&'static str> {
    PACK_SOURCES
        .iter()
        .find(|(f, _)| *f == file)
        .map(|(_, s)| *s)
}

fn category(group: &str) -> RuleCategory {
    match group {
        "ransomware" => RuleCategory::Ransomware,
        "credential_dumping" => RuleCategory::CredentialDumping,
        "persistence" => RuleCategory::Persistence,
        "execution" => RuleCategory::Execution,
        "tamper" => RuleCategory::Tamper,
        "exfiltration" => RuleCategory::Exfiltration,
        _ => RuleCategory::Custom,
    }
}

/// Rule metadata for a pack entry (default mode Audit).
pub fn rule_meta(r: &PackRule, source: &str) -> anyhow::Result<RuleMeta> {
    let info = validate_sigma(source).map_err(|e| anyhow::anyhow!("{}: {e}", r.id))?;
    anyhow::ensure!(
        info.sigma_id.as_deref() == Some(r.sigma_id.as_str()),
        "{}: YAML id does not match pack.json",
        r.id
    );
    let mut references = vec![r.upstream.clone()];
    references.extend(
        info.references
            .iter()
            .filter(|x| **x != r.upstream)
            .cloned(),
    );
    let mut false_positives = info.false_positives.clone();
    false_positives.extend(info.notes.iter().cloned());
    Ok(RuleMeta {
        id: r.id.clone(),
        name: info.title.chars().take(200).collect(),
        description: info.description.clone().unwrap_or_default(),
        kind: RuleKind::Sigma,
        category: category(&r.group),
        severity: info.severity,
        attack: info.attack.clone(),
        default_mode: RuleMode::Audit,
        protect_day_one: false,
        protect_action: String::new(),
        // DRL 1.1: the author must stay with the rule and with every alert.
        author: info.author.clone().or_else(|| Some(r.author.clone())),
        license: Some(PACK_LICENSE.into()),
        references,
        false_positives,
    })
}

fn compiles(def: &RuleDef) -> anyhow::Result<()> {
    let mut engine = Engine::new(
        HostContext::default(),
        Default::default(),
        Default::default(),
    )?;
    engine.update_rules(kestrel_common::RuleBundle {
        version: 1,
        rules: vec![def.clone()],
    })?;
    Ok(())
}

/// What a seeding run did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SeedReport {
    pub inserted: usize,
    pub updated: usize,
    pub adopted: usize,
    pub removed: usize,
    pub unchanged: usize,
    /// Left alone: deleted or edited by an admin, or an admin's own rule with the same id.
    pub kept_admin: usize,
    pub invalid: usize,
    pub rules_version_bumped: bool,
}

/// Insert or update the pack rules. Idempotent; safe to run on every start.
pub async fn seed(db: &PgPool) -> anyhow::Result<SeedReport> {
    let pack = pack()?;
    let mut rep = SeedReport::default();
    let mut tx = db.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(7413002)")
        .execute(&mut *tx)
        .await?;
    let now = now_ms();
    let mut in_pack = HashSet::new();
    for r in &pack.rules {
        in_pack.insert(r.id.clone());
        let Some(source) = source_of(&r.file) else {
            tracing::error!(rule = %r.id, file = %r.file, "sigma pack: vendored file missing from build");
            rep.invalid += 1;
            continue;
        };
        let meta = match rule_meta(r, source) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(rule = %r.id, error = %e, "sigma pack: rule rejected");
                rep.invalid += 1;
                continue;
            }
        };
        let def = RuleDef {
            meta: meta.clone(),
            source: source.to_string(),
        };
        if let Err(e) = compiles(&def) {
            tracing::error!(rule = %r.id, error = %e, "sigma pack: rule does not compile");
            rep.invalid += 1;
            continue;
        }
        let sha = sha256_hex(source);
        let row: Option<(Value, String)> =
            sqlx::query_as("SELECT meta, source FROM rules WHERE id = $1")
                .bind(&r.id)
                .fetch_optional(&mut *tx)
                .await?;
        let tracked: Option<(String,)> =
            sqlx::query_as("SELECT source_sha256 FROM sigma_pack_rules WHERE id = $1")
                .bind(&r.id)
                .fetch_optional(&mut *tx)
                .await?;
        match (row, tracked) {
            (None, None) => {
                sqlx::query("INSERT INTO rules (id, kind, meta, source, enabled, created_by, created_at, updated_at) VALUES ($1,'sigma',$2,$3,true,NULL,$4,$4)")
                    .bind(&r.id)
                    .bind(serde_json::to_value(&meta)?)
                    .bind(source)
                    .bind(now)
                    .execute(&mut *tx)
                    .await?;
                track(&mut tx, r, &sha, &pack.commit, now).await?;
                rep.inserted += 1;
            }
            // Seeded before, deleted by an admin since: respect it.
            (None, Some(_)) => rep.kept_admin += 1,
            (Some((_, stored_src)), None) => {
                if stored_src == source {
                    // The admin imported this exact SigmaHQ rule earlier: adopt
                    // it without touching their settings.
                    track(&mut tx, r, &sha, &pack.commit, now).await?;
                    rep.adopted += 1;
                } else {
                    tracing::info!(rule = %r.id, "sigma pack: an admin rule with this id exists; leaving it");
                    rep.kept_admin += 1;
                }
            }
            (Some((stored_meta, stored_src)), Some((seeded_sha,))) => {
                if sha256_hex(&stored_src) != seeded_sha {
                    tracing::info!(rule = %r.id, "sigma pack: rule edited by an admin; not updating");
                    rep.kept_admin += 1;
                    continue;
                }
                // Keep the admin's mode choice; everything else follows the pack.
                let mut want = meta.clone();
                if let Some(m) = stored_meta
                    .get("default_mode")
                    .and_then(|v| serde_json::from_value::<RuleMode>(v.clone()).ok())
                {
                    want.default_mode = m;
                }
                let want_v = serde_json::to_value(&want)?;
                if stored_src == source && stored_meta == want_v {
                    rep.unchanged += 1;
                    continue;
                }
                sqlx::query(
                    "UPDATE rules SET meta = $2, source = $3, updated_at = $4 WHERE id = $1",
                )
                .bind(&r.id)
                .bind(want_v)
                .bind(source)
                .bind(now)
                .execute(&mut *tx)
                .await?;
                track(&mut tx, r, &sha, &pack.commit, now).await?;
                rep.updated += 1;
            }
        }
    }
    // Rules dropped from the pack: remove them unless an admin edited them.
    let tracked: Vec<(String, String)> =
        sqlx::query_as("SELECT id, source_sha256 FROM sigma_pack_rules")
            .fetch_all(&mut *tx)
            .await?;
    for (id, seeded_sha) in tracked {
        if in_pack.contains(&id) {
            continue;
        }
        let row: Option<(String,)> = sqlx::query_as("SELECT source FROM rules WHERE id = $1")
            .bind(&id)
            .fetch_optional(&mut *tx)
            .await?;
        if let Some((src,)) = row {
            if sha256_hex(&src) != seeded_sha {
                // Edited: it is the admin's rule now.
                sqlx::query("DELETE FROM sigma_pack_rules WHERE id = $1")
                    .bind(&id)
                    .execute(&mut *tx)
                    .await?;
                rep.kept_admin += 1;
                continue;
            }
            sqlx::query("DELETE FROM rules WHERE id = $1")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
            rep.removed += 1;
        }
        sqlx::query("DELETE FROM sigma_pack_rules WHERE id = $1")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    if rep.inserted + rep.updated + rep.removed > 0 {
        sqlx::query("UPDATE settings SET rules_version = rules_version + 1 WHERE id = 1")
            .execute(&mut *tx)
            .await?;
        rep.rules_version_bumped = true;
    }
    tx.commit().await?;
    tracing::info!(
        pack = %pack.name,
        commit = %pack.commit,
        inserted = rep.inserted,
        updated = rep.updated,
        adopted = rep.adopted,
        removed = rep.removed,
        unchanged = rep.unchanged,
        kept_admin = rep.kept_admin,
        invalid = rep.invalid,
        "SigmaHQ Audit pack seeded"
    );
    Ok(rep)
}

async fn track(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    r: &PackRule,
    sha: &str,
    commit: &str,
    now: i64,
) -> anyhow::Result<()> {
    sqlx::query(
        "INSERT INTO sigma_pack_rules (id, sigma_id, source_sha256, pack_commit, seeded_at) VALUES ($1,$2,$3,$4,$5) \
         ON CONFLICT (id) DO UPDATE SET sigma_id = EXCLUDED.sigma_id, source_sha256 = EXCLUDED.source_sha256, \
         pack_commit = EXCLUDED.pack_commit, seeded_at = EXCLUDED.seeded_at",
    )
    .bind(&r.id)
    .bind(&r.sigma_id)
    .bind(sha)
    .bind(commit)
    .bind(now)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// `(pack.json "file", vendored YAML)`, embedded at build time.
pub static PACK_SOURCES: &[(&str, &str)] = &[
    (
        "rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_shadowcopy_deletion.yml"),
    ),
    (
        "rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml",
        include_str!("../../../rules/sigmahq/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_reg_volsnap_disable.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_fsutil_usage.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_fsutil_usage.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_service_tamper.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_service_tamper.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_pua_rclone_execution.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_sysinternals_procdump_lsass.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_lsass_dmp_cli_keywords.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_lsass_dmp_cli_keywords.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_cmd_shadowcopy_access.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_ntds.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_ntds.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_hktl_mimikatz_command_line.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_createdump_lolbin_execution.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_rdrleakdiag_process_dumping.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_sam_access.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_sam_access.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_getprocess_lsass.yml"),
    ),
    (
        "rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml",
        include_str!("../../../rules/sigmahq/rules/windows/powershell/powershell_script/posh_ps_susp_getprocess_lsass.yml"),
    ),
    (
        "rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml",
        include_str!("../../../rules/sigmahq/rules/windows/powershell/powershell_script/posh_ps_potential_invoke_mimikatz.yml"),
    ),
    (
        "rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_access/proc_access_win_lsass_dump_keyword_image.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_schtasks_creation_temp_folder.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_schtasks_creation_temp_folder.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_schtasks_folder_combos.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_schtasks_susp_pattern.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_schtasks_susp_pattern.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_schtasks_appdata_local_system.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_schtasks_appdata_local_system.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_service_creation.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_service_creation.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wmic_eventconsumer_creation.yml"),
    ),
    (
        "rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml",
        include_str!("../../../rules/sigmahq/rules/windows/registry/registry_set/registry_set_susp_reg_persist_explorer_run.yml"),
    ),
    (
        "rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml",
        include_str!("../../../rules/sigmahq/rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_certutil_download_direct_ip.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_certutil_download_file_sharing_domains.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_certutil_decode.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_certutil_decode.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_mshta_http.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_mshta_http.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_mshta_javascript.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_mshta_javascript.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_mshta_susp_pattern.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_mshta_susp_child_processes.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_mshta_susp_child_processes.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_regsvr32_http_ip_pattern.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_regsvr32_http_ip_pattern.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_regsvr32_susp_exec_path_2.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_regsvr32_susp_extensions.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_regsvr32_susp_extensions.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_rundll32_mshtml_runhtmlapplication.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_rundll32_unc_path.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_office_susp_child_processes.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wmic_squiblytwo_bypass.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wmic_susp_process_creation.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_bitsadmin_download_direct_ip.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_curl_download_direct_ip_susp_extensions.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_curl_download_direct_ip_susp_extensions.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_curl_susp_download.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_curl_susp_download.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_base64_iex.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_cmstp_execution_by_creation.yml"),
    ),
    (
        "rules/windows/image_load/image_load_dll_dbghelp_dbgcore_unsigned_load.yml",
        include_str!("../../../rules/sigmahq/rules/windows/image_load/image_load_dll_dbghelp_dbgcore_unsigned_load.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_disable_defender_av_security_monitoring.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_defender_disable_feature.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_defender_disable_feature.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_remove_mppreference.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_remove_mppreference.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_powershell_base64_mppreference.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_powershell_base64_mppreference.yml"),
    ),
    (
        "rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml",
        include_str!("../../../rules/sigmahq/rules/windows/powershell/powershell_script/posh_ps_tamper_windows_defender_set_mp.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_reg_windows_defender_tamper.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_reg_windows_defender_tamper.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_reg_disable_sec_services.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_reg_disable_sec_services.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wmic_uninstall_security_products.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_wmic_namespace_defender.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_wmic_namespace_defender.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_auditpol_susp_execution.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_logman_disable_eventlog.yml"),
    ),
    (
        "rules/windows/process_creation/proc_creation_win_susp_etw_trace_evasion.yml",
        include_str!("../../../rules/sigmahq/rules/windows/process_creation/proc_creation_win_susp_etw_trace_evasion.yml"),
    ),
    (
        "rules/windows/network_connection/net_connection_win_domain_ngrok.yml",
        include_str!("../../../rules/sigmahq/rules/windows/network_connection/net_connection_win_domain_ngrok.yml"),
    ),
    (
        "rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml",
        include_str!("../../../rules/sigmahq/rules/windows/network_connection/net_connection_win_domain_ngrok_tunnel.yml"),
    ),
    (
        "rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml",
        include_str!("../../../rules/sigmahq/rules/windows/dns_query/dns_query_win_tor_onion_domain_query.yml"),
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_and_embedded_sources_agree() {
        let p = pack().unwrap();
        assert_eq!(p.license, PACK_LICENSE);
        assert_eq!(p.rules.len(), PACK_SOURCES.len());
        for r in &p.rules {
            let src = source_of(&r.file).unwrap_or_else(|| panic!("{} not embedded", r.file));
            // Vendored verbatim: the hash recorded at vendoring time still matches.
            assert_eq!(sha256_hex(src), r.sha256, "{} was modified", r.file);
            let m = rule_meta(r, src).unwrap();
            assert_eq!(m.id, r.id);
            assert_eq!(m.author.as_deref(), Some(r.author.as_str()));
            assert_eq!(m.license.as_deref(), Some("DRL-1.1"));
            assert_eq!(m.references[0], r.upstream);
            assert!(r.upstream.contains(&p.commit));
            assert_eq!(m.default_mode, RuleMode::Audit);
            compiles(&RuleDef {
                meta: m,
                source: src.to_string(),
            })
            .unwrap();
        }
    }
}
