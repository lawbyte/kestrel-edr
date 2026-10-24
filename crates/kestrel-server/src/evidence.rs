//! Evidence capture for suspected data theft — server side (owner decision
//! 2026-10-25, `docs/DECISIONS.md` decisions 7, 8, 9, 11, 13).
//!
//! * [`report`] ingests `AgentPayload::Evidence` (lifecycle + privacy-filtered
//!   manifest, scrubbed again here) into `evidence_bundles`. Nothing of it is
//!   ever written to the telemetry store, ClickHouse or hunt.
//! * An administrator collects a bundle (`POST /api/evidence/:id/collect`,
//!   `crate::api::evidence`): the server queues
//!   `ResponseAction::CollectEvidence`; when the PC reports it ok,
//!   [`on_collect_result`] starts a **pull** over the live channel
//!   (`LiveServerMsg::EvidenceRead` → `LiveAgentMsg::EvidenceData`,
//!   sequential ≤ 512 KiB chunks, SHA-256 checked) that writes the bundle
//!   sealed (`kestrel_common::seal` under a random per-bundle data key that
//!   is stored wrapped with the master key in `evidence_bundles.data_key_enc`
//!   and dropped on deletion / expiry; context = bundle id) to
//!   `<KESTREL_EVIDENCE_DIR>/<id>.kes`, re-validates the
//!   container and then asks the PC to delete its copy.
//! * Downloads are AES-256 zips built from the sealed file on a blocking
//!   thread (plaintext only in memory), offered once to the same admin
//!   session for 10 minutes ([`Hub`] tickets; passwords are never stored).
//! * [`retention`] deletes stored bundles after `retention_days.evidence`,
//!   expires uncollected ones the PC dropped, and sweeps orphaned files.

use crate::{
    audit::{self, Actor},
    ingest::{self, Session},
    remote::{clean_text, LiveSession},
    scrub::{redact_secrets, Scrub},
    settings::Settings,
    state::AppState,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use dashmap::DashMap;
use kestrel_common::{
    evidence::{
        self as ev, container, EvidenceManifest, EvidenceReport, EvidenceState, CAP_EVIDENCE,
        MAX_BUNDLE_BYTES, READ_CHUNK_MAX,
    },
    now_ms,
    remote::{FileReply, LiveAgentMsg, LiveServerMsg},
    seal, ActionOutcome, ResponseAction,
};
use rand::RngCore;
use serde_json::json;
use std::{
    collections::{HashMap, VecDeque},
    io::{self, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::sync::{mpsc, Semaphore};
use uuid::Uuid;

/// Bundles pulled from PCs at the same time (server-wide).
pub const MAX_CONCURRENT_PULLS: usize = 2;
/// `EvidenceRead` requests kept in flight during a pull.
pub const PULL_WINDOW: usize = 4;
/// Wait for each `EvidenceData` reply (never extended by other messages).
pub const CHUNK_TIMEOUT: Duration = Duration::from_secs(60);
/// Overall pull deadline: this much plus the size at [`PULL_MIN_RATE`].
pub const PULL_BASE_DEADLINE: Duration = Duration::from_secs(300);
/// Slowest upload rate a pull is given time for (bytes / s).
pub const PULL_MIN_RATE: u64 = 64 * 1024;

/// Overall deadline of a pull of `size` bytes (M6).
pub fn pull_deadline(size: u64) -> Duration {
    PULL_BASE_DEADLINE + Duration::from_secs(size / PULL_MIN_RATE)
}
/// Download archives built at the same time.
pub const MAX_CONCURRENT_BUILDS: usize = 2;
/// Unused download tickets one admin may hold.
pub const MAX_TICKETS_PER_USER: usize = 3;
/// A download ticket (and its archive) lives this long.
pub const DOWNLOAD_TTL_MS: i64 = 10 * 60_000;
/// Longest `last_error` kept.
const ERROR_MAX_CHARS: usize = 500;
/// Alert ids kept per bundle.
const MAX_ALERT_IDS: usize = 64;
/// Upper bound of a stored (scrubbed) manifest, JSON bytes (review of the
/// 1.1.7 integration, M4: was 4 MB; a full manifest with the contract's
/// list caps and clipped strings is about 2 MB at worst and typically tens
/// of kilobytes; the bundle itself keeps the complete one).
pub const MANIFEST_MAX_JSON: usize = 1024 * 1024;
/// Rows one device may hold that are still open (`capturing`,
/// `ready_on_device`, `collecting`) or name an alert the server does not
/// have for that device (M4). New bundles beyond it are ignored.
pub const MAX_OPEN_BUNDLES_PER_DEVICE: i64 = 32;
/// Bundles one alert may have (the agent makes one per tree; merges and a
/// retry after a restart stay far below).
pub const MAX_BUNDLES_PER_ALERT: i64 = 4;
/// Uncollected bundles are marked expired this long after the PC's own
/// deletion time (`local_expires_at`).
const LOCAL_EXPIRY_GRACE_MS: i64 = 86_400_000;
const DAY_MS: i64 = 86_400_000;

/// Status values (`evidence_bundles.status`, console `EvidenceStatus`).
pub const STATUSES: &[&str] = &[
    "capturing",
    "ready_on_device",
    "collecting",
    "stored",
    "failed",
    "expired",
    "deleted",
];

/// A one-time download (archive already built, encrypted).
#[derive(Clone, Debug)]
pub struct Ticket {
    pub path: PathBuf,
    pub user_id: Uuid,
    /// Console session (`sessions.token_hash`) that asked for it.
    pub session: String,
    pub bundle_id: Uuid,
    pub device_id: Uuid,
    pub hostname: String,
    pub file_name: String,
    pub size: u64,
    pub expires_at: i64,
    /// Admin's reason (audit only).
    pub reason: String,
}

/// In-memory evidence state: pulls in progress, build / pull slots, tickets.
pub struct Hub {
    pulls: DashMap<Uuid, ()>,
    pull_slots: Arc<Semaphore>,
    pub(crate) build_slots: Arc<Semaphore>,
    pub(crate) tickets: DashMap<String, Ticket>,
    /// Download files being built or streamed (never swept).
    pub(crate) busy_files: DashMap<PathBuf, ()>,
    /// One pull per device at a time (M6).
    device_locks: DashMap<Uuid, Arc<tokio::sync::Mutex<()>>>,
}

impl Default for Hub {
    fn default() -> Self {
        Hub {
            pulls: DashMap::new(),
            pull_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_PULLS)),
            build_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_BUILDS)),
            tickets: DashMap::new(),
            busy_files: DashMap::new(),
            device_locks: DashMap::new(),
        }
    }
}

impl Hub {
    /// Is a pull of `id` running?
    pub fn pulling(&self, id: &Uuid) -> bool {
        self.pulls.contains_key(id)
    }
}

/// Removes a path from `busy_files` on drop.
pub(crate) struct BusyFile {
    st: AppState,
    path: PathBuf,
}

impl BusyFile {
    pub(crate) fn new(st: &AppState, path: PathBuf) -> BusyFile {
        st.evidence.busy_files.insert(path.clone(), ());
        BusyFile {
            st: st.clone(),
            path,
        }
    }
}

impl Drop for BusyFile {
    fn drop(&mut self) {
        self.st.evidence.busy_files.remove(&self.path);
    }
}

// ------------------------------------------------------------------ storage

pub fn blob_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.kes"))
}

pub fn partial_path(dir: &Path, id: Uuid) -> PathBuf {
    dir.join(format!("{id}.kes.partial"))
}

pub fn downloads_dir(dir: &Path) -> PathBuf {
    dir.join("downloads")
}

/// A fresh random per-bundle data key (crypto-shredding: the key is stored
/// wrapped with the master key in the bundle's row and dropped on deletion /
/// expiry, so a recovered blob can no longer be opened).
pub fn new_data_key() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    k
}

/// Wrap a data key for `evidence_bundles.data_key_enc`.
pub fn wrap_key(st: &AppState, k: &[u8; 32]) -> String {
    st.mk.seal(k)
}

/// Unwrap `evidence_bundles.data_key_enc`.
pub fn unwrap_key(st: &AppState, sealed: &str) -> anyhow::Result<[u8; 32]> {
    let v = st.mk.open(sealed)?;
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad evidence data key"))
}

/// Remove unused download tickets (and their archives) of a bundle.
pub fn purge_tickets(st: &AppState, id: Uuid) {
    let stale: Vec<String> = st
        .evidence
        .tickets
        .iter()
        .filter(|t| t.bundle_id == id)
        .map(|t| t.key().clone())
        .collect();
    for k in stale {
        if let Some((_, t)) = st.evidence.tickets.remove(&k) {
            remove_quiet(&t.path);
        }
    }
}

/// Bring `expires_at` of stored bundles in line with the current
/// `retention_days.evidence` (counted from `collected_at`).
pub async fn apply_retention_days(st: &AppState, days: u32) -> anyhow::Result<u64> {
    let days = days.clamp(1, ev::MAX_RETENTION_DAYS) as i64;
    Ok(sqlx::query(
        "UPDATE evidence_bundles SET expires_at = collected_at + $1          WHERE status = 'stored' AND collected_at IS NOT NULL AND expires_at IS DISTINCT FROM collected_at + $1",
    )
    .bind(days * DAY_MS)
    .execute(&st.db)
    .await?
    .rows_affected())
}

/// Seal context: the bundle id (a sealed file never opens as another bundle).
pub fn seal_context(id: Uuid) -> [u8; 16] {
    *id.as_bytes()
}

/// Create the evidence and download directories (0700 on Unix).
pub fn ensure_dirs(dir: &Path) -> io::Result<()> {
    for d in [dir.to_path_buf(), downloads_dir(dir)] {
        std::fs::create_dir_all(&d)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn remove_quiet(p: &Path) {
    if let Err(e) = std::fs::remove_file(p) {
        if e.kind() != io::ErrorKind::NotFound {
            tracing::warn!(path = %p.display(), error = %e, "removing an evidence file failed");
        }
    }
}

/// Startup: directories, leftovers of a previous run (no pull or download
/// survives a restart).
pub fn init(cfg: &crate::config::Config) {
    let dir = &cfg.evidence_dir;
    if let Err(e) = ensure_dirs(dir) {
        tracing::warn!(dir = %dir.display(), error = %e, "evidence directory unavailable (KESTREL_EVIDENCE_DIR); collecting evidence will fail until it is writable");
        return;
    }
    let mut removed = 0;
    for (d, partial_only) in [(dir.clone(), true), (downloads_dir(dir), false)] {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_file() {
                continue;
            }
            let name = e.file_name().to_string_lossy().to_string();
            if !partial_only || name.ends_with(".kes.partial") {
                remove_quiet(&p);
                removed += 1;
            }
        }
    }
    if removed > 0 {
        tracing::info!(
            removed,
            "removed unfinished evidence uploads / downloads of a previous run"
        );
    }
}

// ------------------------------------------------------------------ ingest

/// `alert_ids` of a report: the first alert first, de-duplicated, capped.
fn merge_alert_ids(existing: &[Uuid], first: Uuid, more: &[Uuid]) -> Vec<Uuid> {
    let mut out: Vec<Uuid> = Vec::new();
    for id in std::iter::once(&first).chain(existing).chain(more) {
        if !id.is_nil() && !out.contains(id) && out.len() < MAX_ALERT_IDS {
            out.push(*id);
        }
    }
    out
}

fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Clean free text: control / bidi characters, secrets, redacted path prefixes.
fn clean_free(s: &mut String, max: usize, sc: &Scrub) {
    *s = redact_secrets(&clean_text(s, max));
    sc.text(s);
}

/// Clean a path / image field: control / bidi characters, secrets, then the
/// policy's redacted prefixes (whole field → `[REDACTED]`).
fn clean_path(s: &mut String, sc: &Scrub) {
    *s = redact_secrets(&clean_text(s, 1024));
    sc.path(s);
    sc.text(s);
}

fn clean_opt_sha(s: &mut Option<String>) {
    if s.as_deref().is_some_and(|v| !is_sha256_hex(v)) {
        *s = None;
    }
    if let Some(v) = s.as_mut() {
        *v = v.to_ascii_lowercase();
    }
}

fn clean_copy(c: &mut ev::FileCopy, sc: &Scrub) {
    if c.entry.as_deref().is_some_and(|e| !ev::valid_entry_name(e)) {
        c.entry = None;
    }
    clean_opt_sha(&mut c.sha256);
    clean_free(&mut c.detail, 300, sc);
}

/// Server-side scrub of an agent-reported manifest (defence in depth on top
/// of the agent's privacy filter): control / bidi characters stripped,
/// secrets redacted, the device policy's redacted path prefixes applied,
/// lists capped at the contract limits.
pub fn scrub_manifest(m: &mut EvidenceManifest, sc: &Scrub) {
    m.rule_id = clean_text(&m.rule_id, 32);
    m.hostname = clean_text(&m.hostname, 255);
    m.agent_version = clean_text(&m.agent_version, 64);
    m.alert_ids.truncate(MAX_ALERT_IDS);
    m.processes.truncate(ev::MAX_TREE_PROCESSES);
    for p in &mut m.processes {
        p.guid.0 = clean_text(&p.guid.0, 128);
        clean_path(&mut p.image, sc);
    }
    m.staged.truncate(ev::MAX_STAGED_FILES);
    for f in &mut m.staged {
        clean_path(&mut f.path, sc);
        clean_path(&mut f.image, sc);
        f.process_guid.0 = clean_text(&f.process_guid.0, 128);
        clean_copy(&mut f.copy, sc);
    }
    m.secrets.truncate(ev::MAX_SECRETS);
    for s in &mut m.secrets {
        clean_path(&mut s.path, sc);
        clean_path(&mut s.image, sc);
        s.store = clean_text(&s.store, 100);
        s.noun = clean_text(&s.noun, 100);
        s.process_guid.0 = clean_text(&s.process_guid.0, 128);
        if let Some(c) = s.copy.as_mut() {
            clean_copy(c, sc);
        }
    }
    if let Some(p) = m.pcap.as_mut() {
        p.mechanism = clean_text(&p.mechanism, 32);
        p.filters
            .retain(|f| f.ip.parse::<std::net::IpAddr>().is_ok());
        p.filters.truncate(ev::PCAP_MAX_FILTERS);
        if p.entry.as_deref().is_some_and(|e| !ev::valid_entry_name(e)) {
            p.entry = None;
        }
        clean_opt_sha(&mut p.sha256);
        clean_free(&mut p.detail, 300, sc);
    }
    m.notes.truncate(64);
    for n in &mut m.notes {
        clean_free(n, 500, sc);
    }
    m.notes.retain(|n| !n.is_empty());
    // Hard cap on what is stored: halve the staged list, then the secrets
    // list, then the process list (the bundle keeps the full manifest).
    let mut shortened = false;
    while serde_json::to_vec(m).map_or(0, |v| v.len()) > MANIFEST_MAX_JSON {
        if !m.staged.is_empty() {
            let keep = m.staged.len() / 2;
            m.staged.truncate(keep);
        } else if !m.secrets.is_empty() {
            let keep = m.secrets.len() / 2;
            m.secrets.truncate(keep);
        } else if m.processes.len() > 1 {
            let keep = m.processes.len() / 2;
            m.processes.truncate(keep.max(1));
        } else {
            m.notes.clear();
            break;
        }
        shortened = true;
    }
    if shortened
        && !m
            .notes
            .iter()
            .any(|n| n.starts_with("The server shortened"))
    {
        m.notes.push(
            "The server shortened the lists of this manifest (too large to store); the bundle holds the complete one.".into(),
        );
    }
}

/// `AgentPayload::Evidence`: upsert the bundle row (scoped to the stream's
/// device). Never touches the telemetry store.
pub async fn report(st: &AppState, s: &Session, r: EvidenceReport) -> anyhow::Result<()> {
    let now = now_ms();
    let id = r.bundle_id;
    if id.is_nil() || r.alert_id.is_nil() {
        tracing::warn!(device_id = %s.device_id, "evidence report without bundle / alert id ignored");
        return Ok(());
    }
    // Alerts of another device are never linked (a bundle shows on every
    // incident whose alerts it names).
    let mut wanted = merge_alert_ids(&[], r.alert_id, &r.alert_ids);
    let foreign: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM alerts WHERE id = ANY($1) AND device_id <> $2")
            .bind(&wanted)
            .bind(s.device_id)
            .fetch_all(&st.db)
            .await?;
    if foreign.iter().any(|f| f.0 == r.alert_id) {
        tracing::warn!(device_id = %s.device_id, bundle_id = %id, "evidence report naming another device's alert ignored");
        return Ok(());
    }
    wanted.retain(|a| !foreign.iter().any(|f| f.0 == *a));
    let rule_id = clean_text(&r.rule_id, 32);
    let detail = redact_secrets(&clean_text(&r.detail, ERROR_MAX_CHARS));

    // Review of the 1.1.7 integration (M4): the bundle's alert must be this
    // device's evidence trigger (ST-02 / ST-04). The agent queues its first
    // `Capturing` (and an immediate `Failed`) before the alert itself, so an
    // alert the server does not have yet is accepted for those, bounded by
    // the per-device cap below; a `Ready` report (the only one that stores
    // a manifest) needs the alert.
    let alert_rule: Option<(String,)> =
        sqlx::query_as("SELECT rule_id FROM alerts WHERE id = $1 AND device_id = $2")
            .bind(r.alert_id)
            .bind(s.device_id)
            .fetch_optional(&st.db)
            .await?;
    let alert_known = match &alert_rule {
        Some((rule,)) if !ev::is_trigger_rule(rule) => {
            tracing::warn!(device_id = %s.device_id, bundle_id = %id, rule = %rule, "evidence report for an alert that does not start a capture ignored");
            return Ok(());
        }
        Some(_) => true,
        None => false,
    };
    if !alert_known && r.state == EvidenceState::Ready {
        tracing::warn!(device_id = %s.device_id, bundle_id = %id, "evidence Ready report for an unknown alert ignored");
        return Ok(());
    }

    let mut tx = st.db.begin().await?;
    // Per-device and per-alert caps on new rows (M4). Serialised per device
    // by locking the device row, so concurrent reports cannot overshoot.
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM evidence_bundles WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        sqlx::query("SELECT id FROM devices WHERE id = $1 FOR UPDATE")
            .bind(s.device_id)
            .execute(&mut *tx)
            .await?;
        let (open, per_alert): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE e.status IN ('capturing','ready_on_device','collecting') \
                    OR NOT EXISTS (SELECT 1 FROM alerts a WHERE a.id = e.alert_id AND a.device_id = e.device_id)), \
                    count(*) FILTER (WHERE e.alert_id = $2) \
             FROM evidence_bundles e WHERE e.device_id = $1",
        )
        .bind(s.device_id)
        .bind(r.alert_id)
        .fetch_one(&mut *tx)
        .await?;
        if open >= MAX_OPEN_BUNDLES_PER_DEVICE || per_alert >= MAX_BUNDLES_PER_ALERT {
            tx.rollback().await?;
            tracing::warn!(device_id = %s.device_id, bundle_id = %id, open, per_alert, "evidence report ignored: too many open bundles for this device or alert");
            return Ok(());
        }
    }
    let created = sqlx::query(
        "INSERT INTO evidence_bundles (id, device_id, alert_id, alert_ids, rule_id, status, created_at, updated_at) \
         VALUES ($1,$2,$3,$4,$5,'capturing',$6,$6) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(s.device_id)
    .bind(r.alert_id)
    .bind(&wanted)
    .bind(&rule_id)
    .bind(now)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        == 1;
    let (owner, status, existing_ids): (Uuid, String, Vec<Uuid>) = sqlx::query_as(
        "SELECT device_id, status, alert_ids FROM evidence_bundles WHERE id = $1 FOR UPDATE",
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await?;
    if owner != s.device_id {
        tx.rollback().await?;
        tracing::warn!(device_id = %s.device_id, bundle_id = %id, "evidence report for a bundle of another device ignored");
        return Ok(());
    }
    let alert_ids = merge_alert_ids(&existing_ids, r.alert_id, &wanted);
    let on_pc = matches!(status.as_str(), "capturing" | "ready_on_device");
    let mut new_status = status.clone();
    match r.state {
        EvidenceState::Capturing => {}
        EvidenceState::Ready if on_pc => {
            let sha = r
                .bundle_sha256
                .as_deref()
                .filter(|h| is_sha256_hex(h))
                .map(str::to_ascii_lowercase);
            let size_ok = r.bundle_size > 0 && r.bundle_size <= MAX_BUNDLE_BYTES;
            match sha.filter(|_| size_ok) {
                None => {
                    new_status = "failed".into();
                    sqlx::query(
                        "UPDATE evidence_bundles SET status = 'failed', last_error = $2 WHERE id = $1",
                    )
                    .bind(id)
                    .bind("the PC reported an invalid bundle (size or SHA-256); it cannot be collected")
                    .execute(&mut *tx)
                    .await?;
                }
                Some(sha) => {
                    let manifest = match r.manifest {
                        Some(mut m) if m.bundle_id == id => {
                            let privacy = ingest::device_privacy(st, s.device_id).await?;
                            let prefixes = crate::scrub::norm_prefixes(&privacy);
                            let sc = ingest::scrub_for(st, &privacy, &prefixes);
                            scrub_manifest(&mut m, &sc);
                            Some(serde_json::to_value(&m)?)
                        }
                        Some(_) => {
                            tracing::warn!(device_id = %s.device_id, bundle_id = %id, "evidence manifest of another bundle dropped");
                            None
                        }
                        None => None,
                    };
                    new_status = "ready_on_device".into();
                    sqlx::query(
                        "UPDATE evidence_bundles SET status = 'ready_on_device', manifest = $2, bundle_size = $3, bundle_sha256 = $4, \
                         captured_at = $5, local_expires_at = $6 WHERE id = $1",
                    )
                    .bind(id)
                    .bind(manifest)
                    .bind(r.bundle_size as i64)
                    .bind(sha)
                    .bind(r.ts.clamp(0, now))
                    .bind(r.local_expires_at.filter(|t| *t > 0))
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }
        // A late duplicate never moves a bundle that is being collected,
        // stored or already gone.
        EvidenceState::Ready => {}
        EvidenceState::Failed if on_pc => {
            new_status = "failed".into();
            sqlx::query(
                "UPDATE evidence_bundles SET status = 'failed', last_error = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(if detail.is_empty() {
                "the capture failed on the PC".to_string()
            } else {
                detail.clone()
            })
            .execute(&mut *tx)
            .await?;
        }
        EvidenceState::Failed => {}
        EvidenceState::Deleted | EvidenceState::Expired => {
            // A bundle already on the server stays `stored`.
            if !matches!(status.as_str(), "stored" | "deleted" | "expired") {
                let s2 = if r.state == EvidenceState::Deleted {
                    "deleted"
                } else {
                    "expired"
                };
                new_status = s2.into();
                sqlx::query(
                    "UPDATE evidence_bundles SET status = $2, deleted_at = CASE WHEN $2 = 'deleted' THEN $3 ELSE deleted_at END WHERE id = $1",
                )
                .bind(id)
                .bind(s2)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            }
        }
    }
    sqlx::query("UPDATE evidence_bundles SET alert_ids = $2, updated_at = $3 WHERE id = $1")
        .bind(id)
        .bind(&alert_ids)
        .bind(now)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    if new_status != status {
        tracing::info!(device_id = %s.device_id, bundle_id = %id, from = %status, to = %new_status, "evidence bundle state");
    }
    // M4: console clients hear about real changes only (a repeated report
    // must not flood the event stream).
    if created || new_status != status || alert_ids != existing_ids {
        st.publish("evidence", id, if created { "created" } else { "updated" });
    }
    Ok(())
}

// ------------------------------------------------------------------ collect

/// Display name + actor of a user (audit / API).
async fn user_actor(st: &AppState, id: Option<Uuid>) -> Actor {
    let Some(id) = id else {
        return Actor::system();
    };
    let row: Option<(String,)> = sqlx::query_as("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await
        .ok()
        .flatten();
    Actor {
        id: Some(id),
        email: row.map(|r| r.0),
    }
}

/// Incident of a bundle's first alert (same device), if the alert is stored.
pub async fn incident_of(
    st: &AppState,
    device_id: Uuid,
    alert_id: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    let row: Option<(Option<Uuid>,)> =
        sqlx::query_as("SELECT incident_id FROM alerts WHERE id = $1 AND device_id = $2")
            .bind(alert_id)
            .bind(device_id)
            .fetch_optional(&st.db)
            .await?;
    Ok(row.and_then(|r| r.0))
}

/// Bytes stored plus bytes being collected (storage cap).
pub async fn storage_in_use(st: &AppState) -> anyhow::Result<u64> {
    let (n,): (Option<i64>,) = sqlx::query_as(
        "SELECT sum(CASE WHEN status = 'stored' THEN COALESCE(stored_size, bundle_size) ELSE bundle_size END)::bigint \
         FROM evidence_bundles WHERE status IN ('stored','collecting')",
    )
    .fetch_one(&st.db)
    .await?;
    Ok(n.unwrap_or(0).max(0) as u64)
}

/// The agent answered `CollectEvidence`.
pub async fn on_collect_result(
    st: &AppState,
    device_id: Uuid,
    command_id: Uuid,
    bundle_id: Uuid,
    outcome: &ActionOutcome,
) -> anyhow::Result<()> {
    let artifact_ok = outcome
        .artifact
        .as_deref()
        .is_none_or(|a| a.trim().eq_ignore_ascii_case(&bundle_id.to_string()));
    if outcome.ok && artifact_ok {
        let n = sqlx::query(
            "UPDATE evidence_bundles SET collect_action_id = $3, updated_at = $4 WHERE id = $1 AND device_id = $2 AND status = 'collecting'",
        )
        .bind(bundle_id)
        .bind(device_id)
        .bind(command_id)
        .bind(now_ms())
        .execute(&st.db)
        .await?
        .rows_affected();
        if n == 1 {
            spawn_pull(st, bundle_id);
        }
        return Ok(());
    }
    let (why, agent) = if outcome.ok {
        ("the PC prepared a different bundle than requested", None)
    } else {
        let d = redact_secrets(&clean_text(&outcome.detail, 300));
        (
            "the PC could not prepare the upload",
            Some(d).filter(|d| !d.is_empty()),
        )
    };
    fail_collect(st, bundle_id, device_id, why, agent.as_deref()).await
}

/// Start a pull in the background (no-op when one is running).
pub fn spawn_pull(st: &AppState, id: Uuid) {
    let st = st.clone();
    tokio::spawn(async move { pull(st, id).await });
}

/// Ends a pull registration on drop.
struct PullGuard {
    st: AppState,
    id: Uuid,
}

impl Drop for PullGuard {
    fn drop(&mut self) {
        self.st.evidence.pulls.remove(&self.id);
    }
}

#[derive(sqlx::FromRow)]
struct PullRow {
    device_id: Uuid,
    hostname: String,
    alert_id: Uuid,
    bundle_size: i64,
    bundle_sha256: Option<String>,
    collect_requested_by: Option<Uuid>,
}

async fn pull(st: AppState, id: Uuid) {
    use dashmap::mapref::entry::Entry;
    match st.evidence.pulls.entry(id) {
        Entry::Occupied(_) => return,
        Entry::Vacant(v) => {
            v.insert(());
        }
    }
    let _guard = PullGuard { st: st.clone(), id };
    let row: Option<PullRow> = match sqlx::query_as(
        "SELECT e.device_id, d.hostname, e.alert_id, e.bundle_size, e.bundle_sha256, e.collect_requested_by \
         FROM evidence_bundles e JOIN devices d ON d.id = e.device_id WHERE e.id = $1 AND e.status = 'collecting'",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(bundle_id = %id, error = %e, "evidence pull: loading the bundle failed");
            return;
        }
    };
    let Some(row) = row else {
        return;
    };
    // M6: one pull per device, at most MAX_CONCURRENT_PULLS server-wide.
    let lock = st
        .evidence
        .device_locks
        .entry(row.device_id)
        .or_default()
        .clone();
    let _device = lock.lock().await;
    let Ok(_permit) = st.evidence.pull_slots.clone().acquire_owned().await else {
        return;
    };
    // Still wanted after the wait (deleted meanwhile?).
    let still: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM evidence_bundles WHERE id = $1 AND status = 'collecting'")
            .bind(id)
            .fetch_optional(&st.db)
            .await
            .ok()
            .flatten();
    if still.is_none() {
        return;
    }
    tracing::info!(bundle_id = %id, device_id = %row.device_id, bytes = row.bundle_size, "evidence upload started");
    let mut agent_error: Option<String> = None;
    let res = pull_inner(&st, id, &row, &mut agent_error).await;
    let partial = partial_path(&st.cfg.evidence_dir, id);
    match res {
        Ok((stored_size, sha, key)) => {
            if let Err(e) = finish_pull(&st, id, &row, stored_size, &sha, &key).await {
                tracing::error!(bundle_id = %id, error = %e, "evidence upload: recording the stored bundle failed");
                remove_quiet(&blob_path(&st.cfg.evidence_dir, id));
                let _ = fail_collect(
                    &st,
                    id,
                    row.device_id,
                    "the server could not record the stored bundle",
                    None,
                )
                .await;
            }
        }
        Err(e) => {
            remove_quiet(&partial);
            tracing::info!(bundle_id = %id, device_id = %row.device_id, error = %e, "evidence upload failed");
            if let Err(e2) = fail_collect(&st, id, row.device_id, &e, agent_error.as_deref()).await
            {
                tracing::warn!(bundle_id = %id, error = %e2, "evidence upload: recording the failure failed");
            }
        }
    }
}

/// Pull, seal and validate one bundle. Returns (sealed file size, SHA-256).
async fn pull_inner(
    st: &AppState,
    id: Uuid,
    row: &PullRow,
    agent_error: &mut Option<String>,
) -> Result<(u64, String, [u8; 32]), String> {
    let size = u64::try_from(row.bundle_size).unwrap_or(0);
    if size == 0 || size > MAX_BUNDLE_BYTES {
        return Err("the reported bundle size is invalid".into());
    }
    let expected_sha = row
        .bundle_sha256
        .clone()
        .filter(|h| is_sha256_hex(h))
        .ok_or("the PC did not report the bundle's SHA-256")?;
    let others = storage_in_use(st)
        .await
        .map_err(|e| format!("database error: {e}"))?
        .saturating_sub(size);
    if others + size > st.cfg.evidence_max_bytes {
        return Err("the server's evidence storage is full (KESTREL_EVIDENCE_MAX_GB); delete stored evidence first".into());
    }
    let dir = st.cfg.evidence_dir.clone();
    ensure_dirs(&dir).map_err(|e| format!("the evidence directory is not writable: {e}"))?;
    let Some(conn) = st.agents.get(&row.device_id) else {
        return Err("device disconnected".into());
    };
    if !conn.has_capability(CAP_EVIDENCE) {
        return Err("the agent on this PC is too old to upload evidence".into());
    }
    let mut s = LiveSession::open(st, row.device_id, conn);
    let overall = tokio::time::Instant::now() + pull_deadline(size);

    // Writer thread: plaintext chunks → SealWriter → `<id>.kes.partial`.
    let partial = partial_path(&dir, id);
    remove_quiet(&partial);
    let data_key = new_data_key();
    let key = data_key;
    let ctx = seal_context(id);
    let mut prefix = [0u8; 8];
    rand::rngs::OsRng.fill_bytes(&mut prefix);
    let (wtx, mut wrx) = mpsc::channel::<Vec<u8>>(8);
    let wpath = partial.clone();
    let writer = tokio::task::spawn_blocking(move || -> io::Result<seal::Sealed> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&wpath)?;
        let mut w = seal::SealWriter::new(BufWriter::new(f), &key, prefix, &ctx)?;
        while let Some(chunk) = wrx.blocking_recv() {
            w.write_all(&chunk)?;
        }
        let (bw, sealed) = w.finish()?;
        let f = bw.into_inner().map_err(|e| e.into_error())?;
        f.sync_all()?;
        Ok(sealed)
    });

    let transfer: Result<Option<String>, String> = async {
        let mut inflight: VecDeque<(u64, u64)> = VecDeque::new();
        let mut early: HashMap<u64, FileReply> = HashMap::new();
        let mut next_rid: u64 = 0;
        let mut next_offset: u64 = 0;
        let mut received: u64 = 0;
        let mut tail_requested = false;
        let mut eof_sha: Option<Option<String>> = None;
        while eof_sha.is_none() {
            while inflight.len() < PULL_WINDOW && !tail_requested {
                if next_offset >= size {
                    if !inflight.is_empty() {
                        break;
                    }
                    tail_requested = true;
                }
                let len = if next_offset >= size {
                    READ_CHUNK_MAX
                } else {
                    (size - next_offset).min(READ_CHUNK_MAX as u64) as u32
                };
                next_rid += 1;
                s.send(LiveServerMsg::EvidenceRead {
                    request_id: next_rid,
                    bundle_id: id,
                    offset: next_offset,
                    len,
                })
                .map_err(|e| e.describe())?;
                inflight.push_back((next_rid, next_offset));
                next_offset = (next_offset + len as u64).min(size);
            }
            let Some((rid, offset)) = inflight.pop_front() else {
                return Err("the PC did not report the end of the bundle".into());
            };
            let reply = wait_reply(&mut s, rid, next_rid, &mut early, overall).await?;
            match reply {
                FileReply::Error { code, message } => {
                    let m = redact_secrets(&clean_text(&message, 300));
                    if !m.is_empty() {
                        *agent_error = Some(m);
                    }
                    return Err(format!("the PC refused the upload ({})", code.as_str()));
                }
                FileReply::Data {
                    offset: got,
                    data_b64,
                    size: total,
                    eof,
                    sha256,
                } => {
                    if total != size {
                        return Err("the bundle on the PC does not have the reported size".into());
                    }
                    if got != offset || offset != received {
                        return Err("chunk offsets out of order".into());
                    }
                    let data = B64
                        .decode(data_b64.as_bytes())
                        .map_err(|_| "the PC sent invalid base64 data".to_string())?;
                    let n = data.len() as u64;
                    if n > READ_CHUNK_MAX as u64 {
                        return Err("the PC sent an oversized chunk".into());
                    }
                    if received + n > size {
                        return Err("the PC sent more data than the reported size".into());
                    }
                    let want = (size - offset).min(READ_CHUNK_MAX as u64);
                    if !eof && offset < size && n != want {
                        return Err("short read from the PC".into());
                    }
                    received += n;
                    if n > 0 && wtx.send(data).await.is_err() {
                        return Err("writing the bundle failed".into());
                    }
                    if eof {
                        eof_sha = Some(sha256);
                    }
                }
                _ => return Err("unexpected reply from the PC".into()),
            }
        }
        if received != size {
            return Err("the bundle changed size while it was uploaded".into());
        }
        Ok(eof_sha.flatten())
    }
    .await;
    drop(wtx);
    drop(s);
    let written = writer
        .await
        .map_err(|_| "the bundle writer failed".to_string())
        .and_then(|r| r.map_err(|e| format!("writing the bundle failed: {e}")));
    let theirs = transfer?;
    let sealed = written?;
    let theirs = theirs.ok_or("the PC did not report the bundle's SHA-256")?;
    if sealed.plaintext_len != size {
        return Err("the bundle changed size while it was uploaded".into());
    }
    if !sealed.sha256.eq_ignore_ascii_case(&theirs) {
        return Err("SHA-256 reported by the PC does not match the bytes received".into());
    }
    if !sealed.sha256.eq_ignore_ascii_case(&expected_sha) {
        return Err(
            "the uploaded bundle does not match the SHA-256 reported when it was captured".into(),
        );
    }
    // Re-open what was written and validate the container (names, sizes,
    // manifest last) before it is accepted.
    let vpath = partial.clone();
    let key = data_key;
    let sha = sealed.sha256.clone();
    let checked = tokio::task::spawn_blocking(move || -> Result<u64, String> {
        let f = std::fs::File::open(&vpath)
            .map_err(|e| format!("reading the stored bundle failed: {e}"))?;
        let mut r = seal::SealReader::new(BufReader::new(f), &key, &ctx)
            .map_err(|e| format!("the stored bundle does not open: {e}"))?;
        container::read_container(&mut r, container::ContainerLimits::default(), |name, _| {
            if ev::valid_entry_name(name) {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid entry name",
                ))
            }
        })
        .map_err(|e| format!("the bundle is not a valid evidence container: {e}"))?;
        match r.sealed() {
            Some(s) if s.sha256.eq_ignore_ascii_case(&sha) => {}
            _ => return Err("the stored bundle does not match what was uploaded".into()),
        }
        drop(r);
        let fin = vpath.with_extension("");
        // `<id>.kes.partial` → `<id>.kes`
        std::fs::rename(&vpath, &fin).map_err(|e| format!("storing the bundle failed: {e}"))?;
        Ok(std::fs::metadata(&fin).map(|m| m.len()).unwrap_or(0))
    })
    .await
    .map_err(|_| "validating the bundle failed".to_string())??;
    Ok((checked, sealed.sha256.to_ascii_lowercase(), data_key))
}

/// Wait for the `EvidenceData` reply to `rid` (replies to other in-flight
/// requests are kept).
async fn wait_reply(
    s: &mut LiveSession,
    rid: u64,
    max_rid: u64,
    early: &mut HashMap<u64, FileReply>,
    overall: tokio::time::Instant,
) -> Result<FileReply, String> {
    if let Some(r) = early.remove(&rid) {
        return Ok(r);
    }
    // M6: one deadline per chunk that other live messages never extend,
    // capped by the pull's overall deadline.
    let deadline = (tokio::time::Instant::now() + CHUNK_TIMEOUT).min(overall);
    let too_slow = || -> String {
        if deadline >= overall {
            "the upload took too long".into()
        } else {
            "the agent did not answer in time".into()
        }
    };
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Err(too_slow());
        }
        match s.recv_timeout(left).await {
            Err(crate::remote::RemoteFail::Timeout) => return Err(too_slow()),
            Err(e) => return Err(e.describe()),
            Ok(LiveAgentMsg::EvidenceData { request_id, reply }) => {
                if request_id == rid {
                    return Ok(reply);
                }
                if request_id > 0 && request_id <= max_rid && early.len() < PULL_WINDOW * 2 {
                    early.insert(request_id, reply);
                } else {
                    return Err("the PC sent an unrequested reply".into());
                }
            }
            Ok(_) => continue,
        }
    }
}

async fn finish_pull(
    st: &AppState,
    id: Uuid,
    row: &PullRow,
    stored_size: u64,
    sha: &str,
    data_key: &[u8; 32],
) -> anyhow::Result<()> {
    let now = now_ms();
    let days = match crate::settings::load(&st.db).await {
        Ok(s) => s.retention_days.evidence,
        Err(_) => ev::DEFAULT_RETENTION_DAYS,
    }
    .clamp(1, ev::MAX_RETENTION_DAYS) as i64;
    let n = sqlx::query(
        "UPDATE evidence_bundles SET status = 'stored', collected_at = $2, stored_size = $3, expires_at = $4, last_error = NULL, \
         auto_retry = false, data_key_enc = $5, updated_at = $2 WHERE id = $1 AND status = 'collecting'",
    )
    .bind(id)
    .bind(now)
    .bind(stored_size as i64)
    .bind(now + days * DAY_MS)
    .bind(wrap_key(st, data_key))
    .execute(&st.db)
    .await?
    .rows_affected();
    if n != 1 {
        // Deleted (or expired) by an administrator while it was uploading.
        remove_quiet(&blob_path(&st.cfg.evidence_dir, id));
        tracing::info!(bundle_id = %id, "evidence upload finished after the bundle was deleted; discarded");
        return Ok(());
    }
    let actor = user_actor(st, row.collect_requested_by).await;
    audit::log(
        &st.db,
        &actor,
        "evidence.collected",
        id.to_string(),
        json!({"bundle_id": id, "device_id": row.device_id, "hostname": row.hostname, "bytes": row.bundle_size, "sha256": sha}),
    )
    .await;
    tracing::info!(bundle_id = %id, device_id = %row.device_id, bytes = row.bundle_size, "evidence stored");
    st.publish("evidence", id, "updated");
    // The PC's copy is no longer needed.
    let incident = incident_of(st, row.device_id, row.alert_id)
        .await
        .unwrap_or(None);
    if let Err(e) = ingest::enqueue_command(
        st,
        row.device_id,
        incident,
        &ResponseAction::DeleteEvidence { bundle_id: id },
        None,
        "Automatic: the evidence is stored on the server; deleting the PC's copy",
    )
    .await
    {
        tracing::warn!(bundle_id = %id, error = %e, "queueing the deletion of the PC's evidence copy failed");
    }
    Ok(())
}

/// An upload (or its preparation) failed: back to `ready_on_device` with the
/// reason; the first failure of a bundle is retried once automatically on
/// the PC's next connect.
async fn fail_collect(
    st: &AppState,
    id: Uuid,
    device_id: Uuid,
    why: &str,
    agent_error: Option<&str>,
) -> anyhow::Result<()> {
    let why = clean_text(why, ERROR_MAX_CHARS);
    let agent_error = agent_error.map(|a| redact_secrets(&clean_text(a, 300)));
    let shown = match &agent_error {
        Some(a) => clean_text(&format!("{why} (the PC reported: {a})"), ERROR_MAX_CHARS),
        None => why.clone(),
    };
    let row: Option<(Option<Uuid>, String)> = sqlx::query_as(
        "UPDATE evidence_bundles e SET status = 'ready_on_device', last_error = $3, attempts = attempts + 1, \
         auto_retry = (attempts = 0), updated_at = $4 FROM devices d \
         WHERE e.id = $1 AND e.device_id = $2 AND e.status = 'collecting' AND d.id = e.device_id \
         RETURNING e.collect_requested_by, d.hostname",
    )
    .bind(id)
    .bind(device_id)
    .bind(&shown)
    .bind(now_ms())
    .fetch_optional(&st.db)
    .await?;
    let Some((by, hostname)) = row else {
        return Ok(());
    };
    // L4: the server records the failure (actor system); the admin who asked
    // and the agent's own text are labelled as such.
    let requester = user_actor(st, by).await;
    audit::log(
        &st.db,
        &Actor::system(),
        "evidence.collect_failed",
        id.to_string(),
        json!({"bundle_id": id, "device_id": device_id, "hostname": hostname, "error": why,
               "agent_error": agent_error, "requested_by": by, "requested_by_email": requester.email}),
    )
    .await;
    st.publish("evidence", id, "updated");
    Ok(())
}

/// Queue `CollectEvidence` for a bundle that was just moved to `collecting`.
pub async fn queue_collect(
    st: &AppState,
    id: Uuid,
    device_id: Uuid,
    alert_id: Uuid,
    requested_by: Option<Uuid>,
    comment: &str,
) -> anyhow::Result<Uuid> {
    let incident = incident_of(st, device_id, alert_id).await?;
    let aid = ingest::enqueue_command(
        st,
        device_id,
        incident,
        &ResponseAction::CollectEvidence { bundle_id: id },
        requested_by,
        comment,
    )
    .await?;
    // The result may already have arrived (and set it): keep that one.
    sqlx::query(
        "UPDATE evidence_bundles SET collect_action_id = COALESCE(collect_action_id, $2) WHERE id = $1",
    )
    .bind(id)
    .bind(aid)
    .execute(&st.db)
    .await?;
    Ok(aid)
}

/// A device (re)connected: resume uploads whose `CollectEvidence` already
/// succeeded (interrupted by a disconnect or a server restart) and run the
/// one automatic retry of a failed upload.
pub async fn on_connect(st: &AppState, device_id: Uuid) -> anyhow::Result<()> {
    let Some(conn) = st.agents.get(&device_id) else {
        return Ok(());
    };
    if !conn.has_capability(CAP_EVIDENCE) {
        return Ok(());
    }
    let resume: Vec<(Uuid,)> = sqlx::query_as(
        "SELECT e.id FROM evidence_bundles e JOIN response_actions ra ON ra.id = e.collect_action_id \
         WHERE e.device_id = $1 AND e.status = 'collecting' AND ra.status = 'succeeded'",
    )
    .bind(device_id)
    .fetch_all(&st.db)
    .await?;
    for (id,) in resume {
        spawn_pull(st, id);
    }
    let retry: Vec<(Uuid, Uuid, Option<Uuid>)> = sqlx::query_as(
        "UPDATE evidence_bundles e SET status = 'collecting', auto_retry = false, collect_action_id = NULL, updated_at = $2 \
         FROM devices d WHERE e.device_id = $1 AND d.id = e.device_id AND d.decommissioned_at IS NULL \
         AND e.status = 'ready_on_device' AND e.auto_retry RETURNING e.id, e.alert_id, e.collect_requested_by",
    )
    .bind(device_id)
    .bind(now_ms())
    .fetch_all(&st.db)
    .await?;
    for (id, alert_id, by) in retry {
        tracing::info!(bundle_id = %id, %device_id, "retrying a failed evidence upload after the PC reconnected");
        if let Err(e) = queue_collect(
            st,
            id,
            device_id,
            alert_id,
            by,
            "Automatic retry of a failed evidence upload after the PC reconnected",
        )
        .await
        {
            tracing::warn!(bundle_id = %id, error = %e, "queueing the evidence retry failed");
            let _ = fail_collect(
                st,
                id,
                device_id,
                "the automatic retry could not be queued",
                None,
            )
            .await;
        }
        st.publish("evidence", id, "updated");
    }
    Ok(())
}

// ------------------------------------------------------------------ housekeeping

/// Every 30 s: expired download tickets / orphaned archives, collect
/// requests that will never be answered.
pub async fn fast_job(st: &AppState) -> anyhow::Result<()> {
    let now = now_ms();
    let expired: Vec<String> = st
        .evidence
        .tickets
        .iter()
        .filter(|t| t.expires_at <= now)
        .map(|t| t.key().clone())
        .collect();
    for k in expired {
        if let Some((_, t)) = st.evidence.tickets.remove(&k) {
            remove_quiet(&t.path);
        }
    }
    sweep_downloads(st);
    // CollectEvidence that expired / was cancelled before the PC answered,
    // or a request that never got its command (crash in between).
    let stuck: Vec<(Uuid, Uuid, Option<String>)> = sqlx::query_as(
        "SELECT e.id, e.device_id, ra.status FROM evidence_bundles e LEFT JOIN response_actions ra ON ra.id = e.collect_action_id \
         WHERE e.status = 'collecting' AND ((ra.id IS NOT NULL AND ra.status IN ('expired','cancelled','failed')) \
         OR (e.collect_action_id IS NULL AND e.collect_requested_at < $1))",
    )
    .bind(now - 10 * 60_000)
    .fetch_all(&st.db)
    .await?;
    for (id, device_id, status) in stuck {
        if st.evidence.pulling(&id) {
            continue;
        }
        let why = match status.as_deref() {
            Some("expired") => "the PC did not connect before the collect request expired",
            Some("cancelled") => "the collect request was cancelled",
            Some("failed") => "the PC could not prepare the upload",
            _ => "the collect request was not queued",
        };
        fail_collect(st, id, device_id, why, None).await?;
    }
    Ok(())
}

/// Delete download archives nobody holds a ticket for (older than 2 min).
fn sweep_downloads(st: &AppState) {
    let dir = downloads_dir(&st.cfg.evidence_dir);
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return;
    };
    let held: std::collections::HashSet<PathBuf> =
        st.evidence.tickets.iter().map(|t| t.path.clone()).collect();
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_file() || held.contains(&p) || st.evidence.busy_files.contains_key(&p) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|m| m.elapsed().ok())
            .is_none_or(|age| age > Duration::from_secs(120));
        if old {
            remove_quiet(&p);
        }
    }
}

/// Hourly retention. Returns stored bundles expired.
pub async fn retention(st: &AppState, s: &Settings) -> anyhow::Result<u64> {
    let now = now_ms();
    let dir = st.cfg.evidence_dir.clone();
    // 1. Stored bundles past their retention (counted from collection with
    //    the *current* setting): blob and data key deleted, metadata kept.
    apply_retention_days(st, s.retention_days.evidence).await?;
    let expired: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "UPDATE evidence_bundles e SET status = 'expired', data_key_enc = NULL, updated_at = $1 FROM devices d \
         WHERE d.id = e.device_id AND e.status = 'stored' AND e.expires_at < $1 RETURNING e.id, e.device_id, d.hostname",
    )
    .bind(now)
    .fetch_all(&st.db)
    .await?;
    for (id, device_id, hostname) in &expired {
        purge_tickets(st, *id);
        remove_quiet(&blob_path(&dir, *id));
        audit::log(
            &st.db,
            &Actor::system(),
            "evidence.expired",
            id.to_string(),
            json!({"bundle_id": id, "device_id": device_id, "hostname": hostname, "reason": "retention"}),
        )
        .await;
        st.publish("evidence", id, "updated");
    }
    // 2. Never collected: the PC deleted it by now (metadata only, no audit).
    let local: Vec<(Uuid,)> = sqlx::query_as(
        "UPDATE evidence_bundles SET status = 'expired', updated_at = $1 \
         WHERE status IN ('ready_on_device','capturing') \
         AND COALESCE(local_expires_at, created_at + $2) + $3 < $1 RETURNING id",
    )
    .bind(now)
    .bind(ev::MAX_RETENTION_DAYS as i64 * DAY_MS)
    .bind(LOCAL_EXPIRY_GRACE_MS)
    .fetch_all(&st.db)
    .await?;
    for (id,) in &local {
        st.publish("evidence", id, "updated");
    }
    // 3. Metadata lives as long as its alerts: rows older than the alert
    //    retention, or whose alert is gone (kept a day for late alerts).
    //    A stored bundle loses its blob first (audited).
    let cutoff = now - s.retention_days.alerts as i64 * DAY_MS;
    let gone: Vec<(Uuid, Uuid, String, String)> = sqlx::query_as(
        "SELECT e.id, e.device_id, d.hostname, e.status FROM evidence_bundles e JOIN devices d ON d.id = e.device_id \
         WHERE e.status <> 'collecting' AND (e.created_at < $1 OR (e.created_at < $2 AND NOT EXISTS (SELECT 1 FROM alerts a WHERE a.id = e.alert_id)))",
    )
    .bind(cutoff)
    .bind(now - DAY_MS)
    .fetch_all(&st.db)
    .await?;
    for (id, device_id, hostname, status) in &gone {
        if status == "stored" {
            purge_tickets(st, *id);
            remove_quiet(&blob_path(&dir, *id));
            audit::log(
                &st.db,
                &Actor::system(),
                "evidence.expired",
                id.to_string(),
                json!({"bundle_id": id, "device_id": device_id, "hostname": hostname, "reason": "alert_retention"}),
            )
            .await;
        }
        sqlx::query("DELETE FROM evidence_bundles WHERE id = $1 AND status <> 'collecting'")
            .bind(id)
            .execute(&st.db)
            .await?;
        st.publish("evidence", id, "updated");
    }
    // 4. Orphaned files (deleted rows, crashes, a device purged).
    sweep_blobs(st).await?;
    Ok(expired.len() as u64)
}

/// Delete `*.kes` files without a `stored` row and `*.kes.partial` files
/// without a running pull.
pub async fn sweep_blobs(st: &AppState) -> anyhow::Result<u64> {
    let dir = st.cfg.evidence_dir.clone();
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(0);
    };
    let stored: Vec<(Uuid,)> =
        sqlx::query_as("SELECT id FROM evidence_bundles WHERE status = 'stored'")
            .fetch_all(&st.db)
            .await?;
    let stored: std::collections::HashSet<Uuid> = stored.into_iter().map(|r| r.0).collect();
    let mut removed = 0;
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().to_string();
        let (stem, partial) = if let Some(s) = name.strip_suffix(".kes.partial") {
            (s.to_string(), true)
        } else if let Some(s) = name.strip_suffix(".kes") {
            (s.to_string(), false)
        } else {
            continue;
        };
        let Ok(id) = Uuid::parse_str(&stem) else {
            continue;
        };
        let keep = if partial {
            st.evidence.pulling(&id)
        } else {
            stored.contains(&id) || st.evidence.pulling(&id)
        };
        if !keep {
            remove_quiet(&p);
            removed += 1;
        }
    }
    Ok(removed)
}

// ------------------------------------------------------------------ download archive

/// Unambiguous password alphabet (no 0/O, 1/l/I).
const PASSWORD_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
pub const PASSWORD_LEN: usize = 24;

/// Random download password (OS RNG).
pub fn new_password() -> String {
    use rand::Rng;
    let mut rng = rand::rngs::OsRng;
    (0..PASSWORD_LEN)
        .map(|_| PASSWORD_ALPHABET[rng.gen_range(0..PASSWORD_ALPHABET.len())] as char)
        .collect()
}

/// `evidence-<hostname>-<id8>` with a file-name-safe hostname.
pub fn archive_stem(hostname: &str, id: Uuid) -> String {
    let h: String = hostname
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(63)
        .collect();
    let h = if h.is_empty() { "pc".to_string() } else { h };
    let id8: String = id.simple().to_string().chars().take(8).collect();
    format!("evidence-{h}-{id8}")
}

pub const README: &str = "Kestrel EDR - evidence bundle
=============================

This archive holds the evidence Kestrel kept on one PC after a suspected data
theft alert (ST-02 / ST-04) and that an administrator collected:

  staged/     copies of files the suspicious process tree created or wrote
              (archives, password dumps, screenshots) as they were at the end
              of the capture window, named NNNN-<original name>.bin
  secrets/    copies of the credential stores (browser / wallet / app files)
              the process tree read, named NNNN.bin (manifest.json says
              which store each number is)
  capture.pcapng
              packet capture of the process tree's connections (60 seconds
              after the alert)
  manifest.json
              what was captured, from which process, with SHA-256 hashes and
              the reason for anything that was not copied

These files can contain the employee's real passwords, cookies and private
data. Handle them under your incident-response / evidence-handling policy,
store them encrypted, and delete them when the investigation ends. Every
download is recorded in Kestrel's audit log.

DANGER: the files in staged/ were produced by the suspicious program. They
may be malware or booby-trapped documents (shortcuts, HTML applications,
scripts, macro documents). Every staged file ends in .bin so a double-click
does not open it; do not rename or open them on a workstation. Examine them
only in an isolated analysis machine or sandbox.

The file names in this archive are not encrypted (only the contents are):
anyone holding the zip can read the list of names without the password.
Credential-store copies are therefore numbered only; manifest.json (whose
content is encrypted) maps each number to its store and original path.

Limitations
-----------
* Encrypted traffic (TLS / HTTPS, VPN) stays encrypted in the packet capture:
  you see where data went and how much, not its content.
* The capture filter is the remote IP address and port the process tree
  connected to. Other programs' traffic to the same IP:port (for example a
  shared CDN address) is included too. Loopback traffic is not captured.
* Files that another program held open without read sharing (for example a
  browser's Cookies database while the browser was running) were not copied;
  the manifest lists them as \"locked\".
* Files deleted before the end of the capture window are listed as \"missing\".

Opening the archive
-------------------
The archive is encrypted with AES-256 (WinZip AE-2). Use 7-Zip
(https://www.7-zip.org), WinRAR, WinZip, Keka (macOS) or `7z x <file>` and
enter the password shown once in the Kestrel console. Windows Explorer's
built-in zip support cannot open AES-encrypted archives.
";

/// Name of a (validated) bundle entry inside the download archive (review
/// of the 1.1.7 integration, I1). Zip entry names are not encrypted (AE-2
/// encrypts contents only), so:
/// * `secrets/NNNN-<store file>` becomes `secrets/NNNN.bin`: the archive's
///   file list does not say which credential stores were taken (the
///   encrypted `manifest.json` maps `NNNN` to the store);
/// * `staged/NNNN-<name>` becomes `staged/NNNN-<name>.bin`: files the
///   suspicious program produced never open or run on a double-click
///   (`.lnk`, `.hta`, `.js` keep their name in front of `.bin`).
///
/// `manifest.json`, `capture.pcapng` and anything else keep their name.
pub fn archive_entry_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix("secrets/") {
        let idx: String = rest.chars().take(4).collect();
        return format!("secrets/{idx}.bin");
    }
    if name.starts_with("staged/") {
        return format!("{name}.bin");
    }
    name.to_string()
}

/// Build the AES-256 zip of a stored bundle (blocking): decrypt the sealed
/// file chunk by chunk straight into encrypted zip entries (plaintext never
/// touches the disk). Verifies the plaintext SHA-256. Returns the archive size.
pub fn build_archive(
    sealed: &Path,
    key: &[u8; 32],
    id: Uuid,
    expected_sha: Option<&str>,
    out: &Path,
    top: &str,
    password: &str,
) -> io::Result<u64> {
    use zip::{write::SimpleFileOptions, AesMode, CompressionMethod, ZipWriter};
    let res = (|| -> io::Result<u64> {
        let f = std::fs::File::open(sealed)?;
        let mut r = seal::SealReader::new(BufReader::new(f), key, &seal_context(id))?;
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).read(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(out)?;
        let mut zw = ZipWriter::new(BufWriter::new(file));
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Stored)
            .with_aes_encryption(AesMode::Aes256, password);
        let zerr = |e: zip::result::ZipError| io::Error::other(e.to_string());
        zw.add_directory(format!("{top}/"), SimpleFileOptions::default())
            .map_err(zerr)?;
        zw.start_file(format!("{top}/README.txt"), options)
            .map_err(zerr)?;
        zw.write_all(README.as_bytes())?;
        container::read_container(
            &mut r,
            container::ContainerLimits::default(),
            |name, data| {
                if !ev::valid_entry_name(name) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid entry name",
                    ));
                }
                zw.start_file(format!("{top}/{}", archive_entry_name(name)), options)
                    .map_err(zerr)?;
                io::copy(data, &mut zw)?;
                Ok(())
            },
        )?;
        if let Some(want) = expected_sha {
            match r.sealed() {
                Some(s) if s.sha256.eq_ignore_ascii_case(want) => {}
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "the stored bundle does not match its recorded SHA-256",
                    ))
                }
            }
        }
        let bw = zw.finish().map_err(zerr)?;
        let file = bw.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        Ok(file.metadata()?.len())
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(out);
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn passwords_are_unambiguous() {
        let a = new_password();
        let b = new_password();
        assert_eq!(a.len(), PASSWORD_LEN);
        assert_ne!(a, b);
        assert!(a.bytes().all(|c| PASSWORD_ALPHABET.contains(&c)));
        for bad in ['0', 'O', '1', 'l', 'I'] {
            assert!(!PASSWORD_ALPHABET.contains(&(bad as u8)));
        }
    }

    #[test]
    fn pull_deadline_grows_with_size() {
        assert_eq!(pull_deadline(0), Duration::from_secs(300));
        assert_eq!(pull_deadline(64 * 1024 * 600), Duration::from_secs(900));
        assert!(pull_deadline(MAX_BUNDLE_BYTES) < Duration::from_secs(3 * 3600));
    }

    #[test]
    fn archive_names_are_safe() {
        let id = Uuid::parse_str("0123abcd-0000-0000-0000-000000000000").unwrap();
        assert_eq!(archive_stem("PC-01", id), "evidence-PC-01-0123abcd");
        assert_eq!(archive_stem("../\u{202e}x y", id), "evidence-xy-0123abcd");
        assert_eq!(archive_stem("", id), "evidence-pc-0123abcd");
    }

    #[test]
    fn alert_ids_merge() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(merge_alert_ids(&[b], a, &[b, a, Uuid::nil()]), vec![a, b]);
        let many: Vec<Uuid> = (0..100).map(|_| Uuid::new_v4()).collect();
        assert_eq!(merge_alert_ids(&[], a, &many).len(), MAX_ALERT_IDS);
    }

    #[test]
    fn manifest_scrub() {
        let id = Uuid::new_v4();
        let mut m: EvidenceManifest = serde_json::from_value(json!({
            "bundle_id": id, "alert_id": id, "rule_id": "ST-02\u{202e}", "started_at": 1, "window_start": 0,
            "window_end": 2, "completed_at": 3, "parts": {},
            "staged": [{"path": "C:\\Users\\bob\\Secret\\a.zip", "written_at": 1, "process_guid": "g",
                        "copy": {"status": "copied", "entry": "staged/../x", "sha256": "zz"}}],
            "notes": ["token=kte_abcdefgh1234 at C:\\Users\\bob\\Secret\\x", ""],
            "pcap": {"status": "captured", "filters": [{"ip": "203.0.113.7"}, {"ip": "evil.example"}]}
        }))
        .unwrap();
        let prefixes = vec!["c:\\users\\bob\\secret".to_string()];
        let sc = Scrub {
            users: None,
            prefixes: &prefixes,
            capture_cmdline: true,
        };
        scrub_manifest(&mut m, &sc);
        assert_eq!(m.rule_id, "ST-02");
        assert_eq!(m.staged[0].path, crate::scrub::REDACTED);
        assert_eq!(m.staged[0].copy.entry, None);
        assert_eq!(m.staged[0].copy.sha256, None);
        assert_eq!(m.notes.len(), 1);
        assert!(!m.notes[0].contains("abcdefgh1234"), "{}", m.notes[0]);
        assert!(!m.notes[0].contains("Secret"), "{}", m.notes[0]);
        assert_eq!(m.pcap.unwrap().filters.len(), 1);
    }

    #[test]
    fn archive_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let id = Uuid::new_v4();
        let key = [5u8; 32];
        let mut w = container::ContainerWriter::new(Vec::new()).unwrap();
        w.entry("staged/0001-a.txt", b"hello evidence").unwrap();
        w.entry("manifest.json", b"{}").unwrap();
        let plain = w.finish().unwrap();
        let sha = ev::sha256_hex(&plain);
        let sealed = dir.path().join("b.kes");
        seal::seal_stream(
            &key,
            [1; 8],
            &seal_context(id),
            &plain[..],
            std::fs::File::create(&sealed).unwrap(),
        )
        .unwrap();
        let out = dir.path().join("o.zip");
        let n = build_archive(&sealed, &key, id, Some(&sha), &out, "evidence-x-1", "pw").unwrap();
        assert!(n > 0);
        let raw = std::fs::read(&out).unwrap();
        assert!(!raw.windows(14).any(|w| w == b"hello evidence"));
        let mut z = zip::ZipArchive::new(std::fs::File::open(&out).unwrap()).unwrap();
        let mut s = String::new();
        z.by_name_decrypt("evidence-x-1/staged/0001-a.txt.bin", b"pw")
            .unwrap()
            .read_to_string(&mut s)
            .unwrap();
        assert_eq!(s, "hello evidence");
        assert!(z
            .by_name_decrypt("evidence-x-1/staged/0001-a.txt.bin", b"nope")
            .is_err());
        // Wrong recorded hash: no archive.
        let out2 = dir.path().join("o2.zip");
        assert!(build_archive(&sealed, &key, id, Some(&"0".repeat(64)), &out2, "t", "pw").is_err());
        assert!(!out2.exists());
    }

    /// Review of the 1.1.7 integration, I1: unencrypted zip names.
    #[test]
    fn archive_entry_names_i1() {
        assert_eq!(
            archive_entry_name("secrets/0007-Login_Data"),
            "secrets/0007.bin"
        );
        assert_eq!(
            archive_entry_name("staged/0001-invoice.pdf.lnk"),
            "staged/0001-invoice.pdf.lnk.bin"
        );
        assert_eq!(archive_entry_name("manifest.json"), "manifest.json");
        assert_eq!(archive_entry_name("capture.pcapng"), "capture.pcapng");
        assert!(!README.contains('\u{2014}') && !README.contains('\u{2013}'));
        assert!(README.contains("DANGER"));
    }
}
