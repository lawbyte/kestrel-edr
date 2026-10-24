//! Evidence REST endpoints (`/api/evidence…`, `/api/incidents/:id/evidence`).
//!
//! Reading metadata needs `read`. Collecting, downloading and deleting need
//! `evidence.download` (admin only, through `*`) **and** an interactive
//! console session: API tokens are refused even with `*`. Every collection,
//! download and deletion is audited (`evidence.*`). See `crate::evidence`.

use super::{csv, list_response, page, parse_uuid, ApiPath, ApiQuery, Arg, Filter};
use crate::{
    audit,
    auth::{Principal, Via},
    error::{ApiError, ApiResult},
    evidence::{self as core, BusyFile, Ticket},
    remote::files::content_disposition,
    state::AppState,
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use kestrel_common::{evidence::CAP_EVIDENCE, now_ms, ResponseAction};
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::AsyncReadExt;
use uuid::Uuid;

const PRIVILEGE: &str = "evidence.download";

/// `evidence.download` + interactive console session.
fn authorize(p: &Principal) -> ApiResult<()> {
    p.require(PRIVILEGE)?;
    if !matches!(p.via, Via::Session { .. }) {
        return Err(ApiError::forbidden(
            "evidence needs an interactive console session; API tokens cannot collect, download or delete it",
        ));
    }
    Ok(())
}

/// Longest `reason` accepted (audit).
const REASON_MAX_CHARS: usize = 200;

/// Optional body of collect / download / delete.
#[derive(Deserialize, Default)]
struct ReasonBody {
    #[serde(default)]
    reason: Option<String>,
}

/// `{reason?}` from a raw body (empty body = no reason). Control / bidi
/// characters are stripped; longer than 200 characters → 400.
fn parse_reason(body: &[u8]) -> ApiResult<String> {
    if body.iter().all(u8::is_ascii_whitespace) {
        return Ok(String::new());
    }
    let b: ReasonBody = serde_json::from_slice(body)
        .map_err(|e| ApiError::bad_request(format!("invalid body: {e}")))?;
    let raw = b.reason.unwrap_or_default();
    if raw.chars().count() > REASON_MAX_CHARS {
        return Err(ApiError::bad_request(format!(
            "reason must be at most {REASON_MAX_CHARS} characters"
        )));
    }
    Ok(crate::remote::clean_text(&raw, REASON_MAX_CHARS))
}

/// M7: collecting and downloading need a recent MFA re-check
/// (`POST /me/reauth`, 10 minutes) for admins with MFA. Admins without MFA
/// are allowed, like Remove device (decision F5).
async fn require_step_up(st: &AppState, p: &Principal, what: &str) -> ApiResult<()> {
    if p.user.mfa_enabled && !crate::remote::reauth_recent(st, p).await? {
        return Err(ApiError::forbidden(format!(
            "confirm your MFA code again (POST /api/me/reauth) to {what}"
        ))
        .with_field("reason", "reauth_required"));
    }
    Ok(())
}

fn session_of(p: &Principal) -> String {
    match &p.via {
        Via::Session { token_hash, .. } => token_hash.clone(),
        Via::Token { .. } => String::new(),
    }
}

#[derive(sqlx::FromRow)]
struct BundleRow {
    id: Uuid,
    device_id: Uuid,
    hostname: String,
    incident_id: Option<Uuid>,
    alert_id: Uuid,
    alert_ids: Vec<Uuid>,
    rule_id: String,
    status: String,
    created_at: i64,
    captured_at: Option<i64>,
    manifest: Option<Value>,
    bundle_size: i64,
    bundle_sha256: Option<String>,
    local_expires_at: Option<i64>,
    collect_requested_at: Option<i64>,
    collect_requested_by: Option<String>,
    collected_at: Option<i64>,
    expires_at: Option<i64>,
    deleted_at: Option<i64>,
    deleted_by: Option<String>,
    last_error: Option<String>,
    downloads: i32,
    last_downloaded_at: Option<i64>,
    capabilities: Vec<String>,
    decommissioned_at: Option<i64>,
}

const SELECT: &str = "SELECT e.id, e.device_id, d.hostname, a.incident_id, e.alert_id, e.alert_ids, e.rule_id, e.status, \
     e.created_at, e.captured_at, e.manifest, e.bundle_size, e.bundle_sha256, e.local_expires_at, e.collect_requested_at, \
     COALESCE(NULLIF(cu.name, ''), cu.email) AS collect_requested_by, e.collected_at, e.expires_at, e.deleted_at, \
     COALESCE(NULLIF(du.name, ''), du.email) AS deleted_by, e.last_error, e.downloads, e.last_downloaded_at, \
     d.capabilities, d.decommissioned_at \
     FROM evidence_bundles e JOIN devices d ON d.id = e.device_id \
     LEFT JOIN alerts a ON a.id = e.alert_id AND a.device_id = e.device_id \
     LEFT JOIN users cu ON cu.id = e.collect_requested_by \
     LEFT JOIN users du ON du.id = e.deleted_by";

impl BundleRow {
    fn to_api(&self, st: &AppState) -> Value {
        let conn = st.agents.get(&self.device_id);
        let supports = match &conn {
            Some(c) => c.has_capability(CAP_EVIDENCE),
            None => self.capabilities.iter().any(|c| c == CAP_EVIDENCE),
        };
        json!({
            "id": self.id,
            "device_id": self.device_id,
            "hostname": self.hostname,
            "incident_id": self.incident_id,
            "alert_id": self.alert_id,
            "alert_ids": self.alert_ids,
            "rule_id": self.rule_id,
            "status": self.status,
            "created_at": self.created_at,
            "captured_at": self.captured_at,
            "manifest": self.manifest,
            "bundle_size": self.bundle_size,
            "bundle_sha256": self.bundle_sha256,
            "local_expires_at": self.local_expires_at,
            "collect_requested_at": self.collect_requested_at,
            "collect_requested_by": self.collect_requested_by,
            "collected_at": self.collected_at,
            "expires_at": self.expires_at,
            "deleted_at": self.deleted_at,
            "deleted_by": self.deleted_by,
            "last_error": self.last_error,
            "downloads": self.downloads,
            "last_downloaded_at": self.last_downloaded_at,
            "device_online": conn.is_some() && self.decommissioned_at.is_none(),
            "agent_supports_evidence": supports,
        })
    }
}

async fn load(st: &AppState, id: Uuid) -> ApiResult<BundleRow> {
    sqlx::query_as::<_, BundleRow>(&format!("{SELECT} WHERE e.id = $1"))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(|| ApiError::not_found("evidence bundle not found"))
}

// ------------------------------------------------------------------ read

/// `GET /incidents/:id/evidence` → `{items}` (newest first).
pub async fn for_incident(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    let inc: Option<(Uuid,)> = sqlx::query_as("SELECT device_id FROM incidents WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    let Some((device_id,)) = inc else {
        return Err(ApiError::not_found("incident not found"));
    };
    let rows: Vec<BundleRow> = sqlx::query_as(&format!(
        "{SELECT} WHERE e.device_id = $2 AND e.alert_ids && \
         COALESCE((SELECT array_agg(x.id) FROM alerts x WHERE x.incident_id = $1), '{{}}'::uuid[]) \
         ORDER BY e.created_at DESC, e.id LIMIT 200"
    ))
    .bind(id)
    .bind(device_id)
    .fetch_all(&st.db)
    .await?;
    Ok(Json(
        json!({"items": rows.iter().map(|r| r.to_api(&st)).collect::<Vec<_>>()}),
    ))
}

#[derive(Deserialize, Default)]
pub struct ListQuery {
    device_id: Option<String>,
    status: Option<String>,
    limit: Option<i64>,
    cursor: Option<String>,
}

/// `GET /evidence?device_id=&status=&limit=&cursor=`.
pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiQuery(q): ApiQuery<ListQuery>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let pg = page(q.limit, q.cursor.as_deref())?;
    let mut f = Filter::default();
    if let Some(d) = q.device_id.as_deref().filter(|s| !s.trim().is_empty()) {
        f.push("e.device_id = ?", vec![Arg::Uuid(parse_uuid(d.trim())?)]);
    }
    let statuses = csv(&q.status);
    if let Some(bad) = statuses
        .iter()
        .find(|s| !core::STATUSES.contains(&s.as_str()))
    {
        return Err(ApiError::bad_request(format!("unknown status '{bad}'")));
    }
    if !statuses.is_empty() {
        f.push("e.status = ANY(?)", vec![Arg::Strs(statuses)]);
    }
    let total: i64 = f
        .bind_scalar(sqlx::query_scalar(&format!(
            "SELECT count(*) FROM evidence_bundles e WHERE {}",
            f.where_sql()
        )))
        .fetch_one(&st.db)
        .await?;
    let n = f.next_idx();
    let rows: Vec<BundleRow> = f
        .bind(sqlx::query_as(&format!(
            "{SELECT} WHERE {} ORDER BY e.created_at DESC, e.id LIMIT ${} OFFSET ${}",
            f.where_sql(),
            n,
            n + 1
        )))
        .bind(pg.limit)
        .bind(pg.offset)
        .fetch_all(&st.db)
        .await?;
    let items = rows.iter().map(|r| r.to_api(&st)).collect();
    Ok(Json(list_response(items, total, &pg)))
}

/// `GET /evidence/:id`.
pub async fn get_one(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    p.require("read")?;
    let id = parse_uuid(&id)?;
    Ok(Json(load(&st, id).await?.to_api(&st)))
}

// ------------------------------------------------------------------ collect

/// `POST /evidence/:id/collect` — queue the upload (delivered when the PC is
/// online). 409 unless `ready_on_device`, for decommissioned / removed
/// devices, agents without `evidence.v1` (`reason: agent_too_old`) and when
/// the storage cap would be exceeded (`reason: storage_full`).
pub async fn collect(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authorize(&p)?;
    let id = parse_uuid(&id)?;
    let reason = parse_reason(&body)?;
    require_step_up(&st, &p, "collect evidence").await?;
    let b = load(&st, id).await?;
    if b.status != "ready_on_device" {
        return Err(ApiError::conflict(format!(
            "this evidence cannot be collected (status: {})",
            b.status
        ))
        .with_field("reason", "not_ready"));
    }
    if b.decommissioned_at.is_some() {
        return Err(
            ApiError::conflict("the device is decommissioned or removed")
                .with_field("reason", "decommissioned"),
        );
    }
    let supports = match st.agents.get(&b.device_id) {
        Some(c) => c.has_capability(CAP_EVIDENCE),
        None => b.capabilities.iter().any(|c| c == CAP_EVIDENCE),
    };
    if !supports {
        return Err(ApiError::conflict(
            "the agent on this PC is too old to upload evidence; update it first",
        )
        .with_field("reason", "agent_too_old"));
    }
    let used = core::storage_in_use(&st).await?;
    if used + b.bundle_size.max(0) as u64 > st.cfg.evidence_max_bytes {
        return Err(ApiError::conflict(format!(
            "the server's evidence storage is full ({} of {} MB used, KESTREL_EVIDENCE_MAX_GB); delete stored evidence first",
            used / (1024 * 1024),
            st.cfg.evidence_max_bytes / (1024 * 1024)
        ))
        .with_field("reason", "storage_full"));
    }
    if let Err(e) = core::ensure_dirs(&st.cfg.evidence_dir) {
        tracing::error!(error = %e, "evidence directory unavailable");
        return Err(ApiError::unavailable(
            "the server's evidence directory (KESTREL_EVIDENCE_DIR) is not writable",
        ));
    }
    let now = now_ms();
    let moved = sqlx::query(
        "UPDATE evidence_bundles SET status = 'collecting', collect_requested_at = $2, collect_requested_by = $3, \
         collect_action_id = NULL, auto_retry = false, updated_at = $2 WHERE id = $1 AND status = 'ready_on_device'",
    )
    .bind(id)
    .bind(now)
    .bind(p.user.id)
    .execute(&st.db)
    .await?
    .rows_affected();
    if moved != 1 {
        return Err(
            ApiError::conflict("this evidence is already being collected")
                .with_field("reason", "not_ready"),
        );
    }
    let aid = match core::queue_collect(
        &st,
        id,
        b.device_id,
        b.alert_id,
        Some(p.user.id),
        "Collect evidence (requested in the console)",
    )
    .await
    {
        Ok(a) => a,
        Err(e) => {
            let _ = sqlx::query(
                "UPDATE evidence_bundles SET status = 'ready_on_device', updated_at = $2 WHERE id = $1 AND status = 'collecting'",
            )
            .bind(id)
            .bind(now_ms())
            .execute(&st.db)
            .await;
            return Err(e.into());
        }
    };
    audit::log(
        &st.db,
        &p.actor(),
        "evidence.collect_requested",
        id.to_string(),
        json!({"bundle_id": id, "device_id": b.device_id, "hostname": b.hostname, "action_id": aid,
               "bytes": b.bundle_size, "retry": b.last_error.is_some(), "reason": reason, "ip": p.ip}),
    )
    .await;
    st.publish("evidence", id, "updated");
    Ok(Json(load(&st, id).await?.to_api(&st)))
}

// ------------------------------------------------------------------ delete

/// `DELETE /evidence/:id` — delete the stored copy (if any) and ask the PC
/// to delete its copy while it may still hold one. Idempotent.
pub async fn delete_bundle(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authorize(&p)?;
    let id = parse_uuid(&id)?;
    let reason = parse_reason(&body)?;
    // Review of the 1.1.7 integration (L3): deleting is irreversible (the
    // data key goes too), so it needs the same fresh MFA as collect and
    // download.
    require_step_up(&st, &p, "delete evidence").await?;
    let b = load(&st, id).await?;
    if matches!(b.status.as_str(), "deleted" | "expired") {
        return Ok(Json(b.to_api(&st)));
    }
    let now = now_ms();
    let prev: Option<(String,)> = sqlx::query_as(
        "UPDATE evidence_bundles e SET status = 'deleted', deleted_at = $2, deleted_by = $3, auto_retry = false, data_key_enc = NULL, updated_at = $2 \
         FROM evidence_bundles old WHERE e.id = $1 AND old.id = e.id AND e.status NOT IN ('deleted','expired') RETURNING old.status",
    )
    .bind(id)
    .bind(now)
    .bind(p.user.id)
    .fetch_optional(&st.db)
    .await?;
    let Some((prev,)) = prev else {
        return Ok(Json(load(&st, id).await?.to_api(&st)));
    };
    let dir = st.cfg.evidence_dir.clone();
    let _ = std::fs::remove_file(core::blob_path(&dir, id));
    // Unused download tickets of this bundle go too.
    core::purge_tickets(&st, id);
    let on_pc = matches!(
        prev.as_str(),
        "capturing" | "ready_on_device" | "collecting"
    );
    let mut action_id = None;
    if on_pc && b.decommissioned_at.is_none() {
        let incident = core::incident_of(&st, b.device_id, b.alert_id).await?;
        action_id = Some(
            crate::ingest::enqueue_command(
                &st,
                b.device_id,
                incident,
                &ResponseAction::DeleteEvidence { bundle_id: id },
                Some(p.user.id),
                "Delete evidence (requested in the console)",
            )
            .await?,
        );
    }
    audit::log(
        &st.db,
        &p.actor(),
        "evidence.deleted",
        id.to_string(),
        json!({"bundle_id": id, "device_id": b.device_id, "hostname": b.hostname, "previous_status": prev,
               "pc_delete_action_id": action_id, "reason": reason, "ip": p.ip}),
    )
    .await;
    st.publish("evidence", id, "updated");
    Ok(Json(load(&st, id).await?.to_api(&st)))
}

// ------------------------------------------------------------------ download

/// `POST /evidence/:id/download` — build the password-protected archive and
/// return a one-time ticket (`EvidenceDownloadTicket`). The password is
/// returned only here and never stored or logged.
pub async fn create_download(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    body: Bytes,
) -> ApiResult<Json<Value>> {
    authorize(&p)?;
    let id = parse_uuid(&id)?;
    let reason = parse_reason(&body)?;
    require_step_up(&st, &p, "download evidence").await?;
    let b = load(&st, id).await?;
    if b.status != "stored" {
        return Err(ApiError::conflict(format!(
            "this evidence is not stored on the server (status: {})",
            b.status
        ))
        .with_field("reason", "not_ready"));
    }
    let now = now_ms();
    let held = st
        .evidence
        .tickets
        .iter()
        .filter(|t| t.user_id == p.user.id && t.expires_at > now)
        .count();
    if held >= core::MAX_TICKETS_PER_USER {
        return Err(ApiError::rate_limited(
            "too many evidence downloads prepared and not fetched yet; use or let them expire (10 minutes)",
        ));
    }
    let Ok(permit) = st.evidence.build_slots.clone().try_acquire_owned() else {
        return Err(ApiError::unavailable(
            "other evidence archives are being prepared; try again in a moment",
        ));
    };
    let dir = st.cfg.evidence_dir.clone();
    core::ensure_dirs(&dir)
        .map_err(|_| ApiError::unavailable("the server's evidence directory is not writable"))?;
    let blob = core::blob_path(&dir, id);
    if !blob.exists() {
        return Err(ApiError::conflict(
            "the stored evidence file is missing on the server",
        ));
    }
    let download_id = crate::crypto::random_token(18);
    let path = core::downloads_dir(&dir).join(format!("{download_id}.zip"));
    let stem = core::archive_stem(&b.hostname, id);
    let file_name = format!("{stem}.zip");
    let password = core::new_password();
    let (wrapped,): (Option<String>,) =
        sqlx::query_as("SELECT data_key_enc FROM evidence_bundles WHERE id = $1")
            .bind(id)
            .fetch_one(&st.db)
            .await?;
    let key = match wrapped.as_deref().map(|w| core::unwrap_key(&st, w)) {
        Some(Ok(k)) => k,
        Some(Err(e)) => {
            tracing::error!(bundle_id = %id, error = %e, "evidence data key unreadable");
            return Err(ApiError::internal(
                "the stored evidence key could not be read (the master key changed?)",
            ));
        }
        None => {
            return Err(ApiError::conflict("this evidence is no longer stored")
                .with_field("reason", "not_ready"))
        }
    };
    let busy = BusyFile::new(&st, path.clone());
    let (out, pw, sha) = (path.clone(), password.clone(), b.bundle_sha256.clone());
    let built = tokio::task::spawn_blocking(move || {
        let _busy = busy;
        let _permit = permit;
        core::build_archive(&blob, &key, id, sha.as_deref(), &out, &stem, &pw)
    })
    .await
    .map_err(|_| ApiError::internal("building the evidence archive failed"))?;
    let size = match built {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(bundle_id = %id, error = %e, "building the evidence archive failed");
            return Err(ApiError::internal(
                "the stored evidence could not be read (damaged, or the master key changed)",
            ));
        }
    };
    // L1: deleted / expired while the archive was being built → no ticket.
    let still: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM evidence_bundles WHERE id = $1 AND status = 'stored' AND data_key_enc IS NOT NULL",
    )
    .bind(id)
    .fetch_optional(&st.db)
    .await?;
    if still.is_none() {
        let _ = std::fs::remove_file(&path);
        return Err(ApiError::conflict("this evidence is no longer stored")
            .with_field("reason", "not_ready"));
    }
    let expires_at = now_ms() + core::DOWNLOAD_TTL_MS;
    st.evidence.tickets.insert(
        download_id.clone(),
        Ticket {
            path,
            user_id: p.user.id,
            session: session_of(&p),
            bundle_id: id,
            device_id: b.device_id,
            hostname: b.hostname.clone(),
            file_name: file_name.clone(),
            size,
            expires_at,
            reason,
        },
    );
    Ok(Json(json!({
        "download_id": download_id,
        "password": password,
        "file_name": file_name,
        "size": size,
        "expires_at": expires_at,
        "url": format!("/api/evidence/downloads/{download_id}"),
    })))
}

/// `GET /evidence/downloads/:download_id` — stream the archive once, to the
/// user and console session that prepared it, within 10 minutes. The file
/// is deleted afterwards (also when the client aborts) and the download is
/// audited in a task of its own.
pub async fn download_file(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(download_id): ApiPath<String>,
) -> ApiResult<Response> {
    authorize(&p)?;
    let session = session_of(&p);
    let now = now_ms();
    let owned = |t: &Ticket| t.user_id == p.user.id && t.session == session && t.expires_at > now;
    // Single use: only the owner's request consumes the ticket.
    let Some((_, t)) = st.evidence.tickets.remove_if(&download_id, |_, t| owned(t)) else {
        return Err(ApiError::not_found("download not found or expired"));
    };
    let file = match tokio::fs::File::open(&t.path).await {
        Ok(f) => f,
        Err(_) => return Err(ApiError::not_found("download not found or expired")),
    };
    let busy = BusyFile::new(&st, t.path.clone());
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(4);
    let size = t.size;
    let ip = p.ip.clone();
    let actor = p.actor();
    let st2 = st.clone();
    let t2 = t.clone();
    let did = download_id.clone();
    tokio::spawn(async move {
        let _busy = busy;
        // L4: recorded before the first byte leaves the server.
        audit::log(
            &st2.db,
            &actor,
            "evidence.download_started",
            t2.bundle_id.to_string(),
            json!({"bundle_id": t2.bundle_id, "download_id": did, "device_id": t2.device_id, "hostname": t2.hostname,
                   "bytes": t2.size, "reason": t2.reason, "ip": ip}),
        )
        .await;
        let _ = sqlx::query(
            "UPDATE evidence_bundles SET downloads = downloads + 1, last_downloaded_at = $2 WHERE id = $1",
        )
        .bind(t2.bundle_id)
        .bind(now_ms())
        .execute(&st2.db)
        .await;
        let mut file = file;
        let mut sent: u64 = 0;
        let mut buf = vec![0u8; 256 * 1024];
        // Review of the 1.1.7 integration (I2): a download in flight stops
        // when the bundle is deleted or expires (checked about once a
        // second; a database error does not stop it).
        let mut checked = std::time::Instant::now();
        let mut cancelled = false;
        let complete = loop {
            if checked.elapsed() >= std::time::Duration::from_secs(1) {
                checked = std::time::Instant::now();
                let gone: Option<(String,)> =
                    sqlx::query_as("SELECT status FROM evidence_bundles WHERE id = $1")
                        .bind(t2.bundle_id)
                        .fetch_optional(&st2.db)
                        .await
                        .unwrap_or(Some(("stored".into(),)));
                if gone.is_none_or(|(s,)| s == "deleted" || s == "expired") {
                    cancelled = true;
                    let _ = tx
                        .send(Err(std::io::Error::other(
                            "the evidence was deleted during the download",
                        )))
                        .await;
                    break false;
                }
            }
            match file.read(&mut buf).await {
                Ok(0) => break sent == t2.size,
                Ok(n) => {
                    if tx
                        .send(Ok(Bytes::copy_from_slice(&buf[..n])))
                        .await
                        .is_err()
                    {
                        break false;
                    }
                    sent += n as u64;
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                    break false;
                }
            }
        };
        drop(file);
        drop(tx);
        let _ = tokio::fs::remove_file(&t2.path).await;
        audit::log(
            &st2.db,
            &actor,
            "evidence.downloaded",
            t2.bundle_id.to_string(),
            json!({"bundle_id": t2.bundle_id, "download_id": did, "device_id": t2.device_id, "hostname": t2.hostname,
                   "bytes": sent, "complete": complete, "cancelled_by_delete": cancelled, "reason": t2.reason, "ip": ip}),
        )
        .await;
        st2.publish("evidence", t2.bundle_id, "updated");
    });
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/zip"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&t.file_name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}
