//! Remote file manager REST endpoints (`/api/devices/:id/files…`).
//!
//! Every request opens its own live session with the agent and carries a
//! `FileContext` (the console's file-manager session `fm_session`, the admin's
//! name and the reason) so the agent can ask the employee for consent once per
//! file-manager session. File contents are streamed through memory only (never
//! logged, stored or sent to telemetry); the audit log records path, size and
//! SHA-256.
//!
//! `POST …/files/end` (console file manager closed) tells the agent that the
//! file-manager session is over, so the employee's mandatory on-screen
//! banner and tray notice end at once instead of after the agent's idle
//! timeout (`FILE_SESSION_IDLE_MS`).

use super::{
    admin_name, audit_op, authorize, check_audited, clean_text, LiveSession, RemoteFail, Target,
};
use crate::{
    api::{parse_uuid, ApiJson, ApiPath, ApiQuery},
    auth::Principal,
    error::{ApiError, ApiResult},
    remote::Feature,
    state::AppState,
};
use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::StreamExt;
use kestrel_common::remote::{
    file_name_of, parent_of, validate_remote_path, FileContext, FileEntry, FileKind, FileOp,
    FileReply, LiveServerMsg, RemoteErrorCode, FILE_CHUNK_MAX, LIST_MAX_ENTRIES,
    TRANSFER_IDLE_TIMEOUT_MS, TRANSFER_MAX,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::VecDeque, time::Duration};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Read requests a download keeps in flight.
const DOWNLOAD_WINDOW: usize = 4;
/// Write chunks an upload keeps in flight (each waits for its `Done`).
const UPLOAD_WINDOW: usize = 2;
/// Longest reason accepted (banner, consent prompt, audit).
const REASON_MAX_CHARS: usize = 200;

#[derive(Deserialize, Default)]
pub struct PathQuery {
    #[serde(default)]
    path: Option<String>,
}

/// Query parameters every `/files…` endpoint accepts.
#[derive(Deserialize, Default)]
pub struct FmQuery {
    /// File-manager session chosen by the console (consent is per session).
    #[serde(default)]
    fm_session: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

/// Validated `fm_session` / `reason`.
struct Fm {
    session: Uuid,
    reason: String,
}

impl FmQuery {
    fn parse(&self) -> ApiResult<Fm> {
        let session = match self.fm_session.as_deref().map(str::trim) {
            None | Some("") => Uuid::new_v4(),
            Some(s) => Uuid::parse_str(s)
                .map_err(|_| ApiError::bad_request("fm_session must be a UUID"))?,
        };
        Ok(Fm {
            session,
            reason: clean_text(self.reason.as_deref().unwrap_or(""), REASON_MAX_CHARS),
        })
    }
}

fn valid_path(p: &str) -> ApiResult<String> {
    validate_remote_path(p).map_err(|e| ApiError::bad_request(format!("invalid path: {e}")))
}

fn required_path(p: Option<&str>) -> ApiResult<String> {
    match p {
        Some(p) if !p.is_empty() => valid_path(p),
        _ => Err(ApiError::bad_request("path is required")),
    }
}

fn is_drive_root(p: &str) -> bool {
    p.len() == 3 && p.ends_with(":\\")
}

fn unexpected(op: &str) -> RemoteFail {
    RemoteFail::Protocol(format!("unexpected agent reply to {op}"))
}

/// Turn a reply into `Ok(reply)` or the agent's error.
fn agent_ok(r: FileReply) -> Result<FileReply, RemoteFail> {
    match r {
        FileReply::Error { code, message } => Err(RemoteFail::Agent { code, message }),
        other => Ok(other),
    }
}

/// Run the preconditions for `op` and open a live session carrying the
/// file-manager context.
#[allow(clippy::too_many_arguments)]
async fn open(
    st: &AppState,
    p: &Principal,
    device_id: Uuid,
    op: &FileOp,
    fm: &Fm,
    action: &str,
    details: &mut Value,
) -> ApiResult<(Target, LiveSession)> {
    details["fm_session"] = fm.session.to_string().into();
    if !fm.reason.is_empty() {
        details["reason"] = fm.reason.clone().into();
    }
    let t = check_audited(
        st,
        p,
        device_id,
        Feature::Files,
        Some(op),
        &fm.reason,
        action,
        details,
    )
    .await?;
    let mut s = LiveSession::open(st, device_id, t.conn.clone());
    s.context = Some(FileContext {
        fm_session: fm.session,
        admin_name: admin_name(p),
        reason: fm.reason.clone(),
    });
    Ok((t, s))
}

/// Audit the outcome of an operation (and the consent result when the agent
/// asked the employee) and map the failure to the REST error.
async fn finish<T>(
    st: &AppState,
    p: &Principal,
    action: &str,
    t: &Target,
    s: &LiveSession,
    details: Value,
    res: Result<T, RemoteFail>,
) -> ApiResult<T> {
    if s.consent_asked {
        let result = match (s.consent_result, &res) {
            (Some(r), _) => r,
            (None, Ok(_)) => "allowed",
            (None, Err(e)) => e.consent_result(),
        };
        audit_op(
            st,
            p,
            "remote.consent",
            t.device_id,
            &t.hostname,
            json!({"kind": "files", "fm_session": details["fm_session"], "result": result}),
            Ok(()),
        )
        .await;
    }
    let audit_res = res.as_ref().map(|_| ()).map_err(|e| e.describe());
    audit_op(st, p, action, t.device_id, &t.hostname, details, audit_res).await;
    res.map_err(|e| e.to_api())
}

/// H3: run the agent exchange and its audit row in a task of its own. A
/// client that aborts the HTTP request drops the handler future, but never
/// this task, so an operation that reached the agent is always audited.
async fn spawn_audited<T: Send + 'static>(
    fut: impl std::future::Future<Output = ApiResult<T>> + Send + 'static,
) -> ApiResult<T> {
    match tokio::spawn(fut).await {
        Ok(r) => r,
        Err(_) => Err(ApiError::internal("remote operation task failed")),
    }
}

/// L1: periodic re-check of the console session, the `remote.files`
/// privilege and the device's effective profile during a transfer.
struct Revalidate {
    last: tokio::time::Instant,
    chunks: u64,
}

impl Revalidate {
    fn new() -> Self {
        Revalidate {
            last: tokio::time::Instant::now(),
            chunks: 0,
        }
    }

    async fn chunk(
        &mut self,
        st: &AppState,
        p: &Principal,
        device_id: Uuid,
        op: &FileOp,
    ) -> Result<(), RemoteFail> {
        self.chunks += 1;
        if !self.chunks.is_multiple_of(super::REVALIDATE_EVERY_CHUNKS)
            && self.last.elapsed() < super::TRANSFER_REVALIDATE_EVERY
        {
            return Ok(());
        }
        self.last = tokio::time::Instant::now();
        match super::still_allowed(st, p, device_id, Feature::Files, Some(op)).await {
            Ok(true) => Ok(()),
            // Fails closed on database errors too.
            _ => Err(RemoteFail::Protocol(
                "the console session or the device's remote-access permission is no longer valid"
                    .into(),
            )),
        }
    }
}

// ------------------------------------------------------------------ list / stat

/// `GET /devices/:id/files?path=` — folder listing (empty path = drives).
pub async fn list(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PathQuery>,
    ApiQuery(fq): ApiQuery<FmQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = match q.path.as_deref().map(str::trim) {
        None | Some("") => String::new(),
        Some(raw) => valid_path(raw)?,
    };
    let op = FileOp::List { path: path.clone() };
    let mut details = json!({ "path": path });
    let (t, mut s) = open(&st, &p, id, &op, &fm, "remote.files.list", &mut details).await?;
    spawn_audited(async move {
        let res = match s.call(op).await.and_then(agent_ok) {
            Ok(FileReply::List {
                mut entries,
                truncated,
                ..
            }) => {
                let truncated = truncated || entries.len() > LIST_MAX_ENTRIES;
                entries.truncate(LIST_MAX_ENTRIES);
                Ok(json!({
                    "path": path,
                    "parent": if path.is_empty() { None } else { parent_of(&path) },
                    "entries": entries,
                    "truncated": truncated,
                }))
            }
            Ok(_) => Err(unexpected("list")),
            Err(e) => Err(e),
        };
        finish(&st, &p, "remote.files.list", &t, &s, details, res).await
    })
    .await
    .map(Json)
}

/// `GET /devices/:id/files/stat?path=` — one entry (audited as
/// `remote.files.stat`).
pub async fn stat(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PathQuery>,
    ApiQuery(fq): ApiQuery<FmQuery>,
) -> ApiResult<Json<FileEntry>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = required_path(q.path.as_deref())?;
    let op = FileOp::Stat { path: path.clone() };
    let mut details = json!({ "path": path });
    let (t, mut s) = open(&st, &p, id, &op, &fm, "remote.files.stat", &mut details).await?;
    spawn_audited(async move {
        let res = match s.call(op).await.and_then(agent_ok) {
            Ok(FileReply::Stat(e)) => Ok(e),
            Ok(_) => Err(unexpected("stat")),
            Err(e) => Err(e),
        };
        finish(&st, &p, "remote.files.stat", &t, &s, details, res).await
    })
    .await
    .map(Json)
}

// ------------------------------------------------------------------ mutations

#[derive(Deserialize)]
pub struct RenameBody {
    from: String,
    to: String,
    #[serde(default)]
    overwrite: bool,
}

/// `POST /devices/:id/files/rename {from, to, overwrite?}`.
pub async fn rename(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(fq): ApiQuery<FmQuery>,
    ApiJson(b): ApiJson<RenameBody>,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let from = valid_path(&b.from)?;
    let to = valid_path(&b.to)?;
    if is_drive_root(&from) || is_drive_root(&to) {
        return Err(ApiError::bad_request("a drive root cannot be renamed"));
    }
    if from == to {
        return Err(ApiError::bad_request("source and target are the same"));
    }
    let op = FileOp::Rename {
        from: from.clone(),
        to: to.clone(),
        overwrite: b.overwrite,
    };
    let mut details = json!({"from": from, "to": to, "overwrite": b.overwrite});
    let (t, mut s) = open(&st, &p, id, &op, &fm, "remote.files.rename", &mut details).await?;
    spawn_audited(async move {
        let res = match s.call(op).await.and_then(agent_ok) {
            Ok(FileReply::Done { .. }) => Ok(json!({"from": from, "to": to})),
            Ok(_) => Err(unexpected("rename")),
            Err(e) => Err(e),
        };
        finish(&st, &p, "remote.files.rename", &t, &s, details, res).await
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
pub struct DeleteBody {
    path: String,
    #[serde(default)]
    recursive: bool,
}

/// `POST /devices/:id/files/delete {path, recursive?}`.
pub async fn delete(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(fq): ApiQuery<FmQuery>,
    ApiJson(b): ApiJson<DeleteBody>,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = valid_path(&b.path)?;
    if is_drive_root(&path) {
        return Err(ApiError::bad_request("a drive root cannot be deleted"));
    }
    let op = FileOp::Delete {
        path: path.clone(),
        recursive: b.recursive,
    };
    let mut details = json!({"path": path, "recursive": b.recursive});
    let (t, mut s) = open(&st, &p, id, &op, &fm, "remote.files.delete", &mut details).await?;
    spawn_audited(async move {
        let res = match s.call(op).await.and_then(agent_ok) {
            Ok(FileReply::Done { count }) => Ok(count),
            Ok(_) => Err(unexpected("delete")),
            Err(e) => Err(e),
        };
        if let Ok(n) = &res {
            details["removed"] = (*n).into();
        }
        let removed = finish(&st, &p, "remote.files.delete", &t, &s, details, res).await?;
        Ok(json!({"path": path, "removed": removed}))
    })
    .await
    .map(Json)
}

#[derive(Deserialize)]
pub struct MkdirBody {
    path: String,
}

/// `POST /devices/:id/files/mkdir {path}` (parents created).
pub async fn mkdir(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(fq): ApiQuery<FmQuery>,
    ApiJson(b): ApiJson<MkdirBody>,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = valid_path(&b.path)?;
    if is_drive_root(&path) {
        return Err(ApiError::bad_request("a drive root already exists"));
    }
    let op = FileOp::Mkdir { path: path.clone() };
    let mut details = json!({ "path": path });
    let (t, mut s) = open(&st, &p, id, &op, &fm, "remote.files.mkdir", &mut details).await?;
    spawn_audited(async move {
        let res = match s.call(op).await.and_then(agent_ok) {
            Ok(FileReply::Done { .. }) => Ok(json!({ "path": path })),
            Ok(_) => Err(unexpected("mkdir")),
            Err(e) => Err(e),
        };
        finish(&st, &p, "remote.files.mkdir", &t, &s, details, res).await
    })
    .await
    .map(Json)
}

// ----------------------------------------------------------------------- end

/// `POST /devices/:id/files/end?fm_session=…`: the admin closed the file
/// manager. Best effort and idempotent: the agent (if connected) ends that
/// file-manager session of this admin (banner and tray notice off, consent
/// dropped); no reply is awaited. 204 for any known device, also offline
/// (the agent ends sessions on stream loss) or old agents (they end it after
/// the idle timeout). Audited as `remote.files.end`.
pub async fn end(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(fq): ApiQuery<FmQuery>,
) -> ApiResult<StatusCode> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = match fq.fm_session.as_deref().map(str::trim) {
        Some(s) if !s.is_empty() => {
            Uuid::parse_str(s).map_err(|_| ApiError::bad_request("fm_session must be a UUID"))?
        }
        _ => return Err(ApiError::bad_request("fm_session is required")),
    };
    let conn = st.agents.get(&id);
    let Some(dev) = super::load_device(&st, id, conn.as_deref()).await? else {
        return Err(ApiError::not_found("device not found"));
    };
    let delivered = conn.is_some_and(|c| {
        c.tx.try_send(kestrel_common::wire::ServerPayload::Live {
            session_id: Uuid::new_v4(),
            msg: LiveServerMsg::FileSessionEnd {
                fm_session: fm,
                admin_name: admin_name(&p),
            },
        })
        .is_ok()
    });
    audit_op(
        &st,
        &p,
        "remote.files.end",
        id,
        &dev.hostname,
        json!({ "fm_session": fm.to_string(), "delivered": delivered }),
        Ok(()),
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

// ------------------------------------------------------------------ download

/// `Content-Disposition: attachment` with an ASCII fallback and an RFC 5987
/// `filename*` (UTF-8, percent-encoded).
pub fn content_disposition(name: &str) -> String {
    let name = clean_text(name, 255);
    let name = if name.is_empty() {
        "download".to_string()
    } else {
        name
    };
    let ascii: String = name
        .chars()
        .map(|c| {
            if c == ' ' || (c.is_ascii_graphic() && !matches!(c, '"' | '\\' | ';' | '%')) {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut enc = String::new();
    for b in name.as_bytes() {
        let c = *b as char;
        if c.is_ascii_alphanumeric() || "!#$&+-.^_`|~".contains(c) {
            enc.push(c);
        } else {
            enc.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{enc}")
}

struct FirstChunk {
    data: Vec<u8>,
    size: u64,
    eof: bool,
    sha256: Option<String>,
}

fn decode_chunk(data_b64: &str) -> Result<Vec<u8>, RemoteFail> {
    let data = B64
        .decode(data_b64)
        .map_err(|_| RemoteFail::Protocol("agent sent invalid base64 file data".into()))?;
    if data.len() > FILE_CHUNK_MAX as usize {
        return Err(RemoteFail::Protocol("agent sent an oversized chunk".into()));
    }
    Ok(data)
}

fn integrity(m: &str) -> RemoteFail {
    RemoteFail::Agent {
        code: RemoteErrorCode::IntegrityError,
        message: m.into(),
    }
}

fn too_large() -> RemoteFail {
    RemoteFail::Agent {
        code: RemoteErrorCode::TooLarge,
        message: "files larger than 4 GiB cannot be downloaded".into(),
    }
}

/// `GET /devices/:id/files/download?path=` — streamed as the agent's chunks
/// arrive (up to [`DOWNLOAD_WINDOW`] requests in flight).
pub async fn download(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PathQuery>,
    ApiQuery(fq): ApiQuery<FmQuery>,
) -> ApiResult<Response> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = required_path(q.path.as_deref())?;
    let first_op = FileOp::ReadChunk {
        path: path.clone(),
        offset: 0,
        len: FILE_CHUNK_MAX,
    };
    let mut details = json!({"path": path, "bytes": 0, "sha256": null});
    let (t, s) = open(
        &st,
        &p,
        id,
        &first_op,
        &fm,
        "remote.files.download",
        &mut details,
    )
    .await?;
    // H3: the agent exchange (stat, first chunk, the rest) and the audit row
    // live in a task of their own: a client that disconnects before or
    // during the transfer cannot skip the audit.
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<ApiResult<u64>>();
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(DOWNLOAD_WINDOW);
    let name = file_name_of(&path).to_string();
    tokio::spawn(download_task(st, p, t, path, s, details, ready_tx, tx));
    let size = match ready_rx.await {
        Ok(r) => r?,
        Err(_) => return Err(ApiError::internal("download task failed")),
    };
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    let mut resp = (StatusCode::OK, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    if let Ok(v) = HeaderValue::from_str(&content_disposition(&name)) {
        h.insert(header::CONTENT_DISPOSITION, v);
    }
    Ok(resp)
}

/// Stat + first chunk; everything before the first byte uses the normal
/// error format.
async fn download_first(s: &mut LiveSession, path: &str) -> Result<FirstChunk, RemoteFail> {
    match agent_ok(
        s.call(FileOp::Stat {
            path: path.to_string(),
        })
        .await?,
    )? {
        FileReply::Stat(e) => {
            if matches!(e.kind, FileKind::Dir | FileKind::Drive) {
                return Err(RemoteFail::Agent {
                    code: RemoteErrorCode::InvalidOperation,
                    message: "this is a folder; only files can be downloaded".into(),
                });
            }
            if e.size > TRANSFER_MAX {
                return Err(too_large());
            }
        }
        _ => return Err(unexpected("stat")),
    }
    match agent_ok(
        s.call(FileOp::ReadChunk {
            path: path.to_string(),
            offset: 0,
            len: FILE_CHUNK_MAX,
        })
        .await?,
    )? {
        FileReply::Data {
            offset: 0,
            data_b64,
            size,
            eof,
            sha256,
        } => {
            if size > TRANSFER_MAX {
                return Err(too_large());
            }
            let data = decode_chunk(&data_b64)?;
            if data.len() as u64 > size || (!eof && data.is_empty()) {
                return Err(integrity("the file changed while it was read"));
            }
            Ok(FirstChunk {
                data,
                size,
                eof,
                sha256,
            })
        }
        _ => Err(unexpected("read")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn download_task(
    st: AppState,
    p: Principal,
    t: Target,
    path: String,
    mut s: LiveSession,
    details: Value,
    ready: tokio::sync::oneshot::Sender<ApiResult<u64>>,
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let first = match download_first(&mut s, &path).await {
        Ok(f) => f,
        Err(e) => {
            let r = finish::<u64>(&st, &p, "remote.files.download", &t, &s, details, Err(e)).await;
            let _ = ready.send(r);
            return;
        }
    };
    // A client that went away before the headers is still audited below:
    // the first body send fails as "cancelled".
    let _ = ready.send(Ok(first.size));
    pump_download(st, p, t, path, s, first, details, tx).await;
}

/// Feed the response body from agent `Data` replies, verify the SHA-256 and
/// audit the outcome. An error aborts the body (the browser sees a failed
/// download).
#[allow(clippy::too_many_arguments)]
async fn pump_download(
    st: AppState,
    p: Principal,
    t: Target,
    path: String,
    mut s: LiveSession,
    first: FirstChunk,
    mut details: Value,
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
) {
    let size = first.size;
    let mut hasher = Sha256::new();
    let mut sent: u64 = 0;
    let res: Result<String, RemoteFail> = async {
        let cancelled = || RemoteFail::Protocol("download cancelled by the client".into());
        let mut eof_sha: Option<Option<String>> = None;
        hasher.update(&first.data);
        sent += first.data.len() as u64;
        if tx.send(Ok(Bytes::from(first.data))).await.is_err() {
            return Err(cancelled());
        }
        if first.eof {
            eof_sha = Some(first.sha256);
        }
        let mut inflight: VecDeque<(u64, u64)> = VecDeque::new();
        let mut next_offset = sent;
        let mut tail_requested = false;
        let mut revalidate = Revalidate::new();
        let read_op = FileOp::ReadChunk {
            path: path.clone(),
            offset: 0,
            len: FILE_CHUNK_MAX,
        };
        while eof_sha.is_none() {
            // Keep the window full with reads up to the size at open; if the
            // agent has not reported eof by then, one more read at `size`.
            while inflight.len() < DOWNLOAD_WINDOW && !tail_requested {
                if next_offset >= size {
                    if !inflight.is_empty() {
                        break;
                    }
                    tail_requested = true;
                }
                revalidate.chunk(&st, &p, t.device_id, &read_op).await?;
                let rid = s.request(FileOp::ReadChunk {
                    path: path.clone(),
                    offset: next_offset,
                    len: FILE_CHUNK_MAX,
                })?;
                inflight.push_back((rid, next_offset));
                next_offset = (next_offset + FILE_CHUNK_MAX as u64).min(size);
            }
            let Some((rid, offset)) = inflight.pop_front() else {
                return Err(integrity("the agent did not report the end of the file"));
            };
            match agent_ok(s.reply(rid).await?)? {
                FileReply::Data {
                    offset: got,
                    data_b64,
                    eof,
                    sha256,
                    ..
                } => {
                    if got != offset || offset != sent {
                        return Err(integrity("chunk offsets out of order"));
                    }
                    let data = decode_chunk(&data_b64)?;
                    let n = data.len() as u64;
                    if sent + n > size {
                        return Err(integrity("the file grew while it was read"));
                    }
                    if !eof && (n == 0 || (n < FILE_CHUNK_MAX as u64 && sent + n < size)) {
                        return Err(integrity("short read from the agent"));
                    }
                    hasher.update(&data);
                    sent += n;
                    if n > 0 && tx.send(Ok(Bytes::from(data))).await.is_err() {
                        return Err(cancelled());
                    }
                    if eof {
                        eof_sha = Some(sha256);
                    }
                }
                _ => return Err(unexpected("read")),
            }
        }
        if sent != size {
            return Err(integrity("the file changed size while it was read"));
        }
        let ours = hex::encode(hasher.finalize_reset());
        match eof_sha.flatten() {
            Some(theirs) if theirs.eq_ignore_ascii_case(&ours) => Ok(ours),
            Some(_) => Err(integrity(
                "SHA-256 reported by the agent does not match the bytes received",
            )),
            None => Err(integrity("the agent did not report the file's SHA-256")),
        }
    }
    .await;
    details["bytes"] = sent.into();
    details["sha256"] = res.as_ref().ok().cloned().into();
    if let Err(e) = &res {
        // Abort the body: hyper resets the stream / connection.
        let _ = tx.send(Err(std::io::Error::other(e.describe()))).await;
        tracing::info!(device_id = %t.device_id, error = %e.describe(), "remote download failed");
    }
    let _ = finish(&st, &p, "remote.files.download", &t, &s, details, res).await;
}

// ------------------------------------------------------------------ upload

/// `POST /devices/:id/files/upload?path=` — raw body, `Content-Length`
/// required, ≤ 4 GiB. Re-chunked into ≤ 512 KiB `WriteChunk`s. Mounted
/// outside the 8 MiB API body limit; CSRF is still required (POST).
pub async fn upload(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<PathQuery>,
    ApiQuery(fq): ApiQuery<FmQuery>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Files)?;
    let id = parse_uuid(&id)?;
    let fm = fq.parse()?;
    let path = required_path(q.path.as_deref())?;
    if is_drive_root(&path) {
        return Err(ApiError::bad_request(
            "the upload target must be a file path",
        ));
    }
    let size = match headers.get(header::CONTENT_LENGTH) {
        None => {
            return Err(ApiError::length_required(
                "Content-Length is required for uploads",
            ))
        }
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .ok_or_else(|| ApiError::bad_request("invalid Content-Length"))?,
    };
    if size > TRANSFER_MAX {
        return Err(ApiError::payload_too_large("uploads are limited to 4 GiB"));
    }
    let op = FileOp::WriteBegin {
        path: path.clone(),
        size,
    };
    let mut details = json!({"path": path, "bytes": size, "sha256": null});
    let (t, s) = open(&st, &p, id, &op, &fm, "remote.files.upload", &mut details).await?;
    // Run in a task so a client that disconnects mid-upload still gets the
    // agent-side temp file aborted and the attempt audited.
    let task = tokio::spawn(upload_task(st, p, t, s, path, size, details, body));
    match task.await {
        Ok(r) => r.map(Json),
        Err(_) => Err(ApiError::internal("upload task failed")),
    }
}

#[allow(clippy::too_many_arguments)]
async fn upload_task(
    st: AppState,
    p: Principal,
    t: Target,
    mut s: LiveSession,
    path: String,
    size: u64,
    mut details: Value,
    body: Body,
) -> ApiResult<Value> {
    let mut hasher = Sha256::new();
    let mut began = false;
    let mut received: u64 = 0;
    let res: Result<(), RemoteFail> = async {
        // A folder at the target is a conflict (409), not an overwrite.
        match s.call(FileOp::Stat { path: path.clone() }).await? {
            FileReply::Stat(e) if matches!(e.kind, FileKind::Dir | FileKind::Drive) => {
                return Err(RemoteFail::Agent {
                    code: RemoteErrorCode::AlreadyExists,
                    message: "the target is a folder".into(),
                })
            }
            FileReply::Error {
                code: RemoteErrorCode::NotFound,
                ..
            }
            | FileReply::Stat(_) => {}
            other => {
                agent_ok(other)?;
            }
        }
        match agent_ok(
            s.call(FileOp::WriteBegin {
                path: path.clone(),
                size,
            })
            .await?,
        )? {
            FileReply::Done { .. } => began = true,
            _ => return Err(unexpected("write_begin")),
        }
        let mut inflight: VecDeque<u64> = VecDeque::new();
        let mut revalidate = Revalidate::new();
        let write_op = FileOp::WriteChunk {
            offset: 0,
            data_b64: String::new(),
        };
        let mut buf: Vec<u8> = Vec::with_capacity(FILE_CHUNK_MAX as usize);
        let mut offset: u64 = 0;
        let mut stream = body.into_data_stream();
        let idle = Duration::from_millis(TRANSFER_IDLE_TIMEOUT_MS as u64);
        let mut done = false;
        while !done || !buf.is_empty() {
            if !done {
                match tokio::time::timeout(idle, stream.next()).await {
                    Err(_) => return Err(RemoteFail::Protocol("upload body stalled".into())),
                    Ok(None) => done = true,
                    Ok(Some(Err(_))) => {
                        return Err(RemoteFail::Protocol("upload body was interrupted".into()))
                    }
                    Ok(Some(Ok(bytes))) => {
                        received += bytes.len() as u64;
                        if received > size {
                            return Err(RemoteFail::Agent {
                                code: RemoteErrorCode::InvalidOperation,
                                message: "the body is longer than Content-Length".into(),
                            });
                        }
                        hasher.update(&bytes);
                        buf.extend_from_slice(&bytes);
                    }
                }
            }
            // Send every full chunk (and the remainder once the body ended).
            while buf.len() >= FILE_CHUNK_MAX as usize || (done && !buf.is_empty()) {
                let n = buf.len().min(FILE_CHUNK_MAX as usize);
                let chunk: Vec<u8> = buf.drain(..n).collect();
                revalidate.chunk(&st, &p, t.device_id, &write_op).await?;
                if inflight.len() >= UPLOAD_WINDOW {
                    if let Some(rid) = inflight.pop_front() {
                        expect_done(s.reply(rid).await?)?;
                    }
                }
                let rid = s.request(FileOp::WriteChunk {
                    offset,
                    data_b64: B64.encode(&chunk),
                })?;
                offset += n as u64;
                inflight.push_back(rid);
            }
        }
        while let Some(rid) = inflight.pop_front() {
            expect_done(s.reply(rid).await?)?;
        }
        if received != size {
            return Err(RemoteFail::Agent {
                code: RemoteErrorCode::InvalidOperation,
                message: "the body is shorter than Content-Length".into(),
            });
        }
        Ok(())
    }
    .await;
    let ours = hex::encode(hasher.finalize());
    let res = match res {
        Ok(()) => match s
            .call(FileOp::WriteEnd {
                sha256: ours.clone(),
            })
            .await
            .and_then(agent_ok)
        {
            Ok(FileReply::Written {
                size: n, sha256, ..
            }) => {
                if n != size || !sha256.eq_ignore_ascii_case(&ours) {
                    Err(integrity(
                        "the agent wrote different bytes than were uploaded",
                    ))
                } else {
                    began = false;
                    Ok(())
                }
            }
            Ok(_) => Err(unexpected("write_end")),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    if res.is_err() && began {
        // Best effort: the agent deletes the temp file.
        let _ = s.request(FileOp::WriteAbort);
    }
    details["bytes"] = if res.is_ok() { size } else { received }.into();
    details["sha256"] = if res.is_ok() {
        Value::from(ours.clone())
    } else {
        Value::Null
    };
    finish(&st, &p, "remote.files.upload", &t, &s, details, res).await?;
    Ok(json!({"path": path, "size": size, "sha256": ours}))
}

fn expect_done(r: FileReply) -> Result<(), RemoteFail> {
    match agent_ok(r)? {
        FileReply::Done { .. } => Ok(()),
        _ => Err(unexpected("write_chunk")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disposition_is_safe() {
        assert_eq!(
            content_disposition("report.pdf"),
            "attachment; filename=\"report.pdf\"; filename*=UTF-8''report.pdf"
        );
        let cd = content_disposition("na\"me;\r\nX-Evil: 1 é.txt");
        assert!(!cd.contains('\r') && !cd.contains('\n'));
        assert!(
            cd.starts_with("attachment; filename=\"na_me_X-Evil: 1 _.txt\""),
            "{cd}"
        );
        assert!(
            cd.ends_with("filename*=UTF-8''na%22me%3BX-Evil%3A%201%20%C3%A9.txt"),
            "{cd}"
        );
        assert!(HeaderValue::from_str(&cd).is_ok());
        assert!(content_disposition("").contains("download"));
        assert!(is_drive_root("C:\\") && !is_drive_root("C:\\a"));
    }

    #[test]
    fn fm_query() {
        let q = FmQuery {
            fm_session: Some("not-a-uuid".into()),
            reason: None,
        };
        assert!(q.parse().is_err());
        let id = Uuid::new_v4();
        let q = FmQuery {
            fm_session: Some(id.to_string()),
            reason: Some(" fix\u{202e} printer \n".into()),
        };
        let f = q.parse().unwrap();
        assert_eq!(f.session, id);
        assert_eq!(f.reason, "fix printer");
        assert_ne!(FmQuery::default().parse().unwrap().session, id);
    }
}
