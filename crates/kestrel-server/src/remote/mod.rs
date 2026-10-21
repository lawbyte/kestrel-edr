//! Remote access (owner request 2026-10-21): admin remote desktop and remote
//! file manager, relayed to agents over their mTLS gRPC stream as live
//! messages (`ServerPayload::Live` / `AgentPayload::Live`).
//!
//! * [`Hub`] routes `AgentPayload::Live` messages to the waiting session
//!   (bounded channel per session; a session only receives messages from the
//!   device and stream it was opened on). Sessions end when the agent stream
//!   ends ([`Hub::close_conn`]).
//! * Remote-access profiles: the device's **ceiling** (pinned at enrollment
//!   from the token's profile, intersected with what the agent reports) ∩ the
//!   device policy's `remote_access` = the **effective** profile ([`Profiles`]).
//! * [`check`] runs the contract preconditions in order (device → not
//!   decommissioned → ceiling / policy permit the operation → reason → MFA
//!   re-auth → connected → capability).
//! * Live traffic is never stored, acked or logged: frames and file contents
//!   only pass through memory.

pub mod desktop;
pub mod files;

use crate::{
    audit,
    auth::{Principal, Via},
    error::ApiError,
    policy_svc,
    registry::AgentConn,
    state::AppState,
};
use axum::http::StatusCode;
use dashmap::DashMap;
use kestrel_common::{
    now_ms,
    remote::{
        DesktopMode, FileContext, FileOp, FileReply, LiveAgentMsg, LiveServerMsg,
        RemoteAccessProfile, RemoteErrorCode, CAP_LIVE_DESKTOP, CAP_LIVE_FILES,
    },
    wire::ServerPayload,
};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};
use tokio::sync::mpsc;
use uuid::Uuid;

/// How long the server waits for each agent reply.
pub const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
/// Extra wait after the employee's consent timeout (file requests).
pub const CONSENT_MARGIN: Duration = Duration::from_secs(15);
/// Longest consent wait the server honours (`RemoteAccessProfile::validate`
/// caps the setting at 600 s).
pub const CONSENT_MAX_SECS: u32 = 600;
/// An MFA step-up (`POST /me/reauth`) covers remote access for this long.
pub const REAUTH_VALID_MS: i64 = 10 * 60 * 1000;
/// Queue of agent messages per live session (file transfers keep ≤ 4 requests
/// in flight, desktop agents ≤ 3 frames).
const SESSION_QUEUE: usize = 32;
/// M5: most bytes (approximate, payload data) queued for one live session,
/// including replies kept for later requests. Exceeding it closes the session.
pub const SESSION_MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// L1: transfers re-check the console session and the effective profile at
/// least this often, and every [`REVALIDATE_EVERY_CHUNKS`] chunks.
pub const TRANSFER_REVALIDATE_EVERY: Duration = Duration::from_secs(60);
pub const REVALIDATE_EVERY_CHUNKS: u64 = 16;

/// Which remote-access feature a request uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    Desktop,
    Files,
}

impl Feature {
    pub fn privilege(self) -> &'static str {
        match self {
            Feature::Desktop => "remote.desktop",
            Feature::Files => "remote.files",
        }
    }
    pub fn capability(self) -> &'static str {
        match self {
            Feature::Desktop => CAP_LIVE_DESKTOP,
            Feature::Files => CAP_LIVE_FILES,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Feature::Desktop => "remote desktop",
            Feature::Files => "the remote file manager",
        }
    }
}

/// RBAC for remote access: the privilege **and** an interactive console
/// session (API tokens are refused even with `*`).
pub fn authorize(p: &Principal, f: Feature) -> Result<(), ApiError> {
    p.require(f.privilege())?;
    if !matches!(p.via, Via::Session { .. }) {
        return Err(ApiError::forbidden(
            "remote access needs an interactive console session; API tokens cannot use it",
        ));
    }
    Ok(())
}

/// Display name shown to the employee (banner, consent prompt).
pub fn admin_name(p: &Principal) -> String {
    let n = clean_text(&p.user.name, 100);
    if n.is_empty() {
        p.user.email.clone()
    } else {
        n
    }
}

// --------------------------------------------------------------- profiles

/// Stored profile JSON → profile (anything unreadable = no remote access).
pub fn profile_from_json(v: Value) -> RemoteAccessProfile {
    serde_json::from_value(v).unwrap_or_else(|_| RemoteAccessProfile::none())
}

/// The three inputs of a device's effective remote-access profile.
#[derive(Clone, Debug)]
pub struct Profiles {
    /// Server record: the enrollment token's profile.
    pub stored_ceiling: RemoteAccessProfile,
    /// What the agent says it pinned (`None`: never reported / older agent).
    pub agent_ceiling: Option<RemoteAccessProfile>,
    /// The device policy's `remote_access`.
    pub policy: RemoteAccessProfile,
}

impl Profiles {
    /// stored ceiling ∩ agent-reported ceiling (missing report = none()).
    pub fn ceiling(&self) -> RemoteAccessProfile {
        let reported = self
            .agent_ceiling
            .clone()
            .unwrap_or_else(RemoteAccessProfile::none);
        self.stored_ceiling.intersect(&reported)
    }

    pub fn effective(&self) -> RemoteAccessProfile {
        self.ceiling().intersect(&self.policy)
    }
}

/// Does `prof` allow the feature (and, for files, this operation)?
pub fn permits(prof: &RemoteAccessProfile, f: Feature, op: Option<&FileOp>) -> bool {
    match f {
        Feature::Desktop => prof.desktop != DesktopMode::Off,
        Feature::Files => match op {
            Some(op) => prof.file_op_permitted(op).is_ok(),
            None => prof.files != kestrel_common::remote::FileMode::Off,
        },
    }
}

struct DeviceInfo {
    hostname: String,
    decommissioned: bool,
    profiles: Profiles,
}

async fn load_device(
    st: &AppState,
    device_id: Uuid,
    conn: Option<&AgentConn>,
) -> anyhow::Result<Option<DeviceInfo>> {
    let row: Option<(String, Option<i64>, Value, Option<Value>)> = sqlx::query_as(
        "SELECT hostname, decommissioned_at, remote_ceiling, agent_remote_ceiling FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((hostname, decom, stored, reported)) = row else {
        return Ok(None);
    };
    let pid = policy_svc::device_policy_id(&st.db, device_id).await?;
    let policy = policy_svc::load_stored(&st.db, &pid)
        .await?
        .map(|p| p.remote_access)
        .unwrap_or_else(RemoteAccessProfile::none);
    let agent_ceiling = match conn {
        Some(c) => c.remote_ceiling.clone(),
        None => reported.map(profile_from_json),
    };
    Ok(Some(DeviceInfo {
        hostname,
        decommissioned: decom.is_some(),
        profiles: Profiles {
            stored_ceiling: profile_from_json(stored),
            agent_ceiling,
            policy,
        },
    }))
}

/// Effective profile of a device right now (desktop revalidation).
pub async fn effective_now(
    st: &AppState,
    device_id: Uuid,
) -> anyhow::Result<Option<RemoteAccessProfile>> {
    let conn = st.agents.get(&device_id);
    Ok(load_device(st, device_id, conn.as_deref())
        .await?
        .map(|d| d.profiles.effective()))
}

// ------------------------------------------------------------------ hub

struct LiveEntry {
    device_id: Uuid,
    /// Agent stream (`AgentConn.session`) the session was opened on.
    conn_session: Uuid,
    tx: mpsc::Sender<LiveAgentMsg>,
    usage: Arc<QueueUsage>,
}

/// What an agent has queued for one live session (M5).
#[derive(Default)]
struct QueueUsage {
    bytes: std::sync::atomic::AtomicUsize,
    frames: std::sync::atomic::AtomicUsize,
    /// The agent broke the limits; the session was closed.
    violated: AtomicBool,
}

/// Approximate payload size of an agent live message (queue accounting).
pub fn approx_size(m: &LiveAgentMsg) -> usize {
    match m {
        LiveAgentMsg::DesktopFrame(f) => f.jpeg_b64.len() + 64,
        LiveAgentMsg::FileReply { reply, .. } => reply_size(reply),
        _ => 256,
    }
}

fn reply_size(r: &FileReply) -> usize {
    match r {
        FileReply::Data { data_b64, .. } => data_b64.len() + 64,
        FileReply::List { entries, .. } => {
            entries
                .iter()
                .map(|e| {
                    e.name.len() + e.path.len() + e.label.as_ref().map_or(0, |l| l.len()) + 128
                })
                .sum::<usize>()
                + 64
        }
        FileReply::Error { message, .. } => message.len() + 64,
        _ => 256,
    }
}

/// Would queueing `size` more bytes (and one more frame) break the limits?
pub fn over_limits(queued_bytes: usize, queued_frames: usize, size: usize, is_frame: bool) -> bool {
    queued_bytes + size > SESSION_MAX_QUEUED_BYTES
        || (is_frame && queued_frames + 1 > kestrel_common::remote::DESKTOP_MAX_INFLIGHT as usize)
}

/// The remote-desktop session that holds a device (one per device).
pub struct DesktopSlot {
    pub session_id: Uuid,
    pub admin_id: Uuid,
    pub admin_email: String,
    pub admin_name: String,
    pub view_only: AtomicBool,
    pub started_at: i64,
}

impl DesktopSlot {
    pub fn to_api(&self) -> Value {
        json!({
            "session_id": self.session_id,
            "admin_email": self.admin_email,
            "admin_name": self.admin_name,
            "view_only": self.view_only.load(std::sync::atomic::Ordering::Relaxed),
            "started_at": self.started_at,
        })
    }
}

#[derive(Default)]
pub struct Hub {
    sessions: DashMap<Uuid, LiveEntry>,
    desktops: DashMap<Uuid, Arc<DesktopSlot>>,
}

impl Hub {
    /// Route one agent live message to its session. Messages for unknown
    /// sessions, or for a session of another device / stream, are dropped.
    /// Never logs the message content.
    pub fn dispatch(
        &self,
        device_id: Uuid,
        conn_session: Uuid,
        session_id: Uuid,
        msg: LiveAgentMsg,
    ) {
        use std::sync::atomic::Ordering::SeqCst;
        let (tx, usage) = match self.sessions.get(&session_id) {
            Some(e) if e.device_id == device_id && e.conn_session == conn_session => {
                (e.tx.clone(), e.usage.clone())
            }
            _ => {
                tracing::debug!(%device_id, %session_id, "live message for an unknown session dropped");
                return;
            }
        };
        let size = approx_size(&msg);
        let is_frame = matches!(msg, LiveAgentMsg::DesktopFrame(_));
        if over_limits(
            usage.bytes.load(SeqCst),
            usage.frames.load(SeqCst),
            size,
            is_frame,
        ) {
            // M5: an agent that floods a session (more unacked frames than
            // allowed, or too many queued bytes) loses the session.
            usage.violated.store(true, SeqCst);
            self.sessions.remove(&session_id);
            tracing::warn!(%device_id, %session_id, "agent exceeded the live-session queue limits; session closed");
            return;
        }
        usage.bytes.fetch_add(size, SeqCst);
        if is_frame {
            usage.frames.fetch_add(1, SeqCst);
        }
        if tx.try_send(msg).is_err() {
            usage.bytes.fetch_sub(size, SeqCst);
            if is_frame {
                usage.frames.fetch_sub(1, SeqCst);
            }
            tracing::debug!(%device_id, %session_id, "live session queue full or closed; message dropped");
        }
    }

    /// The agent stream `conn_session` of `device_id` ended: close every live
    /// session opened on it (their waiters see "device disconnected").
    pub fn close_conn(&self, device_id: Uuid, conn_session: Uuid) {
        self.sessions
            .retain(|_, e| !(e.device_id == device_id && e.conn_session == conn_session));
    }

    /// Number of open live sessions (tests, metrics).
    pub fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub fn desktop(&self, device_id: &Uuid) -> Option<Arc<DesktopSlot>> {
        self.desktops.get(device_id).map(|s| s.clone())
    }
}

/// Why a live exchange with the agent failed.
#[derive(Debug, Clone, PartialEq)]
pub enum RemoteFail {
    /// No reply within [`REPLY_TIMEOUT`] (plus any consent wait).
    Timeout,
    /// The agent stream ended.
    Disconnected,
    /// The agent's outbound queue is full.
    Busy,
    /// The agent refused / failed.
    Agent {
        code: RemoteErrorCode,
        message: String,
    },
    /// Unexpected reply shape or integrity problem detected by the server.
    Protocol(String),
}

impl RemoteFail {
    /// Short text for the audit log / error message.
    pub fn describe(&self) -> String {
        match self {
            RemoteFail::Timeout => "the agent did not answer in time".into(),
            RemoteFail::Disconnected => "device disconnected".into(),
            RemoteFail::Busy => "the agent connection is busy; try again".into(),
            RemoteFail::Agent { code, message } => {
                format!("{}: {}", code.as_str(), clean_text(message, 500))
            }
            RemoteFail::Protocol(m) => m.clone(),
        }
    }

    pub fn to_api(&self) -> ApiError {
        match self {
            RemoteFail::Timeout => ApiError::gateway_timeout(self.describe())
                .with_remote_code(RemoteErrorCode::Timeout),
            RemoteFail::Disconnected => ApiError::conflict(self.describe()),
            RemoteFail::Busy => ApiError::unavailable(self.describe())
                .with_remote_code(RemoteErrorCode::Unavailable),
            RemoteFail::Agent { code, message } => agent_error(*code, message),
            RemoteFail::Protocol(m) => ApiError::internal(m.clone()),
        }
    }

    /// Consent outcome implied by a failure (after a `ConsentPending`).
    pub fn consent_result(&self) -> &'static str {
        match self {
            RemoteFail::Agent {
                code: RemoteErrorCode::ConsentDenied,
                ..
            } => "denied",
            RemoteFail::Agent {
                code: RemoteErrorCode::ConsentTimeout,
                ..
            }
            | RemoteFail::Timeout => "timeout",
            _ => "allowed",
        }
    }
}

/// Map an agent `RemoteErrorCode` to the REST error (contract table).
pub fn agent_error(code: RemoteErrorCode, message: &str) -> ApiError {
    use RemoteErrorCode as C;
    let msg = clean_text(message, 500);
    let msg = if msg.is_empty() {
        code.as_str().replace('_', " ")
    } else {
        msg
    };
    let e = match code {
        C::NotFound => ApiError::not_found(msg),
        C::ProtectedPath
        | C::BlockedPath
        | C::AccessDenied
        | C::DisabledByPolicy
        | C::NotPermitted
        | C::ConsentDenied
        | C::OutsideAllowedHours => ApiError::forbidden(msg),
        C::ReasonRequired | C::InvalidOperation | C::InvalidPath => ApiError::bad_request(msg),
        C::ConsentTimeout => ApiError::new(StatusCode::REQUEST_TIMEOUT, "consent_timeout", msg),
        C::AlreadyExists | C::Busy | C::IntegrityError => ApiError::conflict(msg),
        C::TooLarge => ApiError::payload_too_large(msg),
        C::Timeout => ApiError::gateway_timeout(msg),
        C::Unavailable => ApiError::unavailable(msg),
        C::Io | C::Other => ApiError::internal(msg),
    };
    let e = match code {
        C::DisabledByPolicy | C::NotPermitted | C::ReasonRequired => {
            e.with_field("reason", code.as_str())
        }
        _ => e,
    };
    e.with_remote_code(code)
}

/// Strip control / bidi formatting characters and clip (agent- or
/// admin-supplied text that ends up in JSON, banners and the audit log).
pub fn clean_text(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && !matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}' | '\u{061c}' | '\u{feff}')
        })
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// One live session with an agent (a desktop session, a download, an upload
/// or a single file operation). Unregisters itself from the hub on drop.
pub struct LiveSession {
    st: AppState,
    pub id: Uuid,
    pub device_id: Uuid,
    conn: Arc<AgentConn>,
    rx: mpsc::Receiver<LiveAgentMsg>,
    next_request: u64,
    /// Attached to every `FileRequest` (file-manager session, admin, reason).
    pub context: Option<FileContext>,
    /// Replies that arrived before the caller asked for them.
    early: HashMap<u64, FileReply>,
    early_bytes: usize,
    /// The agent asked the employee for consent during this session.
    pub consent_asked: bool,
    /// Outcome the agent reported with `ConsentResult` ("allowed" /
    /// "denied" / "timeout").
    pub consent_result: Option<&'static str>,
    usage: Arc<QueueUsage>,
}

/// `remote.consent` result for a `ConsentResult` message.
pub fn consent_result_str(allowed: bool, code: Option<RemoteErrorCode>) -> &'static str {
    if allowed {
        "allowed"
    } else if code == Some(RemoteErrorCode::ConsentTimeout) {
        "timeout"
    } else {
        "denied"
    }
}

impl LiveSession {
    pub fn open(st: &AppState, device_id: Uuid, conn: Arc<AgentConn>) -> LiveSession {
        Self::open_with_id(st, device_id, conn, Uuid::new_v4())
    }

    /// Open with a caller-chosen session id (the desktop session id).
    pub fn open_with_id(
        st: &AppState,
        device_id: Uuid,
        conn: Arc<AgentConn>,
        id: Uuid,
    ) -> LiveSession {
        let (tx, rx) = mpsc::channel(SESSION_QUEUE);
        let usage = Arc::new(QueueUsage::default());
        st.remote.sessions.insert(
            id,
            LiveEntry {
                device_id,
                conn_session: conn.session,
                tx,
                usage: usage.clone(),
            },
        );
        LiveSession {
            st: st.clone(),
            id,
            device_id,
            conn,
            rx,
            next_request: 0,
            context: None,
            early: HashMap::new(),
            early_bytes: 0,
            consent_asked: false,
            consent_result: None,
            usage,
        }
    }

    /// The agent broke the queue limits (M5) and the session was closed.
    pub fn violated(&self) -> bool {
        self.usage
            .violated
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    fn release(&self, m: &LiveAgentMsg) {
        use std::sync::atomic::Ordering::SeqCst;
        // Exactly what `dispatch` added for this message (sizes are
        // deterministic), so this never underflows.
        self.usage.bytes.fetch_sub(approx_size(m), SeqCst);
        if matches!(m, LiveAgentMsg::DesktopFrame(_)) {
            self.usage.frames.fetch_sub(1, SeqCst);
        }
    }

    fn closed(&self) -> RemoteFail {
        if self.violated() {
            RemoteFail::Protocol("the agent exceeded the live-session limits".into())
        } else {
            RemoteFail::Disconnected
        }
    }

    /// Queue a message for the agent (non-blocking; a full queue is an error).
    pub fn send(&self, msg: LiveServerMsg) -> Result<(), RemoteFail> {
        use mpsc::error::TrySendError;
        match self.conn.tx.try_send(ServerPayload::Live {
            session_id: self.id,
            msg,
        }) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err(RemoteFail::Busy),
            Err(TrySendError::Closed(_)) => Err(RemoteFail::Disconnected),
        }
    }

    /// Send a `FileRequest` (with the session's context); returns its id.
    pub fn request(&mut self, op: FileOp) -> Result<u64, RemoteFail> {
        self.next_request += 1;
        let request_id = self.next_request;
        self.send(LiveServerMsg::FileRequest {
            request_id,
            op,
            context: self.context.clone(),
        })?;
        Ok(request_id)
    }

    /// Next agent message, waiting at most `timeout`.
    pub async fn recv_timeout(&mut self, timeout: Duration) -> Result<LiveAgentMsg, RemoteFail> {
        match tokio::time::timeout(timeout, self.rx.recv()).await {
            Err(_) => Err(RemoteFail::Timeout),
            Ok(None) => Err(self.closed()),
            Ok(Some(m)) => {
                self.release(&m);
                Ok(m)
            }
        }
    }

    /// Next agent message without a deadline (`None` = stream ended or the
    /// session was closed for breaking the limits, see [`Self::violated`]).
    pub async fn recv(&mut self) -> Option<LiveAgentMsg> {
        let m = self.rx.recv().await?;
        self.release(&m);
        Some(m)
    }

    /// Wait for the `FileReply` of `request_id`: [`REPLY_TIMEOUT`], extended
    /// by the consent timeout (+ [`CONSENT_MARGIN`]) when the agent reports
    /// `ConsentPending` for it. Replies to other requests are kept.
    pub async fn reply(&mut self, request_id: u64) -> Result<FileReply, RemoteFail> {
        if let Some(r) = self.early.remove(&request_id) {
            self.early_bytes = self.early_bytes.saturating_sub(reply_size(&r));
            return Ok(r);
        }
        let mut deadline = tokio::time::Instant::now() + REPLY_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.recv_timeout(left).await? {
                LiveAgentMsg::FileReply {
                    request_id: r,
                    reply,
                } => {
                    if r == request_id {
                        return Ok(reply);
                    }
                    if r > 0 && r <= self.next_request {
                        let size = reply_size(&reply);
                        if self.early.len() >= 64
                            || self.early_bytes + size > SESSION_MAX_QUEUED_BYTES
                        {
                            return Err(RemoteFail::Protocol(
                                "the agent sent too many unrequested replies".into(),
                            ));
                        }
                        self.early_bytes += size;
                        self.early.insert(r, reply);
                    }
                }
                LiveAgentMsg::ConsentResult {
                    request_id: rid,
                    allowed,
                    code,
                } if rid.is_none_or(|r| r == request_id) => {
                    self.consent_asked = true;
                    self.consent_result = Some(consent_result_str(allowed, code));
                }
                LiveAgentMsg::ConsentPending {
                    request_id: rid,
                    timeout_secs,
                } if rid.is_none_or(|r| r == request_id) => {
                    self.consent_asked = true;
                    let wait = Duration::from_secs(timeout_secs.min(CONSENT_MAX_SECS) as u64)
                        + CONSENT_MARGIN;
                    deadline = deadline.max(tokio::time::Instant::now() + wait);
                }
                _ => continue,
            }
        }
    }

    /// One request → one reply.
    pub async fn call(&mut self, op: FileOp) -> Result<FileReply, RemoteFail> {
        let id = self.request(op)?;
        self.reply(id).await
    }
}

impl Drop for LiveSession {
    fn drop(&mut self) {
        self.st.remote.sessions.remove(&self.id);
    }
}

/// Holds a device's remote-desktop slot; releases it on drop.
pub struct DesktopClaim {
    st: AppState,
    device_id: Uuid,
    pub slot: Arc<DesktopSlot>,
}

impl DesktopClaim {
    /// Claim the device's single desktop slot, or return the holder.
    pub fn claim(
        st: &AppState,
        device_id: Uuid,
        slot: DesktopSlot,
    ) -> Result<DesktopClaim, Arc<DesktopSlot>> {
        use dashmap::mapref::entry::Entry;
        match st.remote.desktops.entry(device_id) {
            Entry::Occupied(o) => Err(o.get().clone()),
            Entry::Vacant(v) => {
                let slot = Arc::new(slot);
                v.insert(slot.clone());
                Ok(DesktopClaim {
                    st: st.clone(),
                    device_id,
                    slot,
                })
            }
        }
    }
}

impl Drop for DesktopClaim {
    fn drop(&mut self) {
        let sid = self.slot.session_id;
        self.st
            .remote
            .desktops
            .remove_if(&self.device_id, |_, s| s.session_id == sid);
    }
}

// --------------------------------------------------------- preconditions

/// A device that passed every precondition.
pub struct Target {
    pub device_id: Uuid,
    pub hostname: String,
    pub conn: Arc<AgentConn>,
    /// Effective remote-access profile (ceiling ∩ policy).
    pub effective: RemoteAccessProfile,
}

/// A precondition failure. `hostname` is set when the device exists, so the
/// refusal is audited (policy / ceiling refusals, guardrails, offline, …).
pub struct Refusal {
    pub error: ApiError,
    pub hostname: Option<String>,
}

/// `RemoteAvailability.reason` values, in contract order.
pub fn unavailable_reason(
    decommissioned: bool,
    ceiling_permits: bool,
    policy_permits: bool,
    connected: bool,
    has_capability: bool,
) -> Option<&'static str> {
    if decommissioned {
        Some("decommissioned")
    } else if !ceiling_permits {
        Some("not_permitted")
    } else if !policy_permits {
        Some("disabled_by_policy")
    } else if !connected {
        Some("offline")
    } else if !has_capability {
        Some("agent_too_old")
    } else {
        None
    }
}

/// L1 / desktop revalidation: is the console session still valid with the
/// feature's privilege, and does the device's effective profile still allow
/// the feature (and `op`)? Fails closed on database errors.
pub async fn still_allowed(
    st: &AppState,
    p: &Principal,
    device_id: Uuid,
    f: Feature,
    op: Option<&FileOp>,
) -> Result<bool, anyhow::Error> {
    let Via::Session { token_hash, .. } = &p.via else {
        return Ok(false);
    };
    if !crate::auth::session_still_valid(st, token_hash, f.privilege()).await? {
        return Ok(false);
    }
    Ok(effective_now(st, device_id)
        .await?
        .is_some_and(|e| permits(&e, f, op)))
}

/// Has this console session confirmed an MFA code within [`REAUTH_VALID_MS`]?
pub async fn reauth_recent(st: &AppState, p: &Principal) -> anyhow::Result<bool> {
    let now = now_ms();
    Ok(reauth_at(st, p)
        .await?
        .is_some_and(|t| t <= now && now - t < REAUTH_VALID_MS))
}

/// When the session's last `POST /me/reauth` succeeded.
async fn reauth_at(st: &AppState, p: &Principal) -> anyhow::Result<Option<i64>> {
    let Via::Session { token_hash, .. } = &p.via else {
        return Ok(None);
    };
    let row: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT reauth_at FROM sessions WHERE token_hash = $1")
            .bind(token_hash)
            .fetch_optional(&st.db)
            .await?;
    Ok(row.and_then(|r| r.0))
}

/// Contract preconditions, in order: 404 → decommissioned 409 → ceiling
/// (403 `not_permitted`) → policy (403 `disabled_by_policy`) → reason (400
/// `reason_required`) → MFA re-auth (403 `mfa_not_enabled` /
/// `reauth_required`) → offline 409 → capability 409.
// `Refusal` wraps the contract error body (large by design, like `ApiError`).
#[allow(clippy::result_large_err)]
pub async fn check(
    st: &AppState,
    p: &Principal,
    device_id: Uuid,
    f: Feature,
    op: Option<&FileOp>,
    reason: &str,
) -> Result<Target, Refusal> {
    let internal = |e: anyhow::Error| Refusal {
        error: e.into(),
        hostname: None,
    };
    let conn = st.agents.get(&device_id);
    let Some(dev) = load_device(st, device_id, conn.as_deref())
        .await
        .map_err(internal)?
    else {
        return Err(Refusal {
            error: ApiError::not_found("device not found"),
            hostname: None,
        });
    };
    let refuse = |error: ApiError| Refusal {
        error,
        hostname: Some(dev.hostname.clone()),
    };
    if dev.decommissioned {
        return Err(refuse(ApiError::conflict("device is decommissioned")));
    }
    let what = match op {
        Some(op) => format!("{} ({})", f.label(), op.name().replace('_', " ")),
        None => f.label().to_string(),
    };
    if !permits(&dev.profiles.ceiling(), f, op) {
        return Err(refuse(agent_error(
            RemoteErrorCode::NotPermitted,
            &format!(
                "the remote-access profile this device was installed with does not allow {what}"
            ),
        )));
    }
    if !permits(&dev.profiles.policy, f, op) {
        return Err(refuse(agent_error(
            RemoteErrorCode::DisabledByPolicy,
            &format!("the device's policy does not allow {what}"),
        )));
    }
    let effective = dev.profiles.effective();
    let g = &effective.guardrails;
    if g.require_reason && reason.trim().is_empty() {
        return Err(refuse(agent_error(
            RemoteErrorCode::ReasonRequired,
            "this device requires a reason for remote access",
        )));
    }
    if g.require_mfa_reauth {
        if !p.user.mfa_enabled {
            return Err(refuse(
                ApiError::forbidden(
                    "this device requires an MFA re-check; enable multi-factor authentication on your account first",
                )
                .with_field("reason", "mfa_not_enabled"),
            ));
        }
        if !reauth_recent(st, p).await.map_err(internal)? {
            return Err(refuse(
                ApiError::forbidden(
                    "confirm your MFA code again (POST /api/me/reauth) to use remote access on this device",
                )
                .with_field("reason", "reauth_required"),
            ));
        }
    }
    let Some(conn) = conn else {
        return Err(refuse(ApiError::conflict("device is offline")));
    };
    if !conn.has_capability(f.capability()) {
        return Err(refuse(ApiError::conflict(
            "the agent on this device is too old for remote access; update it",
        )));
    }
    Ok(Target {
        device_id,
        hostname: dev.hostname,
        conn,
        effective,
    })
}

/// Run the preconditions and audit a refusal (when the device exists).
#[allow(clippy::too_many_arguments)]
pub async fn check_audited(
    st: &AppState,
    p: &Principal,
    device_id: Uuid,
    f: Feature,
    op: Option<&FileOp>,
    reason: &str,
    action: &str,
    details: &Value,
) -> Result<Target, ApiError> {
    match check(st, p, device_id, f, op, reason).await {
        Ok(t) => Ok(t),
        Err(r) => {
            if let Some(h) = &r.hostname {
                audit_op(
                    st,
                    p,
                    action,
                    device_id,
                    h,
                    details.clone(),
                    Err(r.error.message.clone()),
                )
                .await;
            }
            Err(r.error)
        }
    }
}

/// `remote_access` block of `GET /devices/:id`.
pub async fn availability_json(st: &AppState, device_id: Uuid) -> anyhow::Result<Value> {
    let conn = st.agents.get(&device_id);
    let Some(dev) = load_device(st, device_id, conn.as_deref()).await? else {
        return Ok(Value::Null);
    };
    let ceiling = dev.profiles.ceiling();
    let effective = dev.profiles.effective();
    let one = |f: Feature| {
        let reason = unavailable_reason(
            dev.decommissioned,
            permits(&ceiling, f, None),
            permits(&dev.profiles.policy, f, None),
            conn.is_some(),
            conn.as_ref()
                .is_some_and(|c| c.has_capability(f.capability())),
        );
        json!({"available": reason.is_none(), "reason": reason})
    };
    Ok(json!({
        "desktop": one(Feature::Desktop),
        "files": one(Feature::Files),
        "ceiling": ceiling,
        "ceiling_summary": ceiling.summary(),
        "policy": dev.profiles.policy,
        "effective": effective,
        "effective_summary": effective.summary(),
        "agent_reported_ceiling": dev.profiles.agent_ceiling,
    }))
}

/// Append a remote-access audit row (target = device id). `details` gets
/// `hostname`, `ok` and, on failure, `error`.
pub async fn audit_op(
    st: &AppState,
    p: &Principal,
    action: &str,
    device_id: Uuid,
    hostname: &str,
    mut details: Value,
    result: Result<(), String>,
) {
    if let Some(o) = details.as_object_mut() {
        o.insert("hostname".into(), hostname.into());
        o.insert("ok".into(), result.is_ok().into());
        if let Err(e) = &result {
            o.insert("error".into(), clean_text(e, 1000).into());
        }
        if let Some(ip) = &p.ip {
            o.insert("ip".into(), ip.clone().into());
        }
    }
    audit::log(&st.db, &p.actor(), action, device_id.to_string(), details).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::remote::FileMode;

    #[test]
    fn reasons_in_contract_order() {
        assert_eq!(
            unavailable_reason(true, false, false, false, false),
            Some("decommissioned")
        );
        assert_eq!(
            unavailable_reason(false, false, false, false, false),
            Some("not_permitted")
        );
        assert_eq!(
            unavailable_reason(false, true, false, false, false),
            Some("disabled_by_policy")
        );
        assert_eq!(
            unavailable_reason(false, true, true, false, false),
            Some("offline")
        );
        assert_eq!(
            unavailable_reason(false, true, true, true, false),
            Some("agent_too_old")
        );
        assert_eq!(unavailable_reason(false, true, true, true, true), None);
    }

    #[test]
    fn agent_codes_map_to_http() {
        use axum::http::StatusCode as S;
        use RemoteErrorCode as C;
        for (c, s) in [
            (C::NotFound, S::NOT_FOUND),
            (C::ProtectedPath, S::FORBIDDEN),
            (C::BlockedPath, S::FORBIDDEN),
            (C::AccessDenied, S::FORBIDDEN),
            (C::DisabledByPolicy, S::FORBIDDEN),
            (C::NotPermitted, S::FORBIDDEN),
            (C::ConsentDenied, S::FORBIDDEN),
            (C::OutsideAllowedHours, S::FORBIDDEN),
            (C::ReasonRequired, S::BAD_REQUEST),
            (C::ConsentTimeout, S::REQUEST_TIMEOUT),
            (C::AlreadyExists, S::CONFLICT),
            (C::Busy, S::CONFLICT),
            (C::IntegrityError, S::CONFLICT),
            (C::InvalidOperation, S::BAD_REQUEST),
            (C::InvalidPath, S::BAD_REQUEST),
            (C::TooLarge, S::PAYLOAD_TOO_LARGE),
            (C::Timeout, S::GATEWAY_TIMEOUT),
            (C::Unavailable, S::SERVICE_UNAVAILABLE),
            (C::Io, S::INTERNAL_SERVER_ERROR),
            (C::Other, S::INTERNAL_SERVER_ERROR),
        ] {
            let e = agent_error(c, "x");
            assert_eq!(e.status, s, "{c:?}");
            assert_eq!(e.extra.as_ref().unwrap()["remote_code"], c.as_str());
        }
        assert_eq!(agent_error(C::TooLarge, "").code, "payload_too_large");
        assert_eq!(agent_error(C::ConsentTimeout, "").code, "consent_timeout");
        assert_eq!(
            agent_error(C::DisabledByPolicy, "off").extra.unwrap()["reason"],
            "disabled_by_policy"
        );
        assert_eq!(
            agent_error(C::NotPermitted, "no").extra.unwrap()["reason"],
            "not_permitted"
        );
        assert_eq!(RemoteFail::Timeout.to_api().status, S::GATEWAY_TIMEOUT);
    }

    #[test]
    fn queue_limits() {
        assert!(!over_limits(0, 0, 1024, true));
        assert!(!over_limits(0, 2, 1024, true));
        assert!(over_limits(0, 3, 1024, true), "a 4th unacked frame");
        assert!(!over_limits(0, 3, 1024, false));
        assert!(over_limits(SESSION_MAX_QUEUED_BYTES - 10, 0, 11, false));
        assert_eq!(consent_result_str(true, None), "allowed");
        assert_eq!(
            consent_result_str(false, Some(RemoteErrorCode::ConsentTimeout)),
            "timeout"
        );
        assert_eq!(consent_result_str(false, None), "denied");
    }

    #[test]
    fn text_is_cleaned() {
        assert_eq!(clean_text(" a\u{202e}b\nc\u{0} ", 10), "abc");
        assert_eq!(clean_text("abcdef", 3), "abc");
    }

    #[test]
    fn effective_is_the_intersection() {
        let mut policy = RemoteAccessProfile::unrestricted();
        policy.files = FileMode::ReadOnly;
        let p = Profiles {
            stored_ceiling: RemoteAccessProfile::guarded_default(),
            agent_ceiling: Some(RemoteAccessProfile::unrestricted()),
            policy,
        };
        let e = p.effective();
        assert_eq!(e.desktop, DesktopMode::Control);
        assert_eq!(e.files, FileMode::ReadOnly);
        assert!(e.guardrails.require_consent);
        // No report from the agent = no remote access.
        let none = Profiles {
            agent_ceiling: None,
            ..p.clone()
        };
        assert!(none.effective().is_none());
        let up = FileOp::WriteBegin {
            path: "C:\\a".into(),
            size: 1,
        };
        assert!(permits(&p.ceiling(), Feature::Files, Some(&up)));
        assert!(!permits(&p.policy, Feature::Files, Some(&up)));
        assert!(permits(&p.policy, Feature::Files, None));
    }

    #[test]
    fn migration_default_is_none() {
        let sql = include_str!("../../migrations/0007_remote_access.sql");
        let start = sql.find("'{\"desktop\"").unwrap() + 1;
        let end = start + sql[start..].find("'::jsonb").unwrap();
        let v: Value = serde_json::from_str(&sql[start..end]).unwrap();
        assert_eq!(profile_from_json(v.clone()), RemoteAccessProfile::none());
        assert_eq!(
            v,
            serde_json::to_value(RemoteAccessProfile::none()).unwrap()
        );
        assert_eq!(
            profile_from_json(json!({"bogus": 1, "desktop": "warp"})),
            RemoteAccessProfile::none()
        );
    }
}
