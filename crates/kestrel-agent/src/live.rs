//! Live remote-access sessions (admin remote desktop + remote file manager).
//!
//! The transport hands every `ServerPayload::Live { session_id, msg }` to
//! [`LiveManager::handle`] (non-blocking) and attaches / detaches the current
//! stream's sender. Live replies are `AgentPayload::Live` envelopes with
//! `seq = 0`, sent straight on the current stream (never the SQLite outbox);
//! while detached they are dropped. When the stream ends, every live session
//! ends: the desktop session is stopped, uploads are aborted (temp files
//! deleted), downloads closed and file-manager consents dropped.
//!
//! **Profiles.** The agent is the authority. It enforces the *effective*
//! profile = install ceiling (pinned at enrollment) ∩ policy
//! (`RemoteAccessProfile::intersect`). A feature the ceiling forbids is
//! refused with `NotPermitted` (message names the install profile); one the
//! policy forbids with `DisabledByPolicy`. Guardrails: allowed hours
//! (device local time; unknown time = refuse), required reason, blocked
//! paths, upload / delete switches, maximum desktop session length, and
//! employee consent.
//!
//! **Consent** (`require_consent`): before a desktop session starts and
//! before the first write/delete-class file operation of a file-manager
//! session (`FileContext.fm_session`; without context the live session id),
//! the agent sends `ConsentPending` to the server and pushes a
//! `ConsentRequest` to the tray in the console session; the first
//! `TrayRequest::ConsentResponse` from an identified tray client in that
//! session wins. No signed-in user = deny at once; no answer = timeout.
//! File consents are cached per file-manager session (expire after
//! `max_session_minutes`, after `idle_timeout_minutes` without operations,
//! else after 8 h).
//!
//! * **Files:** one serial worker task per live `session_id` (requests of
//!   one session run strictly in order; the server keeps several
//!   `read_chunk`s in flight), at most [`LiveConfig::max_file_sessions`] at
//!   a time (else `Busy`). Blocking work runs in `spawn_blocking`. Exactly
//!   one `FileReply` per `FileRequest` while the stream is up.
//! * **Desktop:** at most one session. Frames use credit flow control: never
//!   more than `DESKTOP_MAX_INFLIGHT` sent-but-unacked frames, and the
//!   platform sink is only polled while credit is available. The session
//!   ends on `DesktopStop`, server silence, the maximum duration, leaving
//!   the allowed hours, a profile change that forbids it, stream loss, agent
//!   shutdown or the platform ending it; the platform session's `stop()` is
//!   called exactly once on every path.
//! * **Employee notice** (mandatory in every profile): the tray gets a High
//!   activity item and `RemoteSession` pushes (desktop: start, mode change,
//!   end; files: first operation of a file-manager session, then inactive
//!   after [`LiveConfig::fm_idle`] without operations or on stream loss).
//!   `TrayStatus.remote_session` shows the desktop session, else an active
//!   file-manager session.
//! * **On-screen banner** (mandatory, privacy rule): the employee sees a
//!   banner for the whole of every remote session. Desktop: the platform's
//!   capture helper shows it. Files: before the first operation of a
//!   file-manager session runs, the agent shows a stand-alone banner
//!   (`RemoteDesktop::show_banner`; Windows: the same helper in banner-only
//!   mode) reading "IT (admin) is accessing files on this PC since HH:MM";
//!   if it cannot be shown the operation is refused (fail closed, like a
//!   desktop session whose helper cannot start) and the session does not
//!   start. Every operation re-checks the banner (a helper that died is
//!   restarted, else the file sessions end). While a desktop session runs,
//!   its banner carries the file notice (`DesktopSession::set_files_notice`)
//!   and the stand-alone banner is closed: one banner on screen. When the
//!   desktop session ends with file sessions still active, the stand-alone
//!   banner is shown *before* the desktop banner is removed. The banner ends
//!   with the last file-manager session: `FileSessionEnd` from the server
//!   (admin closed the file manager), [`LiveConfig::fm_idle`] without
//!   operations, stream loss, files switched off by policy, agent shutdown.

use base64::Engine as _;
use kestrel_common::{
    remote::{
        file_op_class, DesktopInfo, DesktopMode, DesktopStart, FileContext, FileMode, FileOp,
        FileOpClass, FileReply, LiveAgentMsg, LiveServerMsg, RemoteAccessProfile, RemoteErrorCode,
        DESKTOP_MAX_INFLIGHT, DESKTOP_SERVER_SILENCE_MS, FILE_SESSION_IDLE_MS, LIVE_MAX_MESSAGE,
        TRANSFER_IDLE_TIMEOUT_MS,
    },
    tray::{ActivityItem, ConsentRequest, RemoteKind, RemoteSessionNotice, TrayResponse},
    wire::AgentPayload,
    Severity,
};
use kestrel_platform::{
    Audience, DesktopEvent, DesktopSession, DesktopStartParams, RemoteDesktop, RemoteFs,
    SessionBanner, TrayClient, TrayPush,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::codec;
use crate::proto::AgentEnvelope;
use crate::remote_fs::{self, FsSession};

/// Queued requests per file session before `Busy`.
const FILE_QUEUE: usize = 64;
/// Oversize-frame warnings at most this often.
const OVERSIZE_WARN_EVERY_MS: i64 = 60_000;
/// A file consent without any configured limit expires after this long.
const CONSENT_GRANT_MAX: Duration = Duration::from_secs(8 * 3600);

/// What the live manager needs from the agent (implemented by `Core`;
/// tests use a fake).
pub trait LiveHost: Send + Sync {
    fn remote_fs(&self) -> Option<Arc<dyn RemoteFs>>;
    fn remote_desktop(&self) -> Option<Arc<dyn RemoteDesktop>>;
    /// Ceiling pinned at enrollment (`none()` when absent).
    fn remote_ceiling(&self) -> RemoteAccessProfile;
    /// The policy's remote-access profile in force now.
    fn remote_policy(&self) -> RemoteAccessProfile;
    /// Interactive user signed in at the console, if any.
    fn logged_on_user(&self) -> Option<String>;
    /// Windows session id of the console (`None` = unknown).
    fn console_session_id(&self) -> Option<u32>;
    /// Device local time (weekday 0 = Monday, minute since midnight).
    fn local_weekday_minute(&self) -> Option<(u8, u16)>;
    /// Persist + push a machine-wide activity item to the tray.
    fn notify_activity(&self, item: ActivityItem);
    /// Broadcast a raw tray push.
    fn broadcast(&self, push: TrayPush);
}

/// Timing / sizing knobs (tests shrink them).
#[derive(Debug, Clone)]
pub struct LiveConfig {
    pub desktop_silence: Duration,
    pub transfer_idle: Duration,
    pub max_file_sessions: usize,
    /// Desktop housekeeping period (silence / duration / hours checks).
    pub tick: Duration,
    /// A file-manager session without operations for this long is ended
    /// (tray notice and on-screen banner).
    pub fm_idle: Duration,
    /// How often idle file-manager sessions are swept.
    pub fm_sweep: Duration,
}

impl Default for LiveConfig {
    fn default() -> Self {
        LiveConfig {
            desktop_silence: Duration::from_millis(DESKTOP_SERVER_SILENCE_MS as u64),
            transfer_idle: Duration::from_millis(TRANSFER_IDLE_TIMEOUT_MS as u64),
            max_file_sessions: 8,
            tick: Duration::from_secs(1),
            fm_idle: Duration::from_millis(FILE_SESSION_IDLE_MS as u64),
            fm_sweep: Duration::from_secs(30),
        }
    }
}

/// Result of sending one live message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sent {
    Ok,
    /// Too large (or not encodable): dropped.
    Dropped,
    /// No stream.
    Detached,
}

/// A refusal: code + message for the admin.
type Refusal = (RemoteErrorCode, String);

/// A consent prompt in progress (desktop switch to control, H2).
type ConsentFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Refusal>> + Send>>;

struct Outbound {
    gen: u64,
    tx: mpsc::Sender<AgentEnvelope>,
}

struct FileWorker {
    wid: u64,
    tx: mpsc::Sender<(u64, FileOp, Option<FileContext>)>,
    cancel: CancellationToken,
    /// Set when cancelled by a profile change: queued requests are answered
    /// with it (else they are dropped: no stream).
    refuse: Arc<OnceLock<Refusal>>,
}

/// Calls the platform session's `stop()` exactly once, whichever path ends
/// the session first (including a stop requested before `start` returned).
#[derive(Default)]
struct StopOnce {
    session: Mutex<Option<Arc<dyn DesktopSession>>>,
    stopped: AtomicBool,
}

impl StopOnce {
    fn set(&self, s: Arc<dyn DesktopSession>) {
        let mut g = lock(&self.session);
        if self.stopped.load(Ordering::SeqCst) {
            drop(g);
            s.stop();
            return;
        }
        *g = Some(s);
    }

    fn stop(&self) {
        let s = {
            let g = lock(&self.session);
            if self.stopped.swap(true, Ordering::SeqCst) {
                return;
            }
            g.clone()
        };
        if let Some(s) = s {
            s.stop();
        }
    }

    fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

enum DeskCtl {
    Server(LiveServerMsg),
    /// New effective profile (policy change).
    Profile(RemoteAccessProfile),
    End {
        reason: String,
        code: Option<RemoteErrorCode>,
        tell_server: bool,
    },
}

struct DesktopSlot {
    session_id: Uuid,
    ctl: mpsc::UnboundedSender<DeskCtl>,
    stopper: Arc<StopOnce>,
}

struct PendingConsent {
    tx: oneshot::Sender<bool>,
    /// Only a tray in this Windows session (the console) may answer.
    session: u32,
}

#[derive(Debug, Clone, Copy)]
struct Grant {
    granted: Instant,
    last: Instant,
}

/// A file-manager session as the employee sees it: console session id +
/// the admin using it (a different admin reusing the id is a new session).
type FmKey = (Uuid, String);

struct FmActive {
    notice: RemoteSessionNotice,
    last: Instant,
    /// Device local start time "HH:MM" ("" when unknown), for the banner.
    since: String,
}

/// The mandatory on-screen banner (see the module docs).
#[derive(Default)]
struct BannerState {
    /// Running desktop session whose banner is on screen; the file-manager
    /// notice is shown as part of it.
    desktop: Option<(Uuid, Arc<dyn DesktopSession>)>,
    /// Stand-alone banner of the file-manager sessions (no desktop session).
    files: Option<Arc<dyn SessionBanner>>,
    /// File-manager notice last given to `desktop` / `files`.
    shown: String,
    /// Agent shutting down: nothing is shown any more.
    closed: bool,
}

/// Desktop-session change applied together with a banner update.
enum DeskBanner {
    Keep,
    /// The desktop session's banner is on screen (capture is running).
    Set(Uuid, Arc<dyn DesktopSession>),
    /// The desktop session is about to stop.
    Clear(Uuid),
}

struct Inner {
    cfg: LiveConfig,
    host: OnceLock<Weak<dyn LiveHost>>,
    out: Mutex<Option<Outbound>>,
    gen: AtomicU64,
    wid: AtomicU64,
    files: Mutex<HashMap<Uuid, FileWorker>>,
    desktop: Mutex<Option<DesktopSlot>>,
    /// Desktop notice shown to the employee.
    notice: Mutex<Option<RemoteSessionNotice>>,
    /// Effective profile last applied (change detection).
    effective: Mutex<Option<RemoteAccessProfile>>,
    consents: Mutex<HashMap<Uuid, PendingConsent>>,
    /// File-manager consent grants per (fm session, admin) (M1).
    grants: Mutex<HashMap<FmKey, Grant>>,
    /// One consent prompt at a time per (fm session, admin).
    asking: Mutex<HashMap<FmKey, Arc<tokio::sync::Mutex<()>>>>,
    /// Active file-manager sessions shown to the employee.
    fm_active: Mutex<HashMap<FmKey, FmActive>>,
    /// What the on-screen banner shows (mandatory notice).
    banner: Mutex<BannerState>,
    /// Serialises banner changes (starting a banner helper takes time).
    banner_op: tokio::sync::Mutex<()>,
    /// A desktop session in control mode is running: the admin could click
    /// "Allow" on a consent prompt through injected input (M2).
    control_active: AtomicBool,
    fm_sweeper: AtomicBool,
    last_oversize_warn: AtomicI64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Owner of every live session of this agent.
pub struct LiveManager {
    inner: Arc<Inner>,
}

impl Default for LiveManager {
    fn default() -> Self {
        LiveManager::new(LiveConfig::default())
    }
}

impl LiveManager {
    pub fn new(cfg: LiveConfig) -> LiveManager {
        LiveManager {
            inner: Arc::new(Inner {
                cfg,
                host: OnceLock::new(),
                out: Mutex::new(None),
                gen: AtomicU64::new(0),
                wid: AtomicU64::new(0),
                files: Mutex::new(HashMap::new()),
                desktop: Mutex::new(None),
                notice: Mutex::new(None),
                effective: Mutex::new(None),
                consents: Mutex::new(HashMap::new()),
                grants: Mutex::new(HashMap::new()),
                asking: Mutex::new(HashMap::new()),
                fm_active: Mutex::new(HashMap::new()),
                banner: Mutex::new(BannerState::default()),
                banner_op: tokio::sync::Mutex::new(()),
                fm_sweeper: AtomicBool::new(false),
                control_active: AtomicBool::new(false),
                last_oversize_warn: AtomicI64::new(0),
            }),
        }
    }

    /// Connect to the agent (once; `Core` binds itself right after creation).
    pub fn bind(&self, host: Weak<dyn LiveHost>) {
        let _ = self.inner.host.set(host);
    }

    /// A stream session started: live messages go to `tx` from now on.
    /// Returns the attachment generation for [`LiveManager::detach`].
    pub fn attach(&self, tx: mpsc::Sender<AgentEnvelope>) -> u64 {
        let gen = self.inner.gen.fetch_add(1, Ordering::SeqCst) + 1;
        let prev = lock(&self.inner.out).replace(Outbound { gen, tx });
        if prev.is_some() {
            // A previous stream was never detached: its sessions are dead.
            self.inner.end_all("connection replaced");
        }
        gen
    }

    /// The stream of attachment `gen` ended: end every live session.
    /// Returns whether `gen` was the current attachment (callers end their
    /// own stream-bound sessions too, e.g. evidence uploads).
    pub fn detach(&self, gen: u64) -> bool {
        let mine = {
            let mut out = lock(&self.inner.out);
            if out.as_ref().is_some_and(|o| o.gen == gen) {
                *out = None;
                true
            } else {
                false
            }
        };
        if mine {
            self.inner.end_all("connection to the server lost");
        }
        mine
    }

    /// Send one live message (`AgentPayload::Live`, seq 0) on the attached
    /// stream, outside any remote-access session (evidence uploads).
    /// Returns false when no stream is attached or the message was dropped
    /// (over `LIVE_MAX_MESSAGE`).
    pub async fn send_message(&self, session_id: Uuid, msg: LiveAgentMsg) -> bool {
        self.inner.send(session_id, msg).await == Sent::Ok
    }

    /// Agent shutdown: stop the desktop session now (banner removed),
    /// abort every transfer and pending consent.
    pub fn shutdown(&self) {
        let slot = lock(&self.inner.desktop).take();
        if let Some(s) = slot {
            s.stopper.stop();
            let _ = s.ctl.send(DeskCtl::End {
                reason: "the Kestrel agent is stopping".into(),
                code: Some(RemoteErrorCode::Unavailable),
                tell_server: true,
            });
        }
        *lock(&self.inner.notice) = None;
        self.inner.control_active.store(false, Ordering::SeqCst);
        lock(&self.inner.consents).clear();
        lock(&self.inner.grants).clear();
        lock(&self.inner.fm_active).clear();
        self.inner.cancel_files(None);
        // Remove the file-manager banner now (the desktop one went with the
        // desktop session above).
        let files = {
            let mut b = lock(&self.inner.banner);
            b.closed = true;
            b.desktop = None;
            b.files.take()
        };
        if let Some(b) = files {
            b.close();
        }
    }

    /// A new policy is in force: recompute the effective profile and end /
    /// restrict sessions it no longer allows.
    pub fn policy_changed(&self, policy: &RemoteAccessProfile) {
        let Some(host) = self.inner.host() else {
            return;
        };
        let eff = host.remote_ceiling().intersect(policy);
        let old = lock(&self.inner.effective).replace(eff.clone());
        if old.as_ref() == Some(&eff) {
            return;
        }
        // Desktop: the session task re-checks (ends it, or forces view-only).
        let ctl = lock(&self.inner.desktop).as_ref().map(|s| s.ctl.clone());
        if let Some(ctl) = ctl {
            let _ = ctl.send(DeskCtl::Profile(eff.clone()));
        }
        // Files: any change of the file part ends running file sessions and
        // drops consents (they were granted under other rules).
        let files_changed = match &old {
            Some(o) => o.files != eff.files || o.guardrails != eff.guardrails,
            None => true,
        };
        if files_changed {
            lock(&self.inner.grants).clear();
            if eff.files == FileMode::Off {
                // No file access any more: the file-manager sessions (and
                // their banner) end now.
                self.inner.end_fm_notices(&*host, |_, _| true);
            }
            if !lock(&self.inner.files).is_empty() {
                tracing::info!("remote-access profile changed; aborting file transfers");
                self.inner.cancel_files(Some((
                    RemoteErrorCode::DisabledByPolicy,
                    "the remote-access policy of this device changed".into(),
                )));
            }
        }
    }

    /// The remote session the employee is told about: the desktop session
    /// if any, else an active file-manager session.
    pub fn remote_session_notice(&self) -> Option<RemoteSessionNotice> {
        if let Some(n) = lock(&self.inner.notice).clone() {
            return Some(n);
        }
        lock(&self.inner.fm_active)
            .values()
            .max_by_key(|a| a.notice.started_at)
            .map(|a| a.notice.clone())
    }

    /// The employee's answer to a consent prompt (tray). Only identified
    /// clients in the console session (when known) may answer; the first
    /// answer wins.
    pub fn consent_response(
        &self,
        request_id: Uuid,
        allow: bool,
        client: &TrayClient,
    ) -> TrayResponse {
        let mut m = lock(&self.inner.consents);
        let Some(p) = m.get(&request_id) else {
            return TrayResponse::Error {
                message: "this request is no longer pending".into(),
            };
        };
        if !client.is_identified() {
            return TrayResponse::Error {
                message: "your identity could not be verified".into(),
            };
        }
        if client.session_id != Some(p.session) {
            return TrayResponse::Error {
                message: "only the person signed in at this PC's screen can answer".into(),
            };
        }
        let Some(p) = m.remove(&request_id) else {
            return TrayResponse::Error {
                message: "this request is no longer pending".into(),
            };
        };
        drop(m);
        // M2: while IT controls the mouse and keyboard, an "Allow" could have
        // been clicked by the admin; it counts as a denial.
        if allow && self.inner.control_active.load(Ordering::SeqCst) {
            let _ = p.tx.send(false);
            tracing::warn!(%request_id, "consent approval refused: a remote control session is active");
            return TrayResponse::Error {
                message: "can't approve while IT is controlling this PC".into(),
            };
        }
        let _ = p.tx.send(allow);
        tracing::info!(%request_id, allow, "remote-access consent answered");
        TrayResponse::Ack {
            ok: true,
            message: if allow {
                "IT can connect now.".into()
            } else {
                "You declined the request.".into()
            },
        }
    }

    /// Whether a stand-alone file-manager banner is on screen (tests,
    /// diagnostics).
    pub fn files_banner_shown(&self) -> bool {
        lock(&self.inner.banner).files.is_some()
    }

    /// Whether a desktop session is running (tests, diagnostics).
    pub fn desktop_active(&self) -> bool {
        lock(&self.inner.desktop).is_some()
    }

    /// Open file sessions (tests, diagnostics).
    pub fn file_sessions(&self) -> usize {
        lock(&self.inner.files).len()
    }

    /// Consent prompts waiting for an answer (tests, diagnostics).
    pub fn pending_consents(&self) -> Vec<Uuid> {
        lock(&self.inner.consents).keys().copied().collect()
    }

    /// Route one server live message. Never blocks; must run inside the
    /// Tokio runtime.
    pub fn handle(&self, session_id: Uuid, msg: LiveServerMsg) {
        let inner = &self.inner;
        match msg {
            LiveServerMsg::FileRequest {
                request_id,
                op,
                context,
            } => inner.file_request(session_id, request_id, op, context),
            LiveServerMsg::DesktopStart(s) => inner.desktop_start(session_id, s),
            LiveServerMsg::FileSessionEnd {
                fm_session,
                admin_name,
            } => inner.file_session_end(fm_session, &admin_name),
            LiveServerMsg::Unknown => {
                tracing::debug!(%session_id, "unknown live message kind ignored")
            }
            other => {
                let ctl = lock(&inner.desktop)
                    .as_ref()
                    .filter(|s| s.session_id == session_id)
                    .map(|s| s.ctl.clone());
                match ctl {
                    Some(c) => {
                        let _ = c.send(DeskCtl::Server(other));
                    }
                    None => {
                        tracing::debug!(%session_id, "live message for no active desktop session")
                    }
                }
            }
        }
    }
}

/// Mode refusal: the ceiling forbids it → `NotPermitted`, else the policy.
fn mode_refusal(ceiling_forbids: bool, ceiling: &RemoteAccessProfile, what: &str) -> Refusal {
    if ceiling_forbids {
        (
            RemoteErrorCode::NotPermitted,
            format!(
                "{what} is not permitted by this device's install profile: {}",
                ceiling.summary()
            ),
        )
    } else {
        (
            RemoteErrorCode::DisabledByPolicy,
            format!("{what} is not allowed by this device's policy"),
        )
    }
}

/// Allowed-hours guardrail.
fn check_hours(eff: &RemoteAccessProfile, host: &dyn LiveHost) -> Result<(), Refusal> {
    let Some(h) = &eff.guardrails.allowed_hours else {
        return Ok(());
    };
    match host.local_weekday_minute() {
        None => Err((
            RemoteErrorCode::OutsideAllowedHours,
            "device local time unknown; remote access is limited to allowed hours".into(),
        )),
        Some((d, m)) if !h.contains(d, m) => Err((
            RemoteErrorCode::OutsideAllowedHours,
            "remote access is not allowed at this time on this device".into(),
        )),
        Some(_) => Ok(()),
    }
}

/// Removes a pending consent when its wait ends (answered, timed out or
/// abandoned).
struct ConsentGuard<'a> {
    inner: &'a Inner,
    id: Uuid,
}

impl Drop for ConsentGuard<'_> {
    fn drop(&mut self) {
        lock(&self.inner.consents).remove(&self.id);
    }
}

impl Inner {
    fn host(&self) -> Option<Arc<dyn LiveHost>> {
        self.host.get().and_then(|w| w.upgrade())
    }

    fn profiles(&self, host: &dyn LiveHost) -> (RemoteAccessProfile, RemoteAccessProfile) {
        let ceiling = host.remote_ceiling();
        let eff = ceiling.intersect(&host.remote_policy());
        (ceiling, eff)
    }

    /// Send one live message on the current stream.
    async fn send(&self, session_id: Uuid, msg: LiveAgentMsg) -> Sent {
        let Some(tx) = lock(&self.out).as_ref().map(|o| o.tx.clone()) else {
            return Sent::Detached;
        };
        let payload = AgentPayload::Live { session_id, msg };
        let json = match serde_json::to_vec(&payload) {
            Ok(j) => j,
            Err(e) => {
                tracing::warn!("live message not encodable: {e}");
                return Sent::Dropped;
            }
        };
        if json.len() > LIVE_MAX_MESSAGE {
            let now = kestrel_common::now_ms();
            let last = self.last_oversize_warn.load(Ordering::Relaxed);
            if now - last >= OVERSIZE_WARN_EVERY_MS
                && self
                    .last_oversize_warn
                    .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                tracing::warn!(
                    bytes = json.len(),
                    limit = LIVE_MAX_MESSAGE,
                    "live message over the size limit dropped"
                );
            }
            return Sent::Dropped;
        }
        let (payload, compressed) = match codec::encode_json(json, false) {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("live message encoding failed: {e:#}");
                return Sent::Dropped;
            }
        };
        let env = AgentEnvelope {
            seq: 0,
            compressed,
            payload,
        };
        if tx.send(env).await.is_err() {
            return Sent::Detached;
        }
        Sent::Ok
    }

    fn spawn_send(self: &Arc<Self>, session_id: Uuid, msg: LiveAgentMsg) {
        let me = self.clone();
        tokio::spawn(async move {
            me.send(session_id, msg).await;
        });
    }

    fn reply_now(self: &Arc<Self>, session_id: Uuid, request_id: u64, reply: FileReply) {
        self.spawn_send(session_id, LiveAgentMsg::FileReply { request_id, reply });
    }

    fn end_all(self: &Arc<Self>, reason: &str) {
        let ctl = lock(&self.desktop).as_ref().map(|s| s.ctl.clone());
        if let Some(ctl) = ctl {
            let _ = ctl.send(DeskCtl::End {
                reason: reason.into(),
                code: None,
                tell_server: false,
            });
        }
        self.cancel_files(None);
        // Pending prompts are abandoned (the waiting task ends with its
        // session); consents are not carried over to another stream.
        lock(&self.grants).clear();
        if let Some(host) = self.host() {
            self.end_fm_notices(&*host, |_, _| true);
        }
    }

    fn cancel_files(&self, refuse: Option<Refusal>) {
        let workers: Vec<FileWorker> = lock(&self.files).drain().map(|(_, w)| w).collect();
        for w in workers {
            if let Some(r) = &refuse {
                let _ = w.refuse.set(r.clone());
            }
            w.cancel.cancel();
        }
    }

    // ----------------------------------------------------------- consent

    /// Ask the employee. `server_request_id`: the file request waiting for
    /// it (`None` for a desktop session). Sends `ConsentPending` before and
    /// `ConsentResult` after the prompt. No signed-in user or no known
    /// console session = denied without a prompt (L6).
    #[allow(clippy::too_many_arguments)]
    async fn ask_consent(
        &self,
        host: &dyn LiveHost,
        live_session: Uuid,
        server_request_id: Option<u64>,
        kind: RemoteKind,
        admin_name: &str,
        view_only: bool,
        reason: &str,
        timeout_secs: u32,
    ) -> Result<(), Refusal> {
        if host.logged_on_user().is_none() {
            return Err((
                RemoteErrorCode::ConsentDenied,
                "no one is signed in at this PC to approve".into(),
            ));
        }
        let Some(session) = host.console_session_id() else {
            return Err((
                RemoteErrorCode::ConsentDenied,
                "no console session to ask".into(),
            ));
        };
        let timeout_secs = timeout_secs.max(1);
        let id = Uuid::new_v4();
        let (tx, rx) = oneshot::channel();
        lock(&self.consents).insert(id, PendingConsent { tx, session });
        let _guard = ConsentGuard { inner: self, id };
        self.send(
            live_session,
            LiveAgentMsg::ConsentPending {
                request_id: server_request_id,
                timeout_secs,
            },
        )
        .await;
        host.broadcast(TrayPush {
            audience: Audience::Session(session),
            resp: TrayResponse::ConsentRequest(ConsentRequest {
                request_id: id,
                kind,
                admin_name: admin_name.to_string(),
                view_only,
                reason: reason.to_string(),
                timeout_secs,
                expires_at: kestrel_common::now_ms() + timeout_secs as i64 * 1000,
            }),
        });
        tracing::info!(
            ?kind,
            timeout_secs,
            "asking the employee for remote-access consent"
        );
        let r = match tokio::time::timeout(Duration::from_secs(timeout_secs as u64), rx).await {
            Ok(Ok(true)) => Ok(()),
            Ok(Ok(false)) => Err((
                RemoteErrorCode::ConsentDenied,
                "the user at this PC declined the request".into(),
            )),
            Ok(Err(_)) => Err((
                RemoteErrorCode::ConsentDenied,
                "the consent request was cancelled".into(),
            )),
            Err(_) => Err((
                RemoteErrorCode::ConsentTimeout,
                format!("no answer from the user at this PC within {timeout_secs} s"),
            )),
        };
        self.send(
            live_session,
            LiveAgentMsg::ConsentResult {
                request_id: server_request_id,
                allowed: r.is_ok(),
                code: r.as_ref().err().map(|e| e.0),
            },
        )
        .await;
        r
    }

    // ------------------------------------------------------------- files

    fn file_request(
        self: &Arc<Self>,
        session_id: Uuid,
        request_id: u64,
        op: FileOp,
        context: Option<FileContext>,
    ) {
        let Some(host) = self.host() else { return };
        let Some(fs) = host.remote_fs() else {
            return self.reply_now(
                session_id,
                request_id,
                FileReply::error(
                    RemoteErrorCode::Unavailable,
                    "the remote file manager is not supported on this device",
                ),
            );
        };
        let mut files = lock(&self.files);
        let mut item = (request_id, op, context);
        if let Some(w) = files.get(&session_id) {
            match w.tx.try_send(item) {
                Ok(()) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    drop(files);
                    return self.reply_now(
                        session_id,
                        request_id,
                        FileReply::error(RemoteErrorCode::Busy, "too many queued requests"),
                    );
                }
                Err(mpsc::error::TrySendError::Closed(back)) => {
                    // The worker died; start a fresh one.
                    files.remove(&session_id);
                    item = back;
                }
            }
        }
        if files.len() >= self.cfg.max_file_sessions {
            drop(files);
            return self.reply_now(
                session_id,
                request_id,
                FileReply::error(
                    RemoteErrorCode::Busy,
                    "too many file operations in progress on this device",
                ),
            );
        }
        let (tx, rx) = mpsc::channel(FILE_QUEUE);
        let _ = tx.try_send(item);
        let wid = self.wid.fetch_add(1, Ordering::Relaxed) + 1;
        let cancel = CancellationToken::new();
        let refuse = Arc::new(OnceLock::new());
        files.insert(
            session_id,
            FileWorker {
                wid,
                tx,
                cancel: cancel.clone(),
                refuse: refuse.clone(),
            },
        );
        drop(files);
        let me = self.clone();
        tokio::spawn(async move {
            me.file_worker(session_id, wid, rx, cancel, refuse, fs)
                .await
        });
    }

    /// Profile, hours, reason and consent checks for one file request.
    /// Returns what the operation may do beyond its class (blocked paths,
    /// overwrite permission).
    async fn file_gate(
        self: &Arc<Self>,
        host: &dyn LiveHost,
        session_id: Uuid,
        request_id: u64,
        op: &FileOp,
        ctx: Option<&FileContext>,
    ) -> Result<remote_fs::OpPolicy, Refusal> {
        let (ceiling, eff) = self.profiles(host);
        // L3: overwriting an existing file destroys it, so it needs
        // `allow_delete` as well as `allow_upload`.
        let overwrite_refusal = if eff.guardrails.allow_delete {
            None
        } else if !ceiling.guardrails.allow_delete {
            Some((
                RemoteErrorCode::NotPermitted,
                format!(
                    "overwriting an existing file also needs delete permission, which this device's install profile does not grant: {}",
                    ceiling.summary()
                ),
            ))
        } else {
            Some((
                RemoteErrorCode::DisabledByPolicy,
                "overwriting an existing file also needs delete permission, which this device's policy does not grant".into(),
            ))
        };
        let pol = remote_fs::OpPolicy {
            blocked: eff.guardrails.blocked_paths.clone(),
            overwrite_refusal,
        };
        // Abandoning an upload is always allowed (it only deletes our temp file).
        if matches!(op, FileOp::WriteAbort) {
            return Ok(pol);
        }
        if let Err(m) = eff.file_op_permitted(op) {
            let ceiling_forbids = ceiling.file_op_permitted(op).is_err();
            let (code, _) = mode_refusal(ceiling_forbids, &ceiling, "this file operation");
            let msg = if ceiling_forbids {
                format!(
                    "{m}: not permitted by this device's install profile: {}",
                    ceiling.summary()
                )
            } else {
                format!("{m} by this device's policy")
            };
            return Err((code, msg));
        }
        check_hours(&eff, host)?;
        let g = &eff.guardrails;
        let admin = clean_text(ctx.map(|c| c.admin_name.as_str()).unwrap_or(""), 100);
        let admin = if admin.is_empty() {
            "an administrator".to_string()
        } else {
            admin
        };
        let reason = clean_text(ctx.map(|c| c.reason.as_str()).unwrap_or(""), 500);
        if g.require_reason && reason.is_empty() {
            return Err((
                RemoteErrorCode::ReasonRequired,
                "a reason is required for remote access to this device".into(),
            ));
        }
        // Without context (older server) each live session is its own
        // file-manager session. Keyed with the admin (M1): another admin
        // reusing the id is asked again and named correctly.
        let fm: FmKey = (
            ctx.map(|c| c.fm_session).unwrap_or(session_id),
            admin.clone(),
        );
        // Mandatory banner before anything runs (fail closed).
        self.touch_fm(
            host,
            fm.clone(),
            &admin,
            &reason,
            eff.files == FileMode::ReadOnly,
        )
        .await?;
        if file_op_class(op) != FileOpClass::Read && g.require_consent {
            let cell = lock(&self.asking)
                .entry(fm.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone();
            let _one = cell.lock().await;
            let now = Instant::now();
            let valid = lock(&self.grants)
                .get(&fm)
                .is_some_and(|gr| grant_valid(gr, &eff, now));
            if !valid {
                lock(&self.grants).remove(&fm);
                self.ask_consent(
                    host,
                    session_id,
                    Some(request_id),
                    RemoteKind::Files,
                    &admin,
                    false,
                    &reason,
                    g.consent_timeout(),
                )
                .await?;
                let now = Instant::now();
                lock(&self.grants).insert(
                    fm.clone(),
                    Grant {
                        granted: now,
                        last: now,
                    },
                );
            }
        }
        if let Some(gr) = lock(&self.grants).get_mut(&fm) {
            gr.last = Instant::now();
        }
        Ok(pol)
    }

    async fn file_worker(
        self: Arc<Self>,
        session_id: Uuid,
        wid: u64,
        mut rx: mpsc::Receiver<(u64, FileOp, Option<FileContext>)>,
        cancel: CancellationToken,
        refuse: Arc<OnceLock<Refusal>>,
        fs: Arc<dyn RemoteFs>,
    ) {
        let idle = self.cfg.transfer_idle;
        let mut sess = FsSession::default();
        let mut pending: Option<(u64, FileOp, Option<FileContext>)> = None;
        let mut last_req = Instant::now();
        loop {
            let item = match pending.take() {
                Some(i) => Some(i),
                None => {
                    let deadline = last_req + idle;
                    let transfer = sess.has_transfer();
                    tokio::select! {
                        _ = cancel.cancelled() => None,
                        _ = tokio::time::sleep_until(deadline), if transfer => {
                            tracing::info!("remote file transfer idle for {idle:?}; aborted");
                            sess.abort_all();
                            None
                        }
                        m = rx.recv() => match m {
                            Some(i) => Some(i),
                            None => break,
                        }
                    }
                }
            };
            if cancel.is_cancelled() {
                if let Some((request_id, ..)) = item {
                    if let Some((code, msg)) = refuse.get() {
                        self.send(
                            session_id,
                            LiveAgentMsg::FileReply {
                                request_id,
                                reply: FileReply::error(*code, msg.clone()),
                            },
                        )
                        .await;
                    }
                }
                break;
            }
            if let Some((request_id, op, ctx)) = item {
                last_req = Instant::now();
                let Some(host) = self.host() else { break };
                let gate = tokio::select! {
                    g = self.file_gate(&*host, session_id, request_id, &op, ctx.as_ref()) => Some(g),
                    _ = cancel.cancelled() => None,
                };
                let reply = match gate {
                    None => {
                        // Session ended while waiting for consent.
                        if let Some((code, msg)) = refuse.get() {
                            self.send(
                                session_id,
                                LiveAgentMsg::FileReply {
                                    request_id,
                                    reply: FileReply::error(*code, msg.clone()),
                                },
                            )
                            .await;
                        }
                        break;
                    }
                    Some(Err((code, msg))) => {
                        if file_op_class(&op) == FileOpClass::Write {
                            // A refused upload step ends the upload.
                            sess.abort_all();
                        }
                        tracing::debug!(
                            op = op.name(),
                            code = code.as_str(),
                            "remote file op refused"
                        );
                        FileReply::error(code, msg)
                    }
                    Some(Ok(pol)) => {
                        let fs2 = fs.clone();
                        let r = tokio::task::spawn_blocking(move || {
                            let reply = remote_fs::handle(&fs2, &mut sess, op, &pol);
                            (sess, reply)
                        })
                        .await;
                        match r {
                            Ok((s, reply)) => {
                                sess = s;
                                reply
                            }
                            Err(_) => {
                                sess = FsSession::default();
                                FileReply::error(RemoteErrorCode::Io, "internal error")
                            }
                        }
                    }
                };
                if cancel.is_cancelled() {
                    // Session ended while the operation ran: drop any open
                    // transfer it just created.
                    sess.abort_all();
                    if refuse.get().is_none() {
                        break;
                    }
                }
                self.send(session_id, LiveAgentMsg::FileReply { request_id, reply })
                    .await;
            }
            if cancel.is_cancelled() {
                break;
            }
            // Exit when idle with nothing open (checked under the map lock,
            // so a request routed concurrently is never lost).
            if !sess.has_transfer() {
                let mut files = lock(&self.files);
                match rx.try_recv() {
                    Ok(i) => pending = Some(i),
                    Err(_) => {
                        if files.get(&session_id).is_some_and(|w| w.wid == wid) {
                            files.remove(&session_id);
                        }
                        break;
                    }
                }
            }
        }
        sess.abort_all();
        if cancel.is_cancelled() {
            if let Some((code, msg)) = refuse.get() {
                // Answer what is still queued.
                rx.close();
                while let Ok((request_id, ..)) = rx.try_recv() {
                    self.send(
                        session_id,
                        LiveAgentMsg::FileReply {
                            request_id,
                            reply: FileReply::error(*code, msg.clone()),
                        },
                    )
                    .await;
                }
            }
        }
        let mut files = lock(&self.files);
        if files.get(&session_id).is_some_and(|w| w.wid == wid) {
            files.remove(&session_id);
        }
    }

    /// Record activity of file-manager session `fm` and make sure the
    /// mandatory banner is on screen; the first operation tells the employee
    /// (banner first, then tray). `Err` = no banner: the operation is
    /// refused (a new session does not start; running ones end).
    async fn touch_fm(
        self: &Arc<Self>,
        host: &dyn LiveHost,
        fm: FmKey,
        admin: &str,
        reason: &str,
        read_only: bool,
    ) -> Result<(), Refusal> {
        let new = {
            let mut m = lock(&self.fm_active);
            if let Some(a) = m.get_mut(&fm) {
                a.last = Instant::now();
                None
            } else {
                let notice = RemoteSessionNotice {
                    active: true,
                    kind: RemoteKind::Files,
                    admin_name: admin.to_string(),
                    view_only: read_only,
                    reason: reason.to_string(),
                    started_at: kestrel_common::now_ms(),
                    ended_at: None,
                };
                let since = host
                    .local_weekday_minute()
                    .map(|(_, m)| format!("{:02}:{:02}", (m / 60) % 24, m % 60))
                    .unwrap_or_default();
                m.insert(
                    fm.clone(),
                    FmActive {
                        notice: notice.clone(),
                        last: Instant::now(),
                        since,
                    },
                );
                Some(notice)
            }
        };
        if let Err(r) = self.banner_update(DeskBanner::Keep).await {
            if let Some(n) = &new {
                // Never shown to the employee: drop it silently.
                let mut m = lock(&self.fm_active);
                if m.get(&fm)
                    .is_some_and(|a| a.notice.started_at == n.started_at)
                {
                    m.remove(&fm);
                }
            }
            tracing::warn!(code = r.0.as_str(), "remote file access refused: {}", r.1);
            // Sessions already running have no banner either: end them.
            if !lock(&self.fm_active).is_empty() {
                self.files_fail_closed(host, r.clone());
            }
            return Err(r);
        }
        let Some(notice) = new else { return Ok(()) };
        let mut body = String::new();
        if !reason.is_empty() {
            body.push_str(&format!("Reason given: {reason}. "));
        }
        body.push_str(if read_only {
            "IT can browse and download files on this PC. "
        } else {
            "IT can browse, download and change files on this PC. "
        });
        body.push_str(
            "A banner stays at the top of the screen while IT has access. If you did not expect this, contact IT.",
        );
        host.notify_activity(ActivityItem {
            id: Uuid::new_v4(),
            ts: kestrel_common::now_ms(),
            title: format!("IT ({admin}) is accessing files on this PC"),
            body,
            severity: Severity::High,
            alert_id: None,
            file: None,
            action_taken: "Remote file access started".into(),
            review: None,
        });
        host.broadcast(public(TrayResponse::RemoteSession(notice)));
        self.start_fm_sweeper();
        Ok(())
    }

    /// The admin closed the file manager (`FileSessionEnd`).
    fn file_session_end(self: &Arc<Self>, fm_session: Uuid, admin_name: &str) {
        let admin = clean_text(admin_name, 100);
        let admin = if admin.is_empty() {
            "an administrator".to_string()
        } else {
            admin
        };
        let key: FmKey = (fm_session, admin);
        lock(&self.grants).remove(&key);
        let Some(host) = self.host() else { return };
        tracing::info!(%fm_session, "remote file-manager session ended by the server");
        self.end_fm_notices(&*host, |k, _| *k == key);
    }

    /// No banner can be shown for the file-manager sessions: end them all,
    /// abort running transfers (queued requests get `r`) and drop consents.
    fn files_fail_closed(self: &Arc<Self>, host: &dyn LiveHost, r: Refusal) {
        tracing::warn!("ending remote file-manager sessions: {}", r.1);
        self.cancel_files(Some(r));
        lock(&self.grants).clear();
        self.end_fm_notices(host, |_, _| true);
    }

    fn start_fm_sweeper(self: &Arc<Self>) {
        if self.fm_sweeper.swap(true, Ordering::SeqCst) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(me.cfg.fm_sweep).await;
                let Some(host) = me.host() else { break };
                let idle = me.cfg.fm_idle;
                let now = Instant::now();
                me.end_fm_notices(&*host, |_, a| now.duration_since(a.last) >= idle);
                // The banner of the remaining sessions must still be up.
                if !lock(&me.fm_active).is_empty() {
                    if let Err(r) = me.banner_update(DeskBanner::Keep).await {
                        me.files_fail_closed(&*host, r);
                    }
                }
                // Stop when nothing is active (under the lock, so a new
                // session either sees the flag cleared or is swept).
                let m = lock(&me.fm_active);
                if m.is_empty() {
                    me.fm_sweeper.store(false, Ordering::SeqCst);
                    break;
                }
            }
        });
    }

    /// End (tell the employee) the file-manager sessions matching `pred`;
    /// the banner follows (removed with the last session).
    fn end_fm_notices(
        self: &Arc<Self>,
        host: &dyn LiveHost,
        pred: impl Fn(&FmKey, &FmActive) -> bool,
    ) {
        let ended: Vec<RemoteSessionNotice> = {
            let mut m = lock(&self.fm_active);
            let keys: Vec<FmKey> = m
                .iter()
                .filter(|(k, a)| pred(k, a))
                .map(|(k, _)| k.clone())
                .collect();
            // Prompt locks of ended sessions (unless a prompt is running)
            // and grants unused for longer than any grant can live.
            lock(&self.asking).retain(|k, v| !keys.contains(k) || Arc::strong_count(v) > 1);
            let now = Instant::now();
            lock(&self.grants).retain(|_, g| now.duration_since(g.last) < CONSENT_GRANT_MAX);
            keys.into_iter()
                .filter_map(|k| m.remove(&k))
                .map(|a| a.notice)
                .collect()
        };
        if ended.is_empty() {
            return;
        }
        self.spawn_banner_sync();
        for mut n in ended {
            n.active = false;
            n.ended_at = Some(kestrel_common::now_ms());
            host.broadcast(public(TrayResponse::RemoteSession(n)));
        }
    }

    // ------------------------------------------------------------ banner

    /// File-manager notice for the banner ("" = no file-manager session).
    fn files_notice(&self) -> String {
        let m = lock(&self.fm_active);
        let mut v: Vec<&FmActive> = m.values().collect();
        v.sort_by_key(|a| a.notice.started_at);
        let parts: Vec<(&str, &str, &str)> = v
            .iter()
            .map(|a| {
                (
                    a.notice.admin_name.as_str(),
                    a.since.as_str(),
                    a.notice.reason.as_str(),
                )
            })
            .collect();
        files_banner_text(&parts)
    }

    /// Bring the screen in line with the sessions (after applying `desk`):
    /// while a desktop session runs its banner carries the file notice;
    /// otherwise a stand-alone banner shows it while file-manager sessions
    /// are active; otherwise nothing. `Err` = file-manager sessions are
    /// active but no banner could be shown.
    async fn banner_update(self: &Arc<Self>, desk: DeskBanner) -> Result<(), Refusal> {
        let _op = self.banner_op.lock().await;
        {
            let mut st = lock(&self.banner);
            match desk {
                DeskBanner::Keep => {}
                DeskBanner::Set(id, s) => {
                    if !st.closed {
                        st.desktop = Some((id, s));
                        // The desktop helper starts without the notice.
                        st.shown.clear();
                    }
                }
                DeskBanner::Clear(id) => {
                    if st.desktop.as_ref().is_some_and(|(d, _)| *d == id) {
                        st.desktop = None;
                        st.shown.clear();
                    }
                }
            }
        }
        let text = self.files_notice();
        let (desk, files, shown, closed) = {
            let st = lock(&self.banner);
            (
                st.desktop.clone(),
                st.files.clone(),
                st.shown.clone(),
                st.closed,
            )
        };
        if closed {
            return if text.is_empty() {
                Ok(())
            } else {
                Err((
                    RemoteErrorCode::Unavailable,
                    "the Kestrel agent is stopping".into(),
                ))
            };
        }
        if let Some((_, d)) = desk {
            if shown != text {
                d.set_files_notice(&text);
            }
            // The desktop banner is on screen: one banner only.
            let old = {
                let mut st = lock(&self.banner);
                st.shown = text;
                st.files.take()
            };
            if let Some(b) = old {
                b.close();
            }
            return Ok(());
        }
        if text.is_empty() {
            let old = {
                let mut st = lock(&self.banner);
                st.shown.clear();
                st.files.take()
            };
            if let Some(b) = old {
                b.close();
                tracing::info!("remote file access ended; banner removed");
            }
            return Ok(());
        }
        if let Some(b) = files {
            if b.is_alive() {
                if shown != text {
                    b.set_text(&text);
                    lock(&self.banner).shown = text;
                }
                return Ok(());
            }
            tracing::warn!("the remote-access banner is no longer on screen; showing it again");
            {
                let mut st = lock(&self.banner);
                if st.files.as_ref().is_some_and(|f| Arc::ptr_eq(f, &b)) {
                    st.files = None;
                }
            }
            b.close();
        }
        let refuse = |code: RemoteErrorCode, msg: &str| -> Refusal {
            (
                code,
                format!(
                    "the on-screen notice for the user at this PC could not be shown ({msg}); remote file access is refused"
                ),
            )
        };
        let Some(rd) = self.host().and_then(|h| h.remote_desktop()) else {
            return Err(refuse(
                RemoteErrorCode::Unavailable,
                "this device cannot show it",
            ));
        };
        let t = text.clone();
        match tokio::task::spawn_blocking(move || rd.show_banner(&t)).await {
            Ok(Ok(b)) => {
                let b: Arc<dyn SessionBanner> = Arc::from(b);
                let mut st = lock(&self.banner);
                if st.closed {
                    drop(st);
                    b.close();
                    return Err((
                        RemoteErrorCode::Unavailable,
                        "the Kestrel agent is stopping".into(),
                    ));
                }
                st.files = Some(b);
                st.shown = text;
                tracing::info!("remote file access: banner shown");
                Ok(())
            }
            Ok(Err((code, msg))) => Err(refuse(code, &msg)),
            Err(_) => Err(refuse(
                RemoteErrorCode::Unavailable,
                "the banner helper failed",
            )),
        }
    }

    /// [`Inner::banner_update`] in the background (after sessions ended).
    fn spawn_banner_sync(self: &Arc<Self>) {
        match tokio::runtime::Handle::try_current() {
            Ok(h) => {
                let me = self.clone();
                h.spawn(async move {
                    if let Err(r) = me.banner_update(DeskBanner::Keep).await {
                        if let Some(host) = me.host() {
                            me.files_fail_closed(&*host, r);
                        }
                    }
                });
            }
            Err(_) => {
                // No runtime: only removing is possible.
                if lock(&self.fm_active).is_empty() {
                    let old = lock(&self.banner).files.take();
                    if let Some(b) = old {
                        b.close();
                    }
                }
            }
        }
    }

    // ----------------------------------------------------------- desktop

    fn desktop_ended(self: &Arc<Self>, session_id: Uuid, (code, reason): Refusal) {
        self.spawn_send(
            session_id,
            LiveAgentMsg::DesktopEnded {
                reason,
                code: Some(code),
            },
        );
    }

    /// Profile checks for a desktop session (mode, hours, reason).
    fn desktop_gate(
        &self,
        host: &dyn LiveHost,
        start: &DesktopStart,
    ) -> Result<RemoteAccessProfile, Refusal> {
        let (ceiling, eff) = self.profiles(host);
        if eff.desktop == DesktopMode::Off {
            return Err(mode_refusal(
                ceiling.desktop == DesktopMode::Off,
                &ceiling,
                "remote desktop",
            ));
        }
        check_hours(&eff, host)?;
        if eff.guardrails.require_reason && clean_text(&start.reason, 500).is_empty() {
            return Err((
                RemoteErrorCode::ReasonRequired,
                "a reason is required for remote access to this device".into(),
            ));
        }
        Ok(eff)
    }

    fn desktop_start(self: &Arc<Self>, session_id: Uuid, start: DesktopStart) {
        let Some(host) = self.host() else { return };
        let Some(rd) = host.remote_desktop() else {
            return self.desktop_ended(
                session_id,
                (
                    RemoteErrorCode::Unavailable,
                    "remote desktop is not supported on this device".into(),
                ),
            );
        };
        let mut slot = lock(&self.desktop);
        if let Some(s) = slot.as_ref() {
            if s.session_id == session_id {
                tracing::debug!(%session_id, "duplicate desktop start ignored");
                return;
            }
            drop(slot);
            return self.desktop_ended(
                session_id,
                (
                    RemoteErrorCode::Busy,
                    "another remote desktop session is active on this device".into(),
                ),
            );
        }
        let eff = match self.desktop_gate(&*host, &start) {
            Ok(e) => e,
            Err(r) => {
                drop(slot);
                tracing::info!(code = r.0.as_str(), "remote desktop refused: {}", r.1);
                return self.desktop_ended(session_id, r);
            }
        };
        let (ctl_tx, ctl_rx) = mpsc::unbounded_channel();
        let stopper = Arc::new(StopOnce::default());
        *slot = Some(DesktopSlot {
            session_id,
            ctl: ctl_tx,
            stopper: stopper.clone(),
        });
        drop(slot);
        let me = self.clone();
        tokio::spawn(async move {
            me.run_desktop(host, rd, eff, session_id, start, ctl_rx, stopper)
                .await
        });
    }

    fn set_notice(&self, n: Option<RemoteSessionNotice>) {
        *lock(&self.notice) = n;
    }

    fn clear_slot(&self, session_id: Uuid) {
        let mut slot = lock(&self.desktop);
        if slot.as_ref().is_some_and(|s| s.session_id == session_id) {
            *slot = None;
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_desktop(
        self: Arc<Self>,
        host: Arc<dyn LiveHost>,
        rd: Arc<dyn RemoteDesktop>,
        mut eff: RemoteAccessProfile,
        session_id: Uuid,
        start: DesktopStart,
        mut ctl: mpsc::UnboundedReceiver<DeskCtl>,
        stopper: Arc<StopOnce>,
    ) {
        // View-only profiles force a view-only session.
        let mut view_only = start.view_only || eff.desktop != DesktopMode::Control;
        let admin = clean_text(&start.admin_name, 100);
        let admin = if admin.is_empty() {
            "an administrator".to_string()
        } else {
            admin
        };
        let reason = clean_text(&start.reason, 500);

        // Consent before anything is captured.
        if eff.guardrails.require_consent {
            let ask = self.ask_consent(
                &*host,
                session_id,
                None,
                RemoteKind::Desktop,
                &admin,
                view_only,
                &reason,
                eff.guardrails.consent_timeout(),
            );
            tokio::pin!(ask);
            let outcome: Result<(), (Refusal, bool)> = loop {
                tokio::select! {
                    r = &mut ask => break r.map_err(|e| (e, true)),
                    c = ctl.recv() => match c {
                        None => break Err(((RemoteErrorCode::Unavailable, "the Kestrel agent is stopping".into()), false)),
                        Some(DeskCtl::End { reason, code, tell_server }) => {
                            break Err(((code.unwrap_or(RemoteErrorCode::Unavailable), reason), tell_server))
                        }
                        Some(DeskCtl::Server(LiveServerMsg::DesktopStop { .. })) => {
                            break Err(((RemoteErrorCode::ConsentDenied, "stopped by the administrator before consent".into()), true))
                        }
                        Some(DeskCtl::Profile(p)) => {
                            if p.desktop == DesktopMode::Off {
                                break Err(((RemoteErrorCode::DisabledByPolicy, "remote desktop was switched off by policy".into()), true));
                            }
                            eff = p;
                        }
                        Some(DeskCtl::Server(_)) => {}
                    }
                }
            };
            if let Err(((code, msg), tell)) = outcome {
                tracing::info!(%session_id, code = code.as_str(), "remote desktop not started: {msg}");
                if tell {
                    self.send(
                        session_id,
                        LiveAgentMsg::DesktopEnded {
                            reason: msg,
                            code: Some(code),
                        },
                    )
                    .await;
                }
                self.clear_slot(session_id);
                return;
            }
            view_only = view_only || eff.desktop != DesktopMode::Control;
        }
        if stopper.is_stopped() {
            self.clear_slot(session_id);
            return;
        }

        let started = Instant::now();
        let started_at = kestrel_common::now_ms();
        let mut settings = start.settings.clamped();
        settings.view_only = None;
        let params = DesktopStartParams {
            view_only,
            admin_name: admin.clone(),
            reason: reason.clone(),
            settings,
        };
        let (sink_tx, mut sink) = mpsc::channel::<DesktopEvent>(2);
        let r = tokio::task::spawn_blocking(move || rd.start(params, sink_tx)).await;
        let session: Arc<dyn DesktopSession> = match r {
            Ok(Ok(b)) => Arc::from(b),
            Ok(Err((code, msg))) => {
                tracing::warn!(
                    code = code.as_str(),
                    "remote desktop could not start: {msg}"
                );
                self.send(
                    session_id,
                    LiveAgentMsg::DesktopEnded {
                        reason: msg,
                        code: Some(code),
                    },
                )
                .await;
                self.clear_slot(session_id);
                return;
            }
            Err(_) => {
                self.send(
                    session_id,
                    LiveAgentMsg::DesktopEnded {
                        reason: "remote desktop failed to start".into(),
                        code: Some(RemoteErrorCode::Unavailable),
                    },
                )
                .await;
                self.clear_slot(session_id);
                return;
            }
        };
        stopper.set(session.clone());
        tracing::info!(%session_id, view_only, "remote desktop session started");
        if !stopper.is_stopped() {
            self.control_active.store(!view_only, Ordering::SeqCst);
        }
        // Settings to apply when a consented switch to control goes through.
        let mut last_settings = kestrel_common::remote::DesktopSettings {
            view_only: None,
            ..start.settings.clamped()
        };
        // H2: a pending "switch to control" consent prompt.
        let mut switch_ask: Option<ConsentFuture> = None;

        let mut notice = RemoteSessionNotice {
            active: true,
            kind: RemoteKind::Desktop,
            admin_name: admin.clone(),
            view_only,
            reason: reason.clone(),
            started_at,
            ended_at: None,
        };
        // Shutdown may have run while the helper started.
        if !stopper.is_stopped() {
            self.set_notice(Some(notice.clone()));
        }
        host.notify_activity(start_item(&admin, view_only, &reason));
        host.broadcast(public(TrayResponse::RemoteSession(notice.clone())));

        let mut sent: u64 = 0;
        let mut acked: u64 = 0;
        let mut started_sent = false;
        // This session's banner carries the file-manager notice.
        let mut banner_registered = false;
        let mut last_heard = Instant::now();
        let mut tick = tokio::time::interval(self.cfg.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let inflight_max = DESKTOP_MAX_INFLIGHT as u64;

        let (end_reason, end_code, tell_server) = loop {
            let credit = sent.saturating_sub(acked) < inflight_max;
            let mut mode_change: Option<bool> = None;
            tokio::select! {
                c = ctl.recv() => match c {
                    None => break ("the Kestrel agent is stopping".to_string(), None, false),
                    Some(DeskCtl::End { reason, code, tell_server }) => break (reason, code, tell_server),
                    Some(DeskCtl::Profile(p)) => {
                        if p.desktop == DesktopMode::Off {
                            break ("remote desktop was switched off by policy".to_string(), Some(RemoteErrorCode::DisabledByPolicy), true);
                        }
                        if p.desktop == DesktopMode::ViewOnly && !view_only {
                            mode_change = Some(true);
                        }
                        eff = p;
                    }
                    Some(DeskCtl::Server(m)) => {
                        last_heard = Instant::now();
                        match m {
                            LiveServerMsg::DesktopAck { seq } => acked = acked.max(seq.min(sent)),
                            LiveServerMsg::DesktopPing => {}
                            LiveServerMsg::DesktopStop { reason } => {
                                let r = clean_text(&reason, 200);
                                break (if r.is_empty() { "stopped by the administrator".into() } else { r }, None, true);
                            }
                            LiveServerMsg::DesktopInput { event } => {
                                if !view_only {
                                    if let Some(ev) = event.sanitized() {
                                        session.input(&ev);
                                    }
                                }
                            }
                            LiveServerMsg::DesktopSettings(s) => {
                                let mut c = s.clamped();
                                last_settings = kestrel_common::remote::DesktopSettings { view_only: None, ..c.clone() };
                                if let Some(v) = c.view_only {
                                    if !v && eff.desktop != DesktopMode::Control {
                                        tracing::info!(%session_id, "switch to control refused: view-only profile");
                                        c.view_only = None;
                                    } else if !v && view_only && eff.guardrails.require_consent {
                                        // H2: ask the employee again; stay view-only meanwhile.
                                        c.view_only = None;
                                        if switch_ask.is_none() {
                                            let me = self.clone();
                                            let h = host.clone();
                                            let (a, r) = (admin.clone(), reason.clone());
                                            let t = eff.guardrails.consent_timeout();
                                            switch_ask = Some(Box::pin(async move {
                                                me.ask_consent(&*h, session_id, None, RemoteKind::Desktop, &a, false, &r, t).await
                                            }));
                                        }
                                    } else if v != view_only {
                                        mode_change = Some(v);
                                    } else if v {
                                        // Back to view-only: drop a pending switch prompt.
                                        switch_ask = None;
                                    }
                                }
                                session.settings(&c);
                            }
                            _ => {}
                        }
                    }
                },
                ev = sink.recv(), if credit => match ev {
                    None => break ("the screen capture stopped".to_string(), Some(RemoteErrorCode::Unavailable), true),
                    Some(DesktopEvent::Ended { reason, code }) => break (reason, code, true),
                    Some(DesktopEvent::Info(mut info)) => {
                        info.view_only = view_only;
                        let msg = if started_sent {
                            LiveAgentMsg::DesktopInfo(info)
                        } else {
                            started_sent = true;
                            // Capture runs only once the banner is up: it
                            // now carries the file-manager notice too.
                            let _ = self.banner_update(DeskBanner::Set(session_id, session.clone())).await;
                            banner_registered = true;
                            LiveAgentMsg::DesktopStarted(info)
                        };
                        if self.send(session_id, msg).await == Sent::Detached {
                            break ("connection to the server lost".to_string(), None, false);
                        }
                    }
                    Some(DesktopEvent::Frame { width, height, ts, jpeg }) => {
                        if !started_sent {
                            started_sent = true;
                            let _ = self.banner_update(DeskBanner::Set(session_id, session.clone())).await;
                            banner_registered = true;
                            let info = DesktopInfo { width, height, monitors: 1, view_only, ..Default::default() };
                            if self.send(session_id, LiveAgentMsg::DesktopStarted(info)).await == Sent::Detached {
                                break ("connection to the server lost".to_string(), None, false);
                            }
                        }
                        let seq = sent + 1;
                        let frame = kestrel_common::remote::DesktopFrame {
                            seq,
                            width,
                            height,
                            ts,
                            jpeg_b64: base64::engine::general_purpose::STANDARD.encode(&jpeg),
                        };
                        drop(jpeg);
                        match self.send(session_id, LiveAgentMsg::DesktopFrame(frame)).await {
                            Sent::Ok => sent = seq,
                            Sent::Dropped => {}
                            Sent::Detached => break ("connection to the server lost".to_string(), None, false),
                        }
                    }
                },
                r = async {
                    match switch_ask.as_mut() {
                        Some(f) => f.await,
                        None => std::future::pending().await,
                    }
                }, if switch_ask.is_some() => {
                    switch_ask = None;
                    match r {
                        Ok(()) if view_only && eff.desktop == DesktopMode::Control => {
                            session.settings(&kestrel_common::remote::DesktopSettings {
                                view_only: Some(false),
                                ..last_settings.clone()
                            });
                            mode_change = Some(false);
                        }
                        Ok(()) => {}
                        Err((code, msg)) => {
                            tracing::info!(%session_id, code = code.as_str(), "switch to control not approved: {msg}");
                        }
                    }
                }
                _ = tick.tick() => {
                    if last_heard.elapsed() >= self.cfg.desktop_silence {
                        break ("no contact with the server".to_string(), Some(RemoteErrorCode::Timeout), true);
                    }
                    let max = eff.guardrails.max_session_minutes;
                    if max > 0 && started.elapsed() >= Duration::from_secs(max as u64 * 60) {
                        break ("the maximum session length was reached".to_string(), Some(RemoteErrorCode::Timeout), true);
                    }
                    if let Err((code, msg)) = check_hours(&eff, &*host) {
                        break (msg, Some(code), true);
                    }
                }
            }
            if let Some(v) = mode_change {
                view_only = v;
                notice.view_only = v;
                if v {
                    switch_ask = None;
                }
                if !stopper.is_stopped() {
                    self.control_active.store(!v, Ordering::SeqCst);
                }
                tracing::info!(%session_id, view_only, "remote desktop mode changed");
                if v {
                    // Tell the platform (banner text) when the agent forced it.
                    session.settings(&kestrel_common::remote::DesktopSettings {
                        view_only: Some(true),
                        ..start.settings.clamped()
                    });
                }
                if !stopper.is_stopped() {
                    self.set_notice(Some(notice.clone()));
                }
                host.broadcast(public(TrayResponse::RemoteSession(notice.clone())));
            }
        };

        if banner_registered {
            // File-manager sessions still active: their stand-alone banner
            // goes up before this one comes down; without it they end.
            if let Err(r) = self.banner_update(DeskBanner::Clear(session_id)).await {
                self.files_fail_closed(&*host, r);
            }
        }
        stopper.stop();
        self.control_active.store(false, Ordering::SeqCst);
        drop(switch_ask);
        drop(sink);
        tracing::info!(%session_id, reason = %end_reason, "remote desktop session ended");
        if tell_server {
            self.send(
                session_id,
                LiveAgentMsg::DesktopEnded {
                    reason: end_reason.clone(),
                    code: end_code,
                },
            )
            .await;
        }
        let ended_at = kestrel_common::now_ms();
        notice.active = false;
        notice.ended_at = Some(ended_at);
        self.clear_slot(session_id);
        {
            let mut n = lock(&self.notice);
            if n.as_ref().is_some_and(|x| x.started_at == started_at) {
                *n = None;
            }
        }
        host.notify_activity(end_item(&admin, ended_at - started_at));
        host.broadcast(public(TrayResponse::RemoteSession(notice)));
    }
}

fn grant_valid(g: &Grant, eff: &RemoteAccessProfile, now: Instant) -> bool {
    let max = eff.guardrails.max_session_minutes as u64;
    let idle = eff.guardrails.idle_timeout_minutes as u64;
    if max > 0 && now.duration_since(g.granted) >= Duration::from_secs(max * 60) {
        return false;
    }
    if idle > 0 && now.duration_since(g.last) >= Duration::from_secs(idle * 60) {
        return false;
    }
    if max == 0 && idle == 0 && now.duration_since(g.granted) >= CONSENT_GRANT_MAX {
        return false;
    }
    true
}

/// Banner text of the active file-manager sessions, oldest first:
/// `(admin, local start "HH:MM" or "", reason)`. "" when there are none.
/// "IT (Jane Doe) is accessing files on this PC since 14:02 — Reason: …";
/// several admins are listed together, the reason only when all sessions
/// give the same one.
fn files_banner_text(sessions: &[(&str, &str, &str)]) -> String {
    let Some(first) = sessions.first() else {
        return String::new();
    };
    let mut admins: Vec<&str> = Vec::new();
    for (a, _, _) in sessions {
        if !admins.contains(a) {
            admins.push(a);
        }
    }
    let mut s = format!("IT ({}) is accessing files on this PC", admins.join(", "));
    if !first.1.is_empty() {
        s.push_str(" since ");
        s.push_str(first.1);
    }
    let reason = first.2;
    if !reason.is_empty() && sessions.iter().all(|(_, _, r)| *r == reason) {
        s.push_str(" \u{2014} Reason: ");
        s.push_str(reason);
    }
    s
}

fn public(resp: TrayResponse) -> TrayPush {
    TrayPush {
        audience: Audience::Public,
        resp,
    }
}

/// Single-line, length-capped text from the server for the employee notice.
fn clean_text(s: &str, max: usize) -> String {
    s.chars()
        // L5: bidi overrides / isolates / marks and other invisible format
        // characters could disguise who is connecting or why.
        .filter(|c| !is_format_char(*c))
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect()
}

/// Bidi controls and invisible format characters.
fn is_format_char(c: char) -> bool {
    matches!(
        c,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

fn start_item(admin: &str, view_only: bool, reason: &str) -> ActivityItem {
    let verb = if view_only { "viewing" } else { "controlling" };
    let mut body = String::new();
    if !reason.is_empty() {
        body.push_str(&format!("Reason given: {reason}. "));
    }
    body.push_str(if view_only {
        "IT can see your screen but cannot use your mouse or keyboard. "
    } else {
        "IT can see your screen and use your mouse and keyboard. "
    });
    body.push_str(
        "A banner stays at the top of the screen for the whole session. If you did not expect this, contact IT.",
    );
    ActivityItem {
        id: Uuid::new_v4(),
        ts: kestrel_common::now_ms(),
        title: format!("IT ({admin}) is {verb} this PC"),
        body,
        severity: Severity::High,
        alert_id: None,
        file: None,
        action_taken: "Remote session started".into(),
        review: None,
    }
}

fn human_duration(ms: i64) -> String {
    let s = (ms / 1000).max(0);
    if s < 60 {
        format!("{s} seconds")
    } else if s < 3600 {
        format!("{} minutes", s / 60)
    } else {
        format!("{} h {} min", s / 3600, (s % 3600) / 60)
    }
}

fn end_item(admin: &str, duration_ms: i64) -> ActivityItem {
    ActivityItem {
        id: Uuid::new_v4(),
        ts: kestrel_common::now_ms(),
        title: "IT ended the remote session".into(),
        body: format!(
            "The remote session by IT ({admin}) ended after {}. The banner has been removed.",
            human_duration(duration_ms)
        ),
        severity: Severity::High,
        alert_id: None,
        file: None,
        action_taken: "Remote session ended".into(),
        review: None,
    }
}

// ------------------------------------------------------------ Core glue

impl LiveHost for crate::agent::Core {
    fn remote_fs(&self) -> Option<Arc<dyn RemoteFs>> {
        self.platform.remote_fs()
    }
    fn remote_desktop(&self) -> Option<Arc<dyn RemoteDesktop>> {
        self.platform.remote_desktop()
    }
    fn remote_ceiling(&self) -> RemoteAccessProfile {
        crate::agent::Core::remote_ceiling(self)
    }
    fn remote_policy(&self) -> RemoteAccessProfile {
        self.policy().remote_access
    }
    fn logged_on_user(&self) -> Option<String> {
        self.platform.logged_on_user()
    }
    fn console_session_id(&self) -> Option<u32> {
        self.platform.console_session_id()
    }
    fn local_weekday_minute(&self) -> Option<(u8, u16)> {
        self.platform.local_weekday_minute()
    }
    fn notify_activity(&self, item: ActivityItem) {
        self.notify_tray(item, true, None);
    }
    fn broadcast(&self, push: TrayPush) {
        self.broadcast_tray(push);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::remote::{AllowedHours, DesktopSettings, FileEntry, FileKind, InputEvent};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicU32;

    struct FakeHost {
        fs: Option<Arc<dyn RemoteFs>>,
        desk: Option<Arc<FakeDesktop>>,
        ceiling: Mutex<RemoteAccessProfile>,
        policy: Mutex<RemoteAccessProfile>,
        user: Mutex<Option<String>>,
        session: Option<u32>,
        time: Mutex<Option<(u8, u16)>>,
        activity: Mutex<Vec<ActivityItem>>,
        pushes: Mutex<Vec<TrayPush>>,
    }

    impl Default for FakeHost {
        fn default() -> Self {
            FakeHost {
                fs: None,
                desk: None,
                ceiling: Mutex::new(RemoteAccessProfile::unrestricted()),
                policy: Mutex::new(RemoteAccessProfile::unrestricted()),
                user: Mutex::new(Some("CORP\\j.doe".into())),
                session: Some(1),
                time: Mutex::new(Some((2, 600))),
                activity: Mutex::default(),
                pushes: Mutex::default(),
            }
        }
    }

    impl LiveHost for FakeHost {
        fn remote_fs(&self) -> Option<Arc<dyn RemoteFs>> {
            self.fs.clone()
        }
        fn remote_desktop(&self) -> Option<Arc<dyn RemoteDesktop>> {
            self.desk.clone().map(|d| d as Arc<dyn RemoteDesktop>)
        }
        fn remote_ceiling(&self) -> RemoteAccessProfile {
            lock(&self.ceiling).clone()
        }
        fn remote_policy(&self) -> RemoteAccessProfile {
            lock(&self.policy).clone()
        }
        fn logged_on_user(&self) -> Option<String> {
            lock(&self.user).clone()
        }
        fn console_session_id(&self) -> Option<u32> {
            self.session
        }
        fn local_weekday_minute(&self) -> Option<(u8, u16)> {
            *lock(&self.time)
        }
        fn notify_activity(&self, item: ActivityItem) {
            lock(&self.activity).push(item);
        }
        fn broadcast(&self, push: TrayPush) {
            lock(&self.pushes).push(push);
        }
    }

    /// Produces frames as fast as the sink accepts them.
    #[derive(Default)]
    struct FakeDesktop {
        starts: Arc<AtomicU32>,
        stops: Arc<AtomicU32>,
        view_only_at_start: Arc<Mutex<Option<bool>>>,
        inputs: Arc<Mutex<Vec<InputEvent>>>,
        settings: Arc<Mutex<Vec<DesktopSettings>>>,
        /// File notices given to the desktop session's banner.
        files_notices: Arc<Mutex<Vec<String>>>,
        /// `show_banner` fails while set.
        banner_fail: Arc<AtomicBool>,
        /// Stand-alone banners shown so far.
        banners: Arc<Mutex<Vec<Arc<FakeBanner>>>>,
        /// Ordered screen events: "banner.show", "banner.close",
        /// "desktop.stop".
        log: Arc<Mutex<Vec<String>>>,
    }

    impl FakeDesktop {
        fn banner_count(&self) -> usize {
            lock(&self.banners).len()
        }
        fn last_banner(&self) -> Arc<FakeBanner> {
            lock(&self.banners).last().cloned().expect("a banner")
        }
        /// Stand-alone banners on screen now.
        fn banners_on_screen(&self) -> usize {
            lock(&self.banners)
                .iter()
                .filter(|b| b.alive.load(Ordering::SeqCst))
                .count()
        }
        fn log(&self) -> Vec<String> {
            lock(&self.log).clone()
        }
    }

    struct FakeBanner {
        alive: AtomicBool,
        text: Mutex<String>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl SessionBanner for FakeBanner {
        fn set_text(&self, text: &str) {
            *lock(&self.text) = text.to_string();
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }
        fn close(&self) {
            if self.alive.swap(false, Ordering::SeqCst) {
                lock(&self.log).push("banner.close".into());
            }
        }
    }

    struct FakeSession {
        stop: Arc<AtomicBool>,
        stops: Arc<AtomicU32>,
        inputs: Arc<Mutex<Vec<InputEvent>>>,
        settings: Arc<Mutex<Vec<DesktopSettings>>>,
        files_notices: Arc<Mutex<Vec<String>>>,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl DesktopSession for FakeSession {
        fn input(&self, ev: &InputEvent) {
            lock(&self.inputs).push(ev.clone());
        }
        fn settings(&self, s: &DesktopSettings) {
            lock(&self.settings).push(s.clone());
        }
        fn stop(&self) {
            if !self.stop.swap(true, Ordering::SeqCst) {
                lock(&self.log).push("desktop.stop".into());
            }
            self.stops.fetch_add(1, Ordering::SeqCst);
        }
        fn set_files_notice(&self, text: &str) {
            lock(&self.files_notices).push(text.to_string());
        }
    }

    impl RemoteDesktop for FakeDesktop {
        fn start(
            &self,
            params: DesktopStartParams,
            sink: kestrel_platform::DesktopSink,
        ) -> Result<Box<dyn DesktopSession>, (RemoteErrorCode, String)> {
            self.starts.fetch_add(1, Ordering::SeqCst);
            *lock(&self.view_only_at_start) = Some(params.view_only);
            let stop = Arc::new(AtomicBool::new(false));
            let st = stop.clone();
            std::thread::spawn(move || {
                let _ = sink.blocking_send(DesktopEvent::Info(DesktopInfo {
                    width: 64,
                    height: 32,
                    monitors: 1,
                    view_only: params.view_only,
                    ..Default::default()
                }));
                while !st.load(Ordering::SeqCst) {
                    let ev = DesktopEvent::Frame {
                        width: 64,
                        height: 32,
                        ts: kestrel_common::now_ms(),
                        jpeg: vec![0xff, 0xd8, 0xff, 0xd9],
                    };
                    match sink.try_send(ev) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Err(_) => break,
                    }
                }
            });
            Ok(Box::new(FakeSession {
                stop,
                stops: self.stops.clone(),
                inputs: self.inputs.clone(),
                settings: self.settings.clone(),
                files_notices: self.files_notices.clone(),
                log: self.log.clone(),
            }))
        }

        fn show_banner(
            &self,
            text: &str,
        ) -> Result<Box<dyn SessionBanner>, (RemoteErrorCode, String)> {
            if self.banner_fail.load(Ordering::SeqCst) {
                return Err((
                    RemoteErrorCode::Unavailable,
                    "the banner window did not appear".into(),
                ));
            }
            let b = Arc::new(FakeBanner {
                alive: AtomicBool::new(true),
                text: Mutex::new(text.to_string()),
                log: self.log.clone(),
            });
            lock(&self.banners).push(b.clone());
            lock(&self.log).push("banner.show".into());
            Ok(Box::new(SharedBanner(b)))
        }
    }

    /// Box adapter so the test keeps a handle on the banner.
    struct SharedBanner(Arc<FakeBanner>);

    impl SessionBanner for SharedBanner {
        fn set_text(&self, text: &str) {
            self.0.set_text(text)
        }
        fn is_alive(&self) -> bool {
            self.0.is_alive()
        }
        fn close(&self) {
            self.0.close()
        }
    }

    struct TmpFs(PathBuf);
    impl RemoteFs for TmpFs {
        fn local_path(&self, win_path: &str) -> PathBuf {
            let mut p = self.0.clone();
            for part in win_path.split('\\').filter(|s| !s.is_empty()) {
                p.push(part.replace(':', ""));
            }
            p
        }
        fn drives(&self) -> Vec<FileEntry> {
            vec![FileEntry {
                name: "C:".into(),
                path: "C:\\".into(),
                kind: FileKind::Drive,
                ..Default::default()
            }]
        }
        fn protected_roots(&self) -> Vec<PathBuf> {
            vec![]
        }
    }

    struct Rig {
        mgr: LiveManager,
        host: Arc<FakeHost>,
        rx: mpsc::Receiver<AgentEnvelope>,
        gen: u64,
        desk: Arc<FakeDesktop>,
        dir: tempfile::TempDir,
    }

    fn rig_with(cfg: LiveConfig, ceiling: RemoteAccessProfile, policy: RemoteAccessProfile) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("C/data")).unwrap();
        let desk = Arc::new(FakeDesktop::default());
        let host = Arc::new(FakeHost {
            fs: Some(Arc::new(TmpFs(dir.path().to_path_buf()))),
            desk: Some(desk.clone()),
            ceiling: Mutex::new(ceiling),
            policy: Mutex::new(policy),
            ..Default::default()
        });
        let mgr = LiveManager::new(cfg);
        mgr.bind(Arc::downgrade(&(host.clone() as Arc<dyn LiveHost>)));
        let (tx, rx) = mpsc::channel(64);
        let gen = mgr.attach(tx);
        Rig {
            mgr,
            host,
            rx,
            gen,
            desk,
            dir,
        }
    }

    fn rig(cfg: LiveConfig) -> Rig {
        rig_with(
            cfg,
            RemoteAccessProfile::unrestricted(),
            RemoteAccessProfile::unrestricted(),
        )
    }

    fn decode(env: &AgentEnvelope) -> (Uuid, LiveAgentMsg) {
        assert_eq!(env.seq, 0, "live messages are ephemeral");
        match codec::decode::<AgentPayload>(&env.payload, env.compressed).unwrap() {
            AgentPayload::Live { session_id, msg } => (session_id, msg),
            other => panic!("not live: {other:?}"),
        }
    }

    async fn next(rx: &mut mpsc::Receiver<AgentEnvelope>) -> (Uuid, LiveAgentMsg) {
        let env = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timed out waiting for a live message")
            .expect("channel closed");
        decode(&env)
    }

    /// Messages arriving within `ms`.
    async fn drain(rx: &mut mpsc::Receiver<AgentEnvelope>, ms: u64) -> Vec<LiveAgentMsg> {
        let mut out = vec![];
        let deadline = tokio::time::Instant::now() + Duration::from_millis(ms);
        while let Ok(Some(env)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            out.push(decode(&env).1);
        }
        out
    }

    fn start_with(view_only: bool, reason: &str) -> LiveServerMsg {
        LiveServerMsg::DesktopStart(DesktopStart {
            view_only,
            admin_name: "Jane Doe".into(),
            reason: reason.into(),
            settings: DesktopSettings::default(),
        })
    }

    fn start_msg(view_only: bool) -> LiveServerMsg {
        start_with(view_only, "ticket 42")
    }

    fn file_req(request_id: u64, op: FileOp, fm: Option<Uuid>) -> LiveServerMsg {
        LiveServerMsg::FileRequest {
            request_id,
            op,
            context: fm.map(|fm_session| FileContext {
                fm_session,
                admin_name: "Jane Doe".into(),
                reason: "ticket 42".into(),
            }),
        }
    }

    fn list(path: &str) -> FileOp {
        FileOp::List { path: path.into() }
    }

    fn mkdir(path: &str) -> FileOp {
        FileOp::Mkdir { path: path.into() }
    }

    fn frames(msgs: &[LiveAgentMsg]) -> Vec<u64> {
        msgs.iter()
            .filter_map(|m| match m {
                LiveAgentMsg::DesktopFrame(f) => Some(f.seq),
                _ => None,
            })
            .collect()
    }

    fn ended_code(m: &LiveAgentMsg) -> Option<Option<RemoteErrorCode>> {
        match m {
            LiveAgentMsg::DesktopEnded { code, .. } => Some(*code),
            _ => None,
        }
    }

    fn reply_code(m: &LiveAgentMsg) -> Option<RemoteErrorCode> {
        match m {
            LiveAgentMsg::FileReply {
                reply: FileReply::Error { code, .. },
                ..
            } => Some(*code),
            _ => None,
        }
    }

    fn is_ok_reply(m: &LiveAgentMsg) -> bool {
        matches!(m, LiveAgentMsg::FileReply { .. }) && reply_code(m).is_none()
    }

    fn console_client() -> TrayClient {
        TrayClient {
            user: Some("CORP\\j.doe".into()),
            session_id: Some(1),
            ..Default::default()
        }
    }

    /// Wait for a pending consent prompt and answer it.
    async fn answer(mgr: &LiveManager, allow: bool) {
        for _ in 0..200 {
            if let Some(id) = mgr.pending_consents().first().copied() {
                let r = mgr.consent_response(id, allow, &console_client());
                assert!(matches!(r, TrayResponse::Ack { ok: true, .. }), "{r:?}");
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no consent prompt");
    }

    /// The next message is a `ConsentResult` (denial `code`, or allowed).
    async fn expect_result(rx: &mut mpsc::Receiver<AgentEnvelope>, code: Option<RemoteErrorCode>) {
        match next(rx).await.1 {
            LiveAgentMsg::ConsentResult {
                allowed, code: c, ..
            } => {
                assert_eq!(allowed, code.is_none());
                assert_eq!(c, code);
            }
            other => panic!("expected ConsentResult, got {other:?}"),
        }
    }

    fn guarded(timeout_secs: u32) -> RemoteAccessProfile {
        let mut p = RemoteAccessProfile::unrestricted();
        p.guardrails.require_consent = true;
        p.guardrails.consent_timeout_secs = timeout_secs;
        p
    }

    #[tokio::test]
    async fn ceiling_vs_policy_refusals() {
        // Ceiling none: NotPermitted naming the install profile.
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::none(),
            RemoteAccessProfile::unrestricted(),
        );
        let s = Uuid::new_v4();
        r.mgr.handle(s, file_req(9, list(""), None));
        let (sid, m) = next(&mut r.rx).await;
        assert_eq!(sid, s);
        assert_eq!(reply_code(&m), Some(RemoteErrorCode::NotPermitted));
        r.mgr.handle(s, start_msg(false));
        match next(&mut r.rx).await.1 {
            LiveAgentMsg::DesktopEnded { code, reason } => {
                assert_eq!(code, Some(RemoteErrorCode::NotPermitted));
                assert!(reason.contains("install profile"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        // Policy off (ceiling allows): DisabledByPolicy.
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            RemoteAccessProfile::none(),
        );
        r.mgr.handle(s, file_req(1, list(""), None));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::DisabledByPolicy)
        );
        r.mgr.handle(s, start_msg(false));
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::DisabledByPolicy))
        );
        assert!(!r.mgr.desktop_active());
        assert_eq!(r.desk.starts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_only_no_delete_and_blocked_paths() {
        let mut ro = RemoteAccessProfile::unrestricted();
        ro.files = FileMode::ReadOnly;
        let mut r = rig_with(
            LiveConfig::default(),
            ro,
            RemoteAccessProfile::unrestricted(),
        );
        let s = Uuid::new_v4();
        r.mgr.handle(s, file_req(1, list("C:\\data"), None));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::FileReply {
                reply: FileReply::List { .. },
                ..
            }
        ));
        r.mgr.handle(s, file_req(2, mkdir("C:\\data\\x"), None));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::NotPermitted)
        );
        assert!(!r.dir.path().join("C/data/x").exists());

        // Policy: full but no delete; blocked path.
        let mut pol = RemoteAccessProfile::unrestricted();
        pol.guardrails.allow_delete = false;
        pol.guardrails.blocked_paths = vec!["C:\\data\\secret".into()];
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            pol,
        );
        std::fs::create_dir_all(r.dir.path().join("C/data/secret")).unwrap();
        std::fs::write(r.dir.path().join("C/data/f.txt"), b"x").unwrap();
        r.mgr.handle(
            s,
            file_req(
                3,
                FileOp::Delete {
                    path: "C:\\data\\f.txt".into(),
                    recursive: false,
                },
                None,
            ),
        );
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::DisabledByPolicy)
        );
        r.mgr.handle(
            s,
            file_req(
                4,
                FileOp::Rename {
                    from: "C:\\data\\f.txt".into(),
                    to: "C:\\data\\g.txt".into(),
                    overwrite: false,
                },
                None,
            ),
        );
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::DisabledByPolicy)
        );
        assert!(r.dir.path().join("C/data/f.txt").exists());
        r.mgr.handle(s, file_req(5, list("C:\\data\\secret"), None));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::BlockedPath)
        );
        // Mkdir (write class) is still allowed.
        r.mgr.handle(s, file_req(6, mkdir("C:\\data\\n"), None));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::FileReply {
                reply: FileReply::Done { count: 1 },
                ..
            }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn hours_and_reason_guardrails() {
        let mut pol = RemoteAccessProfile::unrestricted();
        pol.guardrails.allowed_hours = Some(AllowedHours {
            days: vec![0, 1, 2, 3, 4],
            start_minute: 9 * 60,
            end_minute: 17 * 60,
        });
        pol.guardrails.require_reason = true;
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            pol,
        );
        let s = Uuid::new_v4();
        // Saturday: outside.
        *lock(&r.host.time) = Some((5, 600));
        r.mgr.handle(s, file_req(1, list(""), Some(s)));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::OutsideAllowedHours)
        );
        r.mgr.handle(s, start_msg(false));
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::OutsideAllowedHours))
        );
        // Unknown local time fails closed.
        *lock(&r.host.time) = None;
        r.mgr.handle(s, file_req(2, list(""), Some(s)));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::OutsideAllowedHours)
        );
        // Wednesday 10:00: inside, but no reason.
        *lock(&r.host.time) = Some((2, 600));
        r.mgr.handle(s, file_req(3, list(""), None));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::ReasonRequired)
        );
        r.mgr.handle(s, start_with(false, "   "));
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::ReasonRequired))
        );
        // With a reason: fine, and the employee is told about file access once.
        r.mgr.handle(s, file_req(4, list(""), Some(s)));
        r.mgr.handle(s, file_req(5, list(""), Some(s)));
        for _ in 0..2 {
            assert!(is_ok_reply(&next(&mut r.rx).await.1));
        }
        let titles: Vec<String> = lock(&r.host.activity)
            .iter()
            .map(|a| a.title.clone())
            .collect();
        assert_eq!(titles, ["IT (Jane Doe) is accessing files on this PC"]);
        let n = r.mgr.remote_session_notice().unwrap();
        assert_eq!(n.kind, RemoteKind::Files);
        assert!(n.active);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn view_only_profile_forces_view_only() {
        let mut vo = RemoteAccessProfile::unrestricted();
        vo.desktop = DesktopMode::ViewOnly;
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            vo,
        );
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(false));
        match next(&mut r.rx).await.1 {
            LiveAgentMsg::DesktopStarted(i) => assert!(i.view_only),
            other => panic!("{other:?}"),
        }
        assert_eq!(*lock(&r.desk.view_only_at_start), Some(true));
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopSettings(DesktopSettings {
                view_only: Some(false),
                ..Default::default()
            }),
        );
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopInput {
                event: InputEvent::MouseMove { x: 0.5, y: 0.5 },
            },
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(lock(&r.desk.inputs).is_empty());
        assert_eq!(lock(&r.desk.settings)[0].view_only, None, "switch refused");
        assert!(r.mgr.remote_session_notice().unwrap().view_only);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn desktop_consent_allow_deny_timeout_and_no_user() {
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            guarded(1),
        );
        let a = Uuid::new_v4();
        // Allow.
        r.mgr.handle(a, start_msg(true));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::ConsentPending {
                request_id: None,
                timeout_secs: 1
            }
        ));
        assert_eq!(
            r.desk.starts.load(Ordering::SeqCst),
            0,
            "nothing before consent"
        );
        // The prompt went only to the console session's tray.
        let p = lock(&r.host.pushes)
            .iter()
            .find(|p| matches!(p.resp, TrayResponse::ConsentRequest(_)))
            .cloned()
            .unwrap();
        assert_eq!(p.audience, Audience::Session(1));
        // Someone in another session (or unidentified) cannot answer.
        let id = r.mgr.pending_consents()[0];
        let other = TrayClient {
            user: Some("CORP\\eve".into()),
            session_id: Some(2),
            ..Default::default()
        };
        assert!(matches!(
            r.mgr.consent_response(id, true, &other),
            TrayResponse::Error { .. }
        ));
        let anon = TrayClient {
            session_id: Some(1),
            ..Default::default()
        };
        assert!(matches!(
            r.mgr.consent_response(id, true, &anon),
            TrayResponse::Error { .. }
        ));
        answer(&r.mgr, true).await;
        expect_result(&mut r.rx, None).await;
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::DesktopStarted(_)
        ));
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopStop {
                reason: String::new(),
            },
        );
        let got = drain(&mut r.rx, 300).await;
        assert!(got.iter().any(|m| ended_code(m) == Some(None)));
        // Deny.
        let b = Uuid::new_v4();
        r.mgr.handle(b, start_msg(true));
        next(&mut r.rx).await;
        answer(&r.mgr, false).await;
        expect_result(&mut r.rx, Some(RemoteErrorCode::ConsentDenied)).await;
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::ConsentDenied))
        );
        // Timeout (1 s).
        let c = Uuid::new_v4();
        r.mgr.handle(c, start_msg(true));
        next(&mut r.rx).await;
        expect_result(&mut r.rx, Some(RemoteErrorCode::ConsentTimeout)).await;
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::ConsentTimeout))
        );
        assert!(r.mgr.pending_consents().is_empty());
        // No one signed in: denied at once.
        *lock(&r.host.user) = None;
        let d = Uuid::new_v4();
        r.mgr.handle(d, start_msg(true));
        assert_eq!(
            ended_code(&next(&mut r.rx).await.1),
            Some(Some(RemoteErrorCode::ConsentDenied))
        );
        assert_eq!(r.desk.starts.load(Ordering::SeqCst), 1);
        assert!(!r.mgr.desktop_active());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_consent_once_per_fm_session_never_for_reads() {
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            guarded(5),
        );
        let fm = Uuid::new_v4();
        // Reads: no consent.
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        // First write asks.
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, mkdir("C:\\data\\a"), Some(fm)));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::ConsentPending {
                request_id: Some(2),
                ..
            }
        ));
        answer(&r.mgr, true).await;
        expect_result(&mut r.rx, None).await;
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        // Later writes of the same fm session do not ask again.
        r.mgr
            .handle(Uuid::new_v4(), file_req(3, mkdir("C:\\data\\b"), Some(fm)));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::FileReply {
                request_id: 3,
                reply: FileReply::Done { count: 1 }
            }
        ));
        // Another fm session asks again; deny.
        let fm2 = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(4, mkdir("C:\\data\\c"), Some(fm2)));
        next(&mut r.rx).await;
        answer(&r.mgr, false).await;
        expect_result(&mut r.rx, Some(RemoteErrorCode::ConsentDenied)).await;
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::ConsentDenied)
        );
        assert!(!r.dir.path().join("C/data/c").exists());
        // A policy change drops the grant.
        let mut p = guarded(5);
        p.guardrails.allow_delete = false;
        r.mgr.policy_changed(&p);
        *lock(&r.host.policy) = p;
        r.mgr
            .handle(Uuid::new_v4(), file_req(5, mkdir("C:\\data\\d"), Some(fm)));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::ConsentPending {
                request_id: Some(5),
                ..
            }
        ));
        answer(&r.mgr, true).await;
        expect_result(&mut r.rx, None).await;
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn desktop_credit_flow_busy_and_stop() {
        let mut r = rig(LiveConfig::default());
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(false));
        let (sid, m) = next(&mut r.rx).await;
        assert_eq!(sid, a);
        match m {
            LiveAgentMsg::DesktopStarted(i) => assert_eq!((i.width, i.height), (64, 32)),
            other => panic!("{other:?}"),
        }
        // Without acks the agent stops at DESKTOP_MAX_INFLIGHT frames.
        let got = drain(&mut r.rx, 300).await;
        assert_eq!(frames(&got), [1, 2, 3]);
        // Second session is refused, the first keeps running.
        let b = Uuid::new_v4();
        r.mgr.handle(b, start_msg(true));
        let (sid, m) = next(&mut r.rx).await;
        assert_eq!(sid, b);
        assert_eq!(ended_code(&m), Some(Some(RemoteErrorCode::Busy)));
        // Cumulative ack of 2 → exactly two more frames.
        r.mgr.handle(a, LiveServerMsg::DesktopAck { seq: 2 });
        let got = drain(&mut r.rx, 300).await;
        assert_eq!(frames(&got), [4, 5]);
        // A bogus ack beyond what was sent does not grant extra credit.
        r.mgr.handle(a, LiveServerMsg::DesktopAck { seq: 1000 });
        let got = drain(&mut r.rx, 300).await;
        assert_eq!(frames(&got), [6, 7, 8]);
        // Employee told.
        let n = r.mgr.remote_session_notice().unwrap();
        assert!(n.active && !n.view_only && n.admin_name == "Jane Doe");
        assert_eq!(n.kind, RemoteKind::Desktop);
        assert!(lock(&r.host.activity)[0]
            .title
            .contains("IT (Jane Doe) is controlling this PC"));
        // Stop.
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopStop {
                reason: String::new(),
            },
        );
        let got = drain(&mut r.rx, 300).await;
        assert!(got.iter().any(|m| ended_code(m) == Some(None)));
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 1);
        assert!(!r.mgr.desktop_active());
        assert!(r.mgr.remote_session_notice().is_none());
        let pushes = lock(&r.host.pushes).clone();
        assert!(matches!(
            pushes.last().map(|p| &p.resp),
            Some(TrayResponse::RemoteSession(RemoteSessionNotice {
                active: false,
                ..
            }))
        ));
        assert_eq!(
            lock(&r.host.activity)[1].title,
            "IT ended the remote session"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn view_only_drops_input_and_mode_switch() {
        let mut r = rig(LiveConfig::default());
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(true));
        next(&mut r.rx).await;
        let mv = InputEvent::MouseMove { x: 0.5, y: 2.0 };
        r.mgr
            .handle(a, LiveServerMsg::DesktopInput { event: mv.clone() });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(lock(&r.desk.inputs).is_empty(), "view-only drops input");
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopSettings(DesktopSettings {
                quality: 200,
                view_only: Some(false),
                ..Default::default()
            }),
        );
        r.mgr.handle(a, LiveServerMsg::DesktopInput { event: mv });
        r.mgr.handle(
            a,
            LiveServerMsg::DesktopInput {
                event: InputEvent::MouseMove {
                    x: f32::NAN,
                    y: 0.0,
                },
            },
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Sanitised (clamped), the NaN one dropped.
        assert_eq!(
            *lock(&r.desk.inputs),
            [InputEvent::MouseMove { x: 0.5, y: 1.0 }]
        );
        assert_eq!(lock(&r.desk.settings)[0].quality, 90, "clamped");
        assert!(!r.mgr.remote_session_notice().unwrap().view_only);
        let modes: Vec<bool> = lock(&r.host.pushes)
            .iter()
            .filter_map(|p| match &p.resp {
                TrayResponse::RemoteSession(n) if n.active => Some(n.view_only),
                _ => None,
            })
            .collect();
        assert_eq!(modes, [true, false]);
        assert!(lock(&r.host.pushes)
            .iter()
            .all(|p| p.audience == Audience::Public));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detach_policy_change_and_shutdown_stop_the_session() {
        let mut r = rig(LiveConfig::default());
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(false));
        next(&mut r.rx).await;
        r.mgr.detach(r.gen);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 1);
        assert!(!r.mgr.desktop_active());
        assert!(r.mgr.remote_session_notice().is_none());

        // Policy downgrade to view-only forces view-only; then off ends it.
        let (tx, mut rx) = mpsc::channel(64);
        r.mgr.attach(tx);
        let b = Uuid::new_v4();
        r.mgr.handle(b, start_msg(false));
        next(&mut rx).await;
        let mut vo = RemoteAccessProfile::unrestricted();
        vo.desktop = DesktopMode::ViewOnly;
        r.mgr.policy_changed(&vo);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(r.mgr.remote_session_notice().unwrap().view_only);
        r.mgr.handle(
            b,
            LiveServerMsg::DesktopInput {
                event: InputEvent::ReleaseAll,
            },
        );
        r.mgr.policy_changed(&RemoteAccessProfile::none());
        let got = drain(&mut rx, 300).await;
        assert!(got
            .iter()
            .any(|m| ended_code(m) == Some(Some(RemoteErrorCode::DisabledByPolicy))));
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 2);
        assert!(lock(&r.desk.inputs).is_empty());

        // Shutdown stops synchronously, exactly once.
        r.mgr.policy_changed(&RemoteAccessProfile::unrestricted());
        let c = Uuid::new_v4();
        r.mgr.handle(c, start_msg(false));
        next(&mut rx).await;
        r.mgr.shutdown();
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 3);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 3, "stop exactly once");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn server_silence_ends_the_session() {
        let mut r = rig(LiveConfig {
            desktop_silence: Duration::from_millis(200),
            tick: Duration::from_millis(20),
            ..LiveConfig::default()
        });
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(false));
        let got = drain(&mut r.rx, 600).await;
        assert!(got
            .iter()
            .any(|m| ended_code(m) == Some(Some(RemoteErrorCode::Timeout))));
        assert_eq!(r.desk.stops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_requests_are_serial_per_session_and_capped() {
        let mut r = rig(LiveConfig {
            max_file_sessions: 2,
            fm_idle: Duration::from_millis(100),
            fm_sweep: Duration::from_millis(50),
            ..LiveConfig::default()
        });
        let s = Uuid::new_v4();
        for i in 0..20u64 {
            r.mgr
                .handle(s, file_req(i, mkdir(&format!("C:\\data\\d{i}")), None));
        }
        let mut ids = vec![];
        for _ in 0..20 {
            match next(&mut r.rx).await.1 {
                LiveAgentMsg::FileReply { request_id, reply } => {
                    assert_eq!(reply, FileReply::Done { count: 1 });
                    ids.push(request_id);
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(ids, (0..20).collect::<Vec<_>>(), "in order");
        // The idle file-manager session is shown as ended.
        tokio::time::sleep(Duration::from_millis(400)).await;
        assert!(r.mgr.remote_session_notice().is_none());
        assert!(matches!(
            lock(&r.host.pushes).last().map(|p| &p.resp),
            Some(TrayResponse::RemoteSession(RemoteSessionNotice {
                active: false,
                kind: RemoteKind::Files,
                ..
            }))
        ));
        // Open uploads keep two workers busy; a third session is refused.
        for _ in 0..2 {
            r.mgr.handle(
                Uuid::new_v4(),
                file_req(
                    1,
                    FileOp::WriteBegin {
                        path: format!("C:\\data\\u{}", Uuid::new_v4().simple()),
                        size: 10,
                    },
                    None,
                ),
            );
        }
        for _ in 0..2 {
            assert!(matches!(
                next(&mut r.rx).await.1,
                LiveAgentMsg::FileReply {
                    reply: FileReply::Done { count: 0 },
                    ..
                }
            ));
        }
        assert_eq!(r.mgr.file_sessions(), 2);
        r.mgr.handle(Uuid::new_v4(), file_req(7, list(""), None));
        let m = next(&mut r.rx).await.1;
        assert!(matches!(m, LiveAgentMsg::FileReply { request_id: 7, .. }));
        assert_eq!(reply_code(&m), Some(RemoteErrorCode::Busy));
        // Detach aborts the uploads (temp files removed).
        r.mgr.detach(r.gen);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(r.mgr.file_sessions(), 0);
        let leftovers = std::fs::read_dir(r.dir.path().join("C/data"))
            .unwrap()
            .filter(|e| {
                e.as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains("kestrel-upload")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[tokio::test]
    async fn unsupported_platform_is_unavailable() {
        let host = Arc::new(FakeHost::default());
        let mgr = LiveManager::default();
        mgr.bind(Arc::downgrade(&(host.clone() as Arc<dyn LiveHost>)));
        let (tx, mut rx) = mpsc::channel(8);
        mgr.attach(tx);
        let s = Uuid::new_v4();
        mgr.handle(
            s,
            file_req(
                1,
                FileOp::Stat {
                    path: "C:\\x".into(),
                },
                None,
            ),
        );
        mgr.handle(s, start_msg(true));
        let mut codes = vec![];
        for _ in 0..2 {
            let m = next(&mut rx).await.1;
            codes.push(reply_code(&m).or(ended_code(&m).flatten()).unwrap());
        }
        assert_eq!(codes, [RemoteErrorCode::Unavailable; 2]);
    }

    #[tokio::test]
    async fn oversize_messages_are_dropped() {
        let mut r = rig(LiveConfig::default());
        let big = "x".repeat(LIVE_MAX_MESSAGE + 1);
        let s = r
            .mgr
            .inner
            .send(
                Uuid::new_v4(),
                LiveAgentMsg::DesktopEnded {
                    reason: big,
                    code: None,
                },
            )
            .await;
        assert_eq!(s, Sent::Dropped);
        assert!(drain(&mut r.rx, 50).await.is_empty());
    }

    #[test]
    fn grants_expire() {
        let now = Instant::now();
        let g = Grant {
            granted: now,
            last: now,
        };
        let mut p = RemoteAccessProfile::guarded_default();
        p.guardrails.max_session_minutes = 60;
        p.guardrails.idle_timeout_minutes = 15;
        assert!(grant_valid(&g, &p, now + Duration::from_secs(14 * 60)));
        assert!(!grant_valid(&g, &p, now + Duration::from_secs(15 * 60)));
        let g2 = Grant {
            granted: now,
            last: now + Duration::from_secs(50 * 60),
        };
        assert!(!grant_valid(&g2, &p, now + Duration::from_secs(61 * 60)));
        p.guardrails.max_session_minutes = 0;
        p.guardrails.idle_timeout_minutes = 0;
        assert!(grant_valid(&g, &p, now + Duration::from_secs(7 * 3600)));
        assert!(!grant_valid(&g, &p, now + Duration::from_secs(8 * 3600)));
    }

    // ------------------------------------------- security review regressions

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn switch_to_control_asks_again() {
        // H2: view-only start, then the admin asks for control.
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            guarded(2),
        );
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(true));
        next(&mut r.rx).await; // pending
        answer(&r.mgr, true).await;
        expect_result(&mut r.rx, None).await;
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::DesktopStarted(_)
        ));
        let to_control = || {
            LiveServerMsg::DesktopSettings(DesktopSettings {
                view_only: Some(false),
                ..Default::default()
            })
        };
        let mv = || LiveServerMsg::DesktopInput {
            event: InputEvent::MouseMove { x: 0.5, y: 0.5 },
        };
        // Deny: stays view-only, input still dropped.
        r.mgr.handle(a, to_control());
        let got = wait_msgs(&mut r.rx, |m| {
            matches!(
                m,
                LiveAgentMsg::ConsentPending {
                    request_id: None,
                    ..
                }
            )
        })
        .await;
        assert!(!got.is_empty());
        r.mgr.handle(a, mv());
        answer(&r.mgr, false).await;
        wait_msgs(&mut r.rx, |m| {
            matches!(m, LiveAgentMsg::ConsentResult { allowed: false, .. })
        })
        .await;
        r.mgr.handle(a, mv());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            lock(&r.desk.inputs).is_empty(),
            "input dropped until approved"
        );
        assert!(r.mgr.remote_session_notice().unwrap().view_only);
        // Timeout: stays view-only.
        r.mgr.handle(a, to_control());
        wait_msgs(&mut r.rx, |m| {
            matches!(
                m,
                LiveAgentMsg::ConsentResult {
                    code: Some(RemoteErrorCode::ConsentTimeout),
                    ..
                }
            )
        })
        .await;
        assert!(r.mgr.remote_session_notice().unwrap().view_only);
        // Allow: control, banner/tray updated, input flows.
        r.mgr.handle(a, to_control());
        wait_msgs(&mut r.rx, |m| {
            matches!(m, LiveAgentMsg::ConsentPending { .. })
        })
        .await;
        let prompt = lock(&r.host.pushes)
            .iter()
            .rev()
            .find_map(|p| match &p.resp {
                TrayResponse::ConsentRequest(c) => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        assert!(!prompt.view_only, "the prompt asks for control");
        answer(&r.mgr, true).await;
        wait_msgs(&mut r.rx, |m| {
            matches!(m, LiveAgentMsg::ConsentResult { allowed: true, .. })
        })
        .await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!r.mgr.remote_session_notice().unwrap().view_only);
        assert_eq!(
            lock(&r.desk.settings).last().unwrap().view_only,
            Some(false),
            "the platform banner switches to control"
        );
        r.mgr.handle(a, mv());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(lock(&r.desk.inputs).len(), 1);
    }

    /// Messages until one matches (returns everything read).
    async fn wait_msgs<F: Fn(&LiveAgentMsg) -> bool>(
        rx: &mut mpsc::Receiver<AgentEnvelope>,
        f: F,
    ) -> Vec<LiveAgentMsg> {
        let mut out = vec![];
        loop {
            let m = next(rx).await.1;
            let hit = f(&m);
            out.push(m);
            if hit {
                return out;
            }
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_approval_while_in_control() {
        // M2: a file consent prompt during a control session cannot be
        // approved (the admin could click it).
        let mut pol = guarded(5);
        pol.guardrails.require_consent = true;
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            pol,
        );
        let a = Uuid::new_v4();
        r.mgr.handle(a, start_msg(false));
        next(&mut r.rx).await;
        answer(&r.mgr, true).await; // desktop consent (not in control yet)
        expect_result(&mut r.rx, None).await;
        wait_msgs(&mut r.rx, |m| matches!(m, LiveAgentMsg::DesktopStarted(_))).await;
        let fm = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, mkdir("C:\\data\\x"), Some(fm)));
        wait_msgs(&mut r.rx, |m| {
            matches!(
                m,
                LiveAgentMsg::ConsentPending {
                    request_id: Some(1),
                    ..
                }
            )
        })
        .await;
        let id = loop {
            if let Some(id) = r.mgr.pending_consents().first().copied() {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        match r.mgr.consent_response(id, true, &console_client()) {
            TrayResponse::Error { message } => {
                assert!(message.contains("controlling"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        let got = wait_msgs(&mut r.rx, |m| {
            matches!(m, LiveAgentMsg::FileReply { request_id: 1, .. })
        })
        .await;
        assert_eq!(
            reply_code(got.last().unwrap()),
            Some(RemoteErrorCode::ConsentDenied)
        );
        assert!(!r.dir.path().join("C/data/x").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_consent_is_per_admin() {
        // M1: another admin reusing the fm session is asked again and named.
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            guarded(5),
        );
        let fm = Uuid::new_v4();
        let req = |id, admin: &str, path: &str| LiveServerMsg::FileRequest {
            request_id: id,
            op: mkdir(path),
            context: Some(FileContext {
                fm_session: fm,
                admin_name: admin.into(),
                reason: "r".into(),
            }),
        };
        r.mgr.handle(Uuid::new_v4(), req(1, "Jane", "C:\\data\\a"));
        next(&mut r.rx).await;
        answer(&r.mgr, true).await;
        expect_result(&mut r.rx, None).await;
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        r.mgr
            .handle(Uuid::new_v4(), req(2, "Mallory", "C:\\data\\b"));
        assert!(matches!(
            next(&mut r.rx).await.1,
            LiveAgentMsg::ConsentPending {
                request_id: Some(2),
                ..
            }
        ));
        let prompt = lock(&r.host.pushes)
            .iter()
            .rev()
            .find_map(|p| match &p.resp {
                TrayResponse::ConsentRequest(c) => Some(c.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(prompt.admin_name, "Mallory");
        answer(&r.mgr, false).await;
        expect_result(&mut r.rx, Some(RemoteErrorCode::ConsentDenied)).await;
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::ConsentDenied)
        );
        let titles: Vec<String> = lock(&r.host.activity)
            .iter()
            .map(|a| a.title.clone())
            .collect();
        assert!(
            titles.iter().any(|t| t.contains("IT (Mallory)")),
            "{titles:?}"
        );
    }

    #[tokio::test]
    async fn no_console_session_means_no_prompt() {
        // L6.
        let dir = tempfile::tempdir().unwrap();
        let desk = Arc::new(FakeDesktop::default());
        let host = Arc::new(FakeHost {
            desk: Some(desk.clone()),
            policy: Mutex::new(guarded(5)),
            session: None,
            ..Default::default()
        });
        let mgr = LiveManager::default();
        mgr.bind(Arc::downgrade(&(host.clone() as Arc<dyn LiveHost>)));
        let (tx, mut rx) = mpsc::channel(8);
        mgr.attach(tx);
        mgr.handle(Uuid::new_v4(), start_msg(true));
        match next(&mut rx).await.1 {
            LiveAgentMsg::DesktopEnded { code, reason } => {
                assert_eq!(code, Some(RemoteErrorCode::ConsentDenied));
                assert!(reason.contains("console session"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
        assert!(lock(&host.pushes).is_empty(), "no prompt to anyone");
        assert_eq!(desk.starts.load(Ordering::SeqCst), 0);
        drop(dir);
    }

    #[tokio::test]
    async fn overwrite_needs_delete_permission() {
        // L3: upload allowed, delete not → new files fine, overwrite refused.
        let mut pol = RemoteAccessProfile::unrestricted();
        pol.guardrails.allow_delete = false;
        let mut r = rig_with(
            LiveConfig::default(),
            RemoteAccessProfile::unrestricted(),
            pol,
        );
        std::fs::write(r.dir.path().join("C/data/old.txt"), b"keep").unwrap();
        let s = Uuid::new_v4();
        r.mgr.handle(
            s,
            file_req(
                1,
                FileOp::WriteBegin {
                    path: "C:\\data\\old.txt".into(),
                    size: 1,
                },
                None,
            ),
        );
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::DisabledByPolicy)
        );
        r.mgr.handle(
            s,
            file_req(
                2,
                FileOp::WriteBegin {
                    path: "C:\\data\\new.txt".into(),
                    size: 1,
                },
                None,
            ),
        );
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        // The ceiling forbidding delete → NotPermitted.
        let mut ceil = RemoteAccessProfile::unrestricted();
        ceil.guardrails.allow_delete = false;
        let mut r = rig_with(
            LiveConfig::default(),
            ceil,
            RemoteAccessProfile::unrestricted(),
        );
        std::fs::write(r.dir.path().join("C/data/old.txt"), b"keep").unwrap();
        r.mgr.handle(
            s,
            file_req(
                3,
                FileOp::WriteBegin {
                    path: "C:\\data\\old.txt".into(),
                    size: 1,
                },
                None,
            ),
        );
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::NotPermitted)
        );
    }

    #[test]
    fn bidi_and_format_chars_are_stripped() {
        // L5.
        let evil = "Jane\u{202E}eoD\u{202C} \u{2066}x\u{2069}\u{200F}\u{061C}\u{FEFF}\r\nok";
        let c = clean_text(evil, 100);
        assert_eq!(c, "JaneeoD x  ok");
        assert!(c.chars().all(|ch| !is_format_char(ch) && !ch.is_control()));
        let item = start_item(&clean_text("A\u{202E}B", 100), false, "");
        assert_eq!(item.title, "IT (AB) is controlling this PC");
    }

    // ------------------------------------------------ file-manager banner

    async fn wait_until(what: &str, f: impl Fn() -> bool) {
        for _ in 0..500 {
            if f() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("timed out waiting for: {what}");
    }

    /// Skip messages (frames…) until one matches.
    async fn until(
        rx: &mut mpsc::Receiver<AgentEnvelope>,
        pred: impl Fn(&LiveAgentMsg) -> bool,
    ) -> LiveAgentMsg {
        loop {
            let m = next(rx).await.1;
            if pred(&m) {
                return m;
            }
        }
    }

    fn is_reply(id: u64) -> impl Fn(&LiveAgentMsg) -> bool {
        move |m| matches!(m, LiveAgentMsg::FileReply { request_id, .. } if *request_id == id)
    }

    fn fm_end(fm: Uuid, admin: &str) -> LiveServerMsg {
        LiveServerMsg::FileSessionEnd {
            fm_session: fm,
            admin_name: admin.into(),
        }
    }

    fn files_pushes(host: &FakeHost) -> Vec<bool> {
        lock(&host.pushes)
            .iter()
            .filter_map(|p| match &p.resp {
                TrayResponse::RemoteSession(n) if n.kind == RemoteKind::Files => Some(n.active),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn files_banner_texts() {
        assert_eq!(files_banner_text(&[]), "");
        assert_eq!(
            files_banner_text(&[("Jane Doe", "09:05", "ticket 42")]),
            "IT (Jane Doe) is accessing files on this PC since 09:05 \u{2014} Reason: ticket 42"
        );
        assert_eq!(
            files_banner_text(&[("Jane Doe", "", "")]),
            "IT (Jane Doe) is accessing files on this PC"
        );
        // Two admins (oldest first, listed once each); different reasons
        // are not shown.
        assert_eq!(
            files_banner_text(&[
                ("Jane Doe", "09:05", "a"),
                ("Bob", "09:30", "b"),
                ("Jane Doe", "09:40", "a"),
            ]),
            "IT (Jane Doe, Bob) is accessing files on this PC since 09:05"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_session_shows_banner_until_idle() {
        let mut r = rig(LiveConfig {
            fm_idle: Duration::from_millis(200),
            fm_sweep: Duration::from_millis(50),
            ..LiveConfig::default()
        });
        let fm = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        // The banner was up before the operation ran, and before the tray
        // was told.
        assert_eq!(r.desk.banner_count(), 1);
        assert!(r.mgr.files_banner_shown());
        let b = r.desk.last_banner();
        assert!(b.is_alive());
        assert_eq!(
            *lock(&b.text),
            "IT (Jane Doe) is accessing files on this PC since 10:00 \u{2014} Reason: ticket 42"
        );
        assert_eq!(files_pushes(&r.host), vec![true]);
        let item = lock(&r.host.activity)[0].clone();
        assert!(item.body.contains("banner"), "{}", item.body);
        // More operations of the session: the same banner.
        for i in 2..5 {
            r.mgr
                .handle(Uuid::new_v4(), file_req(i, list("C:\\data"), Some(fm)));
            assert!(is_ok_reply(&next(&mut r.rx).await.1));
        }
        assert_eq!(r.desk.banner_count(), 1);
        assert!(b.is_alive());
        // Idle: the session ends and the banner is removed.
        wait_until("banner removed after idle", || !b.is_alive()).await;
        wait_until("no banner", || !r.mgr.files_banner_shown()).await;
        assert!(r.mgr.remote_session_notice().is_none());
        assert_eq!(files_pushes(&r.host), vec![true, false]);
        assert_eq!(r.desk.log(), vec!["banner.show", "banner.close"]);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn file_session_end_and_disconnect_remove_banner() {
        let mut r = rig(LiveConfig::default());
        let fm = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        let b = r.desk.last_banner();
        // Another admin cannot end Jane's session.
        r.mgr.handle(Uuid::new_v4(), fm_end(fm, "Mallory"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(b.is_alive());
        // The admin closed the file manager.
        r.mgr.handle(Uuid::new_v4(), fm_end(fm, "Jane Doe"));
        wait_until("banner removed on FileSessionEnd", || !b.is_alive()).await;
        assert!(r.mgr.remote_session_notice().is_none());
        assert_eq!(files_pushes(&r.host), vec![true, false]);

        // A new session shows a new banner; stream loss removes it.
        let fm2 = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, list("C:\\data"), Some(fm2)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        assert_eq!(r.desk.banner_count(), 2);
        let b2 = r.desk.last_banner();
        assert!(b2.is_alive());
        r.mgr.detach(r.gen);
        wait_until("banner removed on disconnect", || !b2.is_alive()).await;

        // Files switched off by policy: the session and banner end.
        let mut r = rig(LiveConfig::default());
        r.mgr
            .handle(Uuid::new_v4(), file_req(3, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        let b3 = r.desk.last_banner();
        r.mgr.policy_changed(&RemoteAccessProfile::unrestricted());
        assert!(b3.is_alive(), "unchanged files part keeps the session");
        r.mgr.policy_changed(&RemoteAccessProfile::none());
        wait_until("banner removed when files are switched off", || {
            !b3.is_alive()
        })
        .await;
        // Agent shutdown removes the banner at once.
        let mut r = rig(LiveConfig::default());
        r.mgr
            .handle(Uuid::new_v4(), file_req(4, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        let b4 = r.desk.last_banner();
        r.mgr.shutdown();
        assert!(!b4.is_alive());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn banner_failure_refuses_the_file_session() {
        let mut r = rig(LiveConfig::default());
        r.desk.banner_fail.store(true, Ordering::SeqCst);
        let fm = Uuid::new_v4();
        r.mgr.handle(
            Uuid::new_v4(),
            file_req(1, mkdir("C:\\data\\new"), Some(fm)),
        );
        match next(&mut r.rx).await.1 {
            LiveAgentMsg::FileReply {
                request_id: 1,
                reply: FileReply::Error { code, message },
            } => {
                assert_eq!(code, RemoteErrorCode::Unavailable);
                assert!(message.contains("could not be shown"), "{message}");
                assert!(message.contains("did not appear"), "{message}");
            }
            other => panic!("{other:?}"),
        }
        assert!(!r.dir.path().join("C/data/new").exists(), "nothing ran");
        // Reads are refused too; the employee was never told of a session
        // that did not start.
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, list("C:\\data"), Some(fm)));
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::Unavailable)
        );
        assert!(files_pushes(&r.host).is_empty());
        assert!(lock(&r.host.activity).is_empty());
        assert!(r.mgr.remote_session_notice().is_none());
        assert!(!r.mgr.files_banner_shown());
        // Once the banner can be shown, the same session works.
        r.desk.banner_fail.store(false, Ordering::SeqCst);
        r.mgr.handle(
            Uuid::new_v4(),
            file_req(3, mkdir("C:\\data\\new"), Some(fm)),
        );
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        assert!(r.dir.path().join("C/data/new").exists());
        assert!(r.mgr.files_banner_shown());

        // A platform without a banner refuses file access.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("C/data")).unwrap();
        let host = Arc::new(FakeHost {
            fs: Some(Arc::new(TmpFs(dir.path().to_path_buf()))),
            desk: None,
            ..Default::default()
        });
        let mgr = LiveManager::default();
        mgr.bind(Arc::downgrade(&(host.clone() as Arc<dyn LiveHost>)));
        let (tx, mut rx) = mpsc::channel(8);
        mgr.attach(tx);
        mgr.handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert_eq!(
            reply_code(&next(&mut rx).await.1),
            Some(RemoteErrorCode::Unavailable)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_banner_is_restarted_or_the_sessions_end() {
        let mut r = rig(LiveConfig::default());
        let fm = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        // The helper died (e.g. the user switched): shown again on the next
        // operation, before it runs.
        r.desk.last_banner().alive.store(false, Ordering::SeqCst);
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        assert_eq!(r.desk.banner_count(), 2);
        assert!(r.desk.last_banner().is_alive());
        // Died again and cannot come back: refused, and the session ends.
        r.desk.last_banner().alive.store(false, Ordering::SeqCst);
        r.desk.banner_fail.store(true, Ordering::SeqCst);
        r.mgr.handle(
            Uuid::new_v4(),
            file_req(3, mkdir("C:\\data\\late"), Some(fm)),
        );
        assert_eq!(
            reply_code(&next(&mut r.rx).await.1),
            Some(RemoteErrorCode::Unavailable)
        );
        assert!(!r.dir.path().join("C/data/late").exists());
        assert!(r.mgr.remote_session_notice().is_none());
        assert_eq!(files_pushes(&r.host), vec![true, false]);

        // The sweeper notices a dead banner without any operation.
        let mut r = rig(LiveConfig {
            fm_sweep: Duration::from_millis(50),
            ..LiveConfig::default()
        });
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        r.desk.banner_fail.store(true, Ordering::SeqCst);
        r.desk.last_banner().alive.store(false, Ordering::SeqCst);
        wait_until("file session ended by the sweeper", || {
            r.mgr.remote_session_notice().is_none()
        })
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn desktop_and_files_share_one_banner() {
        // Files first, then a desktop session.
        let mut r = rig(LiveConfig::default());
        let fm = Uuid::new_v4();
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        assert!(is_ok_reply(&next(&mut r.rx).await.1));
        let fb = r.desk.last_banner();
        assert!(fb.is_alive());
        let d = Uuid::new_v4();
        r.mgr.handle(d, start_msg(true));
        until(&mut r.rx, |m| matches!(m, LiveAgentMsg::DesktopStarted(_))).await;
        // The desktop banner carries the file notice; the stand-alone one
        // is gone (after the desktop banner was up).
        wait_until("stand-alone banner closed", || !fb.is_alive()).await;
        assert_eq!(r.desk.banners_on_screen(), 0);
        let notice = lock(&r.desk.files_notices).last().cloned().unwrap();
        assert!(
            notice.starts_with("IT (Jane Doe) is accessing files"),
            "{notice}"
        );
        // More file operations: no second banner.
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, list("C:\\data"), Some(fm)));
        until(&mut r.rx, is_reply(2)).await;
        assert_eq!(r.desk.banner_count(), 1);
        assert_eq!(r.desk.banners_on_screen(), 0);
        // Desktop ends while files are active: the stand-alone banner is
        // shown before the desktop banner comes down.
        r.mgr.handle(
            d,
            LiveServerMsg::DesktopStop {
                reason: String::new(),
            },
        );
        until(&mut r.rx, |m| ended_code(m).is_some()).await;
        wait_until("desktop stopped", || !r.mgr.desktop_active()).await;
        assert_eq!(r.desk.banner_count(), 2);
        assert_eq!(r.desk.banners_on_screen(), 1);
        let log = r.desk.log();
        let show = log.iter().rposition(|e| e == "banner.show").unwrap();
        let stop = log.iter().position(|e| e == "desktop.stop").unwrap();
        assert!(show < stop, "no gap: {log:?}");
        // The admin closes the file manager: nothing on screen.
        r.mgr.handle(Uuid::new_v4(), fm_end(fm, "Jane Doe"));
        wait_until("no banner", || r.desk.banners_on_screen() == 0).await;

        // Desktop first, then files: no stand-alone banner at all; the
        // notice is removed from the desktop banner when files end.
        let mut r = rig(LiveConfig::default());
        let d = Uuid::new_v4();
        r.mgr.handle(d, start_msg(false));
        until(&mut r.rx, |m| matches!(m, LiveAgentMsg::DesktopStarted(_))).await;
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        until(&mut r.rx, is_reply(1)).await;
        assert_eq!(r.desk.banner_count(), 0);
        assert!(lock(&r.desk.files_notices)
            .last()
            .is_some_and(|n| n.contains("accessing files")));
        r.mgr.handle(Uuid::new_v4(), fm_end(fm, "Jane Doe"));
        wait_until("notice removed from the desktop banner", || {
            lock(&r.desk.files_notices)
                .last()
                .is_some_and(|n| n.is_empty())
        })
        .await;
        assert!(r.mgr.desktop_active(), "the desktop session goes on");
        r.mgr.handle(
            d,
            LiveServerMsg::DesktopStop {
                reason: String::new(),
            },
        );
        until(&mut r.rx, |m| ended_code(m).is_some()).await;
        wait_until("desktop stopped", || !r.mgr.desktop_active()).await;
        assert_eq!(r.desk.banner_count(), 0, "no files session left");

        // Handover fails: the file sessions end with the desktop session.
        let mut r = rig(LiveConfig::default());
        let d = Uuid::new_v4();
        r.mgr.handle(d, start_msg(true));
        until(&mut r.rx, |m| matches!(m, LiveAgentMsg::DesktopStarted(_))).await;
        r.mgr
            .handle(Uuid::new_v4(), file_req(1, list("C:\\data"), Some(fm)));
        until(&mut r.rx, is_reply(1)).await;
        r.desk.banner_fail.store(true, Ordering::SeqCst);
        r.mgr.handle(
            d,
            LiveServerMsg::DesktopStop {
                reason: String::new(),
            },
        );
        until(&mut r.rx, |m| ended_code(m).is_some()).await;
        wait_until("desktop stopped", || !r.mgr.desktop_active()).await;
        assert!(r.mgr.remote_session_notice().is_none());
        assert_eq!(files_pushes(&r.host), vec![true, false]);
        r.mgr
            .handle(Uuid::new_v4(), file_req(2, list("C:\\data"), Some(fm)));
        assert_eq!(
            reply_code(&until(&mut r.rx, is_reply(2)).await),
            Some(RemoteErrorCode::Unavailable)
        );
    }
}
