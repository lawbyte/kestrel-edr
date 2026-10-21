//! Remote desktop: `GET /api/devices/:id/remote-desktop/status` and the
//! WebSocket relay `GET /api/devices/:id/remote-desktop`.
//!
//! Browser ⇄ server: JSON text messages (`DesktopClientMsg` /
//! `DesktopServerMsg`) and binary frames (16-byte header + JPEG). Server ⇄
//! agent: `LiveServerMsg::Desktop*` / `LiveAgentMsg::Desktop*` on the agent
//! stream. Credit flow control: the agent keeps ≤ 3 frames unacked and the
//! server acks a frame once it was written to the WebSocket. Frames are
//! never logged or stored.

use super::{
    admin_name, audit_op, authorize, check_audited, clean_text, DesktopClaim, DesktopSlot, Feature,
    LiveSession, Target,
};
use crate::{
    api::{parse_uuid, ApiPath, ApiQuery},
    auth::{session_still_valid, Principal, Via},
    crypto::ct_eq,
    error::{ApiError, ApiResult},
    state::AppState,
};
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{header, HeaderMap},
    response::Response,
    Json,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use futures::{SinkExt, StreamExt};
use kestrel_common::{
    now_ms,
    remote::{
        ws_frame_header, DesktopClientMsg, DesktopMode, DesktopServerMsg, DesktopSettings,
        DesktopStart, LiveAgentMsg, LiveServerMsg, RemoteErrorCode, DESKTOP_PING_EVERY_MS,
    },
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{sync::atomic::Ordering, time::Duration};

/// Largest browser → server message.
pub const WS_MAX_CLIENT_MESSAGE: usize = 64 * 1024;
/// The agent must confirm the start within this time.
pub const START_TIMEOUT_MS: i64 = 30_000;
/// Console session / policy re-validation period.
pub const REVALIDATE_EVERY_MS: i64 = 60_000;
/// L9: consecutive failed re-checks (database errors) that end a session.
pub const REVALIDATE_MAX_FAILURES: u32 = 2;
/// A WebSocket write that takes longer than this ends the session.
const WS_SEND_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest `reason` shown to the employee.
pub const REASON_MAX_CHARS: usize = 200;

/// `GET /devices/:id/remote-desktop/status`.
pub async fn status(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
) -> ApiResult<Json<Value>> {
    authorize(&p, Feature::Desktop)?;
    let id = parse_uuid(&id)?;
    let exists: Option<(uuid::Uuid,)> = sqlx::query_as("SELECT id FROM devices WHERE id = $1")
        .bind(id)
        .fetch_optional(&st.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::not_found("device not found"));
    }
    let slot = st.remote.desktop(&id);
    Ok(Json(json!({
        "active": slot.is_some(),
        "session": slot.map(|s| s.to_api()),
    })))
}

#[derive(Deserialize, Default, Debug)]
pub struct DesktopQuery {
    #[serde(default)]
    pub view_only: Option<String>,
    #[serde(default)]
    pub quality: Option<String>,
    #[serde(default)]
    pub scale: Option<String>,
    #[serde(default)]
    pub fps: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub csrf: Option<String>,
}

/// Parsed, clamped session options.
#[derive(Debug, Clone, PartialEq)]
pub struct DesktopOptions {
    pub view_only: bool,
    pub settings: DesktopSettings,
    pub reason: String,
}

fn num(v: &Option<String>, default: u8) -> Result<u8, ApiError> {
    match v.as_deref().map(str::trim) {
        None | Some("") => Ok(default),
        Some(s) => s
            .parse::<i64>()
            .map(|n| n.clamp(0, 255) as u8)
            .map_err(|_| ApiError::bad_request(format!("invalid number '{}'", clean_text(s, 20)))),
    }
}

impl DesktopQuery {
    pub fn options(&self) -> Result<DesktopOptions, ApiError> {
        let view_only = matches!(
            self.view_only
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .as_deref(),
            Some("1" | "true" | "yes")
        );
        let settings = DesktopSettings {
            quality: num(&self.quality, kestrel_common::remote::DEFAULT_QUALITY)?,
            scale_pct: num(&self.scale, 100)?,
            max_fps: num(&self.fps, kestrel_common::remote::DEFAULT_MAX_FPS)?,
            view_only: None,
        }
        .clamped();
        Ok(DesktopOptions {
            view_only,
            settings,
            reason: clean_text(self.reason.as_deref().unwrap_or(""), REASON_MAX_CHARS),
        })
    }
}

/// `scheme://host[:port]` → (`https`?, `host[:port]` lower-case without the
/// scheme's default port).
fn split_origin(origin: &str) -> Option<(bool, String)> {
    let (https, rest) = if let Some(r) = origin.strip_prefix("https://") {
        (true, r)
    } else {
        (false, origin.strip_prefix("http://")?)
    };
    if rest.is_empty() || rest.contains(['/', '@', '?', '#', ' ']) {
        return None;
    }
    Some((https, strip_default_port(&rest.to_ascii_lowercase(), https)))
}

fn strip_default_port(auth: &str, https: bool) -> String {
    let default = if https { ":443" } else { ":80" };
    auth.strip_suffix(default).unwrap_or(auth).to_string()
}

fn host_only(auth: &str) -> &str {
    if auth.starts_with('[') {
        // [v6]:port
        return auth
            .split_once(']')
            .map(|(h, _)| &auth[..h.len() + 1])
            .unwrap_or(auth);
    }
    auth.rsplit_once(':')
        .filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit()))
        .map(|(h, _)| h)
        .unwrap_or(auth)
}

/// Port of a normalised `host[:port]` (443 when absent: https only).
fn port_of(auth: &str) -> Option<u16> {
    let host = host_only(auth);
    if host.len() == auth.len() {
        return Some(443);
    }
    auth[host.len() + 1..].parse().ok()
}

/// Same-origin check for the WebSocket (CSWSH, L8): the `Origin` must be
/// `https` and its host and port must equal the request `Host` exactly (the
/// default port 443 may be omitted on either side), or its host must be one of
/// the configured public hostnames **and** its port the public HTTPS port.
pub fn origin_allowed(
    origin: Option<&str>,
    host: Option<&str>,
    public_hostnames: &[String],
    public_port: u16,
) -> bool {
    let Some((https, auth)) = origin.and_then(split_origin) else {
        return false;
    };
    if !https {
        return false;
    }
    if let Some(h) = host {
        if strip_default_port(&h.trim().to_ascii_lowercase(), true) == auth {
            return true;
        }
    }
    let oh = host_only(&auth);
    port_of(&auth) == Some(public_port)
        && public_hostnames
            .iter()
            .any(|p| !p.is_empty() && p.trim().eq_ignore_ascii_case(oh))
}

/// Why a desktop session ended (`ended_by` in the audit log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndedBy {
    Admin,
    Idle,
    MaxDuration,
    Agent,
    Disconnect,
    Server,
}

impl EndedBy {
    pub fn as_str(self) -> &'static str {
        match self {
            EndedBy::Admin => "admin",
            EndedBy::Idle => "idle",
            EndedBy::MaxDuration => "max_duration",
            EndedBy::Agent => "agent",
            EndedBy::Disconnect => "disconnect",
            EndedBy::Server => "server",
        }
    }
}

/// Session timers from the effective profile (`None` = no limit).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub idle_ms: Option<i64>,
    pub max_ms: Option<i64>,
}

impl Limits {
    pub fn from_profile(p: &kestrel_common::remote::RemoteAccessProfile) -> Limits {
        let ms = |m: u32| (m > 0).then_some(m as i64 * 60_000);
        Limits {
            idle_ms: ms(p.guardrails.idle_timeout_minutes),
            max_ms: ms(p.guardrails.max_session_minutes),
        }
    }
}

/// Timer decisions (checked every second): start deadline (30 s, extended
/// while the employee is asked for consent), max duration, idle.
pub fn timer_check(
    now: i64,
    opened_at: i64,
    start_deadline: Option<i64>,
    last_activity: i64,
    limits: Limits,
) -> Option<(EndedBy, &'static str)> {
    if start_deadline.is_some_and(|d| now >= d) {
        return Some((
            EndedBy::Agent,
            "the agent did not start the session in time",
        ));
    }
    if limits.max_ms.is_some_and(|m| now - opened_at >= m) {
        return Some((EndedBy::MaxDuration, "the session reached its time limit"));
    }
    if limits.idle_ms.is_some_and(|m| now - last_activity >= m) {
        return Some((EndedBy::Idle, "no admin activity for the idle timeout"));
    }
    None
}

/// `GET /devices/:id/remote-desktop?view_only=&quality=&scale=&fps=&reason=&csrf=`
/// (WebSocket). All checks happen before the upgrade.
pub async fn connect(
    State(st): State<AppState>,
    p: Principal,
    ApiPath(id): ApiPath<String>,
    ApiQuery(q): ApiQuery<DesktopQuery>,
    headers: HeaderMap,
    uri: axum::http::Uri,
    ws: Option<WebSocketUpgrade>,
) -> ApiResult<Response> {
    authorize(&p, Feature::Desktop)?;
    let Via::Session { token_hash, csrf } = &p.via else {
        return Err(ApiError::forbidden(
            "remote desktop needs an interactive console session",
        ));
    };
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok());
    // HTTP/1.1 `Host`, or the HTTP/2 `:authority` (request URI).
    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(|a| a.as_str()));
    if !origin_allowed(
        origin,
        host,
        &st.cfg.public_hostnames,
        st.cfg.https_addr.port(),
    ) {
        return Err(ApiError::forbidden(
            "cross-origin remote desktop connections are refused",
        ));
    }
    let sent = q.csrf.as_deref().unwrap_or("");
    if sent.is_empty() || !ct_eq(sent, csrf) {
        return Err(ApiError::forbidden("missing or invalid CSRF token"));
    }
    let id = parse_uuid(&id)?;
    let mut opts = q.options()?;
    let details = json!({"session_id": null, "view_only": opts.view_only, "reason": opts.reason});
    let t = check_audited(
        &st,
        &p,
        id,
        Feature::Desktop,
        None,
        &opts.reason,
        "remote.desktop.start",
        &details,
    )
    .await?;
    // A view-only profile never gets control.
    if t.effective.desktop == DesktopMode::ViewOnly {
        opts.view_only = true;
    }
    let admin_name = admin_name(&p);
    let slot = DesktopSlot {
        session_id: uuid::Uuid::new_v4(),
        admin_id: p.user.id,
        admin_email: p.user.email.clone(),
        admin_name: admin_name.clone(),
        view_only: opts.view_only.into(),
        started_at: now_ms(),
    };
    let claim = match DesktopClaim::claim(&st, id, slot) {
        Ok(c) => c,
        Err(holder) => {
            let who = if holder.admin_name.is_empty() {
                holder.admin_email.clone()
            } else {
                format!("{} ({})", holder.admin_name, holder.admin_email)
            };
            let e = ApiError::conflict(format!(
                "a remote desktop session on this device is already open by {who}"
            ))
            .with_field("session", holder.to_api());
            audit_op(
                &st,
                &p,
                "remote.desktop.start",
                id,
                &t.hostname,
                details,
                Err(e.message.clone()),
            )
            .await;
            return Err(e);
        }
    };
    // Checked after the slot so a plain GET also learns who holds it; the
    // claim is released when this returns without upgrading.
    let Some(ws) = ws else {
        return Err(ApiError::bad_request("a WebSocket upgrade is required"));
    };
    let token_hash = token_hash.clone();
    Ok(ws
        .max_message_size(WS_MAX_CLIENT_MESSAGE)
        .max_frame_size(WS_MAX_CLIENT_MESSAGE)
        .on_upgrade(move |socket| async move {
            run(st, p, token_hash, t, claim, opts, admin_name, socket).await;
        }))
}

fn text(m: &DesktopServerMsg) -> Message {
    Message::Text(serde_json::to_string(m).unwrap_or_default())
}

#[allow(clippy::too_many_arguments)]
async fn run(
    st: AppState,
    p: Principal,
    token_hash: String,
    t: Target,
    claim: DesktopClaim,
    opts: DesktopOptions,
    admin_name: String,
    socket: WebSocket,
) {
    let session_id = claim.slot.session_id;
    let device_id = t.device_id;
    // The desktop session id is also the live session id on the agent stream.
    let mut live = LiveSession::open_with_id(&st, device_id, t.conn.clone(), session_id);
    let mut agent_ended = false;
    let (mut sink, mut stream) = socket.split();
    let opened_at = now_ms();
    let mut last_activity = opened_at;
    let mut view_only = opts.view_only;
    let mut started = false;
    let mut start_audited = false;
    // A consent prompt is open on the device (start or a switch to control).
    let mut consent_open = false;
    // The admin asked for control; the profile requires consent, so the
    // session stays view-only until the agent confirms.
    let mut pending_control = false;
    let mut revalidate_failures = 0u32;
    let mut start_deadline = Some(opened_at + START_TIMEOUT_MS);
    let control_allowed = t.effective.desktop == DesktopMode::Control;
    let limits = Limits::from_profile(&t.effective);
    let profile_summary = t.effective.summary();

    let start = LiveServerMsg::DesktopStart(DesktopStart {
        view_only,
        admin_name,
        reason: opts.reason.clone(),
        settings: opts.settings.clone(),
    });
    let mut end: Option<(EndedBy, String, Option<RemoteErrorCode>)> = None;
    if let Err(e) = live.send(start) {
        end = Some((EndedBy::Disconnect, e.describe(), None));
    } else {
        let _ = sink
            .send(text(&DesktopServerMsg::Starting {
                session_id: session_id.to_string(),
                view_only,
            }))
            .await;
    }

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut ping = tokio::time::interval(Duration::from_millis(DESKTOP_PING_EVERY_MS as u64));
    let mut revalidate = tokio::time::interval(Duration::from_millis(REVALIDATE_EVERY_MS as u64));
    ping.tick().await;
    revalidate.tick().await;

    while end.is_none() {
        tokio::select! {
            m = live.recv() => match m {
                None => {
                    let why = if live.violated() {
                        "the agent exceeded the live-session limits"
                    } else {
                        "device disconnected"
                    };
                    end = Some((EndedBy::Disconnect, why.into(), None));
                }
                Some(LiveAgentMsg::ConsentPending { timeout_secs, .. }) => {
                    consent_open = true;
                    let secs = timeout_secs.min(super::CONSENT_MAX_SECS);
                    if !started {
                        start_deadline = Some(now_ms() + secs as i64 * 1000 + START_TIMEOUT_MS);
                    }
                    let m = text(&DesktopServerMsg::ConsentPending { timeout_secs: secs });
                    if send_ws(&mut sink, m).await.is_err() {
                        end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                    }
                }
                Some(LiveAgentMsg::ConsentResult { allowed, code, .. }) => {
                    consent_open = false;
                    let result = super::consent_result_str(allowed, code);
                    audit_op(&st, &p, "remote.consent", device_id, &t.hostname,
                        json!({"kind": "desktop", "session_id": session_id, "result": result}), Ok(())).await;
                    if pending_control {
                        pending_control = false;
                        if allowed && view_only {
                            view_only = false;
                            claim.slot.view_only.store(false, Ordering::Relaxed);
                            audit_op(&st, &p, "remote.desktop.mode", device_id, &t.hostname,
                                json!({"session_id": session_id, "view_only": false}), Ok(())).await;
                        }
                    }
                    if send_ws(&mut sink, text(&DesktopServerMsg::ConsentResult { allowed, code })).await.is_err() {
                        end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                    }
                }
                Some(LiveAgentMsg::DesktopStarted(info)) => {
                    if !started {
                        started = true;
                        start_audited = true;
                        start_deadline = None;
                        if consent_open {
                            // Agent without ConsentResult: the start means allowed.
                            consent_open = false;
                            audit_op(&st, &p, "remote.consent", device_id, &t.hostname,
                                json!({"kind": "desktop", "session_id": session_id, "result": "allowed"}), Ok(())).await;
                        }
                        audit_op(&st, &p, "remote.desktop.start", device_id, &t.hostname,
                            json!({"session_id": session_id, "view_only": view_only, "reason": opts.reason, "profile": profile_summary}), Ok(())).await;
                    }
                    if send_ws(&mut sink, text(&DesktopServerMsg::Started(info))).await.is_err() {
                        end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                    }
                }
                Some(LiveAgentMsg::DesktopInfo(info)) => {
                    // The agent is the authority on the mode: it may confirm a
                    // pending switch to control or fall back to view-only, but
                    // it never gets control the admin did not ask for.
                    if started && info.view_only != view_only && (info.view_only || pending_control) {
                        pending_control = false;
                        view_only = info.view_only;
                        claim.slot.view_only.store(view_only, Ordering::Relaxed);
                        audit_op(&st, &p, "remote.desktop.mode", device_id, &t.hostname,
                            json!({"session_id": session_id, "view_only": view_only}), Ok(())).await;
                    }
                    if send_ws(&mut sink, text(&DesktopServerMsg::Info(info))).await.is_err() {
                        end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                    }
                }
                Some(LiveAgentMsg::DesktopFrame(f)) => {
                    let seq = f.seq;
                    if let Ok(jpeg) = B64.decode(f.jpeg_b64.as_bytes()) {
                        let mut buf = Vec::with_capacity(16 + jpeg.len());
                        buf.extend_from_slice(&ws_frame_header(f.seq, f.width, f.height, f.ts));
                        buf.extend_from_slice(&jpeg);
                        if send_ws(&mut sink, Message::Binary(buf)).await.is_err() {
                            end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                            continue;
                        }
                    }
                    // Ack after the write (or a bad frame) so the agent's credits flow.
                    if let Err(e) = live.send(LiveServerMsg::DesktopAck { seq }) {
                        end = Some((EndedBy::Disconnect, e.describe(), None));
                    }
                }
                Some(LiveAgentMsg::DesktopEnded { reason, code }) => {
                    let reason = clean_text(&reason, 300);
                    agent_ended = true;
                    end = Some((EndedBy::Agent, if reason.is_empty() { "ended on the device".into() } else { reason }, code));
                }
                Some(_) => {}
            },
            m = stream.next() => match m {
                None | Some(Err(_)) | Some(Ok(Message::Close(_))) => {
                    end = Some((EndedBy::Admin, "the admin closed the session".into(), None));
                }
                Some(Ok(Message::Text(txt))) => {
                    if txt.len() > WS_MAX_CLIENT_MESSAGE {
                        continue;
                    }
                    let Ok(msg) = serde_json::from_str::<DesktopClientMsg>(&txt) else { continue };
                    match msg {
                        DesktopClientMsg::Input { event } => {
                            if view_only {
                                continue;
                            }
                            last_activity = now_ms();
                            if let Some(event) = event.sanitized() {
                                if let Err(e) = live.send(LiveServerMsg::DesktopInput { event }) {
                                    end = Some((EndedBy::Disconnect, e.describe(), None));
                                }
                            }
                        }
                        DesktopClientMsg::Settings(s) => {
                            last_activity = now_ms();
                            let mut s = s.clamped();
                            if s.view_only == Some(false) && !control_allowed {
                                s.view_only = None;
                                let m = text(&DesktopServerMsg::Error {
                                    message: "this device only allows view-only remote desktop".into(),
                                });
                                if send_ws(&mut sink, m).await.is_err() {
                                    end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                                    continue;
                                }
                            }
                            if s.view_only == Some(false)
                                && view_only
                                && t.effective.guardrails.require_consent
                            {
                                // Control only after the employee allows it.
                                pending_control = true;
                            } else if let Some(v) = s.view_only {
                                if v != view_only {
                                    pending_control = false;
                                    view_only = v;
                                    claim.slot.view_only.store(v, Ordering::Relaxed);
                                    audit_op(&st, &p, "remote.desktop.mode", device_id, &t.hostname,
                                        json!({"session_id": session_id, "view_only": v}), Ok(())).await;
                                }
                            }
                            if let Err(e) = live.send(LiveServerMsg::DesktopSettings(s)) {
                                end = Some((EndedBy::Disconnect, e.describe(), None));
                            }
                        }
                        DesktopClientMsg::Activity => last_activity = now_ms(),
                        DesktopClientMsg::Ping => {
                            if send_ws(&mut sink, text(&DesktopServerMsg::Pong)).await.is_err() {
                                end = Some((EndedBy::Admin, "browser disconnected".into(), None));
                            }
                        }
                        DesktopClientMsg::Stop => {
                            end = Some((EndedBy::Admin, "the admin ended the session".into(), None));
                        }
                        DesktopClientMsg::Unknown => {}
                    }
                }
                Some(Ok(_)) => {} // binary / ping / pong from the browser: ignored
            },
            _ = tick.tick() => {
                if let Some((by, why)) = timer_check(now_ms(), opened_at, start_deadline, last_activity, limits) {
                    end = Some((by, why.into(), if started { None } else { Some(RemoteErrorCode::Timeout) }));
                }
            }
            _ = ping.tick() => {
                if let Err(e) = live.send(LiveServerMsg::DesktopPing) {
                    if e == super::RemoteFail::Disconnected {
                        end = Some((EndedBy::Disconnect, e.describe(), None));
                    }
                }
            }
            _ = revalidate.tick() => {
                // A logout / role change, or a policy change that removes
                // desktop access, ends the session. L9: fails closed — two
                // consecutive failed checks (database errors) end it too.
                let check = async {
                    let session_ok = session_still_valid(&st, &token_hash, Feature::Desktop.privilege()).await?;
                    let profile_ok = super::effective_now(&st, device_id)
                        .await?
                        .is_some_and(|e| e.desktop != DesktopMode::Off);
                    Ok::<_, anyhow::Error>((session_ok, profile_ok))
                }
                .await;
                match check {
                    Ok((false, _)) => {
                        end = Some((EndedBy::Server, "the console session is no longer valid".into(), None));
                    }
                    Ok((true, false)) => {
                        end = Some((EndedBy::Server, "remote desktop is no longer allowed on this device".into(), Some(RemoteErrorCode::DisabledByPolicy)));
                    }
                    Ok((true, true)) => revalidate_failures = 0,
                    Err(e) => {
                        revalidate_failures += 1;
                        tracing::warn!(%device_id, %session_id, error = %e, "remote desktop re-check failed");
                        if revalidate_failures >= REVALIDATE_MAX_FAILURES {
                            end = Some((EndedBy::Server, "the session could not be re-checked".into(), None));
                        }
                    }
                }
            }
        }
    }

    let (ended_by, reason, code) = end.unwrap_or((EndedBy::Server, "ended".into(), None));
    // Tell the agent (unless it ended the session itself or is gone).
    if !agent_ended && ended_by != EndedBy::Disconnect {
        let _ = live.send(LiveServerMsg::DesktopStop {
            reason: ended_by.as_str().to_string(),
        });
    }
    let _ = send_ws(
        &mut sink,
        text(&DesktopServerMsg::Ended {
            reason: reason.clone(),
            code,
        }),
    )
    .await;
    let _ = sink.send(Message::Close(None)).await;
    let _ = sink.close().await;
    if start_audited {
        audit_op(
            &st,
            &p,
            "remote.desktop.stop",
            device_id,
            &t.hostname,
            json!({
                "session_id": session_id,
                "duration_ms": now_ms() - opened_at,
                "ended_by": ended_by.as_str(),
                "reason": reason,
            }),
            Ok(()),
        )
        .await;
    } else {
        if consent_open
            || matches!(
                code,
                Some(RemoteErrorCode::ConsentDenied | RemoteErrorCode::ConsentTimeout)
            )
        {
            let result = match code {
                Some(RemoteErrorCode::ConsentDenied) => "denied",
                _ => "timeout",
            };
            audit_op(
                &st,
                &p,
                "remote.consent",
                device_id,
                &t.hostname,
                json!({"kind": "desktop", "session_id": session_id, "result": result}),
                Ok(()),
            )
            .await;
        }
        audit_op(
            &st,
            &p,
            "remote.desktop.start",
            device_id,
            &t.hostname,
            json!({"session_id": session_id, "view_only": view_only, "reason": opts.reason, "profile": profile_summary}),
            Err(reason),
        )
        .await;
    }
    tracing::info!(%device_id, %session_id, ended_by = ended_by.as_str(), "remote desktop session ended");
    drop(live);
    drop(claim);
}

async fn send_ws(
    sink: &mut futures::stream::SplitSink<WebSocket, Message>,
    m: Message,
) -> Result<(), ()> {
    match tokio::time::timeout(WS_SEND_TIMEOUT, sink.send(m)).await {
        Ok(Ok(())) => Ok(()),
        _ => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_rules() {
        let pubs = vec!["edr.acme.sg".to_string()];
        let ok = |o: &str, h: &str, pubs: &[String], port: u16| {
            origin_allowed(Some(o), Some(h), pubs, port)
        };
        // Same host and port as the request.
        assert!(ok("https://localhost:8443", "localhost:8443", &[], 443));
        assert!(ok("https://EDR.acme.sg", "edr.acme.sg:443", &[], 443));
        assert!(ok("https://edr.acme.sg:443", "edr.acme.sg", &[], 443));
        assert!(ok("https://[::1]:9443", "[::1]:9443", &[], 443));
        assert!(!ok("https://localhost:1", "localhost:2", &[], 443));
        assert!(!ok("https://localhost:8443", "localhost", &[], 443));
        // Public hostnames only on the public HTTPS port.
        assert!(ok("https://edr.acme.sg", "10.0.0.5:443", &pubs, 443));
        assert!(!ok("https://edr.acme.sg:8443", "internal", &pubs, 443));
        assert!(ok("https://edr.acme.sg:8443", "internal", &pubs, 8443));
        assert!(!ok("https://edr.acme.sg", "internal", &pubs, 8443));
        // Never: missing, null, http, other hosts, user info.
        assert!(!origin_allowed(None, Some("localhost"), &pubs, 443));
        assert!(!ok("null", "localhost", &pubs, 443));
        assert!(!ok("http://localhost", "localhost", &[], 443));
        assert!(!ok("http://edr.acme.sg", "x", &pubs, 443));
        assert!(!ok("https://evil.example", "localhost", &pubs, 443));
        assert!(!ok("https://localhost.evil.example", "localhost", &[], 443));
        assert!(!ok("https://user@localhost", "localhost", &[], 443));
    }

    #[test]
    fn query_options() {
        let q = DesktopQuery {
            view_only: Some("TRUE".into()),
            quality: Some("200".into()),
            scale: Some("5".into()),
            fps: None,
            reason: Some(format!("Fix \u{202e}printer\n{}", "x".repeat(300))),
            csrf: None,
        };
        let o = q.options().unwrap();
        assert!(o.view_only);
        assert_eq!(o.settings.quality, 90);
        assert_eq!(o.settings.scale_pct, 25);
        assert_eq!(o.settings.max_fps, kestrel_common::remote::DEFAULT_MAX_FPS);
        assert_eq!(o.reason.chars().count(), REASON_MAX_CHARS);
        assert!(o.reason.starts_with("Fix printer"));
        let o = DesktopQuery::default().options().unwrap();
        assert!(!o.view_only && o.settings == DesktopSettings::default() && o.reason.is_empty());
        let bad = DesktopQuery {
            quality: Some("abc".into()),
            ..Default::default()
        };
        assert!(bad.options().is_err());
    }

    #[test]
    fn timers() {
        use kestrel_common::remote::RemoteAccessProfile;
        let t0 = 1_000_000;
        let g = Limits::from_profile(&RemoteAccessProfile::guarded_default());
        assert_eq!(
            g,
            Limits {
                idle_ms: Some(15 * 60_000),
                max_ms: Some(60 * 60_000)
            }
        );
        let none = Limits::from_profile(&RemoteAccessProfile::unrestricted());
        assert_eq!(
            none,
            Limits {
                idle_ms: None,
                max_ms: None
            }
        );
        let start = Some(t0 + START_TIMEOUT_MS);
        assert_eq!(timer_check(t0 + 29_000, t0, start, t0, g), None);
        assert_eq!(
            timer_check(t0 + 30_000, t0, start, t0, g).unwrap().0,
            EndedBy::Agent
        );
        assert_eq!(timer_check(t0 + 60_000, t0, None, t0, g), None);
        assert_eq!(
            timer_check(t0 + 15 * 60_000, t0, None, t0, g).unwrap().0,
            EndedBy::Idle
        );
        let late = t0 + 60 * 60_000;
        assert_eq!(
            timer_check(late, t0, None, late - 1, g).unwrap().0,
            EndedBy::MaxDuration
        );
        assert_eq!(timer_check(late - 1, t0, None, late - 2, g), None);
        // No limits: never idles out or expires.
        assert_eq!(timer_check(t0 + 100 * 3_600_000, t0, None, t0, none), None);
    }
}
