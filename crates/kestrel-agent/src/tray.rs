//! Tray protocol: the agent-side [`TrayHandler`] plus a reusable JSON-lines
//! connection server (used by the simulator's socket) and client (used by
//! `kestrel-agent status`).
//!
//! Every request carries the client's identity ([`TrayClient`], established
//! by the transport: on Windows the pipe client's process token). M3:
//! * `Activity` returns only the caller's own items plus machine-wide ones;
//! * `RequestReview` needs an identified caller, only works for alerts the
//!   caller can see, once per alert until IT decides, and at most
//!   [`REVIEWS_PER_HOUR`] per user;
//! * `QuickCheck` runs at most once per [`CHECK_INTERVAL_MS`] and never
//!   concurrently (a recent result is returned instead).

use anyhow::{anyhow, Result};
use kestrel_common::{
    tray::{ProtectionState, ReviewState, TrayRequest, TrayResponse, TrayStatus},
    wire::{AgentPayload, ReviewRequest},
    ResponseAction, TimestampMs,
};
use kestrel_platform::{ActionOrigin, TrayClient, TrayHandler, TrayPush};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};

use crate::agent::Core;
use crate::store;

/// Max request line accepted from the (unprivileged) tray.
pub const MAX_LINE: usize = 64 * 1024;
const MAX_JUSTIFICATION: usize = 2000;
/// Recent protective actions keep the tray in "attention" state this long.
const ATTENTION_MS: i64 = 24 * 3600 * 1000;
/// Review requests per user per hour.
pub const REVIEWS_PER_HOUR: usize = 5;
/// Minimum interval between two quick checks (any user).
pub const CHECK_INTERVAL_MS: i64 = 5 * 60 * 1000;

/// Rate limits for the unprivileged tray protocol (pure; unit-tested).
#[derive(Debug, Default)]
pub struct TrayLimits {
    reviews: HashMap<String, VecDeque<TimestampMs>>,
    last_check: Option<(TimestampMs, bool, String)>,
}

impl TrayLimits {
    /// Record a review request by `user` at `now` if under the hourly cap.
    pub fn allow_review(&mut self, user: &str, now: TimestampMs) -> bool {
        let q = self.reviews.entry(user.to_string()).or_default();
        while q.front().is_some_and(|t| now - t >= 3_600_000) {
            q.pop_front();
        }
        if q.len() >= REVIEWS_PER_HOUR {
            return false;
        }
        q.push_back(now);
        if self.reviews.len() > 4096 {
            self.reviews.retain(|_, v| !v.is_empty());
        }
        true
    }

    /// Result of a quick check finished less than [`CHECK_INTERVAL_MS`] ago.
    pub fn recent_check(&self, now: TimestampMs) -> Option<(TimestampMs, bool, &str)> {
        self.last_check
            .as_ref()
            .filter(|(t, _, _)| now - t < CHECK_INTERVAL_MS)
            .map(|(t, ok, m)| (*t, *ok, m.as_str()))
    }

    pub fn record_check(&mut self, now: TimestampMs, ok: bool, message: String) {
        self.last_check = Some((now, ok, message));
    }
}

pub struct TrayService {
    core: Arc<Core>,
    limits: Mutex<TrayLimits>,
    /// Single in-flight quick check.
    check: tokio::sync::Mutex<()>,
}

impl TrayService {
    pub fn new(core: Arc<Core>) -> TrayService {
        TrayService {
            core,
            limits: Mutex::new(TrayLimits::default()),
            check: tokio::sync::Mutex::new(()),
        }
    }

    fn limits(&self) -> std::sync::MutexGuard<'_, TrayLimits> {
        self.limits.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn status(&self, client: &TrayClient) -> TrayStatus {
        let c = &self.core;
        let p = c.policy();
        let health_ok = c.health_snapshot_etw_ok();
        let connected = c.is_connected();
        let recent = c
            .store
            .activity_for(&client.owner_keys(), 20)
            .unwrap_or_default();
        let recent_attention = recent.iter().any(|a| {
            a.alert_id.is_some()
                && a.review.is_none()
                && a.action_taken != "Reported to IT"
                && kestrel_common::now_ms() - a.ts < ATTENTION_MS
        });
        let state = if c.platform.is_isolated() {
            ProtectionState::Isolated
        } else if !health_ok {
            ProtectionState::Degraded
        } else if recent_attention {
            ProtectionState::Attention
        } else if !connected {
            ProtectionState::Offline
        } else {
            ProtectionState::Protected
        };
        let org = if p.branding.org_name.is_empty() {
            "Your organisation".to_string()
        } else {
            p.branding.org_name.clone()
        };
        TrayStatus {
            state,
            agent_version: kestrel_common::VERSION.into(),
            server_connected: connected,
            last_policy_sync: c.store.kv_get_i64(store::KV_LAST_POLICY_SYNC),
            policy_name: p.name.clone(),
            org_name: org,
            it_contact: p.branding.it_contact.clone(),
            privacy_notice_md: p.branding.privacy_notice_md.clone(),
            hostname: c.hostname.clone(),
            last_check: c.store.kv_get_i64(store::KV_LAST_CHECK),
            remote_session: c.live.remote_session_notice(),
        }
    }
}

#[async_trait::async_trait]
impl TrayHandler for TrayService {
    async fn handle(&self, req: TrayRequest, client: &TrayClient) -> TrayResponse {
        match req {
            TrayRequest::Status => TrayResponse::Status(self.status(client)),
            TrayRequest::Activity { limit } => {
                match self
                    .core
                    .store
                    .activity_for(&client.owner_keys(), limit.clamp(1, 500))
                {
                    Ok(items) => TrayResponse::Activity { items },
                    Err(e) => TrayResponse::Error {
                        message: format!("activity unavailable: {e}"),
                    },
                }
            }
            TrayRequest::QuickCheck => {
                let now = kestrel_common::now_ms();
                if let Some((t, ok, m)) = self.limits().recent_check(now) {
                    let mins = ((now - t) / 60_000).max(0);
                    return TrayResponse::Ack {
                        ok,
                        message: format!(
                            "A quick check already ran {} ago: {m}",
                            if mins == 0 {
                                "less than a minute".to_string()
                            } else if mins == 1 {
                                "1 minute".to_string()
                            } else {
                                format!("{mins} minutes")
                            }
                        ),
                    };
                }
                let Ok(_guard) = self.check.try_lock() else {
                    return TrayResponse::Ack {
                        ok: true,
                        message: "A quick check is already running.".into(),
                    };
                };
                let o = self
                    .core
                    .execute_action_as(&ResponseAction::Scan { path: None }, ActionOrigin::Local)
                    .await;
                let now = kestrel_common::now_ms();
                let _ = self
                    .core
                    .store
                    .kv_set(store::KV_LAST_CHECK, &now.to_string());
                let message = if o.ok {
                    if o.detail.is_empty() {
                        "Quick check finished. Nothing suspicious found.".into()
                    } else {
                        o.detail
                    }
                } else {
                    format!("Quick check could not complete: {}", o.detail)
                };
                self.limits().record_check(now, o.ok, message.clone());
                TrayResponse::Ack { ok: o.ok, message }
            }
            TrayRequest::RequestReview {
                alert_id,
                justification,
            } => {
                let keys = client.owner_keys();
                let Some(who) = keys.first().cloned() else {
                    return TrayResponse::Error {
                        message: "your identity could not be verified; ask IT directly".into(),
                    };
                };
                // Only alerts this user can see (own or machine-wide).
                let visible = match self.core.store.alert_owner(alert_id) {
                    Some(None) => true,
                    Some(Some(o)) => keys.contains(&o),
                    None => false,
                };
                if !visible {
                    return TrayResponse::Error {
                        message: "unknown alert".into(),
                    };
                }
                if self.core.store.review_state(alert_id) == Some(ReviewState::Requested) {
                    return TrayResponse::Ack {
                        ok: true,
                        message: "IT already has your request for this block.".into(),
                    };
                }
                if !self.limits().allow_review(&who, kestrel_common::now_ms()) {
                    return TrayResponse::Error {
                        message: "Too many review requests. Please try again later or contact IT."
                            .into(),
                    };
                }
                let mut j: String = justification
                    .chars()
                    .filter(|c| !c.is_control() || *c == '\n')
                    .collect();
                if j.len() > MAX_JUSTIFICATION {
                    let mut cut = MAX_JUSTIFICATION;
                    while !j.is_char_boundary(cut) {
                        cut -= 1;
                    }
                    j.truncate(cut);
                }
                // The pipe client's own identity (not the console user), with
                // the policy's username hashing applied (M9).
                let raw_user = client
                    .user
                    .clone()
                    .or_else(|| client.user_sid.clone())
                    .unwrap_or_else(|| "unknown".into());
                let filter = self.core.filter();
                let user = filter.user(&raw_user);
                let j = crate::privacy::redact_secrets(&j);
                self.core
                    .enqueue(&AgentPayload::ReviewRequest(ReviewRequest {
                        alert_id,
                        user,
                        justification: j,
                        ts: kestrel_common::now_ms(),
                    }));
                let _ = self
                    .core
                    .store
                    .set_review_state(alert_id, ReviewState::Requested);
                TrayResponse::Ack {
                    ok: true,
                    message: "Your request was sent to IT.".into(),
                }
            }
            TrayRequest::Subscribe | TrayRequest::SubscribeWith { .. } => TrayResponse::Ack {
                ok: true,
                message: "subscribed".into(),
            },
            TrayRequest::ConsentResponse { request_id, allow } => {
                self.core.live.consent_response(request_id, allow, client)
            }
        }
    }

    fn subscribe(&self) -> broadcast::Receiver<TrayPush> {
        self.core.subscribe_tray()
    }
}

/// Serve one tray connection: JSON-lines requests → responses, plus pushed
/// notifications (only those visible to `client`) after `Subscribe` /
/// `SubscribeWith`. Opt-in push kinds (`TrayResponse::RemoteSession`) are
/// only forwarded to connections that subscribed with the matching feature,
/// so an older tray never receives a response type it cannot parse.
/// Returns when the peer disconnects.
pub async fn serve_connection<S>(stream: S, handler: Arc<dyn TrayHandler>, client: TrayClient)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let (out_tx, mut out_rx) = mpsc::channel::<TrayResponse>(64);
    let writer = tokio::spawn(async move {
        while let Some(r) = out_rx.recv().await {
            let mut line = match serde_json::to_vec(&r) {
                Ok(l) => l,
                Err(_) => continue,
            };
            line.push(b'\n');
            if wr.write_all(&line).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
    });
    let mut rd = BufReader::new(rd);
    let mut sub_task: Option<tokio::task::JoinHandle<()>> = None;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let n = match (&mut rd)
            .take(MAX_LINE as u64 + 1)
            .read_until(b'\n', &mut buf)
            .await
        {
            Ok(n) => n,
            Err(_) => break,
        };
        if n == 0 {
            break;
        }
        if buf.len() > MAX_LINE {
            let _ = out_tx
                .send(TrayResponse::Error {
                    message: "request too large".into(),
                })
                .await;
            break;
        }
        let line = String::from_utf8_lossy(&buf);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<TrayRequest>(line) {
            Ok(req) => {
                let sub = match &req {
                    TrayRequest::Subscribe => Some(Features::default()),
                    TrayRequest::SubscribeWith { features } => Some(Features::from(features)),
                    _ => None,
                };
                let r = handler.handle(req, &client).await;
                if let (Some(feat), None) = (sub, &sub_task) {
                    let mut rx = handler.subscribe();
                    let tx = out_tx.clone();
                    let who = client.clone();
                    sub_task = Some(tokio::spawn(async move {
                        loop {
                            match rx.recv().await {
                                Ok(n) => {
                                    if !n.visible_to(&who) || !feat.allows(&n.resp) {
                                        continue;
                                    }
                                    if tx.send(n.resp).await.is_err() {
                                        break;
                                    }
                                }
                                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                                Err(_) => break,
                            }
                        }
                    }));
                }
                r
            }
            Err(e) => TrayResponse::Error {
                message: format!("bad request: {e}"),
            },
        };
        if out_tx.send(resp).await.is_err() {
            break;
        }
    }
    if let Some(t) = sub_task {
        t.abort();
    }
    drop(out_tx);
    let _ = writer.await;
}

/// Opt-in push kinds of one tray connection.
#[derive(Debug, Clone, Copy, Default)]
struct Features {
    remote_session: bool,
    remote_consent: bool,
}

impl Features {
    fn from(list: &[String]) -> Features {
        Features {
            remote_session: list
                .iter()
                .any(|f| f == kestrel_common::tray::FEATURE_REMOTE_SESSION),
            remote_consent: list
                .iter()
                .any(|f| f == kestrel_common::tray::FEATURE_REMOTE_CONSENT),
        }
    }

    /// May this push kind go to a connection with these opt-ins?
    fn allows(&self, resp: &TrayResponse) -> bool {
        match resp {
            TrayResponse::RemoteSession(_) => self.remote_session,
            TrayResponse::ConsentRequest(_) => self.remote_consent,
            _ => true,
        }
    }
}

use tokio::io::AsyncReadExt as _;

/// Send one request over an established tray connection and read one response.
pub async fn request<S>(stream: S, req: &TrayRequest) -> Result<TrayResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut line = serde_json::to_vec(req)?;
    line.push(b'\n');
    wr.write_all(&line).await?;
    wr.flush().await?;
    let mut rd = BufReader::new(rd);
    let mut resp = String::new();
    let n = rd.read_line(&mut resp).await?;
    if n == 0 {
        return Err(anyhow!("agent closed the connection"));
    }
    Ok(serde_json::from_str(resp.trim())?)
}

/// Connect to a running agent's tray endpoint in `state_dir` and issue `req`.
///
/// * Unix (simulator): `<state>/tray.sock`.
/// * Windows: `<state>/tray.port` (simulator TCP listener) if present,
///   else the service's named pipe `\\.\pipe\kestrel-tray`.
pub async fn query(state_dir: &std::path::Path, req: &TrayRequest) -> Result<TrayResponse> {
    let fut = async {
        #[cfg(unix)]
        {
            let s = tokio::net::UnixStream::connect(state_dir.join(crate::sim::TRAY_SOCK)).await?;
            request(s, req).await
        }
        #[cfg(windows)]
        {
            let port_file = state_dir.join(crate::sim::TRAY_PORT_FILE);
            if let Ok(p) = std::fs::read_to_string(&port_file) {
                let port: u16 = p.trim().parse()?;
                let s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                return request(s, req).await;
            }
            let s = tokio::net::windows::named_pipe::ClientOptions::new()
                .open(kestrel_common::TRAY_PIPE_NAME)?;
            request(s, req).await
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (state_dir, req);
            Err(anyhow!("tray transport unsupported on this OS"))
        }
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), fut)
        .await
        .map_err(|_| anyhow!("timed out talking to the agent"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::tray::ActivityItem;

    struct Echo(broadcast::Sender<TrayPush>);

    #[async_trait::async_trait]
    impl TrayHandler for Echo {
        async fn handle(&self, req: TrayRequest, _c: &TrayClient) -> TrayResponse {
            match req {
                TrayRequest::Activity { limit } => TrayResponse::Ack {
                    ok: true,
                    message: limit.to_string(),
                },
                _ => TrayResponse::Ack {
                    ok: true,
                    message: "ok".into(),
                },
            }
        }
        fn subscribe(&self) -> broadcast::Receiver<TrayPush> {
            self.0.subscribe()
        }
    }

    #[test]
    fn rate_limits() {
        let mut l = TrayLimits::default();
        for i in 0..REVIEWS_PER_HOUR as i64 {
            assert!(l.allow_review("corp\\alice", i));
        }
        assert!(!l.allow_review("corp\\alice", 10));
        assert!(l.allow_review("corp\\bob", 10), "per user");
        assert!(l.allow_review("corp\\alice", 3_600_000), "window slides");
        assert!(l.recent_check(0).is_none());
        l.record_check(1_000, true, "clean".into());
        assert_eq!(
            l.recent_check(1_000 + CHECK_INTERVAL_MS - 1).unwrap().2,
            "clean"
        );
        assert!(l.recent_check(1_000 + CHECK_INTERVAL_MS).is_none());
    }

    #[tokio::test]
    async fn framing_and_push() {
        let (tx, _) = broadcast::channel(8);
        let h: Arc<dyn TrayHandler> = Arc::new(Echo(tx.clone()));
        let (a, b) = tokio::io::duplex(4096);
        let me = TrayClient {
            user_sid: Some("S-1-5-21-1-1001".into()),
            user: Some("CORP\\alice".into()),
            ..Default::default()
        };
        tokio::spawn(serve_connection(a, h, me));
        let (rd, mut wr) = tokio::io::split(b);
        let mut rd = BufReader::new(rd);
        wr.write_all(b"{\"op\":\"activity\"}\nnot json\n{\"op\":\"subscribe\"}\n")
            .await
            .unwrap();
        let mut l = String::new();
        rd.read_line(&mut l).await.unwrap();
        assert_eq!(
            serde_json::from_str::<TrayResponse>(&l).unwrap(),
            TrayResponse::Ack {
                ok: true,
                message: "50".into()
            }
        );
        l.clear();
        rd.read_line(&mut l).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<TrayResponse>(&l).unwrap(),
            TrayResponse::Error { .. }
        ));
        l.clear();
        rd.read_line(&mut l).await.unwrap();
        // Push after subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let item = ActivityItem {
            id: uuid::Uuid::new_v4(),
            ts: 1,
            title: "t".into(),
            body: String::new(),
            severity: kestrel_common::Severity::High,
            alert_id: None,
            file: None,
            action_taken: String::new(),
            review: None,
        };
        // Another user's notification is not forwarded; ours and public ones are.
        let mut other = item.clone();
        other.title = "bob's".into();
        tx.send(TrayPush {
            audience: kestrel_platform::Audience::Owner("corp\\bob".into()),
            resp: TrayResponse::Notification(other),
        })
        .unwrap();
        tx.send(TrayPush {
            audience: kestrel_platform::Audience::Owner("s-1-5-21-1-1001".into()),
            resp: TrayResponse::Notification(item.clone()),
        })
        .unwrap();
        l.clear();
        rd.read_line(&mut l).await.unwrap();
        assert_eq!(
            serde_json::from_str::<TrayResponse>(&l).unwrap(),
            TrayResponse::Notification(item)
        );
    }

    fn remote_notice(active: bool) -> TrayResponse {
        TrayResponse::RemoteSession(kestrel_common::tray::RemoteSessionNotice {
            active,
            kind: kestrel_common::tray::RemoteKind::Desktop,
            admin_name: "Jane".into(),
            view_only: true,
            reason: String::new(),
            started_at: 1,
            ended_at: None,
        })
    }

    /// Subscribe on a fresh connection with `req`, then push a
    /// `RemoteSession` followed by a marker notification; return what the
    /// client received after the subscription ack.
    async fn pushes_after(req: &str) -> Vec<TrayResponse> {
        let (tx, _) = broadcast::channel(8);
        let h: Arc<dyn TrayHandler> = Arc::new(Echo(tx.clone()));
        let (a, b) = tokio::io::duplex(4096);
        tokio::spawn(serve_connection(a, h, TrayClient::default()));
        let (rd, mut wr) = tokio::io::split(b);
        let mut rd = BufReader::new(rd);
        wr.write_all(
            format!(
                "{req}
"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
        let mut l = String::new();
        rd.read_line(&mut l).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<TrayResponse>(&l).unwrap(),
            TrayResponse::Ack { ok: true, .. }
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let marker = TrayResponse::Error {
            message: "marker".into(),
        };
        let consent = TrayResponse::ConsentRequest(kestrel_common::tray::ConsentRequest {
            request_id: uuid::Uuid::nil(),
            kind: kestrel_common::tray::RemoteKind::Files,
            admin_name: "Jane".into(),
            view_only: false,
            reason: String::new(),
            timeout_secs: 60,
            expires_at: 0,
        });
        for resp in [remote_notice(true), consent, marker.clone()] {
            tx.send(TrayPush {
                audience: kestrel_platform::Audience::Public,
                resp,
            })
            .unwrap();
        }
        let mut got = vec![];
        loop {
            l.clear();
            rd.read_line(&mut l).await.unwrap();
            let r: TrayResponse = serde_json::from_str(&l).unwrap();
            let done = r == marker;
            got.push(r);
            if done {
                return got;
            }
        }
    }

    #[tokio::test]
    async fn remote_session_pushes_only_for_opted_in_trays() {
        // Older tray: plain Subscribe never sees the new response type.
        let got = pushes_after(r#"{"op":"subscribe"}"#).await;
        assert_eq!(got.len(), 1, "{got:?}");
        // SubscribeWith without the feature: same.
        let got = pushes_after(r#"{"op":"subscribe_with","features":["other"]}"#).await;
        assert_eq!(got.len(), 1, "{got:?}");
        // Opted in to session notices only.
        let got = pushes_after(r#"{"op":"subscribe_with","features":["remote_session"]}"#).await;
        assert_eq!(got.len(), 2, "{got:?}");
        assert_eq!(got[0], remote_notice(true));
        // Both.
        let got = pushes_after(
            r#"{"op":"subscribe_with","features":["remote_session","remote_consent"]}"#,
        )
        .await;
        assert_eq!(got.len(), 3, "{got:?}");
        assert!(matches!(got[1], TrayResponse::ConsentRequest(_)));
    }
}
