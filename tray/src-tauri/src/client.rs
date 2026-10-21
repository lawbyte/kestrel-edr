//! Client for the agent's tray protocol (JSON lines).
//!
//! Transports:
//! - Windows: named pipe `\\.\pipe\kestrel-tray` (tokio named-pipe client). The
//!   client opens with `SECURITY_IDENTIFICATION` QoS (tokio's default) so the
//!   server cannot impersonate the user, and verifies the pipe server runs in
//!   session 0 (i.e. is a service), so an unprivileged process that squats the
//!   pipe name cannot feed fake status or toasts to the employee.
//! - Elsewhere (development): Unix socket at `$KESTREL_TRAY_SOCK` (the agent
//!   simulator serves the same protocol there).
//! - `KESTREL_TRAY_MOCK=1`: a built-in in-process mock agent (see `mock.rs`).
//!
//! Requests use a short-lived connection each (one request → one response).
//! Pushes use a long-lived `Subscribe` connection managed by `run_subscriber`.

use crate::protocol::{TrayRequest, TrayResponse};
use serde::Serialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Pipe name; must equal `kestrel_common::TRAY_PIPE_NAME`.
pub const TRAY_PIPE_NAME: &str = r"\\.\pipe\kestrel-tray";
/// Upper bound for one protocol line (status carries the privacy notice).
const MAX_LINE: u64 = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type Conn = BufReader<Box<dyn Stream>>;

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "kind", content = "message", rename_all = "snake_case")]
pub enum ClientError {
    /// The agent service isn't reachable (not running, not installed, or untrusted).
    Unavailable(String),
    Timeout(String),
    Protocol(String),
    /// The agent answered with `Error { message }`.
    Agent(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Unavailable(m) => write!(f, "agent unavailable: {m}"),
            ClientError::Timeout(m) => write!(f, "timed out: {m}"),
            ClientError::Protocol(m) => write!(f, "protocol error: {m}"),
            ClientError::Agent(m) => write!(f, "agent error: {m}"),
        }
    }
}
impl std::error::Error for ClientError {}

pub enum Backend {
    #[cfg_attr(not(windows), allow(dead_code))]
    Pipe,
    #[cfg(unix)]
    Unix(std::path::PathBuf),
    Mock(Arc<crate::mock::MockAgent>),
    /// Nothing configured (non-Windows without socket or mock).
    #[cfg_attr(windows, allow(dead_code))]
    None,
}

pub struct Client {
    backend: Backend,
}

impl Client {
    pub fn new(backend: Backend) -> Self {
        Client { backend }
    }

    pub fn from_env() -> Self {
        if std::env::var("KESTREL_TRAY_MOCK")
            .map(|v| v == "1")
            .unwrap_or(false)
        {
            return Client::new(Backend::Mock(Arc::new(crate::mock::MockAgent::new())));
        }
        #[cfg(windows)]
        {
            Client::new(Backend::Pipe)
        }
        #[cfg(unix)]
        {
            match std::env::var_os("KESTREL_TRAY_SOCK") {
                Some(p) if !p.is_empty() => Client::new(Backend::Unix(p.into())),
                _ => Client::new(Backend::None),
            }
        }
    }

    pub fn describe(&self) -> String {
        match &self.backend {
            Backend::Pipe => TRAY_PIPE_NAME.to_string(),
            #[cfg(unix)]
            Backend::Unix(p) => format!("unix:{}", p.display()),
            Backend::Mock(_) => "mock".into(),
            Backend::None => "none (set KESTREL_TRAY_SOCK or KESTREL_TRAY_MOCK=1)".into(),
        }
    }

    pub async fn connect(&self) -> Result<Conn, ClientError> {
        self.connect_checked(false).await
    }

    /// `strict`: the request carries a secret (the uninstall token), so on
    /// Windows the pipe server must also be the installed `kestrel-agent.exe`
    /// next to this tray, not just any session-0 process (a service account
    /// such as NETWORK SERVICE could add a pipe instance and collect it).
    async fn connect_checked(&self, strict: bool) -> Result<Conn, ClientError> {
        let stream: Box<dyn Stream> = match &self.backend {
            Backend::Pipe => {
                #[cfg(windows)]
                {
                    let pipe = win::open_pipe().await?;
                    if strict {
                        win::verify_agent_image(&pipe)?;
                    }
                    Box::new(pipe)
                }
                #[cfg(not(windows))]
                {
                    let _ = strict;
                    return Err(ClientError::Unavailable("named pipes need Windows".into()));
                }
            }
            #[cfg(unix)]
            Backend::Unix(path) => {
                let s =
                    tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::UnixStream::connect(path))
                        .await
                        .map_err(|_| ClientError::Unavailable("connect timed out".into()))?
                        .map_err(|e| ClientError::Unavailable(e.to_string()))?;
                Box::new(s)
            }
            Backend::Mock(m) => Box::new(m.connect()),
            Backend::None => {
                return Err(ClientError::Unavailable(
                    "no agent transport configured".into(),
                ))
            }
        };
        Ok(BufReader::new(stream))
    }

    /// Send one request on a fresh connection and wait for its single response.
    pub async fn request(
        &self,
        req: &TrayRequest,
        timeout: Duration,
    ) -> Result<TrayResponse, ClientError> {
        let strict = matches!(req, TrayRequest::PauseProtection { .. });
        let mut conn = self.connect_checked(strict).await?;
        let fut = async {
            send(&mut conn, req).await?;
            match read_response(&mut conn).await? {
                Some(TrayResponse::Error { message }) => Err(ClientError::Agent(message)),
                Some(r) => Ok(r),
                None => Err(ClientError::Unavailable(
                    "agent closed the connection".into(),
                )),
            }
        };
        tokio::time::timeout(timeout, fut)
            .await
            // Only the op name: a request may carry the uninstall token.
            .map_err(|_| ClientError::Timeout(req.op().to_string()))?
    }
}

pub async fn send(conn: &mut Conn, req: &TrayRequest) -> Result<(), ClientError> {
    let mut line = serde_json::to_vec(req).map_err(|e| ClientError::Protocol(e.to_string()))?;
    line.push(b'\n');
    let w = conn.get_mut();
    w.write_all(&line)
        .await
        .map_err(|e| ClientError::Unavailable(e.to_string()))?;
    w.flush()
        .await
        .map_err(|e| ClientError::Unavailable(e.to_string()))
}

/// Read one response line. `Ok(None)` on clean EOF. Blank lines are skipped.
pub async fn read_response(conn: &mut Conn) -> Result<Option<TrayResponse>, ClientError> {
    match read_response_lenient(conn).await? {
        None => Ok(None),
        Some(r) => r.map(Some).map_err(ClientError::Protocol),
    }
}

/// Like [`read_response`], but a line that is valid framing yet can't be parsed
/// (e.g. an unknown response `type` from a newer agent) comes back as
/// `Ok(Some(Err(reason)))` so a long-lived reader can log it and keep going.
/// Transport errors and over-long lines are still fatal (`Err`).
pub async fn read_response_lenient(
    conn: &mut Conn,
) -> Result<Option<Result<TrayResponse, String>>, ClientError> {
    loop {
        let mut line = String::new();
        let n = (&mut *conn)
            .take(MAX_LINE)
            .read_line(&mut line)
            .await
            .map_err(|e| ClientError::Unavailable(e.to_string()))?;
        if n == 0 {
            return Ok(None);
        }
        if !line.ends_with('\n') && n as u64 >= MAX_LINE {
            return Err(ClientError::Protocol("response line too long".into()));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return Ok(Some(
            serde_json::from_str(trimmed).map_err(|e| e.to_string()),
        ));
    }
}

/// An open push subscription.
pub struct Subscription {
    pub conn: Conn,
    /// Opt-in features the agent accepted (empty after the plain fallback).
    pub features: Vec<String>,
}

/// Open the long-lived push connection. Sends `SubscribeWith { features }`
/// first; an older agent answers `Error` (unknown op), in which case a fresh
/// connection is opened with plain `Subscribe`. Expects `Ack { ok: true }`.
pub async fn open_subscription(
    client: &Client,
    features: &[&str],
    timeout: Duration,
) -> Result<Subscription, ClientError> {
    let features: Vec<String> = features.iter().map(|f| f.to_string()).collect();
    if !features.is_empty() {
        let mut conn = client.connect().await?;
        let req = TrayRequest::SubscribeWith {
            features: features.clone(),
        };
        match subscribe_ack(&mut conn, &req, timeout).await {
            Ok(()) => return Ok(Subscription { conn, features }),
            Err(ClientError::Agent(m)) => {
                log::info!("agent rejected subscribe_with ({m}); falling back to subscribe");
            }
            Err(e) => return Err(e),
        }
    }
    let mut conn = client.connect().await?;
    subscribe_ack(&mut conn, &TrayRequest::Subscribe, timeout).await?;
    Ok(Subscription {
        conn,
        features: Vec::new(),
    })
}

async fn subscribe_ack(
    conn: &mut Conn,
    req: &TrayRequest,
    timeout: Duration,
) -> Result<(), ClientError> {
    send(conn, req).await?;
    match tokio::time::timeout(timeout, read_response(conn)).await {
        Ok(Ok(Some(TrayResponse::Ack { ok: true, .. }))) => Ok(()),
        Ok(Ok(Some(TrayResponse::Error { message }))) => Err(ClientError::Agent(message)),
        Ok(Ok(Some(other))) => Err(ClientError::Protocol(format!(
            "expected ack, got {other:?}"
        ))),
        Ok(Ok(None)) => Err(ClientError::Unavailable("closed during subscribe".into())),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ClientError::Timeout("subscribe".into())),
    }
}

/// Is `actual` (the pipe server's image, `QueryFullProcessImageNameW`) the
/// agent `expected` next to the tray? Case-insensitive, `\\?\` ignored.
pub fn same_image(actual: &str, expected: &std::path::Path) -> bool {
    fn norm(s: &str) -> String {
        let s = s.trim().replace('/', "\\");
        let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
        s.to_ascii_lowercase()
    }
    let e = norm(&expected.to_string_lossy());
    !e.is_empty() && norm(actual) == e
}

/// Exponential backoff with jitter: 1s, 2s, 4s … capped at 30s.
pub fn backoff(attempt: u32) -> Duration {
    let base = 1000u64.saturating_mul(1u64 << attempt.min(5)).min(30_000);
    let jitter =
        (crate::protocol::now_ms() as u64 ^ (attempt as u64).wrapping_mul(0x9E37)) % (base / 4 + 1);
    Duration::from_millis(base - base / 8 + jitter)
}

#[cfg(windows)]
mod win {
    use super::{ClientError, CONNECT_TIMEOUT, TRAY_PIPE_NAME};
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient};

    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PIPE_BUSY: i32 = 231;

    pub async fn open_pipe() -> Result<NamedPipeClient, ClientError> {
        let deadline = tokio::time::Instant::now() + CONNECT_TIMEOUT;
        let client = loop {
            match ClientOptions::new().open(TRAY_PIPE_NAME) {
                Ok(c) => break c,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(e) if e.raw_os_error() == Some(ERROR_FILE_NOT_FOUND) => {
                    return Err(ClientError::Unavailable(
                        "Kestrel service is not running".into(),
                    ));
                }
                Err(e) => return Err(ClientError::Unavailable(e.to_string())),
            }
        };
        verify_server(&client)?;
        Ok(client)
    }

    /// Before sending the uninstall token: the server process must be the
    /// installed agent image (`kestrel-agent.exe` in the tray's own folder,
    /// which only administrators can write).
    pub fn verify_agent_image(client: &NamedPipeClient) -> Result<(), ClientError> {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
        };
        if cfg!(debug_assertions) && std::env::var_os("KESTREL_TRAY_ALLOW_USER_SERVER").is_some() {
            return Ok(());
        }
        let refuse = |why: &str| {
            log::warn!("refusing to send the token: {why}");
            Err(ClientError::Unavailable(
                "could not verify that the Kestrel service answers on the tray pipe".into(),
            ))
        };
        let mut pid: u32 = 0;
        if unsafe { GetNamedPipeServerProcessId(client.as_raw_handle() as _, &mut pid) } == 0
            || pid == 0
        {
            return refuse("no server process id");
        }
        let ph = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if ph.is_null() {
            return refuse("server process not accessible");
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = unsafe { QueryFullProcessImageNameW(ph, 0, buf.as_mut_ptr(), &mut len) };
        unsafe { CloseHandle(ph) };
        if ok == 0 {
            return refuse("server image unknown");
        }
        let actual = String::from_utf16_lossy(&buf[..(len as usize).min(buf.len())]);
        let expected = match std::env::current_exe() {
            Ok(p) => p.with_file_name("kestrel-agent.exe"),
            Err(_) => return refuse("own path unknown"),
        };
        if !super::same_image(&actual, &expected) {
            return refuse(&format!(
                "server image {actual} is not {}",
                expected.display()
            ));
        }
        Ok(())
    }

    /// Only trust a pipe served from session 0 (Windows services). Interactive
    /// user processes always run in session >= 1, so a squatter can't pass.
    fn verify_server(client: &NamedPipeClient) -> Result<(), ClientError> {
        use windows_sys::Win32::System::Pipes::GetNamedPipeServerSessionId;
        let mut session: u32 = u32::MAX;
        let ok = unsafe { GetNamedPipeServerSessionId(client.as_raw_handle() as _, &mut session) };
        if ok == 0 {
            return Err(ClientError::Unavailable(
                "could not verify the Kestrel service".into(),
            ));
        }
        if session != 0
            && !(cfg!(debug_assertions)
                && std::env::var_os("KESTREL_TRAY_ALLOW_USER_SERVER").is_some())
        {
            log::warn!("refusing tray pipe served from session {session} (expected 0)");
            return Err(ClientError::Unavailable(
                "the tray pipe is not served by the Kestrel service".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::*;

    #[tokio::test]
    async fn mock_roundtrip_and_pushes() {
        let c = Client::new(Backend::Mock(Arc::new(crate::mock::MockAgent::new())));
        let r = c
            .request(&TrayRequest::Status, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(matches!(r, TrayResponse::Status(ref s) if !s.org_name.is_empty()));
        let r = c
            .request(&TrayRequest::Activity { limit: 2 }, Duration::from_secs(2))
            .await
            .unwrap();
        let TrayResponse::Activity { items } = r else {
            panic!("expected activity")
        };
        assert_eq!(items.len(), 2);
        let alert = items.iter().find_map(|i| i.alert_id).unwrap();

        let mut sub = c.connect().await.unwrap();
        send(&mut sub, &TrayRequest::Subscribe).await.unwrap();
        assert!(matches!(
            read_response(&mut sub).await.unwrap(),
            Some(TrayResponse::Ack { ok: true, .. })
        ));

        let r = c
            .request(
                &TrayRequest::RequestReview {
                    alert_id: alert,
                    justification: "I need this".into(),
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(matches!(r, TrayResponse::Ack { ok: true, .. }));
        // The review request is pushed back as an updated notification.
        let push = read_response(&mut sub).await.unwrap().unwrap();
        let TrayResponse::Notification(item) = push else {
            panic!("expected push, got {push:?}")
        };
        assert_eq!(item.review, Some(ReviewState::Requested));
    }

    #[tokio::test]
    async fn agent_error_maps_to_error() {
        let c = Client::new(Backend::Mock(Arc::new(crate::mock::MockAgent::new())));
        let r = c
            .request(
                &TrayRequest::RequestReview {
                    alert_id: uuid::Uuid::nil(),
                    justification: "x".into(),
                },
                Duration::from_secs(2),
            )
            .await;
        assert!(matches!(r, Err(ClientError::Agent(_))));
    }

    #[tokio::test]
    async fn subscribe_with_gets_remote_session_pushes() {
        let mock = Arc::new(crate::mock::MockAgent::new());
        let c = Client::new(Backend::Mock(mock.clone()));
        let mut sub = open_subscription(&c, &[FEATURE_REMOTE_SESSION], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(sub.features, vec![FEATURE_REMOTE_SESSION.to_string()]);
        // A plain subscriber on the same agent must never see RemoteSession.
        let mut plain = open_subscription(&c, &[], Duration::from_secs(2))
            .await
            .unwrap();
        assert!(plain.features.is_empty());

        let notice = crate::mock::sample_remote_session(false);
        mock.start_remote_session(notice.clone());
        let push = read_response(&mut sub.conn).await.unwrap().unwrap();
        assert_eq!(push, TrayResponse::RemoteSession(notice.clone()));
        let TrayResponse::Notification(item) = read_response(&mut sub.conn).await.unwrap().unwrap()
        else {
            panic!("expected notification")
        };
        assert_eq!(item.action_taken, "Remote session started");
        let TrayResponse::Notification(item) =
            read_response(&mut plain.conn).await.unwrap().unwrap()
        else {
            panic!("plain subscriber must get the notification first")
        };
        assert_eq!(item.action_taken, "Remote session started");

        // Status carries the active session.
        let TrayResponse::Status(s) = c
            .request(&TrayRequest::Status, Duration::from_secs(2))
            .await
            .unwrap()
        else {
            panic!("status")
        };
        assert_eq!(s.remote_session, Some(notice));

        mock.end_remote_session();
        let TrayResponse::RemoteSession(n) = read_response(&mut sub.conn).await.unwrap().unwrap()
        else {
            panic!("expected remote_session end")
        };
        assert!(!n.active && n.ended_at.is_some());
        let TrayResponse::Notification(item) =
            read_response(&mut plain.conn).await.unwrap().unwrap()
        else {
            panic!("plain subscriber must skip remote_session and see the end notification")
        };
        assert_eq!(item.action_taken, "Remote session ended");
    }

    #[tokio::test]
    async fn consent_request_push_and_answer() {
        let mock = Arc::new(crate::mock::MockAgent::new());
        let c = Client::new(Backend::Mock(mock.clone()));
        let mut sub = open_subscription(
            &c,
            &[FEATURE_REMOTE_SESSION, FEATURE_REMOTE_CONSENT],
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        // A subscriber without remote_consent never sees the prompt.
        let mut no_consent =
            open_subscription(&c, &[FEATURE_REMOTE_SESSION], Duration::from_secs(2))
                .await
                .unwrap();

        let req = mock.request_consent(RemoteKind::Files, false, 60);
        assert_eq!(
            read_response(&mut sub.conn).await.unwrap().unwrap(),
            TrayResponse::ConsentRequest(req.clone())
        );

        // Deny is acknowledged; the same id can't be answered twice.
        let deny = TrayRequest::ConsentResponse {
            request_id: req.request_id,
            allow: false,
        };
        let r = c.request(&deny, Duration::from_secs(2)).await.unwrap();
        assert!(matches!(r, TrayResponse::Ack { ok: true, .. }));
        assert!(matches!(
            c.request(&deny, Duration::from_secs(2)).await,
            Err(ClientError::Agent(_))
        ));

        // Allow starts a matching session.
        let req = mock.request_consent(RemoteKind::Desktop, true, 60);
        let _ = read_response(&mut sub.conn).await.unwrap().unwrap();
        let r = c
            .request(
                &TrayRequest::ConsentResponse {
                    request_id: req.request_id,
                    allow: true,
                },
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(matches!(r, TrayResponse::Ack { ok: true, .. }));
        let TrayResponse::RemoteSession(n) = read_response(&mut sub.conn).await.unwrap().unwrap()
        else {
            panic!("expected remote_session")
        };
        assert!(n.active && n.view_only && n.kind == RemoteKind::Desktop);
        // The no-consent subscriber's first push is the session, not a prompt.
        assert!(matches!(
            read_response(&mut no_consent.conn).await.unwrap().unwrap(),
            TrayResponse::RemoteSession(_)
        ));
    }

    #[tokio::test]
    async fn subscribe_falls_back_on_older_agent() {
        let mock = Arc::new(crate::mock::MockAgent::legacy());
        let c = Client::new(Backend::Mock(mock.clone()));
        let mut sub = open_subscription(&c, &[FEATURE_REMOTE_SESSION], Duration::from_secs(2))
            .await
            .unwrap();
        assert!(sub.features.is_empty(), "fell back to plain subscribe");
        mock.start_remote_session(crate::mock::sample_remote_session(true));
        // Only the regular notification arrives on a plain subscription.
        let TrayResponse::Notification(item) = read_response(&mut sub.conn).await.unwrap().unwrap()
        else {
            panic!("expected notification")
        };
        assert_eq!(item.action_taken, "Remote session started");
    }

    #[test]
    fn same_image_matches_installed_agent_only() {
        let exp = std::path::Path::new(r"C:\Program Files\Kestrel\kestrel-agent.exe");
        assert!(same_image(
            r"C:\Program Files\Kestrel\kestrel-agent.exe",
            exp
        ));
        assert!(same_image(
            r"\\?\c:\program files\kestrel\KESTREL-AGENT.EXE",
            exp
        ));
        assert!(!same_image(r"C:\Users\Public\kestrel-agent.exe", exp));
        assert!(!same_image(r"C:\Windows\System32\svchost.exe", exp));
        assert!(!same_image("", std::path::Path::new("")));
    }

    async fn ask(c: &Client, req: TrayRequest) -> PauseResult {
        match c.request(&req, Duration::from_secs(5)).await.unwrap() {
            TrayResponse::PauseResult(r) => r,
            other => panic!("expected pause_result, got {other:?}"),
        }
    }

    fn pause(token: &str, mode: PauseMode, minutes: Option<u32>) -> TrayRequest {
        TrayRequest::PauseProtection {
            token: TokenInput(token.into()),
            mode,
            minutes,
        }
    }

    #[tokio::test]
    async fn pause_wrong_tokens_lock_out() {
        let c = Client::new(Backend::Mock(Arc::new(crate::mock::MockAgent::new())));
        for left in (1..=4).rev() {
            let r = ask(&c, pause("nope", PauseMode::DetectionOnly, Some(60))).await;
            assert_eq!(
                (r.ok, r.error, r.attempts_left),
                (false, Some(PauseError::WrongToken), Some(left))
            );
        }
        let r = ask(&c, pause("nope", PauseMode::DetectionOnly, Some(60))).await;
        assert_eq!(r.error, Some(PauseError::LockedOut));
        let until = r.locked_until_ms.unwrap();
        let left = until - now_ms();
        assert!(left > 55_000 && left <= 60_000, "{left}");
        // Even the right token is refused while locked, and status says so.
        let r = ask(
            &c,
            pause(crate::mock::MOCK_TOKEN, PauseMode::DetectionOnly, Some(60)),
        )
        .await;
        assert_eq!(r.error, Some(PauseError::LockedOut));
        let TrayResponse::Status(s) = c
            .request(&TrayRequest::Status, Duration::from_secs(2))
            .await
            .unwrap()
        else {
            panic!("status")
        };
        assert_eq!(s.local_pause.unwrap().locked_until_ms, Some(until));
        assert!(s.pause.is_none());
    }

    #[tokio::test]
    async fn pause_policy_success_and_resume() {
        let mock = Arc::new(crate::mock::MockAgent::new());
        let c = Client::new(Backend::Mock(mock.clone()));
        let mut sub = open_subscription(&c, &[], Duration::from_secs(2))
            .await
            .unwrap();
        let r = ask(
            &c,
            pause(crate::mock::MOCK_TOKEN, PauseMode::DetectionOnly, Some(7)),
        )
        .await;
        assert_eq!(
            (r.error, r.denied),
            (
                Some(PauseError::NotAllowed),
                Some(PauseDenied::DurationNotAllowed)
            )
        );
        let r = ask(&c, pause(crate::mock::MOCK_TOKEN, PauseMode::Full, None)).await;
        assert!(r.ok, "{r:?}");
        let state = r.state.unwrap();
        assert_eq!((state.mode, state.until_ms), (PauseMode::Full, None));
        let TrayResponse::Notification(item) = read_response(&mut sub.conn).await.unwrap().unwrap()
        else {
            panic!("expected notification")
        };
        assert_eq!(item.action_taken, "Protection turned off");
        let r = ask(&c, pause(crate::mock::MOCK_TOKEN, PauseMode::Full, None)).await;
        assert_eq!(r.error, Some(PauseError::AlreadyOff));
        let r = ask(&c, TrayRequest::ResumeProtection).await;
        assert!(r.ok && r.state.is_none());
        let r = ask(&c, TrayRequest::ResumeProtection).await;
        assert_eq!(r.error, Some(PauseError::NotOff));
    }

    #[tokio::test]
    async fn pause_on_older_agent_is_an_agent_error() {
        let c = Client::new(Backend::Mock(Arc::new(crate::mock::MockAgent::legacy())));
        let TrayResponse::Status(s) = c
            .request(&TrayRequest::Status, Duration::from_secs(2))
            .await
            .unwrap()
        else {
            panic!("status")
        };
        assert!(s.local_pause.is_none());
        let r = c
            .request(
                &pause("kun_secret", PauseMode::DetectionOnly, Some(15)),
                Duration::from_secs(2),
            )
            .await;
        let Err(ClientError::Agent(m)) = r else {
            panic!("expected agent error, got {r:?}")
        };
        assert!(!m.contains("kun_secret"));
    }

    #[tokio::test]
    async fn lenient_reader_skips_unknown_types() {
        let (client_side, mut server_side) = tokio::io::duplex(4096);
        let mut conn: Conn = BufReader::new(Box::new(client_side));
        server_side
            .write_all(b"{\"type\":\"from_the_future\",\"x\":1}\n\n{\"type\":\"ack\",\"ok\":true,\"message\":\"m\"}\n")
            .await
            .unwrap();
        drop(server_side);
        let first = read_response_lenient(&mut conn).await.unwrap().unwrap();
        assert!(first.is_err());
        let second = read_response_lenient(&mut conn).await.unwrap().unwrap();
        assert!(matches!(second, Ok(TrayResponse::Ack { ok: true, .. })));
        assert!(read_response_lenient(&mut conn).await.unwrap().is_none());
    }

    #[test]
    fn backoff_is_capped() {
        assert!(backoff(0) <= Duration::from_millis(1300));
        assert!(backoff(20) <= Duration::from_secs(34));
        assert!(backoff(20) >= Duration::from_secs(26));
    }
}
