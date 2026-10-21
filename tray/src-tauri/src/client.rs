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
        let stream: Box<dyn Stream> = match &self.backend {
            Backend::Pipe => {
                #[cfg(windows)]
                {
                    Box::new(win::open_pipe().await?)
                }
                #[cfg(not(windows))]
                {
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
        let mut conn = self.connect().await?;
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
            .map_err(|_| ClientError::Timeout(format!("{req:?}")))?
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
        return serde_json::from_str(trimmed)
            .map(Some)
            .map_err(|e| ClientError::Protocol(e.to_string()));
    }
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

    #[test]
    fn backoff_is_capped() {
        assert!(backoff(0) <= Duration::from_millis(1300));
        assert!(backoff(20) <= Duration::from_secs(34));
        assert!(backoff(20) >= Duration::from_secs(26));
    }
}
