//! Tray protocol connection handling (transport independent).
//!
//! JSON lines per `kestrel_common::tray`: each request gets exactly one
//! response; after `Subscribe` / `SubscribeWith` the agent's broadcast
//! notifications are pushed on the same connection. Opt-in push kinds
//! (`RemoteSession`, `ConsentRequest`) reach only connections that asked for
//! them with `SubscribeWith { features }`, so an older tray never receives a
//! response type it cannot parse. Lines are capped at [`MAX_LINE`] bytes; an
//! oversized line gets an `Error` response and the connection is closed. The
//! Windows module runs this over `\\.\pipe\kestrel-tray`; tests use an
//! in-memory duplex.

use kestrel_common::tray::{
    TrayRequest, TrayResponse, FEATURE_REMOTE_CONSENT, FEATURE_REMOTE_SESSION,
};
use kestrel_platform::{TrayClient, TrayHandler};
use std::io;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{broadcast, mpsc};

pub const MAX_LINE: usize = 64 * 1024;

/// Read one `\n`-terminated line (without the terminator) into `buf`.
/// Returns `Ok(false)` at clean EOF; errors with `InvalidData` past `max`.
pub async fn read_line_bounded<R: AsyncBufRead + Unpin>(
    r: &mut R,
    max: usize,
    buf: &mut Vec<u8>,
) -> io::Result<bool> {
    buf.clear();
    loop {
        let available = r.fill_buf().await?;
        if available.is_empty() {
            return Ok(!buf.is_empty());
        }
        if let Some(i) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + i > max {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            buf.extend_from_slice(&available[..i]);
            r.consume(i + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return Ok(true);
        }
        let n = available.len();
        if buf.len() + n > max {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
        }
        buf.extend_from_slice(available);
        r.consume(n);
    }
}

/// Opt-in push kinds of one connection (bit set).
pub const PUSH_REMOTE_SESSION: u8 = 1;
pub const PUSH_REMOTE_CONSENT: u8 = 2;

/// Opt-in bits for `SubscribeWith.features` (unknown features ignored).
pub fn feature_bits(features: &[String]) -> u8 {
    features.iter().fold(0, |acc, f| match f.as_str() {
        FEATURE_REMOTE_SESSION => acc | PUSH_REMOTE_SESSION,
        FEATURE_REMOTE_CONSENT => acc | PUSH_REMOTE_CONSENT,
        _ => acc,
    })
}

/// May `resp` be pushed to a connection with opt-in bits `bits`?
pub fn push_allowed(resp: &TrayResponse, bits: u8) -> bool {
    match resp {
        TrayResponse::RemoteSession(_) => bits & PUSH_REMOTE_SESSION != 0,
        TrayResponse::ConsentRequest(_) => bits & PUSH_REMOTE_CONSENT != 0,
        _ => true,
    }
}

fn encode(resp: &TrayResponse) -> Vec<u8> {
    let mut v = serde_json::to_vec(resp)
        .unwrap_or_else(|_| br#"{"type":"error","message":"encode failed"}"#.to_vec());
    v.push(b'\n');
    v
}

/// Serve one tray connection until EOF / error. `client` is the identity the
/// transport established for the peer (M3): requests are answered for it and
/// only notifications visible to it are forwarded.
pub async fn handle_connection<S>(
    stream: S,
    handler: Arc<dyn TrayHandler>,
    client: TrayClient,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<TrayResponse>(64);
    let writer = tokio::spawn(async move {
        while let Some(resp) = rx.recv().await {
            if wr.write_all(&encode(&resp)).await.is_err() || wr.flush().await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    let mut reader = BufReader::new(rd);
    let mut line = Vec::new();
    let mut forwarder: Option<tokio::task::JoinHandle<()>> = None;
    let bits = Arc::new(AtomicU8::new(0));
    let result = loop {
        match read_line_bounded(&mut reader, MAX_LINE, &mut line).await {
            Ok(false) => break Ok(()),
            Ok(true) => {}
            Err(e) => {
                let _ = tx
                    .send(TrayResponse::Error {
                        message: format!("request rejected: {e}"),
                    })
                    .await;
                break Err(e);
            }
        }
        if line.iter().all(|b| b.is_ascii_whitespace()) {
            continue;
        }
        let req: TrayRequest = match serde_json::from_slice(&line) {
            Ok(r) => r,
            Err(e) => {
                if tx
                    .send(TrayResponse::Error {
                        message: format!("bad request: {e}"),
                    })
                    .await
                    .is_err()
                {
                    break Ok(());
                }
                continue;
            }
        };
        let (subscribe, wanted) = match &req {
            TrayRequest::Subscribe => (true, 0),
            TrayRequest::SubscribeWith { features } => (true, feature_bits(features)),
            _ => (false, 0),
        };
        // Subscribe before answering so no notification sent between the
        // Ack and the subscription is missed.
        let sub_rx = if subscribe && forwarder.is_none() {
            Some(handler.subscribe())
        } else {
            None
        };
        let resp = handler.handle(req, &client).await;
        // A refused subscription (e.g. an agent that rejects `SubscribeWith`)
        // subscribes nothing; the tray falls back to `Subscribe`.
        let refused = matches!(resp, TrayResponse::Error { .. });
        if subscribe && !refused {
            bits.fetch_or(wanted, Ordering::SeqCst);
        }
        if tx.send(resp).await.is_err() {
            break Ok(());
        }
        if let Some(mut brx) = sub_rx.filter(|_| !refused) {
            let tx2 = tx.clone();
            let who = client.clone();
            let bits2 = bits.clone();
            forwarder = Some(tokio::spawn(async move {
                loop {
                    match brx.recv().await {
                        Ok(item) => {
                            if !item.visible_to(&who)
                                || !push_allowed(&item.resp, bits2.load(Ordering::SeqCst))
                            {
                                continue;
                            }
                            if tx2.send(item.resp).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => break,
                    }
                }
            }));
        }
    };
    if let Some(f) = forwarder {
        f.abort();
    }
    drop(tx);
    let _ = writer.await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::tray::{ActivityItem, TrayRequest};
    use kestrel_common::Severity;
    use kestrel_platform::TrayPush;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct H {
        tx: broadcast::Sender<TrayPush>,
        /// Behave like an older agent that rejects `SubscribeWith`.
        refuse_with: bool,
    }

    #[async_trait::async_trait]
    impl TrayHandler for H {
        async fn handle(&self, req: TrayRequest, c: &TrayClient) -> TrayResponse {
            if matches!(req, TrayRequest::Status) {
                return TrayResponse::Ack {
                    ok: true,
                    message: format!("you are {:?}", c.user),
                };
            }
            match req {
                TrayRequest::Subscribe => TrayResponse::Ack {
                    ok: true,
                    message: "subscribed".into(),
                },
                TrayRequest::SubscribeWith { .. } if self.refuse_with => TrayResponse::Error {
                    message: "unknown op".into(),
                },
                TrayRequest::SubscribeWith { features } => TrayResponse::Ack {
                    ok: true,
                    message: format!("subscribed with {}", features.join(",")),
                },
                TrayRequest::ConsentResponse { allow, .. } => TrayResponse::Ack {
                    ok: true,
                    message: format!("consent allow={allow}"),
                },
                TrayRequest::Activity { limit } => TrayResponse::Ack {
                    ok: true,
                    message: format!("limit {limit}"),
                },
                _ => TrayResponse::Error {
                    message: "unsupported".into(),
                },
            }
        }
        fn subscribe(&self) -> broadcast::Receiver<TrayPush> {
            self.tx.subscribe()
        }
    }

    #[tokio::test]
    async fn bounded_lines() {
        let data = b"abc\r\ndef\nlast".to_vec();
        let mut r = BufReader::new(&data[..]);
        let mut buf = Vec::new();
        assert!(read_line_bounded(&mut r, 10, &mut buf).await.unwrap());
        assert_eq!(buf, b"abc");
        assert!(read_line_bounded(&mut r, 10, &mut buf).await.unwrap());
        assert_eq!(buf, b"def");
        assert!(read_line_bounded(&mut r, 10, &mut buf).await.unwrap());
        assert_eq!(buf, b"last");
        assert!(!read_line_bounded(&mut r, 10, &mut buf).await.unwrap());
        let big = [b'x'; 100];
        let mut r = BufReader::with_capacity(8, &big[..]);
        assert!(read_line_bounded(&mut r, 50, &mut buf).await.is_err());
    }

    #[tokio::test]
    async fn protocol() {
        let (tx, _) = broadcast::channel(16);
        let h = Arc::new(H {
            tx: tx.clone(),
            refuse_with: false,
        });
        let (client, server) = tokio::io::duplex(1 << 16);
        let me = TrayClient {
            user_sid: Some("S-1-5-21-7-1001".into()),
            user: Some("CORP\\alice".into()),
            session_id: Some(1),
            pid: Some(77),
        };
        let srv = tokio::spawn(handle_connection(
            server,
            h.clone() as Arc<dyn TrayHandler>,
            me,
        ));
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(
            b"{\"op\":\"activity\"}\nnot json\n{\"op\":\"subscribe\"}\n{\"op\":\"status\"}\n",
        )
        .await
        .unwrap();
        let mut got = String::new();
        let mut buf = [0u8; 4096];
        while got.matches('\n').count() < 4 {
            let n = cr.read(&mut buf).await.unwrap();
            got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
        let lines: Vec<&str> = got.lines().collect();
        assert!(lines[0].contains("limit 50"));
        assert!(lines[1].contains("\"type\":\"error\""));
        assert!(lines[2].contains("subscribed"));
        assert!(
            lines[3].contains("alice"),
            "client identity reaches the handler"
        );
        let item = ActivityItem {
            id: uuid::Uuid::nil(),
            ts: 1,
            title: "Blocked".into(),
            body: String::new(),
            severity: Severity::High,
            alert_id: None,
            file: None,
            action_taken: "Stopped".into(),
            review: None,
        };
        // Another user's notification is filtered; ours arrives.
        let mut theirs = item.clone();
        theirs.title = "bob only".into();
        tx.send(TrayPush {
            audience: kestrel_platform::Audience::Owner("corp\\bob".into()),
            resp: TrayResponse::Notification(theirs),
        })
        .unwrap();
        tx.send(TrayPush {
            audience: kestrel_platform::Audience::Owner("corp\\alice".into()),
            resp: TrayResponse::Notification(item),
        })
        .unwrap();
        let n = cr.read(&mut buf).await.unwrap();
        let s = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(s.contains("\"type\":\"notification\""));
        assert!(!s.contains("bob only"), "{s}");
        // Oversized line closes the connection with an error.
        let big = vec![b'a'; MAX_LINE + 10];
        cw.write_all(&big).await.unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut rest = Vec::new();
        cr.read_to_end(&mut rest).await.unwrap();
        assert!(String::from_utf8_lossy(&rest).contains("request rejected"));
        assert!(srv.await.unwrap().is_err());
    }

    fn alice() -> TrayClient {
        TrayClient {
            user_sid: Some("S-1-5-21-7-1001".into()),
            user: Some("CORP\\alice".into()),
            session_id: Some(1),
            pid: Some(77),
        }
    }

    type Rd = tokio::io::ReadHalf<tokio::io::DuplexStream>;
    type Wr = tokio::io::WriteHalf<tokio::io::DuplexStream>;

    /// Connect, send `first` (one request line), return the halves and the
    /// response line.
    async fn connect(h: Arc<H>, first: &str) -> (Rd, Wr, String) {
        let (client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(handle_connection(
            server,
            h as Arc<dyn TrayHandler>,
            alice(),
        ));
        let (mut cr, mut cw) = tokio::io::split(client);
        cw.write_all(first.as_bytes()).await.unwrap();
        cw.write_all(b"\n").await.unwrap();
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while cr.read(&mut b).await.unwrap() == 1 && b[0] != b'\n' {
            line.push(b[0]);
        }
        (cr, cw, String::from_utf8(line).unwrap())
    }

    /// Everything readable within 300 ms.
    async fn drain(cr: &mut Rd) -> String {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(Ok(n)) =
            tokio::time::timeout(std::time::Duration::from_millis(300), cr.read(&mut buf)).await
        {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        String::from_utf8(out).unwrap()
    }

    fn session_push() -> TrayPush {
        TrayPush {
            audience: kestrel_platform::Audience::Public,
            resp: TrayResponse::RemoteSession(kestrel_common::tray::RemoteSessionNotice {
                active: true,
                kind: Default::default(),
                admin_name: "Jane".into(),
                view_only: true,
                reason: String::new(),
                started_at: 1,
                ended_at: None,
            }),
        }
    }

    fn consent_push(session: u32) -> TrayPush {
        TrayPush {
            audience: kestrel_platform::Audience::Session(session),
            resp: TrayResponse::ConsentRequest(kestrel_common::tray::ConsentRequest {
                request_id: uuid::Uuid::nil(),
                kind: Default::default(),
                admin_name: "Jane".into(),
                view_only: false,
                reason: String::new(),
                timeout_secs: 30,
                expires_at: 2,
            }),
        }
    }

    fn note_push() -> TrayPush {
        TrayPush {
            audience: kestrel_platform::Audience::Public,
            resp: TrayResponse::Ack {
                ok: true,
                message: "public note".into(),
            },
        }
    }

    #[test]
    fn feature_gating_rules() {
        let f = |v: &[&str]| feature_bits(&v.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        assert_eq!(f(&[]), 0);
        assert_eq!(f(&["remote_session"]), PUSH_REMOTE_SESSION);
        assert_eq!(
            f(&["remote_consent", "remote_session", "future_thing"]),
            PUSH_REMOTE_SESSION | PUSH_REMOTE_CONSENT
        );
        let s = session_push().resp;
        let c = consent_push(1).resp;
        let n = note_push().resp;
        assert!(!push_allowed(&s, 0));
        assert!(!push_allowed(&c, 0));
        assert!(push_allowed(&n, 0));
        assert!(push_allowed(&s, PUSH_REMOTE_SESSION));
        assert!(!push_allowed(&c, PUSH_REMOTE_SESSION));
        assert!(push_allowed(&c, PUSH_REMOTE_CONSENT));
    }

    #[tokio::test]
    async fn opt_in_pushes_only_reach_subscribers() {
        let (tx, _) = broadcast::channel(16);
        let h = Arc::new(H {
            tx: tx.clone(),
            refuse_with: false,
        });
        let (mut old, _w1, r1) = connect(h.clone(), r#"{"op":"subscribe"}"#).await;
        assert!(r1.contains("subscribed"), "{r1}");
        let (mut sess, _w2, r2) = connect(
            h.clone(),
            r#"{"op":"subscribe_with","features":["remote_session"]}"#,
        )
        .await;
        assert!(r2.contains("subscribed with remote_session"), "{r2}");
        let (mut both, mut w3, r3) = connect(
            h.clone(),
            r#"{"op":"subscribe_with","features":["remote_session","remote_consent"]}"#,
        )
        .await;
        assert!(r3.contains("remote_consent"), "{r3}");
        // A connection that never subscribed gets nothing.
        let (mut none, _w4, _) = connect(h.clone(), r#"{"op":"status"}"#).await;

        tx.send(session_push()).unwrap();
        tx.send(consent_push(1)).unwrap(); // alice's session
        tx.send(consent_push(2)).unwrap(); // another session: never shown
        tx.send(note_push()).unwrap();

        let o = drain(&mut old).await;
        assert!(o.contains("public note"), "{o}");
        assert!(
            !o.contains("remote_session") && !o.contains("consent_request"),
            "{o}"
        );
        let s = drain(&mut sess).await;
        assert!(s.contains("\"type\":\"remote_session\""), "{s}");
        assert!(!s.contains("consent_request"), "{s}");
        let b = drain(&mut both).await;
        assert!(b.contains("\"type\":\"remote_session\""), "{b}");
        assert_eq!(b.matches("\"type\":\"consent_request\"").count(), 1, "{b}");
        assert!(b.contains("public note"), "{b}");
        assert_eq!(drain(&mut none).await, "");

        // ConsentResponse is an ordinary request answered by the handler.
        w3.write_all(
            b"{\"op\":\"consent_response\",\"request_id\":\"00000000-0000-0000-0000-000000000000\",\"allow\":true}\n",
        )
        .await
        .unwrap();
        let r = drain(&mut both).await;
        assert!(r.contains("consent allow=true"), "{r}");
    }

    #[tokio::test]
    async fn refused_subscribe_with_falls_back() {
        let (tx, _keep) = broadcast::channel(16);
        let h = Arc::new(H {
            tx: tx.clone(),
            refuse_with: true,
        });
        let (mut c, mut w, r) = connect(
            h.clone(),
            r#"{"op":"subscribe_with","features":["remote_session"]}"#,
        )
        .await;
        assert!(r.contains("\"type\":\"error\""), "{r}");
        tx.send(note_push()).unwrap();
        assert_eq!(
            drain(&mut c).await,
            "",
            "refused subscription delivers nothing"
        );
        // The tray falls back to plain Subscribe: notifications, but no
        // opt-in kinds.
        w.write_all(b"{\"op\":\"subscribe\"}\n").await.unwrap();
        assert!(drain(&mut c).await.contains("subscribed"));
        tx.send(session_push()).unwrap();
        tx.send(note_push()).unwrap();
        let got = drain(&mut c).await;
        assert!(got.contains("public note"), "{got}");
        assert!(!got.contains("remote_session"), "{got}");
    }
}
