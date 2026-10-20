//! Tray protocol connection handling (transport independent).
//!
//! JSON lines per `kestrel_common::tray`: each request gets exactly one
//! response; after `Subscribe` the agent's broadcast notifications are pushed
//! on the same connection. Lines are capped at [`MAX_LINE`] bytes; an
//! oversized line gets an `Error` response and the connection is closed. The
//! Windows module runs this over `\\.\pipe\kestrel-tray`; tests use an
//! in-memory duplex.

use kestrel_common::tray::{TrayRequest, TrayResponse};
use kestrel_platform::{TrayClient, TrayHandler};
use std::io;
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
        let subscribe = matches!(req, TrayRequest::Subscribe);
        // Subscribe before answering so no notification sent between the
        // Ack and the subscription is missed.
        let sub_rx = if subscribe && forwarder.is_none() {
            Some(handler.subscribe())
        } else {
            None
        };
        let resp = handler.handle(req, &client).await;
        if tx.send(resp).await.is_err() {
            break Ok(());
        }
        if let Some(mut brx) = sub_rx {
            let tx2 = tx.clone();
            let who = client.clone();
            forwarder = Some(tokio::spawn(async move {
                loop {
                    match brx.recv().await {
                        Ok(item) => {
                            if !item.visible_to(&who) {
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
        let h = Arc::new(H { tx: tx.clone() });
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
}
