//! In-process mock agent (`KESTREL_TRAY_MOCK=1`) speaking the real JSON-lines
//! protocol over an in-memory duplex stream. Lets the native shell (tray icon,
//! toasts, window behaviour) be exercised on a machine without the agent.
//!
//! `KESTREL_TRAY_MOCK_STATE=protected|attention|isolated|degraded|offline`
//! picks the initial state (default `attention`). After the first `Subscribe`
//! the mock pushes one demo notification after ~15 s.

use crate::protocol::*;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};
use tokio::sync::broadcast;
use uuid::Uuid;

pub struct MockAgent {
    inner: Mutex<Inner>,
    push: broadcast::Sender<TrayResponse>,
}

struct Inner {
    status: TrayStatus,
    items: Vec<ActivityItem>,
    demo_pushed: bool,
}

const MIN: i64 = 60_000;

fn uuid(n: u128) -> Uuid {
    Uuid::from_u128(0x6b65_7374_7265_6c00_0000_0000_0000_0000 | n)
}

pub fn sample_status(state: ProtectionState) -> TrayStatus {
    let now = now_ms();
    TrayStatus {
        state,
        agent_version: "0.1.0".into(),
        server_connected: !matches!(state, ProtectionState::Offline),
        last_policy_sync: Some(now - if matches!(state, ProtectionState::Offline) { 26 * 60 * MIN } else { 4 * MIN }),
        policy_name: "Staff laptops".into(),
        org_name: "Nusantara Logistik".into(),
        it_contact: ItContact {
            name: "IT Service Desk".into(),
            email: "servicedesk@nusantaralogistik.example".into(),
            phone: "+62 21 5088 1200".into(),
            url: "https://help.nusantaralogistik.example".into(),
        },
        privacy_notice_md: SAMPLE_NOTICE.into(),
        hostname: "LT-JKT-0142".into(),
        last_check: Some(now - 2 * 24 * 60 * MIN),
    }
}

pub const SAMPLE_NOTICE: &str = "## Monitoring notice\n\nNusantara Logistik uses **Kestrel** on company laptops to detect malware that steals passwords, browser sessions and crypto wallets. This notice is given under Indonesia's Personal Data Protection Law (UU PDP) and Singapore's PDPA.\n\n### What is collected\n- Names, locations and fingerprints (hashes) of programs that run, and which program started them\n- Which programs open browser password, cookie and wallet files (not what is inside them)\n- Network addresses contacted by programs that are not web browsers\n\n### Why\nTo stop account theft and investigate security incidents. This data is not used to measure your work or performance.\n\n### How long we keep it, and your rights\nAlerts are kept for 12 months and raw activity records for 30 days. To get a copy of data about you or ask a question, contact our Data Protection Officer at [dpo@nusantaralogistik.example](mailto:dpo@nusantaralogistik.example).\n\nFull policy: https://intranet.nusantaralogistik.example/privacy/endpoint\n";

pub fn sample_activity() -> Vec<ActivityItem> {
    let now = now_ms();
    vec![
        ActivityItem {
            id: uuid(1),
            ts: now - 12 * MIN,
            title: "Kestrel stopped setup_x64.exe from reading your saved browser passwords".into(),
            body: "This installer was downloaded today and tried to open the file where Chrome keeps your saved passwords. Installers don't need that file, so Kestrel stopped it before anything was read.".into(),
            severity: Severity::High,
            alert_id: Some(uuid(101)),
            file: Some(r"C:\Users\dewi.lestari\Downloads\setup_x64.exe".into()),
            action_taken: "Stopped and quarantined".into(),
            review: None,
        },
        ActivityItem {
            id: uuid(2),
            ts: now - 3 * 60 * MIN,
            title: "Kestrel blocked a command pasted into the Run box".into(),
            body: "A web page asked you to paste a command into Windows Run to \"verify you are human\". The command would have downloaded a hidden program. If you were following steps from a website, close that page.".into(),
            severity: Severity::Medium,
            alert_id: Some(uuid(102)),
            file: None,
            action_taken: "Blocked before it ran".into(),
            review: Some(ReviewState::Requested),
        },
        ActivityItem {
            id: uuid(3),
            ts: now - 27 * 60 * MIN,
            title: "Kestrel stopped an app from sending your Telegram login to the internet".into(),
            body: "upd4831.exe copied your Telegram Desktop session files and tried to upload them. Kestrel stopped the upload and told IT, who may contact you.".into(),
            severity: Severity::Critical,
            alert_id: Some(uuid(103)),
            file: Some(r"C:\Users\dewi.lestari\AppData\Local\Temp\upd4831.exe".into()),
            action_taken: "Stopped, quarantined and reported to IT".into(),
            review: Some(ReviewState::Denied),
        },
        ActivityItem {
            id: uuid(4),
            ts: now - 3 * 24 * 60 * MIN,
            title: "Kestrel paused an app that read your Discord login".into(),
            body: "DiscordChatExporter.exe opened Discord's saved login. You asked IT to review it and they allowed it for your PC.".into(),
            severity: Severity::Low,
            alert_id: Some(uuid(104)),
            file: Some(r"C:\Users\dewi.lestari\Tools\DiscordChatExporter.exe".into()),
            action_taken: "Paused, then allowed by IT".into(),
            review: Some(ReviewState::Approved),
        },
        ActivityItem {
            id: uuid(5),
            ts: now - 5 * 24 * 60 * MIN,
            title: "Your IT team updated Kestrel's protection settings".into(),
            body: "New settings from the \"Staff laptops\" policy are now in effect. You don't need to do anything.".into(),
            severity: Severity::Info,
            alert_id: None,
            file: None,
            action_taken: "Settings applied".into(),
            review: None,
        },
    ]
}

fn demo_push() -> ActivityItem {
    ActivityItem {
        id: Uuid::new_v4(),
        ts: now_ms(),
        title: "Kestrel stopped invoice_0921.scr from reading your crypto wallet".into(),
        body: "This file came from an email attachment and tried to open your Exodus wallet folder. Kestrel stopped it before anything was read.".into(),
        severity: Severity::Critical,
        alert_id: Some(Uuid::new_v4()),
        file: Some(r"C:\Users\dewi.lestari\Downloads\invoice_0921.scr".into()),
        action_taken: "Stopped and quarantined".into(),
        review: None,
    }
}

impl MockAgent {
    pub fn new() -> Self {
        let state = match std::env::var("KESTREL_TRAY_MOCK_STATE").as_deref() {
            Ok("protected") => ProtectionState::Protected,
            Ok("isolated") => ProtectionState::Isolated,
            Ok("degraded") => ProtectionState::Degraded,
            Ok("offline") => ProtectionState::Offline,
            _ => ProtectionState::Attention,
        };
        let (push, _) = broadcast::channel(32);
        MockAgent {
            inner: Mutex::new(Inner { status: sample_status(state), items: sample_activity(), demo_pushed: false }),
            push,
        }
    }

    /// Open a new in-memory connection served by this mock.
    pub fn connect(self: &std::sync::Arc<Self>) -> DuplexStream {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let me = self.clone();
        tokio::spawn(async move {
            let _ = me.serve(server).await;
        });
        client
    }

    async fn serve(self: std::sync::Arc<Self>, stream: DuplexStream) -> std::io::Result<()> {
        let (r, mut w) = tokio::io::split(stream);
        let mut lines = BufReader::new(r).lines();
        while let Some(line) = lines.next_line().await? {
            let resp = match serde_json::from_str::<TrayRequest>(&line) {
                Ok(TrayRequest::Subscribe) => {
                    write(&mut w, &TrayResponse::Ack { ok: true, message: "subscribed".into() }).await?;
                    self.schedule_demo_push();
                    let mut rx = self.push.subscribe();
                    // From here on this connection only carries pushes.
                    loop {
                        match rx.recv().await {
                            Ok(msg) => write(&mut w, &msg).await?,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        }
                    }
                }
                Ok(req) => self.handle(req).await,
                Err(e) => TrayResponse::Error { message: format!("bad request: {e}") },
            };
            write(&mut w, &resp).await?;
        }
        Ok(())
    }

    fn schedule_demo_push(self: &std::sync::Arc<Self>) {
        {
            let mut g = self.inner.lock().unwrap();
            if g.demo_pushed {
                return;
            }
            g.demo_pushed = true;
        }
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let item = demo_push();
            {
                let mut g = me.inner.lock().unwrap();
                g.items.insert(0, item.clone());
                if g.status.state == ProtectionState::Protected {
                    g.status.state = ProtectionState::Attention;
                }
            }
            let _ = me.push.send(TrayResponse::Notification(item));
        });
    }

    async fn handle(&self, req: TrayRequest) -> TrayResponse {
        match req {
            TrayRequest::Status => TrayResponse::Status(self.inner.lock().unwrap().status.clone()),
            TrayRequest::Activity { limit } => {
                let g = self.inner.lock().unwrap();
                TrayResponse::Activity { items: g.items.iter().take(limit as usize).cloned().collect() }
            }
            TrayRequest::QuickCheck => {
                tokio::time::sleep(Duration::from_millis(2600)).await;
                self.inner.lock().unwrap().status.last_check = Some(now_ms());
                TrayResponse::Ack { ok: true, message: "Checked 147 running apps. Nothing needs your attention.".into() }
            }
            TrayRequest::RequestReview { alert_id, justification } => {
                if justification.trim().is_empty() {
                    return TrayResponse::Error { message: "justification is required".into() };
                }
                let updated = {
                    let mut g = self.inner.lock().unwrap();
                    match g.items.iter_mut().find(|i| i.alert_id == Some(alert_id)) {
                        Some(item) => {
                            item.review = Some(ReviewState::Requested);
                            Some(item.clone())
                        }
                        None => None,
                    }
                };
                match updated {
                    Some(item) => {
                        let _ = self.push.send(TrayResponse::Notification(item));
                        TrayResponse::Ack { ok: true, message: "Your request was sent to IT.".into() }
                    }
                    None => TrayResponse::Error { message: "unknown alert".into() },
                }
            }
            TrayRequest::Subscribe => unreachable!("handled in serve"),
        }
    }
}

async fn write<W: tokio::io::AsyncWrite + Unpin>(w: &mut W, msg: &TrayResponse) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(msg).expect("serialisable");
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}
