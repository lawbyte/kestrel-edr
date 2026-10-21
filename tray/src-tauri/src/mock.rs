//! In-process mock agent (`KESTREL_TRAY_MOCK=1`) speaking the real JSON-lines
//! protocol over an in-memory duplex stream. Lets the native shell (tray icon,
//! toasts, window behaviour) be exercised on a machine without the agent.
//!
//! `KESTREL_TRAY_MOCK_STATE=protected|attention|isolated|degraded|offline`
//! picks the initial state (default `attention`). After the first `Subscribe`
//! the mock pushes one demo notification after ~15 s.
//!
//! `KESTREL_TRAY_MOCK_REMOTE` simulates an admin remote-desktop session:
//! `view` / `control` / `files` = a session is already active at launch
//! (view-only desktop, full-control desktop, or file access); `cycle` = after the first subscription a session starts
//! ~5 s later, ends ~40 s after that, and repeats every ~90 s. Like the real
//! agent, `RemoteSession` pushes only go to `subscribe_with` connections that
//! asked for `remote_session`, and each start/end also pushes a `Notification`.
//!
//! `KESTREL_TRAY_MOCK_CONSENT=desktop|view|files` pushes an IT consent request
//! ~5 s after the first subscription (60 s timeout; only to `remote_consent`
//! subscribers). Allowing it starts a matching remote session.
//!
//! Local "turn protection off" switch. **Mock uninstall token: `kun_mock_token`**
//! (see [`MOCK_TOKEN`]). Five wrong tokens lock the switch for 1 minute,
//! doubling up to 1 hour, like the agent. `KESTREL_TRAY_MOCK_PAUSE` picks the
//! policy and the starting state: `open` (default: every mode and "until
//! turned back on" allowed), `basic` (agent defaults: detection only, timed
//! only), `disabled` (switch not allowed), `active` (already off, detection
//! only, ~80 min left), `active_full` (already completely off, until turned
//! back on), `locked` (lockout in force for 4 minutes).

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
    /// Behave like an agent that predates `subscribe_with` (answers `Error`).
    legacy: bool,
    remote_mode: RemoteMode,
    remote_cycle_started: bool,
    consents: Vec<ConsentRequest>,
    consent_demo: Option<(RemoteKind, bool)>,
    consent_demo_started: bool,
    /// Consecutive wrong uninstall tokens (reset by a lockout or success).
    pause_failures: u32,
    /// Lockouts so far (each doubles the next one).
    pause_lockouts: u32,
}

/// Uninstall token the mock accepts.
pub const MOCK_TOKEN: &str = "kun_mock_token";
const PAUSE_MAX_FAILURES: u32 = 5;
const PAUSE_LOCKOUT_BASE_MS: i64 = 60_000;
const PAUSE_LOCKOUT_MAX_MS: i64 = 3_600_000;
const MOCK_USER: &str = r"NUSANTARA\dewi.lestari";

/// Offer for the mock policy: `open` = everything allowed (all UI visible).
pub fn sample_pause_offer(open: bool) -> PauseOffer {
    PauseOffer {
        enabled: true,
        allow_full: open,
        minutes: vec![15, 60, 240, 480],
        allow_until_resumed: open,
        locked_until_ms: None,
    }
}

/// A sample active pause for the mock and tests.
pub fn sample_pause(mode: PauseMode, until_resumed: bool) -> PauseState {
    let now = now_ms();
    PauseState {
        mode,
        since_ms: now - 40 * MIN,
        until_ms: (!until_resumed).then_some(now + 80 * MIN),
        by_user: MOCK_USER.into(),
    }
}

fn pause_fail(error: PauseError, message: &str) -> PauseResult {
    PauseResult {
        ok: false,
        error: Some(error),
        message: message.into(),
        attempts_left: None,
        locked_until_ms: None,
        denied: None,
        state: None,
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum RemoteMode {
    Off,
    Cycle,
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
        last_policy_sync: Some(
            now - if matches!(state, ProtectionState::Offline) {
                26 * 60 * MIN
            } else {
                4 * MIN
            },
        ),
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
        remote_session: None,
        pause: None,
        local_pause: Some(sample_pause_offer(true)),
    }
}

/// A sample admin session for the mock and tests.
pub fn sample_remote_session(view_only: bool) -> RemoteSessionNotice {
    RemoteSessionNotice {
        active: true,
        kind: RemoteKind::Desktop,
        admin_name: "Rina Wijaya".into(),
        view_only,
        reason: "Checking the VPN problem you reported (ticket #4821)".into(),
        started_at: now_ms() - 3 * MIN,
        ended_at: None,
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

impl Default for MockAgent {
    fn default() -> Self {
        Self::new()
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
        let mut status = sample_status(state);
        let remote_mode = match std::env::var("KESTREL_TRAY_MOCK_REMOTE").as_deref() {
            Ok("view") => {
                status.remote_session = Some(sample_remote_session(true));
                RemoteMode::Off
            }
            Ok("control") => {
                status.remote_session = Some(sample_remote_session(false));
                RemoteMode::Off
            }
            Ok("files") => {
                let mut n = sample_remote_session(false);
                n.kind = RemoteKind::Files;
                status.remote_session = Some(n);
                RemoteMode::Off
            }
            Ok("cycle") => RemoteMode::Cycle,
            _ => RemoteMode::Off,
        };
        let consent_demo = match std::env::var("KESTREL_TRAY_MOCK_CONSENT").as_deref() {
            Ok("desktop") => Some((RemoteKind::Desktop, false)),
            Ok("view") => Some((RemoteKind::Desktop, true)),
            Ok("files") => Some((RemoteKind::Files, false)),
            _ => None,
        };
        match std::env::var("KESTREL_TRAY_MOCK_PAUSE").as_deref() {
            Ok("basic") => status.local_pause = Some(sample_pause_offer(false)),
            Ok("disabled") => {
                status.local_pause = Some(PauseOffer {
                    enabled: false,
                    ..Default::default()
                })
            }
            Ok("active") => status.pause = Some(sample_pause(PauseMode::DetectionOnly, false)),
            Ok("active_full") => status.pause = Some(sample_pause(PauseMode::Full, true)),
            Ok("locked") => {
                if let Some(o) = status.local_pause.as_mut() {
                    o.locked_until_ms = Some(now_ms() + 4 * MIN);
                }
            }
            _ => {}
        }
        let (push, _) = broadcast::channel(32);
        MockAgent {
            inner: Mutex::new(Inner {
                status,
                items: sample_activity(),
                demo_pushed: false,
                legacy: false,
                remote_mode,
                remote_cycle_started: false,
                consents: Vec::new(),
                consent_demo,
                consent_demo_started: false,
                pause_failures: 0,
                pause_lockouts: 0,
            }),
            push,
        }
    }

    /// A mock that behaves like an agent from before `subscribe_with` existed
    /// (and before the local pause switch: no `local_pause`, `Error` for its ops).
    pub fn legacy() -> Self {
        let m = Self::new();
        {
            let mut g = m.inner.lock().unwrap();
            g.legacy = true;
            g.status.pause = None;
            g.status.local_pause = None;
        }
        m
    }

    /// Turn protection off (`PauseProtection`), checked like the agent:
    /// lockout, policy, then the token.
    fn pause(&self, token: &TokenInput, mode: PauseMode, minutes: Option<u32>) -> PauseResult {
        let now = now_ms();
        let mut g = self.inner.lock().unwrap();
        self.expire_pause(&mut g, now);
        let offer = g.status.local_pause.clone().unwrap_or_default();
        if let Some(until) = offer.locked_until_ms.filter(|u| *u > now) {
            return PauseResult {
                locked_until_ms: Some(until),
                ..pause_fail(PauseError::LockedOut, "Too many wrong tokens.")
            };
        }
        let denied = |d| PauseResult {
            denied: Some(d),
            ..pause_fail(
                PauseError::NotAllowed,
                "Not allowed by your organisation's policy.",
            )
        };
        if !offer.enabled {
            return denied(PauseDenied::Disabled);
        }
        if let Some(p) = &g.status.pause {
            return PauseResult {
                state: Some(p.clone()),
                ..pause_fail(PauseError::AlreadyOff, "Protection is already off.")
            };
        }
        if mode == PauseMode::Full && !offer.allow_full {
            return denied(PauseDenied::ModeNotAllowed);
        }
        let duration_ok = match minutes {
            None => offer.allow_until_resumed,
            Some(m) => offer.minutes.contains(&m),
        };
        if !duration_ok {
            return denied(PauseDenied::DurationNotAllowed);
        }
        if token.0.trim() != MOCK_TOKEN {
            g.pause_failures += 1;
            if g.pause_failures >= PAUSE_MAX_FAILURES {
                g.pause_failures = 0;
                let shift = g.pause_lockouts.min(6);
                g.pause_lockouts += 1;
                let until = now + (PAUSE_LOCKOUT_BASE_MS << shift).min(PAUSE_LOCKOUT_MAX_MS);
                if let Some(o) = g.status.local_pause.as_mut() {
                    o.locked_until_ms = Some(until);
                }
                return PauseResult {
                    locked_until_ms: Some(until),
                    ..pause_fail(PauseError::LockedOut, "Too many wrong tokens.")
                };
            }
            return PauseResult {
                attempts_left: Some(PAUSE_MAX_FAILURES - g.pause_failures),
                ..pause_fail(PauseError::WrongToken, "Wrong token.")
            };
        }
        g.pause_failures = 0;
        if let Some(o) = g.status.local_pause.as_mut() {
            o.locked_until_ms = None;
        }
        let state = PauseState {
            mode,
            since_ms: now,
            until_ms: minutes.map(|m| now + i64::from(m) * MIN),
            by_user: MOCK_USER.into(),
        };
        g.status.pause = Some(state.clone());
        let item = ActivityItem {
            id: Uuid::new_v4(),
            ts: now,
            title: match mode {
                PauseMode::DetectionOnly => {
                    "Protection was turned off on this PC (detection only)".into()
                }
                PauseMode::Full => "Protection was turned off completely on this PC".into(),
            },
            body: format!(
                "{MOCK_USER} turned Kestrel's protection off with the uninstall token. IT has been told."
            ),
            severity: Severity::High,
            alert_id: None,
            file: None,
            action_taken: "Protection turned off".into(),
            review: None,
        };
        g.items.insert(0, item.clone());
        drop(g);
        let _ = self.push.send(TrayResponse::Notification(item));
        PauseResult {
            ok: true,
            error: None,
            message: "Protection is off.".into(),
            attempts_left: None,
            locked_until_ms: None,
            denied: None,
            state: Some(state),
        }
    }

    /// Turn protection back on (`ResumeProtection`, no token).
    fn resume(&self) -> PauseResult {
        let mut g = self.inner.lock().unwrap();
        if g.status.pause.take().is_none() {
            return pause_fail(PauseError::NotOff, "Protection is already on.");
        }
        let item = turned_on_item(&format!(
            "{MOCK_USER} turned protection back on from the tray."
        ));
        g.items.insert(0, item.clone());
        drop(g);
        let _ = self.push.send(TrayResponse::Notification(item));
        PauseResult {
            ok: true,
            error: None,
            message: "Protection is back on.".into(),
            attempts_left: None,
            locked_until_ms: None,
            denied: None,
            state: None,
        }
    }

    /// End a timed pause that has run out (the agent does this on a timer).
    fn expire_pause(&self, g: &mut Inner, now: TimestampMs) {
        if g.status
            .pause
            .as_ref()
            .is_some_and(|p| p.until_ms.is_some_and(|u| now >= u))
        {
            g.status.pause = None;
            let item =
                turned_on_item("The chosen time ran out, so Kestrel turned protection back on.");
            g.items.insert(0, item.clone());
            let _ = self.push.send(TrayResponse::Notification(item));
        }
    }

    /// Simulate IT asking the employee for consent (pushed to `remote_consent`
    /// subscribers only). Returns the request so tests can answer it.
    pub fn request_consent(
        &self,
        kind: RemoteKind,
        view_only: bool,
        timeout_secs: u32,
    ) -> ConsentRequest {
        let req = ConsentRequest {
            request_id: Uuid::new_v4(),
            kind,
            admin_name: "Rina Wijaya".into(),
            view_only: view_only && kind == RemoteKind::Desktop,
            reason: "Checking the VPN problem you reported (ticket #4821)".into(),
            timeout_secs,
            expires_at: now_ms() + i64::from(timeout_secs) * 1000,
        };
        self.inner.lock().unwrap().consents.push(req.clone());
        let _ = self.push.send(TrayResponse::ConsentRequest(req.clone()));
        req
    }

    fn answer_consent(&self, request_id: Uuid, allow: bool) -> TrayResponse {
        let req = {
            let mut g = self.inner.lock().unwrap();
            let now = now_ms();
            g.consents.retain(|r| r.expires_at > now);
            let i = g.consents.iter().position(|r| r.request_id == request_id);
            i.map(|i| g.consents.remove(i))
        };
        let Some(req) = req else {
            return TrayResponse::Error {
                message: "no pending request with that id (it may have expired)".into(),
            };
        };
        if !allow {
            return TrayResponse::Ack {
                ok: true,
                message: "IT has been told you said no. They can't connect.".into(),
            };
        }
        self.start_remote_session(RemoteSessionNotice {
            active: true,
            kind: req.kind,
            admin_name: req.admin_name,
            view_only: req.view_only,
            reason: req.reason,
            started_at: now_ms(),
            ended_at: None,
        });
        TrayResponse::Ack {
            ok: true,
            message: "IT can now connect. You'll see a banner while they're connected.".into(),
        }
    }

    fn schedule_consent_demo(self: &std::sync::Arc<Self>) {
        let demo = {
            let mut g = self.inner.lock().unwrap();
            if g.consent_demo_started {
                return;
            }
            g.consent_demo_started = true;
            g.consent_demo
        };
        let Some((kind, view_only)) = demo else {
            return;
        };
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            me.request_consent(kind, view_only, 60);
        });
    }

    /// Simulate an admin opening a remote session (pushes like the real agent).
    pub fn start_remote_session(&self, notice: RemoteSessionNotice) {
        let item = ActivityItem {
            id: Uuid::new_v4(),
            ts: now_ms(),
            title: if notice.kind == RemoteKind::Files {
                format!(
                    "{} from IT is accessing files on this PC",
                    notice.admin_name
                )
            } else if notice.view_only {
                format!("{} from IT started viewing your screen", notice.admin_name)
            } else {
                format!(
                    "{} from IT connected and can control your screen",
                    notice.admin_name
                )
            },
            body: if notice.reason.is_empty() {
                "Contact IT if you weren't expecting this.".into()
            } else {
                format!(
                    "Reason: {}. Contact IT if you weren't expecting this.",
                    notice.reason
                )
            },
            severity: Severity::High,
            alert_id: None,
            file: None,
            action_taken: "Remote session started".into(),
            review: None,
        };
        {
            let mut g = self.inner.lock().unwrap();
            g.status.remote_session = Some(notice.clone());
            g.items.insert(0, item.clone());
        }
        let _ = self.push.send(TrayResponse::RemoteSession(notice));
        let _ = self.push.send(TrayResponse::Notification(item));
    }

    /// Simulate the admin's session ending.
    pub fn end_remote_session(&self) {
        let ended = {
            let mut g = self.inner.lock().unwrap();
            let taken = g.status.remote_session.take();
            taken.map(|mut n| {
                n.active = false;
                n.ended_at = Some(now_ms());
                let item = ActivityItem {
                    id: Uuid::new_v4(),
                    ts: now_ms(),
                    title: format!("{} from IT disconnected from your PC", n.admin_name),
                    body: "IT can no longer see your screen.".into(),
                    severity: Severity::High,
                    alert_id: None,
                    file: None,
                    action_taken: "Remote session ended".into(),
                    review: None,
                };
                g.items.insert(0, item.clone());
                (n, item)
            })
        };
        if let Some((n, item)) = ended {
            let _ = self.push.send(TrayResponse::RemoteSession(n));
            let _ = self.push.send(TrayResponse::Notification(item));
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
                Ok(TrayRequest::SubscribeWith { .. }) if self.inner.lock().unwrap().legacy => {
                    // Exactly what an older agent says about an op it doesn't know.
                    TrayResponse::Error {
                        message: "bad request: unknown variant `subscribe_with`".into(),
                    }
                }
                Ok(req @ (TrayRequest::Subscribe | TrayRequest::SubscribeWith { .. })) => {
                    let wants = |feature: &str| {
                        matches!(&req, TrayRequest::SubscribeWith { features }
                            if features.iter().any(|f| f == feature))
                    };
                    let (remote, consent) =
                        (wants(FEATURE_REMOTE_SESSION), wants(FEATURE_REMOTE_CONSENT));
                    // Subscribe before acking so no push between the two is lost.
                    let mut rx = self.push.subscribe();
                    write(
                        &mut w,
                        &TrayResponse::Ack {
                            ok: true,
                            message: "subscribed".into(),
                        },
                    )
                    .await?;
                    self.schedule_demo_push();
                    self.schedule_remote_cycle();
                    self.schedule_consent_demo();
                    // From here on this connection only carries pushes.
                    loop {
                        match rx.recv().await {
                            Ok(TrayResponse::RemoteSession(_)) if !remote => continue,
                            Ok(TrayResponse::ConsentRequest(_)) if !consent => continue,
                            Ok(msg) => write(&mut w, &msg).await?,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => return Ok(()),
                        }
                    }
                }
                Ok(req) => self.handle(req).await,
                Err(e) => TrayResponse::Error {
                    message: format!("bad request: {e}"),
                },
            };
            write(&mut w, &resp).await?;
        }
        Ok(())
    }

    fn schedule_remote_cycle(self: &std::sync::Arc<Self>) {
        {
            let mut g = self.inner.lock().unwrap();
            if g.remote_mode != RemoteMode::Cycle || g.remote_cycle_started {
                return;
            }
            g.remote_cycle_started = true;
        }
        let me = self.clone();
        tokio::spawn(async move {
            let mut view_only = false;
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut n = sample_remote_session(view_only);
                n.started_at = now_ms();
                me.start_remote_session(n);
                tokio::time::sleep(Duration::from_secs(40)).await;
                me.end_remote_session();
                tokio::time::sleep(Duration::from_secs(45)).await;
                view_only = !view_only;
            }
        });
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
            TrayRequest::Status => {
                let mut g = self.inner.lock().unwrap();
                self.expire_pause(&mut g, now_ms());
                TrayResponse::Status(g.status.clone())
            }
            TrayRequest::Activity { limit } => {
                let g = self.inner.lock().unwrap();
                TrayResponse::Activity {
                    items: g.items.iter().take(limit as usize).cloned().collect(),
                }
            }
            TrayRequest::QuickCheck => {
                tokio::time::sleep(Duration::from_millis(2600)).await;
                self.inner.lock().unwrap().status.last_check = Some(now_ms());
                TrayResponse::Ack {
                    ok: true,
                    message: "Checked 147 running apps. Nothing needs your attention.".into(),
                }
            }
            TrayRequest::RequestReview {
                alert_id,
                justification,
            } => {
                if justification.trim().is_empty() {
                    return TrayResponse::Error {
                        message: "justification is required".into(),
                    };
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
                        TrayResponse::Ack {
                            ok: true,
                            message: "Your request was sent to IT.".into(),
                        }
                    }
                    None => TrayResponse::Error {
                        message: "unknown alert".into(),
                    },
                }
            }
            TrayRequest::Subscribe | TrayRequest::SubscribeWith { .. } => TrayResponse::Error {
                message: "subscribe is handled by the connection loop".into(),
            },
            TrayRequest::ConsentResponse { request_id, allow } => {
                self.answer_consent(request_id, allow)
            }
            TrayRequest::PauseProtection { .. } | TrayRequest::ResumeProtection
                if self.inner.lock().unwrap().legacy =>
            {
                // Exactly what an older agent says about an op it doesn't know.
                TrayResponse::Error {
                    message: format!("bad request: unknown variant `{}`", req.op()),
                }
            }
            TrayRequest::PauseProtection {
                token,
                mode,
                minutes,
            } => {
                // A short delay on every attempt, as a real token check takes a moment.
                tokio::time::sleep(Duration::from_millis(300)).await;
                TrayResponse::PauseResult(self.pause(&token, mode, minutes))
            }
            TrayRequest::ResumeProtection => TrayResponse::PauseResult(self.resume()),
        }
    }
}

fn turned_on_item(body: &str) -> ActivityItem {
    ActivityItem {
        id: Uuid::new_v4(),
        ts: now_ms(),
        title: "Protection is back on".into(),
        body: body.into(),
        severity: Severity::Low,
        alert_id: None,
        file: None,
        action_taken: "Protection turned back on".into(),
        review: None,
    }
}

async fn write<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    msg: &TrayResponse,
) -> std::io::Result<()> {
    let mut line = serde_json::to_vec(msg).expect("serialisable");
    line.push(b'\n');
    w.write_all(&line).await?;
    w.flush().await
}
