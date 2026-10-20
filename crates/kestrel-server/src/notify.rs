//! Alert notifications: Slack, Teams, signed generic webhook, SMTP email and
//! syslog (CEF/JSON over UDP/TCP/TLS). Submissions never block ingest: jobs go
//! through a bounded queue and each channel retries with backoff on its own task.

use crate::{
    crypto::{hmac_sha256_hex, MasterKey},
    netguard,
    settings::{self, Settings, SyslogCfg, SyslogFormat, SyslogProto},
};
use kestrel_common::{now_ms, Alert, Severity};
use serde_json::json;
use sqlx::PgPool;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncWriteExt, sync::mpsc};
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct NotifyJob {
    pub alert: Alert,
    pub device_id: Uuid,
    pub hostname: String,
    pub incident_id: Uuid,
    pub incident_created: bool,
}

#[derive(Clone)]
pub struct Notifier {
    tx: mpsc::Sender<NotifyJob>,
}

impl Notifier {
    pub fn submit(&self, job: NotifyJob) {
        if let Err(e) = self.tx.try_send(job) {
            tracing::warn!("notification queue full, dropping notification: {e}");
        }
    }

    pub fn start(
        db: PgPool,
        mk: MasterKey,
        base_url: String,
        outbound: netguard::Policy,
    ) -> Notifier {
        let (tx, mut rx) = mpsc::channel::<NotifyJob>(2048);
        let ctx = Arc::new(Ctx {
            db,
            mk,
            base_url,
            // SSRF guard: public destinations only, no redirects (L7).
            http: netguard::client(&outbound, Duration::from_secs(15)),
            outbound,
        });
        tokio::spawn(async move {
            while let Some(job) = rx.recv().await {
                let ctx = ctx.clone();
                // Load settings per job so changes apply immediately.
                let (s, secrets) = match (
                    settings::load(&ctx.db).await,
                    settings::load_secrets(&ctx.db, &ctx.mk).await,
                ) {
                    (Ok(s), Ok(sec)) => (s, sec),
                    (Err(e), _) | (_, Err(e)) => {
                        tracing::error!(error = %e, "notifier cannot load settings");
                        continue;
                    }
                };
                dispatch(ctx, Arc::new(s), Arc::new(secrets), Arc::new(job));
            }
        });
        Notifier { tx }
    }
}

struct Ctx {
    db: PgPool,
    mk: MasterKey,
    base_url: String,
    http: reqwest::Client,
    outbound: netguard::Policy,
}

/// Slack mrkdwn: `&`, `<`, `>` are control characters (links, mentions).
pub fn slack_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Teams MessageCard text is markdown + limited HTML: neutralise both so
/// endpoint-controlled strings cannot add links or formatting.
pub fn teams_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\\' | '*' | '_' | '[' | ']' | '(' | ')' | '#' | '`' | '~' | '|' | '!' => {
                out.push('\\');
                out.push(c);
            }
            '\n' | '\r' => out.push(' '),
            c => out.push(c),
        }
    }
    out
}

fn dispatch(ctx: Arc<Ctx>, s: Arc<Settings>, secrets: Arc<settings::Secrets>, job: Arc<NotifyJob>) {
    let sev = job.alert.severity;
    let n = &s.notifications;
    let link = format!("{}/incidents/{}", ctx.base_url, job.incident_id);
    if n.slack.enabled && !n.slack.webhook_url.is_empty() && sev >= n.slack.min_severity {
        let url = n.slack.webhook_url.clone();
        let body = json!({ "text": format!(
            "{} *{}* on `{}` — {}\n<{}|Open incident>",
            sev_emoji(sev),
            slack_escape(&job.alert.rule_name),
            slack_escape(&job.hostname).replace('`', "'"),
            slack_escape(&job.alert.summary),
            link
        ) });
        spawn_retry("slack", ctx.clone(), move |c| {
            let (url, body) = (url.clone(), body.clone());
            async move { post_json(&c.http, &c.outbound, &url, &body, &[]).await }
        });
    }
    if n.teams.enabled && !n.teams.webhook_url.is_empty() && sev >= n.teams.min_severity {
        let url = n.teams.webhook_url.clone();
        let body = json!({
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": format!("Kestrel: {}", teams_escape(&job.alert.rule_name)),
            "themeColor": sev_color(sev),
            "title": format!("[{}] {} on {}", sev.as_str().to_uppercase(), teams_escape(&job.alert.rule_name), teams_escape(&job.hostname)),
            "text": teams_escape(&job.alert.summary),
            "potentialAction": [{"@type": "OpenUri", "name": "Open incident", "targets": [{"os": "default", "uri": link}]}],
        });
        spawn_retry("teams", ctx.clone(), move |c| {
            let (url, body) = (url.clone(), body.clone());
            async move { post_json(&c.http, &c.outbound, &url, &body, &[]).await }
        });
    }
    if n.webhook.enabled && !n.webhook.url.is_empty() && sev >= n.webhook.min_severity {
        let url = n.webhook.url.clone();
        let secret = secrets.webhook_secret.clone();
        let body = webhook_body(&job, &link);
        spawn_retry("webhook", ctx.clone(), move |c| {
            let (url, body, secret) = (url.clone(), body.clone(), secret.clone());
            async move {
                let raw = serde_json::to_vec(&body)?;
                let mut headers = vec![("X-Kestrel-Event".to_string(), "alert".to_string())];
                if !secret.is_empty() {
                    headers.push((
                        "X-Kestrel-Signature".into(),
                        format!("sha256={}", hmac_sha256_hex(secret.as_bytes(), &raw)),
                    ));
                }
                post_raw(&c.http, &c.outbound, &url, raw, &headers).await
            }
        });
    }
    if n.email.enabled
        && !n.email.smtp_host.is_empty()
        && !n.email.to.is_empty()
        && sev >= n.email.min_severity
    {
        let cfg = n.email.clone();
        let password = secrets.smtp_password.clone();
        let subject = format!(
            "[Kestrel {}] {} on {}",
            sev.as_str().to_uppercase(),
            job.alert.rule_name,
            job.hostname
        );
        let text = format!(
            "{}\n\nDevice: {}\nRule: {} ({})\nSeverity: {}\nProcess: {}\n\nOpen incident: {}\n",
            job.alert.summary,
            job.hostname,
            job.alert.rule_name,
            job.alert.rule_id,
            sev.as_str(),
            job.alert.process.image,
            link
        );
        spawn_retry("email", ctx.clone(), move |_c| {
            let (cfg, password, subject, text) =
                (cfg.clone(), password.clone(), subject.clone(), text.clone());
            async move { send_email(&cfg, &password, &subject, &text).await }
        });
    }
    if n.syslog.enabled && !n.syslog.host.is_empty() && sev >= n.syslog.min_severity {
        let cfg = n.syslog.clone();
        let line = match cfg.format {
            SyslogFormat::Cef => cef_line(&job),
            SyslogFormat::Json => {
                serde_json::to_string(&webhook_body(&job, &link)).unwrap_or_default()
            }
        };
        let msg = syslog_frame(sev, &line);
        spawn_retry("syslog", ctx, move |c| {
            let (cfg, msg) = (cfg.clone(), msg.clone());
            async move { send_syslog(&cfg, &c.outbound.allow, &msg).await }
        });
    }
}

fn spawn_retry<F, Fut>(channel: &'static str, ctx: Arc<Ctx>, f: F)
where
    F: Fn(Arc<Ctx>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = anyhow::Result<()>> + Send,
{
    tokio::spawn(async move {
        let mut delay = Duration::from_secs(1);
        for attempt in 1..=4 {
            match f(ctx.clone()).await {
                Ok(()) => return,
                Err(e) => {
                    tracing::warn!(channel, attempt, error = %e, "notification failed");
                    if attempt < 4 {
                        tokio::time::sleep(delay).await;
                        delay *= 4;
                    }
                }
            }
        }
        tracing::error!(channel, "notification dropped after retries");
    });
}

pub fn webhook_body(job: &NotifyJob, link: &str) -> serde_json::Value {
    let a = &job.alert;
    json!({
        "type": "alert",
        "ts": a.ts,
        "sent_at": now_ms(),
        "alert_id": a.id,
        "incident_id": job.incident_id,
        "incident_created": job.incident_created,
        "device_id": job.device_id,
        "hostname": job.hostname,
        "rule_id": a.rule_id,
        "rule_name": a.rule_name,
        "rule_author": a.rule_author,
        "severity": a.severity,
        "mode": a.mode,
        "attack": a.attack,
        "summary": a.summary,
        "image": a.process.image,
        "process_guid": a.process.guid,
        "sha256": a.process.sha256,
        "user": a.process.user,
        "data_at_risk": a.data_at_risk,
        "actions": a.actions,
        "url": link,
    })
}

fn sev_emoji(s: Severity) -> &'static str {
    match s {
        Severity::Critical => ":red_circle:",
        Severity::High => ":large_orange_circle:",
        Severity::Medium => ":large_yellow_circle:",
        _ => ":white_circle:",
    }
}

fn sev_color(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "B91C1C",
        Severity::High => "EA580C",
        Severity::Medium => "CA8A04",
        _ => "6B7280",
    }
}

async fn post_json(
    http: &reqwest::Client,
    policy: &netguard::Policy,
    url: &str,
    body: &serde_json::Value,
    headers: &[(String, String)],
) -> anyhow::Result<()> {
    post_raw(http, policy, url, serde_json::to_vec(body)?, headers).await
}

async fn post_raw(
    http: &reqwest::Client,
    policy: &netguard::Policy,
    url: &str,
    raw: Vec<u8>,
    headers: &[(String, String)],
) -> anyhow::Result<()> {
    // The client's resolver filters DNS answers; IP-literal hosts are checked here.
    policy.check_url(url)?;
    let mut req = http
        .post(url)
        .header("Content-Type", "application/json")
        .body(raw);
    for (k, v) in headers {
        req = req.header(k, v);
    }
    let r = req.send().await?;
    if !r.status().is_success() {
        anyhow::bail!("HTTP {}", r.status());
    }
    Ok(())
}

async fn send_email(
    cfg: &settings::EmailCfg,
    password: &str,
    subject: &str,
    text: &str,
) -> anyhow::Result<()> {
    use lettre::{
        message::header::ContentType, transport::smtp::authentication::Credentials,
        AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    };
    let from = if cfg.from.is_empty() {
        format!("kestrel@{}", cfg.smtp_host)
    } else {
        cfg.from.clone()
    };
    let mut builder = Message::builder()
        .from(from.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);
    for to in &cfg.to {
        builder = builder.to(to.parse()?);
    }
    let msg = builder.body(text.to_string())?;
    let mut t = if cfg.smtp_port == 465 {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.smtp_host)?
    } else if cfg.smtp_port == 25 && cfg.username.is_empty() {
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.smtp_host)?
    }
    .port(cfg.smtp_port)
    .timeout(Some(Duration::from_secs(20)));
    if !cfg.username.is_empty() {
        t = t.credentials(Credentials::new(cfg.username.clone(), password.to_string()));
    }
    t.build().send(msg).await?;
    Ok(())
}

fn cef_escape_header(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace(['\r', '\n'], " ")
}

fn cef_escape_ext(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('=', "\\=")
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

pub fn cef_line(job: &NotifyJob) -> String {
    let a = &job.alert;
    let sev = match a.severity {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 5,
        Severity::High => 8,
        Severity::Critical => 10,
    };
    let ext = [
        ("rt", a.ts.to_string()),
        ("dvchost", job.hostname.clone()),
        ("deviceExternalId", job.device_id.to_string()),
        ("suser", a.process.user.clone().unwrap_or_default()),
        ("sproc", a.process.image.clone()),
        ("spid", a.process.pid.to_string()),
        ("fileHash", a.process.sha256.clone().unwrap_or_default()),
        ("msg", a.summary.clone()),
        (
            "act",
            a.actions
                .iter()
                .filter(|o| o.ok)
                .map(|o| o.action.name())
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("cs1Label", "incident_id".into()),
        ("cs1", job.incident_id.to_string()),
        ("cs2Label", "attack".into()),
        ("cs2", a.attack.join(",")),
        ("cs3Label", "data_at_risk".into()),
        (
            "cs3",
            a.data_at_risk
                .iter()
                .filter_map(|c| serde_json::to_value(c).ok()?.as_str().map(String::from))
                .collect::<Vec<_>>()
                .join(","),
        ),
        ("externalId", a.id.to_string()),
    ]
    .iter()
    .filter(|(_, v)| !v.is_empty())
    .map(|(k, v)| format!("{k}={}", cef_escape_ext(v)))
    .collect::<Vec<_>>()
    .join(" ");
    format!(
        "CEF:0|Kestrel|Kestrel EDR|{}|{}|{}|{}|{}",
        kestrel_common::VERSION,
        cef_escape_header(&a.rule_id),
        cef_escape_header(&a.rule_name),
        sev,
        ext
    )
}

/// RFC 5424 frame (facility local4).
fn syslog_frame(sev: Severity, msg: &str) -> String {
    let level = match sev {
        Severity::Critical => 2,
        Severity::High => 3,
        Severity::Medium => 4,
        Severity::Low => 5,
        Severity::Info => 6,
    };
    let pri = 20 * 8 + level;
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "kestrel-server".into());
    format!("<{pri}>1 {ts} {host} kestrel - alert - {msg}")
}

/// Write the audit-chain head to the configured syslog destination (L6 anchor).
pub async fn send_audit_anchor(
    cfg: &SyslogCfg,
    allow: &[ipnet::IpNet],
    id: i64,
    hash: &str,
) -> anyhow::Result<()> {
    let line = format!("audit_head id={id} hash={hash}");
    let pri = 13 * 8 + 6; // log audit, informational
    let ts = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let host = std::env::var("HOSTNAME").unwrap_or_else(|_| "kestrel-server".into());
    let msg = format!("<{pri}>1 {ts} {host} kestrel - audit-anchor - {line}");
    send_syslog(cfg, allow, &msg).await
}

async fn send_syslog(cfg: &SyslogCfg, allow: &[ipnet::IpNet], msg: &str) -> anyhow::Result<()> {
    // Private collectors only with `allow_private`; link-local never (L7).
    let policy = netguard::Policy {
        allow: allow.to_vec(),
        allow_private: cfg.allow_private,
    };
    let host = cfg.host.as_str();
    let addrs = policy.resolve(host, cfg.port).await?;
    let addr = addrs[0];
    match cfg.protocol {
        SyslogProto::Udp => {
            let bind = if addr.is_ipv6() {
                "[::]:0"
            } else {
                "0.0.0.0:0"
            };
            let sock = tokio::net::UdpSocket::bind(bind).await?;
            sock.send_to(msg.as_bytes(), addr).await?;
        }
        SyslogProto::Tcp => {
            let mut s = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await??;
            s.write_all(format!("{msg}\n").as_bytes()).await?;
            s.flush().await?;
        }
        SyslogProto::Tls => {
            let mut roots = rustls::RootCertStore::empty();
            for c in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(c);
            }
            let cfg = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
            let tcp = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::net::TcpStream::connect(addr),
            )
            .await??;
            let name =
                rustls::pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_string())?;
            let mut s = connector.connect(name, tcp).await?;
            s.write_all(format!("{msg}\n").as_bytes()).await?;
            s.flush().await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cef_escaping() {
        let mut a = crate::incidents::server_tamper_alert(
            "TP-SRV|X",
            "a=b",
            Severity::High,
            "line1\nmsg=x".into(),
        );
        a.process.user = Some("CORP\\bob".into());
        let job = NotifyJob {
            alert: a,
            device_id: Uuid::nil(),
            hostname: "H".into(),
            incident_id: Uuid::nil(),
            incident_created: true,
        };
        let l = cef_line(&job);
        assert!(l.starts_with("CEF:0|Kestrel|Kestrel EDR|"));
        assert!(l.contains("TP-SRV\\|X|a=b|8|"));
        assert!(l.contains("msg=line1\\nmsg\\=x"));
        assert!(l.contains("suser=CORP\\\\bob"));
    }

    #[test]
    fn chat_escaping() {
        let evil = "x <https://evil.example|Open incident> & [click](https://evil) *b*";
        let sl = slack_escape(evil);
        assert!(!sl.contains('<') && !sl.contains('>'), "{sl}");
        assert!(sl.contains("&lt;https://evil.example|Open incident&gt; &amp;"));
        let t = teams_escape(evil);
        assert!(!t.contains("[click](") && !t.contains('<'), "{t}");
        assert!(t.contains("\\[click\\]\\(https://evil\\)"), "{t}");
    }

    #[tokio::test]
    async fn syslog_refuses_metadata_and_private_by_default() {
        let mut cfg = SyslogCfg {
            enabled: true,
            host: "169.254.169.254".into(),
            ..Default::default()
        };
        assert!(send_syslog(&cfg, &[], "x").await.is_err());
        cfg.host = "127.0.0.1".into();
        assert!(send_syslog(&cfg, &[], "x").await.is_err());
        cfg.allow_private = true;
        // UDP to loopback is allowed once explicitly opted in.
        assert!(send_syslog(&cfg, &[], "x").await.is_ok());
        cfg.host = "169.254.169.254".into();
        assert!(send_syslog(&cfg, &[], "x").await.is_err());
    }
}
