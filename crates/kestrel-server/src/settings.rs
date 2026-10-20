//! Org settings singleton (`settings` row id = 1). Secrets are stored separately,
//! encrypted with the master key, and are write-only over the API.

use crate::crypto::MasterKey;
use kestrel_common::{Branding, Severity};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Settings {
    pub org_name: String,
    pub branding: Branding,
    pub retention_days: Retention,
    pub notifications: Notifications,
    pub oidc: Oidc,
    pub session_timeout_minutes: u32,
    /// Absolute session lifetime regardless of activity (L5).
    pub session_max_days: u32,
    pub require_mfa: bool,
}

impl Settings {
    pub fn session_max_age_ms(&self) -> i64 {
        self.session_max_days.clamp(1, 90) as i64 * 86_400_000
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            org_name: String::new(),
            branding: Branding::default(),
            retention_days: Retention::default(),
            notifications: Notifications::default(),
            oidc: Oidc::default(),
            session_timeout_minutes: 480,
            session_max_days: 7,
            require_mfa: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Retention {
    pub events: u32,
    pub alerts: u32,
    pub audit: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention {
            events: 30,
            alerts: 365,
            audit: 730,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct Notifications {
    pub email: EmailCfg,
    pub slack: ChatCfg,
    pub teams: ChatCfg,
    pub webhook: WebhookCfg,
    pub syslog: SyslogCfg,
}

fn sev_high() -> Severity {
    Severity::High
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct EmailCfg {
    pub enabled: bool,
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: String,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default = "sev_high")]
    pub min_severity: Severity,
}

impl Default for EmailCfg {
    fn default() -> Self {
        EmailCfg {
            enabled: false,
            smtp_host: String::new(),
            smtp_port: 587,
            username: String::new(),
            from: String::new(),
            to: vec![],
            min_severity: Severity::High,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct ChatCfg {
    pub enabled: bool,
    pub webhook_url: String,
    pub min_severity: Severity,
}

impl Default for ChatCfg {
    fn default() -> Self {
        ChatCfg {
            enabled: false,
            webhook_url: String::new(),
            min_severity: Severity::High,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct WebhookCfg {
    pub enabled: bool,
    pub url: String,
    pub min_severity: Severity,
}

impl Default for WebhookCfg {
    fn default() -> Self {
        WebhookCfg {
            enabled: false,
            url: String::new(),
            min_severity: Severity::Medium,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogProto {
    #[default]
    Udp,
    Tcp,
    Tls,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum SyslogFormat {
    #[default]
    Cef,
    Json,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct SyslogCfg {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub protocol: SyslogProto,
    pub format: SyslogFormat,
    /// Extension: minimum severity forwarded (default: everything).
    pub min_severity: Severity,
    /// Allow a private / loopback syslog destination (link-local stays blocked).
    pub allow_private: bool,
}

impl Default for SyslogCfg {
    fn default() -> Self {
        SyslogCfg {
            enabled: false,
            host: String::new(),
            port: 514,
            protocol: SyslogProto::Udp,
            format: SyslogFormat::Cef,
            min_severity: Severity::Info,
            allow_private: false,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Oidc {
    pub enabled: bool,
    pub issuer: String,
    pub client_id: String,
    /// Email domains allowed to sign in. Empty = nobody (fail closed).
    pub allowed_domains: Vec<String>,
    /// Role of users created by their first SSO login (never `admin`).
    pub default_role: String,
}

impl Oidc {
    /// Domain allow-list check (H6): an empty list denies everyone.
    pub fn domain_allowed(&self, email: &str) -> bool {
        let Some((_, domain)) = email.rsplit_once('@') else {
            return false;
        };
        !domain.is_empty()
            && self.allowed_domains.iter().any(|d| {
                let d = d.trim().trim_start_matches('@');
                !d.is_empty() && d.eq_ignore_ascii_case(domain)
            })
    }
}

impl Default for Oidc {
    fn default() -> Self {
        Oidc {
            enabled: false,
            issuer: String::new(),
            client_id: String::new(),
            allowed_domains: vec![],
            default_role: "readonly".into(),
        }
    }
}

/// Write-only secrets, stored encrypted.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct Secrets {
    pub oidc_client_secret: String,
    pub smtp_password: String,
    pub webhook_secret: String,
}

pub async fn load(db: &PgPool) -> anyhow::Result<Settings> {
    let (body,): (serde_json::Value,) = sqlx::query_as("SELECT body FROM settings WHERE id = 1")
        .fetch_one(db)
        .await?;
    Ok(serde_json::from_value(body).unwrap_or_default())
}

pub async fn load_secrets(db: &PgPool, mk: &MasterKey) -> anyhow::Result<Secrets> {
    let (enc,): (Option<String>,) = sqlx::query_as("SELECT secrets_enc FROM settings WHERE id = 1")
        .fetch_one(db)
        .await?;
    match enc {
        Some(e) if !e.is_empty() => Ok(serde_json::from_slice(&mk.open(&e)?)?),
        _ => Ok(Secrets::default()),
    }
}

pub async fn save_secrets(db: &PgPool, mk: &MasterKey, s: &Secrets) -> anyhow::Result<()> {
    let enc = mk.seal(&serde_json::to_vec(s)?);
    sqlx::query("UPDATE settings SET secrets_enc = $1, updated_at = kestrel_now_ms() WHERE id = 1")
        .bind(enc)
        .execute(db)
        .await?;
    Ok(())
}

/// API view: secrets replaced by `*_set` booleans.
pub fn to_api(s: &Settings, secrets: &Secrets, reveal_urls: bool) -> serde_json::Value {
    let mut v = serde_json::to_value(s).unwrap_or_default();
    v["oidc"]["client_secret_set"] = (!secrets.oidc_client_secret.is_empty()).into();
    v["notifications"]["email"]["password_set"] = (!secrets.smtp_password.is_empty()).into();
    v["notifications"]["webhook"]["secret_set"] = (!secrets.webhook_secret.is_empty()).into();
    if !reveal_urls {
        // Webhook URLs are bearer secrets (Slack/Teams) or internal endpoints.
        for (ch, key) in [
            ("slack", "webhook_url"),
            ("teams", "webhook_url"),
            ("webhook", "url"),
        ] {
            let set = !v["notifications"][ch][key]
                .as_str()
                .unwrap_or("")
                .is_empty();
            v["notifications"][ch][key] = "".into();
            v["notifications"][ch][format!("{key}_set")] = set.into();
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_domain_list_denies() {
        let mut o = Oidc::default();
        assert!(!o.domain_allowed("a@corp.com"));
        o.allowed_domains = vec!["@Corp.com".into(), " ".into()];
        assert!(o.domain_allowed("a@corp.com"));
        assert!(!o.domain_allowed("a@evilcorp.com"));
        assert!(!o.domain_allowed("corp.com"));
        o.allowed_domains = vec!["".into()];
        assert!(!o.domain_allowed("a@"));
    }

    #[test]
    fn generic_webhook_url_masked() {
        let mut s = Settings::default();
        s.notifications.webhook.url = "https://siem.corp/hook?key=secret".into();
        let v = to_api(&s, &Secrets::default(), false);
        assert_eq!(v["notifications"]["webhook"]["url"], "");
        assert_eq!(v["notifications"]["webhook"]["url_set"], true);
        let v = to_api(&s, &Secrets::default(), true);
        assert_eq!(
            v["notifications"]["webhook"]["url"],
            "https://siem.corp/hook?key=secret"
        );
    }
}
