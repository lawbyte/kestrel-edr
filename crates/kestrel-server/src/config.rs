//! Runtime configuration from environment variables.

use std::{net::SocketAddr, path::PathBuf};

#[derive(Clone, Debug)]
pub struct Config {
    /// Postgres connection string.
    pub database_url: String,
    /// Secret used to wrap keys/secrets at rest (AES-256-GCM key derived from it).
    pub master_key: String,
    /// Hostname(s) agents and browsers use to reach this server (comma separated; first is primary).
    pub public_hostnames: Vec<String>,
    pub https_addr: SocketAddr,
    pub grpc_addr: SocketAddr,
    /// Port agents connect to (may differ from the bind port behind NAT).
    pub grpc_public_port: u16,
    /// Optional operator-supplied web TLS certificate/key (PEM paths).
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub console_dir: PathBuf,
    /// Directory holding agent installers served at /downloads/.
    pub agent_dir: PathBuf,
    pub agent_msi_url: Option<String>,
    pub clickhouse: Option<ClickHouseConfig>,
    /// Expected agent heartbeat interval (tamper heuristics).
    pub heartbeat_interval_ms: i64,
    /// Reverse proxies whose `X-Forwarded-For` is honoured (`KESTREL_TRUSTED_PROXIES`,
    /// comma-separated IPs/CIDRs). Empty: the TCP peer address is always used.
    pub trusted_proxies: Vec<ipnet::IpNet>,
    /// One-time first-run setup code (`KESTREL_SETUP_CODE`). When unset a random
    /// code is generated at startup and printed to the server log.
    pub setup_code: Option<String>,
    /// Private ranges outbound HTTP (webhooks, OIDC) may reach
    /// (`KESTREL_OUTBOUND_ALLOW_CIDRS`); everything private is blocked otherwise.
    pub outbound_allow: Vec<ipnet::IpNet>,
    /// Base64 Ed25519 public key that agent release manifests must be signed
    /// with (`KESTREL_UPDATE_PUBKEY`). Unset: release registration is refused.
    /// The matching private key never touches the server.
    pub update_pubkey: Option<String>,
    /// Run background jobs (retention, status) — disabled in some tests.
    pub run_jobs: bool,
}

#[derive(Clone, Debug)]
pub struct ClickHouseConfig {
    pub url: String,
    pub user: String,
    pub password: String,
    pub database: String,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

impl Config {
    pub fn from_env() -> anyhow::Result<Config> {
        let database_url = match env("DATABASE_URL") {
            Some(u) => u,
            None => {
                let host = env("POSTGRES_HOST").unwrap_or_else(|| "postgres".into());
                let port = env("POSTGRES_PORT").unwrap_or_else(|| "5432".into());
                let user = env("POSTGRES_USER").unwrap_or_else(|| "kestrel".into());
                let pass = env("POSTGRES_PASSWORD").ok_or_else(|| {
                    anyhow::anyhow!("DATABASE_URL or POSTGRES_PASSWORD must be set")
                })?;
                let db = env("POSTGRES_DB").unwrap_or_else(|| "kestrel".into());
                format!("postgres://{user}:{}@{host}:{port}/{db}", urlencode(&pass))
            }
        };
        let master_key = env("KESTREL_MASTER_KEY").ok_or_else(|| {
            anyhow::anyhow!(
                "KESTREL_MASTER_KEY is required (generate one with `openssl rand -base64 32`)"
            )
        })?;
        if master_key.len() < 16 {
            anyhow::bail!(
                "KESTREL_MASTER_KEY must be at least 16 characters (use `openssl rand -base64 32`)"
            );
        }
        let public_hostnames: Vec<String> = env("KESTREL_PUBLIC_HOSTNAME")
            .unwrap_or_else(|| "localhost".into())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let clickhouse = env("CLICKHOUSE_URL").map(|url| ClickHouseConfig {
            url: url.trim_end_matches('/').to_string(),
            user: env("CLICKHOUSE_USER").unwrap_or_else(|| "default".into()),
            password: env("CLICKHOUSE_PASSWORD").unwrap_or_default(),
            database: env("CLICKHOUSE_DB")
                .or_else(|| env("CLICKHOUSE_DATABASE"))
                .unwrap_or_else(|| "kestrel".into()),
        });
        Ok(Config {
            database_url,
            master_key,
            public_hostnames,
            https_addr: env("KESTREL_HTTPS_ADDR")
                .unwrap_or_else(|| "0.0.0.0:443".into())
                .parse()?,
            grpc_addr: env("KESTREL_GRPC_ADDR")
                .unwrap_or_else(|| "0.0.0.0:8443".into())
                .parse()?,
            grpc_public_port: env("KESTREL_GRPC_PUBLIC_PORT")
                .map(|p| p.parse())
                .transpose()?
                .unwrap_or(8443),
            tls_cert: env("TLS_CERT").map(PathBuf::from),
            tls_key: env("TLS_KEY").map(PathBuf::from),
            console_dir: env("CONSOLE_DIR")
                .unwrap_or_else(|| "/app/console".into())
                .into(),
            agent_dir: env("AGENT_DIR")
                .unwrap_or_else(|| "/app/agent".into())
                .into(),
            agent_msi_url: env("KESTREL_AGENT_MSI_URL"),
            clickhouse,
            heartbeat_interval_ms: env("KESTREL_HEARTBEAT_INTERVAL_SECS")
                .map(|s| s.parse::<i64>())
                .transpose()?
                .unwrap_or(60)
                * 1000,
            trusted_proxies: parse_nets("KESTREL_TRUSTED_PROXIES")?,
            setup_code: env("KESTREL_SETUP_CODE"),
            outbound_allow: parse_nets("KESTREL_OUTBOUND_ALLOW_CIDRS")?,
            update_pubkey: match env("KESTREL_UPDATE_PUBKEY") {
                Some(k) => {
                    crate::updates::parse_pubkey(&k)
                        .map_err(|e| anyhow::anyhow!("KESTREL_UPDATE_PUBKEY: {e}"))?;
                    Some(k.trim().to_string())
                }
                None => None,
            },
            run_jobs: true,
        })
    }

    pub fn primary_hostname(&self) -> &str {
        self.public_hostnames
            .first()
            .map(|s| s.as_str())
            .unwrap_or("localhost")
    }

    /// `host:port` agents should dial.
    pub fn agent_server_addr(&self) -> String {
        format!("{}:{}", self.primary_hostname(), self.grpc_public_port)
    }

    /// Base URL of the console as seen by browsers.
    pub fn public_base_url(&self) -> String {
        let port = self.https_addr.port();
        if port == 443 {
            format!("https://{}", self.primary_hostname())
        } else {
            format!("https://{}:{}", self.primary_hostname(), port)
        }
    }
}

/// Comma-separated IPs / CIDRs from an environment variable.
fn parse_nets(name: &str) -> anyhow::Result<Vec<ipnet::IpNet>> {
    if env("KESTREL_TRUST_PROXY_HEADERS").is_some() && name == "KESTREL_TRUSTED_PROXIES" {
        tracing::warn!("KESTREL_TRUST_PROXY_HEADERS is no longer supported; list the proxy addresses in KESTREL_TRUSTED_PROXIES");
    }
    parse_net_list(&env(name).unwrap_or_default()).map_err(|e| anyhow::anyhow!("{name}: {e}"))
}

pub fn parse_net_list(s: &str) -> anyhow::Result<Vec<ipnet::IpNet>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| {
            p.parse::<ipnet::IpNet>()
                .or_else(|_| p.parse::<std::net::IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| anyhow::anyhow!("invalid IP or CIDR '{p}'"))
        })
        .collect()
}

fn urlencode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
