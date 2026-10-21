//! `<state_dir>/agent.toml` and key-material locations.

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const CONFIG_FILE: &str = "agent.toml";
pub const KEYS_DIR: &str = "keys";
pub const KEY_FILE: &str = "agent.key";
pub const CERT_FILE: &str = "agent.crt";
pub const AGENT_CA_FILE: &str = "agent-ca.pem";

/// Persistent agent configuration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct AgentConfig {
    /// Server gRPC address, `host:port`.
    pub server: String,
    /// TLS server name to verify (defaults to the host part of `server`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    /// Pinned server CA (PEM). The agent trusts nothing else.
    pub ca_pem: String,
    /// Assigned by the server at enrollment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
    /// Argon2id PHC hash of the uninstall token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uninstall_token_hash: Option<String>,
    /// Enrollment token kept only until enrollment succeeds (lets the service
    /// retry if the server was unreachable at install time).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_enroll_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Hostname override (simulator / tests).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Remote-access ceiling pinned at enrollment (`EnrollResponse.remote_profile`).
    /// Never changed by any later server message; only a new enrollment
    /// replaces it. `None` (enrolled before profiles) = no remote access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_ceiling: Option<kestrel_common::remote::RemoteAccessProfile>,
}

impl AgentConfig {
    /// The pinned remote-access ceiling (`none()` when absent).
    pub fn remote_ceiling(&self) -> kestrel_common::remote::RemoteAccessProfile {
        self.remote_ceiling.clone().unwrap_or_default()
    }
}

impl AgentConfig {
    pub fn path(state_dir: &Path) -> PathBuf {
        state_dir.join(CONFIG_FILE)
    }

    pub fn load(state_dir: &Path) -> Result<AgentConfig> {
        let p = Self::path(state_dir);
        let s = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        let c: AgentConfig =
            toml::from_str(&s).with_context(|| format!("parsing {}", p.display()))?;
        Ok(c)
    }

    pub fn save(&self, state_dir: &Path) -> Result<()> {
        std::fs::create_dir_all(state_dir)
            .with_context(|| format!("creating {}", state_dir.display()))?;
        let p = Self::path(state_dir);
        let tmp = p.with_extension("toml.tmp");
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            f.write_all(toml::to_string_pretty(self)?.as_bytes())?;
            f.sync_all()?;
        }
        restrict_perms(&tmp)?;
        // Atomic replace (MoveFileEx REPLACE_EXISTING on Windows).
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    /// `(host, port)` of the configured server.
    pub fn host_port(&self) -> Result<(String, u16)> {
        split_host_port(&self.server)
    }

    /// Name verified against the server certificate.
    pub fn tls_server_name(&self) -> Result<String> {
        match &self.server_name {
            Some(n) if !n.is_empty() => Ok(n.clone()),
            _ => Ok(self.host_port()?.0),
        }
    }

    pub fn set_uninstall_token(&mut self, token: &str) -> Result<()> {
        self.uninstall_token_hash = Some(hash_secret(token)?);
        Ok(())
    }

    /// Constant-time verification of the uninstall token. No hash configured → refuse.
    pub fn verify_uninstall_token(&self, token: &str) -> bool {
        match &self.uninstall_token_hash {
            Some(h) => verify_secret(token, h),
            None => false,
        }
    }
}

pub fn split_host_port(s: &str) -> Result<(String, u16)> {
    let s = s
        .trim()
        .trim_start_matches("https://")
        .trim_end_matches('/');
    // [v6]:port
    if let Some(rest) = s.strip_prefix('[') {
        let (h, p) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow!("bad server address {s:?}"))?;
        return Ok((h.to_string(), p.parse().context("bad port")?));
    }
    let (h, p) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("server address {s:?} must be host:port"))?;
    if h.is_empty() {
        bail!("server address {s:?} has an empty host");
    }
    Ok((
        h.to_string(),
        p.parse().with_context(|| format!("bad port in {s:?}"))?,
    ))
}

/// Default state directory: `C:\ProgramData\Kestrel` on Windows, `./kestrel-state` elsewhere.
pub fn default_state_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Kestrel")
    } else {
        PathBuf::from("./kestrel-state")
    }
}

pub fn keys_dir(state_dir: &Path) -> PathBuf {
    state_dir.join(KEYS_DIR)
}

/// Accept a CA as a PEM file path, inline PEM, or base64 (of PEM text or DER).
pub fn load_ca_arg(arg: &str) -> Result<String> {
    let p = Path::new(arg);
    let raw = if arg.len() < 4096 && p.is_file() {
        std::fs::read_to_string(p).with_context(|| format!("reading CA {}", p.display()))?
    } else {
        arg.to_string()
    };
    let raw = raw.trim();
    if raw.contains("-----BEGIN CERTIFICATE-----") {
        validate_pem_certs(raw)?;
        return Ok(format!("{raw}\n"));
    }
    let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .context("--ca is neither a file, PEM, nor base64")?;
    if let Ok(text) = std::str::from_utf8(&bytes) {
        if text.contains("-----BEGIN CERTIFICATE-----") {
            validate_pem_certs(text)?;
            return Ok(format!("{}\n", text.trim()));
        }
    }
    // DER certificate → PEM
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    validate_pem_certs(&pem)?;
    Ok(pem)
}

fn validate_pem_certs(pem: &str) -> Result<()> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .context("invalid CA PEM")?;
    if certs.is_empty() {
        bail!("CA PEM contains no certificates");
    }
    Ok(())
}

pub fn hash_secret(secret: &str) -> Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut OsRng);
    argon2::Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow!("hashing token: {e}"))
}

pub fn verify_secret(secret: &str, phc: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    match PasswordHash::new(phc) {
        Ok(h) => argon2::Argon2::default()
            .verify_password(secret.as_bytes(), &h)
            .is_ok(),
        Err(_) => false,
    }
}

/// Random URL-safe token (used when an uninstall token isn't supplied).
pub fn random_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!(
        "kun_{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    )
}

/// Restrict a secret file to its owner. On Unix: 0600. On Windows the state
/// directory ACL (SYSTEM + Administrators, set by the MSI) is what protects
/// keys; we don't re-ACL individual files here.
pub fn restrict_perms(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Write a secret file atomically with restricted permissions.
pub fn write_secret(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    let tmp = path.with_extension("tmp");
    {
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp)?;
        use std::io::Write;
        f.write_all(data)?;
        f.sync_all()?;
    }
    restrict_perms(&tmp)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut c = AgentConfig {
            server: "edr.example.com:8443".into(),
            server_name: Some("kestrel-server".into()),
            ca_pem: "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into(),
            device_id: Some(Uuid::new_v4()),
            tags: vec!["finance".into()],
            remote_ceiling: Some({
                let mut p = kestrel_common::remote::RemoteAccessProfile::guarded_default();
                p.guardrails.allowed_hours = Some(kestrel_common::remote::AllowedHours {
                    days: vec![0, 1, 2, 3, 4],
                    start_minute: 480,
                    end_minute: 1080,
                });
                p
            }),
            ..Default::default()
        };
        c.set_uninstall_token("s3cret").unwrap();
        c.save(dir.path()).unwrap();
        let back = AgentConfig::load(dir.path()).unwrap();
        assert_eq!(back, c);
        assert!(back.verify_uninstall_token("s3cret"));
        assert!(!back.verify_uninstall_token("wrong"));
        assert_eq!(back.tls_server_name().unwrap(), "kestrel-server");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let m = std::fs::metadata(AgentConfig::path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(m & 0o777, 0o600);
        }
    }

    #[test]
    fn no_hash_refuses_uninstall() {
        let c = AgentConfig::default();
        assert!(!c.verify_uninstall_token(""));
    }

    #[test]
    fn host_port_parsing() {
        assert_eq!(split_host_port("a.b:8443").unwrap(), ("a.b".into(), 8443));
        assert_eq!(
            split_host_port("https://10.0.0.1:1/").unwrap(),
            ("10.0.0.1".into(), 1)
        );
        assert_eq!(split_host_port("[::1]:9").unwrap(), ("::1".into(), 9));
        assert!(split_host_port("nohost").is_err());
        let c = AgentConfig {
            server: "srv.local:8443".into(),
            ..Default::default()
        };
        assert_eq!(c.tls_server_name().unwrap(), "srv.local");
    }

    #[test]
    fn ca_arg_forms() {
        let ca = rcgen::generate_simple_self_signed(vec!["x".into()]).unwrap();
        let pem = ca.cert.pem();
        assert!(load_ca_arg(&pem).unwrap().contains("BEGIN CERTIFICATE"));
        let b64 = base64::engine::general_purpose::STANDARD.encode(pem.as_bytes());
        assert!(load_ca_arg(&b64).unwrap().contains("BEGIN CERTIFICATE"));
        let der = base64::engine::general_purpose::STANDARD.encode(ca.cert.der());
        assert!(load_ca_arg(&der).unwrap().contains("BEGIN CERTIFICATE"));
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("ca.pem");
        std::fs::write(&f, &pem).unwrap();
        assert!(load_ca_arg(f.to_str().unwrap())
            .unwrap()
            .contains("BEGIN CERTIFICATE"));
        assert!(load_ca_arg("not a cert!").is_err());
    }
}
