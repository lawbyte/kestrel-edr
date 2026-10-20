//! Key generation, CSR, enrollment, and TLS configuration.
//!
//! The agent trusts exactly one CA — the server CA pinned in `agent.toml` —
//! and never the system root store.

use anyhow::{anyhow, bail, Context, Result};
use kestrel_common::wire::{EnrollRequest, EnrollResponse, OsInfo};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};

use crate::config::{self, AgentConfig};
use crate::proto::{agent_service_client::AgentServiceClient, EnrollEnvelope};

/// Placeholder CN; the server issues the certificate with CN = device id.
pub const CSR_CN: &str = "kestrel-agent-pending-enrollment";

/// Install ring as the process-wide rustls provider. Safe to call repeatedly;
/// required when several providers are compiled into one workspace build.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub struct KeyMaterial {
    pub key_pem: String,
    pub csr_pem: String,
}

/// Fresh ECDSA P-256 key + PKCS#10 CSR.
pub fn generate_key_and_csr(hostname: &str) -> Result<KeyMaterial> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, CSR_CN);
    if !hostname.is_empty() {
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationalUnitName, hostname);
    }
    let csr = params.serialize_request(&kp)?;
    Ok(KeyMaterial {
        key_pem: kp.serialize_pem(),
        csr_pem: csr.pem()?,
    })
}

pub fn key_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join(config::KEY_FILE)
}
pub fn cert_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join(config::CERT_FILE)
}
pub fn agent_ca_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join(config::AGENT_CA_FILE)
}

/// True when a client certificate and key are present.
pub fn is_enrolled(state_dir: &Path, cfg: &AgentConfig) -> bool {
    cfg.device_id.is_some() && key_path(state_dir).is_file() && cert_path(state_dir).is_file()
}

/// Load the client identity (cert PEM, key PEM).
pub fn load_identity(state_dir: &Path) -> Result<(String, String)> {
    let cert =
        std::fs::read_to_string(cert_path(state_dir)).context("reading client certificate")?;
    let key = std::fs::read_to_string(key_path(state_dir)).context("reading client key")?;
    Ok((cert, key))
}

async fn endpoint(cfg: &AgentConfig, identity: Option<(String, String)>) -> Result<Endpoint> {
    let (host, port) = cfg.host_port()?;
    // H10: while the host is isolated only the agent may resolve names (its
    // own DNS queries); the OS resolver (DNS Client service) is blocked. So a
    // server configured by name is resolved here and dialled by IP; the TLS
    // name below is still the configured one.
    let host = resolve_server_addr(&host, port).await.unwrap_or(host);
    let host_uri = if host.contains(':') {
        format!("[{host}]")
    } else {
        host
    };
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(cfg.ca_pem.as_bytes()))
        .domain_name(cfg.tls_server_name()?)
        .assume_http2(true);
    if let Some((cert, key)) = identity {
        tls = tls.identity(Identity::from_pem(cert, key));
    }
    Ok(Endpoint::from_shared(format!("https://{host_uri}:{port}"))?
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(15))
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .http2_keep_alive_interval(Duration::from_secs(45))
        .keep_alive_timeout(Duration::from_secs(20))
        .keep_alive_while_idle(true))
}

/// `host` as an IP literal if it is a name that resolves (OS resolver first,
/// then the agent's own DNS query on Windows); `None` keeps the name.
async fn resolve_server_addr(host: &str, port: u16) -> Option<String> {
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    let os = tokio::time::timeout(
        Duration::from_secs(3),
        tokio::net::lookup_host((host.to_string(), port)),
    )
    .await;
    if let Ok(Ok(mut addrs)) = os {
        if let Some(a) = addrs.next() {
            return Some(a.ip().to_string());
        }
    }
    direct_resolve(host).await
}

#[cfg(all(windows, feature = "win-platform"))]
async fn direct_resolve(host: &str) -> Option<String> {
    let h = host.to_string();
    tokio::task::spawn_blocking(move || kestrel_win::resolve_host_direct(&h))
        .await
        .ok()?
        .first()
        .map(|ip| ip.to_string())
}

#[cfg(not(all(windows, feature = "win-platform")))]
async fn direct_resolve(_host: &str) -> Option<String> {
    None
}

/// Server-auth-only channel (enrollment).
pub async fn enroll_channel(cfg: &AgentConfig) -> Result<Channel> {
    install_crypto_provider();
    endpoint(cfg, None)
        .await?
        .connect()
        .await
        .context("connecting to server")
}

/// mTLS channel for the long-lived stream.
pub async fn mtls_channel(state_dir: &Path, cfg: &AgentConfig) -> Result<Channel> {
    install_crypto_provider();
    let id = load_identity(state_dir)?;
    endpoint(cfg, Some(id))
        .await?
        .connect()
        .await
        .context("connecting to server")
}

/// Enroll: generate key + CSR, exchange the token for a client certificate,
/// persist keys, and update `cfg.device_id` (caller saves the config).
pub async fn enroll(
    state_dir: &Path,
    cfg: &mut AgentConfig,
    token: &str,
    hostname: &str,
    os: OsInfo,
) -> Result<EnrollResponse> {
    if token.trim().is_empty() {
        bail!("an enrollment token is required");
    }
    let km = generate_key_and_csr(hostname)?;
    let req = EnrollRequest {
        token: token.trim().to_string(),
        csr_pem: km.csr_pem,
        hostname: hostname.to_string(),
        os,
    };
    let channel = enroll_channel(cfg).await?;
    let mut client = AgentServiceClient::new(channel);
    let resp = client
        .enroll(EnrollEnvelope {
            json: serde_json::to_vec(&req)?,
        })
        .await
        .map_err(|s| anyhow!("enrollment rejected: {} ({:?})", s.message(), s.code()))?
        .into_inner();
    let er: EnrollResponse =
        serde_json::from_slice(&resp.json).context("decoding EnrollResponse")?;
    // Sanity: the returned certificate must parse.
    let mut rd = std::io::BufReader::new(er.cert_pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut rd)
        .collect::<Result<_, _>>()
        .context("server sent an invalid certificate")?;
    if certs.is_empty() {
        bail!("server returned no client certificate");
    }
    config::write_secret(&key_path(state_dir), km.key_pem.as_bytes())?;
    config::write_secret(&cert_path(state_dir), er.cert_pem.as_bytes())?;
    if !er.ca_pem.trim().is_empty() {
        config::write_secret(&agent_ca_path(state_dir), er.ca_pem.as_bytes())?;
    }
    cfg.device_id = Some(er.device_id);
    cfg.pending_enroll_token = None;
    // M5: the server issues the per-device uninstall token; only its
    // Argon2id hash is stored. Old servers send none: keep what we have.
    if !er.uninstall_token.trim().is_empty() {
        cfg.set_uninstall_token(er.uninstall_token.trim())?;
    }
    Ok(er)
}

// ----------------------------------------------------------------- renewal

/// Renew when the client certificate has less than this left (H3).
pub const RENEW_BEFORE_SECS: i64 = 30 * 24 * 3600;

pub fn pending_key_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join("agent.key.new")
}
fn new_cert_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join("agent.crt.new")
}
pub fn prev_key_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join("agent.key.prev")
}
pub fn prev_cert_path(state_dir: &Path) -> PathBuf {
    config::keys_dir(state_dir).join("agent.crt.prev")
}

fn first_cert_der(pem: &str) -> Result<Vec<u8>> {
    let mut rd = std::io::BufReader::new(pem.as_bytes());
    let der = rustls_pemfile::certs(&mut rd)
        .next()
        .ok_or_else(|| anyhow!("no certificate in PEM"))?
        .context("invalid certificate PEM")?;
    Ok(der.as_ref().to_vec())
}

/// `notAfter` of the first certificate in `pem`, as Unix seconds.
pub fn cert_not_after(pem: &str) -> Result<i64> {
    let der = first_cert_der(pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow!("unparseable certificate: {e}"))?;
    Ok(cert.validity().not_after.timestamp())
}

/// Does the certificate in `cert_pem` certify the public key of `key_pem`?
pub fn cert_matches_key(cert_pem: &str, key_pem: &str) -> Result<bool> {
    let der = first_cert_der(cert_pem)?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der)
        .map_err(|e| anyhow!("unparseable certificate: {e}"))?;
    let kp = rcgen::KeyPair::from_pem(key_pem).context("unparseable private key")?;
    Ok(cert.public_key().raw == kp.public_key_der().as_slice())
}

/// Should the certificate be renewed at `now` (Unix seconds)?
pub fn needs_renewal(cert_pem: &str, now_secs: i64) -> bool {
    match cert_not_after(cert_pem) {
        Ok(na) => na - now_secs < RENEW_BEFORE_SECS,
        // Unreadable certificate: try to replace it while the session works.
        Err(_) => true,
    }
}

/// Seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    kestrel_common::now_ms() / 1000
}

/// Step 1: a fresh key (kept as `agent.key.new` until the certificate
/// arrives) and its CSR.
pub fn begin_renewal(state_dir: &Path, hostname: &str) -> Result<String> {
    let km = generate_key_and_csr(hostname)?;
    config::write_secret(&pending_key_path(state_dir), km.key_pem.as_bytes())?;
    Ok(km.csr_pem)
}

/// Step 2: install the renewed certificate. Validates that it parses, is
/// currently valid and certifies the pending key; keeps the previous
/// key/certificate as `*.prev` (removed by [`confirm_renewal`] once a
/// connection with the new identity succeeded, restored by
/// [`rollback_renewal`] otherwise). Each file is written atomically
/// (temp + rename).
pub fn complete_renewal(state_dir: &Path, cert_pem: &str, ca_pem: &str) -> Result<()> {
    let key = std::fs::read_to_string(pending_key_path(state_dir))
        .context("no renewal in progress (pending key missing)")?;
    if !cert_matches_key(cert_pem, &key)? {
        bail!("renewed certificate does not match the pending key");
    }
    let not_after = cert_not_after(cert_pem)?;
    if not_after <= now_secs() {
        bail!("renewed certificate is already expired");
    }
    // Keep the working identity until the new one has been proven.
    if let Ok((old_cert, old_key)) = load_identity(state_dir) {
        config::write_secret(&prev_key_path(state_dir), old_key.as_bytes())?;
        config::write_secret(&prev_cert_path(state_dir), old_cert.as_bytes())?;
    }
    config::write_secret(&new_cert_path(state_dir), cert_pem.as_bytes())?;
    // Swap: key first, then certificate; `recover_identity` repairs a crash
    // between the two renames.
    std::fs::rename(pending_key_path(state_dir), key_path(state_dir))
        .context("installing renewed key")?;
    std::fs::rename(new_cert_path(state_dir), cert_path(state_dir))
        .context("installing renewed certificate")?;
    if !ca_pem.trim().is_empty() {
        config::write_secret(&agent_ca_path(state_dir), ca_pem.as_bytes())?;
    }
    Ok(())
}

/// A connection with the renewed identity succeeded: drop the previous one.
pub fn confirm_renewal(state_dir: &Path) -> bool {
    let had = prev_key_path(state_dir).exists() || prev_cert_path(state_dir).exists();
    let _ = std::fs::remove_file(prev_key_path(state_dir));
    let _ = std::fs::remove_file(prev_cert_path(state_dir));
    had
}

/// Is a renewed identity still unconfirmed?
pub fn renewal_unconfirmed(state_dir: &Path) -> bool {
    prev_key_path(state_dir).exists() && prev_cert_path(state_dir).exists()
}

/// The renewed identity cannot connect: go back to the previous one.
pub fn rollback_renewal(state_dir: &Path) -> Result<bool> {
    if !renewal_unconfirmed(state_dir) {
        return Ok(false);
    }
    let k = std::fs::read_to_string(prev_key_path(state_dir))?;
    let c = std::fs::read_to_string(prev_cert_path(state_dir))?;
    if !cert_matches_key(&c, &k).unwrap_or(false) {
        bail!("previous identity is inconsistent; not restored");
    }
    config::write_secret(&key_path(state_dir), k.as_bytes())?;
    config::write_secret(&cert_path(state_dir), c.as_bytes())?;
    confirm_renewal(state_dir);
    Ok(true)
}

/// Start-up repair after a crash in the middle of a renewal: if the current
/// key and certificate do not match, use whichever consistent pair exists.
pub fn recover_identity(state_dir: &Path) -> Result<()> {
    let Ok((cert, key)) = load_identity(state_dir) else {
        return Ok(());
    };
    if cert_matches_key(&cert, &key).unwrap_or(false) {
        // Stale pending key from an interrupted renewal is harmless; drop it.
        let _ = std::fs::remove_file(new_cert_path(state_dir));
        return Ok(());
    }
    // Key already swapped, certificate not yet: finish with crt.new if present.
    if let Ok(newc) = std::fs::read_to_string(new_cert_path(state_dir)) {
        if cert_matches_key(&newc, &key).unwrap_or(false) {
            std::fs::rename(new_cert_path(state_dir), cert_path(state_dir))?;
            return Ok(());
        }
    }
    if rollback_renewal(state_dir)? {
        return Ok(());
    }
    bail!("client key and certificate do not match and no consistent backup exists")
}

/// rustls client config (pinned CA + client cert) for plain HTTPS downloads.
pub fn rustls_client_config(
    state_dir: &Path,
    cfg: &AgentConfig,
) -> Result<Arc<rustls::ClientConfig>> {
    install_crypto_provider();
    let mut roots = rustls::RootCertStore::empty();
    let mut rd = std::io::BufReader::new(cfg.ca_pem.as_bytes());
    for c in rustls_pemfile::certs(&mut rd) {
        roots.add(c?)?;
    }
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots);
    let mut conf = match load_identity(state_dir) {
        Ok((cert, key)) => {
            let mut rd = std::io::BufReader::new(cert.as_bytes());
            let chain = rustls_pemfile::certs(&mut rd).collect::<Result<Vec<_>, _>>()?;
            let mut rd = std::io::BufReader::new(key.as_bytes());
            let key =
                rustls_pemfile::private_key(&mut rd)?.ok_or_else(|| anyhow!("no private key"))?;
            builder.with_client_auth_cert(chain, key)?
        }
        Err(_) => builder.with_no_client_auth(),
    };
    conf.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(conf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(csr_pem: &str, days: i64) -> (String, String) {
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut p = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        p.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca = p.self_signed(&ca_key).unwrap();
        let mut csr = rcgen::CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        csr.params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        (csr.signed_by(&ca, &ca_key).unwrap().pem(), ca.pem())
    }

    #[test]
    fn renewal_swaps_atomically_and_rolls_back() {
        let dir = tempfile::tempdir().unwrap();
        let st = dir.path();
        // Current identity: 10 days left → needs renewal.
        let km = generate_key_and_csr("h").unwrap();
        let (cert, _) = issue(&km.csr_pem, 10);
        config::write_secret(&key_path(st), km.key_pem.as_bytes()).unwrap();
        config::write_secret(&cert_path(st), cert.as_bytes()).unwrap();
        assert!(needs_renewal(&cert, now_secs()));
        assert!(cert_matches_key(&cert, &km.key_pem).unwrap());
        // A certificate for a different key is refused and nothing changes.
        let csr = begin_renewal(st, "h").unwrap();
        let other = generate_key_and_csr("h").unwrap();
        let (wrong, _) = issue(&other.csr_pem, 365);
        assert!(complete_renewal(st, &wrong, "").is_err());
        assert_eq!(load_identity(st).unwrap().0, cert);
        // The matching one is installed; the previous identity is kept.
        let (renewed, ca) = issue(&csr, 365);
        complete_renewal(st, &renewed, &ca).unwrap();
        let (c, k) = load_identity(st).unwrap();
        assert_eq!(c, renewed);
        assert!(cert_matches_key(&c, &k).unwrap());
        assert!(!needs_renewal(&c, now_secs()));
        assert!(renewal_unconfirmed(st));
        assert!(!pending_key_path(st).exists());
        // Roll back (new identity could not connect) → old pair restored.
        assert!(rollback_renewal(st).unwrap());
        assert_eq!(load_identity(st).unwrap().0, cert);
        assert!(!renewal_unconfirmed(st));
        // Renew again and confirm.
        let csr = begin_renewal(st, "h").unwrap();
        let (renewed, _) = issue(&csr, 365);
        complete_renewal(st, &renewed, "").unwrap();
        assert!(confirm_renewal(st));
        assert!(!prev_key_path(st).exists());
        recover_identity(st).unwrap();
        assert_eq!(load_identity(st).unwrap().0, renewed);
    }

    #[test]
    fn recover_after_crash_between_renames() {
        let dir = tempfile::tempdir().unwrap();
        let st = dir.path();
        let km = generate_key_and_csr("h").unwrap();
        let (cert, _) = issue(&km.csr_pem, 100);
        config::write_secret(&key_path(st), km.key_pem.as_bytes()).unwrap();
        config::write_secret(&cert_path(st), cert.as_bytes()).unwrap();
        let csr = begin_renewal(st, "h").unwrap();
        let (renewed, _) = issue(&csr, 365);
        // Simulate: prev written, crt.new written, key renamed, crash.
        config::write_secret(&prev_key_path(st), km.key_pem.as_bytes()).unwrap();
        config::write_secret(&prev_cert_path(st), cert.as_bytes()).unwrap();
        config::write_secret(&new_cert_path(st), renewed.as_bytes()).unwrap();
        std::fs::rename(pending_key_path(st), key_path(st)).unwrap();
        recover_identity(st).unwrap();
        let (c, k) = load_identity(st).unwrap();
        assert_eq!(c, renewed);
        assert!(cert_matches_key(&c, &k).unwrap());
    }

    #[test]
    fn csr_is_parseable() {
        let km = generate_key_and_csr("FIN-LAPTOP-07").unwrap();
        assert!(km.key_pem.contains("PRIVATE KEY"));
        let p = rcgen::CertificateSigningRequestParams::from_pem(&km.csr_pem).unwrap();
        let cn = p
            .params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .unwrap();
        assert!(
            matches!(cn, rcgen::DnValue::Utf8String(s) if s == CSR_CN)
                || format!("{cn:?}").contains(CSR_CN)
        );
    }
}
