//! Signed agent updates.
//!
//! The server sends `UpdateManifest { version, url, sha256, signature }`.
//! The agent:
//! 1. refuses unless an Ed25519 public key was embedded at build time
//!    (`KESTREL_UPDATE_PUBKEY`, base64 of the 32-byte key);
//! 2. verifies `signature` (base64 Ed25519) over [`signed_message`]:
//!    `kestrel-update-v1\n<version>\n<url>\n<lower-case sha256 hex>` — the
//!    signature binds the version and the download URL, not only the hash, so
//!    a signed package cannot be replayed under another version or URL
//!    (a downgrade or a re-pointed download);
//! 3. downloads `url` over HTTPS trusting only the pinned server CA (and
//!    presenting the agent's client certificate);
//! 4. checks the file's sha256;
//! 5. Windows: runs `msiexec /i <file> /qn /norestart` detached. Elsewhere the
//!    verified package is only stored (no installer).

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use http_body_util::BodyExt;
use kestrel_common::wire::UpdateManifest;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::agent::Core;
use crate::store;

/// Update signing key embedded at build time.
pub const EMBEDDED_PUBKEY: Option<&str> = option_env!("KESTREL_UPDATE_PUBKEY");
const MAX_PACKAGE: u64 = 512 * 1024 * 1024;

pub fn verifying_key(b64: Option<&str>) -> Result<VerifyingKey> {
    let b64 = b64.filter(|s| !s.trim().is_empty()).ok_or_else(|| {
        anyhow!("this agent was built without KESTREL_UPDATE_PUBKEY; remote updates are disabled")
    })?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("bad update public key")?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("update public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&arr)?)
}

/// Bytes covered by the manifest signature (domain-separated, v1).
pub fn signed_message(m: &UpdateManifest) -> Vec<u8> {
    format!(
        "kestrel-update-v1\n{}\n{}\n{}",
        m.version.trim(),
        m.url.trim(),
        m.sha256.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

/// Verify the manifest signature. Pure; used by tests.
pub fn verify_manifest(key: &VerifyingKey, m: &UpdateManifest) -> Result<()> {
    let hex = m.sha256.trim().to_ascii_lowercase();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("manifest sha256 is not a hex digest");
    }
    if m.version.contains('\n') || m.url.contains('\n') {
        bail!("manifest fields must not contain line breaks");
    }
    let sig = base64::engine::general_purpose::STANDARD
        .decode(m.signature.trim())
        .context("bad signature encoding")?;
    let sig = Signature::from_slice(&sig).map_err(|_| anyhow!("bad signature length"))?;
    key.verify(&signed_message(m), &sig)
        .map_err(|_| anyhow!("update signature does not verify"))?;
    Ok(())
}

/// Simple dotted-numeric version compare: is `a` newer than `b`?
pub fn is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (mut x, mut y) = (parse(a), parse(b));
    let n = x.len().max(y.len());
    x.resize(n, 0);
    y.resize(n, 0);
    x > y
}

pub async fn handle(core: &Arc<Core>, m: UpdateManifest) -> Result<()> {
    if !is_newer(&m.version, kestrel_common::VERSION) {
        tracing::info!(offered = %m.version, running = kestrel_common::VERSION, "update not newer; ignored");
        return Ok(());
    }
    if core.store.kv_get(store::KV_LAST_UPDATE)?.as_deref() == Some(m.version.as_str()) {
        tracing::info!(version = %m.version, "update already attempted; waiting for installer");
        return Ok(());
    }
    let key = verifying_key(EMBEDDED_PUBKEY)?;
    verify_manifest(&key, &m)?;
    tracing::info!(version = %m.version, url = %m.url, "update manifest verified; downloading");
    let dir = core.state_dir.join("updates");
    tokio::fs::create_dir_all(&dir).await?;
    let file = dir.join(format!("kestrel-agent-{}.msi", sanitize(&m.version)));
    let cfg = core.config();
    let tls = crate::pki::rustls_client_config(&core.state_dir, &cfg)?;
    let digest = download(&m.url, &file, tls, &cfg).await?;
    if !digest.eq_ignore_ascii_case(m.sha256.trim()) {
        let _ = tokio::fs::remove_file(&file).await;
        bail!(
            "downloaded package hash {digest} does not match manifest {}",
            m.sha256
        );
    }
    core.store.kv_set(store::KV_LAST_UPDATE, &m.version)?;
    install(&file)
}

fn sanitize(v: &str) -> String {
    v.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

#[cfg(windows)]
fn install(file: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    let log = file.with_extension("log");
    let sys = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    std::process::Command::new(sys.join("System32").join("msiexec.exe"))
        .arg("/i")
        .arg(file)
        .args(["/qn", "/norestart", "/l*v"])
        .arg(&log)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .context("starting msiexec")?;
    tracing::info!(package = %file.display(), "installer started");
    Ok(())
}

#[cfg(not(windows))]
fn install(file: &Path) -> Result<()> {
    let _ = PathBuf::new();
    tracing::warn!(package = %file.display(), "verified update stored; automatic install is only supported on Windows");
    Ok(())
}

/// HTTPS GET into `dest`, returning the sha256 hex of the body.
async fn download(
    url: &str,
    dest: &Path,
    tls: Arc<rustls::ClientConfig>,
    cfg: &crate::config::AgentConfig,
) -> Result<String> {
    let uri: hyper::Uri = url.parse().context("bad update url")?;
    if uri.scheme_str() != Some("https") {
        bail!("update url must be https");
    }
    let host = uri
        .host()
        .ok_or_else(|| anyhow!("update url has no host"))?
        .trim_matches(['[', ']'])
        .to_string();
    let port = uri.port_u16().unwrap_or(443);
    // Use the configured TLS name when the package is served by our server host.
    let (cfg_host, _) = cfg.host_port()?;
    let sni = if host.eq_ignore_ascii_case(&cfg_host) {
        cfg.tls_server_name()?
    } else {
        host.clone()
    };
    let server_name = rustls::pki_types::ServerName::try_from(sni.clone())
        .map_err(|_| anyhow!("bad TLS name {sni}"))?;
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timeout")??;
    let tls_stream = tokio_rustls::TlsConnector::from(tls)
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;
    let (mut sender, conn) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(tls_stream)).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let host_hdr = match uri.port_u16() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let req = hyper::Request::get(path)
        .header(hyper::header::HOST, host_hdr)
        .header(
            hyper::header::USER_AGENT,
            format!("kestrel-agent/{}", kestrel_common::VERSION),
        )
        .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
    let mut resp = sender.send_request(req).await?;
    if !resp.status().is_success() {
        bail!("update download failed: HTTP {}", resp.status());
    }
    let tmp = dest.with_extension("part");
    let mut f = tokio::fs::File::create(&tmp).await?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let body = resp.body_mut();
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(chunk) = frame.data_ref() {
            total += chunk.len() as u64;
            if total > MAX_PACKAGE {
                drop(f);
                let _ = tokio::fs::remove_file(&tmp).await;
                bail!("update package exceeds {MAX_PACKAGE} bytes");
            }
            hasher.update(chunk);
            f.write_all(chunk).await?;
        }
    }
    f.flush().await?;
    f.sync_all().await?;
    drop(f);
    tokio::fs::rename(&tmp, dest).await?;
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signature_verification() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk_b64 =
            base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        let key = verifying_key(Some(&pk_b64)).unwrap();
        let sha = "ab".repeat(32);
        let mut m = UpdateManifest {
            version: "9.9.9".into(),
            url: "https://x/y.msi".into(),
            sha256: sha.clone(),
            signature: String::new(),
        };
        m.signature = base64::engine::general_purpose::STANDARD
            .encode(sk.sign(&signed_message(&m)).to_bytes());
        verify_manifest(&key, &m).unwrap();
        // The signature binds every field.
        let mut bad = m.clone();
        bad.sha256 = "cd".repeat(32);
        assert!(verify_manifest(&key, &bad).is_err());
        let mut bad = m.clone();
        bad.version = "9.9.10".into();
        assert!(verify_manifest(&key, &bad).is_err(), "version is signed");
        let mut bad = m.clone();
        bad.url = "https://evil/y.msi".into();
        assert!(verify_manifest(&key, &bad).is_err(), "url is signed");
        // Legacy signatures over the bare hash no longer verify.
        let mut legacy = m.clone();
        legacy.signature =
            base64::engine::general_purpose::STANDARD.encode(sk.sign(sha.as_bytes()).to_bytes());
        assert!(verify_manifest(&key, &legacy).is_err());
        assert!(verifying_key(None).is_err());
        assert!(verifying_key(Some("")).is_err());
    }

    #[test]
    fn versions() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
    }
}
