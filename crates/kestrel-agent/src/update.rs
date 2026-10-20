//! Signed agent updates.
//!
//! The server sends `UpdateManifest { version, url, sha256, signature }`
//! (only for releases an administrator promoted to this device's ring). The
//! agent:
//! 1. refuses unless an Ed25519 public key was embedded at build time
//!    (`KESTREL_UPDATE_PUBKEY`, base64 of the 32-byte key);
//! 2. verifies `signature` (base64 Ed25519) over [`signed_message`]:
//!    `kestrel-update-v1\n<version>\n<url>\n<lower-case sha256 hex>` — the
//!    signature binds the version and the download URL, not only the hash, so
//!    a signed package cannot be replayed under another version or URL
//!    (a downgrade or a re-pointed download);
//! 3. downloads `url` over HTTPS. A package on the Kestrel server (same host
//!    as the agent's server address — served on the agent port at
//!    `/downloads/updates/`) is fetched trusting only the pinned agent CA and
//!    presenting the client certificate. Any other host is verified against
//!    the public web PKI (Mozilla roots) without a client certificate: the
//!    signature and hash, not TLS, are what make the package trustworthy;
//! 4. checks the file's sha256;
//! 5. Windows: runs `msiexec /i <file> /qn /norestart` detached. Elsewhere the
//!    verified package is only stored (no installer).
//!
//! Failures are reported to the server (`AgentPayload::UpdateResult`, once
//! per version and error); success shows up as the new version in `Hello`.
//!
//! The owner's offline signing tool lives here too ([`keygen`],
//! [`sign_release`]; CLI `kestrel-agent update-keygen` / `update-sign`).

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use http_body_util::BodyExt;
use kestrel_common::wire::{AgentPayload, UpdateManifest};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

use crate::agent::Core;
use crate::store;

/// Update signing key embedded at build time.
pub const EMBEDDED_PUBKEY: Option<&str> = option_env!("KESTREL_UPDATE_PUBKEY");
const MAX_PACKAGE: u64 = 512 * 1024 * 1024;
/// `version|error` of the last failure reported (reported once).
const KV_LAST_UPDATE_FAILURE: &str = "last_update_failure";
/// File names written by [`keygen`].
pub const KEY_FILE: &str = "kestrel-update-signing.key";
pub const PUB_FILE: &str = "kestrel-update-signing.pub";
const KEY_HEADER: &str = "kestrel-update-signing-key-v1";

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
    kestrel_common::update::signed_message(m)
}

/// Verify the manifest format and signature. Pure; used by tests.
pub fn verify_manifest(key: &VerifyingKey, m: &UpdateManifest) -> Result<()> {
    kestrel_common::update::check_manifest_format(m).map_err(|e| anyhow!("manifest: {e}"))?;
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
    kestrel_common::update::is_newer(a, b)
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
    let r = apply(core, &m).await;
    if let Err(e) = &r {
        report_failure(core, &m.version, &format!("{e:#}"));
    }
    r
}

/// Tell the server (once per version + error) that the update failed.
fn report_failure(core: &Arc<Core>, version: &str, error: &str) {
    let error: String = error.chars().take(500).collect();
    let key = format!("{version}|{error}");
    if core
        .store
        .kv_get(KV_LAST_UPDATE_FAILURE)
        .ok()
        .flatten()
        .as_deref()
        == Some(key.as_str())
    {
        return;
    }
    let _ = core.store.kv_set(KV_LAST_UPDATE_FAILURE, &key);
    core.enqueue(&AgentPayload::UpdateResult {
        version: version.to_string(),
        ok: false,
        error,
    });
}

async fn apply(core: &Arc<Core>, m: &UpdateManifest) -> Result<()> {
    let key = verifying_key(EMBEDDED_PUBKEY)?;
    verify_manifest(&key, m)?;
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
    tracing::warn!(package = %file.display(), "verified update stored; automatic install is only supported on Windows");
    Ok(())
}

/// TLS for a package outside the Kestrel server: public web PKI, no client
/// certificate (never present the device identity to third parties).
fn public_tls() -> Result<Arc<rustls::ClientConfig>> {
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let conf = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(conf))
}

/// HTTPS GET into `dest`, returning the sha256 hex of the body. Speaks
/// HTTP/2 when the server negotiates it (the agent port is HTTP/2-only) and
/// HTTP/1.1 otherwise.
async fn download(
    url: &str,
    dest: &Path,
    pinned_tls: Arc<rustls::ClientConfig>,
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
    // Our own server: the pinned CA and the configured TLS name. Elsewhere:
    // the public web PKI.
    let (cfg_host, _) = cfg.host_port()?;
    let ours = host.eq_ignore_ascii_case(&cfg_host);
    let (base, sni) = if ours {
        (pinned_tls, cfg.tls_server_name()?)
    } else {
        (public_tls()?, host.clone())
    };
    let mut tls = (*base).clone();
    tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let server_name = rustls::pki_types::ServerName::try_from(sni.clone())
        .map_err(|_| anyhow!("bad TLS name {sni}"))?;
    let tcp = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timeout")??;
    let tls_stream = tokio_rustls::TlsConnector::from(Arc::new(tls))
        .connect(server_name, tcp)
        .await
        .context("TLS handshake")?;
    let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let user_agent = format!("kestrel-agent/{}", kestrel_common::VERSION);
    let mut resp = if h2 {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::get(uri.clone())
            .header(hyper::header::USER_AGENT, user_agent)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        sender.send_request(req).await?
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
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
            .header(hyper::header::USER_AGENT, user_agent)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        sender.send_request(req).await?
    };
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

// ------------------------------------------------------------------ signing tool

/// Output of [`keygen`].
#[derive(Debug)]
pub struct GeneratedKey {
    pub key_file: PathBuf,
    pub pub_file: PathBuf,
    /// Base64 Ed25519 public key (`KESTREL_UPDATE_PUBKEY` for the agent build
    /// and the server).
    pub public_key: String,
}

/// Create a new update signing key in `out_dir`: the private key file
/// (owner-only permissions) and the public key file. Refuses to overwrite.
pub fn keygen(out_dir: &Path) -> Result<GeneratedKey> {
    use rand::RngCore;
    std::fs::create_dir_all(out_dir).with_context(|| format!("creating {}", out_dir.display()))?;
    let key_file = out_dir.join(KEY_FILE);
    let pub_file = out_dir.join(PUB_FILE);
    if key_file.exists() || pub_file.exists() {
        bail!(
            "{} already contains an update signing key; refusing to overwrite it",
            out_dir.display()
        );
    }
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    seed.fill(0);
    let b64 = base64::engine::general_purpose::STANDARD;
    let public_key = b64.encode(sk.verifying_key().to_bytes());
    let secret = format!("{KEY_HEADER}\n{}\n", b64.encode(sk.to_bytes()));
    write_private(&key_file, secret.as_bytes())?;
    std::fs::write(&pub_file, format!("{public_key}\n"))
        .with_context(|| format!("writing {}", pub_file.display()))?;
    Ok(GeneratedKey {
        key_file,
        pub_file,
        public_key,
    })
}

/// Create `path` (must not exist) readable only by its owner, then write.
#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Create `path` (must not exist), strip inherited ACEs and grant only the
/// current user and SYSTEM (icacls), then write the secret.
#[cfg(windows)]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    let user = match (std::env::var("USERDOMAIN"), std::env::var("USERNAME")) {
        (Ok(d), Ok(u)) if !d.is_empty() => format!("{d}\\{u}"),
        (_, Ok(u)) => u,
        _ => String::new(),
    };
    let sys = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let mut cmd = std::process::Command::new(sys.join("System32").join("icacls.exe"));
    cmd.arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F"]);
    if !user.is_empty() {
        cmd.args(["/grant:r", &format!("{user}:F")]);
    }
    let ok = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        drop(f);
        let _ = std::fs::remove_file(path);
        bail!(
            "could not restrict permissions on {} (icacls failed); key not written",
            path.display()
        );
    }
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

/// Read a key file written by [`keygen`] (a bare base64 seed is accepted too).
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("reading signing key {}", path.display()))?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && *l != KEY_HEADER)
        .ok_or_else(|| anyhow!("{} holds no key", path.display()))?;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(line)
        .context("signing key is not base64")?;
    let seed: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("signing key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Lower-case hex SHA-256 of a file.
pub fn sha256_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Build and sign a manifest. `url` is where agents will download the
/// package (for a package on the Kestrel server:
/// `https://<host>:<agent port>/downloads/updates/<file>`).
pub fn sign_release(
    key: &SigningKey,
    version: &str,
    url: &str,
    sha256: &str,
) -> Result<UpdateManifest> {
    let mut m = UpdateManifest {
        version: version.trim().to_string(),
        url: url.trim().to_string(),
        sha256: sha256.trim().to_ascii_lowercase(),
        signature: "-".into(),
    };
    kestrel_common::update::check_manifest_format(&m).map_err(|e| anyhow!("{e}"))?;
    m.signature =
        base64::engine::general_purpose::STANDARD.encode(key.sign(&signed_message(&m)).to_bytes());
    verify_manifest(&key.verifying_key(), &m)?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn keygen_sign_verify_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("keys");
        let g = keygen(&out).unwrap();
        assert!(g.key_file.is_file() && g.pub_file.is_file());
        assert_eq!(
            std::fs::read_to_string(&g.pub_file).unwrap().trim(),
            g.public_key
        );
        // Never overwrite an existing key.
        assert!(keygen(&out).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&g.key_file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let sk = load_signing_key(&g.key_file).unwrap();
        let vk = verifying_key(Some(&g.public_key)).unwrap();
        assert_eq!(sk.verifying_key(), vk);

        let pkg = dir.path().join("KestrelAgent.msi");
        std::fs::write(&pkg, b"not really an msi").unwrap();
        let sha = sha256_file(&pkg).unwrap();
        assert_eq!(
            sha,
            hex::encode(Sha256::digest(b"not really an msi")),
            "sha256_file"
        );
        let m = sign_release(
            &sk,
            "1.4.0",
            "https://kestrel.acme.sg:8443/downloads/updates/KestrelAgent-1.4.0.msi",
            &sha,
        )
        .unwrap();
        verify_manifest(&vk, &m).unwrap();
        // Round trip through JSON (what the admin pastes into the console).
        let j = serde_json::to_string_pretty(&m).unwrap();
        let back: UpdateManifest = serde_json::from_str(&j).unwrap();
        verify_manifest(&vk, &back).unwrap();
        // A different key does not verify it.
        let other = keygen(&dir.path().join("other")).unwrap();
        let ok = verifying_key(Some(&other.public_key)).unwrap();
        assert!(verify_manifest(&ok, &m).is_err());
        // Bad inputs are refused before signing.
        assert!(sign_release(&sk, "1.4", "http://x/y.msi", &sha).is_err());
        assert!(sign_release(&sk, "latest", "https://x/y.msi", &sha).is_err());
        assert!(sign_release(&sk, "1.4", "https://x/y.msi", "abc").is_err());
        // Bare base64 key files load too; garbage does not.
        let bare = dir.path().join("bare.key");
        std::fs::write(
            &bare,
            base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
        )
        .unwrap();
        assert_eq!(
            load_signing_key(&bare).unwrap().to_bytes(),
            SigningKey::from_bytes(&[7u8; 32]).to_bytes()
        );
        std::fs::write(&bare, "not a key").unwrap();
        assert!(load_signing_key(&bare).is_err());
    }
}
