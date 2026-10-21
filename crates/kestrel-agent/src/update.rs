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
//! 4. checks the package's sha256 **from disk** (security review v1.1 V-H3):
//!    the download goes to a random temp name opened `create_new` with no
//!    sharing, is renamed to a fresh random name, re-opened deny-write
//!    (`FILE_SHARE_READ` only) and hashed through that handle, which stays
//!    open until msiexec has exited, so nobody can swap the bytes between the
//!    check and the install;
//! 5. optionally (build-time `KESTREL_UPDATE_REQUIRE_SIGNED`) requires a valid
//!    Authenticode signature on the MSI from the named signer;
//! 6. Windows: runs `msiexec /i <file> /qn /norestart /l*v <log>` and waits for
//!    it. Elsewhere the verified package is only stored (no installer).
//!
//! Only one update runs at a time ([`try_begin`]); a delivery that arrives
//! while one is in flight is ignored. Downloads have an overall deadline, a
//! per-read timeout and a minimum throughput (V-L9).
//!
//! Results (V-M3) go to the server as `AgentPayload::UpdateResult`. The MSI
//! upgrade stops the running service, so usually the *new* agent reports
//! success: [`on_startup`] checks the version recorded as pending before
//! msiexec started. `KV_LAST_UPDATE` is written only after success. A failed
//! version is retried at most every [`RETRY_AFTER_MS`].
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;

use crate::agent::Core;
use crate::store;

/// Update signing key embedded at build time.
pub const EMBEDDED_PUBKEY: Option<&str> = option_env!("KESTREL_UPDATE_PUBKEY");
/// Build-time Authenticode requirement for update MSIs: a substring of the
/// required signer's subject (e.g. `Acme Pte Ltd`). Unset / empty = no
/// Authenticode check (the Ed25519 manifest signature + SHA-256 still apply).
pub const REQUIRE_SIGNED: Option<&str> = option_env!("KESTREL_UPDATE_REQUIRE_SIGNED");
const MAX_PACKAGE: u64 = 512 * 1024 * 1024;
/// `version|error` of the last failure reported (reported once).
const KV_LAST_UPDATE_FAILURE: &str = "last_update_failure";
/// `version|unix ms` of the last attempt (download started).
const KV_UPDATE_ATTEMPT: &str = "update_attempt";
/// Version whose installer was started and whose outcome is not known yet.
pub const KV_UPDATE_PENDING: &str = "update_pending";
/// A failed version is tried again at most this often.
pub const RETRY_AFTER_MS: i64 = 6 * 3600 * 1000;
/// Whole download (connect to last byte).
const DOWNLOAD_DEADLINE: Duration = Duration::from_secs(30 * 60);
/// No single read may stall longer than this.
const READ_TIMEOUT: Duration = Duration::from_secs(60);
/// Minimum throughput: at least this many bytes in every window.
const MIN_WINDOW_BYTES: u64 = 64 * 1024;
const THROUGHPUT_WINDOW: Duration = Duration::from_secs(60);
/// msiexec is waited for at most this long.
#[cfg(windows)]
const INSTALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
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

// ------------------------------------------------------------------ one at a time

static IN_FLIGHT: AtomicBool = AtomicBool::new(false);

/// Held while an update runs; dropping it lets the next delivery through.
#[derive(Debug)]
pub struct InFlight(());

impl Drop for InFlight {
    fn drop(&mut self) {
        IN_FLIGHT.store(false, Ordering::SeqCst);
    }
}

/// Claim the single update slot (V-H3). `None` while another update runs.
pub fn try_begin() -> Option<InFlight> {
    IN_FLIGHT
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .ok()
        .map(|_| InFlight(()))
}

/// Should an attempt at `version` start now, given the last attempt record
/// (`version|unix ms`)? A different version always may; the same one only
/// after [`RETRY_AFTER_MS`].
pub fn attempt_allowed(last_attempt: Option<&str>, version: &str, now_ms: i64) -> bool {
    let Some((v, t)) = last_attempt.and_then(|s| s.rsplit_once('|')) else {
        return true;
    };
    if v != version {
        return true;
    }
    match t.parse::<i64>() {
        Ok(t) => now_ms - t >= RETRY_AFTER_MS || now_ms < t,
        Err(_) => true,
    }
}

/// msiexec exit code → Ok(note) on success, Err(message) otherwise.
pub fn msiexec_outcome(code: Option<i32>) -> std::result::Result<&'static str, String> {
    match code {
        Some(0) => Ok(""),
        Some(3010) => Ok("installed; a reboot is required to finish"),
        Some(1641) => Ok("installed; the installer initiated a reboot"),
        Some(1618) => Err("msiexec exit 1618: another installation is in progress".into()),
        Some(1638) => Err("msiexec exit 1638: this version is already installed".into()),
        Some(1603) => Err("msiexec exit 1603: fatal error during installation (see the MSI log in the state directory's updates folder)".into()),
        Some(c) => Err(format!("msiexec exit {c}")),
        None => Err("msiexec was terminated".into()),
    }
}

/// What a freshly started agent should report about a pending update.
#[derive(Debug, PartialEq, Eq)]
pub enum PendingOutcome {
    /// Nothing was pending.
    None,
    /// The pending version is the one now running.
    Succeeded(String),
    /// The installer started but this version is not the pending one.
    Failed(String),
}

pub fn pending_outcome(pending: Option<&str>, running: &str) -> PendingOutcome {
    match pending.map(str::trim).filter(|p| !p.is_empty()) {
        None => PendingOutcome::None,
        Some(p) if p == running => PendingOutcome::Succeeded(p.to_string()),
        Some(p) => PendingOutcome::Failed(p.to_string()),
    }
}

/// Called once after the agent started: report the outcome of an update
/// whose installer was started by the previous agent process.
pub fn on_startup(core: &Arc<Core>) {
    let pending = core.store.kv_get(KV_UPDATE_PENDING).ok().flatten();
    match pending_outcome(pending.as_deref(), kestrel_common::VERSION) {
        PendingOutcome::None => {}
        PendingOutcome::Succeeded(v) => {
            tracing::info!(version = %v, "agent update installed");
            let _ = core.store.kv_set(store::KV_LAST_UPDATE, &v);
            let _ = core.store.kv_set(KV_UPDATE_PENDING, "");
            core.enqueue(&AgentPayload::UpdateResult {
                version: v,
                ok: true,
                error: String::new(),
            });
        }
        PendingOutcome::Failed(v) => {
            let _ = core.store.kv_set(KV_UPDATE_PENDING, "");
            report_failure(
                core,
                &v,
                &format!(
                    "installer did not complete (agent {} is still running)",
                    kestrel_common::VERSION
                ),
            );
        }
    }
}

pub async fn handle(core: &Arc<Core>, m: UpdateManifest) -> Result<()> {
    if !is_newer(&m.version, kestrel_common::VERSION) {
        tracing::info!(offered = %m.version, running = kestrel_common::VERSION, "update not newer; ignored");
        return Ok(());
    }
    if core.store.kv_get(store::KV_LAST_UPDATE)?.as_deref() == Some(m.version.as_str()) {
        tracing::info!(version = %m.version, "update already installed; waiting for the restart");
        return Ok(());
    }
    let now = kestrel_common::now_ms();
    let last = core.store.kv_get(KV_UPDATE_ATTEMPT)?;
    if !attempt_allowed(last.as_deref(), &m.version, now) {
        tracing::info!(version = %m.version, "update attempted recently; retrying later");
        return Ok(());
    }
    core.store
        .kv_set(KV_UPDATE_ATTEMPT, &format!("{}|{now}", m.version))?;
    let r = apply(core, &m).await;
    if let Err(e) = &r {
        let _ = core.store.kv_set(KV_UPDATE_PENDING, "");
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

fn random_name(prefix: &str, ext: &str) -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("{prefix}-{}.{ext}", hex::encode(b))
}

/// Remove leftovers of earlier attempts (the updates folder is inside the
/// SYSTEM-only state directory; nothing else lives there).
fn clean_updates_dir(dir: &Path) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if e.file_type().is_ok_and(|t| t.is_file())
                && p.extension().is_some_and(|x| {
                    x.eq_ignore_ascii_case("part") || x.eq_ignore_ascii_case("msi")
                })
            {
                let _ = std::fs::remove_file(&p);
            }
        }
    }
}

async fn apply(core: &Arc<Core>, m: &UpdateManifest) -> Result<()> {
    let key = verifying_key(EMBEDDED_PUBKEY)?;
    verify_manifest(&key, m)?;
    tracing::info!(version = %m.version, url = %m.url, "update manifest verified; downloading");
    let dir = core.state_dir.join("updates");
    tokio::fs::create_dir_all(&dir).await?;
    clean_updates_dir(&dir);
    let tmp = dir.join(random_name("dl", "part"));
    let file = dir.join(random_name("pkg", "msi"));
    let cfg = core.config();
    let tls = crate::pki::rustls_client_config(&core.state_dir, &cfg)?;
    let r = tokio::time::timeout(DOWNLOAD_DEADLINE, download(&m.url, &tmp, tls, &cfg)).await;
    let net_digest = match r {
        Ok(Ok(d)) => d,
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e);
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            bail!(
                "update download exceeded {} minutes",
                DOWNLOAD_DEADLINE.as_secs() / 60
            );
        }
    };
    tokio::fs::rename(&tmp, &file).await?;
    // Re-open deny-write and hash what is on disk (V-H3); keep the handle.
    let (pinned, digest) = {
        let f = file.clone();
        tokio::task::spawn_blocking(move || open_and_hash(&f)).await??
    };
    if !digest.eq_ignore_ascii_case(m.sha256.trim()) || !net_digest.eq_ignore_ascii_case(&digest) {
        drop(pinned);
        let _ = tokio::fs::remove_file(&file).await;
        bail!(
            "downloaded package hash {digest} does not match manifest {}",
            m.sha256
        );
    }
    check_authenticode(&file)?;
    core.store.kv_set(KV_UPDATE_PENDING, &m.version)?;
    let f = file.clone();
    let outcome = tokio::task::spawn_blocking(move || install(&f, pinned)).await?;
    let _ = tokio::fs::remove_file(&file).await;
    let note = outcome?;
    core.store.kv_set(store::KV_LAST_UPDATE, &m.version)?;
    core.store.kv_set(KV_UPDATE_PENDING, "")?;
    tracing::info!(version = %m.version, "{}", if note.is_empty() { "update installed" } else { note });
    core.enqueue(&AgentPayload::UpdateResult {
        version: m.version.clone(),
        ok: true,
        error: note.to_string(),
    });
    Ok(())
}

/// Open `path` read-only, deny-write (Windows: `FILE_SHARE_READ` only), and
/// return the handle with the SHA-256 of the bytes read through it.
fn open_and_hash(path: &Path) -> Result<(std::fs::File, String)> {
    use std::io::{Read, Seek};
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x1;
        o.share_mode(FILE_SHARE_READ);
    }
    let mut f = o
        .open(path)
        .with_context(|| format!("re-opening {}", path.display()))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    f.rewind()?;
    Ok((f, hex::encode(h.finalize())))
}

/// Authenticode on the MSI when the build requires a signer (default off:
/// the owner has no code-signing certificate yet; see docs/DECISIONS.md).
fn check_authenticode(file: &Path) -> Result<()> {
    let Some(signer) = REQUIRE_SIGNED.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    authenticode_signer_ok(file, signer)
}

/// WinVerifyTrust (whole chain, online revocation) on the pinned package; the
/// signer subject must contain `signer` (case-insensitive).
#[cfg(all(windows, feature = "win-platform"))]
fn authenticode_signer_ok(file: &Path, signer: &str) -> Result<()> {
    let (state, subject) = kestrel_win::verify_file_signature(file);
    if state != kestrel_common::SignatureState::Valid {
        bail!("update package has no valid Authenticode signature ({state:?}); update refused");
    }
    let subject = subject.unwrap_or_default();
    if !subject
        .to_ascii_lowercase()
        .contains(&signer.trim().to_ascii_lowercase())
    {
        bail!("update package is signed by \"{subject}\", not \"{signer}\"; update refused");
    }
    Ok(())
}

#[cfg(not(all(windows, feature = "win-platform")))]
fn authenticode_signer_ok(_file: &Path, signer: &str) -> Result<()> {
    bail!("this build requires update MSIs signed by \"{signer}\"; Authenticode can only be verified on Windows; update refused")
}

/// Run msiexec on the verified package and wait for it, holding `pinned`
/// (the deny-write handle the hash was taken through) until it exits. The
/// MSI upgrade normally stops this service, which ends this process; the
/// next agent then reports the result ([`on_startup`]).
#[cfg(windows)]
fn install(file: &Path, pinned: std::fs::File) -> Result<&'static str> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let log = file.with_extension("log");
    let msiexec = crate::platform_win::windows_dir()
        .join("System32")
        .join("msiexec.exe");
    let mut child = std::process::Command::new(&msiexec)
        .arg("/i")
        .arg(file)
        .args(["/qn", "/norestart", "/l*v"])
        .arg(&log)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("starting msiexec")?;
    crate::platform_win::record_spawned_child(&child);
    tracing::info!(package = %file.display(), "installer started");
    let start = Instant::now();
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break st;
        }
        if start.elapsed() > INSTALL_TIMEOUT {
            drop(pinned);
            bail!(
                "msiexec did not finish within {} minutes (left running)",
                INSTALL_TIMEOUT.as_secs() / 60
            );
        }
        std::thread::sleep(Duration::from_secs(1));
    };
    drop(pinned);
    msiexec_outcome(status.code()).map_err(|e| anyhow!(e))
}

#[cfg(not(windows))]
fn install(file: &Path, pinned: std::fs::File) -> Result<&'static str> {
    drop(pinned);
    tracing::warn!(package = %file.display(), "verified update stored; automatic install is only supported on Windows");
    Ok("verified package stored; automatic install is only supported on Windows")
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

/// Minimum-throughput guard (V-L9): after the first byte, every
/// [`THROUGHPUT_WINDOW`] must deliver at least [`MIN_WINDOW_BYTES`].
#[derive(Debug)]
pub struct Throughput {
    window_start: Option<Instant>,
    bytes: u64,
    window: Duration,
    min_bytes: u64,
}

impl Throughput {
    pub fn new(window: Duration, min_bytes: u64) -> Self {
        Throughput {
            window_start: None,
            bytes: 0,
            window,
            min_bytes,
        }
    }

    /// Account `n` bytes received at `now`; Err when a full window was too slow.
    pub fn on_bytes(&mut self, n: u64, now: Instant) -> Result<()> {
        let start = *self.window_start.get_or_insert(now);
        self.bytes += n;
        if now.duration_since(start) >= self.window {
            if self.bytes < self.min_bytes {
                bail!(
                    "update download too slow ({} bytes in {} s)",
                    self.bytes,
                    now.duration_since(start).as_secs()
                );
            }
            self.window_start = Some(now);
            self.bytes = 0;
        }
        Ok(())
    }
}

/// HTTPS GET into the new file `dest` (created `create_new`, no sharing),
/// returning the sha256 hex of the body. Speaks HTTP/2 when the server
/// negotiates it (the agent port is HTTP/2-only) and HTTP/1.1 otherwise.
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
        Duration::from_secs(20),
        tokio::net::TcpStream::connect((host.as_str(), port)),
    )
    .await
    .context("connect timeout")??;
    let tls_stream = tokio::time::timeout(
        Duration::from_secs(20),
        tokio_rustls::TlsConnector::from(Arc::new(tls)).connect(server_name, tcp),
    )
    .await
    .context("TLS handshake timeout")?
    .context("TLS handshake")?;
    let h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let io = hyper_util::rt::TokioIo::new(tls_stream);
    let user_agent = format!("kestrel-agent/{}", kestrel_common::VERSION);
    let request = async {
        let resp = if h2 {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                    .await?;
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
        anyhow::Ok(resp)
    };
    let mut resp = tokio::time::timeout(READ_TIMEOUT, request)
        .await
        .context("no response from the update server")??;
    if !resp.status().is_success() {
        bail!("update download failed: HTTP {}", resp.status());
    }
    let mut f = tokio::fs::File::from_std(create_exclusive(dest)?);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut rate = Throughput::new(THROUGHPUT_WINDOW, MIN_WINDOW_BYTES);
    let body = resp.body_mut();
    loop {
        let frame = match tokio::time::timeout(READ_TIMEOUT, body.frame()).await {
            Ok(Some(f)) => f?,
            Ok(None) => break,
            Err(_) => bail!(
                "update download stalled (no data for {} s)",
                READ_TIMEOUT.as_secs()
            ),
        };
        if let Some(chunk) = frame.data_ref() {
            total += chunk.len() as u64;
            if total > MAX_PACKAGE {
                bail!("update package exceeds {MAX_PACKAGE} bytes");
            }
            rate.on_bytes(chunk.len() as u64, Instant::now())?;
            hasher.update(chunk);
            f.write_all(chunk).await?;
        }
    }
    f.flush().await?;
    f.sync_all().await?;
    drop(f);
    Ok(hex::encode(hasher.finalize()))
}

/// Create a new file (fails if it exists) that nobody else can open while
/// it is being written (Windows: share mode 0).
fn create_exclusive(path: &Path) -> Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        o.share_mode(0);
    }
    o.open(path)
        .with_context(|| format!("creating {}", path.display()))
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
/// current user and SYSTEM (icacls), then write the secret. icacls comes from
/// `GetSystemWindowsDirectoryW`, never `%SystemRoot%` (the caller's
/// environment: V-H1).
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
    let icacls = crate::platform_win::windows_dir()
        .join("System32")
        .join("icacls.exe");
    let mut cmd = std::process::Command::new(icacls);
    cmd.arg(path)
        .args(["/inheritance:r", "/grant:r", "*S-1-5-18:F"]);
    if !user.is_empty() {
        cmd.args(["/grant:r", &format!("{user}:F")]);
    }
    // Recorded in the spawn registry like every agent child (re-review N8).
    let ok = cmd
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .and_then(|mut child| {
            crate::platform_win::record_spawned_child(&child);
            child.wait()
        })
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
    fn one_update_in_flight() {
        let g = try_begin().expect("slot free");
        assert!(try_begin().is_none(), "second delivery refused");
        drop(g);
        let g2 = try_begin().expect("free again after the first finished");
        drop(g2);
    }

    #[test]
    fn retry_backoff() {
        assert!(attempt_allowed(None, "1.2.0", 1_000));
        let last = format!("1.2.0|{}", 1_000);
        assert!(!attempt_allowed(Some(&last), "1.2.0", 1_000 + 60_000));
        assert!(attempt_allowed(
            Some(&last),
            "1.2.0",
            1_000 + RETRY_AFTER_MS
        ));
        assert!(attempt_allowed(Some(&last), "1.3.0", 2_000), "new version");
        assert!(attempt_allowed(Some("garbage"), "1.2.0", 2_000));
        // Clock went backwards: do not wedge.
        assert!(attempt_allowed(Some(&last), "1.2.0", 10));
    }

    #[test]
    fn msiexec_codes() {
        assert_eq!(msiexec_outcome(Some(0)), Ok(""));
        assert!(msiexec_outcome(Some(3010)).is_ok());
        assert!(msiexec_outcome(Some(1641)).is_ok());
        assert!(msiexec_outcome(Some(1603)).unwrap_err().contains("1603"));
        assert!(msiexec_outcome(Some(1618)).is_err());
        assert!(msiexec_outcome(Some(1)).is_err());
        assert!(msiexec_outcome(None).is_err());
    }

    #[test]
    fn pending_after_restart() {
        assert_eq!(pending_outcome(None, "1.0.0"), PendingOutcome::None);
        assert_eq!(pending_outcome(Some(""), "1.0.0"), PendingOutcome::None);
        assert_eq!(
            pending_outcome(Some("1.1.0"), "1.1.0"),
            PendingOutcome::Succeeded("1.1.0".into())
        );
        assert_eq!(
            pending_outcome(Some("1.1.0"), "1.0.0"),
            PendingOutcome::Failed("1.1.0".into())
        );
    }

    #[test]
    fn throughput_guard() {
        let t0 = Instant::now();
        let mut r = Throughput::new(Duration::from_secs(60), 64 * 1024);
        r.on_bytes(1, t0).unwrap();
        r.on_bytes(1, t0 + Duration::from_secs(30)).unwrap();
        // A full window with only a few bytes: too slow.
        assert!(r.on_bytes(1, t0 + Duration::from_secs(61)).is_err());
        let mut ok = Throughput::new(Duration::from_secs(60), 64 * 1024);
        ok.on_bytes(40_000, t0).unwrap();
        ok.on_bytes(40_000, t0 + Duration::from_secs(61)).unwrap();
        // New window starts; still fine with enough bytes.
        ok.on_bytes(70_000, t0 + Duration::from_secs(122)).unwrap();
    }

    #[test]
    fn exclusive_download_file_and_disk_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(random_name("dl", "part"));
        assert!(random_name("dl", "part") != random_name("dl", "part"));
        {
            use std::io::Write;
            let mut f = create_exclusive(&p).unwrap();
            // Nobody (not even we) can create it again.
            assert!(create_exclusive(&p).is_err());
            #[cfg(windows)]
            assert!(
                std::fs::OpenOptions::new().write(true).open(&p).is_err(),
                "no sharing while downloading"
            );
            f.write_all(b"package bytes").unwrap();
        }
        let (pinned, digest) = open_and_hash(&p).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(b"package bytes")));
        #[cfg(windows)]
        {
            assert!(
                std::fs::OpenOptions::new().write(true).open(&p).is_err(),
                "deny-write while pinned"
            );
            assert!(
                std::fs::remove_file(&p).is_err(),
                "deny-delete while pinned"
            );
            // Readers (msiexec) are still allowed.
            assert!(std::fs::File::open(&p).is_ok());
        }
        drop(pinned);
        std::fs::remove_file(&p).unwrap();
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
