//! Long-lived `Connect` stream with reconnect/backoff, outbox replay and
//! server payload handling.
//!
//! Envelope `seq` semantics (agent → server):
//! * durable payloads (everything from the outbox) carry their outbox seq
//!   (≥ 1, strictly increasing, survives restarts); the server acks
//!   cumulatively with `ServerPayload::Ack { seq }` once stored;
//! * ephemeral messages (`Hello`, the agent's own `Ack`) carry `seq = 0` and
//!   must not be acked or deduplicated by the server.
//!
//! After a reconnect every unacked row is re-sent in seq order, so the server
//! must treat a seq it has already stored as a duplicate (ack it, don't store).
//! `Hello.outbox_epoch` identifies the outbox database; a new epoch means the
//! seq numbering restarted (M8).
//!
//! Certificate renewal (H3): after `Welcome`, once a day, and whenever the
//! server sends `RenewCertificate`, the agent checks its client certificate;
//! with less than 30 days left (or on request) it generates a new key + CSR
//! and sends `AgentPayload::RenewCertificate` (ephemeral, seq 0). On
//! `ServerPayload::Certificate` it installs key + certificate atomically
//! (keeping the previous pair), then reconnects. The previous pair is deleted
//! after the next `Welcome`, or restored if the new identity cannot connect.
//!
//! Every server message with seq > 0 is acked after it was handled, except a
//! `SetUninstallToken` whose new hash could not be saved (the server re-sends
//! it on the next connect and only promotes the token once acked).

use anyhow::{anyhow, Context, Result};
use kestrel_common::{
    tray::{ActivityItem, ReviewState},
    wire::{AgentPayload, Hello, ServerPayload},
    Severity,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::agent::Core;
use crate::backoff::Backoff;
use crate::codec;
use crate::config::AgentConfig;
use crate::proto::{agent_service_client::AgentServiceClient, AgentEnvelope, ServerEnvelope};

/// Max unacked rows in flight on one stream before waiting for acks.
const WINDOW: u64 = 4096;
const READ_BATCH: usize = 128;
/// A stream that stays up this long resets the backoff even without Welcome.
const HEALTHY_AFTER: Duration = Duration::from_secs(60);
/// Renewal check period while connected.
const RENEW_CHECK_EVERY: Duration = Duration::from_secs(24 * 3600);
/// A renewal request without an answer may be retried after this long.
const RENEW_RETRY_AFTER_MS: i64 = 10 * 60 * 1000;
/// Consecutive failed connections with an unconfirmed renewed identity
/// before the previous identity is restored.
const RENEW_ROLLBACK_AFTER: u32 = 3;

pub async fn run(core: Arc<Core>) {
    let mut backoff = Backoff::default();
    let mut unconfirmed_failures = 0u32;
    if let Err(e) = crate::pki::recover_identity(&core.state_dir) {
        tracing::error!("client identity damaged: {e:#}");
    }
    loop {
        if core.shutdown.is_cancelled() {
            break;
        }
        let started = std::time::Instant::now();
        let mut st = SessionState::default();
        let r = session(&core, &mut backoff, &mut st).await;
        core.set_connected(false);
        // A renewed identity that never got a Welcome is rolled back after a
        // few attempts; the old certificate is still valid server-side until
        // the new one has been used.
        if st.welcomed {
            unconfirmed_failures = 0;
        } else if crate::pki::renewal_unconfirmed(&core.state_dir) {
            unconfirmed_failures += 1;
            if unconfirmed_failures >= RENEW_ROLLBACK_AFTER {
                match crate::pki::rollback_renewal(&core.state_dir) {
                    Ok(true) => tracing::warn!(
                        "renewed client certificate could not connect; restored the previous one"
                    ),
                    Ok(false) => {}
                    Err(e) => tracing::error!("renewal rollback failed: {e:#}"),
                }
                unconfirmed_failures = 0;
            }
        }
        if st.reconnect_now {
            backoff.reset();
            continue;
        }
        if core.shutdown.is_cancelled() {
            break;
        }
        if started.elapsed() >= HEALTHY_AFTER {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        match r {
            Ok(()) => tracing::info!("server closed the stream; reconnecting in {delay:?}"),
            Err(e) => tracing::warn!(
                "connection to server failed: {e:#}; retrying in {delay:?} (attempt {})",
                backoff.attempt()
            ),
        }
        tokio::select! {
            _ = core.shutdown.cancelled() => break,
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// Reload config from disk (re-enrollment may have rotated cert / device id).
fn reload_config(core: &Core) -> AgentConfig {
    match AgentConfig::load(&core.state_dir) {
        Ok(c) => {
            *core.cfg.write().unwrap_or_else(|e| e.into_inner()) = c.clone();
            c
        }
        Err(_) => core.config(),
    }
}

async fn ensure_enrolled(core: &Core) -> Result<AgentConfig> {
    let mut cfg = reload_config(core);
    if crate::pki::is_enrolled(&core.state_dir, &cfg) {
        return Ok(cfg);
    }
    let token = cfg
        .pending_enroll_token
        .clone()
        .ok_or_else(|| anyhow!("agent is not enrolled and has no enrollment token; run `kestrel-agent enroll --token …`"))?;
    tracing::info!(server = %cfg.server, "enrolling");
    let er = crate::pki::enroll(
        &core.state_dir,
        &mut cfg,
        &token,
        &core.hostname,
        core.platform.os_info(),
    )
    .await?;
    cfg.save(&core.state_dir)?;
    *core.cfg.write().unwrap_or_else(|e| e.into_inner()) = cfg.clone();
    tracing::info!(device_id = %er.device_id, "enrolled");
    Ok(cfg)
}

fn envelope(seq: u64, p: &AgentPayload) -> Result<AgentEnvelope> {
    let (payload, compressed) = codec::encode(p, false)?;
    Ok(AgentEnvelope {
        seq,
        compressed,
        payload,
    })
}

/// Per-session flags shared between the stream loop and `run`.
#[derive(Default)]
struct SessionState {
    welcomed: bool,
    /// Renewal request in flight (ms sent).
    renew_sent: Option<i64>,
    /// New identity installed: reconnect immediately.
    reconnect_now: bool,
}

/// What the stream loop should do after a server payload.
enum Flow {
    Continue,
    Reconnect,
    /// The payload could not be applied: do not ack it, so the server keeps
    /// it pending and sends it again (uninstall-token rotation).
    NoAck,
}

async fn session(core: &Arc<Core>, backoff: &mut Backoff, st: &mut SessionState) -> Result<()> {
    let cfg = ensure_enrolled(core).await?;
    let device_id = cfg.device_id.ok_or_else(|| anyhow!("no device id"))?;
    let channel = crate::pki::mtls_channel(&core.state_dir, &cfg).await?;
    let mut client = AgentServiceClient::new(channel)
        .max_decoding_message_size(64 * 1024 * 1024)
        .max_encoding_message_size(64 * 1024 * 1024);

    let (tx, rx) = mpsc::channel::<AgentEnvelope>(64);
    let hello = AgentPayload::Hello(Hello {
        device_id,
        agent_version: kestrel_common::VERSION.into(),
        hostname: core.hostname.clone(),
        os: core.platform.os_info(),
        boot_id: core.boot_id.clone(),
        policy_version: core.policy_version(),
        rules_version: core.rules_version(),
        outbox_epoch: core.store.outbox_epoch(),
    });
    tx.send(envelope(0, &hello)?)
        .await
        .map_err(|_| anyhow!("stream closed"))?;

    let resp = client
        .connect(ReceiverStream::new(rx))
        .await
        .map_err(|s| anyhow!("Connect rejected: {:?}: {}", s.code(), s.message()))?;
    let mut inbound = resp.into_inner();
    tracing::info!(server = %cfg.server, %device_id, "connected");
    core.set_connected(true);

    // Highest outbox seq acked by the server during this session.
    let (acked_tx, acked_rx) = tokio::sync::watch::channel(0u64);
    let pump = tokio::spawn(pump_outbox(core.clone(), tx.clone(), acked_rx));
    let mut renew_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + RENEW_CHECK_EVERY,
        RENEW_CHECK_EVERY,
    );
    let result = async {
        loop {
            let msg = tokio::select! {
                _ = core.shutdown.cancelled() => return Ok(()),
                _ = renew_tick.tick() => {
                    maybe_renew(core, &tx, st, false).await;
                    continue;
                }
                m = inbound.message() => m,
            };
            let env: ServerEnvelope = match msg {
                Ok(Some(e)) => e,
                Ok(None) => return Ok(()),
                Err(s) => return Err(anyhow!("stream error: {:?}: {}", s.code(), s.message())),
            };
            let payload: ServerPayload = match codec::decode(&env.payload, env.compressed) {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(seq = env.seq, "undecodable server payload: {e:#}");
                    continue;
                }
            };
            let flow = handle_server(core, payload, &acked_tx, backoff, &tx, st).await;
            if env.seq > 0 && !matches!(flow, Flow::NoAck) {
                let ack = envelope(0, &AgentPayload::Ack { seq: env.seq })?;
                if tx.send(ack).await.is_err() {
                    return Err(anyhow!("outbound stream closed"));
                }
            }
            if let Flow::Reconnect = flow {
                tracing::info!("reconnecting with the renewed client certificate");
                st.reconnect_now = true;
                return Ok(());
            }
        }
    }
    .await;
    pump.abort();
    result
}

/// Send unacked outbox rows in seq order, then wait for new ones.
async fn pump_outbox(
    core: Arc<Core>,
    tx: mpsc::Sender<AgentEnvelope>,
    mut acked: tokio::sync::watch::Receiver<u64>,
) {
    let mut sent_upto = 0u64;
    loop {
        // Flow control: don't run unboundedly ahead of the server's acks.
        let acked_now = *acked.borrow();
        if sent_upto > acked_now + WINDOW {
            tokio::select! {
                r = acked.changed() => if r.is_err() { return },
                _ = tokio::time::sleep(Duration::from_secs(30)) => {}
            }
            continue;
        }
        let store = core.store.clone();
        let rows =
            match tokio::task::spawn_blocking(move || store.pending_after(sent_upto, READ_BATCH))
                .await
            {
                Ok(Ok(r)) => r,
                Ok(Err(e)) => {
                    tracing::error!("outbox read failed: {e:#}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
                Err(_) => return,
            };
        if rows.is_empty() {
            tokio::select! {
                _ = core.outbox_notify.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            continue;
        }
        for r in rows {
            let env = AgentEnvelope {
                seq: r.seq,
                compressed: r.compressed,
                payload: r.payload,
            };
            if tx.send(env).await.is_err() {
                return;
            }
            sent_upto = r.seq;
        }
    }
}

/// Start a certificate renewal if due (or `force`d by the server).
async fn maybe_renew(
    core: &Arc<Core>,
    tx: &mpsc::Sender<AgentEnvelope>,
    st: &mut SessionState,
    force: bool,
) {
    let now = kestrel_common::now_ms();
    if st
        .renew_sent
        .is_some_and(|t| now - t < RENEW_RETRY_AFTER_MS)
    {
        return;
    }
    let due = match crate::pki::load_identity(&core.state_dir) {
        Ok((cert, _)) => crate::pki::needs_renewal(&cert, crate::pki::now_secs()),
        Err(_) => false,
    };
    if !(force || due) {
        return;
    }
    let csr = match crate::pki::begin_renewal(&core.state_dir, &core.hostname) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("certificate renewal: cannot create key/CSR: {e:#}");
            return;
        }
    };
    match envelope(0, &AgentPayload::RenewCertificate { csr_pem: csr }) {
        Ok(env) => {
            if tx.send(env).await.is_ok() {
                st.renew_sent = Some(now);
                tracing::info!(forced = force, "client certificate renewal requested");
            }
        }
        Err(e) => tracing::error!("certificate renewal: {e:#}"),
    }
}

async fn handle_server(
    core: &Arc<Core>,
    p: ServerPayload,
    acked: &tokio::sync::watch::Sender<u64>,
    backoff: &mut Backoff,
    tx: &mpsc::Sender<AgentEnvelope>,
    st: &mut SessionState,
) -> Flow {
    match p {
        ServerPayload::Welcome {
            device_id,
            server_time,
        } => {
            let skew = kestrel_common::now_ms() - server_time;
            tracing::info!(%device_id, skew_ms = skew, "welcome");
            if skew.abs() > 5 * 60 * 1000 {
                tracing::warn!(skew_ms = skew, "clock skew to server exceeds 5 minutes");
            }
            backoff.reset();
            st.welcomed = true;
            core.mark_server_contact();
            if crate::pki::confirm_renewal(&core.state_dir) {
                tracing::info!("renewed client certificate confirmed; previous one removed");
            }
            // Fresh heartbeat so the console shows health immediately.
            core.send_heartbeat();
            maybe_renew(core, tx, st, false).await;
        }
        ServerPayload::RenewCertificate => {
            maybe_renew(core, tx, st, true).await;
        }
        ServerPayload::Certificate { cert_pem, ca_pem } => {
            let state_dir = core.state_dir.clone();
            let r = tokio::task::spawn_blocking(move || {
                crate::pki::complete_renewal(&state_dir, &cert_pem, &ca_pem)
            })
            .await;
            st.renew_sent = None;
            match r {
                Ok(Ok(())) => {
                    tracing::info!("renewed client certificate installed");
                    return Flow::Reconnect;
                }
                Ok(Err(e)) => tracing::error!("renewed certificate rejected: {e:#}"),
                Err(e) => tracing::error!("renewal task failed: {e}"),
            }
        }
        ServerPayload::Ack { seq } => {
            let store = core.store.clone();
            match tokio::task::spawn_blocking(move || store.ack(seq)).await {
                Ok(Ok(n)) => tracing::trace!(seq, removed = n, "acked"),
                Ok(Err(e)) => tracing::warn!("outbox ack failed: {e:#}"),
                Err(_) => {}
            }
            acked.send_modify(|v| *v = (*v).max(seq));
        }
        ServerPayload::Policy(p) => {
            core.apply_policy(*p);
        }
        ServerPayload::Rules(b) => {
            core.apply_rules(b).await;
        }
        ServerPayload::Command { command_id, action } => {
            let c = core.clone();
            tokio::spawn(async move { c.run_command(command_id, action).await });
        }
        ServerPayload::Update(m) => {
            let c = core.clone();
            tokio::spawn(async move {
                if let Err(e) = crate::update::handle(&c, m).await {
                    tracing::error!("agent update failed: {e:#}");
                }
            });
        }
        ServerPayload::ReviewDecision {
            alert_id,
            approved,
            message,
        } => review_decision(core, alert_id, approved, message),
        ServerPayload::SetUninstallToken { token } => {
            // Hash + atomic save before the ack: the server makes the token
            // current only once acked (never log the token itself).
            let c = core.clone();
            match tokio::task::spawn_blocking(move || c.set_uninstall_token(&token)).await {
                Ok(Ok(())) => tracing::info!("uninstall token rotated by the server"),
                Ok(Err(e)) => {
                    tracing::error!("new uninstall token not stored: {e:#}");
                    return Flow::NoAck;
                }
                Err(e) => {
                    tracing::error!("uninstall token task failed: {e}");
                    return Flow::NoAck;
                }
            }
        }
    }
    Flow::Continue
}

fn review_decision(core: &Core, alert_id: Uuid, approved: bool, message: String) {
    // Shown only to the user the alert belongs to (M3).
    let owner = core.store.alert_owner(alert_id).flatten();
    let state = if approved {
        ReviewState::Approved
    } else {
        ReviewState::Denied
    };
    if let Err(e) = core.store.set_review_state(alert_id, state) {
        tracing::warn!("updating review state failed: {e:#}");
    }
    let title = if approved {
        "IT approved your review request".to_string()
    } else {
        "IT reviewed your request and kept the block in place".to_string()
    };
    core.notify_tray(
        ActivityItem {
            id: Uuid::new_v4(),
            ts: kestrel_common::now_ms(),
            title,
            body: message,
            severity: Severity::Info,
            alert_id: Some(alert_id),
            file: None,
            action_taken: if approved {
                "Approved".into()
            } else {
                "Denied".into()
            },
            review: Some(state),
        },
        true,
        owner,
    );
}

/// One-shot enroll used by the CLI (`install`, `enroll`, `simulate`).
pub async fn enroll_now(
    state_dir: &std::path::Path,
    token: &str,
    hostname: &str,
    os: kestrel_common::wire::OsInfo,
) -> Result<Uuid> {
    let mut cfg = AgentConfig::load(state_dir)?;
    let er = crate::pki::enroll(state_dir, &mut cfg, token, hostname, os)
        .await
        .context("enrollment failed")?;
    cfg.save(state_dir)?;
    Ok(er.device_id)
}
