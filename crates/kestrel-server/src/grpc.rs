//! Agent gRPC service (`proto/kestrel.proto`): enrollment and the live stream.

// tonic's `Status` is ~180 bytes; every gRPC handler returns it by design.
#![allow(clippy::result_large_err)]

pub mod pb {
    #![allow(clippy::all, clippy::pedantic)]
    tonic::include_proto!("kestrel.v1");
}

use crate::{
    audit::{self, Actor},
    crypto::{random_token, sha256_hex},
    ingest::{self, Session},
    pki,
    registry::AgentConn,
    state::AppState,
};
use dashmap::DashMap;
use futures::{FutureExt, Stream};
use kestrel_common::{
    now_ms,
    wire::{AgentPayload, EnrollRequest, EnrollResponse, ServerPayload},
};
use pb::{agent_service_server::AgentService, AgentEnvelope, EnrollEnvelope, ServerEnvelope};
use serde_json::json;
use std::{
    io::Read,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use uuid::Uuid;

/// Max decompressed payload accepted from an agent.
pub const MAX_PAYLOAD: usize = 64 * 1024 * 1024;
/// Payloads larger than this are zstd-compressed server → agent.
const COMPRESS_OVER: usize = 8 * 1024;

pub struct AgentSvc {
    pub state: AppState,
}

pub fn decode_payload(compressed: bool, payload: &[u8]) -> Result<Vec<u8>, String> {
    if !compressed {
        return Ok(payload.to_vec());
    }
    let mut out = Vec::new();
    let dec = zstd::stream::read::Decoder::new(payload).map_err(|e| e.to_string())?;
    dec.take(MAX_PAYLOAD as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > MAX_PAYLOAD {
        return Err("payload too large".into());
    }
    Ok(out)
}

pub fn encode_payload(json: Vec<u8>) -> (bool, Vec<u8>) {
    if json.len() > COMPRESS_OVER {
        if let Ok(c) = zstd::encode_all(&json[..], 3) {
            return (true, c);
        }
    }
    (false, json)
}

/// Device id (CN) and serial of the presented client certificate, if any.
fn peer_identity<T>(req: &Request<T>) -> Option<(String, String)> {
    let certs = req.peer_certs()?;
    let leaf = certs.first()?;
    pki::cert_cn_serial(leaf.as_ref()).ok()
}

/// Certificates within this window of expiry are renewed (server asks on Hello).
pub const RENEW_BEFORE_MS: i64 = 30 * 86_400_000;
/// At most this many stream renewals per device per 10 minutes.
const MAX_RENEWALS_PER_10_MIN: i64 = 3;
/// Prefix of server-issued per-device uninstall tokens.
pub const UNINSTALL_TOKEN_PREFIX: &str = "kun_";

pub fn new_uninstall_token() -> String {
    format!("{UNINSTALL_TOKEN_PREFIX}{}", random_token(24))
}

/// Validate the presented certificate; returns its `not_after`.
async fn cert_valid(state: &AppState, device_id: Uuid, serial: &str) -> Result<i64, Status> {
    let row: Option<(Option<i64>, i64, Option<i64>)> = sqlx::query_as(
        "SELECT c.revoked_at, c.not_after, d.decommissioned_at FROM agent_certs c JOIN devices d ON d.id = c.device_id \
         WHERE c.serial = $1 AND c.device_id = $2",
    )
    .bind(serial)
    .bind(device_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| Status::unavailable("database unavailable"))?;
    match row {
        None => Err(Status::permission_denied("unknown client certificate")),
        Some((Some(_), _, _)) => Err(Status::permission_denied("client certificate revoked")),
        Some((_, _, Some(_))) => Err(Status::permission_denied("device decommissioned")),
        Some((None, not_after, None)) if not_after < now_ms() => {
            Err(Status::permission_denied("client certificate expired"))
        }
        Some((_, not_after, _)) => Ok(not_after),
    }
}

/// The device is now using `serial`: record it and revoke every certificate of
/// the device issued before it (the ones a renewal replaced). Revocation only
/// happens here, so an agent whose renewal reply was lost keeps working.
async fn mark_cert_in_use(state: &AppState, device_id: Uuid, serial: &str) -> anyhow::Result<u64> {
    let now = now_ms();
    sqlx::query("UPDATE agent_certs SET last_used_at = $3 WHERE serial = $1 AND device_id = $2")
        .bind(serial)
        .bind(device_id)
        .bind(now)
        .execute(&state.db)
        .await?;
    let revoked = sqlx::query(
        "UPDATE agent_certs SET revoked_at = $3 WHERE device_id = $1 AND serial <> $2 AND revoked_at IS NULL \
         AND issued_at < (SELECT issued_at FROM agent_certs WHERE serial = $2)",
    )
    .bind(device_id)
    .bind(serial)
    .bind(now)
    .execute(&state.db)
    .await?
    .rows_affected();
    if revoked > 0 {
        audit::log(
            &state.db,
            &Actor::system(),
            "device.cert_superseded",
            device_id.to_string(),
            json!({"serial_in_use": serial, "revoked": revoked}),
        )
        .await;
    }
    Ok(revoked)
}

/// Sign a renewal CSR for an authenticated device (CN = `device_id`, never the
/// CSR's subject) and record which serial it replaces.
pub async fn renew_certificate(
    state: &AppState,
    device_id: Uuid,
    old_serial: &str,
    csr_pem: &str,
) -> anyhow::Result<pki::IssuedCert> {
    if csr_pem.len() > 16 * 1024 {
        anyhow::bail!("CSR too large");
    }
    let now = now_ms();
    let (recent,): (i64,) = sqlx::query_as(
        "SELECT count(*) FROM agent_certs WHERE device_id = $1 AND replaces_serial IS NOT NULL AND issued_at > $2",
    )
    .bind(device_id)
    .bind(now - 600_000)
    .fetch_one(&state.db)
    .await?;
    if recent >= MAX_RENEWALS_PER_10_MIN {
        anyhow::bail!("too many certificate renewals; try again later");
    }
    let issued = state.ca.sign_agent_csr(csr_pem, device_id)?;
    sqlx::query(
        "INSERT INTO agent_certs (serial, device_id, not_before, not_after, issued_at, replaces_serial) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(&issued.serial)
    .bind(device_id)
    .bind(issued.not_before)
    .bind(issued.not_after)
    .bind(now)
    .bind(old_serial)
    .execute(&state.db)
    .await?;
    audit::log(
        &state.db,
        &Actor::system(),
        "device.cert_renewed",
        device_id.to_string(),
        json!({"old_serial": old_serial, "new_serial": issued.serial, "not_after": issued.not_after}),
    )
    .await;
    Ok(issued)
}

impl AgentSvc {
    async fn enroll_inner(
        &self,
        peer: Option<(String, String)>,
        req: EnrollRequest,
    ) -> Result<EnrollResponse, Status> {
        let st = &self.state;
        if req.csr_pem.len() > 16 * 1024
            || req.hostname.len() > 255
            || req.hostname.trim().is_empty()
        {
            return Err(Status::invalid_argument("invalid enrollment request"));
        }
        // Renewal: valid client certificate, no token (same as the stream's
        // RenewCertificate; the old certificate stays valid until the new one is used).
        if req.token.is_empty() {
            let (cn, serial) =
                peer.ok_or_else(|| Status::unauthenticated("enrollment token required"))?;
            let device_id = Uuid::parse_str(&cn)
                .map_err(|_| Status::permission_denied("bad certificate CN"))?;
            cert_valid(st, device_id, &serial).await?;
            let issued = renew_certificate(st, device_id, &serial, &req.csr_pem)
                .await
                .map_err(|e| Status::invalid_argument(format!("renewal refused: {e}")))?;
            return Ok(EnrollResponse {
                device_id,
                cert_pem: issued.cert_pem,
                ca_pem: st.ca.cert_pem.clone(),
                uninstall_token: String::new(),
            });
        }
        let now = now_ms();
        let hash = sha256_hex(req.token.as_bytes());
        let tok: Option<(Uuid, Uuid, String)> = sqlx::query_as(
            "UPDATE enrollment_tokens SET uses = uses + 1 WHERE token_hash = $1 AND NOT revoked AND expires_at > $2 AND uses < max_uses \
             RETURNING id, group_id, token_prefix",
        )
        .bind(&hash)
        .bind(now)
        .fetch_optional(&st.db)
        .await
        .map_err(|_| Status::unavailable("database unavailable"))?;
        let Some((token_id, group_id, prefix)) = tok else {
            tracing::warn!("enrollment rejected: invalid, expired, revoked or exhausted token");
            return Err(Status::unauthenticated(
                "invalid or expired enrollment token",
            ));
        };
        // H2: every enrollment is a new device. The hardware UUID is client
        // asserted, so a match never re-binds (or revokes) an existing identity;
        // it is only flagged on both devices for an administrator to merge.
        let id = Uuid::new_v4();
        let issued = st
            .ca
            .sign_agent_csr(&req.csr_pem, id)
            .map_err(|e| Status::invalid_argument(format!("CSR rejected: {e}")))?;
        let hw = req
            .os
            .hw_uuid
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty() && h.len() <= 128);
        let dups: Vec<(Uuid, String, i64)> = match hw {
            Some(hw) => sqlx::query_as(
                "SELECT id, hostname, last_seen FROM devices WHERE hw_uuid = $1 AND decommissioned_at IS NULL",
            )
            .bind(hw)
            .fetch_all(&st.db)
            .await
            .map_err(|_| Status::unavailable("database unavailable"))?,
            None => vec![],
        };
        let dup_ids: Vec<Uuid> = dups.iter().map(|d| d.0).collect();
        let uninstall_token = new_uninstall_token();
        let res: Result<(), sqlx::Error> = async {
            let mut tx = st.db.begin().await?;
            sqlx::query(
                "INSERT INTO devices (id, hostname, os_name, os_build, arch, domain, hw_uuid, group_id, first_seen, last_seen, \
                 possible_duplicate_ids, uninstall_token_enc) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11)",
            )
            .bind(id)
            .bind(&req.hostname)
            .bind(&req.os.name)
            .bind(&req.os.build)
            .bind(&req.os.arch)
            .bind(&req.os.domain)
            .bind(hw)
            .bind(group_id)
            .bind(now)
            .bind(&dup_ids)
            .bind(st.mk.seal_str(&uninstall_token))
            .execute(&mut *tx)
            .await?;
            if !dup_ids.is_empty() {
                sqlx::query(
                    "UPDATE devices SET possible_duplicate_ids = array_append(possible_duplicate_ids, $2) WHERE id = ANY($1)",
                )
                .bind(&dup_ids)
                .bind(id)
                .execute(&mut *tx)
                .await?;
            }
            sqlx::query("INSERT INTO agent_certs (serial, device_id, not_before, not_after, issued_at) VALUES ($1,$2,$3,$4,$5)")
                .bind(&issued.serial)
                .bind(id)
                .bind(issued.not_before)
                .bind(issued.not_after)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            tx.commit().await
        }
        .await;
        res.map_err(|e| Status::internal(format!("storing enrollment: {e}")))?;
        audit::log(
            &st.db,
            &Actor::system(),
            "device.enrolled",
            id.to_string(),
            json!({"hostname": req.hostname, "group_id": group_id, "token_id": token_id, "token_prefix": prefix, "possible_duplicates": dup_ids}),
        )
        .await;
        for (dup, host, last_seen) in &dups {
            st.publish("device", *dup, "updated");
            // A device that was alive recently is unlikely to have been re-imaged.
            if now - last_seen < 24 * 3_600_000 {
                ingest::raise_tamper(
                    st,
                    *dup,
                    "TP-SRV-DUP-ENROLL",
                    "New enrollment reused this device's hardware UUID",
                    kestrel_common::Severity::High,
                    format!(
                        "A new agent enrolled as {} (device {id}) with the same hardware UUID as {host}, which was active in the last 24 h. \
                         This is a cloned VM, a re-install, or someone using an enrollment token to impersonate {host}. \
                         {host} keeps its identity; merge or decommission one of the two devices once verified.",
                        req.hostname
                    ),
                )
                .await;
            }
        }
        st.publish("device", id, "created");
        Ok(EnrollResponse {
            device_id: id,
            cert_pem: issued.cert_pem,
            ca_pem: st.ca.cert_pem.clone(),
            uninstall_token,
        })
    }
}

type ConnectStream = Pin<Box<dyn Stream<Item = Result<ServerEnvelope, Status>> + Send>>;

#[tonic::async_trait]
impl AgentService for AgentSvc {
    async fn enroll(
        &self,
        request: Request<EnrollEnvelope>,
    ) -> Result<Response<EnrollEnvelope>, Status> {
        let peer = peer_identity(&request);
        let body = request.into_inner();
        if body.json.len() > 64 * 1024 {
            return Err(Status::invalid_argument("request too large"));
        }
        let req: EnrollRequest = serde_json::from_slice(&body.json)
            .map_err(|e| Status::invalid_argument(format!("bad EnrollRequest: {e}")))?;
        let resp = self.enroll_inner(peer, req).await?;
        Ok(Response::new(EnrollEnvelope {
            json: serde_json::to_vec(&resp).map_err(|e| Status::internal(e.to_string()))?,
        }))
    }

    type ConnectStream = ConnectStream;

    async fn connect(
        &self,
        request: Request<Streaming<AgentEnvelope>>,
    ) -> Result<Response<Self::ConnectStream>, Status> {
        let state = self.state.clone();
        let (cn, serial) = peer_identity(&request)
            .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
        let device_id =
            Uuid::parse_str(&cn).map_err(|_| Status::permission_denied("bad certificate CN"))?;
        let not_after = cert_valid(&state, device_id, &serial).await?;
        let peer_ip = request.remote_addr().map(|a| a.ip().to_string());
        let mut inbound = request.into_inner();

        // First message must be Hello.
        let first = tokio::time::timeout(Duration::from_secs(30), inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("no Hello received"))??
            .ok_or_else(|| Status::cancelled("stream closed before Hello"))?;
        let raw =
            decode_payload(first.compressed, &first.payload).map_err(Status::invalid_argument)?;
        let hello = match serde_json::from_slice::<AgentPayload>(&raw) {
            Ok(AgentPayload::Hello(h)) => h,
            Ok(_) => return Err(Status::failed_precondition("first message must be Hello")),
            Err(e) => return Err(Status::invalid_argument(format!("bad payload: {e}"))),
        };
        if hello.device_id != device_id {
            return Err(Status::permission_denied(
                "Hello.device_id does not match certificate",
            ));
        }
        if let Err(e) = mark_cert_in_use(&state, device_id, &serial).await {
            tracing::warn!(%device_id, error = %e, "recording certificate use failed");
        }
        let mut initial = ingest::hello(&state, device_id, &hello, peer_ip)
            .await
            .map_err(|e| Status::internal(format!("hello: {e}")))?;
        if not_after - now_ms() < RENEW_BEFORE_MS {
            initial.push(ServerPayload::RenewCertificate);
        }

        let (tx, rx) = mpsc::channel::<ServerPayload>(1024);
        let session = Uuid::new_v4();
        let conn = Arc::new(AgentConn {
            session,
            tx: tx.clone(),
            connected_at: now_ms(),
            last_hb: AtomicI64::new(0),
            silence_alerted: AtomicBool::new(false),
            kill: tokio::sync::Notify::new(),
        });
        if let Some(old) = state.agents.register(device_id, conn.clone()) {
            old.kill.notify_one();
        }
        tracing::info!(%device_id, hostname = %hello.hostname, version = %hello.agent_version, "agent connected");

        for m in initial {
            let _ = tx.send(m).await;
        }
        if first.seq > 0 {
            let _ = tx.send(ServerPayload::Ack { seq: first.seq }).await;
        }
        let (hwm,): (i64,) = sqlx::query_as("SELECT last_agent_seq FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_one(&state.db)
            .await
            .map_err(|_| Status::unavailable("database unavailable"))?;

        // seq → payload awaiting the agent's Ack.
        let sent: Arc<DashMap<u64, ServerPayload>> = Arc::new(DashMap::new());
        let out_seq = Arc::new(AtomicU64::new(0));

        // Inbound processing.
        {
            let state = state.clone();
            let sent = sent.clone();
            let sess = Session {
                device_id,
                hostname: hello.hostname.clone(),
                conn: conn.clone(),
                serial: serial.clone(),
            };
            let mut hwm = hwm.max(0) as u64;
            tokio::spawn(async move {
                loop {
                    let next = tokio::select! {
                        m = inbound.message() => m,
                        _ = sess.conn.kill.notified() => {
                            tracing::info!(%device_id, "agent stream terminated by server");
                            break;
                        }
                    };
                    let msg = match next {
                        Ok(Some(m)) => m,
                        Ok(None) => break,
                        Err(e) => {
                            tracing::debug!(%device_id, error = %e, "agent stream error");
                            break;
                        }
                    };
                    let seq = msg.seq;
                    // Agent outbox seqs are persistent and re-sent after reconnects:
                    // anything at or below the high-water mark is a duplicate (ack again).
                    if seq > 0 && seq <= hwm {
                        if sess
                            .conn
                            .tx
                            .send(ServerPayload::Ack { seq: hwm })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        continue;
                    }
                    let payload = match decode_payload(msg.compressed, &msg.payload).and_then(
                        |raw| {
                            serde_json::from_slice::<AgentPayload>(&raw).map_err(|e| e.to_string())
                        },
                    ) {
                        Ok(p) => Some(p),
                        Err(e) => {
                            // Can never succeed: record and ack so the outbox drops it.
                            tracing::warn!(%device_id, seq, error = %e, "dropping malformed agent message");
                            None
                        }
                    };
                    // A bug in one handler must not leave a dead stream registered:
                    // contain the panic and close the stream (the agent re-sends).
                    let dispatched = std::panic::AssertUnwindSafe(async {
                        match payload {
                        None | Some(AgentPayload::Hello(_)) => Ok(()),
                        Some(AgentPayload::Heartbeat(hb)) => {
                            ingest::heartbeat(&state, &sess, &hb).await
                        }
                        Some(AgentPayload::Events { events }) => {
                            ingest::events(&state, &sess, &events).await
                        }
                        Some(AgentPayload::Alert(a)) => ingest::alert(&state, &sess, *a).await,
                        Some(AgentPayload::ActionResult {
                            command_id,
                            outcome,
                        }) => ingest::action_result(&state, &sess, command_id, &outcome).await,
                        Some(AgentPayload::ReviewRequest(rr)) => {
                            ingest::review_request(&state, &sess, &rr).await
                        }
                        Some(AgentPayload::Inventory(inv)) => {
                            ingest::inventory(&state, &sess, &inv).await
                        }
                        Some(AgentPayload::UpdateResult { version, ok, error }) => {
                            crate::updates::on_result(&state, device_id, &version, ok, &error).await
                        }
                        Some(AgentPayload::RenewCertificate { csr_pem }) => {
                            match renew_certificate(&state, device_id, &sess.serial, &csr_pem).await
                            {
                                Ok(issued) => {
                                    let _ = sess
                                        .conn
                                        .tx
                                        .send(ServerPayload::Certificate {
                                            cert_pem: issued.cert_pem,
                                            ca_pem: state.ca.cert_pem.clone(),
                                        })
                                        .await;
                                }
                                // Bad CSR / rate limit: can never succeed as sent; ack
                                // it so the outbox drops it (the agent asks again later).
                                Err(e) => {
                                    tracing::warn!(%device_id, error = %e, "certificate renewal refused")
                                }
                            }
                            Ok(())
                        }
                        Some(AgentPayload::Ack { seq: acked }) => {
                            // Server acks are per message; the agent acks each server seq.
                            if let Some((_, p)) = sent.remove(&acked) {
                                if let Err(e) =
                                    ingest::server_message_acked(&state, device_id, &p).await
                                {
                                    tracing::warn!(error = %e, "processing agent ack");
                                }
                            }
                            Ok(())
                        }
                    }
                    })
                    .catch_unwind()
                    .await;
                    let res = match dispatched {
                        Ok(r) => r,
                        Err(_) => {
                            tracing::error!(%device_id, seq, "agent message handler panicked; closing stream");
                            break;
                        }
                    };
                    if seq == 0 {
                        continue; // seq 0 (Hello / agent Acks) is never acked or deduped
                    }
                    match res {
                        Ok(()) => {
                            hwm = seq;
                            if let Err(e) = sqlx::query("UPDATE devices SET last_agent_seq = GREATEST(last_agent_seq, $2) WHERE id = $1")
                                .bind(device_id)
                                .bind(seq as i64)
                                .execute(&state.db)
                                .await
                            {
                                tracing::error!(%device_id, error = %e, "failed to persist agent seq");
                                break;
                            }
                            if sess.conn.tx.send(ServerPayload::Ack { seq }).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            // Acks are cumulative, so nothing after this message may be acked:
                            // drop the stream; the agent re-sends from its outbox on reconnect.
                            tracing::error!(%device_id, seq, error = %e, "failed to process agent message; closing stream");
                            break;
                        }
                    }
                }
                state.agents.unregister(device_id, session);
                let _ = sqlx::query(
                    "UPDATE devices SET last_seen = GREATEST(last_seen, $2) WHERE id = $1",
                )
                .bind(device_id)
                .bind(now_ms())
                .execute(&state.db)
                .await;
                tracing::info!(%device_id, "agent disconnected");
            });
        }

        // Outbound: assign seq, remember what needs an Ack, compress big payloads.
        #[allow(clippy::result_large_err)]
        let stream = tokio_stream::wrappers::ReceiverStream::new(rx).map(move |payload| {
            let seq = out_seq.fetch_add(1, Ordering::Relaxed) + 1;
            if matches!(
                payload,
                ServerPayload::Command { .. }
                    | ServerPayload::Policy(_)
                    | ServerPayload::Rules(_)
                    | ServerPayload::SetUninstallToken { .. }
            ) {
                sent.insert(seq, payload.clone());
            }
            let json = serde_json::to_vec(&payload).map_err(|e| Status::internal(e.to_string()))?;
            let (compressed, payload) = encode_payload(json);
            Ok(ServerEnvelope {
                seq,
                compressed,
                payload,
            })
        });
        drop(tx);
        Ok(Response::new(Box::pin(stream)))
    }
}
