//! Signed agent auto-update with staged rings (canary → early → broad).
//!
//! * The server never holds the signing key. An administrator registers a
//!   release by pasting the manifest `kestrel-agent update-sign` printed
//!   offline; the server checks its format and verifies the Ed25519 signature
//!   against `KESTREL_UPDATE_PUBKEY` (registration is refused when unset).
//!   Agents verify the signature again with the key built into them.
//! * A release starts with no ring enabled. Admins promote it ring by ring and
//!   can halt it (terminal: nothing more is delivered; agents that already
//!   updated stay updated).
//! * A device's ring is its group's `update_ring` (`pinned` never updates).
//!   Connected agents of a ring get `ServerPayload::Update` on promotion,
//!   others on their next `Hello`, but only when the newest release enabled
//!   for their ring is newer than the version they run. Decommissioned devices
//!   never get anything (they cannot connect either).
//! * Outcomes: a later `Hello` with the new version marks the delivery
//!   succeeded; an `AgentPayload::UpdateResult { ok: false }` marks it failed.

use crate::{crypto::sha256_hex, state::AppState};
use base64::Engine as _;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use kestrel_common::{
    now_ms,
    update::{check_manifest_format, is_newer, signed_message, UpdateRing},
    wire::{ServerPayload, UpdateManifest},
};
use serde_json::{json, Value};
use sqlx::PgPool;
use std::collections::{BTreeMap, HashMap};
use uuid::Uuid;

/// Group ring value for "never auto-update".
pub const PINNED: &str = "pinned";
/// URL path under which server-hosted packages are served (agent port).
pub const PACKAGE_PATH: &str = "/downloads/updates/";
/// A delivered device silent for this long counts as "offline after delivery".
pub const OFFLINE_AFTER_MS: i64 = 24 * 3_600_000;

pub fn valid_group_ring(s: &str) -> bool {
    s == PINNED || UpdateRing::parse(s).is_some()
}

/// Parse a base64 32-byte Ed25519 public key.
pub fn parse_pubkey(b64: &str) -> Result<VerifyingKey, String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .map_err(|_| "not base64".to_string())?;
    let arr: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| "an Ed25519 public key is 32 bytes".to_string())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "not a valid Ed25519 public key".to_string())
}

/// Verify a manifest's signature with `key`.
pub fn verify_signature(key: &VerifyingKey, m: &UpdateManifest) -> Result<(), String> {
    let sig = base64::engine::general_purpose::STANDARD
        .decode(m.signature.trim())
        .map_err(|_| "signature is not base64".to_string())?;
    let sig = Signature::from_slice(&sig).map_err(|_| "signature has the wrong length")?;
    key.verify(&signed_message(m), &sig).map_err(|_| {
        "signature does not verify against the configured update key (KESTREL_UPDATE_PUBKEY)"
            .to_string()
    })
}

/// Base URL agents can download server-hosted packages from: the agent
/// (gRPC) port, whose certificate chains to the pinned agent CA. The web
/// port's certificate is not trusted by agents.
pub fn package_base_url(st: &AppState) -> String {
    format!(
        "https://{}:{}{PACKAGE_PATH}",
        st.cfg.primary_hostname(),
        st.cfg.grpc_public_port
    )
}

/// What a manifest URL points at.
#[derive(Debug, PartialEq)]
pub enum PackageLocation {
    /// A file in `<AGENT_DIR>/updates/` on this server.
    Local(String),
    /// Somewhere else (agents verify it against the public web PKI).
    External,
}

/// Classify a manifest URL. URLs on one of the server's public host names
/// must use the agent port and `/downloads/updates/<file>`.
pub fn classify_url(
    url: &str,
    hostnames: &[String],
    agent_port: u16,
) -> Result<PackageLocation, String> {
    let u = reqwest::Url::parse(url).map_err(|e| format!("url: {e}"))?;
    let host = u
        .host_str()
        .ok_or("url has no host")?
        .trim_matches(['[', ']'])
        .to_ascii_lowercase();
    if !hostnames.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
        return Ok(PackageLocation::External);
    }
    if u.port_or_known_default() != Some(agent_port) {
        return Err(format!(
            "packages on this server must be referenced on the agent port {agent_port} \
             (https://{host}:{agent_port}{PACKAGE_PATH}<file>): agents trust only the agent CA, \
             which the web port does not use"
        ));
    }
    let name = u
        .path()
        .strip_prefix(PACKAGE_PATH)
        .ok_or_else(|| format!("packages on this server must live under {PACKAGE_PATH}"))?;
    if u.query().is_some()
        || name.is_empty()
        || name.len() > 200
        || name.starts_with('.')
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return Err(format!(
            "package file name must be a plain name ([A-Za-z0-9._-]) directly under {PACKAGE_PATH}"
        ));
    }
    Ok(PackageLocation::Local(name.to_string()))
}

/// SHA-256 of a server-hosted package (`<AGENT_DIR>/updates/<name>`).
pub async fn local_package_sha256(st: &AppState, name: &str) -> Result<String, String> {
    let path = st.cfg.agent_dir.join("updates").join(name);
    tokio::task::spawn_blocking(move || {
        use sha2::Digest;
        use std::io::Read;
        let mut f = std::fs::File::open(&path).map_err(|_| {
            format!(
                "{} not found: copy the MSI into deploy/installers/updates/ first",
                path.display()
            )
        })?;
        let mut h = sha2::Sha256::new();
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = f.read(&mut buf).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Full registration check (format, signature, server-hosted package hash).
pub async fn validate_release(st: &AppState, m: &UpdateManifest) -> Result<(), String> {
    let key = st.cfg.update_pubkey.as_deref().ok_or(
        "agent updates are disabled: KESTREL_UPDATE_PUBKEY is not configured on the server. \
         Generate a key offline with `kestrel-agent update-keygen` (docs/BUILDING.md), set the \
         public key on the server and build the agent with it",
    )?;
    let key = parse_pubkey(key)?;
    check_manifest_format(m)?;
    verify_signature(&key, m)?;
    if let PackageLocation::Local(name) =
        classify_url(&m.url, &st.cfg.public_hostnames, st.cfg.grpc_public_port)?
    {
        let sha = local_package_sha256(st, &name).await?;
        if !sha.eq_ignore_ascii_case(m.sha256.trim()) {
            return Err(format!(
                "updates/{name} has SHA-256 {sha}, the manifest says {}: wrong file or stale manifest",
                m.sha256
            ));
        }
    }
    Ok(())
}

#[derive(sqlx::FromRow, Clone, Debug)]
pub struct ReleaseRow {
    pub id: Uuid,
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub signature: String,
    pub notes: String,
    pub created_by: Option<Uuid>,
    pub created_at: i64,
    pub halted_at: Option<i64>,
    pub halted_by: Option<Uuid>,
    pub halt_reason: String,
}

impl ReleaseRow {
    pub fn manifest(&self) -> UpdateManifest {
        UpdateManifest {
            version: self.version.clone(),
            url: self.url.clone(),
            sha256: self.sha256.clone(),
            signature: self.signature.clone(),
        }
    }
}

pub const RELEASE_COLS: &str =
    "id, version, url, sha256, signature, notes, created_by, created_at, halted_at, halted_by, halt_reason";

/// SQL expression for a device's ring (`d` = devices, `g` = its group).
pub const DEVICE_RING_EXPR: &str =
    "COALESCE(g.update_ring, (SELECT update_ring FROM groups WHERE is_default LIMIT 1), 'broad')";

pub async fn load_release(db: &PgPool, id: Uuid) -> anyhow::Result<Option<ReleaseRow>> {
    Ok(sqlx::query_as(&format!(
        "SELECT {RELEASE_COLS} FROM agent_releases WHERE id = $1"
    ))
    .bind(id)
    .fetch_optional(db)
    .await?)
}

/// Newest non-halted release enabled for each ring.
pub async fn ring_targets(db: &PgPool) -> anyhow::Result<HashMap<String, ReleaseRow>> {
    let rows: Vec<(String, Uuid)> = sqlx::query_as(
        "SELECT rr.ring, r.id FROM agent_release_rings rr JOIN agent_releases r ON r.id = rr.release_id \
         WHERE r.halted_at IS NULL",
    )
    .fetch_all(db)
    .await?;
    let releases: Vec<ReleaseRow> = sqlx::query_as(&format!(
        "SELECT {RELEASE_COLS} FROM agent_releases WHERE halted_at IS NULL"
    ))
    .fetch_all(db)
    .await?;
    let by_id: HashMap<Uuid, &ReleaseRow> = releases.iter().map(|r| (r.id, r)).collect();
    let mut out: HashMap<String, ReleaseRow> = HashMap::new();
    for (ring, id) in rows {
        let Some(r) = by_id.get(&id) else { continue };
        let newer = match out.get(&ring) {
            Some(cur) => is_newer(&r.version, &cur.version),
            None => true,
        };
        if newer {
            out.insert(ring, (*r).clone());
        }
    }
    Ok(out)
}

/// Remember that `release` was sent to `device_id`.
async fn record_delivery(
    db: &PgPool,
    release: Uuid,
    device_id: Uuid,
    ring: &str,
    from_version: &str,
) -> anyhow::Result<()> {
    let now = now_ms();
    sqlx::query(
        "INSERT INTO agent_update_deliveries (release_id, device_id, ring, from_version, first_sent_at, last_sent_at) \
         VALUES ($1,$2,$3,$4,$5,$5) ON CONFLICT (release_id, device_id) DO UPDATE SET \
         last_sent_at = EXCLUDED.last_sent_at, attempts = agent_update_deliveries.attempts + 1",
    )
    .bind(release)
    .bind(device_id)
    .bind(ring)
    .bind(from_version)
    .bind(now)
    .execute(db)
    .await?;
    Ok(())
}

/// The release a device in `ring` running `version` should get, if any.
fn offer<'a>(
    targets: &'a HashMap<String, ReleaseRow>,
    ring: &str,
    version: &str,
) -> Option<&'a ReleaseRow> {
    if ring == PINNED {
        return None;
    }
    targets.get(ring).filter(|r| is_newer(&r.version, version))
}

/// On `Hello` (after `devices.agent_version` was updated): settle outcomes
/// of earlier deliveries and return the manifest to offer, if any.
pub async fn on_hello(
    st: &AppState,
    device_id: Uuid,
    agent_version: &str,
) -> anyhow::Result<Option<ServerPayload>> {
    let open: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT d.release_id, r.version FROM agent_update_deliveries d JOIN agent_releases r ON r.id = d.release_id \
         WHERE d.device_id = $1 AND d.status <> 'succeeded'",
    )
    .bind(device_id)
    .fetch_all(&st.db)
    .await?;
    let now = now_ms();
    for (rid, version) in open {
        if !is_newer(&version, agent_version) {
            sqlx::query(
                "UPDATE agent_update_deliveries SET status = 'succeeded', completed_at = $3, error = '' \
                 WHERE release_id = $1 AND device_id = $2",
            )
            .bind(rid)
            .bind(device_id)
            .bind(now)
            .execute(&st.db)
            .await?;
            st.publish("update_release", rid, "updated");
        }
    }
    let row: Option<(String, Option<i64>)> = sqlx::query_as(&format!(
        "SELECT {DEVICE_RING_EXPR}, d.decommissioned_at FROM devices d LEFT JOIN groups g ON g.id = d.group_id WHERE d.id = $1"
    ))
    .bind(device_id)
    .fetch_optional(&st.db)
    .await?;
    let Some((ring, None)) = row else {
        return Ok(None);
    };
    let targets = ring_targets(&st.db).await?;
    let Some(r) = offer(&targets, &ring, agent_version) else {
        return Ok(None);
    };
    record_delivery(&st.db, r.id, device_id, &ring, agent_version).await?;
    st.publish("update_release", r.id, "updated");
    Ok(Some(ServerPayload::Update(r.manifest())))
}

/// Which connected devices to consider in [`deliver_to_connected`].
pub enum Scope {
    Ring(UpdateRing),
    Group(Uuid),
}

/// Send the current target release to connected, non-decommissioned agents
/// in `scope` that run an older version. Returns how many were sent.
pub async fn deliver_to_connected(st: &AppState, scope: Scope) -> anyhow::Result<usize> {
    let connected: Vec<Uuid> = st
        .agents
        .connected()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    if connected.is_empty() {
        return Ok(0);
    }
    let base = format!(
        "SELECT d.id, d.agent_version, {DEVICE_RING_EXPR} AS ring FROM devices d LEFT JOIN groups g ON g.id = d.group_id \
         WHERE d.id = ANY($1) AND d.decommissioned_at IS NULL"
    );
    let rows: Vec<(Uuid, String, String)> = match scope {
        Scope::Ring(r) => {
            sqlx::query_as(&format!("{base} AND {DEVICE_RING_EXPR} = $2"))
                .bind(&connected)
                .bind(r.as_str())
                .fetch_all(&st.db)
                .await?
        }
        Scope::Group(gid) => {
            sqlx::query_as(&format!("{base} AND d.group_id = $2"))
                .bind(&connected)
                .bind(gid)
                .fetch_all(&st.db)
                .await?
        }
    };
    let targets = ring_targets(&st.db).await?;
    let mut sent = 0;
    let mut touched = std::collections::BTreeSet::new();
    for (device_id, version, ring) in rows {
        let Some(r) = offer(&targets, &ring, &version) else {
            continue;
        };
        if st
            .agents
            .send(&device_id, ServerPayload::Update(r.manifest()))
        {
            record_delivery(&st.db, r.id, device_id, &ring, &version).await?;
            touched.insert(r.id);
            sent += 1;
        }
    }
    for id in touched {
        st.publish("update_release", id, "updated");
    }
    Ok(sent)
}

/// `AgentPayload::UpdateResult` from a device.
pub async fn on_result(
    st: &AppState,
    device_id: Uuid,
    version: &str,
    ok: bool,
    error: &str,
) -> anyhow::Result<()> {
    let error: String = error.chars().take(1000).collect();
    let r: Option<(Uuid,)> = sqlx::query_as(
        "UPDATE agent_update_deliveries d SET status = $3, completed_at = $4, error = $5 \
         FROM agent_releases r WHERE r.id = d.release_id AND r.version = $2 AND d.device_id = $1 \
         AND d.status <> 'succeeded' RETURNING d.release_id",
    )
    .bind(device_id)
    .bind(version)
    .bind(if ok { "succeeded" } else { "failed" })
    .bind(now_ms())
    .bind(&error)
    .fetch_optional(&st.db)
    .await?;
    match r {
        Some((rid,)) => {
            if !ok {
                tracing::warn!(%device_id, version, error = %error, "agent update failed");
            }
            st.publish("update_release", rid, "updated");
        }
        None => {
            tracing::info!(%device_id, version, ok, "update result for a release not delivered to this device; ignored")
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ views

struct DeviceVer {
    ring: String,
    version: String,
}

async fn fleet(db: &PgPool) -> anyhow::Result<Vec<DeviceVer>> {
    let rows: Vec<(String, String)> = sqlx::query_as(&format!(
        "SELECT {DEVICE_RING_EXPR}, d.agent_version FROM devices d LEFT JOIN groups g ON g.id = d.group_id \
         WHERE d.decommissioned_at IS NULL"
    ))
    .fetch_all(db)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(ring, version)| DeviceVer { ring, version })
        .collect())
}

async fn user_names(db: &PgPool) -> anyhow::Result<HashMap<Uuid, String>> {
    let rows: Vec<(Uuid, String, String)> = sqlx::query_as("SELECT id, name, email FROM users")
        .fetch_all(db)
        .await?;
    Ok(rows
        .into_iter()
        .map(|(id, n, e)| (id, if n.is_empty() { e } else { n }))
        .collect())
}

/// Releases (newest first) with per-ring health.
pub async fn releases_view(db: &PgPool, only: Option<Uuid>) -> anyhow::Result<Vec<Value>> {
    let mut releases: Vec<ReleaseRow> = match only {
        Some(id) => load_release(db, id).await?.into_iter().collect(),
        None => {
            sqlx::query_as(&format!("SELECT {RELEASE_COLS} FROM agent_releases"))
                .fetch_all(db)
                .await?
        }
    };
    releases.sort_by(|a, b| {
        if is_newer(&a.version, &b.version) {
            std::cmp::Ordering::Less
        } else if is_newer(&b.version, &a.version) {
            std::cmp::Ordering::Greater
        } else {
            b.created_at.cmp(&a.created_at)
        }
    });
    let ids: Vec<Uuid> = releases.iter().map(|r| r.id).collect();
    let rings: Vec<(Uuid, String, i64, Option<Uuid>)> = sqlx::query_as(
        "SELECT release_id, ring, enabled_at, enabled_by FROM agent_release_rings WHERE release_id = ANY($1)",
    )
    .bind(&ids)
    .fetch_all(db)
    .await?;
    let cutoff = now_ms() - OFFLINE_AFTER_MS;
    type Agg = (Uuid, String, i64, i64, i64, i64, i64);
    let agg: Vec<Agg> = sqlx::query_as(
        "SELECT d.release_id, d.ring, count(*), \
         count(*) FILTER (WHERE d.status = 'succeeded'), \
         count(*) FILTER (WHERE d.status = 'failed'), \
         count(*) FILTER (WHERE d.status = 'sent'), \
         count(*) FILTER (WHERE d.status = 'sent' AND dv.last_seen < $2) \
         FROM agent_update_deliveries d JOIN devices dv ON dv.id = d.device_id \
         WHERE d.release_id = ANY($1) AND dv.decommissioned_at IS NULL GROUP BY d.release_id, d.ring",
    )
    .bind(&ids)
    .bind(cutoff)
    .fetch_all(db)
    .await?;
    let failures: Vec<(Uuid, Uuid, String, String, Option<i64>)> = sqlx::query_as(
        "SELECT d.release_id, d.device_id, dv.hostname, d.error, d.completed_at FROM agent_update_deliveries d \
         JOIN devices dv ON dv.id = d.device_id WHERE d.release_id = ANY($1) AND d.status = 'failed' \
         ORDER BY d.completed_at DESC NULLS LAST LIMIT 1000",
    )
    .bind(&ids)
    .fetch_all(db)
    .await?;
    let devices = fleet(db).await?;
    let names = user_names(db).await?;
    let name = |id: &Option<Uuid>| id.and_then(|u| names.get(&u).cloned());

    let mut out = Vec::with_capacity(releases.len());
    for r in &releases {
        let enabled: BTreeMap<&str, (i64, Option<Uuid>)> = rings
            .iter()
            .filter(|x| x.0 == r.id)
            .map(|x| (x.1.as_str(), (x.2, x.3)))
            .collect();
        let mut ring_views = Vec::new();
        for ring in UpdateRing::ALL {
            let rs = ring.as_str();
            let in_ring: Vec<&DeviceVer> = devices.iter().filter(|d| d.ring == rs).collect();
            let on_target = in_ring
                .iter()
                .filter(|d| !d.version.is_empty() && !is_newer(&r.version, &d.version))
                .count();
            let a = agg
                .iter()
                .find(|x| x.0 == r.id && x.1 == rs)
                .map(|x| (x.2, x.3, x.4, x.5, x.6))
                .unwrap_or_default();
            let en = enabled.get(rs);
            ring_views.push(json!({
                "ring": rs,
                "enabled": en.is_some(),
                "enabled_at": en.map(|e| e.0),
                "enabled_by": en.and_then(|e| e.1),
                "enabled_by_name": en.and_then(|e| name(&e.1)),
                "devices": in_ring.len(),
                "on_target": on_target,
                "delivered": a.0,
                "succeeded": a.1,
                "failed": a.2,
                "pending": a.3,
                "offline_24h": a.4,
            }));
        }
        let state = if r.halted_at.is_some() {
            "halted"
        } else if enabled.contains_key("broad") {
            "complete"
        } else if enabled.is_empty() {
            "staged"
        } else {
            "rolling"
        };
        let next_ring = if r.halted_at.is_some() {
            None
        } else {
            UpdateRing::ALL
                .iter()
                .find(|x| !enabled.contains_key(x.as_str()))
                .map(|x| x.as_str())
        };
        let recent: Vec<Value> = failures
            .iter()
            .filter(|f| f.0 == r.id)
            .take(20)
            .map(|f| json!({"device_id": f.1, "hostname": f.2, "error": f.3, "at": f.4.unwrap_or(0)}))
            .collect();
        out.push(json!({
            "id": r.id,
            "version": r.version,
            "url": r.url,
            "sha256": r.sha256,
            "signature": r.signature,
            "notes": r.notes,
            "created_by": r.created_by,
            "created_by_name": name(&r.created_by),
            "created_at": r.created_at,
            "state": state,
            "halted_at": r.halted_at,
            "halted_by": r.halted_by,
            "halted_by_name": name(&r.halted_by),
            "halt_reason": r.halt_reason,
            "next_ring": next_ring,
            "rings": ring_views,
            "recent_failures": recent,
        }));
    }
    Ok(out)
}

/// Fleet overview per ring (incl. pinned).
pub async fn status_view(st: &AppState) -> anyhow::Result<Value> {
    let groups: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, name, update_ring FROM groups ORDER BY is_default DESC, name")
            .fetch_all(&st.db)
            .await?;
    let devices = fleet(&st.db).await?;
    let targets = ring_targets(&st.db).await?;
    let mut rings = Vec::new();
    for rs in ["canary", "early", "broad", PINNED] {
        let mut versions: BTreeMap<&str, usize> = BTreeMap::new();
        let mut n = 0;
        for d in devices.iter().filter(|d| d.ring == rs) {
            n += 1;
            *versions.entry(d.version.as_str()).or_default() += 1;
        }
        let mut versions: Vec<(&str, usize)> = versions.into_iter().collect();
        versions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        rings.push(json!({
            "ring": rs,
            "groups": groups.iter().filter(|g| g.2 == rs).map(|g| json!({"id": g.0, "name": g.1})).collect::<Vec<_>>(),
            "devices": n,
            "versions": versions.iter().map(|(v, c)| json!({"version": v, "count": c})).collect::<Vec<_>>(),
            "target": targets.get(rs).map(|r| json!({"id": r.id, "version": r.version})),
        }));
    }
    Ok(json!({
        "signing_key_configured": st.cfg.update_pubkey.is_some(),
        "public_key": st.cfg.update_pubkey,
        "package_base_url": package_base_url(st),
        "server_version": kestrel_common::VERSION,
        "rings": rings,
    }))
}

/// Short fingerprint of the configured key for audit entries.
pub fn key_fingerprint(st: &AppState) -> Option<String> {
    st.cfg
        .update_pubkey
        .as_deref()
        .map(|k| sha256_hex(k.trim().as_bytes())[..16].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hosts() -> Vec<String> {
        vec!["kestrel.acme.sg".into(), "10.0.0.5".into()]
    }

    #[test]
    fn url_classification() {
        let c = |u: &str| classify_url(u, &hosts(), 8443);
        assert_eq!(
            c("https://cdn.example.com/k/KestrelAgent-1.4.0.msi").unwrap(),
            PackageLocation::External
        );
        assert_eq!(
            c("https://kestrel.acme.sg:8443/downloads/updates/KestrelAgent-1.4.0.msi").unwrap(),
            PackageLocation::Local("KestrelAgent-1.4.0.msi".into())
        );
        assert_eq!(
            c("https://KESTREL.acme.sg:8443/downloads/updates/a.msi").unwrap(),
            PackageLocation::Local("a.msi".into())
        );
        assert_eq!(
            c("https://10.0.0.5:8443/downloads/updates/a.msi").unwrap(),
            PackageLocation::Local("a.msi".into())
        );
        // Web port: agents would not trust the certificate.
        assert!(c("https://kestrel.acme.sg/downloads/updates/a.msi").is_err());
        // Outside the updates directory / traversal / sub-directories / queries.
        assert!(c("https://kestrel.acme.sg:8443/downloads/KestrelAgent.msi").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/../x.msi").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/%2e%2e%2fx.msi").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/a/b.msi").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/.hidden").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/a.msi?x=1").is_err());
        assert!(c("https://kestrel.acme.sg:8443/downloads/updates/").is_err());
    }

    #[test]
    fn rings_and_offers() {
        assert!(valid_group_ring("pinned") && valid_group_ring("canary"));
        assert!(!valid_group_ring("ring0"));
        let rel = |v: &str| ReleaseRow {
            id: Uuid::new_v4(),
            version: v.into(),
            url: String::new(),
            sha256: String::new(),
            signature: String::new(),
            notes: String::new(),
            created_by: None,
            created_at: 0,
            halted_at: None,
            halted_by: None,
            halt_reason: String::new(),
        };
        let mut t = HashMap::new();
        t.insert("canary".to_string(), rel("1.4.0"));
        assert!(offer(&t, "canary", "1.3.9").is_some());
        assert!(offer(&t, "canary", "1.4.0").is_none());
        assert!(offer(&t, "canary", "1.5.0").is_none(), "never downgrade");
        assert!(offer(&t, "broad", "1.0.0").is_none());
        assert!(offer(&t, PINNED, "1.0.0").is_none());
    }

    #[test]
    fn pubkey_parsing() {
        assert!(parse_pubkey("").is_err());
        assert!(parse_pubkey("AAAA").is_err());
        let sk = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let b64 = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        assert!(parse_pubkey(&b64).is_ok());
    }
}
