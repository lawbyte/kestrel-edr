//! Internal agent CA (rcgen). The CA key is generated on first run and stored in
//! Postgres wrapped with the master key. It signs agent CSRs (CN = device id,
//! 1-year validity) and the gRPC server certificate.
//!
//! Renewal: an agent holding a still-valid, non-revoked client certificate calls
//! `Enroll` over mTLS with an empty token and a fresh CSR; the server issues a
//! new certificate for the same device id (CN taken from the presented cert).

use crate::crypto::{sha256_hex, MasterKey};
use anyhow::Context;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, DistinguishedName,
    DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType, SerialNumber,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;
use time::OffsetDateTime;

pub const AGENT_CERT_VALIDITY_DAYS: i64 = 365;

#[derive(Serialize, Deserialize)]
struct StoredKeyCert {
    cert_pem: String,
    key_enc: String,
    #[serde(default)]
    hostnames: Vec<String>,
}

pub struct AgentCa {
    pub cert_pem: String,
    key: KeyPair,
}

pub struct IssuedCert {
    pub cert_pem: String,
    pub serial: String,
    pub not_before: i64,
    pub not_after: i64,
}

pub struct ServerIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

fn random_serial() -> SerialNumber {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b[0] &= 0x7f; // positive
    b[0] |= 0x01; // no leading zero byte → stable hex form
    SerialNumber::from_slice(&b)
}

fn ms(t: OffsetDateTime) -> i64 {
    (t.unix_timestamp_nanos() / 1_000_000) as i64
}

impl AgentCa {
    /// Load the CA from Postgres or create it on first run.
    pub async fn load_or_create(
        db: &PgPool,
        mk: &MasterKey,
        org_name: &str,
    ) -> anyhow::Result<AgentCa> {
        if let Some((data,)) = sqlx::query_as::<_, (serde_json::Value,)>(
            "SELECT data FROM server_secrets WHERE name = 'agent_ca'",
        )
        .fetch_optional(db)
        .await?
        {
            let s: StoredKeyCert = serde_json::from_value(data)?;
            let key_pem = mk.open_str(&s.key_enc).context("unwrapping agent CA key")?;
            let key = KeyPair::from_pem(&key_pem)?;
            return Ok(AgentCa {
                cert_pem: s.cert_pem,
                key,
            });
        }
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Kestrel EDR Agent CA");
        if !org_name.is_empty() {
            dn.push(DnType::OrganizationName, org_name);
        }
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::from_secs(3600);
        params.not_after = now + Duration::from_secs(20 * 365 * 86400);
        params.serial_number = Some(random_serial());
        let cert = params.self_signed(&key)?;
        let stored = StoredKeyCert {
            cert_pem: cert.pem(),
            key_enc: mk.seal_str(&key.serialize_pem()),
            hostnames: vec![],
        };
        // Insert-if-absent so two replicas starting together agree on one CA.
        sqlx::query("INSERT INTO server_secrets (name, data) VALUES ('agent_ca', $1) ON CONFLICT (name) DO NOTHING")
            .bind(serde_json::to_value(&stored)?)
            .execute(db)
            .await?;
        tracing::info!("generated new internal agent CA");
        Box::pin(Self::load_or_create(db, mk, org_name)).await
    }

    fn issuer(&self) -> anyhow::Result<Issuer<'static, &KeyPair>> {
        Ok(Issuer::from_ca_cert_pem(&self.cert_pem, &self.key)?)
    }

    pub fn ca_sha256(&self) -> String {
        match rustls_pemfile::certs(&mut self.cert_pem.as_bytes()).next() {
            Some(Ok(der)) => sha256_hex(der.as_ref()),
            _ => String::new(),
        }
    }

    /// Sign an agent CSR. The subject and SANs of the CSR are ignored; the
    /// issued certificate always has CN = `device_id` and clientAuth EKU.
    pub fn sign_agent_csr(
        &self,
        csr_pem: &str,
        device_id: uuid::Uuid,
    ) -> anyhow::Result<IssuedCert> {
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).context("invalid CSR")?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, device_id.to_string());
        dn.push(DnType::OrganizationalUnitName, "Kestrel Agent");
        let now = OffsetDateTime::now_utc();
        let p = &mut csr.params;
        p.distinguished_name = dn;
        p.subject_alt_names = vec![];
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        p.not_before = now - Duration::from_secs(300);
        p.not_after = now + Duration::from_secs(AGENT_CERT_VALIDITY_DAYS as u64 * 86400);
        p.serial_number = Some(random_serial());
        p.use_authority_key_identifier_extension = true;
        p.custom_extensions = vec![];
        p.name_constraints = None;
        p.crl_distribution_points = vec![];
        let (nb, na) = (ms(p.not_before), ms(p.not_after));
        let cert = csr.signed_by(&self.issuer()?)?;
        let serial = cert_serial_hex(cert.der())?;
        Ok(IssuedCert {
            cert_pem: cert.pem(),
            serial,
            not_before: nb,
            not_after: na,
        })
    }

    /// gRPC server certificate signed by the agent CA (regenerated every start).
    pub fn server_identity(&self, hostnames: &[String]) -> anyhow::Result<ServerIdentity> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(
            DnType::CommonName,
            hostnames
                .first()
                .cloned()
                .unwrap_or_else(|| "localhost".into()),
        );
        params.distinguished_name = dn;
        params.subject_alt_names = san_list(hostnames)?;
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::from_secs(3600);
        params.not_after = now + Duration::from_secs(365 * 86400);
        params.serial_number = Some(random_serial());
        params.use_authority_key_identifier_extension = true;
        let cert = params.signed_by(&key, &self.issuer()?)?;
        Ok(ServerIdentity {
            cert_pem: format!("{}{}", cert.pem(), self.cert_pem),
            key_pem: key.serialize_pem(),
        })
    }
}

fn san_list(hostnames: &[String]) -> anyhow::Result<Vec<SanType>> {
    let mut names: Vec<String> = hostnames.to_vec();
    for extra in ["localhost", "127.0.0.1", "::1"] {
        if !names.iter().any(|n| n.eq_ignore_ascii_case(extra)) {
            names.push(extra.into());
        }
    }
    names
        .into_iter()
        .map(|n| match n.parse::<std::net::IpAddr>() {
            Ok(ip) => Ok(SanType::IpAddress(ip)),
            Err(_) => Ok(SanType::DnsName(n.try_into()?)),
        })
        .collect()
}

/// Self-signed web certificate, persisted (encrypted) so browsers can pin an exception.
pub async fn web_identity(
    db: &PgPool,
    mk: &MasterKey,
    hostnames: &[String],
) -> anyhow::Result<ServerIdentity> {
    if let Some((data,)) = sqlx::query_as::<_, (serde_json::Value,)>(
        "SELECT data FROM server_secrets WHERE name = 'web_tls'",
    )
    .fetch_optional(db)
    .await?
    {
        let s: StoredKeyCert = serde_json::from_value(data)?;
        if s.hostnames == hostnames {
            return Ok(ServerIdentity {
                cert_pem: s.cert_pem,
                key_pem: mk.open_str(&s.key_enc)?,
            });
        }
    }
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(
        DnType::CommonName,
        hostnames
            .first()
            .cloned()
            .unwrap_or_else(|| "localhost".into()),
    );
    dn.push(DnType::OrganizationName, "Kestrel EDR (self-signed)");
    params.distinguished_name = dn;
    params.subject_alt_names = san_list(hostnames)?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::from_secs(3600);
    params.not_after = now + Duration::from_secs(825 * 86400);
    params.serial_number = Some(random_serial());
    let cert = params.self_signed(&key)?;
    let stored = StoredKeyCert {
        cert_pem: cert.pem(),
        key_enc: mk.seal_str(&key.serialize_pem()),
        hostnames: hostnames.to_vec(),
    };
    sqlx::query(
        "INSERT INTO server_secrets (name, data) VALUES ('web_tls', $1) ON CONFLICT (name) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind(serde_json::to_value(&stored)?)
    .execute(db)
    .await?;
    tracing::info!(
        "generated self-signed web TLS certificate for {:?}",
        hostnames
    );
    Ok(ServerIdentity {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// Lower-case hex of the certificate serial number.
pub fn cert_serial_hex(der: &[u8]) -> anyhow::Result<String> {
    let (_, c) =
        x509_parser::parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("x509: {e}"))?;
    Ok(hex::encode(c.raw_serial()))
}

/// Common name and serial of a DER certificate.
pub fn cert_cn_serial(der: &[u8]) -> anyhow::Result<(String, String)> {
    let (_, c) =
        x509_parser::parse_x509_certificate(der).map_err(|e| anyhow::anyhow!("x509: {e}"))?;
    let cn = c
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .ok_or_else(|| anyhow::anyhow!("certificate has no CN"))?
        .to_string();
    Ok((cn, hex::encode(c.raw_serial())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_csr_forces_cn() {
        let ca_key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::default();
        p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = p.self_signed(&ca_key).unwrap();
        let ca = AgentCa {
            cert_pem: ca_cert.pem(),
            key: ca_key,
        };

        let agent_key = KeyPair::generate().unwrap();
        let mut req = CertificateParams::new(vec!["evil.example".to_string()]).unwrap();
        req.distinguished_name
            .push(DnType::CommonName, "00000000-0000-0000-0000-000000000000");
        let csr = req.serialize_request(&agent_key).unwrap().pem().unwrap();
        let id = uuid::Uuid::new_v4();
        let issued = ca.sign_agent_csr(&csr, id).unwrap();
        let der = rustls_pemfile::certs(&mut issued.cert_pem.as_bytes())
            .next()
            .unwrap()
            .unwrap();
        let (cn, serial) = cert_cn_serial(&der).unwrap();
        assert_eq!(cn, id.to_string());
        assert_eq!(serial, issued.serial);
        assert!(issued.not_after - issued.not_before > 364 * 86_400_000);
    }
}
