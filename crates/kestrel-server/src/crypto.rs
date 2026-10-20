//! Small crypto helpers: secret wrapping with the master key, hashing, tokens, passwords.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{
    engine::general_purpose::STANDARD as B64, engine::general_purpose::URL_SAFE_NO_PAD as B64URL,
    Engine,
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// AES-256-GCM key derived from `KESTREL_MASTER_KEY`. Used to wrap the agent CA
/// private key, the self-signed web key, TOTP secrets and settings secrets.
#[derive(Clone)]
pub struct MasterKey {
    cipher: Aes256Gcm,
    /// KDF output; only used to derive independent sub-keys (never as a cipher key itself).
    seed: [u8; 32],
}

const WRAP_PREFIX: &str = "kv1:";

impl MasterKey {
    pub fn new(secret: &str) -> MasterKey {
        // Domain-separated SHA-256 KDF. The env secret is expected to be 32 random
        // bytes (base64); a slow KDF adds nothing for a random key.
        let mut h = Sha256::new();
        h.update(b"kestrel-master-key-v1\0");
        h.update(secret.as_bytes());
        let key = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key);
        MasterKey {
            cipher: Aes256Gcm::new_from_slice(&key).expect("32-byte key"),
            seed,
        }
    }

    /// Independent 32-byte sub-key for `label` (HMAC-SHA256 of the label under the
    /// master seed), e.g. the audit-chain HMAC key or the username-hash key.
    pub fn subkey(&self, label: &str) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.seed).expect("hmac key");
        mac.update(b"kestrel-subkey-v1\0");
        mac.update(label.as_bytes());
        mac.finalize().into_bytes().into()
    }

    /// Pseudonymised user name (`u_` + 16 hex), stable per server. Values that are
    /// already pseudonyms (from an agent applying the same privacy policy) are kept.
    pub fn hash_username(&self, user: &str) -> String {
        if is_pseudonym(user) {
            return user.to_string();
        }
        let key = self.subkey("username-hash");
        format!(
            "u_{}",
            &hmac_sha256_hex(&key, user.trim().to_lowercase().as_bytes())[..16]
        )
    }

    /// Encrypt to `kv1:<base64(nonce || ciphertext)>`.
    pub fn seal(&self, plaintext: &[u8]) -> String {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .expect("aes-gcm encrypt");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ct);
        format!("{WRAP_PREFIX}{}", B64.encode(out))
    }

    pub fn open(&self, sealed: &str) -> anyhow::Result<Vec<u8>> {
        let b = sealed
            .strip_prefix(WRAP_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("unknown secret wrapping format"))?;
        let raw = B64.decode(b)?;
        if raw.len() < 12 + 16 {
            anyhow::bail!("sealed secret too short");
        }
        let (nonce, ct) = raw.split_at(12);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| {
                anyhow::anyhow!("cannot decrypt secret: wrong KESTREL_MASTER_KEY or corrupted data")
            })
    }

    pub fn seal_str(&self, s: &str) -> String {
        self.seal(s.as_bytes())
    }

    pub fn open_str(&self, sealed: &str) -> anyhow::Result<String> {
        Ok(String::from_utf8(self.open(sealed)?)?)
    }
}

/// `u_` followed by 16 lower-case hex digits (agent and server pseudonym format).
pub fn is_pseudonym(s: &str) -> bool {
    s.len() == 18
        && s.starts_with("u_")
        && s[2..]
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    hex::encode(Sha256::digest(data.as_ref()))
}

pub fn hmac_sha256_hex(key: &[u8], data: &[u8]) -> String {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// URL-safe random token with `n` bytes of entropy.
pub fn random_token(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut b);
    B64URL.encode(b)
}

/// Constant-time string comparison.
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("argon2: {e}"))
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    match PasswordHash::new(hash) {
        Ok(parsed) => Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok(),
        Err(_) => false,
    }
}

/// A fixed argon2 hash used to equalise timing when the user does not exist.
pub fn dummy_password_check(password: &str) {
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let h = DUMMY.get_or_init(|| hash_password("kestrel-dummy-password").unwrap_or_default());
    let _ = verify_password(password, h);
}

pub fn totp_for(secret_b32: &str, account: &str) -> anyhow::Result<totp_rs::TOTP> {
    let secret = totp_rs::Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    totp_rs::TOTP::new(
        totp_rs::Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("Kestrel EDR".into()),
        account.to_string(),
    )
    .map_err(|e| anyhow::anyhow!("totp: {e}"))
}

/// Verify a TOTP code (±1 step of skew) and return the matched time step. Steps
/// at or below `last_step` are refused (L1: a code works only once).
pub fn totp_verify_step(
    totp: &totp_rs::TOTP,
    code: &str,
    now_secs: u64,
    last_step: Option<i64>,
) -> Option<i64> {
    let code = code.trim();
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let cur = (now_secs / 30) as i64;
    let mut hit = None;
    for step in [cur - 1, cur, cur + 1] {
        if step < 0 || last_step.map(|l| step <= l).unwrap_or(false) {
            continue;
        }
        if ct_eq(&totp.generate(step as u64 * 30), code) {
            hit = Some(step);
        }
    }
    hit
}

pub fn new_totp_secret() -> String {
    totp_rs::Secret::generate_secret().to_encoded().to_string()
}

/// Canonical JSON: object keys sorted recursively, no insignificant whitespace.
/// Used for the audit-log hash chain (independent of serde_json's map ordering).
pub fn canonical_json(v: &serde_json::Value) -> String {
    use serde_json::Value;
    fn write(v: &Value, out: &mut String) {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(k).unwrap_or_default());
                    out.push(':');
                    write(&m[*k], out);
                }
                out.push('}');
            }
            Value::Array(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write(x, out);
                }
                out.push(']');
            }
            other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
        }
    }
    let mut s = String::new();
    write(v, &mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_roundtrip() {
        let k = MasterKey::new("0123456789abcdef0123456789abcdef");
        let s = k.seal_str("hello");
        assert!(s.starts_with("kv1:"));
        assert_eq!(k.open_str(&s).unwrap(), "hello");
        let other = MasterKey::new("another-master-key-0000000000000");
        assert!(other.open_str(&s).is_err());
    }

    #[test]
    fn totp_step_replay() {
        let t = totp_for(&new_totp_secret(), "a@b.c").unwrap();
        let now = 1_760_000_000u64;
        let code = t.generate(now);
        let step = totp_verify_step(&t, &code, now, None).unwrap();
        assert_eq!(step, (now / 30) as i64);
        assert_eq!(totp_verify_step(&t, &code, now, Some(step)), None, "replay");
        let next = t.generate(now + 30);
        assert_eq!(totp_verify_step(&t, &next, now, Some(step)), Some(step + 1));
        assert_eq!(totp_verify_step(&t, "12345", now, None), None);
    }

    #[test]
    fn subkeys_and_pseudonyms() {
        let k = MasterKey::new("0123456789abcdef0123456789abcdef");
        assert_ne!(k.subkey("a"), k.subkey("b"));
        let h = k.hash_username("CORP\\Alice");
        assert!(is_pseudonym(&h), "{h}");
        assert_eq!(h, k.hash_username("corp\\alice"));
        assert_eq!(k.hash_username(&h), h);
        let other = MasterKey::new("another-master-key-0000000000000");
        assert_ne!(other.hash_username("CORP\\Alice"), h);
    }

    #[test]
    fn canonical_sorted() {
        let v = serde_json::json!({"b": 1, "a": {"d": [1, {"z": 1, "y": 2}], "c": "x"}});
        assert_eq!(
            canonical_json(&v),
            r#"{"a":{"c":"x","d":[1,{"y":2,"z":1}]},"b":1}"#
        );
    }

    #[test]
    fn passwords() {
        let h = hash_password("correct horse").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &h));
        assert!(!verify_password("wrong", &h));
    }
}
