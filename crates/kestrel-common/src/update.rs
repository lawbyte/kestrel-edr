//! Signed agent updates: the pieces agent, server and signing tool share.
//!
//! A release is described by [`crate::wire::UpdateManifest`]. Its `signature`
//! is base64 Ed25519 over [`signed_message`]. The private key never touches
//! the server: the owner signs offline (`kestrel-agent update-sign`), the
//! server verifies against `KESTREL_UPDATE_PUBKEY` before it distributes a
//! release, and every agent verifies again with the key built into it.

use crate::wire::UpdateManifest;
use serde::{Deserialize, Serialize};

/// Domain separator of the signed message (version 1).
pub const SIGNED_PREFIX: &str = "kestrel-update-v1";
/// Longest accepted version string.
pub const MAX_VERSION_LEN: usize = 64;
/// Longest accepted package URL.
pub const MAX_URL_LEN: usize = 2048;

/// Bytes covered by the manifest signature:
/// `kestrel-update-v1\n{version}\n{url}\n{sha256}` (fields trimmed, sha256
/// lower-case hex). Binding version and URL stops a signed package from being
/// replayed under another version (downgrade) or download location.
pub fn signed_message(m: &UpdateManifest) -> Vec<u8> {
    format!(
        "{SIGNED_PREFIX}\n{}\n{}\n{}",
        m.version.trim(),
        m.url.trim(),
        m.sha256.trim().to_ascii_lowercase()
    )
    .into_bytes()
}

/// Dotted-numeric version compare: is `a` newer than `b`? Non-numeric parts
/// count as 0 (`1.2.3-rc1` == `1.2.3.0`), a leading `v` is ignored.
pub fn is_newer(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim()
            .trim_start_matches('v')
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

/// Semver-ish: `[v]N.N[.N[.N]]` with an optional `-pre` / `+build` suffix of
/// `[0-9A-Za-z.-]`.
pub fn valid_version(v: &str) -> bool {
    if v.is_empty() || v.len() > MAX_VERSION_LEN || v.trim() != v {
        return false;
    }
    let v = v.strip_prefix('v').unwrap_or(v);
    let (core, suffix) = match v.find(['-', '+']) {
        Some(i) => (&v[..i], Some(&v[i + 1..])),
        None => (v, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if !(2..=4).contains(&parts.len())
        || parts
            .iter()
            .any(|p| p.is_empty() || p.len() > 9 || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    match suffix {
        None => true,
        Some(s) => {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
        }
    }
}

/// Lower-case 64-hex-digit SHA-256.
pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Format checks shared by the signing tool, the server and the agent: the
/// version is semver-ish, the URL is an absolute `https://` URL without
/// whitespace, the hash is hex. Signature checks are separate (crypto lives
/// in the callers).
pub fn check_manifest_format(m: &UpdateManifest) -> Result<(), String> {
    if !valid_version(&m.version) {
        return Err(format!(
            "version '{}' is not a version number like 1.4.0 or 1.4.0-rc1",
            m.version.chars().take(80).collect::<String>()
        ));
    }
    let url = m.url.as_str();
    if url.is_empty() || url.len() > MAX_URL_LEN {
        return Err("url is empty or too long".into());
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url must not contain whitespace or control characters".into());
    }
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("url must start with https://".into());
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() || host.contains('@') {
        return Err("url must name a host (and no user info)".into());
    }
    if !valid_sha256(&m.sha256.to_ascii_lowercase()) || m.sha256.trim() != m.sha256 {
        return Err("sha256 must be 64 hexadecimal characters".into());
    }
    if m.signature.trim().is_empty() {
        return Err("signature is missing".into());
    }
    Ok(())
}

/// Staged rollout ring of a device group.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UpdateRing {
    /// Ring 0: a handful of IT machines that get every release first.
    Canary,
    /// Ring 1: early adopters.
    Early,
    /// Ring 2: everyone else (default).
    Broad,
}

impl UpdateRing {
    pub const ALL: [UpdateRing; 3] = [UpdateRing::Canary, UpdateRing::Early, UpdateRing::Broad];

    pub fn as_str(&self) -> &'static str {
        match self {
            UpdateRing::Canary => "canary",
            UpdateRing::Early => "early",
            UpdateRing::Broad => "broad",
        }
    }

    pub fn parse(s: &str) -> Option<UpdateRing> {
        match s {
            "canary" => Some(UpdateRing::Canary),
            "early" => Some(UpdateRing::Early),
            "broad" => Some(UpdateRing::Broad),
            _ => None,
        }
    }

    pub fn index(&self) -> usize {
        *self as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(version: &str, url: &str, sha: &str) -> UpdateManifest {
        UpdateManifest {
            version: version.into(),
            url: url.into(),
            sha256: sha.into(),
            signature: "c2ln".into(),
        }
    }

    #[test]
    fn versions() {
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("1.0", "0.9.9"));
        assert!(is_newer("v1.0.1", "1.0.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        assert!(!is_newer("1.2.3-rc1", "1.2.3"));
        for ok in ["1.2", "1.2.3", "v1.2.3", "1.2.3.4", "1.2.3-rc1", "1.2.3+b7"] {
            assert!(valid_version(ok), "{ok}");
        }
        for bad in [
            "",
            "1",
            "1..2",
            "a.b",
            "1.2.3\n",
            " 1.2",
            "1.2.3-",
            "1.2.3-x y",
            "1.2.3.4.5",
        ] {
            assert!(!valid_version(bad), "{bad:?}");
        }
    }

    #[test]
    fn manifest_format() {
        let sha = "ab".repeat(32);
        assert!(check_manifest_format(&m("1.2.3", "https://h/x.msi", &sha)).is_ok());
        assert!(check_manifest_format(&m("1.2.3", "http://h/x.msi", &sha)).is_err());
        assert!(check_manifest_format(&m("1.2.3", "https:///x.msi", &sha)).is_err());
        assert!(check_manifest_format(&m("1.2.3", "https://u@h/x.msi", &sha)).is_err());
        assert!(check_manifest_format(&m("1.2.3", "https://h/x\n.msi", &sha)).is_err());
        assert!(check_manifest_format(&m("1.2.3", "https://h/x.msi", "abc")).is_err());
        assert!(check_manifest_format(&m("x", "https://h/x.msi", &sha)).is_err());
        let mut no_sig = m("1.2.3", "https://h/x.msi", &sha);
        no_sig.signature.clear();
        assert!(check_manifest_format(&no_sig).is_err());
    }

    #[test]
    fn signed_message_binds_fields() {
        let sha = "AB".repeat(32);
        let msg = signed_message(&m(" 1.2.3 ", "https://h/x.msi", &sha));
        assert_eq!(
            String::from_utf8(msg).unwrap(),
            format!(
                "kestrel-update-v1\n1.2.3\nhttps://h/x.msi\n{}",
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn rings() {
        for r in UpdateRing::ALL {
            assert_eq!(UpdateRing::parse(r.as_str()), Some(r));
        }
        assert_eq!(UpdateRing::Early.index(), 1);
        assert!(UpdateRing::parse("pinned").is_none());
    }
}
