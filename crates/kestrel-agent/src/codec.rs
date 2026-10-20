//! JSON (+ optional zstd) payload encoding inside the gRPC envelopes.

use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Serialize};

/// Payloads larger than this are zstd-compressed.
pub const COMPRESS_THRESHOLD: usize = 1024;
const ZSTD_LEVEL: i32 = 3;
/// Refuse to inflate payloads beyond this (defends against zstd bombs).
pub const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Serialise `v` as JSON; compress when large or when `force_compress`.
/// Returns `(bytes, compressed)`.
pub fn encode<T: Serialize>(v: &T, force_compress: bool) -> Result<(Vec<u8>, bool)> {
    let json = serde_json::to_vec(v)?;
    if force_compress || json.len() > COMPRESS_THRESHOLD {
        let z = zstd::bulk::compress(&json, ZSTD_LEVEL)?;
        Ok((z, true))
    } else {
        Ok((json, false))
    }
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8], compressed: bool) -> Result<T> {
    if compressed {
        let raw = zstd::bulk::decompress(bytes, MAX_DECOMPRESSED).context("zstd decompress")?;
        Ok(serde_json::from_slice(&raw).context("decode json payload")?)
    } else {
        Ok(serde_json::from_slice(bytes).context("decode json payload")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::wire::AgentPayload;

    #[test]
    fn roundtrip_small_and_large() {
        let small = AgentPayload::Ack { seq: 7 };
        let (b, c) = encode(&small, false).unwrap();
        assert!(!c);
        assert_eq!(decode::<AgentPayload>(&b, c).unwrap(), small);
        let (b, c) = encode(&small, true).unwrap();
        assert!(c);
        assert_eq!(decode::<AgentPayload>(&b, c).unwrap(), small);
    }
}
