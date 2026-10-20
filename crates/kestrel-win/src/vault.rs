//! Quarantine vault format (pure, streaming).
//!
//! `<state>\quarantine\<id>.bin` = header + AES-256-GCM chunks:
//! * header: `b"KQV1"`, chunk size (u32 LE), 8-byte random nonce prefix
//! * chunk *i*: ciphertext ‖ 16-byte tag, nonce = prefix ‖ i (u32 BE),
//!   AAD = `b"KQV1"` ‖ i (u64 BE) ‖ last-flag. The last chunk is always
//!   flagged (possibly empty), so truncation and reordering are detected.
//!
//! Streaming keeps memory flat for large samples (stealer loaders padded to
//! ~500 MB are common). The 32-byte key is per host, generated once and stored
//! DPAPI-protected (machine scope) by the Windows module.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"KQV1";
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;

fn aad(index: u64, last: bool) -> [u8; 13] {
    let mut a = [0u8; 13];
    a[..4].copy_from_slice(MAGIC);
    a[4..12].copy_from_slice(&index.to_be_bytes());
    a[12] = last as u8;
    a
}

fn nonce(prefix: &[u8; 8], index: u64) -> io::Result<[u8; 12]> {
    let i: u32 = index
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "file too large for vault"))?;
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&i.to_be_bytes());
    Ok(n)
}

/// Fill `buf` as far as possible; returns bytes read (short only at EOF).
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

pub struct Sealed {
    pub plaintext_len: u64,
    pub sha256: String,
}

/// Encrypt `r` into `w`. Returns plaintext length and SHA-256 (hex).
pub fn encrypt_stream(
    key: &[u8; 32],
    nonce_prefix: [u8; 8],
    mut r: impl Read,
    mut w: impl Write,
) -> io::Result<Sealed> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| io::Error::other("bad key"))?;
    w.write_all(MAGIC)?;
    w.write_all(&(CHUNK as u32).to_le_bytes())?;
    w.write_all(&nonce_prefix)?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut cur = vec![0u8; CHUNK];
    let mut next = vec![0u8; CHUNK];
    let mut cur_len = read_full(&mut r, &mut cur)?;
    let mut index = 0u64;
    loop {
        let next_len = if cur_len == CHUNK {
            read_full(&mut r, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        hasher.update(&cur[..cur_len]);
        total += cur_len as u64;
        let n = nonce(&nonce_prefix, index)?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &cur[..cur_len],
                    aad: &aad(index, last),
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;
        w.write_all(&ct)?;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        index += 1;
    }
    w.flush()?;
    Ok(Sealed {
        plaintext_len: total,
        sha256: hex(&hasher.finalize()),
    })
}

/// Decrypt a vault stream into `w`. Fails on any tampering or truncation.
pub fn decrypt_stream(key: &[u8; 32], mut r: impl Read, mut w: impl Write) -> io::Result<Sealed> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| io::Error::other("bad key"))?;
    let mut hdr = [0u8; 16];
    if read_full(&mut r, &mut hdr)? != 16 || &hdr[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a Kestrel vault file",
        ));
    }
    let chunk = u32::from_le_bytes(hdr[4..8].try_into().unwrap()) as usize;
    if chunk == 0 || chunk > 64 << 20 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"));
    }
    let prefix: [u8; 8] = hdr[8..16].try_into().unwrap();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut cur = vec![0u8; chunk + TAG];
    let mut next = vec![0u8; chunk + TAG];
    let mut cur_len = read_full(&mut r, &mut cur)?;
    let mut index = 0u64;
    loop {
        if cur_len < TAG {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated vault file",
            ));
        }
        let next_len = if cur_len == chunk + TAG {
            read_full(&mut r, &mut next)?
        } else {
            0
        };
        let last = next_len == 0;
        let n = nonce(&prefix, index)?;
        let pt = cipher
            .decrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &cur[..cur_len],
                    aad: &aad(index, last),
                },
            )
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "vault authentication failed")
            })?;
        hasher.update(&pt);
        total += pt.len() as u64;
        w.write_all(&pt)?;
        if last {
            break;
        }
        std::mem::swap(&mut cur, &mut next);
        cur_len = next_len;
        index += 1;
    }
    w.flush()?;
    Ok(Sealed {
        plaintext_len: total,
        sha256: hex(&hasher.finalize()),
    })
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_stream(mut r: impl Read) -> io::Result<(String, u64)> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&h.finalize()), total))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    Held,
    Restored,
    Deleted,
}

/// What a vault entry holds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryKind {
    /// A quarantined file (restorable with `RestoreFile`).
    #[default]
    File,
    /// A `RemoveAutorun` backup (JSON [`crate::autorun_plan::AutorunBackup`]);
    /// `original_path` is a label, never a filesystem path, so `RestoreFile`
    /// refuses it.
    AutorunBackup,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    /// Original security descriptor (owner, group, DACL) in SDDL.
    #[serde(default)]
    pub acl_sddl: Option<String>,
    /// Original file attributes.
    #[serde(default)]
    pub attributes: u32,
    pub created_at: i64,
    pub state: EntryState,
    /// Notes, e.g. "original could not be deleted (in use); renamed and scheduled for deletion at reboot".
    #[serde(default)]
    pub note: String,
    /// Owner SID of the parent directory at quarantine time; a restore
    /// requires the same owner class (H8).
    #[serde(default)]
    pub parent_owner: Option<String>,
    #[serde(default)]
    pub kind: EntryKind,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QuarantineIndex {
    pub entries: Vec<QuarantineEntry>,
}

impl QuarantineIndex {
    pub fn get(&self, id: &str) -> Option<&QuarantineEntry> {
        self.entries.iter().find(|e| e.id == id)
    }
    pub fn get_mut(&mut self, id: &str) -> Option<&mut QuarantineEntry> {
        self.entries.iter_mut().find(|e| e.id == id)
    }
    /// A held entry with the same hash and path (re-quarantine is a no-op).
    pub fn find_held(&self, path: &str, sha256: &str) -> Option<&QuarantineEntry> {
        self.entries.iter().find(|e| {
            e.state == EntryState::Held
                && e.kind == EntryKind::File
                && e.sha256.eq_ignore_ascii_case(sha256)
                && e.original_path.eq_ignore_ascii_case(path)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(len: usize) {
        let key = [7u8; 32];
        let data: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let mut sealed = Vec::new();
        let s = encrypt_stream(&key, [1; 8], &data[..], &mut sealed).unwrap();
        assert_eq!(s.plaintext_len, len as u64);
        assert_eq!(s.sha256, sha256_stream(&data[..]).unwrap().0);
        if len > 0 {
            assert_ne!(&sealed[16..16 + len.min(32)], &data[..len.min(32)]);
        }
        let mut out = Vec::new();
        let d = decrypt_stream(&key, &sealed[..], &mut out).unwrap();
        assert_eq!(out, data);
        assert_eq!(d.sha256, s.sha256);
    }

    #[test]
    fn roundtrips() {
        for len in [
            0,
            1,
            1000,
            CHUNK - 1,
            CHUNK,
            CHUNK + 1,
            2 * CHUNK,
            2 * CHUNK + 17,
        ] {
            roundtrip(len);
        }
    }

    #[test]
    fn tamper_and_truncation() {
        let key = [9u8; 32];
        let data = vec![0x41u8; CHUNK + 100];
        let mut sealed = Vec::new();
        encrypt_stream(&key, [2; 8], &data[..], &mut sealed).unwrap();
        let mut bad = sealed.clone();
        bad[100] ^= 1;
        assert!(decrypt_stream(&key, &bad[..], std::io::sink()).is_err());
        // Drop the final chunk entirely → the first chunk is not flagged last.
        let truncated = &sealed[..16 + CHUNK + 16];
        assert!(decrypt_stream(&key, truncated, std::io::sink()).is_err());
        assert!(decrypt_stream(&[0u8; 32], &sealed[..], std::io::sink()).is_err());
        assert!(decrypt_stream(&key, &b"nope"[..], std::io::sink()).is_err());
    }

    #[test]
    fn index() {
        let mut idx = QuarantineIndex::default();
        idx.entries.push(QuarantineEntry {
            parent_owner: None,
            id: "q1".into(),
            original_path: r"C:\Users\a\Downloads\x.exe".into(),
            sha256: "AB".into(),
            size: 1,
            acl_sddl: None,
            attributes: 0,
            created_at: 0,
            state: EntryState::Held,
            note: String::new(),
            kind: EntryKind::File,
        });
        assert!(idx.find_held(r"c:\users\a\downloads\x.exe", "ab").is_some());
        idx.get_mut("q1").unwrap().state = EntryState::Restored;
        assert!(idx.find_held(r"c:\users\a\downloads\x.exe", "ab").is_none());
        let j = serde_json::to_string(&idx).unwrap();
        assert!(j.contains("\"restored\""));
        // Older index files (no `kind`) load as file entries.
        let old = r#"{"entries":[{"id":"q2","original_path":"C:\\x","sha256":"cd","size":1,"created_at":0,"state":"held"}]}"#;
        let mut idx: QuarantineIndex = serde_json::from_str(old).unwrap();
        assert_eq!(idx.get("q2").unwrap().kind, EntryKind::File);
        assert!(idx.find_held(r"c:\x", "CD").is_some());
        // An autorun backup is never matched as "already quarantined".
        idx.get_mut("q2").unwrap().kind = EntryKind::AutorunBackup;
        assert!(idx.find_held(r"c:\x", "CD").is_none());
    }
}
