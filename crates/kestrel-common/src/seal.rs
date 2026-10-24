//! Streaming authenticated encryption for data at rest (feature `seal`):
//! evidence bundles on the PC and on the server.
//!
//! Format `KSE1` (same construction as the quarantine vault `KQV1`, plus a
//! caller-chosen context bound into every chunk, e.g. the bundle id, so a
//! sealed file cannot be swapped for another one):
//!
//! * header (16 bytes): `b"KSE1"`, chunk size (u32 LE), 8-byte random nonce
//!   prefix;
//! * chunk *i*: AES-256-GCM ciphertext ‖ 16-byte tag, nonce = prefix ‖ i
//!   (u32 BE), AAD = `b"KSE1"` ‖ i (u64 BE) ‖ last-flag (u8) ‖ context.
//!   The last chunk is always flagged (possibly empty), so truncation,
//!   reordering and appending are detected.
//!
//! [`SealWriter`] and [`SealReader`] are `Write` / `Read` adapters (memory
//! stays at about two chunks), and both compute the SHA-256 of the
//! plaintext.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};

pub const MAGIC: &[u8; 4] = b"KSE1";
/// Plaintext bytes per chunk.
pub const CHUNK: usize = 1 << 20;
const TAG: usize = 16;
const HEADER: usize = 16;
/// Largest context accepted (it is part of every chunk's AAD).
pub const MAX_CONTEXT: usize = 256;

fn aad(index: u64, last: bool, ctx: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(13 + ctx.len());
    a.extend_from_slice(MAGIC);
    a.extend_from_slice(&index.to_be_bytes());
    a.push(last as u8);
    a.extend_from_slice(ctx);
    a
}

fn nonce(prefix: &[u8; 8], index: u64) -> io::Result<[u8; 12]> {
    let i: u32 = index
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sealed stream too large"))?;
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(prefix);
    n[8..].copy_from_slice(&i.to_be_bytes());
    Ok(n)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Result of sealing / opening a stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub plaintext_len: u64,
    /// SHA-256 (hex) of the plaintext.
    pub sha256: String,
}

/// Encrypting writer. Call [`SealWriter::finish`]; dropping it without
/// finishing leaves a stream without its last chunk, which never opens.
pub struct SealWriter<W: Write> {
    w: W,
    cipher: Aes256Gcm,
    prefix: [u8; 8],
    ctx: Vec<u8>,
    buf: Vec<u8>,
    index: u64,
    hasher: Sha256,
    total: u64,
}

impl<W: Write> SealWriter<W> {
    /// `nonce_prefix` must be random per stream (the caller supplies it so
    /// this crate needs no RNG); `context` is bound into every chunk.
    pub fn new(
        mut w: W,
        key: &[u8; 32],
        nonce_prefix: [u8; 8],
        context: &[u8],
    ) -> io::Result<Self> {
        if context.len() > MAX_CONTEXT {
            return Err(io::Error::other("seal context too long"));
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| io::Error::other("bad key"))?;
        w.write_all(MAGIC)?;
        w.write_all(&(CHUNK as u32).to_le_bytes())?;
        w.write_all(&nonce_prefix)?;
        Ok(SealWriter {
            w,
            cipher,
            prefix: nonce_prefix,
            ctx: context.to_vec(),
            buf: Vec::with_capacity(CHUNK),
            index: 0,
            hasher: Sha256::new(),
            total: 0,
        })
    }

    fn seal_buf(&mut self, last: bool) -> io::Result<()> {
        let n = nonce(&self.prefix, self.index)?;
        let ct = self
            .cipher
            .encrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &self.buf,
                    aad: &aad(self.index, last, &self.ctx),
                },
            )
            .map_err(|_| io::Error::other("encryption failed"))?;
        self.w.write_all(&ct)?;
        self.buf.clear();
        self.index += 1;
        Ok(())
    }

    /// Plaintext bytes written so far.
    pub fn plaintext_len(&self) -> u64 {
        self.total
    }

    /// Seal the last chunk, flush, and return the inner writer.
    pub fn finish(mut self) -> io::Result<(W, Sealed)> {
        self.seal_buf(true)?;
        self.w.flush()?;
        let sealed = Sealed {
            plaintext_len: self.total,
            sha256: hex(&self.hasher.finalize_reset()),
        };
        Ok((self.w, sealed))
    }
}

impl<W: Write> Write for SealWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        // A full buffer is sealed as "not last" only once more data
        // arrives, so the final chunk is always the one `finish` seals.
        if self.buf.len() == CHUNK {
            self.seal_buf(false)?;
        }
        let n = data.len().min(CHUNK - self.buf.len());
        self.buf.extend_from_slice(&data[..n]);
        self.hasher.update(&data[..n]);
        self.total += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.w.flush()
    }
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

/// Decrypting reader. Every byte it returns has been authenticated; it
/// fails (`InvalidData` / `UnexpectedEof`) on tampering, truncation, a
/// wrong key or a wrong context. Data before the error was authentic.
pub struct SealReader<R: Read> {
    r: R,
    cipher: Aes256Gcm,
    prefix: [u8; 8],
    ctx: Vec<u8>,
    chunk: usize,
    /// Next ciphertext chunk read ahead (to know whether the current is last).
    next: Vec<u8>,
    next_len: usize,
    plain: Vec<u8>,
    pos: usize,
    index: u64,
    done: bool,
    hasher: Sha256,
    total: u64,
    started: bool,
}

impl<R: Read> SealReader<R> {
    pub fn new(mut r: R, key: &[u8; 32], context: &[u8]) -> io::Result<Self> {
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| io::Error::other("bad key"))?;
        let mut hdr = [0u8; HEADER];
        if read_full(&mut r, &mut hdr)? != HEADER || &hdr[..4] != MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a Kestrel sealed file",
            ));
        }
        let chunk = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]) as usize;
        if chunk == 0 || chunk > 64 << 20 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"));
        }
        let mut prefix = [0u8; 8];
        prefix.copy_from_slice(&hdr[8..16]);
        Ok(SealReader {
            r,
            cipher,
            prefix,
            ctx: context.to_vec(),
            chunk,
            next: vec![0u8; chunk + TAG],
            next_len: 0,
            plain: Vec::new(),
            pos: 0,
            index: 0,
            done: false,
            hasher: Sha256::new(),
            total: 0,
            started: false,
        })
    }

    fn open_next(&mut self) -> io::Result<()> {
        if !self.started {
            self.started = true;
            self.next_len = read_full(&mut self.r, &mut self.next)?;
        }
        let cur_len = self.next_len;
        if cur_len < TAG {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated sealed file",
            ));
        }
        let cur = std::mem::replace(&mut self.next, vec![0u8; self.chunk + TAG]);
        self.next_len = if cur_len == self.chunk + TAG {
            read_full(&mut self.r, &mut self.next)?
        } else {
            0
        };
        let last = self.next_len == 0;
        let n = nonce(&self.prefix, self.index)?;
        let pt = self
            .cipher
            .decrypt(
                Nonce::from_slice(&n),
                Payload {
                    msg: &cur[..cur_len],
                    aad: &aad(self.index, last, &self.ctx),
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sealed data failed authentication",
                )
            })?;
        self.hasher.update(&pt);
        self.total += pt.len() as u64;
        self.plain = pt;
        self.pos = 0;
        self.index += 1;
        if last {
            self.done = true;
        }
        Ok(())
    }

    /// Plaintext length and SHA-256 once the reader returned EOF (`None`
    /// before).
    pub fn sealed(&self) -> Option<Sealed> {
        (self.done && self.pos >= self.plain.len()).then(|| Sealed {
            plaintext_len: self.total,
            sha256: hex(&self.hasher.clone().finalize()),
        })
    }
}

impl<R: Read> Read for SealReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.plain.len() {
            if self.done {
                return Ok(0);
            }
            self.open_next()?;
        }
        let n = buf.len().min(self.plain.len() - self.pos);
        buf[..n].copy_from_slice(&self.plain[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Seal all of `r` into `w` (convenience).
pub fn seal_stream(
    key: &[u8; 32],
    nonce_prefix: [u8; 8],
    context: &[u8],
    mut r: impl Read,
    w: impl Write,
) -> io::Result<Sealed> {
    let mut sw = SealWriter::new(w, key, nonce_prefix, context)?;
    io::copy(&mut r, &mut sw)?;
    Ok(sw.finish()?.1)
}

/// Open all of `r` into `w` (convenience).
pub fn open_stream(
    key: &[u8; 32],
    context: &[u8],
    r: impl Read,
    mut w: impl Write,
) -> io::Result<Sealed> {
    let mut sr = SealReader::new(r, key, context)?;
    io::copy(&mut sr, &mut w)?;
    w.flush()?;
    sr.sealed()
        .ok_or_else(|| io::Error::other("sealed stream not fully read"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 31 % 251) as u8).collect()
    }

    #[test]
    fn roundtrips_at_chunk_boundaries() {
        let key = [7u8; 32];
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
            let d = data(len);
            let mut sealed = Vec::new();
            // Odd write sizes exercise the buffering.
            let mut w = SealWriter::new(&mut sealed, &key, [1; 8], b"ctx").unwrap();
            for c in d.chunks(70_001) {
                w.write_all(c).unwrap();
            }
            let (_, s) = w.finish().unwrap();
            assert_eq!(s.plaintext_len, len as u64);
            assert_eq!(s.sha256, crate::evidence::sha256_hex(&d));
            if len > 32 {
                assert_ne!(&sealed[16..48], &d[..32]);
            }
            let mut out = Vec::new();
            let o = open_stream(&key, b"ctx", &sealed[..], &mut out).unwrap();
            assert_eq!(out, d, "len {len}");
            assert_eq!(o, s);
            // Small reads.
            let mut r = SealReader::new(&sealed[..], &key, b"ctx").unwrap();
            let mut out2 = Vec::new();
            let mut b = [0u8; 4093];
            loop {
                let n = r.read(&mut b).unwrap();
                if n == 0 {
                    break;
                }
                out2.extend_from_slice(&b[..n]);
            }
            assert_eq!(out2, d);
            assert_eq!(r.sealed().unwrap(), s);
        }
    }

    #[test]
    fn tampering_truncation_key_and_context() {
        let key = [9u8; 32];
        let d = data(CHUNK + 100);
        let mut sealed = Vec::new();
        seal_stream(&key, [2; 8], b"bundle-1", &d[..], &mut sealed).unwrap();
        let open =
            |bytes: &[u8], k: &[u8; 32], ctx: &[u8]| open_stream(k, ctx, bytes, std::io::sink());
        assert!(open(&sealed, &key, b"bundle-1").is_ok());
        let mut bad = sealed.clone();
        bad[100] ^= 1;
        assert!(open(&bad, &key, b"bundle-1").is_err());
        // Last chunk dropped: the first is not flagged last.
        assert!(open(&sealed[..HEADER + CHUNK + TAG], &key, b"bundle-1").is_err());
        // Cut inside a chunk.
        assert!(open(&sealed[..sealed.len() - 5], &key, b"bundle-1").is_err());
        // Appended bytes.
        let mut long = sealed.clone();
        long.extend_from_slice(&[0u8; 40]);
        assert!(open(&long, &key, b"bundle-1").is_err());
        assert!(open(&sealed, &[0u8; 32], b"bundle-1").is_err());
        // Another bundle's context (swapped files) never opens.
        assert!(open(&sealed, &key, b"bundle-2").is_err());
        assert!(open(b"nope", &key, b"").is_err());
        assert!(SealWriter::new(Vec::new(), &key, [0; 8], &[0u8; MAX_CONTEXT + 1]).is_err());
    }

    #[test]
    fn unfinished_writer_never_opens() {
        let key = [3u8; 32];
        let mut sealed = Vec::new();
        {
            let mut w = SealWriter::new(&mut sealed, &key, [4; 8], b"").unwrap();
            w.write_all(&data(CHUNK * 2 + 5)).unwrap();
            // dropped without finish
        }
        assert!(open_stream(&key, b"", &sealed[..], std::io::sink()).is_err());
    }
}
