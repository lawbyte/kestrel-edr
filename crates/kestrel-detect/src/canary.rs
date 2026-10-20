//! ST-16 canary (decoy credential store) generation and arming.
//!
//! [`canary_specs`] returns, for one user profile:
//! 1. a decoy Chromium profile directory `…\Google\Chrome\User Data\Profile NN`
//!    (NN is derived from the host name, 51-98, so it is stable per host and
//!    unlikely to collide with a real profile),
//! 2. a decoy `Login Data` in it — a valid SQLite database with a `logins`
//!    table holding fake entries (so a stealer proceeds and uploads fakes),
//! 3. a decoy MetaMask wallet-extension LevelDB folder
//!    (`Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn`) with
//!    `CURRENT`, `LOCK`, `LOG`, `MANIFEST-000001` and `000003.log` holding a
//!    fake encrypted vault,
//! 4. **last**, a decoy `.aws\credentials` with a fake access key.
//!
//! Specs are ordered so a directory precedes its files.
//!
//! **Agent contract** (no field for this exists in `CanarySpec`, see report):
//! * never overwrite an existing path — skip any spec whose path exists;
//! * plant the `.aws\credentials` decoy **only if the real file does not exist**
//!   ([`is_conditional_canary`] tells which specs are conditional).
//!
//! Arming for ST-16: the Chrome decoy profile is armed as soon as the specs
//! are generated (its name is unlikely to collide; if the agent skips it
//! because it exists it should call `Engine::disarm_canary`). The
//! `.aws\credentials` decoy is armed only when the agent confirms it planted it
//! (`Engine::arm_canary`) or when the engine sees the agent's own process
//! create/write that file; it is disarmed again when any other process writes
//! to it (the user configured real credentials).
//!
//! Processes that never trip ST-16: the Kestrel agent itself, PID 0/4 and the
//! readers in [`crate::paths::CANARY_IGNORED_READERS`] (Windows Search
//! indexer and Microsoft Defender, which read everything) when they are not
//! unsigned / running from a user-writable path.

use crate::util::driveless;
use crate::CanarySpec;
use kestrel_common::DataCategory;

/// MetaMask extension id used for the decoy wallet folder.
pub const DECOY_WALLET_EXTENSION: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";

/// FNV-1a 64.
pub(crate) fn fnv64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Deterministic pseudo-random byte stream (xorshift64*), seeded per host.
struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
    fn alnum(&mut self, n: usize, alphabet: &[u8]) -> String {
        (0..n)
            .map(|_| alphabet[(self.next() % alphabet.len() as u64) as usize] as char)
            .collect()
    }
}

const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const UPPER_ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SECRET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+";

/// Decoy Chrome profile directory name for a host.
pub fn decoy_profile_name(hostname: &str) -> String {
    format!(
        "Profile {}",
        51 + fnv64(&hostname.to_ascii_lowercase()) % 48
    )
}

fn join(base: &str, rel: &str) -> String {
    let sep = if base.contains('/') && !base.contains('\\') {
        '/'
    } else {
        '\\'
    };
    let b = base.trim_end_matches(['\\', '/']);
    let r = if sep == '/' {
        rel.replace('\\', "/")
    } else {
        rel.to_string()
    };
    format!("{b}{sep}{r}")
}

/// Is this spec conditional (plant only if the real file does not exist)?
pub fn is_conditional_canary(path: &str) -> bool {
    let d = driveless(path);
    d.ends_with(r"\.aws\credentials")
}

/// Generate decoy specs for a user profile.
pub fn canary_specs(hostname: &str, user_profile: &str) -> Vec<CanarySpec> {
    let mut rng = Prng(
        fnv64(&format!(
            "{}|{}",
            hostname.to_ascii_lowercase(),
            driveless(user_profile)
        )) | 1,
    );
    let profile_dir = join(
        user_profile,
        &format!(
            r"AppData\Local\Google\Chrome\User Data\{}",
            decoy_profile_name(hostname)
        ),
    );
    let ext_dir = join(
        &profile_dir,
        &format!(r"Local Extension Settings\{DECOY_WALLET_EXTENSION}"),
    );
    let user = user_profile
        .trim_end_matches(['\\', '/'])
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or("user")
        .to_string();

    let mut v = vec![
        CanarySpec { path: profile_dir.clone(), category: DataCategory::BrowserPasswords, content: vec![], is_dir: true },
        CanarySpec {
            path: join(&profile_dir, "Login Data"),
            category: DataCategory::BrowserPasswords,
            content: login_data_sqlite(&mut rng, &user),
            is_dir: false,
        },
        CanarySpec { path: join(&profile_dir, "Local Extension Settings"), category: DataCategory::CryptoWallet, content: vec![], is_dir: true },
        CanarySpec { path: ext_dir.clone(), category: DataCategory::CryptoWallet, content: vec![], is_dir: true },
        CanarySpec { path: join(&ext_dir, "CURRENT"), category: DataCategory::CryptoWallet, content: b"MANIFEST-000001\n".to_vec(), is_dir: false },
        CanarySpec { path: join(&ext_dir, "LOCK"), category: DataCategory::CryptoWallet, content: vec![], is_dir: false },
        CanarySpec {
            path: join(&ext_dir, "LOG"),
            category: DataCategory::CryptoWallet,
            content: b"2026/03/02-09:14:51.207 3a1c Reusing MANIFEST C:\\LevelDB\\MANIFEST-000001\n2026/03/02-09:14:51.208 3a1c Recovering log #3\n2026/03/02-09:14:51.211 3a1c Reusing old log 000003.log\n".to_vec(),
            is_dir: false,
        },
        CanarySpec { path: join(&ext_dir, "MANIFEST-000001"), category: DataCategory::CryptoWallet, content: leveldb_manifest(), is_dir: false },
        CanarySpec { path: join(&ext_dir, "000003.log"), category: DataCategory::CryptoWallet, content: metamask_log(&mut rng), is_dir: false },
    ];
    // Conditional decoy: only when the real file does not exist (agent checks).
    let key_id = format!("AKIA{}", rng.alnum(16, UPPER_ALNUM));
    let secret = rng.alnum(40, SECRET);
    v.push(CanarySpec {
        path: join(user_profile, r".aws\credentials"),
        category: DataCategory::CloudToken,
        content: format!("[default]\naws_access_key_id = {key_id}\naws_secret_access_key = {secret}\nregion = ap-southeast-1\n").into_bytes(),
        is_dir: false,
    });
    v
}

/// Paths armed immediately when specs are generated (the decoy Chrome profile directory).
pub(crate) fn immediate_arm_prefixes(specs: &[CanarySpec]) -> Vec<String> {
    specs
        .first()
        .filter(|s| s.is_dir)
        .map(|s| vec![driveless(&s.path)])
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Fake LevelDB content
// ---------------------------------------------------------------------------

fn leveldb_manifest() -> Vec<u8> {
    // A LevelDB log-format record header (checksum, length, type=FULL) + VersionEdit with comparator name.
    let mut payload = vec![0x01, 0x1a];
    payload.extend_from_slice(b"leveldb.BytewiseComparator");
    payload.extend_from_slice(&[0x02, 0x00, 0x03, 0x04, 0x04, 0x00]);
    let mut out = vec![0x56, 0xf3, 0x1c, 0x7e];
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.push(1);
    out.extend_from_slice(&payload);
    out
}

fn metamask_log(rng: &mut Prng) -> Vec<u8> {
    let data = String::from_utf8(
        rng.bytes(180)
            .iter()
            .map(|b| B64[(*b as usize) % 64])
            .collect(),
    )
    .unwrap_or_default();
    let iv = String::from_utf8(
        rng.bytes(22)
            .iter()
            .map(|b| B64[(*b as usize) % 64])
            .collect(),
    )
    .unwrap_or_default();
    let salt = String::from_utf8(
        rng.bytes(43)
            .iter()
            .map(|b| B64[(*b as usize) % 64])
            .collect(),
    )
    .unwrap_or_default();
    let value = format!(
        "{{\"KeyringController\":{{\"vault\":\"{{\\\"data\\\":\\\"{data}==\\\",\\\"iv\\\":\\\"{iv}==\\\",\\\"keyMetadata\\\":{{\\\"algorithm\\\":\\\"PBKDF2\\\",\\\"params\\\":{{\\\"iterations\\\":600000}}}},\\\"salt\\\":\\\"{salt}=\\\"}}\"}}}}"
    );
    let key = b"data";
    // LevelDB write batch: seq(8) count(4) [type=1 varint keylen key varint vallen val]
    let mut batch = Vec::new();
    batch.extend_from_slice(&7u64.to_le_bytes());
    batch.extend_from_slice(&1u32.to_le_bytes());
    batch.push(1);
    put_varint32(&mut batch, key.len() as u32);
    batch.extend_from_slice(key);
    put_varint32(&mut batch, value.len() as u32);
    batch.extend_from_slice(value.as_bytes());
    let mut out = rng.bytes(4); // fake crc
    out.extend_from_slice(&(batch.len() as u16).to_le_bytes());
    out.push(1);
    out.extend_from_slice(&batch);
    out
}

fn put_varint32(out: &mut Vec<u8>, mut v: u32) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

// ---------------------------------------------------------------------------
// Minimal valid SQLite database ("Login Data") with a logins table
// ---------------------------------------------------------------------------

enum Val<'a> {
    Int(i64),
    Text(&'a str),
    Blob(&'a [u8]),
}

fn sqlite_varint(out: &mut Vec<u8>, v: u64) {
    if v <= 0x7f {
        out.push(v as u8);
        return;
    }
    let mut tmp = Vec::new();
    let mut x = v;
    tmp.push((x & 0x7f) as u8);
    x >>= 7;
    while x > 0 {
        tmp.push(((x & 0x7f) as u8) | 0x80);
        x >>= 7;
    }
    tmp.reverse();
    out.extend_from_slice(&tmp);
}

fn record(vals: &[Val<'_>]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut body = Vec::new();
    for v in vals {
        match v {
            Val::Int(i) => {
                sqlite_varint(&mut types, 6);
                body.extend_from_slice(&i.to_be_bytes());
            }
            Val::Text(t) => {
                sqlite_varint(&mut types, 13 + 2 * t.len() as u64);
                body.extend_from_slice(t.as_bytes());
            }
            Val::Blob(b) => {
                sqlite_varint(&mut types, 12 + 2 * b.len() as u64);
                body.extend_from_slice(b);
            }
        }
    }
    let mut hdr = Vec::new();
    // header size includes its own varint (1 byte while < 128)
    sqlite_varint(&mut hdr, (types.len() + 1) as u64);
    hdr.extend_from_slice(&types);
    hdr.extend_from_slice(&body);
    hdr
}

/// Build a table-leaf page (`page_size` bytes) with cells (rowid, record); `hdr_off` = 100 for page 1.
fn leaf_page(page_size: usize, hdr_off: usize, rows: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut page = vec![0u8; page_size];
    let mut content_start = page_size;
    let mut ptrs = Vec::new();
    for (rowid, rec) in rows {
        let mut cell = Vec::new();
        sqlite_varint(&mut cell, rec.len() as u64);
        sqlite_varint(&mut cell, *rowid);
        cell.extend_from_slice(rec);
        content_start -= cell.len();
        page[content_start..content_start + cell.len()].copy_from_slice(&cell);
        ptrs.push(content_start as u16);
    }
    page[hdr_off] = 0x0d;
    page[hdr_off + 3..hdr_off + 5].copy_from_slice(&(rows.len() as u16).to_be_bytes());
    page[hdr_off + 5..hdr_off + 7].copy_from_slice(&(content_start as u16).to_be_bytes());
    for (i, p) in ptrs.iter().enumerate() {
        let o = hdr_off + 8 + 2 * i;
        page[o..o + 2].copy_from_slice(&p.to_be_bytes());
    }
    page
}

fn login_data_sqlite(rng: &mut Prng, user: &str) -> Vec<u8> {
    const PS: usize = 4096;
    let create = "CREATE TABLE logins (origin_url VARCHAR NOT NULL, action_url VARCHAR, username_element VARCHAR, username_value VARCHAR, password_element VARCHAR, password_value BLOB, signon_realm VARCHAR NOT NULL, date_created INTEGER NOT NULL, times_used INTEGER, id INTEGER PRIMARY KEY)";
    let schema = record(&[
        Val::Text("table"),
        Val::Text("logins"),
        Val::Text("logins"),
        Val::Int(2),
        Val::Text(create),
    ]);
    let mut page1 = leaf_page(PS, 100, &[(1, schema)]);
    // Database header.
    let h = &mut page1[..100];
    h[..16].copy_from_slice(b"SQLite format 3\0");
    h[16..18].copy_from_slice(&(PS as u16).to_be_bytes());
    h[18] = 1;
    h[19] = 1;
    h[20] = 0;
    h[21] = 64;
    h[22] = 32;
    h[23] = 32;
    h[24..28].copy_from_slice(&3u32.to_be_bytes()); // change counter
    h[28..32].copy_from_slice(&2u32.to_be_bytes()); // pages
    h[40..44].copy_from_slice(&1u32.to_be_bytes()); // schema cookie
    h[44..48].copy_from_slice(&4u32.to_be_bytes()); // schema format
    h[56..60].copy_from_slice(&1u32.to_be_bytes()); // UTF-8
    h[92..96].copy_from_slice(&3u32.to_be_bytes()); // version-valid-for
    h[96..100].copy_from_slice(&3_045_001u32.to_be_bytes());

    let user_l = user.to_ascii_lowercase();
    let sites = [
        (
            "https://login.microsoftonline.com/",
            format!("{user_l}@corp-mail.com"),
        ),
        (
            "https://accounts.google.com/",
            format!("{user_l}.work@gmail.com"),
        ),
        ("https://github.com/session", user_l.clone()),
        (
            "https://www.binance.com/en/login",
            format!("{user_l}@corp-mail.com"),
        ),
    ];
    let mut rows = Vec::new();
    for (i, (url, name)) in sites.iter().enumerate() {
        let mut pw = b"v10".to_vec();
        pw.extend(rng.bytes(12 + 16 + 16)); // nonce + ciphertext + tag (AES-GCM shaped)
        let realm = url.split('/').take(3).collect::<Vec<_>>().join("/") + "/";
        let created = 13_350_000_000_000_000i64 + (rng.next() % 50_000_000_000_000) as i64;
        let rec = record(&[
            Val::Text(url),
            Val::Text(url),
            Val::Text("username"),
            Val::Text(name),
            Val::Text("password"),
            Val::Blob(&pw),
            Val::Text(&realm),
            Val::Int(created),
            Val::Int((rng.next() % 40) as i64 + 1),
            Val::Int((i + 1) as i64),
        ]);
        rows.push(((i + 1) as u64, rec));
    }
    // `id` is INTEGER PRIMARY KEY (rowid alias): SQLite stores NULL in the record; we store the
    // value too, which readers tolerate. Keep the page valid.
    let page2 = leaf_page(PS, 0, &rows);
    let mut out = page1;
    out.extend_from_slice(&page2);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_shape() {
        let v = canary_specs("FIN-LAPTOP-07", r"C:\Users\alice");
        assert_eq!(v.len(), 10);
        assert!(v[0].is_dir);
        assert!(v[0]
            .path
            .starts_with(r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Profile "));
        let login = v.iter().find(|s| s.path.ends_with("Login Data")).unwrap();
        assert!(login.content.starts_with(b"SQLite format 3\0"));
        assert_eq!(login.content.len(), 8192);
        assert!(crate::paths::classify_sensitive_path(&login.path).is_some());
        let ext = v.iter().find(|s| s.path.ends_with("000003.log")).unwrap();
        assert_eq!(
            crate::paths::classify_sensitive_path(&ext.path).map(|c| c.0),
            Some(DataCategory::CryptoWallet)
        );
        assert!(String::from_utf8_lossy(&ext.content).contains("KeyringController"));
        let aws = v.last().unwrap();
        assert!(is_conditional_canary(&aws.path));
        assert!(String::from_utf8_lossy(&aws.content).contains("aws_access_key_id = AKIA"));
        // deterministic per host
        assert_eq!(canary_specs("FIN-LAPTOP-07", r"C:\Users\alice"), v);
        // parents first
        for (i, s) in v.iter().enumerate() {
            if let Some(parent) = s.path.rsplit_once('\\').map(|p| p.0) {
                if let Some(j) = v.iter().position(|x| x.path == parent) {
                    assert!(j < i);
                }
            }
        }
    }

    #[test]
    fn sqlite_varints() {
        let mut v = Vec::new();
        sqlite_varint(&mut v, 300);
        assert_eq!(v, vec![0x82, 0x2c]);
    }
}
