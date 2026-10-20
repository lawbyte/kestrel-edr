//! Minimal ZIP writer (stored entries, UTF-8 names, no ZIP64) for triage
//! packages. Triage content is small text/JSON, so compression is not worth a
//! dependency; any unzip tool and `Expand-Archive` read these files.

use std::io::{self, Write};

struct Entry {
    name: String,
    crc: u32,
    size: u32,
    offset: u32,
}

pub struct ZipWriter<W: Write> {
    w: W,
    pos: u64,
    entries: Vec<Entry>,
    dos_time: u16,
    dos_date: u16,
}

/// Unix ms → (DOS time, DOS date) in UTC.
pub fn dos_datetime(ms: i64) -> (u16, u16) {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    let year = (y - 1980).clamp(0, 127) as u16;
    let time = ((h as u16) << 11) | ((m as u16) << 5) | ((s / 2) as u16);
    let date = (year << 9) | ((mo as u16) << 5) | d as u16;
    (time, date)
}

impl<W: Write> ZipWriter<W> {
    pub fn new(w: W, now_ms: i64) -> Self {
        let (dos_time, dos_date) = dos_datetime(now_ms);
        ZipWriter {
            w,
            pos: 0,
            entries: Vec::new(),
            dos_time,
            dos_date,
        }
    }

    fn put(&mut self, b: &[u8]) -> io::Result<()> {
        self.w.write_all(b)?;
        self.pos += b.len() as u64;
        Ok(())
    }

    fn too_big() -> io::Error {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "zip entry/archive exceeds 4 GiB (no ZIP64)",
        )
    }

    pub fn add(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
        let size: u32 = data.len().try_into().map_err(|_| Self::too_big())?;
        let offset: u32 = self.pos.try_into().map_err(|_| Self::too_big())?;
        let crc = crc32fast::hash(data);
        let name_b = name.replace('\\', "/");
        let nb = name_b.as_bytes();
        let mut h = Vec::with_capacity(30 + nb.len());
        h.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        h.extend_from_slice(&20u16.to_le_bytes()); // version needed
        h.extend_from_slice(&0x0800u16.to_le_bytes()); // UTF-8 names
        h.extend_from_slice(&0u16.to_le_bytes()); // stored
        h.extend_from_slice(&self.dos_time.to_le_bytes());
        h.extend_from_slice(&self.dos_date.to_le_bytes());
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&size.to_le_bytes());
        h.extend_from_slice(&(nb.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(nb);
        self.put(&h)?;
        self.put(data)?;
        self.entries.push(Entry {
            name: name_b,
            crc,
            size,
            offset,
        });
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<W> {
        let cd_start: u32 = self.pos.try_into().map_err(|_| Self::too_big())?;
        let entries = std::mem::take(&mut self.entries);
        for e in &entries {
            let nb = e.name.as_bytes();
            let mut c = Vec::with_capacity(46 + nb.len());
            c.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
            c.extend_from_slice(&20u16.to_le_bytes()); // made by
            c.extend_from_slice(&20u16.to_le_bytes()); // needed
            c.extend_from_slice(&0x0800u16.to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes());
            c.extend_from_slice(&self.dos_time.to_le_bytes());
            c.extend_from_slice(&self.dos_date.to_le_bytes());
            c.extend_from_slice(&e.crc.to_le_bytes());
            c.extend_from_slice(&e.size.to_le_bytes());
            c.extend_from_slice(&e.size.to_le_bytes());
            c.extend_from_slice(&(nb.len() as u16).to_le_bytes());
            c.extend_from_slice(&0u16.to_le_bytes()); // extra
            c.extend_from_slice(&0u16.to_le_bytes()); // comment
            c.extend_from_slice(&0u16.to_le_bytes()); // disk
            c.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
            c.extend_from_slice(&0u32.to_le_bytes()); // external attrs
            c.extend_from_slice(&e.offset.to_le_bytes());
            c.extend_from_slice(nb);
            self.put(&c)?;
        }
        let cd_size: u32 = (self.pos - cd_start as u64)
            .try_into()
            .map_err(|_| Self::too_big())?;
        let n = entries.len() as u16;
        let mut eocd = Vec::with_capacity(22);
        eocd.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        eocd.extend_from_slice(&n.to_le_bytes());
        eocd.extend_from_slice(&n.to_le_bytes());
        eocd.extend_from_slice(&cd_size.to_le_bytes());
        eocd.extend_from_slice(&cd_start.to_le_bytes());
        eocd.extend_from_slice(&0u16.to_le_bytes());
        self.put(&eocd)?;
        self.w.flush()?;
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dos_dates() {
        // 2026-10-21 13:45:30 UTC
        let (t, d) = dos_datetime(1_792_590_330_000);
        assert_eq!(d >> 9, 2026 - 1980);
        assert_eq!((d >> 5) & 0xf, 10);
        assert_eq!(d & 0x1f, 21);
        assert_eq!(t >> 11, 13);
        assert_eq!((t >> 5) & 0x3f, 45);
        assert_eq!(t & 0x1f, 15);
    }

    #[test]
    fn structure() {
        let mut z = ZipWriter::new(Vec::new(), 1_792_590_330_000);
        z.add("processes.json", b"[]").unwrap();
        z.add("dir\\netstat.txt", b"hello").unwrap();
        let bytes = z.finish().unwrap();
        assert_eq!(&bytes[..4], &[0x50, 0x4b, 0x03, 0x04]);
        let eocd = &bytes[bytes.len() - 22..];
        assert_eq!(&eocd[..4], &[0x50, 0x4b, 0x05, 0x06]);
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 2);
        let cd_off = u32::from_le_bytes(eocd[16..20].try_into().unwrap()) as usize;
        assert_eq!(&bytes[cd_off..cd_off + 4], &[0x50, 0x4b, 0x01, 0x02]);
        // second entry name normalised to forward slashes, crc correct
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("dir/netstat.txt"));
        assert!(bytes
            .windows(4)
            .any(|w| w == crc32fast::hash(b"hello").to_le_bytes()));
    }
}
