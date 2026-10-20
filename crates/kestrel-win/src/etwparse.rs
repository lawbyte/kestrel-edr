//! Pure decoding helpers for ETW payloads (no Windows APIs).
//!
//! The ETW callback copies raw property bytes out of the record; everything
//! that interprets those bytes lives here so it can be unit-tested on Linux.

use kestrel_common::{FileOp, Integrity};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 100-ns intervals between 1601-01-01 and 1970-01-01.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

/// FILETIME (100 ns since 1601) → ms since Unix epoch. 0 → 0.
pub fn filetime_to_ms(ft: u64) -> i64 {
    if ft <= FILETIME_UNIX_EPOCH {
        return 0;
    }
    ((ft - FILETIME_UNIX_EPOCH) / 10_000) as i64
}

pub fn le_u16(b: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(..2)?.try_into().ok()?))
}
pub fn le_u32(b: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(..4)?.try_into().ok()?))
}
pub fn le_u64(b: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(..8)?.try_into().ok()?))
}
/// Pointer-sized little-endian value (4 or 8 bytes).
pub fn le_ptr(b: &[u8]) -> Option<u64> {
    match b.len() {
        4 => le_u32(b).map(u64::from),
        8 => le_u64(b),
        _ => None,
    }
}

/// UTF-16LE bytes → String, stopping at the first NUL.
pub fn utf16le(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Integrity level from a mandatory-label RID.
pub fn integrity_from_rid(rid: u32) -> Integrity {
    match rid {
        r if r < 0x1000 => Integrity::Untrusted,
        r if r < 0x2000 => Integrity::Low,
        r if r < 0x3000 => Integrity::Medium, // includes MediumPlus 0x2100
        r if r < 0x4000 => Integrity::High,
        _ => Integrity::System, // System 0x4000, Protected 0x5000
    }
}

/// Integrity from a mandatory label SID string ("S-1-16-8192").
pub fn integrity_from_label_sid(sid: &str) -> Option<Integrity> {
    let rest = sid.strip_prefix("S-1-16-")?;
    rest.parse::<u32>().ok().map(integrity_from_rid)
}

/// Kernel-Network addresses are copied from `in_addr` / `in6_addr`, i.e. in
/// network byte order; the manifest types them as UInt32 / Binary.
pub fn net_addr(raw: &[u8]) -> Option<IpAddr> {
    match raw.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::new(raw[0], raw[1], raw[2], raw[3]))),
        16 => {
            let a: [u8; 16] = raw.try_into().ok()?;
            let v6 = Ipv6Addr::from(a);
            Some(match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            })
        }
        _ => None,
    }
}

/// Kernel-Network ports are in network byte order.
pub fn net_port(raw: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(raw.get(..2)?.try_into().ok()?))
}

pub fn is_loopback(ip: &IpAddr) -> bool {
    ip.is_loopback()
}

/// Kernel-File Create: the high byte of CreateOptions is the create disposition.
pub fn file_op_from_create_options(create_options: u32) -> FileOp {
    match (create_options >> 24) & 0xff {
        1 | 3 => FileOp::Open,           // FILE_OPEN, FILE_OPEN_IF
        0 | 2 | 4 | 5 => FileOp::Create, // SUPERSEDE, CREATE, OVERWRITE, OVERWRITE_IF
        _ => FileOp::Open,
    }
}

/// Kernel-File CreateOptions has FILE_DIRECTORY_FILE (0x1) for directory opens.
pub fn is_directory_open(create_options: u32) -> bool {
    create_options & 0x0000_0001 != 0
}

// ---------------------------------------------------------------- registry

/// `\REGISTRY\MACHINE\SOFTWARE\…` → `HKLM\SOFTWARE\…`, `\REGISTRY\USER\S-…` → `HKU\S-…`.
pub fn normalize_reg_key(key: &str) -> String {
    let lower = key.to_ascii_lowercase();
    for (nt, short) in [(r"\registry\machine", "HKLM"), (r"\registry\user", "HKU")] {
        if lower.starts_with(nt) {
            return format!("{short}{}", &key[nt.len()..]);
        }
    }
    key.to_string()
}

/// Registry keys whose value writes are emitted as `RegistrySet` (ClickFix
/// artefacts, persistence, AMSI tampering, debugger hijacks). Everything else
/// is dropped at the source.
pub fn is_interesting_reg_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    const CONTAINS: &[&str] = &[
        r"\currentversion\explorer\runmru",
        r"\currentversion\explorer\typedpaths",
        r"\currentversion\policies\explorer",
        r"\microsoft\amsi",
        r"\windows nt\currentversion\image file execution options",
        r"\microsoft\windows defender\exclusions",
        r"\currentcontrolset\services\kestrelagent",
    ];
    if CONTAINS.iter().any(|c| k.contains(c)) {
        return true;
    }
    // \CurrentVersion\Run, \RunOnce, \RunOnceEx (+ WOW6432Node variants),
    // but not RunMRU-like siblings such as \CurrentVersion\RunServicesFoo.
    if let Some(i) = k.find(r"\currentversion\run") {
        let tail = &k[i + r"\currentversion\run".len()..];
        let tail = tail.split('\\').next().unwrap_or("");
        return matches!(tail, "" | "once" | "onceex" | "services" | "servicesonce");
    }
    false
}

pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_QWORD: u32 = 11;

/// Render captured registry data for the `RegistrySet.data` field.
pub fn render_reg_data(ty: u32, data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }
    Some(match ty {
        REG_SZ | REG_EXPAND_SZ => utf16le(data),
        REG_MULTI_SZ => {
            let units: Vec<u16> = data
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            units
                .split(|&u| u == 0)
                .filter(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect::<Vec<_>>()
                .join("\n")
        }
        REG_DWORD => le_u32(data)?.to_string(),
        REG_QWORD => le_u64(data)?.to_string(),
        _ => {
            let n = data.len().min(256);
            let mut s: String = data[..n].iter().map(|b| format!("{b:02x}")).collect();
            if data.len() > n {
                s.push('…');
            }
            s
        }
    })
}

// ---------------------------------------------------------------- DNS

/// DNS-Client 3008 `QueryResults`: `"type:  5 cname.example;::ffff:1.2.3.4;2606:…;"`.
/// Returns the IP answers (IPv4-mapped addresses unwrapped).
pub fn parse_dns_results(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in s.split(';') {
        let p = part.trim();
        if p.is_empty() || p.starts_with("type:") {
            continue;
        }
        if let Ok(ip) = p.parse::<IpAddr>() {
            let ip = match ip {
                IpAddr::V6(v6) => v6
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(v6)),
                v4 => v4,
            };
            let s = ip.to_string();
            if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- process access

pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;

/// Process-handle rights worth reporting (read/write memory, inject, dup
/// handles, suspend). Pure query/synchronize opens are dropped at the source.
pub fn is_interesting_process_access(mask: u32) -> bool {
    mask & (PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE
        | PROCESS_DUP_HANDLE
        | PROCESS_SET_INFORMATION
        | PROCESS_SUSPEND_RESUME)
        != 0
}

/// Thread-handle rights that precede NtSetContextThread / APC injection.
pub fn is_interesting_thread_access(mask: u32) -> bool {
    mask & (THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME) != 0
}

/// Sysmon renders GrantedAccess as "0x1410".
pub fn parse_hex_u32(s: &str) -> Option<u32> {
    let t = s.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    u32::from_str_radix(t, 16).ok()
}

// ---------------------------------------------------------------- network flows

/// Upload-size thresholds at which a flow re-reports `bytes_sent`.
pub const SEND_THRESHOLDS: [u64; 4] = [1024, 64 * 1024, 1024 * 1024, 16 * 1024 * 1024];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub pid: u32,
    /// true = TCP, false = UDP (`NetProto` is not `Hash`).
    pub tcp: bool,
    pub dst: IpAddr,
    pub dport: u16,
    /// 0 for UDP (UDP flows are keyed per destination, not per socket).
    pub sport: u16,
}

#[derive(Debug, Clone)]
struct Flow {
    bytes: u64,
    next_threshold: usize,
    last_ms: i64,
}

/// What the network translator should emit for a raw Kernel-Network event.
#[derive(Debug, Clone, PartialEq)]
pub enum FlowEmit {
    /// New connection / first datagram: emit `NetConnect` with this byte count (None for TCP connect).
    New(Option<u64>),
    /// Existing flow crossed an upload threshold: emit `NetConnect` with the running total.
    Update(u64),
    Nothing,
}

/// Bounded per-flow byte accounting so `bytes_sent` can be reported without
/// emitting one event per send.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    max: usize,
    idle_ms: i64,
}

impl FlowTable {
    pub fn new(max: usize, idle_ms: i64) -> Self {
        FlowTable {
            flows: HashMap::new(),
            max,
            idle_ms,
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn make_room(&mut self, now: i64) {
        if self.flows.len() < self.max {
            return;
        }
        let idle = self.idle_ms;
        self.flows.retain(|_, f| now - f.last_ms < idle);
        if self.flows.len() >= self.max {
            // Still full: drop the oldest half.
            let mut ages: Vec<i64> = self.flows.values().map(|f| f.last_ms).collect();
            ages.sort_unstable();
            let cut = ages[ages.len() / 2];
            self.flows.retain(|_, f| f.last_ms > cut);
        }
    }

    pub fn on_connect(&mut self, key: FlowKey, now: i64) -> FlowEmit {
        self.make_room(now);
        self.flows.insert(
            key,
            Flow {
                bytes: 0,
                next_threshold: 0,
                last_ms: now,
            },
        );
        FlowEmit::New(None)
    }

    pub fn on_send(&mut self, key: FlowKey, size: u64, now: i64) -> FlowEmit {
        if let Some(f) = self.flows.get_mut(&key) {
            f.bytes = f.bytes.saturating_add(size);
            f.last_ms = now;
            let mut crossed = false;
            while f.next_threshold < SEND_THRESHOLDS.len()
                && f.bytes >= SEND_THRESHOLDS[f.next_threshold]
            {
                f.next_threshold += 1;
                crossed = true;
            }
            return if crossed {
                FlowEmit::Update(f.bytes)
            } else {
                FlowEmit::Nothing
            };
        }
        // Unknown flow (started before the sensor, or connect event lost; or UDP).
        self.make_room(now);
        let mut f = Flow {
            bytes: size,
            next_threshold: 0,
            last_ms: now,
        };
        while f.next_threshold < SEND_THRESHOLDS.len()
            && f.bytes >= SEND_THRESHOLDS[f.next_threshold]
        {
            f.next_threshold += 1;
        }
        self.flows.insert(key, f);
        FlowEmit::New(Some(size))
    }

    pub fn on_close(&mut self, key: &FlowKey) {
        self.flows.remove(key);
    }

    /// Forget all flows of an exited process.
    pub fn forget_pid(&mut self, pid: u32) {
        self.flows.retain(|k, _| k.pid != pid);
    }

    pub fn expire(&mut self, now: i64) {
        let idle = self.idle_ms;
        self.flows.retain(|_, f| now - f.last_ms < idle);
    }
}

// ---------------------------------------------------------------- MOTW

/// `Zone.Identifier` stream → ZoneId.
pub fn parse_zone_identifier(s: &str) -> Option<u8> {
    for line in s.lines() {
        let l = line.trim();
        if let Some(v) = l
            .strip_prefix("ZoneId=")
            .or_else(|| l.strip_prefix("ZoneID="))
        {
            return v.trim().parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime() {
        assert_eq!(filetime_to_ms(0), 0);
        // 2024-04-01T00:00:00Z = 1711929600000 ms
        let ft = FILETIME_UNIX_EPOCH + 1_711_929_600_000 * 10_000;
        assert_eq!(filetime_to_ms(ft), 1_711_929_600_000);
        // Google's sample CallerProcessCreationTime 133561300019253302 → 2024-04-01
        let ms = filetime_to_ms(133_561_300_019_253_302);
        assert!(ms > 1_711_000_000_000 && ms < 1_712_500_000_000);
    }

    #[test]
    fn integrity() {
        assert_eq!(
            integrity_from_label_sid("S-1-16-8192"),
            Some(Integrity::Medium)
        );
        assert_eq!(
            integrity_from_label_sid("S-1-16-8448"),
            Some(Integrity::Medium)
        );
        assert_eq!(
            integrity_from_label_sid("S-1-16-12288"),
            Some(Integrity::High)
        );
        assert_eq!(
            integrity_from_label_sid("S-1-16-16384"),
            Some(Integrity::System)
        );
        assert_eq!(
            integrity_from_label_sid("S-1-16-4096"),
            Some(Integrity::Low)
        );
        assert_eq!(
            integrity_from_label_sid("S-1-16-0"),
            Some(Integrity::Untrusted)
        );
        assert_eq!(integrity_from_label_sid("S-1-5-18"), None);
    }

    #[test]
    fn net_decoding() {
        assert_eq!(
            net_addr(&[93, 184, 216, 34]).unwrap().to_string(),
            "93.184.216.34"
        );
        let mut v6 = [0u8; 16];
        v6[10] = 0xff;
        v6[11] = 0xff;
        v6[12..].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(net_addr(&v6).unwrap().to_string(), "1.2.3.4");
        assert_eq!(net_port(&[0x01, 0xbb]), Some(443));
        assert_eq!(net_addr(&[1, 2, 3]), None);
    }

    #[test]
    fn file_ops() {
        assert_eq!(file_op_from_create_options(0x0100_0020), FileOp::Open);
        assert_eq!(file_op_from_create_options(0x0500_0060), FileOp::Create);
        assert_eq!(file_op_from_create_options(0x0300_0000), FileOp::Open);
        assert!(is_directory_open(0x0100_0001));
    }

    #[test]
    fn reg_keys() {
        let k = normalize_reg_key(
            r"\REGISTRY\USER\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
        );
        assert_eq!(
            k,
            r"HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
        );
        assert!(is_interesting_reg_key(&k));
        assert!(is_interesting_reg_key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        ));
        assert!(is_interesting_reg_key(
            r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
        ));
        assert!(is_interesting_reg_key(
            r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
        ));
        assert!(is_interesting_reg_key(
            r"HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}"
        ));
        assert!(is_interesting_reg_key(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\chrome.exe"
        ));
        assert!(is_interesting_reg_key(
            r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        ));
        assert!(!is_interesting_reg_key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Runtime"
        ));
        assert!(!is_interesting_reg_key(
            r"HKU\S-1\Software\Google\Chrome\PreferenceMACs"
        ));
    }

    #[test]
    fn reg_data() {
        let s: Vec<u8> = "powershell -w h iex\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(render_reg_data(REG_SZ, &s).unwrap(), "powershell -w h iex");
        assert_eq!(
            render_reg_data(REG_DWORD, &1u32.to_le_bytes()).unwrap(),
            "1"
        );
        let m: Vec<u8> = "a\0b\0\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(render_reg_data(REG_MULTI_SZ, &m).unwrap(), "a\nb");
        assert_eq!(render_reg_data(REG_BINARY, &[0xde, 0xad]).unwrap(), "dead");
        assert_eq!(render_reg_data(REG_SZ, &[]), None);
    }

    #[test]
    fn dns() {
        let r = parse_dns_results("type:  5 edge.example.net;::ffff:93.184.216.34;2606:2800:220:1::248;::ffff:93.184.216.34;");
        assert_eq!(
            r,
            vec![
                "93.184.216.34".to_string(),
                "2606:2800:220:1::248".to_string()
            ]
        );
        assert!(parse_dns_results("").is_empty());
    }

    #[test]
    fn access_masks() {
        assert!(is_interesting_process_access(0x1410));
        assert!(is_interesting_process_access(0x143a));
        assert!(!is_interesting_process_access(0x1000));
        assert!(!is_interesting_process_access(0x100000 | 0x1000 | 0x400));
        assert_eq!(parse_hex_u32("0x1FFFFF"), Some(0x1fffff));
        assert!(is_interesting_thread_access(0x1fffff));
    }

    #[test]
    fn flows() {
        let mut t = FlowTable::new(4, 60_000);
        let k = FlowKey {
            pid: 1,
            tcp: true,
            dst: "1.2.3.4".parse().unwrap(),
            dport: 443,
            sport: 5000,
        };
        assert_eq!(t.on_connect(k.clone(), 0), FlowEmit::New(None));
        assert_eq!(t.on_send(k.clone(), 500, 1), FlowEmit::Nothing);
        assert_eq!(t.on_send(k.clone(), 600, 2), FlowEmit::Update(1100));
        assert_eq!(t.on_send(k.clone(), 10, 3), FlowEmit::Nothing);
        assert_eq!(
            t.on_send(k.clone(), 2_000_000, 4),
            FlowEmit::Update(2_001_110)
        );
        let u = FlowKey {
            pid: 2,
            tcp: false,
            dst: "8.8.8.8".parse().unwrap(),
            dport: 53,
            sport: 0,
        };
        assert_eq!(t.on_send(u.clone(), 40, 5), FlowEmit::New(Some(40)));
        assert_eq!(t.on_send(u.clone(), 40, 6), FlowEmit::Nothing);
        for i in 0..10 {
            let kk = FlowKey {
                pid: 10 + i,
                ..k.clone()
            };
            t.on_connect(kk, 100_000 + i as i64);
        }
        assert!(t.len() <= 4);
        t.forget_pid(1);
        t.expire(1_000_000);
        assert!(t.is_empty());
    }

    #[test]
    fn motw() {
        assert_eq!(
            parse_zone_identifier("[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl=https://x\r\n"),
            Some(3)
        );
        assert_eq!(parse_zone_identifier("[ZoneTransfer]\nHostUrl=x"), None);
    }

    #[test]
    fn utf16() {
        let b: Vec<u8> = "abc\0zzz"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        assert_eq!(utf16le(&b), "abc");
        assert_eq!(le_ptr(&[1, 0, 0, 0]), Some(1));
        assert_eq!(
            le_ptr(&[1, 0, 0, 0, 0, 0, 0, 1]),
            Some(0x0100_0000_0000_0001)
        );
    }
}
