//! Minimal DNS stub resolver over UDP (A / AAAA), used while the host is
//! isolated (H10).
//!
//! Isolation permits DNS to the adapters' resolvers **only for the agent
//! executable** (WFP app-id condition, see [`crate::wfp_plan::plan_isolation`]).
//! `getaddrinfo` on Windows is answered by the DNS Client service
//! (`Dnscache`, an svchost.exe), whose packets do not carry the agent's app
//! id, so while isolated the agent sends its own queries from its own
//! process with this module. Nothing else on the host can resolve names
//! while isolated — that is intended: DNS to an attacker-controlled
//! authoritative server is a classic tunnel out of an isolated host.
//!
//! Hardening of the parser: response id, QR bit, opcode, RCODE and the echoed
//! question (name, type, class) must match; the source address must be the
//! queried server; compression pointers are bounded; only the answer
//! section's A/AAAA records of class IN are used (CNAME chains are followed
//! implicitly because recursive resolvers include the target records).
//! A spoofed answer can at worst add an address that only the agent may
//! reach, and the agent's TLS still pins the Kestrel CA.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_PTR_JUMPS: usize = 16;

/// Encode `name` as DNS labels (validated: 1-63 bytes per label, ≤ 253 total).
fn encode_name(name: &str) -> Result<Vec<u8>, String> {
    let n = name.trim().trim_end_matches('.');
    if n.is_empty() || n.len() > 253 {
        return Err(format!("invalid DNS name {name:?}"));
    }
    let mut out = Vec::with_capacity(n.len() + 2);
    for label in n.split('.') {
        let b = label.as_bytes();
        if b.is_empty()
            || b.len() > 63
            || !b
                .iter()
                .all(|c| c.is_ascii_alphanumeric() || *c == b'-' || *c == b'_')
        {
            return Err(format!("invalid DNS name {name:?}"));
        }
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0);
    Ok(out)
}

/// Build a recursive query for (`name`, `qtype`).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    q.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    q.extend(encode_name(name)?);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(q)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

/// Read a (possibly compressed) name starting at `pos`; returns (lower-case
/// dotted name, position after the name in the original stream).
fn read_name(b: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    let mut jumps = 0;
    loop {
        let len = *b.get(pos)? as usize;
        if len & 0xC0 == 0xC0 {
            let ptr = (u16_at(b, pos)? & 0x3FFF) as usize;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > MAX_PTR_JUMPS || ptr >= b.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        if len == 0 {
            let after = end.unwrap_or(pos + 1);
            return Some((labels.join("."), after));
        }
        let l = b.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(l).to_ascii_lowercase());
        if labels.len() > 128 {
            return None;
        }
        pos += 1 + len;
    }
}

/// Parse a response to the query built by [`build_query`].
pub fn parse_response(b: &[u8], id: u16, name: &str, qtype: u16) -> Result<Vec<IpAddr>, String> {
    if b.len() < 12 {
        return Err("short DNS response".into());
    }
    if u16_at(b, 0) != Some(id) {
        return Err("DNS id mismatch".into());
    }
    let flags = u16_at(b, 2).unwrap_or(0);
    if flags & 0x8000 == 0 || (flags >> 11) & 0xF != 0 {
        return Err("not a standard DNS response".into());
    }
    if flags & 0x0200 != 0 {
        return Err("truncated DNS response".into());
    }
    let rcode = flags & 0xF;
    if rcode != 0 {
        return Err(format!("DNS rcode {rcode}"));
    }
    let qd = u16_at(b, 4).unwrap_or(0);
    let an = u16_at(b, 6).unwrap_or(0) as usize;
    if qd != 1 {
        return Err("unexpected question count".into());
    }
    let want = name.trim().trim_end_matches('.').to_ascii_lowercase();
    let (qname, mut pos) = read_name(b, 12).ok_or("bad question name")?;
    if qname != want || u16_at(b, pos) != Some(qtype) || u16_at(b, pos + 2) != Some(CLASS_IN) {
        return Err("DNS question mismatch".into());
    }
    pos += 4;
    let mut out = Vec::new();
    for _ in 0..an.min(64) {
        let (_, p) = read_name(b, pos).ok_or("bad answer name")?;
        let ty = u16_at(b, p).ok_or("truncated answer")?;
        let class = u16_at(b, p + 2).ok_or("truncated answer")?;
        let rdlen = u16_at(b, p + 8).ok_or("truncated answer")? as usize;
        let rd = b.get(p + 10..p + 10 + rdlen).ok_or("truncated rdata")?;
        if class == CLASS_IN && ty == qtype {
            match (ty, rd.len()) {
                (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(rd[0], rd[1], rd[2], rd[3]))),
                (TYPE_AAAA, 16) => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(rd);
                    out.push(IpAddr::V6(Ipv6Addr::from(a)));
                }
                _ => {}
            }
        }
        pos = p + 10 + rdlen;
    }
    Ok(out)
}

fn query_one(dest: SocketAddr, name: &str, qtype: u16, timeout: Duration) -> Vec<IpAddr> {
    let bind: SocketAddr = if dest.is_ipv4() {
        "0.0.0.0:0".parse().expect("static addr")
    } else {
        "[::]:0".parse().expect("static addr")
    };
    let Ok(sock) = UdpSocket::bind(bind) else {
        return vec![];
    };
    let mut idb = [0u8; 2];
    if getrandom::getrandom(&mut idb).is_err() {
        return vec![];
    }
    let id = u16::from_be_bytes(idb);
    let Ok(q) = build_query(id, name, qtype) else {
        return vec![];
    };
    if sock.send_to(&q, dest).is_err() {
        return vec![];
    }
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 1500];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() || sock.set_read_timeout(Some(left)).is_err() {
            return vec![];
        }
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if from == dest => {
                match parse_response(&buf[..n], id, name, qtype) {
                    Ok(v) => return v,
                    // A mismatched (spoofed / stale) packet: keep waiting.
                    Err(_) => continue,
                }
            }
            Ok(_) => continue,
            Err(_) => return vec![],
        }
    }
}

/// Resolve `name` (A then AAAA) against `servers` directly from this process.
/// IP literals are returned as-is. At most `cap` addresses.
pub fn resolve_via(name: &str, servers: &[IpAddr], timeout: Duration, cap: usize) -> Vec<IpAddr> {
    let dests: Vec<SocketAddr> = servers.iter().map(|s| SocketAddr::new(*s, 53)).collect();
    resolve_at(name, &dests, timeout, cap)
}

fn resolve_at(name: &str, servers: &[SocketAddr], timeout: Duration, cap: usize) -> Vec<IpAddr> {
    if let Ok(ip) = name.trim().parse::<IpAddr>() {
        return vec![ip];
    }
    if encode_name(name).is_err() {
        return vec![];
    }
    let mut out: Vec<IpAddr> = Vec::new();
    for qtype in [TYPE_A, TYPE_AAAA] {
        for s in servers.iter().take(4) {
            let r = query_one(*s, name, qtype, timeout);
            if !r.is_empty() {
                for ip in r {
                    if !out.contains(&ip) && out.len() < cap {
                        out.push(ip);
                    }
                }
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(id: u16, name: &str, qtype: u16, rdata: &[&[u8]], flags: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&id.to_be_bytes());
        b.extend_from_slice(&flags.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&(rdata.len() as u16 + 1).to_be_bytes());
        b.extend_from_slice(&[0, 0, 0, 0]);
        b.extend(encode_name(name).unwrap());
        b.extend_from_slice(&qtype.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        // CNAME first (pointer to the question name), then the records.
        b.extend_from_slice(&[0xC0, 12]);
        b.extend_from_slice(&5u16.to_be_bytes());
        b.extend_from_slice(&1u16.to_be_bytes());
        b.extend_from_slice(&60u32.to_be_bytes());
        let target = encode_name("edge.example.net").unwrap();
        b.extend_from_slice(&(target.len() as u16).to_be_bytes());
        let target_pos = b.len();
        b.extend(target);
        for rd in rdata {
            b.extend_from_slice(&[0xC0, target_pos as u8]);
            b.extend_from_slice(&qtype.to_be_bytes());
            b.extend_from_slice(&1u16.to_be_bytes());
            b.extend_from_slice(&60u32.to_be_bytes());
            b.extend_from_slice(&(rd.len() as u16).to_be_bytes());
            b.extend_from_slice(rd);
        }
        b
    }

    #[test]
    fn query_encoding() {
        let q = build_query(0x1234, "edr.Example.com.", TYPE_A).unwrap();
        assert_eq!(&q[..2], &[0x12, 0x34]);
        assert_eq!(&q[12..17], &[3, b'e', b'd', b'r', 7]);
        assert!(build_query(1, "", TYPE_A).is_err());
        assert!(build_query(1, "a..b", TYPE_A).is_err());
        assert!(build_query(1, &"a".repeat(64), TYPE_A).is_err());
        assert!(build_query(1, "evil\".com", TYPE_A).is_err());
    }

    #[test]
    fn responses() {
        let r = answer(
            7,
            "edr.example.com",
            TYPE_A,
            &[&[10, 0, 0, 5], &[10, 0, 0, 6]],
            0x8180,
        );
        assert_eq!(
            parse_response(&r, 7, "EDR.example.com", TYPE_A).unwrap(),
            vec![
                "10.0.0.5".parse::<IpAddr>().unwrap(),
                "10.0.0.6".parse().unwrap()
            ]
        );
        let v6 = [0xfdu8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        let r6 = answer(9, "edr.example.com", TYPE_AAAA, &[&v6], 0x8180);
        assert_eq!(
            parse_response(&r6, 9, "edr.example.com", TYPE_AAAA).unwrap(),
            vec!["fd00::5".parse::<IpAddr>().unwrap()]
        );
        // id / question / type mismatches, errors, truncation
        assert!(parse_response(&r, 8, "edr.example.com", TYPE_A).is_err());
        assert!(parse_response(&r, 7, "other.example.com", TYPE_A).is_err());
        assert!(parse_response(&r, 7, "edr.example.com", TYPE_AAAA).is_err());
        let nx = answer(7, "edr.example.com", TYPE_A, &[], 0x8183);
        assert!(parse_response(&nx, 7, "edr.example.com", TYPE_A).is_err());
        let tc = answer(7, "edr.example.com", TYPE_A, &[], 0x8380);
        assert!(parse_response(&tc, 7, "edr.example.com", TYPE_A).is_err());
        let query = build_query(7, "edr.example.com", TYPE_A).unwrap();
        assert!(parse_response(&query, 7, "edr.example.com", TYPE_A).is_err());
        for cut in 0..r.len() {
            let _ = parse_response(&r[..cut], 7, "edr.example.com", TYPE_A);
        }
        // pointer loop does not hang
        let mut lp = r.clone();
        let n = lp.len();
        lp[n - 16] = 0xC0;
        lp[n - 15] = (n - 16) as u8;
        let _ = parse_response(&lp, 7, "edr.example.com", TYPE_A);
        assert!(read_name(&[0xC0, 0], 0).is_none());
    }

    #[test]
    fn resolves_against_local_server() {
        let srv = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = srv.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let (n, from) = srv.recv_from(&mut buf).unwrap();
                let id = u16_at(&buf[..n], 0).unwrap();
                let qtype = u16_at(&buf[..n], n - 4).unwrap();
                // A spoofed reply from another socket is ignored first.
                let spoof = UdpSocket::bind("127.0.0.1:0").unwrap();
                let bad = answer(id, "edr.example.com", qtype, &[&[6, 6, 6, 6]], 0x8180);
                spoof.send_to(&bad, from).unwrap();
                // A wrong-id reply from the server is ignored too.
                let wrong = answer(id ^ 1, "edr.example.com", qtype, &[&[7, 7, 7, 7]], 0x8180);
                srv.send_to(&wrong, from).unwrap();
                let reply = if qtype == TYPE_A {
                    answer(id, "edr.example.com", TYPE_A, &[&[192, 0, 2, 1]], 0x8180)
                } else {
                    answer(id, "edr.example.com", TYPE_AAAA, &[], 0x8180)
                };
                srv.send_to(&reply, from).unwrap();
            }
        });
        let got = resolve_at("edr.example.com", &[addr], Duration::from_secs(3), 8);
        t.join().unwrap();
        assert_eq!(got, vec!["192.0.2.1".parse::<IpAddr>().unwrap()]);
        // unreachable server → empty, bounded by the timeout
        let dead = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let t0 = Instant::now();
        assert!(resolve_at(
            "edr.example.com",
            &[dead_addr],
            Duration::from_millis(200),
            8
        )
        .is_empty());
        assert!(t0.elapsed() < Duration::from_secs(3));
        // literals short-circuit, bad names resolve to nothing
        assert_eq!(
            resolve_via("10.1.2.3", &[], Duration::from_millis(10), 4),
            vec!["10.1.2.3".parse::<IpAddr>().unwrap()]
        );
        assert!(resolve_via("bad name", &[], Duration::from_millis(10), 4).is_empty());
    }
}
