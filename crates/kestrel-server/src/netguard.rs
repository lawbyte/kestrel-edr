//! Outbound-request guard (SSRF): webhook, Slack/Teams and OIDC requests may only
//! reach public addresses. Private, loopback, link-local (cloud metadata),
//! CGNAT, multicast and reserved ranges are refused unless the operator lists
//! them in `KESTREL_OUTBOUND_ALLOW_CIDRS`. Redirects are never followed.
//! Syslog may target private ranges only when `notifications.syslog.allow_private`
//! is set; link-local / metadata stays blocked even then.

use ipnet::IpNet;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

/// Link-local / metadata: never reachable, whatever the configuration.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn is_private_v4(v4: &Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || o[0] == 0
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || o[0] >= 240 // reserved
}

fn is_private_v6(v6: &Ipv6Addr) -> bool {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return is_private_v4(&v4);
    }
    let s0 = v6.segments()[0];
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (s0 & 0xfe00) == 0xfc00 // ULA
        || (s0 == 0x0064 && v6.segments()[1] == 0xff9b) // NAT64 (may embed private v4)
}

/// Not a public unicast address (link-local included).
pub fn is_non_public(ip: &IpAddr) -> bool {
    is_link_local(ip)
        || match ip {
            IpAddr::V4(v4) => is_private_v4(v4),
            IpAddr::V6(v6) => is_private_v6(v6),
        }
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    /// Operator allow-list of private ranges (never overrides link-local).
    pub allow: Vec<IpNet>,
    /// Allow every private (but not link-local) address (syslog opt-in).
    pub allow_private: bool,
}

impl Policy {
    pub fn new(allow: &[IpNet]) -> Policy {
        Policy {
            allow: allow.to_vec(),
            allow_private: false,
        }
    }

    pub fn permits(&self, ip: &IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(*ip),
            other => *other,
        };
        if is_link_local(&ip) {
            return false;
        }
        if !is_non_public(&ip) {
            return true;
        }
        self.allow_private || self.allow.iter().any(|n| n.contains(&ip))
    }

    /// Resolve `host:port` and keep only permitted addresses.
    pub async fn resolve(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        let host = host.trim_start_matches('[').trim_end_matches(']');
        if (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost"))
            && !self.permits(&IpAddr::V4(Ipv4Addr::LOCALHOST))
        {
            anyhow::bail!("destination {host} is not allowed (loopback)");
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
        let ok: Vec<SocketAddr> = addrs
            .iter()
            .copied()
            .filter(|a| self.permits(&a.ip()))
            .collect();
        if ok.is_empty() {
            anyhow::bail!(
                "destination {host} resolves only to private, loopback or link-local addresses; \
                 list the range in KESTREL_OUTBOUND_ALLOW_CIDRS to allow it"
            );
        }
        Ok(ok)
    }

    /// Static URL check (scheme, IP-literal hosts). Name resolution is checked
    /// again on every request by [`client`].
    pub fn check_url(&self, url: &str) -> anyhow::Result<()> {
        let u = reqwest::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid URL"))?;
        if u.scheme() != "https" && u.scheme() != "http" {
            anyhow::bail!("URL must be http(s)");
        }
        if !u.username().is_empty() || u.password().is_some() {
            anyhow::bail!("URL must not contain credentials");
        }
        let host = u
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("URL has no host"))?
            .trim_start_matches('[')
            .trim_end_matches(']');
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !self.permits(&ip) {
                anyhow::bail!("URL points at a private, loopback or link-local address");
            }
        } else if (host.eq_ignore_ascii_case("localhost") || host.ends_with(".localhost"))
            && !self.permits(&IpAddr::V4(Ipv4Addr::LOCALHOST))
        {
            anyhow::bail!("URL points at localhost");
        }
        Ok(())
    }
}

struct GuardedResolver(Policy);

impl Resolve for GuardedResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let policy = self.0.clone();
        Box::pin(async move {
            let addrs = policy
                .resolve(name.as_str(), 0)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// HTTP client whose DNS answers are filtered by `policy` and that never follows
/// redirects. Callers must still run [`Policy::check_url`] for IP-literal URLs
/// (reqwest does not resolve those).
pub fn client(policy: &Policy, timeout: Duration) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .dns_resolver(Arc::new(GuardedResolver(policy.clone())))
        .build()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        let p = Policy::default();
        for bad in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            assert!(!p.permits(&bad.parse().unwrap()), "{bad} must be blocked");
        }
        for good in ["8.8.8.8", "203.0.114.1", "2606:4700::1111"] {
            assert!(p.permits(&good.parse().unwrap()), "{good} must be allowed");
        }
        let allow = Policy::new(&["10.0.0.0/8".parse().unwrap()]);
        assert!(allow.permits(&"10.1.2.3".parse().unwrap()));
        assert!(!allow.permits(&"192.168.1.1".parse().unwrap()));
        let syslog = Policy {
            allow: vec![],
            allow_private: true,
        };
        assert!(syslog.permits(&"192.168.1.1".parse().unwrap()));
        assert!(!syslog.permits(&"169.254.169.254".parse().unwrap()));
        let all = Policy::new(&["0.0.0.0/0".parse().unwrap()]);
        assert!(!all.permits(&"169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn urls() {
        let p = Policy::default();
        assert!(p.check_url("https://hooks.slack.com/services/x").is_ok());
        assert!(p
            .check_url("http://169.254.169.254/latest/meta-data")
            .is_err());
        assert!(p.check_url("http://[::1]:8080/").is_err());
        assert!(p.check_url("https://localhost/x").is_err());
        assert!(p.check_url("ftp://example.com/").is_err());
        assert!(p.check_url("https://user:pw@example.com/").is_err());
    }

    #[tokio::test]
    async fn resolver_filters() {
        let p = Policy::default();
        assert!(p.resolve("127.0.0.1", 80).await.is_err());
        assert!(p.resolve("localhost", 80).await.is_err());
    }
}
