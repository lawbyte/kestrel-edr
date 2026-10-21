//! WFP filter planning (pure). The Windows module turns each [`FilterSpec`]
//! into an `FWPM_FILTER0` inside the agent's own provider + sublayer
//! (sublayer weight 0xFFFF). All filters are persistent and "hard"
//! (`FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`), so lower-priority sublayers cannot
//! override them with soft actions.
//!
//! Weights inside the sublayer: permits 15, targeted blocks 10, isolation
//! catch-all block 0. The first matching filter by weight decides inside a
//! sublayer, so isolation permits beat the catch-all block, and a server
//! permit beats a destination block.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Layer {
    /// FWPM_LAYER_ALE_AUTH_CONNECT_V4 (outbound connect / first datagram)
    ConnectV4,
    ConnectV6,
    /// FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4 (inbound accept / first datagram)
    RecvAcceptV4,
    RecvAcceptV6,
}

impl Layer {
    pub fn is_v4(&self) -> bool {
        matches!(self, Layer::ConnectV4 | Layer::RecvAcceptV4)
    }
    pub fn is_inbound(&self) -> bool {
        matches!(self, Layer::RecvAcceptV4 | Layer::RecvAcceptV6)
    }
    pub const ALL: [Layer; 4] = [
        Layer::ConnectV4,
        Layer::ConnectV6,
        Layer::RecvAcceptV4,
        Layer::RecvAcceptV6,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Action {
    Permit,
    Block,
}

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cond {
    /// FWPM_CONDITION_IP_REMOTE_ADDRESS == ip
    RemoteAddr(IpAddr),
    /// FWPM_CONDITION_IP_REMOTE_PORT == port
    RemotePort(u16),
    /// FWPM_CONDITION_IP_LOCAL_PORT == port
    LocalPort(u16),
    /// FWPM_CONDITION_IP_PROTOCOL == proto
    Protocol(u8),
    /// FWPM_CONDITION_ALE_APP_ID == FwpmGetAppIdFromFileName0(path)
    AppPath(String),
    /// FWPM_CONDITION_FLAGS has FWP_CONDITION_FLAG_IS_LOOPBACK
    Loopback,
    /// FWPM_CONDITION_ALE_USER_ID matched against this security descriptor
    /// (SDDL; FWP_SECURITY_DESCRIPTOR_TYPE). The filter matches only when an
    /// access check of the connecting process's token against the SD grants
    /// `FWP_ACTRL_MATCH_FILTER` (V-H10).
    UserSd(String),
}

/// `FWP_ACTRL_MATCH_FILTER` (fwpmu.h, 0x00000001): the access right WFP
/// checks for `FWPM_CONDITION_ALE_USER_ID` ("Filtering Condition
/// Identifiers", learn.microsoft.com/windows/win32/fwp/filtering-condition-identifiers-;
/// "Access Right Identifiers", …/fwp/access-right-identifiers). In SDDL the
/// generic right string `CC` is bit 0x1.
pub const FWP_ACTRL_MATCH_FILTER: u32 = 0x1;

/// SDDL for the ALE user-id condition: only `sid` (a SID string, e.g. the
/// service SID `S-1-5-80-…` of `NT SERVICE\KestrelAgent`, or `S-1-5-18`) is
/// granted `FWP_ACTRL_MATCH_FILTER`. None for anything that is not a plain
/// SID string (fail closed: the caller then adds no agent permit).
pub fn agent_user_sddl(sid: &str) -> Option<String> {
    let s = sid.trim();
    let ok = s.starts_with("S-1-")
        && s.len() <= 184
        && s[4..]
            .split('-')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
    ok.then(|| format!("O:SYG:SYD:(A;;CC;;;{s})"))
}

/// The agent process as WFP sees it: image path (ALE app id) **and** token
/// identity (ALE user id). Every agent-scoped permit carries both, so a copy
/// of `kestrel-agent.exe` started by a user (same path → same app id) does
/// not match (V-H10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentId {
    pub exe: String,
    /// SDDL from [`agent_user_sddl`].
    pub user_sddl: String,
}

impl AgentId {
    /// None unless both parts are present.
    pub fn new(exe: &str, sid: &str) -> Option<AgentId> {
        if exe.trim().is_empty() {
            return None;
        }
        Some(AgentId {
            exe: exe.to_string(),
            user_sddl: agent_user_sddl(sid)?,
        })
    }

    fn conds(&self) -> [Cond; 2] {
        [
            Cond::AppPath(self.exe.clone()),
            Cond::UserSd(self.user_sddl.clone()),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterSpec {
    pub name: String,
    pub layer: Layer,
    pub action: Action,
    /// FWP_UINT8 weight inside our sublayer (0-15).
    pub weight: u8,
    pub conditions: Vec<Cond>,
}

pub const W_PERMIT: u8 = 15;
pub const W_BLOCK: u8 = 10;
pub const W_ISOLATE_BLOCK: u8 = 0;

fn family_ok(layer: Layer, ip: &IpAddr) -> bool {
    layer.is_v4() == ip.is_ipv4()
}

/// Filters for host isolation: everything blocked except loopback, the
/// Kestrel server(s) **for the agent process only** (image path + token
/// identity, V-H10), the extra allow-list (any process), DHCP, and DNS
/// (TCP/UDP 53) to the resolvers frozen at isolation time (V-M7), again for
/// the agent process only (H10). Without a known agent identity no server or
/// DNS permit is added at all (fail closed; the platform refuses to isolate
/// in that case).
///
/// Trade-off (intended): while isolated no other process — including the
/// Windows DNS Client service that answers `getaddrinfo` — can resolve
/// names, which closes DNS tunnelling out of an isolated host. The agent
/// resolves the server name itself with [`crate::dnswire`]; analysts who
/// need another service reachable add its IP to the allow-list.
pub fn plan_isolation(
    servers: &[IpAddr],
    allow: &[IpAddr],
    dns: &[IpAddr],
    agent: Option<&AgentId>,
) -> Vec<FilterSpec> {
    let mut v = Vec::new();
    for layer in Layer::ALL {
        let dir = if layer.is_inbound() { "in" } else { "out" };
        v.push(FilterSpec {
            name: format!("Kestrel isolate: permit loopback ({dir})"),
            layer,
            action: Action::Permit,
            weight: W_PERMIT,
            conditions: vec![Cond::Loopback],
        });
        if let Some(a) = agent {
            for ip in servers {
                if family_ok(layer, ip) {
                    let mut conditions = vec![Cond::RemoteAddr(*ip)];
                    conditions.extend(a.conds());
                    v.push(FilterSpec {
                        name: format!("Kestrel isolate: permit server {ip} ({dir})"),
                        layer,
                        action: Action::Permit,
                        weight: W_PERMIT,
                        conditions,
                    });
                }
            }
        }
        for ip in allow {
            if family_ok(layer, ip) {
                v.push(FilterSpec {
                    name: format!("Kestrel isolate: permit {ip} ({dir})"),
                    layer,
                    action: Action::Permit,
                    weight: W_PERMIT,
                    conditions: vec![Cond::RemoteAddr(*ip)],
                });
            }
        }
        // DHCP client: v4 68<->67, v6 546<->547.
        let (lp, rp) = if layer.is_v4() { (68, 67) } else { (546, 547) };
        v.push(FilterSpec {
            name: format!("Kestrel isolate: permit DHCP ({dir})"),
            layer,
            action: Action::Permit,
            weight: W_PERMIT,
            conditions: vec![
                Cond::Protocol(IPPROTO_UDP),
                Cond::LocalPort(lp),
                Cond::RemotePort(rp),
            ],
        });
        // H10: DNS only for the agent itself (it resolves the server with its
        // own stub resolver, `crate::dnswire`, while isolated). Without a
        // known agent image no DNS permit is added at all (fail closed).
        if let (false, Some(a)) = (layer.is_inbound(), agent) {
            for ip in dns {
                if family_ok(layer, ip) {
                    let mut conditions = vec![Cond::RemoteAddr(*ip), Cond::RemotePort(53)];
                    conditions.extend(a.conds());
                    v.push(FilterSpec {
                        name: format!("Kestrel isolate: permit agent DNS {ip}"),
                        layer,
                        action: Action::Permit,
                        weight: W_PERMIT,
                        conditions,
                    });
                }
            }
        }
        v.push(FilterSpec {
            name: format!("Kestrel isolate: block all ({dir})"),
            layer,
            action: Action::Block,
            weight: W_ISOLATE_BLOCK,
            conditions: vec![],
        });
    }
    v
}

/// Outbound block to one destination (optionally one port / one image).
pub fn plan_block_destination(
    ip: IpAddr,
    port: Option<u16>,
    image: Option<&str>,
) -> Vec<FilterSpec> {
    let layer = if ip.is_ipv4() {
        Layer::ConnectV4
    } else {
        Layer::ConnectV6
    };
    let mut conditions = vec![Cond::RemoteAddr(ip)];
    if let Some(p) = port {
        conditions.push(Cond::RemotePort(p));
    }
    if let Some(img) = image {
        conditions.push(Cond::AppPath(img.to_string()));
    }
    let what = match (port, image) {
        (Some(p), Some(i)) => format!("{ip}:{p} for {i}"),
        (Some(p), None) => format!("{ip}:{p}"),
        (None, Some(i)) => format!("{ip} for {i}"),
        (None, None) => ip.to_string(),
    };
    vec![FilterSpec {
        name: format!("Kestrel block destination {what}"),
        layer,
        action: Action::Block,
        weight: W_BLOCK,
        conditions,
    }]
}

/// All traffic (both directions, both families) for one executable.
pub fn plan_block_image(image: &str) -> Vec<FilterSpec> {
    Layer::ALL
        .iter()
        .map(|&layer| FilterSpec {
            name: format!("Kestrel block image {image}"),
            layer,
            action: Action::Block,
            weight: W_BLOCK,
            conditions: vec![Cond::AppPath(image.to_string())],
        })
        .collect()
}

/// Always-on hard permits for the agent's own server connections, so a
/// soft block added by another tool (EDRSilencer-style) cannot silence it.
/// Scoped to the agent process (image + token identity, V-H10): these
/// permits outrank the isolation catch-all block in the same sublayer.
pub fn plan_server_permits(servers: &[IpAddr], agent: &AgentId) -> Vec<FilterSpec> {
    servers
        .iter()
        .map(|ip| {
            let mut conditions = vec![Cond::RemoteAddr(*ip)];
            conditions.extend(agent.conds());
            FilterSpec {
                name: format!("Kestrel agent: permit server {ip}"),
                layer: if ip.is_ipv4() {
                    Layer::ConnectV4
                } else {
                    Layer::ConnectV6
                },
                action: Action::Permit,
                weight: W_PERMIT,
                conditions,
            }
        })
        .collect()
}

/// V-H10 invariant: every permit that is scoped to an application (ALE app
/// id) also carries the ALE user-id condition. Used by tests and checked by
/// the Windows glue before adding filters.
pub fn app_permits_have_user_sd(specs: &[FilterSpec]) -> bool {
    specs
        .iter()
        .filter(|f| f.action == Action::Permit)
        .filter(|f| f.conditions.iter().any(|c| matches!(c, Cond::AppPath(_))))
        .all(|f| f.conditions.iter().any(|c| matches!(c, Cond::UserSd(_))))
}

/// A set of filters added for one response action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockRecord {
    pub id: String,
    pub description: String,
    /// Filter keys (GUID strings) in WFP.
    pub filter_keys: Vec<String>,
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub created_at: i64,
    /// Block IOC whose hit created this block (`BlockDestination.ioc_id`).
    /// `None` for every other block (detection rules, analysts); only tagged
    /// blocks are ever lifted by [`WfpState::take_lifted_ioc_blocks`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ioc_id: Option<String>,
}

/// Persisted WFP state (`<state>\wfp_state.json`). Filters are persistent in
/// BFE, so this file is what lets the agent find and remove them after a
/// restart / reboot and enforce TTLs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct WfpState {
    pub isolated: bool,
    #[serde(default)]
    pub isolation_filters: Vec<String>,
    #[serde(default)]
    pub isolation_allow: Vec<String>,
    #[serde(default)]
    pub blocks: Vec<BlockRecord>,
    #[serde(default)]
    pub server_permit_filters: Vec<String>,
    /// Exact isolation plan, so missing filters can be re-added (tamper repair).
    #[serde(default)]
    pub isolation_specs: Vec<FilterSpec>,
    /// When the current isolation started (ms). Used for the auto-release
    /// deadline (H10).
    #[serde(default)]
    pub isolated_at: Option<i64>,
    /// Server addresses currently permitted (re-resolved while isolated).
    #[serde(default)]
    pub isolation_servers: Vec<String>,
    /// Extra addresses the analyst allowed (kept for re-planning).
    #[serde(default)]
    pub isolation_allow_ips: Vec<String>,
    /// DNS resolvers frozen when isolation started (V-M7): re-plans never
    /// permit a resolver that appeared later (rogue DHCPv6 / mitm6).
    #[serde(default)]
    pub isolation_dns: Vec<String>,
    /// Plan behind `server_permit_filters`, so a changed plan (new agent
    /// identity condition, new address) replaces the filters.
    #[serde(default)]
    pub server_permit_specs: Vec<FilterSpec>,
}

/// Resolvers to permit on a re-plan while isolated (V-M7): only those frozen
/// at isolation time that are still configured; when none of them is still
/// configured the frozen set is kept as is (never the new ones).
pub fn frozen_resolvers(frozen: &[IpAddr], current: &[IpAddr]) -> Vec<IpAddr> {
    let still: Vec<IpAddr> = frozen
        .iter()
        .filter(|ip| current.contains(ip))
        .copied()
        .collect();
    if still.is_empty() {
        frozen.to_vec()
    } else {
        still
    }
}

/// Resolvers an existing isolation plan permits (agent DNS permits).
pub fn planned_dns(specs: &[FilterSpec]) -> Vec<IpAddr> {
    let mut out = Vec::new();
    for f in specs {
        if f.action == Action::Permit && f.conditions.contains(&Cond::RemotePort(53)) {
            for c in &f.conditions {
                if let Cond::RemoteAddr(ip) = c {
                    if !out.contains(ip) {
                        out.push(*ip);
                    }
                }
            }
        }
    }
    out
}

/// Server addresses to permit after a re-resolution: the fresh answers
/// first, then previously permitted ones (so a failed or partial lookup never
/// removes a working address), bounded to `cap`. Not used while isolated
/// (V-M7: the server set is frozen then).
pub fn merge_server_ips(fresh: &[IpAddr], previous: &[IpAddr], cap: usize) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in fresh.iter().chain(previous.iter()) {
        if !out.contains(ip) && out.len() < cap {
            out.push(*ip);
        }
    }
    out
}

/// Should the isolation filters be re-planned? (DNS servers or server
/// addresses changed; filter order / names are ignored.)
pub fn isolation_plan_changed(current: &[FilterSpec], wanted: &[FilterSpec]) -> bool {
    let key = |v: &[FilterSpec]| {
        let mut k: Vec<String> = v
            .iter()
            .map(|f| {
                format!(
                    "{:?}|{:?}|{}|{:?}",
                    f.layer, f.action, f.weight, f.conditions
                )
            })
            .collect();
        k.sort();
        k
    };
    key(current) != key(wanted)
}

impl WfpState {
    /// Remove and return blocks whose TTL has passed.
    pub fn take_expired(&mut self, now: i64) -> Vec<BlockRecord> {
        let (expired, keep): (Vec<_>, Vec<_>) = self
            .blocks
            .drain(..)
            .partition(|b| b.expires_at.map(|e| e <= now).unwrap_or(false));
        self.blocks = keep;
        expired
    }

    /// M10: remove and return the IOC-created blocks whose IOC is no longer a
    /// Block IOC (`block_iocs` = ids of the Block IOCs in the newly applied
    /// policy). Blocks without an IOC tag are never returned.
    pub fn take_lifted_ioc_blocks(
        &mut self,
        block_iocs: &std::collections::BTreeSet<String>,
    ) -> Vec<BlockRecord> {
        let (lifted, keep): (Vec<_>, Vec<_>) = self
            .blocks
            .drain(..)
            .partition(|b| b.ioc_id.as_ref().is_some_and(|id| !block_iocs.contains(id)));
        self.blocks = keep;
        lifted
    }

    /// Every filter key this agent owns.
    pub fn all_keys(&self) -> Vec<String> {
        let mut v = self.isolation_filters.clone();
        v.extend(self.server_permit_filters.iter().cloned());
        for b in &self.blocks {
            v.extend(b.filter_keys.iter().cloned());
        }
        v
    }
}

/// Parse IP strings, resolving host names with `resolve` (callers pass a DNS
/// resolver; tests pass a stub). Unparseable entries are reported.
pub fn parse_ips(
    items: &[String],
    resolve: impl Fn(&str) -> Vec<IpAddr>,
) -> (Vec<IpAddr>, Vec<String>) {
    let mut ok = Vec::new();
    let mut bad = Vec::new();
    for s in items {
        let t = s.trim();
        // Allow "host:port" / "[v6]:port" forms from server URLs.
        let host = if let Some(stripped) = t.strip_prefix('[') {
            stripped.split(']').next().unwrap_or(stripped)
        } else if t.matches(':').count() == 1 {
            t.split(':').next().unwrap_or(t)
        } else {
            t
        };
        match host.parse::<IpAddr>() {
            Ok(ip) => {
                if !ok.contains(&ip) {
                    ok.push(ip)
                }
            }
            Err(_) => {
                let r = resolve(host);
                if r.is_empty() {
                    bad.push(s.clone());
                }
                for ip in r {
                    if !ok.contains(&ip) {
                        ok.push(ip);
                    }
                }
            }
        }
    }
    (ok, bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn isolation_plan() {
        let f = plan_isolation(
            &[ip("10.0.0.5"), ip("fd00::5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53")],
            None,
        );
        // every layer ends with a catch-all block at weight 0
        for layer in Layer::ALL {
            let l: Vec<_> = f.iter().filter(|x| x.layer == layer).collect();
            let last = l.last().unwrap();
            assert_eq!(last.action, Action::Block);
            assert!(last.conditions.is_empty());
            assert_eq!(last.weight, 0);
            assert!(l.iter().any(|x| x.conditions == vec![Cond::Loopback]));
        }
        // No agent identity known → no DNS and no server permit at all
        // (fail closed, H10 / V-H10)
        assert!(!f
            .iter()
            .any(|x| x.conditions.contains(&Cond::RemotePort(53))));
        assert!(!f
            .iter()
            .any(|x| x.conditions.contains(&Cond::RemoteAddr(ip("10.0.0.5")))));
        let f = plan_isolation(
            &[ip("10.0.0.5"), ip("fd00::5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53")],
            Some(&agent()),
        );
        // server permitted only in its own family
        assert!(f.iter().any(|x| x.layer == Layer::ConnectV4
            && x.conditions.contains(&Cond::RemoteAddr(ip("10.0.0.5")))));
        assert!(!f.iter().any(|x| x.layer == Layer::ConnectV6
            && x.conditions.contains(&Cond::RemoteAddr(ip("10.0.0.5")))));
        assert!(f.iter().any(|x| x.layer == Layer::ConnectV6
            && x.conditions.contains(&Cond::RemoteAddr(ip("fd00::5")))));
        // DNS only outbound
        assert!(f
            .iter()
            .any(|x| x.layer == Layer::ConnectV4 && x.conditions.contains(&Cond::RemotePort(53))));
        assert!(!f
            .iter()
            .any(|x| x.layer.is_inbound() && x.conditions.contains(&Cond::RemotePort(53))));
        // DHCP both directions
        assert_eq!(
            f.iter()
                .filter(|x| x.conditions.contains(&Cond::LocalPort(68)))
                .count(),
            2
        );
        // all permits outrank blocks
        assert!(f
            .iter()
            .filter(|x| x.action == Action::Permit)
            .all(|x| x.weight > W_ISOLATE_BLOCK));
    }

    const EXE: &str = r"C:\Program Files\Kestrel\kestrel-agent.exe";
    const SVC_SID: &str = "S-1-5-80-1234567890-1-2-3-4";

    fn agent() -> AgentId {
        AgentId::new(EXE, SVC_SID).unwrap()
    }

    #[test]
    fn agent_identity_sddl() {
        assert_eq!(
            agent_user_sddl(SVC_SID).unwrap(),
            format!("O:SYG:SYD:(A;;CC;;;{SVC_SID})")
        );
        assert_eq!(
            agent_user_sddl("S-1-5-18").unwrap(),
            "O:SYG:SYD:(A;;CC;;;S-1-5-18)"
        );
        // Anything but a plain SID string is refused (no SDDL injection).
        for bad in [
            "",
            "SY",
            "S-1-5-18)(A;;CC;;;WD",
            "S-1-5-",
            "S-1-5--18",
            "S-1-5-x",
            "s-1-5-18",
        ] {
            assert!(agent_user_sddl(bad).is_none(), "{bad}");
        }
        assert!(AgentId::new("", SVC_SID).is_none());
        assert!(AgentId::new(EXE, "nope").is_none());
        assert_eq!(FWP_ACTRL_MATCH_FILTER, 1);
    }

    /// V-H10: every agent-scoped permit (isolation server + DNS, always-on
    /// hard permits) carries the ALE user-id condition next to the app id.
    #[test]
    fn every_agent_permit_has_user_id() {
        let a = agent();
        let iso = plan_isolation(
            &[ip("10.0.0.5"), ip("fd00::5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53"), ip("fd00::53")],
            Some(&a),
        );
        let hard = plan_server_permits(&[ip("10.0.0.5"), ip("fd00::5")], &a);
        for plan in [&iso, &hard] {
            assert!(app_permits_have_user_sd(plan));
            let scoped: Vec<_> = plan
                .iter()
                .filter(|f| f.conditions.contains(&Cond::AppPath(EXE.into())))
                .collect();
            assert!(!scoped.is_empty());
            for f in scoped {
                assert!(f.conditions.contains(&Cond::UserSd(a.user_sddl.clone())));
            }
        }
        // The invariant check catches a permit without it.
        let mut broken = hard.clone();
        broken[0]
            .conditions
            .retain(|c| !matches!(c, Cond::UserSd(_)));
        assert!(!app_permits_have_user_sd(&broken));
        // Blocks by image are not permits and need no user condition.
        assert!(app_permits_have_user_sd(&plan_block_image(r"C:\x.exe")));
    }

    #[test]
    fn resolvers_stay_frozen() {
        let frozen = [ip("10.0.0.53")];
        // A rogue resolver appearing later is never added.
        assert_eq!(
            frozen_resolvers(&frozen, &[ip("10.0.0.53"), ip("fe80::bad")]),
            vec![ip("10.0.0.53")]
        );
        assert_eq!(
            frozen_resolvers(&frozen, &[ip("192.168.1.1")]),
            vec![ip("10.0.0.53")]
        );
        assert!(frozen_resolvers(&[], &[ip("192.168.1.1")]).is_empty());
        // Pre-V-M7 state: the frozen set is what the plan already permits.
        let plan = plan_isolation(
            &[ip("10.0.0.5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53"), ip("fd00::53")],
            Some(&agent()),
        );
        assert_eq!(planned_dns(&plan), vec![ip("10.0.0.53"), ip("fd00::53")]);
    }

    #[test]
    fn isolation_server_permit_is_agent_only_and_replannable() {
        let exe = EXE;
        let a = agent();
        let f = plan_isolation(
            &[ip("10.0.0.5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53")],
            Some(&a),
        );
        // server permitted only for the agent process
        assert!(f.iter().any(|x| x.layer == Layer::ConnectV4
            && x.conditions
                == vec![
                    Cond::RemoteAddr(ip("10.0.0.5")),
                    Cond::AppPath(exe.into()),
                    Cond::UserSd(a.user_sddl.clone())
                ]));
        assert!(!f
            .iter()
            .any(|x| x.conditions == vec![Cond::RemoteAddr(ip("10.0.0.5"))]));
        // DNS to the resolvers only for the agent executable (H10)
        let dns: Vec<_> = f
            .iter()
            .filter(|x| x.conditions.contains(&Cond::RemotePort(53)))
            .collect();
        assert_eq!(dns.len(), 1);
        assert_eq!(dns[0].layer, Layer::ConnectV4);
        assert_eq!(
            dns[0].conditions,
            vec![
                Cond::RemoteAddr(ip("10.0.0.53")),
                Cond::RemotePort(53),
                Cond::AppPath(exe.into()),
                Cond::UserSd(a.user_sddl.clone())
            ]
        );
        assert!(!f
            .iter()
            .any(|x| x.conditions.contains(&Cond::RemotePort(53))
                && !x.conditions.contains(&Cond::AppPath(exe.into()))));
        assert_eq!(
            plan_isolation(&[ip("10.0.0.5")], &[], &[ip("10.0.0.53")], None)
                .iter()
                .filter(|x| x.conditions.contains(&Cond::RemotePort(53)))
                .count(),
            0
        );
        // analyst allow-list stays any-process
        assert!(f
            .iter()
            .any(|x| x.conditions == vec![Cond::RemoteAddr(ip("10.0.0.9"))]));
        // roaming: new DHCP DNS server → plan changes; same inputs → unchanged
        let same = plan_isolation(
            &[ip("10.0.0.5")],
            &[ip("10.0.0.9")],
            &[ip("10.0.0.53")],
            Some(&a),
        );
        assert!(!isolation_plan_changed(&f, &same));
        let roamed = plan_isolation(
            &[ip("10.0.0.5")],
            &[ip("10.0.0.9")],
            &[ip("192.168.1.1")],
            Some(&a),
        );
        assert!(isolation_plan_changed(&f, &roamed));
        // A plan from before V-H10 (no user-id condition) is re-planned.
        let old: Vec<FilterSpec> = f
            .iter()
            .cloned()
            .map(|mut s| {
                s.conditions.retain(|c| !matches!(c, Cond::UserSd(_)));
                s
            })
            .collect();
        assert!(isolation_plan_changed(&old, &f));
        // server IP changed: new answer first, old kept
        assert_eq!(
            merge_server_ips(&[ip("10.0.0.6")], &[ip("10.0.0.5")], 8),
            vec![ip("10.0.0.6"), ip("10.0.0.5")]
        );
        assert_eq!(
            merge_server_ips(&[], &[ip("10.0.0.5")], 8),
            vec![ip("10.0.0.5")]
        );
        assert_eq!(
            merge_server_ips(&[ip("1.1.1.1"), ip("1.1.1.2")], &[ip("1.1.1.3")], 2).len(),
            2
        );
    }

    #[test]
    fn block_plans() {
        let b = plan_block_destination(ip("1.2.3.4"), Some(443), Some(r"C:\x\evil.exe"));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].layer, Layer::ConnectV4);
        assert_eq!(b[0].conditions.len(), 3);
        let b6 = plan_block_destination(ip("2001:db8::1"), None, None);
        assert_eq!(b6[0].layer, Layer::ConnectV6);
        assert_eq!(plan_block_image(r"C:\a.exe").len(), 4);
        let p = plan_server_permits(&[ip("10.0.0.5")], &agent());
        assert_eq!(p[0].action, Action::Permit);
        assert!(p[0].weight > W_BLOCK);
    }

    #[test]
    fn ioc_blocks_lifted_only_when_ioc_gone() {
        let rec = |id: &str, ioc: Option<&str>| BlockRecord {
            id: id.into(),
            description: String::new(),
            filter_keys: vec![format!("k-{id}")],
            expires_at: Some(1_000),
            created_at: 0,
            ioc_id: ioc.map(str::to_string),
        };
        let mut s = WfpState {
            blocks: vec![
                rec("st04", None),              // ST-04 destination block
                rec("analyst", None),           // analyst command
                rec("kept", Some("ioc-1")),     // IOC still a Block IOC
                rec("deleted", Some("ioc-2")),  // IOC deleted
                rec("deleted2", Some("ioc-2")), // second hit of the same IOC
                rec("demoted", Some("ioc-3")),  // IOC changed to Audit/Allow
            ],
            ..Default::default()
        };
        let keep: std::collections::BTreeSet<String> = ["ioc-1".to_string()].into();
        let lifted = s.take_lifted_ioc_blocks(&keep);
        let ids: Vec<&str> = lifted.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(ids, ["deleted", "deleted2", "demoted"]);
        let left: Vec<&str> = s.blocks.iter().map(|b| b.id.as_str()).collect();
        assert_eq!(left, ["st04", "analyst", "kept"]);
        // Idempotent; an empty Block-IOC set lifts every remaining IOC block
        // but never untagged ones.
        assert!(s.take_lifted_ioc_blocks(&keep).is_empty());
        let lifted = s.take_lifted_ioc_blocks(&Default::default());
        assert_eq!(lifted.len(), 1);
        assert_eq!(s.blocks.len(), 2);
        // Old state files (no ioc_id) still load; the tag round-trips.
        let old: BlockRecord =
            serde_json::from_str(r#"{"id":"x","description":"","filter_keys":[],"created_at":0}"#)
                .unwrap();
        assert_eq!(old.ioc_id, None);
        let j = serde_json::to_string(&rec("y", Some("ioc-9"))).unwrap();
        assert_eq!(
            serde_json::from_str::<BlockRecord>(&j)
                .unwrap()
                .ioc_id
                .as_deref(),
            Some("ioc-9")
        );
    }

    #[test]
    fn state_ttl() {
        let mut s = WfpState::default();
        s.blocks.push(BlockRecord {
            id: "a".into(),
            description: String::new(),
            filter_keys: vec!["k1".into()],
            expires_at: Some(100),
            created_at: 0,
            ioc_id: None,
        });
        s.blocks.push(BlockRecord {
            id: "b".into(),
            description: String::new(),
            filter_keys: vec!["k2".into()],
            expires_at: None,
            created_at: 0,
            ioc_id: None,
        });
        s.isolation_filters = vec!["k3".into()];
        assert_eq!(s.all_keys().len(), 3);
        assert!(s.take_expired(50).is_empty());
        let e = s.take_expired(100);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].id, "a");
        assert_eq!(s.blocks.len(), 1);
        let j = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<WfpState>(&j).unwrap(), s);
    }

    #[test]
    fn ip_parsing() {
        let (ok, bad) = parse_ips(
            &[
                "10.0.0.1".into(),
                "10.0.0.1:8443".into(),
                "[fd00::1]:8443".into(),
                "edr.example".into(),
                "nope".into(),
            ],
            |h| {
                if h == "edr.example" {
                    vec![ip("10.0.0.2")]
                } else {
                    vec![]
                }
            },
        );
        assert_eq!(ok, vec![ip("10.0.0.1"), ip("fd00::1"), ip("10.0.0.2")]);
        assert_eq!(bad, vec!["nope".to_string()]);
    }
}
