//! Shared helpers for scenario tests (included with `mod common;`).
#![allow(dead_code)]

use kestrel_common::*;
use kestrel_detect::*;
use std::path::PathBuf;

pub const T0: i64 = 1_760_000_000_000;
pub const AGENT: &str = r"C:\Program Files\Kestrel\kestrel-agent.exe";
pub const SERVER_IP: &str = "203.0.113.10";

pub fn host() -> HostContext {
    HostContext {
        boot_id: "boot-1".into(),
        hostname: "FIN-LAPTOP-07".into(),
        agent_image: AGENT.into(),
        server_ips: vec![SERVER_IP.into()],
        system_drive: Some('c'),
    }
}

pub fn fixture(name: &str) -> Vec<Event> {
    let p: PathBuf = [env!("CARGO_MANIFEST_DIR"), "tests", "fixtures", name]
        .iter()
        .collect();
    let s = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    s.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{name}: bad line {l}: {e}")))
        .collect()
}

/// Policy with every builtin rule forced to `mode`.
pub fn policy_all(mode: RuleMode) -> Policy {
    let mut p = Policy::default();
    for m in Engine::catalog() {
        p.rules.insert(m.id.clone(), mode);
    }
    p
}

pub fn engine(policy: Policy) -> Engine {
    Engine::new(host(), policy, RuleBundle::default()).unwrap()
}

pub fn replay(engine: &mut Engine, events: &[Event]) -> Vec<Output> {
    events.iter().flat_map(|e| engine.process(e)).collect()
}

pub fn alerts(out: &[Output]) -> Vec<&Detection> {
    out.iter()
        .filter_map(|o| match o {
            Output::Alert(d) => Some(d),
            _ => None,
        })
        .collect()
}

pub fn rule_ids(out: &[Output]) -> Vec<String> {
    alerts(out)
        .iter()
        .map(|d| d.alert.rule_id.clone())
        .collect()
}

pub fn first<'a>(out: &'a [Output], rule: &str) -> &'a Detection {
    alerts(out)
        .into_iter()
        .find(|d| d.alert.rule_id == rule)
        .unwrap_or_else(|| panic!("no {rule} alert in {:?}", rule_ids(out)))
}

pub fn standalone(out: &[Output]) -> Vec<&ResponseAction> {
    out.iter()
        .filter_map(|o| match o {
            Output::Action(a) => Some(a),
            _ => None,
        })
        .collect()
}

pub fn kills(actions: &[ResponseAction]) -> Vec<(String, bool)> {
    actions
        .iter()
        .filter_map(|a| match a {
            ResponseAction::KillProcess { guid, tree, .. } => {
                Some((guid.clone().map(|g| g.0).unwrap_or_default(), *tree))
            }
            _ => None,
        })
        .collect()
}

pub fn action_names(actions: &[ResponseAction]) -> Vec<&'static str> {
    actions.iter().map(|a| a.name()).collect()
}

pub fn dump(out: &[Output]) -> String {
    let mut s = String::new();
    for o in out {
        match o {
            Output::Alert(d) => s.push_str(&format!(
                "ALERT {} {:?} {:?} [{}] proc={} risk={:?} ev={} anc={} :: {}\n",
                d.alert.rule_id,
                d.alert.mode,
                d.alert.severity,
                d.actions
                    .iter()
                    .map(|a| format!("{a:?}"))
                    .collect::<Vec<_>>()
                    .join("; "),
                d.alert.process.guid,
                d.alert.data_at_risk,
                d.alert.evidence.len(),
                d.alert.ancestry.len(),
                d.alert.summary
            )),
            Output::Action(a) => s.push_str(&format!("ACTION {a:?}\n")),
        }
    }
    s
}

// ----- inline event builders -----

pub fn g(s: &str) -> ProcessGuid {
    ProcessGuid(s.into())
}

pub fn ev(ts: i64, guid: &str, pid: u32, data: EventData) -> Event {
    Event {
        ts: T0 + ts,
        pid,
        guid: g(guid),
        data,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn start(
    ts: i64,
    guid: &str,
    pid: u32,
    image: &str,
    cmdline: &str,
    parent: Option<(&str, u32)>,
    signed: SignatureState,
    signer: Option<&str>,
) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::ProcessStart(ProcessStart {
            ppid: parent.map(|p| p.1).unwrap_or(0),
            parent_guid: parent.map(|p| g(p.0)),
            image: image.into(),
            cmdline: cmdline.into(),
            signed,
            signer: signer.map(Into::into),
            ..Default::default()
        }),
    )
}

pub fn read(ts: i64, guid: &str, pid: u32, path: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::FileAccess {
            path: path.into(),
            op: FileOp::Read,
        },
    )
}

pub fn write(ts: i64, guid: &str, pid: u32, path: &str) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::FileAccess {
            path: path.into(),
            op: FileOp::Write,
        },
    )
}

pub fn connect(ts: i64, guid: &str, pid: u32, ip: &str, port: u16) -> Event {
    ev(
        ts,
        guid,
        pid,
        EventData::NetConnect {
            proto: NetProto::Tcp,
            dst_ip: ip.into(),
            dst_port: port,
            src_port: 50123,
            dst_host: None,
            bytes_sent: None,
        },
    )
}

pub const CHROME_LOGIN: &str =
    r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data";
pub const CHROME_COOKIES: &str =
    r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies";
pub const CHROME_STATE: &str = r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Local State";
pub const CHROME_EXE: &str = r"C:\Program Files\Google\Chrome\Application\chrome.exe";
