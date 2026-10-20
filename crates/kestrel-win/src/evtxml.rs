//! Parsing of event-log XML rendered by `EvtRender(EvtRenderEventXml)` for
//! the Sysmon and Security channels (pure).

use crate::etwparse::parse_hex_u32;
use std::collections::HashMap;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Rendered {
    pub event_id: u32,
    pub provider: String,
    pub time_ms: Option<i64>,
    /// System/Execution/@ProcessID (the logging process).
    pub exec_pid: Option<u32>,
    pub data: HashMap<String, String>,
}

impl Rendered {
    pub fn get(&self, k: &str) -> Option<&str> {
        self.data.get(k).map(|s| s.as_str())
    }
    pub fn get_u32(&self, k: &str) -> Option<u32> {
        let v = self.get(k)?.trim();
        if v.starts_with("0x") || v.starts_with("0X") {
            parse_hex_u32(v)
        } else {
            v.parse().ok()
        }
    }
}

pub fn parse_event_xml(xml: &str) -> Option<Rendered> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    let root = doc.root_element();
    let mut r = Rendered::default();
    for sect in root.children().filter(|n| n.is_element()) {
        match sect.tag_name().name() {
            "System" => {
                for n in sect.children().filter(|n| n.is_element()) {
                    match n.tag_name().name() {
                        "EventID" => {
                            r.event_id = n.text().and_then(|t| t.trim().parse().ok()).unwrap_or(0)
                        }
                        "Provider" => {
                            r.provider = n.attribute("Name").unwrap_or_default().to_string()
                        }
                        "TimeCreated" => {
                            r.time_ms = n.attribute("SystemTime").and_then(parse_iso8601_ms)
                        }
                        "Execution" => {
                            r.exec_pid = n.attribute("ProcessID").and_then(|p| p.parse().ok())
                        }
                        _ => {}
                    }
                }
            }
            "EventData" | "UserData" => {
                for d in sect
                    .descendants()
                    .filter(|n| n.is_element() && n.has_tag_name("Data"))
                {
                    if let Some(name) = d.attribute("Name") {
                        r.data
                            .insert(name.to_string(), d.text().unwrap_or_default().to_string());
                    }
                }
            }
            _ => {}
        }
    }
    Some(r)
}

/// "2026-10-21T13:45:30.1234567Z" → ms since epoch (UTC only).
pub fn parse_iso8601_ms(s: &str) -> Option<i64> {
    let s = s.trim().trim_end_matches('Z');
    let (date, time) = s.split_once('T')?;
    let mut dp = date.split('-');
    let y: i64 = dp.next()?.parse().ok()?;
    let m: i64 = dp.next()?.parse().ok()?;
    let d: i64 = dp.next()?.parse().ok()?;
    let (hms, frac) = time.split_once('.').unwrap_or((time, "0"));
    let mut tp = hms.split(':');
    let hh: i64 = tp.next()?.parse().ok()?;
    let mm: i64 = tp.next()?.parse().ok()?;
    let ss: i64 = tp.next()?.parse().ok()?;
    let frac_ms: i64 = {
        let f: String = frac.chars().take(3).collect();
        let f = format!("{f:0<3}");
        f.parse().ok()?
    };
    // days_from_civil (Howard Hinnant)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + hh * 3600 + mm * 60 + ss) * 1000) + frac_ms)
}

/// Kind of cross-process activity reported by Sysmon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysmonKind {
    ProcessAccess,
    RemoteThread,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SysmonCross {
    pub kind: SysmonKind,
    pub source_pid: u32,
    pub target_pid: u32,
    pub target_image: String,
    pub granted_access: u32,
    pub time_ms: Option<i64>,
}

/// Sysmon EID 10 (ProcessAccess) / EID 8 (CreateRemoteThread).
pub fn sysmon_cross(ev: &Rendered) -> Option<SysmonCross> {
    let kind = match ev.event_id {
        10 => SysmonKind::ProcessAccess,
        8 => SysmonKind::RemoteThread,
        _ => return None,
    };
    let source_pid = ev.get_u32("SourceProcessId")?;
    let target_pid = ev.get_u32("TargetProcessId")?;
    if source_pid == target_pid {
        return None;
    }
    Some(SysmonCross {
        kind,
        source_pid,
        target_pid,
        target_image: ev.get("TargetImage").unwrap_or_default().to_string(),
        granted_access: if kind == SysmonKind::ProcessAccess {
            ev.get_u32("GrantedAccess").unwrap_or(0)
        } else {
            0
        },
        time_ms: ev.time_ms,
    })
}

pub const LAYER_ALE_CONNECT_V4: &str = "c38d57d1-05a7-4c33-904f-7fbceee60e82";
pub const LAYER_ALE_CONNECT_V6: &str = "4a72393b-319f-44bc-84c3-ba54dcb3b6b4";
pub const LAYER_ALE_RECV_V4: &str = "e1cd9fe7-f4b5-4273-96c0-592e487b8650";
pub const LAYER_ALE_RECV_V6: &str = "a3b42c97-9f04-4672-b87e-cee9c483257f";
/// Windows Firewall (MPSSVC) providers.
pub const PROVIDER_MPSSVC_WF: &str = "decc16ca-3f33-4346-be1e-8fb4ae0f3d62";
pub const PROVIDER_MPSSVC_WSH: &str = "4b153735-1049-4480-aab4-d1b9bdc03710";

fn guid_eq(a: &str, b: &str) -> bool {
    a.trim_matches(|c| c == '{' || c == '}')
        .eq_ignore_ascii_case(b.trim_matches(|c| c == '{' || c == '}'))
}

/// Decide whether a Security 5446-5450 event is a tamper signal. Returns the
/// tamper detail when it is.
///
/// * Any change to Kestrel's own provider, sublayer or filters by another
///   process (someone removing isolation / server permits).
/// * A filter (5447) at the ALE connect / recv-accept layers added by a
///   non-firewall provider (or with no provider), by a process other than the
///   agent — the EDRSilencer pattern of blocking security products' traffic.
pub fn wfp_tamper(
    ev: &Rendered,
    self_pid: u32,
    our_keys: &[String],
    our_provider: &str,
    our_sublayer: &str,
) -> Option<String> {
    if !(5446..=5450).contains(&ev.event_id) {
        return None;
    }
    let pid = ev.get_u32("ProcessId").unwrap_or(0);
    if pid == self_pid {
        return None;
    }
    let provider_key = ev.get("ProviderKey").unwrap_or_default();
    let filter_key = ev.get("FilterKey").unwrap_or_default();
    let sublayer_key = ev.get("SubLayerKey").unwrap_or_default();
    let name = ev
        .get("FilterName")
        .or_else(|| ev.get("SubLayerName"))
        .or_else(|| ev.get("ProviderName"))
        .unwrap_or_default();
    let change = ev.get("ChangeType").unwrap_or_default();
    let ours = (!provider_key.is_empty() && guid_eq(provider_key, our_provider))
        || (!sublayer_key.is_empty() && guid_eq(sublayer_key, our_sublayer))
        || (!filter_key.is_empty() && our_keys.iter().any(|k| guid_eq(k, filter_key)));
    if ours {
        return Some(format!(
            "Kestrel WFP object modified by pid {pid}: event {} change {change} '{name}' (filter {filter_key})",
            ev.event_id
        ));
    }
    if ev.event_id != 5447 {
        return None;
    }
    let layer = ev.get("LayerKey").unwrap_or_default();
    let ale = [
        LAYER_ALE_CONNECT_V4,
        LAYER_ALE_CONNECT_V6,
        LAYER_ALE_RECV_V4,
        LAYER_ALE_RECV_V6,
    ]
    .iter()
    .any(|l| guid_eq(layer, l));
    if !ale {
        return None;
    }
    let firewall =
        guid_eq(provider_key, PROVIDER_MPSSVC_WF) || guid_eq(provider_key, PROVIDER_MPSSVC_WSH);
    if firewall {
        return None;
    }
    Some(format!(
        "WFP filter '{name}' changed at {} by pid {pid} (provider '{}' {provider_key}, change {change}, action {})",
        ev.get("LayerName").unwrap_or(layer),
        ev.get("ProviderName").unwrap_or("-"),
        ev.get("Action").unwrap_or("-"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYSMON10: &str = r#"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>10</EventID><Version>3</Version><TimeCreated SystemTime='2026-08-13T10:00:01.5000000Z'/><Execution ProcessID='3000' ThreadID='4000'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System><EventData><Data Name='RuleName'>-</Data><Data Name='SourceProcessId'>6789</Data><Data Name='SourceImage'>C:\Users\a\AppData\Local\Temp\x.exe</Data><Data Name='TargetProcessId'>1234</Data><Data Name='TargetImage'>C:\Program Files\Google\Chrome\Application\chrome.exe</Data><Data Name='GrantedAccess'>0x143a</Data></EventData></Event>"#;

    #[test]
    fn sysmon() {
        let ev = parse_event_xml(SYSMON10).unwrap();
        assert_eq!(ev.event_id, 10);
        assert_eq!(ev.exec_pid, Some(3000));
        let c = sysmon_cross(&ev).unwrap();
        assert_eq!(c.kind, SysmonKind::ProcessAccess);
        assert_eq!(c.source_pid, 6789);
        assert_eq!(c.target_pid, 1234);
        assert_eq!(c.granted_access, 0x143a);
        assert!(c.target_image.ends_with("chrome.exe"));
        assert_eq!(c.time_ms, parse_iso8601_ms("2026-08-13T10:00:01.5Z"));
    }

    #[test]
    fn iso() {
        assert_eq!(parse_iso8601_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(
            parse_iso8601_ms("2024-04-01T00:00:00Z"),
            Some(1_711_929_600_000)
        );
        assert_eq!(
            parse_iso8601_ms("2024-02-29T12:00:00.25Z"),
            Some(1_709_208_000_250)
        );
        assert_eq!(parse_iso8601_ms("garbage"), None);
    }

    fn wfp_event(id: u32, pairs: &[(&str, &str)]) -> Rendered {
        Rendered {
            event_id: id,
            data: pairs
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            ..Default::default()
        }
    }

    #[test]
    fn wfp() {
        let ours = vec!["{11111111-2222-3333-4444-555555555555}".to_string()];
        let p = crate::consts::wfp::PROVIDER_KEY_STR;
        let s = crate::consts::wfp::SUBLAYER_KEY_STR;
        // Our filter deleted by someone else.
        let e = wfp_event(
            5447,
            &[
                ("ProcessId", "4321"),
                ("FilterKey", "{11111111-2222-3333-4444-555555555555}"),
                ("ChangeType", "%%16386"),
            ],
        );
        assert!(wfp_tamper(&e, 100, &ours, p, s)
            .unwrap()
            .contains("Kestrel WFP object"));
        // Same change by the agent itself: ignored.
        let e2 = wfp_event(
            5447,
            &[
                ("ProcessId", "100"),
                ("FilterKey", "{11111111-2222-3333-4444-555555555555}"),
            ],
        );
        assert!(wfp_tamper(&e2, 100, &ours, p, s).is_none());
        // EDRSilencer-like filter at ALE connect with no provider.
        let e3 = wfp_event(
            5447,
            &[
                ("ProcessId", "777"),
                ("FilterName", "Custom Outbound Filter"),
                ("ProviderKey", "{00000000-0000-0000-0000-000000000000}"),
                ("LayerKey", "{c38d57d1-05a7-4c33-904f-7fbceee60e82}"),
            ],
        );
        assert!(wfp_tamper(&e3, 100, &ours, p, s).is_some());
        // Windows Firewall rule churn: ignored.
        let e4 = wfp_event(
            5447,
            &[
                ("ProcessId", "1500"),
                ("ProviderKey", "{DECC16CA-3F33-4346-BE1E-8FB4AE0F3D62}"),
                ("LayerKey", "{c38d57d1-05a7-4c33-904f-7fbceee60e82}"),
            ],
        );
        assert!(wfp_tamper(&e4, 100, &ours, p, s).is_none());
        // Non-ALE layer: ignored.
        let e5 = wfp_event(
            5447,
            &[
                ("ProcessId", "777"),
                ("LayerKey", "{AC4A9833-F69D-4648-B261-6DC84835EF39}"),
            ],
        );
        assert!(wfp_tamper(&e5, 100, &ours, p, s).is_none());
        // Our sublayer changed (5450).
        let e6 = wfp_event(
            5450,
            &[("ProcessId", "777"), ("SubLayerKey", &format!("{{{s}}}"))],
        );
        assert!(wfp_tamper(&e6, 100, &ours, p, s).is_some());
    }
}
