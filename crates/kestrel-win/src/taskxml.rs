//! Scheduled-task XML (`C:\Windows\System32\Tasks\<name>`) → the fields of
//! `kestrel_common::TaskChange` (pure).
//!
//! Schema: `http://schemas.microsoft.com/windows/2004/02/mit/task`. Files on
//! disk are UTF-16LE with a BOM; `schtasks /query /xml` output is the same
//! document. Only `Exec` actions carry command lines; COM-handler actions are
//! reported as `com:{CLSID}` so they are not silently lost.

/// Largest task file read (real tasks are a few KB).
pub const MAX_TASK_XML_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TaskInfo {
    pub actions: Vec<String>,
    pub hidden: bool,
    /// `logon`, `boot`, `time`, `daily`, `weekly`, `monthly`, `idle`,
    /// `event`, `registration`, `session`, `custom`, `calendar`.
    pub triggers: Vec<String>,
    /// Principal `UserId` (SID or account), else `GroupId`.
    pub user: Option<String>,
    pub author: Option<String>,
    /// FNV-1a of the decoded XML text (de-duplication key, V-M8).
    pub xml_hash: u64,
    /// The task file was larger than [`MAX_TASK_XML_BYTES`] (V-M9); the
    /// fields then come from the Task Scheduler COM API when possible.
    pub oversized: bool,
}

/// Trigger marker added to `TaskChange::triggers` when the task XML was
/// oversized or unreadable (no dedicated contract field yet).
pub const TRIGGER_XML_OVERSIZED: &str = "xml_oversized";

/// Decode task-file bytes (UTF-16LE/BE with BOM, or UTF-8 with / without BOM).
pub fn decode_task_bytes(b: &[u8]) -> Option<String> {
    let b = &b[..b.len().min(MAX_TASK_XML_BYTES)];
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let u: Vec<u16> = b[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return Some(String::from_utf16_lossy(&u));
    }
    if b.len() >= 2 && b[0] == 0xFE && b[1] == 0xFF {
        let u: Vec<u16> = b[2..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        return Some(String::from_utf16_lossy(&u));
    }
    let b = b.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(b);
    // UTF-16LE without BOM: every second byte of "<?" is 0.
    if b.len() >= 4 && b[1] == 0 && b[3] == 0 {
        let u: Vec<u16> = b
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return Some(String::from_utf16_lossy(&u));
    }
    std::str::from_utf8(b).ok().map(str::to_string)
}

/// roxmltree refuses `encoding="UTF-16"` declarations on already-decoded
/// text only when it cannot parse at all; strip the declaration to be safe.
fn strip_decl(s: &str) -> &str {
    let t = s.trim_start_matches('\u{feff}').trim_start();
    if t.starts_with("<?xml") {
        if let Some(i) = t.find("?>") {
            return &t[i + 2..];
        }
    }
    t
}

fn trigger_kind(tag: &str) -> &'static str {
    match tag {
        "LogonTrigger" => "logon",
        "BootTrigger" => "boot",
        "TimeTrigger" => "time",
        "IdleTrigger" => "idle",
        "EventTrigger" => "event",
        "RegistrationTrigger" => "registration",
        "SessionStateChangeTrigger" => "session",
        "CalendarTrigger" => "calendar",
        "WnfStateChangeTrigger" => "wnf",
        _ => "custom",
    }
}

/// Quote a command the way `cmd` would need it (only when it has a space
/// and is not already quoted).
fn quote_cmd(cmd: &str) -> String {
    let c = cmd.trim();
    if c.contains(' ') && !c.starts_with('"') {
        format!("\"{c}\"")
    } else {
        c.to_string()
    }
}

pub fn parse_task_xml(xml: &str) -> Option<TaskInfo> {
    let doc = roxmltree::Document::parse(strip_decl(xml)).ok()?;
    let root = doc.root_element();
    if root.tag_name().name() != "Task" {
        return None;
    }
    let mut info = TaskInfo {
        xml_hash: crate::regdiff::fnv1a(xml.as_bytes()),
        ..Default::default()
    };
    let child = |n: roxmltree::Node<'_, '_>, name: &str| -> Option<String> {
        n.children()
            .find(|c| c.is_element() && c.tag_name().name() == name)
            .and_then(|c| c.text())
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
    };
    for sect in root.children().filter(|n| n.is_element()) {
        match sect.tag_name().name() {
            "RegistrationInfo" => info.author = child(sect, "Author"),
            "Settings" => {
                info.hidden = child(sect, "Hidden").is_some_and(|v| v.eq_ignore_ascii_case("true"));
            }
            "Principals" => {
                if let Some(p) = sect
                    .children()
                    .find(|c| c.is_element() && c.tag_name().name() == "Principal")
                {
                    info.user = child(p, "UserId").or_else(|| child(p, "GroupId"));
                }
            }
            "Triggers" => {
                for t in sect.children().filter(|n| n.is_element()) {
                    let k = trigger_kind(t.tag_name().name());
                    if !info.triggers.iter().any(|x| x == k) && info.triggers.len() < 16 {
                        info.triggers.push(k.to_string());
                    }
                }
            }
            "Actions" => {
                for a in sect.children().filter(|n| n.is_element()).take(32) {
                    match a.tag_name().name() {
                        "Exec" => {
                            let Some(cmd) = child(a, "Command") else {
                                continue;
                            };
                            let mut line = quote_cmd(&cmd);
                            if let Some(args) = child(a, "Arguments") {
                                line.push(' ');
                                line.push_str(&args);
                            }
                            info.actions.push(line);
                        }
                        "ComHandler" => {
                            if let Some(id) = child(a, "ClassId") {
                                info.actions.push(format!("com:{id}"));
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(info)
}

/// Safe relative path of a task inside the Tasks folder: `\Foo\Bar` →
/// `Foo\Bar`. Rejects `..`, `.`, empty components, drive letters, ADS
/// (`:`) and anything over 260 characters.
pub fn task_rel_path(task_name: &str) -> Option<String> {
    let t = task_name.trim().trim_start_matches('\\');
    if t.is_empty() || t.len() > 260 || t.contains(':') || t.contains('/') {
        return None;
    }
    let parts: Vec<&str> = t.split('\\').collect();
    if parts
        .iter()
        .any(|p| p.trim().is_empty() || *p == "." || *p == "..")
    {
        return None;
    }
    if t.chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | '"' | '|' | '?' | '*'))
    {
        return None;
    }
    Some(parts.join("\\"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name);
        std::fs::read_to_string(p).unwrap()
    }

    /// Real `schtasks /query /xml` output (Windows 11 25H2), scrubbed.
    #[test]
    fn real_system_task() {
        let i = parse_task_xml(&fixture("task_scheduleddefrag.xml")).unwrap();
        assert_eq!(i.actions, vec![r"%windir%\system32\defrag.exe -c -h -o -$"]);
        assert_eq!(i.user.as_deref(), Some("S-1-5-18"));
        assert!(!i.hidden);
        assert!(i.triggers.is_empty());
    }

    #[test]
    fn real_user_task_with_space_in_path() {
        let i = parse_task_xml(&fixture("task_user_timetrigger.xml")).unwrap();
        assert_eq!(
            i.actions,
            vec![
                r#""C:\Program Files\Microsoft OneDrive\OneDriveStandaloneUpdater.exe" /reporting"#
            ]
        );
        assert_eq!(i.triggers, vec!["time"]);
        assert_eq!(
            i.user.as_deref(),
            Some("S-1-5-21-1000000000-1000000000-1000000000-1001")
        );
        assert_eq!(i.author.as_deref(), Some("Microsoft Corporation"));
    }

    #[test]
    fn hidden_logon_task_utf16() {
        let xml = r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Settings><Hidden>true</Hidden></Settings>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger><BootTrigger/><LogonTrigger/></Triggers>
  <Actions Context="Author">
    <Exec><Command>C:\Users\Public\u.exe</Command></Exec>
    <ComHandler><ClassId>{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}</ClassId></ComHandler>
  </Actions>
</Task>"#;
        let mut b = vec![0xFF, 0xFE];
        b.extend(xml.encode_utf16().flat_map(|u| u.to_le_bytes()));
        let s = decode_task_bytes(&b).unwrap();
        let i = parse_task_xml(&s).unwrap();
        assert!(i.hidden);
        assert_eq!(i.triggers, vec!["logon", "boot"]);
        assert_eq!(
            i.actions,
            vec![
                r"C:\Users\Public\u.exe".to_string(),
                "com:{0F87369F-A4E5-4CFC-BD3E-73E6154572DD}".to_string()
            ]
        );
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse_task_xml("not xml").is_none());
        assert!(parse_task_xml("<Other/>").is_none());
        assert!(decode_task_bytes(&[0xFF, 0xFE, 0x41]).is_some());
        assert_eq!(decode_task_bytes(b"<a/>").unwrap(), "<a/>");
    }

    #[test]
    fn rel_paths() {
        assert_eq!(
            task_rel_path(r"\KestrelProbe").as_deref(),
            Some("KestrelProbe")
        );
        assert_eq!(
            task_rel_path(r"\Microsoft\Windows\Defrag\ScheduledDefrag").as_deref(),
            Some(r"Microsoft\Windows\Defrag\ScheduledDefrag")
        );
        for bad in [
            r"\..\..\Windows\win.ini",
            r"\a\..\b",
            "",
            r"\",
            r"\a\\b",
            r"C:\x",
            r"\a:stream",
            r"\a/b",
            "\\a\u{0}",
        ] {
            assert!(task_rel_path(bad).is_none(), "{bad:?}");
        }
    }
}
