//! AppLocker policy editing (pure).
//!
//! Strategy (never weaken anyone else's application control, H9):
//! * The **effective** policy (`Get-AppLockerPolicy -Effective`, i.e. local,
//!   GPO and MDM) is inspected first. If it contains any rule that is neither
//!   Kestrel's nor in the local policy (AppLocker is managed by GPO or MDM),
//!   Kestrel does not touch AppLocker at all and reports
//!   `skipped: domain policy present` (and removes its own allow rules if an
//!   earlier version left them behind). AppLocker merges local and domain
//!   rules as a union, so any local allow rule would widen a domain
//!   allowlist.
//! * Only the **Exe** rule collection of the **local** policy is touched; the
//!   rest of the document is kept byte-for-byte.
//! * Kestrel rules have fixed ids (prefix `4b455354-`) so edits are
//!   idempotent and reversible: on every apply we remove our old rules and
//!   insert the desired set.
//! * If no policy exists at all we enable the Exe collection with the
//!   **standard AppLocker default rules** (Everyone: `%PROGRAMFILES%\*`,
//!   Everyone: `%WINDIR%\*`, Administrators: `*`) plus our deny rules — never
//!   an "allow Everyone `*`". Note that this blocks executables in user
//!   profiles (per-user installs in AppData) for standard users; enable the
//!   AppLocker controls only where that is acceptable, or manage AppLocker
//!   centrally and let Kestrel stay out of it.
//! * If foreign local Exe rules exist we only add deny rules, and we refuse to
//!   change the collection's enforcement mode unless it is already `Enabled`
//!   (flipping someone else's AuditOnly whitelist to Enabled would break the
//!   machine).
//! * Deny rules apply to Everyone (`S-1-1-0`): AppLocker cannot target
//!   "standard users only" because elevated admin tokens also contain
//!   BUILTIN\Users. Admins rarely need mshta.exe; for `block_user_path_exec`
//!   admins must move installers out of Downloads/Temp to run them.

use roxmltree::{Document, Node};

pub const OUR_ID_PREFIX: &str = "4b455354-";
/// Legacy "allow Everyone *" (removed on every apply; never written again).
pub const ID_ALLOW_ALL: &str = "4b455354-0000-4000-8000-000000000001";
pub const ID_ALLOW_ADMINS: &str = "4b455354-0000-4000-8000-000000000002";
pub const ID_ALLOW_PROGRAMFILES: &str = "4b455354-0000-4000-8000-000000000003";
pub const ID_ALLOW_WINDIR: &str = "4b455354-0000-4000-8000-000000000004";
/// Reported when the effective policy is managed by GPO / MDM.
pub const SKIPPED_DOMAIN_POLICY: &str = "skipped: domain policy present";
pub const ID_DENY_MSHTA_PUBLISHER: &str = "4b455354-0000-4000-8000-000000000010";
pub const ID_DENY_MSHTA_PATH: &str = "4b455354-0000-4000-8000-000000000011";
pub const ID_DENY_USER_TEMP: &str = "4b455354-0000-4000-8000-000000000020";
pub const ID_DENY_USER_DOWNLOADS: &str = "4b455354-0000-4000-8000-000000000021";

const SID_EVERYONE: &str = "S-1-1-0";
const SID_ADMINS: &str = "S-1-5-32-544";
const MS_PUBLISHER: &str = "O=MICROSOFT CORPORATION, L=REDMOND, S=WASHINGTON, C=US";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Want {
    pub block_mshta: bool,
    pub block_user_path_exec: bool,
}

impl Want {
    pub fn any(&self) -> bool {
        self.block_mshta || self.block_user_path_exec
    }
}

fn path_rule(id: &str, name: &str, sid: &str, action: &str, path: &str) -> String {
    format!(
        r#"<FilePathRule Id="{id}" Name="{name}" Description="Managed by Kestrel EDR" UserOrGroupSid="{sid}" Action="{action}"><Conditions><FilePathCondition Path="{path}" /></Conditions></FilePathRule>"#
    )
}

fn publisher_rule(id: &str, name: &str, sid: &str, action: &str, binary: &str) -> String {
    format!(
        r#"<FilePublisherRule Id="{id}" Name="{name}" Description="Managed by Kestrel EDR" UserOrGroupSid="{sid}" Action="{action}"><Conditions><FilePublisherCondition PublisherName="{MS_PUBLISHER}" ProductName="*" BinaryName="{binary}"><BinaryVersionRange LowSection="*" HighSection="*" /></FilePublisherCondition></Conditions></FilePublisherRule>"#
    )
}

/// Our rules for the desired controls. `with_allow` adds the standard
/// AppLocker default allow rules (Program Files, Windows, Administrators).
pub fn our_rules(want: Want, with_allow: bool) -> Vec<String> {
    let mut v = Vec::new();
    if with_allow && want.any() {
        v.push(path_rule(
            ID_ALLOW_PROGRAMFILES,
            "Kestrel: (default rule) all files in the Program Files folder",
            SID_EVERYONE,
            "Allow",
            r"%PROGRAMFILES%\*",
        ));
        v.push(path_rule(
            ID_ALLOW_WINDIR,
            "Kestrel: (default rule) all files in the Windows folder",
            SID_EVERYONE,
            "Allow",
            r"%WINDIR%\*",
        ));
        v.push(path_rule(
            ID_ALLOW_ADMINS,
            "Kestrel: (default rule) all files for Administrators",
            SID_ADMINS,
            "Allow",
            "*",
        ));
    }
    if want.block_mshta {
        v.push(publisher_rule(
            ID_DENY_MSHTA_PUBLISHER,
            "Kestrel: deny mshta.exe (any location)",
            SID_EVERYONE,
            "Deny",
            "MSHTA.EXE",
        ));
        v.push(path_rule(
            ID_DENY_MSHTA_PATH,
            "Kestrel: deny mshta.exe",
            SID_EVERYONE,
            "Deny",
            r"%SYSTEM32%\mshta.exe",
        ));
    }
    if want.block_user_path_exec {
        v.push(path_rule(
            ID_DENY_USER_TEMP,
            "Kestrel: deny exe from user Temp",
            SID_EVERYONE,
            "Deny",
            r"%OSDRIVE%\Users\*\AppData\Local\Temp\*",
        ));
        v.push(path_rule(
            ID_DENY_USER_DOWNLOADS,
            "Kestrel: deny exe from Downloads",
            SID_EVERYONE,
            "Deny",
            r"%OSDRIVE%\Users\*\Downloads\*",
        ));
    }
    v
}

fn is_ours(n: &Node) -> bool {
    n.attribute("Id")
        .map(|id| id.to_ascii_lowercase().starts_with(OUR_ID_PREFIX))
        .unwrap_or(false)
}

fn exe_collection<'a, 'i>(doc: &'a Document<'i>) -> Option<Node<'a, 'i>> {
    doc.root_element().children().find(|n| {
        n.is_element()
            && n.has_tag_name("RuleCollection")
            && n.attribute("Type")
                .map(|t| t.eq_ignore_ascii_case("Exe"))
                .unwrap_or(false)
    })
}

/// What the local policy currently looks like for our purposes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Inspect {
    pub exe_mode: String,
    pub foreign_rules: usize,
    pub our_ids: Vec<String>,
}

/// (non-Kestrel rule ids, (collection type, configured mode)).
type ForeignView = (Vec<String>, Vec<(String, String)>);

/// Lower-case ids of every non-Kestrel rule in every collection, plus the
/// collections whose enforcement mode is configured (not `NotConfigured`).
fn foreign_ids_and_modes(xml: &str) -> Result<ForeignView, String> {
    if xml.trim().is_empty() {
        return Ok((vec![], vec![]));
    }
    let doc = Document::parse(xml).map_err(|e| format!("AppLocker XML parse error: {e}"))?;
    let mut ids = Vec::new();
    let mut modes = Vec::new();
    for c in doc
        .root_element()
        .children()
        .filter(|n| n.is_element() && n.has_tag_name("RuleCollection"))
    {
        let ty = c.attribute("Type").unwrap_or("").to_ascii_lowercase();
        let mode = c.attribute("EnforcementMode").unwrap_or("NotConfigured");
        if !mode.eq_ignore_ascii_case("NotConfigured") {
            modes.push((ty.clone(), mode.to_ascii_lowercase()));
        }
        for r in c
            .children()
            .filter(|n| n.is_element() && n.tag_name().name().ends_with("Rule"))
        {
            if !is_ours(&r) {
                ids.push(r.attribute("Id").unwrap_or("?").to_ascii_lowercase());
            }
        }
    }
    Ok((ids, modes))
}

/// Is AppLocker managed outside the local policy (GPO / MDM)? True when the
/// effective policy has a non-Kestrel rule the local policy does not have,
/// or configures a collection's mode the local policy leaves unconfigured.
pub fn managed_elsewhere(local_xml: &str, effective_xml: &str) -> Result<bool, String> {
    let (eff_ids, eff_modes) = foreign_ids_and_modes(effective_xml)?;
    let (loc_ids, loc_modes) = foreign_ids_and_modes(local_xml)?;
    if eff_ids.iter().any(|i| !loc_ids.contains(i)) {
        return Ok(true);
    }
    Ok(eff_modes
        .iter()
        .any(|(t, _)| !loc_modes.iter().any(|(lt, _)| lt == t)))
}

/// Remove Kestrel's *allow* rules from the local policy (keep everything
/// else). Used when a domain policy appeared: our allow rules would widen it.
pub fn strip_our_allow_rules(local_xml: &str) -> Edit {
    if local_xml.trim().is_empty() {
        return Edit::Unchanged;
    }
    let Ok(doc) = Document::parse(local_xml) else {
        return Edit::Refused("AppLocker XML parse error".into());
    };
    let allow_ids = [
        ID_ALLOW_ALL,
        ID_ALLOW_ADMINS,
        ID_ALLOW_PROGRAMFILES,
        ID_ALLOW_WINDIR,
    ];
    let mut ranges: Vec<std::ops::Range<usize>> = doc
        .descendants()
        .filter(|n| {
            n.is_element()
                && n.attribute("Id")
                    .map(|id| allow_ids.contains(&id.to_ascii_lowercase().as_str()))
                    .unwrap_or(false)
        })
        .map(|n| n.range())
        .collect();
    if ranges.is_empty() {
        return Edit::Unchanged;
    }
    ranges.sort_by_key(|r| std::cmp::Reverse(r.start));
    let mut out = local_xml.to_string();
    for r in ranges {
        out.replace_range(r, "");
    }
    Edit::Write(out)
}

/// H9 entry point: decide the local-policy edit from the local *and*
/// effective policies. A policy managed by GPO / MDM is never touched
/// (`Refused(SKIPPED_DOMAIN_POLICY)`), except that stale Kestrel allow rules
/// are removed from the local policy (`Write` of the stripped document is
/// returned through `cleanup`).
pub fn plan_edit(local_xml: &str, effective_xml: &str, want: Want) -> (Edit, Option<Edit>) {
    match managed_elsewhere(local_xml, effective_xml) {
        Err(e) => (Edit::Refused(e), None),
        Ok(true) => {
            let cleanup = match strip_our_allow_rules(local_xml) {
                Edit::Write(x) => Some(Edit::Write(x)),
                _ => None,
            };
            (Edit::Refused(SKIPPED_DOMAIN_POLICY.into()), cleanup)
        }
        Ok(false) => (edit_local_policy(local_xml, want), None),
    }
}

pub fn inspect(xml: &str) -> Result<Inspect, String> {
    if xml.trim().is_empty() {
        return Ok(Inspect {
            exe_mode: "NotConfigured".into(),
            ..Default::default()
        });
    }
    let doc = Document::parse(xml).map_err(|e| format!("AppLocker XML parse error: {e}"))?;
    let mut out = Inspect {
        exe_mode: "NotConfigured".into(),
        ..Default::default()
    };
    if let Some(c) = exe_collection(&doc) {
        out.exe_mode = c
            .attribute("EnforcementMode")
            .unwrap_or("NotConfigured")
            .to_string();
        for r in c
            .children()
            .filter(|n| n.is_element() && n.tag_name().name().ends_with("Rule"))
        {
            if is_ours(&r) {
                out.our_ids
                    .push(r.attribute("Id").unwrap_or_default().to_ascii_lowercase());
            } else {
                out.foreign_rules += 1;
            }
        }
    }
    Ok(out)
}

/// Is the desired control in effect according to an *effective* policy XML?
pub fn in_effect(xml: &str, want: Want) -> bool {
    let Ok(i) = inspect(xml) else { return false };
    if !i.exe_mode.eq_ignore_ascii_case("Enabled") {
        return false;
    }
    let has = |id: &str| i.our_ids.iter().any(|x| x == id);
    (!want.block_mshta || has(ID_DENY_MSHTA_PUBLISHER) || has(ID_DENY_MSHTA_PATH))
        && (!want.block_user_path_exec || (has(ID_DENY_USER_TEMP) && has(ID_DENY_USER_DOWNLOADS)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Write this XML with `Set-AppLockerPolicy -XmlPolicy` (replaces local policy).
    Write(String),
    /// Nothing to change.
    Unchanged,
    /// Refused for safety, with reason.
    Refused(String),
}

/// Compute the new local policy from the current local policy XML.
pub fn edit_local_policy(local_xml: &str, want: Want) -> Edit {
    let current = match inspect(local_xml) {
        Ok(i) => i,
        Err(e) => return Edit::Refused(e),
    };
    let foreign = current.foreign_rules > 0;
    if foreign && want.any() && !current.exe_mode.eq_ignore_ascii_case("Enabled") {
        return Edit::Refused(format!(
            "existing AppLocker Exe rules are in '{}' mode; refusing to switch someone else's policy to Enabled",
            current.exe_mode
        ));
    }
    let rules = our_rules(want, !foreign);
    // Mode: Enabled when we have rules; otherwise keep the existing mode
    // (or NotConfigured when nothing remains).
    let mode = if want.any() {
        "Enabled".to_string()
    } else if foreign {
        current.exe_mode.clone()
    } else {
        "NotConfigured".to_string()
    };

    let new_xml = if local_xml.trim().is_empty() {
        if !want.any() {
            return Edit::Unchanged;
        }
        format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="{mode}">{}</RuleCollection></AppLockerPolicy>"#,
            rules.join("")
        )
    } else {
        let doc = match Document::parse(local_xml) {
            Ok(d) => d,
            Err(e) => return Edit::Refused(format!("AppLocker XML parse error: {e}")),
        };
        let root = doc.root_element();
        match exe_collection(&doc) {
            Some(c) => {
                let mut inner = String::new();
                for ch in c.children() {
                    if ch.is_element() && is_ours(&ch) {
                        continue;
                    }
                    if ch.is_element() || ch.is_comment() {
                        inner.push_str(&local_xml[ch.range()]);
                    }
                }
                inner.push_str(&rules.join(""));
                let replacement = format!(
                    r#"<RuleCollection Type="Exe" EnforcementMode="{mode}">{inner}</RuleCollection>"#
                );
                let r = c.range();
                format!(
                    "{}{}{}",
                    &local_xml[..r.start],
                    replacement,
                    &local_xml[r.end..]
                )
            }
            None => {
                if !want.any() {
                    return Edit::Unchanged;
                }
                let r = root.range();
                let end_tag = "</AppLockerPolicy>";
                let insert = format!(
                    r#"<RuleCollection Type="Exe" EnforcementMode="{mode}">{}</RuleCollection>"#,
                    rules.join("")
                );
                let src = &local_xml[r.clone()];
                if let Some(pos) = src.rfind(end_tag) {
                    let abs = r.start + pos;
                    format!("{}{}{}", &local_xml[..abs], insert, &local_xml[abs..])
                } else {
                    // Self-closing root: <AppLockerPolicy Version="1" />
                    format!(
                        r#"{}<AppLockerPolicy Version="1">{insert}</AppLockerPolicy>{}"#,
                        &local_xml[..r.start],
                        &local_xml[r.end..]
                    )
                }
            }
        }
    };
    // Idempotence: same rules + mode → unchanged.
    match inspect(&new_xml) {
        Ok(n) if n == current && normalize_ws(&new_xml) == normalize_ws(local_xml) => {
            Edit::Unchanged
        }
        Ok(n) => {
            let mut a = n.our_ids.clone();
            a.sort();
            let mut b = current.our_ids.clone();
            b.sort();
            if a == b && n.exe_mode == current.exe_mode && n.foreign_rules == current.foreign_rules
            {
                Edit::Unchanged
            } else {
                Edit::Write(new_xml)
            }
        }
        Err(e) => Edit::Refused(format!("generated invalid XML: {e}")),
    }
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_LOCAL: &str = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Appx" EnforcementMode="NotConfigured" /><RuleCollection Type="Dll" EnforcementMode="NotConfigured" /><RuleCollection Type="Exe" EnforcementMode="NotConfigured" /><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /><RuleCollection Type="Script" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;

    #[test]
    fn fresh_machine() {
        let want = Want {
            block_mshta: true,
            block_user_path_exec: false,
        };
        let Edit::Write(x) = edit_local_policy(EMPTY_LOCAL, want) else {
            panic!()
        };
        let i = inspect(&x).unwrap();
        assert_eq!(i.exe_mode, "Enabled");
        assert_eq!(i.foreign_rules, 0);
        // H9: the standard default rules, never "allow Everyone *".
        assert!(!i.our_ids.contains(&ID_ALLOW_ALL.to_string()));
        assert!(!x.contains(
            r#"UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="*""#
        ));
        assert!(i.our_ids.contains(&ID_ALLOW_PROGRAMFILES.to_string()));
        assert!(i.our_ids.contains(&ID_ALLOW_WINDIR.to_string()));
        assert!(i.our_ids.contains(&ID_ALLOW_ADMINS.to_string()));
        assert!(x.contains(r"%PROGRAMFILES%\*") && x.contains(r"%WINDIR%\*"));
        assert!(in_effect(&x, want));
        assert!(!in_effect(
            &x,
            Want {
                block_mshta: true,
                block_user_path_exec: true
            }
        ));
        // Other collections untouched.
        assert!(x.contains(r#"<RuleCollection Type="Dll" EnforcementMode="NotConfigured" />"#));
        // Idempotent.
        assert_eq!(edit_local_policy(&x, want), Edit::Unchanged);
        // Turning everything off removes our rules and resets the mode.
        let Edit::Write(y) = edit_local_policy(&x, Want::default()) else {
            panic!()
        };
        let j = inspect(&y).unwrap();
        assert!(j.our_ids.is_empty());
        assert_eq!(j.exe_mode, "NotConfigured");
    }

    #[test]
    fn empty_document() {
        let want = Want {
            block_mshta: false,
            block_user_path_exec: true,
        };
        let Edit::Write(x) = edit_local_policy("", want) else {
            panic!()
        };
        assert!(in_effect(&x, want));
        assert_eq!(edit_local_policy("", Want::default()), Edit::Unchanged);
    }

    #[test]
    fn foreign_policy() {
        let enabled = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="(Default Rule) All files located in the Program Files folder" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#;
        let want = Want {
            block_mshta: true,
            block_user_path_exec: false,
        };
        let Edit::Write(x) = edit_local_policy(enabled, want) else {
            panic!()
        };
        let i = inspect(&x).unwrap();
        assert_eq!(i.foreign_rules, 1);
        // No allow rules added on top of someone else's whitelist.
        assert!(!i.our_ids.contains(&ID_ALLOW_ALL.to_string()));
        assert!(!i.our_ids.contains(&ID_ALLOW_PROGRAMFILES.to_string()));
        assert!(x.contains("921cc481-6e17-4653-8f75-050b80acca20"));
        // Audit-mode foreign policy: refuse.
        let audit = enabled.replace("\"Enabled\"", "\"AuditOnly\"");
        assert!(matches!(edit_local_policy(&audit, want), Edit::Refused(_)));
        // Removing ours keeps theirs and their mode.
        let Edit::Write(y) = edit_local_policy(&x, Want::default()) else {
            panic!()
        };
        let j = inspect(&y).unwrap();
        assert_eq!(j.foreign_rules, 1);
        assert_eq!(j.exe_mode, "Enabled");
    }

    #[test]
    fn domain_policy_is_never_touched() {
        let want = Want {
            block_mshta: true,
            block_user_path_exec: true,
        };
        // GPO allowlist visible only in the effective policy.
        let effective = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="11111111-2222-3333-4444-555555555555" Name="Corp: Program Files" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#;
        let (e, cleanup) = plan_edit(EMPTY_LOCAL, effective, want);
        assert_eq!(e, Edit::Refused(SKIPPED_DOMAIN_POLICY.into()));
        assert!(cleanup.is_none());
        // GPO only configures the Script collection mode: still "managed".
        let script_only = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Script" EnforcementMode="AuditOnly" /></AppLockerPolicy>"#;
        assert!(managed_elsewhere(EMPTY_LOCAL, script_only).unwrap());
        // A legacy local allow-all left by an older agent is removed when a
        // domain policy shows up (it would widen the domain allowlist).
        let legacy_local = format!(
            r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled">{}</RuleCollection></AppLockerPolicy>"#,
            path_rule(ID_ALLOW_ALL, "old", SID_EVERYONE, "Allow", "*")
                + &path_rule(ID_DENY_MSHTA_PATH, "deny", SID_EVERYONE, "Deny", "x")
        );
        let eff_with_ours = effective.replace(
            "</RuleCollection>",
            &format!(
                "{}</RuleCollection>",
                path_rule(ID_ALLOW_ALL, "old", SID_EVERYONE, "Allow", "*")
            ),
        );
        let (e, cleanup) = plan_edit(&legacy_local, &eff_with_ours, want);
        assert_eq!(e, Edit::Refused(SKIPPED_DOMAIN_POLICY.into()));
        let Some(Edit::Write(x)) = cleanup else {
            panic!()
        };
        assert!(!x.contains(ID_ALLOW_ALL));
        assert!(x.contains(ID_DENY_MSHTA_PATH), "deny rules are kept");
        // Effective == local (no GPO): normal edit.
        let (e, _) = plan_edit(EMPTY_LOCAL, EMPTY_LOCAL, want);
        assert!(matches!(e, Edit::Write(_)));
        let (e, _) = plan_edit("", "", want);
        assert!(matches!(e, Edit::Write(_)));
        // Local foreign rules (configured locally, no GPO) → normal edit path.
        let enabled_local = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Exe" EnforcementMode="Enabled"><FilePathRule Id="921cc481-6e17-4653-8f75-050b80acca20" Name="x" Description="" UserOrGroupSid="S-1-1-0" Action="Allow"><Conditions><FilePathCondition Path="%PROGRAMFILES%\*" /></Conditions></FilePathRule></RuleCollection></AppLockerPolicy>"#;
        assert!(!managed_elsewhere(enabled_local, enabled_local).unwrap());
    }

    #[test]
    fn no_exe_collection() {
        let doc = r#"<AppLockerPolicy Version="1"><RuleCollection Type="Msi" EnforcementMode="NotConfigured" /></AppLockerPolicy>"#;
        let want = Want {
            block_mshta: true,
            block_user_path_exec: true,
        };
        let Edit::Write(x) = edit_local_policy(doc, want) else {
            panic!()
        };
        assert!(in_effect(&x, want));
        assert!(x.contains(r#"Type="Msi""#));
        let selfclosing = r#"<AppLockerPolicy Version="1" />"#;
        let Edit::Write(z) = edit_local_policy(selfclosing, want) else {
            panic!()
        };
        assert!(in_effect(&z, want));
    }
}
