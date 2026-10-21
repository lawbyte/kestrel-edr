//! Ransomware canary documents (decoys) for the file-activity sensor.
//!
//! Small, believable documents are planted in the **roots** of each
//! profile's Documents (3) and Pictures (2) folders. Names start with `!` or
//! `0` so they come first in NTFS directory order (upper-cased UTF-16
//! collation: `!` 0x21 < `0` 0x30 < letters) — encryptors walking a folder
//! with `FindFirstFile` hit them early. Content is a valid minimal file of
//! the claimed type (OOXML zip, PDF, JPEG/JFIF) so magic-byte checks pass.
//!
//! Fresh-install lab 2026-10-21: the decoys used to be visible (and two of
//! them sat on the Desktop), so an employee tidying up moved or deleted
//! them and tripped RW-07. Now every decoy carries **FILE_ATTRIBUTE_HIDDEN**
//! (not SYSTEM) and none is planted on the Desktop:
//! * Research (`docs/research/notes/ransomware-decoy-attributes.md`): no
//!   family found skips hidden *files* by default (Conti and Babuk source:
//!   no attribute check at all, Babuk resets attributes to NORMAL); LockBit
//!   3.0 has an optional `skip_hidden_folders` (folders, and our decoys sit
//!   in normal folders); LockBit 2.0 applies its name / extension checks
//!   only to non-SYSTEM files, so SYSTEM adds risk without detection gain.
//! * Desktop is the folder employees look at all day (and the one where
//!   "show hidden files" users would still see the decoys); its traversal
//!   advantage (reached just before Documents on a depth-first walk) is
//!   small because modern encryptors spread files over many threads.
//!   Earlier Desktop decoys are removed on upgrade when provably ours
//!   ([`RETIRED_DECOYS`]).
//!
//! Ownership ([`owned`], lab 2026-10-21): a file at a decoy path is
//! Kestrel's only when its SHA-256 is the one recorded for that path in
//! `rcanaries.json` (any version) or the content of a decoy some released
//! version planted ([`KNOWN_DECOY_SHA256`]). Only such files are armed,
//! given attributes or removed; a file with unknown content may be the
//! user's, so the decoy moves to the next free name ([`candidate_names`]).
//!
//! Safety (same rules as the credential canaries in [`crate::canary`]):
//! never overwrite an existing file, never follow a reparse point anywhere
//! in the path, create with `create_new`, verify the final path. Folders
//! redirected into OneDrive are skipped (decoys would sync to the cloud).
//! The registry of the armed decoys (with SHA-256) lives in
//! `<state>\rcanaries.json`; [`remove_all`] (uninstall) removes every
//! provably-ours decoy of any version, registry or not.

use crate::canary::{self, CanaryRecord, CanaryRegistry, DecoyFs, Probe, RemoveResult};
use kestrel_common::DataCategory;
use kestrel_platform::CanarySpec;
use sha2::Digest;
use std::path::Path;

/// Registry file name in the agent state directory.
pub const REGISTRY_FILE: &str = "rcanaries.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocKind {
    Docx,
    Xlsx,
    Pdf,
    Jpg,
}

/// (profile sub-folder, file name, kind)
pub const DECOYS: &[(&str, &str, DocKind)] = &[
    ("Documents", "!Payroll Q3.xlsx", DocKind::Xlsx),
    ("Documents", "!Accounts summary.docx", DocKind::Docx),
    ("Documents", "0 Contract - signed.pdf", DocKind::Pdf),
    ("Pictures", "!IMG_0001.jpg", DocKind::Jpg),
    ("Pictures", "0 Scan 0917.jpg", DocKind::Jpg),
];

/// Attributes of every ransomware decoy (see the module docs: HIDDEN only).
pub const DECOY_ATTRS: u32 = canary::ATTR_HIDDEN;

/// Decoys planted by earlier versions and no longer wanted: (profile
/// sub-folder, file name). Removed on upgrade only while they still hold
/// exactly what Kestrel wrote; a decoy the user changed is forgotten and
/// left in place.
pub const RETIRED_DECOYS: &[(&str, &str)] = &[
    ("Desktop", "!Passwords.docx"),
    ("Desktop", "0 Invoice 0917.pdf"),
];

/// Fixed timestamp inside the OOXML zips (content must be deterministic so
/// the registry can recognise our own files).
const ZIP_TIME_MS: i64 = 1_735_689_600_000; // 2025-01-01

fn filler(seed: &str, n: usize) -> String {
    // Deterministic, plain-looking text (no randomness: content is hashed).
    const WORDS: &[&str] = &[
        "account",
        "balance",
        "quarter",
        "payment",
        "invoice",
        "total",
        "approved",
        "review",
        "budget",
        "transfer",
        "client",
        "summary",
        "period",
        "amount",
        "reference",
        "notes",
    ];
    let mut h = crate::regdiff::fnv1a(seed.as_bytes());
    let mut s = String::with_capacity(n + 16);
    while s.len() < n {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        s.push_str(WORDS[(h % WORDS.len() as u64) as usize]);
        s.push(if h.is_multiple_of(11) { '\n' } else { ' ' });
    }
    s
}

fn ooxml(kind: DocKind, seed: &str) -> Vec<u8> {
    let text = filler(seed, 6000);
    let mut z = crate::zipw::ZipWriter::new(Vec::new(), ZIP_TIME_MS);
    let r = (|| -> std::io::Result<Vec<u8>> {
        match kind {
            DocKind::Docx => {
                z.add("[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#)?;
                z.add("_rels/.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#)?;
                let doc = format!(
                    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>"#
                );
                z.add("word/document.xml", doc.as_bytes())?;
            }
            _ => {
                z.add("[Content_Types].xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>"#)?;
                z.add("_rels/.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>"#)?;
                z.add("xl/workbook.xml", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>"#)?;
                z.add("xl/_rels/workbook.xml.rels", br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>"#)?;
                let sheet = format!(
                    r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>{text}</t></is></c></row></sheetData></worksheet>"#
                );
                z.add("xl/worksheets/sheet1.xml", sheet.as_bytes())?;
            }
        }
        z.finish()
    })();
    r.unwrap_or_default()
}

fn pdf(seed: &str) -> Vec<u8> {
    let text: String = filler(seed, 4000)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == ' ')
        .collect();
    let stream = format!("BT /F1 10 Tf 40 800 Td ({text}) Tj ET");
    let mut out = String::from("%PDF-1.4\n%\u{e2}\u{e3}\u{cf}\u{d3}\n");
    let mut offs = Vec::new();
    let objs = [
        "<< /Type /Catalog /Pages 2 0 R >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>".to_string(),
        format!("<< /Length {} >>\nstream\n{stream}\nendstream", stream.len()),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut bytes = out.clone().into_bytes();
    out.clear();
    for (i, o) in objs.iter().enumerate() {
        offs.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = bytes.len();
    let mut x = format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1);
    for o in offs {
        x.push_str(&format!("{o:010} 00000 n \n"));
    }
    x.push_str(&format!(
        "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
        objs.len() + 1
    ));
    bytes.extend_from_slice(x.as_bytes());
    bytes
}

fn jpg(seed: &str) -> Vec<u8> {
    // SOI, APP0 JFIF 1.01, COM segment(s) with filler, EOI.
    let mut b = vec![
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x01, 0x00,
        0x48, 0x00, 0x48, 0x00, 0x00,
    ];
    let text = filler(seed, 12_000);
    for chunk in text.as_bytes().chunks(60_000) {
        b.extend_from_slice(&[0xFF, 0xFE]);
        b.extend_from_slice(&((chunk.len() + 2) as u16).to_be_bytes());
        b.extend_from_slice(chunk);
    }
    b.extend_from_slice(&[0xFF, 0xD9]);
    b
}

/// Content of a decoy (deterministic for a given name).
pub fn content(kind: DocKind, name: &str) -> Vec<u8> {
    match kind {
        DocKind::Docx | DocKind::Xlsx => ooxml(kind, name),
        DocKind::Pdf => pdf(name),
        DocKind::Jpg => jpg(name),
    }
}

/// Is a profile folder redirected into OneDrive (or otherwise not the
/// plain `<profile>\<Folder>`)? Decoys are only planted in plain folders.
fn plain_folder(profile: &str, folder: &str) -> bool {
    let p = profile.trim_end_matches(['\\', '/']);
    !p.is_empty() && !folder.contains(['\\', '/']) && !p.to_ascii_lowercase().contains("onedrive")
}

/// Specs for one profile directory (`C:\Users\bob`). Only folders that
/// already exist are used; nothing is created above the decoy itself.
pub fn specs_for_profile(profile: &str, folder_exists: impl Fn(&str) -> bool) -> Vec<CanarySpec> {
    let base = profile.trim_end_matches(['\\', '/']);
    let mut out = Vec::new();
    for (folder, name, kind) in DECOYS {
        if !plain_folder(base, folder) {
            continue;
        }
        let dir = format!(r"{base}\{folder}");
        if !folder_exists(&dir) {
            continue;
        }
        out.push(CanarySpec {
            path: format!(r"{dir}\{name}"),
            // No ransomware class in DataCategory yet (contract gap); the
            // category is not persisted by the planter.
            category: DataCategory::PasswordManager,
            content: content(*kind, name),
            is_dir: false,
        });
    }
    out
}

// ------------------------------------------------------------- ownership

/// SHA-256 of every decoy content any released Kestrel version planted, for
/// migration and uninstall ([`owned`]). **Append only**: a content change
/// adds the new hashes and keeps the old ones, or decoys planted by older
/// versions can no longer be recognised (lab 2026-10-21). The generator
/// (`content`, `zipw`, `fnv1a`) is byte-identical in every commit that
/// shipped decoys (56ec926, 655e352, 92fd9d4, b6c8a52 = 1.1.3), so this is
/// one hash per decoy name, current and retired.
pub const KNOWN_DECOY_SHA256: &[&str] = &[
    // Documents
    "75d96a5a8d110cf956427023c6800842f8f07e342853f863ea351c78792d0fb2", // !Payroll Q3.xlsx
    "9096b07d0c558de8415202855b499e46d8a949c166f08036ce996d857cb10418", // !Accounts summary.docx
    "d1a1faba9a497d48762da15e9dd3d05401bfee160163aa371d87d3ebc454efa8", // 0 Contract - signed.pdf
    // Desktop (retired after 1.1.2)
    "e179ea40aab824cd172dfd8ff470d2e1b914776972f3b3a0ba918f7968ce4cc5", // !Passwords.docx
    "fdf18ab3366757b2bc737d8a8e3e51c63430a15f7f7f699bc28d7d1ac7e4a97d", // 0 Invoice 0917.pdf
    // Pictures
    "c6dfac87991ebd26ec21767458875916cc5e1641e0aea6367ccb3f899cc2bc8d", // !IMG_0001.jpg
    "06aa1d6f66abd39c0e0d6bc993429acfe427ac0b314cad061b9e2c5f9b153a27", // 0 Scan 0917.jpg
];

/// Can Kestrel prove it planted the file at a decoy path whose content hash
/// is `sha`? Only when `sha` is the hash recorded for that path in a
/// `rcanaries.json` (any version) or the hash of a decoy content some
/// released version planted. Anything else may be a real user file: never
/// armed, never removed, never given attributes.
pub fn owned(sha: &str, recorded: Option<&str>) -> bool {
    recorded.is_some_and(|r| r.eq_ignore_ascii_case(sha))
        || KNOWN_DECOY_SHA256
            .iter()
            .any(|k| k.eq_ignore_ascii_case(sha))
}

/// How many names a decoy slot may use: the layout name, then
/// `<stem> 2.<ext>` … `<stem> 5.<ext>` when a file Kestrel cannot prove it
/// planted holds the name (it may be the user's).
pub const MAX_NAME_CANDIDATES: usize = 5;

/// The names a decoy slot may use, in order (see [`MAX_NAME_CANDIDATES`]).
/// They keep the `!` / `0` prefix and the extension.
pub fn candidate_names(name: &str) -> Vec<String> {
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s, Some(e)),
        _ => (name, None),
    };
    let mut out = vec![name.to_string()];
    for i in 2..=MAX_NAME_CANDIDATES {
        out.push(match ext {
            Some(e) => format!("{stem} {i}.{e}"),
            None => format!("{stem} {i}"),
        });
    }
    out
}

fn join(dir: &str, name: &str) -> String {
    format!(r"{}\{name}", dir.trim_end_matches(['\\', '/']))
}

/// Every path in `profile` where any version may have planted a decoy (the
/// current layout, retired names, and every candidate name of both).
pub fn all_decoy_paths(profile: &str) -> Vec<String> {
    let base = profile.trim_end_matches(['\\', '/']);
    let mut out = Vec::new();
    let names = DECOYS
        .iter()
        .map(|(f, n, _)| (*f, *n))
        .chain(RETIRED_DECOYS.iter().copied());
    for (folder, name) in names {
        if base.is_empty() || !plain_folder(base, folder) {
            continue;
        }
        for c in candidate_names(name) {
            out.push(join(&format!(r"{base}\{folder}"), &c));
        }
    }
    out
}

// -------------------------------------------------------------- planting

/// Plant decoys for `profiles` (path-based [`canary::StdFs`]; the Windows
/// agent uses [`plant_with`] and the handle-based `SafeDecoyFs`). Returns the
/// paths that now hold our decoys.
pub fn plant(profiles: &[String], reg: &mut CanaryRegistry) -> Vec<String> {
    plant_with(
        &canary::StdFs {
            set_attrs: &|_, _| {},
        },
        profiles,
        reg,
    )
}

/// Plant / adopt decoys for `profiles` and rebuild `reg` so it lists
/// exactly the armed decoys. Returns their paths.
///
/// Per decoy slot (profile × [`DECOYS`] entry), over its
/// [`candidate_names`]:
/// * a file Kestrel can prove it planted ([`owned`]) is **adopted**: armed,
///   recorded with its actual hash, and given [`DECOY_ATTRS`] through the
///   verified handle (never rewritten, so a decoy from an older version is
///   not touched beyond its attributes);
/// * otherwise the decoy is written (hidden) at the first free name;
/// * a file it cannot prove it planted is never armed, never changed and
///   its stale record is dropped (lab 2026-10-21: a visible, unproven
///   `!Accounts summary.docx` stayed listed in `rcanaries.json`).
///
/// Retired decoys ([`RETIRED_DECOYS`]) that are provably ours are removed.
pub fn plant_with(fs: &dyn DecoyFs, profiles: &[String], reg: &mut CanaryRegistry) -> Vec<String> {
    let old = std::mem::take(&mut reg.planted);
    let recorded = |path: &str| -> Option<String> {
        old.get(&crate::ntpath::norm_key(path))
            .and_then(|r| r.sha256.clone())
    };
    let mut armed = Vec::new();
    let mut planned: std::collections::HashSet<String> = Default::default();
    for profile in profiles {
        let base = profile.trim_end_matches(['\\', '/']);
        if base.is_empty() {
            continue;
        }
        // Retired names: remove what is provably ours.
        for (folder, name) in RETIRED_DECOYS {
            if !plain_folder(base, folder) {
                continue;
            }
            let path = join(&format!(r"{base}\{folder}"), name);
            planned.insert(crate::ntpath::norm_key(&path));
            if let Probe::File(sha) = fs.probe(Path::new(&path)) {
                if owned(&sha, recorded(&path).as_deref())
                    && fs.remove_if_ours(Path::new(&path), &sha) == RemoveResult::Removed
                {
                    tracing::info!(path = %path, "retired ransomware decoy removed");
                }
            }
        }
        for (folder, name, kind) in DECOYS {
            if !plain_folder(base, folder) {
                continue;
            }
            let dir = format!(r"{base}\{folder}");
            if fs.probe(Path::new(&dir)) != Probe::Dir {
                continue;
            }
            let data = content(*kind, name);
            let data_sha = crate::vault::hex(&sha2::Sha256::digest(&data));
            let mut first_free: Option<String> = None;
            let mut adopted = false;
            for cand in candidate_names(name) {
                let path = join(&dir, &cand);
                let k = crate::ntpath::norm_key(&path);
                planned.insert(k.clone());
                match fs.probe(Path::new(&path)) {
                    Probe::File(sha) if owned(&sha, recorded(&path).as_deref()) => {
                        match fs.ensure_attributes(Path::new(&path), &sha, DECOY_ATTRS) {
                            Ok(true) => tracing::info!(path = %path, "decoy attributes re-applied"),
                            Ok(false) => {}
                            Err(e) => {
                                tracing::warn!(path = %path, "decoy attributes not applied: {e}")
                            }
                        }
                        reg.planted.insert(
                            k,
                            CanaryRecord {
                                path: path.clone(),
                                sha256: Some(sha),
                            },
                        );
                        armed.push(path);
                        adopted = true;
                    }
                    Probe::File(_) => {
                        tracing::warn!(path = %path, "file at a decoy name is not Kestrel's (unknown content): not armed, left alone");
                    }
                    Probe::Absent => {
                        if first_free.is_none() {
                            first_free = Some(path);
                        }
                    }
                    Probe::Dir | Probe::Foreign => {
                        tracing::warn!(path = %path, "decoy name taken by a folder / link / unreadable object: skipped");
                    }
                }
            }
            if adopted {
                continue;
            }
            let Some(path) = first_free else {
                tracing::warn!(dir = %dir, decoy = %name, "no free decoy name; decoy not planted");
                continue;
            };
            match fs.write_file(Path::new(&path), &data, None, DECOY_ATTRS) {
                Ok(()) => {
                    reg.planted.insert(
                        crate::ntpath::norm_key(&path),
                        CanaryRecord {
                            path: path.clone(),
                            sha256: Some(data_sha),
                        },
                    );
                    armed.push(path);
                }
                Err(e) => tracing::warn!(path = %path, "planting decoy failed: {e}"),
            }
        }
    }
    // Records outside the planned paths (a profile not enumerated now, an
    // older layout): kept only while the file is still provably ours, so
    // uninstall finds them; they are not armed.
    for (k, rec) in old {
        if planned.contains(&k) {
            continue;
        }
        if let (Probe::File(sha), Some(r)) = (fs.probe(Path::new(&rec.path)), rec.sha256.as_deref())
        {
            if owned(&sha, Some(r)) {
                reg.retained.insert(k, rec);
            }
        }
    }
    armed
}

// --------------------------------------------------------------- removal

/// Remove every decoy Kestrel can prove it planted ([`owned`]), from any
/// version: the registry's records (current and retained) plus every
/// decoy path of every version in `profiles` ([`all_decoy_paths`]), so a
/// decoy whose record was lost is still found. Handle-based through `fs`
/// (never follows a link); files with unknown content are left alone. The
/// registry keeps only records that could not be removed because of an I/O
/// failure. Returns the removed paths.
pub fn remove_all_with(
    fs: &dyn DecoyFs,
    reg: &mut CanaryRegistry,
    profiles: &[String],
) -> Vec<String> {
    let mut recorded: std::collections::BTreeMap<String, (String, Option<String>)> = reg
        .planted
        .iter()
        .chain(reg.retained.iter())
        .map(|(k, r)| (k.clone(), (r.path.clone(), r.sha256.clone())))
        .collect();
    for p in profiles {
        for path in all_decoy_paths(p) {
            recorded
                .entry(crate::ntpath::norm_key(&path))
                .or_insert((path, None));
        }
    }
    let mut removed = Vec::new();
    let mut keep = std::collections::BTreeMap::new();
    for (k, (path, rec_sha)) in recorded {
        let Probe::File(sha) = fs.probe(Path::new(&path)) else {
            continue;
        };
        if !owned(&sha, rec_sha.as_deref()) {
            continue;
        }
        // The hash is re-checked on the delete handle itself.
        match fs.remove_if_ours(Path::new(&path), &sha) {
            RemoveResult::Removed => removed.push(path),
            RemoveResult::Failed => {
                keep.insert(
                    k,
                    CanaryRecord {
                        path,
                        sha256: Some(sha),
                    },
                );
            }
            RemoveResult::Gone | RemoveResult::NotOurs => {}
        }
    }
    reg.planted = keep;
    reg.retained.clear();
    removed
}

/// Path-based [`remove_all_with`] (tests, non-Windows).
pub fn remove_planted(reg: &mut CanaryRegistry, profiles: &[String]) -> Vec<String> {
    remove_all_with(
        &canary::StdFs {
            set_attrs: &|_, _| {},
        },
        reg,
        profiles,
    )
}

// ------------------------------------------------------------ poller logic

/// How a decoy's (size, mtime) stamp changed between two polls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StampChange {
    Same,
    /// Still there, different size / mtime: an in-place write.
    Modified,
    /// Was there, is gone (renamed, moved, deleted).
    Gone,
    /// Was absent, is back.
    Appeared,
}

pub fn stamp_change<T: PartialEq>(old: &Option<T>, new: &Option<T>) -> StampChange {
    match (old, new) {
        (Some(a), Some(b)) if a == b => StampChange::Same,
        (Some(_), Some(_)) => StampChange::Modified,
        (Some(_), None) => StampChange::Gone,
        (None, Some(_)) => StampChange::Appeared,
        (None, None) => StampChange::Same,
    }
}

/// How long a disappearance noticed by the poller waits for the Kernel-File
/// rename / delete event (File session flush 1 s + translation).
pub const GONE_GRACE_MS: i64 = 4_000;
/// A Kernel-File hit this long before the poller noticed the disappearance
/// still explains it (poll interval 2 s plus ETW delivery).
pub const GONE_LOOKBACK_MS: i64 = 10_000;

/// Decision for a decoy the poller found gone at `noticed`: `Some(false)`
/// = Kernel-File already reported it (rename / delete with the real actor,
/// e.g. Explorer moving it to the Recycle Bin): nothing more to report;
/// `Some(true)` = no kernel event within the grace period: report it (with
/// the opener heuristic, V-H9); `None` = keep waiting.
///
/// Fresh-install lab 2026-10-21: the poller reported every disappearance
/// as an *in-place rewrite* blamed on the last process that had opened the
/// decoy, so an employee deleting a desktop decoy in Explorer could be
/// reported as a Critical RW-07 against an unrelated opener (or as a remote
/// SMB writer when the System process had opened it).
pub fn gone_verdict(noticed: i64, now: i64, kernel_hit: bool) -> Option<bool> {
    if kernel_hit {
        Some(false)
    } else if now - noticed >= GONE_GRACE_MS {
        Some(true)
    } else {
        None
    }
}

/// Load / save the decoy registry.
pub fn load_registry(state_dir: &Path) -> CanaryRegistry {
    std::fs::read(state_dir.join(REGISTRY_FILE))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

pub fn save_registry(state_dir: &Path, reg: &CanaryRegistry) -> std::io::Result<()> {
    let b = serde_json::to_vec_pretty(reg).map_err(std::io::Error::other)?;
    let p = state_dir.join(REGISTRY_FILE);
    let tmp = p.with_extension("tmp-kestrel");
    std::fs::write(&tmp, b)?;
    std::fs::rename(&tmp, &p)
}

/// Uninstall / policy-off entry point: remove every ransomware decoy Kestrel
/// can prove it planted, from any version ([`remove_all_with`]), and update
/// the registry in `state_dir`. Returns the removed paths.
pub fn remove_all(state_dir: &Path) -> Vec<String> {
    let mut reg = load_registry(state_dir);
    // V-H8: on Windows (SYSTEM, user-writable profiles) handle-based only.
    // Profiles are scanned even with an empty registry (lab 2026-10-21: a
    // decoy whose record was lost survived every uninstall).
    #[cfg(windows)]
    let removed = remove_all_with(
        &crate::win::rcanary::SafeDecoyFs,
        &mut reg,
        &crate::win::host::user_profiles(),
    );
    #[cfg(not(windows))]
    let removed = remove_planted(&mut reg, &[]);
    if let Err(e) = save_registry(state_dir, &reg) {
        tracing::warn!("saving {REGISTRY_FILE}: {e}");
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_sort_first_and_look_real() {
        for (_, name, kind) in DECOYS {
            let c = name.chars().next().unwrap();
            assert!(c == '!' || c == '0', "{name}");
            // NTFS order: upper-cased UTF-16 code units; '!' and '0' precede letters.
            assert!((c as u32) < 'A' as u32);
            let ext = name.rsplit('.').next().unwrap();
            let want = match kind {
                DocKind::Docx => "docx",
                DocKind::Xlsx => "xlsx",
                DocKind::Pdf => "pdf",
                DocKind::Jpg => "jpg",
            };
            assert_eq!(ext, want);
        }
        for folder in ["Documents", "Pictures"] {
            let n = DECOYS.iter().filter(|d| d.0 == folder).count();
            assert!((2..=3).contains(&n), "{folder}: {n}");
        }
        // Fresh-install lab 2026-10-21: nothing on the Desktop any more,
        // and every decoy is hidden (not system: see the module docs).
        assert!(DECOYS.iter().all(|d| d.0 != "Desktop"));
        assert_eq!(DECOY_ATTRS, canary::ATTR_HIDDEN);
        assert_eq!(DECOY_ATTRS & canary::ATTR_SYSTEM, 0);
        for (folder, name) in RETIRED_DECOYS {
            assert!(!DECOYS.iter().any(|d| d.0 == *folder && d.1 == *name));
        }
    }

    #[test]
    fn poller_stamp_changes() {
        use StampChange::*;
        assert_eq!(stamp_change(&Some(1), &Some(1)), Same);
        assert_eq!(stamp_change(&Some(1), &Some(2)), Modified);
        assert_eq!(stamp_change(&Some(1), &None::<i32>), Gone);
        assert_eq!(stamp_change(&None, &Some(1)), Appeared);
        assert_eq!(stamp_change(&None::<i32>, &None), Same);
    }

    /// Fresh-install lab 2026-10-21: a decoy that disappears (moved,
    /// deleted, recycled) is reported by Kernel-File with the real actor;
    /// the poller only reports it when no kernel event arrives in time.
    #[test]
    fn gone_decoy_waits_for_the_kernel_event() {
        let noticed = 10_000;
        // Kernel already reported it: drop.
        assert_eq!(gone_verdict(noticed, noticed, true), Some(false));
        assert_eq!(
            gone_verdict(noticed, noticed + GONE_GRACE_MS * 3, true),
            Some(false)
        );
        // Not yet: wait.
        assert_eq!(gone_verdict(noticed, noticed, false), None);
        assert_eq!(
            gone_verdict(noticed, noticed + GONE_GRACE_MS - 1, false),
            None
        );
        // Grace period over without a kernel event: report.
        assert_eq!(
            gone_verdict(noticed, noticed + GONE_GRACE_MS, false),
            Some(true)
        );
    }

    #[test]
    fn headers_are_valid_and_deterministic() {
        for (_, name, kind) in DECOYS {
            let a = content(*kind, name);
            assert_eq!(a, content(*kind, name), "deterministic");
            assert!(a.len() > 1024 && a.len() < 64 * 1024, "{name}: {}", a.len());
            match kind {
                DocKind::Docx | DocKind::Xlsx => {
                    assert_eq!(&a[..4], b"PK\x03\x04");
                    // End-of-central-directory record present.
                    assert!(a.windows(4).any(|w| w == b"PK\x05\x06"));
                }
                DocKind::Pdf => {
                    assert!(a.starts_with(b"%PDF-1."));
                    assert!(a.ends_with(b"%%EOF\n"));
                }
                DocKind::Jpg => {
                    assert_eq!(&a[..4], &[0xFF, 0xD8, 0xFF, 0xE0]);
                    assert_eq!(&a[6..10], b"JFIF");
                    assert!(a.ends_with(&[0xFF, 0xD9]));
                }
            }
        }
        // Different decoys get different content.
        assert_ne!(
            content(DocKind::Pdf, "a.pdf"),
            content(DocKind::Pdf, "b.pdf")
        );
    }

    #[test]
    fn specs_use_existing_plain_folders_only() {
        let s = specs_for_profile(r"C:\Users\labuser\", |d| !d.ends_with("Pictures"));
        assert_eq!(s.len(), 3);
        assert!(s
            .iter()
            .all(|c| c.path.starts_with(r"C:\Users\labuser\Documents\!")
                || c.path.starts_with(r"C:\Users\labuser\Documents\0")));
        assert_eq!(specs_for_profile(r"C:\Users\labuser", |_| true).len(), 5);
        assert!(specs_for_profile(r"C:\Users\x\OneDrive", |_| true).is_empty());
    }

    /// In-memory [`DecoyFs`] keyed by path string (both separators work on
    /// every OS): directories, files (content + attributes).
    #[derive(Default)]
    struct MemFs {
        dirs: std::cell::RefCell<std::collections::HashSet<String>>,
        files: std::cell::RefCell<std::collections::HashMap<String, (Vec<u8>, u32)>>,
        /// Paths whose delete fails (I/O failure).
        stuck: std::collections::HashSet<String>,
    }

    fn sha(b: &[u8]) -> String {
        crate::vault::hex(&sha2::Sha256::digest(b))
    }

    impl MemFs {
        fn dir(&self, p: &str) {
            self.dirs.borrow_mut().insert(p.to_string());
        }
        fn put(&self, p: &str, b: &[u8]) {
            self.files
                .borrow_mut()
                .insert(p.to_string(), (b.to_vec(), 0x20));
        }
        fn get(&self, p: &str) -> Option<(Vec<u8>, u32)> {
            self.files.borrow().get(p).cloned()
        }
    }

    impl DecoyFs for MemFs {
        fn probe(&self, path: &Path) -> Probe {
            let p = path.to_string_lossy().into_owned();
            if self.dirs.borrow().contains(&p) {
                return Probe::Dir;
            }
            match self.files.borrow().get(&p) {
                Some((b, _)) => Probe::File(sha(b)),
                None => Probe::Absent,
            }
        }
        fn create_dirs(&self, path: &Path, _attrs: u32) -> std::io::Result<()> {
            self.dir(&path.to_string_lossy());
            Ok(())
        }
        fn write_file(
            &self,
            path: &Path,
            data: &[u8],
            replace_sha: Option<&str>,
            attrs: u32,
        ) -> std::io::Result<()> {
            let p = path.to_string_lossy().into_owned();
            match (self.probe(path), replace_sha) {
                (Probe::Absent, None) => {}
                (Probe::File(c), Some(w)) if c == w => {}
                _ => return Err(std::io::Error::other("not ours")),
            }
            self.files.borrow_mut().insert(p, (data.to_vec(), attrs));
            Ok(())
        }
        fn ensure_attributes(&self, path: &Path, s: &str, attrs: u32) -> std::io::Result<bool> {
            let p = path.to_string_lossy().into_owned();
            let mut f = self.files.borrow_mut();
            match f.get_mut(&p) {
                Some((b, a)) if sha(b) == s => {
                    let changed = *a & attrs != attrs;
                    *a = (*a & !0x80) | attrs;
                    Ok(changed)
                }
                _ => Err(std::io::Error::other("not ours")),
            }
        }
        fn remove_if_ours(&self, path: &Path, s: &str) -> RemoveResult {
            let p = path.to_string_lossy().into_owned();
            let cur = self.get(&p);
            match cur {
                None => RemoveResult::Gone,
                Some((b, _)) if sha(&b) == s => {
                    if self.stuck.contains(&p) {
                        return RemoveResult::Failed;
                    }
                    self.files.borrow_mut().remove(&p);
                    RemoveResult::Removed
                }
                Some(_) => RemoveResult::NotOurs,
            }
        }
        fn remove_empty_dir(&self, _path: &Path) -> RemoveResult {
            RemoveResult::NotOurs
        }
    }

    const PROF: &str = r"C:\Users\employee";
    const DOCS: &str = r"C:\Users\employee\Documents";
    const PICS: &str = r"C:\Users\employee\Pictures";
    const DESK: &str = r"C:\Users\employee\Desktop";

    fn lab_fs() -> MemFs {
        let fs = MemFs::default();
        for d in [PROF, DOCS, PICS, DESK] {
            fs.dir(d);
        }
        fs
    }

    fn p(dir: &str, name: &str) -> String {
        format!(r"{dir}\{name}")
    }

    /// The hash list is append-only and covers every name any version
    /// planted (current and retired): the generator never changed.
    #[test]
    fn known_hashes_cover_every_decoy_of_every_version() {
        let all = DECOYS.iter().map(|(_, n, k)| (*n, *k)).chain([
            ("!Passwords.docx", DocKind::Docx),
            ("0 Invoice 0917.pdf", DocKind::Pdf),
        ]);
        for (name, kind) in all {
            let h = sha(&content(kind, name));
            assert!(KNOWN_DECOY_SHA256.contains(&h.as_str()), "{name}: {h}");
            assert!(owned(&h, None));
        }
        assert_eq!(
            KNOWN_DECOY_SHA256.len(),
            DECOYS.len() + RETIRED_DECOYS.len()
        );
        // Unknown content is never ours, unless the registry recorded it.
        let user = sha(b"user's own document");
        assert!(!owned(&user, None));
        assert!(!owned(&user, Some(&sha(b"other"))));
        assert!(owned(&user, Some(&user.to_ascii_uppercase())));
    }

    #[test]
    fn candidate_names_keep_prefix_and_extension() {
        let c = candidate_names("!Accounts summary.docx");
        assert_eq!(c.len(), MAX_NAME_CANDIDATES);
        assert_eq!(c[0], "!Accounts summary.docx");
        assert_eq!(c[1], "!Accounts summary 2.docx");
        assert_eq!(c[4], "!Accounts summary 5.docx");
        assert_eq!(candidate_names("0 Scan")[1], "0 Scan 2");
    }

    /// Fresh plant: every decoy written hidden at its layout name, the
    /// registry lists exactly those; a second run changes nothing.
    #[test]
    fn plant_fresh_hidden_and_idempotent() {
        let fs = lab_fs();
        let mut reg = CanaryRegistry::default();
        let armed = plant_with(&fs, &[PROF.into()], &mut reg);
        assert_eq!(armed.len(), DECOYS.len());
        for (folder, name, _) in DECOYS {
            let dir = if *folder == "Documents" { DOCS } else { PICS };
            let (_, a) = fs.get(&p(dir, name)).expect(name);
            assert_eq!(a & canary::ATTR_HIDDEN, canary::ATTR_HIDDEN, "{name}");
        }
        assert_eq!(reg.planted.len(), DECOYS.len());
        let before = fs.files.borrow().clone();
        let again = plant_with(&fs, &[PROF.into()], &mut reg);
        assert_eq!(again.len(), DECOYS.len());
        assert_eq!(*fs.files.borrow(), before);
    }

    /// Lab 2026-10-21 (1.1.3): a visible `!Accounts summary.docx` with
    /// content Kestrel cannot prove it planted (7283 bytes, no matching
    /// record) was listed in rcanaries.json. Now: not armed, untouched,
    /// its record dropped, and the decoy goes to the next free name.
    #[test]
    fn unproven_file_at_decoy_name_is_not_armed() {
        let fs = lab_fs();
        let squatter = p(DOCS, "!Accounts summary.docx");
        let unknown = vec![7u8; 7283];
        fs.put(&squatter, &unknown);
        // A stale record with another hash (e.g. an earlier plant whose
        // file was later replaced).
        let mut reg = CanaryRegistry::default();
        reg.planted.insert(
            crate::ntpath::norm_key(&squatter),
            CanaryRecord {
                path: squatter.clone(),
                sha256: Some(sha(b"something else")),
            },
        );
        let armed = plant_with(&fs, &[PROF.into()], &mut reg);
        assert!(!armed.contains(&squatter), "{armed:?}");
        assert!(!reg
            .planted
            .contains_key(&crate::ntpath::norm_key(&squatter)));
        assert!(reg.retained.is_empty());
        // Untouched: content and attributes.
        assert_eq!(fs.get(&squatter), Some((unknown, 0x20)));
        // Planted under the next free name, hidden, with the known content.
        let alt = p(DOCS, "!Accounts summary 2.docx");
        assert!(armed.contains(&alt), "{armed:?}");
        let (b, a) = fs.get(&alt).unwrap();
        assert_eq!(a & canary::ATTR_HIDDEN, canary::ATTR_HIDDEN);
        assert!(owned(&sha(&b), None));
        // Next run keeps using the alternate, plants nothing new.
        let n = fs.files.borrow().len();
        let again = plant_with(&fs, &[PROF.into()], &mut reg);
        assert!(again.contains(&alt) && !again.contains(&squatter));
        assert_eq!(fs.files.borrow().len(), n);
        // Uninstall leaves the unproven file, removes the decoys.
        let removed = remove_all_with(&fs, &mut reg, &[PROF.into()]);
        assert_eq!(removed.len(), DECOYS.len(), "{removed:?}");
        assert!(fs.get(&squatter).is_some());
        assert_eq!(fs.files.borrow().len(), 1);
    }

    /// A visible decoy from an older version is adopted (armed, hidden
    /// through the handle, never rewritten) when ownership is proven by
    /// the recorded hash of a previous rcanaries.json, or by the content
    /// of any released version even without a record.
    #[test]
    fn legacy_decoys_are_adopted_and_hidden() {
        let fs = lab_fs();
        // Proven by the registry only (content not in the known list, e.g.
        // an unreleased build that recorded its own hash).
        let by_record = p(DOCS, "!Accounts summary.docx");
        let legacy = vec![9u8; 7283];
        fs.put(&by_record, &legacy);
        // Proven by known content, no record at all (registry lost).
        let by_content = p(DOCS, "!Payroll Q3.xlsx");
        fs.put(&by_content, &content(DocKind::Xlsx, "!Payroll Q3.xlsx"));
        let mut reg = CanaryRegistry::default();
        reg.planted.insert(
            crate::ntpath::norm_key(&by_record),
            CanaryRecord {
                path: by_record.clone(),
                sha256: Some(sha(&legacy)),
            },
        );
        let armed = plant_with(&fs, &[PROF.into()], &mut reg);
        for path in [&by_record, &by_content] {
            assert!(armed.contains(path), "{path}: {armed:?}");
            let (_, a) = fs.get(path).unwrap();
            assert_eq!(a & canary::ATTR_HIDDEN, canary::ATTR_HIDDEN, "{path}");
        }
        // Never rewritten, recorded with its actual hash.
        assert_eq!(fs.get(&by_record).unwrap().0, legacy);
        assert_eq!(
            reg.planted[&crate::ntpath::norm_key(&by_record)].sha256,
            Some(sha(&legacy))
        );
        // No duplicate at the alternate name.
        assert!(fs.get(&p(DOCS, "!Accounts summary 2.docx")).is_none());
        // Uninstall removes both.
        let removed = remove_all_with(&fs, &mut reg, &[PROF.into()]);
        assert!(removed.contains(&by_record) && removed.contains(&by_content));
        assert!(fs.files.borrow().is_empty());
        assert!(reg.planted.is_empty());
    }

    /// Upgrade from 1.1.2: the Desktop decoys are removed while provably
    /// Kestrel's; a user-changed one stays.
    #[test]
    fn retired_desktop_decoys_removed_when_provably_ours() {
        let fs = lab_fs();
        let pw = p(DESK, "!Passwords.docx");
        let inv = p(DESK, "0 Invoice 0917.pdf");
        fs.put(&pw, &content(DocKind::Docx, "!Passwords.docx"));
        fs.put(&inv, b"my notes");
        let mut reg = CanaryRegistry::default();
        let armed = plant_with(&fs, &[PROF.into()], &mut reg);
        assert!(fs.get(&pw).is_none());
        assert_eq!(fs.get(&inv).unwrap().0, b"my notes");
        assert!(!armed.iter().any(|a| a.contains("Desktop")));
        assert!(!reg.planted.values().any(|r| r.path.contains("Desktop")));
    }

    /// Lab 2026-10-21: uninstall left a decoy behind because removal used
    /// only the registry. Now every decoy path of every version is scanned
    /// with the ownership rule, even with an empty registry; a delete
    /// failure keeps the record for the next attempt; unknown files stay.
    #[test]
    fn uninstall_removes_every_provable_decoy_without_a_registry() {
        let mut fs = lab_fs();
        let docs = p(DOCS, "!Accounts summary.docx");
        let alt = p(DOCS, "0 Contract - signed 2.pdf");
        let desk = p(DESK, "0 Invoice 0917.pdf");
        let user = p(DOCS, "!Payroll Q3.xlsx");
        fs.put(&docs, &content(DocKind::Docx, "!Accounts summary.docx"));
        fs.put(&alt, &content(DocKind::Pdf, "0 Contract - signed.pdf"));
        fs.put(&desk, &content(DocKind::Pdf, "0 Invoice 0917.pdf"));
        fs.put(&user, b"the user's real payroll");
        let stuck = p(PICS, "!IMG_0001.jpg");
        fs.put(&stuck, &content(DocKind::Jpg, "!IMG_0001.jpg"));
        fs.stuck.insert(stuck.clone());
        let mut reg = CanaryRegistry::default();
        let removed = remove_all_with(&fs, &mut reg, &[PROF.into()]);
        for path in [&docs, &alt, &desk] {
            assert!(removed.contains(path), "{path}: {removed:?}");
        }
        assert_eq!(fs.get(&user).unwrap().0, b"the user's real payroll");
        assert!(fs.get(&stuck).is_some());
        assert_eq!(reg.planted.len(), 1);
        assert!(reg.planted.contains_key(&crate::ntpath::norm_key(&stuck)));
        // Retained records outside the scanned profiles are removed too.
        let other = r"C:\Users\former\Documents\!Payroll Q3.xlsx";
        fs.put(other, &content(DocKind::Xlsx, "!Payroll Q3.xlsx"));
        reg.retained.insert(
            crate::ntpath::norm_key(other),
            CanaryRecord {
                path: other.into(),
                sha256: Some(sha(&content(DocKind::Xlsx, "!Payroll Q3.xlsx"))),
            },
        );
        let removed = remove_all_with(&fs, &mut reg, &[]);
        assert_eq!(removed, vec![other.to_string()]);
        assert!(reg.retained.is_empty());
    }

    /// Records of profiles not enumerated now are kept as `retained` (not
    /// armed) while provably ours, and dropped when not.
    #[test]
    fn records_outside_current_profiles_are_retained_not_armed() {
        let fs = lab_fs();
        let other = r"C:\Users\former\Documents\!Payroll Q3.xlsx";
        let gone = r"C:\Users\former\Documents\0 Contract - signed.pdf";
        fs.put(other, &content(DocKind::Xlsx, "!Payroll Q3.xlsx"));
        let mut reg = CanaryRegistry::default();
        for path in [other, gone] {
            reg.planted.insert(
                crate::ntpath::norm_key(path),
                CanaryRecord {
                    path: path.into(),
                    sha256: Some("00".into()),
                },
            );
        }
        let armed = plant_with(&fs, &[PROF.into()], &mut reg);
        assert!(!armed.iter().any(|a| a.contains("former")));
        assert!(!reg.planted.values().any(|r| r.path.contains("former")));
        assert_eq!(reg.retained.len(), 1);
        assert!(reg.retained.contains_key(&crate::ntpath::norm_key(other)));
    }
}
