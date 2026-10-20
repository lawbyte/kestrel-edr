//! Ransomware canary documents (decoys) for the file-activity sensor.
//!
//! Two or three small, believable documents are planted in the **roots** of
//! each profile's Documents, Desktop and Pictures folders. Names start with
//! `!` or `0` so they come first in NTFS directory order (upper-cased UTF-16
//! collation: `!` 0x21 < `0` 0x30 < letters) — encryptors walking a folder
//! with `FindFirstFile` hit them early. They are **not** hidden or system:
//! most ransomware skips such files. Content is a valid minimal file of the
//! claimed type (OOXML zip, PDF, JPEG/JFIF) so magic-byte checks pass.
//!
//! Safety (same rules as the credential canaries in [`crate::canary`]):
//! never overwrite an existing file, never follow a reparse point anywhere
//! in the path, create with `create_new`, verify the final path. Folders
//! redirected into OneDrive are skipped (decoys would sync to the cloud).
//! The registry of what was planted (with SHA-256) lives in
//! `<state>\rcanaries.json`; [`remove_planted`] deletes only files whose
//! content is still exactly what Kestrel wrote (call it at uninstall).

use crate::canary::{self, CanaryRecord, CanaryRegistry};
use crate::vault::hex;
use kestrel_common::DataCategory;
use kestrel_platform::CanarySpec;
use sha2::{Digest, Sha256};
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
    ("Desktop", "!Passwords.docx", DocKind::Docx),
    ("Desktop", "0 Invoice 0917.pdf", DocKind::Pdf),
    ("Pictures", "!IMG_0001.jpg", DocKind::Jpg),
    ("Pictures", "0 Scan 0917.jpg", DocKind::Jpg),
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

/// Plant decoys for `profiles`. Returns the paths that now hold our decoys.
pub fn plant(profiles: &[String], reg: &mut CanaryRegistry) -> Vec<String> {
    let mut specs = Vec::new();
    for p in profiles {
        specs.extend(specs_for_profile(p, |d| {
            let path = Path::new(d);
            !canary::has_link_in_chain(path)
                && std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
        }));
    }
    // Never hidden: ransomware skips hidden/system files.
    canary::plant(&specs, reg, &|_: &Path| {})
}

/// Remove every planted decoy whose content is still ours (uninstall /
/// policy turned off). Files the user changed, links and directories are
/// left alone. Returns the removed paths; the registry keeps entries that
/// could not be removed for a later attempt.
pub fn remove_planted(reg: &mut CanaryRegistry) -> Vec<String> {
    let mut removed = Vec::new();
    let mut keep = std::collections::BTreeMap::new();
    for (k, rec) in std::mem::take(&mut reg.planted) {
        match remove_one(&rec) {
            RemoveResult::Removed => removed.push(rec.path.clone()),
            RemoveResult::Gone | RemoveResult::NotOurs => {}
            RemoveResult::Failed => {
                keep.insert(k, rec);
            }
        }
    }
    reg.planted = keep;
    removed
}

enum RemoveResult {
    Removed,
    Gone,
    NotOurs,
    Failed,
}

fn remove_one(rec: &CanaryRecord) -> RemoveResult {
    let p = Path::new(&rec.path);
    if canary::has_link_in_chain(p) {
        return RemoveResult::NotOurs;
    }
    let Ok(m) = std::fs::symlink_metadata(p) else {
        return RemoveResult::Gone;
    };
    if !m.is_file() {
        return RemoveResult::NotOurs;
    }
    let Some(want) = rec.sha256.as_deref() else {
        return RemoveResult::NotOurs;
    };
    match std::fs::read(p) {
        Ok(b) if hex(&Sha256::digest(&b)).eq_ignore_ascii_case(want) => {
            match std::fs::remove_file(p) {
                Ok(()) => RemoveResult::Removed,
                Err(_) => RemoveResult::Failed,
            }
        }
        Ok(_) => RemoveResult::NotOurs,
        Err(_) => RemoveResult::Failed,
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
/// planted (only files still holding exactly our content) and update the
/// registry in `state_dir`. Returns the removed paths.
pub fn remove_all(state_dir: &Path) -> Vec<String> {
    let mut reg = load_registry(state_dir);
    if reg.planted.is_empty() {
        return vec![];
    }
    let removed = remove_planted(&mut reg);
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
        for folder in ["Documents", "Desktop", "Pictures"] {
            let n = DECOYS.iter().filter(|d| d.0 == folder).count();
            assert!((2..=3).contains(&n), "{folder}: {n}");
        }
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
        assert_eq!(s.len(), 5);
        assert!(s
            .iter()
            .all(|c| c.path.starts_with(r"C:\Users\labuser\Documents\!")
                || c.path.starts_with(r"C:\Users\labuser\Documents\0")
                || c.path.starts_with(r"C:\Users\labuser\Desktop\")));
        assert!(specs_for_profile(r"C:\Users\x\OneDrive", |_| true).is_empty());
    }

    #[test]
    fn plant_and_remove_roundtrip() {
        let d = std::env::temp_dir().join(format!("kestrel-rcanary-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        for f in ["Documents", "Desktop", "Pictures"] {
            std::fs::create_dir_all(d.join(f)).unwrap();
        }
        // A real user file with a decoy name is never touched.
        std::fs::write(d.join("Desktop").join("!Passwords.docx"), b"mine").unwrap();
        let prof = d.to_string_lossy().replace('/', "\\");
        let mut reg = CanaryRegistry::default();
        // Use the platform separator for the actual filesystem test.
        let specs = specs_for_profile(&prof, |_| true)
            .into_iter()
            .map(|mut s| {
                s.path = s.path.replace('\\', std::path::MAIN_SEPARATOR_STR);
                s
            })
            .collect::<Vec<_>>();
        let ok = canary::plant(&specs, &mut reg, &|_: &Path| {});
        assert_eq!(ok.len(), DECOYS.len() - 1);
        assert_eq!(
            std::fs::read(d.join("Desktop").join("!Passwords.docx")).unwrap(),
            b"mine"
        );
        // User edits one decoy: removal leaves it.
        let edited = d.join("Documents").join("0 Contract - signed.pdf");
        std::fs::write(&edited, b"changed").unwrap();
        let removed = remove_planted(&mut reg);
        assert_eq!(removed.len(), DECOYS.len() - 2);
        assert!(edited.exists());
        assert!(!d.join("Pictures").join("!IMG_0001.jpg").exists());
        assert!(reg.planted.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }
}
