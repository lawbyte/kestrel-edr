//! Canary (decoy credential store) planting. Never overwrites a real user
//! file: a path is only (re)written when it does not exist or when it still
//! holds exactly what Kestrel planted last time (tracked in
//! `<state>\canaries.json` by SHA-256).
//!
//! L12: planting runs as SYSTEM inside user-controlled profile folders, so it
//! never follows a symbolic link / junction / mount point: every existing
//! component of the target path is checked (`symlink_metadata`, which on
//! Windows reports name-surrogate reparse points), directories are created
//! one level at a time and re-checked, files are created with `create_new`
//! (fails on an existing link) and the final location is verified with
//! `canonicalize` (`GetFinalPathNameByHandleW` on Windows). A mismatch
//! removes what was just created and skips the decoy.

use crate::vault::hex;
use kestrel_platform::CanarySpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRecord {
    pub path: String,
    /// SHA-256 of the planted content; None for directories.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryRegistry {
    pub planted: BTreeMap<String, CanaryRecord>,
    /// Ransomware decoys that are provably Kestrel's but not armed (a
    /// profile not enumerated at the last plant, an older layout): kept so
    /// uninstall removes them. Never armed. Absent in older files.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub retained: BTreeMap<String, CanaryRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    WriteNew,
    Refresh,
    KeepOurs,
    SkipForeign,
}

pub fn decide(
    is_dir: bool,
    exists: bool,
    current_sha: Option<&str>,
    record: Option<&CanaryRecord>,
    new_sha: &str,
) -> Decision {
    if !exists {
        return Decision::WriteNew;
    }
    let Some(rec) = record else {
        return Decision::SkipForeign;
    };
    if is_dir {
        return Decision::KeepOurs;
    }
    match (current_sha, rec.sha256.as_deref()) {
        (Some(cur), Some(ours)) if cur.eq_ignore_ascii_case(ours) => {
            if cur.eq_ignore_ascii_case(new_sha) {
                Decision::KeepOurs
            } else {
                Decision::Refresh
            }
        }
        _ => Decision::SkipForeign,
    }
}

fn key(p: &str) -> String {
    crate::ntpath::norm_key(p)
}

/// Is any existing component of `path` (including `path`) a symbolic link,
/// junction or other name-surrogate reparse point?
pub fn has_link_in_chain(path: &Path) -> bool {
    let mut cur = std::path::PathBuf::new();
    for c in path.components() {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => return true,
            Ok(_) => {}
            Err(_) => break, // does not exist yet: nothing below can be a link
        }
    }
    false
}

/// Does `path` resolve to itself (no link anywhere, after the fact)?
fn resolves_to_itself(path: &Path) -> bool {
    match std::fs::canonicalize(path) {
        Ok(c) => {
            #[cfg(windows)]
            {
                crate::qpolicy::same_path(&path.to_string_lossy(), &c.to_string_lossy())
            }
            #[cfg(not(windows))]
            {
                let expect = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    std::env::current_dir()
                        .map(|d| d.join(path))
                        .unwrap_or_default()
                };
                c == expect
            }
        }
        Err(_) => false,
    }
}

/// Create `dir` and missing parents without following links.
fn create_dirs_no_follow(dir: &Path) -> std::io::Result<()> {
    if has_link_in_chain(dir) {
        return Err(std::io::Error::other("link in path"));
    }
    let mut cur = std::path::PathBuf::new();
    for c in dir.components() {
        cur.push(c);
        match std::fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(std::io::Error::other("link in path"))
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(std::io::Error::other("not a directory")),
            Err(_) => {
                std::fs::create_dir(&cur)?;
                let m = std::fs::symlink_metadata(&cur)?;
                if m.file_type().is_symlink() || !m.is_dir() || !resolves_to_itself(&cur) {
                    let _ = std::fs::remove_dir(&cur);
                    return Err(std::io::Error::other("directory was redirected"));
                }
            }
        }
    }
    Ok(())
}

/// Write `data` to `path` via a fresh temp file (never through a link).
fn write_no_follow(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    create_dirs_no_follow(parent)?;
    if has_link_in_chain(path) {
        return Err(std::io::Error::other("link in path"));
    }
    let tmp = path.with_extension("kestrel-tmp");
    let _ = std::fs::remove_file(&tmp); // removes a link itself, never its target
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)?;
    let r = f.write_all(data).and_then(|_| f.sync_all());
    drop(f);
    if let Err(e) = r {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if !resolves_to_itself(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(std::io::Error::other("temp file was redirected"));
    }
    std::fs::rename(&tmp, path).inspect_err(|_| {
        let _ = std::fs::remove_file(&tmp);
    })?;
    if !resolves_to_itself(path) {
        let _ = std::fs::remove_file(path);
        return Err(std::io::Error::other("decoy was redirected"));
    }
    Ok(())
}

/// `FILE_ATTRIBUTE_HIDDEN`.
pub const ATTR_HIDDEN: u32 = 0x2;
/// `FILE_ATTRIBUTE_SYSTEM`.
pub const ATTR_SYSTEM: u32 = 0x4;

/// What is at a canary path ([`DecoyFs::probe`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    Absent,
    /// A regular, single-link, non-reparse file with this SHA-256 (hex).
    File(String),
    /// A real (non-link) directory.
    Dir,
    /// A link / reparse point / multi-link file / unreadable object: never ours.
    Foreign,
}

/// Outcome of [`DecoyFs::remove_if_ours`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveResult {
    Removed,
    Gone,
    NotOurs,
    Failed,
}

/// File operations used to plant and remove decoys. On Windows the agent
/// runs them as SYSTEM inside user-writable profiles, so the Windows
/// implementation (`win::rcanary::SafeDecoyFs`, V-H8) works on handles: every
/// ancestor verified with `FILE_FLAG_OPEN_REPARSE_POINT`, files created /
/// opened relative to a verified directory handle, and the hash check and
/// the delete done through the **same** handle. [`StdFs`] is the portable
/// path-based version (tests, non-Windows).
pub trait DecoyFs {
    fn probe(&self, path: &Path) -> Probe;
    /// Create `path` (and missing parents) as directories, never through a
    /// link; `attrs` (`ATTR_*` bits) are added to `path` itself.
    fn create_dirs(&self, path: &Path, attrs: u32) -> std::io::Result<()>;
    /// Write `data` to `path`. `replace_sha`: the file currently there must
    /// have exactly this SHA-256 (it is ours) and is replaced; `None`: the
    /// path must not exist. `attrs` (`ATTR_*` bits) are set on the new file.
    fn write_file(
        &self,
        path: &Path,
        data: &[u8],
        replace_sha: Option<&str>,
        attrs: u32,
    ) -> std::io::Result<()>;
    /// Add `attrs` (`ATTR_*` bits) to the plain file at `path` if it still
    /// holds exactly `sha` (ours); never through a link, never recreating
    /// it, never touching a file the user changed. `Ok(true)` when the
    /// attributes were changed, `Ok(false)` when they were already set.
    fn ensure_attributes(&self, path: &Path, sha: &str, attrs: u32) -> std::io::Result<bool>;
    /// Delete `path` only if it is a plain file whose SHA-256 is `sha`.
    fn remove_if_ours(&self, path: &Path, sha: &str) -> RemoveResult;
    /// Delete the directory `path` only if it is a real (non-link) and
    /// **empty** directory. `Removed`, `Gone` (absent), `NotOurs` (not
    /// empty, a link / reparse point, not a directory) or `Failed`.
    fn remove_empty_dir(&self, path: &Path) -> RemoveResult;
}

/// Portable, path-based [`DecoyFs`] (link checks before and after; not
/// race-free against a local attacker: Windows uses `SafeDecoyFs`).
pub struct StdFs<'a> {
    /// Applies `ATTR_*` bits (no-op off Windows / in tests).
    pub set_attrs: &'a dyn Fn(&Path, u32),
}

impl DecoyFs for StdFs<'_> {
    fn probe(&self, path: &Path) -> Probe {
        if has_link_in_chain(path) {
            return Probe::Foreign;
        }
        match std::fs::symlink_metadata(path) {
            Err(_) => Probe::Absent,
            Ok(m) if m.is_dir() => Probe::Dir,
            Ok(m) if m.is_file() => match std::fs::read(path) {
                Ok(b) => Probe::File(hex(&Sha256::digest(&b))),
                Err(_) => Probe::Foreign,
            },
            Ok(_) => Probe::Foreign,
        }
    }

    fn create_dirs(&self, path: &Path, attrs: u32) -> std::io::Result<()> {
        create_dirs_no_follow(path)?;
        if attrs != 0 {
            (self.set_attrs)(path, attrs);
        }
        Ok(())
    }

    fn write_file(
        &self,
        path: &Path,
        data: &[u8],
        replace_sha: Option<&str>,
        attrs: u32,
    ) -> std::io::Result<()> {
        match (self.probe(path), replace_sha) {
            (Probe::Absent, None) => {}
            (Probe::File(cur), Some(want)) if cur.eq_ignore_ascii_case(want) => {}
            _ => return Err(std::io::Error::other("target changed; not ours")),
        }
        write_no_follow(path, data)?;
        if attrs != 0 {
            (self.set_attrs)(path, attrs);
        }
        Ok(())
    }

    fn ensure_attributes(&self, path: &Path, sha: &str, attrs: u32) -> std::io::Result<bool> {
        match self.probe(path) {
            Probe::File(cur) if cur.eq_ignore_ascii_case(sha) => {
                (self.set_attrs)(path, attrs);
                Ok(true)
            }
            _ => Err(std::io::Error::other("not ours; attributes left alone")),
        }
    }

    fn remove_if_ours(&self, path: &Path, sha: &str) -> RemoveResult {
        match self.probe(path) {
            Probe::Absent => RemoveResult::Gone,
            Probe::File(cur) if cur.eq_ignore_ascii_case(sha) => match std::fs::remove_file(path) {
                Ok(()) => RemoveResult::Removed,
                Err(_) => RemoveResult::Failed,
            },
            _ => RemoveResult::NotOurs,
        }
    }

    fn remove_empty_dir(&self, path: &Path) -> RemoveResult {
        match self.probe(path) {
            Probe::Absent => RemoveResult::Gone,
            Probe::Dir => match std::fs::read_dir(path).map(|mut d| d.next().is_none()) {
                Ok(true) => match std::fs::remove_dir(path) {
                    Ok(()) => RemoveResult::Removed,
                    Err(_) => RemoveResult::Failed,
                },
                Ok(false) => RemoveResult::NotOurs,
                Err(_) => RemoveResult::Failed,
            },
            _ => RemoveResult::NotOurs,
        }
    }
}

/// Folders (relative to `%LOCALAPPDATA%`, lower-case) the pre-2026-10-21
/// ST-16 decoy created implicitly above its recorded `Profile NN` folder.
/// Removed on upgrade only when they are empty real directories (Chrome is
/// then not installed: an empty `Google\Chrome\User Data` is what made the
/// decoy look like an installed Chrome to Edge's importer).
// On-disk casing (NTFS ignores case; Linux test runs do not).
const LEGACY_IMPLICIT_PARENTS: &[&str] = &[r"Google\Chrome\User Data", r"Google\Chrome", r"Google"];

/// Upgrade / migration: remove every decoy recorded in `reg` that is not
/// part of the current `specs` (e.g. the legacy `Google\Chrome\User
/// Data\Profile NN` decoy): files only while they still hold exactly what
/// Kestrel planted, directories only when empty, deepest first, never
/// through a link. Then the empty legacy parent folders the old layout
/// created implicitly. Entries that could not be removed because of an
/// I/O failure stay recorded for the next attempt; everything else is
/// forgotten (a non-empty / changed object is the user's now). Returns the
/// removed paths.
pub fn retire_stale(
    fs: &dyn DecoyFs,
    specs: &[CanarySpec],
    reg: &mut CanaryRegistry,
) -> Vec<String> {
    let current: std::collections::HashSet<String> = specs.iter().map(|s| key(&s.path)).collect();
    let mut stale: Vec<(String, CanaryRecord)> = reg
        .planted
        .iter()
        .filter(|(k, _)| !current.contains(*k))
        .map(|(k, r)| (k.clone(), r.clone()))
        .collect();
    if stale.is_empty() {
        return vec![];
    }
    // Deepest first: files and sub-folders before their parents.
    // Deepest first (children before their folders); either separator.
    stale.sort_by_key(|(k, _)| std::cmp::Reverse(k.matches(['\\', '/']).count()));
    let mut removed = Vec::new();
    let mut legacy_bases: Vec<std::path::PathBuf> = Vec::new();
    for (k, rec) in stale {
        let path = Path::new(&rec.path);
        let r = match rec.sha256.as_deref() {
            Some(sha) => fs.remove_if_ours(path, sha),
            None => fs.remove_empty_dir(path),
        };
        match r {
            RemoveResult::Removed => removed.push(rec.path.clone()),
            RemoveResult::Gone | RemoveResult::NotOurs => {}
            RemoveResult::Failed => continue, // keep the record, retry later
        }
        reg.planted.remove(&k);
        // `…\AppData\Local\Google\Chrome\User Data\<x>` → remember `…\AppData\Local`.
        let lower = rec.path.replace('/', "\\").to_ascii_lowercase();
        if let Some(i) = lower.find(r"\appdata\local\google\chrome\user data\") {
            let base = Path::new(&rec.path[..i + r"\appdata\local".len()]).to_path_buf();
            if !legacy_bases.contains(&base) {
                legacy_bases.push(base);
            }
        }
    }
    for base in legacy_bases {
        for rel in LEGACY_IMPLICIT_PARENTS {
            let p = rel.split('\\').fold(base.clone(), |acc, c| acc.join(c));
            // Case of the on-disk names does not matter on NTFS.
            if fs.remove_empty_dir(&p) == RemoveResult::Removed {
                removed.push(p.to_string_lossy().into_owned());
            }
        }
    }
    removed
}

/// Plant `specs`; returns paths that now hold Kestrel canaries. `set_attrs`
/// applies the attributes ([`ATTR_HIDDEN`] here). Path-based: Windows
/// callers use [`plant_with`] and the handle-based `SafeDecoyFs`.
pub fn plant(
    specs: &[CanarySpec],
    reg: &mut CanaryRegistry,
    set_attrs: &dyn Fn(&Path, u32),
) -> Vec<String> {
    plant_with(&StdFs { set_attrs }, specs, reg, ATTR_HIDDEN)
}

/// Plant `specs` through `fs`; `attrs` (`ATTR_*` bits, 0 = none) are set
/// on what is created and re-applied to decoys already planted that still
/// hold exactly Kestrel's content (upgrade from a version that planted them
/// without; a user-modified decoy is never touched).
pub fn plant_with(
    fs: &dyn DecoyFs,
    specs: &[CanarySpec],
    reg: &mut CanaryRegistry,
    attrs: u32,
) -> Vec<String> {
    let mut ok = Vec::new();
    // Directory specs that exist and are not Kestrel's (the user really has
    // that browser): nothing is planted below them.
    let mut foreign_dirs: Vec<String> = Vec::new();
    for spec in specs {
        let path = Path::new(&spec.path);
        let k = key(&spec.path);
        if foreign_dirs
            .iter()
            .any(|d| k.starts_with(d.as_str()) && k.as_bytes().get(d.len()) == Some(&b'\\'))
        {
            continue;
        }
        let rec = reg.planted.get(&k);
        let probe = fs.probe(path);
        if probe == Probe::Foreign {
            tracing::warn!(path = %spec.path, "not planting canary: link / junction / foreign object at the path");
            if spec.is_dir {
                foreign_dirs.push(k);
            }
            continue;
        }
        let exists = probe != Probe::Absent;
        if spec.is_dir {
            if exists && (probe != Probe::Dir || rec.is_none()) {
                // A real folder of that browser (or a file in the way).
                // Review F9: malware or a login script could pre-create the
                // folder to suppress the decoys, so say so loudly.
                tracing::warn!(
                    path = %spec.path,
                    "decoy not planted: folder exists and is not Kestrel's (a real install of that browser, or decoy suppression)"
                );
                foreign_dirs.push(k);
                continue;
            }
            match decide(true, exists, None, rec, "") {
                Decision::WriteNew => {
                    if fs.create_dirs(path, attrs).is_ok() {
                        reg.planted.insert(
                            k,
                            CanaryRecord {
                                path: spec.path.clone(),
                                sha256: None,
                            },
                        );
                        ok.push(spec.path.clone());
                    }
                }
                Decision::KeepOurs | Decision::Refresh => ok.push(spec.path.clone()),
                Decision::SkipForeign => {}
            }
            continue;
        }
        let new_sha = hex(&Sha256::digest(&spec.content));
        let current = match &probe {
            Probe::File(s) => Some(s.clone()),
            Probe::Absent => None,
            // A directory (or something else) sits where a file canary should go.
            _ => continue,
        };
        match decide(false, exists, current.as_deref(), rec, &new_sha) {
            Decision::WriteNew | Decision::Refresh => {
                // Temp name first so a crash never leaves a partial canary.
                let written = fs
                    .write_file(path, &spec.content, current.as_deref(), attrs)
                    .is_ok();
                if written {
                    reg.planted.insert(
                        k,
                        CanaryRecord {
                            path: spec.path.clone(),
                            sha256: Some(new_sha),
                        },
                    );
                    ok.push(spec.path.clone());
                }
            }
            Decision::KeepOurs => {
                if attrs != 0 {
                    if let Err(e) = fs.ensure_attributes(path, &new_sha, attrs) {
                        tracing::debug!(path = %spec.path, "decoy attributes not re-applied: {e}");
                    }
                }
                ok.push(spec.path.clone());
            }
            Decision::SkipForeign => {}
        }
    }
    ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::DataCategory;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kestrel-canary-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn decisions() {
        let rec = CanaryRecord {
            path: "x".into(),
            sha256: Some("aa".into()),
        };
        assert_eq!(decide(false, false, None, None, "bb"), Decision::WriteNew);
        assert_eq!(
            decide(false, true, Some("aa"), None, "aa"),
            Decision::SkipForeign
        );
        assert_eq!(
            decide(false, true, Some("aa"), Some(&rec), "aa"),
            Decision::KeepOurs
        );
        assert_eq!(
            decide(false, true, Some("aa"), Some(&rec), "bb"),
            Decision::Refresh
        );
        assert_eq!(
            decide(false, true, Some("cc"), Some(&rec), "bb"),
            Decision::SkipForeign
        );
        assert_eq!(decide(true, true, None, None, ""), Decision::SkipForeign);
    }

    #[test]
    fn planting() {
        let d = tmpdir("plant");
        let real = d.join("real").join("Login Data");
        std::fs::create_dir_all(real.parent().unwrap()).unwrap();
        std::fs::write(&real, b"user's real data").unwrap();
        let specs = vec![
            CanarySpec {
                path: d.join("decoy").join("Login Data").to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: real.to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: d.join("wallet").to_string_lossy().into(),
                category: DataCategory::CryptoWallet,
                content: vec![],
                is_dir: true,
            },
        ];
        let mut reg = CanaryRegistry::default();
        let hidden = std::cell::RefCell::new(0);
        let h = |_: &Path, a: u32| {
            assert_eq!(a, ATTR_HIDDEN);
            *hidden.borrow_mut() += 1
        };
        let ok = plant(&specs, &mut reg, &h);
        assert_eq!(ok.len(), 2);
        assert_eq!(std::fs::read(&real).unwrap(), b"user's real data");
        assert_eq!(*hidden.borrow(), 2);
        // Second run: keep, no rewrites; the file decoy (still ours) gets
        // its attributes re-applied (upgrade path), the folder does not.
        let mtime = std::fs::metadata(&specs[0].path)
            .unwrap()
            .modified()
            .unwrap();
        let ok2 = plant(&specs, &mut reg, &h);
        assert_eq!(ok2.len(), 2);
        assert_eq!(*hidden.borrow(), 3);
        assert_eq!(
            std::fs::metadata(&specs[0].path)
                .unwrap()
                .modified()
                .unwrap(),
            mtime
        );
        // User replaced our decoy with real content → we leave it alone
        // (no rewrite, no attribute change).
        std::fs::write(&specs[0].path, b"now real").unwrap();
        let ok3 = plant(&specs, &mut reg, &h);
        assert_eq!(ok3.len(), 1);
        assert_eq!(*hidden.borrow(), 3);
        assert_eq!(std::fs::read(&specs[0].path).unwrap(), b"now real");
        let _ = std::fs::remove_dir_all(&d);
    }

    fn std_fs() -> StdFs<'static> {
        StdFs {
            set_attrs: &|_: &Path, _| {},
        }
    }

    /// Never plant inside a folder of a browser that is really installed.
    #[test]
    fn never_plants_into_a_foreign_browser_folder() {
        let d = tmpdir("foreign");
        let real = d.join("Kometa");
        std::fs::create_dir_all(real.join("User Data")).unwrap();
        let specs = vec![
            CanarySpec {
                path: real.to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: vec![],
                is_dir: true,
            },
            CanarySpec {
                path: real.join("User Data").to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: vec![],
                is_dir: true,
            },
            CanarySpec {
                path: real
                    .join("User Data")
                    .join("Local State")
                    .to_string_lossy()
                    .into(),
                category: DataCategory::BrowserMasterKey,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: d.join("elsewhere").to_string_lossy().into(),
                category: DataCategory::CryptoWallet,
                content: vec![],
                is_dir: true,
            },
        ];
        let mut reg = CanaryRegistry::default();
        let ok = plant_with(&std_fs(), &specs, &mut reg, 0);
        assert_eq!(ok, vec![specs[3].path.clone()]);
        assert!(!real.join("User Data").join("Local State").exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Upgrade: the legacy `Google\Chrome\User Data\Profile NN` decoy (and
    /// the empty Chrome folders it implied) is removed; a changed file and a
    /// real Chrome install are left alone.
    #[test]
    fn retires_legacy_chrome_decoy() {
        let d = tmpdir("retire");
        let local = d
            .join("Users")
            .join("employee")
            .join("AppData")
            .join("Local");
        let profile = local
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Profile 68");
        let ext = profile.join("Local Extension Settings").join("nkbih");
        let legacy = vec![
            CanarySpec {
                path: profile.to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: vec![],
                is_dir: true,
            },
            CanarySpec {
                path: profile.join("Login Data").to_string_lossy().into(),
                category: DataCategory::BrowserPasswords,
                content: b"sqlite decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: profile
                    .join("Local Extension Settings")
                    .to_string_lossy()
                    .into(),
                category: DataCategory::CryptoWallet,
                content: vec![],
                is_dir: true,
            },
            CanarySpec {
                path: ext.to_string_lossy().into(),
                category: DataCategory::CryptoWallet,
                content: vec![],
                is_dir: true,
            },
            CanarySpec {
                path: ext.join("000003.log").to_string_lossy().into(),
                category: DataCategory::CryptoWallet,
                content: b"vault".to_vec(),
                is_dir: false,
            },
        ];
        let mut reg = CanaryRegistry::default();
        assert_eq!(plant_with(&std_fs(), &legacy, &mut reg, 0).len(), 5);
        // Edge's importer dropped nothing; the new layout is planted elsewhere.
        let new_specs = vec![CanarySpec {
            path: local.join("Kometa").to_string_lossy().into(),
            category: DataCategory::BrowserPasswords,
            content: vec![],
            is_dir: true,
        }];
        let removed = retire_stale(&std_fs(), &new_specs, &mut reg);
        assert!(removed.len() >= 5, "{removed:?}");
        assert!(reg.planted.is_empty());
        assert!(
            !local.join("Google").exists(),
            "empty legacy parents removed"
        );
        assert!(local.exists());
        assert_eq!(plant_with(&std_fs(), &new_specs, &mut reg, 0).len(), 1);
        // Idempotent.
        assert!(retire_stale(&std_fs(), &new_specs, &mut reg).is_empty());

        // A real Chrome next to a legacy decoy: decoy removed, Chrome kept;
        // a decoy the user changed is kept (and forgotten).
        let mut reg = CanaryRegistry::default();
        assert_eq!(plant_with(&std_fs(), &legacy, &mut reg, 0).len(), 5);
        let real_default = local
            .join("Google")
            .join("Chrome")
            .join("User Data")
            .join("Default");
        std::fs::create_dir_all(&real_default).unwrap();
        std::fs::write(real_default.join("Login Data"), b"real").unwrap();
        std::fs::write(ext.join("000003.log"), b"user changed it").unwrap();
        let removed = retire_stale(&std_fs(), &new_specs, &mut reg);
        assert!(removed.iter().any(|p| p.ends_with("Login Data")));
        assert!(!profile.join("Login Data").exists());
        assert_eq!(
            std::fs::read(ext.join("000003.log")).unwrap(),
            b"user changed it"
        );
        assert_eq!(
            std::fs::read(real_default.join("Login Data")).unwrap(),
            b"real"
        );
        assert!(reg.planted.is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// L12: a junction / symlink anywhere in the profile path is never followed.
    #[cfg(unix)]
    #[test]
    fn never_follows_links() {
        let d = tmpdir("links");
        let victim = d.join("system-dir");
        std::fs::create_dir_all(&victim).unwrap();
        // The "profile" points somewhere else via a symlinked directory.
        let profile = d.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        std::os::unix::fs::symlink(&victim, profile.join("AppData")).unwrap();
        let specs = vec![
            CanarySpec {
                path: profile
                    .join("AppData")
                    .join("Local")
                    .join("Login Data")
                    .to_string_lossy()
                    .into(),
                category: DataCategory::BrowserPasswords,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
            CanarySpec {
                path: profile
                    .join("AppData")
                    .join("wallet")
                    .to_string_lossy()
                    .into(),
                category: DataCategory::CryptoWallet,
                content: vec![],
                is_dir: true,
            },
            // final component is a link to a file elsewhere
            CanarySpec {
                path: profile.join("aws-credentials").to_string_lossy().into(),
                category: DataCategory::CloudToken,
                content: b"decoy".to_vec(),
                is_dir: false,
            },
        ];
        std::fs::write(victim.join("secret"), b"system file").unwrap();
        std::os::unix::fs::symlink(victim.join("secret"), profile.join("aws-credentials")).unwrap();
        let mut reg = CanaryRegistry::default();
        let ok = plant(&specs, &mut reg, &|_: &Path, _| {});
        assert!(ok.is_empty(), "{ok:?}");
        assert_eq!(
            std::fs::read_dir(&victim).unwrap().count(),
            1,
            "nothing created through the link"
        );
        assert_eq!(
            std::fs::read(victim.join("secret")).unwrap(),
            b"system file"
        );
        assert!(has_link_in_chain(&profile.join("AppData").join("x")));
        assert!(!has_link_in_chain(&profile.join("Desktop").join("x")));
        let _ = std::fs::remove_dir_all(&d);
    }
}
