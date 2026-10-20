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

/// Plant `specs`; returns paths that now hold Kestrel canaries. `set_hidden`
/// marks files/dirs hidden (Windows: FILE_ATTRIBUTE_HIDDEN).
pub fn plant(
    specs: &[CanarySpec],
    reg: &mut CanaryRegistry,
    set_hidden: &dyn Fn(&Path),
) -> Vec<String> {
    let mut ok = Vec::new();
    for spec in specs {
        let path = Path::new(&spec.path);
        let k = key(&spec.path);
        let rec = reg.planted.get(&k);
        if has_link_in_chain(path) {
            tracing::warn!(path = %spec.path, "not planting canary: link / junction in the path");
            continue;
        }
        let exists = path.exists();
        if spec.is_dir {
            match decide(true, exists, None, rec, "") {
                Decision::WriteNew => {
                    if create_dirs_no_follow(path).is_ok() {
                        set_hidden(path);
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
        let current = if exists && path.is_file() {
            std::fs::read(path).ok().map(|b| hex(&Sha256::digest(&b)))
        } else {
            None
        };
        if exists && !path.is_file() {
            continue; // a directory (or something else) sits where a file canary should go
        }
        match decide(false, exists, current.as_deref(), rec, &new_sha) {
            Decision::WriteNew | Decision::Refresh => {
                // Temp name first so a crash never leaves a partial canary.
                let written = write_no_follow(path, &spec.content).is_ok();
                if written {
                    set_hidden(path);
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
            Decision::KeepOurs => ok.push(spec.path.clone()),
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
        let h = |_: &Path| *hidden.borrow_mut() += 1;
        let ok = plant(&specs, &mut reg, &h);
        assert_eq!(ok.len(), 2);
        assert_eq!(std::fs::read(&real).unwrap(), b"user's real data");
        assert_eq!(*hidden.borrow(), 2);
        // Second run: keep, no rewrites.
        let ok2 = plant(&specs, &mut reg, &h);
        assert_eq!(ok2.len(), 2);
        assert_eq!(*hidden.borrow(), 2);
        // User replaced our decoy with real content → we leave it alone.
        std::fs::write(&specs[0].path, b"now real").unwrap();
        let ok3 = plant(&specs, &mut reg, &h);
        assert_eq!(ok3.len(), 1);
        assert_eq!(std::fs::read(&specs[0].path).unwrap(), b"now real");
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
        let ok = plant(&specs, &mut reg, &|_: &Path| {});
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
