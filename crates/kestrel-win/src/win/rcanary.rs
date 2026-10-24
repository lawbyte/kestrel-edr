//! Ransomware decoys on Windows: planting (only when the agent runs as
//! LocalSystem — never from an interactive `sensors-test`), the NT-path set
//! the Kernel-File aggregator matches, and a 2 s poller that catches
//! in-place encryption of a decoy (open + write without rename / overwrite
//! disposition, which Kernel-File Create/Rename/Delete cannot see without
//! the very high-volume Write keyword).

use super::etw::{FileState, Raw, Sink};
use super::safefs::{
    attr_tag, create_in_dir, delete_now_by_handle, final_path, is_name_surrogate, link_count,
    long_path, open_in_dir, open_verified_dir, rename_in_dir, set_attributes, RelOpenError,
};
use super::util::*;
use crate::canary::{CanaryRegistry, DecoyFs, Probe, RemoveResult};
use crate::fileagg::InPlaceWriter;
use crate::ntpath::DeviceMap;
use crate::rcanary;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE,
    FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

/// Is this process running as LocalSystem (the installed service)?
pub fn running_as_system() -> bool {
    open_process(std::process::id(), PROCESS_QUERY_LIMITED_INFORMATION)
        .map(|h| process_token_info(&h).0.as_deref() == Some("S-1-5-18"))
        .unwrap_or(false)
}

// ------------------------------------------------------------------ safe fs

/// Handle-based [`DecoyFs`] (security review v1.1 V-H8). Every operation:
/// * opens the parent directory with [`open_verified_dir`] (each ancestor
///   checked with `FILE_FLAG_OPEN_REPARSE_POINT`, final path verified) and
///   keeps that handle **without** `FILE_SHARE_DELETE`, so the directory
///   cannot be renamed / replaced by a junction while it is in use;
/// * opens or creates the file *relative to that handle*
///   (`NtCreateFile` + `RootDirectory`, `FILE_OPEN_REPARSE_POINT`), refuses
///   reparse points and files with more than one hard link, and checks the
///   handle's final path;
/// * hashes, deletes (`FileDispositionInfo`) and renames through the same
///   handle, opened with sharing `FILE_SHARE_READ` only: nobody can write
///   or swap the file between the hash check and the delete. An oplock
///   break during our open no longer helps: there is no later path lookup.
pub struct SafeDecoyFs;

/// Largest file read for hashing (decoys and credential canaries are small).
const MAX_HASH_BYTES: u64 = 4 * 1024 * 1024;
const DIR_ACCESS: u32 = FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_TRAVERSE;

fn split(path: &Path) -> Option<(String, String)> {
    let parent = path.parent()?.to_string_lossy().into_owned();
    let name = path.file_name()?.to_string_lossy().into_owned();
    (!parent.is_empty() && !name.is_empty()).then_some((parent, name))
}

fn open_dir(dir: &str) -> Result<Handle, String> {
    open_verified_dir(dir, DIR_ACCESS, FILE_SHARE_READ | FILE_SHARE_WRITE).map(|(h, _)| h)
}

/// Open (or create, with `create`) the directory chain of `dir` without
/// following links: the deepest existing ancestor is verified, missing
/// components are created relative to their verified parent.
fn ensure_dir(dir: &Path, create: bool) -> Result<Handle, String> {
    let s = dir.to_string_lossy().into_owned();
    if let Ok(h) = open_dir(&s) {
        return Ok(h);
    }
    if !create {
        return Err(format!("{s}: not an openable directory"));
    }
    // Deepest existing ancestor.
    let mut missing = Vec::new();
    let mut cur = dir.to_path_buf();
    let base = loop {
        if std::fs::symlink_metadata(&cur).is_ok() {
            break open_dir(&cur.to_string_lossy())?;
        }
        let name = cur
            .file_name()
            .ok_or_else(|| format!("{s}: no existing ancestor"))?
            .to_string_lossy()
            .into_owned();
        missing.push(name);
        cur = cur
            .parent()
            .ok_or_else(|| format!("{s}: no existing ancestor"))?
            .to_path_buf();
        if missing.len() > 16 {
            return Err(format!("{s}: too deep"));
        }
    };
    let mut h = base;
    for name in missing.iter().rev() {
        let child = open_in_dir(
            &h,
            name,
            DIR_ACCESS | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE,
        )
        .map_err(|e| format!("{s}: creating {name}: {e:?}"))?;
        let (attrs, tag) = attr_tag(&child).ok_or_else(|| format!("{s}: cannot query {name}"))?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate(tag) {
            return Err(format!("{s}: {name} is a link; refusing"));
        }
        h = child;
    }
    Ok(h)
}

/// Open `name` in `dir` for hashing (+ `extra` access), sharing read only.
/// Ok(None) when absent; Err(Probe::Dir / Foreign) for anything not a plain file.
fn open_file_in(
    dir: &Handle,
    dir_path: &str,
    name: &str,
    extra: u32,
) -> Result<Option<Handle>, Probe> {
    let h = match open_in_dir(
        dir,
        name,
        FILE_GENERIC_READ | extra,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    ) {
        Ok(h) => h,
        Err(RelOpenError::NotFound) => return Ok(None),
        Err(RelOpenError::IsDirectory) => return Err(Probe::Dir),
        Err(RelOpenError::Other(_)) => return Err(Probe::Foreign),
    };
    let Some((attrs, _)) = attr_tag(&h) else {
        return Err(Probe::Foreign);
    };
    if attrs & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(Probe::Foreign);
    }
    if link_count(&h) != Some(1) {
        return Err(Probe::Foreign);
    }
    let want = format!(r"{}\{name}", dir_path.trim_end_matches('\\'));
    match final_path(&h) {
        Some(fp) if crate::qpolicy::same_path(&long_path(&want), &fp) => Ok(Some(h)),
        _ => Err(Probe::Foreign),
    }
}

fn hash_handle(h: &Handle) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(
                h.raw(),
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return None;
        }
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_HASH_BYTES {
            return None;
        }
        hasher.update(&buf[..n as usize]);
    }
    Some(crate::vault::hex(&hasher.finalize()))
}

fn write_all(h: &Handle, data: &[u8]) -> bool {
    let mut off = 0usize;
    while off < data.len() {
        let chunk = (data.len() - off).min(1 << 20);
        let mut n = 0u32;
        let ok = unsafe {
            WriteFile(
                h.raw(),
                data[off..].as_ptr(),
                chunk as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            return false;
        }
        off += n as usize;
    }
    unsafe { FlushFileBuffers(h.raw()) != 0 }
}

impl DecoyFs for SafeDecoyFs {
    fn probe(&self, path: &Path) -> Probe {
        // A directory canary / a profile folder: the path itself is a dir.
        let s = path.to_string_lossy();
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.is_dir() {
                return match open_dir(&s) {
                    Ok(_) => Probe::Dir,
                    Err(_) => Probe::Foreign,
                };
            }
        }
        let Some((parent, name)) = split(path) else {
            return Probe::Foreign;
        };
        let dir = match open_dir(&parent) {
            Ok(d) => d,
            // A missing parent means the file is absent (it may be created
            // later through `ensure_dir`); anything else is foreign.
            Err(_) if std::fs::symlink_metadata(&parent).is_err() => return Probe::Absent,
            Err(_) => return Probe::Foreign,
        };
        match open_file_in(&dir, &parent, &name, 0) {
            Ok(None) => Probe::Absent,
            Ok(Some(h)) => hash_handle(&h).map_or(Probe::Foreign, Probe::File),
            Err(p) => p,
        }
    }

    fn create_dirs(&self, path: &Path, attrs: u32) -> std::io::Result<()> {
        let h = ensure_dir(path, true).map_err(std::io::Error::other)?;
        if attrs != 0 {
            // Re-open with attribute-write access through the verified chain.
            if let Some((parent, name)) = split(path) {
                if let Ok(p) = open_dir(&parent) {
                    if let Ok(d) = open_in_dir(
                        &p,
                        &name,
                        FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_OPEN,
                        FILE_DIRECTORY_FILE,
                    ) {
                        if let Some((cur, _)) = attr_tag(&d) {
                            if cur & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
                                set_attributes(&d, cur | attrs);
                            }
                        }
                    }
                }
            }
        }
        drop(h);
        Ok(())
    }

    fn write_file(
        &self,
        path: &Path,
        data: &[u8],
        replace_sha: Option<&str>,
        attrs: u32,
    ) -> std::io::Result<()> {
        let (parent, name) = split(path).ok_or_else(|| std::io::Error::other("bad canary path"))?;
        let dir = ensure_dir(Path::new(&parent), true).map_err(std::io::Error::other)?;
        // Re-verify the (possibly just created) parent by path too.
        let dir_path = parent.clone();
        // Existing file: must be exactly ours to be replaced.
        match (open_file_in(&dir, &dir_path, &name, DELETE), replace_sha) {
            (Ok(None), _) => {}
            (Ok(Some(h)), Some(want)) => {
                if !hash_handle(&h).is_some_and(|s| s.eq_ignore_ascii_case(want)) {
                    return Err(std::io::Error::other("canary changed; not replaced"));
                }
                if !delete_now_by_handle(&h) {
                    return Err(std::io::Error::other("cannot remove old canary"));
                }
            }
            _ => return Err(std::io::Error::other("target exists and is not ours")),
        }
        // Temp file relative to the verified directory, then renamed in.
        let tmp = format!("{name}.kestrel-tmp");
        if let Ok(Some(old)) = open_file_in(&dir, &dir_path, &tmp, DELETE) {
            delete_now_by_handle(&old); // our own leftover from a crash
        }
        let access = FILE_GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
        let h = create_in_dir(&dir, &tmp, access, 0)?;
        if !write_all(&h, data) {
            delete_now_by_handle(&h);
            return Err(std::io::Error::other("writing canary failed"));
        }
        if attrs != 0 {
            set_attributes(&h, attrs);
        }
        if !rename_in_dir(&h, &dir, &name) {
            let e = std::io::Error::last_os_error();
            delete_now_by_handle(&h);
            return Err(std::io::Error::other(format!(
                "canary not renamed into place (target appeared?): {e}"
            )));
        }
        Ok(())
    }

    fn ensure_attributes(&self, path: &Path, sha: &str, attrs: u32) -> std::io::Result<bool> {
        let (parent, name) = split(path).ok_or_else(|| std::io::Error::other("bad canary path"))?;
        let dir = open_dir(&parent).map_err(std::io::Error::other)?;
        // Same handle for the hash check and the attribute change (sharing
        // read only: nobody can swap or rewrite the file in between).
        let h = match open_file_in(&dir, &parent, &name, FILE_WRITE_ATTRIBUTES) {
            Ok(Some(h)) => h,
            Ok(None) => return Err(std::io::Error::from(std::io::ErrorKind::NotFound)),
            Err(_) => return Err(std::io::Error::other("not a plain file; left alone")),
        };
        if !hash_handle(&h).is_some_and(|s| s.eq_ignore_ascii_case(sha)) {
            return Err(std::io::Error::other(
                "decoy changed by the user; left alone",
            ));
        }
        let (cur, _) = attr_tag(&h).ok_or_else(|| std::io::Error::other("cannot query"))?;
        if cur & attrs == attrs {
            return Ok(false);
        }
        // FILE_ATTRIBUTE_NORMAL (0x80) is only valid alone.
        let new = (cur & !0x80) | attrs;
        if set_attributes(&h, new) {
            Ok(true)
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn remove_if_ours(&self, path: &Path, sha: &str) -> RemoveResult {
        let Some((parent, name)) = split(path) else {
            return RemoveResult::NotOurs;
        };
        let dir = match open_dir(&parent) {
            Ok(d) => d,
            Err(_) if std::fs::symlink_metadata(&parent).is_err() => return RemoveResult::Gone,
            Err(_) => return RemoveResult::NotOurs,
        };
        match open_file_in(&dir, &parent, &name, DELETE) {
            Ok(None) => RemoveResult::Gone,
            Ok(Some(h)) => match hash_handle(&h) {
                Some(s) if s.eq_ignore_ascii_case(sha) => {
                    if delete_now_by_handle(&h) {
                        RemoveResult::Removed
                    } else {
                        RemoveResult::Failed
                    }
                }
                Some(_) => RemoveResult::NotOurs,
                None => RemoveResult::Failed,
            },
            // Sharing violation (someone has it open for writing) etc.
            // is reported as Foreign by `open_file_in`: leave it.
            Err(_) => RemoveResult::NotOurs,
        }
    }

    fn remove_empty_dir(&self, path: &Path) -> RemoveResult {
        let Some((parent, name)) = split(path) else {
            return RemoveResult::NotOurs;
        };
        let dir = match open_dir(&parent) {
            Ok(d) => d,
            Err(_) if std::fs::symlink_metadata(&parent).is_err() => return RemoveResult::Gone,
            Err(_) => return RemoveResult::NotOurs,
        };
        // Relative to the verified parent, the link itself (never its target).
        let h = match open_in_dir(
            &dir,
            &name,
            DELETE | FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        ) {
            Ok(h) => h,
            Err(RelOpenError::NotFound) => return RemoveResult::Gone,
            Err(_) => return RemoveResult::NotOurs,
        };
        match attr_tag(&h) {
            Some((attrs, _))
                if attrs & FILE_ATTRIBUTE_REPARSE_POINT == 0
                    && attrs & FILE_ATTRIBUTE_DIRECTORY != 0 => {}
            _ => return RemoveResult::NotOurs,
        }
        // Fails (STATUS_DIRECTORY_NOT_EMPTY) unless the folder is empty.
        if delete_now_by_handle(&h) {
            RemoveResult::Removed
        } else {
            RemoveResult::NotOurs
        }
    }
}

/// Plant decoys for every profile (SYSTEM only). Returns the decoy paths
/// (Win32) now in place, including ones planted earlier.
pub fn plant(state_dir: &Path, profiles: &[String]) -> Vec<String> {
    let mut reg: CanaryRegistry = rcanary::load_registry(state_dir);
    let ok = rcanary::plant_with(&SafeDecoyFs, profiles, &mut reg);
    if let Err(e) = rcanary::save_registry(state_dir, &reg) {
        tracing::warn!("saving ransomware canary registry: {e}");
    }
    ok
}

/// Decoys already planted (from the registry), without planting.
pub fn planted(state_dir: &Path) -> Vec<String> {
    rcanary::load_registry(state_dir)
        .planted
        .values()
        .map(|r| r.path.clone())
        .collect()
}

fn stamp(p: &Path) -> Option<(u64, SystemTime)> {
    let m = std::fs::symlink_metadata(p).ok()?;
    Some((m.len(), m.modified().ok()?))
}

/// Start the in-place-modification poller.
pub fn start_poller(
    paths: Vec<String>,
    devmap: Arc<RwLock<DeviceMap>>,
    file_state: Arc<Mutex<FileState>>,
    sink: Sink,
    stop: Arc<AtomicBool>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name("kestrel-rcanary".into())
        .spawn(move || {
            let mut base: HashMap<PathBuf, Option<(u64, SystemTime)>> = paths
                .iter()
                .map(|p| (PathBuf::from(p), stamp(Path::new(p))))
                .collect();
            // Decoys found gone, waiting for the Kernel-File rename / delete
            // event that names the real actor (time noticed).
            let mut gone: HashMap<PathBuf, i64> = HashMap::new();
            let nt_of = |p: &Path| {
                let win32 = p.to_string_lossy().into_owned();
                devmap
                    .read()
                    .ok()
                    .and_then(|m| m.to_nt_lower(&win32))
                    .unwrap_or_else(|| win32.to_ascii_lowercase())
            };
            // V-H9: only a single recent (write-capable) opener is blamed; a
            // remote (pid 4) writer is reported as such.
            let report = |nt: &str, ts: i64| {
                let emit = file_state.lock().ok().map(|mut fs| {
                    let w = fs.openers.in_place_writer(nt, ts);
                    let pid = match w {
                        InPlaceWriter::Local(p) => p,
                        InPlaceWriter::Remote => 4,
                        InPlaceWriter::Unknown => 0,
                    };
                    fs.agg.canary_modified(ts, pid, nt)
                });
                if let Some(e) = emit {
                    sink.send(Raw::FileActivity {
                        ts: e.ts,
                        pid: e.pid,
                        act: Box::new(e.activity),
                    });
                }
            };
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_secs(2));
                let now = kestrel_common::now_ms();
                for (p, old) in base.iter_mut() {
                    let now_stamp = stamp(p);
                    let change = rcanary::stamp_change(old, &now_stamp);
                    *old = now_stamp;
                    match change {
                        rcanary::StampChange::Same => {}
                        rcanary::StampChange::Appeared => {
                            gone.remove(p);
                        }
                        rcanary::StampChange::Gone => {
                            gone.insert(p.clone(), now);
                        }
                        rcanary::StampChange::Modified => report(&nt_of(p), now),
                    }
                }
                gone.retain(|p, noticed| {
                    let nt = nt_of(p);
                    let kernel = file_state.lock().is_ok_and(|fs| {
                        fs.agg
                            .kernel_hit_since(&nt, *noticed - rcanary::GONE_LOOKBACK_MS)
                    });
                    match rcanary::gone_verdict(*noticed, now, kernel) {
                        None => true,
                        Some(false) => false,
                        Some(true) => {
                            report(&nt, *noticed);
                            false
                        }
                    }
                });
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canary::DecoyFs;
    use kestrel_platform::CanarySpec;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kestrel-safefs-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn safe_fs_plant_probe_remove() {
        let d = tmp("plant");
        let fs = SafeDecoyFs;
        let p = d.join("Documents").join("!Payroll Q3.xlsx");
        assert_eq!(fs.probe(&p), Probe::Absent);
        fs.write_file(&p, b"decoy-1", None, 0).unwrap();
        let sha1 = match fs.probe(&p) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        // Refuses to create over an existing file, or replace a foreign one.
        assert!(fs.write_file(&p, b"x", None, 0).is_err());
        assert!(fs.write_file(&p, b"x", Some("00"), 0).is_err());
        // Replaces ours.
        fs.write_file(&p, b"decoy-2", Some(&sha1), 0).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"decoy-2");
        // Not ours any more -> left alone.
        assert_eq!(fs.remove_if_ours(&p, &sha1), RemoveResult::NotOurs);
        let sha2 = match fs.probe(&p) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(fs.remove_if_ours(&p, &sha2), RemoveResult::Removed);
        assert!(!p.exists());
        assert_eq!(fs.remove_if_ours(&p, &sha2), RemoveResult::Gone);
        // Hard-linked file is never ours.
        let q = d.join("Documents").join("linked.docx");
        std::fs::write(&q, b"z").unwrap();
        std::fs::hard_link(&q, d.join("other-name")).unwrap();
        assert_eq!(fs.probe(&q), Probe::Foreign);
        // Directory canary through the generic planter (hidden).
        let mut reg = CanaryRegistry::default();
        let w = d.join("AppData").join("wallet");
        let specs = vec![CanarySpec {
            path: w.to_string_lossy().into_owned(),
            category: kestrel_common::DataCategory::CryptoWallet,
            content: vec![],
            is_dir: true,
        }];
        assert_eq!(
            crate::canary::plant_with(&fs, &specs, &mut reg, crate::canary::ATTR_HIDDEN).len(),
            1
        );
        assert!(w.is_dir());
        // Empty-directory removal (decoy migration): only when empty.
        std::fs::write(w.join("user-file"), b"u").unwrap();
        assert_eq!(fs.remove_empty_dir(&w), RemoveResult::NotOurs);
        assert!(w.join("user-file").exists());
        std::fs::remove_file(w.join("user-file")).unwrap();
        assert_eq!(fs.remove_empty_dir(&w), RemoveResult::Removed);
        assert!(!w.exists());
        assert_eq!(fs.remove_empty_dir(&w), RemoveResult::Gone);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// Fresh-install lab 2026-10-21: decoys planted by 1.1.2 without
    /// FILE_ATTRIBUTE_HIDDEN get it on upgrade through the same verified
    /// handle, without being rewritten; a decoy the user changed is left
    /// exactly as it is.
    #[test]
    fn safe_fs_reapplies_hidden_to_our_decoys_only() {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN;
        let d = tmp("attrs");
        let fs = SafeDecoyFs;
        let p = d.join("Documents").join("!Payroll Q3.xlsx");
        fs.write_file(&p, b"decoy", None, 0).unwrap();
        let sha = match fs.probe(&p) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        let m0 = std::fs::metadata(&p).unwrap();
        assert_eq!(m0.file_attributes() & FILE_ATTRIBUTE_HIDDEN, 0);
        assert!(fs
            .ensure_attributes(&p, &sha, crate::canary::ATTR_HIDDEN)
            .unwrap());
        let m1 = std::fs::metadata(&p).unwrap();
        assert_ne!(m1.file_attributes() & FILE_ATTRIBUTE_HIDDEN, 0);
        assert_eq!(m1.modified().unwrap(), m0.modified().unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"decoy");
        // Already set: nothing to do.
        assert!(!fs
            .ensure_attributes(&p, &sha, crate::canary::ATTR_HIDDEN)
            .unwrap());
        // A user-changed decoy keeps its attributes.
        let q = d.join("Documents").join("0 Contract - signed.pdf");
        fs.write_file(&q, b"decoy-q", None, 0).unwrap();
        let sha_q = match fs.probe(&q) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        std::fs::write(&q, b"the user's own text").unwrap();
        assert!(fs
            .ensure_attributes(&q, &sha_q, crate::canary::ATTR_HIDDEN)
            .is_err());
        assert_eq!(
            std::fs::metadata(&q).unwrap().file_attributes() & FILE_ATTRIBUTE_HIDDEN,
            0
        );
        // New decoys through the planter are created hidden.
        let r = d.join("Pictures").join("!IMG_0001.jpg");
        let mut reg = CanaryRegistry::default();
        let specs = vec![CanarySpec {
            path: r.to_string_lossy().into_owned(),
            category: kestrel_common::DataCategory::PasswordManager,
            content: b"jpeg".to_vec(),
            is_dir: false,
        }];
        std::fs::create_dir_all(r.parent().unwrap()).unwrap();
        assert_eq!(
            crate::canary::plant_with(&fs, &specs, &mut reg, crate::canary::ATTR_HIDDEN).len(),
            1
        );
        assert_ne!(
            std::fs::metadata(&r).unwrap().file_attributes() & FILE_ATTRIBUTE_HIDDEN,
            0
        );
        // Hidden decoys are still found by the probe and removed when ours.
        let sha_r = match fs.probe(&r) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        assert_eq!(fs.remove_if_ours(&r, &sha_r), RemoveResult::Removed);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// V-H8: a junction in the path (here: the decoy folder redirected to a
    /// "victim" directory) is never followed for plant or delete.
    #[test]
    fn safe_fs_refuses_junctions() {
        let d = tmp("junction");
        let victim = d.join("victim");
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(victim.join("!Payroll Q3.xlsx"), b"victim data").unwrap();
        let link = d.join("Documents");
        let ok = std::process::Command::new(format!(r"{}\System32\cmd.exe", system_root()))
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&victim)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            eprintln!("mklink /J unavailable; skipping");
            return;
        }
        let fs = SafeDecoyFs;
        let p = link.join("!Payroll Q3.xlsx");
        let sha = match SafeDecoyFs.probe(&victim.join("!Payroll Q3.xlsx")) {
            Probe::File(s) => s,
            other => panic!("{other:?}"),
        };
        // Same content hash, but reached through a junction: refused.
        assert_eq!(fs.remove_if_ours(&p, &sha), RemoveResult::NotOurs);
        assert!(fs
            .write_file(&link.join("new.docx"), b"x", None, 0)
            .is_err());
        // The junction itself is never removed as an "empty decoy folder".
        assert_eq!(fs.remove_empty_dir(&link), RemoveResult::NotOurs);
        assert!(link.exists());
        assert_eq!(
            std::fs::read(victim.join("!Payroll Q3.xlsx")).unwrap(),
            b"victim data"
        );
        assert!(!victim.join("new.docx").exists());
        let _ = std::fs::remove_dir(&link);
        let _ = std::fs::remove_dir_all(&d);
    }
}
