//! Encrypted quarantine vault (`<state>\quarantine`).
//!
//! * Per-host 256-bit key, generated once, stored DPAPI-protected with
//!   machine scope (`key.dpapi`); the directory DACL is SYSTEM + Administrators only.
//! * Files are opened with backup semantics (SeBackup/SeRestore enabled), so
//!   restrictive DACLs do not block quarantine, and **without following
//!   links** ([`super::safefs`]): no junction / symlink on the path, one hard
//!   link, final path == requested path; all I/O goes through that handle.
//! * Sealed with the streaming AES-256-GCM format in [`crate::vault`]; the
//!   index (`index.json`) keeps original path, SHA-256, size, attributes and
//!   the original owner/group/DACL as SDDL for restore.
//! * If the original cannot be deleted (a running image), it is renamed
//!   through the handle to `<name>.<id>.kestrel-quarantined`, execute is
//!   denied and the renamed file is scheduled for deletion at reboot.
//! * Restore goes only to the recorded path, re-validated (see [`Vault::restore`]).
//! * `RemoveAutorun` backups (registry value, task XML, service config, WMI
//!   MOF) are sealed the same way ([`Vault::store_backup`]) as entries of kind
//!   `autorun_backup`; `RestoreFile` refuses them, `DeleteQuarantined` works.

use super::safefs;
use super::util::*;
use crate::qpolicy;
use crate::vault::{
    decrypt_stream, encrypt_stream, EntryKind, EntryState, QuarantineEntry, QuarantineIndex,
};
use kestrel_platform::ActionOrigin;
use std::ffi::c_void;
use std::io;
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
use windows_sys::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
    CRYPT_INTEGER_BLOB,
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, DELETE, FILE_ADD_FILE, FILE_ATTRIBUTE_NORMAL, FILE_LIST_DIRECTORY,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES,
    INVALID_FILE_ATTRIBUTES, MOVEFILE_DELAY_UNTIL_REBOOT, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};

/// Descriptor for an in-use original that could not be deleted: SYSTEM and
/// Administrators only, execute denied to everyone.
const QUARANTINED_SDDL: &str = "D:P(D;;FX;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)";

pub struct Vault {
    dir: PathBuf,
    key: [u8; 32],
    index: Mutex<QuarantineIndex>,
}

fn dpapi(data: &[u8], protect: bool) -> io::Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: data.len() as u32,
        pbData: data.as_ptr() as *mut u8,
    };
    let mut out = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let desc = wide("Kestrel quarantine key");
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                desc.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        } else {
            CryptUnprotectData(
                &input,
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
    };
    if ok == 0 {
        return Err(last_err());
    }
    let v = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec() };
    unsafe { windows_sys::Win32::Foundation::LocalFree(out.pbData as *mut c_void) };
    Ok(v)
}

impl Vault {
    pub fn open(state_dir: &Path) -> io::Result<Vault> {
        let dir = state_dir.join("quarantine");
        ensure_private_dir(&dir)?;
        let key_path = dir.join("key.dpapi");
        let key = match std::fs::read(&key_path) {
            Ok(blob) => {
                let k = dpapi(&blob, false)?;
                k.try_into().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "bad quarantine key length")
                })?
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut k = [0u8; 32];
                getrandom::getrandom(&mut k).map_err(|e| io::Error::other(e.to_string()))?;
                write_atomic(&key_path, &dpapi(&k, true)?)?;
                k
            }
            Err(e) => return Err(e),
        };
        let index = std::fs::read(dir.join("index.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        Ok(Vault {
            dir,
            key,
            index: Mutex::new(index),
        })
    }

    fn save(&self, idx: &QuarantineIndex) -> io::Result<()> {
        write_atomic(
            &self.dir.join("index.json"),
            &serde_json::to_vec_pretty(idx).map_err(io::Error::other)?,
        )
    }

    fn blob_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.bin"))
    }

    /// Quarantine `path` on behalf of `origin` (H8). Returns (quarantine id, detail).
    ///
    /// * policy first ([`qpolicy::quarantine_allowed`]): automatic actions
    ///   only touch user-writable / external locations; server commands never
    ///   Microsoft-signed OS files, protected images or Kestrel itself;
    /// * the file is opened without following links anywhere in its path,
    ///   must have one hard link and its final path must equal the request
    ///   ([`safefs::open_verified_file`]); everything else happens through
    ///   that handle — no `takeown` / `icacls`, no path-based re-opens;
    /// * the expected sha256 (when given) is checked before the original is
    ///   touched.
    pub fn quarantine(
        &self,
        path: &str,
        expected_sha256: Option<&str>,
        origin: ActionOrigin,
        system_drive: char,
        own_prefixes: &[String],
    ) -> Result<(String, String), String> {
        let long = safefs::long_path(path);
        let ms_signed = if qpolicy::needs_signature_check(&long, origin, system_drive) {
            let (st, signer, ms_root) = super::enrich::verify_signature_ms(&long);
            st == kestrel_common::SignatureState::Valid
                && (ms_root
                    || signer
                        .as_deref()
                        .is_some_and(kestrel_detect::protect::is_microsoft_signer))
        } else {
            false
        };
        qpolicy::quarantine_allowed(&long, origin, ms_signed, system_drive, own_prefixes)?;
        let v = safefs::open_verified_file(
            &long,
            GENERIC_READ | DELETE | READ_CONTROL | WRITE_DAC | FILE_WRITE_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_DELETE | FILE_SHARE_WRITE,
        )?;
        let path = v.path.clone();
        let h = v.h;
        let acl_sddl = sddl_of_handle(h.raw());
        let parent_owner = std::path::Path::new(&path)
            .parent()
            .and_then(|p| {
                safefs::open_verified_dir(
                    &p.to_string_lossy(),
                    READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                )
                .ok()
            })
            .and_then(|(dh, _)| safefs::owner_sid(&dh));
        let id = uuid::Uuid::new_v4().to_string();
        let blob = self.blob_path(&id);
        let tmp = blob.with_extension("partial");
        // Read through a File view that does not own our handle.
        let sealed = {
            let src = unsafe { std::fs::File::from_raw_handle(h.raw() as _) };
            let src = std::mem::ManuallyDrop::new(src);
            let out =
                std::fs::File::create(&tmp).map_err(|e| format!("vault write failed: {e}"))?;
            let mut prefix = [0u8; 8];
            getrandom::getrandom(&mut prefix).map_err(|e| e.to_string())?;
            let r = encrypt_stream(
                &self.key,
                prefix,
                std::io::BufReader::with_capacity(1 << 20, &*src),
                std::io::BufWriter::new(out),
            );
            match r {
                Ok(s) => s,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(format!("encryption failed: {e}"));
                }
            }
        };
        if let Some(exp) = expected_sha256 {
            if !exp.trim().is_empty() && !exp.trim().eq_ignore_ascii_case(&sealed.sha256) {
                let _ = std::fs::remove_file(&tmp);
                return Err(format!(
                    "sha256 mismatch: expected {exp}, file is {} — file changed, not quarantined",
                    sealed.sha256
                ));
            }
        }
        {
            let idx = self.index.lock().map_err(|_| "index lock poisoned")?;
            if let Some(e) = idx.find_held(&path, &sealed.sha256) {
                let _ = std::fs::remove_file(&tmp);
                // Already held; still make sure the original is gone.
                let id = e.id.clone();
                drop(idx);
                let note = Self::remove_original(&h, &path, &id);
                return Ok((id.clone(), format!("already quarantined as {id}; {note}")));
            }
        }
        std::fs::rename(&tmp, &blob).map_err(|e| format!("vault rename failed: {e}"))?;
        let note = Self::remove_original(&h, &path, &id);
        drop(h);
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: path.clone(),
            sha256: sealed.sha256.clone(),
            size: sealed.plaintext_len,
            acl_sddl,
            attributes: if v.attributes == INVALID_FILE_ATTRIBUTES {
                0
            } else {
                v.attributes
            },
            created_at: kestrel_common::now_ms(),
            state: EntryState::Held,
            note: note.clone(),
            parent_owner,
            kind: EntryKind::File,
        };
        let mut idx = self.index.lock().map_err(|_| "index lock poisoned")?;
        idx.entries.push(entry);
        self.save(&idx)
            .map_err(|e| format!("index write failed: {e}"))?;
        Ok((
            id.clone(),
            format!(
                "quarantined {path} as {id} (sha256 {}, {} bytes); {note}",
                sealed.sha256, sealed.plaintext_len
            ),
        ))
    }

    /// Delete the original through our (verified) handle; for files in use,
    /// rename it through the handle to a unique name, deny execute on it via
    /// the handle and schedule *that unique name* for deletion at reboot —
    /// never the original path, which a junction could redirect later.
    fn remove_original(h: &Handle, path: &str, id: &str) -> String {
        if safefs::delete_by_handle(h) {
            return "original deleted".into();
        }
        let err = last_err();
        // Read-only attribute blocks deletion: clear it (via the handle) and retry.
        let _ = safefs::set_attributes(h, FILE_ATTRIBUTE_NORMAL);
        if safefs::delete_by_handle(h) {
            return "original deleted".into();
        }
        let short = id.split('-').next().unwrap_or(id);
        let renamed = format!("{path}.{short}.kestrel-quarantined");
        let moved = safefs::rename_by_handle(h, &renamed);
        // SYSTEM + Administrators only, execute denied to everyone.
        let deny = safefs::set_security(h, QUARANTINED_SDDL, true).is_ok();
        let mut scheduled = false;
        if moved {
            let wr = wide(&renamed);
            scheduled =
                unsafe { MoveFileExW(wr.as_ptr(), std::ptr::null(), MOVEFILE_DELAY_UNTIL_REBOOT) }
                    != 0;
        }
        format!(
            "original could not be deleted ({err}); {}{}{}",
            if moved {
                format!("renamed to {renamed}")
            } else {
                "left in place".into()
            },
            if deny { ", execute denied" } else { "" },
            if scheduled {
                ", deletion scheduled at reboot"
            } else {
                ""
            }
        )
    }

    /// Seal an in-memory backup (a `RemoveAutorun` original) into the vault.
    /// `label` is recorded as the entry's `original_path` (never a real path:
    /// the entry kind makes `restore` refuse it). Returns the vault id.
    /// The blob is written and the index saved **before** the caller changes
    /// anything, so a failed backup means no removal.
    pub fn store_backup(&self, label: &str, data: &[u8]) -> Result<String, String> {
        let id = uuid::Uuid::new_v4().to_string();
        let blob = self.blob_path(&id);
        let tmp = blob.with_extension("partial");
        let mut prefix = [0u8; 8];
        getrandom::getrandom(&mut prefix).map_err(|e| e.to_string())?;
        let sealed = {
            let out =
                std::fs::File::create(&tmp).map_err(|e| format!("vault write failed: {e}"))?;
            match encrypt_stream(&self.key, prefix, data, std::io::BufWriter::new(out)) {
                Ok(s) => s,
                Err(e) => {
                    let _ = std::fs::remove_file(&tmp);
                    return Err(format!("encryption failed: {e}"));
                }
            }
        };
        if let Err(e) = std::fs::rename(&tmp, &blob) {
            let _ = std::fs::remove_file(&tmp);
            return Err(format!("vault rename failed: {e}"));
        }
        let entry = QuarantineEntry {
            id: id.clone(),
            original_path: label.to_string(),
            sha256: sealed.sha256,
            size: sealed.plaintext_len,
            acl_sddl: None,
            attributes: 0,
            created_at: kestrel_common::now_ms(),
            state: EntryState::Held,
            note: "autorun backup".into(),
            parent_owner: None,
            kind: EntryKind::AutorunBackup,
        };
        let mut idx = self.index.lock().map_err(|_| "index lock poisoned")?;
        idx.entries.push(entry);
        if let Err(e) = self.save(&idx) {
            idx.entries.retain(|x| x.id != id);
            let _ = std::fs::remove_file(&blob);
            return Err(format!("index write failed: {e}"));
        }
        Ok(id)
    }

    /// Restore a held item to its **recorded** original path only (H8):
    /// never into %SystemRoot% / Program Files; the parent directory must
    /// still exist, contain no junction / link on its path, resolve to itself
    /// and have the same owner class as at quarantine time; the file is
    /// created relative to the verified (and locked) parent handle with
    /// `FILE_CREATE`, so nothing is ever overwritten or redirected.
    pub fn restore(&self, id: &str, system_drive: char) -> Result<String, String> {
        let mut idx = self.index.lock().map_err(|_| "index lock poisoned")?;
        let e = idx
            .get(id)
            .cloned()
            .ok_or_else(|| format!("unknown quarantine id {id}"))?;
        if e.state != EntryState::Held {
            return Err(format!("quarantine item {id} is {:?}, not held", e.state));
        }
        if e.kind != EntryKind::File {
            return Err(format!(
                "quarantine item {id} is an autorun backup ({}), not a file; it cannot be restored with restore_file",
                e.original_path
            ));
        }
        qpolicy::restore_allowed(&e.original_path, system_drive)?;
        let dest = std::path::Path::new(&e.original_path);
        let parent = dest
            .parent()
            .ok_or_else(|| format!("{} has no parent directory", e.original_path))?
            .to_string_lossy()
            .to_string();
        let name = dest
            .file_name()
            .ok_or_else(|| format!("{} has no file name", e.original_path))?
            .to_string_lossy()
            .to_string();
        // No FILE_SHARE_DELETE: the directory cannot be renamed or replaced
        // while we hold it.
        let (dir, _) = safefs::open_verified_dir(
            &parent,
            FILE_LIST_DIRECTORY | FILE_ADD_FILE | FILE_TRAVERSE | READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
        )
        .map_err(|er| format!("restore refused: {er}"))?;
        let owner = safefs::owner_sid(&dir).ok_or("cannot read the parent directory's owner")?;
        qpolicy::restore_parent_ok(e.parent_owner.as_deref(), &owner)
            .map_err(|er| format!("restore refused: {er}"))?;
        let fh = safefs::create_in_dir(
            &dir,
            &name,
            GENERIC_WRITE | DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | FILE_WRITE_ATTRIBUTES,
            0,
        )
        .map_err(|er| format!("cannot create {}: {er}", e.original_path))?;
        let blob = std::fs::File::open(self.blob_path(id))
            .map_err(|er| format!("vault file missing: {er}"))?;
        let r = {
            let out = unsafe { std::fs::File::from_raw_handle(fh.raw() as _) };
            let out = std::mem::ManuallyDrop::new(out);
            decrypt_stream(
                &self.key,
                std::io::BufReader::with_capacity(1 << 20, blob),
                std::io::BufWriter::new(&*out),
            )
        };
        let sealed = match r {
            Ok(s) if s.sha256.eq_ignore_ascii_case(&e.sha256) => s,
            Ok(_) => {
                safefs::delete_by_handle(&fh);
                return Err("restored content hash mismatch".into());
            }
            Err(er) => {
                safefs::delete_by_handle(&fh);
                return Err(format!("decryption failed: {er}"));
            }
        };
        let mut notes = Vec::new();
        if let Some(sddl) = &e.acl_sddl {
            if let Err(er) = safefs::set_security(&fh, sddl, false) {
                notes.push(format!("original ACL not re-applied: {er}"));
            }
        }
        if e.attributes != 0 {
            let _ = safefs::set_attributes(&fh, e.attributes);
        }
        drop(fh);
        drop(dir);
        let _ = std::fs::remove_file(self.blob_path(id));
        if let Some(m) = idx.get_mut(id) {
            m.state = EntryState::Restored;
        }
        self.save(&idx)
            .map_err(|er| format!("index write failed: {er}"))?;
        let mut d = format!(
            "restored {} (sha256 {}, {} bytes)",
            e.original_path, e.sha256, sealed.plaintext_len
        );
        if !notes.is_empty() {
            d.push_str("; ");
            d.push_str(&notes.join("; "));
        }
        Ok(d)
    }

    pub fn delete(&self, id: &str) -> Result<String, String> {
        let mut idx = self.index.lock().map_err(|_| "index lock poisoned")?;
        let e = idx
            .get(id)
            .cloned()
            .ok_or_else(|| format!("unknown quarantine id {id}"))?;
        if e.state != EntryState::Held {
            return Err(format!("quarantine item {id} is {:?}, not held", e.state));
        }
        match std::fs::remove_file(self.blob_path(id)) {
            Ok(()) => {}
            Err(er) if er.kind() == io::ErrorKind::NotFound => {}
            Err(er) => return Err(format!("cannot delete vault file: {er}")),
        }
        if let Some(m) = idx.get_mut(id) {
            m.state = EntryState::Deleted;
        }
        self.save(&idx)
            .map_err(|er| format!("index write failed: {er}"))?;
        Ok(format!(
            "permanently deleted quarantined copy of {} ({})",
            e.original_path, e.sha256
        ))
    }
}
