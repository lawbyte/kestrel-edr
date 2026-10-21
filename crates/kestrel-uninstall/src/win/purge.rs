//! Optional purge of `%ProgramData%\Kestrel` after a successful uninstall,
//! without ever following a reparse point (same approach as
//! `kestrel-win`'s `hardfs`):
//!
//! * The folder is opened with `FILE_FLAG_OPEN_REPARSE_POINT`; it must be a
//!   real directory (not a junction / symbolic link / mount point), its
//!   `GetFinalPathNameByHandleW` must equal the expected path (so no link
//!   on any parent either), and its owner must be SYSTEM or
//!   Administrators (the installer and the agent create it that way; a
//!   folder planted by someone else is left alone).
//! * Children are enumerated through the directory handle
//!   (`FileFullDirectoryInfo`) and each one is opened **relative to its
//!   parent handle** (`NtCreateFile` with `RootDirectory` and
//!   `FILE_OPEN_REPARSE_POINT`). Reparse points are deleted as themselves
//!   and never descended into, so a link's target is never touched.
//! * Deletes go through the open handle (`FileDispositionInfoEx`, POSIX
//!   semantics, ignore read-only; classic disposition as a fallback).
//! * Best effort: an item that cannot be deleted (in use) is counted and
//!   the rest continues.

use super::{last_err, wide, Handle};
use crate::{same_final_path, PurgeReport};
use std::ffi::c_void;
use std::io;
use std::path::Path;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT,
    FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, RtlNtStatusToDosError, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES,
    ERROR_PATH_NOT_FOUND, ERROR_SHARING_VIOLATION, ERROR_SUCCESS, HANDLE, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo, FileDispositionInfoEx,
    FileFullDirectoryInfo, FileFullDirectoryRestartInfo, FileStandardInfo,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, SetFileInformationByHandle, DELETE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO,
    FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, OPEN_EXISTING,
    READ_CONTROL, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const MAX_DEPTH: usize = 256;

/// Why the folder was left alone.
#[derive(Debug)]
pub enum PurgeError {
    /// Nothing to delete.
    NotFound,
    /// The folder itself is a junction / symbolic link / mount point.
    IsLink,
    /// Not a directory.
    NotADirectory,
    /// It resolves somewhere else (a link on a parent folder).
    Redirected(String),
    /// Not owned by SYSTEM or Administrators.
    UntrustedOwner,
    Io(io::Error),
}

impl std::fmt::Display for PurgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PurgeError::NotFound => write!(
                f,
                "the folder does not exist, so there was nothing to delete"
            ),
            PurgeError::IsLink => write!(
                f,
                "the folder is a link (junction or symbolic link), so it was left alone"
            ),
            PurgeError::NotADirectory => write!(f, "it is not a folder, so it was left alone"),
            PurgeError::Redirected(p) => {
                write!(f, "the folder resolves to {p}, so it was left alone")
            }
            PurgeError::UntrustedOwner => write!(
                f,
                "the folder is not owned by SYSTEM or Administrators, so it was left alone"
            ),
            PurgeError::Io(e) => write!(f, "it could not be opened ({e})"),
        }
    }
}

fn nt_err(status: i32) -> io::Error {
    // SAFETY: pure conversion.
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

fn attr_tag(h: &Handle) -> io::Result<(u32, u32)> {
    let mut i = FILE_ATTRIBUTE_TAG_INFO {
        FileAttributes: 0,
        ReparseTag: 0,
    };
    // SAFETY: buffer matches the class.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileAttributeTagInfo,
            &mut i as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } != 0;
    if ok {
        Ok((i.FileAttributes, i.ReparseTag))
    } else {
        Err(last_err())
    }
}

fn file_size(h: &Handle) -> u64 {
    // SAFETY: plain C struct; buffer matches the class.
    let mut i: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileStandardInfo,
            &mut i as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } != 0;
    if ok {
        i.EndOfFile.max(0) as u64
    } else {
        0
    }
}

fn final_path(h: &Handle) -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: buffer length passed.
        let n =
            unsafe { GetFinalPathNameByHandleW(h.raw(), buf.as_mut_ptr(), buf.len() as u32, 0) };
        if n == 0 {
            return Err(last_err());
        }
        if (n as usize) < buf.len() {
            return Ok(String::from_utf16_lossy(&buf[..n as usize]));
        }
        if buf.len() > 70_000 {
            return Err(io::Error::other("final path too long"));
        }
        buf.resize(n as usize + 1, 0);
    }
}

/// Owner is LocalSystem or BUILTIN\Administrators.
fn owner_trusted(h: &Handle) -> bool {
    let mut owner: PSID = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: out pointers valid; sd freed with LocalFree.
    let rc = unsafe {
        GetSecurityInfo(
            h.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        return false;
    }
    let ok = !owner.is_null()
        && unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        };
    unsafe { LocalFree(sd as _) };
    ok
}

/// `NtCreateFile` of one child relative to `dir`; a reparse point is opened
/// as itself.
fn nt_open(dir: &Handle, name: &str, access: u32) -> io::Result<Handle> {
    if name.is_empty() || name.contains(['\\', '/', ':', '\0']) || name == "." || name == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad file name"));
    }
    let wname: Vec<u16> = name.encode_utf16().collect();
    if wname.len() * 2 > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
    }
    let us = UNICODE_STRING {
        Length: (wname.len() * 2) as u16,
        MaximumLength: (wname.len() * 2) as u16,
        Buffer: wname.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: dir.raw(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE as _,
        SecurityDescriptor: std::ptr::null(),
        SecurityQualityOfService: std::ptr::null(),
    };
    // SAFETY: plain C struct.
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: all pointers valid for the call.
    let st = unsafe {
        NtCreateFile(
            &mut h,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT | FILE_OPEN_FOR_BACKUP_INTENT,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 {
        return Err(nt_err(st));
    }
    Handle::new(h).ok_or_else(|| io::Error::other("NtCreateFile returned no handle"))
}

fn list_names(dir: &Handle) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = vec![0u64; 64 * 1024 / 8];
    let mut class = FileFullDirectoryRestartInfo;
    loop {
        // SAFETY: buffer length passed in bytes.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                dir.raw(),
                class,
                buf.as_mut_ptr() as *mut c_void,
                (buf.len() * 8) as u32,
            )
        };
        if ok == 0 {
            let e = last_err();
            if e.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                return Ok(out);
            }
            return Err(e);
        }
        class = FileFullDirectoryInfo;
        let base = buf.as_ptr() as *const u8;
        let total = buf.len() * 8;
        let name_off = std::mem::offset_of!(FILE_FULL_DIR_INFO, FileName);
        let mut off = 0usize;
        loop {
            if off + name_off > total {
                break;
            }
            // SAFETY: bounds checked; entries are 8-byte aligned.
            let e = unsafe { &*(base.add(off) as *const FILE_FULL_DIR_INFO) };
            let len = e.FileNameLength as usize / 2;
            if off + name_off + len * 2 > total {
                break;
            }
            // SAFETY: bounds checked above.
            let name =
                unsafe { std::slice::from_raw_parts(base.add(off + name_off) as *const u16, len) };
            let name = String::from_utf16_lossy(name);
            if name != "." && name != ".." {
                out.push(name);
            }
            if e.NextEntryOffset == 0 {
                break;
            }
            off += e.NextEntryOffset as usize;
        }
    }
}

/// Delete the object behind `h` (opened with DELETE | FILE_WRITE_ATTRIBUTES).
fn delete_handle(h: &Handle, attrs: u32) -> io::Result<()> {
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    // SAFETY: buffer matches the class.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfoEx,
            &ex as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } != 0;
    if ok {
        return Ok(());
    }
    // Older file systems: clear read-only, classic disposition.
    if attrs & FILE_ATTRIBUTE_READONLY != 0 {
        // SAFETY: plain C struct; zero times mean "do not change".
        let mut bi: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
        let a = attrs & !FILE_ATTRIBUTE_READONLY;
        bi.FileAttributes = if a == 0 { FILE_ATTRIBUTE_NORMAL } else { a };
        unsafe {
            SetFileInformationByHandle(
                h.raw(),
                FileBasicInfo,
                &bi as *const _ as *const c_void,
                std::mem::size_of::<FILE_BASIC_INFO>() as u32,
            )
        };
    }
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: buffer matches the class.
    let ok = unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } != 0;
    if ok {
        Ok(())
    } else {
        Err(last_err())
    }
}

fn note_fail(r: &mut PurgeReport, name: &str, e: &io::Error) {
    r.failed += 1;
    if r.first_error.is_none() {
        r.first_error = Some(format!("{name}: {e}"));
    }
}

/// Delete everything inside `dir` (children opened relative to it).
fn purge_children(dir: &Handle, depth: usize, r: &mut PurgeReport) {
    let names = match list_names(dir) {
        Ok(n) => n,
        Err(e) => {
            note_fail(r, "listing a folder", &e);
            return;
        }
    };
    for name in names {
        let base = DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
        let h = match nt_open(dir, &name, base | FILE_LIST_DIRECTORY | FILE_TRAVERSE) {
            Ok(h) => Ok(h),
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) =>
            {
                nt_open(dir, &name, base)
            }
            Err(e) => Err(e),
        };
        let h = match h {
            Ok(h) => h,
            Err(e) => {
                note_fail(r, &name, &e);
                continue;
            }
        };
        let (attrs, _tag) = match attr_tag(&h) {
            Ok(a) => a,
            Err(e) => {
                note_fail(r, &name, &e);
                continue;
            }
        };
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            // Any reparse point (junction, symbolic link, mount point, cloud
            // placeholder) is deleted as itself, never descended into.
            match delete_handle(&h, attrs) {
                Ok(()) => r.links += 1,
                Err(e) => note_fail(r, &name, &e),
            }
            continue;
        }
        if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
            if depth >= MAX_DEPTH {
                note_fail(r, &name, &io::Error::other("folder tree too deep"));
                continue;
            }
            purge_children(&h, depth + 1, r);
            match delete_handle(&h, attrs) {
                Ok(()) => r.folders += 1,
                Err(e) => note_fail(r, &name, &e),
            }
        } else {
            let size = file_size(&h);
            match delete_handle(&h, attrs) {
                Ok(()) => {
                    r.files += 1;
                    r.bytes += size;
                }
                Err(e) => note_fail(r, &name, &e),
            }
        }
    }
}

/// Delete the folder `path` and everything in it. `check_owner`: require
/// SYSTEM / Administrators ownership of the folder (the production path;
/// tests use folders the test user owns).
pub fn purge_dir(path: &Path, check_owner: bool) -> Result<PurgeReport, PurgeError> {
    let p = wide(&path.to_string_lossy());
    // SAFETY: valid string.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            DELETE
                | FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_WRITE_ATTRIBUTES
                | READ_CONTROL
                | SYNCHRONIZE,
            SHARE_ALL,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    let Some(h) = Handle::new(h) else {
        let e = last_err();
        return Err(match e.raw_os_error() {
            Some(c) if c == ERROR_FILE_NOT_FOUND as i32 || c == ERROR_PATH_NOT_FOUND as i32 => {
                PurgeError::NotFound
            }
            _ => PurgeError::Io(e),
        });
    };
    let (attrs, _tag) = attr_tag(&h).map_err(PurgeError::Io)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PurgeError::IsLink);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(PurgeError::NotADirectory);
    }
    let fin = final_path(&h).map_err(PurgeError::Io)?;
    if !same_final_path(&fin, &path.to_string_lossy()) {
        return Err(PurgeError::Redirected(
            fin.trim_start_matches(r"\\?\").to_string(),
        ));
    }
    if check_owner && !owner_trusted(&h) {
        return Err(PurgeError::UntrustedOwner);
    }
    let mut r = PurgeReport::default();
    purge_children(&h, 0, &mut r);
    match delete_handle(&h, attrs) {
        Ok(()) => r.folders += 1,
        Err(e) => note_fail(&mut r, &path.to_string_lossy(), &e),
    }
    Ok(r)
}

/// Create the new folder `path` (it must not exist; a link or file already
/// there makes this fail) with owner Administrators and a protected DACL
/// granting only SYSTEM and Administrators, and return a handle to it. The
/// handle is opened without `FILE_SHARE_DELETE`, so while it is held nobody
/// can rename or delete the folder and swap in another one. Created and
/// opened in one `NtCreateFile`, so there is no window between the two.
///
/// Used for the work folder under `%TEMP%` (installer log, moved
/// executable): for an administrator using UAC elevation, `%TEMP%` belongs
/// to the same user an unelevated program runs as.
pub(crate) fn create_private_dir(path: &Path) -> io::Result<Handle> {
    let p = path.to_string_lossy();
    let nt = if let Some(rest) = p.strip_prefix(r"\\?\") {
        format!(r"\??\{rest}")
    } else {
        format!(r"\??\{p}")
    };
    let wname: Vec<u16> = nt.encode_utf16().collect();
    if wname.len() * 2 > u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "path too long"));
    }
    let sddl = wide("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)");
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid string; sd freed with LocalFree below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_err());
    }
    let us = UNICODE_STRING {
        Length: (wname.len() * 2) as u16,
        MaximumLength: (wname.len() * 2) as u16,
        Buffer: wname.as_ptr() as *mut u16,
    };
    let oa = OBJECT_ATTRIBUTES {
        Length: std::mem::size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: std::ptr::null_mut(),
        ObjectName: &us,
        Attributes: OBJ_CASE_INSENSITIVE as _,
        SecurityDescriptor: sd as *const _,
        SecurityQualityOfService: std::ptr::null(),
    };
    // SAFETY: plain C struct.
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut h: HANDLE = std::ptr::null_mut();
    // SAFETY: all pointers valid for the call.
    let st = unsafe {
        NtCreateFile(
            &mut h,
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_CREATE,
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe { LocalFree(sd as _) };
    if st < 0 {
        return Err(nt_err(st));
    }
    Handle::new(h).ok_or_else(|| io::Error::other("NtCreateFile returned no handle"))
}
/// Production entry point: `%ProgramData%\Kestrel`, owner checked.
pub fn purge_state_dir(path: &Path) -> Result<PurgeReport, PurgeError> {
    purge_dir(path, true)
}

#[cfg(test)]
mod tests {
    //! Run only inside a fresh folder under %TEMP%; junctions point only to
    //! other folders inside it (`mklink /J` needs no administrator rights).
    use super::*;
    use std::path::PathBuf;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let base = std::env::temp_dir().join(format!(
                "kestrel-uninst-{tag}-{}-{nanos}",
                std::process::id()
            ));
            std::fs::create_dir_all(&base).unwrap();
            // Long, final form (the temp dir may be an 8.3 path).
            let fin = std::fs::canonicalize(&base).unwrap();
            let s = fin
                .to_string_lossy()
                .trim_start_matches(r"\\?\")
                .to_string();
            Tmp(PathBuf::from(s))
        }
        fn p(&self, rel: &str) -> PathBuf {
            self.0.join(rel)
        }
        fn junction(&self, link: &str, target: &str) {
            let (l, t) = (self.p(link), self.p(target));
            let st = std::process::Command::new("cmd")
                .args(["/c", "mklink", "/J"])
                .arg(&l)
                .arg(&t)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(st.success(), "mklink /J failed");
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            // std's remove_dir_all does not follow junctions.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn purge_deletes_tree_but_not_link_targets() {
        let t = Tmp::new("purge");
        std::fs::create_dir_all(t.p("outside")).unwrap();
        std::fs::write(t.p("outside\\keep.txt"), b"keep").unwrap();
        std::fs::create_dir_all(t.p("Kestrel\\quarantine\\a")).unwrap();
        std::fs::write(t.p("Kestrel\\quarantine\\a\\q.bin"), b"12345").unwrap();
        std::fs::write(t.p("Kestrel\\agent.log"), b"abc").unwrap();
        let ro = t.p("Kestrel\\ro.txt");
        std::fs::write(&ro, b"x").unwrap();
        let mut perm = std::fs::metadata(&ro).unwrap().permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(&ro, perm).unwrap();
        t.junction("Kestrel\\quarantine\\link", "outside");
        let r = purge_dir(&t.p("Kestrel"), false).unwrap();
        assert_eq!((r.files, r.links, r.failed), (3, 1, 0), "{r:?}");
        assert_eq!(r.folders, 3, "a, quarantine, Kestrel: {r:?}");
        assert_eq!(r.bytes, 9);
        assert!(!t.p("Kestrel").exists());
        assert_eq!(std::fs::read(t.p("outside\\keep.txt")).unwrap(), b"keep");
    }

    #[test]
    fn root_link_and_link_parents_are_refused() {
        let t = Tmp::new("purge-link");
        std::fs::create_dir_all(t.p("real\\Kestrel")).unwrap();
        std::fs::write(t.p("real\\Kestrel\\keep.txt"), b"k").unwrap();
        // The folder itself is a junction.
        t.junction("Kestrel", "real\\Kestrel");
        assert!(matches!(
            purge_dir(&t.p("Kestrel"), false),
            Err(PurgeError::IsLink)
        ));
        // A parent folder is a junction.
        t.junction("pd", "real");
        assert!(matches!(
            purge_dir(&t.p("pd\\Kestrel"), false),
            Err(PurgeError::Redirected(_))
        ));
        assert!(t.p("real\\Kestrel\\keep.txt").exists());
        assert!(matches!(
            purge_dir(&t.p("missing"), false),
            Err(PurgeError::NotFound)
        ));
        std::fs::write(t.p("file"), b"f").unwrap();
        assert!(matches!(
            purge_dir(&t.p("file"), false),
            Err(PurgeError::NotADirectory)
        ));
    }

    #[test]
    fn private_dir_never_reuses_an_existing_name() {
        let t = Tmp::new("private");
        std::fs::create_dir_all(t.p("target")).unwrap();
        t.junction("planted", "target");
        assert!(create_private_dir(&t.p("planted")).is_err());
        std::fs::create_dir_all(t.p("exists")).unwrap();
        assert!(create_private_dir(&t.p("exists")).is_err());
        assert_eq!(std::fs::read_dir(t.p("target")).unwrap().count(), 0);
        if super::super::system::is_elevated() {
            // Owner Administrators needs an elevated token; then the folder
            // is pinned: it cannot be renamed while the handle is open.
            let h = create_private_dir(&t.p("work")).unwrap();
            assert!(std::fs::rename(t.p("work"), t.p("moved")).is_err());
            drop(h);
        } else {
            // An unelevated token cannot make Administrators the owner.
            assert!(create_private_dir(&t.p("work")).is_err());
        }
    }

    #[test]
    fn user_owned_folder_fails_the_owner_check() {
        // A folder created by a non-elevated test run is owned by the user.
        if super::super::system::is_elevated() {
            return;
        }
        let t = Tmp::new("purge-owner");
        std::fs::create_dir_all(t.p("Kestrel")).unwrap();
        std::fs::write(t.p("Kestrel\\x"), b"x").unwrap();
        assert!(matches!(
            purge_state_dir(&t.p("Kestrel")),
            Err(PurgeError::UntrustedOwner)
        ));
        assert!(t.p("Kestrel\\x").exists());
    }
}
