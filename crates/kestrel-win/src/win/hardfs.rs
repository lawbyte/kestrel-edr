//! Handle-based, link-safe file operations for the remote file manager
//! (security review H1 / M3).
//!
//! * Every path is walked from the volume root (`X:\`, opened with
//!   `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`); each
//!   component is opened **relative to its parent handle** (`NtCreateFile`
//!   with `RootDirectory` and `FILE_OPEN_REPARSE_POINT`), so a folder swapped
//!   for a junction / symlink / mount point between check and use is never
//!   followed: a name-surrogate reparse point in the middle of a path is
//!   refused.
//! * The guard sees `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` of the exact
//!   handle that is then used, normalised to `X:\…`; network / device /
//!   volume-GUID final paths are refused (`InvalidPath`).
//! * Reads use the opened handle, creates are relative to the verified
//!   parent handle (`FILE_CREATE`), renames go through the source handle
//!   with `FILE_RENAME_INFORMATION.RootDirectory` = the verified destination
//!   folder, deletes use `FileDispositionInfoEx` (POSIX semantics, ignore
//!   read-only) on the handle, and recursive deletes enumerate through the
//!   directory handle (`FileFullDirectoryInfo`) and open each child relative
//!   to it. Links are deleted as links and never descended into.

use super::safefs::{attr_tag, is_name_surrogate, open_raw, set_attributes};
use super::util::*;
use crate::remotefs::{join_final, normalize_final_path, split_drive_path};
use kestrel_common::remote::RemoteErrorCode;
use kestrel_platform::{FsGuard, FsOpError};
use std::ffi::c_void;
use std::io;
use std::path::{Path, PathBuf};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FileRenameInformation, NtCreateFile, NtSetInformationFile, FILE_CREATE, FILE_DIRECTORY_FILE,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_FOR_BACKUP_INTENT, FILE_OPEN_REPARSE_POINT,
    FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    RtlNtStatusToDosError, ERROR_DIRECTORY, ERROR_NO_MORE_FILES, ERROR_SHARING_VIOLATION, HANDLE,
    UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileDispositionInfo, FileDispositionInfoEx, FileFullDirectoryInfo,
    FileFullDirectoryRestartInfo, GetFileInformationByHandleEx, GetFinalPathNameByHandleW,
    SetFileInformationByHandle, DELETE, FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FULL_DIR_INFO, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_TRAVERSE, FILE_WRITE_ATTRIBUTES, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const DIR_READ: u32 = FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | SYNCHRONIZE;
const DIR_WRITE: u32 = DIR_READ | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
/// Deepest folder tree a recursive delete descends into.
const MAX_DEPTH: usize = 512;

fn refused(code: RemoteErrorCode, m: impl Into<String>) -> FsOpError {
    FsOpError::refused(code, m)
}

fn link_refusal() -> FsOpError {
    refused(
        RemoteErrorCode::InvalidOperation,
        "the path goes through a link (junction, symbolic link or mount point); open its target instead",
    )
}

fn nt_err(status: i32) -> io::Error {
    io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32)
}

/// `NtCreateFile` of one component relative to `dir`, never following a
/// reparse point at `name`, with backup intent (the agent holds
/// SeBackup/SeRestore) and synchronous I/O.
fn nt_open(
    dir: &Handle,
    name: &str,
    access: u32,
    disposition: u32,
    options: u32,
) -> io::Result<Handle> {
    if name.is_empty() || name.contains(['\\', '/', ':', '\0']) || name == "." || name == ".." {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad file name"));
    }
    let wname: Vec<u16> = name.encode_utf16().collect();
    if wname.len() * 2 > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "file name too long",
        ));
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
    let st = unsafe {
        NtCreateFile(
            &mut h,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            SHARE_ALL,
            disposition,
            options
                | FILE_SYNCHRONOUS_IO_NONALERT
                | FILE_OPEN_REPARSE_POINT
                | FILE_OPEN_FOR_BACKUP_INTENT,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 {
        return Err(nt_err(st));
    }
    Handle::new(h).ok_or_else(|| io::Error::other("NtCreateFile returned no handle"))
}

/// Raw `GetFinalPathNameByHandleW(FILE_NAME_NORMALIZED | VOLUME_NAME_DOS)`.
fn final_raw(h: &Handle) -> io::Result<String> {
    let mut buf = vec![0u16; 1024];
    loop {
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

/// Final local `X:\…` path of a handle; network / device paths are refused.
fn final_local(h: &Handle) -> Result<String, FsOpError> {
    let raw = final_raw(h).map_err(|e| {
        refused(
            RemoteErrorCode::InvalidPath,
            format!("resolves to a network or device path ({e})"),
        )
    })?;
    normalize_final_path(&raw).map_err(|m| refused(RemoteErrorCode::InvalidPath, m))
}

/// An open object with its final path and attributes.
struct Node {
    h: Handle,
    path: String,
    attrs: u32,
    tag: u32,
}

impl Node {
    fn new(h: Handle) -> Result<Node, FsOpError> {
        let (attrs, tag) = attr_tag(&h).ok_or_else(|| FsOpError::Io(last_err()))?;
        let path = final_local(&h)?;
        Ok(Node {
            h,
            path,
            attrs,
            tag,
        })
    }
    fn is_link(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate(self.tag)
    }
    fn is_dir(&self) -> bool {
        self.attrs & FILE_ATTRIBUTE_DIRECTORY != 0
    }
    fn guard(&self, guard: FsGuard<'_>) -> Result<(), FsOpError> {
        guard(Path::new(&self.path))
    }
}

fn parse(p: &Path) -> Result<(char, Vec<String>), FsOpError> {
    p.to_str()
        .and_then(split_drive_path)
        .ok_or_else(|| refused(RemoteErrorCode::InvalidPath, "not an absolute local path"))
}

fn open_root(drive: char, write: bool) -> Result<Node, FsOpError> {
    let root = format!("{drive}:\\");
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    let h = match open_raw(
        &root,
        if write { DIR_WRITE } else { DIR_READ },
        SHARE_ALL,
        flags,
    ) {
        Err(e) if write && e.kind() == io::ErrorKind::PermissionDenied => {
            open_raw(&root, DIR_READ, SHARE_ALL, flags)?
        }
        r => r?,
    };
    Node::new(h)
}

/// Open the existing folder `c` under `cur`; with `write`, ask for the
/// rights to create children too (falling back to read rights when those
/// are denied: creating then fails with "access denied").
fn open_dir_comp(cur: &Handle, c: &str, write: bool) -> io::Result<Handle> {
    if write {
        match nt_open(cur, c, DIR_WRITE, FILE_OPEN, FILE_DIRECTORY_FILE) {
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {}
            r => return r,
        }
    }
    nt_open(cur, c, DIR_READ, FILE_OPEN, FILE_DIRECTORY_FILE)
}

/// Open the folder `drive:\comps…`, every component relative to its parent
/// and none of them a link.
fn open_dir(drive: char, comps: &[String], write: bool) -> Result<Node, FsOpError> {
    let mut cur = open_root(drive, write && comps.is_empty())?;
    for (i, c) in comps.iter().enumerate() {
        let w = write && i + 1 == comps.len();
        let h = open_dir_comp(&cur.h, c, w).map_err(|e| {
            if e.raw_os_error() == Some(ERROR_DIRECTORY as i32) {
                refused(
                    RemoteErrorCode::InvalidOperation,
                    format!("\"{c}\" is not a folder"),
                )
            } else {
                FsOpError::Io(e)
            }
        })?;
        let n = Node::new(h)?;
        if n.is_link() {
            return Err(link_refusal());
        }
        cur = n;
    }
    Ok(cur)
}

/// Parent folder (verified) and last component.
fn open_parent(p: &Path, write: bool) -> Result<(char, Node, String), FsOpError> {
    let (d, mut comps) = parse(p)?;
    let name = comps.pop().ok_or_else(|| {
        refused(
            RemoteErrorCode::InvalidOperation,
            "not allowed on a drive root",
        )
    })?;
    Ok((d, open_dir(d, &comps, write)?, name))
}

fn into_file(h: Handle) -> std::fs::File {
    use std::os::windows::io::FromRawHandle;
    let raw = h.0;
    std::mem::forget(h);
    // SAFETY: we own `raw` (a synchronous file handle) and give it to File.
    unsafe { std::fs::File::from_raw_handle(raw as _) }
}

/// Enumerate a folder's child names through its handle.
fn list_names(dir: &Handle) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut buf = vec![0u64; 64 * 1024 / 8];
    let mut class = FileFullDirectoryRestartInfo;
    loop {
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
            // SAFETY: bounds checked above; entries are 8-byte aligned.
            let e = unsafe { &*(base.add(off) as *const FILE_FULL_DIR_INFO) };
            let len = e.FileNameLength as usize / 2;
            if off + name_off + len * 2 > total {
                break;
            }
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

/// Delete the object behind `n.h` (opened with DELETE | FILE_WRITE_ATTRIBUTES).
fn delete_node(n: &Node) -> io::Result<()> {
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE
            | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
            | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            n.h.raw(),
            FileDispositionInfoEx,
            &ex as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    } != 0;
    if ok {
        return Ok(());
    }
    let first = last_err();
    // Older systems / file systems: clear read-only, classic disposition.
    if n.attrs & FILE_ATTRIBUTE_READONLY != 0 {
        let a = n.attrs & !FILE_ATTRIBUTE_READONLY;
        set_attributes(&n.h, if a == 0 { FILE_ATTRIBUTE_NORMAL } else { a });
    }
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        SetFileInformationByHandle(
            n.h.raw(),
            FileDispositionInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } != 0;
    if ok {
        Ok(())
    } else {
        let e = last_err();
        tracing::debug!("FileDispositionInfoEx failed: {first}; FileDispositionInfo: {e}");
        Err(e)
    }
}

fn rm_child(
    dir: &Handle,
    name: &str,
    recursive: bool,
    guard: FsGuard<'_>,
    top: bool,
    depth: usize,
) -> Result<u64, FsOpError> {
    let base = DELETE | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES;
    // Listing rights are only needed for folders; a file another process
    // holds without FILE_SHARE_READ is opened with the delete rights alone.
    let h = match nt_open(
        dir,
        name,
        base | FILE_LIST_DIRECTORY | FILE_TRAVERSE,
        FILE_OPEN,
        0,
    ) {
        Ok(h) => h,
        Err(e)
            if e.kind() == io::ErrorKind::PermissionDenied
                || e.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) =>
        {
            nt_open(dir, name, base, FILE_OPEN, 0)?
        }
        Err(e) => return Err(e.into()),
    };
    let n = Node::new(h)?;
    n.guard(guard)?;
    if n.is_link() || !n.is_dir() {
        // Links are removed as links, never followed.
        delete_node(&n)?;
        return Ok(1);
    }
    let names = list_names(&n.h)?;
    if !names.is_empty() && !recursive {
        return Err(refused(
            RemoteErrorCode::InvalidOperation,
            if top {
                "the folder is not empty"
            } else {
                "a sub-folder is not empty"
            },
        ));
    }
    if depth >= MAX_DEPTH {
        return Err(refused(
            RemoteErrorCode::InvalidOperation,
            "the folder tree is too deep",
        ));
    }
    let mut count = 0u64;
    for c in &names {
        count += rm_child(&n.h, c, recursive, guard, false, depth + 1)?;
    }
    delete_node(&n)?;
    Ok(count + 1)
}

/// `FileRenameInformation` with `RootDirectory` (cannot be redirected).
fn nt_rename(h: &Handle, dir: &Handle, name: &str, replace: bool) -> io::Result<()> {
    let wname: Vec<u16> = name.encode_utf16().collect();
    let size = std::mem::size_of::<FILE_RENAME_INFORMATION>() + wname.len() * 2;
    let mut buf = vec![0u64; size.div_ceil(8)];
    let st = unsafe {
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*info).Anonymous.ReplaceIfExists = replace;
        (*info).RootDirectory = dir.raw();
        (*info).FileNameLength = (wname.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            wname.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName) as *mut u16,
            wname.len(),
        );
        let mut iosb: IO_STATUS_BLOCK = std::mem::zeroed();
        NtSetInformationFile(
            h.raw(),
            &mut iosb,
            info as *const c_void,
            size as u32,
            FileRenameInformation,
        )
    };
    if st < 0 {
        Err(nt_err(st))
    } else {
        Ok(())
    }
}

// ------------------------------------------------------------ operations

pub fn verify_dir(p: &Path, guard: FsGuard<'_>) -> Result<PathBuf, FsOpError> {
    let (d, comps) = parse(p)?;
    let n = open_dir(d, &comps, false)?;
    n.guard(guard)?;
    Ok(PathBuf::from(n.path))
}

pub fn open_read(p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
    let (_, parent, name) = open_parent(p, false)?;
    let h = nt_open(&parent.h, &name, FILE_GENERIC_READ, FILE_OPEN, 0)?;
    let n = Node::new(h)?;
    if n.is_link() {
        return Err(refused(
            RemoteErrorCode::InvalidOperation,
            "the path is a link; open its target instead",
        ));
    }
    if n.is_dir() {
        return Err(refused(
            RemoteErrorCode::InvalidOperation,
            "the path is a folder",
        ));
    }
    n.guard(guard)?;
    Ok(into_file(n.h))
}

pub fn create_new(p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
    let (_, parent, name) = open_parent(p, true)?;
    guard(Path::new(&join_final(&parent.path, &name)))?;
    let h = nt_open(
        &parent.h,
        &name,
        FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )?;
    let n = Node::new(h)?;
    if let Err(e) = n.guard(guard) {
        let _ = delete_node(&n);
        return Err(e);
    }
    Ok(into_file(n.h))
}

pub fn rename(from: &Path, to: &Path, replace: bool, guard: FsGuard<'_>) -> Result<(), FsOpError> {
    let (d1, sparent, sname) = open_parent(from, false)?;
    let sh = nt_open(
        &sparent.h,
        &sname,
        DELETE | FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        0,
    )?;
    let src = Node::new(sh)?;
    src.guard(guard)?;
    let (d2, dparent, dname) = open_parent(to, false)?;
    if d1 != d2 {
        return Err(refused(
            RemoteErrorCode::InvalidOperation,
            "cannot move between drives",
        ));
    }
    guard(Path::new(&join_final(&dparent.path, &dname)))?;
    match nt_open(&dparent.h, &dname, FILE_READ_ATTRIBUTES, FILE_OPEN, 0) {
        Ok(eh) => {
            let ex = Node::new(eh)?;
            let same = ex.path.eq_ignore_ascii_case(&src.path);
            if !same {
                if ex.is_dir() {
                    return Err(refused(
                        RemoteErrorCode::InvalidOperation,
                        "the destination is a folder",
                    ));
                }
                if !replace {
                    return Err(refused(
                        RemoteErrorCode::AlreadyExists,
                        "the destination exists",
                    ));
                }
                ex.guard(guard)?;
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    nt_rename(&src.h, &dparent.h, &dname, replace)?;
    Ok(())
}

pub fn remove(p: &Path, recursive: bool, guard: FsGuard<'_>) -> Result<u64, FsOpError> {
    let (_, parent, name) = open_parent(p, false)?;
    rm_child(&parent.h, &name, recursive, guard, true, 0)
}

pub fn create_dir_all(p: &Path, guard: FsGuard<'_>) -> Result<(), FsOpError> {
    let (d, comps) = parse(p)?;
    let mut cur = open_root(d, true)?;
    let last = comps.len().saturating_sub(1);
    for (i, c) in comps.iter().enumerate() {
        let n = match open_dir_comp(&cur.h, c, true) {
            Ok(h) => {
                let n = Node::new(h)?;
                if n.is_link() {
                    return Err(link_refusal());
                }
                n
            }
            Err(e) if e.raw_os_error() == Some(ERROR_DIRECTORY as i32) => {
                return Err(refused(
                    RemoteErrorCode::AlreadyExists,
                    if i == last {
                        "a file with that name exists".to_string()
                    } else {
                        format!("\"{c}\" is a file, not a folder")
                    },
                ))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                guard(Path::new(&join_final(&cur.path, c)))?;
                let h = nt_open(&cur.h, c, DIR_WRITE, FILE_CREATE, FILE_DIRECTORY_FILE)?;
                Node::new(h)?
            }
            Err(e) => return Err(e.into()),
        };
        cur = n;
    }
    Ok(())
}

/// Enable RedirectionGuard for this process
/// (`SetProcessMitigationPolicy(ProcessRedirectionTrustPolicy,
/// EnforceRedirectionTrust)`): junctions created by non-administrators are
/// no longer followed by any file open in the process. Windows 11 22H2+
/// (and servicing updates); failure (older OS) is ignored. Returns whether
/// it was enabled.
pub fn enable_redirection_guard() -> bool {
    use windows_sys::Win32::System::SystemServices::PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY;
    use windows_sys::Win32::System::Threading::{
        ProcessRedirectionTrustPolicy, SetProcessMitigationPolicy,
    };
    let mut p = PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY::default();
    p.Anonymous.Flags = 1; // EnforceRedirectionTrust
    unsafe {
        SetProcessMitigationPolicy(
            ProcessRedirectionTrustPolicy,
            &p as *const _ as *const c_void,
            std::mem::size_of::<PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY>(),
        ) != 0
    }
}

#[cfg(test)]
mod tests {
    //! Run only inside a fresh directory under %TEMP%; links point only to
    //! other folders inside it.
    use super::*;
    use std::sync::Mutex;

    struct Tmp(PathBuf);

    impl Tmp {
        fn new(tag: &str) -> Tmp {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let base = std::env::temp_dir().join(format!(
                "kestrel-hardfs-{tag}-{}-{nanos}",
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
            assert!(t.starts_with(&self.0) && l.starts_with(&self.0));
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

    fn recorder() -> (Mutex<Vec<String>>,) {
        (Mutex::new(Vec::new()),)
    }

    #[test]
    fn recursive_remove_deletes_junction_not_target() {
        let t = Tmp::new("rm");
        std::fs::create_dir_all(t.p("target")).unwrap();
        std::fs::write(t.p("target\\secret.txt"), b"keep").unwrap();
        std::fs::create_dir_all(t.p("tree\\sub")).unwrap();
        std::fs::write(t.p("tree\\sub\\f.txt"), b"x").unwrap();
        std::fs::write(t.p("tree\\ro.txt"), b"x").unwrap();
        let mut perm = std::fs::metadata(t.p("tree\\ro.txt"))
            .unwrap()
            .permissions();
        perm.set_readonly(true);
        std::fs::set_permissions(t.p("tree\\ro.txt"), perm).unwrap();
        t.junction("tree\\link", "target");
        let (seen,) = recorder();
        let g = |p: &Path| -> Result<(), FsOpError> {
            seen.lock().unwrap().push(p.to_string_lossy().into_owned());
            Ok(())
        };
        // Non-recursive on a non-empty folder is refused.
        assert!(matches!(
            remove(&t.p("tree"), false, &g),
            Err(FsOpError::Refused { .. })
        ));
        let n = remove(&t.p("tree"), true, &g).unwrap();
        assert_eq!(
            n,
            5,
            "tree, sub, f.txt, ro.txt, link: {:?}",
            seen.lock().unwrap()
        );
        assert!(!t.p("tree").exists());
        assert_eq!(std::fs::read(t.p("target\\secret.txt")).unwrap(), b"keep");
        let seen = seen.lock().unwrap();
        assert!(seen.iter().any(|s| s.ends_with("\\tree\\link")), "{seen:?}");
        assert!(!seen.iter().any(|s| s.contains("secret")), "{seen:?}");
    }

    #[test]
    fn guard_refusal_stops_remove() {
        let t = Tmp::new("rmg");
        std::fs::create_dir_all(t.p("a\\keep")).unwrap();
        std::fs::write(t.p("a\\keep\\k.txt"), b"k").unwrap();
        let g = |p: &Path| -> Result<(), FsOpError> {
            if p.to_string_lossy().ends_with("\\keep") {
                Err(FsOpError::refused(
                    RemoteErrorCode::ProtectedPath,
                    "protected",
                ))
            } else {
                Ok(())
            }
        };
        assert!(matches!(
            remove(&t.p("a"), true, &g),
            Err(FsOpError::Refused {
                code: RemoteErrorCode::ProtectedPath,
                ..
            })
        ));
        assert!(t.p("a\\keep\\k.txt").exists());
    }

    #[test]
    fn junction_parents_are_refused() {
        let t = Tmp::new("jp");
        std::fs::create_dir_all(t.p("target")).unwrap();
        std::fs::write(t.p("target\\secret.txt"), b"s").unwrap();
        t.junction("jdir", "target");
        let (seen,) = recorder();
        let g = |p: &Path| -> Result<(), FsOpError> {
            seen.lock().unwrap().push(p.to_string_lossy().into_owned());
            Ok(())
        };
        assert!(matches!(
            open_read(&t.p("jdir\\secret.txt"), &g),
            Err(FsOpError::Refused { .. })
        ));
        assert!(matches!(
            create_new(&t.p("jdir\\new.txt"), &g),
            Err(FsOpError::Refused { .. })
        ));
        std::fs::write(t.p("src.txt"), b"m").unwrap();
        assert!(matches!(
            rename(&t.p("src.txt"), &t.p("jdir\\moved.txt"), false, &g),
            Err(FsOpError::Refused { .. })
        ));
        assert!(matches!(
            verify_dir(&t.p("jdir"), &g),
            Err(FsOpError::Refused { .. })
        ));
        assert!(matches!(
            create_dir_all(&t.p("jdir\\x\\y"), &g),
            Err(FsOpError::Refused { .. })
        ));
        assert!(!t.p("target\\new.txt").exists());
        assert!(!t.p("target\\moved.txt").exists());
        assert!(!t.p("target\\x").exists());
        assert!(!seen.lock().unwrap().iter().any(|s| s.contains("target")));
        // The link itself can be renamed and removed (as a link).
        rename(&t.p("jdir"), &t.p("jdir2"), false, &g).unwrap();
        assert_eq!(remove(&t.p("jdir2"), false, &g).unwrap(), 1);
        assert!(t.p("target\\secret.txt").exists());
    }

    #[test]
    fn normal_operations_and_final_paths() {
        let t = Tmp::new("ops");
        let (seen,) = recorder();
        let g = |p: &Path| -> Result<(), FsOpError> {
            seen.lock().unwrap().push(p.to_string_lossy().into_owned());
            Ok(())
        };
        create_dir_all(&t.p("d1\\d2"), &g).unwrap();
        create_dir_all(&t.p("d1\\d2"), &g).unwrap();
        assert!(t.p("d1\\d2").is_dir());
        let fin = verify_dir(&t.p("d1"), &g).unwrap();
        assert!(fin
            .to_string_lossy()
            .eq_ignore_ascii_case(&t.p("d1").to_string_lossy()));
        {
            use std::io::Write;
            let mut f = create_new(&t.p("d1\\up.tmp"), &g).unwrap();
            f.write_all(b"hello").unwrap();
        }
        assert!(matches!(
            create_new(&t.p("d1\\up.tmp"), &g),
            Err(FsOpError::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists
        ));
        {
            use std::io::Read;
            let mut s = String::new();
            open_read(&t.p("d1\\up.tmp"), &g)
                .unwrap()
                .read_to_string(&mut s)
                .unwrap();
            assert_eq!(s, "hello");
        }
        assert!(matches!(
            open_read(&t.p("d1"), &g),
            Err(FsOpError::Refused { .. })
        ));
        std::fs::write(t.p("d1\\other.txt"), b"o").unwrap();
        assert!(matches!(
            rename(&t.p("d1\\up.tmp"), &t.p("d1\\other.txt"), false, &g),
            Err(FsOpError::Refused {
                code: RemoteErrorCode::AlreadyExists,
                ..
            })
        ));
        assert!(matches!(
            rename(&t.p("d1\\up.tmp"), &t.p("d1\\d2"), true, &g),
            Err(FsOpError::Refused { .. })
        ));
        rename(&t.p("d1\\up.tmp"), &t.p("d1\\other.txt"), true, &g).unwrap();
        assert_eq!(std::fs::read(t.p("d1\\other.txt")).unwrap(), b"hello");
        rename(&t.p("d1\\other.txt"), &t.p("d1\\OTHER.txt"), false, &g).unwrap();
        assert!(matches!(
            create_dir_all(&t.p("d1\\OTHER.txt"), &g),
            Err(FsOpError::Refused {
                code: RemoteErrorCode::AlreadyExists,
                ..
            })
        ));
        assert!(matches!(
            remove(&t.p("d1\\nope"), false, &g),
            Err(FsOpError::Io(e)) if e.kind() == io::ErrorKind::NotFound
        ));
        // Every path the guard saw is the long, final form inside the temp dir.
        let base = t.0.to_string_lossy().to_lowercase();
        for s in seen.lock().unwrap().iter() {
            assert!(s.to_lowercase().starts_with(&base), "{s} not under {base}");
            assert!(!s.starts_with(r"\\"), "{s}");
        }
    }
}
