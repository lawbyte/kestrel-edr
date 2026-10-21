//! Handle-based file operations that never follow junctions / symbolic
//! links (H8, L12, H4).
//!
//! Every privileged file operation in user-controlled locations goes through
//! these helpers:
//! * each ancestor directory is opened with `FILE_FLAG_OPEN_REPARSE_POINT`
//!   and refused when it is a name-surrogate reparse point (junction,
//!   symbolic link, mount point);
//! * the target itself is opened with `FILE_FLAG_OPEN_REPARSE_POINT`, must not
//!   be a name surrogate, must have exactly one hard link, and its
//!   `GetFinalPathNameByHandleW` must equal the requested (long) path — this
//!   last check also closes the race between the ancestor checks and the
//!   open, because it is made on the handle that is then used for all I/O;
//! * new files are created relative to a verified directory handle
//!   (`NtCreateFile` with `RootDirectory`), which cannot be redirected.

#![allow(clippy::missing_safety_doc)]

use super::util::*;
use crate::qpolicy;
use std::ffi::c_void;
use std::io;
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_CREATE, FILE_NON_DIRECTORY_FILE, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, UNICODE_STRING,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorGroup, GetSecurityDescriptorOwner, ACL,
    DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FileBasicInfo, FileDispositionInfo,
    FileRenameInfo, GetFileInformationByHandle, GetFileInformationByHandleEx,
    GetFinalPathNameByHandleW, GetLongPathNameW, SetFileInformationByHandle,
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_BASIC_INFO, FILE_DISPOSITION_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_RENAME_INFO, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

/// Name-surrogate bit of a reparse tag (junctions, symlinks, mount points).
pub const REPARSE_TAG_NAME_SURROGATE: u32 = 0x2000_0000;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

pub fn is_name_surrogate(tag: u32) -> bool {
    tag & REPARSE_TAG_NAME_SURROGATE != 0
}

/// Long (non-8.3) form of an existing path; the input when it cannot be resolved.
pub fn long_path(path: &str) -> String {
    let w = wide(path);
    let mut buf = vec![0u16; 1024];
    for _ in 0..2 {
        let n = unsafe { GetLongPathNameW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return path.to_string();
        }
        if (n as usize) < buf.len() {
            return String::from_utf16_lossy(&buf[..n as usize]);
        }
        buf.resize(n as usize + 1, 0);
    }
    path.to_string()
}

pub fn open_raw(path: &str, access: u32, share: u32, flags: u32) -> io::Result<Handle> {
    let w = wide(path);
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            access,
            share,
            std::ptr::null(),
            OPEN_EXISTING,
            flags,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_null() {
        return Err(last_err());
    }
    Ok(Handle(h))
}

/// `\\?\C:\…` final path of an open handle (DOS volume name), without the prefix.
pub fn final_path(h: &Handle) -> Option<String> {
    let mut buf = vec![0u16; 1024];
    for _ in 0..2 {
        let n =
            unsafe { GetFinalPathNameByHandleW(h.raw(), buf.as_mut_ptr(), buf.len() as u32, 0) };
        if n == 0 {
            return None;
        }
        if (n as usize) < buf.len() {
            let s = String::from_utf16_lossy(&buf[..n as usize]);
            return Some(match s.strip_prefix(r"\\?\UNC\") {
                Some(r) => format!(r"\\{r}"),
                None => s.strip_prefix(r"\\?\").unwrap_or(&s).to_string(),
            });
        }
        buf.resize(n as usize + 1, 0);
    }
    None
}

/// (attributes, reparse tag) of an open handle.
pub fn attr_tag(h: &Handle) -> Option<(u32, u32)> {
    let mut info: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h.raw(),
            FileAttributeTagInfo,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    };
    (ok != 0).then_some((info.FileAttributes, info.ReparseTag))
}

pub fn link_count(h: &Handle) -> Option<u32> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(h.raw(), &mut info) };
    (ok != 0).then_some(info.nNumberOfLinks)
}

/// Refuse when any ancestor directory of `path` is a junction / symlink /
/// mount point.
pub fn check_ancestors(path: &str) -> Result<(), String> {
    for dir in qpolicy::ancestors(path) {
        let h = open_raw(
            &dir,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .map_err(|e| format!("cannot open {dir}: {e}"))?;
        let (attrs, tag) = attr_tag(&h).ok_or_else(|| format!("cannot query {dir}"))?;
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate(tag) {
            return Err(format!(
                "{dir} is a junction / symbolic link (reparse tag 0x{tag:08x}); refusing to follow it"
            ));
        }
    }
    Ok(())
}

/// A verified open file.
pub struct Verified {
    pub h: Handle,
    /// Long path that was requested and verified (as given, long form).
    pub path: String,
    pub attributes: u32,
}

/// Open an existing **file** without following links anywhere in its path.
/// `access` is added to `FILE_READ_ATTRIBUTES`; opened with backup semantics.
pub fn open_verified_file(path: &str, access: u32, share: u32) -> Result<Verified, String> {
    let req = long_path(path);
    check_ancestors(&req)?;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT;
    let mut h = open_raw(&req, access | FILE_READ_ATTRIBUTES, share, flags)
        .map_err(|e| format!("cannot open {req}: {e}"))?;
    let (mut attrs, tag) = attr_tag(&h).ok_or_else(|| format!("cannot query {req}"))?;
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(format!("{req} is a directory"));
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        if is_name_surrogate(tag) {
            return Err(format!(
                "{req} is a symbolic link / junction; refusing to follow it"
            ));
        }
        // Other reparse points (cloud placeholders, dedup): let the filter
        // driver serve the data; the final-path check below still applies.
        h = open_raw(
            &req,
            access | FILE_READ_ATTRIBUTES,
            share,
            FILE_FLAG_BACKUP_SEMANTICS,
        )
        .map_err(|e| format!("cannot open {req}: {e}"))?;
        attrs = attr_tag(&h).map(|a| a.0).unwrap_or(attrs);
    }
    match link_count(&h) {
        Some(1) => {}
        Some(n) => {
            return Err(format!(
                "{req} has {n} hard links; refusing (it may alias another file)"
            ))
        }
        None => return Err(format!("cannot query link count of {req}")),
    }
    let fp = final_path(&h).ok_or_else(|| format!("cannot resolve the final path of {req}"))?;
    if !qpolicy::same_path(&req, &fp) {
        return Err(format!(
            "{req} resolves to {fp} (redirected by a link); refusing"
        ));
    }
    Ok(Verified {
        h,
        path: req,
        attributes: attrs,
    })
}

/// Open an existing **directory** without following links; `share` should
/// omit `FILE_SHARE_DELETE` so the directory cannot be renamed / replaced
/// while the handle is held.
pub fn open_verified_dir(path: &str, access: u32, share: u32) -> Result<(Handle, String), String> {
    let req = long_path(path);
    check_ancestors(&req)?;
    let h = open_raw(
        &req,
        access | FILE_READ_ATTRIBUTES,
        share,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .map_err(|e| format!("cannot open {req}: {e}"))?;
    let (attrs, tag) = attr_tag(&h).ok_or_else(|| format!("cannot query {req}"))?;
    if attrs & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(format!("{req} is not a directory"));
    }
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 && is_name_surrogate(tag) {
        return Err(format!("{req} is a junction / symbolic link; refusing"));
    }
    let fp = final_path(&h).ok_or_else(|| format!("cannot resolve the final path of {req}"))?;
    if !qpolicy::same_path(&req, &fp) {
        return Err(format!("{req} resolves to {fp}; refusing"));
    }
    Ok((h, req))
}

/// Owner SID (string) of an open handle.
pub fn owner_sid(h: &Handle) -> Option<String> {
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut sd: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        let rc = GetSecurityInfo(
            h.raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS || sd.is_null() {
            return None;
        }
        let s = sid_to_string(owner);
        LocalFree(sd);
        s
    }
}

/// Apply owner / group / DACL from `sddl` to an open handle (needs
/// WRITE_DAC, and WRITE_OWNER or SeRestorePrivilege for the owner).
pub fn set_security(h: &Handle, sddl: &str, protect: bool) -> io::Result<()> {
    let sd = sd_from_sddl(sddl)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SDDL"))?;
    unsafe {
        let mut owner: PSID = std::ptr::null_mut();
        let mut group: PSID = std::ptr::null_mut();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut present = 0;
        let mut defaulted = 0;
        GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted);
        GetSecurityDescriptorGroup(sd.0, &mut group, &mut defaulted);
        GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted);
        let mut info = 0;
        if !owner.is_null() {
            info |= OWNER_SECURITY_INFORMATION;
        }
        if !group.is_null() {
            info |= GROUP_SECURITY_INFORMATION;
        }
        if present != 0 {
            info |= DACL_SECURITY_INFORMATION;
            if protect {
                info |= PROTECTED_DACL_SECURITY_INFORMATION;
            }
        }
        let rc = SetSecurityInfo(
            h.raw(),
            SE_FILE_OBJECT,
            info,
            owner,
            group,
            dacl,
            std::ptr::null(),
        );
        if rc == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(win32_err(rc))
        }
    }
}

/// Delete an open file with POSIX semantics (the name disappears at once,
/// even while another process — e.g. an AV scanner — still holds a handle),
/// falling back to the classic delete-on-close disposition.
pub fn delete_now_by_handle(h: &Handle) -> bool {
    use windows_sys::Win32::Storage::FileSystem::{
        FileDispositionInfoEx, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        FILE_DISPOSITION_INFO_EX,
    };
    let info = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    let ok = unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfoEx,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        ) != 0
    };
    ok || delete_by_handle(h)
}

/// Mark an open file for deletion (needs DELETE access).
pub fn delete_by_handle(h: &Handle) -> bool {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileDispositionInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_DISPOSITION_INFO>() as u32,
        ) != 0
    }
}

/// Rename an open file to `new_path` (full Win32 path, same volume; needs
/// DELETE access). Does not replace an existing file.
pub fn rename_by_handle(h: &Handle, new_path: &str) -> bool {
    let name: Vec<u16> = new_path.encode_utf16().collect();
    let size = std::mem::size_of::<FILE_RENAME_INFO>() + name.len() * 2;
    // u64 storage for alignment.
    let mut buf = vec![0u64; size.div_ceil(8)];
    unsafe {
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFO;
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = std::ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(
            name.as_ptr(),
            std::ptr::addr_of_mut!((*info).FileName) as *mut u16,
            name.len(),
        );
        SetFileInformationByHandle(h.raw(), FileRenameInfo, info as *const c_void, size as u32) != 0
    }
}

/// Set file attributes through a handle (needs FILE_WRITE_ATTRIBUTES).
pub fn set_attributes(h: &Handle, attributes: u32) -> bool {
    let mut info: FILE_BASIC_INFO = unsafe { std::mem::zeroed() };
    info.FileAttributes = attributes;
    unsafe {
        SetFileInformationByHandle(
            h.raw(),
            FileBasicInfo,
            &info as *const _ as *const c_void,
            std::mem::size_of::<FILE_BASIC_INFO>() as u32,
        ) != 0
    }
}

/// Create a **new** file `name` (a single path component) inside the open
/// directory `dir` — relative to the handle, so it cannot be redirected.
pub fn create_in_dir(dir: &Handle, name: &str, access: u32, share: u32) -> io::Result<Handle> {
    open_in_dir(
        dir,
        name,
        access,
        share,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )
    .map_err(|e| match e {
        RelOpenError::NotFound => io::Error::from(io::ErrorKind::NotFound),
        RelOpenError::IsDirectory => io::Error::other("is a directory"),
        RelOpenError::Other(s) => io::Error::other(s),
    })
}

/// Error of [`open_in_dir`].
#[derive(Debug)]
pub enum RelOpenError {
    /// STATUS_OBJECT_NAME_NOT_FOUND.
    NotFound,
    /// STATUS_FILE_IS_A_DIRECTORY (non-directory open of a directory).
    IsDirectory,
    Other(String),
}

/// `NtCreateFile` of the single component `name` relative to the open
/// directory `dir`, never following a reparse point at `name`
/// (`FILE_OPEN_REPARSE_POINT`; a link is opened as itself and the caller
/// checks [`attr_tag`]). `options` is added to synchronous I/O.
pub fn open_in_dir(
    dir: &Handle,
    name: &str,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
) -> Result<Handle, RelOpenError> {
    if name.is_empty() || name.contains(['\\', '/', ':']) || name == "." || name == ".." {
        return Err(RelOpenError::Other("bad file name".into()));
    }
    let wname: Vec<u16> = name.encode_utf16().collect();
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
    let mut iosb: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut h: HANDLE = std::ptr::null_mut();
    let st = unsafe {
        NtCreateFile(
            &mut h,
            access | SYNCHRONIZE,
            &oa,
            &mut iosb,
            std::ptr::null(),
            0x80, // FILE_ATTRIBUTE_NORMAL
            share,
            disposition,
            options | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT,
            std::ptr::null(),
            0,
        )
    };
    if st < 0 {
        return Err(match st as u32 {
            0xC000_0034 => RelOpenError::NotFound, // STATUS_OBJECT_NAME_NOT_FOUND
            0xC000_00BA => RelOpenError::IsDirectory, // STATUS_FILE_IS_A_DIRECTORY
            s => RelOpenError::Other(format!("NtCreateFile({name}) failed: NTSTATUS 0x{s:08X}")),
        });
    }
    Handle::new(h).ok_or_else(|| RelOpenError::Other("NtCreateFile returned no handle".into()))
}

/// Rename the open file `h` to `name` inside the open directory `dir`
/// (`FILE_RENAME_INFO.RootDirectory`: cannot be redirected). Never replaces
/// an existing file. Needs DELETE access on `h`.
pub fn rename_in_dir(h: &Handle, dir: &Handle, name: &str) -> bool {
    if name.is_empty() || name.contains(['\\', '/', ':']) {
        return false;
    }
    // NtSetInformationFile directly: kernelbase's SetFileInformationByHandle
    // rejects a relative name with a RootDirectory (ERROR_INVALID_PARAMETER,
    // measured on build 26200).
    use windows_sys::Wdk::Storage::FileSystem::{
        FileRenameInformation, NtSetInformationFile, FILE_RENAME_INFORMATION,
    };
    let wname: Vec<u16> = name.encode_utf16().collect();
    let size = std::mem::size_of::<FILE_RENAME_INFORMATION>() + wname.len() * 2;
    let mut buf = vec![0u64; size.div_ceil(8)];
    unsafe {
        let info = buf.as_mut_ptr() as *mut FILE_RENAME_INFORMATION;
        (*info).Anonymous.ReplaceIfExists = false;
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
        ) >= 0
    }
}

/// Create a directory with an explicit security descriptor (owner + DACL).
pub fn create_dir_with_sddl(path: &str, sddl: &str) -> io::Result<()> {
    let sd = sd_from_sddl(sddl)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid SDDL"))?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let w = wide(path);
    if unsafe { CreateDirectoryW(w.as_ptr(), &sa) } == 0 {
        return Err(last_err());
    }
    Ok(())
}
