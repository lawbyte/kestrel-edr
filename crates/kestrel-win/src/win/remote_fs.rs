//! `RemoteFs` for Windows: drive listing, network / missing drive refusal,
//! protected folders, and the hardened (handle-based, link-safe) file
//! operations from `super::hardfs` (security review H1 / M3).

use super::hardfs;
use super::util::*;
use crate::remotefs::{self as plan};
use kestrel_common::remote::{FileEntry, FileKind};
use kestrel_platform::{FsGuard, FsOpError, RemoteFs};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use windows_sys::Win32::Storage::FileSystem::{
    GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
    FILE_ATTRIBUTE_DIRECTORY,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    SetThreadErrorMode, SEM_FAILCRITICALERRORS, SEM_NOOPENFILEERRORBOX,
};

/// Slow-media queries (empty CD / card reader) give up after this.
const SLOW_MEDIA_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct WinRemoteFs {
    roots: Vec<PathBuf>,
}

impl WinRemoteFs {
    pub fn new(state_dir: &Path, system_drive: char) -> WinRemoteFs {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf));
        WinRemoteFs {
            roots: plan::protected_roots_from(exe_dir.as_deref(), state_dir, system_drive),
        }
    }
}

fn drive_type(letter: char) -> u32 {
    let root = wide(&format!("{letter}:\\"));
    unsafe { GetDriveTypeW(root.as_ptr()) }
}

/// Suppress "insert a disk" error boxes for this thread while `f` runs.
fn quiet<T>(f: impl FnOnce() -> T) -> T {
    let mut old = 0u32;
    let set =
        unsafe { SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &mut old) }
            != 0;
    let r = f();
    if set {
        unsafe { SetThreadErrorMode(old, std::ptr::null_mut()) };
    }
    r
}

/// (volume label, free bytes available, total bytes).
fn volume_facts(letter: char) -> (Option<String>, Option<u64>, Option<u64>) {
    quiet(|| {
        let root = wide(&format!("{letter}:\\"));
        let mut name = [0u16; 261];
        let label = (unsafe {
            GetVolumeInformationW(
                root.as_ptr(),
                name.as_mut_ptr(),
                name.len() as u32,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } != 0)
            .then(|| from_wide(&name));
        let (mut avail, mut total, mut free) = (0u64, 0u64, 0u64);
        let ok =
            unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut avail, &mut total, &mut free) } != 0;
        if ok {
            (label, Some(avail), Some(total))
        } else {
            (label, None, None)
        }
    })
}

/// [`volume_facts`] with a timeout (the worker thread finishes on its own if
/// the device is stuck).
fn volume_facts_bounded(letter: char) -> (Option<String>, Option<u64>, Option<u64>) {
    let (tx, rx) = mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("kestrel-drive-query".into())
        .spawn(move || {
            let _ = tx.send(volume_facts(letter));
        });
    if spawned.is_err() {
        return (None, None, None);
    }
    rx.recv_timeout(SLOW_MEDIA_TIMEOUT)
        .unwrap_or((None, None, None))
}

impl RemoteFs for WinRemoteFs {
    fn local_path(&self, win_path: &str) -> PathBuf {
        // std adds the `\\?\` prefix itself for paths beyond MAX_PATH.
        PathBuf::from(win_path)
    }

    fn drives(&self) -> Vec<FileEntry> {
        let mask = unsafe { GetLogicalDrives() };
        let mut out = Vec::new();
        for letter in plan::drive_letters(mask) {
            let t = drive_type(letter);
            if !plan::include_drive(t) {
                continue;
            }
            let (vol, free, total) = if plan::is_slow_media(t) {
                volume_facts_bounded(letter)
            } else {
                volume_facts(letter)
            };
            out.push(FileEntry {
                name: format!("{letter}:"),
                path: format!("{letter}:\\"),
                kind: FileKind::Drive,
                attributes: FILE_ATTRIBUTE_DIRECTORY,
                free_bytes: free,
                total_bytes: total,
                label: Some(plan::drive_label(t, vol.as_deref())),
                ..Default::default()
            });
        }
        out
    }

    fn check_path(&self, win_path: &str) -> Result<(), String> {
        let d = plan::drive_of(win_path).ok_or_else(|| "path has no drive letter".to_string())?;
        match plan::drive_refusal(d, drive_type(d)) {
            Some(m) => Err(m),
            None => Ok(()),
        }
    }

    fn protected_roots(&self) -> Vec<PathBuf> {
        self.roots.clone()
    }

    fn verify_dir(&self, p: &Path, guard: FsGuard<'_>) -> Result<PathBuf, FsOpError> {
        hardfs::verify_dir(p, guard)
    }

    fn open_read(&self, p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
        hardfs::open_read(p, guard)
    }

    fn create_new(&self, p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
        hardfs::create_new(p, guard)
    }

    fn rename(
        &self,
        from: &Path,
        to: &Path,
        replace: bool,
        guard: FsGuard<'_>,
    ) -> Result<(), FsOpError> {
        hardfs::rename(from, to, replace, guard)
    }

    fn remove(&self, p: &Path, recursive: bool, guard: FsGuard<'_>) -> Result<u64, FsOpError> {
        hardfs::remove(p, recursive, guard)
    }

    fn create_dir_all(&self, p: &Path, guard: FsGuard<'_>) -> Result<(), FsOpError> {
        hardfs::create_dir_all(p, guard)
    }
}
