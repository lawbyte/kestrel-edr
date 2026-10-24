//! Platform hooks for admin remote access (remote desktop + file manager).
//!
//! The wire contract lives in `kestrel_common::remote`; the agent core
//! (`kestrel-agent/src/live.rs`, `remote_fs.rs`) owns sessions, policy
//! switches, path validation, protected folders, chunked transfers and flow
//! control. Platforms only provide the OS primitives below.

use kestrel_common::remote::{
    DesktopInfo, DesktopSettings, FileEntry, InputEvent, RemoteErrorCode,
};
use kestrel_common::TimestampMs;
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;

/// Refusal from a [`FsGuard`] or a hardened operation.
#[derive(Debug)]
pub enum FsOpError {
    /// Refused by a rule (protected / blocked / not local / wrong kind).
    Refused {
        code: RemoteErrorCode,
        message: String,
    },
    Io(std::io::Error),
}

impl FsOpError {
    pub fn refused(code: RemoteErrorCode, message: impl Into<String>) -> FsOpError {
        FsOpError::Refused {
            code,
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for FsOpError {
    fn from(e: std::io::Error) -> Self {
        FsOpError::Io(e)
    }
}

impl std::fmt::Display for FsOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FsOpError::Refused { message, .. } => f.write_str(message),
            FsOpError::Io(e) => write!(f, "{e}"),
        }
    }
}

/// Check applied to the final local path of every object a hardened
/// operation is about to use (see [`RemoteFs::remove`] etc.).
pub type FsGuard<'a> = &'a (dyn Fn(&Path) -> Result<(), FsOpError> + Send + Sync);

/// OS file-system primitives for the remote file manager. Every path given
/// to these methods has already passed
/// `kestrel_common::remote::validate_remote_path` (absolute `X:\…`, no `.`
/// / `..`, no streams, no UNC).
pub trait RemoteFs: Send + Sync {
    /// Local path `std::fs` should use for the Windows path `win_path`
    /// (Windows: the path itself; simulator: mapped under its state dir).
    fn local_path(&self, win_path: &str) -> PathBuf;

    /// Drive roots (`FileEntry { kind: Drive, path: "C:\\", .. }`), with
    /// label / free / total bytes when known. Network (remote) drives are
    /// omitted.
    fn drives(&self) -> Vec<FileEntry>;

    /// Platform-specific refusal (Windows: the drive is a network drive,
    /// `GetDriveTypeW == DRIVE_REMOTE`, or does not exist). `Err` carries a
    /// message for the admin.
    fn check_path(&self, win_path: &str) -> Result<(), String> {
        let _ = win_path;
        Ok(())
    }

    /// Local folders that must never be read, written, renamed or deleted
    /// through the file manager, nor any of their ancestors renamed or
    /// deleted (Windows: the agent's install folder, e.g.
    /// `C:\Program Files\Kestrel`, and its state folder
    /// `%ProgramData%\Kestrel`). The agent canonicalises them (resolving
    /// 8.3 names, junctions and symlinks) before comparing.
    fn protected_roots(&self) -> Vec<PathBuf>;

    // ------------------------------------------------------------------
    // Hardened operations (security review: H1 / M3). The agent core calls
    // these instead of `std::fs` for everything that opens, creates, renames
    // or deletes. `guard` is called with the **final** local path of every
    // object (after it was opened without following a final reparse point,
    // before anything is read, written, renamed or deleted); an `Err` from
    // the guard aborts with that refusal. The guard implements the protected
    // folders, blocked paths and "local volume only" rules.
    //
    // The defaults below use `std::fs` with `symlink_metadata` checks and
    // `canonicalize` for the guard: good enough for the simulator and tests,
    // but racy (a parent folder can be swapped for a junction between the
    // check and the use). The Windows platform overrides every method with
    // handle-based implementations: each component is opened relative to its
    // parent handle with `FILE_FLAG_OPEN_REPARSE_POINT`, the guard sees
    // `GetFinalPathNameByHandleW` of the handle that is then used, deletes
    // and renames go through that handle, and enumeration uses the directory
    // handle, so nothing is ever acted on through a swapped link.
    // ------------------------------------------------------------------

    /// Verify a folder for listing; returns the local path to enumerate
    /// (the final path the guard approved).
    fn verify_dir(&self, p: &Path, guard: FsGuard<'_>) -> Result<PathBuf, FsOpError> {
        let md = std::fs::metadata(p)?;
        if !md.is_dir() {
            return Err(FsOpError::refused(
                RemoteErrorCode::InvalidOperation,
                "not a folder",
            ));
        }
        let fin = std::fs::canonicalize(p)?;
        guard(&fin)?;
        Ok(fin)
    }

    /// Open an existing regular file for reading (never a directory, never
    /// through a final reparse point).
    fn open_read(&self, p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
        let lmd = std::fs::symlink_metadata(p)?;
        if lmd.file_type().is_symlink() {
            return Err(FsOpError::refused(
                RemoteErrorCode::InvalidOperation,
                "the path is a link; open its target instead",
            ));
        }
        if lmd.is_dir() {
            return Err(FsOpError::refused(
                RemoteErrorCode::InvalidOperation,
                "the path is a folder",
            ));
        }
        guard(&std::fs::canonicalize(p)?)?;
        Ok(std::fs::File::open(p)?)
    }

    /// Create a new file exclusively (fails if anything exists at `p`) in an
    /// existing folder, for writing. Used for upload temp files.
    fn create_new(&self, p: &Path, guard: FsGuard<'_>) -> Result<std::fs::File, FsOpError> {
        let parent = p
            .parent()
            .ok_or_else(|| FsOpError::refused(RemoteErrorCode::InvalidPath, "no parent folder"))?;
        let pfin = std::fs::canonicalize(parent)?;
        if let Some(name) = p.file_name() {
            guard(&pfin.join(name))?;
        }
        Ok(std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(p)?)
    }

    /// Rename / move `from` to `to` (same volume), replacing an existing
    /// **file** at `to` only when `replace`. A link at `from` is moved as the
    /// link itself. The guard sees both the final source path and the final
    /// destination path (destination folder + new name).
    fn rename(
        &self,
        from: &Path,
        to: &Path,
        replace: bool,
        guard: FsGuard<'_>,
    ) -> Result<(), FsOpError> {
        let lmd = std::fs::symlink_metadata(from)?;
        let src_fin = if lmd.file_type().is_symlink() {
            match (from.parent(), from.file_name()) {
                (Some(d), Some(n)) => std::fs::canonicalize(d)?.join(n),
                _ => from.to_path_buf(),
            }
        } else {
            std::fs::canonicalize(from)?
        };
        guard(&src_fin)?;
        let to_parent = to.parent().ok_or_else(|| {
            FsOpError::refused(RemoteErrorCode::InvalidPath, "no destination folder")
        })?;
        if let Some(n) = to.file_name() {
            guard(&std::fs::canonicalize(to_parent)?.join(n))?;
        }
        match std::fs::symlink_metadata(to) {
            Ok(md) if md.is_dir() => {
                return Err(FsOpError::refused(
                    RemoteErrorCode::InvalidOperation,
                    "the destination is a folder",
                ))
            }
            Ok(_) if !replace => {
                return Err(FsOpError::refused(
                    RemoteErrorCode::AlreadyExists,
                    "the destination exists",
                ))
            }
            _ => {}
        }
        std::fs::rename(from, to)?;
        Ok(())
    }

    /// Delete a file, an empty folder, or (with `recursive`) a folder tree.
    /// Links (junctions, symlinks, mount points) are removed as links and
    /// never descended into. Read-only attributes are cleared first. Every
    /// object is passed to the guard before it is removed. Returns the
    /// number of objects removed.
    fn remove(&self, p: &Path, recursive: bool, guard: FsGuard<'_>) -> Result<u64, FsOpError> {
        fn clear_ro(p: &Path) {
            if let Ok(md) = std::fs::symlink_metadata(p) {
                let mut perm = md.permissions();
                if perm.readonly() {
                    #[allow(clippy::permissions_set_readonly_false)]
                    perm.set_readonly(false);
                    let _ = std::fs::set_permissions(p, perm);
                }
            }
        }
        fn fin(p: &Path) -> std::io::Result<PathBuf> {
            match (p.parent(), p.file_name()) {
                (Some(d), Some(n)) => Ok(std::fs::canonicalize(d)?.join(n)),
                _ => Ok(p.to_path_buf()),
            }
        }
        fn rm(p: &Path, recursive: bool, guard: FsGuard<'_>, top: bool) -> Result<u64, FsOpError> {
            let md = std::fs::symlink_metadata(p)?;
            guard(&fin(p)?)?;
            if md.file_type().is_symlink() {
                // Remove the link itself; never follow it.
                if std::fs::remove_dir(p).is_err() {
                    std::fs::remove_file(p)?;
                }
                return Ok(1);
            }
            if md.is_dir() {
                let mut n = 0;
                let mut entries = std::fs::read_dir(p)?.peekable();
                if entries.peek().is_some() && !recursive && top {
                    return Err(FsOpError::refused(
                        RemoteErrorCode::InvalidOperation,
                        "the folder is not empty",
                    ));
                }
                for e in entries {
                    n += rm(&e?.path(), recursive, guard, false)?;
                }
                clear_ro(p);
                std::fs::remove_dir(p)?;
                return Ok(n + 1);
            }
            clear_ro(p);
            std::fs::remove_file(p)?;
            Ok(1)
        }
        rm(p, recursive, guard, true)
    }

    /// Create a folder and its missing parents; each folder created is
    /// passed to the guard first. An existing file at `p` → `AlreadyExists`.
    fn create_dir_all(&self, p: &Path, guard: FsGuard<'_>) -> Result<(), FsOpError> {
        match std::fs::symlink_metadata(p) {
            Ok(md) if md.is_dir() => return Ok(()),
            Ok(_) => {
                return Err(FsOpError::refused(
                    RemoteErrorCode::AlreadyExists,
                    "a file with that name exists",
                ))
            }
            Err(_) => {}
        }
        if let Some(parent) = p.parent() {
            if std::fs::symlink_metadata(parent).is_err() {
                self.create_dir_all(parent, guard)?;
            }
            if let Some(n) = p.file_name() {
                guard(&std::fs::canonicalize(parent)?.join(n))?;
            }
        }
        std::fs::create_dir(p)?;
        Ok(())
    }
}

/// Parameters of a remote-desktop session.
#[derive(Debug, Clone, PartialEq)]
pub struct DesktopStartParams {
    pub view_only: bool,
    /// Shown in the employee's banner: "IT ({admin_name}) is viewing /
    /// controlling this PC".
    pub admin_name: String,
    pub reason: String,
    pub settings: DesktopSettings,
}

/// What a running capture reports to the agent core.
#[derive(Debug, Clone, PartialEq)]
pub enum DesktopEvent {
    /// Capture is running (first event) or the geometry changed.
    Info(DesktopInfo),
    /// One JPEG frame (already scaled per settings).
    Frame {
        width: u32,
        height: u32,
        ts: TimestampMs,
        jpeg: Vec<u8>,
    },
    /// The session ended on its own (helper exited, user logged off, error).
    Ended {
        reason: String,
        code: Option<RemoteErrorCode>,
    },
}

/// Event channel from the platform session to the agent core. It is small
/// (capacity 1-2): the core only pulls frames while it has flow-control
/// credit. A producer whose `try_send` fails must **not** treat that frame
/// as delivered: change detection compares against the last frame the sink
/// accepted, so the newest screen content is always sent eventually.
/// `Info` / `Ended` events should use `blocking_send` / `send`.
pub type DesktopSink = mpsc::Sender<DesktopEvent>;

/// A running remote-desktop session.
pub trait DesktopSession: Send + Sync {
    /// Inject input. Callers already dropped input for view-only sessions and
    /// sanitised coordinates (`InputEvent::sanitized`).
    fn input(&self, ev: &InputEvent);
    /// Apply new quality / scale / fps; `view_only: Some(_)` also updates the
    /// employee's banner text.
    fn settings(&self, s: &DesktopSettings);
    /// End the session: stop capture, remove the banner, terminate any helper
    /// process. Idempotent; must not block for long.
    fn stop(&self);
    /// Show `text` (the remote file-manager notice composed by the agent
    /// core, e.g. "IT (Jane Doe) is accessing files on this PC since
    /// 14:02") as an extra line of this session's banner; empty removes it.
    /// While a desktop session runs, its banner is the only one on screen:
    /// the agent closes the stand-alone file banner ([`SessionBanner`]) once
    /// the desktop banner carries the notice.
    fn set_files_notice(&self, text: &str);
}

/// A stand-alone employee banner (remote file manager without a desktop
/// session). Windows: the desktop helper in banner-only mode (no capture,
/// no input) in the active console session.
pub trait SessionBanner: Send + Sync {
    /// Replace the text.
    fn set_text(&self, text: &str);
    /// Whether the banner is still on screen (helper process running and
    /// connected). `false` after [`SessionBanner::close`] or when the helper
    /// ended on its own (user logged off, console session changed).
    fn is_alive(&self) -> bool;
    /// Remove the banner and end any helper process. Idempotent; must not
    /// block for long.
    fn close(&self);
}

/// Screen capture + input injection.
pub trait RemoteDesktop: Send + Sync {
    /// Start a session. Windows: spawns the capture helper in the active
    /// console session (it shows the banner for the whole session). Returns
    /// `Unavailable` when no interactive session exists or the helper cannot
    /// start.
    fn start(
        &self,
        params: DesktopStartParams,
        sink: DesktopSink,
    ) -> Result<Box<dyn DesktopSession>, (RemoteErrorCode, String)>;

    /// Show the mandatory employee banner on its own (remote file-manager
    /// sessions). Returns only once the banner is on screen; any failure is
    /// an `Err` and the agent refuses the file operation (fail closed), with
    /// the same rules as [`RemoteDesktop::start`]: `Unavailable` when no
    /// interactive console session exists or the helper / banner window
    /// cannot start. The default refuses (no banner on this platform).
    fn show_banner(&self, text: &str) -> Result<Box<dyn SessionBanner>, (RemoteErrorCode, String)> {
        let _ = text;
        Err((
            RemoteErrorCode::Unavailable,
            "this device cannot show the on-screen notice for remote access".into(),
        ))
    }
}
