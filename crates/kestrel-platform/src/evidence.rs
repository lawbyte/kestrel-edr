//! Evidence capture: what the agent core needs from the OS
//! (`kestrel_common::evidence`). The agent core (portable, Linux-tested)
//! decides *what* to collect and builds the bundle; the platform opens
//! source files safely, holds the at-rest key, runs the packet capture and
//! reports which files processes wrote ([`WriteHint`]).

use kestrel_common::{
    evidence::{PcapFilter, WriteOp},
    ProcessGuid, TimestampMs,
};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A file a process created / overwrote / renamed into place under a
/// user-writable location, reported by the sensors through
/// `SensorConfig::write_tx`. Never uploaded and never an `Event`: it only
/// feeds the agent's bounded evidence journal (staged-file candidates).
#[derive(Debug, Clone, PartialEq)]
pub struct WriteHint {
    pub ts: TimestampMs,
    pub pid: u32,
    pub guid: ProcessGuid,
    /// Win32 path (`C:\Users\…`).
    pub path: String,
    pub op: WriteOp,
}

/// An opened source file (staged file or credential store), positioned at 0.
pub struct SourceFile {
    pub reader: Box<dyn Read + Send>,
    /// Size when opened.
    pub size: u64,
    /// The verified path that was opened (long form).
    pub path: String,
}

impl std::fmt::Debug for SourceFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceFile")
            .field("size", &self.size)
            .field("path", &self.path)
            .finish()
    }
}

/// Why a source file could not be opened (maps to
/// `kestrel_common::evidence::CopyStatus`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// Does not exist (any more).
    NotFound,
    /// A junction / symbolic link / mount point on the path or the file
    /// itself, a hard-linked file, a path that resolves elsewhere, or an
    /// alternate data stream. Never followed.
    Link(String),
    /// Open by another process without read sharing ("locked, not copied").
    Locked,
    /// Bigger than the cap passed to [`EvidenceHost::open_source`] (size).
    TooLarge(u64),
    /// A directory or a device / network path.
    NotAFile,
    /// Access denied or any other error.
    Other(String),
}

/// Why a packet capture did not start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureStartError {
    /// Another capture (someone else's pktmon session) is running.
    Busy(String),
    /// The mechanism is missing on this OS version / platform.
    Unsupported(String),
    Failed(String),
}

/// The pcapng a capture produced (plaintext, in the evidence work folder;
/// the agent seals it into the bundle and deletes it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFile {
    pub path: PathBuf,
    pub bytes: u64,
    /// The capture reached its size cap (circular log: the oldest packets
    /// were overwritten).
    pub truncated: bool,
}

/// A running capture. Blocking calls; the agent runs them on a blocking
/// thread.
pub trait CaptureSession: Send {
    /// Add filters to the running capture when the mechanism supports it
    /// (new connections of the tree during the window). Returns the filters
    /// actually added; default: none.
    fn add_filters(&mut self, filters: &[PcapFilter]) -> Vec<PcapFilter> {
        let _ = filters;
        Vec::new()
    }
    /// Stop capturing, remove Kestrel's filters and convert the capture to
    /// pcapng. Also called when the agent stops (partial capture kept).
    fn stop(self: Box<Self>) -> Result<CapturedFile, String>;
}

/// Packet capture (Windows: `PktMon.exe`, see
/// `docs/research/notes/evidence-pcap.md`).
pub trait PacketCapture: Send + Sync {
    /// Start a capture of traffic matching any of `filters` (remote IP,
    /// optional port and protocol; both directions) into `work_dir` (a
    /// private folder created by the agent), bounded to `max_bytes`.
    /// Never takes over a capture someone else started (`Busy`).
    fn start(
        &self,
        filters: &[PcapFilter],
        work_dir: &Path,
        max_bytes: u64,
    ) -> Result<Box<dyn CaptureSession>, CaptureStartError>;

    /// At agent start: stop a capture a previous agent process left running
    /// (crash), only if it is Kestrel's (its log file is inside
    /// `work_root`), and remove Kestrel's filters. Best effort.
    fn cleanup_stale(&self, work_root: &Path) {
        let _ = work_root;
    }

    /// Short mechanism name for the manifest (`pktmon`).
    fn mechanism(&self) -> &'static str;
}

/// Evidence support of a platform (`Platform::evidence`).
pub trait EvidenceHost: Send + Sync {
    /// Private folder for bundles and capture work files (inside the
    /// SYSTEM / Administrators-only state directory). The agent creates
    /// sub-folders below it.
    fn evidence_dir(&self) -> PathBuf;

    /// 32-byte at-rest key for bundles on this PC (Windows: generated once,
    /// stored DPAPI-protected with machine scope). Blocking.
    fn bundle_key(&self) -> Result<[u8; 32], String>;

    /// Lower-case path prefixes Kestrel owns (install folder, state
    /// folder): files below them are never collected.
    fn own_prefixes(&self) -> Vec<String>;

    /// Open an existing file for copying into a bundle, read-only, sharing
    /// read / write / delete with other programs (never blocks the owner),
    /// without following links anywhere on its path, refusing hard-linked
    /// files, alternate data streams, directories and network paths, and
    /// refusing files bigger than `max_bytes` (`TooLarge`). Blocking.
    fn open_source(&self, path: &str, max_bytes: u64) -> Result<SourceFile, SourceError>;

    /// Size of a file without opening it for reading (credential stores
    /// listed but not copied). `None` when unknown. Blocking.
    fn file_size(&self, path: &str) -> Option<u64> {
        let _ = path;
        None
    }

    /// The path the file system resolves `path` to, long form (8.3 short
    /// names expanded, verified against the opened handle's final path),
    /// without following links and without reading data. `None` when it
    /// cannot be resolved (missing, a link, an invalid path) or the platform
    /// does not resolve paths. The agent makes its collection-scope
    /// decisions on this path (review of the 1.1.7 integration, M1:
    /// `C:\PROGRA~3\Microsoft\Vault\…` is `C:\ProgramData\Microsoft\Vault\…`).
    /// Blocking.
    fn resolve_path(&self, path: &str) -> Option<String> {
        let _ = path;
        None
    }

    /// Profile folder of the account `user` (`DOMAIN\name`), from its SID
    /// (Windows: `LookupAccountNameW`, then
    /// `HKLM\…\ProfileList\<SID>\ProfileImagePath`). `None` when unknown.
    /// The agent copies profile files only from this exact folder when it
    /// is known (review of the 1.1.7 integration, L2). Blocking.
    fn profile_dir(&self, user: &str) -> Option<String> {
        let _ = user;
        None
    }

    /// Free bytes on the volume holding [`EvidenceHost::evidence_dir`]
    /// (`None` = unknown). The agent refuses to build a bundle that would
    /// leave less than a safety margin free. Blocking.
    fn free_bytes(&self) -> Option<u64> {
        None
    }

    /// Packet capture (`None` = unsupported on this platform).
    fn packet_capture(&self) -> Option<Arc<dyn PacketCapture>> {
        None
    }
}
