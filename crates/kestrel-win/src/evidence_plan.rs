//! Evidence capture for suspected data theft: the pure (platform
//! independent, Linux-tested) half of the Windows layer
//! (`docs/DECISIONS.md` 2026-10-25, decisions 3, 4, 5, 6 and 10).
//!
//! * [`WriteScope`] / [`write_op`] / [`HintDedup`]: which Kernel-File creates
//!   become `kestrel_platform::WriteHint`s (staged-file candidates);
//! * [`check_source_path`] / [`classify_os_error`]: the path checks and error
//!   mapping of `EvidenceHost::open_source` before / after the link-safe open;
//! * [`pktmon`]: every `PktMon.exe` command line, built only from parsed
//!   values, and the parsers of `pktmon status` / `pktmon filter list`
//!   (research: `docs/research/notes/evidence-pcap.md`).

use crate::etwparse::is_directory_open;
use kestrel_common::evidence::WriteOp;
use kestrel_platform::SourceError;
use std::collections::HashMap;

// ------------------------------------------------------------ write hints

/// User-writable locations on the system volume whose new / overwritten
/// files are staged-file candidates. NT paths (`\Device\HarddiskVolume3\…`).
#[derive(Debug, Clone)]
pub struct WriteScope {
    /// Lower-cased NT device of the system volume, no trailing `\`
    /// ("" = unknown: nothing is in scope).
    system_device: String,
}

/// Roots (below the system volume, lower-case, with trailing `\`) whose
/// files are in scope.
const WRITE_ROOTS: &[&str] = &[
    r"\users\",
    r"\programdata\",
    r"\windows\temp\",
    r"\temp\",
    r"\tmp\",
];

/// Never in scope (Kestrel's own state, Defender's working folders).
const WRITE_EXCLUDES: &[&str] = &[
    r"\programdata\kestrel\",
    r"\programdata\microsoft\windows defender\",
];

impl WriteScope {
    pub fn new(system_device: &str) -> Self {
        WriteScope {
            system_device: system_device.trim_end_matches('\\').to_ascii_lowercase(),
        }
    }

    /// Is the NT path `nt` (any case) a file in a user-writable location of
    /// the system volume? Network paths, other volumes, shadow copies,
    /// alternate data streams and folder paths are out.
    pub fn in_scope(&self, nt: &str) -> bool {
        let dev = self.system_device.as_str();
        if dev.is_empty() {
            return false;
        }
        let Some(head) = nt.get(..dev.len()) else {
            return false;
        };
        if !head.eq_ignore_ascii_case(dev) {
            return false;
        }
        let rest = &nt[dev.len()..];
        if !rest.starts_with('\\') || rest.ends_with('\\') || rest.contains(':') {
            return false;
        }
        let rest = rest.to_ascii_lowercase();
        if WRITE_EXCLUDES.iter().any(|x| rest.starts_with(x)) {
            return false;
        }
        WRITE_ROOTS
            .iter()
            .any(|r| rest.len() > r.len() && rest.starts_with(r))
    }
}

/// The write a Kernel-File event reports, if any: only CreateNewFile (30),
/// the confirmed creation of a new file → `Created`. Directory creates
/// (FILE_DIRECTORY_FILE) never.
///
/// Kernel-File Create (12) is **not** used (security review 2026-10-25,
/// H1): it is logged for failed opens too, so a process could "overwrite"
/// files it cannot write (another user's documents, SSH / machine keys)
/// and make the SYSTEM agent copy them. Consequence: `Overwritten` is never
/// reported, and an existing file overwritten in place (supersede /
/// overwrite dispositions) or appended to is not seen; staging archives and
/// dumps are new files, which are.
pub fn write_op(event_id: u16, create_options: u32) -> Option<WriteOp> {
    if event_id == crate::consts::eid::FILE_CREATE_NEW && !is_directory_open(create_options) {
        Some(WriteOp::Created)
    } else {
        None
    }
}

/// Longest NT path (UTF-16 units) a write hint is made for (checked in the
/// ETW callback, before anything is allocated).
pub const MAX_HINT_PATH_UNITS: usize = 1024;

/// Is `name` at most [`MAX_HINT_PATH_UNITS`] UTF-16 units long? No
/// allocation (UTF-16 units never exceed UTF-8 bytes).
pub fn hint_path_len_ok(name: &str) -> bool {
    name.len() <= MAX_HINT_PATH_UNITS || name.encode_utf16().nth(MAX_HINT_PATH_UNITS).is_none()
}

/// Same (pid, path) at most once per [`HINT_DEDUP_MS`].
pub const HINT_DEDUP_MS: i64 = 1_000;
const HINT_DEDUP_CAP: usize = 16_384;
/// Bound on the key bytes the de-duplication map holds.
const HINT_DEDUP_MAX_BYTES: usize = 4 * 1024 * 1024;

/// Duplicate suppression of write hints (translator thread).
#[derive(Debug, Default)]
pub struct HintDedup {
    seen: HashMap<(u32, String), i64>,
    newest: i64,
    /// Sum of the key paths' lengths (bytes).
    bytes: usize,
}

impl HintDedup {
    /// Should a hint of `pid` for `path_key` (lower-case Win32 path) at `ts`
    /// be reported?
    pub fn admit(&mut self, pid: u32, path_key: String, ts: i64) -> bool {
        self.newest = self.newest.max(ts);
        let key = (pid, path_key);
        if let Some(prev) = self.seen.get(&key) {
            if (ts - prev).abs() < HINT_DEDUP_MS {
                return false;
            }
        }
        let n = key.1.len();
        if self.seen.insert(key, ts).is_none() {
            self.bytes += n;
        }
        if self.seen.len() > HINT_DEDUP_CAP || self.bytes > HINT_DEDUP_MAX_BYTES {
            let cut = self.newest - HINT_DEDUP_MS;
            self.seen.retain(|_, t| *t >= cut);
            self.bytes = self.seen.keys().map(|k| k.1.len()).sum();
            if self.seen.len() > HINT_DEDUP_CAP || self.bytes > HINT_DEDUP_MAX_BYTES {
                self.seen.clear();
                self.bytes = 0;
            }
        }
        true
    }

    /// Key bytes held.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// `C:\…` (a DOS drive path, the translator's mapping succeeded).
pub fn is_drive_path(p: &str) -> bool {
    let b = p.as_bytes();
    b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\'
}

// ------------------------------------------------------------ source files

/// Checks of `EvidenceHost::open_source` / `file_size` before anything is
/// opened: an absolute `X:\…` path (forward slashes normalised), no UNC /
/// device / `\\?\` form, no alternate data stream (`:` after the drive), no
/// `.` / `..` components, no wildcard / quote characters, not a folder path.
/// Returns the normalised path.
pub fn check_source_path(path: &str) -> Result<String, SourceError> {
    if path.is_empty() || path.contains('\0') || path.chars().any(|c| c.is_control()) {
        return Err(SourceError::Other("invalid path".into()));
    }
    let p = path.replace('/', "\\");
    if p.starts_with('\\') {
        return Err(SourceError::NotAFile);
    }
    if !is_drive_path(&p) {
        return Err(SourceError::Other("not an absolute path".into()));
    }
    let rest = &p[2..];
    if rest.contains(':') {
        return Err(SourceError::Link(
            "alternate data stream; never collected".into(),
        ));
    }
    if rest.ends_with('\\') {
        return Err(SourceError::NotAFile);
    }
    if rest
        .chars()
        .any(|c| matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return Err(SourceError::Other("invalid character in path".into()));
    }
    if rest
        .split('\\')
        .skip(1)
        .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return Err(SourceError::Other(
            "relative or empty path component".into(),
        ));
    }
    Ok(p)
}

/// Win32 error codes of a failed open that have their own [`SourceError`].
pub fn classify_os_error(code: Option<i32>) -> Option<SourceError> {
    match code? {
        // ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND
        2 | 3 => Some(SourceError::NotFound),
        // ERROR_SHARING_VIOLATION, ERROR_LOCK_VIOLATION
        32 | 33 => Some(SourceError::Locked),
        // ERROR_ACCESS_DENIED
        5 => Some(SourceError::Other("access denied".into())),
        _ => None,
    }
}

/// `STATUS_OPLOCK_BREAK_IN_PROGRESS`.
pub const STATUS_OPLOCK_BREAK_IN_PROGRESS: u32 = 0x0000_0108;

/// NTSTATUS of an `NtCreateFile` that did not give a usable handle →
/// [`SourceError`]. `STATUS_OPLOCK_BREAK_IN_PROGRESS` (a success code with
/// `FILE_COMPLETE_IF_OPLOCKED`) is `Locked`: another program holds an
/// oplock on the file and Kestrel never waits for it.
pub fn classify_ntstatus(status: u32) -> SourceError {
    match status {
        STATUS_OPLOCK_BREAK_IN_PROGRESS => SourceError::Locked,
        // OBJECT_NAME_NOT_FOUND, OBJECT_PATH_NOT_FOUND, NO_SUCH_FILE, DELETE_PENDING
        0xC000_0034 | 0xC000_003A | 0xC000_000F | 0xC000_0056 => SourceError::NotFound,
        // SHARING_VIOLATION, FILE_LOCK_CONFLICT, LOCK_NOT_GRANTED
        0xC000_0043 | 0xC000_0054 | 0xC000_0055 => SourceError::Locked,
        // FILE_IS_A_DIRECTORY
        0xC000_00BA => SourceError::NotAFile,
        // ACCESS_DENIED
        0xC000_0022 => SourceError::Other("access denied".into()),
        s => SourceError::Other(format!("cannot open (NTSTATUS 0x{s:08X})")),
    }
}

/// What to do with a reparse point on a source file (opened with
/// `FILE_OPEN_REPARSE_POINT`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReparseAction {
    /// Data deduplication: reopen without `FILE_OPEN_REPARSE_POINT` so the
    /// dedup filter serves the (local) data.
    ReopenDedup,
    Refuse(SourceError),
}

/// `IO_REPARSE_TAG_DEDUP`.
pub const IO_REPARSE_TAG_DEDUP: u32 = 0x8000_0013;

/// Reparse-point policy of `open_source` (security review 2026-10-25, H2):
/// name surrogates (junction, symbolic link, mount point) are links; cloud
/// placeholders (`IO_REPARSE_TAG_CLOUD*`) are never hydrated as SYSTEM (a
/// user-registered sync provider could stall the open / read forever);
/// dedup is reopened; every other reparse point is refused.
pub fn reparse_action(tag: u32) -> ReparseAction {
    if tag & 0x2000_0000 != 0 {
        return ReparseAction::Refuse(SourceError::Link(
            "the file is a symbolic link / junction; not followed".into(),
        ));
    }
    if tag & 0xFFFF_0FFF == 0x9000_001A {
        return ReparseAction::Refuse(SourceError::Other(
            "cloud placeholder not downloaded; not collected".into(),
        ));
    }
    if tag == IO_REPARSE_TAG_DEDUP {
        return ReparseAction::ReopenDedup;
    }
    ReparseAction::Refuse(SourceError::Other(format!(
        "reparse point (tag 0x{tag:08X}); not collected"
    )))
}

/// `\??\C:\…` NT form of a checked `C:\…` path for `NtCreateFile`.
pub fn nt_object_path(dos: &str) -> String {
    format!(r"\??\{dos}")
}

/// Lower-case, normalised (no `\\?\`, no trailing `\`) Kestrel folders for
/// `EvidenceHost::own_prefixes`. A path is inside one when it equals it or
/// starts with it followed by `\`.
pub fn own_prefixes(dirs: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in dirs {
        let n = crate::qpolicy::normalize_for_compare(d);
        if !n.is_empty() && !out.contains(&n) {
            out.push(n);
        }
    }
    out
}

/// Build number from `OsInfo.build` (`10.0.19045.1234`).
pub fn os_build(build: &str) -> Option<u32> {
    build.split('.').nth(2)?.trim().parse().ok()
}

// ------------------------------------------------------------ pktmon

/// `PktMon.exe` planning and output parsing (Decision section of
/// `docs/research/notes/evidence-pcap.md`). Nothing here runs anything.
pub mod pktmon {
    use kestrel_common::evidence::{PcapFilter, PCAP_MAX_FILTERS};
    use kestrel_common::NetProto;
    use serde::{Deserialize, Serialize};
    use std::net::IpAddr;

    /// Packet Monitor's current command syntax: Windows 10 2004 and later.
    pub const MIN_BUILD: u32 = 19041;
    /// Kestrel's filter names: `KestrelEv01` … `KestrelEv16`.
    pub const FILTER_PREFIX: &str = "KestrelEv";
    /// Marker file in the work root (the parent of a capture's work dir)
    /// while a capture runs.
    pub const MARKER_FILE: &str = "pktmon-active.json";
    pub const ETL_NAME: &str = "capture.etl";
    pub const PCAPNG_NAME: &str = "capture.pcapng";
    /// Largest `--file-size` (MB) Kestrel ever asks for.
    pub const MAX_FILE_SIZE_MB: u64 = 512;

    pub fn filter_name(i: usize) -> String {
        format!("{FILTER_PREFIX}{:02}", i + 1)
    }

    /// `KestrelEvNN` (two digits).
    pub fn is_our_filter_name(name: &str) -> bool {
        name.strip_prefix(FILTER_PREFIX)
            .is_some_and(|d| d.len() == 2 && d.bytes().all(|b| b.is_ascii_digit()))
    }

    /// Re-parse a filter: `ip` must be an IP literal (never a host name),
    /// IPv4-mapped IPv6 becomes IPv4; loopback, unspecified, multicast,
    /// broadcast and link-local addresses are refused (never useful, or not
    /// captured); a port must be 1..=65535.
    pub fn normalize_filter(f: &PcapFilter) -> Option<PcapFilter> {
        let ip: IpAddr = f.ip.parse().ok()?;
        let ip = ip.to_canonical();
        let bad = ip.is_loopback()
            || ip.is_unspecified()
            || ip.is_multicast()
            || match ip {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_link_local(),
                IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
            };
        if bad {
            return None;
        }
        if f.port == Some(0) {
            return None;
        }
        Some(PcapFilter {
            ip: ip.to_string(),
            port: f.port,
            proto: f.proto,
        })
    }

    /// One `pktmon filter add` of a capture.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct PlannedFilter {
        pub name: String,
        pub filter: PcapFilter,
        /// Arguments after the executable.
        pub args: Vec<String>,
    }

    /// Filters of a capture: normalised, de-duplicated, at most
    /// [`PCAP_MAX_FILTERS`] (the first ones: the agent passes the most
    /// recent tuples first). Returns (planned, dropped count).
    pub fn plan_filters(filters: &[PcapFilter]) -> (Vec<PlannedFilter>, usize) {
        let mut out: Vec<PlannedFilter> = Vec::new();
        let mut dropped = 0usize;
        for f in filters {
            let Some(n) = normalize_filter(f) else {
                dropped += 1;
                continue;
            };
            if out.iter().any(|p| p.filter == n) {
                continue;
            }
            if out.len() >= PCAP_MAX_FILTERS {
                dropped += 1;
                continue;
            }
            let name = filter_name(out.len());
            let args = filter_add_args(&name, &n);
            out.push(PlannedFilter {
                name,
                filter: n,
                args,
            });
        }
        (out, dropped)
    }

    /// `filter add <name> [-t TCP|UDP] -i <ip> [-p <port>]` from an already
    /// normalised filter (the IP is re-parsed and re-formatted once more).
    fn filter_add_args(name: &str, f: &PcapFilter) -> Vec<String> {
        let mut a = vec!["filter".to_string(), "add".to_string(), name.to_string()];
        if let Some(p) = f.proto {
            a.push("-t".into());
            a.push(
                match p {
                    NetProto::Tcp => "TCP",
                    NetProto::Udp => "UDP",
                }
                .into(),
            );
        }
        let ip: IpAddr = f.ip.parse().unwrap_or(IpAddr::from([0u8, 0, 0, 0]));
        a.push("-i".into());
        a.push(ip.to_string());
        if let Some(port) = f.port.filter(|p| *p > 0) {
            a.push("-p".into());
            a.push(port.to_string());
        }
        a
    }

    /// The files of one capture. All absolute; only built from the work
    /// directory the agent passed in.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct Paths {
        pub work_dir: String,
        pub work_root: String,
        pub etl: String,
        pub pcapng: String,
        pub marker: String,
    }

    /// Validate a folder path that will be passed to PktMon: `X:\…`,
    /// absolute, no UNC / device form, no `:` after the drive, no quote or
    /// control characters, no `.` / `..` component, nothing that could be
    /// read as an option. Returns it without a trailing `\`.
    pub fn validate_dir(dir: &str) -> Result<String, String> {
        let d = dir.trim_end_matches('\\');
        if !super::is_drive_path(&format!("{d}\\")) || d.len() < 3 {
            return Err(format!("{dir}: not an absolute folder path"));
        }
        let rest = &d[2..];
        if rest.contains(':')
            || d.chars()
                .any(|c| c.is_control() || matches!(c, '"' | '*' | '?' | '<' | '>' | '|' | '/'))
        {
            return Err(format!("{dir}: invalid characters"));
        }
        if rest
            .split('\\')
            .skip(1)
            .any(|c| c.is_empty() || c == "." || c == ".." || c.trim() != c)
        {
            return Err(format!("{dir}: invalid path component"));
        }
        Ok(d.to_string())
    }

    /// Paths of a capture in `work_dir`; the marker lives in its parent
    /// (the work root passed to `cleanup_stale`).
    pub fn paths(work_dir: &str) -> Result<Paths, String> {
        let wd = validate_dir(work_dir)?;
        let root = match wd.rfind('\\') {
            Some(i) if i > 2 => wd[..i].to_string(),
            _ => return Err(format!("{work_dir}: the work folder needs a parent folder")),
        };
        Ok(Paths {
            etl: format!("{wd}\\{ETL_NAME}"),
            pcapng: format!("{wd}\\{PCAPNG_NAME}"),
            marker: format!("{root}\\{MARKER_FILE}"),
            work_root: root,
            work_dir: wd,
        })
    }

    /// `--file-size` in MB for a byte cap (at least 1, at most
    /// [`MAX_FILE_SIZE_MB`]).
    pub fn file_size_mb(max_bytes: u64) -> u64 {
        (max_bytes / (1024 * 1024)).clamp(1, MAX_FILE_SIZE_MB)
    }

    fn v(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    pub fn start_args(etl: &str, file_size_mb: u64) -> Vec<String> {
        let mut a = v(&[
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            "0",
            "--file-name",
        ]);
        a.push(etl.to_string());
        a.push("--file-size".into());
        a.push(file_size_mb.clamp(1, MAX_FILE_SIZE_MB).to_string());
        a.push("--log-mode".into());
        a.push("circular".into());
        a
    }

    pub fn stop_args() -> Vec<String> {
        v(&["stop"])
    }

    pub fn status_args() -> Vec<String> {
        v(&["status"])
    }

    pub fn filter_list_args() -> Vec<String> {
        v(&["filter", "list"])
    }

    /// Removes **all** filters (the only documented form): only run when
    /// every configured filter is Kestrel's.
    pub fn filter_remove_args() -> Vec<String> {
        v(&["filter", "remove"])
    }

    pub fn etl2pcap_args(etl: &str, out: &str) -> Vec<String> {
        vec![
            "etl2pcap".into(),
            etl.to_string(),
            "--out".into(),
            out.to_string(),
        ]
    }

    /// Parsed `pktmon status`.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Status {
        /// A capture / counters session is running.
        pub running: bool,
        pub log_file: Option<String>,
        pub events_lost: Option<u64>,
    }

    /// Parse `pktmon status`. Running when any of the documented session
    /// lines is present (`Collected Data:`, `Logger name:`, `Logging mode:`,
    /// `Log file:`); the idle text is not documented (lab check), so
    /// anything else counts as idle.
    pub fn parse_status(text: &str) -> Status {
        let mut s = Status::default();
        for line in text.lines() {
            let Some((k, val)) = line.split_once(':') else {
                continue;
            };
            let key = k.trim().to_ascii_lowercase();
            let val = val.trim();
            match key.as_str() {
                "collected data" | "logger name" | "logging mode" => s.running = true,
                "log file" => {
                    s.running = true;
                    if !val.is_empty() {
                        s.log_file = Some(val.to_string());
                    }
                }
                "events lost" => s.events_lost = val.parse().ok(),
                _ => {}
            }
        }
        s
    }

    /// Parsed `pktmon filter list`.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct FilterList {
        /// Names of Kestrel's filters.
        pub ours: Vec<String>,
        /// Filters that are not Kestrel's (other names, or no name).
        pub foreign: usize,
    }

    impl FilterList {
        pub fn is_empty(&self) -> bool {
            self.ours.is_empty() && self.foreign == 0
        }
    }

    /// Parse the table of `pktmon filter list`: rows start with the filter
    /// number, then the name (optional in pktmon: a row whose second column
    /// is not a Kestrel name counts as foreign).
    pub fn parse_filter_list(text: &str) -> FilterList {
        let mut l = FilterList::default();
        for line in text.lines() {
            let mut it = line.split_whitespace();
            let Some(first) = it.next() else {
                continue;
            };
            if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            match it.next() {
                Some(name) if is_our_filter_name(name) => l.ours.push(name.to_string()),
                _ => l.foreign += 1,
            }
        }
        l
    }

    /// Is `path` inside the folder `root` (case-insensitive, `\`)?
    pub fn path_inside(path: &str, root: &str) -> bool {
        let p = crate::qpolicy::normalize_for_compare(path);
        let r = crate::qpolicy::normalize_for_compare(root);
        !r.is_empty() && p.len() > r.len() + 1 && p.starts_with(&format!("{r}\\"))
    }

    /// Can a capture start?
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum StartCheck {
        /// Nothing running, no foreign filters. `remove_ours`: Kestrel
        /// filters of an earlier capture are still configured.
        Go {
            remove_ours: bool,
        },
        Busy(String),
    }

    pub fn assess_start(status: &Status, filters: &FilterList) -> StartCheck {
        if status.running {
            return StartCheck::Busy(match &status.log_file {
                Some(f) => format!("a Packet Monitor capture is already running (log file {f})"),
                None => "a Packet Monitor session is already running".into(),
            });
        }
        if filters.foreign > 0 {
            return StartCheck::Busy(format!(
                "{} Packet Monitor filter(s) configured by someone else",
                filters.foreign
            ));
        }
        StartCheck::Go {
            remove_ours: !filters.ours.is_empty(),
        }
    }

    /// What `cleanup_stale` does.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct CleanupPlan {
        pub stop: bool,
        pub remove_filters: bool,
    }

    /// Stale capture of a crashed agent: only with the marker, stop only a
    /// session whose log file is inside `work_root`, remove filters only
    /// when every configured one is Kestrel's and no foreign session runs.
    pub fn assess_cleanup(
        marker_exists: bool,
        status: &Status,
        filters: &FilterList,
        work_root: &str,
    ) -> CleanupPlan {
        if !marker_exists {
            return CleanupPlan::default();
        }
        let ours_running = status.running
            && status
                .log_file
                .as_deref()
                .is_some_and(|f| path_inside(f, work_root));
        let foreign_running = status.running && !ours_running;
        CleanupPlan {
            stop: ours_running,
            remove_filters: !foreign_running && filters.foreign == 0 && !filters.ours.is_empty(),
        }
    }

    /// What ending a capture does.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct HaltPlan {
        /// Run `pktmon stop` (the running session is Kestrel's).
        pub stop: bool,
        /// Remove Kestrel's filters (only when all are ours, re-listed).
        pub remove_filters: bool,
        /// Keep the marker for `cleanup_stale` (state unknown or a foreign
        /// session runs).
        pub keep_marker: bool,
        /// The capture file is complete and can be converted.
        pub convert: bool,
    }

    /// End of a capture given `pktmon status` (`None` = the status query
    /// failed: unknown, treated as not ours: nothing is stopped or removed,
    /// the marker stays for `cleanup_stale`). A session whose log file is not
    /// inside `work_dir` is someone else's: never stopped, filters left.
    pub fn assess_halt(status: Option<&Status>, work_dir: &str) -> HaltPlan {
        let unknown = HaltPlan {
            stop: false,
            remove_filters: false,
            keep_marker: true,
            convert: false,
        };
        let Some(s) = status else {
            return unknown;
        };
        if !s.running {
            return HaltPlan {
                stop: false,
                remove_filters: true,
                keep_marker: false,
                convert: true,
            };
        }
        if s.log_file
            .as_deref()
            .is_some_and(|f| path_inside(f, work_dir))
        {
            return HaltPlan {
                stop: true,
                remove_filters: true,
                keep_marker: false,
                convert: true,
            };
        }
        unknown
    }

    /// A converted capture larger than the cap plus
    /// [`kestrel_common::evidence::PCAP_SLACK_BYTES`] is discarded.
    pub fn pcapng_size_ok(bytes: u64, max_bytes: u64) -> bool {
        use kestrel_common::evidence::{PCAP_MAX_BYTES, PCAP_SLACK_BYTES};
        bytes <= max_bytes.min(PCAP_MAX_BYTES) + PCAP_SLACK_BYTES
    }

    /// The circular log reached its cap (the oldest packets were
    /// overwritten). Within 1 MB of the cap counts (ETW buffers).
    pub fn etl_reached_cap(etl_bytes: u64, file_size_mb: u64) -> bool {
        let cap = file_size_mb.saturating_mul(1024 * 1024);
        etl_bytes.saturating_add(1024 * 1024) >= cap
    }

    /// Marker written before `pktmon start` (crash recovery).
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct Marker {
        pub etl: String,
        pub work_dir: String,
        pub started_at: i64,
        pub filters: Vec<String>,
    }
}

#[cfg(test)]
mod tests {
    use super::pktmon::*;
    use super::*;
    use kestrel_common::evidence::{PcapFilter, PCAP_MAX_FILTERS};
    use kestrel_common::NetProto;

    const DEV: &str = r"\Device\HarddiskVolume3";

    #[test]
    fn write_scope() {
        let s = WriteScope::new(DEV);
        for p in [
            r"\Device\HarddiskVolume3\Users\bob\AppData\Local\Temp\x.zip",
            r"\device\harddiskvolume3\users\bob\desktop\a.txt",
            r"\Device\HarddiskVolume3\ProgramData\stage\out.7z",
            r"\Device\HarddiskVolume3\Windows\Temp\dump.bin",
            r"\Device\HarddiskVolume3\Temp\a",
            r"\Device\HarddiskVolume3\tmp\b",
        ] {
            assert!(s.in_scope(p), "{p}");
        }
        for p in [
            r"\Device\HarddiskVolume3\ProgramData\Kestrel\evidence\x",
            r"\Device\HarddiskVolume3\ProgramData\Microsoft\Windows Defender\Scans\x",
            r"\Device\HarddiskVolume3\Windows\System32\x.dll",
            r"\Device\HarddiskVolume3\Program Files\x.exe",
            r"\Device\HarddiskVolume3\Users\",
            r"\Device\HarddiskVolume3\Users\bob\",
            r"\Device\HarddiskVolume3\Users\bob\a.zip:Zone.Identifier",
            r"\Device\HarddiskVolume4\Users\bob\a.zip",
            r"\Device\HarddiskVolume33\Users\bob\a.zip",
            r"\Device\HarddiskVolumeShadowCopy3\Users\bob\a.zip",
            r"\Device\Mup\server\share\Users\a",
            r"\Device\HarddiskVolume3",
            r"\Device\HarddiskVolume3\Temp\",
            r"\Device\HarddiskVolume3\Tempo\x",
            "",
        ] {
            assert!(!s.in_scope(p), "{p}");
        }
        // Unknown system device: nothing.
        assert!(!WriteScope::new("").in_scope(r"\Device\HarddiskVolume3\Users\bob\a"));
        // Non-ASCII paths do not panic.
        assert!(!s.in_scope("\\Device\\Hä"));
        assert!(s.in_scope("\\Device\\HarddiskVolume3\\Users\\bö\\ä.zip"));
    }

    #[test]
    fn write_ops() {
        use crate::consts::eid;
        let co = |disp: u32, opts: u32| (disp << 24) | opts;
        // H1: Kernel-File Create (12) is logged for failed opens too: never
        // a hint, whatever the disposition.
        for d in [0, 1, 2, 3, 4, 5, 6, 0xff] {
            assert_eq!(write_op(eid::FILE_CREATE, co(d, 0x60)), None);
        }
        // Directory creates never.
        assert_eq!(write_op(eid::FILE_CREATE_NEW, co(2, 0x21)), None);
        assert_eq!(
            write_op(eid::FILE_CREATE_NEW, co(3, 0x60)),
            Some(WriteOp::Created)
        );
        assert_eq!(write_op(eid::FILE_CREATE_NEW, 0), Some(WriteOp::Created));
        assert_eq!(write_op(eid::FILE_DELETE_PATH, co(2, 0)), None);
    }

    #[test]
    fn dedup() {
        let mut d = HintDedup::default();
        assert!(d.admit(10, "c:\\a".into(), 1_000));
        assert!(!d.admit(10, "c:\\a".into(), 1_500));
        assert!(d.admit(11, "c:\\a".into(), 1_500));
        assert!(d.admit(10, "c:\\b".into(), 1_500));
        assert!(d.admit(10, "c:\\a".into(), 2_000));
        // Bounded.
        for i in 0..40_000u32 {
            d.admit(i, format!("c:\\f{i}"), 10_000 + i as i64);
        }
        assert!(d.len() <= 16_384 + 1);
        // Bounded by bytes too (long paths, same timestamp window).
        let mut d = HintDedup::default();
        let long = "x".repeat(1000);
        for i in 0..10_000u32 {
            d.admit(i, format!("c:\\{long}{i}"), 5_000);
        }
        assert!(d.bytes() <= 4 * 1024 * 1024 + 2_000, "{}", d.bytes());
        assert_eq!(d.bytes(), d.seen.keys().map(|k| k.1.len()).sum::<usize>());
    }

    #[test]
    fn hint_path_length() {
        assert!(hint_path_len_ok(&"a".repeat(1024)));
        assert!(!hint_path_len_ok(&"a".repeat(1025)));
        // 3-byte UTF-8 characters are one UTF-16 unit each.
        assert!(hint_path_len_ok(&"€".repeat(1024)));
        assert!(!hint_path_len_ok(&"€".repeat(1025)));
        // 4-byte characters are two units.
        assert!(hint_path_len_ok(&"😀".repeat(512)));
        assert!(!hint_path_len_ok(&"😀".repeat(513)));
    }

    #[test]
    fn ntstatus_and_reparse() {
        assert_eq!(classify_ntstatus(0x108), SourceError::Locked);
        assert_eq!(classify_ntstatus(0xC000_0034), SourceError::NotFound);
        assert_eq!(classify_ntstatus(0xC000_003A), SourceError::NotFound);
        assert_eq!(classify_ntstatus(0xC000_0043), SourceError::Locked);
        assert_eq!(classify_ntstatus(0xC000_0054), SourceError::Locked);
        assert_eq!(classify_ntstatus(0xC000_00BA), SourceError::NotAFile);
        assert!(matches!(
            classify_ntstatus(0xC000_0022),
            SourceError::Other(_)
        ));
        assert!(matches!(
            classify_ntstatus(0xC000_000D),
            SourceError::Other(_)
        ));
        // Junction, symlink.
        for t in [0xA000_0003u32, 0xA000_000C] {
            assert!(matches!(
                reparse_action(t),
                ReparseAction::Refuse(SourceError::Link(_))
            ));
        }
        // IO_REPARSE_TAG_CLOUD and CLOUD_1..F.
        for t in [0x9000_001Au32, 0x9000_101A, 0x9000_F01A] {
            assert_eq!(
                reparse_action(t),
                ReparseAction::Refuse(SourceError::Other(
                    "cloud placeholder not downloaded; not collected".into()
                ))
            );
        }
        assert_eq!(reparse_action(0x8000_0013), ReparseAction::ReopenDedup);
        // WOF, AppExecLink, anything else.
        for t in [0x8000_0017u32, 0x8000_001B, 0x0000_0001] {
            assert!(matches!(
                reparse_action(t),
                ReparseAction::Refuse(SourceError::Other(_))
            ));
        }
        assert_eq!(nt_object_path(r"C:\Users\a"), r"\??\C:\Users\a");
    }

    #[test]
    fn source_paths() {
        assert_eq!(
            check_source_path(r"C:\Users\bob\a.zip").unwrap(),
            r"C:\Users\bob\a.zip"
        );
        assert_eq!(
            check_source_path("C:/Users/bob/a.zip").unwrap(),
            r"C:\Users\bob\a.zip"
        );
        assert!(matches!(
            check_source_path(r"C:\Users\bob\a.zip:secret"),
            Err(SourceError::Link(_))
        ));
        assert!(matches!(
            check_source_path(r"C:\Users\bob\a.zip::$DATA"),
            Err(SourceError::Link(_))
        ));
        for p in [
            r"\\server\share\a",
            r"\\?\C:\Users\a",
            r"\\.\PhysicalDrive0",
            r"\??\C:\a",
            r"\Device\HarddiskVolume3\a",
            r"C:\Users\bob\",
        ] {
            assert_eq!(check_source_path(p), Err(SourceError::NotAFile), "{p}");
        }
        for p in [
            "",
            "a.txt",
            r"C:a.txt",
            r"1:\a",
            r"C:\Users\..\Windows\x",
            r"C:\Users\.\x",
            r"C:\Users\\x",
            r"C:\Users\*.txt",
            "C:\\Users\\a\0b",
            "C:\\Users\\a\nb",
        ] {
            assert!(
                matches!(check_source_path(p), Err(SourceError::Other(_))),
                "{p:?}"
            );
        }
    }

    #[test]
    fn os_errors() {
        assert_eq!(classify_os_error(Some(2)), Some(SourceError::NotFound));
        assert_eq!(classify_os_error(Some(3)), Some(SourceError::NotFound));
        assert_eq!(classify_os_error(Some(32)), Some(SourceError::Locked));
        assert_eq!(classify_os_error(Some(33)), Some(SourceError::Locked));
        assert!(matches!(
            classify_os_error(Some(5)),
            Some(SourceError::Other(_))
        ));
        assert_eq!(classify_os_error(Some(87)), None);
        assert_eq!(classify_os_error(None), None);
    }

    #[test]
    fn prefixes_and_build() {
        let p = own_prefixes(&[
            r"C:\ProgramData\Kestrel\".into(),
            r"\\?\C:\Program Files\Kestrel".into(),
            r"c:\programdata\kestrel".into(),
            "".into(),
        ]);
        assert_eq!(
            p,
            vec![
                r"c:\programdata\kestrel".to_string(),
                r"c:\program files\kestrel".to_string()
            ]
        );
        assert_eq!(os_build("10.0.19045.1234"), Some(19045));
        assert_eq!(os_build("10.0.17763"), Some(17763));
        assert_eq!(os_build("10.0"), None);
        assert_eq!(os_build("x.y.z"), None);
    }

    fn pf(ip: &str, port: Option<u16>, proto: Option<NetProto>) -> PcapFilter {
        PcapFilter {
            ip: ip.into(),
            port,
            proto,
        }
    }

    #[test]
    fn filter_command_lines() {
        let (p, dropped) = plan_filters(&[
            pf("203.0.113.7", Some(443), Some(NetProto::Tcp)),
            pf("198.51.100.9", Some(53), Some(NetProto::Udp)),
            pf("2001:db8::5", Some(8443), Some(NetProto::Tcp)),
            pf("192.0.2.1", None, None),
            pf("192.0.2.2", Some(80), None),
            pf("::ffff:192.0.2.3", None, Some(NetProto::Tcp)),
            pf("2001:DB8:0:0::5", Some(8443), Some(NetProto::Tcp)), // duplicate after normalising
        ]);
        assert_eq!(dropped, 0);
        let lines: Vec<String> = p.iter().map(|f| f.args.join(" ")).collect();
        assert_eq!(
            lines,
            vec![
                "filter add KestrelEv01 -t TCP -i 203.0.113.7 -p 443",
                "filter add KestrelEv02 -t UDP -i 198.51.100.9 -p 53",
                "filter add KestrelEv03 -t TCP -i 2001:db8::5 -p 8443",
                "filter add KestrelEv04 -i 192.0.2.1",
                "filter add KestrelEv05 -i 192.0.2.2 -p 80",
                "filter add KestrelEv06 -t TCP -i 192.0.2.3",
            ]
        );
        assert_eq!(p[2].filter.ip, "2001:db8::5");
    }

    #[test]
    fn injection_is_refused() {
        let evil = [
            "1.2.3.4 & calc",
            "--file-name",
            "1.2.3.4\" x",
            "1.2.3.4 -p 1",
            "example.com",
            "localhost",
            "",
            " 1.2.3.4",
            "1.2.3.4\n",
            "1.2.3.4/24",
            "1.2.3.4;calc",
            "-i",
            "0.0.0.0",
            "127.0.0.1",
            "::1",
            "::",
            "224.0.0.1",
            "255.255.255.255",
            "169.254.1.1",
            "fe80::1",
            "ff02::1",
        ];
        let filters: Vec<PcapFilter> = evil
            .iter()
            .map(|ip| pf(ip, Some(443), Some(NetProto::Tcp)))
            .chain([pf("203.0.113.7", Some(0), None)])
            .collect();
        let (p, dropped) = plan_filters(&filters);
        assert!(p.is_empty(), "{p:?}");
        assert_eq!(dropped, filters.len());
        // Mixed: only the valid one survives, and no argument of any
        // command line carries anything but our tokens.
        let (p, _) = plan_filters(&[
            pf("1.2.3.4 & calc", Some(443), None),
            pf("203.0.113.9", Some(443), Some(NetProto::Tcp)),
        ]);
        assert_eq!(p.len(), 1);
        for a in &p[0].args {
            assert!(
                matches!(a.as_str(), "-t" | "-i" | "-p")
                    || a.chars()
                        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':')),
                "{a}"
            );
        }
        assert_eq!(
            p[0].args.join(" "),
            "filter add KestrelEv01 -t TCP -i 203.0.113.9 -p 443"
        );
    }

    #[test]
    fn filter_cap() {
        let many: Vec<PcapFilter> = (1..=40u8)
            .map(|i| pf(&format!("203.0.113.{i}"), Some(443), Some(NetProto::Tcp)))
            .collect();
        let (p, dropped) = plan_filters(&many);
        assert_eq!(p.len(), PCAP_MAX_FILTERS);
        assert_eq!(dropped, 40 - PCAP_MAX_FILTERS);
        assert_eq!(p[0].name, "KestrelEv01");
        assert_eq!(p[15].name, "KestrelEv16");
        assert_eq!(p[0].filter.ip, "203.0.113.1");
        assert!(p.iter().all(|f| is_our_filter_name(&f.name)));
    }

    #[test]
    fn names() {
        assert!(is_our_filter_name("KestrelEv01"));
        assert!(is_our_filter_name("KestrelEv16"));
        assert!(!is_our_filter_name("KestrelEv1"));
        assert!(!is_our_filter_name("KestrelEv001"));
        assert!(!is_our_filter_name("kestrelev01"));
        assert!(!is_our_filter_name("MyPing"));
    }

    #[test]
    fn work_paths() {
        let p = paths(r"C:\ProgramData\Kestrel\evidence\work\b-1234").unwrap();
        assert_eq!(p.work_dir, r"C:\ProgramData\Kestrel\evidence\work\b-1234");
        assert_eq!(p.work_root, r"C:\ProgramData\Kestrel\evidence\work");
        assert_eq!(
            p.etl,
            r"C:\ProgramData\Kestrel\evidence\work\b-1234\capture.etl"
        );
        assert_eq!(
            p.pcapng,
            r"C:\ProgramData\Kestrel\evidence\work\b-1234\capture.pcapng"
        );
        assert_eq!(
            p.marker,
            r"C:\ProgramData\Kestrel\evidence\work\pktmon-active.json"
        );
        // Trailing separator.
        assert_eq!(
            paths(r"C:\ProgramData\Kestrel\evidence\w\")
                .unwrap()
                .work_dir,
            r"C:\ProgramData\Kestrel\evidence\w"
        );
        for bad in [
            "",
            "relative\\dir",
            r"\\server\share\x",
            r"\\?\C:\x\y",
            r"C:\",
            r"C:\x",
            r"C:\x\..\y",
            r"C:\x\y:z",
            "C:\\x\\y\" --file-name",
            r"C:\x\ -s",
            "C:/x/y",
            "--file-name",
        ] {
            assert!(paths(bad).is_err(), "{bad}");
        }
        let a = start_args(&p.etl, file_size_mb(50 * 1024 * 1024));
        assert_eq!(
            a.join(" "),
            r"start --capture --comp nics --pkt-size 0 --file-name C:\ProgramData\Kestrel\evidence\work\b-1234\capture.etl --file-size 50 --log-mode circular"
        );
        assert_eq!(
            etl2pcap_args(&p.etl, &p.pcapng).join(" "),
            r"etl2pcap C:\ProgramData\Kestrel\evidence\work\b-1234\capture.etl --out C:\ProgramData\Kestrel\evidence\work\b-1234\capture.pcapng"
        );
        assert_eq!(stop_args(), vec!["stop"]);
        assert_eq!(filter_remove_args(), vec!["filter", "remove"]);
        assert_eq!(filter_list_args(), vec!["filter", "list"]);
        assert_eq!(status_args(), vec!["status"]);
        assert_eq!(file_size_mb(0), 1);
        assert_eq!(file_size_mb(10 << 40), MAX_FILE_SIZE_MB);
    }

    /// `pktmon status` while a capture runs ([S12] in the research notes).
    const STATUS_RUNNING_FOREIGN: &str = "Collected Data: Packet counters, packet capture
Capture Type: All packets
Monitored Components: All
Packet Filters: None
Logger name: PktMon
Logging mode: Circular
Log file: C:\\Users\\Administrator\\pga_1.etl
Max file size: 512 MB
Memory used: 64 MB
Events lost: 0
";

    const STATUS_RUNNING_OURS: &str = "Collected Data: Packet counters, packet capture
Capture Type: All packets
Monitored Components: NICs
Packet Filters: 2
Logger name: PktMon
Logging mode: Circular
Log file: C:\\ProgramData\\Kestrel\\evidence\\work\\b-1\\capture_1.etl
Max file size: 50 MB
Memory used: 8 MB
Events lost: 3
";

    /// The idle text is not documented (lab check); assumed wording.
    const STATUS_IDLE: &str = "Packet Monitor is not running.\r\n";

    const FILTERS_FOREIGN: &str = " # Name        EtherType Protocol IP Address    Port
 - ----        --------- -------- ----------    ----
 1 MyPing      IPv4      ICMP     10.10.10.10
 2 MySmbSyn    *         TCP-SYN  10.10.10.10   445
";

    const FILTERS_OURS: &str = " # Name         EtherType Protocol IP Address    Port
 - ----         --------- -------- ----------    ----
 1 KestrelEv01  *         TCP      203.0.113.7   443
 2 KestrelEv02  *         UDP      198.51.100.9  53
";

    const FILTERS_UNNAMED: &str = " # Name EtherType Protocol IP Address Port
 - ---- --------- -------- ---------- ----
 1      *         TCP      10.0.0.1   445
";

    #[test]
    fn status_parsing() {
        let s = parse_status(STATUS_RUNNING_FOREIGN);
        assert!(s.running);
        assert_eq!(
            s.log_file.as_deref(),
            Some(r"C:\Users\Administrator\pga_1.etl")
        );
        assert_eq!(s.events_lost, Some(0));
        let s = parse_status(STATUS_RUNNING_OURS);
        assert!(s.running);
        assert_eq!(s.events_lost, Some(3));
        let s = parse_status(STATUS_IDLE);
        assert_eq!(s, Status::default());
        assert_eq!(parse_status(""), Status::default());
        // CRLF output.
        let s = parse_status(&STATUS_RUNNING_FOREIGN.replace('\n', "\r\n"));
        assert_eq!(
            s.log_file.as_deref(),
            Some(r"C:\Users\Administrator\pga_1.etl")
        );
    }

    #[test]
    fn filter_list_parsing() {
        let l = parse_filter_list(FILTERS_FOREIGN);
        assert_eq!(l.foreign, 2);
        assert!(l.ours.is_empty());
        let l = parse_filter_list(FILTERS_OURS);
        assert_eq!(l.ours, vec!["KestrelEv01", "KestrelEv02"]);
        assert_eq!(l.foreign, 0);
        let l = parse_filter_list(FILTERS_UNNAMED);
        assert_eq!(l.foreign, 1);
        assert!(parse_filter_list("There are no packet filters.\r\n").is_empty());
        assert!(parse_filter_list("").is_empty());
    }

    #[test]
    fn busy_decisions() {
        let idle = parse_status(STATUS_IDLE);
        let none = parse_filter_list("");
        assert_eq!(
            assess_start(&idle, &none),
            StartCheck::Go { remove_ours: false }
        );
        assert_eq!(
            assess_start(&idle, &parse_filter_list(FILTERS_OURS)),
            StartCheck::Go { remove_ours: true }
        );
        assert!(matches!(
            assess_start(&idle, &parse_filter_list(FILTERS_FOREIGN)),
            StartCheck::Busy(_)
        ));
        assert!(matches!(
            assess_start(&idle, &parse_filter_list(FILTERS_UNNAMED)),
            StartCheck::Busy(_)
        ));
        // Any running session is busy, ours included (never two captures).
        assert!(matches!(
            assess_start(&parse_status(STATUS_RUNNING_FOREIGN), &none),
            StartCheck::Busy(_)
        ));
        assert!(matches!(
            assess_start(&parse_status(STATUS_RUNNING_OURS), &none),
            StartCheck::Busy(_)
        ));
    }

    #[test]
    fn cleanup_decisions() {
        let root = r"C:\ProgramData\Kestrel\evidence\work";
        let ours = parse_status(STATUS_RUNNING_OURS);
        let foreign = parse_status(STATUS_RUNNING_FOREIGN);
        let idle = parse_status(STATUS_IDLE);
        let fo = parse_filter_list(FILTERS_OURS);
        let ff = parse_filter_list(FILTERS_FOREIGN);
        let none = parse_filter_list("");
        // No marker: never touch anything.
        assert_eq!(
            assess_cleanup(false, &ours, &fo, root),
            CleanupPlan::default()
        );
        assert_eq!(
            assess_cleanup(true, &ours, &fo, root),
            CleanupPlan {
                stop: true,
                remove_filters: true
            }
        );
        // Someone else's capture: leave it and the filters alone.
        assert_eq!(
            assess_cleanup(true, &foreign, &fo, root),
            CleanupPlan::default()
        );
        // Not running: only our filters.
        assert_eq!(
            assess_cleanup(true, &idle, &fo, root),
            CleanupPlan {
                stop: false,
                remove_filters: true
            }
        );
        assert_eq!(
            assess_cleanup(true, &idle, &ff, root),
            CleanupPlan::default()
        );
        assert_eq!(
            assess_cleanup(true, &idle, &none, root),
            CleanupPlan::default()
        );
        // A log file in a folder that only shares the prefix is not ours.
        let mut lookalike = ours.clone();
        lookalike.log_file = Some(r"C:\ProgramData\Kestrel\evidence\work2\x.etl".into());
        assert!(!assess_cleanup(true, &lookalike, &fo, root).stop);
    }

    #[test]
    fn inside_and_cap() {
        assert!(path_inside(r"C:\a\b\c.etl", r"c:\A\b"));
        assert!(path_inside(r"\\?\C:\a\b\c.etl", r"C:\a\b\"));
        assert!(!path_inside(r"C:\a\bc\c.etl", r"C:\a\b"));
        assert!(!path_inside(r"C:\a\b", r"C:\a\b"));
        assert!(!path_inside(r"C:\a\b\c", ""));
        assert!(etl_reached_cap(50 * 1024 * 1024, 50));
        assert!(etl_reached_cap(49 * 1024 * 1024 + 1, 50));
        assert!(!etl_reached_cap(10 * 1024 * 1024, 50));
    }

    #[test]
    fn halt_decisions() {
        let wd = r"C:\ProgramData\Kestrel\evidence\work\b-1";
        let ours = parse_status(STATUS_RUNNING_OURS);
        let foreign = parse_status(STATUS_RUNNING_FOREIGN);
        let idle = parse_status(STATUS_IDLE);
        // L6: a failed status is unknown → nothing stopped / removed.
        let h = assess_halt(None, wd);
        assert!(!h.stop && !h.remove_filters && h.keep_marker && !h.convert);
        let h = assess_halt(Some(&foreign), wd);
        assert!(!h.stop && !h.remove_filters && h.keep_marker && !h.convert);
        let h = assess_halt(Some(&ours), wd);
        assert!(h.stop && h.remove_filters && !h.keep_marker && h.convert);
        let h = assess_halt(Some(&idle), wd);
        assert!(!h.stop && h.remove_filters && !h.keep_marker && h.convert);
        // Another bundle's folder is not ours.
        let h = assess_halt(Some(&ours), r"C:\ProgramData\Kestrel\evidence\work\b-2");
        assert!(!h.stop);
    }

    #[test]
    fn pcapng_cap() {
        use kestrel_common::evidence::{PCAP_MAX_BYTES, PCAP_SLACK_BYTES};
        assert!(pcapng_size_ok(
            PCAP_MAX_BYTES + PCAP_SLACK_BYTES,
            PCAP_MAX_BYTES
        ));
        assert!(!pcapng_size_ok(
            PCAP_MAX_BYTES + PCAP_SLACK_BYTES + 1,
            PCAP_MAX_BYTES
        ));
        // A larger cap passed in never raises the limit.
        assert!(!pcapng_size_ok(PCAP_MAX_BYTES * 2, PCAP_MAX_BYTES * 4));
        assert!(!pcapng_size_ok(20 << 20, 10 << 20));
    }

    #[test]
    fn marker_roundtrip() {
        let m = Marker {
            etl: r"C:\x\y\capture.etl".into(),
            work_dir: r"C:\x\y".into(),
            started_at: 5,
            filters: vec!["KestrelEv01".into()],
        };
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(serde_json::from_str::<Marker>(&j).unwrap(), m);
    }
}
