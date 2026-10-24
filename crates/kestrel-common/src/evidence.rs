//! Evidence capture for suspected data theft (owner decision 2026-10-25,
//! `docs/DECISIONS.md`).
//!
//! When ST-02 or ST-04 fires (any mode, Audit included) the agent builds an
//! **evidence bundle** for the alerting process tree and keeps it, encrypted,
//! on the PC:
//!
//! 1. **staged files**: files the tree created / wrote under user-writable
//!    locations from [`LOOKBACK_MS`] before the alert until [`FOLLOW_MS`]
//!    after it (copies; originals untouched);
//! 2. **secrets list**: every credential-store file the tree opened (metadata);
//! 3. **secrets copy**: copies of those store files as they are at capture time;
//! 4. **connection capture**: a pcapng of the tree's connections for
//!    [`PCAP_SECONDS`] after the alert (remote IP / port filters).
//!
//! Nothing is uploaded automatically. The server only receives an
//! [`EvidenceReport`] (state + privacy-filtered [`EvidenceManifest`], i.e.
//! metadata). An administrator may collect the bundle
//! (`ResponseAction::CollectEvidence`); the server then pulls it over the live
//! channel ([`crate::remote::LiveServerMsg::EvidenceRead`]), stores it
//! encrypted and offers it as a password-protected AES-256 zip. Evidence never
//! goes into telemetry, ClickHouse or hunt.
//!
//! The bundle itself is a [`container`] stream (`KEB1`): every file entry,
//! then `manifest.json` last.

use crate::{event::NetProto, DataCategory, ProcessGuid, TimestampMs};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `Hello.capabilities` entry of agents that capture evidence and answer
/// `LiveServerMsg::EvidenceRead`, `ResponseAction::CollectEvidence` and
/// `ResponseAction::DeleteEvidence`.
pub const CAP_EVIDENCE: &str = "evidence.v1";

/// Rules whose alerts start an evidence capture (any mode).
pub const TRIGGER_RULES: &[&str] = &["ST-02", "ST-04"];

/// Does an alert of `rule_id` start an evidence capture?
pub fn is_trigger_rule(rule_id: &str) -> bool {
    TRIGGER_RULES.contains(&rule_id)
}

/// Writes / store reads this long before the alert are included.
pub const LOOKBACK_MS: i64 = 120_000;
/// The capture keeps following the tree this long after the alert.
pub const FOLLOW_MS: i64 = 60_000;
/// A second trigger alert for a tree already being captured within this time
/// joins the running capture instead of starting a new bundle.
pub const MERGE_MS: i64 = 10 * 60_000;

/// Largest staged file copied (bigger files are listed, not copied).
pub const MAX_STAGED_FILE_BYTES: u64 = 50 * 1024 * 1024;
/// Sum of staged file copies per bundle.
pub const MAX_STAGED_BYTES: u64 = 200 * 1024 * 1024;
/// Staged files listed (and at most copied) per bundle.
pub const MAX_STAGED_FILES: usize = 500;
/// Largest credential-store file copied.
pub const MAX_SECRET_FILE_BYTES: u64 = 50 * 1024 * 1024;
/// Sum of credential-store copies per bundle.
pub const MAX_SECRET_BYTES: u64 = 100 * 1024 * 1024;
/// Credential-store files listed per bundle.
pub const MAX_SECRETS: usize = 200;
/// Connection capture length.
pub const PCAP_SECONDS: u32 = 60;
/// Connection capture size cap (the capture stops growing at this size).
pub const PCAP_MAX_BYTES: u64 = 50 * 1024 * 1024;
/// Remote IP / port filters per capture (most recent tuples first).
pub const PCAP_MAX_FILTERS: usize = 16;
/// Processes in one evidence tree.
pub const MAX_TREE_PROCESSES: usize = 64;
/// Skipped files listed in the manifest (beyond that only counted).
pub const MAX_SKIPPED_LISTED: usize = 200;

/// Hard cap on a whole bundle (container bytes), checked by agent and server.
pub const MAX_BUNDLE_BYTES: u64 =
    MAX_STAGED_BYTES + MAX_SECRET_BYTES + PCAP_MAX_BYTES + PCAP_SLACK_BYTES + (16 << 20);
/// A pcapng may exceed [`PCAP_MAX_BYTES`] by this much (pktmon's circular
/// ETL cap is approximate, and pcapng framing differs from ETL); larger
/// captures are discarded by the platform.
pub const PCAP_SLACK_BYTES: u64 = 8 * 1024 * 1024;
/// Largest single container entry (any file cap plus slack for the pcap).
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024;
/// Largest `manifest.json` entry.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
/// Entries per container (staged + secrets + pcap + manifest, with slack).
pub const MAX_ENTRIES: usize = MAX_STAGED_FILES + MAX_SECRETS + 16;
/// Bytes per `EvidenceRead` chunk (same as remote file downloads).
pub const READ_CHUNK_MAX: u32 = 512 * 1024;
/// Default days a bundle is kept (on the PC when not collected; on the
/// server after collection, `Settings.retention_days.evidence`).
pub const DEFAULT_RETENTION_DAYS: u32 = 14;
/// Allowed retention range (days), PC and server.
pub const MAX_RETENTION_DAYS: u32 = 365;

/// Text of the tray notification shown when IT collects a bundle.
pub const TRAY_COLLECTED_TITLE: &str =
    "IT collected evidence from this PC for a security investigation";
/// Body of that notification.
pub const TRAY_COLLECTED_BODY: &str = "After a security alert, Kestrel kept copies of files and connection data related to the suspicious app. Your IT team has now collected them. The copies are encrypted, only administrators can open them, and they are deleted automatically.";

fn yes() -> bool {
    true
}
fn default_retention() -> u32 {
    DEFAULT_RETENTION_DAYS
}

/// `Policy.evidence`: which parts of an evidence capture run. Policies saved
/// before this field existed get the defaults (all on, owner decision).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct EvidencePolicy {
    /// Copy staged files (archives, password dumps, screenshots) the tree wrote.
    #[serde(default = "yes")]
    pub staged_files: bool,
    /// List the credential-store files the tree opened (metadata only).
    #[serde(default = "yes")]
    pub secrets_list: bool,
    /// Copy those credential-store files (needs `secrets_list`).
    #[serde(default = "yes")]
    pub secrets_copy: bool,
    /// Capture the tree's connections for 60 s as pcapng.
    #[serde(default = "yes")]
    pub pcap: bool,
    /// Days an uncollected bundle stays on the PC (1-365, default 14).
    #[serde(default = "default_retention")]
    pub local_retention_days: u32,
}

impl Default for EvidencePolicy {
    fn default() -> Self {
        EvidencePolicy {
            staged_files: true,
            secrets_list: true,
            secrets_copy: true,
            pcap: true,
            local_retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

impl EvidencePolicy {
    /// Everything off.
    pub fn off() -> Self {
        EvidencePolicy {
            staged_files: false,
            secrets_list: false,
            secrets_copy: false,
            pcap: false,
            local_retention_days: DEFAULT_RETENTION_DAYS,
        }
    }

    /// Does any part run (else no capture starts at all)?
    pub fn any(&self) -> bool {
        self.staged_files || self.secrets_list || self.secrets_copy || self.pcap
    }

    /// Effective secrets copy (a copy implies the list).
    pub fn copies_secrets(&self) -> bool {
        self.secrets_copy && self.secrets_list
    }

    /// Retention clamped to 1..=365 days.
    pub fn retention_days(&self) -> u32 {
        self.local_retention_days.clamp(1, MAX_RETENTION_DAYS)
    }

    /// Server-side validation for `PUT /policies/:id`.
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_RETENTION_DAYS).contains(&self.local_retention_days) {
            return Err(format!(
                "evidence.local_retention_days must be 1-{MAX_RETENTION_DAYS}"
            ));
        }
        Ok(())
    }
}

/// How a staged file was written.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum WriteOp {
    /// Newly created.
    Created,
    /// Existing file opened for overwrite / supersede.
    Overwritten,
    /// Renamed into place.
    Renamed,
    /// Written, how unknown (e.g. a `file_activity` sample path).
    #[default]
    Written,
}

/// Role of a process in the evidence tree.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRole {
    /// The process the trigger alert is about.
    #[default]
    Alerting,
    /// A child / grandchild of it.
    Descendant,
    /// A parent outside Windows / Program Files (loader, dropper).
    Ancestor,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct EvidenceProcess {
    pub guid: ProcessGuid,
    pub pid: u32,
    pub image: String,
    #[serde(default)]
    pub start_ts: TimestampMs,
    #[serde(default)]
    pub role: ProcessRole,
}

/// What happened to one file copy.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CopyStatus {
    /// Copied completely.
    Copied,
    /// The file grew past the per-file cap while it was copied; the first
    /// cap bytes are in the bundle.
    Truncated,
    /// Bigger than the per-file cap; listed, not copied.
    TooLarge,
    /// The bundle's byte or file cap was reached.
    BundleFull,
    /// A junction / symbolic link / hard-linked file / reparse redirect, or
    /// an alternate data stream: never followed.
    Link,
    /// Open by another program without read sharing (e.g. a browser's
    /// locked SQLite database): "locked, not copied".
    Locked,
    /// Gone (deleted or renamed away) before the capture copied it.
    Missing,
    /// Inside a Kestrel folder (install / state): never collected.
    Kestrel,
    /// Not a regular file (a folder, a device path).
    NotAFile,
    /// Access refused or another error (see `detail`).
    Error,
    /// This part of the capture is turned off by policy.
    #[default]
    Disabled,
}

impl CopyStatus {
    /// Bytes of the file are in the bundle.
    pub fn has_data(&self) -> bool {
        matches!(self, CopyStatus::Copied | CopyStatus::Truncated)
    }
}

/// One file copy (staged file or credential store).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct FileCopy {
    pub status: CopyStatus,
    /// Container entry name (`staged/0001-name.zip`) when `status.has_data()`.
    #[serde(default)]
    pub entry: Option<String>,
    /// Bytes copied (or the size on disk when not copied, if known).
    #[serde(default)]
    pub size: u64,
    /// SHA-256 (hex) of the bytes copied.
    #[serde(default)]
    pub sha256: Option<String>,
    /// Short reason (errors), never file content.
    #[serde(default)]
    pub detail: String,
}

/// A file the tree created / wrote during the window.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct StagedFile {
    /// Win32 path as written.
    pub path: String,
    /// Last write seen in the window.
    pub written_at: TimestampMs,
    #[serde(default)]
    pub op: WriteOp,
    /// Writer process.
    pub process_guid: ProcessGuid,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub copy: FileCopy,
}

/// A credential-store file the tree opened.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SecretRead {
    pub path: String,
    /// Application / store label, e.g. "Chrome", "MetaMask".
    pub store: String,
    /// What the file holds, e.g. "saved passwords", "cookies".
    pub noun: String,
    pub category: DataCategory,
    pub first_read: TimestampMs,
    pub last_read: TimestampMs,
    /// Opens / reads seen (de-duplicated by the sensor per second).
    pub open_count: u32,
    /// Reader process (the first one seen).
    pub process_guid: ProcessGuid,
    #[serde(default)]
    pub image: String,
    /// Size on disk at capture time, when it could be read.
    #[serde(default)]
    pub size: Option<u64>,
    /// The copy, when `secrets_copy` is on (`None` = list only).
    #[serde(default)]
    pub copy: Option<FileCopy>,
}

/// One packet filter of the connection capture: traffic to / from `ip`
/// (and `port` / `proto` when set), in both directions.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PcapFilter {
    /// Remote IP (validated `IpAddr` text, never a host name).
    pub ip: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub proto: Option<NetProto>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum PcapStatus {
    /// Captured for the whole window (or until the size cap).
    Captured,
    /// The agent stopped during the capture; what was captured is kept.
    Stopped,
    /// The tree made no connections Kestrel saw: nothing to filter on.
    NoConnections,
    /// Another packet capture (pktmon) was already running on the PC;
    /// Kestrel never takes over someone else's capture.
    Busy,
    /// Not available on this Windows version / platform.
    Unsupported,
    /// Capture or conversion failed (see `detail`).
    Failed,
    /// Turned off by policy.
    #[default]
    Disabled,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct PcapInfo {
    pub status: PcapStatus,
    /// Capture mechanism (`pktmon`).
    #[serde(default)]
    pub mechanism: String,
    /// Filters used (the capture matches these remote IP / port tuples for
    /// every program on the PC: traffic of other apps to the same shared
    /// IP:port, e.g. a CDN, is included too).
    #[serde(default)]
    pub filters: Vec<PcapFilter>,
    #[serde(default)]
    pub started_at: Option<TimestampMs>,
    #[serde(default)]
    pub ended_at: Option<TimestampMs>,
    /// pcapng size in the bundle.
    #[serde(default)]
    pub bytes: u64,
    /// The capture reached [`PCAP_MAX_BYTES`].
    #[serde(default)]
    pub truncated: bool,
    /// Container entry (`capture.pcapng`) when there is data.
    #[serde(default)]
    pub entry: Option<String>,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(default)]
    pub detail: String,
}

/// File skipped before any copy was attempted (outside the scope, beyond the
/// listing caps) is only counted; these are the ones listed.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct EvidenceTotals {
    #[serde(default)]
    pub staged_listed: u32,
    #[serde(default)]
    pub staged_copied: u32,
    #[serde(default)]
    pub staged_bytes: u64,
    /// Candidates beyond [`MAX_STAGED_FILES`] (not listed).
    #[serde(default)]
    pub staged_unlisted: u32,
    #[serde(default)]
    pub secrets_listed: u32,
    #[serde(default)]
    pub secrets_copied: u32,
    #[serde(default)]
    pub secret_bytes: u64,
    #[serde(default)]
    pub pcap_bytes: u64,
    /// Sum of every data entry (excluding the manifest).
    #[serde(default)]
    pub data_bytes: u64,
}

/// `manifest.json` (last entry of the bundle) and, privacy-filtered, the
/// metadata the server shows on the incident.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EvidenceManifest {
    /// Manifest format (1).
    #[serde(default = "manifest_format")]
    pub format: u32,
    pub bundle_id: Uuid,
    /// First trigger alert.
    pub alert_id: Uuid,
    /// Every trigger alert merged into this capture (first included).
    #[serde(default)]
    pub alert_ids: Vec<Uuid>,
    pub rule_id: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub agent_version: String,
    /// Time of the first trigger alert.
    pub started_at: TimestampMs,
    /// `started_at - LOOKBACK_MS`.
    pub window_start: TimestampMs,
    /// End of the follow-up (normally `started_at + FOLLOW_MS`).
    pub window_end: TimestampMs,
    pub completed_at: TimestampMs,
    /// Parts that ran (the policy at capture time).
    pub parts: EvidencePolicy,
    #[serde(default)]
    pub processes: Vec<EvidenceProcess>,
    #[serde(default)]
    pub staged: Vec<StagedFile>,
    #[serde(default)]
    pub secrets: Vec<SecretRead>,
    #[serde(default)]
    pub pcap: Option<PcapInfo>,
    #[serde(default)]
    pub totals: EvidenceTotals,
    /// Plain-language notes (limits hit, sensor gaps).
    #[serde(default)]
    pub notes: Vec<String>,
}

fn manifest_format() -> u32 {
    1
}

/// State of a bundle on the PC, as reported to the server.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceState {
    /// Capture running (follow-up window, connection capture).
    Capturing,
    /// Bundle complete and stored encrypted on the PC.
    Ready,
    /// The capture failed (see `detail`); nothing to collect.
    Failed,
    /// Deleted on the PC (after collection, or by an administrator).
    Deleted,
    /// Deleted on the PC because nobody collected it within the retention.
    Expired,
}

/// `AgentPayload::Evidence`: lifecycle of one bundle (outbox, durable).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EvidenceReport {
    pub bundle_id: Uuid,
    pub alert_id: Uuid,
    #[serde(default)]
    pub alert_ids: Vec<Uuid>,
    pub rule_id: String,
    pub state: EvidenceState,
    pub ts: TimestampMs,
    /// With `Ready`: the manifest, filtered by the device's privacy policy.
    #[serde(default)]
    pub manifest: Option<EvidenceManifest>,
    /// With `Ready`: container bytes and their SHA-256 (what an upload
    /// must deliver).
    #[serde(default)]
    pub bundle_size: u64,
    #[serde(default)]
    pub bundle_sha256: Option<String>,
    /// With `Ready`: when the PC deletes the bundle if nobody collects it.
    #[serde(default)]
    pub local_expires_at: Option<TimestampMs>,
    #[serde(default)]
    pub detail: String,
}

// ---------------------------------------------------------------- names

/// Is `name` a valid container entry name? `manifest.json`,
/// `capture.pcapng`, or `staged/<file>` / `secrets/<file>` where `<file>`
/// is 1-120 characters of `[A-Za-z0-9._-]`, not starting with `.` and not
/// containing `..`. Agents only write such names and the server refuses
/// any other (no traversal, no absolute paths, no drive letters, no ADS).
pub fn valid_entry_name(name: &str) -> bool {
    match name {
        "manifest.json" | "capture.pcapng" => return true,
        _ => {}
    }
    let Some((dir, file)) = name.split_once('/') else {
        return false;
    };
    if !matches!(dir, "staged" | "secrets") {
        return false;
    }
    // `NNNN-<name>` exactly as [`entry_name`] writes them: the numeric
    // prefix rules out Windows device names (`CON`, `NUL`, `COM1`), and a
    // trailing dot is refused (Windows strips it on extraction).
    let b = file.as_bytes();
    file.len() > 5
        && file.len() <= 120
        && b[..4].iter().all(u8::is_ascii_digit)
        && b[4] == b'-'
        && !file.ends_with('.')
        && !file.contains("..")
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Container entry name for the `index`-th file of `dir` (`staged` /
/// `secrets`) whose original Win32 path is `path`: `dir/NNNN-<sanitised
/// file name>` (characters outside `[A-Za-z0-9._-]` become `_`, at most
/// 100 of them kept, leading dots dropped). Always [`valid_entry_name`].
pub fn entry_name(dir: &str, index: usize, path: &str) -> String {
    let dir = if dir == "secrets" {
        "secrets"
    } else {
        "staged"
    };
    let base = path.rsplit(['\\', '/']).next().unwrap_or(path);
    // An alternate data stream suffix never reaches here (refused earlier),
    // but a ':' is mapped like any other character.
    let mut s: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    while s.contains("..") {
        s = s.replace("..", "._");
    }
    let s = s.trim_start_matches('.');
    let s: String = s.chars().take(100).collect();
    let s = s.trim_end_matches('.');
    let s = if s.is_empty() {
        "file".to_string()
    } else {
        s.to_string()
    };
    format!("{dir}/{:04}-{s}", index % 10_000)
}

/// Lower-case hex of a digest.
pub fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// SHA-256 (hex) of a slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex_lower(&Sha256::digest(data))
}

/// The file name of a Win32 or POSIX path (for logs: never the folder).
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

// ------------------------------------------------------------ container

/// `KEB1` evidence bundle container (pure, streaming, no compression).
///
/// ```text
/// "KEB1"
/// entry*:  0x01 | u16 BE name length | name (UTF-8, valid_entry_name)
///          | (u32 BE chunk length > 0 | chunk bytes)* | u32 0
/// end:     0x00
/// ```
/// `manifest.json` is the last entry. Readers enforce [`ContainerLimits`]
/// and refuse invalid names, duplicate names, oversize entries, trailing
/// bytes and a missing end marker.
pub mod container {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::io::{self, Read, Write};

    pub const MAGIC: &[u8; 4] = b"KEB1";
    const ENTRY: u8 = 1;
    const END: u8 = 0;
    /// Largest chunk a writer emits / a reader accepts.
    pub const MAX_CHUNK: u32 = 1 << 20;

    #[derive(Debug, Clone, Copy)]
    pub struct ContainerLimits {
        pub max_entries: usize,
        pub max_entry_bytes: u64,
        pub max_manifest_bytes: u64,
        pub max_total_bytes: u64,
    }

    impl Default for ContainerLimits {
        fn default() -> Self {
            ContainerLimits {
                max_entries: MAX_ENTRIES,
                max_entry_bytes: MAX_ENTRY_BYTES,
                max_manifest_bytes: MAX_MANIFEST_BYTES,
                max_total_bytes: MAX_BUNDLE_BYTES,
            }
        }
    }

    fn bad(m: impl Into<String>) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, m.into())
    }

    /// Streaming writer.
    pub struct ContainerWriter<W: Write> {
        w: W,
        names: std::collections::HashSet<String>,
        in_entry: bool,
        bytes: u64,
    }

    impl<W: Write> ContainerWriter<W> {
        pub fn new(mut w: W) -> io::Result<Self> {
            w.write_all(MAGIC)?;
            Ok(ContainerWriter {
                w,
                names: Default::default(),
                in_entry: false,
                bytes: 4,
            })
        }

        /// Container bytes written so far.
        pub fn bytes(&self) -> u64 {
            self.bytes
        }

        fn put(&mut self, b: &[u8]) -> io::Result<()> {
            self.w.write_all(b)?;
            self.bytes += b.len() as u64;
            Ok(())
        }

        /// Start an entry; then [`Self::write_data`] and [`Self::end_entry`].
        pub fn begin_entry(&mut self, name: &str) -> io::Result<()> {
            if self.in_entry {
                return Err(io::Error::other("previous entry not ended"));
            }
            if !valid_entry_name(name) {
                return Err(bad(format!("invalid entry name {name:?}")));
            }
            if !self.names.insert(name.to_ascii_lowercase()) {
                return Err(bad(format!("duplicate entry {name}")));
            }
            let n = name.as_bytes();
            self.put(&[ENTRY])?;
            self.put(&(n.len() as u16).to_be_bytes())?;
            self.put(n)?;
            self.in_entry = true;
            Ok(())
        }

        pub fn write_data(&mut self, mut data: &[u8]) -> io::Result<()> {
            if !self.in_entry {
                return Err(io::Error::other("no entry open"));
            }
            while !data.is_empty() {
                let n = data.len().min(MAX_CHUNK as usize);
                self.put(&(n as u32).to_be_bytes())?;
                self.put(&data[..n])?;
                data = &data[n..];
            }
            Ok(())
        }

        pub fn end_entry(&mut self) -> io::Result<()> {
            if !self.in_entry {
                return Err(io::Error::other("no entry open"));
            }
            self.put(&0u32.to_be_bytes())?;
            self.in_entry = false;
            Ok(())
        }

        /// Whole entry from a slice.
        pub fn entry(&mut self, name: &str, data: &[u8]) -> io::Result<()> {
            self.begin_entry(name)?;
            self.write_data(data)?;
            self.end_entry()
        }

        /// Copy at most `max` bytes of `r` into a new entry. Returns
        /// (bytes copied, SHA-256 hex of them, `true` when `r` had more).
        pub fn entry_from_reader(
            &mut self,
            name: &str,
            r: &mut dyn Read,
            max: u64,
        ) -> io::Result<(u64, String, bool)> {
            self.begin_entry(name)?;
            let mut h = Sha256::new();
            let mut buf = vec![0u8; 256 * 1024];
            let mut total = 0u64;
            let mut more = false;
            loop {
                let want = (max - total).min(buf.len() as u64) as usize;
                if want == 0 {
                    // At the cap: is there more?
                    let mut one = [0u8; 1];
                    more = loop {
                        match r.read(&mut one) {
                            Ok(n) => break n > 0,
                            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                            Err(e) => return Err(e),
                        }
                    };
                    break;
                }
                let n = match r.read(&mut buf[..want]) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                h.update(&buf[..n]);
                self.write_data(&buf[..n])?;
                total += n as u64;
            }
            self.end_entry()?;
            Ok((total, hex_lower(&h.finalize()), more))
        }

        /// Write the end marker and return the inner writer.
        pub fn finish(mut self) -> io::Result<W> {
            if self.in_entry {
                return Err(io::Error::other("entry not ended"));
            }
            self.put(&[END])?;
            self.w.flush()?;
            Ok(self.w)
        }
    }

    /// One entry while it is being read: a `Read` over its data.
    pub struct EntryReader<'a, R: Read> {
        r: &'a mut R,
        left_in_chunk: u32,
        done: bool,
        read: u64,
        max: u64,
    }

    impl<R: Read> EntryReader<'_, R> {
        fn next_chunk(&mut self) -> io::Result<()> {
            let mut l = [0u8; 4];
            self.r.read_exact(&mut l)?;
            let n = u32::from_be_bytes(l);
            if n == 0 {
                self.done = true;
            } else if n > MAX_CHUNK {
                return Err(bad("container chunk too large"));
            } else {
                self.left_in_chunk = n;
            }
            Ok(())
        }

        /// Bytes of this entry read so far.
        pub fn bytes_read(&self) -> u64 {
            self.read
        }
    }

    impl<R: Read> Read for EntryReader<'_, R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            while !self.done && self.left_in_chunk == 0 {
                self.next_chunk()?;
            }
            if self.done {
                return Ok(0);
            }
            let want = buf.len().min(self.left_in_chunk as usize);
            let n = self.r.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated container",
                ));
            }
            self.left_in_chunk -= n as u32;
            self.read += n as u64;
            if self.read > self.max {
                return Err(bad("container entry exceeds the size limit"));
            }
            Ok(n)
        }
    }

    /// Read a whole container, calling `on_entry(name, data)` for each entry
    /// (the callback may read the data partially; the rest is drained and
    /// still counted). Returns the entry names in order. Fails on any
    /// format violation or limit; a callback error aborts the read.
    pub fn read_container<R: Read>(
        mut r: R,
        limits: ContainerLimits,
        mut on_entry: impl FnMut(&str, &mut dyn Read) -> io::Result<()>,
    ) -> io::Result<Vec<String>> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|_| bad("not an evidence bundle"))?;
        if &magic != MAGIC {
            return Err(bad("not an evidence bundle"));
        }
        let mut names: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut total = 4u64;
        loop {
            let mut tag = [0u8; 1];
            r.read_exact(&mut tag)
                .map_err(|_| bad("container end marker missing"))?;
            match tag[0] {
                END => break,
                ENTRY => {}
                _ => return Err(bad("bad container record")),
            }
            if names.len() >= limits.max_entries {
                return Err(bad("too many container entries"));
            }
            let mut l = [0u8; 2];
            r.read_exact(&mut l)?;
            let len = u16::from_be_bytes(l) as usize;
            if len == 0 || len > 512 {
                return Err(bad("bad entry name length"));
            }
            let mut nb = vec![0u8; len];
            r.read_exact(&mut nb)?;
            let name = String::from_utf8(nb).map_err(|_| bad("entry name is not UTF-8"))?;
            if !valid_entry_name(&name) {
                return Err(bad(format!("invalid entry name {name:?}")));
            }
            // Case-insensitive: entries that differ only in case would overwrite
            // each other when extracted on Windows.
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(bad(format!("duplicate entry {name}")));
            }
            if names.iter().any(|n| n == "manifest.json") {
                return Err(bad("entries after manifest.json"));
            }
            let max = if name == "manifest.json" {
                limits.max_manifest_bytes
            } else {
                limits.max_entry_bytes
            };
            let mut er = EntryReader {
                r: &mut r,
                left_in_chunk: 0,
                done: false,
                read: 0,
                max,
            };
            on_entry(&name, &mut er)?;
            io::copy(&mut er, &mut io::sink())?;
            total += 3 + len as u64 + er.read;
            if total > limits.max_total_bytes {
                return Err(bad("evidence bundle exceeds the size limit"));
            }
            names.push(name);
        }
        let mut extra = [0u8; 1];
        loop {
            match r.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(bad("trailing bytes after the container end")),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if names.last().map(String::as_str) != Some("manifest.json") {
            return Err(bad("manifest.json missing (must be the last entry)"));
        }
        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::container::*;
    use super::*;

    #[test]
    fn policy_defaults_and_old_policies() {
        let p: EvidencePolicy = serde_json::from_str("{}").unwrap();
        assert_eq!(p, EvidencePolicy::default());
        assert!(p.any() && p.copies_secrets());
        assert_eq!(p.retention_days(), 14);
        let off = EvidencePolicy::off();
        assert!(!off.any());
        let mut q = EvidencePolicy {
            secrets_list: false,
            ..Default::default()
        };
        assert!(!q.copies_secrets());
        q.local_retention_days = 0;
        assert!(q.validate().is_err());
        q.local_retention_days = 366;
        assert!(q.validate().is_err());
        q.local_retention_days = 30;
        assert!(q.validate().is_ok());
        // A policy saved before the field: all parts on.
        let pol: crate::Policy =
            serde_json::from_str(r#"{"id":"d","name":"D","version":3}"#).unwrap();
        assert_eq!(pol.evidence, EvidencePolicy::default());
    }

    #[test]
    fn entry_names_are_safe() {
        for good in [
            "manifest.json",
            "capture.pcapng",
            "staged/0001-a.zip",
            "secrets/0002-Login_Data",
            "staged/9999-x",
        ] {
            assert!(valid_entry_name(good), "{good}");
        }
        for bad in [
            "",
            "manifest.json/",
            "../x",
            "staged/../x",
            "staged/..x",
            "staged/.hidden",
            "staged/a/b",
            "staged/",
            "other/a",
            "/staged/a",
            "staged\\a",
            "C:/x",
            "staged/a:b",
            "staged/a b",
            "secrets/\u{202e}exe.txt",
            "staged/CON",
            "staged/0001-a.",
            "staged/0001-",
            "staged/001-ab",
            "staged/abcd-x",
        ] {
            assert!(!valid_entry_name(bad), "{bad:?}");
        }
        let n = entry_name(
            "staged",
            1,
            r"C:\Users\a\AppData\Local\Temp\x\Passwords (1).txt",
        );
        assert_eq!(n, "staged/0001-Passwords__1_.txt");
        assert!(valid_entry_name(&n));
        let n = entry_name(
            "secrets",
            7,
            r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        );
        assert_eq!(n, "secrets/0007-Login_Data");
        for weird in [
            "..",
            "...",
            r"C:\x\..\..\evil",
            "\u{202e}gpj.exe",
            "a:b:$DATA",
            "",
            "/",
            "....txt",
        ] {
            let n = entry_name("staged", 3, weird);
            assert!(valid_entry_name(&n), "{weird:?} -> {n}");
        }
        let long = "x".repeat(500);
        assert!(valid_entry_name(&entry_name("staged", 9999, &long)));
        assert!(entry_name("evil/../", 1, "a").starts_with("staged/"));
    }

    fn sample() -> Vec<u8> {
        let mut w = ContainerWriter::new(Vec::new()).unwrap();
        w.entry("staged/0001-a.zip", b"PK\x03\x04data").unwrap();
        let big = vec![7u8; (MAX_CHUNK as usize) + 10];
        let (n, sha, more) = w
            .entry_from_reader("secrets/0001-Login_Data", &mut &big[..], 1 << 30)
            .unwrap();
        assert_eq!(n, big.len() as u64);
        assert!(!more);
        assert_eq!(sha, sha256_hex(&big));
        w.entry("manifest.json", b"{}").unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn container_roundtrip() {
        let bytes = sample();
        let mut got = vec![];
        let names = read_container(&bytes[..], ContainerLimits::default(), |name, r| {
            let mut v = vec![];
            r.read_to_end(&mut v)?;
            got.push((name.to_string(), v.len()));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            names,
            [
                "staged/0001-a.zip",
                "secrets/0001-Login_Data",
                "manifest.json"
            ]
        );
        assert_eq!(got[1].1, MAX_CHUNK as usize + 10);
        // A callback that reads nothing still works (data drained).
        read_container(&bytes[..], ContainerLimits::default(), |_, _| Ok(())).unwrap();
    }

    #[test]
    fn container_caps_a_growing_file() {
        let mut w = ContainerWriter::new(Vec::new()).unwrap();
        let data = vec![1u8; 1000];
        let (n, _, more) = w
            .entry_from_reader("staged/0001-x", &mut &data[..], 400)
            .unwrap();
        assert_eq!((n, more), (400, true));
        let (n, _, more) = w
            .entry_from_reader("staged/0002-x", &mut &data[..], 1000)
            .unwrap();
        assert_eq!((n, more), (1000, false));
        w.entry("manifest.json", b"{}").unwrap();
        w.finish().unwrap();
    }

    #[test]
    fn writer_refuses_bad_names() {
        let mut w = ContainerWriter::new(Vec::new()).unwrap();
        assert!(w.begin_entry("../evil").is_err());
        w.entry("staged/0001-a", b"x").unwrap();
        assert!(w.entry("staged/0001-a", b"x").is_err());
        // Differs only in case: collides on Windows extraction.
        assert!(w.entry("staged/0001-A", b"x").is_err());
    }

    #[test]
    fn reader_refuses_malformed_containers() {
        let lim = ContainerLimits::default();
        let ok = sample();
        // Truncated anywhere.
        for cut in [0, 3, 5, 20, ok.len() / 2, ok.len() - 1] {
            assert!(
                read_container(&ok[..cut], lim, |_, _| Ok(())).is_err(),
                "cut {cut}"
            );
        }
        // Trailing junk.
        let mut t = ok.clone();
        t.push(0);
        assert!(read_container(&t[..], lim, |_, _| Ok(())).is_err());
        // Hand-made traversal name.
        let mut evil = b"KEB1".to_vec();
        let name = b"staged/../../x";
        evil.push(1);
        evil.extend_from_slice(&(name.len() as u16).to_be_bytes());
        evil.extend_from_slice(name);
        evil.extend_from_slice(&0u32.to_be_bytes());
        evil.push(0);
        assert!(read_container(&evil[..], lim, |_, _| Ok(())).is_err());
        // No manifest.
        let mut w = ContainerWriter::new(Vec::new()).unwrap();
        w.entry("staged/0001-a", b"x").unwrap();
        let nm = w.finish().unwrap();
        assert!(read_container(&nm[..], lim, |_, _| Ok(())).is_err());
        // Entry limit.
        let small = ContainerLimits {
            max_entry_bytes: 4,
            ..lim
        };
        assert!(read_container(&ok[..], small, |_, _| Ok(())).is_err());
        let few = ContainerLimits {
            max_entries: 2,
            ..lim
        };
        assert!(read_container(&ok[..], few, |_, _| Ok(())).is_err());
        let total = ContainerLimits {
            max_total_bytes: 100,
            ..lim
        };
        assert!(read_container(&ok[..], total, |_, _| Ok(())).is_err());
        // Oversize chunk header.
        let mut huge = b"KEB1".to_vec();
        huge.push(1);
        huge.extend_from_slice(&13u16.to_be_bytes());
        huge.extend_from_slice(b"manifest.json");
        huge.extend_from_slice(&(MAX_CHUNK + 1).to_be_bytes());
        assert!(read_container(&huge[..], lim, |_, _| Ok(())).is_err());
    }

    #[test]
    fn report_wire_format_is_additive() {
        let r = EvidenceReport {
            bundle_id: Uuid::nil(),
            alert_id: Uuid::nil(),
            alert_ids: vec![],
            rule_id: "ST-04".into(),
            state: EvidenceState::Capturing,
            ts: 1,
            manifest: None,
            bundle_size: 0,
            bundle_sha256: None,
            local_expires_at: None,
            detail: String::new(),
        };
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""state":"capturing""#), "{j}");
        let min: EvidenceReport = serde_json::from_str(
            r#"{"bundle_id":"00000000-0000-0000-0000-000000000000","alert_id":"00000000-0000-0000-0000-000000000000","rule_id":"ST-02","state":"ready","ts":5}"#,
        )
        .unwrap();
        assert_eq!(min.state, EvidenceState::Ready);
        assert!(is_trigger_rule("ST-02") && is_trigger_rule("ST-04") && !is_trigger_rule("ST-01"));
        let f: PcapFilter =
            serde_json::from_str(r#"{"ip":"203.0.113.7","port":443,"proto":"tcp"}"#).unwrap();
        assert_eq!(f.port, Some(443));
    }
}
