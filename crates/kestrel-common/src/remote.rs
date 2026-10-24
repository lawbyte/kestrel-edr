//! Remote access (owner request, 2026-10-21): admin-initiated remote desktop
//! (view + control) and a remote file manager.
//!
//! Both ride the existing mTLS gRPC stream as **live** messages:
//! `ServerPayload::Live { session_id, msg: LiveServerMsg }` and
//! `AgentPayload::Live { session_id, msg: LiveAgentMsg }`. Live messages are
//! ephemeral: envelope `seq = 0` on the agent side, never written to the
//! agent's SQLite outbox, never acked or deduplicated, never stored by the
//! server (no telemetry, no ClickHouse, no logs of frames or file contents).
//! If the stream drops, every live session on it ends.
//!
//! Compatibility: both message enums carry a `#[serde(other)] Unknown`
//! variant so a newer peer's message kinds are ignored, and older agents /
//! servers drop a whole `Live` payload as undecodable (agent: logged and not
//! acked; server: "malformed", seq 0 is never acked). Servers only open live
//! sessions with agents whose `Hello.capabilities` lists the feature.
//!
//! Binary data (JPEG frames, file chunks) is standard base64 in JSON. One
//! serialised live message must stay below [`LIVE_MAX_MESSAGE`].

use crate::TimestampMs;
use serde::{Deserialize, Serialize};

/// Upper bound of one serialised live message (JSON, before compression).
pub const LIVE_MAX_MESSAGE: usize = 1024 * 1024;
/// Largest file chunk (raw bytes) in one `ReadChunk` / `WriteChunk`.
pub const FILE_CHUNK_MAX: u32 = 512 * 1024;
/// Largest single download or upload.
pub const TRANSFER_MAX: u64 = 4 * 1024 * 1024 * 1024;
/// Longest path accepted (UTF-16 code units are not counted; chars are).
pub const PATH_MAX_CHARS: usize = 32_000;
/// Most directory entries returned by one `List`.
pub const LIST_MAX_ENTRIES: usize = 10_000;
/// Frames the agent may have in flight (sent, not yet acked by the server).
pub const DESKTOP_MAX_INFLIGHT: u32 = 3;
/// A desktop session with no admin input / activity for this long ends.
pub const DESKTOP_IDLE_TIMEOUT_MS: i64 = 15 * 60 * 1000;
/// Hard limit on one desktop session.
pub const DESKTOP_MAX_DURATION_MS: i64 = 4 * 60 * 60 * 1000;
/// The server pings a desktop session at least this often; the agent ends a
/// session that has heard nothing from the server for [`DESKTOP_SERVER_SILENCE_MS`].
pub const DESKTOP_PING_EVERY_MS: i64 = 20_000;
pub const DESKTOP_SERVER_SILENCE_MS: i64 = 90_000;
/// An unfinished upload with no chunk for this long is aborted (temp file removed).
pub const TRANSFER_IDLE_TIMEOUT_MS: i64 = 120_000;
/// A file-manager session without operations for this long is over on the
/// agent (its on-screen banner and tray notice end) unless the server ended
/// it earlier with [`LiveServerMsg::FileSessionEnd`].
pub const FILE_SESSION_IDLE_MS: i64 = 300_000;

/// `Hello.capabilities` values.
pub const CAP_LIVE_FILES: &str = "live.files";
pub const CAP_LIVE_DESKTOP: &str = "live.desktop";

// ------------------------------------------------------------------ envelope

/// Server → agent live message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveServerMsg {
    /// Start a remote desktop session (one per device).
    DesktopStart(DesktopStart),
    /// Change quality / scale / frame rate / control mode mid-session.
    DesktopSettings(DesktopSettings),
    /// Mouse / keyboard input from the admin (ignored in view-only sessions).
    DesktopInput { event: InputEvent },
    /// The server delivered every frame up to and including `seq`
    /// (credit-based flow control, see [`DESKTOP_MAX_INFLIGHT`]).
    DesktopAck { seq: u64 },
    /// Keep-alive while a desktop session is open.
    DesktopPing,
    /// End the session (admin disconnect, idle / max-duration timeout).
    DesktopStop {
        #[serde(default)]
        reason: String,
    },
    /// One file-manager request; answered by exactly one `FileReply`
    /// (possibly after a `ConsentPending`).
    FileRequest {
        request_id: u64,
        op: FileOp,
        /// File-manager session, admin and reason (consent and audit on the
        /// device). Absent from servers older than remote-access profiles.
        #[serde(default)]
        context: Option<FileContext>,
    },
    /// The admin closed the console's file manager: the file-manager session
    /// `fm_session` of `admin_name` is over (its on-screen banner and tray
    /// notice end, its consent grant is dropped). No reply. Older agents
    /// ignore it (`Unknown`) and end the session after
    /// [`FILE_SESSION_IDLE_MS`] without operations.
    FileSessionEnd {
        fm_session: uuid::Uuid,
        #[serde(default)]
        admin_name: String,
    },
    /// Read the next chunk of evidence bundle `bundle_id` (container
    /// plaintext) for an upload the agent prepared with
    /// `ResponseAction::CollectEvidence`. Within one live session (= one
    /// upload) reads are sequential from offset 0 and `len` ≤
    /// `evidence::READ_CHUNK_MAX`; answered by exactly one
    /// `LiveAgentMsg::EvidenceData` (`FileReply::Data`, whose `eof` reply
    /// carries the SHA-256 of the whole bundle, or `FileReply::Error`). Not
    /// subject to the remote-access profile; only sent to agents announcing
    /// `evidence::CAP_EVIDENCE`.
    EvidenceRead {
        request_id: u64,
        bundle_id: uuid::Uuid,
        offset: u64,
        len: u32,
    },
    /// Message kind this agent does not know (newer server).
    #[serde(other)]
    Unknown,
}

/// Agent → server live message.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LiveAgentMsg {
    /// Capture is running in the interactive session.
    DesktopStarted(DesktopInfo),
    /// One full JPEG frame. Only sent when the screen changed (or after a
    /// settings change), and only while fewer than `DESKTOP_MAX_INFLIGHT`
    /// frames are unacked.
    DesktopFrame(DesktopFrame),
    /// Screen geometry changed (resolution, monitor added).
    DesktopInfo(DesktopInfo),
    /// The session ended on the agent side (or could not start).
    DesktopEnded {
        reason: String,
        /// Machine-readable code (see [`RemoteErrorCode`]); `None` = normal end.
        #[serde(default)]
        code: Option<RemoteErrorCode>,
    },
    /// Answer to `FileRequest { request_id, .. }`.
    FileReply { request_id: u64, reply: FileReply },
    /// The agent is waiting for the employee's Allow/Deny (guardrail
    /// `require_consent`). For a desktop session `request_id` is `None`; for
    /// a file request it names the request. The server extends its reply
    /// timeout by `timeout_secs` (+ a margin) and tells the console.
    ConsentPending {
        #[serde(default)]
        request_id: Option<u64>,
        timeout_secs: u32,
    },
    /// Outcome of a consent prompt the agent announced with
    /// `ConsentPending` (also sent when an admin asks to switch a running
    /// view-only desktop session to control and the profile requires
    /// consent: the session stays view-only until `allowed`).
    ConsentResult {
        #[serde(default)]
        request_id: Option<u64>,
        allowed: bool,
        /// `ConsentDenied` / `ConsentTimeout` when not allowed.
        #[serde(default)]
        code: Option<RemoteErrorCode>,
    },
    /// Answer to `EvidenceRead { request_id, .. }`: `FileReply::Data` or
    /// `FileReply::Error` (`not_found` = no such bundle / not prepared for
    /// upload, `invalid_operation` = out-of-order read, `integrity_error` =
    /// the local bundle failed authentication).
    EvidenceData { request_id: u64, reply: FileReply },
    /// Message kind this server does not know (newer agent).
    #[serde(other)]
    Unknown,
}

// ------------------------------------------------------------------ desktop

/// Default JPEG quality.
pub const DEFAULT_QUALITY: u8 = 60;
/// Default frame-rate cap.
pub const DEFAULT_MAX_FPS: u8 = 8;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DesktopStart {
    /// `true` = the admin can only watch; input is dropped by the agent.
    #[serde(default)]
    pub view_only: bool,
    /// Who is connected, shown to the employee ("IT (Jane Doe) is …").
    pub admin_name: String,
    /// Optional reason shown in the banner and notification.
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub settings: DesktopSettings,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DesktopSettings {
    /// JPEG quality, clamped to 30..=90.
    #[serde(default = "default_quality")]
    pub quality: u8,
    /// Downscale in percent of the native size, clamped to 25..=100.
    #[serde(default = "default_scale")]
    pub scale_pct: u8,
    /// Frame-rate cap, clamped to 1..=15 (the agent adapts below it).
    #[serde(default = "default_fps")]
    pub max_fps: u8,
    /// Switch between view-only and control mid-session. `None` = unchanged.
    #[serde(default)]
    pub view_only: Option<bool>,
}

fn default_quality() -> u8 {
    DEFAULT_QUALITY
}
fn default_scale() -> u8 {
    100
}
fn default_fps() -> u8 {
    DEFAULT_MAX_FPS
}

impl Default for DesktopSettings {
    fn default() -> Self {
        DesktopSettings {
            quality: DEFAULT_QUALITY,
            scale_pct: 100,
            max_fps: DEFAULT_MAX_FPS,
            view_only: None,
        }
    }
}

impl DesktopSettings {
    /// Clamp every field into its documented range.
    pub fn clamped(&self) -> DesktopSettings {
        DesktopSettings {
            quality: self.quality.clamp(30, 90),
            scale_pct: self.scale_pct.clamp(25, 100),
            max_fps: self.max_fps.clamp(1, 15),
            view_only: self.view_only,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct DesktopInfo {
    /// Captured (virtual-screen) size in physical pixels.
    pub width: u32,
    pub height: u32,
    /// Monitors in the virtual screen.
    #[serde(default)]
    pub monitors: u32,
    /// Interactive session id the helper runs in.
    #[serde(default)]
    pub session_id: Option<u32>,
    /// `true` while the input desktop is not the user's default desktop
    /// (UAC secure desktop, lock screen) and could not be captured.
    #[serde(default)]
    pub secure_desktop: bool,
    #[serde(default)]
    pub view_only: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DesktopFrame {
    /// Strictly increasing per session, starting at 1.
    pub seq: u64,
    /// Size of the encoded image (after downscaling).
    pub width: u32,
    pub height: u32,
    /// Capture time on the agent.
    pub ts: TimestampMs,
    /// Standard base64 of a baseline JPEG.
    pub jpeg_b64: String,
}

/// Mouse / keyboard input. Coordinates are normalised to the captured
/// virtual screen: `x, y` in `0.0..=1.0` (left/top = 0).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InputEvent {
    MouseMove {
        x: f32,
        y: f32,
    },
    MouseButton {
        x: f32,
        y: f32,
        button: MouseButton,
        down: bool,
    },
    /// Wheel delta in notches (positive = away from the user / right).
    MouseWheel {
        x: f32,
        y: f32,
        #[serde(default)]
        delta_y: f32,
        #[serde(default)]
        delta_x: f32,
    },
    /// One key transition. `code` is the browser `KeyboardEvent.code`
    /// (layout independent, e.g. "KeyA", "Enter", "ShiftLeft"); the agent
    /// maps it to a scan code + virtual key. Unknown codes are dropped.
    Key {
        code: String,
        down: bool,
    },
    /// Type text (e.g. a pasted string) as Unicode key events. ≤ 4096 chars.
    Text {
        text: String,
    },
    /// Secure attention sequence (Ctrl+Alt+Del). Best effort: needs the
    /// `SoftwareSASGeneration` policy on Windows; the agent reports failure
    /// through `DesktopInfo`/logs only.
    CtrlAltDel,
    /// Release every key and button the session pressed (sent on focus loss).
    ReleaseAll,
    #[serde(other)]
    Unknown,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    X1,
    X2,
}

impl InputEvent {
    /// Clamp coordinates into 0..=1 and reject non-finite values / oversize text.
    pub fn sanitized(self) -> Option<InputEvent> {
        fn c(v: f32) -> Option<f32> {
            v.is_finite().then(|| v.clamp(0.0, 1.0))
        }
        fn d(v: f32) -> Option<f32> {
            v.is_finite().then(|| v.clamp(-50.0, 50.0))
        }
        Some(match self {
            InputEvent::MouseMove { x, y } => InputEvent::MouseMove { x: c(x)?, y: c(y)? },
            InputEvent::MouseButton { x, y, button, down } => InputEvent::MouseButton {
                x: c(x)?,
                y: c(y)?,
                button,
                down,
            },
            InputEvent::MouseWheel {
                x,
                y,
                delta_y,
                delta_x,
            } => InputEvent::MouseWheel {
                x: c(x)?,
                y: c(y)?,
                delta_y: d(delta_y)?,
                delta_x: d(delta_x)?,
            },
            InputEvent::Key { code, down } => {
                if code.is_empty()
                    || code.len() > 32
                    || !code.chars().all(|ch| ch.is_ascii_alphanumeric())
                {
                    return None;
                }
                InputEvent::Key { code, down }
            }
            InputEvent::Text { text } => {
                if text.is_empty() || text.chars().count() > 4096 {
                    return None;
                }
                InputEvent::Text { text }
            }
            InputEvent::Unknown => return None,
            other => other,
        })
    }
}

// --------------------------------------------------------------------- files

/// One file-manager operation. Paths are absolute Windows paths (`X:\…`) or
/// a drive root (`X:\`); `List` with an empty path lists the drives. UNC /
/// device paths (`\\server\share`, `\\?\…`, `\\.\…`) are refused: the agent
/// runs as SYSTEM and never opens network paths (V-M1).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FileOp {
    List {
        #[serde(default)]
        path: String,
    },
    Stat {
        path: String,
    },
    /// Read `len` (≤ `FILE_CHUNK_MAX`) bytes at `offset`. Within one live
    /// session (= one download) reads must be sequential from offset 0; the
    /// agent keeps the file open and hashes as it goes, and the reply with
    /// `eof = true` carries the SHA-256 of the whole file.
    ReadChunk {
        path: String,
        offset: u64,
        len: u32,
    },
    /// Start an upload to `path` (create or overwrite) of exactly `size`
    /// bytes. The agent writes a temp file in the same folder.
    WriteBegin {
        path: String,
        size: u64,
    },
    /// Next chunk of the session's upload; `offset` must equal the bytes
    /// written so far.
    WriteChunk {
        offset: u64,
        data_b64: String,
    },
    /// Finish: size and SHA-256 must match, then the temp file is renamed
    /// over the target atomically.
    WriteEnd {
        sha256: String,
    },
    /// Abandon the session's upload (temp file deleted).
    WriteAbort,
    Rename {
        from: String,
        to: String,
        /// Replace an existing file at `to` (never a directory).
        #[serde(default)]
        overwrite: bool,
    },
    /// Delete a file or folder. Folders need `recursive` unless empty. Reparse
    /// points (junctions, symlinks) are removed as links, never followed.
    Delete {
        path: String,
        #[serde(default)]
        recursive: bool,
    },
    Mkdir {
        path: String,
    },
    #[serde(other)]
    Unknown,
}

impl FileOp {
    /// Short operation name (audit log, metrics).
    pub fn name(&self) -> &'static str {
        match self {
            FileOp::List { .. } => "list",
            FileOp::Stat { .. } => "stat",
            FileOp::ReadChunk { .. } => "read_chunk",
            FileOp::WriteBegin { .. } => "write_begin",
            FileOp::WriteChunk { .. } => "write_chunk",
            FileOp::WriteEnd { .. } => "write_end",
            FileOp::WriteAbort => "write_abort",
            FileOp::Rename { .. } => "rename",
            FileOp::Delete { .. } => "delete",
            FileOp::Mkdir { .. } => "mkdir",
            FileOp::Unknown => "unknown",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum FileReply {
    /// `List`: entries of a folder (or the drives for an empty path).
    List {
        path: String,
        entries: Vec<FileEntry>,
        /// More than `LIST_MAX_ENTRIES` entries; the rest were omitted.
        #[serde(default)]
        truncated: bool,
    },
    Stat(FileEntry),
    /// `ReadChunk` data.
    Data {
        offset: u64,
        data_b64: String,
        /// Size of the file when it was opened.
        size: u64,
        eof: bool,
        /// SHA-256 (hex) of every byte read in this session, on `eof`.
        #[serde(default)]
        sha256: Option<String>,
    },
    /// Success of a mutation (`WriteBegin`/`WriteChunk`/`WriteAbort`,
    /// `Rename`, `Delete`, `Mkdir`).
    Done {
        /// Bytes written so far (uploads) / items removed (delete).
        #[serde(default)]
        count: u64,
    },
    /// `WriteEnd` success.
    Written {
        path: String,
        size: u64,
        sha256: String,
    },
    Error {
        code: RemoteErrorCode,
        message: String,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct FileEntry {
    pub name: String,
    /// Full path (for drives: `C:\`).
    pub path: String,
    pub kind: FileKind,
    #[serde(default)]
    pub size: u64,
    /// Last write time (ms), when known.
    #[serde(default)]
    pub modified: Option<TimestampMs>,
    /// Win32 `FILE_ATTRIBUTE_*` bits.
    #[serde(default)]
    pub attributes: u32,
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub readonly: bool,
    /// Junction / symlink / other reparse point (never followed on delete).
    #[serde(default)]
    pub reparse: bool,
    /// Drives only: free / total bytes and a label ("Local Disk", "Removable").
    #[serde(default)]
    pub free_bytes: Option<u64>,
    #[serde(default)]
    pub total_bytes: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    #[default]
    File,
    Dir,
    Drive,
    /// A reparse point whose target kind is not a plain file/folder.
    Link,
}

/// Machine-readable error codes for remote-access failures.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteErrorCode {
    /// The device's policy has the feature (or this kind of operation) switched off.
    DisabledByPolicy,
    /// Outside the remote-access ceiling pinned on the device at install
    /// (only a reinstall with another profile can change it).
    NotPermitted,
    /// The employee clicked Deny, or no one could be asked (no signed-in
    /// user / no tray).
    ConsentDenied,
    /// The employee did not answer within the consent timeout.
    ConsentTimeout,
    /// Outside the profile's allowed hours (device local time).
    OutsideAllowedHours,
    /// The profile requires a reason and none was given.
    ReasonRequired,
    /// The path is under one of the profile's blocked paths.
    BlockedPath,
    /// Path is malformed, relative, UNC/device, too long, …
    InvalidPath,
    /// Inside (or an ancestor of) the Kestrel agent's install/state folders.
    ProtectedPath,
    NotFound,
    AlreadyExists,
    AccessDenied,
    /// A folder that is not empty and `recursive` was not set, a file that is a
    /// directory, etc.
    InvalidOperation,
    /// Offsets out of order, hash mismatch, size mismatch, file changed.
    IntegrityError,
    TooLarge,
    /// Another session is active (one desktop session per device).
    Busy,
    /// No interactive session / helper could not start / not supported here.
    Unavailable,
    Timeout,
    Io,
    #[serde(other)]
    Other,
}

impl RemoteErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RemoteErrorCode::DisabledByPolicy => "disabled_by_policy",
            RemoteErrorCode::NotPermitted => "not_permitted",
            RemoteErrorCode::ConsentDenied => "consent_denied",
            RemoteErrorCode::ConsentTimeout => "consent_timeout",
            RemoteErrorCode::OutsideAllowedHours => "outside_allowed_hours",
            RemoteErrorCode::ReasonRequired => "reason_required",
            RemoteErrorCode::BlockedPath => "blocked_path",
            RemoteErrorCode::InvalidPath => "invalid_path",
            RemoteErrorCode::ProtectedPath => "protected_path",
            RemoteErrorCode::NotFound => "not_found",
            RemoteErrorCode::AlreadyExists => "already_exists",
            RemoteErrorCode::AccessDenied => "access_denied",
            RemoteErrorCode::InvalidOperation => "invalid_operation",
            RemoteErrorCode::IntegrityError => "integrity_error",
            RemoteErrorCode::TooLarge => "too_large",
            RemoteErrorCode::Busy => "busy",
            RemoteErrorCode::Unavailable => "unavailable",
            RemoteErrorCode::Timeout => "timeout",
            RemoteErrorCode::Io => "io",
            RemoteErrorCode::Other => "other",
        }
    }
}

impl FileReply {
    pub fn error(code: RemoteErrorCode, message: impl Into<String>) -> FileReply {
        FileReply::Error {
            code,
            message: message.into(),
        }
    }
}

// ------------------------------------------------------ profiles & ceiling

/// Remote-desktop permission. Ordered: `Off < ViewOnly < Control`.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum DesktopMode {
    #[default]
    Off,
    ViewOnly,
    Control,
}

/// File-manager permission. Ordered: `Off < ReadOnly < Full`.
/// `ReadOnly` = list / stat / download only.
#[derive(
    Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum FileMode {
    #[default]
    Off,
    ReadOnly,
    Full,
}

/// Weekly window in the **device's local time** during which remote access
/// is allowed. `days`: 0 = Monday … 6 = Sunday. Minutes since local
/// midnight, `start_minute < end_minute ≤ 1440`. Windows do not wrap past
/// midnight. An empty window (no days, or start ≥ end after an
/// intersection) allows nothing.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AllowedHours {
    #[serde(default)]
    pub days: Vec<u8>,
    #[serde(default)]
    pub start_minute: u16,
    #[serde(default = "full_day")]
    pub end_minute: u16,
}

fn full_day() -> u16 {
    1440
}

impl AllowedHours {
    /// Is local `weekday` (0 = Monday) at `minute` (since midnight) inside?
    pub fn contains(&self, weekday: u8, minute: u16) -> bool {
        self.days.contains(&weekday)
            && minute >= self.start_minute
            && minute < self.end_minute.min(1440)
    }

    /// Never allows anything (empty day set or empty time range).
    pub fn is_empty(&self) -> bool {
        self.days.is_empty() || self.start_minute >= self.end_minute.min(1440)
    }

    /// Sanity check for API input.
    pub fn validate(&self) -> Result<(), String> {
        if self.days.iter().any(|d| *d > 6) {
            return Err("allowed_hours.days must be 0 (Monday) … 6 (Sunday)".into());
        }
        if self.end_minute > 1440 || self.start_minute >= self.end_minute {
            return Err("allowed_hours needs start_minute < end_minute ≤ 1440".into());
        }
        Ok(())
    }

    fn intersect(&self, o: &AllowedHours) -> AllowedHours {
        let mut days: Vec<u8> = self
            .days
            .iter()
            .copied()
            .filter(|d| o.days.contains(d))
            .collect();
        days.sort_unstable();
        days.dedup();
        AllowedHours {
            days,
            start_minute: self.start_minute.max(o.start_minute),
            end_minute: self.end_minute.min(o.end_minute),
        }
    }
}

/// Default consent timeout (seconds) when the field is 0 or absent.
pub const DEFAULT_CONSENT_TIMEOUT_SECS: u32 = 60;

/// Guardrails of a remote-access profile. Missing fields deserialize to the
/// **guarded** defaults (the strict side), never to "unrestricted".
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RemoteGuardrails {
    /// The employee must click Allow in the tray before a desktop session
    /// (or a full-access file-manager session) starts. No answer, no tray or
    /// no signed-in user = deny.
    #[serde(default = "yes")]
    pub require_consent: bool,
    /// 0 = [`DEFAULT_CONSENT_TIMEOUT_SECS`].
    #[serde(default = "default_consent_timeout")]
    pub consent_timeout_secs: u32,
    /// The admin must give a reason (shown in the banner / consent prompt and audited).
    #[serde(default = "yes")]
    pub require_reason: bool,
    /// Server-side step-up: the admin re-enters a TOTP code (valid 10 min)
    /// before starting a session or a file-manager session.
    #[serde(default = "yes")]
    pub require_mfa_reauth: bool,
    /// Uploads (create / overwrite) and mkdir. `FileMode::Full` only.
    #[serde(default = "yes")]
    pub allow_upload: bool,
    /// Delete and rename / move. `FileMode::Full` only.
    #[serde(default)]
    pub allow_delete: bool,
    /// 0 = no limit.
    #[serde(default = "default_max_minutes")]
    pub max_session_minutes: u32,
    /// 0 = no limit.
    #[serde(default = "default_idle_minutes")]
    pub idle_timeout_minutes: u32,
    #[serde(default)]
    pub allowed_hours: Option<AllowedHours>,
    /// Path prefixes the file manager refuses (case-insensitive, drive-aware,
    /// component-wise). Kestrel's own folders are always refused.
    #[serde(default = "default_blocked_paths")]
    pub blocked_paths: Vec<String>,
}

fn yes() -> bool {
    true
}
fn default_consent_timeout() -> u32 {
    DEFAULT_CONSENT_TIMEOUT_SECS
}
fn default_max_minutes() -> u32 {
    60
}
fn default_idle_minutes() -> u32 {
    15
}
fn default_blocked_paths() -> Vec<String> {
    vec![r"C:\Windows\System32\config".to_string()]
}

impl Default for RemoteGuardrails {
    /// The guarded defaults.
    fn default() -> Self {
        RemoteGuardrails {
            require_consent: true,
            consent_timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
            require_reason: true,
            require_mfa_reauth: true,
            allow_upload: true,
            allow_delete: false,
            max_session_minutes: 60,
            idle_timeout_minutes: 15,
            allowed_hours: None,
            blocked_paths: default_blocked_paths(),
        }
    }
}

impl RemoteGuardrails {
    /// Every guardrail off, no limits.
    pub fn none() -> Self {
        RemoteGuardrails {
            require_consent: false,
            consent_timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
            require_reason: false,
            require_mfa_reauth: false,
            allow_upload: true,
            allow_delete: true,
            max_session_minutes: 0,
            idle_timeout_minutes: 0,
            allowed_hours: None,
            blocked_paths: vec![],
        }
    }

    /// Consent timeout with 0 mapped to the default.
    pub fn consent_timeout(&self) -> u32 {
        if self.consent_timeout_secs == 0 {
            DEFAULT_CONSENT_TIMEOUT_SECS
        } else {
            self.consent_timeout_secs
        }
    }

    /// Is `path` (normalised by [`validate_remote_path`]) under a blocked prefix?
    /// Returns the matching prefix.
    pub fn blocked_prefix(&self, path: &str) -> Option<&str> {
        self.blocked_paths
            .iter()
            .map(String::as_str)
            .find(|b| !b.trim().is_empty() && path_is_within(path, b))
    }
}

/// What remote access a device permits. Used three ways: the **ceiling**
/// pinned on the agent at enrollment (from the enrollment token, never
/// changed by later server messages), the **policy** setting, and their
/// [`intersect`](RemoteAccessProfile::intersect)ion — the **effective**
/// profile the agent enforces. The on-screen banner and tray notification are
/// mandatory in every profile (not configurable).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct RemoteAccessProfile {
    #[serde(default)]
    pub desktop: DesktopMode,
    #[serde(default)]
    pub files: FileMode,
    #[serde(default)]
    pub guardrails: RemoteGuardrails,
}

impl Default for RemoteAccessProfile {
    /// [`RemoteAccessProfile::none`]: the safe default for existing
    /// policies, tokens and agents enrolled before profiles existed.
    fn default() -> Self {
        Self::none()
    }
}

/// Which preset a profile equals (UI labels; `Custom` otherwise).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RemoteProfilePreset {
    None,
    Unrestricted,
    Guarded,
    Custom,
}

impl RemoteAccessProfile {
    /// No remote access at all.
    pub fn none() -> Self {
        RemoteAccessProfile {
            desktop: DesktopMode::Off,
            files: FileMode::Off,
            guardrails: RemoteGuardrails::default(),
        }
    }

    /// Remote control + full file manager, no guardrails (banner and
    /// notification still mandatory).
    pub fn unrestricted() -> Self {
        RemoteAccessProfile {
            desktop: DesktopMode::Control,
            files: FileMode::Full,
            guardrails: RemoteGuardrails::none(),
        }
    }

    /// Remote control + file manager with the default guardrails.
    pub fn guarded_default() -> Self {
        RemoteAccessProfile {
            desktop: DesktopMode::Control,
            files: FileMode::Full,
            guardrails: RemoteGuardrails::default(),
        }
    }

    pub fn is_none(&self) -> bool {
        self.desktop == DesktopMode::Off && self.files == FileMode::Off
    }

    pub fn preset(&self) -> RemoteProfilePreset {
        if self.is_none() {
            RemoteProfilePreset::None
        } else if *self == Self::unrestricted() {
            RemoteProfilePreset::Unrestricted
        } else if *self == Self::guarded_default() {
            RemoteProfilePreset::Guarded
        } else {
            RemoteProfilePreset::Custom
        }
    }

    /// Validate API input (hours, blocked path syntax, limits).
    pub fn validate(&self) -> Result<(), String> {
        let g = &self.guardrails;
        if let Some(h) = &g.allowed_hours {
            h.validate()?;
        }
        if g.blocked_paths.len() > 256 {
            return Err("at most 256 blocked paths".into());
        }
        for p in &g.blocked_paths {
            validate_remote_path(p).map_err(|e| format!("blocked path {p:?}: {e}"))?;
        }
        if g.consent_timeout_secs > 600 {
            return Err("consent_timeout_secs must be ≤ 600".into());
        }
        if g.max_session_minutes > 24 * 60 || g.idle_timeout_minutes > 24 * 60 {
            return Err("session limits must be ≤ 1440 minutes".into());
        }
        Ok(())
    }

    /// Stricter-wins intersection (used as `ceiling.intersect(&policy)`;
    /// commutative). Modes: the lower one. Guardrail requirements: either
    /// side requires it. `allow_*`: both must allow. Limits and the consent
    /// timeout: the smaller non-zero value. Allowed hours: the intersection
    /// when either side sets them (an empty result means never). Blocked
    /// paths: the union.
    pub fn intersect(&self, o: &RemoteAccessProfile) -> RemoteAccessProfile {
        fn min_nz(a: u32, b: u32) -> u32 {
            match (a, b) {
                (0, x) | (x, 0) => x,
                (x, y) => x.min(y),
            }
        }
        let (a, b) = (&self.guardrails, &o.guardrails);
        let allowed_hours = match (&a.allowed_hours, &b.allowed_hours) {
            (None, None) => None,
            (Some(h), None) | (None, Some(h)) => Some(h.clone()),
            (Some(x), Some(y)) => Some(x.intersect(y)),
        };
        let mut blocked: Vec<String> = a
            .blocked_paths
            .iter()
            .chain(b.blocked_paths.iter())
            .map(|p| validate_remote_path(p).unwrap_or_else(|_| p.clone()))
            .collect();
        // Order-independent result (the intersection is commutative).
        blocked.sort_by(|x, y| x.to_lowercase().cmp(&y.to_lowercase()).then(x.cmp(y)));
        blocked.dedup_by(|x, y| x.to_lowercase() == y.to_lowercase());
        RemoteAccessProfile {
            desktop: self.desktop.min(o.desktop),
            files: self.files.min(o.files),
            guardrails: RemoteGuardrails {
                require_consent: a.require_consent || b.require_consent,
                consent_timeout_secs: min_nz(a.consent_timeout(), b.consent_timeout()),
                require_reason: a.require_reason || b.require_reason,
                require_mfa_reauth: a.require_mfa_reauth || b.require_mfa_reauth,
                allow_upload: a.allow_upload && b.allow_upload,
                allow_delete: a.allow_delete && b.allow_delete,
                max_session_minutes: min_nz(a.max_session_minutes, b.max_session_minutes),
                idle_timeout_minutes: min_nz(a.idle_timeout_minutes, b.idle_timeout_minutes),
                allowed_hours,
                blocked_paths: blocked,
            },
        }
    }

    /// Is a file operation of this kind permitted by the modes and
    /// `allow_*` flags (paths and hours are checked separately)?
    pub fn file_op_permitted(&self, op: &FileOp) -> Result<(), String> {
        let need = file_op_class(op);
        match (self.files, need) {
            (FileMode::Off, _) => Err("the file manager is off".into()),
            (_, FileOpClass::Read) => Ok(()),
            (FileMode::ReadOnly, _) => Err("the file manager is read-only".into()),
            (FileMode::Full, FileOpClass::Write) if !self.guardrails.allow_upload => {
                Err("uploads and new folders are not allowed".into())
            }
            (FileMode::Full, FileOpClass::Delete) if !self.guardrails.allow_delete => {
                Err("delete, rename and move are not allowed".into())
            }
            _ => Ok(()),
        }
    }

    /// Human summary, e.g. "Remote control + full file manager (consent,
    /// reason, MFA; no delete; 60 min max)".
    pub fn summary(&self) -> String {
        if self.is_none() {
            return "No remote access".into();
        }
        let d = match self.desktop {
            DesktopMode::Off => None,
            DesktopMode::ViewOnly => Some("view-only remote desktop"),
            DesktopMode::Control => Some("remote control"),
        };
        let f = match self.files {
            FileMode::Off => None,
            FileMode::ReadOnly => Some("read-only file manager"),
            FileMode::Full => Some("full file manager"),
        };
        let mut s = [d, f].into_iter().flatten().collect::<Vec<_>>().join(" + ");
        let g = &self.guardrails;
        let mut parts: Vec<String> = vec![];
        if g.require_consent {
            parts.push("employee consent".into());
        }
        if g.require_reason {
            parts.push("reason".into());
        }
        if g.require_mfa_reauth {
            parts.push("MFA re-auth".into());
        }
        if self.files == FileMode::Full {
            if !g.allow_upload {
                parts.push("no upload".into());
            }
            if !g.allow_delete {
                parts.push("no delete".into());
            }
        }
        if g.max_session_minutes > 0 {
            parts.push(format!("{} min max", g.max_session_minutes));
        }
        if g.idle_timeout_minutes > 0 {
            parts.push(format!("{} min idle", g.idle_timeout_minutes));
        }
        if g.allowed_hours.is_some() {
            parts.push("allowed hours".into());
        }
        if !g.blocked_paths.is_empty() {
            parts.push(format!("{} blocked path(s)", g.blocked_paths.len()));
        }
        if parts.is_empty() {
            s.push_str(" (no guardrails)");
        } else {
            s.push_str(&format!(" ({})", parts.join(", ")));
        }
        let mut c = s.chars();
        match c.next() {
            Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
            None => s,
        }
    }
}

/// What a file operation needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileOpClass {
    /// list, stat, download.
    Read,
    /// upload (write_*), mkdir.
    Write,
    /// delete, rename / move.
    Delete,
}

pub fn file_op_class(op: &FileOp) -> FileOpClass {
    match op {
        FileOp::List { .. } | FileOp::Stat { .. } | FileOp::ReadChunk { .. } | FileOp::Unknown => {
            FileOpClass::Read
        }
        FileOp::WriteBegin { .. }
        | FileOp::WriteChunk { .. }
        | FileOp::WriteEnd { .. }
        | FileOp::WriteAbort
        | FileOp::Mkdir { .. } => FileOpClass::Write,
        FileOp::Rename { .. } | FileOp::Delete { .. } => FileOpClass::Delete,
    }
}

/// Context the server attaches to file requests: one file-manager session
/// (the console's Files tab) shares one consent prompt and one reason.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileContext {
    /// Console file-manager session id (consent is granted per session).
    pub fm_session: uuid::Uuid,
    /// Display name of the admin (consent prompt, tray notice).
    #[serde(default)]
    pub admin_name: String,
    #[serde(default)]
    pub reason: String,
}

// --------------------------------------------------------------- path rules

/// Why a remote path was refused by [`validate_remote_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathError(pub String);

impl std::fmt::Display for PathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate and normalise a remote file-manager path (shared by server and
/// agent). Accepts `X:\` (drive root) and `X:\a\b` (absolute, `/` allowed
/// as separator). Returns the normalised path: upper-case drive letter,
/// backslashes, no duplicate or trailing separators (except the root).
///
/// Refused: empty, relative, UNC / device / NT paths, NUL or other control
/// characters, `.` / `..` components, a `:` after the drive (alternate data
/// streams), components ending in `.` or space (Win32 strips them, so they
/// could alias another name), wildcard characters `*?"<>|`, more than
/// [`PATH_MAX_CHARS`] characters.
pub fn validate_remote_path(p: &str) -> Result<String, PathError> {
    let err = |m: &str| Err(PathError(m.to_string()));
    if p.is_empty() {
        return err("path is empty");
    }
    if p.chars().count() > PATH_MAX_CHARS {
        return err("path is too long");
    }
    if p.chars().any(|c| c.is_control()) {
        return err("path contains control characters");
    }
    let s = p.replace('/', "\\");
    let b = s.as_bytes();
    if b.len() < 2 || !b[0].is_ascii_alphabetic() || b[1] != b':' {
        return err("path must be absolute and start with a drive letter (e.g. C:\\)");
    }
    if b.len() == 2 {
        // "C:" alone is drive-relative; treat as the root.
        return Ok(format!("{}:\\", (b[0] as char).to_ascii_uppercase()));
    }
    if b[2] != b'\\' {
        return err("path must be absolute (X:\\…)");
    }
    let drive = (b[0] as char).to_ascii_uppercase();
    let mut out = format!("{drive}:");
    for comp in s[3..].split('\\') {
        if comp.is_empty() {
            continue;
        }
        if comp == "." || comp == ".." {
            return err("path must not contain '.' or '..' components");
        }
        if comp.contains(':') {
            return err("path must not contain ':' after the drive (alternate data streams)");
        }
        if comp
            .chars()
            .any(|c| matches!(c, '*' | '?' | '"' | '<' | '>' | '|'))
        {
            return err("path contains a character Windows does not allow in names");
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            return err("path components must not end with a dot or a space");
        }
        out.push('\\');
        out.push_str(comp);
    }
    if out.len() == 2 {
        out.push('\\');
    }
    Ok(out)
}

/// Is `path` (normalised by [`validate_remote_path`]) equal to or inside
/// `root`? Case-insensitive, component-wise.
pub fn path_is_within(path: &str, root: &str) -> bool {
    let norm = |s: &str| s.replace('/', "\\").trim_end_matches('\\').to_lowercase();
    let (p, r) = (norm(path), norm(root));
    if r.is_empty() {
        return false;
    }
    p == r || p.starts_with(&format!("{r}\\"))
}

/// Last component of a path (file name for `Content-Disposition`, etc.).
pub fn file_name_of(path: &str) -> &str {
    let t = path.trim_end_matches(['\\', '/']);
    t.rsplit(['\\', '/']).next().unwrap_or(t)
}

/// Parent folder of a normalised path (`None` for a drive root).
pub fn parent_of(path: &str) -> Option<String> {
    let t = path.trim_end_matches('\\');
    let i = t.rfind('\\')?;
    if i <= 2 {
        // "C:\x" → "C:\"
        Some(format!("{}\\", &t[..2]))
    } else {
        Some(t[..i].to_string())
    }
}

// ---------------------------------------------------------- browser (WS) API

/// Text messages the console sends on the remote-desktop WebSocket.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopClientMsg {
    Input {
        event: InputEvent,
    },
    Settings(DesktopSettings),
    /// Admin activity without input (e.g. mouse over a view-only canvas):
    /// resets the idle timeout.
    Activity,
    /// Keep-alive (does not reset the idle timeout).
    Ping,
    Stop,
    #[serde(other)]
    Unknown,
}

/// Text messages the server sends on the remote-desktop WebSocket. Frames
/// are binary messages: 16-byte header (big-endian `u32 seq`, `u16 width`,
/// `u16 height`, `u64 agent ts ms`) followed by the JPEG bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DesktopServerMsg {
    /// Session id assigned by the server; the agent is starting capture.
    Starting {
        session_id: String,
        view_only: bool,
    },
    /// The employee is being asked to allow the session (up to `timeout_secs`).
    ConsentPending {
        timeout_secs: u32,
    },
    /// Outcome of a consent prompt (start, or a later switch to control).
    ConsentResult {
        allowed: bool,
        #[serde(default)]
        code: Option<RemoteErrorCode>,
    },
    Started(DesktopInfo),
    Info(DesktopInfo),
    Ended {
        reason: String,
        #[serde(default)]
        code: Option<RemoteErrorCode>,
    },
    Error {
        message: String,
    },
    Pong,
}

/// Header length of a binary frame message on the WebSocket.
pub const WS_FRAME_HEADER: usize = 16;

/// Build the 16-byte WS frame header.
pub fn ws_frame_header(
    seq: u64,
    width: u32,
    height: u32,
    ts: TimestampMs,
) -> [u8; WS_FRAME_HEADER] {
    let mut h = [0u8; WS_FRAME_HEADER];
    h[0..4].copy_from_slice(&(seq as u32).to_be_bytes());
    h[4..6].copy_from_slice(&(width.min(u16::MAX as u32) as u16).to_be_bytes());
    h[6..8].copy_from_slice(&(height.min(u16::MAX as u32) as u16).to_be_bytes());
    h[8..16].copy_from_slice(&(ts.max(0) as u64).to_be_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_validated_and_normalised() {
        assert_eq!(validate_remote_path("c:").unwrap(), "C:\\");
        assert_eq!(validate_remote_path("c:\\").unwrap(), "C:\\");
        assert_eq!(
            validate_remote_path("c:/Users//bob/").unwrap(),
            "C:\\Users\\bob"
        );
        assert_eq!(
            validate_remote_path("D:\\a b\\c.txt").unwrap(),
            "D:\\a b\\c.txt"
        );
        for bad in [
            "",
            "Users\\bob",
            "\\\\server\\share\\x",
            "\\\\?\\C:\\x",
            "\\\\.\\PhysicalDrive0",
            "C:x",
            "C:\\a\\..\\Windows",
            "C:\\a\\.\\b",
            "C:\\a\\file.txt:stream",
            "C:\\a\\b.",
            "C:\\a\\b ",
            "C:\\a\\b*",
            "C:\\a\u{0}b",
            "1:\\x",
        ] {
            assert!(
                validate_remote_path(bad).is_err(),
                "{bad:?} should be refused"
            );
        }
        let long = format!("C:\\{}", "a".repeat(PATH_MAX_CHARS));
        assert!(validate_remote_path(&long).is_err());
    }

    #[test]
    fn within_and_parents() {
        assert!(path_is_within(
            "C:\\Program Files\\Kestrel",
            "c:\\program files\\kestrel"
        ));
        assert!(path_is_within(
            "C:\\Program Files\\Kestrel\\x.exe",
            "C:\\Program Files\\Kestrel\\"
        ));
        assert!(!path_is_within(
            "C:\\Program Files\\Kestrel2",
            "C:\\Program Files\\Kestrel"
        ));
        assert!(!path_is_within("C:\\x", ""));
        assert_eq!(parent_of("C:\\a\\b").as_deref(), Some("C:\\a"));
        assert_eq!(parent_of("C:\\a").as_deref(), Some("C:\\"));
        assert_eq!(parent_of("C:\\"), None);
        assert_eq!(file_name_of("C:\\a\\b.txt"), "b.txt");
    }

    #[test]
    fn unknown_variants_are_tolerated() {
        let m: LiveServerMsg = serde_json::from_str(r#"{"type":"hologram","x":1}"#).unwrap();
        assert_eq!(m, LiveServerMsg::Unknown);
        let m: LiveAgentMsg = serde_json::from_str(r#"{"type":"smell"}"#).unwrap();
        assert_eq!(m, LiveAgentMsg::Unknown);
        let op: FileOp = serde_json::from_str(r#"{"op":"chmod"}"#).unwrap();
        assert_eq!(op, FileOp::Unknown);
        let c: RemoteErrorCode = serde_json::from_str(r#""brand_new""#).unwrap();
        assert_eq!(c, RemoteErrorCode::Other);
    }

    #[test]
    fn json_shapes() {
        let m = LiveServerMsg::FileRequest {
            request_id: 7,
            op: FileOp::Delete {
                path: "C:\\x".into(),
                recursive: true,
            },
            context: None,
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["type"], "file_request");
        assert_eq!(v["op"]["op"], "delete");
        let fm = uuid::Uuid::new_v4();
        let end = LiveServerMsg::FileSessionEnd {
            fm_session: fm,
            admin_name: "Jane Doe".into(),
        };
        let v = serde_json::to_value(&end).unwrap();
        assert_eq!(v["type"], "file_session_end");
        assert_eq!(v["fm_session"], fm.to_string());
        let back: LiveServerMsg = serde_json::from_str(&format!(
            r#"{{"type":"file_session_end","fm_session":"{fm}"}}"#
        ))
        .unwrap();
        assert_eq!(
            back,
            LiveServerMsg::FileSessionEnd {
                fm_session: fm,
                admin_name: String::new()
            }
        );
        let r = LiveAgentMsg::FileReply {
            request_id: 7,
            reply: FileReply::error(RemoteErrorCode::ProtectedPath, "no"),
        };
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["reply"]["result"], "error");
        assert_eq!(v["reply"]["code"], "protected_path");
        let s: DesktopSettings = serde_json::from_str("{}").unwrap();
        assert_eq!(s, DesktopSettings::default());
        let i = InputEvent::MouseMove {
            x: 2.0,
            y: f32::NAN,
        }
        .sanitized();
        assert!(i.is_none());
        let i = InputEvent::MouseMove { x: 2.0, y: -1.0 }
            .sanitized()
            .unwrap();
        assert_eq!(i, InputEvent::MouseMove { x: 1.0, y: 0.0 });
        assert!(InputEvent::Key {
            code: "Key A".into(),
            down: true
        }
        .sanitized()
        .is_none());
        let h = ws_frame_header(258, 1920, 1080, 5);
        assert_eq!(&h[0..4], &[0, 0, 1, 2]);
        assert_eq!(u16::from_be_bytes([h[4], h[5]]), 1920);
    }

    #[test]
    fn presets() {
        let n = RemoteAccessProfile::none();
        assert!(n.is_none());
        assert_eq!(n.preset(), RemoteProfilePreset::None);
        assert_eq!(RemoteAccessProfile::default(), n);
        let u = RemoteAccessProfile::unrestricted();
        assert_eq!((u.desktop, u.files), (DesktopMode::Control, FileMode::Full));
        let g = &u.guardrails;
        assert!(!g.require_consent && !g.require_reason && !g.require_mfa_reauth);
        assert!(g.allow_upload && g.allow_delete);
        assert_eq!((g.max_session_minutes, g.idle_timeout_minutes), (0, 0));
        assert!(g.allowed_hours.is_none() && g.blocked_paths.is_empty());
        assert_eq!(u.preset(), RemoteProfilePreset::Unrestricted);
        let gd = RemoteAccessProfile::guarded_default();
        let g = &gd.guardrails;
        assert!(g.require_consent && g.require_reason && g.require_mfa_reauth);
        assert!(g.allow_upload && !g.allow_delete);
        assert_eq!((g.max_session_minutes, g.idle_timeout_minutes), (60, 15));
        assert_eq!(
            g.blocked_paths,
            vec![r"C:\Windows\System32\config".to_string()]
        );
        assert_eq!(gd.preset(), RemoteProfilePreset::Guarded);
        for p in [&n, &u, &gd] {
            p.validate().unwrap();
            let back: RemoteAccessProfile =
                serde_json::from_value(serde_json::to_value(p).unwrap()).unwrap();
            assert_eq!(&back, p);
        }
        assert_eq!(n.summary(), "No remote access");
        assert!(u.summary().contains("no guardrails"), "{}", u.summary());
        assert!(gd.summary().contains("no delete"), "{}", gd.summary());
    }

    #[test]
    fn serde_back_compat() {
        // Older policy / token / enroll response JSON without the field.
        let p: crate::Policy =
            serde_json::from_str(r#"{"id":"x","name":"x","version":1}"#).unwrap();
        assert_eq!(p.remote_access, RemoteAccessProfile::none());
        let e: crate::wire::EnrollResponse = serde_json::from_str(
            r#"{"device_id":"00000000-0000-0000-0000-000000000000","cert_pem":"c","ca_pem":"a"}"#,
        )
        .unwrap();
        assert!(e.remote_profile.is_none());
        // Missing guardrail fields take the strict (guarded) defaults.
        let p: RemoteAccessProfile =
            serde_json::from_str(r#"{"desktop":"control","files":"full"}"#).unwrap();
        assert_eq!(p, RemoteAccessProfile::guarded_default());
        let p: RemoteAccessProfile =
            serde_json::from_str(r#"{"desktop":"view_only","files":"read_only","guardrails":{}}"#)
                .unwrap();
        assert_eq!(
            (p.desktop, p.files),
            (DesktopMode::ViewOnly, FileMode::ReadOnly)
        );
        assert!(p.guardrails.require_consent);
        let h: crate::wire::Hello = serde_json::from_value(serde_json::json!({
            "device_id": "00000000-0000-0000-0000-000000000000", "agent_version": "1",
            "hostname": "h", "os": {"name":"w","build":"1","arch":"x64"}, "boot_id": "b",
            "policy_version": 1, "rules_version": 1
        }))
        .unwrap();
        assert!(h.remote_ceiling.is_none() && h.capabilities.is_empty());
    }

    #[test]
    fn intersection_is_stricter_wins() {
        let u = RemoteAccessProfile::unrestricted();
        let n = RemoteAccessProfile::none();
        let g = RemoteAccessProfile::guarded_default();
        // none caps everything
        assert!(u.intersect(&n).is_none());
        assert!(n.intersect(&u).is_none());
        // unrestricted ∩ guarded = guarded
        assert_eq!(u.intersect(&g), g);
        assert_eq!(g.intersect(&u), g);
        // modes take the minimum
        let mut v = u.clone();
        v.desktop = DesktopMode::ViewOnly;
        v.files = FileMode::ReadOnly;
        let e = u.intersect(&v);
        assert_eq!(
            (e.desktop, e.files),
            (DesktopMode::ViewOnly, FileMode::ReadOnly)
        );
        // limits: smaller non-zero; booleans
        let mut a = RemoteAccessProfile::unrestricted();
        a.guardrails.max_session_minutes = 30;
        a.guardrails.consent_timeout_secs = 0;
        a.guardrails.blocked_paths = vec!["c:/secret".into()];
        let mut b = RemoteAccessProfile::unrestricted();
        b.guardrails.max_session_minutes = 120;
        b.guardrails.idle_timeout_minutes = 5;
        b.guardrails.consent_timeout_secs = 20;
        b.guardrails.require_reason = true;
        b.guardrails.allow_delete = false;
        b.guardrails.blocked_paths = vec![r"C:\Secret".into(), r"D:\x".into()];
        let e = a.intersect(&b);
        assert_eq!(e, b.intersect(&a), "commutative");
        let eg = &e.guardrails;
        assert_eq!(eg.max_session_minutes, 30);
        assert_eq!(eg.idle_timeout_minutes, 5);
        assert_eq!(eg.consent_timeout_secs, 20);
        assert!(eg.require_reason && !eg.require_consent && !eg.allow_delete && eg.allow_upload);
        assert_eq!(eg.blocked_paths.len(), 2, "{:?}", eg.blocked_paths);
        assert!(eg.blocked_prefix(r"C:\SECRET\a.txt").is_some());
        assert!(eg.blocked_prefix(r"C:\secretive").is_none());
        // hours
        let mut h1 = RemoteAccessProfile::unrestricted();
        h1.guardrails.allowed_hours = Some(AllowedHours {
            days: vec![0, 1, 2, 3, 4],
            start_minute: 8 * 60,
            end_minute: 18 * 60,
        });
        let mut h2 = RemoteAccessProfile::unrestricted();
        h2.guardrails.allowed_hours = Some(AllowedHours {
            days: vec![4, 5],
            start_minute: 9 * 60,
            end_minute: 20 * 60,
        });
        let e = h1.intersect(&h2).guardrails.allowed_hours.unwrap();
        assert_eq!(e.days, vec![4]);
        assert_eq!((e.start_minute, e.end_minute), (540, 1080));
        assert!(e.contains(4, 600) && !e.contains(3, 600) && !e.contains(4, 1080));
        assert_eq!(
            h1.intersect(&u).guardrails.allowed_hours,
            h1.guardrails.allowed_hours
        );
        let mut h3 = RemoteAccessProfile::unrestricted();
        h3.guardrails.allowed_hours = Some(AllowedHours {
            days: vec![6],
            start_minute: 0,
            end_minute: 60,
        });
        assert!(h1
            .intersect(&h3)
            .guardrails
            .allowed_hours
            .unwrap()
            .is_empty());
    }

    #[test]
    fn file_op_permissions() {
        let rd = FileOp::ReadChunk {
            path: "C:\\a".into(),
            offset: 0,
            len: 1,
        };
        let up = FileOp::WriteBegin {
            path: "C:\\a".into(),
            size: 1,
        };
        let del = FileOp::Delete {
            path: "C:\\a".into(),
            recursive: false,
        };
        let mv = FileOp::Rename {
            from: "C:\\a".into(),
            to: "C:\\b".into(),
            overwrite: false,
        };
        let n = RemoteAccessProfile::none();
        assert!(n.file_op_permitted(&rd).is_err());
        let mut ro = RemoteAccessProfile::unrestricted();
        ro.files = FileMode::ReadOnly;
        assert!(ro.file_op_permitted(&rd).is_ok());
        assert!(ro.file_op_permitted(&up).is_err());
        assert!(ro.file_op_permitted(&del).is_err());
        let g = RemoteAccessProfile::guarded_default();
        assert!(g.file_op_permitted(&up).is_ok());
        assert!(g.file_op_permitted(&del).is_err());
        assert!(g.file_op_permitted(&mv).is_err());
        assert!(RemoteAccessProfile::unrestricted()
            .file_op_permitted(&mv)
            .is_ok());
        let mut bad = g.clone();
        bad.guardrails.allowed_hours = Some(AllowedHours {
            days: vec![7],
            start_minute: 0,
            end_minute: 10,
        });
        assert!(bad.validate().is_err());
        bad.guardrails.allowed_hours = None;
        bad.guardrails.blocked_paths = vec!["\\\\srv\\share".into()];
        assert!(bad.validate().is_err());
    }
}
