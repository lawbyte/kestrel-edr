//! Pipe protocol between the agent service and the remote-desktop helper
//! (`kestrel-agent desktop-helper --pipe <name> --parent <pid>`), plus the
//! employee banner text. Platform independent and unit-tested everywhere.
//!
//! Framing: `u32` little-endian length (of `kind` + payload), `u8 kind`,
//! payload. A message longer than [`MAX_MESSAGE`] or with length 0 is a
//! protocol error (the reader closes the pipe). Malformed input never panics.
//!
//! Helper → agent: `Hello{pid}`, `Info(DesktopInfo JSON)`,
//! `Frame{width, height, ts, jpeg}` (16-byte binary header + raw JPEG),
//! `Error(text)`, `Log(text)`, `BannerShown` (the banner window is on
//! screen; sent once, before anything is captured).
//! Agent → helper: `Settings(JSON)`, `Input(InputEvent JSON)`,
//! `FrameAck{accepted}` (one per `Frame`: the helper sends the next frame only
//! after the ack, and compares change detection against the last *accepted*
//! frame), `Stop`.

use kestrel_common::remote::{DesktopInfo, DesktopSettings, InputEvent};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Every desktop pipe name starts with this (the helper refuses anything else).
pub const PIPE_PREFIX: &str = r"\\.\pipe\kestrel-desktop-";
/// Per-session pipe DACL: SYSTEM only (agent service and helper both run as
/// SYSTEM).
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)";
/// Largest message (length field value) accepted on the pipe.
pub const MAX_MESSAGE: usize = 2 * 1024 * 1024;
/// Longest `Error` / `Log` text kept (chars).
pub const MAX_TEXT: usize = 4096;

pub mod kind {
    pub const HELLO: u8 = 0x01;
    pub const INFO: u8 = 0x02;
    pub const FRAME: u8 = 0x03;
    pub const ERROR: u8 = 0x04;
    pub const LOG: u8 = 0x05;
    pub const BANNER_SHOWN: u8 = 0x06;
    pub const SETTINGS: u8 = 0x81;
    pub const INPUT: u8 = 0x82;
    pub const FRAME_ACK: u8 = 0x83;
    pub const STOP: u8 = 0x84;
}

/// `name` is `\\.\pipe\kestrel-desktop-<32 lower-case hex>`.
pub fn is_valid_pipe_name(name: &str) -> bool {
    match name.strip_prefix(PIPE_PREFIX) {
        Some(rest) => {
            rest.len() == 32
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// Pipe name for 16 random bytes.
pub fn pipe_name_from(random: &[u8; 16]) -> String {
    let mut s = String::from(PIPE_PREFIX);
    for b in random {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// What the helper needs: capture settings plus the banner fields.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct HelperSettings {
    pub quality: u8,
    pub scale_pct: u8,
    pub max_fps: u8,
    #[serde(default)]
    pub view_only: bool,
    #[serde(default)]
    pub admin_name: String,
    #[serde(default)]
    pub reason: String,
    /// Banner only (remote file manager without a desktop session): the
    /// helper shows the banner and nothing else (no capture, no input).
    #[serde(default)]
    pub banner_only: bool,
    /// Remote file-manager notice composed by the agent ("IT (Jane Doe) is
    /// accessing files on this PC since 14:02"); empty = none. Banner-only:
    /// the whole text; desktop session: an extra part of the banner.
    #[serde(default)]
    pub files_notice: String,
}

/// Longest file-manager notice shown (chars).
pub const FILES_NOTICE_MAX: usize = 300;

impl HelperSettings {
    pub fn new(view_only: bool, admin_name: &str, reason: &str, s: &DesktopSettings) -> Self {
        let c = s.clamped();
        HelperSettings {
            quality: c.quality,
            scale_pct: c.scale_pct,
            max_fps: c.max_fps,
            view_only: c.view_only.unwrap_or(view_only),
            admin_name: admin_name.to_string(),
            reason: reason.to_string(),
            banner_only: false,
            files_notice: String::new(),
        }
    }

    /// Settings of a banner-only helper showing `files_notice`.
    pub fn banner_only(files_notice: &str) -> Self {
        HelperSettings {
            banner_only: true,
            files_notice: files_notice.to_string(),
            ..HelperSettings::new(true, "", "", &DesktopSettings::default())
        }
    }

    /// Apply a mid-session settings change (`view_only: None` = unchanged).
    pub fn apply(&mut self, s: &DesktopSettings) {
        let c = s.clamped();
        self.quality = c.quality;
        self.scale_pct = c.scale_pct;
        self.max_fps = c.max_fps;
        if let Some(v) = c.view_only {
            self.view_only = v;
        }
    }

    /// Clamp into the documented ranges (the helper never trusts the wire).
    pub fn clamped(&self) -> Self {
        HelperSettings {
            quality: self.quality.clamp(30, 90),
            scale_pct: self.scale_pct.clamp(25, 100),
            max_fps: self.max_fps.clamp(1, 15),
            view_only: self.view_only,
            admin_name: self.admin_name.clone(),
            reason: self.reason.clone(),
            banner_only: self.banner_only,
            files_notice: self
                .files_notice
                .chars()
                .take(FILES_NOTICE_MAX * 4)
                .collect(),
        }
    }
}

/// Helper → agent.
#[derive(Clone, Debug, PartialEq)]
pub enum HelperMsg {
    Hello {
        pid: u32,
    },
    Info(DesktopInfo),
    Frame {
        width: u32,
        height: u32,
        ts: i64,
        jpeg: Vec<u8>,
    },
    Error(String),
    Log(String),
    /// The banner window is on screen.
    BannerShown,
}

/// Agent → helper.
#[derive(Clone, Debug, PartialEq)]
pub enum AgentMsg {
    Settings(HelperSettings),
    Input(InputEvent),
    FrameAck { accepted: bool },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Length field is 0.
    Empty,
    /// Length field above [`MAX_MESSAGE`].
    TooLarge(usize),
    UnknownKind(u8),
    Malformed(&'static str),
    Json(String),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Empty => f.write_str("empty message"),
            ProtoError::TooLarge(n) => write!(f, "message of {n} bytes exceeds the limit"),
            ProtoError::UnknownKind(k) => write!(f, "unknown message kind {k:#04x}"),
            ProtoError::Malformed(m) => write!(f, "malformed message: {m}"),
            ProtoError::Json(e) => write!(f, "bad JSON payload: {e}"),
        }
    }
}

impl std::error::Error for ProtoError {}

/// Frame one message.
pub fn encode_raw(kind: u8, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    let len = payload.len() + 1;
    if len > MAX_MESSAGE {
        return Err(ProtoError::TooLarge(len));
    }
    let mut v = Vec::with_capacity(4 + len);
    v.extend_from_slice(&(len as u32).to_le_bytes());
    v.push(kind);
    v.extend_from_slice(payload);
    Ok(v)
}

fn json<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtoError> {
    serde_json::to_vec(v).map_err(|e| ProtoError::Json(e.to_string()))
}

fn from_json<'a, T: Deserialize<'a>>(b: &'a [u8]) -> Result<T, ProtoError> {
    serde_json::from_slice(b).map_err(|e| ProtoError::Json(e.to_string()))
}

fn clip_text(s: &str) -> String {
    s.chars().take(MAX_TEXT).collect()
}

impl HelperMsg {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        match self {
            HelperMsg::Hello { pid } => encode_raw(kind::HELLO, &pid.to_le_bytes()),
            HelperMsg::Info(i) => encode_raw(kind::INFO, &json(i)?),
            HelperMsg::Frame {
                width,
                height,
                ts,
                jpeg,
            } => {
                let mut p = Vec::with_capacity(16 + jpeg.len());
                p.extend_from_slice(&width.to_le_bytes());
                p.extend_from_slice(&height.to_le_bytes());
                p.extend_from_slice(&ts.to_le_bytes());
                p.extend_from_slice(jpeg);
                encode_raw(kind::FRAME, &p)
            }
            HelperMsg::Error(t) => encode_raw(kind::ERROR, clip_text(t).as_bytes()),
            HelperMsg::Log(t) => encode_raw(kind::LOG, clip_text(t).as_bytes()),
            HelperMsg::BannerShown => encode_raw(kind::BANNER_SHOWN, &[]),
        }
    }

    pub fn decode(k: u8, p: &[u8]) -> Result<HelperMsg, ProtoError> {
        Ok(match k {
            kind::HELLO => {
                let b: [u8; 4] = p
                    .try_into()
                    .map_err(|_| ProtoError::Malformed("hello must carry 4 bytes"))?;
                HelperMsg::Hello {
                    pid: u32::from_le_bytes(b),
                }
            }
            kind::INFO => HelperMsg::Info(from_json(p)?),
            kind::FRAME => {
                if p.len() <= 16 {
                    return Err(ProtoError::Malformed("frame without image data"));
                }
                let u = |i: usize| u32::from_le_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
                let mut ts = [0u8; 8];
                ts.copy_from_slice(&p[8..16]);
                let (width, height) = (u(0), u(4));
                if width == 0 || height == 0 || width > 65_535 || height > 65_535 {
                    return Err(ProtoError::Malformed("frame size out of range"));
                }
                HelperMsg::Frame {
                    width,
                    height,
                    ts: i64::from_le_bytes(ts),
                    jpeg: p[16..].to_vec(),
                }
            }
            kind::ERROR => HelperMsg::Error(clip_text(&String::from_utf8_lossy(p))),
            kind::LOG => HelperMsg::Log(clip_text(&String::from_utf8_lossy(p))),
            kind::BANNER_SHOWN => HelperMsg::BannerShown,
            other => return Err(ProtoError::UnknownKind(other)),
        })
    }
}

impl AgentMsg {
    pub fn encode(&self) -> Result<Vec<u8>, ProtoError> {
        match self {
            AgentMsg::Settings(s) => encode_raw(kind::SETTINGS, &json(s)?),
            AgentMsg::Input(e) => encode_raw(kind::INPUT, &json(e)?),
            AgentMsg::FrameAck { accepted } => encode_raw(kind::FRAME_ACK, &[*accepted as u8]),
            AgentMsg::Stop => encode_raw(kind::STOP, &[]),
        }
    }

    pub fn decode(k: u8, p: &[u8]) -> Result<AgentMsg, ProtoError> {
        Ok(match k {
            kind::SETTINGS => AgentMsg::Settings(from_json::<HelperSettings>(p)?.clamped()),
            kind::INPUT => AgentMsg::Input(from_json(p)?),
            kind::FRAME_ACK => match p {
                [b] => AgentMsg::FrameAck { accepted: *b != 0 },
                _ => return Err(ProtoError::Malformed("frame ack must carry 1 byte")),
            },
            kind::STOP => AgentMsg::Stop,
            other => return Err(ProtoError::UnknownKind(other)),
        })
    }
}

/// Incremental decoder for a byte stream.
#[derive(Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Bytes buffered but not yet returned.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }

    /// Next complete message `(kind, payload)`, `None` if more bytes are
    /// needed. After an error the stream must be abandoned.
    pub fn next_raw(&mut self) -> Result<Option<(u8, Vec<u8>)>, ProtoError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len == 0 {
            return Err(ProtoError::Empty);
        }
        if len > MAX_MESSAGE {
            return Err(ProtoError::TooLarge(len));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let k = self.buf[4];
        let payload = self.buf[5..4 + len].to_vec();
        self.buf.drain(..4 + len);
        Ok(Some((k, payload)))
    }
}

/// Read the next raw message from an async stream. `Ok(None)` = clean EOF
/// between messages; EOF inside a message is `UnexpectedEof`.
pub async fn read_raw<R: AsyncRead + Unpin>(
    r: &mut R,
    dec: &mut Decoder,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        match dec.next_raw() {
            Ok(Some(m)) => return Ok(Some(m)),
            Ok(None) => {}
            Err(e) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    e.to_string(),
                ))
            }
        }
        let n = r.read(&mut chunk).await?;
        if n == 0 {
            return if dec.pending() == 0 {
                Ok(None)
            } else {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            };
        }
        dec.push(&chunk[..n]);
    }
}

/// Write one already-encoded message and flush.
pub async fn write_raw<W: AsyncWrite + Unpin>(w: &mut W, bytes: &[u8]) -> std::io::Result<()> {
    w.write_all(bytes).await?;
    w.flush().await
}

fn clean(s: &str, max: usize) -> String {
    let t: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > max {
        let mut c: String = t.chars().take(max.saturating_sub(1)).collect();
        c.push('…');
        c
    } else {
        t
    }
}

/// Employee banner text: "IT (Jane Doe) is viewing this PC — Reason: …".
pub fn banner_text(admin_name: &str, view_only: bool, reason: &str) -> String {
    let who = clean(admin_name, 64);
    let verb = if view_only { "viewing" } else { "controlling" };
    let mut s = if who.is_empty() {
        format!("IT is {verb} this PC")
    } else {
        format!("IT ({who}) is {verb} this PC")
    };
    let r = clean(reason, 200);
    if !r.is_empty() {
        s.push_str(" \u{2014} Reason: ");
        s.push_str(&r);
    }
    s
}

/// The banner text for `s`: the desktop text ([`banner_text`]) with the
/// file-manager notice appended, or (banner-only) the notice alone.
pub fn helper_banner_text(s: &HelperSettings) -> String {
    let files = clean(&s.files_notice, FILES_NOTICE_MAX);
    if s.banner_only {
        return if files.is_empty() {
            "IT is accessing files on this PC".to_string()
        } else {
            files
        };
    }
    let mut t = banner_text(&s.admin_name, s.view_only, &s.reason);
    if !files.is_empty() {
        t.push_str("  |  ");
        t.push_str(&files);
    }
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_common::remote::MouseButton;

    fn roundtrip_helper(m: HelperMsg) -> HelperMsg {
        let bytes = m.encode().unwrap();
        let mut d = Decoder::new();
        d.push(&bytes);
        let (k, p) = d.next_raw().unwrap().unwrap();
        assert_eq!(d.pending(), 0);
        HelperMsg::decode(k, &p).unwrap()
    }

    fn roundtrip_agent(m: AgentMsg) -> AgentMsg {
        let bytes = m.encode().unwrap();
        let mut d = Decoder::new();
        d.push(&bytes);
        let (k, p) = d.next_raw().unwrap().unwrap();
        AgentMsg::decode(k, &p).unwrap()
    }

    #[test]
    fn messages_roundtrip() {
        for m in [
            HelperMsg::Hello { pid: 4242 },
            HelperMsg::Info(DesktopInfo {
                width: 3840,
                height: 1080,
                monitors: 2,
                session_id: Some(1),
                secure_desktop: true,
                view_only: false,
            }),
            HelperMsg::Frame {
                width: 1920,
                height: 1080,
                ts: 1_700_000_000_123,
                jpeg: vec![0xFF, 0xD8, 1, 2, 3],
            },
            HelperMsg::Error("boom".into()),
            HelperMsg::Log("note".into()),
            HelperMsg::BannerShown,
        ] {
            assert_eq!(roundtrip_helper(m.clone()), m);
        }
        let s = HelperSettings::new(true, "Jane", "ticket 7", &DesktopSettings::default());
        let mut f = HelperSettings::banner_only("IT (Jane) is accessing files on this PC");
        f.files_notice.push_str(" since 14:02");
        for m in [
            AgentMsg::Settings(s),
            AgentMsg::Settings(f),
            AgentMsg::Input(InputEvent::MouseButton {
                x: 0.5,
                y: 0.25,
                button: MouseButton::X2,
                down: true,
            }),
            AgentMsg::Input(InputEvent::Text {
                text: "héllo 😀".into(),
            }),
            AgentMsg::FrameAck { accepted: true },
            AgentMsg::FrameAck { accepted: false },
            AgentMsg::Stop,
        ] {
            assert_eq!(roundtrip_agent(m.clone()), m);
        }
    }

    #[test]
    fn decoder_handles_split_and_batched_input() {
        let mut all = Vec::new();
        all.extend(HelperMsg::Hello { pid: 1 }.encode().unwrap());
        all.extend(HelperMsg::Log("x".into()).encode().unwrap());
        let mut d = Decoder::new();
        let mut got = Vec::new();
        for b in &all {
            d.push(std::slice::from_ref(b));
            while let Some((k, p)) = d.next_raw().unwrap() {
                got.push(HelperMsg::decode(k, &p).unwrap());
            }
        }
        assert_eq!(
            got,
            vec![HelperMsg::Hello { pid: 1 }, HelperMsg::Log("x".into())]
        );
    }

    #[test]
    fn bounds_and_malformed_input() {
        // Length 0, oversized length.
        let mut d = Decoder::new();
        d.push(&[0, 0, 0, 0]);
        assert_eq!(d.next_raw(), Err(ProtoError::Empty));
        let mut d = Decoder::new();
        d.push(&((MAX_MESSAGE as u32) + 1).to_le_bytes());
        assert_eq!(d.next_raw(), Err(ProtoError::TooLarge(MAX_MESSAGE + 1)));
        let mut d = Decoder::new();
        d.push(&u32::MAX.to_le_bytes());
        assert!(matches!(d.next_raw(), Err(ProtoError::TooLarge(_))));
        // Exactly at the limit is fine to encode; above is not.
        assert!(encode_raw(kind::LOG, &vec![b'a'; MAX_MESSAGE - 1]).is_ok());
        assert!(encode_raw(kind::LOG, &vec![b'a'; MAX_MESSAGE]).is_err());
        let big = HelperMsg::Frame {
            width: 1,
            height: 1,
            ts: 0,
            jpeg: vec![0; MAX_MESSAGE],
        };
        assert!(big.encode().is_err());
        // Partial header / body → need more.
        let mut d = Decoder::new();
        d.push(&[5, 0]);
        assert_eq!(d.next_raw(), Ok(None));
        d.push(&[0, 0, kind::HELLO, 1]);
        assert_eq!(d.next_raw(), Ok(None));
        // Payload decoding never panics on junk.
        assert!(HelperMsg::decode(kind::HELLO, &[1, 2]).is_err());
        assert!(HelperMsg::decode(kind::FRAME, &[0; 16]).is_err());
        let mut zero_size = vec![0u8; 17];
        zero_size[16] = 0xFF;
        assert!(HelperMsg::decode(kind::FRAME, &zero_size).is_err());
        assert!(HelperMsg::decode(kind::INFO, b"{not json").is_err());
        assert!(HelperMsg::decode(0x7F, b"").is_err());
        assert!(AgentMsg::decode(kind::FRAME_ACK, &[]).is_err());
        assert!(AgentMsg::decode(kind::INPUT, b"[]").is_err());
        assert!(AgentMsg::decode(kind::HELLO, &[0; 4]).is_err());
        assert_eq!(
            HelperMsg::decode(kind::ERROR, &[0xFF, 0xFE, b'a']).unwrap(),
            HelperMsg::Error("\u{FFFD}\u{FFFD}a".into())
        );
        // Settings from the wire are clamped.
        let s = br#"{"quality":200,"scale_pct":1,"max_fps":0}"#;
        match AgentMsg::decode(kind::SETTINGS, s).unwrap() {
            AgentMsg::Settings(h) => {
                assert_eq!((h.quality, h.scale_pct, h.max_fps), (90, 25, 1));
                assert!(!h.view_only);
            }
            other => panic!("{other:?}"),
        }
        // Long log text is clipped.
        let t = "x".repeat(MAX_TEXT + 50);
        match roundtrip_helper(HelperMsg::Log(t)) {
            HelperMsg::Log(s) => assert_eq!(s.len(), MAX_TEXT),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn async_stream_read_write() {
        let (mut a, mut b) = tokio::io::duplex(64);
        let w = tokio::spawn(async move {
            for m in [
                AgentMsg::Stop,
                AgentMsg::FrameAck { accepted: true },
                AgentMsg::Input(InputEvent::ReleaseAll),
            ] {
                write_raw(&mut a, &m.encode().unwrap()).await.unwrap();
            }
        });
        let mut d = Decoder::new();
        let mut got = Vec::new();
        while let Some((k, p)) = read_raw(&mut b, &mut d).await.unwrap() {
            got.push(AgentMsg::decode(k, &p).unwrap());
        }
        w.await.unwrap();
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], AgentMsg::Stop);
        // EOF in the middle of a message is an error.
        let (mut a, mut b) = tokio::io::duplex(64);
        tokio::spawn(async move {
            let _ = write_raw(&mut a, &[9, 0, 0, 0, kind::LOG]).await;
        });
        let mut d = Decoder::new();
        assert!(read_raw(&mut b, &mut d).await.is_err());
    }

    #[test]
    fn pipe_names() {
        let n = pipe_name_from(&[0xab; 16]);
        assert!(n.starts_with(PIPE_PREFIX));
        assert!(is_valid_pipe_name(&n));
        assert!(!is_valid_pipe_name(r"\\.\pipe\kestrel-tray"));
        assert!(!is_valid_pipe_name(&format!(
            "{PIPE_PREFIX}ABABABABABABABABABABABABABABABAB"
        )));
        assert!(!is_valid_pipe_name(&format!("{n}0")));
        assert!(!is_valid_pipe_name(
            r"\\server\pipe\kestrel-desktop-00000000000000000000000000000000"
        ));
    }

    #[test]
    fn settings_apply() {
        let mut h = HelperSettings::new(false, "Jane", "", &DesktopSettings::default());
        assert!(!h.view_only);
        h.apply(&DesktopSettings {
            quality: 10,
            scale_pct: 50,
            max_fps: 99,
            view_only: Some(true),
        });
        assert_eq!(
            (h.quality, h.scale_pct, h.max_fps, h.view_only),
            (30, 50, 15, true)
        );
        h.apply(&DesktopSettings::default());
        assert!(h.view_only, "None keeps the mode");
    }

    #[test]
    fn banner_texts() {
        assert_eq!(
            banner_text("Jane Doe", true, ""),
            "IT (Jane Doe) is viewing this PC"
        );
        assert_eq!(
            banner_text("Jane Doe", false, "  ticket\n#42 "),
            "IT (Jane Doe) is controlling this PC \u{2014} Reason: ticket #42"
        );
        assert_eq!(banner_text(" \t", false, ""), "IT is controlling this PC");
        let long = banner_text(&"a".repeat(500), true, &"r".repeat(500));
        assert!(long.chars().count() < 64 + 200 + 60, "{}", long.len());
        assert!(long.contains('…'));
    }

    #[test]
    fn helper_banner_texts() {
        // Banner-only: the agent's file notice, cleaned.
        let b = HelperSettings::banner_only(
            "IT (Jane Doe) is accessing
files on this PC",
        );
        assert_eq!(
            helper_banner_text(&b),
            "IT (Jane Doe) is accessing files on this PC"
        );
        assert_eq!(
            helper_banner_text(&HelperSettings::banner_only("  ")),
            "IT is accessing files on this PC"
        );
        let long = HelperSettings::banner_only(&"x".repeat(5000));
        assert!(helper_banner_text(&long).chars().count() <= FILES_NOTICE_MAX);
        // Desktop: unchanged without a notice, the notice appended with one.
        let mut d = HelperSettings::new(true, "Jane Doe", "", &DesktopSettings::default());
        assert_eq!(helper_banner_text(&d), "IT (Jane Doe) is viewing this PC");
        d.files_notice = "IT (Bob) is accessing files on this PC".into();
        assert_eq!(
            helper_banner_text(&d),
            "IT (Jane Doe) is viewing this PC  |  IT (Bob) is accessing files on this PC"
        );
        // A settings change keeps the notice (only the agent changes it).
        d.apply(&DesktopSettings {
            view_only: Some(false),
            ..DesktopSettings::default()
        });
        assert!(
            helper_banner_text(&d).starts_with("IT (Jane Doe) is controlling this PC  |  IT (Bob)")
        );
        // Old agents' settings (no new fields) decode as a desktop session.
        let old: HelperSettings =
            serde_json::from_str(r#"{"quality":60,"scale_pct":100,"max_fps":5}"#).unwrap();
        assert!(!old.banner_only && old.files_notice.is_empty());
    }
}
