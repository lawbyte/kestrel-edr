//! Shared types for Kestrel EDR.
//!
//! This crate is the single source of truth for every structure that crosses a
//! process or network boundary: agent telemetry, detections, policy, response
//! commands, the agent<->server wire payloads (carried inside the gRPC envelope
//! defined in `proto/kestrel.proto`), and the tray<->agent named-pipe protocol.
//!
//! Everything here is platform independent and serialises with serde as JSON.

pub mod alert;
pub mod event;
pub mod policy;
pub mod response;
pub mod rules;
pub mod tray;
pub mod wire;

pub use alert::*;
pub use event::*;
pub use policy::*;
pub use response::*;
pub use rules::*;

/// Milliseconds since the Unix epoch (UTC).
pub type TimestampMs = i64;

/// Agent/product version, embedded at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Named pipe used by the tray app to talk to the agent service.
pub const TRAY_PIPE_NAME: &str = r"\\.\pipe\kestrel-tray";

/// Current wall-clock time in ms.
pub fn now_ms() -> TimestampMs {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
