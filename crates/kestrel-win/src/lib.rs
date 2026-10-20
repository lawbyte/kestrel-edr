//! Windows platform layer for the Kestrel agent.
//!
//! On Windows this crate provides [`WindowsPlatform`] (the
//! `kestrel_platform::Platform` implementation: ETW sensors, enrichment,
//! response, WFP isolation, hardening, canaries, tray pipe, host facts) and the
//! service helpers [`run_service`], [`install_service`], [`uninstall_service`].
//!
//! Everything that does not need Windows APIs (payload decoding, NT path
//! mapping, WFP filter planning, AppLocker XML editing, the quarantine vault
//! format, tray framing, …) lives in platform-independent modules that are
//! compiled and unit-tested on every OS.
//!
//! ## Sensor pipeline
//! ETW callbacks (ferrisetw, one thread per real-time session) only decode the
//! fields they need into a small owned [`win`]-internal record and `try_send`
//! it to a bounded internal queue (drops are counted). A translator thread
//! resolves process GUIDs, NT paths, DNS→IP correlation and enrichment caches,
//! and `try_send`s `kestrel_common::Event`s to the agent's channel (drops
//! counted again). Hashing and Authenticode checks run on a separate worker,
//! so a `ProcessStart` carries sha256/signer only when the image was already
//! in the cache; otherwise it is emitted immediately with what is known and
//! the cache is filled for the next start / for `snapshot_processes`.

pub mod applocker;
pub mod canary;
pub mod consts;
pub mod etwparse;
pub mod evtxml;
pub mod filters;
pub mod hostfacts;
pub mod jsonc;
pub mod ntpath;
pub mod proctrack;
pub mod qpolicy;
pub mod sddl;
pub mod tray;
pub mod vault;
pub mod wfp_plan;
pub mod zipw;

#[cfg(windows)]
mod win;

#[cfg(windows)]
pub use win::platform::WindowsPlatform;
#[cfg(windows)]
pub use win::service::{install_service, run_service, uninstall_service};
#[cfg(windows)]
pub use win::statedir::{secure_state_dir, StateDirResult};
#[cfg(windows)]
pub use win::wfp::{release_isolation_offline, remove_all_wfp_objects};

pub use consts::{SERVICE_ARG, SERVICE_NAME};
