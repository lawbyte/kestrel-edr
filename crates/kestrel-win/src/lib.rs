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
pub mod autorun_plan;
pub mod canary;
pub mod consts;
pub mod desktop_image;
pub mod desktop_keymap;
pub mod desktop_proto;
pub mod dnswire;
pub mod etwparse;
pub mod evtxml;
pub mod fileagg;
pub mod filters;
pub mod hardening_plan;
pub mod hostfacts;
pub mod jsonc;
pub mod ntpath;
pub mod persist;
pub mod proctrack;
pub mod pump;
pub mod qpolicy;
pub mod rcanary;
pub mod regdiff;
pub mod remotefs;
pub mod sddl;
pub mod spawnreg;
pub mod taskxml;
pub mod tray;
pub mod vault;
pub mod wfp_plan;
pub mod zipw;

#[cfg(windows)]
mod win;

/// Hidden `kestrel-agent desktop-helper --pipe <name> --parent <pid>`
/// subcommand: the remote-desktop helper (capture, input, banner).
#[cfg(windows)]
pub use win::desktop::run_desktop_helper;
/// RedirectionGuard for the current process (called by `WindowsPlatform::new`).
#[cfg(windows)]
pub use win::hardfs::enable_redirection_guard;
#[cfg(windows)]
pub use win::platform::{resolve_host_direct, WindowsPlatform};
#[cfg(windows)]
pub use win::service::{install_service, run_service, service_installed, uninstall_service};
#[cfg(windows)]
pub use win::statedir::{secure_state_dir, StateDirResult};
#[cfg(windows)]
pub use win::wfp::{release_isolation_offline, remove_all_wfp_objects};

pub use consts::{SERVICE_ARG, SERVICE_NAME};

/// `%SystemRoot%` from `GetSystemWindowsDirectoryW`, never from the caller's
/// environment (a standard user controls that for the agent CLI: V-H1).
#[cfg(windows)]
/// Authenticode check of a local file (WinVerifyTrust, whole chain, online
/// revocation): (state, signer subject). A revoked certificate is reported as
/// `Invalid`. Used for update packages (V-H3).
pub fn verify_file_signature(
    path: &std::path::Path,
) -> (kestrel_common::SignatureState, Option<String>) {
    use win::enrich::{verify_ex, RevMode, Revocation};
    let v = verify_ex(&path.to_string_lossy(), RevMode::Online);
    let state = if v.revocation == Revocation::Revoked {
        kestrel_common::SignatureState::Invalid
    } else {
        v.state
    };
    (state, v.signer)
}

#[cfg(windows)]
pub fn windows_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(win::util::system_root())
}
