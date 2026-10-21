//! Kestrel EDR endpoint agent — portable core.
//!
//! The agent talks to the OS only through [`kestrel_platform::Platform`]
//! (`kestrel_win::WindowsPlatform` on Windows, [`sim::SimPlatform`] for
//! replays/tests) and to the server over gRPC/mTLS (`proto/kestrel.proto`).

pub mod proto {
    #![allow(clippy::all, clippy::pedantic)]
    tonic::include_proto!("kestrel.v1");
}

pub mod agent;
pub mod backoff;
pub mod codec;
pub mod commands;
pub mod config;
pub mod detection;
pub mod live;
pub mod logging;
pub mod pki;
pub mod platform_win;
pub mod privacy;
pub mod remote_fs;
pub mod sim;
pub mod sim_remote;
pub mod store;
pub mod transport;
pub mod tray;
pub mod update;
