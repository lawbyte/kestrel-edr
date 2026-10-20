//! `tracing` setup: stderr in console mode, daily rolling file in
//! `<state>/logs` when running as a service (and on Windows always).

use std::path::Path;
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

pub struct LogGuard(#[allow(dead_code)] Option<WorkerGuard>);

/// Initialise logging. `RUST_LOG`/`KESTREL_LOG` override the default `info`.
pub fn init(state_dir: Option<&Path>, console: bool) -> LogGuard {
    let filter = || {
        EnvFilter::try_from_env("KESTREL_LOG")
            .or_else(|_| EnvFilter::try_from_default_env())
            .unwrap_or_else(|_| EnvFilter::new("info,h2=warn,hyper=warn,tower=warn,rustls=warn"))
    };
    let want_file = state_dir.is_some() && (cfg!(windows) || !console);
    let (file_layer, guard) = match state_dir.filter(|_| want_file) {
        Some(dir) => {
            let logs = dir.join("logs");
            match std::fs::create_dir_all(&logs) {
                Ok(()) => {
                    let appender = tracing_appender::rolling::Builder::new()
                        .rotation(tracing_appender::rolling::Rotation::DAILY)
                        .filename_prefix("kestrel-agent")
                        .filename_suffix("log")
                        .max_log_files(14)
                        .build(&logs);
                    match appender {
                        Ok(a) => {
                            let (nb, g) = tracing_appender::non_blocking(a);
                            (
                                Some(
                                    fmt::layer()
                                        .with_ansi(false)
                                        .with_writer(nb)
                                        .with_filter(filter()),
                                ),
                                Some(g),
                            )
                        }
                        Err(_) => (None, None),
                    }
                }
                Err(_) => (None, None),
            }
        }
        None => (None, None),
    };
    let stderr_layer = console.then(|| {
        fmt::layer()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_filter(filter())
    });
    let _ = tracing_subscriber::registry()
        .with(file_layer)
        .with(stderr_layer)
        .try_init();
    LogGuard(guard)
}
