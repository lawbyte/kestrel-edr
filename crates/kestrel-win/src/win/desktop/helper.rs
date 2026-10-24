//! The remote-desktop helper process (`kestrel-agent desktop-helper --pipe
//! <name> --parent <pid>`), started by the agent service as SYSTEM in the
//! active console session.
//!
//! Threads: pipe I/O (own current-thread tokio runtime, overlapped pipe
//! client), capture, input, banner; the calling thread supervises (parent
//! process alive, console session unchanged) and routes agent commands.
//! The helper exits when the agent says `Stop`, the pipe closes, the agent
//! process dies, or the console session changes.
//!
//! Banner-only mode (`HelperSettings.banner_only`, remote file manager
//! without a desktop session): only the banner thread runs; no capture and
//! no input thread are started and `Input` / `FrameAck` are ignored.

use super::super::util::*;
use super::banner::Banner;
use super::capture::{self, CapCmd};
use super::input::{self, InputCmd};
use super::spawn::active_console_session;
use crate::desktop_proto::{
    helper_banner_text, is_valid_pipe_name, read_raw, write_raw, AgentMsg, Decoder, HelperMsg,
    HelperSettings, ProtoError,
};
use anyhow::{anyhow, bail, Context};
use std::os::windows::io::AsRawHandle;
use std::sync::mpsc as smpsc;
use std::time::{Duration, Instant};
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::sync::mpsc as tmpsc;
use windows_sys::Win32::Foundation::{ERROR_PIPE_BUSY, WAIT_OBJECT_0};
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Threading::{
    WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};
use windows_sys::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};

enum Ctl {
    Agent(AgentMsg),
    /// The pipe closed / failed.
    Closed(String),
}

async fn open_client(
    pipe: &str,
) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match ClientOptions::new().open(pipe) {
            Ok(c) => return Ok(c),
            Err(e)
                if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                    && Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Pipe I/O thread body.
fn io_thread(
    pipe: String,
    parent_pid: u32,
    mut out_rx: tmpsc::Receiver<HelperMsg>,
    ctl: smpsc::Sender<Ctl>,
    ready: smpsc::Sender<Result<(), String>>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready.send(Err(format!("cannot build the I/O runtime: {e}")));
            return;
        }
    };
    rt.block_on(async move {
        let client = match open_client(&pipe).await {
            Ok(c) => c,
            Err(e) => {
                let _ = ready.send(Err(format!("cannot open {pipe}: {e}")));
                return;
            }
        };
        let mut server_pid = 0u32;
        let raw = client.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        if unsafe { GetNamedPipeServerProcessId(raw, &mut server_pid) } == 0
            || server_pid != parent_pid
        {
            let _ = ready.send(Err(format!(
                "pipe server is pid {server_pid}, not the agent ({parent_pid})"
            )));
            return;
        }
        let (mut rd, mut wr) = tokio::io::split(client);
        let hello = HelperMsg::Hello {
            pid: std::process::id(),
        };
        match hello.encode() {
            Ok(b) => {
                if let Err(e) = write_raw(&mut wr, &b).await {
                    let _ = ready.send(Err(format!("pipe write failed: {e}")));
                    return;
                }
            }
            Err(e) => {
                let _ = ready.send(Err(e.to_string()));
                return;
            }
        }
        let _ = ready.send(Ok(()));
        let ctl2 = ctl.clone();
        let reader = async move {
            let mut dec = Decoder::new();
            loop {
                match read_raw(&mut rd, &mut dec).await {
                    Ok(Some((k, p))) => match AgentMsg::decode(k, &p) {
                        Ok(m) => {
                            if ctl2.send(Ctl::Agent(m)).is_err() {
                                return "helper is shutting down".to_string();
                            }
                        }
                        Err(ProtoError::UnknownKind(_)) => continue,
                        Err(e) => return format!("bad message from the agent: {e}"),
                    },
                    Ok(None) => return "the agent closed the connection".to_string(),
                    Err(e) => return format!("pipe read failed: {e}"),
                }
            }
        };
        let writer = async move {
            while let Some(m) = out_rx.recv().await {
                match m.encode() {
                    Ok(b) => {
                        if let Err(e) = write_raw(&mut wr, &b).await {
                            return format!("pipe write failed: {e}");
                        }
                    }
                    Err(e) => tracing::debug!("cannot encode {e}"),
                }
            }
            "helper output closed".to_string()
        };
        let why = tokio::select! {
            r = reader => r,
            w = writer => w,
        };
        let _ = ctl.send(Ctl::Closed(why));
    });
}

fn own_session() -> Option<u32> {
    let mut s = 0u32;
    (unsafe { ProcessIdToSessionId(std::process::id(), &mut s) } != 0).then_some(s)
}

/// Entry point of the hidden `desktop-helper` subcommand. Runs until the
/// session ends; `Err` = it could not start or failed (the agent reports the
/// helper's last `Error` message / exit code).
pub fn run_desktop_helper(pipe: &str, parent_pid: u32) -> anyhow::Result<()> {
    if !is_valid_pipe_name(pipe) {
        bail!("invalid desktop pipe name");
    }
    // Physical-pixel coordinates everywhere (must precede any window).
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let parent = open_process(
        parent_pid,
        PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
    )
    .ok_or_else(|| anyhow!("cannot open the agent process {parent_pid}: {}", last_err()))?;
    let session = own_session().context("cannot read the helper's session id")?;

    let (out_tx, out_rx) = tmpsc::channel::<HelperMsg>(4);
    let (ctl_tx, ctl_rx) = smpsc::channel::<Ctl>();
    let (ready_tx, ready_rx) = smpsc::channel();
    let pipe_s = pipe.to_string();
    let io = std::thread::Builder::new()
        .name("kestrel-desktop-io".into())
        .spawn(move || io_thread(pipe_s, parent_pid, out_rx, ctl_tx, ready_tx))
        .context("cannot start the I/O thread")?;
    match ready_rx.recv_timeout(Duration::from_secs(15)) {
        Ok(Ok(())) => {}
        Ok(Err(e)) => bail!("{e}"),
        Err(_) => bail!("timed out connecting to the agent"),
    }

    // The first settings carry the banner text; nothing is captured before
    // the banner is up.
    let mut settings: HelperSettings = loop {
        match ctl_rx.recv_timeout(Duration::from_secs(15)) {
            Ok(Ctl::Agent(AgentMsg::Settings(s))) => break s,
            Ok(Ctl::Agent(AgentMsg::Stop)) => return Ok(()),
            Ok(Ctl::Agent(_)) => continue,
            Ok(Ctl::Closed(why)) => bail!("{why}"),
            Err(_) => bail!("no settings from the agent"),
        }
    };
    let banner_only = settings.banner_only;
    let mut shown_text = helper_banner_text(&settings);
    let banner = match Banner::start(&shown_text) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("cannot show the remote-session banner: {e}");
            let _ = out_tx.blocking_send(HelperMsg::Error(msg.clone()));
            drop(out_tx);
            let _ = io.join();
            bail!("{msg}");
        }
    };

    // The agent waits for this before it lets a file operation run.
    let _ = out_tx.blocking_send(HelperMsg::BannerShown);

    let (cap_tx, cap_rx) = smpsc::channel::<CapCmd>();
    let (in_tx, in_rx) = smpsc::channel::<InputCmd>();
    let (cap, inp) = if banner_only {
        (None, None)
    } else {
        let cap_out = out_tx.clone();
        let cap_settings = settings.clone();
        let cap = std::thread::Builder::new()
            .name("kestrel-desktop-capture".into())
            .spawn(move || capture::run(cap_rx, cap_out, cap_settings, session))
            .context("cannot start the capture thread")?;
        let inp = std::thread::Builder::new()
            .name("kestrel-desktop-input".into())
            .spawn(move || input::run(in_rx))
            .context("cannot start the input thread")?;
        (Some(cap), Some(inp))
    };

    let mut session_mismatch = 0u32;
    let mut error: Option<String> = None;
    loop {
        match ctl_rx.recv_timeout(Duration::from_millis(500)) {
            Ok(Ctl::Agent(AgentMsg::Settings(s))) => {
                settings = s;
                // The mode is fixed at start.
                settings.banner_only = banner_only;
                let text = helper_banner_text(&settings);
                if text != shown_text {
                    banner.set_text(&text);
                    shown_text = text;
                }
                if banner_only {
                    continue;
                }
                if settings.view_only {
                    let _ = in_tx.send(InputCmd::Event(
                        kestrel_common::remote::InputEvent::ReleaseAll,
                    ));
                }
                let _ = cap_tx.send(CapCmd::Settings(settings.clone()));
            }
            Ok(Ctl::Agent(AgentMsg::Input(ev))) => {
                // Defence in depth: the agent already drops view-only input.
                if !settings.view_only && !banner_only {
                    let _ = in_tx.send(InputCmd::Event(ev));
                }
            }
            Ok(Ctl::Agent(AgentMsg::FrameAck { accepted })) => {
                let _ = cap_tx.send(CapCmd::Ack(accepted));
            }
            Ok(Ctl::Agent(AgentMsg::Stop)) => break,
            Ok(Ctl::Closed(why)) => {
                error = Some(why);
                break;
            }
            Err(smpsc::RecvTimeoutError::Disconnected) => {
                error = Some("pipe I/O thread ended".into());
                break;
            }
            Err(smpsc::RecvTimeoutError::Timeout) => {}
        }
        if unsafe { WaitForSingleObject(parent.raw(), 0) } == WAIT_OBJECT_0 {
            error = Some("the agent process exited".into());
            break;
        }
        if active_console_session() != Some(session) {
            session_mismatch += 1;
            if session_mismatch >= 6 {
                let msg = "the console session changed (user switch or remote logon)";
                let _ = out_tx.try_send(HelperMsg::Error(msg.into()));
                error = Some(msg.into());
                break;
            }
        } else {
            session_mismatch = 0;
        }
        if cap.as_ref().is_some_and(|c| c.is_finished()) {
            error = Some("capture stopped".into());
            break;
        }
    }

    // Shutdown: release input, stop capture, remove the banner.
    let _ = in_tx.send(InputCmd::Stop);
    let _ = cap_tx.send(CapCmd::Stop);
    let deadline = Instant::now() + Duration::from_secs(2);
    let done = |t: &Option<std::thread::JoinHandle<()>>| t.as_ref().is_none_or(|t| t.is_finished());
    while !(done(&inp) && done(&cap)) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    banner.close();
    drop(out_tx);
    let deadline = Instant::now() + Duration::from_secs(1);
    while !io.is_finished() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    match error {
        None => Ok(()),
        Some(e) => Err(anyhow!(e)),
    }
}
