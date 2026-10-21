//! Remote desktop on Windows.
//!
//! The agent service (session 0) cannot see or drive the user's desktop, so
//! [`WindowsRemoteDesktop::start`] launches a helper — the agent binary's
//! hidden `desktop-helper` subcommand ([`run_desktop_helper`]) — as SYSTEM in
//! the active console session and talks to it over a per-session named pipe
//! (`\\.\pipe\kestrel-desktop-<random>`, DACL SYSTEM only, remote clients
//! rejected, first-instance, one instance). The client's PID must be the
//! spawned helper's (`GetNamedPipeClientProcessId`), and the helper checks
//! the server's PID is its parent (`GetNamedPipeServerProcessId`).
//!
//! The helper captures the screen (GDI), injects input (`SendInput`) and
//! shows the always-on-top banner; it follows input-desktop switches (UAC
//! secure desktop, lock screen). Ctrl+Alt+Del is sent from this process
//! (`SendSAS` only works from a service).

mod banner;
mod capture;
mod deskfollow;
mod helper;
mod input;
mod spawn;

pub use helper::run_desktop_helper;

use super::util::*;
use crate::desktop_proto::{
    pipe_name_from, read_raw, write_raw, AgentMsg, Decoder, HelperMsg, HelperSettings, PIPE_SDDL,
};
use kestrel_common::remote::{DesktopSettings, InputEvent, RemoteErrorCode};
use kestrel_platform::{
    DesktopEvent, DesktopSession, DesktopSink, DesktopStartParams, RemoteDesktop,
};
use spawn::HelperProcess;
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::mpsc;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

/// Helper start-up (process start + pipe connect + Hello).
const START_TIMEOUT: Duration = Duration::from_secs(20);
/// Grace period for the helper to exit after `Stop` before it is killed.
const STOP_GRACE_MS: u32 = 2000;

type Fail = (RemoteErrorCode, String);

fn unavailable(m: impl Into<String>) -> Fail {
    (RemoteErrorCode::Unavailable, m.into())
}

#[derive(Default)]
pub struct WindowsRemoteDesktop;

impl WindowsRemoteDesktop {
    pub fn new() -> Self {
        WindowsRemoteDesktop
    }
}

fn create_pipe(name: &str, sd: &LocalSd) -> std::io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let mut o = ServerOptions::new();
    o.first_pipe_instance(true)
        .reject_remote_clients(true)
        .max_instances(1)
        .in_buffer_size(1024 * 1024)
        .out_buffer_size(64 * 1024);
    // SAFETY: `sa` and the descriptor it points to outlive the call.
    unsafe {
        o.create_with_security_attributes_raw(
            name,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
        )
    }
}

/// Connect, check the client PID, read `Hello`, send the first settings.
async fn handshake(
    server: NamedPipeServer,
    child_pid: u32,
    settings: HelperSettings,
) -> Result<(NamedPipeServer, Decoder), String> {
    server
        .connect()
        .await
        .map_err(|e| format!("helper did not connect: {e}"))?;
    let mut client_pid = 0u32;
    let raw = server.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    if unsafe { GetNamedPipeClientProcessId(raw, &mut client_pid) } == 0 {
        return Err(format!(
            "GetNamedPipeClientProcessId failed: {}",
            last_err()
        ));
    }
    if client_pid != child_pid {
        let _ = server.disconnect();
        return Err(format!(
            "unexpected pipe client (pid {client_pid}, expected the helper {child_pid})"
        ));
    }
    let mut server = server;
    let mut dec = Decoder::new();
    match read_raw(&mut server, &mut dec).await {
        Ok(Some((k, p))) => match HelperMsg::decode(k, &p) {
            Ok(HelperMsg::Hello { pid }) if pid == child_pid => {}
            Ok(HelperMsg::Error(e)) => return Err(format!("helper: {e}")),
            other => return Err(format!("unexpected first helper message: {other:?}")),
        },
        Ok(None) => return Err("helper closed the pipe before saying hello".into()),
        Err(e) => return Err(format!("pipe read failed: {e}")),
    }
    let bytes = AgentMsg::Settings(settings)
        .encode()
        .map_err(|e| e.to_string())?;
    write_raw(&mut server, &bytes)
        .await
        .map_err(|e| format!("pipe write failed: {e}"))?;
    Ok((server, dec))
}

struct Shared {
    stopped: AtomicBool,
    child: Mutex<Option<HelperProcess>>,
    cmd: mpsc::Sender<AgentMsg>,
    settings: Mutex<HelperSettings>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Shared {
    fn send(&self, m: AgentMsg) {
        if let Err(e) = self.cmd.try_send(m) {
            tracing::warn!("remote desktop: helper command dropped ({e})");
        }
    }

    /// Stop once: ask the helper to quit, then kill it (and close its job)
    /// on a background thread.
    fn stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.cmd.try_send(AgentMsg::Stop);
        let child = self.child.lock().ok().and_then(|mut c| c.take());
        let tasks: Vec<_> = self
            .tasks
            .lock()
            .map(|mut t| t.drain(..).collect())
            .unwrap_or_default();
        let _ = std::thread::Builder::new()
            .name("kestrel-desktop-stop".into())
            .spawn(move || {
                if let Some(c) = child {
                    if !c.wait(STOP_GRACE_MS) {
                        tracing::warn!("remote desktop helper {} did not exit; terminating", c.pid);
                        c.terminate();
                        c.wait(1000);
                    }
                    drop(c); // closes the job (kill-on-close)
                }
                for t in tasks {
                    t.abort();
                }
            });
    }
}

pub struct WinDesktopSession {
    shared: Arc<Shared>,
}

impl DesktopSession for WinDesktopSession {
    fn input(&self, ev: &InputEvent) {
        if self.shared.stopped.load(Ordering::SeqCst) {
            return;
        }
        match ev {
            InputEvent::CtrlAltDel => send_sas(),
            InputEvent::Unknown => {}
            other => self.shared.send(AgentMsg::Input(other.clone())),
        }
    }

    fn settings(&self, s: &DesktopSettings) {
        if self.shared.stopped.load(Ordering::SeqCst) {
            return;
        }
        let next = match self.shared.settings.lock() {
            Ok(mut cur) => {
                cur.apply(s);
                cur.clone()
            }
            Err(_) => return,
        };
        self.shared.send(AgentMsg::Settings(next));
    }

    fn stop(&self) {
        self.shared.stop();
    }
}

impl Drop for WinDesktopSession {
    fn drop(&mut self) {
        self.shared.stop();
    }
}

/// Pipe → sink bridge. Frames use `try_send` (a full sink = not delivered;
/// the helper is told and keeps comparing against the last accepted frame);
/// `Info` / `Ended` wait for room.
async fn bridge_reader<R: tokio::io::AsyncRead + Unpin>(
    mut rd: R,
    mut dec: Decoder,
    sink: DesktopSink,
    shared: Arc<Shared>,
) {
    let mut last_error: Option<String> = None;
    let end = loop {
        match read_raw(&mut rd, &mut dec).await {
            Ok(Some((k, p))) => match HelperMsg::decode(k, &p) {
                Ok(HelperMsg::Info(i)) => {
                    if sink.send(DesktopEvent::Info(i)).await.is_err() {
                        break None;
                    }
                }
                Ok(HelperMsg::Frame {
                    width,
                    height,
                    ts,
                    jpeg,
                }) => {
                    let accepted = match sink.try_send(DesktopEvent::Frame {
                        width,
                        height,
                        ts,
                        jpeg,
                    }) {
                        Ok(()) => true,
                        Err(mpsc::error::TrySendError::Full(_)) => false,
                        Err(mpsc::error::TrySendError::Closed(_)) => break None,
                    };
                    let _ = shared.cmd.send(AgentMsg::FrameAck { accepted }).await;
                }
                Ok(HelperMsg::Error(e)) => {
                    tracing::warn!("remote desktop helper: {e}");
                    last_error = Some(e);
                }
                Ok(HelperMsg::Log(l)) => tracing::info!("remote desktop helper: {l}"),
                Ok(HelperMsg::Hello { .. }) => {}
                Err(e) => {
                    tracing::debug!("remote desktop: ignoring helper message: {e}");
                }
            },
            Ok(None) => break Some("the remote desktop helper closed the connection".to_string()),
            Err(e) => break Some(format!("remote desktop pipe error: {e}")),
        }
    };
    // Sink closed: the core dropped the session.
    let Some(mut reason) = end else {
        shared.stop();
        return;
    };
    if shared.stopped.load(Ordering::SeqCst) {
        return;
    }
    // Give the helper a moment to exit so its exit code explains the end.
    let sh = shared.clone();
    let code = tokio::task::spawn_blocking(move || {
        let guard = sh.child.lock().ok()?;
        let c = guard.as_ref()?;
        c.wait(1000);
        c.exit_code()
    })
    .await
    .ok()
    .flatten();
    if let Some(e) = last_error {
        reason = e;
    } else if let Some(c) = code {
        reason = format!("{reason} (exit code {c:#x})");
    }
    if shared.stopped.swap(true, Ordering::SeqCst) {
        return;
    }
    let _ = sink
        .send(DesktopEvent::Ended {
            reason,
            code: Some(RemoteErrorCode::Unavailable),
        })
        .await;
    // Kill leftovers (if the helper only closed the pipe) and close the job.
    let child = shared.child.lock().ok().and_then(|mut c| c.take());
    if let Some(c) = child {
        let _ = tokio::task::spawn_blocking(move || {
            if !c.wait(500) {
                c.terminate();
            }
        })
        .await;
    }
}

async fn bridge_writer<W: tokio::io::AsyncWrite + Unpin>(
    mut wr: W,
    mut rx: mpsc::Receiver<AgentMsg>,
) {
    while let Some(m) = rx.recv().await {
        let stop = matches!(m, AgentMsg::Stop);
        match m.encode() {
            Ok(b) => {
                if write_raw(&mut wr, &b).await.is_err() {
                    break;
                }
            }
            Err(e) => tracing::warn!("remote desktop: cannot encode helper command: {e}"),
        }
        if stop {
            break;
        }
    }
}

impl RemoteDesktop for WindowsRemoteDesktop {
    fn start(
        &self,
        params: DesktopStartParams,
        sink: DesktopSink,
    ) -> Result<Box<dyn DesktopSession>, (RemoteErrorCode, String)> {
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|_| unavailable("remote desktop needs the agent's async runtime"))?;
        let session = spawn::active_console_session()
            .ok_or_else(|| unavailable("no user is signed in at the console"))?;
        let mut rnd = [0u8; 16];
        getrandom::getrandom(&mut rnd)
            .map_err(|e| unavailable(format!("no randomness for the pipe name: {e}")))?;
        let name = pipe_name_from(&rnd);
        let sd = sd_from_sddl(PIPE_SDDL).ok_or_else(|| unavailable("invalid pipe SDDL"))?;
        let server = {
            let _g = rt.enter();
            create_pipe(&name, &sd)
        }
        .map_err(|e| unavailable(format!("cannot create the helper pipe: {e}")))?;
        let child = spawn::spawn_helper(session, &name)
            .map_err(|e| unavailable(format!("cannot start the remote desktop helper: {e}")))?;
        let settings = HelperSettings::new(
            params.view_only,
            &params.admin_name,
            &params.reason,
            &params.settings,
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let child_pid = child.pid;
        let first = settings.clone();
        let hs = rt.spawn(async move {
            let r = tokio::time::timeout(START_TIMEOUT, handshake(server, child_pid, first))
                .await
                .unwrap_or_else(|_| Err("timed out waiting for the helper".into()));
            let _ = tx.send(r);
        });
        let deadline = Instant::now() + START_TIMEOUT + Duration::from_secs(1);
        let (server, dec) = loop {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(v)) => break v,
                Ok(Err(e)) => {
                    child.terminate();
                    return Err(unavailable(e));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(code) = child.exit_code() {
                        hs.abort();
                        return Err(unavailable(format!(
                            "the remote desktop helper exited during start-up (code {code:#x})"
                        )));
                    }
                    if Instant::now() > deadline {
                        hs.abort();
                        child.terminate();
                        return Err((
                            RemoteErrorCode::Timeout,
                            "the remote desktop helper did not start".into(),
                        ));
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    child.terminate();
                    return Err(unavailable("helper start-up was cancelled"));
                }
            }
        };

        let (cmd_tx, cmd_rx) = mpsc::channel::<AgentMsg>(512);
        let shared = Arc::new(Shared {
            stopped: AtomicBool::new(false),
            child: Mutex::new(Some(child)),
            cmd: cmd_tx,
            settings: Mutex::new(settings),
            tasks: Mutex::new(Vec::new()),
        });
        let (rd, wr) = tokio::io::split(server);
        let w = rt.spawn(bridge_writer(wr, cmd_rx));
        let r = rt.spawn(bridge_reader(rd, dec, sink, shared.clone()));
        if let Ok(mut t) = shared.tasks.lock() {
            t.push(w);
            t.push(r);
        }
        tracing::info!(
            "remote desktop helper started in session {session} (view_only={})",
            params.view_only
        );
        Ok(Box::new(WinDesktopSession { shared }))
    }
}

/// `SendSAS(FALSE)` from `%SystemRoot%\System32\sas.dll` (loaded by full
/// path). Works only from a LocalSystem service and only when the
/// `SoftwareSASGeneration` policy (HKLM\SOFTWARE\Microsoft\Windows\
/// CurrentVersion\Policies\System, 1 = services or 3 = services + Ease of
/// Access) allows it; `SendSAS` returns nothing, so failure is only logged.
fn send_sas() {
    let _ = std::thread::Builder::new()
        .name("kestrel-sas".into())
        .spawn(|| {
            use windows_sys::Win32::Foundation::FreeLibrary;
            use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
            use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
            let policy = reg_open(
                HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                false,
            )
            .and_then(|k| reg_get_dword(&k, "SoftwareSASGeneration"));
            if !matches!(policy, Some(1) | Some(3)) {
                tracing::warn!(
                    "remote desktop: Ctrl+Alt+Del requested but the SoftwareSASGeneration policy \
                     does not allow services to generate it (value {policy:?}); it will likely be ignored"
                );
            }
            let path = wide(&format!(r"{}\System32\sas.dll", system_root()));
            let m = unsafe { LoadLibraryW(path.as_ptr()) };
            if m.is_null() {
                tracing::warn!("remote desktop: cannot load sas.dll: {}", last_err());
                return;
            }
            match unsafe { GetProcAddress(m, c"SendSAS".as_ptr() as *const u8) } {
                Some(f) => {
                    // SAFETY: documented signature `VOID SendSAS(BOOL AsUser)`.
                    let f: unsafe extern "system" fn(i32) = unsafe { std::mem::transmute(f) };
                    unsafe { f(0) };
                    tracing::info!("remote desktop: Ctrl+Alt+Del sent (SendSAS)");
                }
                None => tracing::warn!("remote desktop: SendSAS not found in sas.dll"),
            }
            unsafe {
                FreeLibrary(m);
            }
        });
}
