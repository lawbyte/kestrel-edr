//! `\\.\pipe\kestrel-tray` server (must run inside the service process: the
//! tray trusts the pipe only if its server lives in session 0).
//!
//! DACL `D:P(A;;GA;;;SY)(A;;GRGW;;;AU)`: SYSTEM full, Authenticated Users
//! read/write; remote clients rejected; first instance created with
//! FILE_FLAG_FIRST_PIPE_INSTANCE so a pre-created (squatted) pipe makes us
//! fail loudly instead of sharing the name. Note GW includes
//! FILE_CREATE_PIPE_INSTANCE, so a local user could add instances later:
//! clients must verify the server (GetNamedPipeServerProcessId → session 0 /
//! the KestrelAgent service), which the tray already does.
//!
//! M3: every connection is attributed to its client — `GetNamedPipeClientProcessId`
//! → that process's token user (SID + account name) and
//! `GetNamedPipeClientSessionId` — and the agent answers per user
//! (activity, review requests, notifications, rate limits).

use super::util::*;
use crate::tray::handle_connection;
use kestrel_common::TRAY_PIPE_NAME;
use kestrel_platform::{TrayClient, TrayHandler};
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use tokio::sync::Semaphore;
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeClientSessionId};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

pub const TRAY_PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GRGW;;;AU)";
const MAX_CLIENTS: usize = 16;

fn create(first: bool, sd: &LocalSd) -> std::io::Result<NamedPipeServer> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first).reject_remote_clients(true);
    // SAFETY: `sa` and the descriptor it points to outlive the call.
    unsafe {
        opts.create_with_security_attributes_raw(
            TRAY_PIPE_NAME,
            &mut sa as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void,
        )
    }
}

/// Identify the process at the other end of a connected pipe instance.
fn client_identity(pipe: windows_sys::Win32::Foundation::HANDLE) -> TrayClient {
    let mut pid = 0u32;
    let mut session = 0u32;
    let have_pid = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } != 0 && pid != 0;
    let session_id =
        (unsafe { GetNamedPipeClientSessionId(pipe, &mut session) } != 0).then_some(session);
    if !have_pid {
        return TrayClient {
            session_id,
            ..Default::default()
        };
    }
    let (user_sid, _) = match open_process(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Some(h) => process_token_info(&h),
        None => (None, None),
    };
    let user = user_sid.as_deref().and_then(lookup_sid_string);
    TrayClient {
        user_sid,
        user,
        session_id,
        pid: Some(pid),
    }
}

pub async fn serve(handler: Arc<dyn TrayHandler>) -> anyhow::Result<()> {
    let sd =
        sd_from_sddl(TRAY_PIPE_SDDL).ok_or_else(|| anyhow::anyhow!("invalid tray pipe SDDL"))?;
    let mut server = loop {
        match create(true, &sd) {
            Ok(s) => break s,
            Err(e) => {
                tracing::error!("cannot create {TRAY_PIPE_NAME} (already owned by another process?): {e}; retrying");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    let slots = Arc::new(Semaphore::new(MAX_CLIENTS));
    loop {
        if let Err(e) = server.connect().await {
            tracing::warn!("tray pipe connect failed: {e}");
            server = create(false, &sd)?;
            continue;
        }
        let connected = server;
        // Always keep a listening instance available before serving.
        server = create(false, &sd)?;
        match slots.clone().try_acquire_owned() {
            Ok(permit) => {
                let h = handler.clone();
                let raw = connected.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
                let client = tokio::task::block_in_place(|| client_identity(raw));
                tokio::spawn(async move {
                    let _ = handle_connection(connected, h, client).await;
                    drop(permit);
                });
            }
            Err(_) => drop(connected), // too many clients
        }
    }
}
