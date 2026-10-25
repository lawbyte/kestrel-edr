//! Kestrel employee tray app (Tauri 2).
//!
//! Runs per user at logon, unprivileged, single instance. Shows protection state
//! in the notification area, a flyout window (Status / Activity / Help & privacy)
//! that only exists while it is shown (see `window.rs`: an idle tray runs no
//! WebView2), and Windows toasts for pushed notifications. Talks to the agent service over
//! the tray protocol only. The one thing it can change is the local "turn
//! protection off" switch, and only with the device's uninstall token (checked
//! by the agent); turning protection back on never needs one. The token is
//! never logged: requests are only ever named by `TrayRequest::op`.

pub mod client;
pub mod consent;
pub mod mock;
pub mod protocol;
pub mod window;

use client::{backoff, open_subscription, read_response_lenient, Client, ClientError};
use protocol::*;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::image::Image;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, PhysicalSize, RunEvent, WebviewWindow,
    WebviewWindowBuilder, WindowEvent,
};
use tauri_plugin_notification::NotificationExt;
use tauri_plugin_opener::OpenerExt;
use window::{blur_action, window_needed, BlurAction, IntentBox, UiIntent};

const MAIN: &str = "main";
const TRAY_ID: &str = "kestrel";
const REQ_TIMEOUT: Duration = Duration::from_secs(10);
const QUICK_CHECK_TIMEOUT: Duration = Duration::from_secs(180);
/// The agent checks the token (and rate-limits it) before it answers.
const PAUSE_TIMEOUT: Duration = Duration::from_secs(20);
/// Longest token the tray sends (uninstall tokens are far shorter).
const MAX_TOKEN_LEN: usize = 512;
const STATUS_POLL: Duration = Duration::from_secs(30);
/// A new window is shown when its UI says it is ready (no blank flash), or
/// after this long if the UI never says so.
const SHOW_FALLBACK: Duration = Duration::from_secs(3);

// Frontend event names.
const EV_NOTIFICATION: &str = "kestrel://notification";
const EV_CONNECTION: &str = "kestrel://connection";
const EV_STATUS: &str = "kestrel://status";
const EV_NAVIGATE: &str = "kestrel://navigate";
const EV_QUICK_CHECK: &str = "kestrel://quick-check";
const EV_REMOTE_SESSION: &str = "kestrel://remote-session";
const EV_CONSENT_REQUEST: &str = "kestrel://consent-request";

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowMode {
    /// Borderless, opens next to the tray, hides when it loses focus.
    Flyout,
    /// Normal framed window that stays open.
    Window,
}

struct AppState {
    client: Arc<Client>,
    last_status: Mutex<Option<TrayStatus>>,
    connected: Mutex<bool>,
    mode: Mutex<WindowMode>,
    /// When the flyout was last hidden by losing focus (tray click toggle debounce).
    blur_hidden_at: Mutex<Option<Instant>>,
    /// Last known tray icon rectangle (physical px), for positioning the flyout.
    tray_anchor: Mutex<Option<(f64, f64, f64, f64)>>,
    /// Mica backdrop applied (Windows 11). The UI uses translucent surfaces only then.
    mica: Mutex<bool>,
    /// IT consent requests waiting for the employee's answer.
    consents: Mutex<consent::ConsentQueue>,
    /// Tab / quick-check requests waiting for the (re)built UI.
    intents: Mutex<IntentBox>,
    /// The window was just built; it is shown once its UI is ready.
    show_on_ready: Mutex<bool>,
}

#[derive(Clone, Serialize)]
struct ConnectionEvent {
    connected: bool,
    reason: Option<String>,
}

#[derive(Serialize)]
pub struct Ack {
    ok: bool,
    message: String,
}

fn state(app: &AppHandle) -> tauri::State<'_, AppState> {
    app.state::<AppState>()
}

// ---- Tray icon ---------------------------------------------------------------

fn tray_png(s: Option<&TrayStatus>) -> &'static [u8] {
    if s.is_some_and(|s| s.pause.is_some()) {
        return include_bytes!("../icons/tray/paused.png");
    }
    match s.map(|s| s.state) {
        Some(ProtectionState::Protected) => include_bytes!("../icons/tray/protected.png"),
        Some(ProtectionState::Attention) => include_bytes!("../icons/tray/attention.png"),
        Some(ProtectionState::Isolated) => include_bytes!("../icons/tray/isolated.png"),
        Some(ProtectionState::Degraded) => include_bytes!("../icons/tray/degraded.png"),
        Some(ProtectionState::Offline) => include_bytes!("../icons/tray/offline.png"),
        None => include_bytes!("../icons/tray/unavailable.png"),
    }
}

/// Tooltip text; the state is always spelled out (not conveyed by colour alone).
/// An active IT remote session is named first so it's never hidden by truncation.
fn tray_tooltip(s: Option<&TrayStatus>) -> String {
    match s {
        None => "Kestrel: service isn't running. Contact IT.".into(),
        Some(st) if st.remote_session.as_ref().is_some_and(|r| r.active) => {
            let r = st.remote_session.as_ref().expect("checked above");
            let who = r.admin_name.trim();
            let who = if who.is_empty() { "IT" } else { who };
            let what = match (r.kind, r.view_only) {
                (RemoteKind::Files, _) => "accessing your files",
                (RemoteKind::Desktop, true) => "viewing your screen",
                (RemoteKind::Desktop, false) => "controlling your screen",
            };
            format!("Kestrel: IT is connected\n{who} is {what}")
                .chars()
                .take(127)
                .collect()
        }
        Some(st) => {
            let label = match (st.pause.as_ref(), st.state) {
                (Some(p), _) if p.mode == PauseMode::Full => "Protection is off (completely)",
                (Some(_), _) => "Protection is off (detection only)",
                (None, state) => state_label(state),
            };
            let org = if st.org_name.is_empty() {
                String::new()
            } else {
                format!("\n{}", st.org_name)
            };
            // Windows truncates tray tooltips at 127 chars.
            format!("Kestrel: {label}{org}").chars().take(127).collect()
        }
    }
}

fn state_label(state: ProtectionState) -> &'static str {
    match state {
        ProtectionState::Protected => "Protected",
        ProtectionState::Attention => "Protected. Something was blocked",
        ProtectionState::Isolated => "Network limited by IT",
        ProtectionState::Degraded => "Protection partly working",
        ProtectionState::Offline => "Protected, not connected to IT",
    }
}

fn update_tray(app: &AppHandle, status: Option<&TrayStatus>) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        match Image::from_bytes(tray_png(status)) {
            Ok(img) => {
                let _ = tray.set_icon(Some(img));
            }
            Err(e) => log::warn!("tray icon: {e}"),
        }
        let _ = tray.set_tooltip(Some(tray_tooltip(status)));
    }
}

fn set_connected(app: &AppHandle, connected: bool, reason: Option<String>) {
    let st = state(app);
    let changed = {
        let mut c = st.connected.lock().unwrap();
        let changed = *c != connected;
        *c = connected;
        changed
    };
    if !connected {
        *st.last_status.lock().unwrap() = None;
        update_tray(app, None);
    }
    if changed {
        let _ = app.emit(EV_CONNECTION, ConnectionEvent { connected, reason });
    }
}

fn record_status(app: &AppHandle, s: &TrayStatus) {
    let st = state(app);
    let changed = st.last_status.lock().unwrap().as_ref() != Some(s);
    *st.last_status.lock().unwrap() = Some(s.clone());
    set_connected(app, true, None);
    if changed {
        update_tray(app, Some(s));
        let _ = app.emit(EV_STATUS, s.clone());
    }
}

/// Treat transport failures as "service unavailable" for the tray icon.
fn note_err(app: &AppHandle, e: &ClientError) {
    if matches!(e, ClientError::Unavailable(_)) {
        set_connected(app, false, Some(e.to_string()));
    }
}

// ---- Commands ----------------------------------------------------------------

#[tauri::command]
async fn get_status(app: AppHandle) -> Result<TrayStatus, ClientError> {
    let client = state(&app).client.clone();
    match client.request(&TrayRequest::Status, REQ_TIMEOUT).await {
        Ok(TrayResponse::Status(s)) => {
            record_status(&app, &s);
            Ok(s)
        }
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
        Err(e) => {
            note_err(&app, &e);
            Err(e)
        }
    }
}

#[tauri::command]
async fn get_activity(
    app: AppHandle,
    limit: Option<u32>,
) -> Result<Vec<ActivityItem>, ClientError> {
    let client = state(&app).client.clone();
    let limit = limit.unwrap_or(50).clamp(1, 200);
    match client
        .request(&TrayRequest::Activity { limit }, REQ_TIMEOUT)
        .await
    {
        Ok(TrayResponse::Activity { items }) => Ok(items),
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
        Err(e) => {
            note_err(&app, &e);
            Err(e)
        }
    }
}

#[tauri::command]
async fn quick_check(app: AppHandle) -> Result<Ack, ClientError> {
    let client = state(&app).client.clone();
    let res = client
        .request(&TrayRequest::QuickCheck, QUICK_CHECK_TIMEOUT)
        .await;
    // Refresh status (last_check / state may have changed) in the background.
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = get_status(app2).await;
    });
    match res {
        Ok(TrayResponse::Ack { ok, message }) => Ok(Ack { ok, message }),
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
        Err(e) => {
            note_err(&app, &e);
            Err(e)
        }
    }
}

#[tauri::command]
async fn request_review(
    app: AppHandle,
    alert_id: String,
    justification: String,
) -> Result<Ack, ClientError> {
    let alert_id =
        uuid::Uuid::parse_str(&alert_id).map_err(|e| ClientError::Protocol(e.to_string()))?;
    let justification = justification.trim().to_string();
    if justification.is_empty() {
        return Err(ClientError::Protocol("justification is required".into()));
    }
    // Keep it bounded; the console shows it to an analyst.
    let justification: String = justification.chars().take(2000).collect();
    let client = state(&app).client.clone();
    match client
        .request(
            &TrayRequest::RequestReview {
                alert_id,
                justification,
            },
            REQ_TIMEOUT,
        )
        .await
    {
        Ok(TrayResponse::Ack { ok, message }) => Ok(Ack { ok, message }),
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
        Err(e) => {
            note_err(&app, &e);
            Err(e)
        }
    }
}

/// Turn protection off with the device's uninstall token. The agent checks
/// the token, the policy (`mode`, `minutes`; `None` = until turned back on)
/// and the lockout, and answers with a `PauseResult` either way. An older
/// agent answers `Error` (`ClientError::Agent`). The token is moved straight
/// into the request and never logged or echoed in an error.
#[tauri::command]
async fn pause_protection(
    app: AppHandle,
    token: String,
    mode: PauseMode,
    minutes: Option<u32>,
) -> Result<PauseResult, ClientError> {
    let token = TokenInput(token.trim().to_string());
    if token.0.is_empty() {
        return Err(ClientError::Protocol("the token is required".into()));
    }
    if token.0.len() > MAX_TOKEN_LEN {
        return Err(ClientError::Protocol("the token is too long".into()));
    }
    let req = TrayRequest::PauseProtection {
        token,
        mode,
        minutes,
    };
    pause_request(&app, &req).await
}

/// Turn protection back on (never needs a token).
#[tauri::command]
async fn resume_protection(app: AppHandle) -> Result<PauseResult, ClientError> {
    pause_request(&app, &TrayRequest::ResumeProtection).await
}

async fn pause_request(app: &AppHandle, req: &TrayRequest) -> Result<PauseResult, ClientError> {
    let client = state(app).client.clone();
    let res = client.request(req, PAUSE_TIMEOUT).await;
    // Status (pause state, lockout) changes with every answer: refresh it so
    // the tray icon and tooltip follow right away.
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = get_status(app2).await;
    });
    match res {
        Ok(TrayResponse::PauseResult(r)) => Ok(r),
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response to {}: {}",
            req.op(),
            response_kind(&other)
        ))),
        Err(e) => {
            note_err(app, &e);
            Err(e)
        }
    }
}

/// Response variant name, for error messages.
fn response_kind(r: &TrayResponse) -> &'static str {
    match r {
        TrayResponse::Status(_) => "status",
        TrayResponse::Activity { .. } => "activity",
        TrayResponse::Ack { .. } => "ack",
        TrayResponse::Notification(_) => "notification",
        TrayResponse::Error { .. } => "error",
        TrayResponse::RemoteSession(_) => "remote_session",
        TrayResponse::ConsentRequest(_) => "consent_request",
        TrayResponse::PauseResult(_) => "pause_result",
    }
}

/// Open an IT-contact or privacy-notice link in the default handler.
/// Only https/http, mailto: and tel: are allowed (the notice is server-provided).
#[tauri::command]
fn open_link(app: AppHandle, url: String) -> Result<(), String> {
    if !is_safe_link(&url) {
        return Err("link type not allowed".into());
    }
    app.opener()
        .open_url(url, None::<String>)
        .map_err(|e| e.to_string())
}

fn is_safe_link(url: &str) -> bool {
    let u = url.trim();
    if u.len() > 2048
        || u.chars()
            .any(|c| c.is_control() || c.is_whitespace() && c != ' ')
    {
        return false;
    }
    let lower = u.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://")) && u.len() > 8
        || lower.starts_with("mailto:") && u.contains('@')
        || lower.starts_with("tel:")
            && u[4..]
                .chars()
                .all(|c| c.is_ascii_digit() || "+-() ".contains(c))
}

/// Start `kestrel-uninstall.exe` from the install folder (next to this
/// app). `ShellExecuteW` (not `CreateProcess`) so its requireAdministrator
/// manifest raises the UAC prompt. The agent is not involved: the tool asks
/// for the uninstall token itself.
#[tauri::command]
fn launch_uninstaller() -> Result<(), String> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::ShellExecuteW;
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let dir = exe.parent().ok_or("no install folder")?.to_path_buf();
        let tool = dir.join("kestrel-uninstall.exe");
        if !tool.is_file() {
            return Err("The uninstall tool is not installed on this PC.".into());
        }
        let w = |s: &std::path::Path| -> Vec<u16> {
            use std::os::windows::ffi::OsStrExt;
            s.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        };
        let (file, cwd) = (w(&tool), w(&dir));
        let verb: Vec<u16> = "open\0".encode_utf16().collect();
        // SAFETY: valid NUL-terminated strings.
        let h = unsafe {
            ShellExecuteW(
                std::ptr::null_mut(),
                verb.as_ptr(),
                file.as_ptr(),
                std::ptr::null(),
                cwd.as_ptr(),
                SW_SHOWNORMAL,
            )
        };
        // > 32 = started; ERROR_CANCELLED (1223) when the UAC prompt is declined.
        if h as isize > 32 {
            Ok(())
        } else {
            Err(format!(
                "The uninstall tool could not start (code {}).",
                h as isize
            ))
        }
    }
    #[cfg(not(windows))]
    {
        Err("Only available on Windows.".into())
    }
}

#[tauri::command]
fn get_window_mode(app: AppHandle) -> WindowMode {
    *state(&app).mode.lock().unwrap()
}

#[tauri::command]
fn set_window_mode(app: AppHandle, mode: WindowMode) -> Result<(), String> {
    *state(&app).mode.lock().unwrap() = mode;
    let w = app.get_webview_window(MAIN).ok_or("no window")?;
    apply_mode(&w, mode).map_err(|e| e.to_string())?;
    if mode == WindowMode::Window {
        let _ = w.center();
    }
    Ok(())
}

#[tauri::command]
fn mica_enabled(app: AppHandle) -> bool {
    *state(&app).mica.lock().unwrap()
}

/// Close the window; it is rebuilt on demand (see `window.rs`).
#[tauri::command]
fn hide_window(app: AppHandle) {
    close_main(&app);
}

/// The UI has mounted and listens for events: show a freshly built window and
/// hand over the tab / quick-check requests made while it didn't exist.
#[tauri::command]
fn ui_ready(app: AppHandle) -> UiIntent {
    let intent = state(&app).intents.lock().unwrap().ready();
    let show = std::mem::take(&mut *state(&app).show_on_ready.lock().unwrap());
    if show {
        if let Some(w) = app.get_webview_window(MAIN) {
            present(&app, &w);
        }
    }
    intent
}

// ---- Window behaviour --------------------------------------------------------

/// Windows 11 (build 22000+) supports the Mica system backdrop.
#[cfg(windows)]
fn supports_mica() -> bool {
    use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
    use windows_sys::Win32::System::SystemInformation::OSVERSIONINFOW;
    let mut v: OSVERSIONINFOW = unsafe { std::mem::zeroed() };
    v.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOW>() as u32;
    unsafe { RtlGetVersion(&mut v) == 0 && v.dwMajorVersion >= 10 && v.dwBuildNumber >= 22000 }
}
#[cfg(not(windows))]
fn supports_mica() -> bool {
    false
}

/// Mica follows the system light/dark theme automatically (no fixed variant).
fn apply_backdrop(app: &AppHandle, w: &WebviewWindow) {
    use tauri::window::{Effect, EffectsBuilder};
    let ok = supports_mica()
        && w.set_effects(EffectsBuilder::new().effect(Effect::Mica).build())
            .is_ok();
    *state(app).mica.lock().unwrap() = ok;
}

fn apply_mode(w: &WebviewWindow, mode: WindowMode) -> tauri::Result<()> {
    let flyout = mode == WindowMode::Flyout;
    w.set_decorations(!flyout)?;
    w.set_always_on_top(flyout)?;
    w.set_skip_taskbar(flyout)?;
    w.set_resizable(!flyout)?;
    Ok(())
}

/// Place the flyout next to the tray icon inside the monitor's work area,
/// like Windows 11 flyouts (12px margin from the taskbar edge).
fn position_flyout(app: &AppHandle, w: &WebviewWindow) {
    let anchor = *state(app).tray_anchor.lock().unwrap();
    let monitor = anchor
        .and_then(|(x, y, _, _)| w.monitor_from_point(x, y).ok().flatten())
        .or_else(|| w.primary_monitor().ok().flatten());
    let Some(monitor) = monitor else { return };
    let wa = monitor.work_area();
    let size = w.outer_size().unwrap_or(PhysicalSize::new(420, 600));
    let (ww, wh) = (size.width as i32, size.height as i32);
    let margin = (12.0 * monitor.scale_factor()).round() as i32;
    let (left, top) = (wa.position.x, wa.position.y);
    let (right, bottom) = (left + wa.size.width as i32, top + wa.size.height as i32);
    let (cx, cy) = match anchor {
        Some((x, y, aw, ah)) => ((x + aw / 2.0) as i32, (y + ah / 2.0) as i32),
        None => (right, bottom), // no anchor: bottom-right, where the tray usually is
    };
    let x = if cx > (left + right) / 2 {
        (cx + ww / 2).min(right - margin) - ww
    } else {
        (cx - ww / 2).max(left + margin)
    };
    let x = x.clamp(left + margin, (right - ww - margin).max(left + margin));
    let y = if cy > (top + bottom) / 2 {
        bottom - wh - margin
    } else {
        top + margin
    };
    let _ = w.set_position(PhysicalPosition::new(x, y));
}

/// Build the window from its config entry. `create: false` in
/// `tauri.conf.json`: it doesn't exist until something needs it, and is
/// destroyed again when hidden, so an idle tray runs no WebView2 at all.
fn create_main(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|w| w.label == MAIN)
        .cloned()
        .ok_or(tauri::Error::WindowNotFound)?;
    let w = WebviewWindowBuilder::from_config(app, &config)?
        .additional_browser_args(window::BROWSER_ARGS)
        .visible(false)
        .build()?;
    let mode = *state(app).mode.lock().unwrap();
    apply_mode(&w, mode)?;
    if mode == WindowMode::Window {
        let _ = w.center();
    }
    apply_backdrop(app, &w);
    Ok(w)
}

fn present(app: &AppHandle, w: &WebviewWindow) {
    if *state(app).mode.lock().unwrap() == WindowMode::Flyout {
        position_flyout(app, w);
    }
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        *state(app).show_on_ready.lock().unwrap() = false;
        present(app, &w);
        return;
    }
    if let Err(e) = create_main(app) {
        log::warn!("tray window: {e}");
        return;
    }
    *state(app).show_on_ready.lock().unwrap() = true;
    // Normally `ui_ready` shows it; don't leave it invisible if the UI fails.
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(SHOW_FALLBACK).await;
        let pending = std::mem::take(&mut *state(&app2).show_on_ready.lock().unwrap());
        if pending {
            if let Some(w) = app2.get_webview_window(MAIN) {
                present(&app2, &w);
            }
        }
    });
}

/// Destroy the window (and with it the WebView2 processes).
fn close_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window(MAIN) {
        if let Err(e) = w.destroy() {
            log::warn!("tray window close: {e}");
        }
    }
}

/// Send a tab / quick-check request to the UI now, or keep it until the
/// (re)built UI is ready.
fn send_intent(app: &AppHandle, intent: UiIntent) {
    let now = state(app).intents.lock().unwrap().deliver(intent);
    if let Some(i) = now {
        if i.quick_check {
            let _ = app.emit(EV_QUICK_CHECK, ());
        }
        if let Some(tab) = i.tab {
            let _ = app.emit(EV_NAVIGATE, tab);
        }
    }
}

fn toggle_main(app: &AppHandle) {
    // Clicking the tray icon steals focus first, which closes the flyout via
    // blur (the window may already be gone); treat a click within 300ms of
    // that as "close" rather than reopening.
    let recently_hidden = state(app)
        .blur_hidden_at
        .lock()
        .unwrap()
        .map(|t| t.elapsed() < Duration::from_millis(300))
        .unwrap_or(false);
    let visible = app
        .get_webview_window(MAIN)
        .is_some_and(|w| w.is_visible().unwrap_or(false));
    if visible {
        close_main(app);
    } else if !recently_hidden {
        show_main(app);
    }
}

// ---- Push subscription -------------------------------------------------------

/// Keep one `Subscribe` connection open; reconnect with backoff.
async fn run_subscriber(app: AppHandle) {
    let client = state(&app).client.clone();
    let mut attempt: u32 = 0;
    loop {
        match subscribe_once(&app, &client).await {
            Ok(()) => attempt = 0, // clean close; retry quickly
            Err(e) => {
                log::info!("tray subscription ({}) ended: {e}", client.describe());
                note_err(&app, &e);
                if !matches!(e, ClientError::Unavailable(_)) {
                    set_connected(&app, false, Some(e.to_string()));
                }
            }
        }
        tokio::time::sleep(backoff(attempt)).await;
        attempt = attempt.saturating_add(1);
    }
}

async fn subscribe_once(app: &AppHandle, client: &Client) -> Result<(), ClientError> {
    // Ask for remote-session + consent pushes; older agents get a plain `Subscribe`.
    let sub = open_subscription(
        client,
        &[FEATURE_REMOTE_SESSION, FEATURE_REMOTE_CONSENT],
        REQ_TIMEOUT,
    )
    .await?;
    if sub.features.is_empty() {
        log::info!(
            "agent doesn't support subscribe_with; remote-session state comes from status polling"
        );
    }
    let mut conn = sub.conn;
    // Connected: refresh status so the tray icon is right immediately.
    let _ = get_status(app.clone()).await;
    loop {
        match read_response_lenient(&mut conn).await? {
            None => return Ok(()),
            Some(Ok(TrayResponse::Notification(item))) => on_push(app, item),
            Some(Ok(TrayResponse::Status(s))) => record_status(app, &s),
            Some(Ok(TrayResponse::RemoteSession(n))) => on_remote_session(app, n),
            Some(Ok(TrayResponse::ConsentRequest(r))) => on_consent_request(app, r),
            Some(Ok(other)) => log::debug!("ignoring push {other:?}"),
            // A newer agent may push kinds this tray doesn't know: skip the line.
            Some(Err(e)) => log::warn!("ignoring unparseable push: {e}"),
        }
    }
}

/// IT asks to connect: queue it, bring the flyout to the front with the
/// Allow / Deny prompt, and raise a toast pointing to it. No answer = deny.
fn on_consent_request(app: &AppHandle, req: ConsentRequest) {
    let fresh = state(app)
        .consents
        .lock()
        .unwrap()
        .push(req.clone(), now_ms());
    let _ = app.emit(EV_CONSENT_REQUEST, req.clone());
    if !fresh {
        return; // expired, duplicate or queue full: no second toast
    }
    show_main(app);
    let org = state(app)
        .last_status
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.org_name.clone())
        .unwrap_or_default();
    let title = if org.is_empty() {
        "Kestrel: IT wants to connect".to_string()
    } else {
        format!("Kestrel for {org}: IT wants to connect")
    };
    if let Err(e) = app
        .notification()
        .builder()
        .title(title)
        .body(consent::consent_toast_body(&req))
        .show()
    {
        log::warn!("toast failed: {e}");
    }
}

/// Requests still waiting for an answer (the UI loads these when it starts).
#[tauri::command]
fn get_pending_consents(app: AppHandle) -> Vec<ConsentRequest> {
    state(&app).consents.lock().unwrap().pending(now_ms())
}

/// Send the employee's answer on a fresh request connection.
#[tauri::command]
async fn respond_consent(
    app: AppHandle,
    request_id: String,
    allow: bool,
) -> Result<Ack, ClientError> {
    let request_id =
        uuid::Uuid::parse_str(&request_id).map_err(|e| ClientError::Protocol(e.to_string()))?;
    let client = state(&app).client.clone();
    let res = client
        .request(
            &TrayRequest::ConsentResponse { request_id, allow },
            REQ_TIMEOUT,
        )
        .await;
    match res {
        Ok(TrayResponse::Ack { ok, message }) => {
            state(&app).consents.lock().unwrap().remove(&request_id);
            Ok(Ack { ok, message })
        }
        Ok(other) => Err(ClientError::Protocol(format!(
            "unexpected response: {other:?}"
        ))),
        Err(e) => {
            // The agent rejected it (expired / unknown): it can't be answered again.
            if matches!(e, ClientError::Agent(_)) {
                state(&app).consents.lock().unwrap().remove(&request_id);
            }
            note_err(&app, &e);
            Err(e)
        }
    }
}

/// Patch the cached status with a remote-session push (`None` once it ends).
fn apply_remote_session(status: &mut TrayStatus, n: &RemoteSessionNotice) {
    status.remote_session = n.active.then(|| n.clone());
}

/// Remote-session pushes drive UI state only: the agent also sends a regular
/// `Notification` for start/end, which produces the toast.
fn on_remote_session(app: &AppHandle, n: RemoteSessionNotice) {
    let patched = {
        let st = state(app);
        let mut g = st.last_status.lock().unwrap();
        g.as_mut().map(|s| {
            apply_remote_session(s, &n);
            s.clone()
        })
    };
    if let Some(s) = &patched {
        update_tray(app, Some(s));
        let _ = app.emit(EV_STATUS, s.clone());
    }
    let _ = app.emit(EV_REMOTE_SESSION, n);
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = get_status(app2).await;
    });
}

fn on_push(app: &AppHandle, item: ActivityItem) {
    let _ = app.emit(EV_NOTIFICATION, item.clone());
    let org = state(app)
        .last_status
        .lock()
        .unwrap()
        .as_ref()
        .map(|s| s.org_name.clone())
        .unwrap_or_default();
    let window_open = app
        .get_webview_window(MAIN)
        .map(|w| w.is_visible().unwrap_or(false) && w.is_focused().unwrap_or(false))
        .unwrap_or(false);
    // Critical notices are always shown, even when the window is open. Info-level
    // items (e.g. "settings updated") only appear in Activity.
    let show =
        item.severity == Severity::Critical || (!window_open && item.severity != Severity::Info);
    if show {
        let (title, body) = toast_text(&org, &item);
        if let Err(e) = app.notification().builder().title(title).body(body).show() {
            log::warn!("toast failed: {e}");
        }
    }
    // State (e.g. Attention) usually changes with a push.
    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        let _ = get_status(app2).await;
    });
}

fn toast_text(org: &str, item: &ActivityItem) -> (String, String) {
    let title = if org.is_empty() {
        "Kestrel".to_string()
    } else {
        format!("Kestrel for {org}")
    };
    let body = match item.review {
        Some(ReviewState::Approved) => format!("IT approved your review request. {}", item.title),
        Some(ReviewState::Denied) => format!(
            "IT reviewed your request and kept the block. {}",
            item.title
        ),
        _ => format!(
            "{}. {}",
            item.title.trim_end_matches('.'),
            item.action_taken
        ),
    };
    (title, body.chars().take(250).collect())
}

async fn poll_status(app: AppHandle) {
    loop {
        tokio::time::sleep(STATUS_POLL).await;
        let _ = get_status(app.clone()).await;
    }
}

// ---- App entry ---------------------------------------------------------------

fn build_tray(app: &AppHandle) -> tauri::Result<TrayIcon> {
    let open = MenuItem::with_id(app, "open", "Open Kestrel", true, None::<&str>)?;
    let check = MenuItem::with_id(app, "check", "Quick check", true, None::<&str>)?;
    let contact = MenuItem::with_id(app, "contact", "Contact IT", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&open, &check, &contact, &sep, &quit])?;

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(Image::from_bytes(tray_png(None))?)
        .tooltip(tray_tooltip(None))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, ev| match ev.id().as_ref() {
            "open" => show_main(app),
            "check" => {
                send_intent(app, UiIntent::quick_check());
                show_main(app);
            }
            "contact" => {
                send_intent(app, UiIntent::tab("help"));
                show_main(app);
            }
            // Quitting only closes this app; the agent service keeps protecting.
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, ev| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                rect,
                ..
            } = ev
            {
                let app = tray.app_handle();
                // The rect is physical on Windows; the scale only matters elsewhere.
                let scale = app
                    .get_webview_window(MAIN)
                    .and_then(|w| w.scale_factor().ok())
                    .or_else(|| {
                        app.primary_monitor()
                            .ok()
                            .flatten()
                            .map(|m| m.scale_factor())
                    })
                    .unwrap_or(1.0);
                let p = rect.position.to_physical::<f64>(scale);
                let s = rect.size.to_physical::<f64>(scale);
                *state(app).tray_anchor.lock().unwrap() = Some((p.x, p.y, s.width, s.height));
                toggle_main(app);
            }
        })
        .build(app)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let background = std::env::args().any(|a| a == "--background");
    let client = Arc::new(Client::from_env());

    tauri::Builder::default()
        // Must be registered first so a second launch exits before doing work.
        .plugin(tauri_plugin_single_instance::init(|app, args, _cwd| {
            // A background start (Run key at logon, or the agent after an
            // install) racing the running tray must not open the window.
            if !args.iter().any(|a| a == "--background") {
                show_main(app)
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            client,
            last_status: Mutex::new(None),
            connected: Mutex::new(false),
            mode: Mutex::new(WindowMode::Flyout),
            blur_hidden_at: Mutex::new(None),
            tray_anchor: Mutex::new(None),
            mica: Mutex::new(false),
            consents: Mutex::new(consent::ConsentQueue::default()),
            intents: Mutex::new(IntentBox::default()),
            show_on_ready: Mutex::new(false),
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            get_activity,
            quick_check,
            request_review,
            open_link,
            launch_uninstaller,
            get_window_mode,
            set_window_mode,
            mica_enabled,
            hide_window,
            ui_ready,
            get_pending_consents,
            respond_consent,
            pause_protection,
            resume_protection
        ])
        .setup(move |app| {
            let handle = app.handle().clone();
            build_tray(&handle)?;
            // Started at logon (`--background`): no window, so no WebView2.
            if window_needed(!background, false) {
                show_main(&handle);
            }
            tauri::async_runtime::spawn(run_subscriber(handle.clone()));
            tauri::async_runtime::spawn(poll_status(handle));
            Ok(())
        })
        .on_window_event(|window, event| {
            let app = window.app_handle();
            match event {
                // Closing (or a flyout losing focus) destroys the window; the
                // app lives in the tray and rebuilds it on demand, so no
                // hidden WebView2 is left running.
                WindowEvent::Focused(false) => {
                    let mode = *state(app).mode.lock().unwrap();
                    let visible = window.is_visible().unwrap_or(false);
                    // A pending IT consent prompt keeps the flyout open until answered or expired.
                    let consents = !state(app).consents.lock().unwrap().is_empty(now_ms());
                    if blur_action(mode, visible, consents) == BlurAction::Destroy {
                        *state(app).blur_hidden_at.lock().unwrap() = Some(Instant::now());
                        let _ = window.destroy();
                    }
                }
                WindowEvent::Destroyed => {
                    state(app).intents.lock().unwrap().reset();
                    *state(app).show_on_ready.lock().unwrap() = false;
                }
                _ => {}
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Kestrel tray")
        .run(|_app, event| {
            // The last window closing must not end the app (it lives in the
            // tray); only "Quit" (`app.exit`, which sets a code) does.
            if let RunEvent::ExitRequested { api, code, .. } = event {
                if code.is_none() {
                    api.prevent_exit();
                }
            }
        });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        assert!(is_safe_link("https://help.example.com/kestrel"));
        assert!(is_safe_link("mailto:it@example.com"));
        assert!(is_safe_link("tel:+62 21 5088 1200"));
        assert!(!is_safe_link("javascript:alert(1)"));
        assert!(!is_safe_link("file:///C:/Windows/System32/calc.exe"));
        assert!(!is_safe_link("ms-settings:"));
        assert!(!is_safe_link("tel:123;rm"));
        assert!(!is_safe_link("https://a\nb"));
    }

    #[test]
    fn tooltip_names_state_and_fits() {
        let mut s = mock::sample_status(ProtectionState::Isolated);
        assert!(tray_tooltip(Some(&s)).contains("Network limited"));
        s.org_name = "x".repeat(400);
        assert!(tray_tooltip(Some(&s)).chars().count() <= 127);
        assert!(tray_tooltip(None).contains("isn't running"));
    }

    #[test]
    fn tooltip_names_remote_session_first() {
        let mut s = mock::sample_status(ProtectionState::Protected);
        s.remote_session = Some(mock::sample_remote_session(false));
        let t = tray_tooltip(Some(&s));
        assert!(t.starts_with("Kestrel: IT is connected"));
        assert!(t.contains("Rina Wijaya is controlling your screen"));
        s.remote_session = Some(mock::sample_remote_session(true));
        assert!(tray_tooltip(Some(&s)).contains("viewing your screen"));
        s.remote_session.as_mut().unwrap().kind = RemoteKind::Files;
        assert!(tray_tooltip(Some(&s)).contains("accessing your files"));
        s.remote_session.as_mut().unwrap().admin_name = "x".repeat(400);
        assert!(tray_tooltip(Some(&s)).chars().count() <= 127);
        s.remote_session.as_mut().unwrap().active = false;
        assert_eq!(
            tray_tooltip(Some(&s)),
            "Kestrel: Protected\nNusantara Logistik"
        );
    }

    #[test]
    fn tooltip_and_icon_say_protection_is_off() {
        let mut s = mock::sample_status(ProtectionState::Attention);
        let paused: &[u8] = include_bytes!("../icons/tray/paused.png");
        assert_ne!(tray_png(Some(&s)), paused);
        s.pause = Some(mock::sample_pause(PauseMode::DetectionOnly, false));
        assert!(tray_tooltip(Some(&s)).starts_with("Kestrel: Protection is off (detection only)"));
        assert_eq!(tray_png(Some(&s)), paused);
        s.pause = Some(mock::sample_pause(PauseMode::Full, true));
        assert!(tray_tooltip(Some(&s)).contains("Protection is off (completely)"));
        // An IT remote session is still named first.
        s.remote_session = Some(mock::sample_remote_session(true));
        assert!(tray_tooltip(Some(&s)).starts_with("Kestrel: IT is connected"));
    }

    #[test]
    fn remote_push_patches_status() {
        let mut s = mock::sample_status(ProtectionState::Protected);
        let mut n = mock::sample_remote_session(true);
        apply_remote_session(&mut s, &n);
        assert_eq!(s.remote_session.as_ref(), Some(&n));
        n.active = false;
        n.ended_at = Some(n.started_at + 1);
        apply_remote_session(&mut s, &n);
        assert_eq!(s.remote_session, None);
    }

    #[test]
    fn toast_mentions_org_and_action() {
        let item = mock::sample_activity().remove(0);
        let (t, b) = toast_text("Nusantara Logistik", &item);
        assert_eq!(t, "Kestrel for Nusantara Logistik");
        assert!(b.contains("setup_x64.exe") && b.contains("quarantined"));
    }
}
