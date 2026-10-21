//! The employee banner: a topmost, click-through, non-activating popup at
//! the top centre of the primary monitor ("IT (Jane) is viewing this PC").
//!
//! `RegisterClassExW` → `CreateWindowExW(WS_EX_TOPMOST | WS_EX_TOOLWINDOW |
//! WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TRANSPARENT, WS_POPUP)` →
//! `SetLayeredWindowAttributes(LWA_ALPHA)` → `ShowWindow(SW_SHOWNOACTIVATE)`
//! → `SetTimer` (re-assert `HWND_TOPMOST` every 2 s). `WM_CLOSE` is ignored,
//! `WM_NCHITTEST` returns `HTTRANSPARENT`. It runs on its own thread, which
//! never calls `SetThreadDesktop`, so it lives on `winsta0\default` and is not
//! visible on the secure desktop (UAC prompt, lock screen).

use super::super::util::wide;
use std::sync::mpsc;
use std::sync::Mutex;
use windows_sys::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, SIZE, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect, GetDC,
    GetMonitorInfoW, GetTextExtentPoint32W, InvalidateRect, MonitorFromPoint, ReleaseDC,
    SelectObject, SetBkMode, SetTextColor, CLEARTYPE_QUALITY, DEFAULT_CHARSET, DT_CENTER,
    DT_END_ELLIPSIS, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, FW_SEMIBOLD, HFONT, MONITORINFO,
    MONITOR_DEFAULTTOPRIMARY, PAINTSTRUCT, TRANSPARENT,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::HiDpi::{GetDpiForMonitor, MDT_EFFECTIVE_DPI};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW, PostMessageW,
    PostQuitMessage, RegisterClassExW, SetLayeredWindowAttributes, SetTimer, SetWindowPos,
    ShowWindow, TranslateMessage, HTTRANSPARENT, HWND_TOPMOST, LWA_ALPHA, MA_NOACTIVATE, MSG,
    SWP_NOACTIVATE, SWP_SHOWWINDOW, SW_SHOWNOACTIVATE, WM_APP, WM_CLOSE, WM_DESTROY,
    WM_DISPLAYCHANGE, WM_ERASEBKGND, WM_MOUSEACTIVATE, WM_NCHITTEST, WM_PAINT, WM_TIMER,
    WNDCLASSEXW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
    WS_EX_TRANSPARENT, WS_POPUP,
};

const WM_SET_TEXT: u32 = WM_APP + 1;
const WM_SHUTDOWN: u32 = WM_APP + 2;
const TIMER_ID: usize = 1;
/// COLORREF is 0x00BBGGRR: amber background, black text and border.
const BG: COLORREF = 0x0000_C8FF;
const FG: COLORREF = 0x0000_0000;

/// Latest text for the banner thread (one banner per helper process).
static TEXT: Mutex<String> = Mutex::new(String::new());

thread_local! {
    static FONT: std::cell::Cell<HFONT> = const { std::cell::Cell::new(std::ptr::null_mut()) };
}

/// Handle to the banner window (owned by its own thread).
pub struct Banner {
    hwnd: usize,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Banner {
    /// Create and show the banner; fails if the window cannot be created.
    pub fn start(text: &str) -> Result<Banner, String> {
        if let Ok(mut t) = TEXT.lock() {
            *t = text.to_string();
        }
        let (tx, rx) = mpsc::channel::<Result<usize, String>>();
        let thread = std::thread::Builder::new()
            .name("kestrel-banner".into())
            .spawn(move || banner_thread(tx))
            .map_err(|e| format!("cannot start the banner thread: {e}"))?;
        match rx.recv_timeout(std::time::Duration::from_secs(10)) {
            Ok(Ok(hwnd)) => Ok(Banner {
                hwnd,
                thread: Some(thread),
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => Err("the banner window did not appear".into()),
        }
    }

    pub fn set_text(&self, text: &str) {
        if let Ok(mut t) = TEXT.lock() {
            *t = text.to_string();
        }
        unsafe {
            PostMessageW(self.hwnd as HWND, WM_SET_TEXT, 0, 0);
        }
    }

    /// Remove the banner and wait (briefly) for its thread.
    pub fn close(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        unsafe {
            PostMessageW(self.hwnd as HWND, WM_SHUTDOWN, 0, 0);
        }
        if let Some(t) = self.thread.take() {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while !t.is_finished() && std::time::Instant::now() < deadline {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

impl Drop for Banner {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.shutdown();
        }
    }
}

fn current_text() -> Vec<u16> {
    let t = TEXT.lock().map(|t| t.clone()).unwrap_or_default();
    t.encode_utf16().collect()
}

/// Primary monitor rectangle and its effective DPI.
fn primary_monitor() -> (RECT, u32) {
    unsafe {
        let mon = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let mut mi: MONITORINFO = std::mem::zeroed();
        mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
        let rect = if GetMonitorInfoW(mon, &mut mi) != 0 {
            mi.rcMonitor
        } else {
            RECT {
                left: 0,
                top: 0,
                right: 1024,
                bottom: 768,
            }
        };
        let (mut dx, mut dy) = (96u32, 96u32);
        if GetDpiForMonitor(mon, MDT_EFFECTIVE_DPI, &mut dx, &mut dy) != 0 {
            dy = 96;
        }
        (rect, dy.clamp(96, 480))
    }
}

/// (Re)create the font for `dpi` and place the window over the primary
/// monitor's top centre, sized to the text.
fn layout(hwnd: HWND) {
    let (mon, dpi) = primary_monitor();
    let px = |v: i32| v * dpi as i32 / 96;
    unsafe {
        let face = wide("Segoe UI");
        let font = CreateFontW(
            -px(16),
            0,
            0,
            0,
            FW_SEMIBOLD as i32,
            0,
            0,
            0,
            DEFAULT_CHARSET as u32,
            0,
            0,
            CLEARTYPE_QUALITY as u32,
            0,
            face.as_ptr(),
        );
        let old = FONT.with(|f| f.replace(font));
        if !old.is_null() {
            DeleteObject(old);
        }
        let text = current_text();
        let mut sz = SIZE { cx: 400, cy: 20 };
        let dc = GetDC(hwnd);
        if !dc.is_null() {
            let prev = SelectObject(dc, font);
            GetTextExtentPoint32W(dc, text.as_ptr(), text.len() as i32, &mut sz);
            SelectObject(dc, prev);
            ReleaseDC(hwnd, dc);
        }
        let mon_w = mon.right - mon.left;
        let w = (sz.cx + px(48)).min(mon_w - px(16)).max(px(200));
        let h = sz.cy + px(16);
        let x = mon.left + (mon_w - w) / 2;
        let y = mon.top;
        SetWindowPos(
            hwnd,
            HWND_TOPMOST,
            x,
            y,
            w,
            h,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        );
        InvalidateRect(hwnd, std::ptr::null(), 1);
    }
}

fn paint(hwnd: HWND) {
    unsafe {
        let mut ps: PAINTSTRUCT = std::mem::zeroed();
        let dc = BeginPaint(hwnd, &mut ps);
        if dc.is_null() {
            return;
        }
        let mut rc = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect(hwnd, &mut rc);
        let border = CreateSolidBrush(FG);
        let fill = CreateSolidBrush(BG);
        FillRect(dc, &rc, border);
        let inner = RECT {
            left: rc.left + 2,
            top: rc.top,
            right: rc.right - 2,
            bottom: rc.bottom - 2,
        };
        FillRect(dc, &inner, fill);
        DeleteObject(border);
        DeleteObject(fill);
        let font = FONT.with(|f| f.get());
        let prev = SelectObject(dc, font);
        SetBkMode(dc, TRANSPARENT as i32);
        SetTextColor(dc, FG);
        let mut text = current_text();
        let mut trc = inner;
        DrawTextW(
            dc,
            text.as_mut_ptr(),
            text.len() as i32,
            &mut trc,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX | DT_END_ELLIPSIS,
        );
        SelectObject(dc, prev);
        EndPaint(hwnd, &ps);
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        // The employee cannot close the notice.
        WM_CLOSE => 0,
        WM_NCHITTEST => HTTRANSPARENT as LRESULT,
        WM_MOUSEACTIVATE => MA_NOACTIVATE as LRESULT,
        WM_ERASEBKGND => 1,
        WM_PAINT => {
            paint(hwnd);
            0
        }
        WM_TIMER => {
            SetWindowPos(
                hwnd,
                HWND_TOPMOST,
                0,
                0,
                0,
                0,
                windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOMOVE
                    | windows_sys::Win32::UI::WindowsAndMessaging::SWP_NOSIZE
                    | SWP_NOACTIVATE
                    | SWP_SHOWWINDOW,
            );
            0
        }
        WM_DISPLAYCHANGE | WM_SET_TEXT => {
            layout(hwnd);
            0
        }
        WM_SHUTDOWN => {
            DestroyWindow(hwnd);
            0
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            0
        }
        _ => DefWindowProcW(hwnd, msg, wp, lp),
    }
}

fn banner_thread(ready: mpsc::Sender<Result<usize, String>>) {
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("KestrelRemoteSessionBanner");
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: 0,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: std::ptr::null_mut(),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        // 0 = failure, but ERROR_CLASS_ALREADY_EXISTS is fine (CreateWindowExW
        // reports any real problem).
        RegisterClassExW(&wc);
        let title = wide("Kestrel remote session");
        let hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE | WS_EX_LAYERED | WS_EX_TRANSPARENT,
            class.as_ptr(),
            title.as_ptr(),
            WS_POPUP,
            0,
            0,
            400,
            32,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            let _ = ready.send(Err(format!(
                "cannot create the banner window: {}",
                std::io::Error::last_os_error()
            )));
            return;
        }
        SetLayeredWindowAttributes(hwnd, 0, 235, LWA_ALPHA);
        layout(hwnd);
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetTimer(hwnd, TIMER_ID, 2000, None);
        let _ = ready.send(Ok(hwnd as usize));
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        let f = FONT.with(|f| f.replace(std::ptr::null_mut()));
        if !f.is_null() {
            DeleteObject(f);
        }
    }
}
