//! The uninstall dialog: a plain Win32 window with Common Controls v6
//! (visual styles come from the embedded manifest), Segoe UI 9 pt, laid out
//! in device-independent pixels and re-laid out on `WM_DPICHANGED`
//! (per-monitor v2). `IsDialogMessageW` gives Tab / Enter / Escape their
//! dialog meaning: Enter is `IDOK` (the default button), Escape `IDCANCEL`.
//!
//! The removal runs on a worker thread that posts its result back
//! (`WM_WORK_DONE`), so the window keeps painting while Windows Installer
//! works.

use super::{purge, system, wide};
use crate::{
    check_token, classify, exit_code, failure_message, log_mentions_invalid_token, parse_args, rc,
    wipe_string, wipe_wide, Mode, Outcome, MSG_DECOMMISSION, MSG_NOT_ELEVATED, MSG_NOT_INSTALLED,
    MSG_REBOOT, MSG_REMOVED, MSG_WRONG_TOKEN, UNUSUAL_PREFIX_WARNING, USAGE,
};
use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi::{
    CreateFontIndirectW, DeleteObject, DrawTextW, FillRect, GetDC, GetMonitorInfoW, GetSysColor,
    GetSysColorBrush, InvalidateRect, MonitorFromWindow, ReleaseDC, SelectObject, SetBkColor,
    SetTextColor, CLEARTYPE_QUALITY, COLOR_BTNFACE, COLOR_WINDOW, COLOR_WINDOWTEXT,
    DEFAULT_CHARSET, DT_CALCRECT, DT_EDITCONTROL, DT_NOPREFIX, DT_WORDBREAK, FF_MODERN,
    FIXED_PITCH, FW_NORMAL, FW_SEMIBOLD, HDC, HFONT, LOGFONTW, MONITORINFO,
    MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::Diagnostics::Debug::MessageBeep;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::SystemServices::{SS_EDITCONTROL, SS_LEFT, SS_NOPREFIX};
use windows_sys::Win32::UI::Controls::{
    InitCommonControlsEx, BST_CHECKED, EM_LIMITTEXT, EM_SCROLLCARET, EM_SETPASSWORDCHAR, EM_SETSEL,
    ICC_PROGRESS_CLASS, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, PBM_SETMARQUEE, PBS_MARQUEE,
    PROGRESS_CLASSW,
};
use windows_sys::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, GetDpiForWindow, GetSystemMetricsForDpi,
};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::{EnableWindow, SetFocus};
use windows_sys::Win32::UI::Shell::{DefSubclassProc, SetWindowSubclass};
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const ID_TOKEN: i32 = 100;
const ID_SHOW: i32 = 101;
const ID_PURGE: i32 = 102;
const ID_LOG: i32 = 103;
const WM_WORK_DONE: u32 = WM_APP + 1;
/// Bullet shown for each hidden token character (the v6 edit default).
const PASSWORD_CHAR: usize = 0x25CF;
/// Width of the client area at 96 DPI.
const CLIENT_W: i32 = 468;
const MARGIN: i32 = 20;

const INTRO: &str = "Removing Kestrel stops protection on this PC. You need this PC's uninstall token: your IT administrator can find it in the Kestrel console, on this device's page, under Uninstall token.";
const PREVIEW_NOTE: &str = "Preview: nothing will be changed.";
const PREVIEW_DONE: &str = "Preview: nothing was changed or deleted.";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Screen {
    Form,
    Working,
    Done,
}

struct Ctl {
    preview: HWND,
    intro: HWND,
    label: HWND,
    edit: HWND,
    show: HWND,
    purge: HWND,
    inline: HWND,
    progress_label: HWND,
    progress: HWND,
    head: HWND,
    body: HWND,
    /// Read-only view of the installer log (instead of starting an
    /// elevated Notepad, whose File > Open dialog would hand an elevated
    /// shell to whoever sits at the keyboard).
    logview: HWND,
    primary: HWND,
    secondary: HWND,
    log: HWND,
}

struct App {
    hwnd: HWND,
    preview: bool,
    dpi: u32,
    font: HFONT,
    head_font: HFONT,
    c: Ctl,
    screen: Screen,
    outcome: Option<Outcome>,
    log: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    positioned: bool,
    /// Private work folder of the last attempt (pinned until exit).
    work: Option<system::WorkDir>,
    /// Result channel of the running worker.
    rx: Option<std::sync::mpsc::Receiver<WorkResult>>,
    /// Monospace font of the log view.
    mono_font: HFONT,
    log_shown: bool,
}

struct WorkResult {
    outcome: Outcome,
    log: Option<PathBuf>,
    purge: Option<String>,
    /// Keeps the private work folder pinned while the window is open.
    work: Option<system::WorkDir>,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
    /// Painting state read without borrowing APP (paint messages arrive
    /// re-entrantly while APP is borrowed).
    static FOOTER_TOP: Cell<i32> = const { Cell::new(i32::MAX) };
    static INLINE_HWND: Cell<isize> = const { Cell::new(0) };
    static INLINE_ERROR: Cell<bool> = const { Cell::new(false) };
    static EXIT_CODE: Cell<i32> = const { Cell::new(2) };
}

// ---------------------------------------------------------------- helpers

fn msgbox(hwnd: HWND, text: &str, style: MESSAGEBOX_STYLE) {
    let t = wide(text);
    let c = wide("Uninstall Kestrel EDR");
    // SAFETY: valid strings.
    unsafe { MessageBoxW(hwnd, t.as_ptr(), c.as_ptr(), style | MB_OK) };
}

fn scale(v: i32, dpi: u32) -> i32 {
    (v * dpi as i32 + 48) / 96
}

fn make_font(dpi: u32, points: i32, weight: i32) -> HFONT {
    // SAFETY: plain C struct.
    let mut lf: LOGFONTW = unsafe { std::mem::zeroed() };
    lf.lfHeight = -((points * dpi as i32 + 36) / 72);
    lf.lfWeight = weight;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    for (d, s) in lf.lfFaceName.iter_mut().zip("Segoe UI".encode_utf16()) {
        *d = s;
    }
    // SAFETY: valid LOGFONTW.
    unsafe { CreateFontIndirectW(&lf) }
}

fn create(parent: HWND, class: *const u16, text: &str, style: u32, ex: u32, id: i32) -> HWND {
    let t = wide(text);
    // SAFETY: valid strings; child id passed as the menu handle.
    unsafe {
        CreateWindowExW(
            ex,
            class,
            t.as_ptr(),
            WS_CHILD | style,
            0,
            0,
            0,
            0,
            parent,
            id as isize as HMENU,
            GetModuleHandleW(std::ptr::null()),
            std::ptr::null(),
        )
    }
}

fn make_mono_font(dpi: u32) -> HFONT {
    // SAFETY: plain C struct.
    let mut lf: LOGFONTW = unsafe { std::mem::zeroed() };
    lf.lfHeight = -((9 * dpi as i32 + 36) / 72);
    lf.lfWeight = FW_NORMAL as i32;
    lf.lfCharSet = DEFAULT_CHARSET;
    lf.lfQuality = CLEARTYPE_QUALITY;
    lf.lfPitchAndFamily = FIXED_PITCH | FF_MODERN;
    for (d, s) in lf.lfFaceName.iter_mut().zip("Consolas".encode_utf16()) {
        *d = s;
    }
    // SAFETY: valid LOGFONTW.
    unsafe { CreateFontIndirectW(&lf) }
}

/// Read-only multi-line edit inside a dialog-style window: give Tab and
/// Escape back to the dialog (a multi-line edit asks for all keys), so
/// keyboard users can leave the log view and Escape still closes.
unsafe extern "system" fn logview_proc(
    hwnd: HWND,
    msg: u32,
    wp: WPARAM,
    lp: LPARAM,
    _id: usize,
    _data: usize,
) -> LRESULT {
    let r = DefSubclassProc(hwnd, msg, wp, lp);
    if msg == WM_GETDLGCODE {
        return r & !((DLGC_WANTALLKEYS | DLGC_WANTTAB) as LRESULT);
    }
    r
}

fn set_text(h: HWND, s: &str) {
    let w = wide(s);
    // SAFETY: valid string.
    unsafe { SetWindowTextW(h, w.as_ptr()) };
}

fn get_text(h: HWND) -> String {
    let mut w = get_text_wide(h);
    let s = String::from_utf16_lossy(&w);
    wipe_wide(&mut w);
    s
}

/// The control's text as UTF-16 (no NUL). Caller wipes it.
fn get_text_wide(h: HWND) -> Vec<u16> {
    // SAFETY: buffer length passed.
    unsafe {
        let n = GetWindowTextLengthW(h).max(0) as usize;
        let mut buf = vec![0u16; n + 1];
        let got = GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32).max(0) as usize;
        buf.truncate(got);
        buf
    }
}

fn show(h: HWND, on: bool) {
    // SAFETY: plain call.
    unsafe { ShowWindow(h, if on { SW_SHOW } else { SW_HIDE }) };
}

fn enable(h: HWND, on: bool) {
    // SAFETY: plain call.
    unsafe { EnableWindow(h, on as i32) };
}

fn place(h: HWND, x: i32, y: i32, w: i32, hgt: i32) {
    // SAFETY: plain call.
    unsafe {
        SetWindowPos(
            h,
            std::ptr::null_mut(),
            x,
            y,
            w,
            hgt,
            SWP_NOZORDER | SWP_NOACTIVATE,
        )
    };
}

fn checked(h: HWND) -> bool {
    // SAFETY: plain call.
    unsafe { SendMessageW(h, BM_GETCHECK, 0, 0) as u32 == BST_CHECKED }
}

/// Height of `text` wrapped to `width` pixels in `font`.
fn measure(hwnd: HWND, font: HFONT, text: &str, width: i32) -> i32 {
    if text.is_empty() {
        return 0;
    }
    let w: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: DC obtained and released here; buffers valid.
    unsafe {
        let dc: HDC = GetDC(hwnd);
        let old = SelectObject(dc, font as _);
        let mut rc = RECT {
            left: 0,
            top: 0,
            right: width.max(1),
            bottom: 0,
        };
        DrawTextW(
            dc,
            w.as_ptr(),
            w.len() as i32,
            &mut rc,
            DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL | DT_NOPREFIX,
        );
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
        rc.bottom - rc.top
    }
}

fn text_width(hwnd: HWND, font: HFONT, text: &str) -> i32 {
    let w: Vec<u16> = text.encode_utf16().collect();
    // SAFETY: as above.
    unsafe {
        let dc: HDC = GetDC(hwnd);
        let old = SelectObject(dc, font as _);
        let mut rc = RECT {
            left: 0,
            top: 0,
            right: 0,
            bottom: 0,
        };
        DrawTextW(
            dc,
            w.as_ptr(),
            w.len() as i32,
            &mut rc,
            DT_CALCRECT | DT_NOPREFIX,
        );
        SelectObject(dc, old);
        ReleaseDC(hwnd, dc);
        rc.right - rc.left
    }
}

// ----------------------------------------------------------------- layout

impl App {
    fn s(&self, v: i32) -> i32 {
        scale(v, self.dpi)
    }

    fn all(&self) -> [HWND; 15] {
        let c = &self.c;
        [
            c.preview,
            c.intro,
            c.label,
            c.edit,
            c.show,
            c.purge,
            c.inline,
            c.progress_label,
            c.progress,
            c.head,
            c.body,
            c.logview,
            c.primary,
            c.secondary,
            c.log,
        ]
    }

    fn apply_fonts(&self) {
        for h in self.all() {
            let f = if h == self.c.head {
                self.head_font
            } else if h == self.c.logview {
                self.mono_font
            } else {
                self.font
            };
            // SAFETY: plain message.
            unsafe { SendMessageW(h, WM_SETFONT, f as WPARAM, 1) };
        }
    }

    /// Show the controls of the current screen and position everything.
    /// `origin`: new window top-left (DPI change); otherwise the window is
    /// centred the first time and keeps its position afterwards.
    fn layout(&mut self, origin: Option<(i32, i32)>) {
        let form = matches!(self.screen, Screen::Form | Screen::Working);
        let working = self.screen == Screen::Working;
        let done = self.screen == Screen::Done;
        let c = &self.c;
        show(c.preview, self.preview);
        for h in [c.intro, c.label, c.edit, c.show, c.purge, c.inline] {
            show(h, form);
        }
        show(c.progress_label, working);
        show(c.progress, working);
        show(c.head, done);
        show(c.body, done);
        show(c.secondary, !done);
        let log_ok = done
            && matches!(self.outcome, Some(Outcome::Failed { .. }))
            && self.log.as_ref().is_some_and(|p| p.exists());
        show(c.log, log_ok);
        show(c.logview, log_ok && self.log_shown);
        show(c.primary, true);

        let hwnd = self.hwnd;
        let f = self.font;
        let w = self.s(CLIENT_W);
        let m = self.s(MARGIN);
        let inner = w - 2 * m;
        let line = measure(hwnd, f, "Ag", inner);
        let mut y = self.s(18);
        if self.preview {
            let h = measure(hwnd, f, PREVIEW_NOTE, inner);
            place(c.preview, m, y, inner, h);
            y += h + self.s(10);
        }
        if form {
            let h = measure(hwnd, f, INTRO, inner);
            place(c.intro, m, y, inner, h);
            y += h + self.s(16);
            place(c.label, m, y, inner, line);
            y += line + self.s(5);
            let show_w = text_width(hwnd, f, "Show") + self.s(26);
            let eh = line + self.s(9);
            place(c.edit, m, y, inner - show_w - self.s(10), eh);
            let ch = line.max(self.s(17));
            place(c.show, m + inner - show_w, y + (eh - ch) / 2, show_w, ch);
            y += eh + self.s(14);
            let purge_text = get_text(c.purge);
            let h = measure(hwnd, f, &purge_text, inner - self.s(22)).max(ch);
            place(c.purge, m, y, inner, h);
            y += h + self.s(12);
            let it = get_text(c.inline);
            let h = measure(hwnd, f, &it, inner).max(2 * line);
            place(c.inline, m, y, inner, h);
            y += h + self.s(6);
            if working {
                place(c.progress_label, m, y, inner, line);
                y += line + self.s(6);
                place(c.progress, m, y, inner, self.s(12));
                y += self.s(12) + self.s(14);
            }
        } else {
            let ht = get_text(c.head);
            let h = measure(hwnd, self.head_font, &ht, inner);
            place(c.head, m, y, inner, h);
            y += h + self.s(10);
            let bt = get_text(c.body);
            let h = measure(hwnd, f, &bt, inner);
            place(c.body, m, y, inner, h);
            y += h + self.s(18);
            if log_ok && self.log_shown {
                let lh = self.s(220);
                place(c.logview, m, y, inner, lh);
                y += lh + self.s(14);
            }
        }

        // Footer band with right-aligned buttons.
        let pad = self.s(12);
        let bh = self.s(23);
        let bw = |t: &str| (text_width(hwnd, f, t) + self.s(24)).max(self.s(80));
        let footer_top = y;
        let height = y + bh + 2 * pad;
        let mut x = w - m;
        let gap = self.s(8);
        // Visibility is decided above (IsWindowVisible is false for every
        // child until the window itself is first shown).
        for (b, visible) in [(c.secondary, !done), (c.primary, true), (c.log, log_ok)] {
            if !visible {
                continue;
            }
            let bwid = bw(&get_text(b).replace('&', ""));
            x -= bwid;
            place(b, x, footer_top + pad, bwid, bh);
            x -= gap;
        }
        FOOTER_TOP.with(|t| t.set(footer_top));

        // Window size for this client area at this DPI.
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let mut r = RECT {
            left: 0,
            top: 0,
            right: w,
            bottom: height,
        };
        // SAFETY: valid rect.
        unsafe { AdjustWindowRectExForDpi(&mut r, style, 0, 0, self.dpi) };
        let (ww, wh) = (r.right - r.left, r.bottom - r.top);
        let (x, y) = match origin {
            Some(o) => o,
            None if !self.positioned => {
                // SAFETY: plain C struct.
                let mut mi: MONITORINFO = unsafe { std::mem::zeroed() };
                mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
                // SAFETY: valid struct.
                unsafe {
                    GetMonitorInfoW(MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST), &mut mi)
                };
                let wa = mi.rcWork;
                (
                    wa.left + ((wa.right - wa.left) - ww).max(0) / 2,
                    wa.top + ((wa.bottom - wa.top) - wh).max(0) / 2,
                )
            }
            None => {
                let mut cur = RECT {
                    left: 0,
                    top: 0,
                    right: 0,
                    bottom: 0,
                };
                // SAFETY: valid rect.
                unsafe { GetWindowRect(hwnd, &mut cur) };
                (cur.left, cur.top)
            }
        };
        self.positioned = true;
        // SAFETY: plain calls.
        unsafe {
            SetWindowPos(
                hwnd,
                std::ptr::null_mut(),
                x,
                y,
                ww,
                wh,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
            InvalidateRect(hwnd, std::ptr::null(), 1);
        }
    }

    fn set_inline(&mut self, text: &str, error: bool) {
        INLINE_ERROR.with(|e| e.set(error));
        set_text(self.c.inline, text);
        self.layout(None);
    }

    // ------------------------------------------------------------ actions

    fn start(&mut self) {
        let mut raw = get_text_wide(self.c.edit);
        let mut s = String::from_utf16_lossy(&raw);
        wipe_wide(&mut raw);
        let mut token = s.trim().to_string();
        wipe_string(&mut s);
        let chk = match check_token(&token) {
            Ok(c) => c,
            Err(e) => {
                wipe_string(&mut token);
                // SAFETY: plain calls.
                unsafe { MessageBeep(MB_ICONWARNING) };
                self.set_inline(e.message(), true);
                self.focus_token();
                return;
            }
        };
        let purge = checked(self.c.purge);
        let preview = self.preview;
        if preview {
            // Walk through the screens without touching anything.
            wipe_string(&mut token);
        }
        INLINE_ERROR.with(|e| e.set(false));
        set_text(
            self.c.inline,
            if chk.unusual_prefix {
                UNUSUAL_PREFIX_WARNING
            } else {
                ""
            },
        );
        self.screen = Screen::Working;
        for h in [
            self.c.edit,
            self.c.show,
            self.c.purge,
            self.c.primary,
            self.c.secondary,
        ] {
            enable(h, false);
        }
        // SAFETY: plain message.
        unsafe { SendMessageW(self.c.progress, PBM_SETMARQUEE, 1, 30) };
        self.layout(None);
        let hwnd = self.hwnd as isize;
        let state_dir = self.state_dir.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        self.rx = Some(rx);
        std::thread::spawn(move || {
            let run = std::panic::AssertUnwindSafe(move || {
                if preview {
                    std::thread::sleep(std::time::Duration::from_secs(3));
                    WorkResult {
                        outcome: Outcome::Removed {
                            reboot_required: false,
                        },
                        log: None,
                        purge: purge.then(|| PREVIEW_DONE.to_string()),
                        work: None,
                    }
                } else {
                    work(token, purge, state_dir)
                }
            });
            // A panic in the worker still ends the Working screen (and the
            // moved executable is put back by MovedSelf's Drop).
            let r = std::panic::catch_unwind(run).unwrap_or(WorkResult {
                outcome: Outcome::Failed {
                    code: rc::FUNCTION_FAILED,
                },
                log: None,
                purge: None,
                work: None,
            });
            let _ = tx.send(r);
            // The result travels over the channel; the message only wakes
            // the window (nothing in it is trusted).
            // SAFETY: the window cannot close while working (WM_CLOSE is
            // refused), so the handle is valid.
            unsafe { PostMessageW(hwnd as HWND, WM_WORK_DONE, 0, 0) };
        });
    }

    fn focus_token(&self) {
        // SAFETY: plain calls.
        unsafe {
            SetFocus(self.c.edit);
            SendMessageW(self.c.edit, EM_SETSEL, 0, -1);
        }
    }

    fn finished(&mut self, r: WorkResult) {
        // SAFETY: plain message.
        unsafe { SendMessageW(self.c.progress, PBM_SETMARQUEE, 0, 0) };
        for h in [
            self.c.edit,
            self.c.show,
            self.c.purge,
            self.c.primary,
            self.c.secondary,
        ] {
            enable(h, true);
        }
        self.log = r.log.clone();
        if r.work.is_some() {
            self.work = r.work;
        }
        // Preview changes nothing and exits 0.
        let code = if self.preview {
            0
        } else {
            exit_code(Some(&r.outcome))
        };
        EXIT_CODE.with(|c| c.set(code));
        self.outcome = Some(r.outcome.clone());
        if r.outcome == Outcome::WrongToken {
            self.screen = Screen::Form;
            // SAFETY: plain call.
            unsafe { MessageBeep(MB_ICONWARNING) };
            self.set_inline(MSG_WRONG_TOKEN, true);
            self.focus_token();
            return;
        }
        let (head, body) = match &r.outcome {
            Outcome::Removed { reboot_required } => {
                let mut b = MSG_DECOMMISSION.to_string();
                if *reboot_required {
                    b.push_str("\n\n");
                    b.push_str(MSG_REBOOT);
                }
                if let Some(p) = &r.purge {
                    b.push_str("\n\n");
                    b.push_str(p);
                }
                (MSG_REMOVED.to_string(), b)
            }
            Outcome::NotInstalled => (
                MSG_NOT_INSTALLED.to_string(),
                "Nothing was changed.".to_string(),
            ),
            Outcome::NotElevated => (
                "Kestrel was not removed.".to_string(),
                MSG_NOT_ELEVATED.to_string(),
            ),
            Outcome::Failed { code } => (
                "Kestrel was not removed.".to_string(),
                failure_message(
                    *code,
                    &r.log
                        .as_ref()
                        .filter(|p| p.exists())
                        .map(|p| p.display().to_string())
                        .unwrap_or_default(),
                ),
            ),
            Outcome::WrongToken => unreachable!("handled above"),
        };
        let mut body = body;
        if self.preview && !body.contains(PREVIEW_DONE) {
            body.push_str("\n\n");
            body.push_str(PREVIEW_DONE);
        }
        // The token is not needed any more (the Done screen has no way back).
        set_text(self.c.edit, "");
        set_text(self.c.head, &head);
        set_text(self.c.body, &body);
        set_text(self.c.primary, "Close");
        self.screen = Screen::Done;
        self.layout(None);
        // SAFETY: plain call.
        unsafe { SetFocus(self.c.primary) };
    }

    fn toggle_log(&mut self) {
        self.log_shown = !self.log_shown;
        if self.log_shown {
            let text = self
                .log
                .as_deref()
                .map(|l| crate::log_tail_text(&system::read_log(l), 256 * 1024))
                .unwrap_or_default();
            set_text(self.c.logview, &text);
            set_text(self.c.log, "Hide &log");
        } else {
            set_text(self.c.log, "Show &log");
        }
        self.layout(None);
        if self.log_shown {
            // SAFETY: plain messages; caret to the end (the failure is there).
            unsafe {
                let n = GetWindowTextLengthW(self.c.logview).max(0) as usize;
                SendMessageW(self.c.logview, EM_SETSEL, n, n as isize);
                SendMessageW(self.c.logview, EM_SCROLLCARET, 0, 0);
                SetFocus(self.c.logview);
            }
        }
    }

    fn toggle_show(&self) {
        let ch = if checked(self.c.show) {
            0
        } else {
            PASSWORD_CHAR
        };
        // SAFETY: plain calls.
        unsafe {
            SendMessageW(self.c.edit, EM_SETPASSWORDCHAR, ch, 0);
            InvalidateRect(self.c.edit, std::ptr::null(), 1);
        }
    }

    fn dpi_changed(&mut self, dpi: u32, suggested: &RECT) {
        self.dpi = dpi;
        // SAFETY: fonts created by us and replaced on the controls first.
        let (old_f, old_h) = (self.font, self.head_font);
        self.font = make_font(dpi, 9, FW_NORMAL as i32);
        self.head_font = make_font(dpi, 12, FW_SEMIBOLD as i32);
        let old_m = self.mono_font;
        self.mono_font = make_mono_font(dpi);
        self.apply_fonts();
        unsafe {
            DeleteObject(old_f as _);
            DeleteObject(old_h as _);
            DeleteObject(old_m as _);
        }
        self.layout(Some((suggested.left, suggested.top)));
    }
}

/// The worker: find the product, remove it, classify, purge.
fn work(mut token: String, purge: bool, state_dir: Option<PathBuf>) -> WorkResult {
    let done = |outcome, log, mut token: String| {
        wipe_string(&mut token);
        WorkResult {
            outcome,
            log,
            purge: None,
            work: None,
        }
    };
    if !system::is_elevated() {
        return done(Outcome::NotElevated, None, token);
    }
    let Some(pc) = system::installed_product() else {
        return done(Outcome::NotInstalled, None, token);
    };
    let work = system::work_dir();
    let log = work.as_ref().map(|w| w.log.clone());
    let mut moved = work.as_ref().and_then(system::move_self_aside);
    let code = system::uninstall(&pc, &token, log.as_deref());
    wipe_string(&mut token);
    let invalid = code == rc::INSTALL_FAILURE
        && log
            .as_deref()
            .is_some_and(|l| log_mentions_invalid_token(&system::read_log(l)));
    let outcome = classify(code, invalid, system::still_installed(&pc));
    if let Some(m) = moved.as_mut() {
        if matches!(outcome, Outcome::Removed { .. }) {
            m.delete_on_reboot();
        } else {
            m.restore();
        }
    }
    let purge_text = match (&outcome, purge, state_dir) {
        (Outcome::Removed { .. }, true, Some(dir)) => {
            let shown = dir.display().to_string();
            Some(match purge::purge_state_dir(&dir) {
                Ok(r) => r.summary(&shown),
                Err(e) => format!("{shown} was not deleted: {e}."),
            })
        }
        (Outcome::Removed { .. }, true, None) => {
            Some("The Kestrel data folder could not be located, so nothing was deleted.".into())
        }
        _ => None,
    };
    WorkResult {
        outcome,
        log,
        purge: purge_text,
        work,
    }
}

// --------------------------------------------------------------- wndproc

/// Run `f` on the app state unless it is already borrowed (re-entrant
/// message): then `None` and the caller falls back to `DefWindowProcW`.
fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|a| {
        let mut g = a.try_borrow_mut().ok()?;
        g.as_mut().map(f)
    })
}

fn paint_background(hwnd: HWND, dc: HDC) {
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    };
    // SAFETY: valid DC and rect; system brushes need no cleanup.
    unsafe {
        GetClientRect(hwnd, &mut rc);
        let top = FOOTER_TOP.with(|t| t.get()).min(rc.bottom);
        let body = RECT { bottom: top, ..rc };
        FillRect(dc, &body, GetSysColorBrush(COLOR_WINDOW));
        let foot = RECT { top, ..rc };
        FillRect(dc, &foot, GetSysColorBrush(COLOR_BTNFACE));
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_ERASEBKGND => {
            paint_background(hwnd, wp as HDC);
            return 1;
        }
        WM_PRINTCLIENT => {
            paint_background(hwnd, wp as HDC);
            return 0;
        }
        WM_CTLCOLORSTATIC => {
            let dc = wp as HDC;
            let err = INLINE_ERROR.with(|e| e.get()) && INLINE_HWND.with(|h| h.get()) == lp;
            SetTextColor(
                dc,
                if err {
                    0x001C_2BC4 // #C42B1C; the text itself says what is wrong
                } else {
                    GetSysColor(COLOR_WINDOWTEXT)
                },
            );
            SetBkColor(dc, GetSysColor(COLOR_WINDOW));
            return GetSysColorBrush(COLOR_WINDOW) as LRESULT;
        }
        WM_CTLCOLORBTN => {
            return GetSysColorBrush(COLOR_BTNFACE) as LRESULT;
        }
        DM_GETDEFID => {
            return ((DC_HASDEFID as LRESULT) << 16) | IDOK as LRESULT;
        }
        WM_COMMAND => {
            let id = (wp & 0xFFFF) as i32;
            let code = ((wp >> 16) & 0xFFFF) as u32;
            let handled = with_app(|app| match (id, code) {
                (IDOK, 0) => {
                    match app.screen {
                        Screen::Form => app.start(),
                        Screen::Done => {
                            DestroyWindow(app.hwnd);
                        }
                        Screen::Working => {}
                    }
                    true
                }
                (IDCANCEL, 0) => {
                    if app.screen == Screen::Working {
                        MessageBeep(MB_ICONWARNING);
                    } else {
                        DestroyWindow(app.hwnd);
                    }
                    true
                }
                (ID_SHOW, 0) => {
                    app.toggle_show();
                    true
                }
                (ID_LOG, 0) => {
                    app.toggle_log();
                    true
                }
                (ID_TOKEN, c) if c == EN_CHANGE => {
                    // Typing clears an error about the previous token.
                    if INLINE_ERROR.with(|e| e.get()) && app.screen == Screen::Form {
                        app.set_inline("", false);
                    }
                    true
                }
                _ => false,
            });
            if handled == Some(true) {
                return 0;
            }
        }
        WM_WORK_DONE => {
            with_app(|app| {
                let r = app.rx.as_ref().and_then(|rx| rx.try_recv().ok());
                if let Some(r) = r {
                    app.rx = None;
                    app.finished(r);
                }
            });
            return 0;
        }
        WM_DPICHANGED => {
            let dpi = (wp & 0xFFFF) as u32;
            let suggested = *(lp as *const RECT);
            if with_app(|app| app.dpi_changed(dpi, &suggested)).is_some() {
                return 0;
            }
        }
        WM_QUERYENDSESSION => {
            // Do not let a sign-out / shutdown (or Restart Manager) close
            // the window half-way through a removal.
            let working = with_app(|app| app.screen == Screen::Working).unwrap_or(false);
            return (!working) as LRESULT;
        }
        WM_CLOSE => {
            let working = with_app(|app| app.screen == Screen::Working).unwrap_or(false);
            if working {
                MessageBeep(MB_ICONWARNING);
            } else {
                DestroyWindow(hwnd);
            }
            return 0;
        }
        WM_DESTROY => {
            with_app(|app| {
                DeleteObject(app.font as _);
                DeleteObject(app.head_font as _);
                DeleteObject(app.mono_font as _);
            });
            PostQuitMessage(EXIT_CODE.with(|c| c.get()));
            return 0;
        }
        _ => {}
    }
    DefWindowProcW(hwnd, msg, wp, lp)
}

// ------------------------------------------------------------------ entry

/// Process entry point on Windows; returns the exit code.
pub fn main() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse_args(&args) {
        Mode::Help => {
            msgbox(std::ptr::null_mut(), USAGE, MB_ICONINFORMATION);
            0
        }
        Mode::BadArgs(a) => {
            msgbox(
                std::ptr::null_mut(),
                &format!("Unknown option: {a}\n\n{USAGE}"),
                MB_ICONWARNING,
            );
            2
        }
        Mode::Run => run(false),
        Mode::Preview => run(true),
    }
}

fn run(preview: bool) -> i32 {
    // SAFETY: plain struct.
    unsafe {
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS,
        };
        InitCommonControlsEx(&icc);
    }
    if !preview && !system::is_elevated() {
        msgbox(std::ptr::null_mut(), MSG_NOT_ELEVATED, MB_ICONERROR);
        return 2;
    }
    // SAFETY: Win32 window creation and message loop on this thread.
    unsafe {
        let hinst = GetModuleHandleW(std::ptr::null());
        let class = wide("KestrelUninstall");
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: hinst,
            hIcon: std::ptr::null_mut(),
            hCursor: LoadCursorW(std::ptr::null_mut(), IDC_ARROW),
            hbrBackground: std::ptr::null_mut(),
            lpszMenuName: std::ptr::null(),
            lpszClassName: class.as_ptr(),
            hIconSm: std::ptr::null_mut(),
        };
        RegisterClassExW(&wc);
        let title = wide(if preview {
            "Uninstall Kestrel EDR (preview)"
        } else {
            "Uninstall Kestrel EDR"
        });
        let style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        let hwnd = CreateWindowExW(
            0,
            class.as_ptr(),
            title.as_ptr(),
            style,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            400,
            300,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinst,
            std::ptr::null(),
        );
        if hwnd.is_null() {
            return 2;
        }
        let dpi = GetDpiForWindow(hwnd).max(96);
        // Icon from the embedded resource (group 1), when there is one.
        for (which, metric) in [(ICON_BIG, SM_CXICON), (ICON_SMALL, SM_CXSMICON)] {
            let px = GetSystemMetricsForDpi(metric, dpi);
            let ico = LoadImageW(hinst, 1 as _, IMAGE_ICON, px, px, LR_DEFAULTCOLOR);
            if !ico.is_null() {
                SendMessageW(hwnd, WM_SETICON, which as WPARAM, ico as LPARAM);
            }
        }

        let state_dir = system::state_dir();
        let purge_label = format!(
            "Also &delete quarantined files and logs ({})",
            state_dir
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| r"C:\ProgramData\Kestrel".into())
        );
        let stat = wide("STATIC");
        let edit = wide("EDIT");
        let button = wide("BUTTON");
        let st = WS_VISIBLE | SS_LEFT | SS_NOPREFIX | SS_EDITCONTROL;
        // Creation order is the tab order; each label precedes its control
        // so screen readers take the label as the control's name.
        let c = Ctl {
            preview: create(hwnd, stat.as_ptr(), PREVIEW_NOTE, st, 0, -1),
            intro: create(hwnd, stat.as_ptr(), INTRO, st, 0, -1),
            label: create(
                hwnd,
                stat.as_ptr(),
                "Uninstall &token:",
                WS_VISIBLE | SS_LEFT,
                0,
                -1,
            ),
            edit: create(
                hwnd,
                edit.as_ptr(),
                "",
                WS_VISIBLE | WS_TABSTOP | WS_GROUP | ES_PASSWORD as u32 | ES_AUTOHSCROLL as u32,
                WS_EX_CLIENTEDGE,
                ID_TOKEN,
            ),
            show: create(
                hwnd,
                button.as_ptr(),
                "&Show",
                WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32,
                0,
                ID_SHOW,
            ),
            purge: create(
                hwnd,
                button.as_ptr(),
                &purge_label,
                WS_VISIBLE | WS_TABSTOP | BS_AUTOCHECKBOX as u32 | BS_MULTILINE as u32,
                0,
                ID_PURGE,
            ),
            inline: create(hwnd, stat.as_ptr(), "", st, 0, -1),
            progress_label: create(hwnd, stat.as_ptr(), "Removing Kestrel...", st, 0, -1),
            progress: create(hwnd, PROGRESS_CLASSW, "", PBS_MARQUEE, 0, -1),
            head: create(hwnd, stat.as_ptr(), "", st, 0, -1),
            body: create(hwnd, stat.as_ptr(), "", st, 0, -1),
            logview: create(
                hwnd,
                edit.as_ptr(),
                "",
                WS_TABSTOP
                    | WS_VSCROLL
                    | WS_HSCROLL
                    | ES_MULTILINE as u32
                    | ES_READONLY as u32
                    | ES_AUTOVSCROLL as u32
                    | ES_AUTOHSCROLL as u32,
                WS_EX_CLIENTEDGE,
                -1,
            ),
            primary: create(
                hwnd,
                button.as_ptr(),
                "Uninstall",
                WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_DEFPUSHBUTTON as u32,
                0,
                IDOK,
            ),
            secondary: create(
                hwnd,
                button.as_ptr(),
                "Cancel",
                WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                IDCANCEL,
            ),
            log: create(
                hwnd,
                button.as_ptr(),
                "Show &log",
                WS_TABSTOP | BS_PUSHBUTTON as u32,
                0,
                ID_LOG,
            ),
        };
        SendMessageW(c.edit, EM_SETPASSWORDCHAR, PASSWORD_CHAR, 0);
        SetWindowSubclass(c.logview, Some(logview_proc), 1, 0);
        // Tokens are short; this caps what a stray paste can hold.
        SendMessageW(c.edit, EM_LIMITTEXT, 1024, 0);
        INLINE_HWND.with(|h| h.set(c.inline as isize));
        let mut app = App {
            hwnd,
            preview,
            dpi,
            font: make_font(dpi, 9, FW_NORMAL as i32),
            head_font: make_font(dpi, 12, FW_SEMIBOLD as i32),
            c,
            screen: Screen::Form,
            outcome: None,
            log: None,
            state_dir,
            positioned: false,
            work: None,
            rx: None,
            mono_font: make_mono_font(dpi),
            log_shown: false,
        };
        app.apply_fonts();
        app.layout(None);
        let edit_h = app.c.edit;
        APP.with(|a| *a.borrow_mut() = Some(app));
        ShowWindow(hwnd, SW_SHOW);
        SetForegroundWindow(hwnd);
        SetFocus(edit_h);

        let mut msg: MSG = std::mem::zeroed();
        loop {
            let r = GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
            if r == 0 || r == -1 {
                break;
            }
            if IsDialogMessageW(hwnd, &msg) == 0 {
                TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }
        APP.with(|a| a.borrow_mut().take());
        if r_is_quit(&msg) {
            msg.wParam as i32
        } else {
            EXIT_CODE.with(|c| c.get())
        }
    }
}

fn r_is_quit(m: &MSG) -> bool {
    m.message == WM_QUIT
}
