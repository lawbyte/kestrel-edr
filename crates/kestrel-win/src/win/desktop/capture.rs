//! Screen capture thread of the helper (GDI).
//!
//! Per frame: follow the input desktop → virtual-screen geometry
//! (`GetSystemMetrics(SM_XVIRTUALSCREEN …)`, physical pixels because the
//! helper is per-monitor DPI aware v2) → `GetDC(NULL)` → `BitBlt(SRCCOPY |
//! CAPTUREBLT)` into a top-down 32-bit DIB section (`CreateDIBSection`) →
//! `GdiFlush` → downscale → change detection against the last frame the
//! agent accepted → bounded JPEG → `Frame` → wait for the agent's ack.
//! The mouse pointer is not drawn into the image.

use super::deskfollow::{is_default_desktop, DesktopFollower};
use crate::desktop_image::{
    downscale_bgra, encode_bounded, frame_hash, frame_interval, next_delay, scaled_dims,
    JPEG_SOFT_MAX,
};
use crate::desktop_keymap::VirtualScreen;
use crate::desktop_proto::{HelperMsg, HelperSettings};
use kestrel_common::remote::DesktopInfo;
use std::borrow::Cow;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::Sender;
use windows_sys::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleDC, CreateDIBSection, DeleteDC, DeleteObject, GdiFlush, GetDC,
    ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB, CAPTUREBLT, DIB_RGB_COLORS,
    HBITMAP, HDC, HGDIOBJ, SRCCOPY,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    GetSystemMetrics, SM_CMONITORS, SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN,
    SM_YVIRTUALSCREEN,
};

/// Commands for the capture thread.
pub enum CapCmd {
    Settings(HelperSettings),
    Ack(bool),
    Stop,
}

pub fn virtual_screen() -> VirtualScreen {
    unsafe {
        VirtualScreen {
            x: GetSystemMetrics(SM_XVIRTUALSCREEN),
            y: GetSystemMetrics(SM_YVIRTUALSCREEN),
            w: GetSystemMetrics(SM_CXVIRTUALSCREEN).max(1),
            h: GetSystemMetrics(SM_CYVIRTUALSCREEN).max(1),
        }
    }
}

/// Memory DC + DIB section of the virtual-screen size.
struct Capturer {
    dc: HDC,
    bmp: HBITMAP,
    old: HGDIOBJ,
    bits: *mut u8,
    w: i32,
    h: i32,
}

impl Capturer {
    fn new(w: i32, h: i32) -> Option<Capturer> {
        unsafe {
            let dc = CreateCompatibleDC(std::ptr::null_mut());
            if dc.is_null() {
                return None;
            }
            let mut bmi: BITMAPINFO = std::mem::zeroed();
            bmi.bmiHeader = BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            };
            let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
            let bmp =
                CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
            if bmp.is_null() || bits.is_null() {
                if !bmp.is_null() {
                    DeleteObject(bmp);
                }
                DeleteDC(dc);
                return None;
            }
            let old = SelectObject(dc, bmp);
            Some(Capturer {
                dc,
                bmp,
                old,
                bits: bits as *mut u8,
                w,
                h,
            })
        }
    }

    /// Copy the virtual screen of this thread's desktop into the DIB.
    fn grab(&mut self, vs: &VirtualScreen) -> bool {
        unsafe {
            let sdc = GetDC(std::ptr::null_mut());
            if sdc.is_null() {
                return false;
            }
            let ok = BitBlt(
                self.dc,
                0,
                0,
                self.w,
                self.h,
                sdc,
                vs.x,
                vs.y,
                SRCCOPY | CAPTUREBLT,
            );
            ReleaseDC(std::ptr::null_mut(), sdc);
            GdiFlush();
            ok != 0
        }
    }

    fn pixels(&self) -> &[u8] {
        // SAFETY: the DIB section is w*h*4 bytes (32 bpp rows are always
        // DWORD aligned) and lives as long as `self`.
        unsafe { std::slice::from_raw_parts(self.bits, self.w as usize * self.h as usize * 4) }
    }
}

impl Drop for Capturer {
    fn drop(&mut self) {
        unsafe {
            SelectObject(self.dc, self.old);
            DeleteObject(self.bmp);
            DeleteDC(self.dc);
        }
    }
}

enum Wait {
    Continue,
    Stop,
}

/// Apply commands that arrive while waiting `dur`. `ack` receives a frame ack.
fn wait_for(
    rx: &Receiver<CapCmd>,
    dur: Duration,
    settings: &mut HelperSettings,
    force: &mut bool,
    mut ack: Option<&mut Option<bool>>,
) -> Wait {
    let deadline = Instant::now() + dur;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(CapCmd::Settings(s)) => {
                *settings = s.clamped();
                *force = true;
            }
            Ok(CapCmd::Ack(a)) => {
                if let Some(slot) = ack.as_deref_mut() {
                    *slot = Some(a);
                    return Wait::Continue;
                }
            }
            Ok(CapCmd::Stop) | Err(RecvTimeoutError::Disconnected) => return Wait::Stop,
            Err(RecvTimeoutError::Timeout) => return Wait::Continue,
        }
    }
}

/// Capture loop; returns when told to stop or the pipe writer is gone.
pub fn run(
    rx: Receiver<CapCmd>,
    out: Sender<HelperMsg>,
    mut settings: HelperSettings,
    session_id: u32,
) {
    let mut follower = DesktopFollower::new();
    let mut cap: Option<Capturer> = None;
    let mut last_info: Option<DesktopInfo> = None;
    let mut last_accepted: Option<u64> = None;
    let mut force = true;
    let mut failures = 0u32;
    loop {
        let started = Instant::now();
        let interval = frame_interval(settings.max_fps);
        // Commands that arrived since the last wait.
        loop {
            match rx.try_recv() {
                Ok(CapCmd::Settings(s)) => {
                    settings = s.clamped();
                    force = true;
                }
                Ok(CapCmd::Ack(_)) => {}
                Ok(CapCmd::Stop) | Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
            }
        }
        let desk = follower
            .sync()
            .unwrap_or_else(|| follower.name().to_string());
        let vs = virtual_screen();
        let info = DesktopInfo {
            width: vs.w as u32,
            height: vs.h as u32,
            monitors: unsafe { GetSystemMetrics(SM_CMONITORS) }.max(1) as u32,
            session_id: Some(session_id),
            secure_desktop: !is_default_desktop(&desk),
            view_only: settings.view_only,
        };
        if last_info.as_ref() != Some(&info) {
            if out.blocking_send(HelperMsg::Info(info.clone())).is_err() {
                return;
            }
            last_info = Some(info);
            force = true;
        }
        if cap.as_ref().map(|c| (c.w, c.h)) != Some((vs.w, vs.h)) {
            drop(cap.take()); // free the old DIB before allocating the new one
            cap = Capturer::new(vs.w, vs.h);
        }
        let grabbed = match cap.as_mut() {
            Some(c) => c.grab(&vs),
            None => false,
        };
        if !grabbed {
            failures += 1;
            if failures == 20 {
                let _ = out.blocking_send(HelperMsg::Error(
                    "screen capture is failing (desktop switch or access denied)".into(),
                ));
            }
            if let Wait::Stop = wait_for(
                &rx,
                Duration::from_millis(200),
                &mut settings,
                &mut force,
                None,
            ) {
                return;
            }
            continue;
        }
        failures = 0;
        let Some(c) = cap.as_ref() else { continue };
        let (w, h) = (c.w as u32, c.h as u32);
        let (dw, dh) = scaled_dims(w, h, settings.scale_pct);
        let img: Cow<[u8]> = if (dw, dh) == (w, h) {
            Cow::Borrowed(c.pixels())
        } else {
            Cow::Owned(downscale_bgra(c.pixels(), w as usize * 4, w, h, dw, dh))
        };
        let hash = frame_hash(&img, dw, dh);
        let mut accepted = None;
        if force || last_accepted != Some(hash) {
            match encode_bounded(&img, dw, dh, settings.quality, JPEG_SOFT_MAX) {
                Ok((jpeg, fw, fh)) => {
                    drop(img);
                    let ts = kestrel_common::now_ms();
                    if out
                        .blocking_send(HelperMsg::Frame {
                            width: fw,
                            height: fh,
                            ts,
                            jpeg,
                        })
                        .is_err()
                    {
                        return;
                    }
                    if let Wait::Stop = wait_for(
                        &rx,
                        Duration::from_secs(5),
                        &mut settings,
                        &mut force,
                        Some(&mut accepted),
                    ) {
                        return;
                    }
                    if accepted == Some(true) {
                        last_accepted = Some(hash);
                        force = false;
                    }
                }
                Err(e) => {
                    let _ = out.blocking_send(HelperMsg::Log(format!("frame skipped: {e}")));
                }
            }
        }
        let mut delay = next_delay(interval, started.elapsed());
        if accepted == Some(false) {
            // The agent had no room: try again after a full interval.
            delay = delay.max(interval);
        }
        if let Wait::Stop = wait_for(&rx, delay, &mut settings, &mut force, None) {
            return;
        }
    }
}
