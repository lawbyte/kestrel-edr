//! Follow the input desktop (Default ↔ Winlogon for UAC / lock screen).
//!
//! `OpenInputDesktop` + `GetUserObjectInformationW(UOI_NAME)`; when the name
//! differs from this thread's desktop, `SetThreadDesktop` (the calling thread
//! must own no windows or hooks — only the capture and input threads use
//! this, never the banner thread).

use super::super::util::from_wide;
use windows_sys::Win32::Foundation::GENERIC_ALL;
use windows_sys::Win32::System::StationsAndDesktops::{
    CloseDesktop, GetThreadDesktop, GetUserObjectInformationW, OpenInputDesktop, SetThreadDesktop,
    HDESK, UOI_NAME,
};
use windows_sys::Win32::System::Threading::GetCurrentThreadId;

fn desktop_name(h: HDESK) -> Option<String> {
    let mut buf = [0u16; 256];
    let mut need = 0u32;
    let ok = unsafe {
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            buf.as_mut_ptr() as *mut std::ffi::c_void,
            (buf.len() * 2) as u32,
            &mut need,
        )
    };
    (ok != 0).then(|| from_wide(&buf))
}

pub struct DesktopFollower {
    /// Desktop handle we opened and set on this thread (closed on switch).
    owned: Option<HDESK>,
    name: String,
}

impl DesktopFollower {
    pub fn new() -> DesktopFollower {
        let cur = unsafe { GetThreadDesktop(GetCurrentThreadId()) };
        let name = if cur.is_null() {
            String::new()
        } else {
            desktop_name(cur).unwrap_or_default()
        };
        DesktopFollower { owned: None, name }
    }

    /// Name of this thread's desktop after following the input desktop.
    /// `None` when the input desktop cannot be opened right now (switch in
    /// progress) or the switch failed.
    pub fn sync(&mut self) -> Option<String> {
        let h = unsafe { OpenInputDesktop(0, 0, GENERIC_ALL) };
        if h.is_null() {
            return None;
        }
        let Some(name) = desktop_name(h) else {
            unsafe { CloseDesktop(h) };
            return None;
        };
        if name.eq_ignore_ascii_case(&self.name) {
            unsafe { CloseDesktop(h) };
            return Some(name);
        }
        if unsafe { SetThreadDesktop(h) } == 0 {
            tracing::debug!(
                "SetThreadDesktop({name}) failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe { CloseDesktop(h) };
            return None;
        }
        if let Some(old) = self.owned.replace(h) {
            unsafe { CloseDesktop(old) };
        }
        self.name = name.clone();
        Some(name)
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

/// The user's normal desktop? (Anything else — `Winlogon`, `Screen-saver`,
/// a third-party secure desktop — is reported as `secure_desktop`.)
pub fn is_default_desktop(name: &str) -> bool {
    name.eq_ignore_ascii_case("Default")
}
