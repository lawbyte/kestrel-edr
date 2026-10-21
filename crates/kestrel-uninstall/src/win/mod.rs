//! Windows implementation: the dialog ([`gui`]), the Windows Installer call
//! and system queries ([`system`]) and the link-safe purge ([`purge`]).

pub mod gui;
pub mod purge;
pub mod system;

/// NUL-terminated UTF-16.
pub(crate) fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// UTF-16 up to the first NUL.
pub(crate) fn from_wide(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Owned kernel handle, closed on drop.
pub(crate) struct Handle(pub windows_sys::Win32::Foundation::HANDLE);

// SAFETY: a kernel handle is a process-wide value with no thread affinity.
unsafe impl Send for Handle {}

impl Handle {
    pub(crate) fn new(h: windows_sys::Win32::Foundation::HANDLE) -> Option<Handle> {
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(Handle(h))
    }
    pub(crate) fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: we own the handle.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

pub(crate) fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}
