//! Resource priority of non-urgent agent work (owner request 2026-10-25:
//! "light on endpoints"). Detection and response threads keep normal
//! priority; only work that may run late (outbox encoding and writes,
//! background signature / revocation checks) asks Windows to yield.
//!
//! APIs (Microsoft Learn, processthreadsapi.h):
//! * `SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)`:
//!   lowers the CPU, I/O and memory scheduling priority of the calling
//!   thread ("will never be starved"); current thread only.
//! * `SetThreadInformation(.., ThreadPowerThrottling,
//!   THREAD_POWER_THROTTLING_STATE { Version: 1, ControlMask:
//!   EXECUTION_SPEED, StateMask: EXECUTION_SPEED })`: EcoQoS (efficiency
//!   cores / lower frequency on Windows 11; LowQoS before).
//! * `SetThreadPriority(.., THREAD_PRIORITY_BELOW_NORMAL)`: CPU only.

use windows_sys::Win32::System::Threading::{
    GetCurrentThread, SetThreadInformation, SetThreadPriority, ThreadPowerThrottling,
    THREAD_MODE_BACKGROUND_BEGIN, THREAD_POWER_THROTTLING_CURRENT_VERSION,
    THREAD_POWER_THROTTLING_EXECUTION_SPEED, THREAD_POWER_THROTTLING_STATE,
    THREAD_PRIORITY_BELOW_NORMAL,
};

/// How much the calling thread should yield.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Background {
    /// Below-normal CPU priority + EcoQoS; normal I/O (work that should
    /// still finish within seconds, e.g. hashing a new binary).
    Light,
    /// Background mode (CPU, I/O and memory priority) + EcoQoS: work that
    /// may wait (outbox writes, revocation checks).
    Full,
}

/// Lower the calling thread's priority. Best effort: failures are logged at
/// debug level and ignored. Returns true if every call succeeded.
pub fn current_thread(level: Background) -> bool {
    // SAFETY: pseudo-handle of the calling thread; the state struct lives
    // for the duration of the call and its size is passed.
    unsafe {
        let t = GetCurrentThread();
        let prio_ok = match level {
            Background::Light => SetThreadPriority(t, THREAD_PRIORITY_BELOW_NORMAL) != 0,
            Background::Full => SetThreadPriority(t, THREAD_MODE_BACKGROUND_BEGIN) != 0,
        };
        let state = THREAD_POWER_THROTTLING_STATE {
            Version: THREAD_POWER_THROTTLING_CURRENT_VERSION,
            ControlMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
            StateMask: THREAD_POWER_THROTTLING_EXECUTION_SPEED,
        };
        let eco_ok = SetThreadInformation(
            t,
            ThreadPowerThrottling,
            &state as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<THREAD_POWER_THROTTLING_STATE>() as u32,
        ) != 0;
        if !(prio_ok && eco_ok) {
            tracing::debug!(
                ?level,
                prio_ok,
                eco_ok,
                "lowering thread priority partly failed"
            );
        }
        prio_ok && eco_ok
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs on a throwaway thread: only that thread is lowered.
    #[test]
    fn lowers_a_throwaway_thread() {
        assert!(std::thread::spawn(|| current_thread(Background::Light))
            .join()
            .unwrap());
        assert!(std::thread::spawn(|| current_thread(Background::Full))
            .join()
            .unwrap());
    }
}
