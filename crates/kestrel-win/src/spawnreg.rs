//! Processes the agent itself started (security review v1.1 V-H1).
//!
//! Every child the agent spawns (hardening `sc.exe` / `auditpol.exe` /
//! PowerShell through `run_cmd`, `kestrel-scan.exe`, `msiexec.exe` for an
//! update) is recorded here by **pid + kernel creation time** (FILETIME,
//! taken from the child's own process handle, so a recycled pid can never be
//! recorded by mistake). The sensor marks a `ProcessStart` as
//! `agent_spawned` only when all of these hold ([`is_agent_spawned`]):
//!
//! 1. (pid, creation time) is in this registry;
//! 2. the ETW `ParentProcessID` is the agent's own pid;
//! 3. the EVENT_HEADER `ProcessId` of the Kernel-Process start event (the
//!    process that actually called `NtCreateUserProcess`) equals that parent.
//!    `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` (PPID spoofing) changes the
//!    reported parent but not the creator in the header (the technique
//!    documented by F-Secure Countercept, "Detecting Parent PID Spoofing",
//!    2018, using Microsoft-Windows-Kernel-Process event 1).
//!
//! Nothing is inherited: grandchildren are never `agent_spawned`.
//!
//! The registry is process-wide (a `static`), bounded, and entries expire
//! after [`TTL_MS`] (the start event reaches the translator within seconds).

use std::collections::VecDeque;
use std::sync::Mutex;

/// Entries kept at most.
pub const MAX_ENTRIES: usize = 512;
/// How long a recorded child stays recognisable (ms since it was recorded).
pub const TTL_MS: i64 = 10 * 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    pid: u32,
    create_ft: u64,
    recorded_ms: i64,
}

/// Bounded (pid, creation FILETIME) set.
#[derive(Debug, Default)]
pub struct SpawnRegistry {
    entries: VecDeque<Entry>,
}

impl SpawnRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, pid: u32, create_ft: u64, now_ms: i64) {
        if pid == 0 || create_ft == 0 {
            return;
        }
        self.expire(now_ms);
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.pop_front();
        }
        self.entries.push_back(Entry {
            pid,
            create_ft,
            recorded_ms: now_ms,
        });
    }

    pub fn contains(&self, pid: u32, create_ft: u64, now_ms: i64) -> bool {
        create_ft != 0
            && self.entries.iter().any(|e| {
                e.pid == pid && e.create_ft == create_ft && now_ms - e.recorded_ms <= TTL_MS
            })
    }

    pub fn expire(&mut self, now_ms: i64) {
        while self
            .entries
            .front()
            .is_some_and(|e| now_ms - e.recorded_ms > TTL_MS)
        {
            self.entries.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

static GLOBAL: Mutex<SpawnRegistry> = Mutex::new(SpawnRegistry {
    entries: VecDeque::new(),
});

/// Record a child of this process (pid + kernel creation FILETIME).
pub fn record(pid: u32, create_ft: u64) {
    if let Ok(mut r) = GLOBAL.lock() {
        r.record(pid, create_ft, kestrel_common::now_ms());
    }
}

/// Is (pid, creation FILETIME) a child this process recorded?
pub fn is_recorded(pid: u32, create_ft: u64) -> bool {
    GLOBAL
        .lock()
        .map(|r| r.contains(pid, create_ft, kestrel_common::now_ms()))
        .unwrap_or(false)
}

/// How long the sensor holds the `ProcessStart` of a direct agent child that
/// the agent has not recorded yet (soak 2026-10-21: the Kernel-Process
/// start event can be translated before the spawning thread returns from
/// `CreateProcess` and records the child; deciding `agent_spawned` then
/// raised a Sigma alert on the agent's own `powershell -EncodedCommand`).
pub const AGENT_CHILD_WAIT_MS: i64 = 5_000;

/// Keep holding an unrecorded agent-child start? (pure; `until` = hold
/// deadline). Once recorded, or past the deadline, the start goes out and
/// [`is_agent_spawned`] decides.
pub fn registry_wait_pending(recorded: bool, now_ms: i64, until: i64) -> bool {
    !recorded && now_ms < until
}

/// The full V-H1 check (pure apart from the registry lookup `recorded`):
/// recorded child, ETW parent is the agent, and the event's creator (header
/// pid) is that same parent (no PPID spoofing).
pub fn agent_spawned_check(
    recorded: bool,
    etw_parent_pid: u32,
    creator_pid: u32,
    agent_pid: u32,
) -> bool {
    recorded && agent_pid != 0 && etw_parent_pid == agent_pid && creator_pid == etw_parent_pid
}

/// [`agent_spawned_check`] against the process-wide registry.
pub fn is_agent_spawned(
    pid: u32,
    create_ft: u64,
    etw_parent_pid: u32,
    creator_pid: u32,
    agent_pid: u32,
) -> bool {
    agent_spawned_check(
        is_recorded(pid, create_ft),
        etw_parent_pid,
        creator_pid,
        agent_pid,
    )
}

/// Record a freshly spawned `std::process::Child` (creation time read from
/// the child's own handle: no pid-reuse race). Returns false when the
/// creation time could not be read (the child is then simply not trusted).
#[cfg(windows)]
pub fn record_child(child: &std::process::Child) -> bool {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: the live process handle owned by `child`.
    unsafe { record_handle(child.id(), child.as_raw_handle() as _) }
}

/// Record a child started with a raw process handle (`CreateProcessAsUserW`,
/// e.g. the remote-desktop helper; re-review N8). `h` must be the live
/// handle of process `pid` returned by the create call.
///
/// # Safety
/// `h` must be a valid, open process handle (`PROCESS_QUERY_LIMITED_INFORMATION`).
#[cfg(windows)]
pub unsafe fn record_handle(pid: u32, h: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;
    let z = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut c, mut e, mut k, mut u) = (z, z, z, z);
    // SAFETY: `h` is a live process handle (caller contract).
    let ok = unsafe { GetProcessTimes(h, &mut c, &mut e, &mut k, &mut u) };
    if ok == 0 {
        return false;
    }
    let ft = ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64;
    record(pid, ft);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_matches_pid_and_create_time_only() {
        let mut r = SpawnRegistry::new();
        r.record(100, 0xAAAA, 1_000);
        assert!(r.contains(100, 0xAAAA, 2_000));
        // Recycled pid (other creation time) is not the agent's child.
        assert!(!r.contains(100, 0xBBBB, 2_000));
        assert!(!r.contains(101, 0xAAAA, 2_000));
        // Unknown creation time never matches.
        assert!(!r.contains(100, 0, 2_000));
        // Expiry.
        assert!(!r.contains(100, 0xAAAA, 1_000 + TTL_MS + 1));
        r.expire(1_000 + TTL_MS + 1);
        assert!(r.is_empty());
        // pid 0 / ft 0 are never recorded.
        r.record(0, 1, 5);
        r.record(5, 0, 5);
        assert!(r.is_empty());
    }

    #[test]
    fn registry_is_bounded() {
        let mut r = SpawnRegistry::new();
        for i in 0..(MAX_ENTRIES as u32 + 10) {
            r.record(i + 1, 7, 1);
        }
        assert_eq!(r.len(), MAX_ENTRIES);
        assert!(!r.contains(1, 7, 1), "oldest evicted");
        assert!(r.contains(MAX_ENTRIES as u32 + 10, 7, 1));
    }

    #[test]
    fn ppid_spoof_and_foreign_parent_are_refused() {
        let agent = 4242;
        // Genuine: recorded, ETW parent = agent, header creator = agent.
        assert!(agent_spawned_check(true, agent, agent, agent));
        // Not recorded (e.g. started by a user through the agent CLI, or a
        // grandchild).
        assert!(!agent_spawned_check(false, agent, agent, agent));
        // PPID spoofing: the reported parent is the agent, the creator is not.
        assert!(!agent_spawned_check(true, agent, 777, agent));
        // Parent is someone else.
        assert!(!agent_spawned_check(true, 777, 777, agent));
        // Agent pid unknown.
        assert!(!agent_spawned_check(true, 0, 0, 0));
    }

    /// Service start-up ordering (soak 2026-10-21): the start event of the
    /// agent's hardening PowerShell is translated *before* the spawning
    /// thread records the child. The start is held (no decision) until the
    /// record lands, then `agent_spawned` is true.
    #[test]
    fn start_event_before_record_is_held_until_recorded() {
        let (agent, child, ft) = (4242, 5150, 0xABCD_EF01_u64);
        let t0 = 1_000_000;
        let until = t0 + AGENT_CHILD_WAIT_MS;
        // ETW start arrives first: not recorded yet → keep holding, even
        // after the 1 s command-line wait would have released it.
        let mut r = SpawnRegistry::new();
        assert!(registry_wait_pending(r.contains(child, ft, t0), t0, until));
        assert!(registry_wait_pending(
            r.contains(child, ft, t0 + 1_500),
            t0 + 1_500,
            until
        ));
        // The spawning thread records the child; the start is released and
        // judged the agent's own.
        r.record(child, ft, t0 + 1_600);
        let rec = r.contains(child, ft, t0 + 1_700);
        assert!(!registry_wait_pending(rec, t0 + 1_700, until));
        assert!(agent_spawned_check(rec, agent, agent, agent));
        // Never recorded (not ours): released at the deadline, not trusted.
        let r2 = SpawnRegistry::new();
        assert!(!registry_wait_pending(
            r2.contains(child, ft, until),
            until,
            until
        ));
        assert!(!agent_spawned_check(false, agent, agent, agent));
    }

    #[test]
    fn global_registry_round_trip() {
        record(31337, 0x1234_5678);
        assert!(is_recorded(31337, 0x1234_5678));
        assert!(is_agent_spawned(31337, 0x1234_5678, 9, 9, 9));
        assert!(!is_agent_spawned(31337, 0x1234_5678, 9, 8, 9));
        assert!(!is_recorded(31337, 0x1234_5679));
    }
}
