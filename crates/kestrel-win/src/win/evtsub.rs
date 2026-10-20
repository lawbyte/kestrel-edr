//! Event-log subscriptions: Sysmon (EID 8/10, optional) and Security
//! 5446-5450 (WFP policy changes → tamper), plus channel configuration
//! helpers used by hardening (Crypto-DPAPI/Debug).

use super::etw::{Raw, Sink};
use super::util::*;
use crate::consts;
use crate::evtxml::{parse_event_xml, sysmon_cross, wfp_tamper};
use kestrel_common::TamperKind;
use std::ffi::c_void;
use std::sync::{Arc, RwLock};
use windows_sys::Win32::System::EventLog::{
    EvtChannelConfigEnabled, EvtClose, EvtGetChannelConfigProperty, EvtOpenChannelConfig,
    EvtRender, EvtRenderEventXml, EvtSaveChannelConfig, EvtSetChannelConfigProperty, EvtSubscribe,
    EvtSubscribeActionDeliver, EvtSubscribeToFutureEvents, EvtVarTypeBoolean, EVT_HANDLE,
    EVT_VARIANT,
};

enum Kind {
    Sysmon,
    Security {
        our_keys: Arc<RwLock<Vec<String>>>,
    },
    /// TaskScheduler / System 7045 / WMI-Activity fallback (ETW is primary).
    Persist,
}

struct Ctx {
    sink: Sink,
    kind: Kind,
}

/// A live subscription; dropping it closes the handle and frees the context.
pub struct Subscription {
    handle: EVT_HANDLE,
    ctx: *mut Ctx,
}

unsafe impl Send for Subscription {}
unsafe impl Sync for Subscription {}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe {
            EvtClose(self.handle);
            // EvtClose waits for in-flight callbacks, so the context is free to drop.
            drop(Box::from_raw(self.ctx));
        }
    }
}

fn render_xml(event: EVT_HANDLE) -> Option<String> {
    let mut used = 0u32;
    let mut count = 0u32;
    unsafe {
        EvtRender(
            0,
            event,
            EvtRenderEventXml,
            0,
            std::ptr::null_mut(),
            &mut used,
            &mut count,
        );
        if used == 0 {
            return None;
        }
        let mut buf = vec![0u16; (used as usize).div_ceil(2) + 1];
        if EvtRender(
            0,
            event,
            EvtRenderEventXml,
            (buf.len() * 2) as u32,
            buf.as_mut_ptr() as *mut c_void,
            &mut used,
            &mut count,
        ) == 0
        {
            return None;
        }
        Some(from_wide(&buf))
    }
}

unsafe extern "system" fn callback(action: i32, ctx: *const c_void, event: EVT_HANDLE) -> u32 {
    if action != EvtSubscribeActionDeliver || ctx.is_null() {
        return 0;
    }
    let ctx = &*(ctx as *const Ctx);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let Some(xml) = render_xml(event) else { return };
        if matches!(ctx.kind, Kind::Persist) {
            if let Some(mut p) = crate::persist::parse_persist_xml(&xml) {
                let task = super::persist::enrich(&mut p.record);
                ctx.sink.send(Raw::Persist {
                    ts: p.ts.unwrap_or_else(kestrel_common::now_ms),
                    logger_pid: p.logger_pid.unwrap_or(0),
                    record: p.record,
                    task,
                });
            }
            return;
        }
        let Some(ev) = parse_event_xml(&xml) else {
            return;
        };
        match &ctx.kind {
            Kind::Sysmon => {
                if let Some(c) = sysmon_cross(&ev) {
                    ctx.sink.send(Raw::Sysmon(c));
                }
            }
            Kind::Persist => {}
            Kind::Security { our_keys } => {
                let keys = our_keys.read().map(|k| k.clone()).unwrap_or_default();
                if let Some(detail) = wfp_tamper(
                    &ev,
                    ctx.sink.self_pid,
                    &keys,
                    consts::wfp::PROVIDER_KEY_STR,
                    consts::wfp::SUBLAYER_KEY_STR,
                ) {
                    ctx.sink.send(Raw::Tamper {
                        kind: TamperKind::WfpFilterChange,
                        detail,
                    });
                }
            }
        }
    }));
    0
}

fn subscribe(channel: &str, query: &str, ctx: Ctx) -> Option<Subscription> {
    let c = wide(channel);
    let q = wide(query);
    let ctx = Box::into_raw(Box::new(ctx));
    let h = unsafe {
        EvtSubscribe(
            0,
            std::ptr::null_mut(),
            c.as_ptr(),
            q.as_ptr(),
            0,
            ctx as *const c_void,
            Some(callback),
            EvtSubscribeToFutureEvents,
        )
    };
    if h == 0 {
        unsafe { drop(Box::from_raw(ctx)) };
        return None;
    }
    Some(Subscription { handle: h, ctx })
}

/// Sysmon ProcessAccess / CreateRemoteThread, when Sysmon is installed.
pub fn subscribe_sysmon(sink: Sink) -> Option<Subscription> {
    subscribe(
        consts::channel::SYSMON,
        "*[System[(EventID=8 or EventID=10)]]",
        Ctx {
            sink,
            kind: Kind::Sysmon,
        },
    )
}

/// Persistence fallbacks: TaskScheduler/Operational 106/140/141 (channel is
/// disabled by default — the `task_scheduler_log` hardening control enables
/// it), System 7045 (Service Control Manager), WMI-Activity/Operational 5861.
/// Returns the subscriptions that could be opened.
pub fn subscribe_persistence(sink: Sink) -> Vec<Subscription> {
    let mut v = Vec::new();
    for (channel, query) in [
        (
            consts::channel::TASK_SCHEDULER,
            "*[System[(EventID=106 or EventID=140 or EventID=141)]]",
        ),
        (
            consts::channel::SYSTEM,
            "*[System[Provider[@Name='Service Control Manager'] and EventID=7045]]",
        ),
        (consts::channel::WMI_ACTIVITY, "*[System[EventID=5861]]"),
    ] {
        match subscribe(
            channel,
            query,
            Ctx {
                sink: sink.clone(),
                kind: Kind::Persist,
            },
        ) {
            Some(s) => v.push(s),
            None => tracing::info!("event-log subscription to {channel} unavailable"),
        }
    }
    v
}

/// Security 5446-5450 (requires WFP policy-change auditing;
/// enabled best-effort by [`enable_wfp_policy_audit`]).
pub fn subscribe_wfp_audit(sink: Sink, our_keys: Arc<RwLock<Vec<String>>>) -> Option<Subscription> {
    subscribe(
        consts::channel::SECURITY,
        "*[System[(EventID>=5446 and EventID<=5450)]]",
        Ctx {
            sink,
            kind: Kind::Security { our_keys },
        },
    )
}

/// Turn on success auditing so 5446-5450 are logged: "Filtering Platform
/// Policy Change" ({0CCE9233-69AE-11D9-BED3-505054503030}, per the WFP
/// "Auditing and Logging" docs) and "Other Policy Change Events"
/// ({0CCE9234-…}, which the event-5447 article lists for persistent filter
/// changes). GUID form avoids localisation problems.
pub fn enable_wfp_policy_audit() -> bool {
    let exe = format!(r"{}\System32\auditpol.exe", system_root());
    let mut ok = true;
    for sub in [
        "{0CCE9233-69AE-11D9-BED3-505054503030}",
        "{0CCE9234-69AE-11D9-BED3-505054503030}",
    ] {
        let arg = format!("/subcategory:{sub}");
        ok &= run_cmd(
            &exe,
            &["/set", &arg, "/success:enable"],
            std::time::Duration::from_secs(15),
        )
        .map(|o| o.code == 0)
        .unwrap_or(false);
    }
    ok
}

/// Read a channel's Enabled flag.
pub fn channel_enabled(channel: &str) -> Option<bool> {
    let w = wide(channel);
    unsafe {
        let h = EvtOpenChannelConfig(0, w.as_ptr(), 0);
        if h == 0 {
            return None;
        }
        let mut v: EVT_VARIANT = std::mem::zeroed();
        let mut used = 0u32;
        let ok = EvtGetChannelConfigProperty(
            h,
            EvtChannelConfigEnabled,
            0,
            std::mem::size_of::<EVT_VARIANT>() as u32,
            &mut v,
            &mut used,
        );
        EvtClose(h);
        if ok == 0 {
            return None;
        }
        Some(v.Anonymous.BooleanVal != 0)
    }
}

/// Enable/disable a channel (e.g. Microsoft-Windows-Crypto-DPAPI/Debug).
pub fn set_channel_enabled(channel: &str, enabled: bool) -> std::io::Result<()> {
    let w = wide(channel);
    unsafe {
        let h = EvtOpenChannelConfig(0, w.as_ptr(), 0);
        if h == 0 {
            return Err(last_err());
        }
        let mut v: EVT_VARIANT = std::mem::zeroed();
        v.Anonymous.BooleanVal = enabled as i32;
        v.Count = 0;
        v.Type = EvtVarTypeBoolean as u32;
        let r = if EvtSetChannelConfigProperty(h, EvtChannelConfigEnabled, 0, &v) == 0
            || EvtSaveChannelConfig(h, 0) == 0
        {
            Err(last_err())
        } else {
            Ok(())
        };
        EvtClose(h);
        r
    }
}
