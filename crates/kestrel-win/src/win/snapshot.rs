//! Startup process snapshot (Toolhelp32 + per-process queries).

use super::enrich::Enricher;
use super::util::*;
use crate::etwparse::filetime_to_ms;
use crate::proctrack::ProcTracker;
use kestrel_common::{PathClass, ProcessGuid, ProcessInfo};
use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::PROCESS_QUERY_LIMITED_INFORMATION;

/// Enrichment (hash + signature) budget for the whole snapshot.
const ENRICH_BUDGET: Duration = Duration::from_secs(20);

#[derive(Debug, Clone)]
pub struct Row {
    pub pid: u32,
    pub ppid: u32,
    pub exe: String,
}

pub fn toolhelp_rows() -> Vec<Row> {
    let mut out = Vec::new();
    unsafe {
        let Some(snap) = Handle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) else {
            return out;
        };
        let mut pe: PROCESSENTRY32W = std::mem::zeroed();
        pe.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap.raw(), &mut pe) == 0 {
            return out;
        }
        loop {
            out.push(Row {
                pid: pe.th32ProcessID,
                ppid: pe.th32ParentProcessID,
                exe: from_wide(&pe.szExeFile),
            });
            if Process32NextW(snap.raw(), &mut pe) == 0 {
                break;
            }
        }
    }
    out
}

/// Rows with start times (ms), for tree operations.
pub fn rows_with_start() -> Vec<(u32, u32, i64)> {
    toolhelp_rows()
        .into_iter()
        .map(|r| {
            let s = live_proc(r.pid)
                .map(|l| filetime_to_ms(l.create_ft))
                .unwrap_or(0);
            (r.pid, r.ppid, s)
        })
        .collect()
}

pub fn snapshot(
    boot_id: &str,
    boot_time_ms: i64,
    enricher: &Enricher,
    tracker: &RwLock<ProcTracker>,
) -> Vec<ProcessInfo> {
    let rows = toolhelp_rows();
    let started = Instant::now();
    struct Tmp {
        pid: u32,
        ppid: u32,
        image: String,
        cmdline: String,
        user_sid: Option<String>,
        integrity: Option<kestrel_common::Integrity>,
        start_ts: i64,
    }
    let mut tmp = Vec::with_capacity(rows.len());
    for r in &rows {
        if r.pid == 0 {
            continue;
        }
        let mut t = Tmp {
            pid: r.pid,
            ppid: r.ppid,
            image: r.exe.clone(),
            cmdline: String::new(),
            user_sid: None,
            integrity: None,
            start_ts: boot_time_ms,
        };
        if let Some(h) = open_process(r.pid, PROCESS_QUERY_LIMITED_INFORMATION) {
            if let Some(img) = process_image(&h) {
                t.image = img;
            }
            if let Some(ft) = process_create_time(&h) {
                if ft > 0 {
                    t.start_ts = filetime_to_ms(ft);
                }
            }
            t.cmdline = process_cmdline(&h).unwrap_or_default();
            let (sid, integ) = process_token_info(&h);
            t.user_sid = sid;
            t.integrity = integ;
        }
        tmp.push(t);
    }
    let starts: HashMap<u32, i64> = tmp.iter().map(|t| (t.pid, t.start_ts)).collect();
    let mut out = Vec::with_capacity(tmp.len());
    if let Ok(mut tr) = tracker.write() {
        for t in &tmp {
            tr.on_start(t.pid, t.start_ts, &t.image, t.ppid);
        }
    }
    for t in tmp {
        let guid = ProcessGuid::derive(boot_id, t.pid, t.start_ts);
        let parent_guid = starts
            .get(&t.ppid)
            .filter(|&&ps| ps <= t.start_ts && t.ppid != 0)
            .map(|&ps| ProcessGuid::derive(boot_id, t.ppid, ps));
        let is_path = t.image.contains('\\');
        let facts = if is_path {
            if started.elapsed() < ENRICH_BUDGET {
                enricher.file_blocking(&t.image, true)
            } else {
                enricher.file_or_request(&t.image, true).unwrap_or_default()
            }
        } else {
            Default::default()
        };
        if is_path
            && (facts.signed == kestrel_common::SignatureState::Unknown || facts.sha256.is_none())
        {
            // Budget exhausted: deliver the facts to the engine when ready (H7).
            enricher.watch(&t.image, guid.clone(), t.pid, Some(facts.clone()));
        }
        let user = t
            .user_sid
            .as_deref()
            .map(|s| enricher.user_blocking(s).unwrap_or_else(|| s.to_string()));
        out.push(ProcessInfo {
            guid,
            pid: t.pid,
            ppid: t.ppid,
            parent_guid,
            path_class: if is_path {
                PathClass::of(&t.image)
            } else {
                PathClass::System
            },
            image: t.image,
            cmdline: t.cmdline,
            user,
            integrity: t.integrity,
            start_ts: t.start_ts,
            exit_ts: None,
            signer: facts.signer,
            signed: facts.signed,
            sha256: facts.sha256,
            motw_zone: facts.motw_zone,
            file_size: facts.file_size,
        });
    }
    out
}
