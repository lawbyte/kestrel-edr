//! Persistence sensor glue: read the XML of a newly registered scheduled
//! task (path-safe, no reparse following, size-capped) and complete a 7045
//! service record from its registry key.
//!
//! V-M9: this work (file reads, a short retry sleep, COM) never runs inside
//! an ETW or event-log callback any more. The callbacks hand the bare record
//! to [`submit`]; one worker thread enriches it and forwards `Raw::Persist`
//! to the translator. The queue is bounded; overflow is counted as dropped
//! raw events. Oversized task XML (> [`MAX_TASK_XML_BYTES`]) falls back to
//! the Task Scheduler COM API (`IRegisteredTask::Xml`, capped at 4 MiB) and
//! is flagged with the [`TRIGGER_XML_OVERSIZED`] trigger marker.

use super::etw::{Raw, Sink};
use super::safefs::open_verified_file;
use super::util::*;
use crate::persist::PersistRecord;
use crate::taskxml::{
    decode_task_bytes, parse_task_xml, task_rel_path, TaskInfo, MAX_TASK_XML_BYTES,
    TRIGGER_XML_OVERSIZED,
};
use kestrel_common::{ServiceInstall, TaskOp};
use std::sync::atomic::Ordering;
use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// Largest task XML accepted through the COM fallback.
const MAX_COM_XML_CHARS: usize = 4 * 1024 * 1024;
/// Records waiting for enrichment.
const QUEUE: usize = 512;

/// Result of reading a task file.
enum TaskRead {
    Ok(TaskInfo),
    /// Larger than the cap: not parsed from disk.
    Oversized,
    /// Missing, unreadable, refused by the path checks, or not task XML.
    Unreadable,
}

/// Read and parse `%SystemRoot%\System32\Tasks\<name>`. Every component is
/// checked for junctions / symlinks and the final path must match (a task
/// folder redirected elsewhere is refused). The file is read with full
/// sharing so the Task Scheduler is never blocked.
fn read_task_file(task_name: &str) -> TaskRead {
    let Some(rel) = task_rel_path(task_name) else {
        return TaskRead::Unreadable;
    };
    let path = format!(r"{}\System32\Tasks\{rel}", system_root());
    let Ok(v) = open_verified_file(
        &path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    ) else {
        return TaskRead::Unreadable;
    };
    // One byte more than the cap tells "exactly at the cap" from "larger".
    let mut buf = vec![0u8; MAX_TASK_XML_BYTES + 1];
    let mut total = 0usize;
    while total < buf.len() {
        let mut n = 0u32;
        let ok = unsafe {
            ReadFile(
                v.h.raw(),
                buf[total..].as_mut_ptr(),
                (buf.len() - total) as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || n == 0 {
            break;
        }
        total += n as usize;
    }
    if total > MAX_TASK_XML_BYTES {
        return TaskRead::Oversized;
    }
    buf.truncate(total);
    match decode_task_bytes(&buf).and_then(|s| parse_task_xml(&s)) {
        Some(i) => TaskRead::Ok(i),
        None => TaskRead::Unreadable,
    }
}

/// `\Folder\Sub\Name` → (`\Folder\Sub`, `Name`).
fn split_task_path(task_name: &str) -> Option<(String, String)> {
    let rel = task_rel_path(task_name)?;
    match rel.rsplit_once('\\') {
        Some((dir, leaf)) => Some((format!(r"\{dir}"), leaf.to_string())),
        None => Some((r"\".to_string(), rel)),
    }
}

/// Task XML through the Task Scheduler COM API (worker thread only).
fn read_task_com(task_name: &str) -> Option<TaskInfo> {
    use windows::core::BSTR;
    let (folder, leaf) = split_task_path(task_name)?;
    let _com = super::com::ComInit::new().ok()?;
    let ts = super::com::task_service().ok()?;
    let xml = unsafe {
        ts.GetFolder(&BSTR::from(folder.as_str()))
            .ok()?
            .GetTask(&BSTR::from(leaf.as_str()))
            .ok()?
            .Xml()
            .ok()?
            .to_string()
    };
    if xml.chars().count() > MAX_COM_XML_CHARS {
        return None;
    }
    parse_task_xml(&xml)
}

/// Task info for a created / updated task: the file first (one short retry
/// for a slow writer), the COM API when the file is oversized or unreadable.
pub fn read_task(task_name: &str) -> TaskInfo {
    let mut r = read_task_file(task_name);
    if matches!(r, TaskRead::Unreadable) {
        std::thread::sleep(std::time::Duration::from_millis(150));
        r = read_task_file(task_name);
    }
    match r {
        TaskRead::Ok(i) => i,
        TaskRead::Oversized => {
            let mut i = read_task_com(task_name).unwrap_or_default();
            i.oversized = true;
            if !i.triggers.iter().any(|t| t == TRIGGER_XML_OVERSIZED) {
                i.triggers.push(TRIGGER_XML_OVERSIZED.to_string());
            }
            i
        }
        TaskRead::Unreadable => read_task_com(task_name).unwrap_or_default(),
    }
}

/// Fill type / start / image / account from
/// `HKLM\SYSTEM\CurrentControlSet\Services\<name>` (authoritative; the 7045
/// strings are localised).
pub fn enrich_service(s: &mut ServiceInstall) {
    if s.name.is_empty() || s.name.contains(['\\', '/']) || s.name.len() > 256 {
        return;
    }
    let Some(k) = reg_open(
        HKEY_LOCAL_MACHINE,
        &format!(r"SYSTEM\CurrentControlSet\Services\{}", s.name),
        false,
    ) else {
        return;
    };
    if let Some(t) = reg_get_dword(&k, "Type") {
        s.service_type = Some(t);
    }
    if let Some(t) = reg_get_dword(&k, "Start") {
        s.start_type = Some(t);
    }
    if s.image_path.is_empty() {
        if let Some(p) = reg_get_string(&k, "ImagePath") {
            s.image_path = p;
        }
    }
    if s.account.is_none() {
        s.account = reg_get_string(&k, "ObjectName");
    }
}

/// Task XML for created / updated tasks; service registry details.
pub fn enrich(record: &mut PersistRecord) -> Option<TaskInfo> {
    match record {
        PersistRecord::Task { name, op, .. } if *op != TaskOp::Deleted => Some(read_task(name)),
        PersistRecord::Service(s) => {
            enrich_service(s);
            None
        }
        _ => None,
    }
}

struct Job {
    sink: Sink,
    ts: i64,
    logger_pid: u32,
    record: PersistRecord,
}

fn worker() -> &'static SyncSender<Job> {
    static TX: OnceLock<SyncSender<Job>> = OnceLock::new();
    TX.get_or_init(|| {
        let (tx, rx) = sync_channel::<Job>(QUEUE);
        let spawned = std::thread::Builder::new()
            .name("kestrel-persist-enrich".into())
            .spawn(move || {
                while let Ok(mut j) = rx.recv() {
                    let task = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        enrich(&mut j.record)
                    }))
                    .unwrap_or_default();
                    j.sink.send(Raw::Persist {
                        ts: j.ts,
                        logger_pid: j.logger_pid,
                        record: j.record,
                        task,
                    });
                }
            });
        if let Err(e) = spawned {
            tracing::error!("persistence enrichment worker: {e}");
        }
        tx
    })
}

/// Queue a persistence record for enrichment (never blocks the caller).
pub fn submit(sink: &Sink, ts: i64, logger_pid: u32, record: PersistRecord) {
    let job = Job {
        sink: sink.clone(),
        ts,
        logger_pid,
        record,
    };
    match worker().try_send(job) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
            sink.counters.raw_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_path_split() {
        assert_eq!(
            split_task_path(r"\Updater"),
            Some((r"\".to_string(), "Updater".to_string()))
        );
        assert_eq!(
            split_task_path(r"\Microsoft\Office\Telemetry"),
            Some((r"\Microsoft\Office".to_string(), "Telemetry".to_string()))
        );
        assert_eq!(split_task_path(r"\..\x"), None);
    }
}
