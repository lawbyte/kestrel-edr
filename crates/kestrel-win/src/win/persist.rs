//! Persistence sensor glue: read the XML of a newly registered scheduled
//! task (path-safe, no reparse following, size-capped) and complete a 7045
//! service record from its registry key.

use super::safefs::open_verified_file;
use super::util::*;
use crate::persist::PersistRecord;
use crate::taskxml::{
    decode_task_bytes, parse_task_xml, task_rel_path, TaskInfo, MAX_TASK_XML_BYTES,
};
use kestrel_common::{ServiceInstall, TaskOp};
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

/// Read and parse `%SystemRoot%\System32\Tasks\<name>`. Every component is
/// checked for junctions / symlinks and the final path must match (a task
/// folder redirected elsewhere is refused). The file is read with full
/// sharing so the Task Scheduler is never blocked.
pub fn read_task(task_name: &str) -> Option<TaskInfo> {
    let rel = task_rel_path(task_name)?;
    let path = format!(r"{}\System32\Tasks\{rel}", system_root());
    let v = open_verified_file(
        &path,
        FILE_GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    )
    .ok()?;
    let mut buf = vec![0u8; MAX_TASK_XML_BYTES];
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
    buf.truncate(total);
    parse_task_xml(&decode_task_bytes(&buf)?)
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
        PersistRecord::Task { name, op, .. } if *op != TaskOp::Deleted => {
            // The XML is written before 106/140 is logged; one short retry
            // covers a slow writer.
            read_task(name).or_else(|| {
                std::thread::sleep(std::time::Duration::from_millis(150));
                read_task(name)
            })
        }
        PersistRecord::Service(s) => {
            enrich_service(s);
            None
        }
        _ => None,
    }
}
