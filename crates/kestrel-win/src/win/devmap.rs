//! Drive-letter device table for NT → Win32 path conversion.

use super::util::*;
use crate::ntpath::DeviceMap;
use windows_sys::Win32::Storage::FileSystem::{GetLogicalDrives, QueryDosDeviceW};

/// Build the table: for every logical drive, `QueryDosDeviceW("C:")` →
/// `\Device\HarddiskVolume3`.
pub fn build() -> DeviceMap {
    let mut m = DeviceMap::new(&system_root());
    let mask = unsafe { GetLogicalDrives() };
    for i in 0..26u32 {
        if mask & (1 << i) == 0 {
            continue;
        }
        let drive = format!("{}:", (b'A' + i as u8) as char);
        let w = wide(&drive);
        let mut buf = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(w.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            continue;
        }
        // Multi-string; the first entry is the current mapping.
        let target = from_wide(&buf);
        if !target.is_empty() {
            m.insert(&target, &drive);
        }
    }
    m
}
