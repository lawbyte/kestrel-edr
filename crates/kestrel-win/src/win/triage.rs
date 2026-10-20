//! Triage package: process list, network table, autoruns, recent Prefetch
//! names → `<state>\triage\triage-<host>-<ts>.zip`.

use super::util::*;
use crate::zipw::ZipWriter;
use kestrel_common::ProcessInfo;
use serde_json::json;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::System::Registry::{HKEY, HKEY_LOCAL_MACHINE, HKEY_USERS};

const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;

fn table(tcp: bool, af: u32) -> Vec<u8> {
    let mut size = 0u32;
    unsafe {
        if tcp {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                1,
                af,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            );
        } else {
            GetExtendedUdpTable(
                std::ptr::null_mut(),
                &mut size,
                1,
                af,
                UDP_TABLE_OWNER_PID,
                0,
            );
        }
    }
    for _ in 0..3 {
        let mut buf = vec![0u8; size as usize + 4096];
        size = buf.len() as u32;
        let rc = unsafe {
            if tcp {
                GetExtendedTcpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    1,
                    af,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            } else {
                GetExtendedUdpTable(
                    buf.as_mut_ptr() as *mut _,
                    &mut size,
                    1,
                    af,
                    UDP_TABLE_OWNER_PID,
                    0,
                )
            }
        };
        if rc == 0 {
            buf.truncate(size as usize);
            return buf;
        }
        if rc != 122 {
            break; // not ERROR_INSUFFICIENT_BUFFER
        }
    }
    Vec::new()
}

fn u32le(b: &[u8], o: usize) -> u32 {
    b.get(o..o + 4)
        .map(|x| u32::from_le_bytes(x.try_into().unwrap()))
        .unwrap_or(0)
}
fn port(b: &[u8], o: usize) -> u16 {
    b.get(o..o + 2)
        .map(|x| u16::from_be_bytes([x[0], x[1]]))
        .unwrap_or(0)
}
fn v4(b: &[u8], o: usize) -> String {
    b.get(o..o + 4)
        .map(|x| Ipv4Addr::new(x[0], x[1], x[2], x[3]).to_string())
        .unwrap_or_default()
}
fn v6(b: &[u8], o: usize) -> String {
    b.get(o..o + 16)
        .map(|x| Ipv6Addr::from(<[u8; 16]>::try_from(x).unwrap()).to_string())
        .unwrap_or_default()
}

const TCP_STATES: [&str; 13] = [
    "?",
    "CLOSED",
    "LISTEN",
    "SYN_SENT",
    "SYN_RCVD",
    "ESTABLISHED",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "CLOSE_WAIT",
    "CLOSING",
    "LAST_ACK",
    "TIME_WAIT",
    "DELETE_TCB",
];

pub fn netstat(images: &dyn Fn(u32) -> String) -> String {
    let mut out = String::from("proto\tlocal\tremote\tstate\tpid\timage\n");
    let b = table(true, AF_INET);
    let n = u32le(&b, 0) as usize;
    for i in 0..n {
        let o = 4 + i * 24;
        let st = u32le(&b, o) as usize;
        let pid = u32le(&b, o + 20);
        out.push_str(&format!(
            "tcp\t{}:{}\t{}:{}\t{}\t{pid}\t{}\n",
            v4(&b, o + 4),
            port(&b, o + 8),
            v4(&b, o + 12),
            port(&b, o + 16),
            TCP_STATES.get(st).unwrap_or(&"?"),
            images(pid)
        ));
    }
    let b = table(true, AF_INET6);
    let n = u32le(&b, 0) as usize;
    for i in 0..n {
        let o = 4 + i * 56;
        let st = u32le(&b, o + 48) as usize;
        let pid = u32le(&b, o + 52);
        out.push_str(&format!(
            "tcp6\t[{}]:{}\t[{}]:{}\t{}\t{pid}\t{}\n",
            v6(&b, o),
            port(&b, o + 20),
            v6(&b, o + 24),
            port(&b, o + 44),
            TCP_STATES.get(st).unwrap_or(&"?"),
            images(pid)
        ));
    }
    let b = table(false, AF_INET);
    let n = u32le(&b, 0) as usize;
    for i in 0..n {
        let o = 4 + i * 12;
        let pid = u32le(&b, o + 8);
        out.push_str(&format!(
            "udp\t{}:{}\t*:*\t\t{pid}\t{}\n",
            v4(&b, o),
            port(&b, o + 4),
            images(pid)
        ));
    }
    out
}

fn reg_dump(root: HKEY, root_name: &str, path: &str) -> Vec<serde_json::Value> {
    match reg_open(root, path, false) {
        Some(k) => reg_values(&k)
            .into_iter()
            .map(|(n, v)| json!({"key": format!(r"{root_name}\{path}"), "name": n, "data": v}))
            .collect(),
        None => vec![],
    }
}

fn autoruns(profiles: &[String]) -> serde_json::Value {
    let run_keys = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
    ];
    let mut entries = Vec::new();
    for k in run_keys {
        entries.extend(reg_dump(HKEY_LOCAL_MACHINE, "HKLM", k));
    }
    entries.extend(
        reg_dump(
            HKEY_LOCAL_MACHINE,
            "HKLM",
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        )
        .into_iter()
        .filter(|e| {
            matches!(
                e["name"].as_str(),
                Some("Shell") | Some("Userinit") | Some("Taskman") | Some("AppSetup")
            )
        }),
    );
    if let Some(users) = reg_open(HKEY_USERS, "", false) {
        for sid in reg_subkeys(&users)
            .into_iter()
            .filter(|s| s.starts_with("S-1-") && !s.ends_with("_Classes"))
        {
            for k in [
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
                r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            ] {
                entries.extend(reg_dump(HKEY_USERS, "HKU", &format!(r"{sid}\{k}")));
            }
        }
    }
    // IFEO debuggers / silent-process-exit hijacks.
    let ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    if let Some(k) = reg_open(HKEY_LOCAL_MACHINE, ifeo, false) {
        for sub in reg_subkeys(&k) {
            entries.extend(
                reg_dump(HKEY_LOCAL_MACHINE, "HKLM", &format!(r"{ifeo}\{sub}"))
                    .into_iter()
                    .filter(|e| {
                        matches!(
                            e["name"].as_str(),
                            Some("Debugger") | Some("VerifierDlls") | Some("GlobalFlag")
                        )
                    }),
            );
        }
    }
    // AMSI providers.
    if let Some(k) = reg_open(
        HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\AMSI\Providers",
        false,
    ) {
        for sub in reg_subkeys(&k) {
            entries.push(
                json!({"key": r"HKLM\SOFTWARE\Microsoft\AMSI\Providers", "name": sub, "data": ""}),
            );
        }
    }
    // Services.
    let mut services = Vec::new();
    if let Some(k) = reg_open(
        HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Services",
        false,
    ) {
        for s in reg_subkeys(&k) {
            if let Some(sk) = reg_open(
                HKEY_LOCAL_MACHINE,
                &format!(r"SYSTEM\CurrentControlSet\Services\{s}"),
                false,
            ) {
                if let Some(img) = reg_get_string(&sk, "ImagePath") {
                    services.push(
                        json!({"name": s, "image_path": img, "start": reg_get_dword(&sk, "Start")}),
                    );
                }
            }
        }
    }
    // Startup folders.
    let mut startup = Vec::new();
    let mut dirs = vec![PathBuf::from(
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    )];
    for p in profiles {
        dirs.push(
            Path::new(p).join(r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"),
        );
    }
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                startup.push(e.path().to_string_lossy().into_owned());
            }
        }
    }
    // Scheduled tasks (names + exec commands).
    let mut tasks = Vec::new();
    let mut stack = vec![PathBuf::from(format!(r"{}\System32\Tasks", system_root()))];
    while let Some(d) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&d) else {
            continue;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if tasks.len() < 2000 {
                let raw = std::fs::read(&p).unwrap_or_default();
                let text = if raw.starts_with(&[0xff, 0xfe]) {
                    crate::etwparse::utf16le(&raw[2..])
                } else {
                    String::from_utf8_lossy(&raw).into_owned()
                };
                let cmds: Vec<String> = text
                    .split("<Command>")
                    .skip(1)
                    .filter_map(|s| s.split("</Command>").next())
                    .map(|s| s.trim().to_string())
                    .collect();
                tasks.push(json!({"task": p.to_string_lossy(), "commands": cmds}));
            }
        }
    }
    json!({"registry": entries, "services": services, "startup_folders": startup, "scheduled_tasks": tasks})
}

fn prefetch() -> String {
    let dir = format!(r"{}\Prefetch", system_root());
    let mut v: Vec<(i64, String)> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| {
                    e.path()
                        .extension()
                        .map(|x| x.eq_ignore_ascii_case("pf"))
                        .unwrap_or(false)
                })
                .map(|e| {
                    let m = e
                        .metadata()
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    (m, e.file_name().to_string_lossy().into_owned())
                })
                .collect()
        })
        .unwrap_or_default();
    v.sort_by_key(|e| std::cmp::Reverse(e.0));
    let mut out = String::from("last_modified_ms\tprefetch_file\n");
    for (m, n) in v.into_iter().take(300) {
        out.push_str(&format!("{m}\t{n}\n"));
    }
    out
}

pub fn collect(
    state_dir: &Path,
    hostname: &str,
    procs: &[ProcessInfo],
    profiles: &[String],
    extra: serde_json::Value,
) -> Result<PathBuf, String> {
    let dir = state_dir.join("triage");
    ensure_private_dir(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let now = kestrel_common::now_ms();
    let path = dir.join(format!(
        "triage-{}-{now}.zip",
        hostname.replace(['\\', '/', ':'], "_")
    ));
    let images = |pid: u32| {
        procs
            .iter()
            .find(|p| p.pid == pid)
            .map(|p| p.image.clone())
            .unwrap_or_default()
    };
    let file = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    let mut z = ZipWriter::new(std::io::BufWriter::new(file), now);
    let add = |z: &mut ZipWriter<_>, name: &str, data: &[u8]| {
        z.add(name, data).map_err(|e| e.to_string())
    };
    add(
        &mut z,
        "processes.json",
        &serde_json::to_vec_pretty(procs).unwrap_or_default(),
    )?;
    add(&mut z, "netstat.txt", netstat(&images).as_bytes())?;
    add(
        &mut z,
        "autoruns.json",
        &serde_json::to_vec_pretty(&autoruns(profiles)).unwrap_or_default(),
    )?;
    add(&mut z, "prefetch.txt", prefetch().as_bytes())?;
    add(
        &mut z,
        "host.json",
        &serde_json::to_vec_pretty(&extra).unwrap_or_default(),
    )?;
    z.finish().map_err(|e| e.to_string())?;
    Ok(path)
}
