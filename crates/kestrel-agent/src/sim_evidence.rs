//! Simulated evidence host for `SimPlatform` (tests, `kestrel-agent
//! simulate`). Never touches the real filesystem outside the simulator's
//! state directory:
//!
//! * Windows paths map into `<state>/sim-fs/<drive letter>/<rest>` (the same
//!   sandbox the simulated canaries and remote file manager use);
//! * `open_source` refuses UNC / device paths and non-drive paths
//!   (`NotAFile`), alternate data streams and symbolic links anywhere on the
//!   mapped path or hard-linked files (`Link`), directories (`NotAFile`),
//!   files over the cap (`TooLarge`); a file with a sibling
//!   `<name>.sim-locked` marker is `Locked` (tests);
//! * the bundle key is a random 32-byte file in the state directory;
//! * `own_prefixes` = the state directory plus fake Kestrel install / data
//!   folders (`C:\Program Files\Kestrel`, `C:\ProgramData\Kestrel`);
//! * the packet capture writes a minimal valid pcapng (Section Header Block
//!   + Interface Description Block) and records the filters it was given.

use kestrel_common::evidence::PcapFilter;
use kestrel_platform::{
    CaptureSession, CaptureStartError, CapturedFile, EvidenceHost, PacketCapture, SourceError,
    SourceFile,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// Marker suffix that makes the simulated file "locked by another program".
pub const SIM_LOCKED_SUFFIX: &str = ".sim-locked";

pub struct SimEvidence {
    state_dir: PathBuf,
    fs_root: PathBuf,
    pcap: Arc<SimPcap>,
    /// Tests: every `open_source` blocks this long (an oplock / a cloud
    /// placeholder being hydrated).
    pub open_delay_ms: AtomicU64,
    /// Tests: 8.3 short-name aliases (`C:\PROGRA~3` -> `C:\ProgramData`),
    /// expanded like the file system does on open and in `resolve_path`.
    pub short_names: Mutex<Vec<(String, String)>>,
    /// Tests: profile folder per account (`CORP\a` -> `C:\Users\a.CORP`),
    /// what Windows reads from the SID's ProfileList entry.
    pub profiles: Mutex<Vec<(String, String)>>,
}

#[derive(Default)]
pub struct SimPcap {
    /// Filters of every started capture.
    starts: Mutex<Vec<Vec<PcapFilter>>>,
    /// Make `start` answer `Busy` (someone else's capture).
    pub busy: AtomicBool,
    pub cleanups: AtomicU64,
    pub stops: Arc<AtomicU64>,
}

impl SimPcap {
    pub fn starts(&self) -> Vec<Vec<PcapFilter>> {
        self.starts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

/// Minimal valid pcapng: SHB (little endian, v1.0, unknown section length)
/// + IDB (Ethernet, no snap limit).
pub fn minimal_pcapng() -> Vec<u8> {
    let mut v = Vec::with_capacity(48);
    // Section Header Block
    v.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes());
    v.extend_from_slice(&28u32.to_le_bytes());
    v.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&u64::MAX.to_le_bytes());
    v.extend_from_slice(&28u32.to_le_bytes());
    // Interface Description Block
    v.extend_from_slice(&1u32.to_le_bytes());
    v.extend_from_slice(&20u32.to_le_bytes());
    v.extend_from_slice(&1u16.to_le_bytes());
    v.extend_from_slice(&0u16.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(&20u32.to_le_bytes());
    v
}

struct SimSession {
    work: PathBuf,
    stops: Arc<AtomicU64>,
}

impl CaptureSession for SimSession {
    fn stop(self: Box<Self>) -> Result<CapturedFile, String> {
        self.stops.fetch_add(1, Ordering::Relaxed);
        let path = self.work.join("capture.pcapng");
        let data = minimal_pcapng();
        std::fs::write(&path, &data).map_err(|e| format!("sim capture: {}", e.kind()))?;
        Ok(CapturedFile {
            path,
            bytes: data.len() as u64,
            truncated: false,
        })
    }
}

impl PacketCapture for SimPcap {
    fn start(
        &self,
        filters: &[PcapFilter],
        work_dir: &Path,
        _max_bytes: u64,
    ) -> Result<Box<dyn CaptureSession>, CaptureStartError> {
        if self.busy.load(Ordering::Relaxed) {
            return Err(CaptureStartError::Busy(
                "another packet capture is running".into(),
            ));
        }
        self.starts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(filters.to_vec());
        Ok(Box::new(SimSession {
            work: work_dir.to_path_buf(),
            stops: self.stops.clone(),
        }))
    }

    fn cleanup_stale(&self, _work_root: &Path) {
        self.cleanups.fetch_add(1, Ordering::Relaxed);
    }

    fn mechanism(&self) -> &'static str {
        "sim"
    }
}

impl SimEvidence {
    pub fn new(state_dir: PathBuf) -> Self {
        SimEvidence {
            fs_root: state_dir.join("sim-fs"),
            state_dir,
            pcap: Arc::new(SimPcap::default()),
            open_delay_ms: AtomicU64::new(0),
            short_names: Mutex::new(Vec::new()),
            profiles: Mutex::new(Vec::new()),
        }
    }

    /// `path` with its first matching short-name alias expanded.
    pub fn expand(&self, path: &str) -> String {
        let aliases = self.short_names.lock().unwrap_or_else(|e| e.into_inner());
        for (short, long) in aliases.iter() {
            if path.len() >= short.len()
                && path.is_char_boundary(short.len())
                && path[..short.len()].eq_ignore_ascii_case(short)
            {
                return format!("{long}{}", &path[short.len()..]);
            }
        }
        path.to_string()
    }

    pub fn pcap(&self) -> Arc<SimPcap> {
        self.pcap.clone()
    }

    /// Sandbox location of a Windows path (`None` = not a drive path, or an
    /// alternate data stream).
    pub fn map(&self, win: &str) -> Result<PathBuf, SourceError> {
        let w = win.trim();
        let b = w.as_bytes();
        if w.starts_with(r"\\") || w.starts_with("//") {
            return Err(SourceError::NotAFile);
        }
        if b.len() < 3
            || !b[0].is_ascii_alphabetic()
            || b[1] != b':'
            || !matches!(b[2], b'\\' | b'/')
        {
            return Err(SourceError::NotAFile);
        }
        if w[2..].contains(':') {
            return Err(SourceError::Link("alternate data stream".into()));
        }
        let mut p = self
            .fs_root
            .join((b[0] as char).to_ascii_uppercase().to_string());
        for part in w[3..].split(['\\', '/']).filter(|s| !s.is_empty()) {
            if part == ".." || part == "." {
                return Err(SourceError::Other("relative path component".into()));
            }
            p.push(part);
        }
        Ok(p)
    }

    /// No component below the sandbox root may be a symbolic link.
    fn check_links(&self, p: &Path) -> Result<std::fs::Metadata, SourceError> {
        let rel = p
            .strip_prefix(&self.fs_root)
            .map_err(|_| SourceError::NotAFile)?;
        let mut cur = self.fs_root.clone();
        let mut last = None;
        for c in rel.components() {
            cur.push(c);
            match std::fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => {
                    return Err(SourceError::Link("symbolic link on the path".into()))
                }
                Ok(m) => last = Some(m),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    return Err(SourceError::NotFound)
                }
                Err(e) => return Err(SourceError::Other(e.kind().to_string())),
            }
        }
        last.ok_or(SourceError::NotAFile)
    }
}

impl EvidenceHost for SimEvidence {
    fn evidence_dir(&self) -> PathBuf {
        self.state_dir.join("evidence")
    }

    fn bundle_key(&self) -> Result<[u8; 32], String> {
        let p = self.state_dir.join("sim-evidence.key");
        if let Ok(v) = std::fs::read(&p) {
            return v
                .as_slice()
                .try_into()
                .map_err(|_| "bundle key file damaged".to_string());
        }
        let key: [u8; 32] = rand::random();
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&p)
            .map_err(|e| format!("bundle key: {}", e.kind()))?;
        f.write_all(&key)
            .map_err(|e| format!("bundle key: {}", e.kind()))?;
        Ok(key)
    }

    fn own_prefixes(&self) -> Vec<String> {
        vec![
            self.state_dir
                .to_string_lossy()
                .replace('/', "\\")
                .trim_end_matches('\\')
                .to_lowercase(),
            r"c:\program files\kestrel".into(),
            r"c:\programdata\kestrel".into(),
        ]
    }

    fn open_source(&self, path: &str, max_bytes: u64) -> Result<SourceFile, SourceError> {
        let delay = self.open_delay_ms.load(Ordering::Relaxed);
        if delay > 0 {
            std::thread::sleep(std::time::Duration::from_millis(delay));
        }
        let long = self.expand(path);
        let p = self.map(&long)?;
        let m = self.check_links(&p)?;
        if !m.is_file() {
            return Err(SourceError::NotAFile);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if m.nlink() > 1 {
                return Err(SourceError::Link("hard-linked file".into()));
            }
        }
        let mut lock = p.clone().into_os_string();
        lock.push(SIM_LOCKED_SUFFIX);
        if Path::new(&lock).exists() {
            return Err(SourceError::Locked);
        }
        if m.len() > max_bytes {
            return Err(SourceError::TooLarge(m.len()));
        }
        let f = std::fs::File::open(&p).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => SourceError::NotFound,
            k => SourceError::Other(k.to_string()),
        })?;
        Ok(SourceFile {
            reader: Box::new(f),
            size: m.len(),
            path: long,
        })
    }

    fn file_size(&self, path: &str) -> Option<u64> {
        let p = self.map(&self.expand(path)).ok()?;
        let m = self.check_links(&p).ok()?;
        m.is_file().then_some(m.len())
    }

    fn resolve_path(&self, path: &str) -> Option<String> {
        let long = self.expand(path);
        let p = self.map(&long).ok()?;
        self.check_links(&p).ok()?;
        Some(long)
    }

    fn profile_dir(&self, user: &str) -> Option<String> {
        let profiles = self.profiles.lock().unwrap_or_else(|e| e.into_inner());
        profiles
            .iter()
            .find(|(u, _)| u.eq_ignore_ascii_case(user.trim()))
            .map(|(_, d)| d.clone())
    }

    fn packet_capture(&self) -> Option<Arc<dyn PacketCapture>> {
        Some(self.pcap.clone())
    }
}
