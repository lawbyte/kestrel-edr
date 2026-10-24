//! Simulator remote access: a file system mapped under `<state>/sim-fs`
//! and a synthetic remote-desktop source (test pattern), so the whole live
//! path (server ↔ agent ↔ platform) can be exercised on any OS without
//! touching real files or the real screen.
//!
//! * Files: `X:\…` maps to `<state>/sim-fs/X/…` (same as
//!   `SimPlatform::map_path`); drives `C:\` and `D:\`; protected roots are
//!   the mapped `C:\Program Files\Kestrel` and `C:\ProgramData\Kestrel`. A
//!   small demo tree is seeded on first use.
//! * Desktop: a thread renders a 1280×720 test pattern (colour bars, a block
//!   moving once per second, the seconds counter as blocks and a crosshair
//!   at the last mouse position), JPEG-encodes it at the session's quality /
//!   scale and offers it to the sink at ≤ `max_fps`, only when the content
//!   changed. The "banner" state (`{active, admin_name, view_only, reason,
//!   inputs, files_notice}`) is written to `<state>/sim-desktop.json`; input
//!   is counted, never recorded.
//! * File-manager banner (no desktop session): `{active, text}` in
//!   `<state>/sim-files-banner.json`.

use kestrel_common::remote::{
    DesktopInfo, DesktopSettings, FileEntry, FileKind, InputEvent, RemoteErrorCode,
};
use kestrel_platform::{
    DesktopEvent, DesktopSession, DesktopSink, DesktopStartParams, RemoteDesktop, RemoteFs,
    SessionBanner,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc::error::TrySendError;

/// Banner state file of the simulated desktop session.
pub const SIM_DESKTOP_FILE: &str = "sim-desktop.json";
/// Banner state file of the simulated stand-alone file-manager banner.
pub const SIM_FILES_BANNER_FILE: &str = "sim-files-banner.json";
/// Native size of the simulated screen.
pub const SIM_SCREEN: (u32, u32) = (1280, 720);

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Map a Windows path into `<base>/…` (drive letter becomes a folder).
pub fn map_into(base: &Path, win_path: &str) -> PathBuf {
    let mut p = base.to_path_buf();
    for part in win_path.split(['\\', '/']).filter(|s| !s.is_empty()) {
        let part = part.replace(':', "");
        if part == ".." || part == "." {
            continue;
        }
        p.push(part);
    }
    p
}

// --------------------------------------------------------------------- files

pub struct SimRemoteFs {
    base: PathBuf,
}

impl SimRemoteFs {
    /// `base` = `<state>/sim-fs`. Seeds the demo tree for `user` (`DOMAIN\name`).
    pub fn new(base: PathBuf, user: &str) -> SimRemoteFs {
        let fs = SimRemoteFs { base };
        fs.seed(user);
        fs
    }

    fn seed(&self, user: &str) {
        let name = user.rsplit('\\').next().unwrap_or("user");
        let mk = |p: &str| {
            let _ = std::fs::create_dir_all(self.local_path(p));
        };
        mk("C:\\");
        mk("D:\\");
        for root in [r"C:\Program Files\Kestrel", r"C:\ProgramData\Kestrel"] {
            mk(root);
            let f = self.local_path(&format!(r"{root}\README.txt"));
            if !f.exists() {
                let _ = std::fs::write(
                    f,
                    b"Kestrel agent folder (simulated). Protected from the remote file manager.\n",
                );
            }
        }
        let docs = format!(r"C:\Users\{name}\Documents");
        mk(&docs);
        mk(&format!(r"C:\Users\{name}\Desktop"));
        mk(r"C:\Windows\System32\config");
        let welcome = self.local_path(&format!(r"{docs}\welcome.txt"));
        if !welcome.exists() {
            let _ = std::fs::write(
                welcome,
                b"Welcome to the Kestrel simulated PC.\nThis file lives in the agent's sim-fs folder.\n",
            );
        }
    }
}

impl RemoteFs for SimRemoteFs {
    fn local_path(&self, win_path: &str) -> PathBuf {
        map_into(&self.base, win_path)
    }

    fn drives(&self) -> Vec<FileEntry> {
        ["C", "D"]
            .iter()
            .map(|d| FileEntry {
                name: format!("{d}:"),
                path: format!("{d}:\\"),
                kind: FileKind::Drive,
                label: Some("Local Disk (simulated)".into()),
                ..Default::default()
            })
            .collect()
    }

    fn check_path(&self, win_path: &str) -> Result<(), String> {
        match win_path.as_bytes().first().map(u8::to_ascii_uppercase) {
            Some(b'C') | Some(b'D') => Ok(()),
            _ => Err("this drive does not exist on the device".into()),
        }
    }

    fn protected_roots(&self) -> Vec<PathBuf> {
        vec![
            self.local_path(r"C:\Program Files\Kestrel"),
            self.local_path(r"C:\ProgramData\Kestrel"),
        ]
    }
}

// ------------------------------------------------------------------- desktop

pub struct SimDesktop {
    state_dir: PathBuf,
}

impl SimDesktop {
    pub fn new(state_dir: PathBuf) -> SimDesktop {
        SimDesktop { state_dir }
    }
}

struct Shared {
    stop: AtomicBool,
    view_only: AtomicBool,
    settings: Mutex<DesktopSettings>,
    mouse: Mutex<(f32, f32)>,
    inputs: AtomicU64,
    admin_name: String,
    reason: String,
    file: PathBuf,
    banner: Mutex<()>,
    files_notice: Mutex<String>,
}

fn write_json(file: &Path, v: &serde_json::Value) {
    if let Ok(b) = serde_json::to_vec_pretty(v) {
        let tmp = file.with_extension("json.tmp");
        if std::fs::write(&tmp, b).is_ok() {
            let _ = std::fs::rename(&tmp, file);
        }
    }
}

impl Shared {
    fn write_banner(&self, active: bool) {
        let _g = lock(&self.banner);
        // Never re-show the banner after stop.
        let active = active && !self.stop.load(Ordering::SeqCst);
        let v = serde_json::json!({
            "active": active,
            "admin_name": self.admin_name,
            "view_only": self.view_only.load(Ordering::SeqCst),
            "reason": self.reason,
            "inputs": self.inputs.load(Ordering::SeqCst),
            "files_notice": lock(&self.files_notice).clone(),
        });
        write_json(&self.file, &v);
    }
}

struct SimDesktopSession {
    sh: Arc<Shared>,
}

impl DesktopSession for SimDesktopSession {
    fn input(&self, ev: &InputEvent) {
        match ev {
            InputEvent::MouseMove { x, y }
            | InputEvent::MouseButton { x, y, .. }
            | InputEvent::MouseWheel { x, y, .. } => *lock(&self.sh.mouse) = (*x, *y),
            _ => {}
        }
        self.sh.inputs.fetch_add(1, Ordering::SeqCst);
    }

    fn settings(&self, s: &DesktopSettings) {
        let c = s.clamped();
        if let Some(v) = c.view_only {
            self.sh.view_only.store(v, Ordering::SeqCst);
        }
        *lock(&self.sh.settings) = DesktopSettings {
            view_only: None,
            ..c
        };
        self.sh.write_banner(true);
    }

    fn stop(&self) {
        self.sh.stop.store(true, Ordering::SeqCst);
        self.sh.write_banner(false);
    }

    fn set_files_notice(&self, text: &str) {
        *lock(&self.sh.files_notice) = text.to_string();
        self.sh.write_banner(true);
    }
}

/// Simulated stand-alone file-manager banner (a state file).
struct SimFilesBanner {
    file: PathBuf,
    state: Mutex<(bool, String)>,
}

impl SimFilesBanner {
    fn write(&self, st: &(bool, String)) {
        write_json(
            &self.file,
            &serde_json::json!({ "active": st.0, "text": st.1 }),
        );
    }
}

impl SessionBanner for SimFilesBanner {
    fn set_text(&self, text: &str) {
        let mut st = lock(&self.state);
        if st.0 {
            st.1 = text.to_string();
            self.write(&st);
        }
    }

    fn is_alive(&self) -> bool {
        lock(&self.state).0
    }

    fn close(&self) {
        let mut st = lock(&self.state);
        if st.0 {
            st.0 = false;
            self.write(&st);
        }
    }
}

impl Drop for SimFilesBanner {
    fn drop(&mut self) {
        self.close();
    }
}

impl RemoteDesktop for SimDesktop {
    fn start(
        &self,
        params: DesktopStartParams,
        sink: DesktopSink,
    ) -> Result<Box<dyn DesktopSession>, (RemoteErrorCode, String)> {
        let sh = Arc::new(Shared {
            stop: AtomicBool::new(false),
            view_only: AtomicBool::new(params.view_only),
            settings: Mutex::new(DesktopSettings {
                view_only: None,
                ..params.settings.clamped()
            }),
            mouse: Mutex::new((0.5, 0.5)),
            inputs: AtomicU64::new(0),
            admin_name: params.admin_name.clone(),
            reason: params.reason.clone(),
            file: self.state_dir.join(SIM_DESKTOP_FILE),
            banner: Mutex::new(()),
            files_notice: Mutex::new(String::new()),
        });
        sh.write_banner(true);
        let t = sh.clone();
        std::thread::Builder::new()
            .name("sim-desktop".into())
            .spawn(move || capture_loop(t, sink))
            .map_err(|e| (RemoteErrorCode::Unavailable, format!("capture thread: {e}")))?;
        Ok(Box::new(SimDesktopSession { sh }))
    }

    fn show_banner(&self, text: &str) -> Result<Box<dyn SessionBanner>, (RemoteErrorCode, String)> {
        let b = SimFilesBanner {
            file: self.state_dir.join(SIM_FILES_BANNER_FILE),
            state: Mutex::new((true, text.to_string())),
        };
        b.write(&lock(&b.state));
        Ok(Box::new(b))
    }
}

/// What determines the picture (change detection).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Key {
    second: u64,
    mouse: (u16, u16),
    quality: u8,
    scale: u8,
}

fn capture_loop(sh: Arc<Shared>, sink: DesktopSink) {
    let (w0, h0) = SIM_SCREEN;
    let info = DesktopInfo {
        width: w0,
        height: h0,
        monitors: 1,
        session_id: Some(1),
        secure_desktop: false,
        view_only: sh.view_only.load(Ordering::SeqCst),
    };
    if sink.blocking_send(DesktopEvent::Info(info)).is_err() {
        return;
    }
    let started = Instant::now();
    let mut last: Option<Key> = None;
    let mut pending: Option<(Key, DesktopEvent)> = None;
    let mut inputs_written = 0;
    while !sh.stop.load(Ordering::SeqCst) {
        let s = lock(&sh.settings).clone();
        let (mx, my) = *lock(&sh.mouse);
        let key = Key {
            second: started.elapsed().as_secs(),
            mouse: ((mx * 1000.0) as u16, (my * 1000.0) as u16),
            quality: s.quality,
            scale: s.scale_pct,
        };
        if last != Some(key) {
            let ev = match pending.take() {
                Some((k, ev)) if k == key => ev,
                _ => render(key, (mx, my)),
            };
            match sink.try_send(ev) {
                Ok(()) => last = Some(key),
                // Not delivered: keep it; compare against the last accepted frame.
                Err(TrySendError::Full(ev)) => pending = Some((key, ev)),
                Err(TrySendError::Closed(_)) => break,
            }
        }
        let n = sh.inputs.load(Ordering::SeqCst);
        if n != inputs_written {
            inputs_written = n;
            sh.write_banner(true);
        }
        let period = Duration::from_millis(1000 / s.max_fps.clamp(1, 15) as u64);
        let until = Instant::now() + period;
        while Instant::now() < until && !sh.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(10).min(period));
        }
    }
}

/// Draw the test pattern and encode it.
fn render(key: Key, mouse: (f32, f32)) -> DesktopEvent {
    let (w0, h0) = SIM_SCREEN;
    let w = (w0 * key.scale as u32 / 100).max(16);
    let h = (h0 * key.scale as u32 / 100).max(16);
    let mut rgb = vec![0u8; (w * h * 3) as usize];
    const BARS: [[u8; 3]; 8] = [
        [192, 192, 192],
        [192, 192, 0],
        [0, 192, 192],
        [0, 192, 0],
        [192, 0, 192],
        [192, 0, 0],
        [0, 0, 192],
        [16, 16, 16],
    ];
    let mut put = |x: u32, y: u32, c: [u8; 3]| {
        if x < w && y < h {
            let i = ((y * w + x) * 3) as usize;
            rgb[i..i + 3].copy_from_slice(&c);
        }
    };
    for y in 0..h {
        for x in 0..w {
            let c = if y < h * 2 / 3 {
                BARS[(x * 8 / w) as usize]
            } else {
                [24, 28, 36]
            };
            put(x, y, c);
        }
    }
    // Moving block (once per second).
    let bs = (h / 10).max(4);
    let bx = (key.second as u32 * bs) % (w - bs).max(1);
    let by = h * 2 / 3 + bs / 2;
    for y in by..(by + bs) {
        for x in bx..(bx + bs) {
            put(x, y, [255, 200, 0]);
        }
    }
    // Seconds counter as 16 binary blocks.
    let cs = (w / 40).max(2);
    for bit in 0..16u32 {
        let on = (key.second >> bit) & 1 == 1;
        let x0 = 4 + bit * (cs + 2);
        let y0 = h - cs - 4;
        for y in y0..(y0 + cs) {
            for x in x0..(x0 + cs) {
                put(x, y, if on { [255, 255, 255] } else { [70, 70, 70] });
            }
        }
    }
    // Crosshair at the last mouse position.
    let cx = (mouse.0.clamp(0.0, 1.0) * (w - 1) as f32) as u32;
    let cy = (mouse.1.clamp(0.0, 1.0) * (h - 1) as f32) as u32;
    let arm = (h / 20).max(3);
    for d in 0..=arm {
        for (x, y) in [
            (cx.saturating_sub(d), cy),
            (cx + d, cy),
            (cx, cy.saturating_sub(d)),
            (cx, cy + d),
        ] {
            put(x, y, [255, 0, 0]);
        }
    }
    let mut jpeg = Vec::new();
    let enc = jpeg_encoder::Encoder::new(&mut jpeg, key.quality.clamp(30, 90));
    if enc
        .encode(&rgb, w as u16, h as u16, jpeg_encoder::ColorType::Rgb)
        .is_err()
    {
        jpeg.clear();
    }
    DesktopEvent::Frame {
        width: w,
        height: h,
        ts: kestrel_common::now_ms(),
        jpeg,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::mpsc;

    #[test]
    fn fs_mapping_drives_and_seed() {
        let d = tempfile::tempdir().unwrap();
        let fs = SimRemoteFs::new(d.path().join("sim-fs"), r"CORP\j.doe");
        assert!(fs
            .local_path(r"C:\Users\j.doe\Documents\welcome.txt")
            .is_file());
        assert_eq!(fs.drives().len(), 2);
        assert!(fs.check_path("E:\\").is_err());
        assert!(fs.check_path("d:\\x").is_ok());
        assert!(fs.protected_roots().iter().all(|p| p.is_dir()));
    }

    #[test]
    fn desktop_frames_respect_sink_and_stop() {
        let d = tempfile::tempdir().unwrap();
        let desk = SimDesktop::new(d.path().to_path_buf());
        let (tx, mut rx) = mpsc::channel(1);
        let s = desk
            .start(
                DesktopStartParams {
                    view_only: true,
                    admin_name: "Jane".into(),
                    reason: "test".into(),
                    settings: DesktopSettings {
                        max_fps: 15,
                        scale_pct: 25,
                        ..Default::default()
                    },
                },
                tx,
            )
            .unwrap();
        let banner = || -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(d.path().join(SIM_DESKTOP_FILE)).unwrap())
                .unwrap()
        };
        assert_eq!(banner()["active"], true);
        assert_eq!(banner()["view_only"], true);
        match rx.blocking_recv().unwrap() {
            DesktopEvent::Info(i) => assert_eq!((i.width, i.height), SIM_SCREEN),
            other => panic!("{other:?}"),
        }
        match rx.blocking_recv().unwrap() {
            DesktopEvent::Frame {
                width,
                height,
                jpeg,
                ..
            } => {
                assert_eq!((width, height), (320, 180));
                assert_eq!(&jpeg[..2], &[0xff, 0xd8], "JPEG SOI");
            }
            other => panic!("{other:?}"),
        }
        // Input moves the crosshair → a new frame soon.
        s.input(&InputEvent::MouseMove { x: 0.1, y: 0.9 });
        assert!(matches!(
            rx.blocking_recv().unwrap(),
            DesktopEvent::Frame { .. }
        ));
        s.settings(&DesktopSettings {
            view_only: Some(false),
            ..Default::default()
        });
        assert_eq!(banner()["view_only"], false);
        s.stop();
        s.stop();
        assert_eq!(banner()["active"], false);
        assert_eq!(banner()["inputs"], 1);
        // The thread exits promptly: the channel closes.
        let t = Instant::now();
        while rx.blocking_recv().is_some() {
            assert!(t.elapsed() < Duration::from_secs(5));
        }
    }
}
