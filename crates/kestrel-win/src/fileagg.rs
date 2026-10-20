//! Ransomware file-activity aggregation (pure, runs in the Kernel-File ETW
//! callback thread).
//!
//! Inputs are Kernel-File events with **lower-cased NT paths**
//! (`\device\harddiskvolume3\users\bob\documents\a.docx`): Create (12, the
//! high byte of `CreateOptions` is the disposition), CreateNewFile (30),
//! DeletePath (26) and RenamePath (27). Only user-data paths
//! ([`FileScope`]) are kept; everything else is dropped before allocation.
//!
//! Per process, a 10 s sliding window of operations is kept (bounded) and a
//! [`FileActivity`] summary is produced when at least
//! [`EMIT_MIN_FILES`] distinct files were touched — at most every
//! [`REEMIT_MS`] per process while the count grows — or at once when a
//! ransomware canary is written, renamed or deleted.
//!
//! RenamePath `FilePath` semantics (source or target) are not documented and
//! could not be measured on the host yet; both are handled: the old name
//! comes from the `FileObject → path` map filled by Create, and `FilePath`
//! is treated as the new name when it differs from it.

use kestrel_common::FileActivity;
use std::collections::{HashMap, HashSet, VecDeque};

pub const WINDOW_MS: i64 = 10_000;
pub const EMIT_MIN_FILES: u32 = 10;
pub const REEMIT_MS: i64 = 2_000;
/// Operations kept per process in the window.
pub const MAX_OPS_PER_PID: usize = 2048;
/// Processes tracked at once.
pub const MAX_PIDS: usize = 256;
/// Operations across all processes.
pub const MAX_TOTAL_OPS: usize = 131_072;
/// FileObject → path entries (Create → later Rename/Delete).
pub const MAX_FILE_OBJECTS: usize = 65_536;
/// A name newly created in at least this many directories is a ransom-note candidate.
pub const NOTE_MIN_DIRS: u32 = 3;

/// Extensions that are normal results of a rename / new file (documents,
/// media, archives, temp and editor artefacts). A rename *to* one of these is
/// not an extension change.
pub const KNOWN_EXTENSIONS: &[&str] = &[
    // documents
    "doc",
    "docx",
    "docm",
    "dot",
    "dotx",
    "xls",
    "xlsx",
    "xlsm",
    "xlsb",
    "xlt",
    "xltx",
    "ppt",
    "pptx",
    "pptm",
    "pps",
    "ppsx",
    "odt",
    "ods",
    "odp",
    "rtf",
    "txt",
    "csv",
    "tsv",
    "pdf",
    "md",
    "xml",
    "json",
    "yaml",
    "yml",
    "html",
    "htm",
    "mht",
    "eml",
    "msg",
    "pst",
    "ost",
    "vsd",
    "vsdx",
    "pub",
    "one",
    "epub",
    "log",
    "ini",
    "cfg",
    "conf",
    // images / media
    "jpg",
    "jpeg",
    "png",
    "gif",
    "bmp",
    "tif",
    "tiff",
    "heic",
    "heif",
    "webp",
    "svg",
    "ico",
    "raw",
    "cr2",
    "cr3",
    "nef",
    "arw",
    "dng",
    "psd",
    "ai",
    "mp3",
    "wav",
    "flac",
    "aac",
    "m4a",
    "ogg",
    "wma",
    "mp4",
    "mov",
    "avi",
    "mkv",
    "wmv",
    "m4v",
    "webm",
    // archives / packages / data
    "zip",
    "7z",
    "rar",
    "gz",
    "tgz",
    "bz2",
    "xz",
    "zst",
    "tar",
    "cab",
    "iso",
    "msi",
    "db",
    "sqlite",
    "sqlite3",
    "bak",
    "old",
    "orig",
    // temp / partial / sync / editors
    "tmp",
    "temp",
    "part",
    "partial",
    "crdownload",
    "download",
    "!ut",
    "lock",
    "lck",
    "swp",
    "swo",
    "asd",
    "wbk",
    "laccdb",
    "ldb",
    "~tmp",
    "temp$",
    "cache",
    // code
    "c",
    "h",
    "cpp",
    "hpp",
    "cs",
    "rs",
    "py",
    "js",
    "ts",
    "tsx",
    "jsx",
    "java",
    "go",
    "rb",
    "php",
    "ps1",
    "bat",
    "cmd",
    "sh",
    "sql",
    "css",
    "scss",
    "toml",
    "lock",
    // executables / libraries (renamed by updaters)
    "exe",
    "dll",
    "sys",
    "lnk",
    "url",
];

pub fn is_known_ext(ext: &str) -> bool {
    KNOWN_EXTENSIONS.contains(&ext)
}

/// File name of a `\`-separated path.
pub fn file_name(path: &str) -> &str {
    path.rsplit('\\').next().unwrap_or(path)
}

/// Parent directory of a `\`-separated path.
pub fn parent(path: &str) -> &str {
    path.rsplit_once('\\').map(|(p, _)| p).unwrap_or("")
}

/// Last extension of a file name (lower-case input expected), without the
/// dot. None when there is no dot, the dot is first, or the extension is
/// longer than 32 characters.
pub fn ext_of(name: &str) -> Option<&str> {
    let (stem, e) = name.rsplit_once('.')?;
    if stem.is_empty() || e.is_empty() || e.len() > 32 || e.contains(' ') {
        return None;
    }
    Some(e)
}

/// `report.docx.k3str` → true: a known extension followed by an unknown one.
pub fn is_appended_unknown_ext(name: &str) -> bool {
    let Some(e) = ext_of(name) else { return false };
    if is_known_ext(e) {
        return false;
    }
    let stem = &name[..name.len() - e.len() - 1];
    ext_of(stem).is_some_and(is_known_ext)
}

/// Where file activity is aggregated.
#[derive(Debug, Clone, Default)]
pub struct FileScope {
    /// Lower-cased NT device of the system volume (`\device\harddiskvolume3`).
    pub system_device: String,
}

/// Top-level profile folders that hold user data.
const USER_DATA_DIRS: &[&str] = &[
    "documents",
    "desktop",
    "pictures",
    "downloads",
    "music",
    "videos",
    "favorites",
    "contacts",
];
/// Non-user-data roots on other volumes.
const OTHER_VOLUME_EXCLUDES: &[&str] = &[
    r"\$recycle.bin",
    r"\system volume information",
    r"\windows",
    r"\program files",
    r"\program files (x86)",
    r"\programdata",
    r"\$extend",
    r"\$windows.~bt",
    r"\$windows.~ws",
    r"\recovery",
    r"\pagefile.sys",
    r"\swapfile.sys",
    r"\hiberfil.sys",
    r"\$mft",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    UserData,
    Network,
}

impl FileScope {
    pub fn new(system_device: &str) -> Self {
        FileScope {
            system_device: system_device.trim_end_matches('\\').to_ascii_lowercase(),
        }
    }

    /// Classify a lower-cased NT path.
    pub fn classify(&self, p: &str) -> Option<ScopeKind> {
        if let Some(rest) = p.strip_prefix(r"\device\mup\") {
            return (!rest.is_empty()).then_some(ScopeKind::Network);
        }
        let dev_rest = p.strip_prefix(r"\device\")?;
        let i = dev_rest.find('\\')?;
        let dev = &p[..r"\device\".len() + i];
        let rest = &dev_rest[i..];
        if dev.starts_with(r"\device\harddiskvolumeshadowcopy") || rest.len() < 2 {
            return None;
        }
        if !self.system_device.is_empty() && dev == self.system_device {
            // \users\<name>\<documents|desktop|…|onedrive*>\…
            let r = rest.strip_prefix(r"\users\")?;
            let mut parts = r.splitn(3, '\\');
            let _user = parts.next()?;
            let top = parts.next()?;
            parts.next().filter(|s| !s.is_empty())?;
            return (USER_DATA_DIRS.contains(&top) || top.starts_with("onedrive"))
                .then_some(ScopeKind::UserData);
        }
        if !dev.starts_with(r"\device\harddiskvolume") && !dev.starts_with(r"\device\cdrom") {
            // Removable media show up as \Device\HarddiskVolumeN too; other
            // device kinds (named pipes, mailslots, …) are never in scope.
            return None;
        }
        if OTHER_VOLUME_EXCLUDES
            .iter()
            .any(|x| rest == *x || rest.starts_with(&format!("{x}\\")))
        {
            return None;
        }
        Some(ScopeKind::UserData)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Overwrite,
    NewFile,
    Rename,
    Delete,
}

#[derive(Debug, Clone)]
struct Op {
    ts: i64,
    kind: Kind,
    file: u64,
    dir: u64,
    net: bool,
    /// New extension when this op is an extension change.
    new_ext: Option<Box<str>>,
    /// File name for new files (ransom-note fan-out).
    new_name: Option<Box<str>>,
}

#[derive(Debug, Default)]
struct PidState {
    ops: VecDeque<Op>,
    last_emit: Option<i64>,
    last_emit_files: u32,
    samples: VecDeque<String>,
    canary_hits: Vec<String>,
    canary_pending: bool,
    last_ts: i64,
}

/// Summary for one process, ready to become an `Event`.
#[derive(Debug, Clone, PartialEq)]
pub struct AggEmit {
    pub ts: i64,
    pub pid: u32,
    /// Paths are lower-cased NT paths; the glue maps them to Win32.
    pub activity: FileActivity,
}

#[derive(Debug, Default)]
pub struct FileAgg {
    pub scope: FileScope,
    /// Lower-cased NT paths of planted ransomware canaries.
    canaries: HashSet<String>,
    pids: HashMap<u32, PidState>,
    file_objects: HashMap<(u32, u64), String>,
    total_ops: usize,
    /// Operations dropped by the caps (health counter).
    pub dropped: u64,
    /// Summaries produced.
    pub emitted: u64,
}

fn h64(s: &str) -> u64 {
    crate::regdiff::fnv1a(s.as_bytes())
}

impl FileAgg {
    pub fn new(scope: FileScope) -> Self {
        FileAgg {
            scope,
            ..Default::default()
        }
    }

    pub fn set_canaries(&mut self, nt_lower_paths: impl IntoIterator<Item = String>) {
        self.canaries = nt_lower_paths.into_iter().collect();
    }

    pub fn is_canary(&self, p: &str) -> bool {
        self.canaries.contains(p)
    }

    pub fn tracked_pids(&self) -> usize {
        self.pids.len()
    }

    fn remember_fo(&mut self, pid: u32, fo: u64, path: &str) {
        if fo == 0 {
            return;
        }
        if self.file_objects.len() >= MAX_FILE_OBJECTS {
            self.file_objects.clear();
        }
        self.file_objects.insert((pid, fo), path.to_string());
    }

    /// Kernel-File Create (12). `disposition` is `CreateOptions >> 24`.
    pub fn on_create(
        &mut self,
        ts: i64,
        pid: u32,
        fo: u64,
        path: &str,
        disposition: u32,
        is_dir: bool,
    ) -> Option<AggEmit> {
        if is_dir {
            return None;
        }
        let scope = self.scope.classify(path)?;
        self.remember_fo(pid, fo, path);
        match disposition {
            // FILE_SUPERSEDE, FILE_OVERWRITE, FILE_OVERWRITE_IF
            0 | 4 | 5 => self.record(ts, pid, Kind::Overwrite, path, None, scope),
            // FILE_CREATE
            2 => self.record(ts, pid, Kind::NewFile, path, None, scope),
            _ => None,
        }
    }

    /// Kernel-File CreateNewFile (30).
    pub fn on_create_new(&mut self, ts: i64, pid: u32, fo: u64, path: &str) -> Option<AggEmit> {
        let scope = self.scope.classify(path)?;
        self.remember_fo(pid, fo, path);
        self.record(ts, pid, Kind::NewFile, path, None, scope)
    }

    /// Kernel-File DeletePath (26).
    pub fn on_delete(&mut self, ts: i64, pid: u32, fo: u64, file_path: &str) -> Option<AggEmit> {
        let path = if file_path.is_empty() {
            self.file_objects.get(&(pid, fo))?.clone()
        } else {
            file_path.to_string()
        };
        let scope = self.scope.classify(&path)?;
        self.record(ts, pid, Kind::Delete, &path, None, scope)
    }

    /// Kernel-File RenamePath (27).
    pub fn on_rename(&mut self, ts: i64, pid: u32, fo: u64, file_path: &str) -> Option<AggEmit> {
        let known = self.file_objects.get(&(pid, fo)).cloned();
        let (old, new) = match known {
            Some(o) if !file_path.is_empty() && o != file_path => (Some(o), file_path.to_string()),
            Some(o) => (None, o),
            None if !file_path.is_empty() => (None, file_path.to_string()),
            None => return None,
        };
        // In scope when either side is (moving data out of / into user folders).
        let scope = self
            .scope
            .classify(&new)
            .or_else(|| old.as_deref().and_then(|o| self.scope.classify(o)))?;
        if old.is_some() {
            self.remember_fo(pid, fo, &new);
        }
        self.record(ts, pid, Kind::Rename, &new, old.as_deref(), scope)
    }

    fn record(
        &mut self,
        ts: i64,
        pid: u32,
        kind: Kind,
        path: &str,
        old: Option<&str>,
        scope: ScopeKind,
    ) -> Option<AggEmit> {
        let name = file_name(path);
        let canary = self.canaries.contains(path) || old.is_some_and(|o| self.canaries.contains(o));
        let new_ext = match kind {
            Kind::Rename => {
                let ne = ext_of(name);
                let changed = match old.map(file_name).map(ext_of) {
                    Some(oe) => ne != oe && ne.is_some_and(|e| !is_known_ext(e)),
                    None => is_appended_unknown_ext(name),
                };
                changed.then(|| ne.unwrap_or_default().into())
            }
            Kind::NewFile => {
                is_appended_unknown_ext(name).then(|| ext_of(name).unwrap_or_default().into())
            }
            _ => None,
        };
        if !self.pids.contains_key(&pid) && self.pids.len() >= MAX_PIDS {
            self.evict(ts);
            if self.pids.len() >= MAX_PIDS {
                self.dropped += 1;
                return None;
            }
        }
        if self.total_ops >= MAX_TOTAL_OPS && !canary {
            self.gc(ts);
            if self.total_ops >= MAX_TOTAL_OPS {
                self.dropped += 1;
                return None;
            }
        }
        let st = self.pids.entry(pid).or_default();
        st.last_ts = ts;
        // Slide the window.
        while st.ops.front().is_some_and(|o| ts - o.ts > WINDOW_MS) {
            st.ops.pop_front();
            self.total_ops -= 1;
        }
        if st.ops.len() >= MAX_OPS_PER_PID {
            st.ops.pop_front();
            self.total_ops -= 1;
            self.dropped += 1;
        }
        st.ops.push_back(Op {
            ts,
            kind,
            file: h64(old.unwrap_or(path)),
            dir: h64(parent(path)),
            net: scope == ScopeKind::Network,
            new_ext,
            new_name: (kind == Kind::NewFile).then(|| name.into()),
        });
        self.total_ops += 1;
        if !st.samples.iter().any(|s| s == path) {
            if st.samples.len() >= 5 {
                st.samples.pop_front();
            }
            st.samples.push_back(path.to_string());
        }
        if canary {
            let hit = old
                .filter(|o| self.canaries.contains(*o))
                .unwrap_or(path)
                .to_string();
            if !st.canary_hits.contains(&hit) && st.canary_hits.len() < 32 {
                st.canary_hits.push(hit);
                st.canary_pending = true;
            }
        }
        let due = st.canary_pending
            || (st.ops.len() >= EMIT_MIN_FILES as usize
                && st.last_emit.is_none_or(|t| ts - t >= REEMIT_MS));
        if !due {
            return None;
        }
        let act = summarise(st);
        let emit = st.canary_pending
            || (act.files_touched >= EMIT_MIN_FILES && act.files_touched != st.last_emit_files);
        if !emit {
            return None;
        }
        st.canary_pending = false;
        st.last_emit = Some(ts);
        st.last_emit_files = act.files_touched;
        self.emitted += 1;
        Some(AggEmit {
            ts,
            pid,
            activity: act,
        })
    }

    /// A canary was modified in place (no rename / overwrite disposition):
    /// produce a summary for `pid` (the last process that opened it).
    pub fn canary_modified(&mut self, ts: i64, pid: u32, path: &str) -> AggEmit {
        let st = self.pids.entry(pid).or_default();
        if !st.canary_hits.iter().any(|h| h == path) && st.canary_hits.len() < 32 {
            st.canary_hits.push(path.to_string());
        }
        let mut act = summarise(st);
        act.canary_hits = st.canary_hits.clone();
        self.emitted += 1;
        AggEmit {
            ts,
            pid,
            activity: act,
        }
    }

    /// Forget idle processes (no op for 30 s) and stale window entries.
    pub fn gc(&mut self, now: i64) {
        let mut freed = 0usize;
        self.pids.retain(|_, st| {
            while st.ops.front().is_some_and(|o| now - o.ts > WINDOW_MS) {
                st.ops.pop_front();
                freed += 1;
            }
            let keep = now - st.last_ts < 30_000 || !st.ops.is_empty();
            if !keep {
                freed += st.ops.len();
            }
            keep
        });
        self.total_ops = self.total_ops.saturating_sub(freed);
    }

    fn evict(&mut self, now: i64) {
        self.gc(now);
        if self.pids.len() < MAX_PIDS {
            return;
        }
        if let Some((&pid, _)) = self.pids.iter().min_by_key(|(_, s)| s.last_ts) {
            if let Some(st) = self.pids.remove(&pid) {
                self.total_ops = self.total_ops.saturating_sub(st.ops.len());
            }
        }
    }

    pub fn forget_pid(&mut self, pid: u32) {
        if let Some(st) = self.pids.remove(&pid) {
            self.total_ops = self.total_ops.saturating_sub(st.ops.len());
        }
        self.file_objects.retain(|(p, _), _| *p != pid);
    }
}

fn summarise(st: &PidState) -> FileActivity {
    let mut files = HashSet::new();
    let mut dirs = HashSet::new();
    let (mut renames, mut overwrites, mut news, mut deletes, mut net) = (
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
        HashSet::new(),
    );
    let mut ext_files: HashMap<u64, &str> = HashMap::new();
    let mut note_dirs: HashMap<&str, HashSet<u64>> = HashMap::new();
    let first = st.ops.front().map(|o| o.ts).unwrap_or(0);
    let last = st.ops.back().map(|o| o.ts).unwrap_or(0);
    for o in &st.ops {
        files.insert(o.file);
        dirs.insert(o.dir);
        if o.net {
            net.insert(o.file);
        }
        match o.kind {
            Kind::Rename => {
                renames.insert(o.file);
            }
            Kind::Overwrite => {
                overwrites.insert(o.file);
            }
            Kind::NewFile => {
                news.insert(o.file);
            }
            Kind::Delete => {
                deletes.insert(o.file);
            }
        }
        if let Some(e) = o.new_ext.as_deref() {
            ext_files.insert(o.file, e);
        }
        if let Some(n) = o.new_name.as_deref() {
            if note_dirs.len() < 512 || note_dirs.contains_key(n) {
                note_dirs.entry(n).or_default().insert(o.dir);
            }
        }
    }
    let mut ext_count: HashMap<&str, u32> = HashMap::new();
    for e in ext_files.values() {
        *ext_count.entry(e).or_default() += 1;
    }
    let ext_changes = ext_files.len() as u32;
    let top = ext_count
        .iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.cmp(a.0)))
        .map(|(e, c)| (e.to_string(), *c));
    let note = note_dirs
        .iter()
        .map(|(n, d)| (*n, d.len() as u32))
        .filter(|(_, d)| *d >= NOTE_MIN_DIRS)
        .max_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(a.0)));
    FileActivity {
        window_ms: (last - first).clamp(0, WINDOW_MS) as u64,
        files_touched: files.len() as u32,
        dirs: dirs.len() as u32,
        renames: renames.len() as u32,
        ext_changes,
        overwrites: overwrites.len() as u32,
        new_files: news.len() as u32,
        deletes: deletes.len() as u32,
        net_paths: net.len() as u32,
        top_new_ext: top.as_ref().map(|(e, _)| e.clone()),
        top_ext_pct: match (&top, ext_changes) {
            (Some((_, c)), n) if n > 0 => ((*c as u64 * 100) / n as u64) as u8,
            _ => 0,
        },
        note_name: note.map(|(n, _)| n.to_string()),
        note_dirs: note.map(|(_, d)| d).unwrap_or(0),
        canary_hits: st.canary_hits.clone(),
        sample_paths: st.samples.iter().cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = r"\device\harddiskvolume3";

    fn agg() -> FileAgg {
        FileAgg::new(FileScope::new(r"\Device\HarddiskVolume3"))
    }

    fn doc(i: usize, dir: usize) -> String {
        format!(r"{DEV}\users\labuser\documents\d{dir}\file{i}.docx")
    }

    #[test]
    fn scope() {
        let s = FileScope::new(r"\Device\HarddiskVolume3");
        assert_eq!(s.classify(&doc(1, 1)), Some(ScopeKind::UserData));
        assert_eq!(
            s.classify(r"\device\harddiskvolume3\users\labuser\onedrive - contoso\x.xlsx"),
            Some(ScopeKind::UserData)
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolume3\users\labuser\appdata\local\temp\x.tmp"),
            None
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolume3\users\labuser\documents"),
            None
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolume3\windows\system32\x.dll"),
            None
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolume7\projects\a.docx"),
            Some(ScopeKind::UserData)
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolume7\$recycle.bin\s-1\x"),
            None
        );
        assert_eq!(s.classify(r"\device\harddiskvolume7\windows\x"), None);
        assert_eq!(
            s.classify(r"\device\mup\srv\share\a.docx"),
            Some(ScopeKind::Network)
        );
        assert_eq!(
            s.classify(r"\device\harddiskvolumeshadowcopy1\users\a\documents\x"),
            None
        );
        assert_eq!(s.classify(r"\device\namedpipe\x"), None);
    }

    #[test]
    fn extensions() {
        assert_eq!(ext_of("a.docx"), Some("docx"));
        assert_eq!(ext_of(".gitignore"), None);
        assert_eq!(ext_of("noext"), None);
        assert!(is_appended_unknown_ext("report.docx.k3str"));
        assert!(!is_appended_unknown_ext("report.docx"));
        assert!(!is_appended_unknown_ext("report.k3str"));
        assert!(!is_appended_unknown_ext("archive.tar.gz"));
    }

    #[test]
    fn mass_rename_emits_with_top_ext() {
        let mut a = agg();
        let mut out = Vec::new();
        for i in 0..40 {
            let ts = 1_000 + i as i64 * 100;
            let old = doc(i, i % 4);
            assert!(a
                .on_create(ts, 77, 0x1000 + i as u64, &old, 1, false)
                .is_none());
            // FilePath = new name (target semantics)
            if let Some(e) = a.on_rename(ts + 1, 77, 0x1000 + i as u64, &format!("{old}.k3str")) {
                out.push(e);
            }
        }
        assert!(!out.is_empty());
        let first = &out[0].activity;
        assert_eq!(first.files_touched, 10);
        assert_eq!(first.renames, 10);
        assert_eq!(first.ext_changes, 10);
        assert_eq!(first.top_new_ext.as_deref(), Some("k3str"));
        assert_eq!(first.top_ext_pct, 100);
        assert_eq!(first.dirs, 4);
        assert!(first.sample_paths.len() <= 5);
        // Re-emission is rate-limited to every 2 s and only while growing.
        for w in out.windows(2) {
            assert!(w[1].ts - w[0].ts >= REEMIT_MS);
            assert!(w[1].activity.files_touched > w[0].activity.files_touched);
        }
        let last = &out.last().unwrap().activity;
        assert!(last.files_touched > 10);
    }

    #[test]
    fn rename_with_source_semantics_still_counts() {
        // If FilePath turned out to be the *old* name (== FileObject path),
        // the new name is unknown; appended-extension detection then needs
        // the name itself. Renames are counted either way.
        let mut a = agg();
        let mut got = None;
        for i in 0..12 {
            let p = doc(i, 0);
            a.on_create(i as i64, 5, i as u64 + 1, &p, 1, false);
            got = a.on_rename(i as i64, 5, i as u64 + 1, &p).or(got);
        }
        let act = got.unwrap().activity;
        assert_eq!(act.renames, 10);
        assert_eq!(act.ext_changes, 0);
    }

    #[test]
    fn office_save_is_not_an_ext_change() {
        let mut a = agg();
        let p = doc(1, 0);
        a.on_create(0, 9, 1, &p, 1, false);
        a.on_rename(
            1,
            9,
            1,
            &format!(r"{DEV}\users\labuser\documents\d0\~wrl0001.tmp"),
        );
        a.on_create(
            2,
            9,
            2,
            &format!(r"{DEV}\users\labuser\documents\d0\~wrd0002.tmp"),
            2,
            false,
        );
        a.on_rename(3, 9, 2, &p);
        let e = a.canary_modified(4, 9, "x");
        assert_eq!(e.activity.ext_changes, 0);
        assert_eq!(e.activity.renames, 2);
    }

    #[test]
    fn below_threshold_and_out_of_scope_are_silent() {
        let mut a = agg();
        for i in 0..9 {
            assert!(a
                .on_create(i, 1, i as u64, &doc(i as usize, 0), 5, false)
                .is_none());
        }
        for i in 0..50 {
            let p = format!(r"{DEV}\users\labuser\appdata\local\temp\t{i}.tmp");
            assert!(a
                .on_create(100 + i, 1, 100 + i as u64, &p, 5, false)
                .is_none());
        }
        // Directory opens are ignored.
        assert!(a.on_create(200, 1, 999, &doc(99, 0), 2, true).is_none());
    }

    #[test]
    fn window_slides() {
        let mut a = agg();
        for i in 0..9 {
            a.on_create(i, 3, 0, &doc(i as usize, 0), 5, false);
        }
        // 11 s later: the earlier 9 ops left the window, so one more is not enough.
        assert!(a.on_create(11_000, 3, 0, &doc(50, 0), 5, false).is_none());
    }

    #[test]
    fn canary_hit_emits_immediately() {
        let mut a = agg();
        let c = format!(r"{DEV}\users\labuser\documents\!payroll 2026-q3.xlsx");
        a.set_canaries([c.clone()]);
        a.on_create(0, 42, 7, &c, 1, false);
        let e = a
            .on_rename(1, 42, 7, &format!("{c}.locked"))
            .expect("canary emit");
        assert_eq!(e.activity.canary_hits, vec![c.clone()]);
        assert_eq!(e.pid, 42);
        // Same canary again: no new immediate emit.
        assert!(a.on_delete(2, 42, 7, &format!("{c}.locked")).is_none());
        // Overwrite of the canary by another process.
        let e2 = a.on_create(3, 43, 8, &c, 5, false).unwrap();
        assert_eq!(e2.activity.canary_hits.len(), 1);
        assert_eq!(a.canary_modified(4, 44, &c).activity.canary_hits, vec![c]);
    }

    #[test]
    fn ransom_note_fanout() {
        let mut a = agg();
        for d in 0..6 {
            let p = format!(r"{DEV}\users\labuser\documents\d{d}\readme_restore.txt");
            a.on_create_new(d as i64 * 10, 8, 0, &p);
            for i in 0..3 {
                a.on_create(d as i64 * 10 + 1, 8, 0, &doc(d * 10 + i, d), 0, false);
            }
        }
        let act = a.canary_modified(100, 8, "x").activity;
        assert_eq!(act.note_name.as_deref(), Some("readme_restore.txt"));
        assert_eq!(act.note_dirs, 6);
        assert_eq!(act.new_files, 6);
        assert!(act.overwrites >= 10);
    }

    #[test]
    fn caps_and_gc() {
        let mut a = agg();
        for pid in 0..(MAX_PIDS as u32 + 20) {
            a.on_create(pid as i64, pid + 10, 0, &doc(1, 0), 5, false);
        }
        assert!(a.tracked_pids() <= MAX_PIDS);
        a.gc(1_000_000);
        assert_eq!(a.tracked_pids(), 0);
        assert_eq!(a.total_ops, 0);
        // A process with a huge burst stays bounded.
        for i in 0..(MAX_OPS_PER_PID + 100) {
            a.on_create(1, 1, 0, &doc(i, 0), 5, false);
        }
        assert!(a.total_ops <= MAX_OPS_PER_PID);
        assert!(a.dropped >= 100);
        a.forget_pid(1);
        assert_eq!(a.total_ops, 0);
    }

    #[test]
    fn delete_resolves_path_from_file_object() {
        let mut a = agg();
        a.on_create(0, 2, 55, &doc(1, 0), 1, false);
        for i in 0..9 {
            a.on_create(1, 2, 0, &doc(i + 10, 0), 5, false);
        }
        let e = a.on_delete(3_000, 2, 55, "").unwrap();
        assert_eq!(e.activity.deletes, 1);
        assert!(a.on_delete(3_000, 2, 12345, "").is_none());
    }
}
