//! Genuine browsers and password managers (Program Files installs only) and
//! the narrow, per-rule ownership decisions built on them.
//!
//! Lab finding 2026-10-21: Microsoft Edge's built-in "import from Chrome"
//! opened a file inside a decoy Chrome profile Kestrel had planted; ST-16
//! (Protect) killed the whole Edge tree and blocked Edge's network for 24 h.
//!
//! Uses (and nothing else):
//! * ST-16 ([`importer`]): a decoy read by one of these applications is an
//!   **Audit** alert without actions (a possible import);
//! * ST-01 / ST-03 ([`browser_store_owner`], soak 2026-10-21): a validly
//!   signed image in a browser's own Program Files install tree owns that
//!   browser's stores (updater / elevation / WebView helpers);
//! * ST-01 ([`wam_client_reader`], soak 2026-10-21): Microsoft-signed
//!   Program Files apps read the Windows token broker (WAM) cache.
//!
//! It is **not** a general "never kill" list: every rule still responds to
//! these processes (a global exemption keyed on signature + path was tried
//! and withdrawn after hostile review — Electron hosts run arbitrary JS,
//! per-user folders are writable, injected browsers would survive; see
//! `docs/DECISIONS.md`).
//!
//! A process qualifies as an importer only when **all** of these hold
//! ([`importer`]):
//! 1. its image file name is listed for the application;
//! 2. its image is in one of the application's install folders under
//!    `Program Files` / `Program Files (x86)` **on the system volume**
//!    (admin-only locations; per-user installs under `%LOCALAPPDATA%` /
//!    `%APPDATA%` never qualify);
//! 3. its Authenticode signature is **valid** (`Unknown` never counts) and
//!    the signer display name (certificate subject CN) is exactly one of the
//!    application's signers;
//! 4. its command line carries no remote-control / developer switch
//!    ([`remote_control_switch`]: `headless`, `remote-debugging-*`,
//!    `remote-allow-origins`, `load-extension`, `disable-extensions-except`,
//!    `inspect`, `inspect-brk` (not `inspect-port`), `marionette`, `start-debugger-server`, with any of the
//!    `--` / `-` / `/` prefixes Chromium and Firefox accept on Windows) and
//!    no `user-data-dir` outside the browser's own default data folder;
//! 5. it has not been the target of a cross-process injection / memory-write
//!    / thread-context / debugger signal in its lifetime (the caller passes
//!    that; the engine records it from ST-07's inputs).

use crate::paths::glob_match_path;
use kestrel_common::{PathClass, ProcessInfo, SignatureState};

/// What kind of application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    Browser,
    PasswordManager,
}

/// One genuine browser / password manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownApp {
    /// Display name, e.g. "Microsoft Edge".
    pub name: &'static str,
    /// Vendor shown in alerts, e.g. "Microsoft".
    pub vendor: &'static str,
    pub kind: AppKind,
    /// Image file names (lower-case, exact).
    pub images: &'static [&'static str],
    /// Authenticode signer subject CNs (lower-case, exact match after trim).
    pub signers: &'static [&'static str],
    /// Install directories (lower-case, trailing `\`) relative to
    /// `\program files` and `\program files (x86)` on the system volume;
    /// `*` = within one path segment.
    pub dirs: &'static [&'static str],
    /// The browser's own default profile folders (lower-case, driveless
    /// substrings): a `user-data-dir` pointing anywhere else disqualifies.
    pub data_dirs: &'static [&'static str],
    /// Signer subject checked on a real install (Kestrel dev host,
    /// 2026-10-21, `Get-AuthenticodeSignature`). `false` = taken from the
    /// vendor's published signing identity, not checked on a binary yet.
    pub signer_verified: bool,
}

/// The table: browsers and password managers with an import feature.
pub const KNOWN_APPS: &[KnownApp] = &[
    KnownApp {
        name: "Microsoft Edge",
        vendor: "Microsoft",
        kind: AppKind::Browser,
        images: &["msedge.exe"],
        signers: &["microsoft corporation"],
        dirs: &[
            r"\microsoft\edge\application\",
            r"\microsoft\edge beta\application\",
            r"\microsoft\edge dev\application\",
        ],
        data_dirs: &[
            r"\appdata\local\microsoft\edge\user data",
            r"\appdata\local\microsoft\edge beta\user data",
            r"\appdata\local\microsoft\edge dev\user data",
        ],
        signer_verified: true,
    },
    KnownApp {
        name: "Google Chrome",
        vendor: "Google",
        kind: AppKind::Browser,
        images: &["chrome.exe"],
        signers: &["google llc"],
        dirs: &[
            r"\google\chrome\application\",
            r"\google\chrome beta\application\",
            r"\google\chrome dev\application\",
        ],
        data_dirs: &[
            r"\appdata\local\google\chrome\user data",
            r"\appdata\local\google\chrome beta\user data",
            r"\appdata\local\google\chrome dev\user data",
        ],
        signer_verified: true,
    },
    KnownApp {
        name: "Mozilla Firefox",
        vendor: "Mozilla",
        kind: AppKind::Browser,
        images: &["firefox.exe"],
        signers: &["mozilla corporation"],
        dirs: &[
            r"\mozilla firefox\",
            r"\firefox developer edition\",
            r"\firefox nightly\",
        ],
        data_dirs: &[],
        signer_verified: true,
    },
    KnownApp {
        name: "Brave",
        vendor: "Brave Software",
        kind: AppKind::Browser,
        images: &["brave.exe"],
        signers: &["brave software, inc."],
        dirs: &[
            r"\bravesoftware\brave-browser\application\",
            r"\bravesoftware\brave-browser-beta\application\",
        ],
        data_dirs: &[
            r"\appdata\local\bravesoftware\brave-browser\user data",
            r"\appdata\local\bravesoftware\brave-browser-beta\user data",
        ],
        signer_verified: true,
    },
    KnownApp {
        name: "Opera",
        vendor: "Opera",
        kind: AppKind::Browser,
        images: &["opera.exe"],
        // Unverified on a binary: Opera's published code-signing identity.
        signers: &["opera norway as"],
        dirs: &[r"\opera\", r"\opera\*\"],
        data_dirs: &[
            r"\appdata\roaming\opera software\opera stable",
            r"\appdata\roaming\opera software\opera gx stable",
        ],
        signer_verified: false,
    },
    KnownApp {
        name: "Vivaldi",
        vendor: "Vivaldi Technologies",
        kind: AppKind::Browser,
        images: &["vivaldi.exe"],
        // Unverified on a binary.
        signers: &["vivaldi technologies as"],
        dirs: &[r"\vivaldi\application\"],
        data_dirs: &[r"\appdata\local\vivaldi\user data"],
        signer_verified: false,
    },
    KnownApp {
        name: "Bitwarden",
        vendor: "Bitwarden",
        kind: AppKind::PasswordManager,
        images: &["bitwarden.exe"],
        // Unverified on a binary ("8bit Solutions LLC" = the pre-2022 name).
        signers: &["bitwarden inc.", "8bit solutions llc"],
        dirs: &[r"\bitwarden\"],
        data_dirs: &[],
        signer_verified: false,
    },
    KnownApp {
        name: "1Password",
        vendor: "AgileBits",
        kind: AppKind::PasswordManager,
        images: &["1password.exe"],
        // Unverified on a binary.
        signers: &["agilebits inc."],
        dirs: &[r"\1password\app\8\"],
        data_dirs: &[],
        signer_verified: false,
    },
    KnownApp {
        name: "KeePass",
        vendor: "Dominik Reichl",
        kind: AppKind::PasswordManager,
        images: &["keepass.exe"],
        // Unverified on a binary: KeePass 2.x releases are signed by the author.
        signers: &["dominik reichl"],
        dirs: &[r"\keepass password safe 2\"],
        data_dirs: &[],
        signer_verified: false,
    },
    KnownApp {
        name: "KeePassXC",
        vendor: "KeePassXC",
        kind: AppKind::PasswordManager,
        images: &["keepassxc.exe"],
        // Unverified on a binary.
        signers: &["droidmonkey apps, llc"],
        dirs: &[r"\keepassxc\"],
        data_dirs: &[],
        signer_verified: false,
    },
];

/// Soak 2026-10-21 (ST-01/ST-04 on Chrome's `os_update_handler.exe`): the
/// browser's own **install tree** under Program Files, per [`KNOWN_APPS`]
/// browser name: (image path patterns relative to `\program files` /
/// `\program files (x86)`, `**` = any depth; store labels it owns — the
/// `SensitiveStore::app` of [`crate::paths`], exact or followed by a space,
/// e.g. "Chrome" owns "Chrome Beta" but not "Chromium").
/// A validly signed image of that vendor anywhere in this tree (the browser
/// itself, `elevation_service.exe`, `os_update_handler.exe`,
/// `chrome_proxy.exe`, `identity_helper.exe`, `msedgewebview2.exe`, …) is
/// an owner of that browser's own stores, never of another browser's.
pub const BROWSER_INSTALL_TREES: &[(&str, &[&str], &[&str])] = &[
    (
        "Microsoft Edge",
        &[
            r"\microsoft\edge\application\**",
            r"\microsoft\edge beta\application\**",
            r"\microsoft\edge dev\application\**",
            r"\microsoft\edgewebview\application\**",
        ],
        &["Edge"],
    ),
    (
        "Google Chrome",
        &[
            r"\google\chrome\application\**",
            r"\google\chrome beta\application\**",
            r"\google\chrome dev\application\**",
        ],
        &["Chrome"],
    ),
    (
        "Mozilla Firefox",
        &[
            r"\mozilla firefox\**",
            r"\firefox developer edition\**",
            r"\firefox nightly\**",
        ],
        &["Firefox"],
    ),
    (
        "Brave",
        &[
            r"\bravesoftware\brave-browser\application\**",
            r"\bravesoftware\brave-browser-beta\application\**",
        ],
        &["Brave"],
    ),
    ("Opera", &[r"\opera\**"], &["Opera"]),
    ("Vivaldi", &[r"\vivaldi\application\**"], &["Vivaldi"]),
];

/// Driveless rest of `image` below `\program files` / `\program files (x86)`
/// on the system volume (`None` elsewhere, or with a `..` component).
fn program_files_rest(image: &str, system_drive: char) -> Option<String> {
    if PathClass::of_with_system_drive(image, system_drive) != PathClass::ProgramFiles {
        return None;
    }
    let rest = crate::protect::on_system_volume(image, system_drive)?;
    if rest.split('\\').any(|c| c == "..") {
        return None;
    }
    rest.strip_prefix(r"\program files (x86)")
        .or_else(|| rest.strip_prefix(r"\program files"))
        .map(str::to_string)
}

/// Is `image` under `Program Files` / `Program Files (x86)` (incl.
/// `WindowsApps`) on the system volume?
pub fn in_program_files(image: &str, system_drive: char) -> bool {
    program_files_rest(image, system_drive).is_some()
}

/// Is `p` an owner of the browser store labelled `store_app` because it is
/// part of that browser's own Program Files install (valid signature by the
/// browser vendor, no remote-control / dev switches, not injected into)?
pub fn browser_store_owner(
    p: &ProcessInfo,
    store_app: &str,
    system_drive: char,
    tampered: bool,
) -> Option<&'static KnownApp> {
    if tampered || p.signed != SignatureState::Valid {
        return None;
    }
    let sub = program_files_rest(&p.image, system_drive)?;
    let name = sub.rsplit('\\').next().unwrap_or("");
    if name.is_empty() || crate::engine::is_lolbin(name) {
        return None;
    }
    let owns = |labels: &[&str]| {
        labels
            .iter()
            .any(|l| store_app == *l || store_app.starts_with(&format!("{l} ")))
    };
    let (app_name, _, _) = BROWSER_INSTALL_TREES.iter().find(|(_, trees, labels)| {
        owns(labels) && trees.iter().any(|t| glob_match_path(t, &sub))
    })?;
    let app = KNOWN_APPS.iter().find(|a| a.name == *app_name)?;
    if !signer_ok(app, p.signer.as_deref())
        || remote_control_switch(&p.cmdline, Some(app)).is_some()
    {
        return None;
    }
    Some(app)
}

/// Soak 2026-10-21 (ST-01/ST-04 on VS Code reading the WAM cache; Windows
/// Widgets in the fresh-install lab run): a Microsoft-signed application
/// ([`WAM_CLIENT_SIGNERS`]) in Program Files / WindowsApps reading the
/// **Windows token broker (WAM) SSO cache** is a WAM client, not a thief.
/// Only that store; never a LOLBin / script host; never an instance that
/// runs a script (`.js` / `.mjs` / `.cjs` argument, `cli.js`, `--inspect` / `--inspect-brk`
/// — the `ELECTRON_RUN_AS_NODE` pattern, whose environment variable the
/// sensor cannot see) or carries remote-control switches.
pub fn wam_client_reader(p: &ProcessInfo, store_app: &str, system_drive: char) -> bool {
    if store_app != "Windows token broker"
        || p.signed != SignatureState::Valid
        || !p.signer.as_deref().is_some_and(|s| {
            WAM_CLIENT_SIGNERS
                .iter()
                .any(|w| s.trim().eq_ignore_ascii_case(w))
        })
    {
        return false;
    }
    let Some(sub) = program_files_rest(&p.image, system_drive) else {
        return false;
    };
    let name = sub.rsplit('\\').next().unwrap_or("").to_string();
    if name.is_empty()
        || crate::engine::is_lolbin(&name)
        || SCRIPT_HOSTS.contains(&name.as_str())
        || MACRO_HOSTS.contains(&name.as_str())
    {
        return false;
    }
    if runs_script(&p.cmdline) || is_remote_controlled(&p.cmdline) || has_eval_switch(&p.cmdline) {
        return false;
    }
    // Electron images can run as Node (`ELECTRON_RUN_AS_NODE`, invisible
    // here) on any file: only the plain app launch (switches, no
    // positional argument) counts.
    !(ELECTRON_HOSTS.contains(&name.as_str()) && !positional_args(&p.cmdline).is_empty())
}

/// Signer subject CNs (as the enrichment reports them:
/// `CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)`) of WAM clients.
/// "Microsoft Corporation" signs Microsoft's own applications (Office, VS
/// Code, Teams); "Microsoft Windows" signs Windows inbox components,
/// including the ones Windows ships as packages under `WindowsApps` (lab
/// 2026-10-21: `MicrosoftWindows.Client.WebExperience_*\Dashboard\Widgets.exe`,
/// embedded Authenticode, `CN=Microsoft Windows`). Exact match only:
/// "Microsoft Windows Publisher" and look-alikes do not qualify. Inbox
/// images in System32 / Windows never reach this check (they are
/// [`crate::engine`] `system_trusted` unless LOLBins).
pub const WAM_CLIENT_SIGNERS: &[&str] = &["microsoft corporation", "microsoft windows"];

/// Re-review N2: .NET and script REPL hosts run arbitrary code without a
/// script-file argument: never WAM-client readers. (Office apps are WAM
/// clients: their token-cache reads are recorded and alerted Low / Audit,
/// never silent, and ST-04 escalates as soon as anything else is read.)
pub(crate) const MACRO_HOSTS: &[&str] = &["dotnet.exe", "csi.exe", "fsi.exe", "dotnet-script.exe"];

/// Microsoft-signed Electron apps (can run as Node on any file).
const ELECTRON_HOSTS: &[&str] = &["code.exe", "code - insiders.exe", "azuredatastudio.exe"];

/// `-e` / `--eval` / `-p` / `--print` / a bare `-` (script on stdin), any prefix.
pub fn has_eval_switch(cmdline: &str) -> bool {
    let c = cmdline.to_ascii_lowercase();
    c.split(|ch: char| ch.is_whitespace() || ch == '"')
        .any(|t| {
            let key = t.split('=').next().unwrap_or(t);
            matches!(
                key,
                "-" | "-e" | "--eval" | "-p" | "--print" | "/e" | "/p" | "-pe" | "-r" | "--require"
            )
        })
}

/// Positional (non-switch) arguments after the image.
pub fn positional_args(cmdline: &str) -> Vec<String> {
    let t = cmdline.trim();
    // Skip the image: quoted or up to the first whitespace.
    let rest = if let Some(r) = t.strip_prefix('"') {
        r.split_once('"').map(|x| x.1).unwrap_or("")
    } else {
        t.split_once(char::is_whitespace).map(|x| x.1).unwrap_or("")
    };
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in rest.chars().chain(std::iter::once(' ')) {
        match ch {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !cur.is_empty() && !cur.starts_with('-') && !cur.starts_with('/') {
                    out.push(std::mem::take(&mut cur));
                }
                cur.clear();
            }
            c => cur.push(c),
        }
    }
    out
}

/// Script / runtime hosts that are never WAM-client exempt.
pub(crate) const SCRIPT_HOSTS: &[&str] = &[
    "node.exe",
    "python.exe",
    "pythonw.exe",
    "py.exe",
    "pwsh.exe",
    "powershell.exe",
    "wscript.exe",
    "cscript.exe",
    "java.exe",
    "javaw.exe",
    "deno.exe",
    "bun.exe",
];

/// Does the command line run a script (a `.js` / `.mjs` / `.cjs` / `.ts`
/// argument or Electron's `cli.js`)?
pub fn runs_script(cmdline: &str) -> bool {
    let c = cmdline.to_ascii_lowercase();
    c.contains("cli.js")
        || c.split(|ch: char| ch.is_whitespace() || ch == '"' || ch == '=')
            .any(|t| {
                let t = t.trim_end_matches(['\'', ',']);
                [".js", ".mjs", ".cjs", ".ts"]
                    .iter()
                    .any(|x| t.ends_with(x))
            })
}

/// Switch names (prefix stripped, lower-case) that put a browser under
/// another program's control or load foreign code into it: the
/// cookie-theft instruments of ST-05 / ST-06 and Electron/Node debugging.
const REMOTE_CONTROL_SWITCHES: &[&str] = &[
    "headless",
    "remote-debugging-port",
    "remote-debugging-pipe",
    "remote-debugging-address",
    "remote-allow-origins",
    "load-extension",
    "disable-extensions-except",
    "inspect",
    "inspect-brk",
    // Not `inspect-port`: it only sets the port an inspector would use;
    // VS Code's NodeService utility runs with `--inspect-port=0` (lab
    // 2026-10-21). `--experimental-network-inspection` is not remote control.
    "marionette",
    "start-debugger-server",
];

/// Switches on a Windows command line: (name without its `--` / `-` / `/`
/// prefix, value after `=` if any). A switch starts at the beginning, after
/// whitespace or after a quote; a value in quotes (or a switch inside a
/// quoted token) runs to the closing quote.
pub(crate) fn switches(cmdline: &str) -> Vec<(String, Option<String>)> {
    let c = cmdline.to_ascii_lowercase();
    let b = c.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let at_start = i == 0 || b[i - 1].is_ascii_whitespace() || b[i - 1] == b'"';
        if !(at_start && (b[i] == b'-' || b[i] == b'/')) {
            i += 1;
            continue;
        }
        let quoted_token = i > 0 && b[i - 1] == b'"';
        let mut j = i;
        while j < b.len() && (b[j] == b'-' || b[j] == b'/') && j - i < 2 {
            j += 1;
        }
        let name_start = j;
        while j < b.len() && !b[j].is_ascii_whitespace() && b[j] != b'=' && b[j] != b'"' {
            j += 1;
        }
        let name = c[name_start..j].to_string();
        let mut value = None;
        if j < b.len() && b[j] == b'=' {
            j += 1;
            let (start, end_quote) = if j < b.len() && b[j] == b'"' {
                (j + 1, true)
            } else {
                (j, quoted_token)
            };
            let mut k = start;
            while k < b.len() && b[k] != b'"' && (end_quote || !b[k].is_ascii_whitespace()) {
                k += 1;
            }
            value = Some(c[start..k].to_string());
            j = k;
        }
        if !name.is_empty() {
            out.push((name, value));
        }
        i = j.max(i + 1);
    }
    out
}

/// The first remote-control / developer switch on `cmdline`, or a
/// `user-data-dir` outside `app`'s default profile folders (any
/// `user-data-dir` when `app` is `None` or has no default listed).
pub fn remote_control_switch(cmdline: &str, app: Option<&KnownApp>) -> Option<String> {
    for (name, value) in switches(cmdline) {
        if REMOTE_CONTROL_SWITCHES.contains(&name.as_str()) {
            return Some(name);
        }
        if name == "user-data-dir" {
            let v = value
                .map(|v| crate::paths::normalize_path(v.trim()))
                .unwrap_or_default();
            // Re-review N7: exactly `<drive>:\users\<one name><data dir>`
            // (optional trailing `\`), not a substring.
            let rest = crate::util::strip_drive(&v)
                .trim_end_matches('\\')
                .to_string();
            let own = app.is_some_and(|a| {
                rest.strip_prefix(r"\users\")
                    .and_then(|r| r.split_once('\\'))
                    .is_some_and(|(user, tail)| {
                        !user.is_empty()
                            && user != ".."
                            && a.data_dirs.iter().any(|d| format!("\\{tail}") == *d)
                    })
            });
            if !own {
                return Some(name);
            }
        }
    }
    None
}

/// Is this command line an instance under remote control (or with a
/// foreign profile folder)?
pub fn is_remote_controlled(cmdline: &str) -> bool {
    remote_control_switch(cmdline, None).is_some_and(|s| s != "user-data-dir")
}

/// The table entry whose image name *and* install folder match `image`
/// (location only — no signature check). Program Files on the system
/// volume only.
pub fn app_at_location(image: &str, system_drive: char) -> Option<&'static KnownApp> {
    if PathClass::of_with_system_drive(image, system_drive) != PathClass::ProgramFiles {
        return None;
    }
    let rest = crate::protect::on_system_volume(image, system_drive)?;
    if rest.split('\\').any(|c| c == "..") {
        return None;
    }
    let (dir, name) = rest.rsplit_once('\\')?;
    if name.is_empty() || crate::engine::is_lolbin(name) {
        return None;
    }
    let dir = format!("{dir}\\");
    let sub = dir
        .strip_prefix(r"\program files (x86)")
        .or_else(|| dir.strip_prefix(r"\program files"))?;
    if sub.starts_with(r"\windowsapps\") {
        // No table entry is an MSIX package today.
        return None;
    }
    KNOWN_APPS
        .iter()
        .find(|a| a.images.contains(&name) && a.dirs.iter().any(|d| glob_match_path(d, sub)))
}

/// Is `signer` one of `app`'s expected signer names (exact, case-insensitive)?
pub fn signer_ok(app: &KnownApp, signer: Option<&str>) -> bool {
    signer.is_some_and(|s| {
        let s = s.trim().to_ascii_lowercase();
        app.signers.iter().any(|x| *x == s)
    })
}

/// The application `image` is, given its signature facts: image name +
/// Program Files install folder on the system volume + a **valid**
/// signature by the expected signer. `None` otherwise.
pub fn known_app(
    image: &str,
    signed: SignatureState,
    signer: Option<&str>,
    system_drive: char,
) -> Option<&'static KnownApp> {
    if signed != SignatureState::Valid {
        return None;
    }
    app_at_location(image, system_drive).filter(|a| signer_ok(a, signer))
}

/// ST-16 importer check (all five conditions of the module docs).
/// `tampered`: the process was the target of an injection signal.
pub fn importer(p: &ProcessInfo, system_drive: char, tampered: bool) -> Option<&'static KnownApp> {
    if tampered {
        return None;
    }
    let app = known_app(&p.image, p.signed, p.signer.as_deref(), system_drive)?;
    if remote_control_switch(&p.cmdline, Some(app)).is_some() {
        return None;
    }
    Some(app)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SignatureState::*;

    const EDGE: &str = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe";
    const MS: Option<&str> = Some("Microsoft Corporation");

    fn proc_(image: &str, cmdline: &str, signer: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            guid: kestrel_common::ProcessGuid("p".into()),
            pid: 10,
            ppid: 1,
            parent_guid: None,
            image: image.into(),
            cmdline: cmdline.into(),
            user: None,
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: signer.map(Into::into),
            signed: Valid,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::of_with_system_drive(image, 'c'),
        }
    }

    #[test]
    fn genuine_program_files_installs_qualify() {
        assert_eq!(
            known_app(EDGE, Valid, MS, 'c').unwrap().name,
            "Microsoft Edge"
        );
        assert!(known_app(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            Valid,
            Some("Google LLC"),
            'c'
        )
        .is_some());
        assert!(known_app(
            r"\\?\C:\Program Files\Opera\112.0.5197.53\opera.exe",
            Valid,
            Some("Opera Norway AS"),
            'c'
        )
        .is_some());
        assert!(known_app(
            r"D:\Program Files\Mozilla Firefox\firefox.exe",
            Valid,
            Some("Mozilla Corporation"),
            'd'
        )
        .is_some());
    }

    #[test]
    fn look_alikes_and_per_user_installs_do_not_qualify() {
        for s in [Unsigned, Invalid, Unknown] {
            assert!(known_app(EDGE, s, MS, 'c').is_none());
        }
        assert!(known_app(EDGE, Valid, Some("Evil Ltd"), 'c').is_none());
        assert!(known_app(EDGE, Valid, Some("Microsoft Corporation Evil"), 'c').is_none());
        assert!(known_app(EDGE, Valid, None, 'c').is_none());
        for (p, signer) in [
            (r"C:\Users\alice\AppData\Local\Temp\msedge.exe", MS),
            (r"C:\Users\alice\Downloads\msedge.exe", MS),
            // per-user installs are user-writable: never
            (
                r"C:\Users\alice\AppData\Local\Google\Chrome\Application\chrome.exe",
                Some("Google LLC"),
            ),
            (
                r"C:\Users\alice\AppData\Local\Programs\Opera\opera.exe",
                Some("Opera Norway AS"),
            ),
            (
                r"C:\Users\alice\AppData\Local\Microsoft\Edge SxS\Application\msedge.exe",
                MS,
            ),
            (r"C:\ProgramData\Microsoft\Edge\Application\msedge.exe", MS),
            (
                r"C:\Program Files Evil\Microsoft\Edge\Application\msedge.exe",
                MS,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\sub\msedge.exe",
                MS,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\..\msedge.exe",
                MS,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\notedge.exe",
                MS,
            ),
            (
                r"E:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                MS,
            ),
            (
                r"\Device\HarddiskVolume9\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                MS,
            ),
            (
                r"\\server\share\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                MS,
            ),
            (
                r"C:\Program Files (x86)\Microsoft\Edge\Application\powershell.exe",
                MS,
            ),
            // removed from the table (no global exemption any more)
            (
                r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE",
                MS,
            ),
            (r"C:\Program Files\Microsoft VS Code\Code.exe", MS),
        ] {
            assert!(known_app(p, Valid, signer, 'c').is_none(), "{p}");
        }
    }

    #[test]
    fn remote_control_switches_with_every_prefix() {
        for c in [
            r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --remote-debugging-port=9223"#,
            "msedge.exe -headless",
            "msedge.exe /headless",
            "msedge.exe /remote-debugging-port=9222",
            "msedge.exe -remote-debugging-pipe",
            "msedge.exe -remote-allow-origins=*",
            r"msedge.exe --load-extension=C:\Users\a\AppData\Local\x",
            r#"msedge.exe "--load-extension=C:\Users\a\x y""#,
            "msedge.exe --disable-extensions-except=abc",
            "code.exe --inspect=9229 x.js",
            "code.exe --inspect-brk",
            "firefox.exe -marionette",
            "firefox.exe /marionette",
            "firefox.exe --start-debugger-server 6000",
        ] {
            assert!(is_remote_controlled(c), "{c}");
        }
        for c in [
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default"#,
            r#""C:\Program Files\Google\Chrome\Application\chrome.exe" --type=renderer /prefetch:1"#,
            "firefox.exe -url https://example.com/inspect",
            // VS Code's NodeService utility (lab 2026-10-21)
            r#""C:\Program Files\Microsoft VS Code\Code.exe" --type=utility --utility-sub-type=node.mojom.NodeService --lang=en-US --service-sandbox-type=none --dns-result-order=ipv4first --experimental-network-inspection --inspect-port=0 --user-data-dir="C:\Users\employee\AppData\Roaming\Code""#,
        ] {
            assert!(!is_remote_controlled(c), "{c}");
        }
    }

    #[test]
    fn user_data_dir_must_be_the_browsers_own() {
        let edge = known_app(EDGE, Valid, MS, 'c');
        assert_eq!(
            remote_control_switch(
                r"msedge.exe --user-data-dir=C:\Users\a\AppData\Local\Temp\x",
                edge
            )
            .as_deref(),
            Some("user-data-dir")
        );
        assert_eq!(
            remote_control_switch(
                r#"msedge.exe "--user-data-dir=C:\Users\a b\AppData\Local\Temp\x""#,
                edge
            )
            .as_deref(),
            Some("user-data-dir")
        );
        assert!(remote_control_switch(
            r#"msedge.exe --user-data-dir="C:\Users\a b\AppData\Local\Microsoft\Edge\User Data""#,
            edge
        )
        .is_none());
        assert!(remote_control_switch(
            r#"msedge.exe "--user-data-dir=C:\Users\a\AppData\Local\Microsoft\Edge\User Data\""#,
            edge
        )
        .is_none());
        // Re-review N7: exact path, not a substring.
        for c in [
            r"msedge.exe --user-data-dir=C:\Users\a\AppData\Local\Temp\x\AppData\Local\Microsoft\Edge\User Data",
            r"msedge.exe --user-data-dir=C:\Users\a\AppData\Local\Microsoft\Edge\User Data2",
            r"msedge.exe --user-data-dir=C:\Users\a\AppData\Local\Microsoft\Edge\User Data\sub",
            r"msedge.exe --user-data-dir=C:\Temp\Users\a\AppData\Local\Microsoft\Edge\User Data",
            r"msedge.exe --user-data-dir=C:\Users\..\AppData\Local\Microsoft\Edge\User Data",
        ] {
            assert_eq!(
                remote_control_switch(c, edge).as_deref(),
                Some("user-data-dir"),
                "{c}"
            );
        }
    }

    #[test]
    fn positional_and_eval_arguments() {
        assert!(positional_args(r#""C:\Program Files\Microsoft VS Code\Code.exe""#).is_empty());
        assert!(positional_args(
            r#""C:\Program Files\Microsoft VS Code\Code.exe" --new-window /x"#
        )
        .is_empty());
        assert_eq!(
            positional_args(r#""C:\Program Files\Microsoft VS Code\Code.exe" "C:\a b\p.dat" --x"#),
            [r"C:\a b\p.dat"]
        );
        assert_eq!(positional_args(r"Code.exe p.dat"), ["p.dat"]);
        for c in [
            "code.exe -e x",
            "code.exe --eval=x",
            "code.exe -p 1",
            "code.exe -",
            "node.exe -r x",
        ] {
            assert!(has_eval_switch(c), "{c}");
        }
        assert!(!has_eval_switch("code.exe --enable-features=x"));
    }

    #[test]
    fn importer_needs_everything() {
        let ok = proc_(EDGE, "msedge.exe --profile-directory=Default", MS);
        assert!(importer(&ok, 'c', false).is_some());
        assert!(importer(&ok, 'c', true).is_none(), "tampered");
        let hl = proc_(EDGE, "msedge.exe /headless", MS);
        assert!(importer(&hl, 'c', false).is_none());
        let pu = proc_(
            r"C:\Users\alice\AppData\Local\Google\Chrome\Application\chrome.exe",
            "chrome.exe",
            Some("Google LLC"),
        );
        assert!(importer(&pu, 'c', false).is_none());
    }

    #[test]
    fn table_shape() {
        for a in KNOWN_APPS {
            for i in a.images {
                assert!(!crate::engine::is_lolbin(i), "{i}");
                assert_eq!(*i, i.to_ascii_lowercase());
            }
            for s in a.signers {
                assert_eq!(*s, s.to_ascii_lowercase());
            }
            for d in a.dirs {
                assert!(d.starts_with('\\') && d.ends_with('\\'), "{d}");
                assert!(!d.contains("**") && !d.contains("users"), "{d}");
            }
        }
    }
}
