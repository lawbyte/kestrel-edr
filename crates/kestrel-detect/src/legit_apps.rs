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
//! * ST-01 / ST-04 ([`dev_tool_reader`], owner's PC 2026-10-22): validly
//!   signed, non-interpreter Program Files images read developer-tool
//!   credential stores (kubeconfig, Docker, cloud CLIs): Low Audit, recorded;
//! * ST-04 ([`vendor_backend`], same finding): when the send came from the
//!   reader's parent and that parent is the same vendor's signed Program
//!   Files backend, only the reader is stopped and nothing is blocked.
//!
//! It is **not** a general "never kill" list: every rule still responds to
//! these processes (a global exemption keyed on signature + path was tried
//! and withdrawn after hostile review â€” Electron hosts run arbitrary JS,
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
/// `\program files (x86)`, `**` = any depth; store labels it owns â€” the
/// `SensitiveStore::app` of [`crate::paths`], exact or followed by a space,
/// e.g. "Chrome" owns "Chrome Beta" but not "Chromium").
/// A validly signed image of that vendor anywhere in this tree (the browser
/// itself, `elevation_service.exe`, `os_update_handler.exe`,
/// `chrome_proxy.exe`, `identity_helper.exe`, `msedgewebview2.exe`, â€¦) is
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
pub(crate) fn program_files_rest(image: &str, system_drive: char) -> Option<String> {
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
/// â€” the `ELECTRON_RUN_AS_NODE` pattern, whose environment variable the
/// sensor cannot see) or carries remote-control switches.
pub fn wam_client_reader(
    p: &ProcessInfo,
    store_app: &str,
    system_drive: char,
    tampered: bool,
) -> bool {
    // Fix round 2026-10-25 (corpus `evasion_wam_to_attacker_onedrive_graph`,
    // `evasion_office_xll_wam_raw_ip`): an injected or side-loaded client
    // (remote thread into ms-teams.exe, an unsigned XLL in EXCEL.EXE) is not
    // a WAM client any more.
    if tampered
        || store_app != "Windows token broker"
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

/// Electron apps (can run as Node on any file with `ELECTRON_RUN_AS_NODE`,
/// which the sensor cannot see): only a plain launch without a positional
/// argument counts as the app itself. Microsoft-signed ones (WAM clients)
/// and the developer tools that read kubeconfig / Docker credentials.
const ELECTRON_HOSTS: &[&str] = &[
    "code.exe",
    "code - insiders.exe",
    "azuredatastudio.exe",
    "docker desktop.exe",
    "lens.exe",
    "openlens.exe",
    "rancher desktop.exe",
    "cursor.exe",
    "windsurf.exe",
    "postman.exe",
    "githubdesktop.exe",
];

/// Review of the 1.1.7 integration (2026-10-25, M3): Electron applications
/// that **own** a credential store (messengers, wallets, password managers).
/// A genuine, signed copy can still run attacker JavaScript as plain Node
/// (`ELECTRON_RUN_AS_NODE=1 Discord.exe C:\x\s.js`), and the environment
/// variable never reaches the sensor (a process start carries image,
/// command line, user, integrity, signature and parent only), so owner
/// status needs a plain launch ([`electron_runs_foreign_code`]) and a
/// trusted launcher (the engine's parent check).
const ELECTRON_OWNERS: &[&str] = &[
    "discord.exe",
    "discordptb.exe",
    "discordcanary.exe",
    "exodus.exe",
    "slack.exe",
    "ledger live.exe",
    "ledger wallet.exe",
    "bitwarden.exe",
    "1password.exe",
    "signal.exe",
    "element.exe",
    "atomic wallet.exe",
    "guarda.exe",
    "trezor suite.exe",
    "keeweb.exe",
    "teams.exe",
    "skype.exe",
    "whatsapp.exe",
    "mailspring.exe",
    "jaxx liberty.exe",
    "binance.exe",
];

/// Is the (lower-case) image file name an Electron application
/// ([`ELECTRON_OWNERS`] or the developer / Microsoft Electron hosts)?
pub fn is_electron_image(name_lower: &str) -> bool {
    ELECTRON_OWNERS.contains(&name_lower) || ELECTRON_HOSTS.contains(&name_lower)
}

/// Is the (lower-case) image file name a store-owning Electron application
/// ([`ELECTRON_OWNERS`]: messengers, wallets, password managers)?
pub fn is_electron_owner_image(name_lower: &str) -> bool {
    ELECTRON_OWNERS.contains(&name_lower)
}

/// A positional argument that is a protocol activation (`discord://…`,
/// `slack://…`), not a file Node could run. `file:` URLs are files.
fn is_protocol_activation(arg: &str) -> bool {
    let a = arg.trim().to_ascii_lowercase();
    a.contains("://") && !a.starts_with("file:")
}

/// Squirrel.Windows launcher switches whose value is the next token
/// (`Discord.exe --processStart Discord.exe --process-start-args
/// "--start-inactive"`, the stub every Squirrel app is started through).
const SQUIRREL_VALUE_SWITCHES: &[&str] =
    &["processstart", "processstartandwait", "process-start-args"];

/// Positional arguments of an Electron owner's command line: like
/// [`positional_args`], minus the values of [`SQUIRREL_VALUE_SWITCHES`],
/// protocol activations and the relaunch target of Electron's relauncher
/// (`Discord.exe --type=relauncher --no-sandbox --- "C:\…\Discord.exe"`,
/// owner's PC replay 2026-10: the app restarting itself after an update;
/// only the token right after `---` naming the same image is skipped).
fn owner_positional_args(name_lower: &str, cmdline: &str) -> Vec<String> {
    let t = cmdline.trim();
    let rest = if let Some(r) = t.strip_prefix('"') {
        r.split_once('"').map(|x| x.1).unwrap_or("")
    } else {
        t.split_once(char::is_whitespace).map(|x| x.1).unwrap_or("")
    };
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut any = false;
    for ch in rest.chars().chain(std::iter::once(' ')) {
        match ch {
            '"' => {
                quoted = !quoted;
                any = true;
            }
            c if c.is_whitespace() && !quoted => {
                if any || !cur.is_empty() {
                    tokens.push(std::mem::take(&mut cur));
                }
                any = false;
            }
            c => cur.push(c),
        }
    }
    let mut out = Vec::new();
    let mut skip_next = false;
    let mut relaunch_target = false;
    for tok in tokens {
        if skip_next {
            skip_next = false;
            continue;
        }
        if std::mem::take(&mut relaunch_target) {
            let file = tok.rsplit(['\\', '/']).next().unwrap_or("");
            if file.eq_ignore_ascii_case(name_lower) {
                continue;
            }
        }
        if tok == "---" {
            relaunch_target = true;
            continue;
        }
        if tok.starts_with('-') || tok.starts_with('/') {
            let key = tok.trim_start_matches(['-', '/']).to_ascii_lowercase();
            skip_next = !key.contains('=') && SQUIRREL_VALUE_SWITCHES.contains(&key.as_str());
            continue;
        }
        if !tok.is_empty() && !is_protocol_activation(&tok) {
            out.push(tok);
        }
    }
    out
}

/// Review 1.1.7 M3: does the command line of the Electron image `name_lower`
/// look like the app running someone else's code rather than itself?
/// Every Electron image: a script argument ([`runs_script`]), an eval /
/// print / require switch ([`has_eval_switch`]) or an inspector /
/// remote-control switch ([`is_remote_controlled`]). Store-owning apps
/// ([`ELECTRON_OWNERS`]) also: any positional argument other than a
/// protocol activation or a Squirrel launcher value (Node runs whatever
/// file it is given, with or without a `.js` extension). Developer hosts
/// (VS Code and friends) are not held to the positional rule: their own
/// extension hosts run as Node on bundled files with positional arguments
/// (`Code.exe "…\serverWorkerMain" --node-ipc`). Chromium child processes
/// (`--type=renderer --user-data-dir="…"`) and `--start-minimized` style
/// switches are plain. Non-Electron images: always `false`.
pub fn electron_runs_foreign_code(name_lower: &str, cmdline: &str) -> bool {
    if !is_electron_image(name_lower) {
        return false;
    }
    runs_script(cmdline)
        || has_eval_switch(cmdline)
        || is_remote_controlled(cmdline)
        || (is_electron_owner_image(name_lower)
            && !owner_positional_args(name_lower, cmdline).is_empty())
}

/// Owner's PC 2026-10-22 (Docker Desktop killed by ST-04): store labels
/// ([`crate::paths`] `SensitiveStore::app`) of **developer-tool credential
/// stores**. Many signed developer tools read them as part of normal work
/// (Docker Desktop, kubectl, Helm, Lens, VS Code, Rancher Desktop, cloud
/// CLIs, Terraform). Exactly these labels: AWS (`.aws\credentials`, SSO /
/// CLI cache), Azure CLI token cache, Google Cloud SDK credentials,
/// kubeconfig, Docker `config.json`. Not the WAM cache (own rule), not the
/// MSAL `.IdentityService` cache, Git / GitHub CLI / ngrok / Terraform
/// tokens, and never a browser, wallet, messenger or Windows credential
/// store.
pub const DEV_TOOL_STORES: &[&str] = &[
    "AWS",
    "Azure CLI",
    "Google Cloud SDK",
    "Kubernetes",
    "Docker",
];

/// Interpreters and script hosts beyond [`SCRIPT_HOSTS`] / [`MACRO_HOSTS`]
/// and the engine's LOLBin list: they run whatever code they are given, so
/// their signature says nothing about what read the store.
const MORE_INTERPRETERS: &[&str] = &[
    "ruby.exe",
    "rubyw.exe",
    "irb.exe",
    "perl.exe",
    "wperl.exe",
    "php.exe",
    "php-cgi.exe",
    "lua.exe",
    "luajit.exe",
    "rscript.exe",
    "r.exe",
    "julia.exe",
    "tclsh.exe",
    "wish.exe",
    "jshell.exe",
    "jrunscript.exe",
    "groovy.exe",
    "uv.exe",
    "uvx.exe",
    "ipython.exe",
    "jupyter.exe",
    "conda.exe",
    "mshta.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "rundll32.exe",
    "regsvr32.exe",
];

/// Interpreter / script host / .NET or script REPL / LOLBin by image file
/// name (lower-case). Versioned Python names (`python3.exe`,
/// `python3.12.exe`, `pythonw3.exe`) count too.
pub fn is_interpreter(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    SCRIPT_HOSTS.contains(&n.as_str())
        || MACRO_HOSTS.contains(&n.as_str())
        || MORE_INTERPRETERS.contains(&n.as_str())
        || crate::engine::is_lolbin(&n)
        || (n.starts_with("python") && n.ends_with(".exe"))
}

/// The image file name of a validly signed image under Program Files /
/// Program Files (x86) / WindowsApps on the system volume that is not an
/// interpreter, script host or LOLBin, does not run a script, eval or
/// inspector argument, is not under remote control, was never tampered
/// with and (Electron hosts) is a plain launch. `None` otherwise.
fn signed_program_files_app(p: &ProcessInfo, system_drive: char, tampered: bool) -> Option<String> {
    if tampered
        || p.signed != SignatureState::Valid
        || !p.signer.as_deref().is_some_and(|s| !s.trim().is_empty())
    {
        return None;
    }
    let sub = program_files_rest(&p.image, system_drive)?;
    let name = sub.rsplit('\\').next().unwrap_or("").to_string();
    if name.is_empty() || is_interpreter(&name) {
        return None;
    }
    if runs_script(&p.cmdline) || is_remote_controlled(&p.cmdline) || has_eval_switch(&p.cmdline) {
        return None;
    }
    if ELECTRON_HOSTS.contains(&name.as_str()) && !positional_args(&p.cmdline).is_empty() {
        return None;
    }
    Some(name)
}

/// Owner's PC 2026-10-22: `C:\Program Files\Docker\Docker\resources\
/// com.docker.build.exe --log-no-timestamp` (signed "Docker Inc") read
/// `.kube\config`; ST-04 then killed Docker Desktop. A read of a
/// [`DEV_TOOL_STORES`] store by a validly signed (any named signer), non-
/// interpreter image under Program Files / WindowsApps on the system volume,
/// with no script / eval / inspector / remote-control argument, not
/// tampered, is a developer tool doing its job: ST-01 Low Audit, recorded
/// for correlation, and ST-04 after only such reads is Audit. Per-user
/// installs (`%LOCALAPPDATA%`), unsigned images, interpreters and anything
/// reading a browser / wallet / Windows credential store are unaffected.
pub fn dev_tool_reader(
    p: &ProcessInfo,
    store_app: &str,
    system_drive: char,
    tampered: bool,
) -> bool {
    if !DEV_TOOL_STORES.contains(&store_app) {
        return false;
    }
    // Fix round 2026-10-25 (corpus `evasion_trojanised_signed_devtool_cloud_creds`):
    // only the stores' own tool publishers ([`DEV_TOOL_PUBLISHERS`], exact
    // signer), not any validly signed Program Files image.
    let Some(publisher) = dev_tool_publisher(p.signer.as_deref()) else {
        return false;
    };
    if !publisher.stores.contains(&store_app) {
        return false;
    }
    let name = crate::paths::file_name(&p.image).to_ascii_lowercase();
    // Red-team round 2 (2026-10-25): a publisher that also signs
    // document / macro hosts (Microsoft: Office) is a developer tool only
    // for its developer-tool images.
    if OFFICE_MACRO_HOSTS.contains(&name.as_str())
        || (!publisher.images.is_empty()
            && !publisher
                .images
                .iter()
                .any(|i| crate::paths::glob_match(i, &name)))
    {
        return false;
    }
    // FP-02: native CLI plugins (Go binaries) are judged without the
    // runtime eval switches (`docker-buildx bake --file -` reads stdin, it
    // does not evaluate code); Electron hosts keep the strict test.
    if ELECTRON_HOSTS.contains(&name.as_str()) {
        signed_program_files_app(p, system_drive, tampered).is_some()
    } else {
        signed_program_files_native(p, system_drive, tampered) && !has_inline_code(&p.cmdline)
    }
}

/// Developer-tool publishers: exact signer subject, the [`DEV_TOOL_STORES`]
/// their tools read, and their own service endpoints (DNS suffixes).
/// Subjects from `docs/research/notes/publisher-signers.md`.
#[derive(Debug, Clone, Copy)]
pub struct DevToolPublisher {
    pub signers: &'static [&'static str],
    pub stores: &'static [&'static str],
    pub endpoints: &'static [&'static str],
    /// Image names (lower-case, `*` glob) of the publisher's developer
    /// tools; empty = every non-interpreter image of the signer.
    pub images: &'static [&'static str],
}

/// Office / document hosts: never developer tools (macros, add-ins).
pub const OFFICE_MACRO_HOSTS: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "olk.exe",
    "msaccess.exe",
    "mspub.exe",
    "visio.exe",
    "onenote.exe",
    "winproj.exe",
];

pub const DEV_TOOL_PUBLISHERS: &[DevToolPublisher] = &[
    DevToolPublisher {
        signers: &["docker inc"],
        stores: &["Docker", "Kubernetes"],
        endpoints: &["docker.io", "docker.com"],
        images: &[],
    },
    DevToolPublisher {
        signers: &["microsoft corporation"],
        stores: &["Azure CLI", "Kubernetes", "Docker"],
        endpoints: &[
            "azure.com",
            "azure.net",
            "azurecr.io",
            "login.microsoftonline.com",
            "login.windows.net",
            "management.core.windows.net",
            "mcr.microsoft.com",
            "events.data.microsoft.com",
        ],
        images: &[
            "az.exe",
            "azcopy.exe",
            "azd.exe",
            "func.exe",
            "kubectl.exe",
            "kubelogin.exe",
            "devenv.exe",
            "azuredatastudio.exe",
            "servicehub.*.exe",
            "msbuild.exe",
            "docker*.exe",
            "bicep.exe",
        ],
    },
    DevToolPublisher {
        signers: &["amazon.com services llc", "amazon web services, inc."],
        stores: &["AWS"],
        endpoints: &["amazonaws.com", "aws.amazon.com", "amazonaws.com.cn"],
        images: &[],
    },
    DevToolPublisher {
        signers: &["google llc"],
        stores: &["Google Cloud SDK", "Kubernetes"],
        endpoints: &["googleapis.com", "accounts.google.com", "gcr.io", "pkg.dev"],
        images: &[],
    },
    DevToolPublisher {
        signers: &["hashicorp, inc."],
        stores: &[
            "AWS",
            "Azure CLI",
            "Google Cloud SDK",
            "Kubernetes",
            "Docker",
        ],
        endpoints: &["hashicorp.com", "terraform.io"],
        images: &[],
    },
    // Rancher Desktop (unverified subject: SUSE's published signing name).
    DevToolPublisher {
        signers: &["suse llc"],
        stores: &["Kubernetes", "Docker"],
        endpoints: &["rancher.io", "rancherdesktop.io", "suse.com"],
        images: &[],
    },
    DevToolPublisher {
        signers: &["jetbrains s.r.o."],
        stores: &[
            "AWS",
            "Azure CLI",
            "Google Cloud SDK",
            "Kubernetes",
            "Docker",
        ],
        endpoints: &["jetbrains.com"],
        images: &[],
    },
];

/// The developer-tool publisher of `signer` (exact subject), if any.
pub fn dev_tool_publisher(signer: Option<&str>) -> Option<&'static DevToolPublisher> {
    DEV_TOOL_PUBLISHERS
        .iter()
        .find(|d| crate::identity::signer_in(d.signers, signer))
}

/// Is `host` one of the developer-tool publisher's own endpoints?
pub fn dev_tool_endpoint(signer: Option<&str>, host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    // Red-team round 2: customer-named Azure namespaces (VMs, web apps,
    // vaults, registries, storage) are nobody's developer-tool endpoint.
    if MICROSOFT_CUSTOMER_NAMESPACES
        .iter()
        .chain(MICROSOFT_FIRST_PARTY_EXCLUDED.iter())
        .any(|s| crate::util::host_matches(&h, s))
    {
        return false;
    }
    dev_tool_publisher(signer)
        .is_some_and(|d| d.endpoints.iter().any(|s| crate::util::host_matches(&h, s)))
}

/// [`has_eval_switch`] without the bare `-` (FP-02: `docker-buildx bake
/// --file -` reads its bake file from stdin; a native tool does not
/// evaluate stdin as code), plus the inspector switches.
fn has_inline_code(cmdline: &str) -> bool {
    let c = cmdline.to_ascii_lowercase();
    c.split(|ch: char| ch.is_whitespace() || ch == '"')
        .any(|t| {
            matches!(
                t.split('=').next().unwrap_or(t),
                "-e" | "--eval"
                    | "-p"
                    | "--print"
                    | "/e"
                    | "/p"
                    | "-pe"
                    | "-r"
                    | "--require"
                    | "--inspect"
                    | "--inspect-brk"
            )
        })
}

/// Fix round 2026-10-25: Microsoft first-party service domains a Program
/// Files Microsoft WAM client (Office, OneDrive, Teams, Widgets) talks to
/// after reading its token cache. Broader than [`MICROSOFT_ENDPOINTS`]
/// (SharePoint, Graph, Outlook are what Office *does*): a raw IP, an
/// exfiltration service or any other host from such a reader escalates.
pub const MICROSOFT_FIRST_PARTY: &[&str] = &[
    "microsoft.com",
    "microsoftonline.com",
    "office.com",
    "office.net",
    "office365.com",
    "sharepoint.com",
    "live.com",
    "live.net",
    "outlook.com",
    "onedrive.com",
    "1drv.com",
    "msauth.net",
    "msftauth.net",
    "msftidentity.com",
    "windows.net",
    "windows.com",
    "azure.com",
    "azureedge.net",
    "msedge.net",
    "bing.com",
    "msn.com",
    "skype.com",
    "xboxlive.com",
    "xbox.com",
    "teams.cloud.microsoft",
    "cloud.microsoft",
    "static.microsoft",
    "microsoftapp.net",
    "svc.ms",
    "aka.ms",
    "visualstudio.com",
    "vscode-cdn.net",
    "exp-tas.com",
];

/// Is `host` a Microsoft first-party domain ([`MICROSOFT_FIRST_PARTY`]),
/// minus the namespaces where any customer owns the name
/// ([`MICROSOFT_CUSTOMER_NAMESPACES`] and [`MICROSOFT_FIRST_PARTY_EXCLUDED`];
/// red-team round 2 2026-10-25: a macro uploading tokens to the attacker's
/// own `*.blob.core.windows.net` account)?
pub fn microsoft_first_party(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    MICROSOFT_FIRST_PARTY
        .iter()
        .any(|s| crate::util::host_matches(&h, s))
        && !MICROSOFT_CUSTOMER_NAMESPACES
            .iter()
            .chain(MICROSOFT_FIRST_PARTY_EXCLUDED.iter())
            .any(|s| crate::util::host_matches(&h, s))
}

/// Customer-named namespaces under [`MICROSOFT_FIRST_PARTY`] suffixes beyond
/// [`MICROSOFT_CUSTOMER_NAMESPACES`]: web apps, static sites, CDN endpoints,
/// Front Door, API management, key vaults, container registries, event hubs.
pub const MICROSOFT_FIRST_PARTY_EXCLUDED: &[&str] = &[
    "azurewebsites.net",
    "azurestaticapps.net",
    "azureedge.net",
    "azurefd.net",
    "azure-api.net",
    "vault.azure.net",
    "azurecr.io",
    "trafficmanager.net",
    "cloudapp.net",
    "web.core.windows.net",
    "blob.core.windows.net",
    "queue.core.windows.net",
    "table.core.windows.net",
    "file.core.windows.net",
    "dfs.core.windows.net",
];

/// FP-03 (fix round 2026-10-25): GitHub sign-in from VS Code. Only the web
/// sign-in host itself (`github.com`, OAuth / device flow pages) is a
/// sign-in endpoint. `api.github.com` is also called by the sign-in (the
/// `user` endpoint) but can create gists, so it is never Low;
/// `gist.github.com`, `uploads.github.com` and `*.githubusercontent.com`
/// are content channels.
pub fn github_signin_host(host: &str) -> bool {
    host.trim()
        .trim_end_matches('.')
        .eq_ignore_ascii_case("github.com")
}

/// Azure Application Insights ingestion hosts used by VS Code extension
/// telemetry (`*.in.applicationinsights.azure.com`,
/// `dc.services.visualstudio.com`). Anyone can own an ingestion key, so a
/// send there after a token read is High Audit, never Low.
pub fn extension_telemetry_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    crate::util::host_matches(&h, "in.applicationinsights.azure.com")
        || h == "dc.services.visualstudio.com"
}

/// GitHub Copilot's own service endpoints used by VS Code after a WAM read
/// (owner export 2026-10-25): the Copilot API (`*.githubcopilot.com`,
/// operated by GitHub, no user-hostable content) and its telemetry host
/// `copilot-telemetry.githubusercontent.com` (exact name; other
/// `githubusercontent.com` hosts serve user content and stay out).
pub fn github_copilot_host(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    crate::util::host_matches(&h, "githubcopilot.com")
        || h == "copilot-telemetry.githubusercontent.com"
}

/// Owner's PC 2026-10-22: ST-04 killed Docker Desktop's backend (the
/// reader's parent, which made the connection) and its whole tree. Is
/// `sender` the reader's own vendor backend: a validly signed, non-
/// interpreter Program Files image (same constraints as
/// [`dev_tool_reader`]) whose signer is exactly the reader's (valid)
/// signer? The caller checks that `sender` is the reader's parent.
pub fn vendor_backend(
    sender: &ProcessInfo,
    reader: &ProcessInfo,
    system_drive: char,
    sender_tampered: bool,
) -> bool {
    if reader.signed != SignatureState::Valid
        || signed_program_files_app(sender, system_drive, sender_tampered).is_none()
    {
        return false;
    }
    match (sender.signer.as_deref(), reader.signer.as_deref()) {
        (Some(a), Some(b)) => {
            let (a, b) = (a.trim(), b.trim());
            !a.is_empty() && a.eq_ignore_ascii_case(b)
        }
        _ => false,
    }
}

/// 2026-10-22 (coordinator review of the AWS trade-off): the cloud provider
/// of a developer-tool store, by store label. Kubeconfig has none: its API
/// server is whatever the kubeconfig names, which the engine does not know.
pub fn cloud_provider(store_app: &str) -> Option<&'static str> {
    match store_app {
        "AWS" => Some("AWS"),
        "Azure CLI" => Some("Azure"),
        "Google Cloud SDK" => Some("Google Cloud"),
        "Docker" => Some("Docker"),
        _ => None,
    }
}

/// Service endpoint DNS suffixes per [`cloud_provider`] (label-boundary
/// suffix match on the correlated host name; never on an IP). Kept to the
/// providers' API / sign-in / registry domains: not `microsoft.com` or
/// `google.com` as a whole.
pub const PROVIDER_ENDPOINTS: &[(&str, &[&str])] = &[
    (
        "AWS",
        &["amazonaws.com", "aws.amazon.com", "amazonaws.com.cn"],
    ),
    (
        "Azure",
        &[
            "azure.com",
            "azure.net",
            "core.windows.net",
            "login.windows.net",
            "login.microsoftonline.com",
            "graph.microsoft.com",
            "azurecr.io",
        ],
    ),
    (
        "Google Cloud",
        &["googleapis.com", "accounts.google.com", "gcr.io", "pkg.dev"],
    ),
    ("Docker", &["docker.io", "docker.com"]),
];

/// Is `host` one of `provider`'s service endpoints?
pub fn provider_endpoint(provider: &str, host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    PROVIDER_ENDPOINTS
        .iter()
        .filter(|(p, _)| *p == provider)
        .flat_map(|(_, s)| s.iter())
        .any(|s| crate::util::host_matches(&h, s))
}

/// Who may get ST-04's provider-destination allowance (reader and sender):
/// a validly signed image (interpreters included: boto3 runs under a
/// signed python.exe) that is not in Temp / Downloads / external media and
/// was never injected into. Unsigned readers never get it.
pub fn provider_allowance_ok(p: &ProcessInfo, tampered: bool) -> bool {
    !tampered
        && !p.image.is_empty()
        && p.signed == SignatureState::Valid
        && !matches!(
            p.path_class,
            PathClass::Temp | PathClass::Downloads | PathClass::External
        )
}

/// Tokens after the image on a Windows command line (quote-aware).
fn args_after_image(cmdline: &str) -> Vec<String> {
    let t = cmdline.trim();
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
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    out
}

/// Python flags allowed before the CLI entry point: single-dash letter
/// groups without `c` (command), `m` (module) or `X` / `W` values.
fn harmless_python_flags(t: &str) -> bool {
    t.strip_prefix('-').is_some_and(|f| {
        !f.is_empty()
            && f.chars().all(|c| {
                matches!(
                    c.to_ascii_lowercase(),
                    'b' | 'e' | 'i' | 's' | 'u' | 'o' | 'q' | 'd'
                )
            })
    })
}

/// 2026-10-22: the official Azure CLI and Google Cloud CLI are Python
/// programs. Their **bundled** interpreter, in the CLI's own Program Files
/// install on the system volume, validly signed, not tampered, started the
/// way the CLI's launcher starts it, owns that CLI's store:
/// * Azure CLI: `<Program Files[ (x86)]>\Microsoft SDKs\Azure\CLI2\python.exe`
///   with `-IBm azure.cli` (`az.cmd`; any harmless flag group ending in `m`
///   followed by exactly `azure.cli`);
/// * Google Cloud CLI: `<Program Files[ (x86)]>\Google\Cloud SDK\
///   google-cloud-sdk\platform\bundledpython\python.exe` whose first
///   non-flag argument is that SDK's `lib\gcloud.py`.
///
/// The command lines follow the launchers' published scripts and were not
/// checked on a live install; a mismatch only means the provider-destination
/// path (High Audit) applies instead of silence.
pub fn bundled_cli_python(
    p: &ProcessInfo,
    store_app: &str,
    system_drive: char,
    tampered: bool,
) -> bool {
    if tampered || p.signed != SignatureState::Valid {
        return false;
    }
    let Some(sub) = program_files_rest(&p.image, system_drive) else {
        return false;
    };
    let args: Vec<String> = args_after_image(&p.cmdline)
        .into_iter()
        .map(|a| a.to_ascii_lowercase())
        .collect();
    match store_app {
        "Azure CLI" if sub == r"\microsoft sdks\azure\cli2\python.exe" => {
            args.len() >= 2
                && args[0].ends_with('m')
                && harmless_python_flags(&args[0][..args[0].len() - 1])
                && args[1] == "azure.cli"
                || args.len() >= 2 && args[0] == "-m" && args[1] == "azure.cli"
        }
        "Google Cloud SDK"
            if sub == r"\google\cloud sdk\google-cloud-sdk\platform\bundledpython\python.exe" =>
        {
            let Some(script) = args.iter().find(|a| !harmless_python_flags(a)) else {
                return false;
            };
            let s = crate::paths::normalize_path(script);
            if !s.starts_with(&format!("{}:\\", system_drive.to_ascii_lowercase())) {
                return false;
            }
            let s = crate::util::strip_drive(&s);
            let s = s.replace(r"\bin\..\", r"\").replace(r"\bin\\..\", r"\");
            matches!(
                s.as_str(),
                r"\program files\google\cloud sdk\google-cloud-sdk\lib\gcloud.py"
                    | r"\program files (x86)\google\cloud sdk\google-cloud-sdk\lib\gcloud.py"
            )
        }
        _ => false,
    }
}

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
/// (location only â€” no signature check). Program Files on the system
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

// ---------------------------------------------------------------------------
// Owner's PC alert triage 2026-10-22 (7,614 alerts, all-Audit policy)
// ---------------------------------------------------------------------------

/// Is the image signer exactly one of [`WAM_CLIENT_SIGNERS`] with a valid signature?
fn microsoft_client_signed(p: &ProcessInfo) -> bool {
    p.signed == SignatureState::Valid
        && p.signer.as_deref().is_some_and(|s| {
            WAM_CLIENT_SIGNERS
                .iter()
                .any(|w| s.trim().eq_ignore_ascii_case(w))
        })
}

/// Triage item 6: VS Code installs per user by default
/// (`%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe`, Microsoft
/// Corporation) and was killed by ST-04 after a WAM token-cache read and a
/// telemetry send to `mobile.events.data.microsoft.com`. A WAM token-cache
/// read by a validly Microsoft-signed image (Corporation or Windows) that is
/// **not** under Program Files / WindowsApps (those are
/// [`wam_client_reader`]) but in the user's profile (`PathClass::UserWritable`;
/// never Temp, Downloads, external media or another volume), not a LOLBin,
/// script host, interpreter or REPL, without a script / eval / inspector /
/// remote-control argument, a plain launch for Electron hosts, and never
/// injected into. Its ST-01 is Low Audit; ST-04 is Low Audit **only** when
/// the send goes to a [`microsoft_endpoint`] (by DNS name) and keeps the full
/// response for any other destination. The per-user folder is writable by
/// the user (DLL side-loading, file swap): this is why the allowance is
/// destination-bound and never silent.
pub fn ms_wam_reader_per_user(
    p: &ProcessInfo,
    store_app: &str,
    system_drive: char,
    tampered: bool,
) -> bool {
    if tampered || store_app != "Windows token broker" || !microsoft_client_signed(p) {
        return false;
    }
    if p.path_class != PathClass::UserWritable
        || crate::protect::on_system_volume(&p.image, system_drive).is_none()
    {
        return false;
    }
    // Review H2: a catalog-signed Microsoft binary (powershell.exe) copied
    // and renamed into the profile would otherwise qualify. Only the exact
    // per-user install locations of Microsoft's WAM clients count.
    let norm = crate::paths::normalize_path(&p.image);
    let Some(rel) = crate::paths::profile_relative(&norm) else {
        return false;
    };
    if !PER_USER_MS_WAM_CLIENTS.contains(&rel) {
        return false;
    }
    let name = crate::paths::file_name(&p.image).to_ascii_lowercase();
    if name.is_empty() || is_interpreter(&name) {
        return false;
    }
    if runs_script(&p.cmdline) || is_remote_controlled(&p.cmdline) || has_eval_switch(&p.cmdline) {
        return false;
    }
    !(ELECTRON_HOSTS.contains(&name.as_str()) && !positional_args(&p.cmdline).is_empty())
}

/// Exact per-user install locations (relative to the profile root,
/// lower-case) of Microsoft-signed WAM clients (review H2).
pub const PER_USER_MS_WAM_CLIENTS: &[&str] = &[
    r"appdata\local\programs\microsoft vs code\code.exe",
    r"appdata\local\programs\microsoft vs code insiders\code - insiders.exe",
    r"appdata\local\microsoft\onedrive\onedrive.exe",
];

/// Triage item 6, narrowed after review H1: Microsoft **sign-in and
/// telemetry** endpoints a WAM client talks to after reading its token
/// cache (label-boundary suffix match on the correlated DNS name, never an
/// IP). Storage and collaboration services where anyone can own a tenant
/// (SharePoint, OneDrive, Graph, Office, Azure DevOps, `*.windows.net`,
/// `*.azure.com`) are deliberately not listed: a stealer can upload stolen
/// tokens to its own tenant there.
pub const MICROSOFT_ENDPOINTS: &[&str] = &[
    "events.data.microsoft.com",
    "login.microsoftonline.com",
    "login.microsoft.com",
    "login.live.com",
    "login.windows.net",
    "exp-tas.com",
    "vscode-cdn.net",
    "update.code.visualstudio.com",
    "marketplace.visualstudio.com",
];

/// Customer-controlled namespaces under the suffixes above (anyone can
/// create a storage account, Service Bus namespace, SQL server or VM name
/// there): never a Microsoft endpoint for this purpose.
pub const MICROSOFT_CUSTOMER_NAMESPACES: &[&str] = &[
    "core.windows.net",
    "servicebus.windows.net",
    "database.windows.net",
    "azurewebsites.windows.net",
    "cloudapp.azure.com",
    "azurecontainer.azure.com",
];

/// Is `host` a Microsoft-owned endpoint ([`MICROSOFT_ENDPOINTS`], minus
/// [`MICROSOFT_CUSTOMER_NAMESPACES`])?
pub fn microsoft_endpoint(host: &str) -> bool {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.parse::<std::net::IpAddr>().is_ok() {
        return false;
    }
    MICROSOFT_ENDPOINTS
        .iter()
        .any(|s| crate::util::host_matches(&h, s))
        && !MICROSOFT_CUSTOMER_NAMESPACES
            .iter()
            .any(|s| crate::util::host_matches(&h, s))
}

/// Is `p` a validly Microsoft-signed (Corporation / Windows) sender outside
/// Temp / Downloads / external media that was never injected into (the
/// sender side of the per-user WAM allowance)?
pub fn microsoft_sender_ok(p: &ProcessInfo, tampered: bool) -> bool {
    !tampered
        && microsoft_client_signed(p)
        && provider_allowance_ok(p, tampered)
        && !is_interpreter(&crate::paths::file_name(&p.image).to_ascii_lowercase())
}

/// Triage item 8: SSH client family that owns the user's `.ssh` keys.
pub const SSH_CLIENT_IMAGES: &[&str] = &[
    "ssh.exe",
    "ssh-agent.exe",
    "ssh-add.exe",
    "scp.exe",
    "sftp.exe",
    "ssh-keygen.exe",
    "plink.exe",
    "pageant.exe",
    "git-remote-*.exe",
];

/// Install folders (driveless, lower-case, system volume) of the SSH
/// clients above. Git for Windows ships its `usr\bin\ssh.exe` unsigned, so
/// the location (admin-only) is the identity here, not the signature.
pub const SSH_CLIENT_DIRS: &[&str] = &[
    r"\windows\system32\openssh\",
    r"\program files\git\usr\bin\",
    r"\program files\openssh\",
    r"\program files\putty\",
];

/// `ssh -o` options (and `ssh_config` keywords) that run a local command:
/// ssh then becomes a launcher, not just a client.
const SSH_COMMAND_OPTIONS: &[&str] = &[
    "proxycommand",
    "localcommand",
    "permitlocalcommand",
    "knownhostscommand",
    "securitykeyprovider",
    "pkcs11provider",
];

/// The first command-running or library-loading option on an SSH client
/// command line, if any. `name` is the lower-case image file name.
pub fn ssh_suspicious_option(name: &str, cmdline: &str) -> Option<String> {
    let c = cmdline.to_ascii_lowercase();
    if let Some(o) = SSH_COMMAND_OPTIONS.iter().find(|o| c.contains(*o)) {
        return Some(o.to_string());
    }
    // Review M3: switches that load a library into the client, run another
    // program, or read an alternate config file (which can carry
    // ProxyCommand / Match exec / a provider). Case-sensitive (`-i` is the
    // ordinary identity file); per client, because ssh's own `-s`
    // (subsystem, used by sftp) and `-D` (SOCKS forward) are ordinary.
    let flags: &[&str] = match name {
        "ssh.exe" => &["-I", "-F"],
        "scp.exe" | "sftp.exe" => &["-F", "-S", "-D"],
        "ssh-add.exe" => &["-s", "-S", "-e"],
        "ssh-keygen.exe" => &["-D", "-w"],
        "ssh-agent.exe" => &["-P"],
        _ => &[],
    };
    cmdline
        .split(|ch: char| ch.is_whitespace() || ch == '"')
        .find(|t| flags.iter().any(|f| t.starts_with(f)))
        .map(str::to_string)
}

/// Triage item 8: Git for Windows' unsigned `ssh.exe` read `~\.ssh\id_rsa`
/// and connected to github.com:22 (ST-01 + ST-04 critical). An SSH client
/// ([`SSH_CLIENT_IMAGES`]) directly inside one of [`SSH_CLIENT_DIRS`] on the
/// system volume, with no command-running option, owns the SSH key stores.
/// Copies elsewhere (Temp, Downloads, a profile folder, another volume),
/// other readers and ssh with `ProxyCommand` / `LocalCommand` /
/// `KnownHostsCommand` / provider options still alert.
pub fn ssh_client_owner(
    p: &ProcessInfo,
    store: &crate::paths::SensitiveStore,
    system_drive: char,
    tampered: bool,
) -> bool {
    if tampered || store.owner != crate::paths::OwnerApp::Ssh || p.image.is_empty() {
        return false;
    }
    let Some(rest) = crate::protect::on_system_volume(&p.image, system_drive) else {
        return false;
    };
    if rest.split('\\').any(|c| c == "..") {
        return false;
    }
    let in_dir = SSH_CLIENT_DIRS.iter().any(|d| {
        rest.strip_prefix(d)
            .is_some_and(|n| !n.is_empty() && !n.contains('\\'))
    });
    let name = crate::paths::file_name(&rest).to_string();
    in_dir
        && SSH_CLIENT_IMAGES
            .iter()
            .any(|i| crate::paths::glob_match(i, &name))
        && ssh_suspicious_option(&name, &p.cmdline).is_none()
}

/// Triage item 9: NVIDIA's `nvcontainer.exe` (signed, Program Files) read
/// Steam's `config\config.vdf`, then contacted api-prod.nvidia.com. GPU /
/// overlay / game-library tools scan that file. A read of the Steam client
/// configuration store ([`crate::paths::STEAM_CONFIG_NOUN`]) by a validly
/// signed native Program Files image ([`signed_program_files_native`]: not
/// an interpreter or Electron host, no script / remote-control argument,
/// not tampered) is Low Audit (ST-04 after only
/// such reads is Low Audit too). The Steam secrets (`ssfn*`,
/// `loginusers.vdf`, `local.vdf`) are never covered.
pub fn vendor_config_reader(
    p: &ProcessInfo,
    store: &crate::paths::SensitiveStore,
    system_drive: char,
    tampered: bool,
) -> bool {
    store.app == "Steam"
        && store.noun == crate::paths::STEAM_CONFIG_NOUN
        && signed_program_files_native(p, system_drive, tampered)
}

/// A validly signed (named signer) native image under Program Files /
/// WindowsApps on the system volume: not an interpreter, script host, LOLBin
/// or Electron host (those keep the stricter [`signed_program_files_app`]
/// test), no script argument, not under remote control, not tampered.
/// Unlike [`signed_program_files_app`], `-e` / `-p` style switches are not
/// held against it: they mean "eval" / "print" only to a runtime, and
/// native services use them for their own options (NVIDIA's nvcontainer
/// runs with `-p 30000`, owner's PC 2026-10-22).
fn signed_program_files_native(p: &ProcessInfo, system_drive: char, tampered: bool) -> bool {
    if tampered
        || p.signed != SignatureState::Valid
        || !p.signer.as_deref().is_some_and(|s| !s.trim().is_empty())
    {
        return false;
    }
    let Some(sub) = program_files_rest(&p.image, system_drive) else {
        return false;
    };
    let name = sub.rsplit('\\').next().unwrap_or("").to_string();
    !name.is_empty()
        && !is_interpreter(&name)
        && !ELECTRON_HOSTS.contains(&name.as_str())
        && !runs_script(&p.cmdline)
        && !is_remote_controlled(&p.cmdline)
}

/// Triage item 11: WSL's service answers DNS for Linux processes (DNS
/// tunnelling), so every lookup made inside WSL shows up as
/// `C:\Program Files\WSL\wslservice.exe`. That exact image on the system
/// volume with a valid Microsoft signature.
pub fn wsl_dns_proxy(p: &ProcessInfo, system_drive: char) -> bool {
    microsoft_client_signed(p)
        && crate::protect::on_system_volume(&p.image, system_drive).as_deref()
            == Some(r"\program files\wsl\wslservice.exe")
}

/// Triage item 10: read-only LSASS access bits (QUERY_INFORMATION 0x400,
/// QUERY_LIMITED_INFORMATION 0x1000, VM_READ 0x10, SYNCHRONIZE 0x100000).
pub fn lsass_read_only_mask(mask: u32) -> bool {
    mask != 0 && mask & !(0x10 | 0x400 | 0x1000 | 0x0010_0000) == 0
}

/// Triage item 10: a validly signed (named signer) Program Files service or
/// updater that is not an interpreter / LOLBin and runs no script / eval /
/// remote-control argument (NVIDIA nvcontainer, BraveUpdate).
pub fn signed_program_files_service(p: &ProcessInfo, system_drive: char, tampered: bool) -> bool {
    signed_program_files_native(p, system_drive, tampered)
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

    /// Review of the 1.1.7 integration, M3.
    #[test]
    fn electron_foreign_code_m3() {
        // Store owners: positional arguments count (Node runs any file).
        assert!(electron_runs_foreign_code(
            "slack.exe",
            r#""C:\Program Files\Slack\slack.exe" C:\x\a"#
        ));
        assert!(electron_runs_foreign_code(
            "exodus.exe",
            r#"Exodus.exe "C:\x y\s.cjs""#
        ));
        assert!(electron_runs_foreign_code(
            "bitwarden.exe",
            "Bitwarden.exe --require=C:\\x\\a"
        ));
        assert!(electron_runs_foreign_code(
            "1password.exe",
            "1Password.exe --remote-debugging-port=9222"
        ));
        assert!(!electron_runs_foreign_code(
            "slack.exe",
            r#""C:\Program Files\Slack\slack.exe" --startup"#
        ));
        assert!(!electron_runs_foreign_code(
            "slack.exe",
            r#"slack.exe "slack://open?team=T1""#
        ));
        assert!(!electron_runs_foreign_code(
            "discord.exe",
            r#"Discord.exe --processStart Discord.exe --process-start-args "--start-inactive""#
        ));
        // Electron's relauncher (owner's PC replay 2026-10).
        assert!(!electron_runs_foreign_code(
            "discord.exe",
            r#""C:\Users\a\AppData\Local\Discord\app-1.0.9265\Discord.exe" --type=relauncher --no-sandbox --- "C:\Users\a\AppData\Local\Discord\app-1.0.9265\Discord.exe""#
        ));
        assert!(electron_runs_foreign_code(
            "discord.exe",
            r#"Discord.exe --type=relauncher --- "C:\x\Discord.exe" C:\x\s"#
        ));
        assert!(electron_runs_foreign_code(
            "discord.exe",
            r#"Discord.exe --type=relauncher --- C:\x\node.exe"#
        ));
        // Developer hosts: only script / eval / inspector switches.
        assert!(!electron_runs_foreign_code(
            "code.exe",
            r#""C:\Users\a\AppData\Local\Programs\Microsoft VS Code\Code.exe" "c:\Users\a\AppData\Local\Programs\Microsoft VS Code\1b6a188127\resources\app\extensions\x\dist\serverWorkerMain" --node-ipc"#
        ));
        assert!(electron_runs_foreign_code(
            "code.exe",
            r#"Code.exe C:\x\s.js"#
        ));
        // Not Electron: never.
        assert!(!electron_runs_foreign_code(
            "keepass.exe",
            r#"KeePass.exe C:\db.kdbx"#
        ));
        assert!(is_electron_owner_image("discord.exe"));
        assert!(!is_electron_owner_image("code.exe"));
        assert!(is_electron_image("code.exe"));
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
    fn dev_tool_reader_and_vendor_backend() {
        const BUILD: &str = r"C:\Program Files\Docker\Docker\resources\com.docker.build.exe";
        const BACKEND: &str = r"C:\Program Files\Docker\Docker\resources\com.docker.backend.exe";
        let docker = Some("Docker Inc");
        let build = proc_(BUILD, "com.docker.build.exe --log-no-timestamp", docker);
        // Fix round 2026-10-25: only the publisher's own stores.
        for store in DEV_TOOL_STORES {
            let own = matches!(*store, "Docker" | "Kubernetes");
            assert_eq!(dev_tool_reader(&build, store, 'c', false), own, "{store}");
        }
        let fake = proc_(
            r"C:\Program Files\KubeDash\kubedash.exe",
            "kubedash.exe --background",
            Some("Nimbus Devtools OU"),
        );
        assert!(!dev_tool_reader(&fake, "Kubernetes", 'c', false));
        // FP-02: `docker-buildx bake --file -` (stdin) is not an eval switch.
        let bx = proc_(
            r"C:\Program Files\Docker\cli-plugins\docker-buildx.exe",
            "docker-buildx.exe bake --file - --progress rawjson",
            docker,
        );
        assert!(dev_tool_reader(&bx, "Docker", 'c', false));
        assert!(dev_tool_endpoint(docker, "auth.docker.io"));
        assert!(!dev_tool_endpoint(docker, "198.51.100.1"));
        assert!(!dev_tool_endpoint(docker, "evil.example"));
        assert!(
            !dev_tool_reader(&build, "Kubernetes", 'c', true),
            "tampered"
        );
        for store in [
            "Chrome",
            "Windows token broker",
            "Git",
            "Exodus",
            "Microsoft identity (MSAL)",
        ] {
            assert!(!dev_tool_reader(&build, store, 'c', false), "{store}");
        }
        for name in [
            "python.exe",
            "python3.12.exe",
            "pythonw.exe",
            "node.exe",
            "javaw.exe",
            "pwsh.exe",
            "cmd.exe",
            "rundll32.exe",
            "dotnet.exe",
            "ruby.exe",
            "perl.exe",
            "php.exe",
            "mshta.exe",
        ] {
            assert!(is_interpreter(name), "{name}");
            let p = proc_(&format!(r"C:\Program Files\X\{name}"), name, docker);
            assert!(!dev_tool_reader(&p, "Kubernetes", 'c', false), "{name}");
        }
        assert!(!is_interpreter("com.docker.build.exe"));
        let backend = proc_(BACKEND, "com.docker.backend.exe run", docker);
        assert!(vendor_backend(&backend, &build, 'c', false));
        assert!(!vendor_backend(&backend, &build, 'c', true), "tampered");
        let other = proc_(BACKEND, "x", Some("Other Ltd"));
        assert!(!vendor_backend(&other, &build, 'c', false));
        let mut unsigned_reader = build.clone();
        unsigned_reader.signed = Unsigned;
        assert!(!vendor_backend(&backend, &unsigned_reader, 'c', false));
        let user = proc_(
            r"C:\Users\a\AppData\Local\Docker\com.docker.backend.exe",
            "x",
            docker,
        );
        assert!(!vendor_backend(&user, &build, 'c', false));
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
