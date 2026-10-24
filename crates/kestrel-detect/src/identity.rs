//! Application identity: "trust is identity, not name" (fix round
//! 2026-10-25, `docs/DETECTION-QUALITY.md`, corpus findings 2 and 8).
//!
//! An image name says nothing on its own: a stolen certificate, a copied
//! genuinely signed binary or a mock `Program Files ` folder all carry the
//! right name. A process is the application it claims to be
//! ([`genuine`]) only when **all** of these hold:
//!
//! 1. it was never the target of an injection signal and never loaded an
//!    unsigned DLL from a user-writable folder (the engine's taint set,
//!    passed in as `tampered`);
//! 2. its Authenticode signature is **valid** (`Unknown` never counts);
//! 3. it does not run from Temp / Downloads / removable media;
//! 4. when its image name is listed in [`PUBLISHERS`]: the signer subject is
//!    **exactly** one of that publisher's subjects (case-insensitive, no
//!    substring) **and** the image sits in one of the publisher's install
//!    locations. A listed name with any other signer or location is not the
//!    application;
//! 5. an unlisted name falls back to the install location only: Program
//!    Files / WindowsApps / System32 on the system volume, or below the
//!    user profile's `AppData\` (not `AppData\Local\Temp`). Anything on
//!    another volume, in a mock folder or loose in the profile is not.
//!
//! Signer subjects come from `docs/research/notes/publisher-signers.md`;
//! the ones marked unverified there are the vendors' published names.

use crate::paths::{file_name, glob_match, glob_match_path, normalize_path, profile_relative};
use kestrel_common::{PathClass, ProcessInfo, SignatureState};

/// Marker in [`Publisher::signers`]: any Microsoft signer of
/// [`crate::protect::is_microsoft_signer`] (Microsoft Windows, Microsoft
/// Windows Publisher, Microsoft Corporation).
pub const MICROSOFT: &str = "@microsoft";

/// One publisher's binaries and where they are installed.
#[derive(Debug, Clone, Copy)]
pub struct Publisher {
    /// Vendor name for alert text.
    pub vendor: &'static str,
    /// Image file names (lower-case, `*` glob within the name).
    pub images: &'static [&'static str],
    /// Exact signer subjects (lower-case) or [`MICROSOFT`].
    pub signers: &'static [&'static str],
    /// Install trees relative to `\Program Files` / `\Program Files (x86)`
    /// on the system volume (`\windowsapps\<package>_*\**` for MSIX), path
    /// globs (`*` one segment, `**` any depth).
    pub program_files: &'static [&'static str],
    /// Install trees relative to a user profile root (`appdata\local\...`).
    pub profile: &'static [&'static str],
    /// `\Windows\` (System32, SysWOW64, ...) on the system volume.
    pub system: bool,
    /// Portable application: any folder except Temp / Downloads / removable
    /// media (the signer is then the whole identity).
    pub anywhere: bool,
}

const NONE: &[&str] = &[];

macro_rules! publisher {
    ($vendor:expr, $images:expr, $signers:expr, pf: $pf:expr, profile: $prof:expr, system: $sys:expr, anywhere: $any:expr) => {
        Publisher {
            vendor: $vendor,
            images: $images,
            signers: $signers,
            program_files: $pf,
            profile: $prof,
            system: $sys,
            anywhere: $any,
        }
    };
}

/// Publisher table. Names listed here are only genuine with these signers
/// in these places (see the module docs).
pub const PUBLISHERS: &[Publisher] = &[
    // ---- browsers ---------------------------------------------------------
    publisher!(
        "Google",
        &[
            "chrome.exe",
            "chrome_proxy.exe",
            "chrome_pwa_launcher.exe",
            "notification_helper.exe",
            "elevation_service.exe",
            "os_update_handler.exe",
        ],
        &["google llc", "google inc"],
        pf: &[r"\google\chrome\application\**", r"\google\chrome beta\application\**", r"\google\chrome dev\application\**"],
        profile: &[r"appdata\local\google\chrome\application\**", r"appdata\local\google\chrome beta\application\**", r"appdata\local\google\chrome dev\application\**", r"appdata\local\google\chrome sxs\application\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Microsoft",
        &[
            "msedge.exe",
            "msedge_proxy.exe",
            "msedge_pwa_launcher.exe",
            "identity_helper.exe",
            "cookie_exporter.exe",
            "elevation_service.exe",
            "os_update_handler.exe",
        ],
        &["microsoft corporation"],
        pf: &[r"\microsoft\edge\application\**", r"\microsoft\edge beta\application\**", r"\microsoft\edge dev\application\**", r"\microsoft\edgecore\**", r"\microsoft\edgewebview\application\**", r"\microsoft\copilot\application\**"],
        profile: &[r"appdata\local\microsoft\edge sxs\application\**", r"appdata\local\microsoft\edge beta\application\**", r"appdata\local\microsoft\edge dev\application\**"],
        system: false,
        anywhere: false
    ),
    // The Evergreen runtime lives in the EdgeWebView tree; fixed-version
    // runtimes ship inside an application's own Program Files folder.
    publisher!(
        "Microsoft",
        &["msedgewebview2.exe"],
        &["microsoft corporation"],
        pf: &[r"\**"],
        profile: &[r"appdata\local\microsoft\edgewebview\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Brave Software",
        &["brave.exe", "elevation_service.exe", "brave_vpn_helper.exe", "braveupdate.exe"],
        &["brave software, inc."],
        pf: &[r"\bravesoftware\**"],
        profile: &[r"appdata\local\bravesoftware\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Mozilla",
        &[
            "firefox.exe",
            "default-browser-agent.exe",
            "pingsender.exe",
            "plugin-container.exe",
            "private_browsing.exe",
            "maintenanceservice.exe",
            "thunderbird.exe",
            "updater.exe",
            "crashreporter.exe",
        ],
        &["mozilla corporation"],
        pf: &[r"\mozilla firefox\**", r"\firefox developer edition\**", r"\firefox nightly\**", r"\mozilla thunderbird\**", r"\mozilla maintenance service\**"],
        profile: &[r"appdata\local\mozilla firefox\**", r"appdata\local\mozilla\updates\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Opera",
        &["opera.exe", "opera_gx.exe"],
        &["opera norway as", "opera software as"],
        pf: &[r"\opera*\**"],
        profile: &[r"appdata\local\programs\opera*\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Vivaldi",
        &["vivaldi.exe"],
        &["vivaldi technologies as"],
        pf: &[r"\vivaldi\**"],
        profile: &[r"appdata\local\vivaldi\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Yandex",
        &["browser.exe"],
        &["yandex llc"],
        pf: &[r"\yandex\**"],
        profile: &[r"appdata\local\yandex\yandexbrowser\application\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "The Browser Company",
        &["arc.exe"],
        &["the browser company of new york inc."],
        pf: &[r"\windowsapps\thebrowsercompany.arc_*\**"],
        profile: NONE,
        system: false,
        anywhere: false
    ),
    // ---- Windows hosts that own Windows stores ----------------------------
    publisher!(
        "Microsoft",
        &[
            "svchost.exe",
            "lsass.exe",
            "backgroundtaskhost.exe",
            "runtimebroker.exe",
            "dllhost.exe",
            "explorer.exe",
            "taskhostw.exe",
        ],
        &[MICROSOFT],
        pf: NONE,
        profile: NONE,
        system: true,
        anywhere: false
    ),
    publisher!(
        "Microsoft",
        &["microsoft.aad.brokerplugin.exe", "tokenbrokerhost.exe"],
        &[MICROSOFT],
        pf: &[r"\windowsapps\**"],
        profile: NONE,
        system: true,
        anywhere: false
    ),
    publisher!(
        "Microsoft",
        &["code.exe", "code - insiders.exe"],
        &["microsoft corporation"],
        pf: &[r"\microsoft vs code\**", r"\microsoft vs code insiders\**"],
        profile: &[r"appdata\local\programs\microsoft vs code\**", r"appdata\local\programs\microsoft vs code insiders\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Microsoft",
        &["onedrive.exe", "onedrive.sync.service.exe"],
        &["microsoft corporation"],
        pf: &[r"\microsoft onedrive\**"],
        profile: &[r"appdata\local\microsoft\onedrive\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Microsoft",
        &["ms-teams.exe"],
        &["microsoft corporation"],
        pf: &[r"\windowsapps\msteams_*\**"],
        profile: NONE,
        system: false,
        anywhere: false
    ),
    // ---- messengers, gaming, wallets ---------------------------------------
    publisher!(
        "Discord",
        &["discord.exe", "discordptb.exe", "discordcanary.exe", "update.exe"],
        &["discord inc."],
        pf: NONE,
        profile: &[r"appdata\local\discord\**", r"appdata\local\discordptb\**", r"appdata\local\discordcanary\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Exodus",
        &["exodus.exe", "update.exe"],
        &["exodus movement, inc.", "exodus movement inc"],
        pf: NONE,
        profile: &[r"appdata\local\exodus\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Telegram",
        &["telegram.exe", "updater.exe"],
        &["telegram fz-llc"],
        pf: NONE,
        profile: NONE,
        system: false,
        anywhere: true
    ),
    publisher!(
        "Valve",
        &[
            "steam.exe",
            "steamservice.exe",
            "steamwebhelper.exe",
            "gameoverlayui.exe",
            "gameoverlayui64.exe",
            "steamerrorreporter.exe",
            "steamerrorreporter64.exe",
        ],
        &["valve corp."],
        pf: NONE,
        profile: NONE,
        system: false,
        anywhere: true
    ),
    publisher!(
        "Ledger",
        &["ledger live.exe", "ledger wallet.exe"],
        &["ledger sas"],
        pf: &[r"\ledger live\**", r"\ledger wallet\**"],
        profile: &[r"appdata\local\programs\ledger-live\**", r"appdata\local\programs\ledger live\**", r"appdata\local\programs\ledger-wallet\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Electrum",
        &["electrum*.exe"],
        &["electrum technologies gmbh"],
        pf: NONE,
        profile: NONE,
        system: false,
        anywhere: true
    ),
    publisher!(
        "FileZilla",
        &["filezilla.exe", "fzsftp.exe", "fzputtygen.exe", "fzstorj.exe"],
        &["tim kosse"],
        pf: &[r"\filezilla ftp client\**", r"\filezilla\**"],
        profile: NONE,
        system: false,
        anywhere: false
    ),
    publisher!(
        "WinSCP",
        &["winscp.exe", "winscp.com"],
        &["martin přikryl", "martin prikryl"],
        pf: &[r"\winscp\**"],
        profile: &[r"appdata\local\programs\winscp\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "Slack",
        &["slack.exe"],
        &["slack technologies, llc", "slack technologies, inc."],
        pf: &[r"\slack\**", r"\windowsapps\91750d7e.slack_*\**"],
        profile: &[r"appdata\local\slack\**"],
        system: false,
        anywhere: false
    ),
    // ---- password managers ------------------------------------------------
    publisher!(
        "KeePass",
        &["keepass.exe"],
        &["open source developer, dominik reichl", "dominik reichl"],
        pf: NONE,
        profile: NONE,
        system: false,
        anywhere: true
    ),
    publisher!(
        "KeePassXC",
        &["keepassxc.exe", "keepassxc-proxy.exe"],
        &["droidmonkey apps, llc"],
        pf: NONE,
        profile: NONE,
        system: false,
        anywhere: true
    ),
    publisher!(
        "Bitwarden",
        &["bitwarden.exe"],
        &["bitwarden inc.", "8bit solutions llc"],
        pf: &[r"\bitwarden\**"],
        profile: &[r"appdata\local\programs\bitwarden\**"],
        system: false,
        anywhere: false
    ),
    publisher!(
        "AgileBits",
        &["1password.exe", "1password-browsersupport.exe", "op.exe"],
        &["agilebits", "agilebits inc."],
        pf: &[r"\1password\**"],
        profile: &[r"appdata\local\1password\**", r"appdata\local\microsoft\winget\packages\**"],
        system: false,
        anywhere: false
    ),
    // ---- developer tools ----------------------------------------------------
    publisher!(
        "Docker",
        &[
            "docker.exe",
            "docker desktop.exe",
            "com.docker.backend.exe",
            "com.docker.build.exe",
            "docker-credential-desktop.exe",
            "docker-credential-wincred.exe",
            "docker-compose.exe",
            "docker-buildx.exe",
            "docker-scout.exe",
        ],
        &["docker inc"],
        pf: &[r"\docker\**"],
        profile: NONE,
        system: false,
        anywhere: false
    ),
];

/// Publishers whose image list contains `name` (lower-case file name).
pub fn publishers_for(name: &str) -> impl Iterator<Item = &'static Publisher> + '_ {
    PUBLISHERS
        .iter()
        .filter(move |p| p.images.iter().any(|i| glob_match(i, name)))
}

/// Exact signer match against a publisher's list.
pub fn signer_in(signers: &[&str], signer: Option<&str>) -> bool {
    let Some(s) = signer.map(|s| s.trim().to_ascii_lowercase()) else {
        return false;
    };
    if s.is_empty() {
        return false;
    }
    signers.iter().any(|x| {
        if *x == MICROSOFT {
            crate::protect::is_microsoft_signer(&s)
        } else {
            *x == s
        }
    })
}

/// Does `image` sit in one of the publisher's install locations?
fn location_ok(p: &Publisher, image: &str, path_class: PathClass, system_drive: char) -> bool {
    if p.anywhere
        && !matches!(
            path_class,
            PathClass::Temp | PathClass::Downloads | PathClass::External
        )
    {
        return true;
    }
    if !p.program_files.is_empty() {
        if let Some(sub) = crate::legit_apps::program_files_rest(image, system_drive) {
            if p.program_files.iter().any(|g| glob_match_path(g, &sub)) {
                return true;
            }
        }
    }
    if p.system && in_windows_dir(image, system_drive) {
        return true;
    }
    if !p.profile.is_empty() {
        let norm = normalize_path(image);
        if let Some(rel) = profile_relative(&norm) {
            if !rel.starts_with(r"appdata\local\temp\")
                && !rel.split('\\').any(|c| c == "..")
                && p.profile.iter().any(|g| glob_match_path(g, rel))
            {
                return true;
            }
        }
    }
    false
}

/// `\Windows\...` on the system volume (System32, SysWOW64, WinSxS, ...).
pub fn in_windows_dir(image: &str, system_drive: char) -> bool {
    crate::protect::on_system_volume(image, system_drive)
        .is_some_and(|r| r.starts_with(r"\windows\") && !r.split('\\').any(|c| c == ".."))
}

/// The location fallback for names not in [`PUBLISHERS`]: Program Files /
/// WindowsApps / Windows on the system volume, or below the profile's
/// `AppData\` (not its Temp folder).
pub fn generic_location_ok(image: &str, path_class: PathClass, system_drive: char) -> bool {
    if matches!(
        path_class,
        PathClass::Temp | PathClass::Downloads | PathClass::External
    ) {
        return false;
    }
    if crate::legit_apps::program_files_rest(image, system_drive).is_some()
        || in_windows_dir(image, system_drive)
    {
        return true;
    }
    let norm = normalize_path(image);
    profile_relative(&norm).is_some_and(|rel| {
        rel.starts_with(r"appdata\")
            && !rel.starts_with(r"appdata\local\temp\")
            && !rel.split('\\').any(|c| c == "..")
    })
}

/// Is `p` the application its image name claims (module docs)?
pub fn genuine(p: &ProcessInfo, system_drive: char, tampered: bool) -> bool {
    if tampered || p.image.is_empty() || p.signed != SignatureState::Valid {
        return false;
    }
    if p.signer.as_deref().is_none_or(|s| s.trim().is_empty()) {
        return false;
    }
    if matches!(
        p.path_class,
        PathClass::Temp | PathClass::Downloads | PathClass::External
    ) {
        return false;
    }
    let name = file_name(&p.image).to_ascii_lowercase();
    let mut listed = false;
    for pb in publishers_for(&name) {
        listed = true;
        if signer_in(pb.signers, p.signer.as_deref())
            && location_ok(pb, &p.image, p.path_class, system_drive)
        {
            return true;
        }
    }
    !listed && generic_location_ok(&p.image, p.path_class, system_drive)
}

/// Is the image file name listed in [`PUBLISHERS`]?
pub fn listed(image: &str) -> bool {
    let name = file_name(image).to_ascii_lowercase();
    let found = publishers_for(&name).next().is_some();
    found
}

/// Program Files / WindowsApps / Windows on the system volume: folders only
/// an administrator (or TrustedInstaller) can write.
pub fn admin_location(image: &str, system_drive: char) -> bool {
    crate::legit_apps::program_files_rest(image, system_drive).is_some()
        || in_windows_dir(image, system_drive)
}

/// A genuine browser: a [`crate::paths::BROWSER_IMAGES`] name that is
/// [`genuine`] and listed in [`PUBLISHERS`] (exact signer and install
/// location). Red-team round 2026-10-25: an unlisted minor-browser name
/// (`thorium.exe`, `kometa.exe`, ...) with any valid signer, in the profile
/// or in Program Files, is not a browser for the engine's shortcuts.
/// Copies, renamed stealers, stolen-certificate binaries and injected
/// browsers are not either.
pub fn genuine_browser(p: &ProcessInfo, system_drive: char, tampered: bool) -> bool {
    // Red-team round 2026-10-25: a folder is not an identity; only browsers
    // pinned to their publisher are browsers for the engine's shortcuts.
    crate::paths::is_browser_image(&p.image)
        && genuine(p, system_drive, tampered)
        && listed(&p.image)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pi(image: &str, signed: SignatureState, signer: Option<&str>) -> ProcessInfo {
        ProcessInfo {
            guid: Default::default(),
            pid: 1,
            ppid: 0,
            parent_guid: None,
            image: image.into(),
            cmdline: String::new(),
            user: None,
            integrity: None,
            start_ts: 0,
            exit_ts: None,
            signer: signer.map(str::to_string),
            signed,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::of_with_system_drive(image, 'c'),
        }
    }

    #[test]
    fn browsers_need_signer_and_location() {
        let ok = pi(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            SignatureState::Valid,
            Some("Google LLC"),
        );
        assert!(genuine_browser(&ok, 'c', false));
        assert!(!genuine_browser(&ok, 'c', true), "tainted");
        let per_user = pi(
            r"C:\Users\a\AppData\Local\Google\Chrome\Application\chrome.exe",
            SignatureState::Valid,
            Some("Google LLC"),
        );
        assert!(genuine_browser(&per_user, 'c', false));
        let stolen = pi(
            r"C:\Users\a\AppData\Local\Google\Chrome\Application\chrome.exe",
            SignatureState::Valid,
            Some("Shenzhen Yuanshi Network Technology Co., Ltd."),
        );
        assert!(!genuine_browser(&stolen, 'c', false));
        let copy = pi(
            r"C:\Users\a\AppData\Roaming\GoogleUpdateCache\chrome.exe",
            SignatureState::Valid,
            Some("Google LLC"),
        );
        assert!(!genuine_browser(&copy, 'c', false));
        let mock = pi(
            r"C:\Program Files \BraveSoftware\Brave-Browser\Application\brave.exe",
            SignatureState::Valid,
            Some("Brave Software, Inc."),
        );
        assert!(!genuine_browser(&mock, 'c', false));
        let edge_copy = pi(
            r"C:\ProgramData\EdgeCache\msedge.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        );
        assert!(!genuine_browser(&edge_copy, 'c', false));
    }

    #[test]
    fn system_hosts_and_squirrel_updaters() {
        let pxa = pi(
            r"C:\Users\Public\Windows\svchost.exe",
            SignatureState::Valid,
            Some("Python Software Foundation"),
        );
        assert!(!genuine(&pxa, 'c', false));
        let svc = pi(
            r"C:\Windows\System32\svchost.exe",
            SignatureState::Valid,
            Some("Microsoft Windows Publisher"),
        );
        assert!(genuine(&svc, 'c', false));
        let upd = pi(
            r"C:\Users\a\AppData\Local\Discord\Update.exe",
            SignatureState::Valid,
            Some("Guangzhou Kingsoft Network Technology Co., Ltd."),
        );
        assert!(!genuine(&upd, 'c', false));
        let real = pi(
            r"C:\Users\a\AppData\Local\Discord\Update.exe",
            SignatureState::Valid,
            Some("Discord Inc."),
        );
        assert!(genuine(&real, 'c', false));
    }

    #[test]
    fn unlisted_names_need_an_install_location() {
        let pf = pi(
            r"C:\Program Files\Foo\foo.exe",
            SignatureState::Valid,
            Some("Foo Ltd"),
        );
        assert!(genuine(&pf, 'c', false));
        let other_volume = pi(r"D:\tools\foo.exe", SignatureState::Valid, Some("Foo Ltd"));
        assert!(!genuine(&other_volume, 'c', false));
        let public = pi(
            r"C:\Users\Public\foo.exe",
            SignatureState::Valid,
            Some("Foo Ltd"),
        );
        assert!(!genuine(&public, 'c', false));
        let unsigned = pi(
            r"C:\Program Files\Foo\foo.exe",
            SignatureState::Unsigned,
            None,
        );
        assert!(!genuine(&unsigned, 'c', false));
    }
}
