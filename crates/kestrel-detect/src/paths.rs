//! Sensitive-path catalog (credential stores) and browser identification.
//! CONTRACT: the agent uses these to filter Kernel-File ETW at the source.
//!
//! Everything here is pure string matching on a *normalised* path (see
//! [`normalize_path`]): lower-case, `\` separators, `\\?\`, `\??\` and
//! `\Device\HarddiskVolumeN` prefixes stripped. Matching never touches the
//! filesystem and works for any drive letter or user name.
//!
//! The catalog covers what 2025-2026 stealers (Lumma, Vidar 2.0, StealC v2,
//! Acreed, Katz, ACR, RedLine successors) collect:
//! Chromium-family browsers (`Login Data`, `Network\Cookies`, `Web Data`,
//! `Local State`, wallet / password-manager extension LevelDB folders), Gecko
//! profiles (`key4.db`, `logins.json`, `cookies.sqlite`, `formhistory.sqlite`),
//! Discord, Telegram `tdata`, Steam `ssfn*` / `loginusers.vdf`, FTP clients,
//! desktop crypto wallets, cloud CLI / MSAL token caches, SSH keys, password
//! manager vaults, VPN profiles and mail stores.
//!
//! Data tables (owner images, benign readers, wallet extension ids) are public
//! so the console can show admins exactly what is trusted out of the box.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use kestrel_common::{DataCategory, PathClass, ProcessInfo, SignatureState};
use std::sync::OnceLock;

/// Which application legitimately owns a sensitive store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerApp {
    Chromium,
    Firefox,
    Discord,
    Telegram,
    Steam,
    FileZilla,
    WinScp,
    WalletApp,
    CloudCli,
    PasswordManager,
    Ssh,
    Other,
}

/// Full match result for a sensitive path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SensitiveStore {
    pub category: DataCategory,
    pub owner: OwnerApp,
    /// Human label of the application / store, e.g. "Chrome", "MetaMask", "AWS CLI".
    pub app: &'static str,
    /// What the file holds, e.g. "saved passwords", "cookies", "wallet".
    pub noun: &'static str,
    /// Image file names (lower-case, `*` glob allowed) that legitimately read this store.
    pub owners: &'static [&'static str],
}

/// Classify a file path as a sensitive credential store. Case-insensitive,
/// accepts `\` or `/`, any drive / user. Returns `None` for ordinary files.
pub fn classify_sensitive_path(path: &str) -> Option<(DataCategory, OwnerApp)> {
    match_sensitive_path(path).map(|s| (s.category, s.owner))
}

/// Like [`classify_sensitive_path`] but returns the full catalog entry.
pub fn match_sensitive_path(path: &str) -> Option<SensitiveStore> {
    if !may_be_sensitive(path) {
        return None;
    }
    let p = normalize_path(path);
    match_normalized(&p)
}

/// Classify a registry key holding saved credentials (for registry query
/// telemetry, e.g. SACL 4663 / registry ETW). Case-insensitive, any hive prefix.
pub fn classify_sensitive_registry(key: &str) -> Option<(DataCategory, OwnerApp)> {
    let k = key.to_ascii_lowercase().replace('/', "\\");
    if k.contains(r"\software\martin prikryl\winscp 2\sessions")
        || k.contains(r"\software\martin prikryl\winscp 2\configuration\security")
    {
        return Some((DataCategory::FtpClient, OwnerApp::WinScp));
    }
    if k.contains(r"\software\simontatham\putty\sessions")
        || k.contains(r"\software\simontatham\putty\sshhostkeys")
    {
        return Some((DataCategory::SshKeys, OwnerApp::Ssh));
    }
    if k.contains(r"\software\microsoft\office\") && k.contains(r"\outlook\profiles\")
        || k.contains(r"\windows messaging subsystem\profiles\")
    {
        return Some((DataCategory::Email, OwnerApp::Other));
    }
    if k.contains(r"\software\openvpn-gui\configs") || k.contains(r"\software\openvpn\") {
        return Some((DataCategory::Vpn, OwnerApp::Other));
    }
    if k.contains(r"\software\teamviewer")
        && (k.ends_with("securitypasswordaes") || k.ends_with("optionspasswordaes"))
    {
        return Some((DataCategory::PasswordManager, OwnerApp::Other));
    }
    if k.contains(r"\software\ftpware\coreftp\sites")
        || k.contains(r"\software\ghisler\total commander")
    {
        return Some((DataCategory::FtpClient, OwnerApp::FileZilla));
    }
    None
}

/// Cheap pre-filter for the ETW file sensor: true if the path *might* be
/// sensitive (substring check), so the sensor can drop everything else.
///
/// Guarantee: `classify_sensitive_path(p).is_some()` implies `may_be_sensitive(p)`.
/// Also passes Chromium `DevToolsActivePort` (ST-06) and canary folders (ST-16),
/// which live under `User Data`.
pub fn may_be_sensitive(path: &str) -> bool {
    prefilter().is_match(path)
}

/// Image file names of known browsers (chrome.exe, msedge.exe, brave.exe, firefox.exe, opera.exe, …).
pub fn is_browser_image(image_path: &str) -> bool {
    let name = file_name(image_path);
    BROWSER_IMAGES.iter().any(|b| name.eq_ignore_ascii_case(b))
}

/// Chromium-family browser executables (subset of [`BROWSER_IMAGES`]).
pub fn is_chromium_image(image_path: &str) -> bool {
    let name = file_name(image_path);
    CHROMIUM_IMAGES.iter().any(|b| name.eq_ignore_ascii_case(b))
}

/// Gecko-family (Mozilla) executables, the legitimate loaders of `nss3.dll` (ST-09).
pub fn is_mozilla_image(image_path: &str) -> bool {
    let name = file_name(image_path);
    MOZILLA_IMAGES.iter().any(|b| name.eq_ignore_ascii_case(b))
}

/// Every browser executable name (lower-case). Used for "non-browser" tests and owner checks.
pub const BROWSER_IMAGES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "browser.exe",
    "chromium.exe",
    "yandex.exe",
    "whale.exe",
    "arc.exe",
    "thorium.exe",
    "360chrome.exe",
    "360se.exe",
    "qqbrowser.exe",
    "sogouexplorer.exe",
    "ucbrowser.exe",
    "maxthon.exe",
    "slimjet.exe",
    "epic.exe",
    "avastbrowser.exe",
    "avgbrowser.exe",
    "ccleanerbrowser.exe",
    "torch.exe",
    "dragon.exe",
    "iridium.exe",
    "blisk.exe",
    "sidekick.exe",
    "duckduckgo.exe",
    "orbitum.exe",
    "amigo.exe",
    "kometa.exe",
    "sputnik.exe",
    "uran.exe",
    "chedot.exe",
    "nichrome.exe",
    "superbird.exe",
    "liebao.exe",
    "coowon.exe",
    "citrio.exe",
    "7star.exe",
    "atom.exe",
    "msedgewebview2.exe",
    "iexplore.exe",
    "firefox.exe",
    "waterfox.exe",
    "librewolf.exe",
    "palemoon.exe",
    "basilisk.exe",
    "seamonkey.exe",
    "floorp.exe",
    "zen.exe",
    "k-meleon.exe",
    "icedragon.exe",
    "cyberfox.exe",
    "mercury.exe",
    "falkon.exe",
];

/// Chromium-family browser executables.
pub const CHROMIUM_IMAGES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "browser.exe",
    "chromium.exe",
    "yandex.exe",
    "whale.exe",
    "arc.exe",
    "thorium.exe",
    "360chrome.exe",
    "360se.exe",
    "qqbrowser.exe",
    "sogouexplorer.exe",
    "maxthon.exe",
    "slimjet.exe",
    "epic.exe",
    "avastbrowser.exe",
    "avgbrowser.exe",
    "ccleanerbrowser.exe",
    "torch.exe",
    "dragon.exe",
    "iridium.exe",
    "blisk.exe",
    "sidekick.exe",
    "orbitum.exe",
    "amigo.exe",
    "kometa.exe",
    "sputnik.exe",
    "uran.exe",
    "chedot.exe",
    "nichrome.exe",
    "superbird.exe",
    "liebao.exe",
    "coowon.exe",
    "citrio.exe",
    "7star.exe",
    "atom.exe",
];

/// Gecko-family executables (legitimate `nss3.dll` loaders, Gecko store owners).
pub const MOZILLA_IMAGES: &[&str] = &[
    "firefox.exe",
    "thunderbird.exe",
    "waterfox.exe",
    "librewolf.exe",
    "palemoon.exe",
    "basilisk.exe",
    "seamonkey.exe",
    "floorp.exe",
    "zen.exe",
    "k-meleon.exe",
    "icedragon.exe",
    "cyberfox.exe",
    "mercury.exe",
    "plugin-container.exe",
    "crashreporter.exe",
    "updater.exe",
    "maintenanceservice.exe",
    "default-browser-agent.exe",
    "pingsender.exe",
    "private_browsing.exe",
];

/// Owners of Chromium stores besides the browsers themselves (helpers shipped in the browser dir).
const CHROMIUM_HELPERS: &[&str] = &[
    "elevation_service.exe",
    "chrome_proxy.exe",
    "chrome_pwa_launcher.exe",
    "notification_helper.exe",
    "cookie_exporter.exe",
    "identity_helper.exe",
    "msedge_pwa_launcher.exe",
    "browser_broker.exe",
];

// ---------------------------------------------------------------------------
// Owner image lists per store family (lower-case file names, `*` glob allowed).
// Browsers are trusted readers of every browser store (password import between
// browsers is a product feature), see `is_trusted_owner`.
// ---------------------------------------------------------------------------

const O_CHROMIUM: &[&str] = &[
    "elevation_service.exe",
    "chrome_proxy.exe",
    "chrome_pwa_launcher.exe",
    "notification_helper.exe",
    "cookie_exporter.exe",
    "identity_helper.exe",
    "msedge_pwa_launcher.exe",
];
const O_GECKO: &[&str] = &[
    "firefox.exe",
    "waterfox.exe",
    "librewolf.exe",
    "palemoon.exe",
    "basilisk.exe",
    "seamonkey.exe",
    "floorp.exe",
    "zen.exe",
    "k-meleon.exe",
    "icedragon.exe",
    "cyberfox.exe",
    "mercury.exe",
    "crashreporter.exe",
    "pingsender.exe",
    "default-browser-agent.exe",
];
const O_THUNDERBIRD: &[&str] = &["thunderbird.exe", "crashreporter.exe", "betterbird.exe"];
const O_DISCORD: &[&str] = &[
    "discord.exe",
    "discordptb.exe",
    "discordcanary.exe",
    "discorddevelopment.exe",
    "lightcord.exe",
    "update.exe",
];
const O_TELEGRAM: &[&str] = &[
    "telegram.exe",
    "updater.exe",
    "ayugram.exe",
    "kotatogram.exe",
    "64gram.exe",
];
const O_STEAM: &[&str] = &[
    "steam.exe",
    "steamservice.exe",
    "steamwebhelper.exe",
    "gameoverlayui.exe",
    "steamerrorreporter.exe",
    "steamerrorreporter64.exe",
];
const O_FILEZILLA: &[&str] = &[
    "filezilla.exe",
    "fzsftp.exe",
    "fzputtygen.exe",
    "fzstorj.exe",
];
const O_WINSCP: &[&str] = &["winscp.exe", "winscp.com"];
const O_TOTALCMD: &[&str] = &["totalcmd.exe", "totalcmd64.exe"];
const O_SMARTFTP: &[&str] = &["smartftp.exe"];
const O_EXODUS: &[&str] = &["exodus.exe", "update.exe"];
const O_ELECTRUM: &[&str] = &["electrum*.exe", "electron-cash*.exe"];
const O_ATOMIC: &[&str] = &["atomic wallet.exe", "atomicwallet.exe"];
const O_ARMORY: &[&str] = &["armoryqt.exe", "armorydb.exe"];
const O_BITCOIN: &[&str] = &[
    "bitcoin-qt.exe",
    "bitcoind.exe",
    "litecoin-qt.exe",
    "litecoind.exe",
    "dash-qt.exe",
    "dogecoin-qt.exe",
    "zcashd.exe",
    "bitcoin-wallet.exe",
];
const O_COINOMI: &[&str] = &["coinomi.exe"];
const O_GUARDA: &[&str] = &["guarda.exe"];
const O_JAXX: &[&str] = &["jaxx liberty.exe", "jaxx.exe"];
const O_LEDGER: &[&str] = &["ledger live.exe"];
const O_WASABI: &[&str] = &[
    "wassabee.exe",
    "wasabi wallet.exe",
    "wasabiwallet.fluent.desktop.exe",
    "wassabeed.exe",
];
const O_MONERO: &[&str] = &[
    "monero-wallet-gui.exe",
    "monero-wallet-rpc.exe",
    "monerod.exe",
];
const O_GETH: &[&str] = &["geth.exe", "mist.exe"];
const O_DAEDALUS: &[&str] = &["daedalus.exe", "cardano-wallet.exe", "cardano-node.exe"];
const O_BINANCE: &[&str] = &["binance.exe"];
// Owner's PC 2026-10-22: generic interpreters (python, pythonw, node, java,
// javaw) are no longer owners of the AWS stores by file name: they run any
// script, so a stealer script under a signed python.exe was silent. Their
// reads now raise ST-01; a following send to AWS itself is a High Audit ST-04
// (`legit_apps::provider_endpoint`), anywhere else the full ST-04. The AWS CLI v2 (`aws.exe`) is
// a frozen executable and stays an owner.
const O_AWS: &[&str] = &[
    "aws.exe",
    "aws_completer.exe",
    "terraform.exe",
    "pulumi.exe",
    "code.exe",
    "session-manager-plugin.exe",
    "sam.exe",
    "cdk.exe",
];
// python / pythonw removed 2026-10-22: only the Azure CLI's bundled
// interpreter owns the store (`legit_apps::bundled_cli_python`).
const O_AZURE: &[&str] = &[
    "az.exe",
    "azcopy.exe",
    "terraform.exe",
    "pulumi.exe",
    "devenv.exe",
    "code.exe",
    "func.exe",
    "azd.exe",
    "pwsh.exe",
    "powershell_ise.exe",
];
const O_IDENTITYSERVICE: &[&str] = &[
    "devenv.exe",
    "servicehub.identityhost.exe",
    "servicehub.host.dotnet.x64.exe",
    "servicehub.host.netfx.x86.exe",
    "msbuild.exe",
    "dotnet.exe",
    "code.exe",
    "azuredatastudio.exe",
    "ssms.exe",
    "sqlpackage.exe",
];
const O_TOKENBROKER: &[&str] = &[
    "svchost.exe",
    "microsoft.aad.brokerplugin.exe",
    "backgroundtaskhost.exe",
    "runtimebroker.exe",
    "tokenbrokerhost.exe",
    // WAM clients read the cache in-process (lab VM: msedge.exe).
    "msedge.exe",
    "msedgewebview2.exe",
    "onedrive.exe",
    "ms-teams.exe",
    // Office (WINWORD, EXCEL, POWERPNT, OUTLOOK, olk) is deliberately not an
    // owner (re-review N2, 2026-10-21): VBA runs arbitrary code in it. Its
    // token-cache reads go through `legit_apps::wam_client_reader` instead:
    // a Low Audit ST-01 that is recorded for ST-02 / ST-04 correlation.
];
// python, pythonw, java, node removed 2026-10-22: only the Google Cloud
// CLI's bundled interpreter owns the store (`legit_apps::bundled_cli_python`).
const O_GCLOUD: &[&str] = &[
    "gcloud.exe",
    "gsutil.exe",
    "bq.exe",
    "terraform.exe",
    "pulumi.exe",
    "code.exe",
];
const O_KUBE: &[&str] = &[
    "kubectl.exe",
    "helm.exe",
    "k9s.exe",
    "lens.exe",
    "openlens.exe",
    "kubelogin.exe",
    "minikube.exe",
    "kind.exe",
    "docker desktop.exe",
    "com.docker.backend.exe",
    "terraform.exe",
    "code.exe",
    "rancher desktop.exe",
    "kubectx.exe",
    "kubens.exe",
];
const O_DOCKER: &[&str] = &[
    "docker.exe",
    "docker desktop.exe",
    "com.docker.backend.exe",
    "com.docker.build.exe",
    "docker-credential-desktop.exe",
    "docker-credential-wincred.exe",
    "docker-compose.exe",
    "code.exe",
    "rancher desktop.exe",
    "podman.exe",
];
const O_GIT: &[&str] = &[
    "git.exe",
    "git-credential-manager.exe",
    "git-credential-manager-core.exe",
    "git-credential-store.exe",
    "git-remote-https.exe",
    "githubdesktop.exe",
    "sourcetree.exe",
    "code.exe",
];
const O_GH: &[&str] = &[
    "gh.exe",
    "git.exe",
    "git-credential-manager.exe",
    "code.exe",
];
const O_NGROK: &[&str] = &["ngrok.exe"];
const O_TERRAFORM: &[&str] = &["terraform.exe", "terraform-ls.exe", "tofu.exe"];
const O_SSH: &[&str] = &[
    "ssh.exe",
    "ssh-agent.exe",
    "ssh-add.exe",
    "ssh-keygen.exe",
    "scp.exe",
    "sftp.exe",
    "git.exe",
    "git-remote-https.exe",
    "putty.exe",
    "pageant.exe",
    "plink.exe",
    "pscp.exe",
    "psftp.exe",
    "puttygen.exe",
    "kitty.exe",
    "winscp.exe",
    "filezilla.exe",
    "fzsftp.exe",
    "mobaxterm.exe",
    "termius.exe",
    "tortoiseplink.exe",
    "code.exe",
    "windowsterminal.exe",
    "sshd.exe",
    "githubdesktop.exe",
    "sourcetree.exe",
];
const O_KEEPASS: &[&str] = &[
    "keepass.exe",
    "keepassxc.exe",
    "keepassxc-proxy.exe",
    "keeweb.exe",
    "kpcli.exe",
    "strongbox.exe",
    "keepassium.exe",
];
const O_BITWARDEN: &[&str] = &["bitwarden.exe"];
const O_1PASSWORD: &[&str] = &["1password.exe", "1password-browsersupport.exe", "op.exe"];
const O_WINCRED: &[&str] = &["lsass.exe", "svchost.exe"];
const O_OPENVPN: &[&str] = &[
    "openvpn.exe",
    "openvpn-gui.exe",
    "openvpnconnect.exe",
    "openvpnserv.exe",
    "openvpnserv2.exe",
    "ovpnconnector.exe",
    "agent_ovpnconnect*.exe",
];
const O_NORDVPN: &[&str] = &[
    "nordvpn.exe",
    "nordvpn-service.exe",
    "nordupdateservice.exe",
];
const O_PROTONVPN: &[&str] = &[
    "protonvpn.exe",
    "protonvpnservice.exe",
    "protonvpn.client.exe",
    "protonvpn.launcher.exe",
    "protonvpn.wireguardservice.exe",
];
const O_WIREGUARD: &[&str] = &["wireguard.exe"];
const O_OUTLOOK: &[&str] = &[
    "outlook.exe",
    "olk.exe",
    "scanpst.exe",
    "mspub.exe",
    "winword.exe",
    "excel.exe",
    "ucmapi.exe",
    "lync.exe",
];
const O_MAILBIRD: &[&str] = &["mailbird.exe"];
const O_SLACK: &[&str] = &["slack.exe"];

/// Union of owner image names per [`OwnerApp`] (lower-case, `*` glob allowed).
/// ST-01 uses the per-store list from [`SensitiveStore::owners`]; this is the
/// admin-facing view ("who may read Telegram's tdata?").
pub fn owner_images(owner: OwnerApp) -> Vec<&'static str> {
    let lists: &[&[&str]] = match owner {
        OwnerApp::Chromium => &[CHROMIUM_IMAGES, CHROMIUM_HELPERS],
        OwnerApp::Firefox => &[O_GECKO, O_THUNDERBIRD],
        OwnerApp::Discord => &[O_DISCORD],
        OwnerApp::Telegram => &[O_TELEGRAM],
        OwnerApp::Steam => &[O_STEAM],
        OwnerApp::FileZilla => &[O_FILEZILLA, O_TOTALCMD, O_SMARTFTP],
        OwnerApp::WinScp => &[O_WINSCP],
        OwnerApp::WalletApp => &[
            O_EXODUS, O_ELECTRUM, O_ATOMIC, O_ARMORY, O_BITCOIN, O_COINOMI, O_GUARDA, O_JAXX,
            O_LEDGER, O_WASABI, O_MONERO, O_GETH, O_DAEDALUS, O_BINANCE,
        ],
        OwnerApp::CloudCli => &[
            O_AWS,
            O_AZURE,
            O_IDENTITYSERVICE,
            O_TOKENBROKER,
            O_GCLOUD,
            O_KUBE,
            O_DOCKER,
            O_GIT,
            O_GH,
            O_NGROK,
            O_TERRAFORM,
        ],
        OwnerApp::PasswordManager => &[O_KEEPASS, O_BITWARDEN, O_1PASSWORD, O_WINCRED],
        OwnerApp::Ssh => &[O_SSH],
        OwnerApp::Other => &[
            O_OPENVPN,
            O_NORDVPN,
            O_PROTONVPN,
            O_WIREGUARD,
            O_OUTLOOK,
            O_MAILBIRD,
            O_SLACK,
        ],
    };
    let mut v: Vec<&'static str> = lists.iter().flat_map(|l| l.iter().copied()).collect();
    v.sort_unstable();
    v.dedup();
    v
}

// ---------------------------------------------------------------------------
// Browser vendors (Chromium "User Data" roots, SigmaHQ a1dfd976 vendor list)
// ---------------------------------------------------------------------------

/// Chromium vendor folders: (path needle relative to AppData, display name).
/// The needle is matched against the part of the path *before* `\User Data\`.
pub const CHROMIUM_VENDORS: &[(&str, &str)] = &[
    (r"\google\chrome sxs", "Chrome Canary"),
    (r"\google\chrome beta", "Chrome Beta"),
    (r"\google\chrome dev", "Chrome Dev"),
    (r"\google\chrome", "Chrome"),
    (r"\microsoft\edge sxs", "Edge Canary"),
    (r"\microsoft\edge beta", "Edge Beta"),
    (r"\microsoft\edge dev", "Edge Dev"),
    (r"\microsoft\edge", "Edge"),
    (r"\bravesoftware\brave-browser-beta", "Brave Beta"),
    (r"\bravesoftware\brave-browser-nightly", "Brave Nightly"),
    (r"\bravesoftware\brave-browser", "Brave"),
    (r"\vivaldi", "Vivaldi"),
    (r"\yandex\yandexbrowser", "Yandex Browser"),
    (r"\chromium", "Chromium"),
    (r"\coccoc\browser", "CocCoc"),
    (r"\360browser\browser", "360 Browser"),
    (r"\360chrome\chrome", "360 Chrome"),
    (r"\360se6", "360 Secure Browser"),
    (r"\tencent\qqbrowser", "QQ Browser"),
    (r"\naver\naver whale", "Naver Whale"),
    (r"\thorium", "Thorium"),
    (r"\arc", "Arc"),
    (r"\epic privacy browser", "Epic Privacy Browser"),
    (r"\comodo\dragon", "Comodo Dragon"),
    (r"\centbrowser", "CentBrowser"),
    (r"\chedot", "Chedot"),
    (r"\amigo", "Amigo"),
    (r"\kometa", "Kometa"),
    (r"\orbitum", "Orbitum"),
    (r"\sputnik\sputnik", "Sputnik"),
    (r"\torch", "Torch"),
    (r"\ucozmedia\uran", "Uran"),
    (r"\nichrome", "Nichrome"),
    (r"\elements browser", "Elements Browser"),
    (r"\qip surf", "QIP Surf"),
    (r"\catalinagroup\citrio", "Citrio"),
    (r"\coowon\coowon", "Coowon"),
    (r"\liebao", "Liebao"),
    (r"\7star\7star", "7Star"),
    (r"\iridium", "Iridium"),
    (r"\slimjet", "Slimjet"),
    (r"\blisk", "Blisk"),
    (r"\superbird", "Superbird"),
    (r"\mail.ru\atom", "Atom"),
    (r"\avast software\browser", "Avast Secure Browser"),
    (r"\avg\browser", "AVG Secure Browser"),
    (r"\ccleaner browser", "CCleaner Browser"),
    (r"\kinza", "Kinza"),
    (r"\xpom", "Xpom"),
    (r"\go!", "Go!"),
    (r"\rafotech\mustang", "Mustang"),
    (r"\salamweb", "SalamWeb"),
    (r"\maxthon3", "Maxthon"),
    (r"\maxthon5", "Maxthon"),
    (r"\sidekick", "Sidekick"),
    (r"\duckduckgo", "DuckDuckGo"),
    (r"\ungoogled-chromium", "Ungoogled Chromium"),
    (r"\cromite", "Cromite"),
];

/// Opera keeps its profile directly under `Opera Software\<channel>`.
const OPERA_CHANNELS: &[(&str, &str)] = &[
    ("opera gx stable", "Opera GX"),
    ("opera stable", "Opera"),
    ("opera neon", "Opera Neon"),
    ("opera beta", "Opera Beta"),
    ("opera developer", "Opera Developer"),
    ("opera air stable", "Opera Air"),
];

/// Gecko family profile roots: (needle, display name, is mail client).
const GECKO_VENDORS: &[(&str, &str, bool)] = &[
    (r"\mozilla\firefox", "Firefox", false),
    (r"\thunderbird", "Thunderbird", true),
    (r"\betterbird", "Betterbird", true),
    (r"\waterfox", "Waterfox", false),
    (r"\librewolf", "LibreWolf", false),
    (r"\moonchild productions\pale moon", "Pale Moon", false),
    (r"\moonchild productions\basilisk", "Basilisk", false),
    (r"\mozilla\seamonkey", "SeaMonkey", false),
    (r"\floorp", "Floorp", false),
    (r"\zen", "Zen Browser", false),
    (r"\mercury", "Mercury", false),
    (r"\comodo\icedragon", "IceDragon", false),
    (r"\8pecxstudios\cyberfox", "Cyberfox", false),
    (r"\k-meleon", "K-Meleon", false),
    (r"\netgate technologies\blackhawk", "BlackHawk", false),
    (r"\tor browser", "Tor Browser", false),
    (r"\mullvad browser", "Mullvad Browser", false),
];

/// Crypto-wallet browser extensions (Chrome Web Store / Edge Add-ons ids) → name.
/// Matched under `Local Extension Settings\<id>`, `Sync Extension Settings\<id>`
/// and `IndexedDB\chrome-extension_<id>_0.indexeddb.leveldb`.
pub const WALLET_EXTENSIONS: &[(&str, &str)] = &[
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("ejbalbakoplchlghecdalmeeeajnimhm", "MetaMask (Edge)"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
    ("fhbohimaelbohpjbbldcngcnapndodjp", "Binance Wallet"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet"),
    ("aholpfdialjgjfhomihkjbmgjidlcdno", "Exodus Web3 Wallet"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "OKX Wallet"),
    ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby Wallet"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
    ("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
    ("afbcbjpbpfadlkmhmclhkeeodmamcflc", "Math Wallet"),
    ("aeachknmefphepccionboohckonoeemg", "Coin98"),
    ("jiidiaalihmmhddjgbnbgdfflelocpak", "Bitget Wallet"),
    ("ffnbelfdoeiohenkjibnmadjiehjhajb", "Yoroi"),
    ("lpfcbjknijpeeillifnkikgncikgfhdo", "Nami"),
    ("hpglfhgfnhbgpjdenjgmdgoeiappafln", "Guarda (extension)"),
    (
        "cjelfplplebdjjenllpjcblmjkfcffne",
        "Jaxx Liberty (extension)",
    ),
    ("kncchdigobghenbbaddojjnnaogfppfj", "iWallet"),
    ("amkmjjmmflddogmhpjloimipbofnfjih", "Wombat"),
    ("nlbmnnijcnlegkjjpcfjclmcfggfefdm", "MEW CX"),
    ("nkddgncdjgjfcddamfgcmfnlhccnimig", "Saturn Wallet"),
    ("aiifbnbfobpmeekipheeijimdpnlpgpp", "Terra Station"),
    ("fnnegphlobjdpkhecapkijjdkgcjhkib", "Harmony"),
    ("kpfopkelmapcoipemfendmdcghnegimn", "Liquality"),
    ("opcgpfmipidbgpenhmajoajpbobppdil", "Sui Wallet"),
    ("efbglgofoippbgcjepnhiblaibcnclgk", "Martian"),
    ("ejjladinnckdgjemekebdpeokbikhfci", "Petra"),
    ("jnlgamecbpmbajjfhmmmlhejkemejdma", "Braavos"),
    ("dlcobpjiigpikoobohmabehhmhfoodbb", "Argent X"),
    ("fcfcfllfndlomdhbehjjcoimbgofdncg", "Leap Cosmos"),
    ("agoakfejjabomempkjlepdflaleeobhb", "Core (Avalanche)"),
    ("hmeobnfnfcmdkdcmlblgagmfpfboieaf", "XDEFI / Ctrl"),
    ("kkpllkodjeloidieedojogacfhpaihoh", "Enkrypt"),
    ("mfgccjchihfkkindfppnaooecgfneiii", "TokenPocket"),
    ("lgmpcpglpngdoalbgeoldeajfclnhafa", "SafePal"),
];

/// Password-manager / authenticator browser extensions → name (category PasswordManager).
pub const PASSWORD_MANAGER_EXTENSIONS: &[(&str, &str)] = &[
    ("nngceckbapebfimnlniiiahkandclblb", "Bitwarden (extension)"),
    ("aeblfdkhhhdcdjpifhhbdiojplfjncoa", "1Password (extension)"),
    ("hdokiejnpimakedhajhdlcegeplioahd", "LastPass (extension)"),
    ("fdjamakpfbbddfjaooikfcpapjohcfmg", "Dashlane (extension)"),
    ("fooolghllnmhmmndgjiamiiodkpenpbb", "NordPass (extension)"),
    ("oboonakemofpalcgghocfoadofidjkkk", "KeePassXC-Browser"),
    ("bfogiafebfohielmmehodmfbbebbbpei", "Keeper (extension)"),
    ("pnlccmojcmeohlpggmfnbbiapkmbliob", "RoboForm (extension)"),
    (
        "ghmbeldphafepmbegfdlkpapadhbakde",
        "Proton Pass (extension)",
    ),
    (
        "bhghoamapcdpbohphigoooaddinpkbai",
        "Authenticator (2FA extension)",
    ),
];

// ---------------------------------------------------------------------------
// Benign readers (shipped allow-list)
// ---------------------------------------------------------------------------

/// Where a benign reader is allowed to read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenignScope {
    /// Any sensitive store.
    AllStores,
    /// Only stores whose normalised path contains this substring (sync clients reading their own folder).
    PathContains(&'static str),
    /// Only stores of these categories.
    Categories(&'static [DataCategory]),
}

/// What kind of product a benign reader is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BenignKind {
    /// Windows Search indexer.
    Indexer,
    /// Antivirus / EDR (also exempt from ST-07 browser-access checks).
    Security,
    PasswordManager,
    Backup,
    Cleaner,
    SyncClient,
    Management,
}

/// Built-in allow-listed reader of credential stores (known benign false positives).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenignReader {
    /// Image file name, lower-case, `*` glob allowed.
    pub image: &'static str,
    pub kind: BenignKind,
    /// Required Authenticode signer substring (case-insensitive), when the agent knows the signer.
    pub signer: Option<&'static str>,
    pub scope: BenignScope,
    pub reason: &'static str,
}

const BROWSER_CATS: &[DataCategory] = &[
    DataCategory::BrowserPasswords,
    DataCategory::BrowserCookies,
    DataCategory::BrowserAutofill,
    DataCategory::BrowserMasterKey,
];

/// Shipped allow-list of benign credential-store readers (password managers,
/// backup agents, Windows Search, Defender / AV, cleaners, sync clients, SCCM/Intune).
/// A reader only qualifies when it is not unsigned / invalidly signed and does
/// not run from Temp / Downloads / removable media.
pub const BENIGN_READERS: &[BenignReader] = &[
    // Windows Search indexer reads everything it indexes.
    BenignReader {
        kind: BenignKind::Indexer,
        image: "searchprotocolhost.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Windows Search indexer",
    },
    BenignReader {
        kind: BenignKind::Indexer,
        image: "searchindexer.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Windows Search indexer",
    },
    BenignReader {
        kind: BenignKind::Indexer,
        image: "searchfilterhost.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Windows Search indexer",
    },
    // Microsoft Defender / MDE.
    BenignReader {
        kind: BenignKind::Security,
        image: "msmpeng.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender Antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "mpdefendercoreservice.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender Antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "nissrv.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender Network Inspection",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "mpcmdrun.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender command-line scanner",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "mssense.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender for Endpoint sensor",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "sensendr.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender for Endpoint sensor",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "senseir.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Microsoft Defender for Endpoint live response",
    },
    // Third-party AV / EDR.
    BenignReader {
        kind: BenignKind::Security,
        image: "avp.exe",
        signer: Some("kaspersky"),
        scope: BenignScope::AllStores,
        reason: "Kaspersky antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "ekrn.exe",
        signer: Some("eset"),
        scope: BenignScope::AllStores,
        reason: "ESET antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "csfalconservice.exe",
        signer: Some("crowdstrike"),
        scope: BenignScope::AllStores,
        reason: "CrowdStrike Falcon",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "sentinelagent.exe",
        signer: Some("sentinel"),
        scope: BenignScope::AllStores,
        reason: "SentinelOne agent",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "mbamservice.exe",
        signer: Some("malwarebytes"),
        scope: BenignScope::AllStores,
        reason: "Malwarebytes",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "avastsvc.exe",
        signer: Some("avast"),
        scope: BenignScope::AllStores,
        reason: "Avast antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "avgsvc.exe",
        signer: Some("avast"),
        scope: BenignScope::AllStores,
        reason: "AVG antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "mcshield.exe",
        signer: Some("mcafee"),
        scope: BenignScope::AllStores,
        reason: "McAfee antivirus",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "elastic-endpoint.exe",
        signer: Some("elastic"),
        scope: BenignScope::AllStores,
        reason: "Elastic Defend",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "cyserver.exe",
        signer: Some("palo alto"),
        scope: BenignScope::AllStores,
        reason: "Cortex XDR",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "ntrtscan.exe",
        signer: Some("trend micro"),
        scope: BenignScope::AllStores,
        reason: "Trend Micro Apex One",
    },
    // Password managers importing browser passwords.
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "keepass.exe",
        signer: None,
        scope: BenignScope::AllStores,
        reason: "KeePass (vault owner / browser import)",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "keepassxc.exe",
        signer: None,
        scope: BenignScope::AllStores,
        reason: "KeePassXC (vault owner / browser import)",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "bitwarden.exe",
        signer: Some("bitwarden"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "Bitwarden browser import",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "1password.exe",
        signer: Some("agilebits"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "1Password browser import",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "dashlane.exe",
        signer: Some("dashlane"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "Dashlane browser import",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "nordpass.exe",
        signer: Some("nord"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "NordPass browser import",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "roboform.exe",
        signer: Some("siber"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "RoboForm browser import",
    },
    BenignReader {
        kind: BenignKind::PasswordManager,
        image: "enpass.exe",
        signer: Some("enpass"),
        scope: BenignScope::Categories(BROWSER_CATS),
        reason: "Enpass browser import",
    },
    // Backup agents.
    BenignReader {
        kind: BenignKind::Backup,
        image: "veeam.endpoint.service.exe",
        signer: Some("veeam"),
        scope: BenignScope::AllStores,
        reason: "Veeam Agent backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "veeamagent.exe",
        signer: Some("veeam"),
        scope: BenignScope::AllStores,
        reason: "Veeam Agent backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "bztransmit.exe",
        signer: Some("backblaze"),
        scope: BenignScope::AllStores,
        reason: "Backblaze backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "bztransmit64.exe",
        signer: Some("backblaze"),
        scope: BenignScope::AllStores,
        reason: "Backblaze backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "bzfilelist.exe",
        signer: Some("backblaze"),
        scope: BenignScope::AllStores,
        reason: "Backblaze backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "carboniteservice.exe",
        signer: Some("carbonite"),
        scope: BenignScope::AllStores,
        reason: "Carbonite backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "code42service.exe",
        signer: Some("code42"),
        scope: BenignScope::AllStores,
        reason: "Code42 / CrashPlan backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "crashplanservice.exe",
        signer: Some("code42"),
        scope: BenignScope::AllStores,
        reason: "Code42 / CrashPlan backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "reflectbin.exe",
        signer: Some("paramount"),
        scope: BenignScope::AllStores,
        reason: "Macrium Reflect backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "wbengine.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Windows Server Backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "cbbackupplan.exe",
        signer: Some("msp360"),
        scope: BenignScope::AllStores,
        reason: "MSP360 (CloudBerry) backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "acronis_agent.exe",
        signer: Some("acronis"),
        scope: BenignScope::AllStores,
        reason: "Acronis backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "datto*.exe",
        signer: Some("datto"),
        scope: BenignScope::AllStores,
        reason: "Datto backup agent",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "veeam*.exe",
        signer: Some("veeam"),
        scope: BenignScope::AllStores,
        reason: "Veeam backup",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "scanstate.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "USMT user-state migration",
    },
    BenignReader {
        kind: BenignKind::Backup,
        image: "filehistory.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Windows File History",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "sophos*.exe",
        signer: Some("sophos"),
        scope: BenignScope::AllStores,
        reason: "Sophos endpoint",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "bdservicehost.exe",
        signer: Some("bitdefender"),
        scope: BenignScope::AllStores,
        reason: "Bitdefender",
    },
    BenignReader {
        kind: BenignKind::Security,
        image: "epsecurityservice.exe",
        signer: Some("bitdefender"),
        scope: BenignScope::AllStores,
        reason: "Bitdefender GravityZone",
    },
    // Cleaners.
    BenignReader {
        kind: BenignKind::Cleaner,
        image: "ccleaner.exe",
        signer: Some("piriform"),
        scope: BenignScope::AllStores,
        reason: "CCleaner",
    },
    BenignReader {
        kind: BenignKind::Cleaner,
        image: "ccleaner64.exe",
        signer: Some("piriform"),
        scope: BenignScope::AllStores,
        reason: "CCleaner",
    },
    BenignReader {
        kind: BenignKind::Cleaner,
        image: "bleachbit.exe",
        signer: None,
        scope: BenignScope::AllStores,
        reason: "BleachBit",
    },
    BenignReader {
        kind: BenignKind::Cleaner,
        image: "bleachbit_console.exe",
        signer: None,
        scope: BenignScope::AllStores,
        reason: "BleachBit",
    },
    BenignReader {
        kind: BenignKind::Cleaner,
        image: "privazer.exe",
        signer: None,
        scope: BenignScope::AllStores,
        reason: "PrivaZer",
    },
    // Sync clients reading their own folders (e.g. a .kdbx vault kept in OneDrive).
    BenignReader {
        kind: BenignKind::SyncClient,
        image: "onedrive.exe",
        signer: Some("microsoft"),
        scope: BenignScope::PathContains(r"\onedrive"),
        reason: "OneDrive sync of its own folder",
    },
    BenignReader {
        kind: BenignKind::SyncClient,
        image: "dropbox.exe",
        signer: Some("dropbox"),
        scope: BenignScope::PathContains(r"\dropbox"),
        reason: "Dropbox sync of its own folder",
    },
    BenignReader {
        kind: BenignKind::SyncClient,
        image: "googledrivefs.exe",
        signer: Some("google"),
        scope: BenignScope::PathContains(r"\my drive\"),
        reason: "Google Drive sync of its own folder",
    },
    BenignReader {
        kind: BenignKind::SyncClient,
        image: "box.exe",
        signer: Some("box"),
        scope: BenignScope::PathContains(r"\box\"),
        reason: "Box Drive sync of its own folder",
    },
    BenignReader {
        kind: BenignKind::SyncClient,
        image: "nextcloud.exe",
        signer: None,
        scope: BenignScope::PathContains(r"\nextcloud\"),
        reason: "Nextcloud sync of its own folder",
    },
    // Endpoint management.
    BenignReader {
        kind: BenignKind::Management,
        image: "ccmexec.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "SCCM / ConfigMgr client inventory",
    },
    BenignReader {
        kind: BenignKind::Management,
        image: "microsoft.management.services.intunewindowsagent.exe",
        signer: Some("microsoft"),
        scope: BenignScope::AllStores,
        reason: "Intune management extension",
    },
];

/// Processes that read *everything* and therefore must never trip the ST-16
/// canary tripwire (in addition to the Kestrel agent itself and PID 4/System).
pub const CANARY_IGNORED_READERS: &[&str] = &[
    "searchprotocolhost.exe",
    "searchindexer.exe",
    "searchfilterhost.exe",
    // Malicious Software Removal Tool (monthly Windows Update scan) reads
    // every file in user profiles; seen opening a decoy in the lab VM.
    "mrt.exe",
    // Optimize Drives (defrag / TRIM / slab consolidation) opens every file to
    // move its clusters; seen reading a decoy profile in the lab VM.
    "defrag.exe",
    "msmpeng.exe",
    "mpdefendercoreservice.exe",
    "nissrv.exe",
    "mpcmdrun.exe",
    "mssense.exe",
    "sensendr.exe",
    // Windows backup / migration (Microsoft-signed): File History, Windows
    // Backup, USMT, Volume Shadow Copy.
    "filehistory.exe",
    "sdclt.exe",
    "wbengine.exe",
    "scanstate.exe",
    "loadstate.exe",
    "vssvc.exe",
];

/// Does `proc_` read files for indexing / scanning / backup and therefore
/// must not trip ST-16? Requires a SYSTEM token, a trusted location and a
/// **valid** signature:
/// either a Microsoft-signed image on [`CANARY_IGNORED_READERS`], or an
/// allow-listed security / indexer / backup / management product
/// ([`BENIGN_READERS`]) whose signer matches.
/// Windows services that open files for storage maintenance and run inside
/// the shared `svchost.exe` (so the image name alone says nothing): the
/// Optimize Drives service (`svchost.exe -k defragsvc`). Microsoft-signed, at
/// its exact System32 location on the system volume, running as SYSTEM and
/// started by System32 `services.exe` (V-M12: a user-started, hollowed
/// `svchost -k defragsvc` has the user's token and an untrusted parent).
pub fn is_os_file_maintenance_host(proc_: &ProcessInfo, parent: Option<&ProcessInfo>) -> bool {
    if proc_.signed != SignatureState::Valid
        || !proc_
            .signer
            .as_deref()
            .is_some_and(crate::protect::is_microsoft_signer)
        || proc_.path_class != kestrel_common::PathClass::System
        || !file_name(&proc_.image).eq_ignore_ascii_case("svchost.exe")
        || !crate::util::is_system_user(proc_.user.as_deref())
    {
        return false;
    }
    let scm_parent = parent.is_some_and(|p| {
        file_name(&p.image).eq_ignore_ascii_case("services.exe")
            && p.path_class == kestrel_common::PathClass::System
    });
    if !scm_parent {
        return false;
    }
    let cmd = proc_.cmdline.to_ascii_lowercase();
    let mut args = cmd.split_whitespace();
    while let Some(a) = args.next() {
        if a == "-k" {
            return args.next() == Some("defragsvc");
        }
    }
    false
}

pub fn is_canary_ignored_reader(proc_: &ProcessInfo, parent: Option<&ProcessInfo>) -> bool {
    if is_untrusted_location_or_signature(proc_) || proc_.signed != SignatureState::Valid {
        return false;
    }
    // V-M12: every exempt reader (indexer, Defender, backup engines, the
    // allow-listed products) does its whole-disk reading as SYSTEM. One
    // running with a user's token — FileHistory, sdclt, MpCmdRun or
    // SearchProtocolHost started by the user, possibly suspended and
    // injected — reads decoys like any other process.
    if !crate::util::is_system_user(proc_.user.as_deref()) {
        return false;
    }
    let name = file_name(&proc_.image).to_ascii_lowercase();
    if is_os_file_maintenance_host(proc_, parent) {
        return true;
    }
    // V-M12: Optimize Drives runs as SYSTEM (scheduled task / defragsvc);
    // a user-started (possibly hollowed) defrag.exe is not exempt.
    if name == "defrag.exe" && !crate::util::is_system_user(proc_.user.as_deref()) {
        return false;
    }
    if CANARY_IGNORED_READERS.contains(&name.as_str())
        && proc_
            .signer
            .as_deref()
            .is_some_and(crate::protect::is_microsoft_signer)
    {
        return true;
    }
    BENIGN_READERS.iter().any(|r| {
        matches!(
            r.kind,
            BenignKind::Security
                | BenignKind::Indexer
                | BenignKind::Backup
                | BenignKind::Management
        ) && glob_match(r.image, &name)
            && match (r.signer, proc_.signer.as_deref()) {
                (Some(req), Some(have)) => contains_ci(have, req),
                _ => false,
            }
    })
}

/// Is this process an allow-listed benign reader for this store?
pub fn benign_reader_for(
    proc_: &ProcessInfo,
    store: &SensitiveStore,
    normalized_path: &str,
) -> Option<&'static BenignReader> {
    if is_untrusted_location_or_signature(proc_) {
        return None;
    }
    let name = file_name(&proc_.image).to_ascii_lowercase();
    BENIGN_READERS.iter().find(|r| {
        if !glob_match(r.image, &name) {
            return false;
        }
        if let (Some(req), Some(have)) = (r.signer, proc_.signer.as_deref()) {
            if !contains_ci(have, req) {
                return false;
            }
        }
        match r.scope {
            BenignScope::AllStores => true,
            BenignScope::PathContains(s) => normalized_path.contains(s),
            BenignScope::Categories(c) => c.contains(&store.category),
        }
    })
}

/// Is `proc_` the trusted owner of `store`? Browsers own every browser store
/// (cross-browser import), each store has its own owner list, and an owner only
/// counts when it is not unsigned / invalidly signed and not running from
/// Temp / Downloads / removable media (renamed-binary defence).
pub fn is_trusted_owner(proc_: &ProcessInfo, store: &SensitiveStore) -> bool {
    if is_untrusted_location_or_signature(proc_) {
        return false;
    }
    let name = file_name(&proc_.image).to_ascii_lowercase();
    let browser_store = matches!(store.owner, OwnerApp::Chromium | OwnerApp::Firefox)
        || matches!(
            store.category,
            DataCategory::BrowserPasswords
                | DataCategory::BrowserCookies
                | DataCategory::BrowserAutofill
                | DataCategory::BrowserMasterKey
        ) && store.owner != OwnerApp::Other;
    if browser_store && BROWSER_IMAGES.contains(&name.as_str()) {
        return true;
    }
    store.owners.iter().any(|o| glob_match(o, &name))
}

// ---------------------------------------------------------------------------
// Store location anchoring (owner's PC triage 2026-10-22)
// ---------------------------------------------------------------------------

/// Where a matched store must sit to be the real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchor {
    /// Under a user profile root, below `AppData\` (browsers, Discord,
    /// password-manager apps, WAM / MSAL caches, gcloud).
    ProfileAppData,
    /// Directly in a user profile's home folder (`.aws`, `.azure`, `.kube`,
    /// `.docker`, `.ssh`).
    ProfileHome(&'static str),
    /// Anywhere under a user profile root (Git / GitHub CLI / ngrok /
    /// Terraform tokens, whose location depends on configuration).
    Profile,
    /// Windows Credential Manager / DPAPI: a profile's `AppData\` or the
    /// machine-wide locations (`ProgramData\Microsoft\`, System32 `Protect`).
    WinCred,
    /// Portable / installer-chosen locations (Steam, Telegram, FTP clients,
    /// desktop wallets, KeePass, VPN profiles, `.ppk` keys, mail): only
    /// fake profile trees inside Temp are rejected.
    Free,
}

fn anchor_of(store: &SensitiveStore) -> Anchor {
    match store.owner {
        OwnerApp::Chromium | OwnerApp::Firefox | OwnerApp::Discord => Anchor::ProfileAppData,
        OwnerApp::Ssh if store.app == "SSH" => Anchor::ProfileHome(".ssh"),
        OwnerApp::CloudCli => match store.app {
            "AWS" => Anchor::ProfileHome(".aws"),
            "Azure CLI" => Anchor::ProfileHome(".azure"),
            "Kubernetes" => Anchor::ProfileHome(".kube"),
            "Docker" => Anchor::ProfileHome(".docker"),
            "Windows token broker" | "Microsoft identity (MSAL)" | "Google Cloud SDK" => {
                Anchor::ProfileAppData
            }
            _ => Anchor::Profile,
        },
        OwnerApp::PasswordManager if matches!(store.app, "Bitwarden" | "1Password") => {
            Anchor::ProfileAppData
        }
        OwnerApp::Other if matches!(store.app, "Windows Credential Manager" | "Windows DPAPI") => {
            Anchor::WinCred
        }
        _ => Anchor::Free,
    }
}

/// The part of a normalised path below a user profile root, or `None`.
/// Profile roots: `<any drive>:\Users\<name>\` (also driveless, as left by
/// `\Device\HarddiskVolumeN`), the SYSTEM profile
/// (`\Windows\System32\config\systemprofile\`), service profiles
/// (`\Windows\ServiceProfiles\<name>\`) and redirected folders on a share
/// (`\\server\share\...\AppData\...`, returned from `appdata\` on).
pub fn profile_relative(norm: &str) -> Option<&str> {
    let mut d = crate::util::strip_drive(norm);
    if let Some(unc) = d.strip_prefix(r"\\") {
        // Review M2: an administrative share of this machine
        // (`\\localhost\c$\Users\...`) is a local path.
        let mut parts = unc.splitn(3, '\\');
        let host = parts.next().unwrap_or("");
        let share = parts.next().unwrap_or("");
        let loopback = matches!(host, "localhost" | "127.0.0.1" | "::1" | "." | "?");
        let admin = share.len() == 2 && share.ends_with('$');
        if loopback && admin {
            d = &d[2 + host.len() + 1 + share.len()..];
        } else {
            let i = d.find(r"\appdata\")?;
            return Some(&d[i + 1..]);
        }
    }
    let named = |prefix: &str| -> Option<&str> {
        let r = d.strip_prefix(prefix)?;
        let (user, rest) = r.split_once('\\')?;
        (!user.is_empty() && user != "." && user != ".." && !rest.is_empty()).then_some(rest)
    };
    named(r"\users\")
        .or_else(|| named(r"\windows\serviceprofiles\"))
        .or_else(|| d.strip_prefix(r"\windows\system32\config\systemprofile\"))
}

/// `NAME~N` / `NAME~N.EXT`: an 8.3 short-name component.
fn short_name_component(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or(c);
    stem.rsplit_once('~').is_some_and(|(a, n)| {
        !a.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
    })
}

/// A fake profile tree (`...\sim-fs\C\Users\j.doe\...`, a test or replay
/// fixture, a copy unpacked from an archive) nested inside a profile's Temp
/// folder or below another profile: a component `users` followed by more
/// components, below the real profile root.
fn nested_profile_tree(rel: &str) -> bool {
    let comps: Vec<&str> = rel.split('\\').filter(|c| !c.is_empty()).collect();
    comps
        .iter()
        .enumerate()
        .any(|(i, c)| *c == "users" && i + 2 < comps.len())
}

/// Package family name (`<name>_<publisher id>`, lower-case) of an image
/// that runs from its MSIX package folder
/// `<system drive>:\Program Files\WindowsApps\<name>_<ver>_<arch>_<res>_<publisher id>\`.
/// WindowsApps is writable only by TrustedInstaller.
pub fn msix_package_family(image: &str, system_drive: char) -> Option<String> {
    if PathClass::of_with_system_drive(image, system_drive) != PathClass::ProgramFiles {
        return None;
    }
    let rest = crate::protect::on_system_volume(image, system_drive)?;
    let dir = rest
        .strip_prefix(r"\program files\windowsapps\")?
        .split('\\')
        .next()?;
    let parts: Vec<&str> = dir.split('_').collect();
    if parts.len() < 3 || parts[0].is_empty() || parts.contains(&"..") {
        return None;
    }
    let publisher = parts.last().filter(|p| !p.is_empty())?;
    Some(format!("{}_{}", parts[0], publisher))
}

/// Owner's PC triage 2026-10-22: a credential store matched by name must
/// also sit where the real store lives. Stores were matched by path suffix,
/// so Kestrel's own test binaries reading a simulated profile under
/// `%TEMP%\.tmpX\sim-fs\C\Users\j.doe\...`, an MSIX app reading its own
/// virtualised copy under `AppData\Local\Packages\<its family>\LocalCache\`
/// and a shell whose command text was logged as a path
/// (`D:\project\...\c\Users\azka\.claude\...`) fired ST-01 / ST-02.
///
/// * profile stores (browsers, Discord, Bitwarden / 1Password, WAM / MSAL /
///   gcloud caches) must be below `<profile>\AppData\`; home stores
///   (`.aws`, `.azure`, `.kube`, `.docker`, `.ssh`) directly in the
///   profile folder; Git / GitHub CLI / ngrok / Terraform tokens anywhere
///   in a profile. A profile root is `<drive>:\Users\<name>\`, the SYSTEM or
///   a service profile, or a redirected `AppData` on a share;
/// * never inside the profile's Temp folder or a nested `\users\<x>\` tree;
/// * Windows Credential Manager / DPAPI keys: a profile's `AppData\` or the
///   machine-wide `\ProgramData\Microsoft\` and `\Windows\System32\Microsoft\Protect\`;
/// * portable stores (Steam, Telegram, FTP clients, desktop wallets,
///   KeePass, VPN profiles, `.ppk` keys) keep matching anywhere except in a
///   fake profile tree inside Temp;
/// * a store under `AppData\Local\Packages\<family>\LocalCache\` read by
///   that package's own app (image in its WindowsApps folder) is the app's
///   private data, not the store it imitates. Any other reader still counts
///   (Store-installed Telegram keeps its `tdata` there).
///
/// Kestrel's decoys live under the real profile and still match.
pub fn store_location_real(
    norm: &str,
    store: &SensitiveStore,
    reader_image: &str,
    system_drive: char,
    reader_tampered: bool,
) -> bool {
    // Review M2: an 8.3 short name (`APPDAT~1`) may stand for any long name
    // the anchors below look for; fail open (match as before) rather than
    // lose a real store.
    if norm.split('\\').any(short_name_component) {
        return true;
    }
    let rel = profile_relative(norm);
    if let Some(r) = rel {
        if let Some(pk) = r.strip_prefix(r"appdata\local\packages\") {
            if let Some((family, tail)) = pk.split_once('\\') {
                if tail.starts_with(r"localcache\")
                    && !reader_tampered
                    && msix_package_family(reader_image, system_drive).as_deref() == Some(family)
                {
                    return false;
                }
            }
        }
        if nested_profile_tree(r) {
            return false;
        }
    }
    let in_temp = rel.is_some_and(|r| r.starts_with(r"appdata\local\temp\"));
    match anchor_of(store) {
        Anchor::Free => true,
        _ if in_temp => false,
        Anchor::Profile => rel.is_some(),
        Anchor::ProfileAppData => rel.is_some_and(|r| r.starts_with(r"appdata\")),
        Anchor::ProfileHome(dir) => rel.is_some_and(|r| r.split('\\').next() == Some(dir)),
        Anchor::WinCred => {
            let d = crate::util::strip_drive(norm);
            rel.is_some_and(|r| r.starts_with(r"appdata\"))
                || (rel.is_none()
                    && (d.starts_with(r"\programdata\microsoft\")
                        || d.starts_with(r"\windows\system32\microsoft\protect\")))
        }
    }
}

/// Unsigned / invalid / **unknown** signature, or image in Temp / Downloads /
/// external media. `Unknown` (enrichment not available yet) is never trusted:
/// the Windows layer computes hash + signature synchronously for first-seen
/// images and re-feeds late results through `Engine::enrich_process`.
pub fn is_untrusted_location_or_signature(proc_: &ProcessInfo) -> bool {
    matches!(
        proc_.signed,
        SignatureState::Unsigned | SignatureState::Invalid | SignatureState::Unknown
    ) || matches!(
        proc_.path_class,
        PathClass::Temp | PathClass::Downloads | PathClass::External
    )
}

// ---------------------------------------------------------------------------
// Normalisation and helpers
// ---------------------------------------------------------------------------

/// Normalise a Windows / NT path for matching: lower-case, `\` separators,
/// strip `\\?\`, `\??\`, `\\?\UNC\` (→ `\\`), `\Device\HarddiskVolumeN`
/// (→ path without drive), `\Device\Mup\` (→ `\\`), `\SystemRoot\` (→ `\windows\`).
pub fn normalize_path(path: &str) -> String {
    let mut s = String::with_capacity(path.len());
    for c in path.chars() {
        if c == '/' {
            s.push('\\');
        } else {
            s.extend(c.to_lowercase());
        }
    }
    if let Some(rest) = s.strip_prefix(r"\\?\unc\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = s.strip_prefix(r"\\?\").or_else(|| s.strip_prefix(r"\??\")) {
        return rest.to_string();
    }
    if let Some(rest) = s.strip_prefix(r"\device\mup\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = s.strip_prefix(r"\device\") {
        // \device\harddiskvolume3\users\.. | \device\harddiskvolumeshadowcopy1\.. | \device\cdrom0\..
        if let Some(i) = rest.find('\\') {
            return rest[i..].to_string();
        }
    }
    if let Some(rest) = s.strip_prefix(r"\systemroot\") {
        return format!(r"\windows\{rest}");
    }
    s
}

/// File name component of a path (either separator). Not lower-cased.
pub fn file_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn contains_ci(hay: &str, needle_lower: &str) -> bool {
    hay.to_ascii_lowercase().contains(needle_lower)
}

/// Path glob (callers normalise / lower-case both sides): `*` matches any
/// run of characters **within one path segment** (never `\`), `**` matches
/// across segments (including none), `?` matches one non-separator character.
pub fn glob_match_path(pattern: &str, text: &str) -> bool {
    let p = pattern.as_bytes();
    let t = text.as_bytes();
    // Iterative matcher with a backtrack stack (patterns are short).
    fn m(p: &[u8], t: &[u8], depth: u32) -> bool {
        if depth > 64 {
            return false;
        }
        let (mut pi, mut ti) = (0usize, 0usize);
        while pi < p.len() {
            match p[pi] {
                b'*' => {
                    let double = p.get(pi + 1) == Some(&b'*');
                    let next = if double { pi + 2 } else { pi + 1 };
                    // `**\` also matches zero segments.
                    if double
                        && p.get(next) == Some(&b'\\')
                        && m(&p[next + 1..], &t[ti..], depth + 1)
                    {
                        return true;
                    }
                    let mut k = ti;
                    loop {
                        if m(&p[next..], &t[k..], depth + 1) {
                            return true;
                        }
                        if k >= t.len() || (!double && t[k] == b'\\') {
                            return false;
                        }
                        k += 1;
                    }
                }
                b'?' => {
                    if ti >= t.len() || t[ti] == b'\\' {
                        return false;
                    }
                    pi += 1;
                    ti += 1;
                }
                c => {
                    if ti >= t.len() || t[ti] != c {
                        return false;
                    }
                    pi += 1;
                    ti += 1;
                }
            }
        }
        ti == t.len()
    }
    m(p, t, 0)
}

/// Case-sensitive glob with `*` (callers lower-case both sides).
pub fn glob_match(pattern: &str, text: &str) -> bool {
    if !pattern.contains('*') {
        return pattern == text;
    }
    let parts: Vec<&str> = pattern.split('*').collect();
    let mut pos = 0usize;
    let last = parts.len() - 1;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if i == last {
            return text.len() >= pos + part.len() && text[pos..].ends_with(part);
        } else {
            match text[pos..].find(part) {
                Some(j) => pos += j + part.len(),
                None => return false,
            }
        }
    }
    // pattern ends with '*' (or is only '*')
    true
}

/// Substrings that every sensitive path contains at least one of (ASCII case-insensitive).
const PREFILTER_NEEDLES: &[&str] = &[
    "user data",
    "opera software",
    "profiles",
    "profile.default",
    "tdata",
    "discord",
    "lightcord",
    "ssfn",
    ".vdf",
    "filezilla",
    "winscp.ini",
    "wcx_ftp.ini",
    "smartftp",
    "wallet",
    "exodus",
    "electrum",
    "electron cash",
    "atomic",
    "armory",
    "coinomi",
    "guarda",
    "jaxx",
    "ledger live",
    "monero",
    "ethereum",
    "daedalus",
    "binance",
    ".aws",
    ".azure",
    "gcloud",
    ".kube",
    ".docker",
    ".identityservice",
    "tokenbroker",
    ".git-credentials",
    "hosts.yml",
    "ngrok.yml",
    "credentials.tfrc",
    ".ssh",
    ".ppk",
    ".kdb",
    "bitwarden",
    "1password",
    ".ovpn",
    "openvpn",
    "nordvpn",
    "protonvpn",
    "wireguard",
    ".pst",
    ".ost",
    "mailbird",
    "slack",
    "microsoft\\protect",
    "microsoft/protect",
    "microsoft\\credentials",
    "microsoft/credentials",
    "microsoft\\vault",
    "microsoft/vault",
];

fn prefilter() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::LeftmostFirst)
            .build(PREFILTER_NEEDLES)
            .expect("static needles")
    })
}

fn store(
    category: DataCategory,
    owner: OwnerApp,
    app: &'static str,
    noun: &'static str,
    owners: &'static [&'static str],
) -> Option<SensitiveStore> {
    Some(SensitiveStore {
        category,
        owner,
        app,
        noun,
        owners,
    })
}

fn chromium_file(
    app: &'static str,
    rest: &str,
    owners: &'static [&'static str],
) -> Option<SensitiveStore> {
    let fname = file_name(rest);
    let comps: Vec<&str> = rest.split('\\').filter(|c| !c.is_empty()).collect();
    if comps.len() == 1 && fname == "local state" {
        return store(
            DataCategory::BrowserMasterKey,
            OwnerApp::Chromium,
            app,
            "encryption key",
            owners,
        );
    }
    match fname {
        "login data" | "login data for account" => {
            return store(
                DataCategory::BrowserPasswords,
                OwnerApp::Chromium,
                app,
                "saved passwords",
                owners,
            )
        }
        "cookies" => {
            return store(
                DataCategory::BrowserCookies,
                OwnerApp::Chromium,
                app,
                "cookies",
                owners,
            )
        }
        "web data" => {
            return store(
                DataCategory::BrowserAutofill,
                OwnerApp::Chromium,
                app,
                "autofill and saved cards",
                owners,
            )
        }
        _ => {}
    }
    // Extension storage
    for (i, c) in comps.iter().enumerate() {
        let id: Option<&str> = if (*c == "local extension settings"
            || *c == "sync extension settings")
            && i + 1 < comps.len()
        {
            Some(comps[i + 1])
        } else if *c == "indexeddb" && i + 1 < comps.len() {
            comps[i + 1]
                .strip_prefix("chrome-extension_")
                .and_then(|s| s.split('_').next())
        } else {
            None
        };
        if let Some(id) = id {
            if let Some((_, name)) = WALLET_EXTENSIONS.iter().find(|(x, _)| *x == id) {
                return store(
                    DataCategory::CryptoWallet,
                    OwnerApp::Chromium,
                    name,
                    "wallet extension vault",
                    owners,
                );
            }
            if let Some((_, name)) = PASSWORD_MANAGER_EXTENSIONS.iter().find(|(x, _)| *x == id) {
                return store(
                    DataCategory::PasswordManager,
                    OwnerApp::Chromium,
                    name,
                    "password-manager extension vault",
                    owners,
                );
            }
            return None;
        }
    }
    None
}

/// Noun of Steam's `config\config.vdf` store (client / library configuration).
pub const STEAM_CONFIG_NOUN: &str = "client configuration (config.vdf)";

fn comp_idx(comps: &[&str], name: &str) -> Option<usize> {
    comps.iter().position(|c| *c == name)
}

/// Match on an already-normalised path.
pub fn match_normalized(p: &str) -> Option<SensitiveStore> {
    let fname = file_name(p);
    let comps: Vec<&str> = p.split('\\').filter(|c| !c.is_empty()).collect();

    // --- Chromium family: <vendor>\User Data\...
    if let Some(i) = p.find(r"\user data\") {
        let root = &p[..i];
        let rest = &p[i + r"\user data\".len()..];
        let app = CHROMIUM_VENDORS
            .iter()
            .find(|(needle, _)| root.ends_with(needle))
            .map(|(_, n)| *n)
            .unwrap_or(if root.contains(r"\appdata\") {
                "Chromium-based browser"
            } else {
                ""
            });
        if !app.is_empty() {
            if let Some(s) = chromium_file(app, rest, O_CHROMIUM) {
                return Some(s);
            }
        }
    }
    // --- Opera: Opera Software\<channel>\...
    if let Some(i) = comp_idx(&comps, "opera software") {
        if let Some(ch) = comps.get(i + 1) {
            if let Some((_, app)) = OPERA_CHANNELS.iter().find(|(c, _)| c == ch) {
                let rest = comps[i + 2..].join("\\");
                if let Some(s) = chromium_file(app, &rest, O_CHROMIUM) {
                    return Some(s);
                }
            }
        }
    }
    // --- Gecko family profiles
    if matches!(
        fname,
        "key4.db"
            | "key3.db"
            | "logins.json"
            | "signons.sqlite"
            | "cookies.sqlite"
            | "formhistory.sqlite"
    ) && (p.contains(r"\profiles\") || p.contains(r"\profile.default"))
    {
        let (app, mail) = GECKO_VENDORS
            .iter()
            .find(|(n, _, _)| p.contains(n))
            .map(|(_, a, m)| (*a, *m))
            .unwrap_or(("Gecko-based browser", false));
        let owners = if mail { O_THUNDERBIRD } else { O_GECKO };
        if mail {
            let noun = match fname {
                "cookies.sqlite" | "formhistory.sqlite" => "profile data",
                _ => "saved mail passwords",
            };
            return store(DataCategory::Email, OwnerApp::Firefox, app, noun, owners);
        }
        return match fname {
            "key4.db" | "key3.db" => store(
                DataCategory::BrowserMasterKey,
                OwnerApp::Firefox,
                app,
                "encryption key",
                owners,
            ),
            "logins.json" | "signons.sqlite" => store(
                DataCategory::BrowserPasswords,
                OwnerApp::Firefox,
                app,
                "saved passwords",
                owners,
            ),
            "cookies.sqlite" => store(
                DataCategory::BrowserCookies,
                OwnerApp::Firefox,
                app,
                "cookies",
                owners,
            ),
            _ => store(
                DataCategory::BrowserAutofill,
                OwnerApp::Firefox,
                app,
                "form history",
                owners,
            ),
        };
    }
    // --- Discord (token LevelDB, Local State key, desktop core tamper target)
    for (i, c) in comps.iter().enumerate() {
        if matches!(
            *c,
            "discord" | "discordptb" | "discordcanary" | "discorddevelopment" | "lightcord"
        ) {
            let rest = &comps[i + 1..];
            if rest.len() >= 2 && rest[0] == "local storage" && rest[1] == "leveldb" {
                return store(
                    DataCategory::Discord,
                    OwnerApp::Discord,
                    "Discord",
                    "token store",
                    O_DISCORD,
                );
            }
            if rest == ["local state"] {
                return store(
                    DataCategory::Discord,
                    OwnerApp::Discord,
                    "Discord",
                    "token encryption key",
                    O_DISCORD,
                );
            }
            if fname == "index.js" && rest.iter().any(|r| r.starts_with("discord_desktop_core")) {
                return store(
                    DataCategory::Discord,
                    OwnerApp::Discord,
                    "Discord",
                    "client core (index.js)",
                    O_DISCORD,
                );
            }
        }
    }
    // --- Telegram tdata
    if let Some(i) = comp_idx(&comps, "tdata") {
        if i > 0 && comps[i - 1].contains("gram") {
            return store(
                DataCategory::Telegram,
                OwnerApp::Telegram,
                "Telegram",
                "session (tdata)",
                O_TELEGRAM,
            );
        }
    }
    // --- Steam
    if let Some(i) = comps.iter().rposition(|c| *c == "steam") {
        let rest = &comps[i + 1..];
        if rest.len() == 1 && rest[0].starts_with("ssfn") {
            return store(
                DataCategory::Steam,
                OwnerApp::Steam,
                "Steam",
                "Steam Guard file (ssfn)",
                O_STEAM,
            );
        }
        // Owner's PC 2026-10-22: `config.vdf` is Steam's client / library
        // configuration (GPU and overlay tools such as NVIDIA's nvcontainer
        // scan it); stealers grab it with the secrets, so it stays a store
        // under its own noun ([`STEAM_CONFIG_NOUN`]) that signed Program Files
        // vendor services may read (Low Audit, see `legit_apps`).
        if rest.len() == 2 && rest[0] == "config" && rest[1] == "config.vdf" {
            return store(
                DataCategory::Steam,
                OwnerApp::Steam,
                "Steam",
                STEAM_CONFIG_NOUN,
                O_STEAM,
            );
        }
        if rest.len() == 2 && rest[0] == "config" && rest[1] == "loginusers.vdf" {
            return store(
                DataCategory::Steam,
                OwnerApp::Steam,
                "Steam",
                "login configuration",
                O_STEAM,
            );
        }
        if rest == ["local.vdf"] {
            return store(
                DataCategory::Steam,
                OwnerApp::Steam,
                "Steam",
                "login tokens (local.vdf)",
                O_STEAM,
            );
        }
    }
    // --- FTP clients
    if comp_idx(&comps, "filezilla").is_some()
        && matches!(fname, "recentservers.xml" | "sitemanager.xml")
    {
        return store(
            DataCategory::FtpClient,
            OwnerApp::FileZilla,
            "FileZilla",
            "saved servers",
            O_FILEZILLA,
        );
    }
    if fname == "winscp.ini" {
        return store(
            DataCategory::FtpClient,
            OwnerApp::WinScp,
            "WinSCP",
            "saved sessions",
            O_WINSCP,
        );
    }
    if fname == "wcx_ftp.ini" {
        return store(
            DataCategory::FtpClient,
            OwnerApp::FileZilla,
            "Total Commander FTP",
            "saved servers",
            O_TOTALCMD,
        );
    }
    if p.contains(r"\smartftp\") && p.contains(r"\favorites\") {
        return store(
            DataCategory::FtpClient,
            OwnerApp::FileZilla,
            "SmartFTP",
            "saved servers",
            O_SMARTFTP,
        );
    }
    // --- Desktop wallets
    let wallet = |app: &'static str, owners: &'static [&'static str]| {
        store(
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
            app,
            "wallet",
            owners,
        )
    };
    if p.contains(r"\exodus\exodus.wallet") {
        return wallet("Exodus", O_EXODUS);
    }
    if p.contains(r"\electrum\wallets")
        || p.contains(r"\electrum-ltc\wallets")
        || p.contains(r"\electron cash\wallets")
    {
        return wallet("Electrum", O_ELECTRUM);
    }
    if p.contains(r"\atomic\local storage\leveldb") {
        return wallet("Atomic Wallet", O_ATOMIC);
    }
    if comp_idx(&comps, "armory").is_some() && fname.ends_with(".wallet") {
        return wallet("Armory", O_ARMORY);
    }
    if fname == "wallet.dat" {
        return wallet("Bitcoin Core (wallet.dat)", O_BITCOIN);
    }
    if p.contains(r"\coinomi\coinomi\wallets") {
        return wallet("Coinomi", O_COINOMI);
    }
    if p.contains(r"\guarda\local storage\leveldb") || p.contains(r"\guarda\indexeddb") {
        return wallet("Guarda", O_GUARDA);
    }
    if p.contains(r"\com.liberty.jaxx\indexeddb") || p.contains(r"\jaxx\local storage") {
        return wallet("Jaxx Liberty", O_JAXX);
    }
    if p.contains(r"\ledger live\") && fname == "app.json" {
        return wallet("Ledger Live", O_LEDGER);
    }
    if p.contains(r"\walletwasabi\client\wallets") {
        return wallet("Wasabi Wallet", O_WASABI);
    }
    if p.contains(r"\monero\wallets")
        || (comp_idx(&comps, "monero").is_some() && fname.ends_with(".keys"))
    {
        return wallet("Monero", O_MONERO);
    }
    if p.contains(r"\ethereum\keystore") {
        return wallet("Ethereum keystore", O_GETH);
    }
    if p.contains(r"\daedalus mainnet\wallets") {
        return wallet("Daedalus", O_DAEDALUS);
    }
    if comp_idx(&comps, "binance").is_some()
        && matches!(
            fname,
            "app-store.json" | ".finger-print.fp" | "simple-storage.json"
        )
    {
        return wallet("Binance desktop", O_BINANCE);
    }
    // --- Cloud / developer tokens
    let cloud = |app: &'static str, noun: &'static str, owners: &'static [&'static str]| {
        store(
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
            app,
            noun,
            owners,
        )
    };
    if let Some(i) = comp_idx(&comps, ".aws") {
        let rest = &comps[i + 1..];
        if rest == ["credentials"] {
            return cloud("AWS", "credentials", O_AWS);
        }
        if rest.len() >= 2 && matches!(rest[0], "sso" | "cli") && rest[1] == "cache" {
            return cloud("AWS", "SSO / CLI token cache", O_AWS);
        }
    }
    if comp_idx(&comps, ".azure").is_some()
        && (fname.starts_with("msal_token_cache")
            || matches!(
                fname,
                "accesstokens.json"
                    | "service_principal_entries.json"
                    | "tokencache.dat"
                    | "msal_http_cache.bin"
            ))
    {
        return cloud("Azure CLI", "token cache", O_AZURE);
    }
    if comp_idx(&comps, ".identityservice").is_some() && comps.last() != Some(&".identityservice") {
        return cloud(
            "Microsoft identity (MSAL)",
            "token cache",
            O_IDENTITYSERVICE,
        );
    }
    if p.contains(r"\microsoft\tokenbroker\cache\") && fname.ends_with(".tbres") {
        return cloud("Windows token broker", "SSO token cache", O_TOKENBROKER);
    }
    if let Some(i) = comp_idx(&comps, "gcloud") {
        let rest = &comps[i + 1..];
        if matches!(
            fname,
            "credentials.db" | "access_tokens.db" | "application_default_credentials.json"
        ) || rest.first() == Some(&"legacy_credentials")
        {
            return cloud("Google Cloud SDK", "credentials", O_GCLOUD);
        }
    }
    if let Some(i) = comp_idx(&comps, ".kube") {
        if comps[i + 1..] == ["config"] {
            return cloud("Kubernetes", "kubeconfig", O_KUBE);
        }
    }
    if let Some(i) = comp_idx(&comps, ".docker") {
        if comps[i + 1..] == ["config.json"] {
            return cloud("Docker", "registry credentials", O_DOCKER);
        }
    }
    if fname == ".git-credentials" {
        return cloud("Git", "stored credentials", O_GIT);
    }
    if fname == "hosts.yml" && (p.contains(r"\.config\gh\") || p.contains(r"\github cli\")) {
        return cloud("GitHub CLI", "OAuth token", O_GH);
    }
    if fname == "ngrok.yml" {
        return cloud("ngrok", "auth token", O_NGROK);
    }
    if fname == "credentials.tfrc.json" {
        return cloud("Terraform", "API token", O_TERRAFORM);
    }
    // --- SSH
    if let Some(i) = comp_idx(&comps, ".ssh") {
        if i + 2 == comps.len()
            && ((fname.starts_with("id_") && !fname.ends_with(".pub"))
                || fname.ends_with(".pem")
                || fname.ends_with(".ppk"))
        {
            return store(
                DataCategory::SshKeys,
                OwnerApp::Ssh,
                "SSH",
                "private key",
                O_SSH,
            );
        }
    }
    if fname.ends_with(".ppk") {
        return store(
            DataCategory::SshKeys,
            OwnerApp::Ssh,
            "PuTTY",
            "private key",
            O_SSH,
        );
    }
    // --- Password managers
    if fname.ends_with(".kdbx") || fname.ends_with(".kdb") {
        return store(
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
            "KeePass",
            "vault",
            O_KEEPASS,
        );
    }
    if p.contains(r"\bitwarden\") && fname == "data.json" {
        return store(
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
            "Bitwarden",
            "vault",
            O_BITWARDEN,
        );
    }
    if p.contains(r"\1password\data\")
        && fname.starts_with("1password")
        && fname.contains(".sqlite")
    {
        return store(
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
            "1Password",
            "vault",
            O_1PASSWORD,
        );
    }
    if p.contains(r"\microsoft\credentials\") || p.contains(r"\microsoft\vault\") {
        return store(
            DataCategory::PasswordManager,
            OwnerApp::Other,
            "Windows Credential Manager",
            "saved credentials",
            O_WINCRED,
        );
    }
    if p.contains(r"\microsoft\protect\")
        && comps.last().is_some_and(|l| !l.is_empty())
        && !p.ends_with(r"\protect\")
    {
        return store(
            DataCategory::BrowserMasterKey,
            OwnerApp::Other,
            "Windows DPAPI",
            "master keys",
            O_WINCRED,
        );
    }
    // --- VPN
    if fname.ends_with(".ovpn") || p.contains(r"\openvpn connect\profiles\") {
        return store(
            DataCategory::Vpn,
            OwnerApp::Other,
            "OpenVPN",
            "VPN profile",
            O_OPENVPN,
        );
    }
    if fname == "user.config" && p.contains(r"\nordvpn") {
        return store(
            DataCategory::Vpn,
            OwnerApp::Other,
            "NordVPN",
            "VPN credentials",
            O_NORDVPN,
        );
    }
    if fname == "user.config" && p.contains(r"\protonvpn") {
        return store(
            DataCategory::Vpn,
            OwnerApp::Other,
            "ProtonVPN",
            "VPN credentials",
            O_PROTONVPN,
        );
    }
    if p.contains(r"\wireguard\data\configurations\") {
        return store(
            DataCategory::Vpn,
            OwnerApp::Other,
            "WireGuard",
            "tunnel configuration",
            O_WIREGUARD,
        );
    }
    // --- Email
    if fname.ends_with(".pst") || (fname.ends_with(".ost") && p.contains(r"\microsoft\outlook\")) {
        return store(
            DataCategory::Email,
            OwnerApp::Other,
            "Outlook",
            "mailbox",
            O_OUTLOOK,
        );
    }
    if p.contains(r"\mailbird\store\") && fname == "store.db" {
        return store(
            DataCategory::Email,
            OwnerApp::Other,
            "Mailbird",
            "mail store",
            O_MAILBIRD,
        );
    }
    // --- Slack session cookies
    if let Some(i) = comp_idx(&comps, "slack") {
        let rest = &comps[i + 1..];
        if rest == ["cookies"] || rest == ["network", "cookies"] {
            return store(
                DataCategory::BrowserCookies,
                OwnerApp::Other,
                "Slack",
                "session cookies",
                O_SLACK,
            );
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cls(p: &str) -> Option<(DataCategory, OwnerApp)> {
        classify_sensitive_path(p)
    }

    const POSITIVES: &[(&str, DataCategory, OwnerApp)] = &[
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data",
            DataCategory::BrowserPasswords,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Profile 2\Login Data For Account",
            DataCategory::BrowserPasswords,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies",
            DataCategory::BrowserCookies,
            OwnerApp::Chromium,
        ),
        (
            r"c:/users/bob/appdata/local/microsoft/edge/user data/default/cookies",
            DataCategory::BrowserCookies,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Local State",
            DataCategory::BrowserMasterKey,
            OwnerApp::Chromium,
        ),
        (
            r"\Device\HarddiskVolume3\Users\alice\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Web Data",
            DataCategory::BrowserAutofill,
            OwnerApp::Chromium,
        ),
        (
            r"\\?\C:\Users\alice\AppData\Local\Yandex\YandexBrowser\User Data\Default\Login Data",
            DataCategory::BrowserPasswords,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Opera Software\Opera GX Stable\Login Data",
            DataCategory::BrowserPasswords,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Opera Software\Opera Stable\Local State",
            DataCategory::BrowserMasterKey,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Opera Software\Opera Stable\Default\Network\Cookies",
            DataCategory::BrowserCookies,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Vivaldi\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log",
            DataCategory::CryptoWallet,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa",
            DataCategory::CryptoWallet,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\IndexedDB\chrome-extension_hnfanknocfeofbddgcijnmhnfnkdnaad_0.indexeddb.leveldb\CURRENT",
            DataCategory::CryptoWallet,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nngceckbapebfimnlniiiahkandclblb\LOG",
            DataCategory::PasswordManager,
            OwnerApp::Chromium,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\key4.db",
            DataCategory::BrowserMasterKey,
            OwnerApp::Firefox,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\logins.json",
            DataCategory::BrowserPasswords,
            OwnerApp::Firefox,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\abcd.default-release\cookies.sqlite",
            DataCategory::BrowserCookies,
            OwnerApp::Firefox,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Waterfox\Profiles\x.default\formhistory.sqlite",
            DataCategory::BrowserAutofill,
            OwnerApp::Firefox,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Thunderbird\Profiles\x.default\logins.json",
            DataCategory::Email,
            OwnerApp::Firefox,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb",
            DataCategory::Discord,
            OwnerApp::Discord,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\discordptb\Local Storage\leveldb\LOG",
            DataCategory::Discord,
            OwnerApp::Discord,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\discordcanary\Local State",
            DataCategory::Discord,
            OwnerApp::Discord,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Telegram Desktop\tdata\key_datas",
            DataCategory::Telegram,
            OwnerApp::Telegram,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Telegram Desktop\tdata",
            DataCategory::Telegram,
            OwnerApp::Telegram,
        ),
        (
            r"C:\Program Files (x86)\Steam\ssfn1234567890",
            DataCategory::Steam,
            OwnerApp::Steam,
        ),
        (
            r"D:\Games\Steam\config\loginusers.vdf",
            DataCategory::Steam,
            OwnerApp::Steam,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\FileZilla\recentservers.xml",
            DataCategory::FtpClient,
            OwnerApp::FileZilla,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\FileZilla\sitemanager.xml",
            DataCategory::FtpClient,
            OwnerApp::FileZilla,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\WinSCP.ini",
            DataCategory::FtpClient,
            OwnerApp::WinScp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Exodus\exodus.wallet\seed.seco",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Electrum\wallets\default_wallet",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\atomic\Local Storage\leveldb\000003.log",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Armory\armory_abc_.wallet",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Bitcoin\wallets\main\wallet.dat",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Coinomi\Coinomi\wallets\a.wallet",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Guarda\Local Storage\leveldb\x.ldb",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb\x",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Ledger Live\app.json",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\WalletWasabi\Client\Wallets\w.json",
            DataCategory::CryptoWallet,
            OwnerApp::WalletApp,
        ),
        (
            r"C:\Users\alice\.aws\credentials",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.aws\sso\cache\abc.json",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.azure\msal_token_cache.bin",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.azure\accessTokens.json",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\gcloud\credentials.db",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.kube\config",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.docker\config.json",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\AppData\Local\.IdentityService\msal.cache",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\AppData\Local\Microsoft\TokenBroker\Cache\abc.tbres",
            DataCategory::CloudToken,
            OwnerApp::CloudCli,
        ),
        (
            r"C:\Users\alice\.ssh\id_ed25519",
            DataCategory::SshKeys,
            OwnerApp::Ssh,
        ),
        (
            r"C:\Users\alice\.ssh\id_rsa",
            DataCategory::SshKeys,
            OwnerApp::Ssh,
        ),
        (
            r"C:\Users\alice\Documents\keys\server.ppk",
            DataCategory::SshKeys,
            OwnerApp::Ssh,
        ),
        (
            r"C:\Users\alice\Documents\Passwords.kdbx",
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Bitwarden\data.json",
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
        ),
        (
            r"C:\Users\alice\AppData\Local\1Password\data\1password.sqlite",
            DataCategory::PasswordManager,
            OwnerApp::PasswordManager,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\OpenVPN Connect\profiles\work.ovpn",
            DataCategory::Vpn,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\OpenVPN\config\home.ovpn",
            DataCategory::Vpn,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\AppData\Local\NordVPN\NordVPN.exe_Url_x\7.1.0.0\user.config",
            DataCategory::Vpn,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\AppData\Local\ProtonVPN\ProtonVPN.exe_Url_y\3.0\user.config",
            DataCategory::Vpn,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\AppData\Local\Microsoft\Outlook\alice@corp.com.ost",
            DataCategory::Email,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\Documents\Outlook Files\archive.pst",
            DataCategory::Email,
            OwnerApp::Other,
        ),
        (
            r"C:\Users\alice\AppData\Roaming\Slack\Network\Cookies",
            DataCategory::BrowserCookies,
            OwnerApp::Other,
        ),
    ];

    #[test]
    fn positives_classify_and_prefilter() {
        for (p, cat, owner) in POSITIVES {
            assert!(may_be_sensitive(p), "prefilter missed {p}");
            assert_eq!(cls(p), Some((*cat, *owner)), "wrong class for {p}");
        }
    }

    #[test]
    fn negatives() {
        for p in [
            r"C:\Windows\System32\kernel32.dll",
            r"C:\Users\alice\Documents\report.docx",
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\History",
            r"C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x",
            r"C:\Users\alice\.ssh\id_rsa.pub",
            r"C:\Users\alice\.ssh\known_hosts",
            r"C:\Users\alice\.aws\config",
            r"C:\Users\alice\AppData\Roaming\Mozilla\Firefox\Profiles\x\places.sqlite",
            r"C:\Users\alice\AppData\Roaming\discord\settings.json",
        ] {
            assert_eq!(cls(p), None, "{p}");
        }
    }

    #[test]
    fn normalisation() {
        assert_eq!(
            normalize_path(r"\Device\HarddiskVolume3\Users\A\x"),
            r"\users\a\x"
        );
        assert_eq!(normalize_path(r"\\?\C:\Users\A"), r"c:\users\a");
        assert_eq!(normalize_path(r"\??\C:\Users\A"), r"c:\users\a");
        assert_eq!(normalize_path(r"\\?\UNC\srv\share\a"), r"\\srv\share\a");
        assert_eq!(normalize_path("C:/Users/A/b"), r"c:\users\a\b");
        assert_eq!(
            PathClass::of(&normalize_path(
                r"\Device\HarddiskVolume3\Users\a\Downloads\x.exe"
            )),
            PathClass::Downloads
        );
    }

    #[test]
    fn browsers() {
        assert!(is_browser_image(
            r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        ));
        assert!(is_browser_image("MSEDGE.EXE"));
        assert!(is_browser_image("/x/firefox.exe"));
        assert!(!is_browser_image(r"C:\Windows\explorer.exe"));
        assert!(is_chromium_image("brave.exe"));
        assert!(!is_chromium_image("firefox.exe"));
        assert!(is_mozilla_image("thunderbird.exe"));
    }

    #[test]
    fn registry_keys() {
        assert_eq!(
            classify_sensitive_registry(
                r"HKEY_CURRENT_USER\Software\Martin Prikryl\WinSCP 2\Sessions\prod"
            ),
            Some((DataCategory::FtpClient, OwnerApp::WinScp))
        );
        assert_eq!(
            classify_sensitive_registry(r"HKCU\Software\SimonTatham\PuTTY\Sessions\srv"),
            Some((DataCategory::SshKeys, OwnerApp::Ssh))
        );
        assert_eq!(
            classify_sensitive_registry(
                r"HKCU\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375"
            ),
            Some((DataCategory::Email, OwnerApp::Other))
        );
        assert_eq!(
            classify_sensitive_registry(r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"),
            None
        );
        assert!(BENIGN_READERS.iter().any(|r| r.kind == BenignKind::Indexer));
    }

    #[test]
    fn globbing() {
        assert!(glob_match("electrum*.exe", "electrum-4.5.5.exe"));
        assert!(!glob_match("electrum*.exe", "electrum-4.5.5.dll"));
        assert!(glob_match("*", "x"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxbyy"));
    }

    fn pinfo(image: &str, signed: SignatureState, signer: Option<&str>) -> ProcessInfo {
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
            signer: signer.map(Into::into),
            signed,
            sha256: None,
            motw_zone: None,
            file_size: None,
            path_class: PathClass::of(image),
        }
    }

    #[test]
    fn owners_and_benign() {
        let st =
            match_sensitive_path(r"C:\Users\a\AppData\Roaming\Telegram Desktop\tdata\x").unwrap();
        let tg = pinfo(
            r"C:\Users\a\AppData\Roaming\Telegram Desktop\Telegram.exe",
            SignatureState::Valid,
            Some("Telegram FZ-LLC"),
        );
        assert!(is_trusted_owner(&tg, &st));
        let fake = pinfo(
            r"C:\Users\a\AppData\Local\Temp\telegram.exe",
            SignatureState::Unsigned,
            None,
        );
        assert!(!is_trusted_owner(&fake, &st));
        let chrome_st = match_sensitive_path(
            r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data",
        )
        .unwrap();
        let edge = pinfo(
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        );
        assert!(is_trusted_owner(&edge, &chrome_st));
        let idx = pinfo(
            r"C:\Windows\System32\SearchProtocolHost.exe",
            SignatureState::Valid,
            Some("Microsoft Windows"),
        );
        assert!(benign_reader_for(&idx, &chrome_st, "").is_some());
        let od = pinfo(
            r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
            SignatureState::Valid,
            Some("Microsoft Corporation"),
        );
        let kdbx = match_sensitive_path(r"C:\Users\a\OneDrive\vault.kdbx").unwrap();
        assert!(benign_reader_for(&od, &kdbx, r"c:\users\a\onedrive\vault.kdbx").is_some());
        assert!(benign_reader_for(
            &od,
            &chrome_st,
            r"c:\users\a\appdata\local\google\chrome\user data\default\login data"
        )
        .is_none());
        assert!(owner_images(OwnerApp::Telegram).contains(&"telegram.exe"));
        assert!(WALLET_EXTENSIONS.len() >= 20);
    }
}
