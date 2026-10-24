# Publisher signer names (Authenticode leaf CN) for genuine-app checks

Research notes, 2026-10-25. Purpose: exact signer display names for the "is this the genuine application?"
check (image name + install location + signer), so an attacker with some other company's stolen certificate
cannot pass by a substring match.

## How the values were obtained, and how much to trust them

| Tag | Meaning |
|---|---|
| **L** (verified, local) | Read on the owner's Windows 11 PC on 2026-10-25 with `Get-AuthenticodeSignature` (status `Valid`) on the installed binary. Read-only, nothing was changed. Strongest evidence. |
| **C** (verified, cert) | Taken from a real leaf certificate in [jkerai1/SoftwareCertificates](https://github.com/jkerai1/SoftwareCertificates) (certs exported from shipped binaries). The display name was extracted with .NET `X509Certificate2.GetNameInfo(SimpleName)`, which matches `CertGetNameStringW(CERT_NAME_SIMPLE_DISPLAY_TYPE)`. Validity dates are shown where they matter. |
| **E** (verified, rule) | Appears as a `process.code_signature.subject_name` value in Elastic's [protections-artifacts](https://github.com/elastic/protections-artifacts) or [detection-rules](https://github.com/elastic/detection-rules), which use the same Windows simple display name. Only the facts (names) were read; no rule text was copied (ELv2). |
| **V** (verified, vendor or packager) | The vendor's own docs or repo, or a packaging tool that pins the full subject DN ([striezel/updater](https://github.com/striezel/updater/tree/master/updater/software)). |
| **3** (third party) | A file-reputation site (FreeFixer etc.) reports the "signer name". It's usually right, but the punctuation is less reliable. |
| **U** (unverified) | Best guess. Don't hard-code it without seeing it in the field. |

### Important implementation facts (from the local checks)

* `Get-AuthenticodeSignature` prints the DN with X.500 escaping, e.g. `CN="Brave Software, Inc."`. The simple display name that `CertGetNameStringW` returns has **no quotes**: `Brave Software, Inc.`. Compare against the unquoted form. Never split on commas, because many CNs contain them (`Open Source Developer, Dominik Reichl`, `ESET, spol. s r.o.`).
* The punctuation differs between vendors and must be copied exactly: `Docker Inc` (no period), `Dropbox, Inc` (no period), `Malwarebytes Inc` **and** `Malwarebytes Inc.` (both seen), `Exodus Movement, Inc.` **and** `Exodus Movement Inc` (both seen), `Valve Corp.`, `Siber Systems Inc`.
* Case varies across certificate renewals for the same vendor: `PIRIFORM SOFTWARE LIMITED` vs `Piriform Software Ltd`, and `THE BROWSER COMPANY OF NEW YORK INC.`. Compare exactly per variant, or case-insensitively over the **whole** string, never as a substring or prefix.
* Diacritics: WinSCP's current EV certificate is `Martin Přikryl` (U+0159). Its earlier certificate is `Martin Prikryl` (ASCII). Store both, and compare as UTF-16 rather than an ASCII-folded string.
* Microsoft signs with several CNs: `Microsoft Corporation` (Edge, WebView2, VS Code, Office/Outlook), `Microsoft Windows` (inbox binaries, `C:\Program Files\Windows Defender\MsMpEng.exe`) and `Microsoft Windows Publisher` (Defender platform `C:\ProgramData\Microsoft\Windows Defender\Platform\<ver>\MsMpEng.exe`). All three were seen locally (L).
* **MSIX / Store apps may have unsigned files.** Locally, `C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_2.2640.100.0_x64__cv1g1gvanyjgm\WhatsApp.Root.exe` returned `NotSigned`. The trust comes from the package signature, and the package publisher is `CN=24803D75-212C-471A-BC57-9EF86AB91435`, a Store-assigned GUID. A signer-based check will therefore fail for WhatsApp Store builds. Use package identity instead: the `WindowsApps\<PackageFamilyName>` path, which only TrustedInstaller can write. Other MSIX apps sign their files (the Claude MSIX `claude.exe` is signed `Anthropic, PBC`, L).
* Image names collide, so the name alone means nothing. On this PC, `...\steamapps\common\wallpaper_engine\launcher.exe` is signed `Skutta Software GmbH`, not Opera. `updater.exe` is signed by Mozilla, by Google (`GoogleUpdater`) and by `OBS Project, LLC`. `Update.exe` is the generic Squirrel updater used by Discord, Slack, Exodus and others. `browser.exe` is Yandex. Burp Suite's bundled Chromium (`%LOCALAPPDATA%\Programs\BurpSuite\burpbrowser\<ver>\chrome.exe`) is **NotSigned** (L). Genuine unsigned Chromium builds exist, so expect them.

## 1. Browsers

| Product | Image(s) | Exact signer CN(s) | Verified? | Install location(s) | Source |
|---|---|---|---|---|---|
| Google Chrome | chrome.exe, elevation_service.exe (in `<ver>\`), GoogleUpdater `updater.exe` | `Google LLC` (current; certs 2021-24 and 2024-27); `Google Inc` (pre-2018 builds) | Google LLC: L, C. Google Inc: E | `C:\Program Files\Google\Chrome\Application\`; per-user `%LOCALAPPDATA%\Google\Chrome\Application\`; updater `C:\Program Files (x86)\Google\GoogleUpdater\<ver>\updater.exe` | local; SoftwareCertificates `Browsers/Google LCC 2027.cer`; Elastic list |
| Microsoft Edge | msedge.exe, elevation_service.exe, msedgewebview2.exe | `Microsoft Corporation` | L | `C:\Program Files (x86)\Microsoft\Edge\Application\[<ver>\]`; `...\Microsoft\EdgeCore\<ver>\` (also `Optimized\`); WebView2 `C:\Program Files (x86)\Microsoft\EdgeWebView\Application\<ver>\`; per-user WebView2 `%LOCALAPPDATA%\Microsoft\EdgeWebView\Application\` (U). The Copilot app ships its own `elevation_service.exe` under `...\Microsoft\Copilot\Application\<ver>\` | local |
| Brave | brave.exe, elevation_service.exe, BraveUpdate.exe | `Brave Software, Inc.` | L, C, E | `C:\Program Files\BraveSoftware\Brave-Browser\Application\`; per-user `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\Application\`; updater `C:\Program Files (x86)\BraveSoftware\Update\[<ver>\]BraveUpdate.exe` | local; `Browsers/Brave Software, Inc. 2027.cer` |
| Mozilla Firefox | firefox.exe, updater.exe, maintenanceservice.exe | `Mozilla Corporation` (the DN also has `OU=Firefox Engineering Operations`; L changed from Mountain View to San Francisco around 2021, which doesn't affect the CN) | L, C, E, V | `C:\Program Files\Mozilla Firefox\`, `C:\Program Files (x86)\Mozilla Firefox\`, `%LOCALAPPDATA%\Mozilla Firefox\`; Store MSIX `WindowsApps\Mozilla.Firefox_*` (U) | local; striezel `Firefox.cs`; Elastic |
| Opera / Opera GX | opera.exe (in `<ver>\`), launcher.exe, opera_autoupdate.exe | `Opera Norway AS` (current, certs 2022 to 2026-05); `Opera Software AS` (older) | Opera Norway AS: C, E, V. Opera Software AS: E | `%LOCALAPPDATA%\Programs\Opera\` and `%LOCALAPPDATA%\Programs\Opera GX\` (launcher.exe at the root, opera.exe in the version folder); all-users `C:\Program Files\Opera\` | striezel `Opera.cs` / `OperaGX.cs` (full DN `CN=Opera Norway AS, ... SERIALNUMBER=916 368 127`); `Browsers/Opera May 2026.cer` |
| Vivaldi | vivaldi.exe, update_notifier.exe | `Vivaldi Technologies AS` | C (certs 2021-23 and 2023-26), E | `%LOCALAPPDATA%\Vivaldi\Application\`; system `C:\Program Files\Vivaldi\Application\` | `Browsers/Vivaldi 2025.cer`; Elastic `credential_access_access_to_browser_credentials_from_suspicious_memory.toml` |
| Yandex Browser | browser.exe, service_update.exe | `YANDEX LLC` | C (cert 2022-24), E | `%LOCALAPPDATA%\Yandex\YandexBrowser\Application\` (U, standard) | `Browsers/Yandex.cer`; Elastic |
| Chromium (raw/snapshot/ungoogled builds) | chrome.exe | **unsigned**; no signer to match | U (the Burp bundled Chromium is NotSigned, L) | anywhere, often `%LOCALAPPDATA%\Chromium\Application\` | local example |
| Arc | Arc.exe (MSIX) | `THE BROWSER COMPANY OF NEW YORK INC.` (upper case; cert 2023-06 to 2026-06) | C | MSIX `C:\Program Files\WindowsApps\TheBrowserCompany.Arc_*` | `Browsers/Arc Browser - Sept 2024.cer` |
| Thorium | thorium.exe | not found; believed **unsigned** | U | `%LOCALAPPDATA%\Thorium\Application\` (U) | no source found |
| (related) AVG Secure Browser / CCleaner Browser / Norton/Gen "neo" | — | `AVG Technologies USA, LLC`; `PIRIFORM SOFTWARE LIMITED`; `Gen Digital Inc.` | C | — | SoftwareCertificates `Browsers/` |

## 2. Messengers, wallets, file transfer

| Product | Image(s) | Exact signer CN(s) | Verified? | Install location(s) | Source |
|---|---|---|---|---|---|
| Discord | Discord.exe, Update.exe (Squirrel) | `Discord Inc.` | L, C (certs 2021-24, 2024-27), E | `%LOCALAPPDATA%\Discord\Update.exe`, `%LOCALAPPDATA%\Discord\app-<ver>\Discord.exe` (also `DiscordPTB\`, `DiscordCanary\`) | local; `Messaging or Conferencing/Discord 2024.cer` |
| Telegram Desktop | Telegram.exe, Updater.exe | `Telegram FZ-LLC` | L, C | `%APPDATA%\Telegram Desktop\` (default); Store MSIX `WindowsApps\TelegramMessengerLLP.TelegramDesktop_*` (U) | local; `Telegram July 2025.cer`. Older builds may carry `Telegram Messenger LLP` (U) |
| Steam | steam.exe, steamwebhelper.exe, steamservice.exe | `Valve Corp.` | L, C (certs 2021-24, 2024-27), E | `C:\Program Files (x86)\Steam\steam.exe`; `...\Steam\bin\cef\cef.win64\steamwebhelper.exe` (older `cef.win7x64`); `...\Steam\bin\SteamService.exe` and `C:\Program Files (x86)\Common Files\Steam\steamservice.exe` | local |
| WhatsApp (Store/MSIX, current) | WhatsApp.Root.exe | **file not Authenticode-signed**; package publisher `CN=24803D75-212C-471A-BC57-9EF86AB91435` | L | `C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_<ver>_x64__cv1g1gvanyjgm\` | local |
| WhatsApp (legacy Squirrel/Electron) | WhatsApp.exe | `WhatsApp LLC` (cert 2022-07 to 2025-07) | C | `%LOCALAPPDATA%\WhatsApp\` (U) | `Messaging or Conferencing/Whatsapp.cer`. Beware `Guangzhou Suyi Commerce and Trade Co., Ltd.`: a fake "WhatsApp" cert in the same repo |
| Slack | slack.exe | `Slack Technologies, Inc.` (cert 2022-23); `Slack Technologies, LLC` (current, after Salesforce) | C (Inc.); E (LLC) | `%LOCALAPPDATA%\slack\app-<ver>\slack.exe`; machine-wide `C:\Program Files\Slack\`; MSIX also exists | `Messaging or Conferencing/Slack.cer`; Elastic |
| Exodus | Exodus.exe | `Exodus Movement, Inc.` (cert 2024-27); `Exodus Movement Inc` (also listed) | C, E, V | `%LOCALAPPDATA%\exodus\app-<ver>\Exodus.exe` | [Exodus support: verify download](https://www.exodus.com/support/en/articles/8598686-how-can-i-verify-that-my-exodus-download-is-authentic); Elastic `credential_access_access_attempt_to_non_existing_cryptocurrency_wallet.toml` |
| Atomic Wallet | Atomic Wallet.exe | not found | U | `%LOCALAPPDATA%\Programs\atomic\` (U) | none |
| Ledger Live (being renamed "Ledger Wallet") | Ledger Live.exe | `Ledger SAS` (cert 2024-05 to 2025-05) | C | `C:\Program Files\Ledger Live\` (U) | `CryptoMiners/Ledger SAS - Crypto.cer`; [Ledger rename note](https://developers.ledger.com/docs/ledger-live/accounts/integration/staking/qa-requirements/e2e) |
| Electrum | electrum-<ver>.exe | `Electrum Technologies GmbH` (cert 2024-25); older releases were GPG-signed only (U) | C | `C:\Program Files (x86)\Electrum\` (U) | `CryptoMiners/Electrum Technologies GmbH.cer` |
| Blockstream Green (related wallet) | — | `Blockstream USA Corp` | E | — | Elastic wallet rule |
| FileZilla | filezilla.exe, fzsftp.exe | `Tim Kosse` | C (cert 2022-25), V | `C:\Program Files\FileZilla FTP Client\` | striezel `FileZilla.cs` (`CN=Tim Kosse, O=Tim Kosse, S=Nordrhein-Westfalen, C=DE`) |
| WinSCP | WinSCP.exe | `Martin Přikryl` (current EV, with ř); `Martin Prikryl` (cert 2022-11 to 2026-02) | V (Přikryl); C, E (Prikryl) | `C:\Program Files (x86)\WinSCP\`; per-user `%LOCALAPPDATA%\Programs\WinSCP\` | striezel `WinSCP.cs`; `Cloud backup or Exfil Tools/WinSCP.cer`; Elastic |
| Signal | Signal.exe | `Signal Messenger, LLC` | C (certs 2020-23, 2024-27), E | `%LOCALAPPDATA%\Programs\signal-desktop\` | `Messaging or Conferencing/Signal Jan 2025.cer` |

## 3. Password managers

| Product | Image(s) | Exact signer CN(s) | Verified? | Install location(s) | Source |
|---|---|---|---|---|---|
| KeePass 2 | KeePass.exe | `Open Source Developer, Dominik Reichl` | C, V | `C:\Program Files\KeePass Password Safe 2\` (or `(x86)`) | [KeePass FAQ](https://keepass.info/help/kb/faq.html); striezel `KeePass.cs`; `PasswordManger/Keepass.cer` |
| KeePassXC | KeePassXC.exe | `DroidMonkey Apps, LLC` | C (cert 2024-02 to 2027-02), V | `C:\Program Files\KeePassXC\` | striezel `KeePassXC.cs`; `PasswordManger/DroidMonkey Apps, LLC - KeePassXC.cer` |
| Bitwarden desktop | Bitwarden.exe | `Bitwarden Inc.` (EV) | V | `%LOCALAPPDATA%\Programs\Bitwarden\` (per-user) or `C:\Program Files\Bitwarden\` | bitwarden/clients `apps/desktop/scripts/appx-cross-build.ps1` (`CN=Bitwarden Inc., O=Bitwarden Inc., L=Santa Barbara, ... SERIALNUMBER=7654941`). `8bit Solutions LLC` (the former company name) is U: no binary signed with it was found. The certificate was rotated in 2026 ([Bitwarden community](https://community.bitwarden.com/t/windows-desktop-cli-microsoft-defender-notice/96853)) and the CN is presumably unchanged (U) |
| 1Password 8 | 1Password.exe, op.exe | `Agilebits` (current, Microsoft ID Verified / Trusted Signing chain, `CN=Agilebits, O=Agilebits, L=Toronto, S=Ontario, C=CA`); `AgileBits Inc.` (older, COMODO chain) | V for op.exe; 3 for older desktop components; U whether current 1Password.exe uses `Agilebits` | `%LOCALAPPDATA%\1Password\app\8\1Password.exe` (U) | [1Password CLI verify](https://www.1password.dev/cli/verify); [FreeFixer agile1pservice.exe](https://www.freefixer.com/library/file/agile1pservice.exe-125067/) |
| Dashlane | Dashlane.exe, DashlanePlugin.exe | `Dashlane USA, Inc.` (newer, DigiCert EV); `Dashlane` (older) | 3 | `%APPDATA%\Dashlane\` (old desktop app; Dashlane dropped the Windows desktop app in 2022 and now ships the extension only, U) | [FreeFixer Dashlane.exe](https://www.freefixer.com/library/file/Dashlane.exe-292892) |
| NordPass | NordPass.exe | not found | U | `%LOCALAPPDATA%\Programs\nordpass\` (U) | none (NordVPN's own `nordvpn s.a.` must **not** be assumed) |
| RoboForm | RoboForm.exe, RoboTaskBarIcon.exe | `Siber Systems Inc` (COMODO era, no period); `Siber Systems` (older Thawte era) | 3 | `C:\Program Files (x86)\Siber Systems\AI RoboForm\` (U) | [FreeFixer RoboTaskBarIcon.exe](https://www.freefixer.com/library/file/robotaskbaricon.exe-86233) |
| Enpass | Enpass.exe | `Sinew Software Systems Private Limited` (older); possibly `Enpass Technologies Inc.` after the 2021 certificate change (U) | 3 / U | `C:\Program Files\Enpass\` or `(x86)` | [FreeFixer Enpass.exe](https://freefixer.com/library/file/Enpass.exe-280826) |
| Keeper (related) | — | `Keeper Security Inc.` | E | — | Elastic |

## 4. Security, backup, cleaners, sync

| Product | Image(s) | Exact signer CN(s) | Verified? | Install location(s) | Source |
|---|---|---|---|---|---|
| ESET | ekrn.exe, egui.exe | `ESET, spol. s r.o.` | E | `C:\Program Files\ESET\ESET Security\` (also `ESET Endpoint Security\`) | Elastic (19 rules) |
| Kaspersky | avp.exe | `AO Kaspersky Lab`; `Kaspersky Lab JSC` (older); `Kaspersky Lab` | E | `C:\Program Files (x86)\Kaspersky Lab\<product>\` | Elastic |
| CrowdStrike Falcon | CSFalconService.exe, CSFalconContainer.exe | `CrowdStrike, Inc.` | C (certs 2015-18, 2023-26) | `C:\Program Files\CrowdStrike\` | `AV/Crowdstrike.cer` |
| SentinelOne | SentinelAgent.exe, SentinelServiceHost.exe | `Sentinel Labs, Inc.`; `SentinelOne Inc.`; `Sentinelone, Inc.` | C (Sentinel Labs, 2020-23); E (all three) | `C:\Program Files\SentinelOne\Sentinel Agent <ver>\` | `AV/SentinelOne Agent.cer`; Elastic |
| Malwarebytes | MBAMService.exe, mbam.exe | `Malwarebytes Inc` **and** `Malwarebytes Inc.` | C (`Inc`), E (both) | `C:\Program Files\Malwarebytes\Anti-Malware\` | `AV/Malwarebytes Dec 2024.cer`; Elastic |
| Avast | AvastSvc.exe, AvastUI.exe | `Avast Software s.r.o.` (cert 2022-09 to 2025-09); `Gen Digital Inc.` (2026 builds, Sectigo R36) | C, E (s.r.o.); 3 (Gen Digital) | `C:\Program Files\Avast Software\Avast\` | `AV/Avast.cer`; [FreeFixer AvastSvc.exe 26.4](https://www.freefixer.com/library/file/AvastSvc.exe-323061/) |
| AVG | AVGSvc.exe | `AVG Technologies USA, LLC` (cert to 2025-09); expected `Gen Digital Inc.` on new builds (U) | C, E | `C:\Program Files\AVG\Antivirus\` | `Browsers/AVG Browser.cer`; Elastic |
| Norton (same group) | — | `Symantec Corporation` → `NortonLifeLock Inc.` → `Gen Digital Inc.` | C / E / C | `C:\Program Files\Norton\` (U) | SoftwareCertificates; Elastic |
| McAfee consumer | mcshield.exe, mfemms.exe | `McAfee, LLC` (cert 2023-10 to 2026-10); `McAfee, Inc.` (older) | C, E | `C:\Program Files\McAfee\`, `C:\Program Files\Common Files\McAfee\` | `AV/McAfee, LLC - October 2024.cer`; Elastic |
| Trellix / McAfee ENS (enterprise) | mfetp.exe, mcshield.exe | `Musarubra US LLC` / `MUSARUBRA US LLC` (both casings listed) | E | `C:\Program Files\McAfee\Endpoint Security\` | Elastic |
| Elastic Defend | elastic-endpoint.exe | `Elasticsearch, Inc.` | E | `C:\Program Files\Elastic\Endpoint\` | Elastic |
| Palo Alto Cortex XDR | cyserver.exe, cytool.exe | `Palo Alto Networks`; `Palo Alto Networks (Netherlands) B.V.` | E | `C:\Program Files\Palo Alto Networks\Traps\` | Elastic |
| Trend Micro Apex One / OfficeScan | ntrtscan.exe, tmlisten.exe | `Trend Micro, Inc.` | E | `C:\Program Files (x86)\Trend Micro\OfficeScan Client\` (Apex One: `Security Agent\`) | Elastic |
| Sophos | SophosHealth.exe, SSPService.exe etc. | `Sophos Ltd`; `Sophos Limited` | C (Ltd, 2021-24), E (both) | `C:\Program Files\Sophos\` | `AV/sophos.cer`; Elastic |
| Bitdefender | bdservicehost.exe, vsserv.exe | `Bitdefender SRL` | C (old cert), E | `C:\Program Files\Bitdefender\` | `AV/bitdefender.cer`; Elastic |
| Veeam | Veeam.*.exe | `Veeam Software Group GmbH` (current); `Veeam Software AG` (older) | E | `C:\Program Files\Veeam\` | Elastic |
| Backblaze | bztransmit.exe, bztransmit64.exe, bzbui.exe | `Backblaze Inc` (as reported; punctuation not confirmed) | 3 | `C:\Program Files (x86)\Backblaze\` (64-bit in `x64\`) | [FreeFixer bztransmit64.exe](https://www.freefixer.com/library/file/bztransmit64.exe-162513/) |
| Carbonite | CarboniteService.exe, CarboniteUI.exe | `Carbonite` (newer); `Carbonite, Inc` (older); now OpenText, current name unknown | 3 / U | `C:\Program Files\Carbonite\` (U) | [FreeFixer CarboniteUI.exe](https://www.freefixer.com/library/file/CarboniteUI.exe-238306/) |
| Code42 / CrashPlan | CrashPlanService.exe | not found (expect `Code42 Software, Inc.` or `CrashPlan Group LLC`; both U) | U | `C:\Program Files\CrashPlan\` (U) | none |
| Macrium Reflect | ReflectService.exe, ReflectUI.exe, Reflect.exe | `Paramount Software UK Ltd` | V | `C:\Program Files\Macrium\Reflect\` | [Macrium KB](https://knowledgebase.macrium.com/x/-0d2) |
| MSP360 / CloudBerry | cbb.exe, CloudBerry*.exe | not found (`CloudBerry Lab` or `MSP360` would be U) | U | `C:\Program Files\CloudBerryLab\` (U) | none |
| Acronis | — | `Acronis International GmbH` | E | `C:\Program Files\Acronis\`, `C:\Program Files (x86)\Acronis\` | Elastic |
| Datto (now Kaseya) | — | `Datto Inc`; Kaseya products: `Kaseya Holdings Inc`, `KASEYA US LLC` | E | `C:\Program Files\Datto\` (U) | Elastic |
| CCleaner | CCleaner64.exe, CCleaner.exe | `Gen Digital Inc.` (cert 2024-05 to 2027-05); `PIRIFORM SOFTWARE LIMITED` (2022-25); `Piriform Software Ltd` (2021-24) | C, V, E | `C:\Program Files\CCleaner\` | striezel `CCleaner.cs` (`CN=Gen Digital Inc., O=Gen Digital Inc., S=Arizona, C=US`); `Unwanted/CCleaner Gen Inc - May 2027.cer` |
| BleachBit | bleachbit.exe, bleachbit_console.exe | `Open Source Developer, Andrew Ziem` (current); `Andrew Ziem` (old 0.9.x, COMODO) | V; 3 | `C:\Program Files (x86)\BleachBit\` (also portable) | [bleachbit.org SmartScreen page](https://www.bleachbit.org/microsoft-defender-smartscreen); [FreeFixer 0.9.6](https://www.freefixer.com/library/file/BleachBit-0.9.6-cs-setup.exe-116714) |
| PrivaZer | PrivaZer.exe | `Goversoft LLC` (newer); `Goversoft` (older) | 3 | `C:\Program Files (x86)\PrivaZer\` (U) | [FreeFixer PrivaZer portable](https://www.freefixer.com/library/file/PrivaZer_portable_V3_067.exe-292850/) |
| Dropbox | Dropbox.exe | `Dropbox, Inc` (**no period**) | C (cert 2020-24), E | `C:\Program Files (x86)\Dropbox\Client\`; per-user `%APPDATA%\Dropbox\bin\` | `Cloud backup or Exfil Tools/Dropbox, Inc.cer`; Elastic |
| Google Drive for desktop | GoogleDriveFS.exe | `Google LLC` | U (high confidence) | `C:\Program Files\Google\Drive File Stream\<ver>\` | none found |
| Box Drive | Box.exe, Box Local Com Service.exe | `Box, Inc.` | 3 | `C:\Program Files\Box\Box\` | [FreeFixer Box Local Com Service.exe](https://freefixer.com/library/file/Box%20Local%20Com%20Service.exe-239200) |
| Nextcloud desktop | nextcloud.exe | `Nextcloud GmbH` | C (certs 2020-23, 2023-09 to 2026-09) | `C:\Program Files\Nextcloud\` | `Cloud backup or Exfil Tools/Nextcloud GmbH - September 2026.cer` |

## 5. Developer and other tools

| Product | Image(s) | Exact signer CN(s) | Verified? | Install location(s) | Source |
|---|---|---|---|---|---|
| Docker Desktop and CLI | docker.exe, com.docker.backend.exe, Docker Desktop.exe, docker-buildx.exe, bundled kubectl.exe | `Docker Inc` (**no period, no comma**) | L, C | `C:\Program Files\Docker\Docker\` (`resources\bin\`, `resources\cli-plugins\`, `frontend\`); `C:\Program Files\Docker\cli-plugins\` | local |
| Roblox | RobloxPlayerBeta.exe | `Roblox Corporation` | L, C, E | `%LOCALAPPDATA%\Roblox\Versions\version-<hash>\`; all-users `C:\Program Files (x86)\Roblox\Versions\` | local. Roblox's anti-tamper vendor `BYFRON TECHNOLOGIES LLC` also appears in Elastic |
| NordVPN | NordVPN.exe, nordvpn-service.exe | `nordvpn s.a.` (lower case) | L, C | `C:\Program Files\NordVPN\` | local. Older builds: `Datasec Holding Ltd` (3). `TEFINCOM S.A.` is only the version-info company name, not the signer ([FreeFixer](https://freefixer.com/library/file/NordVPN.exe-312569)) |
| Anthropic Claude (desktop and Claude Code) | claude.exe, chrome-native-host.exe | `Anthropic, PBC` | L, C (certs 2024-25, 2025-26), E | MSIX `C:\Program Files\WindowsApps\Claude_<ver>_x64__pzs8sxrjxfjjc\app\`; Claude Code `%LOCALAPPDATA%\Claude-Data\...\claude-code\<ver>\...\claude.exe` (seen locally) | local |
| Internet Download Manager | IDMan.exe | `Tonec Inc.` | L, C | `C:\Program Files (x86)\Internet Download Manager\` | local |
| VS Code | Code.exe | `Microsoft Corporation` | L | `%LOCALAPPDATA%\Programs\Microsoft VS Code\`; system `C:\Program Files\Microsoft VS Code\` | local |
| GitHub CLI | gh.exe | `GitHub, Inc.` | L, E | `C:\Program Files\GitHub CLI\`; winget per-user `%LOCALAPPDATA%\Microsoft\WinGet\Packages\GitHub.cli_*\bin\` | local |
| Git for Windows | git.exe (also bash.exe etc.) | `Johannes Schindelin` (two DN variants, `L=Bruehl` and `S=Nordrhein-Westfalen`, same CN) | L, V, E | `C:\Program Files\Git\` (`cmd\`, `bin\`, `mingw64\bin\`, `mingw64\libexec\git-core\`) | local; striezel `Git.cs` |
| AWS CLI v2 | aws.exe | `Amazon.com Services LLC` (also `Amazon Services LLC` listed) | E (U that aws.exe specifically carries it) | `C:\Program Files\Amazon\AWSCLIV2\` | Elastic |
| Azure CLI | az.cmd → `python.exe` | expect `Microsoft Corporation` on the MSI and bundled python (U); az.cmd is a script | U | `C:\Program Files\Microsoft SDKs\Azure\CLI2\` | none |
| Google Cloud SDK | gcloud.cmd (script) → bundled python | installer `Google LLC` (U); scripts unsigned | U | `%LOCALAPPDATA%\Google\Cloud SDK\google-cloud-sdk\` | none |
| kubectl (upstream dl.k8s.io) | kubectl.exe | upstream is believed **not** Authenticode-signed (it ships Sigstore `.sig`/`.cert`); the Docker-bundled copy is `Docker Inc` | U (upstream); L (Docker copy) | user-chosen | [k8s mirror listing](https://ru.archive.ubuntu.com/mirrors/dl.k8s.io/v1.31.3/bin/windows/arm64/) |
| Terraform | terraform.exe | `HashiCorp, Inc.` | E (U whether every terraform.exe is signed) | user-chosen or winget path | Elastic |
| ngrok | ngrok.exe | `ngrok, Inc.` | C (cert 2022-23), E | user-chosen | `VPN Or Networking/ngrok.cer` |
| OpenVPN Connect | OpenVPNConnect.exe | `OpenVPN Inc.` | L, C | `C:\Program Files\OpenVPN Connect\` | local |
| ProtonVPN | ProtonVPN.exe, ProtonVPNService.exe | `Proton AG` (current); `Proton Technologies AG` (cert 2020-23) | E; C | `C:\Program Files\Proton\VPN\` (U) | Elastic; `VPN Or Networking/ProtonVPN.cer` |
| WireGuard | wireguard.exe | `WireGuard LLC` | L, C | `C:\Program Files\WireGuard\` | local |
| Thunderbird | thunderbird.exe | `Mozilla Corporation` | V | `C:\Program Files\Mozilla Thunderbird\` | striezel `Thunderbird.cs` |
| Mailbird | Mailbird.exe | `Mailbird, Inc.` | C (cert 2024-02 to 2027-02) | `C:\Program Files\Mailbird\` (U) | `Unwanted/Mailbird, Inc..cer` |
| Outlook (classic) | OUTLOOK.EXE | `Microsoft Corporation` | L | `C:\Program Files\Microsoft Office\root\Office16\` | local. New Outlook (`olk.exe`) is MSIX `WindowsApps\Microsoft.OutlookForWindows_*` (U) |

## Changes over time (renames to accept as old variants)

* **Avast / AVG / Norton / Avira / CCleaner → Gen Digital.** `Avast Software s.r.o.`, `AVG Technologies USA, LLC`, `Symantec Corporation` → `NortonLifeLock Inc.`, and `Piriform Software Ltd` / `PIRIFORM SOFTWARE LIMITED` all move to `Gen Digital Inc.` from about 2024 (CCleaner cert 2024-05; Avast 2026 builds). Avira still has its own `Avira Operations GmbH` cert (2023-26, C). Installed old versions keep the old names until they update.
* **Google:** `Google Inc` → `Google LLC` (2017-18).
* **Opera:** `Opera Software AS` → `Opera Norway AS`.
* **Kaspersky:** `Kaspersky Lab` → `Kaspersky Lab JSC` → `AO Kaspersky Lab`.
* **SentinelOne:** `Sentinel Labs, Inc.` → `SentinelOne Inc.` / `Sentinelone, Inc.`.
* **McAfee:** `McAfee, Inc.` → `McAfee, LLC` (consumer); enterprise moved to Trellix as `Musarubra US LLC`.
* **Slack:** `Slack Technologies, Inc.` → `Slack Technologies, LLC`.
* **Proton:** `Proton Technologies AG` → `Proton AG`.
* **Veeam:** `Veeam Software AG` → `Veeam Software Group GmbH`.
* **WinSCP:** `Martin Prikryl` → `Martin Přikryl` (EV cert with diacritic).
* **1Password:** `AgileBits Inc.` → `Agilebits` (Microsoft Trusted Signing chain, at least for op.exe).
* **NordVPN:** `Datasec Holding Ltd` (old) → `nordvpn s.a.`.
* **Dashlane:** `Dashlane` → `Dashlane USA, Inc.`.
* **RoboForm:** `Siber Systems` → `Siber Systems Inc`.
* **BleachBit:** `Andrew Ziem` → `Open Source Developer, Andrew Ziem`.
* **Bitwarden:** company renamed from 8bit Solutions LLC to Bitwarden Inc.; only `Bitwarden Inc.` is verified on Windows binaries.

## Gaps (could not verify; need a field observation)

Thorium (likely unsigned), Atomic Wallet, NordPass, Code42/CrashPlan, MSP360/CloudBerry, the current Carbonite/OpenText name, the current Enpass name, Google Drive (`Google LLC` expected), Azure CLI and gcloud (script wrappers), and the upstream kubectl. Suggestion: have the agent report the observed (image, path, signer) tuples for these apps from real fleets, then pin them.
