# Windows Infostealer Tradecraft (2025-2026) and EDR Detection Signals

Scope: Windows only. Research date: 2026-10-20. Material older than 2025 is marked **[OLDER]**. Defensive framing only: behaviors are described at the level needed to build detections.

---

## 1. Which stealer families are most active in 2025-2026, and what is their market share?

### Takeaway
The market is fragmented after law-enforcement action. Lumma led 2024 and early 2025 (about 92% of Russian Market log alerts in Q4 2024, per ReliaQuest). It was disrupted in May 2025 but kept operating, mainly through ClickFix. Acreed surged briefly afterwards. Rhadamanthys was dismantled in November 2025. Vidar 2.0 (released October 2025) has been the most-used stealer on Russian Market since November 2025, with StealC v2 also prominent. By 2025 infected hosts (Flashpoint), the top five were Lumma > Acreed > Rhadamanthys > Vidar > StealC.

### Cited Findings
**Overall volume and rankings**
- Flashpoint's 2026 Global Threat Intelligence Report counts 11.1M machines infected by infostealers in 2025 and 3.3B stolen credentials, cookies, tokens and records. Its 2025 ranking by infected hosts is Lumma, Acreed, Rhadamanthys, Vidar, StealC. By January 2026, Vidar 2.0 was the most widely used stealer among threat actors. Lumma's administrators were doxxed in August 2025. — [Help Net Security (Flashpoint report), Mar 12 2026](https://www.helpnetsecurity.com/2026/03/12/agentic-attack-chains-infostealers-criminal-markets/)
- Kaspersky DFI analyzed 5M stealer log files from 2025 and reports a 59% year-over-year rise in infections. About 35% of infections started from files run in `%LOCALAPPDATA%\Temp`, and about 32% originated from `C:\Windows\Microsoft.NET\Framework` (injection/LOLBin, e.g. into RegAsm/MSBuild). Observed filenames: Vidar uses "Bootstrapper.exe" variants, StealC uses names like "Licence_Version_Loader.exe" or random names, and RisePro uses MPGPH.exe and MSIUpdater.exe. — [Kaspersky via SocialNews, Jun 17 2026](https://www.socialnews.xyz/2026/06/17/kaspersky-35-of-infostealer-infections-begin-with-users-running-files-directly-from-temporary-folders/)
- Lumma accounted for almost 92% of Russian Market credential-log alerts in Q4 2024 (ReliaQuest). Acreed took the lead after the takedown (no percentage given). Article dated June 3, 2025. — [Dark Reading](https://www.darkreading.com/remote-workforce/lummac2-fractures-acreed-malware-top-dog)
- Intrinsec (Sep 2025): Acreed was the third-largest stealer with about 17% share, sharing the top tier with Rhadamanthys. First Acreed log appeared on Russian Market on Feb 14, 2025. Acreed logs are a few KB, compared with roughly 1-5 MB for Lumma logs. — [Intrinsec Acreed report (PDF)](https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf)
- Intrinsec (Apr 24, 2026): Vidar has been the most-used stealer on Russian Market since November 2025. Lumma use fell after May 2025 but continues, "mainly in ClickFix campaigns." StealC gained use after Acreed. Rhadamanthys rose around mid-2025 before its takedown. — [Intrinsec New Vidar (PDF)](https://www.intrinsec.com/wp-content/uploads/2026/04/TLP_CLEAR-20260424-New_Vidar.pdf); [Dark Reading, Apr 28 2026](https://www.darkreading.com/vulnerabilities-threats/vidar-top-chaotic-infostealer-market)

**Lumma (LummaC2)**
- The takedown was coordinated by Microsoft DCU, DOJ and Europol, with Cloudflare, Lumen, ESET and others. About 2,300 domains were seized or blocked. Microsoft observed about 394,000 infected Windows PCs between March 16 and May 16, 2025. — [Microsoft Security Blog, May 21 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/); [heise](https://heise.de/-10393351)
- Resurgence: infrastructure ramped back up within weeks. Targeted accounts returned to usual levels in June-July 2025. Operators moved away from Cloudflare toward providers such as Selectel, and from public forums to covert channels. — [Trend Micro, Jul 2025](https://www.trendmicro.com/en/research/25/g/lumma-stealer-returns.html)
- Check Point found that many Russia-hosted C2 servers survived. The developer claimed the main server was compromised through an iDRAC vulnerability and wiped. — [GBHackers (Check Point research)](https://gbhackers.com/lumma-infostealer-developers/)
- Lumma was still active in 2026. In February 2026 a ClickFix campaign used Win+X → Windows Terminal and injected Lumma into chrome.exe/msedge.exe via QueueUserAPC. — [The Hacker News (Microsoft), Mar 6 2026](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html)

**Vidar 2.0**
- Announced October 6, 2025 by "Loadbaks". It is a C++ to C rewrite with multithreaded collection (thread count based on CPU and RAM) and costs $300. Its ABE bypass launches the browser with debugging and injects shellcode or a reflective DLL into it, then returns keys to the main process over named pipes. Dead-drop C2 resolution uses Telegram bots and Steam profiles. Exfiltration is HTTP multipart. — [Trend Micro, Oct 21 2025](https://www.trendmicro.com/en/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
- An April 2026 campaign used malvertised cracks in password-protected ".bin" archives and a Go "Factory-v3" loader builder that also served Lumma. Loaders were padded to as much as 491 MB, and certificates were self-signed impersonations. A malicious MpClient.dll was sideloaded by a Defender binary. Vidar patched AmsiScanBuffer, used a Telegram dead drop, sent a ZIP to a raw IP on port 443, and dropped XMRig. — [Unit 42, Jul 7 2026](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)

**StealC v2**
- Released March 2025. It delivers EXE, MSI and PowerShell payloads, uses a JSON C2 protocol (create / upload_file / done / loader) with RC4 enabled from 2.1.1, decrypts data server-side, supports Chrome v20 (ABE), and has a unified file grabber, multi-monitor screenshots and a C2-triggered `self_delete`. It is often delivered by Amadey. — [Zscaler ThreatLabz, May 1 2025](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)

**Rhadamanthys**
- Version 0.9.2 (Oct 2025) shows a Lumma-like "anti-leak" MessageBox, runs heavy sandbox and HWID checks before contacting C2, fetches its core from C2 hidden in PNG, WAV or JPEG steganography, and uses Lua plugins for theft. — [The Hacker News (Check Point), Oct 3 2025](https://thehackernews.com/2025/10/rhadamanthys-stealer-evolves-adds.html)
- Operation Endgame (Nov 10-14, 2025) took down more than 1,025 servers and 20 domains linked to Rhadamanthys, VenomRAT and Elysium. Infections numbered in the hundreds of thousands, with several million credentials stolen. — [Help Net Security, Nov 13 2025](https://www.helpnetsecurity.com/2025/11/13/rhadamanthys-infostealer-operation-disrupted/)

**Acreed, Katz and other newcomers**
- Acreed resolves C2 through a BNB Smart Chain testnet `eth_call` (HTTP POST to an RPC endpoint on port 8545) or Steam profile comments, both XOR-decoded. It talks over HTTPS with TLS 1.1/1.2 only. User agents: `PohSoftware/1.0`, `POSDATAGENT`, `POHSOFTWARE`, `DLAGENT`. Endpoints include `/getjson.php`. It writes a `log_info.json` summary and includes clipper modules. — [Intrinsec Acreed (PDF)](https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf)
- Katz (first seen Apr 2025, $100/month), Bee (Jun 2025), Cyber ($99, self-hosted panel) and AURA (Jul 2025, advertises an ABE bypass). — [Flashpoint, Sep 2025](https://flashpoint.io/blog/infostealers-2025-katz-bee-acreed-more/)
- Amatera is a rebranded ACR Stealer. In 2026 ACR ran ClickFix campaigns (late April to mid-June 2026) through fake Claude / Claude Code pages delivered by malvertising and sites.google.com, stealing Chrome/Edge Login Data and Web Data plus M365/OneDrive documents. — [The Hacker News (Microsoft Defender Experts), Jul 17 2026](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html); [Proofpoint Amatera](https://www.proofpoint.com/us/blog/threat-insight/amatera-stealer-rebranded-acr-stealer-improved-evasion-sophistication)
- Red Canary's July 2026 top 10 is led by ClickFix-style delivery (ClearFake #1 for the fourth straight month, plus KongTuke and Scarlet Goldfinch). Stealers on the list are mostly macOS (MacSync, Phexia) plus Amber Albatross (fake free-software installers leading to a PyInstaller stealer). — [Red Canary Intelligence Insights Aug 2026](https://www.zscaler.com/blogs/cybersecurity-best-practices/intelligence-insights-august-2026)

### Inferences
- Detections should be **family-agnostic**. Families and brands churn every few months (Lumma → Acreed → Vidar/StealC), while the behaviors stay stable: file access to credential stores, DPAPI use, browser injection or debugging, and dead-drop resolution.
- Market-share figures are inconsistent across sources. Different vendors measure log uploads (Russian Market), infected hosts (Flashpoint) or detections (AV telemetry). The report should quote each figure with its metric.
- RedLine/META: I found no reliable 2025-2026 market-share data in this session. Kaspersky's "RedLine most prevalent" finding is **[OLDER]** (2023-2024 data). RedLine and META were disrupted by Operation Magnus in Oct 2024 **[OLDER]**, which is background knowledge not verified here.

### Gaps
- No exact percentage shares for 2026 (Intrinsec's 2026 chart is an image without numbers). ESET's H1 2026 public page gives no stealer family shares. Red Canary's 2026 Threat Detection Report PDF was not fetched.
- I found no primary source confirming a Lumma "second takedown" in 2026. One tech-insider headline claims it, but it was not verified.

---

## 2. Delivery vectors and detection signals

### Takeaway
Paste-and-run social engineering is the dominant delivery vector for Windows stealers in 2025-2026: ClickFix, fake CAPTCHA, FileFix and their variants. ESET recorded a 108% rise in ClickFix detections from H2 2025 to H1 2026. Attackers are rotating input surfaces (Run dialog → Explorer address bar → Windows Terminal via Win+X → nslookup/DNS staging) to evade RunMRU-centric detections. The other main vectors are cracked software, malvertising and SEO lures, GitHub, and YouTube.

### Cited Findings
**ClickFix (Run dialog)**
- Lures include fake CAPTCHA, reCAPTCHA, Cloudflare Turnstile, Chrome "Aw, Snap!", Word Online and Discord verification. Lumma is the most prolific ClickFix payload. Most payloads run filelessly through mshta, powershell, msbuild or regasm. — [Microsoft, Aug 21 2025](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- Signals:
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` values containing LOLBins (powershell, mshta, rundll32, wscript, curl, wget) or `iwr` / `irm` / `iex`. The key is not written if execution fails.
  - Payloads hosted on raw IPs, CDNs, paste sites or rare TLDs, often with double extensions (e.g. `.hta.mp4`).
  - Defender detection names: Behavior:Win32/ClickFix, Behavior:Win32/RegRunMRU, Trojan:HTML/FakeCaptcha. MDE alert: "Suspicious command in RunMRU registry".
  
  — [Microsoft, Aug 21 2025](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- Telemetry: Sysmon EID 13 on RunMRU (holds the pre-decoding pasted string), EID 1 or 4688 with explorer.exe → powershell/cmd/mshta/wscript, and PowerShell 4104 (de-obfuscated). Treat a gap of seconds between the RunMRU write and process creation as a scoring signal. The Run dialog accepts at most 259 characters. Evasions include LOLBin rotation (conhost, forfiles, msiexec), split execution and PowerShell 2.0 downgrade. — [Decryption Digest, Sep 2 2026](https://www.decryptiondigest.com/blog/clickfix-detection-guide-fake-captcha-malware)
- KQL ideas: RunMRU writes by explorer.exe containing a ✅ emoji prefix, non-Latin homoglyphs, `mshta`, `bitsadmin`, `forfiles` or `ProxyCommand=`, or cmd/powershell with `-w h`, `iex`, `irm`, `DownloadString`, `FromBase64String` or `[char]`. MDE has shipped ClickFix behavior alerts since Q2 2025. Cloud alerts can lag by more than a minute. A WindowsTerminal.exe → pwsh → powershell chain has been observed. — [glueckkanja, Sep 21 2026](https://www.glueckkanja.com/en/posts/2026-09-21-clickfix-prevent-detect)
- SigmaHQ rule "Suspicious ClickFix/FileFix Execution Pattern" (id d487ed4a-fd24-436d-a0b2-f4e95f7b2635, 2025-11-19, high): ParentImage ends with `\explorer.exe`, CommandLine contains `#`, and CommandLine contains a lure keyword (captcha, robot, human, verify, verification, …). This catches the "command # I am not a robot" comment trick. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_clickfix_filefix_execution/)
- ESET H1 2026: ClickFix detections up 108% from H2 2025. Variants named include AI-fix, CrashFix and ConsentFix. — [ESET Threat Report page](https://www.eset.com/int/business/threat-report/)

**FileFix (Explorer address bar or browser file-upload dialog)**
- SigmaHQ "FileFix - Suspicious Child Process from Browser File Upload Abuse" (id 4be03877-d5b6-4520-85c9-a5911c0a656c, 2025-06-26, high): ParentImage is chrome, msedge, firefox or brave; Image is powershell, pwsh, cmd, mshta, certutil, bitsadmin or regsvr32; CommandLine contains `#`. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_filefix_browsers)
- Elastic "Potential FileFix Command via Windows Explorer Address Bar" (created 2026-09-28, high, risk 73): registry write to `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths\*` where the data invokes powershell, pwsh, mshta, msiexec, rundll32, cmd /c, curl, certutil, bitsadmin, wscript, conhost or forfiles with arguments. — [detection.fyi (Elastic)](https://detection.fyi/elastic/detection-rules/windows/execution_windows_filefix_typedpaths/)

**Other ClickFix variants**
- Windows Terminal: the lure says Win+X then I to open wt.exe, which bypasses Run-dialog detections. Two chains followed: a renamed 7-Zip extracting a ZIP plus scheduled tasks and Defender exclusions; or cmd → batch file in AppData\Local → VBS in %TEMP% → MSBuild with EtherHiding RPC lookups. Both ended in QueueUserAPC injection of Lumma into Chrome/Edge (observed Feb 2026). — [The Hacker News (Microsoft), Mar 6 2026](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html)
- DNS / nslookup staging (Feb 2026): cmd runs nslookup against a hard-coded external DNS server, and the `Name:` field of the response is executed as stage 2. This led to a portable Python bundle (ModeloRAT, not a stealer) with persistence via `%STARTUP%\MonitoringService.lnk`. — [Security Affairs, Feb 16 2026](https://securityaffairs.com/188039/hacking/microsoft-alerts-on-dns-based-clickfix-variant-delivering-malware-via-nslookup.html)
- ACR Stealer (2026) chains:
  - mshta → VBScript → PowerShell, with the payload hidden in JPEG pixels hosted on ImgBB.
  - rundll32 loading a DLL over WebDAV/HTTPS → ZIP in `%LocalAppData%\Temp` → bundled pythonw.exe, plus EtherHiding.
  
  Persistence uses a hidden scheduled task disguised as an update, with timestomping and PowerShell history clearing. Red Canary suggests hunting for rundll32 with no command-line arguments that makes network connections. — [The Hacker News, Jul 17 2026](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)
- ClearFake injects JavaScript into compromised sites to show fake CAPTCHA paste lures and uses EtherHiding (blockchain-hosted JS). Red Canary advises blocking direct blockchain RPC access where it isn't needed. — [Red Canary Aug 2026](https://www.zscaler.com/blogs/cybersecurity-best-practices/intelligence-insights-august-2026)

**Cracked software, malvertising, GitHub, YouTube**
- Lumma post-takedown: fake cracks and keygens behind a TDS that serves password-protected downloaders; auto-generated GitHub repositories with AI-written READMEs offering game cheats as EXE/ZIP Releases; YouTube "Photoshop crack" videos; Facebook ads; sites.google.com download pages. — [Trend Micro, Jul 2025](https://www.trendmicro.com/en/research/25/g/lumma-stealer-returns.html)
- Lumma pre-takedown: phishing through the Prometheus TDS, malvertising for Notepad++ and Chrome updates, EtherHiding on BSC, and drops by DanaBot. — [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- Vidar: fake "NeoHub" installer on MediaFire reached from YouTube, with msedge_elf.dll sideloading and fake certificates impersonating "githab.com". Also delivered through trojanized npm packages (Nov 2025). — [Intrinsec Apr 2026](https://www.intrinsec.com/wp-content/uploads/2026/04/TLP_CLEAR-20260424-New_Vidar.pdf)
- Katz: gzip'd JavaScript → hidden PowerShell → PE hidden in an image hosted on archive.org → .NET loader → payload from Cloudflare `r2.dev` hollowed into MSBuild.exe, with a UAC bypass through cmstp.exe. — [Nextron, May 23 2025](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)
- Kaspersky: lures include activators, cracks and game mods, and users are instructed to disable AV first. — [Kaspersky via SocialNews](https://www.socialnews.xyz/2026/06/17/kaspersky-35-of-infostealer-infections-begin-with-users-running-files-directly-from-temporary-folders/)

### Inferences
- Detection for this stage should key on the **intersection of three things**: (a) an interactive shell or LOLBin whose parent is explorer.exe, a browser or WindowsTerminal.exe; (b) a network fetch or decode within seconds; (c) a payload landing in or running from %TEMP%, %LOCALAPPDATA% or %APPDATA%, or hollowing into .NET Framework binaries (MSBuild, RegAsm, RegSvcs). Covering only RunMRU misses FileFix (TypedPaths), Terminal and nslookup variants.
- Strong cheap signals:
  - Very large executables (null-padded to hundreds of MB).
  - Password-protected archives downloaded by a browser and then extracted.
  - Self-signed or impersonated certificates.
  - Defender binaries (MpCmdRun, NisSrv) or Edge components running from user-writable paths and loading MpClient.dll or msedge_elf.dll locally.

### Gaps
- Discord-specific delivery (fake game-test invitations) was not researched in depth this session.
- I found no source confirming a native Windows 11 paste or Run-dialog warning built specifically for ClickFix.

---

## 3. Targets and file paths

### Takeaway
All major families collect the same core set:
- Chromium `Login Data`, `Cookies` (under `Network\`), `Web Data` and `Local State`.
- Firefox `key4.db`, `logins.json`, `cookies.sqlite` and `cert9.db`.
- Wallet extension LevelDB stores and desktop wallets.
- Discord tokens, Telegram `tdata`, Steam `ssfn`/VDF, FileZilla and WinSCP.
- VPN configs, and increasingly cloud CLI and MSAL tokens.
- Documents matching configurable masks.

### Cited Findings
- Vidar 2.0 targets:
  - Browsers: Chrome, Edge, Opera, Opera GX, Vivaldi, Firefox, Waterfox and Palemoon (Login Data, Web Data, logins.json, cookies.sqlite, key4.db).
  - Wallets: extension IndexedDB/LevelDB stores and the Monero wallet directory.
  - Cloud: `.aws` and `.azure` credentials, Azure identity tokens and the MSAL cache.
  - FTP/SSH: FileZilla recent servers and WinSCP sessions.
  - Apps: Steam login and Steam Guard `ssfn` files, Telegram Desktop data and Discord token files.
  - A file grabber across user directories and removable drives.
  
  — [Trend Micro, Oct 2025](https://www.trendmicro.com/en/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
- Lumma targets browser passwords, cookies and autofill (Chromium and Gecko), the MetaMask, Electrum and Exodus wallets, `.ovpn` files, email and FTP clients, Telegram, and .pdf/.docx/.rtf documents in user profiles. — [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- RedLine **[OLDER, but its path list is the template for successors]**:
  - Messaging and gaming: `Telegram Desktop\tdata`; Discord `.log` and `.ldb` files; Steam SSFN and VDF files (path read from the `SteamPath` registry value).
  - FTP: FileZilla `recentservers.xml`.
  - VPN: `%LOCALAPPDATA%\NordVPN\...\user.config` and `%APPDATA%\OpenVPN Connect\profiles`.
  - Wallets: `%APPDATA%\Armory`, `%APPDATA%\atomic`, `%APPDATA%\Guarda`, `%APPDATA%\Electrum\wallets`, `com.liberty.jaxx`, and any `wallet.dat`.
  - Discovery: enumerates `SOFTWARE\Clients\StartMenuInternet` and the Uninstall keys.
  
  — [SecurityScorecard](https://securityscorecard.com/research/detailed-analysis-redline-stealer/)
- StealC v2 has a unified grabber for wallets, gaming, messengers, email, VPN and browsers, with Steam and Outlook paths hardcoded. — [Zscaler, May 2025](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)
- Katz targets browser data, wallets (including Brave Wallet), email, Steam, FTP, VPN, messaging apps, WiFi profiles (via `netsh`) and `ngrok.yml`. It backdoors Discord by modifying `index.js` in the latest `app-*` directory and writes decrypted keys to plaintext files such as `decrypted_chrome_key.txt` in AppData. — [Nextron, May 2025](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)
- Acreed checks wallet extensions by ID (MetaMask, Phantom, OKX, Rabby) and desktop wallets, and collects Chrome, Edge and Brave User Data. — [Intrinsec Acreed](https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf)
- ACR Stealer (2026) collects Chrome and Edge `Login Data` and `Web Data` via DPAPI, plus PDFs and M365 documents synced from OneDrive and SharePoint. — [The Hacker News, Jul 2026](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)
- SigmaHQ path set (rule a1dfd976, 2025-05-22): about 50 browser vendor folders × `\User Data` or `\Profiles\` × `\Login Data`, `\Cookies`, `\EncryptedStorage`, `\WebCache\`, `logins.json`, `key4.db`, `cert9.db`, `cookies.sqlite`, `formhistory.sqlite`, `places.sqlite`. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files/)
- Elastic's sensitive-file set **[OLDER, 2023]** adds:
  - DPAPI master keys (`Protect\<SID>`, CREDHIST, and the S-1-5-18 system key); Vault and Credentials folders.
  - RDCMan settings; NordVPN `user.config`; pgpass and DB tools.
  - AWS, gcloud and Azure configs; Git credentials; `.ssh`; KeePass `.kdbx`; key and certificate files; Slack cookies; Thunderbird; WLAN profiles.
  - Registry: PuTTY, WinSCP, TeamViewer and OpenVPN keys, and Outlook password values.
  
  — [Elastic Security Labs, Mar 2023](https://www.elastic.co/security-labs/detect-credential-access)

### Inferences
Path patterns an EDR should watch. These are common knowledge consistent with the sources above; exact subpaths should be validated in a lab.
- **Chromium:** `%LOCALAPPDATA%\<Vendor>\<Browser>\User Data\Local State` and `...\<Profile>\{Login Data, Login Data For Account, Web Data, Network\Cookies}`.
- **Wallet extensions:** `...\<Profile>\Local Extension Settings\<extID>\` and `...\IndexedDB\chrome-extension_<extID>*`.
- **Firefox:** `%APPDATA%\Mozilla\Firefox\Profiles\*\{key4.db, logins.json, cookies.sqlite, cert9.db}`.
- **Discord:** `%APPDATA%\discord*\Local Storage\leveldb\*.ldb|*.log` and `%LOCALAPPDATA%\Discord\app-*\modules\discord_desktop_core-*\...\index.js` (tamper target).
- **Telegram:** `%APPDATA%\Telegram Desktop\tdata\`.
- **Steam:** `<SteamPath>\ssfn*` and `config\*.vdf`.
- **Desktop wallets:** `%APPDATA%\Exodus\exodus.wallet\` and `%APPDATA%\Electrum\wallets\`.
- **FileZilla:** `%APPDATA%\FileZilla\{recentservers.xml, sitemanager.xml}`.
- **Cloud and dev:** `%USERPROFILE%\.aws\credentials`, `.azure\msal_token_cache*`, `%LOCALAPPDATA%\.IdentityService\`.

High-fidelity behavior: **one non-browser process touching three or more distinct categories** (browser + wallet + messenger) within about 60 seconds. This matches Elastic's "≥3 sensitive opens within 1 min" hunt and the smash-and-grab pattern.

### Gaps
- No authoritative 2025-2026 per-family list of wallet extension IDs was collected.
- Password manager targeting (KeePass, Bitwarden desktop, 1Password) is mentioned only in passing. Sources don't confirm which families actively target vaults versus just grabbing `.kdbx` files.

---

## 4. Chrome App-Bound Encryption (ABE): mechanism, bypasses, telemetry

### Takeaway
ABE (Chrome 127, July 2024) wraps the cookie key with a SYSTEM-run elevation service that checks the caller's identity, specifically its path. The `v20` prefix marks ABE-encrypted values. Stealers bypassed it within about 45 days. Bypasses fall into six classes, each with distinct telemetry:
1. CDP / remote debugging (restricted on the default profile from Chrome 136).
2. COM IElevator abuse from the Chrome directory, or via injection.
3. Admin/SYSTEM re-implementation of the decryption.
4. Injection into chrome.exe (CreateRemoteThread, QueueUserAPC, reflective DLL).
5. ChromeKatz-style memory reading of CookieMonster.
6. Debugger and hardware-breakpoint key capture (VoidStealer, 2026).

### Cited Findings
**Mechanism**
- A privileged service running with system privileges encodes the requesting app's identity into the encrypted data and refuses to decrypt for other apps. Malware must therefore get SYSTEM or inject into Chrome, both of which are "noisier." Chrome logs Event ID 257 (source "Chrome", Application log) when verification fails. Policy `ApplicationBoundEncryptionEnabled` exists for roaming-profile environments. At launch ABE covered cookies only, with other secrets planned. — [Google Security Blog, Jul 30 2024 [OLDER]](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)
- The elevation service validates only the calling process's path, so code running from the browser's application directory, or injected into the browser, can call IElevator DecryptData. Chrome 137+ added post-processing: on domain-joined hosts a CNG key plus XOR; on others a hard-coded ChaCha20-Poly1305 key. Re-implementing this requires SYSTEM. Chrome 137 also removed `--load-extension`, which is still accepted by Edge. Edge lacks Chrome's extra post-processing layer. — [SpecterOps, Aug 27 2025](https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/)
- The elevation service COM CLSID used by METASTEALER is `708860E0-F641-4611-8895-7D867DD3675B` (GoogleChromeElevationService). — [Elastic, Oct 2024 [OLDER]](https://www.elastic.co/security-labs/katz-and-mouse-game)

**Bypasses observed in the wild**
- Speed and scope: first bypass seen Sep 12, 2024, under 45 days after release. Families claiming a bypass: Phemedrone, Lumma, Meta, Lumar, Meduza, Vidar, StealC, Rhadamanthys and WhiteSnake. — [SpyCloud, Feb 2025](https://spycloud.com/blog/infostealers-bypass-new-chrome-security-feature/)
- Elastic (Oct 2024) **[OLDER but foundational]**:
  - **StealC/Vidar:** ChromeKatz-like. Kills chrome.exe, relaunches it on a hidden desktop, and reads CookieMonster from the NetworkService utility process with ReadProcessMemory.
  - **METASTEALER:** impersonates a SYSTEM token and calls DecryptData via COM (requires admin).
  - **Phemedrone:** runs `--remote-debugging-port=9222 --window-position=-2400,-2400` and calls `Network.getAllCookies` over WebSocket.
  - **Xenostealer:** injects into chrome.exe (SharpInjector) to call DecryptData.
  - **Lumma:** creates chrome.exe, reads `chrome.dll` with NtReadVirtualMemory, and signature-scans for CookieMonster.
  
  — [Elastic Security Labs](https://www.elastic.co/security-labs/katz-and-mouse-game)
- Vidar 2.0 launches the browser with debugging enabled, then injects shellcode or a reflective DLL. Keys return over named pipes. — [Trend Micro, Oct 2025](https://www.trendmicro.com/en/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
- Katz launches Chromium headless, injects a DLL with CreateRemoteThread, uses IElevator from inside the browser, and writes `decrypted_*_key.txt`. — [Nextron, May 2025](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)
- Lumma (Feb 2026) uses QueueUserAPC injection into chrome.exe and msedge.exe. — [The Hacker News (Microsoft), Mar 2026](https://thehackernews.com/2026/03/microsoft-reveals-clickfix-campaign.html)
- VoidStealer v2.0 (Mar 2026) spawns the browser and attaches as a **debugger** (no injection, no admin). It waits for chrome.dll or msedge.dll to load, locates the code that handles the plaintext `v20_master_key`, and sets **hardware breakpoints** on the browser threads to read the key from memory at startup. Adapted from the public ElevationKatz project. — [Gen Digital, Mar 19 2026](https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass)

**Chrome 136 remote-debugging restriction**
- Chrome 136 ignores `--remote-debugging-port` and `--remote-debugging-pipe` on the default data directory. A non-standard `--user-data-dir` is required, and it uses a different encryption key. Google's stated rationale is infostealers turning to CDP after ABE. Announced Mar 17, 2025. — [Chrome Developers blog](https://developer.chrome.com/blog/remote-debugging-port)
- Post-136 workarounds:
  - Swap the user's shortcut to add debugging flags and an alternate data directory, forcing re-login.
  - Edge does not need the alternate directory but all Edge instances must be closed first.
  
  — [SpecterOps, Aug 2025](https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/)
- In-process CDP enablement (Aug 2026): inject into a running chrome.exe or msedge.exe and call Chromium's internal remote-debugging startup routine. No launch flag is needed. This enables live session riding that sidesteps device-bound cookies. Telemetry: Sysmon EID 8 (CreateRemoteThread) into chrome/msedge plus EID 10 with GrantedAccess `0x143a`. — [SpecterOps, Aug 13 2026](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
- Edge reportedly decrypts the entire saved-password vault into process memory at launch (disclosed Apr 29, 2026). Microsoft called this "by design." ABE protects keys at rest, not memory. — [PPC Land, May 2026](https://ppc.land/microsoft-edge-keeps-every-saved-password-in-cleartext-memory-at-launch/)

**Telemetry and detection per technique**
- **CDP / debugging flags:**
  - SigmaHQ "Browser Started with Remote Debugging" (b3d34dc5, medium): CommandLine contains `--remote-debugging-`; for Firefox, `-start-debugger-server`. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_browsers_remote_debugging/)
  - SigmaHQ "Potential Data Stealing Via Chromium Headless Debugging" (3e8207c5, high): `--remote-debugging-` + `--user-data-dir` + `--headless`. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging/)
  - Elastic "Potential Cookies Theft via Browser Debugging" (medium, high noise): debugging argument + user-data-dir, excluding port 0. — [Elastic](https://www.elastic.co/guide/en/security/current/potential-cookies-theft-via-browser-debugging.html)
  - Elastic "Browser Process Spawned from an Unusual Parent" (high, risk 73): chrome or msedge with a bare command line, `--headless` with logging suppressed, `--remote-debugging-port=922?` + `--profile-directory="Default"`, or `--window-position=-*,-*`; parent not explorer.exe, Program Files, sihost or RuntimeBroker. — [Elastic docs](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/credential_access_browsers_unusual_parent)
  - Elastic hunt: a non-browser process connecting to a local debugging port (e.g. 9222). — [Elastic Labs](https://www.elastic.co/security-labs/katz-and-mouse-game)
- **COM IElevator:**
  - Enable 4663 auditing on the elevation service CLSID registry key and alert on processes other than Chrome or `elevation_service.exe`.
  - EQL sequence: about five chrome.exe terminations followed within 1 second by an `elevation_service.exe` start.
  - Hunt for unsigned DLLs or EXEs executing from `Program Files\Google\Chrome\Application`, the folder the service trusts.
  
  — [Elastic Labs](https://www.elastic.co/security-labs/katz-and-mouse-game)
  - The detection-chokepoints project flags 4688 events with `GoogleChromeElevationService` in the command line. — [detection-chokepoints](https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/)
- **Injection and memory reading:** Sysmon EID 8 into chrome or msedge, and EID 10 with GrantedAccess `0x1010`, `0x1438` or `0x143a`. Exclude EDR/AV processes. — [detection-chokepoints](https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/); [SpecterOps 2026](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
- **Debugger / hardware breakpoints:**
  - Alert on a debug attach to browser processes (DebugActiveProcess, or a browser created with DEBUG_PROCESS) and on browsers launched suspended or hidden.
  - Alert on cross-process memory reads of browsers and on thread-context changes setting debug registers (Dr0-Dr7) on browser threads.
  - Alert on hidden desktops and off-screen windows.
  
  — [Gen Digital, Mar 2026](https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass)
- **Elastic endpoint protections** (names): Web Browser Credential Access via Unusual Process; via Unsigned Process; Access to Browser Credentials from Suspicious Memory; Failed Access Attempt to Web Browser Files; Browser Debugging from Unusual Parent; Potential Browser Information Discovery. — [Elastic Labs](https://www.elastic.co/security-labs/katz-and-mouse-game)
- **Extension loading:** alert on `--load-extension` in command lines, and on new extension folders with unrecognized IDs. — [SpecterOps 2025](https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/)

### Inferences
- A robust EDR should monitor **all access paths into browser processes**, not just file reads:
  - OpenProcess handle rights (via ObRegisterCallbacks, or ETW Threat-Intelligence `READVM_REMOTE` / `WRITEVM_REMOTE` / `QUEUEUSERAPC_REMOTE` / `SETTHREADCONTEXT_REMOTE` events).
  - Debug-object creation and attach.
  - Image loads from the Chrome Application directory that are not Google-signed.
  - COM activation of the elevation service by non-Chrome callers.
- The ETW Threat-Intelligence provider requires a PPL antimalware-signed service. This is an inference to be verified by the platform research thread.
- Chrome 136 makes the "default profile + debugging port" pattern mostly obsolete. Current detections should emphasize: debugging flags with a `--user-data-dir` pointing into Temp or AppData copies of a profile; shortcut (.lnk) modification adding debugging flags; and injection into running browsers.

### Gaps
- The xaitax ABE research document (IElevator interface IDs for Edge and Brave, `APPB` prefix details) could not be fetched. Interface specifics are not verified here.
- No public data on what percentage of 2025-2026 logs contain usable v20 cookies.

---

## 5. Exfiltration channels, size and timing

### Takeaway
Most stealers exfiltrate by HTTP(S) POST (multipart, JSON or form) to a panel. C2 addresses are resolved through dead drops: Telegram channels and bots, Steam profile comments, and blockchain smart contracts (BSC / EtherHiding). Long-lived domains are avoided. Logs are small (KB to a few MB) and sent in chunks within seconds to minutes. Staging is deleted afterwards (self-delete flags, staging folder wipes).

### Cited Findings
- **Lumma:** hardcoded tier-1 C2s behind Cloudflare, with Telegram (checked first) and Steam profiles as fallbacks. HTTPS POST with form fields `act`, `ver` (4.0), `uid`/`lid`, `cid`/`j`, `hwid`, `pid`. Commands are RECEIVE_MESSAGE, SEND_MESSAGE (chunked upload) and GET_MESSAGE. — [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- **Lumma post-takedown:** reduced Cloudflare use, with hosting moved to providers such as Selectel. — [Trend Micro](https://www.trendmicro.com/en/research/25/g/lumma-stealer-returns.html)
- **Vidar:**
  - Telegram and Steam dead drops; HTTP POST with Base64 over HTTPS in chunks. — [Intrinsec 2026](https://www.intrinsec.com/wp-content/uploads/2026/04/TLP_CLEAR-20260424-New_Vidar.pdf)
  - Multipart form; cleans up temp artifacts afterwards. — [Trend Micro](https://www.trendmicro.com/en/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
  - ZIP sent to a raw IP on 443; ip-api[.]com geolocation lookup; Telegram alerts to the operator. — [Unit 42](https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/)
- **StealC v2:** JSON over HTTP on port 80 to `.php` endpoints, with RC4 from 2.1.1 and a server-triggered `self_delete`. — [Zscaler](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)
- **Acreed:** BSC testnet `eth_call` (port 8545) or Steam comments for C2; TLS 1.1/1.2 only; distinctive user agents. — [Intrinsec Acreed](https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf)
- **Katz:** reconnects to a hardcoded IP every 5 seconds, deletes its staging folder after upload, and modifies the Discord client to send a `katz-ontop` user agent. — [Nextron](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)
- **Telegram Bot API:** SigmaHQ "Suspicious Non-Browser Network Communication With Telegram API" (c3dbbc9f, medium) flags `api.telegram.org` from non-browser images. — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access)
- **Discord webhooks:** `discord.com/api/webhooks/...` needs only a URL. PowerShell logs show webhook responses. — [Pen Test Partners, Sep 2025](https://www.pentestpartners.com/security-blog/discord-as-a-c2-and-the-cached-evidence-left-behind/)
- **Log sizes:** Acreed logs are a few KB; Lumma logs are about 1-5 MB. — [Intrinsec Acreed](https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf)
- **Speed:** Vidar 2.0 multithreading "shortens the time the malware stays active on a system." — [Trend Micro](https://www.trendmicro.com/en/research/25/j/how-vidar-stealer-2-upgrades-infostealer-capabilities.html)
- **Dead-drop and EtherHiding guidance:** use network signatures, enforce proxy policy on external services (Pastebin, Telegram), and block or baseline blockchain RPC endpoints. — [Red Canary Aug 2026](https://www.zscaler.com/blogs/cybersecurity-best-practices/intelligence-insights-august-2026)

### Inferences
Network-side EDR signals:
- A **non-browser process** making DNS or HTTPS connections to `api.telegram.org`, `steamcommunity.com` profile pages, `discord.com/api/webhooks`, BSC/ETH RPC endpoints (e.g. `*.binance.org`, port 8545), `ip-api.com` or `ipinfo`, `r2.dev`, `*.workers.dev` or `trycloudflare.com`.
- The above **within about 60-300 s of credential-file access by the same process**. This correlation is the highest-value stealer detection.
- Outbound POSTs from processes with no prior network history; .NET Framework LOLBins (MSBuild, RegAsm, RegSvcs) making external connections.
- The process deleting its own image shortly after a large upload (e.g. a `cmd /c timeout & del` pattern; general knowledge, not sourced here).

### Gaps
- No vendor dataset found with typical end-to-end dwell time (e.g. median seconds from execution to exfiltration).
- Cloudflare Workers and Tunnel use was not confirmed for a specific 2025-2026 Windows stealer in these sources. Only Katz's r2.dev staging and Lumma's Cloudflare proxying are sourced.

---

## 6. Concrete detection rules and telemetry sources

### Takeaway
A layered rule set covers stealers well:
- File-access monitoring of credential stores by unexpected processes (kernel minifilter, Microsoft-Windows-Kernel-File ETW, or SACL 4663).
- DPAPI decrypt attribution (Crypto-DPAPI/Debug event 16385).
- Browser launch-argument rules.
- Process access and injection into browsers.
- ClickFix/FileFix process and registry rules.
- Non-browser access to messaging and dead-drop APIs.

Correlate these per process within a short time window.

### Cited Findings
**Credential file access**
- SigmaHQ "Access To Browser Credential Files By Uncommon Application" (91cb43db, medium): needs the **Microsoft-Windows-Kernel-File ETW** provider. Covers WebCacheV01.dat, Firefox cookies.sqlite, key3/key4.db and logins.json, and Chrome Login Data, Network\Cookies and Local State. Filters System, Program Files, System32 and Defender. "Requires heavy baselining." — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_browser_credential_access/)
- SigmaHQ "Suspicious File Access to Browser Credential Storage" (a1dfd976, 2025-05-22, low): broad vendor list (see section 3). — [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_susp_process_access_browser_cred_files/)
- Detection-chokepoints staged rules (Hunt / Analyst / Research):
  - Credential-path access by a LOLBin-parented process or a binary in a user-writable path.
  - Login Data plus Local State accessed by the same process.
  - An outbound non-RFC1918 connection within 300 s.
  - `nss3.dll` loaded by a non-Mozilla process (Sysmon EID 7).
  - False positives: password managers, backup tools, AV/EDR, CCleaner and BleachBit, SCCM and Intune.
  
  — [detection-chokepoints](https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/)
- Elastic endpoint emits kernel-driver file and registry "open" or "query" events for sensitive paths, one per process entity per pattern. EQL hunt: a process start followed by 3 or more distinct sensitive files within 1 minute. — [Elastic, 2023 [OLDER]](https://www.elastic.co/security-labs/detect-credential-access)
- Katz-related Sigma rules referenced by Nextron: `file_access_win_susp_process_access_browser_cred_files`, `proc_creation_win_browsers_chromium_headless_exec`, `proc_creation_win_msbuild_susp_parent_process`, `proc_creation_win_uac_bypass_cmstp`, `proc_creation_win_registry_enumeration_for_credentials_cli`. — [Nextron](https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/)

**SACL-based file auditing**
- Apply a SACL (Everyone; ReadData and TakeOwnership; success) to `Local State`, `Default\Cookies` and `Login Data`, and enable "Audit File System." This yields 4663 events with process name. Read SACLs can be noisy, and code injected into Chrome evades a filter that excludes Chrome. — [WithSecure Labs](https://www.withsecure.com/en/resources-hub/w-labs/attack-detection-fundamentals-2021-windows-lab-4/)

**DPAPI attribution**
- Enable the `Microsoft-Windows-Crypto-DPAPI/Debug` channel. Event 16385 carries OperationType `SPCryptUnprotect`, DataDescription such as "Google Chrome" (Edge uses the same tag), and CallerProcessID. Join to 4688 for the image path (nearest earlier event, because PIDs are reused). Alert when the caller is not the browser or `elevation_service.exe`. Security event 4693 lacks the caller. — [Google Security Blog, Apr 30 2024 [OLDER]](https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html)
- MDE alert "Suspicious DPAPI Activity". Hunting query: `DpapiAccessed` events from AutoIt, .NET or PowerShell processes that target Chrome, Edge, Opera or Brave data. — [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)

**Browser launch, injection and debugging**
- See the Sigma and Elastic rules listed in section 4: remote debugging, headless debugging, unusual parent, Sysmon 8/10 masks, elevation service CLSID auditing, and debugger attach.

**ClickFix / FileFix**
- SigmaHQ d487ed4a and 4be03877; Elastic TypedPaths rule; RunMRU EID 13 KQL; PowerShell 4104. See section 2.

**Network**
- SigmaHQ c3dbbc9f (Telegram API from non-browser). See section 5.

**Defender and MDE named detections for stealers**
- Antivirus: Behavior:Win32/LummaStealer, Trojan:Win32/ClickFix, Behavior:Win32/RegRunMRU, Trojan:PowerShell/ClickFixObfus.
- Alerts: "Information stealing malware activity", "Process hollowing detected", "Suspicious DPAPI Activity", "Suspicious mshta process launched".

— [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)

**Canary and honeytoken approaches**
- No authoritative 2025-2026 source on browser-credential canaries was found this session (search results were vendor marketing). See Gaps.

### Inferences
A recommended EDR rule stack, from highest to lowest fidelity:
1. Correlation: non-browser process with credential-store access + DPAPI decrypt (16385) + external connection within 300 s.
2. Process handle with VM_READ/VM_WRITE/CREATE_THREAD into a browser, or a debug attach, from an unsigned or user-path image.
3. Browser launched with debugging, headless or off-screen flags, or `--load-extension`, from a non-explorer parent.
4. COM activation of the browser elevation service, or unsigned code executing from the Chrome Application directory.
5. ClickFix/FileFix/Terminal paste chains (explorer, browser or WindowsTerminal → LOLBin with network fetch).
6. .NET Framework LOLBins (MSBuild, RegAsm, RegSvcs, InstallUtil) with an unusual parent and network activity. This matches Kaspersky's 32% figure.
7. Non-browser access to dead-drop or exfil services (Telegram, Steam, Discord webhooks, blockchain RPC).

Canary design (inference, not sourced):
- Plant decoy browser profiles or decoy wallet extension folders (e.g. a fake `Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn` MetaMask folder) whose only legitimate reader is nothing at all. Any open of these is high-confidence.
- Seed fake saved credentials or cookies for monitored canary domains, so that server-side use reveals exfiltration.

### Gaps
- The full Elastic `detection-rules` and `protections-artifacts` rule bodies for stealer endpoint behavior rules (e.g. "Web Browser Credential Access via Unusual Process") were not fetched. Only rule names are sourced.
- No sourced performance data on the cost of Kernel-File ETW versus a minifilter for file-access monitoring.

---

## 7. Prevention controls that actually block stealers

### Takeaway
The controls that block stealers are execution controls and session binding:
- Execution: App Control/WDAC, Smart App Control, ASR prevalence and obfuscation rules, disabling Run, and blocking mshta.
- Session binding: DBSC (GA on Chrome for Windows in 2026, but only for participating sites with a TPM), plus phishing-resistant MFA and passkeys.

Credential Guard does **not** protect browser or app secrets. ABE is bypassable and does not protect memory or in-browser session riding.

### Cited Findings
**ASR rules** (GUIDs from Microsoft):
- Block executables unless they meet prevalence, age or trusted-list criteria: `01443614-cd74-433a-b99e-2ecdc07bfc25` (needs cloud protection).
- Block potentially obfuscated scripts: `5beb7efe-fd9a-4556-801d-275e5ffc04cc`.
- Block JS/VBS launching downloaded executable content: `d3e037e1-3eb8-44c8-a917-57927947596d`.
- Block credential stealing from LSASS: `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`.
- Block use of copied or impersonated system tools: `c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb`.
- Block executable content from email and webmail: `be9ba2d9-53ea-4cdc-84e5-9b1eeee46550`.
- Advanced ransomware protection: `c1db55ab-c21a-4637-bb3f-a12568109d35`.

— [Microsoft Learn ASR reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)

**Microsoft's recommended stealer mitigations**
- Tamper protection, network and web protection, EDR in block mode, the ASR rules above, MFA with passkeys or FIDO, Conditional Access authentication strength, SmartScreen, LSA protection, and AppLocker for RMM and recon tools. — [Microsoft, May 2025](https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/)
- ClickFix-specific: remove the Run dialog by GPO, use App Control to block native binaries launched from Run, set a Windows Terminal multi-line paste warning, PowerShell script block logging, and AllSigned or RemoteSigned execution policy. — [Microsoft, Aug 2025](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- Block `mshta.exe` with AppLocker or WDAC. Use ASR to stop PowerShell, Python, mshta and rundll32 from launching internet-delivered content from user-writable folders. — [The Hacker News (eSentire), Jul 2026](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)

**Smart App Control**
- Blocks executables unknown to Microsoft's cloud unless validly signed by a trusted developer, with no "allow anyway" option. Since preview KB5074105 (Jan 29, 2026; builds 26100/26200.7705) it can be toggled in Settings without reinstalling Windows. — [Chipp.in](https://chipp.in/software/windows/microsoft-lifts-biggest-smart-app-control-hurdle-in-windows-11-but-should-you-use-it)

**Credential Guard**
- Protects domain credentials in Credential Manager and blocks some protocols. "Generic credentials, such as user names and passwords that you use to sign in websites, aren't protected." — [Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-considerations)

**ABE limitations**
- Admin or elevated malware can bypass it. Enterprises that deny admin rights benefit most, because malware is forced to inject. — [Google, Jul 2024](https://security.googleblog.com/2024/07/improving-security-of-chrome-cookies-on.html)

**DBSC (Device Bound Session Credentials)**
- Generally available in Chrome on Windows and on by default for Workspace and personal Google accounts. Rollout began May 25, 2026. There is no admin control to disable it. Binding events appear in Workspace audit logs. — [Google Workspace Updates, May 28 2026](https://workspaceupdates.googleblog.com/2026/05/prevent-account-takeovers-with-DBSC-now-generally-available-in-the-Chrome-browser-for-Windows.html)
- Constella reports GA on Windows from April 10, 2026 (Chrome 146). This conflicts with the Workspace post's May 25 rollout; the difference is likely browser GA versus Workspace enablement. DBSC needs a TPM (falls back silently without one) and site-side support (Google and Okta so far). It covers Chrome on Windows only. It does not protect passwords, VPN configs, SSH keys or cloud tokens. — [Constella](https://constella.ai/blog/google-just-fixed-session-cookie-theft-in-chrome-here-is-what-it-still-cannot-stop/)
- In-browser CDP enablement lets attackers act through the live, bound session, which sidesteps DBSC. — [SpecterOps, Aug 2026](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)

**Post-infection response**
- Invalidate web sessions and revoke tokens (not just reset passwords), and apply cookie expiry policies. — [SpyCloud](https://spycloud.com/blog/infostealers-bypass-new-chrome-security-feature/); [The Hacker News, Jul 2026](https://thehackernews.com/2026/07/acr-stealer-uses-clickfix-lures-to.html)
- Chrome 136 debugging restriction and Chrome 137 `--load-extension` removal reduce CDP and extension abuse. Edge still accepted `--load-extension` as of Aug 2025. — [Chrome Developers](https://developer.chrome.com/blog/remote-debugging-port); [SpecterOps 2025](https://specterops.io/blog/2025/08/27/dough-no-revisiting-cookie-theft/)

### Inferences
- For an EDR product, the most effective **preventive** hooks are:
  - Block-mode rules on unsigned or low-prevalence executables from %TEMP%, %APPDATA% and Downloads (Kaspersky's 35%).
  - Block untrusted processes from opening browser processes with VM_READ, VM_WRITE or CREATE_THREAD, or from debug-attaching.
  - Block or deny-by-default reads of credential-store files by unsigned processes (minifilter pre-create deny, with an allowlist for password managers and backup tools).
  - Block .NET LOLBin hollowing.
- Passkeys and FIDO2 reduce password-replay value. Stolen session cookies still work unless DBSC or token binding is in place.

### Gaps
- Exact semantics of the Chrome enterprise policies `RemoteDebuggingAllowed` and `ApplicationBoundEncryptionEnabled` were not retrieved (the policy page didn't render).
- Microsoft Entra Token Protection (token binding for M365 sign-in sessions) was not researched here. It is relevant to MSAL-token theft by Vidar and ACR.
- Edge's ABE scope for passwords is unclear: sources conflict.
