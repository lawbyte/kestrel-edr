# Ransomware behaviours on Windows and user-mode (ETW) detection and containment

Research notes for Kestrel's `RW-xx` rule family. Written 2026-10-21.
Every factual claim has a source URL inline. **[UNVERIFIED]** marks things I could not confirm from a primary source, and **[DESIGN]** marks Kestrel-specific reasoning (no source; it is our proposal).
Elastic detection rules are ELv2. They are cited here only to show that a *behaviour* is detected elsewhere. No Elastic rule text or logic was copied. SigmaHQ rules are DRL 1.1, and their ids and authors are given where we derive from them.

---

## 1. Threat landscape 2025-2026: who is encrypting Windows endpoints, and how

### 1.1 Active groups

* **Qilin** was the most active RaaS in 2025, averaging about 75 victims a month in Q3 2025. Akira, INC Ransom and Play followed it. Qilin's growth followed the shutdown of **RansomHub** in April 2025 and an influx of its affiliates. Source: Check Point, https://research.checkpoint.com/2025/the-state-of-ransomware-q3-2025/ . SpiderLabs ranked Qilin 1 and Akira 2 in September 2025: https://www.levelblue.com/blogs/levelblue-blog/spiderlabs-ransomware-tracker-update-september-2025-qilin-akira-top-ransomware-attackers
* **Akira**. CISA/FBI advisory AA24-109A was revised on **13 Nov 2025**: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a
  * It uses ChaCha20 with RSA and does **full or partial** encryption depending on file type and size. Extensions are `.akira`, `.powerranges` (Megazord, Rust), and `.akiranew` / `.aki` (Akira_v2). Ransom notes are `fn.txt` and `akira_readme.txt`, written to `C:\` and to each user home.
  * Shadow copies are deleted with `powershell.exe -Command "Get-WmiObject Win32_Shadowcopy | Remove-WmiObject"`, and `vssadmin.exe` is also listed.
  * Encryptor options: `-p` (paths), **`-s` (network drive path)**, `-n` (encryption percent) and `--fork`. Akira_v2 adds thread control and `vmonly`/`stopvm`.
  * Defence evasion uses BYOVD (POORTRY signed vulnerable driver, STONESTOP loader) and the Zemana AntiMalware driver through PowerTool to kill AV. Operators also uninstall EDR.
  * Other activity: LSASS dumps via `comsvcs.dll MiniDump`, and `takeown`/`icacls` for ownership changes.
* **Qilin (Agenda)** was rewritten from Go to Rust: https://www.attackiq.com/2025/11/19/revisiting-qilin-ransomware/
  * It uses BYOVD to disable EDR, **reboots into Safe Mode**, and deletes shadow copies.
  * The AttackIQ emulation shows the following steps: https://www.attackiq.com/2025/10/02/emulating-qilin-ransomware/
    * It checks for Safe Mode in the registry.
    * It runs `vssadmin.exe` for shadow-copy deletion.
    * It clears event logs with PowerShell `[...EventLogSession]::GlobalSession.ClearLog`, falling back to `wevtutil.exe`.
    * It adds persistence under `HKLM\...\CurrentVersion\Run`.
    * It sets **`EnableLinkedConnections`** so that mapped drives are visible to the elevated encryptor.
    * Files are encrypted with AES-256-CTR and RSA-2048.
  * ManageEngine additionally reports event-log clearing (Security 1102) and a Linux ELF encryptor run inside **WSL** on Windows hosts: https://www.manageengine.com/malware-protection/adversaries/qilin-ransomware.html
* **Play**. Advisory AA23-352A was updated 4 Jun 2025: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a
  * It uses **intermittent encryption**, encrypting every other 0x100000-byte chunk. The extension is `.PLAY` and the note is `ReadMe.txt` in `C:\Users\Public\Music\`.
  * It uses GMER, IOBit and PowerTool to disable AV, and removes logs.
  * **The binary is recompiled for every victim**, so hashes and IOCs are useless.
* **Medusa**. Advisory AA25-071A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a
  * `gaze.exe` "terminates all services" related to backups, security, databases, communication, file sharing and websites. It also deletes shadow copies; the appendix gives `vssadmin.exe Delete Shadows /all /quiet`.
  * Files get the `.medusa` extension and the note `!!!READ_ME_MEDUSA!!!.txt`.
  * Remote deployment uses PsExec, PDQ Deploy and BigFix. Operators use vulnerable or signed drivers to kill EDR, and `taskkill /f /im` via PsExec.
* **LockBit 5.0** (Sep 2025): https://www.trendmicro.com/en_us/research/25/i/lockbit-5-targets-windows-linux-esxi.html
  * It is heavily obfuscated and loaded by DLL reflection, with anti-analysis checks.
  * It appends a **random 16-character extension** per file, so extension IOCs are useless.
  * It **clears event logs after encryption**. It has Windows, Linux and ESXi variants.
* **EDR killers are shared across groups.** EDRKillShifter (BYOVD) was built by RansomHub and reused by Medusa, BianLian and Play affiliates. ESET says affiliates disable security tools just before running the encryptor because encryptors rarely change: https://thehackernews.com/2025/03/hackers-repurpose-ransomhubs.html
* **Threat-model implication for Kestrel [DESIGN].** A user-mode agent will often be **killed or blinded by BYOVD minutes before encryption**. The rules that matter most are therefore:
  * the pre-encryption preparation signals (driver load, AV/service kill, VSS deletion, safe-mode staging), which give us a chance to act *before* the EDR killer runs;
  * the server-side "agent went silent" tamper signal (TP-SRV-*), which survives the agent's death.

### 1.2 Common pre-encryption and encryption TTPs (Windows)

| Behaviour | Typical commands / artefacts | Source |
|---|---|---|
| Delete shadow copies (T1490) | `vssadmin delete shadows /all /quiet`, `vssadmin resize shadowstorage /maxsize=…`, `wmic shadowcopy delete`, `diskshadow` (script mode `/s`), PowerShell/CIM `Win32_ShadowCopy` + `.Delete()`/`Remove-WmiObject`/`Remove-CimInstance` | Sigma c947b146 (Roth et al.), c1337eb8 (Rauch, frack113) – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml , https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml ; Akira AA24-109A |
| Delete backup catalog | `wbadmin delete catalog -quiet`, `wbadmin delete systemstatebackup` / `delete backup -keepVersions:0` | Sigma c947b146, 639c9081 – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml |
| Disable boot recovery | `bcdedit /set {default} recoveryenabled no`, `bcdedit /set {default} bootstatuspolicy ignoreallfailures`; `reagentc /disable` | Sigma 1444443e (Anhaus), db1c21e4 (Koifman, 2025) – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml , https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml |
| Safe-mode reboot (evade EDR, which does not run in Safe Mode) | `bcdedit /set {default} safeboot minimal\|network`; register own service under `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\{Minimal,Network}\<svc>` = `Service`; delete SafeBoot keys (`reg delete …\SafeBoot`) to break AV in Safe Mode | Qilin (AttackIQ, above); Sigma c9fbe8e9, 1547e27c, fc0e89b5 – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml |
| Event log clearing | `wevtutil cl <log>`, `wevtutil sl` (shrink), `Clear-EventLog`, `[EventLogSession]::GlobalSession.ClearLog`, WMI `ClearEventLog` | Sigma cc36992a – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml ; Qilin; LockBit 5 (post-encryption) |
| Service / process kill spree (T1489) | `net stop`, `sc stop`, `sc config … start= disabled`, `taskkill /f /im` on SQL, Veeam, backup, AV, Exchange; or `TerminateProcess` in-process | Medusa AA25-071A; Qilin kills SQL/Veeam/Sophos (Picus) https://www.picussecurity.com/resource/blog/top-10-ransomware-groups-of-2025 ; Sigma 88872991 (low level, very FP-prone) |
| BYOVD / EDR killer | load of a signed vulnerable driver (POORTRY, Zemana, IOBit, GMER, EDRKillShifter drivers) | AA24-109A, AA23-352A, ESET (above) |
| Make network drives reachable | `EnableLinkedConnections`=1 (Qilin); `fsutil behavior set SymlinkEvaluation R2L:1 R2R:1` | AttackIQ; Sigma c0b2768a – https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_fsutil_symlinkevaluation.yml |
| Ownership / ACL prep | `takeown /f … /r`, `icacls … /grant Everyone:F /T /C /Q` [UNVERIFIED for the exact icacls flags per family] | AA24-109A (takeown/icacls); Sigma 554601fb |
| Wipe free space | `cipher /w:` (destroys deleted plaintext after encrypt-to-new-file) | Sigma 4b046706 |
| Ransom note drop | Same filename written into many directories: `fn.txt`/`akira_readme.txt` (Akira), `!!!READ_ME_MEDUSA!!!.txt`, `ReadMe.txt` (Play), `README.txt`, `*-README.txt`, `RESTORE-MY-FILES.TXT` (LockBit older) [UNVERIFIED for LockBit 5 note name] | advisories above |
| Extension change | static (`.akira`, `.PLAY`, `.medusa`) or **random per victim/per file** (LockBit 5: 16 chars) | above |
| Intermittent / partial encryption | Play (every other 1 MiB), Akira (`-n` percent), BlackCat, Agenda, Black Basta, LockFile (every 16 bytes) | SentinelOne https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/ ; Sophos LockFile https://www.sophos.com/en-us/blog/lockfile-ransomwares-box-of-tricks-intermittent-encryption-and-evasion |
| Memory-mapped I/O (writes appear to come from the OS, seconds to minutes later) | LockFile, Maze, WastedLocker | Sophos LockFile (above) |
| EFS abuse (encryption done by NTFS/EFS, not by malware writes) | PoC by SafeBreach 2019/2020; evaded ESET, Kaspersky and Defender CFA | https://www.bleepingcomputer.com/news/security/windows-efs-feature-may-help-ransomware-attackers |
| RIPlace rename evasion (DosDevice symlink defeats the minifilter's destination-name lookup) | Thanos ransomware adopted it | https://darkreading.com/cyber-risk/dangerous-riplace-exploit-able-to-bypass-av-edr-protections , https://www.techtarget.com/searchsecurity/news/252484469/New-Thanos-ransomware-weaponizes-RIPlace-evasion-technique |
| Remote encryption over SMB | Encrypt shares from an unmanaged or compromised host. Akira `-s`. | see §1.3 |

**ATT&CK note.** ATT&CK **v19** (28 Apr 2026) split Defense Evasion into **Stealth (TA0005)** and **Defense Impairment (TA0112)**. It merged T1562 Impair Defenses into **T1685 Disable or Modify Tools**: https://attack.mitre.org/resources/updates/updates-april-2026/ , https://d3security.com/blog/mitre-attack-v19/ . SigmaHQ now tags event-log clearing as `attack.t1685.005` / `t1685.001` (rule cc36992a, modified 2026-06-01). The v19 placement of the former T1070.001 (Clear Windows Event Logs) is **[UNVERIFIED]** against attack.mitre.org. Impact techniques are unchanged: T1486 Data Encrypted for Impact, T1490 Inhibit System Recovery, T1489 Service Stop, T1485 Data Destruction.

### 1.3 Remote (SMB) encryption: what the local agent sees

* Sophos (Dec 2023) saw a **62% year-on-year rise** in intentional remote encryption and named Akira, ALPHV, LockBit, Royal and Black Basta: https://www.sophos.com/en-us/press/press-releases/2023/12/prolific-ransomware-groups-intentionally-switch-remote-encryption
* Microsoft Digital Defense Report 2024: in **>90%** of attacks that reached the ransom stage, the attacker used **unmanaged devices** for initial access or remote encryption. Microsoft also says the share of attacks reaching encryption fell threefold over two years: https://www.techtarget.com/searchsecurity/news/366613799/Microsoft-sees-drop-in-ransomware-reaching-encryption-phase
* **On the file server** (the victim of remote encryption), file I/O is performed by the kernel SMB server. It is attributed to the **System process (PID 4)**, not to a malicious process.
  * Public rule descriptions key on "renames by PID 4" and "ransom note created by PID 4" over SMB, and correlate with the SMB source IP and user. https://www.elastic.co/guide/en/security/current/potential-ransomware-note-file-dropped-via-smb.html (description only, ELv2)
  * Sophos WantToCry analysis: https://www.sophos.com/en-us/blog/wanttocry-ransomware-remotely-encrypts-files
  * Consequence: a process-based kill is impossible. Possible responses are to (a) identify the SMB client IP or session and **WFP-block inbound 445 from that IP** or disconnect the session, and (b) alert.
  * The `srv2.sys` attribution detail is **[UNVERIFIED]**.
* **On the attacking host**, if Kestrel is installed there, the encryptor process sees normal process-attributed opens, writes and renames on `\Device\Mup\...` / UNC paths. Network-path file events are visible to Kernel-File, which is a redirector-agnostic I/O manager provider. **[UNVERIFIED: confirm with a lab test that Kernel-File Create/RenamePath fire for `\Device\Mup` paths.]**
* **Lazy-writer and memory-mapped writes** are also attributed to System or the OS, with a delay (Sophos LockFile, above). Do **not** rely on Write(16) events for attribution. Key on **Create with write/overwrite disposition, CreateNewFile, RenamePath and DeletePath**: these are issued synchronously by the malicious thread.

---

## 2. User-mode file telemetry: Microsoft-Windows-Kernel-File

Provider `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`. Kestrel already uses this GUID in `crates/kestrel-win/src/consts.rs`.
Source for every id, keyword and field below: the Kernel-File manifest dump (Win10 build 18990), https://github.com/repnz/etw-providers-docs/blob/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-File.xml , which is the reference the Velociraptor `Windows.ETW.KernelFile` artifact uses: https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelfile

### 2.1 Keywords

| Keyword | Mask |
|---|---|
| KERNEL_FILE_KEYWORD_FILENAME | 0x10 |
| KERNEL_FILE_KEYWORD_FILEIO | 0x20 |
| KERNEL_FILE_KEYWORD_OP_END | 0x40 |
| KERNEL_FILE_KEYWORD_CREATE | 0x80 |
| KERNEL_FILE_KEYWORD_READ | 0x100 |
| KERNEL_FILE_KEYWORD_WRITE | 0x200 |
| KERNEL_FILE_KEYWORD_DELETE_PATH | 0x400 |
| KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH | 0x800 |
| KERNEL_FILE_KEYWORD_CREATE_NEW_FILE | 0x1000 |

Velociraptor's default mask is `0x1490` (FILENAME | CREATE | DELETE_PATH | CREATE_NEW_FILE).
Sigma's `file_rename` category requires "at least the KERNEL_FILE_KEYWORD_RENAME_SETLINK_PATH keyword": https://detection.fyi/sigmahq/sigma/windows/file/file_rename/file_rename_win_ransomware/

### 2.2 Events (id, symbol, keywords, template fields; V1 shown)

| Id | Event | Keywords | Fields (V1) |
|---|---|---|---|
| 10 | NameCreate | FILENAME | FileKey, FileName |
| 11 | NameDelete | FILENAME | FileKey, FileName |
| 12 | Create | FILEIO, CREATE | Irp, FileObject, IssuingThreadId, CreateOptions, CreateAttributes, ShareAccess, FileName |
| 13 | Cleanup | FILEIO | Irp, FileObject, FileKey, IssuingThreadId |
| 14 | Close | FILEIO | Irp, FileObject, FileKey, IssuingThreadId |
| 15 | Read | FILEIO, READ | ByteOffset, Irp, FileObject, FileKey, IssuingThreadId, IOSize, IOFlags, ExtraFlags |
| 16 | Write | FILEIO, **WRITE** | same as Read |
| 17 | SetInformation | FILEIO | Irp, FileObject, FileKey, ExtraInformation, IssuingThreadId, InfoClass |
| 18 | SetDelete | FILEIO | as 17 |
| 19 | Rename | FILEIO | as 17 (**no file name**) |
| 20 | DirEnum | FILEIO | DirEnumArgs |
| 21 | Flush | FILEIO | as 13 |
| 22 | QueryInformation | FILEIO | as 17 |
| 23 | FSCTL | FILEIO | as 17 |
| 24 | OperationEnd | FILEIO, OP_END | Irp, ExtraInformation, Status |
| 25 | DirNotify | FILEIO | DirEnumArgs |
| 26 | DeletePath | **DELETE_PATH** | Irp, FileObject, FileKey, ExtraInformation, IssuingThreadId, InfoClass, **FilePath** |
| 27 | RenamePath | **RENAME_SETLINK_PATH** | as 26 (**FilePath**) |
| 28 | SetLinkPath | RENAME_SETLINK_PATH | as 26 |
| 29 | Rename29 | FILEIO | as 17 |
| 30 | CreateNewFile | **CREATE_NEW_FILE** | as 12 (FileName) |

Notes:

* ETW keyword matching is "any bit". Enabling `0x20 FILEIO` turns on **all** IRP-level events (13-25, 29), which is enormous volume. Write(16) can be obtained with `0x200` alone, and rename/delete *with a path* with `0x800`/`0x400` alone, without FILEIO. **[DESIGN]: never enable 0x20.**
* `InfoClass` values follow `FILE_INFORMATION_CLASS`: FileRenameInformation = 10, FileLinkInformation = 11, FileDispositionInformation = 13, FileEndOfFileInformation = 20, FileDispositionInformationEx = 64, FileRenameInformationEx = 65. Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_file_information_class
* **RenamePath(27) `FilePath` semantics: [UNVERIFIED]** whether it is the *source* or the *target* path. Neither the manifest nor public docs say. **Action:** verify in the lab with `kestrel-agent sensors-test` by renaming a temp file `a.txt` to `a.txt.x` and logging the event.
  * If FilePath is the source, correlate with the FileObject's previous Create name. The target name is then not directly available, and the new extension must come from a subsequent Create/NameCreate on the same FileKey, or from a cheap `GetFinalPathNameByHandle`-style lookup. User mode cannot do the latter without a handle.
  * If FilePath is the target, correlate with the FileObject→name map from Create(12) to get the source.
* Write/Read/SetInformation/Cleanup/Close carry only `FileObject`/`FileKey`. File names come from Create(12)/CreateNewFile(30) (`FileObject`→`FileName`) or NameCreate(10) (`FileKey`→`FileName`). The DEFEAT paper (arXiv 2609.21426, 2026, built on krabsetw) uses exactly this FileKey/FileObject stitching. It notes that Read/Write/Rename/Delete carry no file name: https://arxiv.org/html/2609.21426v1
* `CreateOptions` high byte = create disposition (FILE_SUPERSEDE 0, OPEN 1, CREATE 2, OPEN_IF 3, OVERWRITE 4, OVERWRITE_IF 5). Kestrel already parses this (`kestrel-win/src/etwparse.rs`). Overwrite/supersede on an existing user document is a strong in-place encryption signal that needs no Write events. **[DESIGN]**
* The Create(12) event has **no DesiredAccess field**, so "opened for write" cannot be known from Create alone. The proxies are the disposition (overwrite/supersede), a later Write(16) on the same FileObject, or a RenamePath/DeletePath. **[DESIGN, based on the manifest field list]**

### 2.3 Filtering at source, volume and CPU

* ETW scope filters (EnableTraceEx2 + `EVENT_FILTER_DESCRIPTOR`), from https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_filter_descriptor :
  * `EVENT_FILTER_TYPE_EVENT_ID` takes up to 64 ids and is evaluated in each event-write call.
  * `EVENT_FILTER_TYPE_PID` takes at most 8 PIDs and **only applies to user-mode providers**, so it is useless for Kernel-File.
  * `EVENT_FILTER_TYPE_PAYLOAD` is limited to 4096 bytes.
  * There is **no path-prefix filter** for a kernel provider. Path filtering must happen in Kestrel's callback.
* Measured volume: DEFEAT captured all file I/O (krabsetw, seven event types including Read/Write) at about **1.1-1.2 GB per hour** of desktop activity (97.8 M events in total). Its per-file stitching store cost a median 14.7 ms per operation, **+3.2% CPU** and 85 MB RAM: https://arxiv.org/html/2609.21426v1 . That is the upper bound with Read+Write.
* **[DESIGN] Recommended enablement** for a ransomware sensor:
  * Mask `0x80 | 0x400 | 0x800 | 0x1000` (CREATE, DELETE_PATH, RENAME_SETLINK_PATH, CREATE_NEW_FILE). Optionally add `0x10` (FILENAME) for the FileKey→name map, and `0x200` (WRITE) only if needed.
  * Add an event-id filter of {12, 26, 27, 30} (+10, 11, 16).
  * Never add READ or FILEIO.
* **[DESIGN] Aggregate in the callback, upload only summaries:**
  * Keep a per-PID ring of the last N seconds. Do **not** emit an event per file.
  * Per PID per 10 s window, count:
    * distinct user-data files with overwrite/supersede disposition;
    * distinct RenamePath on user-data paths;
    * distinct **(old ext → new ext)** pairs, the top new extension and its share;
    * distinct parent directories;
    * DeletePath after CreateNewFile with the same stem (the "write copy then delete original" pattern);
    * same-filename CreateNewFile across directories (note drop);
    * canary hits.
  * Emit one `file_activity` summary event when any counter crosses a low pre-threshold, so cloud volume stays tiny.
  * "User-data path" means anything not under `\Windows\`, `\Program Files*\`, `\ProgramData\Microsoft\`, `\$Recycle.Bin`, `AppData\Local\Temp`, browser caches, `.git\objects`, `node_modules`, `target\`, and so on. Network paths (`\Device\Mup\`) count as user data.
  * Use bounded maps (e.g. 64k FileObject entries, LRU) to avoid memory DoS by a process that opens millions of files.
* **Latency.** Kestrel's IO session flushes every 5 s (`kestrel-win/src/win/etw.rs`). Under ransomware load, the 64 KB buffers fill and are delivered well before the flush timer, so latency is dominated by buffer fill. Fill-time reasoning is **[DESIGN]**; buffer size and flush settings follow Microsoft's EVENT_TRACE_PROPERTIES semantics. Even so, put the ransomware Kernel-File events in a session with a **1 s flush** (or the Core session), so that slow, low-rate encryptors are also caught quickly.

---

## 3. Detection heuristics

### 3.1 What others do (behaviour only, no rule text copied)

* **SigmaHQ `file_rename_win_ransomware`** ("Suspicious Appended Extension", e3f673b3, frack113): https://detection.fyi/sigmahq/sigma/windows/file/file_rename/file_rename_win_ransomware/
  * It matches a rename whose source ends in a document/image/archive extension and whose target contains that extension followed by a dot (`.jpg.crypted`, `.docx.locky`). It excludes `.bak/.backup/.old/.orig/.tmp/.temp` and lists backup software as the FP.
  * It is a single-event rule with no rate component.
* **Elastic** (ELv2; ideas only):
  * a Linux rule counting extension renames by one process: 100, later 50, renames within 1 s in common paths: https://www.elastic.co/guide/en/security/8.8/suspicious-file-changes-activity-detected.html
  * Windows rules for PID-4 renames and ransom-note creation over SMB, aggregated over a 60 s window (see §1.3);
  * **canary files** in Elastic Defend since 7.14, possibly hidden or marked as system files. Modifying one triggers an alert, and in prevent mode the modifying process is terminated. Elastic says it cannot guarantee that no file is encrypted before detection, even with a minifilter: https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys , https://discuss.elastic.co/t/ransomware-protection/360948
* **Sophos CryptoGuard**: content-based detection of encryption regardless of source, claimed to catch remote encryption and files only 3% encrypted (press release above). That needs a minifilter, so it is **not achievable** from ETW.
* **Fibratus** (rabbitstack, Apache-2.0) currently ships **no** ransomware, VSS or mass-rename rules in `rules/`; it has only `defense_evasion_clear_eventlog.yml` in this space. Checked via the GitHub API on 2026-10-21: https://github.com/rabbitstack/fibratus/tree/master/rules
* **Academic work:**
  * DEFEAT (2026) stitches per-file Create→Read→Write→Rename/Delete "gadgets" from ETW. Its filter "≥1 Write and ≥1 of Read/Delete/Rename" kept 99.97% of ransomware file sequences and dropped only 0.04% of benign ones. FPR was 0.53% at the file level over 46 benign apps (Office, 7-Zip/WinRAR/PeaZip, KeePass/AxCrypt, Dropbox/Google Drive, VS/PyCharm…): https://arxiv.org/html/2609.21426v1 . The ML is out of scope for us, but the **per-file sequence feature is cheap and useful**.
  * Decoy-based systems: R-Sentry lets up to about 10 files be lost before alerting and R-Trap averages 18. Both suffer FPs when benign apps touch decoys, and anti-decoy ransomware exists: https://arxiv.org/pdf/2508.00293 (ranDecepter, 2025) and https://arxiv.org/pdf/2409.11428

### 3.2 Entropy from user mode

* ETW Write events carry `IOSize`/`ByteOffset`, but **no data**. Entropy therefore needs the agent to read the file after Close/Cleanup. **[DESIGN]**
  * Read only the first 4-64 KiB of a *sample* of files (e.g. one in 20, at most 5 per second per suspect PID).
  * Compare the magic bytes against the extension: OOXML/ZIP `PK\x03\x04`, PDF `%PDF`, JPEG `FF D8 FF`, PNG `89 50 4E 47`. Also compute Shannon entropy and a chi-square test.
  * A magic mismatch on a known-format file is much cheaper and more robust than raw entropy, because compressed formats (docx, jpg, zip) are already near 8 bits per byte.
* Intermittent encryption breaks naive entropy. LockFile encrypts every 16 bytes specifically to look statistically similar to plaintext (Sophos, above), and Play encrypts alternate 1 MiB chunks (AA23-352A). The *header* is still overwritten in most families. **[UNVERIFIED: per-family whether byte 0 is always encrypted]** Treat the header check as corroboration only, never as a primary trigger.
* Reading files under a user profile as SYSTEM is a privacy-sensitive action. Hash or score the header locally and never upload content. **[DESIGN; consistent with Kestrel privacy rules]**

### 3.3 Canary / honey files

* Placement: users' Desktop, Documents and Pictures **roots**, `C:\Users\Public\Documents`, and share roots on file servers. Ransomware skips system and program directories by design. Avoid `AppData`, which many families exclude. **[DESIGN; consistent with Elastic's "targeted locations"]**
* **Enumeration order.**
  * Microsoft documents that FindFirstFile/FindNextFile order is not guaranteed, but **NTFS usually returns names in alphabetical order**: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findnextfilea , and Raymond Chen: https://devblogs.microsoft.com/oldnewthing/20140304-00/?p=1603
  * NTFS sorts the B-tree by upcased name, so names beginning with `!`, `$`, `0`-`9` or `_` sort before letters. **[DESIGN]** The exact NTFS collation (upcase-table code-point order versus Explorer's natural sort) is **[UNVERIFIED]** beyond Chen's "almost sorted" remark.
  * Practitioner guidance says to "name canaries to sort early": https://moltchat-agent-commons.onrender.com/wiki/deploying-decoy-files-for-ransomware-detection_skill_(Anthropic-Cybersecurity-Skills) . That is a community source, not peer-reviewed.
  * Many encryptors are multi-threaded with per-drive or per-directory work queues (Akira_v2 thread control, AA24-109A), so first-in-directory does not mean first globally. **Plant canaries in several directories, and also at depth 1-2.**
* Recommended canary set per profile **[DESIGN]**:
  * `!_<plausible>.docx` and `0_<plausible>.xlsx` in Documents root; one `!`-prefixed `.pdf` on Desktop; one `.jpg` in Pictures.
  * Each canary must be a **valid** file of its type (small, realistic magic bytes and content) so that format-aware encryptors do not skip it.
  * Use randomised but plausible names per host (Kestrel already derives stable per-host names via FNV in `kestrel-detect/src/canary.rs`).
  * Do not set the hidden attribute by default: some families skip hidden files **[UNVERIFIED]**, while Elastic does hide its canaries. Making this a policy option is reasonable.
* **Tripwire semantics.**
  * These count: any Create with overwrite/supersede disposition, any RenamePath or DeletePath, or any Write(16) on a canary by a process that is not on the allow list.
  * The allow list is the Kestrel agent itself and the user's explicit actions via `explorer.exe`, which should *alert* rather than kill.
  * Reads do not count: Windows Search indexer, Defender and backup agents read everything.
* **OneDrive caveat.** OneDrive Known Folder Move syncs Desktop and Documents, so canaries will be uploaded, and OneDrive may rename them on conflict. Allow `OneDrive.exe` reads, treat a OneDrive rename as benign **only** if the target name pattern is OneDrive's conflict suffix, and offer a policy switch to exclude KFM folders. **[DESIGN]**

### 3.4 Encryption speed: how much time containment has

* Splunk SURGe (2022) ran 10 families × 10 hardware configurations on about 100k files (about 54 GB):
  * the **median time to encrypt was about 42 min 52 s**, with a range of 4 min to 3.5 h;
  * the fastest, **LockBit, did about 25,000 files per minute** (about 420 files/s), with a median of about 5 min 50 s;
  * some samples were single-threaded, and extra RAM did not matter.
  * Sources: https://www.splunk.com/content/dam/splunk2/en_us/gated/white-paper/an-empirically-comparative-analysis-of-ransomware-binaries.pdf , https://www.techrepublic.com/article/lockbit-beats-revil-and-ryuk-in-splunks-ransomware-encryption-speed-test/ , https://securityweek.com/analysis-shows-how-fast-various-ransomware-strains-encrypt-100000-files
* So the **median family runs at about 38 files/s** and the fastest at about 420 files/s. With intermittent encryption (Play, Akira `-n`, BlackCat), speed is bounded by enumeration rather than by crypto. BlackCat saved about 2 min on a 50 GB file (SentinelOne, above).
* No newer (2024-2026) public benchmark of Rust encryptors was found. **[UNVERIFIED gap]**
* Huntress 2025 reportedly puts intrusion-to-encryption at about 17 h on average. That is via a secondary aggregator: **[UNVERIFIED]**.
* **[DESIGN] Budget.** At 420 files/s, every 100 ms of latency costs about 42 files. With a 1 s ETW flush, 10 s windows and a 30-file threshold, expect roughly **40-500 files lost** to a fast encryptor before suspend, and fewer than 50 for a median one. Canaries placed early reduce this further. Be honest in the UI: user mode reduces the damage, it does not prevent it (matches CLAUDE.md).

### 3.5 Containment best practice

* **Suspend first, then kill the tree. [DESIGN]**
  * `NtSuspendProcess` on the offender freezes all its threads in one call, so pending writes stop. Then kill the process tree.
  * Kill the **parent** too if it is an unsigned or user-writable launcher (script host, `rundll32` with a temp DLL).
  * Re-check the process start time before acting (Kestrel convention).
* Multi-process encryptors (`--fork`, child workers, PsExec fan-out per Medusa AA25-071A) need **tree** suspension and a *lineage watch*. Any new child of a suspended or killed lineage, or any process launched from the same image hash within N minutes, is auto-suspended.
* After an RW-06/07 kill, **isolate the host** (WFP) if any network-path writes were seen, to stop share encryption from this host. On a **file server under remote encryption** (PID 4), WFP-block inbound TCP 445 from the offending client IP(s), never the Kestrel server. Tie the IP to the SMB session through Security 5140/5145 (needs "Audit File Share" policy) or the Microsoft-Windows-SMBServer ETW provider **[UNVERIFIED event ids; research TODO]**.
* Quarantine the encryptor binary (hash + MOTW) and keep a memory dump if possible. Elastic captures a dump on canary trip to recover keys (Elastic Security Labs, above). **[DESIGN: optional, privacy and size review needed]**
* Shadow copies are usually already gone by encryption time, so the prep-phase rules RW-01/02/03 are the only chance to preserve recovery.
* **Hardening (OS-native).**
  * Enable the Microsoft vulnerable driver blocklist / HVCI against BYOVD: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules
  * Use the LOLDrivers hash list for detection: https://www.loldrivers.io/
  * Register the Kestrel service under `SafeBoot\Network`, as Sophos `SAVService` does. Sigma 1547e27c whitelists exactly that pattern, which proves it is a real vendor practice. This lets Kestrel survive a Safe-Mode reboot. Note that it also means our rule RW-03 must allowlist our own key.
  * Controlled Folder Access is an option, but it was bypassed by EFS abuse (SafeBreach, above).

### 3.6 False positives (all [DESIGN] unless cited)

| Source | Why it looks like ransomware | Mitigation |
|---|---|---|
| Office save | write temp file, delete original, rename temp to original name (https://support.microsoft.com/kb/211632 , old but still the pattern) | final name keeps the original extension; count only renames whose **new extension differs** from the old and is not tmp/bak |
| OneDrive / Dropbox / Google Drive sync | mass create, rename and delete across many dirs on first sync or restore | signed-publisher allow list (Microsoft OneDrive, Dropbox, Google) + extension-preserving check; never auto-kill a signed sync client, alert only |
| Backup agents (Veeam, Acronis, Windows Backup, robocopy) | read everything, write archives; some rename `.bak` | reads are not counted; writes go to one target dir (low directory spread) |
| 7-Zip / WinRAR / tar extraction | thousands of CreateNewFile in many dirs | new files, not overwrite or rename of existing user docs; no ext-change pattern |
| `git checkout`/`clone`, compilers, `npm`/`cargo` | huge create/delete/rename bursts | path excludes (`.git`, `node_modules`, `target`, `obj`, `bin`) + mostly source/binary extensions + no ext-change to a single unknown ext |
| Installers / Windows Update / MSI | mass writes under Program Files/Windows | outside user-data scope |
| Photo apps, Lightroom, media converters | batch convert `.jpg`→`.heic`/`.webp` | target extension is a **known** format; magic bytes valid (§3.2) |
| Encryption tools (AxCrypt `.axx`, VeraCrypt, 7-Zip AES, BitLocker) | legit bulk encryption | DEFEAT benign set included AxCrypt/AESCrypt; allow list by signer; Audit mode |
| Admin VSS maintenance | `vssadmin delete shadows` by an admin | rare on endpoints; alert, and suspend only when the parent is not an interactive admin shell / RMM tool on the allow list |

---

## 4. Proposed rules RW-01 … RW-12

Conventions: "Protect" is the action when policy is Protect, and the default mode is given. "Lineage" means the offending process plus its ancestors up to (excluding) the first protected or system process.
`protect_day_one` is set only where FP risk is very low.

### RW-01 Shadow copy / backup catalog deletion
* **Logic:** `process_start` where one of the following holds:
  * the image or OriginalFileName is vssadmin, wmic, diskshadow or powershell/pwsh, and the cmdline contains `shadow` and `delete`; or `vssadmin resize shadowstorage` with `/maxsize=` or `unbounded`;
  * wbadmin with `delete` + `catalog` (+`quiet`), `delete systemstatebackup`, or `delete backup … -keepVersions:0`;
  * `script_block` contains `Win32_ShadowCopy` together with a getter (Get-WmiObject/gwmi/Get-CimInstance/gcim) and a deleter (.Delete()/Remove-WmiObject/rwmi/Remove-CimInstance/rcim);
  * `diskshadow /s <script>` from a user-writable path.
* Derived from Sigma c947b146, 639c9081 and c1337eb8.
* **Telemetry:** process_start (cmdline), script_block. Already available.
* **Protect:** kill the tool process (best effort) and **suspend the lineage** when the parent is not an allow-listed admin/RMM/backup tool. Alert critical. `protect_day_one: true`.
* **FP:** admin maintenance; backup products using vssadmin (rare; most use the VSS API); LANDesk/Ivanti PS module (per Sigma).
* **ATT&CK:** T1490.

### RW-02 Boot recovery disabled
* **Logic:** bcdedit `set` with (`recoveryenabled` + `no`) or (`bootstatuspolicy` + `ignoreallfailures`); `reagentc /disable`; bcdedit `delete`/`deletevalue` on `{default}` recovery entries (Sigma 1444443e, db1c21e4, c9fbe8e9).
* **Telemetry:** process_start.
* **Protect:** suspend the lineage, alert critical, and offer a remediation command (`bcdedit /set {default} recoveryenabled yes`) in the alert. `protect_day_one: true` for the bcdedit variants; reagentc stays Audit (imaging and OEM tools use it).
* **ATT&CK:** T1490.

### RW-03 Safe-mode boot staging
* **Logic:** any of the following:
  * bcdedit `set … safeboot` (minimal|network) or `safebootalternateshell`;
  * `registry_set` under `\Control\SafeBoot\{Minimal,Network}\<name>\(Default)` = `Service` by a non-installer (not msiexec, and not the Kestrel agent itself);
  * `reg delete …\Control\SafeBoot` (Sigma fc0e89b5);
  * Winlogon `AutoAdminLogon`/`DefaultPassword` set in the same lineage within 10 min **[UNVERIFIED that current families set autologon; documented historically]**.
* **Telemetry:** process_start, registry_set (the Kernel-Registry SetValueKey key-name filter must include `\Control\SafeBoot\` and `\Winlogon\`).
* **Protect:** suspend the lineage, **revert** (`bcdedit /deletevalue {default} safeboot`), and alert critical. `protect_day_one: true` for bcdedit safeboot from a non-admin-tool parent; registry variants Audit.
* **FP:** IT using Safe Mode for repair (rare, interactive); AV/EDR installers registering SafeBoot services (Sophos, Malwarebytes, Hexnode per Sigma 1547e27c filters).
* **ATT&CK:** T1490, T1562.009 (Safe Mode Boot) / v19 T1685 **[UNVERIFIED v19 id]**.

### RW-04 Event log cleared or shrunk
* **Logic:** Sigma cc36992a semantics. `wevtutil` with `cl`/`clear-log`/`sl`/`set-log`/`/lfn:`; PowerShell `Clear-EventLog`, `Remove-EventLog`, `Limit-EventLog`, `Clear-WinEvent`, or `EventLogSession` + `ClearLog`; WMI `ClearEventLog`. Exclude msiexec-parent `sl`.
* **Optional:** subscribe to Security 1102 and System 104 (log cleared) through the event-log channel reader Kestrel already uses for Sysmon.
* **Telemetry:** process_start, script_block (+ event-log channel).
* **Protect:** Audit by default. **Escalate to suspend** when the same lineage also fired RW-01/02/03/05 within 30 min. `protect_day_one: false`.
* **ATT&CK:** T1070.001 (pre-v19) / T1685.00x per Sigma 2026 tagging **[UNVERIFIED]**.

### RW-05 Service / process kill spree
* **Logic:** within 120 s in one lineage, either:
  * ≥ 5 `process_start` of `net/net1 stop`, `sc stop`, `sc config … start= disabled`, PowerShell `Stop-Service`/`Set-Service -StartupType Disabled`, or `taskkill /f /im` targeting names in a curated list (SQL/MSSQL$, Veeam*, backup*, vss, memtas, mepocs, sophos*, MsMpEng, Exchange*, oracle, sap*, …); or
  * ≥ 10 distinct targets of **TerminateProcess** (Kernel-Audit-API-Calls event 2, already collected) by one non-system process within 10 s.
* **Telemetry:** process_start, Audit-API TerminateProcess (map to a `process_access`-like event with a terminate flag).
* **Protect:** suspend the lineage. `protect_day_one: true` only for the TerminateProcess ≥10-distinct variant from an unsigned or user-writable image; the cmdline variant stays Audit.
* **FP:** patch tools and installers stopping services (signed, few targets), developer scripts, MDM.
* **ATT&CK:** T1489, T1685 (v19; formerly T1562.001).

### RW-06 Mass file encryption behaviour (core)
* **Logic:** per PID, over a sliding 10 s window on **user-data paths**, compute
  * `touched` = distinct files with Create disposition overwrite/supersede, or RenamePath, or (CreateNewFile followed by DeletePath of the same stem);
  * `dirs` = distinct parent directories of touched files;
  * `extchg` = renames or new files whose extension differs from the original and whose new extension is **not** in a known-format list (docx, xlsx, pdf, jpg, png, heic, webp, zip, 7z, tmp, bak, …);
  * `top_ext_share` = share of extchg using the single most common new extension. A random per-file extension (LockBit 5) still yields "unknown ext, length ≥ 5, high-entropy charset" as a class.
  * **Trigger** when `touched ≥ 30` AND `dirs ≥ 3` AND (`extchg ≥ 20` OR `overwrite_ratio ≥ 0.8` with ≥ 50 files OR header-mismatch corroboration (§3.2) on ≥ 3 sampled files).
  * Network paths count double towards `touched`.
* **Telemetry (new):** Kernel-File 12 (+CreateOptions), 26 DeletePath, 27 RenamePath, 30 CreateNewFile, optional 10 NameCreate and 16 Write. Path scope filtering and per-PID aggregation in the callback. New aggregated `file_activity` event. Optional post-close header sampler.
* **Protect:** **suspend the lineage immediately**, then kill the tree after the canary/note/ext corroboration or 5 s, quarantine the image, and isolate if network paths were touched. `protect_day_one: true` *with* the signed sync/backup/archiver allow list; otherwise Audit.
* **FP:** see §3.6. Thresholds must be tuned in the lab against the benign set (Office, OneDrive first sync, 7-Zip extract, git clone of a large repo, Lightroom export, Windows Update).
* **ATT&CK:** T1486.

### RW-07 Canary document tampered
* **Logic:** an overwrite/supersede Create, Write, RenamePath or DeletePath on an armed ransomware canary (§3.3) by any process other than the agent. `explorer.exe` (the user deleting it) produces an alert only.
* **Telemetry:** Kernel-File as for RW-06, with path-exact match (cheap hash set). Reuse the ST-16 canary infrastructure: a new canary class `DataCategory::RansomCanary` or similar (contract change in `kestrel-common`).
* **Protect:** suspend and kill the lineage, quarantine. `protect_day_one: true`.
* **FP:** user or IT cleanup, OneDrive conflict rename (allow list), backup *restore* jobs, disk cleanup tools.
* **ATT&CK:** T1486.

### RW-08 Ransom note fan-out
* **Logic:** one process does CreateNewFile of the **same file name** (case-insensitive) in ≥ 5 distinct directories within 60 s, where the extension is in {txt, hta, html, htm, rtf, url} and either
  * the name matches `(?i)(read.?me|restore|recover|decrypt|how.?to|help|instruction|!!!|_info)`, or
  * the directories include a user-data root.
* Name-agnostic fallback: ≥ 20 directories.
* **Telemetry:** Kernel-File 30 (or 12 with create disposition) with a per-PID name→dir-set map.
* **Protect:** suspend the lineage. Kill when combined with RW-06 or RW-07. `protect_day_one: true` when the name regex also matches; otherwise Audit.
* **FP:** installers dropping `readme.txt` into many plugin folders (Program Files, so out of scope), `desktop.ini` (exclude), sync clients.
* **ATT&CK:** T1486, T1491.001 (Internal Defacement, for notes and wallpaper).

### RW-09 Remote (SMB) encryption observed on this host
* **Logic:** RW-06 or RW-08 thresholds met by **PID 4 (System)** on paths that are local shares (resolve via `LanmanServer\Shares` registry or `NetShareEnum` at start-up), with no local process lineage.
* **Telemetry:** as RW-06. For response, the SMB client IP/session is needed: Security 5140/5145 or the SMBServer ETW provider **[UNVERIFIED ids]**.
* **Protect:** WFP-block inbound 445 from the source IP(s) (never the Kestrel server), and alert critical. Default **Audit** on file servers, because blocking the wrong IP breaks business. `protect_day_one: false`.
* **FP:** a user's own sync or backup to the share (no ext change), DFS-R or robocopy migrations.
* **ATT&CK:** T1486, T1021.002.

### RW-10 Recovery-prep / encryption-enabling configuration
* **Logic:** any one is an Audit signal; ≥ 2 in one lineage within 30 min raises it to high:
  * `fsutil behavior set SymlinkEvaluation` with R2L:1, R2R:1 or L2L:1 (Sigma c0b2768a);
  * registry_set `…\Policies\System\EnableLinkedConnections` = 1 (Qilin);
  * `takeown /f … /r` (Sigma 554601fb);
  * `icacls … /grant Everyone:F /T` **[UNVERIFIED flags]**;
  * `cipher /w:` (Sigma 4b046706);
  * `mountvol` of hidden volumes **[UNVERIFIED]**.
* **Telemetry:** process_start, registry_set (key filter must include `EnableLinkedConnections`).
* **Protect:** Audit; contributes to correlation (RW-12).
* **ATT&CK:** T1222.001, T1485, T1490.

### RW-11 Suspicious kernel-driver load (BYOVD) before impact
* **Logic:** an `image_load` of a `.sys` in system context whose sha256 is in the LOLDrivers list, or whose path is user-writable (Temp/Downloads/ProgramData root). Also registry_set `Services\<x>\ImagePath` → `*.sys` in a user-writable path with `Type`=1.
* **Telemetry:** image_load (Kernel-Process IMAGE keyword includes driver loads into PID 4 **[UNVERIFIED for Kernel-Process provider; true for the classic kernel ImageLoad]**), registry_set. Ship the LOLDrivers hash set with IOC updates.
* **Protect:** user mode cannot stop a driver load. Alert critical, suspend the loader lineage, and **isolate the host** (an EDR killer is the last step before encryption, per ESET). `protect_day_one: true` for a LOLDrivers hash match. Hardening: enable the Microsoft vulnerable driver blocklist.
* **Overlap:** coordinate with the existing TP-xx tamper rules. If a TP rule already covers this, RW-11 becomes a correlation input only.
* **ATT&CK:** T1068, T1685 (v19; formerly T1562.001), T1543.003.

### RW-12 Ransomware kill-chain correlation (host)
* **Logic:** within 60 min, ≥ 2 distinct RW signals from {01, 02, 03, 04, 05, 10, 11} in the same lineage **or on the host**. Host-level counts because affiliates run separate tools from separate shells or PsExec.
* **Protect:** host isolation (WFP, keeping the Kestrel server reachable), suspend all participating lineages, and raise the policy to "ransomware alert" (RW-06 thresholds halved for 2 h). `protect_day_one: true`.
* **FP:** a pentest or red-team exercise (that is the point); a sysadmin doing VSS + event-log maintenance in one session (allow-listed admin tooling lowers the score).
* **ATT&CK:** T1486, T1490.

Optional, Audit only: **RW-13 Ransom wallpaper change**. registry_set `HKCU\Control Panel\Desktop\Wallpaper` (or `SystemParametersInfo` via the PowerShell pattern in Sigma `posh_ps_susp_wallpaper`) by an unsigned or user-writable process, correlated with RW-06/08. ATT&CK T1491.001.

---

## 5. Sensor changes Kestrel needs (exact)

1. **Kernel-File provider (kestrel-win):**
   * Add keyword masks to `consts::kw`: `FILE_FILENAME = 0x10`, `FILE_WRITE = 0x200`, `FILE_DELETE_PATH = 0x400`, `FILE_RENAME_SETLINK_PATH = 0x800`, `FILE_CREATE_NEW_FILE = 0x1000`.
   * The event ids `FILE_DELETE_PATH = 26`, `FILE_RENAME_PATH = 27` and `FILE_CREATE_NEW = 30` already exist. Add `FILE_NAME_CREATE = 10` and `FILE_NAME_DELETE = 11`.
   * Enable `0x80 | 0x400 | 0x800 | 0x1000` (+`0x10`) with an `EVENT_FILTER_TYPE_EVENT_ID` filter of {12, 26, 27, 30 [, 10, 11]}. Write(16, keyword 0x200) stays behind a policy flag, off by default. **Never enable 0x20 or 0x100** for this purpose.
   * Field names: `FileObject`, `FileKey`, `FileName` (12/30), `FilePath` (26/27), `InfoClass`, `CreateOptions`, `IssuingThreadId`. Add `FILE_KEY`, `INFO_CLASS` and `ISSUING_THREAD_ID` to `consts::field`.
   * **Lab task first:** confirm `FilePath` semantics of event 27 (source vs target), whether 27 and 30 fire for `\Device\Mup` paths, and how V0/V1 manifests behave on Windows 10 22H2, Windows 11 24H2/25H2 and Server 2019/2022.
2. **Callback-side aggregation (kestrel-win):**
   * A bounded per-PID state. Per-PID LRU tables are FileObject→(path, disposition) and FileKey→path; there is also a 10 s window of counters (§2.3), a canary hash-set, and a note-name→dir-set map.
   * Scope it to user-data paths and network paths, and drop everything else before allocation.
   * Emit a `file_activity` summary event when counters cross a pre-threshold, and a canary event immediately on a canary hit.
   * Drop counters are needed for the health page.
3. **Session placement:** move the ransomware Kernel-File events to a **1 s-flush session** (a new `Kestrel-Ransom`, or Core). Keep the 64 KB buffers.
4. **Contracts (kestrel-common, additive, `#[serde(default)]`):**
   * new `EventData::FileActivity { window_ms, files_touched, dirs, renames, ext_changes, top_new_ext, top_ext_share, overwrites, new_files, deletes, net_paths, sample_paths: Vec<String> (≤5, privacy-filtered), header_mismatch: u32 }`;
   * `FileOp` gains `Rename { new_path: Option<String> }`, `Delete` and `CreateNew` if they are not present;
   * `ProcessAccess` gains a `terminate: bool` (or a new `ProcessTerminate` event) for Audit-API event 2;
   * a canary class for ransomware decoys;
   * mirror all of these in `console/src/api/types.ts` and the tray protocol where relevant.
5. **Registry key filter:** add `\Control\SafeBoot\`, `\Winlogon\` (AutoAdminLogon only), `\Policies\System\EnableLinkedConnections`, `\Services\*\ImagePath` and `HKCU\Control Panel\Desktop\Wallpaper`.
6. **Optional event-log channel subscription:** Security 1102 and System 104 (log cleared); Security 5140/5145 for SMB client IP on file servers.
7. **Header sampler (kestrel-win, optional, Audit first):**
   * After Close/Cleanup of a file in an RW-06 suspect PID's set, open it (FILE_SHARE_READ, no reparse following, per the Kestrel quarantine rule) and read 4-64 KiB.
   * Check magic versus extension, and compute entropy. Rate-limit to 5 files per second per PID.
8. **Response (kestrel-win):**
   * "suspend lineage" as one action, with a lineage watch that auto-suspends new children for 10 min;
   * a WFP inbound-445 block by source IP for RW-09;
   * revert helpers for RW-02/03 (`bcdedit` value restore, logged);
   * self-registration of the Kestrel service under `SafeBoot\Network` (installer change, test in the VM only).
9. **Fixtures (kestrel-detect/tests/fixtures):**
   * Positive: vssadmin/wmic/wbadmin/bcdedit/wevtutil cmdlines, a synthetic mass-rename sequence (`.docx`→`.docx.k3str`), a random-16-char-extension sequence, Play-style intermittent overwrite (overwrite disposition, no rename), a note fan-out, and PID-4 share renames.
   * Benign: Office save (temp, delete, rename), OneDrive first sync, 7-Zip extract, git clone, Lightroom export, MSI install, Windows Update.
   * Replays go into `replays/*.jsonl` for `kestrel-agent simulate`.
10. **Lab validation (VM only, per CLAUDE.md):**
    * Use a benign "ransomware simulator" that XOR-encrypts copies of a seeded corpus and renames them. Do not run real malware.
    * Measure files lost before suspend at 40 files/s and 400 files/s, ETW drop counts, and CPU overhead with the new keywords during a 100k-file `git clone` and an Office-heavy workload.

---

## 6. Open questions / unverified items (summary)

* RenamePath(27) `FilePath`: source or target path. Whether Kernel-File emits 27/30 for SMB redirector paths.
* Kernel-Process image-load events for kernel drivers (PID 4) versus the classic kernel ImageLoad.
* SMB server ETW provider event ids for client IP/session (for RW-09 response).
* Current (2025-2026) per-family ransom-note names for LockBit 5 and Qilin; whether families skip hidden files.
* NTFS enumeration collation details for `!`/`0`/`_` prefixes. This should be verified in the lab with `dir /b` and FindFirstFileW order on a fresh NTFS directory.
* ATT&CK v19 ids for Clear Windows Event Logs and Safe Mode Boot.
* No public 2024-2026 encryption-speed benchmark found. Splunk 2022 remains the reference.
