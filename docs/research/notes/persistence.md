# Persistence techniques (commodity malware, 2025-2026) and user-mode telemetry

Research notes for Kestrel's planned `PS-xx` rule family. Compiled 2026-10-21.
Every claim has an inline source. Items marked **[UNVERIFIED]** come from memory or
single weak sources and must be checked in the VM lab, or with the read-only
`kestrel-agent sensors-test`, before code depends on them.

---

## 0. TL;DR

* **Prevalence.** Persistence remains a top-10 behaviour. Picus Red Report 2026 (1.1 M samples)
  ranks T1547 Boot/Logon Autostart **#7** of all techniques. It also says Defense Evasion and Persistence
  dominated in 2025 ([Picus press release](https://www.picussecurity.com/resource/press-release/red-report-2026-rise-of-digital-parasite),
  [Top-10 page](https://www.picussecurity.com/resource/the-top-ten-mitre-attack-techniques)).
* **Stealers are mostly smash-and-grab. Their loaders and the RATs bundled with them persist.**
  Zscaler's StealC comparison lists "establishes persistence: No" for StealC v1/v2 ([Zscaler](https://www.zscaler.com/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)).
  Sandboxed StealC chains still show scheduled-task persistence created by the AutoIt loader ([Joe Sandbox](https://www.joesandbox.com/analysis/1969203/0/html),
  [MalwareBazaar](https://bazaar.abuse.ch/sample/311d6c2eb62e8cc02df535559b319eaa62f38e6061039bf2ba68aa205fafe6f6)).
  HijackLoader added a dedicated scheduled-task persistence module in 2025 ([Zscaler, 2025-03](https://www.zscaler.com/blogs/security-research/analyzing-new-hijackloader-evasion-tactics)).
  ClickFix chains drop Run keys plus scheduled tasks ([ReliaQuest](https://www.reliaquest.com/blog/threat-spotlight-clickfix-evolves-with-pysoxy-proxying/),
  [SOC Prime summary of Stormshield analysis](https://socprime.com/active-threats/clickfix-attack-chain-analyzing/)).
  In 2025-2026 sandbox runs, XWorm and AsyncRAT use Run keys, Startup-folder files and scheduled tasks (XML) ([MalwareBazaar XWorm](https://bazaar.abuse.ch/sample/af3ce126b72093de4614fe12072896b2b492210a314986c95f78aa5afbdf6ba3),
  [Triage](https://tria.ge/260413-pr4msacz4p)). A Lumma/Vidar/AsyncRAT bundle shows a Run key plus Task Scheduler COM API ([MalwareBazaar](https://bazaar.abuse.ch/sample/880671a7d7b53ac357683c5036019eb5909b7466d29d7e8aad555bccfc38b703)).
  Lumma delivered via CastleLoader persists through `schtasks` ([Bitdefender via repost](https://malwaretips.com/threads/bitdefender-says-lummastealer-is-getting-a-second-life-alongside-castleloader.139624/post-1169791), weak source).
* **The three locations that matter most for Kestrel's buyer** are (1) HKCU Run/RunOnce, (2) scheduled tasks
  and (3) the Startup folder. All three point into `%AppData%`/`%LocalAppData%`/`%Temp%`/`C:\Users\Public`/`C:\ProgramData`.
  The owner's core idea ("new autorun pointing into a user-writable path") covers the bulk of commodity persistence.
* **Telemetry gaps today.** Kestrel's registry filter (`kestrel-win/src/etwparse.rs::is_interesting_reg_key`) covers Run*,
  Policies\Explorer and IFEO. It misses Winlogon, `Windows\Load`, Shell Folders, COM (`_Classes` hive), TaskCache, Services
  and SilentProcessExit. There is **no** Task Scheduler, WMI, SCM or BITS source. Kernel-File does not watch the Startup or Tasks folders.

---

## 1. Techniques: locations, ATT&CK id, 2025-26 relevance

| # | Technique | Where | ATT&CK | Commodity relevance 2025-26 |
|---|---|---|---|---|
| 1 | Run / RunOnce / RunOnceEx / RunServices(Once) | `HK{CU,LM}\Software\[Wow6432Node\]Microsoft\Windows\CurrentVersion\{Run,RunOnce,RunOnceEx,RunServices,RunServicesOnce}` | T1547.001 | **Very high.** XWorm, AsyncRAT, ClickFix droppers (sources above). Full key list: [MITRE T1547.001](https://attack.mitre.org/techniques/T1547/001/) |
| 2 | Policies Run | `HK{CU,LM}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` | T1547.001 | Medium. Used for evasion because users rarely look there ([MITRE](https://attack.mitre.org/techniques/T1547/001/)) |
| 3 | `Load` / `Run` values | `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows` → `Load`, `Run` | T1547.001 | Low-medium (Cardinal RAT per [MITRE](https://attack.mitre.org/techniques/T1547/001/)); in Sigma's `currentversion_nt` ASEP list ([Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml)) |
| 4 | Startup folders | `%AppData%\Microsoft\Windows\Start Menu\Programs\Startup`, `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` | T1547.001 | **High** (XWorm "Drops startup file"; AsyncRAT "autorun by creating a file"; HijackLoader LNK→BITS in 2023 per [HivePro](https://hivepro.com/wp-content/uploads/2023/09/HijackLoader-a-Deceptive-Modular-Malware-Loader_TA2023364.pdf)) |
| 5 | Startup folder redirection | `HKCU\...\Explorer\User Shell Folders\Startup` and `Shell Folders\Startup` (+ HKLM `Common Startup`) | T1547.001 | Low but evasive (MuddyViper per [MITRE](https://attack.mitre.org/techniques/T1547/001/)) |
| 6 | Scheduled task | `schtasks /create`, `Register-ScheduledTask`, COM `ITaskService` (taskschd.dll), `at.exe`, XML import. Stored in `C:\Windows\System32\Tasks\<name>` (XML) + `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\{Tree\<name>,Tasks\{GUID}}` ([Microsoft Tarrask blog](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)) | T1053.005 | **Very high.** HijackLoader 2025, StealC loader chains, ClickFix, CastleLoader→Lumma, XWorm `auto-sch-xml`. Hidden tasks: SD value deletion / Index edit ([MITRE](https://attack.mitre.org/techniques/T1053/005/)) |
| 7 | Windows service | `sc create`, `New-Service`, `CreateServiceW`, or direct `HKLM\SYSTEM\CurrentControlSet\Services\<n>\ImagePath` | T1543.003 | Medium. Needs admin. Seen with miners, RMM abuse and post-UAC-bypass loaders |
| 8 | WMI permanent subscription | `__EventFilter` + `CommandLineEventConsumer`/`ActiveScriptEventConsumer` + `__FilterToConsumerBinding` in `root\subscription` (also `root\default`) | T1546.003 | Low-medium (miners, fileless loaders). Stored in the WMI repository, so file scanning misses it ([Cyber Triage 2025](https://cybertriage.com/?p=27530)) |
| 9 | IFEO Debugger / SilentProcessExit | `HKLM\SOFTWARE\[Wow6432Node\]Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>\Debugger`; `...\SilentProcessExit\<exe>\MonitorProcess` (+ `ReportingMode`, IFEO `GlobalFlag` 0x200) | T1546.012 | Low (SDBbot, SUNBURST per [MITRE](https://attack.mitre.org/techniques/T1546/012/)); value names `MonitorProcess`/`ReportingMode`/`GlobalFlag=0x200` **[UNVERIFIED here, widely documented by Oddvar Moe/Hexacorn]** |
| 10 | Accessibility features | IFEO Debugger on `sethc.exe`, `utilman.exe`, `osk.exe`, `Magnify.exe`, `Narrator.exe`, `DisplaySwitch.exe`, `AtBroker.exe`; or binary replacement in System32 | T1546.008 | Low (hands-on actors, not commodity) |
| 11 | AppInit_DLLs | `HKLM\SOFTWARE\[Wow6432Node\]Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` + `LoadAppInit_DLLs` | T1546.010 | Low. Ignored when Secure Boot is on **[UNVERIFIED: Microsoft doc statement]** |
| 12 | AppCert DLLs | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls` | T1546.009 | Very low |
| 13 | COM hijacking | `HKCU\Software\Classes\CLSID\{…}\{InprocServer32,LocalServer32,TreatAs,ScriptletURL}`. HKCU wins over HKLM ([MITRE T1546.015](https://attack.mitre.org/techniques/T1546/015/), [SpecterOps 2025-05](https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/)) | T1546.015 | Medium. ComRAT, PcShare and SVCReady in MITRE; red-team favourite. Commodity use is less common than Run/tasks |
| 14 | Winlogon | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\{Userinit,Shell,Notify,Taskman,VmApplet,AppSetup}`; `HKCU\...\Winlogon\Shell` (listed in [Sigma currentversion_nt](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion_nt.yml) and [Elastic run-key rule](https://www.elastic.co/guide/en/security/current/startup-or-run-key-registry-modification.html)) | T1547.004 | Low-medium |
| 15 | Active Setup | `HKLM\SOFTWARE\[Wow6432Node\]Microsoft\Active Setup\Installed Components\{GUID}\StubPath` | T1547.014 | Low |
| 16 | BITS jobs | `bitsadmin /create /addfile /SetNotifyCmdLine`, `Start-BitsTransfer`, BITS COM | T1197 | Low-medium (download-cradle use is more common than persistence) |
| 17 | LNK modification | Editing Desktop/Start Menu/Taskbar `.lnk` targets/args | T1547.009 | Medium for **stealers**: adding browser flags (`--load-extension`, `--remote-debugging-port`) to browser shortcuts. Chrome 137 removed `--load-extension` from branded builds ([Chromium PSA, 2025-04](https://groups.google.com/a/chromium.org/g/chromium-extensions/c/1-g8EFx2BBY/m/S0ET5wPjCAAJ)); `--remote-debugging-port` cookie-theft abuse **[UNVERIFIED for 2025-26 specifics]** |
| 18 | Browser extensions | Force-install policy `HKLM\SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge}\ExtensionInstallForcelist`; or editing `Secure Preferences` while the browser is closed ([MITRE T1176.001](https://attack.mitre.org/techniques/T1176/001/)) | T1176.001 | Medium. Malwarebytes documented forced-install via PowerShell plus a scheduled task ([Malwarebytes 2022](https://www.malwarebytes.com/blog/news/2022/06/forced-chrome-extensions-keep-reappearing)). No 2025 stealer-specific source found |
| 19 | Netsh helper DLL | `HKLM\SOFTWARE\Microsoft\Netsh` | T1546.007 | Very low (Sigma has 2 rules, [dir](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/registry/registry_set)) |
| 20 | Print port monitor | `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<n>\Driver` | T1547.010 | Very low (needs admin; Sigma `registry_set_add_port_monitor`) |
| 21 | Time provider | `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\<n>\DllName` | T1547.003 | Very low **[UNVERIFIED path from memory, consistent with MITRE]** |
| 22 | Screensaver | `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` (+ `ScreenSaveActive`) | T1546.002 | Very low **[UNVERIFIED path from memory]** |
| 23 | Office | `HKCU\Software\Microsoft\Office test\Special\Perf` (T1137.002); Word `STARTUP`, Excel `XLSTART` folders, Normal.dotm (T1137.001); COM/VSTO add-in keys (T1137.006) | T1137.* | Low **[UNVERIFIED path specifics]**; Sigma has `registry_set_asep_reg_keys_modification_office` |
| 24 | Explorer shell extensions / SSODL / BHO / credential providers | `...\CurrentVersion\Explorer\{ShellServiceObjects,ShellIconOverlayIdentifiers,ShellExecuteHooks,SharedTaskScheduler,Browser Helper Objects}`, `ShellServiceObjectDelayLoad`, `Authentication\{Credential Providers,PLAP Providers,…}` | T1547 / T1546.015 | Low. All 20 fragments are listed in [Sigma currentversion ASEP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml) |
| 25 | Boot execute | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | T1547.001 | Very low (LoJax) |
| 26 | LSA packages | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\{Security Packages,Authentication Packages,Notification Packages}` | T1547.002/.005, T1556.002 | Low; belongs with `CD-xx` but same sensor |

---

## 2. Telemetry sources: ids, fields, real-time ETW vs EvtSubscribe

General rule: a **manifest provider** can be enabled in Kestrel's own real-time session (up to 8 sessions per provider) whether or not its
event-log channel is enabled. The **Security channel** (`Microsoft-Windows-Security-Auditing`, GUID `{54849625-5478-4994-A5BA-3E3B0328C30D}` per
[Learn 4697 XML](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697))
is OS-owned. The OS starts it, and other tools can only attach to it, not enable it ([Fibratus #705](https://github.com/rabbitstack/fibratus/issues/705)).
→ use EvtSubscribe for Security. **[UNVERIFIED]**: that our private session receives TaskScheduler/WMI/SCM/BITS events when the Operational
channel is disabled. Test with `sensors-test` after the providers are added. That would be a big win, because the TaskScheduler Operational log is **off by default**
([Microsoft Tarrask blog](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)).

Manifest data below is from `repnz/etw-providers-docs` Win10 18990 dumps, the same source as `kestrel-win/src/consts.rs`.
Those dumps strip channel info, so channel assignment comes from other references.

### 2.1 Microsoft-Windows-Kernel-Registry `{70EB4F03-C1DE-4F73-A051-33D13D5413BD}`
Source: [manifest](https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Microsoft-Windows-Kernel-Registry.xml).

| id | event | keyword | template fields |
|---|---|---|---|
| 1 | CreateKey | 0x1000 | BaseObject, KeyObject, Status, Disposition, BaseName, RelativeName |
| 2 | OpenKey | 0x2000 | same as CreateKey |
| 3 | DeleteKey | 0x4000 | KeyObject, Status, KeyName |
| 5 | SetValueKey | 0x100 | KeyObject, Status, Type, DataSize, KeyName, ValueName, CapturedDataSize, CapturedData, PreviousDataType, PreviousDataSize, PreviousDataCapturedSize, PreviousData |
| 6 | DeleteValueKey | 0x200 | KeyObject, Status, KeyName, ValueName |
| 13 | CloseKey | 0x1 | KeyObject, Status, KeyName |

**KeyName resolution.**
* Velociraptor's `Windows.ETW.Registry` caches `RelativeName` by `KeyObject` from events 1/2/4. Later events look up the cache and fall back to the event's own `KeyName`.
  Velociraptor warns that the provider "is not very reliable and seems to miss a lot of registry events" ([Velociraptor](https://docs.velociraptor.app/artifact_references/pages/windows.etw.registry)).
* A Microsoft Q&A user reports that `RelativeName` never contains the root and `BaseName` is always empty.
  Sometimes `RelativeName` is only a fragment, and sometimes it is `REGISTRY\...` ([Q&A](https://learn.microsoft.com/en-us/answers/questions/1320557/etw-registry-event-monitoring)). That makes a relative-only cache insufficient.
* The classic NT Kernel Logger registry class (`Registry_TypeGroup1`) has **KCBCreate (22) / KCBDelete (23) / KCBRundownBegin (24) / KCBRundownEnd (25)** carrying `KeyHandle` + `KeyName`.
  That is the documented way to map a kernel KCB pointer to a full name ([Learn](https://learn.microsoft.com/en-us/windows/win32/etw/registry-typegroup1)).
  The manifest provider has **no** KCB events (checked in the manifest above).
* **Recommended approach** (needs a lab test):
  1. Keep the current SetValueKey-only subscription.
  2. Log, via `sensors-test`, how often `KeyName` arrives absolute (`\REGISTRY\MACHINE…`/`\REGISTRY\USER…`) versus relative/empty for writes from `reg.exe`, PowerShell `Set-ItemProperty` and .NET `Registry.SetValue`.
  3. If relative names show up, add CreateKey/OpenKey (0x1000|0x2000) and build a bounded LRU of `KeyObject → absolute path`. Compose it as `BaseObject`'s path + `RelativeName` when `RelativeName` is not absolute.
  4. Drop CloseKey-invalidated entries (keyword 0x1). OpenKey is very high volume, so decide only after measuring.
  5. Alternatively, when Sysmon is present, prefer Sysmon 12/13/14 (`TargetObject` is a full path).
* **Normalisation gap (affects COM rules):**
  * HKCU writes arrive as `\REGISTRY\USER\<SID>\…`.
  * HKCU\Software\Classes is the separate `\REGISTRY\USER\<SID>_Classes\…` hive (UsrClass.dat) **[UNVERIFIED in ETW output; standard hive layout]**.
  * `normalize_reg_key` must map `HKU\<SID>_Classes\X` → `HKU\<SID>\Software\Classes\X` so matchers can stay simple.
* **CapturedData size.** The template has a `CapturedDataSize` (UInt16) separate from `DataSize`, so data may be truncated. Treat a truncated value as "unresolved": re-read the value with `RegGetValue` from the agent, which is also needed to defeat write-then-overwrite races.

### 2.2 Microsoft-Windows-TaskScheduler `{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}`
Source: [manifest](https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Microsoft-Windows-TaskScheduler.xml). Event meanings: [Learn 106](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774938(v=ws.10)).

| id | meaning | fields |
|---|---|---|
| 106 | task registered | TaskName, UserContext |
| 140 | task registration updated | TaskName, UserName |
| 141 | task deleted | TaskName, UserName |
| 129 | task process created | TaskName, Path, ProcessID, Priority |
| 200 | action started (v1) | TaskName, ActionName, TaskInstanceId, EnginePID |
| 201 | action completed (v2) | TaskName, TaskInstanceId, ActionName, ResultCode, EnginePID |

* There are no useful keywords (only `ForcedIdleProcessing` 0x1), so enable with ALL and filter by event id.
* **106/140 do not carry the action or the creator PID.** Resolve the action by reading `C:\Windows\System32\Tasks\<TaskName>` (XML `<Exec><Command>/<Arguments>`) as SYSTEM, or via `ITaskService::GetFolder/GetTask`.
  The Tasks file and `TaskCache\Tasks\{GUID}\Actions` both hold the command ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)).
* **Attribute the creator** by correlating within ~5 s:
  * `process_start` of `schtasks.exe`/`at.exe` (command line has `/create`, `/xml`),
  * PowerShell 4104 `Register-ScheduledTask`/`New-ScheduledTaskAction`,
  * **image_load of `taskschd.dll` by a non-system, untrusted process** (COM API use; sandboxes tag this as "Uses Task Scheduler COM API", e.g. [MalwareBazaar](https://bazaar.abuse.ch/sample/880671a7d7b53ac357683c5036019eb5909b7466d29d7e8aad555bccfc38b703)).
* 129/200 let Kestrel see the task actually running (the `Path` in 129 gives the image and the ProcessID ties it to process_start).
* **Fallback:** EvtSubscribe on `Microsoft-Windows-TaskScheduler/Operational` (channel must be enabled, e.g. `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true`, as an Audit-safe hardening item).
* **Security 4698/4699/4702:** created/deleted/updated, with the full task XML.
  * Needs `auditpol /set /subcategory:"Other Object Access Events" /success:enable` ([Learn policy](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events), [Elastic audit doc](https://www.elastic.co/docs/reference/security/prebuilt-rules/audit_policies/windows/audit_other_object_access_events)).
  * Not on by default ([Microsoft](https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/)).
  * Because it carries the XML, it is the best single source if Kestrel's hardening pack may set audit policy.
* **Hidden tasks:** Kernel-Registry DeleteValueKey (0x200) on `…\Schedule\TaskCache\Tree\<name>` with ValueName `SD`, or SetValueKey on `Index` ([MITRE](https://attack.mitre.org/techniques/T1053/005/)).
* **Registry route as a bonus:** SetValueKey on `TaskCache\Tasks\{GUID}\Actions` (written by the Schedule service's svchost) gives a real-time signal even if the provider route fails. The value is a binary blob, so read the XML instead **[UNVERIFIED blob format]**.

### 2.3 Service Control Manager `{555908D1-A6D7-4695-8E1E-26931D2012F4}`
* 7045 "service installed" fields: `ServiceName, ImagePath, ServiceType, StartType, AccountName` ([manifest](https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Service%20Control%20Manager.xml)).
* It is a manifest provider (System channel, enabled via the `EventLog-System` autologger). The same GUID already appears in Kestrel's TP tests, so a private real-time session can enable it **[UNVERIFIED in practice]**. Fallback: EvtSubscribe `System` 7045.
* **Security 4697:** `SubjectUserSid/Name, ServiceName, ServiceFileName, ServiceType, ServiceStartType, ServiceAccount`. Subcategory "Audit Security System Extension".
  Microsoft says to alert when ServiceFileName is outside `%windir%`/Program Files, on start type 0/1/4, and on a non-standard account ([Learn 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)).
  Neither 7045 nor 4697 (v0) carries the creator PID → correlate with `sc.exe`/PowerShell `New-Service`, or advapi `CreateServiceW` callers. Kernel-Registry writes to `Services\<n>\ImagePath` come from `services.exe`.
* Also watch direct `Services\<n>\ImagePath` registry edits by anything other than `services.exe`. This bypasses SCM, so no 7045 is raised.

### 2.4 Microsoft-Windows-WMI-Activity `{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}`
* Source: [manifest](https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Microsoft-Windows-WMI-Activity.xml). No keywords.
* **5861** fields: `Namespace, ESS, CONSUMER, PossibleCause`, where ESS is the filter name. It fires on a filter→consumer binding.
  It is in the Operational channel, Windows 10/2012+ ([Fibratus #710](https://github.com/rabbitstack/fibratus/issues/710), [MITRE DS0005](https://attack.mitre.org/datasources/DS0005)).
* 5859 fields: `NamespaceName, Query, User, processid, providerName, queryid, PossibleCause` (filter activation, carries a **processid**). 5860 is a temporary subscription.
* Sigma `win_wmi_persistence`:
  * fires on 5861 containing `ActiveScriptEventConsumer|CommandLineEventConsumer|CommandLineTemplate`, excluding the SCM Event Provider / `MSFT_SCMEventLogEvent` filter;
  * notes HP Health Driver FPs on the generic "Binding EventFilter" keyword;
  * claims WMI namespace auditing/SACL is a prerequisite **[CONFLICT: MITRE says 5861 is logged by default on Win10. Verify in VM]**
  ([Sigma](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/wmi/win_wmi_persistence.yml)).
* Creator attribution:
  * the WMI-Activity/Trace channel event 11 carries operation + client PID (per Fibratus #710). The Trace channel is analytic, so it is reachable only via ETW;
  * or process_start of `wmic.exe ... CommandLineEventConsumer` (Elastic rule logic, [Elastic](https://www.elastic.co/guide/en/security/8.17/persistence-via-wmi-event-subscription.html));
  * or 4104 containing `Set-WmiInstance`/`New-CimInstance` + `__EventFilter`.
* Sysmon 19/20/21 if present ([Splunk](https://github.com/splunk/security_content/blob/develop/detections/endpoint/wmi_permanent_event_subscription___sysmon.yml)).

### 2.5 Microsoft-Windows-Bits-Client `{EF1CC15B-46C1-414E-BB95-E76B077BD51E}`
* Source: [manifest](https://raw.githubusercontent.com/repnz/etw-providers-docs/master/Manifests-Win10-18990/Microsoft-Windows-Bits-Client.xml).
* **3** job created v2: `jobTitle, jobId, jobOwner, processPath, processId`, which identifies the creating process.
* **59** transfer start: `transferId, name, Id, url, peer, …`.
* **60** stop: … `hr` …
* The notify command line is **not** in any event, so detect `bitsadmin … /SetNotifyCmdLine` via process_start and any child process of the BITS svchost (`svchost.exe -k netsvcs -s BITS`) **[UNVERIFIED service group string]**.

### 2.6 Kernel-File (already in Kestrel)
Add these paths to the FileCreate/CreateNewFile (12/30) and Rename (27) source filter:
* `\Microsoft\Windows\Start Menu\Programs\Startup\` (user and ProgramData),
* `\Windows\System32\Tasks\`,
* `\Microsoft\Word\STARTUP\`, `\Microsoft\Excel\XLSTART\`, `\Microsoft\Templates\Normal.dotm`,
* `*.lnk` under `\Desktop\`, `\Start Menu\Programs\`, `\Internet Explorer\Quick Launch\User Pinned\TaskBar\`.

A file written to System32\Tasks without a matching 106 suggests direct XML drop/edit. Whether a dropped XML is picked up without registration is **[UNVERIFIED]**; treat it as audit.

### 2.7 Event-log-only (EvtSubscribe) summary
| Channel | Ids | Needs |
|---|---|---|
| Security | 4698/4699/4702 | auditpol "Other Object Access Events" (success) |
| Security | 4697 | auditpol "Security System Extension" (success) |
| System | 7045 | default on |
| Microsoft-Windows-TaskScheduler/Operational | 106/140/141/129/200 | channel enable (off by default on clients) |
| Microsoft-Windows-WMI-Activity/Operational | 5857-5861 | default on (Win10+) |
| Microsoft-Windows-Bits-Client/Operational | 3/59/60 | default on **[UNVERIFIED]** |
| Microsoft-Windows-Sysmon/Operational | 12/13/14, 19/20/21, 11 (file create) | Sysmon installed |

---

## 3. Practical design

### 3.1 Autorun location catalogue (matchers on normalised key)
Match on the normalised `HKLM\` / `HKU\<SID>\` prefix. Allow optional `Wow6432Node\` after `SOFTWARE\` (HKLM) or `Software\` (HKU).
Compare case-insensitively. A `$` marks a value-name constraint.

```
# Run family (T1547.001) — value = command line
SOFTWARE\Microsoft\Windows\CurrentVersion\{Run,RunOnce,RunServices,RunServicesOnce}\*
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx\*\*            (subkey values, incl. Depend)
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run\*
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows $Load,$Run
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\{User Shell Folders,Shell Folders} $Startup,$Common Startup
SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{Run,Run32,StartupFolder}\*  (enable/disable state — context only)
# Winlogon (T1547.004) — compare with defaults
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon $Userinit,$Shell,$Taskman,$VmApplet,$AppSetup
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\*
SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System $Shell
# DLL injection ASEPs
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows $AppInit_DLLs,$LoadAppInit_DLLs        (T1546.010)
SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls\*                               (T1546.009)
SYSTEM\CurrentControlSet\Control\Session Manager $BootExecute                               (T1547.001)
SYSTEM\CurrentControlSet\Control\Lsa $Security Packages,$Authentication Packages,$Notification Packages
# IFEO / silent exit (T1546.012 / .008)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*\ $Debugger,$GlobalFlag
SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\*\ $MonitorProcess,$ReportingMode
SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug $Debugger ; SOFTWARE\Microsoft\.NETFramework $DbgManagedDebugger
# Services (T1543.003)
SYSTEM\CurrentControlSet\Services\*\ $ImagePath,$ServiceDll(Parameters\),$FailureCommand
# Tasks (T1053.005)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\{Tree,Tasks}\**   (Set + DeleteValue SD/Index)
# COM (T1546.015) — HKU\<SID>\Software\Classes after _Classes normalisation
Software\Classes\CLSID\*\{InprocServer32,LocalServer32,InprocHandler32}\ $(default)
Software\Classes\CLSID\*\TreatAs\ $(default) ; Software\Classes\CLSID\*\ $ScriptletURL
Software\Classes\{*file,exefile,htmlfile,ms-settings,Folder}\shell\open\command  (also UAC-bypass)
# Explorer / shell extensions
SOFTWARE\Microsoft\Windows\CurrentVersion\{ShellServiceObjectDelayLoad,Explorer\ShellServiceObjects,Explorer\ShellIconOverlayIdentifiers,Explorer\ShellExecuteHooks,Explorer\SharedTaskScheduler,Explorer\Browser Helper Objects}\*
SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\{Credential Providers,Credential Provider Filters,PLAP Providers}\*
SOFTWARE\Microsoft\Active Setup\Installed Components\*\ $StubPath                          (T1547.014)
# Misc low-prevalence
SOFTWARE\Microsoft\Netsh\*                                                                   (T1546.007)
SYSTEM\CurrentControlSet\Control\Print\Monitors\*\ $Driver                                  (T1547.010)
SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\*\ $DllName                         (T1547.003)
Control Panel\Desktop $SCRNSAVE.EXE                                                          (T1546.002)
Software\Microsoft\Office test\Special\Perf\*                                                (T1137.002)
Software\Microsoft\Office\*\{Word,Excel,PowerPoint,Outlook}\Addins\*                          (T1137.006)
SOFTWARE\Policies\{Google\Chrome,Microsoft\Edge,BraveSoftware\Brave}\ExtensionInstallForcelist\*  (T1176.001)
SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\{Custom,InstalledSDB}\*           (T1546.011)
```
Sigma's ASEP rules cover the same ground and are a good cross-check ([dir](https://github.com/SigmaHQ/sigma/tree/master/rules/windows/registry/registry_set)). Sigma is DRL 1.1: don't copy filter lists verbatim without attribution.

### 3.2 Resolving the target executable from a value
Implement as a pure function in `kestrel-detect` (Linux-testable): `fn resolve_autorun(cmd: &str, ctx: &UserCtx) -> AutorunTarget { image, args, via: Vec<Lolbin>, payload: Option<PathOrUrl>, decoded: Option<String> }`.

1. **Expand environment variables** for REG_EXPAND_SZ and literal `%VAR%`. The agent runs as SYSTEM, so `%APPDATA%` must come from the writing user's profile:
   SID from `HKU\<SID>` → `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>\ProfileImagePath`.
2. **Tokenise** with `CommandLineToArgvW` rules (quotes, backslash-quote).
3. **Handle unquoted paths with spaces** the way CreateProcess does: try `C:\Program.exe`, `C:\Program Files\X.exe`, …, taking the first that exists. Flag "unquoted path ambiguity" as a weak signal in itself (T1574.009).
4. **Unwrap launchers** recursively (depth ≤ 4):
   * `cmd.exe /c|/k` (split on `&`, `&&`, `|`; `start "" x`);
   * `powershell|pwsh` (`-File x`, `-c/-Command`, `-e/-enc/-EncodedCommand` → base64 → UTF-16LE decode; flag `-w hidden`, `-nop`, `-ep bypass`, `iex`, `irm`, `iwr`, `DownloadString`, `FromBase64String`);
   * `wscript|cscript x.js/.vbs/.jse/.vbe/.wsf`;
   * `mshta <url|file|vbscript:>`;
   * `rundll32 path[,|#]Entry` (DLL is the payload; `javascript:` = immediate high);
   * `regsvr32 [/s] [/i:url] scrobj.dll` (url = high);
   * `conhost.exe [--headless] x`;
   * `explorer.exe x`; `forfiles /c`; `msiexec /i http…`; `schtasks /run`; `curl|bitsadmin` download cradles;
   * `python(w).exe x.py`, `node.exe x.js`, `AutoIt3.exe x.a3x` (AutoIt is a popular 2025 loader host, see the Joe Sandbox StealC chain above), `java -jar`.
5. The **payload** is the innermost file argument; script and DLL payloads count as "the target" for classification.

### 3.3 Classifying the target
* **Path class** (reuse `path_class_of`/`is_user_writable`):
  * user-writable = under `%USERPROFILE%` (AppData\Roaming, AppData\Local\{Temp,…}, Downloads, Desktop, Documents), `C:\Users\Public`, `C:\Windows\Temp`, `C:\ProgramData` (Users can create subdirs), plus known writable system dirs (`C:\Windows\Tasks`, `C:\Windows\Tracing` **[UNVERIFIED ACLs; prefer a real ACL check]**);
  * protected = `%windir%` (minus those), `Program Files*`.
  * Best: real `AccessCheck` against the Users/Authenticated Users/Everyone SIDs on the file **and** its parent directory. Cache the result.
* **Authenticode** (existing enrichment): valid + trusted chain + signer.
* **MOTW** (Zone.Identifier ≥ 3) on the payload or its archive.
* **Age**: file created < N min before the autorun write → "just dropped".
* **Fleet prevalence** (server-side hash count) and **first-seen**. Defender ASR uses the same idea for "prevalence, age, or trusted list" ([consts.rs ASR GUID 01443614…](../../../crates/kestrel-win/src/consts.rs)).
* **Writer context**: writer process path class, signature, whether it is an installer (`msiexec.exe`, signed setup in `%TEMP%` with an InstallShield/WiX/NSIS/Squirrel signature), and whether the writer or its tree already has an alert.

### 3.4 Benign baseline: the big FP source
* **Per-user apps legitimately autorun from AppData.** This is why "user-writable" alone cannot be Protect. Sigma's ASEP rule filters many of these
  ([Sigma currentversion ASEP](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml)):
  * OneDrive: `\AppData\Local\Microsoft\OneDrive\`, plus OneDriveSetup cleanup `cmd /q /c rmdir|del` RunOnce values;
  * Spotify: `\AppData\Roaming\Spotify\Spotify.exe`;
  * Teams classic: `\Microsoft\Teams\Update.exe --processStart`;
  * Discord: `\Discord\Update.exe --processStart Discord.exe`;
  * Python installer: `\AppData\Local\Package Cache\{…}\python-….exe" /burn.runonce`;
  * Zoom repair RunOnce, Google Drive, Opera, Everything, Greenshot, iTunes, AVG/Avast.
  * Other Squirrel apps (Slack, WhatsApp desktop, GitHub Desktop) follow the `Update.exe --processStart` pattern **[UNVERIFIED per-app]**.
* **Elastic's Run-key rule** is Low/21 and excludes by data string (Program Files, a set of AppData\Local vendor paths, installer flags), writer image (msiexec, reg.exe, setup components, vendor updaters) and SIDs (SYSTEM/LOCAL/NETWORK SERVICE). It does not exclude by signature.
  The authors keep it deliberately loose ([Elastic](https://www.elastic.co/guide/en/security/current/startup-or-run-key-registry-modification.html)). The industry treats a bare Run-key write as **low-severity telemetry, not a verdict**.
* **Per-user COM in HKCU is normal** for OneDrive (`FileSyncShell64.dll` in `%LocalAppData%\Microsoft\OneDrive\<ver>\`), Dropbox, Google Drive and Teams. Signed DLLs → suppress **[UNVERIFIED exact OneDrive CLSIDs]**.
* **Scheduled tasks**: Chrome/Edge/Firefox updaters, OneDrive per-user `OneDrive Reporting Task`/`OneDrive Standalone Update Task-S-1-5-21…` (action in `%LocalAppData%\Microsoft\OneDrive\`), Adobe, Dropbox, Zoom and GoogleUpdater per-user installs **[UNVERIFIED task names]**.
* **Kestrel FP policy (proposal):**
  1. **Suppress** when the payload is Authenticode-valid with a trusted chain **and** (signer is in a curated allow-list **or** fleet prevalence ≥ K hosts **or** first seen > 14 days ago).
  2. **Audit (low)**: signed but unknown signer in a user-writable path.
  3. **Alert (medium/high)**: unsigned/invalid payload in a user-writable path; any script host/LOLBin wrapper; payload has MOTW; payload created < 10 min ago.
  4. **Protect**: see the per-rule notes in §5.
  5. Per-tenant learned baseline: first 7 days in Audit, then auto-propose exclusions in the console (existing exclusions mechanism).

### 3.5 Catch-up inventory (because ETW drops events)
Velociraptor reports Kernel-Registry missing events (above). Add an **autoruns snapshot**:
* at agent start, then every N hours, plus on demand via `CollectTriage`;
* enumerate the §3.1 keys for all loaded user hives, the Startup folders, `System32\Tasks` (parse XML), services, and WMI `root\subscription` + `root\default` consumers (Cyber Triage warns that `root\default` is also used, [Cyber Triage](https://cybertriage.com/?p=27530));
* diff against the last snapshot and feed new entries through the same PS rules with `source: inventory` (Audit only; no Protect on inventory hits because the writer is unknown).

---

## 4. Confidence tiers

**High confidence (candidate Protect):**
* An autorun of any kind whose command unwraps to a script host/LOLBin with download/encoded/hidden flags, or to `mshta`/`regsvr32 /i:` with a URL, or `rundll32` of a user-writable DLL.
* An autorun (Run/Startup/task/service) whose payload is unsigned, in a user-writable path, **and** (MOTW or created < 10 min or writer is untrusted/user-path/already alerted).
* Any autorun created by a process tree that a strong ST rule has already flagged. This is the "persistence rollback" case.
* WMI CommandLine/ActiveScript consumer bindings.
* IFEO Debugger on accessibility binaries; SilentProcessExit MonitorProcess pointing to a user-writable/unsigned file.
* Winlogon Userinit/Shell changed from the OS default.
* Startup-folder redirection to a user-writable non-default path.
* Service installed with ImagePath under `C:\Users\` or wrapping cmd/powershell/mshta.

**Audit-only (context or noisy):**
* Bare Run/RunOnce writes with signed payloads.
* HKCU COM registrations with signed DLLs.
* Scheduled tasks by signed updaters.
* Services under ProgramData with signed binaries.
* BITS jobs without a notify command.
* LNK edits without browser flags.
* Active Setup, netsh, port monitor, time provider, screensaver, Office keys (rare, but admin/installer use exists and Protect on them buys little).
* Task XML file writes without a 106.
* Inventory-only findings.

---

## 5. Proposed rules PS-01 … PS-14

Conventions:
* "Protect action" assumes **new response actions**, to be added to `kestrel-common::response` (additive, `#[serde(default)]`):
  * `RemoveAutorun { location: AutorunLocation, backup: bool }`, covering the registry value, Startup file, task, service and WMI binding/consumer/filter;
  * `DisableService`;
  * `DeleteScheduledTask` (or one generic `RemoveAutorun` with a `kind` enum).
  Every removal **must back up** the original (value data, task XML, service config, MOF of consumer) into the quarantine vault so it can be restored, mirroring `RestoreFile`.
* All rules must never act on protected processes (`kestrel_detect::protect`), must skip the Kestrel service itself, and must re-read the registry value / task XML before removing it (TOCTOU).

| id | name | logic | telemetry | Protect action | default | ATT&CK | FP notes |
|---|---|---|---|---|---|---|---|
| **PS-01** | Run-key autorun to untrusted user-writable payload | registry_set on the Run family (§3.1 Run family incl. Policies\Explorer\Run, Windows\Load/Run, RunOnceEx) → resolve (§3.2) → payload user-writable **and** not trusted-signed **and** not baseline-suppressed. Severity high if MOTW, age < 10 min, or writer untrusted | Kernel-Registry 5 (existing) + enrichment; Sysmon 13 alt | Remove value (backup), quarantine payload, kill payload process if running and writer tree if writer untrusted | **Audit**. Protect only for the sub-case "unsigned + (MOTW or just-dropped) + writer untrusted". That sub-case is near-zero-FP and is the core of commodity stealer/RAT persistence | T1547.001 | OneDrive/Spotify/Discord/Teams/Squirrel apps (signed → suppressed); dev tools (unsigned self-built exe in Documents → Audit only); portable apps |
| **PS-02** | Autorun via script host / LOLBin | any autorun (registry Run family, Startup file, task action, service ImagePath, WMI consumer) whose resolved chain contains powershell/pwsh with `-enc`/`-w hidden`/`iex`/`irm`/`iwr`/`DownloadString`; mshta (any URL or `vbscript:`/`javascript:`); wscript/cscript on a user-path script; rundll32/regsvr32 on a user-path DLL or URL; `conhost --headless`; AutoIt3/python/node on a user-path script | as PS-01 + PS-05/06/08 sources | Remove autorun, quarantine script/DLL, kill writer tree | **Protect day one**. Benign software essentially never autostarts encoded/hidden PowerShell or mshta URLs; matches ClickFix/HijackLoader/XWorm patterns | T1547.001, T1053.005, T1059.001/.005, T1218.005/.010/.011 | Enterprise logon scripts (`wscript \\domain\NETLOGON\…`) → exclude UNC SYSVOL/NETLOGON and writers gpsvc/gpscript; some RMM agents use PowerShell tasks (signed RMM writer → Audit) |
| **PS-03** | Startup-folder drop | file create/rename in a user or common Startup folder by a process other than explorer.exe (user drag-drop) or a trusted-signed installer; classify by type: `.exe/.dll/.scr/.com` unsigned, `.js/.jse/.vbs/.vbe/.wsf/.hta/.bat/.cmd/.ps1/.url` = high; `.lnk` → parse target and apply PS-01/02 to it | Kernel-File 12/30/27 with new path filter; Sysmon 11 alt | Quarantine file (and LNK target if user-path unsigned), kill writer tree | **Protect** for script/unsigned-exe types written by an untrusted process; **Audit** for `.lnk` until the LNK parser exists | T1547.001, T1547.009 | Some apps drop signed LNKs to their own Program Files exe (suppress when target is trusted-signed) |
| **PS-04** | Startup folder redirection | User Shell Folders / Shell Folders `Startup` or `Common Startup` set to a non-default path | Kernel-Registry 5 | Restore the default `%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` (or `%APPDATA%\…`) value | **Audit, high severity**. Enterprise folder redirection GPO can legitimately redirect Start Menu, so check writer = gpsvc/svchost (GP) → suppress | T1547.001 | Folder Redirection GPO, roaming profile tools |
| **PS-05** | Scheduled task with untrusted action | TaskScheduler 106/140 (or 4698/4702, Sysmon 11 on System32\Tasks) → read task XML → resolve each `<Exec>` → payload user-writable & not trusted-signed, or LOLBin chain (→ PS-02), or `Hidden=true` + logon/short-interval trigger. Attribute creator via schtasks/4104/`taskschd.dll` image_load correlation | NEW TaskScheduler ETW provider; EvtSubscribe fallbacks; image_load | Disable+delete task (backup XML), quarantine payload, kill creator tree | **Audit**. Protect for "unsigned user-path payload + (MOTW/just-dropped or creator untrusted/alerted)". Per-user updater tasks with AppData actions are common, so the signer check is mandatory | T1053.005 | Chrome/Edge/Zoom/OneDrive/GoogleUpdater per-user tasks (signed); dev/admin scripts in user dirs (Audit) |
| **PS-06** | Hidden or tampered scheduled task | DeleteValueKey of `SD` under `TaskCache\Tree\*`, or SetValueKey `Index`=0, by any process other than the Schedule service's svchost during its own task deletion; or a Tree key without SD in the inventory | Kernel-Registry 6 (add keyword 0x200), 5; inventory | Alert + recommend isolate. Writer is SYSTEM, so the host is already compromised. Optional: restore SD from backup is out of scope | **Audit (critical severity)**. Tarrask-style, very rare benign | T1053.005, T1564 | Task deletion by the Schedule service legitimately deletes the whole key, so ignore when the writer is svchost (Schedule) and the parent key is deleted too |
| **PS-07** | Suspicious service install | 7045/4697 (or `Services\*\ImagePath` write not by services.exe) with ImagePath under `C:\Users\`, `C:\Windows\Temp`, `C:\Users\Public`; or wrapping cmd/powershell/mshta/rundll32; or unsigned ImagePath; or start type 0/1 with driver in a user path | NEW SCM provider (7045); EvtSubscribe System 7045 / Security 4697; Kernel-Registry | Stop + disable service (backup config), quarantine binary, kill creator tree | **Protect** for user-profile/Temp paths + interpreter wrappers (legit services do not live there). **Audit** for ProgramData/unsigned elsewhere (OEM/vendor tools do ship there) | T1543.003, T1569.002 | PsExec (`PSEXESVC` in `%windir%`, signed; Audit), RMM agents, game anti-cheat, OEM utilities in ProgramData |
| **PS-08** | WMI permanent event subscription | 5861 whose CONSUMER contains `CommandLineEventConsumer`/`ActiveScriptEventConsumer`/`CommandLineTemplate`, excluding the SCM Event Provider/`MSFT_SCMEventLogEvent` pair (Sigma); also process_start `wmic … EventConsumer` and 4104 `__EventFilter`/`__FilterToConsumerBinding` | NEW WMI-Activity provider (5861/5859, Trace 11 optional); EvtSubscribe fallback; Sysmon 19-21 | Delete binding + consumer + filter (backup MOF), kill creator if known | **Protect day one** for CommandLine/ActiveScript consumers (rare in SMB estates). Keep **Audit** for other consumer types | T1546.003 | HP/Dell OEM management agents (Sigma notes HP Health Driver FPs on generic bindings), SCCM; allow-list by consumer name per tenant |
| **PS-09** | IFEO / SilentProcessExit hijack | Debugger value set under IFEO for any exe (high if target ∈ accessibility set or a security tool / browser); GlobalFlag with 0x200 + `SilentProcessExit\*\MonitorProcess` | Kernel-Registry 5 (keys already partially in the filter; add SilentProcessExit) | Delete value (backup), quarantine debugger payload if user-path | **Protect** for accessibility binaries and user-path/unsigned debugger payloads; **Audit** otherwise | T1546.012, T1546.008 | Process Explorer "Replace Task Manager" (`taskmgr.exe` Debugger → signed procexp), VS JIT, some AV/app-control tools that use IFEO Debugger to block executables. Deduplicate with existing TP-xx IFEO coverage |
| **PS-10** | Winlogon / AppInit / AppCert / LSA / BootExecute change | Userinit ≠ `C:\Windows\system32\userinit.exe,` or Shell ≠ `explorer.exe` (HKLM or HKCU); any non-empty AppInit_DLLs with LoadAppInit_DLLs=1; any AppCertDlls value; new entry in LSA package lists; BootExecute ≠ `autocheck autochk *` | Kernel-Registry 5 | Restore OS default value for Userinit/Shell/BootExecute; delete AppCert/AppInit value; quarantine user-path DLL | **Protect** for Userinit/Shell/BootExecute (fixed known defaults, restoration is safe); **Audit** for AppInit/AppCert/LSA (security products and kiosks use these) | T1547.004, T1546.010, T1546.009, T1547.002/.005 | Kiosk shells (custom Shell set by admin, exclude via policy), Citrix/VDI Userinit additions, AV AppInit; default value strings are **[UNVERIFIED exact strings]** |
| **PS-11** | COM hijack in user hive | HKCU `Software\Classes\CLSID\{X}\{InprocServer32,LocalServer32,TreatAs,ScriptletURL}` written where {X} also exists in HKLM\Software\Classes (override), or the server path is user-writable & not trusted-signed, or ScriptletURL is set | Kernel-Registry 5 (+ `_Classes` normalisation); image_load of that DLL by explorer/svchost/msedgewebview2 confirms | Delete HKCU CLSID key (backup), quarantine DLL | **Audit**; Protect only when DLL unsigned + MOTW/just-dropped + overrides an HKLM CLSID | T1546.015 | OneDrive, Dropbox, Google Drive, Teams per-user shell extensions (signed → suppress) |
| **PS-12** | BITS persistence / notify abuse | process_start `bitsadmin` with `/SetNotifyCmdLine` or `/addfile` to a user path; child process of the BITS service host; Bits-Client 3 where processPath is untrusted + 59 url to a non-Microsoft domain | process_start; NEW Bits-Client provider (optional) | Cancel job (`bitsadmin /reset` equivalent via COM), kill child tree, quarantine downloaded file | **Audit**; Protect when the notify command runs a script host (route via PS-02) | T1197 | Windows Update/Store/Edge/Office use BITS heavily (all svchost/signed; filter on the creating process) |
| **PS-13** | Browser persistence tamper (stealer-adjacent) | `ExtensionInstallForcelist` (Chrome/Edge/Brave policies) written by a non-GP/MDM process; browser `.lnk` or Run value containing `--load-extension`, `--remote-debugging-port`, `--remote-allow-origins`, `--user-data-dir` pointing to a temp copy; `Secure Preferences` written by a non-browser process | Kernel-Registry 5 (new keys); Kernel-File (LNK paths, Secure Preferences — may already be in the ST file filter) | Remove the policy value / restore the LNK (backup), kill writer | **Audit** (high); Protect when the writer is untrusted/user-path. Intune/GPO legitimately force-install | T1176.001, T1547.009, T1185 | Intune (`IntuneManagementExtension`), GPO (gpsvc), dev tooling (Puppeteer/Playwright use remote debugging, but they spawn browsers with flags, not by editing LNK/Run) |
| **PS-14** | Rare ASEP modified | any write to the low-prevalence keys in §3.1 (Active Setup StubPath, Netsh, Print Monitors, TimeProviders, SCRNSAVE.EXE, Office test\Perf, Office Addins, ShellServiceObjectDelayLoad/shell ext/BHO, credential providers, AppCompatFlags Custom/InstalledSDB, AeDebug/DbgManagedDebugger, `Services\*\Parameters\ServiceDll`, `FailureCommand`) with severity by payload classification | Kernel-Registry 5 | none (alert) | **Audit**. Low prevalence in commodity malware; legitimate installers touch them | T1547.014, T1546.007, T1547.010, T1547.003, T1546.002, T1137.002/.006, T1546.011 | Office/VSTO add-in installers, printer drivers, credential-provider vendors (Duo, password managers) |
| **PS-15** | Persistence rollback (correlation) | track every autorun (any PS source) created by each process GUID / tree. When any strong ST/TP rule kills or quarantines that tree, remove all its autoruns and quarantine their payloads, even if PS-01/05 alone only audited them | engine state (ProcessTable) | `RemoveAutorun` for each recorded autorun (backup) | **Protect day one** (inherits the confidence of the triggering strong rule; fixes the "killed the stealer but its RunOnce re-runs it" gap) | T1547/T1053 | Only as good as attribution: for 106/7045/5861 attribution is correlation-based, so require a confidence ≥ "same tree within 5 s" |

---

## 6. Sensor changes needed (concrete)

1. **Kernel-Registry (`kestrel-win`)**
   * Keywords: keep `0x100` SetValueKey and add `0x200` DeleteValueKey (PS-06; removal of autoruns for context) and `0x4000` DeleteKey (TaskCache Tree/COM key deletions).
     **Measure first** whether `KeyName` in event 5 is absolute. If not, add `0x1000|0x2000` (CreateKey/OpenKey) with a bounded `KeyObject → path` LRU, evicted on CloseKey `0x1` (see §2.1).
     Field names for 6: `KeyObject, Status, KeyName, ValueName`; for 3: `KeyObject, Status, KeyName` (manifest).
   * `normalize_reg_key`: map `\REGISTRY\USER\<SID>_Classes\…` → `HKU\<SID>\Software\Classes\…`. Also accept `\REGISTRY\MACHINE\SOFTWARE\Classes`.
   * Replace `is_interesting_reg_key` with a table built from §3.1 (key-prefix trie + optional value-name set). Currently missing:
     * Windows NT\CurrentVersion\{Winlogon, Windows (Load/Run/AppInit_DLLs), SilentProcessExit, AeDebug, Schedule\TaskCache, AppCompatFlags}
     * Explorer\{User Shell Folders, Shell Folders, StartupApproved, ShellServiceObjects, ShellExecuteHooks, SharedTaskScheduler, Browser Helper Objects, ShellIconOverlayIdentifiers}, ShellServiceObjectDelayLoad, Authentication\*
     * Policies\System\Shell
     * Software\Classes\CLSID\*\{InprocServer32, LocalServer32, TreatAs}, ScriptletURL, shell\open\command
     * Active Setup, Netsh
     * SYSTEM\CurrentControlSet\{Services\*\(ImagePath|ServiceDll|FailureCommand), Control\Session Manager\(AppCertDlls|BootExecute), Control\Lsa, Control\Print\Monitors, Services\W32Time\TimeProviders}
     * Control Panel\Desktop\SCRNSAVE.EXE, Office test, Office Addins
     * Policies\{Google\Chrome, Microsoft\Edge, BraveSoftware\Brave}\ExtensionInstallForcelist
   * Re-read the value with `RegGetValue` when `CapturedDataSize < DataSize`.
2. **New manifest providers in the core real-time session** (keyword ALL, event-id filter):
   * Microsoft-Windows-TaskScheduler `DE7B24EA-73C8-4A09-985D-5BDADCFA9017`: 106, 140, 141, 129, 200.
   * Service Control Manager `555908D1-A6D7-4695-8E1E-26931D2012F4`: 7045.
   * Microsoft-Windows-WMI-Activity `1418EF04-B0B4-4623-BF7E-D74AB47BBDAA`: 5861, 5859 (optionally Trace 11 for client PID).
   * Microsoft-Windows-Bits-Client `EF1CC15B-46C1-414E-BB95-E76B077BD51E`: 3, 59 (optional, behind policy).
   * Verify each in the VM with `sensors-test` (does the private session get the events with the channel disabled? what event versions does Win11 24H2/25H2 ship?).
   * Expose them as new `EventData` variants in `kestrel-common` (additive): `TaskRegistered {name, user, op: Created|Updated|Deleted, actions: Vec<String>}`, `ServiceInstalled {name, image_path, start_type, account}`, `WmiBinding {namespace, filter, consumer}`. Update console types and the server telemetry list accordingly.
3. **EvtSubscribe additions** (existing event-log subscription framework):
   * `System` 7045;
   * `Security` 4697/4698/4699/4702;
   * `Microsoft-Windows-TaskScheduler/Operational` 106/140/141;
   * `Microsoft-Windows-WMI-Activity/Operational` 5861;
   * Sysmon 12/13/14/19/20/21/11 when present.
   * De-duplicate against ETW by (name, ts ± 2 s).
4. **Hardening pack (Audit-safe, reversible):**
   * `auditpol /set /subcategory:"Other Object Access Events" /success:enable` and `"Security System Extension"`;
   * enable the TaskScheduler Operational channel.
   * Record these in the hardening report; they increase Security log volume modestly.
5. **Kernel-File source filter:** add the Startup folders, `System32\Tasks\`, Office STARTUP/XLSTART/Normal.dotm, and `*.lnk` in Desktop/Start Menu/TaskBar pins (§2.6). Emit `file_write` for create/rename.
6. **Image-load:** flag `taskschd.dll` loads by non-system processes (attribution for COM-created tasks). Images to exempt: svchost, mmc, taskmgr, explorer **[UNVERIFIED benign loaders list]**.
7. **Agent-side helpers** (pure, Linux-testable in `kestrel-detect`): `resolve_autorun()` (§3.2), Task XML `<Exec>` parser (namespace `http://schemas.microsoft.com/windows/2004/02/mit/task`), LNK target parser (check licence: MIT/Apache crate only), SID→profile path map supplied by the platform.
8. **Autoruns inventory** at start and every 6 h (§3.5), reused by `CollectTriage`.
9. **Response actions** (contract change, additive): `RemoveAutorun { kind: RunValue|StartupFile|Task|Service|WmiSubscription|ComKey|RestoreDefault, … }` with mandatory backup to the vault and a `RestoreAutorun { quarantine_id }` counterpart. RBAC privilege `response.file` or a new `response.persistence`.

### Open verification items for the VM lab
1. Is Kernel-Registry event 5 `KeyName` absolute on Win11 24H2/25H2 for reg.exe / PowerShell / .NET writers?
2. Does `\REGISTRY\USER\<SID>_Classes` appear for HKCU\Software\Classes writes?
3. Do TaskScheduler/WMI-Activity/SCM/BITS events reach a private real-time session with their Operational channel disabled?
4. Is 5861 logged by default without a WMI namespace SACL? (Sigma vs MITRE conflict.)
5. CapturedData truncation size.
6. OneDrive/Teams/Zoom per-user task names and COM CLSIDs, for baseline fixtures.
