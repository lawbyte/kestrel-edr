# Internal Architecture of Modern Windows EDR Agents (2025-2026)

Research date: 2026-10-20. Sources were fetched this session unless noted. Items marked "general knowledge" in Inferences were not re-verified against a primary source this session and should be checked before relying on them.

---

## 1. Telemetry sources: kernel callbacks, minifilters, WFP, ETW, AMSI, Sysmon. What works from user mode vs what needs a signed driver?

### Takeaway
A production Windows EDR uses two layers. Kernel callbacks, a file-system minifilter and WFP callouts need a signed driver, and they are the only synchronous points where activity can be blocked. ETW (Kernel-Process/File/Network/Registry, Kernel-Audit-API-Calls, DNS-Client, Security-Auditing) and AMSI work from a user-mode service running as admin or SYSTEM, but they are asynchronous and record activity after it happens. ETW-TI is the exception: it is kernel-generated, but only a process running as Antimalware-PPL can consume it, and that requires an ELAM driver.

### Cited Findings
**Kernel callbacks (driver required)**
- `PsSetCreateProcessNotifyRoutineEx(NotifyRoutine, Remove)` returns `STATUS_ACCESS_DENIED` if the image containing the callback lacks `IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY` (the linker's /INTEGRITYCHECK). It returns `STATUS_INVALID_PARAMETER` if the routine is already registered or the system's registration limit is reached. The callback runs at PASSIVE_LEVEL inside a critical region with normal kernel APCs disabled. On process creation it runs in the context of the creating thread; on deletion, in the context of the last exiting thread. Minimum OS is Vista SP1 / Server 2008. — [MS Learn PsSetCreateProcessNotifyRoutineEx](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex)
- `ObRegisterCallbacks` registers callbacks for thread, process and desktop handle operations. It returns `STATUS_FLT_INSTANCE_ALTITUDE_COLLISION` if another driver already uses the same altitude, and `STATUS_ACCESS_DENIED` if the callback routines are not in a signed kernel image. It must be called at IRQL ≤ APC_LEVEL. A driver must call `ObUnRegisterCallbacks` before it unloads. — [MS Learn ObRegisterCallbacks](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
- ELAM drivers also use `CmRegisterCallbackEx` to monitor and validate boot-driver configuration in the System hive. — [MS Learn ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)
- OpenEDR's documented components show the classic full-driver design:
  - a file-system minifilter that "hooks I/O requests file system"
  - low-level process monitoring through "system callbacks"
  - registry monitoring through callbacks
  - a network filter
  - a "self-protection provider"
  - a kernel "Loader for Injected DLL" that loads a user-mode hooking DLL into every new process

  — [OpenEDR README](https://github.com/ComodoSecurity/openedr)
- RedEdr's kernel driver captures `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine` and `PsSetLoadImageNotifyRoutine`. It also performs KAPC DLL injection for `ntdll.dll` hooking, and it requires test-signing. — [RedEdr README](https://github.com/dobin/RedEdr)

**ETW available from user mode as admin/SYSTEM (no driver)**
- **Microsoft-Windows-Kernel-Process**, GUID `{22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716}`. Velociraptor enables it with keyword mask `any=0x50` and uses these event IDs: 1 ProcessStart, 2 ProcessStop, 5 ImageLoad, 6 ImageUnload. The artifact requires SYSTEM. — [Velociraptor Windows.ETW.KernelProcess](https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelprocess)
- The NT Kernel Logger can be enabled from user mode. Velociraptor's `watch_etw` exposes:
  - `kernel_tracer_type` to select event types: registry, process, image_load, network, driver, file, thread, handle
  - `kernel_tracer_stacks` to attach a stack trace to each event of the selected types
  - `enable_map_info`, which the docs warn is "very expensive and causes events to be dropped"

  — [Velociraptor watch_etw](https://docs.velociraptor.app/vql_reference/event/watch_etw/)
- RedEdr's user-mode-only mode (`--etw`, no driver, no test-signing) consumes:
  - Microsoft-Windows-Kernel-Process
  - Microsoft-Windows-Kernel-Audit-API-Calls
  - Microsoft-Windows-Security-Auditing
  - the Defender providers Microsoft-Antimalware-Engine, -RTP, -AMFilter, -Scan-Interface and -Protection

  — [RedEdr README](https://github.com/dobin/RedEdr)
- **Microsoft-Windows-Kernel-Audit-API-Calls** event IDs:

  | ID | Event | Kernel function |
  |---|---|---|
  | 1 | PsSetLoadImageNotifyRoutineEx | PsSetLoadImageNotifyRoutineEx |
  | 2 | TerminateProcess | NtTerminateProcess |
  | 3 | CreateSymbolicLinkObject | ObCreateSymbolicLink |
  | 4 | SetContextThread | NtSetContextThread |
  | 5 | OpenProcess | PsOpenProcess |
  | 6 | OpenThread | PsOpenThread |
  | 7 | IoRegisterLastChanceShutdownNotification | IoRegisterLastChanceShutdownNotification |
  | 8 | IoRegisterShutdownNotification | IoRegisterShutdownNotification |

  — [Elastic Security Labs "Kernel ETW is the best ETW"](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- Security event 4688 passes through lsass.exe, so lsass could tamper with it. The kernel-logged ProcessStart event from Kernel-Process requires kernel privileges to interfere with. — [Elastic "Kernel ETW is the best ETW"](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- Elastic considers kernel ETW "Microsoft's recommended approach" over ntdll hooks. An ntdll hook on `NtProtectVirtualMemory` can often be bypassed, while the kernel PROTECTVM ETW event is significantly harder to evade. Microsoft Defender for Endpoint also prefers kernel ETW. — [Elastic "Kernel ETW is the best ETW"](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- JonMon v2.0 splits the work between a kernel driver and a user-mode component:
  - the driver collects process creation, registry operations and file creates
  - the user-mode component collects .NET, RPC and network activity
  - both write to the Windows event log
  - license is MIT; the project is research-only and "not meant to run in production"

  — [JonMon GitHub](https://github.com/jsecurity101/JonMon)
- Fibratus uses ETW only (Kernel Logger and other providers). It enriches the raw events before rules see them:
  - rebuilds full registry key paths
  - maps DOS device names to drive letters
  - resolves file paths for ReadFile/WriteFile, which ETW reports only as file-object addresses
  - maps handle type IDs to names
  - attaches process state: command line, token integrity level, loaded DLLs, environment
  - captures call stacks

  Event categories: Process, Thread, Module, File, Registry, Memory, Network, Handle, Object. — [Fibratus docs: events](https://docs.fibratus.io/telemetry/events)

**AMSI (user-mode, in-process provider DLL)**
- AMSI covers UAC elevation (EXE/COM/MSI/ActiveX), PowerShell (scripts, interactive use, dynamic code evaluation), Windows Script Host, JavaScript/VBScript and Office VBA macros. It supports session correlation so related fragments of a payload can be judged together. — [MS Learn AMSI portal](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal)
- `IAntimalwareProvider` has three methods: `Scan`, `CloseSession` and `DisplayName`. Minimum OS is Windows 10 / Server 2016. A sample lives at Windows-classic-samples `Samples/AmsiProvider`. — [MS Learn IAntimalwareProvider](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)
- Since Windows 10 1903, an Authenticode check on provider DLLs can be enabled through `HKLM\SOFTWARE\Microsoft\AMSI\FeatureBits` (DWORD):
  - `0x1` disables the check (this is the default)
  - `0x2` enables it

  Providers should be signed with `signtool /ac`. Load failures appear as Code Integrity events 3040/3041. Windows does not protect the FeatureBits registry value, though the installed AV may. — [MS Learn IAntimalwareProvider](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)

**Sysmon**
- The latest Sysinternals release is Sysmon v15.22 (2026-09-10). It installs as a boot-start driver plus a service, and the service runs as a protected process. Event IDs:

  | ID | Event |
  |---|---|
  | 1 | ProcessCreate |
  | 2 | FileCreateTime |
  | 3 | NetworkConnect (off by default) |
  | 4 | Sysmon service state changed |
  | 5 | ProcessTerminate |
  | 6 | DriverLoad |
  | 7 | ImageLoad (off by default) |
  | 8 | CreateRemoteThread |
  | 9 | RawAccessRead |
  | 10 | ProcessAccess |
  | 11 | FileCreate |
  | 12 / 13 / 14 | Registry create/delete, value set, rename |
  | 15 | FileCreateStreamHash |
  | 16 | ServiceConfigurationChange |
  | 17 / 18 | Pipe created / connected |
  | 19 / 20 / 21 | WMI filter / consumer / binding |
  | 22 | DNSEvent |
  | 23 | FileDelete (archived) |
  | 24 | ClipboardChange |
  | 25 | ProcessTampering |
  | 26 | FileDeleteDetected |
  | 27 | FileBlockExecutable |
  | 28 | FileBlockShredding |
  | 29 | FileExecutableDetected |
  | 255 | Error |

  — [MS Learn Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **Native Sysmon in Windows (2026):**
  - It is an optional feature, off by default. Enable it with `Dism /Online /Enable-Feature /FeatureName:Sysmon`, then run `sysmon -i`.
  - The standalone Sysinternals Sysmon must be uninstalled first.
  - It shipped in the KB5077241 preview (OS builds 26200.7922 and 26100.7922, Feb 24, 2026).

  — [KB5077241](https://support.microsoft.com/servicing/os/windows-11/2026/02/february-24-2026-kb5077241-os-builds-26200-7922-and-26100-7922-preview)
- It was first announced in November 2025 and went to Insider builds 26220.7752 and 26300.7733 in early February 2026. — [BleepingComputer, Feb 4 2026](https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring)

### Inferences
- **Architecture option A, no driver:**
  - ETW consumers in a SYSTEM service: Kernel-Process, Kernel-File, Kernel-Network, Kernel-Registry, Kernel-Audit-API-Calls, DNS-Client, Security-Auditing, plus native Sysmon's event log where it is enabled.
  - An AMSI provider DLL.
  - Detection only after the fact; no synchronous blocking of process creation, handle access or file writes.

  This is roughly what Aurora, Fibratus, Velociraptor and Wazuh do.
- **Architecture option B, driver:**
  - `PsSetCreateProcessNotifyRoutineEx` to block process creation.
  - `ObRegisterCallbacks` to strip access rights from handles to lsass and to the agent itself.
  - `CmRegisterCallbackEx` for registry.
  - A minifilter (`FltRegisterFilter`) for pre-write and pre-create on files.
  - A WFP callout for network.
  - `PsSetLoadImageNotifyRoutine` and `PsSetCreateThreadNotifyRoutine`.
  - ETW-TI through a PPL service.
- (General knowledge, unverified this session) Commonly documented details:
  - The process-notify limit is 64 routines.
  - Setting `PS_CREATE_NOTIFY_INFO.CreationStatus` to a failure NTSTATUS blocks process creation.
  - `OB_PRE_OPERATION_INFORMATION` lets a callback strip `DesiredAccess` bits.
  - Handles opened with `OBJ_KERNEL_HANDLE` bypass Ob callbacks.
  - Provider GUIDs to verify with `logman query providers`: Kernel-File `{EDD08927-9CC4-4E65-B970-C2560FB5C289}`, Kernel-Network `{7DD42A49-5329-4832-8DFD-43D979153A88}`, Kernel-Registry `{70EB4F03-C1DE-4F73-A051-33D13D5413BD}`, DNS-Client `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}`, Security-Auditing `{54849625-5478-4994-A5BA-3E3B0328C30D}`.
- AMSI provider-signing enforcement is off by default, so an attacker with admin rights can register a rogue provider or toggle the check. The agent should watch `HKLM\SOFTWARE\Microsoft\AMSI\Providers` and `FeatureBits` for changes.

### Gaps
- Provider GUIDs other than Kernel-Process and Threat-Intelligence were not confirmed from a primary source this session.
- No primary source was found confirming whether native Windows Sysmon is GA on non-Insider/non-preview builds as of October 2026, or which event channel it writes to.

---

## 2. ETW-TI, PPL/ELAM, MVI, driver signing, and Microsoft's 2025-2026 changes

### Takeaway
ETW-TI (`Microsoft-Windows-Threat-Intelligence`, `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) gives kernel-generated events for memory and thread tampering (alloc, protect, map, read/write VM, APC, SetThreadContext, driver load). A consumer must run as Antimalware-PPL, which requires:

1. an ELAM driver, signed by Microsoft through WHQL;
2. MVI membership, without which the WHQL submission fails.

MVI membership in turn requires a commercial real-time AV product, a yearly third-party lab certification, an NDA and program license, and use of Trusted Signing.

On the kernel question: after the CrowdStrike outage, Microsoft's Windows Resiliency Initiative introduced MVI 3.0 (staged/ring deployment, tested incident response). A user-mode "Windows endpoint security platform" went to private preview with MVI partners in July 2025. As of March 2026 there was no public timeline for user-mode APIs and no kernel ban. Separately, starting with the April 2026 update, Windows removes trust for drivers signed under the old cross-signing program; kernel code must now go through WHCP/HDC signing.

### Cited Findings
**ETW-TI**
- The provider GUID is `F4E1897C-BB5D-5668-F1D8-040F4D8DD344`. Only Antimalware-PPL processes can enable it; the kernel enforces this in `EtwCheckSecurityLoggerAccess` / `EtwpCheckNotificationAccess`. — [Origin HQ (Connor McGarr), Jan 19 2026](https://www.originhq.com/research/securitytrace-etw-ppl)
- Categories available by default include executable memory allocation and mapping, remote APC, SetThreadContext, driver load/unload, `NtSystemDebugControl` and `NtQuerySystemInformation`. — [Origin HQ](https://www.originhq.com/research/securitytrace-etw-ppl)
- Impersonation events still require Antimalware-PPL, because enabling them needs a privileged `NtSetInformationProcess` call. Defender, running as AM-PPL, turns on optional telemetry for some processes. — [Origin HQ](https://www.originhq.com/research/securitytrace-etw-ppl)
- **SecurityTrace bypass (Jan 2026):**
  - `SecurityTrace` is a logger flag that limits query operations to AM-PPL processes. It is set on DefenderApiLogger and DefenderAuditLogger.
  - AutoLogger sessions skip the process-context check. A PoC (`ThreatIntelligenceConsumer`) consumes ETW-TI without PPL, a driver or kernel patching.
  - MSRC concluded this is not a vulnerability, because admin-to-PPL is not an enforceable boundary.

  — [Origin HQ](https://www.originhq.com/research/securitytrace-etw-ppl)
- `THREATINT_WRITEVM_REMOTE` is event ID 14 (0x0E), keyword 0x8000000000008000, raised from `NtWriteVirtualMemory`. Local vs remote is decided by comparing the target process with the caller. Read vs write is decided by the requested access (0x10 PROCESS_VM_READ, 0x20 PROCESS_VM_WRITE). — [SpecterOps "Uncovering Windows Events" (2023)](https://specterops.io/blog/2023/03/15/uncovering-windows-events/)
- TI events are logged only when the consumer runs as PPL. Vendors run their service binaries as PPL, and Sealighter-TI exists so researchers can do the same. — [SpecterOps](https://specterops.io/blog/2023/03/15/uncovering-windows-events/)
- **Elastic Defend 8.11** monitors, through ETW-TI with call stacks:
  - `VirtualAlloc`, `VirtualProtect`, `MapViewOfFile`, `VirtualAllocEx`, `VirtualProtectEx`, `MapViewOfFile2`, `WriteProcessMemory`
  - `QueueUserAPC` (call stacks not always available)
  - `SetThreadContext` stacks and lsass `ReadProcessMemory`, both planned for 8.12

  Stack-anomaly tags include `image-hooked`, `image_rop`, `unbacked_rwx` and `direct_syscall`. — [Elastic Security Labs, Jan 9 2024 (older)](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- The Windows 11 24H2 preview added new events to the Threat-Intelligence provider. — [Elastic "Kernel ETW is the best ETW"](https://www.elastic.co/security-labs/kernel-etw-best-etw)
- RedEdr shows the minimal setup for ETW-TI: an "empty, signed ELAM driver used solely to allow `RedEdrPplService` to start as PPL". — [RedEdr README](https://github.com/dobin/RedEdr)
- Sanctum (Rust EDR) had a `sanctum_ppl_runner` that is "ELAM signed" and monitors ETW-TI. It also used Alt Syscalls, which HVCI blocks. The author no longer works on the project. — [Sanctum README](https://github.com/0xflux/sanctum)

**PPL launch requirements**
- The vendor must have an ELAM driver installed that embeds a `MicrosoftElamCertificateInfo` / `MSElamCertInfoID` resource. Each entry gives:
  - a CertHash
  - an algorithm: `0x8004` SHA1, `0x800c` SHA256, `0x800d` SHA384, `0x800e` SHA512
  - optional EKUs, up to 3

  The Code Signing EKU must not be listed. — [MS Learn Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- **Signing rules for the protected service:**
  - The service EXE must be page-hash signed with SHA256.
  - Every non-Windows DLL it loads must be signed with the same registered certificate. Third-party DLLs can be catalog-signed (MakeCat, then `CryptCATAdminAddCatalog`).
  - Code Integrity blocks `scrobj.dll`, `scrrun.dll`, `jscript.dll`, `jscript9.dll` and `vbscript.dll` in protected processes.

  — [MS Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- **Registration and launch:**
  1. Register with `InstallELAMCertificateInfo(hElamDriverFile)`, or install the driver and reboot.
  2. `CreateService`
  3. `ChangeServiceConfig2(SERVICE_CONFIG_LAUNCH_PROTECTED, SERVICE_LAUNCH_PROTECTED_ANTIMALWARE_LIGHT)`
  4. `StartService`

  Child processes are launched with `PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL = PROTECTION_LEVEL_SAME` plus `CREATE_PROTECTED_PROCESS`. — [MS Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- **Restrictions on protected services:**
  - Non-protected processes, admins included, cannot inject into or stop the service.
  - Updates require the service to stop itself on a callback from the installer.
  - Only the service itself can remove its protection.
  - Processes with a UI cannot be protected.
  - TLS was unavailable in protected processes before Windows 10 1703.

  — [MS Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)

**ELAM**
- Prerequisites are MVI membership and a WHQL submission. "The submission fails if the vendor is not an MVI member." Non-members can contact mvi@microsoft.com. — [MS Learn ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites)
- **ELAM driver design:**
  - Boot-start (`StartType=0`), `LoadOrderGroup="Early-Launch"`, installed as a legacy (non-PnP) service via INF with a SignatureAttributes section.
  - `IoRegisterBootDriverCallback` with `BdCbStatusUpdate` and `BdCbInitializeImage`; each boot driver is classified good, bad or unknown.
  - Signature data lives in the `HKLM\ELAM\<Vendor>\` values Measured, Policy and Config, which Measured Boot measures. Changes to that hive are discarded before boot.
  - Driver load policy is set at `HKLM\System\CurrentControlSet\Control\EarlyLaunch\DriverLoadPolicy` (default 0x3).
  - A WinRE backup goes to the `BackupPath` value under `...\Control\EarlyLaunch`.
  - `Tbsi_Revoke_Attestation` can invalidate measured-boot PCRs.

  — [MS Learn ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)
- ELAM performance budgets:

  | Scenario | Limit |
  |---|---|
  | Evaluate one boot driver | 0.5 ms |
  | Evaluate all boot drivers | 50 ms |
  | Driver plus config data in memory | 128 KB |

  — [MS Learn ELAM driver requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)
- An ELAM service runs as PPL and must be debugged with a kernel debugger. — [MS Learn ELAM overview](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/early-launch-antimalware)

**MVI membership (page last updated 2026-09-10)**
- **Membership requirements:**
  - a commercially available real-time product that detects, prevents and remediates malware
  - Windows-compatible updates distributed to customers
  - positive industry reputation
  - an NDA and a program license
  - active participation in the program
  - the solution "requires use of Trusted Signing"
  - certification within the last 12 months by an accepted lab, maintained yearly

  — [MS Learn MVI criteria](https://learn.microsoft.com/en-us/unified-secops-platform/virus-initiative-criteria)
- **Accepted certifications:**

  | Lab | Minimum |
  |---|---|
  | AV-Comparatives | Real-World or Malware Protection, Certified/Approved |
  | AVLab | Excellent, 99.6% |
  | AV-Test | 97% Real-World for MVI, or Certified (Home) / Approved (Enterprise) |
  | MRG Effitas 360 | Level 2 |
  | SE Labs EPS/EAS | AAA |
  | SKD Labs Starcheck | Certified |
  | VB100 | 95%, Grade B or higher |
  | West Coast Labs | Rating A |

  Applications are reviewed monthly, and Microsoft works with partners on Safe Deployment Practices. — [MS Learn MVI criteria](https://learn.microsoft.com/en-us/unified-secops-platform/virus-initiative-criteria)

**Driver signing**
- Attestation or WHCP submissions need at least one valid EV certificate registered to the Partner Center / Hardware Dev Center account. All signatures must be SHA-2 (`signtool sign /fd sha256`). EV certificates come from Certum, DigiCert, GlobalSign, IdenTrust, Sectigo or SSL.com. — [MS Learn code signing requirements (updated 2026-04-14)](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- **Cross-signed driver trust removed (April 2026):**
  - Starts with the April 2026 Windows Update on Windows 11 24H2, 25H2 and 26H1 and Windows Server 2025.
  - Rolls out first in evaluation/audit mode; "essential and reputable" cross-signed drivers stay trusted.
  - Custom drivers can be allowed through an App Control for Business policy signed by an authority in the Secure Boot PK or KEK.
  - Drivers for the Windows ecosystem must be "WHCP certified and signed through the Microsoft HDC portal."

  — [The Register, Mar 27 2026](https://www.theregister.com/2026/03/27/microsoft_kernel_trust/)
- WatchGuard publicly describes its MVI-oriented process (Jul 2026):
  - HLK tests on Windows 10/11
  - DigiCert EV certificates for executables
  - Microsoft Trusted Signing for kernel drivers
  - rings: QA, Staging, Friends & Family, Production
  - rollouts that can be paused
  - automatic installer rollback

  — [WatchGuard Trust Center](https://www.watchguard.com/wgrd-trust-center/microsoft-amdr-safe-deployment-practices)

**Windows Resiliency Initiative and the move out of the kernel**
- Timeline before the 2025 announcement:
  - Sep 10, 2024: Windows Endpoint Security Ecosystem Summit in Redmond. Topics included performance outside kernel mode, anti-tamper, and sensor requirements. ESET: "It remains imperative that kernel access remains an option."
  - The CrowdStrike outage hit about 8.5 million PCs.

  — [Digital Trends via Yahoo, Sep 13 2024](https://tech.yahoo.com/computing/articles/windows-still-making-changes-prevent-202711957.html)
- **June 26, 2025 announcement:**
  - "Next month, we will deliver a private preview of the Windows endpoint security platform to a set of MVI partners." Security products "can run in user mode just as apps do."
  - Named partners: Bitdefender, CrowdStrike, ESET, SentinelOne, Sophos, Trellix, Trend Micro, WithSecure.
  - MVI 3.0 requires testing incident response processes and following SDP; updates "must be gradual, leverage deployment rings" with monitoring.
  - Quick Machine Recovery (through WinRE) also announced.

  — [Windows Experience Blog, Jun 26 2025](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise)
- A Microsoft spokesperson said the preview is "an opportunity for partners to test", not a statement about future kernel access. Analysts expect a gradual future restriction. — [CSO Online, Jun 30 2025](https://www.csoonline.com/article/4014241/microsoft-hints-at-revoking-access-to-the-windows-kernel-eventually.html)
- **Status as of March 2, 2026:**
  - The project is still at an early stage. Microsoft asked vendors to inventory their product features so they can be preserved in user mode.
  - The expected result is a hybrid model, with some products running in both modes during migration.
  - "No public timeline" exists for user-mode APIs or for test readiness.
  - About 100 companies are MVI members; roughly a dozen are working on the kernel changes, covering "a significant majority of the market share."
  - Pavel Yosifovich: in user mode, a product learns about a process only after it starts, and "it's almost impossible to run completely outside the kernel without significant reengineering."

  — [Cybersecurity Dive, Mar 2 2026](https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/)

### Inferences
- A new vendor that is not in MVI cannot get a Microsoft-signed ELAM driver. Without one it cannot run as AM-PPL, so it cannot officially consume ETW-TI and cannot protect its service as a PPL. MVI in turn requires a shipping commercial product with a lab certification, so there is a chicken-and-egg problem. A practical path:
  1. ship v1 with ETW-only telemetry (no TI) plus an attestation- or WHCP-signed driver (EV certificate, HDC);
  2. obtain a lab certification;
  3. apply to MVI.
- The AutoLogger/SecurityTrace route to ETW-TI without PPL (Origin HQ, Jan 2026) works today, but it is undocumented and Microsoft may close it. Do not build a product on it.
- Given the cross-signing removal and Microsoft's stated direction, kernel components should be minimal: callbacks plus a minifilter that forward events, with parsing, rules and network I/O in user mode. Build safe-deployment rings into the content and update pipeline from day one, because MVI 3.0 requires it.
- The user-mode endpoint security platform APIs are NDA-only. Treat them as unavailable for planning unless you join MVI.

### Gaps
- No public documentation was found of the actual user-mode endpoint security platform APIs, or of their status after July 2025 beyond the March 2026 report.
- No public text of the MVI 3.0 requirements beyond the blog summary was found.
- No full list of ETW-TI event IDs and keywords came from a fetched primary source; only WRITEVM_REMOTE = 14 was confirmed. A full list could be built with the jdu2600 Windows10EtwEvents or ETWInspector tools.
- It is unverified whether Windows Server accepts attestation-signed (non-HLK) drivers. General knowledge says Server requires WHCP/HLK, but this was not confirmed this session.

---

## 3. Open-source and agent projects: architecture, language, license

### Takeaway
Most open-source "EDRs" either run on ETW alone (Fibratus, Aurora, Velociraptor, SilkETW, Sealighter) or are research or abandoned driver-based projects (OpenEDR, JonMon, Sanctum, RedEdr, BlueSpawn). Pay attention to licenses: Velociraptor is AGPL, Wazuh is GPLv2/AGPL, BlueSpawn is GPLv3, OpenEDR is the source-available "Comodo Available Source License" (not OSI), and Elastic's rules are ELv2. The permissive options to build on are krabsetw (MIT), Fibratus (Apache-2.0), SilkETW (Apache-2.0) and JonMon (MIT).

### Cited Findings
**Fibratus**
- Go: the repo has go.mod and a go-import meta tag. — [GitHub](https://github.com/rabbitstack/fibratus)
- Apache License 2.0, copyright 2019-2026 Nedim Šabić Šabić. — [LICENSE.MD](https://github.com/rabbitstack/fibratus/blob/master/LICENSE.MD)
- Features:
  - behavior rule engine and a YARA memory scanner
  - output sinks and capture files for forensics
  - "filaments", which are Python extensions
  - releases code-signed through SignPath Foundation

  — [GitHub README](https://github.com/rabbitstack/fibratus)
- Rules are YAML, with fields `name`, `id`, `version`, `min-engine-version`, `condition`, `action`, `severity`, `output`, `labels` (MITRE) and `enabled`. Conditions use a DSL (`ps.exe`, `file.path`, `imatches`, macros). Rules are evaluated lazily. — [Fibratus docs: rules](https://docs.fibratus.io/rules)
- Sequences use `sequence ... |expr| by ps.uuid ... maxspan 2m`, with aliases (`as e1` and `$e1.file.path`). The engine is a state machine: one sequence instance per entity, discarded when maxspan is exceeded or the process terminates. — [Fibratus docs: sequences](https://docs.fibratus.io/rules/sequences)
- The `isolate` action uses WFP; `kill` is also an action. — [Fibratus docs: isolate](https://docs.fibratus.io/rules/actions/isolate)

**Velociraptor**
- Go; the build needs Go ≥ 1.23.2 and CGO with gcc. — [GitHub README](https://github.com/Velocidex/velociraptor)
- AGPL-3.0. — [LICENSE](https://github.com/Velocidex/velociraptor/blob/master/LICENSE)
- ETW support comes from `watch_etw` plus a kernel tracer for the NT Kernel Logger. — [docs](https://docs.velociraptor.app/vql_reference/event/watch_etw/)
- Its isolation artifact uses local IPsec policy through `netsh ipsec static`, not the firewall. It permits the frontend (from `config.server_urls`), DNS and DHCP, and blocks everything else. It tests connectivity to `/server.pem` and removes the policy if that test fails. It does not work if a domain IPsec policy is applied. — [Windows.Remediation.Quarantine](https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/)

**OpenEDR (Comodo/Xcitium)**
- Components:
  - core library and service
  - injected hooking DLL, with a kernel loader and a service-side controller
  - system monitor: minifilter, process and registry callbacks, network filter, self-protection provider
- Telemetry is shipped to Elasticsearch.
- Latest release referenced: 2.5.1.

— [GitHub README](https://github.com/ComodoSecurity/openedr)
- License is the "COMODO AVAILABLE SOURCE LICENSE (CASL) AGREEMENT", which is source-available, not OSI open source. — [LICENSE.md](https://github.com/ComodoSecurity/openedr/blob/main/LICENSE.md)

**Wazuh**
- Licensing is split:
  - the engine (`src/engine/`) is AGPL-3.0+
  - shared libraries are GPL-2.0-only OR AGPL-3.0-or-later
  - "everything else" is GPL (v2)

  — [LICENSE](https://github.com/wazuh/wazuh/blob/main/LICENSE)
- Agent modules:
  - log collector, including Windows events with XPath filters
  - FIM covering files and registry
  - SCA (CIS benchmarks)
  - inventory stored in local SQLite
  - Active Response: block connection, stop process, delete file
  - command execution
  - encrypted, compressed TCP/UDP channel with flow control and queuing

  — [Wazuh agent docs](https://documentation.wazuh.com/current/getting-started/components/wazuh-agent.html)

**Nextron Aurora**
- An ETW-based agent that applies Sigma rules and IOCs to local event streams. It extends Sigma with "response actions". Output goes to the Event Log, a file, or UDP/TCP. — [Aurora manual](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/what-is-aurora.html)
- Aurora Lite is free, including commercial use, but may not be resold. It allows response actions on only 5 rules and excludes management, private rule feeds and non-Sigma modules. Aurora is proprietary. — [Aurora manual](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/what-is-aurora.html)

**ETW libraries and tools**
- **krabsetw:** a C++ ETW library from Microsoft (MIT). A C++/CLI .NET wrapper ("Lobsters", `Microsoft.O365.Security.Native.ETW`) is used in production by the Office 365 Security team. Supports x64/ARM64 only. A throwing callback stops the trace, and `start()` blocks. — [README](https://github.com/microsoft/krabsetw), [LICENSE](https://github.com/microsoft/krabsetw/blob/master/LICENSE)
- **Sealighter:** built on krabsetw. Features:
  - multi-provider ETW and WPP tracing
  - automatic JSON parsing
  - filter chaining and negation
  - stack traces
  - aggregation of repeated events with a count, to cut volume

  — [README](https://github.com/pathtofile/Sealighter)
- **SilkETW:** C# on .NET 4.5 with the TraceEvent library, YaraSharp integration, Apache-2.0. — [README](https://github.com/mandiant/SilkETW), [LICENSE.txt](https://github.com/mandiant/SilkETW/blob/master/LICENSE.txt)

**Research and other agents**
- **JonMon:** a C++ driver plus user-mode component, MIT, research-only. — [GitHub](https://github.com/jsecurity101/JonMon)
- **BLUESPAWN:** GPL-3.0. — [LICENSE](https://github.com/ION28/BLUESPAWN/blob/master/LICENSE)
- **RedEdr:** components talk over named pipes `\\.\pipe\RedEdr*`:
  - `RedEdr.exe`: orchestrator and web UI
  - `RedEdrDriver.sys`
  - an injected `RedEdrDll.dll` (Detours/MinHook)
  - `RedEdrPplService.exe`
  - `elam_driver.sys`

  — [GitHub](https://github.com/dobin/RedEdr)
- **Sanctum:** all Rust (windows-drivers-rs, Tauri GUI). Crates: driver, um_engine, injected_dll (deprecated in favour of Alt Syscalls), shared no_std crates and a ppl_runner. No longer maintained. — [README](https://github.com/0xflux/sanctum)
- **Elastic protections-artifacts** (the published Elastic Defend behavior and YARA rules) is under Elastic License 2.0. — [LICENSE.txt](https://github.com/elastic/protections-artifacts/blob/main/LICENSE.txt)

### Inferences
- The language and license of Sealighter, Aurora's implementation language, and Elastic Endpoint internals were not confirmed (see Gaps). Elastic Endpoint itself is closed source; only its rules are public, under ELv2.
- The most reusable stack for a permissively licensed product:
  - krabsetw (C++) for ETW, or a Rust/Go ETW binding
  - Fibratus as a design reference for the event model, enrichment and rule DSL (Apache-2.0, so code reuse is allowed)
  - YARA (BSD-3, general knowledge) for scanning
  - a Sigma converter for rules

  Avoid copying code from Velociraptor, Wazuh or BlueSpawn into a closed product, because of the AGPL/GPL terms.

### Gaps
- No license file was found for Sealighter at the paths tried (main/master LICENSE*).
- No public architecture document for Elastic Endpoint (the driver plus PPL service internals) was found.
- Fibratus's latest release version and date were not retrieved: the GitHub API was blocked in this environment.

---

## 4. Detection engines: edge Sigma, YARA, stateful/EQL correlation, ML, reputation

### Takeaway
Agents combine four kinds of detection:

- **Single-event matching:** Sigma (Aurora) or a custom DSL (Fibratus).
- **Stateful sequences:** EQL `sequence by ... with maxspan` (Elastic) or Fibratus sequences. These keep per-entity state machines that expire on a time window or on process exit.
- **YARA:** on files and on process memory (Fibratus, SilkETW, Elastic's published YARA rules).
- **Static ML:** PE classifiers trained on datasets such as EMBER2024.

### Cited Findings
- **EQL sequence features:**
  - `sequence by <keys> with maxspan=<t>`
  - per-clause `by` join keys, and `?` for nullable keys
  - `!` for missing-event clauses (requires maxspan)
  - `until` as an expiration event
  - `with runs=N` (1-100)
  - `sample by` for unordered matching

  Example:
  ```
  sequence by user.name with maxspan=15m
    [file where file.extension == "exe"]
    [process where true]
  ```
  — [Elastic EQL syntax](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql-syntax.html)
- Fibratus sequences create a new instance when the first expression matches. Multiple instances run at once, one per entity. An instance is discarded on a maxspan or process-termination violation. Without maxspan, instances live indefinitely, which is "usually undesirable in high-throughput systems." — [Fibratus sequences](https://docs.fibratus.io/rules/sequences)
- Fibratus puts costly functions such as `get_reg_value` last in a condition, so lazy evaluation can skip them. Rules without a scoped event condition get "utterly discarded by the engine". — [Fibratus rules](https://docs.fibratus.io/rules)
- Aurora applies Sigma rules and IOCs to ETW streams on the endpoint and adds response actions to Sigma. — [Aurora manual](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/what-is-aurora.html)
- Elastic fingerprints each high-volume API event and emits only unique events. The most verbose API events are evaluated on the host but not streamed by default. — [Elastic Security Labs](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- Call-stack features (`unbacked_rwx`, `direct_syscall`, `image_rop`, `image-hooked`) act as detection primitives for in-memory threats. — [Elastic Security Labs](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- **EMBER2024** (arXiv Jun 5 2025):
  - more than 3.2 million files in six file formats
  - EMBER feature version 3
  - seven tasks, including detection, family classification and behavior identification
  - a "challenge set" of malware that AV products initially missed

  — [arXiv 2506.05074](https://arxiv.org/abs/2506.05074v1)
- Pretrained EMBER2024 benchmark models are published. — [Hugging Face joyce8/EMBER2024-benchmark-models](https://huggingface.co/joyce8/EMBER2024-benchmark-models)
- The original EMBER (2018) is an open dataset and LightGBM baseline for static PE classification. It is superseded by EMBER2024 for current work. — [arXiv 1804.04637](https://arxiv.org/pdf/1804.04637)

### Inferences
- A suggested engine design:
  1. Normalize events into an ECS-like schema.
  2. Compile Sigma rules into an internal AST, indexed by event type so each event is checked only against relevant rules. Fibratus's discarding of unscoped rules shows why the index matters.
  3. Run a separate sequence engine with per-key partial-match tables, a TTL equal to maxspan, and eviction on process exit and on a memory cap.
  4. Run YARA asynchronously in a worker pool: on file create/write-close (from the minifilter or Kernel-File), and on memory regions flagged by TI or call-stack anomalies.
  5. Use static ML (a LightGBM on EMBER v3 features) as a pre-execution verdict, with reputation as an allow-list short-circuit.
- (General knowledge) For reputation:
  - Authenticode signer: `WinVerifyTrust`, catalog lookups through `CryptCATAdmin*`
  - prevalence counts kept on the server
  - Mark-of-the-Web / `Zone.Identifier`, which Sysmon EID 15 captures

### Gaps
- No primary-source description of commercial reputation and prevalence systems was retrieved.
- EMBER2024 licensing and LightGBM baseline metrics were not on the abstract page.

---

## 5. Response actions: kill/suspend, quarantine, isolation, live response, rollback

### Takeaway
Host isolation is implemented with WFP filters: Fibratus does this, and MDE's "contain" depends on the BFE service. The filters must use maximum weight, the hard-action flag and/or a terminating callout, with exceptions for the agent's own backend, because EDRSilencer-style tools add higher-weight WFP filters to cut the agent off. Without a driver, IPsec policy (Velociraptor) or the firewall API also works. Ransomware rollback uses VSS snapshots, which the agent takes and protects (SentinelOne). MDE's response set is the reference feature list.

### Cited Findings
- **MDE response actions:**
  - isolate (full or selective; keeps the Defender service connection; auto-released after 7 days; offline devices retried for 3 days)
  - restrict app execution (a code integrity policy allowing only Microsoft-signed binaries)
  - AV scan
  - collect investigation package
  - live response
  - contain device (requires BFE; recommended limit of 100 devices)
  - stop and quarantine file

  Linux isolation uses iptables, and an admin change to those rules releases isolation. Full-tunnel VPNs and PAC/WPAD proxies can break recovery from isolation. — [MS Learn MDE response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- **WFP for EDRs:**
  - Filters have conditions, an action (permit/block/callout) and a weight.
  - Sublayers have weights; within a sublayer, the first definitive match wins.
  - A block in any sublayer overrides permits; the order is hard block > hard permit > soft block > soft permit.
  - A terminating callout gives a verdict that cannot be overridden.
  - Relevant flags: `FWPM_FILTER_FLAG_PERSISTENT`, `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`.

  EDRs use permit rules for cloud connectivity and high-precedence block rules for isolation. — [SCRT, Aug 25 2025](https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/)
- **SCRT recommendations against WFP blinding:**
  - use maximum weight plus the hard-action flag plus terminating callouts
  - audit WFP changes through Security events 5446 (callout), 5447 (filter), 5448 (provider), 5449 (provider context) and 5450 (sublayer)
  - regularly compare filters against a known-good baseline
  - test outbound connectivity while isolated

  Some EDRs have already moved to max weight and hard actions. — [SCRT](https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/)
- Fibratus's `isolate` action configures WFP firewall policy. — [Fibratus docs](https://docs.fibratus.io/rules/actions/isolate)
- Velociraptor isolates with IPsec policy; see section 3. — [Velociraptor](https://docs.velociraptor.app/artifact_references/pages/windows.remediation.quarantine/)
- **SentinelOne rollback:**
  - The agent acts as a VSS requestor, taking snapshots every 4 hours by default plus one right after install.
  - It blocks VSS tampering.
  - It can restore only files that were in a snapshot.
  - It can fall back to "ApplicationRollback" snapshots taken by other programs.

  — [CyberVigilance (partner blog)](https://www.cybervigilance.uk/post/sentinelone-how-does-rollback-work)
- Wazuh Active Response can block a connection, stop a process or delete a file, and supports custom responses. — [Wazuh docs](https://documentation.wazuh.com/current/getting-started/components/wazuh-agent.html)

### Inferences
- (General knowledge) Implementation primitives:
  - **Kill:** `OpenProcess(PROCESS_TERMINATE)` + `TerminateProcess`. For PPL or protected targets, use a kernel `ZwTerminateProcess` from the driver.
  - **Suspend:** `NtSuspendProcess`, or freeze the process tree before killing it so children cannot respawn.
  - **Quarantine:** while holding an exclusive handle, encrypt the file (for example AES-GCM or XOR with a per-file key) into an ACL-locked vault directory, store metadata (original path, hash, ACL, ADS) in a DB, then delete the original. This prevents accidental execution.
  - **Isolation:** with a driver, use `FwpmEngineOpen0` → `FwpmTransactionBegin0` → provider/sublayer with max weight → block filters at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6` and `FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4/V6`, with permit exceptions for the agent's own image path (app-ID condition) and backend IPs. Without a driver, the `INetFwPolicy2` COM API works, but it is weaker against tampering.
- **Live response:** a server-initiated command channel over the agent's existing mTLS connection. Commands must be signed and audited. High-value assets should allow restriction, as in MDE.

### Gaps
- No primary vendor documentation of quarantine file formats was retrieved.
- The rollback description comes from a partner blog, not SentinelOne's own documentation.

---

## 6. Tamper protection with and without a driver

### Takeaway
With ELAM, the strongest option is to run the agent service as AM-PPL: admins cannot stop it, inject into it or write to its memory, and every loaded DLL must carry the vendor's signature. A driver adds `ObRegisterCallbacks` handle-access stripping, registry and minifilter protection of the agent's own keys and files, and WFP rule protection. Without a driver, the agent relies on service DACLs, file/registry ACLs, a watchdog, monitoring of its own configuration, and server-side detection of missing heartbeats. All of these are defeatable by an admin, so the heartbeat is what makes tampering detectable.

### Cited Findings
- **What AM-PPL prevents:**
  - non-protected processes, admins included, cannot inject or write memory
  - they cannot stop the service
  - only the service itself can remove its protection
  - only a few SC commands are allowed: `config start=Auto`, `qc`, `start`, `interrogate`, `sdshow`
  - updates require the service to stop itself on request

  — [MS Learn](https://learn.microsoft.com/en-us/windows/win32/services/protecting-anti-malware-services-)
- The Sysmon service runs as a protected process. — [MS Learn Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- **MDE tamper protection:**
  - protects real-time protection, cloud protection, security intelligence updates, automatic actions, archive scanning and exclusions
  - changes may appear to succeed but are not applied; GPO changes are ignored
  - a "troubleshooting mode" can disable it temporarily and reverts changes afterwards
  - tampering attempts raise alerts
  - status via `Get-MpComputerStatus` → `IsTamperProtected`

  — [MS Learn Tamper protection](https://learn.microsoft.com/en-us/defender-endpoint/prevent-changes-to-security-settings-with-tamper-protection)
- OpenEDR includes a kernel "self-protection provider" that prevents "EDR components and configuration from unauthorized changes". — [OpenEDR README](https://github.com/ComodoSecurity/openedr)
- WatchGuard uses token-protected uninstallers that limit removal to authorized processes, and installer config backup and restore. — [WatchGuard](https://www.watchguard.com/wgrd-trust-center/microsoft-amdr-safe-deployment-practices)
- Attackers add WFP filters to block EDR cloud traffic (EDRSilencer). Defences: max-weight hard-permit rules for the agent, monitoring Security events 5446-5450, and baseline diffing. — [SCRT](https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/)
- An admin can toggle AMSI's `FeatureBits`; the OS does not protect it, so the AV must. — [MS Learn IAntimalwareProvider](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)
- Microsoft considers admin-to-PPL a non-enforceable boundary (MSRC response). — [Origin HQ](https://www.originhq.com/research/securitytrace-etw-ppl)
- Anti-tamper protection for security products was a named topic at Microsoft's Sep 2024 summit on the future platform. — [Digital Trends via Yahoo](https://tech.yahoo.com/computing/articles/windows-still-making-changes-prevent-202711957.html)

### Inferences
- **No-driver checklist (general knowledge):**
  - Set the service DACL with `SetServiceObjectSecurity` to deny `SERVICE_STOP`, `SERVICE_CHANGE_CONFIG` and `DELETE` to Administrators, leaving them only to SYSTEM. Admins can still take ownership, so this only raises the bar.
  - Set `SERVICE_CONFIG_FAILURE_ACTIONS` to restart the service.
  - Use a mutual watchdog: two processes, or a service plus a scheduled task.
  - Lock down ACLs on the install and config directories.
  - Sign config files and policies, and verify them on load.
  - Run an ETW session watchdog: re-enable sessions killed with `ControlTrace(STOP)` and detect provider disablement through `EVENT_TRACE_CONTROL_QUERY`.
  - Self-check for ntdll/ETW patching in the agent's own process.
  - Send heartbeats with a sequence number and an event-count summary, so the server can alert on gaps or sudden drops in event volume.
  - Use an uninstall token or password checked by the agent before it accepts a stop request.
- **With a driver:**
  - `ObRegisterCallbacks` on `PsProcessType`/`PsThreadType` strips `PROCESS_TERMINATE`, `PROCESS_VM_WRITE`, `PROCESS_VM_OPERATION`, `PROCESS_CREATE_THREAD` and `PROCESS_SUSPEND_RESUME` from handles to agent PIDs.
  - The minifilter denies write/delete on agent files.
  - `CmRegisterCallbackEx` denies changes to the agent's service key.
  - Block or alert on vulnerable-driver loads (BYOVD) through the image-load callback plus the Microsoft vulnerable driver blocklist.

### Gaps
- No public primary source was found on how commercial EDRs implement heartbeat-based tamper detection server-side; only general practice is available.

---

## 7. Performance: ETW buffer loss, event volume, kernel vs user filtering, local storage, batching

### Takeaway
ETW drops events when consumers fall behind. Real-time sessions should size buffers with `MinimumBuffers = MaximumBuffers`, use `BufferSize` ≤ 64 KB, set `FlushTimer` around 1-10 s, and monitor `EventsLost` / `RealTimeBuffersLost` with `ControlTrace(EVENT_TRACE_CONTROL_QUERY)`. The consumer callback should only enqueue events; parsing happens on other threads. Volume control happens in layers:

1. filter in the kernel or at ETW enable time (keywords/levels, event-ID filters);
2. deduplicate and aggregate on the host (Elastic, Sealighter);
3. evaluate high-volume events locally but do not ship them;
4. on the server side, accept that a selective-capture EDR is not a full audit log.

### Cited Findings
- **EVENT_TRACE_PROPERTIES:**
  - **BufferSize:** 4 KB to 16 MB (1 MB before Windows 8). "Most trace sessions should use a buffer size of 64KB or less." ETW cannot collect events larger than 64 KB. Do not use BufferSize to control memory.
  - **MinimumBuffers:** at least 2 per logical processor unless `EVENT_TRACE_NO_PER_PROCESSOR_BUFFERING` is set. Start tuning by setting MinimumBuffers = MaximumBuffers.
  - **High-IRQL providers:** buffers cannot be allocated on demand, so they may need a higher minimum.
  - **FlushTimer:** for real-time sessions, 0 means 1 s; "most real-time traces should start with a timer of 5 or 10 seconds."
  - **Loss counters:** `EventsLost`, `RealTimeBuffersLost` and `LogBuffersLost`, readable while the session runs through `ControlTrace(EVENT_TRACE_CONTROL_QUERY)`.
  - **EnableFlags:** valid only for system-logger sessions (`EVENT_TRACE_SYSTEM_LOGGER_MODE`, `KERNEL_LOGGER_NAME`).

  — [MS Learn EVENT_TRACE_PROPERTIES](https://learn.microsoft.com/en-us/windows/win32/api/evntrace/ns-evntrace-event_trace_properties)
- Microsoft's xperf guidance has a page on "Avoiding Lost Buffers" (older, superseded WPT docs). — [MS Docs Avoiding Lost Buffers](https://msdn.microsoft.com/en-us/library/ff190866(v=vs.85))
- In krabsetw, throwing in the event callback stops the trace, and `start()` blocks, so thread management is the caller's job. — [krabsetw README](https://github.com/microsoft/krabsetw)
- Velociraptor's `enable_map_info` is "very expensive and causes events to be dropped". Its Kernel-Process artifact uses a 3-second `delay()` so process-tracker enrichment can catch up. — [Velociraptor watch_etw](https://docs.velociraptor.app/vql_reference/event/watch_etw/), [Windows.ETW.KernelProcess](https://docs.velociraptor.app/artifact_references/pages/windows.etw.kernelprocess)
- Elastic fingerprints and deduplicates API events, keeps the most verbose ones local by default, and offers an opt-in policy to stream them. — [Elastic Security Labs](https://www.elastic.co/security-labs/doubling-down-etw-callstacks)
- Elastic Defend "is not designed to provide a complete capture of all system events." Other volume choices:
  - file events are aggregated, truncated or deduplicated
  - driver loads are scanned but produce no per-load event
  - only TCP is tracked, and no event is raised for ports without traffic
  - logon and logoff events are mostly not captured

  Elastic recommends Sysmon or Winlogbeat for full capture. — [Elastic Defend event capture](https://www.elastic.co/guide/en/security/8.19/endpoint-event-capture.html)
- Sealighter can buffer many events within a time period into a single event with a count, and can cap the number of events per ID. — [Sealighter README](https://github.com/pathtofile/Sealighter)
- Wazuh stores inventory in local SQLite databases. Its agent channel uses encryption, compression, flow control and queuing to avoid flooding. — [Wazuh docs](https://documentation.wazuh.com/current/getting-started/components/wazuh-agent.html)
- OpenEDR "records all telemetry information locally" and then ships it to Elasticsearch. — [OpenEDR README](https://github.com/ComodoSecurity/openedr)
- Running fully in user mode costs both latency and capability. Yosifovich: the agent learns of a process only after it starts. ESET: slowed-down protections get disabled by customers, which is "a degradation of security." — [Cybersecurity Dive, Mar 2026](https://www.cybersecuritydive.com/news/microsoft-windows-resilience-initiative-security-kernel/813416/)
- ELAM drivers have hard budgets: 0.5 ms per driver, 50 ms in total, 128 KB of memory. — [MS Learn ELAM requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-driver-requirements)

### Inferences
- **Pipeline design (general knowledge plus the findings above):**
  1. The ETW callback copies the raw record into a lock-free MPSC ring buffer and returns.
  2. Parser and enrichment workers (TDH or pre-compiled schemas; avoid per-event `TdhGetEventInformation` calls by caching on provider + event ID + version) feed the rule engine.
  3. A writer persists events to a local store: SQLite in WAL mode, or a segmented append-only log with size and age caps.
  4. A shipper sends batches (by size or time, e.g. 1-5 s) with zstd/gzip compression over gRPC/HTTP2 + mTLS, with backpressure and disk spill while offline.
- Set ETW keywords narrowly when enabling providers, and use `EnableTraceEx2` with `ENABLE_TRACE_PARAMETERS` event-ID filters (`EVENT_FILTER_TYPE_EVENT_ID`) to drop events before they reach the session. Watch the loss counters and report them in heartbeats.
- File I/O and registry are the highest-volume categories. A minifilter (pre-filtering by path or extension in kernel) or Kernel-File with tight keywords is far cheaper than consuming all FileIO from the NT Kernel Logger.

### Gaps
- No published per-provider event-rate benchmarks for EDR workloads were found.
- No primary source detailing the local storage engines used by commercial EDRs (e.g. MDE, CrowdStrike) was found.
