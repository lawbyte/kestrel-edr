# SigmaHQ fit for Kestrel and how user-mode peers cover general malware

*Research notes, 2026-10-21. Scope: (1) which SigmaHQ rules fit Kestrel's telemetry, with a curated audit pack, and (2) how Fibratus, Nextron Aurora, Velociraptor, Elastic Defend, Rustinel and Wazuh cover ransomware, credential dumping, persistence and LOLBins. Licences are noted for each peer: they decide what Kestrel may reuse.*

**How I checked things.** I verified rule ids, titles, status and level against a shallow clone of `SigmaHQ/sigma` at commit `e3f466211866e92553d8389d621ed13cfed5523d` (2026-10-20). I did not rely on memory. Every rule URL below is pinned to that commit. I also built a scratch harness that runs every SigmaHQ Windows rule through Kestrel's own `kestrel_detect::validate_sigma`, which is rsigma 0.25.0 plus Kestrel's category router. I spot-checked one rule on detection.fyi and it matched. That site does not mirror every rule path one-to-one: `proc_creation_win_susp_shadow_copies_deletion` returned a 404 there, but it exists on GitHub. Items marked **[unverified]** were not confirmed from a primary source.

---

## 1. SigmaHQ repository: structure, counts, licence

### 1.1 Layout (commit e3f4662, 2026-10-20)

* The latest tagged release is `r2026-07-01`, published 2026-07-09 ([GitHub API](https://api.github.com/repos/SigmaHQ/sigma/releases/latest)).
* Top-level rule trees:
  * `rules/`: 3,159 core detection rules.
  * `rules-emerging-threats/`: 474 rules tied to specific campaigns and CVEs, organised by year. They age quickly.
  * `rules-threat-hunting/`: 140 broad hunting rules. They are not meant for alerting.
  * `rules-compliance/`, `rules-dfir/`, `rules-placeholder/` (needs `|expand` placeholders), `deprecated/`, `unsupported/`.
  * `regression_data/`: sample events for rule regression tests. These are useful for Kestrel's tests.
* `rules/windows/` holds 2,424 rules. Per logsource folder:

| Folder (Sigma category) | Rules | Kestrel route (sigma.rs) |
|---|---:|---|
| `process_creation` | 1,192 | `process_start`. **Good fit** |
| `registry/registry_set` | 206 (207 on the `category` line) | `registry_set`, partial (key allow-list, DWORD format; see §2) |
| `registry/registry_event` | 33 | `registry_set`, partial |
| `registry/registry_add`, `registry_delete` | 1, 10 | not routed |
| `file/file_event` | 167 | `file_access` create/write/rename, partial (sensitive paths only) |
| `file/file_access`, `file_delete`, `file_rename` | 7, 12, 1 | partial |
| `image_load` | 100 | partial (System32/Program Files DLLs dropped unless they are on `INTERESTING_DLLS`) |
| `network_connection` | 51 | `net_connect`, good (`DestinationHostname` comes from DNS correlation, best effort) |
| `dns_query` | 22 | `dns_query`, good |
| `process_access` | 23 | partial (desired access, no `CallTrace`) |
| `create_remote_thread` | 11 | partial (no `StartModule`/`StartFunction`/`StartAddress`) |
| `powershell/powershell_script` (`ps_script`) | 165 | `script_block`, good if Script Block Logging is enabled |
| `powershell/powershell_module`, `powershell_classic` | 33, 13 | not routed |
| `pipe_created` | 17 | none (no ETW source; see §2.3) |
| `driver_load` | 10 | none |
| `wmi_event` | 3 | none |
| `create_stream_hash`, `raw_access_thread`, `process_tampering`, `sysmon` | 9, 1, 1, 6 | none |
| `builtin/*` (Security, System, Defender… `service:` logsources, no `category`) | ~240 | none; Kestrel requires `logsource.category` |

* Status across the 2,424 `rules/windows` rules: `test` 2,192, `experimental` 178, `stable` 54. Very few rules are `stable`, so requiring "stable only" would leave almost nothing. Use `test` plus `level: high/critical` as the default bar.
* `process_creation` levels: 24 critical, 592 high, ~516 medium, 59 low, 1 informational. Status: 20 stable, 1,075 test, 97 experimental.
* `registry_set`: 112 high, ~85 medium. `ps_script`: 2 critical, 52 high, 91 medium, 20 low. `process_access`: 18 high.

### 1.2 Compile check against Kestrel (measured)

The scratch harness loaded every `rules/windows/**/*.yml` through `kestrel_detect::validate_sigma`:

* **All 1,990 rules in the categories Kestrel routes compile without error.** That is process_creation 1,192, registry_set 207, registry_event 32, file_event 167, image_load 100, ps_script 165, network_connection 51, process_access 23, dns_query 22, file_delete 12, create_remote_thread 11, file_access 7 and file_rename 1.
* Every failure was a routing rejection, not a parse failure:
  * 335 rules have no `category` (`builtin` service logsources);
  * the rest are in pipe_created, driver_load, ps_module, ps_classic, registry_add/delete, wmi_event, create_stream_hash and similar.
* Parse and compile of 2,424 files took about 0.3 s (release build).
* Compiling is not the same as firing. A rule that requires a field Kestrel never fills (`CallTrace`, `ParentUser`, `StartModule`, `Company`…) loads fine and never matches. Rustinel built a `sigma doctor` command to report exactly this ([Rustinel coverage](https://github.com/karib0u/rustinel/blob/main/docs/coverage.md)). Kestrel should do the same (see §5).

### 1.3 Licence: Detection Rule License 1.1, exact obligations

The SigmaHQ `LICENSE` file says: *"The rules contained in the SigmaHQ repository … are released under the Detection Rule License (DRL) 1.1"*. Source: [SigmaHQ LICENSE](https://github.com/SigmaHQ/sigma/blob/master/LICENSE), text at [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License/blob/main/LICENSE.Detection.Rules.md).

* **Sharing the rules** (for example, shipping the YAML in the agent or MSI, or serving it from the server):
  * Keep the rule's `author` field, and any others designated to receive attribution, in any reasonable form the author asks for.
  * Keep a URI to the rule set or the specific rule, "to the extent reasonably practicable".
  * Indicate that the rules are licensed under DRL 1.1, and include the licence text or a link to it.
* **Using the rules on data**, which is what Kestrel's alerts do: *"messages based on matches with the Rules must retain"* the author identification "if it is supplied within the Rules". For match messages the licence lists only the author attribution. It does not require the rule id or the licence link there.
* **What this means for Kestrel:**
  * Every alert or alert view from a SigmaHQ rule must show `author` verbatim. `SigmaRuleInfo.author` already carries it into `RuleMeta.author` (sigma.rs `compile_bundle`).
  * For the shipped pack, also keep the YAML unmodified (or record modifications), keep `id`, the GitHub URL and `references`, and add a `NOTICE`/licence link (DRL 1.1) in the rule catalog view and in the repo.
  * Showing the rule URL and "DRL 1.1" next to the author in the alert view is cheap and goes beyond the minimum. Recommended.
* DRL is not GPL-family and does not conflict with `deny.toml`. It is a rule-content licence, so the obligations attach to the rule content, not to Kestrel's code.
* SigmaHQ YAML files carry no `license:` field (grep found 0). The licence comes from the repo, so Kestrel must attach "DRL-1.1" itself when importing.

---

## 2. Field mapping: Sysmon schema vs Kestrel

### 2.1 What Kestrel provides (from `crates/kestrel-detect/src/sigma.rs`)

`Image`, `CommandLine`, `OriginalFileName`*, `ParentImage`, `ParentCommandLine`, `User`, `IntegrityLevel`, `ProcessId`, `ParentProcessId`, `ProcessGuid`, `Hashes` (`SHA256=` only), `sha256`, `Signed`, `Signature`, `SignatureStatus`, `TargetFilename`, `DestinationIp/Port/Hostname`, `SourcePort`, `Protocol`, `Initiated`, `QueryName`, `QueryResults`, `TargetObject`, `Details`, `EventType`, `GrantedAccess`, `SourceImage`, `TargetImage`, `TargetProcessId`, `ImageLoaded`, `ScriptBlockText`.

### 2.2 Mapping gaps that change rule behaviour (measured on the SigmaHQ corpus)

| Gap | SigmaHQ rules affected | Effect | Fix |
|---|---|---|---|
| `OriginalFileName` is **the Image file name**, not the PE VERSIONINFO OriginalFilename | 587 process_creation rules use it | Fine in `Image\|endswith OR OriginalFileName` selections. The 36 `*_renamed_*` rules can never fire, and some values differ: pwsh's OriginalFileName is `pwsh.dll`, so `OriginalFileName: pwsh.dll` misses unless `Image\|endswith pwsh.exe` is also present. | Read VS_VERSIONINFO OriginalFilename/Company/Product/Description during enrichment (the hash/signer cache already opens the file). This unlocks renamed-binary detection, a top ransomware/LOLBin tactic. |
| No `Company`/`Product`/`Description` | 92 process_creation rules | Usually in OR with `Image` (harmless), sometimes in filters, where the filter never applies and FPs go up | Same PE version-resource enrichment |
| `Hashes` only `SHA256=` | 32 rules use `IMPHASH=` | HackTool imphash rules are dead | Optional imphash in enrichment (pure-Rust PE parse) |
| No `ParentUser`, `CurrentDirectory`, `LogonId`, `TerminalSessionId` | 3, 8, 2, 0 | Rules that need them never fire (e.g. `9a4ccd1a` WER LSASS shtinkering) | `ParentUser` is cheap (parent's `user` from the process table); `CurrentDirectory` needs PEB reads (skip) |
| `ParentImage` missing when the parent predates the agent or exited | 246 rules use it | A `not filter` on ParentImage passes, so FPs go **up**; positive ParentImage selections miss | Seed the process table at startup from a snapshot (already partly done via `ensure_known`) |
| **Registry `Details` for DWORD/QWORD rendered as decimal** (`"1"`); Sysmon renders `DWORD (0x00000001)` | 71 of 206 registry_set rules (107 occurrences repo-wide) | **Silent miss** on every "value set to 1/0" tamper rule (Defender, WDigest, LSA, PowerShell logging…) | Render REG_DWORD as `DWORD (0x%08x)` and REG_QWORD as `QWORD (0x%08x-0x%08x)` in the Sigma view (keep the raw value for builtin rules). Sysmon's binary format is `Binary Data`. |
| Registry keys are an **allow-list** (`etwparse::is_interesting_reg_key`): Run/RunOnce, RunMRU, TypedPaths, Policies\Explorer, AMSI, IFEO, Defender\Exclusions, KestrelAgent service | all registry rules outside it | Rules on `Policies\Microsoft\Windows Defender\*`, `Control\SecurityProviders\WDigest`, `Services\*\ImagePath`, `SilentProcessExit`, `Classes\CLSID`, `Winlogon`, `PowerShell\ScriptBlockLogging`, `SystemRestore`, `WMI\Autologger` never see events | Extend the allow-list (§3.3, Tier C) |
| Key prefix: Kestrel normalises `\REGISTRY\MACHINE` to `HKLM` and `\REGISTRY\USER` to `HKU` | matches Sysmon | Good. Rustinel keeps NT paths and documents the resulting `startswith: HKLM` misses ([Rustinel limitations](https://github.com/karib0u/rustinel/blob/main/docs/limitations.md)). HKCU appears as `HKU\<SID>\…`, same as Sysmon. | none |
| `GrantedAccess` is the **DesiredAccess** from Kernel-Audit-API-Calls (`consts.rs` `DESIRED_ACCESS`), not the granted mask | all 23 process_access rules | Usually the same for a successful open. It differs for `MAXIMUM_ALLOWED` (0x02000000) and for failed opens (`ReturnCode != 0`). Rustinel says Audit-API-Calls "does not carry `GrantedAccess`" and true granted access needs the Threat-Intelligence provider (PPL) ([Rustinel limitations](https://github.com/karib0u/rustinel/blob/main/docs/limitations.md)). | Drop or flag events with a failing ReturnCode before Sigma; document it as "requested access" |
| No `CallTrace` | 17 rules (`process_access` mostly) | LSASS rules keyed on `dbghelp`/`comsvcs`/`UNKNOWN(` in CallTrace never fire. Filters on CallTrace never apply, so FPs go up. | Possible without a driver: ETW stack-walk on the Audit-API-Calls session (`EVENT_ENABLE_PROPERTY_STACK_TRACE`), which Fibratus uses for `thread.callstack.*` ([Fibratus rule](https://github.com/rabbitstack/fibratus/blob/master/rules/credential_access_lsass_memory_dump_via_minidumpwritedump.yml)). **[unverified cost on Kestrel]** |
| No `StartModule`/`StartFunction`/`StartAddress` on remote threads | 4 of 11 create_remote_thread rules | `f239b326` (stable, `StartModule: ''`) can't fire | Resolve the start address against the target's module list (costly). Skip in v1. |
| `file_event` only for `may_be_sensitive` paths (browser and credential stores, canaries) | most of the 167 file_event rules | Dump-file, startup-folder and dropped-tool rules never see events | Add a small second path set: `*.dmp` anywhere, `\Start Menu\Programs\Startup\`, `\Windows\Tasks\`, `\System32\Tasks\`, ransom-note names. That is still bounded. |
| `image_load` drops System32/Program Files DLLs unless they are on `INTERESTING_DLLS` | ~100 rules | `vssapi.dll`, `clr.dll`, `System.Management.Automation.dll`, `comsvcs.dll` rules are blind | Add `vssapi.dll`, `vss_ps.dll`, `comsvcs.dll`, `clr.dll`, `clrjit.dll`, `system.management.automation.dll`, `amsi.dll` to `INTERESTING_DLLS`, at a volume cost |

### 2.3 Categories with no ETW source (do not route)

* **pipe_created:**
  * Nextron says "There is no ETW provider that provides information about creation of or connection to named pipes"; only the very noisy Kernel Object Handle provider or polling remain ([Aurora manual §15.1](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/detection-gaps.html)).
  * Rustinel agrees: "named-pipe activity is not carried by Microsoft-Windows-Kernel-File" ([Rustinel field availability](https://github.com/karib0u/rustinel/blob/main/docs/field-availability.md)).
* **process_tampering:** needs the Microsoft-Windows-Threat-Intelligence provider, which is PPL-only ([Rustinel coverage](https://github.com/karib0u/rustinel/blob/main/docs/coverage.md)).
* **driver_load:** possible from Kernel-Process image loads where the image is `.sys`. 10 rules; low priority.
* **wmi_event:** possible from Microsoft-Windows-WMI-Activity (5861), as Rustinel does. 3 rules; low priority.

---

## 3. Proposed "Kestrel SigmaHQ Audit pack"

**Selection rules.**
* `status: stable/test` and `level: high/critical`. A few `medium` and `experimental` rules are allowed in Tier B with a reason.
* Behaviour-based: command-line or API patterns, not tool names or hashes.
* No dependence on fields Kestrel lacks, except inside OR-branches where another branch carries the match.
* Every Tier A and Tier B rule compiled with Kestrel's `validate_sigma` (harness output: "PACK OK" for all 91 ids listed in §3.1 to §3.3).
* Ship everything in **Audit** mode. Promote nothing to Protect without a benign baseline (§5).

**URL base** for every row: `https://github.com/SigmaHQ/sigma/blob/e3f466211866e92553d8389d621ed13cfed5523d/` + path. The path is shown abbreviated as `pc/` (= `rules/windows/process_creation/`), `ps/` (= `rules/windows/powershell/powershell_script/`), `pa/` (= `rules/windows/process_access/`), `rs/` (= `rules/windows/registry/registry_set/`), `re/` (= `rules/windows/registry/registry_event/`), `il/` (= `rules/windows/image_load/`), `nc/` (= `rules/windows/network_connection/`), `dq/` (= `rules/windows/dns_query/`), `fe/` (= `rules/windows/file/file_event/`), `crt/` (= `rules/windows/create_remote_thread/`).

### 3.1 Tier A: fits Kestrel today (70 rules)

#### Ransomware and recovery inhibition (T1490/T1489/T1070)

| UUID | Title | Category | Status/Level | Why it fits | Mapping notes | Path |
|---|---|---|---|---|---|---|
| c947b146-0abc-4c87-9c64-b17e9d7274a2 | Shadow Copies Deletion Using Operating Systems Utilities | process_creation | stable/high | vssadmin/wmic/diskshadow/wbadmin delete shadows; near-universal ransomware step | `Image\|endswith OR OriginalFileName`; fine | pc/proc_creation_win_susp_shadow_copies_deletion.yml |
| 21ff4ca9-f13a-41ad-b828-0077b2af2e40 | Deletion of Volume Shadow Copies via WMI with PowerShell | process_creation | test/high | Get-WmiObject Win32_Shadowcopy \| Remove | CommandLine only | pc/proc_creation_win_powershell_shadowcopy_deletion.yml |
| c1337eb8-921a-4b59-855b-4ba188ddcc42 | Deletion of Volume Shadow Copies via WMI with PowerShell - PS Script | ps_script | test/high | Same, in script-block content (catches obfuscated launchers) | needs 4104 logging | ps/posh_ps_susp_win32_shadowcopy_deletion.yml |
| 1444443e-6757-43e4-9ea4-c8fc705f79a2 | Boot Configuration Tampering Via Bcdedit.EXE | process_creation | stable/high | `recoveryenabled no` / `bootstatuspolicy ignoreallfailures` | fine | pc/proc_creation_win_bcdedit_boot_conf_tamper.yml |
| 639c9081-f482-47d3-a0bd-ddee3d4ecd76 | All Backups Deleted Via Wbadmin.EXE | process_creation | test/high | `wbadmin delete catalog/systemstatebackup` | fine | pc/proc_creation_win_wbadmin_delete_all_backups.yml |
| dee4af55-1f22-4e1d-a9d2-4bdc7ecb472a | Disabled Volume Snapshots | process_creation | test/high | reg.exe disabling VSS | CommandLine only | pc/proc_creation_win_reg_volsnap_disable.yml |
| add64136-62e5-48ea-807e-88638d02df1e | Fsutil Suspicious Invocation | process_creation | stable/high | `fsutil usn deletejournal` / `setZeroData` | fine | pc/proc_creation_win_fsutil_usage.yml |
| ce72ef99-22f1-43d4-8695-419dcb5d9330 | Suspicious Windows Service Tampering | process_creation | test/high | Mass `net stop`/`sc stop` of backup, SQL and AV services before encryption | FP: admin maintenance scripts. Pair with an RW correlation. | pc/proc_creation_win_susp_service_tamper.yml |
| e37db05d-d1f9-49c8-b464-cee1a4b11638 | PUA - Rclone Execution | process_creation | test/high | Double-extortion exfil tool | `Description` in OR branch is unused; Image/CommandLine branches work | pc/proc_creation_win_pua_rclone_execution.yml |
| cc36992a-4671-4f21-a91d-6c2b72a2edf5 | Suspicious Eventlog Clearing or Configuration Change Activity | process_creation | stable/high | `wevtutil cl`, `Clear-EventLog`, `Limit-EventLog` | ParentImage used in a filter, so FP risk if the parent is unknown | pc/proc_creation_win_susp_eventlog_clear.yml |

#### Credential dumping (T1003)

| UUID | Title | Category | Status/Level | Why | Mapping notes | Path |
|---|---|---|---|---|---|---|
| 646ea171-dded-4578-8a4d-65e9822892e3 | Process Memory Dump Via Comsvcs.DLL | process_creation | test/high | `rundll32 comsvcs.dll,MiniDump` (incl. ordinal #24) | fine; verified also on [detection.fyi](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs/) | pc/proc_creation_win_rundll32_process_dump_via_comsvcs.yml |
| 5afee48e-67dd-4e03-a783-f74259dcf998 | Potential LSASS Process Dump Via Procdump | process_creation | stable/high | `procdump -ma lsass` | uses `\|windash` (supported) | pc/proc_creation_win_sysinternals_procdump_lsass.yml |
| fd877b94-9bb5-4191-bb25-d79cbd93c167 | Dumping of Sensitive Hives Via Reg.EXE | process_creation | test/high | `reg save HKLM\SAM/SYSTEM/SECURITY` | fine | pc/proc_creation_win_reg_dumping_sensitive_hives.yml |
| ffa6861c-4461-4f59-8a41-578c39f3f23e | LSASS Dump Keyword In CommandLine | process_creation | test/high | Generic `lsass.dmp` / dumper keywords | CommandLine only | pc/proc_creation_win_susp_lsass_dmp_cli_keywords.yml |
| e7be6119-fc37-43f0-ad4f-1f3f99be2f9f | Copying Sensitive Files with Credential Data | process_creation | test/high | esentutl/vss copy of SAM/NTDS | fine | pc/proc_creation_win_esentutl_sensitive_file_copy.yml |
| c73124a7-3e89-44a3-bdc1-25fe4df754b1 | Copy From VolumeShadowCopy Via Cmd.EXE | process_creation | test/high | `copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy` | CommandLine only | pc/proc_creation_win_cmd_shadowcopy_access.yml |
| 8bc64091-6875-4881-aaf9-7bd25b5dda08 | Suspicious Process Patterns NTDS.DIT Exfil | process_creation | test/high | ntdsutil IFM, NTDS copy | ParentImage branch conditional | pc/proc_creation_win_susp_ntds.yml |
| a642964e-bead-4bed-8910-1bb4d63e3b4d | HackTool - Mimikatz Execution | process_creation | test/high | Mimikatz module keywords on the command line (survives renaming) | CommandLine only | pc/proc_creation_win_hktl_mimikatz_command_line.yml |
| 515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48 | CreateDump Process Dump | process_creation | test/high | .NET createdump.exe LOLBin | fine | pc/proc_creation_win_createdump_lolbin_execution.yml |
| edadb1e5-5919-4e4c-8462-a9e643b02c4b | Process Memory Dump via RdrLeakDiag.EXE | process_creation | test/high | LOLBin dumper | windash | pc/proc_creation_win_rdrleakdiag_process_dumping.yml |
| 1af57a4b-460a-4738-9034-db68b880c665 | PowerShell SAM Copy | process_creation | test/high | VSS SAM copy via PowerShell | CommandLine only | pc/proc_creation_win_powershell_sam_access.yml |
| b2815d0d-7481-4bf0-9b6c-a4c48a94b349 | PowerShell Get-Process LSASS | process_creation | test/high | Precursor of PowerShell MiniDump | CommandLine only | pc/proc_creation_win_powershell_getprocess_lsass.yml |
| 84c174ab-d3ef-481f-9c86-a50d0b8e3edb | PowerShell Get-Process LSASS in ScriptBlock | ps_script | test/high | Same in 4104 | 4104 | ps/posh_ps_susp_getprocess_lsass.yml |
| 189e3b02-82b2-4b90-9662-411eb64486d4 | Potential Invoke-Mimikatz PowerShell Script | ps_script | test/high | In-memory Mimikatz | 4104 | ps/posh_ps_potential_invoke_mimikatz.yml |
| 9bd012ee-0dff-44d7-84a0-aa698cfd87a3 | LSASS Memory Access by Tool With Dump Keyword In Name | process_access | test/high | Any `*dump*` binary opening lsass with VM_READ-class rights | `GrantedAccess\|endswith` against Kestrel's `0x…` lowercase hex: Sigma matching is case-insensitive, so this works. Value is *desired* access. | pa/proc_access_win_lsass_dump_keyword_image.yml |

#### Persistence (T1053/T1543/T1547/T1546)

| UUID | Title | Category | Status/Level | Why | Mapping notes | Path |
|---|---|---|---|---|---|---|
| 39019a4e-317f-4ce3-ae63-309a8c6b53c5 | Suspicious Scheduled Task Creation Involving Temp Folder | process_creation | test/high | `schtasks /create` pointing at %TEMP% | fine | pc/proc_creation_win_schtasks_creation_temp_folder.yml |
| 8a8379b8-780b-4dbf-b1e9-31c8d112fefb | Schtasks From Suspicious Folders | process_creation | test/high | Task action from Public/ProgramData/Temp with a script host | fine | pc/proc_creation_win_schtasks_folder_combos.yml |
| f2c64357-b1d2-41b7-849f-34d2682c0fad | Suspicious Command Patterns In Scheduled Task Creation | process_creation | test/high | Task running encoded PowerShell, mshta, `-w hidden` | fine | pc/proc_creation_win_schtasks_susp_pattern.yml |
| c5c00f49-b3f9-45a6-997e-cfdecc6e1967 | Suspicious Schtasks Execution AppData Folder | process_creation | test/high | SYSTEM task executing from AppData\Local | `ParentImage\|contains\|all` in a filter | pc/proc_creation_win_schtasks_appdata_local_system.yml |
| 17a1be64-8d88-40bf-b5ff-a4f7a50ebcc8 | Suspicious New Service Creation | process_creation | test/high | `sc create`/New-Service with a script host or user-writable binpath | fine | pc/proc_creation_win_susp_service_creation.yml |
| ebef4391-1a81-4761-a40a-1db446c0e625 | NewActiveScriptEventConsumer Creation Attempt via Wmic.EXE | process_creation | test/high | WMI event-subscription persistence (wmi_event itself is unavailable) | fine | pc/proc_creation_win_wmic_eventconsumer_creation.yml |
| b7916c2a-fa2f-4795-9477-32b731f70f11 | Registry Persistence via Explorer Run Key | registry_set | test/high | `Policies\Explorer\Run` pointing to ProgramData/Recycle.bin/Temp | key covered by Kestrel's allow-list (`\currentversion\policies\explorer`); REG_SZ only, so no DWORD issue | rs/registry_set_susp_reg_persist_explorer_run.yml |
| 9c5037d1-c568-49b3-88c7-9846a5bdc2be | Suspicious Run Key from Download | registry_event | test/high | A process in Downloads/Temp writes a Run key: classic first-stage stealer and RAT behaviour | Run keys are in the allow-list; `Image` = the writer process | re/registry_event_susp_download_run_key.yml |

#### LOLBins and execution (T1218/T1105/T1059/T1204)

| UUID | Title | Category | Status/Level | Why | Mapping notes | Path |
|---|---|---|---|---|---|---|
| 13e6fe51-d478-4c7e-b0f2-6da9b400a829 | Suspicious File Downloaded From Direct IP Via Certutil.EXE | process_creation | test/high | certutil `-urlcache`/`-verifyctl` from a raw IP | fine | pc/proc_creation_win_certutil_download_direct_ip.yml |
| 42a5f1e7-9603-4f6d-97ae-3f37d130d794 | Suspicious File Downloaded From File-Sharing Website Via Certutil.EXE | process_creation | test/high | certutil from Discord CDN, transfer.sh, GitHub raw… | fine | pc/proc_creation_win_certutil_download_file_sharing_domains.yml |
| cc9cbe82-7bc0-4ef5-bc23-bbfb83947be7 | File Decoded From Base64/Hex Via Certutil.EXE | process_creation | test/high | `certutil -decode` payload staging | FP: PKI admins; baseline first | pc/proc_creation_win_certutil_decode.yml |
| b98d0db6-511d-45de-ad02-e82a98729620 | Remotely Hosted HTA File Executed Via Mshta.EXE | process_creation | test/high | `mshta http(s)://` (ClickFix and fake-captcha delivery for Lumma and others) | fine | pc/proc_creation_win_mshta_http.yml |
| 67f113fa-e23d-4271-befa-30113b3e08b1 | Suspicious JavaScript Execution Via Mshta.EXE | process_creation | test/high | `mshta javascript:` | fine | pc/proc_creation_win_mshta_javascript.yml |
| e32f92d1-523e-49c3-9374-bdb13b46a3ba | Suspicious Mshta.EXE Execution Patterns | process_creation | test/high | mshta from odd parents and paths | ParentImage conditional | pc/proc_creation_win_mshta_susp_pattern.yml |
| 03cc0c25-389f-4bf8-b48d-11878079f1ca | Suspicious MSHTA Child Process | process_creation | test/high | mshta spawning cmd, powershell, wscript… | needs ParentImage (process table) | pc/proc_creation_win_mshta_susp_child_processes.yml |
| 2dd2c217-bf68-437a-b57c-fe9fd01d5de8 | Potentially Suspicious Regsvr32 HTTP IP Pattern | process_creation | test/high | Squiblydoo (`/i:http… scrobj.dll`) from an IP | fine | pc/proc_creation_win_regsvr32_http_ip_pattern.yml |
| 327ff235-94eb-4f06-b9de-aaee571324be | Regsvr32 Execution From Highly Suspicious Location | process_creation | test/high | regsvr32 of a DLL in Public/Temp/PerfLogs | fine | pc/proc_creation_win_regsvr32_susp_exec_path_2.yml |
| 089fc3d2-71e8-4763-a8a5-c97fbb0a403e | Regsvr32 DLL Execution With Suspicious File Extension | process_creation | test/high | regsvr32 on .jpg/.txt/.bin (Qakbot, IcedID loaders) | fine | pc/proc_creation_win_regsvr32_susp_extensions.yml |
| 4782eb5a-a513-4523-a0ac-f3082b26ac5c | Mshtml.DLL RunHTMLApplication Suspicious Usage | process_creation | test/high | `rundll32 javascript:"\..\mshtml,RunHTMLApplication"` | CommandLine only | pc/proc_creation_win_rundll32_mshtml_runhtmlapplication.yml |
| 5cdb711b-5740-4fb2-ba88-f7945027afac | Rundll32 UNC Path Execution | process_creation | test/high | rundll32 loading a DLL from a WebDAV/SMB share | fine | pc/proc_creation_win_rundll32_unc_path.yml |
| 438025f9-5856-4663-83f7-52f878a70a50 | Suspicious Microsoft Office Child Process | process_creation | test/high | Office spawning script hosts and LOLBins | needs ParentImage | pc/proc_creation_win_office_susp_child_processes.yml |
| 8d63dadf-b91b-4187-87b6-34a1114577ea | Potential Remote SquiblyTwo Technique Execution | process_creation | test/high | `wmic /format:http…xsl` | the `Hashes` IMPHASH branch is OR; Image/CommandLine branches work | pc/proc_creation_win_wmic_squiblytwo_bypass.yml |
| 3c89a1e8-0fba-449e-8f1b-8409d6267ec8 | Suspicious Process Created Via Wmic.EXE | process_creation | test/high | `wmic process call create` with LOLBins | CommandLine only | pc/proc_creation_win_wmic_susp_process_creation.yml |
| 99c840f2-2012-46fd-9141-c761987550ef | Suspicious Download From Direct IP Via Bitsadmin | process_creation | test/high | bitsadmin transfer from a raw IP | fine | pc/proc_creation_win_bitsadmin_download_direct_ip.yml |
| 5cb299fc-5fb1-4d07-b989-0644c68b6043 | Suspicious File Download From IP Via Curl.EXE | process_creation | test/high | curl from a raw IP to a suspicious extension | uses `\|re` (supported) | pc/proc_creation_win_curl_download_direct_ip_susp_extensions.yml |
| e218595b-bbe7-4ee5-8a96-f32a24ad3468 | Suspicious Curl.EXE Download | process_creation | test/high | curl writing .dll/.vbs/.png into AppData/Temp | `Product` OR-branch unused | pc/proc_creation_win_curl_susp_download.yml |
| ca2092a1-c273-4878-9b4b-0d60115bf5ea | Suspicious Encoded PowerShell Command Line | process_creation | test/high | `-enc` with common base64 prefixes | fine | pc/proc_creation_win_powershell_base64_encoded_cmd.yml |
| 88f680b8-070e-402c-ae11-d2914f2257f1 | PowerShell Base64 Encoded IEX Cmdlet | process_creation | test/high | IEX hidden in base64 | uses `\|base64offset` (supported) | pc/proc_creation_win_powershell_base64_iex.yml |
| 7d4cdc5a-0076-40ca-aac8-f7e714570e47 | CMSTP Execution Process Creation | process_creation | stable/high | Child of cmstp.exe (UAC bypass / INF proxy) | needs ParentImage | pc/proc_creation_win_cmstp_execution_by_creation.yml |
| bdc64095-d59a-42a2-8588-71fd9c9d9abc | Suspicious Unsigned Dbghelp/Dbgcore DLL Loaded | image_load | test/high | Dumpers shipping their own dbghelp | dbghelp/dbgcore are on `INTERESTING_DLLS`; `Signed` is mapped | il/image_load_dll_dbghelp_dbgcore_unsigned_load.yml |

#### Defence evasion (T1562/T1070)

| UUID | Title | Category | Status/Level | Why | Mapping notes | Path |
|---|---|---|---|---|---|---|
| a7ee1722-c3c5-aeff-3212-c777e4733217 | Disable Windows Defender AV Security Monitoring | process_creation | test/high | `Set-MpPreference -DisableRealtimeMonitoring $true`, `sc stop WinDefend` | fine | pc/proc_creation_win_powershell_disable_defender_av_security_monitoring.yml |
| 1ec65a5f-9473-4f12-97da-622044d6df21 | Powershell Defender Disable Scan Feature | process_creation | test/high | `Set-MpPreference -Disable*Scan*` (incl. base64) | base64offset | pc/proc_creation_win_powershell_defender_disable_feature.yml |
| 07e3cb2c-0608-410d-be4b-1511cb1a0448 | Tamper Windows Defender Remove-MpPreference | process_creation | test/high | Removing Defender settings | CommandLine only | pc/proc_creation_win_powershell_remove_mppreference.yml |
| c6fb44c6-71f5-49e6-9462-1425d328aee3 | Powershell Base64 Encoded MpPreference Cmdlet | process_creation | test/high | Encoded Add/Set-MpPreference | base64offset | pc/proc_creation_win_powershell_base64_mppreference.yml |
| 14c71865-6cd3-44ae-adaa-1db923fae5f2 | Tamper Windows Defender - ScriptBlockLogging | ps_script | test/high | Set-MpPreference disable flags in script content | 4104 | ps/posh_ps_tamper_windows_defender_set_mp.yml |
| 452bce90-6fb0-43cc-97a5-affc283139b3 | Suspicious Windows Defender Registry Key Tampering Via Reg.EXE | process_creation | test/high | reg.exe writes to Defender policy keys (covers the registry gap from the command-line side) | fine | pc/proc_creation_win_reg_windows_defender_tamper.yml |
| 5e95028c-5229-4214-afae-d653d573d0ec | Security Service Disabled Via Reg.EXE | process_creation | test/high | `reg add …\Services\WinDefend /v Start /d 4` | CommandLine only | pc/proc_creation_win_reg_disable_sec_services.yml |
| 847d5ff3-8a31-4737-a970-aeae8fe21765 | Potential Tampering With Security Products Via WMIC | process_creation | test/high | `wmic product where name like '%Antivirus%' call uninstall` | windash | pc/proc_creation_win_wmic_uninstall_security_products.yml |
| 51cbac1e-eee3-4a90-b1b7-358efb81fa0a | Potential Windows Defender Tampering Via Wmic.EXE | process_creation | test/high | wmic on the Defender WMI namespace | fine | pc/proc_creation_win_wmic_namespace_defender.yml |
| 0a13e132-651d-11eb-ae93-0242ac130002 | Audit Policy Tampering Via Auditpol | process_creation | test/high | `auditpol /set /success:disable`, `/clear` | fine | pc/proc_creation_win_auditpol_susp_execution.yml |
| cd1f961e-0b96-436b-b7c6-38da4583ec00 | Suspicious Windows Trace ETW Session Tamper Via Logman.EXE | process_creation | test/high | `logman stop/delete` of EventLog/Defender ETW sessions, which also **blinds Kestrel** | fine. Overlaps TP-xx tamper; keep both. | pc/proc_creation_win_logman_disable_eventlog.yml |
| a238b5d0-ce2d-4414-a676-7a531b3d13d6 | ETW Trace Evasion Activity | process_creation | test/high | `wevtutil sl … /e:false`, `Remove-EtwTraceProvider` | windash | pc/proc_creation_win_susp_etw_trace_evasion.yml |

#### Network / DNS (C2, tunnelling)

| UUID | Title | Category | Status/Level | Why | Mapping notes | Path |
|---|---|---|---|---|---|---|
| 18249279-932f-45e2-b37a-8925f2597670 | Process Initiated Network Connection To Ngrok Domain | network_connection | test/high | ngrok reverse tunnels (RMM / ransomware operators) | `DestinationHostname` is filled only when the same process resolved the name (DNS correlation); `Initiated` is always `true` in Kestrel | nc/net_connection_win_domain_ngrok.yml |
| 1d08ac94-400d-4469-a82f-daee9a908849 | Communication To Ngrok Tunneling Service Initiated | network_connection | test/high | ngrok agent control channel | same | nc/net_connection_win_domain_ngrok_tunnel.yml |
| b55ca2a3-7cff-4dda-8bdd-c7bfa63bf544 | DNS Query Tor .Onion Address - Sysmon | dns_query | test/high | Tor2web gateways used by ransomware and stealers | `QueryName` ok | dq/dns_query_win_tor_onion_domain_query.yml |

That is 70 Tier A rules: 10 ransomware/recovery, 15 credential, 8 persistence, 22 LOLBin/execution, 12 defence evasion and 3 network/DNS.

### 3.2 Tier B: ship disabled or "audit, tune first" (7 rules)

| UUID | Title | Category | Status/Level | Reason it is not Tier A |
|---|---|---|---|---|
| a18dd26b-6450-46de-8c91-9659150cf088 | Potentially Suspicious GrantedAccess Flags On LSASS | process_access | test/medium | Main LSASS-access rule. Its Defender filters use `CallTrace`, which never applies in Kestrel, so expect FPs from AV, backup and VMware tools until there is a local exclusion baseline. Desired ≠ granted access. |
| 02ee49e2-e294-4d0f-9278-f5b3212fc588 | New RUN Key Pointing to Suspicious Folder | registry_set | experimental/high | Very relevant to stealers (Run key into %AppData%/%Temp%), but experimental with a long FP filter list (updaters, Spotify, Discord…) |
| 8d85cf08-bf97-4260-ba49-986a2a65129c | Suspicious PowerShell In Registry Run Keys | registry_set | test/medium | Good signal, medium level; Run keys covered |
| de587dce-915e-4218-aac4-835ca6af6f70 | Potential Persistence Attempt Via Run Keys Using Reg.EXE | process_creation | test/medium | Admin scripts use reg add Run |
| e593cf51-88db-4ee1-b920-37e89012a3c9 | Potentially Suspicious Rundll32 Activity | process_creation | test/medium | Covers `rundll32 javascript:`, `url.dll,FileProtocolHandler`, `zipfldr`…; broad |
| 17769c90-230e-488b-a463-e05c08e9d48f | Powershell Defender Exclusion | process_creation | test/medium | Add-MpPreference -ExclusionPath. Also used by legitimate installers; Kestrel's Defender\Exclusions registry watch overlaps. |
| c1344fa2-323b-4d2e-9176-84b4d4821c88 | Windows Defender Exclusions Added - PowerShell | ps_script | test/medium | Same, in 4104 |

### 3.3 Tier C: high value, blocked by Kestrel sensor or mapping gaps (13 rules)

| UUID | Title | Category | Status/Level | Blocker → required change |
|---|---|---|---|---|
| 5de03871-5d46-4539-a82d-3aa992a69a83 | Registry Disable System Restore | registry_set | test/high | key `…\SystemRestore` not in allow-list, plus DWORD format |
| d6a9b252-c666-4de6-8806-5561bbbd3bdc | Wdigest Enable UseLogonCredential | registry_set | test/high | `Details: DWORD (0x00000001)` format, plus `Control\SecurityProviders\WDigest` not in allow-list |
| 55e29995-75e7-451a-bef0-6225e2f13597 | Potential Credential Dumping Via LSASS SilentProcessExit Technique | registry_event | test/critical | `…\SilentProcessExit\lsass.exe` not in allow-list (IFEO is) |
| 0eb46774-f1ab-4a74-8238-1155855f2263 | Disable Windows Defender Functionalities Via Registry Keys | registry_set | test/high | `Policies\Microsoft\Windows Defender\*` not in allow-list, plus DWORD format |
| fecfd1a1-cc78-4313-a1ea-2ee2e8ec27a7 | PowerShell Logging Disabled Via Registry Key Tampering | registry_set | test/high | `Policies\Microsoft\Windows\PowerShell\*` not in allow-list, plus DWORD |
| 2f78da12-f7c7-430b-8b19-a28f269b77a3 | Disable Windows Event Logging Via Registry | registry_set | test/high | `WINEVT\Channels\*\Enabled` not in allow-list, plus DWORD |
| a07f0359-4c90-4dc4-a681-8ffea40b4f47 | Service Binary in Suspicious Folder | registry_set | test/high | `CurrentControlSet\Services\*\ImagePath`/`Start` not in allow-list |
| 160d2780-31f7-4922-8b3a-efce30e63e96 | Potential AMSI COM Server Hijacking | registry_set | test/high | `CLSID\{fdb00e52-…}\InProcServer32` not in allow-list |
| 37774c23-25a1-4adb-bb6d-8bb9fd59c0f8 | Suspicious Volume Shadow Copy Vssapi.dll Load | image_load | test/high | System32 `vssapi.dll` filtered at source → add to `INTERESTING_DLLS` |
| 4508a70e-97ef-4300-b62b-ff27992990ea | DotNet CLR DLL Loaded By Scripting Applications | image_load | test/high | `clr.dll` filtered at source (Windows path) |
| a5a2d357-1ab8-4675-a967-ef9990a59391 | LSASS Process Memory Dump Files | file_event | test/high | file creation outside sensitive paths not emitted → add a `*.dmp` / `lsass*` name filter |
| a49fa4d5-11db-418c-8473-1e014a8dd462 | Lsass Memory Dump via Comsvcs DLL | process_access | test/high | requires `CallTrace\|contains comsvcs.dll` → ETW stack walk |
| f239b326-2f41-4d6b-9dfa-c846a60ef505 | Password Dumper Remote Thread in LSASS | create_remote_thread | stable/high | requires `StartModule: ''` |

(Also `9a4ccd1a-3526-4d99-b980-9f9c5d3a6ff3` "Potential Credential Dumping Via WER" needs `ParentUser`. That one is trivial to add from the process table.)

**Cheapest unlocks, in order:**
1. Render registry DWORD/QWORD in Sysmon format: 71 registry_set rules.
2. Extend the registry key allow-list with about 8 roots: Defender policies, WDigest, SilentProcessExit, Services ImagePath/Start, WINEVT channels, PowerShell policies, SystemRestore, `Classes\CLSID\*\InProcServer32`, `Winlogon`.
3. Add PE VERSIONINFO enrichment for OriginalFileName/Company/Product/Description: 36 renamed-binary rules plus 92 filter fixes.
4. Fill `ParentUser`.
5. Add a few DLLs to `INTERESTING_DLLS`.
6. Add a `.dmp`/startup/tasks path set for file_event.

### 3.4 Do-not-include list

| What | Count (rules/windows) | Reason |
|---|---:|---|
| `builtin/*` service rules (Security 4688/4624, System 7045, Defender, AppLocker…) | ~240 | No `category`; Kestrel does not ingest event logs. Some of them (7045 service install, 4698 task, 1116 Defender detection, 104/1102 log cleared) would be worth a future EventLog sensor; Rustinel does this. |
| `pipe_created`, `driver_load`, `wmi_event`, `process_tampering`, `raw_access_thread`, `create_stream_hash`, `ps_module`, `ps_classic_*`, `registry_add/delete` | ~110 | No routed telemetry (see §2.3) |
| `*_renamed_*` process_creation rules | 36 | Depend on true PE OriginalFileName/Description; dead until enrichment exists. They will not FP, but they inflate "coverage". |
| HackTool rules keyed on `Hashes\|contains IMPHASH=` | 32 | Kestrel only has SHA256 |
| Rules keyed on `CallTrace`, `StartModule`, `StartFunction` | 17 + 4 | Field never filled. Some also use it in filters, so loading them increases FPs. |
| `proc_creation_win_hktl_*` (94) wholesale | 94 | Many are tool-name/hash based, so they are brittle and age fast. Pick only behavioural ones (e.g. Mimikatz command line above). |
| `proc_creation_win_pua_*` (42) and `*remote_access_tools*` (22) | 64 | AnyDesk, ScreenConnect, NetSupport and similar are legitimately used by SMB IT providers in SG/ID. Ship them as an optional "unsanctioned RMM" pack, not by default. |
| Whoami / discovery rules (e.g. 97a80ec7, 79ce34ca, e9142d84) | — | High FP on admin and dev machines; low value alone. Better used as correlation inputs. |
| `level: low/informational` and `rules-threat-hunting/` | 140+ | Hunting content: alert fatigue on an SMB console |
| `rules-emerging-threats/` (474) wholesale | 474 | Campaign- and CVE-specific (IOC-like), and they age quickly. Optionally cherry-pick current infostealer/ClickFix items into the stealer (ST) context. |
| Rules needing `|expand` placeholders (`rules-placeholder/`) | — | Need a pipeline that fills `%Admins_Workstations%` and similar; rsigma supports `Expand`, but Kestrel has no placeholder source |
| Correlation rules (`correlation:` documents) | — | Rejected by Kestrel by design (`compile_source`). Engine builtins do sequences. |
| Any Elastic detection-rules / protections-artifacts text | — | ELv2: banned by `deny.toml` policy (design reference only) |

---

## 4. How peers cover general malware

### 4.1 Fibratus (Apache-2.0: rules and code reusable with NOTICE)

* **Licence:** Apache-2.0 ([LICENSE.MD](https://github.com/rabbitstack/fibratus/blob/master/LICENSE.MD); [fibratus.io](https://www.fibratus.io/)). The latest release is v3.1.1 (2026-08-19) ([GitHub API](https://api.github.com/repos/rabbitstack/fibratus/releases/latest)). The site says "no drivers" and kernel ETW only.
* **Rule pack** (sparse clone, commit `eee69cf`, 2026-10-18): 140 YAML rules:
  * defense_evasion 49, credential_access 26, privilege_escalation ~23, persistence 16, initial_access 12, execution 5, lateral_movement 2.
  * **No ransomware/impact rules** (grep for ransom/shadow/inhibit/encrypt found none).
  * 49 rules carry an `action: - name: kill`.
* **Rule language:** a filter expression over typed event fields (`ps.exe`, `registry.path`, `thread.callstack.modules`, `module.path`), with macros (`registry_run_keys`, `startup_locations`) and `imatches` globs. Example: LSASS dump via MiniDumpWriteDump keys on `thread.callstack.modules imatches ('*dbgcore.dll','*comsvcs.dll')` or `thread.callstack.symbols imatches '*MiniDumpWriteDump'` on `open_process` against lsass, then `kill` ([rule](https://github.com/rabbitstack/fibratus/blob/master/rules/credential_access_lsass_memory_dump_via_minidumpwritedump.yml)). This is the call-stack signal Sigma calls `CallTrace`, obtained from ETW stack walking.
* **Sequence rules** (62 of 140 use them). Syntax: `sequence maxspan <dur> by ps.uuid |expr1| |expr2|`. Joins use either `by` or per-step `$1` back-references. Examples:
  * WER LSASS dump: `|spawn_process and ps.name iin ('WerFault.exe','WerFaultSecure.exe')|` then `|create_file and file.path icontains 'lsass'|` within 2 m by ps.uuid ([rule](https://github.com/rabbitstack/fibratus/blob/master/rules/credential_access_lsass_memory_dump_via_wer.yml)).
  * Startup-folder persistence: an untrusted executable loaded from a startup location, then an outbound connection outside RFC1918 within 5 m ([rule](https://github.com/rabbitstack/fibratus/blob/master/rules/persistence_network_connection_via_startup_folder_executable_or_script.yml)).
* **Persistence approach:** a registry Run-key write by a process under `C:\Windows\*` that is not on a long allow-list of known writers ([rule](https://github.com/rabbitstack/fibratus/blob/master/rules/persistence_unusual_process_modified_registry_run_key.yml)). This is the "unusual writer" pattern, complementary to Sigma's "suspicious value" pattern.
* **Takeaway for Kestrel:**
  * Fibratus is the closest licence-compatible design reference for builtin `CD-xx`/`PS-xx`/`EX-xx` rules. Rule *ideas and logic* can be adapted (Apache-2.0 allows copying with attribution and NOTICE).
  * Its big advantage over Kestrel is call stacks.
  * Nobody in the open-source user-mode space ships good ransomware *behaviour* rules: Fibratus has none, and Sigma has only command-line precursors. Kestrel's RW-xx family (canaries plus file-rename/entropy rates plus precursor correlation) would be a differentiator.

### 4.2 Nextron Aurora (commercial; Aurora Lite free, closed source)

* Sigma on ETW. Nextron positions Aurora as adding process ancestry (grandparent/tree), full command lines and PE metadata on top of Sysmon-like events ([Nextron blog, 2025-07-31](https://www.nextron-systems.com/2025/07/31/aurora-leveraging-etw-for-advanced-threat-detection/)).
* **Documented limits** ([Aurora manual §15](https://aurora-agent-manual.nextron-systems.com/en/latest/usage/detection-gaps.html)):
  * no named-pipe ETW;
  * Kernel-Registry events reference keys by handle, so handle tracking is needed and is done only in the "Intense" preset;
  * the OpenKey `BaseName` is empty;
  * `CapturedData` on QueryValue fails to parse;
  * SetValue data "appears empty", so it is re-read from the registry, which is less reliable;
  * non-kernel providers can be suppressed by in-process ETW patching (mitigated by its "ETW Canary" module);
  * handle polling skips async handles.
* Nextron's own mitigation is to run Sysmon alongside.
* Aurora Lite lacks extra detection modules and ASGARD management ([Aurora Lite release](https://www.nextron-systems.com/2022/04/04/aurora-lite-agent-v1-0-release/)).
* **Takeaway:** Kestrel has the same registry problems, which is why it uses the key allow-list and captured data. Copy the honesty and the "ETW canary/stat reporting" idea for TP-xx.

### 4.3 Velociraptor (AGPL-3.0: design reference only, no code reuse)

* Licence: AGPL-3.0 ([LICENSE](https://github.com/Velocidex/velociraptor/blob/master/LICENSE)).
* Sigma is evaluated against **Sigma Models**, which are named sets of log sources plus field mappings, e.g. `Windows.Sigma.Base`, `Windows.Sigma.BaseEvents`, `Windows.ETW.Base`. Rules "can only be safely interpreted within the context of a specific Sigma Model" ([Velociraptor blog, 2025-02-02](https://docs.velociraptor.app/blog/2025/2025-02-02-sigma/)).
* Since 0.74, Sigma also runs on real-time ETW and eBPF events ([0.74 release notes](https://docs.velociraptor.app/blog/2025/2025-02-23-release-notes-0.74)).
* Curated rule sets include a Hayabusa port. The workflow is record → replay → tune → deploy (Sigma Studio).
* **Takeaway:** formalise Kestrel's mapping as a declared "model" (the table in sigma.rs) and publish it, together with record/replay of real events against candidate rules. Kestrel's `simulate` + `replays/*.jsonl` is already halfway there.

### 4.4 Elastic Defend (proprietary agent; protections-artifacts under Elastic License 2.0: **do not copy rule text**)

* `elastic/protections-artifacts` contains `behavior/` (EQL endpoint rules), `yara/` and `ransomware/`, "Licensed under the Elastic License 2.0" ([repo](https://github.com/elastic/protections-artifacts)). ELv2 is on Kestrel's banned list.
* Ransomware protection works like this:
  * **canary files** in targeted locations; a modification raises an alert, and in Prevent mode the process is terminated;
  * plus behavioural analysis that includes the MBR;
  * it is a paid (Platinum/Enterprise) feature ([Elastic Defend policy docs](https://www.elastic.co/guide/en/security/current/configure-endpoint-integration-policy.html)).
* Elastic Security Labs adds that canaries "cannot be fingerprinted", that 8.11+ takes a memory snapshot of the flagged process, and, honestly, that "It is hard to be certain on Windows systems that no file has been encrypted before the detection … due to the very structure of how MiniFilters work" ([Elastic Security Labs](https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys)).
* Elastic's LSASS rules key on call traces through dbghelp/dbgcore and on DuplicateHandle (seen in search results; design reference only).
* **Takeaway:** canaries plus suspend-and-snapshot are the right RW-xx primitive, and Kestrel already plants canaries. Without a minifilter, Kestrel's canary signal comes from Kernel-File ETW after the fact, so the UI and docs must say "early warning, not prevention". That is even more true than for Elastic.

### 4.5 Rustinel (Apache-2.0 engine; rules repo DRL 1.1): closest architectural twin

* Licence and project:
  * Apache-2.0 ([repo](https://github.com/karib0u/rustinel)); v1.10.0 released 2026-10-16;
  * about 508 stars ([GitHub API](https://api.github.com/repos/karib0u/rustinel));
  * covered by [Help Net Security, 2026-05-11](https://www.helpnetsecurity.com/2026/05/11/rustinel-open-source-endpoint-detection-windows-linux/).
* **Same stack as Kestrel:** `rsigma-parser`/`rsigma-eval` 0.24, `ferrisetw` 1.2 and `yara-x` 1.21 (from its Cargo.toml). Rustinel "keeps ownership of normalization, logsource routing, ECS alerts, hot reload, and IOC/YARA".
* Sensors: ETW plus Windows Event Log (process, image load, network, file, registry, DNS, PowerShell, WMI, service, task, Security audit, Defender Operational).
* No anti-tamper and no pre-execution blocking. Active response (kill) is documented.
* **Measured SigmaHQ fit:** CI loads SigmaHQ commit `da9bb07` (3,783 rules), and 2,709 load against Windows collectors ([coverage.md](https://github.com/karib0u/rustinel/blob/main/docs/coverage.md)).
  * It warns: "Rule count is not coverage".
  * `rustinel sigma doctor --platform` gives a per-rule verdict "taking `or` branches and negation into account".
  * A generated field-availability table marks 65 Sysmon-view fields as "Never" on Windows ([field-availability.md](https://github.com/karib0u/rustinel/blob/main/docs/field-availability.md)).
* **Its documented Windows limits match Kestrel's:**
  * no create_remote_thread;
  * process access "planned" because Audit-API-Calls lacks true GrantedAccess;
  * no pipe_created;
  * image_load has no `User`;
  * registry `Details` relies on an undocumented ETW option;
  * registry paths stay NT-style, so `startswith: HKLM` misses — Kestrel normalises them and avoids this ([limitations.md](https://github.com/karib0u/rustinel/blob/main/docs/limitations.md)).
* Its rules repo `Karib0u/rustinel-rules` is a curated Sigma and YARA set under DRL 1.1 ([repo](https://github.com/Karib0u/rustinel-rules)).
* **Takeaway:** adopt its practices: a "doctor" field-availability contract, a SigmaHQ CI baseline at a pinned commit, a benchmark (`cargo bench --bench sigma_engine`), and loss counters. Its Apache-2.0 code can be studied and adapted with attribution.

### 4.6 Wazuh (GPLv2 / AGPLv3 engine: design reference only)

* Licence: GPL-2.0 for most of the code; the new engine is AGPL-3.0-or-later ([LICENSE](https://github.com/wazuh/wazuh/blob/main/LICENSE)). Both are banned for Kestrel code and rules.
* **Approach for Windows malware:** install Sysmon with a Wazuh-provided config, forward `Sysmon/Operational`, and match on the server with custom XML rules. Examples:
  * Funklocker rule 101007, level 15: `vssadmin` + `delete shadows` → T1490;
  * similar rules for Phobos (vssadmin/wmic/wbadmin, bcdedit bootstatus, disabled recovery) and for BlackSuit, Cephalus and Gunra;
  * active-response scripts.
  * Sources: [Funklocker](https://wazuh.com/blog/detecting-and-responding-to-funklocker-ransomware-with-wazuh/), [BlackSuit](https://wazuh.com/blog/detect-and-respond-to-blacksuit-ransomware-with-wazuh/), [Cephalus](https://wazuh.com/blog/detecting-and-responding-to-cephalus-ransomware-with-wazuh/).
* **Takeaway:** Wazuh's coverage is server-side, Sysmon-dependent, and mostly per-family blog rules. Kestrel's on-device Sigma with generic recovery-inhibition rules (§3.1) covers the same precursors without Sysmon and acts locally.

### 4.7 Coverage comparison (general-malware families)

| Capability | Kestrel today + pack | Fibratus | Aurora | Rustinel | Elastic Defend | Wazuh |
|---|---|---|---|---|---|---|
| Ransomware precursors (VSS/bcdedit/wbadmin) | Sigma Tier A | none in pack | Sigma | Sigma | EQL (ELv2) | server rules on Sysmon |
| Ransomware in-flight (canary / bulk rename) | canaries (stealer-oriented today) → RW-xx | — | — | — | canaries + behaviour (paid) | FIM-based |
| LSASS dump by command line | Sigma Tier A | yes | Sigma | Sigma | yes | Sysmon |
| LSASS dump by handle/call stack | handle (desired access) only | **call stack** | Sigma (CallTrace via ETW?) **[unverified]** | planned | yes | Sysmon 10 |
| Persistence (tasks/services/Run) | Sigma + allow-listed registry | registry + file + sequences | Sigma + registry (Intense) | Sigma + event log 7045/4698 | yes | Sysmon |
| LOLBins | Sigma process_creation | some | Sigma | Sigma | yes | Sysmon |
| Response | suspend/kill/quarantine/WFP/isolate | kill | kill/suspend (paid) **[unverified]** | kill | full | active-response scripts |

---

## 5. Practical pitfalls

### 5.1 rsigma modifier support (checked in the 0.25.0 source, `rsigma-parser/src/ast.rs`)

* Supported:
  * `contains`, `startswith`, `endswith`, `all`;
  * `base64`, `base64offset`, `wide`/`utf16le`, `utf16be`, `utf16`, `windash`;
  * `re` (plus `i`, `m`, `s` flags), `cidr`, `cased`, `exists`, `expand`, `fieldref`;
  * `gt`/`gte`/`lt`/`lte`, `neq`, and timestamp parts.
* Usage in SigmaHQ `rules/windows`: windash in 82 files, `|re` 84, `|cidr` 17, `|base64offset` 7, `|fieldref` 3, `|expand` 0 (the placeholder rules live in `rules-placeholder/`).
* All 1,990 routed rules compiled, so modifier coverage is not the bottleneck: field availability is.
* `|re` uses the Rust `regex` crate (no look-around or backreferences). SigmaHQ regexes compiled fine, but custom rules copied from PCRE sources may not.
* Kestrel exposes integers (`ProcessId`, `DestinationPort`) as `EventValue::Int`. Sigma rules writing `DestinationPort: '443'` as a string should still match; covered by the existing `network_cidr_and_ints` test for ints. **[verify string-vs-int coercion in rsigma for quoted ports]**

### 5.2 Performance with 100+ rules per event (measured on this host, release build)

* Setup: all 1,192 SigmaHQ process_creation rules, three JSON events (svchost, a chrome renderer, `vssadmin delete shadows`).
* **Per-rule loop** (`evaluate_rule` for each rule, which is what Kestrel's `sigma::matches` does today): **191 to 223 µs per event**.
* **`rsigma_eval::Engine::evaluate`**, which uses a witness-based candidate index (per-field Aho-Corasick over required needles, plus exact and presence maps): **22 to 25 µs per event**, about 9× faster, with identical hits (1 hit on vssadmin).
* For the ~80-rule pack, the per-rule loop costs roughly 15 µs per process start, which is negligible. Process starts are low-rate (a few per second).
* The rates that matter are `image_load`, `net_connect`, `file_access` and `registry_set`. Route rules by category first (Kestrel already does, via `Route`). If imported packs grow beyond a few hundred rules, switch to one `Engine` per category so the candidate index prunes. The index is an "over-approximation … never omits one that would [match]" (`candidate_index.rs` doc comment).
* Note `Engine` evaluates `JsonEvent`/`Event` implementors, so Kestrel's lazy `SigmaEvent` view can be used directly.
* Avoid `all_string_values()` / keyword (field-less) rules on hot paths: they materialise every field.

### 5.3 Testing against a benign baseline

* Positive fixtures:
  * SigmaHQ `regression_data/` (sample events per rule; check which pack rules have them);
  * Atomic Red Team tests in the VM only (per CLAUDE.md), e.g. T1490 vssadmin, T1003.001 comsvcs, T1053.005 schtasks, T1218.005 mshta.
* Benign baseline:
  * record `replays/*.jsonl` from a clean SMB-style VM (Office, Chrome/Edge, Teams, Zoom, OneDrive sync, Windows Update, Defender scans, an RMM agent, a backup agent);
  * run every pack rule over it in `simulate` mode;
  * any hit means either a tuned local exclusion or demotion to Tier B.
  * Expected noisy ones: `ce72ef99` (service stop by updaters), `cc9cbe82` (certutil decode in PKI or installer scripts), `a18dd26b` (AV and backup reading lsass), `e218595b` (dev machines using curl).
* Field-availability CI:
  * write a "doctor" test that, for each pack rule, walks the detection AST, lists referenced fields, and fails if a positive selection depends only on fields absent from `FIELD_NAMES`;
  * this would have flagged `9a4ccd1a` (ParentUser), `a49fa4d5` (CallTrace) and `f239b326` (StartModule);
  * Rustinel does exactly this ([sigma.md](https://github.com/karib0u/rustinel/blob/main/docs/sigma.md)).
* Pin the SigmaHQ commit and diff on update. SigmaHQ edits rules frequently (e.g. 646ea171 modified 2025-02-23), and an upstream change can silently change FP behaviour.

### 5.4 Other mapping traps

* **Parent missing ⇒ filters fail open.** `not filter_parent` evaluates to true when `ParentImage` is absent. For Protect-mode promotion, require `ParentImage` presence, or treat a missing field as "unknown, skip" in a Kestrel-side wrapper.
* **4104 must be enabled.** `ps_script` rules depend on Script Block Logging. Kestrel's hardening should enable it via GPO-equivalent registry settings. Without it, 165 rules are inert. Large scripts are split across multiple 4104 events, so one script's content can be spread over several events. **[verify Kestrel reassembles by ScriptBlockId]**
* **Case:** Sigma matching is case-insensitive unless `|cased`. Kestrel renders `GrantedAccess` as lowercase hex; that is fine.
* **Initiated:** Kestrel hard-codes `"true"`. Rules that look for inbound (`Initiated: 'false'`) never fire. That is acceptable.
* **DNS:** `QueryResults` is joined with `;`, as Sysmon does. DoH/DoT traffic is invisible (as in Rustinel).

---

## 6. Recommendations (summary)

1. Ship the 70 Tier A rules (unmodified YAML, pinned commit, `author` + URL + "DRL 1.1" visible in the alert and catalog views) as an Audit-only "SigmaHQ Audit pack". Ship Tier B disabled.
2. Fix the two silent mapping bugs first:
   * render DWORD/QWORD in Sysmon format;
   * fill `ParentUser`.
3. Then extend the registry allow-list and the `INTERESTING_DLLS` list, and add PE version-resource enrichment. This unlocks Tier C and the renamed-binary rules.
4. Add a `sigma doctor` field-availability check to the server's `POST /rules` validation, so custom rules that can never fire are flagged at upload.
5. Build RW-xx (canary-write + bulk-rename rate + Tier A precursors in a sequence) as Kestrel builtins. Peers either lack this (Fibratus, Rustinel) or keep it behind ELv2 or paid tiers (Elastic). Use Fibratus' Apache-2.0 sequence rules as the design pattern for CD-xx and PS-xx.
6. If rule count grows, move from the per-rule loop to `rsigma_eval::Engine` per category (measured 9× faster at 1,192 rules).
