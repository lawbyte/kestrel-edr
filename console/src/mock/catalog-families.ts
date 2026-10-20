import type { RuleMeta } from '@/api/types'

/** RW/CD/PS catalog, generated from crates/kestrel-detect/src/families/{rw,cd,ps}.rs (mock data). */
export const FAMILY_RULES: RuleMeta[] = [
  {
    "id": "RW-01",
    "name": "Shadow copy / backup catalog deletion",
    "description": "vssadmin, wmic, DiskShadow or PowerShell deleted Volume Shadow Copies or shrank their storage; wbadmin deleted the backup catalog, system-state backups or all backup versions; or a PowerShell script block enumerated Win32_ShadowCopy and deleted the objects. Derived from SigmaHQ c947b146, 639c9081 and c1337eb8 (DRL 1.1).",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1490"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the tool; also kill (tree) and quarantine its unsigned or user-writable launcher chain up to the first protected, system, Explorer or signed Program Files process, unless an administrator typed the command in an interactive shell",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/powershell/powershell_script/posh_ps_susp_win32_shadowcopy_deletion.yml",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_wbadmin_delete_all_backups.yml",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
    ],
    "false_positives": [
      "Administrators cleaning up shadow storage by hand",
      "Backup products that call vssadmin (most use the VSS API)",
      "LANDesk / Ivanti PowerShell modules (per SigmaHQ)"
    ]
  },
  {
    "id": "RW-02",
    "name": "Boot recovery disabled",
    "description": "bcdedit set recoveryenabled No or bootstatuspolicy IgnoreAllFailures, deleted the recovery sequence or the default boot entry; or reagentc /disable switched off the Windows Recovery Environment. The alert names the command that restores the setting. Derived from SigmaHQ 1444443e and db1c21e4 (DRL 1.1).",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1490"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "bcdedit variants: kill bcdedit and its untrusted launcher chain (tree) and quarantine user-writable launchers; reagentc /disable: alert only (imaging and OEM tools use it)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_reagentc_disable_windows_recovery_environment.yml",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
    ],
    "false_positives": [
      "OS imaging and OEM provisioning tools (reagentc)",
      "Kiosk or lab images that disable automatic repair on purpose"
    ]
  },
  {
    "id": "RW-03",
    "name": "Safe-mode boot staging",
    "description": "bcdedit set safeboot (minimal/network) or safebootalternateshell; a non-installer registered a service under Control\\SafeBoot\\{Minimal,Network} (Kestrel's own KestrelAgent key excluded); reg delete under Control\\SafeBoot; or Winlogon AutoAdminLogon/DefaultPassword set by the same lineage within 10 minutes of a Safe Mode staging hit. Derived from SigmaHQ c9fbe8e9, 1547e27c and fc0e89b5 (DRL 1.1). ATT&CK v19 renumbering of T1562.009 is unverified.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1490",
      "T1562.009",
      "T1685"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "bcdedit safeboot from a non-admin context: kill bcdedit and its untrusted launcher chain (tree), quarantine user-writable launchers, and show the revert command (bcdedit /deletevalue {default} safeboot); registry and reg.exe variants: alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_bcdedit_boot_conf_tamper.yml",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_add_load_service_in_safe_mode.yml",
      "https://www.attackiq.com/2025/10/02/emulating-qilin-ransomware/",
      "https://attack.mitre.org/resources/updates/updates-april-2026/"
    ],
    "false_positives": [
      "IT staff booting into Safe Mode for repair (interactive)",
      "AV / EDR installers registering Safe Mode services (Sophos, Malwarebytes, Hexnode)"
    ]
  },
  {
    "id": "RW-04",
    "name": "Event log cleared or shrunk",
    "description": "wevtutil cl/clear-log, or sl/set-log with /ms:, /lfn: or /e:false; PowerShell Clear-EventLog, Remove-EventLog, Limit-EventLog or EventLogSession.ClearLog; WMI ClearEventLog. Semantics of SigmaHQ cc36992a (DRL 1.1). ATT&CK v19 ids for log clearing are unverified.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "medium",
    "attack": [
      "T1070.001",
      "T1685"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Alert only; when the same lineage fired RW-01/02/03/05 in the last 30 minutes, kill the tool and its untrusted launcher chain (tree)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_eventlog_clear.yml",
      "https://www.attackiq.com/2025/10/02/emulating-qilin-ransomware/",
      "https://attack.mitre.org/resources/updates/updates-april-2026/"
    ],
    "false_positives": [
      "Administrators clearing logs during troubleshooting",
      "Golden-image preparation scripts",
      "Installers resizing their own log (wevtutil sl from msiexec)"
    ]
  },
  {
    "id": "RW-05",
    "name": "Service / process kill spree",
    "description": "Within 120 s one lineage ran net/sc stop, sc config start= disabled, Stop-Service/Set-Service -StartupType Disabled or taskkill /f /im against five or more distinct database, backup, Exchange or security targets from a curated list; or one non-system process terminated ten or more distinct other processes (not its own children) within 10 s.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "high",
    "attack": [
      "T1489",
      "T1685",
      "T1562.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "TerminateProcess variant from an unsigned or user-writable image: kill its lineage (tree) and quarantine the image; command-line variant and signed actors: alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-352a"
    ],
    "false_positives": [
      "Patch tools and installers stopping database or backup services",
      "Developer scripts restarting local SQL instances",
      "MDM / RMM maintenance jobs",
      "Process managers used by administrators"
    ]
  },
  {
    "id": "RW-06",
    "name": "Mass file encryption behaviour",
    "description": "The ransomware file sensor saw one process touch at least 30 user-data files (network paths count double) in at least 3 folders within its window, with at least 20 changes to unknown extensions, or at least 50 overwrites making up 80% or more of the files touched. Thresholds are halved for two hours after RW-12.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1486"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the process lineage (tree), quarantine user-writable images and isolate the host when network paths were touched; validly signed sync, backup and archiver clients (OneDrive, Dropbox, Google Drive, 7-Zip, WinRAR, Veeam, Acronis…) and Explorer alert only. User mode cannot guarantee that no file is encrypted first",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/file/file_rename/file_rename_win_ransomware/",
      "https://arxiv.org/html/2609.21426v1",
      "https://securityweek.com/analysis-shows-how-fast-various-ransomware-strains-encrypt-100000-files",
      "https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/"
    ],
    "false_positives": [
      "First sync or restore of OneDrive / Dropbox / Google Drive",
      "Bulk photo or media conversion to an uncommon format",
      "File encryption tools (AxCrypt, AESCrypt)",
      "Large git checkouts or build outputs inside user folders"
    ]
  },
  {
    "id": "RW-07",
    "name": "Ransomware canary tampered",
    "description": "A process other than the Kestrel agent overwrote, renamed or deleted one of the decoy documents Kestrel planted in user folders for ransomware detection.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1486",
      "T1485"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the process lineage (tree), quarantine user-writable images and isolate the host when network paths were touched; Explorer (the user) and signed sync/backup clients alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://www.elastic.co/security-labs/ransomware-in-the-honeypot-how-we-capture-keys",
      "https://arxiv.org/pdf/2508.00293"
    ],
    "false_positives": [
      "The user deleting or moving the decoy file",
      "OneDrive conflict renames",
      "Backup restore jobs and disk-cleanup tools"
    ]
  },
  {
    "id": "RW-08",
    "name": "Ransom-note fan-out",
    "description": "One process created the same file name in at least 5 folders, with a note extension (txt, hta, html, htm, rtf, url) and a ransom-note-like name (read me, restore, recover, decrypt, how to, help, instruction, !!!, _info); or the same name in at least 20 folders regardless of name.",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1486",
      "T1491.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Note-like name, or the same process also tripped RW-06/07: kill the lineage (tree) and quarantine user-writable images; name-agnostic fallback: alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://www.elastic.co/guide/en/security/current/potential-ransomware-note-file-dropped-via-smb.html",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
    ],
    "false_positives": [
      "Installers dropping readme.txt into many folders",
      "Sync clients restoring many folders",
      "Scripts seeding project templates"
    ]
  },
  {
    "id": "RW-12",
    "name": "Ransomware kill-chain correlation",
    "description": "Two or more distinct ransomware preparation rules (RW-01 to RW-05) fired on this host within 60 minutes, in the same lineage or not (affiliates run tools from separate shells and PsExec).",
    "kind": "builtin",
    "category": "ransomware",
    "severity": "critical",
    "attack": [
      "T1486",
      "T1490"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Isolate the host (the Kestrel server stays reachable), kill the participating lineages (tree) and halve the RW-06 thresholds for two hours",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://www.attackiq.com/2025/10/02/emulating-qilin-ransomware/",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-071a",
      "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a"
    ],
    "false_positives": [
      "Penetration tests and red-team exercises",
      "An administrator doing shadow-copy and event-log maintenance in one session"
    ]
  },
  {
    "id": "CD-01",
    "name": "LSASS memory dump via comsvcs MiniDump",
    "description": "rundll32 was started with comsvcs.dll and its MiniDump export (also the #24 ordinal, #+/#- ordinal tricks and 16-bit wrap-arounds such as #65560) with the 'full' argument, or rundll32 opened LSASS with memory-read / full / maximum-allowed rights. A MiniDump of a process other than LSASS is reported at medium severity without response. Logic follows SigmaHQ 646ea171 (author attribution: SigmaHQ, DRL 1.1).",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001",
      "T1218.011"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill rundll32 (process tree) and quarantine the dump file named on the command line",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs",
      "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_dump_comsvcs_dll",
      "https://redcanary.com/threat-detection-report/techniques/lsass-memory/"
    ],
    "false_positives": [
      "None known: no legitimate software dumps LSASS through comsvcs.dll (SigmaHQ: 'Unlikely')"
    ]
  },
  {
    "id": "CD-02",
    "name": "Known LSASS dumping tool",
    "description": "A known dumper ran against LSASS: procdump-style arguments (-ma/-mm/-mp/-mc/-r) with lsass or the LSASS PID (also renamed copies), createdump.exe with the LSASS PID, WerFault.exe / WerFaultSecure.exe started from outside System32/SysWOW64 (the 2025 old-WerFaultSecure technique), mimikatz command syntax (sekurlsa::, lsadump::, misc::memssp) or a known dumper image name (nanodump, PPLBlade, PPLdump, Dumpert, …). Hash/YARA hits arrive as IOC-HASH / YARA alerts.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the tool (process tree) and quarantine its image when it runs from a user-writable folder. Microsoft-signed procdump / createdump under their own name only alert (support cases)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://iimp0ster.github.io/detection-chokepoints/chokepoints/lsass-credential-dumping/",
      "https://borncity.com/win/2025/09/28/windows-11-24h2-hackers-can-use-werfaultsecure-exe-to-steal-lsass-passwords-and-disable-security-software/",
      "https://redcanary.com/threat-detection-report/techniques/lsass-memory/"
    ],
    "false_positives": [
      "Administrators taking an LSASS dump with Microsoft-signed procdump for a Microsoft support case (alert only; add a time-boxed exclusion)"
    ]
  },
  {
    "id": "CD-03",
    "name": "Suspicious LSASS handle request",
    "description": "A process asked for a handle to LSASS with rights that allow reading, writing, cloning or duplicating it (VM_READ/VM_WRITE/VM_OPERATION/CREATE_THREAD/DUP_HANDLE/CREATE_PROCESS, PROCESS_ALL_ACCESS or MAXIMUM_ALLOWED), and the requester is not on the path + signer allow-list of known openers and is unsigned, not Microsoft-signed, user-writable, a LOLBin, or Task Manager asking for full access. Kernel-Audit-API-Calls reports the desired access, not the granted one.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Suspend the requesting process for the suspend window (a later CD-04/CD-05 hit kills it); never acts on LSASS",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_suspicious_lsass_process_access.yml",
      "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_susp_access_flag",
      "https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights",
      "https://github.com/Karib0u/rustinel/issues/302"
    ],
    "false_positives": [
      "Third-party antivirus / EDR not yet on the allow-list",
      "Backup, password-sync and SSO / smart-card middleware",
      "Monitoring agents that request MAXIMUM_ALLOWED",
      "Task Manager 'Create dump file' by an administrator"
    ]
  },
  {
    "id": "CD-04",
    "name": "LSASS handle followed by a dump file",
    "description": "A process that opened LSASS with dangerous rights (and is not an allow-listed opener) wrote a .dmp / .mdmp / .dump file, or a file with 'lsass' in its name, within 120 seconds. Two independent facts, mirroring the Fibratus LSASS memory-dump sequence rule.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the process tree and quarantine the dump file (and the image when it runs from a user-writable folder)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_potential_lsass_memory_dump.yml",
      "https://detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_lsass_default_dump_file_names",
      "https://iimp0ster.github.io/detection-chokepoints/chokepoints/lsass-credential-dumping/"
    ],
    "false_positives": [
      "Support engineers deliberately dumping LSASS (use a time-boxed exclusion)"
    ]
  },
  {
    "id": "CD-05",
    "name": "Debug library dump helper reading LSASS",
    "description": "An unsigned, user-writable or LOLBin process loaded dbghelp.dll or dbgcore.dll (MiniDumpWriteDump) and opened LSASS with dangerous rights within 60 seconds. The image load alone is telemetry: debuggers, crash reporters and anti-cheat load dbghelp constantly but do not read LSASS.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the process tree and quarantine its image when it runs from a user-writable folder",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://sigma.controlassurance.com/rules/proc_access_win_susp_dbgcore_dbghelp_load/",
      "https://detection.fyi/sigmahq/sigma/windows/process_access/proc_access_win_lsass_memdump",
      "https://iimp0ster.github.io/detection-chokepoints/chokepoints/lsass-credential-dumping/"
    ],
    "false_positives": [
      "Developer debugging tools run from a user folder against LSASS (rare)"
    ]
  },
  {
    "id": "CD-06",
    "name": "Blocked LSASS access attempt",
    "description": "A suspicious process asked for dangerous rights on LSASS and Windows refused the open (non-zero NTSTATUS, e.g. LSA protection / RunAsPPL held). Nothing was read, but a credential-dumping attempt is a strong hunting lead. Opens of non-existent PIDs (STATUS_INVALID_CID) are ignored.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Alert; in Protect mode also suspend the requesting process for the suspend window",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
      "https://github.com/Karib0u/rustinel/issues/302",
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_suspicious_lsass_process_access.yml"
    ],
    "false_positives": [
      "Inventory / monitoring tools that request full access and fall back to query rights"
    ]
  },
  {
    "id": "CD-07",
    "name": "LSASS dump preparation via SilentProcessExit / IFEO",
    "description": "A value was written under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass*, or Image File Execution Options\\lsass.exe got GlobalFlag with FLG_MONITOR_SILENT_PROCESS_EXIT (0x200), Debugger or VerifierDlls. AuditLevel=8 (LSA protection audit mode) is legitimate and ignored. Logic follows SigmaHQ 55e29995 (author attribution: SigmaHQ, DRL 1.1).",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001",
      "T1112",
      "T1546.012"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill the writer (process tree) and delete the value (the agent backs it up to the quarantine vault first)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/registry/registry_event/registry_event_silentprocessexit_lsass/",
      "https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2"
    ],
    "false_positives": [
      "None known (SigmaHQ: 'Unlikely')"
    ]
  },
  {
    "id": "CD-08",
    "name": "LSASS dump via Windows Error Reporting",
    "description": "WerFault.exe / WerFaultSecure.exe was started against the LSASS PID (or with lsass on its command line), or wrote a file with 'lsass' in its path such as CrashDumps\\lsass.exe.<pid>.dmp (LSASS Shtinkering, silent-process-exit dumps). A real LSASS crash restarts Windows instead of producing a quiet WER dump.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Kill WerFault (process tree) and quarantine the dump file",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_lsass_memory_dump_via_wer.yml",
      "https://detection.fyi/sigmahq/sigma/windows/file/file_event/file_event_win_lsass_shtinkering/",
      "https://borncity.com/win/2025/09/28/windows-11-24h2-hackers-can-use-werfaultsecure-exe-to-steal-lsass-passwords-and-disable-security-software/"
    ],
    "false_positives": [
      "None expected: treat any WER dump of LSASS as an incident"
    ]
  },
  {
    "id": "CD-09",
    "name": "Malicious LSA security package",
    "description": "A non-installer process registered a non-Microsoft package in Lsa\\Security Packages, Authentication Packages, Notification Packages or Lsa\\OSConfig\\Security Packages; LSASS loaded a DLL that is not Microsoft-signed; or the mimikatz memssp log (mimilsa.log / kiwissp.log) was written to System32. Logic follows SigmaHQ eeb30123 (author attribution: SigmaHQ, DRL 1.1).",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1547.005",
      "T1556.002",
      "T1003.001"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Quarantine the package DLL when it lies in a user-writable folder; the value itself is not reverted automatically (reverting LSA packages can break logon) and LSASS is never killed",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/registry/registry_event/registry_event_ssp_added_lsa_config",
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_suspicious_security_package_loaded_by_lsass.yml"
    ],
    "false_positives": [
      "Password filters (AD password sync, MFA vendors)",
      "Smart-card / credential-provider middleware",
      "Third-party SSO packages"
    ]
  },
  {
    "id": "CD-10",
    "name": "Credential hive save or copy",
    "description": "reg.exe save/export of HKLM\\SAM or HKLM\\SECURITY (critical) or the whole HKLM\\SYSTEM hive (high); esentutl /vss or /y copying config\\SAM|SECURITY|SYSTEM; command lines referencing shadow-copy or RegBack copies of those hives; or a process other than Windows backup components / known backup vendors opening a hive inside a volume shadow copy. Logic follows SigmaHQ fd877b94 and e7be6119 (author attribution: SigmaHQ, DRL 1.1).",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "critical",
    "attack": [
      "T1003.002",
      "T1003.004",
      "T1003.005"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "For reg save/export of SAM or SECURITY: kill reg.exe (process tree) and quarantine the output file. Other sub-cases alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_reg_dumping_sensitive_hives",
      "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy",
      "https://raw.githubusercontent.com/rabbitstack/fibratus/master/rules/credential_access_sensitive_registry_hive_dump.yml"
    ],
    "false_positives": [
      "Backup software (wbengine, wbadmin, Veeam, Veritas, Acronis, SCCM)",
      "Forensic collectors (KAPE, Velociraptor)",
      "Administrators exporting the SYSTEM hive for troubleshooting"
    ]
  },
  {
    "id": "CD-11",
    "name": "NTDS.dit extraction",
    "description": "ntdsutil / dsdbutil 'ifm' + 'create full'; a command line copying ntds.dit out of a volume shadow copy, with esentutl, or within 10 minutes of a shadow copy being created; or an ntds.dit file written outside %SystemRoot%\\NTDS. Mainly relevant on domain controllers. DCSync (directory replication from a non-DC) is out of scope: it leaves no credential-access trace on the endpoint and needs DC-side logs.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1003.003"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Kill the process tree and quarantine the copied ntds.dit when it is in a user-writable folder",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://soc.cyber.wa.gov.au/guidelines/TTP_Hunt/ADS_forms/T1003.003-Creation-of-Ntds.dit-to-Suspicious-Location-in-Server/",
      "https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_esentutl_sensitive_file_copy",
      "https://attack.mitre.org/techniques/T1003/006/"
    ],
    "false_positives": [
      "Domain-controller administrators building IFM media for a new DC",
      "AD backup tools"
    ]
  },
  {
    "id": "CD-12",
    "name": "WDigest cleartext credential downgrade",
    "description": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential was set to a non-zero value (or Negotiate = 1), which makes LSASS keep cleartext passwords after the next logon. Windows 8.1+ default is 0.",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1112",
      "T1003.001",
      "T1562.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Set the value back to 0 (backed up first); the writer is not killed",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://detection.fyi/sigmahq/sigma/windows/registry/registry_set/registry_set_wdigest_enable_uselogoncredential/",
      "https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0087",
      "https://adsecurity.org/?p=559"
    ],
    "false_positives": [
      "Legacy applications that still need Digest authentication (rare)"
    ]
  },
  {
    "id": "CD-13",
    "name": "LSA protection / Credential Guard tamper",
    "description": "Lsa\\RunAsPPL set to 0 or deleted; LsaCfgFlags / Credential Guard Enabled set to 0 or deleted; DisableRestrictedAdmin set to 0; the Defender KslD driver service ImagePath / AllowedProcessName changed by anything but Defender or Windows servicing (KslDump); or a kernel-driver service installed from outside System32\\drivers (bring-your-own-vulnerable-driver).",
    "kind": "builtin",
    "category": "credential_dumping",
    "severity": "high",
    "attack": [
      "T1562.001",
      "T1112",
      "T1068"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Alert only (the setting is not reverted automatically, so deliberate administrator changes are not overridden)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection",
      "https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/how-it-works",
      "https://www.besthub.dev/articles/how-ksldump-uses-a-microsoft-driver-to-bypass-ppl-and-dump-lsass-credentials-via-registry-edit-3c40a1c05f4a"
    ],
    "false_positives": [
      "IT disabling LSA protection for an unsigned smart-card / password-filter plug-in",
      "Microsoft Defender platform updates rewriting KslD",
      "Antivirus, VPN or anti-cheat drivers installed under Program Files"
    ]
  },
  {
    "id": "PS-01",
    "name": "Run key to untrusted payload",
    "description": "A Run-family registry value (Run, RunOnce, RunOnceEx, RunServices, policy Run, Windows Load/Run) was set to a program in a user-writable folder that is not validly signed and not a known per-user application. Severity is raised when the payload carries Mark-of-the-Web, was created in the last 10 minutes, or the writer is untrusted or already alerted.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "medium",
    "attack": [
      "T1547.001"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Remove the value (backed up), quarantine the payload, kill the payload if running and the writer's tree — only when the payload is known unsigned, was just dropped or downloaded, and the writer is untrusted",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/001/",
      "https://www.elastic.co/guide/en/security/current/startup-or-run-key-registry-modification.html",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml",
      "https://www.picussecurity.com/resource/press-release/red-report-2026-rise-of-digital-parasite"
    ],
    "false_positives": [
      "Per-user apps (OneDrive, Teams, Discord, Spotify, Zoom, Squirrel updaters) — suppressed by the built-in baseline",
      "Developer tools or unsigned in-house utilities started from Documents",
      "Portable applications"
    ]
  },
  {
    "id": "PS-02",
    "name": "Autorun via script host or LOLBin",
    "description": "An autostart entry (Run key, Startup folder, scheduled task, service, WMI consumer, IFEO) resolves to a script host or LOLBin chain with tradecraft: PowerShell with an encoded command, hidden window, download cradle or Invoke-Expression; mshta with a URL or vbscript:/javascript:; rundll32/regsvr32 on a user-folder DLL, a URL or script code; wscript/cscript on a user-folder script; conhost --headless; AutoIt/Python/Node on a user-folder script; download tools. Domain logon scripts on SYSVOL/NETLOGON are excluded.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "high",
    "attack": [
      "T1547.001",
      "T1053.005",
      "T1059.001",
      "T1059.005",
      "T1218.005",
      "T1218.010",
      "T1218.011"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Remove the autostart entry (backed up), quarantine the user-folder script/DLL and kill the writer's tree when it is untrusted; alert only when a validly signed management tool wrote it",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/001/",
      "https://www.reliaquest.com/blog/threat-spotlight-clickfix-evolves-with-pysoxy-proxying/",
      "https://www.zscaler.com/blogs/security-research/analyzing-new-hijackloader-evasion-tactics",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml"
    ],
    "false_positives": [
      "RMM / management agents that schedule PowerShell (signed writer → alert only)",
      "Enterprise logon scripts outside SYSVOL/NETLOGON"
    ]
  },
  {
    "id": "PS-03",
    "name": "Startup-folder drop",
    "description": "A script, program or shortcut was created in a user or the common Startup folder by a process other than Explorer (user drag-and-drop) or a validly signed installer. Scripts and programs written by an untrusted or already-alerted process are high severity; shortcuts are alert-only until LNK targets are resolved.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "medium",
    "attack": [
      "T1547.001",
      "T1547.009"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Move the file to the quarantine vault and kill the writer's tree (scripts/programs from an untrusted writer only)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/001/",
      "https://attack.mitre.org/techniques/T1547/009/",
      "https://www.picussecurity.com/resource/press-release/red-report-2026-rise-of-digital-parasite"
    ],
    "false_positives": [
      "Applications that add their own shortcut to Startup from an unsigned helper",
      "Users copying scripts into Startup with a script host"
    ]
  },
  {
    "id": "PS-04",
    "name": "Startup folder redirection",
    "description": "The Startup or Common Startup location under User Shell Folders / Shell Folders was changed to a non-default path. Group Policy folder redirection (written by Windows components) is ignored.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "high",
    "attack": [
      "T1547.001"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Restore the default User Shell Folders value and kill an untrusted writer's tree",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/001/",
      "https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_asep_reg_keys_modification_currentversion.yml"
    ],
    "false_positives": [
      "Folder Redirection or roaming-profile tools not running as Windows components"
    ]
  },
  {
    "id": "PS-05",
    "name": "Scheduled task with untrusted action",
    "description": "A scheduled task was created or updated whose action runs a program in a user-writable folder that is not validly signed and not a known per-user updater, or a hidden task with a logon/boot trigger outside the Microsoft folder runs an untrusted program. Script-host/LOLBin actions are reported as PS-02.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "medium",
    "attack": [
      "T1053.005"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Export and delete the task, quarantine the payload and kill the creator's tree — only when the payload is known unsigned, was just dropped or downloaded, and the creator is untrusted or already alerted",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1053/005/",
      "https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/",
      "https://www.zscaler.com/blogs/security-research/analyzing-new-hijackloader-evasion-tactics"
    ],
    "false_positives": [
      "Per-user updater tasks (GoogleUpdater, Edge, OneDrive, Zoom) — suppressed by the baseline",
      "Admin or developer scripts scheduled from a user folder"
    ]
  },
  {
    "id": "PS-07",
    "name": "Suspicious service install",
    "description": "A service was installed (or its ImagePath written by something other than the Service Control Manager) whose binary lives in a user profile or Temp folder, that wraps cmd/PowerShell/mshta/rundll32/script hosts, that is a driver in a user-writable folder, or (alert only) that is unsigned or in ProgramData. Kestrel's own service is never targeted.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "high",
    "attack": [
      "T1543.003",
      "T1569.002"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Export the configuration, stop and disable the service, quarantine the binary and kill an untrusted creator's tree (user/Temp paths and interpreter wrappers only)",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1543/003/",
      "https://attack.mitre.org/techniques/T1569/002/"
    ],
    "false_positives": [
      "PsExec (PSEXESVC in %WINDIR%, not flagged)",
      "RMM agents, game anti-cheat and OEM utilities under ProgramData (alert only)"
    ]
  },
  {
    "id": "PS-08",
    "name": "WMI permanent event subscription",
    "description": "A permanent WMI event subscription was bound to a CommandLineEventConsumer or ActiveScriptEventConsumer (other consumer types are alert-only), or wmic / a PowerShell script created such a consumer. The built-in SCM Event Log consumer is ignored.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "critical",
    "attack": [
      "T1546.003"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Export the subscription (MOF), delete the binding, consumer and filter, quarantine a user-folder payload and kill an untrusted creator's tree",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1546/003/",
      "https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/builtin/wmi/win_wmi_persistence.yml",
      "https://cybertriage.com/?p=27530"
    ],
    "false_positives": [
      "OEM management agents (HP, Dell) and SCCM that use command-line consumers — add a per-tenant exclusion"
    ]
  },
  {
    "id": "PS-09",
    "name": "IFEO / SilentProcessExit hijack",
    "description": "An Image File Execution Options Debugger value or a SilentProcessExit MonitorProcess was set, so starting (or exiting) a program runs another one. Accessibility binaries (sethc, utilman, osk, …), security tools and browsers are high value; user-folder, unsigned or script-host debuggers are acted on. LSASS targets belong to CD-07.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "high",
    "attack": [
      "T1546.012",
      "T1546.008"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Delete the value (backed up), quarantine a user-folder debugger and kill an untrusted writer's tree",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1546/012/",
      "https://attack.mitre.org/techniques/T1546/008/"
    ],
    "false_positives": [
      "Process Explorer replacing Task Manager (signed, not flagged)",
      "Visual Studio JIT debugging",
      "Application-control tools that block programs through IFEO"
    ]
  },
  {
    "id": "PS-10",
    "name": "Winlogon / AppInit / AppCert / BootExecute change",
    "description": "Winlogon Userinit or Shell (HKLM or HKCU, or the policy Shell) differs from the Windows default, BootExecute contains an entry other than autocheck autochk, or a DLL was added to AppInit_DLLs / AppCertDlls (alert only). Defaults: Userinit = <drive>:\\Windows\\system32\\userinit.exe, Shell = explorer.exe, BootExecute = autocheck autochk * [verify on a clean VM].",
    "kind": "builtin",
    "category": "persistence",
    "severity": "critical",
    "attack": [
      "T1547.004",
      "T1546.010",
      "T1546.009",
      "T1547.001"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Restore the Windows default (Userinit, Shell, BootExecute) or delete the HKCU override, and kill an untrusted writer's tree; AppInit/AppCert alert only",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/004/",
      "https://attack.mitre.org/techniques/T1546/010/",
      "https://attack.mitre.org/techniques/T1546/009/"
    ],
    "false_positives": [
      "Kiosk / Shell Launcher shells and Citrix/VDI Userinit additions (exclude via policy)",
      "Security products using AppInit_DLLs",
      "Disk tools adding BootExecute entries"
    ]
  },
  {
    "id": "PS-11",
    "name": "COM hijack in user hive",
    "description": "A per-user COM registration (HKCU\\Software\\Classes\\CLSID\\{…}\\InprocServer32/LocalServer32/TreatAs or ScriptletURL) points at a server in a user-writable folder that is not validly signed, at a LOLBin chain or at a scriptlet URL. Per-user entries override machine-wide ones. Whether the CLSID also exists in HKLM is not checked yet.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "medium",
    "attack": [
      "T1546.015"
    ],
    "default_mode": "audit",
    "protect_day_one": false,
    "protect_action": "Delete the per-user COM value (backed up), quarantine the DLL and kill an untrusted writer's tree — only for a known-unsigned, just-dropped or downloaded server written by an untrusted process",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1546/015/",
      "https://specterops.io/blog/2025/05/28/revisiting-com-hijacking/"
    ],
    "false_positives": [
      "OneDrive, Dropbox, Google Drive and Teams per-user shell extensions (signed / baseline)",
      "Developer COM registrations (regsvr32 /n /i:user)"
    ]
  },
  {
    "id": "PS-15",
    "name": "Persistence rollback",
    "description": "Kestrel remembers the autostart entries each process creates. When a Protect-mode detection that kills a process tree fires (e.g. ST-02, ST-04, ST-16, RW/CD rules, or a PS rule that killed the writer), every autostart entry created by that tree is removed, even if the PS rule alone only alerted. Entries the tree creates afterwards are removed as they appear.",
    "kind": "builtin",
    "category": "persistence",
    "severity": "high",
    "attack": [
      "T1547",
      "T1053"
    ],
    "default_mode": "protect",
    "protect_day_one": true,
    "protect_action": "Remove every autostart entry the stopped tree created (backed up) and quarantine their user-folder payloads",
    "author": "Kestrel Labs",
    "license": "Apache-2.0",
    "references": [
      "https://attack.mitre.org/techniques/T1547/001/",
      "https://attack.mitre.org/techniques/T1053/005/"
    ],
    "false_positives": [
      "Attribution of tasks/services/WMI subscriptions depends on the sensor; unattributed entries are never rolled back"
    ]
  }
]
