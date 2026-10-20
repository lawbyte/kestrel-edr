import type { RuleMeta } from '@/api/types'

const KESTREL = 'Kestrel Labs'
const LIC = 'Apache-2.0'

/** Builtin catalog, consistent with the v1 rule table in the research report. */
export const BUILTIN_RULES: RuleMeta[] = [
  {
    id: 'ST-01',
    name: 'Credential-store read by untrusted process',
    description:
      'A process that is not the owning application opened a browser, wallet, messenger or cloud-token store. Fires when the reader is unsigned, signed by a publisher that is not allow-listed, or runs from a user-writable folder.',
    kind: 'builtin',
    category: 'credential_access',
    severity: 'high',
    attack: ['T1555.003', 'T1539', 'T1552.001'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Suspend the process while the agent decides (suspend-on-suspicion window)',
    author: KESTREL,
    license: LIC,
    references: ['https://detection.fyi/sigmahq/sigma/windows/file/file_access/file_access_win_browser_credential_access/'],
    false_positives: ['Password managers importing from the browser', 'Backup and sync tools', 'CCleaner / BleachBit', 'SCCM / Intune inventory'],
  },
  {
    id: 'ST-02',
    name: 'Smash-and-grab collection',
    description: 'One process touched three or more distinct credential categories (for example browser, Telegram and wallets) within 60 seconds.',
    kind: 'builtin',
    category: 'credential_access',
    severity: 'critical',
    attack: ['T1555.003', 'T1005', 'T1119'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the process tree and block its network access',
    author: KESTREL,
    license: LIC,
    references: ['https://www.elastic.co/security-labs/detect-credential-access'],
    false_positives: ['Full-profile backup tools (exclude by signer)'],
  },
  {
    id: 'ST-03',
    name: 'Foreign DPAPI decrypt of browser secrets',
    description:
      'DPAPI was asked to decrypt a blob described as Chrome, Edge, Opera or Brave by a process other than the browser or its elevation service. Needs the DPAPI audit channel (hardening).',
    kind: 'builtin',
    category: 'credential_access',
    severity: 'high',
    attack: ['T1555.003', 'T1555.004'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Suspend the process',
    author: KESTREL,
    license: LIC,
    references: ['https://security.googleblog.com/2024/04/detecting-browser-data-theft-using.html'],
    false_positives: ['Password managers with browser import', 'Browser migration tools'],
  },
  {
    id: 'ST-04',
    name: 'Steal-then-send',
    description:
      'The same process read credential stores or decrypted browser secrets and then opened an external connection within five minutes. Treat as a probable credential compromise even when the agent stopped it.',
    kind: 'builtin',
    category: 'exfiltration',
    severity: 'critical',
    attack: ['T1041', 'T1555.003', 'T1539'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the process tree, block the destination and quarantine the program',
    author: KESTREL,
    license: LIC,
    references: ['https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/'],
    false_positives: [],
  },
  {
    id: 'ST-05',
    name: 'Browser launched for remote debugging',
    description:
      'Chrome, Edge or Brave was started with --remote-debugging together with a throwaway profile, --headless or an off-screen window, by something other than Explorer. Used to bypass App-Bound Encryption and dump cookies.',
    kind: 'builtin',
    category: 'browser_tampering',
    severity: 'high',
    attack: ['T1539', 'T1185'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Kill the browser child and its parent',
    author: KESTREL,
    license: LIC,
    references: [
      'https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_browsers_chromium_headless_debugging/',
      'https://developer.chrome.com/blog/remote-debugging-port',
    ],
    false_positives: ['Web test automation (Playwright, Puppeteer, Selenium) on developer machines'],
  },
  {
    id: 'ST-06',
    name: 'Local DevTools client',
    description: 'A non-browser process connected to a loopback browser debugging port such as 9222.',
    kind: 'builtin',
    category: 'browser_tampering',
    severity: 'high',
    attack: ['T1539'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Kill the connecting process',
    author: KESTREL,
    license: LIC,
    references: ['https://www.elastic.co/security-labs/katz-and-mouse-game'],
    false_positives: ['IDE debuggers and test runners'],
  },
  {
    id: 'ST-07',
    name: 'Browser process tampering',
    description:
      'An untrusted process opened a browser with memory read/write or thread-creation rights, injected a thread, attached a debugger or changed a thread context. Covers the in-browser cookie theft and VoidStealer-style key capture techniques.',
    kind: 'builtin',
    category: 'browser_tampering',
    severity: 'critical',
    attack: ['T1055', 'T1539', 'T1555.003'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the tampering process',
    author: KESTREL,
    license: LIC,
    references: ['https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/', 'https://www.gendigital.com/blog/insights/research/voidstealer-abe-bypass'],
    false_positives: ['Accessibility and screen-reader software (exclude by signer)'],
  },
  {
    id: 'ST-08',
    name: 'Browser elevation-service abuse',
    description: 'Several chrome.exe processes were terminated and elevation_service.exe started within a second, or an unsigned program ran from the Chrome application folder.',
    kind: 'builtin',
    category: 'browser_tampering',
    severity: 'high',
    attack: ['T1555.003'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Kill the process',
    author: KESTREL,
    license: LIC,
    references: ['https://www.elastic.co/security-labs/katz-and-mouse-game'],
    false_positives: ['Chrome updates'],
  },
  {
    id: 'ST-09',
    name: 'Firefox crypto library loaded by another program',
    description: 'nss3.dll was loaded by a process that is not a Mozilla product, typically to decrypt Firefox logins.',
    kind: 'builtin',
    category: 'credential_access',
    severity: 'medium',
    attack: ['T1555.003'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only',
    author: KESTREL,
    license: LIC,
    references: ['https://iimp0ster.github.io/detection-chokepoints/chokepoints/browser-credential-theft/'],
    false_positives: ['Thunderbird portable builds', 'Password managers importing Firefox logins'],
  },
  {
    id: 'ST-10',
    name: 'ClickFix Run-dialog artefact',
    description: 'Explorer wrote a RunMRU or TypedPaths value that launches PowerShell, mshta, curl, conhost or a download cradle: someone pasted a command into Win+R or the address bar.',
    kind: 'builtin',
    category: 'delivery',
    severity: 'high',
    attack: ['T1204.004', 'T1059.001'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the spawned command chain',
    author: KESTREL,
    license: LIC,
    references: ['https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/'],
    false_positives: ['Admins running scripts from Win+R'],
  },
  {
    id: 'ST-11',
    name: 'Paste-and-run process chain',
    description:
      'Explorer, a browser or Windows Terminal started a shell or LOLBin with a "# I am not a robot"-style comment, hidden window, base64 or download cradle.',
    kind: 'builtin',
    category: 'execution',
    severity: 'high',
    attack: ['T1204.004', 'T1059.001', 'T1218.005'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the process tree',
    author: KESTREL,
    license: LIC,
    references: ['https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_clickfix_filefix_execution/'],
    false_positives: ['Login scripts that use hidden PowerShell windows'],
  },
  {
    id: 'ST-12',
    name: 'Untrusted program run from a user folder',
    description:
      'An unsigned, self-signed or never-seen executable ran from Temp, AppData, Downloads or an archive folder. Severity is raised for files over 100 MB or with Mark-of-the-Web.',
    kind: 'builtin',
    category: 'execution',
    severity: 'medium',
    attack: ['T1204.002', 'T1036'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Suspend pending verdict (opt-in)',
    author: KESTREL,
    license: LIC,
    references: ['https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/'],
    false_positives: ['Per-user installers (Zoom, Teams, VS Code)', 'Portable tools used by IT'],
  },
  {
    id: 'ST-13',
    name: '.NET LOLBin hollowing',
    description: 'MSBuild, RegAsm, RegSvcs or InstallUtil started with an unusual parent or no project file and then made external connections.',
    kind: 'builtin',
    category: 'execution',
    severity: 'high',
    attack: ['T1127.001', 'T1218.009', 'T1055.012'],
    default_mode: 'protect',
    protect_day_one: false,
    protect_action: 'Kill the process',
    author: KESTREL,
    license: LIC,
    references: ['https://www.nextron-systems.com/2025/05/23/katz-stealer-threat-analysis/'],
    false_positives: ['Developer builds started from IDEs'],
  },
  {
    id: 'ST-14',
    name: 'Dead-drop or exfil service from a non-browser',
    description:
      'A program that is not a browser resolved or connected to Telegram API, Steam profile pages, Discord webhooks, blockchain RPC (port 8545), IP-lookup or file-drop services.',
    kind: 'builtin',
    category: 'exfiltration',
    severity: 'high',
    attack: ['T1102.001', 'T1567', 'T1041'],
    default_mode: 'protect',
    protect_day_one: false,
    protect_action: 'Block network access for that program',
    author: KESTREL,
    license: LIC,
    references: [
      'https://detection.fyi/sigmahq/sigma/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access',
      'https://www.intrinsec.com/wp-content/uploads/2025/09/TLP-CLEAR-Sept-2025-Acreed-infostealer-EN.pdf',
    ],
    false_positives: ['Telegram Desktop', 'Steam client', 'Discord client', 'Crypto wallet apps'],
  },
  {
    id: 'ST-15',
    name: 'Trusted binary sideloaded from a user folder',
    description: 'A Defender or Edge component ran outside its install folder and loaded MpClient.dll or msedge_elf.dll from next to itself.',
    kind: 'builtin',
    category: 'execution',
    severity: 'high',
    attack: ['T1574.002'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the process',
    author: KESTREL,
    license: LIC,
    references: ['https://unit42.paloaltonetworks.com/vidar-stealer-xmrig-miner-campaign-analysis/'],
    false_positives: [],
  },
  {
    id: 'ST-16',
    name: 'Canary tripwire',
    description: 'Something opened a decoy wallet folder, decoy browser profile or decoy cloud credentials file planted by the agent. Nothing legitimate reads these.',
    kind: 'builtin',
    category: 'tripwire',
    severity: 'critical',
    attack: ['T1555.003', 'T1005'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Kill the process tree, block its network and quarantine the image; isolate the host (Kestrel server stays reachable) only when the reader is unsigned or unknown and runs from a user-writable folder',
    author: KESTREL,
    license: LIC,
    references: [],
    false_positives: ['Full-profile backup agents (add a per-rule exclusion for ST-16)', 'Manual browsing of the decoy folder by an administrator'],
  },
  {
    id: 'TP-01',
    name: 'Telemetry session stopped',
    description: "Kestrel's ETW session was stopped or a provider was disabled outside the agent.",
    kind: 'builtin',
    category: 'tamper',
    severity: 'critical',
    attack: ['T1562.006'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Restart the session and raise a critical alert',
    author: KESTREL,
    license: LIC,
    references: [],
    false_positives: [],
  },
  {
    id: 'TP-02',
    name: 'Network filter added against the agent',
    description: 'A WFP filter that affects the Kestrel agent was added (Security events 5446–5450), as EDRSilencer-style tools do.',
    kind: 'builtin',
    category: 'tamper',
    severity: 'high',
    attack: ['T1562.004'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Remove the filter and alert',
    author: KESTREL,
    license: LIC,
    references: ['https://blog.scrt.ch/2025/08/25/blinding-edrs-a-deep-dive-into-wfp-manipulation/'],
    false_positives: ['Third-party firewalls reconfiguring'],
  },
  {
    id: 'TP-03',
    name: 'AMSI provider changed',
    description: 'An AMSI provider was registered or removed, or AMSI FeatureBits were changed.',
    kind: 'builtin',
    category: 'tamper',
    severity: 'high',
    attack: ['T1562.001'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert',
    author: KESTREL,
    license: LIC,
    references: ['https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider'],
    false_positives: ['Antivirus installs and upgrades'],
  },
  {
    id: 'TP-04',
    name: 'Agent service configuration changed',
    description: 'The Kestrel service configuration, binary or startup type was changed, or an uninstall was attempted without the uninstall token.',
    kind: 'builtin',
    category: 'tamper',
    severity: 'critical',
    attack: ['T1489', 'T1562.001'],
    default_mode: 'protect',
    protect_day_one: true,
    protect_action: 'Restore configuration and alert',
    author: KESTREL,
    license: LIC,
    references: [],
    false_positives: ['Approved upgrades through the signed updater'],
  },
  {
    id: 'TP-05',
    name: 'Heartbeat gap or event-rate collapse',
    description: 'The agent stopped reporting without a reboot, or its event rate fell sharply while the device stayed online.',
    kind: 'builtin',
    category: 'tamper',
    severity: 'medium',
    attack: ['T1562'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert (server-side)',
    author: KESTREL,
    license: LIC,
    references: [],
    false_positives: ['Sleep/hibernate on laptops', 'Network outages'],
  },
]

export const SIGMA_SAMPLE = `title: Suspicious ClickFix/FileFix execution pattern
id: d487ed4a-fd24-436d-a0b2-f4e95f7b2635
status: experimental
description: Detects a shell started from Explorer with a fake CAPTCHA comment in the command line.
author: SigmaHQ community
license: DRL-1.1
references:
  - https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_susp_clickfix_filefix_execution/
tags:
  - attack.execution
  - attack.t1204.004
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith: '\\explorer.exe'
  selection_cmd:
    CommandLine|contains: '#'
  selection_lure:
    CommandLine|contains:
      - 'robot'
      - 'captcha'
      - 'verification'
  condition: all of selection_*
falsepositives:
  - Unknown
level: high
`

export const CUSTOM_RULES: (RuleMeta & { source: string; enabled_custom: boolean })[] = [
  {
    id: 'SIG-4be03877',
    name: 'FileFix: shell spawned from a browser upload dialog',
    description: 'A browser spawned cmd or PowerShell with a "#" comment, typical of FileFix lures pasted into a file-upload dialog.',
    kind: 'sigma',
    category: 'custom',
    severity: 'high',
    attack: ['T1204.004'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (custom Sigma)',
    author: 'SigmaHQ community',
    license: 'DRL-1.1',
    references: ['https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_filefix_browsers'],
    false_positives: ['Unknown'],
    enabled_custom: true,
    source: SIGMA_SAMPLE.replace('Suspicious ClickFix/FileFix execution pattern', 'FileFix: shell spawned from a browser upload dialog'),
  },
  {
    id: 'SIG-c3dbbc9f',
    name: 'Telegram API accessed by a non-browser process',
    description: 'Network connection to api.telegram.org from a process that is not a known browser or Telegram client.',
    kind: 'sigma',
    category: 'custom',
    severity: 'medium',
    attack: ['T1102'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (custom Sigma)',
    author: 'SigmaHQ community',
    license: 'DRL-1.1',
    references: ['https://detection.fyi/sigmahq/sigma/windows/network_connection/net_connection_win_domain_telegram_api_non_browser_access'],
    false_positives: ['Legitimate Telegram bots and integrations'],
    enabled_custom: true,
    source: SIGMA_SAMPLE.replace('Suspicious ClickFix/FileFix execution pattern', 'Telegram API accessed by a non-browser process'),
  },
  {
    id: 'SIG-7a1e09d2',
    name: 'Finance share: archive extracted and executed',
    description: 'In-house rule: executable started from a 7-Zip or WinRAR extraction folder on finance laptops.',
    kind: 'sigma',
    category: 'custom',
    severity: 'medium',
    attack: ['T1204.002'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (custom Sigma)',
    author: 'Marcus Lim',
    license: null,
    references: [],
    false_positives: ['Vendor tools shipped as zip files'],
    enabled_custom: false,
    source: SIGMA_SAMPLE.replace('Suspicious ClickFix/FileFix execution pattern', 'Finance share: archive extracted and executed').replace('SigmaHQ community', 'Marcus Lim'),
  },
]

const PACK_COMMIT = 'e3f466211866e92553d8389d621ed13cfed5523d'
const upstream = (file: string) => `https://github.com/SigmaHQ/sigma/blob/${PACK_COMMIT}/${file}`
const packSource = (id: string, title: string, author: string, level: string, body: string) => `title: ${title}
id: ${id}
status: stable
author: ${author}
logsource:
${body}
level: ${level}
`

/** A few rules of the SigmaHQ Audit pack the server seeds (DRL 1.1, pinned upstream link first). */
export const PACK_RULES: (RuleMeta & { source: string; enabled_custom: boolean })[] = [
  {
    id: 'SIG-c947b146',
    name: 'Shadow Copies Deletion Using Operating Systems Utilities',
    description: 'Shadow copies deleted with operating-system utilities (vssadmin, wmic, diskshadow, wbadmin). Corroborates RW-01.',
    kind: 'sigma',
    category: 'ransomware',
    severity: 'high',
    attack: ['T1070', 'T1490'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (SigmaHQ pack; RW-01 owns Protect)',
    author: 'Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)',
    license: 'DRL-1.1',
    references: [upstream('rules/windows/process_creation/proc_creation_win_susp_shadow_copies_deletion.yml'), 'https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment'],
    false_positives: ['Legitimate Administrator deletes Shadow Copies using operating systems utilities for legitimate reason', 'LANDesk LDClient Ivanti-PSModule'],
    enabled_custom: true,
    source: packSource('c947b146-0abc-4c87-9c64-b17e9d7274a2', 'Shadow Copies Deletion Using Operating Systems Utilities', 'Florian Roth (Nextron Systems), Michael Haag, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community, Andreas Hunkeler (@Karneades)', 'high', String.raw`  category: process_creation
  product: windows
detection:
  selection1_img:
    Image|endswith:
      - '\vssadmin.exe'
      - '\wmic.exe'
  selection1_cli:
    CommandLine|contains|all:
      - 'shadow'
      - 'delete'
  condition: all of selection1_*`),
  },
  {
    id: 'SIG-646ea171',
    name: 'Process Memory Dump Via Comsvcs.DLL',
    description: 'rundll32 calls the MiniDump export of comsvcs.dll, a common way to dump LSASS memory. Corroborates CD-01.',
    kind: 'sigma',
    category: 'credential_dumping',
    severity: 'high',
    attack: ['T1036', 'T1003.001'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (SigmaHQ pack; CD-01 owns Protect)',
    author: 'Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)',
    license: 'DRL-1.1',
    references: [upstream('rules/windows/process_creation/proc_creation_win_rundll32_process_dump_via_comsvcs.yml'), 'https://modexp.wordpress.com/2019/08/30/minidumpwritedump-via-com-services-dll/'],
    false_positives: ['Unlikely'],
    enabled_custom: true,
    source: packSource('646ea171-dded-4578-8a4d-65e9822892e3', 'Process Memory Dump Via Comsvcs.DLL', 'Florian Roth (Nextron Systems), Modexp, Nasreddine Bencherchali (Nextron Systems), Swachchhanda Shrawan Poudel (Nextron Systems)', 'high', String.raw`  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: '\rundll32.exe'
  selection_cli:
    CommandLine|contains|all:
      - 'comsvcs'
      - 'full'
  condition: all of selection_*`),
  },
  {
    id: 'SIG-9c5037d1',
    name: 'Suspicious Run Key from Download',
    description: 'A Run key value points to a program in a download or temp folder.',
    kind: 'sigma',
    category: 'persistence',
    severity: 'high',
    attack: ['T1547.001'],
    default_mode: 'audit',
    protect_day_one: false,
    protect_action: 'Alert only (SigmaHQ pack)',
    author: 'Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems)',
    license: 'DRL-1.1',
    references: [upstream('rules/windows/registry/registry_event/registry_event_susp_download_run_key.yml')],
    false_positives: ['Software installers downloaded and used by users'],
    enabled_custom: true,
    source: packSource('9c5037d1-c568-49b3-88c7-9846a5bdc2be', 'Suspicious Run Key from Download', 'Florian Roth (Nextron Systems), Swachchhanda Shrawan Poude (Nextron Systems)', 'high', String.raw`  category: registry_event
  product: windows
detection:
  selection:
    Image|contains:
      - '\Downloads\'
      - '\Temporary Internet Files\Content.Outlook\'
    TargetObject|contains: '\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\'
  condition: selection`),
  },
]
