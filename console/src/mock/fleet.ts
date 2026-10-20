import type { AgentHealth, Device, Group, Inventory, Policy, PolicySummary, RuleMode, Software, User } from '@/api/types'
import { HARDENING_CONTROLS } from '@/lib/labels'
import { chance, int, pick, rand, uuid } from './rng'

export const NOW = Date.now()
export const MIN = 60_000
export const HOUR = 60 * MIN
export const DAY = 24 * HOUR

export const ORG = 'Harbourline Logistics'
export const DOMAIN = 'HARBOURLINE'

function user(name: string, email: string, role: string, o: Partial<User> = {}): User {
  return {
    id: uuid(),
    name,
    email,
    role,
    last_login: NOW - int(1, 30) * HOUR,
    created_at: NOW - int(60, 300) * DAY,
    disabled: false,
    mfa_enabled: true,
    ...o,
  }
}

export const USERS: User[] = [
  user('Priya Raman', 'priya.raman@harbourline.sg', 'admin', { last_login: NOW - 20 * MIN }),
  user('Daniel Tan', 'daniel.tan@harbourline.sg', 'analyst'),
  user('Nur Aisyah Rahman', 'aisyah.rahman@harbourline.sg', 'analyst'),
  user('Marcus Lim', 'marcus.lim@harbourline.sg', 'admin', { mfa_enabled: true }),
  user('Ong Wei Ling', 'weiling.ong@harbourline.sg', 'readonly', { mfa_enabled: false }),
  user('Budi Santoso', 'budi.santoso@harbourline.co.id', 'analyst', { disabled: true, last_login: NOW - 64 * DAY }),
]
export const [PRIYA, DANIEL, AISYAH, MARCUS] = USERS

// ------------------------------------------------------------------ policies

export const DEFAULT_PRIVACY_NOTICE = `## What Kestrel monitors on this laptop

Harbourline uses **Kestrel EDR** to stop malware that steals passwords and browser sessions.

**What is collected:** names and command lines of programs that run, which programs open browser and wallet data folders, network destinations, and security alerts.

**What is never collected:** the contents of your files, emails or chats, screenshots, keystrokes, or your browsing history.

Data stays on Harbourline's own server in Singapore and is kept for 30 days (alerts for 1 year). Questions or access requests: contact IT below.`

function basePolicy(id: string, name: string, version: number): Policy {
  return {
    id,
    name,
    version,
    rules: {},
    suspend_window_ms: 3000,
    exclusions: [],
    iocs: [],
    hardening: {
      mode: 'audit',
      block_mshta: true,
      block_user_path_exec: false,
      disable_run_dialog: false,
      terminal_paste_warning: true,
      script_block_logging: true,
      dpapi_debug_channel: true,
      asr_rules: true,
      browser_disable_remote_debugging: true,
      wdigest_off: true,
      asr_lsass: true,
      lsa_protection: false,
      report_vulnerable_driver_blocklist: true,
      task_scheduler_log: true,
    },
    sensors: { file_activity: true, ransomware_canaries: true, persistence: true, credential_access: true },
    privacy: { capture_cmdline: true, hash_usernames: false, redact_path_prefixes: [], capture_dns: true, capture_script_content: true },
    telemetry: { upload_events: true, event_kinds: [], max_outbox_mb: 1024 },
    canaries: true,
    branding: {
      org_name: ORG,
      it_contact: { name: 'Harbourline IT Service Desk', email: 'itsupport@harbourline.sg', phone: '+65 6123 4567', url: 'https://it.harbourline.sg' },
      privacy_notice_md: DEFAULT_PRIVACY_NOTICE,
    },
    exfil_domains: [
      'api.telegram.org',
      'steamcommunity.com',
      'discord.com/api/webhooks',
      'discordapp.com/api/webhooks',
      'ip-api.com',
      'ipinfo.io',
      'api.ipify.org',
      'r2.dev',
      'pastebin.com',
      'gofile.io',
      'transfer.sh',
      'file.io',
      'trycloudflare.com',
      'bsc-dataseed.binance.org',
      'bsc-dataseed1.binance.org',
      'rpc.ankr.com',
    ],
    isolation_auto_release_hours: 72,
    ioc_block_ttl_secs: 24 * 3600,
    ioc_block_host_wide: false,
  }
}

const pDefault = basePolicy('pol-default', 'Default', 14)
pDefault.rules = { 'ST-10': 'audit', 'ST-11': 'audit' }

const pStrict = basePolicy('pol-finance', 'Finance & Executives (strict)', 9)
pStrict.rules = { 'ST-01': 'protect', 'ST-03': 'protect', 'ST-05': 'protect', 'ST-06': 'protect', 'ST-08': 'protect', 'ST-12': 'protect', 'ST-14': 'protect' }
pStrict.hardening = { ...pStrict.hardening, mode: 'enforce', block_user_path_exec: true, disable_run_dialog: true, lsa_protection: true }
pStrict.suspend_window_ms = 5000
pStrict.isolation_auto_release_hours = 24
pStrict.ioc_block_ttl_secs = 7 * 24 * 3600
pStrict.ioc_block_host_wide = true

const pEng = basePolicy('pol-eng', 'Engineering (developer friendly)', 6)
pEng.rules = { 'ST-05': 'audit', 'ST-06': 'off', 'ST-12': 'audit', 'ST-13': 'audit', 'ST-14': 'audit' }
pEng.hardening = { ...pEng.hardening, block_mshta: true, browser_disable_remote_debugging: false }
pEng.privacy = { ...pEng.privacy, redact_path_prefixes: ['C:\\Users\\*\\Documents\\Personal'] }

const pSrv = basePolicy('pol-servers', 'Servers', 3)
pSrv.rules = { 'ST-10': 'off', 'ST-11': 'protect', 'ST-12': 'protect' }
pSrv.hardening = { ...pSrv.hardening, mode: 'enforce', disable_run_dialog: true, block_user_path_exec: true }
pSrv.canaries = false
pSrv.hardening = { ...pSrv.hardening, lsa_protection: true }
pSrv.sensors = { file_activity: true, ransomware_canaries: false, persistence: true, credential_access: true }

export const POLICIES: Policy[] = [pDefault, pStrict, pEng, pSrv]
export const POLICY_UPDATED: Record<string, number> = {
  'pol-default': NOW - 3 * DAY,
  'pol-finance': NOW - 9 * DAY,
  'pol-eng': NOW - 16 * DAY,
  'pol-servers': NOW - 40 * DAY,
}

export function policySummary(p: Policy, groups: Group[], devices: Device[]): PolicySummary {
  return {
    id: p.id,
    name: p.name,
    version: p.version,
    updated_at: POLICY_UPDATED[p.id] ?? NOW,
    group_count: groups.filter((g) => g.policy_id === p.id).length,
    device_count: devices.filter((d) => d.policy_id === p.id).length,
  }
}

export function ruleModes(p: Policy, defaults: Record<string, RuleMode>): Record<string, RuleMode> {
  return { ...defaults, ...p.rules }
}

// ------------------------------------------------------------------ groups

export const GROUPS: Group[] = [
  { id: 'grp-fin', name: 'Finance', description: 'Finance and treasury laptops', policy_id: 'pol-finance', device_count: 0 },
  { id: 'grp-exec', name: 'Executives', description: 'C-suite and their assistants', policy_id: 'pol-finance', device_count: 0 },
  { id: 'grp-hr', name: 'HR', description: 'People team', policy_id: 'pol-default', device_count: 0 },
  { id: 'grp-sales', name: 'Sales', description: 'Account managers (often travelling)', policy_id: 'pol-default', device_count: 0 },
  { id: 'grp-ops', name: 'Operations', description: 'Warehouse and dispatch desktops', policy_id: 'pol-default', device_count: 0 },
  { id: 'grp-mkt', name: 'Marketing', description: 'Marketing and design', policy_id: 'pol-default', device_count: 0 },
  { id: 'grp-eng', name: 'Engineering', description: 'Developers and data team', policy_id: 'pol-eng', device_count: 0 },
  { id: 'grp-it', name: 'IT', description: 'IT administrators', policy_id: 'pol-default', device_count: 0 },
  { id: 'grp-srv', name: 'Servers', description: 'File, print and app servers', policy_id: 'pol-servers', device_count: 0 },
]

// ------------------------------------------------------------------ devices

const FIRST = ['alicia.goh', 'benjamin.ng', 'chen.jiahui', 'dewi.lestari', 'eugene.koh', 'farah.aziz', 'gabriel.teo', 'hana.yusof', 'ivan.chua', 'jasmine.lee', 'kumar.s', 'lim.boonkiat', 'mei.tan', 'nadia.ismail', 'oliver.sim', 'putri.wulandari', 'qing.huang', 'rahul.menon', 'sarah.wong', 'tommy.lau', 'umar.hakim', 'vanessa.ho', 'wahyu.pratama', 'xin.yi', 'yusuf.rahman', 'zara.lim', 'adrian.toh', 'bella.quek', 'clement.yeo', 'diana.chong', 'edwin.kwek', 'fiona.png', 'glenn.seah', 'helen.foo', 'irfan.said', 'joanne.liew', 'kelvin.ang', 'lydia.soh']

interface DevSpec {
  hostname: string
  group: string
  user: string | null
  os?: string
}

const specs: DevSpec[] = []
const add = (prefix: string, group: string, kinds: [string, number][]) => {
  for (const [kind, n] of kinds) specs.push({ hostname: `${prefix}-${kind}-${String(n).padStart(3, '0')}`, group, user: null })
}
add('FIN', 'grp-fin', [['LT', 14], ['LT', 3], ['LT', 8], ['DT', 2], ['LT', 21], ['LT', 30]])
add('EXE', 'grp-exec', [['LT', 1], ['LT', 2], ['LT', 5]])
add('HR', 'grp-hr', [['DT', 3], ['LT', 6], ['LT', 9], ['DT', 1], ['LT', 12]])
add('SAL', 'grp-sales', [['LT', 22], ['LT', 4], ['LT', 17], ['LT', 30], ['LT', 11]])
add('OPS', 'grp-ops', [['DT', 9], ['DT', 12], ['DT', 15], ['DT', 2], ['LT', 7], ['DT', 18]])
add('MKT', 'grp-mkt', [['LT', 5], ['LT', 8], ['DT', 1]])
add('ENG', 'grp-eng', [['LT', 11], ['DT', 7], ['LT', 3], ['LT', 19], ['LT', 24], ['DT', 2]])
add('IT', 'grp-it', [['LT', 2], ['LT', 4], ['DT', 1]])
specs.push({ hostname: 'SRV-FS-01', group: 'grp-srv', user: null, os: 'Windows Server 2022 Standard' })
specs.push({ hostname: 'SRV-APP-02', group: 'grp-srv', user: null, os: 'Windows Server 2025 Standard' })
specs.push({ hostname: 'SRV-PRT-01', group: 'grp-srv', user: null, os: 'Windows Server 2019 Standard' })

const OS = [
  ['Windows 11 Pro', '10.0.26100.6584'],
  ['Windows 11 Enterprise', '10.0.26100.6584'],
  ['Windows 11 Pro', '10.0.26200.6901'],
  ['Windows 10 Pro', '10.0.19045.6332'],
  ['Windows 11 Enterprise', '10.0.22631.5909'],
] as const
const SERVER_BUILD: Record<string, string> = {
  'Windows Server 2022 Standard': '10.0.20348.4171',
  'Windows Server 2025 Standard': '10.0.26100.6584',
  'Windows Server 2019 Standard': '10.0.17763.7792',
}

export function hardeningFor(p: Policy, drift: number): Record<string, boolean> {
  const out: Record<string, boolean> = {}
  for (const c of HARDENING_CONTROLS) {
    const desired = p.hardening[c]
    out[c] = desired && p.hardening.mode !== 'off' ? !(rand() < drift) : false
  }
  // LSA protection only takes effect after a reboot: about a third of devices are still waiting.
  if (p.hardening.lsa_protection && p.hardening.mode === 'enforce' && rand() < 0.35) {
    out.lsa_protection = false
    out.lsa_protection_pending_reboot = true
  }
  // Report-only: whether Windows has the vulnerable-driver blocklist on.
  if (p.hardening.report_vulnerable_driver_blocklist) out.report_vulnerable_driver_blocklist = rand() < 0.8
  return out
}

export function buildDevices(): Device[] {
  let ui = 0
  return specs.map((s, i) => {
    const g = GROUPS.find((x) => x.id === s.group)!
    const pol = POLICIES.find((p) => p.id === g.policy_id)!
    const isServer = s.hostname.startsWith('SRV')
    const [osName, osBuild] = isServer ? [s.os!, SERVER_BUILD[s.os!]] : pick(OS)
    const uname = isServer ? null : `${DOMAIN}\\${FIRST[ui++ % FIRST.length]}`
    const r = rand()
    let lastSeen = NOW - int(5, 90) * 1000
    if (r < 0.1) lastSeen = NOW - int(20, 60 * 40) * MIN
    const etwOk = !(i === 17 || i === 33)
    const health: AgentHealth = {
      etw_ok: etwOk,
      etw_events_lost: etwOk ? (chance(0.2) ? int(1, 40) : 0) : int(1200, 8000),
      etw_buffers_lost: etwOk ? 0 : int(2, 30),
      events_per_min: isServer ? int(900, 2600) : int(140, 720),
      outbox_depth: lastSeen < NOW - 3 * MIN ? int(200, 4000) : int(0, 12),
      sysmon_present: chance(0.35) || isServer,
      dpapi_channel_enabled: pol.hardening.dpapi_debug_channel && chance(0.93),
      amsi_ok: chance(0.97),
      isolated: false,
      hardening: hardeningFor(pol, 0.08),
      cpu_pct: Math.round((0.3 + rand() * 2.2) * 10) / 10,
      mem_mb: int(38, 96),
      uptime_s: int(3600, 3600 * 24 * 12),
      logged_on_user: uname,
      ip_addresses: [`10.${isServer ? 10 : 20 + (i % 6)}.${int(1, 40)}.${int(10, 250)}`],
      av_product: chance(0.85) ? 'Microsoft Defender Antivirus' : 'Sophos Endpoint',
    }
    const version = r > 0.88 ? '0.9.2' : r > 0.8 ? '0.9.4' : '1.0.1'
    return {
      id: uuid(),
      hostname: s.hostname,
      os_name: osName,
      os_build: osBuild,
      arch: 'x64',
      domain: 'harbourline.local',
      agent_version: version,
      status: 'online',
      last_seen: lastSeen,
      first_seen: NOW - int(30, 220) * DAY,
      ip_addresses: health.ip_addresses ?? [],
      logged_on_user: uname,
      group_id: g.id,
      group_name: g.name,
      policy_id: pol.id,
      policy_name: pol.name,
      policy_version_applied: chance(0.9) ? pol.version : pol.version - 1,
      tags: isServer ? ['server'] : s.hostname.includes('LT') ? ['laptop'] : ['desktop'],
      health,
      open_incidents: 0,
    } satisfies Device
  })
}

/** Contract status rule: isolated > offline (3 min) > degraded > online. */
export function computeStatus(d: Device): Device['status'] {
  if (d.health.isolated) return 'isolated'
  if (d.last_seen < Date.now() - 3 * MIN) return 'offline'
  if (!d.health.etw_ok || (d.health.etw_events_lost ?? 0) > 500) return 'degraded'
  return 'online'
}

// ------------------------------------------------------------------ inventory

const BASE_SW: Software[] = [
  { name: 'Google Chrome', version: '141.0.7390.108', publisher: 'Google LLC' },
  { name: 'Microsoft Edge', version: '141.0.3537.85', publisher: 'Microsoft Corporation' },
  { name: 'Microsoft 365 Apps for enterprise', version: '16.0.19231.20156', publisher: 'Microsoft Corporation' },
  { name: 'Microsoft Teams', version: '25275.2601.4002', publisher: 'Microsoft Corporation' },
  { name: 'Zoom Workplace', version: '6.6.2', publisher: 'Zoom Communications, Inc.' },
  { name: '7-Zip 25.01 (x64)', version: '25.01', publisher: 'Igor Pavlov' },
  { name: 'Adobe Acrobat Reader (64-bit)', version: '25.001.20844', publisher: 'Adobe' },
  { name: 'Kestrel EDR Agent', version: '1.0.1', publisher: 'Kestrel Labs' },
]
const DEPT_SW: Record<string, Software[]> = {
  'grp-fin': [
    { name: 'SAP GUI for Windows', version: '8.00 PL12', publisher: 'SAP SE' },
    { name: 'Xero Practice Manager Connector', version: '3.4.1', publisher: 'Xero' },
  ],
  'grp-eng': [
    { name: 'Microsoft Visual Studio Code', version: '1.105.1', publisher: 'Microsoft Corporation' },
    { name: 'Git', version: '2.51.1', publisher: 'The Git Development Community' },
    { name: 'Docker Desktop', version: '4.48.0', publisher: 'Docker Inc.' },
    { name: 'Python 3.13.8 (64-bit)', version: '3.13.8150.0', publisher: 'Python Software Foundation' },
    { name: 'Node.js', version: '22.20.0', publisher: 'Node.js Foundation' },
  ],
  'grp-mkt': [
    { name: 'Adobe Creative Cloud', version: '6.7.0.278', publisher: 'Adobe Inc.' },
    { name: 'Figma', version: '125.8.8', publisher: 'Figma, Inc.' },
  ],
  'grp-it': [
    { name: 'PuTTY release 0.83 (64-bit)', version: '0.83.0.0', publisher: 'Simon Tatham' },
    { name: 'WinSCP 6.5.4', version: '6.5.4', publisher: 'Martin Prikryl' },
    { name: 'SyncBackPro', version: '11.3.79.0', publisher: '2BrightSparks Pte Ltd' },
    { name: 'KeePassXC', version: '2.7.10', publisher: 'KeePassXC Team' },
  ],
}

export function inventoryFor(d: Device): Inventory {
  const sw = [...BASE_SW, ...(DEPT_SW[d.group_id ?? ''] ?? [])]
  if (d.hostname === 'SAL-LT-022') sw.push({ name: 'Telegram Desktop', version: '6.1.3', publisher: 'Telegram FZ-LLC' })
  return {
    software: sw.map((s) => (s.name === 'Kestrel EDR Agent' ? { ...s, version: d.agent_version } : s)).sort((a, b) => a.name.localeCompare(b.name)),
    local_admins: [`${DOMAIN}\\Domain Admins`, `${d.hostname}\\Administrator`, ...(d.group_id === 'grp-it' || d.group_id === 'grp-eng' ? [d.logged_on_user ?? ''] : [])].filter(Boolean),
  }
}
