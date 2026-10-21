import type { Device, DeviceEvent, KEvent, ProcessInfo } from '@/api/types'
import { pathClassOf } from '@/lib/pathclass'
import { mulberry32 } from './rng'
import { HOUR, NOW } from './fleet'

/** Lazily generated, deterministic background telemetry for one device. */
export interface DeviceTelemetry {
  events: DeviceEvent[]
  procs: Map<string, ProcessInfo>
}

interface Proto {
  image: string
  cmd: string
  signer: string
  parent: 'services' | 'explorer' | 'svchost'
  dns?: string[]
  files?: string[]
  loads?: string[]
}

const PROTOS: Proto[] = [
  { image: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', cmd: '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', signer: 'Google LLC', parent: 'explorer', dns: ['mail.google.com', 'www.google.com', 'harbourline.sharepoint.com', 'accounts.google.com', 'fonts.gstatic.com'], files: ['Network\\Cookies', 'History'] },
  { image: 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe', cmd: '"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe" --profile-directory=Default', signer: 'Microsoft Corporation', parent: 'explorer', dns: ['login.microsoftonline.com', 'www.bing.com', 'harbourline.sharepoint.com'] },
  { image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', cmd: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"', signer: 'Microsoft Corporation', parent: 'explorer', dns: ['outlook.office365.com', 'substrate.office.com'] },
  { image: 'C:\\Program Files\\WindowsApps\\MSTeams_25275.2601.4002.1924_x64__8wekyb3d8bbwe\\ms-teams.exe', cmd: 'ms-teams.exe', signer: 'Microsoft Corporation', parent: 'explorer', dns: ['teams.microsoft.com', 'teams.events.data.microsoft.com'] },
  { image: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE', cmd: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /dde', signer: 'Microsoft Corporation', parent: 'explorer' },
  { image: 'C:\\Windows\\System32\\svchost.exe', cmd: 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s wuauserv', signer: 'Microsoft Windows', parent: 'services', dns: ['fe3cr.delivery.mp.microsoft.com', 'settings-win.data.microsoft.com'] },
  { image: 'C:\\Windows\\System32\\SearchProtocolHost.exe', cmd: '"C:\\Windows\\system32\\SearchProtocolHost.exe" Global\\UsGthrFltPipeMssGthrPipe1', signer: 'Microsoft Windows', parent: 'svchost' },
  { image: 'C:\\Program Files\\Zoom\\bin\\Zoom.exe', cmd: '"C:\\Program Files\\Zoom\\bin\\Zoom.exe"', signer: 'Zoom Communications, Inc.', parent: 'explorer', dns: ['zoom.us', 'us05web.zoom.us'] },
  { image: 'C:\\Windows\\System32\\taskhostw.exe', cmd: 'taskhostw.exe', signer: 'Microsoft Windows', parent: 'svchost' },
  { image: 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25090.3009-0\\MsMpEng.exe', cmd: '"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.25090.3009-0\\MsMpEng.exe"', signer: 'Microsoft Windows', parent: 'services', dns: ['wdcp.microsoft.com'] },
  { image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', cmd: 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File \\\\harbourline.local\\NETLOGON\\map-drives.ps1', signer: 'Microsoft Windows', parent: 'explorer' },
]

const IPS: Record<string, string> = {}
function ipFor(host: string, r: () => number) {
  if (!IPS[host]) IPS[host] = `${[13, 20, 40, 52, 104, 142, 172][Math.floor(r() * 7)]}.${Math.floor(r() * 250)}.${Math.floor(r() * 250)}.${Math.floor(r() * 250)}`
  return IPS[host]
}

function seedOf(id: string) {
  let h = 2166136261
  for (let i = 0; i < id.length; i++) h = Math.imul(h ^ id.charCodeAt(i), 16777619)
  return h >>> 0
}

export function buildTelemetry(d: Device, storyEvents: KEvent[], storyProcs: ProcessInfo[]): DeviceTelemetry {
  const r = mulberry32(seedOf(d.id))
  const ri = (a: number, b: number) => Math.floor(a + r() * (b - a + 1))
  const procs = new Map<string, ProcessInfo>()
  const events: DeviceEvent[] = []
  const user = d.logged_on_user
  const boot = NOW - (d.health.uptime_s ?? 86400) * 1000
  const mk = (image: string, cmd: string, signer: string, parent: ProcessInfo | null, start: number, u: string | null, exit?: number): ProcessInfo => {
    const guid = Array.from({ length: 32 }, () => Math.floor(r() * 16).toString(16)).join('')
    const p: ProcessInfo = {
      guid,
      pid: ri(300, 20000) & ~3,
      ppid: parent?.pid ?? 4,
      parent_guid: parent?.guid ?? null,
      image,
      cmdline: cmd,
      user: u,
      integrity: u ? 'medium' : 'system',
      start_ts: start,
      exit_ts: exit ?? null,
      signer,
      signed: 'valid',
      sha256: Array.from({ length: 64 }, () => Math.floor(r() * 16).toString(16)).join(''),
      motw_zone: null,
      file_size: ri(200_000, 40_000_000),
      path_class: pathClassOf(image),
    }
    procs.set(guid, p)
    return p
  }
  const services = mk('C:\\Windows\\System32\\services.exe', 'C:\\Windows\\system32\\services.exe', 'Microsoft Windows', null, boot, 'NT AUTHORITY\\SYSTEM')
  const svchost = mk('C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p', 'Microsoft Windows', services, boot + 2000, 'NT AUTHORITY\\SYSTEM')
  const agent = mk('C:\\Program Files\\Kestrel\\kestrel-agent.exe', '"C:\\Program Files\\Kestrel\\kestrel-agent.exe" --service', 'Kestrel Labs Pte. Ltd.', services, boot + 3000, 'NT AUTHORITY\\SYSTEM')
  const explorer = user ? mk('C:\\Windows\\explorer.exe', 'C:\\Windows\\Explorer.EXE', 'Microsoft Windows', null, boot + 40_000, user) : null
  const home = `C:\\Users\\${(user ?? 'svc').split('\\').pop()}`
  const n = d.hostname.startsWith('SRV') ? 70 : 120
  for (let i = 0; i < n; i++) {
    const proto = PROTOS[ri(0, PROTOS.length - 1)]
    if (!explorer && proto.parent === 'explorer') continue
    const t = NOW - Math.floor(r() * 30 * HOUR)
    const parent = proto.parent === 'explorer' ? explorer : proto.parent === 'svchost' ? svchost : services
    const p = mk(proto.image, proto.cmd, proto.signer, parent, t, proto.parent === 'explorer' ? user : 'NT AUTHORITY\\SYSTEM', r() < 0.6 ? t + ri(10_000, 3 * HOUR) : undefined)
    events.push({ device_id: d.id, hostname: d.hostname, ts: t, pid: p.pid, guid: p.guid, type: 'process_start', ppid: p.ppid, parent_guid: p.parent_guid, image: p.image, cmdline: p.cmdline, user: p.user, integrity: p.integrity, session_id: 1, signer: p.signer, signed: 'valid', sha256: p.sha256, file_size: p.file_size })
    if (proto.loads || r() < 0.3)
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + 80, pid: p.pid, guid: p.guid, type: 'image_load', path: 'C:\\Windows\\System32\\crypt32.dll', signer: 'Microsoft Windows', signed: 'valid' })
    for (const q of proto.dns ?? []) {
      if (r() < 0.5) continue
      const dt = ri(200, 60_000)
      const ip = ipFor(q, r)
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + dt, pid: p.pid, guid: p.guid, type: 'dns_query', qname: q, answers: [ip] })
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + dt + 40, pid: p.pid, guid: p.guid, type: 'net_connect', proto: 'tcp', dst_ip: ip, dst_port: 443, src_port: ri(49152, 65000), dst_host: q, bytes_sent: ri(400, 90_000) })
    }
    for (const f of proto.files ?? []) {
      if (r() < 0.6) continue
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + ri(500, 4000), pid: p.pid, guid: p.guid, type: 'file_access', path: `${home}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\${f}`, op: 'read' })
    }
    if (proto.image.endsWith('chrome.exe') && r() < 0.3)
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + 1200, pid: p.pid, guid: p.guid, type: 'dpapi_unprotect', description: 'Google Chrome' })
    if (proto.image.endsWith('powershell.exe'))
      events.push({ device_id: d.id, hostname: d.hostname, ts: t + 900, pid: p.pid, guid: p.guid, type: 'script_block', engine: 'PowerShell', content: 'New-PSDrive -Name S -PSProvider FileSystem -Root \\\\SRV-FS-01\\Shared -Persist' })
  }
  if (r() < 0.4)
    events.push({ device_id: d.id, hostname: d.hostname, ts: NOW - ri(1, 20) * HOUR, pid: services.pid, guid: services.guid, type: 'registry_set', key: 'HKLM\\SOFTWARE\\Policies\\Google\\Chrome', value_name: 'RemoteDebuggingAllowed', data: '0' })
  // The agent's own hardening run: a direct child it recorded spawning (agent_spawned).
  {
    const t = NOW - ri(2, 26) * HOUR
    const hp = mk('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', 'powershell.exe -NoProfile -NonInteractive -Command "Add-MpPreference -AttackSurfaceReductionRules_Ids 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 -AttackSurfaceReductionRules_Actions Enabled"', 'Microsoft Windows', agent, t, 'NT AUTHORITY\\SYSTEM', t + 2_400)
    events.push({ device_id: d.id, hostname: d.hostname, ts: t, pid: hp.pid, guid: hp.guid, type: 'process_start', ppid: hp.ppid, parent_guid: hp.parent_guid, image: hp.image, cmdline: hp.cmdline, user: hp.user, integrity: 'system', session_id: 0, signer: hp.signer, signed: 'valid', sha256: hp.sha256, file_size: hp.file_size, agent_spawned: true })
  }
  // File server: a client rewrote files over SMB, so the writer is the System process (pid 4).
  if (d.hostname === 'SRV-FS-01') {
    events.push({
      device_id: d.id,
      hostname: d.hostname,
      ts: NOW - 3 * HOUR - 12 * 60_000,
      pid: 4,
      guid: '',
      type: 'file_activity',
      window_ms: 10_000,
      files_touched: 96,
      dirs: 11,
      renames: 0,
      overwrites: 96,
      new_files: 0,
      net_paths: 0,
      sample_paths: ['D:\\Shared\\Warehouse\\Q3\\stock_count.xlsx', 'D:\\Shared\\Warehouse\\Q3\\pallets.csv'],
      remote_writer: true,
    })
  }
  for (const p of storyProcs) procs.set(p.guid, p)
  for (const e of storyEvents) events.push({ ...e, device_id: d.id, hostname: d.hostname })
  events.sort((a, b) => b.ts - a.ts)
  return { events, procs }
}
