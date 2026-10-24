/**
 * Small, dependency-free facts about Windows telemetry used by both the
 * one-line summaries (`describeEvent`) and the expanded explanations
 * (`explainEvent`). Everything here is plain text: callers render it as text
 * nodes, never as HTML.
 */

/** Kestrel's default dead-drop / exfiltration list (mirrors `default_exfil_domains` in kestrel-common/src/policy.rs). */
export const DEFAULT_EXFIL_DOMAINS = [
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
]

/** Why a dead-drop / exfiltration domain matters, by entry. */
function exfilWhy(entry: string): string {
  const e = entry.toLowerCase()
  if (e.includes('telegram')) return 'Stealers use the Telegram bot API to send stolen data, or read their server address from a Telegram channel (a "dead-drop").'
  if (e.includes('steamcommunity')) return 'Stealers such as Vidar hide their server address in a Steam profile name and read it from there (a "dead-drop").'
  if (e.includes('discord')) return 'Discord webhooks accept uploads without an account; stealers post stolen files and tokens to them.'
  if (e.includes('ip-api') || e.includes('ipinfo') || e.includes('ipify')) return 'IP lookup services tell malware the device’s public IP and country; stealers record it with the stolen data or skip certain countries.'
  if (e.includes('r2.dev') || e.includes('gofile') || e.includes('transfer.sh') || e.includes('file.io')) return 'Anonymous file-sharing services are used to upload stolen archives.'
  if (e.includes('pastebin')) return 'Paste sites host the next server address or a second-stage payload, so malware fetches them right after it starts.'
  if (e.includes('trycloudflare')) return 'Cloudflare quick tunnels give an attacker a throwaway address in front of their own server.'
  if (e.includes('binance') || e.includes('ankr')) return 'Blockchain RPC nodes let malware read its server address from a smart contract (the EtherHiding / Acreed technique), which nobody can take down.'
  return 'This domain is on the policy’s list of exfiltration and dead-drop services.'
}

export interface ExfilMatch {
  entry: string
  why: string
}

/** Match a host name against the dead-drop list (exact or sub-domain; entries with a path match their domain). */
export function matchExfilDomain(host: string | null | undefined, list: string[] = DEFAULT_EXFIL_DOMAINS): ExfilMatch | null {
  if (!host) return null
  const h = host.toLowerCase().replace(/\.$/, '')
  for (const entry of list) {
    const d = entry.toLowerCase().split('/')[0]
    if (!d) continue
    if (h === d || h.endsWith(`.${d}`)) return { entry, why: exfilWhy(entry) }
  }
  return null
}

export interface DpapiKind {
  /** Short meaning for summaries, e.g. "browser/Electron master key". */
  short: string
  /** Who uses this label for what. */
  meaning: string
  /** Who should decrypt it. */
  owner: string
  /** Browser family name when the label is a Chromium-family key (drives "Which key?"). */
  browser?: string
}

/** Meaning of a DPAPI description string (`CryptProtectData` szDataDescr). The label is chosen by whoever encrypted the secret. */
export function dpapiKind(description: string): DpapiKind | null {
  const d = description.toLowerCase()
  const browsers: [string, string][] = [
    ['chrome', 'Chrome'],
    ['edge', 'Edge'],
    ['opera', 'Opera'],
    ['brave', 'Brave'],
    ['vivaldi', 'Vivaldi'],
    ['yandex', 'Yandex'],
  ]
  if (d.includes('chromium'))
    return {
      short: 'browser/Electron master key',
      meaning: 'Chrome, Edge, Brave and Electron apps use this label for the master key that encrypts saved passwords and cookies.',
      owner: 'Only the app that owns the key should decrypt it.',
      browser: 'Chromium',
    }
  for (const [k, name] of browsers)
    if (d.includes(k))
      return {
        short: `${name} master key`,
        meaning: `${name} uses this label for the master key that encrypts its saved passwords, cookies and card data.`,
        owner: `Only ${name} itself should decrypt it.`,
        browser: name,
      }
  if (d.includes('browser'))
    return { short: 'browser master key', meaning: 'Browsers use labels like this for the master key that encrypts saved passwords and cookies.', owner: 'Only the browser itself should decrypt it.', browser: 'browser' }
  if (/credential data|domain credential|credential manager/.test(d))
    return {
      short: 'Credential Manager secret',
      meaning: 'Windows Credential Manager uses this label for saved Windows, network share, RDP and website logons.',
      owner: 'Windows and the app that saved the logon read these; credential-dumping tools decrypt them to steal saved logons.',
    }
  if (/wlan|wi-?fi|wireless/.test(d))
    return { short: 'Wi-Fi key', meaning: 'This label suggests a saved Wi-Fi profile key.', owner: 'Normally only the WLAN service decrypts these.' }
  return null
}

/** Protocol in words from transport + port. */
export function protocolWords(proto: string, port: number): { short: string; long: string; encrypted: boolean } {
  const udp = proto === 'udp'
  if (port === 443) return udp ? { short: 'QUIC', long: 'QUIC (HTTP/3, encrypted)', encrypted: true } : { short: 'HTTPS', long: 'HTTPS (encrypted)', encrypted: true }
  if (port === 53) return { short: 'DNS', long: `DNS over ${udp ? 'UDP' : 'TCP'}`, encrypted: false }
  if (port === 853) return { short: 'DoT', long: 'DNS over TLS (encrypted)', encrypted: true }
  if (port === 22 && !udp) return { short: 'SSH', long: 'SSH (encrypted remote shell / file transfer)', encrypted: true }
  if (port === 80 && !udp) return { short: 'HTTP', long: 'HTTP (not encrypted)', encrypted: false }
  if (port === 3389) return { short: 'RDP', long: 'Remote Desktop (RDP)', encrypted: true }
  if (port === 445 && !udp) return { short: 'SMB', long: 'SMB (Windows file sharing)', encrypted: false }
  if (port === 8545) return { short: 'RPC', long: `${proto.toUpperCase()} port 8545 (Ethereum / BNB Chain JSON-RPC)`, encrypted: false }
  if (port === 9222) return { short: 'CDP', long: `${proto.toUpperCase()} port 9222 (Chrome remote debugging)`, encrypted: false }
  return { short: proto.toUpperCase(), long: `${proto.toUpperCase()} port ${port}`, encrypted: false }
}

/** Plain description of an IPv4/IPv6 address class, or null for a public address. */
export function addressClass(ip: string): string | null {
  const v = ip.toLowerCase()
  if (v === '::1' || v.startsWith('127.')) return 'this computer (loopback)'
  if (v.startsWith('10.') || v.startsWith('192.168.') || /^172\.(1[6-9]|2\d|3[01])\./.test(v) || v.startsWith('fc') || v.startsWith('fd')) return 'a private, local-network address'
  if (v.startsWith('169.254.') || v.startsWith('fe80')) return 'a link-local address'
  return null
}

/** "1.2 KB" / "2.1 MB" (base 1024, one decimal). */
export function kb(n: number): string {
  if (n >= 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`
  return `${(n / 1024).toFixed(1)} KB`
}

const PROCESS_RIGHTS: [number, string, string?][] = [
  [0x0001, 'PROCESS_TERMINATE', 'kill it'],
  [0x0002, 'PROCESS_CREATE_THREAD', 'start threads in it'],
  [0x0004, 'PROCESS_SET_SESSIONID'],
  [0x0008, 'PROCESS_VM_OPERATION', 'change its memory layout'],
  [0x0010, 'PROCESS_VM_READ', 'read its memory'],
  [0x0020, 'PROCESS_VM_WRITE', 'write its memory'],
  [0x0040, 'PROCESS_DUP_HANDLE', 'copy its handles'],
  [0x0080, 'PROCESS_CREATE_PROCESS', 'use it as a parent'],
  [0x0100, 'PROCESS_SET_QUOTA'],
  [0x0200, 'PROCESS_SET_INFORMATION'],
  [0x0400, 'PROCESS_QUERY_INFORMATION', 'query details'],
  [0x0800, 'PROCESS_SUSPEND_RESUME', 'pause it'],
  [0x1000, 'PROCESS_QUERY_LIMITED_INFORMATION', 'query basic details'],
  [0x2000, 'PROCESS_SET_LIMITED_INFORMATION'],
]
const THREAD_RIGHTS: [number, string, string?][] = [
  [0x0001, 'THREAD_TERMINATE'],
  [0x0002, 'THREAD_SUSPEND_RESUME', 'pause threads'],
  [0x0008, 'THREAD_GET_CONTEXT', 'read thread registers'],
  [0x0010, 'THREAD_SET_CONTEXT', 'change thread registers'],
  [0x0020, 'THREAD_SET_INFORMATION'],
  [0x0040, 'THREAD_QUERY_INFORMATION'],
  [0x0080, 'THREAD_SET_THREAD_TOKEN'],
  [0x0100, 'THREAD_IMPERSONATE'],
  [0x0200, 'THREAD_DIRECT_IMPERSONATION'],
  [0x0400, 'THREAD_SET_LIMITED_INFORMATION'],
  [0x0800, 'THREAD_QUERY_LIMITED_INFORMATION'],
]
const STANDARD_RIGHTS: [number, string][] = [
  [0x00010000, 'DELETE'],
  [0x00020000, 'READ_CONTROL'],
  [0x00040000, 'WRITE_DAC'],
  [0x00080000, 'WRITE_OWNER'],
  [0x00100000, 'SYNCHRONIZE'],
  [0x01000000, 'ACCESS_SYSTEM_SECURITY'],
  [0x02000000, 'MAXIMUM_ALLOWED'],
  [0x10000000, 'GENERIC_ALL'],
  [0x20000000, 'GENERIC_EXECUTE'],
  [0x40000000, 'GENERIC_WRITE'],
  [0x80000000, 'GENERIC_READ'],
]

/** Rights that let the opener read secrets out of, or take over, the target process. */
export const DANGEROUS_PROCESS_RIGHTS = 0x0002 | 0x0008 | 0x0010 | 0x0020 | 0x0040 | 0x0080

export interface DecodedMask {
  names: string[]
  /** Plain-language capabilities ("read its memory", …). */
  abilities: string[]
  all: boolean
}

/** Decode a process (or thread) access mask into named rights. 0x1fffff is *_ALL_ACCESS. */
export function decodeAccessMask(mask: number, kind: 'process' | 'thread' = 'process'): DecodedMask {
  const m = mask >>> 0
  const prefix = kind === 'process' ? 'PROCESS' : 'THREAD'
  if ((m & 0x1fffff) === 0x1fffff) {
    const rest = STANDARD_RIGHTS.filter(([b]) => b > 0x100000 && m & b).map(([, n]) => n)
    return { names: [`${prefix}_ALL_ACCESS`, ...rest], abilities: ['full control (read and write memory, start threads, kill it)'], all: true }
  }
  const table = kind === 'process' ? PROCESS_RIGHTS : THREAD_RIGHTS
  const names: string[] = []
  const abilities: string[] = []
  for (const [bit, name, ability] of table) {
    if (m & bit) {
      names.push(name)
      if (ability) abilities.push(ability)
    }
  }
  for (const [bit, name] of STANDARD_RIGHTS) if (m & bit) names.push(name)
  if (m & 0x02000000) abilities.push('every right Windows will grant')
  return { names, abilities, all: false }
}

/** NTSTATUS values worth naming in the UI. */
export const NTSTATUS: Record<number, string> = {
  0xc0000022: 'access denied',
  0xc0000005: 'access violation',
  0xc000000d: 'invalid parameter',
  0xc000000b: 'invalid client id (no such process)',
  0xc0000008: 'invalid handle',
}

/** Mark-of-the-Web zone ids. */
export const MOTW_ZONE: Record<number, string> = {
  0: 'this computer',
  1: 'the local intranet',
  2: 'a trusted site',
  3: 'the internet',
  4: 'a restricted (untrusted) site',
}
