import type { KEvent, PathClass, SignatureState } from '@/api/types'
import { describeFileActivity, describeService, describeTask } from './events'
import { addressClass, DANGEROUS_PROCESS_RIGHTS, decodeAccessMask, dpapiKind, kb, matchExfilDomain, MOTW_ZONE, NTSTATUS, protocolWords } from './event-knowledge'
import { formatDate, formatDuration, formatNumber, formatTime, hex, safeDisplay } from './format'
import { pathClassOf } from './pathclass'
import { basename, dirname } from './utils'

/**
 * Plain-language explanation of one telemetry event, for an admin who knows
 * security but not EDR internals. All strings are plain text: endpoint values
 * pass through `safeDisplay` and the UI renders them as text nodes (no HTML, no
 * links from event data).
 */

export type Tone = 'info' | 'warn' | 'ok'
export interface ExplainNote {
  tone: Tone
  text: string
}
export interface ExplainItem {
  text: string
  /** Short classification shown next to the item, e.g. "the app's own profile". */
  tag?: string
  tone?: Tone
}
export interface ExplainList {
  title: string
  items: ExplainItem[]
  /** Items behind a "+N more" toggle. */
  more?: ExplainItem[]
  /** Shown when `items` is empty. */
  empty?: string
}
export interface ExplainField {
  label: string
  value: string
  mono?: boolean
  /** Long value (command line, script): render as a wrapped block. */
  block?: boolean
}
export interface Explanation {
  what: string[]
  notes: ExplainNote[]
  lists: ExplainList[]
  fields: ExplainField[]
}

/** What the console knows about a process (tree node, process list row or process_start event). */
export interface ProcFacts {
  image?: string
  cmdline?: string
  pid?: number
  signer?: string | null
  signed?: SignatureState
  path_class?: PathClass
  parent_guid?: string | null
}

export interface ExplainContext {
  /** Other events available on the page (incident evidence, device timeline, hunt results). */
  events?: KEvent[]
  /** Processes by guid (incident process tree). */
  processes?: Map<string, ProcFacts>
  /** Dead-drop / exfiltration list; defaults to Kestrel's default policy list. */
  exfilDomains?: string[]
}

const s = safeDisplay

/** "25 Oct 2026, 14:03:22" in the viewer's time zone. */
export function formatEventTime(ts: number): string {
  return `${formatDate(ts)}, ${formatTime(ts)}`
}

function procStartFor(guid: string, ctx: ExplainContext): (KEvent & { type: 'process_start' }) | undefined {
  return ctx.events?.find((x): x is KEvent & { type: 'process_start' } => x.type === 'process_start' && x.guid === guid)
}

/** Merge what is known about the process behind `guid`. */
export function resolveProcess(guid: string, ctx: ExplainContext, fallbackImage?: string): ProcFacts {
  const node = ctx.processes?.get(guid)
  const start = procStartFor(guid, ctx)
  return {
    image: node?.image || start?.image || fallbackImage,
    cmdline: node?.cmdline || start?.cmdline,
    pid: node?.pid ?? start?.pid,
    signer: node?.signer ?? start?.signer,
    signed: node?.signed ?? start?.signed,
    path_class: node?.path_class,
    parent_guid: node?.parent_guid ?? start?.parent_guid,
  }
}

function procName(e: KEvent, ctx: ExplainContext): string {
  const fallback = e.type === 'process_start' ? e.image : (e as { process_image?: string }).process_image
  const p = resolveProcess(e.guid, ctx, fallback)
  return p.image ? s(basename(p.image)) : `The process with PID ${e.pid}`
}

const lower = (x: string) => x.replace(/\//g, '\\').toLowerCase()

/** `--user-data-dir` from a Chromium / Electron command line. */
export function userDataDir(cmdline: string | undefined): string | null {
  if (!cmdline) return null
  const m = /--user-data-dir=(?:"([^"]+)"|(\S+))/i.exec(cmdline)
  return m ? (m[1] ?? m[2] ?? null) : null
}

/** Candidate app-folder names from an image name: "Xeno-v1.3.65.exe" gives "xenov1365" and "xeno". */
function appNames(image: string | undefined): string[] {
  if (!image) return []
  const stem = basename(image).replace(/\.[^.]+$/, '')
  const noVer = stem.replace(/[\s._-]*v?\d+(?:\.\d+)*$/i, '')
  const norm = (x: string) => x.toLowerCase().replace(/[^a-z0-9]/g, '')
  return [...new Set([norm(stem), norm(noVer)])].filter((x) => x.length >= 3)
}

const BROWSER_STORES: [RegExp, string][] = [
  [/\\google\\chrome( beta| sxs| dev)?\\/, 'Chrome'],
  [/\\microsoft\\edge( beta| dev| sxs)?\\/, 'Edge'],
  [/\\bravesoftware\\/, 'Brave'],
  [/\\opera software\\/, 'Opera'],
  [/\\vivaldi\\/, 'Vivaldi'],
  [/\\yandex\\yandexbrowser\\/, 'Yandex Browser'],
  [/\\chromium\\user data\\/, 'Chromium'],
  [/\\coccoc\\/, 'CocCoc'],
  [/\\mozilla\\firefox\\/, 'Firefox'],
  [/\\thunderbird\\/, 'Thunderbird'],
]

/** Which browser's profile a path belongs to, if any. */
export function browserOfPath(path: string): string | null {
  const p = lower(path)
  for (const [re, name] of BROWSER_STORES) if (re.test(p)) return name
  return null
}

/** True when `path` is inside the process's own data: its `--user-data-dir`, `AppData\(Roaming|Local)\<app name>` or its own install folder. */
export function isOwnProfile(path: string, proc: ProcFacts): boolean {
  const p = lower(path)
  const under = (dir: string) => {
    const d = lower(dir).replace(/\\+$/, '')
    return d.length > 3 && p.startsWith(`${d}\\`)
  }
  const udd = userDataDir(proc.cmdline)
  if (udd && under(udd)) return true
  const m = /\\appdata\\(?:roaming|local)\\([^\\]+)\\/.exec(p)
  if (m) {
    const folder = m[1].replace(/[^a-z0-9]/g, '')
    if (appNames(proc.image).some((n) => n === folder)) return true
  }
  // Portable apps keep data next to the executable, but a bare Temp / Downloads /
  // Desktop folder is shared with everything else and proves nothing.
  if (proc.image) {
    const dir = dirname(proc.image)
    const pc = proc.path_class ?? pathClassOf(proc.image)
    if (pc !== 'system' && pc !== 'windows' && !/^(temp|tmp|downloads|desktop)$/i.test(basename(dir)) && under(dir)) return true
  }
  return false
}

/** What a file is, when recognisable (credential stores first). */
export function fileStore(path: string): string | null {
  const p = lower(path)
  const br = browserOfPath(path)
  const who = br ? `${br}’s` : 'a browser’s'
  if (/\\local state$/.test(p)) return `${who} key file (Local State): it holds the encrypted master key for saved passwords and cookies`
  if (/\\login data( for account)?$/.test(p)) return `${who} saved passwords database`
  if (/\\(network\\)?cookies$/.test(p) && br !== 'Firefox') return `${who} cookie database (signed-in sessions)`
  if (/\\web data$/.test(p)) return `${who} autofill and saved cards database`
  if (/\\local extension settings\\nkbihfbeogaeaoehlefnkodbefgpgknn\\/.test(p)) return 'MetaMask wallet extension storage'
  if (/\\local extension settings\\/.test(p)) return `${who} extension storage (crypto wallet extensions keep their vaults here)`
  if (/\\logins\.json$/.test(p)) return 'Firefox saved passwords'
  if (/\\key4\.db$/.test(p)) return 'Firefox key database (decrypts saved passwords)'
  if (/\\cookies\.sqlite$/.test(p)) return 'Firefox cookie database'
  if (/\\telegram desktop\\tdata\\/.test(p)) return 'the Telegram Desktop session (whoever copies it is logged in as the user)'
  if (/\\discord[^\\]*\\local storage\\leveldb\\/.test(p)) return 'Discord’s local storage, where its login token lives'
  if (/\\filezilla\\(sitemanager|recentservers)\.xml$/.test(p)) return 'FileZilla saved server logins'
  if (/\\\.aws\\credentials$/.test(p)) return 'AWS access keys'
  if (/\\\.azure\\|\\gcloud\\/.test(p)) return 'cloud CLI credentials'
  if (/\\\.ssh\\/.test(p)) return 'SSH keys or settings'
  if (/\.kdbx$/.test(p)) return 'a KeePass password vault'
  if (/\\wallet\.dat$|\\exodus\\|\\electrum\\wallets\\|\\atomic\\local storage\\/.test(p)) return 'a crypto wallet'
  if (/\\microsoft\\credentials\\/.test(p)) return 'Windows Credential Manager files'
  if (/\\microsoft\\protect\\/.test(p)) return 'the user’s DPAPI master keys'
  if (/\\microsoft\\windows\\start menu\\programs\\startup\\/.test(p)) return 'the Startup folder: programs here run at every logon'
  return null
}

const BROWSER_EXES = new Set(['chrome.exe', 'msedge.exe', 'brave.exe', 'opera.exe', 'vivaldi.exe', 'browser.exe', 'firefox.exe', 'elevation_service.exe', 'msedgewebview2.exe'])

const PATH_CLASS_WORDS: Record<PathClass, string> = {
  system: 'the Windows system folder',
  windows: 'the Windows folder',
  program_files: 'Program Files (installed software)',
  temp: 'a Temp folder, where installed software rarely lives',
  downloads: 'the Downloads folder',
  user_writable: 'a folder the user can write to (such as AppData or ProgramData)',
  external: 'a network share or removable drive',
  other: 'another location',
}

function signatureSentence(signed: SignatureState | undefined, signer: string | null | undefined): string | null {
  if (signed === 'valid') return `It is signed by ${signer ? s(signer) : 'a publisher'} and the signature is valid.`
  if (signed === 'invalid') return `Its signature does not verify${signer ? ` (it claims to be from ${s(signer)})` : ''}: the file was changed after signing or the signature is forged.`
  if (signed === 'unsigned') return 'It is not signed, so there is no publisher to vouch for it.'
  return null
}

const FILE_OP_VERB: Record<string, string> = { open: 'opened', read: 'read', write: 'wrote to', create: 'created', delete: 'deleted', rename: 'renamed' }

function base(e: KEvent, ctx: ExplainContext): ExplainField[] {
  const fallback = e.type === 'process_start' ? e.image : (e as { process_image?: string }).process_image
  const p = resolveProcess(e.guid, ctx, fallback)
  const out: ExplainField[] = [{ label: 'Time', value: formatEventTime(e.ts) }]
  out.push({ label: 'Process', value: `${p.image ? s(basename(p.image)) : 'unknown'} (PID ${e.pid})`, mono: true })
  if (p.image && e.type !== 'process_start') out.push({ label: 'Process path', value: s(p.image), mono: true })
  return out
}

function explainDpapi(e: KEvent & { type: 'dpapi_unprotect' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const label = s(e.description)
  const kind = dpapiKind(e.description)
  x.what.push(`${name} asked Windows (DPAPI) to decrypt a secret labelled "${label}".${kind ? ` ${kind.meaning} ${kind.owner}` : ''}`)
  if (!kind)
    x.what.push('DPAPI protects secrets for the signed-in user or the computer. The label is chosen by the program that encrypted the secret, so it hints at what the secret is but proves nothing.')
  x.fields.push({ label: 'DPAPI label', value: label, mono: true })
  if (!kind?.browser) return
  const proc = resolveProcess(e.guid, ctx, (e as { process_image?: string }).process_image)
  const exe = proc.image ? basename(proc.image).toLowerCase() : ''
  if (BROWSER_EXES.has(exe)) {
    x.notes.push({ tone: 'ok', text: 'This is a browser decrypting its own key, which it does every time it starts.' })
    return
  }
  const opens = (ctx.events ?? []).filter(
    (o): o is KEvent & { type: 'file_access' } => o.type === 'file_access' && o.guid === e.guid && o.ts <= e.ts && e.ts - o.ts <= 10_000 && /[\\/]local state$/i.test(o.path),
  )
  const items: ExplainItem[] = opens.map((o) => {
    const br = browserOfPath(o.path)
    if (br) return { text: s(o.path), tag: `${br}’s key store`, tone: 'warn' }
    if (isOwnProfile(o.path, proc)) return { text: s(o.path), tag: 'the app’s own profile', tone: 'ok' }
    return { text: s(o.path), tag: 'another program’s profile', tone: 'info' }
  })
  x.lists.push({
    title: 'Which key?',
    items,
    empty: 'Kestrel did not record which file the key came from; look for file opens just before this event.',
  })
  if (items.some((i) => i.tone === 'warn'))
    x.notes.push({ tone: 'warn', text: 'It read a browser’s key file just before decrypting. That is how stealers unlock saved browser passwords and cookies.' })
  else if (items.length && items.every((i) => i.tone === 'ok'))
    x.notes.push({ tone: 'info', text: 'The key came from the app’s own profile, which Electron apps do at start-up. It becomes a concern if the same process also reads browser files or uploads data.' })
}

function explainNet(e: KEvent & { type: 'net_connect' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const pw = protocolWords(e.proto, e.dst_port)
  const ip = s(e.dst_ip)
  const host = e.dst_host ? s(e.dst_host) : null
  const cls = addressClass(e.dst_ip)
  const dest = host ? `${host} (${ip}) on port ${e.dst_port}` : `${ip} on port ${e.dst_port} (no host name recorded)`
  x.what.push(`${name} connected to ${dest} using ${pw.long}.${cls ? ` The address is ${cls}.` : ''}`)
  const bytes = e.bytes_sent
  if (bytes == null) x.what.push('Kestrel did not record how much data was sent.')
  else if (bytes === 0) x.what.push('No outgoing data was recorded on this connection.')
  else x.what.push(`It sent ${kb(bytes)} (${formatNumber(bytes)} bytes) on this connection.`)
  x.what.push(`Kestrel records the connection, not its content${pw.encrypted ? '; the traffic is encrypted.' : '.'}`)
  if (e.proto === 'udp' && e.dst_port === 443 && bytes != null && bytes >= 1200 && bytes <= 1500)
    x.notes.push({ tone: 'info', text: 'About one QUIC handshake packet, which is the minimum size QUIC requires; this is the start of a connection, not a bulk upload.' })
  if (bytes != null && bytes > 100 * 1024)
    x.notes.push({ tone: 'warn', text: `Large upload: ${kb(bytes)} left this computer on this connection. Check what the process read just before it.` })
  const ex = matchExfilDomain(e.dst_host, ctx.exfilDomains)
  if (ex) x.notes.push({ tone: 'warn', text: `${host} is on the dead-drop list (${s(ex.entry)}). ${ex.why}` })
  if (e.dst_port === 9222 && cls?.startsWith('this computer'))
    x.notes.push({ tone: 'warn', text: 'Port 9222 on this computer is usually Chrome’s remote debugging port: a program connected there can read every cookie without decrypting anything.' })
  x.fields.push({ label: 'Protocol', value: `${e.proto.toUpperCase()} (${pw.short})` })
  x.fields.push({ label: 'Destination', value: `${ip}:${e.dst_port}`, mono: true })
  x.fields.push({ label: 'Host name', value: host ?? 'not recorded', mono: !!host })
  if (e.src_port) x.fields.push({ label: 'Source port', value: String(e.src_port), mono: true })
  x.fields.push({ label: 'Sent', value: bytes == null ? 'not recorded' : `${kb(bytes)} (${formatNumber(bytes)} bytes)` })
}

const DNS_SHOWN = 3

function explainDns(e: KEvent & { type: 'dns_query' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const q = s(e.qname)
  const answers = (e.answers ?? []).map((a) => s(a))
  x.what.push(`${name} looked up ${q}.`)
  if (answers.length) x.what.push(`Windows returned ${answers.length === 1 ? 'one answer' : `${answers.length} answers`}. A long list is normal for large cloud and CDN services.`)
  else x.what.push('No answer was recorded (the name may not exist, or the answer was not captured).')
  if (answers.length) x.lists.push({ title: 'Answers', items: answers.slice(0, DNS_SHOWN).map((t) => ({ text: t })), more: answers.slice(DNS_SHOWN).map((t) => ({ text: t })) })
  const ex = matchExfilDomain(e.qname, ctx.exfilDomains)
  if (ex) x.notes.push({ tone: 'warn', text: `${q} is on the dead-drop list (${s(ex.entry)}). ${ex.why} Browsers and the service’s own app use it too; it matters when another program looks it up.` })
  x.fields.push({ label: 'Name looked up', value: q, mono: true })
  x.fields.push({ label: 'Answers', value: String(answers.length) })
}

function explainFile(e: KEvent & { type: 'file_access' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const store = fileStore(e.path)
  x.what.push(`${name} ${FILE_OP_VERB[e.op] ?? e.op} ${s(e.path)}.${store ? ` This is ${store}.` : ''}`)
  const br = browserOfPath(e.path)
  const proc = resolveProcess(e.guid, ctx, (e as { process_image?: string }).process_image)
  const exe = proc.image ? basename(proc.image).toLowerCase() : ''
  if (store && br && !BROWSER_EXES.has(exe) && !isOwnProfile(e.path, proc))
    x.notes.push({ tone: 'warn', text: `Normally only ${br} itself (and backup or sync tools) opens this file.` })
  x.fields.push({ label: 'File', value: s(e.path), mono: true })
  x.fields.push({ label: 'Operation', value: e.op })
  const pc = pathClassOf(e.path)
  x.fields.push({ label: 'Location', value: PATH_CLASS_WORDS[pc] })
}

function explainProcessAccess(e: KEvent & { type: 'process_access' | 'remote_thread' | 'thread_context' | 'debug_attach' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const target = `${s(basename(e.target_image))} (PID ${e.target_pid})`
  const isLsass = /(^|[\\/])lsass\.exe$/i.test(e.target_image)
  const kind = e.type === 'thread_context' ? 'thread' : 'process'
  const mask = e.granted_access
  const dec = mask != null ? decodeAccessMask(mask, kind) : null
  if (e.type === 'process_access') {
    x.what.push(`${name} asked Windows for a handle to ${target}${dec?.abilities.length ? ` that lets it ${dec.abilities.join(', ')}` : ''}.`)
    if (isLsass) x.what.push('LSASS holds the signed-in users’ password hashes and Kerberos tickets. Reading its memory is how credential-dumping tools work.')
  } else if (e.type === 'remote_thread') {
    x.what.push(`${name} started a thread inside ${target}. Running code in another process is a classic injection step; debuggers and some security tools also do it.`)
  } else if (e.type === 'thread_context') {
    x.what.push(`${name} changed the registers of a thread in ${target}. This redirects what the thread runs next (or sets hardware breakpoints), a technique used to hijack a process or catch secrets in its memory.`)
  } else {
    x.what.push(`${name} attached to ${target} as a debugger. A debugger can read and change the target’s memory and pause it at chosen points.`)
  }
  if (e.type === 'process_access') {
    const rc = (e.return_code ?? 0) >>> 0
    if (rc) {
      x.notes.push({ tone: 'ok', text: `Windows refused the request (${hex(rc)}${NTSTATUS[rc] ? ` ${NTSTATUS[rc]}` : ''}), so nothing was read.${isLsass ? ' LSA protection (RunAsPPL) usually causes this.' : ''} The attempt is still worth investigating.` })
    } else if (mask != null && (dec?.all || (mask & DANGEROUS_PROCESS_RIGHTS) !== 0)) {
      x.notes.push({ tone: isLsass ? 'warn' : 'info', text: `The request includes rights to read or change the target’s memory${isLsass ? ', which on LSASS means credential theft is possible' : ''}.` })
    } else if (mask != null) {
      x.notes.push({ tone: 'info', text: 'Only query rights: many programs (task managers, antivirus, updaters) open processes like this.' })
    }
  }
  x.fields.push({ label: 'Target', value: s(e.target_image), mono: true })
  x.fields.push({ label: 'Target PID', value: String(e.target_pid), mono: true })
  if (mask != null) {
    x.fields.push({ label: 'Access mask', value: hex(mask), mono: true })
    x.fields.push({ label: 'Rights', value: dec?.names.join(', ') || 'none', mono: true })
  }
  if (e.type === 'process_access') {
    const rc = (e.return_code ?? 0) >>> 0
    x.fields.push({ label: 'Result', value: rc ? `refused by Windows (${hex(rc)}${NTSTATUS[rc] ? ` ${NTSTATUS[rc]}` : ''})` : 'granted' })
  }
}

function registryMeaning(key: string): string | null {
  const k = lower(key)
  if (/\\currentversion\\run(once|onceex|services)?$/.test(k)) return 'Programs listed in this key start automatically at logon.'
  if (/\\explorer\\runmru$/.test(k)) return 'This is the Win+R Run dialog history: it records what the user typed or pasted into Run.'
  if (/\\winlogon$/.test(k)) return 'Winlogon settings decide what runs when a user logs on.'
  if (k.includes('\\image file execution options\\')) return 'Image File Execution Options can make Windows run another program whenever the named one starts.'
  if (k.includes('\\silentprocessexit\\')) return 'SilentProcessExit can launch a program or write a memory dump when the named process exits.'
  if (/\\control\\lsa(\\|$)/.test(k)) return 'LSA settings control how Windows protects stored credentials.'
  if (k.includes('\\wdigest')) return 'WDigest settings decide whether Windows keeps plain-text passwords in memory.'
  if (/\\currentcontrolset\\services\\/.test(k)) return 'This key holds a Windows service’s configuration.'
  if (k.includes('\\policies\\microsoft\\windows defender')) return 'This key holds Microsoft Defender policy settings.'
  if (/\\classes\\clsid\\/.test(k)) return 'This is a COM registration: it decides which file Windows loads for a COM object.'
  if (k.includes('\\user shell folders') || k.includes('\\shell folders')) return 'This key decides where special folders such as Startup point.'
  return null
}

function explainRegistry(e: KEvent & { type: 'registry_set' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const key = s(e.key)
  const val = e.value_name ? s(e.value_name) : '(default)'
  if (e.op === 'delete_key') x.what.push(`${name} deleted the registry key ${key}.`)
  else if (e.op === 'delete_value') x.what.push(`${name} deleted the value ${val} from ${key}.`)
  else x.what.push(`${name} set the registry value ${val} in ${key}${e.data != null ? ` to ${s(e.data)}` : ''}.`)
  const m = registryMeaning(e.key)
  if (m) x.what.push(m)
  if (e.attribution === 'heuristic') x.notes.push({ tone: 'info', text: 'The writing process was inferred by correlation, not reported by Windows.' })
  if (e.attribution === 'none') x.notes.push({ tone: 'info', text: 'Kestrel could not tell which process wrote this value.' })
  x.fields.push({ label: 'Key', value: key, mono: true })
  if (e.op !== 'delete_key') x.fields.push({ label: 'Value', value: val, mono: true })
  if (e.data != null) x.fields.push({ label: 'Data', value: s(e.data), mono: true, block: true })
  if (e.target) {
    x.fields.push({ label: 'Started file', value: s(e.target.path), mono: true })
    const sig = signatureSentence(e.target.signed, e.target.signer)
    if (sig) x.fields.push({ label: 'Started file signature', value: sig })
  }
}

function explainProcessStart(e: KEvent & { type: 'process_start' }, ctx: ExplainContext, x: Explanation) {
  const name = s(basename(e.image))
  const node = ctx.processes?.get(e.guid)
  const parent = e.parent_guid ? resolveProcess(e.parent_guid, ctx) : undefined
  const pc = node?.path_class ?? pathClassOf(e.image)
  x.what.push(`${name} started (PID ${e.pid})${parent?.image ? `, launched by ${s(basename(parent.image))}` : ''}. It runs from ${PATH_CLASS_WORDS[pc]}.`)
  const sig = signatureSentence(e.signed, e.signer)
  if (sig) x.what.push(sig)
  if (e.motw_zone != null && e.motw_zone >= 3) x.notes.push({ tone: 'warn', text: `The file carries a Mark-of-the-Web: Windows recorded that it came from ${MOTW_ZONE[e.motw_zone] ?? `zone ${e.motw_zone}`}.` })
  if (e.integrity === 'high' || e.integrity === 'system') x.notes.push({ tone: 'info', text: `It runs ${e.integrity === 'system' ? 'as SYSTEM' : 'elevated (administrator rights)'}.` })
  if (e.agent_spawned) x.notes.push({ tone: 'ok', text: 'Kestrel itself started this process (hardening, a scan or an update).' })
  const udd = userDataDir(e.cmdline)
  if (udd && /--headless|--remote-debugging-port/i.test(e.cmdline))
    x.notes.push({ tone: 'warn', text: 'A browser started headless or with remote debugging: another program can then drive it and read its cookies.' })
  x.fields.push({ label: 'Path', value: s(e.image), mono: true })
  x.fields.push({ label: 'Command line', value: s(e.cmdline), mono: true, block: true })
  if (e.user) x.fields.push({ label: 'User', value: s(e.user), mono: true })
  if (parent?.image) x.fields.push({ label: 'Parent', value: `${s(basename(parent.image))} (PID ${e.ppid})`, mono: true })
  else x.fields.push({ label: 'Parent PID', value: String(e.ppid), mono: true })
  x.fields.push({ label: 'Signature', value: e.signed === 'valid' ? `valid, ${e.signer ? s(e.signer) : 'unknown signer'}` : e.signed === 'invalid' ? `invalid${e.signer ? ` (claims ${s(e.signer)})` : ''}` : (e.signed ?? 'unknown') })
  if (e.sha256) x.fields.push({ label: 'SHA-256', value: e.sha256, mono: true })
  if (e.file_size != null) x.fields.push({ label: 'File size', value: kb(e.file_size) })
}

function explainImageLoad(e: KEvent & { type: 'image_load' }, ctx: ExplainContext, x: Explanation) {
  const name = procName(e, ctx)
  const dll = basename(e.path).toLowerCase()
  x.what.push(`${name} loaded ${s(basename(e.path))} from ${PATH_CLASS_WORDS[pathClassOf(e.path)]}.`)
  const sig = signatureSentence(e.signed, e.signer)
  if (sig) x.what.push(sig.replace(/^It is/, 'The DLL is').replace(/^Its/, 'The DLL’s').replace(/^It /, 'The DLL '))
  if (dll === 'dbghelp.dll' || dll === 'dbgcore.dll') x.notes.push({ tone: 'info', text: 'This DLL provides MiniDumpWriteDump, which writes memory dumps. Crash reporters use it; credential dumpers use it on LSASS.' })
  if (dll === 'vaultcli.dll') x.notes.push({ tone: 'info', text: 'This DLL reads the Windows Credential Manager vault.' })
  x.fields.push({ label: 'DLL', value: s(e.path), mono: true })
  x.fields.push({ label: 'Signature', value: e.signed === 'valid' ? `valid, ${e.signer ? s(e.signer) : 'unknown signer'}` : (e.signed ?? 'unknown') })
}

const TAMPER: Record<string, string> = {
  etw_session_stopped: 'Kestrel’s event trace session was stopped. While it is stopped Kestrel cannot see activity on this device.',
  etw_provider_disabled: 'A Windows event provider Kestrel listens to was disabled, so one kind of activity is no longer visible.',
  events_lost: 'Windows dropped events before Kestrel could read them. Heavy load can cause this; repeated bursts can hide activity.',
  wfp_filter_change: 'Windows Filtering Platform filters were changed. This can undo network blocks or host isolation.',
  amsi_provider_change: 'An AMSI provider registration changed. Removing providers stops script content scanning.',
  service_config_change: 'The Kestrel service configuration was changed.',
  agent_file_modified: 'A Kestrel agent file was changed on disk.',
  uninstall_attempt: 'Something tried to uninstall Kestrel.',
}

const TRIGGER_WORDS: Record<string, string> = { logon: 'at every logon', boot: 'at every start-up', time: 'on a schedule', idle: 'when the computer is idle', event: 'when an event is logged' }

/** Plain-language explanation of `e`. `ctx` adds what the page knows about other events and processes. */
export function explainEvent(e: KEvent, ctx: ExplainContext = {}): Explanation {
  const x: Explanation = { what: [], notes: [], lists: [], fields: base(e, ctx) }
  const name = () => procName(e, ctx)
  switch (e.type) {
    case 'dpapi_unprotect':
      explainDpapi(e, ctx, x)
      break
    case 'net_connect':
      explainNet(e, ctx, x)
      break
    case 'dns_query':
      explainDns(e, ctx, x)
      break
    case 'file_access':
      explainFile(e, ctx, x)
      break
    case 'process_access':
    case 'remote_thread':
    case 'thread_context':
    case 'debug_attach':
      explainProcessAccess(e, ctx, x)
      break
    case 'registry_set':
      explainRegistry(e, ctx, x)
      break
    case 'process_start':
      explainProcessStart(e, ctx, x)
      break
    case 'process_stop':
      x.what.push(`${name()} exited${e.exit_code != null ? ` with code ${e.exit_code}` : ''}.`)
      if (e.exit_code != null) x.fields.push({ label: 'Exit code', value: String(e.exit_code), mono: true })
      break
    case 'image_load':
      explainImageLoad(e, ctx, x)
      break
    case 'script_block': {
      const max = 4000
      x.what.push(`${s(e.engine)} recorded a script run by ${name()}. Script logging captures the text as it runs, so encoded commands show up decoded.`)
      x.fields.push({ label: 'Engine', value: s(e.engine) })
      x.fields.push({ label: e.content.length > max ? `Script (first ${formatNumber(max)} characters)` : 'Script', value: s(e.content.slice(0, max)), mono: true, block: true })
      break
    }
    case 'tamper':
      x.what.push(TAMPER[e.kind] ?? `Tamper signal: ${e.kind.replace(/_/g, ' ')}.`)
      x.fields.push({ label: 'Kind', value: e.kind.replace(/_/g, ' ') })
      x.fields.push({ label: 'Detail', value: s(e.detail), mono: true, block: true })
      break
    case 'file_activity':
      x.what.push(`${e.remote_writer ? 'A remote client over SMB' : name()}: ${s(describeFileActivity(e))}.`)
      x.what.push('Kestrel summarises file activity per process over a short window; mass renames to a new extension and ransom-note files are typical of ransomware.')
      if (e.canary_hits?.length) x.notes.push({ tone: 'warn', text: 'It touched decoy files Kestrel planted. No legitimate program opens them.' })
      if (e.remote_writer) x.notes.push({ tone: 'info', text: 'The writes came from another machine over a file share; investigate the client that has this share mapped.' })
      x.fields.push({ label: 'Window', value: formatDuration(e.window_ms) })
      x.fields.push({ label: 'Files touched', value: formatNumber(e.files_touched) })
      x.fields.push({ label: 'Folders', value: formatNumber(e.dirs) })
      if (e.renames) x.fields.push({ label: 'Renames', value: formatNumber(e.renames) })
      if (e.overwrites) x.fields.push({ label: 'Overwrites', value: formatNumber(e.overwrites) })
      if (e.top_new_ext) x.fields.push({ label: 'New extension', value: `.${s(e.top_new_ext)}`, mono: true })
      if (e.canary_hits?.length) x.lists.push({ title: 'Decoy files touched', items: e.canary_hits.map((p) => ({ text: s(p) })) })
      if (e.sample_paths?.length) x.lists.push({ title: 'Sample files', items: e.sample_paths.slice(0, 3).map((p) => ({ text: s(p) })), more: e.sample_paths.slice(3).map((p) => ({ text: s(p) })) })
      break
    case 'task_registered': {
      const verb = e.op === 'created' ? 'created' : e.op === 'updated' ? 'changed' : 'deleted'
      x.what.push(`${name()} ${verb} the scheduled task ${s(e.name)}.`)
      if (e.op !== 'deleted' && e.actions?.length) {
        const when = (e.triggers ?? []).map((t) => TRIGGER_WORDS[t] ?? t)
        x.what.push(`Windows will run ${e.actions.map(s).join(' and ')}${when.length ? ` ${when.join(' and ')}` : ''}${e.user ? ` as ${s(e.user)}` : ''}.`)
      }
      if (e.hidden) x.notes.push({ tone: 'warn', text: 'The task is hidden, so it does not show in Task Scheduler by default.' })
      x.fields.push({ label: 'Task', value: s(e.name), mono: true })
      if (e.actions?.length) x.fields.push({ label: 'Runs', value: e.actions.map(s).join('\n'), mono: true, block: true })
      x.fields.push({ label: 'Summary', value: s(describeTask(e)), mono: true, block: true })
      break
    }
    case 'service_installed':
      x.what.push(`${name()} installed the Windows service ${s(e.name)}, which runs ${s(e.image_path)}${e.account ? ` as ${s(e.account)}` : ''}.`)
      if (e.service_type === 1) x.notes.push({ tone: 'warn', text: 'This is a kernel driver: it runs with full control of the computer.' })
      if (e.start_type === 2 || e.start_type === 0 || e.start_type === 1) x.what.push('It starts automatically with Windows.')
      x.fields.push({ label: 'Service', value: s(e.name), mono: true })
      x.fields.push({ label: 'Image path', value: s(e.image_path), mono: true, block: true })
      x.fields.push({ label: 'Summary', value: s(describeService(e)), mono: true, block: true })
      break
    case 'wmi_subscription':
      x.what.push(`${name()} bound a permanent WMI event subscription in ${s(e.namespace)}. When the filter matches, Windows runs the consumer, and the subscription survives reboots.`)
      if (/commandlineeventconsumer|activescripteventconsumer/i.test(e.consumer)) x.notes.push({ tone: 'warn', text: 'The consumer runs a command or a script, a known way to hide persistence.' })
      x.fields.push({ label: 'Filter', value: s(e.filter), mono: true, block: true })
      x.fields.push({ label: 'Consumer', value: s(e.consumer), mono: true, block: true })
      break
  }
  return x
}
