// Mock evidence bundles (evidence capture after ST-02 / ST-04) and their REST routes.
// Bundles are attached to the existing mock incidents that carry ST-02 or ST-04,
// one in every status, so the console can show each state in mock mode.
import type {
  CopyStatus,
  DataCategory,
  Device,
  EvidenceBundle,
  EvidenceDownloadTicket,
  EvidenceManifest,
  EvidenceProcess,
  EvidenceStatus,
  IncidentDetail,
  LiveEvent,
  SecretRead,
  StagedFile,
  TreeNode,
  User,
} from '@/api/types'
import { EVIDENCE_POLICY_DEFAULTS, EVIDENCE_RETENTION_DEFAULT_DAYS } from '@/api/types'
import type { MockDb } from './db'
import { reauth } from './remote-state'
import { mulberry32 } from './rng'

const MIN = 60_000
const HOUR = 60 * MIN
const DAY = 24 * HOUR
const MB = 1024 * 1024

type Req = { params: Record<string, string>; query: URLSearchParams; body: unknown; method: string }
export interface EvidenceRouteCtx {
  route: (method: string, path: string, h: (r: Req) => unknown) => void
  db: MockDb
  emit: (e: LiveEvent) => void
  me: () => User
  requirePriv: (u: User, priv: string) => void
  err: (status: number, code: string, message: string, extra?: Record<string, unknown>) => Error
}

/** Seeded per process so the demo data is stable between reloads. */
const rnd = mulberry32(0x65766964)
const hex = (n: number) => Array.from({ length: n }, () => Math.floor(rnd() * 16).toString(16)).join('')
const bid = () => {
  const h = hex(32)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-a${h.slice(17, 20)}-${h.slice(20, 32)}`
}

/** Credential-store path → (store, what, category), like the agent's secret-path catalogue. */
function classify(path: string): { store: string; noun: string; category: DataCategory } {
  const p = path.toLowerCase()
  const browser = p.includes('\\microsoft\\edge\\') ? 'Edge' : p.includes('\\mozilla\\firefox\\') ? 'Firefox' : p.includes('\\brave') ? 'Brave' : 'Chrome'
  if (p.endsWith('\\login data') || p.endsWith('logins.json')) return { store: browser, noun: 'saved passwords', category: 'browser_passwords' }
  if (p.endsWith('\\cookies') || p.endsWith('cookies.sqlite')) return { store: browser, noun: 'cookies', category: 'browser_cookies' }
  if (p.endsWith('\\web data')) return { store: browser, noun: 'autofill and saved cards', category: 'browser_autofill' }
  if (p.endsWith('\\local state') || p.endsWith('key4.db')) return { store: browser, noun: 'encryption key', category: 'browser_master_key' }
  if (p.includes('nkbihfbeogaeaoehlefnkodbefgpgknn')) return { store: 'MetaMask', noun: 'wallet vault', category: 'crypto_wallet' }
  if (p.includes('telegram desktop')) return { store: 'Telegram', noun: 'session files', category: 'telegram' }
  if (p.includes('\\discord\\')) return { store: 'Discord', noun: 'login token', category: 'discord' }
  if (p.includes('filezilla')) return { store: 'FileZilla', noun: 'saved FTP logins', category: 'ftp_client' }
  if (p.includes('\\.aws\\')) return { store: 'AWS CLI', noun: 'access keys', category: 'cloud_token' }
  return { store: 'Other', noun: 'credential file', category: 'browser_passwords' }
}

const homeOf = (inc: IncidentDetail) => {
  for (const e of inc.evidence) {
    const path = (e as { path?: string }).path
    const m = path ? /^([A-Za-z]:\\Users\\[^\\]+)/.exec(path) : null
    if (m) return m[1]
  }
  return `C:\\Users\\${(inc.user ?? 'user').split('\\').pop()}`
}

function treeOf(inc: IncidentDetail, alertGuid: string): EvidenceProcess[] {
  const by = new Map(inc.process_tree.map((n) => [n.guid, n]))
  const alerting = by.get(alertGuid) ?? inc.process_tree.find((n) => n.alert_rule_ids.length) ?? inc.process_tree[0]
  if (!alerting) return []
  const out: EvidenceProcess[] = [{ guid: alerting.guid, pid: alerting.pid, image: alerting.image, start_ts: alerting.start_ts, role: 'alerting' }]
  // Ancestors up to (not including) the first one in Windows / Program Files.
  let cur: TreeNode | undefined = alerting.parent_guid ? by.get(alerting.parent_guid) : undefined
  while (cur && !['system', 'windows', 'program_files'].includes(cur.path_class) && out.length < 64) {
    out.push({ guid: cur.guid, pid: cur.pid, image: cur.image, start_ts: cur.start_ts, role: 'ancestor' })
    cur = cur.parent_guid ? by.get(cur.parent_guid) : undefined
  }
  const kids = (g: string) => inc.process_tree.filter((n) => n.parent_guid === g)
  const stack = kids(alerting.guid)
  while (stack.length && out.length < 64) {
    const n = stack.shift()!
    out.push({ guid: n.guid, pid: n.pid, image: n.image, start_ts: n.start_ts, role: 'descendant' })
    stack.push(...kids(n.guid))
  }
  return out
}

function buildManifest(inc: IncidentDetail, bundleId: string, ruleId: string, alertId: string, alertGuid: string, t0: number, agentVersion: string): EvidenceManifest {
  const procs = treeOf(inc, alertGuid)
  const main = procs[0]
  const image = main?.image ?? 'unknown.exe'
  const home = homeOf(inc)
  const seen = new Set<string>()
  const secrets: SecretRead[] = []
  for (const e of inc.evidence) {
    if (e.type !== 'file_access' || seen.has(e.path.toLowerCase())) continue
    seen.add(e.path.toLowerCase())
    const c = classify(e.path)
    if (c.store === 'Other') continue
    const size = Math.round((0.02 + rnd() * 3) * MB)
    const status: CopyStatus = c.category === 'browser_cookies' ? 'locked' : 'copied'
    secrets.push({
      path: e.path,
      ...c,
      first_read: e.ts,
      last_read: e.ts + Math.round(rnd() * 900),
      open_count: 1 + Math.floor(rnd() * 4),
      process_guid: e.guid,
      image,
      size,
      copy: status === 'copied' ? { status, entry: `secrets/${String(secrets.length + 1).padStart(4, '0')}-${e.path.split('\\').pop()}`, size, sha256: hex(64) } : { status, detail: 'opened by chrome.exe without read sharing' },
    })
  }
  const tmp = `${home}\\AppData\\Local\\Temp\\${hex(8).toUpperCase()}`
  const staged: StagedFile[] = (
    [
      [`${tmp}\\Browsers\\Chrome_Default_Passwords.txt`, 'created', 'copied', 48_211],
      [`${tmp}\\Browsers\\Chrome_Default_Cookies.txt`, 'created', 'copied', 1_204_388],
      [`${tmp}\\Wallets\\MetaMask\\000003.log`, 'created', 'copied', 312_904],
      [`${tmp}\\System.txt`, 'created', 'copied', 6_120],
      [`${tmp}\\Screen.png`, 'created', 'copied', 884_102],
      [`${tmp}.zip`, 'created', 'copied', 2_202_009],
      [`${tmp}\\Browsers\\Edge`, 'created', 'link', 0],
      [`${home}\\AppData\\Roaming\\${hex(6)}.tmp`, 'written', 'missing', 0],
      [`${home}\\Videos\\holiday-2026.mp4`, 'overwritten', 'too_large', 812 * MB],
    ] as [string, StagedFile['op'], CopyStatus, number][]
  ).map(([path, op, status, size], i) => ({
    path,
    written_at: t0 + 1_200 + i * 310,
    op,
    process_guid: main?.guid ?? '',
    image,
    copy:
      status === 'copied'
        ? { status, entry: `staged/${String(i + 1).padStart(4, '0')}-${path.split('\\').pop()}`, size, sha256: hex(64) }
        : status === 'link'
          ? { status, detail: 'directory junction to C:\\Users\\Public' }
          : status === 'too_large'
            ? { status, size, detail: 'over the 50 MB per-file limit' }
            : { status, detail: 'deleted before the copy at the end of the 60 s window' },
  }))
  const net = inc.network.filter((n) => n.dst_ip !== '127.0.0.1')
  const filters = [...new Map(net.map((n) => [`${n.dst_ip}:${n.dst_port}`, { ip: n.dst_ip, port: n.dst_port, proto: 'tcp' as const }])).values()].slice(0, 16)
  const pcapBytes = filters.length ? 1_480_332 : 0
  const stagedCopied = staged.filter((s) => s.copy?.status === 'copied')
  const secretsCopied = secrets.filter((s) => s.copy?.status === 'copied')
  const stagedBytes = stagedCopied.reduce((a, s) => a + (s.copy?.size ?? 0), 0)
  const secretBytes = secretsCopied.reduce((a, s) => a + (s.copy?.size ?? 0), 0)
  return {
    format: 1,
    bundle_id: bundleId,
    alert_id: alertId,
    alert_ids: [alertId],
    rule_id: ruleId,
    hostname: inc.hostname,
    agent_version: agentVersion,
    started_at: t0,
    window_start: t0 - 30_000,
    window_end: t0 + 60_000,
    completed_at: t0 + 62_400,
    parts: { ...EVIDENCE_POLICY_DEFAULTS },
    processes: procs,
    staged,
    secrets,
    pcap: filters.length
      ? { status: 'captured', mechanism: 'pktmon', filters, started_at: t0 + 600, ended_at: t0 + 60_600, bytes: pcapBytes, truncated: false, entry: 'capture.pcapng', sha256: hex(64) }
      : { status: 'no_connections', mechanism: 'pktmon', filters: [], bytes: 0 },
    totals: {
      staged_listed: staged.length,
      staged_copied: stagedCopied.length,
      staged_bytes: stagedBytes,
      staged_unlisted: 0,
      secrets_listed: secrets.length,
      secrets_copied: secretsCopied.length,
      secret_bytes: secretBytes,
      pcap_bytes: pcapBytes,
      data_bytes: stagedBytes + secretBytes + pcapBytes,
    },
    notes: [
      'Chrome was running, so its Cookies file was locked and could not be copied.',
      'Connections opened after the capture started may be missing.',
    ],
  }
}

interface Plan {
  status: EvidenceStatus
  last_error?: string
  supports?: boolean
  age: number
}

function makeBundle(inc: IncidentDetail, plan: Plan, db: MockDb, admin: User): EvidenceBundle {
  const alert = inc.alerts.find((a) => a.rule_id === 'ST-04') ?? inc.alerts.find((a) => a.rule_id === 'ST-02') ?? inc.alerts[0]
  const created = Math.min(alert?.ts ?? inc.created_at, Date.now()) - plan.age
  const id = bid()
  const dev = db.devices.find((d) => d.id === inc.device_id)
  const manifest = plan.status === 'capturing' || plan.status === 'failed' ? null : buildManifest(inc, id, alert?.rule_id ?? 'ST-04', alert?.id ?? id, alert?.process_guid ?? '', created, dev?.agent_version ?? '1.1.6')
  const size = manifest?.totals?.data_bytes ? manifest.totals.data_bytes + 48_000 : 0
  const now = Date.now()
  const b: EvidenceBundle = {
    id,
    device_id: inc.device_id,
    hostname: inc.hostname,
    incident_id: inc.id,
    alert_id: alert?.id ?? id,
    alert_ids: alert ? [alert.id] : [],
    rule_id: alert?.rule_id ?? 'ST-04',
    status: plan.status,
    created_at: created,
    captured_at: manifest ? manifest.completed_at : null,
    manifest,
    bundle_size: size,
    bundle_sha256: manifest ? hex(64) : null,
    local_expires_at: created + 14 * DAY,
    collect_requested_at: null,
    collect_requested_by: null,
    collected_at: null,
    expires_at: null,
    deleted_at: null,
    deleted_by: null,
    last_error: plan.last_error ?? null,
    downloads: 0,
    last_downloaded_at: null,
    device_online: true,
    agent_supports_evidence: plan.supports ?? true,
  }
  switch (plan.status) {
    case 'capturing':
      b.created_at = now - 20_000
      b.local_expires_at = now + 14 * DAY
      break
    case 'collecting':
      b.collect_requested_at = now - 6 * MIN
      b.collect_requested_by = admin.name
      break
    case 'stored':
      b.collect_requested_at = created + 25 * MIN
      b.collect_requested_by = admin.name
      b.collected_at = created + 27 * MIN
      b.expires_at = b.collected_at + 14 * DAY
      b.local_expires_at = null
      b.downloads = 1
      b.last_downloaded_at = created + 40 * MIN
      break
    case 'expired':
      b.local_expires_at = created + 14 * DAY
      break
    case 'deleted':
      b.deleted_at = created + 3 * HOUR
      b.deleted_by = admin.name
      b.local_expires_at = null
      break
  }
  return b
}

/** Every bundle of the mock session, newest first per incident. */
export const evidenceStore: { bundles: EvidenceBundle[] | null } = { bundles: null }

const hasTheftRule = (i: IncidentDetail) => i.rule_ids.includes('ST-04') || i.rule_ids.includes('ST-02')

/** Bundles in every status, attached to the incidents that carry ST-02 / ST-04. */
export function seedEvidence(db: MockDb): EvidenceBundle[] {
  const admin = db.users.find((u) => u.role === 'admin') ?? db.users[0]
  const cands = db.incidents.filter(hasTheftRule).sort((a, b) => b.created_at - a.created_at)
  if (!cands.length) return []
  const primary = cands.find((i) => i.rule_ids.includes('ST-04')) ?? cands[0]
  const secondary = cands.find((i) => i !== primary && i.rule_ids.includes('ST-02')) ?? primary
  const out: EvidenceBundle[] = [
    makeBundle(primary, { status: 'stored', age: 0 }, db, admin),
    makeBundle(primary, { status: 'deleted', age: 2 * DAY }, db, admin),
    makeBundle(secondary, { status: 'ready_on_device', age: 0 }, db, admin),
  ]
  const rest: Plan[] = [
    { status: 'capturing', age: 0 },
    { status: 'ready_on_device', age: HOUR, last_error: 'upload stopped: the PC went offline after 38 of 61 MB' },
    { status: 'collecting', age: 2 * HOUR },
    { status: 'failed', age: 3 * HOUR, last_error: 'could not create the bundle file: there is not enough space on the disk (os error 112)' },
    { status: 'expired', age: 20 * DAY },
  ]
  const others = cands.filter((i) => i !== primary && i !== secondary)
  rest.forEach((p, i) => out.push(makeBundle(others.length ? others[i % others.length] : secondary, p, db, admin)))
  return out
}

function store(db: MockDb): EvidenceBundle[] {
  evidenceStore.bundles ??= seedEvidence(db)
  return evidenceStore.bundles
}

/** Live fields the server fills in on every read. */
function view(b: EvidenceBundle, devices: Device[]): EvidenceBundle {
  const d = devices.find((x) => x.id === b.device_id)
  return { ...b, device_online: d ? d.status !== 'offline' : false }
}

const PW_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
function password(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(24))
  return [...bytes].map((x) => PW_ALPHABET[x % PW_ALPHABET.length]).join('')
}

/** Delay before a queued mock collection reaches `stored` (an online PC). */
export const evidenceMockTiming = { uploadMs: 4_000 }

export function registerEvidenceRoutes({ route, db, emit, me, requirePriv, err }: EvidenceRouteCtx) {
  const find = (id: string) => {
    const b = store(db).find((x) => x.id === id)
    if (!b) throw err(404, 'not_found', 'Evidence bundle not found')
    return b
  }
  const changed = (b: EvidenceBundle) => emit({ kind: 'evidence', id: b.id, type: 'updated' })
  const retentionDays = () => db.settings.retention_days.evidence ?? EVIDENCE_RETENTION_DEFAULT_DAYS
  /** Optional `{"reason"}` (≤ 200 characters), as the server. */
  const reasonOf = (body: unknown): string => {
    const r = (body as { reason?: unknown } | undefined)?.reason
    if (r == null) return ''
    if (typeof r !== 'string') throw err(400, 'bad_request', 'reason must be a string')
    if ([...r].length > 200) throw err(400, 'bad_request', 'reason must be at most 200 characters')
    return r.trim()
  }
  /** Admins with MFA need a code confirmed in the last 10 minutes (collect / download). */
  const stepUp = (u: User) => {
    if (u.mfa_enabled && reauth.until < Date.now()) throw err(403, 'forbidden', 'Re-authentication required', { reason: 'reauth_required' })
  }

  route('GET', '/incidents/:id/evidence', ({ params }) => {
    me()
    db.refreshDevices()
    const items = store(db)
      .filter((b) => b.incident_id === params.id)
      .sort((a, b) => b.created_at - a.created_at)
      .map((b) => view(b, db.devices))
    return { items }
  })
  route('GET', '/evidence/:id', ({ params }) => (me(), db.refreshDevices(), view(find(params.id), db.devices)))
  route('POST', '/evidence/:id/collect', ({ params, body }) => {
    const u = me()
    requirePriv(u, 'evidence.download')
    const reason = reasonOf(body)
    stepUp(u)
    const b = find(params.id)
    if (b.status !== 'ready_on_device') throw err(409, 'conflict', 'the bundle is not on the PC waiting to be collected', { reason: 'not_ready' })
    if (!b.agent_supports_evidence) throw err(409, 'conflict', 'the agent on this device is too old to upload evidence', { reason: 'agent_too_old' })
    db.refreshDevices()
    const online = view(b, db.devices).device_online
    Object.assign(b, { status: 'collecting', collect_requested_at: Date.now(), collect_requested_by: u.name, last_error: null })
    db.log(u, 'evidence.collect_requested', b.hostname, { bundle_id: b.id, hostname: b.hostname, incident_id: b.incident_id, rule_id: b.rule_id, bytes: b.bundle_size, reason })
    changed(b)
    if (online)
      setTimeout(() => {
        if (b.status !== 'collecting') return
        const now = Date.now()
        Object.assign(b, { status: 'stored', collected_at: now, expires_at: now + retentionDays() * DAY, local_expires_at: null })
        db.log(null, 'evidence.collected', b.hostname, { bundle_id: b.id, hostname: b.hostname, bytes: b.bundle_size, sha256: b.bundle_sha256 })
        changed(b)
      }, evidenceMockTiming.uploadMs)
    return view(b, db.devices)
  })
  route('POST', '/evidence/:id/download', ({ params, body }): EvidenceDownloadTicket => {
    const u = me()
    requirePriv(u, 'evidence.download')
    const reason = reasonOf(body)
    stepUp(u)
    const b = find(params.id)
    if (b.status !== 'stored') throw err(409, 'conflict', 'this evidence is no longer stored', { reason: 'not_ready' })
    const now = Date.now()
    b.downloads += 1
    b.last_downloaded_at = now
    const file_name = `kestrel-evidence-${b.hostname}-${b.id.slice(0, 8)}.zip`
    // Mock: the browser fetches a data: URL, so the stream's own audit entries (evidence.downloaded) are not simulated.
    db.log(u, 'evidence.download_started', b.hostname, { bundle_id: b.id, hostname: b.hostname, file_name, bytes: b.bundle_size, reason })
    changed(b)
    // Mock: a tiny text file instead of the AES-256 zip.
    const text = `Kestrel mock evidence download for bundle ${b.id}.\nThe real server sends an AES-256 encrypted zip here.\n`
    return { download_id: hex(32), password: password(), file_name, size: b.bundle_size, expires_at: now + 10 * MIN, url: `data:application/octet-stream;base64,${btoa(text)}` }
  })
  route('DELETE', '/evidence/:id', ({ params, body }) => {
    const u = me()
    requirePriv(u, 'evidence.download')
    const reason = reasonOf(body)
    stepUp(u)
    const b = find(params.id)
    if (b.status !== 'stored' && b.status !== 'ready_on_device' && b.status !== 'collecting') throw err(409, 'conflict', 'there is nothing left to delete for this bundle', { reason: 'not_ready' })
    const from = b.status === 'stored' ? 'server' : 'device'
    Object.assign(b, { status: 'deleted', deleted_at: Date.now(), deleted_by: u.name })
    db.log(u, 'evidence.deleted', b.hostname, { bundle_id: b.id, hostname: b.hostname, from, reason })
    changed(b)
    return view(b, db.devices)
  })
}
