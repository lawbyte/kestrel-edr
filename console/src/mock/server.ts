import type {
  AlertRow,
  CreatedEnrollmentToken,
  Dashboard,
  Device,
  DeviceEvent,
  ExclusionScope,
  IncidentDetail,
  LiveEvent,
  Policy,
  ProcessInfo,
  ResponseAction,
  ResponseActionRow,
  ReviewRequestRow,
  RuleRow,
  Settings,
  Severity,
  User,
} from '@/api/types'
import { actionPrivilege, HARDENING_CONTROLS, HARDENING_INFO, ROLE_PRIVILEGES, SEVERITY_RANK } from '@/lib/labels'
import { evaluate, parseHunt } from '@/lib/hunt'
import { toHuntRecord } from '@/lib/events'
import { MockDb } from './db'
import { DAY, HOUR, MIN, NOW, POLICY_UPDATED, computeStatus, inventoryFor, policySummary } from './fleet'
import { liveIncident } from './scenarios'
import { fullAlerts, toAlertRow } from './story'
import { hexId, int, uuid } from './rng'
import { MockUpdates, UpdateError, seedUpdates } from './updates'
import { parseManifest } from '@/lib/updates'
import { reconcilePause } from '@/lib/pause'
import type { GroupUpdateRing, UpdateRing } from '@/api/types'
import { GROUP_UPDATE_RINGS, LOCAL_PAUSE_DEFAULTS, PAUSE_MAX_MINUTES_CAP } from '@/api/types'
import type { EnrollmentToken, FileUploadResult, RemoteAccessProfile, RemoteErrorCode } from '@/api/types'
import { ApiError, apiErrorFrom } from '@/api/client'
import { blockedPrefix, fileOpDenied, hoursContain, isNoneProfile, normaliseProfile, presetOf, profileSummary, validateProfile, type FileOpClass } from '@/lib/remote-profile'
import { pathIsWithin, validateRemotePath } from '@/lib/remote-path'
import { fsFor, RemoteFsError } from './remote-files'
import { consentedFmSessions, desktopSessions, reauth, remoteAccessFor } from './remote-state'

type Handler = (req: { params: Record<string, string>; query: URLSearchParams; body: unknown; method: string }) => unknown

class HttpError extends Error {
  status: number
  code: string
  remoteCode?: RemoteErrorCode
  extra?: Record<string, unknown>
  constructor(status: number, code: string, message: string, remoteCode?: RemoteErrorCode, extra?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.remoteCode = remoteCode
    this.extra = extra
  }
}
/** A non-JSON response (file download). */
class RawBody {
  blob: Blob
  headers: Record<string, string>
  constructor(blob: Blob, headers: Record<string, string>) {
    this.blob = blob
    this.headers = headers
  }
}
const notFound = (what = 'Resource') => new HttpError(404, 'not_found', `${what} not found`)
const bad = (m: string) => new HttpError(400, 'bad_request', m)

export const db = new MockDb()
export const updates = new MockUpdates(
  () => db.devices,
  () => db.groups,
)
seedUpdates(updates, db.devices, db.groups, db.users)
db.refreshDevices()
const live = new Set<(e: LiveEvent) => void>()
export function subscribeMockLive(fn: (e: LiveEvent) => void) {
  live.add(fn)
  return () => live.delete(fn)
}
function emit(e: LiveEvent) {
  for (const f of live) f(e)
}

const routes: { method: string; re: RegExp; keys: string[]; h: Handler }[] = []
function route(method: string, path: string, h: Handler) {
  const keys: string[] = []
  const re = new RegExp('^' + path.replace(/:(\w+)/g, (_, k) => (keys.push(k), '([^/]+)')) + '$')
  routes.push({ method, re, keys, h })
}

function me(): User {
  if (!db.session) throw new HttpError(401, 'unauthorized', 'Sign in to continue')
  return db.session
}
function page<T>(items: T[], q: URLSearchParams) {
  const limit = Number(q.get('limit') ?? 50)
  const cursor = Number(q.get('cursor') ?? 0)
  const slice = items.slice(cursor, cursor + limit)
  return { items: slice, next_cursor: cursor + limit < items.length ? String(cursor + limit) : null, total: items.length }
}
function csv(q: URLSearchParams, k: string): string[] {
  return (q.get(k) ?? '').split(',').filter(Boolean)
}
function stripIncident(i: IncidentDetail) {
  const { storyline: _s, alerts: _a, process_tree: _p, timeline: _t, evidence: _e, network: _n, actions: _ac, checklist: _c, comments: _co, ...rest } = i
  return rest
}
function findIncident(id: string) {
  const i = db.incidents.find((x) => x.id === id)
  if (!i) throw notFound('Incident')
  return i
}
function findDevice(id: string) {
  const d = db.devices.find((x) => x.id === id)
  if (!d) throw notFound('Device')
  return d
}
function alertRows(): AlertRow[] {
  return db.alerts.map(toAlertRow).sort((a, b) => b.ts - a.ts)
}

function textMatch(q: string | null, ...fields: (string | null | undefined)[]) {
  if (!q) return true
  const s = q.toLowerCase()
  return fields.some((f) => f?.toLowerCase().includes(s))
}

// ------------------------------------------------------------------ auth

route('GET', '/auth/setup-status', () => ({ needs_setup: db.needsSetup, oidc_enabled: db.settings.oidc.enabled, org_name: db.settings.org_name }))
route('POST', '/auth/setup', ({ body }) => {
  const b = body as { setup_code?: string; org_name: string; email: string; password: string; name: string }
  if (!db.needsSetup) throw new HttpError(409, 'conflict', 'Setup already completed')
  if (!b.setup_code?.trim()) throw new HttpError(403, 'forbidden', 'Invalid setup code (it is printed in the server log at startup)')
  if (!b.email || !b.password || b.password.length < 12) throw bad('Password must be at least 12 characters')
  db.settings.org_name = b.org_name
  const u: User = { id: uuid(), email: b.email, name: b.name, role: 'admin', last_login: Date.now(), created_at: Date.now(), disabled: false, mfa_enabled: false }
  db.users.unshift(u)
  db.needsSetup = false
  db.session = u
  db.log(u, 'auth.setup', 'org', { org_name: b.org_name })
  return { user: u, csrf_token: hexId(32) }
})
route('POST', '/auth/login', ({ body }) => {
  const b = body as { email: string; password: string; totp?: string }
  const u = db.users.find((x) => x.email.toLowerCase() === (b.email ?? '').toLowerCase())
  if (!u || !b.password) throw new HttpError(401, 'unauthorized', 'Email or password is incorrect')
  if (u.disabled) throw new HttpError(403, 'forbidden', 'This account is disabled. Ask an administrator to re-enable it.')
  if (u.mfa_enabled && !b.totp) throw new HttpError(401, 'mfa_required', 'Enter the 6-digit code from your authenticator app')
  if (u.mfa_enabled && !/^\d{6}$/.test(b.totp ?? '')) throw new HttpError(401, 'unauthorized', 'That code is not valid. Codes are 6 digits.')
  u.last_login = Date.now()
  db.session = u
  // Mirrors the server: require_mfa without an enrolled authenticator gives a setup-only session.
  mfa.setupOnly = db.settings.require_mfa && !u.mfa_enabled
  db.log(u, 'auth.login', u.email, { method: mfa.setupOnly ? 'password_mfa_setup' : 'password' })
  return { user: u, csrf_token: hexId(32) }
})
route('POST', '/auth/logout', () => {
  db.session = null
  mfa.setupOnly = false
  return undefined
})
route('GET', '/me', () => {
  const u = me()
  if (mfa.setupOnly) return { user: u, csrf_token: hexId(32), privileges: [], mfa_setup_required: true }
  return { user: u, csrf_token: hexId(32), privileges: ROLE_PRIVILEGES[u.role] ?? ['read'] }
})

// ------------------------------------------------------------------ MFA self-service (/me/mfa/*)

/** Mock MFA state: pending (not yet active) secrets per user, wrong-code throttle, setup-only session. */
export const mfa = { pending: new Map<string, string>(), wrong: 0, lockedUntil: 0, setupOnly: false }
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
route('POST', '/me/mfa/setup', () => {
  const u = me()
  if (u.mfa_enabled) throw new HttpError(409, 'conflict', 'MFA already enabled')
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  const secret = [...bytes].map((b) => B32[b % 32]).join('')
  mfa.pending.set(u.id, secret)
  return { secret, otpauth_url: `otpauth://totp/Kestrel:${encodeURIComponent(u.email)}?secret=${secret}&algorithm=SHA1&digits=6&period=30&issuer=Kestrel` }
})
route('POST', '/me/mfa/enable', ({ body }) => {
  const u = me()
  const totp = String((body as { totp?: unknown })?.totp ?? '')
  if (!mfa.pending.has(u.id)) throw bad('call /api/me/mfa/setup first')
  // The real server does not throttle enrolment codes; the mock does so the 429 path can be seen.
  if (mfa.lockedUntil > Date.now()) throw new HttpError(429, 'rate_limited', 'too many wrong codes', undefined, { retry_after_ms: mfa.lockedUntil - Date.now() })
  // Mock: any 6 digits except 000000 (to show the wrong-code path).
  if (!/^\d{6}$/.test(totp) || totp === '000000') {
    if (++mfa.wrong >= 5) {
      mfa.wrong = 0
      mfa.lockedUntil = Date.now() + 30_000
    }
    throw new HttpError(400, 'bad_request', 'invalid TOTP code', undefined, { reason: 'invalid_totp' })
  }
  mfa.wrong = 0
  mfa.pending.delete(u.id)
  u.mfa_enabled = true
  mfa.setupOnly = false
  db.log(u, 'user.mfa_enabled', u.id)
  return { user: u }
})
route('POST', '/me/mfa/disable', ({ body }) => {
  const u = me()
  const password = String((body as { password?: unknown })?.password ?? '')
  if (db.settings.require_mfa) throw new HttpError(403, 'forbidden', 'MFA is required by policy')
  if (u.local_password === false || !password || password === 'wrong') throw new HttpError(403, 'forbidden', 'password is wrong')
  u.mfa_enabled = false
  db.log(u, 'user.mfa_disabled', u.id)
  return undefined
})

// ------------------------------------------------------------------ dashboard

route('GET', '/dashboard', (): Dashboard => {
  me()
  db.refreshDevices()
  const devs = db.devices
  const open = db.incidents.filter((i) => i.status === 'open' || i.status === 'in_progress')
  const now = Date.now()
  const trend: Dashboard['alert_trend'] = []
  for (let i = 13; i >= 0; i--) {
    const start = new Date(now - i * DAY)
    start.setHours(0, 0, 0, 0)
    const end = start.getTime() + DAY
    const day = db.alerts.filter((a) => a.ts >= start.getTime() && a.ts < end)
    trend.push({
      day: start.toISOString().slice(0, 10),
      critical: day.filter((a) => a.severity === 'critical').length,
      high: day.filter((a) => a.severity === 'high').length,
      medium: day.filter((a) => a.severity === 'medium').length,
      low: day.filter((a) => a.severity === 'low' || a.severity === 'info').length,
    })
  }
  const counts = new Map<string, number>()
  for (const a of db.alerts) if (a.ts > now - 14 * DAY) counts.set(a.rule_id, (counts.get(a.rule_id) ?? 0) + 1)
  const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([rule_id, count]) => ({ rule_id, name: db.rules.get(rule_id)?.name ?? rule_id, count }))
  const dar = new Map<string, number>()
  for (const i of db.incidents) if (i.created_at > now - 30 * DAY && i.classification !== 'benign' && i.classification !== 'false_positive') for (const c of i.data_at_risk) dar.set(c, (dar.get(c) ?? 0) + 1)
  const vers = new Map<string, number>()
  for (const d of devs) vers.set(d.agent_version, (vers.get(d.agent_version) ?? 0) + 1)
  const resolved = db.incidents.filter((i) => i.status === 'resolved' || i.status === 'dismissed')
  const mttr = resolved.length ? resolved.reduce((s, i) => s + (i.updated_at - i.created_at), 0) / resolved.length / HOUR : 0
  return {
    devices: {
      total: devs.length,
      online: devs.filter((d) => d.status === 'online').length,
      offline: devs.filter((d) => d.status === 'offline').length,
      isolated: devs.filter((d) => d.status === 'isolated').length,
      degraded: devs.filter((d) => d.status === 'degraded').length,
      paused: devs.filter((d) => d.status === 'paused').length,
    },
    incidents: { open: open.length, critical: open.filter((i) => i.severity === 'critical').length, high: open.filter((i) => i.severity === 'high').length, mttr_hours_30d: Math.round(mttr * 10) / 10 },
    alerts_24h: db.alerts.filter((a) => a.ts > now - DAY).length,
    blocked_24h: db.actions.filter((a) => a.requested_by == null && a.created_at > now - DAY && a.status === 'succeeded').length,
    alert_trend: trend,
    top_rules: top,
    data_at_risk_30d: [...dar.entries()].sort((a, b) => b[1] - a[1]).map(([category, count]) => ({ category: category as Dashboard['data_at_risk_30d'][number]['category'], count })),
    hardening_coverage: HARDENING_CONTROLS.map((c) => {
      const want = devs.filter((d) => {
        const p = db.policies.find((x) => x.id === d.policy_id)
        return p && p.hardening.mode !== 'off' && p.hardening[c]
      })
      return { control: c, applied: want.filter((d) => d.health.hardening?.[c]).length, total: want.length }
    }),
    agent_versions: [...vers.entries()].sort((a, b) => b[0].localeCompare(a[0])).map(([version, count]) => ({ version, count })),
    recent_incidents: [...db.incidents].sort((a, b) => b.created_at - a.created_at).slice(0, 5).map(stripIncident),
  }
})

// ------------------------------------------------------------------ devices

route('GET', '/devices', ({ query }) => {
  me()
  db.refreshDevices()
  const status = csv(query, 'status')
  const items = db.devices
    .filter((d) => (!status.length || status.includes(d.status)) && (!query.get('group_id') || d.group_id === query.get('group_id')))
    .filter((d) => textMatch(query.get('q'), d.hostname, d.logged_on_user, d.ip_addresses.join(' '), d.os_name))
    .sort((a, b) => a.hostname.localeCompare(b.hostname))
  return page(items, query)
})
route('GET', '/devices/:id', ({ params }) => {
  me()
  db.refreshDevices()
  const d = findDevice(params.id)
  const pol = db.policies.find((p) => p.id === d.policy_id) ?? db.policies[0]
  return {
    device: { ...d, cert_expires_at: d.cert_expires_at ?? d.first_seen + 365 * DAY, uninstall_token_set: d.uninstall_token_set ?? true },
    duplicates: [],
    inventory: inventoryFor(d),
    recent_alerts: alertRows().filter((a) => a.device_id === d.id).slice(0, 20),
    effective_policy: effectivePolicy(pol),
    remote_access: remoteAccessFor(d, pol),
    hardening: HARDENING_CONTROLS.map((c) => ({
      control: c,
      desired: pol.hardening.mode !== 'off' && pol.hardening[c],
      applied: !!d.health.hardening?.[c],
      source: pol.hardening.mode === 'off' ? 'Not managed' : `Policy “${pol.name}” v${pol.version}${(c === 'asr_rules' || c === 'asr_lsass') && d.health.av_product !== 'Microsoft Defender Antivirus' ? ' (needs Defender as active AV)' : ''}`,
      ...(HARDENING_INFO[c].reportOnly ? { report_only: true } : {}),
      ...(d.health.hardening?.[`${c}_pending_reboot`] ? { pending_reboot: true } : {}),
    })),
  }
})
function effectivePolicy(p: Policy): Policy {
  const global = db.exclusions.filter((e) => e.policy_id === null || e.policy_id === p.id)
  return { ...p, exclusions: global.map(({ policy_id: _p, created_by: _c, created_at: _t, ...e }) => e), iocs: db.iocs.map(({ created_by: _c, created_at: _t, hits: _h, policy_id: _p, ...i }) => i) }
}
route('PATCH', '/devices/:id', ({ params, body }) => {
  const u = me()
  const d = findDevice(params.id)
  const b = body as { group_id?: string; tags?: string[] }
  if (b.group_id) {
    const g = db.groups.find((x) => x.id === b.group_id)
    if (!g) throw bad('Unknown group')
    const p = db.policies.find((x) => x.id === g.policy_id)
    d.group_id = g.id
    d.group_name = g.name
    d.policy_id = p?.id ?? null
    d.policy_name = p?.name ?? null
  }
  if (b.tags) d.tags = b.tags
  db.log(u, 'device.update', d.hostname, b as Record<string, unknown>)
  db.refreshDevices()
  emit({ kind: 'device', id: d.id, type: 'updated' })
  return d
})
route('DELETE', '/devices/:id', ({ params }) => {
  const u = me()
  requirePriv(u, 'devices.write')
  const d = findDevice(params.id)
  db.devices = db.devices.filter((x) => x.id !== d.id)
  db.log(u, 'device.decommission', d.hostname)
  return undefined
})
route('GET', '/devices/:id/events', ({ params, query }) => {
  me()
  const d = findDevice(params.id)
  const t = db.telemetryFor(d)
  const kinds = csv(query, 'kinds')
  const q = query.get('q')
  const from = Number(query.get('from') ?? 0)
  const to = Number(query.get('to') ?? Number.MAX_SAFE_INTEGER)
  const limit = Number(query.get('limit') ?? 200)
  const items = t.events
    .filter((e) => (!kinds.length || kinds.includes(e.type)) && e.ts >= from && e.ts <= to)
    .filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q.toLowerCase()))
    .slice(0, limit)
    .map((e) => (e.type === 'process_start' ? e : { ...e, process_image: t.procs.get(e.guid)?.image }))
  return { items }
})
route('GET', '/devices/:id/processes', ({ params, query }) => {
  me()
  const d = findDevice(params.id)
  const t = db.telemetryFor(d)
  const at = Number(query.get('at') ?? Date.now())
  const items: ProcessInfo[] = [...t.procs.values()].filter((p) => p.start_ts <= at && (p.exit_ts == null || p.exit_ts > at))
  return { items }
})
// Mock uninstall tokens: current + pending (promoted when the "agent" confirms).
const UNINSTALL_TOKENS: Record<string, { token: string; pending: string | null }> = {}
const uninstallTokens = (id: string) => (UNINSTALL_TOKENS[id] ??= { token: `kun_${hexId(32)}`, pending: null })
route('POST', '/devices/:id/uninstall-token/reveal', ({ params }) => {
  const u = me()
  const d = findDevice(params.id)
  db.log(u, 'device.uninstall_token_revealed', d.hostname)
  const t = uninstallTokens(d.id)
  return { token: t.token, pending_token: t.pending }
})
route('POST', '/devices/:id/uninstall-token/rotate', ({ params }) => {
  const u = me()
  const d = findDevice(params.id)
  db.log(u, 'device.uninstall_token_rotated', d.hostname)
  const t = uninstallTokens(d.id)
  const token = `kun_${hexId(32)}`
  t.pending = token
  const sent = d.status !== 'offline'
  d.uninstall_token_pending = true
  if (sent) {
    // A connected agent stores the new hash and acks within a moment.
    setTimeout(() => {
      if (t.pending === token) {
        t.token = token
        t.pending = null
        d.uninstall_token_pending = false
        db.log(null, 'device.uninstall_token_activated', d.hostname)
      }
    }, 1500)
  }
  return {
    pending_token: token,
    token_active: false,
    sent,
    message: sent
      ? 'New token sent to the agent. It becomes current as soon as the agent confirms it; until then the previous token keeps working.'
      : 'The device is offline: the new token is sent when the agent next connects. Until the agent confirms it, the previous token keeps working.',
  }
})
route('POST', '/devices/:id/merge', ({ params, body }) => {
  const u = me()
  const d = findDevice(params.id)
  const other = (body as { device_id: string }).device_id
  db.devices = db.devices.filter((x) => x.id !== other)
  d.possible_duplicates = []
  db.log(u, 'device.merge', d.hostname, { merged: other })
  return d
})
route('POST', '/devices/:id/duplicates/dismiss', ({ params, body }) => {
  const u = me()
  const d = findDevice(params.id)
  const other = (body as { device_id: string }).device_id
  d.possible_duplicates = (d.possible_duplicates ?? []).filter((x) => x !== other)
  db.log(u, 'device.duplicate_dismissed', d.hostname, { other })
  return undefined
})
route('POST', '/devices/:id/actions', ({ params, body }) => {
  const u = me()
  const d = findDevice(params.id)
  const b = body as { action: ResponseAction; incident_id?: string; comment?: string }
  if ((b.action.type === 'kill_process' || b.action.type === 'suspend_process' || b.action.type === 'resume_process') && !b.action.guid)
    throw bad('process actions need the process guid (a PID alone may be reused)')
  requirePriv(u, actionPrivilege(b.action))
  const row = issueAction(d, b.action, u, b.comment ?? '', b.incident_id ?? null)
  return row
})

/** Mirrors the server: 403 unless the user's role grants priv (admin has *). */
function requirePriv(u: User, priv: string) {
  const privs = ROLE_PRIVILEGES[u.role] ?? ['read']
  if (!privs.includes('*') && !privs.includes(priv)) throw new HttpError(403, 'forbidden', `You need the ${priv} privilege`)
}

/** Block ids (action artifacts) lifted by `unblock_network` in this mock session. */
const liftedBlocks = new Set<string>()

function issueAction(d: Device, action: ResponseAction, u: User, comment: string, incidentId: string | null): ResponseActionRow {
  const row: ResponseActionRow = {
    id: uuid(),
    device_id: d.id,
    hostname: d.hostname,
    incident_id: incidentId,
    action,
    status: d.status === 'offline' ? 'pending' : 'sent',
    requested_by: u,
    comment,
    created_at: Date.now(),
    completed_at: null,
    result_detail: '',
  }
  db.actions.unshift(row)
  db.log(u, 'response.request', d.hostname, { action: action.type, incident_id: incidentId, comment })
  const inc = incidentId ? db.incidents.find((i) => i.id === incidentId) : null
  if (inc) {
    inc.actions.unshift(row)
    inc.timeline.push({ ts: row.created_at, kind: 'action', title: `Requested: ${action.type.replace(/_/g, ' ')}`, detail: comment, actor: u.name })
    inc.updated_at = row.created_at
  }
  if (d.status !== 'offline') {
    setTimeout(() => {
      row.status = 'succeeded'
      row.completed_at = Date.now()
      switch (action.type) {
        case 'isolate_host':
          d.health.isolated = true
          row.result_detail = 'Host isolated; only the Kestrel server is reachable'
          break
        case 'release_host':
          d.health.isolated = false
          row.result_detail = 'Isolation removed'
          break
        case 'kill_process':
          row.result_detail = `Terminated ${action.tree ? int(1, 3) : 1} process(es)`
          if (inc) inc.contained = true
          break
        case 'quarantine_file':
          row.result_detail = 'Moved to quarantine vault'
          db.quarantine.unshift({ id: uuid(), device_id: d.id, hostname: d.hostname, sha256: action.sha256 ?? hexId(64), original_path: action.path, alert_id: inc?.alerts[0]?.id ?? null, state: 'held', created_at: Date.now() })
          break
        case 'collect_triage':
          row.result_detail = `Triage package uploaded (${(2 + Math.random() * 4).toFixed(1)} MB)`
          break
        case 'scan':
          row.result_detail = `YARA-X scan: ${int(20, 400)} files, 0 matches`
          break
        case 'resume_protection': {
          // Mirrors the agent: ends the local pause (no-op when not paused) and reports it.
          const p = d.health.pause
          if (!p) {
            row.result_detail = 'Protection was already on'
            break
          }
          d.health.pause = null
          d.pause = null
          d.status = computeStatus(d)
          row.result_detail = 'Protection turned back on'
          db.log(null, 'device.protection_on', d.hostname, { hostname: d.hostname, mode: p.mode, since_ms: p.since_ms, until_ms: p.until_ms, by_user: '', reason: 'console' })
          break
        }
        case 'apply_hardening':
          row.result_detail = 'Hardening re-applied: all desired controls in effect'
          for (const k of Object.keys(d.health.hardening ?? {})) {
            const p = db.policies.find((x) => x.id === d.policy_id)
            // LSA protection still waits for a reboot; report-only controls are never changed.
            if (k === 'lsa_protection' && d.health.hardening?.lsa_protection_pending_reboot) continue
            if (k === 'report_vulnerable_driver_blocklist' || k.endsWith('_pending_reboot')) continue
            if (p && p.hardening[k as keyof Policy['hardening']]) d.health.hardening![k] = true
          }
          break
        case 'block_destination':
        case 'block_image_network':
          row.artifact = uuid()
          row.result_detail = `${action.type === 'block_image_network' ? `blocked all network traffic for ${action.image}` : `blocked outbound ${action.ip}`} (block ${row.artifact}, ${action.ttl_secs ? `expires in ${action.ttl_secs}s` : 'no expiry'})`
          break
        case 'unblock_network': {
          // Lift the matching succeeded blocks on this device (mirrors BlockSelector).
          const norm = (p: string) =>
            p
              .trim()
              .replace(/\//g, '\\')
              .replace(/^\\\\\?\\/, '')
              .toLowerCase()
          const lifted = db.actions.filter((r) => {
            if (r.device_id !== d.id || r.status !== 'succeeded' || !r.artifact || liftedBlocks.has(r.artifact)) return false
            if (r.action.type !== 'block_image_network' && r.action.type !== 'block_destination') return false
            const img = r.action.image ?? null
            if (action.block_id && action.block_id !== r.artifact) return false
            if (action.image && (!img || norm(img) !== norm(action.image))) return false
            return true
          })
          for (const r of lifted) liftedBlocks.add(r.artifact!)
          row.result_detail = lifted.length ? `lifted ${lifted.length} network block(s)` : `no matching block`
          break
        }
        case 'remove_autorun':
          row.artifact = `ar-${hexId(12)}`
          row.result_detail =
            action.kind === 'service'
              ? `Service ${action.location} stopped and disabled; configuration exported`
              : action.restore_data != null
                ? `Value restored to ${action.restore_data}; previous data backed up`
                : `Entry re-read, backed up and removed`
          break
        default:
          row.result_detail = 'Done'
      }
      if (inc) {
        inc.timeline.push({ ts: row.completed_at, kind: 'action', title: `${action.type.replace(/_/g, ' ')} succeeded`, detail: row.result_detail, actor: 'Kestrel agent' })
        inc.updated_at = row.completed_at
        emit({ kind: 'incident', id: inc.id, type: 'updated' })
      }
      db.refreshDevices()
      emit({ kind: 'action', id: row.id, type: 'updated' })
      emit({ kind: 'device', id: d.id, type: 'updated' })
    }, 1800)
  }
  emit({ kind: 'action', id: row.id, type: 'created' })
  return row
}

// ------------------------------------------------------------------ groups & enrollment

route('GET', '/groups', () => (me(), db.refreshDevices(), db.groups))
function checkRing(r: unknown): GroupUpdateRing {
  if (!GROUP_UPDATE_RINGS.includes(r as GroupUpdateRing)) throw bad(`update_ring must be one of ${GROUP_UPDATE_RINGS.join(', ')}`)
  return r as GroupUpdateRing
}
route('POST', '/groups', ({ body }) => {
  const u = me()
  const b = body as { name: string; description: string; policy_id: string | null; update_ring?: GroupUpdateRing }
  if (!b.name?.trim()) throw bad('Name is required')
  const update_ring = b.update_ring === undefined ? 'broad' : checkRing(b.update_ring)
  const g = { id: `grp-${hexId(6)}`, name: b.name, description: b.description ?? '', policy_id: b.policy_id, device_count: 0, is_default: false, update_ring }
  db.groups.push(g)
  db.log(u, 'group.create', g.name, { update_ring })
  emit({ kind: 'group', id: g.id, type: 'created' })
  return g
})
route('PATCH', '/groups/:id', ({ params, body }) => {
  const u = me()
  const g = db.groups.find((x) => x.id === params.id)
  if (!g) throw notFound('Group')
  const b = body as { name?: string; description?: string; policy_id?: string | null; update_ring?: GroupUpdateRing }
  if (b.update_ring !== undefined) g.update_ring = checkRing(b.update_ring)
  if (b.name !== undefined) g.name = b.name
  if (b.description !== undefined) g.description = b.description
  if (b.policy_id !== undefined) g.policy_id = b.policy_id
  for (const d of db.devices.filter((x) => x.group_id === g.id)) {
    const p = db.policies.find((x) => x.id === g.policy_id)
    d.group_name = g.name
    d.policy_id = p?.id ?? null
    d.policy_name = p?.name ?? null
  }
  db.log(u, 'group.update', g.name, body as Record<string, unknown>)
  emit({ kind: 'group', id: g.id, type: 'updated' })
  return g
})
route('DELETE', '/groups/:id', ({ params }) => {
  const u = me()
  const g = db.groups.find((x) => x.id === params.id)
  if (!g) throw notFound('Group')
  if (g.is_default) throw new HttpError(409, 'conflict', 'The default group cannot be deleted')
  if (db.devices.some((d) => d.group_id === g.id)) throw new HttpError(409, 'conflict', 'Move this group’s devices to another group first')
  db.groups = db.groups.filter((x) => x.id !== g.id)
  db.log(u, 'group.delete', g.name)
  return undefined
})
function tokenView(t: EnrollmentToken): EnrollmentToken {
  const p = normaliseProfile(t.remote_profile)
  return { ...t, remote_profile: p, remote_summary: profileSummary(p), remote_preset: presetOf(p) }
}
route('GET', '/enrollment-tokens', () => (me(), db.enrollment.map(tokenView)))
route('POST', '/enrollment-tokens', ({ body }): CreatedEnrollmentToken => {
  const u = me()
  const b = body as { group_id: string; expires_in_days: number; max_uses: number; remote_profile?: RemoteAccessProfile }
  const g = db.groups.find((x) => x.id === b.group_id)
  if (!g) throw bad('Choose a group')
  const profile = normaliseProfile(b.remote_profile)
  if (!isNoneProfile(profile) && !(canDo(u, 'remote.desktop') && canDo(u, 'remote.files')))
    throw new HttpError(403, 'forbidden', 'Only administrators (remote.desktop and remote.files) can create installers with remote access')
  const invalid = validateProfile(profile)
  if (invalid) throw bad(invalid)
  const token = db.newEnrollmentSecret()
  const t: EnrollmentToken = { id: uuid(), group_id: g.id, group_name: g.name, token_prefix: token.slice(0, 8), created_at: Date.now(), expires_at: Date.now() + b.expires_in_days * DAY, max_uses: b.max_uses, uses: 0, revoked: false, remote_profile: profile }
  db.enrollment.unshift(t)
  const view = tokenView(t)
  db.log(u, 'enrollment_token.created', g.name, { expires_in_days: b.expires_in_days, max_uses: b.max_uses, remote_profile: profile, remote_summary: view.remote_summary })
  const host = typeof location !== 'undefined' ? location.host : 'kestrel.example.com'
  const preset = view.remote_preset ?? 'custom'
  const filename = `Install-Kestrel-${preset}.cmd`
  const msiSha = '4f9c2a1be8d7360c51e2a9f04b7d3c86e1f5a0b9d2c48e7f6a3b1d0c9e8f7a6b'
  const cmd = [
    '@echo off',
    `rem Kestrel EDR agent installer (${filename})`,
    `rem Server:          ${host}`,
    `rem Group:           ${g.name}`,
    `rem Remote access:   ${view.remote_summary}`,
    `rem Token:           ${t.token_prefix}... (expires ${new Date(t.expires_at).toISOString().slice(0, 10)}, up to ${t.max_uses} devices)`,
    'rem This file contains an enrollment token. Treat it like a password and delete it after use.',
    'setlocal',
    'net session >nul 2>&1 || (powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath \'%~f0\'" & exit /b)',
    `set "KESTREL_SERVER=${host}"`,
    `set "KESTREL_TOKEN=${token}"`,
    `set "KESTREL_MSI_SHA256=${msiSha}"`,
    'powershell -NoProfile -ExecutionPolicy Bypass -Command ^',
    '  "$m=Join-Path $env:TEMP \'KestrelAgent.msi\';" ^',
    '  "Invoke-WebRequest -UseBasicParsing https://$env:KESTREL_SERVER/downloads/KestrelAgent.msi -OutFile $m;" ^',
    '  "if ((Get-FileHash $m -Algorithm SHA256).Hash -ne $env:KESTREL_MSI_SHA256) { Write-Error \'MSI hash mismatch\'; exit 2 };" ^',
    '  "$p=Start-Process msiexec.exe -Wait -PassThru -ArgumentList \'/i\',$m,\'/qn\',(\'SERVER=\'+$env:KESTREL_SERVER),(\'TOKEN=\'+$env:KESTREL_TOKEN),\'/l*v\',(Join-Path $env:TEMP \'kestrel-install.log\');" ^',
    '  "exit $p.ExitCode"',
    'echo Kestrel installer finished with exit code %ERRORLEVEL%.',
    'endlocal',
    '',
  ].join('\r\n')
  return {
    ...view,
    token,
    install_command: `$m="$env:TEMP\\kestrel-agent.msi"; Invoke-WebRequest -UseBasicParsing https://${host}/downloads/kestrel-agent-1.0.1-x64.msi -OutFile $m; Start-Process msiexec.exe -Wait -ArgumentList "/i \`"$m\`" /qn KESTREL_SERVER=${host}:8443 ENROLL_TOKEN=${token}"`,
    installer_cmd: cmd,
    installer_filename: filename,
  }
})
route('DELETE', '/enrollment-tokens/:id', ({ params }) => {
  const u = me()
  const t = db.enrollment.find((x) => x.id === params.id)
  if (!t) throw notFound('Token')
  t.revoked = true
  db.log(u, 'enrollment_token.revoke', t.token_prefix)
  return undefined
})
route('GET', '/agent/installer', () => ({ version: '1.0.1', msi_url: '/downloads/kestrel-agent-1.0.1-x64.msi', sha256: '4f9c2a1be8d7360c51e2a9f04b7d3c86e1f5a0b9d2c48e7f6a3b1d0c9e8f7a6b' }))

// ------------------------------------------------------------------ incidents & alerts

route('GET', '/incidents', ({ query }) => {
  const u = me()
  const status = csv(query, 'status')
  const sev = csv(query, 'severity')
  const assignee = query.get('assignee')
  const items = db.incidents
    .filter((i) => (!status.length || status.includes(i.status)) && (!sev.length || sev.includes(i.severity)))
    .filter((i) => !assignee || (assignee === 'me' ? i.assignee?.id === u.id : assignee === 'none' ? !i.assignee : i.assignee?.id === assignee))
    .filter((i) => !query.get('device_id') || i.device_id === query.get('device_id'))
    .filter((i) => textMatch(query.get('q'), i.title, i.hostname, i.user, i.rule_ids.join(' ')))
    .sort((a, b) => (query.get('sort') === 'created' ? b.created_at - a.created_at : b.priority - a.priority || b.created_at - a.created_at))
    .map(stripIncident)
  return page(items, query)
})
route('GET', '/incidents/:id', ({ params }) => (me(), findIncident(params.id)))
route('PATCH', '/incidents/:id', ({ params, body }) => {
  const u = me()
  const i = findIncident(params.id)
  const b = body as { status?: IncidentDetail['status']; assignee_id?: string | null; classification?: IncidentDetail['classification'] }
  const now = Date.now()
  if (b.status && b.status !== i.status) {
    i.status = b.status
    i.timeline.push({ ts: now, kind: 'status', title: `Status → ${b.status.replace('_', ' ')}`, detail: '', actor: u.name })
    const st = b.status === 'resolved' || b.status === 'dismissed' ? 'closed' : b.status === 'in_progress' ? 'acknowledged' : 'new'
    for (const a of i.alerts) a.status = st
    for (const a of db.alerts.filter((x) => x.incident_id === i.id)) a.status = st
  }
  if (b.assignee_id !== undefined) {
    i.assignee = b.assignee_id ? (db.users.find((x) => x.id === b.assignee_id) ?? null) : null
    i.timeline.push({ ts: now, kind: 'status', title: i.assignee ? `Assigned to ${i.assignee.name}` : 'Unassigned', detail: '', actor: u.name })
  }
  if (b.classification !== undefined) {
    i.classification = b.classification
    i.timeline.push({ ts: now, kind: 'status', title: `Classified as ${b.classification?.replace('_', ' ') ?? 'unclassified'}`, detail: '', actor: u.name })
  }
  i.updated_at = now
  db.log(u, 'incident.update', i.title, b as Record<string, unknown>)
  db.refreshDevices()
  emit({ kind: 'incident', id: i.id, type: 'updated' })
  return stripIncident(i)
})
route('POST', '/incidents/:id/comments', ({ params, body }) => {
  const u = me()
  const i = findIncident(params.id)
  const text = (body as { body: string }).body?.trim()
  if (!text) throw bad('Comment is empty')
  const c = { id: uuid(), author: u, body: text, ts: Date.now() }
  i.comments.push(c)
  i.timeline.push({ ts: c.ts, kind: 'comment', title: 'Comment', detail: text, actor: u.name })
  i.updated_at = c.ts
  emit({ kind: 'incident', id: i.id, type: 'updated' })
  return c
})
route('POST', '/incidents/:id/checklist/:item', ({ params, body }) => {
  const u = me()
  const i = findIncident(params.id)
  const item = i.checklist.find((c) => c.id === params.item)
  if (!item) throw notFound('Checklist item')
  const done = (body as { done: boolean }).done
  // Approving an action needs that action's privilege (remove_autorun: response.persistence, admin only).
  if (done && item.kind === 'approve' && item.action) requirePriv(u, actionPrivilege(item.action))
  item.done = done
  if (done && item.kind === 'approve' && item.action) {
    const d = findDevice(i.device_id)
    issueAction(d, item.action, u, `Approved from checklist: ${item.text}`, i.id)
  }
  i.timeline.push({ ts: Date.now(), kind: 'status', title: `${done ? 'Completed' : 'Reopened'}: ${item.text}`, detail: '', actor: u.name })
  db.log(u, 'incident.checklist', i.title, { item: item.text, done })
  return item
})
route('GET', '/alerts', ({ query }) => {
  me()
  const status = csv(query, 'status')
  const sev = csv(query, 'severity')
  const items = alertRows()
    .filter((a) => (!status.length || status.includes(a.status)) && (!sev.length || sev.includes(a.severity)))
    .filter((a) => !query.get('device_id') || a.device_id === query.get('device_id'))
    .filter((a) => textMatch(query.get('q'), a.rule_id, a.rule_name, a.hostname, a.image, a.summary))
  return page(items, query)
})
route('GET', '/alerts/:id', ({ params }) => {
  me()
  const a = db.alerts.find((x) => x.id === params.id)
  if (!a) throw notFound('Alert')
  return a
})
route('PATCH', '/alerts', ({ body }) => {
  const u = me()
  const b = body as { ids: string[]; status: AlertRow['status'] }
  for (const a of db.alerts) if (b.ids.includes(a.id)) a.status = b.status
  for (const i of db.incidents) for (const a of i.alerts) if (b.ids.includes(a.id)) a.status = b.status
  db.log(u, 'alert.bulk_update', `${b.ids.length} alerts`, { status: b.status })
  emit({ kind: 'alert', id: b.ids[0], type: 'updated' })
  return undefined
})

// ------------------------------------------------------------------ actions

route('GET', '/actions', ({ query }) => {
  me()
  const status = csv(query, 'status')
  const items = [...db.actions]
    .filter((a) => (!status.length || status.includes(a.status)) && (!query.get('device_id') || a.device_id === query.get('device_id')))
    .sort((a, b) => b.created_at - a.created_at)
  return page(items, query)
})

// ------------------------------------------------------------------ policies & rules

route('GET', '/policies', () => (me(), db.policies.map((p) => policySummary(p, db.groups, db.devices))))
route('GET', '/policies/:id', ({ params }) => {
  me()
  const p = db.policies.find((x) => x.id === params.id)
  if (!p) throw notFound('Policy')
  return p
})
route('POST', '/policies', ({ body }) => {
  const u = me()
  const b = body as { name: string; clone_from?: string }
  if (!b.name?.trim()) throw bad('Name is required')
  const src = db.policies.find((x) => x.id === b.clone_from) ?? db.policies[0]
  const p: Policy = { ...structuredClone(src), id: `pol-${hexId(6)}`, name: b.name, version: 1 }
  db.policies.push(p)
  POLICY_UPDATED[p.id] = Date.now()
  db.log(u, 'policy.create', p.name, { clone_from: src.name })
  return p
})
route('PUT', '/policies/:id', ({ params, body }) => {
  const u = me()
  const i = db.policies.findIndex((x) => x.id === params.id)
  if (i < 0) throw notFound('Policy')
  const p = body as Policy
  if (p.suspend_window_ms < 500 || p.suspend_window_ms > 30000) throw bad('Suspend window must be between 0.5 and 30 seconds')
  if (!Number.isInteger(p.isolation_auto_release_hours) || p.isolation_auto_release_hours < 0 || p.isolation_auto_release_hours > 720)
    throw bad('Isolation auto-release must be between 0 (never) and 720 hours')
  if (!Number.isInteger(p.ioc_block_ttl_secs) || p.ioc_block_ttl_secs < 60 || p.ioc_block_ttl_secs > 30 * 86400)
    throw bad('Indicator block lifetime must be between 1 minute and 30 days')
  const lp = p.local_pause
  if (lp && (!Number.isInteger(lp.max_minutes) || lp.max_minutes < 1 || lp.max_minutes > PAUSE_MAX_MINUTES_CAP)) throw bad('Longest turn-off must be between 1 minute and 7 days')
  const next = { ...p, id: params.id, version: db.policies[i].version + 1 }
  db.policies[i] = next
  POLICY_UPDATED[next.id] = Date.now()
  for (const d of db.devices) if (d.policy_id === next.id) d.policy_name = next.name
  // Mirrors the agent applying the new policy to an active local pause.
  for (const d of db.devices) {
    const cur = d.health.pause
    if (d.policy_id !== next.id || !cur) continue
    const now = Date.now()
    const r = reconcilePause({ ...LOCAL_PAUSE_DEFAULTS, ...(next.local_pause ?? {}) }, cur, now)
    d.health.pause = r
    d.pause = r
    if (!r) db.log(null, 'device.protection_on', d.hostname, { hostname: d.hostname, mode: cur.mode, since_ms: cur.since_ms, until_ms: cur.until_ms, by_user: '', reason: 'policy' })
    else if (r.until_ms !== cur.until_ms) db.log(null, 'device.protection_off_clamped', d.hostname, { hostname: d.hostname, mode: r.mode, since_ms: r.since_ms, until_ms: r.until_ms, by_user: r.by_user })
  }
  db.log(u, 'policy.update', next.name, { version: next.version })
  return next
})
route('DELETE', '/policies/:id', ({ params }) => {
  const u = me()
  const p = db.policies.find((x) => x.id === params.id)
  if (!p) throw notFound('Policy')
  if (db.groups.some((g) => g.policy_id === p.id)) throw new HttpError(409, 'conflict', 'This policy is assigned to a group. Assign the group another policy first.')
  db.policies = db.policies.filter((x) => x.id !== p.id)
  db.log(u, 'policy.delete', p.name)
  return undefined
})
function ruleRows(): RuleRow[] {
  const hits = new Map<string, number>()
  for (const a of db.alerts) if (a.ts > Date.now() - 7 * DAY) hits.set(a.rule_id, (hits.get(a.rule_id) ?? 0) + 1)
  return [...db.rules.values()].map((r) => ({
    ...r,
    enabled_custom: r.kind === 'builtin' ? true : (db.customRules.get(r.id)?.enabled_custom ?? false),
    hits_7d: hits.get(r.id) ?? 0,
    source: db.customRules.get(r.id)?.source,
  }))
}
route('GET', '/rules', () => (me(), ruleRows()))
route('POST', '/rules', ({ body }) => {
  const u = me()
  const src = (body as { source: string }).source ?? ''
  const meta = validateSigma(src)
  const id = `SIG-${hexId(8)}`
  db.rules.set(id, { ...meta, id })
  db.customRules.set(id, { source: src, enabled_custom: true })
  db.log(u, 'rule.create', id, { title: meta.name })
  return ruleRows().find((r) => r.id === id)
})
route('PATCH', '/rules/:id', ({ params, body }) => {
  const u = me()
  const c = db.customRules.get(params.id)
  if (!c) throw new HttpError(400, 'bad_request', 'Built-in rules cannot be edited; change their mode in a policy')
  const b = body as { enabled_custom?: boolean; source?: string }
  if (b.source != null) {
    const meta = validateSigma(b.source)
    db.rules.set(params.id, { ...meta, id: params.id })
    c.source = b.source
  }
  if (b.enabled_custom != null) c.enabled_custom = b.enabled_custom
  db.log(u, 'rule.update', params.id, b as Record<string, unknown>)
  return ruleRows().find((r) => r.id === params.id)
})
route('DELETE', '/rules/:id', ({ params }) => {
  const u = me()
  if (!db.customRules.has(params.id)) throw bad('Built-in rules cannot be deleted')
  db.customRules.delete(params.id)
  db.rules.delete(params.id)
  db.log(u, 'rule.delete', params.id)
  return undefined
})

function validateSigma(src: string) {
  const line = (k: string) => new RegExp(`^${k}:\\s*(.+)$`, 'm').exec(src)?.[1]?.trim().replace(/^['"]|['"]$/g, '')
  const errors: string[] = []
  const title = line('title')
  if (!title) errors.push('line 1: missing required field "title"')
  if (!/^logsource:/m.test(src)) errors.push('missing required section "logsource"')
  if (!/^detection:/m.test(src)) errors.push('missing required section "detection"')
  else if (!/^\s+condition:/m.test(src)) errors.push('detection: missing "condition"')
  const lvl = line('level')
  if (lvl && !['informational', 'low', 'medium', 'high', 'critical'].includes(lvl)) errors.push(`level: "${lvl}" is not one of informational, low, medium, high, critical`)
  const cat = /^\s+category:\s*(\S+)/m.exec(src)?.[1]
  if (cat && !['process_creation', 'file_access', 'file_event', 'network_connection', 'dns_query', 'registry_set', 'image_load', 'process_access', 'create_remote_thread', 'ps_script'].includes(cat))
    errors.push(`logsource.category "${cat}" has no Kestrel field mapping`)
  if (errors.length) throw new HttpError(400, 'bad_request', errors.join('\n'))
  const tags = [...src.matchAll(/attack\.(t\d{4}(?:\.\d{3})?)/gi)].map((m) => m[1].toUpperCase())
  const sev: Severity = lvl === 'informational' ? 'info' : ((lvl ?? 'medium') as Severity)
  return {
    name: title!,
    description: line('description') ?? '',
    kind: 'sigma' as const,
    category: 'custom' as const,
    severity: sev,
    attack: tags,
    default_mode: 'audit' as const,
    protect_day_one: false,
    protect_action: 'Alert only (custom Sigma)',
    author: line('author') ?? db.session?.name ?? null,
    license: line('license') ?? null,
    references: [...src.matchAll(/^\s+-\s+(https?:\/\/\S+)/gm)].map((m) => m[1]),
    false_positives: [],
  }
}

route('GET', '/exclusions', () => (me(), db.exclusions))
route('POST', '/exclusions', ({ body }) => {
  const u = me()
  const b = body as { kind: string; value: string; rule_id?: string | null; expires_at?: number | null; reason?: string; policy_id: string | null }
  if (!b.value?.trim()) throw bad('Value is required')
  if (b.kind === 'sha256' && !/^[a-f0-9]{64}$/i.test(b.value)) throw bad('A SHA-256 is 64 hex characters')
  const e = { id: uuid(), kind: b.kind as 'path', value: b.value.trim(), rule_id: b.rule_id ?? null, expires_at: b.expires_at ?? null, reason: b.reason ?? '', policy_id: b.policy_id ?? null, created_by: u.email, created_at: Date.now() }
  db.exclusions.unshift(e)
  db.log(u, 'exclusion.create', e.value, { kind: e.kind, rule_id: e.rule_id, policy_id: e.policy_id })
  return e
})
route('DELETE', '/exclusions/:id', ({ params }) => {
  const u = me()
  const e = db.exclusions.find((x) => x.id === params.id)
  if (!e) throw notFound('Exclusion')
  db.exclusions = db.exclusions.filter((x) => x.id !== e.id)
  db.log(u, 'exclusion.delete', e.value)
  return undefined
})
route('GET', '/exclusions/preview', ({ query }) => {
  me()
  const kind = query.get('kind')
  const value = (query.get('value') ?? '').toLowerCase()
  const rule = query.get('rule_id')
  if (!value) return { matching_alerts_30d: 0, sample: [] }
  const globRe = new RegExp('^' + value.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$', 'i')
  const match = db.alerts.filter((a) => {
    if (a.ts < Date.now() - 30 * DAY) return false
    if (rule && a.rule_id !== rule) return false
    const p = a.process
    switch (kind) {
      case 'path':
        return globRe.test(p.image) || p.image.toLowerCase().startsWith(value)
      case 'sha256':
        return (p.sha256 ?? '').toLowerCase() === value
      case 'signer':
        return (p.signer ?? '').toLowerCase() === value
      case 'image':
        return p.image.toLowerCase().endsWith('\\' + value) || p.image.toLowerCase() === value
    }
    return false
  })
  return { matching_alerts_30d: match.length, sample: match.slice(0, 5).map(toAlertRow) }
})
route('GET', '/iocs', () => (me(), db.iocs))
route('POST', '/iocs', ({ body }) => {
  const u = me()
  const items = (body as { items: { kind: string; value: string; action: string; description?: string; policy_id?: string | null }[] }).items ?? []
  if (!items.length) throw bad('Add at least one indicator')
  const out = items.map((i) => ({ id: uuid(), kind: i.kind as 'ip', value: i.value.trim(), action: i.action as 'block', description: i.description ?? '', policy_id: i.policy_id ?? null, created_by: u.email, created_at: Date.now(), hits: 0 }))
  db.iocs.unshift(...out)
  db.log(u, 'ioc.create', `${out.length} indicators`, { kinds: [...new Set(out.map((o) => o.kind))] })
  return out
})
route('DELETE', '/iocs/:id', ({ params }) => {
  const u = me()
  const i = db.iocs.find((x) => x.id === params.id)
  if (!i) throw notFound('IOC')
  db.iocs = db.iocs.filter((x) => x.id !== i.id)
  db.log(u, 'ioc.delete', i.value)
  return undefined
})

// ------------------------------------------------------------------ quarantine & review

route('GET', '/quarantine', () => (me(), db.quarantine))
for (const op of ['restore', 'delete'] as const) {
  route('POST', `/quarantine/:id/${op}`, ({ params }) => {
    const u = me()
    const q = db.quarantine.find((x) => x.id === params.id)
    if (!q) throw notFound('Quarantine item')
    if (q.state !== 'held') throw new HttpError(409, 'conflict', `This file was already ${q.state}`)
    q.state = op === 'restore' ? 'restored' : 'deleted'
    const d = db.devices.find((x) => x.id === q.device_id)
    if (d) issueAction(d, op === 'restore' ? { type: 'restore_file', quarantine_id: q.id } : { type: 'delete_quarantined', quarantine_id: q.id }, u, '', null)
    db.log(u, `quarantine.${op}`, q.original_path)
    return q
  })
}
route('GET', '/review-requests', ({ query }) => {
  me()
  const st = query.get('state')
  return db.reviews
    .filter((r) => !st || r.state === st)
    .map((r) => ({ ...r, exclusion_scope: r.exclusion_scope === undefined ? reviewScope(r) : r.exclusion_scope }))
    .sort((a, b) => b.created_at - a.created_at)
})
function reviewScope(r: ReviewRequestRow): ExclusionScope | null {
  const d = db.devices.find((x) => x.id === r.device_id)
  const pol = db.policies.find((p) => p.id === d?.policy_id) ?? db.policies[0]
  r.exclusion_scope = { kind: 'sha256', value: hexId(64), rule_id: r.rule_name.match(/ST-\d+/)?.[0] ?? 'ST-12', policy_id: pol.id, policy_name: pol.name, expires_in_days: 90 }
  return r.exclusion_scope
}
route('POST', '/review-requests/:id/decision', ({ params, body }) => {
  const u = me()
  const r = db.reviews.find((x) => x.id === params.id)
  if (!r) throw notFound('Review request')
  const b = body as { approved: boolean; message: string; create_exclusion: boolean }
  r.state = b.approved ? 'approved' : 'denied'
  r.decided_by = u.email
  r.decided_at = Date.now()
  if (b.approved && b.create_exclusion) {
    const sc = r.exclusion_scope ?? reviewScope(r)
    if (!sc) throw bad('This file has no known hash or valid signature, so no safe exclusion can be created')
    db.exclusions.unshift({ id: uuid(), kind: sc.kind, value: sc.value, rule_id: sc.rule_id, expires_at: Date.now() + sc.expires_in_days * DAY, reason: `Review request from ${r.user}: ${b.message}`, policy_id: sc.policy_id, created_by: u.email, created_at: Date.now() })
  }
  db.log(u, 'review.decide', r.file, { approved: b.approved, create_exclusion: b.create_exclusion })
  return r
})

// ------------------------------------------------------------------ hunt

route('POST', '/hunt', ({ body }) => {
  me()
  const b = body as { query: string; from: number; to: number; limit: number }
  const t0 = performance.now()
  const parsed = parseHunt(b.query ?? '')
  if (!parsed.ok) throw bad(`${parsed.error.message} (at character ${parsed.error.pos + 1})`)
  const out: DeviceEvent[] = []
  for (const d of db.devices) {
    const t = db.telemetryFor(d)
    for (const e of t.events) {
      if (e.ts < b.from || e.ts > b.to) continue
      const p = t.procs.get(e.guid)
      const rec = toHuntRecord(e, { image: p?.image, user: p?.user, signer: p?.signer, sha256: p?.sha256, hostname: d.hostname })
      if (evaluate(parsed.ast, rec)) out.push({ ...e, hostname: d.hostname, ...(e.type !== 'process_start' && p ? { process_image: p.image } : {}) } as DeviceEvent)
    }
  }
  out.sort((a, c) => c.ts - a.ts)
  return { items: out.slice(0, b.limit || 500), elapsed_ms: Math.round(performance.now() - t0 + int(18, 60)) }
})

// ------------------------------------------------------------------ users, tokens, settings, audit

route('GET', '/users', () => (me(), db.users))
route('POST', '/users', ({ body }) => {
  const u = me()
  const b = body as { email: string; name: string; role: string }
  if (!/^\S+@\S+\.\S+$/.test(b.email ?? '')) throw bad('Enter a valid email address')
  if (db.users.some((x) => x.email.toLowerCase() === b.email.toLowerCase())) throw new HttpError(409, 'conflict', 'A user with this email already exists')
  const n: User = { id: uuid(), email: b.email, name: b.name, role: b.role, last_login: null, created_at: Date.now(), disabled: false, mfa_enabled: false }
  db.users.push(n)
  db.log(u, 'user.create', n.email, { role: n.role })
  return n
})
route('PATCH', '/users/:id', ({ params, body }) => {
  const u = me()
  const t = db.users.find((x) => x.id === params.id)
  if (!t) throw notFound('User')
  const b = body as Partial<User> & { oidc_subject?: string | null }
  if (t.id === u.id && (b.disabled || (b.role && b.role !== 'admin'))) throw new HttpError(409, 'conflict', 'You cannot disable or demote your own account')
  if ('oidc_subject' in b) {
    t.sso_linked = !!b.oidc_subject
    delete b.oidc_subject
  }
  Object.assign(t, b)
  db.log(u, 'user.update', t.email, b as Record<string, unknown>)
  return t
})
route('DELETE', '/users/:id', ({ params }) => {
  const u = me()
  if (params.id === u.id) throw new HttpError(409, 'conflict', 'You cannot delete your own account')
  const t = db.users.find((x) => x.id === params.id)
  db.users = db.users.filter((x) => x.id !== params.id)
  db.log(u, 'user.delete', t?.email ?? params.id)
  return undefined
})
route('GET', '/api-tokens', () => (me(), db.apiTokens))
route('POST', '/api-tokens', ({ body }) => {
  const u = me()
  const b = body as { name: string; privileges: string[] }
  if (!b.name?.trim()) throw bad('Name is required')
  const token = `kst_${hexId(40)}`
  const t = { id: uuid(), name: b.name, prefix: token.slice(0, 8), created_at: Date.now(), last_used: null, privileges: b.privileges?.length ? b.privileges : ['read'] }
  db.apiTokens.unshift(t)
  db.log(u, 'api_token.create', t.name, { privileges: t.privileges })
  return { ...t, token }
})
route('DELETE', '/api-tokens/:id', ({ params }) => {
  const u = me()
  const t = db.apiTokens.find((x) => x.id === params.id)
  db.apiTokens = db.apiTokens.filter((x) => x.id !== params.id)
  db.log(u, 'api_token.revoke', t?.name ?? params.id)
  return undefined
})
route('GET', '/settings', () => (me(), db.settings))
route('PUT', '/settings', ({ body }) => {
  const u = me()
  const s = structuredClone(body as Settings)
  if (s.oidc.enabled && !s.oidc.allowed_domains.filter((d) => d.trim()).length)
    throw bad('oidc.allowed_domains must list at least one email domain; single sign-on denies everyone when it is empty')
  if (s.oidc.default_role === 'admin') throw bad('oidc.default_role cannot be an administrator role; promote SSO users explicitly')
  if (s.notifications.email.password) s.notifications.email.password_set = true
  delete s.notifications.email.password
  if (s.notifications.webhook.secret) s.notifications.webhook.secret_set = true
  delete s.notifications.webhook.secret
  if (s.oidc.client_secret) s.oidc.client_secret_set = true
  delete s.oidc.client_secret
  db.settings = s
  db.log(u, 'settings.update', 'settings', {})
  return s
})
route('GET', '/audit-log', ({ query }) => {
  me()
  const items = [...db.audit]
    .reverse()
    .filter((e) => textMatch(query.get('actor'), e.actor?.email) && textMatch(query.get('action'), e.action))
  return page(items, query)
})
route('GET', '/audit-log/verify', () => (me(), db.verifyAudit()))

// ------------------------------------------------------------------ agent updates

function requireUpdatesWrite(u: User) {
  const privs = ROLE_PRIVILEGES[u.role] ?? ['read']
  if (!privs.includes('*') && !privs.includes('updates.write')) throw new HttpError(403, 'forbidden', 'You need the updates.write privilege')
}
function wrapUpdate<T>(f: () => T): T {
  try {
    return f()
  } catch (e) {
    if (e instanceof UpdateError) throw new HttpError(e.status, e.status === 409 ? 'conflict' : e.status === 404 ? 'not_found' : 'bad_request', e.message)
    throw e
  }
}
route('GET', '/updates/status', () => (me(), db.refreshDevices(), updates.status()))
route('GET', '/updates/releases', () => (me(), db.refreshDevices(), updates.list()))
route('POST', '/updates/releases', ({ body }) => {
  const u = me()
  requireUpdatesWrite(u)
  const b = (body ?? {}) as { manifest?: unknown; notes?: string }
  const parsed = parseManifest(JSON.stringify(b.manifest ?? null))
  if (!parsed.ok) throw bad(`invalid manifest: ${parsed.error}`)
  const r = wrapUpdate(() => updates.register(parsed.manifest, (b.notes ?? '').slice(0, 4000), u))
  db.log(u, 'update.register', r.manifest.version, { sha256: r.manifest.sha256, url: r.manifest.url })
  emit({ kind: 'update_release', id: r.id, type: 'registered' })
  return updates.view(r)
})
route('POST', '/updates/releases/:id/promote', ({ params, body }) => {
  const u = me()
  requireUpdatesWrite(u)
  const ring = (body as { ring?: UpdateRing } | undefined)?.ring as UpdateRing
  const out = wrapUpdate(() => updates.promote(params.id, ring, u))
  db.log(u, 'update.promote', out.release.manifest.version, { ring, delivered_now: out.delivered_now })
  emit({ kind: 'update_release', id: params.id, type: 'promoted' })
  if (out.delivered_ids.length) {
    // Connected agents download, verify and install; a later Hello reports the new version.
    setTimeout(() => {
      updates.settle(params.id, out.delivered_ids)
      emit({ kind: 'update_release', id: params.id, type: 'delivery' })
      for (const id of out.delivered_ids) emit({ kind: 'device', id, type: 'updated' })
    }, 6000)
  }
  return { ...updates.view(out.release), delivered_now: out.delivered_now }
})
route('POST', '/updates/releases/:id/halt', ({ params, body }) => {
  const u = me()
  requireUpdatesWrite(u)
  const reason = String((body as { reason?: string } | undefined)?.reason ?? '').slice(0, 2000)
  const r = wrapUpdate(() => updates.halt(params.id, reason, u))
  db.log(u, 'update.halt', r.manifest.version, { reason })
  emit({ kind: 'update_release', id: r.id, type: 'halted' })
  return updates.view(r)
})


// ------------------------------------------------------------------ remote access (admin only)

function canDo(u: User, priv: string) {
  const p = ROLE_PRIVILEGES[u.role] ?? []
  return p.includes('*') || p.includes(priv)
}
const REMOTE_STATUS: Record<RemoteErrorCode, [number, string]> = {
  not_found: [404, 'not_found'],
  protected_path: [403, 'forbidden'],
  blocked_path: [403, 'forbidden'],
  access_denied: [403, 'forbidden'],
  disabled_by_policy: [403, 'forbidden'],
  not_permitted: [403, 'forbidden'],
  consent_denied: [403, 'forbidden'],
  outside_allowed_hours: [403, 'forbidden'],
  reason_required: [400, 'bad_request'],
  consent_timeout: [408, 'consent_timeout'],
  already_exists: [409, 'conflict'],
  busy: [409, 'conflict'],
  integrity_error: [409, 'conflict'],
  invalid_operation: [400, 'bad_request'],
  invalid_path: [400, 'bad_request'],
  too_large: [413, 'payload_too_large'],
  timeout: [504, 'gateway_timeout'],
  unavailable: [503, 'unavailable'],
  io: [500, 'internal'],
  other: [500, 'internal'],
}
function remoteHttpError(code: RemoteErrorCode, message: string): HttpError {
  const [status, c] = REMOTE_STATUS[code]
  return new HttpError(status, c, message, code, ['not_permitted', 'disabled_by_policy', 'reason_required'].includes(code) ? { reason: code } : undefined)
}
/** Device local time (the mock uses the browser's clock): weekday 0 = Monday. */
function localNow() {
  const n = new Date()
  return { weekday: (n.getDay() + 6) % 7, minute: n.getHours() * 60 + n.getMinutes() }
}

/**
 * RBAC → device → effective profile allows the feature / operation (ceiling
 * vs policy) → reason → MFA re-auth → online → capability, as in the contract;
 * then the agent-side checks (allowed hours).
 */
export function remoteGuard(id: string, feature: 'desktop' | 'files', need: FileOpClass, reason: string) {
  const u = me()
  if (!canDo(u, `remote.${feature}`)) throw new HttpError(403, 'forbidden', `Remote ${feature === 'desktop' ? 'desktop' : 'file access'} needs the remote.${feature} privilege (admins only)`)
  db.refreshDevices()
  const d = findDevice(id)
  const pol = db.policies.find((p) => p.id === d.policy_id) ?? db.policies[0]
  const info = remoteAccessFor(d, pol)
  const eff = info.effective!
  const denied = (r: 'not_permitted' | 'disabled_by_policy', m: string) => remoteHttpError(r, m)
  if (feature === 'files') {
    const ceil = fileOpDenied(info.ceiling!, need)
    if (ceil) throw denied('not_permitted', `Not permitted by the install profile: ${ceil}`)
    const pol2 = fileOpDenied(info.policy!, need)
    if (pol2) throw denied('disabled_by_policy', `Not allowed by the policy: ${pol2}`)
  } else {
    if (info.ceiling!.desktop === 'off') throw denied('not_permitted', 'Remote desktop is not permitted by the install profile')
    if (info.policy!.desktop === 'off') throw denied('disabled_by_policy', 'Remote desktop is off in the policy')
  }
  if (eff.guardrails.require_reason && !reason.trim()) throw remoteHttpError('reason_required', 'A reason is required')
  if (eff.guardrails.require_mfa_reauth) {
    if (!u.mfa_enabled) throw new HttpError(403, 'forbidden', 'MFA is not enabled for your account', undefined, { reason: 'mfa_not_enabled' })
    if (reauth.until < Date.now()) throw new HttpError(403, 'forbidden', 'Re-authentication required', undefined, { reason: 'reauth_required' })
  }
  const a = info[feature]
  if (!a.available) {
    if (a.reason === 'offline') throw new HttpError(409, 'conflict', 'device is offline')
    if (a.reason === 'agent_too_old') throw new HttpError(409, 'conflict', 'the agent on this device is too old for remote access; update it')
    throw new HttpError(409, 'conflict', 'device is decommissioned')
  }
  const h = eff.guardrails.allowed_hours
  if (h) {
    const n = localNow()
    if (!hoursContain(h, n.weekday, n.minute)) throw remoteHttpError('outside_allowed_hours', 'Outside the allowed hours (device local time)')
  }
  return { u, d, eff, fs: fsFor(d.id, d.logged_on_user) }
}

function fmCtx(query: URLSearchParams) {
  return { fmSession: query.get('fm_session') ?? '', reason: query.get('reason') ?? '' }
}
/** Agent-side consent for the first non-read op of an fm_session: the mock employee clicks Allow after ~2 s. */
async function consentFor(eff: RemoteAccessProfile, fmSession: string, u: User, deviceId: string) {
  if (!eff.guardrails.require_consent || (fmSession && consentedFmSessions.has(fmSession))) return
  await new Promise((r) => setTimeout(r, CONSENT_DELAY_MS))
  if (fmSession) consentedFmSessions.add(fmSession)
  db.log(u, 'remote.consent', deviceId, { kind: 'files', fm_session: fmSession, result: 'allowed', ok: true })
}
export const CONSENT_DELAY_MS = typeof window === 'undefined' ? 10 : 2000

/** Agent-side path checks: blocked paths of the effective profile (and, for rename / delete, folders that contain one). */
function checkBlocked(eff: RemoteAccessProfile, ...paths: string[]) {
  for (const p of paths) {
    const v = validateRemotePath(p)
    if (v.ok && blockedPrefix(eff.guardrails, v.path)) throw remoteHttpError('blocked_path', `${v.path} is blocked by the remote-access profile`)
  }
}
function checkBlockedAncestor(eff: RemoteAccessProfile, ...paths: string[]) {
  checkBlocked(eff, ...paths)
  for (const p of paths) {
    const v = validateRemotePath(p)
    const b = v.ok ? eff.guardrails.blocked_paths.find((x) => x.trim() && pathIsWithin(x, v.path)) : undefined
    if (b) throw remoteHttpError('blocked_path', `${v.ok ? v.path : p} contains ${b}, which is blocked by the remote-access profile`)
  }
}
/** Run a file op, audit it like the server does, and map agent errors to HTTP. */
function fileOp<T>(u: User, hostname: string, deviceId: string, action: string | null, details: Record<string, unknown>, f: () => T): T {
  try {
    const out = f()
    if (action) db.log(u, action, deviceId, { hostname, ...details, ok: true })
    return out
  } catch (e) {
    if (e instanceof RemoteFsError) {
      if (action) db.log(u, action, deviceId, { hostname, ...details, ok: false, error: e.message })
      throw remoteHttpError(e.code, e.message)
    }
    throw e
  }
}
/** Blob bytes (jsdom's Blob in tests has no arrayBuffer()). */
export async function blobBytes(b: Blob): Promise<ArrayBuffer> {
  if (typeof b.arrayBuffer === 'function') return b.arrayBuffer()
  return new Promise((resolve, reject) => {
    const r = new FileReader()
    r.onload = () => resolve(r.result as ArrayBuffer)
    r.onerror = () => reject(r.error)
    r.readAsArrayBuffer(b)
  })
}
async function sha256Hex(b: Blob): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', await blobBytes(b))
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, '0')).join('')
}

route('POST', '/me/reauth', ({ body }) => {
  const u = me()
  const totp = String((body as { totp?: unknown })?.totp ?? '')
  if (!u.mfa_enabled) throw new HttpError(403, 'forbidden', 'MFA is not enabled for your account', undefined, { reason: 'mfa_not_enabled' })
  // Mock: any 6 digits except 000000 (to show the wrong-code path).
  if (!/^\d{6}$/.test(totp) || totp === '000000') {
    db.log(u, 'auth.reauth', u.email, { ok: false })
    throw new HttpError(400, 'bad_request', 'invalid code', undefined, { reason: 'invalid_totp' })
  }
  reauth.until = Date.now() + 10 * MIN
  db.log(u, 'auth.reauth', u.email, { ok: true })
  return { reauth_until: reauth.until }
})
route('GET', '/devices/:id/files', ({ params, query }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'read', c.reason)
  const path = query.get('path') ?? ''
  if (path) checkBlocked(eff, path)
  return fileOp(u, d.hostname, d.id, 'remote.files.list', { path, reason: c.reason }, () => fs.list(path))
})
route('GET', '/devices/:id/files/stat', ({ params, query }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'read', c.reason)
  const path = query.get('path') ?? ''
  checkBlocked(eff, path)
  return fileOp(u, d.hostname, d.id, null, { path }, () => fs.stat(path))
})
route('GET', '/devices/:id/files/download', async ({ params, query }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'read', c.reason)
  const path = query.get('path') ?? ''
  checkBlocked(eff, path)
  const { entry, blob } = fileOp(u, d.hostname, d.id, null, { path }, () => fs.read(path))
  db.log(u, 'remote.files.download', d.id, { hostname: d.hostname, path, bytes: blob.size, sha256: await sha256Hex(blob), ok: true })
  const ascii = entry.name.replace(/[^\x20-\x7e]|["\\]/g, '_')
  return new RawBody(blob, {
    'Content-Type': 'application/octet-stream',
    'Content-Length': String(blob.size),
    'Content-Disposition': `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(entry.name)}`,
    'X-Content-Type-Options': 'nosniff',
  })
})
route('POST', '/devices/:id/files/upload', async ({ params, query, body }): Promise<FileUploadResult> => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'write', c.reason)
  const path = query.get('path') ?? ''
  if (!(body instanceof Blob)) throw new HttpError(411, 'length_required', 'Content-Length is required')
  checkBlocked(eff, path)
  // Overwriting an existing file is a delete too: it needs allow_delete as well as upload.
  const exists = (() => {
    try {
      return fs.stat(path).kind === 'file'
    } catch {
      return false
    }
  })()
  if (exists && fileOpDenied(eff, 'delete')) {
    const r = remoteAccessFor(d, db.policies.find((p) => p.id === d.policy_id) ?? db.policies[0])
    const code = fileOpDenied(r.ceiling!, 'delete') ? 'not_permitted' : 'disabled_by_policy'
    throw remoteHttpError(code, 'overwriting an existing file needs delete permission')
  }
  await consentFor(eff, c.fmSession, u, d.id)
  const sha256 = await sha256Hex(body)
  const r = fileOp(u, d.hostname, d.id, 'remote.files.upload', { path, bytes: body.size, sha256 }, () => fs.write(path, body))
  return { path: r.path, size: r.size, sha256 }
})
route('POST', '/devices/:id/files/rename', async ({ params, query, body }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'delete', c.reason)
  const b = body as { from: string; to: string; overwrite?: boolean }
  checkBlockedAncestor(eff, b.from, b.to)
  await consentFor(eff, c.fmSession, u, d.id)
  return fileOp(u, d.hostname, d.id, 'remote.files.rename', { from: b.from, to: b.to, overwrite: !!b.overwrite }, () => fs.rename(b.from, b.to, !!b.overwrite))
})
route('POST', '/devices/:id/files/delete', async ({ params, query, body }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'delete', c.reason)
  const b = body as { path: string; recursive?: boolean }
  checkBlockedAncestor(eff, b.path)
  await consentFor(eff, c.fmSession, u, d.id)
  return fileOp(u, d.hostname, d.id, 'remote.files.delete', { path: b.path, recursive: !!b.recursive }, () => fs.remove(b.path, !!b.recursive))
})
route('POST', '/devices/:id/files/mkdir', async ({ params, query, body }) => {
  const c = fmCtx(query)
  const { u, d, fs, eff } = remoteGuard(params.id, 'files', 'write', c.reason)
  const b = body as { path: string }
  checkBlocked(eff, b.path)
  await consentFor(eff, c.fmSession, u, d.id)
  return fileOp(u, d.hostname, d.id, 'remote.files.mkdir', { path: b.path }, () => fs.mkdir(b.path))
})
route('GET', '/devices/:id/remote-desktop/status', ({ params }) => {
  const u = me()
  if (!canDo(u, 'remote.desktop')) throw new HttpError(403, 'forbidden', 'Remote desktop needs the remote.desktop privilege (admins only)')
  findDevice(params.id)
  const s = desktopSessions.get(params.id) ?? null
  return { active: !!s, session: s }
})

/** Mock upload with simulated progress (the patched fetch has no upload progress). */
export async function mockUpload(deviceId: string, target: string, file: Blob, c: { fmSession: string; reason: string }, onProgress: (loaded: number, total: number) => void, signal?: AbortSignal): Promise<FileUploadResult> {
  const steps = 8
  const total = file.size
  const per = Math.min(300, Math.max(60, total / 2_000_000))
  for (let i = 1; i <= steps; i++) {
    if (signal?.aborted) throw new ApiError(0, 'aborted', 'Upload cancelled.')
    await new Promise((r) => setTimeout(r, per))
    onProgress(Math.round((total * i) / steps), total)
  }
  const q = new URLSearchParams({ path: target, fm_session: c.fmSession })
  if (c.reason.trim()) q.set('reason', c.reason.trim())
  const res = await handleMock('POST', `/devices/${deviceId}/files/upload`, q, file)
  if (res.status >= 300) throw apiErrorFrom(res.status, JSON.stringify(res.body))
  return res.body as FileUploadResult
}


// ------------------------------------------------------------------ dispatcher

/** Tests switch the simulated network latency off. */
export const mockOptions = { latency: true }

export async function handleMock(method: string, path: string, query: URLSearchParams, body: unknown): Promise<{ status: number; body: unknown; headers?: Record<string, string> }> {
  if (mockOptions.latency) await new Promise((r) => setTimeout(r, 90 + Math.random() * 160))
  // A setup-only session (require_mfa, no authenticator yet) can only reach /me and /me/mfa/*.
  if (mfa.setupOnly && db.session && !(path.startsWith('/auth/') || path === '/me' || path.startsWith('/me/mfa/')))
    return { status: 403, body: { error: { code: 'forbidden', message: 'set up multi-factor authentication first', mfa_setup_required: true } } }
  for (const r of routes) {
    if (r.method !== method) continue
    const m = r.re.exec(path)
    if (!m) continue
    const params: Record<string, string> = {}
    r.keys.forEach((k, i) => (params[k] = decodeURIComponent(m[i + 1])))
    try {
      const out = await r.h({ params, query, body, method })
      if (out instanceof RawBody) return { status: 200, body: out.blob, headers: out.headers }
      return { status: out === undefined ? 204 : 200, body: out }
    } catch (e) {
      if (e instanceof HttpError)
        return {
          status: e.status,
          body: { error: { code: e.code, message: e.message, ...(e.remoteCode ? { remote_code: e.remoteCode } : {}), ...(e.extra ?? {}) } },
        }
      console.error(e)
      return { status: 500, body: { error: { code: 'internal', message: String(e) } } }
    }
  }
  return { status: 404, body: { error: { code: 'not_found', message: `No route for ${method} ${path}` } } }
}

/** `fetch` replacement serving `/api/*` from memory (used by installMock and component tests). */
export async function mockFetch(input: RequestInfo | URL, init?: RequestInit, orig?: typeof fetch): Promise<Response> {
  const base = typeof location !== 'undefined' ? location.href : 'http://localhost/'
  const url = new URL(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url, base)
  const i = url.pathname.indexOf('/api/')
  if (i < 0) {
    if (orig) return orig(input, init)
    return new Response(null, { status: 404 })
  }
  const path = url.pathname.slice(i + 4)
  const method = (init?.method ?? 'GET').toUpperCase()
  const body = init?.body instanceof Blob ? init.body : init?.body ? JSON.parse(String(init.body)) : undefined
  const res = await handleMock(method, path, url.searchParams, body)
  if (res.body instanceof Blob) return new Response(res.body, { status: res.status, headers: res.headers })
  return new Response(res.status === 204 ? null : JSON.stringify(res.body), { status: res.status, headers: { 'Content-Type': 'application/json' } })
}

/** Patch window.fetch so `/api/*` is served from memory. */
export function installMock(opts: { autoLogin: boolean }) {
  if (opts.autoLogin) db.session = db.users[0]
  const orig = window.fetch.bind(window)
  window.fetch = (input: RequestInfo | URL, init?: RequestInit) => mockFetch(input, init, orig)
  // Simulate a live detection a little after load so the queue's live update is visible.
  setTimeout(() => {
    const inc = liveIncident(db.ctx(), db.devices)
    db.incidents.unshift(inc)
    db.indexIncident(inc)
    db.refreshDevices()
    emit({ kind: 'incident', id: inc.id, type: 'created' })
    emit({ kind: 'alert', id: fullAlerts.get(inc)?.[0]?.id ?? inc.id, type: 'created' })
  }, 45_000)
  // Keep device "last seen" fresh for online devices.
  setInterval(() => {
    for (const d of db.devices) if (d.last_seen > Date.now() - 3 * MIN) d.last_seen = Date.now() - int(2, 50) * 1000
  }, 20_000)
  void NOW
  void SEVERITY_RANK
}
