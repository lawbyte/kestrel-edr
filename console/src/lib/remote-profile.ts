/**
 * TS mirror of the remote-access profile logic in `kestrel_common::remote`
 * ("profiles & ceiling"): presets, stricter-wins intersection, preset
 * detection, summary text, validation and file-op permissions. The server
 * and agent are the authority; the console uses this for previews (policy
 * editor, installer wizard) and to hide buttons the effective profile forbids.
 */
import type { AllowedHours, DesktopMode, FileMode, RemoteAccessProfile, RemoteGuardrails, RemoteProfilePreset } from '@/api/types'
import { pathIsWithin, validateRemotePath } from './remote-path'

export const DEFAULT_CONSENT_TIMEOUT_SECS = 60
export const DEFAULT_BLOCKED_PATHS = ['C:\\Windows\\System32\\config']

const DESKTOP_RANK: Record<DesktopMode, number> = { off: 0, view_only: 1, control: 2 }
const FILE_RANK: Record<FileMode, number> = { off: 0, read_only: 1, full: 2 }

/** `RemoteGuardrails::default()` — the guarded defaults. */
export function guardedGuardrails(): RemoteGuardrails {
  return {
    require_consent: true,
    consent_timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
    require_reason: true,
    require_mfa_reauth: true,
    allow_upload: true,
    allow_delete: false,
    max_session_minutes: 60,
    idle_timeout_minutes: 15,
    allowed_hours: null,
    blocked_paths: [...DEFAULT_BLOCKED_PATHS],
  }
}

/** `RemoteGuardrails::none()` — every guardrail off, no limits. */
export function noGuardrails(): RemoteGuardrails {
  return {
    require_consent: false,
    consent_timeout_secs: DEFAULT_CONSENT_TIMEOUT_SECS,
    require_reason: false,
    require_mfa_reauth: false,
    allow_upload: true,
    allow_delete: true,
    max_session_minutes: 0,
    idle_timeout_minutes: 0,
    allowed_hours: null,
    blocked_paths: [],
  }
}

export const profileNone = (): RemoteAccessProfile => ({ desktop: 'off', files: 'off', guardrails: guardedGuardrails() })
export const profileUnrestricted = (): RemoteAccessProfile => ({ desktop: 'control', files: 'full', guardrails: noGuardrails() })
export const profileGuarded = (): RemoteAccessProfile => ({ desktop: 'control', files: 'full', guardrails: guardedGuardrails() })

export function presetProfile(p: Exclude<RemoteProfilePreset, 'custom'>): RemoteAccessProfile {
  return p === 'none' ? profileNone() : p === 'unrestricted' ? profileUnrestricted() : profileGuarded()
}

/**
 * Fill missing fields like serde does: absent modes = off, absent guardrail
 * fields = the guarded defaults (the strict side), absent profile = none.
 */
export function normaliseProfile(p: Partial<RemoteAccessProfile> | null | undefined): RemoteAccessProfile {
  if (!p) return profileNone()
  const g: Partial<RemoteGuardrails> = p.guardrails ?? {}
  const d = guardedGuardrails()
  return {
    desktop: p.desktop && p.desktop in DESKTOP_RANK ? p.desktop : 'off',
    files: p.files && p.files in FILE_RANK ? p.files : 'off',
    guardrails: {
      require_consent: g.require_consent ?? d.require_consent,
      consent_timeout_secs: g.consent_timeout_secs ?? d.consent_timeout_secs,
      require_reason: g.require_reason ?? d.require_reason,
      require_mfa_reauth: g.require_mfa_reauth ?? d.require_mfa_reauth,
      allow_upload: g.allow_upload ?? d.allow_upload,
      allow_delete: g.allow_delete ?? d.allow_delete,
      max_session_minutes: g.max_session_minutes ?? d.max_session_minutes,
      idle_timeout_minutes: g.idle_timeout_minutes ?? d.idle_timeout_minutes,
      allowed_hours: g.allowed_hours ? { days: g.allowed_hours.days ?? [], start_minute: g.allowed_hours.start_minute ?? 0, end_minute: g.allowed_hours.end_minute ?? 1440 } : null,
      blocked_paths: g.blocked_paths ?? d.blocked_paths,
    },
  }
}

export const isNoneProfile = (p: RemoteAccessProfile) => p.desktop === 'off' && p.files === 'off'

function hoursEq(a: AllowedHours | null, b: AllowedHours | null) {
  if (!a || !b) return a === b
  return a.start_minute === b.start_minute && a.end_minute === b.end_minute && a.days.length === b.days.length && a.days.every((d, i) => d === b.days[i])
}
export function profileEquals(a: RemoteAccessProfile, b: RemoteAccessProfile): boolean {
  const x = a.guardrails
  const y = b.guardrails
  return (
    a.desktop === b.desktop &&
    a.files === b.files &&
    x.require_consent === y.require_consent &&
    x.consent_timeout_secs === y.consent_timeout_secs &&
    x.require_reason === y.require_reason &&
    x.require_mfa_reauth === y.require_mfa_reauth &&
    x.allow_upload === y.allow_upload &&
    x.allow_delete === y.allow_delete &&
    x.max_session_minutes === y.max_session_minutes &&
    x.idle_timeout_minutes === y.idle_timeout_minutes &&
    hoursEq(x.allowed_hours, y.allowed_hours) &&
    x.blocked_paths.length === y.blocked_paths.length &&
    x.blocked_paths.every((p, i) => p === y.blocked_paths[i])
  )
}

/** `RemoteAccessProfile::preset`. */
export function presetOf(p: RemoteAccessProfile): RemoteProfilePreset {
  if (isNoneProfile(p)) return 'none'
  if (profileEquals(p, profileUnrestricted())) return 'unrestricted'
  if (profileEquals(p, profileGuarded())) return 'guarded'
  return 'custom'
}

export const consentTimeout = (g: RemoteGuardrails) => (g.consent_timeout_secs === 0 ? DEFAULT_CONSENT_TIMEOUT_SECS : g.consent_timeout_secs)

const minNz = (a: number, b: number) => (a === 0 ? b : b === 0 ? a : Math.min(a, b))

function intersectHours(a: AllowedHours, b: AllowedHours): AllowedHours {
  const days = [...new Set(a.days.filter((d) => b.days.includes(d)))].sort((x, y) => x - y)
  return { days, start_minute: Math.max(a.start_minute, b.start_minute), end_minute: Math.min(a.end_minute, b.end_minute) }
}

/** Rust `str::cmp` on lower-cased strings ≈ code-unit order (ASCII paths). */
const cmpStr = (x: string, y: string) => (x < y ? -1 : x > y ? 1 : 0)

/** `RemoteAccessProfile::intersect` — stricter wins, commutative. */
export function intersectProfiles(a: RemoteAccessProfile, b: RemoteAccessProfile): RemoteAccessProfile {
  const x = a.guardrails
  const y = b.guardrails
  const allowed_hours = !x.allowed_hours && !y.allowed_hours ? null : !x.allowed_hours ? { ...y.allowed_hours! } : !y.allowed_hours ? { ...x.allowed_hours } : intersectHours(x.allowed_hours, y.allowed_hours)
  const blocked = [...x.blocked_paths, ...y.blocked_paths].map((p) => {
    const v = validateRemotePath(p)
    return v.ok ? v.path : p
  })
  blocked.sort((p, q) => cmpStr(p.toLowerCase(), q.toLowerCase()) || cmpStr(p, q))
  const dedup = blocked.filter((p, i) => i === 0 || p.toLowerCase() !== blocked[i - 1].toLowerCase())
  return {
    desktop: DESKTOP_RANK[a.desktop] <= DESKTOP_RANK[b.desktop] ? a.desktop : b.desktop,
    files: FILE_RANK[a.files] <= FILE_RANK[b.files] ? a.files : b.files,
    guardrails: {
      require_consent: x.require_consent || y.require_consent,
      consent_timeout_secs: minNz(consentTimeout(x), consentTimeout(y)),
      require_reason: x.require_reason || y.require_reason,
      require_mfa_reauth: x.require_mfa_reauth || y.require_mfa_reauth,
      allow_upload: x.allow_upload && y.allow_upload,
      allow_delete: x.allow_delete && y.allow_delete,
      max_session_minutes: minNz(x.max_session_minutes, y.max_session_minutes),
      idle_timeout_minutes: minNz(x.idle_timeout_minutes, y.idle_timeout_minutes),
      allowed_hours,
      blocked_paths: dedup,
    },
  }
}

export function hoursContain(h: AllowedHours, weekday: number, minute: number): boolean {
  return h.days.includes(weekday) && minute >= h.start_minute && minute < Math.min(h.end_minute, 1440)
}
export function hoursEmpty(h: AllowedHours): boolean {
  return h.days.length === 0 || h.start_minute >= Math.min(h.end_minute, 1440)
}

/** `RemoteGuardrails::blocked_prefix`. */
export function blockedPrefix(g: RemoteGuardrails, path: string): string | null {
  return g.blocked_paths.find((b) => b.trim() !== '' && pathIsWithin(path, b)) ?? null
}

export type FileOpClass = 'read' | 'write' | 'delete'
/** `RemoteAccessProfile::file_op_permitted`: `null` = allowed, else the reason. */
export function fileOpDenied(p: RemoteAccessProfile, need: FileOpClass): string | null {
  if (p.files === 'off') return 'the file manager is off'
  if (need === 'read') return null
  if (p.files === 'read_only') return 'the file manager is read-only'
  if (need === 'write' && !p.guardrails.allow_upload) return 'uploads and new folders are not allowed'
  if (need === 'delete' && !p.guardrails.allow_delete) return 'delete, rename and move are not allowed'
  return null
}

/** `RemoteAccessProfile::validate`: `null` when valid. */
export function validateProfile(p: RemoteAccessProfile): string | null {
  const g = p.guardrails
  if (g.allowed_hours) {
    const h = g.allowed_hours
    if (h.days.some((d) => d < 0 || d > 6 || !Number.isInteger(d))) return 'allowed_hours.days must be 0 (Monday) … 6 (Sunday)'
    if (h.end_minute > 1440 || h.start_minute >= h.end_minute) return 'allowed_hours needs start_minute < end_minute ≤ 1440'
  }
  if (g.blocked_paths.length > 256) return 'at most 256 blocked paths'
  for (const bp of g.blocked_paths) {
    const v = validateRemotePath(bp)
    if (!v.ok) return `blocked path "${bp}": ${v.error}`
  }
  if (g.consent_timeout_secs > 600) return 'consent_timeout_secs must be ≤ 600'
  if (g.max_session_minutes > 1440 || g.idle_timeout_minutes > 1440) return 'session limits must be ≤ 1440 minutes'
  return null
}

/** `RemoteAccessProfile::summary` (same wording as the server). */
export function profileSummary(p: RemoteAccessProfile): string {
  if (isNoneProfile(p)) return 'No remote access'
  const d = p.desktop === 'view_only' ? 'view-only remote desktop' : p.desktop === 'control' ? 'remote control' : null
  const f = p.files === 'read_only' ? 'read-only file manager' : p.files === 'full' ? 'full file manager' : null
  let s = [d, f].filter(Boolean).join(' + ')
  const g = p.guardrails
  const parts: string[] = []
  if (g.require_consent) parts.push('employee consent')
  if (g.require_reason) parts.push('reason')
  if (g.require_mfa_reauth) parts.push('MFA re-auth')
  if (p.files === 'full') {
    if (!g.allow_upload) parts.push('no upload')
    if (!g.allow_delete) parts.push('no delete')
  }
  if (g.max_session_minutes > 0) parts.push(`${g.max_session_minutes} min max`)
  if (g.idle_timeout_minutes > 0) parts.push(`${g.idle_timeout_minutes} min idle`)
  if (g.allowed_hours) parts.push('allowed hours')
  if (g.blocked_paths.length) parts.push(`${g.blocked_paths.length} blocked path(s)`)
  s += parts.length ? ` (${parts.join(', ')})` : ' (no guardrails)'
  return s.charAt(0).toUpperCase() + s.slice(1)
}

export const PRESET_LABEL: Record<RemoteProfilePreset, string> = {
  none: 'No remote access',
  unrestricted: 'Remote control + file manager (no guardrails)',
  guarded: 'Remote control + file manager with guardrails',
  custom: 'Custom remote access',
}
export const DESKTOP_MODE_LABEL: Record<DesktopMode, string> = { off: 'Off', view_only: 'View only', control: 'Control' }
export const FILE_MODE_LABEL: Record<FileMode, string> = { off: 'Off', read_only: 'Read only', full: 'Full' }
export const DAY_LABEL = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

/** 540 → "09:00", 1440 → "24:00". */
export const minutesToTime = (m: number) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`
export function timeToMinutes(t: string): number | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(t.trim())
  if (!m) return null
  const h = Number(m[1])
  const mi = Number(m[2])
  if (h > 24 || mi > 59 || (h === 24 && mi > 0)) return null
  return h * 60 + mi
}
export function hoursText(h: AllowedHours | null): string {
  if (!h) return 'Any time'
  if (hoursEmpty(h)) return 'Never (empty window)'
  const days = h.days.length === 7 ? 'Every day' : h.days.join(',') === '0,1,2,3,4' ? 'Mon–Fri' : h.days.map((d) => DAY_LABEL[d]).join(', ')
  return `${days} ${minutesToTime(h.start_minute)}–${minutesToTime(h.end_minute)} (device local time)`
}
