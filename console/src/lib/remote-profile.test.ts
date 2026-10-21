import { describe, expect, it } from 'vitest'
import type { RemoteAccessProfile } from '@/api/types'
import {
  blockedPrefix,
  fileOpDenied,
  hoursContain,
  hoursEmpty,
  hoursText,
  intersectProfiles,
  isNoneProfile,
  minutesToTime,
  normaliseProfile,
  presetOf,
  profileGuarded,
  profileNone,
  profileSummary,
  profileUnrestricted,
  timeToMinutes,
  validateProfile,
} from './remote-profile'

/** Mirrors `kestrel_common::remote::tests::{presets, serde_back_compat, intersection_is_stricter_wins, file_op_permissions}`. */
describe('remote-access presets', () => {
  it('match the Rust values exactly', () => {
    const n = profileNone()
    expect(isNoneProfile(n)).toBe(true)
    expect(presetOf(n)).toBe('none')
    const u = profileUnrestricted()
    expect([u.desktop, u.files]).toEqual(['control', 'full'])
    expect(u.guardrails).toEqual({
      require_consent: false,
      consent_timeout_secs: 60,
      require_reason: false,
      require_mfa_reauth: false,
      allow_upload: true,
      allow_delete: true,
      max_session_minutes: 0,
      idle_timeout_minutes: 0,
      allowed_hours: null,
      blocked_paths: [],
    })
    expect(presetOf(u)).toBe('unrestricted')
    const g = profileGuarded()
    expect(g.guardrails).toEqual({
      require_consent: true,
      consent_timeout_secs: 60,
      require_reason: true,
      require_mfa_reauth: true,
      allow_upload: true,
      allow_delete: false,
      max_session_minutes: 60,
      idle_timeout_minutes: 15,
      allowed_hours: null,
      blocked_paths: ['C:\\Windows\\System32\\config'],
    })
    expect(presetOf(g)).toBe('guarded')
    for (const p of [n, u, g]) expect(validateProfile(p)).toBeNull()
    expect(presetOf({ ...g, desktop: 'view_only' })).toBe('custom')
  })
  it('summaries use the server wording', () => {
    expect(profileSummary(profileNone())).toBe('No remote access')
    expect(profileSummary(profileUnrestricted())).toBe('Remote control + full file manager (no guardrails)')
    expect(profileSummary(profileGuarded())).toBe('Remote control + full file manager (employee consent, reason, MFA re-auth, no delete, 60 min max, 15 min idle, 1 blocked path(s))')
    expect(profileSummary({ ...profileUnrestricted(), desktop: 'view_only', files: 'read_only' })).toBe('View-only remote desktop + read-only file manager (no guardrails)')
  })
})

describe('serde back-compat (normaliseProfile)', () => {
  it('absent profile = none; missing guardrail fields = guarded defaults', () => {
    expect(normaliseProfile(undefined)).toEqual(profileNone())
    expect(normaliseProfile({ desktop: 'control', files: 'full' })).toEqual(profileGuarded())
    const p = normaliseProfile(JSON.parse('{"desktop":"view_only","files":"read_only","guardrails":{}}') as RemoteAccessProfile)
    expect([p.desktop, p.files]).toEqual(['view_only', 'read_only'])
    expect(p.guardrails.require_consent).toBe(true)
  })
})

describe('intersection: stricter wins (mirror of RemoteAccessProfile::intersect)', () => {
  const u = profileUnrestricted()
  const n = profileNone()
  const g = profileGuarded()
  it('none caps everything; unrestricted ∩ guarded = guarded', () => {
    expect(isNoneProfile(intersectProfiles(u, n))).toBe(true)
    expect(isNoneProfile(intersectProfiles(n, u))).toBe(true)
    expect(intersectProfiles(u, g)).toEqual(g)
    expect(intersectProfiles(g, u)).toEqual(g)
  })
  it('modes take the minimum', () => {
    const e = intersectProfiles(u, { ...u, desktop: 'view_only', files: 'read_only' })
    expect([e.desktop, e.files]).toEqual(['view_only', 'read_only'])
  })
  it('limits take the smaller non-zero value, booleans and paths combine', () => {
    const a = profileUnrestricted()
    a.guardrails = { ...a.guardrails, max_session_minutes: 30, consent_timeout_secs: 0, blocked_paths: ['c:/secret'] }
    const b = profileUnrestricted()
    b.guardrails = { ...b.guardrails, max_session_minutes: 120, idle_timeout_minutes: 5, consent_timeout_secs: 20, require_reason: true, allow_delete: false, blocked_paths: ['C:\\Secret', 'D:\\x'] }
    const e = intersectProfiles(a, b)
    expect(e).toEqual(intersectProfiles(b, a))
    const eg = e.guardrails
    expect(eg.max_session_minutes).toBe(30)
    expect(eg.idle_timeout_minutes).toBe(5)
    expect(eg.consent_timeout_secs).toBe(20)
    expect(eg.require_reason && !eg.require_consent && !eg.allow_delete && eg.allow_upload).toBe(true)
    expect(eg.blocked_paths).toHaveLength(2)
    expect(blockedPrefix(eg, 'C:\\SECRET\\a.txt')).not.toBeNull()
    expect(blockedPrefix(eg, 'C:\\secretive')).toBeNull()
  })
  it('intersects allowed hours', () => {
    const h1 = profileUnrestricted()
    h1.guardrails = { ...h1.guardrails, allowed_hours: { days: [0, 1, 2, 3, 4], start_minute: 480, end_minute: 1080 } }
    const h2 = profileUnrestricted()
    h2.guardrails = { ...h2.guardrails, allowed_hours: { days: [4, 5], start_minute: 540, end_minute: 1200 } }
    const e = intersectProfiles(h1, h2).guardrails.allowed_hours!
    expect(e.days).toEqual([4])
    expect([e.start_minute, e.end_minute]).toEqual([540, 1080])
    expect(hoursContain(e, 4, 600) && !hoursContain(e, 3, 600) && !hoursContain(e, 4, 1080)).toBe(true)
    expect(intersectProfiles(h1, u).guardrails.allowed_hours).toEqual(h1.guardrails.allowed_hours)
    const h3 = profileUnrestricted()
    h3.guardrails = { ...h3.guardrails, allowed_hours: { days: [6], start_minute: 0, end_minute: 60 } }
    expect(hoursEmpty(intersectProfiles(h1, h3).guardrails.allowed_hours!)).toBe(true)
  })
})

describe('file-op permissions and validation', () => {
  it('mirrors file_op_permitted', () => {
    expect(fileOpDenied(profileNone(), 'read')).not.toBeNull()
    const ro = { ...profileUnrestricted(), files: 'read_only' as const }
    expect(fileOpDenied(ro, 'read')).toBeNull()
    expect(fileOpDenied(ro, 'write')).not.toBeNull()
    expect(fileOpDenied(ro, 'delete')).not.toBeNull()
    const g = profileGuarded()
    expect(fileOpDenied(g, 'write')).toBeNull()
    expect(fileOpDenied(g, 'delete')).not.toBeNull()
    expect(fileOpDenied(profileUnrestricted(), 'delete')).toBeNull()
  })
  it('validates hours, blocked paths and limits', () => {
    const bad = profileGuarded()
    bad.guardrails = { ...bad.guardrails, allowed_hours: { days: [7], start_minute: 0, end_minute: 10 } }
    expect(validateProfile(bad)).toMatch(/days/)
    bad.guardrails = { ...bad.guardrails, allowed_hours: { days: [1], start_minute: 600, end_minute: 600 } }
    expect(validateProfile(bad)).toMatch(/start_minute/)
    bad.guardrails = { ...bad.guardrails, allowed_hours: null, blocked_paths: ['\\\\srv\\share'] }
    expect(validateProfile(bad)).toMatch(/blocked path/)
    bad.guardrails = { ...bad.guardrails, blocked_paths: [], consent_timeout_secs: 601 }
    expect(validateProfile(bad)).toMatch(/600/)
    bad.guardrails = { ...bad.guardrails, consent_timeout_secs: 60, max_session_minutes: 1441 }
    expect(validateProfile(bad)).toMatch(/1440/)
  })
  it('formats times and hours', () => {
    expect(minutesToTime(540)).toBe('09:00')
    expect(minutesToTime(1440)).toBe('24:00')
    expect(timeToMinutes('8:30')).toBe(510)
    expect(timeToMinutes('24:00')).toBe(1440)
    expect(timeToMinutes('24:01')).toBeNull()
    expect(timeToMinutes('nope')).toBeNull()
    expect(hoursText(null)).toBe('Any time')
    expect(hoursText({ days: [0, 1, 2, 3, 4], start_minute: 480, end_minute: 1140 })).toBe('Mon–Fri 08:00–19:00 (device local time)')
  })
})
