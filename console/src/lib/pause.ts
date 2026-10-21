import { offeredPauseMinutes, PAUSE_MAX_MINUTES_CAP, type LocalPause, type PauseMode, type PauseState } from '@/api/types'
import { formatDateTime, safeDisplay } from './format'
import { formatMinutes, PAUSE_MODE_LABEL } from './labels'
import type { ActionSpec } from '@/components/response-actions'

const hm = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit' })

/** "14:30" when `until` is today, otherwise "22 Oct 2026, 14:30". */
export function pauseUntilLabel(until: number, now = Date.now()): string {
  const a = new Date(until)
  const b = new Date(now)
  const sameDay = a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth() && a.getDate() === b.getDate()
  return sameDay ? hm.format(until) : formatDateTime(until)
}

/**
 * Banner headline for an active pause, e.g.
 * "Protection off (detection only) until 14:30, turned off on the PC by W-FIN-07\nadia" or
 * "Protection completely off until turned back on, turned off on the PC by ...".
 * `by_user` comes from the endpoint and is passed through `safeDisplay`.
 */
export function pauseHeadline(p: PauseState, now = Date.now()): string {
  const what = p.mode === 'full' ? 'Protection completely off' : `Protection off (${PAUSE_MODE_LABEL.detection_only})`
  const until = p.until_ms == null ? 'until turned back on' : `until ${pauseUntilLabel(p.until_ms, now)}`
  const who = safeDisplay(p.by_user).trim()
  return `${what} ${until}, turned off on the PC${who ? ` by ${who}` : ''}`
}

/** Note shown on an alert that fired while protection was off. */
export function protectionOffNote(mode: PauseMode): string {
  return `Protection was turned off on this PC (${PAUSE_MODE_LABEL[mode]}): no automatic action was taken.`
}

export const RESUME_PROTECTION_SPEC: ActionSpec = {
  action: { type: 'resume_protection' },
  impact:
    'Ends the local turn-off now: the device goes back to its policy (automatic response and hardening as configured, sensors running). No uninstall token is needed. The person at the PC can turn protection off again only with the token.',
}

/** One-line summary of a `local_pause` policy, e.g. "Allowed with the uninstall token: detection only, up to 8 h". */
export function localPauseSummary(p: LocalPause): string {
  if (!p.enabled) return 'Not allowed'
  const offered = offeredPauseMinutes(p)
  const max = offered.length ? formatMinutes(offered[offered.length - 1]) : ''
  const modes = p.allow_full ? 'detection only or completely off' : 'detection only'
  const dur = p.allow_until_resumed ? `up to ${max} or until turned back on` : `up to ${max}`
  return `Allowed with the uninstall token: ${modes}, ${dur}`
}

/**
 * Mirrors `LocalPause::reconcile`: what an active pause becomes under a (new)
 * policy at `now`. null = it ends now; otherwise the pause with `until_ms`
 * clamped to `now + max_minutes`.
 */
export function reconcilePause(policy: LocalPause, s: PauseState, now: number): PauseState | null {
  if (!policy.enabled || (s.mode === 'full' && !policy.allow_full)) return null
  const max = Math.min(Math.max(Math.round(policy.max_minutes) || 1, 1), PAUSE_MAX_MINUTES_CAP)
  const cap = now + max * 60_000
  const out = { ...s }
  if (s.until_ms == null) {
    if (!policy.allow_until_resumed) out.until_ms = cap
  } else if (s.until_ms > cap) out.until_ms = cap
  if (out.until_ms != null && now >= out.until_ms) return null
  return out
}
