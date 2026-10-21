import type { Device, Policy, RemoteAccessInfo, RemoteAccessProfile, RemoteAvailability, RemoteDesktopStatus } from '@/api/types'
import { intersectProfiles, normaliseProfile, profileGuarded, profileNone, profileSummary, profileUnrestricted } from '@/lib/remote-profile'

/** Active mock remote-desktop sessions by device id (one per device, like the server). */
export const desktopSessions = new Map<string, NonNullable<RemoteDesktopStatus['session']>>()

/** File-manager sessions (`fm_session`) the mock employee already allowed. */
export const consentedFmSessions = new Set<string>()

/** MFA step-up window of the signed-in mock admin (`POST /me/reauth`). */
export const reauth = { until: 0 }

/** Agents older than this lack `live.files` / `live.desktop` in the mock fleet. */
export const MIN_REMOTE_AGENT = '0.9.4'

function versionLt(a: string, b: string): boolean {
  const pa = a.split(/[.-]/).map((x) => Number(x) || 0)
  const pb = b.split(/[.-]/).map((x) => Number(x) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0)
  }
  return false
}

/**
 * Install-time ceiling per device (from the enrollment token it used):
 * IT and Engineering laptops were enrolled unrestricted, HR with no remote
 * access at all, everything else with the guarded default.
 */
const ceilings = new Map<string, RemoteAccessProfile>()
export function ceilingFor(d: Device): RemoteAccessProfile {
  let c = ceilings.get(d.id)
  if (!c) {
    c = d.group_id === 'grp-it' || d.group_id === 'grp-eng' || d.hostname === 'SAL-LT-022' ? profileUnrestricted() : d.hostname.startsWith('HR-') ? profileNone() : profileGuarded()
    ceilings.set(d.id, c)
  }
  return c
}

export function effectiveFor(d: Device, p: Policy): RemoteAccessProfile {
  return intersectProfiles(ceilingFor(d), normaliseProfile(p.remote_access))
}

/** Preconditions in the contract's order: ceiling / policy → connected → capability. */
export function remoteAccessFor(d: Device, p: Policy): RemoteAccessInfo {
  const ceiling = ceilingFor(d)
  const policy = normaliseProfile(p.remote_access)
  const effective = intersectProfiles(ceiling, policy)
  const one = (ceilOn: boolean, policyOn: boolean): RemoteAvailability => {
    if (!ceilOn) return { available: false, reason: 'not_permitted' }
    if (!policyOn) return { available: false, reason: 'disabled_by_policy' }
    if (d.status === 'offline') return { available: false, reason: 'offline' }
    if (versionLt(d.agent_version, MIN_REMOTE_AGENT)) return { available: false, reason: 'agent_too_old' }
    return { available: true, reason: null }
  }
  return {
    desktop: one(ceiling.desktop !== 'off', policy.desktop !== 'off'),
    files: one(ceiling.files !== 'off', policy.files !== 'off'),
    ceiling,
    ceiling_summary: profileSummary(ceiling),
    policy,
    effective,
    effective_summary: profileSummary(effective),
    agent_reported_ceiling: ceiling,
  }
}
