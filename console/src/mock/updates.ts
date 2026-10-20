// Mock of the signed agent auto-update control plane (staged rings).
// Mirrors the server semantics in the REST contract: rings are promoted strictly
// in order canary -> early -> broad, halt is terminal, health is derived from
// device agent versions plus per-device delivery outcomes.
import type { Device, Group, GroupUpdateRing, UpdateFailure, UpdateManifest, UpdateRelease, UpdateRing, UpdateRingHealth, UpdateStatus, User } from '@/api/types'
import { UPDATE_RINGS } from '@/api/types'
import { compareVersions } from '@/lib/updates'
import { DAY, HOUR, MIN } from './fleet'
import { sha256, uuid } from './rng'

export const MOCK_SERVER_VERSION = '1.1.0'
export const MOCK_PUBLIC_KEY = 'Lk3xV0p2m9QbF7rT1sWc8yHn4eJ6aZdG5uK0iO2qXvE='
export const MOCK_PACKAGE_BASE = 'https://kestrel.harbourline.sg:8443/downloads/updates/'

interface Delivery {
  device_id: string
  at: number
  outcome: 'pending' | 'succeeded' | 'failed'
  error?: string
  outcome_at?: number
}

export interface ReleaseRec {
  id: string
  manifest: UpdateManifest
  notes: string
  created_by: User | null
  created_at: number
  enabled: Partial<Record<UpdateRing, { at: number; by: User | null }>>
  halted: { at: number; by: User | null; reason: string } | null
  deliveries: Map<string, Delivery>
}

export class UpdateError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

export function ringOfDevice(d: Device, groups: Group[]): GroupUpdateRing {
  const g = groups.find((x) => x.id === d.group_id) ?? groups.find((x) => x.is_default)
  return g?.update_ring ?? 'broad'
}

function nextRing(r: ReleaseRec): UpdateRing | null {
  if (r.halted) return null
  return UPDATE_RINGS.find((x) => !r.enabled[x]) ?? null
}

function stateOf(r: ReleaseRec): UpdateRelease['state'] {
  if (r.halted) return 'halted'
  if (r.enabled.broad) return 'complete'
  return UPDATE_RINGS.some((x) => r.enabled[x]) ? 'rolling' : 'staged'
}

export class MockUpdates {
  releases: ReleaseRec[] = []
  signingKeyConfigured = true

  constructor(
    private devices: () => Device[],
    private groups: () => Group[],
  ) {}

  private inRing(ring: GroupUpdateRing) {
    const gs = this.groups()
    return this.devices().filter((d) => ringOfDevice(d, gs) === ring)
  }

  find(id: string): ReleaseRec {
    const r = this.releases.find((x) => x.id === id)
    if (!r) throw new UpdateError(404, 'Release not found')
    return r
  }

  health(r: ReleaseRec, ring: UpdateRing, now = Date.now()): UpdateRingHealth {
    const devs = this.inRing(ring)
    let on_target = 0
    let delivered = 0
    let succeeded = 0
    let failed = 0
    let offline = 0
    for (const d of devs) {
      const onTarget = compareVersions(d.agent_version, r.manifest.version) >= 0
      if (onTarget) on_target++
      const del = r.deliveries.get(d.id)
      if (!del) continue
      delivered++
      if (onTarget) succeeded++
      else if (del.outcome === 'failed') failed++
      if (!onTarget && d.last_seen < now - DAY) offline++
    }
    const en = r.enabled[ring]
    return {
      ring,
      enabled: !!en,
      enabled_at: en?.at ?? null,
      enabled_by: en?.by?.id ?? null,
      enabled_by_name: en?.by?.name ?? null,
      devices: devs.length,
      on_target,
      delivered,
      succeeded,
      failed,
      pending: delivered - succeeded - failed,
      offline_24h: offline,
    }
  }

  view(r: ReleaseRec, now = Date.now()): UpdateRelease {
    const host = new Map(this.devices().map((d) => [d.id, d] as const))
    const failures: UpdateFailure[] = [...r.deliveries.values()]
      .filter((x) => x.outcome === 'failed' && host.has(x.device_id) && compareVersions(host.get(x.device_id)!.agent_version, r.manifest.version) < 0)
      .map((x) => ({ device_id: x.device_id, hostname: host.get(x.device_id)!.hostname, error: x.error ?? 'update failed', at: x.outcome_at ?? x.at }))
      .sort((a, b) => b.at - a.at)
      .slice(0, 20)
    return {
      id: r.id,
      ...r.manifest,
      notes: r.notes,
      created_by: r.created_by?.id ?? null,
      created_by_name: r.created_by?.name ?? null,
      created_at: r.created_at,
      state: stateOf(r),
      halted_at: r.halted?.at ?? null,
      halted_by: r.halted?.by?.id ?? null,
      halted_by_name: r.halted?.by?.name ?? null,
      halt_reason: r.halted?.reason ?? '',
      next_ring: nextRing(r),
      rings: UPDATE_RINGS.map((ring) => this.health(r, ring, now)),
      recent_failures: failures,
    }
  }

  list(): UpdateRelease[] {
    return [...this.releases].sort((a, b) => compareVersions(b.manifest.version, a.manifest.version) || b.created_at - a.created_at).map((r) => this.view(r))
  }

  status(): UpdateStatus {
    const gs = this.groups()
    const rings = (['canary', 'early', 'broad', 'pinned'] as GroupUpdateRing[]).map((ring) => {
      const devs = this.inRing(ring)
      const counts = new Map<string, number>()
      for (const d of devs) counts.set(d.agent_version, (counts.get(d.agent_version) ?? 0) + 1)
      const target =
        ring === 'pinned'
          ? null
          : ([...this.releases].filter((r) => !r.halted && r.enabled[ring]).sort((a, b) => compareVersions(b.manifest.version, a.manifest.version))[0] ?? null)
      return {
        ring,
        groups: gs.filter((g) => g.update_ring === ring).map((g) => ({ id: g.id, name: g.name })),
        devices: devs.length,
        versions: [...counts.entries()].map(([version, count]) => ({ version, count })).sort((a, b) => b.count - a.count || compareVersions(b.version, a.version)),
        target: target ? { id: target.id, version: target.manifest.version } : null,
      }
    })
    return {
      signing_key_configured: this.signingKeyConfigured,
      public_key: this.signingKeyConfigured ? MOCK_PUBLIC_KEY : null,
      package_base_url: MOCK_PACKAGE_BASE,
      server_version: MOCK_SERVER_VERSION,
      rings,
    }
  }

  /** Register a manifest. The mock cannot verify Ed25519 signatures; it accepts any non-empty one. */
  register(manifest: UpdateManifest, notes: string, by: User | null, now = Date.now()): ReleaseRec {
    if (!this.signingKeyConfigured) throw new UpdateError(400, 'KESTREL_UPDATE_PUBKEY is not configured on the server; set it to the base64 Ed25519 public key (see docs/BUILDING.md) and restart the server')
    if (this.releases.some((r) => r.manifest.version === manifest.version)) throw new UpdateError(409, `release ${manifest.version} is already registered`)
    const r: ReleaseRec = { id: uuid(), manifest: { ...manifest }, notes: notes ?? '', created_by: by, created_at: now, enabled: {}, halted: null, deliveries: new Map() }
    this.releases.push(r)
    return r
  }

  /** Enable `ring` for the release; delivers immediately to connected devices in it that are below the version. */
  promote(id: string, ring: UpdateRing, by: User | null, now = Date.now()): { release: ReleaseRec; delivered_now: number; delivered_ids: string[] } {
    const r = this.find(id)
    if (!UPDATE_RINGS.includes(ring)) throw new UpdateError(400, `unknown ring '${String(ring)}'`)
    if (r.halted) throw new UpdateError(409, `release ${r.manifest.version} is halted; register a newer release instead`)
    const next = nextRing(r)
    if (!next) throw new UpdateError(409, `release ${r.manifest.version} is already enabled for every ring`)
    if (ring !== next) throw new UpdateError(409, r.enabled[ring] ? `the ${ring} ring is already enabled for ${r.manifest.version}` : `promote rings in order: enable ${next} before ${ring}`)
    r.enabled[ring] = { at: now, by }
    const ids: string[] = []
    for (const d of this.inRing(ring)) {
      if (compareVersions(d.agent_version, r.manifest.version) >= 0) continue
      if (d.last_seen < now - 3 * MIN) continue // offline: gets it on its next connection
      r.deliveries.set(d.id, { device_id: d.id, at: now, outcome: 'pending' })
      ids.push(d.id)
    }
    return { release: r, delivered_now: ids.length, delivered_ids: ids }
  }

  halt(id: string, reason: string, by: User | null, now = Date.now()): ReleaseRec {
    const r = this.find(id)
    if (r.halted) throw new UpdateError(409, `release ${r.manifest.version} is already halted`)
    r.halted = { at: now, by, reason: reason ?? '' }
    return r
  }

  /** Simulated agent reports after a delivery: most succeed, a few fail. */
  settle(id: string, deviceIds: string[], now = Date.now()) {
    const r = this.releases.find((x) => x.id === id)
    if (!r) return
    const devs = this.devices()
    deviceIds.forEach((did, i) => {
      const del = r.deliveries.get(did)
      const d = devs.find((x) => x.id === did)
      if (!del || !d || del.outcome !== 'pending') return
      if (i % 9 === 4) {
        del.outcome = 'failed'
        del.error = 'msiexec exited with 1618 (another installation is already in progress); will retry on next connection'
        del.outcome_at = now
      } else {
        del.outcome = 'succeeded'
        del.outcome_at = now
        d.agent_version = r.manifest.version
      }
    })
  }
}

const pkg = (v: string) => `${MOCK_PACKAGE_BASE}kestrel-agent-${v}-x64.msi`
const sig = () => btoa(sha256().slice(0, 64)).slice(0, 86) + '=='

/**
 * Seed three releases against the fleet: 1.0.1 complete (most of the fleet),
 * 1.0.2 halted after canary, and 1.1.0 rolling with canary enabled and a mix
 * of succeeded, pending (one offline > 24 h) and one hash-mismatch failure.
 */
export function seedUpdates(store: MockUpdates, devices: Device[], groups: Group[], users: User[], now = Date.now()) {
  const [priya, , , marcus] = users
  const ring = (d: Device) => ringOfDevice(d, groups)
  const managed = devices.filter((d) => ring(d) !== 'pinned')

  // 1.0.1: the whole managed fleet got it a month ago.
  const r1 = store.register({ version: '1.0.1', url: pkg('1.0.1'), sha256: '4f9c2a1be8d7360c51e2a9f04b7d3c86e1f5a0b9d2c48e7f6a3b1d0c9e8f7a6b', signature: sig() }, 'Fixes ETW session restart after sleep; lower memory use of the YARA-X scanner.', priya, now - 36 * DAY)
  r1.enabled = { canary: { at: now - 35 * DAY, by: priya }, early: { at: now - 33 * DAY, by: priya }, broad: { at: now - 31 * DAY, by: marcus } }
  let failedOne = false
  for (const d of managed) {
    const old = compareVersions(d.agent_version, '1.0.1') < 0
    const failed = old && !failedOne && d.last_seen > now - 3 * MIN
    if (failed) failedOne = true
    r1.deliveries.set(d.id, {
      device_id: d.id,
      at: now - 31 * DAY,
      outcome: old ? (failed ? 'failed' : 'pending') : 'succeeded',
      error: failed ? 'msiexec exited with 1603 (fatal error during installation); see C:\\ProgramData\\Kestrel\\update\\msiexec.log' : undefined,
      outcome_at: now - 31 * DAY + 2 * HOUR,
    })
  }

  // Canary devices: IT + Engineering, a deterministic scenario.
  const canary = devices.filter((d) => ring(d) === 'canary')

  // 1.0.2: halted after canary showed a service start failure.
  const r2 = store.register({ version: '1.0.2', url: pkg('1.0.2'), sha256: 'b1e7a9d04c2f6853e19a7c0d4b2f86e3a5c9d1f07e4b2a6c8d3f5e9a1b7c0d24', signature: sig() }, 'Tray app accessibility fixes; new ST-17 rule in Audit.', marcus, now - 10 * DAY)
  r2.enabled = { canary: { at: now - 9 * DAY, by: marcus } }
  r2.halted = { at: now - 8 * DAY - 3 * HOUR, by: priya, reason: 'Agent service fails to start on Windows 10 22H2 after the upgrade (two canary laptops). Fixed in 1.1.0.' }
  canary.forEach((d, i) => {
    if (compareVersions(d.agent_version, '1.0.1') < 0) d.agent_version = '1.0.1'
    r2.deliveries.set(d.id, { device_id: d.id, at: now - 9 * DAY, outcome: i === 2 ? 'failed' : 'succeeded', error: i === 2 ? 'agent did not report the new version 30 min after msiexec; service failed to start (event 7000)' : undefined, outcome_at: now - 9 * DAY + 40 * MIN })
    if (i !== 2) d.agent_version = '1.0.2'
  })

  // 1.1.0: canary enabled ~26 h ago.
  const r3 = store.register({ version: '1.1.0', url: pkg('1.1.0'), sha256: '9d2c48e7f6a3b1d0c9e8f7a6b4f9c2a1be8d7360c51e2a9f04b7d3c86e1f5a0b', signature: sig() }, 'Signed auto-update with staged rings, IOC-linked network blocks, faster process-table rebuild after restart.', priya, now - 2 * DAY)
  r3.enabled = { canary: { at: now - 26 * HOUR, by: priya } }
  canary.forEach((d, i) => {
    const at = now - 26 * HOUR + i * 4 * MIN
    if (i === 1) {
      r3.deliveries.set(d.id, { device_id: d.id, at, outcome: 'failed', error: 'downloaded package hash 3a7f0c1d9e2b… does not match manifest sha256 9d2c48e7f6a3…; package discarded (proxy rewrote the download?)', outcome_at: at + 6 * MIN })
      d.last_seen = Math.max(d.last_seen, now - 40 * 1000)
    } else if (i === 4) {
      r3.deliveries.set(d.id, { device_id: d.id, at, outcome: 'pending' })
      d.last_seen = now - 30 * HOUR // offline > 24 h since delivery
    } else if (i === 6) {
      r3.deliveries.set(d.id, { device_id: d.id, at: now - 6 * MIN, outcome: 'pending' })
      d.last_seen = now - 50 * 1000
    } else {
      r3.deliveries.set(d.id, { device_id: d.id, at, outcome: 'succeeded', outcome_at: at + 9 * MIN })
      d.agent_version = '1.1.0'
    }
  })
}
