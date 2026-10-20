import type { GroupUpdateRing, UpdateManifest, UpdateReleaseState } from '@/api/types'

/** Labels and one-line explanations for the staged update rings. */
export const RING_LABEL: Record<GroupUpdateRing, string> = {
  canary: 'Canary',
  early: 'Early',
  broad: 'Broad',
  pinned: 'Pinned',
}
export const RING_HINT: Record<GroupUpdateRing, string> = {
  canary: 'Ring 0: gets every release first. Put a few IT machines here.',
  early: 'Ring 1: gets a release once canary looks healthy.',
  broad: 'Ring 2: everyone else (the default).',
  pinned: 'Never auto-updates. Upgrade these devices by hand (MSI).',
}
export const RELEASE_STATE_LABEL: Record<UpdateReleaseState, string> = {
  staged: 'Staged',
  rolling: 'Rolling out',
  complete: 'Complete',
  halted: 'Halted',
}

/**
 * Dotted-numeric version compare, mirroring `kestrel_common::update::is_newer`:
 * non-numeric parts count as 0, a leading `v` is ignored. Returns <0, 0 or >0.
 */
export function compareVersions(a: string, b: string): number {
  const parse = (s: string) =>
    s
      .trim()
      .replace(/^v+/, '')
      .split(/[.+-]/)
      .map((p) => (/^\d+$/.test(p) ? Number(p) : 0))
  const x = parse(a)
  const y = parse(b)
  const n = Math.max(x.length, y.length)
  for (let i = 0; i < n; i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

/** Semver-ish `[v]N.N[.N[.N]]` with an optional `-pre` / `+build` suffix (mirrors `valid_version`). */
export function validVersion(v: string): boolean {
  if (!v || v.length > 64 || v.trim() !== v) return false
  return /^v?\d{1,9}(\.\d{1,9}){1,3}([-+][0-9A-Za-z.+-]+)?$/.test(v)
}

/** Same format checks as `kestrel_common::update::check_manifest_format`. Returns an error message or null. */
export function checkManifestFormat(m: UpdateManifest): string | null {
  if (!validVersion(m.version)) return `version '${m.version.slice(0, 80)}' is not a version number like 1.4.0 or 1.4.0-rc1`
  if (!m.url || m.url.length > 2048) return 'url is empty or too long'
  // eslint-disable-next-line no-control-regex
  if (/[\s\u0000-\u001f\u007f]/.test(m.url)) return 'url must not contain whitespace or control characters'
  if (!m.url.startsWith('https://')) return 'url must start with https://'
  const host = m.url.slice('https://'.length).split(/[/?#]/)[0]
  if (!host || host.includes('@')) return 'url must name a host (and no user info)'
  if (!/^[0-9a-fA-F]{64}$/.test(m.sha256)) return 'sha256 must be 64 hexadecimal characters'
  if (!m.signature.trim()) return 'signature is missing'
  return null
}

export type ManifestParse = { ok: true; manifest: UpdateManifest } | { ok: false; error: string }

/**
 * Parse the JSON printed by `kestrel-agent update-sign`. Accepts the bare
 * manifest object or one wrapped as `{ "manifest": { … } }`. Only the four
 * signed fields are kept.
 */
export function parseManifest(text: string): ManifestParse {
  const t = text.trim()
  if (!t) return { ok: false, error: 'Paste the manifest JSON printed by kestrel-agent update-sign.' }
  let raw: unknown
  try {
    raw = JSON.parse(t)
  } catch (e) {
    return { ok: false, error: `Not valid JSON: ${(e as Error).message}` }
  }
  if (raw && typeof raw === 'object' && !Array.isArray(raw) && 'manifest' in raw && typeof (raw as { manifest: unknown }).manifest === 'object') {
    raw = (raw as { manifest: unknown }).manifest
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return { ok: false, error: 'The manifest must be a JSON object with version, url, sha256 and signature.' }
  const o = raw as Record<string, unknown>
  const missing = (['version', 'url', 'sha256', 'signature'] as const).filter((k) => typeof o[k] !== 'string')
  if (missing.length) return { ok: false, error: `Missing or non-text field${missing.length > 1 ? 's' : ''}: ${missing.join(', ')}` }
  const manifest: UpdateManifest = { version: o.version as string, url: o.url as string, sha256: o.sha256 as string, signature: o.signature as string }
  const err = checkManifestFormat(manifest)
  return err ? { ok: false, error: err } : { ok: true, manifest }
}
