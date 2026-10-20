import { describe, expect, it } from 'vitest'
import { checkManifestFormat, compareVersions, parseManifest, validVersion } from './updates'

const SHA = 'a'.repeat(64)
const good = { version: '1.4.0', url: 'https://kestrel.acme.sg:8443/downloads/updates/kestrel-agent-1.4.0-x64.msi', sha256: SHA, signature: 'c2lnbmF0dXJl' }

describe('compareVersions (mirrors kestrel_common::update::is_newer)', () => {
  it('compares dotted numbers, ignoring a leading v and non-numeric parts', () => {
    expect(compareVersions('1.10.0', '1.9.9')).toBe(1)
    expect(compareVersions('v1.2.3', '1.2.3')).toBe(0)
    expect(compareVersions('1.2', '1.2.0.0')).toBe(0)
    expect(compareVersions('1.2.3-rc1', '1.2.3')).toBe(0)
    expect(compareVersions('0.9.4', '1.0.1')).toBe(-1)
  })
})

describe('validVersion', () => {
  it('accepts semver-ish versions and rejects junk', () => {
    for (const v of ['1.4', '1.4.0', 'v1.4.0', '1.4.0.12', '1.4.0-rc1', '1.4.0+build.7']) expect(validVersion(v)).toBe(true)
    for (const v of ['', '1', '1.2.3.4.5', ' 1.2.3', '1.2.x', '1.2.3-', '1.2.3-r c']) expect(validVersion(v)).toBe(false)
  })
})

describe('parseManifest', () => {
  it('parses the manifest printed by update-sign and keeps only the signed fields', () => {
    const r = parseManifest(JSON.stringify({ ...good, extra: 1 }))
    expect(r).toEqual({ ok: true, manifest: good })
  })
  it('accepts a manifest wrapped in { manifest }', () => {
    expect(parseManifest(JSON.stringify({ manifest: good })).ok).toBe(true)
  })
  it('explains what is wrong', () => {
    const err = (s: string) => {
      const r = parseManifest(s)
      return r.ok ? '' : r.error
    }
    expect(err('')).toMatch(/Paste the manifest/)
    expect(err('{ nope')).toMatch(/Not valid JSON/)
    expect(err('[1]')).toMatch(/JSON object/)
    expect(err(JSON.stringify({ version: '1.4.0' }))).toMatch(/Missing or non-text fields: url, sha256, signature/)
    expect(err(JSON.stringify({ ...good, url: 'http://x/a.msi' }))).toMatch(/https:\/\//)
    expect(err(JSON.stringify({ ...good, url: 'https://user@host/a.msi' }))).toMatch(/user info/)
    expect(err(JSON.stringify({ ...good, sha256: 'abc' }))).toMatch(/64 hexadecimal/)
    expect(err(JSON.stringify({ ...good, signature: ' ' }))).toMatch(/signature is missing/)
    expect(err(JSON.stringify({ ...good, version: 'latest' }))).toMatch(/not a version number/)
  })
  it('checkManifestFormat passes a good manifest', () => {
    expect(checkManifestFormat(good)).toBeNull()
  })
})
