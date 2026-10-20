import { describe, expect, it } from 'vitest'
import type { Dashboard, IncidentDetail, Page, Incident, DeviceDetail, HuntResponse, Group, PromotedUpdateRelease, UpdateRelease, UpdateStatus } from '@/api/types'
import { db, handleMock } from './server'

const q = (s = '') => new URLSearchParams(s)

describe('mock API', () => {
  db.session = db.users[0]
  it('seeds ~40 devices and the stealer scenarios', async () => {
    expect(db.devices.length).toBeGreaterThanOrEqual(38)
    const r = await handleMock('GET', '/incidents', q('limit=500'), undefined)
    const page = r.body as Page<Incident>
    const titles = page.items.map((i) => i.title).join('\n')
    expect(titles).toMatch(/Setup_x64\.exe on SAL-LT-022/)
    expect(titles).toMatch(/Invoice_Oct2026\.exe on FIN-LT-003/)
    expect(titles).toMatch(/chrome\.exe on MKT-LT-005|synchelper/)
    expect(page.items.some((i) => i.hostname === 'IT-LT-002' && i.classification === 'benign')).toBe(true)
  })
  it('computes priority per the contract and sorts by it', async () => {
    const page = (await handleMock('GET', '/incidents', q('sort=priority&limit=500'), undefined)).body as Page<Incident>
    for (const i of page.items) {
      const base = { info: 5, low: 20, medium: 45, high: 70, critical: 90 }[i.severity]
      const impact = i.rule_ids.some((r) => r === 'ST-04' || r === 'ST-14' || r.startsWith('RW-') || r.startsWith('CD-'))
      const exp = Math.min(100, base + (i.data_at_risk.length ? 10 : 0) + (impact ? 10 : 0) + (i.contained ? 0 : 5))
      expect(i.priority).toBe(exp)
    }
    const pr = page.items.map((i) => i.priority)
    expect([...pr].sort((a, b) => b - a)).toEqual(pr)
  })
  it('returns incident detail with tree, checklist and storyline', async () => {
    const page = (await handleMock('GET', '/incidents', q('q=SAL-LT-022'), undefined)).body as Page<Incident>
    const d = (await handleMock('GET', `/incidents/${page.items[0].id}`, q(), undefined)).body as IncidentDetail
    expect(d.process_tree.length).toBeGreaterThan(2)
    expect(d.checklist.some((c) => c.kind === 'done')).toBe(true)
    expect(d.checklist.some((c) => c.kind === 'approve')).toBe(true)
    expect(d.network.some((n) => n.blocked)).toBe(true)
    expect(d.storyline).toContain('Telegram')
  })
  it('serves dashboard and device detail', async () => {
    const dash = (await handleMock('GET', '/dashboard', q(), undefined)).body as Dashboard
    expect(dash.alert_trend).toHaveLength(14)
    expect(dash.devices.total).toBe(db.devices.length)
    const dd = (await handleMock('GET', `/devices/${db.devices[0].id}`, q(), undefined)).body as DeviceDetail
    expect(dd.hardening.length).toBe(13)
  })
  it('seeds ransomware, credential-dumping and persistence incidents', async () => {
    const page = (await handleMock('GET', '/incidents', q('limit=500'), undefined)).body as Page<Incident>
    const titles = page.items.map((i) => i.title).join('\n')
    expect(titles).toMatch(/Ransomware activity by lblview\.exe on OPS-DT-009/)
    expect(titles).toMatch(/Credential dumping by rundll32\.exe on SRV-APP-02/)
    expect(titles).toMatch(/Persistence planted by PDF_Converter_Pro_Setup\.exe on HR-LT-006/)
    const ps = page.items.find((i) => i.hostname === 'HR-LT-006' && i.rule_ids.includes('PS-05'))!
    const d = (await handleMock('GET', `/incidents/${ps.id}`, q(), undefined)).body as IncidentDetail
    expect(d.actions.some((a) => a.action.type === 'remove_autorun' && a.artifact)).toBe(true)
    expect(d.checklist.some((c) => c.kind === 'approve' && c.action?.type === 'remove_autorun')).toBe(true)
  })
  it('runs hunts with the shared parser and rejects bad queries', async () => {
    const ok = (await handleMock('POST', '/hunt', q(), { query: 'dns_qname = api.telegram.org', from: 0, to: Date.now() + 1, limit: 100 })).body as HuntResponse
    expect(ok.items.length).toBeGreaterThan(0)
    const bad = await handleMock('POST', '/hunt', q(), { query: 'nope = 1', from: 0, to: 1, limit: 1 })
    expect(bad.status).toBe(400)
  })
  it('bumps policy version on save and records it in the hash-chained audit log', async () => {
    const p = db.policies[0]
    const v = p.version
    const r = await handleMock('PUT', `/policies/${p.id}`, q(), { ...p, canaries: false })
    expect((r.body as { version: number }).version).toBe(v + 1)
    expect(db.audit[db.audit.length - 1].action).toBe('policy.update')
    expect(db.verifyAudit().ok).toBe(true)
  })
  describe('agent updates', () => {
    const SHA = 'b'.repeat(64)
    const manifest = (version: string) => ({ version, url: `https://kestrel.harbourline.sg:8443/downloads/updates/kestrel-agent-${version}-x64.msi`, sha256: SHA, signature: 'bW9jaw==' })
    it('seeds a complete, a halted and a rolling release with canary health', async () => {
      const list = (await handleMock('GET', '/updates/releases', q(), undefined)).body as UpdateRelease[]
      expect(list.map((r) => [r.version, r.state])).toEqual([
        ['1.1.0', 'rolling'],
        ['1.0.2', 'halted'],
        ['1.0.1', 'complete'],
      ])
      const rolling = list[0]
      expect(rolling.next_ring).toBe('early')
      expect(rolling.rings.map((r) => r.ring)).toEqual(['canary', 'early', 'broad'])
      const c = rolling.rings[0]
      expect(c.enabled).toBe(true)
      expect(c.succeeded).toBeGreaterThan(0)
      expect(c.pending).toBeGreaterThan(0)
      expect(c.failed).toBe(1)
      expect(c.offline_24h).toBe(1)
      expect(c.delivered).toBe(c.succeeded + c.failed + c.pending)
      expect(rolling.recent_failures[0].error).toMatch(/does not match manifest/)
      expect(list[1].next_ring).toBeNull()
      const st = (await handleMock('GET', '/updates/status', q(), undefined)).body as UpdateStatus
      expect(st.rings.map((r) => r.ring)).toEqual(['canary', 'early', 'broad', 'pinned'])
      expect(st.rings[0].target?.version).toBe('1.1.0')
      expect(st.rings[1].target?.version).toBe('1.0.1')
      expect(st.rings[3].target).toBeNull()
    })
    it('registers a manifest and rejects bad or duplicate ones', async () => {
      const ok = await handleMock('POST', '/updates/releases', q(), { manifest: manifest('1.2.0'), notes: 'test' })
      expect(ok.status).toBe(200)
      expect((ok.body as UpdateRelease).state).toBe('staged')
      expect((ok.body as UpdateRelease).next_ring).toBe('canary')
      const dup = await handleMock('POST', '/updates/releases', q(), { manifest: manifest('1.2.0') })
      expect(dup.status).toBe(409)
      const badSha = await handleMock('POST', '/updates/releases', q(), { manifest: { ...manifest('1.2.1'), sha256: 'xyz' } })
      expect(badSha.status).toBe(400)
      const http = await handleMock('POST', '/updates/releases', q(), { manifest: { ...manifest('1.2.2'), url: 'http://example.com/a.msi' } })
      expect(http.status).toBe(400)
    })
    it('enforces promote order and makes halt terminal', async () => {
      const list = (await handleMock('GET', '/updates/releases', q(), undefined)).body as UpdateRelease[]
      const rel = list.find((r) => r.version === '1.2.0')!
      expect((await handleMock('POST', `/updates/releases/${rel.id}/promote`, q(), { ring: 'early' })).status).toBe(409)
      expect((await handleMock('POST', `/updates/releases/${rel.id}/promote`, q(), { ring: 'nope' })).status).toBe(400)
      const p1 = await handleMock('POST', `/updates/releases/${rel.id}/promote`, q(), { ring: 'canary' })
      expect(p1.status).toBe(200)
      const out = p1.body as PromotedUpdateRelease
      expect(out.state).toBe('rolling')
      expect(out.next_ring).toBe('early')
      expect(out.delivered_now).toBeGreaterThanOrEqual(0)
      expect((await handleMock('POST', `/updates/releases/${rel.id}/promote`, q(), { ring: 'canary' })).status).toBe(409)
      const h = await handleMock('POST', `/updates/releases/${rel.id}/halt`, q(), { reason: 'bad build' })
      expect((h.body as UpdateRelease).state).toBe('halted')
      expect((h.body as UpdateRelease).halt_reason).toBe('bad build')
      expect((await handleMock('POST', `/updates/releases/${rel.id}/promote`, q(), { ring: 'early' })).status).toBe(409)
      expect((await handleMock('POST', `/updates/releases/${rel.id}/halt`, q(), {})).status).toBe(409)
    })
    it('promotes the whole way to complete', async () => {
      const r = (await handleMock('POST', '/updates/releases', q(), { manifest: manifest('1.3.0') })).body as UpdateRelease
      for (const ring of ['canary', 'early', 'broad']) expect((await handleMock('POST', `/updates/releases/${r.id}/promote`, q(), { ring })).status).toBe(200)
      const list = (await handleMock('GET', '/updates/releases', q(), undefined)).body as UpdateRelease[]
      const done = list.find((x) => x.id === r.id)!
      expect(done.state).toBe('complete')
      expect(done.next_ring).toBeNull()
    })
    it('stores update_ring on groups and validates it', async () => {
      const g = db.groups[0]
      const ok = await handleMock('PATCH', `/groups/${g.id}`, q(), { update_ring: 'pinned' })
      expect((ok.body as Group).update_ring).toBe('pinned')
      expect((await handleMock('PATCH', `/groups/${g.id}`, q(), { update_ring: 'ring9' })).status).toBe(400)
      const created = (await handleMock('POST', '/groups', q(), { name: 'Kiosks', description: '', policy_id: null })).body as Group
      expect(created.update_ring).toBe('broad')
      await handleMock('PATCH', `/groups/${g.id}`, q(), { update_ring: 'broad' })
    })
    it('requires updates.write to change releases', async () => {
      const prev = db.session
      db.session = db.users.find((u) => u.role === 'readonly')!
      const r = await handleMock('POST', '/updates/releases', q(), { manifest: manifest('9.9.9') })
      expect(r.status).toBe(403)
      db.session = prev
    })
  })
})
