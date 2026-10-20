import { describe, expect, it } from 'vitest'
import type { Dashboard, IncidentDetail, Page, Incident, DeviceDetail, HuntResponse } from '@/api/types'
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
      const exp = Math.min(100, base + (i.data_at_risk.length ? 10 : 0) + (i.rule_ids.some((r) => r === 'ST-04' || r === 'ST-14') ? 10 : 0) + (i.contained ? 0 : 5))
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
    expect(dd.hardening.length).toBe(8)
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
})
