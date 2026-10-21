import { describe, expect, it } from 'vitest'
import type { CreatedEnrollmentToken, DeviceDetail, EnrollmentToken, FileEntry, FileListResponse } from '@/api/types'
import { blobBytes, db, handleMock, mockOptions } from './server'
import { reauth } from './remote-state'

const q = (o: Record<string, string> = {}) => new URLSearchParams(o)
const err = (b: unknown) => (b as { error: { code: string; message: string; remote_code?: string; reason?: string } }).error

async function detail(id: string) {
  return (await handleMock('GET', `/devices/${id}`, q(), undefined)).body as DeviceDetail
}
/** First device whose detail matches. */
async function find(pred: (d: DeviceDetail) => boolean) {
  for (const d of db.devices) {
    const dd = await detail(d.id)
    if (pred(dd)) return dd
  }
  throw new Error('no matching mock device')
}

describe('mock remote access', () => {
  db.session = db.users[0] // admin (*)
  mockOptions.latency = false

  it('reports ceiling, policy, effective and availability per device', async () => {
    const eng = await find((d) => d.device.group_id === 'grp-eng' && !!d.remote_access?.files.available)
    expect(eng.remote_access?.ceiling_summary).toMatch(/no guardrails/)
    expect(eng.remote_access?.effective_summary).toMatch(/no guardrails/)
    const hr = await find((d) => d.device.hostname.startsWith('HR-'))
    expect(hr.remote_access?.desktop).toEqual({ available: false, reason: 'not_permitted' })
    const srv = await find((d) => d.device.hostname.startsWith('SRV-') && d.device.status !== 'offline')
    expect(srv.remote_access?.desktop.reason).toBe('disabled_by_policy')
    expect(srv.remote_access?.effective?.files).toBe('read_only')
    const off = await find((d) => d.device.status === 'offline' && d.remote_access?.ceiling?.files !== 'off' && d.remote_access?.policy?.files !== 'off')
    expect(off.remote_access?.files.reason).toBe('offline')
  })

  it('lists drives and folders, refuses Kestrel folders, and does file ops', async () => {
    const dev = await find((d) => d.device.group_id === 'grp-eng' && !!d.remote_access?.files.available)
    const id = dev.device.id
    const ctx = { fm_session: crypto.randomUUID() }
    const drives = (await handleMock('GET', `/devices/${id}/files`, q(ctx), undefined)).body as FileListResponse
    expect(drives.entries.map((e) => e.path)).toEqual(['C:\\', 'D:\\'])
    expect(drives.entries[0].kind).toBe('drive')
    const pf = (await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\Program Files' }), undefined)).body as FileListResponse
    expect(pf.entries.some((e) => e.name === 'Kestrel')).toBe(true)
    const prot = await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'c:/program files/kestrel' }), undefined)
    expect(prot.status).toBe(403)
    expect(err(prot.body).remote_code).toBe('protected_path')
    const delAncestor = await handleMock('POST', `/devices/${id}/files/delete`, q(ctx), { path: 'C:\\Program Files', recursive: true })
    expect(err(delAncestor.body).remote_code).toBe('protected_path')
    const bad = await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\a\\..\\b' }), undefined)
    expect(bad.status).toBe(400)
    expect(err(bad.body).remote_code).toBe('invalid_path')

    const users = (await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\Users' }), undefined)).body as FileListResponse
    const home = users.entries.find((e) => e.kind === 'dir' && !e.hidden && e.name !== 'Public')!
    const docs = `${home.path}\\Documents`

    // mkdir (parents created) + upload + download + rename + delete
    const mk = await handleMock('POST', `/devices/${id}/files/mkdir`, q(ctx), { path: `${docs}\\Kestrel test\\inner` })
    expect(mk.status).toBe(200)
    const blob = new Blob(['hello remote'])
    const up = await handleMock('POST', `/devices/${id}/files/upload`, q({ ...ctx, path: `${docs}\\Kestrel test\\note.txt` }), blob)
    expect(up.status).toBe(200)
    expect(up.body).toMatchObject({ size: 12, sha256: expect.stringMatching(/^[0-9a-f]{64}$/) })
    const dl = await handleMock('GET', `/devices/${id}/files/download`, q({ ...ctx, path: `${docs}\\Kestrel test\\note.txt` }), undefined)
    expect(new TextDecoder().decode(await blobBytes(dl.body as Blob))).toBe('hello remote')
    expect(dl.headers?.['Content-Disposition']).toMatch(/filename="note.txt"/)
    const st = (await handleMock('GET', `/devices/${id}/files/stat`, q({ ...ctx, path: `${docs}\\Kestrel test\\note.txt` }), undefined)).body as FileEntry
    expect(st.size).toBe(12)
    const clash = await handleMock('POST', `/devices/${id}/files/rename`, q(ctx), { from: `${docs}\\Kestrel test\\note.txt`, to: `${docs}\\Kestrel test\\inner` })
    expect(err(clash.body).remote_code).toBe('already_exists')
    const rn = await handleMock('POST', `/devices/${id}/files/rename`, q(ctx), { from: `${docs}\\Kestrel test\\note.txt`, to: `${docs}\\Kestrel test\\renamed.txt` })
    expect(rn.status).toBe(200)
    const notEmpty = await handleMock('POST', `/devices/${id}/files/delete`, q(ctx), { path: `${docs}\\Kestrel test` })
    expect(err(notEmpty.body).remote_code).toBe('invalid_operation')
    const del = await handleMock('POST', `/devices/${id}/files/delete`, q(ctx), { path: `${docs}\\Kestrel test`, recursive: true })
    expect(del.body).toMatchObject({ removed: 3 })
    const gone = await handleMock('GET', `/devices/${id}/files/stat`, q({ ...ctx, path: `${docs}\\Kestrel test` }), undefined)
    expect(gone.status).toBe(404)
    // A blocked folder also protects the folders that contain it from rename / delete.
    const pol = db.policies.find((p) => p.id === dev.device.policy_id)!
    const before = pol.remote_access
    pol.remote_access = { ...pol.remote_access!, guardrails: { ...pol.remote_access!.guardrails, blocked_paths: ['C:\\Users\\Public\\Documents'] } }
    try {
      const inside = await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\Users\\Public\\Documents' }), undefined)
      expect(err(inside.body).remote_code).toBe('blocked_path')
      const parentDel = await handleMock('POST', `/devices/${id}/files/delete`, q(ctx), { path: 'C:\\Users\\Public', recursive: true })
      expect(err(parentDel.body).remote_code).toBe('blocked_path')
      const parentRen = await handleMock('POST', `/devices/${id}/files/rename`, q(ctx), { from: 'C:\\Users\\Public', to: 'C:\\Users\\Shared' })
      expect(err(parentRen.body).remote_code).toBe('blocked_path')
    } finally {
      pol.remote_access = before
    }
    // Overwriting an existing file is allowed here (unrestricted: upload and delete).
    const over = await handleMock('POST', `/devices/${id}/files/upload`, q({ ...ctx, path: `${docs}\\meeting notes.txt` }), new Blob(['new']))
    expect(over.status).toBe(200)
    const big = await handleMock('GET', `/devices/${id}/files/download`, q({ ...ctx, path: 'D:\\Backups\\laptop-image-2026-09.vhdx' }), undefined)
    expect(big.status).toBe(413)
    expect(db.audit.some((a) => a.action === 'remote.files.delete')).toBe(true)
  })

  it('enforces the effective profile: ceiling, policy, reason, MFA re-auth, consent, blocked paths', async () => {
    const hr = await find((d) => d.device.hostname.startsWith('HR-'))
    const np = await handleMock('GET', `/devices/${hr.device.id}/files`, q(), undefined)
    expect(np.status).toBe(403)
    expect(err(np.body).reason).toBe('not_permitted')

    const srv = await find((d) => d.device.hostname.startsWith('SRV-') && d.remote_access?.files.available === true)
    reauth.until = Date.now() + 600_000
    const ro = await handleMock('POST', `/devices/${srv.device.id}/files/mkdir`, q({ reason: 'x' }), { path: 'C:\\tmp\\x' })
    expect(ro.status).toBe(403)
    expect(err(ro.body).reason).toBe('disabled_by_policy')

    const g = await find((d) => d.remote_access?.effective_summary?.includes('employee consent') === true && d.remote_access.effective?.files === 'full' && d.remote_access.files.available)
    const id = g.device.id
    reauth.until = 0
    const noReason = await handleMock('GET', `/devices/${id}/files`, q(), undefined)
    expect(noReason.status).toBe(400)
    expect(err(noReason.body).reason).toBe('reason_required')
    const needMfa = await handleMock('GET', `/devices/${id}/files`, q({ reason: 'ticket 1' }), undefined)
    expect(needMfa.status).toBe(403)
    expect(err(needMfa.body).reason).toBe('reauth_required')
    const wrong = await handleMock('POST', '/me/reauth', q(), { totp: '12' })
    expect(wrong.status).toBe(400)
    expect(err(wrong.body).reason).toBe('invalid_totp')
    const ok = await handleMock('POST', '/me/reauth', q(), { totp: '123456' })
    expect((ok.body as { reauth_until: number }).reauth_until).toBeGreaterThan(Date.now())
    const ctx = { reason: 'ticket 1', fm_session: crypto.randomUUID() }
    expect((await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\' }), undefined)).status).toBe(200)
    const blocked = await handleMock('GET', `/devices/${id}/files`, q({ ...ctx, path: 'C:\\Windows\\System32\\config' }), undefined)
    expect(err(blocked.body).remote_code).toBe('blocked_path')
    const noDelete = await handleMock('POST', `/devices/${id}/files/delete`, q(ctx), { path: 'C:\\Windows\\Temp\\setup.log' })
    expect(err(noDelete.body).reason).toBe('disabled_by_policy')
    // overwriting an existing file needs delete permission too (guarded: allow_delete = false)
    const over = await handleMock('POST', `/devices/${id}/files/upload`, q({ ...ctx, path: 'C:\\Windows\\Temp\\setup.log' }), new Blob(['x']))
    expect(over.status).toBe(403)
    expect(err(over.body).reason).toBe('disabled_by_policy')
    // first change of the fm_session waits for the (simulated) employee consent, then succeeds
    const t0 = Date.now()
    const mk = await handleMock('POST', `/devices/${id}/files/mkdir`, q(ctx), { path: 'C:\\Windows\\Temp\\consented' })
    expect(mk.status).toBe(200)
    expect(Date.now() - t0).toBeGreaterThanOrEqual(1500)
    expect(db.audit.some((a) => a.action === 'remote.consent')).toBe(true)
  }, 15_000)

  it('creates enrollment tokens with a remote profile and a .cmd installer', async () => {
    const r = await handleMock('POST', '/enrollment-tokens', q(), {
      group_id: 'grp-it',
      expires_in_days: 7,
      max_uses: 5,
      remote_profile: { desktop: 'control', files: 'full', guardrails: { require_consent: false, require_reason: false, require_mfa_reauth: false, allow_delete: true, max_session_minutes: 0, idle_timeout_minutes: 0, blocked_paths: [] } },
    })
    const t = r.body as CreatedEnrollmentToken
    expect(t.remote_preset).toBe('unrestricted')
    expect(t.installer_filename).toBe('Install-Kestrel-unrestricted.cmd')
    expect(t.installer_cmd).toContain('\r\n')
    expect(t.installer_cmd).toContain(t.token)
    const list = (await handleMock('GET', '/enrollment-tokens', q(), undefined)).body as EnrollmentToken[]
    expect(list[0].remote_summary).toMatch(/no guardrails/)
    const invalid = await handleMock('POST', '/enrollment-tokens', q(), { group_id: 'grp-it', expires_in_days: 7, max_uses: 5, remote_profile: { desktop: 'control', files: 'full', guardrails: { blocked_paths: ['\\\\srv\\x'] } } })
    expect(invalid.status).toBe(400)
    // analysts can only create "no remote access" installers
    const analyst = db.users.find((u) => u.role === 'analyst' && !u.disabled)!
    db.session = analyst
    try {
      const denied = await handleMock('POST', '/enrollment-tokens', q(), { group_id: 'grp-it', expires_in_days: 7, max_uses: 5, remote_profile: { desktop: 'view_only', files: 'off' } })
      expect(denied.status).toBe(403)
      const none = await handleMock('POST', '/enrollment-tokens', q(), { group_id: 'grp-it', expires_in_days: 7, max_uses: 5 })
      expect((none.body as CreatedEnrollmentToken).remote_preset).toBe('none')
      expect((await handleMock('GET', `/devices/${db.devices[0].id}/files`, q(), undefined)).status).toBe(403)
    } finally {
      db.session = db.users[0]
    }
  })
})
