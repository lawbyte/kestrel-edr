import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiError, apiErrorFrom, extraOf, http, onUnauthorized } from './client'
import { invalidTotp, needsReauth } from './remote'

const realFetch = globalThis.fetch
afterEach(() => {
  globalThis.fetch = realFetch
})
const reply = (status: number, body: unknown) => (globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(body), { status })) as typeof fetch)

describe('API error details', () => {
  it('reads flattened server fields (error.reason) and a nested extra', () => {
    expect(extraOf({ code: 'forbidden', message: 'x', reason: 'reauth_required' })).toEqual({ reason: 'reauth_required' })
    expect(extraOf({ code: 'forbidden', message: 'x', extra: { reason: 'not_permitted' } })).toEqual({ reason: 'not_permitted' })
    expect(extraOf({ code: 'x', message: 'y', remote_code: 'busy' })).toBeUndefined()
    const e = apiErrorFrom(403, '{"error":{"code":"forbidden","message":"m","reason":"reauth_required"}}')
    expect(needsReauth(e)).toBe(true)
  })
  it('a wrong TOTP on /me/reauth is an error for the dialog, never a global logout', async () => {
    const logout = vi.fn()
    const off = onUnauthorized(logout)
    reply(400, { error: { code: 'bad_request', message: 'invalid code', reason: 'invalid_totp' } })
    const e1 = await http.post('/me/reauth', { totp: '000000' }).catch((e) => e)
    expect(e1).toBeInstanceOf(ApiError)
    expect(invalidTotp(e1)).toBe(true)
    reply(401, { error: { code: 'unauthorized', message: 'nope' } })
    const e2 = await http.post('/me/reauth', { totp: '111111' }).catch((e) => e)
    expect(invalidTotp(e2)).toBe(true)
    expect(logout).not.toHaveBeenCalled()
    reply(401, { error: { code: 'unauthorized', message: 'expired' } })
    await http.get('/devices').catch(() => {})
    expect(logout).toHaveBeenCalledTimes(1)
    off()
  })
})
