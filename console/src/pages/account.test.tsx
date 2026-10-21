import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { ApiError } from '@/api/client'
import { api, qk } from '@/api/endpoints'
import type { MeResponse, User } from '@/api/types'
import { TooltipProvider } from '@/components/ui/misc'
import { ReauthProvider, useReauth } from '@/components/remote/reauth'
import { AuthProvider, useAuth } from '@/lib/auth'
import { cleanTotp, groupSecret, mfaErrorText, otpauthLabel } from '@/lib/mfa'
import { db, handleMock, mfa, mockFetch, mockOptions } from '@/mock/server'
import AccountPage from './account'
import { DecommissionDialog } from './device'

const realFetch = globalThis.fetch
beforeAll(() => {
  mockOptions.latency = false
  globalThis.fetch = ((i: RequestInfo | URL, init?: RequestInit) => mockFetch(i, init)) as typeof fetch
})
afterAll(() => {
  globalThis.fetch = realFetch
})

const weiling = () => db.users.find((u) => u.email.startsWith('weiling'))!

function Where() {
  return <span data-testid="where">{useLocation().pathname}</span>
}

/** Renders `ui` with a live `me` taken from the query cache (like the real Gate). */
function wrap(ui: ReactNode, me: MeResponse, path = '/account') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  qc.setQueryData(qk.me, me)
  function LiveAuth({ children }: { children: ReactNode }) {
    const cur = useQuery({ queryKey: qk.me, queryFn: api.me, initialData: me, staleTime: Infinity })
    return <AuthProvider me={cur.data}>{children}</AuthProvider>
  }
  const r = render(
    <MemoryRouter initialEntries={[path]}>
      <QueryClientProvider client={qc}>
        <LiveAuth>
          <TooltipProvider>
            <Routes>
              <Route path="/account" element={ui} />
              <Route path="/devices/:id" element={ui} />
              <Route path="/devices" element={<Where />} />
            </Routes>
          </TooltipProvider>
        </LiveAuth>
      </QueryClientProvider>
    </MemoryRouter>,
  )
  return { ...r, qc }
}

describe('lib/mfa helpers', () => {
  it('formats the setup key and the typed code', () => {
    expect(groupSecret('JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')).toBe('JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP')
    expect(cleanTotp(' 12a3-45 67 ')).toBe('123456')
  })
  it('reads issuer and account from an otpauth URI', () => {
    expect(otpauthLabel('otpauth://totp/Kestrel:priya%40corp.sg?secret=ABC&issuer=Kestrel')).toEqual({ issuer: 'Kestrel', account: 'priya@corp.sg' })
    expect(otpauthLabel('not a uri')).toEqual({ issuer: null, account: null })
  })
  it('explains wrong codes, rate limits and policy refusals', () => {
    expect(mfaErrorText(new ApiError(400, 'bad_request', 'invalid TOTP code'), 'enable')).toMatch(/didn’t work/)
    expect(mfaErrorText(new ApiError(400, 'bad_request', 'x', undefined, { reason: 'invalid_totp' }), 'enable')).toMatch(/didn’t work/)
    expect(mfaErrorText(new ApiError(400, 'bad_request', 'call /api/me/mfa/setup first'), 'enable')).toMatch(/Start again/)
    expect(mfaErrorText(new ApiError(429, 'rate_limited', 'slow', undefined, { retry_after_ms: 4200 }), 'enable')).toBe('Too many attempts. Wait 5 seconds and try again.')
    expect(mfaErrorText(new ApiError(403, 'forbidden', 'MFA is required by policy'), 'disable')).toMatch(/requires two-factor/)
    expect(mfaErrorText(new ApiError(403, 'forbidden', 'password is wrong'), 'disable')).toBe('That password is wrong.')
    expect(mfaErrorText(new ApiError(409, 'conflict', 'MFA already enabled'), 'setup')).toMatch(/already on/)
  })
})

describe('account page: two-factor setup', () => {
  beforeEach(() => {
    const u = weiling()
    u.mfa_enabled = false
    db.session = u
    mfa.pending.clear()
    mfa.lockedUntil = 0
    mfa.wrong = 0
  })

  it('shows status Off, then the QR code and key, rejects a wrong code and turns MFA on', async () => {
    const u = weiling()
    const { qc } = wrap(<AccountPage />, { user: { ...u }, csrf_token: 'c', privileges: ['read'] })
    expect(screen.getByText('Off')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Set up two-factor authentication/ }))
    const qr = await screen.findByTestId('qr-code')
    expect(qr).toHaveAttribute('alt', expect.stringMatching(/QR code/))
    expect(qr.getAttribute('src')).toMatch(/^data:image\/svg\+xml/)
    const secret = mfa.pending.get(u.id)!
    expect(screen.getByTestId('mfa-secret').textContent).toBe(groupSecret(secret))

    const input = screen.getByLabelText('6-digit code')
    fireEvent.change(input, { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: /Turn on/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/didn’t work/)
    expect(u.mfa_enabled).toBe(false)

    fireEvent.change(input, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Turn on/ }))
    expect(await screen.findByText(/Two-factor authentication is on\./)).toBeInTheDocument()
    expect(u.mfa_enabled).toBe(true)
    await waitFor(() => expect(qc.getQueryData<MeResponse>(qk.me)?.user.mfa_enabled).toBe(true))
  })

  it('asks for a 6-digit code before calling the server and shows the rate limit', async () => {
    wrap(<AccountPage />, { user: { ...weiling() }, csrf_token: 'c', privileges: ['read'] })
    fireEvent.click(screen.getByRole('button', { name: /Set up two-factor authentication/ }))
    const input = await screen.findByLabelText('6-digit code')
    fireEvent.click(screen.getByRole('button', { name: /Turn on/ }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Enter the 6-digit code')
    mfa.lockedUntil = Date.now() + 9_000
    fireEvent.change(input, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Turn on/ }))
    expect(await screen.findByText(/Too many attempts\. Wait \d+ seconds/)).toBeInTheDocument()
    expect(weiling().mfa_enabled).toBe(false)
  })

  it('turns MFA off with the password (refused while the organisation requires it)', async () => {
    const u = weiling()
    u.mfa_enabled = true
    const before = db.settings.require_mfa
    db.settings.require_mfa = true
    try {
      wrap(<AccountPage />, { user: { ...u }, csrf_token: 'c', privileges: ['read'] })
      expect(screen.getByText('On')).toBeInTheDocument()
      fireEvent.click(screen.getByRole('button', { name: /Turn off two-factor authentication/ }))
      const pw = await screen.findByLabelText('Current password')
      fireEvent.change(pw, { target: { value: 'hunter2hunter2' } })
      fireEvent.click(screen.getByRole('button', { name: /^Turn off$/ }))
      expect(await screen.findByText(/requires two-factor authentication, so it can’t be turned off/)).toBeInTheDocument()
      db.settings.require_mfa = false
      fireEvent.change(pw, { target: { value: 'wrong' } })
      fireEvent.click(screen.getByRole('button', { name: /^Turn off$/ }))
      expect(await screen.findByText('That password is wrong.')).toBeInTheDocument()
      fireEvent.change(pw, { target: { value: 'hunter2hunter2' } })
      fireEvent.click(screen.getByRole('button', { name: /^Turn off$/ }))
      await waitFor(() => expect(u.mfa_enabled).toBe(false))
      expect(await screen.findByRole('button', { name: /Set up two-factor authentication/ })).toBeInTheDocument()
    } finally {
      db.settings.require_mfa = before
    }
  })

  it('explains a setup-only session (require_mfa) and the mock blocks everything else', async () => {
    const before = db.settings.require_mfa
    db.settings.require_mfa = true
    try {
      const login = await handleMock('POST', '/auth/login', new URLSearchParams(), { email: weiling().email, password: 'x' })
      expect(login.status).toBe(200)
      const me = (await handleMock('GET', '/me', new URLSearchParams(), undefined)).body as MeResponse
      expect(me.mfa_setup_required).toBe(true)
      expect(me.privileges).toEqual([])
      const blocked = await handleMock('GET', '/devices', new URLSearchParams(), undefined)
      expect(blocked.status).toBe(403)
      expect((blocked.body as { error: { mfa_setup_required?: boolean } }).error.mfa_setup_required).toBe(true)
      wrap(<AccountPage />, me)
      expect(screen.getByText('Your organisation requires two-factor authentication')).toBeInTheDocument()
      // Finishing the setup lifts the restriction.
      await handleMock('POST', '/me/mfa/setup', new URLSearchParams(), {})
      await handleMock('POST', '/me/mfa/enable', new URLSearchParams(), { totp: '654321' })
      expect(((await handleMock('GET', '/me', new URLSearchParams(), undefined)).body as MeResponse).mfa_setup_required).toBeUndefined()
      expect((await handleMock('GET', '/devices', new URLSearchParams(), undefined)).status).toBe(200)
    } finally {
      db.settings.require_mfa = before
      mfa.setupOnly = false
    }
  })
})

describe('remote-access re-auth links to the MFA setup', () => {
  it('offers the account page when the admin has no authenticator', async () => {
    const u: User = { ...weiling(), mfa_enabled: false }
    function Ask() {
      const { ask } = useReauth()
      useAuth()
      return (
        <button type="button" onClick={() => void ask()}>
          ask
        </button>
      )
    }
    wrap(
      <ReauthProvider>
        <Ask />
      </ReauthProvider>,
      { user: u, csrf_token: 'c', privileges: ['*'] },
    )
    fireEvent.click(screen.getByRole('button', { name: 'ask' }))
    const link = await screen.findByRole('link', { name: /Set up two-factor authentication/ })
    expect(link).toHaveAttribute('href', '/account#mfa')
  })
})

describe('decommission device', () => {
  it('needs the hostname typed, calls DELETE and returns to Devices', async () => {
    const admin = db.users[0]
    db.session = admin
    const d = db.devices[db.devices.length - 1]
    wrap(<DecommissionDialog deviceId={d.id} hostname={d.hostname} onClose={() => {}} />, { user: admin, csrf_token: 'c', privileges: ['*'] }, `/devices/${d.id}`)
    expect(screen.getByText(/Revokes the device’s certificate and drops its connection/)).toBeInTheDocument()
    expect(screen.getByText(/The agent stays installed/)).toBeInTheDocument()
    expect(screen.getByText(/History is kept/)).toBeInTheDocument()
    const confirm = screen.getByRole('button', { name: /^Decommission$/ })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: d.hostname.toLowerCase() } })
    expect(confirm).toBeEnabled()
    fireEvent.click(confirm)
    await waitFor(() => expect(screen.getByTestId('where')).toHaveTextContent('/devices'))
    expect(db.devices.some((x) => x.id === d.id)).toBe(false)
  })

  it('the mock enforces devices.write like the server', async () => {
    db.session = weiling() // read-only role
    const d = db.devices[0]
    const r = await handleMock('DELETE', `/devices/${d.id}`, new URLSearchParams(), undefined)
    expect(r.status).toBe(403)
    expect(db.devices.some((x) => x.id === d.id)).toBe(true)
  })
})
