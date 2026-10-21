import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import type { MeResponse, RemoteAccessInfo, RemoteAccessProfile } from '@/api/types'
import { AuthProvider } from '@/lib/auth'
import { visibleRemoteTabs } from '@/lib/remote-tabs'
import { profileGuarded, profileUnrestricted } from '@/lib/remote-profile'
import { db, mockFetch, mockOptions } from '@/mock/server'
import { remoteAccessFor } from '@/mock/remote-state'
import { TooltipProvider } from '../ui/misc'
import { InstallAgentWizard, canChooseRemote, nextAfterChoice } from '../install-wizard'
import { FileManager } from './file-manager'
import { RemoteDesktop } from './remote-desktop'
import { ReauthProvider, useReauth } from './reauth'
import { RemoteProfileEditor } from './profile-editor'

const realFetch = globalThis.fetch
beforeAll(() => {
  mockOptions.latency = false
  db.session = db.users[0]
  globalThis.fetch = ((i: RequestInfo | URL, init?: RequestInit) => mockFetch(i, init)) as typeof fetch
})
afterAll(() => {
  globalThis.fetch = realFetch
})

function wrap(ui: ReactNode, privileges: string[] = ['*']) {
  const me: MeResponse = { user: db.users[0], csrf_token: 'csrf', privileges }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AuthProvider me={me}>
          <TooltipProvider>
            <ReauthProvider>{ui}</ReauthProvider>
          </TooltipProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

/** An online engineering device: unrestricted ceiling ∩ unrestricted policy. */
function engDevice() {
  for (const d of db.devices) {
    const pol = db.policies.find((p) => p.id === d.policy_id)!
    if (d.group_id === 'grp-eng' && remoteAccessFor(d, pol).files.available) return d
  }
  throw new Error('no eng device')
}
const can = (privs: string[]) => (p: string) => privs.includes('*') || privs.includes(p)
const info = { desktop: { available: true, reason: null }, files: { available: true, reason: null } } as RemoteAccessInfo

describe('remote tab visibility', () => {
  it('shows the tabs only with the privilege and a server that reports remote access', () => {
    expect(visibleRemoteTabs(can(['*']), info)).toEqual({ desktop: true, files: true })
    expect(visibleRemoteTabs(can(['remote.files']), info)).toEqual({ desktop: false, files: true })
    expect(visibleRemoteTabs(can(['read', 'response.process']), info)).toEqual({ desktop: false, files: false })
    expect(visibleRemoteTabs(can(['*']), undefined)).toEqual({ desktop: false, files: false })
  })
})

describe('FileManager permission-driven controls', () => {
  const fm = (effective: RemoteAccessProfile) => {
    const d = engDevice()
    return wrap(<FileManager deviceId={d.id} hostname={d.hostname} availability={{ available: true, reason: null }} policyId={d.policy_id} effective={effective} />)
  }
  it('full access: Upload and New folder, plus per-row actions', async () => {
    fm(profileUnrestricted())
    await screen.findByText('C:\\')
    expect(screen.getByRole('button', { name: /Upload/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /New folder/ })).toBeInTheDocument()
    fireEvent.click(screen.getByText('C:\\'))
    expect(await screen.findByText('Users')).toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /More actions for/ }).length).toBeGreaterThan(0)
  })
  it('read only: no upload, new folder, rename or delete', async () => {
    fm({ ...profileUnrestricted(), files: 'read_only' })
    await screen.findByText('C:\\')
    expect(screen.queryByRole('button', { name: /Upload/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /New folder/ })).toBeNull()
    fireEvent.click(screen.getByText('C:\\'))
    await screen.findByText('Users')
    expect(screen.queryAllByRole('button', { name: /More actions for/ })).toHaveLength(0)
    expect(screen.getByText(/Read only: browse and download/)).toBeInTheDocument()
  })
  it('guarded: upload allowed, delete/rename hidden, reason asked first', async () => {
    const g = profileGuarded()
    g.guardrails.require_mfa_reauth = false
    g.guardrails.require_consent = false
    fm(g)
    expect(screen.getByText(/requires a reason/)).toBeInTheDocument()
    const open = screen.getByRole('button', { name: 'Open file manager' })
    expect(open).toBeDisabled()
    fireEvent.change(screen.getByLabelText('Reason'), { target: { value: 'ticket 7' } })
    fireEvent.click(open)
    await screen.findByText('C:\\')
    expect(screen.getByRole('button', { name: /Upload/ })).toBeInTheDocument()
    expect(screen.getByText(/Reason: “ticket 7”/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('C:\\'))
    await screen.findByText('Users')
    expect(screen.queryAllByRole('button', { name: /More actions for/ })).toHaveLength(0)
  })
  it('shows a plain reason when not permitted by the install profile', () => {
    const d = engDevice()
    wrap(<FileManager deviceId={d.id} hostname={d.hostname} availability={{ available: false, reason: 'not_permitted' }} policyId={d.policy_id} effective={profileUnrestricted()} />)
    expect(screen.getByText(/install profile/)).toBeInTheDocument()
  })
})

describe('RemoteDesktop guardrail states', () => {
  it('forces view-only and requires a reason', () => {
    const d = engDevice()
    const eff = { ...profileGuarded(), desktop: 'view_only' as const }
    wrap(<RemoteDesktop deviceId={d.id} hostname={d.hostname} availability={{ available: true, reason: null }} policyId={d.policy_id} effective={eff} />)
    const sw = screen.getByRole('switch', { name: 'View only' })
    expect(sw).toBeDisabled()
    expect(sw).toHaveAttribute('data-state', 'checked')
    expect(screen.getByText(/allows viewing only/)).toBeInTheDocument()
    expect(screen.getByText(/The employee sees a banner and a notification while you are connected/)).toBeInTheDocument()
    const connect = screen.getByRole('button', { name: /Connect/ })
    expect(connect).toBeDisabled()
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: 'ticket 9' } })
    expect(connect).toBeEnabled()
  })
})

describe('installer wizard', () => {
  it('flow helpers', () => {
    expect(nextAfterChoice('guarded', false)).toBe(2)
    expect(nextAfterChoice('unrestricted', false)).toBe(3)
    expect(nextAfterChoice('unrestricted', true)).toBe(2)
    expect(nextAfterChoice('none', true)).toBe(3)
    expect(canChooseRemote(can(['*']))).toBe(true)
    expect(canChooseRemote(can(['remote.desktop']))).toBe(false)
  })
  it('admin: profile → guardrails → token → installer download', async () => {
    wrap(<InstallAgentWizard onClose={() => {}} groups={db.groups} />)
    const radios = screen.getAllByRole('radio')
    expect(radios).toHaveLength(3)
    expect(radios.every((r) => !(r as HTMLButtonElement).disabled)).toBe(true)
    expect(screen.getByRole('radio', { name: /with guardrails/ })).toHaveAttribute('aria-checked', 'true')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByText(/Prefilled with the recommended guardrails/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: /Employee must allow/ })).toHaveAttribute('data-state', 'checked')
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    expect(await screen.findByLabelText('Group')).toBeInTheDocument()
    expect(screen.getByText(/employee consent, reason, MFA re-auth/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Create installer' }))
    expect(await screen.findByRole('button', { name: /Download Install-Kestrel-guarded\.cmd/ })).toBeInTheDocument()
    expect(screen.getByText(/Shown once/)).toBeInTheDocument()
    expect(screen.getByText(/PowerShell one-liner/)).toBeInTheDocument()
  })
  it('non-admin: only "No remote access", straight to token settings', async () => {
    wrap(<InstallAgentWizard onClose={() => {}} groups={db.groups} />, ['read', 'devices.write'])
    expect(screen.getByRole('radio', { name: /No remote access/ })).toHaveAttribute('aria-checked', 'true')
    expect(screen.getByRole('radio', { name: /no guardrails/ })).toBeDisabled()
    expect(screen.getByRole('radio', { name: /with guardrails/ })).toBeDisabled()
    expect(screen.getAllByText(/Admins only/)).toHaveLength(2)
    expect(screen.queryByRole('button', { name: /Customise/ })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByLabelText('Group')).toBeInTheDocument())
    expect(screen.getAllByText('No remote access').length).toBeGreaterThan(0)
  })
})

describe('MFA step-up dialog', () => {
  function Asker() {
    const { ask } = useReauth()
    return (
      <button type="button" onClick={() => void ask()}>
        ask
      </button>
    )
  }
  it('says the code did not work on invalid_totp and stays open', async () => {
    wrap(<Asker />)
    fireEvent.click(screen.getByRole('button', { name: 'ask' }))
    fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }))
    expect(await screen.findByText(/That code didn’t work/)).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})

describe('profile editor', () => {
  it('warns that a Full file manager is administrator-equivalent', () => {
    wrap(<RemoteProfileEditor value={profileGuarded()} onChange={() => {}} />)
    expect(screen.getByText(/treat Full as equivalent to administrator access/)).toBeInTheDocument()
    expect(screen.getByText(/replace an existing file/)).toBeInTheDocument()
  })
})
