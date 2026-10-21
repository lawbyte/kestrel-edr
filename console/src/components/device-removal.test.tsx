import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { Device, DeviceDetail, MeResponse, Page } from '@/api/types'
import { AuthProvider } from '@/lib/auth'
import { ACTION_LABEL, ACTION_STATUS_LABEL, actionPrivilege, AUDIT_ACTION_LABEL, describeAction } from '@/lib/labels'
import { db, handleMock, mockFetch, mockOptions } from '@/mock/server'
import { reauth } from '@/mock/remote-state'
import DevicesPage from '@/pages/devices'
import DevicePage from '@/pages/device'
import { ReauthProvider } from './remote/reauth'
import { TooltipProvider } from './ui/misc'
import { AGENT_TOO_OLD_TEXT, RemovalBanner, RemoveDeviceDialog, RemoveDeviceRow, supportsRemoteRemoval } from './device-removal'

// Radix Checkbox measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const realFetch = globalThis.fetch
beforeAll(() => {
  mockOptions.latency = false
  db.session = db.users[0]
  globalThis.fetch = ((i: RequestInfo | URL, init?: RequestInit) => mockFetch(i, init)) as typeof fetch
})
afterAll(() => {
  globalThis.fetch = realFetch
})
beforeEach(() => {
  reauth.until = 0
})

const q = (s = '') => new URLSearchParams(s)

function wrap(ui: ReactNode, { privileges = ['*'], path = '/' }: { privileges?: string[]; path?: string } = {}) {
  const me: MeResponse = { user: db.users[0], csrf_token: 'csrf', privileges }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter initialEntries={[path]}>
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

/** An online device whose agent announces `agent.uninstall` and has no removal yet. */
function capableDevice(skip: string[] = []): Device {
  db.refreshDevices()
  const d = db.devices.find((x) => x.status === 'online' && supportsRemoteRemoval(x) && !x.removal && !skip.includes(x.hostname))
  if (!d) throw new Error('no capable device')
  return d
}
const oldDevice = () => db.devices.find((x) => !supportsRemoteRemoval(x))!
const removeBtn = () => screen.getByRole('button', { name: /^Remove device$/ })

describe('labels', () => {
  it('knows the uninstall action and the removal audit actions', () => {
    expect(ACTION_LABEL.uninstall_agent).toBeTruthy()
    expect(actionPrivilege({ type: 'uninstall_agent', purge_data: true })).toBe('devices.remove')
    expect(describeAction({ type: 'uninstall_agent', purge_data: true })).toMatch(/quarantine and logs/)
    expect(ACTION_STATUS_LABEL.running).toBe('Running')
    expect(ACTION_STATUS_LABEL.cancelled).toBe('Cancelled')
    for (const a of ['requested', 'started', 'completed', 'failed', 'cancelled', 'expired']) expect(AUDIT_ACTION_LABEL[`device.remove.${a}`]).toBeTruthy()
  })
})

describe('Remove device dialog', () => {
  it('enables the button only when the typed hostname matches (case-insensitive)', () => {
    const d = capableDevice()
    wrap(<RemoveDeviceDialog device={d} onClose={() => {}} />)
    expect(screen.getByText(/Kestrel will uninstall itself from this PC/)).toBeInTheDocument()
    expect(screen.getByText(/Decommission only removes the device from the console/)).toBeInTheDocument()
    const box = screen.getByRole('checkbox', { name: /Also delete quarantined files and logs on the PC/ })
    expect(box).toHaveAttribute('data-state', 'unchecked')
    expect(removeBtn()).toBeDisabled()
    const input = screen.getByLabelText(/to confirm/)
    fireEvent.change(input, { target: { value: `${d.hostname}x` } })
    expect(removeBtn()).toBeDisabled()
    fireEvent.change(input, { target: { value: `  ${d.hostname.toLowerCase()} ` } })
    expect(removeBtn()).toBeEnabled()
  })

  it('asks for the MFA code on reauth_required, then retries and queues the removal', async () => {
    const d = capableDevice()
    let closed = false
    wrap(<RemoveDeviceDialog device={d} onClose={() => (closed = true)} />)
    fireEvent.click(screen.getByRole('checkbox', { name: /Also delete quarantined files/ }))
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: d.hostname } })
    fireEvent.change(screen.getByLabelText(/Comment/), { target: { value: 'laptop returned' } })
    fireEvent.click(removeBtn())
    const code = await screen.findByLabelText('Authenticator code')
    expect(screen.getByText(/Removing a device uninstalls Kestrel from the PC/)).toBeInTheDocument()
    fireEvent.change(code, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }))
    await waitFor(() => expect(closed).toBe(true))
    expect(d.removal).toMatchObject({ state: 'pending', purge_data: true, requested_by: db.users[0].name })
    expect(db.actions.find((a) => a.id === d.removal!.action_id)?.action).toEqual({ type: 'uninstall_agent', purge_data: true })
    expect(db.audit.some((e) => e.action === 'device.remove.requested' && e.target === d.hostname)).toBe(true)
  })

  it('shows server refusals inline', async () => {
    const d = oldDevice()
    reauth.until = Date.now() + 600_000
    wrap(<RemoveDeviceDialog device={{ ...d, capabilities: ['agent.uninstall'] }} onClose={() => {}} />)
    fireEvent.change(screen.getByLabelText(/to confirm/), { target: { value: d.hostname } })
    fireEvent.click(removeBtn())
    expect(await screen.findByText(AGENT_TOO_OLD_TEXT)).toBeInTheDocument()
    expect(d.removal ?? null).toBeNull()
  })
})

describe('Danger zone row', () => {
  it('is disabled with an explanation when the agent lacks agent.uninstall', () => {
    const d = oldDevice()
    expect(d).toBeTruthy()
    wrap(<RemoveDeviceRow device={d} onOpen={() => {}} />)
    expect(removeBtn()).toBeDisabled()
    expect(screen.getByText(AGENT_TOO_OLD_TEXT)).toBeInTheDocument()
  })
  it('is enabled for a current agent', async () => {
    const d = capableDevice()
    wrap(<RemoveDeviceRow device={d} onOpen={() => {}} />)
    expect(removeBtn()).toBeEnabled()
  })
  it('device page: no Remove device without devices.remove', async () => {
    const d = capableDevice()
    wrap(
      <Routes>
        <Route path="/devices/:id" element={<DevicePage />} />
      </Routes>,
      { privileges: ['read', 'devices.write'], path: `/devices/${d.id}` },
    )
    expect(await screen.findByRole('button', { name: /Decommission device/ })).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Remove device$/ })).toBeNull()
  })
})

describe('removal states', () => {
  it('cancels a pending removal', async () => {
    const d = capableDevice()
    reauth.until = Date.now() + 600_000
    const res = await handleMock('POST', `/devices/${d.id}/remove`, q(), { purge_data: false, confirm_hostname: d.hostname })
    expect(res.status).toBe(200)
    wrap(<RemovalBanner device={structuredClone(d)} onRetry={() => {}} />)
    expect(screen.getByText('Removal pending')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Cancel removal/ }))
    const actionId = (res.body as { action: { id: string } }).action.id
    await waitFor(() => expect(d.removal).toBeNull())
    expect(db.actions.find((x) => x.id === actionId)).toMatchObject({ status: 'cancelled', result_detail: `cancelled by ${db.users[0].email}` })
    expect(db.audit.some((e) => e.action === 'device.remove.cancelled' && e.target === d.hostname)).toBe(true)
    const again = await handleMock('DELETE', `/devices/${d.id}/remove`, q(), undefined)
    expect(again.status).toBe(404)
    expect((again.body as { error: { reason: string } }).error.reason).toBe('no_pending_removal')
  })
  it('shows the failure text and Try again', () => {
    const d = { ...capableDevice(), removal: { state: 'failed' as const, action_id: 'a', requested_at: Date.now(), requested_by: 'Priya Raman', purge_data: false, started_at: Date.now(), removed_at: null, error: 'Windows Installer error 1603' } }
    let retried = false
    wrap(<RemovalBanner device={d} onRetry={() => (retried = true)} />)
    expect(screen.getByText('Windows Installer error 1603')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Try again/ }))
    expect(retried).toBe(true)
  })
  it('removed device page is read-only', async () => {
    const gone = db.removedDevices[0]
    wrap(
      <Routes>
        <Route path="/devices/:id" element={<DevicePage />} />
      </Routes>,
      { path: `/devices/${gone.id}` },
    )
    expect(await screen.findByText(/^Removed \(uninstalled remotely\) on .* by Priya Raman$/)).toBeInTheDocument()
    expect(screen.queryByRole('toolbar', { name: 'Device actions' })).toBeNull()
    expect(screen.queryByRole('button', { name: /Decommission device/ })).toBeNull()
    expect(screen.queryByRole('button', { name: /^Remove device$/ })).toBeNull()
  })
})

describe('devices list', () => {
  it('hides removed devices by default and shows them with the toggle', async () => {
    wrap(
      <Routes>
        <Route path="/devices" element={<DevicesPage />} />
      </Routes>,
      { path: '/devices' },
    )
    const pendingRow = (await screen.findByText('MKT-DT-001')).closest('tr')!
    expect(within(pendingRow).getByText('Removal pending')).toBeInTheDocument()
    expect(screen.queryByText('MKT-LT-014')).toBeNull()
    fireEvent.click(screen.getByRole('switch', { name: 'Show removed devices' }))
    const removedRow = (await screen.findByText('MKT-LT-014')).closest('tr')!
    expect(within(removedRow).getByText(/Removed \(uninstalled remotely\) on .* by Priya Raman/)).toBeInTheDocument()
  })
})

describe('mock API: POST /devices/:id/remove', () => {
  it('checks confirm, reauth, capability, duplicates and the rate limit in order', async () => {
    const post = (d: Device, confirm: string) => handleMock('POST', `/devices/${d.id}/remove`, q(), { purge_data: false, confirm_hostname: confirm })
    const reason = (r: { body: unknown }) => (r.body as { error: { reason?: string } }).error.reason
    const old = oldDevice()
    let r = await post(old, 'nope')
    expect([r.status, reason(r)]).toEqual([400, 'confirm_mismatch'])
    r = await post(old, old.hostname)
    expect([r.status, reason(r)]).toEqual([403, 'reauth_required'])
    reauth.until = Date.now() + 600_000
    r = await post(old, old.hostname)
    expect([r.status, reason(r)]).toEqual([409, 'agent_too_old'])
    const pending = db.devices.find((x) => x.removal?.state === 'pending')!
    r = await post(pending, pending.hostname)
    expect([r.status, reason(r)]).toEqual([409, 'removal_pending'])
    const list = (await handleMock('GET', '/devices', q(), undefined)).body as Page<Device>
    expect(list.items.some((x) => x.removal?.state === 'removed')).toBe(false)
    const all = (await handleMock('GET', '/devices', q('include_removed=true'), undefined)).body as Page<Device>
    expect(all.items.some((x) => x.hostname === 'MKT-LT-014')).toBe(true)
    const det = (await handleMock('GET', `/devices/${db.removedDevices[0].id}`, q(), undefined)).body as DeviceDetail
    expect(det.device.removal?.state).toBe('removed')
    // Rate limit: 20 per admin per hour (cancel each so the device can be asked again).
    const d = capableDevice()
    let last = 0
    for (let i = 0; i < 21; i++) {
      const x = await post(d, d.hostname)
      last = x.status
      if (x.status === 200) await handleMock('DELETE', `/devices/${d.id}/remove`, q(), undefined)
      else expect(reason(x)).toBe('rate_limited')
    }
    expect(last).toBe(429)
  })
})
