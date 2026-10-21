import { fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LOCAL_PAUSE_DEFAULTS, offeredPauseMinutes, type Dashboard, type DeviceDetail, type LocalPause, type Page, type Device, type AlertRow, type AuditEntry, type PauseState } from '@/api/types'
import { DeviceStatusBadge } from './badges'
import { ProtectionOffBanner, ProtectionOffNote } from './protection-off'
import { LocalPauseEditor, localPauseOf } from './local-pause-editor'
import { TooltipProvider } from './ui/misc'
import { localPauseSummary, pauseHeadline, pauseUntilLabel, reconcilePause } from '@/lib/pause'
import { ACTION_LABEL, actionPrivilege, AUDIT_ACTION_LABEL, DEVICE_STATUS_LABEL, describeAction, formatMinutes } from '@/lib/labels'
import { db, handleMock } from '@/mock/server'

vi.mock('@/lib/auth', () => ({ useAuth: () => ({ me: { user: { id: 'u' }, privileges: ['*'] }, can: () => true }) }))

const at = (h: number, m: number, dayOffset = 0) => new Date(2026, 9, 21 + dayOffset, h, m).getTime()
const NOW = at(12, 0)

describe('pause text', () => {
  it('formats the detection-only headline with today’s time and the user', () => {
    const p: PauseState = { mode: 'detection_only', since_ms: at(10, 30), until_ms: at(14, 30), by_user: 'W-FIN-07\\nadia' }
    expect(pauseHeadline(p, NOW)).toBe('Protection off (detection only) until 14:30, turned off on the PC by W-FIN-07\\nadia')
  })
  it('formats completely off until turned back on', () => {
    const p: PauseState = { mode: 'full', since_ms: at(10, 30), until_ms: null, by_user: 'HARBOURLINE\\tech' }
    expect(pauseHeadline(p, NOW)).toBe('Protection completely off until turned back on, turned off on the PC by HARBOURLINE\\tech')
  })
  it('shows the date when the turn-on is not today, and drops an empty user', () => {
    expect(pauseUntilLabel(at(1, 15, 1), NOW)).toMatch(/22 Oct 2026/)
    const p: PauseState = { mode: 'detection_only', since_ms: at(10, 0), until_ms: at(13, 0), by_user: '' }
    expect(pauseHeadline(p, NOW)).toBe('Protection off (detection only) until 13:00, turned off on the PC')
  })
  it('strips control and bidi characters from the endpoint-supplied user', () => {
    const p: PauseState = { mode: 'detection_only', since_ms: 0, until_ms: null, by_user: 'W\\eve‮gnp.exe' }
    expect(pauseHeadline(p, NOW)).not.toContain('‮')
  })
  it('formats durations', () => {
    expect([15, 60, 90, 240, 480, 1440].map(formatMinutes)).toEqual(['15 min', '1 h', '1 h 30 min', '4 h', '8 h', '1 d'])
  })
})

describe('local_pause policy helpers (mirror kestrel-common)', () => {
  it('offers the standard steps capped by max_minutes', () => {
    const p = (m: number): LocalPause => ({ ...LOCAL_PAUSE_DEFAULTS, max_minutes: m })
    expect(offeredPauseMinutes(LOCAL_PAUSE_DEFAULTS)).toEqual([15, 60, 240, 480])
    expect(offeredPauseMinutes(p(60))).toEqual([15, 60])
    expect(offeredPauseMinutes(p(30))).toEqual([15, 30])
    expect(offeredPauseMinutes(p(5))).toEqual([5])
    expect(offeredPauseMinutes(p(1000))).toEqual([15, 60, 240, 480])
    expect(offeredPauseMinutes({ ...LOCAL_PAUSE_DEFAULTS, enabled: false })).toEqual([])
  })
  it('fills defaults for old policies', () => {
    expect(localPauseOf(undefined)).toEqual({ enabled: true, allow_full: false, max_minutes: 480, allow_until_resumed: false })
    expect(localPauseOf({ allow_full: true }).allow_full).toBe(true)
    expect(localPauseSummary(LOCAL_PAUSE_DEFAULTS)).toBe('Allowed with the uninstall token: detection only, up to 8 h')
    expect(localPauseSummary({ ...LOCAL_PAUSE_DEFAULTS, enabled: false })).toBe('Not allowed')
  })
  it('reconciles an active pause with a new policy', () => {
    const s: PauseState = { mode: 'detection_only', since_ms: 0, until_ms: 480 * 60_000, by_user: 'W\\e' }
    expect(reconcilePause(LOCAL_PAUSE_DEFAULTS, s, 1000)).toEqual(s)
    expect(reconcilePause({ ...LOCAL_PAUSE_DEFAULTS, max_minutes: 60 }, s, 10 * 60_000)?.until_ms).toBe(70 * 60_000)
    expect(reconcilePause({ ...LOCAL_PAUSE_DEFAULTS, enabled: false }, s, 0)).toBeNull()
    expect(reconcilePause(LOCAL_PAUSE_DEFAULTS, { ...s, mode: 'full' }, 0)).toBeNull()
    expect(reconcilePause(LOCAL_PAUSE_DEFAULTS, { ...s, until_ms: null }, 5)?.until_ms).toBe(5 + 480 * 60_000)
    expect(reconcilePause(LOCAL_PAUSE_DEFAULTS, s, 480 * 60_000)).toBeNull()
  })
})

describe('labels', () => {
  it('labels the paused status, the action and the audit actions', () => {
    expect(DEVICE_STATUS_LABEL.paused).toBe('Protection off')
    expect(ACTION_LABEL.resume_protection).toBe('Turn protection back on')
    expect(actionPrivilege({ type: 'resume_protection' })).toBe('response.collect')
    expect(describeAction({ type: 'resume_protection' })).toMatch(/Turn protection back on/)
    for (const a of ['device.protection_off', 'device.protection_on', 'device.protection_off_denied', 'device.protection_off_clamped']) expect(AUDIT_ACTION_LABEL[a]).toBeTruthy()
  })
  it('renders the paused badge with an icon and a text label', () => {
    const { container } = render(<DeviceStatusBadge status="paused" />)
    expect(screen.getByText('Protection off')).toBeInTheDocument()
    expect(container.querySelector('svg')).not.toBeNull()
  })
})

describe('ProtectionOffBanner', () => {
  it('renders nothing without a pause', () => {
    const { container } = render(<ProtectionOffBanner device={{ pause: null }} onPick={() => {}} />)
    expect(container).toBeEmptyDOMElement()
  })
  it('shows the headline, explains the mode and picks resume_protection', () => {
    const onPick = vi.fn()
    render(
      <TooltipProvider>
        <ProtectionOffBanner device={{ pause: { mode: 'full', since_ms: Date.now() - 60_000, until_ms: null, by_user: 'W\\tech' } }} onPick={onPick} />
      </TooltipProvider>,
    )
    expect(screen.getByText(/Protection completely off until turned back on/)).toBeInTheDocument()
    expect(screen.getByText(/Sensors are stopped/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: /Turn protection back on/ }))
    expect(onPick).toHaveBeenCalledWith(expect.objectContaining({ action: { type: 'resume_protection' } }))
  })
  it('alert note says no automatic action was taken', () => {
    render(<ProtectionOffNote mode="detection_only" />)
    expect(screen.getByText('Protection was turned off on this PC (detection only): no automatic action was taken.')).toBeInTheDocument()
  })
})

describe('LocalPauseEditor', () => {
  it('shows defaults and disables the sub-settings when the switch is off', () => {
    const onChange = vi.fn()
    const { rerender } = render(<LocalPauseEditor value={undefined} onChange={onChange} readOnly={false} />)
    expect(screen.getByRole('switch', { name: /Allow turning protection off/ })).toBeChecked()
    expect(screen.getByRole('switch', { name: /completely off/ })).not.toBeChecked()
    expect(screen.getByLabelText('Longest turn-off')).toHaveValue('480')
    expect(screen.getByTestId('lp-offered')).toHaveTextContent('15 min, 1 h, 4 h, 8 h')
    fireEvent.click(screen.getByRole('switch', { name: /Allow turning protection off/ }))
    expect(onChange).toHaveBeenCalledWith({ ...LOCAL_PAUSE_DEFAULTS, enabled: false })
    rerender(<LocalPauseEditor value={{ ...LOCAL_PAUSE_DEFAULTS, enabled: false }} onChange={onChange} readOnly={false} />)
    expect(screen.getByRole('switch', { name: /completely off/ })).toBeDisabled()
    expect(screen.getByRole('switch', { name: /until turned back on/ })).toBeDisabled()
    expect(screen.getByLabelText('Longest turn-off')).toBeDisabled()
  })
  it('changes the longest turn-off and warns about risky options', () => {
    const onChange = vi.fn()
    render(<LocalPauseEditor value={{ ...LOCAL_PAUSE_DEFAULTS, allow_full: true }} onChange={onChange} readOnly={false} />)
    fireEvent.change(screen.getByLabelText('Longest turn-off'), { target: { value: '60' } })
    expect(onChange).toHaveBeenCalledWith({ ...LOCAL_PAUSE_DEFAULTS, allow_full: true, max_minutes: 60 })
    expect(screen.getByText(/can now stop the sensors/)).toBeInTheDocument()
  })
  it('is read-only for viewers', () => {
    render(<LocalPauseEditor value={LOCAL_PAUSE_DEFAULTS} onChange={() => {}} readOnly />)
    expect(screen.getByRole('switch', { name: /Allow turning protection off/ })).toBeDisabled()
  })
})

describe('mock: protection turned off', () => {
  afterEach(() => vi.useRealTimers())
  const q = (s = '') => new URLSearchParams(s)
  it('seeds a paused device, its TP-06 alert and a status filter', async () => {
    db.session = db.users[0]
    const page = (await handleMock('GET', '/devices', q('status=paused'), undefined)).body as Page<Device>
    expect(page.items.map((d) => d.hostname)).toEqual(['MKT-LT-008'])
    const d = page.items[0]
    expect(d.status).toBe('paused')
    expect(d.pause?.mode).toBe('detection_only')
    expect(d.pause?.until_ms).toBeGreaterThan(Date.now())
    const dash = (await handleMock('GET', '/dashboard', q(), undefined)).body as Dashboard
    expect(dash.devices.paused).toBe(1)
    const alerts = (await handleMock('GET', '/alerts', q('limit=500'), undefined)).body as Page<AlertRow>
    const mine = alerts.items.filter((a) => a.device_id === d.id)
    expect(mine.some((a) => a.rule_id === 'TP-06' && a.severity === 'medium' && a.mode === 'audit')).toBe(true)
    expect(mine.some((a) => a.protection_off === 'detection_only' && a.mode === 'audit')).toBe(true)
    const pol = db.policies.find((p) => p.id === 'pol-default')!
    expect(pol.local_pause).toEqual(LOCAL_PAUSE_DEFAULTS)
  })
  it('resume_protection ends the pause and writes the audit log', async () => {
    db.session = db.users[0]
    const dev = db.devices.find((d) => d.hostname === 'MKT-LT-008')!
    vi.useFakeTimers({ toFake: ['setTimeout'] })
    const sent = handleMock('POST', `/devices/${dev.id}/actions`, q(), { action: { type: 'resume_protection' }, comment: 'install approved, back on' })
    await vi.runAllTimersAsync()
    await sent
    await vi.runAllTimersAsync()
    vi.useRealTimers()
    const det = (await handleMock('GET', `/devices/${dev.id}`, q(), undefined)).body as DeviceDetail
    expect(det.device.pause ?? null).toBeNull()
    expect(det.device.status).not.toBe('paused')
    const audit = (await handleMock('GET', '/audit-log', q('action=device.protection&limit=200'), undefined)).body as Page<AuditEntry>
    const acts = audit.items.map((e) => e.action)
    expect(acts).toContain('device.protection_on')
    expect(acts).toContain('device.protection_off')
    expect(audit.items.find((e) => e.action === 'device.protection_on')?.details).toMatchObject({ reason: 'console', hostname: 'MKT-LT-008' })
  })
})
