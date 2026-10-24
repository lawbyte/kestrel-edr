import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { useState, type ReactNode } from 'react'
import { MemoryRouter } from 'react-router'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import type { EvidenceBundle, EvidencePolicy, EvidenceStatus, MeResponse } from '@/api/types'
import { AuthProvider } from '@/lib/auth'
import { ADMIN_ONLY_TEXT, AGENT_TOO_OLD_EVIDENCE_TEXT, EVIDENCE_STATUS } from '@/lib/evidence'
import { ROLE_PRIVILEGES } from '@/lib/labels'
import { evidenceMockTiming, evidenceStore, seedEvidence } from '@/mock/evidence'
import { db, mockFetch, mockOptions } from '@/mock/server'
import { reauth } from '@/mock/remote-state'
import { PASSWORD_NOTE } from './evidence-dialogs'
import { EvidencePanel } from './evidence-panel'
import { EvidencePolicyEditor } from './evidence-policy-editor'
import { TooltipProvider } from './ui/misc'

globalThis.ResizeObserver ??= class {
  observe() {}
  unobserve() {}
  disconnect() {}
} as unknown as typeof ResizeObserver

const realFetch = globalThis.fetch
beforeAll(() => {
  mockOptions.latency = false
  evidenceMockTiming.uploadMs = 5
  db.session = db.users.find((u) => u.role === 'admin') ?? db.users[0]
  globalThis.fetch = ((i: RequestInfo | URL, init?: RequestInit) => mockFetch(i, init)) as typeof fetch
})
afterAll(() => {
  globalThis.fetch = realFetch
})
beforeEach(() => {
  // Fresh bundles in every status for each test.
  evidenceStore.bundles = seedEvidence(db)
  // A fresh MFA confirmation, so only the step-up tests see the code dialog.
  reauth.until = Date.now() + 600_000
  db.session!.mfa_enabled = true
})

function wrap(ui: ReactNode, privileges = ['*']) {
  const me: MeResponse = { user: db.users[0], csrf_token: 'csrf', privileges }
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <AuthProvider me={me}>
          <TooltipProvider>{ui}</TooltipProvider>
        </AuthProvider>
      </QueryClientProvider>
    </MemoryRouter>,
  )
}

const bundles = () => evidenceStore.bundles!
const byStatus = (s: EvidenceStatus, pred: (b: EvidenceBundle) => boolean = () => true) => bundles().find((b) => b.status === s && pred(b))!
describe('EvidencePanel', () => {
  it('covers every status across the mock incidents, newest first', async () => {
    const seen = new Set<EvidenceStatus>()
    for (const id of new Set(bundles().map((b) => b.incident_id!))) {
      const v = wrap(<EvidencePanel incidentId={id} />)
      await screen.findByText('Evidence capture')
      for (const b of bundles().filter((x) => x.incident_id === id)) {
        expect(screen.getAllByText(EVIDENCE_STATUS[b.status].label).length).toBeGreaterThan(0)
        seen.add(b.status)
      }
      v.unmount()
    }
    expect([...seen].sort()).toEqual(['capturing', 'collecting', 'deleted', 'expired', 'failed', 'ready_on_device', 'stored'])
  })

  it('renders nothing for an incident without bundles', async () => {
    const other = db.incidents.find((i) => !bundles().some((b) => b.incident_id === i.id))!
    const { container } = wrap(<EvidencePanel incidentId={other.id} />)
    await waitFor(() => expect(container.textContent).toBe(''))
  })

  it('shows the per-state texts and actions', async () => {
    const stored = byStatus('stored')
    wrap(<EvidencePanel incidentId={stored.incident_id!} />)
    expect(await screen.findByText(/^Ready to download\. Stored encrypted/)).toBeInTheDocument()
    expect(screen.getByText(/Deleted from the server on/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Download$/ })).toBeEnabled()
    expect(screen.getAllByRole('button', { name: /Delete evidence/ })[0]).toBeEnabled()
    expect(screen.getByText(/^Deleted by .* on /)).toBeInTheDocument()
  })

  it('shows capturing with no actions, failed with the error, and the failed upload retry', async () => {
    const cap = byStatus('capturing')
    const v = wrap(<EvidencePanel incidentId={cap.incident_id!} />)
    expect(await screen.findByText(/^Capturing: copying staged files and recording connections for 60 s after the alert/)).toBeInTheDocument()
    v.unmount()
    const failed = byStatus('failed')
    const v2 = wrap(<EvidencePanel incidentId={failed.incident_id!} />)
    expect(await screen.findByText(/^Capture failed: could not create the bundle file/)).toBeInTheDocument()
    v2.unmount()
    const retry = byStatus('ready_on_device', (b) => !!b.last_error)
    wrap(<EvidencePanel incidentId={retry.incident_id!} />)
    expect(await screen.findByText(/The last upload did not finish/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Try again/ })).toBeEnabled()
  })

  it('analysts see the metadata but no usable Collect / Download / Delete', async () => {
    const analyst = ROLE_PRIVILEGES.analyst
    const stored = byStatus('stored')
    const v = wrap(<EvidencePanel incidentId={stored.incident_id!} />, analyst)
    const dl = await screen.findByRole('button', { name: /^Download$/ })
    expect(dl).toBeDisabled()
    expect(screen.getAllByLabelText(ADMIN_ONLY_TEXT).length).toBeGreaterThan(0)
    for (const b of screen.getAllByRole('button', { name: /Delete evidence/ })) expect(b).toBeDisabled()
    // Metadata is still there.
    fireEvent.click(screen.getAllByRole('button', { expanded: false })[0])
    expect(await screen.findByText('Secrets it read', { selector: 'h3' })).toBeInTheDocument()
    v.unmount()
    const ready = byStatus('ready_on_device', (b) => !b.last_error)
    wrap(<EvidencePanel incidentId={ready.incident_id!} />, ['read'])
    expect(await screen.findByRole('button', { name: /Collect evidence/ })).toBeDisabled()
  })

  it('expands a stored bundle: secrets, staged files, capture and processes', async () => {
    const stored = byStatus('stored')
    stored.manifest!.staged![0].path = 'C:\\Users\\x\\AppData\\Local\\Temp\\invoice\u202Etxt.exe'
    wrap(<EvidencePanel incidentId={stored.incident_id!} />)
    const toggles = await screen.findAllByRole('button', { expanded: false })
    fireEvent.click(toggles[0])
    const secrets = screen.getByRole('region', { name: 'Secrets it read' })
    expect(within(secrets).getAllByText('Locked by the app, not copied').length).toBeGreaterThan(0)
    expect(within(secrets).getAllByText('Copied').length).toBeGreaterThan(0)
    const staged = screen.getByRole('region', { name: 'Staged files' })
    expect(within(staged).getByText('Link / junction / hard link — not followed')).toBeInTheDocument()
    expect(within(staged).getByText(/Too large/)).toBeInTheDocument()
    expect(within(staged).getByText('C:\\Users\\x\\AppData\\Local\\Temp\\invoicetxt.exe')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('\u202E')
    const cap = screen.getByRole('region', { name: 'Connection capture' })
    expect(within(cap).getByText('185.208.158.114:443/tcp')).toBeInTheDocument()
    expect(within(cap).getByText('Encrypted traffic (HTTPS/TLS, VPN) stays encrypted in the capture.')).toBeInTheDocument()
    expect(within(cap).getByText(/other apps talking to the same address \(for example a CDN\) can appear too/)).toBeInTheDocument()
    expect(within(cap).getByText('Loopback traffic is not captured.')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Processes in the capture' })).toHaveTextContent('Alerting process')
  })

  it('asks before collecting, explains what is uploaded, then queues the upload', async () => {
    const b = byStatus('ready_on_device', (x) => !x.last_error)
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /Collect evidence/ }))
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText(/real saved passwords, cookies and session tokens/)).toBeInTheDocument()
    expect(within(dlg).getByText(/IT collected evidence from this PC for a security investigation/)).toBeInTheDocument()
    expect(within(dlg).getByText(/Every step is audited/)).toBeInTheDocument()
    fireEvent.click(within(dlg).getByRole('button', { name: /Collect evidence/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    // Queued (collecting), then the online mock PC uploads it.
    expect(b.collect_requested_by).toBe(db.session!.name)
    expect(db.audit.some((e) => e.action === 'evidence.collect_requested' && (e.details as Record<string, unknown> | null)?.bundle_id === b.id)).toBe(true)
    await waitFor(() => expect(b.status).toBe('stored'))
  })

  it('disables Collect for an old agent and says why', async () => {
    const b = byStatus('ready_on_device', (x) => !x.last_error)
    b.agent_supports_evidence = false
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    expect(await screen.findByRole('button', { name: /Collect evidence/ })).toBeDisabled()
    expect(screen.getByText(AGENT_TOO_OLD_EVIDENCE_TEXT)).toBeInTheDocument()
  })

  it('shows the download password once and forgets it on close', async () => {
    const b = byStatus('stored')
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /^Download$/ }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /Create download/ }))
    await screen.findByLabelText('Archive password')
    const dlg = screen.getByRole('dialog')
    const pw = within(dlg).getByLabelText('Archive password').textContent!
    expect(pw).toMatch(/^[A-Za-z0-9]{24}$/)
    expect(within(dlg).getByText(PASSWORD_NOTE)).toBeInTheDocument()
    expect(within(dlg).getByRole('button', { name: 'Copy password' })).toBeInTheDocument()
    const link = within(dlg).getByRole('link', { name: /Download kestrel-evidence-/ })
    expect(link).toHaveAttribute('download', expect.stringMatching(/\.zip$/))
    expect(link.getAttribute('href')).toMatch(/^data:/)
    expect(db.audit.some((e) => e.action === 'evidence.download_started' && (e.details as Record<string, unknown> | null)?.bundle_id === b.id)).toBe(true)
    fireEvent.click(within(dlg).getByRole('button', { name: /Close and forget the password/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(document.body.textContent).not.toContain(pw)
  })

  it('deletes after confirmation', async () => {
    const b = byStatus('stored')
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    const li = (await screen.findByText(/^Ready to download\. Stored/)).closest('li')!
    fireEvent.click(within(li).getByRole('button', { name: /Delete evidence/ }))
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByText(/This cannot be undone/)).toBeInTheDocument()
    fireEvent.click(within(dlg).getByRole('button', { name: /Delete evidence/ }))
    await waitFor(() => expect(b.status).toBe('deleted'))
    expect(b.deleted_by).toBe(db.session!.name)
  })
})

const auditFor = (action: string, b: EvidenceBundle) => db.audit.find((e) => e.action === action && (e.details as Record<string, unknown> | null)?.bundle_id === b.id)

describe('MFA step-up and audit reason', () => {
  it('asks for an authenticator code on reauth_required, then retries the collect', async () => {
    reauth.until = 0
    const b = byStatus('ready_on_device', (x) => !x.last_error)
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /Collect evidence/ }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /Collect evidence/ }))
    const code = await screen.findByLabelText('Authenticator code')
    expect(screen.getByText(/Collecting, downloading and deleting evidence needs a fresh authenticator code/)).toBeInTheDocument()
    expect(auditFor('evidence.collect_requested', b)).toBeUndefined()
    fireEvent.change(code, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }))
    await waitFor(() => expect(auditFor('evidence.collect_requested', b)).toBeTruthy())
    expect(reauth.until).toBeGreaterThan(Date.now())
  })

  it('asks for a code before creating a download, then shows the password', async () => {
    reauth.until = 0
    const b = byStatus('stored')
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /^Download$/ }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /Create download/ }))
    fireEvent.change(await screen.findByLabelText('Authenticator code'), { target: { value: '654321' } })
    fireEvent.click(screen.getByRole('button', { name: /Confirm/ }))
    expect(await screen.findByLabelText('Archive password')).toHaveTextContent(/^[A-Za-z0-9]{24}$/)
  })

  it('does not ask admins without MFA', async () => {
    reauth.until = 0
    db.session!.mfa_enabled = false
    const b = byStatus('ready_on_device', (x) => !x.last_error)
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /Collect evidence/ }))
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: /Collect evidence/ }))
    await waitFor(() => expect(auditFor('evidence.collect_requested', b)).toBeTruthy())
    expect(screen.queryByLabelText('Authenticator code')).toBeNull()
  })

  it('sends the optional reason to the audit log (collect, download, delete), at most 200 characters', async () => {
    const ready = byStatus('ready_on_device', (x) => !x.last_error)
    const v = wrap(<EvidencePanel incidentId={ready.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /Collect evidence/ }))
    const input = await screen.findByLabelText(/Reason \(recorded in the audit log\)/)
    expect(input).toHaveAttribute('maxLength', '200')
    fireEvent.change(input, { target: { value: 'x'.repeat(250) } })
    expect((input as HTMLInputElement).value).toHaveLength(200)
    fireEvent.change(input, { target: { value: '  INC-2291 legal hold  ' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Collect evidence/ }))
    await waitFor(() => expect(auditFor('evidence.collect_requested', ready)?.details).toMatchObject({ reason: 'INC-2291 legal hold' }))
    v.unmount()

    const stored = byStatus('stored')
    wrap(<EvidencePanel incidentId={stored.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /^Download$/ }))
    fireEvent.change(await screen.findByLabelText(/Reason \(recorded/), { target: { value: 'for HR' } })
    fireEvent.click(screen.getByRole('button', { name: /Create download/ }))
    await screen.findByLabelText('Archive password')
    expect(auditFor('evidence.download_started', stored)?.details).toMatchObject({ reason: 'for HR' })
    fireEvent.click(screen.getByRole('button', { name: /Close and forget the password/ }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())

    const li = screen.getByText(/^Ready to download\. Stored/).closest('li')!
    fireEvent.click(within(li).getByRole('button', { name: /Delete evidence/ }))
    fireEvent.change(await screen.findByLabelText(/Reason \(recorded/), { target: { value: 'case closed' } })
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Delete evidence/ }))
    await waitFor(() => expect(auditFor('evidence.deleted', stored)?.details).toMatchObject({ reason: 'case closed' }))
  })

  it('shows "no longer stored" when the bundle went away before the download', async () => {
    const b = byStatus('stored')
    wrap(<EvidencePanel incidentId={b.incident_id!} />)
    fireEvent.click(await screen.findByRole('button', { name: /^Download$/ }))
    const dlg = await screen.findByRole('dialog')
    b.status = 'expired'
    fireEvent.click(within(dlg).getByRole('button', { name: /Create download/ }))
    expect(await screen.findByText('This evidence is no longer stored. The page has been refreshed.')).toBeInTheDocument()
    expect(screen.queryByLabelText('Archive password')).toBeNull()
  })
})

function PolicyHarness({ initial }: { initial?: EvidencePolicy }) {
  const [v, setV] = useState<EvidencePolicy | undefined>(initial)
  return (
    <>
      <EvidencePolicyEditor value={v} onChange={setV} readOnly={false} />
      <output data-testid="json">{JSON.stringify(v ?? null)}</output>
    </>
  )
}

describe('EvidencePolicyEditor', () => {
  const sw = (name: RegExp) => screen.getByRole('switch', { name })
  it('shows the defaults (all on, 14 days) for a policy without the field', () => {
    wrap(<PolicyHarness />)
    for (const n of [/Copies of staged files/, /List of secrets it read/, /Copies of the secrets it read/, /Connection capture/]) expect(sw(n)).toHaveAttribute('data-state', 'checked')
    expect(screen.getByLabelText(/Keep uncollected bundles on the PC/)).toHaveValue(14)
    expect(screen.getByTestId('json').textContent).toBe('null')
  })
  it('turns copies of secrets off with the list, and warns when everything is off', () => {
    wrap(<PolicyHarness />)
    fireEvent.click(sw(/List of secrets it read/))
    expect(sw(/Copies of the secrets it read/)).toHaveAttribute('data-state', 'unchecked')
    expect(sw(/Copies of the secrets it read/)).toBeDisabled()
    expect(JSON.parse(screen.getByTestId('json').textContent!)).toMatchObject({ secrets_list: false, secrets_copy: false, staged_files: true })
    fireEvent.click(sw(/Copies of staged files/))
    fireEvent.click(sw(/Connection capture/))
    expect(screen.getByTestId('ev-off')).toHaveTextContent(/Evidence capture is off for this policy/)
  })
  it('keeps the PC retention between 1 and 365 days', () => {
    wrap(<PolicyHarness />)
    const input = screen.getByLabelText(/Keep uncollected bundles on the PC/)
    fireEvent.change(input, { target: { value: '900' } })
    expect(JSON.parse(screen.getByTestId('json').textContent!).local_retention_days).toBe(365)
    fireEvent.change(input, { target: { value: '30' } })
    expect(JSON.parse(screen.getByTestId('json').textContent!).local_retention_days).toBe(30)
  })
})
