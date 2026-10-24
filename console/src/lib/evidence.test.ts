import { describe, expect, it } from 'vitest'
import { ApiError } from '@/api/client'
import { EVIDENCE_POLICY_DEFAULTS, type EvidenceBundle, type EvidenceStatus } from '@/api/types'
import {
  ADMIN_ONLY_TEXT,
  AGENT_TOO_OLD_EVIDENCE_TEXT,
  bundleActions,
  captureOff,
  copyStatusOf,
  countdown,
  EVIDENCE_STATUS,
  evidenceErrorText,
  evidencePolicyOf,
  evidenceRetentionOf,
  formatPcapFilter,
  manifestSummary,
  PCAP_LIMITATIONS,
  PCAP_STATUS,
  retentionText,
  safeDownloadUrl,
  statusDescription,
} from './evidence'
import { formatBytes } from './format'

const DAY = 86_400_000
const NOW = Date.UTC(2026, 9, 25, 8, 0)

function bundle(p: Partial<EvidenceBundle> = {}): EvidenceBundle {
  return {
    id: '11111111-2222-4333-8444-555555555555',
    device_id: 'd',
    hostname: 'FIN-LT-004',
    incident_id: 'i',
    alert_id: 'a',
    alert_ids: ['a'],
    rule_id: 'ST-04',
    status: 'ready_on_device',
    created_at: NOW - DAY,
    captured_at: NOW - DAY + 62_000,
    manifest: null,
    bundle_size: 61 * 1024 * 1024,
    bundle_sha256: null,
    local_expires_at: NOW + 13 * DAY,
    collect_requested_at: null,
    collect_requested_by: null,
    collected_at: null,
    expires_at: null,
    deleted_at: null,
    deleted_by: null,
    last_error: null,
    downloads: 0,
    last_downloaded_at: null,
    device_online: true,
    agent_supports_evidence: true,
    ...p,
  }
}

describe('status', () => {
  it('has an icon and a label for every status', () => {
    const all: EvidenceStatus[] = ['capturing', 'ready_on_device', 'collecting', 'stored', 'failed', 'expired', 'deleted']
    for (const s of all) {
      expect(EVIDENCE_STATUS[s].label).toBeTruthy()
      expect(EVIDENCE_STATUS[s].icon).toBeTruthy()
      expect(statusDescription(bundle({ status: s }))).toBeTruthy()
    }
  })

  it('describes each state in plain words', () => {
    expect(statusDescription(bundle({ status: 'capturing' }))).toMatch(/^Capturing: copying staged files and recording connections for 60 s after the alert/)
    expect(statusDescription(bundle({ status: 'ready_on_device' }))).toMatch(/^Ready on the PC — not uploaded/)
    expect(statusDescription(bundle({ status: 'collecting', device_online: false }))).toMatch(/queued until the PC is online/)
    expect(statusDescription(bundle({ status: 'collecting', device_online: true, collect_requested_by: 'Priya' }))).toMatch(/uploading.*Requested by Priya/)
    expect(statusDescription(bundle({ status: 'stored' }))).toMatch(/^Ready to download/)
    expect(statusDescription(bundle({ status: 'expired' }))).toMatch(/^Expired: deleted after the retention period/)
    expect(statusDescription(bundle({ status: 'failed', last_error: 'disk full' }))).toBe('Capture failed: disk full.')
    expect(statusDescription(bundle({ status: 'deleted', deleted_by: 'Marcus‮evil', deleted_at: NOW }))).toMatch(/^Deleted by Marcusevil on /)
  })

  it('shows the retention countdown for the PC or the server copy', () => {
    expect(retentionText(bundle(), NOW)).toMatch(/^Deleted from the PC on .* \(in 13 days\)$/)
    expect(retentionText(bundle({ status: 'stored', expires_at: NOW + 3 * 3_600_000 }), NOW)).toMatch(/^Deleted from the server on .* \(in 3 hours\)$/)
    expect(retentionText(bundle({ status: 'deleted' }), NOW)).toBeNull()
    expect(countdown(NOW - 1, NOW)).toBe('due now')
    expect(countdown(NOW + DAY, NOW)).toBe('in 1 day')
  })
})

describe('actions', () => {
  it('offers collect only on the PC, download only when stored, delete while something is left', () => {
    const a = (s: EvidenceStatus) => bundleActions(bundle({ status: s }), true)
    expect(a('ready_on_device')).toMatchObject({ collect: { visible: true, disabledReason: null, retry: false }, download: { visible: false }, remove: { visible: true } })
    expect(a('stored')).toMatchObject({ collect: { visible: false }, download: { visible: true, disabledReason: null }, remove: { visible: true } })
    expect(a('collecting')).toMatchObject({ collect: { visible: false }, download: { visible: false }, remove: { visible: true } })
    for (const s of ['capturing', 'failed', 'expired', 'deleted'] as const) expect(a(s)).toMatchObject({ collect: { visible: false }, download: { visible: false }, remove: { visible: false } })
  })

  it('disables everything for non-admins with the reason', () => {
    const a = bundleActions(bundle({ status: 'stored' }), false)
    expect(a.download.disabledReason).toBe(ADMIN_ONLY_TEXT)
    expect(a.remove.disabledReason).toBe(ADMIN_ONLY_TEXT)
    expect(bundleActions(bundle(), false).collect.disabledReason).toBe(ADMIN_ONLY_TEXT)
  })

  it('explains an old agent, offline PCs and a failed upload', () => {
    expect(bundleActions(bundle({ agent_supports_evidence: false }), true).collect.disabledReason).toBe(AGENT_TOO_OLD_EVIDENCE_TEXT)
    const off = bundleActions(bundle({ device_online: false }), true).collect
    expect(off.disabledReason).toBeNull()
    expect(off.queuedNote).toMatch(/queued until it is online/)
    expect(bundleActions(bundle({ last_error: 'x' }), true).collect.retry).toBe(true)
  })

  it('maps server refusals to plain text', () => {
    expect(evidenceErrorText(new ApiError(409, 'conflict', 'too old', undefined, { reason: 'agent_too_old' }))).toBe(AGENT_TOO_OLD_EVIDENCE_TEXT)
    expect(evidenceErrorText(new ApiError(403, 'forbidden', 'no'))).toMatch(/API tokens cannot/)
    expect(evidenceErrorText(new Error('boom'))).toBe('boom')
    expect(evidenceErrorText(new ApiError(409, 'conflict', 'this evidence is no longer stored', undefined, { reason: 'not_ready' }))).toBe('This evidence is no longer stored. The page has been refreshed.')
    expect(evidenceErrorText(new ApiError(400, 'bad_request', 'reason must be at most 200 characters'))).toMatch(/200 characters/)
  })
})

describe('manifest', () => {
  it('labels copy statuses in plain language', () => {
    expect(copyStatusOf({ status: 'link' }).label).toBe('Link / junction / hard link — not followed')
    expect(copyStatusOf({ status: 'kestrel' }).label).toBe('Kestrel’s own file — skipped')
    expect(copyStatusOf({ status: 'locked' }).label).toBe('Locked by the app, not copied')
    expect(copyStatusOf({ status: 'too_large' }).label).toMatch(/Too large/)
    expect(copyStatusOf({ status: 'bundle_full' }).label).toMatch(/bundle reached its size limit/)
    expect(copyStatusOf(null).label).toMatch(/Listed only/)
    expect(copyStatusOf({ status: 'error', detail: 'access‮denied' }).detail).toBe('accessdenied')
  })

  it('formats capture filters as ip:port/proto', () => {
    expect(formatPcapFilter({ ip: '185.208.158.114', port: 443, proto: 'tcp' })).toBe('185.208.158.114:443/tcp')
    expect(formatPcapFilter({ ip: '2001:db8::1', port: 53, proto: 'udp' })).toBe('[2001:db8::1]:53/udp')
    expect(formatPcapFilter({ ip: '10.0.0.1' })).toBe('10.0.0.1:any/any')
    expect(PCAP_LIMITATIONS).toHaveLength(3)
    expect(PCAP_STATUS.busy.label).toMatch(/pktmon/)
  })

  it('summarises counts and sizes', () => {
    const b = bundle({
      manifest: {
        bundle_id: 'b',
        alert_id: 'a',
        rule_id: 'ST-04',
        started_at: 0,
        window_start: 0,
        window_end: 0,
        completed_at: 0,
        parts: EVIDENCE_POLICY_DEFAULTS,
        pcap: { status: 'captured', bytes: 2048 },
        totals: { staged_listed: 9, staged_copied: 6, staged_bytes: 4 * 1024 * 1024, staged_unlisted: 3, secrets_listed: 5, secrets_copied: 4, secret_bytes: 1024 },
      },
    })
    expect(manifestSummary(b, formatBytes)).toEqual({ staged: '9 listed, 6 copied (4.0 MB), 3 more not listed', secrets: '5 listed, 4 copied (1.0 KB)', pcap: 'Captured (2.0 KB)' })
    const off = bundle({ manifest: { ...b.manifest!, parts: { ...EVIDENCE_POLICY_DEFAULTS, secrets_copy: false, pcap: false } } })
    expect(manifestSummary(off, formatBytes)).toMatchObject({ secrets: '5 listed, copies turned off', pcap: 'Turned off in the policy' })
    expect(manifestSummary(bundle(), formatBytes)).toBeNull()
  })
})

describe('policy', () => {
  it('fills in the defaults for policies saved before the field', () => {
    expect(evidencePolicyOf(undefined)).toEqual(EVIDENCE_POLICY_DEFAULTS)
    expect(evidencePolicyOf({ pcap: false })).toEqual({ ...EVIDENCE_POLICY_DEFAULTS, pcap: false })
  })
  it('turns copies off with the list, and treats all-off as capture off', () => {
    expect(evidencePolicyOf({ secrets_list: false, secrets_copy: true }).secrets_copy).toBe(false)
    expect(captureOff(evidencePolicyOf({ staged_files: false, secrets_list: false, pcap: false }))).toBe(true)
    expect(captureOff(EVIDENCE_POLICY_DEFAULTS)).toBe(false)
  })
  it('defaults the server retention to 14 days', () => {
    expect(evidenceRetentionOf({})).toBe(14)
    expect(evidenceRetentionOf({ evidence: 30 })).toBe(30)
  })
})

describe('download link', () => {
  const o = 'https://kestrel.example.com'
  it('follows only same-origin links (data:/blob: in mock mode only)', () => {
    expect(safeDownloadUrl('/api/evidence/downloads/abc', false, o)).toBe('/api/evidence/downloads/abc')
    expect(safeDownloadUrl('https://kestrel.example.com/api/x?y=1', false, o)).toBe('/api/x?y=1')
    expect(safeDownloadUrl('https://evil.example/x', false, o)).toBeNull()
    expect(safeDownloadUrl('//evil.example/x', false, o)).toBeNull()
    expect(safeDownloadUrl('javascript:alert(1)', false, o)).toBeNull()
    expect(safeDownloadUrl('data:application/octet-stream;base64,AA==', false, o)).toBeNull()
    expect(safeDownloadUrl('data:application/octet-stream;base64,AA==', true, o)).toMatch(/^data:/)
  })
})
