import { Archive, Check, CircleSlash, Clock, HardDrive, Loader2, Lock, Scissors, Trash2, TimerOff, UploadCloud, XCircle, type LucideIcon } from 'lucide-react'
import { ApiError } from '@/api/client'
import {
  EVIDENCE_POLICY_DEFAULTS,
  EVIDENCE_RETENTION_DEFAULT_DAYS,
  type CopyStatus,
  type EvidenceBundle,
  type EvidencePolicy,
  type EvidenceStatus,
  type FileCopy,
  type PcapFilter,
  type PcapStatus,
  type ProcessRole,
  type WriteOp,
} from '@/api/types'
import { formatDateTime, safeDisplay } from './format'

/** Privilege for collecting, downloading and deleting evidence (admins, via `*`; console session only). */
export const EVIDENCE_PRIVILEGE = 'evidence.download'
export const ADMIN_ONLY_TEXT = 'Administrators only'
export const AGENT_TOO_OLD_EVIDENCE_TEXT = 'The agent on this PC is too old to upload evidence. Update the agent first; the bundle stays on the PC until its retention ends.'

export type Tone = 'accent' | 'ok' | 'warn' | 'danger' | 'muted'
export const TONE_CLASS: Record<Tone, string> = {
  accent: 'text-accent-text',
  ok: 'text-ok',
  warn: 'text-warn',
  danger: 'text-danger',
  muted: 'text-fg-muted',
}

// ---------------------------------------------------------------- status

export const EVIDENCE_STATUS: Record<EvidenceStatus, { label: string; icon: LucideIcon; tone: Tone; spin?: boolean }> = {
  capturing: { label: 'Capturing', icon: Loader2, tone: 'accent', spin: true },
  ready_on_device: { label: 'On the PC', icon: HardDrive, tone: 'accent' },
  collecting: { label: 'Collecting', icon: UploadCloud, tone: 'accent' },
  stored: { label: 'Ready to download', icon: Archive, tone: 'ok' },
  failed: { label: 'Capture failed', icon: XCircle, tone: 'danger' },
  expired: { label: 'Expired', icon: TimerOff, tone: 'muted' },
  deleted: { label: 'Deleted', icon: Trash2, tone: 'muted' },
}

/** One plain sentence describing where the bundle is and what can happen next. */
export function statusDescription(b: Pick<EvidenceBundle, 'status' | 'device_online' | 'last_error' | 'deleted_by' | 'deleted_at' | 'collect_requested_by' | 'collect_requested_at'>): string {
  switch (b.status) {
    case 'capturing':
      return 'Capturing: copying staged files and recording connections for 60 s after the alert.'
    case 'ready_on_device':
      return 'Ready on the PC — not uploaded. It is kept there, encrypted, until someone collects it or its retention ends.'
    case 'collecting': {
      const who = b.collect_requested_by ? ` Requested by ${safeDisplay(b.collect_requested_by)}${b.collect_requested_at ? ` on ${formatDateTime(b.collect_requested_at)}` : ''}.` : ''
      return (b.device_online ? 'Collecting: uploading from the PC.' : 'Collecting: queued until the PC is online.') + who
    }
    case 'stored':
      return 'Ready to download. Stored encrypted on the server.'
    case 'expired':
      return 'Expired: deleted after the retention period. The list of what it contained and the audit trail are kept.'
    case 'failed':
      return `Capture failed: ${safeDisplay(b.last_error) || 'the PC gave no details'}.`
    case 'deleted':
      return `Deleted${b.deleted_by ? ` by ${safeDisplay(b.deleted_by)}` : ''}${b.deleted_at ? ` on ${formatDateTime(b.deleted_at)}` : ''}. The list of what it contained and the audit trail are kept.`
  }
}

const DAY = 86_400_000

/** "in 12 days", "in 5 hours", "today", "overdue". */
export function countdown(at: number, now = Date.now()): string {
  const d = at - now
  if (d <= 0) return 'due now'
  if (d < DAY) {
    const h = Math.max(1, Math.round(d / 3_600_000))
    return `in ${h} hour${h === 1 ? '' : 's'}`
  }
  const days = Math.round(d / DAY)
  return `in ${days} day${days === 1 ? '' : 's'}`
}

/** Retention line for the bundle header, or null when nothing is pending deletion. */
export function retentionText(b: Pick<EvidenceBundle, 'status' | 'local_expires_at' | 'expires_at'>, now = Date.now()): string | null {
  switch (b.status) {
    case 'capturing':
    case 'ready_on_device':
    case 'collecting':
      return b.local_expires_at ? `Deleted from the PC on ${formatDateTime(b.local_expires_at)} (${countdown(b.local_expires_at, now)})` : null
    case 'stored':
      return b.expires_at ? `Deleted from the server on ${formatDateTime(b.expires_at)} (${countdown(b.expires_at, now)})` : null
    default:
      return null
  }
}

export interface ActionState {
  /** Shown at all for this status. */
  visible: boolean
  /** Why it is disabled (shown as a tooltip / note), or null when it can be used. */
  disabledReason: string | null
}
export interface BundleActions {
  collect: ActionState & { retry: boolean; queuedNote: string | null }
  download: ActionState
  remove: ActionState
}

/** Which buttons a bundle shows, and why they are disabled. */
export function bundleActions(b: Pick<EvidenceBundle, 'status' | 'agent_supports_evidence' | 'device_online' | 'last_error'>, canManage: boolean): BundleActions {
  const admin = canManage ? null : ADMIN_ONLY_TEXT
  const collectVisible = b.status === 'ready_on_device'
  return {
    collect: {
      visible: collectVisible,
      disabledReason: admin ?? (collectVisible && !b.agent_supports_evidence ? AGENT_TOO_OLD_EVIDENCE_TEXT : null),
      retry: collectVisible && !!b.last_error,
      queuedNote: collectVisible && !b.device_online ? 'The PC is offline: the request is queued until it is online.' : null,
    },
    download: { visible: b.status === 'stored', disabledReason: admin },
    remove: { visible: b.status === 'stored' || b.status === 'ready_on_device' || b.status === 'collecting', disabledReason: admin },
  }
}

/** Text for a failed collect / download / delete request. */
export function evidenceErrorText(e: unknown): string {
  if (!(e instanceof ApiError)) return (e as Error)?.message ?? 'Something went wrong.'
  if (e.extra?.reason === 'agent_too_old') return AGENT_TOO_OLD_EVIDENCE_TEXT
  if (e.extra?.reason === 'not_ready') return `${capitalise(e.message || 'the bundle is not ready for this')}. The page has been refreshed.`
  if (e.extra?.reason === 'reauth_required') return 'This needs a fresh authenticator code. Try again and enter the code when asked.'
  if (e.status === 400 && /reason/i.test(e.message)) return 'The reason is too long: keep it to 200 characters.'
  if (e.status === 403) return 'Only administrators signed in to the console can do this. API tokens cannot collect, download or delete evidence.'
  if (e.status === 409) return `${e.message || 'The bundle changed in the meantime'}. The page has been refreshed.`
  return e.message
}

const capitalise = (s: string) => s.charAt(0).toUpperCase() + s.slice(1).replace(/\.$/, '')

/** Longest audit reason the server accepts for collect / download / delete. */
export const EVIDENCE_REASON_MAX = 200
/** Text for the MFA step-up dialog. */
export const EVIDENCE_REAUTH_WHY = 'Collecting, downloading and deleting evidence needs a fresh authenticator code, because the bundle can hold the employee’s real passwords. One confirmation is valid for 10 minutes.'

// ---------------------------------------------------------------- manifest

export const COPY_STATUS: Record<CopyStatus, { label: string; icon: LucideIcon; tone: Tone }> = {
  copied: { label: 'Copied', icon: Check, tone: 'ok' },
  truncated: { label: 'Copied in part (cut at the size limit)', icon: Scissors, tone: 'warn' },
  too_large: { label: 'Too large — not copied', icon: CircleSlash, tone: 'muted' },
  bundle_full: { label: 'Not copied — the bundle reached its size limit', icon: CircleSlash, tone: 'muted' },
  link: { label: 'Link / junction / hard link — not followed', icon: CircleSlash, tone: 'muted' },
  locked: { label: 'Locked by the app, not copied', icon: Lock, tone: 'muted' },
  missing: { label: 'Gone before the copy was taken', icon: CircleSlash, tone: 'muted' },
  kestrel: { label: 'Kestrel’s own file — skipped', icon: CircleSlash, tone: 'muted' },
  not_a_file: { label: 'Not a regular file — skipped', icon: CircleSlash, tone: 'muted' },
  error: { label: 'Could not be copied', icon: XCircle, tone: 'danger' },
  disabled: { label: 'Listed only (copies turned off)', icon: Clock, tone: 'muted' },
}

/** Copy status of a staged file or secret; `null`/absent = list only (copies turned off). */
export function copyStatusOf(c: FileCopy | null | undefined): { label: string; icon: LucideIcon; tone: Tone; detail: string | null } {
  if (!c) return { ...COPY_STATUS.disabled, detail: null }
  const s = COPY_STATUS[c.status] ?? COPY_STATUS.error
  return { ...s, detail: c.detail ? safeDisplay(c.detail) : null }
}

export const WRITE_OP_LABEL: Record<WriteOp, string> = {
  created: 'Created',
  overwritten: 'Overwritten',
  renamed: 'Renamed into place',
  written: 'Written',
}

export const PROCESS_ROLE_LABEL: Record<ProcessRole, string> = {
  alerting: 'Alerting process',
  descendant: 'Started by it',
  ancestor: 'Started it (loader)',
}

export const PCAP_STATUS: Record<PcapStatus, { label: string; tone: Tone }> = {
  captured: { label: 'Captured', tone: 'ok' },
  stopped: { label: 'Stopped early: the capture ended before the 60 s were up', tone: 'warn' },
  no_connections: { label: 'Nothing to capture: the processes opened no network connections', tone: 'muted' },
  busy: { label: 'Not captured: another packet capture (pktmon) was already running on the PC', tone: 'muted' },
  unsupported: { label: 'Not captured: needs Windows 10 version 2004 or later', tone: 'muted' },
  failed: { label: 'Capture failed', tone: 'danger' },
  disabled: { label: 'Turned off in the policy', tone: 'muted' },
}

/** Fixed limitation notes shown with every connection capture. */
export const PCAP_LIMITATIONS = [
  'Encrypted traffic (HTTPS/TLS, VPN) stays encrypted in the capture.',
  'The filter matches the remote address and port, so other apps talking to the same address (for example a CDN) can appear too.',
  'Loopback traffic is not captured.',
] as const

/** `ip:port/proto` (IPv6 in brackets); missing port or protocol shown as "any". */
export function formatPcapFilter(f: PcapFilter): string {
  const ip = safeDisplay(f.ip)
  const host = ip.includes(':') ? `[${ip}]` : ip
  return `${host}:${f.port ?? 'any'}/${f.proto ?? 'any'}`
}

export interface ManifestSummary {
  staged: string
  secrets: string
  pcap: string
}

/** One-line counts for the three parts ("12 listed, 10 copied (8.4 MB)"). */
export function manifestSummary(b: Pick<EvidenceBundle, 'manifest'>, fmtBytes: (n: number) => string): ManifestSummary | null {
  const m = b.manifest
  if (!m) return null
  const t = m.totals ?? {}
  const stagedListed = t.staged_listed ?? m.staged?.length ?? 0
  const stagedCopied = t.staged_copied ?? m.staged?.filter((s) => s.copy?.status === 'copied' || s.copy?.status === 'truncated').length ?? 0
  const secretsListed = t.secrets_listed ?? m.secrets?.length ?? 0
  const secretsCopied = t.secrets_copied ?? m.secrets?.filter((s) => s.copy?.status === 'copied' || s.copy?.status === 'truncated').length ?? 0
  const unlisted = t.staged_unlisted ? `, ${t.staged_unlisted} more not listed` : ''
  const staged = !m.parts.staged_files
    ? 'Turned off in the policy'
    : `${stagedListed} listed, ${stagedCopied} copied${t.staged_bytes ? ` (${fmtBytes(t.staged_bytes)})` : ''}${unlisted}`
  const secrets = !m.parts.secrets_list
    ? 'Turned off in the policy'
    : `${secretsListed} listed, ${m.parts.secrets_copy ? `${secretsCopied} copied${t.secret_bytes ? ` (${fmtBytes(t.secret_bytes)})` : ''}` : 'copies turned off'}`
  const p = m.pcap
  const pcap = !m.parts.pcap || !p ? 'Turned off in the policy' : `${PCAP_STATUS[p.status]?.label.split(':')[0] ?? p.status}${p.bytes ? ` (${fmtBytes(p.bytes)})` : ''}`
  return { staged, secrets, pcap }
}

// ---------------------------------------------------------------- policy

/** Policies saved before the field have no `evidence`: everything on. */
export function evidencePolicyOf(v: Partial<EvidencePolicy> | null | undefined): EvidencePolicy {
  const p = { ...EVIDENCE_POLICY_DEFAULTS, ...(v ?? {}) }
  if (!p.secrets_list) p.secrets_copy = false
  return p
}

/** Turning every part off disables capture entirely. */
export function captureOff(p: EvidencePolicy): boolean {
  return !p.staged_files && !p.secrets_list && !p.pcap
}

export const evidenceRetentionOf = (r: { evidence?: number } | null | undefined) => r?.evidence ?? EVIDENCE_RETENTION_DEFAULT_DAYS

// ---------------------------------------------------------------- download

/**
 * Only follow a download link that stays on this console's origin (the
 * server answers a relative `/api/...` path). `data:`/`blob:` are allowed only
 * in mock mode.
 */
export function safeDownloadUrl(url: string, allowLocal: boolean, origin = typeof location !== 'undefined' ? location.origin : 'http://localhost'): string | null {
  if (allowLocal && (url.startsWith('data:') || url.startsWith('blob:'))) return url
  try {
    const u = new URL(url, origin)
    if (u.origin !== origin || (u.protocol !== 'https:' && u.protocol !== 'http:')) return null
    return u.pathname + u.search
  } catch {
    return null
  }
}
