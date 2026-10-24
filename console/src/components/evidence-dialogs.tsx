import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, KeyRound, Loader2, ShieldAlert, Trash2, UploadCloud } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { IS_MOCK } from '@/api/client'
import { api, qk } from '@/api/endpoints'
import type { EvidenceBundle, EvidenceDownloadTicket } from '@/api/types'
import { EVIDENCE_REASON_MAX, EVIDENCE_REAUTH_WHY, evidenceErrorText, evidenceRetentionOf, safeDownloadUrl } from '@/lib/evidence'
import { formatBytes, formatTime } from '@/lib/format'
import { CopyButton } from './copy-button'
import { useReauth } from './remote/reauth'
import { Button } from './ui/button'
import { Dialog, DialogContent } from './ui/dialog'
import { Field, Input } from './ui/input'

export const PASSWORD_NOTE = 'AES-256 zip: open with 7-Zip (Windows Explorer cannot open encrypted zips). This password is not stored anywhere; copy it now.'

/** Invalidate every evidence query (panel lists and single bundles). */
export function useRefreshEvidence() {
  const qc = useQueryClient()
  return () => void qc.invalidateQueries({ queryKey: ['evidence'] })
}

function ErrorBox({ text }: { text: string | null }) {
  return text ? (
    <p className="mt-4 rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-fg" role="alert">
      {text}
    </p>
  ) : null
}

/** Optional audit reason (≤ 200 characters), sent as `{"reason": …}`. */
function ReasonField({ id, value, onChange, disabled }: { id: string; value: string; onChange: (v: string) => void; disabled?: boolean }) {
  return (
    <Field label="Reason (recorded in the audit log)" htmlFor={id} hint={`Optional, for example the ticket number. Up to ${EVIDENCE_REASON_MAX} characters.`} className="mt-4">
      <Input id={id} value={value} maxLength={EVIDENCE_REASON_MAX} autoComplete="off" disabled={disabled} onChange={(e) => onChange(e.target.value.slice(0, EVIDENCE_REASON_MAX))} />
    </Field>
  )
}
const reasonOf = (s: string) => s.trim().slice(0, EVIDENCE_REASON_MAX) || undefined

/** Confirmation for `POST /evidence/:id/collect`: what the upload contains and who is told. */
export function CollectEvidenceDialog({ bundle: b, onClose }: { bundle: EvidenceBundle; onClose: () => void }) {
  const refresh = useRefreshEvidence()
  const { withReauth } = useReauth()
  const [error, setError] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  // Admins can read settings; when they cannot, the text falls back to "the retention period".
  const settings = useQuery({ queryKey: qk.settings, queryFn: api.settings, staleTime: 300_000, retry: false })
  const days = settings.data ? evidenceRetentionOf(settings.data.retention_days) : null
  const m = useMutation({
    mutationFn: () => withReauth(() => api.collectEvidence(b.id, reasonOf(reason)), EVIDENCE_REAUTH_WHY),
    onSuccess: (nb) => {
      toast.success(`Collecting evidence from ${b.hostname}`, { description: nb.device_online ? 'The upload starts now. The employee is told in the tray.' : 'The PC is offline: the upload starts when it is next online.' })
      refresh()
      onClose()
    },
    onError: (e) => {
      setError(evidenceErrorText(e))
      refresh()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => !o && !m.isPending && onClose()}>
      <DialogContent
        size="lg"
        title={`Collect evidence from ${b.hostname}?`}
        description="Uploads the encrypted evidence bundle from the PC to the Kestrel server."
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={m.isPending}>
              Cancel
            </Button>
            <Button variant="primary" disabled={m.isPending} onClick={() => (setError(null), m.mutate())}>
              {m.isPending ? <Loader2 className="animate-spin" /> : <UploadCloud />} Collect evidence
            </Button>
          </>
        }
      >
        <ul className="list-disc space-y-2 pl-5 text-sm text-fg-muted marker:text-fg-subtle">
          <li>
            <span className="text-fg">It contains copies of real secrets.</span> The bundle can hold the employee’s real saved passwords, cookies and session tokens (copies of the credential stores the program read), the files it staged, and up to 60 s of its network traffic. Handle the download like a password vault.
          </li>
          <li>
            <span className="text-fg">The employee is told.</span> The Kestrel tray on the PC shows “IT collected evidence from this PC for a security investigation”.
          </li>
          <li>
            <span className="text-fg">Every step is audited.</span> This request, each download and each deletion are recorded in the audit log with your name.
          </li>
          <li>
            <span className="text-fg">Stored encrypted, deleted automatically</span> {days ? `${days} days` : 'after the retention period set in Settings'}
            {days ? ' after it reaches the server' : ''}. It never goes into telemetry or Hunt.
          </li>
        </ul>
        <p className="mt-4 text-sm">
          About <span className="font-medium tabular">{formatBytes(b.bundle_size)}</span> will be uploaded.{' '}
          {b.device_online ? 'The PC is online, so the upload normally starts within a minute.' : <span className="text-warn">The PC is offline: the request is queued and the upload starts when it is next online.</span>}
        </p>
        <ReasonField id="ev-collect-reason" value={reason} onChange={setReason} disabled={m.isPending} />
        <ErrorBox text={error} />
      </DialogContent>
    </Dialog>
  )
}

/** Confirmation for `DELETE /evidence/:id`. */
export function DeleteEvidenceDialog({ bundle: b, onClose }: { bundle: EvidenceBundle; onClose: () => void }) {
  const refresh = useRefreshEvidence()
  const [error, setError] = useState<string | null>(null)
  const [reason, setReason] = useState('')
  const onServer = b.status === 'stored'
  const { withReauth } = useReauth()
  const m = useMutation({
    // Deleting is irreversible: the same MFA step-up as collect / download.
    mutationFn: () => withReauth(() => api.deleteEvidence(b.id, reasonOf(reason)), EVIDENCE_REAUTH_WHY),
    onSuccess: () => {
      toast.success('Evidence deleted', { description: onServer ? 'The copy on the server is gone.' : 'The PC deletes its copy the next time it is online.' })
      refresh()
      onClose()
    },
    onError: (e) => {
      setError(evidenceErrorText(e))
      refresh()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => !o && !m.isPending && onClose()}>
      <DialogContent
        title="Delete this evidence?"
        description={onServer ? 'Deletes the encrypted copy on the server.' : 'Tells the PC to delete its encrypted copy.'}
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={m.isPending}>
              Cancel
            </Button>
            <Button variant="danger" disabled={m.isPending} onClick={() => (setError(null), m.mutate())}>
              {m.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Delete evidence
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg-muted">
          {onServer
            ? 'Nobody can download it afterwards.'
            : b.status === 'collecting'
              ? 'The queued upload is cancelled and the PC deletes its copy. If the PC is offline, it does so the next time it is online.'
              : 'If the PC is offline, it deletes its copy the next time it is online.'}{' '}
          The list of contents and the audit trail are kept. This cannot be undone.
        </p>
        <ReasonField id="ev-delete-reason" value={reason} onChange={setReason} disabled={m.isPending} />
        <ErrorBox text={error} />
      </DialogContent>
    </Dialog>
  )
}

/**
 * Download in two steps: an optional audit reason, then `POST /evidence/:id/download`
 * (MFA step-up when needed) and the password, shown once. The ticket lives only in
 * this dialog's state (no react-query mutation, whose cache would keep the password);
 * closing the dialog forgets it.
 */
export function DownloadEvidenceDialog({ bundle: b, onClose }: { bundle: EvidenceBundle; onClose: () => void }) {
  const refresh = useRefreshEvidence()
  const { withReauth } = useReauth()
  const [reason, setReason] = useState('')
  const [ticket, setTicket] = useState<EvidenceDownloadTicket | null>(null)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const create = async () => {
    if (pending) return
    setPending(true)
    setError(null)
    try {
      setTicket(await withReauth(() => api.evidenceDownload(b.id, reasonOf(reason)), EVIDENCE_REAUTH_WHY))
    } catch (e) {
      setError(evidenceErrorText(e))
    } finally {
      setPending(false)
      refresh()
    }
  }
  const close = () => {
    setTicket(null)
    onClose()
  }
  if (ticket) return <EvidencePasswordDialog ticket={ticket} onClose={close} />
  return (
    <Dialog open onOpenChange={(o) => !o && !pending && close()}>
      <DialogContent
        title="Download evidence archive"
        description={`Creates a one-time download of the ${formatBytes(b.bundle_size)} bundle from ${b.hostname}.`}
        footer={
          <>
            <Button variant="ghost" onClick={close} disabled={pending}>
              Cancel
            </Button>
            <Button variant="primary" disabled={pending} onClick={() => void create()}>
              {pending ? <Loader2 className="animate-spin" /> : <Download />} Create download
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg-muted">The next step shows the archive password once. The download is recorded in the audit log with your name.</p>
        <ReasonField id="ev-download-reason" value={reason} onChange={setReason} disabled={pending} />
        <ErrorBox text={error} />
      </DialogContent>
    </Dialog>
  )
}

/** Shows the archive password once; closing the dialog forgets it. */
export function EvidencePasswordDialog({ ticket: t, onClose }: { ticket: EvidenceDownloadTicket; onClose: () => void }) {
  const [started, setStarted] = useState(false)
  const href = safeDownloadUrl(t.url, IS_MOCK || import.meta.env.MODE === 'test')
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="lg"
        title="Download evidence archive"
        description="The archive is encrypted with the password below. You will not see it again."
        footer={
          <Button variant="secondary" onClick={onClose}>
            Close and forget the password
          </Button>
        }
      >
        <div className="space-y-4">
          <div>
            <p className="mb-1 flex items-center gap-1.5 text-xs text-fg-subtle">
              <KeyRound className="size-3.5" aria-hidden /> Archive password
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <code aria-label="Archive password" className="min-w-0 flex-1 select-all break-all rounded-md border border-border bg-surface-2 px-3 py-2 font-mono text-base tracking-wide">
                {t.password}
              </code>
              <CopyButton text={t.password} label="Copy password" size="md" />
            </div>
          </div>
          <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
            <span>{PASSWORD_NOTE}</span>
          </p>
          <div className="flex flex-wrap items-center gap-3">
            {href ? (
              <Button asChild variant="primary">
                <a href={href} download={t.file_name} onClick={() => setStarted(true)}>
                  <Download /> Download {t.file_name}
                </a>
              </Button>
            ) : (
              <p className="text-sm text-danger" role="alert">
                The server answered with a download link outside this console, so it was not opened.
              </p>
            )}
            <span className="text-xs text-fg-muted">
              {formatBytes(t.size)} · the link works once, until {formatTime(t.expires_at)}
            </span>
          </div>
          {started ? <p className="text-xs text-fg-muted" role="status">Download started. If it did not, close this window and start a new download (it gets a new password).</p> : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
