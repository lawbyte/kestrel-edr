import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Hourglass, Loader2, RotateCcw, TimerOff, Trash2, Undo2, XCircle } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { ApiError } from '@/api/client'
import { api, qk } from '@/api/endpoints'
import { CAP_AGENT_UNINSTALL, type Device, type DeviceRemoval, type DeviceRemovalState } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, Textarea } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/misc'
import { useReauth } from '@/components/remote/reauth'
import { useAuth } from '@/lib/auth'
import { formatDateTime, safeDisplay } from '@/lib/format'
import { cn } from '@/lib/utils'

/** Privilege for `POST|DELETE /devices/:id/remove` (admins, via `*`). */
export const REMOVE_PRIVILEGE = 'devices.remove'

export const AGENT_TOO_OLD_TEXT = 'The agent on this PC is too old for remote removal. Update the agent, or use the uninstall tool on the PC.'
const REAUTH_WHY = 'Removing a device uninstalls Kestrel from the PC, so it needs a fresh authenticator code. One confirmation is valid for 10 minutes.'

/** The agent announced `agent.uninstall` in its last Hello (absent list = older server or agent: no). */
export function supportsRemoteRemoval(d: Pick<Device, 'capabilities'>): boolean {
  return !!d.capabilities?.includes(CAP_AGENT_UNINSTALL)
}

/** A removal is queued or running: no second request until it ends. */
export function removalActive(r: DeviceRemoval | null | undefined): boolean {
  return r?.state === 'pending' || r?.state === 'removing'
}

export const isRemoved = (d: Pick<Device, 'removal'>) => d.removal?.state === 'removed'

/** Text for a failed `POST|DELETE /devices/:id/remove` (the API error's `reason`). */
export function removalErrorText(e: unknown): string {
  if (!(e instanceof ApiError)) return (e as Error)?.message ?? 'Something went wrong.'
  switch (e.extra?.reason) {
    case 'confirm_mismatch':
      return 'The name you typed does not match this device’s hostname.'
    case 'reauth_required':
      return 'Removing a device needs a fresh authenticator code. Try again and enter the code when asked.'
    case 'agent_too_old':
      return AGENT_TOO_OLD_TEXT
    case 'no_uninstall_token':
      return 'The server has no uninstall token for this device, so the agent would refuse the request. Rotate the uninstall token on this page, then try again, or use the uninstall tool on the PC.'
    case 'removal_pending':
      return 'A removal is already queued or running for this device.'
    case 'rate_limited':
      return 'You have asked for 20 removals in the last hour, the most allowed. Wait a while and try again.'
    case 'already_started':
      return 'The removal was already sent to the agent, so it can no longer be cancelled.'
    case 'no_pending_removal':
      return 'There is no queued removal to cancel. The page has been refreshed.'
  }
  if (e.status === 403) return 'You need the devices.remove privilege and a signed-in console session to remove devices. API tokens cannot do this.'
  return e.message
}

const BADGE: Record<DeviceRemovalState, { label: string; icon: typeof Hourglass; cls: string }> = {
  pending: { label: 'Removal pending', icon: Hourglass, cls: 'text-accent-text' },
  removing: { label: 'Removing', icon: Loader2, cls: 'text-accent-text' },
  failed: { label: 'Removal failed', icon: XCircle, cls: 'text-danger' },
  expired: { label: 'Removal expired', icon: TimerOff, cls: 'text-fg-muted' },
  removed: { label: 'Removed', icon: Trash2, cls: 'text-fg-muted' },
}

/** Removal state as icon + label (never colour alone). */
export function RemovalBadge({ state, className }: { state: DeviceRemovalState; className?: string }) {
  const b = BADGE[state]
  const Icon = b.icon
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium', b.cls, className)}>
      <Icon className="size-3.5 shrink-0" strokeWidth={2.25} aria-hidden />
      {b.label}
    </span>
  )
}

/** "on 3 Oct 2026, 14:05 by Priya Raman" */
function byLine(at: number | null, who: string | null): string {
  const w = who ? ` by ${safeDisplay(who)}` : ''
  return at ? ` on ${formatDateTime(at)}${w}` : w
}

/** "Removed (uninstalled remotely) on <date> by <who>". */
export function removedText(r: DeviceRemoval): string {
  return `Removed (uninstalled remotely)${byLine(r.removed_at ?? r.requested_at, r.requested_by)}`
}

function useRefreshDevice(id: string) {
  const qc = useQueryClient()
  return () => {
    void qc.invalidateQueries({ queryKey: qk.device(id) })
    void qc.invalidateQueries({ queryKey: ['devices'] })
    void qc.invalidateQueries({ queryKey: qk.actions({ device_id: id }) })
  }
}

/** Status banner on the device page while a removal is queued, running, failed, expired or done. */
export function RemovalBanner({ device, onRetry }: { device: Device; onRetry: () => void }) {
  const { can } = useAuth()
  const refresh = useRefreshDevice(device.id)
  const [error, setError] = useState<string | null>(null)
  const cancel = useMutation({
    mutationFn: () => api.cancelDeviceRemoval(device.id),
    onSuccess: () => {
      toast.success(`Removal of ${device.hostname} cancelled`, { description: 'Kestrel stays installed and keeps protecting the PC.' })
      refresh()
    },
    onError: (e) => {
      setError(removalErrorText(e))
      refresh()
    },
  })
  const r = device.removal
  if (!r) return null
  const admin = can(REMOVE_PRIVILEGE)
  const Icon = BADGE[r.state].icon
  const purge = r.purge_data ? ' Quarantined files and Kestrel logs on the PC will be deleted too.' : ' Quarantined files and Kestrel logs stay on the PC.'
  let tone = 'border-accent/40 bg-accent-soft'
  let title: ReactNode
  let body: ReactNode
  let action: ReactNode = null
  switch (r.state) {
    case 'pending':
      title = 'Removal pending'
      body = (
        <>
          Requested{byLine(r.requested_at, r.requested_by)}. Kestrel uninstalls itself from this PC the next time the agent connects; an online PC usually starts within a minute. The request stays queued for 90 days.{purge}
        </>
      )
      action = admin ? (
        <Button size="sm" variant="secondary" disabled={cancel.isPending} onClick={() => (setError(null), cancel.mutate())}>
          {cancel.isPending ? <Loader2 className="animate-spin" /> : <Undo2 />} Cancel removal
        </Button>
      ) : null
      break
    case 'removing':
      title = 'Kestrel is uninstalling itself from this PC'
      body = (
        <>
          The agent confirmed the uninstall started{r.started_at ? ` on ${formatDateTime(r.started_at)}` : ''}. Protection on this PC has stopped. The device is marked removed once it stays disconnected for 10 minutes; its certificates are revoked 7 days later.{purge}
        </>
      )
      break
    case 'failed':
      tone = 'border-danger/40 bg-danger-soft'
      title = 'Removal failed'
      body = (
        <>
          The agent reported: <span className="font-mono text-xs text-fg">{safeDisplay(r.error) || 'no details'}</span>. Kestrel is still installed and the device stays in the list. Requested{byLine(r.requested_at, r.requested_by)}.
        </>
      )
      action = admin ? (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          <RotateCcw /> Try again
        </Button>
      ) : null
      break
    case 'expired':
      tone = 'border-warn/40 bg-warn-soft'
      title = 'Removal expired'
      body = <>The PC did not connect within 90 days, so nothing was uninstalled. Requested{byLine(r.requested_at, r.requested_by)}.</>
      action = admin ? (
        <Button size="sm" variant="secondary" onClick={onRetry}>
          <RotateCcw /> Try again
        </Button>
      ) : null
      break
    case 'removed':
      tone = 'border-border bg-surface-2'
      title = removedText(r)
      body = <>Kestrel was uninstalled from this PC. Its certificates are revoked 7 days after the removal; if the PC connects before that, the removal is undone. This page is read-only; alerts, incidents, actions and the audit trail are kept.</>
      break
  }
  return (
    <div role="status" aria-label="Device removal" className={cn('flex flex-wrap items-start gap-x-4 gap-y-3 rounded-lg border px-4 py-3 text-sm', tone)}>
      <div className="min-w-0 flex-1">
        <p className="flex items-center gap-2 font-medium">
          <Icon className={cn('size-4 shrink-0', BADGE[r.state].cls)} strokeWidth={2.25} aria-hidden />
          {title}
        </p>
        <p className="mt-1 text-fg-muted">{body}</p>
        {error ? (
          <p className="mt-1 text-xs text-danger" role="alert">
            {error}
          </p>
        ) : null}
      </div>
      {action}
    </div>
  )
}

/** Danger-zone row: "Remove device" (remote uninstall). */
export function RemoveDeviceRow({ device, onOpen }: { device: Device; onOpen: () => void }) {
  const supported = supportsRemoteRemoval(device)
  const active = removalActive(device.removal)
  return (
    <div className="flex flex-wrap items-center gap-4 p-4">
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium">Remove device</p>
        <p className="max-w-2xl text-xs text-fg-muted">
          Uninstalls Kestrel from the PC remotely, then takes the device off the list and later revokes its certificates. If the PC is offline, it uninstalls the next time it connects.
        </p>
        {!supported ? <p className="mt-1 max-w-2xl text-xs text-warn">{AGENT_TOO_OLD_TEXT}</p> : active ? <p className="mt-1 text-xs text-fg-muted">A removal is already queued or running.</p> : null}
      </div>
      <Button variant="danger-outline" disabled={!supported || active} onClick={onOpen}>
        <Trash2 /> Remove device
      </Button>
    </div>
  )
}

/** `POST /devices/:id/remove` with hostname echo; 403 `reauth_required` opens the MFA dialog and retries once. */
export function RemoveDeviceDialog({ device, onClose }: { device: Device; onClose: () => void }) {
  const { withReauth } = useReauth()
  const refresh = useRefreshDevice(device.id)
  const [typed, setTyped] = useState('')
  const [purge, setPurge] = useState(false)
  const [comment, setComment] = useState('')
  const [error, setError] = useState<string | null>(null)
  const matches = typed.trim().toLowerCase() === device.hostname.toLowerCase()
  const online = device.status !== 'offline'
  const m = useMutation({
    mutationFn: () => withReauth(() => api.removeDevice(device.id, { purge_data: purge, confirm_hostname: typed.trim(), ...(comment.trim() ? { comment: comment.trim() } : {}) }), REAUTH_WHY),
    onSuccess: () => {
      toast.success(`Removal of ${device.hostname} queued`, { description: online ? 'The agent uninstalls itself as soon as it receives the request.' : 'The PC is offline. It uninstalls the next time it connects.' })
      refresh()
      onClose()
    },
    onError: (e) => setError(removalErrorText(e)),
  })
  const submit = () => {
    if (matches && !m.isPending) {
      setError(null)
      m.mutate()
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && !m.isPending && onClose()}>
      <DialogContent
        size="lg"
        title={`Remove ${device.hostname}?`}
        description="Kestrel will uninstall itself from this PC and protection on it stops."
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={m.isPending}>
              Cancel
            </Button>
            <Button variant="danger" disabled={!matches || m.isPending} onClick={submit}>
              {m.isPending ? <Loader2 className="animate-spin" /> : <Trash2 />} Remove device
            </Button>
          </>
        }
      >
        <ul className="mb-4 list-disc space-y-1.5 pl-5 text-sm text-fg-muted marker:text-fg-subtle">
          <li>
            <span className="text-fg">The agent uninstalls itself.</span> {online ? 'The PC is online, so this normally starts within a minute.' : 'The PC is offline right now. It uninstalls the next time it connects; the request stays queued for 90 days and you can cancel it until then.'}
          </li>
          <li>
            <span className="text-fg">The device then leaves the device list</span> and its certificates are revoked a week later. Its history is kept: alerts, incidents, actions and the audit trail stay available under “Show removed devices”.
          </li>
          <li>
            <span className="text-fg">Not the same as decommission.</span> Decommission only removes the device from the console and revokes its certificates; the agent stays installed on the PC.
          </li>
        </ul>
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <label className="flex items-start gap-2.5 text-sm">
            <Checkbox className="mt-0.5" checked={purge} onCheckedChange={(v) => setPurge(v === true)} aria-describedby="remove-purge-hint" />
            <span>
              Also delete quarantined files and logs on the PC
              <span id="remove-purge-hint" className="block text-xs text-fg-muted">
                Off by default. When off, the quarantine folder and Kestrel’s local logs stay on the disk for your own records.
              </span>
            </span>
          </label>
          <Field label={<>Type <span className="font-mono">{device.hostname}</span> to confirm</>} htmlFor="remove-host">
            <Input id="remove-host" autoFocus autoComplete="off" spellCheck={false} value={typed} onChange={(e) => (setTyped(e.target.value), setError(null))} className="font-mono" aria-invalid={typed.trim() !== '' && !matches ? true : undefined} />
          </Field>
          <Field label="Comment (optional)" htmlFor="remove-comment" hint="Saved in the audit log, for example the ticket number or why the PC is leaving.">
            <Textarea id="remove-comment" value={comment} maxLength={500} onChange={(e) => setComment(e.target.value)} className="min-h-14" />
          </Field>
          {error ? (
            <p className="rounded-md border border-danger/40 bg-danger-soft px-3 py-2 text-sm text-fg" role="alert">
              {error}
            </p>
          ) : null}
        </form>
      </DialogContent>
    </Dialog>
  )
}
