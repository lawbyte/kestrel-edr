import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Ban, Crosshair, FileArchive, Lock, LockOpen, PackageSearch, ScanSearch, ShieldPlus, Skull, Unlink, type LucideIcon } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/endpoints'
import { ApiError } from '@/api/client'
import type { Device, ResponseAction } from '@/api/types'
import { useAuth } from '@/lib/auth'
import { ACTION_LABEL, actionPrivilege, describeAction, unblockFor } from '@/lib/labels'
import { safeDisplay } from '@/lib/format'
import { Button } from './ui/button'
import { Dialog, DialogContent } from './ui/dialog'
import { Field, Input, Textarea } from './ui/input'
import { Switch, Tooltip } from './ui/misc'

export interface ActionSpec {
  action: ResponseAction
  /** Extra explanation of the impact, shown in the confirm dialog. */
  impact?: string
  destructive?: boolean
}

const ICONS: Partial<Record<ResponseAction['type'], LucideIcon>> = {
  kill_process: Skull,
  quarantine_file: FileArchive,
  isolate_host: Lock,
  release_host: LockOpen,
  block_destination: Ban,
  block_image_network: Ban,
  unblock_network: Unlink,
  collect_triage: PackageSearch,
  scan: ScanSearch,
  apply_hardening: ShieldPlus,
  suspend_process: Crosshair,
}

/**
 * Confirm spec for lifting a succeeded block action (false positive on a
 * business app), or null when the action is not a block or did not succeed.
 */
export function liftBlockSpec(a: ResponseAction, status: string, artifact?: string | null): ActionSpec | null {
  if (status !== 'succeeded') return null
  const action = unblockFor(a, artifact)
  if (!action) return null
  const what = action.image ? `every Kestrel network block for ${safeDisplay(action.image)}` : `network block ${safeDisplay(action.block_id ?? '')}`
  return {
    action,
    impact: `Removes ${what} on the device, so the program can reach the network again. Do this only if the block was a false positive. Isolation is not affected (use Release host).`,
  }
}

export function useIssueAction(deviceId: string, incidentId?: string) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { action: ResponseAction; comment: string }) => api.deviceAction(deviceId, { action: v.action, incident_id: incidentId, comment: v.comment }),
    onSuccess: (row) => {
      toast.success(`${ACTION_LABEL[row.action.type]} sent to ${row.hostname}`, { description: row.status === 'pending' ? 'The device is offline; it will run when it reconnects.' : 'You’ll see the result in the action log.' })
      void qc.invalidateQueries({ queryKey: ['actions'] })
      void qc.invalidateQueries({ queryKey: ['incident'] })
      void qc.invalidateQueries({ queryKey: ['device', deviceId] })
    },
    onError: (e) => toast.error('Action not sent', { description: e instanceof ApiError ? e.message : String(e) }),
  })
}

/** Confirm dialog with required comment for any response action. */
export function ConfirmActionDialog({
  open,
  onOpenChange,
  spec,
  device,
  incidentId,
  extra,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  spec: ActionSpec | null
  device: Pick<Device, 'id' | 'hostname' | 'status'>
  incidentId?: string
  extra?: ReactNode
}) {
  const [comment, setComment] = useState('')
  const [touched, setTouched] = useState(false)
  const issue = useIssueAction(device.id, incidentId)
  if (!spec) return null
  const a = spec.action
  const err = touched && comment.trim().length < 3 ? 'Add a short reason. It is recorded in the audit log.' : null
  const submit = () => {
    setTouched(true)
    if (comment.trim().length < 3) return
    issue.mutate(
      { action: a, comment: comment.trim() },
      {
        onSuccess: () => {
          setComment('')
          setTouched(false)
          onOpenChange(false)
        },
      },
    )
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        title={`${ACTION_LABEL[a.type]} on ${safeDisplay(device.hostname)}?`}
        description={describeAction(a)}
        footer={
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant={spec.destructive ? 'danger' : 'primary'} onClick={submit} disabled={issue.isPending}>
              {issue.isPending ? 'Sending…' : ACTION_LABEL[a.type]}
            </Button>
          </>
        }
      >
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          {spec.impact ? <p className="rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-fg-muted">{safeDisplay(spec.impact)}</p> : null}
          {device.status === 'offline' ? (
            <p className="rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm text-warn">This device is offline. The action will wait and run when it reconnects (expires after 24 h).</p>
          ) : null}
          {extra}
          <Field label="Reason" htmlFor="action-comment" error={err} hint="Required. Saved with the action and in the audit log.">
            <Textarea
              id="action-comment"
              autoFocus
              value={comment}
              aria-invalid={!!err}
              onChange={(e) => setComment(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) submit()
              }}
              placeholder="e.g. Confirmed Lumma infection, containing until reimage"
              className="min-h-16"
            />
          </Field>
        </form>
      </DialogContent>
    </Dialog>
  )
}

/** Inputs for actions that need parameters (block destination). */
export function BlockDestinationDialog({ open, onOpenChange, device, incidentId, defaults }: { open: boolean; onOpenChange: (o: boolean) => void; device: Pick<Device, 'id' | 'hostname' | 'status'>; incidentId?: string; defaults?: { ip?: string; port?: number | null; image?: string | null } }) {
  const [ip, setIp] = useState(defaults?.ip ?? '')
  const [port, setPort] = useState(defaults?.port ? String(defaults.port) : '')
  const [onlyImage, setOnlyImage] = useState(false)
  const [ttl, setTtl] = useState('24')
  const valid = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f:]+$/i.test(ip.trim())
  const spec: ActionSpec = {
    action: { type: 'block_destination', ip: ip.trim() || '0.0.0.0', port: port ? Number(port) : null, image: onlyImage ? (defaults?.image ?? null) : null, ttl_secs: ttl ? Number(ttl) * 3600 : null },
    impact: 'Adds a Windows Filtering Platform rule on the device. Kestrel’s own server stays reachable.',
  }
  return (
    <ConfirmActionDialog
      open={open}
      onOpenChange={onOpenChange}
      spec={spec}
      device={device}
      incidentId={incidentId}
      extra={
        <div className="grid grid-cols-[1fr_7rem] gap-3">
          <Field label="IP address" htmlFor="blk-ip" error={ip && !valid ? 'Enter an IPv4 or IPv6 address' : null}>
            <Input id="blk-ip" value={ip} onChange={(e) => setIp(e.target.value)} placeholder="185.208.158.114" className="font-mono" />
          </Field>
          <Field label="Port" htmlFor="blk-port" hint="Blank = all">
            <Input id="blk-port" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} placeholder="443" className="font-mono" />
          </Field>
          <Field label="Expires after (hours)" htmlFor="blk-ttl" hint="Blank = never" className="col-span-1">
            <Input id="blk-ttl" value={ttl} onChange={(e) => setTtl(e.target.value.replace(/\D/g, ''))} />
          </Field>
          {defaults?.image ? (
            <label className="col-span-2 flex items-center gap-2 text-sm">
              <Switch checked={onlyImage} onCheckedChange={setOnlyImage} aria-label="Only for this program" />
              Only for <span className="font-mono text-xs">{safeDisplay(defaults.image.split('\\').pop())}</span>
            </label>
          ) : null}
        </div>
      }
    />
  )
}

export function ActionButton({ spec, onPick, label, disabledReason }: { spec: ActionSpec; onPick: (s: ActionSpec) => void; label?: string; disabledReason?: string | null }) {
  const { can } = useAuth()
  const Icon = ICONS[spec.action.type]
  const priv = actionPrivilege(spec.action)
  const reason = disabledReason ?? (can(priv) ? null : `Your role is missing the ${priv} privilege`)
  const btn = (
    <Button size="sm" variant={spec.destructive ? 'danger-outline' : 'secondary'} disabled={!!reason} onClick={() => onPick(spec)}>
      {Icon ? <Icon /> : null}
      {label ?? ACTION_LABEL[spec.action.type]}
    </Button>
  )
  return reason ? (
    <Tooltip content={reason}>
      <span tabIndex={0}>{btn}</span>
    </Tooltip>
  ) : (
    btn
  )
}
