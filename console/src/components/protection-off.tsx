import { ShieldOff } from 'lucide-react'
import type { Device, PauseMode } from '@/api/types'
import { PAUSE_MODE_HINT } from '@/lib/labels'
import { pauseHeadline, protectionOffNote, RESUME_PROTECTION_SPEC } from '@/lib/pause'
import { formatDateTime } from '@/lib/format'
import { cn } from '@/lib/utils'
import { ActionButton, type ActionSpec } from './response-actions'

/** Warning banner on the device page while protection is turned off locally. */
export function ProtectionOffBanner({ device, onPick }: { device: Pick<Device, 'pause'>; onPick: (s: ActionSpec) => void }) {
  const p = device.pause
  if (!p) return null
  return (
    <div role="status" aria-label="Protection turned off" className="flex flex-wrap items-start gap-x-4 gap-y-3 rounded-lg border border-warn/40 bg-warn-soft px-4 py-3 text-sm">
      <div className="min-w-0 flex-1">
        <p className="flex items-center gap-2 font-medium">
          <ShieldOff className="size-4 shrink-0 text-warn" aria-hidden /> {pauseHeadline(p)}
        </p>
        <p className="mt-1 text-fg-muted">
          {PAUSE_MODE_HINT[p.mode]} Turned off {formatDateTime(p.since_ms)} with the device’s uninstall token. Every turn-off raises TP-06 and an audit entry.
        </p>
      </div>
      <ActionButton spec={RESUME_PROTECTION_SPEC} onPick={onPick} />
    </div>
  )
}

/** Note on an alert that fired while protection was turned off on the device. */
export function ProtectionOffNote({ mode, className }: { mode: PauseMode | null | undefined; className?: string }) {
  if (!mode) return null
  return (
    <p className={cn('flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm', className)}>
      <ShieldOff className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
      <span>{protectionOffNote(mode)}</span>
    </p>
  )
}
