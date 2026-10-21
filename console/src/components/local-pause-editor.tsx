import { Info, ShieldAlert } from 'lucide-react'
import { LOCAL_PAUSE_DEFAULTS, offeredPauseMinutes, PAUSE_MAX_MINUTES_CAP, type LocalPause } from '@/api/types'
import { formatMinutes } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { inputClass } from './ui/input'
import { Switch } from './ui/misc'

/**
 * Choices for the longest timed turn-off (minutes). The tray offers the steps
 * 15 min / 1 h / 4 h / 8 h up to this limit (plus the limit itself below 8 h),
 * so longer values add nothing; a longer value already saved is kept as a choice.
 */
const MAX_CHOICES = [15, 30, 60, 120, 240, 480]

/** Old policies have no `local_pause`: fill in the agent's defaults. */
export function localPauseOf(v: Partial<LocalPause> | null | undefined): LocalPause {
  return { ...LOCAL_PAUSE_DEFAULTS, ...(v ?? {}) }
}

function Row({ id, label, hint, checked, onChange, disabled, warn }: { id: string; label: string; hint: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; warn?: boolean }) {
  return (
    <div className={cn('flex items-start justify-between gap-4 px-4 py-3', disabled && 'opacity-60')}>
      <div className="min-w-0">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className={cn('text-xs', warn ? 'text-warn' : 'text-fg-muted')}>{hint}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  )
}

/** Policy settings for the tray's "Turn off protection" switch (`local_pause`). */
export function LocalPauseEditor({ value, onChange, readOnly }: { value: Partial<LocalPause> | null | undefined; onChange: (v: LocalPause) => void; readOnly: boolean }) {
  const v = localPauseOf(value)
  const set = <K extends keyof LocalPause>(k: K, x: LocalPause[K]) => onChange({ ...v, [k]: x })
  const sub = readOnly || !v.enabled
  const cur = Math.min(Math.max(Math.round(v.max_minutes) || 1, 1), PAUSE_MAX_MINUTES_CAP)
  const choices = MAX_CHOICES.includes(cur) ? MAX_CHOICES : [...MAX_CHOICES, cur].sort((a, b) => a - b)
  const offered = offeredPauseMinutes(v)
  return (
    <div className="space-y-3">
      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        <Row
          id="lp-enabled"
          label="Allow turning protection off on the device"
          hint="The tray shows “Turn off protection”. It needs the device’s uninstall token, which you reveal on the device page. Off: only the console can change protection."
          checked={v.enabled}
          onChange={(x) => set('enabled', x)}
          disabled={readOnly}
        />
        <Row
          id="lp-full"
          label="Allow “completely off”"
          hint="Off (recommended): the only choice is detection only, so alerts keep arriving. On: the person can also stop the sensors. A stolen token could then make the PC invisible to you until protection comes back on."
          checked={v.allow_full}
          onChange={(x) => set('allow_full', x)}
          disabled={sub}
          warn={v.allow_full && v.enabled}
        />
        <div className={cn('flex flex-wrap items-center justify-between gap-3 px-4 py-3', sub && 'opacity-60')}>
          <div className="min-w-0 max-w-xl">
            <label htmlFor="lp-max" className="text-sm font-medium">
              Longest turn-off
            </label>
            <p className="text-xs text-fg-muted">Protection comes back on by itself after the chosen time. The tray offers 15 min, 1 h, 4 h and 8 h, up to this limit.</p>
          </div>
          <select id="lp-max" value={cur} disabled={sub} onChange={(e) => set('max_minutes', Number(e.target.value))} className={cn(inputClass, 'h-8 w-32')}>
            {choices.map((m) => (
              <option key={m} value={m}>
                {formatMinutes(m)}
              </option>
            ))}
          </select>
        </div>
        <Row
          id="lp-until"
          label="Allow “until turned back on”"
          hint="Off (recommended): every turn-off has an end time. On: the person can leave protection off with no end time, until someone turns it back on in the tray or here."
          checked={v.allow_until_resumed}
          onChange={(x) => set('allow_until_resumed', x)}
          disabled={sub}
          warn={v.allow_until_resumed && v.enabled}
        />
      </div>
      <p className="text-xs text-fg-muted" data-testid="lp-offered">
        {v.enabled ? (
          <>
            The tray offers: {[...offered.map(formatMinutes), ...(v.allow_until_resumed ? ['until turned back on'] : [])].join(', ')}. Modes: detection only{v.allow_full ? ', completely off' : ''}.
          </>
        ) : (
          'The tray does not offer turning protection off.'
        )}
      </p>
      <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <div className="space-y-1">
          <p>
            <span className="font-medium text-fg">Detection only</span>: sensors and alerts keep running, but Kestrel takes no automatic action and does not enforce hardening. <span className="font-medium text-fg">Completely off</span>: sensors stop and the device only sends heartbeats.
          </p>
          <p>Turning protection back on never needs the token: the person can do it in the tray, and you can do it from the device page. Every turn-off raises a TP-06 alert and an audit entry, and so do wrong tokens.</p>
        </div>
      </div>
      {v.enabled && (v.allow_full || v.allow_until_resumed) ? (
        <p className="flex items-start gap-1.5 text-xs text-warn">
          <ShieldAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Anyone with this device’s uninstall token can now {v.allow_full ? 'stop the sensors' : ''}
          {v.allow_full && v.allow_until_resumed ? ' with no end time' : v.allow_until_resumed ? 'leave protection off with no end time' : ''}. Keep these off unless a technician needs them, and rotate the token afterwards.
        </p>
      ) : null}
    </div>
  )
}
