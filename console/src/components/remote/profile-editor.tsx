import { AlertTriangle, Plus, ShieldCheck, X } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import type { DesktopMode, FileMode, RemoteAccessProfile, RemoteGuardrails } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Segmented, Switch } from '@/components/ui/misc'
import { DAY_LABEL, isNoneProfile, minutesToTime, presetOf, presetProfile, profileSummary, timeToMinutes, validateProfile } from '@/lib/remote-profile'
import { validateRemotePath } from '@/lib/remote-path'
import { cn } from '@/lib/utils'

/** Editor for a `RemoteAccessProfile` (policy editor and installer wizard). */
export function RemoteProfileEditor({ value, onChange, disabled, idPrefix = 'rp', presets = true }: { value: RemoteAccessProfile; onChange: (p: RemoteAccessProfile) => void; disabled?: boolean; idPrefix?: string; presets?: boolean }) {
  const g = value.guardrails
  const set = (patch: Partial<RemoteGuardrails>) => onChange({ ...value, guardrails: { ...g, ...patch } })
  const off = isNoneProfile(value)
  const invalid = validateProfile(value)
  const preset = presetOf(value)
  const id = (s: string) => `${idPrefix}-${s}`
  return (
    <div className="space-y-4">
      {presets ? (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-fg-muted">Start from:</span>
          {(['none', 'guarded', 'unrestricted'] as const).map((p) => (
            <Button key={p} size="sm" variant={preset === p ? 'primary' : 'secondary'} aria-pressed={preset === p} disabled={disabled} onClick={() => onChange(presetProfile(p))}>
              {p === 'none' ? 'No remote access' : p === 'guarded' ? 'Guarded' : 'No guardrails'}
            </Button>
          ))}
          {preset === 'custom' ? <span className="text-xs text-fg-subtle">(custom)</span> : null}
        </div>
      ) : null}

      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        <Row label="Remote desktop" hint="View only: watch the screen. Control: also mouse and keyboard. The employee always sees a banner and a notification.">
          <Segmented<DesktopMode>
            label="Remote desktop"
            value={value.desktop}
            disabled={disabled}
            onChange={(v) => onChange({ ...value, desktop: v })}
            options={[
              { value: 'off', label: 'Off' },
              { value: 'view_only', label: 'View only' },
              { value: 'control', label: 'Control', tone: 'accent' },
            ]}
          />
        </Row>
        <Row
          label="File manager"
          hint="Read only: browse and download. Full: also upload, new folders and (if allowed below) rename and delete. Runs as SYSTEM."
          note={value.files === 'full' ? 'Uploading as SYSTEM can change anything on the PC, including how this agent behaves; treat Full as equivalent to administrator access.' : undefined}
        >
          <Segmented<FileMode>
            label="File manager"
            value={value.files}
            disabled={disabled}
            onChange={(v) => onChange({ ...value, files: v })}
            options={[
              { value: 'off', label: 'Off' },
              { value: 'read_only', label: 'Read only' },
              { value: 'full', label: 'Full', tone: 'accent' },
            ]}
          />
        </Row>
      </div>

      <fieldset disabled={disabled || off} className={cn('space-y-2', off && 'opacity-60')}>
        <legend className="mb-2 text-sm font-semibold">Guardrails</legend>
        <div className="divide-y divide-border rounded-lg border border-border bg-surface">
          <Toggle id={id('consent')} label="Employee must allow each session" hint="An Allow / Deny prompt in the tray before a desktop session or the first change in a file-manager session. No answer, no one signed in = denied." checked={g.require_consent} onChange={(v) => set({ require_consent: v })}>
            {g.require_consent ? <NumberInput id={id('consent-timeout')} label="Wait up to" unit="s" value={g.consent_timeout_secs} min={0} max={600} onChange={(v) => set({ consent_timeout_secs: v })} hint="0 = 60 s" /> : null}
          </Toggle>
          <Toggle id={id('reason')} label="Admin must give a reason" hint="Shown in the banner and the consent prompt, and recorded in the audit log." checked={g.require_reason} onChange={(v) => set({ require_reason: v })} />
          <Toggle id={id('mfa')} label="Fresh MFA check before access" hint="The admin re-enters an authenticator code; one check lasts 10 minutes." checked={g.require_mfa_reauth} onChange={(v) => set({ require_mfa_reauth: v })} />
          <Toggle id={id('upload')} label="Allow uploads and new folders" hint={value.files === 'full' ? 'Create new files and make folders. Replacing an existing file also needs delete.' : 'Only applies when the file manager is Full.'} checked={g.allow_upload} onChange={(v) => set({ allow_upload: v })} />
          <Toggle id={id('delete')} label="Allow delete and rename" hint={value.files === 'full' ? 'Delete files and folders (recursive), rename and move. Also needed to replace an existing file by uploading over it.' : 'Only applies when the file manager is Full.'} checked={g.allow_delete} onChange={(v) => set({ allow_delete: v })} />
          <div className="flex flex-wrap gap-x-8 gap-y-3 px-4 py-3">
            <NumberInput id={id('max')} label="Longest session" unit="min" value={g.max_session_minutes} min={0} max={1440} onChange={(v) => set({ max_session_minutes: v })} hint="0 = no limit" />
            <NumberInput id={id('idle')} label="End after idle" unit="min" value={g.idle_timeout_minutes} min={0} max={1440} onChange={(v) => set({ idle_timeout_minutes: v })} hint="0 = never" />
          </div>
          <HoursEditor idPrefix={idPrefix} value={g.allowed_hours} onChange={(h) => set({ allowed_hours: h })} />
          <BlockedPaths idPrefix={idPrefix} value={g.blocked_paths} onChange={(b) => set({ blocked_paths: b })} />
        </div>
      </fieldset>

      <div className={cn('flex items-start gap-2 rounded-md border px-3 py-2 text-sm', invalid ? 'border-danger/40 bg-danger-soft' : 'border-border bg-surface-2')} role={invalid ? 'alert' : undefined}>
        {invalid ? <AlertTriangle className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden /> : <ShieldCheck className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-hidden />}
        <span>{invalid ? `Fix this before saving: ${invalid}` : profileSummary(value)}</span>
      </div>
    </div>
  )
}

function Row({ label, hint, note, children }: { label: string; hint: string; note?: string; children: ReactNode }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <div className="min-w-0 max-w-xl">
        <p className="text-sm font-medium">{label}</p>
        <p className="text-xs text-fg-muted">{hint}</p>
        {note ? (
          <p className="mt-1 flex items-start gap-1 text-xs font-medium text-warn">
            <AlertTriangle className="mt-px size-3.5 shrink-0" aria-hidden /> {note}
          </p>
        ) : null}
      </div>
      {children}
    </div>
  )
}

function Toggle({ id, label, hint, checked, onChange, children }: { id: string; label: string; hint: string; checked: boolean; onChange: (v: boolean) => void; children?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 px-4 py-3">
      <div className="min-w-0 max-w-xl flex-1">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className="text-xs text-fg-muted">{hint}</p>
        {children ? <div className="mt-2">{children}</div> : null}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  )
}

function NumberInput({ id, label, unit, value, min, max, onChange, hint }: { id: string; label: string; unit: string; value: number; min: number; max: number; onChange: (v: number) => void; hint?: string }) {
  return (
    <div className="flex items-center gap-2">
      <label htmlFor={id} className="text-sm">
        {label}
      </label>
      <Input
        id={id}
        type="number"
        min={min}
        max={max}
        step={1}
        value={value}
        onChange={(e) => {
          const n = Math.trunc(Number(e.target.value))
          onChange(Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : min)
        }}
        className="w-20 text-right tabular"
      />
      <span className="text-sm text-fg-muted">{unit}</span>
      {hint ? <span className="text-xs text-fg-subtle">{hint}</span> : null}
    </div>
  )
}

function HoursEditor({ idPrefix, value, onChange }: { idPrefix: string; value: RemoteGuardrails['allowed_hours']; onChange: (v: RemoteGuardrails['allowed_hours']) => void }) {
  const on = !!value
  const h = value ?? { days: [0, 1, 2, 3, 4], start_minute: 8 * 60, end_minute: 18 * 60 }
  const [start, setStart] = useState(minutesToTime(h.start_minute))
  const [end, setEnd] = useState(minutesToTime(h.end_minute))
  const commit = (s: string, e: string) => {
    const a = timeToMinutes(s)
    const b = timeToMinutes(e)
    if (a != null && b != null) onChange({ ...h, start_minute: a, end_minute: b })
  }
  return (
    <div className="px-4 py-3">
      <div className="flex items-start justify-between gap-3">
        <div>
          <label htmlFor={`${idPrefix}-hours`} className="text-sm font-medium">
            Only during set hours
          </label>
          <p className="text-xs text-fg-muted">In the device’s local time. Windows do not wrap past midnight.</p>
        </div>
        <Switch id={`${idPrefix}-hours`} checked={on} onCheckedChange={(v) => onChange(v ? h : null)} />
      </div>
      {on ? (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <div className="flex gap-1" role="group" aria-label="Allowed days">
            {DAY_LABEL.map((d, i) => {
              const sel = h.days.includes(i)
              return (
                <button
                  key={d}
                  type="button"
                  aria-pressed={sel}
                  onClick={() => onChange({ ...h, days: sel ? h.days.filter((x) => x !== i) : [...h.days, i].sort((a, b) => a - b) })}
                  className={cn('h-7 w-10 rounded-md border text-xs font-medium', sel ? 'border-accent/50 bg-accent-soft text-fg' : 'border-border text-fg-muted hover:text-fg')}
                >
                  {d}
                </button>
              )
            })}
          </div>
          <div className="flex items-center gap-1.5 text-sm">
            <label htmlFor={`${idPrefix}-from`} className="text-fg-muted">
              from
            </label>
            <Input id={`${idPrefix}-from`} value={start} onChange={(e) => (setStart(e.target.value), commit(e.target.value, end))} className="w-24 font-mono" placeholder="08:00" aria-describedby={`${idPrefix}-to-hint`} />
            <label htmlFor={`${idPrefix}-to`} className="text-fg-muted">
              to
            </label>
            <Input id={`${idPrefix}-to`} value={end} onChange={(e) => (setEnd(e.target.value), commit(start, e.target.value))} className="w-24 font-mono" placeholder="18:00" aria-describedby={`${idPrefix}-to-hint`} />
            <span id={`${idPrefix}-to-hint`} className="text-xs text-fg-subtle">
              HH:MM, 24:00 = midnight
            </span>
          </div>
        </div>
      ) : null}
    </div>
  )
}

function BlockedPaths({ idPrefix, value, onChange }: { idPrefix: string; value: string[]; onChange: (v: string[]) => void }) {
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)
  const add = () => {
    const v = validateRemotePath(draft.trim().replace(/^"(.*)"$/, '$1'))
    if (!v.ok) return setError(`Not a valid path: ${v.error}.`)
    if (value.some((x) => x.toLowerCase() === v.path.toLowerCase())) return setError('Already in the list.')
    onChange([...value, v.path])
    setDraft('')
    setError(null)
  }
  return (
    <div className="px-4 py-3">
      <label htmlFor={`${idPrefix}-blocked`} className="text-sm font-medium">
        Blocked folders
      </label>
      <p className="text-xs text-fg-muted">The file manager refuses these folders and everything inside them. Kestrel’s own folders are always refused.</p>
      {value.length ? (
        <ul className="mt-2 flex flex-wrap gap-1.5">
          {value.map((p) => (
            <li key={p} className="inline-flex items-center gap-1 rounded border border-border bg-surface-2 py-0.5 pl-2 pr-0.5 font-mono text-xs">
              {p}
              <Button size="icon-sm" variant="ghost" className="size-5" aria-label={`Remove ${p}`} onClick={() => onChange(value.filter((x) => x !== p))}>
                <X />
              </Button>
            </li>
          ))}
        </ul>
      ) : null}
      <div className="mt-2 flex max-w-xl gap-2">
        <Input
          id={`${idPrefix}-blocked`}
          value={draft}
          onChange={(e) => (setDraft(e.target.value), setError(null))}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              add()
            }
          }}
          aria-invalid={!!error}
          placeholder="e.g. D:\HR or C:\Users\cfo\Documents"
          className="font-mono text-[13px]"
        />
        <Button size="sm" onClick={add} disabled={!draft.trim()}>
          <Plus /> Add
        </Button>
      </div>
      {error ? (
        <p role="alert" className="mt-1 text-xs text-danger">
          {error}
        </p>
      ) : null}
    </div>
  )
}
