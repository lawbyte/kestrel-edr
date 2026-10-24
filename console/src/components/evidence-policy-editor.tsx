import { Info, ShieldAlert } from 'lucide-react'
import type { EvidencePolicy } from '@/api/types'
import { captureOff, evidencePolicyOf } from '@/lib/evidence'
import { cn } from '@/lib/utils'
import { Input } from './ui/input'
import { Switch } from './ui/misc'

function Row({ id, label, hint, checked, onChange, disabled }: { id: string; label: string; hint: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <div className={cn('flex items-start justify-between gap-4 px-4 py-3', disabled && 'opacity-60')}>
      <div className="min-w-0">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className="text-xs text-fg-muted">{hint}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  )
}

/** Policy settings for evidence capture after ST-02 / ST-04 (`Policy.evidence`). */
export function EvidencePolicyEditor({ value, onChange, readOnly }: { value: Partial<EvidencePolicy> | null | undefined; onChange: (v: EvidencePolicy) => void; readOnly: boolean }) {
  const v = evidencePolicyOf(value)
  const set = (patch: Partial<EvidencePolicy>) => onChange(evidencePolicyOf({ ...v, ...patch }))
  const off = captureOff(v)
  return (
    <div className="space-y-3">
      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        <Row
          id="ev-staged"
          label="Copies of staged files"
          hint="Files the suspicious processes created or overwrote in user folders and Temp during the alert window (stolen data is usually packed there before upload). Up to 50 MB per file and 200 MB in total."
          checked={v.staged_files}
          onChange={(x) => set({ staged_files: x })}
          disabled={readOnly}
        />
        <Row
          id="ev-secrets-list"
          label="List of secrets it read"
          hint="Which credential stores the processes opened (browser passwords, cookies, wallets, Telegram…), when and how often. Metadata only; it is shown to analysts on the incident."
          checked={v.secrets_list}
          onChange={(x) => set({ secrets_list: x, ...(x ? {} : { secrets_copy: false }) })}
          disabled={readOnly}
        />
        <Row
          id="ev-secrets-copy"
          label="Copies of the secrets it read"
          hint={v.secrets_list ? 'Copies of those credential stores, so you can see exactly what was exposed. They contain the employee’s real passwords and cookies. Stores the app keeps locked are listed but not copied.' : 'Needs the list of secrets read.'}
          checked={v.secrets_copy}
          onChange={(x) => set({ secrets_copy: x })}
          disabled={readOnly || !v.secrets_list}
        />
        <Row
          id="ev-pcap"
          label="Connection capture"
          hint="Records the processes’ network connections for 60 s after the alert with Windows’ built-in pktmon (Windows 10 2004 or later). Encrypted traffic stays encrypted; other apps talking to the same address can appear too."
          checked={v.pcap}
          onChange={(x) => set({ pcap: x })}
          disabled={readOnly}
        />
        <div className={cn('flex flex-wrap items-center justify-between gap-3 px-4 py-3', off && 'opacity-60')}>
          <div className="min-w-0 max-w-xl">
            <label htmlFor="ev-local-days" className="text-sm font-medium">
              Keep uncollected bundles on the PC
            </label>
            <p className="text-xs text-fg-muted">If no administrator collects a bundle, the PC deletes it after this many days. Collected bundles follow the server retention in Settings.</p>
          </div>
          <div className="flex items-center gap-2">
            <Input
              id="ev-local-days"
              type="number"
              min={1}
              max={365}
              value={v.local_retention_days}
              disabled={readOnly || off}
              onChange={(e) => set({ local_retention_days: Math.min(365, Math.max(1, Math.round(Number(e.target.value)) || 1)) })}
              className="w-24 text-right tabular"
            />
            <span className="text-sm text-fg-muted">days</span>
          </div>
        </div>
      </div>
      {off ? (
        <p className="flex items-start gap-1.5 text-xs text-warn" data-testid="ev-off">
          <ShieldAlert className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Evidence capture is off for this policy: ST-02 / ST-04 alerts still arrive, but nothing is kept for an investigation.
        </p>
      ) : null}
      <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        <div className="space-y-1">
          <p>
            Capture runs only after an ST-02 or ST-04 alert and only for the process tree that raised it; nothing is captured in the background. The bundle stays encrypted on the PC. Only its list of contents reaches the server automatically.
          </p>
          <p>Content is uploaded only when an administrator clicks Collect evidence. The employee is then told in the tray, every collection, download and deletion is audited, and the content never goes into telemetry or Hunt. Mention this in the employee notice below.</p>
        </div>
      </div>
    </div>
  )
}
