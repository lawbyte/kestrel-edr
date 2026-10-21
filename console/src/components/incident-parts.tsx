import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Bot, CheckCircle2, Circle, ClipboardCheck, Hand, KeyRound, ShieldAlert, Zap } from 'lucide-react'
import { Fragment, useState } from 'react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { ChecklistItem, DataCategory, Incident, IncidentDetail, ResponseAction, TreeNode } from '@/api/types'
import { useAuth } from '@/lib/auth'
import { actionPrivilege, AUTORUN_KIND_LABEL, DATA_CATEGORY_LABEL, DATA_CATEGORY_REMEDIATION, describeAction, isCanonicalDefault } from '@/lib/labels'
import { safeDisplay } from '@/lib/format'
import { cn } from '@/lib/utils'
import { Button } from './ui/button'
import { Dialog, DialogContent } from './ui/dialog'
import { Tooltip } from './ui/misc'

/**
 * Shells, session and OS processes the console must never offer to kill (killing
 * explorer.exe / a terminal / svchost takes the user's session or the OS down).
 * Mirrors the agent's protected list; the agent refuses these too.
 */
export const UNSAFE_KILL_TARGETS = new Set([
  'explorer.exe', 'cmd.exe', 'powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'wt.exe', 'windowsterminal.exe', 'openconsole.exe', 'conhost.exe',
  'svchost.exe', 'lsass.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe', 'services.exe', 'smss.exe', 'sihost.exe', 'spoolsv.exe', 'dwm.exe',
  'taskhostw.exe', 'runtimebroker.exe', 'userinit.exe', 'fontdrvhost.exe', 'searchhost.exe', 'startmenuexperiencehost.exe', 'shellexperiencehost.exe',
  'ctfmon.exe', 'lsaiso.exe', 'msmpeng.exe', 'mssense.exe', 'securityhealthservice.exe', 'system', 'registry', 'memory compression', 'kestrel-agent.exe',
])

const baseName = (image: string) => (image.split(/[\\/]/).pop() ?? image).toLowerCase()

const RISKY = new Set(['temp', 'downloads', 'user_writable', 'external'])

/**
 * Can this process be offered as a kill target? Never OS binaries, and never a
 * shell installed in a protected location (pwsh.exe in Program Files). A file
 * merely *named* like a shell in a user-writable folder is malware and is fair game.
 */
export function isSafeKillTarget(n: TreeNode): boolean {
  // Kestrel's own children (hardening PowerShell, scan, update msiexec) are never offered.
  if (n.agent_spawned) return false
  if (n.path_class === 'system' || n.path_class === 'windows') return false
  if (RISKY.has(n.path_class)) return true
  return !UNSAFE_KILL_TARGETS.has(baseName(n.image))
}

/**
 * The process an analyst most likely wants to kill/quarantine: an alerted process
 * that is safe to kill (most-alerted user-writable image first). When the alert
 * is on a shell or OS process (explorer.exe for ClickFix, powershell.exe…), its
 * safe descendant (the payload it started) is chosen instead. `null` when no
 * safe target exists — the Kill button is then disabled.
 */
export function pickTarget(nodes: TreeNode[]): TreeNode | null {
  const rank = (pool: TreeNode[]) =>
    [...pool].sort(
      (a, b) =>
        Number(RISKY.has(b.path_class)) - Number(RISKY.has(a.path_class)) ||
        b.alert_rule_ids.length - a.alert_rule_ids.length ||
        b.start_ts - a.start_ts,
    )[0] ?? null
  const alerted = nodes.filter((n) => n.alert_rule_ids.length > 0)
  const direct = alerted.filter(isSafeKillTarget)
  if (direct.length) return rank(direct)
  // Alerted processes are all shells / OS binaries: look at what they started.
  const children = new Map<string, TreeNode[]>()
  for (const n of nodes) if (n.parent_guid) children.set(n.parent_guid, [...(children.get(n.parent_guid) ?? []), n])
  const seen = new Set<string>()
  const descendants: TreeNode[] = []
  const queue = alerted.map((a) => a.guid)
  while (queue.length) {
    const g = queue.shift()!
    for (const c of children.get(g) ?? []) {
      if (seen.has(c.guid)) continue
      seen.add(c.guid)
      descendants.push(c)
      queue.push(c.guid)
    }
  }
  return rank(descendants.filter(isSafeKillTarget))
}

/** Rule ids that put an incident in the impact stage (+10): exfiltration, ransomware, credential dumping. */
export function impactStage(ruleIds: string[]): string | null {
  if (ruleIds.some((r) => r.startsWith('RW-'))) return 'Ransomware rule fired (RW-xx)'
  if (ruleIds.some((r) => r.startsWith('CD-'))) return 'Credential-dumping rule fired (CD-xx)'
  if (ruleIds.some((r) => r === 'ST-04' || r === 'ST-14')) return 'Exfiltration-stage rule fired (ST-04 / ST-14)'
  return null
}

/** Explains the 0-100 priority as the contract defines it. */
export function priorityFactors(i: Incident): { label: string; points: number }[] {
  const base = { info: 5, low: 20, medium: 45, high: 70, critical: 90 }[i.severity]
  const f = [{ label: `Highest alert severity: ${i.severity}`, points: base }]
  if (i.data_at_risk.length) f.push({ label: 'Credential stores were touched', points: 10 })
  const stage = impactStage(i.rule_ids)
  if (stage) f.push({ label: stage, points: 10 })
  if (!i.contained) f.push({ label: 'Not contained yet', points: 5 })
  return f
}

export function PriorityBreakdown({ incident }: { incident: Incident }) {
  const f = priorityFactors(incident)
  return (
    <div className="space-y-1.5">
      {f.map((x) => (
        <div key={x.label} className="flex items-center justify-between gap-3 text-sm">
          <span className="text-fg-muted">{x.label}</span>
          <span className="tabular font-medium">+{x.points}</span>
        </div>
      ))}
      <div className="flex items-center justify-between gap-3 border-t border-border pt-1.5 text-sm">
        <span className="font-medium">Priority (max 100)</span>
        <span className="tabular font-semibold">{incident.priority}</span>
      </div>
    </div>
  )
}

export function DataAtRiskPanel({ categories, user, compact }: { categories: DataCategory[]; user?: string | null; compact?: boolean }) {
  if (!categories.length)
    return (
      <p className="flex items-center gap-2 text-sm text-fg-muted">
        <CheckCircle2 className="size-4 text-ok" /> No credential stores were touched.
      </p>
    )
  // Cookies and the browser master key share one remediation; show it once.
  const shown = categories.filter((c) => !(c === 'browser_master_key' && categories.includes('browser_cookies')))
  return (
    <div>
      {user ? (
        <p className="mb-3 text-sm text-fg-muted">
          Treat these as stolen for <span className="font-medium text-fg">{user}</span>, even if Kestrel stopped the program.
        </p>
      ) : null}
      <ul className={cn('grid gap-2', !compact && 'sm:grid-cols-2')}>
        {shown.map((c) => (
          <li key={c} className="rounded-md border border-sev-high/25 bg-sev-high-soft/50 px-3 py-2">
            <div className="flex items-center gap-1.5 text-sm font-medium">
              <KeyRound className="size-3.5 text-sev-high" aria-hidden />
              {DATA_CATEGORY_LABEL[c]}
              {c === 'browser_cookies' && categories.includes('browser_master_key') ? <span className="text-xs font-normal text-fg-muted">+ encryption key</span> : null}
            </div>
            {!compact ? <p className="mt-0.5 text-xs leading-relaxed text-fg-muted">{DATA_CATEGORY_REMEDIATION[c]}</p> : null}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** The exact target of a remove_autorun, field by field, with bidi/control characters stripped. */
export function AutorunTarget({ action }: { action: Extract<ResponseAction, { type: 'remove_autorun' }> }) {
  const rows: [string, string][] = [
    ['Type', AUTORUN_KIND_LABEL[action.kind]],
    [action.kind === 'registry_value' ? 'Key' : 'Name', safeDisplay(action.location)],
  ]
  if (action.value_name != null) rows.push(['Value', safeDisplay(action.value_name) || '(default)'])
  if (action.restore_data != null) rows.push(['New data', safeDisplay(action.restore_data)])
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs" data-testid="autorun-target">
      {rows.map(([k, v]) => (
        <Fragment key={k}>
          <dt className="text-fg-subtle">{k}</dt>
          <dd className="font-mono text-fg [overflow-wrap:anywhere]">{v}</dd>
        </Fragment>
      ))}
    </dl>
  )
}

/** Why the Approve button is disabled; always names the missing privilege. */
export function approveDeniedReason(priv: string, canWriteIncidents: boolean): string {
  if (!canWriteIncidents) return 'Your role is missing the incidents.write privilege'
  return priv === 'response.persistence'
    ? 'Your role is missing the response.persistence privilege (admin only by default: it writes the registry as SYSTEM)'
    : `Your role is missing the ${priv} privilege`
}

const KIND_META = {
  done: { title: 'Already done by Kestrel', icon: Bot, empty: 'The agent took no automatic action.' },
  approve: { title: 'Needs your approval', icon: Zap, empty: 'Nothing waiting for approval.' },
  manual: { title: 'Manual steps', icon: Hand, empty: 'No manual steps.' },
} as const

export function RemediationChecklist({ incident }: { incident: IncidentDetail }) {
  const qc = useQueryClient()
  const { can } = useAuth()
  const [confirming, setConfirming] = useState<ChecklistItem | null>(null)
  const m = useMutation({
    mutationFn: (v: { item: ChecklistItem; done: boolean }) => api.setChecklist(incident.id, v.item.id, v.done),
    onMutate: async (v) => {
      await qc.cancelQueries({ queryKey: qk.incident(incident.id) })
      const prev = qc.getQueryData<IncidentDetail>(qk.incident(incident.id))
      if (prev) qc.setQueryData(qk.incident(incident.id), { ...prev, checklist: prev.checklist.map((c) => (c.id === v.item.id ? { ...c, done: v.done } : c)) })
      return { prev }
    },
    onError: (e, _v, ctx) => {
      if (ctx?.prev) qc.setQueryData(qk.incident(incident.id), ctx.prev)
      toast.error('Couldn’t update the checklist', { description: (e as Error).message })
    },
    onSuccess: (_d, v) => {
      if (v.item.kind === 'approve' && v.done) toast.success('Approved and sent', { description: v.item.action ? describeAction(v.item.action) : undefined })
      void qc.invalidateQueries({ queryKey: qk.incident(incident.id) })
      void qc.invalidateQueries({ queryKey: ['actions'] })
    },
  })
  const groups = (['done', 'approve', 'manual'] as const).map((k) => ({ k, items: incident.checklist.filter((c) => c.kind === k) }))
  const total = incident.checklist.length
  const done = incident.checklist.filter((c) => c.done).length
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-surface-3" role="progressbar" aria-valuenow={done} aria-valuemax={total} aria-label="Checklist progress">
          <div className="h-full rounded-full bg-ok transition-[width]" style={{ width: `${total ? (done / total) * 100 : 0}%` }} />
        </div>
        <span className="text-xs tabular text-fg-muted">
          {done} of {total} done
        </span>
      </div>
      {groups.map(({ k, items }) => {
        const meta = KIND_META[k]
        if (!items.length && k === 'done') return null
        return (
          <div key={k}>
            <h3 className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg-subtle">
              <meta.icon className="size-3.5" aria-hidden />
              {meta.title}
            </h3>
            {items.length === 0 ? (
              <p className="text-sm text-fg-subtle">{meta.empty}</p>
            ) : (
              <ul className="divide-y divide-border rounded-md border border-border">
                {items.map((it) => {
                  const priv = it.action ? actionPrivilege(it.action) : 'incidents.write'
                  const allowed = can(priv) && can('incidents.write')
                  return (
                    <li key={it.id} className="flex items-start gap-3 px-3 py-2">
                      {k === 'done' ? (
                        <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-label="Done" />
                      ) : k === 'manual' ? (
                        <button
                          type="button"
                          role="checkbox"
                          aria-checked={it.done}
                          disabled={!can('incidents.write')}
                          onClick={() => m.mutate({ item: it, done: !it.done })}
                          className="mt-0.5 shrink-0 rounded text-fg-subtle hover:text-fg disabled:opacity-50"
                          aria-label={it.done ? 'Mark as not done' : 'Mark as done'}
                        >
                          {it.done ? <CheckCircle2 className="size-4 text-ok" /> : <Circle className="size-4" />}
                        </button>
                      ) : it.done ? (
                        <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-label="Approved" />
                      ) : (
                        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-accent-text" aria-hidden />
                      )}
                      <div className="min-w-0 flex-1">
                        <p className={cn('text-sm [overflow-wrap:anywhere]', it.done && k !== 'done' && 'text-fg-muted line-through decoration-fg-subtle/60')}>{safeDisplay(it.text)}</p>
                        {it.action && k === 'approve' ? <p className="mt-0.5 font-mono text-[11.5px] text-fg-subtle [overflow-wrap:anywhere]">{describeAction(it.action)}</p> : null}
                      </div>
                      {k === 'approve' && !it.done ? (
                        <Tooltip content={allowed ? 'Sends the action to the device now' : approveDeniedReason(priv, can('incidents.write'))}>
                          <span>
                            <Button size="sm" variant="primary" disabled={!allowed || m.isPending} onClick={() => (it.action?.type === 'remove_autorun' ? setConfirming(it) : m.mutate({ item: it, done: true }))}>
                              <ClipboardCheck /> Approve
                            </Button>
                          </span>
                        </Tooltip>
                      ) : null}
                    </li>
                  )
                })}
              </ul>
            )}
          </div>
        )
      })}
      {confirming?.action?.type === 'remove_autorun' ? (
        <Dialog open onOpenChange={(o) => !o && setConfirming(null)}>
          <DialogContent
            title="Remove this persistence entry?"
            description={describeAction(confirming.action)}
            footer={
              <>
                <Button variant="ghost" onClick={() => setConfirming(null)}>
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  disabled={m.isPending}
                  onClick={() => {
                    m.mutate({ item: confirming, done: true })
                    setConfirming(null)
                  }}
                >
                  Remove entry
                </Button>
              </>
            }
          >
            <div className="space-y-2 text-sm text-fg-muted">
              <p>
                The agent re-reads the entry, backs it up to the quarantine vault, then{' '}
                {confirming.action.kind === 'service'
                  ? 'stops the service and sets it to disabled (it is not deleted)'
                  : confirming.action.restore_data != null
                    ? isCanonicalDefault(confirming.action.location, confirming.action.value_name, confirming.action.restore_data)
                      ? `writes the Windows default value ${safeDisplay(confirming.action.restore_data)}`
                      : `writes ${safeDisplay(confirming.action.restore_data)} (not a known Windows default — check it carefully)`
                    : 'deletes it'}
                . It refuses Kestrel’s own entries and protected Windows entries.
              </p>
              <AutorunTarget action={confirming.action} />
              <p>If this is legitimate software, the user loses whatever it started at logon until you restore it from the backup.</p>
            </div>
          </DialogContent>
        </Dialog>
      ) : null}
    </div>
  )
}
