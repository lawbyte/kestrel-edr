import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Anchor, Ban, Bot, ChevronLeft, ChevronRight, FileArchive, Lock, LockOpen, MessageSquare, PackageSearch, ShieldBan, Skull, Siren, Unlink, Activity as ActivityIcon, Wifi } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { AlertRow, IncidentDetail, KEvent, TimelineEntry, TreeNode } from '@/api/types'
import { ActionStatusBadge, ModeBadge, PriorityScore, ProvenanceBadges, SeverityBadge, SeverityIcon } from '@/components/badges'
import { AttackChips, Avatar, Card, EmptyState, ErrorState, KeyValue, LoadingRows, Mono } from '@/components/common'
import { AssigneeControl, ClassificationControl, StatusControl } from '@/components/incident-controls'
import { DataAtRiskPanel, PriorityBreakdown, RemediationChecklist, pickTarget } from '@/components/incident-parts'
import { Markdown } from '@/components/markdown'
import { ProcessDetail, ProcessTree } from '@/components/process-tree'
import { ActionButton, BlockDestinationDialog, ConfirmActionDialog, liftBlockSpec, type ActionSpec } from '@/components/response-actions'
import { Button } from '@/components/ui/button'
import { Textarea } from '@/components/ui/input'
import { Tabs, TabsContent, TabsList, TabsTrigger, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { describeAction, EVENT_KIND_LABEL } from '@/lib/labels'
import { describeEvent, withAgentSpawned } from '@/lib/events'
import { formatDateTime, formatTime, safeDisplay, timeAgo } from '@/lib/format'
import { basename, cn } from '@/lib/utils'
import { ExclusionDialog } from './exclusions'

export default function IncidentPage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: qk.incident(id), queryFn: () => api.incident(id) })
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} className="h-full" />
  if (!q.data) return <LoadingRows rows={12} className="p-6" />
  return <IncidentView inc={q.data} />
}

function IncidentView({ inc }: { inc: IncidentDetail }) {
  const nav = useNavigate()
  const device = useQuery({ queryKey: qk.device(inc.device_id), queryFn: () => api.device(inc.device_id), staleTime: 30_000 })
  const dev = device.data?.device
  const isolated = dev?.status === 'isolated'
  const tree = useMemo(() => withAgentSpawned(inc.process_tree, inc.evidence), [inc.process_tree, inc.evidence])
  const [selected, setSelected] = useState<string | null>(() => pickTarget(tree)?.guid ?? tree[0]?.guid ?? null)
  const [action, setAction] = useState<ActionSpec | null>(null)
  const [blockOpen, setBlockOpen] = useState<{ ip?: string; port?: number | null; image?: string | null } | null>(null)
  const [excludeFrom, setExcludeFrom] = useState<AlertRow | null>(null)
  const selNode = tree.find((n) => n.guid === selected) ?? null
  const byGuid = useMemo(() => new Map(tree.map((n) => [n.guid, n])), [tree])
  const target = pickTarget(tree)
  const devRef = { id: inc.device_id, hostname: inc.hostname, status: dev?.status ?? 'online' }
  const pendingApprovals = inc.checklist.filter((c) => c.kind === 'approve' && !c.done).length
  const lastNet = inc.network.filter((n) => !n.blocked && n.dst_ip !== '127.0.0.1').slice(-1)[0]

  return (
    <div className="pb-16">
      {/* Header */}
      <div className="border-b border-border px-6 pb-4 pt-4">
        <button type="button" onClick={() => (history.length > 1 ? nav(-1) : nav('/incidents'))} className="mb-2 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
          <ChevronLeft className="size-3.5" /> Incidents
        </button>
        <div className="flex flex-wrap items-start gap-x-6 gap-y-3">
          <div className="min-w-0 flex-1">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <SeverityBadge severity={inc.severity} />
              <Tooltip content={<PriorityBreakdown incident={inc} />}>
                <span tabIndex={0}>
                  <PriorityScore value={inc.priority} className="text-xs" />
                </span>
              </Tooltip>
              {inc.contained ? (
                <span className="inline-flex items-center gap-1 text-xs font-medium text-ok">
                  <ShieldBan className="size-3.5" /> Contained
                </span>
              ) : (
                <span className="inline-flex items-center gap-1 rounded bg-danger-soft px-1.5 py-px text-xs font-medium text-danger">
                  <Siren className="size-3.5" /> Not contained
                </span>
              )}
              {isolated ? (
                <span className="inline-flex items-center gap-1 rounded bg-isolated-soft px-1.5 py-px text-xs font-medium text-isolated">
                  <Lock className="size-3.5" /> Host isolated
                </span>
              ) : null}
            </div>
            <h1 className="text-[1.375rem] font-semibold leading-snug tracking-[-0.01em]">{inc.title}</h1>
            <p className="mt-1 text-sm text-fg-muted">
              <Link to={`/devices/${inc.device_id}`} className="font-mono text-fg hover:underline">
                {inc.hostname}
              </Link>
              <span className="mx-1.5 text-fg-subtle">/</span>
              {inc.user ?? 'no signed-in user'}
              <span className="mx-1.5 text-fg-subtle">/</span>
              first alert {formatDateTime(inc.created_at)} ({timeAgo(inc.created_at)})
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <StatusControl incident={inc} />
            <AssigneeControl incident={inc} />
            <ClassificationControl incident={inc} />
          </div>
        </div>
      </div>

      {/* Sticky response bar */}
      <div className="sticky top-0 z-20 flex flex-wrap items-center gap-2 border-b border-border bg-bg/90 px-6 py-2 backdrop-blur" role="toolbar" aria-label="Response actions">
        {target ? (
          <ActionButton spec={{ action: { type: 'kill_process', pid: target.pid, guid: target.guid, tree: true }, destructive: true, impact: `Ends ${safeDisplay(basename(target.image))} (PID ${target.pid}) and every process it started.` }} label={`Kill ${safeDisplay(basename(target.image))}`} onPick={setAction} />
        ) : (
          <ActionButton
            spec={{ action: { type: 'kill_process', pid: 0, guid: null, tree: true }, destructive: true }}
            label="Kill process"
            onPick={setAction}
            disabledReason="No safe process to kill: the alerted processes are Windows shell or system binaries. Kill a specific child from the process tree instead."
          />
        )}
        {target && target.path_class !== 'system' ? (
          <ActionButton spec={{ action: { type: 'quarantine_file', path: target.image, sha256: target.sha256 }, destructive: true, impact: 'Moves the file into Kestrel’s encrypted vault on the device. You can restore it from Quarantine.' }} onPick={setAction} />
        ) : null}
        {isolated ? (
          <ActionButton spec={{ action: { type: 'release_host' }, impact: pendingApprovals ? `${pendingApprovals} checklist item(s) still need approval. Release only once the device is clean.` : 'Restores normal network access.' }} onPick={setAction} />
        ) : (
          <ActionButton spec={{ action: { type: 'isolate_host', allow_ips: [] }, destructive: true, impact: 'Cuts all network traffic except to the Kestrel server. The user loses internet and file shares until released.' }} onPick={setAction} />
        )}
        <Button size="sm" onClick={() => setBlockOpen({ ip: lastNet?.dst_ip, port: lastNet?.dst_port, image: lastNet?.image })}>
          <Ban /> Block destination
        </Button>
        <ActionButton spec={{ action: { type: 'collect_triage' }, impact: 'Uploads the process list, recent events and autoruns from the device. Takes about a minute.' }} label="Collect triage" onPick={setAction} />
        {pendingApprovals ? (
          <a href="#remediation" className="ml-auto inline-flex items-center gap-1.5 rounded-md bg-accent-soft px-2.5 py-1 text-xs font-medium text-accent-text hover:underline">
            {pendingApprovals} action{pendingApprovals > 1 ? 's' : ''} awaiting approval
          </a>
        ) : null}
      </div>

      <div className="grid gap-5 p-6 xl:grid-cols-[minmax(0,1fr)_380px]">
        <div className="min-w-0 space-y-5">
          {/* Storyline */}
          <section aria-label="What happened" className="rounded-lg border border-border bg-surface px-5 py-4">
            <h2 className="mb-2 text-xs font-medium text-fg-subtle">What happened</h2>
            <Markdown source={inc.storyline} links="none" className="text-[15px] leading-[1.65]" />
            <KillChain alerts={inc.alerts} />
          </section>

          <Card title="Data at risk" description="Secret categories the program touched, with what to do about each">
            <DataAtRiskPanel categories={inc.data_at_risk} user={inc.user} />
          </Card>

          <Card title="Process tree" bodyClassName="p-0" description="Top-down from the earliest recorded ancestor. Click a process for details.">
            <div className="grid lg:grid-cols-[minmax(0,1fr)_320px]">
              <ProcessTree nodes={tree} selected={selected} onSelect={setSelected} className="border-b border-border lg:border-b-0 lg:border-r" />
              <div className="p-4">{selNode ? <ProcessDetail node={selNode} parent={selNode.parent_guid ? byGuid.get(selNode.parent_guid) : undefined} /> : <p className="text-sm text-fg-muted">Select a process.</p>}</div>
            </div>
          </Card>

          <Tabs defaultValue="alerts">
            <TabsList>
              <TabsTrigger value="alerts">Alerts <Count n={inc.alerts.length} /></TabsTrigger>
              <TabsTrigger value="timeline">Timeline <Count n={inc.timeline.length} /></TabsTrigger>
              <TabsTrigger value="network">Network <Count n={inc.network.length} /></TabsTrigger>
              <TabsTrigger value="evidence">Evidence <Count n={inc.evidence.length} /></TabsTrigger>
              <TabsTrigger value="actions">Actions <Count n={inc.actions.length} /></TabsTrigger>
            </TabsList>
            <TabsContent value="alerts" className="pt-3">
              <AlertList alerts={inc.alerts} onExclude={setExcludeFrom} onSelectProcess={(g) => setSelected(g)} />
            </TabsContent>
            <TabsContent value="timeline" className="pt-3">
              <Timeline entries={inc.timeline} />
            </TabsContent>
            <TabsContent value="network" className="pt-3">
              <NetworkTable rows={inc.network} onBlock={(r) => setBlockOpen({ ip: r.dst_ip, port: r.dst_port, image: r.image })} />
            </TabsContent>
            <TabsContent value="evidence" className="pt-3">
              <EvidenceTable events={inc.evidence} nodes={byGuid} />
            </TabsContent>
            <TabsContent value="actions" className="pt-3">
              <ActionsList inc={inc} onPick={setAction} />
            </TabsContent>
          </Tabs>
        </div>

        <aside className="min-w-0 space-y-5">
          <Card title="Remediation" id="remediation" description="What Kestrel did, what needs your approval, and what you must do yourself">
            <RemediationChecklist incident={inc} />
          </Card>
          <Card title="Details">
            <KeyValue
              cols={1}
              items={[
                ['Rules', <span className="font-mono text-xs">{inc.rule_ids.join(', ')}</span>],
                ['MITRE ATT&CK', <AttackChips ids={inc.attack} max={8} />],
                ['Device', <Link to={`/devices/${inc.device_id}`} className="font-mono hover:underline">{inc.hostname}</Link>],
                ['Device status', dev ? <span className="capitalize">{dev.status}</span> : '—'],
                ['Last updated', `${formatDateTime(inc.updated_at)}`],
                ['Incident id', <Mono className="text-xs text-fg-muted">{inc.id}</Mono>],
              ]}
            />
          </Card>
          <Comments inc={inc} />
        </aside>
      </div>

      <ConfirmActionDialog open={!!action} onOpenChange={(o) => !o && setAction(null)} spec={action} device={devRef} incidentId={inc.id} />
      {blockOpen ? <BlockDestinationDialog open onOpenChange={(o) => !o && setBlockOpen(null)} device={devRef} incidentId={inc.id} defaults={blockOpen} /> : null}
      {excludeFrom ? <ExclusionDialog open onOpenChange={(o) => !o && setExcludeFrom(null)} fromAlert={excludeFrom} processHint={byGuid.get(excludeFrom.process_guid)} /> : null}
    </div>
  )
}

function Count({ n }: { n: number }) {
  return <span className="rounded bg-surface-3 px-1 text-[11px] tabular text-fg-muted">{n}</span>
}

const STAGES = [
  { key: 'delivery', label: 'Delivery', rules: ['ST-10', 'ST-11', 'ST-12', 'ST-15'] },
  { key: 'execution', label: 'Execution', rules: ['ST-12', 'ST-13', 'ST-15'] },
  { key: 'collection', label: 'Credential access', rules: ['ST-01', 'ST-02', 'ST-03', 'ST-05', 'ST-06', 'ST-07', 'ST-08', 'ST-09', 'ST-16'] },
  { key: 'exfil', label: 'Exfiltration', rules: ['ST-04', 'ST-14'] },
]
/** General-malware stages, shown only when one of their rules fired. */
const EXTRA_STAGES = [
  { key: 'persistence', label: 'Persistence', rules: ['PS-'] },
  { key: 'creddump', label: 'Credential dumping', rules: ['CD-'] },
  { key: 'impact', label: 'Impact (ransomware)', rules: ['RW-'] },
]

function KillChain({ alerts }: { alerts: AlertRow[] }) {
  const hit = (rules: string[]) => alerts.some((a) => rules.some((r) => (r.endsWith('-') ? a.rule_id.startsWith(r) : a.rule_id === r)))
  const stages = [...STAGES, ...EXTRA_STAGES.filter((s) => hit(s.rules))]
  return (
    <ol className="mt-4 flex flex-wrap items-center gap-1 border-t border-border pt-3 text-xs" aria-label="Attack stages reached">
      {stages.map((s, i) => {
        const on = hit(s.rules)
        return (
          <li key={s.key} className="flex items-center gap-1">
            <span className={cn('inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5', on ? 'border-sev-high/40 bg-sev-high-soft font-medium text-sev-high' : 'border-border text-fg-subtle')}>
              <span className={cn('size-1.5 rounded-full', on ? 'bg-sev-high' : 'bg-border-strong')} aria-hidden />
              {s.label}
              <span className="sr-only">{on ? ' reached' : ' not seen'}</span>
            </span>
            {i < stages.length - 1 ? <ChevronRight className="size-3 text-fg-subtle" aria-hidden /> : null}
          </li>
        )
      })}
    </ol>
  )
}

function AlertList({ alerts, onExclude, onSelectProcess }: { alerts: AlertRow[]; onExclude: (a: AlertRow) => void; onSelectProcess: (guid: string) => void }) {
  const { can } = useAuth()
  return (
    <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
      {alerts.map((a) => (
        <li key={a.id} className="flex flex-wrap items-start gap-3 px-4 py-3">
          <SeverityIcon severity={a.severity} className="mt-0.5" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <Link to={`/rules?rule=${a.rule_id}`} className="font-mono text-xs text-fg-muted hover:underline">
                {a.rule_id}
              </Link>
              <span className="font-medium">{a.rule_name}</span>
              <ModeBadge mode={a.mode} />
            </div>
            <p className="mt-0.5 text-sm text-fg-muted">{a.summary}</p>
            {a.rule_author ? (
              <p className="mt-0.5 text-xs text-fg-subtle">
                Rule by <span className="text-fg-muted">{a.rule_author}</span> (Detection Rule License 1.1)
              </p>
            ) : null}
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
              <button type="button" onClick={() => onSelectProcess(a.process_guid)} className="font-mono text-fg-muted hover:text-fg hover:underline">
                {basename(a.image)}
              </button>
              <AttackChips ids={a.attack} max={3} />
              {a.actions.map((o, i) => (
                <span key={i} className={cn('inline-flex items-center gap-1 rounded px-1.5 py-px', o.ok ? 'bg-ok-soft text-ok' : 'bg-danger-soft text-danger')}>
                  <Bot className="size-3" /> {describeAction(o.action)}
                  {o.ok && o.action.type === 'remove_autorun' && o.artifact ? <span className="font-mono opacity-80">· backup {o.artifact}</span> : null}
                </span>
              ))}
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <span className="text-xs tabular text-fg-subtle">{formatTime(a.ts)}</span>
            {can('exclusions.write') ? (
              <Button size="sm" variant="ghost" onClick={() => onExclude(a)}>
                Exclude…
              </Button>
            ) : null}
          </div>
        </li>
      ))}
    </ul>
  )
}

const TL_ICON = { alert: Siren, action: Bot, comment: MessageSquare, status: ActivityIcon }

function Timeline({ entries }: { entries: TimelineEntry[] }) {
  if (!entries.length) return <EmptyState title="Nothing on the timeline yet" />
  const t0 = entries[0].ts
  return (
    <ol className="relative ml-2 border-l border-border pl-5">
      {entries.map((e, i) => {
        const Icon = TL_ICON[e.kind]
        return (
          <li key={i} className="relative pb-4 last:pb-0">
            <span className={cn('absolute -left-[31px] flex size-5 items-center justify-center rounded-full border border-border bg-surface', e.kind === 'alert' && 'border-sev-high/40 text-sev-high', e.kind === 'action' && 'text-ok')}>
              <Icon className="size-3" aria-hidden />
            </span>
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className="text-sm font-medium">{e.title}</span>
              <span className="text-xs text-fg-subtle">{e.actor ?? ''}</span>
              <span className="ml-auto text-xs tabular text-fg-subtle">
                {formatTime(e.ts)} <span className="text-fg-subtle/70">(+{Math.round((e.ts - t0) / 1000)}s)</span>
              </span>
            </div>
            {e.detail ? <p className="mt-0.5 text-sm text-fg-muted">{e.detail}</p> : null}
          </li>
        )
      })}
    </ol>
  )
}

function NetworkTable({ rows, onBlock }: { rows: IncidentDetail['network']; onBlock: (r: IncidentDetail['network'][number]) => void }) {
  if (!rows.length) return <EmptyState icon={Wifi} title="No network connections recorded" />
  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-surface">
      <table className="w-full text-sm">
        <thead className="text-xs text-fg-subtle">
          <tr className="border-b border-border">
            <th className="px-3 py-2 text-left font-medium">Time</th>
            <th className="px-3 py-2 text-left font-medium">Process</th>
            <th className="px-3 py-2 text-left font-medium">Destination</th>
            <th className="px-3 py-2 text-left font-medium">Result</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr key={i} className="border-b border-border last:border-0">
              <td className="whitespace-nowrap px-3 py-2 text-xs tabular text-fg-muted">{formatTime(r.ts)}</td>
              <td className="px-3 py-2 font-mono text-[12.5px]">{basename(r.image)}</td>
              <td className="px-3 py-2">
                <span className="font-mono text-[12.5px]">
                  {r.dst_ip}:{r.dst_port}
                </span>
                {r.dst_host ? <span className="ml-2 text-xs text-fg-muted">{r.dst_host}</span> : null}
              </td>
              <td className="px-3 py-2">
                {r.blocked ? (
                  <span className="inline-flex items-center gap-1 rounded bg-ok-soft px-1.5 py-px text-xs font-medium text-ok">
                    <Ban className="size-3" /> Blocked
                  </span>
                ) : (
                  <span className="text-xs text-fg-muted">Allowed</span>
                )}
              </td>
              <td className="px-3 py-2 text-right">
                {!r.blocked && r.dst_ip !== '127.0.0.1' ? (
                  <Button size="sm" variant="ghost" onClick={() => onBlock(r)}>
                    Block
                  </Button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function EvidenceTable({ events, nodes }: { events: KEvent[]; nodes?: Map<string, TreeNode> }) {
  const [open, setOpen] = useState<Set<number>>(new Set())
  if (!events.length) return <EmptyState title="No evidence events" />
  return (
    <div className="overflow-x-auto rounded-lg border border-border bg-surface">
      <table className="w-full text-sm">
        <thead className="text-xs text-fg-subtle">
          <tr className="border-b border-border">
            <th className="w-6" />
            <th className="px-3 py-2 text-left font-medium">Time</th>
            <th className="px-3 py-2 text-left font-medium">Type</th>
            <th className="px-3 py-2 text-left font-medium">Process</th>
            <th className="px-3 py-2 text-left font-medium">Details</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => {
            const isOpen = open.has(i)
            const proc = nodes?.get(e.guid)
            return (
              <FragmentRow key={i}>
                <tr
                  className="cursor-pointer border-b border-border hover:bg-surface-2/60"
                  onClick={() =>
                    setOpen((s) => {
                      const n = new Set(s)
                      if (n.has(i)) n.delete(i)
                      else n.add(i)
                      return n
                    })
                  }
                  aria-expanded={isOpen}
                >
                  <td className="pl-2">
                    <ChevronRight className={cn('size-3.5 text-fg-subtle transition-transform', isOpen && 'rotate-90')} />
                  </td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-xs tabular text-fg-muted">{formatTime(e.ts)}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 text-xs">{EVENT_KIND_LABEL[e.type]}</td>
                  <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[12px]">
                    <span className="inline-flex items-center gap-1.5">
                      {e.type === 'file_activity' && e.remote_writer ? 'System' : proc ? basename(proc.image) : e.pid}
                      <ProvenanceBadges event={e} />
                    </span>
                  </td>
                  <td className="max-w-[520px] truncate px-3 py-1.5 font-mono text-[12px] text-fg-muted">{describeEvent(e)}</td>
                </tr>
                {isOpen ? (
                  <tr className="border-b border-border bg-surface-2/50">
                    <td />
                    <td colSpan={4} className="px-3 py-2">
                      <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-[11.5px] leading-relaxed">{JSON.stringify(e, null, 2)}</pre>
                    </td>
                  </tr>
                ) : null}
              </FragmentRow>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
function FragmentRow({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}

function ActionsList({ inc, onPick }: { inc: IncidentDetail; onPick: (s: ActionSpec) => void }) {
  if (!inc.actions.length) return <EmptyState title="No response actions yet" />
  const icon = (t: string) => (t === 'kill_process' ? Skull : t === 'quarantine_file' ? FileArchive : t === 'isolate_host' ? Lock : t === 'release_host' ? LockOpen : t === 'unblock_network' ? Unlink : t === 'collect_triage' ? PackageSearch : t === 'remove_autorun' ? Anchor : Ban)
  return (
    <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
      {[...inc.actions].sort((a, b) => b.created_at - a.created_at).map((a) => {
        const Icon = icon(a.action.type)
        return (
          <li key={a.id} className="flex flex-wrap items-start gap-3 px-4 py-2.5">
            <Icon className="mt-0.5 size-4 text-fg-subtle" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium">{describeAction(a.action)}</p>
              <p className="text-xs text-fg-muted">
                {a.requested_by ? `Requested by ${a.requested_by.name}` : 'Automatic (Protect mode)'}
                {a.comment ? ` · “${a.comment}”` : ''}
              </p>
              {a.result_detail ? <p className="text-xs text-fg-subtle">{a.result_detail}</p> : null}
              {a.artifact && a.action.type === 'remove_autorun' ? (
                <p className="text-xs text-fg-muted">
                  Original backed up to the quarantine vault as <span className="font-mono">{a.artifact}</span>
                </p>
              ) : null}
            </div>
            <div className="flex flex-col items-end gap-0.5">
              <ActionStatusBadge status={a.status} />
              <span className="text-xs tabular text-fg-subtle">{formatTime(a.created_at)}</span>
              {(() => {
                const lift = liftBlockSpec(a.action, a.status, a.artifact)
                return lift ? <ActionButton spec={lift} label="Lift block" onPick={onPick} /> : null
              })()}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function Comments({ inc }: { inc: IncidentDetail }) {
  const qc = useQueryClient()
  const { me, can } = useAuth()
  const [body, setBody] = useState('')
  const m = useMutation({
    mutationFn: () => api.addComment(inc.id, body),
    onSuccess: () => {
      setBody('')
      void qc.invalidateQueries({ queryKey: qk.incident(inc.id) })
    },
    onError: (e) => toast.error('Comment not posted', { description: (e as Error).message }),
  })
  return (
    <Card title={`Comments (${inc.comments.length})`}>
      <ul className="space-y-4">
        {inc.comments.map((c) => (
          <li key={c.id} className="flex gap-2.5">
            <Avatar user={c.author} />
            <div className="min-w-0">
              <p className="text-xs">
                <span className="font-medium">{c.author.name}</span> <span className="text-fg-subtle">{timeAgo(c.ts)}</span>
              </p>
              <p className="mt-0.5 whitespace-pre-wrap text-sm text-fg-muted">{c.body}</p>
            </div>
          </li>
        ))}
        {inc.comments.length === 0 ? <li className="text-sm text-fg-subtle">No comments yet. Record what you found and who you spoke to.</li> : null}
      </ul>
      {can('incidents.write') ? (
        <form
          className="mt-4 space-y-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (body.trim()) m.mutate()
          }}
        >
          <div className="flex gap-2.5">
            <Avatar user={me.user} />
            <Textarea
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder="Add a comment…"
              aria-label="Add a comment"
              className="min-h-16"
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.metaKey || e.ctrlKey) && body.trim()) m.mutate()
              }}
            />
          </div>
          <div className="flex justify-end">
            <Button size="sm" type="submit" disabled={!body.trim() || m.isPending}>
              Comment
            </Button>
          </div>
        </form>
      ) : null}
    </Card>
  )
}
