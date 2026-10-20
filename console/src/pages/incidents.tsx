import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { ArrowDown, ArrowUp, Bookmark, BookmarkPlus, ChevronDown, ExternalLink, Layers, Radio, Trash2, X } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import { useLiveEvents } from '@/api/live'
import type { Incident, IncidentDetail, IncidentStatus, Severity } from '@/api/types'
import { IncidentStatusBadge, PriorityScore, SeverityBadge, SeverityIcon } from '@/components/badges'
import { AttackChips, Avatar, EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { BulkBar, DataTable } from '@/components/data-table'
import { FilterChip, SearchInput, useUrlList, useUrlString } from '@/components/filters'
import { AssigneeControl, ClassificationControl, StatusControl, useUpdateIncident } from '@/components/incident-controls'
import { DataAtRiskPanel, PriorityBreakdown, pickTarget } from '@/components/incident-parts'
import { Markdown } from '@/components/markdown'
import { Button } from '@/components/ui/button'
import { Sheet } from '@/components/ui/sheet'
import { Dropdown, DropdownContent, DropdownItem, DropdownLabel, DropdownSeparator, DropdownTrigger, Kbd, Skeleton, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { DATA_CATEGORY_LABEL, INCIDENT_STATUS_LABEL, SEVERITY_LABEL } from '@/lib/labels'
import { formatDateTime, timeAgo } from '@/lib/format'
import { loadJson, saveJson } from '@/lib/storage'
import { cn } from '@/lib/utils'
import { ConfirmActionDialog, type ActionSpec } from '@/components/response-actions'

const DEFAULT_STATUS = ['open', 'in_progress']

const BUILTIN_VIEWS: { name: string; params: string }[] = [
  { name: 'Needs triage', params: 'status=open,in_progress' },
  { name: 'Assigned to me', params: 'status=open,in_progress&assignee=me' },
  { name: 'Unassigned critical & high', params: 'status=open&severity=critical,high&assignee=none' },
  { name: 'Credentials exposed', params: 'status=open,in_progress,resolved&data=1' },
  { name: 'Closed last 14 days', params: 'status=resolved,dismissed' },
]
const VIEWS_KEY = 'kestrel.incident-views'

type GroupKey = 'none' | 'device' | 'severity' | 'assignee' | 'rule'

export default function Incidents() {
  const [sp, setSp] = useSearchParams()
  const nav = useNavigate()
  const { me, can } = useAuth()
  const [status, setStatus] = useUrlList('status', DEFAULT_STATUS)
  const [severity, setSeverity] = useUrlList('severity')
  const [assignee, setAssignee] = useUrlList('assignee')
  const [q, setQ] = useUrlString('q')
  const [group, setGroup] = useUrlString('group', 'none')
  const [sort, setSort] = useUrlString('sort', 'priority')
  const dataOnly = sp.get('data') === '1'
  const [active, setActive] = useState<string | null>(sp.get('open'))
  const [drawer, setDrawer] = useState<string | null>(sp.get('open'))
  const [selection, setSelection] = useState<Record<string, boolean>>({})
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  const [announce, setAnnounce] = useState('')
  const [paused, setPaused] = useState(false)
  const [pending, setPending] = useState(0)

  const query = { status: status.join(','), severity: severity.join(','), assignee: assignee[0], q, sort }
  const list = useQuery({
    queryKey: qk.incidents(query),
    queryFn: () => api.incidents(query),
    placeholderData: (p) => p,
  })
  // Pausing live updates keeps the analyst's place: the queue shows a frozen snapshot until they resume.
  const [frozen, setFrozen] = useState<Incident[] | null>(null)

  useLiveEvents(['incident'], (e) => {
    if (e.type === 'created') {
      if (paused) setPending((n) => n + 1)
      setFresh((s) => new Set(s).add(e.id))
      setAnnounce('New incident added to the queue')
      toast('New incident', { description: 'A new incident was added to the queue.', action: { label: 'Open', onClick: () => nav(`/incidents/${e.id}`) } })
      setTimeout(() => setFresh((s) => (s.delete(e.id), new Set(s))), 6000)
    }
  })

  const items = useMemo(() => (frozen ?? list.data?.items ?? []).filter((i) => !dataOnly || i.data_at_risk.length > 0), [frozen, list.data, dataOnly])
  const selectedIds = Object.keys(selection).filter((k) => selection[k])

  const openDrawer = useCallback(
    (id: string | null) => {
      setDrawer(id)
      if (id) setActive(id)
      setSp(
        (p) => {
          const n = new URLSearchParams(p)
          if (id) n.set('open', id)
          else n.delete('open')
          return n
        },
        { replace: true },
      )
    },
    [setSp],
  )

  const step = useCallback(
    (dir: 1 | -1) => {
      const i = items.findIndex((x) => x.id === drawer)
      const n = items[Math.max(0, Math.min(items.length - 1, i + dir))]
      if (n) openDrawer(n.id)
    },
    [items, drawer, openDrawer],
  )

  const columns = useMemo<ColumnDef<Incident, unknown>[]>(
    () => [
      { id: 'priority', header: 'Priority', accessorKey: 'priority', size: 92, cell: ({ row }) => <PriorityScore value={row.original.priority} className="text-xs" /> },
      { id: 'severity', header: 'Severity', accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), size: 100, cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
      {
        id: 'title',
        header: 'Incident',
        accessorKey: 'title',
        enableSorting: false,
        cell: ({ row }) => {
          const i = row.original
          return (
            <div className="min-w-0 max-w-[560px]">
              <div className="flex items-center gap-2">
                <span className="truncate font-medium">{i.title}</span>
                {!i.contained ? (
                  <span className="shrink-0 rounded bg-danger-soft px-1.5 py-px text-[11px] font-medium text-danger" title="The program may still be running">
                    Not contained
                  </span>
                ) : null}
              </div>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-fg-muted">
                <span className="font-mono">{i.rule_ids.slice(0, 4).join(' ')}</span>
                {i.data_at_risk.length ? (
                  <Tooltip content={i.data_at_risk.map((c) => DATA_CATEGORY_LABEL[c]).join(', ')}>
                    <span className="text-sev-high">
                      {i.data_at_risk.length} secret type{i.data_at_risk.length > 1 ? 's' : ''} at risk
                    </span>
                  </Tooltip>
                ) : null}
                <AttackChips ids={i.attack} max={2} className="hidden xl:inline-flex" />
              </div>
            </div>
          )
        },
      },
      {
        id: 'device',
        header: 'Device',
        accessorKey: 'hostname',
        cell: ({ row }) => (
          <div className="min-w-0">
            <Link to={`/devices/${row.original.device_id}`} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap font-mono text-[13px] hover:underline">
              {row.original.hostname}
            </Link>
            <div className="truncate text-xs text-fg-subtle">{row.original.user?.split('\\').pop() ?? '—'}</div>
          </div>
        ),
      },
      { id: 'status', header: 'Status', accessorKey: 'status', size: 120, cell: ({ row }) => <IncidentStatusBadge status={row.original.status} /> },
      {
        id: 'assignee',
        header: 'Owner',
        accessorFn: (r) => r.assignee?.name ?? '',
        size: 70,
        meta: { className: 'max-lg:hidden' },
        cell: ({ row }) => (
          <Tooltip content={row.original.assignee?.name ?? 'Unassigned'}>
            <span>
              <Avatar user={row.original.assignee} />
            </span>
          </Tooltip>
        ),
      },
      {
        id: 'created',
        header: 'Created',
        accessorKey: 'created_at',
        size: 100,
        meta: { className: 'max-lg:hidden' },
        cell: ({ row }) => (
          <Tooltip content={formatDateTime(row.original.created_at)}>
            <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(row.original.created_at)}</span>
          </Tooltip>
        ),
      },
    ],
    [],
  )

  const groupBy = useMemo(() => {
    const g = group as GroupKey
    if (g === 'none') return undefined
    return (i: Incident) => {
      switch (g) {
        case 'device':
          return { key: i.hostname, label: <span className="font-mono">{i.hostname}</span> }
        case 'severity':
          return { key: i.severity, label: <span className="inline-flex items-center gap-1.5"><SeverityIcon severity={i.severity} />{SEVERITY_LABEL[i.severity]}</span> }
        case 'assignee':
          return { key: i.assignee?.id ?? 'none', label: i.assignee?.name ?? 'Unassigned' }
        case 'rule':
          return { key: i.rule_ids[i.rule_ids.length - 1] ?? '', label: <span className="font-mono">{i.rule_ids[i.rule_ids.length - 1]}</span> }
        default:
          return { key: '', label: '' }
      }
    }
  }, [group])

  const update = useUpdateIncident()
  const bulk = async (patch: { status?: IncidentStatus; assignee_id?: string | null }) => {
    await Promise.all(selectedIds.map((id) => update.mutateAsync({ id, ...patch })))
    toast.success(`Updated ${selectedIds.length} incident${selectedIds.length > 1 ? 's' : ''}`)
    setSelection({})
  }

  const [views, setViews] = useState<{ name: string; params: string }[]>(() => loadJson(VIEWS_KEY, []))
  const currentParams = (() => {
    const n = new URLSearchParams(sp)
    n.delete('open')
    return n.toString()
  })()

  const togglePause = () => {
    if (paused) {
      setFrozen(null)
      setPending(0)
    } else setFrozen(list.data?.items ?? [])
    setPaused(!paused)
  }

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Incidents"
        description="Alerts grouped by device and process tree, ranked by priority."
        actions={
          <>
            <Tooltip content={paused ? 'Resume live updates' : 'Pause live updates to keep your place'}>
              <Button size="sm" variant="ghost" onClick={togglePause} aria-pressed={paused}>
                <Radio className={cn(!paused && 'text-ok')} />
                {paused ? (pending ? `Paused · ${pending} new` : 'Paused') : 'Live'}
              </Button>
            </Tooltip>
            <ViewsMenu
              views={views}
              current={currentParams}
              onPick={(p) => setSp(new URLSearchParams(p), { replace: true })}
              onSave={(name) => {
                const next = [...views.filter((v) => v.name !== name), { name, params: currentParams }]
                setViews(next)
                saveJson(VIEWS_KEY, next)
                toast.success(`Saved view “${name}”`)
              }}
              onDelete={(name) => {
                const next = views.filter((v) => v.name !== name)
                setViews(next)
                saveJson(VIEWS_KEY, next)
              }}
            />
          </>
        }
      >
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <SearchInput value={q} onChange={setQ} placeholder="Search title, device, user, rule…" className="w-64" />
          <FilterChip label="Status" value={status} onChange={setStatus} options={(Object.keys(INCIDENT_STATUS_LABEL) as IncidentStatus[]).map((s) => ({ value: s, label: INCIDENT_STATUS_LABEL[s] }))} />
          <FilterChip
            label="Severity"
            value={severity}
            onChange={setSeverity}
            options={(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => ({ value: s, label: <span className="inline-flex items-center gap-1.5"><SeverityIcon severity={s} className="size-3.5" />{SEVERITY_LABEL[s]}</span> }))}
          />
          <FilterChip label="Owner" single value={assignee} onChange={setAssignee} options={[{ value: 'me', label: 'Me' }, { value: 'none', label: 'Unassigned' }]} />
          <button
            type="button"
            onClick={() => setSp((p) => { const n = new URLSearchParams(p); if (dataOnly) n.delete('data'); else n.set('data', '1'); return n }, { replace: true })}
            className={cn('inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs', dataOnly ? 'border-accent/40 bg-accent-soft' : 'border-dashed border-border-strong text-fg-muted hover:text-fg')}
            aria-pressed={dataOnly}
          >
            Credentials at risk
          </button>
          {(severity.length || assignee.length || q || dataOnly || status.join() !== DEFAULT_STATUS.join()) ? (
            <button type="button" className="inline-flex h-7 items-center gap-1 px-1 text-xs text-fg-muted hover:text-fg" onClick={() => setSp(new URLSearchParams(), { replace: true })}>
              <X className="size-3" /> Reset
            </button>
          ) : null}
          <div className="ml-auto flex items-center gap-2">
            <Dropdown>
              <DropdownTrigger className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border-strong bg-surface px-2 text-xs hover:bg-surface-2">
                <Layers className="size-3.5 text-fg-subtle" /> Group: <span className="font-medium capitalize">{group === 'none' ? 'None' : group}</span> <ChevronDown className="size-3 opacity-60" />
              </DropdownTrigger>
              <DropdownContent>
                {(['none', 'device', 'severity', 'assignee', 'rule'] as GroupKey[]).map((g) => (
                  <DropdownItem key={g} onSelect={() => setGroup(g)} className="capitalize">
                    {g === 'none' ? 'No grouping' : g === 'rule' ? 'Latest rule' : g}
                  </DropdownItem>
                ))}
              </DropdownContent>
            </Dropdown>
            <Button size="sm" variant="ghost" onClick={() => setSort(sort === 'priority' ? 'created' : 'priority')}>
              {sort === 'priority' ? <ArrowDown /> : <ArrowUp />}
              {sort === 'priority' ? 'Priority' : 'Newest'}
            </Button>
          </div>
        </div>
      </PageHeader>

      <div aria-live="polite" className="sr-only">
        {announce}
      </div>

      <div className={cn('min-h-0 flex-1 bg-surface transition-[padding]', drawer && '2xl:pr-[560px]')}>
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows />
        ) : (
          <>
            <div className="flex items-center gap-3 border-b border-border px-4 py-1.5 text-xs text-fg-subtle">
              <span className="tabular">
                {items.length} incident{items.length === 1 ? '' : 's'}
              </span>
              <span className="hidden items-center gap-1 sm:inline-flex">
                <Kbd>J</Kbd>
                <Kbd>K</Kbd> move · <Kbd>Enter</Kbd> preview · <Kbd>X</Kbd> select
              </span>
              {list.isFetching ? <span className="ml-auto">Refreshing…</span> : null}
            </div>
            <DataTable
              label="Incident queue"
              data={items}
              columns={columns}
              getRowId={(r) => r.id}
              keyboard
              selectable={can('incidents.write')}
              selection={selection}
              onSelectionChange={setSelection}
              activeId={active}
              onActiveChange={(id) => {
                setActive(id)
                if (drawer && id) openDrawer(id)
              }}
              onRowClick={(r) => openDrawer(r.id)}
              onRowOpen={(r) => nav(`/incidents/${r.id}`)}
              groupBy={groupBy}
              groupSummary={(rows) => (
                <span className="flex items-center gap-1">
                  {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => {
                    const n = rows.filter((r) => r.severity === s).length
                    return n ? (
                      <span key={s} className="inline-flex items-center gap-0.5 text-xs text-fg-muted">
                        <SeverityIcon severity={s} className="size-3" />
                        {n}
                      </span>
                    ) : null
                  })}
                </span>
              )}
              highlightIds={fresh}
              initialSorting={[]}
              empty={
                <EmptyState title={q || severity.length || assignee.length ? 'No incidents match these filters' : 'Queue is clear'}>
                  {q || severity.length || assignee.length ? 'Remove a filter or search for something else.' : 'New detections will appear here as they happen.'}
                </EmptyState>
              }
              rowClassName={(r) => (r.status === 'resolved' || r.status === 'dismissed' ? 'opacity-70' : undefined)}
            />
          </>
        )}
      </div>

      <BulkBar count={selectedIds.length} onClear={() => setSelection({})}>
        <Button size="sm" onClick={() => bulk({ assignee_id: me.user.id })}>
          Assign to me
        </Button>
        <Button size="sm" onClick={() => bulk({ status: 'in_progress' })}>
          Mark in progress
        </Button>
        <Button size="sm" onClick={() => bulk({ status: 'resolved' })}>
          Resolve
        </Button>
        <Button size="sm" onClick={() => bulk({ status: 'dismissed' })}>
          Dismiss
        </Button>
      </BulkBar>

      <IncidentDrawer id={drawer} onClose={() => openDrawer(null)} onStep={step} position={drawer ? { index: items.findIndex((x) => x.id === drawer), total: items.length } : null} />
    </div>
  )
}

function ViewsMenu({ views, current, onPick, onSave, onDelete }: { views: { name: string; params: string }[]; current: string; onPick: (p: string) => void; onSave: (name: string) => void; onDelete: (name: string) => void }) {
  return (
    <Dropdown>
      <DropdownTrigger asChild>
        <Button size="sm">
          <Bookmark /> Views <ChevronDown className="opacity-60" />
        </Button>
      </DropdownTrigger>
      <DropdownContent className="w-64">
        <DropdownLabel>Built-in</DropdownLabel>
        {BUILTIN_VIEWS.map((v) => (
          <DropdownItem key={v.name} onSelect={() => onPick(v.params)}>
            {v.name}
          </DropdownItem>
        ))}
        {views.length ? (
          <>
            <DropdownSeparator />
            <DropdownLabel>Saved (this browser)</DropdownLabel>
            {views.map((v) => (
              <DropdownItem key={v.name} onSelect={() => onPick(v.params)} className="group">
                <span className="flex-1 truncate">{v.name}</span>
                <button
                  type="button"
                  aria-label={`Delete view ${v.name}`}
                  onClick={(e) => {
                    e.stopPropagation()
                    e.preventDefault()
                    onDelete(v.name)
                  }}
                  className="rounded p-0.5 opacity-0 hover:text-danger group-data-[highlighted]:opacity-100"
                >
                  <Trash2 className="size-3.5" />
                </button>
              </DropdownItem>
            ))}
          </>
        ) : null}
        <DropdownSeparator />
        <DropdownItem
          onSelect={() => {
            const name = window.prompt('Name this view', '')
            if (name?.trim()) onSave(name.trim())
          }}
          disabled={!current}
        >
          <BookmarkPlus /> Save current filters…
        </DropdownItem>
        <DropdownItem
          onSelect={() => {
            void navigator.clipboard?.writeText(location.href)
            toast.success('Link copied', { description: 'Anyone with access sees the same filters.' })
          }}
        >
          <ExternalLink /> Copy link to this view
        </DropdownItem>
      </DropdownContent>
    </Dropdown>
  )
}

function IncidentDrawer({ id, onClose, onStep, position }: { id: string | null; onClose: () => void; onStep: (d: 1 | -1) => void; position: { index: number; total: number } | null }) {
  const nav = useNavigate()
  const q = useQuery({ queryKey: qk.incident(id ?? ''), queryFn: () => api.incident(id!), enabled: !!id })
  const [action, setAction] = useState<ActionSpec | null>(null)

  useEffect(() => {
    if (!id) return
    const onKey = (e: KeyboardEvent) => {
      if (e.target instanceof HTMLInputElement || e.target instanceof HTMLTextAreaElement) return
      if (document.querySelector('[role="dialog"][data-state="open"]:not([data-drawer]), [role="menu"]')) return
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        onStep(1)
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        onStep(-1)
      } else if (e.key === 'o' && !e.metaKey && !e.ctrlKey) {
        e.preventDefault()
        nav(`/incidents/${id}`)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [id, onStep, nav])

  const inc = q.data
  return (
    <Sheet open={!!id} onOpenChange={(o) => !o && onClose()} label="Incident summary drawer">
      <div className="flex items-center gap-1 border-b border-border px-3 py-2">
        <Tooltip content="Previous (↑)">
          <Button size="icon-sm" variant="ghost" aria-label="Previous incident" onClick={() => onStep(-1)} disabled={!position || position.index <= 0}>
            <ArrowUp />
          </Button>
        </Tooltip>
        <Tooltip content="Next (↓)">
          <Button size="icon-sm" variant="ghost" aria-label="Next incident" onClick={() => onStep(1)} disabled={!position || position.index >= position.total - 1}>
            <ArrowDown />
          </Button>
        </Tooltip>
        {position && position.index >= 0 ? (
          <span className="px-1 text-xs tabular text-fg-subtle">
            {position.index + 1} of {position.total}
          </span>
        ) : null}
        <div className="ml-auto flex items-center gap-1">
          <Button size="sm" variant="primary" onClick={() => id && nav(`/incidents/${id}`)}>
            Open <Kbd className="border-white/25 bg-white/10 text-accent-fg">O</Kbd>
          </Button>
          <Button size="icon-sm" variant="ghost" aria-label="Close drawer" onClick={onClose}>
            <X />
          </Button>
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {q.error ? (
          <ErrorState error={q.error} onRetry={() => q.refetch()} />
        ) : !inc ? (
          <div className="space-y-3 p-5">
            <Skeleton className="h-6 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
            <Skeleton className="h-28" />
            <Skeleton className="h-20" />
          </div>
        ) : (
          <div className="space-y-6 p-5">
            <div>
              <div className="mb-2 flex flex-wrap items-center gap-2">
                <SeverityBadge severity={inc.severity} />
                <PriorityScore value={inc.priority} className="text-xs" />
                {inc.contained ? <span className="text-xs text-ok">Contained</span> : <span className="rounded bg-danger-soft px-1.5 py-px text-[11px] font-medium text-danger">Not contained</span>}
              </div>
              <h2 className="text-lg font-semibold leading-snug tracking-[-0.01em]">{inc.title}</h2>
              <p className="mt-1 text-xs text-fg-muted">
                <Link to={`/devices/${inc.device_id}`} className="font-mono hover:underline">
                  {inc.hostname}
                </Link>{' '}
                · {inc.user ?? 'no user'} · {formatDateTime(inc.created_at)} · {inc.alert_count} alert{inc.alert_count === 1 ? '' : 's'}
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                <StatusControl incident={inc} />
                <AssigneeControl incident={inc} />
                <ClassificationControl incident={inc} />
              </div>
            </div>
            <section aria-label="What happened">
              <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">What happened</h3>
              <Markdown source={inc.storyline} className="text-[14px]" />
            </section>
            <section aria-label="Data at risk">
              <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Data at risk</h3>
              <DataAtRiskPanel categories={inc.data_at_risk} compact />
            </section>
            <QuickActions inc={inc} onPick={setAction} />
            <section aria-label="Alerts">
              <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Alerts</h3>
              <ol className="space-y-1.5">
                {inc.alerts.map((a) => (
                  <li key={a.id} className="flex items-start gap-2 text-sm">
                    <SeverityIcon severity={a.severity} className="mt-0.5 size-3.5 shrink-0" />
                    <div className="min-w-0">
                      <span className="font-mono text-xs text-fg-muted">{a.rule_id}</span> {a.summary}
                      {a.rule_author ? <span className="block text-[11px] text-fg-subtle">Rule by {a.rule_author}</span> : null}
                    </div>
                  </li>
                ))}
              </ol>
            </section>
            <section aria-label="Why this priority">
              <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Why this priority</h3>
              <PriorityBreakdown incident={inc} />
            </section>
          </div>
        )}
      </div>
      {inc ? <ConfirmActionDialog open={!!action} onOpenChange={(o) => !o && setAction(null)} spec={action} device={{ id: inc.device_id, hostname: inc.hostname, status: 'online' }} incidentId={inc.id} /> : null}
    </Sheet>
  )
}

function QuickActions({ inc, onPick }: { inc: IncidentDetail; onPick: (s: ActionSpec) => void }) {
  const { can } = useAuth()
  const root = pickTarget(inc.process_tree)
  const pending = inc.checklist.filter((c) => c.kind === 'approve' && !c.done).length
  const specs: { spec: ActionSpec; label: string; disabled?: string }[] = []
  if (root) specs.push({ spec: { action: { type: 'kill_process', pid: root.pid, guid: root.guid, tree: true }, destructive: true }, label: `Kill ${root.image.split('\\').pop()}` })
  else specs.push({ spec: { action: { type: 'kill_process', pid: 0, guid: null, tree: true }, destructive: true }, label: 'Kill process', disabled: 'No safe process to kill (only shell or system processes alerted)' })
  specs.push({ spec: { action: { type: 'isolate_host', allow_ips: [] }, destructive: true, impact: 'Cuts all network traffic except to the Kestrel server. The user loses internet and file shares until released.' }, label: 'Isolate host' })
  specs.push({ spec: { action: { type: 'collect_triage' } }, label: 'Collect triage' })
  return (
    <section aria-label="Quick actions">
      <h3 className="mb-1.5 flex items-center gap-2 text-xs font-medium text-fg-subtle">
        Quick actions
        {pending ? <span className="rounded bg-accent-soft px-1.5 py-px text-[11px] text-accent-text">{pending} awaiting approval on the full page</span> : null}
      </h3>
      <div className="flex flex-wrap gap-2">
        {specs.map((s) => (
          <Button key={s.label} size="sm" title={s.disabled} variant={s.spec.destructive ? 'danger-outline' : 'secondary'} disabled={!!s.disabled || (!can('response.process') && !can('response.network'))} onClick={() => onPick(s.spec)}>
            {s.label}
          </Button>
        ))}
      </div>
    </section>
  )
}
