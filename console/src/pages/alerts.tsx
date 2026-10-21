import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { ChevronDown, Layers, ShieldOff } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { AlertRow, AlertStatus, Severity } from '@/api/types'
import { ModeBadge, SeverityBadge, SeverityIcon } from '@/components/badges'
import { AttackChips, EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { BulkBar, DataTable } from '@/components/data-table'
import { FilterChip, SearchInput, useUrlList, useUrlString } from '@/components/filters'
import { Button } from '@/components/ui/button'
import { Dropdown, DropdownContent, DropdownItem, DropdownTrigger, Kbd, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { DATA_CATEGORY_LABEL, SEVERITY_LABEL } from '@/lib/labels'
import { formatDateTime, timeAgo } from '@/lib/format'
import { protectionOffNote } from '@/lib/pause'
import { basename, cn } from '@/lib/utils'
import { ExclusionDialog } from './exclusions'

const STATUS_LABEL: Record<AlertStatus, string> = { new: 'New', acknowledged: 'Acknowledged', closed: 'Closed' }

export default function Alerts() {
  const qc = useQueryClient()
  const nav = useNavigate()
  const { can } = useAuth()
  const [status, setStatus] = useUrlList('status', ['new', 'acknowledged'])
  const [severity, setSeverity] = useUrlList('severity')
  const [q, setQ] = useUrlString('q')
  const [group, setGroup] = useUrlString('group', 'rule')
  const [selection, setSelection] = useState<Record<string, boolean>>({})
  const [active, setActive] = useState<string | null>(null)
  const [exclude, setExclude] = useState<AlertRow | null>(null)
  const query = { status: status.join(','), severity: severity.join(','), q }
  const list = useQuery({ queryKey: qk.alerts(query), queryFn: () => api.alerts(query), placeholderData: (p) => p })
  const items = list.data?.items ?? []
  const ids = Object.keys(selection).filter((k) => selection[k])

  const bulk = useMutation({
    mutationFn: (s: AlertStatus) => api.patchAlerts(ids, s),
    onSuccess: (_d, s) => {
      toast.success(`${ids.length} alert${ids.length === 1 ? '' : 's'} ${s === 'closed' ? 'closed' : 'acknowledged'}`)
      setSelection({})
      void qc.invalidateQueries({ queryKey: ['alerts'] })
    },
  })

  const cols = useMemo<ColumnDef<AlertRow, unknown>[]>(
    () => [
      { header: 'Severity', id: 'sev', accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), size: 100, cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
      {
        header: 'Alert',
        id: 'alert',
        accessorKey: 'rule_name',
        cell: ({ row }) => {
          const a = row.original
          return (
            <div className="min-w-0 max-w-[520px]">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-fg-muted">{a.rule_id}</span>
                <span className="truncate font-medium">{a.rule_name}</span>
                <ModeBadge mode={a.mode} />
              </div>
              <p className="mt-0.5 truncate text-xs text-fg-muted">{a.summary}</p>
              {a.protection_off ? (
                <p className="mt-0.5 flex items-center gap-1 text-xs text-warn">
                  <ShieldOff className="size-3.5 shrink-0" aria-hidden />
                  <span className="truncate">{protectionOffNote(a.protection_off)}</span>
                </p>
              ) : null}
              {a.rule_author ? <p className="text-[11px] text-fg-subtle">Rule by {a.rule_author}</p> : null}
            </div>
          )
        },
      },
      {
        header: 'Device · process',
        accessorKey: 'hostname',
        cell: ({ row }) => (
          <div className="min-w-0">
            <Link to={`/devices/${row.original.device_id}`} onClick={(e) => e.stopPropagation()} className="whitespace-nowrap font-mono text-[13px] hover:underline">
              {row.original.hostname}
            </Link>
            <div className="truncate font-mono text-xs text-fg-subtle">{basename(row.original.image)}</div>
          </div>
        ),
      },
      {
        header: 'Data at risk',
        id: 'data',
        accessorFn: (r) => r.data_at_risk.length,
        size: 120,
        cell: ({ row }) =>
          row.original.data_at_risk.length ? (
            <Tooltip content={row.original.data_at_risk.map((c) => DATA_CATEGORY_LABEL[c]).join(', ')}>
              <span className="whitespace-nowrap text-xs text-sev-high">
                {row.original.data_at_risk.length} {row.original.data_at_risk.length === 1 ? 'type' : 'types'}
              </span>
            </Tooltip>
          ) : (
            <span className="text-xs text-fg-subtle">—</span>
          ),
      },
      { header: 'ATT&CK', id: 'attack', enableSorting: false, meta: { className: 'max-xl:hidden' }, cell: ({ row }) => <AttackChips ids={row.original.attack} max={1} className="flex-nowrap" /> },
      { header: 'Status', accessorKey: 'status', size: 110, cell: ({ row }) => <span className={cn('whitespace-nowrap text-xs', row.original.status === 'new' ? 'font-medium text-fg' : 'text-fg-muted')}>{STATUS_LABEL[row.original.status]}</span> },
      {
        header: 'Time',
        accessorKey: 'ts',
        size: 90,
        cell: ({ row }) => (
          <Tooltip content={formatDateTime(row.original.ts)}>
            <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(row.original.ts)}</span>
          </Tooltip>
        ),
      },
      {
        id: 'more',
        size: 90,
        enableSorting: false,
        cell: ({ row }) =>
          can('exclusions.write') ? (
            <Button
              size="sm"
              variant="ghost"
              className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100"
              onClick={(e) => {
                e.stopPropagation()
                setExclude(row.original)
              }}
            >
              Exclude…
            </Button>
          ) : null,
      },
    ],
    [can],
  )

  const groupBy = useMemo(() => {
    if (group === 'none') return undefined
    if (group === 'device') return (a: AlertRow) => ({ key: a.hostname, label: <span className="font-mono">{a.hostname}</span> })
    return (a: AlertRow) => ({
      key: a.rule_id,
      label: (
        <span>
          <span className="font-mono text-xs text-fg-muted">{a.rule_id}</span> {a.rule_name}
        </span>
      ),
    })
  }, [group])

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Alerts" description="Every individual detection. Incidents group these by device and process tree.">
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <SearchInput value={q} onChange={setQ} placeholder="Search rule, device, program…" className="w-64" />
          <FilterChip label="Status" value={status} onChange={setStatus} options={(Object.keys(STATUS_LABEL) as AlertStatus[]).map((s) => ({ value: s, label: STATUS_LABEL[s] }))} />
          <FilterChip
            label="Severity"
            value={severity}
            onChange={setSeverity}
            options={(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((s) => ({ value: s, label: <span className="inline-flex items-center gap-1.5"><SeverityIcon severity={s} className="size-3.5" />{SEVERITY_LABEL[s]}</span> }))}
          />
          <div className="ml-auto">
            <Dropdown>
              <DropdownTrigger className="inline-flex h-7 items-center gap-1.5 rounded-md border border-border-strong bg-surface px-2 text-xs hover:bg-surface-2">
                <Layers className="size-3.5 text-fg-subtle" /> Group: <span className="font-medium capitalize">{group === 'none' ? 'None' : group}</span> <ChevronDown className="size-3 opacity-60" />
              </DropdownTrigger>
              <DropdownContent>
                <DropdownItem onSelect={() => setGroup('rule')}>By rule</DropdownItem>
                <DropdownItem onSelect={() => setGroup('device')}>By device</DropdownItem>
                <DropdownItem onSelect={() => setGroup('none')}>No grouping</DropdownItem>
              </DropdownContent>
            </Dropdown>
          </div>
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 bg-surface">
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows />
        ) : (
          <>
            <div className="flex items-center gap-3 border-b border-border px-4 py-1.5 text-xs text-fg-subtle">
              <span className="tabular">{items.length} alerts</span>
              <span className="hidden items-center gap-1 sm:inline-flex">
                <Kbd>J</Kbd>
                <Kbd>K</Kbd> move · <Kbd>Enter</Kbd> open incident · <Kbd>X</Kbd> select
              </span>
            </div>
            <DataTable
              label="Alerts"
              data={items}
              columns={cols}
              getRowId={(r) => r.id}
              keyboard
              selectable={can('incidents.write')}
              selection={selection}
              onSelectionChange={setSelection}
              activeId={active}
              onActiveChange={setActive}
              onRowClick={(r) => nav(`/incidents/${r.incident_id}`)}
              groupBy={groupBy}
              groupSummary={(rows) => (
                <span className="flex items-center gap-2 text-xs text-fg-muted">
                  {new Set(rows.map((r) => r.device_id)).size} device{new Set(rows.map((r) => r.device_id)).size === 1 ? '' : 's'}
                  {can('incidents.write') ? (
                    <button
                      type="button"
                      className="rounded px-1.5 py-0.5 hover:bg-surface-3 hover:text-fg"
                      onClick={(e) => {
                        e.stopPropagation()
                        const next: Record<string, boolean> = { ...selection }
                        rows.forEach((r) => (next[r.id] = true))
                        setSelection(next)
                      }}
                    >
                      Select group
                    </button>
                  ) : null}
                </span>
              )}
              empty={<EmptyState title="No alerts match">Change the status filter to see closed alerts.</EmptyState>}
            />
          </>
        )}
      </div>
      <BulkBar count={ids.length} onClear={() => setSelection({})}>
        <Button size="sm" onClick={() => bulk.mutate('acknowledged')}>
          Acknowledge
        </Button>
        <Button size="sm" onClick={() => bulk.mutate('closed')}>
          Close
        </Button>
      </BulkBar>
      {exclude ? <ExclusionDialog open onOpenChange={(o) => !o && setExclude(null)} fromAlert={exclude} /> : null}
    </div>
  )
}
