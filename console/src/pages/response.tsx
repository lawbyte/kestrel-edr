import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Bot } from 'lucide-react'
import { useMemo } from 'react'
import { Link } from 'react-router'
import { api, qk } from '@/api/endpoints'
import type { ActionStatus, ResponseActionRow } from '@/api/types'
import { ActionStatusBadge } from '@/components/badges'
import { Avatar, EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { DataTable } from '@/components/data-table'
import { FilterChip, SearchInput, useUrlList, useUrlString } from '@/components/filters'
import { Tooltip } from '@/components/ui/misc'
import { ACTION_LABEL, ACTION_STATUS_LABEL, describeAction } from '@/lib/labels'
import { formatDateTime, formatDuration, timeAgo } from '@/lib/format'

export default function Response() {
  const [status, setStatus] = useUrlList('status')
  const [who, setWho] = useUrlList('who')
  const [q, setQ] = useUrlString('q')
  const list = useQuery({ queryKey: qk.actions({ status: status.join(',') }), queryFn: () => api.actions({ status: status.join(',') }), refetchInterval: 15_000 })
  const items = (list.data?.items ?? [])
    .filter((a) => !who.length || (who.includes('auto') && !a.requested_by) || (who.includes('manual') && a.requested_by))
    .filter((a) => !q || `${a.hostname} ${describeAction(a.action)} ${a.comment} ${a.requested_by?.name ?? ''}`.toLowerCase().includes(q.toLowerCase()))
  const cols = useMemo<ColumnDef<ResponseActionRow, unknown>[]>(
    () => [
      { header: 'Status', accessorKey: 'status', size: 120, cell: ({ row }) => <ActionStatusBadge status={row.original.status} /> },
      {
        header: 'Action',
        id: 'action',
        accessorFn: (r) => ACTION_LABEL[r.action.type],
        cell: ({ row }) => (
          <div className="min-w-0 max-w-[300px]">
            <p className="font-medium">{ACTION_LABEL[row.original.action.type]}</p>
            <p className="truncate font-mono text-[11.5px] text-fg-muted">{describeAction(row.original.action)}</p>
          </div>
        ),
      },
      { header: 'Device', accessorKey: 'hostname', cell: ({ row }) => <Link to={`/devices/${row.original.device_id}`} className="whitespace-nowrap font-mono text-[13px] hover:underline">{row.original.hostname}</Link> },
      {
        header: 'Requested by',
        id: 'by',
        accessorFn: (r) => r.requested_by?.name ?? 'Automatic',
        cell: ({ row }) =>
          row.original.requested_by ? (
            <span className="inline-flex items-center gap-2 whitespace-nowrap text-sm">
              <Avatar user={row.original.requested_by} size="xs" /> {row.original.requested_by.name}
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-fg-muted">
              <Bot className="size-4" /> Automatic
            </span>
          ),
      },
      { header: 'Reason / result', id: 'detail', enableSorting: false, cell: ({ row }) => <div className="max-w-[260px] text-xs"><p className="truncate text-fg-muted">{row.original.comment || '—'}</p><p className="truncate text-fg-subtle">{row.original.result_detail}</p></div> },
      { header: 'Incident', id: 'inc', enableSorting: false, size: 80, cell: ({ row }) => (row.original.incident_id ? <Link to={`/incidents/${row.original.incident_id}`} className="text-xs text-accent-text hover:underline">View</Link> : <span className="text-xs text-fg-subtle">—</span>) },
      {
        header: 'Requested',
        accessorKey: 'created_at',
        size: 120,
        cell: ({ row }) => (
          <Tooltip content={`${formatDateTime(row.original.created_at)}${row.original.completed_at ? ` · took ${formatDuration(row.original.completed_at - row.original.created_at)}` : ''}`}>
            <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(row.original.created_at)}</span>
          </Tooltip>
        ),
      },
    ],
    [],
  )
  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Response" description="Every action sent to a device, automatic or requested by a person, with its result.">
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <SearchInput value={q} onChange={setQ} placeholder="Device, action, person…" className="w-64" />
          <FilterChip label="Status" value={status} onChange={setStatus} options={(Object.keys(ACTION_STATUS_LABEL) as ActionStatus[]).map((s) => ({ value: s, label: ACTION_STATUS_LABEL[s] }))} />
          <FilterChip label="Source" value={who} onChange={setWho} options={[{ value: 'auto', label: 'Automatic (Protect mode)' }, { value: 'manual', label: 'Requested by a person' }]} />
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 bg-surface">
        {list.error ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : list.isPending ? <LoadingRows /> : <DataTable label="Response actions" data={items} columns={cols} getRowId={(r) => r.id} initialSorting={[{ id: 'created_at', desc: true }]} empty={<EmptyState title="No actions match" />} />}
      </div>
    </div>
  )
}
