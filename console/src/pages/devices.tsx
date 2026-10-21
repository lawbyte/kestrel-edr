import { useQuery } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Download, Plus } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { api, qk } from '@/api/endpoints'
import type { Device, DeviceStatus } from '@/api/types'
import { DeviceStatusBadge } from '@/components/badges'
import { EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { DataTable } from '@/components/data-table'
import { FilterChip, SearchInput, useUrlList, useUrlString } from '@/components/filters'
import { Button } from '@/components/ui/button'
import { Kbd, Switch, Tooltip } from '@/components/ui/misc'
import { RemovalBadge, isRemoved, removedText } from '@/components/device-removal'
import { DEVICE_STATUS_LABEL } from '@/lib/labels'
import { formatDateTime, timeAgo } from '@/lib/format'
import { toCsv, downloadText } from '@/lib/csv'
import { cn } from '@/lib/utils'
import { useAuth } from '@/lib/auth'
import { InstallAgentWizard } from '@/components/install-wizard'

export default function Devices() {
  const nav = useNavigate()
  const [status, setStatus] = useUrlList('status')
  const [groups, setGroups] = useUrlList('group')
  const [q, setQ] = useUrlString('q')
  const [removedParam, setRemovedParam] = useUrlString('removed')
  const showRemoved = removedParam === '1'
  const [active, setActive] = useState<string | null>(null)
  const [installing, setInstalling] = useState(false)
  const { can } = useAuth()
  const listQuery = { q, status: status.join(','), ...(showRemoved ? { include_removed: true } : {}) }
  const list = useQuery({ queryKey: qk.devices(listQuery), queryFn: () => api.devices(listQuery), placeholderData: (p) => p, refetchInterval: 30_000 })
  const g = useQuery({ queryKey: qk.groups, queryFn: api.groups, staleTime: 60_000 })
  const latest = useMemo(() => (list.data?.items ?? []).filter((d) => !isRemoved(d)).map((d) => d.agent_version).sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))[0], [list.data])
  const items = (list.data?.items ?? []).filter((d) => !groups.length || groups.includes(d.group_id ?? ''))
  const counts = useMemo(() => {
    const c: Record<DeviceStatus, number> = { online: 0, offline: 0, degraded: 0, isolated: 0, paused: 0 }
    let removed = 0
    for (const d of list.data?.items ?? []) {
      if (isRemoved(d)) removed++
      else c[d.status] = (c[d.status] ?? 0) + 1
    }
    return { ...c, removed }
  }, [list.data])

  const cols = useMemo<ColumnDef<Device, unknown>[]>(
    () => [
      {
        header: 'Status',
        accessorKey: 'status',
        size: 130,
        cell: ({ row }) => {
          const r = row.original.removal
          if (r?.state === 'removed') return <RemovalBadge state="removed" className="text-sm" />
          return (
            <div className="space-y-0.5">
              <DeviceStatusBadge status={row.original.status} />
              {r ? <RemovalBadge state={r.state} /> : null}
            </div>
          )
        },
      },
      {
        header: 'Hostname',
        accessorKey: 'hostname',
        cell: ({ row }) => (
          <div>
            <span className="font-mono text-[13px] font-medium">{row.original.hostname}</span>
            <div className="text-xs text-fg-subtle">{row.original.removal?.state === 'removed' ? removedText(row.original.removal) : row.original.ip_addresses[0]}</div>
          </div>
        ),
      },
      { header: 'User', id: 'user', accessorFn: (d) => d.logged_on_user ?? '', cell: ({ row }) => <span className="text-sm text-fg-muted">{row.original.logged_on_user?.split('\\').pop() ?? '—'}</span> },
      {
        header: 'OS',
        id: 'os',
        accessorFn: (d) => d.os_name,
        cell: ({ row }) => (
          <div className="text-sm">
            {row.original.os_name.replace('Windows ', 'Win ')}
            <div className="font-mono text-[11px] text-fg-subtle">{row.original.os_build}</div>
          </div>
        ),
      },
      {
        header: 'Agent',
        accessorKey: 'agent_version',
        size: 90,
        cell: ({ row }) => (
          <span className={cn('font-mono text-xs', row.original.agent_version !== latest && !isRemoved(row.original) && 'text-warn')} title={row.original.agent_version !== latest && !isRemoved(row.original) ? `Older than ${latest}` : undefined}>
            {row.original.agent_version}
          </span>
        ),
      },
      {
        header: 'Last seen',
        accessorKey: 'last_seen',
        size: 110,
        cell: ({ row }) => (
          <Tooltip content={formatDateTime(row.original.last_seen)}>
            <span className={cn('text-xs', row.original.status === 'offline' ? 'text-fg' : 'text-fg-muted')}>{timeAgo(row.original.last_seen)}</span>
          </Tooltip>
        ),
      },
      {
        header: 'Group · policy',
        id: 'policy',
        accessorFn: (d) => d.group_name ?? '',
        cell: ({ row }) => (
          <div className="min-w-0 text-sm">
            {row.original.group_name}
            <div className="truncate text-xs text-fg-subtle">
              {row.original.policy_name} <span className="tabular">v{row.original.policy_version_applied}</span>
            </div>
          </div>
        ),
      },
      {
        header: 'Incidents',
        accessorKey: 'open_incidents',
        size: 90,
        cell: ({ row }) =>
          row.original.open_incidents ? (
            <Link to={`/incidents?device_id=${row.original.id}`} onClick={(e) => e.stopPropagation()} className="inline-flex min-w-6 justify-center rounded-full bg-sev-critical-soft px-1.5 text-xs font-semibold tabular text-sev-critical hover:underline">
              {row.original.open_incidents}
            </Link>
          ) : (
            <span className="text-xs text-fg-subtle">0</span>
          ),
      },
    ],
    [latest],
  )

  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Devices"
        description={list.data ? `${list.data.total - counts.removed} enrolled · ${counts.online} online, ${counts.offline} offline, ${counts.degraded} degraded, ${counts.isolated} isolated${counts.paused ? `, ${counts.paused} with protection off` : ''}` : 'Enrolled Windows endpoints'}
        actions={
          <>
            <Button size="sm" onClick={() => downloadText('kestrel-devices.csv', toCsv(items.map((d) => ({ hostname: d.hostname, status: d.removal ? `${d.status} (removal ${d.removal.state})` : d.status, user: d.logged_on_user, os: `${d.os_name} ${d.os_build}`, agent: d.agent_version, last_seen: new Date(d.last_seen).toISOString(), group: d.group_name, policy: d.policy_name, open_incidents: d.open_incidents, ip: d.ip_addresses.join(' ') }))))}>
              <Download /> Export CSV
            </Button>
            {can('devices.write') ? (
              <Button size="sm" variant="primary" onClick={() => setInstalling(true)}>
                <Plus /> Install agent
              </Button>
            ) : null}
          </>
        }
      >
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <SearchInput value={q} onChange={setQ} placeholder="Hostname, user or IP…" className="w-64" />
          <FilterChip label="Status" value={status} onChange={setStatus} options={(Object.keys(DEVICE_STATUS_LABEL) as DeviceStatus[]).map((s) => ({ value: s, label: <span className="inline-flex items-center gap-2"><DeviceStatusBadge status={s} className="text-xs" /><span className="tabular text-fg-subtle">{counts[s]}</span></span> }))} />
          <FilterChip label="Group" value={groups} onChange={setGroups} options={(g.data ?? []).map((x) => ({ value: x.id, label: x.name }))} />
          <label className="ml-1 inline-flex items-center gap-2 text-sm text-fg-muted">
            <Switch checked={showRemoved} onCheckedChange={(v) => setRemovedParam(v ? '1' : '')} aria-label="Show removed devices" />
            Show removed devices
            {showRemoved && counts.removed ? <span className="tabular text-xs text-fg-subtle">{counts.removed}</span> : null}
          </label>
        </div>
      </PageHeader>
      {installing ? <InstallAgentWizard onClose={() => setInstalling(false)} /> : null}
      <div className="min-h-0 flex-1 bg-surface">
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows />
        ) : (
          <>
            <div className="flex items-center gap-3 border-b border-border px-4 py-1.5 text-xs text-fg-subtle">
              <span className="tabular">{items.length} devices</span>
              <span className="hidden items-center gap-1 sm:inline-flex">
                <Kbd>J</Kbd>
                <Kbd>K</Kbd> move · <Kbd>Enter</Kbd> open
              </span>
            </div>
            <DataTable
              label="Devices"
              data={items}
              columns={cols}
              getRowId={(r) => r.id}
              keyboard
              activeId={active}
              onActiveChange={setActive}
              onRowClick={(d) => nav(`/devices/${d.id}`)}
              rowClassName={(d) => (isRemoved(d) ? 'text-fg-muted opacity-70' : undefined)}
              initialSorting={[{ id: 'hostname', desc: false }]}
              empty={<EmptyState title={q || status.length ? 'No devices match' : 'No devices enrolled yet'} action={q || status.length ? null : <Button size="sm" variant="primary" onClick={() => setInstalling(true)}>Install the agent</Button>}>{q || status.length ? 'Try a different hostname or clear the status filter.' : 'Install the agent with an enrollment token to see devices here.'}</EmptyState>}
            />
          </>
        )}
      </div>
    </div>
  )
}
