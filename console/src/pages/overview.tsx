import { useQuery } from '@tanstack/react-query'
import { ArrowRight, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link, useNavigate } from 'react-router'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip as RTooltip, XAxis, YAxis } from 'recharts'
import { api, qk } from '@/api/endpoints'
import type { Dashboard, HardeningControl } from '@/api/types'
import { DeviceStatusBadge, IncidentStatusBadge, PriorityScore, SeverityBadge, SeverityIcon } from '@/components/badges'
import { Card, EmptyState, ErrorState, PageHeader } from '@/components/common'
import { Skeleton, Tooltip } from '@/components/ui/misc'
import { DATA_CATEGORY_LABEL, HARDENING_INFO } from '@/lib/labels'
import { timeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'

export default function Overview() {
  const q = useQuery({ queryKey: qk.dashboard, queryFn: api.dashboard, refetchInterval: 60_000 })
  return (
    <div>
      <PageHeader title="Overview" description="What needs attention across your devices right now." />
      <div className="space-y-5 p-6">
        {q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : q.isPending ? <OverviewSkeleton /> : <OverviewBody d={q.data} />}
      </div>
    </div>
  )
}

function OverviewSkeleton() {
  return (
    <>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {[0, 1, 2, 3].map((i) => (
          <Skeleton key={i} className="h-[118px]" />
        ))}
      </div>
      <div className="grid gap-5 xl:grid-cols-3">
        <Skeleton className="h-72 xl:col-span-2" />
        <Skeleton className="h-72" />
      </div>
    </>
  )
}

function OverviewBody({ d }: { d: Dashboard }) {
  const nav = useNavigate()
  const openCritHigh = d.incidents.critical + d.incidents.high
  return (
    <>
      {/* Attention strip: what to do next, not a tally */}
      {d.incidents.open > 0 ? (
        <Link
          to="/incidents?status=open,in_progress"
          className="group flex items-center gap-4 rounded-lg border border-sev-critical/25 bg-sev-critical-soft/60 px-4 py-3 transition-colors hover:border-sev-critical/50"
        >
          <SeverityIcon severity={d.incidents.critical ? 'critical' : 'high'} className="size-5" />
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">
              {d.incidents.open} open incident{d.incidents.open === 1 ? '' : 's'}
              {openCritHigh ? (
                <span className="text-fg-muted">
                  {' '}
                  · {d.incidents.critical} critical, {d.incidents.high} high
                </span>
              ) : null}
            </p>
            <p className="text-xs text-fg-muted">Start with the highest priority. Credential theft incidents need sessions revoked even when the agent stopped the program.</p>
          </div>
          <span className="inline-flex items-center gap-1 text-sm font-medium text-fg">
            Triage queue <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" />
          </span>
        </Link>
      ) : (
        <div className="flex items-center gap-3 rounded-lg border border-ok/30 bg-ok-soft px-4 py-3 text-sm">
          <ShieldCheck className="size-5 text-ok" /> No open incidents. Nothing needs you right now.
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi label="Devices" to="/devices" value={d.devices.total}>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs">
            <MiniStat to="/devices?status=online" label="online" n={d.devices.online} status="online" />
            <MiniStat to="/devices?status=offline" label="offline" n={d.devices.offline} status="offline" />
            <MiniStat to="/devices?status=degraded" label="degraded" n={d.devices.degraded} status="degraded" />
            <MiniStat to="/devices?status=isolated" label="isolated" n={d.devices.isolated} status="isolated" />
          </div>
        </Kpi>
        <Kpi label="Open incidents" to="/incidents" value={d.incidents.open}>
          <div className="flex gap-3 text-xs text-fg-muted">
            <span className="inline-flex items-center gap-1">
              <SeverityIcon severity="critical" className="size-3.5" /> {d.incidents.critical} critical
            </span>
            <span className="inline-flex items-center gap-1">
              <SeverityIcon severity="high" className="size-3.5" /> {d.incidents.high} high
            </span>
          </div>
        </Kpi>
        <Kpi label="Stopped automatically, 24 h" to="/response" value={d.blocked_24h}>
          <p className="text-xs text-fg-muted">
            from <span className="tabular">{d.alerts_24h}</span> alerts in the last 24 hours
          </p>
        </Kpi>
        <Kpi label="Mean time to resolve, 30 d" value={d.incidents.mttr_hours_30d} unit="h">
          <p className="text-xs text-fg-muted">{d.incidents.mttr_hours_30d == null ? 'No incidents resolved in the last 30 days' : 'From first alert to resolved or dismissed'}</p>
        </Kpi>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Alerts, last 14 days" className="xl:col-span-2" bodyClassName="pt-2" actions={<Link className="text-xs text-fg-muted hover:text-fg" to="/alerts">All alerts</Link>}>
          <TrendChart data={d.alert_trend} />
        </Card>
        <Card title="Data at risk, 30 days" description="Secrets stealers touched, excluding benign and false positives">
          {d.data_at_risk_30d.length ? (
            <BarList
              items={d.data_at_risk_30d.map((x) => ({ key: x.category, label: DATA_CATEGORY_LABEL[x.category], value: x.count, to: `/incidents?status=open,in_progress,resolved` }))}
              unit="incidents"
              tone="bg-sev-high"
            />
          ) : (
            <EmptyState title="No secrets exposed" className="py-6">
              No incident in the last 30 days touched credential stores.
            </EmptyState>
          )}
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Recent incidents" className="xl:col-span-2" bodyClassName="p-0" actions={<Link className="text-xs text-fg-muted hover:text-fg" to="/incidents">Queue</Link>}>
          <ul className="divide-y divide-border">
            {d.recent_incidents.map((i) => (
              <li key={i.id}>
                <button type="button" onClick={() => nav(`/incidents/${i.id}`)} className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-2/70">
                  <PriorityScore value={i.priority} className="w-14 shrink-0 text-xs" />
                  <SeverityBadge severity={i.severity} className="shrink-0" />
                  <span className="min-w-0 flex-1 truncate text-sm">{i.title}</span>
                  <span className="hidden shrink-0 sm:block">
                    <IncidentStatusBadge status={i.status} />
                  </span>
                  <span className="w-16 shrink-0 text-right text-xs text-fg-subtle">{timeAgo(i.created_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        </Card>
        <Card title="Top rules, 14 days" actions={<Link className="text-xs text-fg-muted hover:text-fg" to="/rules">Catalog</Link>}>
          <BarList items={d.top_rules.map((r) => ({ key: r.rule_id, label: <><span className="font-mono text-xs text-fg-muted">{r.rule_id}</span> {r.name}</>, value: r.count, to: `/alerts?q=${r.rule_id}` }))} unit="alerts" tone="bg-accent" />
        </Card>
      </div>

      <div className="grid gap-5 xl:grid-cols-3">
        <Card title="Hardening coverage" className="xl:col-span-2" description="Devices where each OS control is applied, out of those whose policy asks for it" actions={<Link className="text-xs text-fg-muted hover:text-fg" to="/policies">Policies</Link>}>
          <div className="grid gap-x-8 gap-y-3 sm:grid-cols-2">
            {d.hardening_coverage.map((h) => {
              const pct = h.total ? Math.round((h.applied / h.total) * 100) : 0
              const label = HARDENING_INFO[h.control as HardeningControl]?.label ?? h.control
              const gap = h.total - h.applied
              return (
                <div key={h.control}>
                  <div className="mb-1 flex items-baseline justify-between gap-2 text-sm">
                    <span className="truncate">{label}</span>
                    <span className="shrink-0 tabular text-xs text-fg-muted">{h.total ? `${h.applied}/${h.total}` : 'Not requested'}</span>
                  </div>
                  <Tooltip content={h.total ? `${pct}% applied${gap ? `, ${gap} drifted or pending` : ''}` : 'No policy enables this control'}>
                    <div className="h-1.5 overflow-hidden rounded-full bg-surface-3" role="meter" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={`${label} coverage`}>
                      <div className={cn('h-full rounded-full', pct >= 95 ? 'bg-ok' : pct >= 80 ? 'bg-accent' : 'bg-warn')} style={{ width: `${h.total ? pct : 0}%` }} />
                    </div>
                  </Tooltip>
                </div>
              )
            })}
          </div>
        </Card>
        <Card title="Agent versions">
          <AgentVersions items={d.agent_versions} total={d.devices.total} />
        </Card>
      </div>
    </>
  )
}

function Kpi({ label, value, unit, to, children }: { label: string; value: number | null; unit?: string; to?: string; children?: React.ReactNode }) {
  const body = (
    <>
      <p className="text-xs font-medium text-fg-muted">{label}</p>
      <p className="mt-1.5 text-[2rem] font-semibold leading-none tracking-[-0.02em] tabular">
        {value ?? <span className="text-fg-subtle">—</span>}
        {unit && value != null ? <span className="ml-0.5 text-lg font-medium text-fg-subtle">{unit}</span> : null}
      </p>
      <div className="mt-3">{children}</div>
    </>
  )
  const cls = 'block rounded-lg border border-border bg-surface p-4'
  return to ? (
    <div className={cn(cls, 'transition-colors hover:border-border-strong')}>
      <Link to={to} className="sr-only">
        {label}
      </Link>
      {body}
    </div>
  ) : (
    <div className={cls}>{body}</div>
  )
}

function MiniStat({ to, label, n, status }: { to: string; label: string; n: number; status: 'online' | 'offline' | 'degraded' | 'isolated' }) {
  return (
    <Link to={to} className={cn('inline-flex items-center gap-1 hover:underline', n === 0 && 'opacity-60')} aria-label={`${n} ${label}`}>
      <DeviceStatusBadge status={status} className="text-xs [&>span:last-child]:hidden" />
      <span className="tabular font-medium text-fg">{n}</span>
      <span className="text-fg-muted">{label}</span>
    </Link>
  )
}

const SERIES = [
  { key: 'critical', label: 'Critical', color: 'var(--sev-critical)' },
  { key: 'high', label: 'High', color: 'var(--chart-high)' },
  { key: 'medium', label: 'Medium', color: 'var(--chart-medium)' },
  { key: 'low', label: 'Low / info', color: 'var(--sev-low)' },
] as const

function TrendChart({ data }: { data: Dashboard['alert_trend'] }) {
  const [table, setTable] = useState(false)
  const rows = data.map((d) => ({ ...d, label: new Date(d.day + 'T00:00:00').toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) }))
  return (
    <div>
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-fg-muted">
        {SERIES.map((s) => (
          <span key={s.key} className="inline-flex items-center gap-1.5">
            <span className="size-2.5 rounded-[3px]" style={{ background: s.color }} aria-hidden />
            {s.label}
          </span>
        ))}
        <button type="button" onClick={() => setTable((t) => !t)} className="ml-auto text-fg-muted underline-offset-2 hover:text-fg hover:underline">
          {table ? 'Show chart' : 'Show as table'}
        </button>
      </div>
      {table ? (
        <div className="max-h-56 overflow-auto">
          <table className="w-full text-sm">
            <thead className="text-xs text-fg-subtle">
              <tr>
                <th className="py-1 text-left font-medium">Day</th>
                {SERIES.map((s) => (
                  <th key={s.key} className="py-1 text-right font-medium">
                    {s.label}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.day} className="border-t border-border">
                  <td className="py-1">{r.label}</td>
                  {SERIES.map((s) => (
                    <td key={s.key} className="py-1 text-right tabular">
                      {r[s.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="h-56" role="img" aria-label="Stacked bar chart of daily alerts by severity over the last 14 days">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={rows} margin={{ top: 4, right: 4, bottom: 0, left: -8 }} barCategoryGap="28%">
              <CartesianGrid vertical={false} stroke="var(--chart-grid)" />
              <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: 'var(--fg-subtle)' }} interval="preserveStartEnd" minTickGap={16} />
              <YAxis allowDecimals={false} tickLine={false} axisLine={false} tick={{ fontSize: 11, fill: 'var(--fg-subtle)' }} width={44} />
              <RTooltip
                cursor={{ fill: 'var(--surface-2)' }}
                content={({ active, payload, label }) =>
                  active && payload?.length ? (
                    <div className="rounded-md border border-border bg-surface px-3 py-2 text-xs shadow-pop">
                      <p className="mb-1 font-medium">{label}</p>
                      {[...payload].reverse().map((p) => (
                        <p key={String(p.dataKey)} className="flex items-center justify-between gap-4">
                          <span className="inline-flex items-center gap-1.5 text-fg-muted">
                            <span className="size-2 rounded-[2px]" style={{ background: String(p.color) }} />
                            {SERIES.find((s) => s.key === p.dataKey)?.label}
                          </span>
                          <span className="tabular font-medium">{String(p.value)}</span>
                        </p>
                      ))}
                    </div>
                  ) : null
                }
              />
              {[...SERIES].reverse().map((s, i) => (
                <Bar key={s.key} dataKey={s.key} stackId="a" fill={s.color} stroke="var(--surface)" strokeWidth={1} radius={i === SERIES.length - 1 ? [3, 3, 0, 0] : 0} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}

function BarList({ items, unit, tone }: { items: { key: string; label: React.ReactNode; value: number; to?: string }[]; unit: string; tone: string }) {
  const max = Math.max(1, ...items.map((i) => i.value))
  if (!items.length) return <p className="py-6 text-center text-sm text-fg-muted">No data yet.</p>
  return (
    <ul className="-mx-2 space-y-0.5">
      {items.map((it) => {
        const inner = (
          <>
            <span className="flex items-baseline justify-between gap-3">
              <span className="min-w-0 truncate">{it.label}</span>
              <span className="shrink-0 tabular text-fg-muted" aria-label={`${it.value} ${unit}`}>
                {it.value}
              </span>
            </span>
            <span className="mt-1 block h-1 overflow-hidden rounded-full bg-surface-3" aria-hidden>
              <span className={cn('block h-full rounded-full', tone)} style={{ width: `${(it.value / max) * 100}%` }} />
            </span>
          </>
        )
        const cls = 'block rounded-md px-2 py-1.5 text-sm'
        return (
          <li key={it.key}>
            {it.to ? (
              <Link to={it.to} className={cn(cls, 'hover:bg-surface-2/70')}>
                {inner}
              </Link>
            ) : (
              <div className={cls}>{inner}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}

function AgentVersions({ items, total }: { items: Dashboard['agent_versions']; total: number }) {
  const latest = items[0]?.version
  return (
    <div className="space-y-3">
      <div className="flex h-2 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        {items.map((v, i) => (
          <span key={v.version} className={cn('h-full border-r-2 border-surface last:border-r-0', i === 0 ? 'bg-ok' : i === 1 ? 'bg-accent/70' : 'bg-warn')} style={{ width: `${(v.count / total) * 100}%` }} />
        ))}
      </div>
      <ul className="space-y-1.5 text-sm">
        {items.map((v, i) => (
          <li key={v.version} className="flex items-center gap-2">
            <span className={cn('size-2 rounded-full', i === 0 ? 'bg-ok' : i === 1 ? 'bg-accent/70' : 'bg-warn')} aria-hidden />
            <span className="font-mono text-[13px]">{v.version}</span>
            {v.version === latest ? <span className="text-xs text-fg-subtle">latest</span> : <span className="text-xs text-warn">update pending</span>}
            <span className="ml-auto tabular text-fg-muted">{v.count}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}
