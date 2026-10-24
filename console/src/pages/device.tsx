import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, ChevronLeft, CircleDashed, Copy, KeyRound, Loader2, PowerOff, RefreshCw, RotateCw, ShieldOff, XCircle } from 'lucide-react'
import { toast } from 'sonner'
import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router'
import { api, qk } from '@/api/endpoints'
import type { Device, DeviceDetail, EventKind, HardeningControl, ProcessInfo, TreeNode } from '@/api/types'
import { ActionStatusBadge, DeviceStatusBadge, ModeBadge, ProvenanceBadges, SeverityBadge } from '@/components/badges'
import { Card, EmptyState, ErrorState, KeyValue, LoadingRows, Mono } from '@/components/common'
import { ProcessDetail, ProcessTree } from '@/components/process-tree'
import { ActionButton, ConfirmActionDialog, liftBlockSpec, type ActionSpec } from '@/components/response-actions'
import { SearchInput } from '@/components/filters'
import { ProtectionOffBanner } from '@/components/protection-off'
import { CopyButton } from '@/components/copy-button'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { Tabs, TabsContent, TabsList, TabsTrigger, Tooltip } from '@/components/ui/misc'
import { EVENT_KIND_LABEL, EVENT_KINDS_UI, HARDENING_INFO, describeAction } from '@/lib/labels'
import { describeEvent } from '@/lib/events'
import type { ExplainContext } from '@/lib/explain'
import { EventDetails } from '@/components/event-details'
import { eventsLostDetail } from '@/lib/health'
import { formatBytes, formatDateTime, formatTime, formatUptime, timeAgo } from '@/lib/format'
import { basename, cn } from '@/lib/utils'
import { visibleRemoteTabs } from '@/lib/remote-tabs'
import { localPauseSummary, protectionOffNote } from '@/lib/pause'
import { localPauseOf } from '@/components/local-pause-editor'
import { normaliseProfile, profileSummary, profileUnrestricted } from '@/lib/remote-profile'
import { RemoteDesktop } from '@/components/remote/remote-desktop'
import { FileManager } from '@/components/remote/file-manager'
import { ReauthProvider } from '@/components/remote/reauth'
import { RemoteAccessSummaryCard, RemoteAccessSummaryLine } from '@/components/remote/summary'
import { REMOVE_PRIVILEGE, RemovalBadge, RemovalBanner, RemoveDeviceDialog, RemoveDeviceRow, isRemoved } from '@/components/device-removal'

export default function DevicePage() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: qk.device(id), queryFn: () => api.device(id), refetchInterval: 30_000 })
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} className="h-full" />
  if (!q.data) return <LoadingRows rows={12} className="p-6" />
  return <DeviceView d={q.data} />
}

function DeviceView({ d }: { d: DeviceDetail }) {
  const nav = useNavigate()
  const dev = d.device
  const h = dev.health
  const [action, setAction] = useState<ActionSpec | null>(null)
  const isolated = dev.status === 'isolated'
  const drift = d.hardening.filter((x) => x.desired && x.applied === false && !x.pending_reboot && !x.report_only).length
  const { can } = useAuth()
  const [search] = useSearchParams()
  const ra = d.remote_access
  const removed = isRemoved(dev)
  const [removing, setRemoving] = useState(false)
  const remoteTabs = removed ? { desktop: false, files: false } : visibleRemoteTabs(can, ra)
  // Servers before remote-access profiles send no effective profile: they enforce nothing extra, so don't hide controls.
  const effective = ra?.effective ? normaliseProfile(ra.effective) : profileUnrestricted()

  return (
    <div className="pb-16">
      <div className="border-b border-border px-6 pb-4 pt-4">
        <button type="button" onClick={() => nav('/devices')} className="mb-2 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
          <ChevronLeft className="size-3.5" /> Devices
        </button>
        <div className="flex flex-wrap items-start gap-x-6 gap-y-2">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="font-mono text-[1.375rem] font-semibold tracking-[-0.01em]">{dev.hostname}</h1>
              <DeviceStatusBadge status={dev.status} />
              {dev.removal ? <RemovalBadge state={dev.removal.state} className="text-sm" /> : null}
            </div>
            <p className="mt-1 text-sm text-fg-muted">
              {dev.os_name} <span className="font-mono text-xs">{dev.os_build}</span> · {dev.logged_on_user ?? 'no one signed in'} · last seen {timeAgo(dev.last_seen)} · {dev.group_name} group
            </p>
          </div>
        </div>
      </div>

      {removed ? null : (
      <div className="sticky top-0 z-20 flex flex-wrap items-center gap-2 border-b border-border bg-bg/90 px-6 py-2 backdrop-blur" role="toolbar" aria-label="Device actions">
        {isolated ? (
          <ActionButton spec={{ action: { type: 'release_host' }, impact: 'Restores normal network access for this device.' }} onPick={setAction} />
        ) : (
          <ActionButton spec={{ action: { type: 'isolate_host', allow_ips: [] }, destructive: true, impact: 'Cuts all network traffic except to the Kestrel server. The user loses internet and file shares until released.' }} onPick={setAction} />
        )}
        <ActionButton spec={{ action: { type: 'collect_triage' }, impact: 'Uploads the process list, recent events and autoruns from the device.' }} label="Collect triage" onPick={setAction} />
        <ActionButton spec={{ action: { type: 'scan', path: null }, impact: 'YARA-X scan of every running program that lives in a user-writable folder.' }} label="Scan" onPick={setAction} />
        <ActionButton spec={{ action: { type: 'apply_hardening' }, impact: 'Re-applies every hardening control the device’s policy asks for and reports drift.' }} label={drift ? `Re-apply hardening (${drift} drifted)` : 'Re-apply hardening'} onPick={setAction} />
        {dev.open_incidents ? (
          <Link to={`/incidents?device_id=${dev.id}&status=open,in_progress`} className="ml-auto text-xs font-medium text-sev-critical hover:underline">
            {dev.open_incidents} open incident{dev.open_incidents > 1 ? 's' : ''}
          </Link>
        ) : null}
      </div>
      )}

      <ReauthProvider>
      <div className="space-y-5 p-6">
        <RemovalBanner device={dev} onRetry={() => setRemoving(true)} />
        {removed ? null : <ProtectionOffBanner device={dev} onPick={setAction} />}
        <DuplicateBanner d={d} />
        <div className="grid items-start gap-5 lg:grid-cols-3">
          <Card title="Sensor health" className="lg:col-span-2">
            <div className="grid gap-x-6 gap-y-3 sm:grid-cols-2 xl:grid-cols-3">
              <Health label="Kernel telemetry (ETW)" ok={h.etw_ok} detail={h.etw_ok ? `${h.events_per_min ?? 0} events/min` : 'Session not running'} />
              <Health label="Events lost (1 h)" ok={(h.etw_events_lost ?? 0) === 0} warn={(h.etw_events_lost ?? 0) > 0 && (h.etw_events_lost ?? 0) < 500} detail={eventsLostDetail(h)} />
              <Health label="Sysmon" ok={!!h.sysmon_present} neutral={!h.sysmon_present} detail={h.sysmon_present ? 'Present: adds handle-access detail' : 'Not installed (optional)'} />
              <Health label="DPAPI audit channel" ok={!!h.dpapi_channel_enabled} neutral={!h.dpapi_channel_enabled} detail={h.dpapi_channel_enabled ? 'Enabled: ST-03 active' : 'Off (optional): turn on in Policies, Hardening for ST-03'} />
              <Health label="AMSI provider" ok={!!h.amsi_ok} neutral={!h.amsi_ok} detail={h.amsi_ok ? 'Registered' : 'Not used in this version: script content comes from PowerShell logging'} />
              <Health label="Outbox" ok={(h.outbox_depth ?? 0) < 100} warn={(h.outbox_depth ?? 0) >= 100} detail={`${h.outbox_depth ?? 0} queued messages`} />
            </div>
            <div className="mt-4 grid grid-cols-2 gap-4 border-t border-border pt-3 text-sm sm:grid-cols-4">
              <Stat label="Agent CPU" value={`${h.cpu_pct?.toFixed(1) ?? '—'}%`} />
              <Stat label="Agent memory" value={formatBytes((h.mem_mb ?? 0) * 1024 * 1024)} />
              <Stat label="Uptime" value={formatUptime(h.uptime_s)} />
              <Stat label="Antivirus" value={h.av_product ?? '—'} />
            </div>
          </Card>
          <Card title="Device">
            <KeyValue
              cols={1}
              items={[
                ['Agent', <span className="font-mono text-xs">{dev.agent_version}</span>],
                ['IP addresses', <Mono className="text-xs">{dev.ip_addresses.join(', ')}</Mono>],
                ['Domain', dev.domain ?? '—'],
                ['Policy', <Link to={`/policies/${dev.policy_id}`} className="hover:underline">{dev.policy_name} <span className="text-xs text-fg-subtle">v{dev.policy_version_applied} applied</span></Link>],
                ['Enrolled', formatDateTime(dev.first_seen)],
                ['Certificate', <CertExpiry at={dev.cert_expires_at} />],
                ['Tags', dev.tags.join(', ') || '—'],
              ]}
            />
            {removed ? null : <UninstallToken deviceId={dev.id} hostname={dev.hostname} pending={!!dev.uninstall_token_pending} />}
          </Card>
        </div>

        {ra?.ceiling && !removed ? <RemoteAccessSummaryCard info={ra} policyId={dev.policy_id} policyName={dev.policy_name} /> : null}

        <Tabs defaultValue={search.get('tab') ?? 'timeline'}>
          <TabsList>
            <TabsTrigger value="timeline">Event timeline</TabsTrigger>
            <TabsTrigger value="alerts">Recent alerts</TabsTrigger>
            <TabsTrigger value="processes">Process tree</TabsTrigger>
            <TabsTrigger value="settings">Effective settings</TabsTrigger>
            <TabsTrigger value="hardening">Hardening {drift ? <span className="rounded bg-warn-soft px-1 text-[11px] text-warn">{drift}</span> : null}</TabsTrigger>
            <TabsTrigger value="inventory">Inventory</TabsTrigger>
            <TabsTrigger value="actions">Actions</TabsTrigger>
            {remoteTabs.desktop ? <TabsTrigger value="remote-desktop">Remote desktop</TabsTrigger> : null}
            {remoteTabs.files ? <TabsTrigger value="files">Files</TabsTrigger> : null}
          </TabsList>
          <TabsContent value="timeline" className="pt-4">
            <EventTimeline deviceId={dev.id} />
          </TabsContent>
          <TabsContent value="alerts" className="pt-4">
            {d.recent_alerts.length ? (
              <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
                {d.recent_alerts.map((a) => (
                  <li key={a.id}>
                    <Link to={`/incidents/${a.incident_id}`} className="flex flex-wrap items-center gap-3 px-4 py-2.5 hover:bg-surface-2/60">
                      <SeverityBadge severity={a.severity} />
                      <span className="font-mono text-xs text-fg-muted">{a.rule_id}</span>
                      <span className="min-w-0 flex-1 truncate text-sm">{a.summary}</span>
                      {a.protection_off ? (
                        <span className="inline-flex items-center gap-1 text-xs text-warn" title={protectionOffNote(a.protection_off)}>
                          <ShieldOff className="size-3.5" aria-hidden /> Protection was off
                        </span>
                      ) : null}
                      <span className="text-xs text-fg-subtle">{timeAgo(a.ts)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            ) : (
              <EmptyState title="No alerts on this device" />
            )}
          </TabsContent>
          <TabsContent value="processes" className="pt-4">
            <ProcessSnapshot deviceId={dev.id} />
          </TabsContent>
          <TabsContent value="settings" className="pt-4">
            <EffectiveSettings d={d} />
          </TabsContent>
          <TabsContent value="hardening" className="pt-4">
            <div className="overflow-hidden rounded-lg border border-border bg-surface">
              <table className="w-full text-sm">
                <thead className="text-xs text-fg-subtle">
                  <tr className="border-b border-border">
                    <th className="px-4 py-2 text-left font-medium">Control</th>
                    <th className="px-4 py-2 text-left font-medium">Policy wants</th>
                    <th className="px-4 py-2 text-left font-medium">On device</th>
                    <th className="px-4 py-2 text-left font-medium">Source</th>
                  </tr>
                </thead>
                <tbody>
                  {d.hardening.map((x) => {
                    const info = HARDENING_INFO[x.control as HardeningControl]
                    const reportOnly = x.report_only ?? info?.reportOnly ?? false
                    const drifted = x.desired && x.applied === false && !x.pending_reboot && !reportOnly
                    return (
                      <tr key={x.control} className="border-b border-border last:border-0">
                        <td className="px-4 py-2.5">
                          <div className="font-medium">{info?.label ?? x.control}</div>
                          <div className="max-w-xl text-xs text-fg-muted">{info?.blocks}</div>
                          {info?.caveat ? <div className="mt-0.5 max-w-xl text-xs text-fg-subtle">{info.caveat}</div> : null}
                        </td>
                        <td className="px-4 py-2.5 text-sm">{x.desired ? (reportOnly ? 'Report' : 'On') : <span className="text-fg-subtle">Off</span>}</td>
                        <td className="px-4 py-2.5">
                          {reportOnly && x.desired ? (
                            x.applied == null ? (
                              <span className="inline-flex items-center gap-1 text-fg-subtle">
                                <CircleDashed className="size-4" /> Not reported
                              </span>
                            ) : x.applied ? (
                              <span className="inline-flex items-center gap-1 text-ok">
                                <CheckCircle2 className="size-4" /> On in Windows
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 font-medium text-warn">
                                <AlertTriangle className="size-4" /> Off in Windows
                              </span>
                            )
                          ) : x.pending_reboot && !x.applied ? (
                            <span className="inline-flex items-center gap-1 font-medium text-accent-text">
                              <RotateCw className="size-4" /> Pending reboot
                            </span>
                          ) : x.applied ? (
                            <span className="inline-flex items-center gap-1 text-ok">
                              <CheckCircle2 className="size-4" /> Applied
                            </span>
                          ) : drifted ? (
                            <span className="inline-flex items-center gap-1 font-medium text-warn">
                              <AlertTriangle className="size-4" /> Drifted
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-fg-subtle">
                              <CircleDashed className="size-4" /> Not applied
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-fg-muted">{x.source}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </TabsContent>
          <TabsContent value="inventory" className="pt-4">
            <div className="grid gap-5 lg:grid-cols-3">
              <Card title={`Installed software (${d.inventory.software.length})`} className="lg:col-span-2" bodyClassName="p-0">
                <table className="w-full text-sm">
                  <tbody>
                    {d.inventory.software.map((s) => (
                      <tr key={s.name} className="border-b border-border last:border-0">
                        <td className="px-4 py-2">{s.name}</td>
                        <td className="px-4 py-2 font-mono text-xs text-fg-muted">{s.version}</td>
                        <td className="px-4 py-2 text-xs text-fg-subtle">{s.publisher}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Card>
              <Card title="Local administrators">
                <ul className="space-y-1 font-mono text-[12.5px]">
                  {d.inventory.local_admins.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </Card>
            </div>
          </TabsContent>
          <TabsContent value="actions" className="pt-4">
            <DeviceActions deviceId={dev.id} onPick={setAction} />
          </TabsContent>
          {remoteTabs.desktop && ra ? (
            <TabsContent value="remote-desktop" className="space-y-3 pt-4">
              {ra.ceiling ? <RemoteAccessSummaryLine info={ra} /> : null}
              <RemoteDesktop deviceId={dev.id} hostname={dev.hostname} availability={ra.desktop} policyId={dev.policy_id} effective={effective} />
            </TabsContent>
          ) : null}
          {remoteTabs.files && ra ? (
            <TabsContent value="files" className="space-y-3 pt-4">
              {ra.ceiling ? <RemoteAccessSummaryLine info={ra} /> : null}
              <FileManager deviceId={dev.id} hostname={dev.hostname} availability={ra.files} policyId={dev.policy_id} effective={effective} />
            </TabsContent>
          ) : null}
        </Tabs>
        {removed ? null : <DangerZone device={dev} onRemove={() => setRemoving(true)} />}
      </div>
      {removing ? <RemoveDeviceDialog device={dev} onClose={() => setRemoving(false)} /> : null}
      </ReauthProvider>
      <ConfirmActionDialog open={!!action} onOpenChange={(o) => !o && setAction(null)} spec={action} device={dev} />
    </div>
  )
}

function Health({ label, ok, warn, neutral, detail }: { label: string; ok: boolean; warn?: boolean; neutral?: boolean; detail: string }) {
  const Icon = ok ? CheckCircle2 : neutral ? CircleDashed : warn ? AlertTriangle : XCircle
  return (
    <div className="flex items-start gap-2">
      <Icon className={cn('mt-0.5 size-4 shrink-0', ok ? 'text-ok' : neutral ? 'text-fg-subtle' : warn ? 'text-warn' : 'text-danger')} aria-hidden />
      <div className="min-w-0">
        <p className="text-sm font-medium">
          {label}
          <span className="sr-only">: {ok ? 'healthy' : neutral ? 'not in use' : warn ? 'warning' : 'problem'}</span>
        </p>
        <p className="text-xs text-fg-muted">{detail}</p>
      </div>
    </div>
  )
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="text-xs text-fg-subtle">{label}</p>
      <p className="mt-0.5 truncate tabular">{value}</p>
    </div>
  )
}

function EventTimeline({ deviceId }: { deviceId: string }) {
  const [kinds, setKinds] = useState<EventKind[]>([])
  const [q, setQ] = useState('')
  const [open, setOpen] = useState<number | null>(null)
  const ev = useQuery({ queryKey: qk.deviceEvents(deviceId, { kinds, q }), queryFn: () => api.deviceEvents(deviceId, { kinds, q, limit: 300 }), placeholderData: (p) => p })
  const items = useMemo(() => ev.data?.items ?? [], [ev.data])
  const ctx = useMemo<ExplainContext>(() => ({ events: items }), [items])
  return (
    <div className="rounded-lg border border-border bg-surface">
      <div className="flex flex-wrap items-center gap-1.5 border-b border-border px-3 py-2">
        <SearchInput value={q} onChange={setQ} placeholder="Search events…" className="mr-2 w-56" />
        {EVENT_KINDS_UI.map((k) => {
          const on = kinds.includes(k)
          return (
            <button
              key={k}
              type="button"
              aria-pressed={on}
              onClick={() => setKinds((s) => (on ? s.filter((x) => x !== k) : [...s, k]))}
              className={cn('h-6 rounded-md border px-2 text-xs', on ? 'border-accent/40 bg-accent-soft text-fg' : 'border-border text-fg-muted hover:text-fg')}
            >
              {EVENT_KIND_LABEL[k]}
            </button>
          )
        })}
      </div>
      {ev.error ? (
        <ErrorState error={ev.error} onRetry={() => ev.refetch()} />
      ) : ev.isPending ? (
        <LoadingRows rows={6} />
      ) : items.length === 0 ? (
        <EmptyState title="No events match" />
      ) : (
        <div className="max-h-[560px] overflow-y-auto">
          <table className="w-full text-sm">
            <tbody>
              {items.map((e, i) => (
                <TimelineRow key={i} e={e} open={open === i} onToggle={() => setOpen(open === i ? null : i)} ctx={ctx} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="border-t border-border px-3 py-1.5 text-xs text-fg-subtle">Showing the newest {items.length} events. Use Hunt for longer ranges and across devices.</p>
    </div>
  )
}

function TimelineRow({ e, open, onToggle, ctx }: { e: import('@/api/types').DeviceEvent; open: boolean; onToggle: () => void; ctx: ExplainContext }) {
  const image = e.type === 'process_start' ? e.image : e.process_image
  return (
    <>
      <tr className="cursor-pointer border-b border-border hover:bg-surface-2/60" onClick={onToggle} aria-expanded={open}>
        <td className="whitespace-nowrap py-1.5 pl-3 pr-2 text-xs tabular text-fg-subtle">
          <Tooltip content={formatDateTime(e.ts)}>
            <span>{formatTime(e.ts)}</span>
          </Tooltip>
        </td>
        <td className="whitespace-nowrap px-2 py-1.5 text-xs text-fg-muted">{EVENT_KIND_LABEL[e.type]}</td>
        <td className="whitespace-nowrap px-2 py-1.5 font-mono text-[12px]">
          <span className="inline-flex items-center gap-1.5">
            {e.type === 'file_activity' && e.remote_writer ? 'System' : image ? basename(image) : `PID ${e.pid}`}
            <ProvenanceBadges event={e} />
          </span>
        </td>
        <td className="w-full max-w-0 truncate px-2 py-1.5 font-mono text-[12px] text-fg-muted">{describeEvent(e)}</td>
      </tr>
      {open ? (
        <tr className="border-b border-border bg-surface-2/50">
          <td colSpan={4} className="px-3 py-2">
            <EventDetails event={e} context={ctx} />
          </td>
        </tr>
      ) : null}
    </>
  )
}

function ProcessSnapshot({ deviceId }: { deviceId: string }) {
  const p = useQuery({ queryKey: qk.deviceProcesses(deviceId), queryFn: () => api.deviceProcesses(deviceId) })
  const [sel, setSel] = useState<string | null>(null)
  const nodes: TreeNode[] = useMemo(
    () =>
      (p.data?.items ?? []).map((x: ProcessInfo) => ({
        guid: x.guid,
        parent_guid: x.parent_guid ?? null,
        pid: x.pid,
        image: x.image,
        cmdline: x.cmdline,
        user: x.user ?? null,
        start_ts: x.start_ts,
        exit_ts: x.exit_ts ?? null,
        signer: x.signer ?? null,
        signed: x.signed ?? 'unknown',
        sha256: x.sha256 ?? null,
        path_class: x.path_class,
        alert_rule_ids: [],
        is_root: !x.parent_guid,
      })),
    [p.data],
  )
  const byGuid = useMemo(() => new Map(nodes.map((n) => [n.guid, n])), [nodes])
  if (p.error) return <ErrorState error={p.error} onRetry={() => p.refetch()} />
  if (p.isPending) return <LoadingRows rows={6} />
  const node = sel ? byGuid.get(sel) : undefined
  return (
    <Card title={`Running now (${nodes.length} processes)`} description="Reconstructed from telemetry" bodyClassName="p-0">
      <div className="grid lg:grid-cols-[minmax(0,1fr)_320px]">
        <ProcessTree nodes={nodes} selected={sel} onSelect={setSel} className="max-h-[560px] overflow-y-auto border-b border-border lg:border-b-0 lg:border-r" />
        <div className="p-4">{node ? <ProcessDetail node={node} parent={node.parent_guid ? byGuid.get(node.parent_guid) : undefined} /> : <p className="text-sm text-fg-muted">Select a process to see its command line, signer and hash.</p>}</div>
      </div>
    </Card>
  )
}

function formatTtl(secs: number): string {
  if (secs % 86400 === 0) return `${secs / 86400} day${secs === 86400 ? '' : 's'}`
  if (secs % 3600 === 0) return `${secs / 3600} h`
  return `${Math.round(secs / 60)} min`
}

function EffectiveSettings({ d }: { d: DeviceDetail }) {
  const p = d.effective_policy
  const src = `Policy “${p.name}” v${p.version}`
  const catalog = useQuery({ queryKey: qk.rules, queryFn: api.rules, staleTime: 5 * 60_000 })
  const defaults = Object.fromEntries((catalog.data ?? []).filter((r) => r.kind === 'builtin' || r.enabled_custom).map((r) => [r.id, r.default_mode]))
  const rules = Object.entries({ ...defaults, ...p.rules }).sort(([a], [b]) => a.localeCompare(b, undefined, { numeric: true }))
  const rows: [string, React.ReactNode, string][] = [
    ['Suspend window', `${(p.suspend_window_ms / 1000).toFixed(1)} s`, src],
    ['Canary tripwires', p.canaries ? 'On' : 'Off', src],
    ['Hardening mode', <span className="capitalize">{p.hardening.mode}</span>, src],
    ['Upload command lines', p.privacy.capture_cmdline ? 'Yes' : 'No, image and flags only', src],
    ['Hash user names', p.privacy.hash_usernames ? 'Yes' : 'No', src],
    ['Upload DNS queries', p.privacy.capture_dns ? 'Yes' : 'No', src],
    ['Upload script content', p.privacy.capture_script_content ? 'Yes' : 'No', src],
    ['Redacted path prefixes', p.privacy.redact_path_prefixes.join(', ') || 'None', src],
    ['Raw event upload', p.telemetry.upload_events ? 'On' : 'Alerts only', src],
    ['Isolation auto-release', p.isolation_auto_release_hours ? `After ${p.isolation_auto_release_hours} h without server contact` : 'Never', src],
    ['Indicator block lifetime', formatTtl(p.ioc_block_ttl_secs), src],
    ['Indicator block scope', p.ioc_block_host_wide ? 'Every program' : 'Offending program only', src],
    ['Local turn-off', localPauseSummary(localPauseOf(p.local_pause)), src],
    ['Remote access (policy)', profileSummary(normaliseProfile(p.remote_access)), `${src}, capped by the install profile`],
    ['Exclusions in effect', String(p.exclusions.length), `${src} + global exclusions`],
    ['Indicators in effect', String(p.iocs.length), 'Global indicator list'],
  ]
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Card title="Settings and where they come from" bodyClassName="p-0">
        <table className="w-full text-sm">
          <tbody>
            {rows.map(([k, v, s]) => (
              <tr key={k} className="border-b border-border last:border-0">
                <td className="px-4 py-2 text-fg-muted">{k}</td>
                <td className="px-4 py-2">{v}</td>
                <td className="px-4 py-2 text-xs text-fg-subtle">{s}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
      <Card title="Rule modes" bodyClassName="p-0">
        <table className="w-full text-sm">
          <tbody>
            {rules.map(([id, mode]) => (
              <tr key={id} className="border-b border-border last:border-0">
                <td className="px-4 py-1.5 font-mono text-xs">{id}</td>
                <td className="px-4 py-1.5">
                  <ModeBadge mode={mode} />
                </td>
                <td className="px-4 py-1.5 text-xs text-fg-subtle">{id in p.rules ? src : 'Rule default'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  )
}

function DeviceActions({ deviceId, onPick }: { deviceId: string; onPick: (s: ActionSpec) => void }) {
  const a = useQuery({ queryKey: qk.actions({ device_id: deviceId }), queryFn: () => api.actions({ device_id: deviceId }) })
  if (a.error) return <ErrorState error={a.error} onRetry={() => a.refetch()} />
  if (a.isPending) return <LoadingRows rows={4} />
  if (!a.data.items.length) return <EmptyState title="No response actions on this device" />
  return (
    <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
      {a.data.items.map((r) => (
        <li key={r.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">{describeAction(r.action)}</p>
            <p className="text-xs text-fg-muted">
              {r.requested_by ? r.requested_by.name : 'Automatic'} · {formatDateTime(r.created_at)}
              {r.result_detail ? ` · ${r.result_detail}` : ''}
            </p>
          </div>
          {(() => {
            const lift = liftBlockSpec(r.action, r.status, r.artifact)
            return lift ? <ActionButton spec={lift} label="Lift block" onPick={onPick} /> : null
          })()}
          <ActionStatusBadge status={r.status} />
        </li>
      ))}
    </ul>
  )
}

const DAY_MS = 86_400_000

function CertExpiry({ at }: { at?: number | null }) {
  if (!at) return <span className="text-fg-subtle">—</span>
  const days = Math.floor((at - Date.now()) / DAY_MS)
  const soon = days < 30
  return (
    <span className={cn('text-xs', soon ? 'text-warn' : 'text-fg-muted')} title={formatDateTime(at)}>
      {days < 0 ? 'Expired' : `Expires in ${days} day${days === 1 ? '' : 's'}`}
      {soon && days >= 0 ? ' · renews automatically when the agent connects' : ''}
    </span>
  )
}

/** M5: server-escrowed uninstall token, revealed on demand (audit-logged). */
function UninstallToken({ deviceId, hostname, pending }: { deviceId: string; hostname: string; pending: boolean }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [shown, setShown] = useState<{ token: string | null; pending_token: string | null } | null>(null)
  const reveal = useMutation({
    mutationFn: () => api.revealUninstallToken(deviceId),
    onSuccess: (r) => setShown(r),
    onError: (e) => toast.error('Cannot show the uninstall token', { description: (e as Error).message }),
  })
  const rotate = useMutation({
    mutationFn: () => api.rotateUninstallToken(deviceId),
    onSuccess: (r) => {
      setShown((s) => ({ token: s?.token ?? null, pending_token: r.pending_token }))
      toast.success(r.sent ? 'New uninstall token sent to the agent' : 'New uninstall token created', { description: r.message })
      void qc.invalidateQueries({ queryKey: qk.device(deviceId) })
    },
    onError: (e) => toast.error('Rotation failed', { description: (e as Error).message }),
  })
  if (!can('devices.write')) return null
  return (
    <div className="mt-3 border-t border-border pt-3">
      <p className="flex items-center gap-1.5 text-xs font-medium text-fg-subtle">
        <KeyRound className="size-3.5" /> Uninstall token
      </p>
      {shown ? (
        <div className="mt-1.5 space-y-1.5">
          {shown.token ? (
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded border border-border bg-surface-2 px-2 py-1 font-mono text-xs">{shown.token}</code>
              <CopyButton text={shown.token} iconOnly />
            </div>
          ) : null}
          {shown.pending_token ? (
            <div>
              <p className="text-[11px] text-fg-subtle">Pending, becomes current once the agent confirms it:</p>
              <div className="flex items-center gap-2">
                <code className="min-w-0 flex-1 truncate rounded border border-border bg-surface-2 px-2 py-1 font-mono text-xs">{shown.pending_token}</code>
                <CopyButton text={shown.pending_token} iconOnly />
              </div>
            </div>
          ) : null}
          <p className="text-[11px] text-fg-subtle">Needed to uninstall the agent on {hostname}. Every reveal is recorded in the audit log.</p>
        </div>
      ) : (
        <p className="mt-1 text-xs text-fg-muted">Needed to uninstall the agent. Showing it is recorded in the audit log.</p>
      )}
      {pending && !shown?.pending_token ? <p className="mt-1 text-[11px] text-warn">A rotated token is waiting for the agent to confirm it. The previous token works until then.</p> : null}
      <div className="mt-2 flex gap-2">
        <Button size="sm" variant="secondary" disabled={reveal.isPending} onClick={() => reveal.mutate()}>
          <Copy /> {shown ? 'Refresh' : 'Reveal'}
        </Button>
        <Button size="sm" variant="ghost" disabled={rotate.isPending} onClick={() => rotate.mutate()}>
          <RefreshCw /> Rotate
        </Button>
      </div>
    </div>
  )
}

/** H2: another enrollment used this device's hardware UUID. */
function DuplicateBanner({ d }: { d: DeviceDetail }) {
  const { can } = useAuth()
  const qc = useQueryClient()
  const [merge, setMerge] = useState<{ id: string; hostname: string } | null>(null)
  const dups = (d.duplicates ?? []).filter((x) => !x.decommissioned)
  const done = () => {
    void qc.invalidateQueries({ queryKey: qk.device(d.device.id) })
    void qc.invalidateQueries({ queryKey: ['devices'] })
  }
  const dismiss = useMutation({
    mutationFn: (other: string) => api.dismissDuplicate(d.device.id, other),
    onSuccess: () => (toast.success('Marked as separate devices'), done()),
    onError: (e) => toast.error('Could not update', { description: (e as Error).message }),
  })
  const doMerge = useMutation({
    mutationFn: (other: string) => api.mergeDevice(d.device.id, other),
    onSuccess: () => (toast.success('Merged. The other device was decommissioned.'), setMerge(null), done()),
    onError: (e) => toast.error('Merge failed', { description: (e as Error).message }),
  })
  if (!dups.length) return null
  return (
    <div role="alert" className="rounded-lg border border-warn/40 bg-warn-soft px-4 py-3 text-sm">
      <p className="flex items-center gap-2 font-medium">
        <AlertTriangle className="size-4 text-warn" /> Possible duplicate device
      </p>
      <p className="mt-1 text-fg-muted">
        Another enrollment reported the same hardware ID as this device. That happens after a re-install or a cloned VM, or when someone uses an enrollment token to impersonate this device. Both keep their own identity until you decide.
      </p>
      <ul className="mt-2 space-y-2">
        {dups.map((x) => (
          <li key={x.id} className="flex flex-wrap items-center gap-2">
            <Link to={`/devices/${x.id}`} className="font-mono font-medium hover:underline">
              {x.hostname}
            </Link>
            <span className="text-xs text-fg-muted">
              enrolled {timeAgo(x.first_seen)} · last seen {timeAgo(x.last_seen)}
            </span>
            {can('devices.write') ? (
              <span className="ml-auto flex gap-2">
                <Button size="sm" variant="secondary" onClick={() => setMerge({ id: x.id, hostname: x.hostname })}>
                  Merge into this device
                </Button>
                <Button size="sm" variant="ghost" disabled={dismiss.isPending} onClick={() => dismiss.mutate(x.id)}>
                  Not a duplicate
                </Button>
              </span>
            ) : null}
          </li>
        ))}
      </ul>
      {merge ? (
        <Dialog open onOpenChange={(o) => !o && setMerge(null)}>
          <DialogContent
            title={`Merge ${merge.hostname} into ${d.device.hostname}?`}
            description="Its alerts, incidents, actions and quarantine move to this device. It is then decommissioned and its agent certificate revoked. Raw telemetry stays under the old device."
            footer={
              <>
                <Button variant="ghost" onClick={() => setMerge(null)}>
                  Cancel
                </Button>
                <Button variant="danger" disabled={doMerge.isPending} onClick={() => doMerge.mutate(merge.id)}>
                  Merge and decommission {merge.hostname}
                </Button>
              </>
            }
          >
            <p className="text-sm text-fg-muted">Keep the device whose agent you trust (normally the one that has been reporting longest). If you are not sure this was a re-install, isolate and investigate first.</p>
          </DialogContent>
        </Dialog>
      ) : null}
    </div>
  )
}

/** DELETE /devices/:id (devices.write): revoke the agent certificate; history stays. POST /devices/:id/remove (devices.remove): remote uninstall. */
function DangerZone({ device, onRemove }: { device: Device; onRemove: () => void }) {
  const { can } = useAuth()
  const [open, setOpen] = useState(false)
  const { id: deviceId, hostname } = device
  const decommission = can('devices.write')
  const remove = can(REMOVE_PRIVILEGE)
  if (!decommission && !remove) return null
  return (
    <section aria-labelledby="danger-zone" className="rounded-lg border border-danger/40 bg-surface">
      <header className="border-b border-danger/30 px-4 py-2.5">
        <h2 id="danger-zone" className="flex items-center gap-1.5 text-sm font-semibold text-danger">
          <AlertTriangle className="size-4" aria-hidden /> Danger zone
        </h2>
      </header>
      {remove ? <RemoveDeviceRow device={device} onOpen={onRemove} /> : null}
      {decommission ? (
      <div className={cn('flex flex-wrap items-center gap-4 p-4', remove && 'border-t border-border')}>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-medium">Decommission this device</p>
          <p className="max-w-2xl text-xs text-fg-muted">Revokes the agent’s certificate so it can no longer connect, and takes the device off the list. The agent stays installed on the PC. Use it for retired, wiped or replaced machines. Alerts, incidents and the audit trail are kept.</p>
        </div>
        <Button variant="danger-outline" onClick={() => setOpen(true)}>
          <PowerOff /> Decommission device
        </Button>
      </div>
      ) : null}
      {open ? <DecommissionDialog deviceId={deviceId} hostname={hostname} onClose={() => setOpen(false)} /> : null}
    </section>
  )
}

export function DecommissionDialog({ deviceId, hostname, onClose }: { deviceId: string; hostname: string; onClose: () => void }) {
  const qc = useQueryClient()
  const nav = useNavigate()
  const [typed, setTyped] = useState('')
  const [error, setError] = useState<string | null>(null)
  const matches = typed.trim().toLowerCase() === hostname.toLowerCase()
  const del = useMutation({
    mutationFn: () => api.deleteDevice(deviceId),
    onSuccess: () => {
      qc.removeQueries({ queryKey: qk.device(deviceId) })
      void qc.invalidateQueries({ queryKey: ['devices'] })
      void qc.invalidateQueries({ queryKey: qk.dashboard })
      toast.success(`${hostname} decommissioned`, { description: 'Its certificate is revoked. Uninstall the agent with its uninstall token.' })
      onClose()
      nav('/devices')
    },
    onError: (e) => setError((e as Error).message),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && !del.isPending && onClose()}>
      <DialogContent
        title={`Decommission ${hostname}?`}
        description="This can’t be undone from the console. To bring the machine back, install the agent again with a new enrollment token."
        footer={
          <>
            <Button variant="ghost" onClick={onClose} disabled={del.isPending}>
              Cancel
            </Button>
            <Button variant="danger" disabled={!matches || del.isPending} onClick={() => del.mutate()}>
              {del.isPending ? <Loader2 className="animate-spin" /> : <PowerOff />} Decommission
            </Button>
          </>
        }
      >
        <ul className="mb-4 list-disc space-y-1.5 pl-5 text-sm text-fg-muted marker:text-fg-subtle">
          <li>
            <span className="text-fg">Revokes the device’s certificate and drops its connection.</span> The agent can no longer send telemetry or receive policies and commands; pending commands are cancelled.
          </li>
          <li>
            <span className="text-fg">The agent stays installed</span> on the machine until someone uninstalls it locally with its uninstall token. Reveal the token on this page first if you still need it.
          </li>
          <li>
            <span className="text-fg">History is kept.</span> Alerts, incidents, response actions and audit entries for this device remain searchable.
          </li>
        </ul>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (matches && !del.isPending) del.mutate()
          }}
        >
          <Field label={<>Type <span className="font-mono">{hostname}</span> to confirm</>} htmlFor="decom-host" error={error}>
            <Input id="decom-host" autoFocus autoComplete="off" spellCheck={false} value={typed} onChange={(e) => (setTyped(e.target.value), setError(null))} className="font-mono" />
          </Field>
        </form>
      </DialogContent>
    </Dialog>
  )
}
