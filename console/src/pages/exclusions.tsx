import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { Plus, ShieldBan, Trash2, Fingerprint } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { AlertRow, ExclusionKind, ExclusionRow, IocAction, IocKind, IocRow, TreeNode } from '@/api/types'
import { SeverityIcon } from '@/components/badges'
import { EmptyState, ErrorState, LoadingRows, Mono, PageHeader } from '@/components/common'
import { DataTable } from '@/components/data-table'
import { SearchInput } from '@/components/filters'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, Textarea, inputClass } from '@/components/ui/input'
import { Segmented, Tabs, TabsContent, TabsList, TabsTrigger, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { formatDate, timeAgo } from '@/lib/format'
import { basename, cn } from '@/lib/utils'

const KIND_LABEL: Record<ExclusionKind, string> = { path: 'Path', sha256: 'SHA-256', signer: 'Signer', image: 'File name' }
const KIND_HINT: Record<ExclusionKind, string> = {
  signer: 'Safest choice for vendor software: matches only programs with a valid signature from this publisher.',
  sha256: 'Exact file. Breaks when the vendor ships an update.',
  path: 'Matches an image path; * is a wildcard. Avoid user-writable folders, malware can be placed there.',
  image: 'Matches any program with this file name, anywhere. Broadest and easiest to abuse.',
}

export default function Exclusions() {
  const [sp, setSp] = useSearchParams()
  const tab = sp.get('tab') ?? 'exclusions'
  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Exclusions & IOCs" description="Exclusions tell rules to ignore known-good software. Indicators (IOCs) allow, audit or block specific files, addresses and certificates." />
      <Tabs value={tab} onValueChange={(v) => setSp({ tab: v }, { replace: true })} className="flex min-h-0 flex-1 flex-col">
        <TabsList className="px-6">
          <TabsTrigger value="exclusions">
            <ShieldBan /> Exclusions
          </TabsTrigger>
          <TabsTrigger value="iocs">
            <Fingerprint /> Indicators
          </TabsTrigger>
        </TabsList>
        <TabsContent value="exclusions" className="min-h-0 flex-1">
          <ExclusionsTab />
        </TabsContent>
        <TabsContent value="iocs" className="min-h-0 flex-1">
          <IocsTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

function usePolicyNames() {
  const p = useQuery({ queryKey: qk.policies, queryFn: api.policies, staleTime: 60_000 })
  return { list: p.data ?? [], name: (id: string | null | undefined) => (id ? (p.data?.find((x) => x.id === id)?.name ?? id) : 'All policies') }
}

function ExclusionsTab() {
  const qc = useQueryClient()
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const list = useQuery({ queryKey: qk.exclusions, queryFn: api.exclusions })
  const { name } = usePolicyNames()
  const del = useMutation({
    mutationFn: (id: string) => api.deleteExclusion(id),
    onSuccess: () => {
      toast.success('Exclusion removed')
      void qc.invalidateQueries({ queryKey: qk.exclusions })
    },
  })
  const rows = (list.data ?? []).filter((e) => !q || `${e.value} ${e.reason} ${e.rule_id ?? ''}`.toLowerCase().includes(q.toLowerCase()))
  const cols = useMemo<ColumnDef<ExclusionRow, unknown>[]>(
    () => [
      { header: 'Type', accessorKey: 'kind', size: 90, cell: ({ row }) => <span className="text-xs text-fg-muted">{KIND_LABEL[row.original.kind]}</span> },
      { header: 'Value', accessorKey: 'value', cell: ({ row }) => <Mono className="text-[12.5px]">{row.original.value}</Mono> },
      { header: 'Rule', accessorKey: 'rule_id', size: 90, cell: ({ row }) => <span className="font-mono text-xs">{row.original.rule_id ?? <span className="text-warn">All rules</span>}</span> },
      { header: 'Scope', id: 'scope', accessorFn: (r) => name(r.policy_id), cell: ({ getValue }) => <span className="text-sm">{String(getValue())}</span> },
      { header: 'Reason', accessorKey: 'reason', enableSorting: false, cell: ({ row }) => <span className="line-clamp-2 text-sm text-fg-muted">{row.original.reason || '—'}</span> },
      {
        header: 'Expires',
        accessorKey: 'expires_at',
        size: 100,
        cell: ({ row }) => {
          const e = row.original.expires_at
          if (!e) return <span className="text-xs text-fg-subtle">Never</span>
          return <span className={cn('text-xs', e < Date.now() ? 'text-danger' : e < Date.now() + 14 * 86400000 ? 'text-warn' : 'text-fg-muted')}>{e < Date.now() ? 'Expired' : formatDate(e)}</span>
        },
      },
      { header: 'Added', accessorKey: 'created_at', size: 120, cell: ({ row }) => <span className="text-xs text-fg-muted">{timeAgo(row.original.created_at)} · {row.original.created_by.split('@')[0]}</span> },
      {
        id: 'x',
        size: 44,
        enableSorting: false,
        cell: ({ row }) =>
          can('exclusions.write') ? (
            <Button size="icon-sm" variant="ghost" aria-label="Delete exclusion" onClick={(e) => (e.stopPropagation(), confirm(`Remove the exclusion for ${row.original.value}?`) && del.mutate(row.original.id))}>
              <Trash2 />
            </Button>
          ) : null,
      },
    ],
    [name, can, del],
  )
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-6 py-3">
        <SearchInput value={q} onChange={setQ} placeholder="Filter exclusions…" className="w-64" />
        <div className="ml-auto">
          {can('exclusions.write') ? (
            <Button variant="primary" size="sm" onClick={() => setOpen(true)}>
              <Plus /> Add exclusion
            </Button>
          ) : null}
        </div>
      </div>
      <div className="min-h-0 flex-1 border-t border-border bg-surface">
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows />
        ) : (
          <DataTable
            label="Exclusions"
            data={rows}
            columns={cols}
            getRowId={(r) => r.id}
            empty={<EmptyState title="No exclusions" action={can('exclusions.write') ? <Button size="sm" onClick={() => setOpen(true)}>Add exclusion</Button> : null}>Add one from an alert with “Exclude…” to see exactly what it would hide first.</EmptyState>}
          />
        )}
      </div>
      {open ? <ExclusionDialog open onOpenChange={setOpen} /> : null}
    </div>
  )
}

/** Create-exclusion dialog with live scope preview. Prefilled when opened from an alert. */
export function ExclusionDialog({ open, onOpenChange, fromAlert, processHint }: { open: boolean; onOpenChange: (o: boolean) => void; fromAlert?: AlertRow; processHint?: TreeNode }) {
  const qc = useQueryClient()
  const { list: policies } = usePolicyNames()
  const alertDetail = useQuery({ queryKey: qk.alert(fromAlert?.id ?? ''), queryFn: () => api.alert(fromAlert!.id), enabled: !!fromAlert })
  const proc = alertDetail.data?.process ?? processHint
  const suggested: ExclusionKind = proc?.signed === 'valid' && proc.signer ? 'signer' : proc?.sha256 ? 'sha256' : 'path'
  const [kind, setKind] = useState<ExclusionKind>(fromAlert ? suggested : 'signer')
  const [value, setValue] = useState('')
  const [ruleId, setRuleId] = useState<string>(fromAlert?.rule_id ?? '')
  const [policyId, setPolicyId] = useState<string>('')
  const [reason, setReason] = useState('')
  const [expires, setExpires] = useState('90')
  const [debounced, setDebounced] = useState('')

  useEffect(() => {
    if (!proc) return
    const v = kind === 'signer' ? (proc.signer ?? '') : kind === 'sha256' ? (proc.sha256 ?? '') : kind === 'image' ? basename(proc.image).toLowerCase() : proc.image
    setValue(v)
  }, [kind, proc])
  useEffect(() => {
    if (fromAlert && proc) setKind(suggested)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [proc?.guid])
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), 300)
    return () => clearTimeout(t)
  }, [value])

  const preview = useQuery({
    queryKey: ['excl-preview', kind, debounced, ruleId],
    queryFn: () => api.exclusionPreview({ kind, value: debounced, rule_id: ruleId || null }),
    enabled: debounced.trim().length > 0,
  })
  const risky = (kind === 'path' && /\\(downloads|appdata\\local\\temp|temp)\\/i.test(value)) || (kind === 'path' && /^\*|\\\*\\?$/.test(value)) || (kind === 'image' && !ruleId)
  const create = useMutation({
    mutationFn: () =>
      api.createExclusion({ kind, value: value.trim(), rule_id: ruleId || null, expires_at: expires ? Date.now() + Number(expires) * 86400000 : null, reason, policy_id: policyId || null, from_alert_id: fromAlert?.id }),
    onSuccess: () => {
      toast.success('Exclusion added', { description: 'Agents receive it with the next policy push.' })
      void qc.invalidateQueries({ queryKey: qk.exclusions })
      onOpenChange(false)
    },
    onError: (e) => toast.error('Exclusion not saved', { description: (e as Error).message }),
  })
  const n = preview.data?.matching_alerts_30d
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent
        size="lg"
        title={fromAlert ? `Exclude from ${fromAlert.rule_id}` : 'Add exclusion'}
        description={fromAlert ? `${basename(fromAlert.image)} on ${fromAlert.hostname}` : 'Tell detection rules to ignore known-good software.'}
        footer={
          <>
            <Button variant="ghost" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!value.trim() || !reason.trim() || create.isPending} onClick={() => create.mutate()}>
              {create.isPending ? 'Saving…' : n != null ? `Add exclusion (hides ${n} alert${n === 1 ? '' : 's'})` : 'Add exclusion'}
            </Button>
          </>
        }
      >
        <div className="grid gap-5 md:grid-cols-[minmax(0,1fr)_260px]">
          <div className="space-y-4">
            <Field label="Match by" hint={KIND_HINT[kind]}>
              <Segmented label="Exclusion type" value={kind} onChange={setKind} options={(Object.keys(KIND_LABEL) as ExclusionKind[]).map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
            </Field>
            <Field label="Value" htmlFor="ex-value">
              <Input id="ex-value" value={value} onChange={(e) => setValue(e.target.value)} className="font-mono text-[12.5px]" placeholder={kind === 'signer' ? '2BrightSparks Pte Ltd' : kind === 'path' ? 'C:\\Program Files\\Vendor\\*' : ''} />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Rule" htmlFor="ex-rule" hint="Limit to one rule (recommended)">
                <Input id="ex-rule" value={ruleId} onChange={(e) => setRuleId(e.target.value.toUpperCase())} placeholder="All rules" className="font-mono" />
              </Field>
              <Field label="Applies to" htmlFor="ex-policy">
                <select id="ex-policy" value={policyId} onChange={(e) => setPolicyId(e.target.value)} className={cn(inputClass, 'h-8')}>
                  <option value="">All policies</option>
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Expires after (days)" htmlFor="ex-exp" hint="Blank = never">
                <Input id="ex-exp" value={expires} onChange={(e) => setExpires(e.target.value.replace(/\D/g, ''))} />
              </Field>
            </div>
            <Field label="Reason" htmlFor="ex-reason" hint="Required. Shown to whoever reviews this exclusion later.">
              <Textarea id="ex-reason" value={reason} onChange={(e) => setReason(e.target.value)} className="min-h-14" placeholder="e.g. Nightly SyncBackPro backup of browser profiles (IT)" />
            </Field>
          </div>
          <div className="rounded-lg border border-border bg-surface-2/60 p-3">
            <h3 className="text-xs font-medium text-fg-subtle">Scope preview</h3>
            {!debounced.trim() ? (
              <p className="mt-2 text-sm text-fg-muted">Enter a value to see which past alerts it would hide.</p>
            ) : preview.isPending ? (
              <p className="mt-2 text-sm text-fg-muted">Checking the last 30 days…</p>
            ) : preview.error ? (
              <p className="mt-2 text-sm text-danger">{(preview.error as Error).message}</p>
            ) : (
              <>
                <p className="mt-1 text-[1.75rem] font-semibold tabular leading-tight">{n}</p>
                <p className="text-sm text-fg-muted">alert{n === 1 ? '' : 's'} in the last 30 days would have been hidden{ruleId ? ` for ${ruleId}` : ' across all rules'}.</p>
                {preview.data!.sample.length ? (
                  <ul className="mt-3 space-y-1.5 border-t border-border pt-2">
                    {preview.data!.sample.map((a) => (
                      <li key={a.id} className="flex items-start gap-1.5 text-xs">
                        <SeverityIcon severity={a.severity} className="mt-0.5 size-3" />
                        <span className="min-w-0">
                          <span className="font-mono">{a.hostname}</span> <span className="text-fg-muted">{a.rule_id}</span>
                          <span className="block truncate text-fg-subtle">{basename(a.image)}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : null}
              </>
            )}
            {risky ? <p className="mt-3 rounded-md border border-warn/40 bg-warn-soft px-2 py-1.5 text-xs text-warn">This scope is broad. Stealers run from these folders and can reuse common file names. Prefer a signer or hash, and limit it to one rule.</p> : null}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------- IOCs

const IOC_KIND: Record<IocKind, string> = { sha256: 'SHA-256', ip: 'IP', domain: 'Domain', url: 'URL', certificate: 'Certificate' }

function IocsTab() {
  const qc = useQueryClient()
  const { can } = useAuth()
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const list = useQuery({ queryKey: qk.iocs, queryFn: api.iocs })
  const del = useMutation({
    mutationFn: (id: string) => api.deleteIoc(id),
    onSuccess: () => {
      toast.success('Indicator removed')
      void qc.invalidateQueries({ queryKey: qk.iocs })
    },
  })
  const rows = (list.data ?? []).filter((e) => !q || `${e.value} ${e.description}`.toLowerCase().includes(q.toLowerCase()))
  const cols = useMemo<ColumnDef<IocRow, unknown>[]>(
    () => [
      { header: 'Type', accessorKey: 'kind', size: 100, cell: ({ row }) => <span className="text-xs text-fg-muted">{IOC_KIND[row.original.kind]}</span> },
      { header: 'Value', accessorKey: 'value', cell: ({ row }) => <Mono className="text-[12.5px]">{row.original.value}</Mono> },
      { header: 'Action', accessorKey: 'action', size: 90, cell: ({ row }) => <IocActionBadge action={row.original.action} /> },
      { header: 'Description', accessorKey: 'description', enableSorting: false, cell: ({ row }) => <span className="text-sm text-fg-muted">{row.original.description || '—'}</span> },
      { header: 'Hits', accessorKey: 'hits', size: 60, cell: ({ row }) => <span className="tabular">{row.original.hits}</span> },
      { header: 'Added', accessorKey: 'created_at', size: 130, cell: ({ row }) => <span className="text-xs text-fg-muted">{timeAgo(row.original.created_at)} · {row.original.created_by.split('@')[0]}</span> },
      {
        id: 'x',
        size: 44,
        enableSorting: false,
        cell: ({ row }) => (can('iocs.write') ? <Button size="icon-sm" variant="ghost" aria-label="Delete indicator" onClick={() => confirm(`Remove ${row.original.value}?`) && del.mutate(row.original.id)}><Trash2 /></Button> : null),
      },
    ],
    [can, del],
  )
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 px-6 py-3">
        <SearchInput value={q} onChange={setQ} placeholder="Filter indicators…" className="w-64" />
        <div className="ml-auto">
          {can('iocs.write') ? (
            <Button variant="primary" size="sm" onClick={() => setOpen(true)}>
              <Plus /> Add indicators
            </Button>
          ) : null}
        </div>
      </div>
      <div className="min-h-0 flex-1 border-t border-border bg-surface">
        {list.error ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : list.isPending ? <LoadingRows /> : <DataTable label="Indicators" data={rows} columns={cols} getRowId={(r) => r.id} empty={<EmptyState title="No indicators">Paste hashes, IPs or domains from a threat report to block them everywhere.</EmptyState>} />}
      </div>
      {open ? <IocDialog onClose={() => setOpen(false)} /> : null}
    </div>
  )
}

function IocActionBadge({ action }: { action: IocAction }) {
  return <span className={cn('rounded px-1.5 py-px text-xs font-medium', action === 'block' ? 'bg-danger-soft text-danger' : action === 'allow' ? 'bg-ok-soft text-ok' : 'bg-surface-2 text-fg-muted')}>{action === 'block' ? 'Block' : action === 'allow' ? 'Allow' : 'Audit'}</span>
}

export function guessIocKind(v: string): IocKind | null {
  const s = v.trim()
  if (/^[a-f0-9]{64}$/i.test(s)) return 'sha256'
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s) || /^[0-9a-f]*:[0-9a-f:]+$/i.test(s)) return 'ip'
  if (/^https?:\/\//i.test(s)) return 'url'
  if (/^CN=|^[a-f0-9]{40}$/i.test(s)) return 'certificate'
  if (/^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(s)) return 'domain'
  return null
}

function IocDialog({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [text, setText] = useState('')
  const [action, setAction] = useState<IocAction>('block')
  const [desc, setDesc] = useState('')
  const parsed = text
    .split(/[\n,;]+/)
    .map((s) => s.trim().replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.'))
    .filter(Boolean)
    .map((v) => ({ value: v, kind: guessIocKind(v) }))
  const bad = parsed.filter((p) => !p.kind)
  const [broad, setBroad] = useState(false)
  const m = useMutation({
    mutationFn: () => api.createIocs(parsed.filter((p) => p.kind).map((p) => ({ kind: p.kind!, value: p.value, action, description: desc })), broad),
    onSuccess: (r) => {
      const n = Array.isArray(r) ? r.length : ((r as { items?: unknown[] }).items?.length ?? 0)
      toast.success(`Added ${n} indicator${n === 1 ? '' : 's'}`)
      void qc.invalidateQueries({ queryKey: qk.iocs })
      onClose()
    },
    onError: (e) => toast.error('Indicators not saved', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="lg"
        title="Add indicators"
        description="Paste one per line. Defanged values like hxxp:// and example[.]com are cleaned up."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!parsed.length || parsed.length === bad.length || m.isPending} onClick={() => m.mutate()}>
              Add {parsed.length - bad.length || ''} indicator{parsed.length - bad.length === 1 ? '' : 's'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Textarea value={text} onChange={(e) => setText(e.target.value)} aria-label="Indicators" className="min-h-32 font-mono text-[12.5px]" placeholder={'185.208.158.114\ncdn-verify-human[.]top\ne3b14f7d0a2c…'} />
          {parsed.length ? (
            <ul className="max-h-40 space-y-1 overflow-auto rounded-md border border-border p-2 text-xs">
              {parsed.map((p, i) => (
                <li key={i} className="flex items-center gap-2">
                  <span className={cn('w-20 shrink-0', p.kind ? 'text-fg-muted' : 'text-danger')}>{p.kind ? IOC_KIND[p.kind] : 'Unrecognised'}</span>
                  <span className="truncate font-mono">{p.value}</span>
                </li>
              ))}
            </ul>
          ) : null}
          <div className="flex flex-wrap items-end gap-4">
            <Field label="Action">
              <Segmented label="IOC action" value={action} onChange={setAction} options={[{ value: 'block', label: 'Block', tone: 'danger' }, { value: 'audit', label: 'Audit' }, { value: 'allow', label: 'Allow' }]} />
            </Field>
            <Field label="Description" htmlFor="ioc-desc" className="min-w-60 flex-1">
              <Input id="ioc-desc" value={desc} onChange={(e) => setDesc(e.target.value)} placeholder="Source or campaign" />
            </Field>
          </div>
          {action === 'allow' ? <p className="text-xs text-warn">Allow overrides detections for these items everywhere. Use it only for software you have verified.</p> : null}
          {action === 'block' ? (
            <p className="text-xs text-fg-muted">
              A matching connection is blocked for 24 hours and the connecting process is killed. IP ranges wider than /16 (IPv6 /48) and private or loopback addresses are refused unless you confirm below.
            </p>
          ) : null}
          {m.error && /confirm_broad/.test((m.error as Error).message) ? (
            <label className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-xs">
              <input type="checkbox" checked={broad} onChange={(e) => setBroad(e.target.checked)} className="mt-0.5" />
              <span>I understand this range covers many hosts (or internal servers) and every matching connection on every device will be blocked.</span>
            </label>
          ) : null}
          <Tooltip content="Agents receive indicators with the next policy push (usually within a minute)">
            <p className="text-xs text-fg-subtle">Applies to all policies.</p>
          </Tooltip>
        </div>
      </DialogContent>
    </Dialog>
  )
}
