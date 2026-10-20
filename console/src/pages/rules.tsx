import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { ExternalLink, FileCode2, Plus, Trash2, X } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import { ApiError } from '@/api/client'
import type { RuleCategory, RuleRow, Severity } from '@/api/types'
import { ModeBadge, SeverityBadge, SeverityIcon } from '@/components/badges'
import { AttackChips, EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { DataTable } from '@/components/data-table'
import { FilterChip, SearchInput, useUrlList, useUrlString } from '@/components/filters'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Sheet } from '@/components/ui/sheet'
import { Switch } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { RULE_CATEGORY_LABEL, SEVERITY_LABEL } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { SIGMA_TEMPLATE } from '@/lib/sigma-template'

export default function Rules() {
  const [sp, setSp] = useSearchParams()
  const { can } = useAuth()
  const [q, setQ] = useUrlString('q')
  const [cats, setCats] = useUrlList('category')
  const [kinds, setKinds] = useUrlList('kind')
  const [sev, setSev] = useUrlList('severity')
  const [adding, setAdding] = useState(false)
  const list = useQuery({ queryKey: qk.rules, queryFn: api.rules })
  const selected = sp.get('rule')
  const select = (id: string | null) =>
    setSp(
      (p) => {
        const n = new URLSearchParams(p)
        if (id) n.set('rule', id)
        else n.delete('rule')
        return n
      },
      { replace: true },
    )
  const rows = (list.data ?? [])
    .filter((r) => !cats.length || cats.includes(r.category))
    .filter((r) => !kinds.length || kinds.includes(r.kind))
    .filter((r) => !sev.length || sev.includes(r.severity))
    .filter((r) => !q || `${r.id} ${r.name} ${r.description} ${(r.attack ?? []).join(' ')}`.toLowerCase().includes(q.toLowerCase()))
    .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }))
  const cols = useMemo<ColumnDef<RuleRow, unknown>[]>(
    () => [
      { header: 'ID', accessorKey: 'id', size: 120, cell: ({ row }) => <span className="font-mono text-xs">{row.original.id}</span> },
      {
        header: 'Rule',
        accessorKey: 'name',
        cell: ({ row }) => (
          <div className="min-w-0 max-w-[520px]">
            <p className="font-medium">{row.original.name}</p>
            <p className="truncate text-xs text-fg-muted">{row.original.description}</p>
            {row.original.kind !== 'builtin' && row.original.author ? <p className="text-[11px] text-fg-subtle">by {row.original.author}{row.original.license ? ` · ${row.original.license}` : ''}</p> : null}
          </div>
        ),
      },
      { header: 'Category', accessorKey: 'category', size: 140, cell: ({ row }) => <span className="text-sm text-fg-muted">{RULE_CATEGORY_LABEL[row.original.category]}</span> },
      { header: 'Severity', id: 'sev', accessorFn: (r) => ['info', 'low', 'medium', 'high', 'critical'].indexOf(r.severity), size: 100, cell: ({ row }) => <SeverityBadge severity={row.original.severity} /> },
      { header: 'ATT&CK', id: 'attack', enableSorting: false, cell: ({ row }) => <AttackChips ids={row.original.attack ?? []} max={2} /> },
      { header: 'Default', accessorKey: 'default_mode', size: 80, cell: ({ row }) => <ModeBadge mode={row.original.default_mode} /> },
      { header: 'Hits 7d', accessorKey: 'hits_7d', size: 80, cell: ({ row }) => <span className={cn('tabular', row.original.hits_7d ? 'font-medium' : 'text-fg-subtle')}>{row.original.hits_7d}</span> },
    ],
    [],
  )
  const current = list.data?.find((r) => r.id === selected) ?? null
  return (
    <div className="flex h-full flex-col">
      <PageHeader
        title="Rules"
        description="Built-in stealer (ST) and tamper (TP) rules, plus your custom Sigma rules. Choose each rule’s mode per policy."
        actions={can('rules.write') ? <Button variant="primary" size="sm" onClick={() => setAdding(true)}><Plus /> Add Sigma rule</Button> : null}
      >
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <SearchInput value={q} onChange={setQ} placeholder="Search rules or ATT&CK ids…" className="w-64" />
          <FilterChip label="Category" value={cats} onChange={setCats} options={(Object.keys(RULE_CATEGORY_LABEL) as RuleCategory[]).map((c) => ({ value: c, label: RULE_CATEGORY_LABEL[c] }))} />
          <FilterChip label="Source" value={kinds} onChange={setKinds} options={[{ value: 'builtin', label: 'Built-in' }, { value: 'sigma', label: 'Custom Sigma' }]} />
          <FilterChip label="Severity" value={sev} onChange={setSev} options={(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => ({ value: s, label: <span className="inline-flex items-center gap-1.5"><SeverityIcon severity={s} className="size-3.5" />{SEVERITY_LABEL[s]}</span> }))} />
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 bg-surface">
        {list.error ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : list.isPending ? <LoadingRows /> : <DataTable label="Rules" data={rows} columns={cols} getRowId={(r) => r.id} keyboard activeId={selected} onActiveChange={(id) => id && selected && select(id)} onRowClick={(r) => select(r.id)} rowClassName={(r) => (r.kind !== 'builtin' && !r.enabled_custom ? 'opacity-60' : undefined)} empty={<EmptyState title="No rules match" />} />}
      </div>
      <Sheet open={!!current} onOpenChange={(o) => !o && select(null)} label="Rule details drawer">
        {current ? <RuleDetail rule={current} onClose={() => select(null)} /> : null}
      </Sheet>
      {adding ? <SigmaDialog onClose={() => setAdding(false)} /> : null}
    </div>
  )
}

function RuleDetail({ rule, onClose }: { rule: RuleRow; onClose: () => void }) {
  const qc = useQueryClient()
  const { can } = useAuth()
  const [edit, setEdit] = useState(false)
  const patch = useMutation({
    mutationFn: (enabled: boolean) => api.patchRule(rule.id, { enabled_custom: enabled }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: qk.rules }),
  })
  const del = useMutation({
    mutationFn: () => api.deleteRule(rule.id),
    onSuccess: () => {
      toast.success(`Deleted ${rule.id}`)
      void qc.invalidateQueries({ queryKey: qk.rules })
      onClose()
    },
  })
  return (
    <>
      <div className="flex items-center gap-2 border-b border-border px-4 py-2.5">
        <span className="font-mono text-sm">{rule.id}</span>
        <span className="text-xs text-fg-subtle">{rule.kind === 'builtin' ? 'Built-in' : 'Custom Sigma'}</span>
        <Button size="icon-sm" variant="ghost" className="ml-auto" aria-label="Close" onClick={onClose}>
          <X />
        </Button>
      </div>
      <div className="min-h-0 flex-1 space-y-6 overflow-y-auto p-5">
        <div>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <SeverityBadge severity={rule.severity} />
            <span className="text-xs text-fg-muted">{RULE_CATEGORY_LABEL[rule.category]}</span>
            <span className="text-xs text-fg-muted">· default</span>
            <ModeBadge mode={rule.default_mode} />
          </div>
          <h2 className="text-lg font-semibold leading-snug">{rule.name}</h2>
          <p className="mt-2 text-sm leading-relaxed text-fg-muted">{rule.description}</p>
        </div>
        <dl className="space-y-3 text-sm">
          <div>
            <dt className="text-xs text-fg-subtle">In Protect mode</dt>
            <dd>{rule.protect_action || 'Alert only'}</dd>
          </div>
          <div>
            <dt className="text-xs text-fg-subtle">Safe to protect on day one</dt>
            <dd>{rule.protect_day_one ? 'Yes, low false-positive rate' : 'No, run in Audit for about two weeks and add exclusions first'}</dd>
          </div>
          <div>
            <dt className="text-xs text-fg-subtle">Alerts in the last 7 days</dt>
            <dd className="tabular">{rule.hits_7d}</dd>
          </div>
          <div>
            <dt className="text-xs text-fg-subtle">MITRE ATT&CK</dt>
            <dd className="mt-0.5">
              <AttackChips ids={rule.attack ?? []} max={10} />
            </dd>
          </div>
          {rule.author ? (
            <div>
              <dt className="text-xs text-fg-subtle">Author</dt>
              <dd>
                {rule.author}
                {rule.license ? <span className="text-fg-muted"> · {rule.license}</span> : null}
              </dd>
            </div>
          ) : null}
        </dl>
        {rule.false_positives?.length ? (
          <div>
            <h3 className="mb-1 text-xs font-medium text-fg-subtle">Known false positives</h3>
            <ul className="list-disc space-y-0.5 pl-5 text-sm text-fg-muted">
              {rule.false_positives.map((f) => (
                <li key={f}>{f}</li>
              ))}
            </ul>
            <p className="mt-1.5 text-xs text-fg-subtle">Exclude these by signer, scoped to this rule, from an alert’s “Exclude…” action.</p>
          </div>
        ) : null}
        {rule.references?.length ? (
          <div>
            <h3 className="mb-1 text-xs font-medium text-fg-subtle">References</h3>
            <ul className="space-y-1 text-sm">
              {rule.references.map((r) => (
                <li key={r}>
                  <a href={r} target="_blank" rel="noreferrer noopener" className="inline-flex items-center gap-1 break-all text-accent-text hover:underline">
                    {r.replace(/^https?:\/\//, '')} <ExternalLink className="size-3 shrink-0" />
                  </a>
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        {rule.kind !== 'builtin' ? (
          <div className="space-y-3 border-t border-border pt-4">
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>
                <span className="font-medium">Distribute to agents</span>
                <span className="block text-xs text-fg-muted">Off keeps the rule here without running it.</span>
              </span>
              <Switch checked={rule.enabled_custom} disabled={!can('rules.write')} onCheckedChange={(v) => patch.mutate(v)} aria-label="Distribute to agents" />
            </label>
            {rule.source ? (
              <div>
                <div className="mb-1 flex items-center justify-between">
                  <h3 className="text-xs font-medium text-fg-subtle">Sigma source</h3>
                  {can('rules.write') ? (
                    <Button size="sm" variant="ghost" onClick={() => setEdit(true)}>
                      <FileCode2 /> Edit
                    </Button>
                  ) : null}
                </div>
                <pre className="max-h-80 overflow-auto rounded-md border border-border bg-surface-2 p-3 font-mono text-[11.5px] leading-relaxed">{rule.source}</pre>
              </div>
            ) : null}
            {can('rules.write') ? (
              <Button size="sm" variant="danger-outline" onClick={() => confirm(`Delete ${rule.id}?`) && del.mutate()}>
                <Trash2 /> Delete rule
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
      {edit ? <SigmaDialog onClose={() => setEdit(false)} existing={rule} /> : null}
    </>
  )
}

function SigmaDialog({ onClose, existing }: { onClose: () => void; existing?: RuleRow }) {
  const qc = useQueryClient()
  const [src, setSrc] = useState(existing?.source ?? SIGMA_TEMPLATE)
  const [errors, setErrors] = useState<string[]>([])
  const m = useMutation({
    mutationFn: () => (existing ? api.patchRule(existing.id, { source: src }) : api.createRule(src)),
    onSuccess: (r) => {
      toast.success(existing ? `Updated ${r.id}` : `Added ${r.id}`, { description: 'It runs in Audit until a policy sets it to Protect.' })
      void qc.invalidateQueries({ queryKey: qk.rules })
      onClose()
    },
    onError: (e) => setErrors(e instanceof ApiError ? e.message.split('\n') : [String(e)]),
  })
  const lines = src.split('\n').length
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="xl"
        title={existing ? `Edit ${existing.id}` : 'Add a Sigma rule'}
        description="Paste a SigmaHQ rule or write your own. The server compiles it against Kestrel’s field mapping before saving."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!src.trim() || m.isPending} onClick={() => m.mutate()}>
              {m.isPending ? 'Validating…' : existing ? 'Validate and save' : 'Validate and add'}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <div className="flex overflow-hidden rounded-md border border-border-strong bg-surface focus-within:outline-2 focus-within:outline-ring">
            <div aria-hidden className="select-none border-r border-border bg-surface-2 px-2 py-2 text-right font-mono text-[12px] leading-[1.6] text-fg-subtle">
              {Array.from({ length: lines }, (_, i) => (
                <div key={i}>{i + 1}</div>
              ))}
            </div>
            <textarea
              value={src}
              onChange={(e) => {
                setSrc(e.target.value)
                setErrors([])
              }}
              onKeyDown={(e) => {
                if (e.key === 'Tab') {
                  e.preventDefault()
                  const t = e.currentTarget
                  const s = t.selectionStart
                  setSrc(src.slice(0, s) + '  ' + src.slice(t.selectionEnd))
                  requestAnimationFrame(() => t.setSelectionRange(s + 2, s + 2))
                }
              }}
              spellCheck={false}
              aria-label="Sigma rule YAML"
              aria-invalid={errors.length > 0}
              className="min-h-[360px] flex-1 resize-y bg-transparent px-3 py-2 font-mono text-[12px] leading-[1.6] outline-none"
              wrap="off"
            />
          </div>
          {errors.length ? (
            <div role="alert" className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2">
              <p className="text-sm font-medium text-danger">The server rejected this rule</p>
              <ul className="mt-1 list-disc pl-5 font-mono text-xs text-danger">
                {errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          ) : (
            <p className="text-xs text-fg-muted">SigmaHQ rules are under the Detection Rule License 1.1: keep the author field. Kestrel shows it on every alert the rule raises.</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
