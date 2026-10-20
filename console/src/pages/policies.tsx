import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Copy, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import { EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, inputClass } from '@/components/ui/input'
import { Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { timeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'

export default function Policies() {
  const nav = useNavigate()
  const qc = useQueryClient()
  const { can } = useAuth()
  const list = useQuery({ queryKey: qk.policies, queryFn: api.policies })
  const groups = useQuery({ queryKey: qk.groups, queryFn: api.groups })
  const [create, setCreate] = useState<{ clone?: string } | null>(null)
  const del = useMutation({
    mutationFn: (id: string) => api.deletePolicy(id),
    onSuccess: () => {
      toast.success('Policy deleted')
      void qc.invalidateQueries({ queryKey: qk.policies })
    },
    onError: (e) => toast.error('Policy not deleted', { description: (e as Error).message }),
  })
  return (
    <div>
      <PageHeader
        title="Policies"
        description="A policy decides what each rule does (off, audit or protect), which Windows hardening is applied, and what telemetry leaves the device. Each device group uses one policy."
        actions={can('policies.write') ? <Button variant="primary" size="sm" onClick={() => setCreate({})}><Plus /> New policy</Button> : null}
      />
      <div className="p-6">
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows rows={4} />
        ) : !list.data.length ? (
          <EmptyState title="No policies" />
        ) : (
          <ul className="grid gap-3 md:grid-cols-2">
            {list.data.map((p) => {
              const gs = (groups.data ?? []).filter((g) => g.policy_id === p.id)
              return (
                <li key={p.id} className="group relative rounded-lg border border-border bg-surface transition-colors hover:border-border-strong">
                  <button type="button" onClick={() => nav(`/policies/${p.id}`)} className="block w-full p-4 text-left">
                    <div className="flex items-baseline justify-between gap-3">
                      <h2 className="font-semibold">{p.name}</h2>
                      <span className="text-xs tabular text-fg-subtle">v{p.version}</span>
                    </div>
                    <p className="mt-1 text-sm text-fg-muted">
                      {p.device_count} device{p.device_count === 1 ? '' : 's'} in {gs.length ? gs.map((g) => g.name).join(', ') : 'no groups'}
                    </p>
                    <p className="mt-3 text-xs text-fg-subtle">Changed {timeAgo(p.updated_at)}</p>
                  </button>
                  {can('policies.write') ? (
                    <div className="absolute bottom-3 right-3 flex gap-1 opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100">
                      <Tooltip content="Duplicate">
                        <Button size="icon-sm" variant="ghost" aria-label={`Duplicate ${p.name}`} onClick={() => setCreate({ clone: p.id })}>
                          <Copy />
                        </Button>
                      </Tooltip>
                      <Tooltip content={gs.length ? 'Assigned to a group; reassign first' : 'Delete'}>
                        <span>
                          <Button size="icon-sm" variant="ghost" aria-label={`Delete ${p.name}`} disabled={gs.length > 0} onClick={() => confirm(`Delete policy “${p.name}”?`) && del.mutate(p.id)}>
                            <Trash2 />
                          </Button>
                        </span>
                      </Tooltip>
                    </div>
                  ) : null}
                </li>
              )
            })}
          </ul>
        )}
      </div>
      {create ? <CreatePolicy clone={create.clone} onClose={() => setCreate(null)} /> : null}
    </div>
  )
}

function CreatePolicy({ clone, onClose }: { clone?: string; onClose: () => void }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const list = useQuery({ queryKey: qk.policies, queryFn: api.policies })
  const [name, setName] = useState('')
  const [from, setFrom] = useState(clone ?? 'pol-default')
  const m = useMutation({
    mutationFn: () => api.createPolicy({ name, clone_from: from }),
    onSuccess: (p) => {
      void qc.invalidateQueries({ queryKey: qk.policies })
      toast.success(`Created “${p.name}”`)
      nav(`/policies/${p.id}`)
    },
    onError: (e) => toast.error('Policy not created', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="sm"
        title={clone ? 'Duplicate policy' : 'New policy'}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!name.trim() || m.isPending} onClick={() => m.mutate()}>
              Create policy
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name" htmlFor="pol-name">
            <Input id="pol-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus placeholder="e.g. Contractors" />
          </Field>
          <Field label="Start from" htmlFor="pol-from" hint="Copies every setting; you can change them next.">
            <select id="pol-from" value={from} onChange={(e) => setFrom(e.target.value)} className={cn(inputClass, 'h-8')}>
              {(list.data ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </Field>
        </div>
      </DialogContent>
    </Dialog>
  )
}
