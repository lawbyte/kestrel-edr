import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { ColumnDef } from '@tanstack/react-table'
import { FileArchive } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { QuarantineItem, QuarantineState } from '@/api/types'
import { EmptyState, ErrorState, LoadingRows, Mono, PageHeader } from '@/components/common'
import { DataTable } from '@/components/data-table'
import { FilterChip, useUrlList } from '@/components/filters'
import { CopyButton } from '@/components/copy-button'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { useAuth } from '@/lib/auth'
import { formatDateTime, shortHash, timeAgo } from '@/lib/format'
import { basename, cn, dirname } from '@/lib/utils'

const STATE_LABEL: Record<QuarantineState, string> = { held: 'In quarantine', restored: 'Restored', deleted: 'Deleted' }

export default function Quarantine() {
  const qc = useQueryClient()
  const { can } = useAuth()
  const [state, setState] = useUrlList('state', ['held'])
  const [confirm, setConfirm] = useState<{ item: QuarantineItem; op: 'restore' | 'delete' } | null>(null)
  const list = useQuery({ queryKey: qk.quarantine, queryFn: api.quarantine })
  const m = useMutation({
    mutationFn: (v: { item: QuarantineItem; op: 'restore' | 'delete' }) => (v.op === 'restore' ? api.restoreQuarantine(v.item.id) : api.deleteQuarantine(v.item.id)),
    onSuccess: (_d, v) => {
      toast.success(v.op === 'restore' ? `Restoring ${basename(v.item.original_path)} on ${v.item.hostname}` : `Deleting ${basename(v.item.original_path)} from ${v.item.hostname}`)
      void qc.invalidateQueries({ queryKey: qk.quarantine })
      setConfirm(null)
    },
    onError: (e) => toast.error('Action failed', { description: (e as Error).message }),
  })
  const items = (list.data ?? []).filter((i) => !state.length || state.includes(i.state))
  const cols = useMemo<ColumnDef<QuarantineItem, unknown>[]>(
    () => [
      {
        header: 'File',
        id: 'file',
        accessorFn: (r) => basename(r.original_path),
        cell: ({ row }) => (
          <div className="min-w-0 max-w-[520px]">
            <p className="font-mono text-[13px] font-medium">{basename(row.original.original_path)}</p>
            <p className="truncate font-mono text-[11.5px] text-fg-subtle">{dirname(row.original.original_path)}</p>
          </div>
        ),
      },
      { header: 'Device', accessorKey: 'hostname', cell: ({ row }) => <Link to={`/devices/${row.original.device_id}`} className="font-mono text-[13px] hover:underline">{row.original.hostname}</Link> },
      { header: 'SHA-256', accessorKey: 'sha256', enableSorting: false, cell: ({ row }) => <span className="inline-flex items-center gap-1"><Mono className="text-xs text-fg-muted" title={row.original.sha256}>{shortHash(row.original.sha256, 16)}</Mono><CopyButton text={row.original.sha256} iconOnly label="Copy SHA-256" /></span> },
      { header: 'State', accessorKey: 'state', size: 120, cell: ({ row }) => <span className={cn('text-sm', row.original.state === 'held' ? 'font-medium' : 'text-fg-muted')}>{STATE_LABEL[row.original.state]}</span> },
      { header: 'Quarantined', accessorKey: 'created_at', size: 120, cell: ({ row }) => <span className="text-xs text-fg-muted" title={formatDateTime(row.original.created_at)}>{timeAgo(row.original.created_at)}</span> },
      {
        id: 'ops',
        size: 170,
        enableSorting: false,
        cell: ({ row }) =>
          row.original.state === 'held' && can('response.file') ? (
            <span className="flex gap-1.5">
              <Button size="sm" onClick={() => setConfirm({ item: row.original, op: 'restore' })}>
                Restore
              </Button>
              <Button size="sm" variant="danger-outline" onClick={() => setConfirm({ item: row.original, op: 'delete' })}>
                Delete
              </Button>
            </span>
          ) : null,
      },
    ],
    [can],
  )
  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Quarantine" description="Files Kestrel moved into its encrypted vault on each device. Restoring puts the file back where it was.">
        <div className="mt-4">
          <FilterChip label="State" value={state} onChange={setState} options={(Object.keys(STATE_LABEL) as QuarantineState[]).map((s) => ({ value: s, label: STATE_LABEL[s] }))} />
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 bg-surface">
        {list.error ? <ErrorState error={list.error} onRetry={() => list.refetch()} /> : list.isPending ? <LoadingRows /> : <DataTable label="Quarantined files" data={items} columns={cols} getRowId={(r) => r.id} empty={<EmptyState icon={FileArchive} title="Nothing in quarantine">Files appear here when a Protect rule or an analyst quarantines them.</EmptyState>} />}
      </div>
      <Dialog open={!!confirm} onOpenChange={(o) => !o && setConfirm(null)}>
        {confirm ? (
          <DialogContent
            size="sm"
            title={confirm.op === 'restore' ? 'Restore this file?' : 'Delete this file permanently?'}
            description={`${basename(confirm.item.original_path)} on ${confirm.item.hostname}`}
            footer={
              <>
                <Button variant="ghost" onClick={() => setConfirm(null)}>
                  Cancel
                </Button>
                <Button variant={confirm.op === 'delete' ? 'danger' : 'primary'} disabled={m.isPending} onClick={() => m.mutate(confirm)}>
                  {confirm.op === 'restore' ? 'Restore file' : 'Delete file'}
                </Button>
              </>
            }
          >
            <p className="text-sm text-fg-muted">
              {confirm.op === 'restore'
                ? 'The file goes back to its original folder and can run again. Add an exclusion too if a rule would flag it again.'
                : 'The encrypted copy is erased from the device. This cannot be undone.'}
            </p>
          </DialogContent>
        ) : null}
      </Dialog>
    </div>
  )
}
