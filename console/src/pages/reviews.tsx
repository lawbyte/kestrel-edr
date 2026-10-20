import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Check, MessageSquareMore, X } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { ReviewRequestRow, ReviewState } from '@/api/types'
import { EmptyState, ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { Segmented, Switch } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { formatDateTime, timeAgo } from '@/lib/format'
import { basename, cn } from '@/lib/utils'

export default function Reviews() {
  const [state, setState] = useState<ReviewState | 'all'>('requested')
  const list = useQuery({ queryKey: qk.reviews(state === 'all' ? undefined : state), queryFn: () => api.reviewRequests(state === 'all' ? undefined : state) })
  const [decide, setDecide] = useState<{ r: ReviewRequestRow; approve: boolean } | null>(null)
  const { can } = useAuth()
  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Review requests" description="Employees ask IT to look at something Kestrel blocked, from the Kestrel tray app. Your reply is shown to them on their device.">
        <div className="mt-4">
          <Segmented size="sm" label="Filter by state" value={state} onChange={setState} options={[{ value: 'requested', label: 'Waiting' }, { value: 'approved', label: 'Approved' }, { value: 'denied', label: 'Denied' }, { value: 'all', label: 'All' }]} />
        </div>
      </PageHeader>
      <div className="min-h-0 flex-1 p-6">
        {list.error ? (
          <ErrorState error={list.error} onRetry={() => list.refetch()} />
        ) : list.isPending ? (
          <LoadingRows />
        ) : !list.data.length ? (
          <EmptyState icon={MessageSquareMore} title={state === 'requested' ? 'No one is waiting on you' : 'No requests here'}>
            Requests appear when an employee presses “Ask IT to review” in the tray app.
          </EmptyState>
        ) : (
          <ul className="mx-auto max-w-4xl space-y-3">
            {list.data.map((r) => (
              <li key={r.id} className="rounded-lg border border-border bg-surface p-4">
                <div className="flex flex-wrap items-start gap-3">
                  <div className="min-w-0 flex-1">
                    <p className="font-mono text-[13px] font-medium">{basename(r.file)}</p>
                    <p className="mt-0.5 text-xs text-fg-muted">
                      Blocked by <span className="text-fg">{r.rule_name}</span> on{' '}
                      <Link to={`/devices/${r.device_id}`} className="font-mono hover:underline">
                        {r.hostname}
                      </Link>{' '}
                      · {r.user.split('\\').pop()} · <span title={formatDateTime(r.created_at)}>{timeAgo(r.created_at)}</span>
                    </p>
                  </div>
                  <StateBadge state={r.state} />
                </div>
                <blockquote className="mt-3 border-l-2 border-border-strong pl-3 text-sm">“{r.justification}”</blockquote>
                {r.state === 'requested' ? (
                  can('exclusions.write') ? (
                    <div className="mt-3 flex gap-2">
                      <Button size="sm" variant="primary" onClick={() => setDecide({ r, approve: true })}>
                        <Check /> Approve
                      </Button>
                      <Button size="sm" onClick={() => setDecide({ r, approve: false })}>
                        <X /> Deny
                      </Button>
                    </div>
                  ) : null
                ) : (
                  <p className="mt-3 text-xs text-fg-subtle">
                    {r.state === 'approved' ? 'Approved' : 'Denied'} by {r.decided_by} {timeAgo(r.decided_at)}
                  </p>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
      {decide ? <DecideDialog {...decide} onClose={() => setDecide(null)} /> : null}
    </div>
  )
}

function StateBadge({ state }: { state: ReviewState }) {
  return <span className={cn('rounded-full px-2 py-px text-xs font-medium', state === 'requested' ? 'bg-accent-soft text-accent-text' : state === 'approved' ? 'bg-ok-soft text-ok' : 'bg-surface-2 text-fg-muted')}>{state === 'requested' ? 'Waiting' : state === 'approved' ? 'Approved' : 'Denied'}</span>
}

function DecideDialog({ r, approve, onClose }: { r: ReviewRequestRow; approve: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [msg, setMsg] = useState(approve ? 'Approved. You can run it again now.' : 'This file looks unsafe, so it stays blocked. Contact IT if you need help finding a safe alternative.')
  const scope = r.exclusion_scope ?? null
  const [excl, setExcl] = useState(!!scope)
  const m = useMutation({
    mutationFn: () => api.decideReview(r.id, { approved: approve, message: msg, create_exclusion: approve && excl }),
    onSuccess: () => {
      toast.success(approve ? 'Approved. The employee has been told.' : 'Denied. The employee has been told.')
      void qc.invalidateQueries({ queryKey: ['review-requests'] })
      void qc.invalidateQueries({ queryKey: qk.exclusions })
      onClose()
    },
    onError: (e) => toast.error('Decision not sent', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={approve ? `Approve ${basename(r.file)}?` : `Deny ${basename(r.file)}?`}
        description={`${r.user.split('\\').pop()} on ${r.hostname}`}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant={approve ? 'primary' : 'secondary'} disabled={!msg.trim() || m.isPending} onClick={() => m.mutate()}>
              {approve ? 'Approve and notify' : 'Deny and notify'}
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Message to the employee" htmlFor="rv-msg" hint="Shown in the Kestrel tray app on their device.">
            <Textarea id="rv-msg" value={msg} onChange={(e) => setMsg(e.target.value)} />
          </Field>
          {approve && scope ? (
            <div className="space-y-2">
              <label className="flex items-start gap-3 text-sm">
                <Switch checked={excl} onCheckedChange={setExcl} aria-label="Create exclusion" className="mt-0.5" />
                <span>
                  Also create an exclusion so this exact file is not blocked again
                  <span className="block text-xs text-fg-muted">Matches only this file’s {scope.kind === 'sha256' ? 'contents (SHA-256)' : 'valid publisher signature'}, never a folder or file name.</span>
                </span>
              </label>
              {excl ? (
                <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs" aria-label="Exclusion scope">
                  <dt className="text-fg-subtle">Matches</dt>
                  <dd className="min-w-0 break-all font-mono">
                    {scope.kind === 'sha256' ? 'SHA-256 ' : 'Signer '}
                    {scope.value}
                  </dd>
                  <dt className="text-fg-subtle">Rule</dt>
                  <dd className="font-mono">{scope.rule_id} only</dd>
                  <dt className="text-fg-subtle">Applies to</dt>
                  <dd>
                    Devices using policy <span className="font-medium">{scope.policy_name || scope.policy_id}</span> (the group of {r.hostname})
                  </dd>
                  <dt className="text-fg-subtle">Expires</dt>
                  <dd>after {scope.expires_in_days} days</dd>
                </dl>
              ) : null}
            </div>
          ) : approve ? (
            <p className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
              No exclusion will be created: Kestrel has no hash or valid signature for this file, and a path or file-name exclusion would let any file at that location through. Approving only tells the employee.
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
