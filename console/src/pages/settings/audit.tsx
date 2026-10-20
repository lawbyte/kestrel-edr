import { useQuery } from '@tanstack/react-query'
import { ChevronRight, Link2, Link2Off, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { api, qk } from '@/api/endpoints'
import { SearchInput } from '@/components/filters'
import { Mono } from '@/components/common'
import { Tooltip } from '@/components/ui/misc'
import { formatDateTime, shortHash } from '@/lib/format'
import { cn } from '@/lib/utils'
import { SettingsLoading, SettingsSection } from '../settings'

export default function AuditTab() {
  const [actor, setActor] = useState('')
  const [action, setAction] = useState('')
  const q = useQuery({ queryKey: qk.audit({ actor, action }), queryFn: () => api.auditLog({ actor, action }), placeholderData: (p) => p })
  const v = useQuery({ queryKey: qk.auditVerify, queryFn: api.auditVerify })
  const [open, setOpen] = useState<string | null>(null)
  return (
    <SettingsSection
      title="Audit log"
      description="Every change and every response action, by whom and when. Entries are hash-chained: each one includes the hash of the one before, so edits or deletions are detectable."
    >
      <div className="mb-4 flex flex-wrap items-center gap-3">
        {v.data ? (
          v.data.ok ? (
            <span className="inline-flex items-center gap-1.5 rounded-md bg-ok-soft px-2.5 py-1 text-sm font-medium text-ok">
              <ShieldCheck className="size-4" /> Chain verified · {v.data.count} entries intact
            </span>
          ) : (
            <span className="inline-flex items-center gap-1.5 rounded-md bg-danger-soft px-2.5 py-1 text-sm font-medium text-danger" role="alert">
              <Link2Off className="size-4" /> Chain broken at entry {v.data.broken_at?.slice(0, 8)}
            </span>
          )
        ) : (
          <span className="text-sm text-fg-subtle">Verifying chain…</span>
        )}
        <SearchInput value={actor} onChange={setActor} placeholder="Filter by person (email)" className="w-52" />
        <SearchInput value={action} onChange={setAction} placeholder="Filter by action" className="w-44" />
      </div>
      {!q.data ? (
        <SettingsLoading q={q} />
      ) : (
        <div className="-mx-5 -mb-5 border-t border-border">
          <table className="w-full text-sm">
            <thead className="text-xs text-fg-subtle">
              <tr className="border-b border-border">
                <th className="w-6" />
                <th className="px-3 py-2 text-left font-medium">When</th>
                <th className="px-3 py-2 text-left font-medium">Who</th>
                <th className="px-3 py-2 text-left font-medium">Action</th>
                <th className="px-3 py-2 text-left font-medium">Target</th>
                <th className="px-3 py-2 text-left font-medium">Hash</th>
              </tr>
            </thead>
            <tbody>
              {q.data.items.map((e) => (
                <FragmentRows key={e.id}>
                  <tr className="cursor-pointer border-b border-border hover:bg-surface-2/60" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id}>
                    <td className="pl-3">
                      <ChevronRight className={cn('size-3.5 text-fg-subtle transition-transform', open === e.id && 'rotate-90')} />
                    </td>
                    <td className="whitespace-nowrap px-3 py-2 text-xs tabular text-fg-muted">{formatDateTime(e.ts)}</td>
                    <td className="px-3 py-2 text-xs">{e.actor?.email ?? <span className="text-fg-subtle">Kestrel (automatic)</span>}</td>
                    <td className="px-3 py-2">
                      <code className="text-xs">{e.action}</code>
                    </td>
                    <td className="max-w-[260px] truncate px-3 py-2 text-xs text-fg-muted">{e.target}</td>
                    <td className="px-3 py-2">
                      <Tooltip content={`prev ${shortHash(e.prev_hash, 16)}`}>
                        <span className="inline-flex items-center gap-1 font-mono text-[11px] text-fg-subtle">
                          <Link2 className="size-3" /> {shortHash(e.hash, 10)}
                        </span>
                      </Tooltip>
                    </td>
                  </tr>
                  {open === e.id ? (
                    <tr className="border-b border-border bg-surface-2/50">
                      <td />
                      <td colSpan={5} className="space-y-1 px-3 py-2 text-xs">
                        <pre className="whitespace-pre-wrap break-all font-mono text-[11.5px]">{JSON.stringify(e.details, null, 2)}</pre>
                        <p className="text-fg-subtle">
                          hash <Mono>{e.hash}</Mono>
                        </p>
                        <p className="text-fg-subtle">
                          prev <Mono>{e.prev_hash}</Mono>
                        </p>
                      </td>
                    </tr>
                  ) : null}
                </FragmentRows>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SettingsSection>
  )
}
function FragmentRows({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
