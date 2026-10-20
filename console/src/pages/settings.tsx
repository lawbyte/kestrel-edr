import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Bell, Building2, Download, KeyRound, Lock, ScrollText, Users } from 'lucide-react'
import { lazy, Suspense, useEffect, useState, type ReactNode } from 'react'
import { NavLink, useParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { Settings } from '@/api/types'
import { ErrorState, LoadingRows, PageHeader } from '@/components/common'
import { Button } from '@/components/ui/button'
import { diffJson } from '@/lib/diff'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'

const Tabs = {
  users: lazy(() => import('./settings/users')),
  tokens: lazy(() => import('./settings/tokens')),
  notifications: lazy(() => import('./settings/notifications')),
  sso: lazy(() => import('./settings/sso')),
  organisation: lazy(() => import('./settings/organisation')),
  audit: lazy(() => import('./settings/audit')),
  enrollment: lazy(() => import('./settings/enrollment')),
}
type TabKey = keyof typeof Tabs

const NAV: { key: TabKey; label: string; icon: typeof Users; priv?: string }[] = [
  { key: 'enrollment', label: 'Enrollment', icon: Download },
  { key: 'users', label: 'Users & roles', icon: Users },
  { key: 'tokens', label: 'API tokens', icon: KeyRound },
  { key: 'notifications', label: 'Notifications', icon: Bell },
  { key: 'sso', label: 'Single sign-on', icon: Lock },
  { key: 'organisation', label: 'Branding, privacy & retention', icon: Building2 },
  { key: 'audit', label: 'Audit log', icon: ScrollText, priv: 'audit.read' },
]

export default function SettingsPage() {
  const { tab } = useParams()
  const { can } = useAuth()
  const key = (tab && tab in Tabs ? tab : 'enrollment') as TabKey
  const Comp = Tabs[key]
  return (
    <div>
      <PageHeader title="Settings" />
      <div className="grid gap-6 px-6 py-6 lg:grid-cols-[220px_minmax(0,1fr)]">
        <nav aria-label="Settings sections">
          <ul className="flex gap-1 overflow-x-auto lg:sticky lg:top-6 lg:flex-col lg:overflow-visible">
            {NAV.filter((n) => !n.priv || can(n.priv)).map((n) => (
              <li key={n.key}>
                <NavLink
                  to={`/settings/${n.key}`}
                  className={({ isActive }) =>
                    cn('flex h-8 items-center gap-2 whitespace-nowrap rounded-md px-2 text-sm', isActive || (n.key === key && !tab) ? 'bg-surface font-medium text-fg shadow-[0_0_0_1px_var(--border)]' : 'text-fg-muted hover:bg-surface-2 hover:text-fg')
                  }
                >
                  <n.icon className="size-4 text-fg-subtle" />
                  {n.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 max-w-4xl">
          <Suspense fallback={<LoadingRows rows={6} />}>
            <Comp />
          </Suspense>
        </div>
      </div>
    </div>
  )
}

/** Shared state for tabs that edit the single `Settings` document. */
export function useSettingsDraft() {
  const qc = useQueryClient()
  const q = useQuery({ queryKey: qk.settings, queryFn: api.settings })
  const [draft, setDraft] = useState<Settings | null>(null)
  useEffect(() => {
    if (q.data) setDraft(structuredClone(q.data))
  }, [q.data])
  const save = useMutation({
    mutationFn: (s: Settings) => api.saveSettings(s),
    onSuccess: (s) => {
      qc.setQueryData(qk.settings, s)
      toast.success('Settings saved')
    },
    onError: (e) => toast.error('Settings not saved', { description: (e as Error).message }),
  })
  const dirty = !!(q.data && draft && diffJson(q.data, draft).length)
  return { q, draft, setDraft, save, dirty, reset: () => q.data && setDraft(structuredClone(q.data)) }
}

export function SettingsSection({ title, description, children, footer }: { title: string; description?: ReactNode; children: ReactNode; footer?: ReactNode }) {
  return (
    <section className="rounded-lg border border-border bg-surface">
      <header className="border-b border-border px-5 py-3.5">
        <h2 className="text-[15px] font-semibold">{title}</h2>
        {description ? <p className="mt-0.5 text-sm text-fg-muted">{description}</p> : null}
      </header>
      <div className="p-5">{children}</div>
      {footer ? <footer className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{footer}</footer> : null}
    </section>
  )
}

export function SaveBar({ dirty, onSave, onReset, pending, disabled }: { dirty: boolean; onSave: () => void; onReset: () => void; pending: boolean; disabled?: boolean }) {
  return (
    <>
      {dirty ? <span className="mr-auto text-xs text-fg-muted">Unsaved changes</span> : null}
      <Button variant="ghost" size="sm" onClick={onReset} disabled={!dirty}>
        Discard
      </Button>
      <Button variant="primary" size="sm" onClick={onSave} disabled={!dirty || pending || disabled}>
        {pending ? 'Saving…' : 'Save changes'}
      </Button>
    </>
  )
}

export function SettingsLoading({ q }: { q: { error: unknown; refetch: () => unknown } }) {
  return q.error ? <ErrorState error={q.error} onRetry={() => q.refetch()} /> : <LoadingRows rows={6} />
}
