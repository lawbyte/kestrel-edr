import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { CreatedApiToken } from '@/api/types'
import { CopyButton } from '@/components/copy-button'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, inputClass } from '@/components/ui/input'
import { Checkbox } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { timeAgo } from '@/lib/format'
import { PRIVILEGE_DESCRIPTION, PRIVILEGES } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { SettingsLoading, SettingsSection } from '../settings'

export default function TokensTab() {
  const qc = useQueryClient()
  const { can } = useAuth()
  const q = useQuery({ queryKey: qk.apiTokens, queryFn: api.apiTokens })
  const [adding, setAdding] = useState(false)
  const del = useMutation({
    mutationFn: (id: string) => api.deleteApiToken(id),
    onSuccess: () => {
      toast.success('Token revoked')
      void qc.invalidateQueries({ queryKey: qk.apiTokens })
    },
  })
  if (!q.data) return <SettingsLoading q={q} />
  return (
    <SettingsSection
      title="API tokens"
      description={<>For SIEM, SOAR and scripts. Send as <code className="text-xs">Authorization: Bearer kst_…</code>. Tokens skip CSRF checks, so give each one only the privileges it needs.</>}
      footer={can('tokens.write') ? <Button size="sm" variant="primary" onClick={() => setAdding(true)}><Plus /> Create token</Button> : null}
    >
      {q.data.length ? (
        <ul className="-my-2 divide-y divide-border">
          {q.data.map((t) => (
            <li key={t.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{t.name}</p>
                <p className="text-xs text-fg-muted">
                  <code>{t.prefix}…</code> · created {timeAgo(t.created_at)} · {t.last_used ? `last used ${timeAgo(t.last_used)}` : 'never used'}
                  {t.expires_at ? ` · ${t.expires_at < Date.now() ? 'expired' : 'expires'} ${timeAgo(t.expires_at)}` : ''}
                </p>
              </div>
              <div className="flex flex-wrap gap-1">
                {t.privileges.map((p) => (
                  <code key={p} className="rounded border border-border bg-surface-2 px-1 text-[11px] text-fg-muted">
                    {p}
                  </code>
                ))}
              </div>
              {can('tokens.write') ? (
                <Button size="icon-sm" variant="ghost" aria-label={`Revoke ${t.name}`} onClick={() => confirm(`Revoke “${t.name}”? Anything using it stops working immediately.`) && del.mutate(t.id)}>
                  <Trash2 />
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-fg-muted">No tokens yet.</p>
      )}
      {adding ? <CreateToken onClose={() => setAdding(false)} /> : null}
    </SettingsSection>
  )
}

function CreateToken({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [privs, setPrivs] = useState<string[]>(['read'])
  const [days, setDays] = useState(90)
  const [created, setCreated] = useState<CreatedApiToken | null>(null)
  const m = useMutation({
    mutationFn: () => api.createApiToken({ name, privileges: privs, expires_in_days: days }),
    onSuccess: (t) => {
      setCreated(t)
      void qc.invalidateQueries({ queryKey: qk.apiTokens })
    },
    onError: (e) => toast.error('Token not created', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        title={created ? 'Copy your token now' : 'Create API token'}
        description={created ? 'This is the only time the full token is shown. Store it in your secrets manager.' : undefined}
        footer={
          created ? (
            <Button variant="primary" onClick={onClose}>
              I’ve stored it
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="primary" disabled={!name.trim() || !privs.length || m.isPending} onClick={() => m.mutate()}>
                Create token
              </Button>
            </>
          )
        }
      >
        {created ? (
          <div className="space-y-2">
            <div className="flex items-center gap-2 rounded-md border border-border bg-surface-2 p-2">
              <code className="min-w-0 flex-1 break-all font-mono text-[12.5px]">{created.token}</code>
              <CopyButton text={created.token} />
            </div>
            <p className="text-xs text-fg-muted">Name: {created.name} · privileges: {created.privileges.join(', ')}</p>
          </div>
        ) : (
          <div className="space-y-4">
            <Field label="Name" htmlFor="tk-name" hint="What uses it, e.g. Splunk SIEM pull">
              <Input id="tk-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
            </Field>
            <Field label="Expires after" htmlFor="tk-days" hint="Tokens stop working after this; create a new one to rotate. Tokens cannot change account settings (password, 2FA).">
              <select id="tk-days" value={days} onChange={(e) => setDays(Number(e.target.value))} className={cn(inputClass, 'h-8 max-w-48')}>
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
                <option value={365}>1 year</option>
                <option value={730}>2 years</option>
              </select>
            </Field>
            <fieldset>
              <legend className="mb-1.5 text-sm font-medium">Privileges</legend>
              <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
                {PRIVILEGES.map((p) => (
                  <label key={p} title={PRIVILEGE_DESCRIPTION[p]} className="flex items-center gap-2 text-xs">
                    <Checkbox checked={privs.includes(p)} onCheckedChange={(v) => setPrivs((s) => (v ? [...s, p] : s.filter((x) => x !== p)))} />
                    <code>{p}</code>
                  </label>
                ))}
              </div>
            </fieldset>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
