import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { MoreHorizontal, Plus, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { User } from '@/api/types'
import { Avatar } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, inputClass } from '@/components/ui/input'
import { Dropdown, DropdownContent, DropdownItem, DropdownSeparator, DropdownTrigger } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { timeAgo } from '@/lib/format'
import { PRIVILEGE_DESCRIPTION, ROLE_PRIVILEGES } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { SettingsLoading, SettingsSection } from '../settings'

const ROLE_INFO: Record<string, string> = {
  admin: 'Everything, including policies, users and settings',
  analyst: 'Investigate and respond: incidents, response actions, exclusions and indicators (not persistence removal, which writes the registry as SYSTEM)',
  readonly: 'View only',
}

export default function UsersTab() {
  const qc = useQueryClient()
  const { me, can } = useAuth()
  const q = useQuery({ queryKey: qk.users, queryFn: api.users })
  const [adding, setAdding] = useState(false)
  const patch = useMutation({
    mutationFn: (v: { id: string; b: { role?: string; disabled?: boolean; oidc_subject?: string | null } }) => api.patchUser(v.id, v.b),
    onSuccess: () => {
      toast.success('User updated')
      void qc.invalidateQueries({ queryKey: qk.users })
    },
    onError: (e) => toast.error('User not updated', { description: (e as Error).message }),
  })
  const del = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => {
      toast.success('User removed')
      void qc.invalidateQueries({ queryKey: qk.users })
    },
    onError: (e) => toast.error('User not removed', { description: (e as Error).message }),
  })
  if (!q.data) return <SettingsLoading q={q} />
  const editable = can('users.write')
  return (
    <div className="space-y-6">
      <SettingsSection title="Users" description="People who can sign in to this console." footer={editable ? <Button size="sm" variant="primary" onClick={() => setAdding(true)}><Plus /> Add user</Button> : null}>
        <ul className="-my-2 divide-y divide-border">
          {q.data.map((u) => (
            <li key={u.id} className={cn('flex flex-wrap items-center gap-3 py-2.5', u.disabled && 'opacity-60')}>
              <Avatar user={u} size="md" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">
                  {u.name} {u.id === me.user.id ? <span className="text-xs font-normal text-fg-subtle">(you)</span> : null}
                </p>
                <p className="truncate text-xs text-fg-muted">{u.email}</p>
              </div>
              <div className="hidden text-xs text-fg-subtle sm:block">{u.disabled ? 'Disabled' : u.last_login ? `Active ${timeAgo(u.last_login)}` : 'Never signed in'}</div>
              {u.mfa_enabled ? (
                <span className="inline-flex items-center gap-1 text-xs text-ok" title="Two-factor enabled">
                  <ShieldCheck className="size-3.5" /> 2FA
                </span>
              ) : (
                <span className="text-xs text-warn">No 2FA</span>
              )}
              {u.sso_linked ? (
                <span className="text-xs text-fg-muted" title="Signs in with single sign-on (linked by identity-provider user ID)">
                  SSO
                </span>
              ) : null}
              <span className="w-20 text-sm capitalize">{u.role}</span>
              {editable && u.id !== me.user.id ? (
                <Dropdown>
                  <DropdownTrigger asChild>
                    <Button size="icon-sm" variant="ghost" aria-label={`Manage ${u.name}`}>
                      <MoreHorizontal />
                    </Button>
                  </DropdownTrigger>
                  <DropdownContent>
                    {(['admin', 'analyst', 'readonly'] as const).filter((r) => r !== u.role).map((r) => (
                      <DropdownItem key={r} onSelect={() => patch.mutate({ id: u.id, b: { role: r } })}>
                        Make {r}
                      </DropdownItem>
                    ))}
                    <DropdownSeparator />
                    {u.sso_linked ? (
                      <DropdownItem onSelect={() => confirm(`Unlink single sign-on for ${u.name}?`) && patch.mutate({ id: u.id, b: { oidc_subject: null } })}>Unlink single sign-on</DropdownItem>
                    ) : (
                      <DropdownItem
                        onSelect={() => {
                          const sub = prompt(`Link a single sign-on identity to ${u.email}.\n\nEnter the user's ID at your identity provider (the OIDC "sub" claim, e.g. the Entra object ID). Accounts are never linked by email.`)
                          if (sub?.trim()) patch.mutate({ id: u.id, b: { oidc_subject: sub.trim() } })
                        }}
                      >
                        Link single sign-on…
                      </DropdownItem>
                    )}
                    <DropdownItem onSelect={() => patch.mutate({ id: u.id, b: { disabled: !u.disabled } })}>{u.disabled ? 'Enable account' : 'Disable account'}</DropdownItem>
                    <DropdownItem danger onSelect={() => confirm(`Remove ${u.name}? Their history stays in the audit log.`) && del.mutate(u.id)}>
                      Remove user
                    </DropdownItem>
                  </DropdownContent>
                </Dropdown>
              ) : (
                <span className="w-7" />
              )}
            </li>
          ))}
        </ul>
      </SettingsSection>
      <SettingsSection title="Roles" description="Built-in roles. Response actions each need their own privilege.">
        <ul className="space-y-3">
          {Object.entries(ROLE_PRIVILEGES).map(([r, privs]) => (
            <li key={r}>
              <p className="text-sm font-medium capitalize">{r}</p>
              <p className="text-xs text-fg-muted">{ROLE_INFO[r]}</p>
              <p className="mt-1 flex flex-wrap gap-1">
                {privs.map((p) => (
                  <code key={p} title={PRIVILEGE_DESCRIPTION[p as keyof typeof PRIVILEGE_DESCRIPTION]} className="rounded border border-border bg-surface-2 px-1 text-[11px] text-fg-muted">
                    {p === '*' ? 'all privileges' : p}
                  </code>
                ))}
              </p>
            </li>
          ))}
        </ul>
      </SettingsSection>
      {adding ? <AddUser onClose={() => setAdding(false)} /> : null}
    </div>
  )
}

function AddUser({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState('analyst')
  const [password, setPassword] = useState('')
  const m = useMutation({
    mutationFn: () => api.createUser({ email, name, role, password: password || undefined }),
    onSuccess: (u: User) => {
      toast.success(`Added ${u.name}`)
      void qc.invalidateQueries({ queryKey: qk.users })
      onClose()
    },
    onError: (e) => toast.error('User not added', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="sm"
        title="Add user"
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!email || !name || m.isPending} onClick={() => m.mutate()}>
              Add user
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name" htmlFor="u-name">
            <Input id="u-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </Field>
          <Field label="Email" htmlFor="u-email">
            <Input id="u-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          </Field>
          <Field label="Role" htmlFor="u-role" hint={ROLE_INFO[role]}>
            <select id="u-role" value={role} onChange={(e) => setRole(e.target.value)} className={cn(inputClass, 'h-8')}>
              <option value="admin">Admin</option>
              <option value="analyst">Analyst</option>
              <option value="readonly">Read-only</option>
            </select>
          </Field>
          <Field label="Initial password" htmlFor="u-pw" hint="Leave blank if they sign in with SSO.">
            <Input id="u-pw" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} />
          </Field>
        </div>
      </DialogContent>
    </Dialog>
  )
}
