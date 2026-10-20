import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { CreatedEnrollmentToken, Group } from '@/api/types'
import { CopyButton } from '@/components/copy-button'
import { Mono } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, inputClass } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { formatDate, timeAgo } from '@/lib/format'
import { cn } from '@/lib/utils'
import { SettingsLoading, SettingsSection } from '../settings'

export default function EnrollmentTab() {
  const qc = useQueryClient()
  const { can } = useAuth()
  const groups = useQuery({ queryKey: qk.groups, queryFn: api.groups })
  const tokens = useQuery({ queryKey: qk.enrollmentTokens, queryFn: api.enrollmentTokens })
  const installer = useQuery({ queryKey: qk.installer, queryFn: api.installer })
  const policies = useQuery({ queryKey: qk.policies, queryFn: api.policies })
  const [creating, setCreating] = useState(false)
  const [groupDlg, setGroupDlg] = useState<Group | 'new' | null>(null)
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeEnrollmentToken(id),
    onSuccess: () => {
      toast.success('Token revoked')
      void qc.invalidateQueries({ queryKey: qk.enrollmentTokens })
    },
  })
  if (!groups.data || !tokens.data) return <SettingsLoading q={groups.error ? groups : tokens} />
  const now = Date.now()
  return (
    <div className="space-y-6">
      <SettingsSection title="Install the agent" description="Signed MSI for Windows 10, 11 and Server 2019 or later. Deploy with Intune, Group Policy, or the one-line command from an enrollment token.">
        {installer.data ? (
          <div className="flex flex-wrap items-center gap-4">
            <div className="min-w-0 flex-1 space-y-1 text-sm">
              <p>
                Kestrel agent <span className="font-mono">{installer.data.version}</span> (x64 MSI)
              </p>
              <p className="flex items-center gap-1 text-xs text-fg-muted">
                SHA-256 <Mono className="text-[11px]">{installer.data.sha256}</Mono>
                <CopyButton text={installer.data.sha256} iconOnly label="Copy SHA-256" />
              </p>
            </div>
            <Button asChild variant="secondary" size="sm">
              <a href={installer.data.msi_url} download>
                <Download /> Download MSI
              </a>
            </Button>
          </div>
        ) : (
          <SettingsLoading q={installer} />
        )}
      </SettingsSection>

      <SettingsSection
        title="Enrollment tokens"
        description="A token decides which group (and so which policy) a new device joins. Each token is shown once."
        footer={can('devices.write') ? <Button size="sm" variant="primary" onClick={() => setCreating(true)}><Plus /> Create token</Button> : null}
      >
        <ul className="-my-2 divide-y divide-border">
          {tokens.data.map((t) => {
            const expired = t.expires_at < now
            const used = t.uses >= t.max_uses
            const state = t.revoked ? 'Revoked' : expired ? 'Expired' : used ? 'Used up' : 'Active'
            return (
              <li key={t.id} className={cn('flex flex-wrap items-center gap-3 py-2.5', state !== 'Active' && 'opacity-60')}>
                <code className="font-mono text-sm">{t.token_prefix}…</code>
                <span className="text-sm">{t.group_name}</span>
                <span className="text-xs text-fg-muted">
                  {t.uses}/{t.max_uses} used · {expired ? 'expired' : 'expires'} {formatDate(t.expires_at)} · created {timeAgo(t.created_at)}
                </span>
                <span className={cn('ml-auto rounded px-1.5 py-px text-xs font-medium', state === 'Active' ? 'bg-ok-soft text-ok' : 'bg-surface-2 text-fg-muted')}>{state}</span>
                {state === 'Active' && can('devices.write') ? (
                  <Button size="icon-sm" variant="ghost" aria-label="Revoke token" onClick={() => confirm('Revoke this token? Devices already enrolled are not affected.') && revoke.mutate(t.id)}>
                    <Trash2 />
                  </Button>
                ) : null}
              </li>
            )
          })}
        </ul>
      </SettingsSection>

      <SettingsSection title="Device groups" description="Groups decide which policy a device gets." footer={can('devices.write') ? <Button size="sm" onClick={() => setGroupDlg('new')}><Plus /> New group</Button> : null}>
        <ul className="-my-2 divide-y divide-border">
          {groups.data.map((g) => (
            <li key={g.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">{g.name}</p>
                <p className="text-xs text-fg-muted">{g.description}</p>
              </div>
              <span className="text-xs text-fg-muted">{policies.data?.find((p) => p.id === g.policy_id)?.name ?? 'No policy'}</span>
              <span className="w-20 text-right text-xs tabular text-fg-subtle">{g.device_count} devices</span>
              {can('devices.write') ? (
                <Button size="sm" variant="ghost" onClick={() => setGroupDlg(g)}>
                  Edit
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
      </SettingsSection>

      {creating ? <CreateToken groups={groups.data} onClose={() => setCreating(false)} /> : null}
      {groupDlg ? <GroupDialog group={groupDlg === 'new' ? null : groupDlg} onClose={() => setGroupDlg(null)} /> : null}
    </div>
  )
}

function CreateToken({ groups, onClose }: { groups: Group[]; onClose: () => void }) {
  const qc = useQueryClient()
  const [group, setGroup] = useState(groups[0]?.id ?? '')
  const [days, setDays] = useState(7)
  const [uses, setUses] = useState(50)
  const [created, setCreated] = useState<CreatedEnrollmentToken | null>(null)
  const m = useMutation({
    mutationFn: () => api.createEnrollmentToken({ group_id: group, expires_in_days: days, max_uses: uses }),
    onSuccess: (t) => {
      setCreated(t)
      void qc.invalidateQueries({ queryKey: qk.enrollmentTokens })
    },
    onError: (e) => toast.error('Token not created', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="lg"
        title={created ? 'Install command' : 'Create enrollment token'}
        description={created ? `Run this in an elevated PowerShell on each device. Devices join ${created.group_name}. This is the only time the token is shown.` : undefined}
        footer={
          created ? (
            <Button variant="primary" onClick={onClose}>
              Done
            </Button>
          ) : (
            <>
              <Button variant="ghost" onClick={onClose}>
                Cancel
              </Button>
              <Button variant="primary" disabled={!group || m.isPending} onClick={() => m.mutate()}>
                Create token
              </Button>
            </>
          )
        }
      >
        {created ? (
          <div className="space-y-4">
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs font-medium text-fg-subtle">PowerShell (run as administrator)</span>
                <CopyButton text={created.install_command} label="Copy command" />
              </div>
              <pre className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">{created.install_command}</pre>
            </div>
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="text-xs font-medium text-fg-subtle">Token only (for Intune or GPO MSI properties)</span>
                <CopyButton text={created.token} label="Copy token" />
              </div>
              <code className="block break-all rounded-md border border-border bg-surface-2 p-2 font-mono text-[12px]">{created.token}</code>
            </div>
            <p className="text-xs text-fg-muted">
              Valid until {formatDate(created.expires_at)} for up to {created.max_uses} devices.
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            <Field label="Group" htmlFor="et-group" hint="New devices get this group’s policy.">
              <select id="et-group" value={group} onChange={(e) => setGroup(e.target.value)} className={cn(inputClass, 'h-8')}>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Expires after (days)" htmlFor="et-days">
                <Input id="et-days" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
              </Field>
              <Field label="Maximum devices" htmlFor="et-uses">
                <Input id="et-uses" type="number" min={1} max={10000} value={uses} onChange={(e) => setUses(Number(e.target.value))} />
              </Field>
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function GroupDialog({ group, onClose }: { group: Group | null; onClose: () => void }) {
  const qc = useQueryClient()
  const policies = useQuery({ queryKey: qk.policies, queryFn: api.policies })
  const [name, setName] = useState(group?.name ?? '')
  const [desc, setDesc] = useState(group?.description ?? '')
  const [pol, setPol] = useState(group?.policy_id ?? 'pol-default')
  const m = useMutation({
    mutationFn: () => (group ? api.patchGroup(group.id, { name, description: desc, policy_id: pol }) : api.createGroup({ name, description: desc, policy_id: pol })),
    onSuccess: () => {
      toast.success(group ? 'Group updated' : 'Group created')
      void qc.invalidateQueries({ queryKey: qk.groups })
      void qc.invalidateQueries({ queryKey: ['devices'] })
      onClose()
    },
    onError: (e) => toast.error('Group not saved', { description: (e as Error).message }),
  })
  const del = useMutation({
    mutationFn: () => api.deleteGroup(group!.id),
    onSuccess: () => {
      toast.success('Group deleted')
      void qc.invalidateQueries({ queryKey: qk.groups })
      onClose()
    },
    onError: (e) => toast.error('Group not deleted', { description: (e as Error).message }),
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="sm"
        title={group ? `Edit ${group.name}` : 'New group'}
        footer={
          <>
            {group ? (
              <Button variant="danger-outline" size="sm" className="mr-auto" onClick={() => del.mutate()}>
                Delete
              </Button>
            ) : null}
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!name.trim() || m.isPending} onClick={() => m.mutate()}>
              Save
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          <Field label="Name" htmlFor="g-name">
            <Input id="g-name" value={name} onChange={(e) => setName(e.target.value)} />
          </Field>
          <Field label="Description" htmlFor="g-desc">
            <Input id="g-desc" value={desc} onChange={(e) => setDesc(e.target.value)} />
          </Field>
          <Field label="Policy" htmlFor="g-pol" hint={group ? `Changing it updates all ${group.device_count} devices in this group.` : undefined}>
            <select id="g-pol" value={pol} onChange={(e) => setPol(e.target.value)} className={cn(inputClass, 'h-8')}>
              {(policies.data ?? []).map((p) => (
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
