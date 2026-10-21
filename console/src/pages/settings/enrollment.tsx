import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Download, MonitorOff, MonitorSmartphone, Plus, Trash2 } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { Group, GroupUpdateRing } from '@/api/types'
import { InstallAgentWizard } from '@/components/install-wizard'
import { GROUP_UPDATE_RINGS } from '@/api/types'
import { RingBadge } from '@/components/badges'
import { RING_HINT, RING_LABEL } from '@/lib/updates'
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
        description="A token decides which group (and so which policy) a new device joins, and its remote-access ceiling, which only a reinstall can change. Each token is shown once."
        footer={can('devices.write') ? <Button size="sm" variant="primary" onClick={() => setCreating(true)}><Plus /> Install agent…</Button> : null}
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
                <span className="inline-flex min-w-0 items-center gap-1 text-xs text-fg-muted" title={t.remote_summary ?? 'No remote access'}>
                  {t.remote_preset && t.remote_preset !== 'none' ? <MonitorSmartphone className="size-3.5 shrink-0 text-accent-text" aria-hidden /> : <MonitorOff className="size-3.5 shrink-0 text-fg-subtle" aria-hidden />}
                  <span className="truncate">{t.remote_summary ?? 'No remote access'}</span>
                </span>
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

      <SettingsSection title="Device groups" description="Groups decide which policy a device gets and in which update ring it receives new agent versions." footer={can('devices.write') ? <Button size="sm" onClick={() => setGroupDlg('new')}><Plus /> New group</Button> : null}>
        <ul className="-my-2 divide-y divide-border">
          {groups.data.map((g) => (
            <li key={g.id} className="flex flex-wrap items-center gap-3 py-2.5">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">
                  {g.name}
                  {g.is_default ? <span className="ml-1.5 text-xs font-normal text-fg-subtle">(default)</span> : null}
                </p>
                <p className="text-xs text-fg-muted">{g.description}</p>
              </div>
              <span className="text-xs text-fg-muted">{policies.data?.find((p) => p.id === g.policy_id)?.name ?? 'No policy'}</span>
              <RingBadge ring={g.update_ring ?? 'broad'} />
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

      {creating ? <InstallAgentWizard groups={groups.data} onClose={() => setCreating(false)} /> : null}
      {groupDlg ? <GroupDialog group={groupDlg === 'new' ? null : groupDlg} onClose={() => setGroupDlg(null)} /> : null}
    </div>
  )
}

function GroupDialog({ group, onClose }: { group: Group | null; onClose: () => void }) {
  const qc = useQueryClient()
  const policies = useQuery({ queryKey: qk.policies, queryFn: api.policies })
  const [name, setName] = useState(group?.name ?? '')
  const [desc, setDesc] = useState(group?.description ?? '')
  const [pol, setPol] = useState(group?.policy_id ?? 'pol-default')
  const [ring, setRing] = useState<GroupUpdateRing>(group?.update_ring ?? 'broad')
  const m = useMutation({
    mutationFn: () =>
      group
        ? api.patchGroup(group.id, { name, description: desc, policy_id: pol, update_ring: ring })
        : api.createGroup({ name, description: desc, policy_id: pol, update_ring: ring }),
    onSuccess: () => {
      toast.success(group ? 'Group updated' : 'Group created')
      void qc.invalidateQueries({ queryKey: qk.groups })
      void qc.invalidateQueries({ queryKey: ['devices'] })
      void qc.invalidateQueries({ queryKey: ['updates'] })
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
            {group && !group.is_default ? (
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
          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">Update ring</legend>
            <p className="text-xs text-fg-muted">When devices in this group receive a new agent release. Releases are promoted canary → early → broad.</p>
            <div className="space-y-1">
              {GROUP_UPDATE_RINGS.map((r) => (
                <label key={r} className={cn('flex cursor-pointer items-start gap-2.5 rounded-md border px-2.5 py-2 text-sm', ring === r ? 'border-accent bg-accent-soft' : 'border-border hover:bg-surface-2')}>
                  <input type="radio" name="g-ring" value={r} checked={ring === r} onChange={() => setRing(r)} className="mt-0.5 accent-[var(--accent)]" />
                  <span className="min-w-0">
                    <span className="font-medium">{RING_LABEL[r]}</span>
                    <span className="block text-xs text-fg-muted">{RING_HINT[r]}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>
        </div>
      </DialogContent>
    </Dialog>
  )
}
