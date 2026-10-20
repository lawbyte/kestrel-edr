import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ChevronDown, UserRound } from 'lucide-react'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { Classification, Incident, IncidentStatus } from '@/api/types'
import { useAuth } from '@/lib/auth'
import { CLASSIFICATION_LABEL, INCIDENT_STATUS_LABEL } from '@/lib/labels'
import { IncidentStatusBadge } from './badges'
import { Avatar } from './common'
import { Dropdown, DropdownContent, DropdownLabel, DropdownRadioGroup, DropdownRadioItem, DropdownSeparator, DropdownTrigger } from './ui/misc'

export function useUpdateIncident() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { id: string; status?: IncidentStatus; assignee_id?: string | null; classification?: Classification | null }) => {
      const { id, ...b } = v
      return api.patchIncident(id, b)
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['incidents'] })
      void qc.invalidateQueries({ queryKey: ['incident'] })
      void qc.invalidateQueries({ queryKey: qk.dashboard })
    },
    onError: (e) => toast.error('Couldn’t update the incident', { description: (e as Error).message }),
  })
}

const trigger = 'inline-flex h-7 items-center gap-1.5 rounded-md border border-border-strong bg-surface px-2 text-sm hover:bg-surface-2 disabled:opacity-60'

export function StatusControl({ incident }: { incident: Incident }) {
  const m = useUpdateIncident()
  const { can } = useAuth()
  return (
    <Dropdown>
      <DropdownTrigger className={trigger} disabled={!can('incidents.write')} aria-label={`Status: ${INCIDENT_STATUS_LABEL[incident.status]}`}>
        <IncidentStatusBadge status={incident.status} />
        <ChevronDown className="size-3 text-fg-subtle" />
      </DropdownTrigger>
      <DropdownContent align="start">
        <DropdownLabel>Status</DropdownLabel>
        <DropdownRadioGroup
          value={incident.status}
          onValueChange={(v) => {
            m.mutate({ id: incident.id, status: v as IncidentStatus }, { onSuccess: () => toast.success(`Marked ${INCIDENT_STATUS_LABEL[v as IncidentStatus].toLowerCase()}`) })
          }}
        >
          {(Object.keys(INCIDENT_STATUS_LABEL) as IncidentStatus[]).map((s) => (
            <DropdownRadioItem key={s} value={s}>
              {INCIDENT_STATUS_LABEL[s]}
            </DropdownRadioItem>
          ))}
        </DropdownRadioGroup>
      </DropdownContent>
    </Dropdown>
  )
}

export function AssigneeControl({ incident }: { incident: Incident }) {
  const m = useUpdateIncident()
  const { me, can } = useAuth()
  const users = useQuery({ queryKey: qk.users, queryFn: api.users, staleTime: 5 * 60_000 })
  const assignable = (users.data ?? []).filter((u) => !u.disabled && u.role !== 'readonly')
  return (
    <Dropdown>
      <DropdownTrigger className={trigger} disabled={!can('incidents.write')} aria-label={`Assignee: ${incident.assignee?.name ?? 'unassigned'}`}>
        <Avatar user={incident.assignee} size="xs" />
        <span className="max-w-32 truncate">{incident.assignee?.name ?? 'Unassigned'}</span>
        <ChevronDown className="size-3 text-fg-subtle" />
      </DropdownTrigger>
      <DropdownContent align="start" className="w-56">
        <DropdownLabel>Assign to</DropdownLabel>
        <DropdownRadioGroup value={incident.assignee?.id ?? ''} onValueChange={(v) => m.mutate({ id: incident.id, assignee_id: v || null })}>
          <DropdownRadioItem value={me.user.id}>
            <UserRound className="size-4 text-fg-subtle" /> Me
          </DropdownRadioItem>
          <DropdownSeparator />
          {assignable
            .filter((u) => u.id !== me.user.id)
            .map((u) => (
              <DropdownRadioItem key={u.id} value={u.id}>
                <Avatar user={u} size="xs" /> {u.name}
              </DropdownRadioItem>
            ))}
          <DropdownSeparator />
          <DropdownRadioItem value="">Unassigned</DropdownRadioItem>
        </DropdownRadioGroup>
      </DropdownContent>
    </Dropdown>
  )
}

export function ClassificationControl({ incident }: { incident: Incident }) {
  const m = useUpdateIncident()
  const { can } = useAuth()
  return (
    <Dropdown>
      <DropdownTrigger className={trigger} disabled={!can('incidents.write')} aria-label="Classification">
        <span className={incident.classification ? '' : 'text-fg-muted'}>{incident.classification ? CLASSIFICATION_LABEL[incident.classification] : 'Not classified'}</span>
        <ChevronDown className="size-3 text-fg-subtle" />
      </DropdownTrigger>
      <DropdownContent align="start" className="w-60">
        <DropdownLabel>Classification</DropdownLabel>
        <DropdownRadioGroup value={incident.classification ?? ''} onValueChange={(v) => m.mutate({ id: incident.id, classification: (v || null) as Classification | null })}>
          <DropdownRadioItem value="true_positive">True positive</DropdownRadioItem>
          <DropdownRadioItem value="false_positive">False positive (rule was wrong)</DropdownRadioItem>
          <DropdownRadioItem value="benign">Benign (real, but expected)</DropdownRadioItem>
          <DropdownSeparator />
          <DropdownRadioItem value="">Not classified</DropdownRadioItem>
        </DropdownRadioGroup>
      </DropdownContent>
    </Dropdown>
  )
}
