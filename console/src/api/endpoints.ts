import { http, request } from './client'
import type * as T from './types'

/** Thin typed wrappers over the REST contract (docs/contracts.md). */
export const api = {
  // auth
  setupStatus: () => http.get<T.SetupStatus>('/auth/setup-status'),
  setup: (b: { setup_code: string; org_name: string; email: string; password: string; name: string }) => http.post<T.LoginResponse>('/auth/setup', b),
  login: (b: { email: string; password: string; totp?: string }) => http.post<T.LoginResponse>('/auth/login', b),
  logout: () => http.post<void>('/auth/logout'),
  me: () => http.get<T.MeResponse>('/me'),
  /** Start TOTP enrolment (409 when MFA is already on). */
  mfaSetup: () => http.post<T.MfaSetup>('/me/mfa/setup'),
  /** Activate MFA with a code from the new secret (400 on a wrong code). */
  mfaEnable: (totp: string) => http.post<{ user: T.User }>('/me/mfa/enable', { totp }),
  /** Turn MFA off; needs the account password (403 when wrong or when `require_mfa` is on). */
  mfaDisable: (password: string) => http.post<void>('/me/mfa/disable', { password }),

  dashboard: () => http.get<T.Dashboard>('/dashboard'),

  // devices
  devices: (q: { q?: string; status?: string; group_id?: string; include_removed?: boolean; limit?: number; cursor?: string } = {}) =>
    http.get<T.Page<T.Device>>('/devices', { limit: 500, ...q }),
  device: (id: string) => http.get<T.DeviceDetail>(`/devices/${id}`),
  patchDevice: (id: string, b: { group_id?: string; tags?: string[] }) => http.patch<T.Device>(`/devices/${id}`, b),
  deleteDevice: (id: string) => http.del(`/devices/${id}`),
  /** Remote uninstall (admins, interactive session; 403 `reauth_required` asks for an MFA step-up). */
  removeDevice: (id: string, b: T.RemoveDeviceRequest) => http.post<T.RemoveDeviceResponse>(`/devices/${id}/remove`, b),
  /** Cancel a removal the agent has not received yet. */
  cancelDeviceRemoval: (id: string) => http.del<{ device: T.Device }>(`/devices/${id}/remove`),
  deviceEvents: (id: string, q: { kinds?: string[]; q?: string; from?: number; to?: number; limit?: number } = {}) =>
    http.get<{ items: T.DeviceEvent[] }>(`/devices/${id}/events`, { limit: 200, ...q }),
  deviceProcesses: (id: string, at?: number) => http.get<{ items: T.ProcessInfo[] }>(`/devices/${id}/processes`, { at }),
  revealUninstallToken: (id: string) => http.post<{ token: string | null; pending_token: string | null }>(`/devices/${id}/uninstall-token/reveal`),
  rotateUninstallToken: (id: string) => http.post<{ pending_token: string; token_active: boolean; sent: boolean; message: string }>(`/devices/${id}/uninstall-token/rotate`),
  mergeDevice: (id: string, from: string) => http.post<T.Device>(`/devices/${id}/merge`, { device_id: from }),
  dismissDuplicate: (id: string, other: string) => http.post<void>(`/devices/${id}/duplicates/dismiss`, { device_id: other }),
  deviceAction: (id: string, b: { action: T.ResponseAction; incident_id?: string; comment?: string }) =>
    http.post<T.ResponseActionRow>(`/devices/${id}/actions`, b),

  // groups & enrollment
  groups: () => http.get<T.Group[]>('/groups'),
  createGroup: (b: { name: string; description: string; policy_id: string | null; update_ring?: T.GroupUpdateRing }) => http.post<T.Group>('/groups', b),
  patchGroup: (id: string, b: Partial<Pick<T.Group, 'name' | 'description' | 'policy_id' | 'update_ring'>>) => http.patch<T.Group>(`/groups/${id}`, b),
  deleteGroup: (id: string) => http.del(`/groups/${id}`),
  enrollmentTokens: () => http.get<T.EnrollmentToken[]>('/enrollment-tokens'),
  createEnrollmentToken: (b: { group_id: string; expires_in_days: number; max_uses: number; remote_profile?: T.RemoteAccessProfile }) =>
    http.post<T.CreatedEnrollmentToken>('/enrollment-tokens', b),
  revokeEnrollmentToken: (id: string) => http.del(`/enrollment-tokens/${id}`),
  installer: () => http.get<T.InstallerMeta>('/agent/installer'),

  // signed agent updates (staged rings)
  updateStatus: () => http.get<T.UpdateStatus>('/updates/status'),
  updateReleases: () => http.get<T.UpdateRelease[]>('/updates/releases'),
  registerRelease: (b: { manifest: T.UpdateManifest; notes?: string }) => http.post<T.UpdateRelease>('/updates/releases', b),
  promoteRelease: (id: string, ring: T.UpdateRing) => http.post<T.PromotedUpdateRelease>(`/updates/releases/${id}/promote`, { ring }),
  haltRelease: (id: string, reason?: string) => http.post<T.UpdateRelease>(`/updates/releases/${id}/halt`, { reason }),

  // incidents & alerts
  incidents: (q: { status?: string; severity?: string; assignee?: string; device_id?: string; q?: string; sort?: string; limit?: number; cursor?: string } = {}) =>
    http.get<T.Page<T.Incident>>('/incidents', { limit: 200, sort: 'priority', ...q }),
  incident: (id: string) => http.get<T.IncidentDetail>(`/incidents/${id}`),
  patchIncident: (id: string, b: { status?: T.IncidentStatus; assignee_id?: string | null; classification?: T.Classification | null }) =>
    http.patch<T.Incident>(`/incidents/${id}`, b),
  addComment: (id: string, body: string) => http.post<T.Comment>(`/incidents/${id}/comments`, { body }),
  setChecklist: (id: string, itemId: string, done: boolean) => http.post<T.ChecklistItem>(`/incidents/${id}/checklist/${itemId}`, { done }),
  alerts: (q: { status?: string; severity?: string; device_id?: string; q?: string; limit?: number; cursor?: string } = {}) =>
    http.get<T.Page<T.AlertRow>>('/alerts', { limit: 500, ...q }),
  alert: (id: string) => http.get<T.AlertDetail>(`/alerts/${id}`),
  patchAlerts: (ids: string[], status: T.AlertStatus) => http.patch<void>('/alerts', { ids, status }),

  // evidence capture after ST-02 / ST-04 (collect / download / delete: admins, interactive session)
  incidentEvidence: (id: string) => http.get<{ items: T.EvidenceBundle[] }>(`/incidents/${id}/evidence`),
  evidence: (id: string) => http.get<T.EvidenceBundle>(`/evidence/${id}`),
  /** 403 `reauth_required` when the admin has MFA and no fresh code (wrap in `withReauth`). `reason` (≤ 200 chars) goes to the audit log. */
  collectEvidence: (id: string, reason?: string) => http.post<T.EvidenceBundle>(`/evidence/${id}/collect`, reason ? { reason } : {}),
  /** The ticket's password is shown once and never stored; `url` is single use, same session, 10 min. */
  evidenceDownload: (id: string, reason?: string) => http.post<T.EvidenceDownloadTicket>(`/evidence/${id}/download`, reason ? { reason } : {}),
  deleteEvidence: (id: string, reason?: string) => request<T.EvidenceBundle>('DELETE', `/evidence/${id}`, reason ? { reason } : undefined),

  // response
  actions: (q: { device_id?: string; status?: string; limit?: number; cursor?: string } = {}) =>
    http.get<T.Page<T.ResponseActionRow>>('/actions', { limit: 200, ...q }),

  // policies & rules
  policies: () => http.get<T.PolicySummary[]>('/policies'),
  policy: (id: string) => http.get<T.Policy>(`/policies/${id}`),
  createPolicy: (b: { name: string; clone_from?: string }) => http.post<T.Policy>('/policies', b),
  savePolicy: (p: T.Policy) => http.put<T.Policy>(`/policies/${p.id}`, p),
  deletePolicy: (id: string) => http.del(`/policies/${id}`),
  rules: () => http.get<T.RuleRow[]>('/rules'),
  createRule: (source: string) => http.post<T.RuleRow>('/rules', { source }),
  patchRule: (id: string, b: { enabled_custom?: boolean; source?: string }) => http.patch<T.RuleRow>(`/rules/${id}`, b),
  deleteRule: (id: string) => http.del(`/rules/${id}`),

  exclusions: () => http.get<T.ExclusionRow[]>('/exclusions'),
  createExclusion: (b: Omit<T.Exclusion, 'id'> & { policy_id: string | null; from_alert_id?: string }) => http.post<T.ExclusionRow>('/exclusions', b),
  deleteExclusion: (id: string) => http.del(`/exclusions/${id}`),
  exclusionPreview: (q: { kind: string; value: string; rule_id?: string | null }) =>
    http.get<T.ExclusionPreview>('/exclusions/preview', { kind: q.kind, value: q.value, rule_id: q.rule_id ?? undefined }),
  iocs: () => http.get<T.IocRow[]>('/iocs'),
  createIocs: (items: (Omit<T.Ioc, 'id'> & { policy_id?: string | null })[], confirm_broad = false) =>
    http.post<T.IocRow[]>('/iocs', { items, confirm_broad }),
  deleteIoc: (id: string) => http.del(`/iocs/${id}`),

  // quarantine & review
  quarantine: () => http.get<T.QuarantineItem[]>('/quarantine'),
  restoreQuarantine: (id: string) => http.post<T.QuarantineItem>(`/quarantine/${id}/restore`),
  deleteQuarantine: (id: string) => http.post<T.QuarantineItem>(`/quarantine/${id}/delete`),
  reviewRequests: (state?: string) => http.get<T.ReviewRequestRow[]>('/review-requests', { state }),
  decideReview: (id: string, b: { approved: boolean; message: string; create_exclusion: boolean }) =>
    http.post<T.ReviewRequestRow>(`/review-requests/${id}/decision`, b),

  hunt: (b: T.HuntRequest) => http.post<T.HuntResponse>('/hunt', b),

  // admin
  users: () => http.get<T.User[]>('/users'),
  createUser: (b: { email: string; name: string; role: string; password?: string }) => http.post<T.User>('/users', b),
  patchUser: (id: string, b: { role?: string; disabled?: boolean; name?: string; oidc_subject?: string | null }) => http.patch<T.User>(`/users/${id}`, b),
  deleteUser: (id: string) => http.del(`/users/${id}`),
  apiTokens: () => http.get<T.ApiToken[]>('/api-tokens'),
  createApiToken: (b: { name: string; privileges: string[]; expires_in_days?: number }) => http.post<T.CreatedApiToken>('/api-tokens', b),
  deleteApiToken: (id: string) => http.del(`/api-tokens/${id}`),
  settings: () => http.get<T.Settings>('/settings'),
  saveSettings: (s: T.Settings) => http.put<T.Settings>('/settings', s),
  auditLog: (q: { actor?: string; action?: string; limit?: number; cursor?: string } = {}) =>
    http.get<T.Page<T.AuditEntry>>('/audit-log', { limit: 200, ...q }),
  auditVerify: () => http.get<T.AuditVerify>('/audit-log/verify'),
}

export const qk = {
  me: ['me'] as const,
  setup: ['setup-status'] as const,
  dashboard: ['dashboard'] as const,
  devices: (q?: object) => ['devices', q ?? {}] as const,
  device: (id: string) => ['device', id] as const,
  deviceEvents: (id: string, q?: object) => ['device', id, 'events', q ?? {}] as const,
  deviceProcesses: (id: string) => ['device', id, 'processes'] as const,
  groups: ['groups'] as const,
  enrollmentTokens: ['enrollment-tokens'] as const,
  installer: ['installer'] as const,
  updateStatus: ['updates', 'status'] as const,
  updateReleases: ['updates', 'releases'] as const,
  incidents: (q?: object) => ['incidents', q ?? {}] as const,
  incident: (id: string) => ['incident', id] as const,
  alerts: (q?: object) => ['alerts', q ?? {}] as const,
  alert: (id: string) => ['alert', id] as const,
  incidentEvidence: (id: string) => ['evidence', 'incident', id] as const,
  actions: (q?: object) => ['actions', q ?? {}] as const,
  policies: ['policies'] as const,
  policy: (id: string) => ['policy', id] as const,
  rules: ['rules'] as const,
  exclusions: ['exclusions'] as const,
  iocs: ['iocs'] as const,
  quarantine: ['quarantine'] as const,
  reviews: (state?: string) => ['review-requests', state ?? 'all'] as const,
  users: ['users'] as const,
  apiTokens: ['api-tokens'] as const,
  settings: ['settings'] as const,
  audit: (q?: object) => ['audit', q ?? {}] as const,
  auditVerify: ['audit-verify'] as const,
}
