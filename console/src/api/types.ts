/**
 * TypeScript mirror of `crates/kestrel-common` (serde JSON) and the REST shapes
 * in `docs/contracts.md`. Enums are snake_case strings; `Option<T>` fields are
 * `T | null` and may be omitted when the Rust side has `#[serde(default)]`.
 */

export type TimestampMs = number
export type Uuid = string

// ---------------------------------------------------------------- alert.rs

export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const
export type Severity = (typeof SEVERITIES)[number]

export const DATA_CATEGORIES = [
  'browser_passwords',
  'browser_cookies',
  'browser_autofill',
  'browser_master_key',
  'crypto_wallet',
  'discord',
  'telegram',
  'steam',
  'ftp_client',
  'vpn',
  'cloud_token',
  'password_manager',
  'email',
  'ssh_keys',
] as const
export type DataCategory = (typeof DATA_CATEGORIES)[number]

export interface ProcessInfo {
  guid: string
  pid: number
  ppid: number
  parent_guid?: string | null
  image: string
  cmdline: string
  user?: string | null
  integrity?: Integrity | null
  start_ts: TimestampMs
  exit_ts?: TimestampMs | null
  signer?: string | null
  signed?: SignatureState
  sha256?: string | null
  motw_zone?: number | null
  file_size?: number | null
  path_class: PathClass
}

export interface Alert {
  id: Uuid
  ts: TimestampMs
  rule_id: string
  rule_name: string
  rule_author?: string | null
  severity: Severity
  attack?: string[]
  mode: RuleMode
  summary: string
  process: ProcessInfo
  ancestry?: ProcessInfo[]
  data_at_risk?: DataCategory[]
  evidence?: KEvent[]
  actions?: ActionOutcome[]
}

// ---------------------------------------------------------------- event.rs

export const EVENT_KINDS = [
  'process_start',
  'process_stop',
  'image_load',
  'file_access',
  'registry_set',
  'net_connect',
  'dns_query',
  'dpapi_unprotect',
  'process_access',
  'remote_thread',
  'thread_context',
  'debug_attach',
  'script_block',
  'tamper',
  'file_activity',
  'task_registered',
  'service_installed',
  'wmi_subscription',
] as const
export type EventKind = (typeof EVENT_KINDS)[number]

export type SignatureState = 'unknown' | 'unsigned' | 'valid' | 'invalid'
export type Integrity = 'untrusted' | 'low' | 'medium' | 'high' | 'system'
export type FileOp = 'open' | 'read' | 'write' | 'create' | 'delete' | 'rename'
export type NetProto = 'tcp' | 'udp'
export type TamperKind =
  | 'etw_session_stopped'
  | 'etw_provider_disabled'
  | 'events_lost'
  | 'wfp_filter_change'
  | 'amsi_provider_change'
  | 'service_config_change'
  | 'agent_file_modified'
  | 'uninstall_attempt'
export type PathClass =
  | 'system'
  | 'windows'
  | 'program_files'
  | 'temp'
  | 'downloads'
  | 'user_writable'
  | 'external'
  | 'other'

export interface ProcessStart {
  ppid: number
  parent_guid?: string | null
  image: string
  cmdline: string
  user?: string | null
  integrity?: Integrity | null
  session_id?: number
  signer?: string | null
  signed?: SignatureState
  sha256?: string | null
  motw_zone?: number | null
  file_size?: number | null
}

export interface TargetProcess {
  target_pid: number
  target_guid?: string | null
  target_image: string
  /** Access mask: granted (Sysmon 10) or desired (Kernel-Audit-API-Calls). */
  granted_access?: number
  /** NTSTATUS of the open (0 = success); non-zero only reported for lsass, e.g. refused by LSA protection. */
  return_code?: number
}

export type RegistryOp = 'set' | 'delete_value' | 'delete_key'

/** Per-process file activity summary from the ransomware sensor (`EventData::FileActivity`). */
export interface FileActivity {
  window_ms: number
  files_touched: number
  dirs: number
  renames?: number
  ext_changes?: number
  overwrites?: number
  new_files?: number
  deletes?: number
  net_paths?: number
  top_new_ext?: string | null
  /** Share of ext_changes using top_new_ext, 0-100. */
  top_ext_pct?: number
  note_name?: string | null
  note_dirs?: number
  canary_hits?: string[]
  sample_paths?: string[]
}

export type TaskOp = 'created' | 'updated' | 'deleted'
export interface TaskChange {
  name: string
  op: TaskOp
  user?: string | null
  actions?: string[]
  hidden?: boolean
  triggers?: string[]
}

export interface ServiceInstall {
  name: string
  image_path: string
  /** 0 boot, 1 system, 2 auto, 3 demand, 4 disabled. */
  start_type?: number | null
  /** 1 = kernel driver, 0x10 own process, 0x20 shared process. */
  service_type?: number | null
  account?: string | null
}

export interface WmiBinding {
  namespace: string
  filter: string
  consumer: string
}

export type EventData =
  | ({ type: 'process_start' } & ProcessStart)
  | { type: 'process_stop'; exit_code?: number | null }
  | { type: 'image_load'; path: string; signer?: string | null; signed?: SignatureState }
  | { type: 'file_access'; path: string; op: FileOp }
  | { type: 'registry_set'; key: string; value_name: string; data?: string | null; op?: RegistryOp }
  | {
      type: 'net_connect'
      proto: NetProto
      dst_ip: string
      dst_port: number
      src_port?: number
      dst_host?: string | null
      bytes_sent?: number | null
    }
  | { type: 'dns_query'; qname: string; answers?: string[] }
  | { type: 'dpapi_unprotect'; description: string }
  | ({ type: 'process_access' } & TargetProcess)
  | ({ type: 'remote_thread' } & TargetProcess)
  | ({ type: 'thread_context' } & TargetProcess)
  | ({ type: 'debug_attach' } & TargetProcess)
  | { type: 'script_block'; engine: string; content: string }
  | { type: 'tamper'; kind: TamperKind; detail: string }
  | ({ type: 'file_activity' } & FileActivity)
  | ({ type: 'task_registered' } & TaskChange)
  | ({ type: 'service_installed' } & ServiceInstall)
  | ({ type: 'wmi_subscription' } & WmiBinding)

/** `Event` with its `EventData` flattened in (serde `flatten` + `tag = "type"`). */
export type KEvent = { ts: TimestampMs; pid: number; guid: string } & EventData

/** Event rows returned by device/hunt endpoints carry where they came from. */
export type DeviceEvent = KEvent & {
  device_id: Uuid
  hostname?: string
  /** Optional enrichment (console assumption): image of the acting process for non-process events. */
  process_image?: string
}

// ---------------------------------------------------------------- rules.rs

export type RuleMode = 'off' | 'audit' | 'protect'
export type RuleKind = 'builtin' | 'sigma' | 'yara'
export type RuleCategory =
  | 'delivery'
  | 'execution'
  | 'credential_access'
  | 'browser_tampering'
  | 'exfiltration'
  | 'tripwire'
  | 'tamper'
  | 'custom'
  | 'ransomware'
  | 'credential_dumping'
  | 'persistence'

export interface RuleMeta {
  id: string
  name: string
  description: string
  kind: RuleKind
  category: RuleCategory
  severity: Severity
  attack?: string[]
  default_mode: RuleMode
  protect_day_one?: boolean
  protect_action?: string
  author?: string | null
  license?: string | null
  references?: string[]
  false_positives?: string[]
}

export type RuleRow = RuleMeta & { enabled_custom: boolean; hits_7d: number; source?: string }

// ---------------------------------------------------------------- response.rs

export type ResponseAction =
  | { type: 'kill_process'; pid: number; guid?: string | null; tree?: boolean }
  | { type: 'suspend_process'; pid: number; guid?: string | null }
  | { type: 'resume_process'; pid: number; guid?: string | null }
  | { type: 'quarantine_file'; path: string; sha256?: string | null }
  | { type: 'restore_file'; quarantine_id: string }
  | { type: 'delete_quarantined'; quarantine_id: string }
  | {
      type: 'block_destination'
      ip: string
      port?: number | null
      image?: string | null
      ttl_secs?: number | null
      /** Set by the agent when an IOC hit created the block (analysts never set it). */
      ioc_id?: string | null
    }
  | { type: 'block_image_network'; image: string; ttl_secs?: number | null }
  | { type: 'isolate_host'; allow_ips?: string[] }
  | { type: 'release_host' }
  | { type: 'apply_hardening' }
  | { type: 'scan'; path?: string | null }
  | { type: 'collect_triage' }
  | {
      type: 'remove_autorun'
      kind: AutorunKind
      /** Registry key, Startup file path, task path, service name or WMI consumer name. */
      location: string
      value_name?: string | null
      /** RegistryValue only: write this data (REG_SZ or `dword:N`) instead of deleting the value. */
      restore_data?: string | null
    }

/** Persistence mechanism targeted by `remove_autorun`. */
export type AutorunKind = 'registry_value' | 'startup_file' | 'scheduled_task' | 'service' | 'wmi_subscription'

export type ResponseActionType = ResponseAction['type']

export interface ActionOutcome {
  action: ResponseAction
  ok: boolean
  detail?: string
  ts: TimestampMs
  /** Structured result: quarantine id, triage path, WFP filter id, or the vault backup id of a removed autorun. */
  artifact?: string | null
}

// ---------------------------------------------------------------- policy.rs

export type ExclusionKind = 'path' | 'sha256' | 'signer' | 'image'
export interface Exclusion {
  id: string
  kind: ExclusionKind
  value: string
  rule_id?: string | null
  expires_at?: TimestampMs | null
  reason?: string
}
export type ExclusionRow = Exclusion & { policy_id: string | null; created_by: string; created_at: TimestampMs }

export type IocKind = 'sha256' | 'ip' | 'domain' | 'url' | 'certificate'
export type IocAction = 'allow' | 'audit' | 'block'
export interface Ioc {
  id: string
  kind: IocKind
  value: string
  action: IocAction
  description?: string
}
export type IocRow = Ioc & { policy_id?: string | null; created_by: string; created_at: TimestampMs; hits: number }

export type HardeningMode = 'off' | 'audit' | 'enforce'
export interface Hardening {
  mode: HardeningMode
  block_mshta: boolean
  block_user_path_exec: boolean
  disable_run_dialog: boolean
  terminal_paste_warning: boolean
  script_block_logging: boolean
  dpapi_debug_channel: boolean
  asr_rules: boolean
  browser_disable_remote_debugging: boolean
  /** WDigest UseLogonCredential = 0 (no cleartext passwords in LSASS). */
  wdigest_off: boolean
  /** Defender ASR "Block credential stealing from LSASS" (added without touching other ASR rules). */
  asr_lsass: boolean
  /** LSA protection (RunAsPPL = 2). Takes effect after a reboot the agent never triggers. */
  lsa_protection: boolean
  /** Report (never toggle) the Microsoft vulnerable-driver blocklist state. */
  report_vulnerable_driver_blocklist: boolean
  /** Enable the Microsoft-Windows-TaskScheduler/Operational log. */
  task_scheduler_log: boolean
}

/** Optional sensor groups (`Policy.sensors`); all default to on. */
export interface SensorSettings {
  file_activity: boolean
  ransomware_canaries: boolean
  persistence: boolean
  credential_access: boolean
}
export type HardeningControl = Exclude<keyof Hardening, 'mode'>

export interface Privacy {
  capture_cmdline: boolean
  hash_usernames: boolean
  redact_path_prefixes: string[]
  capture_dns: boolean
  capture_script_content: boolean
}

export interface Telemetry {
  upload_events: boolean
  event_kinds: string[]
  max_outbox_mb: number
}

export interface ItContact {
  name: string
  email: string
  phone: string
  url: string
}

export interface Branding {
  org_name: string
  it_contact: ItContact
  privacy_notice_md: string
}

export interface Policy {
  id: string
  name: string
  version: number
  rules: Record<string, RuleMode>
  suspend_window_ms: number
  exclusions: Exclusion[]
  iocs: Ioc[]
  hardening: Hardening
  privacy: Privacy
  telemetry: Telemetry
  canaries: boolean
  branding: Branding
  exfil_domains: string[]
  /** Release isolation automatically after this many hours without server contact (0 = never). */
  isolation_auto_release_hours: number
  /** Lifetime of firewall blocks created by indicator (IOC) network/DNS hits, in seconds (≥ 60). */
  ioc_block_ttl_secs: number
  /** Indicator hits block the destination for every program instead of only the offending one. */
  ioc_block_host_wide: boolean
  /** Optional sensor groups; absent on servers older than v1.1 (treat as all on). */
  sensors?: SensorSettings
}

export interface PolicySummary {
  id: string
  name: string
  version: number
  updated_at: TimestampMs
  group_count: number
  device_count: number
}

// ---------------------------------------------------------------- wire.rs

export interface AgentHealth {
  etw_ok: boolean
  etw_events_lost?: number
  etw_buffers_lost?: number
  events_per_min?: number
  outbox_depth?: number
  sysmon_present?: boolean
  dpapi_channel_enabled?: boolean
  amsi_ok?: boolean
  isolated?: boolean
  hardening?: Record<string, boolean>
  cpu_pct?: number
  mem_mb?: number
  uptime_s?: number
  logged_on_user?: string | null
  ip_addresses?: string[]
  av_product?: string | null
}

export interface Software {
  name: string
  version?: string
  publisher?: string
}
export interface Inventory {
  software: Software[]
  local_admins: string[]
}

// ---------------------------------------------------------------- REST: auth

export type Role = 'admin' | 'analyst' | 'readonly'
export interface User {
  id: Uuid
  email: string
  name: string
  role: Role | string
  last_login: TimestampMs | null
  created_at: TimestampMs
  disabled: boolean
  mfa_enabled: boolean
  /** A single sign-on identity is linked (accounts are bound by IdP issuer + subject). */
  sso_linked?: boolean
  /** The account has a local password. */
  local_password?: boolean
}
export interface LoginResponse {
  user: User
  csrf_token: string
}
export interface MeResponse {
  user: User
  csrf_token: string
  privileges: string[]
}
export interface SetupStatus {
  needs_setup: boolean
  oidc_enabled: boolean
  org_name: string
}

// ---------------------------------------------------------------- REST: lists

export interface Page<T> {
  items: T[]
  next_cursor: string | null
  total: number
}

// ---------------------------------------------------------------- REST: devices

export type DeviceStatus = 'online' | 'offline' | 'degraded' | 'isolated'
export interface Device {
  id: Uuid
  hostname: string
  os_name: string
  os_build: string
  arch: string
  domain: string | null
  agent_version: string
  status: DeviceStatus
  last_seen: TimestampMs
  first_seen: TimestampMs
  ip_addresses: string[]
  logged_on_user: string | null
  group_id: string | null
  group_name: string | null
  policy_id: string | null
  policy_name: string | null
  policy_version_applied: number
  tags: string[]
  health: AgentHealth
  open_incidents: number
  /** Expiry of the client certificate the agent uses (ms); renewed automatically 30 days before. */
  cert_expires_at?: TimestampMs | null
  /** Devices that enrolled with the same hardware UUID (re-image, clone or impersonation). */
  possible_duplicates?: Uuid[]
  /** The server holds an uninstall token for this device. */
  uninstall_token_set?: boolean
  /** A rotated uninstall token is waiting for the agent to confirm it. */
  uninstall_token_pending?: boolean
}

export interface DuplicateDevice {
  id: Uuid
  hostname: string
  first_seen: TimestampMs
  last_seen: TimestampMs
  decommissioned: boolean
}

export interface HardeningState {
  control: HardeningControl | string
  desired: boolean
  /** null when the agent has not reported this control (older agent). */
  applied: boolean | null
  source: string
  /** Kestrel only reports this control's state and never changes it. */
  report_only?: boolean
  /** Configured on the device but waiting for a reboot (LSA protection). */
  pending_reboot?: boolean
}

export interface DeviceDetail {
  device: Device
  duplicates?: DuplicateDevice[]
  inventory: Inventory
  recent_alerts: AlertRow[]
  effective_policy: Policy
  hardening: HardeningState[]
}

export interface Group {
  id: string
  name: string
  description: string
  policy_id: string | null
  device_count: number
  /** The built-in group devices fall back to; it cannot be deleted. */
  is_default: boolean
  /** Staged auto-update ring of the group's devices (`pinned` = never auto-update). */
  update_ring: GroupUpdateRing
}

export interface EnrollmentToken {
  id: string
  group_id: string
  group_name: string
  token_prefix: string
  created_at: TimestampMs
  expires_at: TimestampMs
  max_uses: number
  uses: number
  revoked: boolean
}
export type CreatedEnrollmentToken = EnrollmentToken & { token: string; install_command: string }

export interface InstallerMeta {
  version: string
  msi_url: string
  sha256: string
}

// ---------------------------------------------------------------- REST: incidents & alerts

export type AlertStatus = 'new' | 'acknowledged' | 'closed'
export interface AlertRow {
  id: Uuid
  incident_id: Uuid
  device_id: Uuid
  hostname: string
  ts: TimestampMs
  rule_id: string
  rule_name: string
  rule_author: string | null
  severity: Severity
  attack: string[]
  mode: RuleMode
  summary: string
  process_guid: string
  image: string
  data_at_risk: DataCategory[]
  actions: ActionOutcome[]
  status: AlertStatus
}

export type AlertDetail = Alert & { incident_id: Uuid; device_id: Uuid; hostname: string; status: AlertStatus }

export type IncidentStatus = 'open' | 'in_progress' | 'resolved' | 'dismissed'
export type Classification = 'true_positive' | 'false_positive' | 'benign'
export interface Incident {
  id: Uuid
  title: string
  severity: Severity
  priority: number
  status: IncidentStatus
  classification: Classification | null
  assignee: User | null
  device_id: Uuid
  hostname: string
  user: string | null
  created_at: TimestampMs
  updated_at: TimestampMs
  alert_count: number
  rule_ids: string[]
  attack: string[]
  data_at_risk: DataCategory[]
  contained: boolean
}

export interface TreeNode {
  guid: string
  parent_guid: string | null
  pid: number
  image: string
  cmdline: string
  user: string | null
  start_ts: TimestampMs
  exit_ts: TimestampMs | null
  signer: string | null
  signed: SignatureState
  sha256: string | null
  path_class: PathClass
  alert_rule_ids: string[]
  is_root: boolean
}

export type TimelineKind = 'alert' | 'action' | 'comment' | 'status'
export interface TimelineEntry {
  ts: TimestampMs
  kind: TimelineKind
  title: string
  detail: string
  actor: string | null
}

export interface NetworkRow {
  ts: TimestampMs
  process_guid: string
  image: string
  dst_ip: string
  dst_port: number
  dst_host: string | null
  blocked: boolean
}

export type ChecklistKind = 'done' | 'approve' | 'manual'
export interface ChecklistItem {
  id: string
  text: string
  kind: ChecklistKind
  done: boolean
  action?: ResponseAction | null
}

export interface Comment {
  id: string
  author: User
  body: string
  ts: TimestampMs
}

export type IncidentDetail = Incident & {
  storyline: string
  alerts: AlertRow[]
  process_tree: TreeNode[]
  timeline: TimelineEntry[]
  evidence: KEvent[]
  network: NetworkRow[]
  actions: ResponseActionRow[]
  checklist: ChecklistItem[]
  comments: Comment[]
}

export type ActionStatus = 'pending' | 'sent' | 'succeeded' | 'failed' | 'expired'
export interface ResponseActionRow {
  id: Uuid
  device_id: Uuid
  hostname: string
  incident_id: Uuid | null
  action: ResponseAction
  status: ActionStatus
  requested_by: User | null
  comment: string
  created_at: TimestampMs
  completed_at: TimestampMs | null
  result_detail: string
  /** Structured result (quarantine id, triage path, filter id) when the agent reports one. */
  artifact?: string | null
}

// ---------------------------------------------------------------- REST: dashboard

export interface Dashboard {
  devices: { total: number; online: number; offline: number; isolated: number; degraded: number }
  incidents: { open: number; critical: number; high: number; mttr_hours_30d: number | null }
  alerts_24h: number
  blocked_24h: number
  alert_trend: { day: string; critical: number; high: number; medium: number; low: number }[]
  top_rules: { rule_id: string; name: string; count: number }[]
  data_at_risk_30d: { category: DataCategory; count: number }[]
  hardening_coverage: { control: string; applied: number; total: number }[]
  agent_versions: { version: string; count: number }[]
  recent_incidents: Incident[]
}

// ---------------------------------------------------------------- REST: misc

export interface ExclusionPreview {
  matching_alerts_30d: number
  sample: AlertRow[]
}

export type QuarantineState = 'held' | 'restored' | 'deleted'
export interface QuarantineItem {
  id: string
  device_id: Uuid
  hostname: string
  sha256: string
  original_path: string
  alert_id: Uuid | null
  state: QuarantineState
  created_at: TimestampMs
}

export type ReviewState = 'requested' | 'approved' | 'denied'
export interface ReviewRequestRow {
  id: string
  device_id: Uuid
  hostname: string
  user: string
  alert_id: Uuid
  rule_name: string
  file: string
  justification: string
  state: ReviewState
  decided_by: string | null
  decided_at: TimestampMs | null
  created_at: TimestampMs
  /** The exclusion approving with "create exclusion" would add; null when the file has no hash or valid signature. */
  exclusion_scope?: ExclusionScope | null
}

export interface ExclusionScope {
  kind: 'sha256' | 'signer'
  value: string
  rule_id: string
  policy_id: string
  policy_name: string
  expires_in_days: number
}

export interface HuntRequest {
  query: string
  from: TimestampMs
  to: TimestampMs
  limit: number
}
export interface HuntResponse {
  items: DeviceEvent[]
  elapsed_ms: number
}

export interface ApiToken {
  id: string
  name: string
  prefix: string
  created_at: TimestampMs
  last_used: TimestampMs | null
  privileges: string[]
  expires_at?: TimestampMs | null
}
export type CreatedApiToken = ApiToken & { token: string }

export interface NotificationSettings {
  email: {
    enabled: boolean
    smtp_host: string
    smtp_port: number
    username: string
    from: string
    to: string[]
    min_severity: Severity
    password?: string
    password_set?: boolean
  }
  slack: { enabled: boolean; webhook_url: string; min_severity: Severity }
  teams: { enabled: boolean; webhook_url: string; min_severity: Severity }
  webhook: { enabled: boolean; url: string; url_set?: boolean; min_severity: Severity; secret?: string; secret_set?: boolean }
  syslog: { enabled: boolean; host: string; port: number; protocol: 'udp' | 'tcp' | 'tls'; format: 'cef' | 'json'; allow_private?: boolean }
}

export interface OidcSettings {
  enabled: boolean
  issuer: string
  client_id: string
  client_secret?: string
  client_secret_set: boolean
  allowed_domains: string[]
  default_role: Role | string
}

export interface Settings {
  org_name: string
  branding: Branding
  retention_days: { events: number; alerts: number; audit: number }
  notifications: NotificationSettings
  oidc: OidcSettings
  session_timeout_minutes: number
  /** Absolute session lifetime in days (1-90), regardless of activity. */
  session_max_days?: number
  require_mfa: boolean
}

export interface AuditEntry {
  id: string
  ts: TimestampMs
  actor: { id: string; email: string } | null
  action: string
  target: string
  details: Record<string, unknown> | string | null
  hash: string
  prev_hash: string
}
export interface AuditVerify {
  ok: boolean
  broken_at: string | null
  count: number
}

export interface ApiErrorBody {
  error: { code: string; message: string }
}

export type LiveEventType = 'incident' | 'alert' | 'device' | 'action' | 'group' | 'update_release'
export interface LiveEvent {
  kind: LiveEventType
  id: string
  /** `created` / `updated` for most kinds; `update_release` may carry other verbs (registered, promoted, halted, delivery). */
  type: string
}

// ---------------------------------------------------------------- agent updates

export type UpdateRing = 'canary' | 'early' | 'broad'
export type GroupUpdateRing = UpdateRing | 'pinned'
export const UPDATE_RINGS: UpdateRing[] = ['canary', 'early', 'broad']
export const GROUP_UPDATE_RINGS: GroupUpdateRing[] = ['canary', 'early', 'broad', 'pinned']

/** Produced offline by `kestrel-agent update-sign`; signature is base64 Ed25519. */
export interface UpdateManifest {
  version: string
  url: string
  sha256: string
  signature: string
}
export interface UpdateRingHealth {
  ring: UpdateRing
  enabled: boolean
  enabled_at: TimestampMs | null
  enabled_by: string | null
  enabled_by_name: string | null
  /** Non-decommissioned devices whose group is in this ring. */
  devices: number
  /** Of those, agent_version >= release version. */
  on_target: number
  /** Devices the server sent this release to. */
  delivered: number
  /** A later Hello reported the new version. */
  succeeded: number
  /** The agent reported an update failure. */
  failed: number
  /** Delivered, not yet succeeded or failed. */
  pending: number
  /** Delivered, not succeeded, device not seen for more than 24 h. */
  offline_24h: number
}
export interface UpdateFailure {
  device_id: string
  hostname: string
  error: string
  at: TimestampMs
}
export type UpdateReleaseState = 'staged' | 'rolling' | 'complete' | 'halted'
export interface UpdateRelease {
  id: string
  version: string
  url: string
  sha256: string
  signature: string
  notes: string
  created_by: string | null
  created_by_name: string | null
  created_at: TimestampMs
  /** staged = no ring enabled; rolling = some rings; complete = broad enabled; halted. */
  state: UpdateReleaseState
  halted_at: TimestampMs | null
  halted_by: string | null
  halted_by_name: string | null
  halt_reason: string
  /** Ring a promote would enable next (null when complete or halted). */
  next_ring: UpdateRing | null
  /** Always 3 entries in order canary, early, broad. */
  rings: UpdateRingHealth[]
  /** Newest first, at most 20. */
  recent_failures: UpdateFailure[]
}
export type PromotedUpdateRelease = UpdateRelease & { delivered_now: number }
export interface UpdateRingSummary {
  ring: GroupUpdateRing
  groups: { id: string; name: string }[]
  devices: number
  /** Agent versions in this ring, most common first. */
  versions: { version: string; count: number }[]
  /** Newest non-halted release enabled for this ring (null for pinned). */
  target: { id: string; version: string } | null
}
export interface UpdateStatus {
  signing_key_configured: boolean
  /** Base64 Ed25519 public key configured on the server (KESTREL_UPDATE_PUBKEY). */
  public_key: string | null
  /** Where server-hosted packages must be referenced from. */
  package_base_url: string
  server_version: string
  /** canary, early, broad, pinned. */
  rings: UpdateRingSummary[]
}
