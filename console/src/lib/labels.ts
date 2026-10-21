import type {
  ActionStatus,
  Classification,
  DataCategory,
  DeviceStatus,
  EventKind,
  HardeningControl,
  IncidentStatus,
  PathClass,
  ResponseAction,
  RuleCategory,
  Severity,
  SignatureState,
} from '@/api/types'
import { safeDisplay } from './format'

export const SEVERITY_LABEL: Record<Severity, string> = {
  info: 'Info',
  low: 'Low',
  medium: 'Medium',
  high: 'High',
  critical: 'Critical',
}
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

/** Mirrors `DataCategory::label()` in kestrel-common. */
export const DATA_CATEGORY_LABEL: Record<DataCategory, string> = {
  browser_passwords: 'Saved browser passwords',
  browser_cookies: 'Browser cookies / sessions',
  browser_autofill: 'Autofill & payment cards',
  browser_master_key: 'Browser encryption key',
  crypto_wallet: 'Crypto wallets',
  discord: 'Discord token',
  telegram: 'Telegram session',
  steam: 'Steam session',
  ftp_client: 'FTP/SFTP client credentials',
  vpn: 'VPN profiles',
  cloud_token: 'Cloud / SSO tokens',
  password_manager: 'Password manager vault',
  email: 'Email client data',
  ssh_keys: 'SSH keys',
}

/** Mirrors `DataCategory::remediation()` in kestrel-common. */
export const DATA_CATEGORY_REMEDIATION: Record<DataCategory, string> = {
  browser_passwords: 'Rotate every password saved in the browser, starting with email, SSO and banking',
  browser_cookies:
    'Revoke all active web sessions for the user (Microsoft 365 / Google Workspace / SaaS) — a password reset alone does not kill stolen cookies',
  browser_master_key:
    'Revoke all active web sessions for the user (Microsoft 365 / Google Workspace / SaaS) — a password reset alone does not kill stolen cookies',
  browser_autofill: 'Ask the user to review saved cards and notify the card issuer',
  crypto_wallet: 'Move funds to a new wallet with a fresh seed immediately',
  discord: 'Change the Discord password (invalidates tokens) and review authorised apps',
  telegram: 'Terminate all other Telegram sessions (Settings → Devices)',
  steam: 'Deauthorize all Steam devices and change the password',
  ftp_client: 'Rotate FTP/SFTP credentials stored in the client',
  vpn: 'Revoke and reissue the VPN profile / certificate',
  cloud_token: 'Revoke cloud CLI tokens and access keys (AWS/Azure/GCP) and review recent API activity',
  password_manager: 'Lock the vault, rotate the master password and high-value entries',
  email: 'Rotate the mail account password and check for forwarding rules',
  ssh_keys: 'Remove the exposed public keys from authorized_keys everywhere and issue new keys',
}

export const RULE_CATEGORY_LABEL: Record<RuleCategory, string> = {
  delivery: 'Delivery',
  execution: 'Execution',
  credential_access: 'Credential access',
  browser_tampering: 'Browser tampering',
  exfiltration: 'Exfiltration',
  tripwire: 'Tripwire',
  tamper: 'Agent tamper',
  custom: 'Custom',
  ransomware: 'Ransomware',
  credential_dumping: 'Credential dumping',
  persistence: 'Persistence',
}

/** Display order of rule categories (catalog groups, policy rule matrix). */
export const RULE_CATEGORY_ORDER: RuleCategory[] = [
  'delivery',
  'execution',
  'credential_access',
  'browser_tampering',
  'exfiltration',
  'tripwire',
  'ransomware',
  'credential_dumping',
  'persistence',
  'tamper',
  'custom',
]

export const RULE_CATEGORY_HINT: Record<RuleCategory, string> = {
  delivery: 'How the malware arrived: lures, downloads, paste-and-run.',
  execution: 'Untrusted programs and script hosts starting.',
  credential_access: 'Browser, wallet and app credential stores read by the wrong program (stealers, ST-xx).',
  browser_tampering: 'Browsers started or modified to give up their secrets.',
  exfiltration: 'Stolen data leaving the device.',
  tripwire: 'Decoys nothing legitimate touches.',
  ransomware: 'Backup deletion, recovery tampering and mass file encryption (RW-xx).',
  credential_dumping: 'LSASS, SAM and NTDS dumping and LSA tampering (CD-xx).',
  persistence: 'Run keys, scheduled tasks, services, WMI and other autoruns (PS-xx).',
  tamper: 'Attempts to blind or remove the Kestrel agent.',
  custom: 'Your own Sigma rules.',
}

export const INCIDENT_STATUS_LABEL: Record<IncidentStatus, string> = {
  open: 'Open',
  in_progress: 'In progress',
  resolved: 'Resolved',
  dismissed: 'Dismissed',
}

export const CLASSIFICATION_LABEL: Record<Classification, string> = {
  true_positive: 'True positive',
  false_positive: 'False positive',
  benign: 'Benign (expected activity)',
}

export const DEVICE_STATUS_LABEL: Record<DeviceStatus, string> = {
  online: 'Online',
  offline: 'Offline',
  degraded: 'Degraded',
  isolated: 'Isolated',
}

export const ACTION_STATUS_LABEL: Record<ActionStatus, string> = {
  pending: 'Pending',
  sent: 'Sent',
  succeeded: 'Succeeded',
  failed: 'Failed',
  expired: 'Expired',
}

export const PATH_CLASS_LABEL: Record<PathClass, string> = {
  system: 'System32',
  windows: 'Windows',
  program_files: 'Program Files',
  temp: 'Temp',
  downloads: 'Downloads',
  user_writable: 'User profile',
  external: 'Network / USB',
  other: 'Other',
}
export function isUserWritable(p: PathClass): boolean {
  return p === 'temp' || p === 'downloads' || p === 'user_writable' || p === 'external'
}

export const SIGNATURE_LABEL: Record<SignatureState, string> = {
  valid: 'Signed',
  unsigned: 'Unsigned',
  invalid: 'Invalid signature',
  unknown: 'Signature unknown',
}

export const EVENT_KIND_LABEL: Record<EventKind, string> = {
  process_start: 'Process start',
  process_stop: 'Process stop',
  image_load: 'Image load',
  file_access: 'File access',
  registry_set: 'Registry set',
  net_connect: 'Network connect',
  dns_query: 'DNS query',
  dpapi_unprotect: 'DPAPI unprotect',
  process_access: 'Process access',
  remote_thread: 'Remote thread',
  thread_context: 'Thread context',
  debug_attach: 'Debugger attach',
  script_block: 'Script block',
  tamper: 'Tamper',
  file_activity: 'File activity',
  task_registered: 'Scheduled task',
  service_installed: 'Service install',
  wmi_subscription: 'WMI subscription',
}

/** Event kinds offered as timeline filters (most useful first). */
export const EVENT_KINDS_UI: EventKind[] = ['process_start', 'file_access', 'file_activity', 'net_connect', 'dns_query', 'dpapi_unprotect', 'process_access', 'registry_set', 'task_registered', 'service_installed', 'wmi_subscription', 'image_load', 'script_block', 'tamper']

export interface HardeningInfo {
  label: string
  blocks: string
  /** Side effects or preconditions the admin must know before turning it on. */
  caveat?: string
  /** Kestrel only reports the state; it never changes it. */
  reportOnly?: boolean
}
export const HARDENING_INFO: Record<HardeningControl, HardeningInfo> = {
  block_mshta: {
    label: 'Block mshta.exe',
    blocks:
      'Stops HTML Application lures (a favourite ClickFix payload) from running for standard users. Admin tools are unaffected.',
  },
  block_user_path_exec: {
    label: 'Block programs in Temp and Downloads',
    blocks:
      'Standard users cannot run .exe files straight from %TEMP% or Downloads, where about a third of stealer infections start. Installers must be run by IT.',
  },
  disable_run_dialog: {
    label: 'Remove the Win+R Run dialog',
    blocks:
      'The strongest control against "press Win+R and paste" ClickFix lures. Users who rely on Run will need the Start menu instead.',
  },
  terminal_paste_warning: {
    label: 'Warn on multi-line paste in Terminal',
    blocks: 'Windows Terminal asks before pasting multi-line commands, interrupting the Win+X paste-and-run variant.',
  },
  script_block_logging: {
    label: 'PowerShell script-block logging',
    blocks: 'Records de-obfuscated PowerShell (event 4104) so paste-and-run scripts are visible to detection rules.',
  },
  dpapi_debug_channel: {
    label: 'DPAPI audit channel',
    blocks:
      'Turns on the Windows log that shows which program decrypted browser secrets. Rule ST-03 depends on it.',
  },
  asr_rules: {
    label: 'Defender attack-surface rules',
    blocks:
      'Blocks rare/unknown executables, obfuscated scripts and impersonated system tools. Applies only where Microsoft Defender is the active antivirus.',
  },
  browser_disable_remote_debugging: {
    label: 'Disable browser remote debugging',
    blocks:
      'Sets Chrome/Edge RemoteDebuggingAllowed = false, closing the headless-debugging route stealers use to bypass App-Bound Encryption.',
  },
  wdigest_off: {
    label: 'Keep WDigest cleartext passwords off',
    blocks:
      'Pins WDigest UseLogonCredential to 0 so Windows does not keep reusable cleartext passwords in LSASS memory. Already the Windows default; attackers flip it back before dumping (rule CD-12).',
  },
  asr_lsass: {
    label: 'Defender: block credential stealing from LSASS',
    blocks: 'Adds the Defender attack-surface rule that stops most programs from reading LSASS memory. Kestrel adds this one rule and leaves your other ASR rules alone.',
    caveat: 'Works only where Microsoft Defender is the active antivirus. Not needed when LSA protection is already on.',
  },
  lsa_protection: {
    label: 'LSA protection (RunAsPPL)',
    blocks: 'Runs LSASS as a protected process so ordinary admin-level tools cannot open it to dump credentials (failed attempts raise CD-06).',
    caveat:
      'Takes effect only after the next reboot, which Kestrel never forces; devices show “Pending reboot” until then. It can stop unsigned LSA plug-ins (some smart-card, SSO or password-filter add-ons) from loading, so test on a few devices first.',
  },
  report_vulnerable_driver_blocklist: {
    label: 'Report the vulnerable-driver blocklist',
    blocks:
      'Shows whether the Microsoft vulnerable-driver blocklist is on. Ransomware loads known-vulnerable signed drivers to kill security tools (BYOVD).',
    caveat: 'Report only: Kestrel never changes this setting. Turn it on through Windows Security or your device management.',
    reportOnly: true,
  },
  task_scheduler_log: {
    label: 'Task Scheduler operational log',
    blocks: 'Turns on the Windows log that records scheduled tasks being created or changed, so persistence rule PS-05 still works if the live sensor misses an event.',
  },
}
export const HARDENING_CONTROLS = Object.keys(HARDENING_INFO) as HardeningControl[]

export const ACTION_LABEL: Record<ResponseAction['type'], string> = {
  kill_process: 'Kill process',
  suspend_process: 'Suspend process',
  resume_process: 'Resume process',
  quarantine_file: 'Quarantine file',
  restore_file: 'Restore file',
  delete_quarantined: 'Delete quarantined file',
  block_destination: 'Block destination',
  block_image_network: 'Block app network',
  unblock_network: 'Lift network block',
  isolate_host: 'Isolate host',
  release_host: 'Release host',
  apply_hardening: 'Re-apply hardening',
  scan: 'Scan',
  collect_triage: 'Collect triage package',
  remove_autorun: 'Remove persistence entry',
}

export const AUTORUN_KIND_LABEL: Record<import('@/api/types').AutorunKind, string> = {
  registry_value: 'Registry value',
  startup_file: 'Startup-folder file',
  scheduled_task: 'Scheduled task',
  service: 'Service',
  wmi_subscription: 'WMI subscription',
}

/** Mirrors `ResponseAction::privilege()`. */
export function actionPrivilege(a: ResponseAction): string {
  switch (a.type) {
    case 'kill_process':
    case 'suspend_process':
    case 'resume_process':
      return 'response.process'
    case 'quarantine_file':
    case 'restore_file':
    case 'delete_quarantined':
      return 'response.file'
    case 'remove_autorun':
      // Writes/deletes registry values as SYSTEM: admin-only by default (V-H2).
      return 'response.persistence'
    case 'block_destination':
    case 'block_image_network':
    case 'unblock_network':
    case 'isolate_host':
    case 'release_host':
      return 'response.network'
    default:
      return 'response.collect'
  }
}

/**
 * Canonical Windows defaults that `remove_autorun` may legitimately restore
 * (mirrors the agent's fixed table). Keys are lower-case, without `Wow6432Node\`.
 */
const CANONICAL_DEFAULTS: { key: string; value: string; data: string }[] = [
  { key: 'hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon', value: 'userinit', data: 'C:\\Windows\\system32\\userinit.exe,' },
  { key: 'hklm\\software\\microsoft\\windows nt\\currentversion\\winlogon', value: 'shell', data: 'explorer.exe' },
  { key: 'hklm\\system\\currentcontrolset\\control\\session manager', value: 'bootexecute', data: 'autocheck autochk *' },
  { key: 'hklm\\system\\currentcontrolset\\control\\securityproviders\\wdigest', value: 'uselogoncredential', data: 'dword:0' },
]

function normKey(k: string): string {
  return k
    .trim()
    .replace(/^HKEY_LOCAL_MACHINE(?=\\|$)/i, 'HKLM')
    .replace(/\\+$/, '')
    .replace(/\\wow6432node(?=\\|$)/gi, '')
    .toLowerCase()
}

/** True only when `data` is exactly the OS default for this exact key and value (key/value compared case-insensitively). */
export function isCanonicalDefault(location: string, valueName: string | null | undefined, data: string): boolean {
  const k = normKey(location)
  const v = (valueName ?? '').toLowerCase()
  return CANONICAL_DEFAULTS.some((d) => d.key === k && d.value === v && d.data.toLowerCase() === data.toLowerCase())
}

/** One-line description of an action with its parameters. Endpoint-controlled text is passed through `safeDisplay`. */
export function describeAction(a: ResponseAction): string {
  switch (a.type) {
    case 'kill_process':
      return `Kill PID ${a.pid}${a.tree ? ' and its children' : ''}`
    case 'suspend_process':
      return `Suspend PID ${a.pid}`
    case 'resume_process':
      return `Resume PID ${a.pid}`
    case 'quarantine_file':
      return `Quarantine ${safeDisplay(a.path)}`
    case 'restore_file':
      return `Restore quarantined item ${a.quarantine_id.slice(0, 8)}`
    case 'delete_quarantined':
      return `Delete quarantined item ${a.quarantine_id.slice(0, 8)}`
    case 'block_destination':
      return `Block ${a.ip}${a.port ? `:${a.port}` : ''}${a.image ? ` for ${safeDisplay(a.image)}` : ''}`
    case 'block_image_network':
      return `Block all network for ${safeDisplay(a.image)}`
    case 'unblock_network':
      if (a.image && a.block_id) return `Lift network block ${safeDisplay(a.block_id)} for ${safeDisplay(a.image)}`
      if (a.image) return `Lift network blocks for ${safeDisplay(a.image)}`
      if (a.block_id) return `Lift network block ${safeDisplay(a.block_id)}`
      return 'Lift every Kestrel network block'
    case 'isolate_host':
      return a.allow_ips?.length ? `Isolate host (allow ${a.allow_ips.join(', ')})` : 'Isolate host'
    case 'release_host':
      return 'Release host from isolation'
    case 'apply_hardening':
      return 'Re-apply hardening pack'
    case 'scan':
      return a.path ? `Scan ${safeDisplay(a.path)}` : 'Scan running user-path programs'
    case 'collect_triage':
      return 'Collect triage package'
    case 'remove_autorun': {
      const loc = safeDisplay(a.location)
      const what = a.kind === 'registry_value' && a.value_name ? `${loc}\\${safeDisplay(a.value_name)}` : loc
      if (a.restore_data != null) {
        if (isCanonicalDefault(a.location, a.value_name, a.restore_data)) return `Restore default of ${what} (${safeDisplay(a.restore_data)})`
        return `Write ${safeDisplay(a.restore_data)} to ${what}`
      }
      const verb = a.kind === 'service' ? 'Disable service' : `Remove ${AUTORUN_KIND_LABEL[a.kind].replace(/^[A-Z][a-z]/, (m) => m.toLowerCase())}`
      return `${verb} ${what}`
    }
  }
}

export const PRIVILEGES = [
  'read',
  'incidents.write',
  'response.process',
  'response.file',
  'response.persistence',
  'response.network',
  'response.collect',
  'exclusions.write',
  'iocs.write',
  'policies.write',
  'rules.write',
  'devices.write',
  'users.write',
  'settings.write',
  'audit.read',
  'tokens.write',
  'updates.write',
] as const

/** What each privilege allows (shown next to privilege pickers and role tables). */
export const PRIVILEGE_DESCRIPTION: Record<(typeof PRIVILEGES)[number], string> = {
  read: 'View devices, incidents, alerts, events and policies',
  'incidents.write': 'Assign, comment on, classify and close incidents',
  'response.process': 'Kill, suspend and resume processes',
  'response.file': 'Quarantine, restore and delete quarantined files',
  'response.persistence': 'Remove/restore persistence entries as SYSTEM (admin only by default)',
  'response.network': 'Block destinations and isolate or release hosts',
  'response.collect': 'Scan, collect triage packages and re-apply hardening',
  'exclusions.write': 'Create and remove exclusions',
  'iocs.write': 'Manage indicators (IOCs)',
  'policies.write': 'Edit policies and groups',
  'rules.write': 'Edit rules and custom Sigma rules',
  'devices.write': 'Edit, tag, move and decommission devices',
  'users.write': 'Manage users and roles',
  'settings.write': 'Change organisation, SSO and notification settings',
  'audit.read': 'Read the audit log',
  'tokens.write': 'Create and revoke API tokens',
  'updates.write': 'Register, promote and halt agent updates',
}

/** Built-in roles. Analysts deliberately lack `response.persistence` (SYSTEM registry writes, V-H2). */
export const ROLE_PRIVILEGES: Record<string, string[]> = {
  admin: ['*'],
  analyst: [
    'read',
    'incidents.write',
    'response.process',
    'response.file',
    'response.network',
    'response.collect',
    'exclusions.write',
    'iocs.write',
  ],
  readonly: ['read'],
}

export function attackUrl(t: string): string {
  const [base, sub] = t.split('.')
  return sub ? `https://attack.mitre.org/techniques/${base}/${sub}/` : `https://attack.mitre.org/techniques/${base}/`
}

/**
 * The `unblock_network` action that undoes a succeeded block action, or null.
 * App blocks lift every block for that program; destination blocks lift exactly
 * that block (its id is the action's `artifact`), falling back to the program.
 */
export function unblockFor(a: ResponseAction, artifact?: string | null): Extract<ResponseAction, { type: 'unblock_network' }> | null {
  if (a.type === 'block_image_network') return a.image ? { type: 'unblock_network', image: a.image, block_id: null } : null
  if (a.type !== 'block_destination') return null
  if (artifact && /^[A-Za-z0-9._-]{1,128}$/.test(artifact)) return { type: 'unblock_network', image: null, block_id: artifact }
  return a.image ? { type: 'unblock_network', image: a.image, block_id: null } : null
}
