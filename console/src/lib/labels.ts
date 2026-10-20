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
}

/** Event kinds offered as timeline filters (most useful first). */
export const EVENT_KINDS_UI: EventKind[] = ['process_start', 'file_access', 'net_connect', 'dns_query', 'dpapi_unprotect', 'process_access', 'registry_set', 'image_load', 'script_block', 'tamper']

export interface HardeningInfo {
  label: string
  blocks: string
  /** Agent health key in `AgentHealth.hardening`. */
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
  isolate_host: 'Isolate host',
  release_host: 'Release host',
  apply_hardening: 'Re-apply hardening',
  scan: 'Scan',
  collect_triage: 'Collect triage package',
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
    case 'block_destination':
    case 'block_image_network':
    case 'isolate_host':
    case 'release_host':
      return 'response.network'
    default:
      return 'response.collect'
  }
}

/** One-line description of an action with its parameters. */
export function describeAction(a: ResponseAction): string {
  switch (a.type) {
    case 'kill_process':
      return `Kill PID ${a.pid}${a.tree ? ' and its children' : ''}`
    case 'suspend_process':
      return `Suspend PID ${a.pid}`
    case 'resume_process':
      return `Resume PID ${a.pid}`
    case 'quarantine_file':
      return `Quarantine ${a.path}`
    case 'restore_file':
      return `Restore quarantined item ${a.quarantine_id.slice(0, 8)}`
    case 'delete_quarantined':
      return `Delete quarantined item ${a.quarantine_id.slice(0, 8)}`
    case 'block_destination':
      return `Block ${a.ip}${a.port ? `:${a.port}` : ''}${a.image ? ` for ${a.image}` : ''}`
    case 'block_image_network':
      return `Block all network for ${a.image}`
    case 'isolate_host':
      return a.allow_ips?.length ? `Isolate host (allow ${a.allow_ips.join(', ')})` : 'Isolate host'
    case 'release_host':
      return 'Release host from isolation'
    case 'apply_hardening':
      return 'Re-apply hardening pack'
    case 'scan':
      return a.path ? `Scan ${a.path}` : 'Scan running user-path programs'
    case 'collect_triage':
      return 'Collect triage package'
  }
}

export const PRIVILEGES = [
  'read',
  'incidents.write',
  'response.process',
  'response.file',
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
] as const

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
