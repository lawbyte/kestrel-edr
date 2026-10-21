import type {
  AlertDetail,
  ApiToken,
  AuditEntry,
  Device,
  EnrollmentToken,
  ExclusionRow,
  Group,
  IncidentDetail,
  IocRow,
  KEvent,
  Policy,
  ProcessInfo,
  QuarantineItem,
  ResponseActionRow,
  ReviewRequestRow,
  RuleMeta,
  RuleMode,
  Settings,
  User,
} from '@/api/types'
import { BUILTIN_RULES, CUSTOM_RULES, PACK_RULES } from './catalog'
import { FAMILY_RULES } from './catalog-families'
import { buildTelemetry, type DeviceTelemetry } from './events'
import {
  AISYAH,
  DANIEL,
  DAY,
  DEFAULT_PRIVACY_NOTICE,
  GROUPS,
  HOUR,
  MARCUS,
  MIN,
  NOW,
  ORG,
  POLICIES,
  PRIYA,
  USERS,
  buildDevices,
  computeStatus,
  ruleModes,
} from './fleet'
import { buildIncidents, type Ctx } from './scenarios'
import { fullAlerts } from './story'
import { hexId, int, pick, sha256, uuid } from './rng'
import { profileGuarded, profileNone, profileUnrestricted } from '@/lib/remote-profile'

function fnv(s: string): string {
  let h1 = 0x811c9dc5
  let h2 = 0x01000193
  for (let i = 0; i < s.length; i++) {
    h1 = Math.imul(h1 ^ s.charCodeAt(i), 16777619)
    h2 = Math.imul(h2 ^ s.charCodeAt(i), 2246822519)
  }
  return ((h1 >>> 0).toString(16).padStart(8, '0') + (h2 >>> 0).toString(16).padStart(8, '0')).repeat(4)
}

export class MockDb {
  users: User[] = structuredClone(USERS)
  groups: Group[] = structuredClone(GROUPS)
  policies: Policy[] = structuredClone(POLICIES)
  devices: Device[] = buildDevices()
  incidents: IncidentDetail[] = []
  alerts: AlertDetail[] = []
  actions: ResponseActionRow[] = []
  rules = new Map<string, RuleMeta>()
  customRules = new Map<string, { source: string; enabled_custom: boolean }>()
  exclusions: ExclusionRow[] = []
  iocs: IocRow[] = []
  quarantine: QuarantineItem[] = []
  reviews: ReviewRequestRow[] = []
  enrollment: EnrollmentToken[] = []
  apiTokens: ApiToken[] = []
  audit: AuditEntry[] = []
  settings: Settings
  telemetry = new Map<string, DeviceTelemetry>()
  storyEvents = new Map<string, KEvent[]>()
  storyProcs = new Map<string, ProcessInfo[]>()
  needsSetup = false
  session: User | null = null

  constructor() {
    // FIN-LT-021 got LSA protection from its policy but has not rebooted yet.
    const fin = this.devices.find((d) => d.hostname === 'FIN-LT-021')
    if (fin?.health.hardening) Object.assign(fin.health.hardening, { lsa_protection: false, lsa_protection_pending_reboot: true })
    // FIN-LT-014 has LSA protection in effect (it refused the dumper in the CD-06 scenario).
    const ppl = this.devices.find((d) => d.hostname === 'FIN-LT-014')
    if (ppl?.health.hardening) Object.assign(ppl.health.hardening, { lsa_protection: true, lsa_protection_pending_reboot: false })
    for (const r of [...BUILTIN_RULES, ...FAMILY_RULES]) this.rules.set(r.id, r)
    for (const r of [...CUSTOM_RULES, ...PACK_RULES]) {
      const { source, enabled_custom, ...meta } = r
      this.rules.set(r.id, meta)
      this.customRules.set(r.id, { source, enabled_custom })
    }
    const ctx = this.ctx()
    this.incidents = buildIncidents(ctx, this.devices)
    for (const inc of this.incidents) this.indexIncident(inc)

    // A few extra manual actions not tied to incidents.
    const it = this.dev('IT-LT-004')
    this.actions.push(
      this.actionRow(it, { type: 'scan', path: null }, PRIYA, 'Monthly spot check', 'succeeded', NOW - 2 * DAY, 'YARA-X scan: 38 running user-path programs, 0 matches'),
      this.actionRow(this.dev('FIN-LT-014'), { type: 'apply_hardening' }, MARCUS, 'Drift on Run-dialog policy', 'succeeded', NOW - 30 * HOUR, 'Hardening re-applied: 8/8 controls in effect'),
      this.actionRow(this.dev('SAL-LT-030'), { type: 'collect_triage' }, DANIEL, 'User reported pop-ups', 'expired', NOW - 3 * DAY, 'Device offline; command expired after 24 h'),
      this.actionRow(this.dev('OPS-DT-009'), { type: 'scan', path: 'C:\\Users\\Public\\Downloads' }, AISYAH, '', 'sent', NOW - 4 * MIN, ''),
      this.actionRow(this.dev('ENG-DT-007'), { type: 'kill_process', pid: 18324, guid: null, tree: false }, DANIEL, 'Runaway miner test from dev', 'failed', NOW - 6 * DAY, 'Process not found (already exited)'),
    )

    this.settings = {
      org_name: ORG,
      branding: structuredClone(POLICIES[0].branding),
      retention_days: { events: 30, alerts: 365, audit: 730 },
      notifications: {
        email: { enabled: true, smtp_host: 'smtp.office365.com', smtp_port: 587, username: 'kestrel-alerts@harbourline.sg', from: 'kestrel-alerts@harbourline.sg', to: ['soc@harbourline.sg'], min_severity: 'high', password_set: true },
        slack: { enabled: false, webhook_url: '', min_severity: 'high' },
        teams: { enabled: true, webhook_url: 'https://harbourline.webhook.office.com/webhookb2/7f1c…', min_severity: 'critical' },
        webhook: { enabled: false, url: '', min_severity: 'medium', secret_set: false },
        syslog: { enabled: true, host: 'siem.harbourline.local', port: 6514, protocol: 'tls', format: 'cef' },
      },
      oidc: { enabled: true, issuer: 'https://login.microsoftonline.com/3c1f0b2e-harbourline/v2.0', client_id: 'b8e2c3d1-4f5a-4b6c-9d7e-kestrel', client_secret_set: true, allowed_domains: ['harbourline.sg', 'harbourline.co.id'], default_role: 'readonly' },
      session_timeout_minutes: 480,
      require_mfa: true,
    }

    this.seedExclusions()
    this.seedIocs()
    this.seedQuarantine()
    this.seedReviews()
    this.seedEnrollment()
    this.seedTokens()
    this.seedAudit()
    this.refreshDevices()
  }

  ctx(): Ctx {
    return {
      rules: this.rules,
      modes: (d: Device) => this.modesFor(d),
      dev: (h: string) => this.dev(h),
    }
  }

  modesFor(d: Device): Record<string, RuleMode> {
    const p = this.policies.find((x) => x.id === d.policy_id) ?? this.policies[0]
    const defaults: Record<string, RuleMode> = {}
    for (const r of this.rules.values()) defaults[r.id] = r.default_mode
    return ruleModes(p, defaults)
  }

  dev(hostname: string): Device {
    const d = this.devices.find((x) => x.hostname === hostname)
    if (!d) throw new Error(`no device ${hostname}`)
    return d
  }

  indexIncident(inc: IncidentDetail) {
    const evs = this.storyEvents.get(inc.device_id) ?? []
    evs.push(...inc.evidence)
    this.storyEvents.set(inc.device_id, evs)
    const ps = this.storyProcs.get(inc.device_id) ?? []
    for (const n of inc.process_tree) {
      ps.push({
        guid: n.guid,
        pid: n.pid,
        ppid: 0,
        parent_guid: n.parent_guid,
        image: n.image,
        cmdline: n.cmdline,
        user: n.user,
        start_ts: n.start_ts,
        exit_ts: n.exit_ts,
        signer: n.signer,
        signed: n.signed,
        sha256: n.sha256,
        path_class: n.path_class,
      })
    }
    this.storyProcs.set(inc.device_id, ps)
    this.telemetry.delete(inc.device_id)
    for (const a of inc.actions) this.actions.push(a)
    this.alerts.push(...(fullAlerts.get(inc) ?? []))
  }

  refreshDevices() {
    for (const d of this.devices) {
      d.status = computeStatus(d)
      d.open_incidents = this.incidents.filter((i) => i.device_id === d.id && (i.status === 'open' || i.status === 'in_progress')).length
    }
    for (const g of this.groups) g.device_count = this.devices.filter((d) => d.group_id === g.id).length
  }

  telemetryFor(d: Device): DeviceTelemetry {
    let t = this.telemetry.get(d.id)
    if (!t) {
      t = buildTelemetry(d, this.storyEvents.get(d.id) ?? [], this.storyProcs.get(d.id) ?? [])
      this.telemetry.set(d.id, t)
    }
    return t
  }

  actionRow(d: Device, action: ResponseActionRow['action'], by: User | null, comment: string, status: ResponseActionRow['status'], ts: number, detail: string, incidentId: string | null = null): ResponseActionRow {
    return {
      id: uuid(),
      device_id: d.id,
      hostname: d.hostname,
      incident_id: incidentId,
      action,
      status,
      requested_by: by,
      comment,
      created_at: ts,
      completed_at: status === 'succeeded' || status === 'failed' || status === 'expired' ? ts + int(1500, 9000) : null,
      result_detail: detail,
    }
  }

  // ------------------------------------------------------------------ audit

  log(actor: User | null, action: string, target: string, details: Record<string, unknown> = {}, ts = Date.now()) {
    const prev = this.audit.length ? this.audit[this.audit.length - 1].hash : '0'.repeat(64)
    const body = JSON.stringify({ ts, actor: actor?.id ?? null, action, target, details, prev })
    this.audit.push({ id: uuid(), ts, actor: actor ? { id: actor.id, email: actor.email } : null, action, target, details, prev_hash: prev, hash: fnv(body) })
  }

  verifyAudit() {
    let prev = '0'.repeat(64)
    for (const e of this.audit) {
      if (e.prev_hash !== prev) return { ok: false, broken_at: e.id, count: this.audit.length }
      prev = e.hash
    }
    return { ok: true, broken_at: null, count: this.audit.length }
  }

  // ------------------------------------------------------------------ seeds

  private seedExclusions() {
    this.exclusions = [
      { id: uuid(), kind: 'signer', value: '2BrightSparks Pte Ltd', rule_id: 'ST-01', expires_at: NOW + 86 * DAY, reason: 'Nightly SyncBackPro profile backups (IT)', policy_id: 'pol-default', created_by: MARCUS.email, created_at: NOW - 4 * DAY },
      { id: uuid(), kind: 'signer', value: 'AgileBits Inc.', rule_id: 'ST-01', expires_at: null, reason: '1Password browser import', policy_id: null, created_by: PRIYA.email, created_at: NOW - 40 * DAY },
      { id: uuid(), kind: 'image', value: 'keepassxc.exe', rule_id: 'ST-09', expires_at: null, reason: 'KeePassXC Firefox import (IT only)', policy_id: 'pol-default', created_by: MARCUS.email, created_at: NOW - 21 * DAY },
      { id: uuid(), kind: 'path', value: 'C:\\Users\\*\\AppData\\Local\\Temp\\playwright_chromiumdev_profile-*', rule_id: 'ST-05', expires_at: null, reason: 'Playwright E2E runs', policy_id: 'pol-eng', created_by: DANIEL.email, created_at: NOW - 12 * DAY },
      { id: uuid(), kind: 'sha256', value: sha256(), rule_id: 'ST-12', expires_at: NOW + 20 * DAY, reason: 'Zebra label printer driver 5.2.1 (vendor hash verified)', policy_id: 'pol-default', created_by: AISYAH.email, created_at: NOW - 10 * DAY },
      { id: uuid(), kind: 'signer', value: 'Telegram FZ-LLC', rule_id: 'ST-14', expires_at: null, reason: 'Sales uses Telegram Desktop with customers', policy_id: 'pol-default', created_by: PRIYA.email, created_at: NOW - 60 * DAY },
    ]
  }

  private seedIocs() {
    const mk = (kind: IocRow['kind'], value: string, action: IocRow['action'], description: string, hits: number, days: number, by = DANIEL): IocRow => ({
      id: uuid(),
      kind,
      value,
      action,
      description,
      policy_id: null,
      created_by: by.email,
      created_at: NOW - days * DAY,
      hits,
    })
    this.iocs = [
      mk('ip', '185.208.158.114', 'block', 'Lumma C2 (SAL-LT-022 incident)', 2, 0.08),
      mk('domain', 'cdn-verify-human.top', 'block', 'ClickFix lure host', 1, 0.08),
      mk('sha256', 'e3b14f7d0a2c9b8e61f04c5d2a7b9e8c3f6a1d0b5e4c7a9f2d8b6e1c0a3f5d7b', 'block', 'Lumma Setup_x64.exe', 1, 0.08),
      mk('domain', 'docs-share-portal.com', 'block', 'FileFix lure (Edge)', 1, 0.5, AISYAH),
      mk('domain', 'pub-3f2c19ad7e.r2.dev', 'audit', 'R2 bucket seen in synchelper upload', 1, 0.02, AISYAH),
      mk('ip', '91.92.243.17', 'block', 'Acreed C2', 0, 0.3),
      mk('certificate', 'CN=Adobe Inc., O=Adobe Inc. (self-signed)', 'block', 'Forged Adobe certificate on Vidar loader', 1, 1, AISYAH),
      mk('url', 'https://docs-share-portal.com/d/a.ps1', 'block', 'FileFix stage 2', 0, 0.5, AISYAH),
      mk('sha256', sha256(), 'allow', 'Zebra label printer driver 5.2.1', 4, 10, MARCUS),
      mk('domain', 'bsc-dataseed1.binance.org', 'audit', 'Blockchain RPC used as dead-drop', 3, 30, PRIYA),
    ]
  }

  private seedQuarantine() {
    const fromActions = this.actions.filter((a) => a.action.type === 'quarantine_file' && a.status === 'succeeded')
    this.quarantine = fromActions.map((a) => {
      const act = a.action as Extract<ResponseActionRow['action'], { type: 'quarantine_file' }>
      const inc = this.incidents.find((i) => i.id === a.incident_id)
      return {
        id: uuid(),
        device_id: a.device_id,
        hostname: a.hostname,
        sha256: act.sha256 ?? sha256(),
        original_path: act.path,
        alert_id: inc?.alerts[inc.alerts.length - 1]?.id ?? null,
        state: 'held' as const,
        created_at: a.completed_at ?? a.created_at,
      }
    })
    const extra = [
      ['OPS-DT-015', 'C:\\Users\\kumar.s\\Downloads\\WhatsApp_Setup_crack.exe', 'held', 12],
      ['SAL-LT-017', 'C:\\Users\\rahul.menon\\AppData\\Local\\Temp\\is-3K2L.tmp\\setup.tmp', 'deleted', 20],
      ['MKT-DT-001', 'C:\\Users\\putri.wulandari\\Downloads\\font-pack-installer.exe', 'restored', 8],
    ] as const
    for (const [h, p, st, days] of extra) {
      const d = this.dev(h)
      this.quarantine.push({ id: uuid(), device_id: d.id, hostname: d.hostname, sha256: sha256(), original_path: p, alert_id: null, state: st, created_at: NOW - days * DAY })
    }
    this.quarantine.sort((a, b) => b.created_at - a.created_at)
  }

  private seedReviews() {
    const mk = (host: string, user: string, rule: string, file: string, just: string, state: ReviewRequestRow['state'], ago: number, by?: User): ReviewRequestRow => {
      const d = this.dev(host)
      const alert = this.alerts.find((a) => a.device_id === d.id) ?? this.alerts[0]
      return {
        id: uuid(),
        device_id: d.id,
        hostname: d.hostname,
        user,
        alert_id: alert?.id ?? uuid(),
        rule_name: this.rules.get(rule)?.name ?? rule,
        file,
        justification: just,
        state,
        decided_by: by?.email ?? null,
        decided_at: by ? NOW - ago + 2 * HOUR : null,
        created_at: NOW - ago,
      }
    }
    const pdev = (h: string) => this.dev(h).logged_on_user ?? 'user'
    this.reviews = [
      mk('ENG-LT-024', pdev('ENG-LT-024'), 'ST-12', 'C:\\Users\\…\\Downloads\\wireshark-4.6.0-x64.exe', 'Need Wireshark to debug the WMS barcode scanner traffic. It is the official installer from wireshark.org.', 'requested', 35 * MIN),
      mk('OPS-DT-015', pdev('OPS-DT-015'), 'ST-12', 'C:\\Users\\…\\Downloads\\WhatsApp_Setup_crack.exe', 'I need WhatsApp to talk with drivers', 'requested', 3 * HOUR),
      mk('MKT-DT-001', pdev('MKT-DT-001'), 'ST-12', 'C:\\Users\\…\\Downloads\\font-pack-installer.exe', 'Brand fonts from our agency for the Q4 campaign.', 'approved', 8 * DAY, MARCUS),
      mk('SAL-LT-017', pdev('SAL-LT-017'), 'ST-12', 'C:\\Users\\…\\AppData\\Local\\Temp\\is-3K2L.tmp\\setup.tmp', 'free pdf converter', 'denied', 20 * DAY, AISYAH),
    ]
  }

  private seedEnrollment() {
    this.enrollment = [
      { id: uuid(), group_id: 'grp-sales', group_name: 'Sales', token_prefix: 'kse_7Hq2', created_at: NOW - 20 * DAY, expires_at: NOW + 10 * DAY, max_uses: 50, uses: 5, revoked: false, remote_profile: profileGuarded() },
      { id: uuid(), group_id: 'grp-fin', group_name: 'Finance', token_prefix: 'kse_Lm4x', created_at: NOW - 45 * DAY, expires_at: NOW - 15 * DAY, max_uses: 10, uses: 5, revoked: false, remote_profile: profileNone() },
      { id: uuid(), group_id: 'grp-eng', group_name: 'Engineering', token_prefix: 'kse_p9Za', created_at: NOW - 70 * DAY, expires_at: NOW - 40 * DAY, max_uses: 25, uses: 6, revoked: true, remote_profile: profileUnrestricted() },
      { id: uuid(), group_id: 'grp-it', group_name: 'IT', token_prefix: 'kse_R2tw', created_at: NOW - 6 * DAY, expires_at: NOW + 24 * DAY, max_uses: 20, uses: 3, revoked: false, remote_profile: profileUnrestricted() },
    ]
  }

  private seedTokens() {
    this.apiTokens = [
      { id: uuid(), name: 'Splunk SIEM pull', prefix: 'kst_9fA2', created_at: NOW - 90 * DAY, last_used: NOW - 3 * MIN, privileges: ['read'] },
      { id: uuid(), name: 'Tines SOAR playbooks', prefix: 'kst_Qe71', created_at: NOW - 30 * DAY, last_used: NOW - 2 * DAY, privileges: ['read', 'incidents.write', 'response.network'] },
    ]
  }

  private seedAudit() {
    const evs: [number, User | null, string, string, Record<string, unknown>][] = [
      [NOW - 60 * DAY, PRIYA, 'auth.setup', 'org', { org_name: ORG }],
      [NOW - 60 * DAY + HOUR, PRIYA, 'user.create', DANIEL.email, { role: 'analyst' }],
      [NOW - 60 * DAY + HOUR, PRIYA, 'user.create', AISYAH.email, { role: 'analyst' }],
      [NOW - 59 * DAY, PRIYA, 'settings.update', 'oidc', { enabled: true }],
      [NOW - 40 * DAY, PRIYA, 'exclusion.create', 'AgileBits Inc.', { rule_id: 'ST-01' }],
      [NOW - 30 * DAY, PRIYA, 'api_token.create', 'Tines SOAR playbooks', {}],
      [NOW - 16 * DAY, MARCUS, 'policy.update', 'Engineering (developer friendly)', { version: 6 }],
      [NOW - 9 * DAY, MARCUS, 'policy.update', 'Finance & Executives (strict)', { version: 9, changed: ['hardening.disable_run_dialog'] }],
      [NOW - 4 * DAY, MARCUS, 'exclusion.create', '2BrightSparks Pte Ltd', { rule_id: 'ST-01', expires_in_days: 90 }],
      [NOW - 3 * DAY, PRIYA, 'policy.update', 'Default', { version: 14, changed: ['rules.ST-14'] }],
      [NOW - 26 * HOUR, AISYAH, 'incident.update', 'Credential theft by Invoice_Oct2026.exe on FIN-LT-003', { status: 'resolved' }],
      [NOW - 2 * HOUR, null, 'response.auto', 'SAL-LT-022', { action: 'kill_process', rule: 'ST-04' }],
      [NOW - 2 * HOUR + 20 * MIN, DANIEL, 'device.view_events', 'SAL-LT-022', { reason: 'incident investigation' }],
      [NOW - 2 * HOUR + 21 * MIN, DANIEL, 'response.request', 'SAL-LT-022', { action: 'collect_triage' }],
      [NOW - 25 * MIN, PRIYA, 'auth.login', PRIYA.email, { method: 'oidc' }],
    ]
    for (const [ts, a, act, tgt, det] of evs) this.log(a, act, tgt, det, ts)
  }

  newEnrollmentSecret() {
    const t = `kse_${hexId(4)}${hexId(36)}`
    return t
  }

  randomDevice() {
    return pick(this.devices)
  }

  get privacyDefault() {
    return DEFAULT_PRIVACY_NOTICE
  }
}
