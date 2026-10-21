import type {
  ActionOutcome,
  AlertDetail,
  AlertStatus,
  ChecklistItem,
  Classification,
  Comment,
  DataCategory,
  Device,
  EventData,
  FileOp,
  IncidentDetail,
  IncidentStatus,
  Integrity,
  KEvent,
  NetworkRow,
  PauseMode,
  ProcessInfo,
  ResponseAction,
  ResponseActionRow,
  RuleMeta,
  RuleMode,
  Severity,
  SignatureState,
  TimelineEntry,
  TreeNode,
  User,
} from '@/api/types'
import { pathClassOf } from '@/lib/pathclass'
import { DATA_CATEGORY_LABEL, DATA_CATEGORY_REMEDIATION, describeAction, SEVERITY_RANK } from '@/lib/labels'
import { basename } from '@/lib/utils'
import { hexId, int, sha256, uuid } from './rng'

/** Full alert details for each finalized incident (rows only carry AlertRow). */
export const fullAlerts = new WeakMap<IncidentDetail, AlertDetail[]>()

export const SEVERITY_BASE = { info: 5, low: 20, medium: 45, high: 70, critical: 90 } as const

export interface ProcOpts {
  dt: number
  pid?: number
  signer?: string | null
  signed?: SignatureState
  user?: string | null
  exitDt?: number | null
  sha?: string | null
  size?: number | null
  motw?: number | null
  integrity?: Integrity
  /** Do not emit a process_start event (pre-existing process such as explorer.exe). */
  quiet?: boolean
}

export interface AlertOpts {
  data?: DataCategory[]
  evidence?: KEvent[]
  /** Automatic response the agent took (Protect mode), dt relative to the alert. */
  auto?: { action: ResponseAction; ok?: boolean; detail: string; after?: number; artifact?: string }[]
  mode?: RuleMode
  /** Protection was turned off on the device when the alert fired (forced to Audit). */
  protectionOff?: PauseMode
  /** Override the rule's severity (TP-06 is medium for detection only, high for completely off, info for turned back on). */
  severity?: Severity
}

export interface FinalizeOpts {
  status: IncidentStatus
  classification?: Classification | null
  assignee?: User | null
  storyline: string
  contained: boolean
  approve?: { text: string; action: ResponseAction; done?: boolean }[]
  manual?: { text: string; done?: boolean }[]
  comments?: { author: User; body: string; dt: number }[]
  statusChanges?: { dt: number; title: string; actor: string }[]
  updatedDt?: number
  /** Override the computed title (e.g. to name the payload rather than a LOLBin it ran). */
  title?: string
}

export class Story {
  readonly id = uuid()
  nodes: TreeNode[] = []
  procs = new Map<string, ProcessInfo>()
  events: KEvent[] = []
  alerts: AlertDetail[] = []
  network: NetworkRow[] = []
  actions: ResponseActionRow[] = []
  private pidSeed = int(1200, 9000)
  private bootId = hexId(8)

  constructor(
    readonly dev: Device,
    readonly t0: number,
    readonly rules: Map<string, RuleMeta>,
    readonly ruleModes: Record<string, RuleMode>,
  ) {}

  t(dt: number) {
    return this.t0 + dt
  }

  proc(parent: TreeNode | null, image: string, cmdline: string, o: ProcOpts): TreeNode {
    const pid = o.pid ?? (this.pidSeed += int(4, 160) * 4)
    const guid = `${this.bootId}${hexId(24)}`
    const pathClass = pathClassOf(image)
    const isMs = /\\windows\\/i.test(image)
    const signed: SignatureState = o.signed ?? (isMs || pathClass === 'program_files' ? 'valid' : 'unsigned')
    const signer = o.signer !== undefined ? o.signer : signed === 'valid' ? (isMs ? 'Microsoft Windows' : null) : null
    const user = o.user !== undefined ? o.user : this.dev.logged_on_user
    const node: TreeNode = {
      guid,
      parent_guid: parent?.guid ?? null,
      pid,
      image,
      cmdline,
      user,
      start_ts: this.t(o.dt),
      exit_ts: o.exitDt != null ? this.t(o.exitDt) : null,
      signer,
      signed,
      sha256: o.sha ?? sha256(),
      path_class: pathClass,
      alert_rule_ids: [],
      is_root: parent == null,
    }
    this.nodes.push(node)
    const info: ProcessInfo = {
      guid,
      pid,
      ppid: parent?.pid ?? 4,
      parent_guid: parent?.guid ?? null,
      image,
      cmdline,
      user,
      integrity: o.integrity ?? 'medium',
      start_ts: node.start_ts,
      exit_ts: node.exit_ts,
      signer,
      signed,
      sha256: node.sha256,
      motw_zone: o.motw ?? null,
      file_size: o.size ?? int(180_000, 9_000_000),
      path_class: pathClass,
    }
    this.procs.set(guid, info)
    if (!o.quiet) {
      this.events.push({
        ts: node.start_ts,
        pid,
        guid,
        type: 'process_start',
        ppid: info.ppid,
        parent_guid: info.parent_guid,
        image,
        cmdline,
        user,
        integrity: info.integrity,
        session_id: 1,
        signer,
        signed,
        sha256: node.sha256,
        motw_zone: info.motw_zone,
        file_size: info.file_size,
      })
    }
    if (o.exitDt != null) this.events.push({ ts: this.t(o.exitDt), pid, guid, type: 'process_stop', exit_code: o.exitDt ? 1 : 0 })
    return node
  }

  ev(n: TreeNode, dt: number, data: EventData): KEvent {
    const e = { ts: this.t(dt), pid: n.pid, guid: n.guid, ...data } as KEvent
    this.events.push(e)
    return e
  }

  file(n: TreeNode, dt: number, path: string, op: FileOp = 'read'): KEvent {
    return this.ev(n, dt, { type: 'file_access', path, op })
  }

  dns(n: TreeNode, dt: number, qname: string, answers: string[]): KEvent {
    return this.ev(n, dt, { type: 'dns_query', qname, answers })
  }

  connect(n: TreeNode, dt: number, ip: string, port: number, host: string | null, o: { blocked?: boolean; bytes?: number } = {}): KEvent {
    const e = this.ev(n, dt, {
      type: 'net_connect',
      proto: 'tcp',
      dst_ip: ip,
      dst_port: port,
      src_port: int(49152, 65000),
      dst_host: host,
      bytes_sent: o.bytes ?? null,
    })
    this.network.push({ ts: e.ts, process_guid: n.guid, image: n.image, dst_ip: ip, dst_port: port, dst_host: host, blocked: !!o.blocked })
    return e
  }

  alert(n: TreeNode, dt: number, ruleId: string, summary: string, o: AlertOpts = {}): AlertDetail {
    const meta = this.rules.get(ruleId)
    if (!meta) throw new Error(`unknown rule ${ruleId}`)
    const mode = o.protectionOff ? 'audit' : (o.mode ?? this.ruleModes[ruleId] ?? meta.default_mode)
    const ts = this.t(dt)
    const outcomes: ActionOutcome[] = (o.auto ?? []).map((a) => ({ action: a.action, ok: a.ok ?? true, detail: a.detail, ts: ts + (a.after ?? 400), artifact: a.artifact ?? null }))
    for (const out of outcomes) {
      this.actions.push({
        id: uuid(),
        device_id: this.dev.id,
        hostname: this.dev.hostname,
        incident_id: this.id,
        action: out.action,
        status: out.ok ? 'succeeded' : 'failed',
        requested_by: null,
        comment: `Automatic: ${ruleId} in Protect mode`,
        created_at: out.ts - 120,
        completed_at: out.ts,
        result_detail: out.detail ?? '',
        artifact: out.artifact ?? null,
      })
    }
    const ancestry: ProcessInfo[] = []
    let cur = n.parent_guid ? this.procs.get(n.parent_guid) : undefined
    while (cur && ancestry.length < 6) {
      ancestry.push(cur)
      cur = cur.parent_guid ? this.procs.get(cur.parent_guid) : undefined
    }
    const a: AlertDetail = {
      id: uuid(),
      ts,
      rule_id: ruleId,
      rule_name: meta.name,
      rule_author: meta.kind === 'builtin' ? null : (meta.author ?? null),
      severity: o.severity ?? meta.severity,
      attack: meta.attack ?? [],
      mode,
      summary,
      process: this.procs.get(n.guid)!,
      ancestry,
      data_at_risk: o.data ?? [],
      evidence: o.evidence ?? [],
      actions: outcomes,
      incident_id: this.id,
      device_id: this.dev.id,
      hostname: this.dev.hostname,
      status: 'new',
      ...(o.protectionOff ? { protection_off: o.protectionOff } : {}),
    }
    if (!n.alert_rule_ids.includes(ruleId)) n.alert_rule_ids.push(ruleId)
    this.alerts.push(a)
    return a
  }

  manualAction(dt: number, by: User, action: ResponseAction, comment: string, detail: string, status: ResponseActionRow['status'] = 'succeeded') {
    const ts = this.t(dt)
    this.actions.push({
      id: uuid(),
      device_id: this.dev.id,
      hostname: this.dev.hostname,
      incident_id: this.id,
      action,
      status,
      requested_by: by,
      comment,
      created_at: ts,
      completed_at: status === 'succeeded' || status === 'failed' ? ts + int(2000, 9000) : null,
      result_detail: detail,
    })
  }

  finalize(o: FinalizeOpts): IncidentDetail {
    const alerts = [...this.alerts].sort((a, b) => a.ts - b.ts)
    const sev = alerts.reduce((m, a) => (SEVERITY_RANK[a.severity] > SEVERITY_RANK[m] ? a.severity : m), alerts[0].severity)
    const data = Array.from(new Set(alerts.flatMap((a) => a.data_at_risk ?? [])))
    const ruleIds = Array.from(new Set(alerts.map((a) => a.rule_id)))
    const attack = Array.from(new Set(alerts.flatMap((a) => a.attack ?? [])))
    // Impact stage (+10): exfiltration-stage stealer rules, any ransomware or credential-dumping rule.
    const exfil = ruleIds.some((r) => r === 'ST-04' || r === 'ST-14' || r.startsWith('RW-') || r.startsWith('CD-'))
    const priority = Math.min(100, SEVERITY_BASE[sev] + (data.length ? 10 : 0) + (exfil ? 10 : 0) + (o.contained ? 0 : 5))
    const alertStatus: AlertStatus = o.status === 'resolved' || o.status === 'dismissed' ? 'closed' : o.status === 'in_progress' ? 'acknowledged' : 'new'
    for (const a of alerts) a.status = alertStatus

    const top = alerts.find((a) => a.severity === sev) ?? alerts[0]
    const actor = basename(top.process.image)
    const cats = new Set(alerts.map((a) => this.rules.get(a.rule_id)?.category))
    const title = cats.has('ransomware')
      ? `Ransomware activity by ${actor} on ${this.dev.hostname}`
      : cats.has('tripwire')
      ? `Canary tripped by ${actor} on ${this.dev.hostname}`
      : cats.has('credential_dumping')
        ? `Credential dumping by ${actor} on ${this.dev.hostname}`
      : cats.has('persistence')
        ? `Persistence planted by ${actor} on ${this.dev.hostname}`
      : cats.has('tamper')
        ? `Agent tamper attempt on ${this.dev.hostname}`
        : cats.has('exfiltration') || cats.has('credential_access')
          ? `Credential theft by ${actor} on ${this.dev.hostname}`
          : cats.has('browser_tampering')
            ? `Browser tampering by ${actor} on ${this.dev.hostname}`
            : `Suspicious execution of ${actor} on ${this.dev.hostname}`

    const checklist: ChecklistItem[] = []
    for (const act of this.actions.filter((x) => x.requested_by == null && x.status === 'succeeded')) {
      const backup = act.action.type === 'remove_autorun' && act.artifact ? ` (backup ${act.artifact} in the quarantine vault)` : ''
      checklist.push({ id: hexId(8), kind: 'done', text: `${describeAction(act.action)}${backup} — done automatically by the agent`, done: true, action: act.action })
    }
    for (const ap of o.approve ?? []) checklist.push({ id: hexId(8), kind: 'approve', text: ap.text, done: !!ap.done, action: ap.action })
    const who = this.dev.logged_on_user?.split('\\').pop() ?? 'the user'
    for (const c of data) {
      if (c === 'browser_master_key' && data.includes('browser_cookies')) continue
      checklist.push({
        id: hexId(8),
        kind: 'manual',
        text: `${DATA_CATEGORY_LABEL[c]}: ${DATA_CATEGORY_REMEDIATION[c]} (${who})`,
        done: o.status === 'resolved',
      })
    }
    for (const m of o.manual ?? []) checklist.push({ id: hexId(8), kind: 'manual', text: m.text, done: !!m.done })

    const comments: Comment[] = (o.comments ?? []).map((c) => ({ id: uuid(), author: c.author, body: c.body, ts: this.t(c.dt) }))
    const timeline: TimelineEntry[] = [
      ...alerts.map((a) => ({ ts: a.ts, kind: 'alert' as const, title: `${a.rule_id} ${a.rule_name}`, detail: a.summary, actor: null })),
      ...this.actions.map((a) => ({
        ts: a.completed_at ?? a.created_at,
        kind: 'action' as const,
        title: describeAction(a.action),
        detail: a.result_detail || a.comment,
        actor: a.requested_by?.name ?? 'Kestrel agent',
      })),
      ...comments.map((c) => ({ ts: c.ts, kind: 'comment' as const, title: 'Comment', detail: c.body, actor: c.author.name })),
      ...(o.statusChanges ?? []).map((s) => ({ ts: this.t(s.dt), kind: 'status' as const, title: s.title, detail: '', actor: s.actor })),
    ].sort((a, b) => a.ts - b.ts)

    const lastTs = Math.max(...timeline.map((x) => x.ts), this.t(o.updatedDt ?? 0))
    const createdAt = alerts[0].ts
    const inc: IncidentDetail = {
      id: this.id,
      title: o.title ?? title,
      severity: sev,
      priority,
      status: o.status,
      classification: o.classification ?? null,
      assignee: o.assignee ?? null,
      device_id: this.dev.id,
      hostname: this.dev.hostname,
      user: this.dev.logged_on_user,
      created_at: createdAt,
      updated_at: lastTs,
      alert_count: alerts.length,
      rule_ids: ruleIds,
      attack,
      data_at_risk: data,
      contained: o.contained,
      storyline: o.storyline,
      alerts: alerts.map(toAlertRow),
      process_tree: this.nodes,
      timeline,
      evidence: [...this.events].sort((a, b) => a.ts - b.ts).slice(0, 200),
      network: this.network,
      actions: this.actions,
      checklist,
      comments,
    }
    fullAlerts.set(inc, alerts)
    return inc
  }
}

export function toAlertRow(a: AlertDetail) {
  return {
    id: a.id,
    incident_id: a.incident_id,
    device_id: a.device_id,
    hostname: a.hostname,
    ts: a.ts,
    rule_id: a.rule_id,
    rule_name: a.rule_name,
    rule_author: a.rule_author ?? null,
    severity: a.severity,
    attack: a.attack ?? [],
    mode: a.mode,
    summary: a.summary,
    process_guid: a.process.guid,
    image: a.process.image,
    data_at_risk: a.data_at_risk ?? [],
    actions: a.actions ?? [],
    status: a.status,
    protection_off: a.protection_off ?? null,
  }
}
