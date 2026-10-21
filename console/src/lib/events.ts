import type { DeviceEvent, FileActivity, KEvent, ServiceInstall, TaskChange } from '@/api/types'
import type { HuntRecord } from './hunt'
import { basename } from './utils'
import { formatDuration, hex } from './format'

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

/** "Renamed 412 files in 37 folders within 10 s, new extension .k3str (95%)" plus note / canary / share clauses. */
export function describeFileActivity(f: FileActivity): string {
  const renames = f.renames ?? 0
  const overwrites = f.overwrites ?? 0
  const created = f.new_files ?? 0
  const [verb, n] =
    renames > 0 && renames >= overwrites && renames >= created
      ? ['Renamed', renames]
      : overwrites > 0 && overwrites >= created
        ? ['Overwrote', overwrites]
        : ['Changed', f.files_touched]
  const parts = [`${verb} ${plural(n, 'file')} in ${plural(f.dirs, 'folder')} within ${formatDuration(f.window_ms)}`]
  if (f.top_new_ext) parts.push(`new extension .${f.top_new_ext}${f.top_ext_pct ? ` (${Math.min(100, f.top_ext_pct)}%)` : ''}`)
  if (f.net_paths) parts.push(`${f.net_paths} on network shares`)
  let s = parts.join(', ')
  if (f.note_name) s += `; created ${f.note_name} in ${plural(f.note_dirs ?? 0, 'folder')}`
  if (f.canary_hits?.length) s += `; touched ${plural(f.canary_hits.length, 'canary file')}${f.canary_in_place ? ' (in-place write found by polling, writer inferred)' : ''}`
  if (f.remote_writer) s += '; written by a remote client over SMB'
  return s
}

export function describeTask(t: TaskChange): string {
  const verb = t.op === 'created' ? 'Created' : t.op === 'updated' ? 'Changed' : 'Deleted'
  const flags = [t.hidden ? 'hidden' : null, t.triggers?.length ? `at ${t.triggers.join('/')}` : null, t.user ? `as ${t.user}` : null].filter(Boolean)
  const run = t.actions?.length ? ` → ${t.actions.join(' ; ')}` : ''
  return `${verb} task ${t.name}${flags.length ? ` (${flags.join(', ')})` : ''}${run}`
}

const START_TYPE: Record<number, string> = { 0: 'boot start', 1: 'system start', 2: 'auto start', 3: 'manual start', 4: 'disabled' }

export function describeService(s: ServiceInstall): string {
  const flags = [s.service_type === 1 ? 'kernel driver' : null, s.start_type != null ? (START_TYPE[s.start_type] ?? `start ${s.start_type}`) : null, s.account ? `as ${s.account}` : null].filter(Boolean)
  return `Installed service ${s.name}${flags.length ? ` (${flags.join(', ')})` : ''} → ${s.image_path}`
}

export type ProvenanceKind = 'writer_inferred' | 'writer_unknown' | 'remote_smb' | 'canary_polled' | 'agent_spawned'
export interface Provenance {
  kind: ProvenanceKind
  label: string
  tip: string
}

export const PROVENANCE_INFO: Record<ProvenanceKind, Omit<Provenance, 'kind'>> = {
  writer_inferred: {
    label: 'writer inferred',
    tip: 'The acting process was inferred by correlation, not reported by the kernel. Kestrel never kills on it; it may still remove the persistence entry itself.',
  },
  writer_unknown: {
    label: 'writer unknown',
    tip: 'No acting process could be determined for this change. Kestrel never kills on it; it may still remove the persistence entry itself.',
  },
  remote_smb: {
    label: 'remote client over SMB',
    tip: 'The writes came through the System process from another machine over a file share. No local process is blamed; investigate the client that has this share mapped.',
  },
  canary_polled: {
    label: 'decoy write found by polling',
    tip: 'The decoy file was changed in place and found by content polling, so the writer is inferred (the last process seen opening it for writing), not reported by the kernel. Kestrel never kills on it.',
  },
  agent_spawned: {
    label: 'started by Kestrel',
    tip: 'The Kestrel agent itself started this process (hardening PowerShell, a scan or an update installer). Rules treat it as Kestrel’s own work.',
  },
}

/**
 * How trustworthy the acting process of an event is, as badges to show next to
 * it. Exact (or absent: older agents) attribution yields nothing.
 */
export function eventProvenance(e: KEvent): Provenance[] {
  const out: ProvenanceKind[] = []
  switch (e.type) {
    case 'process_start':
      if (e.agent_spawned) out.push('agent_spawned')
      break
    case 'registry_set':
    case 'task_registered':
    case 'service_installed':
    case 'wmi_subscription':
      if (e.attribution === 'heuristic') out.push('writer_inferred')
      else if (e.attribution === 'none') out.push('writer_unknown')
      break
    case 'file_activity':
      if (e.remote_writer) out.push('remote_smb')
      if (e.canary_in_place && e.canary_hits?.length) out.push('canary_polled')
      break
  }
  return out.map((kind) => ({ kind, ...PROVENANCE_INFO[kind] }))
}

/**
 * Mark tree nodes whose `process_start` event (in `events`) says the Kestrel
 * agent started them. The server's tree rows don't carry the flag (yet), so the
 * console derives it from the incident evidence. Returns the same array when
 * nothing changes.
 */
export function withAgentSpawned<T extends { guid: string; agent_spawned?: boolean }>(nodes: T[], events: KEvent[]): T[] {
  const spawned = new Set(events.filter((e) => e.type === 'process_start' && e.agent_spawned).map((e) => e.guid))
  if (!spawned.size) return nodes
  return nodes.map((n) => (spawned.has(n.guid) && !n.agent_spawned ? { ...n, agent_spawned: true } : n))
}

/** NTSTATUS values worth naming in the UI. */
const NTSTATUS: Record<number, string> = {
  0xc0000022: 'access denied',
  0xc0000005: 'access violation',
  0xc000000d: 'invalid parameter',
}

/** One-line, human-readable description of an event. */
export function describeEvent(e: KEvent): string {
  switch (e.type) {
    case 'process_start':
      return e.cmdline || e.image
    case 'process_stop':
      return `Exited${e.exit_code != null ? ` with code ${e.exit_code}` : ''}`
    case 'image_load':
      return `Loaded ${e.path}`
    case 'file_access':
      return `${e.op[0].toUpperCase()}${e.op.slice(1)} ${e.path}`
    case 'registry_set': {
      const at = e.value_name ? `${e.key}\\${e.value_name}` : e.key
      if (e.op === 'delete_value') return `Deleted value ${at}`
      if (e.op === 'delete_key') return `Deleted key ${e.key}`
      return `${at}${e.data ? ` = ${e.data}` : ''}`
    }
    case 'net_connect':
      return `${e.proto.toUpperCase()} → ${e.dst_host ? `${e.dst_host} (${e.dst_ip})` : e.dst_ip}:${e.dst_port}${e.bytes_sent ? `, ${e.bytes_sent} bytes sent` : ''}`
    case 'dns_query':
      return `Resolved ${e.qname}${e.answers?.length ? ` → ${e.answers.join(', ')}` : ''}`
    case 'dpapi_unprotect':
      return `Decrypted DPAPI blob "${e.description}"`
    case 'process_access': {
      const base = `Opened ${basename(e.target_image)} (PID ${e.target_pid}) with access ${hex(e.granted_access)}`
      if (!e.return_code) return base
      const rc = e.return_code >>> 0
      return `${base} — refused by Windows (${hex(rc)}${NTSTATUS[rc] ? ` ${NTSTATUS[rc]}` : ''})`
    }
    case 'remote_thread':
      return `Created a thread inside ${basename(e.target_image)} (PID ${e.target_pid})`
    case 'thread_context':
      return `Set thread context in ${basename(e.target_image)} (PID ${e.target_pid})`
    case 'debug_attach':
      return `Attached debugger to ${basename(e.target_image)} (PID ${e.target_pid})`
    case 'script_block':
      return `${e.engine}: ${e.content.slice(0, 160)}`
    case 'tamper':
      return `${e.kind.replace(/_/g, ' ')}: ${e.detail}`
    case 'file_activity':
      return describeFileActivity(e)
    case 'task_registered':
      return describeTask(e)
    case 'service_installed':
      return describeService(e)
    case 'wmi_subscription':
      return `WMI subscription in ${e.namespace}: ${e.filter} → ${e.consumer}`
  }
}

/** Flatten an event into the hunt field namespace (mirrors the server's column mapping in docs/contracts.md). `image` comes from a lookup by guid when the event is not a process start. */
export function toHuntRecord(e: DeviceEvent, ctx: { image?: string; user?: string | null; signer?: string | null; sha256?: string | null; hostname?: string } = {}): HuntRecord {
  const r: HuntRecord = {
    event_type: e.type,
    device_id: e.device_id,
    hostname: e.hostname ?? ctx.hostname,
    image: ctx.image,
    user: ctx.user ?? undefined,
    signer: ctx.signer ?? undefined,
    sha256: ctx.sha256 ?? undefined,
  }
  switch (e.type) {
    case 'process_start':
      r.image = e.image
      r.cmdline = e.cmdline
      r.user = e.user ?? r.user
      r.signer = e.signer ?? r.signer
      r.sha256 = e.sha256 ?? r.sha256
      break
    case 'file_access':
      r.file_path = e.path
      r.op = e.op
      break
    case 'image_load':
      r.file_path = e.path
      break
    case 'net_connect':
      r.dst_ip = e.dst_ip
      r.dst_port = e.dst_port
      r.dns_qname = e.dst_host ?? undefined
      break
    case 'dns_query':
      r.dns_qname = e.qname
      break
    case 'registry_set':
      r.reg_key = e.key
      r.reg_value = e.value_name
      r.op = e.op ?? 'set'
      r.cmdline = e.data ?? undefined
      break
    case 'process_access':
    case 'remote_thread':
    case 'thread_context':
    case 'debug_attach':
      r.target_image = e.target_image
      r.granted_access = e.granted_access ?? 0
      r.return_code = e.type === 'process_access' ? (e.return_code ?? 0) : 0
      break
    case 'file_activity':
      r.file_path = e.canary_hits?.[0] ?? e.sample_paths?.[0]
      r.op = 'activity'
      r.new_ext = e.top_new_ext ?? undefined
      break
    case 'task_registered':
      r.file_path = e.name
      r.op = e.op
      r.cmdline = (e.actions ?? []).join(' | ')
      r.user = e.user ?? r.user
      break
    case 'service_installed':
      r.reg_key = `HKLM\\SYSTEM\\CurrentControlSet\\Services\\${e.name}`
      r.file_path = e.image_path
      r.cmdline = e.image_path
      r.op = 'install'
      r.user = e.account ?? r.user
      break
    case 'wmi_subscription':
      r.reg_key = `${e.namespace}\\${e.filter}`
      r.cmdline = e.consumer
      r.op = 'bind'
      break
  }
  return r
}
