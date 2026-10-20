import type { DeviceEvent, KEvent } from '@/api/types'
import type { HuntRecord } from './hunt'
import { basename } from './utils'
import { hex } from './format'

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
    case 'registry_set':
      return `${e.key}\\${e.value_name}${e.data ? ` = ${e.data}` : ''}`
    case 'net_connect':
      return `${e.proto.toUpperCase()} → ${e.dst_host ? `${e.dst_host} (${e.dst_ip})` : e.dst_ip}:${e.dst_port}${e.bytes_sent ? `, ${e.bytes_sent} bytes sent` : ''}`
    case 'dns_query':
      return `Resolved ${e.qname}${e.answers?.length ? ` → ${e.answers.join(', ')}` : ''}`
    case 'dpapi_unprotect':
      return `Decrypted DPAPI blob "${e.description}"`
    case 'process_access':
      return `Opened ${basename(e.target_image)} (PID ${e.target_pid}) with access ${hex(e.granted_access)}`
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
  }
}

/** Flatten an event into the hunt field namespace. `image` comes from a lookup by guid when the event is not a process start. */
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
  }
  return r
}
