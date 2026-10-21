import type { AgentHealth } from '@/api/types'

function plural(n: number, one: string, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`
}

/**
 * Detail line of the device page's "Events lost" row. Agents from 1.1.6 on
 * split `etw_events_lost` into events Windows (ETW) lost because its buffers
 * were full and events Kestrel's own sensor queues / caps dropped; older
 * agents send only the total.
 */
export function eventsLostDetail(h: Pick<AgentHealth, 'etw_events_lost' | 'etw_buffers_lost' | 'etw_kernel_events_lost' | 'sensor_internal_dropped'>): string {
  const total = h.etw_events_lost ?? 0
  const buffers = plural(h.etw_buffers_lost ?? 0, 'buffer')
  const k = h.etw_kernel_events_lost
  const d = h.sensor_internal_dropped
  if (k == null && d == null) return `${plural(total, 'event')}, ${buffers}`
  const kernel = k ?? Math.max(0, total - (d ?? 0))
  const dropped = d ?? Math.max(0, total - kernel)
  return `${kernel} lost by Windows, ${dropped} dropped by Kestrel; ${buffers}`
}
