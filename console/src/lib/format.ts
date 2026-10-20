const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto', style: 'short' })

export function timeAgo(ms: number | null | undefined, now = Date.now()): string {
  if (ms == null) return '—'
  const diff = (ms - now) / 1000
  const abs = Math.abs(diff)
  if (abs < 45) return 'just now'
  if (abs < 3600) return rtf.format(Math.round(diff / 60), 'minute')
  if (abs < 86400) return rtf.format(Math.round(diff / 3600), 'hour')
  if (abs < 86400 * 30) return rtf.format(Math.round(diff / 86400), 'day')
  return formatDate(ms)
}

const dtf = new Intl.DateTimeFormat('en-GB', {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
})
const tf = new Intl.DateTimeFormat('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
const df = new Intl.DateTimeFormat('en-GB', { year: 'numeric', month: 'short', day: '2-digit' })

export function formatDateTime(ms: number | null | undefined): string {
  return ms == null ? '—' : dtf.format(ms)
}
export function formatTime(ms: number | null | undefined): string {
  return ms == null ? '—' : tf.format(ms)
}
export function formatDate(ms: number | null | undefined): string {
  return ms == null ? '—' : df.format(ms)
}
export function formatIso(ms: number): string {
  return new Date(ms).toISOString()
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  if (s < 60) return `${s < 10 ? s.toFixed(1) : Math.round(s)} s`
  const m = s / 60
  if (m < 60) return `${Math.round(m)} min`
  const h = m / 60
  if (h < 48) return `${h < 10 ? h.toFixed(1) : Math.round(h)} h`
  return `${Math.round(h / 24)} d`
}

export function formatBytes(n: number | null | undefined): string {
  if (n == null) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 && i > 0 ? v.toFixed(1) : Math.round(v)} ${u[i]}`
}

export function formatNumber(n: number): string {
  return new Intl.NumberFormat('en').format(n)
}

export function formatUptime(s: number | undefined): string {
  if (!s) return '—'
  return formatDuration(s * 1000)
}

export function shortHash(h: string | null | undefined, n = 12): string {
  if (!h) return '—'
  return h.length > n ? `${h.slice(0, n)}…` : h
}

export function hex(n: number | undefined): string {
  return n == null ? '—' : `0x${n.toString(16)}`
}
