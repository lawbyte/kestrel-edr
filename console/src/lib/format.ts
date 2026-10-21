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

/**
 * C0/C1 controls (incl. tab, CR, LF), DEL, the Arabic letter mark, LRM/RLM and
 * the bidi embedding/override/isolate controls (U+202A–U+202E, U+2066–U+2069).
 */
const UNSAFE_DISPLAY = new RegExp('[' + [[0x00, 0x1f], [0x7f, 0x9f], [0x061c, 0x061c], [0x200e, 0x200f], [0x2028, 0x2029], [0x202a, 0x202e], [0x2066, 0x2069]].map(([a, b]) => `\\u{${a.toString(16)}}-\\u{${b.toString(16)}}`).join('') + ']', 'gu')

/**
 * Endpoint-controlled text (task/service/WMI names, registry paths and data,
 * file paths) made safe to show in confirmations: strips characters that can
 * hide or reorder what the analyst reads (e.g. U+202E "RIGHT-TO-LEFT OVERRIDE"
 * turning `evil<U+202E>txt.exe` into what reads as `evilexe.txt`) and line breaks that could
 * fake extra lines in a dialog.
 */
export function safeDisplay(s: string | null | undefined): string {
  if (s == null) return ''
  return String(s).replace(UNSAFE_DISPLAY, '')
}

export function hex(n: number | undefined): string {
  return n == null ? '—' : `0x${n.toString(16)}`
}
