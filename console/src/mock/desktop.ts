/**
 * Mock remote-desktop WebSocket for `npm run dev:mock`: implements the same
 * interface the console uses on a real WebSocket and streams a test-pattern
 * "desktop" as binary frames (16-byte header + JPEG) at ~5 fps. The mouse
 * position from `input` messages is echoed as a crosshair, key presses and
 * clicks are shown, and `settings` / `stop` / `ping` are honoured.
 */
import type { DesktopSocket } from '@/api/remote'
import type { DesktopClientMsg, DesktopServerMsg, InputEvent } from '@/api/types'
import { buildFrame } from '@/lib/remote-desktop'
import type { Device } from '@/api/types'
import { consentTimeout } from '@/lib/remote-profile'
import { desktopSessions } from './remote-state'
import { CONSENT_DELAY_MS, db, remoteGuard } from './server'

const SCREEN_W = 1920
const SCREEN_H = 1080
const MOCK_FPS = 5

type Canvas2D = OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D

export class MockDesktopSocket implements DesktopSocket {
  readyState = 0
  binaryType: BinaryType = 'arraybuffer'
  onopen: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null

  private deviceId: string
  private hostname = ''
  private viewOnly: boolean
  private quality: number
  private scale: number
  private reason: string
  private seq = 0
  private timer: ReturnType<typeof setInterval> | null = null
  private encoding = false
  private mouse = { x: 0.5, y: 0.5 }
  private lastKey = ''
  private clicks: { x: number; y: number; at: number; button: string }[] = []
  private typed = ''
  private adminName = 'Admin'
  private forcedViewOnly = false
  private controlAsk: ReturnType<typeof setTimeout> | null = null
  /** Mock employee: denies when the admin's reason contains "deny" (to demo the denial path), else allows after ~2 s. */
  private denies() {
    return /deny/i.test(this.reason)
  }
  private consent = 0

  constructor(url: string) {
    const u = new URL(url, 'http://mock.local')
    this.deviceId = decodeURIComponent(u.pathname.split('/').at(-2) ?? '')
    this.viewOnly = /^(1|true)$/.test(u.searchParams.get('view_only') ?? '')
    this.quality = Number(u.searchParams.get('quality') ?? 60)
    this.scale = Number(u.searchParams.get('scale') ?? 100)
    this.reason = u.searchParams.get('reason') ?? ''
    setTimeout(() => this.open(), 250)
  }

  private open() {
    let d: Device | null = null
    try {
      const g = remoteGuard(this.deviceId, 'desktop', 'read', this.reason)
      d = g.d
      this.forcedViewOnly = g.eff.desktop === 'view_only'
      this.consent = g.eff.guardrails.require_consent ? consentTimeout(g.eff.guardrails) : 0
      if (this.forcedViewOnly) this.viewOnly = true
    } catch {
      d = null
    }
    if (!d || desktopSessions.has(this.deviceId) || !db.session) {
      // A real server answers with an HTTP error before the upgrade; the browser only sees a failed socket.
      this.readyState = 3
      this.onerror?.(new Event('error'))
      this.onclose?.(new CloseEvent('close', { code: 1006, reason: '', wasClean: false }))
      return
    }
    this.hostname = d.hostname
    this.adminName = db.session.name
    const session_id = crypto.randomUUID()
    desktopSessions.set(this.deviceId, { session_id, admin_email: db.session.email, admin_name: db.session.name, view_only: this.viewOnly, started_at: Date.now() })
    db.log(db.session, 'remote.desktop.start', d.id, { hostname: d.hostname, session_id, view_only: this.viewOnly, reason: this.reason, ok: true })
    this.readyState = 1
    this.onopen?.(new Event('open'))
    this.emit({ type: 'starting', session_id, view_only: this.viewOnly })
    if (this.consent) this.emit({ type: 'consent_pending', timeout_secs: this.consent })
    setTimeout(() => {
      if (this.readyState !== 1) return
      if (this.consent && this.denies()) {
        this.emit({ type: 'consent_result', allowed: false, code: 'consent_denied' })
        this.emit({ type: 'ended', reason: 'the employee denied the session', code: 'consent_denied' })
        this.close(1000, 'consent_denied')
        return
      }
      if (this.consent) this.emit({ type: 'consent_result', allowed: true, code: null })
      this.emit({ type: 'started', width: SCREEN_W, height: SCREEN_H, monitors: 1, session_id: 1, secure_desktop: false, view_only: this.viewOnly })
      this.timer = setInterval(() => void this.frame(), 1000 / MOCK_FPS)
      void this.frame()
    }, this.consent ? CONSENT_DELAY_MS : 450)
  }

  private emit(m: DesktopServerMsg) {
    if (this.readyState !== 1) return
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(m) }))
  }

  send(data: string) {
    if (this.readyState !== 1) return
    let m: DesktopClientMsg
    try {
      m = JSON.parse(data) as DesktopClientMsg
    } catch {
      return
    }
    switch (m.type) {
      case 'input':
        if (!this.viewOnly) this.input(m.event)
        break
      case 'settings':
        this.quality = m.quality
        this.scale = m.scale_pct
        if (m.view_only === false && this.forcedViewOnly) {
          this.emit({ type: 'error', message: 'This device only allows view-only remote desktop.' })
        } else if (m.view_only === false && this.viewOnly && this.consent) {
          // Switching to control on a consent profile: ask the (mock) employee first; stay view-only meanwhile.
          if (this.controlAsk) break
          this.emit({ type: 'consent_pending', timeout_secs: this.consent })
          this.controlAsk = setTimeout(() => {
            this.controlAsk = null
            if (this.readyState !== 1) return
            if (this.denies()) {
              this.emit({ type: 'consent_result', allowed: false, code: 'consent_denied' })
              return
            }
            this.emit({ type: 'consent_result', allowed: true, code: null })
            this.viewOnly = false
            const s = desktopSessions.get(this.deviceId)
            if (s) s.view_only = false
            this.emit({ type: 'info', width: SCREEN_W, height: SCREEN_H, monitors: 1, session_id: 1, secure_desktop: false, view_only: false })
          }, CONSENT_DELAY_MS)
        } else if (m.view_only != null && m.view_only !== this.viewOnly) {
          this.viewOnly = m.view_only
          const s = desktopSessions.get(this.deviceId)
          if (s) s.view_only = m.view_only
          this.emit({ type: 'info', width: SCREEN_W, height: SCREEN_H, monitors: 1, session_id: 1, secure_desktop: false, view_only: this.viewOnly })
        }
        break
      case 'ping':
        this.emit({ type: 'pong' })
        break
      case 'stop':
        this.emit({ type: 'ended', reason: 'admin', code: null })
        this.close(1000, 'admin')
        break
      default:
        break
    }
  }

  private input(e: InputEvent) {
    switch (e.kind) {
      case 'mouse_move':
        this.mouse = { x: e.x, y: e.y }
        break
      case 'mouse_button':
        this.mouse = { x: e.x, y: e.y }
        if (e.down) this.clicks = [...this.clicks.slice(-4), { x: e.x, y: e.y, at: Date.now(), button: e.button }]
        break
      case 'mouse_wheel':
        this.mouse = { x: e.x, y: e.y }
        this.lastKey = `wheel ${e.delta_y > 0 ? 'up' : 'down'} ${Math.abs(e.delta_y)}`
        break
      case 'key':
        if (e.down) this.lastKey = e.code
        break
      case 'text':
        this.typed = (this.typed + e.text).slice(-60)
        break
      case 'ctrl_alt_del':
        this.lastKey = 'Ctrl+Alt+Del (secure attention sequence)'
        break
      case 'release_all':
        break
    }
  }

  close(code = 1000, reason = '') {
    if (this.readyState === 3) return
    const wasOpen = this.readyState === 1
    if (this.timer) clearInterval(this.timer)
    if (this.controlAsk) clearTimeout(this.controlAsk)
    this.timer = null
    this.readyState = 3
    if (wasOpen) {
      const s = desktopSessions.get(this.deviceId)
      desktopSessions.delete(this.deviceId)
      if (s && db.session) db.log(db.session, 'remote.desktop.stop', this.deviceId, { hostname: this.hostname, session_id: s.session_id, duration_ms: Date.now() - s.started_at, ended_by: 'admin', ok: true })
    }
    setTimeout(() => this.onclose?.(new CloseEvent('close', { code, reason, wasClean: true })), 0)
  }

  private async frame() {
    if (this.encoding || this.readyState !== 1) return
    this.encoding = true
    try {
      const w = Math.max(2, Math.round((SCREEN_W * this.scale) / 100))
      const h = Math.max(2, Math.round((SCREEN_H * this.scale) / 100))
      const blob = await renderPattern(w, h, (ctx) => this.draw(ctx, w, h), this.quality / 100)
      if (!blob || this.readyState !== 1) return
      const jpeg = new Uint8Array(await blob.arrayBuffer())
      this.seq += 1
      const buf = buildFrame({ seq: this.seq, width: w, height: h, ts: Date.now() - 40 }, jpeg)
      this.onmessage?.(new MessageEvent('message', { data: buf }))
    } finally {
      this.encoding = false
    }
  }

  private draw(ctx: Canvas2D, w: number, h: number) {
    const s = w / SCREEN_W
    const t = Date.now()
    // Wallpaper
    const g = ctx.createLinearGradient(0, 0, w, h)
    g.addColorStop(0, '#0f2a3d')
    g.addColorStop(1, '#1d4e5f')
    ctx.fillStyle = g
    ctx.fillRect(0, 0, w, h)
    // SMPTE-style colour bars (test pattern)
    const bars = ['#c0c0c0', '#c0c000', '#00c0c0', '#00c000', '#c000c0', '#c00000', '#0000c0']
    const bx = 80 * s
    const by = 140 * s
    const bw = 760 * s
    const bh = 300 * s
    bars.forEach((c, i) => {
      ctx.fillStyle = c
      ctx.fillRect(bx + (i * bw) / bars.length, by, bw / bars.length + 1, bh)
    })
    for (let i = 0; i < 16; i++) {
      const v = Math.round((i / 15) * 255)
      ctx.fillStyle = `rgb(${v},${v},${v})`
      ctx.fillRect(bx + (i * bw) / 16, by + bh, bw / 16 + 1, 40 * s)
    }
    // Grid
    ctx.strokeStyle = 'rgba(255,255,255,0.06)'
    ctx.lineWidth = 1
    for (let x = 0; x < w; x += 120 * s) {
      ctx.beginPath()
      ctx.moveTo(x, 0)
      ctx.lineTo(x, h)
      ctx.stroke()
    }
    for (let y = 0; y < h; y += 120 * s) {
      ctx.beginPath()
      ctx.moveTo(0, y)
      ctx.lineTo(w, y)
      ctx.stroke()
    }
    // A "window"
    const wx = 980 * s
    const wy = 140 * s
    const ww = 840 * s
    const wh = 560 * s
    ctx.fillStyle = '#f3f4f6'
    ctx.fillRect(wx, wy, ww, wh)
    ctx.fillStyle = '#e5e7eb'
    ctx.fillRect(wx, wy, ww, 44 * s)
    ctx.fillStyle = '#111827'
    ctx.font = `${Math.round(20 * s)}px "Segoe UI", system-ui, sans-serif`
    ctx.fillText('Kestrel mock desktop — test pattern', wx + 18 * s, wy + 29 * s)
    ctx.font = `${Math.round(22 * s)}px "IBM Plex Mono", ui-monospace, monospace`
    const lines = [
      `Host        ${this.hostname}`,
      `Frame       #${this.seq + 1}`,
      `Time        ${new Date(t).toLocaleTimeString()}`,
      `Mode        ${this.viewOnly ? 'view only' : 'control'}`,
      `Quality     ${this.quality}   Scale ${this.scale}%`,
      `Pointer     ${this.mouse.x.toFixed(3)}, ${this.mouse.y.toFixed(3)}`,
      `Last input  ${this.lastKey || '—'}`,
      `Typed       ${this.typed || '—'}`,
    ]
    lines.forEach((l, i) => ctx.fillText(l, wx + 24 * s, wy + (96 + i * 50) * s))
    // Moving marker so frame updates are visible
    const phase = ((t / 4000) % 1) * Math.PI * 2
    ctx.fillStyle = '#f59e0b'
    ctx.beginPath()
    ctx.arc(bx + bw / 2 + Math.cos(phase) * 300 * s, 640 * s + Math.sin(phase) * 90 * s, 22 * s, 0, Math.PI * 2)
    ctx.fill()
    // Taskbar
    ctx.fillStyle = 'rgba(17,24,39,0.92)'
    ctx.fillRect(0, h - 56 * s, w, 56 * s)
    ctx.fillStyle = '#e5e7eb'
    ctx.font = `${Math.round(18 * s)}px "Segoe UI", system-ui, sans-serif`
    ctx.fillText(new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), w - 110 * s, h - 22 * s)
    // Employee banner (what the agent shows on the real screen)
    ctx.fillStyle = '#b45309'
    ctx.fillRect(w / 2 - 430 * s, 0, 860 * s, 40 * s)
    ctx.fillStyle = '#ffffff'
    ctx.font = `600 ${Math.round(18 * s)}px "Segoe UI", system-ui, sans-serif`
    const banner = `IT (${this.adminName}) is ${this.viewOnly ? 'viewing' : 'controlling'} this PC${this.reason ? ` — ${this.reason}` : ''}`
    ctx.fillText(banner.slice(0, 80), w / 2 - 410 * s, 27 * s)
    // Click ripples
    for (const c of this.clicks) {
      const age = (t - c.at) / 1000
      if (age > 1.5) continue
      ctx.strokeStyle = `rgba(56,189,248,${1 - age / 1.5})`
      ctx.lineWidth = 3 * s
      ctx.beginPath()
      ctx.arc(c.x * w, c.y * h, (10 + age * 40) * s, 0, Math.PI * 2)
      ctx.stroke()
    }
    // Crosshair at the admin's pointer
    const mx = this.mouse.x * w
    const my = this.mouse.y * h
    ctx.strokeStyle = '#ef4444'
    ctx.lineWidth = 2 * s
    ctx.beginPath()
    ctx.moveTo(mx - 24 * s, my)
    ctx.lineTo(mx + 24 * s, my)
    ctx.moveTo(mx, my - 24 * s)
    ctx.lineTo(mx, my + 24 * s)
    ctx.stroke()
  }
}

async function renderPattern(w: number, h: number, draw: (ctx: Canvas2D) => void, quality: number): Promise<Blob | null> {
  if (typeof OffscreenCanvas !== 'undefined') {
    const c = new OffscreenCanvas(w, h)
    const ctx = c.getContext('2d')
    if (!ctx) return null
    draw(ctx)
    return c.convertToBlob({ type: 'image/jpeg', quality })
  }
  if (typeof document === 'undefined') return null
  const c = document.createElement('canvas')
  c.width = w
  c.height = h
  const ctx = c.getContext('2d')
  if (!ctx) return null
  draw(ctx)
  return new Promise((r) => c.toBlob((b) => r(b), 'image/jpeg', quality))
}
