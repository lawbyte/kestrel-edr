/**
 * One remote-desktop session over the WebSocket: decodes binary JPEG frames
 * onto a canvas (newest frame wins, stale ones are dropped), sends input,
 * settings, activity and keep-alive messages, and reports phase changes.
 * Plain TS (no React) so the view component stays small.
 */
import { openDesktopSocket, type DesktopSocket } from '@/api/remote'
import type { DesktopInfo, DesktopServerMsg, DesktopSettings, InputEvent } from '@/api/types'
import { encodeClientMsg, endedText, frameJpeg, inputMsg, isNewerFrame, parseFrameHeader, settingsMsg, type FrameHeader } from '@/lib/remote-desktop'

export type DesktopPhase = 'idle' | 'checking' | 'connecting' | 'starting' | 'consent' | 'connected' | 'ended'

export interface SessionCallbacks {
  onPhase: (phase: DesktopPhase, message?: string) => void
  onInfo: (info: DesktopInfo) => void
  onError: (message: string) => void
  onFrameSize: (w: number, h: number) => void
  /** Mid-session: the employee is being asked to allow control (switch from view-only). */
  onControlConsent?: (timeoutSecs: number) => void
  /** Mid-session: outcome of that prompt. */
  onControlResult?: (allowed: boolean, code: string | null) => void
}

export interface SessionStats {
  fps: number
  /** now − agent capture time of the last drawn frame (includes clock skew). */
  latencyMs: number | null
  /** Browser ↔ server round trip from ping / pong. */
  rttMs: number | null
}

const PING_EVERY_MS = 20_000
const MOVE_EVERY_MS = 33
const ACTIVITY_EVERY_MS = 10_000

export class DesktopSession {
  private ws: DesktopSocket | null = null
  private opened = false
  private ended = false
  private started = false
  private pending: { h: FrameHeader; buf: ArrayBuffer } | null = null
  private decoding = false
  private lastQueued = 0
  private lastDrawn = 0
  private frameTimes: number[] = []
  private latency: number | null = null
  private rtt: number | null = null
  private pingSentAt = 0
  private pingTimer: ReturnType<typeof setInterval> | null = null
  private moveTimer: ReturnType<typeof setTimeout> | null = null
  private lastMoveAt = 0
  private pendingMove: { x: number; y: number } | null = null
  private wheelAcc = { dx: 0, dy: 0, x: 0, y: 0 }
  private wheelTimer: ReturnType<typeof setTimeout> | null = null
  private lastActivity = 0
  private width = 0
  private height = 0
  private canvas: HTMLCanvasElement
  private cb: SessionCallbacks

  constructor(canvas: HTMLCanvasElement, cb: SessionCallbacks) {
    this.canvas = canvas
    this.cb = cb
  }

  get isOpen() {
    return this.opened && !this.ended
  }
  imageSize() {
    return { w: this.width || this.canvas.width, h: this.height || this.canvas.height }
  }

  async start(url: string) {
    this.cb.onPhase('connecting')
    let ws: DesktopSocket
    try {
      ws = await openDesktopSocket(url)
    } catch {
      this.finish('Could not open the connection to the server.')
      return
    }
    if (this.ended) {
      ws.close()
      return
    }
    this.ws = ws
    ws.binaryType = 'arraybuffer'
    ws.onopen = () => {
      this.opened = true
      this.pingTimer = setInterval(() => this.ping(), PING_EVERY_MS)
    }
    ws.onmessage = (ev) => {
      if (typeof ev.data === 'string') this.onText(ev.data)
      else if (ev.data instanceof ArrayBuffer) this.onFrame(ev.data)
    }
    ws.onerror = () => {}
    ws.onclose = (ev) => {
      if (!this.opened) {
        this.finish('The session could not start. The device may have gone offline, its policy or allowed hours may not permit it now, your MFA confirmation may have expired, or another admin connected first. Check the device and try again.')
      } else {
        this.finish(ev.code === 1000 ? 'The session ended.' : `The connection to the server was lost (code ${ev.code}).`)
      }
    }
  }

  private finish(message: string) {
    this.cleanupTimers()
    if (this.ended) return
    this.ended = true
    this.cb.onPhase('ended', message)
  }

  private cleanupTimers() {
    if (this.pingTimer) clearInterval(this.pingTimer)
    if (this.moveTimer) clearTimeout(this.moveTimer)
    if (this.wheelTimer) clearTimeout(this.wheelTimer)
    this.pingTimer = this.moveTimer = this.wheelTimer = null
  }

  private onText(text: string) {
    let m: DesktopServerMsg
    try {
      m = JSON.parse(text) as DesktopServerMsg
    } catch {
      return
    }
    switch (m.type) {
      case 'starting':
        this.cb.onPhase('starting')
        break
      case 'consent_pending':
        if (this.started) this.cb.onControlConsent?.(m.timeout_secs)
        else this.cb.onPhase('consent', `They have up to ${Math.round(m.timeout_secs)} s to answer.`)
        break
      case 'consent_result':
        if (this.started) this.cb.onControlResult?.(m.allowed, m.code ?? null)
        else if (!m.allowed) {
          // The server also sends `ended`; finish now so the reason is the consent outcome.
          this.finish(endedText('', m.code ?? 'consent_denied'))
          this.ws?.close(1000)
        }
        break
      case 'started':
      case 'info': {
        const { type: _t, ...info } = m
        this.cb.onInfo(info)
        if (m.type === 'started') {
          this.started = true
          this.cb.onPhase('connected')
        }
        break
      }
      case 'ended':
        this.finish(endedText(m.reason, m.code))
        this.ws?.close(1000)
        break
      case 'error':
        this.cb.onError(m.message)
        break
      case 'pong':
        if (this.pingSentAt) this.rtt = Date.now() - this.pingSentAt
        break
    }
  }

  private onFrame(buf: ArrayBuffer) {
    const h = parseFrameHeader(buf)
    if (!h || !isNewerFrame(h.seq, this.lastQueued)) return
    this.lastQueued = h.seq
    // Keep only the newest undecoded frame; older ones are dropped.
    this.pending = { h, buf }
    if (!this.decoding) void this.decodeLoop()
  }

  private async decodeLoop() {
    this.decoding = true
    try {
      while (this.pending && !this.ended) {
        const p = this.pending
        this.pending = null
        let bmp: ImageBitmap
        try {
          bmp = await createImageBitmap(new Blob([frameJpeg(p.buf) as BlobPart], { type: 'image/jpeg' }))
        } catch {
          continue // corrupt frame: skip it
        }
        if (!isNewerFrame(p.h.seq, this.lastDrawn) || this.ended) {
          bmp.close()
          continue
        }
        const c = this.canvas
        if (c.width !== bmp.width || c.height !== bmp.height) {
          c.width = bmp.width
          c.height = bmp.height
          this.width = bmp.width
          this.height = bmp.height
          this.cb.onFrameSize(bmp.width, bmp.height)
        }
        c.getContext('2d')?.drawImage(bmp, 0, 0)
        bmp.close()
        this.lastDrawn = p.h.seq
        const now = Date.now()
        this.latency = now - p.h.ts
        this.frameTimes.push(now)
        if (this.frameTimes.length > 60) this.frameTimes.shift()
      }
    } finally {
      this.decoding = false
    }
  }

  stats(): SessionStats {
    const now = Date.now()
    const fps = this.frameTimes.filter((t) => t > now - 2000).length / 2
    return { fps, latencyMs: this.lastDrawn && now - (this.frameTimes.at(-1) ?? 0) < 5000 ? this.latency : null, rttMs: this.rtt }
  }

  private send(text: string) {
    if (this.ws && this.isOpen && this.ws.readyState === 1) this.ws.send(text)
  }
  private ping() {
    this.pingSentAt = Date.now()
    this.send(encodeClientMsg({ type: 'ping' }))
  }

  input(ev: InputEvent) {
    this.send(encodeClientMsg(inputMsg(ev)))
  }

  /** Throttled pointer move (~30/s, trailing edge kept). */
  moveTo(x: number, y: number) {
    this.pendingMove = { x, y }
    const now = Date.now()
    const wait = MOVE_EVERY_MS - (now - this.lastMoveAt)
    if (wait <= 0) this.flushMove()
    else if (!this.moveTimer) this.moveTimer = setTimeout(() => this.flushMove(), wait)
  }
  private flushMove() {
    this.moveTimer = null
    if (!this.pendingMove) return
    this.lastMoveAt = Date.now()
    this.input({ kind: 'mouse_move', ...this.pendingMove })
    this.pendingMove = null
  }

  /** Button events flush a pending move first so the click lands where the pointer is. */
  button(ev: Extract<InputEvent, { kind: 'mouse_button' }>) {
    if (this.pendingMove) this.flushMove()
    this.input(ev)
  }

  /** Wheel notches, accumulated and sent at most ~30/s. */
  wheel(x: number, y: number, dx: number, dy: number) {
    this.wheelAcc = { dx: this.wheelAcc.dx + dx, dy: this.wheelAcc.dy + dy, x, y }
    if (!this.wheelTimer)
      this.wheelTimer = setTimeout(() => {
        this.wheelTimer = null
        const a = this.wheelAcc
        this.wheelAcc = { dx: 0, dy: 0, x: a.x, y: a.y }
        const r = (v: number) => Math.round(Math.max(-50, Math.min(50, v)) * 100) / 100 || 0
        if (a.dx || a.dy) this.input({ kind: 'mouse_wheel', x: a.x, y: a.y, delta_x: r(a.dx), delta_y: r(a.dy) })
      }, MOVE_EVERY_MS)
  }

  /** Admin present without input (view-only): resets the server's idle timer, throttled. */
  activity() {
    const now = Date.now()
    if (now - this.lastActivity < ACTIVITY_EVERY_MS) return
    this.lastActivity = now
    this.send(encodeClientMsg({ type: 'activity' }))
  }

  settings(s: DesktopSettings) {
    this.send(encodeClientMsg(settingsMsg(s)))
  }

  /** Disconnect: ask the server to stop, then close. */
  stop() {
    if (this.isOpen) {
      this.send(encodeClientMsg({ type: 'stop' }))
      this.finish('You disconnected.')
    }
    const ws = this.ws
    // Give the stop message a moment to flush before closing.
    setTimeout(() => ws?.close(1000), 300)
  }

  /** Unmount / tab switch. */
  dispose() {
    if (this.isOpen) this.send(encodeClientMsg({ type: 'stop' }))
    this.ended = true
    this.cleanupTimers()
    this.pending = null
    try {
      this.ws?.close(1000)
    } catch {
      /* already closed */
    }
    this.ws = null
  }
}
