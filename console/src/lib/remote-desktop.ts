/**
 * Pure helpers for the remote-desktop WebSocket (docs/contracts.md "Remote
 * access"): binary frame header, letterbox-aware coordinate normalisation,
 * input mapping and client message encoding. No DOM access, so they are unit
 * tested in Node.
 */
import type { DesktopClientMsg, DesktopSettings, InputEvent, MouseButton } from '@/api/types'

/** Header length of a binary frame message (`WS_FRAME_HEADER`). */
export const WS_FRAME_HEADER = 16

export interface FrameHeader {
  seq: number
  width: number
  height: number
  /** Agent capture time (ms, agent clock). */
  ts: number
}

/** Parse the 16-byte big-endian header (`u32 seq, u16 width, u16 height, u64 ts`). `null` if too short. */
export function parseFrameHeader(buf: ArrayBuffer): FrameHeader | null {
  if (buf.byteLength < WS_FRAME_HEADER) return null
  const v = new DataView(buf)
  const hi = v.getUint32(8)
  const lo = v.getUint32(12)
  return { seq: v.getUint32(0), width: v.getUint16(4), height: v.getUint16(6), ts: hi * 2 ** 32 + lo }
}

/** Build a frame message (header + JPEG); used by the mock socket and tests. Mirrors Rust `ws_frame_header`. */
export function buildFrame(h: FrameHeader, jpeg: Uint8Array): ArrayBuffer {
  const out = new Uint8Array(WS_FRAME_HEADER + jpeg.byteLength)
  const v = new DataView(out.buffer)
  v.setUint32(0, h.seq >>> 0)
  v.setUint16(4, Math.min(h.width, 0xffff))
  v.setUint16(6, Math.min(h.height, 0xffff))
  const ts = Math.max(0, Math.floor(h.ts))
  v.setUint32(8, Math.floor(ts / 2 ** 32))
  v.setUint32(12, ts >>> 0)
  out.set(jpeg, WS_FRAME_HEADER)
  return out.buffer
}

/** The JPEG bytes after the header. */
export function frameJpeg(buf: ArrayBuffer): Uint8Array {
  return new Uint8Array(buf, WS_FRAME_HEADER)
}

/**
 * Sequence check: drop frames that are not newer than the last one drawn.
 * `seq` is a u32 on the wire; treat a large backwards jump as wrap-around.
 */
export function isNewerFrame(seq: number, last: number): boolean {
  if (last === 0) return true
  const diff = (seq - last) >>> 0
  return diff !== 0 && diff < 0x80000000
}

export interface Rect {
  x: number
  y: number
  w: number
  h: number
}

/** Where an image of `imgW × imgH` is drawn inside a box with `object-fit: contain` (letterboxed). */
export function containRect(boxW: number, boxH: number, imgW: number, imgH: number): Rect {
  if (boxW <= 0 || boxH <= 0 || imgW <= 0 || imgH <= 0) return { x: 0, y: 0, w: Math.max(0, boxW), h: Math.max(0, boxH) }
  const s = Math.min(boxW / imgW, boxH / imgH)
  const w = imgW * s
  const h = imgH * s
  return { x: (boxW - w) / 2, y: (boxH - h) / 2, w, h }
}

/**
 * Normalise a pointer position (relative to the canvas element's box) to 0..1
 * over the drawn image, accounting for letterbox bars. Points on the bars are
 * clamped to the nearest edge. `inside` tells whether the pointer is on the image.
 */
export function normalisePoint(px: number, py: number, boxW: number, boxH: number, imgW: number, imgH: number): { x: number; y: number; inside: boolean } {
  const r = containRect(boxW, boxH, imgW, imgH)
  const rx = r.w > 0 ? (px - r.x) / r.w : 0
  const ry = r.h > 0 ? (py - r.y) / r.h : 0
  const inside = rx >= 0 && rx <= 1 && ry >= 0 && ry <= 1
  const c = (v: number) => Math.round(Math.min(1, Math.max(0, v)) * 10000) / 10000
  return { x: c(rx), y: c(ry), inside }
}

/** `MouseEvent.button` → wire button. */
export function mouseButtonOf(button: number): MouseButton | null {
  switch (button) {
    case 0:
      return 'left'
    case 1:
      return 'middle'
    case 2:
      return 'right'
    case 3:
      return 'x1'
    case 4:
      return 'x2'
    default:
      return null
  }
}

/** Accepted `KeyboardEvent.code` (same rule as Rust `InputEvent::sanitized`): 1–32 ASCII letters / digits. */
export function isValidKeyCode(code: string): boolean {
  return /^[A-Za-z0-9]{1,32}$/.test(code)
}

/** Key transition → input event; `null` for codes the agent would drop (IME, unidentified). */
export function keyEvent(code: string, down: boolean): InputEvent | null {
  return isValidKeyCode(code) ? { kind: 'key', code, down } : null
}

/**
 * WheelEvent deltas → notches (positive = away from the user / right, as the
 * Rust contract says; the browser's positive deltaY is towards the user).
 * deltaMode: 0 pixels (~100 px per notch), 1 lines (3 per notch), 2 pages.
 */
export function wheelNotches(deltaX: number, deltaY: number, deltaMode: number): { dx: number; dy: number } {
  const per = deltaMode === 1 ? 3 : deltaMode === 2 ? 1 : 100
  const clamp = (v: number) => Math.max(-50, Math.min(50, v))
  const r = (v: number) => Math.round(v * 100) / 100 || 0
  return { dx: r(clamp(deltaX / per)), dy: r(clamp(-deltaY / per)) }
}

/** Text typed / pasted into the session: ≤ 4096 chars, never empty. */
export function textEvent(text: string): InputEvent | null {
  const chars = [...text]
  if (chars.length === 0) return null
  return { kind: 'text', text: chars.slice(0, 4096).join('') }
}

export const clampSettings = (s: DesktopSettings): DesktopSettings => ({
  quality: Math.round(Math.min(90, Math.max(30, s.quality))),
  scale_pct: Math.round(Math.min(100, Math.max(25, s.scale_pct))),
  max_fps: Math.round(Math.min(15, Math.max(1, s.max_fps))),
  ...(s.view_only != null ? { view_only: s.view_only } : {}),
})

/** Encode a client message (≤ 64 KiB as the server requires). */
export function encodeClientMsg(m: DesktopClientMsg): string {
  return JSON.stringify(m)
}
export const inputMsg = (event: InputEvent): DesktopClientMsg => ({ type: 'input', event })
export const settingsMsg = (s: DesktopSettings): DesktopClientMsg => ({ type: 'settings', ...clampSettings(s) })

/** WebSocket URL (same origin; `csrf` in the query because browsers cannot set headers on a WebSocket). */
export function desktopSocketUrl(
  loc: { protocol: string; host: string },
  deviceId: string,
  o: { viewOnly: boolean; quality: number; scale: number; fps: number; reason: string; csrf: string },
): string {
  const proto = loc.protocol === 'https:' ? 'wss:' : 'ws:'
  const q = new URLSearchParams()
  q.set('view_only', o.viewOnly ? '1' : '0')
  q.set('quality', String(o.quality))
  q.set('scale', String(o.scale))
  q.set('fps', String(o.fps))
  if (o.reason.trim()) q.set('reason', o.reason.trim().slice(0, 200))
  q.set('csrf', o.csrf)
  return `${proto}//${loc.host}/api/devices/${encodeURIComponent(deviceId)}/remote-desktop?${q.toString()}`
}

/** Plain-words session end reason for the status line. */
export function endedText(reason: string, code?: string | null): string {
  const r = reason.trim()
  const byReason: Record<string, string> = {
    admin: 'You disconnected.',
    idle: 'Ended after 15 minutes without activity.',
    max_duration: 'Ended after the 4-hour session limit.',
    agent: 'The device ended the session.',
    disconnect: 'The device lost its connection to the server.',
    server: 'The server ended the session (your sign-in or privileges changed).',
  }
  const byCode: Record<string, string> = {
    disabled_by_policy: 'Remote desktop is switched off in this device’s policy.',
    unavailable: 'No one is signed in on the device, or the capture helper could not start.',
    busy: 'Another remote desktop session is active on this device.',
    timeout: 'The device did not answer in time.',
    not_permitted: 'This device’s install profile does not allow remote desktop.',
    consent_denied: 'The employee denied the session (or no one was signed in to answer).',
    consent_timeout: 'The employee did not answer the access request in time.',
    outside_allowed_hours: 'Remote access is outside the allowed hours for this device.',
    reason_required: 'A reason is required for this device.',
  }
  if (byReason[r]) return byReason[r]
  if (code && byCode[code]) return r ? `${byCode[code]} (${r})` : byCode[code]
  return r || 'The session ended.'
}
