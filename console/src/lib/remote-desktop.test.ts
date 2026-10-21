import { describe, expect, it } from 'vitest'
import type { DesktopClientMsg } from '@/api/types'
import {
  WS_FRAME_HEADER,
  buildFrame,
  containRect,
  desktopSocketUrl,
  encodeClientMsg,
  endedText,
  frameJpeg,
  inputMsg,
  isNewerFrame,
  keyEvent,
  mouseButtonOf,
  normalisePoint,
  parseFrameHeader,
  settingsMsg,
  textEvent,
  wheelNotches,
} from './remote-desktop'

describe('binary frame header', () => {
  it('parses the big-endian 16-byte header like Rust ws_frame_header builds it', () => {
    // ws_frame_header(258, 1920, 1080, 5) → [0,0,1,2, 0x07,0x80, 0x04,0x38, 0,0,0,0,0,0,0,5]
    const bytes = new Uint8Array([0, 0, 1, 2, 0x07, 0x80, 0x04, 0x38, 0, 0, 0, 0, 0, 0, 0, 5, 0xff, 0xd8])
    const h = parseFrameHeader(bytes.buffer)
    expect(h).toEqual({ seq: 258, width: 1920, height: 1080, ts: 5 })
    expect([...frameJpeg(bytes.buffer)]).toEqual([0xff, 0xd8])
  })
  it('round-trips real timestamps above 2^32', () => {
    const ts = 1_792_000_000_123
    const buf = buildFrame({ seq: 7, width: 960, height: 540, ts }, new Uint8Array([1, 2, 3]))
    expect(buf.byteLength).toBe(WS_FRAME_HEADER + 3)
    expect(parseFrameHeader(buf)).toEqual({ seq: 7, width: 960, height: 540, ts })
  })
  it('rejects short messages', () => {
    expect(parseFrameHeader(new ArrayBuffer(15))).toBeNull()
  })
  it('drops stale frames and handles u32 wrap-around', () => {
    expect(isNewerFrame(1, 0)).toBe(true)
    expect(isNewerFrame(5, 4)).toBe(true)
    expect(isNewerFrame(4, 4)).toBe(false)
    expect(isNewerFrame(3, 4)).toBe(false)
    expect(isNewerFrame(2, 0xfffffffe)).toBe(true)
  })
})

describe('coordinate normalisation with letterboxing', () => {
  it('computes the contained image rect', () => {
    // 16:9 image in a 1000×1000 box → bars top and bottom
    const a = containRect(1000, 1000, 1920, 1080)
    expect(a.x).toBeCloseTo(0, 9)
    expect(a.y).toBeCloseTo(218.75, 9)
    expect(a.w).toBeCloseTo(1000, 9)
    expect(a.h).toBeCloseTo(562.5, 9)
    // 4:3 image in a wide box → bars left and right
    const r = containRect(1600, 600, 800, 600)
    expect(r).toEqual({ x: 400, y: 0, w: 800, h: 600 })
  })
  it('maps pointer positions on the image to 0..1', () => {
    expect(normalisePoint(500, 500, 1000, 1000, 1920, 1080)).toEqual({ x: 0.5, y: 0.5, inside: true })
    expect(normalisePoint(0, 218.75, 1000, 1000, 1920, 1080)).toEqual({ x: 0, y: 0, inside: true })
    expect(normalisePoint(1000, 781.25, 1000, 1000, 1920, 1080)).toEqual({ x: 1, y: 1, inside: true })
    expect(normalisePoint(400 + 200, 150, 1600, 600, 800, 600)).toEqual({ x: 0.25, y: 0.25, inside: true })
  })
  it('clamps points on the letterbox bars and says so', () => {
    expect(normalisePoint(500, 10, 1000, 1000, 1920, 1080)).toEqual({ x: 0.5, y: 0, inside: false })
    expect(normalisePoint(100, 300, 1600, 600, 800, 600)).toEqual({ x: 0, y: 0.5, inside: false })
  })
  it('handles an unscaled canvas (no letterbox)', () => {
    expect(normalisePoint(96, 54, 192, 108, 192, 108)).toEqual({ x: 0.5, y: 0.5, inside: true })
  })
})

describe('input mapping and client messages', () => {
  it('maps mouse buttons', () => {
    expect([0, 1, 2, 3, 4, 5].map(mouseButtonOf)).toEqual(['left', 'middle', 'right', 'x1', 'x2', null])
  })
  it('keeps KeyboardEvent.code values the agent accepts', () => {
    expect(keyEvent('KeyA', true)).toEqual({ kind: 'key', code: 'KeyA', down: true })
    expect(keyEvent('ShiftLeft', false)).toEqual({ kind: 'key', code: 'ShiftLeft', down: false })
    expect(keyEvent('', true)).toBeNull()
    expect(keyEvent('Key A', true)).toBeNull()
    expect(keyEvent('Unidentified-1', true)).toBeNull()
    expect(keyEvent('x'.repeat(33), true)).toBeNull()
  })
  it('converts wheel deltas to notches (positive = away from the user)', () => {
    expect(wheelNotches(0, -100, 0)).toEqual({ dx: 0, dy: 1 })
    expect(wheelNotches(0, 300, 0)).toEqual({ dx: 0, dy: -3 })
    expect(wheelNotches(0, 3, 1)).toEqual({ dx: 0, dy: -1 })
    expect(wheelNotches(50, 0, 0)).toEqual({ dx: 0.5, dy: 0 })
    expect(wheelNotches(0, -1e6, 0).dy).toBe(50)
  })
  it('limits typed text to 4096 characters', () => {
    expect(textEvent('')).toBeNull()
    const t = textEvent('é'.repeat(5000))
    expect(t && t.kind === 'text' && [...t.text].length).toBe(4096)
  })
  it('encodes messages with the serde tags', () => {
    expect(JSON.parse(encodeClientMsg(inputMsg({ kind: 'mouse_button', x: 0.1, y: 0.2, button: 'left', down: true })))).toEqual({
      type: 'input',
      event: { kind: 'mouse_button', x: 0.1, y: 0.2, button: 'left', down: true },
    })
    expect(JSON.parse(encodeClientMsg(inputMsg({ kind: 'ctrl_alt_del' })))).toEqual({ type: 'input', event: { kind: 'ctrl_alt_del' } })
    expect(JSON.parse(encodeClientMsg({ type: 'stop' }))).toEqual({ type: 'stop' })
    const s = settingsMsg({ quality: 200, scale_pct: 10, max_fps: 0, view_only: false }) as Extract<DesktopClientMsg, { type: 'settings' }>
    expect(s).toEqual({ type: 'settings', quality: 90, scale_pct: 25, max_fps: 1, view_only: false })
    expect('view_only' in settingsMsg({ quality: 60, scale_pct: 100, max_fps: 8 })).toBe(false)
  })
  it('builds a same-origin WebSocket URL with the CSRF token in the query', () => {
    const u = new URL(desktopSocketUrl({ protocol: 'https:', host: 'edr.example.sg' }, 'dev 1', { viewOnly: true, quality: 60, scale: 75, fps: 8, reason: '  ticket 42  ', csrf: 'abc' }))
    expect(u.protocol).toBe('wss:')
    expect(u.host).toBe('edr.example.sg')
    expect(u.pathname).toBe('/api/devices/dev%201/remote-desktop')
    expect(Object.fromEntries(u.searchParams)).toEqual({ view_only: '1', quality: '60', scale: '75', fps: '8', reason: 'ticket 42', csrf: 'abc' })
    expect(desktopSocketUrl({ protocol: 'http:', host: 'localhost:5173' }, 'x', { viewOnly: false, quality: 60, scale: 100, fps: 8, reason: '', csrf: 't' })).toMatch(/^ws:\/\/localhost:5173\/.*view_only=0/)
  })
  it('explains how a session ended', () => {
    expect(endedText('idle')).toMatch(/15 minutes/)
    expect(endedText('agent', 'unavailable')).toMatch(/device ended/)
    expect(endedText('could not start', 'consent_denied')).toMatch(/^The employee denied the session.*\(could not start\)$/)
    expect(endedText('something new')).toBe('something new')
    expect(endedText('', 'busy')).toMatch(/Another/)
  })
})
