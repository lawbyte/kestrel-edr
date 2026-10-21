import { describe, expect, it, vi } from 'vitest'
import type { DesktopServerMsg } from '@/api/types'

class FakeSocket {
  readyState = 1
  binaryType: BinaryType = 'arraybuffer'
  onopen: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  sent: string[] = []
  send(d: string) {
    this.sent.push(d)
  }
  close() {
    this.readyState = 3
  }
  msg(m: DesktopServerMsg) {
    this.onmessage?.({ data: JSON.stringify(m) } as MessageEvent)
  }
}
let sock: FakeSocket
vi.mock('@/api/remote', () => ({ openDesktopSocket: async () => (sock = new FakeSocket()) }))

const { DesktopSession } = await import('./desktop-session')

function session() {
  const cb = { onPhase: vi.fn(), onInfo: vi.fn(), onError: vi.fn(), onFrameSize: vi.fn(), onControlConsent: vi.fn(), onControlResult: vi.fn() }
  const s = new DesktopSession({ width: 0, height: 0 } as HTMLCanvasElement, cb)
  return { s, cb }
}

describe('DesktopSession consent handling', () => {
  it('a denied consent before start ends the session with the consent reason', async () => {
    const { s, cb } = session()
    await s.start('ws://x')
    sock.onopen?.(new Event('open'))
    sock.msg({ type: 'starting', session_id: 's', view_only: false })
    sock.msg({ type: 'consent_pending', timeout_secs: 30 })
    expect(cb.onPhase).toHaveBeenLastCalledWith('consent', 'They have up to 30 s to answer.')
    sock.msg({ type: 'consent_result', allowed: false, code: 'consent_denied' })
    expect(cb.onPhase).toHaveBeenLastCalledWith('ended', expect.stringMatching(/employee denied/))
    s.dispose()
  })
  it('mid-session consent for control is reported, not treated as a new session phase', async () => {
    const { s, cb } = session()
    await s.start('ws://x')
    sock.onopen?.(new Event('open'))
    sock.msg({ type: 'started', width: 10, height: 10, view_only: true })
    expect(cb.onPhase).toHaveBeenLastCalledWith('connected')
    sock.msg({ type: 'consent_pending', timeout_secs: 60 })
    expect(cb.onControlConsent).toHaveBeenCalledWith(60)
    sock.msg({ type: 'consent_result', allowed: false, code: 'consent_timeout' })
    expect(cb.onControlResult).toHaveBeenCalledWith(false, 'consent_timeout')
    sock.msg({ type: 'consent_result', allowed: true, code: null })
    expect(cb.onControlResult).toHaveBeenLastCalledWith(true, null)
    expect(cb.onPhase).toHaveBeenLastCalledWith('connected')
    s.settings({ quality: 60, scale_pct: 100, max_fps: 8, view_only: false })
    expect(JSON.parse(sock.sent.at(-1)!)).toMatchObject({ type: 'settings', view_only: false })
    s.dispose()
  })
})
