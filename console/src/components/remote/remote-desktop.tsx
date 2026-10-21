import { Eye, Keyboard, Loader2, Maximize, Minimize, MonitorPlay, MonitorX, MousePointer2, Plug, PlugZap, ShieldAlert, Type } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type PointerEvent as ReactPointerEvent } from 'react'
import { getCsrfToken } from '@/api/client'
import { reauthFresh, remoteApi, remoteErrorText } from '@/api/remote'
import { consentTimeout } from '@/lib/remote-profile'
import type { DesktopInfo, RemoteAccessProfile, RemoteAvailability } from '@/api/types'
import { useReauth } from './reauth'
import { Button } from '@/components/ui/button'
import { Input, Label } from '@/components/ui/input'
import { Switch, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { formatTime } from '@/lib/format'
import { desktopSocketUrl, keyEvent, mouseButtonOf, normalisePoint, textEvent, wheelNotches } from '@/lib/remote-desktop'
import { cn } from '@/lib/utils'
import { DesktopSession, type DesktopPhase, type SessionStats } from './desktop-session'
import { RemoteUnavailable } from './availability'

const QUALITIES = [30, 45, 60, 75, 90]
const SCALES = [25, 50, 75, 100]
const FPS = [2, 5, 8, 12, 15]
const ESC_DOUBLE_MS = 500

const selectClass =
  'h-8 rounded-md border border-border-strong bg-surface px-2 text-sm text-fg focus-visible:outline-2 focus-visible:outline-ring disabled:opacity-60'

export function RemoteDesktop({ deviceId, hostname, availability, policyId, effective }: { deviceId: string; hostname: string; availability: RemoteAvailability; policyId: string | null; effective: RemoteAccessProfile }) {
  const { me } = useAuth()
  const { ask } = useReauth()
  const forcedViewOnly = effective.desktop === 'view_only'
  const reasonRequired = effective.guardrails.require_reason
  const [phase, setPhase] = useState<DesktopPhase>('idle')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<DesktopInfo | null>(null)
  const [frame, setFrame] = useState<{ w: number; h: number } | null>(null)
  const [stats, setStats] = useState<SessionStats>({ fps: 0, latencyMs: null, rttMs: null })
  const [reason, setReason] = useState('')
  const [viewOnlyChoice, setViewOnly] = useState(true)
  const viewOnly = viewOnlyChoice || forcedViewOnly
  /** Switched to control on a consent profile: the session stays view-only until the employee allows it (seconds to wait). */
  const [awaitingControl, setAwaitingControl] = useState<number | null>(null)
  const [controlNote, setControlNote] = useState<string | null>(null)
  /** What the session actually is: input is only sent once control was granted. */
  const effViewOnly = viewOnly || awaitingControl != null
  const [quality, setQuality] = useState(60)
  const [scale, setScale] = useState(100)
  const [fps, setFps] = useState(8)
  const [fit, setFit] = useState(true)
  const [focused, setFocused] = useState(false)
  const [fullscreen, setFullscreen] = useState(false)
  const [typing, setTyping] = useState(false)
  const [typed, setTyped] = useState('')

  const canvasRef = useRef<HTMLCanvasElement>(null)
  const stageRef = useRef<HTMLDivElement>(null)
  const sessionRef = useRef<DesktopSession | null>(null)
  const viewOnlyRef = useRef(effViewOnly)
  viewOnlyRef.current = effViewOnly
  const lastEscRef = useRef(0)
  const live = phase === 'connecting' || phase === 'starting' || phase === 'consent' || phase === 'connected'

  // Unmount (tab switch, navigation): stop the session and close the socket.
  useEffect(() => () => sessionRef.current?.dispose(), [])

  // Stats refresh (not per frame, to keep React out of the hot path).
  useEffect(() => {
    if (phase !== 'connected') return
    const t = setInterval(() => sessionRef.current && setStats(sessionRef.current.stats()), 1000)
    return () => clearInterval(t)
  }, [phase])

  // Mid-session settings changes.
  const settingsKey = `${quality}/${scale}/${fps}/${viewOnly}`
  const sentKey = useRef(settingsKey)
  useEffect(() => {
    const s = sessionRef.current
    if (phase !== 'connected' || !s || sentKey.current === settingsKey) return
    const prevViewOnly = sentKey.current.endsWith('true')
    sentKey.current = settingsKey
    s.settings({ quality, scale_pct: scale, max_fps: fps, view_only: viewOnly })
    if (prevViewOnly && !viewOnly && effective.guardrails.require_consent) {
      // The agent asks the employee first; stay view-only until consent_result / info.
      setAwaitingControl(consentTimeout(effective.guardrails))
      setControlNote(null)
    } else if (viewOnly) setAwaitingControl(null)
  }, [phase, settingsKey, quality, scale, fps, viewOnly, effective.guardrails])

  useEffect(() => {
    const h = () => setFullscreen(document.fullscreenElement === stageRef.current && !!stageRef.current)
    document.addEventListener('fullscreenchange', h)
    return () => document.removeEventListener('fullscreenchange', h)
  }, [])

  const connect = async () => {
    const canvas = canvasRef.current
    if (!canvas) return
    if (reasonRequired && !reason.trim()) {
      setError('Enter a reason first. This device’s remote-access profile requires one; the employee sees it in the banner.')
      return
    }
    if (effective.guardrails.require_mfa_reauth && !reauthFresh()) {
      // A WebSocket upgrade cannot report a 403, so confirm MFA up front.
      if (!(await ask())) return
    }
    setError(null)
    setMessage(null)
    setInfo(null)
    setAwaitingControl(null)
    setControlNote(null)
    setFrame(null)
    setStats({ fps: 0, latencyMs: null, rttMs: null })
    setPhase('checking')
    try {
      const st = await remoteApi.desktopStatus(deviceId)
      if (st.active && st.session) {
        setPhase('idle')
        setError(`${st.session.admin_name} (${st.session.admin_email}) is already connected to ${hostname} since ${formatTime(st.session.started_at)}. Only one session per device is allowed.`)
        return
      }
    } catch (e) {
      setPhase('idle')
      setError(remoteErrorText(e))
      return
    }
    const ctx = canvas.getContext('2d')
    ctx?.clearRect(0, 0, canvas.width, canvas.height)
    sessionRef.current?.dispose()
    sentKey.current = `${quality}/${scale}/${fps}/${viewOnly}`
    const s = new DesktopSession(canvas, {
      onPhase: (p, m) => {
        setPhase(p)
        setMessage(m ?? null)
        if (p === 'ended') setFocused(false)
      },
      onInfo: (i) => {
        if (i.view_only === false) setAwaitingControl(null)
        setInfo(i)
        if (typeof i.view_only === 'boolean' && i.view_only !== viewOnlyRef.current) {
          sentKey.current = sentKey.current.replace(/(true|false)$/, String(i.view_only))
          setViewOnly(i.view_only)
        }
      },
      onError: setError,
      onFrameSize: (w, h) => setFrame({ w, h }),
      onControlConsent: (secs) => {
        setAwaitingControl(secs)
        setControlNote(null)
      },
      onControlResult: (allowed, code) => {
        setAwaitingControl(null)
        if (allowed) return
        setControlNote(code === 'consent_timeout' ? 'The employee did not answer in time. The session stays view-only.' : 'The employee did not allow control. The session stays view-only.')
        sentKey.current = sentKey.current.replace(/(true|false)$/, 'true')
        setViewOnly(true)
      },
    })
    sessionRef.current = s
    const url = desktopSocketUrl(window.location, deviceId, { viewOnly, quality, scale, fps, reason, csrf: me.csrf_token || getCsrfToken() || '' })
    await s.start(url)
  }

  const disconnect = () => {
    sessionRef.current?.stop()
    if (document.fullscreenElement) void document.exitFullscreen().catch(() => {})
  }

  const toggleFullscreen = () => {
    const el = stageRef.current
    if (!el) return
    if (document.fullscreenElement) void document.exitFullscreen().catch(() => {})
    else void el.requestFullscreen?.().catch(() => setError('The browser refused full screen.'))
  }

  // ---------------------------------------------------------------- input
  const point = useCallback((clientX: number, clientY: number) => {
    const c = canvasRef.current
    const s = sessionRef.current
    if (!c || !s) return null
    const r = c.getBoundingClientRect()
    const img = s.imageSize()
    return normalisePoint(clientX - r.left, clientY - r.top, r.width, r.height, img.w, img.h)
  }, [])

  const controlling = phase === 'connected' && !effViewOnly

  const onPointerMove = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const s = sessionRef.current
    if (!s || phase !== 'connected') return
    if (effViewOnly) {
      s.activity()
      return
    }
    if (!focused) return
    const p = point(e.clientX, e.clientY)
    if (p) s.moveTo(p.x, p.y)
  }
  const onPointerDown = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const s = sessionRef.current
    if (!s || phase !== 'connected') return
    if (!focused) {
      // First click only focuses ("click to control"); it is not sent.
      canvasRef.current?.focus()
      e.preventDefault()
      return
    }
    if (effViewOnly) return
    const b = mouseButtonOf(e.button)
    const p = point(e.clientX, e.clientY)
    if (!b || !p || !p.inside) return
    e.preventDefault()
    canvasRef.current?.setPointerCapture?.(e.pointerId)
    s.button({ kind: 'mouse_button', x: p.x, y: p.y, button: b, down: true })
  }
  const onPointerUp = (e: ReactPointerEvent<HTMLCanvasElement>) => {
    const s = sessionRef.current
    if (!s || !controlling || !focused) return
    const b = mouseButtonOf(e.button)
    const p = point(e.clientX, e.clientY)
    if (!b || !p) return
    s.button({ kind: 'mouse_button', x: p.x, y: p.y, button: b, down: false })
  }

  // Wheel needs a non-passive listener to stop the page from scrolling.
  useEffect(() => {
    const c = canvasRef.current
    if (!c) return
    const h = (e: WheelEvent) => {
      const s = sessionRef.current
      if (!s || document.activeElement !== c) return
      e.preventDefault()
      if (viewOnlyRef.current) return s.activity()
      const p = point(e.clientX, e.clientY)
      if (!p) return
      const n = wheelNotches(e.deltaX, e.deltaY, e.deltaMode)
      s.wheel(p.x, p.y, n.dx, n.dy)
    }
    c.addEventListener('wheel', h, { passive: false })
    return () => c.removeEventListener('wheel', h)
  }, [point])

  const onKey = (down: boolean) => (e: ReactKeyboardEvent<HTMLCanvasElement>) => {
    const s = sessionRef.current
    if (!s || phase !== 'connected') return
    if (e.key === 'Escape' && down) {
      const now = Date.now()
      if (now - lastEscRef.current < ESC_DOUBLE_MS) {
        lastEscRef.current = 0
        e.preventDefault()
        canvasRef.current?.blur()
        return
      }
      lastEscRef.current = now
    }
    if (effViewOnly) return // keys stay with the browser in view-only mode (Tab moves focus)
    if (e.nativeEvent.isComposing) return
    e.preventDefault()
    const ev = keyEvent(e.code, down)
    if (ev) s.input(ev)
  }

  const onBlur = () => {
    setFocused(false)
    if (controlling) sessionRef.current?.input({ kind: 'release_all' })
  }

  const sendText = () => {
    const ev = textEvent(typed)
    if (ev) sessionRef.current?.input(ev)
    setTyped('')
    setTyping(false)
    canvasRef.current?.focus()
  }

  if (!availability.available) {
    return <RemoteUnavailable feature="desktop" availability={availability} policyId={policyId} />
  }

  const statusText =
    phase === 'idle'
      ? 'Not connected'
      : phase === 'checking'
        ? 'Checking the device…'
        : phase === 'connecting'
          ? 'Connecting…'
          : phase === 'starting'
            ? 'Starting capture on the device…'
            : phase === 'consent'
              ? 'Waiting for the employee to allow access…'
            : phase === 'connected'
              ? awaitingControl != null
                ? `Waiting for the employee to allow control… (${awaitingControl} s)`
                : viewOnly
                ? 'Connected, view only'
                : 'Connected, in control'
              : 'Session ended'

  return (
    <div className="space-y-3">
      <div role="note" className="flex items-start gap-2 rounded-lg border border-warn/40 bg-warn-soft px-3 py-2 text-sm">
        <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
        <p>
          <span className="font-medium">The employee sees a banner and a notification while you are connected.</span> <span className="text-fg-muted">Every session, mode change and its reason is recorded in the audit log. {limitsText(effective)}</span>
        </p>
      </div>

      <div className="rounded-lg border border-border bg-surface">
        <div className="flex flex-wrap items-end gap-x-4 gap-y-3 border-b border-border px-4 py-3" role="toolbar" aria-label="Remote desktop controls">
          {!live ? (
            <>
              <div className="min-w-56 flex-1 space-y-1">
                <Label htmlFor="rd-reason" className="text-xs text-fg-muted">
                  Reason (shown to the employee{reasonRequired ? ', required' : ', optional'})
                </Label>
                <Input id="rd-reason" value={reason} maxLength={200} required={reasonRequired} aria-required={reasonRequired} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Checking the Outlook add-in error you reported" />
              </div>
              <Button variant="primary" onClick={() => void connect()} disabled={phase === 'checking' || (reasonRequired && !reason.trim())}>
                {phase === 'checking' ? <Loader2 className="animate-spin" /> : <Plug />} Connect
              </Button>
            </>
          ) : (
            <Button variant="danger-outline" onClick={disconnect}>
              <PlugZap /> Disconnect
            </Button>
          )}
          <div className="flex items-center gap-2 pb-1.5">
            <Switch id="rd-viewonly" checked={viewOnly} onCheckedChange={setViewOnly} disabled={forcedViewOnly || phase === 'starting' || phase === 'connecting' || phase === 'consent' || phase === 'checking'} aria-describedby={forcedViewOnly ? 'rd-viewonly-why' : undefined} />
            <Label htmlFor="rd-viewonly" className="text-sm">
              View only
            </Label>
            {forcedViewOnly ? (
              <span id="rd-viewonly-why" className="text-xs text-fg-muted">
                (this device allows viewing only)
              </span>
            ) : null}
          </div>
          <SelectField id="rd-quality" label="Quality" value={quality} options={QUALITIES} onChange={setQuality} />
          <SelectField id="rd-scale" label="Scale" value={scale} options={SCALES} suffix="%" onChange={setScale} />
          <SelectField id="rd-fps" label="Max fps" value={fps} options={FPS} onChange={setFps} />
          <div className="flex items-center gap-2 pb-1.5">
            <Switch id="rd-fit" checked={fit} onCheckedChange={setFit} />
            <Label htmlFor="rd-fit" className="text-sm">
              Fit to window
            </Label>
          </div>
          <div className="ml-auto flex flex-wrap items-center gap-2">
            <Tooltip content={viewOnly ? 'Switch off View only to send keys' : 'Sends Ctrl+Alt+Del (needs the SoftwareSASGeneration policy on the device)'}>
              <span>
                <Button size="sm" onClick={() => sessionRef.current?.input({ kind: 'ctrl_alt_del' })} disabled={!controlling}>
                  <Keyboard /> Ctrl+Alt+Del
                </Button>
              </span>
            </Tooltip>
            <Button size="sm" onClick={() => setTyping((t) => !t)} disabled={!controlling} aria-expanded={typing}>
              <Type /> Type text
            </Button>
            <Button size="sm" onClick={toggleFullscreen} disabled={phase !== 'connected'}>
              {fullscreen ? <Minimize /> : <Maximize />} {fullscreen ? 'Exit full screen' : 'Full screen'}
            </Button>
          </div>
        </div>
        {typing && controlling ? (
          <form
            className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2"
            onSubmit={(e) => {
              e.preventDefault()
              sendText()
            }}
          >
            <Label htmlFor="rd-text" className="text-xs text-fg-muted">
              Text to type on the device
            </Label>
            <Input id="rd-text" autoFocus value={typed} maxLength={4096} onChange={(e) => setTyped(e.target.value)} className="max-w-md flex-1" placeholder="Typed as keystrokes into the focused window" />
            <Button size="sm" type="submit" disabled={!typed}>
              Send
            </Button>
          </form>
        ) : null}

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-b border-border px-4 py-2 text-xs" aria-live="polite">
          <span className="inline-flex items-center gap-1.5 font-medium">
            <PhaseIcon phase={phase} viewOnly={effViewOnly} />
            {statusText}
          </span>
          {message && (phase === 'ended' || phase === 'consent') ? <span className="text-fg-muted">{message}</span> : null}
          {controlNote && phase === 'connected' ? <span className="font-medium text-warn">{controlNote}</span> : null}
          {phase === 'connected' ? (
            <>
              <span className="tabular text-fg-muted">{stats.fps.toFixed(1)} fps</span>
              <Tooltip content="Time since the agent captured the newest frame. It includes any clock difference between the device and your computer, so treat it as approximate.">
                <span className="tabular text-fg-muted underline decoration-dotted underline-offset-2">{stats.latencyMs == null ? 'latency —' : `~${Math.max(0, stats.latencyMs)} ms behind`}</span>
              </Tooltip>
              {stats.rttMs != null ? <span className="tabular text-fg-muted">server round trip {stats.rttMs} ms</span> : null}
              {frame ? (
                <span className="tabular text-fg-subtle">
                  {frame.w}×{frame.h}
                  {info ? ` of ${info.width}×${info.height}` : ''}
                  {info?.monitors && info.monitors > 1 ? `, ${info.monitors} monitors` : ''}
                </span>
              ) : null}
            </>
          ) : null}
        </div>
        {error ? (
          <p role="alert" className="flex items-start gap-1.5 border-b border-border bg-danger-soft px-4 py-2 text-sm">
            <MonitorX className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
            {error}
          </p>
        ) : null}
        {info?.secure_desktop && phase === 'connected' ? (
          <p className="border-b border-border bg-warn-soft px-4 py-2 text-sm">The device shows the lock screen or a Windows security prompt (UAC). Kestrel cannot capture or control that screen; the picture resumes when it closes.</p>
        ) : null}

        <div
          ref={stageRef}
          className={cn('relative bg-[#0b0d10]', fullscreen ? 'flex h-screen w-screen items-center justify-center' : fit ? 'h-[min(68vh,760px)]' : 'max-h-[75vh] overflow-auto')}
        >
          <canvas
            ref={canvasRef}
            tabIndex={phase === 'connected' ? 0 : -1}
            aria-label={`Remote screen of ${hostname}. ${effViewOnly ? 'View only.' : 'Click to control; keys and mouse go to the device. Press Escape twice to release the keyboard.'}`}
            onFocus={() => setFocused(true)}
            onBlur={onBlur}
            onPointerMove={onPointerMove}
            onPointerDown={onPointerDown}
            onPointerUp={onPointerUp}
            onContextMenu={(e) => phase === 'connected' && e.preventDefault()}
            onKeyDown={onKey(true)}
            onKeyUp={onKey(false)}
            className={cn(
              'block outline-none',
              fit || fullscreen ? 'h-full w-full object-contain' : '',
              phase === 'connected' && frame ? '' : 'invisible',
              focused && controlling ? 'ring-2 ring-accent ring-inset' : '',
              controlling && focused ? 'cursor-crosshair' : controlling ? 'cursor-pointer' : 'cursor-default',
            )}
            style={!fit && !fullscreen && frame ? { width: frame.w, height: frame.h } : undefined}
          />
          {phase !== 'connected' || !frame ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center gap-2 p-6 text-center text-sm text-[#c9ced6]">
              {live || phase === 'checking' ? (
                <>
                  <Loader2 className="size-6 animate-spin" aria-hidden />
                  <span>{statusText}</span>
                  {phase === 'consent' && message ? <span className="max-w-md text-xs text-[#8b93a1]">{message} The employee sees an Allow / Deny prompt with your name and reason.</span> : null}
                </>
              ) : (
                <>
                  <MonitorPlay className="size-8 text-[#8b93a1]" aria-hidden />
                  <span className="max-w-md">
                    {phase === 'ended' ? (message ?? 'Session ended.') : `Connect to see ${hostname}'s screen. ${viewOnly ? 'You start in view-only mode; switch it off to take control.' : 'You start in control mode.'}`}
                  </span>
                </>
              )}
            </div>
          ) : null}
          {phase === 'connected' && frame ? (
            <div className="pointer-events-none absolute bottom-2 left-2 rounded bg-black/70 px-2 py-1 text-xs text-white">
              {effViewOnly ? (
                <span className="inline-flex items-center gap-1">
                  <Eye className="size-3.5" aria-hidden /> {awaitingControl != null ? 'Waiting for the employee to allow control. Your mouse and keys are not sent yet' : 'View only, your mouse and keys are not sent'}
                </span>
              ) : focused ? (
                <span className="inline-flex items-center gap-1">
                  <Keyboard className="size-3.5" aria-hidden /> In control. Press Esc twice to release the keyboard
                </span>
              ) : (
                <span className="inline-flex items-center gap-1">
                  <MousePointer2 className="size-3.5" aria-hidden /> Click the screen to control it
                </span>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  )
}

function PhaseIcon({ phase, viewOnly }: { phase: DesktopPhase; viewOnly: boolean }) {
  if (phase === 'connected') return viewOnly ? <Eye className="size-3.5 text-accent-text" aria-hidden /> : <MousePointer2 className="size-3.5 text-ok" aria-hidden />
  if (phase === 'ended') return <MonitorX className="size-3.5 text-fg-subtle" aria-hidden />
  if (phase === 'idle') return <Plug className="size-3.5 text-fg-subtle" aria-hidden />
  return <Loader2 className="size-3.5 animate-spin" aria-hidden />
}

function SelectField({ id, label, value, options, suffix = '', onChange }: { id: string; label: string; value: number; options: number[]; suffix?: string; onChange: (v: number) => void }) {
  return (
    <div className="space-y-1">
      <Label htmlFor={id} className="text-xs text-fg-muted">
        {label}
      </Label>
      <select id={id} value={value} onChange={(e) => onChange(Number(e.target.value))} className={selectClass}>
        {options.map((o) => (
          <option key={o} value={o}>
            {o}
            {suffix}
          </option>
        ))}
      </select>
    </div>
  )
}

/** Session limits of the effective profile in words (0 = no limit). */
export function limitsText(p: RemoteAccessProfile): string {
  const { idle_timeout_minutes: idle, max_session_minutes: max } = p.guardrails
  const parts = [idle ? `after ${idle} minutes without activity` : null, max ? `after ${max} minutes in total` : null].filter(Boolean)
  return parts.length ? `This device ends sessions ${parts.join(' and ')}.` : 'This device sets no session time limit.'
}
