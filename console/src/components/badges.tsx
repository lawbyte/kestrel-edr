import { AlertOctagon, AlertTriangle, Circle, ChevronDown, Info, ShieldCheck, ShieldAlert, ShieldX, ShieldQuestion, Wifi, WifiOff, Activity, Lock, CheckCircle2, XCircle, Clock, Send, Hourglass, FolderDown, FolderClock, FolderOpen, Network, HardDrive, Download, SquareTerminal, KeyRound, Globe, Upload, Radar, ShieldOff, FileCode2, FileLock2, Fingerprint, Anchor, Bird, Sunrise, Pin, CircleDashed, Rocket, OctagonPause } from 'lucide-react'
import type { ActionStatus, DeviceStatus, GroupUpdateRing, UpdateReleaseState, IncidentStatus, PathClass, RuleCategory, RuleMode, Severity, SignatureState } from '@/api/types'
import { ACTION_STATUS_LABEL, DEVICE_STATUS_LABEL, INCIDENT_STATUS_LABEL, PATH_CLASS_LABEL, RULE_CATEGORY_LABEL, SEVERITY_LABEL, SIGNATURE_LABEL } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { RELEASE_STATE_LABEL, RING_HINT, RING_LABEL } from '@/lib/updates'
import { Tooltip } from './ui/misc'
import type { ReactNode } from 'react'

const SEV_STYLE: Record<Severity, { icon: typeof AlertOctagon; text: string; bg: string }> = {
  critical: { icon: AlertOctagon, text: 'text-sev-critical', bg: 'bg-sev-critical-soft' },
  high: { icon: AlertTriangle, text: 'text-sev-high', bg: 'bg-sev-high-soft' },
  medium: { icon: Circle, text: 'text-sev-medium', bg: 'bg-sev-medium-soft' },
  low: { icon: ChevronDown, text: 'text-sev-low', bg: 'bg-sev-low-soft' },
  info: { icon: Info, text: 'text-sev-info', bg: 'bg-sev-info-soft' },
}

/** Severity is always icon + label (never colour alone). */
export function SeverityBadge({ severity, compact, className }: { severity: Severity; compact?: boolean; className?: string }) {
  const s = SEV_STYLE[severity]
  const Icon = s.icon
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs font-medium', s.text, s.bg, className)}>
      <Icon className={cn('size-3.5', severity === 'medium' && 'size-3 fill-current')} strokeWidth={2.25} aria-hidden />
      {compact ? <span className="sr-only">{SEVERITY_LABEL[severity]}</span> : SEVERITY_LABEL[severity]}
    </span>
  )
}

export function SeverityIcon({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEV_STYLE[severity]
  const Icon = s.icon
  return <Icon aria-label={SEVERITY_LABEL[severity]} className={cn('size-4', s.text, severity === 'medium' && 'size-3.5 fill-current', className)} strokeWidth={2.25} />
}

export function PriorityScore({ value, className }: { value: number; className?: string }) {
  const tone = value >= 85 ? 'text-sev-critical' : value >= 60 ? 'text-sev-high' : value >= 30 ? 'text-fg' : 'text-fg-subtle'
  return (
    <span className={cn('inline-flex items-center gap-1.5 tabular font-medium', tone, className)} title={`Priority ${value} of 100`}>
      <span className="relative h-1.5 w-8 overflow-hidden rounded-full bg-surface-3" aria-hidden>
        <span className="absolute inset-y-0 left-0 rounded-full bg-current" style={{ width: `${value}%` }} />
      </span>
      {value}
    </span>
  )
}

const DEV_STYLE: Record<DeviceStatus, { dot: string; icon: typeof Wifi }> = {
  online: { dot: 'bg-ok', icon: Wifi },
  offline: { dot: 'bg-fg-subtle', icon: WifiOff },
  degraded: { dot: 'bg-warn', icon: Activity },
  isolated: { dot: 'bg-isolated', icon: Lock },
}
export function DeviceStatusBadge({ status, className }: { status: DeviceStatus; className?: string }) {
  const s = DEV_STYLE[status]
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-sm', className)}>
      <span className="relative flex size-2">
        {status === 'online' && <span className="absolute inset-0 animate-ping rounded-full bg-ok opacity-30 [animation-duration:2.5s]" />}
        <span className={cn('relative size-2 rounded-full', s.dot, status === 'offline' && 'bg-transparent ring-[1.5px] ring-fg-subtle ring-inset')} />
      </span>
      <span className={cn(status === 'isolated' && 'text-isolated font-medium', status === 'degraded' && 'text-warn font-medium', status === 'offline' && 'text-fg-muted')}>{DEVICE_STATUS_LABEL[status]}</span>
    </span>
  )
}

const INC_STATUS: Record<IncidentStatus, string> = {
  open: 'text-fg border-border-strong',
  in_progress: 'text-accent-text border-accent/40 bg-accent-soft',
  resolved: 'text-ok border-ok/30 bg-ok-soft',
  dismissed: 'text-fg-muted border-border',
}
export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-xs font-medium', INC_STATUS[status])}>
      <span className={cn('size-1.5 rounded-full', status === 'open' ? 'bg-fg' : status === 'in_progress' ? 'bg-accent' : status === 'resolved' ? 'bg-ok' : 'bg-fg-subtle')} aria-hidden />
      {INCIDENT_STATUS_LABEL[status]}
    </span>
  )
}

const ACT: Record<ActionStatus, { icon: typeof Clock; cls: string }> = {
  pending: { icon: Hourglass, cls: 'text-fg-muted' },
  sent: { icon: Send, cls: 'text-accent-text' },
  succeeded: { icon: CheckCircle2, cls: 'text-ok' },
  failed: { icon: XCircle, cls: 'text-danger' },
  expired: { icon: Clock, cls: 'text-fg-subtle' },
}
export function ActionStatusBadge({ status }: { status: ActionStatus }) {
  const s = ACT[status]
  const Icon = s.icon
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap text-sm font-medium', s.cls)}>
      <Icon className={cn('size-3.5', status === 'sent' && 'animate-pulse')} aria-hidden />
      {ACTION_STATUS_LABEL[status]}
    </span>
  )
}

export function SignerBadge({ signed, signer, className }: { signed: SignatureState | undefined; signer?: string | null; className?: string }) {
  const s = signed ?? 'unknown'
  const Icon = s === 'valid' ? ShieldCheck : s === 'invalid' ? ShieldX : s === 'unsigned' ? ShieldAlert : ShieldQuestion
  const cls = s === 'valid' ? 'text-ok bg-ok-soft' : s === 'invalid' ? 'text-danger bg-danger-soft' : s === 'unsigned' ? 'text-warn bg-warn-soft' : 'text-fg-muted bg-surface-2'
  const label = s === 'valid' ? (signer ?? 'Signed') : s === 'invalid' ? `Invalid${signer ? ` (${signer})` : ''}` : SIGNATURE_LABEL[s]
  return (
    <Tooltip content={s === 'valid' ? `Valid signature: ${signer ?? 'unknown publisher'}` : s === 'invalid' ? `Signature is present but invalid, revoked or self-signed${signer ? ` — claims “${signer}”` : ''}` : SIGNATURE_LABEL[s]}>
      <span className={cn('inline-flex max-w-56 items-center gap-1 truncate whitespace-nowrap rounded px-1.5 py-px text-[11px] font-medium', cls, className)}>
        <Icon className="size-3 shrink-0" aria-hidden />
        <span className="truncate">{label}</span>
      </span>
    </Tooltip>
  )
}

export function PathClassBadge({ pathClass, className }: { pathClass: PathClass; className?: string }) {
  const risky = pathClass === 'temp' || pathClass === 'downloads' || pathClass === 'user_writable' || pathClass === 'external'
  if (pathClass === 'system' || pathClass === 'program_files' || pathClass === 'windows' || pathClass === 'other') {
    return <span className={cn('inline-flex items-center gap-1 rounded px-1.5 py-px text-[11px] text-fg-muted bg-surface-2', className)}><HardDrive className="size-3" aria-hidden />{PATH_CLASS_LABEL[pathClass]}</span>
  }
  const Icon = pathClass === 'downloads' ? FolderDown : pathClass === 'temp' ? FolderClock : pathClass === 'external' ? Network : FolderOpen
  return (
    <Tooltip content="Runs from a folder any user can write to — a strong stealer signal">
      <span className={cn('inline-flex items-center gap-1 rounded px-1.5 py-px text-[11px] font-medium', risky ? 'bg-sev-high-soft text-sev-high' : 'bg-surface-2 text-fg-muted', className)}>
        <Icon className="size-3" aria-hidden />
        {PATH_CLASS_LABEL[pathClass]}
      </span>
    </Tooltip>
  )
}

export function ModeBadge({ mode }: { mode: RuleMode }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded px-1.5 py-px text-[11px] font-medium',
        mode === 'protect' ? 'bg-accent-soft text-accent-text' : mode === 'audit' ? 'bg-surface-2 text-fg-muted' : 'bg-surface-2 text-fg-subtle line-through',
      )}
    >
      {mode === 'protect' ? 'Protect' : mode === 'audit' ? 'Audit' : 'Off'}
    </span>
  )
}

export function Chip({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-border bg-surface-2 px-1.5 py-px text-xs text-fg-muted', className)}>
      {children}
    </span>
  )
}

const CATEGORY_ICON: Record<RuleCategory, typeof AlertOctagon> = {
  delivery: Download,
  execution: SquareTerminal,
  credential_access: KeyRound,
  browser_tampering: Globe,
  exfiltration: Upload,
  tripwire: Radar,
  tamper: ShieldOff,
  custom: FileCode2,
  ransomware: FileLock2,
  credential_dumping: Fingerprint,
  persistence: Anchor,
}

/** Rule category as icon + label (never colour alone). */
export function CategoryBadge({ category, className, iconOnly }: { category: RuleCategory; className?: string; iconOnly?: boolean }) {
  const Icon = CATEGORY_ICON[category] ?? FileCode2
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-sm text-fg-muted', className)}>
      <Icon className="size-3.5 shrink-0" aria-hidden />
      {iconOnly ? <span className="sr-only">{RULE_CATEGORY_LABEL[category]}</span> : RULE_CATEGORY_LABEL[category]}
    </span>
  )
}

const RING_ICON: Record<GroupUpdateRing, typeof Bird> = { canary: Bird, early: Sunrise, broad: Globe, pinned: Pin }
/** Update ring: icon + label. */
export function RingBadge({ ring, className }: { ring: GroupUpdateRing; className?: string }) {
  const Icon = RING_ICON[ring]
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-md bg-surface-2 px-1.5 py-0.5 text-xs font-medium text-fg-muted', className)} title={RING_HINT[ring]}>
      <Icon className="size-3.5" aria-hidden />
      {RING_LABEL[ring]}
    </span>
  )
}

const RELEASE_STATE: Record<UpdateReleaseState, { icon: typeof Bird; cls: string }> = {
  staged: { icon: CircleDashed, cls: 'text-fg-muted border-border' },
  rolling: { icon: Rocket, cls: 'text-accent-text border-accent/40 bg-accent-soft' },
  complete: { icon: CheckCircle2, cls: 'text-ok border-ok/30 bg-ok-soft' },
  halted: { icon: OctagonPause, cls: 'text-danger border-danger/30 bg-danger-soft' },
}
/** Release state is always icon + label (never colour alone). */
export function ReleaseStateBadge({ state }: { state: UpdateReleaseState }) {
  const s = RELEASE_STATE[state]
  const Icon = s.icon
  return (
    <span className={cn('inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-px text-xs font-medium', s.cls)}>
      <Icon className="size-3.5" aria-hidden />
      {RELEASE_STATE_LABEL[state]}
    </span>
  )
}
