import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronRight, CircleArrowUp, KeyRound, OctagonPause, PackageCheck, PackagePlus, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { UpdateRelease, UpdateRing, UpdateRingHealth, UpdateRingSummary, UpdateStatus } from '@/api/types'
import { ReleaseStateBadge, RingBadge } from '@/components/badges'
import { Card, EmptyState, ErrorState, KeyValue, LoadingRows, Mono, PageHeader } from '@/components/common'
import { CopyButton } from '@/components/copy-button'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Textarea } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { formatDateTime, shortHash, timeAgo } from '@/lib/format'
import { RING_HINT, RING_LABEL, parseManifest } from '@/lib/updates'
import { cn } from '@/lib/utils'

export default function UpdatesPage() {
  const { can } = useAuth()
  const status = useQuery({ queryKey: qk.updateStatus, queryFn: api.updateStatus })
  const releases = useQuery({ queryKey: qk.updateReleases, queryFn: api.updateReleases })
  const [registering, setRegistering] = useState(false)
  const [promote, setPromote] = useState<{ release: UpdateRelease; ring: UpdateRing } | null>(null)
  const [halt, setHalt] = useState<UpdateRelease | null>(null)
  const writable = can('updates.write')

  return (
    <div className="min-h-full">
      <PageHeader
        title="Agent updates"
        description={
          <>
            Releases are signed offline with Ed25519 (<code className="text-xs">kestrel-agent update-sign</code>); this server only verifies the signature and distributes the manifest. Each agent verifies the signature again with the key built into it, checks the package SHA-256 and runs msiexec. Promote a release canary → early → broad and watch each ring’s health before the next. Halting stops further delivery; it does not roll back agents that already updated.
          </>
        }
        actions={
          writable ? (
            <Button variant="primary" onClick={() => setRegistering(true)}>
              <PackagePlus /> Register release
            </Button>
          ) : null
        }
      />
      <div className="space-y-6 p-6">
        {status.error ? (
          <ErrorState error={status.error} onRetry={() => status.refetch()} />
        ) : !status.data ? (
          <LoadingRows rows={4} />
        ) : (
          <>
            <SigningKeyCard status={status.data} />
            <RingOverview rings={status.data.rings} />
          </>
        )}
        <section aria-labelledby="releases-h" className="space-y-3">
          <h2 id="releases-h" className="text-sm font-semibold">
            Releases
          </h2>
          {releases.error ? (
            <ErrorState error={releases.error} onRetry={() => releases.refetch()} />
          ) : !releases.data ? (
            <LoadingRows rows={6} />
          ) : releases.data.length === 0 ? (
            <Card>
              <EmptyState icon={PackageCheck} title="No releases registered" action={writable ? <Button onClick={() => setRegistering(true)}><PackagePlus /> Register release</Button> : null}>
                Sign a release offline with <code className="text-xs">kestrel-agent update-sign</code>, then paste the manifest it prints here.
              </EmptyState>
            </Card>
          ) : (
            releases.data.map((r) => <ReleaseCard key={r.id} release={r} writable={writable} onPromote={(ring) => setPromote({ release: r, ring })} onHalt={() => setHalt(r)} />)
          )}
        </section>
      </div>
      {registering ? <RegisterDialog status={status.data} onClose={() => setRegistering(false)} /> : null}
      {promote ? <PromoteDialog release={promote.release} ring={promote.ring} summary={status.data?.rings.find((x) => x.ring === promote.ring)} onClose={() => setPromote(null)} /> : null}
      {halt ? <HaltDialog release={halt} onClose={() => setHalt(null)} /> : null}
    </div>
  )
}

function SigningKeyCard({ status }: { status: UpdateStatus }) {
  return (
    <Card title="Signing key and packages" bodyClassName="space-y-4">
      {status.signing_key_configured ? (
        <div className="flex items-start gap-2.5">
          <ShieldCheck className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
          <div className="min-w-0 space-y-1 text-sm">
            <p className="font-medium">Update signing key configured</p>
            {status.public_key ? (
              <p className="flex flex-wrap items-center gap-1 text-xs text-fg-muted">
                Ed25519 public key <Mono className="text-[11.5px]">{status.public_key}</Mono>
                <CopyButton text={status.public_key} iconOnly label="Copy public key" />
              </p>
            ) : null}
            <p className="text-xs text-fg-muted">It must match the key built into the agents, or they will refuse every release.</p>
          </div>
        </div>
      ) : (
        <div className="flex items-start gap-2.5 rounded-md border border-warn/40 bg-warn-soft p-3" role="status">
          <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
          <div className="space-y-1 text-sm">
            <p className="font-medium">No update signing key configured: releases cannot be registered</p>
            <p className="text-xs text-fg-muted">
              Set <code>KESTREL_UPDATE_PUBKEY</code> on the server to the base64 Ed25519 public key that matches your offline signing key, then restart the server. See <code>docs/BUILDING.md</code> (signed agent updates).
            </p>
          </div>
        </div>
      )}
      <div className="flex items-start gap-2.5">
        <KeyRound className="mt-0.5 size-4 shrink-0 text-fg-subtle" aria-hidden />
        <div className="min-w-0 flex-1 space-y-1 text-sm">
          <p className="font-medium">Package location</p>
          <p className="text-xs text-fg-muted">Packages hosted by this server are served from this address; use it as the start of the manifest’s url when you sign. Agents only download over HTTPS.</p>
          <div className="flex flex-wrap items-center gap-2">
            <Mono className="rounded border border-border bg-surface-2 px-2 py-1 text-[12px]">{status.package_base_url}</Mono>
            <CopyButton text={status.package_base_url} label="Copy URL" />
          </div>
        </div>
        <span className="shrink-0 text-xs text-fg-subtle">Server {status.server_version}</span>
      </div>
    </Card>
  )
}

function RingOverview({ rings }: { rings: UpdateRingSummary[] }) {
  return (
    <section aria-labelledby="rings-h" className="space-y-3">
      <h2 id="rings-h" className="text-sm font-semibold">
        Update rings
      </h2>
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {rings.map((r) => {
          const max = Math.max(1, ...r.versions.map((v) => v.count))
          return (
            <section key={r.ring} aria-label={`${RING_LABEL[r.ring]} ring`} className="flex flex-col gap-3 rounded-lg border border-border bg-surface p-4">
              <div className="flex items-center justify-between gap-2">
                <RingBadge ring={r.ring} className="text-sm" />
                <span className="text-xs tabular text-fg-muted">{r.devices} devices</span>
              </div>
              <p className="text-xs text-fg-muted">{RING_HINT[r.ring]}</p>
              <div className="text-xs">
                <span className="text-fg-subtle">Groups: </span>
                {r.groups.length ? r.groups.map((g) => g.name).join(', ') : <span className="text-fg-subtle">none</span>}
              </div>
              <div className="text-xs">
                <span className="text-fg-subtle">Target: </span>
                {r.ring === 'pinned' ? (
                  <span className="text-fg-muted">never auto-updates</span>
                ) : r.target ? (
                  <span className="font-mono font-medium">{r.target.version}</span>
                ) : (
                  <span className="text-fg-muted">no release enabled</span>
                )}
              </div>
              {r.versions.length ? (
                <ul className="space-y-1" aria-label="Agent versions">
                  {r.versions.map((v) => (
                    <li key={v.version} className="flex items-center gap-2 text-xs">
                      <span className="w-16 shrink-0 font-mono">{v.version}</span>
                      <span className="relative h-1.5 flex-1 overflow-hidden rounded-full bg-surface-3" aria-hidden>
                        <span className={cn('absolute inset-y-0 left-0 rounded-full', r.target && v.version === r.target.version ? 'bg-ok' : 'bg-fg-subtle')} style={{ width: `${(v.count / max) * 100}%` }} />
                      </span>
                      <span className="w-8 shrink-0 text-right tabular text-fg-muted">{v.count}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-fg-subtle">No devices.</p>
              )}
            </section>
          )
        })}
      </div>
    </section>
  )
}

function ReleaseCard({ release: r, writable, onPromote, onHalt }: { release: UpdateRelease; writable: boolean; onPromote: (ring: UpdateRing) => void; onHalt: () => void }) {
  return (
    <section aria-label={`Release ${r.version}`} className="rounded-lg border border-border bg-surface">
      <header className="flex flex-wrap items-start gap-3 border-b border-border px-4 py-3">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="font-mono text-base font-semibold">{r.version}</h3>
            <ReleaseStateBadge state={r.state} />
          </div>
          <p className="text-xs text-fg-muted">
            Registered by {r.created_by_name ?? 'unknown'} <span title={formatDateTime(r.created_at)}>{timeAgo(r.created_at)}</span>
          </p>
          {r.notes ? <p className="max-w-3xl whitespace-pre-wrap text-sm">{r.notes}</p> : null}
        </div>
        {writable && r.state !== 'halted' ? (
          <div className="flex shrink-0 flex-wrap gap-1.5">
            {r.next_ring ? (
              <Button size="sm" variant="primary" onClick={() => onPromote(r.next_ring!)}>
                <CircleArrowUp /> Promote to {RING_LABEL[r.next_ring].toLowerCase()}
              </Button>
            ) : null}
            <Button size="sm" variant="danger-outline" onClick={onHalt}>
              <OctagonPause /> Halt
            </Button>
          </div>
        ) : null}
      </header>
      <div className="space-y-4 px-4 py-3">
        {r.state === 'halted' ? (
          <p className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-sm" role="note">
            <OctagonPause className="mt-0.5 size-4 shrink-0 text-danger" aria-hidden />
            <span>
              Halted by {r.halted_by_name ?? 'unknown'} <span title={formatDateTime(r.halted_at)}>{timeAgo(r.halted_at)}</span>
              {r.halt_reason ? `: ${r.halt_reason}` : '.'} No further devices receive it; agents that already installed it keep it.
            </span>
          </p>
        ) : null}
        <KeyValue
          cols={2}
          items={[
            [
              'Package',
              <span key="u" className="inline-flex max-w-full items-center gap-1">
                <Mono className="text-[12px]">{r.url}</Mono>
                <CopyButton text={r.url} iconOnly label="Copy package URL" />
              </span>,
            ],
            [
              'SHA-256',
              <span key="h" className="inline-flex items-center gap-1">
                <Mono className="text-[12px]" title={r.sha256}>
                  {shortHash(r.sha256, 24)}
                </Mono>
                <CopyButton text={r.sha256} iconOnly label="Copy SHA-256" />
              </span>,
            ],
          ]}
        />
        <RingHealthTable rings={r.rings} />
        <FailureList release={r} />
      </div>
    </section>
  )
}

const HEALTH_COLS: { key: keyof UpdateRingHealth; label: string; hint: string }[] = [
  { key: 'devices', label: 'Devices', hint: 'Devices whose group is in this ring' },
  { key: 'on_target', label: 'On target', hint: 'Already running this version or newer' },
  { key: 'delivered', label: 'Delivered', hint: 'The server sent this release to the device' },
  { key: 'succeeded', label: 'Succeeded', hint: 'The device later reported the new version' },
  { key: 'failed', label: 'Failed', hint: 'The agent reported an update failure' },
  { key: 'pending', label: 'Pending', hint: 'Delivered, no result yet' },
  { key: 'offline_24h', label: 'Offline >24 h', hint: 'Delivered, not updated, device not seen for more than 24 hours' },
]

function RingHealthTable({ rings }: { rings: UpdateRingHealth[] }) {
  return (
    <div className="overflow-x-auto rounded-md border border-border">
      <table className="w-full min-w-[720px] text-sm">
        <caption className="sr-only">Health per ring</caption>
        <thead className="bg-surface-2 text-xs text-fg-subtle">
          <tr>
            <th scope="col" className="px-3 py-1.5 text-left font-medium">
              Ring
            </th>
            <th scope="col" className="px-3 py-1.5 text-left font-medium">
              Enabled
            </th>
            {HEALTH_COLS.map((c) => (
              <th key={c.key} scope="col" className="px-3 py-1.5 text-right font-medium" title={c.hint}>
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {rings.map((h) => (
            <tr key={h.ring} className={cn(!h.enabled && 'text-fg-muted')}>
              <th scope="row" className="px-3 py-1.5 text-left font-normal">
                <RingBadge ring={h.ring} />
              </th>
              <td className="whitespace-nowrap px-3 py-1.5 text-xs">
                {h.enabled ? (
                  <span className="inline-flex items-center gap-1" title={formatDateTime(h.enabled_at)}>
                    <ShieldCheck className="size-3.5 text-ok" aria-hidden />
                    <span>
                      Enabled {timeAgo(h.enabled_at)}
                      {h.enabled_by_name ? ` by ${h.enabled_by_name}` : ''}
                    </span>
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1">
                    <span className="size-3.5 rounded-full border border-dashed border-fg-subtle" aria-hidden />
                    Not enabled
                  </span>
                )}
              </td>
              {HEALTH_COLS.map((c) => {
                const v = h[c.key] as number
                const alarm = (c.key === 'failed' || c.key === 'offline_24h') && v > 0
                return (
                  <td key={c.key} className={cn('px-3 py-1.5 text-right tabular', alarm && 'font-semibold text-danger')}>
                    {alarm ? <AlertTriangle className="mr-1 inline size-3.5 align-[-2px]" aria-label="Needs attention" /> : null}
                    {v}
                    {c.key === 'on_target' && h.devices > 0 ? <span className="ml-1 text-xs font-normal text-fg-subtle">({Math.round((v / h.devices) * 100)}%)</span> : null}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FailureList({ release }: { release: UpdateRelease }) {
  const [open, setOpen] = useState(false)
  const n = release.recent_failures.length
  if (!n) return null
  return (
    <div>
      <button type="button" className="inline-flex items-center gap-1 text-sm font-medium text-danger hover:underline" aria-expanded={open} onClick={() => setOpen((o) => !o)}>
        <ChevronRight className={cn('size-4 transition-transform', open && 'rotate-90')} aria-hidden />
        {n} recent failure{n === 1 ? '' : 's'}
      </button>
      {open ? (
        <ul className="mt-2 divide-y divide-border rounded-md border border-border">
          {release.recent_failures.map((f) => (
            <li key={`${f.device_id}-${f.at}`} className="flex flex-wrap items-start gap-x-3 gap-y-1 px-3 py-2 text-sm">
              <Link to={`/devices/${f.device_id}`} className="font-mono text-[13px] hover:underline">
                {f.hostname}
              </Link>
              <span className="min-w-0 flex-1 break-words font-mono text-[12px] text-fg-muted">{f.error}</span>
              <span className="text-xs text-fg-subtle" title={formatDateTime(f.at)}>
                {timeAgo(f.at)}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

function useInvalidateUpdates() {
  const qc = useQueryClient()
  return () => void qc.invalidateQueries({ queryKey: ['updates'] })
}

function PromoteDialog({ release: r, ring, summary, onClose }: { release: UpdateRelease; ring: UpdateRing; summary?: UpdateRingSummary; onClose: () => void }) {
  const invalidate = useInvalidateUpdates()
  const health = r.rings.find((x) => x.ring === ring)
  const needs = health ? health.devices - health.on_target : 0
  const prev = r.rings[r.rings.findIndex((x) => x.ring === ring) - 1]
  const prevTrouble = prev && (prev.failed > 0 || prev.pending > 0)
  const m = useMutation({
    mutationFn: () => api.promoteRelease(r.id, ring),
    onSuccess: (out) => {
      toast.success(`${r.version} enabled for the ${ring} ring`, { description: `Sent to ${out.delivered_now} connected device${out.delivered_now === 1 ? '' : 's'} now; the rest get it on their next connection.` })
      invalidate()
      onClose()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="md"
        title={`Promote ${r.version} to the ${ring} ring?`}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={m.isPending} onClick={() => m.mutate()}>
              <CircleArrowUp /> Promote to {ring}
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <p>
            Deliver <span className="font-mono font-medium">{r.version}</span> to {needs} device{needs === 1 ? '' : 's'} in the {ring} ring now; connected agents get it immediately, others on their next connection.
          </p>
          {summary?.groups.length ? <p className="text-fg-muted">Groups in this ring: {summary.groups.map((g) => g.name).join(', ')}.</p> : <p className="text-fg-muted">No groups are in this ring yet; the release will reach devices once a group is moved into it.</p>}
          <p className="text-fg-muted">Each agent verifies the signature and SHA-256 before running msiexec. This cannot be undone: halting later stops further delivery but does not roll back devices that already updated.</p>
          {prevTrouble ? (
            <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2" role="note">
              <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
              <span>
                The {prev.ring} ring still has {prev.failed} failed and {prev.pending} pending device{prev.failed + prev.pending === 1 ? '' : 's'}. Review them before promoting.
              </span>
            </p>
          ) : null}
          {m.error ? (
            <p className="text-sm text-danger" role="alert">
              {(m.error as Error).message}
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}

function HaltDialog({ release: r, onClose }: { release: UpdateRelease; onClose: () => void }) {
  const invalidate = useInvalidateUpdates()
  const [reason, setReason] = useState('')
  const updated = r.rings.reduce((n, x) => n + x.succeeded, 0)
  const m = useMutation({
    mutationFn: () => api.haltRelease(r.id, reason.trim() || undefined),
    onSuccess: () => {
      toast.success(`${r.version} halted`)
      invalidate()
      onClose()
    },
  })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="md"
        title={`Halt ${r.version}?`}
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="danger" disabled={m.isPending} onClick={() => m.mutate()}>
              <OctagonPause /> Halt release
            </Button>
          </>
        }
      >
        <div className="space-y-3 text-sm">
          <p>
            The server stops delivering <span className="font-mono font-medium">{r.version}</span> to any further device, in every ring. Halting is final; to continue, sign and register a newer release.
          </p>
          <p className="text-fg-muted">
            It does not roll back: the {updated} device{updated === 1 ? '' : 's'} that already updated keep running {r.version}.
          </p>
          <Field label="Reason (optional)" htmlFor="halt-reason" hint="Shown on the release and recorded in the audit log.">
            <Textarea id="halt-reason" value={reason} maxLength={2000} onChange={(e) => setReason(e.target.value)} placeholder="e.g. service fails to start on Windows 10 22H2" />
          </Field>
          {m.error ? (
            <p className="text-sm text-danger" role="alert">
              {(m.error as Error).message}
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}

const MANIFEST_PLACEHOLDER = `{
  "version": "1.4.0",
  "url": "https://kestrel.example.com:8443/downloads/updates/kestrel-agent-1.4.0-x64.msi",
  "sha256": "…64 hex characters…",
  "signature": "…base64 Ed25519…"
}`

function RegisterDialog({ status, onClose }: { status?: UpdateStatus; onClose: () => void }) {
  const invalidate = useInvalidateUpdates()
  const [text, setText] = useState('')
  const [notes, setNotes] = useState('')
  const parsed = useMemo(() => (text.trim() ? parseManifest(text) : null), [text])
  const m = useMutation({
    mutationFn: () => {
      if (!parsed?.ok) throw new Error('Fix the manifest first')
      return api.registerRelease({ manifest: parsed.manifest, notes: notes.trim() || undefined })
    },
    onSuccess: (r) => {
      toast.success(`Release ${r.version} registered`, { description: 'No ring is enabled yet. Promote it to canary when you are ready.' })
      invalidate()
      onClose()
    },
  })
  const baseMismatch = parsed?.ok && status?.package_base_url && !parsed.manifest.url.startsWith(status.package_base_url)
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="lg"
        title="Register release"
        description="Paste the manifest JSON printed by kestrel-agent update-sign. The server verifies the signature against its configured key; nothing is delivered until you promote a ring."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" disabled={!parsed?.ok || m.isPending} onClick={() => m.mutate()}>
              <PackagePlus /> Register
            </Button>
          </>
        }
      >
        <div className="space-y-4">
          {status && !status.signing_key_configured ? (
            <p className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm" role="note">
              <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
              <span>
                The server has no update signing key (<code>KESTREL_UPDATE_PUBKEY</code>), so it will reject every release until one is configured.
              </span>
            </p>
          ) : null}
          <Field label="Manifest JSON" htmlFor="rel-manifest" error={parsed && !parsed.ok ? parsed.error : null}>
            <Textarea
              id="rel-manifest"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={MANIFEST_PLACEHOLDER}
              spellCheck={false}
              aria-invalid={parsed ? !parsed.ok : undefined}
              className="min-h-40 font-mono text-[12px]"
            />
          </Field>
          {parsed?.ok ? (
            <div className="space-y-2 rounded-md border border-border bg-surface-2 p-3">
              <p className="flex items-center gap-1.5 text-xs font-medium text-ok">
                <ShieldCheck className="size-3.5" aria-hidden /> Format OK (the server checks the signature)
              </p>
              <KeyValue
                cols={1}
                items={[
                  ['Version', <Mono key="v">{parsed.manifest.version}</Mono>],
                  ['Package URL', <Mono key="u">{parsed.manifest.url}</Mono>],
                  ['SHA-256', <Mono key="h">{parsed.manifest.sha256}</Mono>],
                ]}
              />
              {baseMismatch ? <p className="text-xs text-fg-muted">The URL is not under this server’s package location ({status?.package_base_url}). That is fine if agents can reach it over HTTPS.</p> : null}
            </div>
          ) : null}
          <Field label="Release notes (optional)" htmlFor="rel-notes">
            <Textarea id="rel-notes" value={notes} maxLength={4000} onChange={(e) => setNotes(e.target.value)} placeholder="What changed, known issues" />
          </Field>
          {m.error ? (
            <p className="flex items-start gap-2 rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-sm text-danger" role="alert">
              <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
              <span>{(m.error as Error).message}</span>
            </p>
          ) : null}
        </div>
      </DialogContent>
    </Dialog>
  )
}
