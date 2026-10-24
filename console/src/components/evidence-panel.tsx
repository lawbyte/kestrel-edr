import { useQuery } from '@tanstack/react-query'
import { ChevronRight, Download, FileSearch, Info, RotateCcw, Trash2, UploadCloud } from 'lucide-react'
import { Fragment, useState, type ReactNode } from 'react'
import { api, qk } from '@/api/endpoints'
import type { EvidenceBundle, EvidenceManifest, EvidenceStatus, FileCopy } from '@/api/types'
import { useAuth } from '@/lib/auth'
import { bundleActions, copyStatusOf, EVIDENCE_PRIVILEGE, EVIDENCE_STATUS, evidenceErrorText, formatPcapFilter, manifestSummary, PCAP_LIMITATIONS, PCAP_STATUS, PROCESS_ROLE_LABEL, retentionText, statusDescription, TONE_CLASS, WRITE_OP_LABEL } from '@/lib/evidence'
import { DATA_CATEGORY_LABEL } from '@/lib/labels'
import { formatBytes, formatDateTime, formatTime, safeDisplay, shortHash } from '@/lib/format'
import { basename, cn } from '@/lib/utils'
import { Card } from './common'
import { CollectEvidenceDialog, DeleteEvidenceDialog, DownloadEvidenceDialog } from './evidence-dialogs'
import { ReauthProvider } from './remote/reauth'
import { Button, type ButtonProps } from './ui/button'
import { Tooltip } from './ui/misc'

/** Bundle status as icon + label (never colour alone). */
export function EvidenceStatusBadge({ status, className }: { status: EvidenceStatus; className?: string }) {
  const s = EVIDENCE_STATUS[status]
  const Icon = s.icon
  return (
    <span className={cn('inline-flex items-center gap-1.5 whitespace-nowrap text-xs font-medium', TONE_CLASS[s.tone], className)}>
      <Icon className={cn('size-3.5 shrink-0', s.spin && 'animate-spin')} strokeWidth={2.25} aria-hidden />
      {s.label}
    </span>
  )
}

/** A button that explains why it is disabled in a tooltip (disabled buttons get no pointer events, so the span carries it). */
function GatedButton({ reason, children, ...p }: ButtonProps & { reason: string | null }) {
  const btn = (
    <Button size="sm" {...p} disabled={!!reason || p.disabled}>
      {children}
    </Button>
  )
  return reason ? (
    <Tooltip content={reason}>
      <span tabIndex={0} aria-label={reason}>
        {btn}
      </span>
    </Tooltip>
  ) : (
    btn
  )
}

/**
 * Evidence bundles of one incident (ST-02 / ST-04 capture): status, retention
 * and the privacy-filtered manifest for every role; collect / download / delete
 * for administrators. Renders nothing when the incident has no bundle.
 */
export function EvidencePanel({ incidentId }: { incidentId: string }) {
  const q = useQuery({ queryKey: qk.incidentEvidence(incidentId), queryFn: () => api.incidentEvidence(incidentId) })
  if (q.error)
    return (
      <Card title="Evidence capture">
        <p className="text-sm text-fg-muted" role="alert">
          Could not load the evidence bundles: {evidenceErrorText(q.error)}{' '}
          <Button size="sm" variant="link" onClick={() => void q.refetch()}>
            Try again
          </Button>
        </p>
      </Card>
    )
  const items = [...(q.data?.items ?? [])].sort((a, b) => b.created_at - a.created_at)
  if (!items.length) return null
  return (
    <Card
      title="Evidence capture"
      description="Copies Kestrel kept after a data-theft alert (ST-02 / ST-04): staged files, the credential stores it read and a 60 s connection capture"
      bodyClassName="p-0"
    >
      {/* Own MFA step-up dialog (collect / download answer 403 reauth_required without a fresh code). */}
      <ReauthProvider>
        <ul className="divide-y divide-border">
          {items.map((b) => (
            <BundleItem key={b.id} b={b} />
          ))}
        </ul>
      </ReauthProvider>
      <p className="flex items-start gap-2 border-t border-border px-4 py-2.5 text-xs text-fg-muted">
        <Info className="mt-0.5 size-3.5 shrink-0" aria-hidden />
        Bundles can contain the employee’s real passwords and cookies. Only administrators can collect, download or delete them, every step is audited, and the employee is told in the tray when evidence is collected. Their contents never go into telemetry or Hunt.
      </p>
    </Card>
  )
}

function BundleItem({ b }: { b: EvidenceBundle }) {
  const { can } = useAuth()
  const [open, setOpen] = useState(false)
  const [dialog, setDialog] = useState<'collect' | 'download' | 'delete' | null>(null)
  const acts = bundleActions(b, can(EVIDENCE_PRIVILEGE))
  const retention = retentionText(b)
  const detailsId = `evidence-${b.id}`
  return (
    <li>
      <div className="flex flex-wrap items-start gap-x-4 gap-y-2 px-4 py-3">
        <button type="button" className="flex min-w-0 flex-1 items-start gap-2 text-left" onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-controls={detailsId}>
          <ChevronRight className={cn('mt-0.5 size-4 shrink-0 text-fg-subtle transition-transform', open && 'rotate-90')} aria-hidden />
          <span className="min-w-0">
            <span className="flex flex-wrap items-center gap-x-2.5 gap-y-1">
              <span className="font-mono text-xs text-fg-muted">{b.rule_id}</span>
              <EvidenceStatusBadge status={b.status} />
              {b.bundle_size ? <span className="text-xs tabular text-fg-muted">{formatBytes(b.bundle_size)}</span> : null}
              <span className="sr-only">{open ? 'Hide contents' : 'Show contents'}</span>
            </span>
            <span className="mt-1 block text-sm text-fg-muted">{statusDescription(b)}</span>
            <span className="mt-0.5 block text-xs text-fg-subtle">
              Started {formatDateTime(b.created_at)}
              {b.captured_at ? ` · captured ${formatDateTime(b.captured_at)}` : ''}
              {b.status === 'stored' && b.downloads ? ` · downloaded ${b.downloads} time${b.downloads === 1 ? '' : 's'}` : ''}
              {retention ? <span className="block text-fg-muted">{retention}</span> : null}
            </span>
          </span>
        </button>
        <div className="flex flex-wrap items-center gap-2">
          {acts.collect.visible ? (
            <GatedButton reason={acts.collect.disabledReason} variant="primary" onClick={() => setDialog('collect')}>
              {acts.collect.retry ? <RotateCcw /> : <UploadCloud />} {acts.collect.retry ? 'Try again' : 'Collect evidence'}
            </GatedButton>
          ) : null}
          {acts.download.visible ? (
            <GatedButton reason={acts.download.disabledReason} variant="primary" onClick={() => setDialog('download')}>
              <Download /> Download
            </GatedButton>
          ) : null}
          {acts.remove.visible ? (
            <GatedButton reason={acts.remove.disabledReason} variant="danger-outline" onClick={() => setDialog('delete')}>
              <Trash2 /> Delete evidence
            </GatedButton>
          ) : null}
        </div>
      </div>
      {acts.collect.retry ? (
        <p className="mx-4 mb-3 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm" role="status">
          <span className="font-medium">The last upload did not finish:</span> <span className="font-mono text-xs">{safeDisplay(b.last_error)}</span>. The bundle is still on the PC.
        </p>
      ) : null}
      {acts.collect.visible && acts.collect.disabledReason && can(EVIDENCE_PRIVILEGE) ? <p className="mx-4 mb-3 text-xs text-warn">{acts.collect.disabledReason}</p> : null}
      {acts.collect.visible && acts.collect.queuedNote && !acts.collect.disabledReason ? <p className="mx-4 mb-3 text-xs text-fg-muted">{acts.collect.queuedNote}</p> : null}
      {open ? (
        <div id={detailsId} className="border-t border-border bg-surface-2/40 px-4 py-4">
          <BundleDetails b={b} />
        </div>
      ) : null}
      {dialog === 'collect' ? <CollectEvidenceDialog bundle={b} onClose={() => setDialog(null)} /> : null}
      {dialog === 'delete' ? <DeleteEvidenceDialog bundle={b} onClose={() => setDialog(null)} /> : null}
      {dialog === 'download' ? <DownloadEvidenceDialog bundle={b} onClose={() => setDialog(null)} /> : null}
    </li>
  )
}

// ---------------------------------------------------------------- manifest

function Section({ title, children, aside }: { title: string; children: ReactNode; aside?: ReactNode }) {
  return (
    <section aria-label={title} className="space-y-2">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-semibold text-fg">{title}</h3>
        {aside ? <span className="text-xs text-fg-subtle">{aside}</span> : null}
      </div>
      {children}
    </section>
  )
}

function CopyCell({ copy }: { copy: FileCopy | null | undefined }) {
  const c = copyStatusOf(copy)
  const Icon = c.icon
  return (
    <span className={cn('inline-flex items-start gap-1 text-xs', TONE_CLASS[c.tone])}>
      <Icon className="mt-0.5 size-3.5 shrink-0" aria-hidden />
      <span>
        {c.label}
        {c.detail ? <span className="block text-fg-subtle">{c.detail}</span> : null}
      </span>
    </span>
  )
}

/** Endpoint-controlled string: text only, bidi/control characters stripped. */
function PathText({ path, className }: { path: string; className?: string }) {
  const p = safeDisplay(path)
  return (
    <span className={cn('font-mono text-[12px] [overflow-wrap:anywhere]', className)} title={p}>
      {p.split('\\').map((part, i) => (
        <Fragment key={i}>
          {i ? '\\' : null}
          {i ? <wbr /> : null}
          {part}
        </Fragment>
      ))}
    </span>
  )
}

const th = 'px-3 py-2 text-left font-medium'
const td = 'px-3 py-1.5 align-top'

export function BundleDetails({ b }: { b: EvidenceBundle }) {
  const m = b.manifest
  if (!m)
    return (
      <p className="flex items-center gap-2 text-sm text-fg-muted">
        <FileSearch className="size-4 shrink-0" aria-hidden />
        {b.status === 'capturing' ? 'The list of contents arrives when the capture ends (about a minute after the alert).' : 'The PC did not report a list of contents for this bundle.'}
      </p>
    )
  const sum = manifestSummary(b, formatBytes)
  return (
    <div className="space-y-5">
      <dl className="grid gap-x-6 gap-y-2.5 text-sm sm:grid-cols-3">
        <div>
          <dt className="text-xs text-fg-subtle">Staged files</dt>
          <dd>{sum?.staged}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Secrets it read</dt>
          <dd>{sum?.secrets}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Connection capture</dt>
          <dd>{sum?.pcap}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Window</dt>
          <dd className="tabular">
            {formatTime(m.window_start)} – {formatTime(m.window_end)}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Bundle</dt>
          <dd className="tabular">
            {formatBytes(b.bundle_size)}
            {b.bundle_sha256 ? (
              <span className="ml-2 font-mono text-xs text-fg-muted" title={`SHA-256 ${b.bundle_sha256}`}>
                SHA-256 {shortHash(b.bundle_sha256)}
              </span>
            ) : null}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Agent</dt>
          <dd>{m.agent_version ? safeDisplay(m.agent_version) : '—'}</dd>
        </div>
      </dl>

      <SecretsTable m={m} />
      <StagedTable m={m} />
      <CaptureBlock m={m} />
      <ProcessList m={m} />

      {m.notes?.length ? (
        <Section title="Notes from the PC">
          <ul className="list-disc space-y-1 pl-5 text-sm text-fg-muted marker:text-fg-subtle">
            {m.notes.map((n, i) => (
              <li key={i}>{safeDisplay(n)}</li>
            ))}
          </ul>
        </Section>
      ) : null}
      <p className="text-xs text-fg-subtle">This list is what the PC reported, filtered by the device’s privacy settings. The bundle itself holds the full, unfiltered list.</p>
    </div>
  )
}

function SecretsTable({ m }: { m: EvidenceManifest }) {
  if (!m.parts.secrets_list) return <Section title="Secrets it read">{<p className="text-sm text-fg-muted">The list of secrets read is turned off in the policy.</p>}</Section>
  const rows = m.secrets ?? []
  return (
    <Section title="Secrets it read" aside={m.parts.secrets_copy ? undefined : 'Copies are turned off in the policy: list only'}>
      {rows.length ? (
        <div className="overflow-x-auto rounded-lg border border-border bg-surface">
          <table className="w-full text-sm">
            <thead className="text-xs text-fg-subtle">
              <tr className="border-b border-border">
                <th className={th}>Store</th>
                <th className={th}>Path</th>
                <th className={cn(th, 'text-right')}>Size</th>
                <th className={th}>First / last read</th>
                <th className={cn(th, 'text-right')}>Opens</th>
                <th className={th}>Copy</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  <td className={cn(td, 'whitespace-nowrap')}>
                    <span className="font-medium">{safeDisplay(s.store)}</span>
                    <span className="block text-xs text-fg-muted">{safeDisplay(s.noun)}</span>
                    {DATA_CATEGORY_LABEL[s.category] && DATA_CATEGORY_LABEL[s.category] !== s.noun ? <span className="sr-only">{DATA_CATEGORY_LABEL[s.category]}</span> : null}
                  </td>
                  <td className={cn(td, 'min-w-56')}>
                    <PathText path={s.path} />
                  </td>
                  <td className={cn(td, 'whitespace-nowrap text-right text-xs tabular text-fg-muted')}>{s.size != null ? formatBytes(s.size) : '—'}</td>
                  <td className={cn(td, 'whitespace-nowrap text-xs tabular text-fg-muted')}>
                    {formatTime(s.first_read)}
                    {s.last_read !== s.first_read ? <span className="block">{formatTime(s.last_read)}</span> : null}
                  </td>
                  <td className={cn(td, 'text-right text-xs tabular text-fg-muted')}>{s.open_count}</td>
                  <td className={cn(td, 'min-w-44')}>
                    <CopyCell copy={m.parts.secrets_copy ? s.copy : null} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-fg-muted">No credential store was read in the window.</p>
      )}
    </Section>
  )
}

function StagedTable({ m }: { m: EvidenceManifest }) {
  if (!m.parts.staged_files) return <Section title="Staged files">{<p className="text-sm text-fg-muted">Copies of staged files are turned off in the policy.</p>}</Section>
  const rows = m.staged ?? []
  const unlisted = m.totals?.staged_unlisted ?? 0
  return (
    <Section title="Staged files" aside="Files the processes created or overwrote in user-writable folders">
      {rows.length ? (
        <div className="overflow-x-auto rounded-lg border border-border bg-surface">
          <table className="w-full text-sm">
            <thead className="text-xs text-fg-subtle">
              <tr className="border-b border-border">
                <th className={th}>Path</th>
                <th className={th}>Time</th>
                <th className={th}>Change</th>
                <th className={cn(th, 'text-right')}>Size</th>
                <th className={th}>Copy</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((s, i) => (
                <tr key={i} className="border-b border-border last:border-0">
                  <td className={cn(td, 'min-w-64')}>
                    <PathText path={s.path} />
                    {s.image ? <span className="block text-xs text-fg-subtle">by {safeDisplay(basename(s.image))}</span> : null}
                  </td>
                  <td className={cn(td, 'whitespace-nowrap text-xs tabular text-fg-muted')}>{formatTime(s.written_at)}</td>
                  <td className={cn(td, 'whitespace-nowrap text-xs')}>{s.op ? WRITE_OP_LABEL[s.op] ?? s.op : '—'}</td>
                  <td className={cn(td, 'whitespace-nowrap text-right text-xs tabular text-fg-muted')}>{s.copy?.size ? formatBytes(s.copy.size) : '—'}</td>
                  <td className={cn(td, 'min-w-44')}>
                    <CopyCell copy={s.copy} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-fg-muted">The processes wrote no files in user-writable folders in the window.</p>
      )}
      {unlisted ? <p className="text-xs text-fg-muted">{unlisted} more written files are not listed (the per-process list is capped).</p> : null}
    </Section>
  )
}

function CaptureBlock({ m }: { m: EvidenceManifest }) {
  const p = m.pcap
  if (!m.parts.pcap || !p) return <Section title="Connection capture">{<p className="text-sm text-fg-muted">The connection capture is turned off in the policy.</p>}</Section>
  const st = PCAP_STATUS[p.status] ?? { label: p.status, tone: 'muted' as const }
  return (
    <Section title="Connection capture">
      <div className="space-y-2 rounded-lg border border-border bg-surface px-4 py-3 text-sm">
        <p>
          <span className={cn('font-medium', TONE_CLASS[st.tone])}>{st.label}</span>
          {p.bytes ? <span className="text-fg-muted"> · {formatBytes(p.bytes)}</span> : null}
          {p.truncated ? <span className="text-warn"> · the oldest packets were overwritten at 50 MB</span> : null}
          {p.started_at ? (
            <span className="text-fg-muted">
              {' '}
              · {formatTime(p.started_at)} – {formatTime(p.ended_at ?? null)}
            </span>
          ) : null}
          {p.mechanism ? <span className="text-fg-subtle"> · {safeDisplay(p.mechanism)}</span> : null}
        </p>
        {p.detail ? <p className="text-xs text-fg-muted">{safeDisplay(p.detail)}</p> : null}
        {p.filters?.length ? (
          <div>
            <p className="text-xs text-fg-subtle">Filters used (remote address:port/protocol)</p>
            <ul className="mt-1 flex flex-wrap gap-1.5">
              {p.filters.map((f, i) => (
                <li key={i} className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[12px]">
                  {formatPcapFilter(f)}
                </li>
              ))}
            </ul>
          </div>
        ) : null}
        <ul className="list-disc space-y-0.5 pl-5 text-xs text-fg-muted marker:text-fg-subtle">
          {PCAP_LIMITATIONS.map((l) => (
            <li key={l}>{l}</li>
          ))}
        </ul>
      </div>
    </Section>
  )
}

function ProcessList({ m }: { m: EvidenceManifest }) {
  const procs = m.processes ?? []
  if (!procs.length) return null
  return (
    <Section title="Processes in the capture">
      <ul className="divide-y divide-border rounded-lg border border-border bg-surface">
        {procs.map((p) => (
          <li key={p.guid} className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5">
            <PathText path={p.image} className="min-w-0 flex-1" />
            <span className="text-xs tabular text-fg-muted">PID {p.pid}</span>
            <span className="text-xs text-fg-muted">{p.role ? PROCESS_ROLE_LABEL[p.role] ?? p.role : ''}</span>
          </li>
        ))}
      </ul>
    </Section>
  )
}
