import { AlertTriangle, CheckCircle2, ChevronRight, Info } from 'lucide-react'
import { useMemo, useState } from 'react'
import type { KEvent } from '@/api/types'
import { explainEvent, type ExplainContext, type ExplainList, type Tone } from '@/lib/explain'
import { cn } from '@/lib/utils'
import { CopyButton } from './copy-button'

const TONE: Record<Tone, { icon: typeof Info; label: string; cls: string }> = {
  info: { icon: Info, label: 'Note', cls: 'border-border bg-surface text-fg' },
  warn: { icon: AlertTriangle, label: 'Watch', cls: 'border-warn/40 bg-warn-soft text-fg' },
  ok: { icon: CheckCircle2, label: 'Reassuring', cls: 'border-ok/40 bg-ok-soft text-fg' },
}
const TAG_CLS: Record<Tone, string> = { info: 'text-fg-muted', warn: 'text-warn', ok: 'text-ok' }

/**
 * Expanded view of one telemetry event: plain-language explanation, key
 * fields and the raw JSON behind a toggle. Every value from the endpoint is
 * rendered as text (React escapes it); nothing becomes a link or HTML.
 */
export function EventDetails({ event, context }: { event: KEvent; context?: ExplainContext }) {
  const x = useMemo(() => explainEvent(event, context), [event, context])
  const [raw, setRaw] = useState(false)
  const json = useMemo(() => JSON.stringify(event, null, 2), [event])
  return (
    <div className="space-y-3 py-1 font-sans text-sm" onClick={(ev) => ev.stopPropagation()}>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <section aria-label="What happened" className="min-w-0 space-y-2">
          <h4 className="text-xs font-medium uppercase tracking-wide text-fg-subtle">What happened</h4>
          {x.what.map((t, i) => (
            <p key={i} className="leading-relaxed [overflow-wrap:anywhere]">
              {t}
            </p>
          ))}
          {x.lists.map((l, i) => (
            <ListBlock key={i} list={l} />
          ))}
          {x.notes.map((n, i) => {
            const T = TONE[n.tone]
            return (
              <div key={i} className={cn('flex items-start gap-2 rounded-md border px-3 py-2 text-[13px]', T.cls)}>
                <T.icon className={cn('mt-0.5 size-4 shrink-0', TAG_CLS[n.tone])} aria-hidden />
                <p className="[overflow-wrap:anywhere]">
                  <span className="font-medium">{T.label}: </span>
                  {n.text}
                </p>
              </div>
            )
          })}
        </section>
        <section aria-label="Key fields" className="min-w-0">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-fg-subtle">Key fields</h4>
          <table className="w-full text-[13px]">
            <tbody>
              {x.fields.map((f, i) => (
                <tr key={i} className="border-b border-border/60 last:border-0 align-top">
                  <th scope="row" className="w-36 whitespace-nowrap py-1 pr-3 text-left text-xs font-normal text-fg-subtle">
                    {f.label}
                  </th>
                  <td className={cn('py-1 [overflow-wrap:anywhere]', f.mono && 'font-mono text-[12px]', f.block && 'whitespace-pre-wrap')}>{f.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      </div>
      <div>
        <div className="flex items-center gap-2">
          <button type="button" onClick={() => setRaw((r) => !r)} aria-expanded={raw} className="inline-flex items-center gap-1 rounded text-xs text-fg-muted hover:text-fg focus-visible:outline-2 focus-visible:outline-ring">
            <ChevronRight className={cn('size-3.5 transition-transform', raw && 'rotate-90')} aria-hidden />
            {raw ? 'Hide raw event' : 'Show raw event'}
          </button>
          {raw ? <CopyButton text={json} label="Copy raw event" iconOnly /> : null}
        </div>
        {raw ? <pre className="mt-1.5 max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface p-2 font-mono text-[11.5px] leading-relaxed">{json}</pre> : null}
      </div>
    </div>
  )
}

function ListBlock({ list }: { list: ExplainList }) {
  const [more, setMore] = useState(false)
  const extra = list.more ?? []
  const items = more ? [...list.items, ...extra] : list.items
  return (
    <div>
      <p className="text-[13px] font-medium">{list.title}</p>
      {items.length ? (
        <ul className="mt-1 space-y-1">
          {items.map((it, i) => (
            <li key={i} className="flex flex-wrap items-baseline gap-x-2 text-[13px]">
              <span className="font-mono text-[12px] [overflow-wrap:anywhere]">{it.text}</span>
              {it.tag ? (
                <span className={cn('inline-flex items-center gap-1 text-xs font-medium', TAG_CLS[it.tone ?? 'info'])}>
                  {it.tone === 'warn' ? <AlertTriangle className="size-3" aria-hidden /> : it.tone === 'ok' ? <CheckCircle2 className="size-3" aria-hidden /> : <Info className="size-3" aria-hidden />}
                  {it.tag}
                </span>
              ) : null}
            </li>
          ))}
        </ul>
      ) : list.empty ? (
        <p className="mt-1 text-[13px] text-fg-muted">{list.empty}</p>
      ) : null}
      {extra.length ? (
        <button type="button" onClick={() => setMore((m) => !m)} aria-expanded={more} className="mt-1 text-xs text-accent-text hover:underline">
          {more ? 'Show fewer' : `+${extra.length} more`}
        </button>
      ) : null}
    </div>
  )
}
