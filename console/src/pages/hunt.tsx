import { useMutation, useQuery } from '@tanstack/react-query'
import { BookOpen, Bookmark, ChevronRight, Download, Play, Trash2 } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { DeviceEvent, HuntResponse } from '@/api/types'
import { ProvenanceBadges } from '@/components/badges'
import { EmptyState, ErrorState, PageHeader } from '@/components/common'
import { Button } from '@/components/ui/button'
import { Popover, PopoverContent, PopoverTrigger, Segmented } from '@/components/ui/misc'
import { describeEvent } from '@/lib/events'
import type { ExplainContext } from '@/lib/explain'
import { EventDetails } from '@/components/event-details'
import { EXAMPLE_QUERIES, FIELD_HELP, HUNT_FIELDS, complete, parseHunt, type Completion, type HuntField } from '@/lib/hunt'
import { EVENT_KIND_LABEL, EVENT_KINDS_UI } from '@/lib/labels'
import { formatDateTime, formatTime } from '@/lib/format'
import { downloadText, toCsv } from '@/lib/csv'
import { loadJson, saveJson } from '@/lib/storage'
import { basename, cn } from '@/lib/utils'

const SAVED_KEY = 'kestrel.hunt.saved'
const RANGES = { '1h': 3600e3, '24h': 86400e3, '7d': 7 * 86400e3, '30d': 30 * 86400e3 } as const
type Range = keyof typeof RANGES

export default function Hunt() {
  const [sp, setSp] = useSearchParams()
  const [query, setQuery] = useState(sp.get('q') ?? 'event_type = dns_query and dns_qname = api.telegram.org')
  const [range, setRange] = useState<Range>((sp.get('range') as Range) ?? '24h')
  const [saved, setSaved] = useState<{ name: string; query: string }[]>(() => loadJson(SAVED_KEY, []))
  const parsed = useMemo(() => parseHunt(query), [query])
  const devices = useQuery({ queryKey: qk.devices(), queryFn: () => api.devices(), staleTime: 60_000 })
  const hints = useMemo<Partial<Record<HuntField, string[]>>>(
    () => ({
      event_type: [...EVENT_KINDS_UI],
      hostname: (devices.data?.items ?? []).map((d) => d.hostname),
      dns_qname: ['api.telegram.org', 'steamcommunity.com', 'discord.com', 'ip-api.com', 'r2.dev', 'bsc-dataseed1.binance.org', 'pastebin.com'],
      dst_port: ['443', '80', '8545', '9222'],
      signer: ['Microsoft Windows', 'Microsoft Corporation', 'Google LLC'],
      image: ['powershell.exe', 'cmd.exe', 'mshta.exe', 'rundll32.exe', 'regasm.exe', 'msbuild.exe', '\\Downloads\\', '\\AppData\\Local\\Temp\\'],
      file_path: ['Login Data', 'Network\\Cookies', 'Local State', 'key4.db', 'logins.json', 'tdata', 'Local Extension Settings', '.aws\\credentials'],
    }),
    [devices.data],
  )

  const run = useMutation({
    mutationFn: () => {
      const to = Date.now()
      return api.hunt({ query, from: to - RANGES[range], to, limit: 1000 })
    },
  })
  const exec = () => {
    if (!parsed.ok) return
    setSp({ q: query, range }, { replace: true })
    run.mutate()
  }
  useEffect(() => {
    if (sp.get('q') && parsed.ok) run.mutate()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div className="flex h-full flex-col">
      <PageHeader title="Hunt" description="Search raw telemetry across every device. Results come from the events store, newest first." />
      <div className="space-y-3 border-b border-border px-6 py-4">
        <QueryEditor value={query} onChange={setQuery} onRun={exec} hints={hints} error={parsed.ok ? null : parsed.error} />
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" size="sm" onClick={exec} disabled={!parsed.ok || run.isPending}>
            <Play /> {run.isPending ? 'Running…' : 'Run'}
            <span className="ml-1 text-[11px] opacity-70">⌘↵</span>
          </Button>
          <Segmented size="sm" label="Time range" value={range} onChange={setRange} options={(Object.keys(RANGES) as Range[]).map((r) => ({ value: r, label: `Last ${r}` }))} />
          <SyntaxHelp onPick={setQuery} />
          <Popover>
            <PopoverTrigger asChild>
              <Button size="sm" variant="ghost">
                <Bookmark /> Saved{saved.length ? ` (${saved.length})` : ''}
              </Button>
            </PopoverTrigger>
            <PopoverContent className="w-80 p-2">
              {saved.length ? (
                <ul className="mb-2 max-h-60 overflow-auto">
                  {saved.map((s) => (
                    <li key={s.name} className="group flex items-center gap-1">
                      <button type="button" className="min-w-0 flex-1 rounded-md px-2 py-1.5 text-left hover:bg-surface-2" onClick={() => setQuery(s.query)}>
                        <span className="block text-sm">{s.name}</span>
                        <span className="block truncate font-mono text-[11px] text-fg-subtle">{s.query}</span>
                      </button>
                      <Button
                        size="icon-sm"
                        variant="ghost"
                        aria-label={`Delete ${s.name}`}
                        onClick={() => {
                          const n = saved.filter((x) => x.name !== s.name)
                          setSaved(n)
                          saveJson(SAVED_KEY, n)
                        }}
                      >
                        <Trash2 />
                      </Button>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="px-2 py-2 text-sm text-fg-muted">No saved queries yet.</p>
              )}
              <Button
                size="sm"
                className="w-full"
                disabled={!parsed.ok || !query.trim()}
                onClick={() => {
                  const name = window.prompt('Name this query')
                  if (!name?.trim()) return
                  const n = [...saved.filter((x) => x.name !== name.trim()), { name: name.trim(), query }]
                  setSaved(n)
                  saveJson(SAVED_KEY, n)
                  toast.success('Query saved in this browser')
                }}
              >
                Save current query
              </Button>
            </PopoverContent>
          </Popover>
          {run.data ? (
            <span className="ml-auto text-xs tabular text-fg-subtle">
              {run.data.items.length} result{run.data.items.length === 1 ? '' : 's'} in {run.data.elapsed_ms} ms
            </span>
          ) : null}
        </div>
      </div>
      <div className="min-h-0 flex-1 overflow-auto bg-surface">
        {run.error ? (
          <ErrorState error={run.error} onRetry={exec} />
        ) : run.isPending ? (
          <div className="p-8 text-center text-sm text-fg-muted">Searching {range} of telemetry…</div>
        ) : run.data ? (
          <Results data={run.data} />
        ) : (
          <EmptyState icon={BookOpen} title="Write a query and press Run">
            Start from an example under <span className="font-medium">Syntax &amp; examples</span>, or type a field name for suggestions.
          </EmptyState>
        )}
      </div>
    </div>
  )
}

function QueryEditor({ value, onChange, onRun, hints, error }: { value: string; onChange: (v: string) => void; onRun: () => void; hints: Partial<Record<HuntField, string[]>>; error: { message: string; pos: number } | null }) {
  const ref = useRef<HTMLTextAreaElement>(null)
  const [cursor, setCursor] = useState(value.length)
  const [focused, setFocused] = useState(false)
  const [idx, setIdx] = useState(0)
  const [dismissed, setDismissed] = useState(false)
  const comp = useMemo(() => complete(value, cursor, hints), [value, cursor, hints])
  const show = focused && !dismissed && comp.items.length > 0
  useEffect(() => setIdx(0), [comp.from, comp.items.length])

  const accept = (c: Completion) => {
    const next = value.slice(0, comp.from) + c.insert + value.slice(cursor)
    onChange(next)
    const pos = comp.from + c.insert.length
    requestAnimationFrame(() => {
      ref.current?.setSelectionRange(pos, pos)
      setCursor(pos)
    })
  }
  const onKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) {
      e.preventDefault()
      onRun()
      return
    }
    if (show) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setIdx((i) => (i + 1) % comp.items.length)
        return
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault()
        setIdx((i) => (i - 1 + comp.items.length) % comp.items.length)
        return
      }
      if (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey)) {
        e.preventDefault()
        accept(comp.items[idx])
        return
      }
      if (e.key === 'Escape') {
        e.preventDefault()
        setDismissed(true)
        return
      }
    } else if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      onRun()
    }
  }
  return (
    <div className="relative">
      <label htmlFor="hunt-q" className="sr-only">
        Hunt query
      </label>
      <textarea
        id="hunt-q"
        ref={ref}
        value={value}
        spellCheck={false}
        autoComplete="off"
        rows={2}
        aria-invalid={!!error}
        aria-describedby="hunt-err"
        aria-autocomplete="list"
        aria-expanded={show}
        aria-controls="hunt-suggest"
        onChange={(e) => {
          onChange(e.target.value)
          setCursor(e.target.selectionStart)
          setDismissed(false)
        }}
        onSelect={(e) => setCursor((e.target as HTMLTextAreaElement).selectionStart)}
        onKeyDown={onKey}
        onFocus={() => setFocused(true)}
        onBlur={() => setTimeout(() => setFocused(false), 120)}
        className={cn(
          'w-full resize-y rounded-lg border bg-surface px-3 py-2.5 font-mono text-[13.5px] leading-relaxed focus-visible:outline-2 focus-visible:outline-ring',
          error ? 'border-danger/60' : 'border-border-strong',
        )}
      />
      {show ? (
        <ul id="hunt-suggest" role="listbox" className="absolute left-0 top-full z-30 mt-1 max-h-72 w-[min(520px,100%)] overflow-auto rounded-lg border border-border bg-surface p-1 shadow-pop">
          {comp.items.map((c, i) => (
            <li
              key={c.label}
              role="option"
              aria-selected={i === idx}
              onMouseDown={(e) => {
                e.preventDefault()
                accept(c)
              }}
              onMouseEnter={() => setIdx(i)}
              className={cn('flex cursor-default items-baseline gap-3 rounded-md px-2 py-1.5', i === idx && 'bg-surface-2')}
            >
              <span className={cn('font-mono text-[13px]', c.kind === 'op' || c.kind === 'keyword' ? 'text-accent-text' : 'text-fg')}>{c.label}</span>
              {c.detail ? <span className="truncate text-xs text-fg-subtle">{c.detail}</span> : null}
            </li>
          ))}
          <li className="border-t border-border px-2 pt-1.5 text-[11px] text-fg-subtle">Tab or Enter to insert · Esc to close</li>
        </ul>
      ) : null}
      <p id="hunt-err" className={cn('mt-1 min-h-4 text-xs', error ? 'text-danger' : 'text-fg-subtle')} role={error ? 'alert' : undefined}>
        {error ? `${error.message} (character ${error.pos + 1})` : 'field op value, joined by and / or. Ops: = != ~ (contains) > <'}
      </p>
    </div>
  )
}

function SyntaxHelp({ onPick }: { onPick: (q: string) => void }) {
  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button size="sm" variant="ghost">
          <BookOpen /> Syntax &amp; examples
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[560px] max-w-[calc(100vw-2rem)] p-4">
        <div className="grid gap-5 sm:grid-cols-2">
          <div>
            <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Fields</h3>
            <dl className="space-y-1 text-xs">
              {HUNT_FIELDS.map((f) => (
                <div key={f}>
                  <dt className="font-mono text-fg">{f}</dt>
                  <dd className="text-fg-muted">{FIELD_HELP[f]}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div>
            <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Operators</h3>
            <ul className="mb-4 space-y-0.5 text-xs text-fg-muted">
              <li><code className="text-fg">=</code> equals (case-insensitive)</li>
              <li><code className="text-fg">!=</code> not equal</li>
              <li><code className="text-fg">~</code> contains</li>
              <li><code className="text-fg">&gt;</code> <code className="text-fg">&lt;</code> numbers only (dst_port)</li>
              <li><code className="text-fg">and</code> binds tighter than <code className="text-fg">or</code></li>
              <li>Quote values with spaces: <code className="text-fg">"Login Data"</code></li>
            </ul>
            <h3 className="mb-1.5 text-xs font-medium text-fg-subtle">Examples</h3>
            <ul className="space-y-1">
              {EXAMPLE_QUERIES.map((ex) => (
                <li key={ex.label}>
                  <button type="button" onClick={() => onPick(ex.query)} className="group w-full rounded-md px-2 py-1 text-left hover:bg-surface-2">
                    <span className="flex items-center gap-1 text-xs font-medium">
                      {ex.label} <ChevronRight className="size-3 opacity-0 group-hover:opacity-60" />
                    </span>
                    <span className="block truncate font-mono text-[11px] text-fg-subtle">{ex.query}</span>
                  </button>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  )
}

function Results({ data }: { data: HuntResponse }) {
  const [open, setOpen] = useState<number | null>(null)
  const ctx = useMemo<ExplainContext>(() => ({ events: data.items }), [data.items])
  if (!data.items.length) return <EmptyState title="No events match">Widen the time range or loosen a condition (try ~ instead of =).</EmptyState>
  const exportCsv = () =>
    downloadText(
      `kestrel-hunt-${new Date().toISOString().slice(0, 19)}.csv`,
      toCsv(
        data.items.map((e) => ({ ts: new Date(e.ts).toISOString(), hostname: e.hostname, device_id: e.device_id, event_type: e.type, pid: e.pid, guid: e.guid, image: imageOf(e), details: describeEvent(e) })),
        ['ts', 'hostname', 'device_id', 'event_type', 'pid', 'guid', 'image', 'details'],
      ),
    )
  return (
    <div>
      <div className="flex items-center justify-end border-b border-border px-4 py-1.5">
        <Button size="sm" variant="ghost" onClick={exportCsv}>
          <Download /> Export CSV
        </Button>
      </div>
      <table className="w-full text-sm">
        <thead className="sticky top-0 bg-surface text-xs text-fg-subtle">
          <tr className="border-b border-border">
            <th className="px-3 py-2 text-left font-medium">Time</th>
            <th className="px-3 py-2 text-left font-medium">Device</th>
            <th className="px-3 py-2 text-left font-medium">Type</th>
            <th className="px-3 py-2 text-left font-medium">Process</th>
            <th className="px-3 py-2 text-left font-medium">Details</th>
          </tr>
        </thead>
        <tbody>
          {data.items.map((e, i) => (
            <ResultRow key={i} e={e} open={open === i} onToggle={() => setOpen(open === i ? null : i)} ctx={ctx} />
          ))}
        </tbody>
      </table>
    </div>
  )
}

function imageOf(e: DeviceEvent) {
  return e.type === 'process_start' ? e.image : (e.process_image ?? '')
}

function ResultRow({ e, open, onToggle, ctx }: { e: DeviceEvent; open: boolean; onToggle: () => void; ctx: ExplainContext }) {
  const img = imageOf(e)
  return (
    <>
      <tr className="cursor-pointer border-b border-border hover:bg-surface-2/60" onClick={onToggle} aria-expanded={open}>
        <td className="whitespace-nowrap px-3 py-1.5 text-xs tabular text-fg-muted" title={formatDateTime(e.ts)}>
          {formatTime(e.ts)}
        </td>
        <td className="whitespace-nowrap px-3 py-1.5">
          <Link to={`/devices/${e.device_id}`} onClick={(ev) => ev.stopPropagation()} className="font-mono text-[12.5px] hover:underline">
            {e.hostname}
          </Link>
        </td>
        <td className="whitespace-nowrap px-3 py-1.5 text-xs">{EVENT_KIND_LABEL[e.type]}</td>
        <td className="whitespace-nowrap px-3 py-1.5 font-mono text-[12px]">
          <span className="inline-flex items-center gap-1.5">
            {e.type === 'file_activity' && e.remote_writer ? 'System' : img ? basename(img) : e.pid}
            <ProvenanceBadges event={e} />
          </span>
        </td>
        <td className="w-full max-w-0 truncate px-3 py-1.5 font-mono text-[12px] text-fg-muted">{describeEvent(e)}</td>
      </tr>
      {open ? (
        <tr className="border-b border-border bg-surface-2/50">
          <td colSpan={5} className="px-3 py-2">
            <EventDetails event={e} context={ctx} />
          </td>
        </tr>
      ) : null}
    </>
  )
}
