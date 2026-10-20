import { Check, ChevronDown, Search, X } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useSearchParams } from 'react-router'
import { cn } from '@/lib/utils'
import { Popover, PopoverContent, PopoverTrigger } from './ui/misc'

/** URL-backed multi-value filter (comma separated). */
export function useUrlList(key: string, fallback: string[] = []): [string[], (v: string[]) => void] {
  const [sp, setSp] = useSearchParams()
  const raw = sp.get(key)
  const val = raw == null ? fallback : raw.split(',').filter(Boolean)
  const set = (v: string[]) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev)
        if (v.length === 0 && fallback.length === 0) n.delete(key)
        else n.set(key, v.join(','))
        return n
      },
      { replace: true },
    )
  return [val, set]
}

export function useUrlString(key: string, fallback = ''): [string, (v: string) => void] {
  const [sp, setSp] = useSearchParams()
  const val = sp.get(key) ?? fallback
  const set = (v: string) =>
    setSp(
      (prev) => {
        const n = new URLSearchParams(prev)
        if (!v || v === fallback) n.delete(key)
        else n.set(key, v)
        return n
      },
      { replace: true },
    )
  return [val, set]
}

export function FilterChip({
  label,
  options,
  value,
  onChange,
  single,
}: {
  label: string
  options: { value: string; label: ReactNode }[]
  value: string[]
  onChange: (v: string[]) => void
  single?: boolean
}) {
  const active = value.length > 0
  const summary = active ? (value.length === 1 ? options.find((o) => o.value === value[0])?.label : `${value.length} selected`) : null
  return (
    <Popover>
      <PopoverTrigger
        className={cn(
          'inline-flex h-7 items-center gap-1.5 rounded-md border px-2 text-xs transition-colors',
          active ? 'border-accent/40 bg-accent-soft text-fg' : 'border-dashed border-border-strong text-fg-muted hover:border-fg-subtle hover:text-fg',
        )}
      >
        <span className={cn(active && 'text-fg-muted')}>{label}</span>
        {summary ? <span className="font-medium">{summary}</span> : null}
        <ChevronDown className="size-3 opacity-60" />
      </PopoverTrigger>
      <PopoverContent className="w-56">
        <div role="listbox" aria-label={label} aria-multiselectable={!single}>
          {options.map((o) => {
            const on = value.includes(o.value)
            return (
              <button
                type="button"
                role="option"
                aria-selected={on}
                key={o.value}
                onClick={() => onChange(single ? (on ? [] : [o.value]) : on ? value.filter((v) => v !== o.value) : [...value, o.value])}
                className="flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm hover:bg-surface-2"
              >
                <span className={cn('flex size-4 items-center justify-center rounded border', on ? 'border-accent bg-accent text-accent-fg' : 'border-border-strong')}>{on ? <Check className="size-3" strokeWidth={3} /> : null}</span>
                {o.label}
              </button>
            )
          })}
        </div>
        {active ? (
          <button type="button" onClick={() => onChange([])} className="mt-1 w-full rounded-md border-t border-border px-2 py-1.5 text-left text-xs text-fg-muted hover:text-fg">
            Clear filter
          </button>
        ) : null}
      </PopoverContent>
    </Popover>
  )
}

export function SearchInput({ value, onChange, placeholder, className, autoFocusKey }: { value: string; onChange: (v: string) => void; placeholder: string; className?: string; autoFocusKey?: string }) {
  const [local, setLocal] = useState(value)
  const ref = useRef<HTMLInputElement>(null)
  useEffect(() => setLocal(value), [value])
  useEffect(() => {
    const t = setTimeout(() => local !== value && onChange(local), 220)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [local])
  useEffect(() => {
    if (!autoFocusKey) return
    const h = (e: KeyboardEvent) => {
      if (e.key === autoFocusKey && !(e.target instanceof HTMLInputElement) && !(e.target instanceof HTMLTextAreaElement) && !e.metaKey && !e.ctrlKey) {
        e.preventDefault()
        ref.current?.focus()
      }
    }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [autoFocusKey])
  return (
    <div className={cn('relative', className)}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-fg-subtle" />
      <input
        ref={ref}
        value={local}
        onChange={(e) => setLocal(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') {
            setLocal('')
            onChange('')
            ;(e.target as HTMLInputElement).blur()
          }
        }}
        placeholder={placeholder}
        aria-label={placeholder}
        className="h-7 w-full rounded-md border border-border-strong bg-surface pl-8 pr-7 text-xs placeholder:text-fg-subtle focus-visible:outline-2 focus-visible:outline-ring"
      />
      {local ? (
        <button type="button" aria-label="Clear search" onClick={() => (setLocal(''), onChange(''))} className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-0.5 text-fg-subtle hover:text-fg">
          <X className="size-3" />
        </button>
      ) : null}
    </div>
  )
}
