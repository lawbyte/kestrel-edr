import {
  flexRender,
  getCoreRowModel,
  getSortedRowModel,
  useReactTable,
  type ColumnDef,
  type Row,
  type RowSelectionState,
  type SortingState,
} from '@tanstack/react-table'
import { ArrowDown, ArrowUp, ChevronRight } from 'lucide-react'
import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { cn, isTypingTarget } from '@/lib/utils'
import { Checkbox } from './ui/misc'

export interface DataTableProps<T> {
  data: T[]
  columns: ColumnDef<T, unknown>[]
  getRowId: (row: T) => string
  onRowClick?: (row: T, index: number) => void
  onRowOpen?: (row: T) => void
  activeId?: string | null
  onActiveChange?: (id: string | null) => void
  selectable?: boolean
  selection?: RowSelectionState
  onSelectionChange?: (s: RowSelectionState) => void
  /** Enable j/k/Enter/x keyboard handling at the document level. */
  keyboard?: boolean
  groupBy?: (row: T) => { key: string; label: ReactNode }
  groupSummary?: (rows: T[]) => ReactNode
  highlightIds?: Set<string>
  initialSorting?: SortingState
  dense?: boolean
  empty?: ReactNode
  className?: string
  label: string
  rowClassName?: (row: T) => string | undefined
}

export function DataTable<T>({
  data,
  columns,
  getRowId,
  onRowClick,
  onRowOpen,
  activeId,
  onActiveChange,
  selectable,
  selection,
  onSelectionChange,
  keyboard,
  groupBy,
  groupSummary,
  highlightIds,
  initialSorting,
  dense,
  empty,
  className,
  label,
  rowClassName,
}: DataTableProps<T>) {
  const [sorting, setSorting] = useState<SortingState>(initialSorting ?? [])
  const [innerSel, setInnerSel] = useState<RowSelectionState>({})
  const sel = selection ?? innerSel
  const setSel = onSelectionChange ?? setInnerSel
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  const cols = useMemo<ColumnDef<T, unknown>[]>(() => {
    if (!selectable) return columns
    return [
      {
        id: '__select',
        size: 36,
        enableSorting: false,
        header: ({ table }) => (
          <Checkbox
            aria-label="Select all rows"
            checked={table.getIsAllRowsSelected() ? true : table.getIsSomeRowsSelected() ? 'indeterminate' : false}
            onCheckedChange={(v) => table.toggleAllRowsSelected(!!v)}
          />
        ),
        cell: ({ row }) => (
          <Checkbox aria-label="Select row" checked={row.getIsSelected()} onClick={(e) => e.stopPropagation()} onCheckedChange={(v) => row.toggleSelected(!!v)} />
        ),
      },
      ...columns,
    ]
  }, [columns, selectable])

  const table = useReactTable({
    data,
    columns: cols,
    getRowId: (r) => getRowId(r),
    state: { sorting, rowSelection: sel },
    onSortingChange: setSorting,
    onRowSelectionChange: (u) => setSel(typeof u === 'function' ? u(sel) : u),
    enableRowSelection: !!selectable,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  const rows = table.getRowModel().rows
  const groups = useMemo(() => {
    if (!groupBy) return null
    const out: { key: string; label: ReactNode; rows: Row<T>[] }[] = []
    const idx = new Map<string, number>()
    for (const r of rows) {
      const g = groupBy(r.original)
      if (!idx.has(g.key)) {
        idx.set(g.key, out.length)
        out.push({ key: g.key, label: g.label, rows: [] })
      }
      out[idx.get(g.key)!].rows.push(r)
    }
    return out
  }, [rows, groupBy])

  const visibleRows = useMemo(() => (groups ? groups.flatMap((g) => (collapsed.has(g.key) ? [] : g.rows)) : rows), [groups, rows, collapsed])

  const bodyRef = useRef<HTMLTableSectionElement>(null)
  const activeIndex = activeId ? visibleRows.findIndex((r) => r.id === activeId) : -1

  useEffect(() => {
    if (!keyboard) return
    const onKey = (e: KeyboardEvent) => {
      if (isTypingTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) return
      if (document.querySelector('[role="dialog"][data-state="open"]:not([data-drawer]), [role="alertdialog"][data-state="open"], [cmdk-root]')) return
      const n = visibleRows.length
      if (!n) return
      if (e.key === 'j' || e.key === 'ArrowDown') {
        if (e.key === 'ArrowDown' && !(document.activeElement === document.body || bodyRef.current?.contains(document.activeElement))) return
        e.preventDefault()
        const next = visibleRows[Math.min(n - 1, activeIndex + 1)]
        onActiveChange?.(next.id)
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        if (e.key === 'ArrowUp' && !(document.activeElement === document.body || bodyRef.current?.contains(document.activeElement))) return
        e.preventDefault()
        const prev = visibleRows[Math.max(0, activeIndex - 1)]
        onActiveChange?.(prev.id)
      } else if (e.key === 'Enter' && activeIndex >= 0) {
        if (document.activeElement && document.activeElement !== document.body && !bodyRef.current?.contains(document.activeElement)) return
        e.preventDefault()
        const r = visibleRows[activeIndex]
        if (e.shiftKey && onRowOpen) onRowOpen(r.original)
        else onRowClick?.(r.original, activeIndex)
      } else if (e.key === 'x' && selectable && activeIndex >= 0) {
        e.preventDefault()
        visibleRows[activeIndex].toggleSelected()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [keyboard, visibleRows, activeIndex, onActiveChange, onRowClick, onRowOpen, selectable])

  useEffect(() => {
    if (!activeId) return
    const el = bodyRef.current?.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(activeId)}"]`)
    el?.scrollIntoView({ block: 'nearest' })
  }, [activeId])

  const renderRow = (r: Row<T>, i: number) => {
    const active = r.id === activeId
    return (
      <tr
        key={r.id}
        data-row-id={r.id}
        aria-selected={active || undefined}
        onClick={() => {
          onActiveChange?.(r.id)
          onRowClick?.(r.original, i)
        }}
        className={cn(
          'group border-b border-border last:border-b-0 transition-colors',
          onRowClick && 'cursor-pointer',
          active ? 'bg-accent-soft/70' : 'hover:bg-surface-2/70',
          r.getIsSelected() && !active && 'bg-accent-soft/35',
          highlightIds?.has(r.id) && 'animate-flash',
          rowClassName?.(r.original),
        )}
      >
        {r.getVisibleCells().map((c, ci) => (
          <td
            key={c.id}
            className={cn(
              'align-middle text-sm',
              dense ? 'px-3 py-1.5' : 'px-3 py-2.5',
              ci === 0 && 'relative',
              (c.column.columnDef.meta as { className?: string } | undefined)?.className,
            )}
            style={c.column.columnDef.size && c.column.columnDef.size !== 150 ? { width: c.column.columnDef.size } : undefined}
          >
            {ci === 0 && active ? <span className="absolute inset-y-0 left-0 w-0.5 bg-accent" aria-hidden /> : null}
            {flexRender(c.column.columnDef.cell, c.getContext())}
          </td>
        ))}
      </tr>
    )
  }

  return (
    <div className={cn('relative overflow-x-auto', className)}>
      <table className="w-full border-separate border-spacing-0 text-left" aria-label={label}>
        <thead className="sticky top-0 z-10 bg-surface">
          {table.getHeaderGroups().map((hg) => (
            <tr key={hg.id}>
              {hg.headers.map((h) => {
                const canSort = h.column.getCanSort()
                const dir = h.column.getIsSorted()
                return (
                  <th
                    key={h.id}
                    scope="col"
                    aria-sort={dir === 'asc' ? 'ascending' : dir === 'desc' ? 'descending' : undefined}
                    className={cn(
                      'h-9 whitespace-nowrap border-b border-border px-3 text-xs font-medium text-fg-subtle',
                      (h.column.columnDef.meta as { className?: string } | undefined)?.className,
                    )}
                    style={h.column.columnDef.size && h.column.columnDef.size !== 150 ? { width: h.column.columnDef.size } : undefined}
                  >
                    {h.isPlaceholder ? null : canSort ? (
                      <button type="button" className="inline-flex items-center gap-1 hover:text-fg" onClick={h.column.getToggleSortingHandler()}>
                        {flexRender(h.column.columnDef.header, h.getContext())}
                        {dir === 'asc' ? <ArrowUp className="size-3" /> : dir === 'desc' ? <ArrowDown className="size-3" /> : null}
                      </button>
                    ) : (
                      flexRender(h.column.columnDef.header, h.getContext())
                    )}
                  </th>
                )
              })}
            </tr>
          ))}
        </thead>
        <tbody ref={bodyRef}>
          {rows.length === 0 ? (
            <tr>
              <td colSpan={cols.length}>{empty}</td>
            </tr>
          ) : groups ? (
            groups.map((g) => {
              const isCollapsed = collapsed.has(g.key)
              return (
                <Fragment key={g.key}>
                  <tr className="bg-surface-2/60">
                    <td colSpan={cols.length} className="border-b border-border px-3 py-1.5">
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          aria-expanded={!isCollapsed}
                          className="flex min-w-0 flex-1 items-center gap-2 text-left text-sm"
                          onClick={() =>
                            setCollapsed((s) => {
                              const n = new Set(s)
                              if (n.has(g.key)) n.delete(g.key)
                              else n.add(g.key)
                              return n
                            })
                          }
                        >
                          <ChevronRight className={cn('size-3.5 text-fg-subtle transition-transform', !isCollapsed && 'rotate-90')} />
                          <span className="truncate font-medium">{g.label}</span>
                          <span className="tabular text-xs text-fg-subtle">{g.rows.length}</span>
                        </button>
                        {groupSummary ? <span className="ml-auto shrink-0">{groupSummary(g.rows.map((r) => r.original))}</span> : null}
                      </div>
                    </td>
                  </tr>
                  {isCollapsed ? null : g.rows.map((r) => renderRow(r, visibleRows.indexOf(r)))}
                </Fragment>
              )
            })
          ) : (
            rows.map((r, i) => renderRow(r, i))
          )}
        </tbody>
      </table>
    </div>
  )
}

export function BulkBar({ count, onClear, children }: { count: number; onClear: () => void; children: ReactNode }) {
  if (!count) return null
  return (
    <div role="toolbar" aria-label="Bulk actions" className="fixed bottom-5 left-1/2 z-30 flex -translate-x-1/2 items-center gap-2 rounded-xl border border-border-strong bg-surface px-3 py-2 shadow-pop animate-in">
      <span className="pr-1 text-sm font-medium tabular">{count} selected</span>
      <span className="h-5 w-px bg-border" />
      {children}
      <button type="button" onClick={onClear} className="ml-1 rounded px-1.5 text-xs text-fg-muted hover:text-fg">
        Clear
      </button>
    </div>
  )
}
