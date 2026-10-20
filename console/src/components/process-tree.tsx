import { ChevronRight, Siren } from 'lucide-react'
import { useMemo, useState, type KeyboardEvent } from 'react'
import type { TreeNode } from '@/api/types'
import { formatDateTime, formatDuration, formatTime, shortHash } from '@/lib/format'
import { basename, cn } from '@/lib/utils'
import { PathClassBadge, SignerBadge } from './badges'
import { KeyValue, Mono } from './common'
import { CopyButton } from './copy-button'
import { Tooltip } from './ui/misc'

interface Built {
  node: TreeNode
  depth: number
  children: Built[]
  /** ancestors' "has a later sibling" flags, for drawing guide lines */
  rails: boolean[]
  last: boolean
}

export function buildForest(nodes: TreeNode[]): Built[] {
  const byParent = new Map<string | null, TreeNode[]>()
  const ids = new Set(nodes.map((n) => n.guid))
  for (const n of nodes) {
    const p = n.parent_guid && ids.has(n.parent_guid) ? n.parent_guid : null
    const arr = byParent.get(p) ?? []
    arr.push(n)
    byParent.set(p, arr)
  }
  for (const arr of byParent.values()) arr.sort((a, b) => a.start_ts - b.start_ts)
  const walk = (n: TreeNode, depth: number, rails: boolean[], last: boolean): Built => {
    const kids = byParent.get(n.guid) ?? []
    return {
      node: n,
      depth,
      rails,
      last,
      children: kids.map((k, i) => walk(k, depth + 1, [...rails, !last], i === kids.length - 1)),
    }
  }
  const roots = byParent.get(null) ?? []
  return roots.map((r, i) => walk(r, 0, [], i === roots.length - 1))
}

function flatten(forest: Built[], collapsed: Set<string>): Built[] {
  const out: Built[] = []
  const rec = (b: Built) => {
    out.push(b)
    if (!collapsed.has(b.node.guid)) b.children.forEach(rec)
  }
  forest.forEach(rec)
  return out
}

const INDENT = 22
/** x of the vertical rail joining children at `depth` (centre of their parent's chevron). */
const railX = (depth: number) => 12 + (depth - 1) * INDENT + 10

export function ProcessTree({ nodes, selected, onSelect, className }: { nodes: TreeNode[]; selected: string | null; onSelect: (guid: string) => void; className?: string }) {
  const forest = useMemo(() => buildForest(nodes), [nodes])
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())
  const rows = useMemo(() => flatten(forest, collapsed), [forest, collapsed])
  const byGuid = useMemo(() => new Map(nodes.map((n) => [n.guid, n])), [nodes])

  const toggle = (g: string) =>
    setCollapsed((s) => {
      const n = new Set(s)
      if (n.has(g)) n.delete(g)
      else n.add(g)
      return n
    })

  const onKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const i = rows.findIndex((r) => r.node.guid === selected)
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      onSelect(rows[Math.min(rows.length - 1, i + 1)].node.guid)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      onSelect(rows[Math.max(0, i - 1)].node.guid)
    } else if ((e.key === 'ArrowLeft' || e.key === 'ArrowRight') && i >= 0) {
      e.preventDefault()
      const g = rows[i].node.guid
      const isCol = collapsed.has(g)
      if ((e.key === 'ArrowLeft' && !isCol && rows[i].children.length) || (e.key === 'ArrowRight' && isCol)) toggle(g)
      else if (e.key === 'ArrowLeft' && rows[i].node.parent_guid && byGuid.has(rows[i].node.parent_guid!)) onSelect(rows[i].node.parent_guid!)
    }
  }

  if (!nodes.length) return <p className="px-4 py-8 text-center text-sm text-fg-muted">No process data for this incident.</p>

  return (
    <div role="tree" aria-label="Process tree" tabIndex={0} onKeyDown={onKey} className={cn('py-1 font-sans focus-visible:outline-offset-[-2px]', className)}>
      {rows.map((b) => {
        const n = b.node
        const parent = n.parent_guid ? byGuid.get(n.parent_guid) : undefined
        const gap = parent ? n.start_ts - parent.start_ts : null
        const hasKids = b.children.length > 0
        const isCol = collapsed.has(n.guid)
        const sel = n.guid === selected
        const alerted = n.alert_rule_ids.length > 0
        return (
          <div
            key={n.guid}
            role="treeitem"
            aria-selected={sel}
            aria-expanded={hasKids ? !isCol : undefined}
            aria-level={b.depth + 1}
            onClick={() => onSelect(n.guid)}
            className={cn('tree-row group flex min-h-[42px] cursor-pointer items-center pr-3 transition-colors', sel ? 'bg-accent-soft' : 'hover:bg-surface-2/70')}
          >
            <div className="relative shrink-0 self-stretch" style={{ width: 12 + b.depth * INDENT }}>
              {b.rails.map((on, d) => (d > 0 && on ? <span key={d} className="tree-guide" style={{ left: railX(d) }} /> : null))}
              {b.depth > 0 ? (
                <>
                  <span className="tree-elbow" style={{ left: railX(b.depth), width: 12 + b.depth * INDENT - railX(b.depth) + (hasKids ? 0 : 18) }} />
                  {!b.last ? <span className="tree-guide" style={{ left: railX(b.depth), top: '50%' }} /> : null}
                </>
              ) : null}
              {hasKids && !isCol ? <span className="tree-guide" style={{ left: railX(b.depth + 1), top: 'calc(50% + 10px)' }} /> : null}
            </div>
            <button
              type="button"
              tabIndex={-1}
              aria-label={isCol ? 'Expand' : 'Collapse'}
              onClick={(e) => {
                e.stopPropagation()
                if (hasKids) toggle(n.guid)
              }}
              className={cn('mr-1 flex size-5 shrink-0 items-center justify-center rounded text-fg-subtle', hasKids ? 'hover:bg-surface-3' : 'invisible')}
            >
              <ChevronRight className={cn('size-3.5 transition-transform', !isCol && 'rotate-90')} />
            </button>
            <div className="flex min-w-0 flex-1 flex-wrap items-center gap-x-2 gap-y-0.5 py-1.5">
              <span className={cn('flex size-5 shrink-0 items-center justify-center rounded', alerted ? 'bg-sev-critical-soft text-sev-critical' : 'bg-surface-3 text-fg-subtle')}>
                {alerted ? <Siren className="size-3" aria-label="Alerted" /> : <span className="text-[9px] font-semibold">EXE</span>}
              </span>
              <span className={cn('truncate font-mono text-[13px]', alerted ? 'font-semibold text-fg' : 'text-fg')}>{basename(n.image)}</span>
              <span className="text-xs tabular text-fg-subtle">{n.pid}</span>
              <SignerBadge signed={n.signed} signer={n.signer} />
              {n.path_class !== 'system' && n.path_class !== 'program_files' && n.path_class !== 'windows' ? <PathClassBadge pathClass={n.path_class} /> : null}
              {n.alert_rule_ids.map((r) => (
                <span key={r} className="rounded bg-sev-critical-soft px-1 py-px font-mono text-[10.5px] font-medium text-sev-critical">
                  {r}
                </span>
              ))}
            </div>
            {gap != null && gap >= 0 ? (
              <Tooltip content={`Started ${formatDuration(gap)} after its parent`}>
                <span className="ml-2 shrink-0 text-xs tabular text-fg-subtle">+{formatDuration(gap)}</span>
              </Tooltip>
            ) : (
              <span className="ml-2 shrink-0 text-xs tabular text-fg-subtle">{formatTime(n.start_ts)}</span>
            )}
          </div>
        )
      })}
    </div>
  )
}

export function ProcessDetail({ node, parent }: { node: TreeNode; parent?: TreeNode }) {
  return (
    <div className="space-y-4">
      <div>
        <div className="flex items-start justify-between gap-2">
          <div className="min-w-0">
            <p className="truncate font-mono text-sm font-semibold">{basename(node.image)}</p>
            <p className="break-all font-mono text-xs text-fg-muted">{node.image}</p>
          </div>
          <CopyButton text={node.image} iconOnly label="Copy path" />
        </div>
        <div className="mt-2 flex flex-wrap gap-1.5">
          <SignerBadge signed={node.signed} signer={node.signer} />
          <PathClassBadge pathClass={node.path_class} />
        </div>
      </div>
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs text-fg-subtle">Command line</span>
          <CopyButton text={node.cmdline} iconOnly label="Copy command line" />
        </div>
        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-2 px-2.5 py-2 font-mono text-[12px] leading-relaxed">{node.cmdline}</pre>
      </div>
      <KeyValue
        items={[
          ['PID', <span className="tabular">{node.pid}</span>],
          ['User', node.user ?? '—'],
          ['Started', formatDateTime(node.start_ts)],
          ['Exited', node.exit_ts ? `${formatDateTime(node.exit_ts)} (ran ${formatDuration(node.exit_ts - node.start_ts)})` : 'Still running or unknown'],
          ['Parent', parent ? <Mono className="break-normal">{basename(parent.image)} ({parent.pid})</Mono> : 'None recorded'],
          ['Alerts', node.alert_rule_ids.length ? node.alert_rule_ids.join(', ') : 'None'],
        ]}
      />
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs text-fg-subtle">SHA-256</span>
          {node.sha256 ? <CopyButton text={node.sha256} iconOnly label="Copy SHA-256" /> : null}
        </div>
        <Mono className="text-fg-muted" title={node.sha256 ?? undefined}>
          {node.sha256 ?? '—'}
        </Mono>
      </div>
      <p className="text-xs text-fg-subtle">
        GUID <Mono>{shortHash(node.guid, 20)}</Mono>
      </p>
    </div>
  )
}
