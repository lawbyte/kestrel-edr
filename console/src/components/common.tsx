import { AlertCircle, Inbox, RefreshCw } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ApiError } from '@/api/client'
import type { User } from '@/api/types'
import { attackUrl } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { Button } from './ui/button'
import { Skeleton, Tooltip } from './ui/misc'

export function PageHeader({ title, description, actions, children, className }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <div className={cn('border-b border-border bg-bg px-6 pb-4 pt-5', className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="text-[1.375rem] font-semibold leading-7 tracking-[-0.01em]">{title}</h1>
          {description ? <p className="mt-1 max-w-3xl text-sm text-fg-muted">{description}</p> : null}
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {children}
    </div>
  )
}

export function Card({ title, actions, children, className, bodyClassName, description, id }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClassName?: string; description?: ReactNode; id?: string }) {
  return (
    <section id={id} className={cn('rounded-lg border border-border bg-surface', className)} aria-label={typeof title === 'string' ? title : undefined}>
      {title ? (
        <header className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
          <div className="min-w-0">
            <h2 className="text-sm font-semibold">{title}</h2>
            {description ? <p className="text-xs text-fg-muted">{description}</p> : null}
          </div>
          {actions ? <div className="flex shrink-0 items-center gap-1.5">{actions}</div> : null}
        </header>
      ) : null}
      <div className={cn('p-4', bodyClassName)}>{children}</div>
    </section>
  )
}

export function EmptyState({ icon: Icon = Inbox, title, children, action, className }: { icon?: typeof Inbox; title: string; children?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
      <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-surface-2 text-fg-subtle">
        <Icon className="size-5" aria-hidden />
      </div>
      <p className="text-sm font-medium">{title}</p>
      {children ? <div className="mt-1 max-w-sm text-sm text-fg-muted">{children}</div> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  )
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const msg = error instanceof ApiError ? error.message : error instanceof Error ? error.message : 'Something went wrong'
  const code = error instanceof ApiError ? error.status : null
  return (
    <div role="alert" className={cn('flex flex-col items-center justify-center px-6 py-12 text-center', className)}>
      <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-danger-soft text-danger">
        <AlertCircle className="size-5" aria-hidden />
      </div>
      <p className="text-sm font-medium">{code === 404 ? 'Not found' : code === 403 ? 'You don’t have access to this' : 'Couldn’t load this'}</p>
      <p className="mt-1 max-w-md text-sm text-fg-muted">{msg}</p>
      {onRetry ? (
        <Button className="mt-4" size="sm" onClick={onRetry}>
          <RefreshCw /> Try again
        </Button>
      ) : null}
    </div>
  )
}

export function LoadingRows({ rows = 8, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('space-y-2 p-4', className)} aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-8" />
      ))}
    </div>
  )
}

export function AttackChips({ ids, max = 3, className }: { ids: string[]; max?: number; className?: string }) {
  if (!ids.length) return null
  const shown = ids.slice(0, max)
  return (
    <span className={cn('inline-flex flex-wrap items-center gap-1 whitespace-nowrap', className)}>
      {shown.map((t) => (
        <a
          key={t}
          href={attackUrl(t)}
          target="_blank"
          rel="noreferrer noopener"
          onClick={(e) => e.stopPropagation()}
          className="rounded border border-border px-1 py-px font-mono text-[11px] text-fg-muted hover:border-accent/50 hover:text-accent-text"
          title={`MITRE ATT&CK ${t}`}
        >
          {t}
        </a>
      ))}
      {ids.length > max ? (
        <Tooltip content={ids.slice(max).join(', ')}>
          <span className="text-[11px] text-fg-subtle">+{ids.length - max}</span>
        </Tooltip>
      ) : null}
    </span>
  )
}

export function RuleRef({ id, name, author, link = true }: { id: string; name?: string; author?: string | null; link?: boolean }) {
  const inner = (
    <>
      <span className="font-mono text-xs text-fg-muted">{id}</span>
      {name ? <span className="truncate">{name}</span> : null}
    </>
  )
  return (
    <span className="inline-flex min-w-0 flex-col">
      {link ? (
        <Link to={`/rules?rule=${encodeURIComponent(id)}`} className="inline-flex min-w-0 items-baseline gap-1.5 hover:underline" onClick={(e) => e.stopPropagation()}>
          {inner}
        </Link>
      ) : (
        <span className="inline-flex min-w-0 items-baseline gap-1.5">{inner}</span>
      )}
      {author ? <span className="text-[11px] text-fg-subtle">Rule by {author}</span> : null}
    </span>
  )
}

const AVATAR_TONES = ['bg-[#dfe4fb] text-[#33449c]', 'bg-[#dcefe6] text-[#22603f]', 'bg-[#f6e3d6] text-[#8a4114]', 'bg-[#efe0f3] text-[#6a2d7d]', 'bg-[#dfeef4] text-[#1f5c73]']
export function Avatar({ user, size = 'sm' }: { user: Pick<User, 'name' | 'email'> | null; size?: 'xs' | 'sm' | 'md' }) {
  const s = size === 'xs' ? 'size-5 text-[9px]' : size === 'md' ? 'size-8 text-xs' : 'size-6 text-[10px]'
  if (!user) return <span className={cn('inline-flex shrink-0 items-center justify-center rounded-full border border-dashed border-border-strong text-fg-subtle', s)} aria-label="Unassigned" />
  const initials = user.name.split(/\s+/).map((p) => p[0]).slice(0, 2).join('').toUpperCase()
  let h = 0
  for (const c of user.email) h = (h * 31 + c.charCodeAt(0)) >>> 0
  return (
    <span className={cn('inline-flex shrink-0 items-center justify-center rounded-full font-semibold dark:brightness-90', AVATAR_TONES[h % AVATAR_TONES.length], s)} title={user.name} aria-label={user.name}>
      {initials}
    </span>
  )
}

export function KeyValue({ items, className, cols = 2 }: { items: [ReactNode, ReactNode][]; className?: string; cols?: 1 | 2 | 3 }) {
  return (
    <dl className={cn('grid gap-x-6 gap-y-2.5 text-sm', cols === 1 ? 'grid-cols-1' : cols === 2 ? 'grid-cols-1 sm:grid-cols-2' : 'grid-cols-1 sm:grid-cols-3', className)}>
      {items.map(([k, v], i) => (
        <div key={i} className="min-w-0">
          <dt className="text-xs text-fg-subtle">{k}</dt>
          <dd className="mt-0.5 min-w-0 break-words">{v ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn('font-mono text-[12.5px] break-all', className)}>
      {children}
    </span>
  )
}
