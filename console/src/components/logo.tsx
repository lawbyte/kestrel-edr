import { cn } from '@/lib/utils'

/** Kestrel mark: a stooping falcon wing over a shield edge. */
export function KestrelMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={cn('shrink-0', className)} aria-hidden>
      <rect width="32" height="32" rx="8" fill="var(--accent)" />
      <path d="M6.5 19.5 16 7l9.5 12.5-9.5-3.8z" fill="var(--accent-fg)" />
      <path d="M16 18.6 11.6 25h8.8z" fill="var(--accent-fg)" opacity=".55" />
    </svg>
  )
}
