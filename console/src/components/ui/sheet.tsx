import { Dialog as D } from 'radix-ui'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

/** Right-side drawer. Non-modal overlay so the queue behind stays visible. */
export function Sheet({ open, onOpenChange, children, className, label }: { open: boolean; onOpenChange: (o: boolean) => void; children: ReactNode; className?: string; label: string }) {
  return (
    <D.Root open={open} onOpenChange={onOpenChange} modal={false}>
      <D.Portal>
        <D.Content
          onInteractOutside={(e) => e.preventDefault()}
          onOpenAutoFocus={(e) => e.preventDefault()}
          aria-label={label}
          data-drawer=""
          className={cn(
            'fixed inset-y-0 right-0 z-40 flex w-full max-w-[560px] flex-col border-l border-border bg-surface shadow-pop data-[state=open]:animate-slide-in focus:outline-none',
            className,
          )}
        >
          <D.Title className="sr-only">{label}</D.Title>
          <D.Description className="sr-only">{label}</D.Description>
          {children}
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}
export const SheetClose = D.Close
