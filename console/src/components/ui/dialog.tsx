import { Dialog as D } from 'radix-ui'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/utils'

export const Dialog = D.Root
export const DialogTrigger = D.Trigger
export const DialogClose = D.Close

export function DialogContent({
  title,
  description,
  children,
  className,
  footer,
  size = 'md',
}: {
  title: ReactNode
  description?: ReactNode
  children?: ReactNode
  className?: string
  footer?: ReactNode
  size?: 'sm' | 'md' | 'lg' | 'xl'
}) {
  const w = { sm: 'max-w-md', md: 'max-w-lg', lg: 'max-w-2xl', xl: 'max-w-4xl' }[size]
  return (
    <D.Portal>
      <D.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[1px] data-[state=open]:animate-in" />
      <D.Content
        className={cn(
          'fixed left-1/2 top-[12vh] z-50 flex max-h-[80vh] w-[calc(100vw-2rem)] -translate-x-1/2 flex-col rounded-xl border border-border bg-surface shadow-pop data-[state=open]:animate-in',
          w,
          className,
        )}
      >
        <div className="flex items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div className="min-w-0">
            <D.Title className="text-base font-semibold leading-6">{title}</D.Title>
            {description ? <D.Description className="mt-0.5 text-sm text-fg-muted">{description}</D.Description> : <D.Description className="sr-only">{typeof title === 'string' ? title : 'Dialog'}</D.Description>}
          </div>
          <D.Close className="-mr-1 rounded-md p-1 text-fg-subtle hover:bg-surface-2 hover:text-fg" aria-label="Close">
            <X className="size-4" />
          </D.Close>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">{children}</div>
        {footer ? <div className="flex items-center justify-end gap-2 border-t border-border px-5 py-3">{footer}</div> : null}
      </D.Content>
    </D.Portal>
  )
}
