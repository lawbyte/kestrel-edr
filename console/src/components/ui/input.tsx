import { forwardRef, type InputHTMLAttributes, type TextareaHTMLAttributes } from 'react'
import { cn } from '@/lib/utils'

export const inputClass =
  'w-full rounded-md border border-border-strong bg-surface px-2.5 text-sm text-fg placeholder:text-fg-subtle transition-colors hover:border-fg-subtle/60 focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-0 focus-visible:border-transparent disabled:opacity-60 aria-[invalid=true]:border-danger'

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(({ className, ...p }, ref) => (
  <input ref={ref} className={cn(inputClass, 'h-8', className)} {...p} />
))
Input.displayName = 'Input'

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(({ className, ...p }, ref) => (
  <textarea ref={ref} className={cn(inputClass, 'min-h-20 py-2 leading-relaxed', className)} {...p} />
))
Textarea.displayName = 'Textarea'

export function Label({ className, ...p }: React.LabelHTMLAttributes<HTMLLabelElement>) {
  return <label className={cn('block text-sm font-medium text-fg', className)} {...p} />
}

export function Field({ label, hint, error, children, htmlFor, className }: { label: React.ReactNode; hint?: React.ReactNode; error?: string | null; children: React.ReactNode; htmlFor?: string; className?: string }) {
  return (
    <div className={cn('space-y-1.5', className)}>
      <Label htmlFor={htmlFor}>{label}</Label>
      {children}
      {error ? (
        <p className="text-xs text-danger" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-xs text-fg-muted">{hint}</p>
      ) : null}
    </div>
  )
}
