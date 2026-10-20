import { Tooltip as T, Switch as S, Checkbox as C, Tabs as Tb, ToggleGroup as TG, Popover as P, DropdownMenu as DM, Separator as Sep } from 'radix-ui'
import { Check, Minus } from 'lucide-react'
import type { ComponentProps, ReactNode } from 'react'
import { cn } from '@/lib/utils'

// ---------------------------------------------------------------- Tooltip
export function Tooltip({ content, children, side = 'top' }: { content: ReactNode; children: ReactNode; side?: 'top' | 'bottom' | 'left' | 'right' }) {
  if (!content) return <>{children}</>
  return (
    <T.Root delayDuration={250}>
      <T.Trigger asChild>{children}</T.Trigger>
      <T.Portal>
        <T.Content side={side} sideOffset={6} className="z-[60] max-w-xs rounded-md bg-fg px-2 py-1 text-xs text-bg shadow-pop data-[state=delayed-open]:animate-in">
          {content}
        </T.Content>
      </T.Portal>
    </T.Root>
  )
}
export const TooltipProvider = T.Provider

// ---------------------------------------------------------------- Switch
export function Switch({ className, ...p }: ComponentProps<typeof S.Root>) {
  return (
    <S.Root
      className={cn(
        'peer relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-transparent bg-surface-3 transition-colors data-[state=checked]:bg-accent disabled:cursor-not-allowed disabled:opacity-50 focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2',
        className,
      )}
      {...p}
    >
      <S.Thumb className="pointer-events-none block size-4 translate-x-0.5 rounded-full bg-white shadow-sm ring-0 transition-transform data-[state=checked]:translate-x-[18px]" />
    </S.Root>
  )
}

// ---------------------------------------------------------------- Checkbox
export function Checkbox({ className, checked, ...p }: ComponentProps<typeof C.Root>) {
  return (
    <C.Root
      checked={checked}
      className={cn(
        'flex size-4 shrink-0 items-center justify-center rounded-[4px] border border-border-strong bg-surface transition-colors data-[state=checked]:border-accent data-[state=checked]:bg-accent data-[state=indeterminate]:border-accent data-[state=indeterminate]:bg-accent text-accent-fg focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-1',
        className,
      )}
      {...p}
    >
      <C.Indicator>{checked === 'indeterminate' ? <Minus className="size-3" strokeWidth={3} /> : <Check className="size-3" strokeWidth={3} />}</C.Indicator>
    </C.Root>
  )
}

// ---------------------------------------------------------------- Tabs
export const Tabs = Tb.Root
export function TabsList({ className, ...p }: ComponentProps<typeof Tb.List>) {
  return <Tb.List className={cn('flex items-center gap-1 border-b border-border', className)} {...p} />
}
export function TabsTrigger({ className, ...p }: ComponentProps<typeof Tb.Trigger>) {
  return (
    <Tb.Trigger
      className={cn(
        'relative -mb-px inline-flex h-9 items-center gap-1.5 border-b-2 border-transparent px-2.5 text-sm font-medium text-fg-muted transition-colors hover:text-fg data-[state=active]:border-accent data-[state=active]:text-fg [&_svg]:size-4',
        className,
      )}
      {...p}
    />
  )
}
export const TabsContent = Tb.Content

// ---------------------------------------------------------------- Segmented control
export function Segmented<T extends string>({
  value,
  onChange,
  options,
  size = 'md',
  label,
  disabled,
}: {
  value: T
  onChange: (v: T) => void
  options: { value: T; label: ReactNode; title?: string; tone?: 'neutral' | 'accent' | 'warn' | 'danger' }[]
  size?: 'sm' | 'md'
  label: string
  disabled?: boolean
}) {
  return (
    <TG.Root
      type="single"
      value={value}
      onValueChange={(v) => v && onChange(v as T)}
      aria-label={label}
      disabled={disabled}
      className="inline-flex rounded-md border border-border-strong bg-surface-2 p-0.5"
    >
      {options.map((o) => (
        <TG.Item
          key={o.value}
          value={o.value}
          title={o.title}
          className={cn(
            'rounded-[5px] font-medium text-fg-muted transition-colors hover:text-fg data-[state=on]:bg-surface data-[state=on]:shadow-[0_1px_2px_rgb(0_0_0/0.12)] disabled:opacity-50',
            size === 'sm' ? 'h-6 px-2 text-xs' : 'h-7 px-3 text-sm',
            o.tone === 'accent' && 'data-[state=on]:text-accent-text',
            o.tone === 'warn' && 'data-[state=on]:text-warn',
            o.tone === 'danger' && 'data-[state=on]:text-danger',
            (!o.tone || o.tone === 'neutral') && 'data-[state=on]:text-fg',
          )}
        >
          {o.label}
        </TG.Item>
      ))}
    </TG.Root>
  )
}

// ---------------------------------------------------------------- Popover
export const Popover = P.Root
export const PopoverTrigger = P.Trigger
export function PopoverContent({ className, align = 'start', ...p }: ComponentProps<typeof P.Content>) {
  return (
    <P.Portal>
      <P.Content align={align} sideOffset={6} className={cn('z-50 rounded-lg border border-border bg-surface p-1 shadow-pop data-[state=open]:animate-in focus:outline-none', className)} {...p} />
    </P.Portal>
  )
}

// ---------------------------------------------------------------- Dropdown
export const Dropdown = DM.Root
export const DropdownTrigger = DM.Trigger
export function DropdownContent({ className, align = 'end', ...p }: ComponentProps<typeof DM.Content>) {
  return (
    <DM.Portal>
      <DM.Content align={align} sideOffset={6} className={cn('z-50 min-w-44 rounded-lg border border-border bg-surface p-1 shadow-pop data-[state=open]:animate-in', className)} {...p} />
    </DM.Portal>
  )
}
export function DropdownItem({ className, danger, ...p }: ComponentProps<typeof DM.Item> & { danger?: boolean }) {
  return (
    <DM.Item
      className={cn(
        'flex cursor-default items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-surface-2 data-[disabled]:opacity-50 [&_svg]:size-4 [&_svg]:text-fg-subtle',
        danger && 'text-danger [&_svg]:text-danger',
        className,
      )}
      {...p}
    />
  )
}
export function DropdownLabel({ className, ...p }: ComponentProps<typeof DM.Label>) {
  return <DM.Label className={cn('px-2 py-1 text-xs text-fg-subtle', className)} {...p} />
}
export function DropdownSeparator() {
  return <DM.Separator className="my-1 h-px bg-border" />
}
export const DropdownCheckboxItem = ({ className, children, ...p }: ComponentProps<typeof DM.CheckboxItem>) => (
  <DM.CheckboxItem className={cn('flex cursor-default items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-surface-2', className)} {...p}>
    <span className="flex size-4 items-center justify-center">
      <DM.ItemIndicator>
        <Check className="size-3.5" />
      </DM.ItemIndicator>
    </span>
    {children}
  </DM.CheckboxItem>
)
export const DropdownRadioGroup = DM.RadioGroup
export const DropdownRadioItem = ({ className, children, ...p }: ComponentProps<typeof DM.RadioItem>) => (
  <DM.RadioItem className={cn('flex cursor-default items-center gap-2 rounded-md px-2 py-1.5 text-sm outline-none data-[highlighted]:bg-surface-2', className)} {...p}>
    <span className="flex size-4 items-center justify-center">
      <DM.ItemIndicator>
        <Check className="size-3.5" />
      </DM.ItemIndicator>
    </span>
    {children}
  </DM.RadioItem>
)

export function Separator({ className, ...p }: ComponentProps<typeof Sep.Root>) {
  return <Sep.Root className={cn('bg-border data-[orientation=horizontal]:h-px data-[orientation=horizontal]:w-full data-[orientation=vertical]:h-full data-[orientation=vertical]:w-px', className)} {...p} />
}

// ---------------------------------------------------------------- small bits
export function Kbd({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <kbd className={cn('inline-flex h-5 min-w-5 items-center justify-center rounded border border-border-strong bg-surface-2 px-1 font-sans text-[11px] font-medium text-fg-muted', className)}>
      {children}
    </kbd>
  )
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-md bg-surface-3/70', className)} />
}
