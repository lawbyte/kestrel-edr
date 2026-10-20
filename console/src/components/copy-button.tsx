import { Check, Copy } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { copyText } from '@/lib/utils'
import { Button } from './ui/button'

export function CopyButton({ text, label = 'Copy', iconOnly, size = 'sm' }: { text: string; label?: string; iconOnly?: boolean; size?: 'sm' | 'icon-sm' | 'md' }) {
  const [done, setDone] = useState(false)
  return (
    <Button
      size={iconOnly ? 'icon-sm' : size}
      variant={iconOnly ? 'ghost' : 'secondary'}
      aria-label={label}
      onClick={async (e) => {
        e.stopPropagation()
        await copyText(text)
        setDone(true)
        toast.success('Copied to clipboard')
        setTimeout(() => setDone(false), 1500)
      }}
    >
      {done ? <Check /> : <Copy />}
      {iconOnly ? null : done ? 'Copied' : label}
    </Button>
  )
}
