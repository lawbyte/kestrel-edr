import { ShieldPlus } from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { ACCOUNT_MFA_PATH } from '@/lib/mfa'
import { cn } from '@/lib/utils'

/** Link to the account page's two-factor section (`/account#mfa`). */
export function MfaSetupLink({ children = 'Set up two-factor authentication', className, onClick }: { children?: ReactNode; className?: string; onClick?: () => void }) {
  return (
    <Link to={ACCOUNT_MFA_PATH} onClick={onClick} className={cn('inline-flex items-center gap-1 font-medium text-accent-text underline-offset-2 hover:underline', className)}>
      <ShieldPlus className="size-3.5" aria-hidden />
      {children}
    </Link>
  )
}
