import { CloudOff, Download, PowerOff, ShieldOff } from 'lucide-react'
import { Link } from 'react-router'
import { UNAVAILABLE_TEXT } from '@/api/remote'
import type { RemoteAvailability } from '@/api/types'

/** Disabled state of a remote-access tab, with a plain explanation of why. */
export function RemoteUnavailable({ feature, availability, policyId }: { feature: 'desktop' | 'files'; availability: RemoteAvailability; policyId: string | null }) {
  const reason = availability.reason ?? 'offline'
  const Icon = reason === 'disabled_by_policy' ? ShieldOff : reason === 'agent_too_old' ? Download : reason === 'decommissioned' ? PowerOff : CloudOff
  const what = feature === 'desktop' ? 'Remote desktop' : 'The file manager'
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-surface px-6 py-12 text-center" role="status">
      <div className="mb-3 flex size-10 items-center justify-center rounded-full bg-surface-2 text-fg-subtle">
        <Icon className="size-5" aria-hidden />
      </div>
      <p className="text-sm font-medium">{what} is not available for this device</p>
      <p className="mt-1 max-w-md text-sm text-fg-muted">
        {UNAVAILABLE_TEXT[reason]}{' '}
        {reason === 'disabled_by_policy' && policyId ? (
          <>
            An admin can turn it on under{' '}
            <Link className="text-accent-text hover:underline" to={`/policies/${policyId}#remote`}>
              the policy’s Remote access section
            </Link>
            .
          </>
        ) : reason === 'agent_too_old' ? (
          <>
            See{' '}
            <Link className="text-accent-text hover:underline" to="/updates">
              Agent updates
            </Link>
            .
          </>
        ) : null}
      </p>
    </div>
  )
}
