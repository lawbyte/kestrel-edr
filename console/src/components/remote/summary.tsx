import { Info, Lock } from 'lucide-react'
import { Link } from 'react-router'
import type { RemoteAccessInfo } from '@/api/types'
import { Card } from '@/components/common'
import { Tooltip } from '@/components/ui/misc'
import { hoursText, normaliseProfile, profileSummary } from '@/lib/remote-profile'

function texts(info: RemoteAccessInfo) {
  const ceiling = normaliseProfile(info.ceiling)
  const policy = normaliseProfile(info.policy)
  const effective = normaliseProfile(info.effective)
  return {
    ceiling,
    policy,
    effective,
    ceilingText: info.ceiling_summary ?? profileSummary(ceiling),
    policyText: profileSummary(policy),
    effectiveText: info.effective_summary ?? profileSummary(effective),
  }
}

const CAP_NOTE = 'Capped by the install profile; changing the ceiling requires reinstalling the agent with another profile.'

/** Device overview card: install ceiling, policy and effective remote access. */
export function RemoteAccessSummaryCard({ info, policyId, policyName }: { info: RemoteAccessInfo; policyId: string | null; policyName: string | null }) {
  const t = texts(info)
  const hours = t.effective.guardrails.allowed_hours
  return (
    <Card title="Remote access" description={CAP_NOTE}>
      <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-3">
        <div>
          <dt className="flex items-center gap-1 text-xs text-fg-subtle">
            <Lock className="size-3" aria-hidden /> Install ceiling
          </dt>
          <dd className="mt-0.5">{t.ceilingText}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">
            Policy
            {policyId ? (
              <>
                {': '}
                <Link to={`/policies/${policyId}#remote`} className="hover:underline">
                  {policyName ?? 'open'}
                </Link>
              </>
            ) : null}
          </dt>
          <dd className="mt-0.5">{t.policyText}</dd>
        </div>
        <div>
          <dt className="text-xs text-fg-subtle">Effective (what the agent enforces)</dt>
          <dd className="mt-0.5 font-medium">{t.effectiveText}</dd>
          {hours ? <dd className="mt-0.5 text-xs text-fg-muted">Allowed: {hoursText(hours)}</dd> : null}
        </div>
      </dl>
    </Card>
  )
}

/** One-line version for the remote tabs. */
export function RemoteAccessSummaryLine({ info }: { info: RemoteAccessInfo }) {
  const t = texts(info)
  const same = t.ceilingText === t.effectiveText && t.policyText === t.effectiveText
  return (
    <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-fg-muted">
      <span>
        <span className="text-fg-subtle">Effective:</span> <span className="font-medium text-fg">{t.effectiveText}</span>
        {same ? <span className="text-fg-subtle"> (install ceiling and policy agree)</span> : null}
      </span>
      {same ? null : (
        <>
          <span aria-hidden>·</span>
          <span>
            <span className="text-fg-subtle">Ceiling:</span> {t.ceilingText}
          </span>
          <span aria-hidden>·</span>
          <span>
            <span className="text-fg-subtle">Policy:</span> {t.policyText}
          </span>
        </>
      )}
      <Tooltip content={CAP_NOTE}>
        <Info className="size-3.5 text-fg-subtle" aria-label={CAP_NOTE} />
      </Tooltip>
    </p>
  )
}
