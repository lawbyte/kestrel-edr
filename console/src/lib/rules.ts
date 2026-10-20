import type { RuleRow } from '@/api/types'

export type RuleSource = 'builtin' | 'sigmahq' | 'custom'

export const SOURCE_LABEL: Record<RuleSource, string> = { builtin: 'Built-in', sigmahq: 'SigmaHQ pack', custom: 'Custom Sigma' }

export const DRL_URL = 'https://github.com/SigmaHQ/Detection-Rule-License'

/**
 * Pinned upstream link of a SigmaHQ pack rule. The server seeds pack rules with
 * `references[0]` = the rule file at the vendored commit
 * (`https://github.com/SigmaHQ/sigma/blob/<40-hex commit>/rules/…`).
 */
export function upstreamUrl(r: Pick<RuleRow, 'references'>): string | null {
  return (r.references ?? []).find((x) => /^https:\/\/github\.com\/SigmaHQ\/sigma\/blob\/[0-9a-f]{40}\//i.test(x)) ?? null
}

/** Built-in, SigmaHQ pack (DRL 1.1 with a pinned upstream link) or a Sigma rule added in the console. */
export function ruleSource(r: Pick<RuleRow, 'kind' | 'license' | 'references'>): RuleSource {
  if (r.kind === 'builtin') return 'builtin'
  if (r.kind === 'sigma' && /DRL/i.test(r.license ?? '') && upstreamUrl(r)) return 'sigmahq'
  return 'custom'
}
