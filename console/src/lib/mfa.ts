import { ApiError } from '@/api/client'

/** Route of the self-service account page (two-factor authentication lives there). */
export const ACCOUNT_MFA_PATH = '/account#mfa'

/** A TOTP code as typed by a person: digits only, at most 6. */
export function cleanTotp(v: string): string {
  return v.replace(/\D/g, '').slice(0, 6)
}

/** Base32 secret in groups of four for manual entry (`JBSW Y3DP …`). */
export function groupSecret(secret: string): string {
  return secret.replace(/\s+/g, '').replace(/(.{4})/g, '$1 ').trim()
}

/** Issuer and account label from an `otpauth://totp/Issuer:account?...` URI, for display. */
export function otpauthLabel(uri: string): { issuer: string | null; account: string | null } {
  try {
    const u = new URL(uri)
    const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''))
    const [a, b] = label.includes(':') ? label.split(/:(.*)/s) : [null, label]
    return { issuer: u.searchParams.get('issuer') ?? a ?? null, account: (b ?? '').trim() || null }
  } catch {
    return { issuer: null, account: null }
  }
}

function retrySeconds(e: ApiError): number | null {
  const ms = Number(e.extra?.retry_after_ms)
  return Number.isFinite(ms) && ms > 0 ? Math.ceil(ms / 1000) : null
}

/** Plain-words message for a failed `/me/mfa/*` call. */
export function mfaErrorText(e: unknown, op: 'setup' | 'enable' | 'disable'): string {
  if (!(e instanceof ApiError)) return e instanceof Error ? e.message : 'Something went wrong.'
  if (e.status === 429) {
    const s = retrySeconds(e)
    return s ? `Too many attempts. Wait ${s} second${s === 1 ? '' : 's'} and try again.` : 'Too many attempts. Wait a moment and try again.'
  }
  if (e.status === 400) {
    if (/setup/i.test(e.message)) return 'The setup expired. Start again to get a new QR code.'
    if (op === 'enable' || e.extra?.reason === 'invalid_totp') return 'That code didn’t work. Check that the clock on your phone is correct and enter the current 6-digit code.'
    return e.message
  }
  if (e.status === 409) return 'Two-factor authentication is already on for your account.'
  if (e.status === 403) {
    if (/required by policy/i.test(e.message)) return 'Your organisation requires two-factor authentication, so it can’t be turned off. An administrator can change this in Settings → Single sign-on.'
    if (/password/i.test(e.message)) return 'That password is wrong.'
    return e.message || 'Only an interactive console sign-in can change two-factor authentication (API tokens can’t).'
  }
  if (e.status === 0) return e.message
  return e.message || `Request failed (${e.status})`
}
