import type { ApiErrorBody, RemoteErrorCode } from './types'

export const API_BASE = '/api'
export const IS_MOCK = import.meta.env.VITE_MOCK === '1'

let csrfToken: string | null = null
export function setCsrfToken(t: string | null) {
  csrfToken = t
}
export function getCsrfToken(): string | null {
  return csrfToken
}

export class ApiError extends Error {
  status: number
  code: string
  /** Remote-access failures carry the machine-readable `remote_code`. */
  remoteCode?: RemoteErrorCode
  extra?: Record<string, unknown>
  constructor(status: number, code: string, message: string, remoteCode?: RemoteErrorCode, extra?: Record<string, unknown>) {
    super(message)
    this.status = status
    this.code = code
    this.remoteCode = remoteCode
    this.extra = extra
  }
}

/**
 * Extra error details. The server flattens them into the `error` object
 * (`{"error":{"code","message","reason":"reauth_required"}}`); an `extra`
 * object is accepted too.
 */
export function extraOf(err: ApiErrorBody['error'] | undefined): Record<string, unknown> | undefined {
  if (!err) return undefined
  const { code: _c, message: _m, remote_code: _r, extra, ...rest } = err as ApiErrorBody['error'] & Record<string, unknown>
  const merged = { ...(extra && typeof extra === 'object' ? (extra as Record<string, unknown>) : {}), ...rest }
  return Object.keys(merged).length ? merged : undefined
}

/** 401s from these paths are answers, not an expired session (no global logout). */
const NOT_A_LOGOUT = (path: string) => path.startsWith('/auth/') || path === '/me' || path === '/me/reauth'

/** Build an ApiError from a failed response's (possibly empty / non-JSON) body text. */
export function apiErrorFrom(status: number, text: string): ApiError {
  let err: ApiErrorBody['error'] | undefined
  try {
    err = text ? (JSON.parse(text) as ApiErrorBody | undefined)?.error : undefined
  } catch {
    err = undefined
  }
  return new ApiError(status, err?.code ?? 'internal', err?.message ?? `Request failed (${status})`, err?.remote_code, extraOf(err))
}

type Query = Record<string, string | number | boolean | null | undefined | string[]>

export function qs(q?: Query): string {
  if (!q) return ''
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(q)) {
    if (v == null || v === '' || (Array.isArray(v) && v.length === 0)) continue
    p.set(k, Array.isArray(v) ? v.join(',') : String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

/** Listeners notified on 401 so the app can route to the login screen. */
const unauthorizedListeners = new Set<() => void>()
export function onUnauthorized(fn: () => void) {
  unauthorizedListeners.add(fn)
  return () => unauthorizedListeners.delete(fn)
}

export async function request<T>(method: string, path: string, body?: unknown, query?: Query): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  if (method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}${qs(query)}`, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new ApiError(0, 'network', 'Cannot reach the Kestrel server. Check your connection and try again.')
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  let data: unknown = undefined
  if (text) {
    try {
      data = JSON.parse(text)
    } catch {
      data = undefined
    }
  }
  if (!res.ok) {
    const err = (data as ApiErrorBody | undefined)?.error
    if (res.status === 401 && !NOT_A_LOGOUT(path)) unauthorizedListeners.forEach((f) => f())
    throw new ApiError(res.status, err?.code ?? 'internal', err?.message ?? `Request failed (${res.status})`, err?.remote_code, extraOf(err))
  }
  return data as T
}

export const http = {
  get: <T>(path: string, query?: Query) => request<T>('GET', path, undefined, query),
  post: <T>(path: string, body?: unknown) => request<T>('POST', path, body ?? {}),
  put: <T>(path: string, body: unknown) => request<T>('PUT', path, body),
  patch: <T>(path: string, body: unknown) => request<T>('PATCH', path, body),
  del: <T = void>(path: string) => request<T>('DELETE', path),
}
