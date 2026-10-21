/**
 * Remote access (admin only): remote file manager REST calls and the remote
 * desktop WebSocket. See docs/contracts.md "Remote access".
 *
 * Downloads: the browser must stream large files straight to disk (up to
 * 4 GiB), so we never buffer them in JS. We first call `files/stat` — that
 * surfaces every error that can happen before the first byte (offline,
 * protected path, not found, folder, too large, policy off) as JSON we can
 * show inline — and then navigate a hidden anchor to the download URL (same
 * origin, session cookie) so the browser's own download manager streams it.
 * An error after streaming started shows up as a failed download in the
 * browser (and is audited server-side). In mock mode there is no server to
 * navigate to, so the mock serves the Blob through the patched `fetch`.
 *
 * Uploads use XMLHttpRequest (fetch has no upload progress) with the raw
 * `File` as the body, which also makes the browser set `Content-Length`.
 */
import { API_BASE, ApiError, IS_MOCK, apiErrorFrom, getCsrfToken, http, qs } from './client'
import type { FileEntry, FileListResponse, FileUploadResult, RemoteDesktopStatus, RemoteErrorCode, RemoteUnavailableReason } from './types'

/** Largest single transfer (`TRANSFER_MAX`). */
export const TRANSFER_MAX = 4 * 1024 * 1024 * 1024

const dev = (id: string) => `/devices/${encodeURIComponent(id)}`

/** File-manager session context sent with every `/files…` request (consent per `fm_session`, reason for audit / banner). */
export interface FmContext {
  fmSession: string
  reason: string
}
const ctxQuery = (c: FmContext) => ({ fm_session: c.fmSession, reason: c.reason.trim() || undefined })
const withCtx = (path: string, c: FmContext, q: Record<string, string | undefined> = {}) => `${path}${qs({ ...q, ...ctxQuery(c) })}`

export const remoteApi = {
  listFiles: (id: string, path: string, c: FmContext) => http.get<FileListResponse>(`${dev(id)}/files`, { path: path || undefined, ...ctxQuery(c) }),
  stat: (id: string, path: string, c: FmContext) => http.get<FileEntry>(`${dev(id)}/files/stat`, { path, ...ctxQuery(c) }),
  rename: (id: string, from: string, to: string, c: FmContext, overwrite = false) => http.post<{ from: string; to: string }>(withCtx(`${dev(id)}/files/rename`, c), { from, to, overwrite }),
  remove: (id: string, path: string, recursive: boolean, c: FmContext) => http.post<{ path: string; removed: number }>(withCtx(`${dev(id)}/files/delete`, c), { path, recursive }),
  mkdir: (id: string, path: string, c: FmContext) => http.post<{ path: string }>(withCtx(`${dev(id)}/files/mkdir`, c), { path }),
  desktopStatus: (id: string) => http.get<RemoteDesktopStatus>(`${dev(id)}/remote-desktop/status`),
  downloadUrl: (id: string, path: string, c: FmContext) => `${API_BASE}${withCtx(`${dev(id)}/files/download`, c, { path })}`,
  reauth: (totp: string) => http.post<{ reauth_until: number }>('/me/reauth', { totp }),
}

// ------------------------------------------------------------------ MFA step-up (require_mfa_reauth)

let reauthUntil = 0
/** Remember the step-up window returned by `POST /me/reauth` (server is the authority). */
export function setReauthUntil(ms: number) {
  reauthUntil = ms
}
/** A recent re-auth is (probably) still valid; leave a minute of margin. */
export function reauthFresh(now = Date.now()): boolean {
  return reauthUntil - 60_000 > now
}
/** The request failed because the admin must re-enter a TOTP code. */
export const needsReauth = (e: unknown) => e instanceof ApiError && e.status === 403 && e.extra?.reason === 'reauth_required'
/** Wrong TOTP on `POST /me/reauth`: 400 `reason: "invalid_totp"` (a 401 there is also a wrong code, never a logout). */
export const invalidTotp = (e: unknown) => e instanceof ApiError && ((e.status === 400 && e.extra?.reason === 'invalid_totp') || e.status === 401)
export const mfaNotEnabled = (e: unknown) => e instanceof ApiError && e.status === 403 && e.extra?.reason === 'mfa_not_enabled'

export const remoteKeys = {
  files: (id: string, path: string) => ['device', id, 'files', path] as const,
}

export async function downloadFile(id: string, path: string, c: FmContext): Promise<FileEntry> {
  const st = await remoteApi.stat(id, path, c)
  if (st.kind === 'dir' || st.kind === 'drive') throw new ApiError(400, 'bad_request', 'Folders cannot be downloaded. Open the folder and download files one by one.', 'invalid_operation')
  if (st.size > TRANSFER_MAX) throw new ApiError(413, 'payload_too_large', 'The file is larger than 4 GiB.', 'too_large')
  const url = remoteApi.downloadUrl(id, path, c)
  let href = url
  let revoke: string | null = null
  if (IS_MOCK) {
    const res = await fetch(url)
    if (!res.ok) throw apiErrorFrom(res.status, await res.text())
    href = revoke = URL.createObjectURL(await res.blob())
  }
  const a = document.createElement('a')
  a.href = href
  a.download = st.name
  a.rel = 'noopener'
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  a.remove()
  if (revoke) {
    const r = revoke
    setTimeout(() => URL.revokeObjectURL(r), 60_000)
  }
  return st
}

export interface UploadHandle {
  promise: Promise<FileUploadResult>
  abort: () => void
}

/** Upload `file` to the exact target path (create or overwrite). */
export function uploadFile(id: string, target: string, file: Blob, c: FmContext, onProgress: (loaded: number, total: number) => void): UploadHandle {
  if (file.size > TRANSFER_MAX) {
    return { promise: Promise.reject(new ApiError(413, 'payload_too_large', 'The file is larger than 4 GiB.', 'too_large')), abort: () => {} }
  }
  const url = `${API_BASE}${withCtx(`${dev(id)}/files/upload`, c, { path: target })}`
  if (IS_MOCK) {
    const ctl = new AbortController()
    const promise = import('@/mock/server').then(({ mockUpload }) => mockUpload(id, target, file, c, onProgress, ctl.signal))
    return { promise, abort: () => ctl.abort() }
  }
  const xhr = new XMLHttpRequest()
  const promise = new Promise<FileUploadResult>((resolve, reject) => {
    xhr.open('POST', url)
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    xhr.setRequestHeader('Accept', 'application/json')
    const csrf = getCsrfToken()
    if (csrf) xhr.setRequestHeader('X-CSRF-Token', csrf)
    xhr.upload.onprogress = (e) => onProgress(e.loaded, e.lengthComputable ? e.total : file.size)
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as FileUploadResult)
        } catch {
          resolve({ path: target, size: file.size, sha256: '' })
        }
      } else reject(apiErrorFrom(xhr.status, xhr.responseText))
    }
    xhr.onerror = () => reject(new ApiError(0, 'network', 'The upload was interrupted. Check your connection and try again.'))
    xhr.onabort = () => reject(new ApiError(0, 'aborted', 'Upload cancelled.'))
    xhr.send(file)
  })
  return { promise, abort: () => xhr.abort() }
}

// ------------------------------------------------------------------ errors

export const REMOTE_ERROR_TEXT: Record<RemoteErrorCode, string> = {
  disabled_by_policy: 'This device’s policy does not allow that.',
  not_permitted: 'This device’s install profile does not allow that. Only reinstalling the agent with another profile can change it.',
  consent_denied: 'The employee denied access (or no one was signed in to answer).',
  consent_timeout: 'The employee did not answer the access request in time.',
  outside_allowed_hours: 'Remote access is outside the allowed hours for this device (device local time).',
  reason_required: 'A reason is required for remote access to this device.',
  blocked_path: 'That folder is blocked for remote access by the device’s profile. Folders that contain a blocked folder can’t be renamed or deleted either.',
  invalid_path: 'That path is not valid on Windows.',
  protected_path: 'Kestrel’s own folders can’t be changed from here.',
  not_found: 'That file or folder doesn’t exist (any more).',
  already_exists: 'Something with that name already exists here.',
  access_denied: 'Windows denied access. The file may be open in another program or locked.',
  invalid_operation: 'That isn’t possible here (for example, the target is a folder, or the folder is not empty).',
  integrity_error: 'The transfer didn’t verify (size or checksum mismatch, or the file changed meanwhile). Try again.',
  too_large: 'The file is too large. Transfers are limited to 4 GiB.',
  busy: 'Another session is already active on this device.',
  unavailable: 'The device can’t do that right now (for example, a network drive, or no one is signed in).',
  timeout: 'The device didn’t answer in time. It may be busy or its connection is slow.',
  io: 'The device reported a disk or file-system error.',
  other: 'The device reported an unexpected error.',
}

/** Plain-words message for a failed remote-access call. */
export function remoteErrorText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.remoteCode && REMOTE_ERROR_TEXT[e.remoteCode]) {
      const base = REMOTE_ERROR_TEXT[e.remoteCode]
      // The detail helps for these (which rule the path broke, which OS error).
      const detail = e.remoteCode === 'invalid_path' || e.remoteCode === 'io' || e.remoteCode === 'other'
      return detail && e.message ? `${base} (${e.message})` : base
    }
    const r = e.extra?.reason
    if (r === 'disabled_by_policy' || r === 'not_permitted' || r === 'reason_required') return REMOTE_ERROR_TEXT[r]
    if (r === 'reauth_required') return 'Confirm your authenticator code to continue (required every 10 minutes for this device).'
    if (r === 'mfa_not_enabled') return 'This device requires an MFA re-check, but your account has no authenticator app. Turn on two-factor authentication for your account first.'
    if (e.status === 408) return REMOTE_ERROR_TEXT.consent_timeout
    if (e.status === 409 && /offline/i.test(e.message)) return 'The device is offline. Remote access needs the agent to be connected.'
    if (e.status === 403) return e.message || 'You don’t have permission for remote access. It needs the admin role and an interactive console sign-in.'
    if (e.status === 504) return REMOTE_ERROR_TEXT.timeout
    return e.message
  }
  return e instanceof Error ? e.message : 'Something went wrong.'
}

export const UNAVAILABLE_TEXT: Record<RemoteUnavailableReason, string> = {
  not_permitted: 'Not permitted by the install profile this device was enrolled with. Changing it requires reinstalling the agent with another profile.',
  offline: 'The device is offline. Remote access needs the agent to be connected to the server.',
  disabled_by_policy: 'Switched off in this device’s policy.',
  agent_too_old: 'The agent on this device is too old for remote access. Update it first.',
  decommissioned: 'This device is decommissioned.',
}

// ------------------------------------------------------------------ desktop socket

/** The subset of WebSocket the remote desktop view uses (implemented by the mock too). */
export interface DesktopSocket {
  readonly readyState: number
  binaryType: BinaryType
  onopen: ((ev: Event) => void) | null
  onmessage: ((ev: MessageEvent) => void) | null
  onclose: ((ev: CloseEvent) => void) | null
  onerror: ((ev: Event) => void) | null
  send(data: string): void
  close(code?: number, reason?: string): void
}

export async function openDesktopSocket(url: string): Promise<DesktopSocket> {
  if (IS_MOCK) {
    const { MockDesktopSocket } = await import('@/mock/desktop')
    return new MockDesktopSocket(url)
  }
  const ws = new WebSocket(url)
  ws.binaryType = 'arraybuffer'
  return ws
}
