import { KeyRound } from 'lucide-react'
import { createContext, useCallback, useContext, useMemo, useRef, useState, type ReactNode } from 'react'
import { invalidTotp, mfaNotEnabled, needsReauth, remoteApi, remoteErrorText, setReauthUntil } from '@/api/remote'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'

interface ReauthCtx {
  /** Ask for a TOTP code; resolves true once the server accepted it. */
  ask: () => Promise<boolean>
  /** Run `fn`; on 403 `reauth_required` ask for a code and retry once. */
  withReauth: <T>(fn: () => Promise<T>) => Promise<T>
}
const Ctx = createContext<ReauthCtx | null>(null)

/** MFA step-up for remote access (`require_mfa_reauth`): one dialog shared by the remote tabs. */
export function ReauthProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const resolver = useRef<((ok: boolean) => void) | null>(null)

  const ask = useCallback(
    () =>
      new Promise<boolean>((resolve) => {
        resolver.current?.(false)
        resolver.current = resolve
        setCode('')
        setError(null)
        setOpen(true)
      }),
    [],
  )
  const finish = (ok: boolean) => {
    resolver.current?.(ok)
    resolver.current = null
    setOpen(false)
  }
  const submit = async () => {
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
    setBusy(true)
    try {
      const r = await remoteApi.reauth(code)
      setReauthUntil(r.reauth_until)
      finish(true)
    } catch (e) {
      setError(
        mfaNotEnabled(e)
          ? 'Your account has no authenticator app. Turn on two-factor authentication in your account settings first.'
          : invalidTotp(e)
            ? 'That code didn’t work. Check your authenticator app and try the current code.'
            : remoteErrorText(e),
      )
    } finally {
      setBusy(false)
    }
  }
  const withReauth = useCallback(
    async <T,>(fn: () => Promise<T>): Promise<T> => {
      try {
        return await fn()
      } catch (e) {
        if (!needsReauth(e)) throw e
        if (!(await ask())) throw e
        return fn()
      }
    },
    [ask],
  )
  const value = useMemo(() => ({ ask, withReauth }), [ask, withReauth])
  return (
    <Ctx.Provider value={value}>
      {children}
      <Dialog open={open} onOpenChange={(o) => !o && finish(false)}>
        {open ? (
          <DialogContent
            size="sm"
            title="Confirm it’s you"
            description="This device’s remote-access profile requires a fresh MFA check. One confirmation is valid for 10 minutes."
            footer={
              <>
                <Button variant="ghost" onClick={() => finish(false)}>
                  Cancel
                </Button>
                <Button variant="primary" disabled={busy} onClick={() => void submit()}>
                  <KeyRound /> Confirm
                </Button>
              </>
            }
          >
            <form
              onSubmit={(e) => {
                e.preventDefault()
                void submit()
              }}
            >
              <Field label="Authenticator code" htmlFor="reauth-code" error={error}>
                <Input id="reauth-code" autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} placeholder="123456" className="font-mono tracking-widest" />
              </Field>
            </form>
          </DialogContent>
        ) : null}
      </Dialog>
    </Ctx.Provider>
  )
}

export function useReauth(): ReauthCtx {
  const v = useContext(Ctx)
  if (!v) throw new Error('useReauth outside ReauthProvider')
  return v
}
