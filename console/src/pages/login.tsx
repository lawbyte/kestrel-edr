import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { KeyRound, ShieldCheck } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { ApiError, IS_MOCK, setCsrfToken } from '@/api/client'
import { api, qk } from '@/api/endpoints'
import { Button } from '@/components/ui/button'
import { Field, Input } from '@/components/ui/input'
import { KestrelMark } from '@/components/logo'
import { ErrorState } from '@/components/common'

export function LoginPage() {
  const status = useQuery({ queryKey: qk.setup, queryFn: api.setupStatus, retry: 1 })
  if (status.error) return <ErrorState error={status.error} onRetry={() => status.refetch()} className="h-full" />
  return (
    <div className="grid min-h-full lg:grid-cols-[1fr_minmax(0,560px)]">
      <aside className="relative hidden overflow-hidden border-r border-border bg-sidebar lg:flex lg:flex-col lg:justify-between lg:p-10">
        <div className="flex items-center gap-2.5">
          <KestrelMark className="size-8" />
          <span className="text-lg font-semibold tracking-[-0.01em]">Kestrel EDR</span>
        </div>
        <div className="max-w-md">
          <p className="text-[1.75rem] font-semibold leading-tight tracking-[-0.02em]">Stops password-stealing malware before the upload finishes.</p>
          <p className="mt-3 text-fg-muted">Self-hosted. Your telemetry stays on {status.data?.org_name || 'your'} servers.</p>
        </div>
        <Flightpath />
      </aside>
      <div className="flex items-center justify-center p-6">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <KestrelMark className="size-8" />
            <span className="text-lg font-semibold">Kestrel EDR</span>
          </div>
          {status.isPending ? <p className="text-sm text-fg-subtle">Checking server…</p> : status.data?.needs_setup ? <SetupForm /> : <LoginForm oidc={!!status.data?.oidc_enabled} org={status.data?.org_name ?? ''} />}
        </div>
      </div>
    </div>
  )
}

function Flightpath() {
  // Decorative: the kestrel's hover-and-stoop path, drawn once.
  return (
    <svg viewBox="0 0 400 120" className="w-full max-w-md text-border-strong" aria-hidden>
      <path d="M0 90 C 60 90, 90 30, 150 30 S 230 30, 250 30 L 268 30 C 290 30, 300 100, 330 104 L 400 104" fill="none" stroke="currentColor" strokeWidth="1.5" strokeDasharray="3 5" />
      <circle cx="259" cy="30" r="4" fill="var(--accent)" />
      <circle cx="330" cy="104" r="3" fill="var(--sev-critical)" />
    </svg>
  )
}

function useSignedIn() {
  const qc = useQueryClient()
  return async (csrf: string) => {
    setCsrfToken(csrf)
    await qc.invalidateQueries({ queryKey: qk.me })
  }
}

function LoginForm({ oidc, org }: { oidc: boolean; org: string }) {
  const [email, setEmail] = useState(IS_MOCK ? 'priya.raman@harbourline.sg' : '')
  const [password, setPassword] = useState('')
  const [totp, setTotp] = useState('')
  const [needTotp, setNeedTotp] = useState(false)
  const signedIn = useSignedIn()
  const login = useMutation({
    mutationFn: () => api.login({ email, password, totp: needTotp ? totp : undefined }),
    onSuccess: (r) => signedIn(r.csrf_token),
    onError: (e) => {
      if (e instanceof ApiError && (e.code === 'mfa_required' || /code|totp|authenticator/i.test(e.message)) && !needTotp) setNeedTotp(true)
    },
  })
  const err = login.error instanceof ApiError && !(login.error.code === 'mfa_required' && !totp) ? login.error.message : login.error ? String(login.error) : null
  const submit = (e: FormEvent) => {
    e.preventDefault()
    login.mutate()
  }
  return (
    <form onSubmit={submit} className="space-y-5" noValidate>
      <div>
        <h1 className="text-xl font-semibold tracking-[-0.01em]">Sign in{org ? ` to ${org}` : ''}</h1>
        <p className="mt-1 text-sm text-fg-muted">Use your Kestrel console account.</p>
      </div>
      {oidc ? (
        <>
          <Button asChild variant="secondary" size="lg" className="w-full">
            <a href="/api/auth/oidc/start">
              <ShieldCheck /> Continue with single sign-on
            </a>
          </Button>
          <div className="flex items-center gap-3 text-xs text-fg-subtle">
            <span className="h-px flex-1 bg-border" />
            or with email
            <span className="h-px flex-1 bg-border" />
          </div>
        </>
      ) : null}
      <Field label="Email" htmlFor="email">
        <Input id="email" type="email" autoComplete="username" value={email} onChange={(e) => setEmail(e.target.value)} required className="h-9" />
      </Field>
      <Field label="Password" htmlFor="password">
        <Input id="password" type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required className="h-9" autoFocus={IS_MOCK} />
      </Field>
      {needTotp ? (
        <Field label="Authentication code" htmlFor="totp" hint="The 6-digit code from your authenticator app.">
          <Input
            id="totp"
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            value={totp}
            onChange={(e) => setTotp(e.target.value.replace(/\D/g, ''))}
            autoFocus
            className="h-9 font-mono tracking-[0.3em]"
          />
        </Field>
      ) : null}
      {err && !(needTotp && !totp) ? (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-sm text-danger">
          {err}
        </p>
      ) : null}
      <Button type="submit" variant="primary" size="lg" className="w-full" disabled={login.isPending || !email || !password}>
        <KeyRound /> {login.isPending ? 'Signing in…' : 'Sign in'}
      </Button>
      {IS_MOCK ? <p className="text-center text-xs text-fg-subtle">Demo: any password, then any 6-digit code.</p> : null}
    </form>
  )
}

function SetupForm() {
  const [code, setCode] = useState('')
  const [org, setOrg] = useState('')
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const signedIn = useSignedIn()
  const setup = useMutation({ mutationFn: () => api.setup({ setup_code: code.trim(), org_name: org, name, email, password }), onSuccess: (r) => signedIn(r.csrf_token) })
  const pwErr = password && password.length < 12 ? 'Use at least 12 characters' : null
  const cfErr = confirm && confirm !== password ? 'Passwords don’t match' : null
  const valid = code.trim() && org && name && /\S+@\S+/.test(email) && password.length >= 12 && confirm === password
  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault()
        if (valid) setup.mutate()
      }}
    >
      <div>
        <h1 className="text-xl font-semibold tracking-[-0.01em]">Set up Kestrel</h1>
        <p className="mt-1 text-sm text-fg-muted">Name your organisation and create the first administrator. You can add more people later.</p>
      </div>
      <Field
        label="Setup code"
        htmlFor="setup-code"
        hint="Printed in the Kestrel server log at startup (look for “KESTREL SETUP CODE”), or the value of KESTREL_SETUP_CODE. It proves you run this server."
      >
        <Input id="setup-code" value={code} onChange={(e) => setCode(e.target.value)} autoFocus autoComplete="off" spellCheck={false} className="h-9 font-mono uppercase" />
      </Field>
      <Field label="Organisation name" htmlFor="org" hint="Shown to employees in the Kestrel tray app.">
        <Input id="org" value={org} onChange={(e) => setOrg(e.target.value)} className="h-9" />
      </Field>
      <Field label="Your name" htmlFor="name">
        <Input id="name" value={name} onChange={(e) => setName(e.target.value)} className="h-9" />
      </Field>
      <Field label="Email" htmlFor="setup-email">
        <Input id="setup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="h-9" />
      </Field>
      <Field label="Password" htmlFor="setup-pw" error={pwErr}>
        <Input id="setup-pw" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-9" aria-invalid={!!pwErr} />
      </Field>
      <Field label="Confirm password" htmlFor="setup-pw2" error={cfErr}>
        <Input id="setup-pw2" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="h-9" aria-invalid={!!cfErr} />
      </Field>
      {setup.error ? (
        <p role="alert" className="rounded-md border border-danger/30 bg-danger-soft px-3 py-2 text-sm text-danger">
          {(setup.error as Error).message}
        </p>
      ) : null}
      <Button type="submit" variant="primary" size="lg" className="w-full" disabled={!valid || setup.isPending}>
        {setup.isPending ? 'Creating…' : 'Create organisation'}
      </Button>
    </form>
  )
}
