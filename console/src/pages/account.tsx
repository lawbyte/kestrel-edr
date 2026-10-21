import { useMutation, useQueryClient } from '@tanstack/react-query'
import { CheckCircle2, KeyRound, Loader2, LockKeyhole, ShieldAlert, ShieldCheck, ShieldOff, ShieldPlus } from 'lucide-react'
import { useEffect, useState } from 'react'
import { useLocation } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { MeResponse, MfaSetup, User } from '@/api/types'
import { Avatar, Card, KeyValue, PageHeader } from '@/components/common'
import { CopyButton } from '@/components/copy-button'
import { QrCode } from '@/components/qr-code'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { formatDateTime } from '@/lib/format'
import { cleanTotp, groupSecret, mfaErrorText, otpauthLabel } from '@/lib/mfa'
import { cn } from '@/lib/utils'

export default function AccountPage() {
  const { me } = useAuth()
  const loc = useLocation()
  useEffect(() => {
    if (loc.hash === '#mfa') document.getElementById('mfa')?.scrollIntoView({ block: 'start' })
  }, [loc.hash])
  const u = me.user
  return (
    <div className="pb-16">
      <PageHeader title="Your account" description={`Profile and sign-in security for ${u.email}.`} />
      <div className="space-y-5 p-6">
        {me.mfa_setup_required ? (
          <div role="alert" className="flex items-start gap-2.5 rounded-lg border border-warn/40 bg-warn-soft px-4 py-3 text-sm">
            <ShieldAlert className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
            <div>
              <p className="font-medium">Your organisation requires two-factor authentication</p>
              <p className="mt-0.5 text-fg-muted">Set it up below to continue. Until you do, the rest of the console is unavailable for this sign-in.</p>
            </div>
          </div>
        ) : null}
        <div className="grid items-start gap-5 lg:grid-cols-3">
          <Card title="Profile">
            <div className="mb-4 flex items-center gap-3">
              <Avatar user={u} size="md" />
              <div className="min-w-0">
                <p className="truncate font-medium">{u.name}</p>
                <p className="truncate text-xs text-fg-muted">{u.email}</p>
              </div>
            </div>
            <KeyValue
              cols={1}
              items={[
                ['Role', <span className="capitalize">{u.role}</span>],
                ['Signs in with', signInMethods(u)],
                ['Last sign-in', u.last_login ? formatDateTime(u.last_login) : '—'],
                ['Account created', formatDateTime(u.created_at)],
              ]}
            />
          </Card>
          <MfaCard me={me} className="lg:col-span-2" />
        </div>
      </div>
    </div>
  )
}

function signInMethods(u: User): string {
  const pw = u.local_password !== false
  if (u.sso_linked && pw) return 'Password or single sign-on'
  if (u.sso_linked) return 'Single sign-on'
  return 'Password'
}

function MfaStatus({ on }: { on: boolean }) {
  return on ? (
    <span className="inline-flex items-center gap-1 rounded-full bg-ok-soft px-2 py-0.5 text-xs font-medium text-ok">
      <ShieldCheck className="size-3.5" aria-hidden /> On
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 rounded-full bg-warn-soft px-2 py-0.5 text-xs font-medium text-warn">
      <ShieldOff className="size-3.5" aria-hidden /> Off
    </span>
  )
}

type Step = { kind: 'idle' } | { kind: 'setup'; data: MfaSetup } | { kind: 'done' }

/** TOTP self-service: `/me/mfa/setup` → QR + key → `/me/mfa/enable`; `/me/mfa/disable` with the password. */
export function MfaCard({ me, className }: { me: MeResponse; className?: string }) {
  const qc = useQueryClient()
  const u = me.user
  const [step, setStep] = useState<Step>({ kind: 'idle' })
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [disableOpen, setDisableOpen] = useState(false)
  const ssoOnly = !!u.sso_linked && u.local_password === false

  const setup = useMutation({
    mutationFn: api.mfaSetup,
    onSuccess: (data) => {
      setCode('')
      setError(null)
      setStep({ kind: 'setup', data })
    },
    onError: (e) => toast.error('Couldn’t start the setup', { description: mfaErrorText(e, 'setup') }),
  })
  const enable = useMutation({
    mutationFn: (totp: string) => api.mfaEnable(totp),
    onSuccess: (r) => {
      setStep({ kind: 'done' })
      setCode('')
      // The server upgrades this session (a setup-only session gets its privileges back): reload /me.
      qc.setQueryData<MeResponse>(qk.me, (old) => (old ? { ...old, user: r.user } : old))
      void qc.invalidateQueries({ queryKey: qk.me })
      toast.success('Two-factor authentication is on')
    },
    onError: (e) => setError(mfaErrorText(e, 'enable')),
  })
  const submit = () => {
    if (!/^\d{6}$/.test(code)) {
      setError('Enter the 6-digit code from your authenticator app.')
      return
    }
    setError(null)
    enable.mutate(code)
  }

  return (
    <Card
      id="mfa"
      title="Two-factor authentication"
      description="A 6-digit code from an authenticator app, asked for at every password sign-in."
      actions={<MfaStatus on={u.mfa_enabled} />}
      className={cn('scroll-mt-4', className)}
    >
      {step.kind === 'setup' ? (
        <div className="space-y-5">
          <ol className="space-y-5">
            <li>
              <StepTitle n={1}>Scan this QR code with your authenticator app</StepTitle>
              <p className="mt-1 text-sm text-fg-muted">Microsoft Authenticator, Google Authenticator, 1Password, Bitwarden, Authy and other TOTP apps work.</p>
              <div className="mt-3 flex flex-wrap items-start gap-5">
                <QrCode value={step.data.otpauth_url} label="QR code to add Kestrel to your authenticator app" />
                <div className="min-w-0 max-w-sm flex-1 space-y-2">
                  <p className="text-sm font-medium">Can’t scan it? Enter this key instead</p>
                  <div className="flex items-center gap-2">
                    <code className="min-w-0 flex-1 break-all rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-[13px] tracking-wide" aria-label="Setup key" data-testid="mfa-secret">
                      {groupSecret(step.data.secret)}
                    </code>
                    <CopyButton text={step.data.secret} label="Copy key" iconOnly />
                  </div>
                  <ManualDetails uri={step.data.otpauth_url} email={u.email} />
                  <p className="text-xs text-fg-subtle">Keep this key private. Kestrel stores it encrypted and won’t show it again once you leave this page.</p>
                </div>
              </div>
            </li>
            <li>
              <StepTitle n={2}>Enter the code the app shows</StepTitle>
              <form
                className="mt-3 flex flex-wrap items-start gap-2"
                onSubmit={(e) => {
                  e.preventDefault()
                  submit()
                }}
              >
                <Field label="6-digit code" htmlFor="mfa-code" error={error} className="w-56">
                  <Input
                    id="mfa-code"
                    autoFocus
                    inputMode="numeric"
                    autoComplete="one-time-code"
                    maxLength={6}
                    value={code}
                    aria-invalid={!!error}
                    onChange={(e) => (setCode(cleanTotp(e.target.value)), setError(null))}
                    placeholder="123456"
                    className="font-mono tracking-widest"
                  />
                </Field>
                <div className="flex gap-2 pt-[26px]">
                  <Button type="submit" variant="primary" disabled={enable.isPending}>
                    {enable.isPending ? <Loader2 className="animate-spin" /> : <ShieldCheck />} Turn on
                  </Button>
                  <Button variant="ghost" onClick={() => (setStep({ kind: 'idle' }), setError(null))}>
                    Cancel
                  </Button>
                </div>
              </form>
            </li>
          </ol>
        </div>
      ) : step.kind === 'done' || u.mfa_enabled ? (
        <div className="space-y-4">
          {step.kind === 'done' ? (
            <p role="status" className="flex items-start gap-2 rounded-md border border-ok/30 bg-ok-soft px-3 py-2 text-sm">
              <CheckCircle2 className="mt-0.5 size-4 shrink-0 text-ok" aria-hidden />
              <span>
                <span className="font-medium">Two-factor authentication is on.</span> From your next sign-in, Kestrel asks for a code after your password.
              </span>
            </p>
          ) : (
            <p className="text-sm text-fg-muted">Your account asks for a code from your authenticator app after your password. The same code confirms remote access on devices whose profile requires a fresh MFA check.</p>
          )}
          <RecoveryNote />
          {!me.mfa_setup_required ? (
            <div className="flex flex-wrap items-center gap-2 border-t border-border pt-3">
              {ssoOnly ? (
                <p className="text-xs text-fg-muted">Your account has no Kestrel password, so two-factor authentication can’t be turned off here.</p>
              ) : (
                <Button variant="danger-outline" size="sm" onClick={() => setDisableOpen(true)}>
                  <ShieldOff /> Turn off two-factor authentication
                </Button>
              )}
            </div>
          ) : null}
        </div>
      ) : (
        <div className="space-y-4">
          <p className="max-w-2xl text-sm text-fg-muted">
            Protects your password sign-in even if the password leaks. It’s also required before remote access on devices whose remote-access profile asks for a fresh MFA check.
          </p>
          {u.sso_linked ? (
            <p className="max-w-2xl rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
              You also sign in with single sign-on: your identity provider applies its own MFA there. Setting up an authenticator here protects password sign-ins and remote-access checks.
            </p>
          ) : null}
          <Button variant="primary" disabled={setup.isPending} onClick={() => setup.mutate()}>
            {setup.isPending ? <Loader2 className="animate-spin" /> : <ShieldPlus />} Set up two-factor authentication
          </Button>
        </div>
      )}
      {disableOpen ? <DisableDialog onClose={() => setDisableOpen(false)} onDisabled={() => setStep({ kind: 'idle' })} /> : null}
    </Card>
  )
}

function StepTitle({ n, children }: { n: number; children: React.ReactNode }) {
  return (
    <p className="flex items-center gap-2 text-sm font-semibold">
      <span className="flex size-5 items-center justify-center rounded-full bg-accent-soft text-[11px] font-semibold text-accent-text" aria-hidden>
        {n}
      </span>
      {children}
    </p>
  )
}

function ManualDetails({ uri, email }: { uri: string; email: string }) {
  const l = otpauthLabel(uri)
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      <dt className="text-fg-subtle">Account</dt>
      <dd className="truncate">{l.account ?? email}</dd>
      {l.issuer ? (
        <>
          <dt className="text-fg-subtle">Issuer</dt>
          <dd>{l.issuer}</dd>
        </>
      ) : null}
      <dt className="text-fg-subtle">Type</dt>
      <dd>Time-based, 6 digits, every 30 seconds</dd>
    </dl>
  )
}

function RecoveryNote() {
  return (
    <div className="flex items-start gap-2 rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
      <LockKeyhole className="mt-0.5 size-3.5 shrink-0 text-fg-subtle" aria-hidden />
      <p>
        Kestrel doesn’t issue recovery codes. Use an authenticator that backs up to your account or password manager. If you lose it, another administrator has to remove your Kestrel account and invite you again.
      </p>
    </div>
  )
}

function DisableDialog({ onClose, onDisabled }: { onClose: () => void; onDisabled: () => void }) {
  const qc = useQueryClient()
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const off = useMutation({
    mutationFn: () => api.mfaDisable(password),
    onSuccess: () => {
      qc.setQueryData<MeResponse>(qk.me, (old) => (old ? { ...old, user: { ...old.user, mfa_enabled: false } } : old))
      void qc.invalidateQueries({ queryKey: qk.me })
      toast.success('Two-factor authentication is off')
      onDisabled()
      onClose()
    },
    onError: (e) => setError(mfaErrorText(e, 'disable')),
  })
  const submit = () => {
    if (!password) return setError('Enter your current password.')
    off.mutate()
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent
        size="sm"
        title="Turn off two-factor authentication?"
        description="Your password alone will sign you in, and you won’t be able to confirm remote access on devices that require a fresh MFA check."
        footer={
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="danger" disabled={off.isPending} onClick={submit}>
              {off.isPending ? <Loader2 className="animate-spin" /> : <ShieldOff />} Turn off
            </Button>
          </>
        }
      >
        <form
          onSubmit={(e) => {
            e.preventDefault()
            submit()
          }}
        >
          <Field label="Current password" htmlFor="mfa-off-pw" error={error}>
            <Input id="mfa-off-pw" type="password" autoFocus autoComplete="current-password" value={password} aria-invalid={!!error} onChange={(e) => (setPassword(e.target.value), setError(null))} />
          </Field>
          <p className="mt-3 flex items-center gap-1.5 text-xs text-fg-subtle">
            <KeyRound className="size-3.5" aria-hidden /> The change is recorded in the audit log.
          </p>
        </form>
      </DialogContent>
    </Dialog>
  )
}
