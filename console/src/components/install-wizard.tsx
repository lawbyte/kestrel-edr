import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, Check, Download, MonitorOff, MonitorSmartphone, ShieldCheck } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { api, qk } from '@/api/endpoints'
import type { CreatedEnrollmentToken, Group, RemoteAccessProfile, RemoteProfilePreset } from '@/api/types'
import { CopyButton } from '@/components/copy-button'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, inputClass } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { formatDate } from '@/lib/format'
import { PRESET_LABEL, presetOf, presetProfile, profileSummary, validateProfile } from '@/lib/remote-profile'
import { cn } from '@/lib/utils'
import { RemoteProfileEditor } from './remote/profile-editor'

export type WizardChoice = Exclude<RemoteProfilePreset, 'custom'>
export type WizardStep = 1 | 2 | 3

/** Step after "Next" on step 1: guarded (or "customise") goes to the guardrail editor, the others straight to token settings. */
export function nextAfterChoice(choice: WizardChoice, customise: boolean): WizardStep {
  return choice === 'guarded' || (customise && choice !== 'none') ? 2 : 3
}

/** Only admins (remote.desktop and remote.files) may create installers with remote access. */
export function canChooseRemote(can: (p: string) => boolean): boolean {
  return can('remote.desktop') && can('remote.files')
}

/** Save the generated `.cmd` (contains the enrollment token, shown once). */
export function downloadInstaller(t: Pick<CreatedEnrollmentToken, 'installer_cmd' | 'installer_filename'>) {
  if (!t.installer_cmd) return
  const blob = new Blob([t.installer_cmd], { type: 'application/octet-stream' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = t.installer_filename || 'Install-Kestrel.cmd'
  a.style.display = 'none'
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 30_000)
}

const CARDS: { choice: WizardChoice; icon: typeof ShieldCheck; title: string; body: string; points: string[] }[] = [
  {
    choice: 'none',
    icon: MonitorOff,
    title: 'No remote access',
    body: 'Detection and response only. Nobody can view the screen or open files on these devices.',
    points: ['Remote desktop: off', 'File manager: off', 'Can only be raised by reinstalling'],
  },
  {
    choice: 'unrestricted',
    icon: MonitorSmartphone,
    title: 'Remote control + file manager (no guardrails)',
    body: 'Admins can take control and manage files at any time, without asking the employee.',
    points: ['Banner and notification always shown', 'No consent prompt, reason or MFA check', 'Upload, rename and delete allowed'],
  },
  {
    choice: 'guarded',
    icon: ShieldCheck,
    title: 'Remote control + file manager with guardrails',
    body: 'Recommended. The employee allows each session; admins give a reason and confirm MFA.',
    points: ['Employee consent, reason, MFA re-check', 'Uploads yes, delete no', '60 min sessions, 15 min idle'],
  },
]

export function InstallAgentWizard({ onClose, groups: groupsProp }: { onClose: () => void; groups?: Group[] }) {
  const qc = useQueryClient()
  const { can } = useAuth()
  const remoteAllowed = canChooseRemote(can)
  const groupsQ = useQuery({ queryKey: qk.groups, queryFn: api.groups, enabled: !groupsProp })
  const groups = groupsProp ?? groupsQ.data ?? []
  const [step, setStep] = useState<WizardStep>(1)
  const [choice, setChoice] = useState<WizardChoice>(remoteAllowed ? 'guarded' : 'none')
  const [profile, setProfile] = useState<RemoteAccessProfile>(presetProfile(remoteAllowed ? 'guarded' : 'none'))
  const [group, setGroup] = useState('')
  const [days, setDays] = useState(7)
  const [uses, setUses] = useState(50)
  const [created, setCreated] = useState<CreatedEnrollmentToken | null>(null)
  const groupId = group || groups[0]?.id || ''
  const invalid = validateProfile(profile)

  const pick = (c: WizardChoice) => {
    if (c !== 'none' && !remoteAllowed) return
    setChoice(c)
    setProfile(presetProfile(c))
  }
  const create = useMutation({
    mutationFn: () => api.createEnrollmentToken({ group_id: groupId, expires_in_days: days, max_uses: uses, remote_profile: profile }),
    onSuccess: (t) => {
      setCreated(t)
      void qc.invalidateQueries({ queryKey: qk.enrollmentTokens })
    },
  })

  const preset = presetOf(profile)
  const stepTitle = created ? 'Installer ready' : step === 1 ? 'Install agent: remote access' : step === 2 ? 'Install agent: guardrails' : 'Install agent: enrollment token'

  const footer = created ? (
    <Button variant="primary" onClick={onClose}>
      Done
    </Button>
  ) : step === 1 ? (
    <>
      {choice !== 'none' ? (
        <Button variant="ghost" className="mr-auto" onClick={() => setStep(2)}>
          Customise…
        </Button>
      ) : null}
      <Button variant="ghost" onClick={onClose}>
        Cancel
      </Button>
      <Button variant="primary" onClick={() => setStep(nextAfterChoice(choice, false))}>
        Next
      </Button>
    </>
  ) : step === 2 ? (
    <>
      <Button variant="ghost" onClick={() => setStep(1)}>
        Back
      </Button>
      <Button variant="primary" disabled={!!invalid} onClick={() => setStep(3)}>
        Next
      </Button>
    </>
  ) : (
    <>
      <Button variant="ghost" onClick={() => setStep(choice === 'guarded' || preset === 'custom' ? 2 : 1)}>
        Back
      </Button>
      <Button variant="primary" disabled={!groupId || create.isPending || !!invalid} onClick={() => create.mutate()}>
        Create installer
      </Button>
    </>
  )

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent size="xl" title={stepTitle} description={created ? undefined : <Steps step={step} />} footer={footer}>
        {created ? (
          <Result t={created} />
        ) : step === 1 ? (
          <div className="space-y-3">
            <p className="text-sm text-fg-muted">
              The profile is the <strong className="text-fg">ceiling</strong> for every device installed with this token. Policies can only narrow it; raising it later means reinstalling the agent.
            </p>
            <div role="radiogroup" aria-label="Remote-access profile" className="grid gap-3 md:grid-cols-3">
              {CARDS.map((c) => {
                const disabled = c.choice !== 'none' && !remoteAllowed
                const sel = choice === c.choice
                return (
                  <button
                    key={c.choice}
                    type="button"
                    role="radio"
                    aria-checked={sel}
                    aria-disabled={disabled}
                    disabled={disabled}
                    onClick={() => pick(c.choice)}
                    className={cn(
                      'relative flex flex-col rounded-lg border p-4 text-left transition-colors focus-visible:outline-2 focus-visible:outline-ring',
                      sel ? 'border-accent bg-accent-soft' : 'border-border bg-surface hover:bg-surface-2',
                      disabled && 'cursor-not-allowed opacity-55 hover:bg-surface',
                    )}
                  >
                    <span className="mb-2 flex items-center justify-between">
                      <c.icon className={cn('size-5', sel ? 'text-accent-text' : 'text-fg-subtle')} aria-hidden />
                      {sel ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-accent-text">
                          <Check className="size-3.5" aria-hidden /> Selected
                        </span>
                      ) : null}
                    </span>
                    <span className="text-sm font-semibold">{c.title}</span>
                    <span className="mt-1 text-xs text-fg-muted">{c.body}</span>
                    <ul className="mt-2 space-y-0.5 text-xs text-fg-muted">
                      {c.points.map((p) => (
                        <li key={p}>• {p}</li>
                      ))}
                    </ul>
                    {disabled ? <span className="mt-2 text-xs font-medium text-fg">Admins only: needs the remote.desktop and remote.files privileges.</span> : null}
                  </button>
                )
              })}
            </div>
            {!remoteAllowed ? <p className="text-xs text-fg-muted">Your role can create installers without remote access. Ask an administrator for an installer with remote access.</p> : null}
          </div>
        ) : step === 2 ? (
          <div className="space-y-3">
            <p className="text-sm text-fg-muted">Prefilled with the recommended guardrails. Every setting here is a maximum: a device’s policy can make it stricter, never looser.</p>
            <RemoteProfileEditor value={profile} onChange={setProfile} idPrefix="wiz" presets={false} />
          </div>
        ) : (
          <div className="space-y-4">
            <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-sm">
              <span className="text-xs text-fg-subtle">Remote access ceiling</span>
              <p className="font-medium">{profileSummary(profile)}</p>
            </div>
            <Field label="Group" htmlFor="wiz-group" hint="New devices join this group and get its policy.">
              <select id="wiz-group" value={groupId} onChange={(e) => setGroup(e.target.value)} className={cn(inputClass, 'h-8')}>
                {groups.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
              </select>
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Expires after (days)" htmlFor="wiz-days" hint="1 to 90">
                <Input id="wiz-days" type="number" min={1} max={90} value={days} onChange={(e) => setDays(Math.min(90, Math.max(1, Math.trunc(Number(e.target.value)) || 1)))} />
              </Field>
              <Field label="Maximum devices" htmlFor="wiz-uses" hint="1 to 10,000">
                <Input id="wiz-uses" type="number" min={1} max={10000} value={uses} onChange={(e) => setUses(Math.min(10000, Math.max(1, Math.trunc(Number(e.target.value)) || 1)))} />
              </Field>
            </div>
            {create.error ? (
              <p role="alert" className="text-sm text-danger">
                {(create.error as Error).message}
              </p>
            ) : null}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

function Steps({ step }: { step: WizardStep }) {
  const items: [WizardStep, string][] = [
    [1, 'Remote access'],
    [2, 'Guardrails'],
    [3, 'Token'],
  ]
  return (
    // Rendered inside the dialog description (<p>), so spans only.
    <span className="mt-1 flex flex-wrap items-center gap-2 text-xs">
      <span className="sr-only">
        Step {step} of 3: {items[step - 1][1]}.
      </span>
      {items.map(([n, label]) => (
        <span key={n} aria-hidden className={cn('inline-flex items-center gap-1.5', n === step ? 'font-medium text-fg' : 'text-fg-subtle')}>
          <span className={cn('flex size-5 items-center justify-center rounded-full border text-[11px]', n === step ? 'border-accent bg-accent text-accent-fg' : n < step ? 'border-accent text-accent-text' : 'border-border')}>{n < step ? <Check className="size-3" aria-hidden /> : n}</span>
          {label}
          {n < 3 ? <span className="text-fg-subtle">›</span> : null}
        </span>
      ))}
    </span>
  )
}

function Result({ t }: { t: CreatedEnrollmentToken }) {
  const preset = t.remote_preset ?? 'none'
  return (
    <div className="space-y-4">
      <div role="alert" className="flex items-start gap-2 rounded-md border border-warn/40 bg-warn-soft px-3 py-2 text-sm">
        <AlertTriangle className="mt-0.5 size-4 shrink-0 text-warn" aria-hidden />
        <p>
          <span className="font-medium">Shown once.</span> The installer and the command contain the enrollment token. Anyone with them can enroll a device into {t.group_name} until the token expires or is used up. Store them like a password and delete the file after use.
        </p>
      </div>
      <dl className="grid gap-3 text-sm sm:grid-cols-3">
        <Item label="Remote access ceiling">{t.remote_summary ?? PRESET_LABEL[preset]}</Item>
        <Item label="Group">{t.group_name}</Item>
        <Item label="Valid">
          until {formatDate(t.expires_at)}, up to {t.max_uses} devices
        </Item>
      </dl>
      {t.installer_cmd ? (
        <div className="flex flex-wrap items-center gap-3 rounded-lg border border-border bg-surface-2 p-3">
          <div className="min-w-0 flex-1">
            <p className="text-sm font-medium">Installer for double-click or software deployment</p>
            <p className="text-xs text-fg-muted">Asks for administrator rights, downloads the MSI from your server, checks its SHA-256 and installs silently.</p>
          </div>
          <Button variant="primary" onClick={() => downloadInstaller(t)}>
            <Download /> Download {t.installer_filename ?? 'installer'}
          </Button>
        </div>
      ) : null}
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs font-medium text-fg-subtle">PowerShell one-liner (run as administrator)</span>
          <CopyButton text={t.install_command} label="Copy command" />
        </div>
        <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-md border border-border bg-surface-2 p-3 font-mono text-[12px] leading-relaxed">{t.install_command}</pre>
      </div>
      <div>
        <div className="mb-1 flex items-center justify-between">
          <span className="text-xs font-medium text-fg-subtle">Token only (for Intune or GPO MSI properties)</span>
          <CopyButton text={t.token} label="Copy token" />
        </div>
        <code className="block break-all rounded-md border border-border bg-surface-2 p-2 font-mono text-[12px]">{t.token}</code>
      </div>
    </div>
  )
}

function Item({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-fg-subtle">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  )
}
