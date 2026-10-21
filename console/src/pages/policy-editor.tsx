import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, ChevronLeft, Eye, Info, ShieldCheck, Sparkles, X } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { useBlocker, useNavigate, useParams } from 'react-router'
import { toast } from 'sonner'
import { api, qk } from '@/api/endpoints'
import type { HardeningControl, HardeningMode, Policy, RuleMode, RuleRow, SensorSettings } from '@/api/types'
import { CategoryBadge, SeverityIcon } from '@/components/badges'
import { ErrorState, LoadingRows } from '@/components/common'
import { Markdown } from '@/components/markdown'
import { Button } from '@/components/ui/button'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { Field, Input, Textarea } from '@/components/ui/input'
import { Segmented, Switch, Tooltip } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { diffJson, type Change } from '@/lib/diff'
import { HARDENING_CONTROLS, HARDENING_INFO, RULE_CATEGORY_ORDER } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { normaliseProfile, validateProfile } from '@/lib/remote-profile'
import { RemoteProfileEditor } from '@/components/remote/profile-editor'

const SECTIONS = [
  { id: 'rules', label: 'Detection rules' },
  { id: 'suspend', label: 'Suspend on suspicion' },
  { id: 'containment', label: 'Isolation & indicator blocks' },
  { id: 'sensors', label: 'Sensors' },
  { id: 'hardening', label: 'Windows hardening' },
  { id: 'privacy', label: 'Privacy' },
  { id: 'telemetry', label: 'Telemetry' },
  { id: 'canaries', label: 'Canaries & exfil domains' },
  { id: 'branding', label: 'Branding & notice' },
  { id: 'remote', label: 'Remote access' },
]

export default function PolicyEditor() {
  const { id = '' } = useParams()
  const q = useQuery({ queryKey: qk.policy(id), queryFn: () => api.policy(id) })
  const rules = useQuery({ queryKey: qk.rules, queryFn: api.rules })
  if (q.error) return <ErrorState error={q.error} onRetry={() => q.refetch()} className="h-full" />
  if (rules.error) return <ErrorState error={rules.error} onRetry={() => rules.refetch()} className="h-full" />
  if (!q.data || !rules.data) return <LoadingRows rows={12} className="p-6" />
  return <Editor key={`${q.data.id}-${q.data.version}`} original={q.data} catalog={rules.data} />
}

function Editor({ original, catalog }: { original: Policy; catalog: RuleRow[] }) {
  const nav = useNavigate()
  const qc = useQueryClient()
  const { can } = useAuth()
  const readOnly = !can('policies.write')
  const [p, setP] = useState<Policy>(() => structuredClone(original))
  const [review, setReview] = useState(false)
  const changes = useMemo(() => diffJson(original, p), [original, p])
  const dirty = changes.length > 0
  const blocker = useBlocker(({ currentLocation, nextLocation }) => dirty && currentLocation.pathname !== nextLocation.pathname)
  useEffect(() => {
    const h = (e: BeforeUnloadEvent) => {
      if (dirty) e.preventDefault()
    }
    window.addEventListener('beforeunload', h)
    return () => window.removeEventListener('beforeunload', h)
  }, [dirty])

  const save = useMutation({
    mutationFn: () => {
      const bad = p.remote_access ? validateProfile(normaliseProfile(p.remote_access)) : null
      if (bad) throw new Error(`Remote access: ${bad}`)
      return api.savePolicy(p)
    },
    onSuccess: (np) => {
      toast.success(`Saved “${np.name}” as version ${np.version}`, { description: 'Agents pick up the new version on their next check-in (usually under a minute).' })
      qc.setQueryData(qk.policy(np.id), np)
      void qc.invalidateQueries({ queryKey: qk.policies })
      setReview(false)
    },
    onError: (e) => toast.error('Policy not saved', { description: (e as Error).message }),
  })

  const set = <K extends keyof Policy>(k: K, v: Policy[K]) => setP((x) => ({ ...x, [k]: v }))

  return (
    <div className="pb-24">
      <div className="border-b border-border px-6 pb-4 pt-4">
        <button type="button" onClick={() => nav('/policies')} className="mb-2 inline-flex items-center gap-1 text-xs text-fg-muted hover:text-fg">
          <ChevronLeft className="size-3.5" /> Policies
        </button>
        <div className="flex flex-wrap items-center gap-3">
          <input
            aria-label="Policy name"
            value={p.name}
            onChange={(e) => set('name', e.target.value)}
            readOnly={readOnly}
            className="min-w-0 flex-1 rounded-md bg-transparent px-1 -mx-1 text-[1.375rem] font-semibold tracking-[-0.01em] hover:bg-surface-2 focus-visible:bg-surface focus-visible:outline-2 focus-visible:outline-ring"
          />
          <span className="text-sm tabular text-fg-subtle">Version {original.version}</span>
        </div>
      </div>

      <div className="mx-auto grid max-w-[1200px] gap-8 px-6 py-6 lg:grid-cols-[180px_minmax(0,1fr)]">
        <nav aria-label="Policy sections" className="hidden lg:block">
          <ul className="sticky top-6 space-y-0.5 text-sm">
            {SECTIONS.map((s) => (
              <li key={s.id}>
                <a href={`#${s.id}`} className="block rounded-md px-2 py-1 text-fg-muted hover:bg-surface-2 hover:text-fg">
                  {s.label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 space-y-10">
          <RuleMatrix p={p} catalog={catalog} onChange={(rules) => set('rules', rules)} readOnly={readOnly} />

          <Section id="suspend" title="Suspend on suspicion" description="When a process reads browser secrets or calls DPAPI, Kestrel freezes it and waits this long for the rest of the evidence. If a Protect rule fires in the window, the process is killed; otherwise it resumes.">
            <div className="flex flex-wrap items-center gap-4">
              <input
                type="range"
                min={500}
                max={10000}
                step={500}
                value={p.suspend_window_ms}
                disabled={readOnly}
                onChange={(e) => set('suspend_window_ms', Number(e.target.value))}
                className="w-72 accent-[var(--accent)]"
                aria-label="Suspend window in milliseconds"
              />
              <span className="tabular text-sm font-medium">{(p.suspend_window_ms / 1000).toFixed(1)} s</span>
              <span className="text-xs text-fg-muted">2–5 s suits most offices. Longer windows catch slower stealers but pause legitimate tools longer.</span>
            </div>
          </Section>

          <Section id="containment" title="Isolation and indicator blocks" description="How long network containment lasts when the server cannot be reached, and how hits on your indicators (IOCs) block network destinations.">
            <div className="divide-y divide-border rounded-lg border border-border bg-surface">
              <NumberRow
                id="n-auto-release"
                label="Release isolation automatically"
                hint="If an isolated device cannot reach the server for this long (for example a laptop that moved to another network), the agent lifts isolation by itself so the device is never stranded. 0 keeps isolation until the console or a local administrator with the uninstall token releases it."
                value={p.isolation_auto_release_hours}
                min={0}
                max={720}
                unit="hours"
                disabled={readOnly}
                onChange={(v) => set('isolation_auto_release_hours', v)}
              />
              <NumberRow
                id="n-ioc-ttl"
                label="Indicator block lifetime"
                hint="Firewall blocks created when a program connects to or looks up one of your indicators expire after this long. If you delete a Block indicator, switch it to Audit or Allow, or a device leaves its scope, the agent lifts the blocks that indicator created as soon as it receives the updated policy (offline devices do so when they reconnect). Blocks from other rules or from analyst commands are not lifted this way."
                value={Math.max(1, Math.round(p.ioc_block_ttl_secs / 3600))}
                min={1}
                max={720}
                unit="hours"
                disabled={readOnly}
                onChange={(v) => set('ioc_block_ttl_secs', v * 3600)}
              />
              <ToggleRow
                label="Block indicator destinations for every program"
                hint="Off (recommended): only the program that contacted the indicator is cut off, so a shared CDN address doesn’t break other apps. On: the destination is blocked for the whole device."
                checked={p.ioc_block_host_wide}
                onChange={(v) => set('ioc_block_host_wide', v)}
                disabled={readOnly}
              />
            </div>
            {p.isolation_auto_release_hours === 0 ? (
              <p className="mt-2 flex items-start gap-1.5 text-xs text-warn">
                <Info className="mt-0.5 size-3.5 shrink-0" />
                With auto-release off, an isolated device that loses its route to the server stays isolated until someone runs <code className="font-mono">kestrel-agent release-isolation</code> on it.
              </p>
            ) : null}
          </Section>

          <SensorsSection value={p.sensors ?? DEFAULT_SENSORS} onChange={(v) => set('sensors', v)} readOnly={readOnly} />

          <HardeningSection p={p} onChange={(h) => set('hardening', h)} readOnly={readOnly} />

          <Section id="privacy" title="Privacy and data minimisation" description="What leaves the device. Turning things off reduces what analysts can see during an investigation.">
            <div className="divide-y divide-border rounded-lg border border-border bg-surface">
              <ToggleRow label="Upload full command lines" hint="Off: only the program and its flags are uploaded. Command lines can contain file names and personal data." checked={p.privacy.capture_cmdline} onChange={(v) => set('privacy', { ...p.privacy, capture_cmdline: v })} disabled={readOnly} law />
              <ToggleRow label="Replace user names with a hash" hint="Analysts see a stable pseudonym instead of the account name. Useful where monitoring must be pseudonymised under PDPA or UU PDP." checked={p.privacy.hash_usernames} onChange={(v) => set('privacy', { ...p.privacy, hash_usernames: v })} disabled={readOnly} law />
              <ToggleRow label="Upload DNS queries" hint="Needed for hunting dead-drop domains. DNS names reveal which sites people visit." checked={p.privacy.capture_dns} onChange={(v) => set('privacy', { ...p.privacy, capture_dns: v })} disabled={readOnly} law />
              <ToggleRow label="Upload script content" hint="PowerShell and AMSI content is the best evidence for paste-and-run attacks. It can contain credentials typed into scripts." checked={p.privacy.capture_script_content} onChange={(v) => set('privacy', { ...p.privacy, capture_script_content: v })} disabled={readOnly} />
              <div className="px-4 py-3">
                <p className="text-sm font-medium">Never upload paths under</p>
                <p className="mb-2 text-xs text-fg-muted">For personal folders. Events under these prefixes keep their type and process but lose the path. * matches one folder.</p>
                <ListEditor values={p.privacy.redact_path_prefixes} onChange={(v) => set('privacy', { ...p.privacy, redact_path_prefixes: v })} placeholder="C:\Users\*\Documents\Personal" disabled={readOnly} mono />
              </div>
            </div>
            <p className="mt-2 flex items-start gap-1.5 text-xs text-fg-muted">
              <Info className="mt-0.5 size-3.5 shrink-0" />
              Singapore’s PDPA lets employers monitor company devices without consent but requires that employees are told. Indonesia’s UU PDP requires a DPIA for systematic monitoring. Keep the employee notice below accurate when you change these.
            </p>
          </Section>

          <Section id="telemetry" title="Telemetry" description="Alerts are always uploaded. Raw events power Hunt and device timelines.">
            <div className="divide-y divide-border rounded-lg border border-border bg-surface">
              <ToggleRow label="Upload raw events for hunting" hint="Off: only alerts and their evidence leave the device." checked={p.telemetry.upload_events} onChange={(v) => set('telemetry', { ...p.telemetry, upload_events: v })} disabled={readOnly} />
              <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
                <div>
                  <p className="text-sm font-medium">Local outbox limit</p>
                  <p className="text-xs text-fg-muted">While offline, the agent queues events up to this size, then drops the oldest low-priority ones. Alerts are never dropped.</p>
                </div>
                <div className="flex items-center gap-2">
                  <Input type="number" min={64} max={8192} value={p.telemetry.max_outbox_mb} disabled={readOnly} onChange={(e) => set('telemetry', { ...p.telemetry, max_outbox_mb: Number(e.target.value) || 0 })} className="w-24 text-right tabular" aria-label="Outbox limit in MB" />
                  <span className="text-sm text-fg-muted">MB</span>
                </div>
              </div>
            </div>
          </Section>

          <Section id="canaries" title="Canaries and exfiltration domains">
            <div className="divide-y divide-border rounded-lg border border-border bg-surface">
              <ToggleRow label="Plant canary credential stores" hint="Hidden decoy wallet folders, a decoy browser profile and decoy cloud keys. Nothing legitimate opens them, so rule ST-16 fires with near-zero false positives." checked={p.canaries} onChange={(v) => set('canaries', v)} disabled={readOnly} />
              <div className="px-4 py-3">
                <p className="text-sm font-medium">Exfiltration and dead-drop domains</p>
                <p className="mb-2 text-xs text-fg-muted">Rule ST-14 alerts when a program that isn’t a browser resolves or connects to these.</p>
                <ListEditor values={p.exfil_domains} onChange={(v) => set('exfil_domains', v)} placeholder="example.com" disabled={readOnly} mono />
              </div>
            </div>
          </Section>

          <Section id="branding" title="Branding and employee notice" description="Shown in the Kestrel tray app on every device using this policy.">
            <div className="grid gap-4 rounded-lg border border-border bg-surface p-4 md:grid-cols-2">
              <Field label="Organisation name" htmlFor="b-org">
                <Input id="b-org" value={p.branding.org_name} disabled={readOnly} onChange={(e) => set('branding', { ...p.branding, org_name: e.target.value })} />
              </Field>
              <Field label="IT contact name" htmlFor="b-name">
                <Input id="b-name" value={p.branding.it_contact.name} disabled={readOnly} onChange={(e) => set('branding', { ...p.branding, it_contact: { ...p.branding.it_contact, name: e.target.value } })} />
              </Field>
              <Field label="IT email" htmlFor="b-email">
                <Input id="b-email" type="email" value={p.branding.it_contact.email} disabled={readOnly} onChange={(e) => set('branding', { ...p.branding, it_contact: { ...p.branding.it_contact, email: e.target.value } })} />
              </Field>
              <Field label="IT phone" htmlFor="b-phone">
                <Input id="b-phone" value={p.branding.it_contact.phone} disabled={readOnly} onChange={(e) => set('branding', { ...p.branding, it_contact: { ...p.branding.it_contact, phone: e.target.value } })} />
              </Field>
              <Field label="Help page URL" htmlFor="b-url" className="md:col-span-2">
                <Input id="b-url" value={p.branding.it_contact.url} disabled={readOnly} onChange={(e) => set('branding', { ...p.branding, it_contact: { ...p.branding.it_contact, url: e.target.value } })} />
              </Field>
              <div className="md:col-span-2">
                <NoticeEditor value={p.branding.privacy_notice_md} onChange={(v) => set('branding', { ...p.branding, privacy_notice_md: v })} disabled={readOnly} />
              </div>
            </div>
          </Section>

          <Section
            id="remote"
            title="Remote access"
            description="Remote desktop and the remote file manager for administrators. Devices are capped by their install profile: a device only gets what both its install profile and this policy allow. The employee always sees a banner and a notification during desktop sessions, and every file operation is recorded in the audit log."
          >
            <RemoteProfileEditor value={normaliseProfile(p.remote_access)} onChange={(v) => set('remote_access', v)} disabled={readOnly} idPrefix="pol-remote" />
          </Section>
        </div>
      </div>

      {dirty && !readOnly ? (
        <div className="fixed bottom-4 left-1/2 z-30 flex -translate-x-1/2 items-center gap-3 rounded-xl border border-border-strong bg-surface px-4 py-2.5 shadow-pop animate-in lg:left-[calc(50%+116px)]">
          <span className="text-sm">
            <span className="font-medium tabular">{changes.length}</span> unsaved change{changes.length === 1 ? '' : 's'}
          </span>
          <Button size="sm" variant="ghost" onClick={() => setP(structuredClone(original))}>
            Discard
          </Button>
          <Button size="sm" variant="primary" onClick={() => setReview(true)}>
            Review and save
          </Button>
        </div>
      ) : null}

      <Dialog open={review} onOpenChange={setReview}>
        <DialogContent
          size="lg"
          title={`Save as version ${original.version + 1}?`}
          description={`Every device using “${original.name}” receives these changes.`}
          footer={
            <>
              <Button variant="ghost" onClick={() => setReview(false)}>
                Keep editing
              </Button>
              <Button variant="primary" onClick={() => save.mutate()} disabled={save.isPending}>
                {save.isPending ? 'Saving…' : `Save version ${original.version + 1}`}
              </Button>
            </>
          }
        >
          <DiffView changes={changes} />
        </DialogContent>
      </Dialog>

      <Dialog open={blocker.state === 'blocked'} onOpenChange={(o) => !o && blocker.reset?.()}>
        <DialogContent
          size="sm"
          title="Leave without saving?"
          description={`${changes.length} change${changes.length === 1 ? '' : 's'} to this policy will be lost.`}
          footer={
            <>
              <Button variant="ghost" onClick={() => blocker.reset?.()}>
                Stay
              </Button>
              <Button variant="danger" onClick={() => blocker.proceed?.()}>
                Discard changes
              </Button>
            </>
          }
        />
      </Dialog>
    </div>
  )
}

function Section({ id, title, description, children, aside }: { id: string; title: string; description?: ReactNode; children: ReactNode; aside?: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-6">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div className="max-w-2xl">
          <h2 id={`${id}-h`} className="text-base font-semibold">
            {title}
          </h2>
          {description ? <p className="mt-0.5 text-sm text-fg-muted">{description}</p> : null}
        </div>
        {aside}
      </div>
      {children}
    </section>
  )
}

function ToggleRow({ label, hint, checked, onChange, disabled, law }: { label: string; hint: string; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean; law?: boolean }) {
  const id = `t-${label.replace(/\W+/g, '-').toLowerCase()}`
  return (
    <div className="flex items-start justify-between gap-4 px-4 py-3">
      <div className="min-w-0">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
          {law ? <span className="ml-2 rounded bg-surface-2 px-1.5 py-px text-[10.5px] font-normal text-fg-muted">PDPA / UU PDP</span> : null}
        </label>
        <p className="text-xs text-fg-muted">{hint}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} disabled={disabled} />
    </div>
  )
}

function NumberRow({ id, label, hint, value, min, max, unit, onChange, disabled }: { id: string; label: string; hint: string; value: number; min: number; max: number; unit: string; onChange: (v: number) => void; disabled?: boolean }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-3">
      <div className="min-w-0 max-w-xl">
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className="text-xs text-fg-muted">{hint}</p>
      </div>
      <div className="flex items-center gap-2">
        <Input
          id={id}
          type="number"
          min={min}
          max={max}
          step={1}
          value={value}
          disabled={disabled}
          onChange={(e) => {
            const n = Math.trunc(Number(e.target.value))
            onChange(Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : min)
          }}
          className="w-24 text-right tabular"
        />
        <span className="text-sm text-fg-muted">{unit}</span>
      </div>
    </div>
  )
}

export const DEFAULT_SENSORS: SensorSettings = { file_activity: true, ransomware_canaries: true, persistence: true, credential_access: true }

const SENSOR_INFO: { key: keyof SensorSettings; label: string; hint: string }[] = [
  {
    key: 'file_activity',
    label: 'File activity (ransomware)',
    hint: 'Counts file renames, overwrites and deletes per program in your users’ document folders and on network shares, so mass encryption (RW-06) and ransom notes (RW-08) are caught within seconds. Costs a little CPU on devices that move many files.',
  },
  {
    key: 'ransomware_canaries',
    label: 'Ransomware canary documents',
    hint: 'Plants a few hidden decoy documents in the Documents and Pictures folders (not the Desktop). Any program that changes one triggers RW-07. Users may notice them if they show hidden files.',
  },
  {
    key: 'persistence',
    label: 'Persistence (tasks, services, WMI, autorun registry keys)',
    hint: 'Watches scheduled tasks, new services, WMI subscriptions and Run / Winlogon / IFEO keys for the PS-xx rules. Off: Kestrel no longer sees malware making itself start at logon.',
  },
  {
    key: 'credential_access',
    label: 'LSASS access (credential dumping)',
    hint: 'Reports failed and dump-capable opens of lsass.exe and the dump files that follow (CD-xx rules). Off: credential-dumping rules can only use command lines.',
  },
]

function SensorsSection({ value, onChange, readOnly }: { value: SensorSettings; onChange: (v: SensorSettings) => void; readOnly: boolean }) {
  return (
    <Section id="sensors" title="Sensors" description="Optional sensor groups for ransomware, credential dumping and persistence. All are on by default; turn one off only if it costs too much on a particular fleet, because the rules that depend on it go quiet.">
      <div className="divide-y divide-border rounded-lg border border-border bg-surface">
        {SENSOR_INFO.map((s) => (
          <ToggleRow key={s.key} label={s.label} hint={s.hint} checked={value[s.key]} onChange={(v) => onChange({ ...value, [s.key]: v })} disabled={readOnly} />
        ))}
      </div>
    </Section>
  )
}

function RuleMatrix({ p, catalog, onChange, readOnly }: { p: Policy; catalog: RuleRow[]; onChange: (r: Record<string, RuleMode>) => void; readOnly: boolean }) {
  const rules = catalog.filter((r) => r.kind === 'builtin' || r.enabled_custom)
  const mode = (r: RuleRow) => p.rules[r.id] ?? r.default_mode
  const setMode = (r: RuleRow, m: RuleMode) => {
    const next = { ...p.rules }
    if (m === r.default_mode) delete next[r.id]
    else next[r.id] = m
    onChange(next)
  }
  const recommended = () => {
    const next: Record<string, RuleMode> = {}
    for (const r of rules) {
      const m: RuleMode = r.protect_day_one ? 'protect' : r.kind === 'builtin' ? 'audit' : 'audit'
      if (m !== r.default_mode) next[r.id] = m
    }
    onChange(next)
  }
  const counts = rules.reduce((a, r) => ((a[mode(r)] = (a[mode(r)] ?? 0) + 1), a), {} as Record<RuleMode, number>)
  return (
    <Section
      id="rules"
      title="Detection rules"
      description={
        <>
          <strong className="font-medium text-fg">Audit</strong> alerts only. <strong className="font-medium text-fg">Protect</strong> alerts and takes the listed action. Rules marked “Safe on day one” rarely misfire; run the rest in Audit for about two weeks first.
        </>
      }
      aside={
        <div className="flex items-center gap-3">
          <span className="text-xs tabular text-fg-muted">
            {counts.protect ?? 0} protect · {counts.audit ?? 0} audit · {counts.off ?? 0} off
          </span>
          {!readOnly ? (
            <Button size="sm" variant="ghost" onClick={recommended}>
              <Sparkles /> Apply recommended
            </Button>
          ) : null}
        </div>
      }
    >
      <div className="overflow-hidden rounded-lg border border-border bg-surface">
        {RULE_CATEGORY_ORDER.map((cat) => {
          const rs = rules.filter((r) => r.category === cat)
          if (!rs.length) return null
          return (
            <div key={cat}>
              <div className="border-b border-border bg-surface-2/60 px-4 py-1.5">
                <CategoryBadge category={cat} className="text-xs font-medium" />
              </div>
              <ul className="divide-y divide-border">
                {rs.map((r) => {
                  const m = mode(r)
                  const overridden = r.id in p.rules
                  return (
                    <li key={r.id} className="grid gap-x-4 gap-y-2 px-4 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                          <SeverityIcon severity={r.severity} className="size-3.5" />
                          <span className="font-mono text-xs text-fg-muted">{r.id}</span>
                          <span className="text-sm font-medium">{r.name}</span>
                          {r.protect_day_one ? (
                            <Tooltip content="Low false-positive rate: safe to protect immediately">
                              <span className="inline-flex items-center gap-1 rounded bg-ok-soft px-1.5 py-px text-[11px] font-medium text-ok">
                                <ShieldCheck className="size-3" /> Safe on day one
                              </span>
                            </Tooltip>
                          ) : null}
                          {overridden ? <span className="text-[11px] text-accent-text">changed from default ({r.default_mode})</span> : null}
                        </div>
                        <p className={cn('mt-0.5 text-xs', m === 'protect' ? 'text-fg' : 'text-fg-subtle')}>
                          In Protect: {r.protect_action || 'Alert only'}
                          {m === 'protect' && !r.protect_day_one && r.kind === 'builtin' ? <span className="ml-1 text-warn">· Check two weeks of Audit hits for false positives first.</span> : null}
                        </p>
                      </div>
                      <Segmented
                        size="sm"
                        label={`Mode for ${r.id}`}
                        value={m}
                        onChange={(v) => setMode(r, v)}
                        disabled={readOnly}
                        options={[
                          { value: 'off', label: 'Off' },
                          { value: 'audit', label: 'Audit' },
                          { value: 'protect', label: 'Protect', tone: 'accent' },
                        ]}
                      />
                    </li>
                  )
                })}
              </ul>
            </div>
          )
        })}
      </div>
    </Section>
  )
}

function HardeningSection({ p, onChange, readOnly }: { p: Policy; onChange: (h: Policy['hardening']) => void; readOnly: boolean }) {
  const h = p.hardening
  return (
    <Section
      id="hardening"
      title="Windows hardening"
      description="Built-in Windows controls Kestrel applies and keeps applied. Windows itself does the blocking, so these work even before a detection rule fires."
      aside={
        <Segmented<HardeningMode>
          label="Hardening mode"
          value={h.mode}
          disabled={readOnly}
          onChange={(m) => onChange({ ...h, mode: m })}
          options={[
            { value: 'off', label: 'Off', title: 'Kestrel does not manage these settings' },
            { value: 'audit', label: 'Audit', title: 'Report drift only' },
            { value: 'enforce', label: 'Enforce', tone: 'accent', title: 'Apply and keep applied' },
          ]}
        />
      }
    >
      <p className="mb-3 text-xs text-fg-muted">
        {h.mode === 'off' ? 'Kestrel leaves these settings alone. Toggles below are saved but not applied.' : h.mode === 'audit' ? 'Audit: Kestrel checks each enabled control and reports devices where it is missing, without changing anything.' : 'Enforce: Kestrel applies every enabled control and re-applies it if someone changes it.'}
      </p>
      <ul className={cn('grid gap-3 md:grid-cols-2', h.mode === 'off' && 'opacity-60')}>
        {HARDENING_CONTROLS.map((c: HardeningControl) => {
          const info = HARDENING_INFO[c]
          const id = `h-${c}`
          return (
            <li key={c} className={cn('rounded-lg border bg-surface p-3.5', h[c] ? 'border-accent/30' : 'border-border')}>
              <div className="flex items-start justify-between gap-3">
                <label htmlFor={id} className="text-sm font-medium">
                  {info.label}
                  {info.reportOnly ? (
                    <span className="ml-2 inline-flex items-center gap-1 rounded bg-surface-2 px-1.5 py-px align-middle text-[10.5px] font-normal text-fg-muted">
                      <Eye className="size-3" aria-hidden /> Report only
                    </span>
                  ) : null}
                </label>
                <Switch id={id} checked={h[c]} disabled={readOnly} onCheckedChange={(v) => onChange({ ...h, [c]: v })} />
              </div>
              <p className="mt-1 text-xs leading-relaxed text-fg-muted">{info.blocks}</p>
              {info.caveat ? (
                <p className="mt-1.5 flex gap-1.5 text-xs leading-relaxed text-warn">
                  <AlertTriangle className="mt-px size-3.5 shrink-0" aria-hidden />
                  <span>{info.caveat}</span>
                </p>
              ) : null}
            </li>
          )
        })}
      </ul>
    </Section>
  )
}

function ListEditor({ values, onChange, placeholder, disabled, mono }: { values: string[]; onChange: (v: string[]) => void; placeholder: string; disabled?: boolean; mono?: boolean }) {
  const [draft, setDraft] = useState('')
  const add = () => {
    const v = draft.trim()
    if (!v || values.includes(v)) return
    onChange([...values, v])
    setDraft('')
  }
  return (
    <div>
      <ul className="mb-2 flex flex-wrap gap-1.5">
        {values.map((v) => (
          <li key={v} className={cn('inline-flex items-center gap-1 rounded-md border border-border bg-surface-2 py-0.5 pl-2 pr-1 text-xs', mono && 'font-mono')}>
            {v}
            {!disabled ? (
              <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(values.filter((x) => x !== v))} className="rounded p-0.5 text-fg-subtle hover:bg-surface-3 hover:text-fg">
                <X className="size-3" />
              </button>
            ) : null}
          </li>
        ))}
        {!values.length ? <li className="text-xs text-fg-subtle">None</li> : null}
      </ul>
      {!disabled ? (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            add()
          }}
        >
          <Input value={draft} onChange={(e) => setDraft(e.target.value)} placeholder={placeholder} className={cn('max-w-sm', mono && 'font-mono text-xs')} aria-label="Add entry" />
          <Button size="md" type="submit" disabled={!draft.trim()}>
            Add
          </Button>
        </form>
      ) : null}
    </div>
  )
}

export function NoticeEditor({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  const [tab, setTab] = useState<'write' | 'preview'>('write')
  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <span className="text-sm font-medium">Employee monitoring notice</span>
        <Segmented size="sm" label="Notice editor view" value={tab} onChange={setTab} options={[{ value: 'write', label: 'Write' }, { value: 'preview', label: 'Preview' }]} />
      </div>
      {tab === 'write' ? (
        <Textarea value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} className="min-h-56 font-mono text-[12.5px]" aria-label="Notice markdown" />
      ) : (
        <div className="min-h-56 rounded-md border border-border bg-bg p-4">
          <Markdown source={value || '_Nothing written yet._'} className="text-sm" />
        </div>
      )}
      <p className="mt-1 text-xs text-fg-muted">Markdown: **bold**, lists, ## headings and links. Say what is collected, what is not, where it is stored, and who to contact.</p>
    </div>
  )
}

function fmt(v: unknown): string {
  if (v === undefined) return '(unset)'
  if (typeof v === 'string') return v.length > 140 ? `${v.slice(0, 140)}…` : v || '""'
  return JSON.stringify(v)
}

function DiffView({ changes }: { changes: Change[] }) {
  return (
    <ul className="space-y-2">
      {changes.map((c) => (
        <li key={c.path} className="rounded-md border border-border">
          <div className="border-b border-border bg-surface-2/60 px-3 py-1 font-mono text-xs text-fg-muted">{c.path}</div>
          {Array.isArray(c.before) && Array.isArray(c.after) ? (
            <div className="space-y-0.5 px-3 py-2 font-mono text-[12px]">
              {(c.before as unknown[]).filter((x) => !(c.after as unknown[]).includes(x)).map((x) => (
                <div key={`-${String(x)}`} className="text-danger">
                  − {String(x)}
                </div>
              ))}
              {(c.after as unknown[]).filter((x) => !(c.before as unknown[]).includes(x)).map((x) => (
                <div key={`+${String(x)}`} className="text-ok">
                  + {String(x)}
                </div>
              ))}
            </div>
          ) : (
            <div className="grid gap-px px-3 py-2 font-mono text-[12px] sm:grid-cols-2 sm:gap-4">
              <div className="break-words text-danger">− {fmt(c.before)}</div>
              <div className="break-words text-ok">+ {fmt(c.after)}</div>
            </div>
          )}
        </li>
      ))}
    </ul>
  )
}
