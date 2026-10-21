import { Info } from 'lucide-react'
import type { ReactNode } from 'react'
import type { NotificationSettings, Severity } from '@/api/types'
import { Field, Input, inputClass } from '@/components/ui/input'
import { Switch } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { SEVERITY_LABEL } from '@/lib/labels'
import { cn } from '@/lib/utils'
import { SaveBar, SettingsLoading, SettingsSection, useSettingsDraft } from '../settings'

export default function NotificationsTab() {
  const { q, draft, setDraft, save, dirty, reset } = useSettingsDraft()
  const { can } = useAuth()
  if (!draft) return <SettingsLoading q={q} />
  const n = draft.notifications
  const ro = !can('settings.write')
  const set = <K extends keyof NotificationSettings>(k: K, v: Partial<NotificationSettings[K]>) => setDraft({ ...draft, notifications: { ...n, [k]: { ...n[k], ...v } } })
  return (
    <SettingsSection
      title="Notifications"
      description="Where Kestrel sends new incidents. Each channel has its own minimum severity."
      footer={<SaveBar dirty={dirty} onSave={() => save.mutate(draft)} onReset={reset} pending={save.isPending} disabled={ro} />}
    >
      <div className="space-y-4">
        <Channel title="Email" enabled={n.email.enabled} onToggle={(v) => set('email', { enabled: v })} disabled={ro}>
          <div className="grid gap-3 sm:grid-cols-[1fr_6rem]">
            <Field label="SMTP host" htmlFor="smtp-host">
              <Input id="smtp-host" value={n.email.smtp_host} onChange={(e) => set('email', { smtp_host: e.target.value })} disabled={ro} />
            </Field>
            <Field label="Port" htmlFor="smtp-port">
              <Input id="smtp-port" type="number" value={n.email.smtp_port} onChange={(e) => set('email', { smtp_port: Number(e.target.value) })} disabled={ro} />
            </Field>
            <Field label="Username" htmlFor="smtp-user">
              <Input id="smtp-user" value={n.email.username} onChange={(e) => set('email', { username: e.target.value })} disabled={ro} />
            </Field>
            <span />
            <Field label="Password" htmlFor="smtp-pw" hint={n.email.password_set ? 'A password is saved. Type to replace it.' : 'Not set'}>
              <Input id="smtp-pw" type="password" autoComplete="new-password" placeholder={n.email.password_set ? '••••••••' : ''} value={n.email.password ?? ''} onChange={(e) => set('email', { password: e.target.value })} disabled={ro} />
            </Field>
            <span />
            <Field label="From" htmlFor="smtp-from">
              <Input id="smtp-from" value={n.email.from} onChange={(e) => set('email', { from: e.target.value })} disabled={ro} />
            </Field>
            <span />
            <Field label="Send to" htmlFor="smtp-to" hint="Comma-separated">
              <Input id="smtp-to" value={n.email.to.join(', ')} onChange={(e) => set('email', { to: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} disabled={ro} />
            </Field>
          </div>
          <MinSeverity value={n.email.min_severity} onChange={(v) => set('email', { min_severity: v })} disabled={ro} />
        </Channel>
        <Channel title="Slack" enabled={n.slack.enabled} onToggle={(v) => set('slack', { enabled: v })} disabled={ro}>
          <Field label="Incoming webhook URL" htmlFor="slack-url">
            <Input id="slack-url" value={n.slack.webhook_url} onChange={(e) => set('slack', { webhook_url: e.target.value })} disabled={ro} placeholder="https://hooks.slack.com/services/…" />
          </Field>
          <MinSeverity value={n.slack.min_severity} onChange={(v) => set('slack', { min_severity: v })} disabled={ro} />
        </Channel>
        <Channel title="Microsoft Teams" enabled={n.teams.enabled} onToggle={(v) => set('teams', { enabled: v })} disabled={ro}>
          <Field label="Workflow webhook URL" htmlFor="teams-url">
            <Input id="teams-url" value={n.teams.webhook_url} onChange={(e) => set('teams', { webhook_url: e.target.value })} disabled={ro} />
          </Field>
          <MinSeverity value={n.teams.min_severity} onChange={(v) => set('teams', { min_severity: v })} disabled={ro} />
        </Channel>
        <Channel title="Webhook" enabled={n.webhook.enabled} onToggle={(v) => set('webhook', { enabled: v })} disabled={ro}>
          <Field label="URL" htmlFor="wh-url" hint="Kestrel POSTs incident JSON, signed with HMAC-SHA256 in the X-Kestrel-Signature header. Public addresses only; redirects are not followed.">
            <Input id="wh-url" value={n.webhook.url} onChange={(e) => set('webhook', { url: e.target.value })} disabled={ro} placeholder={ro && n.webhook.url_set ? 'Set (hidden)' : 'https://'} />
          </Field>
          <Field label="Signing secret" htmlFor="wh-secret" hint={n.webhook.secret_set ? 'A secret is saved. Type to replace it.' : 'Not set'}>
            <Input id="wh-secret" type="password" autoComplete="new-password" value={n.webhook.secret ?? ''} placeholder={n.webhook.secret_set ? '••••••••' : ''} onChange={(e) => set('webhook', { secret: e.target.value })} disabled={ro} />
          </Field>
          <MinSeverity value={n.webhook.min_severity} onChange={(v) => set('webhook', { min_severity: v })} disabled={ro} />
        </Channel>
        <Channel title="Syslog (SIEM)" enabled={n.syslog.enabled} onToggle={(v) => set('syslog', { enabled: v })} disabled={ro}>
          <div className="grid gap-3 sm:grid-cols-[1fr_6rem_6rem_6rem]">
            <Field label="Host" htmlFor="sl-host">
              <Input id="sl-host" value={n.syslog.host} onChange={(e) => set('syslog', { host: e.target.value })} disabled={ro} />
            </Field>
            <Field label="Port" htmlFor="sl-port">
              <Input id="sl-port" type="number" value={n.syslog.port} onChange={(e) => set('syslog', { port: Number(e.target.value) })} disabled={ro} />
            </Field>
            <Field label="Protocol" htmlFor="sl-proto">
              <select id="sl-proto" value={n.syslog.protocol} onChange={(e) => set('syslog', { protocol: e.target.value as 'udp' })} className={cn(inputClass, 'h-8')} disabled={ro}>
                <option value="udp">UDP</option>
                <option value="tcp">TCP</option>
                <option value="tls">TLS</option>
              </select>
            </Field>
            <Field label="Format" htmlFor="sl-fmt">
              <select id="sl-fmt" value={n.syslog.format} onChange={(e) => set('syslog', { format: e.target.value as 'cef' })} className={cn(inputClass, 'h-8')} disabled={ro}>
                <option value="cef">CEF</option>
                <option value="json">JSON</option>
              </select>
            </Field>
          </div>
          <label className="flex items-start justify-between gap-3">
            <span>
              <span className="text-sm font-medium">Collector is on the internal network</span>
              <span className="block text-xs text-fg-muted">Allow a private or loopback address (10.x, 192.168.x, …). Cloud metadata and link-local addresses stay blocked.</span>
            </span>
            <Switch checked={!!n.syslog.allow_private} onCheckedChange={(v) => set('syslog', { allow_private: v })} disabled={ro} aria-label="Allow a private syslog address" />
          </label>
          <p className="text-xs text-fg-muted">Syslog receives every alert, regardless of severity, and the audit-log head hash every 15 minutes (tamper evidence).</p>
        </Channel>
        <p className="flex items-center gap-1.5 text-xs text-fg-subtle">
          <Info className="size-3.5" /> Test sends are not available yet; save, then watch the channel for the next incident.
        </p>
      </div>
    </SettingsSection>
  )
}

function Channel({ title, enabled, onToggle, children, disabled }: { title: string; enabled: boolean; onToggle: (v: boolean) => void; children: ReactNode; disabled?: boolean }) {
  return (
    <div className={cn('rounded-lg border', enabled ? 'border-border-strong' : 'border-border')}>
      <div className="flex items-center justify-between px-4 py-2.5">
        <span className="text-sm font-medium">{title}</span>
        <Switch checked={enabled} onCheckedChange={onToggle} aria-label={`Enable ${title}`} disabled={disabled} />
      </div>
      {enabled ? <div className="space-y-3 border-t border-border px-4 py-3">{children}</div> : null}
    </div>
  )
}

function MinSeverity({ value, onChange, disabled }: { value: Severity; onChange: (v: Severity) => void; disabled?: boolean }) {
  return (
    <label className="flex items-center gap-2 text-sm">
      <span className="text-fg-muted">Send incidents of severity</span>
      <select value={value} onChange={(e) => onChange(e.target.value as Severity)} className={cn(inputClass, 'h-7 w-44')} disabled={disabled}>
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((s) => (
          <option key={s} value={s}>
            {SEVERITY_LABEL[s]}
            {s !== 'critical' ? ' and above' : ' only'}
          </option>
        ))}
      </select>
    </label>
  )
}
