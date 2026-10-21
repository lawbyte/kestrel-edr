import { CopyButton } from '@/components/copy-button'
import { MfaSetupLink } from '@/components/mfa-link'
import { Field, Input, inputClass } from '@/components/ui/input'
import { Switch } from '@/components/ui/misc'
import { useAuth } from '@/lib/auth'
import { cn } from '@/lib/utils'
import { SaveBar, SettingsLoading, SettingsSection, useSettingsDraft } from '../settings'

export default function SsoTab() {
  const { q, draft, setDraft, save, dirty, reset } = useSettingsDraft()
  const { can, me } = useAuth()
  if (!draft) return <SettingsLoading q={q} />
  const o = draft.oidc
  const ro = !can('settings.write')
  const set = (v: Partial<typeof o>) => setDraft({ ...draft, oidc: { ...o, ...v } })
  const redirect = `${location.origin}/api/auth/oidc/callback`
  const noDomains = o.allowed_domains.length === 0
  return (
    <div className="space-y-6">
      <SettingsSection
        title="Single sign-on (OIDC)"
        description="Let people sign in with Microsoft Entra ID, Google Workspace, Okta or any OpenID Connect provider."
        footer={<SaveBar dirty={dirty} onSave={() => save.mutate(draft)} onReset={reset} pending={save.isPending} disabled={ro} />}
      >
        <div className="space-y-4">
          <label className="flex items-center justify-between gap-3">
            <span className="text-sm font-medium">Enable single sign-on</span>
            <Switch checked={o.enabled} onCheckedChange={(v) => set({ enabled: v })} disabled={ro} />
          </label>
          <Field label="Redirect URI" hint="Register this in your identity provider.">
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 truncate rounded-md border border-border bg-surface-2 px-2.5 py-1.5 font-mono text-xs">{redirect}</code>
              <CopyButton text={redirect} />
            </div>
          </Field>
          <Field label="Issuer URL" htmlFor="oidc-iss">
            <Input id="oidc-iss" value={o.issuer} onChange={(e) => set({ issuer: e.target.value })} disabled={ro} placeholder="https://login.microsoftonline.com/<tenant>/v2.0" />
          </Field>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Client ID" htmlFor="oidc-cid">
              <Input id="oidc-cid" value={o.client_id} onChange={(e) => set({ client_id: e.target.value })} disabled={ro} />
            </Field>
            <Field label="Client secret" htmlFor="oidc-sec" hint={o.client_secret_set ? 'A secret is saved. Type to replace it.' : 'Not set'}>
              <Input id="oidc-sec" type="password" autoComplete="new-password" value={o.client_secret ?? ''} placeholder={o.client_secret_set ? '••••••••' : ''} onChange={(e) => set({ client_secret: e.target.value })} disabled={ro} />
            </Field>
          </div>
          <Field
            label="Allowed email domains"
            htmlFor="oidc-dom"
            hint="Required. Comma-separated, e.g. corp.com. Only people whose verified email is in one of these domains can sign in; if the list is empty, nobody can (single sign-on fails closed)."
            error={o.enabled && noDomains ? 'Add at least one domain: with an empty list every SSO sign-in is denied, and the server will not save SSO as enabled.' : null}
          >
            <Input id="oidc-dom" value={o.allowed_domains.join(', ')} onChange={(e) => set({ allowed_domains: e.target.value.split(',').map((s) => s.trim()).filter(Boolean) })} disabled={ro} placeholder="corp.com" aria-invalid={o.enabled && noDomains} />
          </Field>
          <Field label="Role for new SSO users" htmlFor="oidc-role" hint="Administrator is not allowed here: promote people from Users & roles after their first sign-in.">
            <select id="oidc-role" value={o.default_role === 'admin' ? 'readonly' : o.default_role} onChange={(e) => set({ default_role: e.target.value })} className={cn(inputClass, 'h-8 max-w-48')} disabled={ro}>
              <option value="readonly">Read-only</option>
              <option value="analyst">Analyst</option>
            </select>
          </Field>
          <div className="rounded-md border border-border bg-surface-2 px-3 py-2 text-xs text-fg-muted">
            <p>
              Accounts are tied to the identity provider’s user ID, never matched by email. A first SSO sign-in creates a new account with the role above. If someone already has a password account with the same email, an
              administrator links it from <span className="text-fg">Users &amp; roles</span> first. The provider must mark the email as verified.
            </p>
          </div>
        </div>
      </SettingsSection>
      <SettingsSection title="Sessions" footer={<SaveBar dirty={dirty} onSave={() => save.mutate(draft)} onReset={reset} pending={save.isPending} disabled={ro} />}>
        <div className="space-y-4">
          <label className="flex items-center justify-between gap-3">
            <span>
              <span className="text-sm font-medium">Require two-factor authentication</span>
              <span className="block text-xs text-fg-muted">For password sign-ins. SSO users follow their identity provider’s policy.</span>
            </span>
            <Switch checked={draft.require_mfa} onCheckedChange={(v) => setDraft({ ...draft, require_mfa: v })} disabled={ro} aria-label="Require two-factor authentication" />
          </label>
          <p className="-mt-2 text-xs text-fg-muted" data-testid="require-mfa-hint">
            Everyone sets up their own authenticator app under <span className="text-fg">Account &amp; security</span> in the user menu. People who haven’t yet are sent there at their next password sign-in and can’t use
            the console until they finish.{' '}
            {me.user.mfa_enabled ? <MfaSetupLink>Your two-factor settings</MfaSetupLink> : <MfaSetupLink>Set up yours first</MfaSetupLink>}
          </p>
          <Field label="Sign people out after (minutes)" htmlFor="sess" hint="Of inactivity.">
            <Input id="sess" type="number" min={15} max={1440} value={draft.session_timeout_minutes} onChange={(e) => setDraft({ ...draft, session_timeout_minutes: Number(e.target.value) })} className="w-32" disabled={ro} />
          </Field>
          <Field label="Maximum session length (days)" htmlFor="sess-max" hint="People sign in again after this long, even when active. Live updates stop for sessions that end or lose access.">
            <Input id="sess-max" type="number" min={1} max={90} value={draft.session_max_days ?? 7} onChange={(e) => setDraft({ ...draft, session_max_days: Number(e.target.value) })} className="w-32" disabled={ro} />
          </Field>
        </div>
      </SettingsSection>
    </div>
  )
}
