import { Field, Input } from '@/components/ui/input'
import { useAuth } from '@/lib/auth'
import { NoticeEditor } from '../policy-editor'
import { SaveBar, SettingsLoading, SettingsSection, useSettingsDraft } from '../settings'

export default function OrganisationTab() {
  const { q, draft, setDraft, save, dirty, reset } = useSettingsDraft()
  const { can } = useAuth()
  if (!draft) return <SettingsLoading q={q} />
  const ro = !can('settings.write')
  const b = draft.branding
  const footer = <SaveBar dirty={dirty} onSave={() => save.mutate(draft)} onReset={reset} pending={save.isPending} disabled={ro} />
  return (
    <div className="space-y-6">
      <SettingsSection title="Organisation and branding" description="Defaults for new policies. Each policy can override branding for its devices." footer={footer}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Organisation name" htmlFor="o-name">
            <Input id="o-name" value={draft.org_name} onChange={(e) => setDraft({ ...draft, org_name: e.target.value, branding: { ...b, org_name: e.target.value } })} disabled={ro} />
          </Field>
          <Field label="IT contact name" htmlFor="o-it">
            <Input id="o-it" value={b.it_contact.name} onChange={(e) => setDraft({ ...draft, branding: { ...b, it_contact: { ...b.it_contact, name: e.target.value } } })} disabled={ro} />
          </Field>
          <Field label="IT email" htmlFor="o-email">
            <Input id="o-email" value={b.it_contact.email} onChange={(e) => setDraft({ ...draft, branding: { ...b, it_contact: { ...b.it_contact, email: e.target.value } } })} disabled={ro} />
          </Field>
          <Field label="IT phone" htmlFor="o-phone">
            <Input id="o-phone" value={b.it_contact.phone} onChange={(e) => setDraft({ ...draft, branding: { ...b, it_contact: { ...b.it_contact, phone: e.target.value } } })} disabled={ro} />
          </Field>
          <div className="sm:col-span-2">
            <NoticeEditor value={b.privacy_notice_md} onChange={(v) => setDraft({ ...draft, branding: { ...b, privacy_notice_md: v } })} disabled={ro} />
          </div>
        </div>
      </SettingsSection>
      <SettingsSection title="Data retention" description="How long the server keeps each kind of data. Shorter retention means less personal data held, and less history to investigate with." footer={footer}>
        <div className="grid gap-4 sm:grid-cols-3">
          {(
            [
              ['events', 'Raw events', 'Hunt and device timelines'],
              ['alerts', 'Alerts and incidents', 'Including evidence'],
              ['audit', 'Audit log', 'MAS TRM expects at least 1 year'],
            ] as const
          ).map(([k, label, hint]) => (
            <Field key={k} label={label} htmlFor={`ret-${k}`} hint={hint}>
              <div className="flex items-center gap-2">
                <Input id={`ret-${k}`} type="number" min={1} max={3650} value={draft.retention_days[k]} onChange={(e) => setDraft({ ...draft, retention_days: { ...draft.retention_days, [k]: Number(e.target.value) } })} className="w-24 text-right tabular" disabled={ro} />
                <span className="text-sm text-fg-muted">days</span>
              </div>
            </Field>
          ))}
        </div>
      </SettingsSection>
    </div>
  )
}
