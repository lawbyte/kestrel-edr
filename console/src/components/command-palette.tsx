import { useQuery } from '@tanstack/react-query'
import { Command } from 'cmdk'
import { Dialog as D } from 'radix-ui'
import { Activity, BookOpenCheck, Crosshair, FileArchive, Gauge, Keyboard, Laptop, MessageSquareMore, Moon, Search, Settings, ShieldBan, Siren, SlidersHorizontal, Zap, Users, KeyRound, Bell, ScrollText, Download, CloudDownload } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router'
import { api, qk } from '@/api/endpoints'
import { setTheme } from '@/lib/theme'
import { DeviceStatusBadge, SeverityIcon } from './badges'

const PAGES = [
  { to: '/', label: 'Overview', icon: Gauge },
  { to: '/incidents', label: 'Incidents', icon: Siren },
  { to: '/incidents?assignee=me', label: 'Incidents assigned to me', icon: Siren },
  { to: '/alerts', label: 'Alerts', icon: Activity },
  { to: '/devices', label: 'Devices', icon: Laptop },
  { to: '/devices?status=offline', label: 'Offline devices', icon: Laptop },
  { to: '/hunt', label: 'Hunt', icon: Crosshair },
  { to: '/response', label: 'Response action log', icon: Zap },
  { to: '/policies', label: 'Policies', icon: SlidersHorizontal },
  { to: '/rules', label: 'Rules', icon: BookOpenCheck },
  { to: '/exclusions', label: 'Exclusions & IOCs', icon: ShieldBan },
  { to: '/quarantine', label: 'Quarantine', icon: FileArchive },
  { to: '/updates', label: 'Agent updates', icon: CloudDownload },
  { to: '/reviews', label: 'Review requests', icon: MessageSquareMore },
  { to: '/settings/users', label: 'Users & roles', icon: Users },
  { to: '/settings/tokens', label: 'API tokens', icon: KeyRound },
  { to: '/settings/notifications', label: 'Notifications', icon: Bell },
  { to: '/settings/enrollment', label: 'Enroll devices', icon: Download },
  { to: '/settings/audit', label: 'Audit log', icon: ScrollText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function CommandPalette({ open, onOpenChange, onShowShortcuts }: { open: boolean; onOpenChange: (o: boolean) => void; onShowShortcuts: () => void }) {
  const nav = useNavigate()
  const [q, setQ] = useState('')
  const devices = useQuery({ queryKey: qk.devices(), queryFn: () => api.devices(), enabled: open, staleTime: 60_000 })
  const incidents = useQuery({ queryKey: qk.incidents({ sort: 'priority' }), queryFn: () => api.incidents({ sort: 'priority' }), enabled: open, staleTime: 30_000 })
  const go = (to: string) => {
    onOpenChange(false)
    setQ('')
    nav(to)
  }
  const term = q.trim().toLowerCase()
  const devs = (devices.data?.items ?? []).filter((d) => !term || d.hostname.toLowerCase().includes(term) || d.logged_on_user?.toLowerCase().includes(term) || d.ip_addresses.some((i) => i.includes(term))).slice(0, term ? 8 : 4)
  const incs = (incidents.data?.items ?? []).filter((i) => !term || i.title.toLowerCase().includes(term) || i.hostname.toLowerCase().includes(term) || i.rule_ids.some((r) => r.toLowerCase().includes(term))).slice(0, term ? 8 : 5)

  return (
    <D.Root open={open} onOpenChange={onOpenChange}>
      <D.Portal>
        <D.Overlay className="fixed inset-0 z-50 bg-black/40" />
        <D.Content className="fixed left-1/2 top-[14vh] z-50 w-[calc(100vw-2rem)] max-w-xl -translate-x-1/2 overflow-hidden rounded-xl border border-border bg-surface shadow-pop animate-in" aria-label="Command palette">
          <D.Title className="sr-only">Command palette</D.Title>
          <D.Description className="sr-only">Search pages, devices and incidents</D.Description>
          <Command shouldFilter={false} label="Command palette" loop>
            <div className="flex items-center gap-2 border-b border-border px-3">
              <Search className="size-4 text-fg-subtle" />
              <Command.Input value={q} onValueChange={setQ} autoFocus placeholder="Search devices, incidents, pages…" className="h-12 flex-1 bg-transparent text-[15px] outline-none placeholder:text-fg-subtle" />
            </div>
            <Command.List className="max-h-[52vh] overflow-y-auto p-1.5 [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:pt-2 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:text-fg-subtle">
              <Command.Empty className="px-3 py-8 text-center text-sm text-fg-muted">No matches for “{q}”. Try a hostname, user name, rule id or page.</Command.Empty>
              {incs.length ? (
                <Command.Group heading="Incidents">
                  {incs.map((i) => (
                    <Item key={i.id} value={`inc-${i.id}`} onSelect={() => go(`/incidents/${i.id}`)}>
                      <SeverityIcon severity={i.severity} />
                      <span className="flex-1 truncate">{i.title}</span>
                      <span className="text-xs tabular text-fg-subtle">P{i.priority}</span>
                    </Item>
                  ))}
                </Command.Group>
              ) : null}
              {devs.length ? (
                <Command.Group heading="Devices">
                  {devs.map((d) => (
                    <Item key={d.id} value={`dev-${d.id}`} onSelect={() => go(`/devices/${d.id}`)}>
                      <Laptop className="size-4 text-fg-subtle" />
                      <span className="font-mono text-[13px]">{d.hostname}</span>
                      <span className="flex-1 truncate text-xs text-fg-subtle">{d.logged_on_user ?? ''}</span>
                      <DeviceStatusBadge status={d.status} className="text-xs" />
                    </Item>
                  ))}
                </Command.Group>
              ) : null}
              <Command.Group heading="Go to">
                {PAGES.filter((p) => !term || p.label.toLowerCase().includes(term)).map((p) => (
                  <Item key={p.to} value={`page-${p.to}`} onSelect={() => go(p.to)}>
                    <p.icon className="size-4 text-fg-subtle" />
                    {p.label}
                  </Item>
                ))}
              </Command.Group>
              {!term || 'theme dark light shortcuts keyboard'.includes(term) ? (
                <Command.Group heading="Actions">
                  {term && term.startsWith('hunt') ? null : (
                    <Item value="hunt-q" onSelect={() => go(`/hunt${term ? `?q=${encodeURIComponent(`image ~ ${term}`)}` : ''}`)}>
                      <Crosshair className="size-4 text-fg-subtle" /> Hunt for {term ? `“${term}”` : 'an indicator'}
                    </Item>
                  )}
                  <Item
                    value="theme"
                    onSelect={() => {
                      setTheme(document.documentElement.classList.contains('dark') ? 'light' : 'dark')
                      onOpenChange(false)
                    }}
                  >
                    <Moon className="size-4 text-fg-subtle" /> Switch theme
                  </Item>
                  <Item
                    value="shortcuts"
                    onSelect={() => {
                      onOpenChange(false)
                      onShowShortcuts()
                    }}
                  >
                    <Keyboard className="size-4 text-fg-subtle" /> Keyboard shortcuts
                  </Item>
                </Command.Group>
              ) : null}
            </Command.List>
          </Command>
        </D.Content>
      </D.Portal>
    </D.Root>
  )
}

function Item({ children, ...p }: React.ComponentProps<typeof Command.Item>) {
  return (
    <Command.Item {...p} className="flex h-9 cursor-default items-center gap-2.5 rounded-md px-2 text-sm data-[selected=true]:bg-surface-2">
      {children}
    </Command.Item>
  )
}
