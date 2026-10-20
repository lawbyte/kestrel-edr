import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  BookOpenCheck,
  Crosshair,
  FileArchive,
  Gauge,
  Keyboard,
  LogOut,
  Menu,
  Moon,
  Search,
  Settings,
  ShieldBan,
  ShieldHalf,
  Siren,
  SlidersHorizontal,
  Sun,
  Laptop,
  MessageSquareMore,
  Zap,
} from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router'
import { api, qk } from '@/api/endpoints'
import { IS_MOCK } from '@/api/client'
import { useLiveInvalidation } from '@/api/live'
import { useAuth } from '@/lib/auth'
import { useTheme } from '@/lib/theme'
import { cn, isTypingTarget } from '@/lib/utils'
import { Avatar } from './common'
import { CommandPalette } from './command-palette'
import { ShortcutsDialog } from './shortcuts'
import { Dropdown, DropdownContent, DropdownItem, DropdownLabel, DropdownSeparator, DropdownTrigger, Kbd } from './ui/misc'
import { KestrelMark } from './logo'

interface NavItem {
  to: string
  label: string
  icon: typeof Gauge
  badge?: number
  hint?: string
}

function useNavBadges() {
  const inc = useQuery({ queryKey: qk.incidents({ status: 'open,in_progress' }), queryFn: () => api.incidents({ status: 'open,in_progress', limit: 1 }), staleTime: 30_000 })
  const rev = useQuery({ queryKey: qk.reviews('requested'), queryFn: () => api.reviewRequests('requested'), staleTime: 60_000 })
  return { incidents: inc.data?.total, reviews: rev.data?.length }
}

export function AppLayout() {
  useLiveInvalidation()
  const { me } = useAuth()
  const [theme, , toggleTheme] = useTheme()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [helpOpen, setHelpOpen] = useState(false)
  const [mobileNav, setMobileNav] = useState(false)
  const nav = useNavigate()
  const loc = useLocation()
  const badges = useNavBadges()
  const org = useQuery({ queryKey: qk.setup, queryFn: api.setupStatus, staleTime: Infinity })

  useEffect(() => setMobileNav(false), [loc.pathname])

  useEffect(() => {
    let gPressed = 0
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((o) => !o)
        return
      }
      if (isTypingTarget(e.target) || e.metaKey || e.ctrlKey || e.altKey) return
      if (document.querySelector('[role="dialog"][data-state="open"]:not([data-drawer])')) return
      if (e.key === '?') {
        e.preventDefault()
        setHelpOpen(true)
      } else if (e.key === '/') {
        e.preventDefault()
        setPaletteOpen(true)
      } else if (e.key === 'g') {
        gPressed = Date.now()
      } else if (Date.now() - gPressed < 900) {
        const map: Record<string, string> = { o: '/', i: '/incidents', a: '/alerts', d: '/devices', h: '/hunt', r: '/response', p: '/policies', s: '/settings' }
        if (map[e.key]) {
          e.preventDefault()
          nav(map[e.key])
        }
        gPressed = 0
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [nav])

  const sections: { label: string; items: NavItem[] }[] = [
    {
      label: 'Respond',
      items: [
        { to: '/', label: 'Overview', icon: Gauge, hint: 'G O' },
        { to: '/incidents', label: 'Incidents', icon: Siren, badge: badges.incidents, hint: 'G I' },
        { to: '/alerts', label: 'Alerts', icon: Activity, hint: 'G A' },
        { to: '/devices', label: 'Devices', icon: Laptop, hint: 'G D' },
        { to: '/hunt', label: 'Hunt', icon: Crosshair, hint: 'G H' },
        { to: '/response', label: 'Response', icon: Zap, hint: 'G R' },
      ],
    },
    {
      label: 'Configure',
      items: [
        { to: '/policies', label: 'Policies', icon: SlidersHorizontal, hint: 'G P' },
        { to: '/rules', label: 'Rules', icon: BookOpenCheck },
        { to: '/exclusions', label: 'Exclusions & IOCs', icon: ShieldBan },
        { to: '/quarantine', label: 'Quarantine', icon: FileArchive },
        { to: '/reviews', label: 'Review requests', icon: MessageSquareMore, badge: badges.reviews },
        { to: '/settings', label: 'Settings', icon: Settings, hint: 'G S' },
      ],
    },
  ]

  const sidebar = (
    <nav aria-label="Main" className="flex h-full flex-col">
      <div className="flex h-14 items-center gap-2.5 px-4">
        <KestrelMark className="size-7" />
        <div className="min-w-0 leading-tight">
          <div className="text-[15px] font-semibold tracking-[-0.01em]">Kestrel</div>
          <div className="truncate text-[11px] text-fg-subtle">{org.data?.org_name ?? 'EDR console'}</div>
        </div>
      </div>
      <button
        type="button"
        onClick={() => setPaletteOpen(true)}
        className="mx-3 mb-3 flex h-8 items-center gap-2 rounded-md border border-border bg-surface px-2.5 text-sm text-fg-subtle hover:border-border-strong hover:text-fg-muted"
      >
        <Search className="size-3.5" />
        <span className="flex-1 text-left">Search or jump to…</span>
        <Kbd>⌘K</Kbd>
      </button>
      <div className="flex-1 space-y-5 overflow-y-auto px-3 pb-4">
        {sections.map((s) => (
          <div key={s.label}>
            <div className="mb-1 px-2 text-[11px] font-medium text-fg-subtle">{s.label}</div>
            <ul className="space-y-px">
              {s.items.map((it) => (
                <li key={it.to}>
                  <NavLink
                    to={it.to}
                    end={it.to === '/'}
                    className={({ isActive }) =>
                      cn(
                        'group flex h-8 items-center gap-2.5 rounded-md px-2 text-sm transition-colors',
                        isActive ? 'bg-surface text-fg font-medium shadow-[0_0_0_1px_var(--border)]' : 'text-fg-muted hover:bg-surface/60 hover:text-fg',
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <it.icon className={cn('size-4 shrink-0', isActive ? 'text-accent-text' : 'text-fg-subtle group-hover:text-fg-muted')} aria-hidden />
                        <span className="flex-1 truncate">{it.label}</span>
                        {it.badge ? (
                          <span className={cn('min-w-5 rounded-full px-1.5 text-center text-[11px] font-semibold tabular leading-[18px]', it.to === '/incidents' ? 'bg-sev-critical-soft text-sev-critical' : 'bg-surface-3 text-fg-muted')} aria-label={`${it.badge} open`}>
                            {it.badge}
                          </span>
                        ) : null}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
      <div className="border-t border-border p-2">
        <Dropdown>
          <DropdownTrigger className="flex w-full items-center gap-2.5 rounded-md p-2 text-left hover:bg-surface/70">
            <Avatar user={me.user} size="sm" />
            <span className="min-w-0 flex-1">
              <span className="block truncate text-sm font-medium">{me.user.name}</span>
              <span className="block truncate text-[11px] capitalize text-fg-subtle">{me.user.role}</span>
            </span>
          </DropdownTrigger>
          <DropdownContent align="start" side="top" className="w-60">
            <DropdownLabel>{me.user.email}</DropdownLabel>
            <DropdownSeparator />
            <DropdownItem onSelect={toggleTheme}>
              {theme === 'dark' ? <Sun /> : <Moon />} {theme === 'dark' ? 'Light theme' : 'Dark theme'}
            </DropdownItem>
            <DropdownItem onSelect={() => setHelpOpen(true)}>
              <Keyboard /> Keyboard shortcuts
            </DropdownItem>
            <DropdownItem onSelect={() => nav('/settings')}>
              <Settings /> Settings
            </DropdownItem>
            <DropdownSeparator />
            <DropdownItem
              onSelect={async () => {
                await api.logout().catch(() => undefined)
                location.reload()
              }}
            >
              <LogOut /> Sign out
            </DropdownItem>
          </DropdownContent>
        </Dropdown>
      </div>
    </nav>
  )

  return (
    <div className="flex h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-surface focus:px-3 focus:py-2">
        Skip to content
      </a>
      <aside className="hidden w-[232px] shrink-0 border-r border-border bg-sidebar lg:block">{sidebar}</aside>
      {mobileNav ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/40" onClick={() => setMobileNav(false)} />
          <aside className="absolute inset-y-0 left-0 w-[260px] border-r border-border bg-sidebar animate-in">{sidebar}</aside>
        </div>
      ) : null}
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-12 items-center gap-2 border-b border-border px-3 lg:hidden">
          <button type="button" aria-label="Open navigation" className="rounded-md p-1.5 hover:bg-surface-2" onClick={() => setMobileNav(true)}>
            <Menu className="size-5" />
          </button>
          <KestrelMark className="size-6" />
          <span className="font-semibold">Kestrel</span>
          <button type="button" aria-label="Search" className="ml-auto rounded-md p-1.5 hover:bg-surface-2" onClick={() => setPaletteOpen(true)}>
            <Search className="size-5" />
          </button>
        </div>
        {IS_MOCK ? <DemoBanner /> : null}
        <main id="main" className="min-h-0 flex-1 overflow-y-auto" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} onShowShortcuts={() => setHelpOpen(true)} />
      <ShortcutsDialog open={helpOpen} onOpenChange={setHelpOpen} />
    </div>
  )
}

function DemoBanner() {
  const [hidden, setHidden] = useState(() => sessionStorage.getItem('kestrel-demo-banner') === '0')
  if (hidden) return null
  return (
    <div className="flex items-center gap-2 border-b border-border bg-accent-soft px-4 py-1.5 text-xs text-accent-text">
      <ShieldHalf className="size-3.5" />
      <span>Demo data. Nothing here touches real devices; changes reset when you reload.</span>
      <button
        type="button"
        className="ml-auto rounded px-1.5 hover:bg-accent/10"
        onClick={() => {
          sessionStorage.setItem('kestrel-demo-banner', '0')
          setHidden(true)
        }}
      >
        Dismiss
      </button>
    </div>
  )
}

export function Shell({ children }: { children: ReactNode }) {
  return <div className="flex min-h-full items-center justify-center bg-bg p-6">{children}</div>
}

