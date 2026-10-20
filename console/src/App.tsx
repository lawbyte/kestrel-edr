import { QueryClient, QueryClientProvider, useQuery, useQueryClient } from '@tanstack/react-query'
import { lazy, Suspense, useEffect, type ReactNode } from 'react'
import { createBrowserRouter, createHashRouter, Navigate, RouterProvider } from 'react-router'
import { Toaster } from 'sonner'
import { ApiError, onUnauthorized, setCsrfToken } from './api/client'
import { api, qk } from './api/endpoints'
import { AuthProvider } from './lib/auth'
import { useTheme } from './lib/theme'
import { AppLayout } from './components/layout'
import { LoadingRows, ErrorState } from './components/common'
import { TooltipProvider } from './components/ui/misc'
import { LoginPage } from './pages/login'

const Overview = lazy(() => import('./pages/overview'))
const Incidents = lazy(() => import('./pages/incidents'))
const IncidentPage = lazy(() => import('./pages/incident'))
const Alerts = lazy(() => import('./pages/alerts'))
const Devices = lazy(() => import('./pages/devices'))
const DevicePage = lazy(() => import('./pages/device'))
const Hunt = lazy(() => import('./pages/hunt'))
const Response = lazy(() => import('./pages/response'))
const Policies = lazy(() => import('./pages/policies'))
const PolicyEditor = lazy(() => import('./pages/policy-editor'))
const Rules = lazy(() => import('./pages/rules'))
const Exclusions = lazy(() => import('./pages/exclusions'))
const Quarantine = lazy(() => import('./pages/quarantine'))
const Reviews = lazy(() => import('./pages/reviews'))
const SettingsPage = lazy(() => import('./pages/settings'))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (n, e) => !(e instanceof ApiError && e.status >= 400 && e.status < 500) && n < 2,
    },
  },
})

function Page({ children }: { children: ReactNode }) {
  return <Suspense fallback={<LoadingRows rows={10} className="p-6" />}>{children}</Suspense>
}

const routes = [
  {
    element: <AppLayout />,
    children: [
      { index: true, element: <Page><Overview /></Page> },
      { path: 'incidents', element: <Page><Incidents /></Page> },
      { path: 'incidents/:id', element: <Page><IncidentPage /></Page> },
      { path: 'alerts', element: <Page><Alerts /></Page> },
      { path: 'devices', element: <Page><Devices /></Page> },
      { path: 'devices/:id', element: <Page><DevicePage /></Page> },
      { path: 'hunt', element: <Page><Hunt /></Page> },
      { path: 'response', element: <Page><Response /></Page> },
      { path: 'policies', element: <Page><Policies /></Page> },
      { path: 'policies/:id', element: <Page><PolicyEditor /></Page> },
      { path: 'rules', element: <Page><Rules /></Page> },
      { path: 'exclusions', element: <Page><Exclusions /></Page> },
      { path: 'quarantine', element: <Page><Quarantine /></Page> },
      { path: 'reviews', element: <Page><Reviews /></Page> },
      { path: 'settings/:tab?', element: <Page><SettingsPage /></Page> },
      { path: '*', element: <Navigate to="/" replace /> },
    ],
  },
]

// The static demo build is served from any path, so it uses hash routing.
const router = import.meta.env.VITE_DEMO === '1' ? createHashRouter(routes) : createBrowserRouter(routes)

function Gate() {
  const qc = useQueryClient()
  const me = useQuery({ queryKey: qk.me, queryFn: api.me, retry: false, staleTime: Infinity })
  useEffect(() => {
    const off = onUnauthorized(() => void qc.resetQueries({ queryKey: qk.me }))
    return () => {
      off()
    }
  }, [qc])
  useEffect(() => {
    if (me.data) setCsrfToken(me.data.csrf_token)
  }, [me.data])
  if (me.isPending) return <div className="flex h-full items-center justify-center text-sm text-fg-subtle">Loading Kestrel…</div>
  if (me.error) {
    if (me.error instanceof ApiError && me.error.status === 401) return <LoginPage />
    return <ErrorState error={me.error} onRetry={() => me.refetch()} className="h-full" />
  }
  return (
    <AuthProvider me={me.data}>
      <RouterProvider router={router} />
    </AuthProvider>
  )
}

export function App() {
  const [theme] = useTheme()
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Gate />
        <Toaster theme={theme} position="bottom-right" closeButton toastOptions={{ className: '!bg-surface !border-border !text-fg !shadow-pop', descriptionClassName: '!text-fg-muted' }} />
      </TooltipProvider>
    </QueryClientProvider>
  )
}
