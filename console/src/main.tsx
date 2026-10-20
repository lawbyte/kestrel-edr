import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import { IS_MOCK } from './api/client'

async function boot() {
  if (IS_MOCK) {
    const { installMock } = await import('./mock/server')
    // Demo builds skip the login screen; dev:mock shows it (any password, any 6-digit code).
    installMock({ autoLogin: import.meta.env.VITE_DEMO === '1' || new URLSearchParams(location.search).has('autologin') })
  }
  const { App } = await import('./App')
  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}
void boot()
