import { createContext, useContext, useMemo, type ReactNode } from 'react'
import type { MeResponse } from '@/api/types'

interface AuthCtx {
  me: MeResponse
  can: (privilege: string) => boolean
}
const Ctx = createContext<AuthCtx | null>(null)

export function AuthProvider({ me, children }: { me: MeResponse; children: ReactNode }) {
  const value = useMemo<AuthCtx>(
    () => ({ me, can: (p: string) => me.privileges.includes('*') || me.privileges.includes(p) }),
    [me],
  )
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>
}

export function useAuth(): AuthCtx {
  const v = useContext(Ctx)
  if (!v) throw new Error('useAuth outside AuthProvider')
  return v
}
