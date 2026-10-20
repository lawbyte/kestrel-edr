import { useCallback, useSyncExternalStore } from 'react'

export type Theme = 'dark' | 'light'
const KEY = 'kestrel-theme'
const subs = new Set<() => void>()

function read(): Theme {
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light'
}

export function setTheme(t: Theme) {
  const el = document.documentElement
  el.classList.toggle('dark', t === 'dark')
  el.classList.toggle('light', t === 'light')
  try {
    localStorage.setItem(KEY, t)
  } catch {
    /* storage may be unavailable */
  }
  subs.forEach((f) => f())
}

export function useTheme(): [Theme, (t: Theme) => void, () => void] {
  const theme = useSyncExternalStore(
    (f) => {
      subs.add(f)
      return () => subs.delete(f)
    },
    read,
    () => 'dark' as Theme,
  )
  const toggle = useCallback(() => setTheme(read() === 'dark' ? 'light' : 'dark'), [])
  return [theme, setTheme, toggle]
}
