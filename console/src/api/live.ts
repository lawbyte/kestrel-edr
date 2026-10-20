import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import type { LiveEvent, LiveEventType } from './types'
import { API_BASE, IS_MOCK } from './client'

type Listener = (e: LiveEvent) => void
const listeners = new Set<Listener>()
let started = false

function dispatch(e: LiveEvent) {
  for (const l of listeners) l(e)
}

async function start() {
  if (started) return
  started = true
  if (IS_MOCK) {
    const { subscribeMockLive } = await import('@/mock/server')
    subscribeMockLive(dispatch)
    return
  }
  const connect = () => {
    const es = new EventSource(`${API_BASE}/events/stream`, { withCredentials: true })
    const kinds: LiveEventType[] = ['incident', 'alert', 'device', 'action']
    for (const k of kinds) {
      es.addEventListener(k, (m) => {
        try {
          const d = JSON.parse((m as MessageEvent).data) as { id: string; type: 'created' | 'updated' }
          dispatch({ kind: k, id: d.id, type: d.type })
        } catch {
          /* ignore malformed */
        }
      })
    }
    es.onerror = () => {
      es.close()
      setTimeout(connect, 5000)
    }
  }
  connect()
}

export function subscribeLive(fn: Listener) {
  void start()
  listeners.add(fn)
  return () => {
    listeners.delete(fn)
  }
}

/** Invalidate the right queries when the server pushes a change. */
export function useLiveInvalidation() {
  const qc = useQueryClient()
  useEffect(
    () =>
      subscribeLive((e) => {
        switch (e.kind) {
          case 'incident':
            void qc.invalidateQueries({ queryKey: ['incidents'] })
            void qc.invalidateQueries({ queryKey: ['incident', e.id] })
            void qc.invalidateQueries({ queryKey: ['dashboard'] })
            break
          case 'alert':
            void qc.invalidateQueries({ queryKey: ['alerts'] })
            void qc.invalidateQueries({ queryKey: ['dashboard'] })
            break
          case 'device':
            void qc.invalidateQueries({ queryKey: ['devices'] })
            void qc.invalidateQueries({ queryKey: ['device', e.id] })
            break
          case 'action':
            void qc.invalidateQueries({ queryKey: ['actions'] })
            void qc.invalidateQueries({ queryKey: ['incident'] })
            break
        }
      }),
    [qc],
  )
}

/** Calls `fn` for live events of the given kinds (used for "new" row highlighting and live-region announcements). */
export function useLiveEvents(kinds: LiveEventType[], fn: Listener) {
  const ref = useRef(fn)
  ref.current = fn
  const key = kinds.join(',')
  useEffect(() => subscribeLive((e) => key.split(',').includes(e.kind) && ref.current(e)), [key])
}
