import { useCallback, useEffect, useState } from 'react'
import { Outlet } from 'react-router-dom'
import { fetchHealth } from './api/client'
import type { HealthResponse } from './api/client'
import SideBar from './components/SideBar/SideBar'
import { Badge, Dot } from './components/ui'
import type { ShellContext } from './shell-context'

function TopBar({ health, loading }: { health: HealthResponse | null; loading: boolean }) {
  const reachable = health !== null
  const live = health?.live_mode.available ?? false

  return (
    <header className="flex h-14 shrink-0 items-center justify-between gap-4 border-b border-line bg-surface px-6">
      <div className="flex items-baseline gap-3">
        <h1 className="text-sm font-semibold tracking-[0.18em] text-text">CONTROL CENTER</h1>
        {health && (
          <span className="tnum font-mono text-xs text-faint">
            {health.service} v{health.version}
          </span>
        )}
      </div>

      <div className="flex items-center gap-2.5">
        {/* Live mode is two independent conditions in the service; the badge states which
            one is missing rather than just "off", because "not enabled" and "no
            credentials" are different things to go and fix. */}
        {health && (
          <Badge tone={live ? 'gov' : 'neutral'}>
            {live
              ? 'LIVE AVAILABLE'
              : health.live_mode.enabled
                ? 'LIVE: NO CREDENTIALS'
                : 'LIVE: DISABLED'}
          </Badge>
        )}
        {health?.enterprise.simulated && <Badge tone="warn">SIMULATED ENTERPRISE</Badge>}
        <span className="flex items-center gap-2 text-xs text-muted">
          <Dot tone={loading ? 'neutral' : reachable ? 'good' : 'bad'} />
          {loading ? 'Connecting' : reachable ? 'Service reachable' : 'Service unreachable'}
        </span>
      </div>
    </header>
  )
}

export default function AppShell() {
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  // `loading` starts true and is cleared when the first fetch settles, so the effect
  // never sets state synchronously — doing that schedules a second render before the
  // first has painted, and the initial value already says what it would have said.
  const load = useCallback(() => {
    fetchHealth()
      .then((value) => {
        setHealth(value)
        setError(null)
      })
      .catch((cause: unknown) => {
        setHealth(null)
        setError(cause instanceof Error ? cause.message : String(cause))
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(load, [load])

  const refresh = useCallback(() => {
    setLoading(true)
    load()
  }, [load])

  const context: ShellContext = { health, error, loading, refresh }

  return (
    <div className="flex h-screen overflow-hidden bg-bg text-text">
      <SideBar />
      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar health={health} loading={loading} />
        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="mx-auto max-w-6xl">
            <Outlet context={context} />
          </div>
        </main>
      </div>
    </div>
  )
}
