/* What the shell hands every page through the router's outlet context.
 *
 * Health is fetched once, in `AppShell`, rather than per page. Four pages each fetching
 * `/health` on mount would show four independent loading states for one unchanging
 * document, and could disagree with each other about whether live mode is available.
 *
 * A plain module with no component in it, so React Fast Refresh keeps working: a file
 * that exports both a hook and a component invalidates its component on every edit.
 */

import { useOutletContext } from 'react-router-dom'
import type { HealthResponse } from './api/client'

export interface ShellContext {
  health: HealthResponse | null
  /** Non-null once the first fetch failed. Pages render their own notice from it. */
  error: string | null
  loading: boolean
  /** Re-fetch health, e.g. after starting the service. */
  refresh: () => void
}

export function useShell(): ShellContext {
  return useOutletContext<ShellContext>()
}
