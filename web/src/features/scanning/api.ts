import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { EngineId, RunningJob, SafetyInput, SafetySaved, Safety, Scanning } from './types'

/** GET /scanning: the page, the engines, the shared safety block and the runs going on (served by core, so it answers while every
 *  engine's module is off). Read every 5 s while a run goes on (its progress), every 30 s otherwise so the top-bar indicator sees a
 *  run another page or a schedule started; never in a hidden tab (TanStack's default). Tests shorten it. */
export const scanningPoll = { runningMs: 5000, idleMs: 30_000 }
export const useScanning = (enabled = true) => useQuery({
  queryKey: ['scanning'], queryFn: () => api.get<Scanning>('/scanning'), enabled,
  refetchInterval: (q) => (q.state.data?.running.length ? scanningPoll.runningMs : scanningPoll.idleMs),
})

function useRefresh() {
  const qc = useQueryClient()
  return () => {
    // the switches and the block move other modules' state: their pages read them again
    for (const k of ['modules', 'scan', 'inventory', 'exposure', 'honeypot']) void qc.invalidateQueries({ queryKey: [k] })
  }
}

/** PATCH /scanning/engines/{id}: the answer is the whole page (one switch can move several engines). */
export function useSetEngine() {
  const qc = useQueryClient()
  const refresh = useRefresh()
  return useMutation({
    mutationFn: (v: { id: EngineId; enabled: boolean; withDependencies?: boolean }) =>
      api.patch<Scanning>(`/scanning/engines/${encodeURIComponent(v.id)}`, { enabled: v.enabled, ...(v.withDependencies ? { with_dependencies: true } : {}) }),
    onSuccess: (page) => { qc.setQueryData(['scanning'], page); refresh() },
  })
}

/** PUT /scanning/safety: the one writer of the shared block (inventory stores it). */
export function useSaveSafety() {
  const qc = useQueryClient()
  const refresh = useRefresh()
  return useMutation({
    mutationFn: (b: SafetyInput) => api.put<SafetySaved>('/scanning/safety', b),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['scanning'] }); refresh() },
  })
}

/** The block as a save body: what GET /scanning shows, with the changes of `patch`. */
export function safetyInput(s: Safety, patch: Partial<SafetyInput> = {}): SafetyInput {
  return {
    scope: { lan_ranges: s.scope.lan_ranges, confirmed: !!s.scope.confirmed_at },
    window: { days: s.window.days, from: s.window.from, to: s.window.to }, // as they are: an empty list is the server's no_days to fix, never a window nobody chose
    speed: s.speed, exclusions: s.exclusions, fragile: { kinds: s.fragile.kinds, regular_scan_kinds: s.fragile.regular_scan_kinds },
    ...patch,
  }
}

/** POST /scanning/engines/nmap-discovery/run: "Scan the LAN now" (no targets) or check these devices now. */
export function useRunDiscovery() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (targets?: string[]) => api.post<RunningJob>('/scanning/engines/nmap-discovery/run', targets?.length ? { targets } : {}),
    // the 202 run goes into the page at once, so the button shows it (and never "finished") before the next read
    onSuccess: (j) => {
      qc.setQueryData<Scanning>(['scanning'], (d) => (d && !d.running.some((r) => r.id === j.id) ? { ...d, running: [...d.running, j] } : d))
      return qc.invalidateQueries({ queryKey: ['scanning'] })
    },
  })
}
