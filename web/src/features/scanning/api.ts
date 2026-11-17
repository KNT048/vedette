import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import type { EngineId, HistoryRun, RunningJob, SafetyInput, SafetySaved, Scanning } from './types'
import type { z } from 'zod'
import type { RangeAdd } from './contract'

/** GET /scanning: the page, the engines, the shared safety block and the runs going on (served by core, so it answers while every
 *  engine's module is off). Read every 5 s while a run goes on (its progress), every 30 s otherwise so the top-bar indicator sees a
 *  run another page or a schedule started; never in a hidden tab (TanStack's default). Tests shorten it. */
export const scanningPoll = { runningMs: 5000, idleMs: 30_000 }
export const useScanning = (enabled = true) => useQuery({
  queryKey: ['scanning'], queryFn: () => api.get<Scanning>('/scanning'), enabled,
  refetchInterval: (q) => (q.state.data?.running.length ? scanningPoll.runningMs : scanningPoll.idleMs),
})

/** GET /scanning/history (kien G7a): the LAN runs and public scans with their outcome; every 30 s while the tab is open. With an
 *  asset (kien G7b/c), only the runs that reached that device: its checks and the SNMP reads that asked it. */
export const useScanningHistory = (asset?: string | null) => useQuery({
  queryKey: asset ? ['scanning', 'history', asset] : ['scanning', 'history'],
  queryFn: () => api.get<{ items: HistoryRun[] }>(asset ? `/scanning/history?asset=${encodeURIComponent(asset)}` : '/scanning/history'),
  refetchInterval: 30_000,
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
    // b.version is the block the form was built on (#860): another one stored is 409 safety_changed, nothing stored; the page reads again
    mutationFn: (b: SafetyInput) => api.put<SafetySaved>('/scanning/safety', b),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['scanning'] }); refresh() },
    onError: (e) => { if (e instanceof ApiError && e.code === 'safety_changed') void qc.invalidateQueries({ queryKey: ['scanning'] }) },
  })
}

/** POST /scanning/safety/ranges (#860): one range added, or the shown ranges confirmed, in one transaction on the server, never a
 *  read-modify-write of the block. The tick confirms exactly what the dialog showed (shown_ranges, shown_confirmed_at): another
 *  admin's change since is 409 scope_changed and nothing is stored; the page reads the block again. */
export function useAddRange() {
  const qc = useQueryClient()
  const refresh = useRefresh()
  return useMutation({
    mutationFn: (b: z.infer<typeof RangeAdd>) => api.post<SafetySaved>('/scanning/safety/ranges', b),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['scanning'] }); refresh() },
    onError: (e) => { if (e instanceof ApiError && e.code === 'scope_changed') void qc.invalidateQueries({ queryKey: ['scanning'] }) },
  })
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
