import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import type { EngineId, HistoryRun, Run, RunDetail, RunList, RunStatus, RunningJob, SafetyInput, SafetySaved, Scanning, ScopeCost, ScopeCostInput } from './types'
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

/** GET /scanning/history: the LAN runs and public scans with their outcome; every 30 s while the tab is open. With an
 *  asset, only the runs that reached that device: its checks and the SNMP reads that asked it. */
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

/** POST /scanning/safety/estimate: what one pass over the scope as typed would cost, before it is saved (the box's numbers; keyed by
 *  the values, so the card follows the form; the last answer stays while the next is read). */
export const useScopeCost = (b: ScopeCostInput, enabled = true) => useQuery({
  queryKey: ['scanning', 'estimate', b], queryFn: () => api.post<ScopeCost>('/scanning/safety/estimate', b), enabled, placeholderData: keepPreviousData, staleTime: 60_000,
})

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

/** A run that holds its lane now (its progress moves) and one that waits for it (queued, or waiting for a window or another run). */
export const runMoves = (s: RunStatus) => s === 'running' || s === 'stopping'
export const runWaits = (s: RunStatus) => s === 'queued' || s === 'waiting'

/** How often a list or a run is read again: every 5 s while one moves, every 30 s while one waits, otherwise not. Tests shorten it. */
export const runsPoll = { movingMs: 5000, waitingMs: 30_000 }
const pollFor = (statuses: RunStatus[]): number | false =>
  statuses.some(runMoves) ? runsPoll.movingMs : statuses.some(runWaits) ? runsPoll.waitingMs : false

/** The filters of the Runs list (the query of GET /runs); empty strings ask for every value. */
export type RunQuery = { q: string; kind: string; status: string; device: string; offset: number; limit: number }

export function runsUrl(p: RunQuery): string {
  const qs = new URLSearchParams()
  if (p.q) qs.set('q', p.q)
  if (p.kind) qs.set('kind', p.kind)
  if (p.status) qs.set('status', p.status)
  if (p.device) { qs.set('subject_kind', 'device'); qs.set('subject_id', p.device) }
  if (p.offset) qs.set('offset', String(p.offset))
  qs.set('limit', String(p.limit))
  return `/runs?${qs}`
}

/** GET /runs: one page of every run of every engine, newest first. The page stays while the next one loads (lists keep their page),
 *  and it is read again every 30 s (every 5 s while a run on it moves). */
export const useRunList = (p: RunQuery, enabled = true) => useQuery({
  queryKey: ['scanning', 'runs', p], queryFn: () => api.get<RunList>(runsUrl(p)), placeholderData: keepPreviousData, enabled,
  refetchInterval: (q) => (q.state.data?.items.some((r) => runMoves(r.status)) ? runsPoll.movingMs : runsPoll.waitingMs),
})

/** GET /runs/{id}: one run with its steps, devices, log tail and the runs under it; read again while it moves or waits. */
export const useRun = (id: string) => useQuery({
  queryKey: ['scanning', 'run', id], queryFn: () => api.get<RunDetail>(`/runs/${encodeURIComponent(id)}`), retry: false,
  refetchInterval: (q) => (q.state.data ? pollFor([q.state.data.status, ...q.state.data.children.map((c) => c.status)]) : false),
})

/** POST /runs/{id}/stop or /resume: the answer is the run as it is now; every run read (the list, the page, GET /scanning) reads again. */
export function useRunAction() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { id: string; action: 'stop' | 'resume' }) => api.post<Run>(`/runs/${encodeURIComponent(v.id)}/${v.action}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanning'] }),
  })
}
