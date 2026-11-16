import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CredTarget, ProbeEntry, RescanEvent, ScanConfig, ScanConfigResponse, ScanRun, ScanTarget } from './types'

export const isLive = (r: ScanRun) => r.status === 'running' || r.status === 'stopping'

export const useScanConfig = () => useQuery({ queryKey: ['scan', 'config'], queryFn: () => api.get<ScanConfigResponse>('/scans/config') })
export const useTargets = () => useQuery({ queryKey: ['scan', 'targets'], queryFn: () => api.get<{ items: ScanTarget[] }>('/scans/targets') })

/** How often the runs are read (#830): every 5 s while a scan runs or the engine is busy (the box reports a device's progress at most every 5 s),
 *  every second while one is stopping (spec §4: "Stop now" seen as stopped within 5 s), not at all otherwise. Tests shorten `runningMs`. */
export const runsPoll = { runningMs: 5000, stoppingMs: 1000 }
export function runsPollMs(d: { items: ScanRun[]; engine_busy: boolean } | undefined): number | false {
  if (d?.items.some((r) => r.status === 'stopping')) return runsPoll.stoppingMs
  return d?.items.some(isLive) || d?.engine_busy ? runsPoll.runningMs : false
}
export const useRuns = () =>
  useQuery({
    queryKey: ['scan', 'runs'],
    queryFn: () => api.get<{ items: ScanRun[]; engine_busy: boolean }>('/scans/runs'),
    refetchInterval: (q) => runsPollMs(q.state.data),
  })

export const useProbes = () => useQuery({ queryKey: ['scan', 'probes'], queryFn: () => api.get<{ items: ProbeEntry[]; retention_days: number }>('/scans/probes') })
export const useEvents = () => useQuery({ queryKey: ['scan', 'events'], queryFn: () => api.get<{ items: RescanEvent[]; auto_rescan: boolean }>('/scans/events') })
export const useCreds = () => useQuery({ queryKey: ['scan', 'creds'], queryFn: () => api.get<{ items: CredTarget[]; enabled: boolean }>('/scans/credentialed') })

function useScanMutation<V, R>(fn: (v: V) => Promise<R>, extra: string[] = []) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['scan'] })
      for (const k of extra) void qc.invalidateQueries({ queryKey: [k] })
    },
  })
}

export const useSaveConfig = () => useScanMutation((c: Partial<ScanConfig>) => api.put<ScanConfigResponse>('/scans/config', c))
export const useStartRun = () => useScanMutation((targets: string[]) => api.post<ScanRun>('/scans/runs', { targets }))
export const useStopRun = () => useScanMutation((id: string) => api.post<ScanRun>(`/scans/runs/${encodeURIComponent(id)}/stop`), ['findings'])
export const useAddCred = () => useScanMutation((v: { asset_id: string; port: number; username: string; private_key: string }) => api.post<CredTarget>('/scans/credentialed', v))
export const useDelCred = () => useScanMutation((id: string) => api.del<void>(`/scans/credentialed/${encodeURIComponent(id)}`))
export const useTestCred = () => useScanMutation((id: string) => api.post<CredTarget>(`/scans/credentialed/${encodeURIComponent(id)}/test`))
