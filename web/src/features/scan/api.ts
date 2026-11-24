import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import i18n from 'i18next'
import { loadNamespaces } from '@/lib/i18n'
import { toast } from 'sonner'
import { api, ApiError } from '@/lib/api'
import type { CredTarget, ProbeEntry, RescanEvent, ScanConfig, ScanConfigResponse, ScanRun, ScanTarget } from './types'

export const isLive = (r: ScanRun) => r.status === 'running' || r.status === 'stopping'

export const useScanConfig = (enabled = true) => useQuery({ queryKey: ['scan', 'config'], queryFn: () => api.get<ScanConfigResponse>('/scans/config'), enabled })
export const useTargets = (enabled = true) => useQuery({ queryKey: ['scan', 'targets'], queryFn: () => api.get<{ items: ScanTarget[] }>('/scans/targets'), enabled })

/** How often the runs are read (#830): every 5 s while a scan runs or the engine is busy (the box reports a device's progress at most every 5 s),
 *  every second while one is stopping (spec §4: "Stop now" seen as stopped within 5 s), not at all otherwise. Tests shorten `runningMs`. */
export const runsPoll = { runningMs: 5000, stoppingMs: 1000 }
export function runsPollMs(d: { items: ScanRun[]; engine_busy: boolean } | undefined): number | false {
  if (d?.items.some((r) => r.status === 'stopping')) return runsPoll.stoppingMs
  return d?.items.some(isLive) || d?.engine_busy ? runsPoll.runningMs : false
}
export const useRuns = (enabled = true) =>
  useQuery({
    queryKey: ['scan', 'runs'], enabled,
    queryFn: () => api.get<{ items: ScanRun[]; engine_busy: boolean }>('/scans/runs'),
    refetchInterval: (q) => runsPollMs(q.state.data),
  })

/** GET /scans/runs?asset=: the runs of one device, however many runs of other devices came after. */
export const useDeviceRuns = (asset: string, enabled = true) =>
  useQuery({
    queryKey: ['scan', 'runs', asset], enabled,
    queryFn: () => api.get<{ items: ScanRun[]; engine_busy: boolean }>(`/scans/runs?asset=${encodeURIComponent(asset)}`),
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

/** PUT /scans/config with the version of the shared safety block the page read (review #860 r2 M2). On 409 safety_changed the
 *  settings are read again: the form is built again on the current values (SafetyTab keys it by version) and a toast says why. */
export function useSaveConfig() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (c: Partial<ScanConfig> & { version?: string }) => api.put<ScanConfigResponse>('/scans/config', c),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ['scan'] }),
    onError: async (e) => {
      if (e instanceof ApiError && e.code === 'safety_changed') {
        await loadNamespaces('scan') // the form may be on another feature's page: its words before the toast
        toast.error(i18n.t('scan:safety.changedElsewhere'))
        await qc.invalidateQueries({ queryKey: ['scan', 'config'] })
      }
    },
  })
}
export function useStartRun() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (targets: string[]) => api.post<ScanRun>('/scans/runs', { targets }),
    // the new run goes into the list at once, so a button never says "finished" before the next read
    onSuccess: (r) => {
      qc.setQueryData<{ items: ScanRun[]; engine_busy: boolean }>(['scan', 'runs'], (d) => (d ? { ...d, items: [r, ...d.items.filter((x) => x.id !== r.id)] } : d))
      void qc.invalidateQueries({ queryKey: ['scan'] })
      void qc.invalidateQueries({ queryKey: ['scanning'] })
    },
  })
}
export const useStopRun = () => useScanMutation((id: string) => api.post<ScanRun>(`/scans/runs/${encodeURIComponent(id)}/stop`), ['findings'])
export const useAddCred = () => useScanMutation((v: { asset_id: string; port: number; username: string; private_key: string }) => api.post<CredTarget>('/scans/credentialed', v))
export const useDelCred = () => useScanMutation((id: string) => api.del<void>(`/scans/credentialed/${encodeURIComponent(id)}`))
export const useTestCred = () => useScanMutation((id: string) => api.post<CredTarget>(`/scans/credentialed/${encodeURIComponent(id)}/test`))

