import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ApplyItem, BulkAction, FindingDetail, FindingRow, Plan, PlanFilter, StatusAction, VersionNeeded } from './types'

export const useFindings = (asset?: string) =>
  useQuery({ queryKey: ['findings', 'list', asset ?? null], queryFn: () => api.get<{ items: FindingRow[]; version_needed: VersionNeeded[] }>(asset ? `/findings?asset=${encodeURIComponent(asset)}` : '/findings') })

/** Updates to plan (D-613): tier 2 and 3 CVEs grouped by update; all devices or one. */
export const usePlan = (tier: PlanFilter = 'all', asset?: string, enabled = true) => {
  const q = new URLSearchParams()
  if (tier !== 'all') q.set('tier', tier)
  if (asset) q.set('asset', asset)
  const qs = q.toString()
  return useQuery({ queryKey: ['findings', 'plan', tier, asset ?? null], queryFn: () => api.get<Plan>(`/findings/plan${qs ? `?${qs}` : ''}`), enabled })
}

export const useFinding = (id: string) =>
  useQuery({ queryKey: ['findings', 'detail', id], queryFn: () => api.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`), retry: false })

/** Mọi thay đổi trả về chi tiết mới; làm mới cả danh sách (và trang thiết bị/CVE đọc chung). */
function useWrite<V>(id: string, fn: (v: V) => Promise<FindingDetail>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (d) => {
      qc.setQueryData(['findings', 'detail', id], d)
      void qc.invalidateQueries({ queryKey: ['findings', 'list'] })
    },
  })
}

export const useSetStatus = (id: string) =>
  useWrite<{ action: StatusAction; note: string; until?: string }>(id, (v) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/status`, v))

export const useApplied = (id: string) =>
  useWrite<ApplyItem>(id, (item) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/applied`, { item }))

export const useAskAi = (id: string) =>
  useWrite<'explain' | 'mitigation-config'>(id, (skill) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/ai`, { skill }))

/** Một hành động, một ghi chú cho nhiều phát hiện (W1-12, INV-10): tất cả hoặc không gì. */
export function useBulkStatus() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { ids: string[]; action: BulkAction; note: string; until?: string }) => api.post<{ updated: number; skipped: number }>('/findings/status', v),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['findings'] }) },
  })
}
