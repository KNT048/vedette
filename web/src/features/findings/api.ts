import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ApplyItem, BulkAction, FindingDetail, FindingRow, Plan, PlanDone, PlanFilter, StatusAction, ToFix, UncheckedItem, VersionNeeded } from './types'

export const useFindings = (asset?: string, enabled = true) =>
  useQuery({ queryKey: ['findings', 'list', asset ?? null], enabled, queryFn: () => api.get<{ items: FindingRow[]; version_needed: VersionNeeded[]; unchecked: UncheckedItem[] }>(asset ? `/findings?asset=${encodeURIComponent(asset)}` : '/findings') })

/** GET /findings/to-fix: what each device needs, the most urgent first; one device with `asset` (its Software tab). */
export const useToFix = (asset?: string, enabled = true) =>
  useQuery({ queryKey: ['findings', 'to-fix', asset ?? null], enabled, queryFn: () => api.get<ToFix>(asset ? `/findings/to-fix?asset=${encodeURIComponent(asset)}` : '/findings/to-fix') })

/** Updates to plan: tier 2 and 3 CVEs grouped by update; all devices or one. */
export const usePlan = (tier: PlanFilter = 'all', asset?: string, enabled = true, done = false) => {
  const q = new URLSearchParams()
  if (tier !== 'all') q.set('tier', tier)
  if (asset) q.set('asset', asset)
  if (done) q.set('done', 'true')
  const qs = q.toString()
  return useQuery({ queryKey: ['findings', 'plan', tier, asset ?? null, done], queryFn: () => api.get<Plan>(`/findings/plan${qs ? `?${qs}` : ''}`), enabled })
}

/** A person marks a recommended update done, or puts it back: the plan, To fix and the risk markers read again. */
export function usePlanDone() {
  const qc = useQueryClient()
  const refresh = () => { void qc.invalidateQueries({ queryKey: ['findings'] }) }
  return {
    mark: useMutation({ mutationFn: (v: { group: string; note: string }) => api.post<PlanDone>('/findings/plan/done', v), onSuccess: refresh }),
    undo: useMutation({ mutationFn: (group: string) => api.post<{ group: string }>('/findings/plan/undone', { group }), onSuccess: refresh }),
  }
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
      void qc.invalidateQueries({ queryKey: ['findings', 'summary'] })
      void qc.invalidateQueries({ queryKey: ['findings', 'to-fix'] })
    },
  })
}

export const useSetStatus = (id: string) =>
  useWrite<{ action: StatusAction; note: string; until?: string }>(id, (v) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/status`, v))

/** An admin confirms a suspected finding with a note; Undo returns it to suspected. */
export const useConfirmFinding = (id: string) =>
  useWrite<{ note: string }>(id, (v) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/confirm`, v))
export const useUnconfirmFinding = (id: string) =>
  useWrite<void>(id, () => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/unconfirm`, {}))

export const useApplied = (id: string) =>
  useWrite<ApplyItem>(id, (item) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/applied`, { item }))

export const useAskAi = (id: string) =>
  useWrite<'explain' | 'mitigation-config'>(id, (skill) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/ai`, { skill }))

/** Một hành động, một ghi chú cho nhiều phát hiện (INV-10): tất cả hoặc không gì. */
export function useBulkStatus() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { ids: string[]; action: BulkAction; note: string; until?: string }) => api.post<{ updated: number; skipped: number }>('/findings/status', v),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['findings'] }) },
  })
}
