import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { ApplyItem, FindingDetail, FindingRow, StatusAction, VersionNeeded } from './types'

export const useFindings = (asset?: string) =>
  useQuery({ queryKey: ['findings', 'list', asset ?? null], queryFn: () => api.get<{ items: FindingRow[]; version_needed: VersionNeeded[] }>(asset ? `/findings?asset=${encodeURIComponent(asset)}` : '/findings') })

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
  useWrite<{ action: StatusAction; note: string }>(id, (v) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/status`, v))

export const useApplied = (id: string) =>
  useWrite<ApplyItem>(id, (item) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/applied`, { item }))

export const useAskAi = (id: string) =>
  useWrite<'explain' | 'mitigation-config'>(id, (skill) => api.post<FindingDetail>(`/findings/${encodeURIComponent(id)}/ai`, { skill }))
