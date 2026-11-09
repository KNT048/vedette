import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { BoxIpDetectResult, BoxIpSettings, Diff, Snapshot, SnapshotMeta, Target, TargetList, VerifyResult } from './types'

export const useTargets = () => useQuery({ queryKey: ['exposure', 'targets'], queryFn: () => api.get<TargetList>('/exposure/targets') })
export const useTarget = (id: string) => useQuery({ queryKey: ['exposure', 'target', id], queryFn: () => api.get<Target>(`/exposure/targets/${encodeURIComponent(id)}`), retry: false })
export const useSnapshots = (id: string) => useQuery({ queryKey: ['exposure', 'snapshots', id], queryFn: () => api.get<{ items: SnapshotMeta[] }>(`/exposure/targets/${encodeURIComponent(id)}/snapshots`) })
export const useSnapshot = (id: string, date: string | null) =>
  useQuery({ queryKey: ['exposure', 'snapshot', id, date], queryFn: () => api.get<Snapshot>(`/exposure/targets/${encodeURIComponent(id)}/snapshots/${date}`), enabled: !!date })
export const useDiff = (id: string, from: string | null, to: string | null) =>
  useQuery({ queryKey: ['exposure', 'diff', id, from, to], queryFn: () => api.get<Diff>(`/exposure/targets/${encodeURIComponent(id)}/diff?from=${from}&to=${to}`), enabled: !!from && !!to && from !== to, retry: false })

function useInvalidate() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['exposure'] })
}

export function useAddTarget() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (value: string) => api.post<Target>('/exposure/targets', { value }), onSuccess: inv })
}
export function useDeleteTarget() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/exposure/targets/${encodeURIComponent(id)}`),
    // Bỏ cache của mục tiêu vừa xoá (không tải lại: tải lại sẽ ra 404 ngay trước khi chuyển trang), chỉ làm mới danh sách.
    onSuccess: (_d, id) => {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] === 'exposure' && q.queryKey[1] !== 'targets' && q.queryKey.includes(id) })
      return qc.invalidateQueries({ queryKey: ['exposure', 'targets'] })
    },
  })
}
export function useVerify() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (id: string) => api.post<VerifyResult>(`/exposure/targets/${encodeURIComponent(id)}/verify`), onSuccess: inv })
}
/** "Detect now": the box probes its own public IPs and adds or renews each one for 30 days. No IP is sent. */
export function useDetectBoxIp() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: () => api.post<BoxIpDetectResult>('/exposure/box-ip/verify'), onSuccess: inv, onError: inv })
}
/** Auto-detect on or off and the check interval (15 to 1440 minutes). */
export function useSaveBoxIpSettings() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (s: Pick<BoxIpSettings, 'auto' | 'interval_min'>) => api.put<BoxIpSettings>('/exposure/box-ip/settings', s), onSuccess: inv })
}
export function useCommit() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (id: string) => api.post<Target>(`/exposure/targets/${encodeURIComponent(id)}/commitment`, { confirm: true }), onSuccess: inv })
}
export function useScan() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (id: string) => api.post<Snapshot>(`/exposure/targets/${encodeURIComponent(id)}/scan`), onSuccess: inv })
}
