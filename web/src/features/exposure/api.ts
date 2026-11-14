import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { BoxIpDetectResult, BoxIpSettings, Diff, Greenbone, OutsideView, ScanRun, Snapshot, SnapshotMeta, Target, TargetList, VerifyResult } from './types'

export const useTargets = () => useQuery({ queryKey: ['exposure', 'targets'], queryFn: () => api.get<TargetList>('/exposure/targets') })
export const useTarget = (id: string) => useQuery({ queryKey: ['exposure', 'target', id], queryFn: () => api.get<Target>(`/exposure/targets/${encodeURIComponent(id)}`), retry: false })
export const useSnapshots = (id: string) => useQuery({ queryKey: ['exposure', 'snapshots', id], queryFn: () => api.get<{ items: SnapshotMeta[] }>(`/exposure/targets/${encodeURIComponent(id)}/snapshots`) })
export const useSnapshot = (id: string, date: string | null) =>
  useQuery({ queryKey: ['exposure', 'snapshot', id, date], queryFn: () => api.get<Snapshot>(`/exposure/targets/${encodeURIComponent(id)}/snapshots/${date}`), enabled: !!date })
export const useDiff = (id: string, from: string | null, to: string | null) =>
  useQuery({ queryKey: ['exposure', 'diff', id, from, to], queryFn: () => api.get<Diff>(`/exposure/targets/${encodeURIComponent(id)}/diff?from=${from}&to=${to}`), enabled: !!from && !!to && from !== to, retry: false })

/** How often the page asks how the scan is going while one runs. */
export const SCAN_POLL_MS = 2000
/** The scan that runs now, or the last one (null before the first since the box started). Polls only while it runs. */
export const useScanRun = () => useQuery({
  queryKey: ['exposure', 'scan'], queryFn: () => api.get<ScanRun | null>('/exposure/scan'),
  // a failed poll slows down but does not stop while the last answer says running, so the row cannot hang on "Scanning"
  refetchInterval: (q) => (q.state.data?.status === 'running' ? (q.state.status === 'error' ? SCAN_POLL_MS * 5 : SCAN_POLL_MS) : false) })

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
    // ignore: an IP also goes on the Ignored list (D-79).
    mutationFn: ({ id, ignore }: { id: string; ignore?: boolean }) => api.del<void>(`/exposure/targets/${encodeURIComponent(id)}${ignore ? '?ignore=true' : ''}`),
    // Bỏ cache của mục tiêu vừa xoá (không tải lại: tải lại sẽ ra 404 ngay trước khi chuyển trang), chỉ làm mới danh sách.
    onSuccess: (_d, { id }) => {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] === 'exposure' && q.queryKey[1] !== 'targets' && q.queryKey.includes(id) })
      return qc.invalidateQueries({ queryKey: ['exposure', 'targets'] })
    },
  })
}
/** Restore an IP from the Ignored list: detection may add it again. Nothing is added by this call. */
export function useRestoreIgnored() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (ip: string) => api.del<void>(`/exposure/box-ip/ignored/${encodeURIComponent(ip)}`), onSuccess: inv })
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
/** Auto-detect on or off and the check interval (1 to 1440 minutes). */
export function useSaveBoxIpSettings() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (s: Pick<BoxIpSettings, 'auto' | 'interval_min'>) => api.put<BoxIpSettings>('/exposure/box-ip/settings', s), onSuccess: inv })
}
export function useScan() {
  const qc = useQueryClient()
  const inv = useInvalidate()
  // onError too: a refused scan may have found the IP paused, and the page must then show it (the answer is a state of the target).
  return useMutation({ // noticeVersion: the version of the sentence shown next to the button; the server records it with the first scan of a target (D-473).
    mutationFn: ({ id, noticeVersion }: { id: string; noticeVersion?: string }) => api.post<ScanRun>(`/exposure/targets/${encodeURIComponent(id)}/scan`, noticeVersion ? { notice_version: noticeVersion } : undefined),
    // the 202 run goes into the cache at once, so a run that ends before the first poll still ends a "running" the page has seen
    onSuccess: (run) => { qc.setQueryData(['exposure', 'scan'], run); return inv() }, onError: inv })
}
/** Stop the scan that runs now (operator). */
export function useStopScan() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: () => api.post<ScanRun>('/exposure/scan/stop'), onSuccess: inv, onError: inv })
}

/** D-558: Shodan's last answer about this IP of the box (null before the first check). Reading sends nothing. */
export const useOutside = (id: string) => useQuery({ queryKey: ['exposure', 'outside', id], queryFn: () => api.get<OutsideView | null>(`/exposure/targets/${encodeURIComponent(id)}/outside`) })
/** Sends this IP of the box to Shodan InternetDB (admin). Only called after the person confirmed what is sent. */
export function useCheckOutside() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post<OutsideView>(`/exposure/targets/${encodeURIComponent(id)}/outside`),
    onSuccess: (v, id) => { qc.setQueryData(['exposure', 'outside', id], v) },
    // a refusal may have found the IP paused (INV-13), which the page must then show
    onError: () => qc.invalidateQueries({ queryKey: ['exposure', 'target'] }),
  })
}

/** D-563: the optional deep scan with Greenbone. Asks again every 30 s while it starts or loads its feed (about 2 hours the first time). */
export const useGreenbone = () => useQuery({
  queryKey: ['exposure', 'greenbone'], queryFn: () => api.get<Greenbone>('/exposure/greenbone'),
  refetchInterval: (q) => (q.state.data?.state === 'starting' || q.state.data?.state === 'loading' ? 30_000 : false) })
/** Turn Greenbone on (refused with the measured numbers below 8 GB of memory or 60 GB free) or off (admin). */
export function useSetGreenbone() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (enabled: boolean) => api.put<Greenbone>('/exposure/greenbone', { enabled }), onSuccess: inv, onError: inv })
}

/** FULL-1 (D-566): accept the testing terms of a target (admin with two-step), with or without the disruptive tick, or withdraw them. */
export function useAcceptTerms(id: string) {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: { version: string; disruptive: boolean }) => api.put<Target>(`/exposure/targets/${encodeURIComponent(id)}/terms`, b), onSuccess: inv })
}
export function useRevokeTerms(id: string) {
  const inv = useInvalidate()
  return useMutation({ mutationFn: () => api.del<Target>(`/exposure/targets/${encodeURIComponent(id)}/terms`), onSuccess: inv })
}
