import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Address, BoxIpDetectResult, BoxIpSettings, Greenbone, Host, Issue, OutsideView, Resolution, Scan, ScopeMode, Service, TargetKind, TargetNode, TargetTree } from './types'

const enc = encodeURIComponent

/** A run that still holds or waits for the exposure lane: the page reads it again until it ends. */
const LIVE: readonly Scan['status'][] = ['queued', 'waiting', 'running', 'stopping']
export const isLive = (s: Scan | null | undefined): boolean => !!s && LIVE.includes(s.status)

/** How often a page with a live scan asks again. Tests shorten it. */
export const scanPoll = { ms: 5000 }

/** Every target as a tree, with the box-IP settings, the Ignored list and the gateway. Read again while a scan of any target is live. */
export const useTree = () => useQuery({
  queryKey: ['exposure', 'tree'], queryFn: () => api.get<TargetTree>('/exposure/tree'),
  refetchInterval: (q) => (q.state.data?.items.some((n) => isLive(n.last_scan)) ? scanPoll.ms : false),
})
/** One target node; read again while its scan is live, so the page sees it start and end. */
export const useNode = (id: string) => useQuery({
  queryKey: ['exposure', 'node', id], queryFn: () => api.get<TargetNode>(`/exposure/tree/${enc(id)}`), retry: false,
  refetchInterval: (q) => (isLive(q.state.data?.last_scan) ? scanPoll.ms : false),
})

type Rows = { hosts: Host; addresses: Address; services: Service; issues: Issue; scans: Scan }
/** The rows of a node: names, addresses, services, issues or runs. `poll` reads them again while a scan is live (the runs list). */
export function useRows<K extends keyof Rows>(id: string, kind: K, o: { enabled?: boolean; poll?: boolean } = {}) {
  return useQuery({
    queryKey: ['exposure', 'rows', id, kind], queryFn: () => api.get<{ items: Rows[K][] }>(`/exposure/tree/${enc(id)}/${kind}`),
    enabled: o.enabled ?? true, refetchInterval: o.poll ? scanPoll.ms : false,
  })
}

function useInvalidate() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['exposure'] })
}

export function useAddNode() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: { value: string; kind: TargetKind; scope_mode?: ScopeMode }) => api.post<TargetNode>('/exposure/tree', b), onSuccess: inv })
}
export type NodeEdit = { scope_mode?: ScopeMode; enabled?: boolean; selected?: string[] }
export function useEditNode(id: string) {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: NodeEdit) => api.patch<TargetNode>(`/exposure/tree/${enc(id)}`, b), onSuccess: inv })
}
export function useDeleteNode() {
  const qc = useQueryClient()
  return useMutation({
    // ignore: an IP also goes on the Ignored list.
    mutationFn: ({ id, ignore }: { id: string; ignore?: boolean }) => api.del<void>(`/exposure/tree/${enc(id)}${ignore ? '?ignore=true' : ''}`),
    // Drop the deleted node's own queries without reading them again (that would be a 404 just before the page leaves), then the rest.
    onSuccess: (_d, { id }) => {
      qc.removeQueries({ predicate: (q) => q.queryKey[0] === 'exposure' && q.queryKey.includes(id) })
      return qc.invalidateQueries({ queryKey: ['exposure'] })
    },
  })
}
export function useVerifyNode() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (id: string) => api.post<{ verified: boolean; message: string; node: TargetNode }>(`/exposure/tree/${enc(id)}/verify`), onSuccess: inv })
}
/** Scan now. noticeVersion: the confirmation sentence shown next to the button, which an administrator's first scan records. */
export function useScanNode() {
  const inv = useInvalidate()
  // onError too: a refusal may come from a state the page must then show (proof gone, turned off).
  return useMutation({
    mutationFn: ({ id, noticeVersion }: { id: string; noticeVersion?: string }) => api.post<Scan>(`/exposure/tree/${enc(id)}/scan`, noticeVersion ? { notice_version: noticeVersion } : undefined),
    onSuccess: inv, onError: inv,
  })
}
/** Stop a scan through the shared runs: a queued one stops at once, a running one is stopping until its step ends. */
export function useStopRun() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (runId: string) => api.post<unknown>(`/runs/${enc(runId)}/stop`), onSuccess: inv, onError: inv })
}

/** Accept the testing terms of a node (admin with two-step), the disruptive checks included, or withdraw them. */
export function useAcceptTerms(id: string) {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: { version: string }) => api.put<TargetNode>(`/exposure/tree/${enc(id)}/terms`, b), onSuccess: inv })
}
export function useRevokeTerms(id: string) {
  const inv = useInvalidate()
  return useMutation({ mutationFn: () => api.del<TargetNode>(`/exposure/tree/${enc(id)}/terms`), onSuccess: inv })
}

export type HandleBody = { ids: string[]; resolution: Resolution; note: string; accepted_until?: string }
/** Handle open issues with one resolution and note; issues no longer open are skipped. */
export function useHandleIssues() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: HandleBody) => api.post<{ handled: number; skipped: number }>('/exposure/issues/handle', b), onSuccess: inv })
}
export function useReopenIssues() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (ids: string[]) => api.post<{ reopened: number; skipped: number }>('/exposure/issues/reopen', { ids }), onSuccess: inv })
}

/** Restore an IP from the Ignored list: detection may add it again. Nothing is added by this call. */
export function useRestoreIgnored() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (ip: string) => api.del<void>(`/exposure/box-ip/ignored/${enc(ip)}`), onSuccess: inv })
}
/** "Detect now": the box probes its own public IPs and adds or renews each one for 90 days. No IP is sent. */
export function useDetectBoxIp() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: () => api.post<BoxIpDetectResult>('/exposure/box-ip/verify'), onSuccess: inv, onError: inv })
}
/** Auto-detect on or off and the check interval (1 to 1440 minutes). */
export function useSaveBoxIpSettings() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (s: Pick<BoxIpSettings, 'auto' | 'interval_min'>) => api.put<BoxIpSettings>('/exposure/box-ip/settings', s), onSuccess: inv })
}

/** Shodan's last answer about this IP of the box (null before the first check). Reading sends nothing. */
export const useOutside = (id: string) => useQuery({ queryKey: ['exposure', 'outside', id], queryFn: () => api.get<OutsideView | null>(`/exposure/targets/${enc(id)}/outside`) })
/** Sends this IP of the box to Shodan InternetDB (admin). Only called after the person confirmed what is sent. */
export function useCheckOutside() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => api.post<OutsideView>(`/exposure/targets/${enc(id)}/outside`),
    onSuccess: (v, id) => { qc.setQueryData(['exposure', 'outside', id], v) },
    // a refusal may have found the IP not in use now, which the page must then show
    onError: () => qc.invalidateQueries({ queryKey: ['exposure', 'node'] }),
  })
}

/** The optional deep scan with Greenbone. Asks again every 30 s while it starts or loads its feed (1 to 3 hours the first time). */
export const useGreenbone = () => useQuery({
  queryKey: ['exposure', 'greenbone'], queryFn: () => api.get<Greenbone>('/exposure/greenbone'),
  refetchInterval: (q) => (q.state.data?.state === 'starting' || q.state.data?.state === 'loading' ? 30_000 : false) })
/** Turn Greenbone on (refused with the measured numbers below 6 GB of memory, under 8 GB without 2 GB of swap, or below 60 GB free) or off (admin). */
export function useSetGreenbone() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (enabled: boolean) => api.put<Greenbone>('/exposure/greenbone', { enabled }), onSuccess: inv, onError: inv })
}
