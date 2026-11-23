import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type {
  ApplyItem, DeviceCards, FindingDetail, FindingRow, FixCards, HandledList, InputList, Overview, Plan, PlanFilter, Resolution, StatusAction, ToFix,
  UncheckedItem, VersionNeeded, View,
} from './types'

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

// ---- The findings model (contract.ts, "The findings model"): lists grouped on the server, handling, Home's overview.

/** A query string of the set values only, in a fixed order (one cache entry per list state). */
function qs(p: Record<string, string | number | undefined | null>): string {
  const q = new URLSearchParams()
  for (const [k, v] of Object.entries(p)) if (v !== undefined && v !== null && v !== '') q.set(k, String(v))
  const s = q.toString()
  return s ? `?${s}` : ''
}
/** A page of a server-paged list: offset and limit. */
export type Page = { offset: number; limit: number }
const model = (...k: unknown[]) => ['findings', 'model', ...k]

/** By device: one card per device, its fix blocks inside; `ignored` lists only the ignored devices. */
export const useDeviceCards = (f: { q?: string; status?: string; device?: string; ignored?: boolean }, page: Page, enabled = true) => {
  const path = `/findings/devices${qs({ q: f.q, status: f.status, device: f.device, ignored: f.ignored ? 'true' : undefined, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('devices', path), queryFn: () => api.get<DeviceCards>(path), enabled, placeholderData: keepPreviousData })
}
export const useFixCards = (f: { q?: string; status?: string }, page: Page, enabled = true) => {
  const path = `/findings/fixes${qs({ q: f.q, status: f.status, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('fixes', path), queryFn: () => api.get<FixCards>(path), enabled, placeholderData: keepPreviousData })
}
export const useInputList = (f: { device?: string }, page: Page, enabled = true) => {
  const path = `/findings/input${qs({ device: f.device, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('input', path), queryFn: () => api.get<InputList>(path), enabled, placeholderData: keepPreviousData })
}
export const useHandledList = (f: { q?: string; resolution?: string; device?: string; from?: string }, page: Page, enabled = true) => {
  const path = `/findings/handled${qs({ q: f.q, resolution: f.resolution, device: f.device, from: f.from, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('handled', path), queryFn: () => api.get<HandledList>(path), enabled, placeholderData: keepPreviousData })
}
export const useOverview = (enabled = true) =>
  useQuery({ queryKey: model('overview'), queryFn: () => api.get<Overview>('/findings/overview'), enabled })

/** Every finding read (lists, views, Home, the device page) is read again after a change. */
function useModelWrite<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['findings'] }); void qc.invalidateQueries({ queryKey: ['inventory'] }) } })
}
/** The handle request: findings of one device, by ids or by one of its fixes. */
export type HandleInput = ({ ids: string[] } | { device: string; fix: string }) & { resolution: Resolution; note: string; until?: string }
export const useHandle = () => useModelWrite((v: HandleInput) => api.post<{ handled: number; skipped: number }>('/findings/handle', v))
export const useReopen = () => useModelWrite((v: { id: string; note: string }) => api.post<View>(`/findings/${encodeURIComponent(v.id)}/reopen`, { note: v.note }))
export const useVerify = () => useModelWrite((v: { id: string; note: string }) => api.post<View>(`/findings/${encodeURIComponent(v.id)}/verify`, { note: v.note }))
export const useAnswer = () => useModelWrite((v: { id: string; answer: 'affected' | 'not_affected'; note: string }) =>
  api.post<{ finding: string | null }>(`/findings/questions/${encodeURIComponent(v.id)}/answer`, { answer: v.answer, note: v.note }))
