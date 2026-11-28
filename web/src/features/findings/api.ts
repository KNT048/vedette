import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { PAGE_MAX } from './contract'
import type { AnsweredList, ApplyItem, Coverage, DeviceCards, FindingDetail, FindingRow, FixCards, HandledList, Overview, PossibleCheckRun, PossibleCheckState, PossibleList, Resolution, ReviewConfirmed, ReviewList, View } from './types'

/** GET /findings?asset=: one device's findings in every state, each with its history (what a version entry, "I updated it" or
 *  "Not installed" changed). */
export const useFindings = (asset: string, enabled = true) =>
  useQuery({ queryKey: ['findings', 'list', asset], enabled, queryFn: () => api.get<{ items: FindingRow[] }>(`/findings?asset=${encodeURIComponent(asset)}`) })

export const useFinding = (id: string) =>
  useQuery({ queryKey: ['findings', 'detail', id], queryFn: () => api.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`), retry: false })

/** Mitigation's writes on the finding page answer with the new detail; the lists that read the finding are read again. */
function useWrite<V>(id: string, fn: (v: V) => Promise<FindingDetail>) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (d) => {
      qc.setQueryData(['findings', 'detail', id], d)
      void qc.invalidateQueries({ queryKey: ['findings', 'list'] })
      void qc.invalidateQueries({ queryKey: ['findings', 'model'] })
    },
  })
}

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

/** By device: one card per device, its fix blocks inside; `ignored` lists only the ignored devices; `cve` keeps only that CVE's
 *  findings; `devices` (comma-separated, at most PAGE_MAX) only those devices. */
type DeviceFilter = { q?: string; status?: string; device?: string; devices?: string; cve?: string; ignored?: boolean }
const devicesPath = (f: DeviceFilter, page: Page) =>
  `/findings/devices${qs({ q: f.q, status: f.status, device: f.device, devices: f.devices, cve: f.cve, ignored: f.ignored ? 'true' : undefined, offset: page.offset, limit: page.limit })}`
export const useDeviceCards = (f: DeviceFilter, page: Page, enabled = true) => {
  const path = devicesPath(f, page)
  return useQuery({ queryKey: model('devices', path), queryFn: () => api.get<DeviceCards>(path), enabled, placeholderData: keepPreviousData })
}
/** Every page of a paged list in one answer: the first page gives the total, the other pages are read after it. */
async function allPages<T extends { items: unknown[]; total: number }>(pathOf: (page: Page) => string): Promise<T> {
  const first = await api.get<T>(pathOf({ offset: 0, limit: PAGE_MAX }))
  const items = [...first.items]
  for (let offset = PAGE_MAX; offset < first.total; offset += PAGE_MAX) items.push(...(await api.get<T>(pathOf({ offset, limit: PAGE_MAX }))).items)
  return { ...first, items }
}
/** Open findings per device for these devices, however many: By device filtered by device ids, PAGE_MAX ids a request. */
export const useOpenFindingsOf = (ids: readonly string[], enabled = true) => {
  const sorted = [...new Set(ids)].sort()
  return useQuery({
    queryKey: model('devices', 'open-of', sorted.join(',')),
    enabled: enabled && sorted.length > 0,
    queryFn: async () => {
      const out = new Map<string, number>()
      for (let i = 0; i < sorted.length; i += PAGE_MAX) {
        const page = await api.get<DeviceCards>(devicesPath({ devices: sorted.slice(i, i + PAGE_MAX).join(',') }, { offset: 0, limit: PAGE_MAX }))
        for (const c of page.items) out.set(c.device.id, c.findings)
      }
      return out
    },
  })
}
export const useFixCards = (f: { q?: string; status?: string }, page: Page, enabled = true) => {
  const path = `/findings/fixes${qs({ q: f.q, status: f.status, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('fixes', path), queryFn: () => api.get<FixCards>(path), enabled, placeholderData: keepPreviousData })
}
/** The questions answered "not affected": each can be asked again (useUnanswer). */
export const useAnswered = (f: { device?: string }, page: Page, enabled = true) => {
  const path = `/findings/answered${qs({ device: f.device, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('answered', path), queryFn: () => api.get<AnsweredList>(path), enabled, placeholderData: keepPreviousData })
}
export const useHandledList = (f: { q?: string; resolution?: string; device?: string; from?: string; corrections?: boolean }, page: Page, enabled = true) => {
  const path = `/findings/handled${qs({ q: f.q, resolution: f.resolution, device: f.device, from: f.from, corrections: f.corrections ? 'true' : undefined, offset: page.offset, limit: page.limit })}`
  return useQuery({ queryKey: model('handled', path), queryFn: () => api.get<HandledList>(path), enabled, placeholderData: keepPreviousData })
}
/** The open findings of one CVE on every device, each with its device and the fix block it is in: By device filtered by the CVE,
 *  every page. */
export const useCveFindings = (cve: string, enabled = true) => {
  const q = useQuery({ queryKey: model('devices', 'cve', cve), enabled, queryFn: () => allPages<DeviceCards>((p) => devicesPath({ cve }, p)) })
  const hits = q.data?.items.flatMap((card) => card.blocks.flatMap((block) => block.findings.map((finding) => ({ device: card.device, block, finding })))) ?? []
  return { query: q, hits }
}
/** How many open findings one CVE has on all devices (By device filtered by the CVE: its total, one small request). */
export const useCveOpenCount = (cve: string, enabled = true): number | undefined =>
  useDeviceCards({ cve }, { offset: 0, limit: 1 }, enabled).data?.findings
export const useOverview = (enabled = true) =>
  useQuery({ queryKey: model('overview'), queryFn: () => api.get<Overview>('/findings/overview'), enabled })

/** Every finding read (lists, views, Home, the device page) is read again after a change. */
function useModelWrite<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['findings'] }); void qc.invalidateQueries({ queryKey: ['inventory'] }) } })
}
/** The handle request: findings of one device, by ids or by one of its fixes. */
export type HandleInput = ({ ids: string[] } | { device: string; fix: string; software?: string }) & { resolution: Resolution; note: string; until?: string; confirm?: boolean }
export const useHandle = () => useModelWrite((v: HandleInput) => api.post<{ handled: number; skipped: number }>('/findings/handle', v))
export const useReopen = () => useModelWrite((v: { id: string; note: string }) => api.post<View>(`/findings/${encodeURIComponent(v.id)}/reopen`, { note: v.note }))
export const useVerify = () => useModelWrite((v: { id: string; note: string }) => api.post<View>(`/findings/${encodeURIComponent(v.id)}/verify`, { note: v.note }))
export const useUnverify = () => useModelWrite((v: { id: string }) => api.post<View>(`/findings/${encodeURIComponent(v.id)}/unverify`, {}))
export const useAnswer = () => useModelWrite((v: { id: string; answer: 'affected' | 'not_affected'; note: string }) =>
  api.post<{ finding: string | null }>(`/findings/questions/${encodeURIComponent(v.id)}/answer`, { answer: v.answer, note: v.note }))
/** Ignore (bypass): every open question of a device, or of one software line of it, answered "not affected" at once. */
export const useIgnoreQuestions = () => useModelWrite((v: { device: string; software?: string; note: string }) =>
  api.post<{ answered: number }>('/findings/questions/ignore', v))
/** Accept the risk of a device, a software line of it or one question of that line, until a day (the findings open again after it). */
export const useAcceptRiskQuestions = () => useModelWrite((v: { device: string; software?: string; question?: string; note: string; until: string }) =>
  api.post<{ questions: number; findings: number }>('/findings/questions/accept-risk', v))
export const useUnanswer = () => useModelWrite((v: { id: string }) => api.post<{ id: string }>(`/findings/questions/${encodeURIComponent(v.id)}/unanswer`, {}))
/** A view of one finding: its status, the reasons of its urgency and how it is known, as every list row says them. */
export const useView = (id: string, enabled = true) =>
  useQuery({ queryKey: model('view', id), queryFn: () => api.get<View>(`/findings/${encodeURIComponent(id)}/view`), enabled, retry: false })

// ---- Possible findings: the CVEs Vedette cannot decide, counted apart from the open findings (GET /findings/possible).

/** Every possible CVE (of one device when `device` is set) in one answer, every page; `state` one state (settled is only read
 *  when asked for). */
export const useAllPossible = (f: { device?: string; state?: 'possible' | 'proposal' | 'settled' }, enabled = true) =>
  useQuery({
    queryKey: model('possible', 'all', f.device ?? '', f.state ?? ''), enabled,
    queryFn: () => allPages<PossibleList>((p) => `/findings/possible${qs({ device: f.device, state: f.state, offset: p.offset, limit: p.limit })}`),
  })
/** The possible counts of one device (or of every device) only: one small request. */
export const usePossibleCounts = (device: string | undefined, enabled = true) =>
  useQuery({ queryKey: model('possible', 'counts', device ?? ''), enabled, queryFn: () => api.get<PossibleList>(`/findings/possible${qs({ device, limit: 1 })}`), select: (d) => d.counts })
/** Whether a check can run and how the last one stands; read again every 2 s while one runs. */
export const usePossibleCheck = (enabled = true) =>
  useQuery({
    queryKey: ['findings', 'possible-check'], enabled, queryFn: () => api.get<PossibleCheckState>('/findings/possible/check'),
    refetchInterval: (q) => (q.state.data?.run?.running ? 2000 : false),
  })
export const useStartPossibleCheck = () => {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (v: { device?: string }) => api.post<PossibleCheckRun>('/findings/possible/check', v.device ? { device: v.device } : {}),
    onSuccess: (run) => { qc.setQueryData<PossibleCheckState>(['findings', 'possible-check'], (s) => (s ? { ...s, run } : s)) },
    onSettled: () => { void qc.invalidateQueries({ queryKey: ['findings', 'possible-check'] }) },
  })
}
export const useConfirmProposal = () => useModelWrite((v: { id: string }) => api.post<{ finding: string | null }>(`/findings/possible/${encodeURIComponent(v.id)}/confirm`, {}))
export const useConfirmProposals = () => useModelWrite((v: { verdict: 'affected' | 'not_affected'; confidence: 'confident' | 'likely'; device?: string }) =>
  api.post<{ confirmed: number }>('/findings/possible/confirm', v))
export const useRejectProposal = () => useModelWrite((v: { key: string }) => api.post<{ ok: true }>(`/findings/possible/checks/${encodeURIComponent(v.key)}/reject`, {}))
/** Not this product: the AI's identification of a finding's software was wrong (every device with the software, audited). */
export const useRejectIdentity = () => useModelWrite((v: { id: string }) => api.post<{ ok: true }>(`/findings/${encodeURIComponent(v.id)}/identity/reject`, {}))

// ---- Review AI answers: the AI's "not affected" answers, which close nothing until a person confirms them.

/** Every AI "not affected" answer waiting for a person, every page (the screen filters them in place, so its filters list every
 *  device and software line that has one). */
export const useReview = (enabled = true) =>
  useQuery({
    queryKey: model('review', 'all'), enabled,
    queryFn: () => allPages<ReviewList>((p) => `/findings/review${qs({ offset: p.offset, limit: p.limit })}`),
  })
/** How many AI answers wait for review (one small request): the count Not decided leaves out and Review AI answers lists. */
export const useReviewTotal = (enabled = true) =>
  useQuery({ queryKey: model('review', 'total'), enabled, queryFn: () => api.get<ReviewList>('/findings/review?limit=1'), select: (d) => d.total })
/** Confirm AI answers at once: an exploited CVE is confirmed only when `include_exploited` names it. */
export const useConfirmReview = () => useModelWrite((v: { ids: string[]; include_exploited?: string[] }) => api.post<ReviewConfirmed>('/findings/review/confirm', v))
/** Research deeper: the AI researches the release line of one possible CVE again now with its strong profile. */
export const useResearchDeeper = () => useModelWrite((v: { id: string }) => api.post<PossibleCheckRun>(`/findings/possible/${encodeURIComponent(v.id)}/research`, {}))

/** GET /findings/coverage (admin): the decision coverage of the last match pass (Settings → Diagnostics). */
export const useCoverage = (enabled = true) => useQuery({ queryKey: ['findings', 'coverage'], enabled, queryFn: () => api.get<Coverage>('/findings/coverage') })
