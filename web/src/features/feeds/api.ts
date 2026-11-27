import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CveDetail, TierCve, Feed, FeedInput, FeedPatch, FeedStatus, ParseResult, Parser, FeedKind, HotRow, ReportWindow, SearchResult, WeeklyItem } from './types'

export const useFeedStatus = () => useQuery({ queryKey: ['feeds', 'status'], queryFn: () => api.get<FeedStatus>('/feeds/status') })

export const useHot = (window: '24h' | '7d') =>
  useQuery({ queryKey: ['feeds', 'hot', window], queryFn: () => api.get<{ window: string; rows: HotRow[]; latest: { cve: string; date_added: string; display: string } | null }>(`/feeds/hot?window=${window}`) })

export const useWeekly = () => useQuery({ queryKey: ['feeds', 'weekly'], queryFn: () => api.get<{ items: WeeklyItem[] }>('/feeds/weekly') })

export function useAnswerWeekly() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, answer }: { id: string; answer: 'have' | 'not_relevant' }) => api.post<{ items: WeeklyItem[] }>(`/feeds/weekly/${encodeURIComponent(id)}`, { answer }),
    // "I have this" adds a device, so Home's summary (device count, maybe a finding) is asked again too (#825).
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['feeds'] }); void qc.invalidateQueries({ queryKey: ['inventory'] }); void qc.invalidateQueries({ queryKey: ['findings', 'model', 'overview'] }) },
  })
}

export const CVE_ID = /^CVE-\d{4}-\d{4,}$/
export const useCve = (id: string) => useQuery({ queryKey: ['feeds', 'cve', id], queryFn: () => api.get<CveDetail>(`/feeds/cve/${encodeURIComponent(id)}`), retry: false, enabled: CVE_ID.test(id) })
/** S-TIER-1: a CVE on no exploited list, from the tier data; asked only when the brief names no exploited-list entry or the catalogue does not hold the CVE. */
export const useTierCve = (id: string, enabled: boolean) => useQuery({ queryKey: ['feeds', 'cve', id, 'tier'], queryFn: () => api.get<TierCve>(`/feeds/cve/${encodeURIComponent(id)}/tier`), retry: false, enabled: enabled && CVE_ID.test(id) })

export const useSearch = (q: string) =>
  useQuery({ queryKey: ['feeds', 'search', q], queryFn: () => api.get<SearchResult>(`/feeds/search?q=${encodeURIComponent(q)}`), enabled: q.trim().length > 0, retry: false })

// ---------- Feed sources and custom parsing (S-FEED-4, S-FEED-5)
export const useFeedSources = () => useQuery({ queryKey: ['feeds', 'sources'], queryFn: () => api.get<{ items: Feed[] }>('/feeds/sources') })

/** The host of a feed address, for the lists of where the box connects (INV-13, PRIVACY flow 1). Only the host: a path or query can hold a token. */
export function hostOf(url: string): string {
  try { return new URL(url).hostname } catch { return url }
}

function useDone() {
  const qc = useQueryClient()
  return () => { void qc.invalidateQueries({ queryKey: ['feeds', 'sources'] }) }
}
export function usePatchFeed() {
  const done = useDone()
  return useMutation({ mutationFn: ({ id, ...b }: FeedPatch & { id: string }) => api.put<Feed>(`/feeds/sources/${encodeURIComponent(id)}`, b), onSuccess: done })
}
export function useFetchFeed() {
  const done = useDone()
  return useMutation({ mutationFn: (id: string) => api.post<Feed>(`/feeds/sources/${encodeURIComponent(id)}/fetch`, {}), onSettled: done })
}
export function useSaveCustomFeed() {
  const done = useDone()
  return useMutation({ mutationFn: ({ id, ...b }: FeedInput & { id?: string }) => (id ? api.put<Feed>(`/feeds/custom/${encodeURIComponent(id)}`, b) : api.post<Feed>('/feeds/custom', b)), onSuccess: done })
}
export function useDeleteCustomFeed() {
  const done = useDone()
  return useMutation({ mutationFn: (id: string) => api.del<null>(`/feeds/custom/${encodeURIComponent(id)}`), onSuccess: done })
}
export const useParseTest = () => useMutation({ mutationFn: (b: { kind: FeedKind; parser: Parser; sample?: string }) => api.post<ParseResult>('/feeds/parse-test', b) })

// ---------- The reporting window (S-FEED-4): the last 12 months and older CVEs exploited in the wild, or every age
export const useReportWindow = () => useQuery({ queryKey: ['feeds', 'window'], queryFn: () => api.get<ReportWindow>('/feeds/window') })
export function useSetReportWindow() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (everyAge: boolean) => api.put<ReportWindow>('/feeds/window', { every_age: everyAge }),
    // findings close or open again at the next match, so the lists are asked again too
    onSuccess: (w) => { qc.setQueryData(['feeds', 'window'], w); void qc.invalidateQueries({ queryKey: ['findings'] }) },
  })
}
