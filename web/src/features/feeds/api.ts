import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CveDetail, Feed, FeedInput, FeedPatch, FeedStatus, ParseResult, Parser, FeedKind, HotRow, SearchResult, WeeklyItem } from './types'

export const useFeedStatus = () => useQuery({ queryKey: ['feeds', 'status'], queryFn: () => api.get<FeedStatus>('/feeds/status') })

export const useHot = (window: '24h' | '7d') =>
  useQuery({ queryKey: ['feeds', 'hot', window], queryFn: () => api.get<{ window: string; rows: HotRow[]; latest: { cve: string; date_added: string; display: string } | null }>(`/feeds/hot?window=${window}`) })

export const useWeekly = () => useQuery({ queryKey: ['feeds', 'weekly'], queryFn: () => api.get<{ items: WeeklyItem[] }>('/feeds/weekly') })

export function useAnswerWeekly() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, answer }: { id: string; answer: 'have' | 'not_relevant' }) => api.post<{ items: WeeklyItem[] }>(`/feeds/weekly/${encodeURIComponent(id)}`, { answer }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['feeds'] }); void qc.invalidateQueries({ queryKey: ['inventory'] }) },
  })
}

export const useCve = (id: string) => useQuery({ queryKey: ['feeds', 'cve', id], queryFn: () => api.get<CveDetail>(`/feeds/cve/${encodeURIComponent(id)}`), retry: false })

export const useSearch = (q: string) =>
  useQuery({ queryKey: ['feeds', 'search', q], queryFn: () => api.get<SearchResult>(`/feeds/search?q=${encodeURIComponent(q)}`), enabled: q.trim().length > 0, retry: false })

// ---------- Feed sources and custom parsing (S-FEED-4, S-FEED-5)
export const useFeedSources = () => useQuery({ queryKey: ['feeds', 'sources'], queryFn: () => api.get<{ items: Feed[] }>('/feeds/sources') })

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
