import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Digest, EventsResponse, EventWindow, LogSource, SiemConfig, SiemInput, SourceInput, SourcesResponse, UnknownSendersResponse } from './types'

export const useSources = () => useQuery({ queryKey: ['logs', 'sources'], queryFn: () => api.get<SourcesResponse>('/logs/sources') })
// Operator and up (the addresses of dropped senders); refreshed with the rest of the page (query key under 'logs').
export const useUnknownSenders = (enabled: boolean) => useQuery({ queryKey: ['logs', 'unknown-senders'], queryFn: () => api.get<UnknownSendersResponse>('/logs/unknown-senders'), enabled })
export const useDigest = () => useQuery({ queryKey: ['logs', 'digest'], queryFn: () => api.get<Digest>('/logs/digest') })

const eventsUrl = (p: { window: EventWindow; source: string; q: string }, cursor?: string) =>
  `/logs/events?window=${p.window}&source=${encodeURIComponent(p.source)}&q=${encodeURIComponent(p.q)}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ''}`
export const useEvents = (p: { window: EventWindow; source: string; q: string }) =>
  useQuery({
    queryKey: ['logs', 'events', p],
    queryFn: () => api.get<EventsResponse>(eventsUrl(p)),
    placeholderData: (prev) => prev,
  })
// The next step of a keyword search that stopped before the start of the window (S-LOG-1, D-441): the lines older than `cursor`.
export const fetchOlderEvents = (p: { window: EventWindow; source: string; q: string }, cursor: string) => api.get<EventsResponse>(eventsUrl(p, cursor))

function useInvalidating<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['logs'] }) } })
}

export const useAddSource = () => useInvalidating((v: SourceInput) => api.post<LogSource>('/logs/sources', v))
export const useEditSource = () => useInvalidating(({ id, ...v }: SourceInput & { id: string }) => api.put<LogSource>(`/logs/sources/${id}`, v))
export const useDeleteSource = () => useInvalidating((id: string) => api.del<void>(`/logs/sources/${id}`))
export const useSetRetention = () => useInvalidating((days: number) => api.put<{ retention_days: number }>('/logs/retention', { days }))

export const useSiem = () => useQuery({ queryKey: ['logs', 'siem'], queryFn: () => api.get<SiemConfig>('/logs/siem') })
export const useSaveSiem = () => useInvalidating((v: SiemInput) => api.put<SiemConfig>('/logs/siem', v))
export const useTestSiem = () => useInvalidating(() => api.post<{ ok: boolean; at: string; detail: string }>('/logs/siem/test'))
