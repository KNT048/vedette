import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { FindingNotices, HistoryItem, HistoryResponse, IncidentDetail, IncidentsResponse, IncidentStatus, Channel, ChannelInput, ChannelsResponse, ChannelType, Grouping, Quiet, TestResult } from './types'

export const useIncidents = () => useQuery({ queryKey: ['notify', 'incidents'], queryFn: () => api.get<IncidentsResponse>('/notify/incidents') })
export const useIncident = (id: string) => useQuery({ queryKey: ['notify', 'incident', id], queryFn: () => api.get<IncidentDetail>(`/notify/incidents/${encodeURIComponent(id)}`), retry: false })
export const useHistory = () => useQuery({ queryKey: ['notify', 'history'], queryFn: () => api.get<HistoryResponse>('/notify/history') })
export const useFindingNotices = (id: string) => useQuery({ queryKey: ['notify', 'finding', id], queryFn: () => api.get<FindingNotices>(`/notify/findings/${encodeURIComponent(id)}/notices`) })
export const useLegacyTarget = (id: string) => useQuery({ queryKey: ['notify', 'legacy', id], queryFn: () => api.get<{ to: string }>(`/notify/alerts/${encodeURIComponent(id)}/target`), retry: false })
export const useChannels = () => useQuery({ queryKey: ['notify', 'channels'], queryFn: () => api.get<ChannelsResponse>('/notify/channels') })

function useInvalidating<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['notify'] }) } })
}

export const useSetStatus = () => useInvalidating(({ id, status, note }: { id: string; status: IncidentStatus; note?: string }) => api.patch<IncidentDetail>(`/notify/incidents/${encodeURIComponent(id)}`, { status, note }))
export const useResend = () => useInvalidating((id: string) => api.post<HistoryItem>(`/notify/history/${encodeURIComponent(id)}/resend`))
export const useSaveChannel = () => useInvalidating(({ type, ...v }: ChannelInput & { type: ChannelType }) => api.put<Channel>(`/notify/channels/${type}`, v))
export const useRemoveChannel = () => useInvalidating((type: ChannelType) => api.del<void>(`/notify/channels/${type}`))
export const useTestChannel = () => useInvalidating((type: ChannelType) => api.post<TestResult>(`/notify/channels/${type}/test`))
export const useSaveRules = () => useInvalidating((v: { quiet: Quiet; grouping: Grouping }) => api.put<{ quiet: Quiet; grouping: Grouping }>('/notify/rules', v))

