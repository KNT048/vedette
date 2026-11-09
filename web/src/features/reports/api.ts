import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AiSummary, HistoryEntry, PdplOrg, PdplReport, PdplState, Schedule, WeeklyPreview } from './types'

export const useWeekly = () => useQuery({ queryKey: ['reports', 'weekly'], queryFn: () => api.get<WeeklyPreview>('/reports/weekly/preview') })
export const useSchedule = () => useQuery({ queryKey: ['reports', 'schedule'], queryFn: () => api.get<Schedule>('/reports/schedule') })
export const useHistory = () => useQuery({ queryKey: ['reports', 'history'], queryFn: () => api.get<{ items: Omit<HistoryEntry, 'report'>[] }>('/reports/weekly/history') })
export const useHistoryEntry = (id: string) => useQuery({ queryKey: ['reports', 'history', id], queryFn: () => api.get<HistoryEntry>(`/reports/weekly/history/${encodeURIComponent(id)}`), enabled: id !== '' })
export const usePdpl = () => useQuery({ queryKey: ['reports', 'pdpl'], queryFn: () => api.get<PdplState>('/reports/pdpl') })

function useRefresh() {
  const qc = useQueryClient()
  return () => { void qc.invalidateQueries({ queryKey: ['reports'] }); void qc.invalidateQueries({ queryKey: ['ai'] }) }
}
export function useSaveSchedule() {
  const done = useRefresh()
  return useMutation({ mutationFn: (b: Omit<Schedule, 'next_run'>) => api.put<Schedule>('/reports/schedule', b), onSuccess: done })
}
export function useSendWeekly() {
  const done = useRefresh()
  return useMutation({ mutationFn: () => api.post<Omit<HistoryEntry, 'report'>>('/reports/weekly/send'), onSuccess: done })
}
export function useWeeklyAi() {
  const done = useRefresh()
  return useMutation({ mutationFn: () => api.post<AiSummary>('/reports/weekly/ai-summary'), onSuccess: done })
}
export function useSaveOrg() {
  const done = useRefresh()
  return useMutation({ mutationFn: (b: PdplOrg) => api.put<PdplOrg>('/reports/pdpl/org', b), onSuccess: done })
}
export function useGeneratePdpl() {
  const done = useRefresh()
  return useMutation({ mutationFn: () => api.post<PdplReport>('/reports/pdpl/generate'), onSuccess: done })
}
export function usePdplAi() {
  const done = useRefresh()
  return useMutation({ mutationFn: () => api.post<AiSummary>('/reports/pdpl/ai-summary'), onSuccess: done })
}
