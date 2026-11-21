import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AiSummary, PdplOrg, PdplReport, PdplState, ReportDefinition, ReportDefinitionInput, ReportDocument, SentReport, SentReportItem } from './types'

// The periodic security report: its one definition, the document of the current period, sending and the sent documents.
export const useDefinition = () => useQuery({ queryKey: ['reports', 'definition'], queryFn: () => api.get<ReportDefinition>('/reports/definition') })
export const useReportDocument = () => useQuery({ queryKey: ['reports', 'document'], queryFn: () => api.get<ReportDocument>('/reports/document') })
export const useSentList = () => useQuery({ queryKey: ['reports', 'history'], queryFn: () => api.get<{ items: SentReportItem[] }>('/reports/history') })
export const useSentReport = (id: string) => useQuery({ queryKey: ['reports', 'history', id], queryFn: () => api.get<SentReport>(`/reports/history/${encodeURIComponent(id)}`), enabled: id !== '' })
export const usePdpl = () => useQuery({ queryKey: ['reports', 'pdpl'], queryFn: () => api.get<PdplState>('/reports/pdpl') })

function useRefresh() {
  const qc = useQueryClient()
  return () => { void qc.invalidateQueries({ queryKey: ['reports'] }); void qc.invalidateQueries({ queryKey: ['ai'] }) }
}
export function useSaveDefinition() {
  const done = useRefresh()
  return useMutation({ mutationFn: (b: ReportDefinitionInput) => api.put<ReportDefinition>('/reports/definition', b), onSuccess: done })
}
export function useSendReport() {
  const done = useRefresh()
  return useMutation({ mutationFn: () => api.post<SentReportItem>('/reports/send'), onSuccess: done })
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
