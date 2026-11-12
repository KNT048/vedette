import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AiConfigView, AiJob, AiProfile, AskResult, Assignments, ConfigInput, ExplainResult, LogDigest, NewsResult, AiRun, ActivityList, ActivityResult, ActivitySettings, ActivityVerify, ProfileInput, TestInput, TestResult, Usage } from './types'

export const useAiConfig = () => useQuery({ queryKey: ['ai', 'config'], queryFn: () => api.get<AiConfigView>('/ai/config') })

function useInvalidateAi() {
  const qc = useQueryClient()
  return () => { void qc.invalidateQueries({ queryKey: ['ai'] }) }
}
// Lệnh gọi AI bị chặn do trần vẫn ghi một dòng nhật ký, nên làm tươi cả khi lỗi.

export function useSaveConfig() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (b: ConfigInput) => api.put<AiConfigView>('/ai/config', b), onSuccess: done })
}
export const useProfiles = () => useQuery({ queryKey: ['ai', 'profiles'], queryFn: () => api.get<{ items: AiProfile[] }>('/ai/profiles') })
export function useSaveProfile() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (b: ProfileInput) => (b.id ? api.put<AiProfile>(`/ai/profiles/${encodeURIComponent(b.id)}`, b) : api.post<AiProfile>('/ai/profiles', b)), onSuccess: done })
}
export function useRemoveProfile() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (id: string) => api.del<{ cleared_jobs: AiJob[] }>(`/ai/profiles/${encodeURIComponent(id)}`), onSuccess: done })
}
export function useTestProfile() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (b: TestInput) => api.post<TestResult>('/ai/profiles/test', b), onSuccess: done })
}
export const useAssignments = () => useQuery({ queryKey: ['ai', 'assignments'], queryFn: () => api.get<Assignments>('/ai/assignments') })
export function useSaveAssignments() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (b: Assignments) => api.put<Assignments>('/ai/assignments', b), onSuccess: done })
}
export const fetchSuggestion = (internalOnly: boolean) => api.get<Assignments>(`/ai/assignments/suggestion?internal_only=${internalOnly}`)

export const useUsage = () => useQuery({ queryKey: ['ai', 'usage'], queryFn: () => api.get<Usage>('/ai/usage') })
export const useRuns = () => useQuery({ queryKey: ['ai', 'runs'], queryFn: () => api.get<{ items: AiRun[] }>('/ai/runs') })
export const useAsks = () => useQuery({ queryKey: ['ai', 'asks'], queryFn: () => api.get<{ items: AskResult[] }>('/ai/asks') })

export function useAsk() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (question: string) => api.post<AskResult>('/ai/ask', { question }), onSettled: done })
}

export const useCveCached = (cve: string) =>
  useQuery({ queryKey: ['ai', 'cve', cve], queryFn: () => api.get<{ explain: ExplainResult | null; news: NewsResult | null }>(`/ai/cve/${encodeURIComponent(cve)}/cached`) })

export function useExplain(cve: string) {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: () => api.post<ExplainResult>(`/ai/cve/${encodeURIComponent(cve)}/explain`), onSettled: done })
}
export function useNews(cve: string) {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: () => api.post<NewsResult>(`/ai/cve/${encodeURIComponent(cve)}/news`), onSettled: done })
}

export const useDigest = () => useQuery({ queryKey: ['ai', 'digest'], queryFn: () => api.get<{ digest: LogDigest | null }>('/ai/logs/digest'), retry: false })
export function useRefreshDigest() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: () => api.post<{ digest: LogDigest }>('/ai/logs/digest'), onSettled: done })
}

// S-AI-8: activity log (read only: entries cannot be edited or deleted)
export interface ActivityFilter { job?: string; result?: ActivityResult | ''; from?: string; to?: string }
export function useActivity(f: ActivityFilter) {
  const q = new URLSearchParams()
  if (f.job) q.set('job', f.job)
  if (f.result) q.set('result', f.result)
  if (f.from) q.set('from', new Date(`${f.from}T00:00:00`).toISOString())
  if (f.to) q.set('to', new Date(`${f.to}T23:59:59.999`).toISOString())
  return useQuery({ queryKey: ['ai', 'activity', q.toString()], queryFn: () => api.get<ActivityList>(`/ai/activity?${q}`) })
}
export const useVerifyChain = () => useQuery({ queryKey: ['ai', 'activity-verify'], queryFn: () => api.get<ActivityVerify>('/ai/activity/verify') })
export const useActivitySettings = () => useQuery({ queryKey: ['ai', 'activity-settings'], queryFn: () => api.get<ActivitySettings>('/ai/activity/settings') })
export function useSaveActivitySettings() {
  const done = useInvalidateAi()
  return useMutation({ mutationFn: (b: ActivitySettings) => api.put<ActivitySettings>('/ai/activity/settings', b), onSuccess: done })
}
