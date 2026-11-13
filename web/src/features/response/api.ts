import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError } from '@/lib/api'
import type { ActionRequest, AiState, ApprovalView, Allowlist, Blocklist, Catalog, CatalogAction, CatalogInput, EventView, IncidentPanel, LogEntry, Metrics, PlanList, ProposeResult, Rule, RuleInput, RunSummary, SettingsInput, SettingsView, Simulation, Template, TriggerInfo } from './types'

export const usePlans = (finding?: string) =>
  useQuery({ queryKey: ['response', 'plans', finding ?? 'all'], queryFn: () => api.get<PlanList>(`/response/plans${finding ? `?finding=${encodeURIComponent(finding)}` : ''}`) })
export const useActions = () => useQuery({ queryKey: ['response', 'actions'], queryFn: () => api.get<{ items: ActionRequest[] }>('/response/actions'), refetchInterval: 30_000 })
export const useSettings = (enabled = true) => useQuery({ queryKey: ['response', 'settings'], queryFn: () => api.get<SettingsView>('/response/settings'), enabled })
export const useRules = () => useQuery({ queryKey: ['response', 'rules'], queryFn: () => api.get<{ items: Rule[] }>('/response/rules') })
export const useTriggers = () => useQuery({ queryKey: ['response', 'triggers'], queryFn: () => api.get<{ items: TriggerInfo[] }>('/response/triggers') })
export const useEvents = () => useQuery({ queryKey: ['response', 'events'], queryFn: () => api.get<{ items: EventView[] }>('/response/events') })
export const useTemplates = () => useQuery({ queryKey: ['response', 'templates'], queryFn: () => api.get<{ items: Template[] }>('/response/templates') })
export const useAllowlist = () => useQuery({ queryKey: ['response', 'allowlist'], queryFn: () => api.get<Allowlist>('/response/allowlist') })
export const useBlocklist = (enabled = true) => useQuery({ queryKey: ['response', 'blocklist'], queryFn: () => api.get<Blocklist>('/response/blocklist'), enabled })
export const useCatalog = () => useQuery({ queryKey: ['response', 'catalog'], queryFn: () => api.get<Catalog>('/response/catalog') })
export const useLog = () => useQuery({ queryKey: ['response', 'log'], queryFn: () => api.get<{ items: LogEntry[] }>('/response/log') })
export const useAi = () => useQuery({ queryKey: ['response', 'ai'], queryFn: () => api.get<AiState>('/response/ai') })
export const useMetrics = () => useQuery({ queryKey: ['response', 'metrics'], queryFn: () => api.get<Metrics>('/response/metrics') })
export const useIncidentPanel = (id: string) => useQuery({ queryKey: ['response', 'incident', id], queryFn: () => api.get<IncidentPanel>(`/response/incidents/${encodeURIComponent(id)}`), retry: false })
export const useApprovalView = (token: string) => useQuery({ queryKey: ['approve', token], queryFn: () => api.get<ApprovalView>(`/response/approve/${encodeURIComponent(token)}`), retry: false })

function useInvalidating<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  // Refuse or fail: the server may still have written an audit line or expired a request, so refresh either way.
  return useMutation({ mutationFn: fn, onSettled: () => { void qc.invalidateQueries({ queryKey: ['response'] }); void qc.invalidateQueries({ queryKey: ['me'] }) } })
}
const enc = encodeURIComponent

export const useRequestApproval = () => useInvalidating((proposal: string) => api.post<ActionRequest>(`/response/proposals/${enc(proposal)}/request`))
export const useRequestFromIncident = () => useInvalidating((v: { id: string; action_id: string }) => api.post<ActionRequest>(`/response/incidents/${enc(v.id)}/request`, { action_id: v.action_id }))
export const useApprove = () => useInvalidating((v: { id: string; items?: string[]; code?: string }) => api.post<ActionRequest>(`/response/actions/${enc(v.id)}/approve`, { items: v.items, code: v.code || undefined }))
export const useReject = () => useInvalidating((v: { id: string; reason?: string; remember?: 'none' | 'rule' | 'memory' }) => api.post<ActionRequest>(`/response/actions/${enc(v.id)}/reject`, { reason: v.reason || undefined, remember: v.remember }))
export const useRollback = () => useInvalidating((id: string) => api.post<ActionRequest>(`/response/actions/${enc(id)}/rollback`))
export const useEmergencyStop = () => useInvalidating(() => api.post<{ cancelled: number }>('/response/emergency-stop'))
export const useSetExecution = () => useInvalidating((v: { enabled: boolean; phrase?: string }) => api.post<SettingsView>('/response/execution', v))
export const useSaveSettings = () => useInvalidating((v: SettingsInput) => api.put<SettingsView>('/response/settings', v))
export const useResetBreaker = () => useInvalidating(() => api.post<SettingsView>('/response/breaker/reset'))
export const useSaveRule = () => useInvalidating((v: { id?: string; rule: RuleInput }) => (v.id ? api.put<Rule>(`/response/rules/${enc(v.id)}`, v.rule) : api.post<Rule>('/response/rules', v.rule)))
export const useDeleteRule = () => useInvalidating((id: string) => api.del<void>(`/response/rules/${enc(id)}`))
export const useRunRules = () => useInvalidating(() => api.post<RunSummary>('/response/rules/run'))
export const useRunManual = () => useInvalidating((v: { id: string; asset_id: string }) => api.post<RunSummary>(`/response/rules/${enc(v.id)}/manual`, { asset_id: v.asset_id }))
export const useSimulate = () => useInvalidating((rule: RuleInput) => api.post<Simulation>('/response/rules/simulate', { rule }))
export const useCloneTemplate = () => useInvalidating((id: string) => api.post<Rule>(`/response/templates/${enc(id)}/clone`))
export const useSaveAllowlist = () => useInvalidating((v: Allowlist) => api.put<Allowlist>('/response/allowlist', v))
export const useNewToken = () => useInvalidating(() => api.post<Blocklist>('/response/blocklist/token'))
export const useSaveAction = () => useInvalidating((v: { id?: string; input: Partial<CatalogInput> }) => (v.id ? api.put<CatalogAction>(`/response/catalog/${enc(v.id)}`, v.input) : api.post<CatalogAction>('/response/catalog', v.input)))
export const useDeleteAction = () => useInvalidating((id: string) => api.del<void>(`/response/catalog/${enc(id)}`))
export const useDecideByLink = () => useInvalidating((v: { token: string; decision: 'approve' | 'reject' }) => api.post<ActionRequest>(`/response/approve/${enc(v.token)}`, { decision: v.decision }))
export const usePropose = () => useInvalidating((v: Record<string, unknown>) => api.post<ProposeResult>('/response/ai/proposals', v))
export const useResumeAi = () => useInvalidating(() => api.post<AiState>('/response/ai/resume'))

export const errText = (e: unknown) => (e instanceof ApiError ? e.message : e instanceof Error ? e.message : String(e))
