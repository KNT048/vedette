import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { BuiltinHook, CustomHook, HookInput, HookTestInput, HookTestResult, HooksView, KnowledgeDoc, KnowledgeInput, KnowledgeView, MemoryEntry, MemoryInput, MemoryPatch, MemoryView, Rule, RuleInput, RulesView, Skill } from './types'

const enc = encodeURIComponent
/** Mọi thao tác harness làm tươi cả nhóm ['ai', 'harness']; hỏi dữ liệu cũng làm tươi vì hook/memory đổi theo. */
function useDone() {
  const qc = useQueryClient()
  return () => { void qc.invalidateQueries({ queryKey: ['ai'] }) }
}
const useWrite = <A, R = unknown>(fn: (a: A) => Promise<R>) => { const done = useDone(); return useMutation({ mutationFn: fn, onSuccess: done }) }

export const useRules = () => useQuery({ queryKey: ['ai', 'harness', 'rules'], queryFn: () => api.get<RulesView>('/ai/rules') })
export const useSaveRule = () => useWrite(({ id, ...b }: RuleInput & { id?: string }) => (id ? api.put<Rule>(`/ai/rules/${enc(id)}`, b) : api.post<Rule>('/ai/rules', b)))
export const useRemoveRule = () => useWrite((id: string) => api.del(`/ai/rules/${enc(id)}`))

export const useMemory = () => useQuery({ queryKey: ['ai', 'harness', 'memory'], queryFn: () => api.get<MemoryView>('/ai/memory') })
export const useAddMemory = () => useWrite((b: MemoryInput) => api.post<MemoryEntry>('/ai/memory', b))
export const usePatchMemory = () => useWrite(({ id, ...b }: MemoryPatch & { id: string }) => api.put<MemoryEntry>(`/ai/memory/${enc(id)}`, b))
export const useRemoveMemory = () => useWrite((id: string) => api.del(`/ai/memory/${enc(id)}`))
export const useMemorySettings = () => useWrite((suggest_enabled: boolean) => api.put<MemoryView>('/ai/memory/settings', { suggest_enabled }))
export const useAnswerSuggestion = () => useWrite(({ id, accept }: { id: string; accept: boolean }) => api.post<MemoryEntry | null>(`/ai/memory/suggestions/${enc(id)}/${accept ? 'accept' : 'reject'}`))

export const useSkills = () => useQuery({ queryKey: ['ai', 'harness', 'skills'], queryFn: () => api.get<{ items: Skill[] }>('/ai/skills') })
export const useToggleSkill = () => useWrite(({ id, enabled }: { id: string; enabled: boolean }) => api.put<Skill>(`/ai/skills/${enc(id)}`, { enabled }))

/** Tài liệu đang tải/lập chỉ mục: hỏi lại mỗi giây cho tới khi xong. */
export const useKnowledge = () => useQuery({
  queryKey: ['ai', 'harness', 'knowledge'], queryFn: () => api.get<KnowledgeView>('/ai/knowledge'),
  refetchInterval: (q) => (q.state.data?.items.some((d) => d.status !== 'ready') ? 1000 : false),
})
/** The bytes of a picked file as base64 (the upload body of /ai/knowledge carries the file, like /inventory/import carries its CSV). */
export async function fileBase64(f: File): Promise<string> {
  const bytes = new Uint8Array(await f.arrayBuffer())
  let bin = ''
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(bin)
}
export const useAddDoc = () => useWrite((b: KnowledgeInput) => api.post<KnowledgeDoc>('/ai/knowledge', b))
export const useDocJobs = () => useWrite(({ id, jobs }: { id: string; jobs: KnowledgeDoc['jobs'] }) => api.put<KnowledgeDoc>(`/ai/knowledge/${enc(id)}`, { jobs }))
export const useRemoveDoc = () => useWrite((id: string) => api.del(`/ai/knowledge/${enc(id)}`))
export const useIndexProfile = () => useWrite((index_profile: string | null) => api.put<KnowledgeView>('/ai/knowledge/settings', { index_profile }))

export const useHooks = () => useQuery({ queryKey: ['ai', 'harness', 'hooks'], queryFn: () => api.get<HooksView>('/ai/hooks') })
export const useToggleBuiltinHook = () => useWrite(({ id, enabled }: { id: string; enabled: boolean }) => api.put<BuiltinHook>(`/ai/hooks/builtin/${enc(id)}`, { enabled }))
export const useSaveHook = () => useWrite(({ id, ...b }: HookInput & { id?: string }) => (id ? api.put<CustomHook>(`/ai/hooks/${enc(id)}`, b) : api.post<CustomHook>('/ai/hooks', b)))
export const useRemoveHook = () => useWrite((id: string) => api.del(`/ai/hooks/${enc(id)}`))
export const useTestHook = () => useMutation({ mutationFn: (b: HookTestInput) => api.post<HookTestResult>('/ai/hooks/test', b) })
