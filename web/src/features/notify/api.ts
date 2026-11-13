import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { EmailSignin, EmailSigninStart, FindingNotices, HistoryItem, HistoryResponse, IncidentDetail, IncidentsResponse, IncidentStatus, Channel, ChannelInput, ChannelsResponse, ChannelType, Grouping, Quiet, TestResult, ZaloApprover, ZaloApprovers, ZaloContacts, ZaloFound, ZaloLogin } from './types'

export const useIncidents = () => useQuery({ queryKey: ['notify', 'incidents'], queryFn: () => api.get<IncidentsResponse>('/notify/incidents') })
export const useIncident = (id: string) => useQuery({ queryKey: ['notify', 'incident', id], queryFn: () => api.get<IncidentDetail>(`/notify/incidents/${encodeURIComponent(id)}`), retry: false })
export const useHistory = () => useQuery({ queryKey: ['notify', 'history'], queryFn: () => api.get<HistoryResponse>('/notify/history') })
export const useFindingNotices = (id: string) => useQuery({ queryKey: ['notify', 'finding', id], queryFn: () => api.get<FindingNotices>(`/notify/findings/${encodeURIComponent(id)}/notices`) })
export const useLegacyTarget = (id: string) => useQuery({ queryKey: ['notify', 'legacy', id], queryFn: () => api.get<{ to: string }>(`/notify/alerts/${encodeURIComponent(id)}/target`), retry: false })
export const useChannels = (opts: { retry?: boolean; enabled?: boolean } = {}) => useQuery({ queryKey: ['notify', 'channels'], queryFn: () => api.get<ChannelsResponse>('/notify/channels'), ...opts })

function useInvalidating<V, R>(fn: (v: V) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => { void qc.invalidateQueries({ queryKey: ['notify'] }) } })
}

export const useSetStatus = () => useInvalidating(({ id, status, note }: { id: string; status: IncidentStatus; note?: string }) => api.patch<IncidentDetail>(`/notify/incidents/${encodeURIComponent(id)}`, { status, note }))
export const useResend = () => useInvalidating((id: string) => api.post<HistoryItem>(`/notify/history/${encodeURIComponent(id)}/resend`))
export const useSaveChannel = () => useInvalidating(({ type, ...v }: ChannelInput & { type: ChannelType }) => api.put<Channel>(`/notify/channels/${type}`, v))
export const useRemoveChannel = () => useInvalidating((type: ChannelType) => api.del<void>(`/notify/channels/${type}`))
export const useTestChannel = () => useInvalidating((type: ChannelType) => api.post<TestResult>(`/notify/channels/${type}/test`))
// D-480: a user sign-in of the email channel; nothing is cached (each answer is the state of that sign-in)
export const useStartEmailSignin = () => useMutation({ mutationFn: (v: EmailSigninStart) => api.post<EmailSignin>('/notify/email-signin', v) })
export const useCheckEmailSignin = () => useMutation({ mutationFn: ({ id, url }: { id: string; url?: string }) => api.post<EmailSignin>(`/notify/email-signin/${encodeURIComponent(id)}`, url === undefined ? {} : { url }) })
export const useSaveRules = () => useInvalidating((v: { quiet: Quiet; grouping: Grouping }) => api.put<{ quiet: Quiet; grouping: Grouping }>('/notify/rules', v))


// Zalo personal set-up (D-447). The QR sign-in is polled every 2 s while it waits for the phone; the approvers' link state every 3 s
// while a code is on its way or waits for a reply.
const LIVE: ZaloLogin['state'][] = ['waiting', 'scanned']
export const useZaloLogin = (enabled: boolean) => useQuery({ queryKey: ['notify', 'zalo', 'login'], queryFn: () => api.get<ZaloLogin>('/notify/zalo/login'), enabled,
  refetchInterval: (q) => (q.state.data && LIVE.includes(q.state.data.state) ? 2000 : false) })
export function useStartZaloLogin() {
  const qc = useQueryClient()
  return useMutation({ mutationFn: () => api.post<ZaloLogin>('/notify/zalo/login'), onSuccess: (v) => { qc.setQueryData(['notify', 'zalo', 'login'], v) } })
}
export const cancelZaloLogin = () => api.del<void>('/notify/zalo/login')
export const useZaloContacts = (enabled: boolean) => useQuery({ queryKey: ['zalo-contacts'] /* not under 'notify': a save must not ask Zalo again */, queryFn: () => api.get<ZaloContacts>('/notify/zalo/contacts'), enabled, retry: false, staleTime: Infinity })
export const useResolveZalo = () => useMutation({ mutationFn: (query: string) => api.post<ZaloFound>('/notify/zalo/resolve', { query }) })
const WAITING: ZaloApprover['state'][] = ['sending', 'waiting']
export const useZaloApprovers = (enabled: boolean) => useQuery({ queryKey: ['notify', 'zalo', 'approvers'], queryFn: () => api.get<ZaloApprovers>('/notify/zalo/approvers'), enabled,
  refetchInterval: (q) => (q.state.data?.items.some((a) => WAITING.includes(a.state)) ? 3000 : false) })
export const useSendZaloCode = () => useInvalidating((userId: string) => api.post<ZaloApprover>(`/notify/zalo/approvers/${encodeURIComponent(userId)}/code`))
