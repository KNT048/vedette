import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Hit, HitDetail, HpOverview, HpService, Token, TokenInput, TrapIP, TrapIPInput, TrapIPsResponse } from './types'

// A trap that is coming up or going down changes without the user doing anything (the box takes minutes): look again until it settles.
const SETTLE_MS = 3000
const settling = (s: string) => s === 'starting' || s === 'stopping'
export const useOverview = () => useQuery({ queryKey: ['honeypot', 'overview'], queryFn: () => api.get<HpOverview>('/honeypot'),
  refetchInterval: (q) => (q.state.status !== 'error' && q.state.data?.traps.some((t) => settling(t.state)) ? SETTLE_MS : false) })

export const useHits = (asset?: string) =>
  useQuery({ queryKey: ['honeypot', 'hits', asset ?? 'all'], queryFn: () => api.get<{ items: Hit[] }>(`/honeypot/hits${asset ? `?asset=${encodeURIComponent(asset)}` : ''}`) })

export const useHit = (id: string) => useQuery({ queryKey: ['honeypot', 'hit', id], queryFn: () => api.get<HitDetail>(`/honeypot/hits/${encodeURIComponent(id)}`), retry: false })

function useInvalidate() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['honeypot'] })
}

export function useTestHit() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (service: HpService) => api.post<Hit>('/honeypot/test-hit', { service }), onSuccess: inv })
}

export const useTrapIps = () => useQuery({ queryKey: ['honeypot', 'trap-ips'], queryFn: () => api.get<TrapIPsResponse>('/honeypot/trap-ips'),
  refetchInterval: (q) => (q.state.status !== 'error' && q.state.data?.items.some((d) => settling(d.state)) ? SETTLE_MS : false) })
export const useTokens = () => useQuery({ queryKey: ['honeypot', 'tokens'], queryFn: () => api.get<{ items: Token[] }>('/honeypot/tokens') })

export function useAddTrapIp() { const inv = useInvalidate(); return useMutation({ mutationFn: (b: TrapIPInput) => api.post<TrapIP>('/honeypot/trap-ips', b), onSuccess: inv }) }
export function useEditTrapIp() { const inv = useInvalidate(); return useMutation({ mutationFn: ({ id, ...b }: TrapIPInput & { id: string }) => api.put<TrapIP>(`/honeypot/trap-ips/${id}`, b), onSuccess: inv }) }
export function useToggleTrapIp() { const inv = useInvalidate(); return useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.patch<TrapIP>(`/honeypot/trap-ips/${id}`, { enabled }), onSuccess: inv }) }
export function useDeleteTrapIp() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.del<void>(`/honeypot/trap-ips/${id}`), onSuccess: inv }) }
export function useTestScan() { const inv = useInvalidate(); return useMutation({ mutationFn: () => api.post<Hit>('/honeypot/test-scan'), onSuccess: inv }) }
export function useAddToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (b: TokenInput) => api.post<Token>('/honeypot/tokens', b), onSuccess: inv }) }
export function useDeleteToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.del<void>(`/honeypot/tokens/${id}`), onSuccess: inv }) }
export function useTestToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.post<Hit>(`/honeypot/tokens/${id}/test`), onSuccess: inv }) }
