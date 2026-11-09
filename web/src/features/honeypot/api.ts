import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Decoy, DecoyInput, DecoysResponse, Hit, HitDetail, HpOverview, HpService, Token, TokenInput } from './types'

export const useOverview = () => useQuery({ queryKey: ['honeypot', 'overview'], queryFn: () => api.get<HpOverview>('/honeypot') })

export const useHits = (asset?: string) =>
  useQuery({ queryKey: ['honeypot', 'hits', asset ?? 'all'], queryFn: () => api.get<{ items: Hit[] }>(`/honeypot/hits${asset ? `?asset=${encodeURIComponent(asset)}` : ''}`) })

export const useHit = (id: string) => useQuery({ queryKey: ['honeypot', 'hit', id], queryFn: () => api.get<HitDetail>(`/honeypot/hits/${encodeURIComponent(id)}`), retry: false })

function useInvalidate() {
  const qc = useQueryClient()
  return () => qc.invalidateQueries({ queryKey: ['honeypot'] })
}

export function useSaveConfig() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (b: { secondary_ip: string; hostname: string }) => api.put<HpOverview>('/honeypot/config', b), onSuccess: inv })
}

export function useToggleTrap() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: ({ service, enabled }: { service: HpService; enabled: boolean }) => api.patch<HpOverview>(`/honeypot/traps/${service}`, { enabled }), onSuccess: inv })
}

export function useTestHit() {
  const inv = useInvalidate()
  return useMutation({ mutationFn: (service: HpService) => api.post<Hit>('/honeypot/test-hit', { service }), onSuccess: inv })
}

export const useDecoys = () => useQuery({ queryKey: ['honeypot', 'decoys'], queryFn: () => api.get<DecoysResponse>('/honeypot/decoys') })
export const useTokens = () => useQuery({ queryKey: ['honeypot', 'tokens'], queryFn: () => api.get<{ items: Token[] }>('/honeypot/tokens') })

export function useAddDecoy() { const inv = useInvalidate(); return useMutation({ mutationFn: (b: DecoyInput) => api.post<Decoy>('/honeypot/decoys', b), onSuccess: inv }) }
export function useToggleDecoy() { const inv = useInvalidate(); return useMutation({ mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.patch<Decoy>(`/honeypot/decoys/${id}`, { enabled }), onSuccess: inv }) }
export function useDeleteDecoy() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.del<void>(`/honeypot/decoys/${id}`), onSuccess: inv }) }
export function useTestScan() { const inv = useInvalidate(); return useMutation({ mutationFn: () => api.post<Hit>('/honeypot/test-scan'), onSuccess: inv }) }
export function useAddToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (b: TokenInput) => api.post<Token>('/honeypot/tokens', b), onSuccess: inv }) }
export function useDeleteToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.del<void>(`/honeypot/tokens/${id}`), onSuccess: inv }) }
export function useTestToken() { const inv = useInvalidate(); return useMutation({ mutationFn: (id: string) => api.post<Hit>(`/honeypot/tokens/${id}/test`), onSuccess: inv }) }
