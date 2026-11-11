import { useQuery } from '@tanstack/react-query'
import { api, ApiError } from './api'

export type Role = 'viewer' | 'operator' | 'admin'
export interface Me { id: string; name: string; email: string; role: Role; org: string; twofa: boolean; twofa_method: 'app' | 'email' | null; password_change_required: boolean }

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

export function useMe() {
  return useQuery<Me | null, ApiError>({
    queryKey: ['me'],
    queryFn: async () => {
      try {
        return await api.get<Me>('/me')
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null
        throw e
      }
    },
    staleTime: 60_000,
  })
}

/** RBAC 3 vai (ARCHITECTURE §5): viewer chỉ xem; operator thao tác; admin cấu hình hệ thống. */
export function useCan(min: Role): boolean {
  const { data } = useMe()
  return !!data && rank[data.role] >= rank[min]
}
