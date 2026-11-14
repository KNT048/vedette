import { useQuery } from '@tanstack/react-query'
import { api, ApiError, hasSessionCookie } from './api'

export type Role = 'viewer' | 'operator' | 'admin'
export interface Me { id: string; name: string; email: string; role: Role; org: string; twofa: boolean; twofa_method: 'app' | 'email' | null; password_change_required: boolean }

const rank: Record<Role, number> = { viewer: 0, operator: 1, admin: 2 }

/** enabled false: not asked yet (RequireSession on a box not set up: /me would only answer 401, logged by the browser, W2-8). */
export function useMe(enabled = true) {
  return useQuery<Me | null, ApiError>({
    queryKey: ['me'],
    enabled,
    queryFn: async () => {
      // N44-2: without the session's readable cookie nobody is signed in, and asking /me would only answer 401, which the browser
      // logs on every page load. The mock sets no cookie, so it is asked as before.
      if (import.meta.env.VITE_API_MOCK === 'off' && !hasSessionCookie()) return null
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
