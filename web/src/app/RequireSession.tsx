import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { useMe } from '@/lib/session'
import { ErrorState, Loading } from '@/components/common/States'

export function useSetup() {
  return useQuery({ queryKey: ['setup'], queryFn: () => api.get<{ complete: boolean; org: string; data_mode?: 'sample' | 'clean' }>('/setup'), staleTime: 60_000 })
}

/** Chưa cài đặt ban đầu → /setup; chưa đăng nhập → /login?next=… */
export function RequireSession({ children }: { children: ReactNode }) {
  const loc = useLocation()
  const setup = useSetup()
  const me = useMe()
  if (setup.isPending || me.isPending) return <div className="p-8"><Loading /></div>
  if (setup.error) return <div className="p-8"><ErrorState error={setup.error} onRetry={() => void setup.refetch()} /></div>
  if (setup.data && !setup.data.complete) return <Navigate to="/setup" replace />
  if (me.error) return <div className="p-8"><ErrorState error={me.error} onRetry={() => void me.refetch()} /></div>
  if (!me.data) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  return <>{children}</>
}
