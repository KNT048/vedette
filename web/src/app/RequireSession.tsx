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
  // W2-8: /me only once the box is known to be set up; before setup it answers 401, which the browser logs on the first page load.
  const me = useMe(setup.data?.complete === true)
  if (setup.isPending) return <div className="p-8"><Loading /></div>
  if (setup.isError) return <div className="p-8"><ErrorState error={setup.error} onRetry={() => void setup.refetch()} /></div>
  if (!setup.data.complete) return <Navigate to="/setup" replace />
  if (me.isPending) return <div className="p-8"><Loading /></div>
  if (me.error) return <div className="p-8"><ErrorState error={me.error} onRetry={() => void me.refetch()} /></div>
  if (!me.data) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  // D-180: an administrator-set password must be replaced first; every other call would answer 403 password_change_required.
  if (me.data.password_change_required) return <Navigate to={`/change-password?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  return <>{children}</>
}
