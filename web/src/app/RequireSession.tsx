import { Fragment, Suspense, useEffect, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import { loadNamespaces } from '@/lib/i18n'
import { shellNamespaces } from './feature'
import { useMe } from '@/lib/session'
import { setDisplayTimeZone } from '@/lib/format'
import type { GeneralSettings } from '@/features/core/types'
import { ErrorState, Loading } from '@/components/common/States'

export function useSetup() {
  return useQuery({ queryKey: ['setup'], queryFn: () => api.get<{ complete: boolean; org: string; data_mode?: 'sample' | 'clean' }>('/setup'), staleTime: 60_000 })
}

/** Chưa cài đặt ban đầu → /setup; chưa đăng nhập → /login?next=… */
export function RequireSession({ children }: { children: ReactNode }) {
  const loc = useLocation()
  // The shell's own words (sidebar, tabs, page titles) load while the session is being checked, not after it.
  useEffect(() => { void loadNamespaces(shellNamespaces) }, [])
  const setup = useSetup()
  // /me only once the box is known to be set up; before setup it answers 401, which the browser logs on the first page load.
  const me = useMe(setup.data?.complete === true)
  // Every date is written in the organization's time zone (lib/format), the one the box's own sentences use; read once signed in.
  // A failed read keeps the browser's zone rather than blocking the app.
  const signedIn = !!me.data && !me.data.password_change_required
  const general = useQuery({ queryKey: ['core', 'general'], queryFn: () => api.get<GeneralSettings>('/core/general'), enabled: signedIn, staleTime: 60_000 })
  const zone = general.data?.timezone
  setDisplayTimeZone(zone)
  if (setup.isPending) return <div className="p-8"><Loading /></div>
  if (setup.isError) return <div className="p-8"><ErrorState error={setup.error} onRetry={() => void setup.refetch()} /></div>
  if (!setup.data.complete) return <Navigate to="/setup" replace />
  if (me.isPending) return <div className="p-8"><Loading /></div>
  if (me.error) return <div className="p-8"><ErrorState error={me.error} onRetry={() => void me.refetch()} /></div>
  if (!me.data) return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  // An administrator-set password must be replaced first; every other call would answer 403 password_change_required.
  if (me.data.password_change_required) return <Navigate to={`/change-password?next=${encodeURIComponent(loc.pathname + loc.search)}`} replace />
  if (general.isPending) return <div className="p-8"><Loading /></div>
  // A new zone (Settings › General) draws every page again, so no date stays in the old one.
  return <Fragment key={zone ?? ''}><Suspense fallback={<div className="p-8"><Loading /></div>}>{children}</Suspense></Fragment>
}
