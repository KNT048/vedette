import type { RouteObject } from 'react-router'
import { features } from './feature'
import { Layout } from './Layout'
import { RequireSession } from './RequireSession'
import LoginPage from './LoginPage'
import { NotFound, RouteError } from './NotFound'
import { Loading } from '@/components/common/States'

const PageLoading = () => <div className="mx-auto max-w-5xl px-4 py-8 sm:px-8"><Loading /></div>

export function buildRoutes(): RouteObject[] {
  return [
    { path: '/login', Component: LoginPage, errorElement: <RouteError /> },
    ...features.flatMap((f) => f.publicRoutes ?? []).map((r) => ({ ...r, errorElement: <RouteError />, hydrateFallbackElement: <PageLoading /> })),
    {
      element: <RequireSession><Layout /></RequireSession>,
      errorElement: <RouteError />,
      // A `lazy` page opened straight from a URL: show a loading state instead of a blank page (and no more React Router HydrateFallback warning).
      hydrateFallbackElement: <PageLoading />,
      children: [...features.flatMap((f) => f.routes), { path: '*', Component: NotFound }],
    },
  ]
}
