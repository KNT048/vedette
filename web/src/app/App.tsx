import { useEffect, useState, type CSSProperties } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createBrowserRouter, createMemoryRouter } from 'react-router'
import { Toaster } from 'sonner'
import { buildRoutes } from './router'
import { ApiError } from '@/lib/api'
import { BoxRestarting, resetBoxRestart, useBoxRestarting } from '@/features/core/BoxRestarting'

/** One retry for a network failure or a 5xx; an answer of the box below 500 (409 not_appliance, 404, 403) is final, asking again gets the same (D-381). */
export const retryOnce = (count: number, err: unknown) => count < 1 && !(err instanceof ApiError && err.status < 500)

export function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: import.meta.env.MODE === 'test' ? false : retryOnce, refetchOnWindowFocus: false, notifyOnChangeProps: 'all' }, mutations: { retry: 0 } } })
}

export function App({ initialPath }: { initialPath?: string }) {
  const [qc] = useState(makeQueryClient)
  const [router] = useState(() => (initialPath ? createMemoryRouter(buildRoutes(), { initialEntries: [initialPath] }) : createBrowserRouter(buildRoutes())))
  const restarting = useBoxRestarting()
  useEffect(() => resetBoxRestart, [])
  return (
    <QueryClientProvider client={qc}>
      {restarting ? <BoxRestarting /> : <RouterProvider router={router} />}
      <Toaster position="bottom-right" toastOptions={{ className: '!rounded-md !border !border-rule !bg-surface !text-ink !font-sans', classNames: { title: '!text-ink', description: '!text-muted' } }}
        style={{ '--normal-bg': 'var(--surface)', '--normal-text': 'var(--ink)', '--normal-border': 'var(--rule)' } as CSSProperties} />
    </QueryClientProvider>
  )
}
