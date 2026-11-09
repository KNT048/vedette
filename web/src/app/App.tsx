import { useState, type CSSProperties } from 'react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { RouterProvider, createBrowserRouter, createMemoryRouter } from 'react-router'
import { Toaster } from 'sonner'
import { buildRoutes } from './router'

export function makeQueryClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: import.meta.env.MODE === 'test' ? false : 1, refetchOnWindowFocus: false, notifyOnChangeProps: 'all' }, mutations: { retry: 0 } } })
}

export function App({ initialPath }: { initialPath?: string }) {
  const [qc] = useState(makeQueryClient)
  const [router] = useState(() => (initialPath ? createMemoryRouter(buildRoutes(), { initialEntries: [initialPath] }) : createBrowserRouter(buildRoutes())))
  return (
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
      <Toaster position="bottom-right" toastOptions={{ className: '!rounded-md !border !border-rule !bg-surface !text-ink !font-sans', classNames: { title: '!text-ink', description: '!text-muted' } }}
        style={{ '--normal-bg': 'var(--surface)', '--normal-text': 'var(--ink)', '--normal-border': 'var(--rule)' } as CSSProperties} />
    </QueryClientProvider>
  )
}
