import { afterEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import { useMe } from './session'

// N44-2: a release build asks /me only when the session's readable CSRF cookie is there, so a signed-out page load logs no 401.
describe('useMe in the release build (VITE_API_MOCK=off)', () => {
  afterEach(() => {
    vi.unstubAllEnvs()
    document.cookie = '__Host-vedette_csrf=; Path=/; Secure; Max-Age=0'
  })
  const asked = () => {
    const urls: string[] = []
    server.events.on('request:start', ({ request }) => { if (new URL(request.url).pathname === '/api/v1/me') urls.push(request.url) })
    return urls
  }
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={makeQueryClient()}>{children}</QueryClientProvider>

  it('without the cookie: signed out, /me is not asked', async () => {
    vi.stubEnv('VITE_API_MOCK', 'off')
    const urls = asked()
    const { result } = renderHook(() => useMe(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data).toBeNull()
    expect(urls).toHaveLength(0)
    server.events.removeAllListeners()
  })

  it('with the cookie: /me is asked and answers who is signed in', async () => {
    vi.stubEnv('VITE_API_MOCK', 'off')
    document.cookie = '__Host-vedette_csrf=t; Path=/; Secure'
    sessionStore.set({ userId: 'u-admin' })
    const urls = asked()
    const { result } = renderHook(() => useMe(), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(urls).toHaveLength(1)
    expect(result.current.data?.email).toBeTruthy()
    server.events.removeAllListeners()
  })
})
