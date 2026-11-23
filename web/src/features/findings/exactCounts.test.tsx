// The counts and lists read from By device and Needs your input outside the Findings screen are exact on a network with more
// devices, or a device with more queue items, than one page holds.
import type { ReactNode } from 'react'
import { describe, expect, it } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import { useAllInput, useCveFindings, useOpenFindingsOf } from './api'
import { PAGE_MAX } from './contract'

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>
}
const card = (id: string, findings: number, cve = 'CVE-2026-1001') => ({
  device: { id, name: id }, findings,
  blocks: [{ findings: Array.from({ length: findings }, (_, i) => ({ id: `${id}-${i}`, cve })) }],
})

describe('exact counts beyond one page', () => {
  it('counts the open findings of 250 devices with one request per page of ids', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const asked: string[][] = []
    server.use(http.get('*/api/v1/findings/devices', ({ request }) => {
      const ids = new URL(request.url).searchParams.get('devices')?.split(',') ?? []
      asked.push(ids)
      return HttpResponse.json({ items: ids.filter((id) => id.endsWith('7')).map((id) => card(id, 2)), total: 0, findings: 0 })
    }))
    const ids = Array.from({ length: 250 }, (_, i) => `a-${String(i).padStart(3, '0')}`)
    const { result } = renderHook(() => useOpenFindingsOf(ids), { wrapper })
    await waitFor(() => expect(result.current.data).toBeDefined())
    expect(asked.map((a) => a.length)).toEqual([PAGE_MAX, PAGE_MAX, 50])
    expect(result.current.data?.get('a-247')).toBe(2)
    expect(result.current.data?.size).toBe(25)
  })

  it('lists the devices of one CVE across every page', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const total = 230
    server.use(http.get('*/api/v1/findings/devices', ({ request }) => {
      const p = new URL(request.url).searchParams
      expect(p.get('cve')).toBe('CVE-2026-1001')
      const off = Number(p.get('offset') ?? 0)
      const items = Array.from({ length: Math.max(0, Math.min(PAGE_MAX, total - off)) }, (_, i) => card(`a-${off + i}`, 1))
      return HttpResponse.json({ items, total, findings: total })
    }))
    const { result } = renderHook(() => useCveFindings('CVE-2026-1001'), { wrapper })
    await waitFor(() => expect(result.current.query.isSuccess).toBe(true))
    expect(result.current.hits).toHaveLength(total)
  })

  it('reads a device queue longer than one page', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const total = 130
    server.use(http.get('*/api/v1/findings/input', ({ request }) => {
      const off = Number(new URL(request.url).searchParams.get('offset') ?? 0)
      const items = Array.from({ length: Math.max(0, Math.min(PAGE_MAX, total - off)) }, (_, i) => ({ kind: 'unconfirmed', id: `f-${off + i}` }))
      return HttpResponse.json({ items, total })
    }))
    const { result } = renderHook(() => useAllInput('a-1'), { wrapper })
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.items).toHaveLength(total)
  })
})
