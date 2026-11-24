import { describe, expect, it } from 'vitest'
import type { ReactNode } from 'react'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { useDeviceAction } from './api'

const BASE = `${location.origin}/api/v1/inventory`

// A person's change on a device (a corrected version, Undo of a correction) answers as soon as that device is read again: the row
// shows the new value when the toast appears. The lists and the findings pages are read again too, but a slow one (the findings of a
// box with hundreds of lines) never holds the toast and the row back.
describe('device actions: the answer waits for the device only', () => {
  it('Save resolves with the device read again while a findings page is still loading', async () => {
    let version = '4.8'
    server.use(
      http.patch(`${BASE}/devices/a-box/software/s-1`, async ({ request }) => { version = ((await request.json()) as { version: string }).version; return HttpResponse.json({ ok: true }) }),
      http.get(`${BASE}/devices/a-box`, () => HttpResponse.json({ asset: { id: 'a-box', software: [{ id: 's-1', version }] } })),
    )
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    const { result } = renderHook(() => {
      const device = useQuery({ queryKey: ['inventory', 'device', 'a-box'], queryFn: () => fetch(`${BASE}/devices/a-box`).then((r) => r.json() as Promise<{ asset: { software: { version: string }[] } }>) })
      useQuery({ queryKey: ['findings', 'slow'], queryFn: () => new Promise<never>(() => {}) }) // never answers
      return { device, act: useDeviceAction('a-box') }
    }, { wrapper })
    await waitFor(() => expect(result.current.device.data?.asset.software[0]?.version).toBe('4.8'))
    await result.current.act.correct.mutateAsync({ sid: 's-1', version: '4.9' })
    expect(qc.getQueryData<{ asset: { software: { version: string }[] } }>(['inventory', 'device', 'a-box'])?.asset.software[0]?.version).toBe('4.9')
  })
})
