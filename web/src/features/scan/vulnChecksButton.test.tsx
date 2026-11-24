import { describe, expect, it } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { http, HttpResponse } from 'msw'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import { VulnChecksButton } from './VulnChecksButton'
import type { ScanTarget } from './types'

// Every button that starts vulnerability checks says what the run will check, sends only the devices with something to check, and with
// nothing to check says so and starts nothing (the box's rule, read from GET /scans/targets).
const target = (id: string, c: Partial<Pick<ScanTarget, 'suspected' | 'checkable' | 'again' | 'pick_only'>>): ScanTarget => ({
  id, kind: 'internal', device_kind: 'server', label: id.toUpperCase(), ip: '192.0.2.10', fragile: false, findings: 0, selectable: true, pick_only: false,
  box: false, reason: null, mac: null, vendor: null, approved: true, last_seen: null, suspected: 0, checkable: 0, again: 0, ...c,
})

function renderButton(node: React.ReactNode, items: ScanTarget[]) {
  sessionStore.set({ userId: 'u-op' })
  server.use(http.get('*/api/v1/scans/targets', () => HttpResponse.json({ items })))
  const sent: string[][] = []
  server.use(http.post('*/api/v1/scans/runs', async ({ request }) => {
    sent.push(((await request.json()) as { targets: string[] }).targets)
    return HttpResponse.json({ id: 'run-x', trigger: 'manual', trigger_note: null, started_at: '2026-11-24T03:00:00.000Z', started_by: 'op@acme.example', ended_at: null,
      status: 'running', total: 1, done: 0, current: null, progress: null, results: [], matched: 0, stop_reason: null, identification: [] }, { status: 201 })
  }))
  const router = createMemoryRouter([{ path: '*', element: node }], { initialEntries: ['/settings/scanning'] })
  render(<QueryClientProvider client={makeQueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
  return sent
}

describe('the vulnerability check button follows the count', () => {
  it('the LAN: "Check N suspected findings on M devices", the devices with nothing to check left out and said', async () => {
    const sent = renderButton(<VulnChecksButton targets="lan" />, [
      target('a-1', { suspected: 2, checkable: 2 }),
      target('a-2', { suspected: 3, checkable: 1 }),
      target('a-3', { suspected: 4 }), // no safe check for any of its findings
      target('a-4', { suspected: 1, checkable: 1, pick_only: true }), // only a person's own pick: never in the LAN run
    ])
    const button = await screen.findByRole('button', { name: 'Check 3 suspected findings on 2 devices' }, { timeout: 4000 })
    expect(screen.getByText('1 device with nothing to check is left out.')).toBeInTheDocument()
    await waitFor(() => expect(button).toBeEnabled())
    await userEvent.click(button)
    await waitFor(() => expect(sent).toEqual([['a-1', 'a-2']]))
  })

  it('nothing to check: says so, no button, nothing starts', async () => {
    const sent = renderButton(<VulnChecksButton targets="lan" />, [target('a-1', { suspected: 2 }), target('a-2', { suspected: 1 })])
    expect(await screen.findByText('Nothing to check: no safe check exists for your findings yet.', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
    expect(sent).toEqual([])
  })

  it('no open finding at all: says there is nothing waiting for a check', async () => {
    renderButton(<VulnChecksButton targets="lan" />, [target('a-1', {})])
    expect(await screen.findByText('Nothing to check: no open finding is waiting for a safe check.', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByRole('button')).toBeNull()
  })

  it('a selection: confirmed findings checked again are named as such; one device of its own page drops "on 1 device"', async () => {
    const sent = renderButton(<VulnChecksButton targets={['a-1', 'a-2']} />, [target('a-1', { again: 2 }), target('a-2', { suspected: 1 })])
    const button = await screen.findByRole('button', { name: 'Check 2 confirmed findings again on 1 device' }, { timeout: 4000 })
    await waitFor(() => expect(button).toBeEnabled())
    await userEvent.click(button)
    await waitFor(() => expect(sent).toEqual([['a-1']]))
  })

  it('one device on its own page', async () => {
    renderButton(<VulnChecksButton targets={['a-1']} here />, [target('a-1', { suspected: 3, checkable: 1, again: 1 })])
    expect(await screen.findByRole('button', { name: 'Check 1 suspected and 1 confirmed findings' }, { timeout: 4000 })).toBeInTheDocument()
  })
})
