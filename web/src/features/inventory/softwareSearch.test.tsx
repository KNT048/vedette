import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { ensureBox } from './mocks'

// The list carries no software lines: the search's software: words are answered by GET /inventory/devices?software=. While that
// answer is on its way, or when it fails, the list must not say that no device runs the software.

vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
afterEach(() => { server.events.removeAllListeners() })

const DEVICES = `${location.origin}/api/v1/inventory/devices`
const T = { timeout: 5000 }
const NO_MATCH = 'No rows match these filters.'
const softwareAsked = (r: Request) => r.method === 'GET' && new URL(r.url).pathname.endsWith('/inventory/devices') && new URL(r.url).searchParams.has('software')

describe('Devices search, software: answered by the server', () => {
  it('while the first answer is read, the list says it is looking, never that nothing matches', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    // hold the software answer; any other list read goes on to the mock API
    server.use(http.get(DEVICES, async ({ request }) => { if (softwareAsked(request)) await gate }))
    renderApp('/devices?q=software:openssh')
    const table = await screen.findByRole('table', { name: 'Device list' }, T)
    expect(await within(table).findByText('Looking for this software…', undefined, T)).toBeInTheDocument()
    expect(within(table).queryByText(NO_MATCH)).toBeNull()
    release()
    await waitFor(() => expect(within(table).queryByText('Looking for this software…')).toBeNull(), T)
    // the answer in: the devices that run it, each with its matched line
    expect(within(table).getByRole('columnheader', { name: 'Matched software' })).toBeInTheDocument()
    expect(within(table).getAllByText(/^OpenSSH/).length).toBeGreaterThan(0)
    expect(within(table).queryByText(NO_MATCH)).toBeNull()
  })

  it('a software answer that fails is shown as the error, not as "no match"', async () => {
    server.use(http.get(DEVICES, ({ request }) => (softwareAsked(request)
      ? HttpResponse.json({ error: { code: 'x', message: 'The box is not responding.' } }, { status: 503 })
      : undefined)))
    renderApp('/devices?q=software:openssh')
    const table = await screen.findByRole('table', { name: 'Device list' }, T)
    expect(await within(table).findByText('The box is not responding.', undefined, T)).toBeInTheDocument()
    expect(within(table).queryByText(NO_MATCH)).toBeNull()
  })

  it('typing a software name asks the server once the typing pauses, not on every key', async () => {
    const user = userEvent.setup()
    const asked: string[] = []
    server.events.on('request:start', ({ request }) => { if (softwareAsked(request)) asked.push(new URL(request.url).searchParams.get('software')!) })
    renderApp('/devices')
    await screen.findByRole('table', { name: 'Device list' }, T)
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'software:openssh')
    await waitFor(() => expect(asked).toContain('openssh'), T)
    expect(asked.length, `asked for ${asked.join(', ')}`).toBeLessThanOrEqual(2)
  })
})
