import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { eventsWindowFor } from './LogsPage'

// Connections to bad IPs or domains: one row per device and destination, grouped, searched, ordered and paged by the box; the
// destination opens the Events tab on its log lines.
vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const table = () => screen.findByRole('table', { name: 'Connections to bad IPs or domains' }, T)
const dests = async () => within(await table()).getAllByRole('link', { name: /^Show the log lines of / }).map((a) => a.textContent)
const range = () => screen.getAllByRole('status').map((s) => s.textContent ?? '').find((x) => /of \d+/.test(x)) ?? ''

describe('logs: connections to bad addresses, one row per device and destination', () => {
  it('lists the week grouped by the box with hits, first and last seen and "also from N other devices", 25 a page', async () => {
    const asked: string[] = []
    server.events.on('request:start', ({ request }) => { if (request.url.includes('/logs/bad-connections')) asked.push(new URL(request.url).search) })
    renderApp('/logs')
    await table()
    expect(asked[0]).toBe('?window=7d&q=&sort=last&offset=0&limit=25')
    expect(await dests()).toHaveLength(25)
    expect(range()).toMatch(/^1–25 of \d+$/)
    const row = within(await table()).getAllByRole('row').find((r) => within(r).queryByText('198.51.100.11'))!
    expect(within(row).getByText(/^also from \d+ other devices?$/)).toBeInTheDocument()
    expect(within(row).getByText(/^first /)).toBeInTheDocument()
    server.events.removeAllListeners()
  })

  it('searches on the box over device, destination and feed, goes back to page 1 and keeps it in the URL', async () => {
    const user = userEvent.setup()
    renderApp('/logs?bad.page=2')
    await waitFor(() => expect(range()).toMatch(/^26–50 of/), T)
    await user.type(screen.getByRole('searchbox', { name: 'Search device, destination or feed' }), '198.51.100.11')
    await waitFor(async () => expect(new Set(await dests())).toEqual(new Set(['198.51.100.11'])), T)
    expect(range()).toMatch(/^1–\d of \d$/)
    await user.clear(screen.getByRole('searchbox', { name: 'Search device, destination or feed' }))
    await user.type(screen.getByRole('searchbox', { name: 'Search device, destination or feed' }), 'feodo')
    await waitFor(async () => expect((await dests()).every((d) => /^198\.51\.100\.(\d+)$/.test(d ?? '') && Number(d!.split('.')[3]) % 4 === 2)).toBe(true), T)
  })

  it('jumps to the last page with the pager above or below, and orders by most hits', async () => {
    const user = userEvent.setup()
    renderApp('/logs')
    await table()
    const total = Number(/of (\d+)/.exec(range())![1])
    await user.click(within(screen.getByRole('navigation', { name: 'Pages of Connections to bad IPs or domains, below the list' })).getByRole('button', { name: 'Last page' }))
    await waitFor(() => expect(range()).toBe(`${Math.floor((total - 1) / 25) * 25 + 1}–${total} of ${total}`), T)
    await user.selectOptions(screen.getByRole('combobox', { name: 'Order' }), 'hits')
    await waitFor(() => expect(range()).toMatch(/^1–25 of/), T)
    const hits = within(await table()).getAllByRole('row').slice(1).map((r) => Number(r.querySelectorAll('td')[2]?.textContent))
    expect(hits).toEqual([...hits].sort((a, b) => b - a))
  })

  it('the destination opens the Events tab with the keyword and a range from its first hit; reload keeps them', async () => {
    const user = userEvent.setup()
    const seen: string[] = []
    server.use(http.get('*/api/v1/logs/events', ({ request }) => { seen.push(new URL(request.url).search); return HttpResponse.json({ events: [], total: 0, next_cursor: null }) }))
    const v = renderApp('/logs?bad.window=24h')
    await user.click(within(await table()).getByRole('link', { name: 'Show the log lines of 45.148.10.95' }))
    expect(await screen.findByRole('tab', { name: 'Events', selected: true }, T)).toBeInTheDocument()
    expect(await screen.findByLabelText('Keyword', undefined, T)).toHaveValue('45.148.10.95')
    expect(screen.getByRole('button', { name: '24 hours', pressed: true })).toBeInTheDocument()
    await waitFor(() => expect(seen.at(-1)).toBe('?window=24h&source=&q=45.148.10.95'), T)
    v.unmount()
    renderApp('/logs?tab=events&events.q=45.148.10.95&events.window=7d')
    expect(await screen.findByLabelText('Keyword', undefined, T)).toHaveValue('45.148.10.95')
    expect(screen.getByRole('button', { name: '7 days', pressed: true })).toBeInTheDocument()
  })

  it('the range of the Events link is the smallest that reaches the first hit', () => {
    const now = Date.parse('2026-11-18T12:00:00Z')
    expect(eventsWindowFor('2026-11-18T11:30:00Z', now)).toBe('1h')
    expect(eventsWindowFor('2026-11-18T01:00:00Z', now)).toBe('24h')
    expect(eventsWindowFor('2026-11-12T01:00:00Z', now)).toBe('7d')
  })
})
