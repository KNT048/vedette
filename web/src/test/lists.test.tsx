// Search and pages on the app's lists, as a person uses them: the shared search box and pager on representative lists of every
// kind (a list the browser filters, one the page filters with its own search, one the box pages and searches). The shared parts
// themselves are tested in components/common/Pager.test.tsx; the list guard (listGuard.test.ts) keeps every list on them.
import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { http, HttpResponse } from 'msw'
import { auditStore, findingsStore } from '@/mocks/stores'

vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const NOHASH = { prev_hash: '', hash: '' }
const range = () => screen.getAllByRole('status').map((s) => s.textContent ?? '').find((x) => /^\d+–\d+ of \d+/.test(x)) ?? ''

describe('lists: the audit log, paged and searched by the box', () => {
  it('asks the box for one page at a time, jumps to page N and to the last page, and searches the whole log', async () => {
    const user = userEvent.setup()
    auditStore.set(Array.from({ length: 260 }, (_, i) => ({ id: `a${i}`, ts: new Date(Date.UTC(2026, 10, 1) + i * 60_000).toISOString(), user: 'bot@acme.example', action: 'scan.run', target: `t${i}`, detail: null, ...NOHASH })).reverse()) // newest first, as the store keeps them
    const asked: string[] = []
    server.events.on('request:start', ({ request }) => { if (new URL(request.url).pathname === '/api/v1/core/audit') asked.push(new URL(request.url).search) })
    renderApp('/settings/audit')
    const table = await screen.findByRole('table', { name: 'Audit log' }, T)
    await waitFor(() => expect(range()).toBe('1–50 of 260'), T)
    expect(asked.at(-1)).toBe('?limit=50')
    await user.type(screen.getAllByLabelText('Go to page')[0]!, '4{Enter}')
    await waitFor(() => expect(range()).toBe('151–200 of 260'), T)
    expect(asked.at(-1)).toBe('?offset=150&limit=50')
    await waitFor(() => expect(within(table).getByText('t109')).toBeInTheDocument(), T)
    await user.click(within(screen.getByRole('navigation', { name: 'Pages of Audit log, below the list' })).getByRole('button', { name: 'Last page' }))
    await waitFor(() => expect(range()).toBe('251–260 of 260'), T)
    // the search runs on the box over every line, then pages: t7 is far down the list
    await user.type(screen.getByLabelText('Search text'), 't7')
    await waitFor(() => expect(asked.at(-1)).toBe('?q=t7&limit=50'), T)
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Audit log' })).getByText('t7')).toBeInTheDocument(), T)
    server.events.removeAllListeners()
  })
})

describe('lists: findings, filtered by the page\'s own search', () => {
  it('the search box filters every finding, is kept in the URL, and the list goes back to page 1', async () => {
    const user = userEvent.setup()
    const base = findingsStore.get()[0]!
    findingsStore.set(Array.from({ length: 130 }, (_, i) => ({ ...base, id: `f-x${i}`, cve: `CVE-2026-${String(10_000 + i)}`, status: 'confirmed' as const })))
    renderApp('/findings?tab=open&findings.page=3')
    await screen.findByRole('table', { name: /findings/i }, T)
    await waitFor(() => expect(range()).toMatch(/^101–130 of 130/), T)
    await user.type(screen.getByRole('searchbox', { name: /Search|Filter/ }), 'CVE-2026-10077')
    await waitFor(() => expect(range()).toBe('1–1 of 1'), T)
  })
})

describe('lists: incidents, filtered in the browser', () => {
  it('a list longer than a page has the search box and the pager; a search keeps only what matches and goes back to page 1', async () => {
    const user = userEvent.setup()
    const many = Array.from({ length: 60 }, (_, k) => ({ id: `in-m${k}`, kind: 'log_anomaly', attempt: false, link: '/logs', title: `Log anomaly ${k}`, devices: [], severity: 'medium', what: 'w', action: 'a',
      first_seen: '2026-11-12T08:00:00.000Z', last_seen: '2026-11-12T08:00:00.000Z', count: 1, status: 'new', handled_by: null, handled_at: null, note: null, sends: [], not_sent: null }))
    server.use(http.get('*/api/v1/notify/incidents', () => HttpResponse.json({ incidents: many })))
    renderApp('/incidents')
    await screen.findByRole('table', { name: 'Incidents' }, T)
    await user.click(within(screen.getByRole('navigation', { name: 'Pages of Incidents, above the list' })).getByRole('button', { name: 'Page 2' }))
    await waitFor(() => expect(range()).toBe('51–60 of 60'), T)
    await user.type(screen.getByRole('searchbox', { name: 'Search Incidents' }), 'Log anomaly 42')
    await waitFor(() => expect(range()).toBe('1–1 of 1 matching (60 in all)'), T)
  })
})
