import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'

// kien G11: Home's "Newly exploited" board read as a list that ran once at install. It says how often the box checks CISA's list,
// when it last did (the reader's time), CISA's own last addition, a failed check with the last good pull, and a list never pulled.
const T = { timeout: 5000 }
const today = (h: number, m: number) => { const d = new Date(); d.setHours(h, m, 0, 0); return d.toISOString() }
const local = (y: number, mo: number, d: number, h: number, m: number) => new Date(y, mo - 1, d, h, m).toISOString()
const SOURCES = [{ name: 'CISA KEV', url: 'https://www.cisa.gov/kev', license: 'CC0', fetched_at: today(10, 54) }]

function status(kev: Record<string, unknown>, generatedAt = today(10, 54)) {
  server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: generatedAt, kev_catalog_version: '2026.11.13', sources: SOURCES, inventory_on: true, kev })))
}
const latest = () => server.use(http.get('*/api/v1/feeds/hot', ({ request }) => HttpResponse.json({ window: new URL(request.url).searchParams.get('window'), rows: [], latest: { cve: 'CVE-2026-99001', date_added: '2026-11-13', display: 'Check Point Multiple Products' } })))

describe('Home: how fresh the exploited list is (kien G11)', () => {
  it('checked every hour, the last check in local time, and CISA\'s last addition', async () => {
    status({ state: 'loaded', error: null, interval_hours: 1, checked_at: today(10, 54), last_success: today(10, 54) })
    latest()
    renderApp('/')
    expect(await screen.findByText('Checked every hour, last at 10:54. CISA\'s last addition: 13 Nov 2026, Check Point Multiple Products.', undefined, T)).toBeInTheDocument()
  })

  it('a failed check says so plainly, with the last good pull and the way to the feed settings', async () => {
    status({ state: 'loaded', error: 'cisa.gov answered HTTP 503', interval_hours: 1, checked_at: today(11, 54), last_success: local(2026, 11, 13, 9, 5) }, local(2026, 11, 13, 9, 5))
    latest()
    renderApp('/')
    const line = await screen.findByText(/The last check of CISA's list, at 11:54, failed: cisa\.gov answered HTTP 503\./, undefined, T)
    expect(line).toHaveTextContent('The list shown is from the last good pull, at 13 Nov 2026, 09:05.')
    expect(line.querySelector('a')).toHaveAttribute('href', '/settings/feeds#feed-cisa-kev')
  })

  it('never pulled: it says the first check has not run yet', async () => {
    status({ state: 'never_loaded', error: null, interval_hours: 1, checked_at: null, last_success: null }, '1970-01-01T00:00:00Z')
    renderApp('/')
    expect(await screen.findByText(/Checked every hour; the first check has not run yet\./, undefined, T)).toBeInTheDocument()
  })
})
