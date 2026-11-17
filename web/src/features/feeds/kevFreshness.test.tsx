import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { fmtWhen } from './dates'

// kien G11: Home's "Newly exploited" board read as a list that ran once at install. It says how often the box checks CISA's list,
// when it last did (the reader's time), CISA's own last addition, a failed check with the last good pull, and a list never pulled.
// #938 review r1: a fixed zone (Ho Chi Minh, UTC+7) and a fixed "now", so the run never straddles midnight or depends on the runner.
const ZONE = 'Asia/Ho_Chi_Minh'
const NOW = new Date('2026-11-17T05:00:00Z') // 12:00 in Ho Chi Minh
const T = { timeout: 5000 }
const SOURCES = [{ name: 'CISA KEV', url: 'https://www.cisa.gov/kev', license: 'CC0', fetched_at: '2026-11-17T03:54:00Z' }]
let zoneBefore: string | undefined

beforeAll(() => { zoneBefore = process.env.TZ; process.env.TZ = ZONE })
afterAll(() => { if (zoneBefore === undefined) delete process.env.TZ; else process.env.TZ = zoneBefore })
beforeEach(() => {
  vi.useFakeTimers({ now: NOW, toFake: ['Date'] })
  return () => vi.useRealTimers()
})

function status(kev: Record<string, unknown>, generatedAt = '2026-11-17T03:54:00Z') {
  server.use(http.get('*/api/v1/feeds/status', () => HttpResponse.json({ generated_at: generatedAt, kev_catalog_version: '2026.11.13', sources: SOURCES, inventory_on: true, kev })))
}
const latest = () => server.use(http.get('*/api/v1/feeds/hot', ({ request }) => HttpResponse.json({ window: new URL(request.url).searchParams.get('window'), rows: [], latest: { cve: 'CVE-2026-99001', date_added: '2026-11-13', display: 'Check Point Multiple Products' } })))

describe('Home: how fresh the exploited list is (kien G11)', () => {
  it('times are the reader\'s: the hour alone today, the date otherwise', () => {
    expect(fmtWhen('2026-11-17T03:54:00Z', NOW)).toBe('10:54') // 03:54 UTC is 10:54 in Ho Chi Minh
    expect(fmtWhen('2026-11-16T17:30:00Z', NOW)).toBe('00:30') // still today there, yesterday in UTC
    expect(fmtWhen('2026-11-13T02:05:00Z', NOW)).toBe('13 Nov 2026, 09:05')
  })

  it('checked every hour, the last check in local time, and CISA\'s last addition', async () => {
    status({ state: 'loaded', error: null, interval_hours: 1, checked_at: '2026-11-17T03:54:00Z', last_success: '2026-11-17T03:54:00Z' })
    latest()
    renderApp('/')
    expect(await screen.findByText('Checked every hour, last at 10:54. CISA\'s last addition: 13 Nov 2026, Check Point Multiple Products.', undefined, T)).toBeInTheDocument()
  })

  it('a failed check says so plainly, keeps the cadence, the last good pull, CISA\'s last addition and the way to the feed settings', async () => {
    status({ state: 'loaded', error: 'cisa.gov answered HTTP 503', interval_hours: 1, checked_at: '2026-11-17T04:54:00Z', last_success: '2026-11-13T02:05:00Z' }, '2026-11-13T02:05:00Z')
    latest()
    renderApp('/')
    const line = await screen.findByText(/^Checked every hour; the last check, at 11:54, failed: cisa\.gov answered HTTP 503\. Vedette keeps trying\./, undefined, T)
    expect(line).toHaveTextContent('The list shown is from the last good pull, at 13 Nov 2026, 09:05. CISA\'s last addition: 13 Nov 2026, Check Point Multiple Products.')
    expect(line.querySelector('a')).toHaveAttribute('href', '/settings/feeds#feed-cisa-kev')
  })

  // kien G13 (D-91 as amended): both copies of the CISA list are asked every check; Home says which one the newest list came from, and a
  // copy that failed alone is a quiet note (cisa.gov answers 403 to Vietnamese addresses)
  const copies = (cisa: string | null, mirror: string | null) => [
    { name: 'CISA', url: 'https://www.cisa.gov/kev.json', checked_at: '2026-11-17T03:54:00Z', error: cisa, catalog_version: cisa ? null : '2026.11.17' },
    { name: 'CISA GitHub mirror', url: 'https://raw.githubusercontent.com/cisagov/kev-data/develop/kev.json', checked_at: '2026-11-17T03:54:00Z', error: mirror, catalog_version: mirror ? null : '2026.11.17' },
  ]
  it('says the newest list came from CISA\'s GitHub copy, with cisa.gov\'s refusal as a quiet note', async () => {
    status({ state: 'loaded', error: null, interval_hours: 1, checked_at: '2026-11-17T03:54:00Z', last_success: '2026-11-17T03:54:00Z', answered_by: 'CISA GitHub mirror', copies: copies('cisa.gov refused this box (HTTP 403)', null) })
    latest()
    renderApp('/')
    const line = await screen.findByText(/^Checked every hour at cisa\.gov and at CISA's GitHub copy, last at 10:54; the newest list came from CISA's GitHub copy\./, undefined, T)
    expect(line).toHaveTextContent('At that check cisa.gov refused this box (HTTP 403); the other copy answered. CISA\'s last addition: 13 Nov 2026, Check Point Multiple Products.')
    expect(line).not.toHaveClass('text-danger') // a note, not an alarm
  })

  it('says the newest list came from cisa.gov, with no note when both copies answered', async () => {
    status({ state: 'loaded', error: null, interval_hours: 1, checked_at: '2026-11-17T03:54:00Z', last_success: '2026-11-17T03:54:00Z', answered_by: 'CISA', copies: copies(null, null) })
    latest()
    renderApp('/')
    expect(await screen.findByText('Checked every hour at cisa.gov and at CISA\'s GitHub copy, last at 10:54; the newest list came from cisa.gov. CISA\'s last addition: 13 Nov 2026, Check Point Multiple Products.', undefined, T)).toBeInTheDocument()
  })

  it('both copies failing: the failure with both reasons, and since when the list is stale', async () => {
    status({ state: 'loaded', error: 'cisa.gov refused this box (HTTP 403), and CISA\'s GitHub copy answered HTTP 502', interval_hours: 1, checked_at: '2026-11-17T04:54:00Z', last_success: '2026-11-16T21:05:00Z', answered_by: 'CISA GitHub mirror', copies: copies('cisa.gov refused this box (HTTP 403)', 'CISA\'s GitHub copy answered HTTP 502') }, '2026-11-16T21:05:00Z')
    renderApp('/')
    const line = await screen.findByText(/^Checked every hour; the last check, at 11:54, failed: cisa\.gov refused this box \(HTTP 403\), and CISA's GitHub copy answered HTTP 502\. Vedette keeps trying\./, undefined, T)
    expect(line).toHaveTextContent('The list shown is from the last good pull, at 04:05.')
  })

  it('never pulled: it says the first check has not run yet', async () => {
    status({ state: 'never_loaded', error: null, interval_hours: 1, checked_at: null, last_success: null }, '1970-01-01T00:00:00Z')
    renderApp('/')
    expect(await screen.findByText(/Checked every hour; the first check has not run yet\./, undefined, T)).toBeInTheDocument()
  })

  it('never loaded and failing: the board\'s notice says why, when it last tried and how often', async () => {
    status({ state: 'never_loaded', error: 'cisa.gov answered HTTP 403', interval_hours: 1, checked_at: '2026-11-17T04:54:00Z', last_success: null }, '1970-01-01T00:00:00Z')
    renderApp('/')
    expect((await screen.findAllByText(/The CISA list could not be fetched yet: cisa\.gov answered HTTP 403\. Last tried at 11:54; it is checked every hour\./, undefined, T)).length).toBeGreaterThan(0)
  })
})
