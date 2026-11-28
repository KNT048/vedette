// Research of CVEs Vedette cannot decide: the settings section, the panel on the CVE page and the usage per day. Tokens only, never money.
import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { http, HttpResponse } from 'msw'
import { Toaster } from 'sonner'
import { makeQueryClient } from '@/app/App'
import { server } from '@/test/server'
import { renderApp } from '@/test/render'
import { sessionStore } from '@/mocks/stores'
import AiSettings from './AiSettings'

const FORM = 'Research CVEs Vedette cannot decide'
async function settings() {
  sessionStore.set({ userId: 'u-admin' })
  const qc = makeQueryClient()
  render(<QueryClientProvider client={qc}><MemoryRouter><AiSettings /></MemoryRouter><Toaster /></QueryClientProvider>)
  await waitFor(() => expect(qc.getQueryData(['me'])).toBeTruthy())
  return screen.findByRole('form', { name: FORM })
}
const captured = () => {
  const bodies: Record<string, unknown>[] = []
  server.use(http.put('*/api/v1/ai/config', async ({ request }) => { bodies.push((await request.json()) as Record<string, unknown>); return HttpResponse.json({ error: { code: 'x', message: 'stop' } }, { status: 400 }) }))
  return bodies
}

describe('ai: research settings', () => {
  it('shows the three modes with typical tokens per CVE and saves the chosen mode as research_mode', async () => {
    const form = await settings()
    // a figure only where this box has research runs (the current mode, from the run log); never an invented one
    expect(await within(form).findAllByText(/On this box: about [\d,]+ tokens per CVE \(last 30 days\)/)).toHaveLength(1)
    expect(form.textContent).not.toMatch(/Typically/)
    expect(within(form).getByRole('radio', { name: /Balanced/ })).toBeChecked()
    const bodies = captured()
    await userEvent.click(within(form).getByRole('radio', { name: /Thorough/ }))
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(bodies).toHaveLength(1))
    expect(bodies[0]).toMatchObject({ research_mode: 'thorough', research_share: 50, daily_reads: 300 })
  })

  it('refuses a share outside 1 to 100 and a daily limit outside 1 to 5,000 without calling the box', async () => {
    const form = await settings()
    const bodies = captured()
    const share = within(form).getByLabelText('Share of the monthly token budget')
    await userEvent.clear(share)
    await userEvent.type(share, '101')
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }))
    expect(await within(form).findByText('The share must be a whole number from 1 to 100.')).toBeInTheDocument()
    await userEvent.clear(share)
    await userEvent.type(share, '40')
    const daily = within(form).getByLabelText('Research calls a day')
    await userEvent.clear(daily)
    await userEvent.type(daily, '5001')
    await userEvent.click(within(form).getByRole('button', { name: 'Save' }))
    expect(await within(form).findByText('The number must be a whole number from 1 to 5,000.')).toBeInTheDocument()
    expect(bodies).toHaveLength(0)
  })

  it('says what is sent, shows the share as tokens used and left, and never renders a currency symbol', async () => {
    const form = await settings()
    expect(within(form).getByText('What is sent')).toBeInTheDocument()
    expect(within(form).getByText('%')).toBeInTheDocument()
    expect(within(form).getByText(/Never device names, addresses or users/)).toBeInTheDocument()
    expect(within(form).getByText(/tokens used, .* left\./)).toBeInTheDocument()
    expect(form.textContent).not.toMatch(/[$€£¥₫]/)
    expect(form.textContent).not.toMatch(/\b(USD|EUR|VND|dollars?|cost)\b/i)
  })
})

const ROW = {
  id: 'q1', cve: 'CVE-2022-27593', device: { id: 'd1', name: 'NAS-PHOTOS' }, state: 'possible',
  check: {
    key: 'k1', decided_by: 'ai', verdict: 'affected', confidence: 'likely', reason: '', quote: 'QTS 5.0.1 and earlier are affected; fixed in 5.0.1.2345.',
    sources: [{ url: 'https://vendor.example.com/advisory/qsa-22-29', status: 'ok', cited: true }], model: 'sample-strong', checked_by: 'system', checked_at: '2026-11-27T10:00:00Z', rejected: false,
    reading: {
      status: 'affected', line: '5.0', stated_line: '5.0', introduced: null, fixed_in: '5.0.1.2345', last_affected: null, host: 'vendor.example.com', vendor_page: true, quote_found: true,
      research: {
        layer: 'strong', quote_check: 'live', tokens: 61000,
        detail: {
          mode: 'balanced', verdict: 'affected', confidence: 'medium', basis: 'inferred', fixed_in: '5.0.1.2345', trap: '', note: '', reader: 3, fallback: false,
          fetch: { pages: 1, bytes: 1000, excerpt_chars: 800 },
          steps: [
            { layer: 'quick', model: 'sample-quick', profile: 'Quick', web: 'none', excerpt_chars: 800, tokens_in: 14000, tokens_out: 2000, searches: 0, pages: [], verdict: 'unsure', confidence: 'low', quote_check: '' },
            { layer: 'strong', model: 'sample-strong', profile: 'Strong', web: 'none', excerpt_chars: 800, tokens_in: 40000, tokens_out: 5000, searches: 0, pages: ['https://vendor.example.com/advisory/qsa-22-29'], verdict: 'affected', confidence: 'medium', quote_check: 'live' },
          ],
        },
      },
    },
  },
}

describe('ai: research panel on the CVE page', () => {
  it('shows the verdict, the checked quote with its source link, the model, tokens, the inferred label, and the steps behind one click', async () => {
    server.use(http.get('*/api/v1/findings/possible', () => HttpResponse.json({ items: [ROW, { ...ROW, id: 'q2' }], total: 2, counts: {} })))
    renderApp('/cve/CVE-2022-27593')
    const panel = (await screen.findByRole('heading', { name: 'AI research' }, { timeout: 5000 })).closest('section')!
    expect(within(panel).getByText('Release line 5.0')).toBeInTheDocument()
    expect(within(panel).getByText('2 devices on this line')).toBeInTheDocument()
    expect(within(panel).getByText('Affected')).toBeInTheDocument()
    expect(within(panel).getByText('Fix: 5.0.1.2345')).toBeInTheDocument()
    expect(within(panel).getByText(/QTS 5\.0\.1 and earlier are affected/)).toBeInTheDocument()
    expect(within(panel).getByText('Quote found on the cited page, fetched by Vedette')).toBeInTheDocument()
    expect(within(panel).getByRole('link', { name: 'Source: vendor.example.com' })).toHaveAttribute('href', 'https://vendor.example.com/advisory/qsa-22-29')
    expect(within(panel).getByText('Inferred: from a product that shares its code, not stated for this one')).toBeInTheDocument()
    expect(within(panel).getByText(/sample-strong · 61,000 tokens/)).toBeInTheDocument()
    await userEvent.click(within(panel).getByText('How it decided'))
    expect(within(panel).getByText('1. Quick: unsure')).toBeInTheDocument()
    expect(within(panel).getByText('2. Strong: affected')).toBeInTheDocument()
    expect(panel.textContent).not.toMatch(/[$€£¥₫]/)
  })

  it('a quote the box could not find is said plainly', async () => {
    const bad = structuredClone(ROW)
    bad.check.reading.research.quote_check = 'not_found'
    server.use(http.get('*/api/v1/findings/possible', () => HttpResponse.json({ items: [bad], total: 1, counts: {} })))
    renderApp('/cve/CVE-2022-27593')
    expect(await screen.findByText('Quote not found on any page: this answer decides nothing', undefined, { timeout: 5000 })).toBeInTheDocument()
  })
})

describe('ai: research verdict in customer words', () => {
  it('a reading whose status is fixed reads Not affected, already fixed in the release', async () => {
    const past = structuredClone(ROW)
    past.check.reading.status = 'fixed'
    server.use(http.get('*/api/v1/findings/possible', () => HttpResponse.json({ items: [past], total: 1, counts: {} })))
    renderApp('/cve/CVE-2022-27593')
    const panel = (await screen.findByRole('heading', { name: 'AI research' }, { timeout: 5000 })).closest('section')!
    expect(within(panel).getByText('Not affected')).toBeInTheDocument()
    expect(within(panel).getByText('Already fixed in 5.0.1.2345')).toBeInTheDocument()
    expect(within(panel).queryByText('Fixed')).not.toBeInTheDocument()
  })
})

describe('ai: research tokens per day', () => {
  it('the usage tab lists the research tokens of the last 14 days', async () => {
    renderApp('/assistant?tab=usage')
    const list = await screen.findByRole('list', { name: 'Tokens the research of CVEs used on each of the last 14 days' }, { timeout: 5000 })
    expect(within(list).getAllByRole('listitem')).toHaveLength(14)
    expect(screen.getByText('Research tokens per day')).toBeInTheDocument()
  })
})
