// Settings → Diagnostics: the decision coverage of the last match pass, for an admin. One table: what decided the pairs, by source,
// and why the rest is undecided, by reason; the shares of the whole and the software lines by how they are identified above it.
import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { API } from '@/mocks/http'
import { coverageRows, share } from './coverage'

const T = { timeout: 8000 }

describe('Settings → Diagnostics', () => {
  it('lists the decided pairs by source and the undecided by reason, with the shares of the whole', async () => {
    renderApp('/settings/diagnostics')
    const table = await screen.findByRole('table', { name: 'Decision coverage of the last match pass' }, T)
    const rows = within(table).getAllByRole('row').slice(1)
    expect(rows[0]).toHaveTextContent(/^DecidedDistribution data41239,87040,28284%$/)
    // each cause keeps the matcher's own reasons for its pairs, so the record shapes behind it stay visible
    expect(within(table).getByRole('row', { name: /^Undecided Version or build needed/ })).toHaveTextContent(/^UndecidedVersion or build neededNo version 402 · Platform unknown 164180\.9%$/)
    expect(within(table).getByRole('row', { name: /the distribution's data has no word/ })).toHaveTextContent(/^UndecidedUnnamed: the distribution's data has no word310\.1%$/)
    expect(screen.getByText(/^Decided 98\.2% · Undecided 1\.8% · Unnamed 0\.1%$/)).toBeInTheDocument()
    expect(screen.getByText(/^Last match pass .*: 12 devices, 2,140 software lines, 47,940 pairs\.$/)).toBeInTheDocument()
    expect(screen.getByText('Software lines by identity: stated by the source 1,795, product catalogue 61, own name 23, not identified 261.')).toBeInTheDocument()
  })

  it('says so before the first pass', async () => {
    server.use(http.get(`${API}/findings/coverage`, () => HttpResponse.json({ at: null, devices: 0, lines: 0, pairs: 0, decided: [], possible: [],
      identity: [{ method: 'stated', lines: 0 }, { method: 'catalogue', lines: 0 }, { method: 'record', lines: 0 }, { method: 'none', lines: 0 }] })))
    renderApp('/settings/diagnostics')
    expect(await screen.findByText(/^No match pass has been counted yet\./, {}, T)).toBeInTheDocument()
  })

  it('is for an admin only', async () => {
    renderApp('/settings/diagnostics', { role: 'operator' })
    expect(await screen.findByText('Diagnostics needs a higher role', {}, T)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'Decision coverage of the last match pass' })).toBeNull()
  })

  it('orders decided rows before undecided ones and counts a share of nothing as 0', () => {
    const rows = coverageRows({ at: null, devices: 0, lines: 0, pairs: 3, decided: [{ by: 'nvd', affected: 1, not_affected: 1 }], possible: [{ cause: 'other_dropped', count: 1, details: [] }], identity: [] })
    expect(rows.map((r) => [r.outcome, r.name, r.pairs])).toEqual([['decided', 'nvd', 2], ['undecided', 'other_dropped', 1]])
    expect(share(1, 0)).toBe('0%')
    expect(share(1, 3)).toBe('33.3%')
  })
})
