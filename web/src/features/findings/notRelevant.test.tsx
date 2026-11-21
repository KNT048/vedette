import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { findingsStore } from '@/mocks/stores'
import { withoutNotRelevant } from './notRelevant'

// findings closed as not relevant are hidden by default wherever findings are listed; "Show not relevant (N)" brings them back.
const T = { timeout: 5000 }
/** The device page's list from before the findings model: what a backend that answers the model's reads 501 shows. */
const beforeModel = () => server.use(http.get('*/api/v1/findings/devices', () => HttpResponse.json({ error: { code: 'not_implemented', message: 'Not built yet.' } }, { status: 501 })))
/** Every finding of the first device: one open, one patched, `n` not relevant. Returns the device id and its CVEs by status. */
function seed(n: number) {
  const all = findingsStore.get()
  const dev = all[0]!.asset_id
  const tpl = all[0]!
  const rows = [
    { ...tpl, id: 'g5-open', cve: 'CVE-2026-50001', status: 'suspected' as const },
    { ...tpl, id: 'g5-patched', cve: 'CVE-2026-50002', status: 'patched' as const },
    ...Array.from({ length: n }, (_, i) => ({ ...tpl, id: `g5-nr-${i}`, cve: `CVE-2026-6000${i}`, status: 'not_relevant' as const })),
  ]
  findingsStore.set([...all.filter((f) => f.asset_id !== dev), ...rows])
  return dev
}

describe('not relevant is hidden by default', () => {
  it('withoutNotRelevant: hides them and says how many; shown keeps all', () => {
    const rows = [{ status: 'suspected' }, { status: 'not_relevant' }, { status: 'patched' }, { status: 'not_relevant' }] as const
    expect(withoutNotRelevant(rows, false)).toEqual({ rows: [rows[0], rows[2]], hidden: 2, total: 2 })
    expect(withoutNotRelevant(rows, true)).toMatchObject({ hidden: 0, total: 2 })
    expect(withoutNotRelevant(rows, true).rows).toHaveLength(4)
  })

  it('device page: "Findings on this device" lists open and handled, not the not relevant ones, until the toggle', async () => {
    const dev = seed(3)
    beforeModel()
    renderApp(`/devices/${encodeURIComponent(dev)}?tab=findings`)
    const section = (await screen.findByRole('heading', { level: 2, name: 'Findings on this device' }, T)).closest('section')!
    const rows = () => within(section).getByRole('list', { name: 'Every finding of this device' }) // Below the To fix card
    expect(await within(section).findByRole('list', { name: 'Every finding of this device' }, T)).toBeInTheDocument()
    expect(within(rows()).getByRole('link', { name: 'CVE-2026-50001' })).toBeInTheDocument()
    expect(within(rows()).getByRole('link', { name: 'CVE-2026-50002' })).toBeInTheDocument()
    expect(within(rows()).queryByRole('link', { name: 'CVE-2026-60000' })).toBeNull()
    await userEvent.click(within(section).getByRole('button', { name: 'Show not relevant (3)' }))
    expect(within(rows()).getByRole('link', { name: 'CVE-2026-60000' })).toBeInTheDocument()
    expect(within(section).getByRole('button', { name: 'Hide not relevant (3)' })).toHaveAttribute('aria-pressed', 'true')
    // the tab counts the open findings
    expect(screen.getByRole('tab', { name: /^Findings 1/ })).toBeInTheDocument()
  })

  it('device page with no finding not relevant: no toggle at all', async () => {
    const dev = seed(0)
    beforeModel()
    renderApp(`/devices/${encodeURIComponent(dev)}?tab=findings`)
    const section = (await screen.findByRole('heading', { level: 2, name: 'Findings on this device' }, T)).closest('section')!
    const rows = await within(section).findByRole('list', { name: 'Every finding of this device' }, T)
    expect(within(rows).getByRole('link', { name: 'CVE-2026-50001' })).toBeInTheDocument()
    expect(within(section).queryByRole('button', { name: /not relevant/ })).toBeNull()
  })

})
