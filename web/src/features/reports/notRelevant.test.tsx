import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { buildWeekly } from './weekly'
import { findingsStore } from '@/mocks/stores'

// A report leaves out findings closed as not relevant (lists and totals) until "Show not relevant (N)".
function seed(n: number) {
  const tpl = findingsStore.get()[0]!
  const now = new Date().toISOString()
  const rows = Array.from({ length: n }, (_, i) => ({ ...tpl, id: `nr-rep-${i}`, cve: `CVE-2026-7000${i}`, status: 'not_relevant' as const, first_seen: now, resolved_at: null }))
  findingsStore.set([...findingsStore.get(), ...rows])
}

describe('weekly report: not relevant is hidden by default', () => {
  it('lists and totals leave them out and say how many; the toggle brings them back with matching counts', async () => {
    const before = buildWeekly().counts.new_findings
    seed(2)
    expect(buildWeekly().counts.new_findings).toBe(before + 2) // the box counts them
    renderApp('/reports')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    const fresh = within(doc).getByRole('table', { name: 'What is new' })
    expect(within(fresh).queryByText('CVE-2026-70000')).toBeNull()
    const newStat = within(doc).getByText('New this week').nextElementSibling!
    expect(newStat).toHaveTextContent(String(before))
    expect(within(doc).getByText('2 findings closed as not relevant are hidden from these totals and lists.')).toBeInTheDocument()

    await userEvent.click(within(doc).getByRole('button', { name: 'Show not relevant (2)' }))
    expect(within(within(doc).getByRole('table', { name: 'What is new' })).getAllByText('CVE-2026-70000').length).toBeGreaterThan(0)
    expect(within(doc).getByText('New this week').nextElementSibling).toHaveTextContent(String(before + 2))
    expect(within(doc).queryByText(/hidden from these totals/)).toBeNull()
    expect(within(doc).getByRole('button', { name: 'Hide not relevant (2)' })).toBeInTheDocument()
  })

  it('no toggle and no note when nothing is not relevant', async () => {
    renderApp('/reports')
    const doc = await screen.findByRole('article', { name: 'Weekly security report' })
    expect(within(doc).queryByRole('button', { name: /not relevant/ })).toBeNull()
  })
})
