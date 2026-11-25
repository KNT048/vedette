// Needs your input is one collapsed card per device; inside it the questions are grouped by software line, one entry per line with the
// CVEs counted once, and Ignore answers Not affected to a line or to the whole device in one step.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@/lib/i18n'
import { renderApp } from '@/test/render'
import { auditStore } from '@/mocks/stores'
import { questions } from './modelMocks'
import { openNeeds } from './needsTestUtil'

const T = { timeout: 5000 }

/** A device with 3 software lines and 20 questions (one per CVE and line): 10, 6 and 4. */
function twenty() {
  const lines = [['s-x-a', 'Thunderbird', '115.9.0', 10], ['s-x-b', 'Node.js', '22.19.0', 6], ['s-x-c', 'Java', '8u491', 4]] as const
  const rows = lines.flatMap(([id, name, version, n]) => Array.from({ length: n }, (_, k) => ({
    id: `fq-x-${id}-${k}`, kind: 'no_range_data' as const, asset_id: 'a-pc01', software: { id, name, version }, cve: `CVE-2026-9${id.at(-1) === 'a' ? 1 : id.at(-1) === 'b' ? 2 : 3}${String(k).padStart(3, '0')}`, cves: 1,
    asked_at: new Date().toISOString(), url: null, command: null, choices: [] })))
  questions.update((l) => [...l, ...rows])
  expect(rows).toHaveLength(20)
}

describe('Needs your input grouped by device', () => {
  it('a device with 3 lines and 20 questions is one card with 3 entries, each counting its CVEs once', async () => {
    twenty()
    renderApp('/findings?tab=input', { role: 'operator' })
    const find = () => screen.getAllByRole('article', { name: /^What .+ needs$/ }).find((a) => a.textContent?.includes('20 CVEs waiting'))!
    await waitFor(() => expect(find()).toBeDefined(), T)
    expect(find()).toHaveTextContent('3 software waiting · 20 CVEs waiting')
    expect(within(find()).queryByTestId('needs-line')).toBeNull() // collapsed by default
    await userEvent.click(within(find()).getByRole('button', { expanded: false }))
    await waitFor(() => expect(within(find()).getAllByTestId('needs-line')).toHaveLength(3), T)
    const entries = within(find()).getAllByTestId('needs-line')
    expect(entries[0]).toHaveTextContent('Thunderbird 115.9.0: 10 CVEs waiting')
    expect(entries[1]).toHaveTextContent('Node.js 22.19.0: 6 CVEs waiting')
    expect(entries[2]).toHaveTextContent('Java 8u491: 4 CVEs waiting')
  })

  it('Ignore on a line answers Not affected to its questions only, in one step with one audit row', async () => {
    twenty()
    renderApp('/findings?tab=input', { role: 'operator' })
    await openNeeds()
    const before = auditStore.get().length
    await userEvent.click(await screen.findByRole('button', { name: /^Ignore the questions of Node\.js 22\.19\.0 on / }, T))
    const dlg = await screen.findByRole('dialog', {}, T)
    await userEvent.type(within(dlg).getByRole('textbox'), 'We do not run it')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Ignore' }))
    await waitFor(() => expect(questions.get().filter((q) => q.id.startsWith('fq-x-s-x-b') && q.answered)).toHaveLength(6), T)
    expect(questions.get().filter((q) => q.id.startsWith('fq-x-') && q.answered)).toHaveLength(6)
    expect(auditStore.get().length).toBe(before + 1)
  })

  it('Ignore all on a device answers every open question of it', async () => {
    twenty()
    renderApp('/findings?tab=input', { role: 'operator' })
    await openNeeds(document.body, { cves: false })
    const mine = (await screen.findAllByRole('article', { name: /^What .+ needs$/ }, T)).find((a) => within(a).queryByText(/20 CVEs waiting/))!
    await userEvent.click(within(mine).getByRole('button', { name: /^Ignore every question of / }))
    const dlg = await screen.findByRole('dialog', {}, T)
    await userEvent.type(within(dlg).getByRole('textbox'), 'Not a real device')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Ignore' }))
    await waitFor(() => expect(questions.get().filter((q) => q.id.startsWith('fq-x-') && q.answered)).toHaveLength(20), T)
  })
})
