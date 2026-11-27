// Possible findings: the CVEs Vedette cannot decide, counted apart from the open findings, shown after them in By device and By fix
// and on the device page, each with why it is undecided and the one input or answer that decides it; a check of their advisories
// and the AI proposals a person confirms or rejects.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { modulesStore } from '@/mocks/stores'
import { questions, records } from './modelMocks'
import { checks, possibleCounts } from './possibleMocks'

const T = { timeout: 8000 }
const section = () => screen.findByRole('region', { name: 'Possible findings' }, T)
const openRow = async (root: HTMLElement, name: RegExp) => userEvent.click(await within(root).findByRole('button', { name }, T))

describe('Possible findings in By device and By fix', () => {
  it('are counted apart: the count line says "· N possible", the open total is unchanged, and both lists agree with Home', async () => {
    const n = possibleCounts().possible
    expect(n).toBeGreaterThan(30)
    renderApp('/findings?tab=device')
    const line = await waitFor(() => { const e = document.querySelector('[data-count="by-device"]'); if (!e?.textContent?.includes('possible')) throw new Error('no line'); return e }, T)
    const open = records.get().filter((r) => r.state === 'open').length
    expect(line).toHaveTextContent(new RegExp(`, ${open} open findings · ${n} possible$`))
    expect(within(line as HTMLElement).getByRole('link', { name: `${n} possible` })).toHaveAttribute('href', '#possible')
    const s = await section()
    expect(await within(s).findByText(new RegExp(`^${n} possible CVEs on \\d+ devices: Vedette cannot decide them`), {}, T)).toBeInTheDocument()
    // every device row counts its CVEs; together they are the total
    const rows = within(s).getAllByRole('article')
    const sum = rows.reduce((t, a) => t + Number(/^(\d+)/.exec(within(a).getByText(/^\d+ possible CVEs?$/).textContent ?? '')?.[1]), 0)
    expect(sum).toBe(n)
  })

  it('a device with 30 possible CVEs lists its line once, exploited first, the first 8 then "Show all 30 CVEs"', async () => {
    renderApp('/findings?tab=device')
    const s = await section()
    await openRow(s, /^Show or hide the possible CVEs of RT-BACKUP/)
    const line = await within(s).findByRole('article', { name: 'MikroTik RouterOS 7.14' }, T)
    expect(line).toHaveTextContent('30 possible CVEs')
    expect(within(line).getAllByTestId('possible-row')).toHaveLength(8)
    // exploited first: the first row carries the badge
    expect(within(within(line).getAllByTestId('possible-row')[0]!).getByText('Exploited in the wild')).toBeInTheDocument()
    await userEvent.click(within(line).getByRole('button', { name: 'Show all 30 CVEs' }))
    expect(within(line).getAllByTestId('possible-row')).toHaveLength(30)
    // each row says why in plain words
    expect(line).toHaveTextContent('The CVE names MikroTik RouterOS but lists no affected versions.')
  })

  it('By fix lists one row per software and version across devices, with the same total', async () => {
    renderApp('/findings?tab=fix')
    const s = await section()
    const name = 'Microsoft SQL Server 2019 Enterprise Edition (64-bit) with Reporting Services and Integration Services 15.0.4385.2'
    const row = await within(s).findByRole('article', { name }, T)
    expect(row).toHaveTextContent('3 possible CVEs on 1 device')
    await openRow(row, /^Show or hide the devices that run Microsoft SQL Server 2019/)
    expect(within(row).getByRole('link', { name: 'SRV-ACCOUNTS' })).toHaveAttribute('href', '/devices/a-srvacc?tab=findings#possible')
  })

  it('a line asks only the input that decides it: the version, in one field (no package release on vendor software)', async () => {
    renderApp('/devices/a-srvfile?tab=findings')
    const s = await section()
    expect(await within(s).findByText('Vedette does not know which version runs here: the version decides all 4 CVEs.', {}, T)).toBeInTheDocument()
    // a version_needed CVE has no answer of its own: the version decides it
    expect(within(s).queryByRole('button', { name: /^Answer for / })).toBeNull()
    await userEvent.click(within(s).getByRole('button', { name: 'Add the version of Microsoft SQL Server on SRV-FILE' }))
    const dlg = await screen.findByRole('dialog', {}, T)
    expect(within(dlg).getAllByRole('textbox')).toHaveLength(1)
  })

  it('an answer that contradicts a check shows its evidence once, and the answer is kept', async () => {
    renderApp('/devices/a-rt02?tab=findings')
    const s = await section()
    await userEvent.click(await within(s).findByRole('button', { name: 'Show all 30 CVEs' }, T))
    // CVE-2026-240110: the AI proposed affected and a person rejected it, so it is possible again: no conflict to show
    // CVE-2026-240101: an AI proposal "affected": answering Not affected is not offered on a proposal, Confirm or Reject is
    const prop = within(s).getByRole('link', { name: 'CVE-2026-240101' }).closest('li')!
    expect(within(prop).getByText('AI proposal: affected (confident)')).toBeInTheDocument()
    expect(within(prop).getByRole('button', { name: 'Confirm that CVE-2026-240101 affects RT-BACKUP' })).toHaveTextContent('Confirm affected')
    // the settled ones are under "Checked, not affected", 1 of them exploited; Affected there shows the vendor's evidence
    await userEvent.click(within(s).getByRole('button', { name: 'Checked, not affected: 2 CVEs, 1 exploited' }))
    await userEvent.click(within(s).getByRole('button', { name: 'Affected: CVE-2026-240131 on RT-BACKUP' }))
    const dlg = await screen.findByRole('dialog', { name: 'CVE-2026-240131 affects RT-BACKUP' }, T)
    expect(within(dlg).getByRole('note')).toHaveTextContent("The vendor's advisory says this version is not affected")
    expect(within(dlg).getByRole('note')).toHaveTextContent('7.15 versions from 7.15rc1 before 7.15.3')
    await userEvent.type(within(dlg).getByRole('textbox'), 'The device runs the affected build')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Affected' }))
    await waitFor(() => expect(records.get().some((r) => r.asset_id === 'a-rt02' && r.cve === 'CVE-2026-240131' && r.verified === 'person')).toBe(true), T)
  })

  it('an operator may answer Not affected but not Affected or Accept the risk', async () => {
    renderApp('/devices/a-nas01?tab=findings', { role: 'operator' })
    const s = await section()
    await userEvent.click(await within(s).findByRole('button', { name: 'Answer for CVE-2026-118204 on NAS-BACKUP' }, T))
    expect(await screen.findByRole('menuitem', { name: 'Affected…' })).toHaveAttribute('data-disabled')
    expect(screen.getByRole('menuitem', { name: 'Accept the risk…' })).toHaveAttribute('data-disabled')
    expect(screen.getByRole('menuitem', { name: 'Not affected…' })).not.toHaveAttribute('data-disabled')
  })
})

describe('Checking possible findings and the AI proposals', () => {
  it('"Check N possible" runs in the background, shows how far it is, and says when proposals wait', async () => {
    const before = possibleCounts()
    renderApp('/findings?tab=device')
    const s = await section()
    const button = await within(s).findByRole('button', { name: `Check ${before.unchecked} possible` }, T)
    await userEvent.click(button)
    expect(await within(s).findByText(/^Checking: \d+ of \d+$/, {}, T)).toBeInTheDocument()
    // the run ends by itself; the toast leads to the proposals
    expect(await screen.findByText(/^Check finished: /, {}, { timeout: 20000 })).toBeInTheDocument()
    await waitFor(() => expect(possibleCounts().unchecked).toBe(0), T)
    expect(await within(s).findByRole('button', { name: 'Check 0 possible' }, T)).toBeDisabled()
    expect(possibleCounts().proposals).toBeGreaterThan(before.proposals)
  })

  it('without the AI assistant the check says why and where to set it up', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: false } : m)))
    renderApp('/findings?tab=device')
    const s = await section()
    expect(await within(s).findByText(/needs the AI assistant on/, {}, T)).toBeInTheDocument()
    expect(within(s).getByRole('link', { name: 'Set up the AI assistant' })).toHaveAttribute('href', '/settings/ai')
    expect(within(s).queryByRole('button', { name: /^Check \d+/ })).toBeNull()
  })

  it('AI proposals: a tab with its count; confirm affected records a finding, reject makes the CVE possible again', async () => {
    const n = possibleCounts().proposals
    renderApp('/findings?tab=proposals')
    expect(await screen.findByRole('tab', { name: `AI proposals ${n} wait for you`, selected: true }, T)).toBeInTheDocument()
    const sql = await screen.findByRole('article', { name: 'AI proposal for CVE-2026-245501 on SRV-ACCOUNTS' }, T)
    expect(sql).toHaveTextContent('SQL Server 2019 CU28 and earlier are affected.')
    await userEvent.click(within(sql).getByRole('button', { name: 'Confirm that CVE-2026-245501 affects SRV-ACCOUNTS' }))
    await waitFor(() => expect(records.get().some((r) => r.cve === 'CVE-2026-245501' && r.state === 'open')).toBe(true), T)
    const rt = await screen.findByRole('article', { name: 'AI proposal for CVE-2026-240113 on RT-BACKUP' }, T)
    await userEvent.click(within(rt).getByRole('button', { name: 'Reject the AI proposal for CVE-2026-240113 on RT-BACKUP' }))
    await waitFor(() => expect(Object.values(checks.get()).find((c) => c.quote.startsWith('Versions up to 7.15'))?.rejected).toBe(true), T)
    expect(questions.get().some((q) => q.cve === 'CVE-2026-240113' && !q.answered)).toBe(true)
  })

  it('an exploited CVE proposed not affected is confirmed one by one, never with its group', async () => {
    renderApp('/findings?tab=proposals')
    const row = await screen.findByRole('article', { name: 'AI proposal for CVE-2026-240107 on RT-BACKUP' }, T)
    expect(row).toHaveTextContent('Exploited and proposed not affected: confirm it on its own.')
    await userEvent.click(screen.getByRole('button', { name: 'Confirm a group' }))
    // the only "not affected, confident" proposal is the exploited one: no such group is offered
    expect(screen.queryByRole('menuitem', { name: /^Not affected, confident/ })).toBeNull()
    await userEvent.click(screen.getByRole('menuitem', { name: 'Not affected, likely (1)' }))
    const dlg = await screen.findByRole('dialog', {}, T)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm 1' }))
    await waitFor(() => expect(questions.get().find((q) => q.cve === 'CVE-2026-240102')?.answered).toBeTruthy(), T)
    expect(questions.get().find((q) => q.cve === 'CVE-2026-240107')?.answered).toBeFalsy()
  })

  it('Home says how many possible CVEs and proposals wait, each a link', async () => {
    const c = possibleCounts()
    renderApp('/')
    expect(await screen.findByRole('link', { name: `${c.possible} possible CVEs to check` }, T)).toHaveAttribute('href', '/findings?tab=device#possible')
    expect(screen.getByRole('link', { name: `${c.proposals} AI proposals wait for you` })).toHaveAttribute('href', '/findings?tab=proposals')
  })
})
