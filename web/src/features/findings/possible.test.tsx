// Possible findings: the CVEs Vedette cannot decide, counted apart from the open findings, shown after them in By device and By fix
// and on the device page, each with why it is undecided and the one input or answer that decides it; a check of their advisories
// and the AI proposals a person confirms or rejects.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { modulesStore } from '@/mocks/stores'
import { records } from './modelMocks'
import { possibleCounts, reviewCount } from './possibleMocks'

const T = { timeout: 8000 }
const section = () => screen.findByRole('region', { name: 'Not decided' }, T)
const openRow = async (root: HTMLElement, name: RegExp) => userEvent.click(await within(root).findByRole('button', { name }, T))

describe('Possible findings in By device and By fix', () => {
  it('are counted apart: the count line says "· N not decided", the open total is unchanged, and both lists agree with Home', async () => {
    const n = possibleCounts().possible - reviewCount()
    expect(n).toBeGreaterThan(30)
    renderApp('/findings?tab=device')
    const line = await waitFor(() => { const e = document.querySelector('[data-count="by-device"]'); if (!e?.textContent?.includes('not decided')) throw new Error('no line'); return e }, T)
    const open = records.get().filter((r) => r.state === 'open').length
    const older = possibleCounts().older_build
    const distro = possibleCounts().distro_pending
    expect(line).toHaveTextContent(new RegExp(`, ${open} open findings · ${n} not decided · ${older} older build · ${distro} waiting for the distribution$`))
    expect(within(line as HTMLElement).getByRole('link', { name: `${n} not decided` })).toHaveAttribute('href', '/findings?tab=possible')
    // never hidden: the older-build group's count is a link beside it
    expect(within(line as HTMLElement).getByRole('link', { name: `${older} older build` })).toHaveAttribute('href', '/findings?tab=possible')
    renderApp('/findings?tab=possible')
    const s = await section()
    expect(await within(s).findByText(new RegExp(`^${n} CVEs not decided on \\d+ devices`), {}, T)).toBeInTheDocument()
    // every device row counts its CVEs; together they are the total
    const rows = within(s).getAllByRole('article')
    const sum = rows.reduce((t, a) => t + Number(/^(\d+)/.exec(within(a).getByText(/^\d+ CVEs? not decided$/).textContent ?? '')?.[1]), 0)
    expect(sum).toBe(n)
  })

  it('every possible CVE names its cause in one sentence: a reading from a third party, an unsure one, a rejected one, a page that cannot be read', async () => {
    renderApp('/findings?tab=possible')
    const s = await section()
    await openRow(s, /^Show or hide the not decided CVEs of RT-BACKUP/)
    const line = await within(s).findByRole('article', { name: 'MikroTik RouterOS 7.14' }, T)
    await userEvent.click(within(line).getByRole('button', { name: /^Show all \d+ CVEs/ }))
    const rows = within(line).getAllByTestId('possible-row')
    const causes = new Set(rows.map((r) => within(r).queryByTestId('possible-cause')?.getAttribute('data-cause')))
    for (const c of ['vendor_silent', 'ai_unsure', 'needs_person', 'page_unreadable', 'pending_nvd']) expect(causes).toContain(c)
    expect(causes).not.toContain(undefined)
    const third = rows.find((r) => r.textContent?.includes('CVE-2026-240108'))!
    expect(third).toHaveTextContent('blog.example.net says not affected (not the vendor\'s page)')
    expect(third).toHaveTextContent('No page from the vendor states more than the CVE record for this release line.')
    const counts = possibleCounts().causes
    expect(Object.values(counts).reduce((a, b) => a + b, 0)).toBe(possibleCounts().possible)
  })

  it('a CVE the automatic AI reading leaves for now says until when and why, in plain words', async () => {
    renderApp('/findings?tab=possible')
    const s = await section()
    await openRow(s, /^Show or hide the not decided CVEs of RT-BACKUP/)
    const line = await within(s).findByRole('article', { name: 'MikroTik RouterOS 7.14' }, T)
    const rows = within(line).getAllByTestId('possible-row')
    const row = rows.find((r) => r.textContent?.includes('CVE-2026-240104'))!
    const held = within(row).getByTestId('possible-held')
    expect(held).toHaveAttribute('data-reason', 'answer_unusable')
    expect(held.textContent).toMatch(/^The AI reads this again after .+: its last answer was not in the format Vedette needs or was cut off\.$/)
    // it replaces the cause's default sentence, which would ask for an AI that already tried
    expect(within(row).getByTestId('possible-cause')).toHaveTextContent(/^The AI reads this again after/)
    expect(row).not.toHaveTextContent('With an AI provider set up')
    // a row that is not held says nothing of it
    expect(within(rows.find((r) => r.textContent?.includes('CVE-2026-240101'))!).queryByTestId('possible-held')).toBeNull()
  })

  it('a device with 28 CVEs not decided lists its line once, exploited first, the first 8 then "Show all 28 CVEs"', async () => {
    renderApp('/findings?tab=possible')
    const s = await section()
    await openRow(s, /^Show or hide the not decided CVEs of RT-BACKUP/)
    const line = await within(s).findByRole('article', { name: 'MikroTik RouterOS 7.14' }, T)
    expect(line).toHaveTextContent('28 CVEs not decided')
    expect(within(line).getAllByTestId('possible-row')).toHaveLength(8)
    // exploited first: the first row carries the badge
    expect(within(within(line).getAllByTestId('possible-row')[0]!).getByText('Exploited in the wild')).toBeInTheDocument()
    await userEvent.click(within(line).getByRole('button', { name: 'Show all 28 CVEs' }))
    expect(within(line).getAllByTestId('possible-row')).toHaveLength(28)
    // each row says why in plain words
    expect(line).toHaveTextContent('The CVE names MikroTik RouterOS but lists no affected versions.')
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
    await userEvent.click(await within(s).findByRole('button', { name: 'Show all 28 CVEs' }, T))
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

  it('CVEs reported only for an older build are counted and listed apart, closed, each saying what was tested, when, and what runs', async () => {
    const c = possibleCounts()
    expect(c.older_build).toBe(5)
    renderApp('/findings?tab=possible')
    const s = await section()
    // both numbers on the summary line; the causes add up to the main number only
    expect(await within(s).findByText(new RegExp(`^${c.possible - reviewCount()} CVEs not decided on \\d+ devices · 5 reported only for an older build`), {}, T)).toBeInTheDocument()
    expect(Object.values(c.causes).reduce((a, b) => a + b, 0)).toBe(c.possible)
    // not in the main list: the device row counts only its main possible CVEs
    const group = within(s).getByTestId('older-builds')
    expect(within(group).queryAllByTestId('possible-row')).toHaveLength(0)
    await userEvent.click(within(group).getByRole('button', { name: 'Reported only for an older build: 5 CVEs' }))
    const rows = within(group).getAllByTestId('possible-row')
    expect(rows).toHaveLength(5)
    const row = rows.find((r) => r.textContent?.includes('CVE-2025-900103'))!
    expect(within(row).getByTestId('possible-older-build')).toHaveTextContent('A third party tested 4.0.3, 5.9.1 (reported 2025); this device runs 6.4.2.')
    expect(row).toHaveTextContent('No fix or statement from the vendor in the CVE record.')
    // still possible: answered like any other row
    expect(within(row).getByRole('button', { name: /^Answer for CVE-2025-900103 on SRV-ACCOUNTS/ })).toBeInTheDocument()
    // the record that gives the vendor's fix keeps its CVE in the main list
    expect(rows.some((r) => r.textContent?.includes('CVE-2026-900105'))).toBe(false)
  })

  it('CVEs waiting for the distribution are counted and listed apart, closed, the header saying how many are exploited', async () => {
    const c = possibleCounts()
    expect([c.distro_pending, c.distro_pending_exploited]).toEqual([3, 1])
    expect(c.causes.distro_silent).toBe(0) // the causes add up to the main number only
    renderApp('/findings?tab=possible')
    const s = await section()
    expect(await within(s).findByText(new RegExp(`^${c.possible - reviewCount()} CVEs not decided on \\d+ devices · .* · 3 waiting for the distribution`), {}, T)).toBeInTheDocument()
    const group = within(s).getByTestId('distro-pending')
    expect(within(group).queryAllByTestId('possible-row')).toHaveLength(0)
    await userEvent.click(within(group).getByRole('button', { name: 'The distribution has not decided yet: 3 CVEs · 1 exploited' }))
    const rows = within(group).getAllByTestId('possible-row')
    expect(rows).toHaveLength(3)
    // each row says the distribution's own reason
    const row = rows.find((r) => r.textContent?.includes('CVE-2023-900203'))!
    expect(row).toHaveTextContent('The distribution lists this CVE for curl in other releases only, not the one this device runs.')
  })

  it('a device page shows its CVEs waiting for the distribution as the same closed group', async () => {
    renderApp('/devices/a-web01?tab=findings')
    const s = await section()
    expect(await within(s).findByRole('button', { name: 'The distribution has not decided yet: 3 CVEs · 1 exploited' }, T)).toBeInTheDocument()
    expect(within(s).queryAllByTestId('possible-row')).toHaveLength(0)
  })

  it('a device with possible CVEs of both kinds counts both on its page', async () => {
    renderApp('/devices/a-srvacc?tab=findings')
    const s = await section()
    expect(await within(s).findByText(/· 4 reported only for an older build$/, {}, T)).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'Reported only for an older build: 4 CVEs' })).toBeInTheDocument()
  })

  it('a device whose only possible CVEs were reported for an older build keeps a badge and a link that say so', async () => {
    renderApp('/devices/a-nvr01?tab=findings')
    const s = await section()
    // no empty main list: the group with its count, and the check that can still read it
    expect(await within(s).findByRole('button', { name: 'Reported only for an older build: 1 CVE' }, T)).toBeInTheDocument()
    expect(within(s).queryByText(/^0 possible CVEs/)).toBeNull()
    expect(within(s).getByRole('button', { name: /^Check 1 not decided/ })).toBeInTheDocument()
    // the device's badge in its header and the findings line's link
    expect((await screen.findAllByText('1 older build', {}, T)).length).toBeGreaterThan(0)
    expect(document.querySelector('[data-status="possible"]')).toHaveTextContent('1 older build')
  })
})

describe('Checking possible findings and the AI proposals', () => {
  it('"Check N not decided" runs in the background, shows how far it is, and says when proposals wait', async () => {
    const before = possibleCounts()
    renderApp('/findings?tab=possible')
    const s = await section()
    const button = await within(s).findByRole('button', { name: `Check ${before.unchecked} not decided` }, T)
    await userEvent.click(button)
    expect(await within(s).findByText(/^Checking: \d+ of \d+$/, {}, T)).toBeInTheDocument()
    // the run ends by itself; the toast leads to the proposals
    expect(await screen.findByText(/^Check finished: /, {}, { timeout: 20000 })).toBeInTheDocument()
    await waitFor(() => expect(possibleCounts().unchecked).toBe(0), T)
    expect(await within(s).findByRole('button', { name: 'Check 0 not decided' }, T)).toBeDisabled()
    expect(possibleCounts().proposals).toBeGreaterThan(before.proposals)
  })

  it('without the AI assistant the check says why and where to set it up', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'ai' ? { ...m, enabled: false } : m)))
    renderApp('/findings?tab=possible')
    const s = await section()
    expect(await within(s).findByText(/needs the AI assistant on/, {}, T)).toBeInTheDocument()
    expect(within(s).getByRole('link', { name: 'Set up the AI assistant' })).toHaveAttribute('href', '/settings/ai')
    expect(within(s).queryByRole('button', { name: /^Check \d+/ })).toBeNull()
  })
})
