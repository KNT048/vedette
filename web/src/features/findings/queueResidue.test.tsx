// The Needs your input queue says what each question really is: a device Vedette cannot check (and the ways in), one question for a
// release line the vendor names no fix for, and "gives no affected versions" only when the CVE lists none.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@/lib/i18n'
import { renderApp } from '@/test/render'
import { assetsStore } from '@/mocks/stores'
import { questions } from './modelMocks'
import { openNeeds } from './needsTestUtil'

const T = { timeout: 5000 }

const itemOf = (el: HTMLElement) => (el.closest('tr, li, [role="listitem"]') ?? el.parentElement!.parentElement!) as HTMLElement

describe('Needs your input: what each item really asks', () => {
  it('a device a person added that Vedette cannot check: the three ways in, the firmware in place', async () => {
    assetsStore.update((l) => l.map((a) => (a.id === 'a-unk02' ? { ...a, approved: true, software: [], os: null } : a)))
    renderApp('/findings?tab=input', { role: 'operator' })
    await openNeeds()
    await screen.findAllByRole('button', { name: /^Add the firmware of / }, T)
    const snmp = screen.getAllByRole('link', { name: 'Give SNMP read access' }).find((l) => l.getAttribute('href') === '/devices/a-unk02?tab=overview#sources')!
    const item = itemOf(snmp)
    expect(item).toHaveTextContent(/^Vedette cannot check .+: it does not know what software or firmware runs there, so no finding can appear for it/)
    expect(within(item).getByRole('link', { name: 'Install an agent' })).toHaveAttribute('href', '/devices/setup?tab=agents')
    await userEvent.click(within(item).getByRole('button', { name: /^Add the firmware of / }))
    expect(await screen.findByRole('dialog', {}, T)).toBeInTheDocument()
  })

  it('a release line the vendor names no fix for is one question: the fixes, the CVEs behind one click, one Not affected', async () => {
    renderApp('/findings?tab=input', { role: 'operator' })
    const re = /^The vendor names fixes for 3 CVEs of Synology NAS \(DSM\) only on newer releases/
    await openNeeds()
    await screen.findByText(re, {}, T)
    const text = screen.getByText(re)
    expect(text).toHaveTextContent('(7.3.2-86009 Update 5, 7.4.1-90080 Update 1), and nothing for 7.2, which NAS-BACKUP runs.')
    expect(text).not.toHaveTextContent('gives no affected versions')
    const item = itemOf(text)
    expect(within(item).queryByRole('button', { name: 'Affected' })).toBeNull() // one person's word is not a finding for three CVEs
    expect(within(item).getByRole('link', { name: 'CVE-2026-118211' })).toHaveAttribute('href', '/cve/CVE-2026-118211')
    await userEvent.click(within(item).getByRole('button', { name: 'Not affected' }))
    const dlg = await screen.findByRole('dialog', { name: 'Not affected: Synology NAS (DSM) 7.2 on NAS-BACKUP' }, T)
    await userEvent.type(within(dlg).getByLabelText('How do you know 7.2 is not affected? (required)'), 'Synology says 7.2 is not affected')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Not affected' }))
    await waitFor(() => expect(questions.get().find((q) => q.id === 'fq-nas01-line')?.answered).toBeTruthy(), T)
  })

  it('"gives no affected versions" only when the CVE lists none; listed versions that do not decide say so', async () => {
    questions.update((l) => l.map((q) => (q.id === 'fq-nas01-range' ? { ...q, versions_listed: true } : q)))
    renderApp('/findings?tab=input')
    await openNeeds()
    const cve = await screen.findByRole('link', { name: 'CVE-2026-118204' }, T)
    const item = itemOf(cve)
    expect(item).toHaveTextContent('CVE-2026-118204 lists some affected versions of Synology NAS (DSM), but none that tells whether 7.2 is affected.')
    expect(item).not.toHaveTextContent('gives no affected versions')
  })

  it('a build attribute NVD pins is asked for by name, never as a version to retype', async () => {
    questions.update((l) => [...l, { id: 'fq-nas01-tb', kind: 'not_comparable', attribute: 'edition', asset_id: 'a-nas01',
      software: { id: 's-nas01-tb', name: 'Mozilla Thunderbird', version: '153.0.1' }, cve: 'CVE-2099-0203', cves: 1, asked_at: new Date().toISOString(),
      url: null, command: null, choices: [] }])
    renderApp('/findings?tab=input', { role: 'admin' })
    await openNeeds()
    const sentence = await screen.findByText('Mozilla Thunderbird 153.0.1: is this the ESR edition or the normal release? 1 CVE depends on it.', {}, T)
    const line = sentence.closest('li')!
    expect(within(line).queryByRole('button', { name: 'Add the version…' })).toBeNull()
    const row = itemOf(await within(line).findByRole('link', { name: 'CVE-2099-0203' }, T))
    expect(row).toHaveTextContent('Which edition of Mozilla Thunderbird is this: ESR or the normal release?')
    expect(row).not.toHaveTextContent('Type it as the vendor writes it')
    expect(within(row).getByRole('button', { name: 'Affected' })).toBeEnabled()
    expect(within(row).getByRole('button', { name: 'Not affected' })).toBeEnabled()
  })
})
