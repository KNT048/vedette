// One finding, one story: the status lines every screen draws for a finding, and the Needs your input queue saying its exact count,
// naming its links for what they are and letting a "not affected" answer be taken back.
import { describe, expect, it } from 'vitest'
import { fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import '@/lib/i18n'
import { renderApp } from '@/test/render'
import { Counter } from '@/components/common/Counter'
import { pageSizes } from '@/components/common/Pager'
import { questions, records } from './modelMocks'
import { openNeeds } from './needsTestUtil'
import { useFixTitle } from './parts'
import type { Fix } from './types'

const T = { timeout: 5000 }
/** Findings are collapsed until clicked: opens every closed toggle inside `root`. */
async function expandAll(root: HTMLElement = document.body) {
  for (const b of within(root).queryAllByRole('button').filter((x) => x.getAttribute('aria-expanded') === 'false')) await userEvent.click(b)
}

describe('a finding reads the same in every list', () => {
  it('By device: each CVE row says its reasons and how Vedette knows, under its badge, as the finding page does', async () => {
    const r = records.get().find((x) => x.state === 'open' && x.reasons.some((y) => y.source === 'cisa-kev'))!
    renderApp('/findings?tab=device')
    await screen.findAllByRole('article', undefined, T)
    const link = await waitFor(async () => { for (const a of screen.getAllByRole('article')) await expandAll(a); return screen.getByRole('link', { name: r.cve }) }, T)
    const row = link.closest('li')!
    const lines = within(row).getByTestId('finding-status')
    expect(within(lines).getByTestId('reasons-line')).toHaveTextContent(/^Exploited in the wild: .*CISA KEV.* \(\d{1,2} [A-Z][a-z]{2} \d{4}\)/)
    expect(lines).toHaveTextContent(/Confirmed|Not confirmed yet/)
  })

  it('Home: the badge of a Fix first block carries its cause\'s reasons and confirmation lines', async () => {
    renderApp('/')
    const card = (await screen.findByRole('heading', { name: 'Fix first' }, T)).closest('section')!
    const first = within(card).getAllByRole('listitem')[0]!
    expect(within(first).getByTestId('reasons-line')).toHaveTextContent(/^(Under attack here|Exploited in the wild|Public exploit available|Critical on an edge device): /)
    expect(first).toHaveTextContent(/Confirmed|Not confirmed yet/)
  })

  it('a fix with no release names no empty slot: "Install the distribution\'s security updates for Linux kernel"', () => {
    const title = renderHook(() => useFixTitle()).result.current
    const f = (kind: Fix['kind'], version: string | null = null): Fix => ({ key: 'k', kind, product: 'Linux kernel', version, ref: null, channel: 'public', url: null })
    const out = [f('distro_update'), f('update'), f('os_update'), f('feature_update'), f('distro_update', '6.8.0-90.91')].map((x) => title(x))
    expect(out).toEqual([
      "Install the distribution's security updates for Linux kernel", 'Update Linux kernel to a fixed release', 'Install the latest cumulative update on Linux kernel',
      'Move Linux kernel to a later release', 'Install the Linux kernel package 6.8.0-90.91 or later',
    ])
    for (const s of out) expect(s).not.toMatch(/ {2}|package or later/)
  })

  it('a fix only Ubuntu Pro or Windows ESU carries says so, never the bare "Install … or later"', () => {
    const title = renderHook(() => useFixTitle()).result.current
    const pro: Fix = { key: 'k', kind: 'distro_update', product: 'python3-pip', version: '25.1.1+dfsg-1ubuntu2+esm3', ref: null, channel: 'ubuntu_pro', url: null }
    const esu: Fix = { key: 'k', kind: 'os_update', product: 'Windows 10 22H2', version: '10.0.19045.6575', ref: 'KB5066791', channel: 'esu', url: null }
    expect(title(pro)).toBe('Install the python3-pip package 25.1.1+dfsg-1ubuntu2+esm3 from Ubuntu Pro (ESM): only Ubuntu Pro has this fix')
    expect(title(esu)).toBe('Install KB5066791 on Windows 10 22H2 (needs an Extended Security Updates subscription)')
  })
})

describe('Needs your input', () => {
  it('the tab says the exact count, not "99+"', () => {
    const { container } = render(<Counter count={196} label="waiting" />)
    expect(container).toHaveTextContent('196')
    expect(container).not.toHaveTextContent('99+')
  })

  it('no page size is offered that the server does not send ("200" that showed "1–100 of 196")', () => {
    expect(pageSizes(20, 100)).toEqual([20, 25, 50, 100])
    expect(pageSizes(25)).toEqual([25, 50, 100, 200])
  })

  it('a question\'s link says what it is: NVD\'s entry is not called the vendor advisory', async () => {
    questions.update((l) => l.map((q) => (q.id === 'fq-nas01-range' ? { ...q, url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-118204' } : q)))
    renderApp('/findings?tab=input')
    await openNeeds()
    const link = await screen.findByRole('link', { name: /NVD/ }, T)
    expect(link).toHaveAttribute('href', 'https://nvd.nist.gov/vuln/detail/CVE-2026-118204')
    expect(screen.queryByRole('link', { name: 'Vendor advisory' })).toBeNull()
  })

  it('"Not affected" can be undone from its toast', async () => {
    renderApp('/findings?tab=input')
    await openNeeds()
    const cve = await screen.findByRole('link', { name: 'CVE-2026-118204' }, T)
    const item = cve.closest('tr, li, [role="listitem"]') ?? cve.parentElement!.parentElement!
    await userEvent.click(within(item as HTMLElement).getByRole('button', { name: 'Not affected' }))
    const dlg = await screen.findByRole('dialog', {}, T)
    await userEvent.type(within(dlg).getByRole('textbox'), 'not on this build')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Not affected' }))
    // the toast offers Undo: one click asks the question again
    const undo = await screen.findByRole('button', { name: 'Undo' }, T)
    await waitFor(() => expect(questions.get().find((q) => q.id === 'fq-nas01-range')?.answered).toBeTruthy())
    fireEvent.click(undo) // the toast's own button (a pointer event would start its swipe)
    await waitFor(() => expect(questions.get().find((q) => q.id === 'fq-nas01-range')?.answered).toBeFalsy(), T)

  })

  it('an answered question is listed below the queue; Ask again takes the answer back', async () => {
    questions.update((l) => l.map((q) => (q.id === 'fq-nas01-range' ? { ...q, answered: { by: 'admin@acme.example', at: new Date().toISOString() } } : q)))
    renderApp('/findings?tab=input')
    await userEvent.click(await screen.findByText('1 question answered "Not affected"', {}, T))
    expect(await screen.findByText(/^Not affected, answered by admin@acme\.example on /, {}, T)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^Ask again: CVE-2026-118204/ }))
    await waitFor(() => expect(questions.get().find((q) => q.id === 'fq-nas01-range')?.answered).toBeFalsy(), T)
  })
})
