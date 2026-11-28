// Review AI answers, Not decided and the AI's findings in the lists: what the customer's AI researched about CVEs Vedette could not decide,
// and the person's quick, safe way to confirm or reject its "not affected" answers. Tokens are counted, never money.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { questions } from './modelMocks'

const T = { timeout: 8000 }
const answered = (cve: string) => !!questions.get().find((q) => q.cve === cve)?.answered
const rows = () => screen.findAllByTestId('review-row', {}, T)
const rowOf = async (cve: string) => (await rows()).find((r) => r.textContent?.includes(cve))!

async function selectAll() {
  await rows()
  await userEvent.click(screen.getByRole('checkbox', { name: /^Select all \d+$/ }))
}
const bar = () => screen.getByTestId('review-bar')
const confirmSelected = async () => {
  await userEvent.click(within(bar()).getByRole('button', { name: /^Confirm \d+$/ }))
  const dlg = await screen.findByRole('dialog', {}, T)
  await userEvent.click(within(dlg).getByRole('button', { name: /^Confirm \d+$/ }))
}

describe('Review AI answers', () => {
  it('lists the AI\'s not-affected answers with one evidence line: pages read, quote checked, tokens, model', async () => {
    renderApp('/findings?tab=review')
    const row = await rowOf('CVE-2026-250201')
    expect(within(row).getByTestId('review-evidence')).toHaveTextContent('1 page read · quote checked · 8,200 tokens · qwen3:8b')
    // a row with no quote says so; one whose quote the box did not find says that
    expect(within(await rowOf('CVE-2026-250208')).getByTestId('review-evidence')).toHaveTextContent('no quote')
    expect(within(await rowOf('CVE-2026-250205')).getByTestId('review-evidence')).toHaveTextContent('quote not found on the page')
    // plurals: one page, many pages
    expect(within(await rowOf('CVE-2026-250202')).getByTestId('review-evidence')).toHaveTextContent('2 pages read')
  })

  it('"How it decided" opens the steps and pages behind one click', async () => {
    renderApp('/findings?tab=review')
    const row = await rowOf('CVE-2026-250206')
    await userEvent.click(within(row).getByRole('button', { name: 'Show how the AI decided CVE-2026-250206' }))
    expect(within(row).getByRole('list', { name: 'Steps of the research' })).toHaveTextContent('Step 2: strong profile, claude-sonnet-5')
    expect(within(row).getAllByRole('link', { name: /^https:\/\// }).length).toBeGreaterThan(1)
  })

  it('a row whose answer is inferred from a product sharing its code says "inferred"', async () => {
    renderApp('/findings?tab=review')
    const inferred = await rowOf('CVE-2026-250207')
    expect(within(inferred).getByText('inferred')).toBeInTheDocument()
    expect(within(await rowOf('CVE-2026-250201')).queryByText('inferred')).toBeNull()
  })

  it('nothing is selected by default: the bar offers "Select all N" and Confirm waits for a selection', async () => {
    renderApp('/findings?tab=review')
    await rows()
    expect(within(bar()).getByRole('checkbox', { name: /^Select all \d+$/ })).not.toBeChecked()
    for (const c of screen.getAllByRole('checkbox', { name: /^Select CVE-/ })) expect(c).not.toBeChecked()
    expect(within(bar()).getByRole('button', { name: 'Confirm 0' })).toBeDisabled()
  })

  it('exploited rows stay unticked and locked until "Include N exploited" is ticked, so a bulk confirmation leaves them out', async () => {
    renderApp('/findings?tab=review')
    await selectAll()
    const include = await within(bar()).findByRole('checkbox', { name: /^Include \d+ exploited$/ }, T)
    expect(include).not.toBeChecked()
    const exploitedBox = screen.getByRole('checkbox', { name: /^Select CVE-2026-250218 on/ })
    expect(exploitedBox).toBeDisabled()
    expect(exploitedBox).not.toBeChecked()
    // the button counts only what it will confirm, and the selected rows are those
    const plain = screen.getByRole('checkbox', { name: /^Select CVE-2026-250201 on/ })
    expect(plain).toBeChecked()
    await confirmSelected()
    await waitFor(() => expect(answered('CVE-2026-250201')).toBe(true), T)
    expect(answered('CVE-2026-250218')).toBe(false)
    expect(answered('CVE-2026-250219')).toBe(false)
    expect(answered('CVE-2026-240107')).toBe(false)
  })

  it('ticking "Include N exploited" unlocks and selects the exploited rows, and the dialog says so', async () => {
    renderApp('/findings?tab=review')
    await selectAll()
    await userEvent.click(await within(bar()).findByRole('checkbox', { name: /^Include \d+ exploited$/ }, T))
    const box = screen.getByRole('checkbox', { name: /^Select CVE-2026-250218 on/ })
    expect(box).toBeEnabled()
    expect(box).toBeChecked()
    await userEvent.click(within(bar()).getByRole('button', { name: /^Confirm \d+$/ }))
    const dlg = await screen.findByRole('dialog', {}, T)
    expect(dlg).toHaveTextContent(/of them are on an exploited list/)
    await userEvent.click(within(dlg).getByRole('button', { name: /^Confirm \d+$/ }))
    await waitFor(() => expect(answered('CVE-2026-250218')).toBe(true), T)
    expect(answered('CVE-2026-250219')).toBe(true)
  })

  it('an exploited row confirmed on its own needs the extra tick: "I checked the evidence myself"', async () => {
    renderApp('/findings?tab=review')
    const row = await rowOf('CVE-2026-250218')
    await userEvent.click(within(row).getByRole('button', { name: 'Confirm: CVE-2026-250218 does not affect PC-ACCOUNTS-01' }))
    const dlg = await screen.findByRole('dialog', {}, T)
    const submit = within(dlg).getByRole('button', { name: 'Confirm 1' })
    expect(dlg).toHaveTextContent('This CVE is exploited in the wild. I checked the evidence myself.')
    expect(submit).toBeDisabled()
    await userEvent.click(within(dlg).getByRole('checkbox'))
    expect(submit).toBeEnabled()
    await userEvent.click(submit)
    await waitFor(() => expect(answered('CVE-2026-250218')).toBe(true), T)
  })

  it('a CVE that is not exploited is confirmed without the extra tick', async () => {
    renderApp('/findings?tab=review')
    await userEvent.click(within(await rowOf('CVE-2026-250202')).getByRole('button', { name: /^Confirm: CVE-2026-250202/ }))
    const dlg = await screen.findByRole('dialog', {}, T)
    expect(within(dlg).queryByRole('checkbox')).toBeNull()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm 1' }))
    await waitFor(() => expect(answered('CVE-2026-250202')).toBe(true), T)
  })

  it('a confirmed answer is listed under Handled, where it can be asked again', async () => {
    renderApp('/findings?tab=review')
    const row = await rowOf('CVE-2026-250201')
    await userEvent.click(within(row).getByRole('button', { name: /^Confirm: CVE-2026-250201/ }))
    await userEvent.click(within(await screen.findByRole('dialog', {}, T)).getByRole('button', { name: 'Confirm 1' }))
    await waitFor(() => expect(answered('CVE-2026-250201')).toBe(true), T)
    renderApp('/findings?tab=handled')
    await userEvent.click(await screen.findByRole('button', { name: /^Answered not affected: \d+$/ }, T))
    expect(await screen.findByRole('button', { name: /^Ask again: CVE-2026-250201/ }, T)).toBeInTheDocument()
  })

  it('filters by confidence and by whether the box found the quote', async () => {
    renderApp('/findings?tab=review')
    await rows()
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Evidence' }), 'unchecked')
    await waitFor(async () => { expect((await rows()).every((r) => /quote not found|no quote|No research recorded/.test(r.textContent ?? ''))).toBe(true) }, T)
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Evidence' }), '')
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Confidence' }), 'low')
    await waitFor(async () => { expect((await rows()).every((r) => r.textContent?.includes('Low confidence'))).toBe(true) }, T)
  })
})

describe('Not decided', () => {
  it('says what the AI tried, and Research deeper shows the research mode\'s tokens, never money', async () => {
    renderApp('/findings?tab=possible')
    const section = await screen.findByRole('region', { name: 'Not decided' }, T)
    await userEvent.click(await within(section).findByRole('button', { name: /^Show or hide the not decided CVEs of RT-BACKUP/ }, T))
    await userEvent.click(await within(section).findByRole('button', { name: 'Show all 28 CVEs' }, T))
    const tried = (await within(section).findAllByTestId('possible-tried', {}, T)).find((e) => e.closest('li')?.textContent?.includes('CVE-2026-240109'))!
    expect(tried).toHaveTextContent('Your AI read 3 pages and could not tell (15,200 tokens).')
    const buttons = await within(section).findAllByRole('button', { name: /^Research CVE-.* deeper$/ }, T)
    // the figure is this box's own (its research runs of the last 30 days), never an estimate
    expect(buttons[0]!.textContent).toMatch(/^Research deeper · about [\d,]+ tokens$/)
    expect(buttons[0]).not.toHaveTextContent('200,000')
    expect(document.body.textContent).not.toMatch(/[$€£¥₫]|\b(USD|EUR|GBP|VND)\b/)
  })

  it('keeps AI answers that wait for review out of its list, and the older-build group closed with its count', async () => {
    renderApp('/findings?tab=possible')
    const section = await screen.findByRole('region', { name: 'Not decided' }, T)
    await userEvent.click(await within(section).findByRole('button', { name: /^Show or hide the not decided CVEs of PC-ACCOUNTS-01/ }, T))
    expect(within(section).queryByText('CVE-2026-250201')).toBeNull()
    const older = await within(section).findByTestId('older-builds', {}, T)
    expect(within(older).getByRole('button')).toHaveAttribute('aria-expanded', 'false')
    expect(older).toHaveTextContent(/Reported only for an older build: \d+ CVEs?/)
  })
})

describe('Research deeper', () => {
  it('shows no number when this box has measured nothing', async () => {
    server.use(http.get('*/api/v1/ai/runs', () => HttpResponse.json({ items: [] })))
    renderApp('/findings?tab=possible')
    const section = await screen.findByRole('region', { name: 'Not decided' }, T)
    await userEvent.click(await within(section).findByRole('button', { name: /^Show or hide the not decided CVEs of RT-BACKUP/ }, T))
    const buttons = await within(section).findAllByRole('button', { name: /^Research CVE-.* deeper$/ }, T)
    expect(buttons[0]).toHaveTextContent(/^Research deeper$/)
  })
})

describe('Findings the AI opened, in the lists', () => {
  it('By device says "Found by your AI", marks an inferred one, links the page and offers "Not right?"', async () => {
    renderApp('/devices/a-pc01?tab=findings')
    // a fix block is closed on the device page: open the ones that name the AI's findings
    for (const b of await screen.findAllByRole('button', { name: /^Show or hide the CVEs of Update Eclipse Temurin JDK 21/ }, T)) await userEvent.click(b)
    const marks = await screen.findAllByTestId('found-by-ai', {}, T)
    expect(marks.length).toBeGreaterThanOrEqual(2)
    for (const m of marks) {
      expect(m).toHaveTextContent('Found by your AI')
      expect(within(m).getByRole('link', { name: /Source page/ })).toHaveAttribute('href', expect.stringMatching(/^https:/))
      expect(within(m).getByRole('button', { name: /^Not right: CVE-/ })).toBeInTheDocument()
    }
    expect(marks.filter((m) => /inferred/.test(m.textContent ?? ''))).toHaveLength(1)
  })

  it('By fix groups an AI finding under the fix its quote names, or "to a fixed release" when it names none', async () => {
    renderApp('/findings?tab=fix')
    const named = await screen.findByRole('article', { name: /Update Eclipse Temurin JDK 21 21\.0\.7 → 21\.0\.9$/ }, T)
    expect(named).toBeInTheDocument()
    expect(await screen.findByRole('article', { name: /Update Eclipse Temurin JDK 21 to a fixed release$/ }, T)).toBeInTheDocument()
  })
})

describe('Home', () => {
  it('says three numbers: decided by Vedette, researched by your AI and waiting for you, still unknown', async () => {
    renderApp('/')
    const line = await screen.findByTestId('home-undecided', {}, T)
    await waitFor(() => expect(line).toHaveTextContent(/[\d,]+ decided by Vedette/), T)
    // Vedette decides most CVEs: its figure is far above what is still unknown
    const nums = (line.textContent ?? '').match(/[\d,]+(?= decided by Vedette)|[\d,]+(?= still unknown)/g)!.map((x) => Number(x.replace(/,/g, '')))
    expect(nums[0]).toBeGreaterThan(nums[1]! * 10)
    await waitFor(() => expect(within(line).getByRole('link', { name: /^[\d,]+ researched by your AI, [1-9]\d* wait for you$/ })).toBeInTheDocument(), T)
    expect(within(line).getByRole('link', { name: /^[\d,]+ researched by your AI, \d+ wait for you$/ })).toHaveAttribute('href', '/findings?tab=review')
    expect(within(line).getByRole('link', { name: /^[\d,]+ still unknown$/ })).toHaveAttribute('href', '/findings?tab=possible')
  })
})
