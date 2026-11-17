// Updates to plan (S-TIER-1, S-TIER-2) and the CVE page of a CVE on no exploited list.
import { describe, expect, it } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { tierState } from '@/mocks/tiers'
import { modulesStore } from '@/mocks/stores'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'

describe('Updates to plan (S-TIER-1, S-TIER-2)', () => {
  it('one item per update on one device, the CVEs with tier, published day and evidence; the filter narrows; no a11y violation', async () => {
    renderApp('/plan')
    // With no filter picked, the page opens on "Likely to be exploited" when some update fixes such a CVE
    // the heading names the tab it counts
    expect(await screen.findByRole('heading', { level: 1, name: '3 recommended updates for CVEs likely to be exploited' })).toBeInTheDocument()
    // The first line says the list is Vedette's own, not a to-do list a person fills
    expect(screen.getByText(/Vedette makes this list by itself/)).toBeInTheDocument()
    expect(screen.getByText(/FIRST estimates at least a 1 in 10 chance they are exploited/)).toBeInTheDocument()
    expect(screen.getByText('fixes 2 CVEs likely to be exploited (All lists every CVE it fixes)')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'All (4)' }))
    expect(await screen.findByRole('heading', { level: 1, name: '4 recommended updates' })).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Recommended updates' })
    expect(within(list).getByText(/Install the latest cumulative update for Windows Server 2022 \(from build 20348\.2700 to 20348\.4405 or later\)/)).toBeInTheDocument()
    expect(within(list).getByText('(2 likely to be exploited)')).toBeInTheDocument()
    expect(screen.getByText('1 CVE published more than 12 months ago is listed because a scan found it on the device.')).toBeInTheDocument()
    const nas = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('NAS-BACKUP'))!
    await userEvent.click(within(nas).getByText('Show the 2 CVEs'))
    const table = within(nas).getByRole('table')
    expect(within(table).getByRole('link', { name: 'CVE-2024-28870' })).toHaveAttribute('href', '/cve/CVE-2024-28870')
    expect(within(table).getByText('Found by a scan')).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: 'About Found by a scan' })).toHaveAccessibleDescription('A scan engine (nuclei, OpenVAS or ZAP) found it on the device') // #824: ⓘ, not a hover title
    expect(within(table).getByText('Over 12 months ago')).toBeInTheDocument()
    // #803: what each chip means is text under the list, not only a title
    // #824: each chip also has an ⓘ whose hidden text is its description; the legend is the visible copy
    const hint = within(nas).getAllByText(/A scan engine \(nuclei, OpenVAS or ZAP\) found it on the device/).find((el) => el.closest('dl'))!
    expect(hint).toBeVisible()
    expect(within(hint.closest('dl')!).getByText(/The exact version you entered, or the device states/)).toBeVisible()
    await expectNoA11yViolations()
    await userEvent.click(screen.getByRole('button', { name: /^Recent \(\d+\)$/ }))
    await waitFor(() => expect(screen.queryByText(/Upgrade Synology NAS/)?.closest('li')?.textContent).toMatch(/fixes 1 CVE(?!s)/))
  })

  it('a long list opens on its first 50 CVEs, likely first then by severity, with "Show all"; a distribution package names its fixed version', async () => {
    renderApp('/plan?tier=all')
    const list = await screen.findByRole('list', { name: 'Recommended updates' })
    expect(within(list).getByText('Upgrade the openssl package from 3.0.2-0ubuntu1.18 to 3.0.2-0ubuntu1.20 or later')).toBeInTheDocument()
    const win = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('Windows Server 2022'))!
    await userEvent.click(within(win).getByText('Show the 65 CVEs'))
    const rows = () => within(within(win).getByRole('table')).getAllByRole('row').length - 1
    expect(rows()).toBe(50)
    const [, first] = within(within(win).getByRole('table')).getAllByRole('row')
    expect(within(first!).getByText('Likely to be exploited')).toBeInTheDocument()
    expect(within(win).getByText('The 50 that matter most of 65: likely to be exploited first, then by severity.')).toBeInTheDocument()
    await userEvent.click(within(win).getByRole('button', { name: 'Show all 65 CVEs' }))
    expect(rows()).toBe(65)
    // #808: focus lands on the first CVE the button revealed
    const [, ...cveRows] = within(within(win).getByRole('table')).getAllByRole('row')
    expect(within(cveRows[50]!).getByRole('link')).toHaveFocus()
    expect(within(win).queryByRole('button', { name: 'Show all 65 CVEs' })).not.toBeInTheDocument()
  })

  it('not compared yet comes first: no invitation to turn the feeds on, no device section (#803)', async () => {
    tierState.set({ epss: 'off', recent: 'off', compared: false })
    const { unmount } = renderApp('/plan')
    expect(await screen.findByText('Not compared yet')).toBeInTheDocument()
    expect(screen.queryByText('Turn on the CVE data to see recommended updates')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open Settings, Feeds' })).not.toBeInTheDocument()
    expect(screen.queryByText('No recommended update')).not.toBeInTheDocument()
    unmount()
    const dev = renderApp('/devices/a-web01')
    expect(await screen.findByRole('heading', { name: 'Findings on this device' })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Recommended updates' })).not.toBeInTheDocument())
    dev.unmount()
    tierState.set({ epss: 'ready', recent: 'ready', compared: false })
    renderApp('/plan')
    expect(await screen.findByText('Not compared yet')).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Recommended updates' })).not.toBeInTheDocument()
  })

  it('once compared, says what is missing: feeds off (with the way to turn them on), or the feeds module off', async () => {
    tierState.set({ epss: 'off', recent: 'off', compared: true })
    const { unmount } = renderApp('/plan')
    expect(await screen.findByText('Turn on the CVE data to see recommended updates')).toBeInTheDocument()
    // docs/UI.md §0: the link names the exact switch (the first missing feed)
    expect(screen.getByRole('link', { name: 'Open Settings, Feeds' })).toHaveAttribute('href', '/settings/feeds#feed-epss-all')
    unmount()
    tierState.set({ epss: 'ready', recent: 'ready', compared: true })
    modulesStore.update((l) => l.map((m) => (m.id === 'feeds' ? { ...m, enabled: false } : m)))
    renderApp('/plan')
    expect(await screen.findByText('The feeds module is off')).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Recommended updates' })).not.toBeInTheDocument()
  })

  it('do it where you are (docs/UI.md §0): an administrator turns the missing feeds on from the page', async () => {
    tierState.set({ epss: 'off', recent: 'off', compared: true })
    renderApp('/plan')
    await userEvent.click(await screen.findByRole('button', { name: 'Turn on both feeds' }))
    // both feeds start their first load: the page now says so, with nothing left to turn on
    expect(await screen.findByText('Part of the CVE data is missing')).toBeInTheDocument()
    expect(screen.getByText(/still loading/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Turn on/ })).not.toBeInTheDocument()
    expect(tierState.get()).toMatchObject({ epss: 'loading', recent: 'loading' })
  })

  it('a viewer gets no Turn on button, only the exact link (docs/UI.md §0)', async () => {
    tierState.set({ epss: 'ready', recent: 'off', compared: true })
    renderApp('/plan', { role: 'viewer' })
    expect(await screen.findByText('Part of the CVE data is missing')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /^Turn on/ })).not.toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Settings, Feeds' })).toHaveAttribute('href', '/settings/feeds#feed-nvd-recent')
  })

  it('an administrator turns the feeds module on from the page (docs/UI.md §0)', async () => {
    tierState.set({ epss: 'ready', recent: 'ready', compared: true })
    modulesStore.update((l) => l.map((m) => (m.id === 'feeds' ? { ...m, enabled: false } : m)))
    renderApp('/plan')
    await userEvent.click(await screen.findByRole('button', { name: 'Turn on the feeds module' }))
    await waitFor(() => expect(modulesStore.get().find((m) => m.id === 'feeds')?.enabled).toBe(true))
    // #879: the page reads the plan again, so the "module is off" Notice and its button go away with the toast
    expect(await screen.findByText('The feeds module is on.')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('The feeds module is off')).toBeNull())
    expect(screen.queryByRole('button', { name: 'Turn on the feeds module' })).toBeNull()
  })

  it('Findings links to the page; the device page lists its own items', async () => {
    const { unmount } = renderApp('/findings')
    // Each number opens the tab that shows that many updates, and that tab's heading says the same number
    expect(await screen.findByRole('link', { name: '4 updates in all' })).toHaveAttribute('href', '/plan?tier=all')
    await userEvent.click(screen.getByRole('link', { name: '3 recommended updates fix CVEs likely to be exploited' }))
    expect(await screen.findByRole('heading', { level: 1, name: '3 recommended updates for CVEs likely to be exploited' })).toBeInTheDocument()
    // M1 of r1: from the sidebar too, the filters say "1 likely, 3 in all" (counts from the one answer)
    expect(screen.getByRole('button', { name: 'Likely to be exploited (3)' })).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByRole('button', { name: 'All (4)' })).toBeInTheDocument()
    unmount()
    renderApp('/devices/a-web01')
    expect(await screen.findByRole('heading', { name: 'Recommended updates' })).toBeInTheDocument()
    expect(await screen.findByText(/Upgrade nginx from 1\.18\.0 to 1\.28\.1 or later/)).toBeInTheDocument()
    expect(screen.queryByText(/Windows Server 2022/)).not.toBeInTheDocument()
  })

  // L2 of r1: the other shapes of the Findings line and the Recent heading
  const answer = (tiers: ('likely' | 'recent')[]) => {
    const items = tiers.map((t, i) => ({ group: `a-${i}/s`, asset: { id: `a-${i}`, name: `pc-${i}` }, software: 'nginx', version: '1.18.0', fixed: '1.28.1', kind: 'fixed', pro: false,
      cves: [{ cve: `CVE-2026-4100${i}`, tier: t, basis: 'agent', severity: 'high', score: 7.5, published: '2026-10-01', epss: t === 'likely' ? 0.3 : 0.01, percentile: 0.9 }],
      likely: t === 'likely' ? 1 : 0, recent: t === 'recent' ? 1 : 0 }))
    return { items, counts: { likely: tiers.filter((t) => t === 'likely').length, recent: tiers.filter((t) => t === 'recent').length, all: tiers.length },
      compared: true, compared_devices: tiers.length, unchecked_devices: 0, old_evidence: 0, data: { epss: 'ready', recent: 'ready', epss_date: '2026-11-16', recent_since: '2025-11-16' } }
  }
  const serve = async (tiers: ('likely' | 'recent')[]) => {
    const { server } = await import('@/test/server')
    const { http, HttpResponse } = await import('msw')
    server.use(http.get('*/api/v1/findings/plan', () => HttpResponse.json(answer(tiers))))
  }

  it('no update fixes a likely CVE: the line counts every update and opens All', async () => {
    await serve(['recent', 'recent'])
    renderApp('/findings')
    expect(await screen.findByRole('link', { name: '2 recommended updates fix CVEs not exploited yet' })).toHaveAttribute('href', '/plan?tier=all')
    expect(screen.queryByRole('link', { name: /in all$/ })).toBeNull()
  })

  it('every update fixes a likely CVE: one link, singular, no "in all"', async () => {
    await serve(['likely'])
    renderApp('/findings')
    expect(await screen.findByRole('link', { name: '1 recommended update fixes CVEs likely to be exploited' })).toHaveAttribute('href', '/plan?tier=likely')
    expect(screen.queryByRole('link', { name: /in all$/ })).toBeNull()
  })

  it('the Recent tab heading names its tier', async () => {
    renderApp('/plan?tier=recent')
    expect(await screen.findByRole('heading', { level: 1, name: /^\d+ recommended updates? for recent CVEs$/ })).toBeInTheDocument()
  })

  // The evidence follows how the version is known now: a build an agent reported reads "Last reported by an agent" once no agent of
  // the box reports the device (agent-intake's report state, the answer "I updated it" reads), on the list and on the CVE page.
  it('an agent row\'s evidence says when no agent reports the device now', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
    let agent = 'none'
    server.use(http.get('*/api/v1/inventory/agents/devices/:id/report', () =>
      HttpResponse.json({ agent, asked_at: null, ask_again_at: null, last_seen: null, stale: false, wazuh_interval_minutes: null })))
    renderApp('/plan?tier=all')
    const list = await screen.findByRole('list', { name: 'Recommended updates' })
    const win = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('Windows Server 2022'))!
    await userEvent.click(within(win).getByText('Show the 65 CVEs'))
    const table = within(win).getByRole('table')
    expect((await within(table).findAllByText('Last reported by an agent')).length).toBe(50)
    expect(within(table).queryByText('Reported by the agent')).toBeNull()
    expect(within(win).getAllByText(/No agent reports this device now: the build or package is from the last list an agent sent/).find((el) => el.closest('dl'))).toBeVisible()
    await expectNoA11yViolations()
    cleanup()

    agent = 'osquery'
    renderApp('/plan?tier=all')
    const again = await screen.findByRole('list', { name: 'Recommended updates' })
    const item = within(again).getAllByRole('listitem').find((li) => li.textContent?.includes('Windows Server 2022'))!
    await userEvent.click(within(item).getByText('Show the 65 CVEs'))
    expect(within(within(item).getByRole('table')).getAllByText('Reported by the agent').length).toBe(50)
    expect(within(item).queryByText('Last reported by an agent')).toBeNull()
  })

  it('the CVE page answers for a CVE on no exploited list, with its devices from Updates to plan', async () => {
    renderApp('/cve/CVE-2026-31001')
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2026-31001' })).toBeInTheDocument()
    expect(screen.getByText('Not on an exploited list')).toBeInTheDocument()
    expect(screen.getByText('F5 nginx')).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'WEB01' })).toHaveAttribute('href', '/devices/a-web01')
  })
})
