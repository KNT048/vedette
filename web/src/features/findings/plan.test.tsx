// Updates to plan (S-TIER-1, S-TIER-2; D-613, D-615, D-616) and the CVE page of a CVE on no exploited list.
import { describe, expect, it } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { tierState } from '@/mocks/tiers'
import { modulesStore } from '@/mocks/stores'

describe('Updates to plan (S-TIER-1, S-TIER-2)', () => {
  it('one item per update on one device, the CVEs with tier, published day and evidence; the filter narrows; no a11y violation', async () => {
    renderApp('/plan')
    expect(await screen.findByRole('heading', { level: 1, name: '4 updates to plan' })).toBeInTheDocument()
    const list = screen.getByRole('list', { name: 'Updates to plan' })
    expect(within(list).getByText(/Install the latest cumulative update for Windows Server 2022 \(build 20348\.4405 or later\)/)).toBeInTheDocument()
    expect(within(list).getByText('(2 likely to be exploited)')).toBeInTheDocument()
    expect(screen.getByText('1 CVE published more than 12 months ago is listed because a scan found it on the device.')).toBeInTheDocument()
    const nas = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('NAS-BACKUP'))!
    await userEvent.click(within(nas).getByText('Show the 2 CVEs'))
    const table = within(nas).getByRole('table')
    expect(within(table).getByRole('link', { name: 'CVE-2024-28870' })).toHaveAttribute('href', '/cve/CVE-2024-28870')
    expect(within(table).getByText('Found by a scan')).toBeInTheDocument()
    expect(within(table).getByText('Over 12 months ago')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(screen.getByRole('button', { name: 'Recent' }))
    await waitFor(() => expect(screen.queryByText(/Upgrade Synology NAS/)?.closest('li')?.textContent).toMatch(/fixes 1 CVE(?!s)/))
  })

  it('not compared yet comes first: no invitation to turn the feeds on, no device section (review r1 #4 of #803)', async () => {
    tierState.set({ epss: 'off', recent: 'off', compared: false })
    const { unmount } = renderApp('/plan')
    expect(await screen.findByText('Not compared yet')).toBeInTheDocument()
    expect(screen.queryByText('Turn on the CVE data to see updates to plan')).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: 'Open Settings, Feeds' })).not.toBeInTheDocument()
    expect(screen.queryByText('No update to plan')).not.toBeInTheDocument()
    unmount()
    const dev = renderApp('/devices/a-web01')
    expect(await screen.findByRole('heading', { name: 'Findings on this device' })).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByRole('heading', { name: 'Updates to plan' })).not.toBeInTheDocument())
    dev.unmount()
    tierState.set({ epss: 'ready', recent: 'ready', compared: false })
    renderApp('/plan')
    expect(await screen.findByText('Not compared yet')).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Updates to plan' })).not.toBeInTheDocument()
  })

  it('once compared, says what is missing: feeds off (with the way to turn them on), or the feeds module off', async () => {
    tierState.set({ epss: 'off', recent: 'off', compared: true })
    const { unmount } = renderApp('/plan')
    expect(await screen.findByText('Turn on the CVE data to see updates to plan')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Settings, Feeds' })).toHaveAttribute('href', '/settings/feeds')
    unmount()
    tierState.set({ epss: 'ready', recent: 'ready', compared: true })
    modulesStore.update((l) => l.map((m) => (m.id === 'feeds' ? { ...m, enabled: false } : m)))
    renderApp('/plan')
    expect(await screen.findByText('The feeds module is off')).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Updates to plan' })).not.toBeInTheDocument()
  })

  it('Findings links to the page; the device page lists its own items', async () => {
    const { unmount } = renderApp('/findings')
    expect(await screen.findByRole('link', { name: '4 updates to plan fix CVEs not exploited yet' })).toHaveAttribute('href', '/plan')
    unmount()
    renderApp('/devices/a-web01')
    expect(await screen.findByRole('heading', { name: 'Updates to plan' })).toBeInTheDocument()
    expect(await screen.findByText(/Upgrade nginx from 1\.18\.0 to 1\.28\.1 or later/)).toBeInTheDocument()
    expect(screen.queryByText(/Windows Server 2022/)).not.toBeInTheDocument()
  })

  it('the CVE page answers for a CVE on no exploited list, with its devices from Updates to plan', async () => {
    renderApp('/cve/CVE-2026-31001')
    expect(await screen.findByRole('heading', { level: 1, name: 'CVE-2026-31001' })).toBeInTheDocument()
    expect(screen.getByText('Not on an exploited list')).toBeInTheDocument()
    expect(screen.getByText('F5 nginx')).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: 'WEB01' })).toHaveAttribute('href', '/devices/a-web01')
  })
})
