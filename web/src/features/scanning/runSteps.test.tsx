// A run's page lists every step of the scan in order, each with its state and, when it did not simply finish, why; its breadcrumb and
// the menu lead back to what the run is about (the target's Scans tab, the device), or to Settings › Scanning › Runs when opened there.
import { describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { renderApp } from '@/test/render'

vi.setConfig({ testTimeout: 20_000 })
const T = { timeout: 5000 }

const stepsOf = async (title: string) => within(await screen.findByRole('list', { name: `Steps of ${title}` }, T)).getAllByRole('listitem')
const crumbs = () => within(screen.getByRole('navigation', { name: 'Breadcrumb' })).getAllByRole('link').map((a) => [a.textContent, a.getAttribute('href')])
/** The menu entry the sidebar marks as the current place. */
const current = () => [...document.querySelectorAll('nav a.nav-current')].map((a) => a.textContent?.trim() ?? '')

describe('the steps of a run', () => {
  it('a deep scan that runs lists every step in order: what each found, and OpenVAS running with where it is', async () => {
    renderApp('/runs/run-x14-3')
    const items = await stepsOf('Scan of 198.51.100.2')
    expect(items.map((li) => li.querySelector('.text-sm')?.textContent?.replace(/^\w[\w ]*: /, ''))).toEqual([
      'Check ownership, terms and safety rules', 'Common ports, web pages and certificates', 'Find open ports (every TCP port)',
      "Identify services and run nmap's scripts", 'Templates (nuclei)', 'Passive web scan (ZAP)', 'Compare with exploited CVEs and save the results', 'OpenVAS',
    ])
    expect(within(items[0]!).getByText('Done:')).toHaveClass('sr-only') // done is a check mark, said to a screen reader
    expect(within(items[4]!).getByText(/3 ports were not scanned, over the limit of 40 jobs a scan/)).toBeInTheDocument()
    expect(within(items[7]!).getAllByText(/Running/).length).toBeGreaterThan(0)
    expect(within(items[7]!).getByText('41%')).toBeInTheDocument()
    expect(screen.getByText('7 of 8 steps finished')).toBeInTheDocument()
    expect(screen.getByText('7 of 8 steps')).toBeInTheDocument() // the run's own line
    // the log has a line for each start and end, not one "Started"
    expect(screen.getByText(/Log \(\d+ lines\)/).textContent).not.toBe('Log (1 line)')
  })

  it('a finished scan shows the step that failed and the one skipped, each with why, and the one that ended with a problem', async () => {
    renderApp('/runs/run-x14-2')
    const items = await stepsOf('Scan of 198.51.100.2')
    expect(within(items[4]!).getAllByText(/Partly done/).length).toBeGreaterThan(0)
    expect(within(items[4]!).getByText(/port 9443 stopped answering/)).toHaveClass('text-warn')
    expect(within(items[5]!).getAllByText(/Skipped/).length).toBeGreaterThan(0)
    expect(within(items[5]!).getByText(/its image is being downloaded/)).toBeInTheDocument()
    expect(within(items[7]!).getAllByText(/Failed/).length).toBeGreaterThan(0)
    expect(within(items[7]!).getByText(/OpenVAS did not finish within 90 minutes/)).toHaveClass('text-danger')
    expect(screen.getByText('8 of 8 steps finished · 1 failed')).toBeInTheDocument()
  })

  it('a domain\'s deep scan has a step per address it scanned and one for the addresses left for the next scans', async () => {
    renderApp('/runs/run-x11-2')
    const items = await stepsOf('Scan of example.com')
    expect(within(items[2]!).getByText(/Deep scan of 203.0.113.20/)).toBeInTheDocument()
    expect(within(items[3]!).getByText(/nmap did not finish on this address/)).toBeInTheDocument()
    expect(within(items[4]!).getByText(/2 addresses wait for the next scans/)).toBeInTheDocument()
    expect(within(items[8]!).getByText(/OpenVAS is off/)).toBeInTheDocument()
  })
})

describe('where a run belongs', () => {
  it('a public scan\'s run leads back to its target\'s Scans tab and keeps External exposure lit', async () => {
    renderApp('/runs/run-x14-3')
    await stepsOf('Scan of 198.51.100.2')
    expect(crumbs()).toEqual([['External exposure', '/exposure'], ['198.51.100.2', '/exposure/xt-14'], ['Scans', '/exposure/xt-14?tab=scans']])
    expect(current()).toContain('External exposure')
    expect(current()).not.toContain('Settings')
  })

  it('a device check\'s run leads back to the device', async () => {
    renderApp('/runs/run-m2')
    expect(await screen.findByRole('heading', { level: 1, name: 'Check NAS-PHOTOS' }, T)).toBeInTheDocument()
    expect(crumbs()).toEqual([['Devices', '/devices'], ['NAS-PHOTOS', '/devices/a-nas02']])
    expect(current()).toContain('Devices')
  })

  it('a run opened from Settings › Scanning › Runs leads back there; a run about no one subject does too', async () => {
    renderApp('/runs/run-x14-3?from=settings')
    await stepsOf('Scan of 198.51.100.2')
    expect(crumbs()).toEqual([['Scanning', '/settings/scanning'], ['Runs', '/settings/scanning?tab=runs']])
    expect(current()).toContain('Settings')
  })

  it('a LAN sweep, about no one subject, belongs to Settings › Scanning › Runs', async () => {
    renderApp('/runs/run-m1')
    expect(await screen.findByRole('heading', { level: 1, name: 'LAN sweep of 192.0.2.0/24, 10.20.0.0/16' }, T)).toBeInTheDocument()
    expect(crumbs()).toEqual([['Scanning', '/settings/scanning'], ['Runs', '/settings/scanning?tab=runs']])
  })
})

describe('a target\'s Scans tab', () => {
  it('shows the newest scan\'s steps, the same list as its run page, and opens the run', async () => {
    renderApp('/exposure/xt-14?tab=scans')
    const items = within(await screen.findByRole('list', { name: /^Steps of the scan of / }, T)).getAllByRole('listitem')
    expect(items).toHaveLength(8)
    expect(screen.getByText(/OpenVAS did not finish within 90 minutes, so its results are not shown/)).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: /^Latest scan/ })).toBeInTheDocument()
    expect(screen.getAllByRole('link', { name: 'Open the run' }).some((a) => a.getAttribute('href') === '/runs/run-x14-2')).toBe(true)
  })
})
