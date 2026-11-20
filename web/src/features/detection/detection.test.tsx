import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { networkStore } from '@/mocks/network'
import { installStore, modulesStore, sessionStore } from '@/mocks/stores'

const T = { timeout: 5000 }
const row = async (id: string) => within(await screen.findByTestId(`watcher-${id}`, undefined, T))

describe('intrusion detection page', () => {
  it('shows each watcher with its true state and one action, and no row for an engine that does not exist', async () => {
    renderApp('/detection')
    expect(await screen.findByRole('heading', { level: 1, name: 'Intrusion detection' }, T)).toBeInTheDocument()
    const items = (await screen.findAllByTestId(/^watcher-/, undefined, T)).map((x) => x.getAttribute('data-testid'))
    expect(items).toEqual(['watcher-traps', 'watcher-logs', 'watcher-mirror_port', 'watcher-ips_events'])
    expect(document.body.textContent).not.toMatch(/Suricata|signature engine/i)
    const mirror = await row('mirror_port')
    expect(mirror.getByText('Watching')).toBeInTheDocument()
    expect(mirror.getByRole('link', { name: 'Open mirror port' })).toHaveAttribute('href', '/settings/network#span')
    await expectNoA11yViolations()
  })

  it('without a mirror port the row says it is not set up and the way to set one up is on the row', async () => {
    networkStore.update((s) => ({ ...s, span: { ...s.span, enabled: false, interface: null }, ifaces: s.ifaces.map((i) => (i.role === 'span' ? { ...i, role: 'unused' as const } : i)) }))
    renderApp('/detection')
    const mirror = await row('mirror_port')
    expect(mirror.getByText('Not set up')).toBeInTheDocument()
    expect(mirror.getByRole('link', { name: 'Set up a mirror port' })).toHaveAttribute('href', '/settings/network#span')
  })

  it('on a container-only install the mirror port is set up on the sensor card', async () => {
    installStore.set({ kind: 'container' })
    renderApp('/detection')
    const mirror = await row('mirror_port')
    expect(mirror.getByRole('link', { name: /mirror port$/ })).toHaveAttribute('href', '/devices/setup?tab=sensor')
  })

  it('lists the alerts with their incident and opens one in full with its finding', async () => {
    const u = userEvent.setup()
    renderApp('/detection')
    const table = await screen.findByRole('table', { name: 'Intrusion alerts' }, T)
    const nas = within(table).getByRole('link', { name: 'QNAP.Photo.Station.Path.Traversal' }).closest('tr')!
    expect(within(nas).getByText('Critical')).toBeInTheDocument()
    expect(within(nas).getByRole('link', { name: 'Incident new' })).toHaveAttribute('href', '/incidents/in-ids-1')
    // An alert outside the 7-day range is not in the default list
    expect(within(table).queryByText(/FortiOS SSL VPN/)).toBeNull()
    await u.click(within(nas).getByRole('link', { name: 'QNAP.Photo.Station.Path.Traversal' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'QNAP.Photo.Station.Path.Traversal' }, T)).toBeInTheDocument()
    expect(await screen.findByRole('link', { name: /Finding on / }, T)).toHaveAttribute('href', expect.stringMatching(/^\/findings\//))
    expect(screen.getByRole('link', { name: 'Handle it on the incident' })).toHaveAttribute('href', '/incidents/in-ids-1')
  })

  it('while the ids module is off there is no alert list and the row offers to turn it on', async () => {
    modulesStore.update((l) => [...l.filter((m) => (m.id as string) !== 'ids'), { id: 'ids', enabled: false, tier: 'optional', depends: ['logs'], enabled_at: null, available: true } as never])
    sessionStore.update((s) => ({ ...s }))
    renderApp('/detection')
    const ips = await row('ips_events')
    expect(ips.getByText('Off')).toBeInTheDocument()
    expect(ips.getByRole('link', { name: 'Turn on IPS events' })).toHaveAttribute('href', '/settings/modules#module-ids')
    expect(screen.queryByRole('table', { name: 'Intrusion alerts' })).toBeNull()
  })
})
