import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { networkStore } from '@/mocks/network'
import { installStore, modulesStore, sessionStore } from '@/mocks/stores'
import { badAddressRow } from './DetectionPage'
import type { Watcher } from './types'

const T = { timeout: 5000 }
const row = async (id: string) => within(await screen.findByTestId(`watcher-${id}`, undefined, T))

describe('intrusion detection page', () => {
  it('shows each watcher with its true state and one action, and no row for an engine that does not exist', async () => {
    renderApp('/detection')
    expect(await screen.findByRole('heading', { level: 1, name: 'Intrusion detection' }, T)).toBeInTheDocument()
    const items = (await screen.findAllByTestId(/^watcher-/, undefined, T)).map((x) => x.getAttribute('data-testid'))
    expect(items).toEqual(['watcher-traps', 'watcher-logs', 'watcher-mirror_port', 'watcher-ips_events', 'watcher-bad-addresses'])
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

  it('with IPS events coming in, the row has no link to the alerts list it sits above (no jump to the page it is on)', async () => {
    renderApp('/detection')
    await screen.findByRole('table', { name: 'Intrusion alerts' }, T)
    const ips = await row('ips_events')
    expect(ips.queryByRole('link')).toBeNull()
    expect(document.querySelector('a[href="#alerts"]')).toBeNull()
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

describe('intrusion detection: the bad-address row says what feeds it', () => {
  const w = (id: Watcher['id'], state: Watcher['state'], last: string | null = null): Watcher => ({ id, module: 'x', state, detail: '', last_input_at: last, detections_7d: 0, action: null })
  it('watching while the mirror port or received logs are; else it needs one of them, with the step to take', () => {
    expect(badAddressRow([w('logs', 'watching', '2026-11-24T00:00:00.000Z'), w('mirror_port', 'not_set_up')])).toMatchObject({ state: 'watching', sources: ['logs'], last: '2026-11-24T00:00:00.000Z' })
    expect(badAddressRow([w('logs', 'quiet'), w('mirror_port', 'not_set_up')])).toMatchObject({ state: 'quiet', to: '/logs?tab=sources' })
    expect(badAddressRow([w('logs', 'not_set_up'), w('mirror_port', 'not_set_up')])).toMatchObject({ state: 'not_set_up', to: '/logs?tab=sources&add=source' })
    expect(badAddressRow([w('logs', 'off'), w('mirror_port', 'off')])).toMatchObject({ state: 'not_set_up', to: '/settings/modules#module-logs' })
  })

  it('fed by received logs alone, it says DNS lookups of the box and the LAN need a mirror port or a DNS log, with the step to add one', () => {
    expect(badAddressRow([w('logs', 'watching', '2026-11-24T00:00:00.000Z'), w('mirror_port', 'not_set_up')]).dnsGap).toBe('/logs?tab=sources&add=source')
    expect(badAddressRow([w('logs', 'quiet'), w('mirror_port', 'off')]).dnsGap).toBe('/logs?tab=sources&add=source')
    // a mirror port sees the lookups on the LAN: nothing to add
    expect(badAddressRow([w('logs', 'watching'), w('mirror_port', 'watching')]).dnsGap).toBeNull()
    expect(badAddressRow([w('logs', 'off'), w('mirror_port', 'quiet')]).dnsGap).toBeNull()
    // nothing feeds it: the row's own text already says what is needed
    expect(badAddressRow([w('logs', 'not_set_up'), w('mirror_port', 'not_set_up')]).dnsGap).toBeNull()
  })

  it('on the page, logs without a mirror port: the DNS line and its link are on the row', async () => {
    networkStore.update((s) => ({ ...s, span: { ...s.span, enabled: false, interface: null }, ifaces: s.ifaces.map((i) => (i.role === 'span' ? { ...i, role: 'unused' as const } : i)) }))
    renderApp('/detection')
    const r = await row('bad-addresses')
    expect(r.getByTestId('bad-addresses-dns-gap')).toHaveTextContent(/Without a mirror port, the names the box and the devices on your LAN look up \(DNS\)/)
    expect(r.getByRole('link', { name: 'Add a DNS log source' })).toHaveAttribute('href', '/logs?tab=sources&add=source')
  })

  it('on the page, with no input: it says a mirror port or a firewall or DNS log is needed and offers to add a log source', async () => {
    renderApp('/detection')
    const r = await row('bad-addresses')
    expect(r.getByText('Bad addresses')).toBeInTheDocument()
    expect(r.getByText(/^(Watching|Quiet|Not set up)$/)).toBeInTheDocument()
    for (const l of r.getAllByRole('link')) expect(l).toHaveAttribute('href', expect.stringMatching(/^\/(logs|settings)/))
  })
})
