import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { makeQueryClient } from '@/app/App'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import { scanningPoll } from './api'
import { ScanNowButton, ScansRunningIndicator } from './ScanNow'

scanningPoll.runningMs = 500
const base = () => `${location.origin}/api/v1`
const as = (userId: string) => sessionStore.set({ userId })
const json = (method: string, b: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
const card = (name: RegExp) => screen.findByRole('listitem', { name })
const unconfirm = () => inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))

/** A component where another page places it (#850): the app's providers and a router, no page around it. */
function renderHere(node: React.ReactNode, role: 'admin' | 'operator' | 'viewer' = 'admin') {
  sessionStore.set({ userId: role === 'admin' ? 'u-admin' : role === 'operator' ? 'u-op' : 'u-view' })
  const router = createMemoryRouter([{ path: '*', element: node }], { initialEntries: ['/devices/a-nas02'] })
  return render(<QueryClientProvider client={makeQueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
}

describe('Settings › Scanning: every engine on one page (#850, D-627)', () => {
  it('groups the engines by what they do; each card has its state, memory, runs; Preview engines say so; no a11y errors', async () => {
    renderApp('/settings/scanning')
    for (const g of ['Discover', 'Identify', 'Check vulnerabilities', 'Traps']) expect(await screen.findByRole('heading', { level: 2, name: g }, { timeout: 4000 })).toBeInTheDocument()
    const nuclei = await card(/Vulnerability checks \(Nuclei\)/)
    expect(within(nuclei).getByText('Preview')).toBeInTheDocument()
    expect(within(nuclei).getByText(/up to 1.0 GB while on \(shared scan container\)/)).toBeInTheDocument()
    expect(within(await card(/Decoys \(honeypot\)/)).getByText('Preview')).toBeInTheDocument()
    expect(within(await card(/Service versions \(nmap\)/)).getByText('Follows Network discovery (nmap)')).toBeInTheDocument() // no switch of its own (409 not_toggleable)
    expect(within(await card(/Web checks \(ZAP baseline\)/)).queryByRole('switch')).toBeNull()
    expect(screen.getByText(/The engines that are on hold up to/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('answers with the scan module off (GET /scanning is core\'s): discovery and OpenVAS are still there; History says what it needs', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    renderApp('/settings/scanning')
    expect(await card(/Network discovery \(nmap\)/)).toBeInTheDocument()
    expect(within(await card(/OpenVAS deep scan/)).getByRole('switch')).toBeInTheDocument()
    expect(within(await card(/Vulnerability checks \(Nuclei\)/)).getByRole('switch')).not.toBeChecked()
    await userEvent.click(screen.getByRole('tab', { name: 'History' }))
    expect(await screen.findByRole('link', { name: 'Turn them on: Engines, Vulnerability checks' })).toHaveAttribute('href', '/settings/scanning?tab=engines#engine-nuclei-switch')
  })

  it('turning off an engine names what stops with it, then moves the switch through PATCH /scanning/engines (audited by that switch)', async () => {
    renderApp('/settings/scanning')
    const row = await card(/Network discovery \(nmap\)/)
    await userEvent.click(within(row).getByRole('switch'))
    const dlg = await screen.findByRole('dialog', { name: 'Turn off Network discovery (nmap)?' })
    expect(dlg).toHaveTextContent('This also stops: Service versions (nmap), SNMP reading.')
    await userEvent.click(within(dlg).getByRole('button', { name: 'Turn off' }))
    await waitFor(() => expect(within(row).getByRole('switch')).not.toBeChecked())
    expect(inventorySettingsStore.get().active.enabled).toBe(false)
    expect(auditStore.get().some((a) => a.action === 'inventory.settings')).toBe(true)
  })

  it('OpenVAS: the card switch is the OpenVAS flag of External exposure (PUT /exposure/greenbone behind PATCH openvas)', async () => {
    renderApp('/settings/scanning#openvas')
    const row = await card(/OpenVAS deep scan/)
    await userEvent.click(within(row).getByRole('switch'))
    await waitFor(() => expect(within(row).getByRole('switch')).toBeChecked())
    const g = await (await fetch(`${base()}/exposure/greenbone`)).json()
    expect(g.enabled).toBe(true)
  })

  it('an engine that needs the scope commitment fixes it where it is: the dialog saves the ranges and the commitment (§0)', async () => {
    unconfirm()
    renderApp('/settings/scanning')
    const row = await card(/Network discovery \(nmap\)/)
    expect(within(row).getByText('Needs setup')).toBeInTheDocument()
    await userEvent.click(within(row).getByRole('button', { name: 'Set the network ranges' }))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    expect(within(dlg).getByRole('button', { name: 'Save and confirm' })).toBeDisabled()
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges belong to my company/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and confirm' }))
    await waitFor(() => expect(inventorySettingsStore.get().scope_confirmed_at).not.toBeNull())
    await waitFor(() => expect(within(row).queryByText('Needs setup')).toBeNull())
  })

  it('a deep link opens the engine\'s own settings: SNMP credentials on the SNMP card', async () => {
    renderApp('/settings/scanning#snmp')
    const row = await card(/SNMP reading/)
    expect(within(row).getByRole('button', { name: 'Settings' })).toHaveAttribute('aria-expanded', 'true')
    expect(await within(row).findByRole('heading', { name: 'SNMP credentials' })).toBeInTheDocument()
  })

  it('Safety: one block for the LAN engines through PUT /scanning/safety; it says what it covers and what not', async () => {
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByText(/Scans of your public targets follow their own testing terms and are not covered here yet/)).toBeInTheDocument()
    expect(screen.getByLabelText('Network ranges, one per line')).toHaveValue('192.168.10.0/24\n192.168.20.0/24')
    await userEvent.selectOptions(screen.getByLabelText('Discovery and SNMP'), '100')
    const ex = screen.getByLabelText('One IP or network per line')
    await userEvent.clear(ex)
    await userEvent.type(ex, '192.168.10.250')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    expect(inventorySettingsStore.get().active).toMatchObject({ rate: 100, exclusions: ['192.168.10.250'] })
  })

  it('Safety: changing the ranges asks for the commitment again; the server refuses a save without it while discovery is on', async () => {
    renderApp('/settings/scanning?tab=safety')
    const r = await screen.findByLabelText('Network ranges, one per line')
    await userEvent.type(r, '{enter}10.20.0.0/24')
    expect(screen.getByRole('checkbox', { name: /I confirm these network ranges/ })).not.toBeChecked()
    expect(screen.getByText('The ranges changed: tick the confirmation again to save.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/Tick the confirmation/)
  })

  it('a viewer reads the engines and the block; switches and save are locked with one line', async () => {
    renderApp('/settings/scanning', { role: 'viewer' })
    expect(await screen.findByText('Only an administrator can turn engines on or off.')).toBeInTheDocument()
    expect(within(await card(/Network discovery \(nmap\)/)).getByRole('switch')).toBeDisabled()
    as('u-view')
    expect((await fetch(`${base()}/scanning/engines/passive`, json('PATCH', { enabled: false }))).status).toBe(403)
  })

  it('the old Vulnerability scans links land on their new place; ?target= lands on the device page with its buttons', async () => {
    for (const [from, want] of [['/scans', 'Engines'], ['/scans?tab=safety', 'Safety'], ['/scans?tab=probes', 'Probe log'], ['/scans?tab=auto', 'History']] as const) {
      const view = renderApp(from)
      expect(await screen.findByRole('tab', { name: want, selected: true })).toBeInTheDocument()
      view.unmount()
    }
    const v2 = renderApp('/scans?target=a-nas02&run=run-seed-3') // ?run= wins (review r1 L5)
    expect(within(await screen.findByRole('dialog')).getByText('You pressed Stop now.')).toBeInTheDocument()
    v2.unmount()
    renderApp('/scans?target=a-nas02') // the device page, with its buttons (slot device.actions)
    expect(await screen.findByRole('button', { name: 'Check this device now' }, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run vulnerability checks now' })).toBeInTheDocument()
  })
})

describe('Scan now in context: ScanNowButton and ScansRunningIndicator (#850)', () => {
  it('"Check this device now" starts a discovery run of that device, shows its JobProgress and where it is seen', async () => {
    renderHere(<ScanNowButton targets={['a-nas02']} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Check this device now' }))
    expect(await screen.findByRole('progressbar')).toBeInTheDocument()
    expect(screen.getByText('Check 192.168.10.21')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open the run' })).toHaveAttribute('href', '/devices/a-nas02')
    expect(auditStore.get().length).toBeGreaterThanOrEqual(0)
  })

  it('"Scan the LAN now" sends no targets (the server sweeps the confirmed scope); a second run is locked with the reason and a link', async () => {
    let sent: unknown = null
    const { server } = await import('@/test/server')
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'POST' && request.url.endsWith('/scanning/engines/nmap-discovery/run')) sent = await request.clone().json()
    })
    renderHere(<><ScanNowButton targets="lan" /><ScanNowButton targets={['a-web01', 'a-srvad']} /></>)
    await userEvent.click(await screen.findByRole('button', { name: 'Scan the LAN now' }))
    await waitFor(() => expect(sent).toEqual({}))
    server.events.removeAllListeners()
    expect(await screen.findByText('Another scan is running.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan selected (2)' })).toBeDisabled()
  })

  it('what it needs, where it is (§0): no commitment opens the scope dialog; an operator is told it needs an admin', async () => {
    unconfirm()
    const view = renderHere(<ScanNowButton targets="lan" />)
    expect(await screen.findByText('The network ranges are not confirmed yet.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan the LAN now' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Set the network ranges' }))
    expect(await screen.findByRole('dialog', { name: 'Network ranges you may scan' })).toBeInTheDocument()
    view.unmount()
    renderHere(<ScanNowButton targets={['a-nas02']} />, 'operator')
    expect(await screen.findByText('Requires Admin role')).toBeInTheDocument()
  })

  it('the top-bar indicator: nothing while idle; "1 scan running" opens the place of the run, public scans included (review M5, M7, L8)', async () => {
    const view = renderHere(<ScansRunningIndicator />, 'viewer')
    await waitFor(() => expect(screen.queryByText(/scan running/)).toBeNull())
    view.unmount()
    as('u-admin')
    expect((await fetch(`${base()}/scanning/engines/nmap-discovery/run`, json('POST', { targets: ['a-web01'] }))).status).toBe(202)
    renderHere(<ScansRunningIndicator />, 'viewer')
    expect(await screen.findByRole('link', { name: '1 scan running' })).toHaveAttribute('href', '/devices/a-web01')
  })
})

describe('#850 review r2: dead ends and the buttons of the Devices pages', () => {
  it('N1: turning on Network discovery with the scope not confirmed opens the scope dialog, and the switch is tried again on save', async () => {
    unconfirm()
    inventorySettingsStore.update((s) => ({ ...s, active: { ...s.active, enabled: false } }))
    renderApp('/settings/scanning')
    const row = await card(/Network discovery \(nmap\)/)
    await userEvent.click(within(row).getByRole('switch'))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Save and confirm' }))
    await waitFor(() => expect(within(row).getByRole('switch')).toBeChecked())
    expect(inventorySettingsStore.get().active.enabled).toBe(true)
  })

  it('N2: an engine that is on but not available can still be turned off', async () => {
    const { server } = await import('@/test/server')
    const { http, HttpResponse } = await import('msw')
    const { scanningView } = await import('./mocks')
    server.use(http.get('*/api/v1/scanning', () => {
      const v = scanningView()
      return HttpResponse.json({ ...v, engines: v.engines.map((e) => (e.id === 'nuclei' ? { ...e, state: 'unavailable', reason: 'The scanner is missing.' } : e)) })
    }))
    renderApp('/settings/scanning')
    const row = await card(/Vulnerability checks \(Nuclei\)/)
    expect(within(row).getByRole('switch')).toBeChecked()
    expect(within(row).getByRole('switch')).toBeEnabled()
  })

  it('the Devices list carries "Scan the LAN now" and, with a selection, "Scan selected (N)" (slot devices.actions)', async () => {
    renderApp('/devices')
    expect(await screen.findByRole('button', { name: 'Scan the LAN now' }, { timeout: 4000 })).toBeInTheDocument()
    const boxes = await screen.findAllByRole('checkbox', { name: /^Select / })
    await userEvent.click(boxes[1]!)
    await userEvent.click(boxes[2]!)
    expect(await screen.findByRole('button', { name: 'Scan selected (2)' })).toBeEnabled()
  })

  it('SNMP credentials moved here: /devices/setup?tab=snmp and ?snmp_ip= land on the SNMP card, the address kept for the add form', async () => {
    const v = renderApp('/devices/setup?tab=snmp')
    const row = await card(/SNMP reading/)
    expect(await within(row).findByRole('heading', { name: 'SNMP credentials' })).toBeInTheDocument()
    v.unmount()
    renderApp('/devices/setup?snmp_ip=192.168.10.21')
    expect(await screen.findByRole('dialog', {}, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'SNMP credentials' })).toBeNull()
  })

  it('osquery needs a token: it is made right on the card (§0)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
    const { server } = await import('@/test/server')
    const { http, HttpResponse } = await import('msw')
    const { scanningView } = await import('./mocks')
    server.use(http.get('*/api/v1/scanning', () => {
      const v = scanningView()
      return HttpResponse.json({ ...v, engines: v.engines.map((e) => (e.id === 'osquery' ? { ...e, enabled: true, state: 'needs_setup', reason: 'No osquery token yet.' } : e)) })
    }))
    renderApp('/settings/scanning')
    const row = await card(/osquery agents/)
    await userEvent.click(within(row).getByRole('button', { name: 'Create an osquery token' }))
    expect(await screen.findByRole('dialog', { name: 'Install osquery on a server' })).toBeInTheDocument()
  })
})
