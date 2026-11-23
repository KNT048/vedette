import { describe, expect, it } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClientProvider } from '@tanstack/react-query'
import { createMemoryRouter, RouterProvider } from 'react-router'
import { makeQueryClient } from '@/app/App'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { assetsStore, auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { inventorySettingsStore } from '@/features/inventory/mocks'
import { scanningPoll } from './api'
import { ScanNowButton, ScansRunningIndicator } from './ScanNow'

scanningPoll.runningMs = 500
const T = { timeout: 4000 }
const base = () => `${location.origin}/api/v1`
const as = (userId: string) => sessionStore.set({ userId })
const json = (method: string, b: unknown) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
const card = (name: RegExp) => screen.findByRole('listitem', { name })
/** Adds a range or an exclusion of the Safety tab through its dialog. */
async function addRange(v: string) {
  await userEvent.click(await screen.findByRole('button', { name: 'Add range' }, T))
  const dlg = await screen.findByRole('dialog', { name: 'Add a network range' })
  await userEvent.type(within(dlg).getByLabelText('Network range'), v)
  await userEvent.click(within(dlg).getByRole('button', { name: 'Add range' }))
}
async function addExclusion(v: string) {
  await userEvent.click(await screen.findByRole('button', { name: 'Add exclusion' }, T))
  const dlg = await screen.findByRole('dialog', { name: 'Add an exclusion' })
  await userEvent.type(within(dlg).getByLabelText('IP address or network'), v)
  await userEvent.click(within(dlg).getByRole('button', { name: 'Add exclusion' }))
}
const unconfirm = () => inventorySettingsStore.update((s) => ({ ...s, scope_confirmed_at: null, scope_confirmed_by: null }))

/** A component where another page places it (#850): the app's providers and a router, no page around it. */
function renderHere(node: React.ReactNode, role: 'admin' | 'operator' | 'viewer' = 'admin') {
  sessionStore.set({ userId: role === 'admin' ? 'u-admin' : role === 'operator' ? 'u-op' : 'u-view' })
  const router = createMemoryRouter([{ path: '*', element: node }], { initialEntries: ['/devices/a-nas02'] })
  return render(<QueryClientProvider client={makeQueryClient()}><RouterProvider router={router} /></QueryClientProvider>)
}

describe('Settings › Scanning: every engine on one page', () => {
  it('groups the engines by what they do; each card has its state, memory, runs; Preview engines say so; no a11y errors', async () => {
    renderApp('/settings/scanning')
    for (const g of ['Discover', 'Identify', 'Check vulnerabilities', 'Traps']) expect(await screen.findByRole('heading', { level: 2, name: g }, { timeout: 4000 })).toBeInTheDocument()
    const nuclei = await card(/Vulnerability checks \(Nuclei\)/)
    expect(within(nuclei).getByText('Preview')).toBeInTheDocument()
    expect(within(nuclei).getByText(/up to 1.1 GB while on \(shared scan container\)/)).toBeInTheDocument()
    expect(within(await card(/Decoys \(honeypot\)/)).getByText('Preview')).toBeInTheDocument()
    expect(within(await card(/Service versions \(nmap\)/)).getByText('Follows Network discovery (nmap)')).toBeInTheDocument() // no switch of its own (409 not_toggleable)
    expect(within(await card(/Web checks \(ZAP baseline\)/)).queryByRole('switch')).toBeNull()
    expect(screen.getByText(/^Engines that are on: up to [0-9.]+ GB of this box's 8.1 GB of memory\.$/)).toBeInTheDocument() // one short line, the upper-limit detail behind its info icon
    await expectNoA11yViolations()
  })

  it('answers with the scan module off (GET /scanning is core\'s): discovery and OpenVAS are still there; Runs lists every run and says what the checks need', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    renderApp('/settings/scanning')
    expect(await card(/Network discovery \(nmap\)/)).toBeInTheDocument()
    expect(within(await card(/OpenVAS deep scan/)).getByRole('switch')).toBeInTheDocument()
    expect(within(await card(/Vulnerability checks \(Nuclei\)/)).getByRole('switch')).not.toBeChecked()
    await userEvent.click(screen.getByRole('tab', { name: 'Runs' }))
    expect(await screen.findByRole('link', { name: 'Turn them on: Engines, Vulnerability checks' })).toHaveAttribute('href', '/settings/scanning?tab=engines#engine-nuclei-switch')
    expect(await screen.findByRole('table', { name: 'Runs of every engine' })).toBeInTheDocument()
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
    expect(within(dlg).getByRole('button', { name: 'Confirm these ranges' })).toBeDisabled()
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges belong to my company/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm these ranges' }))
    await waitFor(() => expect(inventorySettingsStore.get().scope_confirmed_at).not.toBeNull())
    await waitFor(() => expect(within(row).queryByText('Needs setup')).toBeNull())
  })

  it('a deep link lands on the engine\'s card; SNMP keeps no credentials here (set up per device)', async () => {
    renderApp('/settings/scanning#snmp')
    const row = await card(/SNMP reading/)
    expect(within(row).queryByRole('heading', { name: 'SNMP credentials' })).toBeNull()
  })

  it('Safety: one block for the LAN engines through PUT /scanning/safety; it says what it covers and what not', async () => {
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, exclusions: [] } }))
    renderApp('/settings/scanning?tab=safety')
    // what the block covers and what not is said behind the info icon of "Where the box may scan"
    expect(await screen.findByRole('button', { name: /Where the box may scan/ }, T)).toBeInTheDocument()
    expect(screen.getAllByRole('listitem').map((li) => li.textContent)).toEqual(expect.arrayContaining([expect.stringContaining('192.168.10.0/24'), expect.stringContaining('192.168.20.0/24')]))
    await userEvent.selectOptions(screen.getByLabelText('Discovery and SNMP'), '100')
    await addExclusion('192.168.10.250')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    expect(await screen.findByText('Safety settings saved')).toBeInTheDocument()
    expect(inventorySettingsStore.get().active).toMatchObject({ rate: 100, exclusions: ['192.168.10.250'] })
  })

  it('Safety: the form shows what one pass of the scope as typed costs, and says before saving that a scope too large for a week is refused', async () => {
    renderApp('/settings/scanning?tab=safety')
    expect(await screen.findByText(/^One pass: [0-9,]+ addresses, at least/, {}, T)).toBeInTheDocument()
    await addRange('10.0.0.0/8') // about 16.7 million addresses: weeks of windows at 10 packets/s
    await userEvent.selectOptions(screen.getByLabelText('Discovery and SNMP'), '10')
    expect(await screen.findByText(/Saving is refused: raise the scan rate/, {}, T)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    expect(screen.getByRole('button', { name: 'Save settings' })).toBeDisabled() // said before, not refused after
    // the box refuses it all the same
    as('u-admin')
    const cur = (await (await fetch(`${base()}/scanning`)).json()) as { safety: { scope: { lan_ranges: string[] }; window: object; speed: object; exclusions: string[]; fragile: { kinds: string[]; regular_scan_kinds: string[] }; version: string } }
    const { safety: sf } = cur
    const r = await fetch(`${base()}/scanning/safety`, json('PUT', { scope: { lan_ranges: [...sf.scope.lan_ranges, '10.0.0.0/8'], confirmed: true }, window: sf.window, speed: { ...sf.speed, packets_per_s: 10 }, exclusions: sf.exclusions, fragile: { kinds: sf.fragile.kinds, regular_scan_kinds: sf.fragile.regular_scan_kinds }, version: sf.version }))
    expect(((await r.json()) as { error: { message: string } }).error.message).toMatch(/never takes a scope it cannot sweep within a week/)
  })

  it('Safety: changing the ranges asks for the commitment again; the server refuses a save without it while discovery is on', async () => {
    renderApp('/settings/scanning?tab=safety')
    await addRange('10.20.0.0/24')
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
    for (const [from, want] of [['/scans', 'Engines'], ['/scans?tab=safety', 'Safety'], ['/scans?tab=probes', 'Probe log'], ['/scans?tab=auto', 'Runs']] as const) {
      const view = renderApp(from)
      expect(await screen.findByRole('tab', { name: want, selected: true })).toBeInTheDocument()
      view.unmount()
    }
    const v2 = renderApp('/scans?target=a-nas02&run=run-seed-3') // ?run= wins: the run's own page
    expect(await screen.findByText(/^Stopped: You pressed Stop now\./, {}, { timeout: 4000 })).toBeInTheDocument() // the run's own line, from the box
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
    // the run's own page, never the device page the button is on
    expect(screen.getByRole('link', { name: 'Open the run' })).toHaveAttribute('href', expect.stringMatching(/^\/runs\/sar-/))
    expect(auditStore.get().length).toBeGreaterThanOrEqual(0)
  })

  it('"Scan the LAN now" sends no targets (the server sweeps the confirmed scope); a check asked while it runs is queued behind it and says so', async () => {
    let sent: unknown = null
    const { server } = await import('@/test/server')
    server.events.on('request:start', async ({ request }) => {
      if (request.method === 'POST' && request.url.endsWith('/scanning/engines/nmap-discovery/run')) sent = await request.clone().json()
    })
    renderHere(<><ScanNowButton targets="lan" /><ScanNowButton targets={['a-web01', 'a-srvad']} /></>)
    await userEvent.click(await screen.findByRole('button', { name: 'Scan the LAN now' }))
    await waitFor(() => expect(sent).toEqual({}))
    server.events.removeAllListeners()
    // a busy scanner never locks a person's ask: the check is accepted and waits behind the sweep, saying so
    const selected = await screen.findByRole('button', { name: 'Scan selected (2)' })
    await waitFor(() => expect(selected).toBeEnabled())
    await userEvent.click(selected)
    expect(await screen.findByText(/^Queued behind “LAN sweep /)).toBeInTheDocument()
    expect(screen.queryByText('Another scan is running.')).toBeNull()
  })

  it('a second "Scan the LAN now" while a LAN sweep goes on points at that sweep instead', async () => {
    renderHere(<ScanNowButton targets="lan" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Scan the LAN now' }))
    await screen.findByRole('progressbar')
    const view = renderHere(<ScanNowButton targets="lan" />)
    expect(await within(view.container).findByText('A LAN scan is going on now.')).toBeInTheDocument()
    expect(within(view.container).getByRole('link', { name: 'Open the run' })).toHaveAttribute('href', expect.stringMatching(/^\/runs\/sar-/))
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

  it('the top-bar indicator: nothing while idle; "1 scan running" opens that run\'s page', async () => {
    const view = renderHere(<ScansRunningIndicator />, 'viewer')
    await waitFor(() => expect(screen.queryByText(/scan running/)).toBeNull())
    view.unmount()
    as('u-admin')
    expect((await fetch(`${base()}/scanning/engines/nmap-discovery/run`, json('POST', { targets: ['a-web01'] }))).status).toBe(202)
    renderHere(<ScansRunningIndicator />, 'viewer')
    expect(await screen.findByRole('link', { name: '1 scan running' })).toHaveAttribute('href', expect.stringMatching(/^\/runs\/sar-/))
  })
})

describe('#850: dead ends and the buttons of the Devices pages', () => {
  it('N1: turning on Network discovery with the scope not confirmed opens the scope dialog, and the switch is tried again on save', async () => {
    unconfirm()
    inventorySettingsStore.update((s) => ({ ...s, active: { ...s.active, enabled: false } }))
    renderApp('/settings/scanning')
    const row = await card(/Network discovery \(nmap\)/)
    await userEvent.click(within(row).getByRole('switch'))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm these ranges' }))
    await waitFor(() => expect(within(row).getByRole('switch')).toBeChecked())
    expect(inventorySettingsStore.get().active.enabled).toBe(true)
  })

  it('limits above the box\'s memory say it is fine while the box responds, name the biggest engine and take an admin to its switch', async () => {
    const { server } = await import('@/test/server')
    const { http, HttpResponse } = await import('msw')
    const { scanningView } = await import('./mocks')
    server.use(http.get('*/api/v1/scanning', () => {
      const v = scanningView()
      return HttpResponse.json({ ...v, box: { memory_mb: 7200, reserved_mb: 7800 },
        engines: v.engines.map((e) => (e.id === 'openvas' ? { ...e, enabled: true, can_toggle: true, cost: { ...e.cost, ram_mb: 4000, while: 'on' } } : e)) })
    }))
    renderApp('/settings/scanning')
    expect(await screen.findByText('The engines\' memory limits add up to more than this box has', undefined, { timeout: 4000 })).toBeInTheDocument()
    expect(screen.getByText(/they would need 8.2 GB; this box has 7.5 GB\. The limits are upper bounds/)).toBeInTheDocument()
    expect(screen.getByText(/OpenVAS deep scan holds the most while it is on: up to 4.2 GB\./)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Go to the OpenVAS deep scan switch' }))
    expect(within(await card(/OpenVAS deep scan/)).getByRole('switch')).toHaveFocus()
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
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select FW-HQ' }))
    expect(await screen.findByRole('button', { name: 'Scan selected (1)' })).toBeEnabled()
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select WEB01' }))
    expect(await screen.findByRole('button', { name: 'Scan selected (2)' })).toBeEnabled()
  })

  it('the old SNMP links /devices/setup?tab=snmp land on the SNMP card', async () => {
    renderApp('/devices/setup?tab=snmp')
    expect(await card(/SNMP reading/)).toBeInTheDocument()
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

describe('#850: an alert channel for the matches, made where it is needed (§0)', () => {
  it('the Nuclei card names the channels that are on and opens notify\'s channel form for a new one; the channels page has the #channels place', async () => {
    renderApp('/settings/scanning')
    const row = await card(/Vulnerability checks \(Nuclei\)/)
    expect(await within(row).findByText(/^(Matches alert you through: .+\.|No alert channel is on: matches only show on the pages\.)$/)).toBeInTheDocument()
    await userEvent.click(await within(row).findByRole('button', { name: 'New channel' }))
    const choose = await screen.findByRole('dialog', { name: 'New alert channel' })
    const kind = within(choose).getByLabelText('Kind of channel') as HTMLSelectElement
    const label = kind.options[kind.selectedIndex]!.textContent!
    await userEvent.click(within(choose).getByRole('button', { name: 'Continue' }))
    expect(await screen.findByRole('dialog', { name: `Channel ${label}` })).toBeInTheDocument()
  })

  it('the channels page has the place deep links name (#channels)', async () => {
    const { container } = renderApp('/settings/channels')
    await screen.findByRole('table', { name: /./ }, { timeout: 4000 })
    expect(container.querySelector('#channels')).not.toBeNull()
  })
})

describe('#860: the scope dialog adds one range atomically and never overwrites another change', () => {
  it('adds a range with POST /scanning/safety/ranges, sending what the dialog showed; no full-block PUT', async () => {
    const { server } = await import('@/test/server')
    const sent: { method: string; path: string; body: Record<string, unknown> }[] = []
    server.events.on('request:start', async ({ request }) => {
      if (request.method !== 'GET' && request.url.includes('/scanning/safety')) sent.push({ method: request.method, path: new URL(request.url).pathname, body: await request.clone().json() as Record<string, unknown> })
    })
    unconfirm()
    renderHere(<ScanNowButton targets="lan" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Set the network ranges' }))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    await userEvent.type(within(dlg).getByLabelText('Another range to add (optional)'), '10.30.0.0/24')
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Add and confirm' }))
    await waitFor(() => expect(inventorySettingsStore.get().lan_ranges).toContain('10.30.0.0/24'))
    server.events.removeAllListeners()
    expect(sent).toEqual([{ method: 'POST', path: '/api/v1/scanning/safety/ranges', body: { range: '10.30.0.0/24', confirm: true, shown_ranges: ['192.168.10.0/24', '192.168.20.0/24'], shown_confirmed_at: null } }])
  })

  it('another admin changed the ranges since the dialog opened: nothing is stored, the dialog says so with the current list, the tick is asked again', async () => {
    unconfirm()
    renderHere(<ScanNowButton targets="lan" />)
    await userEvent.click(await screen.findByRole('button', { name: 'Set the network ranges' }))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: [...s.lan_ranges, '10.99.0.0/24'] })) // another tab
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm these ranges' }))
    expect(await within(dlg).findByText(/The ranges changed since this dialog opened/)).toBeInTheDocument()
    expect(inventorySettingsStore.get().scope_confirmed_at).toBeNull()
    expect(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ })).not.toBeChecked()
    expect(await within(dlg).findByText('10.99.0.0/24')).toBeInTheDocument()
  })
})

describe('#877', () => {
  /** The requests a test cares about, with their JSON body. */
  async function capture(match: (method: string, path: string) => boolean) {
    const { server } = await import('@/test/server')
    const sent: { path: string; body: Record<string, unknown> }[] = []
    server.events.on('request:start', async ({ request }) => {
      const path = new URL(request.url).pathname
      if (match(request.method, path)) sent.push({ path, body: await request.clone().json() as Record<string, unknown> })
    })
    return { sent, stop: () => server.events.removeAllListeners() }
  }

  it('M1: a background read while the scope dialog is open never changes the list under the tick; the save is refused and the new list asked again', async () => {
    unconfirm()
    sessionStore.set({ userId: 'u-admin' })
    const qc = makeQueryClient()
    const router = createMemoryRouter([{ path: '*', element: <ScanNowButton targets="lan" /> }], { initialEntries: ['/devices'] })
    render(<QueryClientProvider client={qc}><RouterProvider router={router} /></QueryClientProvider>)
    await userEvent.click(await screen.findByRole('button', { name: 'Set the network ranges' }))
    const dlg = await screen.findByRole('dialog', { name: 'Network ranges you may scan' })
    await userEvent.click(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ }))
    inventorySettingsStore.update((st) => ({ ...st, lan_ranges: [...st.lan_ranges, '10.99.0.0/24'] })) // another admin
    await qc.invalidateQueries({ queryKey: ['scanning'] }) // the page's regular read
    expect(qc.getQueryData<{ safety: { scope: { lan_ranges: string[] } } }>(['scanning'])!.safety.scope.lan_ranges).toContain('10.99.0.0/24')
    expect(within(dlg).queryByText('10.99.0.0/24')).toBeNull() // the list under the tick is the one the admin saw
    await userEvent.click(within(dlg).getByRole('button', { name: 'Confirm these ranges' }))
    expect(await within(dlg).findByText(/The ranges changed since this dialog opened/)).toBeInTheDocument()
    expect(inventorySettingsStore.get().scope_confirmed_at).toBeNull()
    expect(within(dlg).getByText('10.99.0.0/24')).toBeInTheDocument()
    expect(within(dlg).getByRole('checkbox', { name: /I confirm these network ranges/ })).not.toBeChecked()
  })

  it('M2: Select all → Scan selected leaves out the box and devices added by hand, says so, and the run starts', async () => {
    const pc = assetsStore.get().find((a) => a.id === 'a-pc01')!
    assetsStore.update((l) => [...l, { ...pc, id: 'a-man1', ip: '192.168.10.240', mac: null, hostname: 'MAN-ONE', origin: 'manual' }])
    const cap = await capture((m, p) => m === 'POST' && p.endsWith('/scanning/engines/nmap-discovery/run'))
    renderApp('/devices')
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select every device shown' }, { timeout: 4000 }))
    expect(await screen.findByText('Not in Scan selected: the Vedette box, 1 added by hand.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /^Scan selected \(\d+\)$/ }))
    await waitFor(() => expect(cap.sent).toHaveLength(1))
    cap.stop()
    const targets = cap.sent[0]!.body.targets as string[]
    expect(targets).not.toContain('a-box')
    expect(targets).not.toContain('a-man1')
    expect(targets).toContain('a-web01')
  })

  it('M5: "Run vulnerability checks on selected" sends the selection; a fragile device goes only when ticked by name', async () => {
    const cap = await capture((m, p) => m === 'POST' && p.endsWith('/scans/runs'))
    renderApp('/devices')
    await userEvent.click(await screen.findByRole('checkbox', { name: 'Select WEB01' }, { timeout: 4000 }))
    await userEvent.click(screen.getByRole('checkbox', { name: 'Select NAS-PHOTOS' }))
    expect(await screen.findByRole('button', { name: 'Run vulnerability checks on selected (1)' })).toBeEnabled()
    const pick = screen.getByRole('group', { name: /1 selected device is checked only if you tick it here/ })
    await userEvent.click(within(pick).getByRole('checkbox', { name: 'NAS-PHOTOS' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Run vulnerability checks on selected (2)' }))
    await waitFor(() => expect(cap.sent).toHaveLength(1))
    cap.stop()
    expect(cap.sent[0]!.body).toEqual({ targets: ['a-web01', 'a-nas02'] })
  })

  it('L6: the box\'s own page says why it is not checked instead of a button that always fails', async () => {
    renderApp('/devices/a-box')
    // The device page's fragile line reads the same rule and says the same (#944)
    expect((await screen.findAllByText('The Vedette box itself is never part of a network scan.', {}, { timeout: 4000 })).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'Check this device now' })).toBeNull()
  })

  it('M4: a 409 keeps what was typed, takes the other admin\'s change, says what it was, and the second save stores both', async () => {
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, exclusions: [] } }))
    renderApp('/settings/scanning?tab=safety')
    await addExclusion('192.168.10.250')
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, from: '21:00' } })) // another admin, meanwhile
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    const note = (await screen.findByText(/^Someone else saved these settings after you opened this page/)).closest('[role=alert]')!
    expect(note).toHaveTextContent(/Time window: changed by them, now .*21:00/)
    expect(screen.getByRole('button', { name: 'Remove exclusion 192.168.10.250' })).toBeInTheDocument()
    expect(screen.getByLabelText('From')).toHaveValue('21:00')
    await userEvent.click(screen.getByRole('button', { name: 'Save settings' }))
    await waitFor(() => expect(inventorySettingsStore.get().active).toMatchObject({ from: '21:00', exclusions: ['192.168.10.250'] }))
  })

})
