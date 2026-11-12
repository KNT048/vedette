// A container-only install (no vedette-host, D-168) as the GUI sees it (D-381, the 2026-11-12 walk on Docker Desktop):
// install comes from GET /modules, host pages show what the customer does instead and never call the host endpoints,
// the honeypot cannot be turned on and its page claims no coverage, the setup code hint names vedette-core.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { installStore, sessionStore } from '@/mocks/stores'
import { containerSensorStore } from '@/features/inventory/mocks'
import { MOCK_SETUP_CODE } from './mocks'

const HOST_PATHS = ['/core/updates/os', '/core/data/backups', '/core/data/restore/run', '/core/network']
let calls: string[] = []
beforeEach(() => {
  installStore.set({ kind: 'container' })
  calls = []
  const real = globalThis.fetch
  vi.spyOn(globalThis, 'fetch').mockImplementation((input, init) => { calls.push(String(input instanceof Request ? input.url : input)); return real(input, init) })
})
afterEach(() => vi.restoreAllMocks())
const hostCalls = () => calls.filter((u) => HOST_PATHS.some((p) => new URL(u, location.origin).pathname === `/api/v1${p}`))

describe('container-only install (D-381)', () => {
  it('Updates shows the compose commands and no appliance control; Data shows the volume backup; neither calls the host', async () => {
    renderApp('/settings/updates')
    expect(await screen.findByText('Update Vedette')).toBeInTheDocument()
    expect(screen.getByText(/docker compose --env-file vedette.env pull/)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Check for releases|Export|Import/ })).toBeNull()
    renderApp('/settings/data')
    expect(await screen.findAllByText(/vedette_data/)).not.toHaveLength(0)
    expect(screen.queryByRole('button', { name: 'Download backup' })).toBeNull()
    expect(screen.queryByText('Backups on this box')).toBeNull()
    renderApp('/settings/network')
    expect(await screen.findByText(/Prepare the SPAN card on this machine yourself/)).toBeInTheDocument()
    expect(hostCalls()).toEqual([])
  })

  it('Updates names the offered release and its notes, with the update and cosign blocks for Docker or Podman and no Apply (S-CORE-9 G4)', async () => {
    const u = userEvent.setup()
    renderApp('/settings/updates')
    expect(await screen.findByText('Vedette 0.9.4 is available. This machine runs 0.9.3.')).toBeInTheDocument()
    expect(screen.getByText(/oversized syslog packets/)).toBeInTheDocument()
    // in the order that is safe: keep, minisign, cosign + the digests of vedette.env, and only then pull and up -d
    const steps = within(screen.getByRole('list')).getAllByRole('listitem').map((li) => li.querySelector('code')!.textContent!)
    expect(steps.map((c) => c.split(' ')[0])).toEqual(['mv', 'minisign', 'cosign', 'docker'])
    expect(steps[0]).toBe('mv -n vedette.env vedette.env.0.9.3') // named after the running release: a later update keeps its own way back
    expect(steps[1]).toBe('minisign -Vm vedette.env -p vedette.pub')
    // one line per image this install runs (not the honeypot), by the digest of the release information; no made-up URL
    const lines = screen.getByText(/^cosign verify/).textContent!.split('\n')
    expect(lines.map((l) => /vedette-(\w+)@/.exec(l)?.[1])).toEqual(['core', 'sensor', 'scan'])
    for (const l of lines) expect(l).toMatch(/^cosign verify --key cosign\.pub ghcr\.io\/knt048\/vedette-\w+@sha256:[0-9a-f]{64}$/)
    const grep = screen.getByText(/^grep -cF/).textContent!
    for (const l of lines) expect(grep).toContain(`-e '${l.split(' ').at(-1)!}'`)
    expect(screen.getByText(/it must print 3, or do not go on/)).toBeInTheDocument()
    expect(screen.getByText(/put vedette\.env\.0\.9\.3 back as vedette\.env/)).toBeInTheDocument()
    expect(screen.queryByText(/https?:\/\//)).toBeNull()
    expect(screen.queryByRole('button', { name: /Apply|Roll back|Check for releases/ })).toBeNull()
    expect(screen.queryByText(/System helper/)).toBeNull()
    await u.click(screen.getByRole('button', { name: 'Podman' }))
    expect(screen.getByText(/^podman compose --env-file vedette.env pull/).textContent).toBe('podman compose --env-file vedette.env pull\npodman compose --env-file vedette.env up -d')
    expect(screen.queryByText(/docker compose/)).toBeNull()
  })

  it.each([
    ['no check has succeeded', { last_check: null }, /No release information yet/],
    ['the check is off', { check_enabled: false }, /The update check is off/],
    ['nothing newer', { last_check: '2026-11-12T00:00:00Z' }, /No newer release is offered to this install \(it runs 0\.9\.3\)/],
  ])('Updates without a newer release says why (%s) and keeps the general pull and up -d block', async (_, over, said) => {
    const state = { channel: 'stable', mode: 'manual', check_enabled: true, last_check: null, components: [{ id: 'software', kind: 'software', version: '0.9.3', previous: null, installed_at: '2026-11-01T00:00:00Z', signature: 'unsigned', rollback_restores_data: false }], available: [], history: [], advisories: [], run: null, managed: [], running_revoked: null, stale_since: null, ...over }
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json(state)))
    renderApp('/settings/updates')
    expect(await screen.findByText(said)).toBeInTheDocument()
    expect(screen.getByText(/docker compose --env-file vedette.env pull/)).toBeInTheDocument()
    expect(screen.queryByText(/minisign|cosign verify/)).toBeNull()
  })

  it('Updates: when the update state cannot be read, the error has Try again and the general block stays', async () => {
    server.use(http.get('*/api/v1/core/updates', () => HttpResponse.json({ error: { code: 'x', message: 'The settings server is not responding.' } }, { status: 503 })))
    renderApp('/settings/updates')
    expect(await screen.findByRole('button', { name: /Try again/ })).toBeInTheDocument()
    expect(screen.getByText(/docker compose --env-file vedette.env pull/)).toBeInTheDocument()
  })

  it('Modules: what needs the host is not on this install; off it cannot be turned on, on (sample data) it can be turned off', async () => {
    renderApp('/settings/modules')
    const off = await screen.findByRole('switch', { name: 'Turn on module Credentialed scan' })
    expect(off).toBeDisabled()
    expect(within(off.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
    const on = screen.getByRole('switch', { name: 'Turn off module Internal traps' })
    expect(on).toBeEnabled()
    expect(within(on.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
  })

  it('Modules: the active sensor does not claim nmap here; the response gallery cannot clone a trap template', async () => {
    renderApp('/settings/modules')
    expect(await screen.findByText('Light scans of your network inside the allowed time window.')).toBeInTheDocument()
    expect(screen.queryByText(/nmap/)).toBeNull()
    renderApp('/response')
    const clone = await screen.findByRole('button', { name: /^Clone Trap touched: block the source on FortiGate/ })
    expect(clone).toBeDisabled()
    expect(within(clone.closest('li')!).getByText(/Not available on this install/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /^Clone Known-bad connection: add the destination to the block list/ })).toBeEnabled()
  })

  it('setup: the code hint names vedette-core and the bundles leave the honeypot out', async () => {
    const u = userEvent.setup()
    renderApp('/setup', { role: null, setupComplete: false })
    expect(await screen.findByText(/docker logs vedette-core/)).toBeInTheDocument()
    await u.type(screen.getByLabelText('Setup code'), MOCK_SETUP_CODE)
    await u.type(screen.getByLabelText('Organization name'), 'ABC Company')
    await u.type(screen.getByLabelText('Administrator name'), 'Lan')
    await u.type(screen.getByLabelText('Sign-in email'), 'lan@abc.example')
    await u.type(screen.getByLabelText('Password'), 'a long enough sentence')
    await u.type(screen.getByLabelText('Repeat password'), 'a long enough sentence')
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    await u.type(await screen.findByLabelText('Range 1'), '192.168.10.0/24')
    await u.click(screen.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }))
    await u.click(screen.getByRole('button', { name: 'Continue' }))
    const small = (await screen.findByRole('radio', { name: /Small business/ })).closest('div')!
    expect(within(small).getByText(/Reports/)).toBeInTheDocument()
    expect(within(small).queryByText(/internal traps/i)).toBeNull()
    expect(screen.getByText(/Not on this install: .*Internal traps/)).toBeInTheDocument()
  })

  // The setup page re-mounts its sections once right after first paint (inventory.test.tsx clickUntil): click again until the dialog shows.
  const openSensorDialog = async (u: ReturnType<typeof userEvent.setup>) => {
    await screen.findByRole('button', { name: 'Configure sensor vedette-hq' }, { timeout: 5000 })
    await waitFor(async () => { await u.click(screen.getByRole('button', { name: 'Configure sensor vedette-hq' })); screen.getByRole('dialog') }, { timeout: 8000 })
  }
  // S-CORE-8 G6, D-387: the SPAN card is chosen under Sensors among the cards the sensor reported; Box network has no SPAN here.
  it('Sensors: Configure picks the SPAN card among the reported cards; the box refuses a card with an address', async () => {
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await openSensorDialog(u)
    const dlg = screen.getByRole('dialog')
    expect(within(dlg).queryByRole('link', { name: /Box network/ })).toBeNull()
    const pick = within(dlg).getByRole('combobox', { name: 'SPAN card' })
    expect(within(pick).getAllByRole('option').map((o) => o.textContent)).toEqual(["None (listen on the card with this machine's address)", 'eno1', 'eno2', 'wlp2s0'])
    await u.selectOptions(pick, 'eno1')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(await within(dlg).findByRole('alert')).toHaveTextContent('"eno1" has an IP address; a SPAN port has none.')
    await u.selectOptions(pick, 'eno2')
    await u.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(containerSensorStore.get()).toMatchObject({ chosen: 'eno2', span: true })
    await waitFor(() => expect(screen.getByRole('cell', { name: /eno2/ })).toBeInTheDocument())
    expect(calls.some((u) => new URL(u, location.origin).pathname.startsWith('/api/v1/core/network'))).toBe(false)
  })

  it('Sensors: a sensor never started says Not connected yet and how to start it; no card reported yet, no Save', async () => {
    containerSensorStore.set({ connected: false, cards: [], chosen: null, span: false })
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await waitFor(() => {
      expect(screen.getByText('Not connected yet')).toBeInTheDocument()
      expect(screen.getByText('Start it with compose.sensors.yaml on this machine.')).toBeInTheDocument()
    }, { timeout: 5000 })
    expect(screen.queryByText('Lost contact')).toBeNull()
    await openSensorDialog(u)
    const dlg = screen.getByRole('dialog')
    expect(within(dlg).getByRole('status')).toHaveTextContent('No card reported yet: start the sensor with compose.sensors.yaml.')
    expect(within(dlg).queryByRole('button', { name: 'Save' })).toBeNull()
  })

  it('Sensors: two cards with an address, no SPAN card chosen: the dialog says the sensor is not listening (D-380)', async () => {
    containerSensorStore.set({ connected: true, chosen: null, span: false, cards: [{ name: 'eno1', ipv4: '192.168.10.20/24', link: true }, { name: 'eno2', ipv4: '10.0.0.2/24', link: true }, { name: 'eno3', ipv4: null, link: true }] })
    const u = userEvent.setup()
    renderApp('/devices/setup')
    await openSensorDialog(u)
    expect(within(screen.getByRole('dialog')).getByRole('status')).toHaveTextContent('The sensor is not listening on any card')
  })

  it('PATCH /inventory/sensors/{id} on an appliance is 409 set_in_box_network', async () => {
    installStore.set({ kind: 'appliance' })
    sessionStore.set({ userId: 'u-admin' })
    const r = await fetch(`${location.origin}/api/v1/inventory/sensors/sn-local`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ interface: 'eth1', span: true }) })
    expect(r.status).toBe(409)
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('set_in_box_network')
  })
})
