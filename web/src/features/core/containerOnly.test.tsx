// A container-only install (no vedette-host, D-168) as the GUI sees it (D-381, the 2026-11-12 walk on Docker Desktop):
// install comes from GET /modules, host pages show what the customer does instead and never call the host endpoints,
// the honeypot cannot be turned on and its page claims no coverage, the setup code hint names vedette-core.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { installStore, modulesStore } from '@/mocks/stores'
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

  it('Modules: what needs the host is not on this install; off it cannot be turned on, on (sample data) it can be turned off', async () => {
    renderApp('/settings/modules')
    const off = await screen.findByRole('switch', { name: 'Turn on module Credentialed scan' })
    expect(off).toBeDisabled()
    expect(within(off.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
    const on = screen.getByRole('switch', { name: 'Turn on module Internal traps' })
    expect(on).toBeEnabled()
    expect(within(on.closest('tr')!).getByText('Not on this install')).toBeInTheDocument()
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
    expect(within(small).queryByText(/Internal traps/)).toBeNull()
    expect(screen.getByText(/Not on this install: .*Internal traps/)).toBeInTheDocument()
  })
  it('Scans, Credentialed scan: says it is not on this install, never invites turning it on (S-CORE-9 G5, D-229)', async () => {
    renderApp('/scans?tab=credentialed')
    expect(await screen.findByText('Credentialed scan is not on this install')).toBeInTheDocument()
    expect(screen.getByText(/needs the appliance install/)).toBeInTheDocument()
    expect(screen.queryByText(/Turn the module on/)).toBeNull()
    expect(screen.queryByRole('link', { name: 'Open module settings' })).toBeNull()
  })

  it('MCP: says nothing outside the container can reach it, not "use an SSH tunnel" (S-MCP-1, D-229)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'mcp-server' ? { ...m, enabled: true } : m)))
    renderApp('/settings/mcp')
    expect(await screen.findByText(/the MCP port is not published/)).toBeInTheDocument()
    expect(screen.getByText(/Listening inside the vedette-core container only/)).toBeInTheDocument()
    expect(screen.queryByText(/must go through an SSH tunnel/)).toBeNull()
  })

  it('SIEM forwarding: "Honeypot touches" cannot be ticked and says why (S-LOG-3, D-229)', async () => {
    renderApp('/settings/siem')
    const box = await screen.findByRole('checkbox', { name: 'Honeypot touches' })
    expect(box).toBeDisabled()
    expect(box).not.toBeChecked()
    expect(screen.getByText('Not on this install: the honeypot needs the appliance install.')).toBeInTheDocument()
    expect(screen.getByRole('checkbox', { name: 'Alerts sent' })).toBeEnabled()
  })
})
