import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// A device added by hand repeated "Added by hand: ... turn its network scan on under Sources" in the header, the fragile row,
// Last checks and Sources, and the fragile row lost what "fragile" means. The note is said once, on the network scan row of Sources;
// every other row says what it means, and points at Sources only where it would otherwise read wrong.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const NOTE = /Added by hand:/g
const FRAGILE_INFO = 'Vedette scans a fragile device gently once when it first sees it, then only listens (unless regular scans are allowed below).'
const IDENT = 'Device check: ports, services, software'
const VULN = 'Vulnerability check: does a known exploit work'

const addDevice = (over: Record<string, unknown>) => {
  const pc = assetsStore.get().find((a) => a.id === 'a-pc01')!
  assetsStore.update((l) => [...l, { ...pc, id: 'a-hand1', ip: '192.168.10.241', mac: null, hostname: 'switch-01', services: [], software: [], ...over }])
}
const noRuns = () => server.use(http.get('*/api/v1/scans/runs', () => HttpResponse.json({ engine_busy: false, items: [] })))
const fragileHint = () => screen.getByRole('switch', { name: 'Fragile device' }).closest('dd') as HTMLElement
const notes = () => document.body.textContent?.match(NOTE)?.length ?? 0

describe('the device page of a device added by hand says why it is not scanned once', () => {
  it('the note shows once, on Sources; the fragile row explains fragile; the header and Last checks point at Sources', async () => {
    sessionStore.set({ userId: 'u-admin' })
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' || m.id === 'scan' ? { ...m, enabled: true } : m)))
    noRuns()
    addDevice({ origin: 'manual' })
    renderApp('/devices/a-hand1', { role: 'admin' })
    const checks = await screen.findByRole('region', { name: 'Last checks' }, T)
    const ident = await within(checks).findByRole('group', { name: IDENT }, T)
    await vi.waitFor(() => expect(within(ident).getByRole('link', { name: 'see Sources' })).toHaveAttribute('href', expect.stringMatching(/\?tab=overview#sources$/)), T)
    expect(ident).toHaveTextContent('Never')
    expect(ident).toHaveTextContent('Network scan off: see Sources')
    const vuln = within(checks).getByRole('group', { name: VULN })
    await vi.waitFor(() => expect(vuln).toHaveTextContent('Network scan off: see Sources'), T)

    // the note: exactly once, on the network scan row of Sources, beside its switch
    const sources = screen.getByRole('region', { name: 'Sources' })
    expect(await within(sources).findByText('Off · Added by hand: nothing is sent to it until you turn this on', undefined, T)).toBeInTheDocument()
    expect(notes()).toBe(1)

    // the fragile row says what fragile means, not why the device is not scanned
    expect(fragileHint()).toHaveTextContent(FRAGILE_INFO)
    expect(fragileHint()).not.toHaveTextContent(/Sources/)

    // the header: no button that can only be refused, one short pointer, no "never scanned in the inventory"
    expect(screen.queryAllByRole('button', { name: 'Check this device now' })).toHaveLength(0)
    expect(screen.queryAllByRole('button', { name: 'Run vulnerability checks now' })).toHaveLength(0)
    expect(screen.getAllByRole('link', { name: 'see Sources' })).toHaveLength(3) // header, and the two Last checks rows
    expect(screen.queryByText(/never be scanned in the inventory/)).toBeNull()
  })

  it('the Services tab says the network scan is off and where to turn it on, without the note', async () => {
    addDevice({ origin: 'manual' })
    renderApp('/devices/a-hand1?tab=services')
    const tip = await screen.findByRole('button', { name: 'About No open port seen yet' }, T)
    expect(tip).toHaveAccessibleDescription('Its network scan is off: Sources, on the Overview tab, turns it on.')
    expect(notes()).toBe(0)
  })

  it('SNMP feeding it and the network scan still off: Sources still says why it is not scanned, once', async () => {
    sessionStore.set({ userId: 'u-admin' })
    addDevice({ origin: 'manual' })
    modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    // saving its SNMP settings turns SNMP on for it; its network scan stays off
    const res = await fetch(`${location.origin}/api/v1/inventory/snmp/devices/a-hand1`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ version: 'v2c', community: 'ro-community-1' }) })
    expect(res.status).toBe(200)
    renderApp('/devices/a-hand1', { role: 'admin' })
    const sources = await screen.findByRole('region', { name: 'Sources' }, T)
    expect(await within(sources).findByText('Off · Added by hand: nothing is sent to it until you turn this on', undefined, T)).toBeInTheDocument()
    expect(fragileHint()).toHaveTextContent(FRAGILE_INFO)
    expect(notes()).toBe(1)
  })

  it('its network scan on: no note anywhere, and the fragile row reads as for any device', async () => {
    sessionStore.set({ userId: 'u-admin' })
    addDevice({ origin: 'manual' })
    const res = await fetch(`${location.origin}/api/v1/inventory/devices/a-hand1/sources`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan: 'on' }) })
    expect(res.status).toBe(200)
    renderApp('/devices/a-hand1', { role: 'admin' })
    await screen.findByRole('region', { name: 'Sources' }, T)
    expect(fragileHint()).not.toHaveTextContent(FRAGILE_INFO)
    expect(screen.queryByRole('link', { name: 'see Sources' })).toBeNull()
    expect(notes()).toBe(0)
  })

  it('a discovered device keeps its fragile line and its InfoTip', async () => {
    addDevice({})
    renderApp('/devices/a-hand1')
    await screen.findByRole('switch', { name: 'Fragile device' }, T)
    expect(screen.getByRole('button', { name: 'About Fragile device' })).toBeInTheDocument()
    expect(fragileHint()).not.toHaveTextContent(FRAGILE_INFO)
    expect(screen.queryByRole('link', { name: 'see Sources' })).toBeNull()
    expect(notes()).toBe(0)
  })
})
