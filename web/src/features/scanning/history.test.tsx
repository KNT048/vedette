import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { BOX_ID, inventorySettingsStore } from '@/features/inventory/mocks'

const T = { timeout: 5000 }

// The runs list says what each run was and found; every kind of run is listed, vulnerability checks included.
describe('Runs list every kind of run', () => {
  it('"Check this device now" is listed with what happened, even with the vulnerability checks module off', async () => {
    sessionStore.set({ userId: 'u-admin' })
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
    inventorySettingsStore.update((s) => ({ ...s, active: { ...s.active, enabled: true }, scope_confirmed_at: s.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
    const device = assetsStore.get().find((a) => a.id !== BOX_ID && a.ip && a.ip !== '—' && !inventorySettingsStore.get().active.exclusions.includes(a.ip))!
    const res = await fetch(`${location.origin}/api/v1/scanning/engines/nmap-discovery/run`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: [device.id] }) })
    expect(res.status).toBe(202)
    renderApp('/settings/scanning')
    await userEvent.click(await screen.findByRole('tab', { name: 'Runs' }, T))
    const table = await screen.findByRole('table', { name: 'Runs of every engine' }, T)
    // the person's run, and the device check it made, each with its own page
    expect(within(table).getByRole('link', { name: `Check ${device.ip}` })).toHaveAttribute('href', expect.stringMatching(/^\/runs\/sar-/))
    await userEvent.click(within(table).getAllByRole('link', { name: device.ip })[0]!)
    // what it found, never "see the device page"
    const found = device.services.length === 0 ? 'no open port' : `${device.services.length} open port`
    expect(await screen.findByText((t) => t.startsWith(`Scanned ${device.ip}: ${found}`), {}, T)).toBeInTheDocument()
    expect(screen.getByText(/^Device check · /)).toBeInTheDocument()
  })
})
