import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { BOX_ID, ensureBox, inventorySettingsStore } from './mocks'

// "Vedette may scan this device during the scan window" showed on the box (never scanned) and on a device whose
// network scan is off. The line follows the device's scan source state.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
const T = { timeout: 5000 }
const MAY = 'Vedette may scan this device during the scan window.'
const confirmed = () => {
  modulesStore.update((l) => l.map((m) => (m.id === 'sensor-active' ? { ...m, enabled: true } : m)))
  inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: st.scope_confirmed_at ?? '2026-11-01T00:00:00.000Z' }))
}

describe('device page: the fragile line says whether Vedette may scan the device', () => {
  it('the box itself: never scanned', async () => {
    renderApp(`/devices/${BOX_ID}`)
    expect((await screen.findAllByText('The Vedette box itself is never part of a network scan.', undefined, T)).length).toBeGreaterThan(0) // the fragile line, and the device's Check now slot
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('a device whose network scan is off: not scanned, and says where to turn it on', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const res = await fetch(`${location.origin}/api/v1/inventory/devices/a-nas02/sources`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan: 'off' }) })
    expect(res.status).toBe(200)
    renderApp('/devices/a-nas02')
    expect((await screen.findAllByText('Set to never scan, or its network scan is off under Sources: network discovery does not check it.', undefined, T)).length).toBeGreaterThan(0) // the fragile line, and the device's Check now slot
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('review r1 of #944: the ranges not confirmed or discovery off: no device may be scanned, the line says why', async () => {
    inventorySettingsStore.update((st) => ({ ...st, active: { ...st.active, enabled: true }, scope_confirmed_at: null }))
    renderApp('/devices/a-srvad')
    expect(await screen.findByText(/^The network ranges are not confirmed yet, so network discovery checks no device/, undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('review r1 of #944: an address outside the network ranges: not scanned', async () => {
    confirmed()
    assetsStore.update((l) => l.map((x) => (x.id === 'a-srvad' ? { ...x, ip: '203.0.113.9' } : x)))
    renderApp('/devices/a-srvad')
    expect((await screen.findAllByText(/^Outside the network ranges or excluded/, undefined, T)).length).toBeGreaterThan(0) // the fragile line, and the device's Check now slot
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('a device Vedette may scan still says so', async () => {
    confirmed()
    renderApp('/devices/a-srvad')
    expect(await screen.findByRole('heading', { level: 1 }, T)).toBeInTheDocument()
    expect(await screen.findByText(MAY, undefined, T)).toBeInTheDocument()
  })
})
