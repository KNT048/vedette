import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderApp } from '@/test/render'
import { sessionStore } from '@/mocks/stores'
import { BOX_ID, ensureBox } from './mocks'

// kien G12 (n82 walk): "Vedette may scan this device during the scan window" showed on the box (never scanned) and on a device whose
// network scan is off. The line follows the device's scan source state.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
const T = { timeout: 5000 }
const MAY = 'Vedette may scan this device during the scan window.'

describe('device page: the fragile line says whether Vedette may scan the device (kien G12)', () => {
  it('the box itself: never scanned', async () => {
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText('Vedette never scans this device: it is the Vedette box itself.', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('a device whose network scan is off: not scanned, and says where to turn it on', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const res = await fetch(`${location.origin}/api/v1/inventory/devices/a-nas02/sources`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scan: 'off' }) })
    expect(res.status).toBe(200)
    renderApp('/devices/a-nas02')
    expect(await screen.findByText('Vedette does not scan this device: its network scan is off (Sources).', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(MAY)).toBeNull()
  })

  it('a device Vedette may scan still says so', async () => {
    renderApp('/devices/a-srvad')
    expect(await screen.findByRole('heading', { level: 1 }, T)).toBeInTheDocument()
    expect(await screen.findByText(MAY, undefined, T)).toBeInTheDocument()
  })
})
