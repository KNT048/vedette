import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, auditStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// A value entered by hand wins; when the device's own SNMP reading says something else, the page says so next to the field and the person
// uses the detected value or keeps their own (INV-47). The mock gives a device named "edge-fw" an SNMP reading (SNMP_READS).
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const addDevice = (over: Record<string, unknown> = {}) => {
  const pc = assetsStore.get().find((a) => a.id === 'a-pc01')!
  assetsStore.update((l) => [...l, { ...pc, id: 'a-hand1', ip: '192.168.10.241', mac: null, hostname: 'edge-fw', origin: 'manual', kind: 'firewall', services: [], software: [], vendor: null, model: null, os: null, ...over }])
}
const group = (name: string) => screen.findByRole('group', { name }, T)

describe('a detected value that differs from the one entered by hand', () => {
  it('says so next to the field, with both actions; the entered value is still the one shown', async () => {
    sessionStore.set({ userId: 'u-admin' })
    addDevice()
    renderApp('/devices/a-hand1', { role: 'admin' })
    const g = await group('Detected host name')
    expect(g).toHaveTextContent(/Detected host name: fw-edge-01 \(SNMP, .+\)\./)
    expect(within(g).getByRole('button', { name: 'Use detected' })).toBeEnabled()
    expect(within(g).getByRole('button', { name: 'Keep mine' })).toBeEnabled()
    expect(screen.getByTestId('device-hostname')).toHaveTextContent('edge-fw')
    // the other fields it reads: model and OS differ from nothing entered, so there is nothing to say about them
    expect(screen.queryByRole('group', { name: 'Detected model' })).toBeNull()
    expect(screen.queryByRole('group', { name: 'Detected OS' })).toBeNull()
  })

  it('Use detected switches the shown value and the notice goes; the audit log says who', async () => {
    sessionStore.set({ userId: 'u-admin' })
    addDevice()
    renderApp('/devices/a-hand1', { role: 'admin' })
    const user = userEvent.setup()
    const g = await group('Detected host name')
    await user.click(within(g).getByRole('button', { name: 'Use detected' }))
    await vi.waitFor(() => expect(screen.getByTestId('device-hostname')).toHaveTextContent('fw-edge-01'), T)
    expect(screen.queryByRole('group', { name: 'Detected host name' })).toBeNull()
    expect(auditStore.get().some((e) => e.action === 'inventory.use_detected')).toBe(true)
  })

  it('Keep mine hides the notice and changes nothing else; it stays hidden after a reload of the page', async () => {
    sessionStore.set({ userId: 'u-admin' })
    addDevice()
    const first = renderApp('/devices/a-hand1', { role: 'admin' })
    const user = userEvent.setup()
    const g = await group('Detected host name')
    await user.click(within(g).getByRole('button', { name: 'Keep mine' }))
    await vi.waitFor(() => expect(screen.queryByRole('group', { name: 'Detected host name' })).toBeNull(), T)
    expect(screen.getByTestId('device-hostname')).toHaveTextContent('edge-fw')
    first.unmount()
    renderApp('/devices/a-hand1', { role: 'admin' })
    await screen.findByTestId('device-hostname', undefined, T)
    expect(screen.queryByRole('group', { name: 'Detected host name' })).toBeNull()
  })

  it('a viewer sees the notice but cannot act on it', async () => {
    sessionStore.set({ userId: 'u-viewer' })
    addDevice()
    renderApp('/devices/a-hand1', { role: 'viewer' })
    const g = await group('Detected host name')
    expect(within(g).getByRole('button', { name: 'Use detected' })).toBeDisabled()
    expect(within(g).getByRole('button', { name: 'Keep mine' })).toBeDisabled()
  })

  it('no notice when the two only differ by case', async () => {
    addDevice({ hostname: 'FW-EDGE-01' })
    renderApp('/devices/a-hand1', { role: 'admin' })
    await screen.findByTestId('device-hostname', undefined, T)
    expect(screen.queryByRole('group', { name: 'Detected host name' })).toBeNull()
  })
})
