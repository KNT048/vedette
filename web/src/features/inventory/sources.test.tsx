import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// D-598, issue #829 (kien: "the device came from a scan, I added it, then I could not add SNMP to it; can I add osquery later, or both?").
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const sources = async () => screen.findByRole('list', { name: 'Sources' }, T)
const item = (list: HTMLElement, name: string) => within(list).getByText(name).closest('li') as HTMLElement

describe('Device page: Sources (D-598)', () => {
  it('lists what feeds a scanned device, reads it with SNMP from the device page, and offers osquery', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    expect(item(list, 'Network scan')).toHaveTextContent('Reporting')
    expect(item(list, 'Passive listening')).toHaveTextContent('Reporting')
    const snmp = item(list, 'SNMP')
    expect(snmp).toHaveTextContent('Not set up')
    await user.click(within(snmp).getByRole('button', { name: 'Add SNMP' }))
    expect(await within(snmp).findByLabelText('Credential', undefined, T)).toBeInTheDocument()
    await user.click(within(snmp).getByRole('button', { name: 'Read this device now' }))
    expect(await within(snmp).findByText(/192\.168\.10\.21 (answered|was not read)\./, undefined, T)).toBeInTheDocument()
    expect(within(snmp).getByRole('link', { name: 'Add a credential for this address' })).toHaveAttribute('href', '/devices/setup?tab=snmp&snmp_ip=192.168.10.21')
    const agent = item(list, 'Agent (osquery or Wazuh)')
    expect(within(agent).getByRole('link', { name: 'Install osquery' })).toHaveAttribute('href', '/devices/setup?tab=agents')
    expect(screen.getByText(/set up the new one first, then stop the old one/)).toBeInTheDocument()
    await expectNoA11yViolations(container)
  })

  it('says why SNMP or osquery cannot be added: modules off, not an administrator', async () => {
    enableModule('agent-intake', false)
    renderApp('/devices/a-nas02', { role: 'operator' })
    const list = await sources()
    expect(item(list, 'Agent (osquery or Wazuh)')).toHaveTextContent('Turn on the Agents module in Settings')
    expect(item(list, 'SNMP')).toHaveTextContent('An administrator sets this up.')
    expect(within(item(list, 'SNMP')).queryByRole('button', { name: 'Add SNMP' })).toBeNull()
  })

  it('"Add a credential for <ip>" opens the SNMP form with that address as the scope', async () => {
    renderApp('/devices/setup?tab=snmp&snmp_ip=192.168.10.21', { role: 'admin' })
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByDisplayValue('192.168.10.21')).toBeInTheDocument()
  })

  it('a product declared with no address or name is shown as declared software, not as a device without an IP', async () => {
    sessionStore.set({ userId: 'u-admin' })
    const res = await fetch(`${location.origin}/api/v1/inventory/devices`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ catalog_id: 'microsoft-office-desktop' }) })
    expect(res.status).toBe(201)
    const { id } = (await res.json()) as { id: string }
    renderApp(`/devices/${id}`, { role: 'admin' })
    expect(await screen.findByText('Declared software, no device', undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('list', { name: 'Sources' })).toBeNull()
  })
})
