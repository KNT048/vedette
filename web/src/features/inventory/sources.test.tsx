import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderSnmp } from './snmpHarness'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// D-598, issue #829 (kien: "the device came from a scan, I added it, then I could not add SNMP to it; can I add osquery later, or both?").
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const COMMUNITY_REQUIRED = 'Enter the community.'
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const api = async (method: string, path: string, body?: unknown) => {
  sessionStore.set({ userId: 'u-admin' })
  return fetch(`${location.origin}/api/v1/inventory${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
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
    const agent = item(list, 'Agent (osquery or Wazuh)')
    // #849: Install osquery opens the Add a device dialog's osquery method on this page
    expect(within(agent).getByRole('button', { name: 'Install osquery' })).toBeInTheDocument()
    expect(screen.getByText(/set up the new one first, then stop the old one/)).toBeInTheDocument()
    await expectNoA11yViolations(container)
    await user.selectOptions(within(snmp).getByLabelText('Credential'), '+ New credential') // #842: made right here, in a small dialog
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByDisplayValue('192.168.10.21')).toBeInTheDocument()
  })

  it('says why SNMP or osquery cannot be added: modules off, not an administrator', async () => {
    enableModule('agent-intake', false)
    renderApp('/devices/a-nas02', { role: 'operator' })
    const list = await sources()
    expect(item(list, 'Agent (osquery or Wazuh)')).toHaveTextContent('Turn on the Agents module in Settings')
    expect(item(list, 'SNMP')).toHaveTextContent('An administrator sets this up.')
    expect(within(item(list, 'SNMP')).queryByRole('button', { name: 'Add SNMP' })).toBeNull()
  })

  it('with no credential saved, "Add SNMP" adds one for this address without leaving the page', async () => {
    const list = (await (await api('GET', '/snmp')).json()) as { credentials: { id: string }[] }
    for (const c of list.credentials) expect((await api('DELETE', `/snmp/${c.id}`)).status).toBe(204)
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const snmp = item(await sources(), 'SNMP')
    await user.click(within(snmp).getByRole('button', { name: 'Add SNMP' }))
    await user.click(await within(snmp).findByRole('button', { name: 'Add an SNMP credential for 192.168.10.21' }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByDisplayValue('192.168.10.21')).toBeInTheDocument()
    expect(location.pathname).not.toBe('/devices/setup')
  })

  it('a credential whose scope does not hold the address offers to add it, asking for the secret again', async () => {
    expect((await api('POST', '/snmp', { name: 'Branch printers', version: 'v2c', community: 'public', scope: ['192.168.20.0/24'] })).status).toBe(201)
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const snmp = item(await sources(), 'SNMP')
    await user.click(within(snmp).getByRole('button', { name: 'Add SNMP' }))
    const select = await within(snmp).findByLabelText('Credential', undefined, T)
    await user.selectOptions(select, within(select).getByRole('option', { name: /Branch printers/ }))
    await user.click(within(snmp).getByRole('button', { name: 'Read this device now' }))
    await user.click(await within(snmp).findByRole('button', { name: 'Add 192.168.10.21 to Branch printers' }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect((within(dialog).getByLabelText('Send only to') as HTMLTextAreaElement).value).toBe('192.168.20.0/24\n192.168.10.21')
    await user.click(within(dialog).getByRole('button', { name: 'Save' }))
    expect(await within(dialog).findByText(COMMUNITY_REQUIRED, undefined, T)).toBeInTheDocument() // blank community: asked again, not kept
  })

  it('?snmp_ip= does not open the add form when the 8 credentials are saved', async () => {
    for (let i = 0; i < 8; i++) await api('POST', '/snmp', { name: `Extra ${i}`, version: 'v2c', community: 'public-ro', scope: ['192.168.10.0/24'] })
    renderSnmp('/?snmp_ip=192.168.10.21')
    await screen.findByRole('list', { name: 'SNMP credentials, in the order they are tried' }, T)
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('"Add a credential for <ip>" opens the SNMP form with that address as the scope', async () => {
    renderSnmp('/?snmp_ip=192.168.10.21')
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
