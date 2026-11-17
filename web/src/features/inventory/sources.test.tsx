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

  // n82 (BN340 at 192.168.18.1): the read preselected the first credential, whose scope does not hold the address, so the first press failed.
  const onlyCredentials = async (...scopes: [string, string][]) => {
    const list = (await (await api('GET', '/snmp')).json()) as { credentials: { id: string }[] }
    for (const c of list.credentials) expect((await api('DELETE', `/snmp/${c.id}`)).status).toBe(204)
    for (const [name, scope] of scopes) expect((await api('POST', '/snmp', { name, version: 'v2c', community: 'public', scope: [scope] })).status).toBe(201)
  }

  it('preselects the credential whose scope holds the address, not the first one', async () => {
    await onlyCredentials(['Lab Ubuntu servers', '192.168.20.0/24'], ['Office', '192.168.10.0/24'])
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const snmp = item(await sources(), 'SNMP')
    await user.click(within(snmp).getByRole('button', { name: 'Add SNMP' }))
    const select = (await within(snmp).findByLabelText('Credential', undefined, T)) as HTMLSelectElement
    expect(select.selectedOptions[0]).toHaveTextContent(/Office/)
    expect(within(snmp).queryByText(/None of your SNMP credentials covers/)).toBeNull()
    await user.click(within(snmp).getByRole('button', { name: 'Read this device now' }))
    expect(await within(snmp).findByText(/192\.168\.10\.21 (answered|was not read)\./, undefined, T)).toBeInTheDocument()
  })

  it('with no credential whose scope holds the address, says so before the read and preselects none', async () => {
    await onlyCredentials(['Lab Ubuntu servers', '192.168.20.0/24'])
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const snmp = item(await sources(), 'SNMP')
    await user.click(within(snmp).getByRole('button', { name: 'Add SNMP' }))
    const select = (await within(snmp).findByLabelText('Credential', undefined, T)) as HTMLSelectElement
    expect(select.value).toBe('')
    expect(within(snmp).getByText(/^None of your SNMP credentials covers 192\.168\.10\.21, so a read with one of them is refused\./)).toBeInTheDocument()
    expect(within(snmp).getByRole('button', { name: 'Read this device now' })).toBeDisabled()
    await user.selectOptions(select, within(select).getByRole('option', { name: /Lab Ubuntu servers/ }))
    await user.click(within(snmp).getByRole('button', { name: 'Add 192.168.10.21 to Lab Ubuntu servers' }))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect((within(dialog).getByLabelText('Send only to') as HTMLTextAreaElement).value).toBe('192.168.20.0/24\n192.168.10.21')
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

// D-601 (kien, a FortiGate added by hand: "I should still be able to add other checks later like osquery or SNMP; let the user toggle
// each part on/off"): each active source is switched per device, with what it means in one line; a hand-added device starts silent.
describe('Device page: Sources switches (D-601)', () => {
  const addByHand = async (ip: string) => {
    const r = await api('POST', '/devices', { catalog_id: 'fortigate', ip })
    expect(r.status).toBe(201)
    return ((await r.json()) as { id: string }).id
  }
  const sw = (li: HTMLElement) => within(li).getByRole('switch')

  it('a device added by hand starts with scan and SNMP off; "Turn SNMP on and add" turns SNMP on and reads it right there', async () => {
    enableModule('agent-intake', true)
    const id = await addByHand('192.168.10.77')
    const user = userEvent.setup()
    renderApp(`/devices/${id}`, { role: 'admin' })
    const list = await sources()
    const scan = item(list, 'Network scan')
    const snmp = item(list, 'SNMP')
    expect(sw(scan)).not.toBeChecked()
    expect(sw(snmp)).not.toBeChecked()
    expect(scan).toHaveTextContent('Off: no scan packet goes to this device.')
    expect(snmp).toHaveTextContent('Off: no SNMP read goes to this device.')
    expect(screen.getByText(/Vedette sends nothing to it until you turn a source on here/)).toBeInTheDocument()
    expect(item(list, 'Agent (osquery or Wazuh)')).toHaveTextContent('installed or uninstalled on the machine itself')
    await user.click(within(snmp).getByRole('button', { name: 'Turn SNMP on and add' }))
    expect(await within(snmp).findByLabelText('Credential', undefined, T)).toBeInTheDocument()
    await vi.waitFor(() => expect(sw(item(list, 'SNMP'))).toBeChecked(), T)
    expect(item(list, 'SNMP')).toHaveTextContent('outside the LAN ranges only because you turned it on here; never if excluded')
    expect(sw(item(list, 'Network scan'))).not.toBeChecked() // that source only
    await user.click(within(item(list, 'SNMP')).getByRole('button', { name: 'Read this device now' }))
    expect(await within(item(list, 'SNMP')).findByText(/192\.168\.10\.77 (answered|was not read)\./, undefined, T)).toBeInTheDocument()
    const d = (await (await api('GET', `/devices/${id}`)).json()) as { asset: { scan_source: string; snmp_source: string } }
    expect(d.asset).toMatchObject({ scan_source: 'off', snmp_source: 'on' })
  })

  it('turns the network scan of a discovered device off and on again, saying what off means', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    expect(sw(item(list, 'Network scan'))).toBeChecked()
    await user.click(sw(item(list, 'Network scan')))
    await vi.waitFor(() => expect(item(list, 'Network scan')).toHaveTextContent('Off: no scan packet goes to this device.'), T)
    expect(((await (await api('GET', '/devices/a-nas02')).json()) as { asset: { scan_source: string } }).asset.scan_source).toBe('off')
    await user.click(sw(item(list, 'Network scan')))
    await vi.waitFor(() => expect(sw(item(list, 'Network scan'))).toBeChecked(), T)
  })

  it('a viewer sees the switches locked', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    const list = await sources()
    expect(sw(item(list, 'Network scan'))).toBeDisabled()
    expect(sw(item(list, 'SNMP'))).toBeDisabled()
  })

  it('a Test that SNMP is off for answers with "Turn SNMP on" on the spot', async () => {
    const id = await addByHand('192.168.10.78')
    expect((await api('PUT', `/devices/${id}/sources`, { snmp: 'off' })).status).toBe(200)
    const user = userEvent.setup()
    renderApp(`/devices/${id}`, { role: 'admin' })
    const list = await sources()
    await user.click(sw(item(list, 'SNMP')))
    await vi.waitFor(() => expect(sw(item(list, 'SNMP'))).toBeChecked(), T)
    await user.click(within(item(list, 'SNMP')).getByRole('button', { name: 'Add SNMP' }))
    expect(await within(item(list, 'SNMP')).findByLabelText('Credential', undefined, T)).toBeInTheDocument()
    // turned off again elsewhere (another tab): the read says why and turns it back on here
    expect((await api('PUT', `/devices/${id}/sources`, { snmp: 'off' })).status).toBe(200)
    await user.click(within(item(list, 'SNMP')).getByRole('button', { name: 'Read this device now' }))
    const on = await within(item(list, 'SNMP')).findByRole('button', { name: 'Turn SNMP on for 192.168.10.78 and read it' }, T)
    await user.click(on)
    expect(await within(item(list, 'SNMP')).findByText(/192\.168\.10\.78 (answered|was not read)\./, undefined, T)).toBeInTheDocument()
  })
})
