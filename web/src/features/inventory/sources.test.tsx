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
const api = async (method: string, path: string, body?: unknown) => {
  sessionStore.set({ userId: 'u-admin' })
  return fetch(`${location.origin}/api/v1/inventory${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
const sources = async () => screen.findByRole('list', { name: 'Sources' }, T)
const item = (list: HTMLElement, name: string) => within(list).getByText(name).closest('li') as HTMLElement

describe('Device page: Sources (D-598)', () => {
  it('lists what feeds a scanned device and offers osquery', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    expect(item(list, 'Network scan')).toHaveTextContent('Reporting')
    expect(item(list, 'Passive listening')).toHaveTextContent('Reporting')
    expect(item(list, 'SNMP')).toHaveTextContent('Not set up')
    const agent = item(list, 'Agent (osquery or Wazuh)')
    // #849: Install osquery opens the Add a device dialog's osquery method on this page
    expect(within(agent).getByRole('button', { name: 'Install osquery' })).toBeInTheDocument()
    expect(screen.getByText(/set up the new one first, then stop the old one/)).toBeInTheDocument()
    await expectNoA11yViolations(container)
    await user.click(within(agent).getByRole('button', { name: 'Install osquery' }))
    expect(await screen.findByRole('dialog', undefined, T)).toBeInTheDocument()
  })

  it('says why SNMP or osquery cannot be added: modules off, not an administrator', async () => {
    enableModule('agent-intake', false)
    renderApp('/devices/a-nas02', { role: 'operator' })
    const list = await sources()
    expect(item(list, 'Agent (osquery or Wazuh)')).toHaveTextContent('Turn on the Agents module in Settings')
    expect(item(list, 'SNMP')).toHaveTextContent('An administrator sets this up.')
    expect(within(item(list, 'SNMP')).queryByRole('button', { name: 'Add SNMP' })).toBeNull()
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

  it('a device added by hand starts with scan and SNMP off; the SNMP switch turns that source on only', async () => {
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
    await user.click(sw(snmp))
    await vi.waitFor(() => expect(sw(item(list, 'SNMP'))).toBeChecked(), T)
    expect(item(list, 'SNMP')).toHaveTextContent('outside the LAN ranges only because it is on here; never if excluded')
    expect(sw(item(list, 'Network scan'))).not.toBeChecked() // that source only
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
})

// the mock of the per-device SNMP API answers as the box does: never a secret, only its last 4 characters; Copy from copies on
// the box; saving turns the device's SNMP source on.
describe('SNMP per device, the mock API', () => {
  it('sets up, copies and checks a device without ever answering a secret', async () => {
    const empty = (await (await api('GET', '/snmp/devices/a-nas02')).json()) as { state: string; ip: string }
    expect(empty).toMatchObject({ state: 'not_set_up', ip: '192.168.10.21' })
    const put = await api('PUT', '/snmp/devices/a-nas02', { version: 'v2c', community: 's3cret-community' })
    const body = await put.text()
    expect(put.status).toBe(200)
    expect(body).not.toContain('s3cret')
    expect(JSON.parse(body)).toMatchObject({ state: 'waiting', read_from: '192.168.10.21', read_from_default: true, secret_last4: 'nity' })
    const bad = await api('PUT', '/snmp/devices/a-nas02', { version: 'v2c', community: 'x', read_from: '224.0.0.1' })
    expect(bad.status).toBe(400)
    const list = await (await api('GET', '/snmp')).text()
    expect(list).not.toContain('s3cret')
    const copyElsewhere = await api('PUT', '/snmp/devices/a-nas01', { copy_from: 'a-nas02', read_from: '192.168.10.99' })
    expect(copyElsewhere.status).toBe(400) // a copied secret goes only to the device's own address
    const copy = await api('PUT', '/snmp/devices/a-nas01', { copy_from: 'a-nas02' })
    const copyBody = await copy.text()
    expect(copy.status).toBe(200)
    expect(copyBody).not.toContain('s3cret')
    expect(JSON.parse(copyBody)).toMatchObject({ read_from: '192.168.10.20', secret_last4: 'nity' })
    const taken = await api('PUT', '/snmp/devices/a-sw01', { version: 'v2c', community: 'public', read_from: '192.168.10.20' })
    expect(taken.status).toBe(409)
    const d = (await (await api('GET', '/devices/a-nas02')).json()) as { asset: { snmp_source: string } }
    expect(d.asset.snmp_source).toBe('on')
    const check = (await (await api('POST', '/snmp/devices/a-nas02/check')).json()) as { ok: boolean; reason: string; snmp: { state: string } }
    expect(check.reason).toBe('no_answer') // the mock device answers only the community "public"
    expect(check.snmp.state).toBe('not_answering')
  })
})
