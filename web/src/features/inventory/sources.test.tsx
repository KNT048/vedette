import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// issue #829 ("the device came from a scan, I added it, then I could not add SNMP to it; can I add osquery later, or both?").
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const api = async (method: string, path: string, body?: unknown) => {
  sessionStore.set({ userId: 'u-admin' })
  return fetch(`${location.origin}/api/v1/inventory${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
const sources = async () => screen.findByRole('list', { name: 'Sources' }, T)
/** The row of one source, once the server's rows are drawn. */
const row = async (src: 'scan' | 'snmp' | 'agent') => {
  const list = await sources()
  return vi.waitFor(() => { const li = list.querySelector<HTMLElement>(`li[data-source="${src}"]`); expect(li).not.toBeNull(); return li! }, T)
}
const sw = (li: HTMLElement) => within(li).getByRole('switch')

describe('Device page: Sources, three rows from the server', () => {
  it('network scan, SNMP and agent, each with its state and one button; passive listening is not a row; no a11y violations', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-srvad', { role: 'admin' })
    const list = await sources()
    expect(await row('scan')).toHaveTextContent('Working')
    expect(await row('scan')).toHaveTextContent(/last report/)
    expect(await row('snmp')).toHaveTextContent('Not set up')
    expect(within(await row('snmp')).getByRole('button', { name: 'Set up' })).toHaveTextContent('Set up')
    expect(within(await row('snmp')).queryByRole('switch')).toBeNull() // no switch before SNMP has settings
    const agent = await row('agent')
    expect(agent).toHaveTextContent('No agent')
    expect(within(list).getAllByRole('listitem')).toHaveLength(3)
    expect(within(list).queryByText('Passive listening')).toBeNull()
    // no explanation-only text under the rows: what a source is sits behind its info icon
    expect(screen.queryByText(/set up the new one first, then stop the old one/)).toBeNull()
    await expectNoA11yViolations(container)
    await user.click(within(agent).getByRole('button', { name: 'Create agent token' }))
    expect(await screen.findByRole('dialog', { name: 'Install osquery on SRV-AD' }, T)).toBeInTheDocument()
  })

  it('a module that is off: the row says so and offers to turn it on; a person who is not an administrator is told who can', async () => {
    enableModule('agent-intake', false)
    renderApp('/devices/a-nas02', { role: 'admin' })
    const agent = await row('agent')
    await vi.waitFor(() => expect(agent).toHaveAttribute('data-state', 'module_off'), T)
    expect(agent).toHaveTextContent('Module off')
    expect(agent).not.toHaveTextContent(/last report/)
    expect(within(agent).getByRole('button', { name: 'Turn on Agent intake' })).toBeInTheDocument()
    cleanup()
    renderApp('/devices/a-nas02', { role: 'operator' })
    const snmp = await row('snmp')
    expect(within(snmp).getByRole('button', { name: 'Set up' })).toBeDisabled()
    expect(within(await row('agent')).queryByRole('button', { name: 'Turn on Agent intake' })).toBeNull()
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

// A user request (a FortiGate added by hand: "I should still be able to add other checks later like osquery or SNMP; let the user toggle
// each part on/off"): each active source is switched per device; a hand-added device starts silent.
describe('Device page: Sources switches', () => {
  const addByHand = async (ip: string) => {
    const r = await api('POST', '/devices', { catalog_id: 'fortigate', ip })
    expect(r.status).toBe(201)
    return ((await r.json()) as { id: string }).id
  }

  it('a device added by hand starts silent: scan off, SNMP not set up, one line "Added by hand"; setting SNMP up turns that source on only', async () => {
    enableModule('agent-intake', true)
    const id = await addByHand('192.168.10.77')
    renderApp(`/devices/${id}`, { role: 'admin' })
    const scan = await row('scan')
    expect(sw(scan)).not.toBeChecked()
    expect(scan).toHaveTextContent('Off')
    expect(within(await row('snmp')).queryByRole('switch')).toBeNull()
    expect(await screen.findByTestId('sources-only', {}, T)).toHaveTextContent(/^Added by hand/)
    cleanup()

    // with settings of its own, the switch is drawn, on (saving them was the consent)
    expect((await api('PUT', `/snmp/devices/${id}`, { version: 'v2c', community: 'ro-community-1' })).status).toBe(200)
    renderApp(`/devices/${id}`, { role: 'admin' })
    await vi.waitFor(async () => expect(sw(await row('snmp'))).toBeChecked(), T)
    expect(await row('snmp')).not.toHaveTextContent('Not set up')
    expect(sw(await row('scan'))).not.toBeChecked() // that source only
    const d = (await (await api('GET', `/devices/${id}`)).json()) as { asset: { scan_source: string; snmp_source: string } }
    expect(d.asset).toMatchObject({ scan_source: 'off', snmp_source: 'on' })
  })

  it('a device with SNMP settings whose switch a person turned off shows the switch off, and turns it on again', async () => {
    const user = userEvent.setup()
    expect((await api('PUT', '/snmp/devices/a-nas02', { version: 'v2c', community: 'ro-community-2' })).status).toBe(200)
    expect((await api('PUT', '/devices/a-nas02/sources', { snmp: 'off' })).status).toBe(200)
    renderApp('/devices/a-nas02', { role: 'admin' })
    await vi.waitFor(async () => expect(sw(await row('snmp'))).not.toBeChecked(), T)
    expect(await row('snmp')).toHaveTextContent('Off')
    await user.click(sw(await row('snmp')))
    await vi.waitFor(async () => expect(sw(await row('snmp'))).toBeChecked(), T)
  })

  it('turns the network scan of a discovered device off and on again', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    expect(sw(await row('scan'))).toBeChecked()
    expect(sw(await row('scan'))).toHaveAttribute('title', expect.stringMatching(/^On: scanned in the scan window/))
    await user.click(sw(await row('scan')))
    await vi.waitFor(async () => expect(await row('scan')).toHaveAttribute('data-state', 'off'), T)
    expect(((await (await api('GET', '/devices/a-nas02')).json()) as { asset: { scan_source: string } }).asset.scan_source).toBe('off')
    await user.click(sw(await row('scan')))
    await vi.waitFor(async () => expect(sw(await row('scan'))).toBeChecked(), T)
  })

  it('the agent switch: off refuses the device\'s agent data (the row reads Off), on takes it again', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    await vi.waitFor(async () => expect(sw(await row('agent'))).toBeChecked(), T)
    await user.click(sw(await row('agent')))
    await vi.waitFor(async () => expect(await row('agent')).toHaveAttribute('data-state', 'off'), T)
    expect(sw(await row('agent'))).not.toBeChecked()
    await user.click(sw(await row('agent')))
    await vi.waitFor(async () => expect(sw(await row('agent'))).toBeChecked(), T)
    expect(await row('agent')).not.toHaveAttribute('data-state', 'off')
  })

  it('a viewer sees the switches locked and no SNMP settings', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    expect(sw(await row('scan'))).toBeDisabled()
    expect(within(await row('snmp')).queryByRole('switch')).toBeNull()
    expect(within(await row('snmp')).getByRole('button', { name: 'Set up' })).toBeDisabled()
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
