import { beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { server } from '@/test/server'
import { API } from '@/mocks/http'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { historyStore, markReached } from '@/features/scanning/mocks'
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
const item = (list: HTMLElement, name: string) => within(list).getByText(name).closest('li') as HTMLElement

describe('Device page: Sources', () => {
  it('lists what feeds a scanned device and offers osquery', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-srvad', { role: 'admin' })
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

  // The network scan's time and the Last checks section read the same run: each time is named for what it is, the device check (the
  // run Last checks lists) and a later network scan that heard the device; never one unlabelled "last report".
  it('the network scan names its times: the last device check, as Last checks says, and a later network scan', async () => {
    const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
    historyStore.set([{ id: 'saj-old', kind: 'device', engine: 'nmap-versions', trigger: 'automatic', label: '192.168.10.21', target_id: null, started_at: ago(72), ended_at: ago(71.9), outcome: 'ok', text: 'Scanned 192.168.10.21: no open port' }])
    markReached('saj-old', ['192.168.10.21'])
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, os: { value: 'Linux 5.4 - 5.15', source: 'nmap', confidence: 0.9, seen_at: ago(22) } } : a)))
    renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    const scan = item(list, 'Network scan')
    expect(await within(scan).findByText('last check 3 days ago', {}, T)).toBeInTheDocument()
    expect(within(scan).getByText('seen by a network scan 22 hours ago')).toBeInTheDocument()
    expect(within(scan).queryByText(/last report/)).toBeNull()
    const ident = await screen.findByRole('group', { name: 'Device check: ports, services, software' }, T)
    expect(within(ident).getByText(/\(3 days ago\)/)).toBeInTheDocument()
  })

  it('a scan heard only by the device check itself shows one time, the check', async () => {
    const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
    historyStore.set([{ id: 'saj-new', kind: 'device', engine: 'nmap-versions', trigger: 'person', label: '192.168.10.21', target_id: null, started_at: ago(2), ended_at: ago(1.99), outcome: 'ok', text: 'Scanned 192.168.10.21: no open port' }])
    markReached('saj-new', ['192.168.10.21'])
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, os: { value: 'Linux 5.4 - 5.15', source: 'nmap', confidence: 0.9, seen_at: ago(1.99) } } : a)))
    renderApp('/devices/a-nas02', { role: 'admin' })
    const scan = item(await sources(), 'Network scan')
    expect(await within(scan).findByText('last check 2 hours ago', {}, T)).toBeInTheDocument()
    expect(within(scan).queryByText(/seen by a network scan/)).toBeNull()
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

// A user request (a FortiGate added by hand: "I should still be able to add other checks later like osquery or SNMP; let the user toggle
// each part on/off"): each active source is switched per device, with what it means in one line; a hand-added device starts silent.
describe('Device page: Sources switches', () => {
  const addByHand = async (ip: string) => {
    const r = await api('POST', '/devices', { catalog_id: 'fortigate', ip })
    expect(r.status).toBe(201)
    return ((await r.json()) as { id: string }).id
  }
  const sw = (li: HTMLElement) => within(li).getByRole('switch')

  // SNMP reads go only to a device with SNMP settings of its own: without them there is no SNMP switch to claim "On", only what to do.
  const notSetUp = async (list: HTMLElement) => {
    const snmp = item(list, 'SNMP')
    expect(await within(snmp).findByTestId('snmp-state', {}, T)).toHaveTextContent('Not set up')
    expect(within(snmp).queryByRole('switch')).toBeNull()
    expect(snmp).not.toHaveTextContent('read with the SNMP settings of this device')
    expect(within(snmp).getByRole('button', { name: 'Set up' })).toBeInTheDocument()
    return snmp
  }

  it('a device added by hand starts silent: scan off, SNMP not set up; setting SNMP up turns that source on only', async () => {
    enableModule('agent-intake', true)
    const id = await addByHand('192.168.10.77')
    renderApp(`/devices/${id}`, { role: 'admin' })
    const list = await sources()
    const scan = item(list, 'Network scan')
    expect(sw(scan)).not.toBeChecked()
    expect(scan).toHaveTextContent('Off: no scan packet goes to this device.')
    await notSetUp(list)
    expect(screen.getByText('Added by hand: Vedette sends nothing to it until you turn its network scan on or set up SNMP here.')).toBeInTheDocument()
    expect(item(list, 'Agent (osquery or Wazuh)')).toHaveTextContent('installed or uninstalled on the machine itself')
    cleanup()

    // with settings of its own, the switch is drawn, on (saving them was the consent), and says what on means
    expect((await api('PUT', `/snmp/devices/${id}`, { version: 'v2c', community: 'ro-community-1' })).status).toBe(200)
    renderApp(`/devices/${id}`, { role: 'admin' })
    const after = await sources()
    await vi.waitFor(() => expect(sw(item(after, 'SNMP'))).toBeChecked(), T)
    expect(item(after, 'SNMP')).toHaveTextContent('On: read with the SNMP settings of this device')
    expect(item(after, 'SNMP')).not.toHaveTextContent('Not set up')
    expect(sw(item(after, 'Network scan'))).not.toBeChecked() // that source only
    expect(screen.queryByText(/Vedette sends nothing to it until/)).toBeNull()
    const d = (await (await api('GET', `/devices/${id}`)).json()) as { asset: { scan_source: string; snmp_source: string } }
    expect(d.asset).toMatchObject({ scan_source: 'off', snmp_source: 'on' })
  })

  it('a stored SNMP switch on without SNMP settings (credentials moved away, or settings removed) reads not set up, never On', async () => {
    const id = await addByHand('192.168.10.80')
    expect((await api('PUT', `/devices/${id}/sources`, { snmp: 'on' })).status).toBe(200) // the stored state is left as it is
    renderApp(`/devices/${id}`, { role: 'admin' })
    await notSetUp(await sources())
    // nothing is sent to it: it still reads as silent
    expect(screen.getByText(/Vedette sends nothing to it until you turn its network scan on or set up SNMP here/)).toBeInTheDocument()
    cleanup()

    // a discovered device has SNMP on by default, and also no switch until it has settings
    renderApp('/devices/a-nas02', { role: 'admin' })
    await notSetUp(await sources())
  })

  it('a device with SNMP settings whose switch a person turned off shows the switch off, and turns it on again', async () => {
    const user = userEvent.setup()
    expect((await api('PUT', '/snmp/devices/a-nas02', { version: 'v2c', community: 'ro-community-2' })).status).toBe(200)
    expect((await api('PUT', '/devices/a-nas02/sources', { snmp: 'off' })).status).toBe(200)
    renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    await vi.waitFor(() => expect(sw(item(list, 'SNMP'))).not.toBeChecked(), T)
    expect(item(list, 'SNMP')).toHaveTextContent('Off: no SNMP read goes to this device.')
    await user.click(sw(item(list, 'SNMP')))
    await vi.waitFor(() => expect(sw(item(list, 'SNMP'))).toBeChecked(), T)
  })

  // INV-46: the Manual source says when a person last entered or changed something on the device, never a "report", and never the
  // day it was added once something changed since.
  it('the manual source reads when a person added the device, then when they last changed it', async () => {
    const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString()
    const old = ago(48)
    const fw = { id: 's-fw-old', display: 'FortiGate', vendor: 'Fortinet', product: 'FortiOS', version: null, kev: [], source: 'manual' as const, confidence: 1, set_at: old }
    assetsStore.update((l) => [{ id: 'a-hand-old', site: 'hq', ip: '192.168.10.78', mac: null, hostname: 'fw-01', kind: 'firewall', vendor: { value: 'Fortinet', source: 'manual', confidence: 1, seen_at: old },
      model: null, os: null, software: [fw], services: [], first_seen: old, last_seen: old, approved: true, fragile: false, origin: 'manual' }, ...l])
    const manualText = async () => {
      renderApp('/devices/a-hand-old', { role: 'admin' })
      const li = item(await sources(), 'Manual')
      expect(within(li).queryByText(/last report/)).toBeNull()
      return li
    }

    // nothing changed since it was added two days ago
    let li = await manualText()
    expect(within(li).getByText('added 2 days ago')).toBeInTheDocument()

    // its firmware version was entered two hours ago: that time, not the day it was added
    assetsStore.update((l) => l.map((a) => (a.id === 'a-hand-old' ? { ...a, software: [...a.software, { ...fw, id: 's-fw-new', version: '7.2.13', set_at: ago(2) }] } : a)))
    cleanup()
    li = await manualText()
    expect(within(li).getByText('last changed 2 hours ago')).toBeInTheDocument()

    // an edit of the row now moves it again
    expect((await api('PATCH', '/devices/a-hand-old/software/s-fw-old', { version: '7.2.14' })).status).toBe(200)
    cleanup()
    li = await manualText()
    expect(await within(li).findByText(/^last changed (now|\d+ seconds? ago)$/, {}, T)).toBeInTheDocument()
  })

  it('a hand-added device with no manual row left still reads the manual source as in use, with its time', async () => {
    const old = new Date(Date.now() - 48 * 3_600_000).toISOString()
    assetsStore.update((l) => [{ id: 'a-hand-ip', site: 'hq', ip: '192.168.10.79', mac: null, hostname: null, name: 'switch-01', kind: 'unknown', vendor: null,
      model: null, os: null, software: [], services: [], first_seen: old, last_seen: old, approved: true, fragile: false, origin: 'manual' }, ...l])
    const d = (await (await api('GET', '/devices/a-hand-ip')).json()) as { observations: { source: string }[] }
    // as the API answers it: no manual observation or software row, only the time it was added
    server.use(http.get(`${API}/inventory/devices/a-hand-ip`, () => HttpResponse.json({ ...d, observations: d.observations.filter((o) => o.source !== 'manual'), manual_at: old })))
    renderApp('/devices/a-hand-ip', { role: 'admin' })
    const li = item(await sources(), 'Manual')
    expect(await within(li).findByText('added 2 days ago', {}, T)).toBeInTheDocument()
    expect(li).toHaveTextContent('Reporting')
    expect(li).not.toHaveTextContent('Not set up')
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

  it('a viewer sees the scan switch locked and no SNMP switch: only administrators see whether SNMP is set up', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    const list = await sources()
    expect(sw(item(list, 'Network scan'))).toBeDisabled()
    expect(within(item(list, 'SNMP')).queryByRole('switch')).toBeNull()
    expect(item(list, 'SNMP')).toHaveTextContent('An administrator sets this up.')
    expect(item(list, 'SNMP')).not.toHaveTextContent('read with the SNMP settings of this device')
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
