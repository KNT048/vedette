import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { assetsStore, modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// The device page's Sources list and the install / add flows: everything is done where the person is (no detour to another card or dialog).
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const sources = async () => screen.findByRole('list', { name: 'Sources' }, T)
const item = (list: HTMLElement, name: string) => within(list).getByText(name).closest('li') as HTMLElement
const api = async (method: string, path: string, body?: unknown) => {
  sessionStore.set({ userId: 'u-admin' })
  return fetch(`${location.origin}/api/v1/inventory${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
const setOs = (id: string, os: string | null) => assetsStore.update((l) => l.map((a) => (a.id === id ? { ...a, os: os ? { value: os, source: 'nmap', confidence: 1, seen_at: new Date().toISOString() } : null } : a)))

describe('Device page: SNMP is one row of the Sources list', () => {
  it('has no SNMP card of its own; Set up opens the settings in place and the row then shows the state', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    expect(screen.queryByRole('heading', { name: 'SNMP', level: 2 })).toBeNull()
    expect(screen.getAllByText('SNMP').length).toBe(1) // one row, not a row plus a frame
    const snmp = item(list, 'SNMP')
    expect(await within(snmp).findByTestId('snmp-state', undefined, T)).toHaveTextContent('Not set up')
    await user.click(within(snmp).getByRole('button', { name: 'Set up' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.type(within(dlg).getByLabelText('Community'), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(await within(snmp).findByText(/Waiting for the first read|Working|Not answering/, undefined, T)).toBeInTheDocument()
    expect(within(snmp).getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(within(snmp).getByRole('button', { name: 'Check now' })).toBeInTheDocument()
    expect(within(snmp).queryByRole('button', { name: 'Set up' })).toBeNull()
  })
})

describe('Device page: the Sources list is compact', () => {
  it('sources that only report are one line with no frame and no control; the ones a person acts on keep theirs', async () => {
    renderApp('/devices/a-nas02', { role: 'admin' })
    const list = await sources()
    const passive = item(list, 'Passive listening')
    expect(passive).toHaveTextContent('Reporting')
    expect(passive.className).not.toMatch(/\bborder\b/)
    expect(within(passive).queryByRole('button')).toBeNull()
    expect(within(passive).queryByRole('switch')).toBeNull()
    expect(within(passive).queryByRole('link')).toBeNull()
    const scan = item(list, 'Network scan')
    expect(scan.className).toMatch(/\bborder\b/)
    expect(within(scan).getByRole('switch')).toBeInTheDocument()
    expect(item(list, 'SNMP').className).toMatch(/\bborder\b/)
  })

  it('a hand-added device: its manual line is a plain line too', async () => {
    const r = await api('POST', '/devices', { catalog_id: 'fortigate', ip: '192.168.10.91' })
    const { id } = (await r.json()) as { id: string }
    renderApp(`/devices/${id}`, { role: 'admin' })
    const manual = item(await sources(), 'Manual')
    expect(manual.className).not.toMatch(/\bborder\b/)
    expect(within(manual).queryByRole('button')).toBeNull()
  })
})

describe('Device page: Install osquery goes straight to this device', () => {
  it('a Linux device: its own command, copy button, no Add a device form, the manual way folded', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', 'Ubuntu 22.04 LTS')
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    const agent = item(await sources(), 'Agent (osquery or Wazuh)')
    await user.click(within(agent).getByRole('button', { name: 'Install osquery' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(dlg).toHaveAccessibleName(/^Install osquery on /)
    expect(await within(dlg).findByText(/sudo sh "\$f" --token vdt_osquery_/, undefined, T)).toBeInTheDocument()
    expect(within(dlg).getByText(/Operating system: Linux/)).toBeInTheDocument()
    expect(within(dlg).getAllByRole('button', { name: /^Copy/ }).length).toBeGreaterThan(0)
    expect(within(dlg).queryByText(/Add a device/)).toBeNull()
    expect(within(dlg).queryByRole('radiogroup')).toBeNull()
    expect(within(dlg).queryByLabelText(/Token name/)).toBeNull()
    expect(within(dlg).getByText('Works on Debian, Ubuntu, RHEL family, SUSE, Amazon Linux, Alpine and Arch. Run as root or with sudo.')).toBeInTheDocument()
    const manual = within(dlg).getByText('Download and install manually').closest('details')!
    expect(manual).not.toHaveAttribute('open')
    await user.click(within(dlg).getByText('Download and install manually'))
    expect(manual).toHaveAttribute('open')
  })

  it('a Windows device gets the PowerShell command', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', 'Microsoft Windows Server 2025')
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    await user.click(within(item(await sources(), 'Agent (osquery or Wazuh)')).getByRole('button', { name: 'Install osquery' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(await within(dlg).findByText(/-Token 'vdt_osquery_/, undefined, T)).toBeInTheDocument()
  })

  it('an unknown system is asked for, and only then is the command shown', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', null)
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    await user.click(within(item(await sources(), 'Agent (osquery or Wazuh)')).getByRole('button', { name: 'Install osquery' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(await within(dlg).findByRole('button', { name: 'Windows' }, T)).toBeInTheDocument()
    expect(within(dlg).queryByText(/--token/)).toBeNull()
    await user.click(within(dlg).getByRole('button', { name: 'Linux' }))
    expect(await within(dlg).findByText(/sudo sh "\$f" --token vdt_osquery_/, undefined, T)).toBeInTheDocument()
  })
})

describe('Add a device', () => {
  it('SNMP: address and settings in one form; the device is created with SNMP on, with no "add it manually first"', async () => {
    enableModule('sensor-active', true)
    const user = userEvent.setup()
    renderApp('/devices?add=snmp', { role: 'admin' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    expect(within(dlg).queryByText(/manually|Add the device first/i)).toBeNull()
    await user.type(await within(dlg).findByLabelText('Device IP address', undefined, T), '192.168.10.93')
    await user.type(within(dlg).getByRole('combobox', { name: 'What the device is' }), 'fortigate')
    await user.click(await within(dlg).findByRole('option', { name: /FortiGate/ }, T))
    await user.type(within(dlg).getByLabelText('Community'), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Add device and turn SNMP on' }))
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Add a device' })).toBeNull(), T)
    const list = (await (await api('GET', '/devices')).json()) as { items: { id: string; ip: string }[] }
    const created = list.items.find((d) => d.ip === '192.168.10.93')!
    expect(created).toBeTruthy()
    const d = (await (await api('GET', `/devices/${created.id}`)).json()) as { asset: { snmp_source: string } }
    expect(d.asset.snmp_source).toBe('on')
    const snmp = (await (await api('GET', `/snmp/devices/${created.id}`)).json()) as { state: string; version: string }
    expect(snmp.state).not.toBe('not_set_up')
  })

  it('SNMP with no IP yet: no sentence shows a blank address (no ", ." and no double space)', async () => {
    enableModule('sensor-active', true)
    const user = userEvent.setup()
    renderApp('/devices?add=snmp', { role: 'admin' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await within(dlg).findByLabelText('Community', undefined, T)
    expect(within(dlg).getByText("Leave empty to read the IP you enter above.")).toBeInTheDocument()
    const consent = within(dlg).getByTestId('snmp-consent')
    expect(consent).toHaveTextContent('once you enter its IP')
    expect(dlg.textContent).not.toMatch(/, \.|\s{2,}| to  in /)
    await user.type(within(dlg).getByLabelText('Device IP address'), '192.168.10.93')
    expect(within(dlg).getByText("Leave empty to read the device's IP, 192.168.10.93.")).toBeInTheDocument()
    expect(within(dlg).getByTestId('snmp-consent')).toHaveTextContent('SNMP questions to 192.168.10.93 in the scan window')
  })

  it('SNMP: nothing is created while the address or the product is missing', async () => {
    enableModule('sensor-active', true)
    const user = userEvent.setup()
    renderApp('/devices?add=snmp', { role: 'admin' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.type(await within(dlg).findByLabelText('Community', undefined, T), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Add device and turn SNMP on' }))
    expect(await within(dlg).findByText("Enter the device's IP address.")).toBeInTheDocument()
    expect(within(dlg).getByText('Pick the product the device is.')).toBeInTheDocument()
  })

  it('osquery: the person picks the system first, then sees the one command; the manual way is folded until opened', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices?add=osquery', { role: 'admin' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    expect(await within(dlg).findByRole('button', { name: 'Windows' }, T)).toBeInTheDocument()
    expect(within(dlg).queryByLabelText(/Token name/)).toBeNull()
    expect(within(dlg).queryByText(/--token|-Token/)).toBeNull()
    await user.click(within(dlg).getByRole('button', { name: 'Linux' }))
    expect(await within(dlg).findByText(/sudo sh "\$f" --token vdt_osquery_/, undefined, T)).toBeInTheDocument()
    const manual = within(dlg).getByText('Download and install manually').closest('details')!
    expect(manual).not.toHaveAttribute('open')
    expect(within(dlg).queryByRole('radiogroup', { name: 'How to add it' })).toBeNull() // the only copy of the token stays on screen
    await user.click(within(dlg).getByRole('button', { name: 'Windows' }))
    expect(await within(dlg).findByText(/-Token 'vdt_osquery_/, undefined, T)).toBeInTheDocument()
  })
})

describe('Device page: the Agent row knows what an agent can run on', () => {
  const AGENT = 'Agent (osquery or Wazuh)'
  const HINT = 'Agents run on computers and servers.'

  it('a firewall: no Install osquery; one line says agents are for computers and servers and SNMP reads the firmware; Set up opens the SNMP settings in place', async () => {
    enableModule('agent-intake', true)
    enableModule('sensor-active', true)
    const user = userEvent.setup()
    const r = await api('POST', '/devices', { catalog_id: 'fortigate', ip: '192.168.10.94' })
    const id = ((await r.json()) as { id: string }).id
    renderApp(`/devices/${id}`, { role: 'admin' })
    const agent = item(await sources(), AGENT)
    expect(await within(agent).findByTestId('agent-kind-hint', undefined, T)).toHaveTextContent(`${HINT} For this device, SNMP reads the firmware version.`)
    expect(within(agent).queryByRole('button', { name: 'Install osquery' })).toBeNull()
    await user.click(await within(agent).findByRole('button', { name: 'Set up' }, T))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(within(dlg).getByLabelText('Community')).toBeInTheDocument()
  })

  it('a server keeps Install osquery and gets no hint', async () => {
    enableModule('agent-intake', true)
    renderApp('/devices/a-srvad', { role: 'admin' })
    const agent = item(await sources(), AGENT)
    expect(within(agent).getByRole('button', { name: 'Install osquery' })).toBeInTheDocument()
    expect(within(agent).queryByTestId('agent-kind-hint')).toBeNull()
  })

  it('an unknown kind keeps Install osquery and says what agents are for', async () => {
    enableModule('agent-intake', true)
    assetsStore.update((l) => l.map((a) => (a.id === 'a-srvad' ? { ...a, kind: 'unknown' } : a)))
    renderApp('/devices/a-srvad', { role: 'admin' })
    const agent = item(await sources(), AGENT)
    expect(within(agent).getByRole('button', { name: 'Install osquery' })).toBeInTheDocument()
    expect(within(agent).getByTestId('agent-kind-hint')).toHaveTextContent(HINT)
  })
})
