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
const row = async (src: 'scan' | 'snmp' | 'agent') => {
  const list = await sources()
  return waitFor(() => { const li = list.querySelector<HTMLElement>(`li[data-source="${src}"]`); expect(li).not.toBeNull(); return li! }, T)
}
const api = async (method: string, path: string, body?: unknown) => {
  sessionStore.set({ userId: 'u-admin' })
  return fetch(`${location.origin}/api/v1/inventory${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
}
const setOs = (id: string, os: string | null) => assetsStore.update((l) => l.map((a) => (a.id === id ? { ...a, os: os ? { value: os, source: 'nmap', confidence: 1, seen_at: new Date().toISOString() } : null } : a)))

describe('Device page: SNMP is one row of the Sources list', () => {
  it('has no SNMP card of its own; Set up opens the settings in a dialog; the row then shows its state and Check now only', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'admin' })
    const snmp = await row('snmp')
    expect(screen.queryByRole('heading', { name: 'SNMP', level: 2 })).toBeNull()
    expect(snmp).toHaveTextContent('Not set up')
    await user.click(within(snmp).getByRole('button', { name: 'Set up' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.type(within(dlg).getByLabelText('Community'), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    await waitFor(async () => expect(await row('snmp')).toHaveTextContent(/Waiting for the first read|Working|Not answering/), T)
    const after = await row('snmp')
    expect(within(after).getByRole('button', { name: 'Check now' })).toBeInTheDocument()
    // Edit, Remove and the settings are in the dialog Check now opens, not on the row; "Use on similar devices" is gone
    expect(within(after).queryByRole('button', { name: 'Edit' })).toBeNull()
    expect(within(after).queryByRole('button', { name: /similar devices/ })).toBeNull()
    expect(within(after).queryByText('Read from')).toBeNull()
  })
})

describe('Device page: Install osquery goes straight to this device', () => {
  it('a Linux device: its own command, copy button, no Add a device form, the manual way folded', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', 'Ubuntu 22.04 LTS')
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    await user.click(within(await row('agent')).getByRole('button', { name: 'Create agent token' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(dlg).toHaveAccessibleName(/^Install osquery on /)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
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
    await user.click(within(await row('agent')).getByRole('button', { name: 'Create agent token' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    expect(await within(dlg).findByText(/-Token 'vdt_osquery_/, undefined, T)).toBeInTheDocument()
  })

  it('an unknown system is asked for, and only then is the command shown', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', null)
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    await user.click(within(await row('agent')).getByRole('button', { name: 'Create agent token' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(await within(dlg).findByRole('button', { name: 'Windows' }, T)).toBeInTheDocument()
    expect(within(dlg).queryByText(/--token/)).toBeNull()
    await user.click(within(dlg).getByRole('button', { name: 'Linux' }))
    expect(within(dlg).queryByText(/--token/)).toBeNull() // choosing a system makes no token
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
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
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    expect(await within(dlg).findByText(/sudo sh "\$f" --token vdt_osquery_/, undefined, T)).toBeInTheDocument()
    const manual = within(dlg).getByText('Download and install manually').closest('details')!
    expect(manual).not.toHaveAttribute('open')
    expect(within(dlg).queryByRole('radiogroup', { name: 'How to add it' })).toBeNull() // the only copy of the token stays on screen
    await user.click(within(dlg).getByRole('button', { name: 'Windows' }))
    expect(await within(dlg).findByText(/-Token 'vdt_osquery_/, undefined, T)).toBeInTheDocument()
  })
})

describe('Device page: an agent token made for the device', () => {
  it('is the device\'s: the row then waits for the agent and Show setup gives the token\'s last characters and the command again', async () => {
    enableModule('agent-intake', true)
    setOs('a-srvad', 'Ubuntu 22.04 LTS')
    const user = userEvent.setup()
    renderApp('/devices/a-srvad', { role: 'admin' })
    await user.click(within(await row('agent')).getByRole('button', { name: 'Create agent token' }))
    const dlg = await screen.findByRole('dialog', undefined, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    const secret = (await within(dlg).findByText(/^vdt_osquery_/, undefined, T)).textContent!
    await user.keyboard('{Escape}')
    await waitFor(async () => expect(await row('agent')).toHaveAttribute('data-state', 'waiting'), T)
    expect(await row('agent')).toHaveTextContent('Waiting for the agent to enroll')
    await user.click(within(await row('agent')).getByRole('button', { name: 'Show setup' }))
    const setup = await screen.findByRole('dialog', { name: 'Agent setup of SRV-AD' }, T)
    expect(within(setup).getByTestId('agent-setup-token')).toHaveTextContent(`••••${secret.slice(-4)}`)
    expect(within(setup).queryByText(secret)).toBeNull() // the secret was shown once
    expect(await within(setup).findByText(/--token <TOKEN>/, undefined, T)).toBeInTheDocument()
  })
})
