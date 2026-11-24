import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox, snmpStore } from './mocks'

// S-INV-1: SNMP is set up per device, on the SNMP row of the device's Sources: its state and Check now on the row; the state, settings
// and what answered in the dialog Check now opens, with Edit and Remove there; read address, copy from another device; and the notices
// of what the box changed by itself.
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())

const T = { timeout: 5000 }
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const card = async () => (await screen.findByRole('list', { name: 'Sources' }, T)).querySelector('#device-snmp') as HTMLElement // the SNMP row of the Sources list
const dialog = async () => screen.findByRole('dialog', undefined, T)
/** Check now on the row: the dialog with the state, the settings and what answered. */
const checkNow = async (user: ReturnType<typeof userEvent.setup>, name = 'FW-HQ') => {
  await user.click(await within(await card()).findByRole('button', { name: 'Check now' }, T))
  return screen.findByRole('dialog', { name: `SNMP of ${name}` }, T)
}
const API = '/api/v1/inventory/snmp/devices/:id'
const addByHand = async (ip: string) => {
  sessionStore.set({ userId: 'u-admin' })
  const r = await fetch(`${location.origin}/api/v1/inventory/devices`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ catalog_id: 'fortigate', ip }) })
  expect(r.status).toBe(201)
  return ((await r.json()) as { id: string }).id
}

describe('Device page: SNMP card states', () => {
  it('working: the row says so; Check now shows the read address, secrets by their last 4 characters, the times and what answered', async () => {
    const user = userEvent.setup()
    const { container } = renderApp('/devices/a-fw01', { role: 'admin' })
    expect(await within(await card()).findByText('Working', undefined, T)).toBeInTheDocument()
    expect(await card()).not.toHaveTextContent('Read from') // the settings are behind Check now
    await expectNoA11yViolations(container)
    const c = await checkNow(user)
    expect(await within(c).findByText('Working', undefined, T)).toBeInTheDocument()
    expect(c).toHaveTextContent('The last read at 192.168.10.1 got an answer.')
    expect(c).toHaveTextContent('192.168.10.1 (the device\'s IP)')
    expect(c).toHaveTextContent('v3, user vedette-ro')
    expect(c).toHaveTextContent('SHA-256 · ••••2fe8')
    expect(c).toHaveTextContent('AES-128 · ••••91c4')
    expect(c).not.toHaveTextContent('ro-auth-2fe8')
    expect(c).toHaveTextContent('UDP 161')
    expect(within(c).getByText('What answered at 192.168.10.1')).toBeInTheDocument()
    expect(within(c).getByText('FortiGate 60F')).toBeInTheDocument()
    expect(within(c).getByRole('button', { name: 'Edit' })).toBeInTheDocument()
    expect(within(c).getByRole('button', { name: 'Remove' })).toBeInTheDocument()
  })

  it('not set up: says so and offers Set up SNMP', async () => {
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    expect(await within(c).findByText('Not set up', undefined, T)).toBeInTheDocument()
    expect(within(c).getByRole('button', { name: 'Set up' })).toBeInTheDocument()
    expect(within(c).queryByRole('button', { name: 'Check now' })).toBeNull()
  })

  it('waiting, and moved: the IP changed, so the read address is set again with the secret typed again', async () => {
    // saved while the device was at another address, left to the device's IP: it moved
    snmpStore.update((l) => l.map((x) => (x.device_id === 'a-fw01' ? { ...x, read_from: '192.168.10.99', last_reason: null, last_checked_at: null, last_answer_at: null, answer: null } : x)))
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    const c = await card()
    expect(await within(c).findByText('Waiting for the first read', undefined, T)).toBeInTheDocument()
    // why nothing is sent is said under the row, with its fix
    const notice = (await screen.findByText('Moved: the device\'s IP changed; set the read address again', undefined, T)).closest('[role="status"]') as HTMLElement
    expect(notice).toHaveTextContent('is now at 192.168.10.1')
    await user.click(within(notice).getByRole('button', { name: 'Set the read address' }))
    const dlg = await dialog()
    expect(within(dlg).getByLabelText('Authentication password')).toHaveAccessibleDescription(/Read from changed: type it again/)
    await user.click(within(dlg).getByRole('button', { name: 'Save' }))
    expect(within(dlg).getByLabelText('Authentication password')).toHaveAccessibleDescription('Read from changed: type it again to send it to the new address.')
    await user.type(within(dlg).getByLabelText('Authentication password'), 'new-auth-pass')
    await user.type(within(dlg).getByLabelText('Privacy password'), 'new-priv-pass')
    await user.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    await waitFor(() => expect(screen.queryByText(/Moved:/)).toBeNull(), T)
  })

  it('a viewer and an operator see no SNMP card', async () => {
    for (const role of ['viewer', 'operator'] as const) {
      const { unmount } = renderApp('/devices/a-fw01', { role })
      await screen.findByRole('list', { name: 'Sources' }, T)
      expect(screen.queryByRole('heading', { name: 'SNMP', level: 2 })).toBeNull()
      unmount()
    }
  })

  it('no card while active discovery is off', async () => {
    enableModule('sensor-active', false)
    renderApp('/devices/a-fw01', { role: 'admin' })
    await screen.findByRole('list', { name: 'Sources' }, T)
    expect(screen.queryByRole('heading', { name: 'SNMP', level: 2 })).toBeNull()
  })
})

describe('Device page: SNMP card edit', () => {
  it('sets up v2c; the consent line says saving turns SNMP on for a device added by hand', async () => {
    const id = await addByHand('192.168.10.77')
    const user = userEvent.setup()
    renderApp(`/devices/${id}`, { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    expect(within(dlg).getByTestId('snmp-consent')).toHaveTextContent('Saving turns SNMP on for this device (Sources): Vedette then sends read-only SNMP questions to 192.168.10.77')
    expect(within(dlg).getByText(/v2c sends the community in clear text/)).toBeInTheDocument()
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    expect(within(dlg).getByLabelText('Community')).toHaveAccessibleDescription('Enter the community.')
    await user.type(within(dlg).getByLabelText('Community'), 'public-ro-1234')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(await screen.findByText('SNMP is now on for this device.', undefined, T)).toBeInTheDocument()
    expect(await within(await card()).findByText('Waiting for the first read', undefined, T)).toBeInTheDocument()
    // the Sources switch is on now
    const sources = screen.getByRole('list', { name: 'Sources' })
    await waitFor(() => expect(within(sources).getByRole('switch', { name: 'SNMP reads of this device' })).toBeChecked(), T)
    const shown = await checkNow(user, 'FortiGate')
    expect(await within(shown).findByText(/••••1234/, undefined, T)).toBeInTheDocument()
    expect(shown).not.toHaveTextContent('public-ro-1234')
  })

  it('sets up v3 with a management address and another port', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    expect(within(dlg).getByLabelText('Read from')).toHaveAccessibleDescription('Leave empty to read the device\'s IP, 192.168.10.3.')
    await user.type(within(dlg).getByLabelText('Read from'), '100.66.253.1')
    await user.click(within(dlg).getByRole('button', { name: 'v3' }))
    await user.type(within(dlg).getByLabelText('User name'), 'monitor')
    await user.selectOptions(within(dlg).getByLabelText('Authentication'), 'sha')
    await user.type(within(dlg).getByLabelText('Authentication password'), 'auth-secret-77')
    await user.type(within(dlg).getByLabelText('Privacy password'), 'priv-secret-88')
    await user.type(within(dlg).getByLabelText('Port'), '1161')
    expect(within(dlg).getByTestId('snmp-consent')).toHaveTextContent('to 100.66.253.1')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    const shown = await checkNow(user, 'SW-CORE')
    expect(await within(shown).findByText('100.66.253.1', undefined, T)).toHaveTextContent('(management address)')
    expect(shown).toHaveTextContent('v3, user monitor')
    expect(shown).toHaveTextContent('SHA · ••••t-77')
    expect(shown).toHaveTextContent('UDP 1161')
  })

  it('each read-address mistake is said at Read from, before or after the server', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    await user.type(within(dlg).getByLabelText('Community'), 'public')
    const rf = within(dlg).getByLabelText('Read from')
    const save = within(dlg).getByRole('button', { name: 'Set up SNMP' })
    const tries: [string, RegExp][] = [
      ['192.168.1', /Enter an IPv4 address/],
      ['8.8.8.8', /8\.8\.8\.8 is not a local network address/],
      ['224.0.0.1', /multicast, broadcast or reserved/],
      ['192.168.10.250', /is the Vedette box itself/], // read_from_box, from the server
    ]
    for (const [value, msg] of tries) {
      await user.clear(rf)
      await user.type(rf, value)
      await user.click(save)
      await waitFor(() => expect(rf).toHaveAccessibleDescription(msg), T)
      expect(rf).toHaveAttribute('aria-invalid', 'true')
    }
    // read_from_taken names the other device and links to it
    await user.clear(rf)
    await user.type(rf, '192.168.10.1')
    await user.click(save)
    const err = await within(dlg).findByText(/already the SNMP read address of FW-HQ/, undefined, T)
    expect(rf).toHaveAccessibleDescription(/already the SNMP read address of FW-HQ/)
    expect(within(err).getByRole('link', { name: 'Open FW-HQ' })).toHaveAttribute('href', '/devices/a-fw01#device-snmp')
  })

  // every refusal code of PUT /inventory/snmp/devices/{id} lands at its field (the form matrix)
  const MATRIX: [string, string, 'v2c' | 'v3', boolean][] = [
    ['read_from_not_local', 'Read from', 'v2c', false],
    ['bad_read_from', 'Read from', 'v2c', false],
    ['read_from_box', 'Read from', 'v2c', false],
    ['secret_required', 'Community', 'v2c', false],
    ['secret_required', 'Authentication password', 'v3', false],
    ['secret_required', 'Copy from another device', 'v2c', true],
    ['copy_from_not_found', 'Copy from another device', 'v2c', true],
    ['copy_from_self', 'Copy from another device', 'v2c', true],
    ['bad_secret', 'Community', 'v2c', false],
    ['bad_user', 'User name', 'v3', false],
    ['bad_auth', 'Authentication', 'v3', false],
    ['bad_priv', 'Privacy', 'v3', false],
    ['bad_port', 'Port', 'v2c', false],
  ]
  it.each(MATRIX)('%s is said at %s (%s, copy %s)', async (code, label, version, copy) => {
    server.use(http.put(API, () => HttpResponse.json({ error: { code, message: `Refused: ${code}.` } }, { status: 400 })))
    const user = userEvent.setup()
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    if (copy) await user.selectOptions(within(dlg).getByLabelText('Copy from another device'), 'a-fw01')
    else if (version === 'v3') {
      await user.click(within(dlg).getByRole('button', { name: 'v3' }))
      await user.type(within(dlg).getByLabelText('User name'), 'monitor')
      await user.type(within(dlg).getByLabelText('Authentication password'), 'auth-secret-77')
      await user.type(within(dlg).getByLabelText('Privacy password'), 'priv-secret-88')
    } else await user.type(within(dlg).getByLabelText('Community'), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(within(dlg).getByLabelText(label)).toHaveAccessibleDescription(`Refused: ${code}.`), T)
    expect(within(dlg).queryByRole('alert')).toBeNull()
  })

  it('a refusal with no field (the device is ignored) is said above the buttons', async () => {
    server.use(http.put(API, () => HttpResponse.json({ error: { code: 'device_ignored', message: 'This device is ignored.' } }, { status: 409 })))
    const user = userEvent.setup()
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    await user.type(within(dlg).getByLabelText('Community'), 'public')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    expect(await within(dlg).findByRole('alert', undefined, T)).toHaveTextContent('This device is ignored.')
  })

  it('an edit keeps a blank secret, and asks for it again when Read from changes', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    await user.click(within(await checkNow(user)).getByRole('button', { name: 'Edit' }))
    const dlg = await screen.findByRole('dialog', { name: 'Edit SNMP of FW-HQ' }, T)
    const pw = within(dlg).getByLabelText('Authentication password')
    expect(pw).toHaveAccessibleDescription('Saved: ends in 2fe8. Leave empty to keep it.')
    await user.type(within(dlg).getByLabelText('Read from'), '192.168.10.60')
    expect(pw).toHaveAccessibleDescription(/Read from changed: type it again/)
    await user.clear(within(dlg).getByLabelText('Read from'))
    expect(pw).toHaveAccessibleDescription('Saved: ends in 2fe8. Leave empty to keep it.')
    await user.click(within(dlg).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    expect(await screen.findByText('SNMP saved for FW-HQ.', undefined, T)).toBeInTheDocument()
  })
})

describe('Device page: SNMP copy from another device', () => {
  it('copies on the box to the device\'s own IP: the secret never reaches the browser', async () => {
    const user = userEvent.setup()
    const bodies: unknown[] = []
    server.events.on('request:start', async ({ request }) => { if (request.method === 'PUT' && request.url.includes('/inventory/snmp/devices/')) bodies.push(await request.clone().json()) })
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    const sel = within(dlg).getByLabelText('Copy from another device')
    expect(within(sel).getByRole('option', { name: 'FW-HQ (192.168.10.1, v3)' })).toBeInTheDocument()
    await user.selectOptions(sel, 'a-fw01')
    expect(sel).toHaveAccessibleDescription(/they never reach this browser\. They are sent only to this device's own IP, 192\.168\.10\.3\./)
    expect(within(dlg).queryByLabelText('Community')).toBeNull()
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull(), T)
    server.events.removeAllListeners()
    expect(bodies).toEqual([{ copy_from: 'a-fw01' }])
    const shown = await checkNow(user, 'SW-CORE')
    expect(await within(shown).findByText('v3, user vedette-ro', undefined, T)).toBeInTheDocument()
    expect(shown).toHaveTextContent('192.168.10.3 (the device\'s IP)')
  })

  it('is refused for another read address: the secret must be typed', async () => {
    const user = userEvent.setup()
    let puts = 0
    server.events.on('request:start', ({ request }) => { if (request.method === 'PUT') puts++ })
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    await user.type(within(dlg).getByLabelText('Read from'), '100.66.253.9')
    await user.selectOptions(within(dlg).getByLabelText('Copy from another device'), 'a-fw01')
    await user.click(within(dlg).getByRole('button', { name: 'Set up SNMP' }))
    expect(within(dlg).getByLabelText('Copy from another device')).toHaveAccessibleDescription(/goes only to this device's own IP, 192\.168\.10\.3\. To read it at 100\.66\.253\.9, choose "Don't copy" and type them\./)
    server.events.removeAllListeners()
    expect(puts).toBe(0)
  })

  it('offers no Copy from when no other device has SNMP', async () => {
    snmpStore.set([])
    const user = userEvent.setup()
    renderApp('/devices/a-sw01', { role: 'admin' })
    const c = await card()
    await user.click(await within(c).findByRole('button', { name: 'Set up' }, T))
    const dlg = await dialog()
    expect(within(dlg).queryByLabelText('Copy from another device')).toBeNull()
  })
})

describe('Device page: SNMP Check now and Remove', () => {
  it('Check now is busy while it reads, then shows the new state', async () => {
    let release: () => void = () => {}
    const gate = new Promise<void>((r) => { release = r })
    // holds the check until released, then falls through to the mock box (a resolver that returns nothing passes the request on)
    server.use(http.post(`${API}/check`, async () => { await gate }, { once: true }))
    snmpStore.update((l) => l.map((x) => (x.device_id === 'a-fw01' ? { ...x, last_reason: null, last_checked_at: null, last_answer_at: null, answer: null } : x)))
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    const c = await card()
    expect(await within(c).findByText('Waiting for the first read', undefined, T)).toBeInTheDocument()
    await user.click(within(c).getByRole('button', { name: 'Check now' }))
    const dlg = await screen.findByRole('dialog', { name: 'SNMP of FW-HQ' }, T)
    const busy = await within(dlg).findByRole('button', { name: /Checking/ }, T)
    expect(busy).toHaveAttribute('aria-busy', 'true')
    expect(within(dlg).getByText(/Reading 192\.168\.10\.1 with SNMP/)).toBeInTheDocument()
    release()
    expect(await within(dlg).findByText('Working', undefined, T)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(await within(await card()).findByText('Working', undefined, T)).toBeInTheDocument() // the row reads it again
    expect(await screen.findByText('FW-HQ answered SNMP.', undefined, T)).toBeInTheDocument()
  })

  it('a device that does not answer: the state says why', async () => {
    snmpStore.update((l) => l.map((x) => (x.device_id === 'a-fw01' ? { ...x, version: 'v2c', username: null, auth: null, priv: null, community: 'wrong-community', auth_password: undefined, priv_password: undefined } : x)))
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    const c = await checkNow(user)
    expect(await within(c).findByText('Not answering', undefined, T)).toBeInTheDocument()
    expect(c).toHaveTextContent('No answer from 192.168.10.1')
    expect(await screen.findByText('FW-HQ did not answer SNMP.', undefined, T)).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(await within(await card()).findByText('Not answering', undefined, T)).toBeInTheDocument()
  })

  it('a check refused before anything is sent says why', async () => {
    server.use(http.post(`${API}/check`, () => HttpResponse.json({ error: { code: 'stopped', message: 'Scanning was turned off.' } }, { status: 409 })))
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    const c = await checkNow(user)
    const alert = await within(c).findByRole('alert', undefined, T)
    expect(alert).toHaveTextContent('Nothing was sent')
    expect(alert).toHaveTextContent('Scanning was turned off.')
  })

  it('Remove asks first, then the device has no SNMP', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-fw01', { role: 'admin' })
    await user.click(within(await checkNow(user)).getByRole('button', { name: 'Remove' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove SNMP from FW-HQ?' }, T)
    expect(dlg).toHaveTextContent('Remove SNMP from FW-HQ?')
    expect(dlg).toHaveTextContent('What the device already said stays in the inventory')
    await user.click(within(dlg).getByRole('button', { name: 'Remove SNMP' }))
    expect(await within(await card()).findByText('Not set up', undefined, T)).toBeInTheDocument()
    expect(await screen.findByText('SNMP removed from FW-HQ.', undefined, T)).toBeInTheDocument()
  })
})

describe('SNMP notices and the Scanning card', () => {
  it('the Devices page shows what the box changed by itself until an admin dismisses it', async () => {
    const user = userEvent.setup()
    renderApp('/devices', { role: 'admin' })
    const notice = (await screen.findByText('Vedette changed an SNMP setting by itself', undefined, T)).closest('[role="note"]') as HTMLElement
    expect(notice).toHaveTextContent('SNMP credential "Printers"')
    await user.click(within(notice).getByRole('button', { name: 'Dismiss' }))
    await waitFor(() => expect(screen.queryByText('Vedette changed an SNMP setting by itself')).toBeNull(), T)
  })

  it('an operator sees no notice', async () => {
    renderApp('/devices', { role: 'operator' })
    await screen.findByRole('tab', { name: /Devices/ }, T)
    expect(screen.queryByText('Vedette changed an SNMP setting by itself')).toBeNull()
  })

  it('Settings › Scanning lists the devices with SNMP, each a link to its card', async () => {
    renderApp('/settings/scanning?tab=engines', { role: 'admin' })
    const list = await screen.findByRole('list', { name: 'Devices with SNMP set up' }, T)
    expect(within(list).getByRole('link', { name: 'FW-HQ' })).toHaveAttribute('href', '/devices/a-fw01#device-snmp')
    expect(within(list).getByText('Working')).toBeInTheDocument()
    expect(screen.getByText('SNMP is set up on 1 device. Open one to edit it or check it now.')).toBeInTheDocument()
  })
})
