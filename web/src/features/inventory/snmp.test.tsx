import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp } from '@/test/render'
import { server } from '@/test/server'
import { assetsStore, auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { ensureBox } from './mocks'

// S-INV-1, D-512: SNMP credentials on Devices → Scope and sensors (/devices/setup#snmp).
vi.setConfig({ testTimeout: 30_000 })
beforeEach(() => ensureBox())
afterEach(() => { server.events.removeAllListeners() })

const BASE = `${location.origin}/api/v1/inventory`
const T = { timeout: 5000 }
const LIST = 'SNMP credentials, in the order they are tried'
async function call(method: string, path: string, body?: unknown) {
  sessionStore.set({ userId: 'u-admin' })
  const res = await fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await res.text()
  return { status: res.status, text, json: (text ? JSON.parse(text) : null) as Record<string, any> | null } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
// The setup page re-mounts its sections once right after first paint, so click again with a fresh query until the effect shows.
const clickUntil = (user: ReturnType<typeof userEvent.setup>, get: () => HTMLElement, done: () => unknown) =>
  waitFor(async () => { await user.click(get()); done() }, { timeout: 8000 })
const row = async (name: string) => {
  const list = await screen.findByRole('list', { name: LIST }, T)
  return (await within(list).findByRole('heading', { name }, T)).closest('li') as HTMLElement
}
async function runTest(user: ReturnType<typeof userEvent.setup>, name: string, ip: string) {
  await clickUntil(user, () => screen.getByRole('button', { name: `Test ${name}` }), () => screen.getByLabelText('Device IP address'))
  const li = await row(name)
  await user.type(within(li).getByLabelText('Device IP address'), ip)
  await user.click(within(li).getByRole('button', { name: 'Run test' }))
  return li
}

describe('SNMP credentials (S-INV-1, D-512)', () => {
  it('the list shows secrets only as their last 4 characters (none when shorter than 8), the scope and the answers; the API never returns a secret', async () => {
    expect((await call('POST', '/snmp', { name: 'Printers', version: 'v2c', community: 'public', scope: ['192.168.10.200/29'] })).status).toBe(201)
    const got = await call('GET', '/snmp')
    expect(got.text).not.toMatch(/ro-auth-2fe8|ro-priv-91c4|"community"|password/)
    renderApp('/devices/setup')
    const v3 = await row('Core switches (v3)')
    expect(v3).toHaveTextContent('vedette-ro')
    expect(v3).toHaveTextContent('SHA-256, ••••2fe8')
    expect(v3).toHaveTextContent('AES-128, ••••91c4')
    expect(v3).toHaveTextContent('192.168.10.0/24')
    expect(v3).toHaveTextContent(/Last answered .*, answered by 3 devices/)
    const v2 = await row('Printers')
    expect(within(v2).getByText('••••')).toBeInTheDocument() // "public" has 6 characters: no character shown
    expect(v2).toHaveTextContent('192.168.10.200/29')
    expect(v2).toHaveTextContent('No device has answered yet')
    expect(document.body).not.toHaveTextContent(/ro-auth-2fe8|ro-priv-91c4|public\b/)
    expect(screen.getByText('Vedette tries them in this order, oldest first, until a device answers.')).toBeInTheDocument()
  })

  it('adds a v2c credential from the dialog; the row shows the last 4 characters and the scope, and the audit log has the line', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await row('Core switches (v3)')
    await clickUntil(user, () => screen.getByRole('button', { name: 'Add SNMP credential' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Add SNMP credential' }, T)
    expect(dialog).toHaveTextContent('SNMPv1, MD5 and DES are not offered: they are not secure.')
    await user.type(within(dialog).getByLabelText('Name'), 'Office switches')
    await user.type(within(dialog).getByLabelText('Community'), 'ro-community-2024')
    // D-512 (review M3): no scope, no credential: it would go to any device someone gets approved later
    await user.click(within(dialog).getByRole('button', { name: 'Add credential' }))
    expect(within(dialog).getByText(/^List the addresses or ranges of the devices this credential belongs to/)).toBeInTheDocument()
    await user.type(within(dialog).getByLabelText('Send only to'), '192.168.10.0/24, 192.168.20.5')
    await user.click(within(dialog).getByRole('button', { name: 'Add credential' }))
    const li = await row('Office switches')
    expect(li).toHaveTextContent('••••2024')
    expect(li).toHaveTextContent('192.168.10.0/24, 192.168.20.5')
    expect(document.body).not.toHaveTextContent('ro-community-2024')
    expect(auditStore.get()[0]).toMatchObject({ action: 'inventory.snmp_add', target: 'Office switches' })
  })

  it('v3: a short password, a bad user name and a public scope are refused in the browser and nothing is sent', async () => {
    let posts = 0
    server.events.on('request:start', ({ request }) => { if (request.method === 'POST' && request.url.endsWith('/inventory/snmp')) posts++ })
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await row('Core switches (v3)')
    await clickUntil(user, () => screen.getByRole('button', { name: 'Add SNMP credential' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Add SNMP credential' }, T)
    await user.click(within(dialog).getByRole('button', { name: 'v3' }))
    await user.type(within(dialog).getByLabelText('Name'), 'Firewalls')
    await user.type(within(dialog).getByLabelText('User name'), 'bad user!')
    await user.type(within(dialog).getByLabelText('Authentication password'), 'short')
    await user.type(within(dialog).getByLabelText('Privacy password'), 'long-enough-1')
    await user.type(within(dialog).getByLabelText('Send only to'), '8.8.8.8')
    await user.click(within(dialog).getByRole('button', { name: 'Add credential' }))
    expect(within(dialog).getByText('At least 8 characters.')).toBeInTheDocument()
    expect(within(dialog).getByText('Use letters, digits and . _ @ - only, up to 64 characters.')).toBeInTheDocument()
    expect(within(dialog).getByText(/^8\.8\.8\.8 is not in a local network range/)).toBeInTheDocument()
    expect(within(dialog).getByLabelText('Authentication password')).toHaveAttribute('aria-invalid', 'true')
    expect([...within(dialog).getByLabelText('Authentication').querySelectorAll('option')].map((o) => o.textContent)).toEqual(['SHA-256', 'SHA'])
    expect([...within(dialog).getByLabelText('Privacy (encryption)').querySelectorAll('option')].map((o) => o.textContent)).toEqual(['AES-128', 'None (authNoPriv)'])
    expect(posts).toBe(0)
  })

  it('Test with an answer shows what the device said, links the device and records it in the inventory', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await row('Core switches (v3)')
    const li = await runTest(user, 'Core switches (v3)', '192.168.10.3')
    const answer = await within(li).findByText('192.168.10.3 answered.', undefined, T)
    const box = answer.closest('[role="status"]') as HTMLElement
    expect(box).toHaveTextContent('Juniper Networks Junos')
    expect(box).toHaveTextContent('EX4200-48T')
    expect(box).toHaveTextContent('JUNOS 15.1R7.9')
    expect(box).toHaveTextContent('Switch')
    expect(box).toHaveTextContent('.1.3.6.1.4.1.2636.1.1.1.2.31')
    expect(within(box).getByText(/^Juniper Networks, Inc\. ex4200-48t Ethernet Switch/).tagName).toBe('PRE')
    expect(box).toHaveTextContent('Recorded in the inventory with source SNMP.')
    expect(within(box).getByRole('link', { name: 'Open the device' })).toHaveAttribute('href', '/devices/a-sw01')
    const sw = assetsStore.get().find((a) => a.id === 'a-sw01')!
    expect(sw.os).toMatchObject({ value: 'JUNOS 15.1R7.9', source: 'snmp' })
    expect(auditStore.get()[0]).toMatchObject({ action: 'inventory.snmp_test', target: 'Core switches (v3)', detail: '192.168.10.3: ok' })
  })

  it('Test with a wrong community shows the plain no-answer reason; a bad IP is refused in the browser', async () => {
    expect((await call('POST', '/snmp', { name: 'Old community', version: 'v2c', community: 'wrong-community', scope: ['192.168.10.0/24'] })).status).toBe(201)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await row('Old community')
    const li = await runTest(user, 'Old community', '192.168.10.300')
    expect(within(li).getByText('Enter an IPv4 address, like 192.168.10.3.')).toBeInTheDocument()
    await user.clear(within(li).getByLabelText('Device IP address'))
    await user.type(within(li).getByLabelText('Device IP address'), '192.168.10.3')
    await user.click(within(li).getByRole('button', { name: 'Run test' }))
    const alert = await within(li).findByRole('alert', undefined, T)
    expect(alert).toHaveTextContent('192.168.10.3 was not read.')
    expect(alert).toHaveTextContent('No answer from 192.168.10.3 on UDP 161 within 2 s (sent twice).')
    expect(alert).toHaveTextContent('a device ignores a wrong community instead of saying so')
  })

  it('the mock API: name_taken and too_many are 409; v1, MD5, DES and public scope are refused; Test explains a device that is not approved', async () => {
    const v2 = (name: string) => ({ name, version: 'v2c', community: 'community-1', scope: ['192.168.10.0/24'] })
    expect((await call('POST', '/snmp', v2('core SWITCHES (V3)'))).json?.error.code).toBe('name_taken')
    expect((await call('POST', '/snmp', { ...v2('x'), scope: [] })).json?.error.code).toBe('scope_required')
    expect((await call('POST', '/snmp', { ...v2('x'), version: 'v1' })).json?.error.code).toBe('bad_version')
    expect((await call('POST', '/snmp', { name: 'x', version: 'v3', username: 'u', auth: 'md5', auth_password: '12345678', scope: ['192.168.10.1'] })).json?.error.code).toBe('bad_auth')
    expect((await call('POST', '/snmp', { name: 'x', version: 'v3', username: 'u', auth: 'sha', auth_password: '12345678', priv: 'des', scope: ['192.168.10.1'] })).json?.error.code).toBe('bad_priv')
    expect((await call('POST', '/snmp', { ...v2('x'), scope: ['8.8.8.0/24'] })).json?.error.code).toBe('bad_scope')
    for (let i = 2; i <= 8; i++) expect((await call('POST', '/snmp', v2(`c${i}`))).status).toBe(201)
    expect((await call('POST', '/snmp', v2('c9'))).json?.error.code).toBe('too_many')
    // A blank secret on edit keeps the saved one.
    const id = (await call('GET', '/snmp')).json!.credentials[1].id
    expect((await call('PUT', `/snmp/${id}`, { name: 'c2 renamed', version: 'v2c', scope: ['192.168.10.0/24'] })).json).toMatchObject({ name: 'c2 renamed', secret_last4: 'ty-1' })
    const r = await call('POST', `/snmp/${id}/test`, { ip: '192.168.10.203' })
    expect(r.json).toMatchObject({ ok: false, reason: 'not_approved', device_id: 'a-prn03', answer: null })
    expect(r.json!.message).toContain('is not approved yet')
  })

  it('says why SNMP reads are not available, and adding still works', async () => {
    server.use(http.get('*/api/v1/inventory/snmp', () => HttpResponse.json({ credentials: [], ready: false, message: 'The scan container has not reported yet.' })))
    renderApp('/devices/setup')
    expect(await screen.findByText('The scan container has not reported yet.', undefined, T)).toBeInTheDocument()
    expect(screen.getByText('No SNMP credentials yet')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add SNMP credential' })).toBeEnabled()
  })

  it('the section does not exist while sensor-active is off, and its API is not asked', async () => {
    enableModule('sensor-active', false)
    let asked = 0
    server.events.on('request:start', ({ request }) => { if (new URL(request.url).pathname.endsWith('/inventory/snmp')) asked++ })
    renderApp('/devices/setup')
    await screen.findByRole('heading', { name: /Agents on servers/ }, T)
    expect(screen.queryByRole('heading', { name: 'SNMP credentials' })).toBeNull()
    expect(asked).toBe(0)
    expect((await call('GET', '/snmp')).status).toBe(404)
  })
})
