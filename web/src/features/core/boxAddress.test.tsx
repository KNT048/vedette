import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { linkUrl } from '@/features/response/state'

// D-465: Settings → Box network → Box address. The default is the management address; every link the box makes carries the
// address in use (approval links, the block list URL, agent install commands); the fixed name "vedette" never appears. Review M1: the
// address a change replaces keeps answering until an administrator stops it. Review M2: the agent setup says which address it uses.
vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const asAdmin = () => sessionStore.set({ userId: 'u-admin' })
async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  return { status: res.status, json: (await res.json().catch(() => null)) as Record<string, any> | null } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const links = async () => [(await call('GET', '/response/blocklist')).json!.url as string, (await call('GET', '/inventory/agents')).json!.server_url as string, linkUrl('tok123')]
const section = () => document.getElementById('box-address')!

describe('Box address: the API (D-465)', () => {
  it('defaults to the management address, and every link uses it', async () => {
    asAdmin()
    const d = (await call('GET', '/core/network')).json!
    expect(d.box_address).toEqual({ address: null, default: '192.168.10.250', previous: [], link_base: 'https://192.168.10.250:8443', self_signed: true })
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/192\.168\.10\.250:8443(\/|$)/)
  })

  it('refuses a URL, a port, a path, a space, IPv6, loopback, localhost and an all-number name; saves a name in its normal form; empty goes back', async () => {
    asAdmin()
    for (const bad of ['https://box.lan', 'box.lan:8443', 'box.lan/x', 'box lan', 'fe80::1', '127.0.0.1', '1.2.3', 'box_lan', 'localhost', 'vedette.localhost']) {
      const r = await call('PUT', '/core/network/box-address', { address: bad })
      expect([r.status, r.json?.error.code], bad).toEqual([400, 'bad_box_address'])
    }
    expect((await call('PUT', '/core/network/box-address', {})).json?.error.code).toBe('invalid') // the schema's answer, as the box gives it
    const ok = await call('PUT', '/core/network/box-address', { address: ' Vedette.Office.LAN. ' })
    expect(ok.json!.box_address).toMatchObject({ address: 'vedette.office.lan', default: '192.168.10.250', previous: [], link_base: 'https://vedette.office.lan:8443' })
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/vedette\.office\.lan:8443(\/|$)/)
    expect((await call('PUT', '/core/network/box-address', { address: '' })).json!.box_address).toMatchObject({ address: null, previous: ['vedette.office.lan'] })
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/192\.168\.10\.250:8443(\/|$)/)
  })

  it('keeps answering to the address a change replaces until it is forgotten (review M1)', async () => {
    asAdmin()
    await call('PUT', '/core/network/box-address', { address: 'a.office.lan' })
    await call('PUT', '/core/network/box-address', { address: 'b.office.lan' })
    expect((await call('PUT', '/core/network/box-address', { address: 'c.office.lan' })).json!.box_address.previous).toEqual(['a.office.lan', 'b.office.lan'])
    expect((await call('PUT', '/core/network/box-address', { address: 'a.office.lan' })).json!.box_address.previous).toEqual(['b.office.lan', 'c.office.lan'])
    expect((await call('POST', '/core/network/box-address/forget', { address: 'nas.office.lan' })).json?.error.code).toBe('not_found')
    expect((await call('POST', '/core/network/box-address/forget', { address: 'b.office.lan' })).json!.box_address.previous).toEqual(['c.office.lan'])
  })

  it('a viewer cannot change it', async () => {
    sessionStore.set({ userId: 'u-view' })
    expect((await call('PUT', '/core/network/box-address', { address: 'box.lan' })).status).toBe(403)
    expect((await call('POST', '/core/network/box-address/forget', { address: 'box.lan' })).status).toBe(403)
  })

  it('no link of the box uses the fixed name vedette', async () => {
    asAdmin()
    for (const u of await links()) expect(u, u).not.toMatch(/^https:\/\/vedette[:/]/)
    expect(JSON.stringify((await call('GET', '/honeypot/tokens')).json)).not.toMatch(/https:\/\/vedette[:/]/)
  })
})

describe('Box address: the form (D-465)', () => {
  it('shows the default, refuses a URL under the field, saves, and says how links start', async () => {
    asAdmin()
    const u = userEvent.setup()
    renderApp('/settings/network?tab=box-address')
    await screen.findByRole('heading', { name: 'Box address' }, T)
    const s = within(section())
    const input = s.getByLabelText('Host name or IP address')
    expect(input).toHaveValue('') // the default is said in words, never shown as a value or placeholder
    expect(s.getByText('Default: 192.168.10.250 (the management address)')).toBeInTheDocument()
    expect(s.getByText('Links now start with https://192.168.10.250:8443')).toBeInTheDocument() // the box's own answer, not the page's port

    await u.type(input, 'https://box.lan:8443')
    await u.click(s.getByRole('button', { name: 'Save' }))
    const err = s.getByText(/without https:\/\/ and without a port/)
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAttribute('aria-describedby', err.id)
    expect((await call('GET', '/core/network')).json!.box_address.address).toBeNull() // nothing was sent

    await u.clear(input)
    await u.type(input, 'Vedette.Office.LAN')
    expect(s.queryByText(/without https:\/\//)).toBeNull() // typing clears the error
    await u.click(s.getByRole('button', { name: 'Save' })) // from the default: nothing keeps answering in its place, no question
    await screen.findByText('Box address saved. The certificate will include it within a few seconds.', undefined, T)
    await waitFor(() => expect(within(section()).getByText('Links now start with https://vedette.office.lan:8443')).toBeInTheDocument(), T)
    expect(within(section()).getByLabelText('Host name or IP address')).toHaveValue('vedette.office.lan')
  })

  it('asks before replacing a saved address, then lists the old one with a way to stop answering to it (review M1)', async () => {
    asAdmin()
    await call('PUT', '/core/network/box-address', { address: 'old.office.lan' })
    const u = userEvent.setup()
    renderApp('/settings/network?tab=box-address')
    await screen.findByRole('heading', { name: 'Box address' }, T)
    const input = within(section()).getByLabelText('Host name or IP address')
    await waitFor(() => expect(input).toHaveValue('old.office.lan'), T)
    await u.clear(input)
    await u.type(input, 'new.office.lan')
    await u.click(within(section()).getByRole('button', { name: 'Save' }))
    const dlg = await screen.findByRole('dialog', { name: 'Change the box address?' }, T)
    expect(within(dlg).getByText(/will use new\.office\.lan instead of old\.office\.lan/)).toBeInTheDocument()
    expect(within(dlg).getByText(/the box also keeps answering to old\.office\.lan until you stop it here/)).toBeInTheDocument()
    expect((await call('GET', '/core/network')).json!.box_address.address).toBe('old.office.lan') // nothing saved before the answer
    await u.click(within(dlg).getByRole('button', { name: 'Change the address' }))
    const prev = await within(section()).findByRole('list', { name: 'Earlier box addresses still answered to' }, T)
    expect(within(prev).getByText('Also still answering to old.office.lan (agents, firewalls and links set up with it).')).toBeInTheDocument()
    await u.click(within(prev).getByRole('button', { name: 'Stop answering to old.office.lan' }))
    await screen.findByText('The box no longer answers to old.office.lan.', undefined, T)
    await waitFor(() => expect(within(section()).queryByRole('list', { name: 'Earlier box addresses still answered to' })).toBeNull(), T)
  })

  it('is read only for a viewer', async () => {
    renderApp('/settings/network?tab=box-address', { role: 'viewer' })
    await screen.findByRole('heading', { name: 'Box address' }, T)
    expect(within(section()).getByLabelText('Host name or IP address')).toBeDisabled()
    expect(within(section()).getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})

describe('Box address on the agent setup (review M2)', () => {
  it('says which address the install commands use, where to change it, and that it is not the one the page was opened at', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, enabled: true } : m)))
    const u = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
    const show = await screen.findAllByRole('button', { name: /^Show setup for / }, T)
    await u.click(show[0]!)
    const dlg = await screen.findByRole('dialog', undefined, T)
    expect(within(dlg).getByText('Install commands use https://192.168.10.250:8443.')).toBeInTheDocument()
    expect(within(dlg).getByRole('link', { name: 'Change it in Settings → Box network' })).toHaveAttribute('href', '/settings/network?tab=box-address')
    expect(within(dlg).getByText(`You opened Vedette at ${location.hostname}, but agents will use 192.168.10.250.`)).toBeInTheDocument()
  })
})
