import { describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp } from '@/test/render'
import { sessionStore } from '@/mocks/stores'
import { linkUrl } from '@/features/response/state'

// D-465: Settings → Box network → Box address. The default is the management address; every link the box makes carries the
// address in use (approval links, the block list URL, agent install commands); the fixed name "vedette" never appears.
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
    expect(d.box_address).toEqual({ address: null, default: '192.168.10.250' })
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/192\.168\.10\.250:8443(\/|$)/)
  })

  it('refuses a URL, a port, a path, a space, IPv6, loopback and an all-number name; saves a name in its normal form; empty goes back', async () => {
    asAdmin()
    for (const bad of ['https://box.lan', 'box.lan:8443', 'box.lan/x', 'box lan', 'fe80::1', '127.0.0.1', '1.2.3', 'box_lan']) {
      const r = await call('PUT', '/core/network/box-address', { address: bad })
      expect([r.status, r.json?.error.code], bad).toEqual([400, 'bad_box_address'])
    }
    const ok = await call('PUT', '/core/network/box-address', { address: ' Vedette.Office.LAN. ' })
    expect(ok.json!.box_address).toEqual({ address: 'vedette.office.lan', default: '192.168.10.250' })
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/vedette\.office\.lan:8443(\/|$)/)
    expect((await call('PUT', '/core/network/box-address', { address: '' })).json!.box_address.address).toBeNull()
    for (const u of await links()) expect(u, u).toMatch(/^https:\/\/192\.168\.10\.250:8443(\/|$)/)
  })

  it('a viewer cannot change it', async () => {
    sessionStore.set({ userId: 'u-view' })
    expect((await call('PUT', '/core/network/box-address', { address: 'box.lan' })).status).toBe(403)
  })

  it('no link of the box uses the fixed name vedette', async () => {
    asAdmin()
    for (const u of await links()) expect(u, u).not.toMatch(/^https:\/\/vedette[:/]/)
    expect(JSON.stringify((await call('GET', '/honeypot/tokens')).json)).not.toMatch(/https:\/\/vedette[:/]/)
  })
})

describe('Box address: the form (D-465)', () => {
  it('shows the default, refuses a URL under the field, saves, and says what links use', async () => {
    asAdmin()
    const u = userEvent.setup()
    renderApp('/settings/network')
    await screen.findByRole('heading', { name: 'Box address' }, T)
    const s = within(section())
    const input = s.getByLabelText('Host name or IP address')
    expect(input).toHaveValue('') // the default is said in words, never shown as a value or placeholder
    expect(s.getByText('Default: 192.168.10.250 (the management address)')).toBeInTheDocument()
    expect(s.getByText(/^Links now start with https:\/\/192\.168\.10\.250/)).toBeInTheDocument()

    await u.type(input, 'https://box.lan:8443')
    await u.click(s.getByRole('button', { name: 'Save' }))
    const err = s.getByText(/without https:\/\/ and without a port/)
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(input).toHaveAttribute('aria-describedby', err.id)
    expect((await call('GET', '/core/network')).json!.box_address.address).toBeNull() // nothing was sent

    await u.clear(input)
    await u.type(input, 'Vedette.Office.LAN')
    expect(s.queryByText(/without https:\/\//)).toBeNull() // typing clears the error
    await u.click(s.getByRole('button', { name: 'Save' }))
    await screen.findByText('Box address saved. The box certificate now includes it.', undefined, T)
    await waitFor(() => expect(within(section()).getByText(/^Links now start with https:\/\/vedette\.office\.lan/)).toBeInTheDocument(), T)
    expect(within(section()).getByLabelText('Host name or IP address')).toHaveValue('vedette.office.lan')
  })

  it('is read only for a viewer', async () => {
    renderApp('/settings/network', { role: 'viewer' })
    await screen.findByRole('heading', { name: 'Box address' }, T)
    expect(within(section()).getByLabelText('Host name or IP address')).toBeDisabled()
    expect(within(section()).getByRole('button', { name: 'Save' })).toBeDisabled()
  })
})
