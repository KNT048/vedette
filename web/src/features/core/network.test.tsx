import { describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { eachOption } from '@/test/formMatrix'
import { sessionStore } from '@/mocks/stores'
import { networkStore, SILENT_DEVICES } from '@/mocks/network'
import { GUIDES } from './guideData'

vi.setConfig({ testTimeout: 30_000 })
const T = { timeout: 5000 }
const user = () => userEvent.setup()
const asAdmin = () => sessionStore.set({ userId: 'u-admin' })
const BASE = `${location.origin}/api/v1/core/network`
async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await res.text()
  let json: Record<string, any> | null = null // eslint-disable-line @typescript-eslint/no-explicit-any
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: res.status, json }
}
const code = (r: { json: Record<string, any> | null }) => r.json?.error.code // eslint-disable-line @typescript-eslint/no-explicit-any
const get = async () => (await call('GET', '')).json!
const spanBody = async (patch: object = {}) => ({ ...(await get()).span, ...patch })
const goodStatic = { mode: 'static', address: '192.168.10.200', prefix: 24, gateway: '192.168.10.1', dns: ['192.168.10.1'] }
const open = async () => { renderApp('/settings/network'); await screen.findByRole('heading', { level: 1, name: 'Box network' }, T); await screen.findByRole('table', { name: 'Network interfaces of the box' }, T) }
const spanSection = () => document.getElementById('span')!

describe('box network: the API (S-CORE-8, D-56)', () => {
  it('lists the interfaces from sample data: eth0 management, eth1 SPAN receiving, eth2 unused with no link', async () => {
    asAdmin()
    const d = await get()
    expect(d.interfaces).toMatchObject([
      { name: 'eth0', role: 'management', link: true, address: '192.168.10.250/24' },
      { name: 'eth1', role: 'span', link: true, address: null },
      { name: 'eth2', role: 'unused', link: false, address: null },
    ])
    expect(d.management).toMatchObject({ mode: 'static', gateway: '192.168.10.1' })
    expect(d.span_status.verdict).toBe('ok')
    expect(d.span_status.other_macs).toBeGreaterThan(0)
    expect(d.decoy_ips).toEqual(['192.168.10.240', '192.168.10.241', '192.168.10.242'])
    expect(JSON.stringify(d)).not.toMatch(/hears/)
  })

  it('a viewer can read but every write is 403', async () => {
    sessionStore.set({ userId: 'u-view' })
    expect((await call('GET', '')).status).toBe(200)
    expect((await call('GET', '/span/status')).status).toBe(200)
    for (const [m, p, b] of [['PUT', '/interfaces', { roles: {} }], ['PUT', '/management', goodStatic], ['POST', '/management/confirm', {}], ['PUT', '/span', {}], ['PUT', '/ntp', { mode: 'default' }]] as const) expect((await call(m, p, b)).status, p).toBe(403)
  })

  it('refuses two management interfaces, moving management, and two SPAN interfaces', async () => {
    asAdmin()
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'management', eth2: 'unused' } }))).toBe('management_count')
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'unused', eth1: 'span', eth2: 'unused' } }))).toBe('management_count')
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'unused', eth1: 'management', eth2: 'unused' } }))).toBe('management_fixed')
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'span', eth2: 'span' } }))).toBe('span_count')
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'span' } }))).toBe('invalid_roles')
    expect(code(await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'span', eth2: 'boss' } }))).toBe('invalid_roles')
    expect((await get()).interfaces.map((i: { role: string }) => i.role)).toEqual(['management', 'span', 'unused']) // nothing changed
  })

  it('setting the role of the SPAN port to unused turns SPAN off; picking a port as SPAN makes it the only SPAN port', async () => {
    asAdmin()
    expect((await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'unused', eth2: 'unused' } })).status).toBe(200)
    expect((await get()).span).toMatchObject({ enabled: false, interface: null })
    expect((await call('PUT', '/span', await spanBody({ interface: 'eth2', enabled: true }))).status).toBe(200)
    expect((await get()).interfaces.map((i: { role: string }) => i.role)).toEqual(['management', 'unused', 'span'])
  })

  it('SPAN on the management interface is refused; so are no port, nothing to read, bad filters and bad limits', async () => {
    asAdmin()
    expect(code(await call('PUT', '/span', await spanBody({ interface: 'eth0' })))).toBe('span_on_management')
    expect(code(await call('PUT', '/span', await spanBody({ interface: 'wlan9' })))).toBe('bad_interface')
    expect(code(await call('PUT', '/span', await spanBody({ interface: null, enabled: true })))).toBe('no_interface')
    expect(code(await call('PUT', '/span', await spanBody({ extract: { dns: false, tls_sni: false, http_host: false, flows: false } })))).toBe('nothing_selected')
    for (const f of [{ type: 'cidr', value: '10.0.5.0' }, { type: 'cidr', value: '10.0.0.0/4' }, { type: 'host', value: 'bad host!' }, { type: 'port', value: '70000' }, { type: 'port', value: 'http' }, { type: 'dns', value: 'x' }, { type: 'port', value: '' }]) {
      expect(code(await call('PUT', '/span', await spanBody({ filters: [f] }))), JSON.stringify(f)).toBe('bad_filter')
    }
    expect(code(await call('PUT', '/span', await spanBody({ filters: [{ type: 'port', value: '53' }, { type: 'port', value: '53' }] })))).toBe('bad_filter')
    expect(code(await call('PUT', '/span', await spanBody({ cpu_percent: 80 })))).toBe('bad_limit')
    expect(code(await call('PUT', '/span', await spanBody({ memory_mb: 64 })))).toBe('bad_limit')
    // a good save normalises the values
    const ok = await call('PUT', '/span', await spanBody({ filters: [{ type: 'cidr', value: '10.0.5.9/24' }, { type: 'host', value: 'Backup.LAN' }, { type: 'port', value: '0053' }] }))
    expect(ok.json!.span.filters).toEqual([{ type: 'cidr', value: '10.0.5.0/24' }, { type: 'host', value: 'backup.lan' }, { type: 'port', value: '53' }])
  })

  it('health verdicts: ok, only own traffic, nothing arriving, no cable, off', async () => {
    asAdmin()
    const verdict = async (patch: object) => { await call('PUT', '/span', await spanBody(patch)); return (await call('GET', '/span/status')).json! }
    expect((await verdict({})).verdict).toBe('ok')
    const none = await verdict({ interface: 'eth2' })
    expect(none).toMatchObject({ verdict: 'no_link', packets_per_s: 0, other_macs: 0, last_packet_at: null })
    networkStore.update((s) => ({ ...s, ifaces: s.ifaces.map((i) => (i.name === 'eth2' ? { ...i, link: true } : i)) }))
    expect((await call('GET', '/span/status')).json!.verdict).toBe('no_traffic')
    networkStore.update((s) => ({ ...s, ifaces: s.ifaces.map((i) => (i.name === 'eth2' ? { ...i, hears: 'own' } : i)) }))
    expect(await call('GET', '/span/status').then((r) => r.json!)).toMatchObject({ verdict: 'own_only', other_macs: 0 })
    expect((await verdict({ enabled: false })).verdict).toBe('off')
  })

  it('DHCP takes no static fields; an address change needs confirm, runs a 2 minute timer, reverts unless confirmed', async () => {
    asAdmin()
    expect(code(await call('PUT', '/management', { mode: 'dhcp', address: '192.168.10.9' }))).toBe('dhcp_no_static')
    expect(code(await call('PUT', '/management', { mode: 'dhcp', dns: ['1.1.1.1'] }))).toBe('dhcp_no_static')
    for (const bad of [{ address: '300.1.1.1' }, { address: '192.168.10.0' }, { address: '192.168.10.255' }, { prefix: 31 }, { gateway: '192.168.10.200' }, { dns: [] }, { dns: ['a.b'] }, { dns: ['1.1.1.1', '1.1.1.1'] }, { gateway: undefined }]) {
      expect(code(await call('PUT', '/management', { ...goodStatic, ...bad })), JSON.stringify(bad)).toBe('invalid_static')
    }
    const outside = await call('PUT', '/management', { ...goodStatic, gateway: '10.9.9.9' })
    expect(outside.status).toBe(400)
    expect(outside.json!.error).toMatchObject({ code: 'gateway_outside_subnet', message: 'The gateway must be inside the address range you entered.' })
    expect(code(await call('PUT', '/management', { ...goodStatic, address: '192.168.10.241' }))).toBe('ip_in_use') // a decoy
    expect(code(await call('PUT', '/management', { ...goodStatic, address: '192.168.10.10' }))).toBe('ip_in_use') // an inventory device
    const first = await call('PUT', '/management', goodStatic)
    expect(first.status).toBe(409)
    expect(first.json!.error).toMatchObject({ code: 'confirm_required', new_ip: '192.168.10.200' })
    expect(first.json!.error.message).toContain('Open https://192.168.10.200:8443 within 5 minutes and confirm, or the box returns to the old settings.')
    expect(first.json!.error.message).toContain('You will need to sign in again at the new address')
    expect((await get()).management.address).toBe('192.168.10.250') // nothing applied yet
    const applied = await call('PUT', '/management', { ...goodStatic, confirm: true })
    expect(applied.status).toBe(200)
    expect(applied.json!.management.address).toBe('192.168.10.200')
    expect(applied.json!.pending.previous_address).toBe('192.168.10.250')
    expect(Math.round((new Date(applied.json!.pending.expires_at).getTime() - Date.now()) / 1000)).toBeGreaterThan(295)
    expect(applied.json!.pending.window_s).toBe(300)
    expect(code(await call('PUT', '/management', { ...goodStatic, address: '192.168.10.201', confirm: true }))).toBe('change_pending')
    expect((await call('POST', '/management/confirm')).json!.pending).toBeNull()
    expect((await get()).management.address).toBe('192.168.10.200')
    expect(code(await call('POST', '/management/confirm'))).toBe('nothing_pending')
  })

  it('an unconfirmed change goes back to the old settings after the window, and so does Cancel', async () => {
    asAdmin()
    await call('PUT', '/management', { ...goodStatic, confirm: true })
    networkStore.update((s) => ({ ...s, pending: { ...s.pending!, expires_at: new Date(Date.now() - 1000).toISOString() } }))
    const d = await get()
    expect(d.pending).toBeNull()
    expect(d.management.address).toBe('192.168.10.250')
    await call('PUT', '/management', { ...goodStatic, confirm: true })
    networkStore.update((s) => ({ ...s, pending: { ...s.pending!, expires_at: new Date(Date.now() - 1000).toISOString() } }))
    expect(code(await call('POST', '/management/confirm'))).toBe('nothing_pending') // too late: reverted
    await call('PUT', '/management', { ...goodStatic, confirm: true })
    expect((await call('POST', '/management/revert')).json!.management.address).toBe('192.168.10.250')
    expect(code(await call('POST', '/management/revert'))).toBe('nothing_pending')
  })

  it('DNS alone changes at once without a confirm step; DHCP asks for confirm and keeps no static fields', async () => {
    asAdmin()
    const r = await call('PUT', '/management', { ...goodStatic, address: '192.168.10.250', dns: ['192.168.10.2', '192.168.10.1'] })
    expect(r.status).toBe(200)
    expect(r.json!.pending).toBeNull()
    expect(r.json!.management.dns).toEqual(['192.168.10.2', '192.168.10.1'])
    expect(code(await call('PUT', '/management', { mode: 'dhcp' }))).toBe('confirm_required')
    const d = await call('PUT', '/management', { mode: 'dhcp', confirm: true })
    expect(d.json!.management.mode).toBe('dhcp')
  })

  it('NTP: default takes no servers; custom needs 1 to 4 valid ones', async () => {
    asAdmin()
    expect(code(await call('PUT', '/ntp', { mode: 'default', servers: ['a.example'] }))).toBe('default_no_servers')
    for (const servers of [[], ['a b'], ['x', 'x'], ['a.example', 'b.example', 'c.example', 'd.example', 'e.example'], ['999.1.1.1-']]) expect(code(await call('PUT', '/ntp', { mode: 'custom', servers })), JSON.stringify(servers)).toBe('bad_ntp')
    expect(code(await call('PUT', '/ntp', { mode: 'both' }))).toBe('invalid_mode')
    const ok = await call('PUT', '/ntp', { mode: 'custom', servers: ['NTP.Company.LAN'] })
    expect(ok.json!.ntp).toEqual({ mode: 'custom', servers: ['ntp.company.lan'] })
    expect((await call('PUT', '/ntp', { mode: 'default' })).json!.ntp).toEqual({ mode: 'default', servers: [] })
  })

  it('privacy flow 10 follows NTP: on for the public pool, off for internal addresses only', async () => {
    asAdmin()
    const flow10 = async () => (await (await fetch(`${location.origin}/api/v1/core/privacy`)).json()).flows.find((f: { id: number }) => f.id === 10)
    expect(await flow10()).toMatchObject({ state: 'on' })
    await call('PUT', '/ntp', { mode: 'custom', servers: ['192.168.10.1'] })
    expect(await flow10()).toMatchObject({ state: 'off' })
    await call('PUT', '/ntp', { mode: 'custom', servers: ['192.168.10.1', 'time.google.com'] })
    expect(await flow10()).toMatchObject({ state: 'on' })
  })

  it('audit log gets an entry for every change', async () => {
    asAdmin()
    await call('PUT', '/span', await spanBody({ cpu_percent: 30 }))
    await call('PUT', '/ntp', { mode: 'default' })
    await call('PUT', '/management', { ...goodStatic, confirm: true })
    await call('POST', '/management/revert')
    const rows = (await (await fetch(`${location.origin}/api/v1/core/audit`)).json()).items as { action: string }[]
    for (const a of ['network.span', 'network.ntp', 'network.management', 'network.management_reverted']) expect(rows.map((r) => r.action)).toContain(a)
  })
})

describe('box network: the page', () => {
  it('shows interfaces, management, SPAN status, guides, decoys and NTP with no a11y violations', async () => {
    await open()
    const table = screen.getByRole('table', { name: 'Network interfaces of the box' })
    expect(within(table).getByText('192.168.10.250/24')).toBeInTheDocument()
    expect(within(table).getByText('02:42:ac:11:00:a1')).toBeInTheDocument()
    expect(within(table).getByText('No cable signal'.replace('No cable signal', 'No link'))).toBeInTheDocument()
    expect(screen.getByText(/The web app never runs shell commands/)).toBeInTheDocument()
    expect(await within(spanSection()).findByText('Receiving mirrored traffic', undefined, T)).toBeInTheDocument()
    expect(within(spanSection()).getByText('Packet contents are never stored.')).toBeInTheDocument()
    const decoys = screen.getByRole('list', { name: 'Decoy addresses' })
    expect(within(decoys).getAllByRole('listitem')).toHaveLength(3)
    expect(screen.getByRole('link', { name: 'Change them in Internal traps' })).toHaveAttribute('href', '/honeypot')
    expect(screen.getByText(/Asking a public pool for the time is a data flow/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('is in the settings menu for everyone; a viewer sees everything read-only', async () => {
    renderApp('/settings/network', { role: 'viewer' })
    await screen.findByRole('table', { name: 'Network interfaces of the box' }, T)
    expect(screen.getByRole('link', { name: 'Box network' })).toBeInTheDocument()
    expect(screen.getByText(/You can view this section but not change it/)).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Role of eth1' })).toBeDisabled()
    for (const l of ['How to get its address'.replace('How to get its address', 'How the box gets its address'), 'Capture port', 'Time source']) expect(screen.getByLabelText(l)).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Capture mirrored traffic' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save management settings' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Save SPAN settings' })).toBeDisabled()
    await expectNoA11yViolations()
  })

  describe('form matrix: interface role selector', () => {
    it('each role shows only what belongs to it, and two management ports are refused', async () => {
      const u = user()
      await open()
      const table = screen.getByRole('table', { name: 'Network interfaces of the box' })
      const eth2 = () => within(table).getByRole('combobox', { name: 'Role of eth2' })
      await eachOption([
        { option: 'unused', hidden: [/Exactly one interface must be/], shown: [/Listen only|No IP address \(listen only\)/] }, // eth1 is still the SPAN port
        { option: 'span', shown: ['No IP address (listen only)', 'Capture port'], hidden: [/Exactly one interface/] },
        { option: 'management', shown: [/Exactly one interface must be the management interface; you set 2/], hidden: [] },
        { option: 'unused', hidden: [/Exactly one interface must be/] },
      ], async (o) => { await u.selectOptions(eth2(), o) })
      expect((await get()).interfaces.find((i: { name: string }) => i.name === 'eth2').role).toBe('unused')
      // the management row has no selector at all
      expect(within(table).queryByRole('combobox', { name: 'Role of eth0' })).not.toBeInTheDocument()
    })
  })

  describe('form matrix: management DHCP or static', () => {
    it('static shows address, prefix, gateway and DNS; DHCP shows none of them; nothing leaks across', async () => {
      const u = user()
      await open()
      const form = document.getElementById('management')!
      const fields = ['IP address', 'Prefix length', 'Gateway', 'DNS servers']
      expect(within(form).getByLabelText('IP address')).toHaveValue('192.168.10.250')
      const mode = within(form).getByLabelText('How the box gets its address')
      await eachOption([
        { option: 'dhcp', shown: [/come from your DHCP server/], hidden: fields },
        { option: 'static', shown: fields, hidden: [/come from your DHCP server/] },
        { option: 'dhcp', shown: [/come from your DHCP server/], hidden: fields },
      ], async (o) => { await u.selectOptions(mode, o) }, form)
      await u.selectOptions(mode, 'static')
      for (const f of fields.slice(0, 1).concat(fields.slice(2))) expect(within(form).getByLabelText(f), `${f} does not carry over`).toHaveValue('') // the old address is gone, not leaked
      expect(within(form).getByLabelText('Prefix length')).toHaveValue(24)
      // Static with nothing typed is refused by the server and the message shows
      await u.click(within(form).getByRole('button', { name: 'Save management settings' }))
      expect(await within(form).findByRole('alert', undefined, T)).toHaveTextContent('The IP address must be an IPv4 address')
      // DHCP: the save asks to confirm (the address changes) and sends no static field
      await u.selectOptions(mode, 'dhcp')
      await u.click(within(form).getByRole('button', { name: 'Save management settings' }))
      expect(await screen.findByRole('dialog', { name: 'Change the management address?' }, T)).toBeInTheDocument()
    })
  })

  describe('form matrix: SPAN extraction toggles', () => {
    it('each switch adds or removes its own item from the reading line and the last one cannot be turned off for a running capture', async () => {
      const u = user()
      await open()
      const group = within(spanSection()).getByRole('group', { name: 'What Vedette reads' })
      const names = ['DNS queries', 'TLS server names', 'HTTP hosts', 'Connection metadata']
      const sw = (n: string) => within(group).getByRole('switch', { name: n })
      const cases = names.flatMap((n) => [
        { option: n, hidden: [new RegExp(`Reading: .*${n}`)] }, // turned off
        { option: n, shown: [new RegExp(`Reading: .*${n}`)] }, // turned on again
      ])
      await eachOption(cases, async (o) => { await u.click(sw(o)) }, group)
      for (const n of names) await u.click(sw(n))
      expect(within(group).getByText(/Nothing selected/)).toBeInTheDocument()
      await u.click(within(spanSection()).getByRole('button', { name: 'Save SPAN settings' }))
      expect(await within(spanSection()).findByRole('alert', undefined, T)).toHaveTextContent('Choose at least one thing to read')
      expect(within(group).getByText('Packet contents are never stored.')).toBeInTheDocument()
    })
  })

  describe('form matrix: exclusion filter type', () => {
    it('each type shows its own label and hint, clears the typed value, and bad values are refused', async () => {
      const u = user()
      await open()
      const sec = within(spanSection())
      const type = sec.getByLabelText('Exclude by')
      const hint = { cidr: /With the prefix length/, host: /An IPv4 address or a name/, port: /A number from 1 to 65535/ }
      const label = { cidr: 'Network range', host: 'Host', port: 'Port number' }
      for (const o of ['host', 'port', 'cidr', 'port'] as const) {
        await u.selectOptions(type, o)
        expect(sec.getByLabelText(label[o]), `${o}: its field`).toBeInTheDocument()
        expect(sec.getByText(hint[o])).toBeInTheDocument()
        for (const other of ['cidr', 'host', 'port'] as const) if (other !== o) expect(sec.queryByText(hint[other]), `${o}: hint of ${other} hidden`).not.toBeInTheDocument()
        expect(sec.getByLabelText(label[o])).toHaveValue('') // nothing leaks from the previous type
        await u.type(sec.getByLabelText(label[o]), 'leftover')
      }
      await u.selectOptions(type, 'cidr')
      await u.type(sec.getByLabelText('Network range'), '10.0.5.0')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      expect(sec.getByText(/is not a network range/)).toBeInTheDocument()
      await u.clear(sec.getByLabelText('Network range'))
      await u.type(sec.getByLabelText('Network range'), '10.0.5.0/24')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      await u.selectOptions(type, 'port')
      await u.type(sec.getByLabelText('Port number'), '99999')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      expect(sec.getByText(/is not a port/)).toBeInTheDocument()
      await u.clear(sec.getByLabelText('Port number'))
      await u.type(sec.getByLabelText('Port number'), '5353')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      await u.selectOptions(type, 'host')
      await u.type(sec.getByLabelText('Host'), 'bad host!')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      expect(sec.getByText(/is not a host/)).toBeInTheDocument()
      await u.clear(sec.getByLabelText('Host'))
      await u.type(sec.getByLabelText('Host'), 'Backup.lan')
      await u.click(sec.getByRole('button', { name: 'Add exclusion' }))
      await u.click(sec.getByRole('button', { name: 'Save SPAN settings' }))
      await waitFor(async () => expect((await get()).span.filters).toHaveLength(4), T)
      expect((await get()).span.filters).toEqual([{ type: 'cidr', value: '192.168.10.0/28' }, { type: 'cidr', value: '10.0.5.0/24' }, { type: 'port', value: '5353' }, { type: 'host', value: 'backup.lan' }])
      await u.click(screen.getByRole('button', { name: 'Remove exclusion 5353' }))
      expect(screen.queryByText('5353')).not.toBeInTheDocument()
    })
  })

  it('persona: "I plugged the mirror into eth1, make Vedette use it and check it receives traffic"', async () => {
    const u = user()
    asAdmin()
    // a clean box: eth1 is plugged in but unused
    await call('PUT', '/span', await spanBody({ enabled: false }))
    await call('PUT', '/interfaces', { roles: { eth0: 'management', eth1: 'unused', eth2: 'unused' } })
    await open()
    const sec = () => within(spanSection())
    expect(await sec().findByText('SPAN is off')).toBeInTheDocument()
    // wrong port first: eth2 has no cable
    await u.selectOptions(sec().getByLabelText('Capture port'), 'eth2')
    await u.click(sec().getByRole('switch', { name: 'Capture mirrored traffic' }))
    await u.click(sec().getByRole('button', { name: 'Save SPAN settings' }))
    await waitFor(() => expect(sec().queryByRole('alert')?.textContent ?? 'ok').toBe('ok'), T)
    expect(await sec().findByText('No cable signal', undefined, T)).toBeInTheDocument()
    expect(sec().getByText(/Check the cable and that the switch port is on/)).toBeInTheDocument()
    // the management port is not offered
    expect(sec().getByRole('option', { name: /eth0 \(management\)/ })).toBeDisabled()
    await u.selectOptions(sec().getByLabelText('Capture port'), 'eth1')
    await u.click(sec().getByRole('button', { name: 'Save SPAN settings' }))
    expect(await sec().findByText('Receiving mirrored traffic', undefined, T)).toBeInTheDocument()
    expect(sec().getByText('Packets per second')).toBeInTheDocument()
    expect(sec().getByText('Other devices seen (MAC addresses)')).toBeInTheDocument()
    // the interfaces table agrees
    const row = within(screen.getByRole('table', { name: 'Network interfaces of the box' })).getByRole('combobox', { name: 'Role of eth1' })
    expect(row).toHaveValue('span')
  })

  it('persona: eth1 with a link but only the box\'s own packets says the switch is not mirroring', async () => {
    asAdmin()
    networkStore.update((s) => ({ ...s, ifaces: s.ifaces.map((i) => (i.name === 'eth1' ? { ...i, hears: 'own' } : i)) }))
    await open()
    expect(await within(spanSection()).findByText("Only the box's own traffic", undefined, T)).toBeInTheDocument()
    expect(within(spanSection()).getByText(/The switch is not mirroring other ports/)).toBeInTheDocument()
  })

  it('persona: "change the management IP": confirm step, countdown, confirm from the new address', async () => {
    const u = user()
    await open()
    const form = within(document.getElementById('management')!)
    fireEvent.change(form.getByLabelText('IP address'), { target: { value: '192.168.10.200' } })
    await u.click(form.getByRole('button', { name: 'Save management settings' }))
    const dlg = await screen.findByRole('dialog', { name: 'Change the management address?' }, T)
    expect(dlg).toHaveTextContent('You will lose this page. Open https://192.168.10.200:8443 within 5 minutes and confirm, or the box returns to the old settings.')
    expect(dlg).toHaveTextContent('You will need to sign in again at the new address')
    expect((await get()).management.address).toBe('192.168.10.250') // not applied until the button
    await u.click(within(dlg).getByRole('button', { name: 'Apply and start the 5-minute timer' }))
    const banner = await screen.findByRole('status', undefined, T)
    expect(banner).toHaveTextContent('Waiting for you to confirm at 192.168.10.200')
    expect(banner).toHaveTextContent(/Time left: 4:5\d|Time left: 5:00/)
    expect(form.getByLabelText('IP address')).toBeDisabled() // no second change while one is pending
    await expectNoA11yViolations()
    await u.click(within(banner).getByRole('button', { name: 'Confirm: I opened the new address' }))
    await waitFor(() => expect(screen.queryByRole('status')).not.toBeInTheDocument(), T)
    expect((await get()).management.address).toBe('192.168.10.200')
    expect(form.getByLabelText('IP address')).toHaveValue('192.168.10.200')
  })

  it('cancelling the pending change goes back to the old address at once', async () => {
    const u = user()
    asAdmin()
    await call('PUT', '/management', { ...goodStatic, confirm: true })
    await open()
    await u.click(await screen.findByRole('button', { name: 'Cancel and go back now' }, T))
    await waitFor(() => expect(document.getElementById('management-title')).toBeInTheDocument(), T)
    await waitFor(() => expect(within(document.getElementById('management')!).getByLabelText('IP address')).toHaveValue('192.168.10.250'), T)
  })

  it('NTP form: the default pool hides the server field, your own servers show it; saving internal servers turns flow 10 off', async () => {
    const u = user()
    await open()
    const sec = within(document.getElementById('ntp')!)
    const mode = sec.getByLabelText('Time source')
    await eachOption([
      { option: 'custom', shown: ['NTP servers'], hidden: [/asks the public pool/] },
      { option: 'default', shown: [/asks the public pool/], hidden: ['NTP servers'] },
      { option: 'custom', shown: ['NTP servers'], hidden: [/asks the public pool/] },
    ], async (o) => { await u.selectOptions(mode, o) }, document.getElementById('ntp')!)
    await u.click(sec.getByRole('button', { name: 'Save' }))
    expect(await sec.findByRole('alert', undefined, T)).toHaveTextContent('Give 1 to 4 NTP servers.')
    await u.type(sec.getByLabelText('NTP servers'), '192.168.10.1, ntp.company.lan')
    await u.click(sec.getByRole('button', { name: 'Save' }))
    await waitFor(async () => expect((await get()).ntp).toEqual({ mode: 'custom', servers: ['192.168.10.1', 'ntp.company.lan'] }), T)
  })

  it('every switch type has a guide with commands or steps, a source link and an honest check label', async () => {
    const u = user()
    await open()
    const sec = within(document.getElementById('guides')!)
    expect(sec.getByText(/Choose a switch above to see the exact steps and commands/)).toBeInTheDocument()
    expect(sec.queryByRole('link', { name: /Source page/ })).not.toBeInTheDocument()
    const pick = sec.getByLabelText('Switch or device')
    for (const g of GUIDES) {
      await u.selectOptions(pick, g.id)
      expect(sec.getByRole('heading', { level: 3, name: g.vendor })).toBeInTheDocument()
      expect(sec.getByText(g.check === 'vendor' ? 'Checked against vendor documentation' : g.check === 'partial' ? 'Partly verified, test on your model' : 'General guidance, no single source')).toBeInTheDocument()
      if (g.source) expect(sec.getByRole('link', { name: /Source page/ })).toHaveAttribute('href', g.source)
      else expect(sec.queryByRole('link', { name: /Source page/ })).not.toBeInTheDocument()
      for (const c of g.commands ?? []) expect(sec.getByText(c.label)).toBeInTheDocument()
      expect(sec.getByText(/destination is the port plugged into eth1/)).toBeInTheDocument()
    }
    expect(GUIDES.map((g) => g.id)).toEqual(['cisco', 'aruba-cx', 'aruba-switch', 'mikrotik', 'omada', 'unifi', 'fortiswitch', 'tap'])
    expect(GUIDES.every((g) => g.commands?.length || g.steps?.length)).toBe(true)
    await u.selectOptions(pick, 'mikrotik')
    expect(sec.getByText('RouterOS 7.15 and newer')).toBeInTheDocument()
    expect(document.body.textContent).toMatch(/set switch1 mirror-target=ether8/)
    await expectNoA11yViolations()
  })
})

describe('box network: what the host can refuse (D-99, D-100, D-101)', () => {
  it('another device already answers for the address: said after the confirm, nothing waits', async () => {
    asAdmin()
    const r = await call('PUT', '/management', { ...goodStatic, address: SILENT_DEVICES[0], confirm: true })
    expect(r.status).toBe(409)
    expect(r.json!.error).toMatchObject({ code: 'address_conflict', message: 'Another device already uses this address.' })
    expect((await get()).pending).toBeNull()
    expect((await get()).management.address).toBe('192.168.10.250')
  })

  it('a box the installer did not set up refuses every change with one sentence', async () => {
    asAdmin()
    networkStore.update((s) => ({ ...s, unsupported: true }))
    const sentence = "This box's network files were not set up by the Vedette installer, so Vedette cannot change them. Reinstall with the installer or change the network on the box itself."
    for (const [path, body] of [['/management', { ...goodStatic, confirm: true }], ['/management', { ...goodStatic, address: '192.168.10.250', dns: ['9.9.9.9'] }], ['/ntp', { mode: 'custom', servers: ['ntp.example.com'] }], ['/span', { ...(await spanBody()), interface: 'eth2' }], ['/interfaces', { roles: { eth0: 'management', eth1: 'unused', eth2: 'unused' } }]] as const) {
      const r = await call('PUT', path, body)
      expect(r.status, path).toBe(409)
      expect(r.json!.error, path).toMatchObject({ code: 'net_backend_unsupported', message: sentence })
    }
    expect((await get()).management.address).toBe('192.168.10.250')
  })

  it('DHCP does not know the new address: the question has new_ip null and says where to look', async () => {
    asAdmin()
    const r = await call('PUT', '/management', { mode: 'dhcp' })
    expect(r.status).toBe(409)
    expect(r.json!.error.code).toBe('confirm_required')
    expect(r.json!.error.new_ip).toBeNull()
    expect(r.json!.error.message).toContain('Find the new address your DHCP server gives the box')
  })

  it('persona: "I switch to DHCP": the dialog sends me to the DHCP server, not to an address made up here', async () => {
    const u = user()
    await open()
    const form = within(document.getElementById('management')!)
    await u.selectOptions(form.getByLabelText('How the box gets its address'), 'dhcp')
    await u.click(form.getByRole('button', { name: 'Save management settings' }))
    const dlg = await screen.findByRole('dialog', { name: 'Change the management address?' }, T)
    expect(dlg).toHaveTextContent('Your DHCP server picks the new address')
    expect(dlg).not.toHaveTextContent('https://')
    expect(dlg).toHaveTextContent('do nothing: after 5 minutes the box goes back to the old address by itself')
  })

  it('says next to the save button that a restart before the confirmation brings the old address back', async () => {
    await open()
    expect(within(document.getElementById('management')!).getByText('If the box restarts before you confirm, it comes back on the old address.')).toBeInTheDocument()
  })

  it('a revert that could not be applied shows the restart and takes the buttons away', async () => {
    asAdmin()
    networkStore.update((s) => ({ ...s, pending: { previous: s.mgmt, expires_at: new Date(Date.now() + 60_000).toISOString(), reboot_at: new Date(Date.now() + 50_000).toISOString() } }))
    await open()
    const alert = await screen.findByText('The box could not go back to the old network settings by itself', undefined, T)
    expect(alert.closest('[role="alert"]')).toHaveTextContent('The settings saved on the box are the old ones, so it comes back on 192.168.10.250.')
    expect(screen.queryByRole('button', { name: 'Cancel and go back now' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Confirm: I opened the new address' })).not.toBeInTheDocument()
  })
})

describe('box network: the rules of the host (L1)', () => {
  const put = (b: object) => call('PUT', '/management', b)
  it('refuses what the host refuses: link-local and reserved addresses, a gateway that is the network or broadcast address, bad DNS servers', async () => {
    asAdmin()
    const cases: [object, string][] = [
      [{ address: '169.254.5.5', gateway: '169.254.5.1' }, 'invalid_static'],
      [{ address: '0.1.2.3', prefix: 8, gateway: '0.1.2.1' }, 'invalid_static'],
      [{ gateway: '192.168.10.0' }, 'gateway_not_host'],
      [{ gateway: '192.168.10.255' }, 'gateway_not_host'],
      [{ dns: ['169.254.1.1'] }, 'invalid_static'],
      [{ dns: ['255.255.255.255'] }, 'invalid_static'],
      [{ dns: ['127.0.0.1'] }, 'invalid_static'],
      [{ dns: ['0.0.0.0'] }, 'invalid_static'],
    ]
    for (const [bad, want] of cases) expect(code(await put({ ...goodStatic, ...bad })), JSON.stringify(bad)).toBe(want)
    expect((await put({ ...goodStatic, gateway: '192.168.10.255' })).json!.error.message).toBe('The gateway cannot be the network or broadcast address of the range. Use the address of your router.')
    expect(code(await put({ ...goodStatic, dns: ['10.1.1.1'] }))).toBe('confirm_required') // private DNS is fine
  })
  it('NTP servers: no loopback, link-local, multicast or 0/8 addresses, no all-number names', async () => {
    asAdmin()
    for (const ip of ['127.0.0.1', '0.1.2.3', '169.254.0.1', '224.0.0.1', '255.255.255.255', '1.2.3']) expect(code(await call('PUT', '/ntp', { mode: 'custom', servers: [ip] })), ip).toBe('bad_ntp')
    expect((await call('PUT', '/ntp', { mode: 'custom', servers: ['10.1.1.1'] })).status).toBe(200)
  })
  it('the form says the previous settings, not DHCP, when the old address is unknown', async () => {
    asAdmin()
    networkStore.update((s) => ({ ...s, pending: { previous: { ...s.mgmt, address: null }, expires_at: new Date(Date.now() + 60_000).toISOString() } }))
    await open()
    expect(await screen.findByText(/the box returns to the previous settings/, undefined, T)).toBeInTheDocument()
  })
})
