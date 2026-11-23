import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { auditStore, modulesStore, sessionStore, usersStore } from '@/mocks/stores'
import { scanPoll } from './api'
import { checkPause } from './useCooldown'
import { NOTICE_VERSION } from './contract'
import { feature } from './index'
import { portLabel, riskOf } from './services'
import { fmtDateTime } from '@/lib/format'

const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
async function call(method: string, path: string, body?: unknown, role: keyof typeof USER = 'admin') {
  sessionStore.set({ userId: USER[role] })
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  return { status: res.status, json: (await res.json().catch(() => null)) as any } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const setEgress = (ip: string | null) => { if (ip) localStorage.setItem('vedette-mock-egress', ip); else localStorage.removeItem('vedette-mock-egress') }
scanPoll.ms = 2000 // the page reads every 5 s while a scan runs (#830); the tests' mock scan lasts 2 s
beforeEach(() => { setEgress(null); checkPause.seconds = 0 }) // the 30 s pause between two checks of a target is shown by its own test
afterEach(() => vi.useRealTimers())
const targetsTable = () => screen.findByRole('table', { name: 'Targets' })
const ipTable = targetsTable // the list holds domains and public IPs alike

describe('exposure: list (S-EXP-1)', () => {
  it('first sentence counts exposed admin interfaces; the table says why a target cannot be scanned; axe clean', async () => {
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: '2 admin interfaces are exposed to the Internet' })).toBeInTheDocument()
    const table = await targetsTable()
    expect(within(table).getAllByRole('row')).toHaveLength(8) // header + the three domains and the four public IPs: one list
    const demo = within(table).getByRole('row', { name: /acme-demo\.example/ })
    expect(within(demo).getByText('Awaiting ownership proof')).toBeInTheDocument()
    expect(within(demo).getByText('Needs ownership proof')).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /old-site\.example/ })).getByText('TXT record missing')).toBeInTheDocument()
    const acme = within(table).getByRole('row', { name: /^acme\.example/ })
    expect(within(acme).getByText('Ready to scan')).toBeInTheDocument()
    expect(within(acme).getByText('Domain')).toBeInTheDocument() // the type of each row
    // The IPs the box found: two valid (load balancer), one it has not seen for 26 days (expiring), one not seen for 40 days (expired).
    const ten = within(table).getByRole('row', { name: /203\.0\.113\.10/ })
    expect(within(ten).getByText('Public IP')).toBeInTheDocument()
    expect(within(ten).getByText('Ownership verified')).toBeInTheDocument()
    expect(within(ten).getByText(/^Proof until /)).toBeInTheDocument() // every IP proof says when it runs out
        const eleven = within(table).getByRole('row', { name: /203\.0\.113\.11/ })
    expect(within(eleven).getByText('Ownership verified')).toBeInTheDocument()
    expect(within(eleven).getByText('Terms not accepted')).toBeInTheDocument() // found by the box, terms not accepted yet: a small note, not a warning
    expect(within(within(table).getByRole('row', { name: /203\.0\.113\.12/ })).getByText('Expires in 4 days')).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /203\.0\.113\.55/ })).getAllByText('Verification expired').length).toBeGreaterThan(0)
    expect(screen.getByText(/Only what you have proven you own and confirmed is scanned/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('adds a domain, lowercases it and goes to its page to prove ownership there', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), 'Shop.Acme.Example')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'shop.acme.example cannot be scanned yet: awaiting ownership proof' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Ownership/ })).toHaveAttribute('aria-selected', 'true') // the proof steps are already open
    expect(screen.getByText('vedette-verify=' + (await call('GET', '/exposure/targets')).json.items.find((x: { value: string }) => x.value === 'shop.acme.example').token)).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.target_add' && a.target === 'shop.acme.example')).toBe(true)
  })

  it.each([
    ['Domain', '', /Enter a domain, for example example\.com/],
    ['Domain', 'https://acme.example/admin', /without http:\/\/, a path/],
    ['Domain', '203.0.113.5', /That is an IP address, not a domain/],
    ['Domain', 'not-a-domain', /Not a valid domain/],
    ['Domain', 'acme.example', /acme\.example is already in the list/],
    ['Public IP', '', /Enter a public IPv4 address/],
    ['Public IP', '10.0.0.5', /Private, reserved, carrier-grade NAT and IPv6 addresses cannot be scanned/],
    ['Public IP', '2001:4860:4860::8888', /Private, reserved, carrier-grade NAT and IPv6 addresses cannot be scanned/],
    ['Public IP', '203.0.113.10', /203\.0\.113\.10 is already in the list/],
  ])('rejects %s "%s" and says how to fix it', async (kind, value, message) => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.click(screen.getByRole('button', { name: kind }))
    const input = screen.getByRole('textbox', { name: kind === 'Domain' ? 'Domain' : 'Public IP address' })
    if (value) await userEvent.type(input, value)
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(message)).toBeInTheDocument()
  })

  it('API error shows the message and a retry button', async () => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the target list.' } }, { status: 503 })))
    renderApp('/exposure')
    expect(await screen.findByText('Could not read the target list.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('empty list guides the first steps', async () => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [], box_ip: { auto: true, interval_min: 60, last_run: null }, ignored: [] })))
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: 'No domain or verified public IP yet' })).toBeInTheDocument()
    expect(screen.getAllByText(/Select Add target, choose Domain or Public IP/).length).toBeGreaterThan(0)
  })

  // A row of the target list as the API sends it (the fields the list reads).
  const rowOf = (over: Record<string, unknown>) => ({ id: 't-ip', kind: 'ip', origin: 'box', value: '203.0.113.10', status: 'verified', method: 'box_egress', token: '', verified_at: '2026-11-13T06:02:00.000Z', expires_at: '2026-12-13T06:02:00.000Z', validity: 'valid', last_check: null,
    commitment: { by: 'An', at: '2026-11-13T06:02:00.000Z' }, scannable: true, blocked_reason: null, scan_state: 'ready', created_at: '2026-11-13T06:02:00.000Z', last_scan_at: '2026-11-13T06:02:00.000Z', schedule: { every: 'weekly', next_at: null, note: null }, ...over })
  const BOX = { auto: true, interval_min: 60, last_run: null, retry_in_min: null }
  // The target's own page, as the API sends it: the real sample row of the box IP with what the case changes.
  async function targetPage(over: Record<string, unknown>, gateway: unknown = null) {
    const real = (await call('GET', '/exposure/targets/xt-2')).json
    const row = { ...real, ...over }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2', () => HttpResponse.json(row)),
      http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [row], box_ip: BOX, ignored: [], gateway })),
    )
    renderApp('/exposure/xt-2?tab=exposures')
  }

  it('with no admin page, the first sentence says what is open; the row counts it and its count opens that target', async () => {
    const ip = rowOf({ latest: { subdomains: 0, ips: 1, ports: 2, admin_panels: 0, certs_expiring: 0 }, open_exposures: 2,
      open_ports: [{ ip: '203.0.113.10', port: 5060, service: 'sip' }, { ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }] })
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [ip], box_ip: BOX, ignored: [] })))
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: '2 ports are open to the Internet: SIP 5060, HTTPS 10443' })).toBeInTheDocument()
    const row = within(await targetsTable()).getByRole('row', { name: /203\.0\.113\.10/ })
    expect(within(row).getByRole('link', { name: '2 open exposures on 203.0.113.10' })).toHaveAttribute('href', '/exposure/t-ip?tab=exposures')
    // the KPI tile of open exposures goes to the one target that has some
    expect(within(screen.getByRole('list', { name: 'External exposure at a glance' })).getByRole('link', { name: /open exposures/ })).toHaveAttribute('href', '/exposure/t-ip?tab=exposures')
  })

  it('SIP is called out with "is that on purpose?" on the target that has it', async () => {
    await targetPage({ origin: 'box', latest: { subdomains: 0, ips: 1, ports: 2, admin_panels: 0, certs_expiring: 0 }, open_exposures: 2,
      open_ports: [{ ip: '203.0.113.10', port: 5060, service: 'sip' }, { ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }] })
    const open = await screen.findByRole('region', { name: '2 ports open to the Internet' })
    expect(within(open).getAllByText('Commonly attacked')).toHaveLength(1) // SIP only; HTTPS is not called out
    expect(within(open).getByRole('button', { name: 'About Commonly attacked' })).toHaveAccessibleDescription(/toll fraud/) // #824: the why is behind the chip's ⓘ
    expect(within(open).getAllByText('Is that on purpose? If not, close it on your router or firewall.')).toHaveLength(2)
    expect(within(open).getByText('answers as nginx')).toBeInTheDocument()
    // a service name from the network never finds Object.prototype
    expect([riskOf({ service: 'constructor' }), portLabel({ service: 'constructor', port: 1 })]).toEqual([null, 'constructor 1'])
  })

  it('a port only the port number names says "probably" and is attacked only "if it is" that; an unidentified port says so with its certificate names; no raw nmap names', async () => {
    await targetPage({ origin: 'box', latest: { subdomains: 0, ips: 1, ports: 6, admin_panels: 0, certs_expiring: 0 }, open_exposures: 6,
      open_ports: [
        { ip: '203.0.113.10', port: 5060, service: 'sip', ident: 'port' }, { ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx', ident: 'probed', title: 'Sign in · GitLab' },
        { ip: '203.0.113.10', port: 2000, service: 'cisco-sccp', ident: 'port' }, { ip: '203.0.113.10', port: 10022, service: 'ssh', product: 'OpenSSH 9.6p1 Ubuntu 3ubuntu13.20', ident: 'probed' },
        { ip: '203.0.113.10', port: 11080, service: 'unknown', ident: 'none', server: 'Caddy' }, { ip: '203.0.113.10', port: 11443, service: 'ssl/unknown', ident: 'none', cert_names: ['gw.example.net', 'vpn.example.net'] },
      ] })
    const open = await screen.findByRole('region', { name: '6 ports open to the Internet' })
    for (const label of ['Probably SIP 5060', 'HTTPS 10443', 'Probably Cisco SCCP (IP phones) 2000', 'SSH 10022', 'Unidentified service 11080', 'Unidentified TLS service 11443']) expect(within(open).getByText(label)).toBeInTheDocument()
    expect(within(open).queryByText(/UNKNOWN|CISCO-SCCP/)).toBeNull()
    expect(within(open).getAllByText('by port number, not confirmed')).toHaveLength(2)
    // SSH is attacked for sure; SIP only if it is SIP (the port number is all that says so)
    expect(within(open).getByText('Commonly attacked if it is SIP')).toBeInTheDocument()
    expect(within(open).getAllByText('Commonly attacked')).toHaveLength(1)
    expect(within(open).getByRole('button', { name: 'About Commonly attacked if it is SIP' })).toHaveAccessibleDescription(/could not confirm it.*toll fraud/)
    expect(within(open).getByText('certificate for gw.example.net, vpn.example.net')).toBeInTheDocument()
    expect(within(open).getByText('Server header Caddy')).toBeInTheDocument()
    expect(within(open).getByText('page title "Sign in · GitLab"')).toBeInTheDocument()
    // an older row with no ident still never shows nmap's "unknown" upper-cased
    expect([portLabel({ service: 'ssl/unknown', port: 11443 }), portLabel({ service: 'cisco-sccp', port: 2000 }), riskOf({ service: 'sip', ident: 'none' })]).toEqual(['Unidentified TLS service 11443', 'Cisco SCCP (IP phones) 2000', null])
  })

  const gwTarget = () => ({ origin: 'box', latest: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 }, open_exposures: 1, open_ports: [{ ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }] })
  it.each([
    ['known with findings', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 2 },
      'Your gateway fortigate-hq (192.168.18.1) has 2 open exploited vulnerabilities: fix these first.', /answered by your gateway, or a device it forwards them to/, '/findings?tab=open&device=d-gw'],
    ['known with one finding', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 1 },
      'Your gateway fortigate-hq (192.168.18.1) has 1 open exploited vulnerability: fix these first.', /answered by your gateway, or a device it forwards them to/, '/findings?tab=open&device=d-gw'],
    ['known without findings', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 0 },
      'Your gateway fortigate-hq (192.168.18.1) answers these ports; no open exploited vulnerability is known on it.', /on fortigate-hq does not prove the device it forwards to is safe/, null],
    ['known, named by its IP', { ip: '192.168.18.1', device_id: 'd-gw', name: '192.168.18.1', open_exploited: 1 },
      'Your gateway 192.168.18.1 has 1 open exploited vulnerability: fix these first.', /answered by your gateway, or a device it forwards them to/, '/findings?tab=open&device=d-gw'],
    ['gateway not in the device list', { ip: '192.168.18.1', device_id: null, name: null, open_exploited: 0 },
      'Your gateway (192.168.18.1) answers these ports, but it is not in your device list yet.', /Vedette cannot say what is exploited on it\. Scan your network to add it\./, null],
    ['gateway unknown', { ip: null, device_id: null, name: null, open_exploited: 0 },
      'Vedette cannot see which gateway your network uses from here.', /cannot say which device answers these ports/, null],
  ])('open ports and the gateway, %s', async (_n, gateway, text, info, href) => {
    await targetPage(gwTarget(), gateway)
    const note = await screen.findByTestId('gateway-note')
    expect(within(note).getByText(text)).toBeInTheDocument()
    expect(within(note).getByRole('button', { name: 'More about this' })).toHaveAccessibleDescription(info) // #824: the explanation is behind ⓘ
    if (href) expect(within(note).getByRole('link')).toHaveAttribute('href', href)
    else expect(within(note).queryByRole('link')).toBeNull()
  })

  // A port whose certificate names a FortiGate is tied to the FortiGate of the inventory, not to the gateway (the gateway note is
  // about the other ports, or gone when every port names its appliance); a known vendor with no device says so.
  const fortiPort = (devices: unknown) => ({ ip: '203.0.113.10', port: 11443, service: 'ssl/unknown', ident: 'none', cert_names: ['FortiGate'],
    appliance: { name: 'FortiGate', vendor: 'Fortinet', kind: 'admin_or_vpn', evidence: 'certificate', devices } })
  it.each([
    ['tied to the device', [{ device_id: 'dev-fw', name: 'Edge firewall', open_exploited: 2 }], 'Your device Edge firewall (FortiGate) has 2 open exploited vulnerabilities: fix these first.', '/devices/dev-fw'],
    ['not in the inventory', [], 'No device in your list is recognised as FortiGate, so Vedette cannot say which exploited vulnerabilities it has. If you have one, add it under Devices.', null],
    ['inventory unknown', null, null, null],
  ])('an appliance certificate on an open port, %s', async (_n, devices, line, href) => {
    const gateway = { ip: '192.168.1.1', device_id: 'd-gw', name: 'edge-router', open_exploited: 0 }
    await targetPage({ ...gwTarget(), latest: { subdomains: 0, ips: 1, ports: 2, admin_panels: 1, certs_expiring: 0 }, open_exposures: 2,
      open_ports: [{ ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }, fortiPort(devices)] }, gateway)
    const note = await screen.findByTestId('appliance-note')
    expect(within(note).getByText('Likely the FortiGate admin or SSL-VPN page: its certificate names it.')).toBeInTheDocument()
    if (line) expect(within(note).getByText(line)).toBeInTheDocument()
    if (href) expect(within(note).getByRole('link', { name: 'Open Edge firewall' })).toHaveAttribute('href', href)
    else expect(within(note).queryByRole('link')).toBeNull()
    expect(within(await screen.findByTestId('gateway-note')).getByText('Your gateway edge-router (192.168.1.1) answers the other ports; no open exploited vulnerability is known on it.')).toBeInTheDocument()
  })

  it('an appliance with more devices than the list shows says how many more', async () => {
    const port = { ...fortiPort([{ device_id: 'dev-1', name: 'Branch firewall', open_exploited: 0 }]), appliance: { ...fortiPort([]).appliance, devices: [{ device_id: 'dev-1', name: 'Branch firewall', open_exploited: 0 }], more: 4 } }
    await targetPage({ ...gwTarget(), latest: { subdomains: 0, ips: 1, ports: 1, admin_panels: 1, certs_expiring: 0 }, open_ports: [port] })
    const note = await screen.findByTestId('appliance-note')
    expect(within(note).getByText('Your device Branch firewall (FortiGate): no open exploited vulnerability is known on it.')).toBeInTheDocument()
    expect(within(note).getByText('and 4 more FortiGate devices in your list.')).toBeInTheDocument()
  })

  it('no gateway note when every open port names its appliance', async () => {
    await targetPage({ ...gwTarget(), latest: { subdomains: 0, ips: 1, ports: 1, admin_panels: 1, certs_expiring: 0 }, open_ports: [fortiPort([])] }, { ip: '192.168.1.1', device_id: null, name: null, open_exploited: 0 })
    await screen.findByTestId('appliance-note')
    expect(screen.queryByTestId('gateway-note')).toBeNull()
  })

  it('no gateway note when the server sends none', async () => {
    await targetPage(gwTarget(), null)
    await screen.findByRole('region', { name: '1 port open to the Internet' })
    expect(screen.queryByTestId('gateway-note')).toBeNull()
  })

  it('module off says where to turn it on and calls none of its API (modules.md)', async () => {
    const calls: string[] = []
    const seen = ({ request }: { request: Request }) => { if (new URL(request.url).pathname.startsWith('/api/v1/exposure/')) calls.push(request.url) }
    server.events.on('request:start', seen)
    modulesStore.update((l) => l.map((m) => (m.id === 'exposure' ? { ...m, enabled: false } : m)))
    const list = renderApp('/exposure?tab=targets')
    expect(await screen.findByText('External exposure module is off')).toBeInTheDocument()
    list.unmount()
    renderApp('/exposure/xt-1')
    expect(await screen.findByText('External exposure module is off')).toBeInTheDocument()
    server.events.removeListener('request:start', seen)
    expect(calls).toEqual([])
  })

  it('registers the sidebar entry in the right group', () => {
    expect(feature.nav?.[0]).toMatchObject({ to: '/exposure', group: 'assets', order: 20, module: 'exposure' })
  })
})

describe('exposure: a verified and confirmed domain', () => {
  it('shows subdomains, ports, admin interfaces and expiring certificates; axe clean', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('heading', { level: 1, name: 'acme.example: 8 subdomain(s), 2 admin interface(s) exposed to the Internet' })).toBeInTheDocument()
    expect(within(await screen.findByRole('table', { name: 'Subdomains found' })).getByText('vpn.acme.example')).toBeInTheDocument()
    expect(within(await screen.findByRole('table', { name: 'Ports open to the Internet' })).getAllByRole('row')).toHaveLength(9)
    const admin = await screen.findByRole('table', { name: 'Admin interfaces exposed to the Internet' })
    expect(within(admin).getByText('https://vpn.acme.example:10443')).toBeInTheDocument()
    expect(within(admin).getByText('Close now')).toBeInTheDocument()
    const certs = await screen.findByRole('table', { name: 'Certificates by expiry date' })
    expect(within(within(certs).getByRole('row', { name: /mail\.acme\.example/ })).getByText(/\d+ days left/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'Ownership' }))
    expect(screen.getByText(/Vedette re-checks the record right before every scan/)).toBeInTheDocument()
    expect(screen.getByText(/Confirmed by admin@acme\.example/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).not.toBeDisabled()
    await expectNoA11yViolations()
  })

  it('INV-27: the Surface tab lists each name with where it was found, its CNAME and the kind of each address, the counts and what was not scanned; axe clean', async () => {
    renderApp('/exposure/xt-1?tab=surface')
    const table = await screen.findByRole('table', { name: 'Names under this domain and their addresses' })
    const row = (name: RegExp) => within(table).getByRole('row', { name })
    expect(within(row(/^www\.acme\.example/)).getByText('This box')).toBeInTheDocument()
    expect(within(row(/^www\.acme\.example/)).getByText("This box's verified address: scanned")).toBeInTheDocument()
    expect(within(row(/^cdn\.acme\.example/)).getByText('acme.example.cdn.cloudflare.net')).toBeInTheDocument()
    expect(within(row(/^cdn\.acme\.example/)).getByText("Checked by name on ports 80 and 443. Accept this domain's testing terms for the deep scan of this address.")).toBeInTheDocument()
    expect(within(row(/^docs\.acme\.example/)).getByText('No address: the CNAME leads nowhere')).toBeInTheDocument()
    expect(within(row(/^docs\.acme\.example/)).getByText('Found by a common name')).toBeInTheDocument()
    expect(within(row(/^mail\.acme\.example/)).getByText('Found in the MX records')).toBeInTheDocument()
    expect(within(row(/^intranet\.acme\.example/)).getByText('Private address: never contacted')).toBeInTheDocument()
    expect(within(row(/^acme\.example/)).getByText('IPv6 is not scanned yet.')).toBeInTheDocument()
    expect(screen.queryByText(/CDN|not yours|your OK/)).not.toBeInTheDocument() // what serves a name does not matter
    expect(within(screen.getByRole('list', { name: 'Not checked on the surface' })).getByText(/Names on public addresses that are not this box's \(2 names\)/)).toBeInTheDocument()
    // a name whose lookup failed this time is kept as the last scan found it, and the Surface tab says so.
    expect(within(row(/^nas\.acme\.example/)).getByText('Lookup failed this time: shown as the last scan found it')).toBeInTheDocument()
    expect(within(screen.getByRole('list', { name: 'Not checked on the surface' })).getByText(/Names whose address lookup got no answer this time \(1 name\)/)).toBeInTheDocument()
    // the check by name went to one address of a name; the other says so.
    expect(within(row(/^mail\.acme\.example/)).getByText('Not contacted: the check by name used 203.0.113.21.')).toBeInTheDocument()
    // the tiles count names (acme.example and www share one address), the IP tile distinct addresses.
    expect(screen.getByText('Names on this box').nextSibling?.textContent).toBe('4')
    expect(screen.getByText('Names on other public addresses').nextSibling?.textContent).toBe('2')
    expect(screen.getByText('Names with IPv6 addresses (not scanned)').nextSibling?.textContent).toBe('1')
    expect(screen.getByText('IP addresses').nextSibling?.textContent).toBe('8')
    await expectNoA11yViolations()
  })

  it('INV-27: a snapshot from before the surface map says its classes show from the next scan', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    server.use(
      http.get('*/api/v1/exposure/targets/xt-1/snapshots', () => HttpResponse.json({ items: [{ id: 'sn-o', date, scanned_at: at, counts: { subdomains: 1, ips: 1, ports: 0, admin_panels: 0, certs_expiring: 0 } }] })),
      http.get('*/api/v1/exposure/targets/xt-1/snapshots/:date', () => HttpResponse.json({ id: 'sn-o', date, scanned_at: at, hosts: [{ name: 'www.acme.example', ip: '198.51.100.20' }], ports: [], admin_panels: [], certs: [],
        counts: { subdomains: 1, ips: 1, ports: 0, admin_panels: 0, certs_expiring: 0 }, services: [], templates: [], checks: [], not_checked: [], web_findings: [], greenbone: [], vulns: [], version_gaps: [] })),
    )
    renderApp('/exposure/xt-1?tab=surface')
    expect(await screen.findByText(/This scan ran before the surface map/)).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Names under this domain and their addresses' })).getByText('198.51.100.20')).toBeInTheDocument()
  })

  it('every scan picker shows the time of each scan, so two scans that fall on one calendar day read apart', async () => {
    // the box keeps a snapshot per day of its own time zone: two of them can share a day in the browser's
    const counts = { subdomains: 1, ips: 1, ports: 0, admin_panels: 0, certs_expiring: 0 }
    const items = [
      { id: 'sn-b', date: '2026-11-17', scanned_at: '2026-11-17T14:29:00.000Z', counts },
      { id: 'sn-a', date: '2026-11-16', scanned_at: '2026-11-17T01:05:00.000Z', counts },
      { id: 'sn-0', date: '2026-11-15', scanned_at: '2026-11-15T09:00:00.000Z', counts },
    ]
    server.use(
      http.get('*/api/v1/exposure/targets/xt-1/snapshots', () => HttpResponse.json({ items })),
      http.get('*/api/v1/exposure/targets/xt-1/snapshots/:date', ({ params }) => HttpResponse.json({ id: 'sn-x', date: params.date, scanned_at: items[0]!.scanned_at, hosts: [], ports: [], admin_panels: [], certs: [],
        counts, services: [], templates: [], checks: [], not_checked: [], web_findings: [], greenbone: [], vulns: [], version_gaps: [] })),
    )
    renderApp('/exposure/xt-1')
    const pickers = [await screen.findByRole('combobox', { name: 'Snapshot of' }), screen.getByLabelText('From date'), screen.getByLabelText('To date')]
    for (const pick of pickers) {
      const labels = within(pick).getAllByRole('option').map((o) => o.textContent)
      expect(labels).toEqual(items.map((i) => fmtDateTime(i.scanned_at)))
      for (const l of labels) expect(l).toMatch(/^\d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}$/)
      expect(new Set(labels).size).toBe(labels.length)
    }
  })

  it('compare defaults to the two latest days and lets you change the day', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByText(/2 added, 0 gone, 0 changed/)).toBeInTheDocument()
    const diff = screen.getByRole('table', { name: 'Changes between two scan days' })
    expect(within(diff).getByText('203.0.113.22:10443')).toBeInTheDocument()
    const from = screen.getByLabelText('From date')
    await userEvent.selectOptions(from, within(from).getAllByRole('option')[2]!)
    expect((await within(screen.getByRole('table', { name: 'Changes between two scan days' })).findAllByText('nas.acme.example')).length).toBeGreaterThan(0)
  })

  it('"Scan now" creates a new snapshot; against yesterday the new staging host shows up', async () => {
    renderApp('/exposure/xt-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect((await screen.findAllByText('Scanning acme.example')).length).toBeGreaterThan(0) // 202 at once, the phase row polls GET /exposure/scan
    expect(await screen.findByText('Scan of acme.example finished. The new result is below.', {}, { timeout: 8000 })).toBeInTheDocument()
    expect(await screen.findByRole('heading', { level: 1, name: 'acme.example: 9 subdomain(s), 3 admin interface(s) exposed to the Internet' })).toBeInTheDocument()
    expect(await screen.findByText(/4 added, 0 gone, 0 changed/)).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Changes between two scan days' })).getByText('staging.acme.example')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.scan' && a.target === 'acme.example')).toBe(true)
  })

  it('API: Scan now answers 202 with the run; GET /exposure/scan follows it; an operator stops it and nothing is saved', async () => {
    expect((await call('GET', '/exposure/scan')).json).toBeNull()
    const before = (await call('GET', '/exposure/targets/xt-1/snapshots')).json.items
    const r = await call('POST', '/exposure/targets/xt-1/scan')
    expect(r.status).toBe(202)
    expect(r.json).toMatchObject({ target_id: 'xt-1', status: 'running', phase: 'queued', snapshot_id: null, error: null })
    expect((await call('GET', '/exposure/scan', undefined, 'viewer')).json).toMatchObject({ id: r.json.id, status: 'running' })
    expect((await call('POST', '/exposure/scan/stop', undefined, 'viewer')).status).toBe(403)
    expect((await call('POST', '/exposure/scan/stop', undefined, 'operator')).json).toMatchObject({ status: 'stopped' })
    expect((await call('GET', '/exposure/targets/xt-1/snapshots')).json.items).toEqual(before)
    expect((await call('POST', '/exposure/scan/stop')).json.error.code).toBe('not_running')
  })

  it('with the Vulnerability scans module off (v1 bundles), Scan now still scans: the runner follows exposure\'s switch', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    const r = await call('POST', '/exposure/targets/xt-1/scan')
    expect(r.status).toBe(202)
    expect(r.json).toMatchObject({ target_id: 'xt-1', status: 'running' })
    expect((await call('POST', '/exposure/scan/stop', undefined, 'operator')).json).toMatchObject({ status: 'stopped' })
  })
})

describe('exposure: domain ownership = DNS TXT only', () => {
  it('unverified domain: scan locked with a reason, TXT record shown, first check not found, second found', async () => {
    renderApp('/exposure/xt-3?tab=ownership')
    expect(await screen.findByRole('heading', { level: 1, name: 'acme-demo.example cannot be scanned yet: awaiting ownership proof' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.getByText(/has no ownership proof/)).toBeInTheDocument()
    expect(screen.getByText('vedette-verify=9be41c0a77d2e358')).toBeInTheDocument()
    expect(screen.queryByText(/reverse DNS/i)).not.toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    expect(await screen.findByText(/No TXT record vedette-verify=9be41c0a77d2e358 was found\. Vedette asked acme-demo\.example/)).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    expect(await screen.findByText(/Verified with a DNS TXT record/)).toBeInTheDocument()
    // verified but not confirmed: the administrator sees the sentence beside an enabled button (the server decides about two-step)
    expect(await screen.findByRole('note', { name: 'Pressing Scan now records this confirmation' })).toBeInTheDocument()
  })

  // The main Name is "@" of the registered
  // domain for every target, the subdomain too; a subdomain gets _vedette-verify.<host> as the alternative, never its own name.
  it.each([
    ['example.com', 'Add a TXT record at @ of the DNS zone example.com.', null],
    ['git.example.com', 'Add a TXT record at @ of the DNS zone example.com, where you manage git.example.com: a record there proves git.example.com, and git.example.com itself needs no record.', '_vedette-verify.git'],
    ['a.b.example.com', 'Add a TXT record at @ of the DNS zone example.com, where you manage a.b.example.com: a record there proves a.b.example.com, and a.b.example.com itself needs no record.', '_vedette-verify.a.b'],
  ])('%s shows the Name @ of its zone', async (value, intro, alt) => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), value)
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await userEvent.click(await screen.findByRole('tab', { name: /Ownership/ }))
    expect(await screen.findByTestId('proof-host')).toHaveTextContent('@ (that is example.com)')
    expect(screen.getByText(intro)).toBeInTheDocument()
    if (alt) {
      expect(screen.getByTestId('proof-cname')).toHaveTextContent(`If you cannot add a record at @ of example.com, use the Name ${alt} instead`)
      expect(screen.getByTestId('proof-cname')).toHaveTextContent(`Not on ${value} itself if it is a CNAME`)
      expect(screen.getByTestId('proof-delegated')).toHaveTextContent(`If ${value} sits in a sub-zone of example.com whose DNS is managed separately, add the record at @ of that sub-zone instead`)
    } else {
      expect(screen.queryByTestId('proof-cname')).not.toBeInTheDocument()
      expect(screen.queryByTestId('proof-delegated')).not.toBeInTheDocument()
    }
    expect(screen.queryByText(/^git \(that is|@ \(or /)).not.toBeInTheDocument()
  })

  it('a subdomain of a verified domain says it is covered, and one Check verifies it', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), 'git.acme.example')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await userEvent.click(await screen.findByRole('tab', { name: /Ownership/ }))
    expect(await screen.findByTestId('proof-covered')).toHaveTextContent('acme.example is verified on this box and covers git.acme.example: no record is needed here. Select Check.')
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    expect(await screen.findByText(/Found the TXT record of acme\.example on acme\.example: it proves acme\.example and every name under it, git\.acme\.example included\./)).toBeInTheDocument()
  })

  it('a verified domain whose TXT record is gone cannot be scanned, in the UI and in the API', async () => {
    renderApp('/exposure/xt-5?tab=ownership')
    expect(await screen.findByRole('heading', { level: 1, name: 'old-site.example cannot be scanned yet: DNS TXT record missing' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    const r = await call('POST', '/exposure/targets/xt-5/scan')
    expect(r.status).toBe(409)
    expect(r.json.error.code).toBe('txt_missing')
    // add the record back: the next check finds it
    await userEvent.click(await screen.findByRole('button', { name: 'Check again' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'old-site.example is ready for its first scan' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).not.toBeDisabled()
  })
})

describe('exposure: public IP = only an IP this box uses to reach the Internet', () => {
  it('a typed public IP is in the list at once, never scanned until it is proved, and its proof is a token file or a reverse DNS name', async () => {
    const added = await call('POST', '/exposure/targets', { value: '198.51.100.7', kind: 'ip' })
    expect(added.status).toBe(201)
    expect(added.json).toMatchObject({ kind: 'ip', origin: 'person', status: 'unverified', blocked_reason: 'unverified', scan_state: 'unproved', method: null })
    expect(added.json.ip_proof).toMatchObject({ path: '/.well-known/vedette-verify.txt', content: added.json.token })
    expect((await call('GET', '/exposure/targets')).json.items.map((x: { value: string }) => x.value)).toContain('198.51.100.7')
    const id = added.json.id as string
    expect((await call('POST', `/exposure/targets/${id}/scan`)).json.error.code).toBe('not_verified') // not scanned until proved
    const first = await call('POST', `/exposure/targets/${id}/verify`)
    expect(first.json).toMatchObject({ verified: false })
    expect(first.json.message).toMatch(/Vedette found no proof of 198\.51\.100\.7/)
    const second = await call('POST', `/exposure/targets/${id}/verify`) // the file is served by now
    expect(second.json).toMatchObject({ verified: true, target: { status: 'verified', method: 'ip_file', origin: 'person' } })
    expect(Math.round((Date.parse(second.json.target.expires_at) - Date.parse(second.json.target.verified_at)) / 864e5)).toBe(30)
    expect(second.json.target.next_check_at).not.toBeNull()
  })

  it.each([['10.0.0.5'], ['192.168.1.9'], ['100.64.0.1'], ['2001:4860:4860::8888']])('a typed address %s that cannot be scanned from the Internet is refused', async (v) => {
    const r = await call('POST', '/exposure/targets', { value: v, kind: 'ip' })
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('ip_not_allowed')
  })

  it('an address typed as a domain is refused and points to Public IP', async () => {
    const r = await call('POST', '/exposure/targets', { value: '198.51.100.7', kind: 'domain' })
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('ip_not_allowed')
    expect(r.json.error.message).toMatch(/Choose Public IP/)
  })

  it('detects the IP the box uses and verifies it for 30 days from the sighting; detecting again renews the same target', async () => {
    setEgress('198.51.100.7')
    const a = await call('POST', '/exposure/box-ip/verify')
    expect(a.status).toBe(200)
    expect(a.json.items).toHaveLength(1)
    expect(a.json.items[0]).toMatchObject({ kind: 'ip', value: '198.51.100.7', status: 'verified', method: 'box_egress', validity: 'valid', blocked_reason: 'no_commitment' })
    expect(Math.round((Date.parse(a.json.items[0].expires_at) - Date.parse(a.json.items[0].verified_at)) / 864e5)).toBe(30)
    expect(a.json.message).toMatch(/^The box reaches the Internet via 198\.51\.100\.7\. Verified until \d{1,2} [A-Z][a-z]{2} \d{4}\.$/)
    const b = await call('POST', '/exposure/box-ip/verify')
    expect(b.status).toBe(200)
    expect(b.json.items[0].id).toBe(a.json.items[0].id)
    expect(auditStore.get().some((x) => x.action === 'exposure.verify_ok' && x.target === '198.51.100.7')).toBe(true)
    expect(auditStore.get().some((x) => x.action === 'exposure.verify_renew' && x.target === '198.51.100.7')).toBe(true)
  })

  it.each(['10.1.2.3', '192.168.0.9', '172.20.0.4', '100.64.12.5', '127.0.0.1', '169.254.1.1'])('refuses private, reserved and CGNAT result %s', async (ip) => {
    setEgress(ip)
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('not_public')
    expect(r.json.error.message).toMatch(/private, reserved or shared carrier/)
    expect((await call('GET', '/exposure/targets')).json.items.some((t: { value: string }) => t.value === ip)).toBe(false)
  })

  it('re-verify succeeds only while the box egresses through the same IP, otherwise explains what to do', async () => {
    setEgress('198.51.100.99')
    const wrong = await call('POST', '/exposure/targets/xt-4/verify')
    expect(wrong.json.verified).toBe(false)
    expect(wrong.json.message).toBe('This box currently reaches the Internet via 198.51.100.99, not 203.0.113.55. Ask your admin to route the box through 203.0.113.55 (for example switch WAN), then verify again.')
    expect(wrong.json.target.status).toBe('expired')
    setEgress('203.0.113.55')
    const ok = await call('POST', '/exposure/targets/xt-4/verify')
    expect(ok.json.verified).toBe(true)
    expect(ok.json.target).toMatchObject({ status: 'verified', validity: 'valid' })
  })

  it('verify finds the IP among several (load balancer) and renews it', async () => {
    setEgress('198.51.100.1,203.0.113.12,198.51.100.2')
    const r = await call('POST', '/exposure/targets/xt-7/verify')
    expect(r.json.verified).toBe(true)
    expect(r.json.target).toMatchObject({ value: '203.0.113.12', validity: 'valid' })
  })

  it('an expired IP cannot be scanned until the box uses it again; an expiring one is flagged at 5 days', async () => {
    expect((await call('POST', '/exposure/targets/xt-4/scan')).json.error.code).toBe('expired')
    expect((await call('GET', '/exposure/targets/xt-7')).json).toMatchObject({ status: 'verified', validity: 'expiring' })
    expect((await call('GET', '/exposure/targets/xt-4')).json).toMatchObject({ status: 'expired', validity: 'expired', blocked_reason: 'expired', scannable: false })
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ status: 'verified', validity: 'valid' })
  })

  it('limits verification attempts to 10 per hour with a clear message', async () => {
    setEgress('203.0.113.10')
    for (let i = 0; i < 10; i++) expect((await call('POST', '/exposure/targets/xt-2/verify')).status).toBe(200)
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(429)
    expect(r.json.error.message).toMatch(/Too many verification attempts \(limit 10 per hour\)/)
  })

  it('the IP page shows status, dates and the same-IP rule', async () => {
    renderApp('/exposure/xt-2?tab=ownership')
    expect(await screen.findByText('Last seen by the box')).toBeInTheDocument()
    expect(screen.getByText('Expires on')).toBeInTheDocument()
    expect(screen.getByText('Valid')).toBeInTheDocument()
    expect(screen.getByText(/Works only while this box currently reaches the Internet through 203\.0\.113\.10/)).toBeInTheDocument()
  })
})

describe('exposure: auto-detect of the box public IPs', () => {
  type State = { items: { id: string; value: string; kind: string }[]; box_ip: { auto: boolean; interval_min: number; last_run: { at: string; ok: boolean; message: string } | null } }
  const state = async () => (await call('GET', '/exposure/targets')).json as State
  const ipsOf = async () => (await state()).items.filter((t) => t.kind === 'ip').map((t) => t.value).sort()
  const clean = async () => {
    const { setDataMode } = await import('@/mocks/db')
    const { usersStore } = await import('@/mocks/stores')
    setDataMode('clean')
    usersStore.set((Object.entries(USER) as ['admin' | 'operator' | 'viewer', string][]).map(([role, id]) => ({ id, name: role, email: `${role}@x.example`, role, password: 'x', twofa: false, created_at: new Date().toISOString(), last_login: null })))
  }
  const later = (min: number) => { vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + min * 60_000) }
  const SAMPLE_IPS = ['203.0.113.10', '203.0.113.11', '203.0.113.12', '203.0.113.55']

  it('is on by default, every 60 minutes, and the response carries the settings and the last check', async () => {
    const s = await state()
    expect(s.box_ip).toMatchObject({ auto: true, interval_min: 60 })
    expect(s.box_ip.last_run).toMatchObject({ ok: true })
    expect(s.box_ip.last_run?.message).toMatch(/2 public IPs: 203\.0\.113\.10, 203\.0\.113\.11/)
  })

  it('first start: a clean install finds both IPs of a load balancer by itself, audited as system, without a click', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    expect(await ipsOf()).toEqual(['198.51.100.7', '198.51.100.8'])
    const s = await state()
    expect(s.box_ip.last_run).toMatchObject({ ok: true })
    expect(s.box_ip.last_run?.message).toMatch(/2 public IPs: 198\.51\.100\.7, 198\.51\.100\.8/)
    expect(auditStore.get().find((a) => a.action === 'exposure.auto_detect')).toMatchObject({ user: 'system', target: 'box' })
    expect(auditStore.get().filter((a) => a.action === 'exposure.verify_ok' && a.user === 'system')).toHaveLength(2)
  })

  it('INV-11: a routine run that finds nothing new writes no audit row; a change writes one, once', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    await state() // first start: both IPs added, audited
    const system = () => auditStore.get().filter((a) => a.user === 'system').map((a) => `${a.action} ${a.target}`)
    const first = system()
    expect(first.filter((a) => a.startsWith('exposure.auto_detect'))).toHaveLength(1)
    let clock = Date.now()
    const hour = () => { if (!vi.isFakeTimers()) vi.useFakeTimers({ toFake: ['Date'] }); clock += 61 * 60_000; vi.setSystemTime(clock) }
    const lastRun = async () => (await state()).box_ip.last_run!.at
    const at = await lastRun()
    hour()
    expect(await lastRun()).not.toBe(at) // it did run ...
    expect(system()).toEqual(first) // ... and said nothing: same IPs, still working
    hour(); setEgress('offline'); await state()
    expect(system()).toHaveLength(first.length + 1) // switched from working to failing: one row
    hour(); await state()
    expect(system()).toHaveLength(first.length + 1) // still failing: nothing new
    hour(); setEgress('198.51.100.7,198.51.100.8,198.51.100.9'); await state()
    expect(system()).toHaveLength(first.length + 1 + 2) // working again with a new IP: its verify_ok and one auto_detect
    expect(system().slice(0, 2).sort()).toEqual(['exposure.auto_detect box', 'exposure.verify_ok 198.51.100.9'])
  })

  it('INV-11: a person\'s click is always audited, even when nothing changed', async () => {
    const count = () => auditStore.get().filter((a) => a.action === 'exposure.verify_renew' && a.target === '203.0.113.10').length
    await call('POST', '/exposure/box-ip/verify')
    await call('POST', '/exposure/box-ip/verify')
    expect(count()).toBe(2)
  })

  it('checks again only when the interval has passed; each sighting renews the IP', async () => {
    const before = (await call('GET', '/exposure/targets/xt-2')).json.verified_at as string
    later(10) // the sample last checked 42 minutes ago
    await state()
    expect((await call('GET', '/exposure/targets/xt-2')).json.verified_at).toBe(before) // 52 of 60 minutes since the last check: not due
    later(40)
    setEgress('203.0.113.10,198.51.100.9')
    expect(await ipsOf()).toContain('198.51.100.9') // due: the new IP is added
    const after = (await call('GET', '/exposure/targets/xt-2')).json
    expect(Date.parse(after.verified_at)).toBeGreaterThan(Date.parse(before))
    expect(Math.round((Date.parse(after.expires_at) - Date.parse(after.verified_at)) / 864e5)).toBe(30)
  })

  it('manual mode: with auto-detect off nothing runs by itself, "Detect now" still works and the list is kept', async () => {
    expect((await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })).json).toMatchObject({ auto: false })
    expect(await ipsOf()).toEqual(SAMPLE_IPS)
    later(3 * 60)
    setEgress('198.51.100.9')
    expect(await ipsOf()).toEqual(SAMPLE_IPS) // three hours later and a new IP: nothing happened
    expect((await call('POST', '/exposure/box-ip/verify')).status).toBe(200)
    expect(await ipsOf()).toContain('198.51.100.9')
  })

  it('a longer interval is respected', async () => {
    await call('PUT', '/exposure/box-ip/settings', { auto: true, interval_min: 1440 })
    later(3 * 60)
    setEgress('198.51.100.9')
    expect(await ipsOf()).not.toContain('198.51.100.9')
  })

  it('turning auto-detect on checks at once, but not when it checked in the last 5 minutes', async () => {
    await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    setEgress('198.51.100.9')
    await call('PUT', '/exposure/box-ip/settings', { auto: true, interval_min: 60 }) // the last check was 40 minutes ago: runs now
    expect(await ipsOf()).toContain('198.51.100.9')
    await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    setEgress('198.51.100.10')
    await call('PUT', '/exposure/box-ip/settings', { auto: true, interval_min: 60 }) // just checked: no probe spam by toggling
    expect(await ipsOf()).not.toContain('198.51.100.10')
  })

  it('a removed IP comes back while auto-detect is on and the box still uses it; with auto-detect off it stays removed', async () => {
    expect((await call('DELETE', '/exposure/targets/xt-6')).status).toBe(204)
    expect(await ipsOf()).not.toContain('203.0.113.11')
    later(61)
    expect(await ipsOf()).toContain('203.0.113.11') // seen again at the next check
    await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    const id = (await state()).items.find((t) => t.value === '203.0.113.11')!.id
    await call('DELETE', `/exposure/targets/${id}`)
    later(3 * 60)
    expect(await ipsOf()).not.toContain('203.0.113.11')
  })

  it('an IP the box does not see expires after 30 days and is valid again as soon as it is seen', async () => {
    await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    await state() // seeds the sample at the real time
    later(31 * 1440)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ status: 'expired', validity: 'expired', scannable: false, blocked_reason: 'expired' })
    expect((await call('POST', '/exposure/box-ip/verify')).status).toBe(200)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ status: 'verified', validity: 'valid', scannable: true }) // the old commitment is kept
  })

  it('when the public IP services cannot be reached the check fails visibly and nothing is added or lost', async () => {
    setEgress('offline')
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(502)
    expect(r.json.error.code).toBe('unreachable')
    expect((await state()).box_ip.last_run).toMatchObject({ ok: false })
    expect(await ipsOf()).toEqual(SAMPLE_IPS)
  })


  it('when the three services answer but never agree, nothing is added and the check says why', async () => {
    setEgress('disagree')
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(502)
    expect(r.json.error.code).toBe('unreachable')
    expect(r.json.error.message).toMatch(/did not agree on the box's IP \(at least two of the three/)
    expect((await state()).box_ip.last_run).toMatchObject({ ok: false })
    expect(await ipsOf()).toEqual(SAMPLE_IPS)
    const v = await call('POST', '/exposure/targets/xt-2/verify')
    expect(v.json.verified).toBe(false)
    expect(v.json.message).toMatch(/did not agree/)
  })
  it('refuses a result with no public address and ignores non-public ones next to public ones', async () => {
    setEgress('10.0.0.1,100.64.0.9')
    const bad = await call('POST', '/exposure/box-ip/verify')
    expect(bad.status).toBe(400)
    expect(bad.json.error.code).toBe('not_public')
    expect(bad.json.error.message).toMatch(/10\.0\.0\.1, 100\.64\.0\.9, which are private, reserved or shared carrier \(CGNAT\) addresses/)
    setEgress('10.0.0.1,198.51.100.7')
    const mixed = await call('POST', '/exposure/box-ip/verify')
    expect(mixed.status).toBe(200)
    expect(mixed.json.items.map((t: { value: string }) => t.value)).toEqual(['198.51.100.7'])
    expect(mixed.json.message).toMatch(/Ignored, not public: 10\.0\.0\.1\./)
    expect(await ipsOf()).not.toContain('10.0.0.1')
  })

  it('does not add IPs past the limit of 20 targets and says so', async () => {
    for (let i = 0; i < 13; i++) expect((await call('POST', '/exposure/targets', { value: `d${i}.acme.example` })).status).toBe(201)
    setEgress('198.51.100.7')
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('too_many')
    expect((await state()).box_ip.last_run).toMatchObject({ ok: false })
  })

  it.each([
    [{ auto: true, interval_min: 0 }, 'bad_interval'],
    [{ auto: true, interval_min: -5 }, 'bad_interval'],
    [{ auto: true, interval_min: 1441 }, 'bad_interval'],
    [{ auto: true, interval_min: 60.5 }, 'bad_interval'],
    [{ auto: true, interval_min: '60' }, 'bad_interval'],
    [{ auto: true }, 'bad_interval'],
    [{ auto: 'yes', interval_min: 60 }, 'invalid_setting'],
    [{ interval_min: 60 }, 'invalid_setting'],
  ])('settings %j are refused with %s', async (b, code) => {
    const r = await call('PUT', '/exposure/box-ip/settings', b)
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe(code)
    expect((await state()).box_ip).toMatchObject({ auto: true, interval_min: 60 })
  })

  it.each([5, 15, 60, 1440])('accepts an interval of %i minutes and audits the change', async (n) => {
    const r = await call('PUT', '/exposure/box-ip/settings', { auto: true, interval_min: n })
    expect(r.status).toBe(200)
    expect(r.json).toMatchObject({ auto: true, interval_min: n })
    expect(auditStore.get().some((a) => a.action === 'exposure.box_ip_settings' && a.detail === `auto-detect on, every ${n} minutes`)).toBe(true)
  })

  it('only an administrator changes the settings, runs Detect now or removes an IP', async () => {
    expect((await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 }, 'operator')).status).toBe(403)
    expect((await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 }, 'viewer')).status).toBe(403)
    expect((await call('POST', '/exposure/box-ip/verify', undefined, 'operator')).status).toBe(403)
    expect((await call('DELETE', '/exposure/targets/xt-6', undefined, 'operator')).status).toBe(403)
    expect((await state()).box_ip.auto).toBe(true)
  })

  it('the Settings tab: first line says what the box does; the IPs it finds are rows of the target list; axe clean', async () => {
    renderApp('/exposure?tab=settings')
    expect(await screen.findByText('Auto-detect is on: the box checks its public IPs every hour.')).toBeInTheDocument()
    expect(screen.getByText(/The box reaches the Internet via 2 public IPs: 203\.0\.113\.10, 203\.0\.113\.11/)).toBeInTheDocument()
    expect(screen.getByText('Removed IPs come back if the box keeps using them while auto-detect is on, unless you chose not to add them again.')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /IP/ })).toBeNull()
    expect(screen.queryByRole('table', { name: 'Targets' })).toBeNull() // the list is the other tab
    await expectNoA11yViolations()
    await userEvent.click(screen.getByRole('tab', { name: 'Targets' }))
    const list = await targetsTable()
    for (const col of ['Target', 'Ownership', 'Commitment', 'Scan', 'Latest result', 'Open exposures']) expect(within(list).getByRole('columnheader', { name: col })).toBeInTheDocument()
    expect(within(list).getByRole('link', { name: '203.0.113.11' })).toBeInTheDocument()
  })

  it('form matrix: auto on shows the interval, auto off hides it, Detect now stays and the list keeps its IPs', async () => {
    renderApp('/exposure?tab=settings')
    const toggle = await screen.findByRole('switch', { name: "Detect the box's public IPs automatically" })
    await eachOption([
      { option: 'on', shown: ['Check every', 'Detect now', /Auto-detect is on: the box checks/], hidden: [/Auto-detect is off: the box checks only/] },
      { option: 'off', shown: ['Detect now', /Auto-detect is off: the box checks only when you select Detect now/], hidden: ['Check every', /Auto-detect is on: the box checks/] },
      { option: 'on', shown: ['Check every', 'Detect now', /Auto-detect is on: the box checks/], hidden: [/Auto-detect is off: the box checks only/] },
    ], async (o) => {
      if ((toggle.getAttribute('aria-checked') === 'true') !== (o === 'on')) await userEvent.click(toggle)
      await screen.findByText(o === 'on' ? /Auto-detect is on/ : /Auto-detect is off/)
    })
    await userEvent.click(screen.getByRole('tab', { name: 'Targets' }))
    expect(within(await targetsTable()).getAllByRole('row')).toHaveLength(8) // switching off kept the list
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    expect(screen.getByRole('combobox', { name: 'Check every' })).toHaveValue('60') // and the interval
  })

  it('changing the interval saves it and the first line follows', async () => {
    renderApp('/exposure?tab=settings')
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Check every' }), '15')
    expect(await screen.findByText('Auto-detect is on: the box checks its public IPs every 15 minutes.')).toBeInTheDocument()
    expect((await state()).box_ip.interval_min).toBe(15)
  })

  it('a load balancer: both IPs show up, one is removed from its page after a confirmation, Detect now brings it back', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    expect(await within(await targetsTable()).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
    expect(within(await targetsTable()).getByRole('link', { name: '198.51.100.7' })).toBeInTheDocument()
    await userEvent.click(within(await targetsTable()).getByRole('link', { name: '198.51.100.8' }))
    await userEvent.click(await screen.findByRole('button', { name: 'Delete target' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove 198.51.100.8 from the list?' })
    expect(within(dlg).getByRole('checkbox', { name: "Don't add it again if detected" })).toBeChecked() // On by default
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Delete target' }))
    const again = await screen.findByRole('dialog')
    await userEvent.click(within(again).getByRole('checkbox', { name: "Don't add it again if detected" })) // untick: this one may come back
    await userEvent.click(within(again).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Targets' })).queryByRole('link', { name: '198.51.100.8' })).toBeNull())
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    await userEvent.click(screen.getByRole('tab', { name: 'Targets' }))
    expect(await within(await targetsTable()).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
  })

  it('a viewer sees everything but every control is locked with a visible reason', async () => {
    renderApp('/exposure?tab=settings', { role: 'viewer' })
    expect(await screen.findByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeDisabled()
    expect(screen.getByRole('combobox', { name: 'Check every' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Detect now' })).toBeDisabled()
    expect(screen.getAllByText('Requires Admin role').length).toBeGreaterThan(0)
    cleanup()
    renderApp('/exposure/xt-6', { role: 'viewer' }) // removing an IP is on its own page
    expect(await screen.findByRole('button', { name: 'Delete target' })).toBeDisabled()
  })

  it('while Detect now runs the button is busy and a note says what the box is doing and how long it may take', async () => {
    let answer!: () => void
    const held = new Promise<void>((r) => { answer = r })
    server.use(http.post('*/api/v1/exposure/box-ip/verify', async () => { await held; return HttpResponse.json({ message: 'Done.' }) }))
    renderApp('/exposure?tab=settings')
    await userEvent.click(await screen.findByRole('button', { name: 'Detect now' }))
    expect(await screen.findByRole('button', { name: 'Detecting…' })).toHaveAttribute('aria-busy', 'true')
    expect(screen.getByText(/this can take up to 30 seconds/)).toBeInTheDocument()
    answer()
    expect(await screen.findByRole('button', { name: 'Detect now' })).not.toHaveAttribute('aria-busy')
    expect(screen.queryByText(/this can take up to 30 seconds/)).toBeNull()
  })
})

describe('exposure: the Ignored list', () => {
  const clean = async () => {
    const { setDataMode } = await import('@/mocks/db')
    const { usersStore } = await import('@/mocks/stores')
    setDataMode('clean')
    usersStore.set((Object.entries(USER) as ['admin' | 'operator' | 'viewer', string][]).map(([role, id]) => ({ id, name: role, email: `${role}@x.example`, role, password: 'x', twofa: false, created_at: new Date().toISOString(), last_login: null })))
  }
  type List = { items: { id: string; value: string; kind: string }[]; ignored: { value: string; ignored_by: string; ignored_at: string }[] }
  const list = async () => (await call('GET', '/exposure/targets')).json as List
  const idOf = async (ip: string) => (await list()).items.find((t) => t.value === ip)!.id
  const LABEL = "Don't add it again if detected"
  const actions = () => auditStore.get().map((a) => `${a.action} ${a.target}`)

  it('the sample shows an Ignored section with a Restore button; the list only blocks, it is never an input', async () => {
    renderApp('/exposure?tab=settings')
    const section = (await screen.findByRole('heading', { name: 'Ignored IPs' })).closest('section')!
    const table = within(section).getByRole('table', { name: 'IPs on the Ignored list' })
    expect(within(table).getByText('203.0.113.77')).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: 'Restore 203.0.113.77' })).toBeEnabled()
    expect(within(section).queryByRole('textbox')).toBeNull() // an IP is never typed in, here either
    expect(within(section).getByText(/it still needs ownership proof and your confirmation/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  // Removing an IP is done on its own page; the dialog is the same wherever it opens.
  const openIp = async (ip: string) => { await userEvent.click(await within(await targetsTable()).findByRole('link', { name: ip })); return screen.findByRole('button', { name: 'Delete target' }) }
  const back = async () => userEvent.click(await screen.findByRole('link', { name: 'Back to external exposure' }))

  it('removing an IP: the box "Don\'t add it again if detected" is ticked by default, comes back for the next IP, and the hint follows it (form matrix)', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    await userEvent.click(await openIp('198.51.100.8'))
    const dlg = await screen.findByRole('dialog', { name: 'Remove 198.51.100.8 from the list?' })
    const box = within(dlg).getByRole('checkbox', { name: LABEL })
    expect(box).toBeChecked()
    await eachOption([
      { option: 'ignore', shown: [LABEL, /Vedette will never add this IP back and never scan it/], hidden: [/it is added again as a new target/] },
      { option: 'allow', shown: [LABEL, /it is added again as a new target, with no confirmation/], hidden: [/Vedette will never add this IP back/] },
      { option: 'ignore', shown: [/Vedette will never add this IP back/], hidden: [/it is added again as a new target/] },
    ], async (o) => { if ((box.getAttribute('aria-checked') === 'true') !== (o === 'ignore')) await userEvent.click(box) }, dlg)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    // Cancel, then Remove on the same IP: ticked again (the answer is not remembered)
    await userEvent.click(screen.getByRole('button', { name: 'Delete target' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('checkbox', { name: LABEL })) // untick
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await userEvent.click(screen.getByRole('button', { name: 'Delete target' }))
    expect(within(await screen.findByRole('dialog')).getByRole('checkbox', { name: LABEL })).toBeChecked()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    // the next IP starts ticked again, whatever was chosen before
    await back()
    await userEvent.click(await openIp('198.51.100.7'))
    expect(within(await screen.findByRole('dialog', { name: 'Remove 198.51.100.7 from the list?' })).getByRole('checkbox', { name: LABEL })).toBeChecked()
  })

  it('remove with the box ticked, Detect now does not add it back, Restore lets Detect now add it again', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    await userEvent.click(await openIp('198.51.100.8'))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
    await waitFor(async () => expect(within(await targetsTable()).queryByRole('link', { name: '198.51.100.8' })).toBeNull()) // back on the list
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    const ignored = async () => within(await screen.findByRole('table', { name: 'IPs on the Ignored list' }))
    expect(await (await ignored()).findByText('198.51.100.8')).toBeInTheDocument()

    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    expect((await screen.findAllByText(/Not added, on your Ignored list: 198\.51\.100\.8\./)).length).toBeGreaterThan(0) // the toast and the last-check panel
    expect((await list()).items.map((t) => t.value)).not.toContain('198.51.100.8')
    expect((await list()).items.map((t) => t.value)).toContain('198.51.100.7')

    await userEvent.click((await ignored()).getByRole('button', { name: 'Restore 198.51.100.8' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Restore 198.51.100.8' })).toBeNull())
    expect(screen.getByText('No ignored IPs')).toBeInTheDocument()
    // restoring adds nothing by itself: the IP is still not in the list until detection sees it
    expect((await list()).items.map((t) => t.value)).not.toContain('198.51.100.8')
    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    await userEvent.click(screen.getByRole('tab', { name: 'Targets' }))
    expect(await within(await targetsTable()).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
    expect(actions()).toEqual(expect.arrayContaining(['exposure.ip_ignore 198.51.100.8', 'exposure.ip_restore 198.51.100.8']))
  })

  it('automatic checks never add an ignored IP either, and a check that sees only ignored IPs says so and is not a failure', async () => {
    await clean()
    setEgress('198.51.100.8')
    const first = await list()
    const id = first.items.find((t) => t.value === '198.51.100.8')!.id
    expect((await call('DELETE', `/exposure/targets/${id}?ignore=true`)).status).toBe(204)
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(Date.now() + 61 * 60_000) // the next automatic check is due
    const s = (await call('GET', '/exposure/targets')).json as List & { box_ip: { last_run: { ok: boolean; message: string } } }
    expect(s.items.filter((t) => t.kind === 'ip')).toEqual([])
    expect(s.box_ip.last_run).toMatchObject({ ok: true })
    expect(s.box_ip.last_run.message).toMatch(/198\.51\.100\.8, which is on your Ignored list, so nothing was added/)
    vi.useRealTimers()
  })

  it('API: ignore needs an IP, restore needs the list, both need an admin; an ignored IP is not a target so it cannot be scanned', async () => {
    const domain = (await call('GET', '/exposure/targets')).json.items.find((t: { kind: string }) => t.kind === 'domain') as { id: string }
    const bad = await call('DELETE', `/exposure/targets/${domain.id}?ignore=true`)
    expect(bad.status).toBe(400)
    expect(bad.json.error.code).toBe('bad_value')
    expect((await list()).items.some((t) => t.id === domain.id)).toBe(true) // a refused removal removes nothing

    expect((await call('DELETE', '/exposure/box-ip/ignored/198.51.100.99')).status).toBe(404)
    expect((await call('DELETE', '/exposure/box-ip/ignored/not-an-ip')).json.error.code).toBe('bad_value')
    expect((await call('DELETE', '/exposure/box-ip/ignored/203.0.113.77', undefined, 'operator')).status).toBe(403)
    expect((await call('DELETE', '/exposure/box-ip/ignored/203.0.113.77', undefined, 'viewer')).status).toBe(403)
    expect((await call('DELETE', `/exposure/targets/${await idOf('203.0.113.11')}?ignore=true`, undefined, 'operator')).status).toBe(403)

    const id = await idOf('203.0.113.11')
    expect((await call('DELETE', `/exposure/targets/${id}?ignore=true`)).status).toBe(204)
    expect((await call('POST', `/exposure/targets/${id}/scan`)).status).toBe(404)
    expect((await list()).ignored.map((x) => x.value)).toContain('203.0.113.11')
    expect((await call('DELETE', '/exposure/box-ip/ignored/203.0.113.11')).status).toBe(204)
    expect((await call('DELETE', '/exposure/box-ip/ignored/203.0.113.11')).status).toBe(404) // already restored
  })

  it('a viewer sees the Ignored list, but Restore is locked with a visible reason', async () => {
    renderApp('/exposure?tab=settings', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Restore 203.0.113.77' })).toBeDisabled()
  })
})

describe('exposure: scan-time check of an IP (INV-13)', () => {
  const advance = (min: number) => { if (!vi.isFakeTimers()) vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + min * 60_000) }
  const scanXt2 = () => call('POST', '/exposure/targets/xt-2/scan')

  it('an IP is scanned while the box still goes out through it; otherwise the scan is paused, the IP stays in the list, and it works again when the box is back', async () => {
    expect((await scanXt2()).status).toBe(202) // the sample box goes out through 203.0.113.10: a full check just ran and saw it
    setEgress('198.51.100.50') // the modem rebooted and the address went elsewhere
    expect((await scanXt2()).status).toBe(202) // the check of the last 5 minutes saw it, so no new probe yet
    advance(6)
    const paused = await scanXt2()
    expect(paused.status).toBe(409)
    expect(paused.json.error.code).toBe('ip_not_current')
    expect(paused.json.error.message).toMatch(/^This box no longer reaches the Internet through 203\.0\.113\.10; it was last seen \d{1,2} [A-Z][a-z]{2} \d{4}, \d{2}:\d{2}\. Scans of it are paused until the box uses it again\.$/)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ value: '203.0.113.10', status: 'verified' }) // still in the list
    for (const down of ['offline', 'disagree']) {
      advance(6)
      setEgress(down)
      expect((await scanXt2()).json.error.code).toBe('ip_not_current') // fail closed
    }
    advance(6)
    setEgress('203.0.113.10,203.0.113.11') // a load balancer: every IP is seen, so every IP is scannable
    expect((await scanXt2()).status).toBe(202)
  })

  it('a full check is reused for 5 minutes, a "not seen" included; after that the box is asked again', async () => {
    advance(10) // the sample's last check is old
    setEgress('198.51.100.50')
    expect((await scanXt2()).json.error.code).toBe('ip_not_current') // one full check, not seen
    const first = (await call('GET', '/exposure/targets')).json.box_ip.last_run.at
    setEgress('203.0.113.10') // the box is back, but the answer of the last full check still stands for 5 minutes
    advance(2)
    expect((await scanXt2()).json.error.code).toBe('ip_not_current')
    expect((await call('GET', '/exposure/targets')).json.box_ip.last_run.at).toBe(first) // nothing was probed again
    advance(4)
    expect((await scanXt2()).status).toBe(202)
    expect((await call('GET', '/exposure/targets')).json.box_ip.last_run.at).not.toBe(first)
  })

  it('the commitment is asked first, without a check of the network', async () => {
    setEgress('198.51.100.50')
    await call('POST', '/exposure/box-ip/verify') // adds 198.51.100.50 as a new target, no commitment yet
    const id = (await call('GET', '/exposure/targets')).json.items.find((t: { value: string }) => t.value === '198.51.100.50').id
    setEgress('198.51.100.51')
    advance(6)
    expect((await call('POST', `/exposure/targets/${id}/scan`, undefined, 'operator')).json.error.code).toBe('commitment_required')
  })
})


describe("exposure: an administrator's first Scan now is the confirmation", () => {
  const verifiedTarget = async (value: string) => {
    await call('POST', '/exposure/targets', { value })
    const id = ((await call('GET', '/exposure/targets')).json.items as { id: string; value: string }[]).find((t) => t.value === value)!.id
    await call('POST', `/exposure/targets/${id}/verify`); await call('POST', `/exposure/targets/${id}/verify`)
    return id
  }
  const withTwoStep = (on: boolean) => usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: on } : x)))

  it('has no consent form, template, tick box or file upload', async () => {
    withTwoStep(true)
    const id = await verifiedTarget('nobox.acme.example')
    renderApp(`/exposure/${id}`)
    await screen.findByRole('heading', { level: 1 })
    expect(screen.queryByRole('checkbox')).not.toBeInTheDocument()
    expect(screen.queryByText(/template/i)).not.toBeInTheDocument()
    expect(document.querySelector('input[type="file"]')).toBeNull()
  })

  it('the page shows the sentence the API sent next to the button, and pressing it records exactly that', async () => {
    withTwoStep(true)
    const id = await verifiedTarget('fresh.acme.example')
    const sent = (await call('GET', `/exposure/targets/${id}`)).json.commitment_notice as { version: string; text: string }
    renderApp(`/exposure/${id}`)
    const note = await screen.findByRole('note', { name: 'Pressing Scan now records this confirmation' })
    expect(within(note).getByText(sent.text)).toBeInTheDocument()
    expect(sent.text).toContain('fresh.acme.example')
    await userEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await userEvent.click(screen.getByRole('tab', { name: 'Ownership' }))
    expect(await screen.findByText(/Confirmed by .+ on .+, by pressing Scan now\./)).toBeInTheDocument()
    const c = (await call('GET', `/exposure/targets/${id}`)).json
    expect(c.commitment).toMatchObject({ by: 'admin@acme.example', version: sent.version, sentence: sent.text })
    expect(c.commitment_notice).toBeNull()
    expect(auditStore.get().some((a) => a.action === 'exposure.commitment' && a.target === 'fresh.acme.example' && a.detail?.includes(sent.text))).toBe(true)
  })

  it('an administrator without two-step sign-in is refused by the server and told to turn it on', async () => {
    withTwoStep(false)
    const id = await verifiedTarget('notwo.acme.example')
    renderApp(`/exposure/${id}`)
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect(await screen.findByText(/Turn on two-step sign-in for your account before the first scan/)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Turn on two-step sign-in' })).toHaveAttribute('href', '/settings/account?tab=sign-in#two-step') // §0: the exact tab and field
    const r = await call('POST', `/exposure/targets/${id}/scan`, { notice_version: '2026-11-13' })
    expect(r.status).toBe(403)
    expect(r.json.error.code).toBe('twofa_required')
    expect((await call('GET', `/exposure/targets/${id}`)).json.commitment).toBeNull()
  })

  it('an operator cannot scan an unconfirmed target: the page and the API say an administrator must run the first scan', async () => {
    const id = await verifiedTarget('op.acme.example')
    renderApp(`/exposure/${id}`, { role: 'operator' })
    expect(await screen.findByText(/an administrator must run the first scan of op\.acme\.example/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.queryByRole('note')).not.toBeInTheDocument()
    const r = await call('POST', `/exposure/targets/${id}/scan`, undefined, 'operator')
    expect(r.json.error).toMatchObject({ code: 'commitment_required' })
    expect(r.json.error.message).toMatch(/administrator must run the first scan/)
  })

  it('API: the version must be the current one; a confirmed target is scanned by an operator and never re-recorded', async () => {
    withTwoStep(true)
    const id = await verifiedTarget('api.acme.example')
    expect((await call('POST', `/exposure/targets/${id}/scan`)).json.error.code).toBe('commitment_required') // no version
    const stale = await call('POST', `/exposure/targets/${id}/scan`, { notice_version: '2020-01-01' })
    expect([stale.status, stale.json.error.code]).toEqual([409, 'notice_changed'])
    expect((await call('GET', `/exposure/targets/${id}`)).json.commitment).toBeNull()
    const ok = await call('POST', `/exposure/targets/${id}/scan`, { notice_version: NOTICE_VERSION })
    expect(ok.status).toBe(202)
    const first = (await call('GET', `/exposure/targets/${id}`)).json.commitment
    expect((await call('POST', `/exposure/targets/${id}/scan`, undefined, 'operator')).status).toBe(202)
    expect((await call('POST', `/exposure/targets/${id}/scan`, { notice_version: NOTICE_VERSION })).status).toBe(202)
    expect((await call('GET', `/exposure/targets/${id}`)).json.commitment).toEqual(first)
    expect(auditStore.get().filter((a) => a.action === 'exposure.commitment' && a.target === 'api.acme.example')).toHaveLength(1)
  })

  it('the list and an operator read an older commitment honestly: needs confirming again, not "Commitment confirmed"', async () => {
    withTwoStep(true)
    renderApp('/exposure/xt-6', { role: 'operator' })
    expect(await screen.findByText(/the confirmation text changed\. An administrator confirms 203\.0\.113\.11 once with the next Scan now/)).toBeInTheDocument()
    expect(screen.getByText('Needs confirming again')).toBeInTheDocument()
    expect(screen.queryByText('Commitment confirmed')).not.toBeInTheDocument()
    expect(screen.queryByText(/must run the first scan/)).not.toBeInTheDocument()
    expect((await call('POST', '/exposure/targets/xt-6/scan', undefined, 'operator')).json.error.message).toMatch(/confirmation text changed/)
    expect((await call('POST', '/exposure/targets/xt-6/scan', {})).json.error.code).toBe('notice_changed')
  })

  it('xt-6 is blocked with the new sentence and the changed line; an operator is refused; the administrator re-confirms once', async () => {
    withTwoStep(true)
    const before = (await call('GET', '/exposure/targets/xt-6')).json
    expect([before.blocked_reason, before.commitment.version, before.commitment_notice.version]).toEqual(['no_commitment', '2026-11-13', NOTICE_VERSION])
    const op = await call('POST', '/exposure/targets/xt-6/scan', undefined, 'operator')
    expect([op.json.error.code, op.json.error.message]).toEqual(['commitment_required', expect.stringMatching(/confirmation text changed/)])
    expect((await call('POST', '/exposure/targets/xt-6/scan', { notice_version: '2026-11-13' })).json.error.code).toBe('notice_changed')
    renderApp('/exposure/xt-6')
    const note = await screen.findByRole('note', { name: 'Pressing Scan now records this confirmation' })
    expect(within(note).getByText('The confirmation text changed: an administrator confirms once with the next Scan now.')).toBeInTheDocument()
    expect(within(note).getByRole('button', { name: 'About Pressing Scan now records this confirmation' })).toHaveAccessibleDescription(/It now names service identification/)
    expect(within(note).getByText(before.commitment_notice.text)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Scan now' }))
    await waitFor(async () => expect((await call('GET', '/exposure/targets/xt-6')).json.commitment.version).toBe(NOTICE_VERSION))
    expect((await call('GET', '/exposure/targets/xt-6')).json.commitment_notice).toBeNull()
    expect(auditStore.get().some((a) => a.action === 'exposure.commitment' && a.target === before.value && a.detail?.includes('re-confirmed') && a.detail.includes('2026-11-13'))).toBe(true)
  })
})

describe('exposure: delete and roles', () => {
  it('delete asks for confirmation and removes the target with its data', async () => {
    renderApp('/exposure/xt-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Delete target' }))
    expect(within(await screen.findByRole('dialog')).getByText(/This cannot be undone/)).toBeInTheDocument()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }))
    expect(await screen.findByRole('heading', { level: 1 })).toBeInTheDocument()
    expect((await call('GET', '/exposure/targets/xt-1/snapshots')).status).toBe(404)
  })

  it('viewer sees results but every action is locked with a visible reason', async () => {
    renderApp('/exposure/xt-1', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Delete target' })).toBeDisabled()
    expect(screen.getByText(/You have view-only access/)).toBeInTheDocument()
  })
})

describe('exposure: add target form matrix', () => {
  it('Add target asks Domain or Public IP, shows the field of the one chosen, and can be cancelled', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add a target' })
    expect(within(dlg).getByRole('button', { name: 'Domain' })).toHaveAttribute('aria-pressed', 'true') // a domain unless the person chooses an address
    await eachOption([
      { option: 'domain', shown: ['What to add', 'Add', 'Cancel', 'For example example.com, without http:// or a path.'], hidden: ['Public IP address', 'A public IPv4 address, for example 203.0.113.10.'] },
      { option: 'ip', shown: ['What to add', 'Public IP address', 'A public IPv4 address, for example 203.0.113.10.'], hidden: ['For example example.com, without http:// or a path.'] },
    ], async (o) => { await userEvent.click(within(dlg).getByRole('button', { name: o === 'ip' ? 'Public IP' : 'Domain' })) }, dlg)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    // The box's own IP is never typed: its section has only a switch, a select and buttons.
    await userEvent.click(screen.getByRole('tab', { name: 'Settings' }))
    const section = document.getElementById('box-ip')!
    expect(within(section).queryByRole('textbox')).toBeNull()
    expect(within(section).getByRole('button', { name: 'Detect now' })).toBeInTheDocument()
  })

  it('a public IP typed in goes to its page, shows the token file and the reverse DNS option, and the box proves it once the file is served', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.click(screen.getByRole('button', { name: 'Public IP' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Public IP address' }), '198.51.100.7')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('heading', { level: 1, name: '198.51.100.7 cannot be scanned yet: awaiting ownership proof' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Ownership/, selected: true })).toBeInTheDocument() // taken into the target to prove it in place
    expect(screen.getByTestId('proof-path')).toHaveTextContent('/.well-known/vedette-verify.txt')
    const token = (await call('GET', '/exposure/targets')).json.items.find((x: { value: string }) => x.value === '198.51.100.7').token as string
    expect(screen.getByText(token)).toBeInTheDocument() // the whole content of the file
    expect(screen.getByText('http://198.51.100.7/.well-known/vedette-verify.txt')).toBeInTheDocument()
    expect(screen.getByTestId('proof-ptr')).toHaveTextContent(/under acme\.example/) // the domains of this box that can carry the name
    expect(screen.getByText(/An A record of one of your domains pointing at this address is not proof/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled() // nothing is scanned until it is proved
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    expect(await screen.findByText(/Vedette found no proof of 198\.51\.100\.7/)).toBeInTheDocument()
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 })) // the file is served by now
    expect(await screen.findByText(/198\.51\.100\.7 is proved: the token file was found/)).toBeInTheDocument()
    expect(screen.getByTestId('proof-expires')).toHaveTextContent(/\d{1,2} \w{3} \d{4}/)
    expect(screen.getByTestId('proof-next')).toHaveTextContent(/\d{1,2} \w{3} \d{4}/) // when the box checks it again by itself
  })

  it('the ownership check pauses for 30 seconds: the button counts it down', async () => {
    checkPause.seconds = 3
    renderApp('/exposure/xt-3?tab=ownership')
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    const wait = await screen.findByRole('button', { name: /^Check again in \d s$/ })
    expect(wait).toBeDisabled()
    await waitFor(() => expect(screen.queryByRole('button', { name: /^Check again in/ })).toBeNull(), { timeout: 5000 })
    expect(screen.getByRole('button', { name: /^Check/ })).toBeEnabled()
  })

  it('the box rate limit of a check shows its seconds on the button', async () => {
    checkPause.seconds = 30
    server.use(http.post('*/api/v1/exposure/targets/xt-3/verify', () => HttpResponse.json({ error: { code: 'rate_limited', message: 'This target was checked a moment ago. The next check is allowed in 4 seconds.' } }, { status: 429 })))
    renderApp('/exposure/xt-3?tab=ownership')
    await userEvent.click(await screen.findByRole('button', { name: 'Check' }, { timeout: 5000 }))
    expect(await screen.findByRole('button', { name: /^Check again in [34] s$/ })).toBeDisabled()
  })
})

describe('exposure: QA pass fixes (paused IP, copy, dates, IPv6, remove dialog, rate limit)', () => {
  const human = /\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}/ // table cells join without a space
  const numeric = /\b\d{1,2}\/\d{1,2}\/\d{4}\b/
  const iso = /\b\d{4}-\d{2}-\d{2}\b/
  const pause = async () => {
    setEgress('203.0.113.11') // the box no longer goes out through 203.0.113.10
    expect((await call('POST', '/exposure/targets/xt-2/scan')).json.error.code).toBe('ip_not_current')
  }

  it('1. a paused IP is a state of the target: the API, the target page and both lists say so', async () => {
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ scannable: true, blocked_reason: null }) // before: nothing is known against it
    await pause()
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ status: 'verified', scannable: false, blocked_reason: 'ip_not_current' })
    expect((await call('GET', '/exposure/targets')).json.items.find((x: { id: string }) => x.id === 'xt-2')).toMatchObject({ scannable: false, blocked_reason: 'ip_not_current' })
    renderApp('/exposure/xt-2?tab=ownership')
    expect(await screen.findByRole('heading', { level: 1, name: /203\.0\.113\.10 is paused/ })).toBeInTheDocument()
    expect(screen.getByText(/Scans paused: the box no longer reaches the Internet through this IP \(last seen \d{1,2} \w{3} \d{4}, \d{2}:\d{2}\)/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deep scan now' })).toBeDisabled()
    expect(document.getElementById('scan-reason')?.textContent).toMatch(/no longer goes out through 203\.0\.113\.10/)
    expect(screen.queryByText(/The box reaches the Internet via 203\.0\.113\.10/)).toBeNull() // the stale green "Verified" card is gone
    expect(screen.queryByText(/is ready for its first scan/)).toBeNull()
  })

  it('1. the paused state rests on stored facts: it stays after 10 minutes and 3 hours, a failed check changes nothing, a later check that sees the IP clears it', async () => {
    const advance = (min: number) => { if (!vi.isFakeTimers()) vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + min * 60_000) }
    const state = async () => (await call('GET', '/exposure/targets/xt-2')).json.blocked_reason
    expect(await state()).toBeNull() // no full check yet: nothing is known against the IP
    advance(1)
    await pause()
    for (const min of [10, 170]) {
      advance(min)
      expect(await state()).toBe('ip_not_current') // no window: it stays until a check sees the IP
    }
    for (const down of ['offline', 'disagree']) {
      advance(6)
      setEgress(down)
      await call('POST', '/exposure/box-ip/verify') // a failed check (no answer)
      expect(await state()).toBe('ip_not_current') // changes nothing
    }
    advance(6)
    setEgress('203.0.113.10,203.0.113.11') // a load balancer: both seen
    expect((await call('POST', '/exposure/box-ip/verify')).status).toBe(200)
    expect(await state()).toBeNull()
    advance(180)
    expect(await state()).toBeNull() // it does not come back by itself
    // a new full check that does not see the IP pauses it again
    advance(1)
    setEgress('203.0.113.11')
    await call('POST', '/exposure/box-ip/verify')
    expect(await state()).toBe('ip_not_current')
  })

  it('1. the list says Paused instead of Ready to scan', async () => {
    await pause()
    renderApp('/exposure')
    const row = within(await ipTable()).getByRole('row', { name: /203\.0\.113\.10/ })
    expect(within(row).getByText('Paused')).toBeInTheDocument()
    expect(within(row).queryByText('Ready to scan')).toBeNull()
  })

  it('1. the pause ends when the box uses the IP again (Verify again)', async () => {
    await pause()
    setEgress('203.0.113.10')
    expect((await call('POST', '/exposure/targets/xt-2/verify')).json.verified).toBe(true)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ scannable: true, blocked_reason: null })
  })

  it('2. the IP page says that the box reaches the Internet through the IP only once', async () => {
    renderApp('/exposure/xt-2?tab=ownership')
    await screen.findByRole('heading', { level: 1 })
    expect(screen.getAllByText(/verified because (this|the) box reaches the Internet through it/i)).toHaveLength(1)
  })

  it('3. Verify again says it is a full check (5 rounds, 15 requests), not "three times"', async () => {
    renderApp('/exposure/xt-2?tab=ownership')
    expect(await screen.findByText('Works only while this box currently reaches the Internet through 203.0.113.10.')).toBeInTheDocument()
    const hint = screen.getByRole('button', { name: 'About Verify again' }) // #824: the detail is behind ⓘ
    expect(hint).toHaveAccessibleDescription(/full check/)
    expect(hint).toHaveAccessibleDescription(/15 requests/)
    expect(hint).not.toHaveAccessibleDescription(/three times/)
  })

  it('4. the help and the "no check yet" text say what is a full check and name the services', async () => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [], box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [] })))
    renderApp('/exposure?tab=settings')
    expect(await screen.findByText('No check yet.')).toBeInTheDocument()
    const never = screen.getByRole('button', { name: 'About Last check' }) // #824: the detail is behind ⓘ
    for (const re of [/first check/, /full check/, /15 requests/, /checkip\.amazonaws\.com/, /icanhazip\.com/, /ifconfig\.me\/ip/]) expect(never).toHaveAccessibleDescription(re)
    const help = screen.getByRole('button', { name: 'About Public IP of this box' }).getAttribute('aria-describedby')!
    const helpText = document.getElementById(help)!.textContent!
    expect(helpText).toMatch(/first check after install, Detect now and Verify again are full checks/)
    expect(helpText).toMatch(/checkip\.amazonaws\.com/)
    expect(helpText).toMatch(/once.*3 requests/s)
  })

  it('5. the page header has a space between the certificate count and the rule', async () => {
    renderApp('/exposure')
    await screen.findByRole('heading', { level: 1 })
    const meta = await screen.findByText(/certificates? (is|are) about to expire\./)
    expect(meta.textContent).toMatch(/about to expire\. Only what you have proven/)
  })

  it('6. one date format on the list, the IP page and the domain page: 9 Nov 2026, 21:01', async () => {
    for (const path of ['/exposure', '/exposure/xt-2', '/exposure/xt-1']) {
      const { unmount } = renderApp(path)
      await screen.findByRole('heading', { level: 1 })
      await waitFor(() => expect(screen.queryByText(/^Loading/)).toBeNull())
      const text = document.querySelector('main')!.textContent!
      expect(text, `${path} has a numeric date`).not.toMatch(numeric)
      expect(text, `${path} has an ISO date`).not.toMatch(iso)
      expect(text, `${path} has no readable date`).toMatch(human)
      unmount()
    }
  })

  it('6. messages of the API that carry a date use the same format', async () => {
    setEgress('198.51.100.7')
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.json.message).toMatch(/Verified until \d{1,2} \w{3} \d{4}\./)
    expect(r.json.message).not.toMatch(iso)
    expect((await call('POST', '/exposure/targets/xt-4/scan')).json.error.message).toMatch(/expired on \d{1,2} \w{3} \d{4}, so/)
  })

  it.each(['2001:4860:4860::8888', '[::1]', '::ffff:203.0.113.5', '2001:DB8::1'])('7. IPv6 %s gets the same IP-specific answer as IPv4', async (v) => {
    const r = await call('POST', '/exposure/targets', { value: v })
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('ip_not_allowed')
    expect(r.json.error.message).toMatch(/That is an IP address, not a domain/)
  })

  it('7. a domain with a colon is still a plain bad value; the dialog shows the IP message for IPv6', async () => {
    expect((await call('POST', '/exposure/targets', { value: 'acme.example:8080' })).json.error.code).toBe('bad_value')
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add target' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), '2001:4860:4860::8888')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/That is an IP address, not a domain/)).toBeInTheDocument()
  })

  it('8. deleting an IP from its page opens the same dialog as the list, with "Don\'t add it again" ticked', async () => {
    renderApp('/exposure/xt-2')
    await userEvent.click(await screen.findByRole('button', { name: 'Delete target' }))
    const dlg = await screen.findByRole('dialog')
    expect(within(dlg).getByRole('checkbox', { name: "Don't add it again if detected" })).toBeChecked()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Remove' }))
    await waitFor(async () => expect((await call('GET', '/exposure/targets')).json.ignored.map((x: { value: string }) => x.value)).toContain('203.0.113.10'))
    expect((await call('GET', '/exposure/targets/xt-2')).status).toBe(404)
  })

  it('8. a domain page keeps the plain delete dialog: nothing to ignore', async () => {
    renderApp('/exposure/xt-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Delete target' }))
    expect(within(await screen.findByRole('dialog')).queryByRole('checkbox')).toBeNull()
  })

  it('9. when the 10 attempts an hour are used up, Detect now is disabled with the wait; the help says the budget is shared', async () => {
    expect((await call('GET', '/exposure/targets')).json.box_ip.retry_in_min).toBeNull()
    setEgress('203.0.113.10')
    for (let i = 0; i < 10; i++) expect((await call('POST', '/exposure/targets/xt-2/verify')).status).toBe(200) // a domain Check and Verify again count too
    const box = (await call('GET', '/exposure/targets')).json.box_ip
    expect(box.retry_in_min).toBeGreaterThanOrEqual(1)
    expect(box.retry_in_min).toBeLessThanOrEqual(60)
    renderApp('/exposure?tab=settings')
    const detect = await screen.findByRole('button', { name: 'Detect now' })
    expect(detect).toBeDisabled()
    expect(screen.getByText(/Try again in about \d+ minutes?\./)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About Public IP of this box' })).toHaveAccessibleDescription(/Detect now, Verify again and the DNS Check of a domain share 10 attempts per hour/)
  })

  it('9. with attempts left, Detect now is enabled and no wait is shown', async () => {
    renderApp('/exposure?tab=settings')
    expect(await screen.findByRole('button', { name: 'Detect now' })).toBeEnabled()
    expect(screen.queryByText(/Try again in about/)).toBeNull()
  })
})

describe('exposure: Add a domain form matrix', () => {
  it('Cancel drops the text and its error: the next opening is empty', async () => {
    renderApp('/exposure')
    const add = await screen.findByRole('button', { name: 'Add target' })
    await userEvent.click(add)
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), 'shop.example.com:8443')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await screen.findByText(/without http:\/\/, a path/)
    await eachOption([{ option: 'Cancel, open again', shown: ['What to add'], hidden: [/without http:\/\/, a path/] }], async () => {
      await userEvent.click(screen.getByRole('button', { name: 'Cancel' }))
      await userEvent.click(add)
    })
    expect(screen.getByRole('textbox', { name: 'Domain' })).toHaveValue('')
  })
})

describe('exposure: services and exploited vulnerabilities of the box IP (S-EXP-2)', () => {
  it('lists the exploited CVEs per port with their basis, the service that needs a version, and what was checked; axe clean', async () => {
    renderApp('/exposure/xt-2')
    const vulns = await screen.findByRole('table', { name: 'Exploited vulnerabilities that match the services on this IP' })
    for (const cve of ['CVE-2021-41773', 'CVE-2021-42013']) {
      // Greenbone also names it (INV-25): its row sits next to the version row and never replaces it
      const rows = within(vulns).getAllByRole('row', { name: new RegExp(cve) })
      expect(rows).toHaveLength(2)
      expect(within(rows[1]!).getByText('Scanner: OpenVAS, QoD 99')).toBeInTheDocument()
      const row = rows[0]!
      expect(within(row).getByText('Version in range')).toBeInTheDocument()
      expect(within(row).getByText('18443')).toBeInTheDocument()
      expect(within(row).getByText(/Apache httpd 2\.4\.49\. Its version is inside the range/)).toBeInTheDocument()
    }
    expect(within(screen.getByRole('list', { name: 'Services whose version could not be read' })).getByText(/4 exploited CVEs of Fortinet FortiGate SSL VPN on port 443 could not be checked: the service sent no version/)).toBeInTheDocument()
    const services = screen.getByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })
    expect(within(within(services).getByRole('row', { name: /18443/ })).getByText('2 exploited')).toBeInTheDocument()
    expect(within(within(services).getByRole('row', { name: /^443/ })).getByText('No version sent')).toBeInTheDocument()
    expect(within(services).getByText('Closed at once (tcpwrapped)')).toBeInTheDocument()
    // nmap's table name is a guess, an unknown TLS service says what its certificate names; neither "sent" no version
    const sip = within(services).getByRole('row', { name: /^5060/ })
    expect(within(sip).getByText('Probably SIP')).toBeInTheDocument()
    expect(within(sip).getByText('By port number, not confirmed')).toBeInTheDocument()
    expect(within(sip).getByText('Not read')).toBeInTheDocument()
    const tls = within(services).getByRole('row', { name: /^11443/ })
    expect(within(tls).getByText('TLS, service not identified')).toBeInTheDocument()
    expect(within(tls).getByText('certificate for nas01.acme.example, backup.acme.example')).toBeInTheDocument()
    expect(within(services).queryByText(/^ssl\/unknown$|^sip$/)).toBeNull()
    const checked = screen.getByRole('list', { name: 'Checked' })
    expect(within(checked).getByText(/Port scan \(nmap\) of 1052 TCP ports, then service identification \(nmap -sV\) of the open ones: 2 services identified, 1 named by port number only, 2 not identified\./)).toBeInTheDocument()
    expect(within(checked).getByText(/2 of 5 services compared with today's CISA list of exploited vulnerabilities/)).toBeInTheDocument()
    const not = screen.getByRole('list', { name: 'Not checked' })
    for (const line of ['UDP ports: the scan connects over TCP only.', "TCP ports other than the 1052 ports this scan probed: nmap's 1000 most common ports and the fixed list of commonly exposed ports.", /only the CISA list of exploited vulnerabilities \(KEV\) is compared/]) expect(within(not).getByText(line)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('the matched deep templates are listed by severity with their template and port; the section says these are not in Findings', async () => {
    renderApp('/exposure/xt-2')
    const deep = await screen.findByRole('table', { name: 'Found by the deep scan (nuclei templates that matched)' })
    const rows = within(deep).getAllByRole('row').slice(1)
    expect(rows.map((r) => within(r).getAllByRole('cell')[1]!.textContent)).toEqual(['Git Configuration - Detecttemplate git-config', 'Apache Detectiontemplate apache-detect', 'Fortinet FortiGate SSL VPN Panel - Detecttemplate fortinet-fortigate-panel'])
    expect(within(rows[0]!).getByText('Medium')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('18443')).toBeInTheDocument()
    expect(screen.getByText(/They are listed here, on this target's page, and not under Findings/)).toBeInTheDocument()
  })

  it('compare: the new forward brings its service and both exploited CVEs', async () => {
    renderApp('/exposure/xt-2')
    const diff = await screen.findByRole('table', { name: 'Changes between two scan days' })
    expect(await within(diff).findByText('CVE-2021-41773 on 203.0.113.10:18443')).toBeInTheDocument()
    expect(within(diff).getByText('CVE-2021-42013 on 203.0.113.10:18443')).toBeInTheDocument()
    expect(within(within(diff).getByRole('row', { name: /Service.*203\.0\.113\.10:18443/ })).getByText('Apache httpd 2.4.49')).toBeInTheDocument()
  })

  it('INV-22: a port the newest scan missed says "missed", still counts as open, and the compare does not call it closed', async () => {
    renderApp('/exposure/xt-2')
    const ports = await screen.findByRole('table', { name: 'Ports open to the Internet' })
    const row = within(ports).getByRole('row', { name: /\b8443\b/ })
    expect(within(row).getByText('Missed by the last scan')).toBeInTheDocument()
    expect(within(row).getByText(/Vedette says it is closed only after a second scan also misses it; use Scan now to check again\. Until then it counts as open\./)).toBeInTheDocument()
    expect(within(ports).getAllByText('Missed by the last scan')).toHaveLength(1)
    const svc = await screen.findByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })
    expect(within(within(svc).getByRole('row', { name: /^8443/ })).getByText('Missed by the last scan')).toBeInTheDocument()
    const diff = await screen.findByRole('table', { name: 'Changes between two scan days' })
    const changed = await within(diff).findByRole('row', { name: /Open port.*203\.0\.113\.10:8443/ })
    expect(within(changed).getByText('Missed by the last scan; closed only after a second scan also misses it')).toBeInTheDocument()
    expect(within(changed).getByText('Changed')).toBeInTheDocument()
  })

  it('with no exploited CVE but deep-scan rows, the empty state is not an all-clear and points to them', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const ip = '203.0.113.10'
    const snap = { id: 'sn-d', date, scanned_at: at, hosts: [], ports: [{ ip, port: 8080, service: 'http' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [{ ip, port: 8080, name: 'http', product: 'nginx', version: '1.27.0', cpe: '', extra: '' }], web_findings: [], greenbone: [], vulns: [], version_gaps: [], checks: [], not_checked: [],
      templates: [{ ip, port: 8080, cve: '', template: 'git-config', outcome: 'matched', name: 'Git Configuration - Detect', severity: 'medium' }] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Exploited vulnerabilities' })
    expect(await within(section).findByText('No exploited vulnerability matched the identified versions')).toBeInTheDocument()
    expect(within(section).queryByText('No exploited vulnerability matches the identified services')).toBeNull()
    expect(within(section).getByRole('table', { name: 'Found by the deep scan (nuclei templates that matched)' })).toBeInTheDocument()
  })

  it('without service identification on the box the page says so, and claims nothing about vulnerabilities', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-x', date, scanned_at: at, hosts: [], ports: [{ ip: '203.0.113.10', port: 443, service: 'https' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [], web_findings: [], vulns: [], version_gaps: [], checks: [{ kind: 'ports', text: 'TCP connect to the fixed list of commonly exposed ports, then one GET / on each open web port and a TLS handshake on each TLS port: 1 port open.', at }],
      not_checked: [{ kind: 'udp', text: 'UDP ports: the scan connects over TCP only.' }, { kind: 'services', text: 'Service identification (nmap -sV) is not set up on this box yet.' }] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Exploited vulnerabilities' })
    expect(await within(section).findByText('Services were not identified')).toBeInTheDocument() // Never "No service was identified" here
    expect(within(section).queryByText('No service was identified')).toBeNull()
    expect(within(section).getByText('Service identification (nmap -sV) is not set up on this box yet.')).toBeInTheDocument()
    expect(within(section).queryByRole('table')).toBeNull()
    expect(within(screen.getByRole('list', { name: 'Not checked' })).getByText('Service identification (nmap -sV) is not set up on this box yet.')).toBeInTheDocument()
  })

  it('a match on a distribution package says the fix may be backported and weighs less (Exim 4.89 on Debian)', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-x', date, scanned_at: at, hosts: [], ports: [{ ip: '203.0.113.10', port: 25, service: 'smtp' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [{ ip: '203.0.113.10', port: 25, name: 'smtp', product: 'Exim smtpd', version: '4.89', cpe: 'cpe:/a:exim:exim:4.89', extra: 'Debian' }],
      vulns: [{ ip: '203.0.113.10', port: 25, cve: 'CVE-2019-10149', name: 'Exim Mail Transfer Agent (MTA) Improper Input Validation', basis: 'version', date_added: '2021-11-03', ransomware: false, backport: 'Debian',
        summary: '203.0.113.10 runs Exim smtpd 4.89. Its version is inside the range affected by CVE-2019-10149 (>= 4.87, <= 4.91); no scan has confirmed it yet, so this is only suspected. Debian may have backported the fix without changing the version: check the installed package version against Debian\'s security tracker.' }],
      version_gaps: [], web_findings: [], checks: [], not_checked: [] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    const row = within(await screen.findByRole('table', { name: 'Exploited vulnerabilities that match the services on this IP' })).getByRole('row', { name: /CVE-2019-10149/ })
    expect(within(row).getByText('Version in range, but Debian may have backported the fix')).toBeInTheDocument()
    expect(within(row).queryByText('Version in range')).toBeNull()
    expect(within(row).getByText(/check the installed package version against Debian's security tracker/)).toBeInTheDocument()
    const services = screen.getByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })
    expect(within(services).getByText('1 maybe patched')).toBeInTheDocument()
    expect(within(services).queryByText('1 exploited')).toBeNull()
  })

  it('a JavaScript library CVE on a page is listed but not counted on the service of that port', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-x', date, scanned_at: at, hosts: [], ports: [{ ip: '203.0.113.10', port: 443, service: 'https' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [{ ip: '203.0.113.10', port: 443, name: 'https', product: 'nginx', version: '1.24.0', cpe: 'cpe:/a:igor_sysoev:nginx:1.24.0', extra: '' }],
      vulns: [{ ip: '203.0.113.10', port: 443, cve: 'CVE-2020-11023', name: 'JQuery Cross-Site Scripting (XSS) Vulnerability', basis: 'js_library', date_added: '2025-01-23', ransomware: false, backport: '', template: '', template_result: '',
        summary: 'A page on port 443 loads the JavaScript library jquery 3.4.1 (seen by ZAP). Retire.js lists CVE-2020-11023 for that version and CISA lists it as exploited. A library version alone does not show that the site uses the affected function; the risk is to visitors\' browsers, not the server. Update the library.' }],
      templates: [], version_gaps: [], web_findings: [], checks: [], not_checked: [] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    const row = within(await screen.findByRole('table', { name: 'Exploited vulnerabilities that match the services on this IP' })).getByRole('row', { name: /CVE-2020-11023/ })
    expect(within(row).getByText('JavaScript library version, seen by ZAP')).toBeInTheDocument()
    expect(within(row).getByText(/the risk is to visitors' browsers, not the server/)).toBeInTheDocument()
    const services = screen.getByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })
    expect(within(services).queryByText('1 exploited')).toBeNull()
  })

  it('a domain whose page header names a version with an exploited CVE gets the section in the words of a domain; axe clean', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-d', date, scanned_at: at, hosts: [{ name: 'www.acme.example', ip: '198.51.100.20' }], ports: [{ ip: '198.51.100.20', port: 443, service: 'https' }], admin_panels: [], certs: [],
      counts: { subdomains: 1, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 }, services: [], templates: [],
      vulns: [{ ip: 'www.acme.example', port: 443, cve: 'CVE-2021-41773', name: 'Apache HTTP Server Path Traversal Vulnerability', basis: 'version', date_added: '2021-11-03', ransomware: false, backport: '', template: '', template_result: '',
        summary: 'www.acme.example runs Apache 2.4.49. Its version is inside the range affected by CVE-2021-41773 (= 2.4.49); no scan has confirmed it yet, so this is only suspected. The version was seen in the Server header by ZAP.' }],
      version_gaps: [], checks: [], not_checked: [],
      web_findings: [{ site: 'https://www.acme.example/', plugin_id: '10036', name: 'Server Leaks Version Information via "Server" HTTP Response Header Field', risk: 'low', confidence: 'high', cwe: 200, description: 'The server is leaking version information.',
        solution: 'Hide the version.', urls: ['https://www.acme.example/'], count: 1, group: 'fix', software: [{ product: 'Apache', version: '2.4.49', cves: [], distro: '' }] }] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-1/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-1/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-1')
    const section = await screen.findByRole('region', { name: 'Exploited vulnerabilities' })
    expect(within(section).getByText(/for a domain these are the versions ZAP read on its web pages/)).toBeInTheDocument()
    expect(within(section).queryByText(/each open port of this box's own public IP/)).toBeNull()
    const table = within(section).getByRole('table', { name: "Exploited vulnerabilities that match the versions ZAP read on this domain's pages" })
    expect(within(table).getByText(/seen in the Server header by ZAP/)).toBeInTheDocument()
    expect(within(section).queryByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })).toBeNull()
    await expectNoA11yViolations()
  })

  it('a template match reads "Confirmed by template", a template that did not match reads "No match reported" and never "not vulnerable" (INV-23)', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const v = (cve: string, basis: string, template_result: string, summary: string) => ({ ip: '203.0.113.10', port: 80, cve, name: 'Apache HTTP Server Path Traversal Vulnerability', basis, date_added: '2021-11-03', ransomware: false, backport: '', template: cve, template_result, summary })
    const snap = { id: 'sn-t', date, scanned_at: at, hosts: [], ports: [{ ip: '203.0.113.10', port: 80, service: 'http' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [{ ip: '203.0.113.10', port: 80, name: 'http', product: 'Apache httpd', version: '2.4.49', cpe: 'cpe:/a:apache:http_server:2.4.49', extra: '' }],
      templates: [{ ip: '203.0.113.10', port: 80, cve: 'CVE-2021-41773', template: 'CVE-2021-41773', outcome: 'matched' }, { ip: '203.0.113.10', port: 80, cve: 'CVE-2021-42013', template: 'CVE-2021-42013', outcome: 'no_match' }],
      vulns: [v('CVE-2021-41773', 'template', 'matched', 'Confirmed by template CVE-2021-41773: the safe check got the answer of an affected service.'),
        v('CVE-2021-42013', 'version', 'no_match', 'In range. No match reported by the safe template CVE-2021-42013: that is one check, not proof that this service is not affected.')],
      version_gaps: [], web_findings: [], checks: [], not_checked: [] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    const table = await screen.findByRole('table', { name: 'Exploited vulnerabilities that match the services on this IP' })
    expect(within(within(table).getByRole('row', { name: /CVE-2021-41773/ })).getByText('Confirmed by a safe check')).toBeInTheDocument()
    const none = within(table).getByRole('row', { name: /CVE-2021-42013/ })
    expect(within(none).getByText('Version in range')).toBeInTheDocument()
    expect(within(none).getByText(/No match reported by the safe template CVE-2021-42013/)).toBeInTheDocument()
    expect(within(none).queryByText(/not vulnerable/i)).toBeNull()
  })

  it('INV-24: passive web findings in two groups, "Fix this" first then "Hardening", riskiest first, with the CWE link, three sample pages and the advice; axe clean', async () => {
    renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Web findings (passive)' })
    expect(within(section).getByText(/ZAP looked at the pages without sending forms; these are things it noticed\./)).toBeInTheDocument()
    const groups = within(section).getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
    expect(groups).toEqual(['Fix this', 'Hardening'])
    const fix = within(section).getByRole('table', { name: 'Web findings to fix' })
    const fixRows = within(fix).getAllByRole('row').slice(1)
    expect(within(fixRows[0]!).getByText('Vulnerable JS Library')).toBeInTheDocument()
    expect(within(fixRows[0]!).getByText('jquery 3.4.1')).toBeInTheDocument()
    expect(within(fixRows[0]!).getAllByRole('link', { name: /^CVE-/ }).map((a) => a.textContent)).toEqual(['CVE-2020-11022', 'CVE-2020-11023'])
    expect(within(fix).queryByText(/Content Security Policy/)).toBeNull()
    const hardening = within(section).getByRole('table', { name: 'Web hardening suggestions' })
    const rows = within(hardening).getAllByRole('row').slice(1)
    expect(within(rows[0]!).getByText('Medium')).toBeInTheDocument()
    expect(within(rows[rows.length - 1]!).getByText('Low')).toBeInTheDocument()
    expect(within(section).queryByText('Modern Web Application')).toBeNull()
    const csp = within(hardening).getAllByRole('row', { name: /Content Security Policy/ })[0]!
    expect(within(csp).getByRole('link', { name: 'CWE-693 (opens the MITRE page in a new tab)' })).toHaveAttribute('href', 'https://cwe.mitre.org/data/definitions/693.html')
    expect(within(csp).getAllByText(/^https:\/\/203\.0\.113\.10/)).toHaveLength(3)
    expect(within(csp).getByText(/configured to set the Content-Security-Policy header/)).toBeInTheDocument()
    // the alerts are not mixed into the exploited CVE table; an exploited CVE of a library version ZAP read is, with its own basis
    const vulns = screen.getByRole('table', { name: 'Exploited vulnerabilities that match the services on this IP' })
    expect(within(vulns).queryByText(/Content Security Policy/)).toBeNull()
    const js = within(vulns).getByRole('row', { name: /CVE-2020-11023/ })
    expect(within(js).getByText('JavaScript library version, seen by ZAP')).toBeInTheDocument()
    expect(within(vulns).queryByRole('row', { name: /CVE-2020-11022/ })).toBeNull()
    expect(within(screen.getByRole('list', { name: 'Checked' })).getByText(/Passive web scan \(ZAP baseline: spider and passive rules, no form sent\) of 2 pages/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('INV-24: a scan that looked at no page says why; a page with no alert does not claim the page is safe', async () => {
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-x', date, scanned_at: at, hosts: [], ports: [], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 0, admin_panels: 0, certs_expiring: 0 },
      services: [], templates: [], web_findings: [], vulns: [], version_gaps: [], checks: [] as unknown[], not_checked: [{ kind: 'web', text: 'Passive web scan (ZAP) is not set up on this box yet.' }] }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    const first = renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Web findings (passive)' })
    expect(await within(section).findByText('No page was scanned')).toBeInTheDocument()
    expect(within(section).getByText('Passive web scan (ZAP) is not set up on this box yet.')).toBeInTheDocument()
    expect(within(section).queryByRole('table')).toBeNull()
    first.unmount() // one app at a time: two mounted apps doubled the work and ran past the 1 s default wait on a busy CI runner
    snap.checks = [{ kind: 'web', text: 'Passive web scan (ZAP baseline: spider and passive rules, no form sent) of 1 page: https://203.0.113.10/. 0 alerts.', at }]
    renderApp('/exposure/xt-2')
    const again = await screen.findByRole('region', { name: 'Web findings (passive)' }, { timeout: 5000 })
    expect(await within(again).findByText('ZAP noticed nothing on the pages it looked at', {}, { timeout: 5000 })).toBeInTheDocument()
  })

  it('INV-24: a domain gets web findings for its own names', async () => {
    renderApp('/exposure/xt-1')
    const section = await screen.findByRole('region', { name: 'Web findings (passive)' })
    expect(within(section).getAllByText(/^https:\/\/(www\.)?acme\.example\//).length).toBeGreaterThan(0)
  })

  it('a domain has no vulnerability section and says where service identification runs', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('list', { name: 'Not checked' })).toBeInTheDocument()
    expect(screen.getByText(/it runs on the box's own verified public IP only, not on the names of a domain/)).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'Exploited vulnerabilities' })).toBeNull()
  })
})

describe('exposure: optional deep scan with Greenbone (S-EXP-2, INV-25)', () => {
  afterEach(() => { for (const k of ['memory', 'swap', 'disk']) localStorage.removeItem(`vedette-mock-box-${k}`) })
  const section = () => screen.findByRole('region', { name: 'Optional deep scan: OpenVAS' })

  it('off by default: shows the box\'s numbers and what it needs before Enable; an administrator enables it and it starts; axe clean', async () => {
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByText('Off')).toBeInTheDocument()
    expect(within(s).getByText('Needs about 50 GB of disk and about 2 hours to load the OpenVAS feed the first time.')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'About What OpenVAS needs' })).toHaveAccessibleDescription('The box must have at least 6 GB of memory (under 8 GB, also 2 GB of swap) and 60 GB free.')
    expect(within(s).queryByText(/uses swap/)).toBeNull()
    expect(within(s).getByText('16.0 GB')).toBeInTheDocument()
    expect(within(s).getByText('180.0 GB')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(within(s).getByRole('button', { name: 'Enable OpenVAS' }))
    expect(await within(s).findByText('Starting')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'Turn off OpenVAS' })).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.greenbone' && a.detail === 'enabled (memory 16.0 GB, free disk 180.0 GB)')).toBe(true)
    // The weekly feed update shows when the next one is due; T10: the tests' line shows once OpenVAS was read
    expect(within(s).queryByText('Vulnerability tests')).toBeNull()
    expect(within(s).getByText('Next feed update')).toBeInTheDocument()
  })

  it('a 7.1 GB box may enable it, with the swap note', async () => {
    localStorage.setItem('vedette-mock-box-memory', '7100000000')
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByText('The first feed load uses swap on a box under 8 GB.')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'About Memory of this box' })).toHaveAccessibleDescription('On a 7 GB box it used about 2 GB of swap.')
    expect(within(s).queryByRole('alert')).toBeNull()
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeEnabled()
  })

  it('under 8 GB without 2 GB of swap it is refused with both numbers; at exactly 8 GB no swap is needed and no note shows', async () => {
    localStorage.setItem('vedette-mock-box-memory', '7100000000')
    localStorage.setItem('vedette-mock-box-swap', '0')
    const { unmount } = renderApp('/exposure?tab=settings')
    let s = await section()
    expect(await within(s).findByRole('alert')).toHaveTextContent('This box has 7.1 GB of memory and 0.0 GB of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load.')
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeDisabled()
    const r = await call('PUT', '/exposure/greenbone', { enabled: true })
    expect([r.status, r.json.error.code]).toEqual([409, 'low_memory'])
    unmount()
    localStorage.setItem('vedette-mock-box-memory', '8000000000')
    renderApp('/exposure?tab=settings')
    s = await section()
    expect(await within(s).findByText('8.0 GB')).toBeInTheDocument()
    expect(within(s).queryByText(/uses swap/)).toBeNull()
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeEnabled()
  })

  it('the refusal shows the measured numbers: 5.9 GB of memory, then too little disk', async () => {
    localStorage.setItem('vedette-mock-box-memory', '5900000000')
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByRole('alert')).toHaveTextContent('This box has 5.9 GB of memory; OpenVAS needs at least 6.0 GB.')
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeDisabled()
    const r = await call('PUT', '/exposure/greenbone', { enabled: true })
    expect(r.status).toBe(409)
    expect(r.json.error.code).toBe('low_memory')
    localStorage.setItem('vedette-mock-box-memory', '8300000000')
    localStorage.setItem('vedette-mock-box-disk', '41300000000')
    const d = await call('PUT', '/exposure/greenbone', { enabled: true })
    expect([d.status, d.json.error.code, d.json.error.message]).toEqual([409, 'low_disk', 'This box has 41.3 GB of free disk space; OpenVAS needs at least 60.0 GB free.'])
  })

  it('loading its feed is a visible phase; only an administrator can change it', async () => {
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'loading', reason: 'OpenVAS is loading its feed (first time takes about 2 hours)', changed_by: 'admin@acme.example', changed_at: new Date().toISOString(),
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null }, feed: null, enabled: true })))
    renderApp('/exposure?tab=settings', { role: 'viewer' })
    const s = await section()
    expect(await within(s).findByText('OpenVAS is loading its feed (first time takes about 2 hours)')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'Turn off OpenVAS' })).toBeDisabled()
  })

  it('ready before its first weekly update: the first full feed load is done, never "not yet"', async () => {
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'ready', reason: null, changed_by: 'admin@acme.example', changed_at: '2026-11-14T13:00:00Z',
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: '2026-11-21T13:00:00Z' }, feed: null, enabled: true })))
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByText(/^First full feed load done \(OpenVAS turned on .+\); the weekly update has not run yet$/)).toBeInTheDocument()
    expect(within(s).queryByText(/^Not yet: the first one/)).toBeNull()
  })

  it('T10: shows the date of the tests OpenVAS loaded and the next update, never "not yet" for a working feed; the version is behind ⓘ', async () => {
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'ready', reason: null, changed_by: 'admin@acme.example', changed_at: '2026-11-14T12:31:49Z',
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: '2026-11-21T12:31:49Z' },
      feed: { nvt_version: '202611141200', nvt_date: '2026-11-14T12:00:00.000Z', checked_at: '2026-11-16T09:00:00.000Z' }, enabled: true })))
    renderApp('/exposure?tab=settings')
    const s = await section()
    const tests = (await within(s).findByText('Vulnerability tests')).nextElementSibling as HTMLElement
    expect(tests).toHaveTextContent(/^14 Nov 2026/)
    const next = within(s).getByText('Next feed update').nextElementSibling as HTMLElement
    expect(next).toHaveTextContent(/^21 Nov 2026, \d\d:\d\d$/)
    expect(within(s).queryByText('Last feed update')).toBeNull()
    expect(s).not.toHaveTextContent(/Not yet|not run yet|Not read/)
    expect(within(tests).getByRole('button', { name: 'About Vulnerability tests' })).toHaveAccessibleDescription(/\(version 202611141200\)\..*once a week/)
  })

  it('not available on this box: says so and offers nothing', async () => {
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'unavailable', reason: 'OpenVAS is not available on this box.', changed_by: null, changed_at: null,
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null }, feed: null, enabled: false })))
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByText('OpenVAS is not available on this box.')).toBeInTheDocument()
    expect(within(s).queryAllByRole('button').filter((b) => !b.getAttribute('aria-label')?.startsWith('About '))).toEqual([]) // only the section's ⓘ
  })

  it('results: their own section with the unauthenticated header, severity first, QoD and CVEs; Low results are hardening notes apart; axe clean', async () => {
    renderApp('/exposure/xt-2')
    const s = await screen.findByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })
    expect(within(s).getByText(/Finding nothing is not proof the services are not affected \(distributions backport fixes\)\. For the same reason, on Ubuntu or Debian a result read from a version banner can be a false positive, so Vedette's own package-based result wins when both exist\./)).toBeInTheDocument()
    const rows = within(within(s).getByRole('table', { name: 'What OpenVAS reported on this IP' })).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    expect(rows[0]!.querySelector('[data-band="critical"]')).toHaveTextContent('Critical9.8') // OpenVAS's severity is a CVSS score: FIRST's band
    expect(within(rows[0]!).getByText('99%')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('CVE-2021-41773')).toBeInTheDocument()
    expect(within(s).queryByText('2.6')).toBeNull()
    const notes = await screen.findByRole('region', { name: 'Hardening notes (Low)' })
    const noteRows = within(within(notes).getByRole('table', { name: "OpenVAS hardening notes on this IP" })).getAllByRole('row').slice(1)
    expect(noteRows).toHaveLength(1)
    expect(noteRows[0]!.querySelector('[data-band="low"]')).toHaveTextContent('Low2.6')
    expect(within(noteRows[0]!).getByText('None named')).toBeInTheDocument()
    expect(within(screen.getByRole('list', { name: 'Checked' })).getByText(/OpenVAS scanned 203\.0\.113\.10 from outside without logging in.*\(2 high or medium, 1 hardening note\)/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a scan Greenbone did not run says why under its section, and claims nothing', async () => {
    renderApp('/exposure/xt-2')
    const pick = await screen.findByRole('combobox', { name: 'Snapshot of' })
    await userEvent.selectOptions(pick, within(pick).getAllByRole('option').at(-1)!)
    const s = await screen.findByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })
    expect(await within(s).findByText('OpenVAS did not scan this time')).toBeInTheDocument()
    expect(within(s).getByText(/Optional deep scan with OpenVAS is off/)).toBeInTheDocument()
    expect(within(s).queryByRole('table')).toBeNull()
  })

  it('a domain has no Greenbone section', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('list', { name: 'Not checked' })).toBeInTheDocument()
    expect(screen.queryByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })).toBeNull()
  })
})

describe('exposure: the OpenVAS heading follows its one state, its start in the page\'s time', () => {
  const ip = '203.0.113.10'
  const started = '2026-11-14T18:16:00.000Z'
  const high = { ip, port: '443/tcp', severity: 7.5, name: 'Weak TLS', qod: 98, cves: [], solution: 'Fix TLS.', oid: '1.3.6.1.4.1.25623.1.0.1' }
  type Run = { state: string; started_at: string | null; addresses?: { ip: string; state: string }[]; stop?: { reason: string; by: string | null } }
  const showing = async (run: Run, greenbone: unknown[], not_checked: { kind: string; text: string }[]) => {
    const greenbone_run = { addresses: [], ...run }
    const at = new Date(Date.now() - 864e5).toISOString()
    const date = at.slice(0, 10)
    const snap = { id: 'sn-g', date, scanned_at: at, hosts: [], ports: [{ ip, port: 443, service: 'https' }], admin_panels: [], certs: [], counts: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 },
      services: [], templates: [], web_findings: [], vulns: [], version_gaps: [], checks: [], not_checked, greenbone, greenbone_run }
    server.use(
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => HttpResponse.json({ items: [{ id: snap.id, date, scanned_at: at, counts: snap.counts }] })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots/:date', () => HttpResponse.json(snap)),
    )
    renderApp('/exposure/xt-2')
    return screen.findByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })
  }
  // the time every other part of the page shows: the viewer's time zone, never the box's text. Pinned to a zone that is
  // not UTC (CI runs in UTC), so going back to the box's UTC text fails: 18:16 UTC is 01:16 the next day in Ho Chi Minh City (UTC+7).
  let tz: string | undefined
  beforeAll(() => { tz = process.env.TZ; process.env.TZ = 'Asia/Ho_Chi_Minh' })
  afterAll(() => { if (tz === undefined) delete process.env.TZ; else process.env.TZ = tz })
  const local = (iso: string) => { expect(iso).toBe(started); return '15 Nov 2026, 01:16' }

  it('running: "OpenVAS is scanning" with its start in the viewer\'s time zone, never "did not scan"', async () => {
    const s = await showing({ state: 'running', started_at: started }, [], [{ kind: 'greenbone', text: 'OpenVAS is scanning and runs for up to 90 minutes; its results are added here when it finishes. If none appear, it was stopped before it finished (a stop or a restart of the box).' }])
    expect(await within(s).findByText('OpenVAS is scanning')).toBeInTheDocument()
    expect(within(s).getByText(`OpenVAS started at ${local(started)} and runs for up to 90 minutes. The results of the other checks are already saved; its results are added here when it finishes.`)).toBeInTheDocument()
    expect(within(s).queryByText('OpenVAS did not scan this time')).toBeNull()
    expect(within(s).queryByRole('table')).toBeNull()
  })

  it('partial: the rows found by the 90-minute cap, with the line that says so', async () => {
    const s = await showing({ state: 'partial', started_at: started }, [high], [{ kind: 'greenbone', text: 'OpenVAS was stopped after 90 minutes; these are the results it had found by then.' }])
    expect(await within(s).findByRole('status')).toHaveTextContent('OpenVAS was stopped after 90 minutes; these are the results it had found by then.')
    expect(within(within(s).getByRole('table', { name: 'What OpenVAS reported on this IP' })).getByText('Weak TLS')).toBeInTheDocument()
    expect(within(s).getByText(`OpenVAS started at ${local(started)}.`)).toBeInTheDocument()
    expect(within(s).queryByText(/not shown/)).toBeNull()
  })

  it('partial without a high or medium row says it was stopped, not that it found nothing', async () => {
    const s = await showing({ state: 'partial', started_at: started }, [], [{ kind: 'greenbone', text: 'OpenVAS was stopped after 90 minutes; by then it had found no result with QoD 70 or more.' }])
    expect(await within(s).findByText('OpenVAS was stopped after 90 minutes')).toBeInTheDocument()
    expect(within(s).queryByText('OpenVAS reported no high or medium result with QoD 70 or more')).toBeNull()
  })

  it('a domain stopped on its second address shows the rows of the first, with the line that says so', async () => {
    const s = await showing({ state: 'stopped', started_at: started, addresses: [{ ip, state: 'done' }, { ip: '203.0.113.11', state: 'stopped' }] }, [high],
      [{ kind: 'greenbone', text: 'OpenVAS was stopped before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept.' }])
    expect(await within(s).findByRole('status')).toHaveTextContent('OpenVAS did not finish every address of this domain; these are the results it found. The "Not checked" list below says which address ended early and why.')
    expect(within(within(s).getByRole('table', { name: 'What OpenVAS reported on this IP' })).getByText('Weak TLS')).toBeInTheDocument()
    expect(within(s).queryByText(/not shown/)).toBeNull()
  })

  it('review round 2 N2: a domain whose other address finished never calls its full rows "found by then"', async () => {
    const s = await showing({ state: 'ended', started_at: started, addresses: [{ ip: '203.0.113.11', state: 'ended' }, { ip, state: 'done' }] }, [high],
      [{ kind: 'greenbone', text: "203.0.113.11 (www.acme.example): OpenVAS ended the scan before it finished: the Vedette host's domain fence stopped it while it ran." }])
    expect(await within(s).findByRole('status')).toHaveTextContent(/^OpenVAS did not finish every address of this domain; these are the results it found\./)
    expect(within(s).queryByText(/found by then/)).toBeNull()
  })

  it('review round 2 N3: a stopped run whose finished address had only hardening notes shows them', async () => {
    const low = { ...high, severity: 2.6, name: 'TCP timestamps' }
    await showing({ state: 'stopped', started_at: started, addresses: [{ ip, state: 'done' }, { ip: '203.0.113.11', state: 'stopped' }] }, [low],
      [{ kind: 'greenbone', text: 'OpenVAS was stopped before it had scanned every address; the results of the addresses it finished are shown. The results of the other checks above are kept.' }])
    const notes = await screen.findByRole('region', { name: 'Hardening notes (Low)' })
    expect(within(notes).getByText('TCP timestamps')).toBeInTheDocument()
  })

  const ended = 'OpenVAS ended the scan before it finished: OpenVAS reports it as interrupted; Vedette did not stop it.'
  it('a scan OpenVAS ended is "ended", never "did not scan"', async () => {
    const s = await showing({ state: 'ended', started_at: started }, [], [{ kind: 'greenbone', text: ended }])
    expect(await within(s).findByText('OpenVAS ended the scan before it finished')).toBeInTheDocument()
    expect(within(s).getByText(ended)).toBeInTheDocument()
    expect(within(s).queryByText('OpenVAS did not scan this time')).toBeNull()
  })

  it('the rows of a scan OpenVAS ended are shown with the line that says so', async () => {
    const s = await showing({ state: 'ended', started_at: started }, [high], [{ kind: 'greenbone', text: ended }])
    expect(await within(s).findByRole('status')).toHaveTextContent('OpenVAS ended the scan before it finished; these are the results it had found by then.')
    expect(within(s).getByRole('table', { name: 'What OpenVAS reported on this IP' })).toBeInTheDocument()
  })

  it('a domain\'s body is the line of an address in the run\'s state, not the first OpenVAS line', async () => {
    const s = await showing({ state: 'failed', started_at: started, addresses: [{ ip: '203.0.113.11', state: 'not_run' }, { ip, state: 'failed' }] }, [], [
      { kind: 'greenbone', text: '203.0.113.11 (www.acme.example): OpenVAS did not scan: this scan found no open port to check.' },
      { kind: 'greenbone', text: `${ip} (shop.acme.example): OpenVAS failed, so its results are not shown. The box log has the error.` },
    ])
    expect(await within(s).findByText('OpenVAS did not finish this scan')).toBeInTheDocument()
    expect(within(s).getByText(`${ip} (shop.acme.example): OpenVAS failed, so its results are not shown. The box log has the error.`)).toBeInTheDocument()
    expect(within(s).queryByText(/found no open port/)).toBeNull()
  })

  it('#830: the step of the running scan under its row; the OpenVAS sentence stays, its detail behind an ⓘ', async () => {
    const at = new Date().toISOString()
    const prog = (phase: string, percent: number | null) => ({ phase, percent, done: null, total: null, unit: null, started_at: at, phase_started_at: at, updated_at: at, eta: null, message: null })
    let run = { phase: 'probing', progress: prog('services', null) as unknown }
    server.use(http.get('*/api/v1/exposure/scan', () => HttpResponse.json({ id: 'sr-p', target_id: 'xt-2', target_value: ip, by: 'admin@acme.example', started_at: at, finished_at: null,
      status: 'running', snapshot_id: null, error: null, stop_reason: null, ...run })))
    renderApp('/exposure/xt-2')
    expect(await screen.findByRole('progressbar', { name: 'Identifying services' })).not.toHaveAttribute('aria-valuenow')
    expect(screen.getAllByRole('status').some((x) => x.textContent === `Scanning ${ip}`)).toBe(true)
    expect(screen.queryByText('Probing the target')).toBeNull() // the step says it better
    run = { phase: 'greenbone', progress: prog('openvas', 63) }
    expect(await screen.findByRole('progressbar', { name: 'OpenVAS deep scan' }, { timeout: 5000 })).toHaveAttribute('aria-valuenow', '63')
    expect(screen.getByText('OpenVAS scan running (up to 90 minutes)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About OpenVAS scan' })).toHaveAccessibleDescription(/other checks are already saved/)
    run = { phase: 'queued', progress: null }
    expect(await screen.findByText('Starting', {}, { timeout: 5000 })).toBeInTheDocument()
    expect(screen.queryByRole('progressbar')).toBeNull()
    await expectNoA11yViolations()
  })

  it('when the run enters the OpenVAS phase the page reads the saved snapshot again, without waiting for OpenVAS', async () => {
    const at = new Date().toISOString()
    let phase = 'probing'
    let lists = 0
    server.use(
      http.get('*/api/v1/exposure/scan', () => HttpResponse.json({ id: 'sr-gb', target_id: 'xt-2', target_value: ip, by: 'admin@acme.example', started_at: at, finished_at: null,
        status: 'running', phase, snapshot_id: null, error: null, stop_reason: null })),
      http.get('*/api/v1/exposure/targets/xt-2/snapshots', () => { lists++; return HttpResponse.json({ items: [] }) }),
    )
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Probing the target')).toBeInTheDocument()
    await waitFor(() => expect(lists).toBeGreaterThan(0))
    const before = lists
    phase = 'greenbone'
    expect(await screen.findByText(/^OpenVAS scan running/, {}, { timeout: 5000 })).toBeInTheDocument()
    await waitFor(() => expect(lists).toBeGreaterThan(before))
  })

  it.each([
    ['done', 'OpenVAS reported no high or medium result with QoD 70 or more', 'Not proof that the services are not affected: the exploited CVEs above still stand.'],
    ['not_run', 'OpenVAS did not scan this time', 'OpenVAS did not scan: this scan found no open port to check.'],
    ['failed', 'OpenVAS did not finish this scan', 'OpenVAS failed, so its results are not shown. The box log has the error.'],
    ['stopped', 'OpenVAS was stopped before it finished', 'OpenVAS was stopped before it finished (Vedette restarted), so its results are not shown. The results of the other checks above are kept.',
      'Stopped: Vedette restarted while OpenVAS ran. Its results are not shown. The results of the other checks above are kept.'],
  ])('%s: its own heading and why', async (state, title, body, shown = body) => {
    const line = state === 'done' ? [] : [{ kind: 'greenbone', text: body }]
    const s = await showing({ state, started_at: state === 'not_run' ? null : started, ...(state === 'stopped' ? { stop: { reason: 'restart', by: null } } : {}) }, [], line)
    expect(await within(s).findByText(title)).toBeInTheDocument()
    expect(within(s).getByText(new RegExp(shown.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))).toBeInTheDocument()
    for (const other of ['OpenVAS is scanning', 'OpenVAS did not scan this time', 'OpenVAS did not finish this scan', 'OpenVAS was stopped before it finished', 'OpenVAS ended the scan before it finished'].filter((x) => x !== title)) {
      expect(within(s).queryByText(other)).toBeNull()
    }
  })
})

describe('exposure: testing terms per target (S-EXP-2)', () => {
  const withTwoStep = (on: boolean) => usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: on } : x)))

  it('one screen says what each tool may send and the risk; the disruptive tick is its own box, off by default; axe clean', async () => {
    renderApp('/exposure/xt-1?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(within(s).getByText('Not accepted: scans of this target stay in the Scan now scope.')).toBeInTheDocument()
    const terms = within(s).getByRole('group', { name: 'Testing terms' })
    expect(within(terms).getByText(/^I confirm that my company owns acme\.example and that I am authorized to test it in depth/)).toBeInTheDocument()
    expect(within(terms).getAllByRole('listitem').map((l) => l.textContent?.split(':')[0])).toEqual(['All ports', 'Vulnerability checks', 'Web scanning', 'Authentication checks'])
    expect(within(terms).getByText(/including checks that confirm a flaw by sending the exploit request itself in a harmless form.*Some checks, OpenVAS's in particular, may write a harmless test file or record.*Checks that can crash a service, guess passwords or sign in with default passwords, and the exploit checks of nuclei and nmap that send more than a harmless read, run only with the disruptive checks below\./)).toBeInTheDocument()
    expect(within(terms).getByText(/The deep scan can load or slow the services on acme\.example and may create, change or delete data/)).toBeInTheDocument()
    const tick = within(s).getByRole('checkbox', { name: "Include disruptive checks (denial of service, password guessing, sign-in attempts with default or well-known passwords, and exploit checks that send more than a harmless read, such as nuclei's POST exploit requests that may create or change data and nmap's SQL injection probes): these can crash a service, lock accounts, change data or take a device offline." })
    expect(tick).not.toBeChecked()
    await expectNoA11yViolations()
  })

  it('an administrator with two-step accepts, adds the tick, then withdraws; each is audited with the flag', async () => {
    withTwoStep(true)
    renderApp('/exposure/xt-1?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    await userEvent.click(within(s).getByRole('button', { name: 'Accept the testing terms' }))
    expect(await within(s).findByText(/^Accepted by admin@acme\.example.*Every scan of this target is a deep scan\. Disruptive checks are not included\./)).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.terms_accept' && a.detail?.startsWith('accepted (disruptive checks: no'))).toBe(true)
    await userEvent.click(within(s).getByRole('checkbox'))
    await userEvent.click(within(s).getByRole('button', { name: 'Accept with this choice' }))
    expect(await within(s).findByText(/Disruptive checks are included\./)).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.terms_accept' && a.detail?.includes('(disruptive checks: yes'))).toBe(true)
    await userEvent.click(within(s).getByRole('button', { name: 'Withdraw' }))
    expect(await within(s).findByText('Not accepted: scans of this target stay in the Scan now scope.')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.terms_revoke')).toBe(true)
  })

  it('behind carrier-grade NAT the step warns and the disruptive tick cannot be ticked', async () => {
    const v = (await call('GET', '/exposure/targets/xt-2')).json as Record<string, unknown>
    const warning = 'This box reaches the Internet through carrier-grade NAT (its gateway 100.64.0.1 is in 100.64.0.0/10), so 203.0.113.10 is probably shared with your provider\'s other customers and its open ports are the provider\'s. The disruptive checks cannot be accepted for it; accept the deep scan only if your provider confirms the address is yours alone.'
    server.use(http.get('*/api/v1/exposure/targets/xt-2', () => HttpResponse.json({ ...v, terms_warning: warning })))
    renderApp('/exposure/xt-2?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(await within(s).findByRole('alert')).toHaveTextContent(warning)
    expect(within(s).getByRole('checkbox')).toBeDisabled()
    expect(within(s).queryByText(/Vedette can tell carrier-grade NAT only when/)).toBeNull()
    expect(within(s).getByText(/is yours alone: not an address shared through your Internet provider \(carrier-grade NAT\)/)).toBeInTheDocument()
  })

  it('without a warning, an IP target says what Vedette cannot see', async () => {
    renderApp('/exposure/xt-2?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(await within(s).findByText("If your router gets its address from your provider's shared range, ask your provider before accepting.")).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'About Carrier-grade NAT' })).toHaveAccessibleDescription("Vedette can tell carrier-grade NAT only when this box's own gateway is in 100.64.0.0/10; it cannot see your router's outside address.")
    expect(within(s).getByRole('checkbox')).toBeEnabled()
  })

  it('a run the box stopped because the terms were withdrawn says why', async () => {
    const at = new Date().toISOString()
    server.use(http.get('*/api/v1/exposure/scan', () => HttpResponse.json({ id: 'sr-1', target_id: 'xt-2', target_value: '203.0.113.10', by: 'admin@acme.example', started_at: at, finished_at: at,
      status: 'stopped', phase: 'greenbone', snapshot_id: 'sn-1', error: null, stop_reason: 'the testing terms of this target were withdrawn' })))
    renderApp('/exposure/xt-2')
    expect(await screen.findByText(/The OpenVAS part of the scan of 203\.0\.113\.10 was stopped\..*The box stopped it because the testing terms of this target were withdrawn\./)).toBeInTheDocument()
  })

  it('without two-step the acceptance is refused; a stale version is 409; a viewer cannot accept', async () => {
    withTwoStep(false)
    const v = (await call('GET', '/exposure/targets/xt-1')).json as { terms_notice: { version: string } }
    expect((await call('PUT', '/exposure/targets/xt-1/terms', { version: v.terms_notice.version, disruptive: false })).json.error.code).toBe('twofa_required')
    withTwoStep(true)
    expect((await call('PUT', '/exposure/targets/xt-1/terms', { version: 'old', disruptive: false })).json.error.code).toBe('notice_changed')
    renderApp('/exposure/xt-1?tab=ownership', { role: 'viewer' })
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(within(s).getByRole('button', { name: 'Accept the testing terms' })).toBeDisabled()
  })
})

describe('exposure: deep scan of a domain\'s addresses (S-EXP-2)', () => {
  const withTwoStep = (on: boolean) => usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: on } : x)))

  it('LEGAL-2: a domain\'s terms say the scan reaches third-party hosting, CDN or proxy, name the tools and the customer\'s responsibility; an IP keeps "yours alone"', async () => {
    renderApp('/exposure/xt-1?tab=ownership')
    const terms = within(await screen.findByRole('region', { name: 'Testing terms (deep scan)' })).getByRole('group', { name: 'Testing terms' })
    for (const sentence of [
      'Every name under acme.example that resolves to a public address is scanned at this depth, whatever serves it: your own server, a hosting provider or a CDN.',
      'If a provider serves a name, its testing policy applies to you (for example, Cloudflare and AWS forbid denial-of-service tests); leave the disruptive checks off unless that provider allows them.',
      "Vedette's tools reach each address a name under acme.example resolves to, including a third-party hosting provider, CDN or proxy in front of your names: the scan of all ports, OpenVAS, nuclei and the web scan (ZAP).",
      "With shared or cloud hosting, a CDN or a proxy, that address can also serve other people's systems: you are responsible for having the provider's permission.",
      'Vedette does not check who owns those addresses.',
    ]) expect(terms.textContent).toContain(sentence)
    expect(terms.textContent).not.toContain('yours alone')
    const ip = (await call('GET', '/exposure/targets/xt-2')).json as { terms_notice: { text: string; version: string } }
    expect(ip.terms_notice.version).toBe('2026-11-18b')
    expect(ip.terms_notice.text).toContain('Accept only if 203.0.113.10 is yours alone')
    // the terms say the box also scans on the schedule, never with the disruptive checks
    expect(ip.terms_notice.text).toContain('Vedette also scans 203.0.113.10 by itself on the schedule set on its page (weekly unless changed), never with the disruptive checks below, until that schedule is turned off.')
    expect(ip.terms_notice.text).not.toContain('Verifying a name')
  })

  it('with the terms accepted, Scan now deep-scans 3 addresses, the rest wait in line; Results show each address with its names, the Surface tab counts and notes; axe clean', async () => {
    withTwoStep(true)
    const v = (await call('GET', '/exposure/targets/xt-1')).json as { terms_notice: { version: string } }
    expect((await call('PUT', '/exposure/targets/xt-1/terms', { version: v.terms_notice.version, disruptive: false })).status).toBe(200)
    renderApp('/exposure/xt-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Deep scan now' })) // #850: the terms make it a deep scan, and the button says so
    expect(await screen.findByText('Scan of acme.example finished. The new result is below.', {}, { timeout: 8000 })).toBeInTheDocument()
    const deep = await screen.findByRole('table', { name: "Addresses of this domain's names and their deep scan" }, { timeout: 5000 })
    const row = (ip: string) => within(deep).getByRole('row', { name: new RegExp(`^${ip.replaceAll('.', '\\.')} `) })
    expect(within(row('198.51.100.30')).getByText('cdn.acme.example')).toBeInTheDocument()
    expect(within(row('198.51.100.30')).getByText('Scanned this run')).toBeInTheDocument()
    expect(within(row('203.0.113.20')).getByText('www.acme.example')).toBeInTheDocument() // two names, one address
    expect(within(row('203.0.113.20')).getByText('acme.example')).toBeInTheDocument()
    expect(within(row('203.0.113.22')).getByText('Next in line')).toBeInTheDocument()
    expect(within(row('203.0.113.22')).getByText(/Number 1 in line\. Never deep-scanned\./)).toBeInTheDocument()
    expect(within(deep).queryByText('10.20.0.5')).toBeNull() // private: never dialed, not a deep row
    expect(within(screen.getByRole('table', { name: 'Services identified on the open ports (nmap -sV)' })).getAllByText('198.51.100.30').length).toBeGreaterThan(0) // each service says its address
    expect(within(screen.getByRole('list', { name: 'Not checked' })).getByText('203.0.113.22 (vpn.acme.example): not scanned this run (at most 3 addresses get the deep scan in one run), never scanned at depth; next in line (1).')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(screen.getByRole('tab', { name: 'Surface' }))
    const table = await screen.findByRole('table', { name: 'Names under this domain and their addresses' })
    expect(within(within(table).getByRole('row', { name: /^cdn\.acme\.example/ })).getByText(/^Deep-scanned at the testing terms depth, /)).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /^staging\.acme\.example/ })).getByText(/^Not scanned this run \(at most 3 addresses a run\): next in line \(2\)\. Never deep-scanned\./)).toBeInTheDocument()
    expect(screen.getByText('Addresses deep-scanned this run').nextSibling?.textContent).toBe('3')
    expect(screen.getByText('Addresses next in line').nextSibling?.textContent).toBe('3')
    const lines = within(screen.getByRole('list', { name: 'Not checked on the surface' }))
    expect(lines.getByText('Private addresses (1 address): listed, never contacted.')).toBeInTheDocument()
    expect(lines.getByText('IPv6 addresses (1 listed): IPv6 is not scanned yet.')).toBeInTheDocument()
    expect(lines.queryByText(/checked by name on ports 80 and 443 only/)).toBeNull()
    await expectNoA11yViolations()
  })

  it('the line under Scan now and the Results intro say what the scan does: Scan now scope, then the deep scan with or without the disruptive checks', async () => {
    withTwoStep(true)
    setEgress('203.0.113.10')
    expect((await call('DELETE', '/exposure/targets/xt-2/terms')).status).toBe(200) // the sample IP has them accepted
    const view = renderApp('/exposure/xt-2')
    expect(await screen.findByText('Scan now scope (testing terms not accepted): non-intrusive, no exploitation, no disruption. Aimed only at this target.')).toBeInTheDocument()
    expect(await screen.findByText(/^Ports are scanned only on this box's own verified public IPs: nmap's 1,000 most common TCP ports and a fixed list of commonly exposed ones, then the service behind each open port\. A domain's names get one check/)).toBeInTheDocument()
    view.unmount()
    const v = (await call('GET', '/exposure/targets/xt-2')).json as { terms_notice: { version: string } }
    expect((await call('PUT', '/exposure/targets/xt-2/terms', { version: v.terms_notice.version, disruptive: true })).status).toBe(200)
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Deep scan: the testing terms of this IP are accepted. Disruptive checks are included.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About Scan depth' })).toHaveAccessibleDescription(/Denial of service, password guessing, default-password sign-ins and exploit checks that send more than a harmless read\./)
    expect(screen.queryByText(/Non-intrusive|no exploitation/)).toBeNull()
    expect(await screen.findByText(/^Deep scan \(testing terms accepted\): every TCP port of this IP/)).toBeInTheDocument()
    expect(screen.queryByText(/Ports are scanned only on this box/)).toBeNull()
  })

  it('a domain with accepted terms (no disruptive tick) says its names are deep-scanned at every address they resolve to', async () => {
    withTwoStep(true)
    const v = (await call('GET', '/exposure/targets/xt-1')).json as { terms_notice: { version: string } }
    expect((await call('PUT', '/exposure/targets/xt-1/terms', { version: v.terms_notice.version, disruptive: false })).status).toBe(200)
    renderApp('/exposure/xt-1')
    expect(await screen.findByText('Deep scan: the testing terms of this domain are accepted. Disruptive checks are not included.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'About Scan depth' })).toHaveAccessibleDescription(/^Every public IPv4 address a name under it resolves to is scanned/)
    expect(await screen.findByText(/^Deep scan \(testing terms accepted\): each public IPv4 address a name under this domain resolves to gets every TCP port/)).toBeInTheDocument()
  })

  it('a box without the domain fence, and a refused re-check, say so on the Surface tab and under Results; axe clean', async () => {
    const at = new Date().toISOString()
    const date = at.slice(0, 10)
    const ip = (a: string, deep: string) => ({ ip: a, family: 'ipv4', class: 'public', contacted: true, deep })
    const fence = "Addresses of names under this domain that are not this box's (198.51.100.30): not scanned at depth: this box needs the Vedette host's domain fence (update the box). Their names are checked by name on ports 80 and 443 only."
    server.use(
      http.get('*/api/v1/exposure/targets/xt-1/snapshots', () => HttpResponse.json({ items: [{ id: 'sn-f', date, scanned_at: at, counts: { subdomains: 3, ips: 3, ports: 0, admin_panels: 0, certs_expiring: 0 } }] })),
      http.get('*/api/v1/exposure/targets/xt-1/snapshots/:date', () => HttpResponse.json({ id: 'sn-f', date, scanned_at: at, ports: [], admin_panels: [], certs: [], services: [], templates: [], checks: [], web_findings: [], greenbone: [], vulns: [], version_gaps: [],
        hosts: [{ name: 'cdn.acme.example', ip: '198.51.100.30', source: 'ct', ips: [ip('198.51.100.30', 'fence')] }, { name: 'shop.acme.example', ip: '198.51.100.31', source: 'ct', ips: [ip('198.51.100.31', 'refused')] },
          { name: 'api.acme.example', ip: '198.51.100.32', source: 'ct', ips: [ip('198.51.100.32', 'incomplete')] }],
        not_checked: [{ kind: 'deep', text: fence }, { kind: 'deep', text: '198.51.100.31 (shop.acme.example): not scanned at depth: no name under this domain resolves to this address any more (looked up right before the step), so nothing was sent.' }],
        counts: { subdomains: 2, ips: 2, ports: 0, admin_panels: 0, certs_expiring: 0 } })),
    )
    renderApp('/exposure/xt-1')
    const deep = await screen.findByRole('table', { name: "Addresses of this domain's names and their deep scan" })
    expect(within(deep).getByText('Needs the domain fence')).toBeInTheDocument()
    expect(within(deep).getByText('Refused at the check')).toBeInTheDocument()
    expect(within(deep).getByText('Not finished')).toBeInTheDocument() // nmap did not finish: not "scanned"
    await expectNoA11yViolations()
    await userEvent.click(screen.getByRole('tab', { name: 'Surface' }))
    const table = await screen.findByRole('table', { name: 'Names under this domain and their addresses' })
    expect(within(table).getByText("Checked by name only: the deep scan of an address that is not this box's needs the Vedette host's domain fence (update the box).")).toBeInTheDocument()
    expect(within(table).getByText('Not scanned at depth: the check right before the scan refused it, so nothing was sent (see Not checked).')).toBeInTheDocument()
    expect(within(table).getByText(/^Tried at depth, but service identification did not finish/)).toBeInTheDocument()
    expect(within(screen.getByRole('list', { name: 'Not checked on the surface' })).getByText(fence)).toBeInTheDocument()
    expect(screen.getByText('Addresses deep-scanned this run').nextSibling?.textContent).toBe('0')
    await expectNoA11yViolations()
  })
})

describe('exposure: one page style (S-UI-1)', () => {
  it('the list has a KPI strip and two tabs, Targets and Settings; the old Open exposures and What the Internet sees links land on Targets with a note; old #anchors land on their tab', async () => {
    const view = renderApp('/exposure')
    const strip = await screen.findByRole('list', { name: 'External exposure at a glance' })
    expect(within(strip).getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual(['/exposure?tab=targets', '/exposure?tab=targets', '/exposure?tab=targets'])
    expect(screen.getAllByRole('tab').map((x) => x.textContent?.trim())).toEqual(['Targets', 'Settings'])
    expect(screen.getByRole('tab', { name: 'Targets', selected: true })).toBeInTheDocument()
    expect(screen.queryByText(/are now on each target/)).toBeNull()
    view.unmount()
    for (const tab of ['open', 'outside']) {
      const v = renderApp(`/exposure?tab=${tab}`)
      expect(await screen.findByRole('tab', { name: 'Targets', selected: true })).toBeInTheDocument()
      expect(screen.getByText('Open exposures and What the Internet sees are now on each target.')).toBeInTheDocument()
      v.unmount()
    }
    for (const [hash, tab] of [['open', 'Targets'], ['box-ip', 'Settings'], ['box-ignored', 'Settings'], ['greenbone', 'Settings'], ['outside-list', 'Targets']] as const) {
      const v = renderApp(`/exposure?x=1#${hash}`)
      expect(await screen.findByRole('tab', { name: tab, selected: true })).toBeInTheDocument()
      v.unmount()
    }
  })

  it('Settings holds the public-IP auto-detect, the Ignored IPs, OpenVAS and a link to the shared scan settings', async () => {
    renderApp('/exposure?tab=settings')
    expect(await screen.findByRole('heading', { name: 'Public IP of this box' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Ignored IPs' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /OpenVAS/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Settings, Scanning' })).toHaveAttribute('href', '/settings/scanning')
  })

  it('the open-exposures tile opens the one target that has some', async () => {
    const items = ((await call('GET', '/exposure/targets')).json.items as { id: string }[]).map((x) => ({ ...x, open_exposures: x.id === 'xt-2' ? 3 : 0 }))
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items, box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [] })))
    renderApp('/exposure')
    const strip = await screen.findByRole('list', { name: 'External exposure at a glance' })
    expect(within(strip).getByRole('link', { name: /open exposures/ })).toHaveAttribute('href', '/exposure/xt-2?tab=exposures')
  })

  it('a target page has Results / Open exposures / Ownership, an IP page also Outside view; a domain page has no Outside view; old #anchors land on their tab', async () => {
    const ip = renderApp('/exposure/xt-2')
    expect(await screen.findByRole('tab', { name: 'Outside view' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: /Open exposures/ })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Results', selected: true })).toBeInTheDocument()
    ip.unmount()
    const v = renderApp('/exposure/xt-2#step-verify')
    expect(await screen.findByRole('tab', { name: 'Ownership', selected: true })).toBeInTheDocument()
    v.unmount()
    const o = renderApp('/exposure/xt-2#open')
    expect(await screen.findByRole('tab', { name: /Open exposures/, selected: true })).toBeInTheDocument()
    o.unmount()
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('tab', { name: 'Ownership' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Outside view' })).not.toBeInTheDocument()
  })
})

describe('exposure: what the Internet sees, Shodan InternetDB (S-EXP-1)', () => {
  it('shows Shodan\'s ports beside our own scan, the differences called out, and Shodan\'s CVEs as its claim; axe clean', async () => {
    renderApp('/exposure/xt-2?tab=outside')
    expect(await screen.findByRole('heading', { name: 'What the Internet sees' })).toBeInTheDocument()
    const answer = await screen.findByTestId('outside-answer')
    expect(within(answer).getByText('Shodan and our scan both saw 443 open.')).toBeInTheDocument()
    expect(within(answer).getByText('Shodan saw 10443 open; our scan did not.')).toBeInTheDocument()
    expect(within(answer).getByText('Seen only from outside')).toBeInTheDocument()
    expect(within(answer).getByText('Our scan saw 18443 open; Shodan did not.')).toBeInTheDocument()
    expect(within(answer).getByRole('link', { name: 'CVE-2023-27997' })).toHaveAttribute('href', '/cve/CVE-2023-27997')
    expect(within(answer).getByText('self-signed')).toBeInTheDocument()
    expect(within(answer).getByText(/Shodan updates this data about once a week/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('nothing is sent before Send: the confirm step says what goes to Shodan; Cancel sends nothing; Send sends one request', async () => {
    const posts: string[] = []
    server.events.on('request:start', ({ request }) => { if (request.method === 'POST' && new URL(request.url).pathname.endsWith('/outside')) posts.push(request.url) })
    const user = userEvent.setup()
    renderApp('/exposure/xt-6?tab=outside')
    expect(await screen.findByText(/Vedette has not asked Shodan about 203\.0\.113\.11/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Check what Shodan has seen' }))
    const dialog = await screen.findByRole('dialog', { name: 'Send 203.0.113.11 to Shodan?' })
    expect(within(dialog).getByText('Your public IP 203.0.113.11 is sent to Shodan (internetdb.shodan.io). Shodan learns that someone asked about it. Nothing else is sent to Shodan.')).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'About Send 203.0.113.11 to Shodan?' })).toHaveAccessibleDescription('First the box may re-check that it still goes out through 203.0.113.11 (the same check as before a scan).')
    expect(posts).toEqual([])
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument())
    expect(posts).toEqual([])
    await user.click(screen.getByRole('button', { name: 'Check what Shodan has seen' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Send' }))
    expect(await screen.findByText('Shodan has no record of 203.0.113.11: it has not seen an open port there.')).toBeInTheDocument()
    expect(posts).toHaveLength(1)
    expect(auditStore.get()[0]).toMatchObject({ action: 'exposure.outside_view', target: '203.0.113.11' })
    // At most once a minute on the box; only an administrator sends; a domain is never sent.
    expect((await call('POST', '/exposure/targets/xt-6/outside')).status).toBe(429)
    expect((await call('POST', '/exposure/targets/xt-6/outside', undefined, 'operator')).status).toBe(403)
    expect((await call('POST', '/exposure/targets/xt-1/outside')).json.error.code).toBe('bad_value')
  })

  it('a viewer sees the answer but cannot send', async () => {
    renderApp('/exposure/xt-2?tab=outside', { role: 'viewer' })
    expect(await screen.findByTestId('outside-answer')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Check again' })).toBeDisabled()
  })

  it('a domain has no outside view', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('heading', { level: 2, name: 'Scan results' })).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'What the Internet sees' })).not.toBeInTheDocument()
  })
})

describe('exposure: scheduled scans and the scan queue (S-EXP-1)', () => {
  it('the target page sets how often the box scans it; the list says when next, or that the schedule is off', async () => {
    renderApp('/exposure/xt-2')
    const every = await screen.findByRole('combobox', { name: 'Scheduled scan' })
    expect(every).toHaveValue('weekly') // every target starts weekly
    expect(screen.getByText(/^Next scan /)).toBeInTheDocument()
    await userEvent.selectOptions(every, 'off')
    expect(await screen.findByText('Schedule off')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.schedule' && a.detail === 'off (was weekly)')).toBe(true)
    cleanup()
    renderApp('/exposure')
    const row = within(await targetsTable()).getByRole('row', { name: /203\.0\.113\.10/ })
    expect(within(row).getByText('Schedule off')).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('a target without accepted testing terms says it is not scanned on schedule, and why; a viewer cannot change it', async () => {
    renderApp('/exposure/xt-1', { role: 'viewer' })
    expect(await screen.findByText('Not scanned on schedule: the testing terms are not accepted')).toBeInTheDocument()
    expect(screen.getByRole('combobox', { name: 'Scheduled scan' })).toBeDisabled()
    cleanup()
    expect((await call('PUT', '/exposure/targets/xt-1/schedule', { every: 'daily' }, 'operator')).status).toBe(403)
    expect((await call('PUT', '/exposure/targets/xt-1/schedule', { every: 'hourly' })).json.error.code).toBe('bad_value')
  })

  it('while another target is scanned this page says so (no Stop of that scan here); Scan now queues this one, shows its place and can take it out', async () => {
    const at = new Date().toISOString()
    const runA = { id: 'sr-a', target_id: 'xt-1', target_value: 'acme.example', by: 'admin@acme.example', started_at: at, finished_at: null, status: 'running', phase: 'probing', snapshot_id: null, error: null, progress: null }
    let queue: unknown[] = []
    server.use(
      http.get('*/api/v1/exposure/scan', () => HttpResponse.json({ ...runA, queue })),
      http.post('*/api/v1/exposure/targets/xt-2/scan', () => {
        queue = [{ target_id: 'xt-2', target_value: '203.0.113.10', by: 'admin@acme.example', queued_at: at, scheduled: false, starting: false }]
        return HttpResponse.json({ ...runA, id: 'sr-b', target_id: 'xt-2', target_value: '203.0.113.10', status: 'queued', phase: 'queued', queue }, { status: 202 })
      }),
      http.delete('*/api/v1/exposure/targets/xt-2/queue', () => { queue = []; return new HttpResponse(null, { status: 204 }) }),
    )
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Another target is being scanned (acme.example). A scan of this target now waits in the queue until it ends.')).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Stop' })).toBeNull()
    expect(screen.queryByText('Scanning acme.example')).toBeNull()
    await userEvent.click(screen.getByRole('button', { name: 'Deep scan now' }))
    expect(await screen.findByText('Queued: starts after acme.example')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deep scan now' })).toBeDisabled()
    await userEvent.click(screen.getByRole('button', { name: 'Remove from queue' }))
    expect(await screen.findByText('The scan of 203.0.113.10 was removed from the queue.')).toBeInTheDocument()
    await waitFor(() => expect(screen.queryByText('Queued: starts after acme.example')).toBeNull())
  })
})
