import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { auditStore, modulesStore, sessionStore, usersStore } from '@/mocks/stores'
import { NOTICE_VERSION } from './contract'
import { feature } from './index'
import { portLabel, riskOf } from './services'

const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
async function call(method: string, path: string, body?: unknown, role: keyof typeof USER = 'admin') {
  sessionStore.set({ userId: USER[role] })
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  return { status: res.status, json: (await res.json().catch(() => null)) as any } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const setEgress = (ip: string | null) => { if (ip) localStorage.setItem('vedette-mock-egress', ip); else localStorage.removeItem('vedette-mock-egress') }
beforeEach(() => setEgress(null))
afterEach(() => vi.useRealTimers())
const targetsTable = () => screen.findByRole('table', { name: 'Declared domains' })
const ipTable = () => screen.findByRole('table', { name: 'Public IPs of this box' })

describe('exposure: list (S-EXP-1)', () => {
  it('first sentence counts exposed admin interfaces; the table says why a target cannot be scanned; axe clean', async () => {
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: '2 admin interfaces are exposed to the Internet' })).toBeInTheDocument()
    const table = await targetsTable()
    expect(within(table).getAllByRole('row')).toHaveLength(4) // header + the three domains; public IPs have their own table
    const demo = within(table).getByRole('row', { name: /acme-demo\.example/ })
    expect(within(demo).getByText('Awaiting ownership proof')).toBeInTheDocument()
    expect(within(demo).getByText('Needs ownership proof')).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /old-site\.example/ })).getByText('TXT record missing')).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /^acme\.example/ })).getByText('Ready to scan')).toBeInTheDocument()
    // The IPs the box found: two valid (load balancer), one it has not seen for 26 days (expiring), one not seen for 40 days (expired).
    const ips = await ipTable()
    expect(within(ips).getAllByRole('row')).toHaveLength(5)
    expect(within(within(ips).getByRole('row', { name: /203\.0\.113\.10/ })).getByText('Ownership verified')).toBeInTheDocument()
    expect(within(within(ips).getByRole('row', { name: /203\.0\.113\.11/ })).getByText('Ownership verified')).toBeInTheDocument()
    expect(within(within(ips).getByRole('row', { name: /203\.0\.113\.12/ })).getByText('Expires in 4 days')).toBeInTheDocument()
    expect(within(within(ips).getByRole('row', { name: /203\.0\.113\.55/ })).getAllByText('Verification expired').length).toBeGreaterThan(0)
    expect(screen.getByText(/Only what you have proven you own and confirmed is scanned/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('adds a domain, lowercases it and goes to its verification page', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), 'Shop.Acme.Example')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'shop.acme.example cannot be scanned yet: awaiting ownership proof' })).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.target_add' && a.target === 'shop.acme.example')).toBe(true)
  })

  it.each([
    ['', /Enter a domain, for example example\.com/],
    ['https://acme.example/admin', /without http:\/\/, a path/],
    ['203.0.113.5', /Public IPs are not typed in/],
    ['not-a-domain', /Not a valid domain/],
    ['acme.example', /acme\.example is already in the list/],
  ])('rejects "%s" and says how to fix it', async (value, message) => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }))
    const input = screen.getByRole('textbox', { name: 'Domain' })
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
    expect(screen.getAllByText(/Select Detect now to look right away/).length).toBeGreaterThan(0)
  })

  it('W1-23: with no admin page, the first sentence says what is open and SIP is called out with "is that on purpose?"', async () => {
    const at = '2026-11-13T06:02:00.000Z'
    const ip = { id: 't-ip', kind: 'ip', value: '203.0.113.10', status: 'verified', method: 'box_egress', token: '', verified_at: at, expires_at: '2026-12-13T06:02:00.000Z', validity: 'valid', last_check: null,
      commitment: { by: 'An', at }, scannable: true, blocked_reason: null, created_at: at, last_scan_at: at,
      latest: { subdomains: 0, ips: 1, ports: 2, admin_panels: 0, certs_expiring: 0 },
      open_ports: [{ ip: '203.0.113.10', port: 5060, service: 'sip' }, { ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }] }
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [ip], box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [] })))
    renderApp('/exposure?tab=open')
    expect(await screen.findByRole('heading', { level: 1, name: '2 ports are open to the Internet: SIP 5060, HTTPS 10443' })).toBeInTheDocument()
    const open = screen.getByRole('region', { name: '2 ports open to the Internet' })
    expect(within(open).getAllByText('Commonly attacked')).toHaveLength(1) // SIP only; HTTPS is not called out
    expect(within(open).getByText(/toll fraud.*Is that on purpose\?/)).toBeInTheDocument()
    expect(within(open).getByText('answers as nginx')).toBeInTheDocument()
    // a service name from the network never finds Object.prototype
    expect([riskOf({ service: 'constructor' }), portLabel({ service: 'constructor', port: 1 })]).toEqual([null, 'CONSTRUCTOR 1'])
  })

  const gwTarget = () => {
    const at = '2026-11-13T06:02:00.000Z'
    return { id: 't-ip', kind: 'ip', value: '203.0.113.10', status: 'verified', method: 'box_egress', token: '', verified_at: at, expires_at: '2026-12-13T06:02:00.000Z', validity: 'valid', last_check: null,
      commitment: { by: 'An', at }, scannable: true, blocked_reason: null, created_at: at, last_scan_at: at,
      latest: { subdomains: 0, ips: 1, ports: 1, admin_panels: 0, certs_expiring: 0 }, open_ports: [{ ip: '203.0.113.10', port: 10443, service: 'https', product: 'nginx' }] }
  }
  it.each([
    ['known with findings', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 2 },
      'These ports are answered by your gateway fortigate-hq (192.168.18.1), or a device it forwards them to. fortigate-hq has 2 open exploited vulnerabilities: fix these first.', '/findings?device=d-gw'],
    ['known with one finding', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 1 },
      'These ports are answered by your gateway fortigate-hq (192.168.18.1), or a device it forwards them to. fortigate-hq has 1 open exploited vulnerability: fix these first.', '/findings?device=d-gw'],
    ['known without findings', { ip: '192.168.18.1', device_id: 'd-gw', name: 'fortigate-hq', open_exploited: 0 },
      'These ports are answered by your gateway fortigate-hq (192.168.18.1), or a device it forwards them to. Vedette knows of no open exploited vulnerability on fortigate-hq; that does not prove the device it forwards to is safe.', null],
    ['gateway not in the device list', { ip: '192.168.18.1', device_id: null, name: null, open_exploited: 0 },
      'These ports are answered by your gateway (192.168.18.1), or a device it forwards them to. Your gateway is not in your device list yet, so Vedette cannot say what is exploited on it. Scan your network to add it.', null],
    ['gateway unknown', { ip: null, device_id: null, name: null, open_exploited: 0 },
      'Vedette cannot see which gateway your network uses from here, so it cannot say which device answers these ports.', null],
  ])('D-492: open ports and the gateway, %s', async (_n, gateway, text, href) => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [gwTarget()], box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [], gateway })))
    renderApp('/exposure?tab=open')
    const note = await screen.findByTestId('gateway-note')
    expect(within(note).getByText(text)).toBeInTheDocument()
    if (href) expect(within(note).getByRole('link')).toHaveAttribute('href', href)
    else expect(within(note).queryByRole('link')).toBeNull()
  })

  it('D-492: no gateway note when the server sends none', async () => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [gwTarget()], box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [], gateway: null })))
    renderApp('/exposure?tab=open')
    await screen.findByRole('region', { name: '1 port open to the Internet' })
    expect(screen.queryByTestId('gateway-note')).toBeNull()
  })

  it('module off says where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'exposure' ? { ...m, enabled: false } : m)))
    renderApp('/exposure?tab=open')
    expect(await screen.findByText('External surface module is off')).toBeInTheDocument()
  })

  it('registers the sidebar entry in the right group', () => {
    expect(feature.nav?.[0]).toMatchObject({ to: '/exposure', group: 'assets', order: 20, module: 'exposure' })
  })
})

describe('exposure: a verified and confirmed domain', () => {
  it('shows subdomains, ports, admin interfaces and expiring certificates; axe clean', async () => {
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('heading', { level: 1, name: 'acme.example: 5 subdomain(s), 2 admin interface(s) exposed to the Internet' })).toBeInTheDocument()
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
    expect(await screen.findByRole('heading', { level: 1, name: 'acme.example: 6 subdomain(s), 3 admin interface(s) exposed to the Internet' })).toBeInTheDocument()
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

  it('with the Vulnerability scans module off, "Scan now" says so and saves nothing (D-229)', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'scan' ? { ...m, enabled: false } : m)))
    const before = (await call('GET', '/exposure/targets/xt-1/snapshots')).json.items.length
    renderApp('/exposure/xt-1')
    await userEvent.click(await screen.findByRole('button', { name: 'Scan now' }))
    expect(await screen.findByText('The Vulnerability scans module is off, so the box cannot scan. An admin can turn it on in Settings, Modules.')).toBeInTheDocument()
    expect((await call('GET', '/exposure/targets/xt-1/snapshots')).json.items.length).toBe(before)
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
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/was not found on acme-demo\.example/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/Verified with a DNS TXT record/)).toBeInTheDocument()
    // verified but not confirmed: the administrator sees the sentence beside an enabled button (the server decides about two-step, D-473)
    expect(await screen.findByRole('note', { name: 'Pressing Scan now records this confirmation' })).toBeInTheDocument()
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
  it('no IP input: typing an IP is refused and points to the box', async () => {
    const r = await call('POST', '/exposure/targets', { value: '198.51.100.7' })
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('ip_not_allowed')
    expect(r.json.error.message).toMatch(/Detect now/)
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

describe('exposure: auto-detect of the box public IPs (kien 2026-11-09)', () => {
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

  it.each([1, 15, 60, 1440])('accepts an interval of %i minutes and audits the change', async (n) => {
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

  it('the panel: first line says what the box does; the list shows last seen, expiry and a way to remove each IP; axe clean', async () => {
    renderApp('/exposure')
    expect(await screen.findByText('Auto-detect is on: the box checks its public IPs every hour.')).toBeInTheDocument()
    expect(screen.getByText(/The box reaches the Internet via 2 public IPs: 203\.0\.113\.10, 203\.0\.113\.11/)).toBeInTheDocument()
    const ips = await ipTable()
    for (const col of ['Public IP', 'Status', 'Last seen', 'Expires', 'Scan', 'Remove']) expect(within(ips).getByRole('columnheader', { name: col })).toBeInTheDocument()
    expect(within(ips).getByRole('button', { name: 'Remove 203.0.113.11' })).toBeInTheDocument()
    expect(screen.getByText('Removed IPs come back if the box keeps using them while auto-detect is on, unless you chose not to add them again.')).toBeInTheDocument()
    expect(screen.queryByRole('textbox', { name: /IP/ })).toBeNull()
    await expectNoA11yViolations()
  })

  it('form matrix (docs/QA.md §2): auto on shows the interval, auto off hides it, the list and Detect now stay', async () => {
    renderApp('/exposure')
    const toggle = await screen.findByRole('switch', { name: "Detect the box's public IPs automatically" })
    const rows = () => within(screen.getByRole('table', { name: 'Public IPs of this box' })).getAllByRole('row').length
    const n = rows()
    await eachOption([
      { option: 'on', shown: ['Check every', 'Detect now', /Auto-detect is on: the box checks/], hidden: [/Auto-detect is off: the box checks only/] },
      { option: 'off', shown: ['Detect now', /Auto-detect is off: the box checks only when you select Detect now/], hidden: ['Check every', /Auto-detect is on: the box checks/] },
      { option: 'on', shown: ['Check every', 'Detect now', /Auto-detect is on: the box checks/], hidden: [/Auto-detect is off: the box checks only/] },
    ], async (o) => {
      if ((toggle.getAttribute('aria-checked') === 'true') !== (o === 'on')) await userEvent.click(toggle)
      await screen.findByText(o === 'on' ? /Auto-detect is on/ : /Auto-detect is off/)
    })
    expect(rows()).toBe(n) // switching off kept the list
    expect(screen.getByRole('combobox', { name: 'Check every' })).toHaveValue('60') // and the interval
  })

  it('changing the interval saves it and the first line follows', async () => {
    renderApp('/exposure')
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Check every' }), '15')
    expect(await screen.findByText('Auto-detect is on: the box checks its public IPs every 15 minutes.')).toBeInTheDocument()
    expect((await state()).box_ip.interval_min).toBe(15)
  })

  it('a load balancer: both IPs show up, one is removed after a confirmation, Detect now brings it back', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    const ips = await ipTable()
    expect(await within(ips).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
    expect(within(ips).getByRole('link', { name: '198.51.100.7' })).toBeInTheDocument()
    await userEvent.click(within(ips).getByRole('button', { name: 'Remove 198.51.100.8' }))
    const dlg = await screen.findByRole('dialog', { name: 'Remove 198.51.100.8 from the list?' })
    expect(within(dlg).getByRole('checkbox', { name: "Don't add it again if detected" })).toBeChecked() // D-79: on by default
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.click(within(ips).getByRole('button', { name: 'Remove 198.51.100.8' }))
    const again = await screen.findByRole('dialog')
    await userEvent.click(within(again).getByRole('checkbox', { name: "Don't add it again if detected" })) // untick: this one may come back
    await userEvent.click(within(again).getByRole('button', { name: 'Remove' }))
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Public IPs of this box' })).queryByRole('link', { name: '198.51.100.8' })).toBeNull())
    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    expect(await within(await ipTable()).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
  })

  it('a viewer sees everything but every control is locked with a visible reason', async () => {
    renderApp('/exposure', { role: 'viewer' })
    expect(await screen.findByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeDisabled()
    expect(screen.getByRole('combobox', { name: 'Check every' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Detect now' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Remove 203.0.113.11' })).toBeDisabled()
    expect(screen.getAllByText('Requires Admin role').length).toBeGreaterThan(0)
  })
})

describe('exposure: the Ignored list (D-79 (3))', () => {
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
    renderApp('/exposure')
    const section = (await screen.findByRole('heading', { name: 'Ignored IPs' })).closest('section')!
    const table = within(section).getByRole('table', { name: 'IPs on the Ignored list' })
    expect(within(table).getByText('203.0.113.77')).toBeInTheDocument()
    expect(within(table).getByRole('button', { name: 'Restore 203.0.113.77' })).toBeEnabled()
    expect(within(section).queryByRole('textbox')).toBeNull() // an IP is never typed in, here either
    expect(within(section).getByText(/it still needs ownership proof and your confirmation/)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('removing an IP: the box "Don\'t add it again if detected" is ticked by default, comes back for the next IP, and the hint follows it (form matrix, QA.md section 2)', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    const ips = await ipTable()
    await userEvent.click(await within(ips).findByRole('button', { name: 'Remove 198.51.100.8' }))
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
    await userEvent.click(await within(await ipTable()).findByRole('button', { name: 'Remove 198.51.100.8' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('checkbox', { name: LABEL })) // untick
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await userEvent.click(within(await ipTable()).getByRole('button', { name: 'Remove 198.51.100.8' }))
    expect(within(await screen.findByRole('dialog')).getByRole('checkbox', { name: LABEL })).toBeChecked()
    await userEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    // the next IP starts ticked again, whatever was chosen before
    await userEvent.click(within(ips).getByRole('button', { name: 'Remove 198.51.100.7' }))
    expect(within(await screen.findByRole('dialog', { name: 'Remove 198.51.100.7 from the list?' })).getByRole('checkbox', { name: LABEL })).toBeChecked()
  })

  it('remove with the box ticked, Detect now does not add it back, Restore lets Detect now add it again', async () => {
    await clean()
    setEgress('198.51.100.7,198.51.100.8')
    renderApp('/exposure')
    const ips = await ipTable()
    await userEvent.click(await within(ips).findByRole('button', { name: 'Remove 198.51.100.8' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
    const ignored = async () => within(await screen.findByRole('table', { name: 'IPs on the Ignored list' }))
    expect(await (await ignored()).findByText('198.51.100.8')).toBeInTheDocument()
    expect(within(await ipTable()).queryByRole('link', { name: '198.51.100.8' })).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    expect((await screen.findAllByText(/Not added, on your Ignored list: 198\.51\.100\.8\./)).length).toBeGreaterThan(0) // the toast and the last-check panel
    expect(within(await ipTable()).queryByRole('link', { name: '198.51.100.8' })).toBeNull()
    expect(within(await ipTable()).getByRole('link', { name: '198.51.100.7' })).toBeInTheDocument()

    await userEvent.click((await ignored()).getByRole('button', { name: 'Restore 198.51.100.8' }))
    await waitFor(() => expect(screen.queryByRole('button', { name: 'Restore 198.51.100.8' })).toBeNull())
    expect(screen.getByText('No ignored IPs')).toBeInTheDocument()
    // restoring adds nothing by itself: the IP is still not in the list until detection sees it
    expect((await list()).items.map((t) => t.value)).not.toContain('198.51.100.8')
    await userEvent.click(screen.getByRole('button', { name: 'Detect now' }))
    expect(await within(await ipTable()).findByRole('link', { name: '198.51.100.8' })).toBeInTheDocument()
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
    renderApp('/exposure', { role: 'viewer' })
    expect(await screen.findByRole('button', { name: 'Restore 203.0.113.77' })).toBeDisabled()
  })
})

describe('exposure: scan-time check of an IP (D-79 (2), INV-13)', () => {
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


describe("exposure: an administrator's first Scan now is the confirmation (D-473)", () => {
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
    expect(screen.getByRole('link', { name: 'Turn on two-step sign-in' })).toHaveAttribute('href', '/account#two-step')
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
    expect(within(note).getByText(/The confirmation text changed: it now names service identification/)).toBeInTheDocument()
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

describe('exposure: add target form matrix (docs/QA.md §2)', () => {
  it('a domain is typed in; an IP has its own button with no input, so the Add dialog never offers an IP field, and it can be cancelled', async () => {
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add a domain' })
    await eachOption([{ option: 'domain', shown: ['Domain', 'Add', 'Cancel'], hidden: ['IP address', 'Public IP', 'Type'] }], () => undefined, dlg)
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    // An IP has no field anywhere: the box section only has a switch, a select and buttons.
    const section = document.getElementById('box-ip')!
    expect(within(section).queryByRole('textbox')).toBeNull()
    expect(within(section).getByRole('button', { name: 'Detect now' })).toBeInTheDocument()
  })
})

describe('exposure: QA pass fixes (paused IP, copy, dates, IPv6, remove dialog, rate limit)', () => {
  const human = /\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4}\b/
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
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
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
    const hint = await screen.findByText(/Works only while this box currently reaches the Internet through 203\.0\.113\.10/)
    expect(hint.textContent).toMatch(/full check/)
    expect(hint.textContent).toMatch(/15 requests/)
    expect(hint.textContent).not.toMatch(/three times/)
  })

  it('4. the help and the "no check yet" text say what is a full check and name the services', async () => {
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [], box_ip: { auto: true, interval_min: 60, last_run: null, retry_in_min: null }, ignored: [] })))
    renderApp('/exposure')
    const never = await screen.findByText(/^No check yet\./)
    for (const re of [/first check/, /full check/, /15 requests/, /checkip\.amazonaws\.com/, /icanhazip\.com/, /ifconfig\.me\/ip/]) expect(never.textContent).toMatch(re)
    const help = document.getElementById('box-ip')!.querySelector('details')!.textContent!
    expect(help).toMatch(/first check after install, Detect now and Verify again are full checks/)
    expect(help).toMatch(/checkip\.amazonaws\.com/)
    expect(help).toMatch(/once.*3 requests/s)
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
    expect(r.json.error.message).toMatch(/Public IPs are not typed in/)
  })

  it('7. a domain with a colon is still a plain bad value; the dialog shows the IP message for IPv6', async () => {
    expect((await call('POST', '/exposure/targets', { value: 'acme.example:8080' })).json.error.code).toBe('bad_value')
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: 'Add domain' }))
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), '2001:4860:4860::8888')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/Public IPs are not typed in/)).toBeInTheDocument()
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
    renderApp('/exposure')
    const detect = await screen.findByRole('button', { name: 'Detect now' })
    expect(detect).toBeDisabled()
    expect(screen.getByText(/Try again in about \d+ minutes?\./)).toBeInTheDocument()
    expect(document.getElementById('box-ip')!.querySelector('details')!.textContent).toMatch(/Detect now, Verify again and the DNS Check of a domain share 10 attempts per hour/)
  })

  it('9. with attempts left, Detect now is enabled and no wait is shown', async () => {
    renderApp('/exposure')
    expect(await screen.findByRole('button', { name: 'Detect now' })).toBeEnabled()
    expect(screen.queryByText(/Try again in about/)).toBeNull()
  })
})

describe('exposure: Add a domain form matrix (docs/QA.md §2, QA walk 2026-11-12)', () => {
  it('Cancel drops the text and its error: the next opening is empty', async () => {
    renderApp('/exposure')
    const add = await screen.findByRole('button', { name: 'Add domain' })
    await userEvent.click(add)
    await userEvent.type(screen.getByRole('textbox', { name: 'Domain' }), 'shop.example.com:8443')
    await userEvent.click(screen.getByRole('button', { name: 'Add' }))
    await screen.findByText(/without http:\/\/, a path/)
    await eachOption([{ option: 'Cancel, open again', shown: ['Domain'], hidden: [/without http:\/\/, a path/] }], async () => {
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
    const checked = screen.getByRole('list', { name: 'Checked' })
    expect(within(checked).getByText(/Service identification \(nmap -sV\) on 98 TCP ports: 3 services identified\./)).toBeInTheDocument()
    expect(within(checked).getByText(/2 identified services of 3 compared with today's CISA list of exploited vulnerabilities/)).toBeInTheDocument()
    const not = screen.getByRole('list', { name: 'Not checked' })
    for (const line of ['UDP ports: the scan connects over TCP only.', 'TCP ports outside the fixed list of commonly exposed ports.', /only the CISA list of exploited vulnerabilities \(KEV\) is compared/]) expect(within(not).getByText(line)).toBeInTheDocument()
    await expectNoA11yViolations()
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
    expect(await within(section).findByText('Services were not identified')).toBeInTheDocument() // D-522: never "No service was identified" here
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

  it('D-565 (review r1 M1): a JavaScript library CVE on a page is listed but not counted on the service of that port', async () => {
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

  it('D-565 (review r1 L2): a domain whose page header names a version with an exploited CVE gets the section in the words of a domain; axe clean', async () => {
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
    expect(within(within(table).getByRole('row', { name: /CVE-2021-41773/ })).getByText('Confirmed by template CVE-2021-41773', { selector: 'span' })).toBeInTheDocument()
    const none = within(table).getByRole('row', { name: /CVE-2021-42013/ })
    expect(within(none).getByText('Version in range')).toBeInTheDocument()
    expect(within(none).getByText(/No match reported by the safe template CVE-2021-42013/)).toBeInTheDocument()
    expect(within(none).queryByText(/not vulnerable/i)).toBeNull()
  })

  it('INV-24, D-565: passive web findings in two groups, "Fix this" first then "Hardening", riskiest first, with the CWE link, three sample pages and the advice; axe clean', async () => {
    renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Web findings (passive)' })
    expect(within(section).getByText(/ZAP looked at the pages without sending forms; these are things it noticed\./)).toBeInTheDocument()
    const groups = within(section).getAllByRole('heading', { level: 3 }).map((h) => h.textContent)
    expect(groups).toEqual(['Fix this', 'Hardening'])
    const fix = within(section).getByRole('table', { name: 'Web findings to fix' })
    const fixRows = within(fix).getAllByRole('row').slice(1)
    expect(within(fixRows[0]!).getByText('Vulnerable JS Library')).toBeInTheDocument()
    expect(within(fixRows[0]!).getByText('jquery 3.4.1 · CVE-2020-11022, CVE-2020-11023')).toBeInTheDocument()
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
    renderApp('/exposure/xt-2')
    const section = await screen.findByRole('region', { name: 'Web findings (passive)' })
    expect(await within(section).findByText('No page was scanned')).toBeInTheDocument()
    expect(within(section).getByText('Passive web scan (ZAP) is not set up on this box yet.')).toBeInTheDocument()
    expect(within(section).queryByRole('table')).toBeNull()
    snap.checks = [{ kind: 'web', text: 'Passive web scan (ZAP baseline: spider and passive rules, no form sent) of 1 page: https://203.0.113.10/. 0 alerts.', at }]
    renderApp('/exposure/xt-2')
    expect((await screen.findAllByText('ZAP noticed nothing on the pages it looked at')).length).toBeGreaterThan(0)
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

describe('exposure: optional deep scan with Greenbone (S-EXP-2, INV-25, D-563)', () => {
  afterEach(() => { for (const k of ['memory', 'swap', 'disk']) localStorage.removeItem(`vedette-mock-box-${k}`) })
  const section = () => screen.findByRole('region', { name: 'Optional deep scan: OpenVAS' })

  it('off by default: shows the box\'s numbers and what it needs before Enable; an administrator enables it and it starts; axe clean', async () => {
    renderApp('/exposure')
    const s = await section()
    expect(await within(s).findByText('Off')).toBeInTheDocument()
    expect(within(s).getByText("Needs about 50 GB of disk and about 2 hours to load the OpenVAS feed the first time. The box must have at least 6 GB of memory (under 8 GB, also 2 GB of swap) and 60 GB free.")).toBeInTheDocument()
    expect(within(s).queryByText(/uses swap/)).toBeNull()
    expect(within(s).getByText('16.0 GB')).toBeInTheDocument()
    expect(within(s).getByText('180.0 GB')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(within(s).getByRole('button', { name: 'Enable OpenVAS' }))
    expect(await within(s).findByText('Starting')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'Turn off OpenVAS' })).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.greenbone' && a.detail === 'enabled (memory 16.0 GB, free disk 180.0 GB)')).toBe(true)
    // D-564 G6: the weekly feed update shows when it last ran and when the next one is due
    expect(within(s).getByText('Not yet: the first one is a week after it is turned on')).toBeInTheDocument()
    expect(within(s).getByText('Next feed update')).toBeInTheDocument()
  })

  it('D-569: a 7.1 GB box may enable it, with the swap note', async () => {
    localStorage.setItem('vedette-mock-box-memory', '7100000000')
    renderApp('/exposure')
    const s = await section()
    expect(await within(s).findByText('The first feed load uses swap on a box under 8 GB (on a 7 GB box it used about 2 GB of swap).')).toBeInTheDocument()
    expect(within(s).queryByRole('alert')).toBeNull()
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeEnabled()
  })

  it('D-569: under 8 GB without 2 GB of swap it is refused with both numbers; at exactly 8 GB no swap is needed and no note shows', async () => {
    localStorage.setItem('vedette-mock-box-memory', '7100000000')
    localStorage.setItem('vedette-mock-box-swap', '0')
    const { unmount } = renderApp('/exposure')
    let s = await section()
    expect(await within(s).findByRole('alert')).toHaveTextContent('This box has 7.1 GB of memory and 0.0 GB of swap; with less than 8.0 GB of memory OpenVAS needs at least 2.0 GB of swap for its first feed load.')
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeDisabled()
    const r = await call('PUT', '/exposure/greenbone', { enabled: true })
    expect([r.status, r.json.error.code]).toEqual([409, 'low_memory'])
    unmount()
    localStorage.setItem('vedette-mock-box-memory', '8000000000')
    renderApp('/exposure')
    s = await section()
    expect(await within(s).findByText('8.0 GB')).toBeInTheDocument()
    expect(within(s).queryByText(/uses swap/)).toBeNull()
    expect(within(s).getByRole('button', { name: 'Enable OpenVAS' })).toBeEnabled()
  })

  it('the refusal shows the measured numbers: 5.9 GB of memory, then too little disk', async () => {
    localStorage.setItem('vedette-mock-box-memory', '5900000000')
    renderApp('/exposure')
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
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null }, enabled: true })))
    renderApp('/exposure', { role: 'viewer' })
    const s = await section()
    expect(await within(s).findByText('OpenVAS is loading its feed (first time takes about 2 hours)')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'Turn off OpenVAS' })).toBeDisabled()
  })

  it('not available on this box: says so and offers nothing', async () => {
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'unavailable', reason: 'OpenVAS is not available on this box.', changed_by: null, changed_at: null,
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null }, enabled: false })))
    renderApp('/exposure')
    const s = await section()
    expect(await within(s).findByText('OpenVAS is not available on this box.')).toBeInTheDocument()
    expect(within(s).queryByRole('button')).toBeNull()
  })

  it('results: their own section with the unauthenticated header, severity first, QoD and CVEs; Low results are hardening notes apart (D-564 G3); axe clean', async () => {
    renderApp('/exposure/xt-2')
    const s = await screen.findByRole('region', { name: 'OpenVAS results (unauthenticated, QoD ≥ 70)' })
    expect(within(s).getByText(/Finding nothing is not proof the services are not affected \(distributions backport fixes\)\. For the same reason, on Ubuntu or Debian a result read from a version banner can be a false positive, so Vedette's own package-based result wins when both exist\./)).toBeInTheDocument()
    const rows = within(within(s).getByRole('table', { name: 'What OpenVAS reported on this IP' })).getAllByRole('row').slice(1)
    expect(rows).toHaveLength(2)
    expect(within(rows[0]!).getByText('High 9.8')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('99%')).toBeInTheDocument()
    expect(within(rows[0]!).getByText('CVE-2021-41773')).toBeInTheDocument()
    expect(within(s).queryByText('Low 2.6')).toBeNull()
    const notes = await screen.findByRole('region', { name: 'Hardening notes (Low)' })
    const noteRows = within(within(notes).getByRole('table', { name: "OpenVAS hardening notes on this IP" })).getAllByRole('row').slice(1)
    expect(noteRows).toHaveLength(1)
    expect(within(noteRows[0]!).getByText('Low 2.6')).toBeInTheDocument()
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

describe('exposure: testing terms per target (S-EXP-2, FULL-1, D-566)', () => {
  const withTwoStep = (on: boolean) => usersStore.update((l) => l.map((x) => (x.id === 'u-admin' ? { ...x, twofa: on } : x)))

  it('one screen says what each tool may send and the risk; the disruptive tick is its own box, off by default; axe clean', async () => {
    renderApp('/exposure/xt-1?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(within(s).getByText('Not accepted: scans of this target stay in the Scan now scope.')).toBeInTheDocument()
    const terms = within(s).getByRole('group', { name: 'Testing terms' })
    expect(within(terms).getByText(/^I confirm that my company owns acme\.example and that I am authorized to test it in depth/)).toBeInTheDocument()
    expect(within(terms).getAllByRole('listitem').map((l) => l.textContent?.split(':')[0])).toEqual(['All ports', 'Version and exploit-confirming checks', 'An active web scan that submits forms', 'Authentication checks'])
    expect(within(terms).getByText(/The deep scan can load or slow the services on acme\.example and may create, change or delete data/)).toBeInTheDocument()
    const tick = within(s).getByRole('checkbox', { name: 'Include disruptive checks (denial of service, brute-force and default-password logins): these can crash your service or lock accounts.' })
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

  it('review r1 M2: behind carrier-grade NAT the step warns and the disruptive tick cannot be ticked', async () => {
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

  it('review r2 L2: without a warning, an IP target says what Vedette cannot see', async () => {
    renderApp('/exposure/xt-2?tab=ownership')
    const s = await screen.findByRole('region', { name: 'Testing terms (deep scan)' })
    expect(await within(s).findByText("Vedette can tell carrier-grade NAT only when this box's own gateway is in 100.64.0.0/10; it cannot see your router's outside address. If your router gets its address from your provider's shared range, ask your provider before accepting.")).toBeInTheDocument()
    expect(within(s).getByRole('checkbox')).toBeEnabled()
  })

  it('review r1 M1: a run the box stopped because the terms were withdrawn says why', async () => {
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

describe('exposure: one page style (S-UI-1, D-543)', () => {
  it('the list has a KPI strip and Targets / Open exposures / What the Internet sees tabs; old #anchors land on their tab', async () => {
    const view = renderApp('/exposure')
    const strip = await screen.findByRole('list', { name: 'External exposure at a glance' })
    expect(within(strip).getAllByRole('link').map((a) => a.getAttribute('href'))).toEqual(['/exposure?tab=targets', '/exposure?tab=open', '/exposure?tab=targets'])
    expect(screen.getByRole('tab', { name: 'Targets', selected: true })).toBeInTheDocument()
    await userEvent.click(screen.getByRole('tab', { name: 'What the Internet sees' }))
    expect(await screen.findByTestId('outside-answer')).toBeInTheDocument()
    view.unmount()
    for (const [hash, tab] of [['open', 'Open exposures'], ['box-ip', 'Targets'], ['outside-list', 'What the Internet sees']] as const) {
      const v = renderApp(`/exposure?x=1#${hash}`)
      expect(await screen.findByRole('tab', { name: tab, selected: true })).toBeInTheDocument()
      v.unmount()
    }
  })

  it('an IP page has Results / Ownership / Outside view; a domain page has no Outside view; old #anchors land on their tab', async () => {
    const ip = renderApp('/exposure/xt-2')
    expect(await screen.findByRole('tab', { name: 'Outside view' })).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Results', selected: true })).toBeInTheDocument()
    ip.unmount()
    const v = renderApp('/exposure/xt-2#step-verify')
    expect(await screen.findByRole('tab', { name: 'Ownership', selected: true })).toBeInTheDocument()
    v.unmount()
    renderApp('/exposure/xt-1')
    expect(await screen.findByRole('tab', { name: 'Ownership' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Outside view' })).not.toBeInTheDocument()
  })
})

describe('exposure: what the Internet sees, Shodan InternetDB (S-EXP-1, D-558)', () => {
  it('shows Shodan\'s ports beside our own scan, the differences called out, and Shodan\'s CVEs as its claim; axe clean', async () => {
    renderApp('/exposure/xt-2?tab=outside')
    expect(await screen.findByRole('heading', { name: 'What the Internet sees' })).toBeInTheDocument()
    const answer = await screen.findByTestId('outside-answer')
    expect(within(answer).getByText('Shodan and our scan both saw 443 open.')).toBeInTheDocument()
    expect(within(answer).getByText('Shodan saw 10443 open; our scan did not.')).toBeInTheDocument()
    expect(within(answer).getByText('Seen only from outside')).toBeInTheDocument()
    expect(within(answer).getByText('Our scan saw 18443 open; Shodan did not.')).toBeInTheDocument()
    expect(within(answer).getByText('Shodan lists CVE-2023-27997; Vedette has not confirmed it.')).toBeInTheDocument()
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
    expect(within(dialog).getByText('Your public IP 203.0.113.11 is sent to Shodan (internetdb.shodan.io). Shodan learns that someone asked about it. Nothing else is sent to Shodan. First the box may re-check that it still goes out through 203.0.113.11 (the same check as before a scan).')).toBeInTheDocument()
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
