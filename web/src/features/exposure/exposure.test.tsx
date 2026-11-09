import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { auditStore, modulesStore, sessionStore } from '@/mocks/stores'
import { feature } from './index'

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
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [], box_ip: { auto: true, interval_min: 60, last_run: null } })))
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: 'No domain or verified public IP yet' })).toBeInTheDocument()
    expect(screen.getAllByText(/Select Detect now to look right away/).length).toBeGreaterThan(0)
  })

  it('module off says where to turn it on', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'exposure' ? { ...m, enabled: false } : m)))
    renderApp('/exposure')
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
    expect(await screen.findByText('Scan finished: 10 open port(s), 3 admin interface(s) exposed')).toBeInTheDocument()
    expect(await screen.findByRole('heading', { level: 1, name: 'acme.example: 6 subdomain(s), 3 admin interface(s) exposed to the Internet' })).toBeInTheDocument()
    expect(await screen.findByText(/4 added, 0 gone, 0 changed/)).toBeInTheDocument()
    expect(within(screen.getByRole('table', { name: 'Changes between two scan days' })).getByText('staging.acme.example')).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.scan' && a.target === 'acme.example')).toBe(true)
  })
})

describe('exposure: domain ownership = DNS TXT only', () => {
  it('unverified domain: scan locked with a reason, TXT record shown, first check not found, second found', async () => {
    renderApp('/exposure/xt-3')
    expect(await screen.findByRole('heading', { level: 1, name: 'acme-demo.example cannot be scanned yet: awaiting ownership proof' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.getByText(/has no ownership proof/)).toBeInTheDocument()
    expect(screen.getByText('vedette-verify=9be41c0a77d2e358')).toBeInTheDocument()
    expect(screen.queryByText(/reverse DNS/i)).not.toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/was not found on acme-demo\.example/)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText(/Verified with a DNS TXT record/)).toBeInTheDocument()
    // verified but not confirmed: still locked
    expect(screen.getByRole('button', { name: 'Scan now' })).toBeDisabled()
    expect(screen.getAllByText(/you have not confirmed that your company owns acme-demo\.example/).length).toBeGreaterThan(0)
  })

  it('a verified domain whose TXT record is gone cannot be scanned, in the UI and in the API', async () => {
    renderApp('/exposure/xt-5')
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
    expect(a.json.message).toMatch(/^The box reaches the Internet via 198\.51\.100\.7\. Verified until \d{4}-\d{2}-\d{2}\.$/)
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
    renderApp('/exposure/xt-2')
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

  it('checks again only when the interval has passed; each sighting renews the IP', async () => {
    const before = (await call('GET', '/exposure/targets/xt-2')).json.verified_at as string
    later(30)
    await state()
    expect((await call('GET', '/exposure/targets/xt-2')).json.verified_at).toBe(before) // 30 of 60 minutes: not due
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
    expect(screen.getByText('Removed IPs come back if the box keeps using them while auto-detect is on.')).toBeInTheDocument()
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
    expect(within(dlg).getByText('Removed IPs come back if the box keeps using them while auto-detect is on.')).toBeInTheDocument()
    await userEvent.click(within(dlg).getByRole('button', { name: 'Cancel' }))
    expect(screen.queryByRole('dialog')).toBeNull()
    await userEvent.click(within(ips).getByRole('button', { name: 'Remove 198.51.100.8' }))
    await userEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Remove' }))
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

describe('exposure: the commitment replaces signed documents', () => {
  it('has no consent form, template or file upload', async () => {
    renderApp('/exposure/xt-3')
    await screen.findByRole('heading', { level: 1 })
    expect(screen.queryByText(/template/i)).not.toBeInTheDocument()
    expect(document.querySelector('input[type="file"]')).toBeNull()
  })

  it('needs the tick, shows the as-is line, records who and when, then scanning opens', async () => {
    await call('POST', '/exposure/targets', { value: 'fresh.acme.example' })
    const list = (await call('GET', '/exposure/targets')).json.items as { id: string; value: string }[]
    const id = list.find((t) => t.value === 'fresh.acme.example')!.id
    await call('POST', `/exposure/targets/${id}/verify`); await call('POST', `/exposure/targets/${id}/verify`)
    renderApp(`/exposure/${id}`)
    expect(await screen.findByText('I confirm my company owns this domain/IP and I am authorized to scan it.')).toBeInTheDocument()
    expect(screen.getByText('Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: 'Confirm and allow scanning' }))
    expect(await screen.findByText('Tick the box to confirm.')).toBeInTheDocument()
    await userEvent.click(screen.getByRole('checkbox'))
    await userEvent.click(screen.getByRole('button', { name: 'Confirm and allow scanning' }))
    expect(await screen.findByText(/Confirmed by .+ on /)).toBeInTheDocument()
    expect(auditStore.get().some((a) => a.action === 'exposure.commitment' && a.target === 'fresh.acme.example')).toBe(true)
    expect((await call('POST', `/exposure/targets/${id}/scan`)).status).toBe(200)
  })

  it('API: commitment needs verification and confirm=true; scan is blocked without it', async () => {
    expect((await call('POST', '/exposure/targets/xt-3/commitment', { confirm: true })).json.error.code).toBe('not_verified')
    await call('POST', '/exposure/targets', { value: 'blocked.acme.example' })
    const id = ((await call('GET', '/exposure/targets')).json.items as { id: string; value: string }[]).find((t) => t.value === 'blocked.acme.example')!.id
    await call('POST', `/exposure/targets/${id}/verify`); await call('POST', `/exposure/targets/${id}/verify`)
    expect((await call('POST', `/exposure/targets/${id}/scan`)).json.error).toMatchObject({ code: 'commitment_required' })
    expect((await call('POST', `/exposure/targets/${id}/commitment`, { confirm: false })).status).toBe(400)
    expect((await call('POST', `/exposure/targets/${id}/commitment`, { confirm: true }, 'operator')).status).toBe(403)
    expect((await call('POST', `/exposure/targets/${id}/commitment`, { confirm: true })).status).toBe(200)
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
