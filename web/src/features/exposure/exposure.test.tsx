import { beforeEach, describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
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
const targetsTable = () => screen.findByRole('table', { name: 'Declared domains and verified public IPs' })

describe('exposure: list (S-EXP-1)', () => {
  it('first sentence counts exposed admin interfaces; the table says why a target cannot be scanned; axe clean', async () => {
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: '2 admin interfaces are exposed to the Internet' })).toBeInTheDocument()
    const table = await targetsTable()
    expect(within(table).getAllByRole('row')).toHaveLength(6)
    const demo = within(table).getByRole('row', { name: /acme-demo\.example/ })
    expect(within(demo).getByText('Awaiting ownership proof')).toBeInTheDocument()
    expect(within(demo).getByText('Needs ownership proof')).toBeInTheDocument()
    const expiring = within(table).getByRole('row', { name: /203\.0\.113\.10/ })
    expect(within(expiring).getByText(/Expires in \d+ days/)).toBeInTheDocument()
    const expired = within(table).getByRole('row', { name: /203\.0\.113\.55/ })
    expect(within(expired).getAllByText('Verification expired').length).toBeGreaterThan(0)
    expect(within(within(table).getByRole('row', { name: /old-site\.example/ })).getByText('TXT record missing')).toBeInTheDocument()
    expect(within(within(table).getByRole('row', { name: /^acme\.example/ })).getByText('Ready to scan')).toBeInTheDocument()
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
    server.use(http.get('*/api/v1/exposure/targets', () => HttpResponse.json({ items: [] })))
    renderApp('/exposure')
    expect(await screen.findByRole('heading', { level: 1, name: 'No domain or verified public IP yet' })).toBeInTheDocument()
    expect(screen.getAllByText(/Verify this box's public IP/).length).toBeGreaterThan(0)
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

describe('exposure: public IP = only the IP this box uses to reach the Internet', () => {
  it('no IP input: typing an IP is refused and points to the box button', async () => {
    const r = await call('POST', '/exposure/targets', { value: '198.51.100.7' })
    expect(r.status).toBe(400)
    expect(r.json.error.code).toBe('ip_not_allowed')
  })

  it('verifies the detected IP for 90 days; verifying again renews the same target', async () => {
    setEgress('198.51.100.7')
    const a = await call('POST', '/exposure/box-ip/verify')
    expect(a.status).toBe(201)
    expect(a.json).toMatchObject({ kind: 'ip', value: '198.51.100.7', status: 'verified', method: 'box_egress', validity: 'valid', blocked_reason: 'no_commitment' })
    expect(Math.round((Date.parse(a.json.expires_at) - Date.parse(a.json.verified_at)) / 864e5)).toBe(90)
    const b = await call('POST', '/exposure/box-ip/verify')
    expect(b.status).toBe(200)
    expect(b.json.id).toBe(a.json.id)
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

  it('an expired IP cannot be scanned until re-verified; an expiring one is flagged', async () => {
    expect((await call('POST', '/exposure/targets/xt-4/scan')).json.error.code).toBe('expired')
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ status: 'verified', validity: 'expiring' })
    expect((await call('GET', '/exposure/targets/xt-4')).json).toMatchObject({ status: 'expired', validity: 'expired', blocked_reason: 'expired', scannable: false })
  })

  it('limits verification attempts to 10 per hour with a clear message', async () => {
    setEgress('203.0.113.10')
    for (let i = 0; i < 10; i++) expect((await call('POST', '/exposure/targets/xt-2/verify')).status).toBe(200)
    const r = await call('POST', '/exposure/box-ip/verify')
    expect(r.status).toBe(429)
    expect(r.json.error.message).toMatch(/Too many verification attempts \(limit 10 per hour\)/)
  })

  it('the verify dialog explains the anti-abuse rules and verifies this box IP from the page', async () => {
    setEgress('198.51.100.7')
    renderApp('/exposure')
    await userEvent.click(await screen.findByRole('button', { name: "Verify this box's public IP" }))
    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/You cannot type an IP/)).toBeInTheDocument()
    expect(within(dialog).getByText(/At most 10 verification attempts per hour/)).toBeInTheDocument()
    await userEvent.click(within(dialog).getByRole('button', { name: 'Detect and verify' }))
    expect(await screen.findByRole('heading', { level: 1, name: /198\.51\.100\.7 cannot be scanned yet: needs your confirmation/ })).toBeInTheDocument()
  })

  it('the IP page shows status, dates and the same-IP rule', async () => {
    renderApp('/exposure/xt-2')
    expect(await screen.findByText('Last verified')).toBeInTheDocument()
    expect(screen.getByText('Expires on')).toBeInTheDocument()
    expect(screen.getAllByText(/Expires in \d+ days/).length).toBeGreaterThan(0)
    expect(screen.getByText(/Works only while this box currently reaches the Internet through 203\.0\.113\.10/)).toBeInTheDocument()
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
    expect((await call('POST', `/exposure/targets/${id}/scan`)).json.error.code).toBe('no_commitment')
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
    await userEvent.click(screen.getByRole('button', { name: "Verify this box's public IP" }))
    const ip = await screen.findByRole('dialog')
    expect(within(ip).queryByRole('textbox')).toBeNull()
    expect(within(ip).getByRole('button', { name: 'Cancel' })).toBeInTheDocument()
  })
})
