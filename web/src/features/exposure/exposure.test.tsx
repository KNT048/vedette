import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { auditStore, modulesStore, sessionStore, usersStore } from '@/mocks/stores'
import { setDataMode } from '@/mocks/db'
import { scanPoll } from './api'
import { checkPause } from './useCooldown'
import { NOTICE_VERSION } from './contract'
import { feature } from './index'

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

describe('exposure: list (S-EXP-1)', () => {

  // A port whose certificate names a FortiGate is tied to the FortiGate of the inventory, not to the gateway (the gateway note is
  // about the other ports, or gone when every port names its appliance); a known vendor with no device says so.

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
    expect(Math.round((Date.parse(second.json.target.expires_at) - Date.parse(second.json.target.verified_at)) / 864e5)).toBe(90)
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

  it('detects the IP the box uses and verifies it for 90 days from the sighting; detecting again renews the same target', async () => {
    setEgress('198.51.100.7')
    const a = await call('POST', '/exposure/box-ip/verify')
    expect(a.status).toBe(200)
    expect(a.json.items).toHaveLength(1)
    expect(a.json.items[0]).toMatchObject({ kind: 'ip', value: '198.51.100.7', status: 'verified', method: 'box_egress', validity: 'valid', blocked_reason: 'no_commitment' })
    expect(Math.round((Date.parse(a.json.items[0].expires_at) - Date.parse(a.json.items[0].verified_at)) / 864e5)).toBe(90)
    expect(a.json.message).toMatch(/^The box reaches the Internet via 198\.51\.100\.7\. Verified until \d{1,2} [A-Z][a-z]{2} \d{4}\.$/)
    const b = await call('POST', '/exposure/box-ip/verify')
    expect(b.status).toBe(200)
    expect(b.json.items[0].id).toBe(a.json.items[0].id)
    expect(auditStore.get().some((x) => x.action === 'exposure.verify_ok' && x.target === '198.51.100.7')).toBe(true)
    expect(auditStore.get().some((x) => x.action === 'exposure.verify_renew' && x.target === '198.51.100.7')).toBe(true)
  })

  it('Detect now puts every IP the box uses in the target list as this box\'s IP, renews it there, and an ignored one stays out', async () => {
    type Node = { id: string; kind: string; value: string; origin: string; blocked: string | null; proof: { state: string; method: string | null } }
    const boxNodes = async () => ((await call('GET', '/exposure/tree')).json.items as Node[]).filter((n) => n.kind === 'ip' && n.origin === 'box')
    setEgress('198.51.100.7,198.51.100.8')
    expect((await call('POST', '/exposure/box-ip/verify')).status).toBe(200)
    const found = await boxNodes()
    const seven = found.find((n) => n.value === '198.51.100.7')!
    expect(found.map((n) => n.value)).toEqual(expect.arrayContaining(['198.51.100.7', '198.51.100.8']))
    expect(seven).toMatchObject({ proof: { state: 'proven', method: 'box_egress' }, blocked: 'no_commitment' })
    expect((await call('POST', '/exposure/box-ip/verify')).status).toBe(200)
    expect((await boxNodes()).filter((n) => n.value === '198.51.100.7').map((n) => n.id)).toEqual([seven.id]) // renewed, not added twice
    expect((await call('DELETE', `/exposure/tree/${seven.id}?ignore=true`)).status).toBe(204)
    expect((await call('POST', '/exposure/box-ip/verify')).json.message).toMatch(/Not added, on your Ignored list: 198\.51\.100\.7\./)
    expect((await boxNodes()).map((n) => n.value)).not.toContain('198.51.100.7')
    expect((await call('DELETE', `/exposure/tree/${found.find((n) => n.value === '198.51.100.8')!.id}`)).status).toBe(204)
    await call('POST', '/exposure/box-ip/verify')
    expect((await boxNodes()).map((n) => n.value)).toContain('198.51.100.8') // removed without the Ignored list: found again
  })

  it('on a clean install the first read of the target list runs the first check: the box\'s IPs are there without a click', async () => {
    setDataMode('clean')
    usersStore.set([{ id: USER.admin, name: 'admin', email: 'admin@x.example', role: 'admin', password: 'x', twofa: false, created_at: new Date().toISOString(), last_login: null }])
    const items = (await call('GET', '/exposure/tree')).json.items as { kind: string; value: string; origin: string }[]
    expect(items.filter((n) => n.origin === 'box').map((n) => n.value).sort()).toEqual(['203.0.113.10', '203.0.113.11'])
    expect(auditStore.get().some((x) => x.action === 'exposure.auto_detect' && x.user === 'system')).toBe(true)
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
    expect(Math.round((Date.parse(after.expires_at) - Date.parse(after.verified_at)) / 864e5)).toBe(90)
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

  it('an IP the box does not see expires after 90 days and is valid again as soon as it is seen', async () => {
    await call('PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 60 })
    await state() // seeds the sample at the real time
    later(91 * 1440)
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

  it('changing the interval saves it and the first line follows', async () => {
    renderApp('/exposure?tab=settings')
    await userEvent.selectOptions(await screen.findByRole('combobox', { name: 'Check every' }), '15')
    expect(await screen.findByText('Auto-detect is on: the box checks its public IPs every 15 minutes.')).toBeInTheDocument()
    expect((await state()).box_ip.interval_min).toBe(15)
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

  it('an IP stays scannable for 90 days from its last sighting, even while the box goes out through another IP; a check that sees it renews it', async () => {
    expect((await scanXt2()).status).toBe(202) // the sample box goes out through 203.0.113.10: a full check just ran and saw it
    const before = (await call('GET', '/exposure/targets/xt-2')).json.verified_at as string
    setEgress('198.51.100.50') // the box switched to its other Internet line
    advance(6)
    expect((await scanXt2()).status).toBe(202) // not seen now: a warning, not a block
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ value: '203.0.113.10', status: 'verified', scannable: true, blocked_reason: null })
    for (const down of ['offline', 'disagree']) {
      advance(6)
      setEgress(down)
      expect((await scanXt2()).status).toBe(202) // a check that could not tell changes nothing
    }
    advance(6)
    setEgress('203.0.113.10,203.0.113.11') // back on this line: the check sees it and renews it
    expect((await scanXt2()).status).toBe(202)
    expect(Date.parse((await call('GET', '/exposure/targets/xt-2')).json.verified_at)).toBeGreaterThan(Date.parse(before))
  })

  it('a full check is reused for 5 minutes, a "not seen" included; after that the box is asked again', async () => {
    advance(10) // the sample's last check is old
    setEgress('198.51.100.50')
    expect((await scanXt2()).status).toBe(202) // one full check, not seen
    const first = (await call('GET', '/exposure/targets')).json.box_ip.last_run.at
    setEgress('203.0.113.10') // the box is back, but the answer of the last full check still stands for 5 minutes
    advance(2)
    expect((await scanXt2()).status).toBe(202)
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

})

describe('exposure: QA pass fixes (IP not in use now, copy, dates, IPv6, remove dialog, rate limit)', () => {
  const iso = /\b\d{4}-\d{2}-\d{2}\b/
  const leave = async () => {
    setEgress('203.0.113.11') // the box no longer goes out through 203.0.113.10
    expect((await call('POST', '/exposure/targets/xt-2/scan')).status).toBe(202) // still scannable inside its 90 days
  }

  it('1. an IP the box does not go out through now stays scannable: after 10 minutes, 3 hours and failed checks, no blocked reason', async () => {
    const advance = (min: number) => { if (!vi.isFakeTimers()) vi.useFakeTimers({ toFake: ['Date'] }); vi.setSystemTime(Date.now() + min * 60_000) }
    const state = async () => (await call('GET', '/exposure/targets/xt-2')).json
    advance(1)
    await leave()
    for (const min of [10, 170]) {
      advance(min)
      expect(await state()).toMatchObject({ scannable: true, blocked_reason: null })
    }
    for (const down of ['offline', 'disagree']) {
      advance(6)
      setEgress(down)
      await call('POST', '/exposure/box-ip/verify') // a failed check (no answer)
      expect(await state()).toMatchObject({ scannable: true, blocked_reason: null })
    }
  })

  it('1. Verify again says the box does not go out through it, and renews it once the box does', async () => {
    await leave()
    expect((await call('POST', '/exposure/targets/xt-2/verify')).json.verified).toBe(false)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ scannable: true, blocked_reason: null })
    setEgress('203.0.113.10')
    expect((await call('POST', '/exposure/targets/xt-2/verify')).json.verified).toBe(true)
    expect((await call('GET', '/exposure/targets/xt-2')).json).toMatchObject({ scannable: true, blocked_reason: null })
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

describe('exposure: optional deep scan with Greenbone (S-EXP-2, INV-25)', () => {
  afterEach(() => { for (const k of ['memory', 'swap', 'disk']) localStorage.removeItem(`vedette-mock-box-${k}`) })
  const section = () => screen.findByRole('region', { name: 'Optional deep scan: OpenVAS' })

  it('off by default: shows the box\'s numbers and what it needs before Enable; an administrator enables it and it starts; axe clean', async () => {
    renderApp('/exposure?tab=settings')
    const s = await section()
    expect(await within(s).findByText('Off')).toBeInTheDocument()
    expect(within(s).getByText('Needs about 50 GB of disk. Turning it on the first time takes 1 to 3 hours.')).toBeInTheDocument()
    expect(within(s).getByRole('button', { name: 'About What OpenVAS needs' })).toHaveAccessibleDescription('The box must have at least 6 GB of memory (under 8 GB, also 2 GB of swap) and 60 GB free.')
    expect(within(s).queryByText(/uses swap/)).toBeNull()
    expect(within(s).getByText('16.0 GB')).toBeInTheDocument()
    expect(within(s).getByText('180.0 GB')).toBeInTheDocument()
    await expectNoA11yViolations()
    await userEvent.click(within(s).getByRole('button', { name: 'Enable OpenVAS' }))
    expect(await within(s).findByText('Starting')).toBeInTheDocument()
    // a first start can take hours: the panel says so for as long as it starts or loads, with when it was turned on
    const wait = within(s).getByRole('note')
    expect(wait).toHaveTextContent('OpenVAS takes 1 to 3 hours to start the first time')
    expect(wait).toHaveTextContent('It downloads about 9 GB and loads tens of thousands of vulnerability tests. Please be patient: you can leave this page, and it shows Ready when it is done.')
    expect(wait).toHaveTextContent(/Turned on .+\./)
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
    server.use(http.get('*/api/v1/exposure/greenbone', () => HttpResponse.json({ state: 'loading', reason: 'OpenVAS is loading its feed (first time takes 1 to 3 hours)', changed_by: 'admin@acme.example', changed_at: new Date().toISOString(),
      preflight: { memory_bytes: 16e9, disk_free_bytes: 120e9, ok: true, reason: null }, feed_sync: { last_at: null, ok: null, note: null, next_at: null }, feed: null, enabled: true })))
    renderApp('/exposure?tab=settings', { role: 'viewer' })
    const s = await section()
    expect(await within(s).findByText('OpenVAS is loading its feed (first time takes 1 to 3 hours)')).toBeInTheDocument()
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

})

describe('exposure: one page style (S-UI-1)', () => {

  it('Settings holds the public-IP auto-detect, the Ignored IPs, OpenVAS and a link to the shared scan settings', async () => {
    renderApp('/exposure?tab=settings')
    expect(await screen.findByRole('heading', { name: 'Public IP of this box' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Ignored IPs' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: /OpenVAS/ })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open Settings, Scanning' })).toHaveAttribute('href', '/settings/scanning')
  })

})
