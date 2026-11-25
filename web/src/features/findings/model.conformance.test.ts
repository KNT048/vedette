// Conformance of the findings model API (contract.ts, "The findings model"). The same script runs against the GUI mock (always) and
// against the real backend when VITE_FINDINGS_REAL_URL is set (VITE_FINDINGS_QA_PASSWORD: the password of admin@qa.test, op@qa.test and
// view@qa.test). Every 2xx body is checked against the zod schema of contract.ts, and the counts hold on every answer:
// open findings == the sum over By device == the sum over By fix, for the same filter.
//   VITE_FINDINGS_REAL_URL=http://127.0.0.1:8080 VITE_FINDINGS_QA_PASSWORD=... pnpm --dir web exec vitest run src/features/findings/model.conformance.test.ts
// Against a real box the script handles one fix of one device and opens it again at the end; steps marked mock-only change data
// that cannot be put back (a confirmation, an answered question) and run only on the mock.
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import type { ZodType } from 'zod'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { DeviceCards, FindingDetail, FIRST_TOP, FixCards, HandledList, InputList, Overview, PAGE_DEFAULT, TREND_DAYS, View } from './contract'
import type { DeviceCards as Cards, FixCards as Fixes, InputList as Input } from './types'

const REAL = import.meta.env.VITE_FINDINGS_REAL_URL as string | undefined
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }
const MOCK_EMAIL: Record<Role, string> = { admin: 'admin@acme.example', operator: 'it@acme.example', viewer: 'view@acme.example' }

type Ctx = Record<string, string>
interface Res { status: number; code: string | null; body: any } // eslint-disable-line @typescript-eslint/no-explicit-any
interface Step {
  name: string
  role: Role | null
  method: 'GET' | 'POST'
  path: string | ((c: Ctx) => string)
  body?: Record<string, unknown> | ((c: Ctx) => Record<string, unknown>)
  status: number
  code?: string
  schema?: ZodType
  /** Runs only on the mock: it changes data a real box cannot get back. */
  mockOnly?: boolean
  check?: (body: any, c: Ctx) => void // eslint-disable-line @typescript-eslint/no-explicit-any
}

const sessions = new Map<Role, { cookie: string; csrf: string }>()
async function realSession(role: Role) {
  const have = sessions.get(role)
  if (have) return have
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = await fetch(`${REAL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EMAIL[role], password: import.meta.env.VITE_FINDINGS_QA_PASSWORD }) })
    if (r.status === 503) { await new Promise((ok) => setTimeout(ok, 500)); continue } // the box checks one password at a time
    if (!r.ok) throw new Error(`login as ${role}: ${r.status}`)
    const jar = r.headers.getSetCookie().map((c) => c.split(';')[0]!)
    const csrf = jar.find((c) => c.startsWith('__Host-vedette_csrf='))?.split('=')[1]
    if (!csrf) throw new Error('login gave no CSRF cookie')
    const s = { cookie: jar.join('; '), csrf }
    sessions.set(role, s)
    return s
  }
  throw new Error(`login as ${role}: the box stayed busy`)
}

let target: 'mock' | 'real' = 'mock'
const who = (r: Role) => (target === 'real' ? EMAIL : MOCK_EMAIL)[r]

async function call(method: 'GET' | 'POST', path: string, role: Role | null, body?: unknown): Promise<Res> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let base = 'http://localhost'
  if (target === 'real') {
    base = REAL!
    if (role) {
      const s = await realSession(role)
      headers.Cookie = s.cookie
      if (method !== 'GET') headers['X-CSRF-Token'] = s.csrf
    }
  } else sessionStore.set({ userId: role ? USER[role] : null })
  const r = await fetch(`${base}/api/v1${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  const data: unknown = await r.json().catch(() => null)
  return { status: r.status, code: (data as { error?: { code?: string } } | null)?.error?.code ?? null, body: data }
}

const sum = (l: { findings: number }[]) => l.reduce((n, x) => n + x.findings, 0)
/** Every card of a list, page by page (the default page size), as the GUI pages it. */
async function allPages(path: string): Promise<{ items: { findings: number }[]; total: number; findings: number }> {
  const items: { findings: number }[] = []
  let first: Cards | Fixes | null = null
  for (let offset = 0; ; offset += PAGE_DEFAULT) {
    const sep = path.includes('?') ? '&' : '?'
    const r = await call('GET', `${path}${sep}offset=${offset}`, 'viewer')
    if (r.status !== 200) throw new Error(`${path}: ${r.status} ${r.code}`)
    first ??= r.body
    items.push(...r.body.items)
    if (r.body.items.length < PAGE_DEFAULT) break
  }
  return { items, total: first!.total, findings: first!.findings }
}
/** open == Σ By device == Σ By fix, for one filter. */
async function counts(filter = '') {
  const devices = await allPages(`/findings/devices${filter}`)
  const fixes = await allPages(`/findings/fixes${filter}`)
  expect(devices.items).toHaveLength(devices.total)
  expect(fixes.items).toHaveLength(fixes.total)
  expect(sum(devices.items)).toBe(devices.findings)
  expect(sum(fixes.items)).toBe(fixes.findings)
  expect(devices.findings).toBe(fixes.findings)
  return devices.findings
}

const steps: Step[] = [
  // ---- reads
  { name: 'no session', role: null, method: 'GET', path: '/findings/devices', status: 401, code: 'unauthenticated' },
  { name: 'no session on a view', role: null, method: 'GET', path: '/findings/x/view', status: 401, code: 'unauthenticated' },
  { name: 'overview', role: 'viewer', method: 'GET', path: '/findings/overview', status: 200, schema: Overview,
    check: (b, c) => {
      expect(b.first.length).toBeLessThanOrEqual(FIRST_TOP)
      expect(b.trend).toHaveLength(TREND_DAYS)
      expect(b.trend[TREND_DAYS - 1]).toBe(b.open.findings)
      expect(Object.values(b.open.by_status).reduce((n: number, x) => n + (x as number), 0)).toBe(b.open.findings)
      c.open = String(b.open.findings); c.updates = String(b.open.by_status.update_recommended)
    } },
  { name: 'by device', role: 'viewer', method: 'GET', path: '/findings/devices?limit=100', status: 200, schema: DeviceCards,
    check: (b: Cards, c) => {
      expect(b.findings).toBe(Number(c.open))
      for (const d of b.items) {
        expect(d.blocks.reduce((n, x) => n + x.findings.length, 0)).toBe(d.findings)
        expect(Object.values(d.counts).reduce((n, x) => n + x, 0)).toBe(d.findings)
        expect(d.status?.code).toBe(d.blocks[0]!.status) // the badge is the most urgent block's status
        for (const x of d.blocks) for (const f of x.findings) expect(['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended']).toContain(f.status)
      }
      const two = b.items.find((d) => d.findings >= 2)
      const other = b.items.find((d) => d !== two)
      if (!two || !other) throw new Error('the box needs two devices with open findings, one with two or more')
      const blk = two.blocks[0]!
      c.device = two.device.id; c.fix = blk.fix.key; c.software = blk.software?.id ?? ''; c.blockSize = String(blk.findings.length)
      c.fid = blk.findings[0]!.id; c.blockIds = blk.findings.map((f) => f.id).join(','); c.otherFid = other.blocks[0]!.findings[0]!.id
    } },
  { name: 'by fix', role: 'viewer', method: 'GET', path: '/findings/fixes?limit=100', status: 200, schema: FixCards,
    check: (b: Fixes, c) => {
      expect(b.findings).toBe(Number(c.open))
      for (const f of b.items) { expect(sum(f.items)).toBe(f.findings); expect(f.items).toHaveLength(f.devices) }
    } },
  { name: 'by device and by fix page by page add up to the open findings', role: 'viewer', method: 'GET', path: '/findings/overview', status: 200,
    check: async (b) => { expect(await counts()).toBe(b.open.findings) } },
  { name: 'one status: the lists hold only it and add up', role: 'viewer', method: 'GET', path: '/findings/devices?status=update_recommended&limit=100', status: 200, schema: DeviceCards,
    check: async (b: Cards, c) => {
      for (const d of b.items) for (const x of d.blocks) for (const f of x.findings) expect(f.status).toBe('update_recommended')
      expect(b.findings).toBe(Number(c.updates))
      expect(await counts('?status=update_recommended')).toBe(Number(c.updates))
    } },
  { name: 'an unknown status', role: 'viewer', method: 'GET', path: '/findings/devices?status=urgent', status: 400, code: 'bad_filter' },
  { name: 'an unknown status on By fix', role: 'viewer', method: 'GET', path: '/findings/fixes?status=exploited,nope', status: 400, code: 'bad_filter' },
  { name: 'a limit that is not a number', role: 'viewer', method: 'GET', path: '/findings/devices?limit=ten', status: 400, code: 'invalid' },
  { name: 'one card per page keeps the total', role: 'viewer', method: 'GET', path: '/findings/devices?limit=1', status: 200, schema: DeviceCards,
    check: (b: Cards, c) => { expect(b.items).toHaveLength(1); expect(b.findings).toBe(Number(c.open)) } },
  { name: 'a page past the end is empty', role: 'viewer', method: 'GET', path: '/findings/devices?offset=99999', status: 200, schema: DeviceCards, check: (b: Cards) => expect(b.items).toEqual([]) },
  { name: 'one device', role: 'viewer', method: 'GET', path: (c) => `/findings/devices?device=${encodeURIComponent(c.device!)}`, status: 200, schema: DeviceCards,
    check: (b: Cards, c) => { expect(b.items.map((d) => d.device.id)).toEqual([c.device]); expect(b.total).toBe(1) } },
  { name: 'search by CVE', role: 'viewer', method: 'GET', path: '/findings/devices?q=CVE-0000-0000', status: 200, schema: DeviceCards, check: (b: Cards) => { expect(b.items).toEqual([]); expect(b.findings).toBe(0) } },
  { name: 'needs your input', role: 'viewer', method: 'GET', path: '/findings/input?limit=100', status: 200, schema: InputList,
    check: (b: Input, c) => {
      expect(b.items).toHaveLength(b.total)
      const entries = b.items.flatMap((i) => (i.kind === 'device_needs' ? i.entries : []))
      const questions = entries.flatMap((e) => (e.kind === 'software_group' ? e.questions : []))
      const unconfirmed = entries.find((e) => e.kind === 'unconfirmed')
      if (unconfirmed) c.unconfirmed = unconfirmed.id
      const several = questions.find((i) => i.cve === null)
      if (several) c.severalCves = several.id
      const oneCve = questions.find((i) => i.cve !== null)
      if (oneCve) c.oneCve = oneCve.id
    } },
  { name: 'handled', role: 'viewer', method: 'GET', path: '/findings/handled', status: 200, schema: HandledList,
    check: (b) => { for (let i = 1; i < b.items.length; i++) expect(b.items[i - 1].handled.at >= b.items[i].handled.at).toBe(true) } },
  { name: 'handled, patched only', role: 'viewer', method: 'GET', path: '/findings/handled?resolution=patched', status: 200, schema: HandledList,
    check: (b) => { for (const r of b.items) expect([r.status, r.handled.resolution]).toEqual(['patched', 'patched']) } },
  { name: 'handled, an unknown resolution', role: 'viewer', method: 'GET', path: '/findings/handled?resolution=fixed', status: 400, code: 'bad_filter' },
  { name: 'handled, a time with an offset', role: 'viewer', method: 'GET', path: '/findings/handled?from=2026-11-01T00:00:00%2B07:00', status: 400, code: 'bad_from' },
  { name: 'the view of a finding', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.fid}/view`, status: 200, schema: View,
    check: (b, c) => {
      expect([b.id, b.device.id, b.fix.key, b.handled]).toEqual([c.fid, c.device, c.fix, null])
      expect(b.status).toBe(['under_attack', 'exploited', 'public_exploit', 'critical_edge', 'update_recommended'][b.urgency.layer - 1])
      if (b.urgency.layer === 5) expect(b.urgency.reasons).toEqual([])
      for (const r of b.urgency.reasons) expect(r.layer).toBeGreaterThanOrEqual(b.urgency.layer)
    } },
  { name: 'the view of an unknown finding', role: 'viewer', method: 'GET', path: '/findings/fv-nope/view', status: 404, code: 'not_found' },
  // Every list links a finding to its page by the same id: the page's detail answers for it.
  { name: 'the page of a listed finding', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.fid}`, status: 200, schema: FindingDetail,
    check: (b, c) => { expect([b.id, b.asset?.id]).toEqual([c.fid, c.device]); expect(['confirmed', 'suspected']).toContain(b.status) } },
  { name: 'the page of the finding with a confirmed recommendation', role: 'viewer', method: 'GET', path: '/findings/fv-nas02-ps-1', status: 200, schema: FindingDetail, mockOnly: true,
    check: (b) => { expect(b.cve).toBe('CVE-2022-27593'); expect(b.pack).not.toBeNull(); expect(b.applied).toEqual([]) } },
  { name: '"Applied" on a listed finding is kept on its page', role: 'operator', method: 'POST', path: '/findings/fv-nas02-ps-1/applied', body: { item: 'patch' }, status: 200, schema: FindingDetail, mockOnly: true,
    check: (b) => expect(b.applied).toMatchObject([{ item: 'patch', user: who('operator') }]) },
  { name: 'it is still there on the next read', role: 'viewer', method: 'GET', path: '/findings/fv-nas02-ps-1', status: 200, mockOnly: true,
    check: (b) => expect(b.applied.map((a: { item: string }) => a.item)).toEqual(['patch']) },

  // ---- handling
  { name: 'a viewer cannot handle', role: 'viewer', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], resolution: 'patched', note: '' }), status: 403, code: 'forbidden' },
  { name: 'ids and a fix at once', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], device: c.device, fix: c.fix, resolution: 'patched', note: '' }), status: 400, code: 'bad_target' },
  { name: 'neither ids nor a fix', role: 'operator', method: 'POST', path: '/findings/handle', body: { resolution: 'patched', note: '' }, status: 400, code: 'bad_target' },
  { name: 'a fix without its device', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ fix: c.fix, resolution: 'patched', note: '' }), status: 400, code: 'bad_target' },
  { name: 'findings of two devices', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid, c.otherFid], resolution: 'patched', note: '' }), status: 400, code: 'many_devices' },
  { name: 'an unknown finding', role: 'operator', method: 'POST', path: '/findings/handle', body: { ids: ['fv-nope'], resolution: 'patched', note: '' }, status: 404, code: 'not_found' },
  { name: 'not relevant needs a note', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], resolution: 'not_relevant', note: '  ab ' }), status: 400, code: 'note_required' },
  { name: 'accepted needs a last day', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], resolution: 'accepted', note: 'a test machine' }), status: 400, code: 'bad_until' },
  { name: 'a last day only with accepted', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], resolution: 'patched', note: '', until: '2099-01-01' }), status: 400, code: 'bad_until' },
  { name: 'patched: every open finding of one fix on one device', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ device: c.device, fix: c.fix, ...(c.software ? { software: c.software } : {}), resolution: 'patched', note: 'updated by hand' }), status: 200,
    check: (b, c) => expect(b).toEqual({ handled: Number(c.blockSize), skipped: 0 }) },
  { name: 'the open findings went down by exactly that many, in every list', role: 'viewer', method: 'GET', path: '/findings/overview', status: 200, schema: Overview,
    check: async (b, c) => { expect(b.open.findings).toBe(Number(c.open) - Number(c.blockSize)); expect(await counts()).toBe(b.open.findings) } },
  { name: 'the same handling again is skipped', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: c.blockIds!.split(','), resolution: 'patched', note: '' }), status: 200,
    check: (b, c) => expect(b).toEqual({ handled: 0, skipped: Number(c.blockSize) }) },
  { name: 'the view says who and how', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.fid}/view`, status: 200, schema: View,
    check: (b) => {
      expect(b.status).toBe('patched')
      expect(b.handled).toMatchObject({ resolution: 'patched', via: 'person', by: who('operator'), note: 'updated by hand', accepted_until: null })
      expect(b.events.at(-1)).toMatchObject({ kind: 'handled', actor: who('operator'), resolution: 'patched' })
    } },
  { name: 'the page says it is handled', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.fid}`, status: 200, schema: FindingDetail,
    check: (b) => { expect(b.status).toBe('patched'); expect(b.resolved_by).toBe(who('operator')) } },
  { name: 'handled lists it', role: 'viewer', method: 'GET', path: (c) => `/findings/handled?device=${encodeURIComponent(c.device!)}&limit=100`, status: 200, schema: HandledList,
    check: (b, c) => expect(b.items.map((r: { id: string }) => r.id)).toContain(c.fid) },
  { name: 'one finding handled another way changes exactly that one', role: 'operator', method: 'POST', path: '/findings/handle', body: (c) => ({ ids: [c.fid], resolution: 'mitigated', note: 'firewall rule' }), status: 200,
    check: (b) => expect(b).toEqual({ handled: 1, skipped: 0 }) },
  { name: 'reopen', role: 'operator', method: 'POST', path: (c) => `/findings/${c.fid}/reopen`, body: { note: 'it came back' }, status: 200, schema: View,
    check: (b) => { expect(b.handled).toBeNull(); expect(b.events.at(-1)).toMatchObject({ kind: 'reopened', note: 'it came back' }) } },
  { name: 'reopen an open finding', role: 'operator', method: 'POST', path: (c) => `/findings/${c.fid}/reopen`, body: { note: '' }, status: 409, code: 'already_open' },
  { name: 'a viewer cannot reopen', role: 'viewer', method: 'POST', path: (c) => `/findings/${c.blockIds!.split(',').at(-1)}/reopen`, body: { note: '' }, status: 403, code: 'forbidden' },

  // ---- confirming and answering (mock only: they cannot be undone on a real box)
  { name: 'an operator cannot confirm', role: 'operator', method: 'POST', path: (c) => `/findings/${c.unconfirmed}/verify`, body: { note: 'I checked the version' }, status: 403, code: 'forbidden', mockOnly: true },
  { name: 'confirming needs a note', role: 'admin', method: 'POST', path: (c) => `/findings/${c.unconfirmed}/verify`, body: { note: 'ok' }, status: 400, code: 'confirm_note_required', mockOnly: true },
  { name: 'confirm vulnerability', role: 'admin', method: 'POST', path: (c) => `/findings/${c.unconfirmed}/verify`, body: { note: 'I checked the version on the device' }, status: 200, schema: View, mockOnly: true,
    check: (b) => expect(b.verification).toMatchObject({ verified: 'person', by: who('admin') }) },
  { name: 'confirm it again', role: 'admin', method: 'POST', path: (c) => `/findings/${c.unconfirmed}/verify`, body: { note: 'I checked the version on the device' }, status: 409, code: 'already_verified', mockOnly: true },
  { name: 'it left Needs your input', role: 'viewer', method: 'GET', path: '/findings/input?limit=100', status: 200, schema: InputList, mockOnly: true,
    check: (b: Input, c) => expect(b.items.map((i) => i.id)).not.toContain(c.unconfirmed) },
  { name: 'a question about several CVEs is answered on the device', role: 'operator', method: 'POST', path: (c) => `/findings/questions/${c.severalCves}/answer`, body: { answer: 'not_affected', note: 'not installed' }, status: 409, code: 'not_one_cve', mockOnly: true },
  { name: 'not affected needs a note', role: 'operator', method: 'POST', path: (c) => `/findings/questions/${c.oneCve}/answer`, body: { answer: 'not_affected', note: '' }, status: 400, code: 'note_required', mockOnly: true },
  { name: 'an operator cannot answer affected', role: 'operator', method: 'POST', path: (c) => `/findings/questions/${c.oneCve}/answer`, body: { answer: 'affected', note: 'the advisory lists this build' }, status: 403, code: 'forbidden', mockOnly: true },
  { name: 'affected: a finding confirmed by the person', role: 'admin', method: 'POST', path: (c) => `/findings/questions/${c.oneCve}/answer`, body: { answer: 'affected', note: 'the advisory lists this build' }, status: 200, mockOnly: true,
    check: (b, c) => { expect(b.finding).toEqual(expect.any(String)); c.answered = b.finding } },
  { name: 'the new finding', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.answered}/view`, status: 200, schema: View, mockOnly: true,
    check: (b) => expect(b.verification).toMatchObject({ verified: 'person', basis: 'person', by: who('admin') }) },
  { name: 'the question is gone', role: 'admin', method: 'POST', path: (c) => `/findings/questions/${c.oneCve}/answer`, body: { answer: 'affected', note: '' }, status: 404, code: 'not_found', mockOnly: true },
]

/** A real box keeps what a run left: open the handled block again. */
async function cleanup(c: Ctx) {
  for (const id of c.blockIds?.split(',') ?? []) await call('POST', `/findings/${id}/reopen`, 'operator', { note: '' })
}

async function run(which: 'mock' | 'real') {
  target = which
  const c: Ctx = {}
  const problems: string[] = []
  for (const s of steps) {
    if (s.mockOnly && which === 'real') continue
    const path = typeof s.path === 'function' ? s.path(c) : s.path
    const body = typeof s.body === 'function' ? s.body(c) : s.body
    let r: Res
    try { r = await call(s.method, path, s.role, body) } catch (e) { problems.push(`${s.name}: request failed: ${String(e)}`); continue }
    if (r.status !== s.status || (s.code !== undefined && r.code !== s.code)) { problems.push(`${s.name}: want ${s.status} ${s.code ?? ''}, got ${r.status} ${r.code ?? ''}`); continue }
    if (r.status < 300 && s.schema) {
      const p = s.schema.safeParse(r.body)
      if (!p.success) problems.push(`${s.name}: body does not match contract.ts: ${p.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
    }
    try { await s.check?.(r.body, c) } catch (e) { problems.push(`${s.name}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`) }
  }
  if (which === 'real') await cleanup(c)
  return problems
}

describe('findings model API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await run('mock')).toEqual([]) })
  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough()))
    expect(await run('real')).toEqual([])
  }, 120_000)
})
