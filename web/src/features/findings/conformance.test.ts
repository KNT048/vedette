// The same script of API calls runs against the GUI mock (always) and against the real Go backend (only when
// VITE_FINDINGS_REAL_URL is set, i.e. make dev-api REAL=core,inventory,feeds,findings,mitigation prepared with web/e2e/qa/real-box.mjs;
// VITE_FINDINGS_QA_PASSWORD is the password of admin@qa.test, op@qa.test and view@qa.test). The mock is the approved behaviour
// (GUI-first, D-18): every step states the status and error code the mock gives and, where the real backend deliberately differs
// (D-73: limits that contract.ts states are refused by the generated validator as 400 `invalid`; modules/findings/CONTRACT.md,
// modules/mitigation/CONTRACT.md), what it gives instead. Every 2xx body is checked against the zod schema of contract.ts.
// Run against the real backend:
//   VITE_FINDINGS_REAL_URL=http://127.0.0.1:8080 VITE_FINDINGS_QA_PASSWORD=... pnpm --dir web exec vitest run src/features/findings/conformance.test.ts
// The script changes findings (status, "Applied") on the box it runs against and puts them back open at the end.
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import { server } from '@/test/server'
import type { ZodType } from 'zod'
import { sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { FindingDetail, FindingList } from './contract'

const REAL = import.meta.env.VITE_FINDINGS_REAL_URL as string | undefined
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const PACK_CVE = 'CVE-2022-27593' // the CVE of the recommendation pack the mock ships and the box is seeded with

interface Res { status: number; code: string | null; message: string | null; body: unknown }
type Ctx = Record<string, string>
interface Step {
  name: string
  role: Role | null
  method: 'GET' | 'POST'
  path: string | ((c: Ctx) => string)
  body?: unknown | ((c: Ctx) => unknown)
  status: number
  code?: string
  /** What the real backend answers where it deliberately differs from the mock. */
  real?: { status?: number; code?: string }
  schema?: ZodType
  keep?: (body: any, c: Ctx) => void // eslint-disable-line @typescript-eslint/no-explicit-any
  check?: (body: any, c: Ctx, target: 'mock' | 'real') => void // eslint-disable-line @typescript-eslint/no-explicit-any
}

// Real mode signs in through the real login (POST /auth/login): the cookies and the double-submit CSRF header are assembled by hand.
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }
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

async function call(target: 'mock' | 'real', s: Step, c: Ctx): Promise<Res> {
  const path = typeof s.path === 'function' ? s.path(c) : s.path
  const body = typeof s.body === 'function' ? (s.body as (c: Ctx) => unknown)(c) : s.body
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  let base = 'http://localhost'
  if (target === 'real') {
    base = REAL!
    if (s.role) {
      const ses = await realSession(s.role)
      headers.Cookie = ses.cookie
      if (s.method !== 'GET') headers['X-CSRF-Token'] = ses.csrf
    }
  } else sessionStore.set({ userId: s.role ? USER[s.role] : null })
  const r = await fetch(`${base}/api/v1${path}`, { method: s.method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
  const data: unknown = await r.json().catch(() => null)
  const e = (data as { error?: { code?: string; message?: string } } | null)?.error
  return { status: r.status, code: e?.code ?? null, message: e?.message ?? null, body: data }
}

let target: 'mock' | 'real' = 'mock'
const MOCK_EMAIL: Record<Role, string> = { admin: 'admin@acme.example', operator: 'it@acme.example', viewer: 'view@acme.example' }
const who = (r: Role) => (target === 'real' ? EMAIL : MOCK_EMAIL)[r]
const F = (c: Ctx) => `/findings/${c.nopack}`
const status = (action: string, note = '') => ({ action, note })
const OPEN = ['confirmed', 'suspected']
const lastHistory = (b: { history: { action: string; note?: string; user: string }[] }) => b.history.filter((h) => !h.action.startsWith('applied:')).at(-1)

const steps: Step[] = [
  // ---- reads
  { name: 'list', role: 'viewer', method: 'GET', path: '/findings', status: 200, schema: FindingList,
    keep: (b, c) => {
      const items = b.items as { id: string; cve: string; asset_id: string; status: string }[]
      const pack = items.find((f) => f.cve === PACK_CVE)
      const other = items.find((f) => f.cve !== PACK_CVE)
      if (!pack || !other) throw new Error(`the box needs a finding for ${PACK_CVE} and one for another CVE (real-box.mjs makes them)`)
      c.pack = pack.id; c.nopack = other.id; c.asset = pack.asset_id; c.total = String(items.length)
    },
    check: (b) => {
      expect(b.items.length).toBeGreaterThan(1)
      for (const f of b.items) expect(f.first_seen <= f.last_seen).toBe(true)
      expect(new Set(b.items.map((f: { id: string }) => f.id)).size).toBe(b.items.length)
    } },
  { name: 'list for one device', role: 'viewer', method: 'GET', path: (c) => `/findings?asset=${encodeURIComponent(c.asset!)}`, status: 200, schema: FindingList,
    check: (b, c) => { expect(b.items.length).toBeGreaterThan(0); expect(b.items.length).toBeLessThanOrEqual(Number(c.total)); for (const f of b.items) expect(f.asset_id).toBe(c.asset) } },
  { name: 'list for a device that has none', role: 'viewer', method: 'GET', path: '/findings?asset=a-nothing', status: 200, schema: FindingList, check: (b) => expect(b.items).toEqual([]) },
  { name: 'the row carries the device and the KEV entry', role: 'viewer', method: 'GET', path: (c) => `/findings?asset=${encodeURIComponent(c.asset!)}`, status: 200,
    check: (b) => { const f = b.items[0]; expect(f.asset).toMatchObject({ id: f.asset_id }); expect(f.asset.ip).toMatch(/^\d+\.\d+\.\d+\.\d+$/); expect(f.kev.display.length).toBeGreaterThan(0); expect(Array.isArray(f.kev.links)).toBe(true) } },
  { name: 'detail with a recommendation pack', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.pack}`, status: 200, schema: FindingDetail,
    check: (b) => {
      expect(b.pack).not.toBeNull()
      expect(b.pack.firewall.map((g: { vendor: string }) => g.vendor)).toEqual(['fortigate', 'mikrotik', 'generic'])
      expect(JSON.stringify(b)).not.toMatch(/\{IP\}|\{HOST\}|<IP-NAS>/) // the device values went in
      expect(b.compromise).not.toBeNull()
      expect(b.recheck.steps.length).toBeGreaterThan(0)
    } },
  { name: 'detail without a pack', role: 'viewer', method: 'GET', path: F, status: 200, schema: FindingDetail,
    check: (b) => { expect(b.pack).toBeNull(); expect(b.compromise).toBeNull(); expect(b.recheck.steps.length).toBeGreaterThan(0); expect(b.ai).toEqual({ explain: null, config: null }) } },
  { name: 'detail of an unknown finding', role: 'viewer', method: 'GET', path: '/findings/f-nope', status: 404, code: 'not_found' },
  { name: 'id of 65 characters', role: 'viewer', method: 'GET', path: `/findings/${'f'.repeat(65)}`, status: 404, code: 'not_found', real: { status: 400, code: 'invalid' } },

  // ---- roles
  { name: 'no session', role: null, method: 'GET', path: '/findings', status: 401, code: 'unauthenticated' },
  { name: 'no session on detail', role: null, method: 'GET', path: '/findings/f-1', status: 401, code: 'unauthenticated' },
  { name: 'viewer cannot change status', role: 'viewer', method: 'POST', path: (c) => F(c) + '/status', body: status('patched'), status: 403, code: 'forbidden' },
  { name: 'viewer cannot log "Applied"', role: 'viewer', method: 'POST', path: (c) => `/findings/${c.pack}/applied`, body: { item: 'patch' }, status: 403, code: 'forbidden' },
  { name: 'viewer cannot ask the AI', role: 'viewer', method: 'POST', path: (c) => F(c) + '/ai', body: { skill: 'explain' }, status: 403, code: 'forbidden' },
  { name: 'status on an unknown finding', role: 'operator', method: 'POST', path: '/findings/f-nope/status', body: status('patched'), status: 404, code: 'not_found' },

  // ---- status
  { name: 'bad action', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('delete'), status: 400, code: 'bad_action', real: { code: 'invalid' } },
  { name: 'note of 501 characters', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('patched', 'n'.repeat(501)), status: 400, code: 'note_too_long', real: { code: 'invalid' } },
  { name: 'false positive needs a note', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('false_positive'), status: 400, code: 'note_required' },
  { name: 'not relevant with a 2 character note', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('not_relevant', 'ab'), status: 400, code: 'note_required' },
  { name: 'not relevant with spaces around a short note', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('not_relevant', '  ab  '), status: 400, code: 'note_required' },
  { name: 'reopen a finding that is open', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('reopen'), status: 409, code: 'already_open' },
  { name: 'patched', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('patched', '  updated by hand  '), status: 200, schema: FindingDetail,
    check: (b) => {
      expect([b.status, b.resolved_by, b.resolution_note]).toEqual(['patched', who('operator'), 'updated by hand'])
      expect(b.resolved_at).not.toBeNull()
      expect(lastHistory(b)).toMatchObject({ action: 'patched', user: who('operator'), note: 'updated by hand' })
    } },
  { name: 'the list shows it patched', role: 'viewer', method: 'GET', path: '/findings', status: 200, check: (b, c) => expect(b.items.find((f: { id: string }) => f.id === c.nopack).status).toBe('patched') },
  { name: 'patched again (a closed finding can be closed another way)', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('mitigated'), status: 200, schema: FindingDetail,
    check: (b) => { expect([b.status, b.resolution_note]).toEqual(['mitigated', null]) } },
  { name: 'false positive with a note', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('false_positive', 'we do not run it'), status: 200, schema: FindingDetail,
    check: (b) => expect([b.status, b.resolution_note]).toEqual(['false_positive', 'we do not run it']) },
  { name: 'reopen', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('reopen', 'it came back'), status: 200, schema: FindingDetail,
    check: (b) => {
      expect(OPEN).toContain(b.status)
      expect([b.resolved_by, b.resolved_at, b.resolution_note]).toEqual([null, null, null])
      expect(lastHistory(b)).toMatchObject({ action: 'reopened', note: 'it came back' })
      expect(b.history.filter((h: { action: string }) => !h.action.startsWith('applied:')).map((h: { action: string }) => h.action).slice(-4)).toEqual(['patched', 'mitigated', 'false_positive', 'reopened']) // only ever appended
      expect([...b.history].sort((x: { ts: string }, y: { ts: string }) => x.ts.localeCompare(y.ts))).toEqual(b.history)
    } },
  { name: 'not relevant', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('not_relevant', 'a test machine'), status: 200, schema: FindingDetail, check: (b) => expect(b.status).toBe('not_relevant') },
  { name: 'reopen again', role: 'operator', method: 'POST', path: (c) => F(c) + '/status', body: status('reopen'), status: 200, schema: FindingDetail, check: (b) => expect(OPEN).toContain(b.status) },
  { name: 'admin may change status too', role: 'admin', method: 'POST', path: (c) => F(c) + '/status', body: status('mitigated', 'firewall rule'), status: 200, schema: FindingDetail, check: (b) => expect(b.resolved_by).toBe(who('admin')) },
  { name: 'and reopen it', role: 'admin', method: 'POST', path: (c) => F(c) + '/status', body: status('reopen'), status: 200, schema: FindingDetail },

  // ---- "Applied"
  { name: '"Applied" on a CVE without a pack', role: 'operator', method: 'POST', path: (c) => F(c) + '/applied', body: { item: 'patch' }, status: 400, code: 'no_pack' },
  { name: '"Applied" with an unknown item', role: 'operator', method: 'POST', path: (c) => `/findings/${c.pack}/applied`, body: { item: 'reboot' }, status: 400, code: 'bad_item', real: { code: 'invalid' } },
  { name: '"Applied" on an unknown finding', role: 'operator', method: 'POST', path: '/findings/f-nope/applied', body: { item: 'patch' }, status: 404, code: 'not_found' },
  { name: '"Applied" logs the item and does not change the status', role: 'operator', method: 'POST', path: (c) => `/findings/${c.pack}/applied`, body: { item: 'mikrotik' }, status: 200, schema: FindingDetail,
    keep: (b, c) => { c.packStatus = b.status },
    check: (b) => {
      expect(b.applied.filter((a: { item: string }) => a.item === 'mikrotik')).toHaveLength(1)
      expect(b.applied.find((a: { item: string }) => a.item === 'mikrotik').user).toBe(who('operator'))
      expect(b.history.some((h: { action: string }) => h.action === 'applied:mikrotik')).toBe(true)
    } },
  { name: '"Applied" twice is still one entry', role: 'admin', method: 'POST', path: (c) => `/findings/${c.pack}/applied`, body: { item: 'mikrotik' }, status: 200, schema: FindingDetail,
    check: (b, c) => {
      expect(b.applied.filter((a: { item: string }) => a.item === 'mikrotik')).toHaveLength(1)
      expect(b.applied.find((a: { item: string }) => a.item === 'mikrotik').user).toBe(who('operator')) // the first person stays
      expect(b.history.filter((h: { action: string }) => h.action === 'applied:mikrotik')).toHaveLength(1)
      expect(b.status).toBe(c.packStatus)
    } },
  { name: 'every item of the pack can be logged', role: 'operator', method: 'POST', path: (c) => `/findings/${c.pack}/applied`, body: { item: 'patch' }, status: 200, schema: FindingDetail },
  { name: 'the applied log is read back', role: 'viewer', method: 'GET', path: (c) => `/findings/${c.pack}`, status: 200, schema: FindingDetail,
    check: (b) => expect(b.applied.map((a: { item: string }) => a.item)).toEqual(expect.arrayContaining(['mikrotik', 'patch'])) },

  // ---- AI
  { name: 'ask the AI with an unknown skill', role: 'operator', method: 'POST', path: (c) => F(c) + '/ai', body: { skill: 'chat' }, status: 400, code: 'bad_skill', real: { code: 'invalid' } },
  { name: 'ask the AI on an unknown finding', role: 'operator', method: 'POST', path: '/findings/f-nope/ai', body: { skill: 'explain' }, status: 404, code: 'not_found' },
  { name: 'ask the AI (the box has no AI wired yet)', role: 'operator', method: 'POST', path: (c) => F(c) + '/ai', body: { skill: 'explain' }, status: 200, schema: FindingDetail, real: { status: 409, code: 'ai_unavailable' },
    check: (b, _c, t) => { if (t === 'mock') expect(b.ai.explain.paragraphs.length).toBeGreaterThan(0) } },
]

// A real box keeps what an earlier (or failed) run left: make the two findings open again before starting and after the end.
async function reopen(target: 'mock' | 'real', c: Ctx) {
  for (const id of [c.nopack, c.pack]) {
    if (id) await call(target, { name: 'reopen', role: 'operator', method: 'POST', path: `/findings/${id}/status`, body: status('reopen'), status: 200 }, c)
  }
}

async function run(which: 'mock' | 'real') {
  target = which
  const c: Ctx = {}
  const problems: string[] = []
  for (const s of steps) {
    const want = { status: s.status, code: s.code, ...(target === 'real' ? s.real : {}) }
    let r: Res
    try { r = await call(target, s, c) } catch (e) { problems.push(`${s.name}: request failed: ${String(e)}`); continue }
    if (r.status !== want.status || (want.code !== undefined && r.code !== want.code)) {
      problems.push(`${s.name}: want ${want.status} ${want.code ?? ''}, got ${r.status} ${r.code ?? ''} "${r.message ?? ''}"`)
      continue
    }
    if (r.status < 300 && s.schema) {
      const p = s.schema.safeParse(r.body)
      if (!p.success) problems.push(`${s.name}: body does not match contract.ts: ${p.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
    }
    try { s.keep?.(r.body, c); s.check?.(r.body, c, target) } catch (e) { problems.push(`${s.name}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`) }
    if (s.name === 'list') await reopen(target, c)
  }
  await reopen(target, c)
  return problems
}

describe('findings and mitigation API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await run('mock')).toEqual([]) })
  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough())) // the MSW pattern `*/api/v1` would answer for any origin
    expect(await run('real')).toEqual([])
  }, 120_000)
})
