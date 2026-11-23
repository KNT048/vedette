// The same script of API calls runs against the GUI mock (always, also in CI) and against the real Go backend (only when
// VITE_EXPOSURE_REAL_URL is set; CI does not start a box, so this leg runs by hand before a change of the exposure handlers is merged).
// The mock is the approved behaviour: every step states the status and error code both give, and every 2xx body is checked against
// contract.ts.
// The real leg needs a box built from the same commit, as a container-only install (no vedette-host: a domain's token is then random
// instead of asked of the host), with the feeds, inventory and exposure modules on and three accounts:
//   go build -o /tmp/vedette-conf/vedette ./cmd/vedette
//   /tmp/vedette-conf/vedette -db /tmp/vedette-conf/vedette.db -key /tmp/vedette-conf/vedette.key -listen 127.0.0.1:18431 -host-socket ''
//   BOX_URL=http://127.0.0.1:18431 SETUP_CODE=<setup_code from its log> QA_PASSWORD=<a long password> BOX_MODULES=feeds,inventory,exposure \
//     BOX_SKIP_DATA=1 node web/e2e/qa/real-box.mjs
//   VITE_EXPOSURE_REAL_URL=http://127.0.0.1:18431 VITE_EXPOSURE_QA_PASSWORD=<the same password> pnpm --dir web exec vitest run src/features/exposure/conformance.test.ts
// The script adds two targets under example.org (their ownership check asks the box's DNS resolver for a record that is not there) and
// deletes them at the end; nothing is ever scanned (no target is proved).
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import { z, type ZodType } from 'zod'
import { server } from '@/test/server'
import { sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { Schedule } from '@/features/core/contract'
import { Address, Host, Issue, MAX_SELECTED, Scan, Service, TargetNode, TargetTree } from './contract'

const REAL = import.meta.env.VITE_EXPOSURE_REAL_URL as string | undefined
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }

interface Res { status: number; code: string | null; message: string | null; body: unknown }
type Ctx = Record<string, string>
interface Step {
  name: string
  role: Role | null
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  path: string | ((c: Ctx) => string)
  body?: unknown | ((c: Ctx) => unknown)
  status: number
  code?: string
  /** What the real backend answers where it deliberately differs from the mock. */
  real?: { status?: number; code?: string }
  schema?: ZodType
  keep?: (body: any, c: Ctx) => void // eslint-disable-line @typescript-eslint/no-explicit-any
  check?: (body: any, c: Ctx) => void // eslint-disable-line @typescript-eslint/no-explicit-any
}

const sessions = new Map<Role, { cookie: string; csrf: string }>()
async function realSession(role: Role) {
  const have = sessions.get(role)
  if (have) return have
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = await fetch(`${REAL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EMAIL[role], password: import.meta.env.VITE_EXPOSURE_QA_PASSWORD }) })
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

const run = Math.random().toString(36).slice(2, 8)
const APEX = `conf-${run}.example.org`
const CHILD = `git.${APEX}`
const items = <T extends ZodType>(t: T) => z.object({ items: z.array(t) })
const N = (k: string) => (c: Ctx) => `/exposure/tree/${c[k]}`
const S = (c: Ctx) => `/schedules/exposure.target:${c.apex}`

const steps: Step[] = [
  { name: 'the tree', role: 'viewer', method: 'GET', path: '/exposure/tree', status: 200, schema: TargetTree },
  { name: 'add a subdomain', role: 'admin', method: 'POST', path: '/exposure/tree', body: { value: CHILD, scope_mode: 'self' }, status: 201, schema: TargetNode,
    keep: (b, c) => { c.child = b.id },
    check: (b) => { expect(b).toMatchObject({ value: CHILD, kind: 'domain', scope_mode: 'self', parent_id: null, blocked: 'proof', deep: false }); expect(b.proof.state).toBe('missing') } },
  { name: 'add its apex: the subdomain moves under it', role: 'admin', method: 'POST', path: '/exposure/tree', body: { value: APEX }, status: 201, schema: TargetNode,
    keep: (b, c) => { c.apex = b.id },
    check: (b) => { expect(b).toMatchObject({ value: APEX, scope_mode: 'all', parent_id: null }); expect(b.schedule_key).toBe(`exposure.target:${b.id}`); expect(b.proof.dns.host).toBe('@') } },
  { name: 'an operator adds nothing', role: 'operator', method: 'POST', path: '/exposure/tree', body: { value: `x.${APEX}` }, status: 403 },
  { name: 'a duplicate', role: 'admin', method: 'POST', path: '/exposure/tree', body: { value: APEX }, status: 409, code: 'duplicate' },
  { name: 'a scope for an IP', role: 'admin', method: 'POST', path: '/exposure/tree', body: { value: '8.8.8.8', kind: 'ip', scope_mode: 'all' }, status: 400, code: 'bad_value' },
  { name: 'the tree puts the child under its parent', role: 'viewer', method: 'GET', path: '/exposure/tree', status: 200, schema: TargetTree,
    check: (b, c) => {
      const ids = (b.items as { id: string }[]).map((n) => n.id)
      expect(ids.indexOf(c.apex!)).toBeGreaterThanOrEqual(0)
      expect(ids.indexOf(c.child!)).toBe(ids.indexOf(c.apex!) + 1)
      expect((b.items as { id: string; parent_id: string | null }[]).find((n) => n.id === c.child)?.parent_id).toBe(c.apex)
    } },
  { name: 'one node', role: 'viewer', method: 'GET', path: N('apex'), status: 200, schema: TargetNode },
  { name: 'an unknown node', role: 'viewer', method: 'GET', path: '/exposure/tree/xt-none', status: 404, code: 'not_found' },
  { name: 'check ownership: the record is not there', role: 'operator', method: 'POST', path: (c) => `${N('apex')(c)}/verify`, status: 200,
    check: (b) => { expect(b.verified).toBe(false); TargetNode.parse(b.node) } },
  { name: 'names', role: 'viewer', method: 'GET', path: (c) => `${N('apex')(c)}/hosts`, status: 200, schema: items(Host), check: (b) => expect(b.items).toEqual([]) },
  { name: 'addresses', role: 'viewer', method: 'GET', path: (c) => `${N('apex')(c)}/addresses`, status: 200, schema: items(Address), check: (b) => expect(b.items).toEqual([]) },
  { name: 'services', role: 'viewer', method: 'GET', path: (c) => `${N('apex')(c)}/services`, status: 200, schema: items(Service), check: (b) => expect(b.items).toEqual([]) },
  { name: 'issues', role: 'viewer', method: 'GET', path: (c) => `${N('apex')(c)}/issues`, status: 200, schema: items(Issue), check: (b) => expect(b.items).toEqual([]) },
  { name: 'scans', role: 'viewer', method: 'GET', path: (c) => `${N('apex')(c)}/scans`, status: 200, schema: items(Scan), check: (b) => expect(b.items).toEqual([]) },
  { name: 'scan now without a proof', role: 'operator', method: 'POST', path: (c) => `${N('apex')(c)}/scan`, status: 409, code: 'not_verified' },
  { name: 'choose names: scope selected', role: 'admin', method: 'PATCH', path: N('apex'), body: { scope_mode: 'selected', selected: [] }, status: 200, schema: TargetNode,
    check: (b) => expect(b.scope_mode).toBe('selected') },
  { name: `more than ${MAX_SELECTED} names, refused with the reason`, role: 'admin', method: 'PATCH', path: N('apex'), body: { selected: Array.from({ length: MAX_SELECTED + 1 }, (_, i) => `xh-${i}`) }, status: 400, code: 'invalid' },
  { name: 'a name that is not its own', role: 'admin', method: 'PATCH', path: N('apex'), body: { selected: ['xh-none'] }, status: 400, code: 'bad_value' },
  { name: 'names chosen with another scope', role: 'admin', method: 'PATCH', path: N('child'), body: { selected: [] }, status: 400, code: 'bad_value' },
  { name: 'switch the child off', role: 'admin', method: 'PATCH', path: N('child'), body: { enabled: false }, status: 200, schema: TargetNode,
    check: (b) => expect(b).toMatchObject({ enabled: false, blocked: 'disabled' }) },
  { name: 'scan now of a node switched off', role: 'operator', method: 'POST', path: (c) => `${N('child')(c)}/scan`, status: 409, code: 'disabled' },
  // issues: the shared vocabulary's refusals come before the ids are looked at; unknown ids are skipped
  { name: 'handle: unknown issues are skipped', role: 'operator', method: 'POST', path: '/exposure/issues/handle', body: { ids: ['xi-none'], resolution: 'patched', note: '' }, status: 200,
    check: (b) => expect(b).toEqual({ handled: 0, skipped: 1 }) },
  { name: 'handle: a note for not relevant', role: 'operator', method: 'POST', path: '/exposure/issues/handle', body: { ids: ['xi-none'], resolution: 'not_relevant', note: 'x' }, status: 400, code: 'note_required' },
  { name: 'handle: accepted needs a last day', role: 'operator', method: 'POST', path: '/exposure/issues/handle', body: { ids: ['xi-none'], resolution: 'accepted', note: 'a partner needs it' }, status: 400, code: 'bad_until' },
  { name: 'handle: no ids', role: 'operator', method: 'POST', path: '/exposure/issues/handle', body: { ids: [], resolution: 'patched', note: '' }, status: 400, code: 'invalid' },
  { name: 'handle: a viewer', role: 'viewer', method: 'POST', path: '/exposure/issues/handle', body: { ids: ['xi-none'], resolution: 'patched', note: '' }, status: 403 },
  { name: 'reopen: unknown issues are skipped', role: 'operator', method: 'POST', path: '/exposure/issues/reopen', body: { ids: ['xi-none'] }, status: 200,
    check: (b) => expect(b).toEqual({ reopened: 0, skipped: 1 }) },
  // the schedule of a node is a shared schedule
  { name: 'the schedule of a node', role: 'viewer', method: 'GET', path: S, status: 200, schema: Schedule,
    check: (b) => { expect(b).toMatchObject({ enabled: true, edit_role: 'admin', rule: { freq: 'weekly', window: 'global' } }); expect(b.limits.min_every_minutes).toBe(360) } },
  { name: 'an hourly scan is refused', role: 'admin', method: 'PUT', path: S, body: { enabled: true, paused_until: null, rule: { freq: 'interval', every_minutes: 60, at_time: null, weekdays: null, month_day: null, once_at: null, tz: 'org', window: 'none', window_days: null, window_from: null, window_to: null } }, status: 400 },
  { name: 'an operator changes nothing', role: 'operator', method: 'PUT', path: S, body: { enabled: false, paused_until: null, rule: { freq: 'weekly', every_minutes: null, at_time: '02:30', weekdays: [1], month_day: null, once_at: null, tz: 'org', window: 'global', window_days: null, window_from: null, window_to: null } }, status: 403 },
  { name: 'every 3 days at 02:30 on working days', role: 'admin', method: 'PUT', path: S, body: { enabled: true, paused_until: null, rule: { freq: 'interval', every_minutes: 4320, at_time: '02:30', weekdays: null, month_day: null, once_at: null, tz: 'org', window: 'custom', window_days: [1, 2, 3, 4, 5], window_from: '00:00', window_to: '00:00' } }, status: 200, schema: Schedule,
    check: (b) => { expect(b.rule.freq).toBe('interval'); expect(b.upcoming).toHaveLength(3) } },
  { name: 'run once now of a node without a proof', role: 'admin', method: 'POST', path: (c) => `${S(c)}/run`, status: 409, code: 'not_started' },
  // the end: the nodes go, and their schedules with them
  { name: 'delete the apex', role: 'admin', method: 'DELETE', path: N('apex'), status: 204 },
  { name: 'its schedule is gone', role: 'viewer', method: 'GET', path: S, status: 404, code: 'not_found' },
  { name: 'the child moved up', role: 'viewer', method: 'GET', path: N('child'), status: 200, schema: TargetNode, check: (b) => expect(b.parent_id).toBeNull() },
  { name: 'delete the child', role: 'admin', method: 'DELETE', path: N('child'), status: 204 },
]
let target: 'mock' | 'real' = 'mock'
async function runScript(which: 'mock' | 'real') {
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
    try { s.keep?.(r.body, c); s.check?.(r.body, c) } catch (e) { problems.push(`${s.name}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`) }
  }
  return problems
}

describe('external exposure API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await runScript('mock')).toEqual([]) })
  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough()))
    expect(await runScript('real')).toEqual([])
  }, 120_000)
})
