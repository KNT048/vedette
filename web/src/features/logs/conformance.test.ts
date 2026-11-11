// The same script of API calls runs against the GUI mock (always) and against the real Go backend (only when
// VITE_LOGS_REAL_URL is set: make dev-api REAL=core,inventory,feeds,logs on a box prepared like web/e2e/qa/real-box.mjs with the
// logs module on; VITE_LOGS_QA_PASSWORD is the password of admin@qa.test, op@qa.test and view@qa.test). The mock is the approved
// behaviour (GUI-first, D-18): every step states the status and error code the mock gives and, where the real backend
// deliberately differs (D-73: limits that contract.ts states are refused by the generated validator as 400 `invalid`), what
// it gives instead. Every 2xx body is checked against the zod schema of contract.ts. Run against the real backend:
//   VITE_LOGS_REAL_URL=http://127.0.0.1:8080 VITE_LOGS_QA_PASSWORD=... pnpm --dir web exec vitest run src/features/logs/conformance.test.ts
// Covers what L1 of the module builds (sources, events, retention, digest); the SIEM operations come with L5.
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import { server } from '@/test/server'
import type { ZodType } from 'zod'
import { sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { Digest, EventsResponse, LogSource, SourcesResponse } from './contract'

const REAL = import.meta.env.VITE_LOGS_REAL_URL as string | undefined
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }

interface Res { status: number; code: string | null; message: string | null; body: unknown }
type Ctx = Record<string, string>
interface Step {
  name: string
  role: Role | null
  method: 'GET' | 'POST' | 'PUT' | 'DELETE'
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

const sessions = new Map<Role, { cookie: string; csrf: string }>()
async function realSession(role: Role) {
  const have = sessions.get(role)
  if (have) return have
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = await fetch(`${REAL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EMAIL[role], password: import.meta.env.VITE_LOGS_QA_PASSWORD }) })
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

const SRC = (over: Record<string, unknown> = {}) => ({ kind: 'fortigate', name: 'conf-fw', sender_ip: '192.168.77.5', proto: 'udp', port: 514, ...over })
const ID = (c: Ctx) => `/logs/sources/${c.id}`

const steps: Step[] = [
  // ---- reads and roles
  { name: 'sources', role: 'viewer', method: 'GET', path: '/logs/sources', status: 200, schema: SourcesResponse,
    check: (b) => { expect([7, 30, 90, 180]).toContain(b.retention_days); expect(typeof b.box.hostname).toBe('string') } },
  { name: 'no session', role: null, method: 'GET', path: '/logs/sources', status: 401, code: 'unauthenticated' },
  { name: 'viewer cannot add a source', role: 'viewer', method: 'POST', path: '/logs/sources', body: SRC(), status: 403, code: 'forbidden' },
  { name: 'operator cannot add a source', role: 'operator', method: 'POST', path: '/logs/sources', body: SRC(), status: 403, code: 'forbidden' },
  { name: 'operator cannot change the retention', role: 'operator', method: 'PUT', path: '/logs/retention', body: { days: 7 }, status: 403, code: 'forbidden' },
  { name: 'viewer cannot delete a source', role: 'viewer', method: 'DELETE', path: '/logs/sources/ls-1', status: 403, code: 'forbidden' },

  // ---- sources
  { name: 'add a source', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC(), status: 201, schema: LogSource, keep: (b, c) => { c.id = b.id },
    check: (b) => expect([b.state, b.last_received, b.lines_per_hour, b.name, b.proto, b.port]).toEqual(['never', null, 0, 'conf-fw', 'udp', 514]) },
  { name: 'the name is trimmed', role: 'admin', method: 'PUT', path: ID, body: SRC({ name: '  conf-fw2  ' }), status: 200, schema: LogSource, check: (b) => expect(b.name).toBe('conf-fw2'),
    real: { status: 400, code: 'invalid' } }, // D-73: contract.ts's name pattern is checked before the handler can trim; the GUI sends the trimmed name
  { name: 'the new source is listed', role: 'viewer', method: 'GET', path: '/logs/sources', status: 200, schema: SourcesResponse,
    check: (b, c) => expect(b.sources.some((s: { id: string }) => s.id === c.id)).toBe(true) },
  { name: 'duplicate sender IP', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ name: 'other' }), status: 409, code: 'duplicate' },
  { name: 'unknown kind', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ kind: 'cisco-9000', sender_ip: '192.168.77.6' }), status: 400, code: 'bad_kind', real: { code: 'invalid' } },
  { name: 'name with a space', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ name: 'bad name', sender_ip: '192.168.77.6' }), status: 400, code: 'bad_name', real: { code: 'invalid' } },
  { name: 'IP out of range', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ sender_ip: '192.168.77.300' }), status: 400, code: 'bad_ip', real: { code: 'invalid' } },
  { name: 'protocol the kind cannot send', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ kind: 'sophos', proto: 'tcp', sender_ip: '192.168.77.6' }), status: 400, code: 'bad_proto' },
  { name: 'port 0', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ port: 0, sender_ip: '192.168.77.6' }), status: 400, code: 'bad_port', real: { code: 'invalid' } },
  { name: 'port 65536', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ port: 65536, sender_ip: '192.168.77.6' }), status: 400, code: 'bad_port', real: { code: 'invalid' } },
  { name: 'proto tls', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ proto: 'tls', port: 6514, sender_ip: '192.168.77.8' }), status: 201, schema: LogSource,
    real: { status: 400, code: 'tls_unavailable' } }, // D-203: the real box refuses TLS until the TLS listener exists; the catalog and the mock still offer it, and the form shows the server's message
  { name: 'add a second source', role: 'admin', method: 'POST', path: '/logs/sources', body: SRC({ name: 'conf-fw-b', sender_ip: '192.168.77.7' }), status: 201, schema: LogSource, keep: (b, c) => { c.id2 = b.id } },
  { name: 'edit takes the second source\'s IP', role: 'admin', method: 'PUT', path: ID, body: SRC({ sender_ip: '192.168.77.7' }), status: 409, code: 'duplicate' },
  { name: 'edit an unknown source', role: 'admin', method: 'PUT', path: '/logs/sources/ls-nope', body: SRC({ sender_ip: '192.168.77.9' }), status: 404, code: 'not_found' },
  { name: 'delete an unknown source', role: 'admin', method: 'DELETE', path: '/logs/sources/ls-nope', status: 404, code: 'not_found' },

  // ---- events
  { name: 'events of the last 24 hours', role: 'viewer', method: 'GET', path: '/logs/events?window=24h', status: 200, schema: EventsResponse,
    check: (b) => { expect(b.events.length).toBeLessThanOrEqual(200); expect(b.total).toBeGreaterThanOrEqual(b.events.length) } },
  { name: 'events newest first', role: 'viewer', method: 'GET', path: '/logs/events?window=7d', status: 200, schema: EventsResponse,
    check: (b) => { const ts = b.events.map((e: { ts: string }) => e.ts); expect([...ts].sort().reverse()).toEqual(ts) } },
  { name: 'events of one source', role: 'viewer', method: 'GET', path: (c) => `/logs/events?window=24h&source=${c.id}`, status: 200, schema: EventsResponse, check: (b) => expect(b).toMatchObject({ events: [], total: 0 }) },
  { name: 'a keyword that matches nothing', role: 'viewer', method: 'GET', path: '/logs/events?window=24h&q=zzzz-no-such-line', status: 200, schema: EventsResponse, check: (b) => expect(b).toMatchObject({ events: [], total: 0 }) },
  { name: 'bad window', role: 'viewer', method: 'GET', path: '/logs/events?window=2h', status: 400, code: 'bad_window', real: { code: 'invalid' } },
  { name: 'keyword of 201 characters', role: 'viewer', method: 'GET', path: `/logs/events?window=24h&q=${'a'.repeat(201)}`, status: 200, real: { status: 400, code: 'invalid' } },

  // ---- delete, retention, digest
  { name: 'delete the source', role: 'admin', method: 'DELETE', path: ID, status: 204 },
  { name: 'delete the second source', role: 'admin', method: 'DELETE', path: (c) => `/logs/sources/${c.id2}`, status: 204 },
  { name: 'delete it again', role: 'admin', method: 'DELETE', path: ID, status: 404, code: 'not_found' },
  { name: 'retention 90 days', role: 'admin', method: 'PUT', path: '/logs/retention', body: { days: 90 }, status: 200, check: (b) => expect(b).toEqual({ retention_days: 90 }) },
  { name: 'it is read back', role: 'viewer', method: 'GET', path: '/logs/sources', status: 200, schema: SourcesResponse, check: (b) => expect(b.retention_days).toBe(90) },
  { name: 'retention 14 days', role: 'admin', method: 'PUT', path: '/logs/retention', body: { days: 14 }, status: 400, code: 'bad_days', real: { code: 'invalid' } },
  { name: 'retention back to 30 days', role: 'admin', method: 'PUT', path: '/logs/retention', body: { days: 30 }, status: 200, check: (b) => expect(b.retention_days).toBe(30) },
  { name: 'digest', role: 'viewer', method: 'GET', path: '/logs/digest', status: 200, schema: Digest, check: (b) => expect(b.baseline_days).toBe(7) },
]

async function run(target: 'mock' | 'real') {
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
    if (r.status < 300 && s.schema && r.status !== 204) {
      const p = s.schema.safeParse(r.body)
      if (!p.success) problems.push(`${s.name}: body does not match contract.ts: ${p.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
    }
    try { s.keep?.(r.body, c); s.check?.(r.body, c, target) } catch (e) { problems.push(`${s.name}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`) }
  }
  return problems
}

describe('logs API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await run('mock')).toEqual([]) })
  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough())) // the MSW pattern `*/api/v1` would answer for any origin
    expect(await run('real')).toEqual([])
  }, 120_000)
})
