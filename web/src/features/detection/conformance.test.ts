// The same script of API calls runs against the GUI mock (always) and against the real Go backend (only when
// VITE_DETECTION_REAL_URL is set, on a box with the logs and ids modules on; VITE_DETECTION_QA_PASSWORD is the password of
// admin@qa.test and view@qa.test). The mock is the approved behaviour: every step states the status and error code the mock
// gives and, where the real backend deliberately differs, what it gives instead. Every 2xx body is checked against contract.ts.
//   VITE_DETECTION_REAL_URL=http://127.0.0.1:8080 VITE_DETECTION_QA_PASSWORD=... pnpm --dir web exec vitest run src/features/detection/conformance.test.ts
// Steps that read the sample alerts run only on the mock: a real box has its own.
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import { server } from '@/test/server'
import type { ZodType } from 'zod'
import { modulesStore, sessionStore } from '@/mocks/stores'
import { FINDING_STATUSES, INCIDENT_STATUSES } from '@/lib/statusCodes'
import { Alert, AlertsResponse, Overview } from './contract'
import { DETECTION_KINDS, WATCHER_IDS } from './types'
import { accepted } from '@/features/findings/mocks'

const REAL = import.meta.env.VITE_DETECTION_REAL_URL as string | undefined
type Role = 'admin' | 'viewer'
const USER: Record<Role, string> = { admin: 'u-admin', viewer: 'u-view' }
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', viewer: 'view@qa.test' }

interface Res { status: number; code: string | null; body: unknown }
interface Step {
  name: string
  role: Role | null
  path: string
  status: number
  code?: string
  only?: 'mock'
  real?: { status?: number; code?: string }
  schema?: ZodType
  check?: (body: any) => void // eslint-disable-line @typescript-eslint/no-explicit-any
}

const cookies = new Map<Role, string>()
async function realCookie(role: Role) {
  const have = cookies.get(role)
  if (have) return have
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = await fetch(`${REAL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EMAIL[role], password: import.meta.env.VITE_DETECTION_QA_PASSWORD }) })
    if (r.status === 503) { await new Promise((ok) => setTimeout(ok, 500)); continue } // the box checks one password at a time
    if (!r.ok) throw new Error(`login as ${role}: ${r.status}`)
    const jar = r.headers.getSetCookie().map((c) => c.split(';')[0]!).join('; ')
    cookies.set(role, jar)
    return jar
  }
  throw new Error(`login as ${role}: the box stayed busy`)
}

async function call(target: 'mock' | 'real', s: Step): Promise<Res> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  let base = 'http://localhost'
  if (target === 'real') {
    base = REAL!
    if (s.role) headers.Cookie = await realCookie(s.role)
  } else sessionStore.set({ userId: s.role ? USER[s.role] : null })
  const r = await fetch(`${base}/api/v1${s.path}`, { headers })
  const data: unknown = await r.json().catch(() => null)
  return { status: r.status, code: (data as { error?: { code?: string } } | null)?.error?.code ?? null, body: data }
}

const ids = (b: { items: { id: string }[] }) => b.items.map((a) => a.id)

const steps: Step[] = [
  // ---- overview
  { name: 'overview', role: 'viewer', path: '/detection/overview', status: 200, schema: Overview,
    check: (b) => {
      expect(b.watchers.map((w: { id: string }) => w.id)).toEqual(WATCHER_IDS)
      expect(b.kinds.map((k: { kind: string }) => k.kind)).toEqual(DETECTION_KINDS)
      for (const k of b.kinds) expect(k.new).toBeLessThanOrEqual(k.incidents)
      expect(b.mirror_port_hits.latest.length).toBe(Math.min(5, b.mirror_port_hits.total))
      expect(b.alerts.affected).toBeLessThanOrEqual(b.alerts.total)
    } },
  { name: 'overview without a session', role: null, path: '/detection/overview', status: 401, code: 'unauthenticated' },

  // ---- alerts: reads, filters, order, paging
  { name: 'alerts of 7 days', role: 'viewer', path: '/detection/alerts?window=7d', status: 200, schema: AlertsResponse,
    check: (b) => {
      expect(b.total).toBe(b.items.length)
      const last = b.items.map((a: { last_seen: string }) => a.last_seen)
      expect([...last].sort().reverse()).toEqual(last)
      for (const a of b.items) {
        expect([...a.cves].sort()).toEqual(a.cves)
        for (const f of a.findings) { expect(FINDING_STATUSES).toContain(f.status); expect(a.cves).toContain(f.cve); expect(f.device).toEqual(a.dst_device) }
        if (a.incident) expect(INCIDENT_STATUSES).toContain(a.incident.status)
      }
    } },
  { name: 'the sample alerts of 7 days', role: 'viewer', path: '/detection/alerts?window=7d', status: 200, only: 'mock', check: (b) => expect(ids(b)).toEqual(['ida-4', 'ida-1', 'ida-2', 'ida-3']) },
  { name: 'an older alert is in the 30-day window', role: 'viewer', path: '/detection/alerts?window=30d', status: 200, only: 'mock', check: (b) => expect(ids(b)).toContain('ida-5') },
  { name: 'an attack on an affected device: its finding is under attack and the alert is critical', role: 'viewer', path: '/detection/alerts?window=7d&cve=CVE-2022-27593', status: 200, only: 'mock',
    check: (b) => {
      expect(ids(b)).toEqual(['ida-1'])
      expect(b.items[0]).toMatchObject({ severity: 'critical', dst_device: { id: 'a-nas02' }, findings: [{ id: 'f-1', cve: 'CVE-2022-27593', status: 'under_attack' }], incident: { id: 'in-ids-1', status: 'new' } })
    } },
  { name: 'an attack on a device that is not affected links no finding', role: 'viewer', path: '/detection/alerts/ida-2', status: 200, schema: Alert, only: 'mock',
    check: (b) => expect([b.severity, b.findings, b.cves]).toEqual(['high', [], ['CVE-2021-41773', 'CVE-2021-42013']]) },
  { name: 'filtered by device (source or destination)', role: 'viewer', path: '/detection/alerts?window=30d&device=a-fw01', status: 200, only: 'mock', check: (b) => expect(ids(b)).toEqual(['ida-4', 'ida-5']) },
  { name: 'searched over the signature', role: 'viewer', path: '/detection/alerts?window=7d&q=smb1', status: 200, only: 'mock', check: (b) => expect(ids(b)).toEqual(['ida-3']) },
  { name: 'searched over a device name', role: 'viewer', path: '/detection/alerts?window=7d&q=nas', status: 200, only: 'mock', check: (b) => expect(ids(b)).toContain('ida-1') },
  { name: 'most events first', role: 'viewer', path: '/detection/alerts?window=7d&sort=count', status: 200, only: 'mock', check: (b) => expect(ids(b)).toEqual(['ida-4', 'ida-1', 'ida-2', 'ida-3']) },
  { name: 'one page', role: 'viewer', path: '/detection/alerts?window=7d&offset=1&limit=2', status: 200, schema: AlertsResponse, only: 'mock', check: (b) => expect([ids(b), b.total]).toEqual([['ida-1', 'ida-2'], 4]) },
  { name: 'a search that matches nothing', role: 'viewer', path: '/detection/alerts?window=7d&q=zzzz-no-such-alert', status: 200, schema: AlertsResponse, check: (b) => expect(b).toEqual({ items: [], total: 0 }) },
  { name: 'no window', role: 'viewer', path: '/detection/alerts', status: 400, code: 'bad_window', real: { code: 'invalid' } },
  { name: 'bad window', role: 'viewer', path: '/detection/alerts?window=2h', status: 400, code: 'bad_window', real: { code: 'invalid' } },
  { name: 'bad CVE', role: 'viewer', path: '/detection/alerts?window=7d&cve=CVE-22-1', status: 400, code: 'invalid_cve' },
  { name: 'alerts without a session', role: null, path: '/detection/alerts?window=7d', status: 401, code: 'unauthenticated' },
  { name: 'an unknown alert', role: 'viewer', path: '/detection/alerts/ida-nope', status: 404, code: 'not_found' },
]

async function run(target: 'mock' | 'real') {
  const problems: string[] = []
  for (const s of steps) {
    if (s.only && s.only !== target) continue
    const want = { status: s.status, code: s.code, ...(target === 'real' ? s.real : {}) }
    let r: Res
    try { r = await call(target, s) } catch (e) { problems.push(`${s.name}: request failed: ${String(e)}`); continue }
    if (r.status !== want.status || (want.code !== undefined && r.code !== want.code)) { problems.push(`${s.name}: want ${want.status} ${want.code ?? ''}, got ${r.status} ${r.code ?? ''}`); continue }
    if (r.status < 300 && s.schema) {
      const p = s.schema.safeParse(r.body)
      if (!p.success) problems.push(`${s.name}: body does not match contract.ts: ${p.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
    }
    try { s.check?.(r.body) } catch (e) { problems.push(`${s.name}: ${e instanceof Error ? e.message.split('\n')[0] : String(e)}`) }
  }
  return problems
}

describe('detection API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await run('mock')).toEqual([]) })

  it('the overview says which watcher is off, and the alerts are not there while the ids module is off', async () => {
    modulesStore.update((l) => l.map((m) => (m.id === 'honeypot' || m.id === 'logs' ? { ...m, enabled: false } : m)))
    modulesStore.update((l) => [...l, { id: 'ids' as never, enabled: false, tier: 'optional', depends: ['logs'], enabled_at: null }])
    try {
      sessionStore.set({ userId: USER.viewer })
      const o = Overview.parse(await (await fetch('http://localhost/api/v1/detection/overview')).json())
      expect(o.watchers.map((w) => [w.id, w.state, w.action])).toEqual([['traps', 'off', 'turn_on'], ['logs', 'off', 'turn_on'], ['mirror_port', expect.any(String), expect.any(String)], ['ips_events', 'off', 'turn_on']])
      expect(o.alerts.total).toBe(0)
      expect((await fetch('http://localhost/api/v1/detection/alerts?window=7d')).status).toBe(404)
    } finally {
      modulesStore.update((l) => l.filter((m) => (m.id as string) !== 'ids').map((m) => (m.id === 'honeypot' || m.id === 'logs' ? { ...m, enabled: true } : m)))
    }
  })

  it('an accepted risk is handled: the finding says accepted and the alert is not raised to critical', async () => {
    accepted.update((m) => ({ ...m, 'f-1': '2999-12-31' }))
    try {
      sessionStore.set({ userId: USER.viewer })
      const a = Alert.parse(await (await fetch('http://localhost/api/v1/detection/alerts/ida-1')).json())
      expect([a.severity, a.findings.map((f) => [f.id, f.status])]).toEqual(['high', [['f-1', 'accepted']]])
    } finally {
      accepted.update((m) => { const n = { ...m }; delete n['f-1']; return n })
    }
  })

  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough())) // the MSW pattern `*/api/v1` would answer for any origin
    expect(await run('real')).toEqual([])
  }, 120_000)
})
