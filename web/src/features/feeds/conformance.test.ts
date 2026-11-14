// The same script of API calls runs against the GUI mock (always) and against the real Go backend (only when
// VITE_FEEDS_REAL_URL is set, i.e. make dev-api REAL=core,feeds; VITE_FEEDS_QA_PASSWORD is the password of admin@qa.test, op@qa.test and view@qa.test). The mock is the approved behaviour (GUI-first, D-18), so every
// step states the status and error code the mock gives and, where the real backend deliberately differs
// (modules/feeds/CONTRACT.md, "Khác contract.ts/mock"), what it gives instead. Every 2xx body is checked against the
// zod schema of contract.ts. Run against the real backend:
//   VITE_FEEDS_REAL_URL=http://127.0.0.1:8080 VITE_FEEDS_QA_PASSWORD=... pnpm --dir web exec vitest run src/features/feeds/conformance.test.ts
import { describe, expect, it } from 'vitest'
import { http, passthrough } from 'msw'
import { server } from '@/test/server'
import type { ZodType } from 'zod'
import { sessionStore } from '@/mocks/stores'
import type { Role } from '@/lib/session'
import { CveDetail, Feed, FeedList, FeedStatus, HotResponse, ParseResult, SearchResult, WeeklyResponse } from './contract'
import { defaultParser } from './defaults'
import type { FeedFormat, FeedKind } from './types'

const REAL = import.meta.env.VITE_FEEDS_REAL_URL as string | undefined
const USER: Record<Role, string> = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' }

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
  /** Depends on the mock's sample data (an IOC list, a CVE with an anchor): skipped on a real box, the Go tests cover it. */
  mockOnly?: boolean
  schema?: ZodType
  keep?: (body: any, c: Ctx) => void // eslint-disable-line @typescript-eslint/no-explicit-any
  check?: (body: any, c: Ctx, target: 'mock' | 'real') => void // eslint-disable-line @typescript-eslint/no-explicit-any
}

// Real mode signs in through the real login (POST /auth/login) as the three accounts of the box: admin@qa.test, op@qa.test, view@qa.test
// with the password in VITE_FEEDS_QA_PASSWORD. Test-only, so the cookies and the
// double-submit CSRF header are assembled by hand.
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }
const sessions = new Map<Role, { cookie: string; csrf: string }>()
async function realSession(role: Role) {
  const have = sessions.get(role)
  if (have) return have
  for (let attempt = 0; attempt < 10; attempt++) {
    const r = await fetch(`${REAL}/api/v1/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: EMAIL[role], password: import.meta.env.VITE_FEEDS_QA_PASSWORD }) })
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

const input = (over: Record<string, unknown> = {}) => ({
  name: 'Partner blocklist', kind: 'ioc', url: 'https://threat-share.example.net/list.csv', enabled: true, interval_hours: 6,
  auth: { type: 'none', header_name: null, username: null }, parser: defaultParser('ioc', 'csv'), ...over,
})
const withAuth = (auth: Record<string, unknown>) => input({ name: 'Auth probe', auth: { type: 'none', header_name: null, username: null, ...auth } })
const parseTest = (kind: FeedKind, format: FeedFormat, extra: Record<string, unknown> = {}) => ({ kind, parser: defaultParser(kind, format), ...extra })
const FEED = '/feeds/custom'

const steps: Step[] = [
  // ---- reads
  { name: 'status', role: 'viewer', method: 'GET', path: '/feeds/status', status: 200, schema: FeedStatus },
  { name: 'hot 7d', role: 'viewer', method: 'GET', path: '/feeds/hot?window=7d', status: 200, schema: HotResponse },
  { name: 'hot 24h', role: 'viewer', method: 'GET', path: '/feeds/hot?window=24h', status: 200, schema: HotResponse },
  { name: 'hot bad window', role: 'viewer', method: 'GET', path: '/feeds/hot?window=1h', status: 400, code: 'bad_window', real: { code: 'invalid' } },
  { name: 'weekly', role: 'viewer', method: 'GET', path: '/feeds/weekly', status: 200, schema: WeeklyResponse, keep: (b, c) => { c.cve = b.items[0].cve; c.week = b.items[0].id } },
  { name: 'cve found', role: 'viewer', method: 'GET', path: (c) => `/feeds/cve/${c.cve}`, status: 200, schema: CveDetail },
  { name: 'cve lower case', role: 'viewer', method: 'GET', path: (c) => `/feeds/cve/${c.cve!.toLowerCase()}`, status: 200, real: { status: 400, code: 'invalid' } },
  { name: 'cve whose link has an anchor', mockOnly: true, role: 'viewer', method: 'GET', path: '/feeds/cve/CVE-2021-3199', status: 200, schema: CveDetail, check: (b) => expect(b.links[0]).toMatch(/CHANGELOG.md#563$/) },
  { name: 'cve not in KEV', role: 'viewer', method: 'GET', path: '/feeds/cve/CVE-1999-0001', status: 404, code: 'not_in_kev' },
  { name: 'search CVE found', role: 'viewer', method: 'GET', path: (c) => `/feeds/search?q=${c.cve}`, status: 200, schema: SearchResult, check: (b) => expect(b).toMatchObject({ kind: 'cve', found: true }) },
  { name: 'search CVE not found', role: 'viewer', method: 'GET', path: '/feeds/search?q=CVE-1999-0001', status: 200, schema: SearchResult, check: (b) => expect(b).toMatchObject({ kind: 'cve', found: false }) },
  { name: 'search known bad IP', mockOnly: true, role: 'viewer', method: 'GET', path: '/feeds/search?q=185.220.101.47', status: 200, schema: SearchResult,
    check: (b, _c, t) => { expect(b.kind).toBe('ioc'); if (t === 'real') expect(b.hit).toMatchObject({ verdict: 'block' }) } },
  { name: 'search unknown IP', role: 'viewer', method: 'GET', path: '/feeds/search?q=8.8.4.4', status: 200, schema: SearchResult, check: (b) => expect(b).toMatchObject({ kind: 'ioc', hit: null }) },
  { name: 'search text', role: 'viewer', method: 'GET', path: '/feeds/search?q=apple', status: 200, schema: SearchResult, check: (b) => expect(b.kind).toBe('text') },
  { name: 'search blank', role: 'viewer', method: 'GET', path: '/feeds/search?q=%20%20', status: 400, code: 'empty_query' },
  { name: 'search 201 characters', role: 'viewer', method: 'GET', path: `/feeds/search?q=${'a'.repeat(201)}`, status: 200, real: { status: 400, code: 'invalid' } },
  { name: 'sources list', role: 'viewer', method: 'GET', path: '/feeds/sources', status: 200, schema: FeedList,
    check: (b) => { expect(b.items.filter((f: { builtin: boolean }) => f.builtin).map((f: { id: string }) => f.id)).toEqual(['cisa-kev', 'first-epss', 'nvd-kev', 'cve-org', 'vulncheck-kev', 'ubuntu-osv', 'ubuntu-vex', 'debian-tracker', 'nuclei-templates', 'ipsum', 'et-open', 'abusech-feodo', 'tor-exit', 'hagezi-tif']) } },

  // ---- roles
  { name: 'no session', role: null, method: 'GET', path: '/feeds/status', status: 401, code: 'unauthenticated' },
  { name: 'VulnCheck KEV is off until a key is saved', role: 'viewer', method: 'GET', path: '/feeds/sources', status: 200, schema: FeedList,
    check: (b) => { const f = b.items.find((x: { id: string }) => x.id === 'vulncheck-kev'); expect([f.enabled, f.auth.type, f.auth.secret_last4, f.status]).toEqual([false, 'none', null, 'never']) } },
  { name: 'VulnCheck KEV cannot be turned on without a key', role: 'admin', method: 'PUT', path: '/feeds/sources/vulncheck-kev', body: { enabled: true }, status: 400, code: 'invalid_auth' },
  { name: 'a key on a feed that takes none', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { api_key: 'abcd1234efgh' }, status: 400, code: 'invalid_auth' },
  { name: 'a key that is too short', role: 'admin', method: 'PUT', path: '/feeds/sources/vulncheck-kev', body: { api_key: 'short' }, status: 400, code: 'invalid_auth' },
  { name: 'saving the VulnCheck key turns the feed on and shows only its last 4', role: 'admin', method: 'PUT', path: '/feeds/sources/vulncheck-kev', body: { api_key: 'abcd1234efgh' }, status: 200, schema: Feed,
    check: (b) => { expect([b.enabled, b.auth.type, b.auth.secret_last4]).toEqual([true, 'bearer', 'efgh']); expect(JSON.stringify(b)).not.toContain('abcd1234') } },
  { name: 'removing the key turns the feed off', role: 'admin', method: 'PUT', path: '/feeds/sources/vulncheck-kev', body: { api_key: '' }, status: 200, schema: Feed,
    check: (b) => expect([b.enabled, b.auth.type, b.auth.secret_last4, b.status]).toEqual([false, 'none', null, 'never']) },
  { name: 'viewer cannot change a feed', role: 'viewer', method: 'PUT', path: '/feeds/sources/cisa-kev', body: { enabled: false }, status: 403, code: 'forbidden' },
  { name: 'operator cannot add a feed', role: 'operator', method: 'POST', path: FEED, body: input(), status: 403, code: 'forbidden' },
  { name: 'operator cannot parse-test', role: 'operator', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines'), status: 403, code: 'forbidden' },
  { name: 'viewer cannot answer "this week"', role: 'viewer', method: 'POST', path: (c) => `/feeds/weekly/${encodeURIComponent(c.week!)}`, body: { answer: 'not_relevant' }, status: 403, code: 'forbidden' },
  { name: 'operator answers "not relevant"', role: 'operator', method: 'POST', path: (c) => `/feeds/weekly/${encodeURIComponent(c.week!)}`, body: { answer: 'not_relevant' }, status: 200, schema: WeeklyResponse,
    check: (b, c) => expect(b.items.find((i: { id: string }) => i.id === c.week).answer).toBe('not_relevant') },
  { name: 'answer for an unknown item', role: 'operator', method: 'POST', path: '/feeds/weekly/nope', body: { answer: 'have' }, status: 404, code: 'not_found' },
  { name: 'bad answer', role: 'operator', method: 'POST', path: (c) => `/feeds/weekly/${encodeURIComponent(c.week!)}`, body: { answer: 'maybe' }, status: 400, code: 'bad_answer', real: { code: 'invalid' } },

  // ---- built-in feeds
  { name: 'turn a built-in feed off', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { enabled: false }, status: 200, schema: Feed, check: (b) => expect(b.enabled).toBe(false) },
  { name: 'fetch a feed that is off', role: 'admin', method: 'POST', path: '/feeds/sources/ipsum/fetch', body: {}, status: 409, code: 'feed_disabled' },
  { name: 'turn it on', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { enabled: true, interval_hours: 12 }, status: 200, schema: Feed, check: (b) => expect([b.enabled, b.interval_hours]).toEqual([true, 12]) },
  { name: 'interval 0', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { interval_hours: 0 }, status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'interval 169', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { interval_hours: 169 }, status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'mirror with ftp', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { url: 'ftp://mirror.example.net/ipsum.txt' }, status: 400, code: 'invalid_url' },
  { name: 'mirror with http on a public host', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { url: 'http://mirror.example.net/ipsum.txt' }, status: 400, code: 'invalid_url' },
  { name: 'mirror on an internal host', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { url: 'http://10.0.0.5/ipsum.txt' }, status: 200, schema: Feed, check: (b) => expect(b.url).toBe('http://10.0.0.5/ipsum.txt') },
  { name: 'reset the mirror', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { url: '' }, status: 200, schema: Feed, check: (b) => expect(b.url).toBe(b.default_url) },
  { name: 'turn it off again (a box fetches only what its owner left on)', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { enabled: false }, status: 200, schema: Feed },
  { name: 'unknown feed', role: 'admin', method: 'PUT', path: '/feeds/sources/nope', body: { enabled: true }, status: 404, code: 'not_found' },
  { name: 'fetch an unknown feed', role: 'admin', method: 'POST', path: '/feeds/sources/nope/fetch', body: {}, status: 404, code: 'not_found' },
  { name: 'a built-in feed is not deleted', role: 'admin', method: 'DELETE', path: '/feeds/custom/ipsum', status: 404, code: 'not_found' },
  { name: 'a built-in feed is not edited as custom', role: 'admin', method: 'PUT', path: '/feeds/custom/ipsum', body: input(), status: 404, code: 'not_found' },

  // ---- custom feeds
  { name: 'add a custom feed with a bearer secret', role: 'admin', method: 'POST', path: FEED, status: 201, schema: Feed,
    body: input({ auth: { type: 'bearer', header_name: null, username: null, secret: 'abcd1234efgh' } }), keep: (b, c) => { c.id = b.id },
    check: (b) => expect([b.builtin, b.status, b.records, b.auth.type, b.auth.secret_last4, b.parser.format, b.default_url, b.license]).toEqual([false, 'never', null, 'bearer', 'efgh', 'csv', null, null]) },
  { name: 'the secret is never returned', role: 'admin', method: 'GET', path: '/feeds/sources', status: 200, schema: FeedList, check: (b) => expect(JSON.stringify(b)).not.toContain('abcd1234') },
  { name: 'duplicate name, other case', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'PARTNER BLOCKLIST' }), status: 400, code: 'duplicate_name' },
  { name: 'name of a built-in feed', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'cisa kev' }), status: 400, code: 'duplicate_name' },
  { name: 'blank name', role: 'admin', method: 'POST', path: FEED, body: input({ name: '   ' }), status: 400, code: 'invalid_name' },
  { name: 'empty name', role: 'admin', method: 'POST', path: FEED, body: input({ name: '' }), status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'name of 61 characters', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'n'.repeat(61) }), status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'address that is not a URL', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'U1', url: 'not a url' }), status: 400, code: 'invalid_url' },
  { name: 'http to a public host', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'U2', url: 'http://threat-share.example.net/a.csv' }), status: 400, code: 'invalid_url' },
  // D-420 (1): an address the pull would refuse (link-local, cloud metadata, unspecified) is refused at save, with the pull's sentence
  ...(['https://169.254.169.254/latest/meta-data', 'https://[fe80::1]/x', 'https://0.0.0.0/x', 'https://100.100.100.200/x'] as const).map((url, i): Step => ({ name: `blocked address ${url}`, role: 'admin', method: 'POST', path: FEED, body: input({ name: `B${i}`, url }), status: 400, code: 'blocked_host',
    check: (b) => expect(b.error.message).toBe('Vedette does not pull feeds from link-local, multicast, unspecified or cloud metadata addresses.') })),
  // D-446: Vedette itself (loopback, localhost) has the one sentence of every module
  ...(['https://localhost:8443/x', 'http://127.0.0.1/list.txt', 'https://feeds.localhost/x', 'https://[::1]/x', 'https://[::ffff:127.0.0.1]/x'] as const).map((url, i): Step => ({ name: `Vedette itself ${url}`, role: 'admin', method: 'POST', path: FEED, body: input({ name: `O${i}`, url }), status: 400, code: 'blocked_host',
    check: (b) => expect(b.error.message).toBe("That address is Vedette itself: loopback, Vedette's own container, or one of its ports (8443, 8444, 8765, 514, 6514) on the machine that runs it. For another program on that machine, enter the machine's LAN address and that program's port.") })),
  { name: 'mirror at the cloud metadata address', role: 'admin', method: 'PUT', path: '/feeds/sources/ipsum', body: { url: 'https://169.254.169.254/ipsum.txt' }, status: 400, code: 'blocked_host' },
  // D-420 (2): an address another feed already pulls (a built-in one, or the custom feed above), case and default port aside
  { name: 'address of a built-in feed', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'Copy of a built-in', url: 'https://check.torproject.org:443/torbulkexitlist' }), status: 400, code: 'duplicate_url', check: (b) => expect(b.error.message).toBe('The feed "Tor exit list" already uses this address.') },
  { name: 'address of another custom feed', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'Copy', url: 'HTTPS://Threat-Share.example.net/list.csv' }), status: 400, code: 'duplicate_url', check: (b) => expect(b.error.message).toBe('The feed "Partner blocklist" already uses this address.') },
  { name: 'http to an internal host is fine', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'Internal', url: 'http://feeds.lan/a.csv' }), status: 201, schema: Feed, keep: (b, c) => { c.internal = b.id } },
  { name: 'interval 0 on a custom feed', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'I0', interval_hours: 0 }), status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'format that does not fit the kind', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'F1', kind: 'vulnerabilities', parser: defaultParser('ioc', 'lines') }), status: 400, code: 'invalid_format' },
  { name: 'header auth, bad header name', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'header', header_name: 'X Api Key', secret: 'abcd1234' }), status: 400, code: 'invalid_auth' },
  { name: 'header auth, empty header name', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'header', header_name: null, secret: 'abcd1234' }), status: 400, code: 'invalid_auth' },
  { name: 'basic auth without user', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'basic', username: '  ', secret: 'abcd1234' }), status: 400, code: 'invalid_auth' },
  { name: 'bearer without secret', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'bearer' }), status: 400, code: 'invalid_auth' },
  { name: 'secret too short', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'bearer', secret: 'short' }), status: 400, code: 'invalid_auth' },
  { name: 'secret with a space', role: 'admin', method: 'POST', path: FEED, body: withAuth({ type: 'bearer', secret: 'has space 123' }), status: 400, code: 'invalid_auth' },
  { name: 'basic auth', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'Basic one', url: 'https://threat-share.example.net/basic.csv', auth: { type: 'basic', header_name: null, username: ' svc ', secret: 'abcd1234' } }), status: 201, schema: Feed,
    check: (b) => expect([b.auth.username, b.auth.header_name, b.auth.secret_last4]).toEqual(['svc', null, '1234']) },
  { name: 'header auth', role: 'admin', method: 'POST', path: FEED, body: input({ name: 'Header one', url: 'https://threat-share.example.net/header.csv', auth: { type: 'header', header_name: 'X-Api-Key', username: 'ignored', secret: 'abcd9876' } }), status: 201, schema: Feed,
    check: (b) => expect([b.auth.username, b.auth.header_name, b.auth.secret_last4]).toEqual([null, 'X-Api-Key', '9876']) },
  { name: 'bad regex in the parsing rules', role: 'admin', method: 'POST', path: FEED, status: 400, code: 'bad_config',
    body: input({ name: 'Bad regex', parser: { ...defaultParser('ioc', 'csv'), fields: { ...defaultParser('ioc', 'csv').fields, indicator: { source: 'dst_ip', regex: '([', trim: true, lowercase: false, date_format: 'auto' } } } }) },
  { name: 'JSONPath without $', role: 'admin', method: 'POST', path: FEED, status: 400, code: 'bad_config',
    body: input({ name: 'Bad path', parser: { ...defaultParser('ioc', 'json'), records_path: 'data[*]' } }) },
  { name: 'edit keeps the saved secret when none is sent', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 200, schema: Feed,
    body: input({ name: 'Partner blocklist renamed', interval_hours: 24, auth: { type: 'bearer', header_name: null, username: null } }),
    check: (b) => expect([b.name, b.interval_hours, b.auth.secret_last4]).toEqual(['Partner blocklist renamed', 24, 'efgh']) },
  { name: 'edit with a new secret', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 200, schema: Feed,
    body: input({ name: 'Partner blocklist renamed', auth: { type: 'bearer', header_name: null, username: null, secret: 'zzzz0000' } }), check: (b) => expect(b.auth.secret_last4).toBe('0000') },
  { name: 'edit: auth none drops the secret', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 200, schema: Feed,
    body: input({ name: 'Partner blocklist renamed' }), check: (b) => expect([b.auth.type, b.auth.secret_last4]).toEqual(['none', null]) },
  { name: 'edit: auth back to bearer needs a secret again', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 400, code: 'invalid_auth',
    body: input({ name: 'Partner blocklist renamed', auth: { type: 'bearer', header_name: null, username: null } }) },
  { name: 'edit: bearer with an empty secret and none saved', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.internal}`, status: 400, code: 'invalid_auth',
    body: input({ name: 'Internal', url: 'http://feeds.lan/a.csv', auth: { type: 'bearer', header_name: null, username: null, secret: '' } }) },
  { name: 'edit: keep own name', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 200, schema: Feed, body: input({ name: 'partner blocklist RENAMED' }) },
  { name: 'edit: name taken by another feed', role: 'admin', method: 'PUT', path: (c) => `${FEED}/${c.id}`, status: 400, code: 'duplicate_name', body: input({ name: 'Internal' }) },
  { name: 'edit an unknown feed', role: 'admin', method: 'PUT', path: `${FEED}/cf-nope`, status: 404, code: 'not_found', body: input() },
  { name: 'turn a custom feed off through sources', role: 'admin', method: 'PUT', path: (c) => `/feeds/sources/${c.id}`, body: { enabled: false }, status: 200, schema: Feed, check: (b) => expect(b.enabled).toBe(false) },
  { name: 'fetch a custom feed that is off', role: 'admin', method: 'POST', path: (c) => `/feeds/sources/${c.id}/fetch`, body: {}, status: 409, code: 'feed_disabled' },
  { name: 'delete a custom feed', role: 'admin', method: 'DELETE', path: (c) => `${FEED}/${c.id}`, status: 204 },
  { name: 'delete it again', role: 'admin', method: 'DELETE', path: (c) => `${FEED}/${c.id}`, status: 404, code: 'not_found' },
  { name: 'the list no longer has it', role: 'admin', method: 'GET', path: '/feeds/sources', status: 200, schema: FeedList,
    check: (b, c) => expect(b.items.some((f: { id: string }) => f.id === c.id)).toBe(false) },

  // ---- parse-test
  ...(['json', 'csv', 'rss', 'stix', 'lines'] as const).map((f): Step => ({ name: `parse-test ioc ${f}`, role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', f), status: 200, schema: ParseResult,
    check: (b, _c, t) => { if (f !== 'stix' || t === 'real') expect(b.accepted).toBeGreaterThan(0); expect(b.records.length).toBeLessThanOrEqual(20) } })),
  ...(['json', 'csv', 'rss'] as const).map((f): Step => ({ name: `parse-test vulnerabilities ${f}`, role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('vulnerabilities', f), status: 200, schema: ParseResult,
    check: (b) => expect(b.columns).toEqual(['cve', 'vendor', 'product', 'date', 'description', 'link']) })),
  { name: 'parse-test ioc columns', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines'), status: 200, schema: ParseResult, check: (b) => expect(b.columns).toEqual(['indicator', 'kind', 'confidence', 'first_seen']) },
  { name: 'parse-test own sample', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines', { sample: '185.220.101.47\nnot an ip\n8.8.4.4\n' }), status: 200, schema: ParseResult,
    check: (b) => expect([b.sample_label, b.rejected >= 1, b.rejects.length >= 1, b.rejects[0].row]).toEqual(['Your sample', true, true, 2]) },
  { name: 'parse-test empty sample', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines', { sample: '' }), status: 200, schema: ParseResult, check: (b) => expect([b.accepted, b.rejected, b.records]).toEqual([0, 0, []]) },
  { name: 'parse-test wrong format for the kind', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('vulnerabilities', 'lines'), status: 400, code: 'invalid_format' },
  { name: 'parse-test bad regex', role: 'admin', method: 'POST', path: '/feeds/parse-test', status: 400, code: 'bad_config',
    body: { kind: 'ioc', parser: { ...defaultParser('ioc', 'csv'), fields: { ...defaultParser('ioc', 'csv').fields, indicator: { source: 'dst_ip', regex: '([', trim: true, lowercase: false, date_format: 'auto' } } } } },
  { name: 'parse-test sample over 5 MB', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines', { sample: `${'1.2.3.4\n'.repeat(700_000)}` }), status: 400, code: 'invalid_body', real: { code: 'invalid' } },
  { name: 'parse-test 3 MB sample is read (up to 50,000 rows)', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: parseTest('ioc', 'lines', { sample: '1.2.3.4\n'.repeat(400_000) }), status: 200, schema: ParseResult, check: (b) => expect(b.truncated).toBe(true) },
  { name: 'parse-test missing parser', role: 'admin', method: 'POST', path: '/feeds/parse-test', body: { kind: 'ioc' }, status: 400, code: 'invalid_body', real: { code: 'invalid' } },
]

// A real box keeps what an earlier (or failed) run left: remove the custom feeds this script creates before starting, and again at the end.
const MINE = new Set(['Partner blocklist', 'Partner blocklist renamed', 'partner blocklist RENAMED', 'Internal', 'Basic one', 'Header one', 'Auth probe'])
async function sweep(target: 'mock' | 'real') {
  const list = await call(target, { name: 'list', role: 'admin', method: 'GET', path: '/feeds/sources', status: 200 }, {})
  for (const f of ((list.body as { items?: { id: string; name: string; builtin: boolean }[] })?.items ?? [])) {
    if (!f.builtin && MINE.has(f.name)) await call(target, { name: 'sweep', role: 'admin', method: 'DELETE', path: `/feeds/custom/${f.id}`, status: 204 }, {})
  }
}

async function run(target: 'mock' | 'real') {
  await sweep(target)
  const c: Ctx = {}
  const problems: string[] = []
  for (const s of steps) {
    if (target === 'real' && s.mockOnly) continue
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
  await sweep(target)
  return problems
}

describe('feeds API conformance (contract.ts + mock = approved behaviour)', () => {
  it('the mock follows its own script', async () => { expect(await run('mock')).toEqual([]) })
  it.skipIf(!REAL)('the real backend follows the same script', async () => {
    server.use(http.all(`${REAL}/*`, () => passthrough())) // the MSW pattern `*/api/v1` would answer for any origin
    expect(await run('real')).toEqual([])
  }, 120_000)
})
