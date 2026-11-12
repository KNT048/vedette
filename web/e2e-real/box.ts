// Shared by the specs that run on the real backend (WP-30, D-170): the box manifest, API calls with the CSRF header, sign-in that waits
// out the box's one-password-at-a-time gate, the storageState files of the seeded roles, unique names.
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { expect, type APIRequestContext } from '@playwright/test'

export interface Box {
  base_url: string; setup_code: string; data_dir: string; honeypot_dir: string
  /** The control server of the box (slice 3): the SMTP sink's port and the bearer token for /smtp and /expire-codes. */
  control: string; control_token: string; smtp_port: string
  /** The fake vedette-host's knobs and the second box with no host (slice 4, D-163). */
  host_control?: string; host_token?: string; bare_url?: string; bare_setup_code?: string
  /** The loopback devices a connection can be saved against (slice 5): the target, the user name and the secret to type, by kind. */
  devices?: Record<'http' | 'ssh' | 'mcp', { target: string; username?: string; secret?: string }>
  /** The port of the syslog listener of the logs module (UDP and TCP on loopback): a source declared with sender 127.0.0.1 receives what a spec sends there. */
  syslog_port?: string
  /** Syslog over TLS (D-214, D-427): the port of the TLS listener (the syslog port + 1) and the PEM of the test certificate it presents. */
  syslog_tls_port?: string; syslog_tls_cert?: string
  /** The pages the fake internet of the CVE news fetch serves, as host/path (D-426); the CVE they are about is CVE-2026-0001, the one catalog entry of the run. */
  news_pages?: string[]
}

/** The sensors of the run (slice 7): the REAL vedette-sensor binary, started as a child of the box through its control endpoint. `passive` replays a
 *  recording of modules/sensor-passive/testdata (no card needed); `active` runs with a fake nmap that scans nothing and answers from the fixtures of
 *  modules/sensor-active/testdata by the shape of the argv it gets. `stop` ends one; `argv` is every nmap run the fake saw, oldest first. */
export async function sensorCtl(call: { start: 'passive'; replay: 'lan-discovery' | 'span-metadata' | 'span-own-only' | 'malformed-pcap' } | { start: 'active' } | { stop: 'passive' | 'active' }): Promise<void> {
  const b = box()
  const h = { Authorization: `Bearer ${b.control_token}`, 'Content-Type': 'application/json' }
  const r = 'stop' in call
    ? await fetch(`${b.control}/sensors/${call.stop}`, { method: 'DELETE', headers: h })
    : await fetch(`${b.control}/sensors/${call.start}`, { method: 'POST', headers: h, body: JSON.stringify(call.start === 'passive' ? { replay: call.replay } : {}) })
  if (!r.ok) throw new Error(`sensor ${JSON.stringify(call)}: ${r.status} ${await r.text()}`)
}
export async function nmapRuns(): Promise<string[]> {
  const b = box()
  const r = await fetch(`${b.control}/sensors/active/argv`, { headers: { Authorization: `Bearer ${b.control_token}` } })
  if (!r.ok) throw new Error(`nmap runs: ${r.status}`)
  return ((await r.json()) as { lines: string[] }).lines
}

/** The scan worker (D-427): the REAL worker of sensor-active, in the box process, in the slot of the active sensor (stop it with
 *  `sensorCtl({ stop: 'active' })`), running a FAKE nuclei that sends nothing. `match`: the first target of each template matches; `nomatch`: no
 *  line matches; `hang`: never answers; `dead`: every line is an error (the device stopped responding). The mode applies from the next run. */
export async function scanWorker(nuclei: 'match' | 'nomatch' | 'hang' | 'dead'): Promise<void> {
  const b = box()
  const r = await fetch(`${b.control}/sensors/scan`, { method: 'POST', headers: { Authorization: `Bearer ${b.control_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ nuclei }) })
  if (!r.ok) throw new Error(`scan worker ${nuclei}: ${r.status} ${await r.text()}`)
}
/** Every nuclei run the fake saw, as its argv, oldest first. */
export async function nucleiRuns(): Promise<string[]> {
  const b = box()
  const r = await fetch(`${b.control}/sensors/scan/argv`, { headers: { Authorization: `Bearer ${b.control_token}` } })
  if (!r.ok) throw new Error(`nuclei runs: ${r.status}`)
  return ((await r.json()) as { lines: string[] }).lines
}

/** Turns a knob of the fake vedette-host: `lock` (dpkg lock held), `install_fail` (apt-get install exits 100), `reboot_required` (on/off),
 *  `updates` (`reset`: the packages are pending again), `boot` (a new boot id: a reboot is over), `hp_start` (`fail`: starting the honeypot
 *  container fails; `ok`: it works, slice 8b). */
export async function hostKnob(knob: 'lock' | 'install_fail' | 'reboot_required' | 'updates' | 'boot' | 'hp_start', value: string): Promise<void> {
  const b = box()
  const r = await fetch(`${b.host_control}/host?${knob}=${value}`, { method: 'POST', headers: { Authorization: `Bearer ${b.host_token}` } })
  if (!r.ok) throw new Error(`host knob ${knob}=${value}: ${r.status}`)
}

/** What the fake vedette-host itself says about the honeypot (slice 8b): the state of its unit (`active`, `inactive`, ...), the decoy
 *  addresses it holds with their MAC (GET /v1/state/net), and how many times the container was asked to start (failed ones too). */
export async function hostHoneypot(): Promise<{ unit_state: string; decoys: { ip: string; mac: string }[]; restarts: number }> {
  const b = box()
  const r = await fetch(`${b.host_control}/honeypot`, { headers: { Authorization: `Bearer ${b.host_token}` } })
  if (!r.ok) throw new Error(`host honeypot state: ${r.status}`)
  return (await r.json()) as { unit_state: string; decoys: { ip: string; mac: string }[]; restarts: number }
}

let cached: Box | undefined
/** What TestE2EBox wrote to ready.json: the base URL, the one-time setup code, the data and honeypot folders. */
export function box(): Box {
  const path = process.env.E2E_BOX
  if (!path) throw new Error('E2E_BOX is not set: run `make e2e-real`')
  return (cached ??= JSON.parse(readFileSync(path, 'utf8')) as Box)
}

/** The password of every account of this run: random per run, in the environment only. */
export function password(): string {
  const p = process.env.E2E_PASSWORD
  if (!p) throw new Error('E2E_PASSWORD is not set: run `make e2e-real`')
  return p
}

export type Role = 'admin' | 'operator' | 'viewer'
export const ACCOUNTS: Record<Role, { name: string; email: string }> = {
  admin: { name: 'E2E Admin', email: 'admin@e2e.test' },
  operator: { name: 'E2E Operator', email: 'op@e2e.test' },
  viewer: { name: 'E2E Viewer', email: 'view@e2e.test' },
}
/** The storageState file of a seeded role (written by seed.setup.ts). It lives next to ready.json, in the 0700 temp folder of the run: Playwright
 *  empties its outputDir at the start of every run (that would break a HOLD rerun), and the cookies must not sit in the repository. */
export const authFile = (role: Role) => join(dirname(process.env.E2E_BOX ?? ''), 'auth', `${role}.json`)

let counter = 0
/** A name no other test uses on this box: entities in the parallel project never share one (D-172). */
export function uniq(prefix: string): string {
  return `${prefix}-${process.pid.toString(36)}${Date.now().toString(36)}${(counter++).toString(36)}`
}

export interface Reply<T = unknown> { status: number; body: T }

/** A call to /api/v1 as whoever the context is signed in as; state-changing calls carry the CSRF header from the cookie. */
export async function api<T = any>(request: APIRequestContext, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', path: string, body?: unknown): Promise<Reply<T>> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') {
    const csrf = (await request.storageState()).cookies.find((c) => c.name === '__Host-vedette_csrf')?.value
    if (csrf) headers['X-CSRF-Token'] = csrf
  }
  const r = await request.fetch(`/api/v1${path}`, { method, headers, data: body, failOnStatusCode: false, timeout: 45_000 }) // the box checks one password at a time (argon2): a busy machine queues sign-ins
  const text = await r.text()
  return { status: r.status(), body: (text ? safeJson(text) : null) as T }
}
const safeJson = (t: string) => { try { return JSON.parse(t) } catch { return t } }

/** POST /auth/login; the box checks one password at a time and answers 503 while it is busy, so retry on 503. */
export async function login(request: APIRequestContext, email: string, pw: string): Promise<Reply> {
  for (let i = 0; i < 40; i++) {
    const r = await api(request, 'POST', '/auth/login', { email, password: pw })
    if (r.status !== 503) return r
    await new Promise((ok) => setTimeout(ok, 500))
  }
  throw new Error(`sign-in of ${email}: the box stayed busy`)
}

/** Creates an account as an administrator and takes it through the temporary password and the forced change, as a person does. */
export async function createUser(admin: APIRequestContext, request: APIRequestContext, who: { name: string; email: string; role: Role }, pw = password()): Promise<void> {
  const made = await api<{ temp_password: string }>(admin, 'POST', '/core/users', who)
  expect(made.status, `create ${who.email}: ${JSON.stringify(made.body)}`).toBe(201)
  const first = await login(request, who.email, made.body.temp_password)
  expect(first.status, `first sign-in of ${who.email}`).toBe(200)
  const changed = await api(request, 'POST', '/core/account/password', { current: made.body.temp_password, next: pw })
  expect(changed.status, `password change of ${who.email}: ${JSON.stringify(changed.body)}`).toBe(200)
}

// ---- the fakes that live in the box process (WP-30 slice 3): the SMTP sink behind the control server of cmd/vedette/e2ebox_test.go ----

async function control(method: 'GET' | 'POST', path: string, body?: unknown): Promise<Response> {
  const b = box()
  return fetch(`${b.control}${path}`, { method, headers: { Authorization: `Bearer ${b.control_token}`, 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(10_000) })
}

/** Every message the sink received, oldest first, as raw text. */
export async function mailbox(): Promise<string[]> {
  const r = await control('GET', '/smtp')
  expect(r.status, 'GET /smtp on the control server').toBe(200)
  return ((await r.json()) as { messages: string[] }).messages
}

/** The 6-digit sign-in codes mailed to one address so far, oldest first. */
export async function codesFor(email: string): Promise<string[]> {
  return (await mailbox()).filter((m) => m.toLowerCase().includes(email.toLowerCase())).flatMap((m) => /sign-in code is (\d{6})/.exec(m)?.[1] ?? [])
}

/** The code mailed to `email` after `seen` codes had already been read: polls until a new one arrives (the box mails it in the same request, so this is short). */
export async function nextCode(email: string, seen: number): Promise<string> {
  let codes: string[] = []
  await expect.poll(async () => (codes = await codesFor(email)).length, { message: `a new code mailed to ${email}`, timeout: 15_000 }).toBeGreaterThan(seen)
  return codes[codes.length - 1]!
}

/** Makes the pending email code of that user expire now (the box has no fake clock; the real lifetime is 10 minutes). */
export async function expirePendingCode(email: string): Promise<void> {
  const r = await control('POST', '/expire-codes', { email })
  expect(r.status, `expire the pending code of ${email}: ${await r.text()}`).toBe(204)
}

/** Saves the email channel through notify's real API, pointed at the sink: a precondition of the email-code specs, not what they test. Idempotent. */
export async function ensureEmailChannel(admin: APIRequestContext): Promise<void> {
  const mod = await api<{ modules: { id: string; enabled: boolean }[] }>(admin, 'GET', '/modules')
  if (!mod.body.modules?.find((m) => m.id === 'notify')?.enabled) {
    const on = await api(admin, 'PATCH', '/modules/notify', { enabled: true, with_dependencies: true })
    expect(on.status, `enable notify: ${JSON.stringify(on.body)}`).toBe(200)
  }
  const saved = await api(admin, 'PUT', '/notify/channels/email', {
    enabled: true, min_severity: 'high', secret: 'relay-secret-for-e2e',
    fields: { host: '127.0.0.1', port: box().smtp_port, security: 'none', username: 'alerts@e2e.test', from: 'alerts@e2e.test', to: 'it@e2e.test' },
  })
  expect(saved.status, `save the email channel: ${JSON.stringify(saved.body)}`).toBe(200)
}

// ---- the devices of the box (WP-30 slice 5): an HTTPS, an SSH and an MCP server in the box process, reachable only under their own names ----

export type DeviceKind = 'http' | 'ssh' | 'mcp'
export const device = (kind: DeviceKind) => {
  const d = box().devices?.[kind]
  if (!d) throw new Error(`ready.json has no ${kind} device: run \`make e2e-real\``)
  return d
}

/** What the device received so far: HTTP requests, SSH command lines and sign-ins, MCP calls. */
export async function deviceSeen(kind: DeviceKind): Promise<{ requests?: { method: string; path: string; authorization: string }[]; banned?: string[]; lines?: string[]; logins?: number; auth_calls?: number; calls?: { http: string; rpc: string; authorization: string }[] }> {
  const r = await control('GET', `/devices/${kind}/requests`)
  expect(r.status, `GET /devices/${kind}/requests`).toBe(200)
  return r.json()
}

/** The device shows another certificate or host key from now on: the pin saved at the first test no longer matches. */
export async function rotateDevice(kind: DeviceKind): Promise<void> {
  const r = await control('POST', `/devices/${kind}/rotate`)
  expect(r.status, `rotate the ${kind} device`).toBe(204)
}

/** The HTTP device is a small firewall for the response specs (slice 9a): `ban` and `unban` change its list, `GET /api/e2e/bans` reads it back, and
 *  `GET /api/e2e/status` answers `ready` or, after this call, `maintenance` (what a check before an action refuses on). `deviceSeen('http').banned` is its list. */
export async function httpState(value: 'ready' | 'maintenance'): Promise<void> {
  const r = await control('POST', `/devices/http/state?value=${value}`)
  expect(r.status, `set the HTTP device state to ${value}`).toBe(204)
}
