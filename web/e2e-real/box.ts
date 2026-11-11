// Shared by the specs that run on the real backend (WP-30, D-170): the box manifest, API calls with the CSRF header, sign-in that waits
// out the box's one-password-at-a-time gate, the storageState files of the seeded roles, unique names.
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { expect, type APIRequestContext } from '@playwright/test'

export interface Box { base_url: string; setup_code: string; data_dir: string; honeypot_dir: string }

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
/** The storageState file of a seeded role (written by seed.setup.ts); relative to web/. */
export const authFile = (role: Role) => resolve('test-results/real/.auth', `${role}.json`)

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
