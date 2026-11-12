// A box with no vedette-host (D-55, core INV-20): a container-only install. The API answers its host endpoints with 409 not_appliance, never a
// 5xx; the pages know the install kind from GET /modules (D-381), show what the customer does instead (compose commands, the volume backup)
// and never call those endpoints; the honeypot cannot be turned on. This is a second box of the same run (ready.json:
// bare_url, bare_setup_code), started with `-host-socket ""` by cmd/vedette/e2ehost_test.go. It is set up through the API here, with the
// setup code it printed, as the only account on it.
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { ACCOUNTS, api, box, login, password } from './box'
import { h1, noErrors, noVietnamese, stubSoftwareUpdates } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000, storageState: { cookies: [], origins: [] } })
test.describe.configure({ mode: 'serial' })

const bare = () => box().bare_url!
const SAYS = {
  os: /This install has no operating system helper \(container-only install\), so Vedette cannot update or back up the operating system from here\./,
  network: /This install has no operating system helper \(container-only install\), so Vedette cannot change the box's network from here\./,
}

let admin: APIRequestContext
let signedIn: Awaited<ReturnType<APIRequestContext['storageState']>>

test.beforeAll(async () => {
  expect(bare(), 'the bare box is in ready.json (VEDETTE_E2E_HOST=1)').toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
  admin = await request.newContext({ baseURL: bare() })
  const r = await api<{ error?: { code: string } }>(admin, 'POST', '/core/setup', {
    org: 'Bare Company', admin: { name: ACCOUNTS.admin.name, email: ACCOUNTS.admin.email, password: password() },
    lan: ['192.168.18.0/24'], commitment: false, bundle: 'smb', setup_code: box().bare_setup_code,
  })
  if (r.status >= 300) { // a HOLD=1 rerun: the box was set up by the run before, so sign in as the administrator it made
    expect(r.body.error?.code, JSON.stringify(r.body)).toBe('already_setup')
    const signed = await login(admin, ACCOUNTS.admin.email, password())
    expect(signed.status, JSON.stringify(signed.body)).toBe(200)
  }
  signedIn = await admin.storageState()
})
test.afterAll(async () => { await admin.dispose() })

/** Cookies are per host, not per port: the bare box and the main box share 127.0.0.1, so these tests start from an empty context
 *  (test.use above) and carry only the session the bare box gave the administrator. */
async function openBare(page: Page, path: string) {
  await page.context().addCookies(signedIn.cookies)
  await stubSoftwareUpdates(page) // the software part of Updates is unbuilt (501) and hides the operating system part: see ui.ts
  await page.goto(`${bare()}${path}`)
}

test('the three endpoints answer 409 not_appliance with a sentence, never 5xx', async () => {
  for (const [method, path, says] of [
    ['GET', '/core/updates/os', SAYS.os], ['GET', '/core/updates/os/run', SAYS.os], ['POST', '/core/updates/os/check', SAYS.os],
    ['POST', '/core/updates/os/install', SAYS.os], ['GET', '/core/network', SAYS.network], ['GET', '/core/network/span/status', SAYS.network],
    ['GET', '/core/data/backup', SAYS.os],
  ] as const) {
    const body = method === 'POST' && path.endsWith('install') ? { scope: 'all' } : undefined
    const r = await api<{ error: { code: string; message: string } }>(admin, method, path, body)
    expect(r.status, `${method} ${path}: ${JSON.stringify(r.body)}`).toBe(409)
    expect(r.body.error.code, `${method} ${path}`).toBe('not_appliance')
    expect(r.body.error.message, `${method} ${path}`).toMatch(says)
  }
})

/** The host endpoints of D-381: a page of a container-only install never calls them. */
const HOST = ['/api/v1/core/updates/os', '/api/v1/core/network', '/api/v1/core/data/backup', '/api/v1/core/data/backups', '/api/v1/core/data/restore/run']
const hostCalls = (page: Page) => {
  const calls: string[] = []
  page.on('request', (r) => { const u = new URL(r.url()); if (r.url().startsWith(bare()) && HOST.some((h) => u.pathname === h || u.pathname.startsWith(`${h}/`))) calls.push(`${r.method()} ${u.pathname}`) })
  return calls
}

test('GET /modules says container and the honeypot is not available; turning it on is 409 not_appliance', async () => {
  const mods = await api<{ install: string; modules: { id: string; enabled: boolean; available: boolean }[] }>(admin, 'GET', '/modules')
  expect(mods.status).toBe(200)
  expect(mods.body.install).toBe('container')
  const hp = mods.body.modules.find((m) => m.id === 'honeypot')
  expect(hp, 'the smb bundle leaves the honeypot out here').toMatchObject({ enabled: false, available: false })
  const on = await api<{ error: { code: string } }>(admin, 'PATCH', '/modules/honeypot', { enabled: true })
  expect(on.status, JSON.stringify(on.body)).toBe(409)
  expect(on.body.error.code).toBe('not_appliance')
})

for (const [route, block, label] of [
  ['/settings/updates', /docker compose --env-file vedette\.env pull/, 'Updates'],
  ['/settings/network', /Prepare the SPAN card on this machine yourself/, 'Box network'],
  ['/settings/data', /tar czf \/backup\/vedette-data\.tgz/, 'Data'],
] as const) {
  test(`${route} shows what to do on a container-only install, calls no host endpoint, and nothing breaks`, async ({ page }) => {
    const errors = collectErrors(page)
    const server: string[] = []
    page.on('response', (r) => { if (r.url().startsWith(bare()) && r.status() >= 500) server.push(`${r.request().method()} ${new URL(r.url()).pathname} -> ${r.status()}`) })
    const calls = hostCalls(page)
    await openBare(page, route)
    await expect(h1(page), `${label} has a heading`).toBeVisible()
    await expect(page.getByText(block).first(), `${label}: the container-only text`).toBeVisible()
    await page.waitForLoadState('networkidle')
    await shot(page, 'real', `bare-${route.split('/').pop()}`)
    await noVietnamese(page, route)
    expect(calls, `${label} called a host endpoint`).toEqual([])
    expect(server, 'the API answered 5xx').toEqual([])
    noErrors(errors)
  })
}

test('Settings -> Data has no Download backup and no box backups; Updates has no appliance controls', async ({ page }) => {
  await openBare(page, '/settings/data')
  await expect(page.getByText(/vedette_data/).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Download backup', exact: true })).toHaveCount(0)
  await expect(page.getByText('Backups on this box')).toHaveCount(0)
  await openBare(page, '/settings/updates')
  await expect(page.getByText('Update Vedette').first()).toBeVisible()
  await expect(page.getByRole('button', { name: /Check for releases/ })).toHaveCount(0)
})
