// A box with no vedette-host (D-55, core INV-20): a container-only install. The operating system update, Box network and backup screens
// must say so in plain words (409 not_appliance), never a 5xx and never a script error. This is a second box of the same run (ready.json:
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

for (const [route, says, label] of [
  ['/settings/updates', SAYS.os, 'Updates (operating system)'],
  ['/settings/network', SAYS.network, 'Box network'],
] as const) {
  test(`${route} says "container-only install" in the page, and nothing breaks`, async ({ page }) => {
    const errors = collectErrors(page)
    const server: string[] = []
    page.on('response', (r) => { if (r.url().startsWith(bare()) && r.status() >= 500) server.push(`${r.request().method()} ${new URL(r.url()).pathname} -> ${r.status()}`) })
    await openBare(page, route)
    await expect(h1(page), `${label} has a heading`).toBeVisible()
    await expect(page.getByRole('alert').filter({ hasText: says }).first(), `${label}: the page tells why`).toBeVisible()
    await page.waitForLoadState('networkidle')
    await shot(page, 'real', `bare-${route.split('/').pop()}`)
    await noVietnamese(page, route)
    expect(server, 'the API answered 5xx').toEqual([])
    noErrors(errors, /status of (4|5)\d\d/)
  })
}

test('/settings/data renders, Download backup saves nothing and says nothing false, and no 5xx', async ({ page }) => {
  const errors = collectErrors(page)
  const server: string[] = []
  page.on('response', (r) => { if (r.url().startsWith(bare()) && r.status() >= 500) server.push(`${r.request().method()} ${new URL(r.url()).pathname} -> ${r.status()}`) })
  await openBare(page, '/settings/data')
  await expect(h1(page)).toBeVisible()
  let downloaded = false
  page.on('download', () => { downloaded = true })
  const refused = page.waitForResponse((r) => r.url().endsWith('/api/v1/core/data/backup'))
  await page.getByRole('button', { name: 'Download backup', exact: true }).click()
  expect((await refused).status(), 'the box refuses the backup').toBe(409)
  await expect(page.locator('[data-sonner-toast]').first()).toBeVisible() // a toast says something happened
  await expect(page.locator('[data-sonner-toast]').filter({ hasText: /Downloaded vedette-backup-/ }), 'no "Downloaded" toast for a backup that was refused').toHaveCount(0)
  expect(downloaded, 'a file was saved although the backend refused').toBe(false)
  await shot(page, 'real', 'bare-data')
  expect(server).toEqual([])
  noErrors(errors, /status of (4|5)\d\d/)
})

/** Only the known symptom may satisfy a test.fail: when it is not what the page shows, the expectation is switched off and the test is red. */
const knownSymptom = (known: boolean) => { if (!known) test.fail(false) }

// test.fail (D-171): lib/api.ts download() throws 'HTTP 409' and ignores the box's JSON error body, so the toast does not say why. Issue #237.
test('Download backup tells the person what the box said (the container-only sentence)', async ({ page }) => {
  test.fail(true, 'GUI: the toast says "HTTP 409" (issue #237, .ai/deferred/feat-e2e-real-harness.md)')
  await openBare(page, '/settings/data')
  await page.getByRole('button', { name: 'Download backup', exact: true }).click()
  const toasts = page.locator('[data-sonner-toast]')
  const said = await toasts.filter({ hasText: SAYS.os }).first().waitFor({ timeout: 5_000 }).then(() => true, () => false)
  knownSymptom(!said && (await toasts.filter({ hasText: 'HTTP 409' }).count()) > 0)
  await expect(toasts.filter({ hasText: SAYS.os }).first()).toBeVisible()
})

// test.fail (D-171): a box with no helper is not the person's mistake, yet both screens are titled "Invalid request". Issue #239.
test('a container-only install is not reported as an invalid request', async ({ page }) => {
  test.fail(true, 'GUI: 409 not_appliance is titled "Invalid request" (issue #239, .ai/deferred/feat-e2e-real-harness.md)')
  const titles: string[] = []
  for (const [route, says] of [['/settings/updates', SAYS.os], ['/settings/network', SAYS.network]] as const) {
    await openBare(page, route)
    const alert = page.getByRole('alert').filter({ hasText: says }).first()
    await expect(alert).toBeVisible()
    titles.push(await alert.innerText())
  }
  knownSymptom(titles.every((t) => t.startsWith('Invalid request')))
  for (const t of titles) expect(t).not.toMatch(/^Invalid request/)
})

// test.fail (D-171): the bands of Settings -> Updates are numbered 1, 2, 3; when the operating system part (1) shows only its error, the page
// starts at 2. Issue #241.
test('Settings -> Updates is numbered from 1 when the operating system part is an error', async ({ page }) => {
  test.fail(true, 'GUI: the sections start at "2" when the OS part errors (issue #241, .ai/deferred/feat-e2e-real-harness.md)')
  await openBare(page, '/settings/updates')
  await expect(page.getByRole('alert').filter({ hasText: SAYS.os }).first()).toBeVisible()
  await expect(page.locator('#managed-band')).toBeVisible()
  const nums = await page.locator('main span[aria-hidden="true"]').filter({ hasText: /^\d$/ }).allInnerTexts()
  knownSymptom(nums[0] === '2')
  expect(nums[0]).toBe('1')
})
