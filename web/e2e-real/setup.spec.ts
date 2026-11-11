// First-run setup on the real backend (D-75 setup code, core INV-15, S-INV-5). The wizard steps are those of e2e/qa/core.spec.ts
// ("first-run setup"), with the code the box printed in its log (ready.json) instead of the mock's. Runs first and alone: it sets the box up.
import { expect, test } from '@playwright/test'
import { ACCOUNTS, api, box, login, password } from './box'
import { expectAccessible, h1, next, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

const body = (code: string, extra: Record<string, unknown> = {}) => ({
  org: 'E2E Company', admin: { name: ACCOUNTS.admin.name, email: ACCOUNTS.admin.email, password: password() },
  lan: ['192.168.18.0/24'], commitment: false, bundle: 'smb', setup_code: code, ...extra,
})

test('the box starts with setup open and a wrong setup code is refused', async ({ request }) => {
  const before = await api<{ complete: boolean; data_mode: string }>(request, 'GET', '/setup')
  expect(before.status).toBe(200)
  expect(before.body).toMatchObject({ complete: false, data_mode: 'clean' })
  const wrong = await api<{ error: { code: string } }>(request, 'POST', '/core/setup', body('not-the-setup-code'))
  expect(wrong.status).toBeGreaterThanOrEqual(400)
  expect(wrong.status).toBeLessThan(500)
  expect(wrong.body.error.code).toBe('invalid_setup_code')
  expect((await api<{ complete: boolean }>(request, 'GET', '/setup')).body.complete).toBe(false)
  expect((await api(request, 'GET', '/core/users')).status).toBe(401) // nothing was created: still nobody is signed in
})

test('"Use sample data" is refused cleanly by the real box and creates nothing (INV-15)', async ({ page, request }) => {
  const errors = collectErrors(page)
  // the API, with no setup code at all: the build has no sample data, and that refusal comes before the code is judged
  const r = await api<{ error: { code: string } }>(request, 'POST', '/core/setup', { sample: true })
  expect(r.status).toBe(400)
  expect(r.body.error.code).toBe('sample_unavailable')
  // the release GUI still offers the button (deferred: feat-core-auth-api.md); pressing it shows the refusal and stays on the form
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page.getByText(/no sample data/i).first()).toBeVisible()
  await expect(page).toHaveURL(/\/setup/)
  expect((await api<{ complete: boolean }>(request, 'GET', '/setup')).body.complete).toBe(false)
  expect((await api(request, 'GET', '/core/users')).status).toBe(401) // still nobody
  noErrors(errors, /status of 400/)
})

test('first-run setup: mistakes at every step, fixes, finish on Home', async ({ page }) => {
  test.setTimeout(240_000)
  const errors = collectErrors(page)
  await page.goto('/setup')
  await expect(page.getByRole('heading', { level: 1, name: 'First-time Vedette setup' })).toBeVisible()
  await shot(page, 'real', 'setup-1')
  await expectAccessible(page, 'setup step 1')
  await noVietnamese(page, 'setup 1')

  // step 1: empty, weak password, mismatch, bad email
  await next(page)
  await expect(page.getByText('Enter the organization name (at least 2 characters).')).toBeVisible()
  await page.getByLabel('Setup code').fill(box().setup_code)
  await page.getByLabel('Organization name').fill('QA Company')
  await page.getByLabel('Administrator name').fill(ACCOUNTS.admin.name)
  await page.getByLabel('Sign-in email').fill('not-an-email')
  await page.getByLabel('Password', { exact: true }).fill('short')
  await next(page)
  await expect(page.getByText(/The email does not look right/)).toBeVisible()
  await expect(page.getByText(/The password needs at least 12 characters, it has 5 so far/)).toBeVisible()
  await page.getByLabel('Sign-in email').fill(ACCOUNTS.admin.email)
  await page.getByLabel('Password', { exact: true }).fill(password())
  await page.getByLabel('Repeat password').fill(password() + 'x')
  await next(page)
  await expect(page.getByText('The two entries do not match.')).toBeVisible()
  await expect(page.getByLabel('Organization name')).toHaveValue('QA Company') // typed data is kept
  await page.getByLabel('Repeat password').fill(password())
  await page.getByLabel('Repeat password').press('Enter') // Enter submits the step
  await expect(page.getByRole('heading', { level: 2, name: 'Network to watch' })).toBeVisible()

  // step 2: empty, public range, /0, malformed, bare address, host bits, duplicates, add/remove rows
  await next(page)
  await expect(page.getByText('Enter at least one range.')).toBeVisible()
  await page.getByLabel('Range 1', { exact: true }).fill('8.8.8.0/24')
  await next(page)
  await expect(page.getByText(/8\.8\.8\.0\/24 is not a private range/)).toBeVisible()
  await page.getByLabel('Range 1', { exact: true }).fill('10.0.0.0/0')
  await next(page)
  await expect(page.getByText(/is not a private range/)).toBeVisible()
  await page.getByLabel('Range 1', { exact: true }).fill('abc')
  await next(page)
  await expect(page.getByText(/"abc" is not a valid range/)).toBeVisible()
  await page.getByLabel('Range 1', { exact: true }).fill('192.168.18.0') // a bare address
  await next(page)
  await expect(page.getByText(/"192\.168\.18\.0" has no prefix length/)).toBeVisible()
  await page.getByLabel('Range 1', { exact: true }).fill('192.168.18.0/25')
  await page.getByRole('button', { name: 'Add range' }).click()
  await page.getByLabel('Range 2', { exact: true }).fill('10.1.5.9/16')
  await page.getByLabel('Range 2', { exact: true }).blur()
  await expect(page.getByLabel('Range 2', { exact: true })).toHaveValue('10.1.0.0/16')
  await expect(page.getByText(/was changed to 10\.1\.0\.0\/16/)).toBeVisible()
  await page.getByRole('button', { name: 'Add range' }).click()
  await page.getByLabel('Range 3', { exact: true }).fill('10.1.0.0/16')
  await next(page)
  await expect(page.getByText(/10\.1\.0\.0\/16 is listed twice/)).toBeVisible()
  await page.getByRole('button', { name: 'Remove range 3' }).click()
  await expect(page.getByLabel('Range 3', { exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: 'Add range' }).click()
  await next(page)
  await expect(page.getByText('Fill in this range or remove the row.')).toBeVisible()
  await page.getByRole('button', { name: 'Remove range 3' }).click()
  await expect(page.getByLabel(/Upload/)).toHaveCount(0)
  await expect(page.locator('input[type=file]')).toHaveCount(0)
  await expect(page.getByText('Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.')).toBeVisible()
  await page.getByRole('checkbox', { name: 'I confirm these ranges belong to my company and I am allowed to scan them.' }).check()
  await shot(page, 'real', 'setup-2')
  await next(page)

  // step 3 -> back keeps data -> next
  await expect(page.getByRole('heading', { level: 2, name: 'Choose a module bundle' })).toBeVisible()
  await page.getByRole('button', { name: 'Back' }).click()
  await expect(page.getByLabel('Range 1', { exact: true })).toHaveValue('192.168.18.0/25')
  await expect(page.getByLabel('Range 2', { exact: true })).toHaveValue('10.1.0.0/16')
  await next(page)
  await page.getByRole('radio', { name: /Mid-size business/ }).click()
  await shot(page, 'real', 'setup-3')
  await next(page)

  // step 4: incomplete -> errors; skip
  await expect(page.getByRole('heading', { level: 2, name: 'Where alerts go' })).toBeVisible()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page.getByText('Fill this in.').first()).toBeVisible()
  await shot(page, 'real', 'setup-4')
  await page.getByRole('button', { name: 'Skip and finish' }).click()
  await expect(h1(page)).toBeVisible()
  await expect(page).toHaveURL(/\/$/) // finishing lands on Home, signed in as the new administrator
  await expect(h1(page)).toContainText('Today')

  // the scope reached the inventory module (the real one)
  const inv = await api<{ lan_ranges: string[]; active: { enabled: boolean } }>(page.request, 'GET', '/inventory/settings')
  expect(inv.status).toBe(200)
  expect(inv.body.lan_ranges).toEqual(['192.168.18.0/25', '10.1.0.0/16'])
  expect(inv.body.active.enabled).toBe(true)
  noErrors(errors, /status of 4\d\d/)
})

test('the setup code is dead once setup is done', async ({ request }) => {
  const done = await api<{ complete: boolean; org: string }>(request, 'GET', '/setup')
  expect(done.body).toMatchObject({ complete: true, org: 'QA Company' })
  for (const extra of [{}, { sample: true }]) {
    const r = await api<{ error: { code: string } }>(request, 'POST', '/core/setup', body(box().setup_code, extra))
    expect(r.status).toBe(409)
    expect(r.body.error.code).toBe('already_setup')
  }
  // and the refused attempts left the administrator as it was: the password of the wizard still signs in
  expect((await login(request, ACCOUNTS.admin.email, password())).status).toBe(200)
})

test('the box is device 1 and the only device (S-INV-5, count only)', async ({ page }) => {
  const errors = collectErrors(page)
  expect((await login(page.request, ACCOUNTS.admin.email, password())).status).toBe(200)
  // the box registers itself when the inventory module starts: wait for the job, bounded
  await expect.poll(async () => (await api<{ counts: { all: number } }>(page.request, 'GET', '/inventory/devices')).body.counts?.all, { timeout: 45_000 }).toBe(1)
  const list = await api<{ items: { is_box: boolean }[] }>(page.request, 'GET', '/inventory/devices')
  expect(list.body.items).toHaveLength(1)
  expect(list.body.items[0]!.is_box).toBe(true)
  await page.goto('/devices')
  await expect(h1(page)).toContainText(/^1 device, /)
  await expect(page.getByText('This box').first()).toBeVisible()
  noErrors(errors, /status of 4\d\d/)
})
