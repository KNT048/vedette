// Users and roles on the real backend (S-CORE-3): invite, the temporary password shown once, the first sign-in, role change, disable,
// password reset, and the audit rows with their CSV export. Steps from e2e/qa/core.spec.ts ("users and roles"). Every account here is a
// throwaway made with uniq() (D-172), found in the table through its filter box, so the specs do not depend on how many users the other
// specs left on the box. Last-admin protection needs a box with ONE active administrator: that is box-wide state, so it lives in
// users-lastadmin.global.spec.ts (global project).
import { readFileSync } from 'node:fs'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, createUser, login, password, uniq, type Role } from './box'
import { h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

interface ListedUser { id: string; name: string; email: string; role: Role; disabled?: boolean }

const adminApi = () => request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
const fresh = () => request.newContext({ baseURL: box().base_url })
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()

/** A new account made through the API the way the invite does, and its row id. */
async function account(role: Role) {
  const tag = uniq('usr')
  const who = { name: `Person ${tag}`, email: `${tag}@e2e.test`, role }
  const admin = await adminApi()
  const tmp = await fresh()
  await createUser(admin, tmp, who)
  await tmp.dispose()
  const list = await api<{ items: ListedUser[] }>(admin, 'GET', '/core/users')
  const id = list.body.items.find((u) => u.email === who.email)!.id
  return { ...who, id, admin }
}

/** Opens /settings/users with the table narrowed to one account. */
async function openRow(page: Page, who: { name: string; email: string }) {
  await page.goto('/settings/users')
  await expect(h1(page)).toContainText('active users')
  await page.getByRole('textbox', { name: 'Find a user' }).fill(who.name) // the filter reads the name column
  await expect(page.getByRole('row').filter({ hasText: who.email })).toHaveCount(1)
}

test('invite: field errors, temporary password shown once, duplicate email refused, the new user signs in and changes it', async ({ page, browser }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const tag = uniq('inv')
  const who = { name: `Invitee ${tag}`, email: `${tag}@e2e.test` }
  await page.goto('/settings/users')
  await expect(h1(page)).toContainText('active users')
  await shot(page, 'real', 'users')
  await page.getByRole('button', { name: 'Add user' }).click()
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByText("Enter the user's name.")).toBeVisible()
  await expect(page.getByText(/The email does not look right/)).toBeVisible()
  await page.getByLabel('Display name').fill(who.name)
  await page.getByLabel('Sign-in email').fill(who.email)
  await page.getByLabel('Role', { exact: true }).selectOption('operator')
  await page.getByLabel('Sign-in email').press('Enter')
  const dialog = page.getByRole('dialog', { name: 'Account created' })
  await expect(dialog).toBeVisible()
  const temp = (await dialog.getByLabel('Temporary password').innerText()).trim()
  expect(temp.length, 'a temporary password was made').toBeGreaterThan(10)
  await dialog.getByRole('button', { name: 'I have copied it' }).click()
  await expect(page.getByRole('dialog')).toHaveCount(0)
  // shown once: not on the page any more, not after a reload, and not in the list the API returns
  await expect(page.getByText(temp)).toHaveCount(0)
  await page.reload()
  await expect(page.getByText(temp)).toHaveCount(0)
  const listed = await api<{ items: ListedUser[] }>(page.request, 'GET', '/core/users')
  expect(JSON.stringify(listed.body)).not.toContain(temp)
  await openRow(page, who)
  const row = page.getByRole('row').filter({ hasText: who.email })
  await expect(row).toContainText(who.name)
  await expect(row).toContainText('Never signed in')
  await expect(row.getByRole('combobox', { name: `Role of ${who.name}` })).toHaveValue('operator')

  // the same email in other letters is the same account
  await page.getByRole('button', { name: 'Add user' }).click()
  await page.getByLabel('Display name').fill(`Second ${tag}`)
  await page.getByLabel('Sign-in email').fill(who.email.toUpperCase())
  await page.getByRole('button', { name: 'Create account' }).click()
  await expect(page.getByText('This email already has an account.')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).toHaveCount(0)

  // the first sign-in, in the browser, with the temporary password
  const context = await browser.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] }, locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh' })
  const mine = await context.newPage()
  await mine.goto('/login')
  await mine.getByLabel('Email').fill(who.email)
  await mine.getByLabel('Password').fill(temp)
  await mine.getByLabel('Password').press('Enter')
  // D-180: the temporary password must be replaced first (the forced change has its own test below), then the operator's pages open
  await expect(h1(mine)).toHaveText('Choose a new password', { timeout: 30_000 })
  const next = password()
  await mine.getByLabel('Temporary password').fill(temp)
  await mine.getByLabel('New password', { exact: true }).fill(next)
  await mine.getByLabel('Repeat new password').fill(next)
  await mine.getByRole('button', { name: 'Save and continue' }).click()
  await expect(mine).not.toHaveURL(/change-password|\/login/)
  await expect(h1(mine)).toBeVisible()
  await mine.goto('/settings/users')
  await expect(mine.getByText(/needs a higher role/)).toBeVisible() // an operator
  await context.close()
  const old = await fresh()
  expect((await login(old, who.email, temp)).status, 'the temporary password stops working').toBe(400)
  expect((await login(old, who.email, next)).status).toBe(200)
  await old.dispose()
  await openRow(page, who)
  await expect(page.getByRole('row').filter({ hasText: who.email })).not.toContainText('Never signed in')
  await noVietnamese(page, 'users')
  noErrors(errors, /status of (40\d|409)/)
})

// D-180 (S-CORE-3): a password an administrator set is temporary. The first sign-in lands on "Choose a new password"; until it is replaced every
// other call is 403 password_change_required (only /me, the password change and sign-out answer).
test('the first sign-in with a temporary password must change it before any other page', async ({ browser }) => {
  test.setTimeout(150_000)
  const tag = uniq('c1')
  const who = { name: `Forced ${tag}`, email: `${tag}@e2e.test`, role: 'operator' as const }
  const admin = await adminApi()
  const made = await api<{ temp_password: string }>(admin, 'POST', '/core/users', who)
  expect(made.status).toBe(201)
  const temp = made.body.temp_password
  const context = await browser.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] }, locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh' })
  const page = await context.newPage()
  const errors = collectErrors(page)
  await page.goto('/login?next=%2Faccount')
  await page.getByLabel('Email').fill(who.email)
  await page.getByLabel('Password').fill(temp)
  await page.getByLabel('Password').press('Enter')
  await expect(h1(page)).toHaveText('Choose a new password', { timeout: 30_000 })
  await expect(page).toHaveURL(/\/change-password/)
  await shot(page, 'real', 'change-password')
  await noVietnamese(page, 'change-password')

  // every other page leads back here, and the API refuses everything but the three calls
  for (const path of ['/', '/settings/channels', '/account']) { // the last one is where the person lands after the change
    await page.goto(path)
    await expect(page, path).toHaveURL(/\/change-password/)
    await expect(h1(page)).toHaveText('Choose a new password')
  }
  for (const path of ['/core/account', '/modules', '/core/general', '/inventory/devices']) {
    const r = await api<{ error: { code: string } }>(page.request, 'GET', path)
    expect(r.status, path).toBe(403)
    expect(r.body.error.code, path).toBe('password_change_required')
  }
  expect((await api<{ password_change_required: boolean }>(page.request, 'GET', '/me')).body.password_change_required).toBe(true)

  // field errors: nothing is sent for an empty or short or mismatched form; the temporary password again is refused by the box
  await page.getByRole('button', { name: 'Save and continue' }).click()
  await expect(page.getByText('Enter the temporary password you signed in with.')).toBeVisible()
  await page.getByLabel('Temporary password').fill(temp)
  await page.getByLabel('New password', { exact: true }).fill('short')
  await page.getByRole('button', { name: 'Save and continue' }).click()
  await expect(page.getByText(/at least \d+ characters/).first()).toBeVisible()
  await page.getByLabel('New password', { exact: true }).fill(temp)
  await page.getByLabel('Repeat new password').fill(temp)
  await page.getByRole('button', { name: 'Save and continue' }).click()
  await expect(page.getByText('The new password must differ from the temporary one.')).toBeVisible()
  await page.getByLabel('Temporary password').fill('not-the-temporary-password')
  const next = password()
  await page.getByLabel('New password', { exact: true }).fill(next)
  await page.getByLabel('Repeat new password').fill(next)
  await page.getByRole('button', { name: 'Save and continue' }).click()
  await expect(page).toHaveURL(/\/change-password/) // a wrong temporary password changes nothing
  expect((await api<{ password_change_required: boolean }>(page.request, 'GET', '/me')).body.password_change_required).toBe(true)

  // the right form: lands on the page the person was going to, and everything is open
  await page.getByLabel('Temporary password').fill(temp)
  await page.getByRole('button', { name: 'Save and continue' }).click()
  await expect(page).toHaveURL(/\/account/)
  expect((await api<{ password_change_required: boolean }>(page.request, 'GET', '/me')).body.password_change_required).toBe(false)
  for (const path of ['/core/account', '/modules']) expect((await api(page.request, 'GET', path)).status, path).toBe(200)
  const old = await fresh()
  expect((await login(old, who.email, temp)).status, 'the temporary password stops working').toBe(400)
  expect((await login(old, who.email, next)).status).toBe(200)
  await Promise.all([old.dispose(), context.close(), admin.dispose()])
  noErrors(errors, /status of (40\d|403)/)
})

test('role change and disable in the table, each effect seen by the user, then enable again and reset the password', async ({ page, browser }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  const who = await account('viewer')
  const theirs = await fresh()
  expect((await login(theirs, who.email, password())).status).toBe(200)
  expect((await api<{ role: string }>(theirs, 'GET', '/me')).body.role).toBe('viewer')

  await openRow(page, who)
  await page.getByRole('combobox', { name: `Role of ${who.name}` }).selectOption('operator')
  await toast(page, /Saved/)
  await expect.poll(async () => (await api<{ items: ListedUser[] }>(who.admin, 'GET', '/core/users')).body.items.find((u) => u.id === who.id)?.role).toBe('operator')
  expect((await api<{ role: string }>(theirs, 'GET', '/me')).body.role, 'the role applies to the open session').toBe('operator')

  await page.getByRole('button', { name: `Disable ${who.name}`, exact: true }).click()
  await expect(page.getByRole('row').filter({ hasText: who.email })).toContainText('Disabled')
  await expect(page.getByRole('button', { name: `Enable ${who.name} again` })).toBeVisible()
  // a disabled account cannot sign in: not with the right password, and the session it had is gone
  const refused = await login(await fresh(), who.email, password())
  expect(refused.status).toBe(403)
  expect(refused.body).toMatchObject({ error: { code: 'disabled' } })
  expect((await api(theirs, 'GET', '/me')).status, 'the session of a disabled user ends').toBe(401)
  const context = await browser.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] } })
  const login2 = await context.newPage()
  await login2.goto('/login')
  await login2.getByLabel('Email').fill(who.email)
  await login2.getByLabel('Password').fill(password())
  await login2.getByLabel('Password').press('Enter')
  await expect(login2.getByText('This account has been disabled.')).toBeVisible({ timeout: 30_000 })
  await context.close()

  await page.getByRole('button', { name: `Enable ${who.name} again` }).click()
  await expect(page.getByRole('row').filter({ hasText: who.email })).toContainText('Active')
  const again = await fresh()
  expect((await login(again, who.email, password())).status).toBe(200)

  // reset: Cancel changes nothing, Reset gives a new temporary password and ends the sessions
  await page.getByRole('button', { name: `Reset password of ${who.name}` }).click()
  await page.getByRole('button', { name: 'Cancel' }).click()
  expect((await api(again, 'GET', '/me')).status, 'Cancel leaves the session alone').toBe(200)
  await page.getByRole('button', { name: `Reset password of ${who.name}` }).click()
  await page.getByRole('button', { name: 'Reset', exact: true }).click()
  const done = page.getByRole('dialog', { name: 'Password reset' })
  await expect(done).toBeVisible()
  const temp = (await done.getByLabel('Temporary password').innerText()).trim()
  await done.getByRole('button', { name: 'I have copied it' }).click()
  expect((await api(again, 'GET', '/me')).status, 'a reset ends every session of that user').toBe(401)
  const wrong = await fresh()
  expect((await login(wrong, who.email, password())).status, 'the old password stops working').toBe(400)
  expect((await login(wrong, who.email, temp)).status).toBe(200)
  await Promise.all([theirs.dispose(), again.dispose(), wrong.dispose(), who.admin.dispose()])
  noErrors(errors, /status of (40\d|403)/)
})

test('every change writes an audit row, and the audit CSV export holds them', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const who = await account('viewer')
  expect((await api(who.admin, 'PATCH', `/core/users/${who.id}`, { role: 'operator' })).status).toBe(200)
  expect((await api(who.admin, 'PATCH', `/core/users/${who.id}`, { disabled: true })).status).toBe(200)
  expect((await api(who.admin, 'PATCH', `/core/users/${who.id}`, { disabled: false })).status).toBe(200)
  expect((await api(who.admin, 'POST', `/core/users/${who.id}/reset-password`)).status).toBe(200)
  const actions = ['user.create', 'user.role', 'user.disable', 'user.enable', 'user.password_reset']

  await page.goto('/settings/audit')
  await expect(h1(page)).toContainText('log lines match')
  await page.getByLabel('Search text').fill(who.email)
  await expect(page.getByRole('table', { name: 'Audit log' }).getByRole('row').filter({ hasText: who.email }).first()).toBeVisible()
  const table = page.getByRole('table', { name: 'Audit log' })
  for (const a of actions) {
    const row = table.getByRole('row').filter({ hasText: a }).filter({ hasText: who.email })
    await expect(row, `audit row ${a}`).toHaveCount(1)
    await expect(row).toContainText('admin@e2e.test') // who did it
  }
  await expect(table.getByRole('row').filter({ hasText: 'user.role' })).toContainText('viewer to operator')
  await expect(table.getByRole('row').filter({ hasText: 'user.create' })).toContainText('role viewer')
  await shot(page, 'real', 'audit')

  const download = page.waitForEvent('download')
  await page.getByRole('button', { name: 'Export CSV' }).click()
  const file = (await download).suggestedFilename()
  expect(file).toBe('vedette-audit.csv')
  const csv = readFileSync((await (await download).path())!, 'utf8')
  expect(csv.charCodeAt(0), 'the CSV starts with a UTF-8 byte order mark').toBe(0xfeff)
  const lines = csv.split(/\r?\n/).filter((l) => l.includes(who.email))
  for (const a of actions) expect(lines.filter((l) => l.includes(a)), `${a} in the CSV`).toHaveLength(1)
  expect(csv, 'the temporary password is never in the log').not.toMatch(/temp_password/)
  // the download is itself a row of the log
  const rows = await api<{ items: { action: string; user: string }[] }>(page.request, 'GET', '/core/audit?q=audit.export')
  expect(rows.body.items.some((r) => r.action === 'audit.export' && r.user === 'admin@e2e.test')).toBe(true)
  await noVietnamese(page, 'audit')
  await who.admin.dispose()
  noErrors(errors)
})

test('a viewer or operator cannot reach the user list through the API either', async () => {
  for (const role of ['viewer', 'operator'] as const) {
    const c: APIRequestContext = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    expect((await api(c, 'GET', '/core/users')).status).toBe(403)
    expect((await api(c, 'POST', '/core/users', { name: 'X Y', email: `${uniq('no')}@e2e.test`, role: 'viewer' })).status).toBe(403)
    expect((await api(c, 'GET', '/core/audit')).status).toBe(403)
    await c.dispose()
  }
})
