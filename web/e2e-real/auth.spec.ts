// Sign-in, sign-out and role locks on the real backend (S-CORE-3). Steps from e2e/qa/core.spec.ts ("sign-in and two-step", "viewer and
// operator roles"), with the accounts of seed.setup.ts. A test that fails a password or signs out uses a throwaway account in its own
// context (D-172): the sign-in limit is 10 failures per address and email, and a sign-out ends a session the other specs share.
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { ACCOUNTS, api, authFile, box, createUser, login, password, uniq, type Role } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })

/** A new account of the given role, and a context that is signed in as it. */
async function throwaway(role: Role) {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const email = `${uniq('thr')}@e2e.test`
  const tmp = await request.newContext({ baseURL: box().base_url })
  await createUser(admin, tmp, { name: 'Throwaway', email, role })
  await Promise.all([admin.dispose(), tmp.dispose()])
  const signedIn = await request.newContext({ baseURL: box().base_url })
  expect((await login(signedIn, email, password())).status).toBe(200)
  return { email, ctx: signedIn }
}
const asContext = async (browser: import('@playwright/test').Browser, ctx: APIRequestContext) => browser.newContext({ baseURL: box().base_url, storageState: await ctx.storageState(), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh' })

test.describe('sign-in', () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test('a protected page asks to sign in, a wrong password is refused, Enter submits, lands on the next page', async ({ page }) => {
    const errors = collectErrors(page)
    const who = await throwaway('admin')
    await who.ctx.dispose()
    await page.goto('/settings/audit')
    await expect(page).toHaveURL(/\/login\?next=%2Fsettings%2Faudit/)
    await expectAccessible(page, 'login')
    await noVietnamese(page, 'login')
    await shot(page, 'real', 'login')
    await page.getByLabel('Email').fill(who.email)
    await page.getByLabel('Password').fill('wrong-password')
    await page.getByLabel('Password').press('Enter')
    await expect(page.getByText('Wrong email or password.')).toBeVisible({ timeout: 30_000 }) // the box checks one password at a time
    await expect(page.getByLabel('Email')).toHaveValue(who.email)
    await page.getByLabel('Password').fill(password())
    await page.getByLabel('Password').press('Enter')
    await expect(page).toHaveURL(/\/settings\/audit/, { timeout: 30_000 })
    await expect(h1(page)).toBeVisible()
    noErrors(errors, /status of 401/)
  })

  test('an unknown email gets the same refusal as a wrong password', async ({ page }) => {
    await page.goto('/login')
    await page.getByLabel('Email').fill(`${uniq('nobody')}@e2e.test`)
    await page.getByLabel('Password').fill('wrong-password-123')
    await page.getByLabel('Password').press('Enter')
    await expect(page.getByText('Wrong email or password.')).toBeVisible({ timeout: 30_000 }) // the box checks one password at a time
    await expect(page).toHaveURL(/\/login/)
  })

  test('sign out from the account menu ends that session only', async ({ browser }) => {
    const who = await throwaway('operator')
    const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
    const context = await asContext(browser, who.ctx)
    const page = await context.newPage()
    await page.goto('/')
    await expect(h1(page)).toBeVisible()
    await page.getByRole('button', { name: /Account:/ }).click()
    await page.getByRole('menuitem', { name: 'Sign out' }).click()
    await expect(page).toHaveURL(/\/login/)
    expect((await api(page.request, 'GET', '/me')).status).toBe(401)
    await page.goto('/devices')
    await expect(page).toHaveURL(/\/login\?next=%2Fdevices/)
    expect((await api(admin, 'GET', '/me')).status).toBe(200) // the shared administrator session is untouched
    await Promise.all([context.close(), who.ctx.dispose(), admin.dispose()])
  })
})

const SECTIONS = ['general', 'modules', 'users', 'audit', 'updates', 'privacy', 'mcp', 'data'] as const
const adminOnly = ['users', 'audit', 'mcp', 'data']
const label: Record<string, string> = { users: 'Users', audit: 'Audit log', mcp: 'MCP server', data: 'Data' }

for (const role of ['viewer', 'operator'] as const) {
  test.describe(`${role} role`, () => {
    test.use({ storageState: authFile(role) })

    test('each settings section is read-only or says which role it needs', async ({ page }) => {
      test.setTimeout(150_000)
      const errors = collectErrors(page)
      for (const sec of SECTIONS) {
        await page.goto(`/settings/${sec}`)
        await expect(page.getByRole('heading', { level: 1 }).or(page.getByText(/needs a higher role/)).first()).toBeVisible()
        if (adminOnly.includes(sec)) {
          await expect(page.getByText(/needs a higher role/)).toBeVisible()
          await expect(page.locator('nav[aria-label="Settings sections"]').getByRole('link', { name: label[sec]!, exact: true })).toHaveCount(0)
        } else {
          await expect(page.getByRole('note').filter({ hasText: 'needs the Admin role' })).toBeVisible()
          const enabledSwitches = await page.getByRole('switch').evaluateAll((els) => els.filter((e) => !(e as HTMLButtonElement).disabled).length)
          expect(enabledSwitches, `${sec} still has enabled switches`).toBe(0)
        }
        await expectAccessible(page, `${role} ${sec}`)
        await noVietnamese(page, `${role} ${sec}`)
        if (role === 'viewer') await shot(page, 'real', `role-viewer-${sec}`)
      }
      // the server says the same as the page: the user list is the administrator's
      expect((await api(page.request, 'GET', '/core/users')).status).toBe(403)
      noErrors(errors, /status of (40[13]|501)/) // 501: the updates page, see the fixme above
    })

    test('the account page saves a display name', async ({ browser }) => {
      const who = await throwaway(role)
      const context = await asContext(browser, who.ctx)
      const page = await context.newPage()
      const errors = collectErrors(page)
      await page.goto('/account')
      await expect(h1(page)).toContainText("'s account")
      await page.getByLabel('Display name').fill(`${role} renamed`)
      await page.getByRole('button', { name: 'Save' }).click()
      await expect(page.locator('[data-sonner-toast]').filter({ hasText: /Saved/ }).first()).toBeVisible()
      expect((await api<{ name: string }>(page.request, 'GET', '/me')).body.name).toBe(`${role} renamed`)
      noErrors(errors)
      await Promise.all([context.close(), who.ctx.dispose()])
    })
  })
}

test('the unknown settings section and the settings index', async ({ browser }) => {
  const context = await browser.newContext({ baseURL: box().base_url, storageState: authFile('viewer') })
  const page: Page = await context.newPage()
  await page.goto('/settings/nothing-here')
  await expect(page.getByText('No such settings section')).toBeVisible()
  await page.goto('/settings')
  await expect(page).toHaveURL(/\/settings\/general/)
  await context.close()
})

test('the seeded accounts keep their roles', async () => {
  for (const role of ['admin', 'operator', 'viewer'] as const) {
    const c = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    expect((await api<{ email: string; role: string }>(c, 'GET', '/me')).body).toMatchObject({ email: ACCOUNTS[role].email, role })
    await c.dispose()
  }
})
