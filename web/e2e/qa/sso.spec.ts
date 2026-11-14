// QA as a real admin and user for D-194..D-196 (S-CORE-3): SSO sign-in (OIDC) on the mock API, desktop and phone, light and dark.
// Run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/sso.spec.ts --workers=1
// (needs the dev server on http://localhost:5173; screenshots go to qa-shots/sso/)
import { expect, test, type Page, type TestInfo } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean } from './clean'

test.describe.configure({ retries: 1 })
test.use({ actionTimeout: 10_000 })

const EMAIL = 'admin@testco.example'
const PW = 'a-very-long-password-123'
const ISSUER = 'https://sso.testco.example/realms/main'
const GROUP = 'vedette-operators'
const IDP_EMAIL = 'sso.user@acme.example'

async function scheme(page: Page, colorScheme: 'light' | 'dark') {
  await page.emulateMedia({ colorScheme })
  await page.mouse.move(0, 0)
  await page.waitForTimeout(600)
}
const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
const logout = (page: Page) => page.evaluate(() => fetch('/api/v1/auth/logout', { method: 'POST' }))
const call = (page: Page, path: string, body?: object, method = 'POST') =>
  page.evaluate(async ([p, b, m]) => {
    const r = await fetch(`/api/v1${p as string}`, { method: m as string, headers: { 'Content-Type': 'application/json' }, body: b ? JSON.stringify(b) : undefined })
    return { status: r.status, body: (await r.json().catch(() => null)) as Record<string, unknown> | null }
  }, [path, body ?? null, method] as const)

/** A screenshot in light and dark, an accessibility check in both, no sideways scroll, no Vietnamese text. */
async function look(page: Page, info: TestInfo, name: string) {
  const mod = `sso/${info.project.name}`
  // a toast fading in or out makes axe measure contrast mid-animation (a test artefact); wait until none is on screen
  await page.locator('[data-sonner-toast]').first().waitFor({ state: 'detached', timeout: 12_000 }).catch(() => undefined)
  await shot(page, mod, `${name}-light`)
  await expectAccessible(page, `${name} (light)`)
  const wide = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  expect(wide, `${name}: page scrolls sideways by ${wide}px`).toBeLessThanOrEqual(1)
  const bad = (await page.locator('body').innerText()).split('\n').filter((l) => DIACRITICS.test(l))
  expect(bad, `${name}: Vietnamese text in the UI`).toEqual([])
  await scheme(page, 'dark')
  await shot(page, mod, `${name}-dark`)
  await expectAccessible(page, `${name} (dark)`)
  await scheme(page, 'light')
}
async function loginPw(page: Page, email = EMAIL, password = PW) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).click()
  await expect(page).not.toHaveURL(/\/login/)
}
const oidcForm = (page: Page) => page.locator('form').filter({ has: page.locator('#oidc-issuer') })

/** Setup through the API (what scenario a does by hand): module on, configuration saved. */
async function configureViaApi(page: Page, roleMap: { group: string; role: string }[]) {
  await page.goto('/account') // a fresh page load, so the mock API controls fetch
  await expect(h1(page)).toBeVisible()
  expect((await call(page, '/modules/auth-oidc', { enabled: true }, 'PATCH')).status).toBe(200)
  const r = await call(page, '/core/oidc', { issuer: ISSUER, client_id: 'vedette', client_secret: 'client-secret-123', scopes: 'openid email profile groups', groups_claim: 'groups', default_role: null, role_map: roleMap }, 'PUT')
  expect(r.status).toBe(200)
}

test('A-C, E: admin sets up SSO, a person signs in, admin sees them, admin turns SSO off', async ({ page }, info) => {
  test.setTimeout(240_000)
  const errors = collectErrors(page)
  await finishClean(page)

  // ---- a) admin: Settings -> Users -> SSO
  await page.goto('/settings/users')
  await expect(page.getByRole('heading', { name: 'SSO sign-in (OIDC)' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Turn on SSO sign-in' })).toBeVisible()
  await expect(page.getByText(/SSO sign-in is off\./)).toBeVisible()
  await look(page, info, 'a1-sso-off')
  await page.getByRole('button', { name: 'Turn on SSO sign-in' }).click()
  await expect(page.getByLabel('Issuer')).toBeVisible()
  await expect(page.getByText('Redirect URI: register this address at your identity provider')).toBeVisible()
  await expect(page.getByText(/\/sso\/callback$/).first()).toBeVisible()
  // Test connection is not usable before the first save, and says why
  await expect(page.getByRole('button', { name: 'Test connection' })).toBeDisabled()
  await look(page, info, 'a2-sso-on-empty')

  // http is refused with a clear sentence beside the field
  await page.getByLabel('Issuer').fill('http://sso.testco.example/realms/main')
  await page.getByLabel('Client ID').fill('vedette')
  await page.getByLabel('Client secret').fill('client-secret-123')
  await oidcForm(page).getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText(/The issuer must be an https address/)).toBeVisible()
  await expect(page.getByLabel('Issuer')).toHaveAttribute('aria-invalid', 'true')
  await expect(page.getByLabel('Issuer')).toHaveValue('http://sso.testco.example/realms/main') // what I typed is kept
  await look(page, info, 'a3-http-error')

  await page.getByLabel('Issuer').fill(ISSUER)
  await page.getByLabel('Scopes').fill('openid email profile groups')
  await expect(page.getByLabel('Groups claim')).toHaveValue('groups')
  await page.getByRole('button', { name: 'Add row' }).click()
  await page.getByLabel('Group name, row 1').fill(GROUP)
  await page.getByLabel('Role, row 1').selectOption({ label: 'Operator' })
  await expect(page.getByLabel('People in none of these groups')).toHaveValue(/./) // No access is the default
  await expect(page.getByLabel('People in none of these groups').locator('option:checked')).toHaveText('No access')
  await look(page, info, 'a4-filled')
  await oidcForm(page).getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText('Saved', { exact: true }).first()).toBeVisible()
  await expect(page.getByText('Saved, ending in -123. Leave empty to keep it.')).toBeVisible()
  await expect(page.getByLabel('Client secret')).toHaveValue('') // the secret is not echoed back
  await page.waitForTimeout(1500) // let the "Saved" toast finish its fade-in, or axe measures contrast mid-animation
  await look(page, info, 'a5-saved')

  await expect(page.getByRole('button', { name: 'Test connection' })).toBeEnabled()
  await page.getByRole('button', { name: 'Test connection' }).click()
  // the list has an accessible name only; a sighted admin sees no title above it (noted as a wording gap in the QA report)
  await expect(page.getByRole('region', { name: 'Endpoints read from the identity provider' })).toBeVisible()
  await expect(page.getByText(`${ISSUER}/protocol/openid-connect/auth`)).toBeVisible()
  await expect(page.getByText('Signing keys')).toBeVisible()
  await look(page, info, 'a6-test-endpoints')

  // ---- b) a person signs in through SSO
  await logout(page)
  await page.goto('/login')
  const ssoBtn = page.getByRole('button', { name: 'Sign in with SSO' })
  await expect(ssoBtn).toBeVisible()
  await expect(page.getByRole('button', { name: 'Sign in', exact: true })).toBeVisible() // passwords still work
  await look(page, info, 'b1-login-with-sso')
  await ssoBtn.click()
  await page.waitForURL(/\/sso\/callback/)
  await expect(page.getByText(/Checking the answer|Signing you in/).first()).toBeVisible().catch(() => undefined) // brief on the mock
  await expect(h1(page)).toBeVisible()
  await expect(page).not.toHaveURL(/\/(login|sso\/callback)/)
  expect(page.url(), 'the one-time code stays out of the address bar').not.toMatch(/code=|state=/)
  const me = await call(page, '/core/account', undefined, 'GET')
  expect((me.body!.user as { role: string; email: string }).role).toBe('operator')
  expect((me.body!.user as { email: string }).email).toBe(IDP_EMAIL)
  // The home page itself has a link-in-text-block axe failure (a[href$="feeds"]) that is not part of the SSO screens: screenshots only here.
  await shot(page, `sso/${info.project.name}`, 'b2-in-the-app-operator-light')
  await scheme(page, 'dark')
  await shot(page, `sso/${info.project.name}`, 'b2-in-the-app-operator-dark')
  await scheme(page, 'light')
  // an Operator does not get the admin settings
  await page.goto('/settings/users')
  await expect(page.getByRole('heading', { name: 'SSO sign-in (OIDC)' })).toHaveCount(0)
  await look(page, info, 'b3-operator-no-users-settings')

  await page.goto('/settings/account?tab=sign-in')
  await expect(page.getByRole('heading', { name: 'Password and two-step sign-in' })).toBeVisible()
  await expect(page.getByText(/You sign in through your company account \(SSO\)/)).toBeVisible()
  await expect(page.getByText(/not in Vedette/)).toBeVisible()
  await expect(page.getByLabel('Your current password')).toHaveCount(0)
  await expect(page.getByRole('button', { name: /Set up authenticator app/ })).toHaveCount(0)
  await look(page, info, 'b4-my-account-sso')

  // ---- c) admin: the Users table
  await logout(page)
  await loginPw(page)
  await page.goto('/settings/users')
  const row = page.locator('tr, ul[aria-label] > li').filter({ hasText: IDP_EMAIL })
  await expect(row).toBeVisible()
  await expect(row.getByText('Through SSO')).toBeVisible()
  await expect(row.getByText('Set by SSO groups')).toBeVisible()
  await expect(row.getByText('Operator', { exact: true })).toBeVisible()
  await expect(row.getByRole('combobox')).toHaveCount(0) // no role dropdown
  await expect(row.getByRole('button', { name: /Reset password/ })).toHaveCount(0)
  // the password admin still has all of theirs
  await expect(page.locator('tr, ul[aria-label] > li').filter({ hasText: EMAIL }).getByRole('combobox')).toBeVisible()
  await expect(page.locator('tr, ul[aria-label] > li').filter({ hasText: EMAIL }).getByRole('button', { name: /Reset password/ })).toBeVisible()
  await look(page, info, 'c1-users-table')

  // ---- e) turn SSO off: the dialog counts the people who only sign in through SSO
  await page.getByRole('button', { name: 'Turn off SSO' }).click()
  const dlg = page.getByRole('dialog')
  await expect(dlg.getByText('Turn off SSO sign-in?')).toBeVisible()
  await expect(dlg.getByText(/1 person signs in only through SSO and cannot sign in until SSO is on again/)).toBeVisible()
  await expect(dlg.getByRole('button', { name: 'Cancel' })).toBeVisible()
  await look(page, info, 'e1-turn-off-dialog')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(dlg).toHaveCount(0)
  await expect(page.getByLabel('Issuer')).toHaveValue(ISSUER) // cancel changed nothing
  await page.getByRole('button', { name: 'Turn off SSO' }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'Turn off SSO' }).click()
  await expect(page.getByText(/SSO sign-in is off\. The settings are kept\./).first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Turn on SSO sign-in' })).toBeVisible()
  await look(page, info, 'e2-sso-off-again')
  await logout(page)
  await page.goto('/login')
  await expect(page.getByRole('button', { name: 'Sign in with SSO' })).toHaveCount(0)
  await shot(page, `sso/${info.project.name}`, 'e3-login-no-sso-button')
  expect(errors.filter((e) => !/does not provide an export/.test(e))).toEqual([])
})

test('D: refusals have a clear sentence and a way back', async ({ page, context }, info) => {
  test.setTimeout(240_000)
  const errors = collectErrors(page)
  await finishClean(page)
  await configureViaApi(page, [{ group: GROUP, role: 'operator' }])

  // callback opened in another tab of the same browser: no binding in that tab
  const start = await call(page, '/auth/oidc/start')
  expect(start.status).toBe(200)
  const url = (start.body as { authorize_url: string }).authorize_url
  const other = await context.newPage()
  await other.goto(url)
  await expect(other.getByRole('heading', { name: 'SSO sign-in did not work' })).toBeVisible()
  await expect(other.getByRole('alert')).toContainText('started in another tab')
  expect(other.url(), 'the one-time code is removed from the address bar').not.toMatch(/code=|state=/)
  await look(other, info, 'd1-another-tab')
  await other.getByRole('link', { name: 'Back to sign in' }).click()
  await expect(other).toHaveURL(/\/login/)
  await expect(other.getByRole('button', { name: 'Sign in with SSO' })).toBeVisible() // retry is one click away
  await other.close()

  // a callback link in a fresh browser (nothing stored there at all)
  const fresh = await (await page.context().browser()!.newContext({ baseURL: 'http://localhost:5173' })).newPage()
  await fresh.goto(url)
  await expect(fresh.getByRole('link', { name: 'Back to sign in' })).toBeVisible()
  await shot(fresh, `sso/${info.project.name}`, 'd2-fresh-browser')
  await fresh.context().close()

  // the identity provider answers with an error
  await page.goto('/sso/callback?error=access_denied')
  await expect(page.getByRole('heading', { name: 'SSO sign-in did not work' })).toBeVisible()
  await expect(page.getByRole('alert')).toContainText('access_denied')
  await expect(page.getByRole('alert')).toContainText('did not sign you in')
  await look(page, info, 'd3-idp-error')
  await page.getByRole('link', { name: 'Back to sign in' }).click()
  await expect(page).toHaveURL(/\/login/)

  // a callback with nothing in it
  await page.goto('/sso/callback')
  await expect(page.getByRole('alert')).toContainText('Start again from the sign-in page')
  await expect(page.getByRole('link', { name: 'Back to sign in' })).toBeVisible()

  // the admin removes the only group row; the same person is now refused
  await loginPw(page)
  await page.goto('/settings/users')
  await expect(page.getByLabel('Group name, row 1')).toHaveValue(GROUP)
  await page.getByRole('button', { name: 'Remove row 1' }).click()
  await expect(page.getByLabel('Group name, row 1')).toHaveCount(0)
  await oidcForm(page).getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText('Saved', { exact: true }).first()).toBeVisible()
  await look(page, info, 'd4-group-row-removed')
  await logout(page)
  await page.goto('/login')
  await page.getByRole('button', { name: 'Sign in with SSO' }).click()
  await page.waitForURL(/\/sso\/callback/)
  await expect(page.getByRole('heading', { name: 'SSO sign-in did not work' })).toBeVisible()
  await expect(page.getByRole('alert')).toContainText('Your company account is not in a group that may use Vedette. Ask an administrator.')
  await look(page, info, 'd5-no-group-refused')
  await page.getByRole('link', { name: 'Back to sign in' }).click()
  await expect(page).toHaveURL(/\/login/)
  // back on the sign-in page the password form still works: not a dead end
  await loginPw(page)
  await expect(h1(page)).toBeVisible()
  expect(errors.filter((e) => !/does not provide an export/.test(e))).toEqual([])
})
