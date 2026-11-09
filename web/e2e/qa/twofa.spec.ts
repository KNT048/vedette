// QA as a real user for D-35: two-step sign-in with two methods (authenticator app, email code) and the admin reset.
// Run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/twofa.spec.ts --workers=1
import { createHmac } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean } from './clean'

test.describe.configure({ retries: 1 })
test.use({ actionTimeout: 10_000 })

const EMAIL = 'admin@testco.example'
const PW = 'a-very-long-password-123'
const MASKED = 'a•••@testco.example'

/** Switch the theme and let colour transitions finish, or axe measures contrast mid-fade. */
async function scheme(page: Page, colorScheme: 'light' | 'dark') {
  await page.emulateMedia({ colorScheme })
  await page.mouse.move(0, 0)
  await page.waitForTimeout(600)
}
const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
const logout = (page: Page) => page.evaluate(() => fetch('/api/v1/auth/logout', { method: 'POST' }))
const post = (page: Page, path: string, body: object = {}, method = 'POST') =>
  page.evaluate(async ([p, b, m]) => { const r = await fetch(`/api/v1${p as string}`, { method: m as string, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return { status: r.status, body: (await r.json().catch(() => null)) as Record<string, unknown> | null } }, [path, body, method] as const)

/** The email channel as an administrator would save it (Settings, Alert channels). */
async function addEmailChannel(page: Page) {
  await page.goto('/account') // a fresh page load, so the mock API controls fetch
  await expect(page.getByRole('heading', { name: 'Two-step sign-in' })).toBeVisible()
  const r = await post(page, '/notify/channels/email', { enabled: true, min_severity: 'high', secret: 'smtp-secret-123', fields: { host: 'smtp.testco.example', port: '587', security: 'starttls', username: 'alerts@testco.example', from: 'alerts@testco.example', to: 'it@testco.example' } }, 'PUT')
  expect(r.status).toBe(200)
}
async function login(page: Page, email: string, password: string) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in' }).click()
}
async function noDiacritics(page: Page, label: string) {
  const bad = (await page.locator('body').innerText()).split('\n').filter((l) => DIACRITICS.test(l))
  expect(bad, `${label}: Vietnamese text in the UI`).toEqual([])
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function b32decode(s: string) {
  let bits = 0, v = 0
  const out: number[] = []
  for (const c of s.toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8 } }
  return Buffer.from(out)
}
/** TOTP written independently in the test (node:crypto), RFC 6238, SHA-1, 6 digits, 30 s. */
function totp(secret: string, at = Date.now()) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(at / 30000)))
  const h = createHmac('sha1', b32decode(secret)).update(c).digest()
  const o = h[19]! & 15
  const n = ((h[o]! & 127) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!
  return String(n % 1_000_000).padStart(6, '0')
}
/** The "Preview build: the email would contain 123456" note. */
async function previewCode(page: Page) {
  const note = page.getByTestId('preview-code')
  await expect(note).toBeVisible()
  const m = /(\d{6})\s*$/.exec((await note.innerText()).trim())
  expect(m, 'preview note holds a 6-digit code').not.toBeNull()
  return m![1]!
}

test('authenticator app: QR and manual key, turn on, sign out, sign in with the code', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  await finishClean(page)
  await page.goto('/account')
  await expect(page.getByRole('heading', { name: 'Two-step sign-in' })).toBeVisible()
  await shot(page, 'twofa', 'account-choose-light')
  await page.getByRole('button', { name: 'Set up authenticator app' }).click()

  const qr = page.getByRole('img', { name: 'QR code for your authenticator app' })
  await expect(qr).toBeVisible()
  await expect(page.getByText('Scan this QR code with your authenticator app, or enter the key by hand.')).toBeVisible()
  const box = await qr.boundingBox()
  expect(box!.width).toBeGreaterThanOrEqual(150)
  // black modules on white in every theme, so a phone can scan it
  expect(await qr.locator('rect').getAttribute('fill')).toBe('#fff')
  expect(await qr.locator('path').getAttribute('fill')).toBe('#000')
  await shot(page, 'twofa', 'account-app-qr-light')
  await expectAccessible(page, 'account app setup')
  await noDiacritics(page, 'account app setup')
  await scheme(page, 'dark')
  await shot(page, 'twofa', 'account-app-qr-dark')
  await expectAccessible(page, 'account app setup (dark)')
  await scheme(page, 'light')

  const key = (await page.getByText(/^[A-Z2-7]{32}$/).innerText()).trim()
  await page.getByLabel('6-digit code').fill('000000')
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  await page.getByLabel('6-digit code').fill(totp(key))
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Authenticator app')).toBeVisible()
  await shot(page, 'twofa', 'account-app-on')

  await logout(page)
  await login(page, EMAIL, PW)
  const code = page.getByLabel('6-digit code')
  await expect(code).toBeVisible()
  await expect(code).toBeFocused()
  await expect(page.getByText(/Get the code from your authenticator app/)).toBeVisible()
  await expect(page.getByRole('button', { name: /Send a new code/ })).toHaveCount(0)
  await shot(page, 'twofa', 'login-app')
  await code.fill(totp(key))
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(h1(page)).toBeVisible()
  await expect(page).not.toHaveURL(/\/login/)
  expect(errors.filter((e) => !/does not provide an export/.test(e))).toEqual([])
})

test('email code: disabled on a clean install, then set up, sign in with the preview code, resend cooldown', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  await finishClean(page)
  await page.goto('/account')
  // clean install: no email channel yet
  const setupEmail = page.getByRole('button', { name: 'Set up email code' })
  await expect(setupEmail).toBeDisabled()
  await expect(page.getByText(/the email alert channel, which is not set up or is turned off/)).toBeVisible()
  await expect(page.getByRole('link', { name: 'Open alert channels' })).toHaveAttribute('href', '/settings/channels')
  await shot(page, 'twofa', 'account-email-disabled-light')
  await expectAccessible(page, 'account email disabled')
  await noDiacritics(page, 'account email disabled')
  await scheme(page, 'dark')
  await shot(page, 'twofa', 'account-email-disabled-dark')
  await expectAccessible(page, 'account email disabled (dark)')
  await scheme(page, 'light')

  await addEmailChannel(page)
  await page.reload()
  await expect(setupEmail).toBeEnabled()
  await expect(page.getByText('Email codes need the email alert channel')).toHaveCount(0)
  await setupEmail.click()
  await expect(page.getByText(`We sent a 6-digit code to ${MASKED}.`)).toBeVisible()
  const setupCode = await previewCode(page)
  await expect(page.getByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
  await shot(page, 'twofa', 'account-email-code-light')
  await expectAccessible(page, 'account email code step')
  await scheme(page, 'dark')
  await shot(page, 'twofa', 'account-email-code-dark')
  await scheme(page, 'light')
  await page.getByLabel('6-digit code').fill(setupCode === '000000' ? '111111' : '000000')
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('Wrong code. 4 tries left.')).toBeVisible()
  await page.getByLabel('6-digit code').fill(setupCode)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Email code')).toBeVisible()
  await expect(page.getByText(`emails to ${MASKED}`)).toBeVisible()
  await shot(page, 'twofa', 'account-email-on')

  // switching means turning off first: no way to start the other method while on
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toHaveCount(0)

  await logout(page)
  await login(page, EMAIL, PW)
  const code = page.getByLabel('6-digit code')
  await expect(code).toBeVisible()
  await expect(code).toBeFocused()
  await expect(code).toHaveAttribute('autocomplete', 'one-time-code')
  await expect(page.getByText(`We sent a 6-digit code to ${MASKED}. It expires in 10 minutes.`)).toBeVisible()
  const loginCode = await previewCode(page)
  await expect(page.getByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
  await shot(page, 'twofa', 'login-email-light')
  await expectAccessible(page, 'login email code')
  await noDiacritics(page, 'login email code')
  await scheme(page, 'dark')
  await shot(page, 'twofa', 'login-email-dark')
  await expectAccessible(page, 'login email code (dark)')
  await scheme(page, 'light')
  await code.fill(loginCode === '000000' ? '111111' : '000000')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('Wrong code. 4 tries left.')).toBeVisible()
  await code.fill(loginCode)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(h1(page)).toBeVisible()
  await expect(page).not.toHaveURL(/\/login/)
  expect(errors.filter((e) => !/does not provide an export/.test(e))).toEqual([])
})

test('email channel off: an email-code user is refused, never signed in with the password alone', async ({ page }) => {
  test.setTimeout(120_000)
  await finishClean(page)
  await addEmailChannel(page)
  // the administrator turns on email codes for themselves (the mock returns the code in the response; a real backend only emails it)
  const start = await post(page, '/core/account/2fa/email/start')
  expect(start.status).toBe(200)
  expect((await post(page, '/core/account/2fa/email/confirm', { code: start.body!.preview_code })).status).toBe(200)
  // remove the channel while signed in (this admin is the only user, so this locks them out: that is the case under test)
  expect((await post(page, '/notify/channels/email', {}, 'DELETE')).status).toBe(204)
  await logout(page)
  await login(page, EMAIL, PW)
  await expect(page.getByText('Two-step email codes cannot be sent right now. Ask an administrator to turn the email channel back on, or to reset your two-step sign-in.')).toBeVisible()
  await expect(page.getByLabel('6-digit code')).toHaveCount(0)
  await expect(page).toHaveURL(/\/login/)
  await shot(page, 'twofa', 'login-channel-off')
  await expectAccessible(page, 'login channel off')
})

test('admin resets another user: status shows, confirm dialog, audit entry, user signs in with the password again', async ({ page }) => {
  test.setTimeout(150_000)
  await finishClean(page)
  await addEmailChannel(page)
  // a second user (Sam) turns on email codes
  const created = await post(page, '/core/users', { name: 'Sam Operator', email: 'sam@testco.example', role: 'operator' })
  expect(created.status).toBe(201)
  const temp = created.body!.temp_password as string
  await logout(page)
  const lg = await page.evaluate(async ([e, p]) => (await fetch('/api/v1/auth/login', { method: 'POST', body: JSON.stringify({ email: e, password: p }) })).status, ['sam@testco.example', temp])
  expect(lg).toBe(200)
  const start = await post(page, '/core/account/2fa/email/start')
  expect(start.status).toBe(200)
  expect((await post(page, '/core/account/2fa/email/confirm', { code: start.body!.preview_code })).status).toBe(200)
  await logout(page)

  // the administrator signs in (the admin has no two-step) and opens Users
  await login(page, EMAIL, PW)
  await expect(h1(page)).toBeVisible()
  await page.goto('/settings/users')
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  await expect(page.getByText('Email code').first()).toBeVisible()
  // the administrator cannot reset themselves: no button for a user without two-step
  await expect(page.getByRole('button', { name: 'Reset two-step sign-in of Alex Admin' })).toHaveCount(0)
  await shot(page, 'twofa', 'users-status')
  await expectAccessible(page, 'users with two-step status')
  await noDiacritics(page, 'users')
  await page.getByRole('button', { name: 'Reset two-step sign-in of Sam Operator' }).click()
  const dlg = page.getByRole('dialog', { name: 'Reset two-step sign-in for Sam Operator?' })
  await expect(dlg).toBeVisible()
  await shot(page, 'twofa', 'users-reset-dialog')
  await expectAccessible(page, 'reset dialog')
  await scheme(page, 'dark')
  await shot(page, 'twofa', 'users-reset-dialog-dark')
  await scheme(page, 'light')
  await dlg.getByRole('button', { name: 'Reset two-step sign-in' }).click()
  await expect(page.getByText('Two-step sign-in was reset.').first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Reset two-step sign-in of Sam Operator' })).toHaveCount(0)

  // audit log has the entry
  await page.goto('/settings/audit')
  await expect(page.getByText('Reset two-step sign-in').locator('visible=true').first()).toBeVisible()
  await expect(page.getByText('sam@testco.example').locator('visible=true').first()).toBeVisible()
  await shot(page, 'twofa', 'audit-reset')

  // Sam signs in with the password alone again
  await logout(page)
  await login(page, 'sam@testco.example', temp)
  await expect(page.getByLabel('6-digit code')).toHaveCount(0)
  await expect(page).not.toHaveURL(/\/login/)
})
