// Two-step sign-in on the real backend (S-CORE-3, D-76, D-77, D-35): the authenticator app, the email code (read from the SMTP sink the box
// runs, see cmd/vedette/e2ebox_test.go), an expired and a used code, the administrator's reset, and the device cookie. Steps from
// e2e/qa/twofa.spec.ts; the codes come from the key on the page and from the sink instead of the preview note of the mock. Every account is a
// throwaway made with uniq() (D-172). The email channel is saved through notify's API as a precondition (the sink is its SMTP server).
// What turns the email channel OFF is box-wide and lives in twofa-channel.global.spec.ts.
import { expect, test, type Page } from '@playwright/test'
import { api, authFile, box, codesFor, ensureEmailChannel, expirePendingCode, nextCode } from './box'
import { h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'
import { adminApi, codeAfter, masked, newUser, signIn, step, submitSignIn, totp, wrongCode } from './twofa'

test.use({ actionTimeout: 10_000 })

const code = (page: Page) => page.getByLabel('6-digit code')
const logout = (page: Page) => api(page.request, 'POST', '/auth/logout')

/** My account → Two-step sign-in, started with the current password (D-76), for the authenticator app. Returns the manual key. */
async function startApp(page: Page, pw: string): Promise<string> {
  await page.goto('/account')
  await expect(page.getByRole('heading', { name: 'Two-step sign-in' })).toBeVisible()
  await page.getByLabel('Your current password').fill(pw)
  await page.getByRole('button', { name: 'Set up authenticator app' }).click()
  const key = (await page.getByLabel('Manual key').innerText()).trim()
  expect(key).toMatch(/^[A-Z2-7]{32}$/)
  return key
}

/** Starts the email method and reads the code the box mailed, from the sink. */
async function startEmail(page: Page, email: string, pw: string): Promise<string> {
  const seen = (await codesFor(email)).length
  await page.goto('/account')
  await page.getByLabel('Your current password').fill(pw)
  await page.getByRole('button', { name: 'Set up email code' }).click()
  await expect(page.getByText(`We sent a 6-digit code to ${masked(email)}.`)).toBeVisible()
  return nextCode(email, seen)
}

test('authenticator app: the password comes first, a wrong code is refused, sign-in needs the code, a used code is refused, turn off', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  const who = await newUser('app')
  await signIn(page, who.email, who.pw)
  await page.goto('/account')
  await expect(page.getByRole('heading', { name: 'Two-step sign-in' })).toBeVisible()
  await shot(page, 'real', 'twofa-account-choose')

  // D-76: the current password comes first: the button waits for it and a wrong one is refused (and no key is made)
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toBeDisabled()
  await page.getByLabel('Your current password').fill('not-my-password')
  await page.getByRole('button', { name: 'Set up authenticator app' }).click()
  await expect(page.getByText(/Wrong password/)).toBeVisible()
  await expect(page.getByLabel('Manual key')).toHaveCount(0)

  await page.getByLabel('Your current password').fill(who.pw)
  await page.getByRole('button', { name: 'Set up authenticator app' }).click()
  await expect(page.getByRole('img', { name: 'QR code for your authenticator app' })).toBeVisible()
  const key = (await page.getByLabel('Manual key').innerText()).trim()
  const uri = new URL((await page.getByLabel('otpauth address').innerText()).trim())
  expect(key).toMatch(/^[A-Z2-7]{32}$/)
  expect(uri.protocol + uri.host).toBe('otpauth:totp')
  expect(decodeURIComponent(uri.pathname)).toBe(`/Vedette:${who.email}`)
  expect(uri.searchParams.get('secret')).toBe(key)
  expect(['issuer', 'digits', 'period', 'algorithm'].map((k) => uri.searchParams.get(k))).toEqual(['Vedette', '6', '30', 'SHA1'])
  await shot(page, 'real', 'twofa-app-setup')

  // not on until a right code comes: a short code and a wrong code are refused, and the account is still password-only
  const first = totp(key)
  await code(page).fill('12')
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText(/The code is 6 digits/)).toBeVisible()
  await code(page).fill(wrongCode(first))
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  expect((await api<{ twofa: boolean }>(page.request, 'GET', '/me')).body.twofa).toBe(false)
  const usedAtSetup = step()
  await code(page).fill(first)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Authenticator app')).toBeVisible()
  expect((await api<{ twofa: boolean; twofa_method: string }>(page.request, 'GET', '/me')).body).toMatchObject({ twofa: true, twofa_method: 'app' })

  // sign out, sign in: the password alone is not enough
  await logout(page)
  await submitSignIn(page, who.email, who.pw)
  await expect(code(page)).toBeFocused()
  await expect(page.getByText(/Get the code from your authenticator app/)).toBeVisible()
  await expect(page.getByRole('button', { name: /Send a new code/ })).toHaveCount(0)
  await expect(page).toHaveURL(/\/login/)
  expect((await api(page.request, 'GET', '/me')).status, 'a password without the code opens no session').toBe(401)
  await shot(page, 'real', 'twofa-login-code')
  const second = await codeAfter(key, usedAtSetup)
  await code(page).fill(wrongCode(second.code))
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
  await code(page).fill(second.code.replace(/(\d{3})(\d{3})/, '$1 $2')) // typed with a space, the way an app shows it
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)
  await expect(h1(page)).toBeVisible()

  // the same code, a second time, is refused (a code cannot be replayed within its window)
  await logout(page)
  await submitSignIn(page, who.email, who.pw)
  await code(page).fill(second.code)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
  const third = await codeAfter(key, second.step)
  await code(page).fill(third.code)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)

  // turn off: the password again (D-76)
  await page.goto('/account')
  await page.getByRole('button', { name: 'Turn off two-step sign-in' }).click()
  await page.getByRole('dialog').getByLabel('Current password').fill('not-my-password')
  await page.getByRole('button', { name: 'Turn off', exact: true }).click()
  await expect(page.getByText(/Wrong password/)).toBeVisible()
  await page.getByRole('dialog').getByLabel('Current password').fill(who.pw)
  await page.getByRole('button', { name: 'Turn off', exact: true }).click()
  await expect(page.getByText('Two-step sign-in is off.').first()).toBeVisible()
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toBeVisible()
  await noVietnamese(page, 'account')
  await who.admin.dispose()
  noErrors(errors, /status of (40\d|429)/)
})

test('email code: set up from the code in the mailbox, sign in needs a mailed code, a wrong and a used code are refused', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const who = await newUser('mail')
  await ensureEmailChannel(await adminApi())
  await signIn(page, who.email, who.pw)

  // setup: the code is only in the mailbox of the sink; a wrong one is refused with the tries left
  const setupCode = await startEmail(page, who.email, who.pw)
  await expect(page.getByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
  await shot(page, 'real', 'twofa-email-setup')
  await code(page).fill(wrongCode(setupCode))
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('Wrong code. 4 tries left.')).toBeVisible()
  await code(page).fill(setupCode)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Email code')).toBeVisible()
  await expect(page.getByText(`emails to ${masked(who.email)}`)).toBeVisible()
  // switching means turning off first
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toHaveCount(0)

  // sign in: the same call that answers "a code is needed" has mailed the code
  await logout(page)
  const seen = (await codesFor(who.email)).length
  await submitSignIn(page, who.email, who.pw)
  await expect(code(page)).toBeFocused()
  await expect(code(page)).toHaveAttribute('autocomplete', 'one-time-code')
  await expect(page.getByText(`We sent a 6-digit code to ${masked(who.email)}. It expires in 10 minutes.`)).toBeVisible()
  const loginCode = await nextCode(who.email, seen)
  expect((await codesFor(who.email)).length, 'one code per sign-in prompt').toBe(seen + 1)
  await expect(page.getByRole('button', { name: /^Send a new code in \d+ s$/ })).toBeDisabled()
  await shot(page, 'real', 'twofa-email-login')
  expect((await api(page.request, 'GET', '/me')).status, 'a password without the code opens no session').toBe(401)
  await code(page).fill(wrongCode(loginCode))
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('Wrong code. 4 tries left.')).toBeVisible()
  await code(page).fill(loginCode)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)
  await expect(h1(page)).toBeVisible()

  // a code works once: after signing out, the code that just opened a session is refused, and the next sign-in has its own new code
  await logout(page)
  const seen2 = (await codesFor(who.email)).length
  await submitSignIn(page, who.email, who.pw)
  const newCode = await nextCode(who.email, seen2)
  expect(newCode === loginCode, 'a new code is made for every sign-in').toBe(false)
  await code(page).fill(loginCode)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
  await code(page).fill(newCode)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)
  await noVietnamese(page, 'home')
  await who.admin.dispose()
  noErrors(errors, /status of (40\d|429)/)
})

test('email code: an expired code is refused and a new one can be asked for', async ({ page }) => {
  test.setTimeout(180_000) // the page waits 60 s before it offers a new code
  const errors = collectErrors(page)
  const who = await newUser('exp')
  await ensureEmailChannel(await adminApi())
  await signIn(page, who.email, who.pw)
  const setupCode = await startEmail(page, who.email, who.pw)
  await code(page).fill(setupCode)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Email code')).toBeVisible()
  await logout(page)

  const seen = (await codesFor(who.email)).length
  await submitSignIn(page, who.email, who.pw)
  const stale = await nextCode(who.email, seen)
  await expirePendingCode(who.email) // the real lifetime is 10 minutes and the box has no fake clock
  await code(page).fill(stale) // the right code, but too late
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText('This code has expired. Ask for a new code.')).toBeVisible()
  await expect(page).toHaveURL(/\/login/)
  expect((await api(page.request, 'GET', '/me')).status, 'an expired code opens no session').toBe(401)

  // the page counts 60 s from the mail before it offers Send a new code; then the new code works, and the expired one is not accepted
  const resend = page.getByRole('button', { name: /^Send a new code/ })
  await expect(resend).toBeEnabled({ timeout: 70_000 })
  await resend.click()
  const fresh = await nextCode(who.email, seen + 1)
  await expect(page.getByText(`A new code was sent to ${masked(who.email)}.`)).toBeVisible()
  await code(page).fill(stale)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByText(/Wrong code/)).toBeVisible()
  await code(page).fill(fresh)
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page).not.toHaveURL(/\/login/)
  await who.admin.dispose()
  noErrors(errors, /status of (40\d|429)/)
})

test('an administrator resets another user\'s two-step sign-in: it shows in Users, the reset is audited, the user must set it up again (D-35)', async ({ page, browser }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  const who = await newUser('rst')
  await ensureEmailChannel(await adminApi())
  await signIn(page, who.email, who.pw)
  const setupCode = await startEmail(page, who.email, who.pw)
  await code(page).fill(setupCode)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Email code')).toBeVisible()
  await logout(page)

  const adminCtx = await browser.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const ap = await adminCtx.newPage()
  await ap.goto('/settings/users')
  await expect(h1(ap)).toContainText('active users')
  await ap.getByRole('textbox', { name: 'Find a user' }).fill(who.name)
  const row = ap.getByRole('row').filter({ hasText: who.email })
  await expect(row).toHaveCount(1)
  await expect(row).toContainText('Email code')
  await shot(ap, 'real', 'twofa-users-status')
  await ap.getByRole('button', { name: `Reset two-step sign-in of ${who.name}` }).click()
  const dlg = ap.getByRole('dialog', { name: `Reset two-step sign-in for ${who.name}?` })
  await expect(dlg).toBeVisible()
  await dlg.getByRole('button', { name: 'Cancel' }).click() // Cancel changes nothing
  expect((await api<{ items: { email: string; twofa_method: string | null }[] }>(ap.request, 'GET', '/core/users')).body.items.find((u) => u.email === who.email)!.twofa_method).toBe('email')
  await ap.getByRole('button', { name: `Reset two-step sign-in of ${who.name}` }).click()
  await dlg.getByRole('button', { name: 'Reset two-step sign-in' }).click()
  await expect(ap.getByText('Two-step sign-in was reset.').first()).toBeVisible()
  await expect(ap.getByRole('button', { name: `Reset two-step sign-in of ${who.name}` })).toHaveCount(0)
  await expect(row).toContainText('Off')
  // the reset is a row of the audit log, with who did it and for whom
  const audit = await api<{ items: { action: string; user: string; detail: string }[] }>(ap.request, 'GET', `/core/audit?q=${encodeURIComponent(who.email)}`)
  const rowAudit = audit.body.items.find((r) => r.action === 'user.2fa_reset')
  expect(rowAudit, `audit rows: ${JSON.stringify(audit.body.items)}`).toBeTruthy()
  expect(rowAudit!.user).toBe('admin@e2e.test')
  await adminCtx.close()

  // the user: the password alone opens a session now, and the account offers the setup again (nothing is on)
  const seen = (await codesFor(who.email)).length
  await signIn(page, who.email, who.pw)
  expect((await codesFor(who.email)).length, 'no code is mailed any more').toBe(seen)
  expect((await api<{ twofa: boolean; twofa_method: string | null }>(page.request, 'GET', '/me')).body).toMatchObject({ twofa: false, twofa_method: null })
  await page.goto('/account')
  await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Set up email code' })).toBeVisible()
  await expect(page.getByRole('button', { name: 'Turn off two-step sign-in' })).toHaveCount(0)
  await shot(page, 'real', 'twofa-after-reset')
  // and they set it up again, as a new user would: this time with the app, and a new key
  const key = await startApp(page, who.pw)
  await code(page).fill(totp(key))
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Authenticator app')).toBeVisible()
  await logout(page)
  await submitSignIn(page, who.email, who.pw)
  await expect(code(page)).toBeFocused()
  await who.admin.dispose()
  noErrors(errors, /status of (40\d|429)/)
})

test('an administrator cannot reset their own two-step sign-in through the users API (D-35)', async ({ browser }) => {
  const adminCtx = await browser.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const ap = await adminCtx.newPage()
  const me = await api<{ id: string }>(ap.request, 'GET', '/me')
  const reset = await api(ap.request, 'POST', `/core/users/${me.body.id}/2fa/reset`)
  expect(reset.status, JSON.stringify(reset.body)).toBe(400)
  expect((reset.body as { error: { code: string } }).error.code).toBe('self_reset')
  await adminCtx.close()
})

test('the device cookie (D-77) is set at sign-in for that browser only, and it does not replace the code', async ({ page, browser }) => {
  test.setTimeout(180_000)
  const who = await newUser('dev')
  await ensureEmailChannel(await adminApi())
  await signIn(page, who.email, who.pw)
  const cookies = async (p: Page) => (await p.context().cookies()).filter((c) => c.name === '__Secure-vedette_device')
  const device = await cookies(page)
  expect(device, 'the sign-in sets the device cookie').toHaveLength(1)
  expect(device[0]).toMatchObject({ httpOnly: true, secure: true, sameSite: 'Strict', path: '/api/v1/auth/' })
  const setupCode = await startEmail(page, who.email, who.pw)
  await code(page).fill(setupCode)
  await page.getByRole('button', { name: 'Confirm and turn on' }).click()
  await expect(page.getByText('On: Email code')).toBeVisible()

  // the same browser, signing in again: the cookie is there, and the code is still asked for (nothing here skips two-step)
  await logout(page)
  const seen = (await codesFor(who.email)).length
  await submitSignIn(page, who.email, who.pw)
  await expect(code(page)).toBeFocused()
  await nextCode(who.email, seen)
  expect(await cookies(page)).toHaveLength(1)
  // a browser that never signed in has none
  const other = await browser.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] } })
  expect((await other.cookies()).filter((c) => c.name === '__Secure-vedette_device')).toHaveLength(0)
  const op = await other.newPage()
  const seen2 = (await codesFor(who.email)).length
  await submitSignIn(op, who.email, who.pw)
  await expect(code(op)).toBeFocused()
  // (a code mailed less than 60 s ago and still valid is kept, not sent again: nothing new in the mailbox is expected here)
  expect((await codesFor(who.email)).length).toBe(seen2)
  expect(await other.cookies(), 'a password and no code leaves no session cookie').not.toEqual(expect.arrayContaining([expect.objectContaining({ name: '__Host-vedette_session' })]))
  await other.close()
  await who.admin.dispose()
})
