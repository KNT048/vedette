// Email channel off, on the real backend (S-CORE-3, D-35): the email-code method is refused, never answered with a password-only sign-in.
// Global project: the email channel is one setting of the whole box, and the specs of the parallel project save it as a precondition.
// The channel is saved again at the end, so the box is left the way the other specs expect it.
import { expect, test } from '@playwright/test'
import { api, codesFor, ensureEmailChannel, nextCode } from './box'
import { collectErrors, shot } from '../e2e/helpers'
import { noErrors } from './ui'
import { adminApi, fresh, masked, newUser, signIn, submitSignIn } from './twofa'

test.use({ actionTimeout: 10_000 })

test('email channel off: choosing email codes is refused, and an email-code user is refused, never signed in with the password alone', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const admin = await adminApi()
  const who = await newUser('off')
  try {
    // channel off, the user has no two-step: the account page does not offer email codes, and the API refuses to start them
    await expect(async () => {
      expect((await api(admin, 'DELETE', '/notify/channels/email')).status).toBeLessThan(500)
    }).toPass()
    await signIn(page, who.email, who.pw)
    await page.goto('/account')
    await page.getByLabel('Your current password').fill(who.pw)
    await expect(page.getByRole('button', { name: 'Set up email code' })).toBeDisabled()
    await expect(page.getByText(/the email alert channel, which is not set up or is turned off/)).toBeVisible()
    await expect(page.getByText('Ask an administrator to set up the email channel.')).toBeVisible() // a viewer cannot open the channel settings
    await shot(page, 'real', 'twofa-email-disabled')
    const start = await api<{ error: { code: string } }>(page.request, 'POST', '/core/account/2fa/email/start', { password: who.pw })
    expect(start.status, JSON.stringify(start.body)).toBe(409)
    expect(start.body.error.code, 'turning email codes on without a channel: core IMPACT.md (CodeMailer); the sign-in answer is twofa_email_unavailable (below)').toBe('email_channel_not_ready')
    expect((await api<{ twofa: boolean }>(page.request, 'GET', '/me')).body.twofa, 'a refused start turns nothing on').toBe(false)

    // channel on: the user turns email codes on
    await ensureEmailChannel(admin)
    await page.reload()
    await page.getByLabel('Your current password').fill(who.pw)
    const seen = (await codesFor(who.email)).length
    await page.getByRole('button', { name: 'Set up email code' }).click()
    await expect(page.getByText(`We sent a 6-digit code to ${masked(who.email)}.`)).toBeVisible()
    await page.getByLabel('6-digit code').fill(await nextCode(who.email, seen))
    await page.getByRole('button', { name: 'Confirm and turn on' }).click()
    await expect(page.getByText('On: Email code')).toBeVisible()
    await api(page.request, 'POST', '/auth/logout')

    // channel off again: the password is right and the account has two-step by email, so the sign-in is refused, no session, no fallback
    expect((await api(admin, 'DELETE', '/notify/channels/email')).status).toBeLessThan(500)
    const sent = (await codesFor(who.email)).length
    await submitSignIn(page, who.email, who.pw)
    await expect(page.getByText('Two-step email codes cannot be sent right now. Ask an administrator to turn the email channel back on, or to reset your two-step sign-in.')).toBeVisible()
    await expect(page.getByLabel('6-digit code')).toHaveCount(0)
    await expect(page).toHaveURL(/\/login/)
    await shot(page, 'real', 'twofa-login-channel-off')
    const direct = await api<{ error: { code: string } }>(await fresh(), 'POST', '/auth/login', { email: who.email, password: who.pw })
    expect(direct.status, JSON.stringify(direct.body)).toBe(503)
    expect(direct.body.error.code).toBe('twofa_email_unavailable')
    expect((await api(page.request, 'GET', '/me')).status, 'no session was opened').toBe(401)
    expect((await codesFor(who.email)).length, 'nothing was mailed').toBe(sent)

    // the administrator's way out: reset the user's two-step sign-in (D-35)
    expect((await api(admin, 'GET', '/core/users')).status).toBe(200)
    const list = await api<{ items: { id: string; email: string }[] }>(admin, 'GET', '/core/users')
    const id = list.body.items.find((u) => u.email === who.email)!.id
    expect((await api(admin, 'POST', `/core/users/${id}/2fa/reset`)).status).toBe(200)
    await signIn(page, who.email, who.pw)
  } finally {
    await ensureEmailChannel(admin)
    await who.admin.dispose()
    await admin.dispose()
  }
  noErrors(errors, /status of (40\d|409|503)/)
})
