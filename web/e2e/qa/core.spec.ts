// QA như người dùng thật cho module core: cài đặt ban đầu, đăng nhập, cài đặt, tài khoản. Giao diện chỉ có tiếng Anh (D-28).
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/core.spec.ts
import { createHmac } from 'node:crypto'
import { expect, test, type Page } from '@playwright/test'
import { axeViolations, collectErrors, expectAccessible, shot } from '../helpers'

test.use({ actionTimeout: 10_000 })

const PW = 'a-very-long-password-123'
const LOGIN = { email: 'admin@example.test', password: PW }
const SAMPLE = { admin: 'admin@acme.example', operator: 'it@acme.example', viewer: 'director@acme.example', password: 'vedette-demo' }
// chữ Việt có dấu không được lọt vào giao diện (trừ tên tác giả "Kiên" trong dòng giấy phép và dữ liệu mẫu do người dùng/seed đặt)
const VI = /[ăâđêôơưáàảãạấầẩẫậắằẳẵặéèẻẽẹếềểễệíìỉĩịóòỏõọốồổỗộớờởỡợúùủũụứừửữựýỳỷỹỵ]/i
const ALLOWED_VI = /Kiên|acme\.example/

// the page heading is the box OS line (S-CORE-7, D-53); the Vedette software version is in its table
// installed version of the Vedette software row (table row on desktop, list item on a phone); first .font-mono is the version column
const softwareVersion = (page: Page) => page.locator('#vedette tbody tr, #vedette li').filter({ hasText: /^Vedette software/ }).first().locator('.font-mono').first()
const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
const next = (page: Page) => page.getByRole('button', { name: 'Continue' }).click()
const toastText = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const noErrors = (errors: string[], extra?: RegExp) => expect(errors.filter((e) => !/does not provide an export/.test(e) && !(extra && extra.test(e)))).toEqual([])
async function noVietnamese(page: Page, label: string) {
  const text = await page.locator('body').innerText()
  const bad = text.split('\n').filter((l) => VI.test(l) && !ALLOWED_VI.test(l))
  expect(bad, `${label}: chữ Việt trong giao diện`).toEqual([])
}

async function startSample(page: Page) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(h1(page)).toContainText('Today')
}
async function startClean(page: Page, org = 'Test Company') {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByLabel('Setup code').fill('setup-code-demo') // D-75: the code the mock accepts
  await page.getByLabel('Organization name').fill(org)
  await page.getByLabel('Administrator name').fill('Alex Admin')
  await page.getByLabel('Sign-in email').fill(LOGIN.email)
  await page.getByLabel('Password', { exact: true }).fill(PW)
  await page.getByLabel('Repeat password').fill(PW)
}
/** Cài sạch trọn vẹn, vào trang chủ với tài khoản quản trị mới. */
async function cleanInstall(page: Page, bundle: RegExp = /Small business/) {
  await startClean(page)
  await next(page)
  await page.getByLabel('Range 1', { exact: true }).fill('192.168.50.0/24')
  await next(page)
  await page.getByRole('radio', { name: bundle }).click()
  await next(page)
  await page.getByRole('button', { name: 'Skip and finish' }).click()
  await expect(h1(page)).toBeVisible()
  await expect(page).toHaveURL(/\/$/)
}
async function login(page: Page, email: string, password: string, code?: string) {
  await page.goto('/login')
  await page.getByLabel('Email').fill(email)
  await page.getByLabel('Password').fill(password)
  if (code) await page.getByLabel('6-digit code').fill(code)
  await page.getByRole('button', { name: 'Sign in' }).click()
}
async function logoutApi(page: Page) { await page.evaluate(() => fetch('/api/v1/auth/logout', { method: 'POST' })) }
async function sampleAs(page: Page, email: string) {
  await startSample(page)
  await logoutApi(page)
  await login(page, email, SAMPLE.password)
  await expect(h1(page)).toBeVisible()
  await expect(page).toHaveURL(/\/$/)
}

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
function b32decode(s: string) {
  let bits = 0, v = 0
  const out: number[] = []
  for (const c of s.toUpperCase()) { const i = B32.indexOf(c); if (i < 0) continue; v = (v << 5) | i; bits += 5; if (bits >= 8) { out.push((v >>> (bits - 8)) & 255); bits -= 8 } }
  return Buffer.from(out)
}
/** TOTP viết độc lập trong test (node:crypto) để đối chiếu với bản trong ứng dụng. */
function totp(secret: string, at = Date.now()) {
  const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(at / 30000)))
  const h = createHmac('sha1', b32decode(secret)).update(c).digest()
  const o = h[19]! & 15
  const n = ((h[o]! & 127) << 24) | (h[o + 1]! << 16) | (h[o + 2]! << 8) | h[o + 3]!
  return String(n % 1_000_000).padStart(6, '0')
}

test.describe('first-run setup', () => {
  test('mistakes at every step, fixes, finish; every page is empty with no sample data', async ({ page }) => {
    test.setTimeout(240_000)
    const errors = collectErrors(page)
    await page.goto('/')
    await page.evaluate(() => localStorage.clear())
    await page.goto('/setup')
    await expect(page.getByRole('heading', { level: 1, name: 'First-time Vedette setup' })).toBeVisible()
    await shot(page, 'core', 'setup-1')
    await expectAccessible(page, 'setup step 1')
    await noVietnamese(page, 'setup 1')

    // step 1: empty, weak password, mismatch, bad email
    await next(page)
    await expect(page.getByText('Enter the organization name (at least 2 characters).')).toBeVisible()
    await page.getByLabel('Setup code').fill('setup-code-demo') // D-75: the code the mock accepts
    await page.getByLabel('Organization name').fill('QA Company')
    await page.getByLabel('Administrator name').fill('QA Admin')
    await page.getByLabel('Sign-in email').fill('not-an-email')
    await page.getByLabel('Password', { exact: true }).fill('short')
    await next(page)
    await expect(page.getByText(/The email does not look right/)).toBeVisible()
    await expect(page.getByText(/The password needs at least 12 characters, it has 5 so far/)).toBeVisible()
    await page.getByLabel('Sign-in email').fill(LOGIN.email)
    await page.getByLabel('Password', { exact: true }).fill(PW)
    await page.getByLabel('Repeat password').fill(PW + 'x')
    await next(page)
    await expect(page.getByText('The two entries do not match.')).toBeVisible()
    await expect(page.getByLabel('Organization name')).toHaveValue('QA Company') // typed data is kept
    await page.getByLabel('Repeat password').fill(PW)
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
    // the owner's case: a bare address
    await page.getByLabel('Range 1', { exact: true }).fill('192.168.18.0')
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
    // the single commitment checkbox and the license line replace the consent upload
    await expect(page.getByLabel(/Upload/)).toHaveCount(0)
    await expect(page.locator('input[type=file]')).toHaveCount(0)
    await expect(page.getByText('Vedette is provided as is under the Apache-2.0 license; its author, Kien Nguyen, is not responsible for how you use it.')).toBeVisible()
    await page.getByRole('checkbox', { name: 'I confirm these ranges belong to my company and I am allowed to scan them.' }).check()
    await shot(page, 'core', 'setup-2')
    await next(page)

    // step 3 -> back keeps data -> next
    await expect(page.getByRole('heading', { level: 2, name: 'Choose a module bundle' })).toBeVisible()
    await page.getByRole('button', { name: 'Back' }).click()
    await expect(page.getByLabel('Range 1', { exact: true })).toHaveValue('192.168.18.0/25')
    await expect(page.getByLabel('Range 2', { exact: true })).toHaveValue('10.1.0.0/16')
    await next(page)
    await page.getByRole('radio', { name: /Mid-size business/ }).click()
    await shot(page, 'core', 'setup-3')
    await next(page)

    // step 4: incomplete -> errors; skip
    await expect(page.getByRole('heading', { level: 2, name: 'Where alerts go' })).toBeVisible()
    await page.getByRole('button', { name: 'Finish setup' }).click()
    await expect(page.getByText('Fill this in.').first()).toBeVisible()
    await shot(page, 'core', 'setup-4')
    await page.getByRole('button', { name: 'Skip and finish' }).click()
    await expect(h1(page)).toBeVisible()
    await expect(page).toHaveURL(/\/$/)

    // scope reached the inventory module
    const inv = await page.evaluate(async () => (await (await fetch('/api/v1/inventory/settings')).json()) as { lan_ranges: string[]; active: { enabled: boolean } })
    expect(inv.lan_ranges).toEqual(['192.168.18.0/25', '10.1.0.0/16'])
    expect(inv.active.enabled).toBe(true)

    // every sidebar page is empty: no trace of sample data
    const hrefs = await page.locator('nav[aria-label] a').evaluateAll((as) => as.map((a) => (a as HTMLAnchorElement).getAttribute('href')!))
    const SAMPLE_DATA = /Sample Company|acme\.example|192\.168\.10\.|FortiGate 60F|QNAP|Synology|Sample data|a-nas/i
    const leaks: string[] = []
    for (const h of [...new Set(hrefs)]) {
      await page.goto(h)
      await expect(h1(page)).toBeVisible()
      await page.waitForTimeout(500)
      const txt = await page.locator('main').innerText()
      const m = txt.match(SAMPLE_DATA)
      if (m) leaks.push(`${h}: "${m[0]}"`)
      await noVietnamese(page, h)
      await shot(page, 'core', `clean${h.replace(/\//g, '_') || '_home'}`)
    }
    console.log('CLEAN LEAKS:\n' + (leaks.join('\n') || '(none)'))
    noErrors(errors)
  })
})

test.describe('sign-in and two-step', () => {
  test('wrong password, Enter submits, lands on the next page', async ({ page }) => {
    const errors = collectErrors(page)
    await startSample(page)
    await logoutApi(page)
    await page.goto('/settings/audit')
    await expect(page).toHaveURL(/\/login\?next=%2Fsettings%2Faudit/)
    await expectAccessible(page, 'login')
    await noVietnamese(page, 'login')
    await shot(page, 'core', 'login')
    await page.getByLabel('Email').fill(SAMPLE.admin)
    await page.getByLabel('Password').fill('wrong-password')
    await page.getByLabel('Password').press('Enter')
    await expect(page.getByText('Wrong email or password.')).toBeVisible()
    await expect(page.getByLabel('Email')).toHaveValue(SAMPLE.admin)
    await page.getByLabel('Password').fill(SAMPLE.password)
    await page.getByLabel('Password').press('Enter')
    await expect(page).toHaveURL(/\/settings\/audit/)
    await expect(h1(page)).toBeVisible()
    noErrors(errors)
  })

  test('two-step turns on to the standard, signs in with a code, turns off', async ({ page }) => {
    test.setTimeout(120_000)
    await startSample(page)
    await page.goto('/account')
    // D-76: turning two-step on needs the current password, as turning it off does
    await page.getByLabel('Your current password').fill('wrong')
    await page.getByRole('button', { name: 'Set up authenticator app' }).click()
    await expect(page.getByText(/The password is needed to turn on two-step sign-in/)).toBeVisible()
    await page.getByLabel('Your current password').fill(SAMPLE.password)
    await page.getByRole('button', { name: 'Set up authenticator app' }).click()
    const key = (await page.getByLabel('Manual key').innerText()).trim()
    const uri = (await page.getByLabel('otpauth address').innerText()).trim()
    expect(key).toMatch(/^[A-Z2-7]{32}$/)
    // Google Authenticator key-uri: otpauth://totp/Issuer:account?secret=&issuer=&algorithm=&digits=&period=
    const u = new URL(uri)
    expect(u.protocol).toBe('otpauth:')
    expect(u.host).toBe('totp')
    expect(decodeURIComponent(u.pathname)).toBe(`/Vedette:${SAMPLE.admin}`)
    expect(u.searchParams.get('secret')).toBe(key)
    expect(u.searchParams.get('issuer')).toBe('Vedette')
    expect(u.searchParams.get('digits')).toBe('6')
    expect(u.searchParams.get('period')).toBe('30')
    expect(u.searchParams.get('algorithm')).toBe('SHA1')
    await shot(page, 'core', 'account-2fa-setup')
    await page.getByLabel('6-digit code').fill('12')
    await page.getByRole('button', { name: 'Confirm and turn on' }).click()
    await expect(page.getByText(/The code is 6 digits/)).toBeVisible()
    await page.getByLabel('6-digit code').fill('000000')
    await page.getByLabel('6-digit code').press('Enter')
    await expect(page.getByText(/Wrong code/)).toBeVisible()
    await page.getByLabel('6-digit code').fill(totp(key))
    await page.getByRole('button', { name: 'Confirm and turn on' }).click()
    await expect(page.getByText('Two-step sign-in is on.').first()).toBeVisible()
    await page.reload()
    await expect(page.getByRole('button', { name: 'Turn off two-step sign-in' })).toBeVisible()
    await logoutApi(page)
    await page.goto('/login')
    await page.getByLabel('Email').fill(SAMPLE.admin)
    await page.getByLabel('Password').fill(SAMPLE.password)
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByLabel('6-digit code')).toBeFocused()
    await shot(page, 'core', 'login-code')
    await page.getByLabel('6-digit code').fill('111111')
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page.getByText(/Wrong code/)).toBeVisible()
    await page.getByLabel('6-digit code').fill(totp(key).replace(/(\d{3})(\d{3})/, '$1 $2'))
    await page.getByRole('button', { name: 'Sign in' }).click()
    await expect(page).toHaveURL(/\/$/)
    await page.goto('/account')
    await page.getByRole('button', { name: 'Turn off two-step sign-in' }).click()
    await page.getByRole('dialog').getByLabel('Current password').fill('wrong')
    await page.getByRole('button', { name: 'Turn off', exact: true }).click()
    await expect(page.getByText(/Wrong password/)).toBeVisible()
    await page.getByRole('dialog').getByLabel('Current password').fill(SAMPLE.password)
    await page.getByRole('button', { name: 'Turn off', exact: true }).click()
    await expect(page.getByText('Two-step sign-in is off.').first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Set up authenticator app' })).toBeVisible()
  })
})

test.describe('users and roles', () => {
  test('invite, change role, disable, last-admin protection', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/settings/users')
    await expect(h1(page)).toContainText('1 active users')
    await shot(page, 'core', 'users-clean')
    const vis = { visible: true }
    await expect(page.getByRole('button', { name: /Disable Alex Admin/ }).filter(vis)).toBeDisabled()
    await page.getByLabel('Role of Alex Admin').filter(vis).selectOption('viewer')
    await expect(page.getByText(/At least one active administrator who signs in with a password must remain/).first()).toBeVisible()
    await expect(page.getByLabel('Role of Alex Admin').filter(vis)).toHaveValue('admin')
    await page.getByRole('button', { name: 'Add user' }).click()
    await page.getByRole('button', { name: 'Create account' }).click()
    await expect(page.getByText("Enter the user's name.")).toBeVisible()
    await expect(page.getByText(/The email does not look right/)).toBeVisible()
    await page.getByLabel('Display name').fill('Lan IT')
    await page.getByLabel('Sign-in email').fill('lan@example.test')
    await page.getByLabel('Role', { exact: true }).selectOption('operator')
    await page.getByLabel('Sign-in email').press('Enter')
    await expect(page.getByRole('dialog', { name: 'Account created' })).toBeVisible()
    const temp = (await page.getByLabel('Temporary password').innerText()).trim()
    expect(temp.length).toBeGreaterThan(10)
    await page.getByRole('button', { name: 'I have copied it' }).click()
    await expect(page.getByText('lan@example.test').filter(vis)).toBeVisible()
    await page.getByRole('button', { name: 'Add user' }).click()
    await page.getByLabel('Display name').fill('Lan 2')
    await page.getByLabel('Sign-in email').fill('LAN@example.test')
    await page.getByRole('button', { name: 'Create account' }).click()
    await expect(page.getByText('This email already has an account.')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await logoutApi(page)
    await login(page, 'lan@example.test', temp)
    // D-180: a password an administrator set is changed at the first sign-in
    const lanPw = 'lan-chose-this-one-2026'
    await expect(page.getByRole('heading', { name: 'Choose a new password' })).toBeVisible()
    await page.getByLabel('Temporary password').fill(temp)
    await page.getByLabel('New password', { exact: true }).fill(lanPw)
    await page.getByLabel('Repeat new password').fill(lanPw)
    await page.getByRole('button', { name: 'Save and continue' }).click()
    await expect(h1(page)).not.toHaveText('Choose a new password')
    await page.goto('/settings/users')
    await expect(page.getByText(/needs a higher role/)).toBeVisible()
    await logoutApi(page)
    await login(page, LOGIN.email, LOGIN.password)
    await page.goto('/settings/users')
    await page.getByLabel('Role of Lan IT').filter(vis).selectOption('admin')
    await toastText(page, /Saved/)
    await page.getByRole('button', { name: 'Disable Lan IT' }).filter(vis).click()
    await expect(page.getByText('Disabled').filter(vis).first()).toBeVisible()
    await logoutApi(page)
    await login(page, 'lan@example.test', lanPw) // the right password: a disabled account still cannot sign in
    await expect(page.getByText('Wrong email or password.')).toBeVisible()
    await login(page, LOGIN.email, LOGIN.password)
    await page.goto('/settings/users')
    await page.getByRole('button', { name: 'Enable Lan IT again' }).filter(vis).click()
    await page.getByRole('button', { name: 'Reset password of Lan IT' }).filter(vis).click()
    await page.getByRole('button', { name: 'Cancel' }).click()
    await page.getByRole('button', { name: 'Reset password of Lan IT' }).filter(vis).click()
    await page.getByRole('button', { name: 'Reset', exact: true }).click()
    await expect(page.getByRole('dialog', { name: 'Password reset' })).toBeVisible()
    await page.getByRole('button', { name: 'I have copied it' }).click()
    await page.goto('/settings/audit')
    await expect(page.getByText('Create user').filter(vis).first()).toBeVisible()
    await expect(page.getByText('Change role').filter(vis).first()).toBeVisible()
    await expect(page.getByText('Reset password').filter(vis).first()).toBeVisible()
    await noVietnamese(page, 'audit')
    noErrors(errors)
  })
})

test.describe('modules', () => {
  test('toggle, dependencies, sidebar effects', async ({ page, isMobile }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    await cleanInstall(page, /Small business/)
    await page.goto('/settings/modules')
    await expect(h1(page)).toContainText('modules are on')
    await shot(page, 'core', 'modules')
    const nav = page.locator('nav[aria-label]').first()
    // no multi-site module anywhere
    await expect(page.getByRole('switch', { name: /Multi-site/ })).toHaveCount(0)
    await expect(nav.getByRole('link', { name: 'Multi-site' })).toHaveCount(0)
    // Credentialed scan needs Vulnerability scan (off in the small bundle): ask to turn on together
    await page.getByRole('switch', { name: /Turn (on|off) module Credentialed scan/ }).click()
    const dlg = page.getByRole('dialog', { name: 'Turn on the required modules too?' })
    await expect(dlg).toBeVisible()
    await expect(dlg.getByText('Vulnerability scan')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Credentialed scan/ })).not.toBeChecked()
    await page.getByRole('switch', { name: /Turn (on|off) module Credentialed scan/ }).click()
    await dlg.getByRole('button', { name: 'Turn on together' }).click()
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Vulnerability scan/ })).toBeChecked()
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Credentialed scan/ })).toBeChecked()
    if (!isMobile) await expect(nav.getByRole('link', { name: 'Vulnerability scans' })).toBeVisible() // on a phone the sidebar is behind the menu button
    await page.getByRole('switch', { name: /Turn (on|off) module Vulnerability scan/ }).click()
    const off = page.getByRole('dialog', { name: 'Turn off Vulnerability scan?' })
    await expect(off.getByText('Credentialed scan')).toBeVisible()
    await off.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Vulnerability scan/ })).toBeChecked()
    await page.getByRole('switch', { name: /Turn (on|off) module Vulnerability scan/ }).click()
    await off.getByRole('button', { name: 'Turn off', exact: true }).click()
    if (!isMobile) await expect(nav.getByRole('link', { name: 'Vulnerability scans' })).toHaveCount(0)
    await page.goto('/scans')
    await expect(page.getByText(/is off|off\b/i).first()).toBeVisible()
    await shot(page, 'core', 'module-off-page')
    await page.goto('/settings/modules')
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Core/ })).toBeDisabled()
    await page.reload()
    await expect(page.getByRole('switch', { name: /Turn (on|off) module Credentialed scan/ })).toBeChecked()
    noErrors(errors)
  })
})

test.describe('updates', () => {
  test('check, update, roll back, bad and good bundles', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/settings/updates')
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.3( |$)/)
    await shot(page, 'core', 'updates')
    await expect(page.getByText('No updates yet.')).toBeVisible()
    await expect(page.getByRole('button', { name: /^Back to / })).toHaveCount(0)
    await expect(page.getByRole('alert').filter({ hasText: 'known vulnerabilities' })).toBeVisible()
    await page.getByRole('button', { name: 'Check for Vedette releases' }).click()
    await toastText(page, /new items/)
    await page.getByRole('button', { name: /^Update Vedette software$/ }).click()
    await expect(page.getByRole('heading', { name: 'Updating Vedette software to 0.9.4' })).toBeVisible()
    await shot(page, 'core', 'updates-run')
    await toastText(page, /installed in the spare slot/)
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.4( |$)/)
    await expect(page.getByRole('alert').filter({ hasText: 'known vulnerabilities' })).toHaveCount(0)
    await page.getByRole('button', { name: /Back to 0\.9\.3/ }).click()
    await page.getByRole('button', { name: 'Cancel' }).click()
    await page.getByRole('button', { name: /Back to 0\.9\.3/ }).click()
    // 0.9.4 changed the database (D-340): the rollback puts back the old one, so it needs the box ticked
    await expect(page.getByRole('dialog')).toContainText('Data written since the update is lost.')
    await expect(page.getByRole('button', { name: 'Roll back', exact: true })).toBeDisabled()
    await expectAccessible(page, 'updates rollback that restores data')
    await shot(page, 'core', 'updates-rollback-data-loss')
    await page.getByRole('checkbox', { name: 'I understand that data written since the update is lost.' }).click()
    await page.getByRole('button', { name: 'Roll back', exact: true }).click()
    await toastText(page, /rolled back/)
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.3( |$)/)
    const dl = page.waitForEvent('download')
    await page.getByRole('button', { name: 'Export bundle' }).click()
    const fs = await import('node:fs')
    const good = fs.readFileSync((await (await dl).path())!, 'utf8')
    const bad = good.replace(/mock-sig-[0-9a-f]{8}/, 'mock-sig-00000000')
    await page.getByLabel('Bundle file').setInputFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(bad) })
    await toastText(page, /Invalid signature/)
    await page.getByLabel('Bundle file').setInputFiles({ name: 'junk.json', mimeType: 'application/json', buffer: Buffer.from('not json at all') })
    await toastText(page, /not a Vedette bundle/)
    await page.getByLabel('Bundle file').setInputFiles({ name: 'good.json', mimeType: 'application/json', buffer: Buffer.from(good) })
    await toastText(page, /Bundle imported/)
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.4( |$)/)
    await page.getByRole('button', { name: 'Beta' }).click()
    await expect(page.getByText(/Get new builds early/)).toBeVisible()
    await page.getByRole('button', { name: 'Stable' }).click()
    await page.goto('/settings/privacy')
    const updateCheck = page.getByRole('switch', { name: 'Automatic update check' })
    await expect(updateCheck).toBeChecked()
    await updateCheck.click()
    await expect(updateCheck).not.toBeChecked() // the save landed; leaving earlier cancelled it (the old flake)
    await page.goto('/settings/updates')
    await expect(page.getByText(/Update checks are off/)).toBeVisible()
    await page.getByRole('button', { name: 'Check for Vedette releases' }).click()
    await toastText(page, /off under Privacy/)
    await noVietnamese(page, 'updates')
    noErrors(errors)
  })
})

// S-CORE-2 criterion D-316: the system helper is the first step of the software run. The mock's outcome is set in its store (no button).
test.describe('updates: system helper (D-316)', () => {
  test.skip(({ isMobile }) => isMobile, 'desktop only')
  const helperRow = (page: Page) => page.locator('#vedette tbody tr').filter({ hasText: /^System helper/ })
  async function updateWith(page: Page, code: string | null) {
    // Before the app's code on every load: a patch written while the app runs is lost when the mock saves its own copy.
    await page.addInitScript((c) => {
      const k = 'vedette-mock-db-v4'
      const db = JSON.parse(localStorage.getItem(k) ?? '{}')
      db.core_updates_host_scenario = { code: c, version: null }
      localStorage.setItem(k, JSON.stringify(db))
    }, code)
    await startSample(page)
    await page.goto('/settings/updates')
    await expect(page.getByText('Includes system helper 0.9.4.')).toBeVisible()
    await expect(helperRow(page)).toContainText('Updated together with Vedette. If a new version does not start, the box goes back to the one before by itself.')
    await expect(helperRow(page).getByRole('button')).toHaveCount(0)
    await page.getByRole('button', { name: /^Update Vedette software$/ }).click()
    await expect(page.getByText('Step 1 of 4: update the system helper')).toBeVisible()
    await expect(page.getByText('Updating the system helper. Vedette keeps running; settings that need the helper may not answer for up to a minute.')).toBeVisible()
    await expect(page.getByRole('button', { name: /^Back to .*Vedette software/ })).toBeDisabled()
  }

  test('success: the helper is updated first, then the images', async ({ page }) => {
    const errors = collectErrors(page)
    await updateWith(page, null)
    await expect(helperRow(page)).toContainText('0.9.4')
    await toastText(page, /installed in the spare slot/)
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.4( |$)/)
    await expect(page.locator('#vedette').getByRole('table', { name: 'Update history' })).toContainText(/System helper.*Update.*0\.9\.3 > 0\.9\.4/)
    noErrors(errors)
  })

  test('the new helper does not start: the run went back, nothing else changed', async ({ page }) => {
    const errors = collectErrors(page)
    await updateWith(page, 'self_update_unhealthy')
    const why = 'The new system helper 0.9.4 did not start correctly, so the box went back to 0.9.3 by itself. Nothing else was changed.'
    await expect(page.getByRole('heading', { name: 'Update to 0.9.4 did not start; back on 0.9.3' })).toBeVisible()
    await expect(page.locator('#vedette').getByText(why, { exact: true })).toBeVisible()
    await expect(helperRow(page)).toContainText('0.9.3')
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.3( |$)/)
    await expect(page.getByRole('button', { name: /^Update Vedette software$/ })).toBeEnabled()
    noErrors(errors)
  })

  test('refused (bad signature): failed, nothing installed', async ({ page }) => {
    const errors = collectErrors(page)
    await updateWith(page, 'signature_invalid')
    await expect(page.getByRole('heading', { name: 'Update of Vedette software to 0.9.4 failed' })).toBeVisible()
    await expect(page.locator('#vedette').getByText('The system helper in this update is not signed by the Vedette release key. Nothing was installed.', { exact: true })).toBeVisible()
    await expect(helperRow(page)).toContainText('0.9.3')
    await expect(softwareVersion(page)).toHaveText(/^0\.9\.3( |$)/)
    noErrors(errors)
  })
})

test.describe('privacy', () => {
  test('14 flows, anonymous signal shown as not sent (D-153)', async ({ page, isMobile }) => {
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/settings/privacy')
    await expect(h1(page)).toContainText('connects out only for the flows listed below')
    await expectAccessible(page, 'privacy')
    // table on desktop, list on a phone
    await expect(isMobile ? page.getByRole('list', { name: 'Data flows that leave the box' }).getByRole('listitem') : page.getByRole('table', { name: 'Data flows that leave the box' }).locator('tbody tr')).toHaveCount(14)
    await expect(page.getByText(/Anonymous signal: not sent\./)).toBeVisible()
    await shot(page, 'core', 'privacy')
    await expect(page.getByRole('switch', { name: 'Send anonymous signal' })).toHaveCount(0)
    await expect(page.getByLabel('JSON, exactly what would be sent')).toHaveCount(0)
    await noVietnamese(page, 'privacy')
    noErrors(errors)
  })
})

test.describe('MCP server', () => {
  test('turn on, token shown once, revoke', async ({ page }) => {
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/settings/mcp')
    await expect(h1(page)).toContainText('MCP server is off')
    await page.getByRole('switch', { name: /Turn (on|off) MCP server/ }).click()
    await expect(h1(page)).toContainText('0 tokens')
    // client snippet follows the Claude Code MCP docs (type http)
    await expect(page.getByLabel('Config for the MCP tool')).toContainText('"type": "http"')
    await page.getByRole('button', { name: 'Create token' }).click()
    await expect(page.getByText('Name the token so you know which one to revoke later.')).toBeVisible()
    await page.getByLabel('Token name').fill("Nam's Claude")
    for (const i of [0, 1, 2]) await page.getByRole('checkbox').nth(i).uncheck()
    await page.getByRole('button', { name: 'Create token' }).click()
    await expect(page.getByText('Pick at least one scope.')).toBeVisible()
    await page.getByRole('checkbox').nth(1).check()
    await page.getByLabel('Token name').press('Enter')
    const dlg = page.getByRole('dialog', { name: /Token .* created/ })
    const token = (await dlg.getByLabel('Token', { exact: true }).innerText()).trim()
    expect(token).toMatch(/^vmcp_[0-9a-f]{32}$/)
    await dlg.getByRole('button', { name: 'I have copied it' }).click()
    await expect(page.getByRole('cell', { name: `…${token.slice(-4)}` })).toBeVisible()
    await page.reload()
    await expect(page.locator('body')).not.toContainText(token)
    await page.getByRole('button', { name: "Revoke token Nam's Claude" }).click()
    await page.getByRole('dialog', { name: "Revoke token Nam's Claude?" }).getByRole('button', { name: 'Revoke' }).click()
    await expect(page.getByText(/No tokens yet/)).toBeVisible()
    await noVietnamese(page, 'mcp')
    noErrors(errors)
  })
})

test.describe('data', () => {
  test('backup, export, delete everything needs the exact name', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/settings/data')
    const fs = await import('node:fs')
    for (const [name, fmt] of [['Download backup', 'vedette-backup/1'], ['Export JSON', 'vedette-export/1']] as const) {
      const dl = page.waitForEvent('download')
      await page.getByRole('button', { name, exact: true }).click()
      const body = JSON.parse(fs.readFileSync((await (await dl).path())!, 'utf8')) as Record<string, unknown>
      expect(body.format).toBe(fmt)
      expect(JSON.stringify(body)).not.toContain(PW)
      // a clean install holds no sample data; the box itself is the one asset (D-53 item 4)
      expect((body.assets as { id: string }[]).map((a) => a.id)).toEqual(['a-box'])
    }
    await page.getByRole('button', { name: 'Delete all data', exact: true }).click()
    const dlg = page.getByRole('dialog', { name: 'Delete all data on the box?' })
    const go = dlg.getByRole('button', { name: 'Delete everything' })
    await expect(go).toBeDisabled()
    await dlg.getByLabel(/Type the organization name/).fill('test company')
    await expect(go).toBeDisabled()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await page.getByRole('button', { name: 'Delete all data', exact: true }).click()
    await dlg.getByLabel(/Type the organization name/).fill('Test Company')
    await dlg.getByLabel(/Type the organization name/).press('Enter') // Enter alone must not delete
    await expect(dlg).toBeVisible()
    // D-154: the box says exactly what goes and what stays, and wants the current password as well as the name
    await expect(dlg).toContainText('Deleted: all data, users and backups')
    await expect(dlg).toContainText('The decryption key is replaced')
    await expect(dlg).toContainText('Kept: the TLS certificate, the system journal')
    await expect(go).toBeDisabled() // right name, no password yet
    await dlg.getByLabel('Your current password').fill('not the password')
    await go.click()
    await expect(dlg).toContainText('The password is needed to delete all data')
    await expect(dlg).toBeVisible()
    await dlg.getByLabel('Your current password').fill(PW)
    await go.click()
    // what stays on the box is said before the page leaves (the honeypot's raw log)
    const done = page.getByRole('dialog', { name: 'All data deleted' })
    await expect(done).toContainText("honeypot's raw log")
    await done.getByRole('button', { name: 'Continue to setup' }).click()
    await expect(page).toHaveURL(/\/setup/)
    await expect(page.getByRole('heading', { level: 1, name: 'First-time Vedette setup' })).toBeVisible()
    await login(page, LOGIN.email, LOGIN.password)
    await expect(page).toHaveURL(/\/setup|\/login/)
    await page.goto('/setup')
    await page.getByRole('button', { name: 'Use sample data' }).click()
    await expect(h1(page)).toContainText('Today')
    await page.goto('/devices')
    // the box itself is a sample device too (D-53 item 4): 31 + 1
    await expect(h1(page)).toContainText('32 devices')
    await page.goto('/settings/data')
    await page.getByRole('button', { name: 'Restore sample data', exact: true }).click()
    await page.getByRole('button', { name: 'Restore and reload' }).click()
    await expect(h1(page)).toBeVisible()
    await expect(page).toHaveURL(/\/settings\/data|\/$/)
    noErrors(errors)
  })
})

const SECTIONS = ['general', 'modules', 'users', 'audit', 'updates', 'privacy', 'mcp', 'data'] as const

test.describe('viewer and operator roles', () => {
  for (const [email, role] of [[SAMPLE.viewer, 'viewer'], [SAMPLE.operator, 'operator']] as const) {
    test(`${role}: each section is read-only or says which role it needs`, async ({ page }) => {
      test.setTimeout(150_000)
      const errors = collectErrors(page)
      await sampleAs(page, email)
      const adminOnly = ['users', 'audit', 'mcp', 'data']
      const label: Record<string, string> = { users: 'Users', audit: 'Audit log', mcp: 'MCP server', data: 'Data' }
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
        if (role === 'viewer') await shot(page, 'core', `role-viewer-${sec}`)
      }
      await page.goto('/settings/updates')
      const check = page.getByRole('button', { name: 'Check now' })
      if (role === 'viewer') await expect(check).toBeDisabled(); else await expect(check).toBeEnabled()
      await expect(page.getByRole('button', { name: 'Import bundle' })).toBeDisabled()
      await expect(page.getByRole('button', { name: /^Back to / }).first()).toBeDisabled()
      await expect(page.getByRole('button', { name: 'Beta' })).toBeDisabled()
      await page.goto('/account')
      await expect(h1(page)).toContainText("'s account")
      await page.getByLabel('Display name').fill(`${role} renamed`)
      await page.getByRole('button', { name: 'Save' }).click()
      await toastText(page, /Saved/)
      expect(await page.evaluate(async () => (await fetch('/api/v1/core/users')).status)).toBe(403)
      noErrors(errors, /403/)
    })
  }

  test('unknown settings section and the settings index', async ({ page }) => {
    await sampleAs(page, SAMPLE.viewer)
    await page.goto('/settings/nothing-here')
    await expect(page.getByText('No such settings section')).toBeVisible()
    await page.goto('/settings')
    await expect(page).toHaveURL(/\/settings\/general/)
  })
})

// ---------- giao diện: điện thoại/máy tính, sáng/tối ----------
const SCREENS = ['/settings/general', '/settings/modules', '/settings/users', '/settings/audit', '/settings/updates', '/settings/privacy', '/settings/mcp', '/settings/data', '/account']

test.describe('look and feel', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`${scheme}: no sideways scroll, no raw i18n keys, no Vietnamese, axe clean`, async ({ page }, info) => {
      test.setTimeout(240_000)
      const errors = collectErrors(page)
      await page.emulateMedia({ colorScheme: scheme })
      await startSample(page)
      await page.evaluate((s) => localStorage.setItem('vedette-theme', s), scheme)
      const problems: string[] = []
      for (const path of SCREENS) {
        await page.goto(path)
        await expect(h1(page)).toBeVisible()
        await page.waitForTimeout(400)
        const r = await page.evaluate(() => ({ over: document.documentElement.scrollWidth - window.innerWidth, text: document.querySelector('main')?.innerText ?? '' }))
        if (r.over > 1) problems.push(`${path}: sideways overflow ${r.over}px`)
        const RAW = /\b(core|common|feeds|inventory|notify|findings|scan|exposure|honeypot|logs|ai|reports):[a-zA-Z]+\./
        if (RAW.test(r.text)) problems.push(`${path}: raw i18n key ${r.text.match(RAW)![0]}`)
        const left = r.text.split('\n').filter((l) => VI.test(l) && !ALLOWED_VI.test(l))
        if (left.length) problems.push(`${path}: Vietnamese text: ${left.slice(0, 3).join(' | ')}`)
        for (const v of await axeViolations(page)) problems.push(`${path}: ${v}`)
        await shot(page, 'core', `${info.project.name}-${scheme}${path.replace(/\//g, '_')}`)
      }
      console.log(`PROBLEMS ${info.project.name} ${scheme}:\n` + (problems.join('\n') || '(none)'))
      expect(problems, problems.join('\n')).toEqual([])
      noErrors(errors)
    })
  }

  test('setup and sign-in on a phone, keyboard order', async ({ page }, info) => {
    await page.goto('/')
    await page.evaluate(() => localStorage.clear())
    await page.goto('/setup')
    await shot(page, 'core', `${info.project.name}-setup`)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
    await page.getByLabel('Organization name').focus()
    await page.keyboard.press('Tab'); await expect(page.getByLabel('Administrator name')).toBeFocused()
    await page.keyboard.press('Tab'); await expect(page.getByLabel('Sign-in email')).toBeFocused()
    await page.keyboard.press('Tab'); await expect(page.getByLabel('Password', { exact: true })).toBeFocused()
    await page.keyboard.press('Tab'); await expect(page.getByLabel('Repeat password')).toBeFocused()
    await expect(page.getByRole('button', { name: 'Back' })).toBeDisabled() // a disabled button is skipped by Tab
    await page.keyboard.press('Tab'); await expect(page.getByRole('button', { name: 'Continue' })).toBeFocused()
    // network step on a phone: rows fit, no sideways scroll
    await startClean(page)
    await next(page)
    await page.getByRole('button', { name: 'Add range' }).click()
    await shot(page, 'core', `${info.project.name}-setup-network`)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
    await startSample(page)
    await logoutApi(page)
    await page.goto('/login')
    await shot(page, 'core', `${info.project.name}-login`)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)).toBeLessThanOrEqual(1)
  })
})
