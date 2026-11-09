import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'

// QA như người dùng thật cho module notify (S-ALERT-1, S-NOT-1). Giao diện chỉ có tiếng Anh (D-28). Mỗi test tự dựng dữ liệu, không phụ thuộc thứ tự.
// Không có tin gộp nhiều site/MSP (quyết định của chủ dự án).
// Máy dev dùng chung với agent khác (HMR có thể tải lại trang giữa chừng): cho thử lại một lần.
test.describe.configure({ retries: 1 })
const VI = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i
const TOKEN = '123456789:EXAMPLE_not_a_real_token_0000000000'

async function resetStorage(page: Page) {
  for (let i = 0; i < 3; i++) {
    try {
      await page.goto('/setup')
      await page.waitForLoadState('load')
      await page.evaluate(() => localStorage.clear())
      await page.goto('/setup')
      return
    } catch (e) {
      if (i === 2) throw e
    }
  }
}
async function startWithSample(page: Page) {
  await resetStorage(page)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
async function cleanInstall(page: Page) {
  await resetStorage(page)
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Test Admin')
  await page.getByLabel('Sign-in email').fill('admin@test-company.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password').fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('textbox', { name: 'Range 1' }).fill('192.168.10.0/24')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Skip and finish' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
/** Đổi phiên mock sang tài khoản khác (u-view = chỉ xem; u-op = vận hành). */
async function asUser(page: Page, userId: string) {
  await page.evaluate((u) => {
    const k = 'vedette-mock-db-v3'
    const db = JSON.parse(localStorage.getItem(k) ?? '{}')
    db.core_session = { userId: u }
    localStorage.setItem(k, JSON.stringify(db))
  }, userId)
  await page.reload()
}
const noHorizontalScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
const visible = (l: ReturnType<Page['locator']>) => l.locator('visible=true').first()

test.describe('notify: alerts (S-ALERT-1)', () => {
  test('list, filter by status and kind, open the detail, come back with Back', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/alerts')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('4 unhandled alerts')
    await page.getByRole('button', { name: 'All', exact: true }).click()
    await expect(visible(page.getByText('Microsoft Windows Server'))).toBeVisible()
    await page.getByRole('button', { name: 'Trap touches' }).click()
    await expect(page.getByText('QNAP Photo Station')).toHaveCount(0)
    await expect(visible(page.getByRole('link', { name: 'SMB trap on FILESRV-OLD' }))).toBeVisible()
    await page.getByRole('button', { name: 'Bad IPs, domains' }).click()
    await expect(visible(page.getByRole('link', { name: '185.220.101.47' }))).toBeVisible()
    await page.getByRole('button', { name: 'All kinds' }).click()
    await visible(page.getByRole('link', { name: 'QNAP Photo Station' })).click()
    await expect(page).toHaveURL(/\/alerts\/al-1/)
    await expect(page.getByRole('heading', { level: 1 })).toContainText('QNAP Photo Station is being exploited on')
    await page.goBack()
    await expect(page).toHaveURL(/\/alerts$/)
    await expect(page.getByRole('heading', { level: 1 })).toContainText('unhandled alerts')
    await noHorizontalScroll(page)
    expect(errors).toEqual([])
  })

  test('handle: note, mark handled, still handled after reload, reopen, mark not relevant', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/alerts/al-1')
    await page.getByLabel('Note (optional)').fill('Updated to version 5.2.1 at 9 am')
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await expect(page.getByText('Alert updated.').first()).toBeVisible()
    await expect(page.getByText(/Handled by admin@acme\.example/)).toBeVisible()
    await expect(page.getByText('Updated to version 5.2.1 at 9 am').first()).toBeVisible()
    await page.reload()
    await expect(page.getByText(/Handled by admin@acme\.example/)).toBeVisible()
    await page.goto('/alerts')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('3 unhandled alerts')
    await page.goto('/alerts/al-1')
    await page.getByRole('button', { name: 'Reopen' }).click()
    await expect(page.getByLabel('Note (optional)')).toBeVisible()
    await page.getByRole('button', { name: 'Mark as not relevant' }).click()
    await expect(page.getByText(/Not relevant by admin@acme\.example/)).toBeVisible()
    await expect(page.getByText(/does not change the finding status/)).toBeVisible()
    expect(errors).toEqual([])
  })

  test('detail for vulnerability, trap and bad-IP alerts: title, text sent per channel, link to the source', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/alerts/al-1')
    await expect(page.getByRole('tab', { name: 'Telegram' })).toBeVisible()
    await page.getByRole('tab', { name: 'Email' }).click()
    await expect(page.getByText(/Subject: \[Vedette\] Critical: QNAP Photo Station is being exploited/)).toBeVisible()
    await expect(page.getByRole('link', { name: 'View finding CVE-2022-27593' })).toHaveAttribute('href', '/findings/f-1')
    await page.goto('/alerts/al-4')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('just touched: SMB trap on FILESRV-OLD')
    await expect(page.getByRole('link', { name: 'Open trap touch' })).toHaveAttribute('href', '/honeypot/hits/hit-seed-1')
    await expect(page.getByText('Machine that touched the trap:').first()).toBeVisible()
    await page.goto('/alerts/al-6')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('just connected to 185.220.101.47')
    await expect(page.getByRole('link', { name: 'Open related logs' })).toHaveAttribute('href', '/logs')
    await expect(page.getByText('Machine that made the connection:').first()).toBeVisible()
    await expectAccessible(page, 'bad-IP alert detail')
    await page.getByRole('link', { name: 'PC-SALES-02' }).first().click()
    await expect(page).toHaveURL(/\/devices\/a-pc05/)
  })

  test('send again on a failed channel: the email channel works, so it succeeds', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/alerts/al-2')
    await expect(page.getByText(/The SMTP server rejected the login/)).toBeVisible()
    await page.getByRole('button', { name: 'Send again via Email' }).click()
    await expect(page.getByText('Sent again via Email.').first()).toBeVisible()
    expect(errors).toEqual([])
  })

  test('send again after the channel was removed: the error says how to fix it', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: /Remove channel Email/ }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click()
    await expect(page.getByText('Channel Email and its saved key were removed.').first()).toBeVisible()
    await page.goto('/alerts/al-2')
    await page.getByRole('button', { name: 'Send again via Email' }).click()
    await expect(page.getByText(/not set up or is turned off/).first()).toBeVisible()
  })

  test('unknown alert says so; a viewer sees locked buttons with a reason', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/alerts/no-such-alert')
    await expect(page.getByText(/No such alert/).first()).toBeVisible()
    await asUser(page, 'u-view')
    await page.goto('/alerts/al-1')
    const b = page.getByRole('button', { name: 'Mark as handled' })
    await expect(b).toBeDisabled()
    await expect(b).toHaveAttribute('title', /Operator/)
  })
})

test.describe('notify: alert channels (S-NOT-1)', () => {
  test('Telegram: wrong input points at the right field, right input saves and tests, still there after reload, secret shows only 4 characters', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Edit Telegram' }).click()
    const d = page.getByRole('dialog')
    await expect(d.getByText(/Saved, ending in/)).toBeVisible()
    await expect(d.getByText(/getUpdates/)).toBeVisible()
    await d.getByLabel('Chat ID').fill('abc')
    await d.getByLabel('Chat ID').press('Enter')
    await expect(d.getByRole('alert')).toContainText('Chat ID is a number')
    await expect(d.getByLabel('Chat ID')).toHaveValue('abc')
    await d.getByLabel('Chat ID').fill('-1001234567890')
    await d.getByLabel('Bot token').fill('not-a-token')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('A bot token looks like')
    await d.getByLabel('Bot token').fill(TOKEN)
    await d.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText(/Telegram received the test message \(chat -1001234567890\)/).first()).toBeVisible()
    await page.reload()
    await expect(visible(page.getByText('Chat -1001234567890'))).toBeVisible()
    await expect(page.locator('body')).not.toContainText(TOKEN)
    expect(errors).toEqual([])
  })

  test('Telegram: a rejected token makes the test fail with advice', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Edit Telegram' }).click()
    const d = page.getByRole('dialog')
    await d.getByLabel('Bot token').fill('123456789:invalid_EXAMPLE_not_a_real_token')
    await d.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText(/401 Unauthorized: the bot token is wrong/).first()).toBeVisible()
    await expect(visible(page.getByText(/Tested .*: failed/))).toBeVisible()
  })

  test('Zalo OA: needs OA ID, recipient and access token; each missing piece is reported at its field', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Set up Zalo OA' }).click()
    const d = page.getByRole('dialog')
    await d.getByLabel('OA ID').fill('12345')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('OA ID is a string of digits')
    await d.getByLabel('OA ID').fill('1234567890')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('user_id')
    await d.getByLabel('Recipient ID (user_id)').fill('2468013579')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('access token')
    await d.getByLabel('Access token').fill('zalo-access-token-0123456789abcdef')
    await d.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText(/Zalo OA 1234567890 sent the test message to recipient 2468013579/).first()).toBeVisible()
  })

  test('Email: encryption changes the port, a wrong port/encryption pair is refused, an unreachable server fails the test', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Edit Email' }).click()
    const d = page.getByRole('dialog')
    await d.getByLabel('Encryption').selectOption('ssl')
    await expect(d.getByLabel('Port')).toHaveValue('465')
    await d.getByLabel('Encryption').selectOption('starttls')
    await expect(d.getByLabel('Port')).toHaveValue('587')
    await d.getByLabel('Port').fill('465')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('Port 465 uses SSL/TLS')
    await d.getByLabel('Port').fill('587')
    await d.getByLabel('Send to').fill('it@acme.example, not-an-email')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('A recipient email is not valid')
    await d.getByLabel('Send to').fill('it@acme.example; director@acme.example')
    await d.getByLabel('SMTP server').fill('smtp.no-such-host.invalid')
    await d.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText(/Could not connect to smtp\.no-such-host\.invalid/).first()).toBeVisible()
    await expect(page.getByText(/it@acme\.example, director@acme\.example/).first()).toBeVisible()
  })

  test('Webhook: a new channel needs a signing key, a bad URL is refused, random key works', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Set up Webhook' }).click()
    const d = page.getByRole('dialog')
    await d.getByLabel('Webhook URL').fill('not a url')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('The webhook URL must start with https://')
    await d.getByLabel('Webhook URL').fill('https://hooks.company.com/vedette')
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(d.getByRole('alert')).toContainText('webhook signing key')
    await d.getByRole('button', { name: 'Generate random' }).click()
    await d.getByRole('button', { name: 'Save and send test' }).click()
    await expect(page.getByText('The webhook returned HTTP 200.').first()).toBeVisible()
  })

  test('removing a channel asks first and names the consequence; Cancel keeps it', async ({ page }) => {
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: /Remove channel Telegram/ }).click()
    await expect(page.getByRole('dialog')).toContainText('Future alerts will not be sent through it')
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByRole('button', { name: /Remove channel Telegram/ })).toBeVisible()
    await page.getByRole('button', { name: /Remove channel Telegram/ }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete' }).click()
    await expect(page.getByText('Channel Telegram and its saved key were removed.').first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Set up Telegram' })).toBeVisible()
  })

  test('quiet hours across midnight: summary is right, equal times are refused, saved values survive reload', async ({ page }) => {
    const errors = collectErrors(page)
    await startWithSample(page)
    await page.goto('/settings/channels')
    await expect(page.getByText('Quiet from 22:00 this evening until 06:30 the next morning.')).toBeVisible()
    await page.getByLabel('From').fill('08:00')
    await page.getByLabel('Until').fill('17:30')
    await expect(page.getByText('Quiet from 08:00 to 17:30 on the same day.')).toBeVisible()
    await page.getByLabel('Until').fill('08:00')
    await page.getByRole('button', { name: 'Save quiet hours and grouping' }).click()
    await expect(page.getByRole('alert')).toContainText('must not be the same')
    await page.getByLabel('Until').fill('23:15')
    await page.getByLabel('From').fill('23:00')
    await page.getByLabel('Group messages for the same product').click()
    await page.getByRole('button', { name: 'Save quiet hours and grouping' }).click()
    await expect(page.getByText('Quiet hours and grouping saved.').first()).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('From')).toHaveValue('23:00')
    await expect(page.getByLabel('Group messages for the same product')).not.toBeChecked()
    expect(errors).toEqual([])
  })

  test('an operator cannot manage channels', async ({ page }) => {
    await startWithSample(page)
    await asUser(page, 'u-op')
    await page.goto('/settings/channels')
    await expect(page.getByText('Alert channels needs a higher role')).toBeVisible()
    await expect(page.getByText(/Only the Admin role can open this section/)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Edit Telegram' })).toHaveCount(0)
  })
})

test.describe('notify: clean install', () => {
  test('alerts and channels say what to do first, with no sample data', async ({ page }) => {
    const errors = collectErrors(page)
    await cleanInstall(page)
    await page.goto('/alerts')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('No unhandled alerts')
    await expect(page.getByRole('link', { name: 'Set up alert channels' })).toBeVisible()
    await expect(page.locator('main')).not.toContainText(/QNAP|FILESRV-OLD|185\.220|NAS-PHOTOS/)
    await shot(page, 'notify', 'clean-alerts')
    await expectAccessible(page, 'alerts clean')
    await page.getByRole('link', { name: 'Set up alert channels' }).click()
    await expect(page).toHaveURL(/\/settings\/channels/)
    await expect(page.getByRole('button', { name: /^Set up (Telegram|Zalo OA|Email|Webhook)$/ })).toHaveCount(4)
    await expect(page.locator('main')).not.toContainText(/acme\.example|-1002145678901/)
    await shot(page, 'notify', 'clean-channels')
    await expectAccessible(page, 'channels clean')
    await page.getByRole('button', { name: 'Set up Telegram' }).click()
    const d = page.getByRole('dialog')
    await d.getByLabel('Chat ID').fill('-1001234567890')
    await d.getByLabel('Bot token').fill(TOKEN)
    await d.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Channel Telegram saved.').first()).toBeVisible()
    await page.goto('/alerts')
    await expect(page.getByText(/new vulnerabilit(y|ies) in the last 7 days/).first()).toBeVisible()
    expect(errors).toEqual([])
  })
})

test.describe('notify: look and feel', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`alerts, details and channels ${scheme}: no errors, no horizontal scroll, accessible, English only`, async ({ page }, info) => {
      const errors = collectErrors(page)
      await page.emulateMedia({ colorScheme: scheme })
      await startWithSample(page)
      for (const [name, path] of [['alerts', '/alerts'], ['detail-vuln', '/alerts/al-2'], ['detail-honeypot', '/alerts/al-4'], ['detail-ioc', '/alerts/al-6'], ['channels', '/settings/channels']] as const) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await noHorizontalScroll(page)
        await shot(page, 'notify', `${name}-${info.project.name}-${scheme}`)
        const text = await page.locator('main').innerText()
        expect(text, `${name}: raw i18n key`).not.toMatch(/\b(notify|common|logs):[a-zA-Z.]+/)
        expect(text, `${name}: Vietnamese text`).not.toMatch(VI)
        await expectAccessible(page, `${name} ${scheme}`)
      }
      expect(errors).toEqual([])
    })
  }

  test('phone: channel dialogs fit the screen and buttons are at least 30px tall', async ({ page, isMobile }) => {
    test.skip(!isMobile, 'phone only')
    await startWithSample(page)
    await page.goto('/settings/channels')
    await page.getByRole('button', { name: 'Edit Email' }).click()
    const box = await page.getByRole('dialog').boundingBox()
    expect(box!.x).toBeGreaterThanOrEqual(0)
    expect(box!.x + box!.width).toBeLessThanOrEqual(page.viewportSize()!.width + 1)
    for (const b of await page.getByRole('dialog').getByRole('button').all()) {
      const bb = await b.boundingBox()
      if (bb) expect(bb.height, await b.innerText()).toBeGreaterThanOrEqual(30)
    }
    await shot(page, 'notify', 'dialog-email-mobile')
  })
})
