// QA như người dùng thật cho module findings (D-23, UI chỉ tiếng Anh D-28): IT operator, director (viewer), first-time clean install.
// Spec độc lập, tự dựng dữ liệu; chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/findings.spec.ts
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'

const DB = 'vedette-mock-db-v3'
const DIACRITICS = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i

/** Cài đặt ban đầu bằng dữ liệu mẫu (bản local của helper: nhãn tiếng Anh). */
async function sample(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}
/** Cài sạch: tạo tổ chức + quản trị, một dải mạng, KHÔNG đánh dấu cam kết quét, bỏ qua kênh. */
async function clean(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Test Admin')
  await page.getByLabel('Sign-in email').fill('admin@test.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password').fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel(/^Range 1/).fill('10.20.0.0/24')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: /Skip and finish/ }).click()
  await expect(page).not.toHaveURL(/\/setup/)
}
/** Sửa thẳng kho mock trong trình duyệt (giả lập trạng thái hệ thống) rồi tải lại. */
async function patchDb(page: Page, patch: Record<string, unknown>) {
  await page.evaluate(([k, p]) => {
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    Object.assign(db, p)
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, patch] as const)
  await page.reload()
}
const loginAs = (page: Page, userId: 'u-admin' | 'u-op' | 'u-view') => patchDb(page, { core_session: { userId } })
async function theme(page: Page, t: 'light' | 'dark') {
  await page.evaluate((v) => localStorage.setItem('vedette-theme', v), t)
  await page.reload()
}
const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${where}: horizontal scroll`).toBeLessThanOrEqual(1)
const english = async (page: Page, where: string) => {
  const text = await page.evaluate(() => document.body.innerText)
  expect(text.match(DIACRITICS)?.[0] ?? null, `${where}: Vietnamese text left in the UI`).toBeNull()
}

test.describe('findings: IT operator', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-op') })

  test('list: headline matches the rows, filters, ?cve=, open a row, Back, reload', async ({ page, isMobile }) => {
    const errors = collectErrors(page)
    await page.goto('/findings')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('3 unresolved findings, 1 confirmed')
    const rows = isMobile ? page.getByRole('list', { name: 'Findings list' }).getByRole('listitem') : page.getByRole('table', { name: 'Findings list' }).getByRole('row')
    const head = isMobile ? 0 : 1
    await expect(rows).toHaveCount(3 + head)
    await page.getByRole('button', { name: 'Confirmed', exact: true }).click()
    await expect(rows).toHaveCount(1 + head)
    await page.getByRole('button', { name: 'Resolved', exact: true }).click()
    await expect(page.getByText('No findings in this status.').first()).toBeVisible()
    await page.goto('/findings?cve=cve-2022-27593')
    await expect(rows).toHaveCount(1 + head)
    await page.getByRole('button', { name: /Clear CVE-2022-27593 filter/ }).click()
    await expect(rows).toHaveCount(3 + head)
    await page.getByRole('link', { name: 'CVE-2022-27593' }).first().click()
    await expect(page).toHaveURL(/\/findings\/f-1$/)
    await page.goBack()
    await expect(page).toHaveURL(/\/findings/)
    await page.goto('/findings/f-1')
    await page.reload()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('NAS')
    await english(page, 'finding f-1')
    expect(errors).toEqual([])
  })

  test('status change: note required for false positive, Esc/Cancel, kept text, history, reopen, persists after reload', async ({ page }) => {
    await page.goto('/findings/f-2')
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dlg).toHaveCount(0)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await dlg.getByRole('radio', { name: /False positive/ }).click()
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    await dlg.getByLabel(/Note/).fill('ab')
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    await dlg.getByLabel(/Note/).fill('WordPress already updated, checked by hand')
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(dlg).toHaveCount(0)
    await expect(page.getByRole('heading', { level: 1 })).toContainText('false positive')
    await expect(page.getByText('WordPress already updated, checked by hand')).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('false positive')
    await page.goto('/findings')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('2 unresolved findings, 1 confirmed')
    await page.goto('/findings/f-2')
    await page.getByRole('button', { name: 'Reopen finding' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('may be affected')
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('is patched')
  })

  test('f-1: recommendation confirmed by Vedette maintainers, real NAS IP, switch firewall vendor, "Applied" writes the log', async ({ page }) => {
    await page.goto('/findings/f-1')
    await expect(page.getByText('Confirmed by Vedette maintainers').first()).toBeVisible()
    await expect(page.getByText(/Photo Station 6\.1\.2/).first()).toBeVisible()
    await expect(page.getByText('show firewall vip | grep -f 192.168.10.21')).toBeVisible()
    await expect(page.locator('body')).not.toContainText('{IP}')
    await expect(page.locator('body')).not.toContainText('<IP-NAS>')
    await page.getByRole('button', { name: /MikroTik/ }).click()
    await expect(page.getByText(/dst-address=192\.168\.10\.21/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Applied' }).last().click()
    await expect(page.getByText(/Recorded as applied by it@acme.example/)).toBeVisible()
    await expect(page.getByText('Applied: MikroTik configuration')).toBeVisible()
    await page.reload()
    await expect(page.getByText('Applied: MikroTik configuration')).toBeVisible()
    await expect(page.getByText('Files with a .deadbolt extension')).toBeVisible()
    await expect(page.getByText(/grep -i deadbolt/).first()).toBeVisible()
    await english(page, 'f-1 recommendation')
  })

  test('f-2 has no confirmed recommendation: says so, "Ask my AI" gives a labelled AiBlock that survives reload; explain', async ({ page }) => {
    await page.goto('/findings/f-2')
    await expect(page.getByText('No confirmed recommendation yet')).toBeVisible()
    await page.getByRole('button', { name: 'Ask my AI' }).click()
    await expect(page.getByText(/AI-generated/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Explain', exact: true }).click()
    await expect(page.getByRole('button', { name: /Ask again/ })).toHaveCount(2)
    await page.reload()
    await expect(page.getByRole('button', { name: /Ask again/ })).toHaveCount(2)
    await english(page, 'f-2 AI output')
  })

  test('AI off or not configured: buttons locked with the reason and a way to Settings, no errors', async ({ page }) => {
    const errors = collectErrors(page)
    await patchDb(page, { ai_config: { configured: false, provider: 'anthropic', base_url: 'https://api.anthropic.com', model: 'claude-haiku-5-5', key_last4: '', tier: 'med', daily_cap: 60000, redact_pii: true } })
    await page.goto('/findings/f-3')
    await expect(page.getByRole('button', { name: 'Ask my AI' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
    await expect(page.getByText('The AI assistant is off, or no AI profile is assigned to this job.').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open AI assistant settings' }).first()).toHaveAttribute('href', '/settings/ai')
    expect(errors).toEqual([])
  })

  test('links: device, CVE page, rescan; a missing finding says so', async ({ page }) => {
    await page.goto('/findings/f-1')
    await expect(page.getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', '/scans?target=a-nas02')
    await page.getByRole('link', { name: /Open CVE-2022-27593 page/ }).click()
    await expect(page).toHaveURL(/\/cve\/CVE-2022-27593/)
    await page.goto('/devices/a-nas02')
    await expect(page.getByText('Findings on this device')).toBeVisible()
    await page.getByRole('region', { name: 'Findings on this device' }).getByRole('link', { name: 'CVE-2022-27593' }).click()
    await expect(page).toHaveURL(/\/findings\/f-1/)
    await page.goto('/findings/does-not-exist')
    await expect(page.getByText(/No such finding/)).toBeVisible()
    await expect(page.getByRole('link', { name: 'Back to findings' })).toBeVisible()
  })

  test('keyboard: dialog keeps focus, Esc closes it and returns focus to the button', async ({ page }) => {
    await page.goto('/findings/f-2')
    const btn = page.getByRole('button', { name: 'Mark as handled' })
    await btn.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('dialog')).toBeVisible()
    for (let i = 0; i < 12; i++) await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), 'focus left the dialog').toBe(true)
    await page.keyboard.press('Escape')
    await expect(btn).toBeFocused()
  })
})

test.describe('findings: director (viewer)', () => {
  test('can read; every write button is locked with a reason', async ({ page }) => {
    await sample(page)
    await loginAs(page, 'u-view')
    await page.goto('/findings/f-1')
    const mark = page.getByRole('button', { name: 'Mark as handled' })
    await expect(mark).toBeDisabled()
    await expect(mark).toHaveAttribute('title', /Operator/)
    for (const b of await page.getByRole('button', { name: 'Applied' }).all()) await expect(b).toBeDisabled()
    await page.goto('/findings/f-2')
    await expect(page.getByRole('button', { name: 'Ask my AI' })).toBeDisabled()
    await expect(page.getByText(/Operator/).first()).toBeVisible()
  })
})

test.describe('findings: clean install', () => {
  test('no findings; the empty screen says what to do first; a detail link says it does not exist', async ({ page }) => {
    const errors = collectErrors(page)
    await clean(page)
    await page.goto('/findings')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('No unresolved findings')
    await expect(page.locator('body')).not.toContainText('NAS')
    await expect(page.locator('body')).not.toContainText('192.168')
    await expect(page.getByRole('link', { name: 'Open Devices' }).first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Vulnerability scans' }).first()).toBeVisible()
    await english(page, 'clean findings')
    await page.goto('/findings/f-1')
    await expect(page.getByText(/No such finding/)).toBeVisible()
    expect(errors).toEqual([])
  })
})

test.describe('findings: screenshots and accessibility', () => {
  for (const t of ['light', 'dark'] as const) {
    test(`screens in ${t}`, async ({ page }, info) => {
      test.setTimeout(120_000)
      const errors = collectErrors(page)
      await sample(page)
      await theme(page, t)
      const tag = `${info.project.name}-${t}`
      for (const [path, name] of [['/findings', 'list'], ['/findings/f-1', 'f1'], ['/findings/f-2', 'f2'], ['/devices/a-nas02', 'device']] as const) {
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await shot(page, 'findings', `${name}-${tag}`)
        await noHScroll(page, `${path} ${tag}`)
        await english(page, `${path} ${tag}`)
        await expectAccessible(page, `${path} ${tag}`)
      }
      await page.goto('/findings/f-2')
      await page.getByRole('button', { name: 'Mark as handled' }).click()
      await shot(page, 'findings', `dialog-${tag}`)
      await expectAccessible(page, `dialog ${tag}`)
      expect(errors).toEqual([])
    })
  }
})
