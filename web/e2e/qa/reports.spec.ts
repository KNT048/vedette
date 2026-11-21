import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, finishClean, sampleStart } from './clean'

// QA như người dùng thật cho module reports (S-REP-1, S-REP-2). UI chỉ có tiếng Anh; báo cáo đánh giá nói về Luật 91/2025/QH15.
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/reports.spec.ts
// Máy dùng chung với nhiều agent nên chậm: nới thời gian mỗi test.
test.describe.configure({ timeout: 150_000 })

/** Đổi phiên sang tài khoản khác: ép core_session trước mỗi lần tải trang (một lần ghi muộn của trang cũ không đè được). */
async function asUser(page: Page, userId: string) {
  await page.addInitScript((u) => {
    try {
      const k = 'vedette-mock-db-v4'
      const raw = localStorage.getItem(k)
      if (raw) { const db = JSON.parse(raw); db.core_session = { userId: u }; localStorage.setItem(k, JSON.stringify(db)) }
    } catch { /* bỏ qua */ }
  }, userId)
  await page.reload()
}
const noHorizontalScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
const device = (page: Page) => (page.viewportSize()?.width ?? 1366) < 700 ? 'mobile' : 'desktop'
const noVietnamese = async (page: Page) => expect(await page.locator('body').innerText()).not.toMatch(DIACRITICS)

async function fillOrg(page: Page, o: { tax?: string; size?: string } = {}) {
  await page.getByLabel('Tax code', { exact: true }).fill(o.tax ?? '0312345678')
  await page.getByLabel('Head office address', { exact: true }).fill('12 Nguyen Hue, District 1, Ho Chi Minh City')
  await page.getByLabel('Line of business', { exact: true }).selectOption({ label: 'Retail and trade' })
  await page.getByLabel('Number of staff', { exact: true }).fill('45')
  await page.getByLabel('Organisation size', { exact: true }).selectOption({ label: o.size ?? 'Small enterprise' })
  await page.getByLabel('Data protection contact', { exact: true }).fill('Tran Van An')
  await page.getByLabel('Contact email', { exact: true }).fill('anna@acme.example')
  await page.getByLabel('Contact phone', { exact: true }).fill('0901234567')
}

test.describe('reports: clean install', () => {
  test('no data yet: the report points to Devices; no recipient, nothing sent, no sample data', async ({ page }) => {
    const errors = collectErrors(page)
    await finishClean(page)
    await page.goto('/reports')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('No data to build a report yet')
    await expect(page.getByText('No data for the report yet')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Devices' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Send now' })).toHaveCount(0)
    await page.getByRole('tab', { name: 'History' }).click()
    await expect(page.getByText('No report sent yet')).toBeVisible()
    await page.getByRole('tab', { name: 'Settings' }).click()
    await expect(page.getByText('No recipients yet.')).toBeVisible()
    await expect(page.getByText('director@acme.example')).toHaveCount(0)
    await shot(page, 'reports', `settings-clean-${device(page)}`)
    await expectAccessible(page, 'reports, clean')
    await noHorizontalScroll(page)
    await noVietnamese(page)
    await page.getByRole('tab', { name: 'Report' }).click()
    await page.getByRole('link', { name: 'Open Devices' }).click()
    await expect(page).toHaveURL(/\/devices/)
    await page.goto('/reports?tab=pdpl')
    const gen = page.getByRole('button', { name: 'Generate report' })
    await expect(gen).toBeDisabled()
    await expect(gen).toHaveAttribute('title', /Save the organisation details first/)
    await expect(page.getByLabel('Organisation name', { exact: true })).toHaveValue('Test Company')
    expect(errors).toEqual([])
  })
})

test.describe('reports: the security report (sample data)', () => {
  test('seven sections; Settings change the report; Send now confirms and lands in History; a sent report reopens as sent', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/reports')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('findings are open')
    const doc = page.getByRole('article', { name: 'Security report' })
    await expect(doc).toBeVisible()
    for (const s of ['Summary', 'Handled this period', 'Still open', 'New this period', 'External exposure', 'Detections', 'Coverage']) await expect(doc.getByRole('heading', { level: 3, name: s })).toBeVisible()
    await expect(doc.getByText(/Patched by Vedette: version moved 6\.24 → 7\.23/).first()).toBeVisible()
    await shot(page, 'reports', `report-${device(page)}`)
    await expectAccessible(page, 'security report')
    await noHorizontalScroll(page)

    await page.getByRole('tab', { name: 'Settings' }).click()
    await page.getByRole('checkbox', { name: 'External exposure' }).click()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Report settings saved').first()).toBeVisible()
    await page.getByRole('tab', { name: 'Report' }).click()
    await expect(doc.getByRole('heading', { level: 3, name: 'External exposure' })).toHaveCount(0)

    await page.getByRole('button', { name: 'Send now' }).click()
    await expect(page.getByRole('dialog')).toContainText('director@acme.example')
    await page.getByRole('dialog').getByRole('button', { name: 'Send', exact: true }).click()
    await expect(page.getByText('Report sent. It is kept in History.').first()).toBeVisible()
    await page.getByRole('tab', { name: 'History' }).click()
    const table = page.getByRole('table', { name: 'Reports sent' })
    await expect(table.getByText(/^Sent by /)).toBeVisible()
    await expect(table.getByText(/The email channel has no valid SMTP settings/)).toBeVisible()
    await table.getByRole('link', { name: /^Open the report sent / }).first().click()
    await expect(page).toHaveURL(/\/reports\/sent\//)
    await expect(page.getByRole('article', { name: 'Security report' })).toBeVisible()
    await noVietnamese(page)
    expect(errors).toEqual([])
  })

  test('print: only the report prints, in colour, on A4; Back returns to History; an unknown id is explained', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/reports/sent/rh-1')
    await expect(page.getByRole('article', { name: 'Security report' })).toBeVisible()
    await shot(page, 'reports', `sent-screen-${device(page)}`)
    await page.emulateMedia({ media: 'print' })
    await expect(page.getByRole('button', { name: 'Print / Save PDF' })).toBeHidden()
    await expect(page.getByRole('navigation', { name: 'Breadcrumb' })).toBeHidden()
    await page.screenshot({ path: `qa-shots/reports/sent-print-${device(page)}.png`, fullPage: true })
    await page.emulateMedia({ media: 'screen' })
    await page.getByRole('navigation', { name: 'Breadcrumb' }).getByRole('link', { name: 'History' }).click() // docs/UI.md §3: the parent in the breadcrumb
    await expect(page).toHaveURL(/\/reports\?tab=history$/)
    await page.goto('/reports/sent/rh-missing')
    await expect(page.getByText('This report is not in the history.')).toBeVisible()
    await noVietnamese(page)
    expect(errors.filter((e) => !/404/.test(e))).toEqual([])
  })

  test('viewer (director): can read and print, cannot send or change the settings, is told which role is needed', async ({ page }) => {
    await sampleStart(page)
    const send = page.getByRole('button', { name: 'Send now' })
    await expect(async () => {
      await asUser(page, 'u-view')
      await page.goto('/reports')
      await expect(send).toHaveAttribute('title', /Operator/, { timeout: 4000 })
    }).toPass({ timeout: 60_000 })
    await expect(page.getByRole('article', { name: 'Security report' })).toBeVisible()
    await expect(send).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Print / Save PDF' })).toBeVisible()
    await page.getByRole('tab', { name: 'Settings' }).click()
    await expect(page.getByRole('button', { name: 'Save', exact: true })).toBeDisabled()
  })
})

test.describe('reports: data protection assessment under Law 91/2025/QH15 (S-REP-2)', () => {
  test('form: empty, bad tax code, bad email and phone, then valid; typed data is kept; generate, check the legal content, print', async ({ page }) => {
    const errors = collectErrors(page)
    await sampleStart(page)
    await page.goto('/reports?tab=pdpl')
    await expect(page.getByRole('note').first()).toContainText('Assessment support, not legal advice')
    await page.getByLabel('Organisation name', { exact: true }).fill('')
    await page.getByRole('button', { name: 'Save details' }).click()
    for (const m of ['Enter the organisation name', 'The tax code is 10 digits', 'Enter the head office address', 'Pick the field of activity', 'Enter the headcount', 'Pick the organisation size', 'Enter the name of the person', 'Enter the contact email', 'Enter the contact phone number']) await expect(page.getByText(new RegExp(m)).first()).toBeVisible()
    await page.getByLabel('Organisation name', { exact: true }).fill('Sample Company')
    await fillOrg(page, { tax: '123' })
    await page.getByLabel('Contact email', { exact: true }).fill('anna@@acme')
    await page.getByLabel('Contact phone', { exact: true }).fill('12345')
    await page.getByRole('button', { name: 'Save details' }).click()
    await expect(page.getByText(/The tax code is 10 digits/)).toBeVisible()
    await expect(page.getByText('The email is not valid. Use the form name@company.com.')).toBeVisible()
    await expect(page.getByLabel('Head office address', { exact: true })).toHaveValue(/Nguyen Hue/)
    await page.getByLabel('Tax code', { exact: true }).fill('0312345678-001')
    await page.getByLabel('Contact email', { exact: true }).fill('anna@acme.example')
    await page.getByLabel('Contact phone', { exact: true }).fill('0901 234 567')
    await page.getByLabel('Contact phone', { exact: true }).press('Enter') // Enter gửi form
    await expect(page.getByText('Organisation details saved').first()).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('Tax code', { exact: true })).toHaveValue('0312345678-001')
    await page.getByRole('button', { name: 'Generate report' }).click()
    const doc = page.getByRole('article', { name: /Information security and personal data assessment report/ })
    await expect(doc).toBeVisible()
    for (const must of ['91/2025/QH15', 'Decree 356/2025/ND-CP', '72 hours', '60 days', 'Article 23', 'Articles 21, 22', 'Official Gazette No. 18']) await expect(doc).toContainText(must)
    await expect(doc.getByText('Assessment support, not legal advice')).toHaveCount(2)
    await shot(page, 'reports', `pdpl-${device(page)}`)
    await expectAccessible(page, 'assessment')
    await noHorizontalScroll(page)
    await noVietnamese(page)
    await page.getByRole('link', { name: 'Print / Save PDF' }).click()
    await expect(page).toHaveURL(/print\/pdpl/)
    await expect(page.getByRole('article', { name: /Information security and personal data assessment report/ })).toBeVisible()
    await shot(page, 'reports', `print-pdpl-screen-${device(page)}`)
    await page.emulateMedia({ media: 'print' })
    await page.screenshot({ path: `qa-shots/reports/print-pdpl-print-${device(page)}.png`, fullPage: true })
    await page.emulateMedia({ media: 'screen' })
    expect(errors).toEqual([])
  })

  test('size decides the obligations: a micro enterprise is exempt from the dossier and the data protection person; sensitive data makes them mandatory; transfer abroad always applies', async ({ page }) => {
    await sampleStart(page)
    await page.goto('/reports?tab=pdpl')
    await fillOrg(page, { size: 'Micro enterprise' })
    await page.getByRole('checkbox', { name: 'We transfer data abroad' }).check()
    await page.getByRole('button', { name: 'Save details' }).click()
    await expect(page.getByText('Organisation details saved').first()).toBeVisible()
    await page.getByRole('button', { name: 'Generate report' }).click()
    const doc = page.getByRole('article', { name: /Information security and personal data assessment report/ })
    await expect(doc.getByText('Not mandatory at your size')).toHaveCount(2)
    await expect(doc.getByText('Transfer of data abroad').first()).toBeVisible()
    await page.getByRole('checkbox', { name: 'We process sensitive personal data' }).check()
    await page.getByRole('button', { name: 'Save details' }).click()
    await expect(page.getByText('Organisation details saved').first()).toBeVisible()
    await page.getByRole('button', { name: 'Regenerate from new data' }).click()
    await expect(doc.getByText('Not mandatory at your size')).toHaveCount(0)
    await expect(doc.getByText('Sensitive personal data').first()).toBeVisible()
  })

  test('AI commentary: labelled, with the profile that wrote it, kept out of the legal sections', async ({ page }) => {
    await sampleStart(page)
    await page.goto('/reports?tab=pdpl')
    await fillOrg(page)
    await page.getByRole('button', { name: 'Save details' }).click()
    await expect(page.getByText('Organisation details saved').first()).toBeVisible()
    await page.getByRole('button', { name: 'Generate report' }).click()
    await page.getByRole('button', { name: 'Write AI commentary' }).click()
    const doc = page.getByRole('article', { name: /Information security and personal data assessment report/ })
    await expect(doc.getByText('AI-generated, needs human review')).toBeVisible()
    await expect(doc.getByText(/Model claude-sonnet-5-5 \(Claude Sonnet\)/)).toBeVisible()
  })
})

test.describe('reports: appearance', () => {
  for (const scheme of ['light', 'dark'] as const) {
    test(`main screens, ${scheme}: English only, accessible, no horizontal scroll`, async ({ page }) => {
      const errors = collectErrors(page)
      await page.emulateMedia({ colorScheme: scheme })
      await sampleStart(page)
      await page.goto('/reports')
      await expect(page.getByRole('article').first()).toBeVisible()
      await page.waitForLoadState('networkidle')
      await shot(page, 'reports', `report-${scheme}-${device(page)}`)
      await expectAccessible(page, `report ${scheme}`)
      await noHorizontalScroll(page)
      await noVietnamese(page)
      await page.goto('/reports?tab=pdpl')
      await expect(page.getByRole('button', { name: 'Save details' })).toBeVisible()
      await page.waitForLoadState('networkidle')
      await shot(page, 'reports', `pdpl-form-${scheme}-${device(page)}`)
      await expectAccessible(page, `pdpl ${scheme}`)
      await noHorizontalScroll(page)
      await noVietnamese(page)
      expect(errors).toEqual([])
    })
  }
})
