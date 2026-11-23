import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// "As the admin I choose when the security report is emailed and see when the next one goes out."
// Reports -> Settings -> Delivery: the shared schedule editor, limited to weekly or monthly (a report covers a week or a month).

for (const theme of THEMES) {
  test(`report schedule [${theme}]: weekly or monthly only, with the reason; saving shows the next send on the Report tab`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'reports-schedule', theme)
    await begin(page, theme)
    await page.goto('/reports?tab=settings')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await shot('settings')
    await page.getByRole('button', { name: 'Change the schedule of the security report' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    const on = dlg.getByRole('switch', { name: 'Run on a schedule' })
    if ((await on.getAttribute('aria-checked')) !== 'true') await on.click()
    const repeat = dlg.getByLabel('Repeat', { exact: true })
    expect(await repeat.locator('option').allTextContents()).toEqual(['Every week', 'Every month'])
    await expect(dlg.getByText('A report covers a week or a month.')).toBeVisible()
    await shot('dialog')
    await dlg.getByRole('button', { name: 'Save', exact: true }).click()
    await expect(page.getByText('Schedule of the security report saved.').first()).toBeVisible()
    await page.getByRole('tab', { name: 'Report' }).click()
    await expect(page.getByText(/^Next send .+ to \d+ recipients?$/)).toBeVisible()
    await shot('report')
    await noHScroll(page, 'reports')
    await expectAccessible(page, 'reports schedule')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}
