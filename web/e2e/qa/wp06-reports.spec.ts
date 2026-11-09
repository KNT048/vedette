import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'

// WP-06 independent check, area 4: "As the admin I choose the day the weekly report is emailed and see when the next one goes out."
// Reports -> Weekly report -> Schedule and recipients. Days Monday-Sunday (1-7).
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

for (const theme of THEMES) {
  test(`weekly schedule [${theme}]: day select Monday to Sunday saves and shows the right next send`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'reports-schedule', theme)
    await begin(page, theme)
    await page.goto('/reports')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await shot('page')
    const day = page.locator('#rep-day')
    await expect(day).toBeVisible()
    await day.scrollIntoViewIfNeeded()
    await shot('schedule')
    const options = await day.locator('option').allTextContents()
    console.log('DAY OPTIONS', JSON.stringify(options))
    expect(options).toEqual(DAYS)
    expect(await day.locator('option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))).toEqual(['1', '2', '3', '4', '5', '6', '7'])
    // enabled with a recipient (sample data may already have both)
    const sw = page.locator('#rep-enabled')
    if ((await sw.getAttribute('aria-checked')) !== 'true') await sw.click()
    if ((await page.getByText('No recipients yet.').count()) > 0) {
      await page.locator('#rep-email').fill('boss@acme.example')
      await page.getByRole('button', { name: 'Add', exact: true }).click()
    }
    for (const [i, name] of DAYS.entries()) {
      await day.selectOption(String(i + 1))
      await page.getByRole('button', { name: 'Save', exact: true }).click()
      await expect(page.getByText('Schedule saved').first()).toBeVisible()
      await page.reload()
      await expect(page.locator('#rep-day')).toHaveValue(String(i + 1))
      const next = await page.getByText(/Next send:/).innerText()
      console.log('NEXT', name, next)
      await shot(`day-${i + 1}-${name}`)
      const wd = await page.evaluate((t) => {
        const m = /(\d{1,2})\/(\d{1,2})\/(\d{4})/.exec(t)
        return m ? new Date(Date.UTC(+m[3]!, +m[2]! - 1, +m[1]!)).getUTCDay() : null
      }, next)
      expect(wd, `"${next}" should fall on ${name}`).toBe((i + 1) % 7)
    }
    // the way back / errors: turning it off says so; enabling with no recipients says what is missing
    await page.locator('#rep-enabled').click()
    await page.getByRole('button', { name: 'Save', exact: true }).click()
    await shot('off')
    await expect(page.getByText('Automatic sending is off.')).toBeVisible()
    await noHScroll(page, 'reports')
    await expectAccessible(page, 'reports weekly schedule')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}
