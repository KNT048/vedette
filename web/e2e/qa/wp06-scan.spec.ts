import { expect, test } from '@playwright/test'
import { collectErrors, expectAccessible, startWithSample } from '../helpers'
import { begin, noHScroll, stepper, THEMES } from './wp06-shared'
import { finishClean } from './clean'

// WP-06 independent check, area 3: "As the IT operator I try to scan before confirming I may scan those networks; as the admin I set the weekly schedule."
// Scan -> Scans and history / Schedule and safety. D-57: weekdays 1-7, Monday first. Server refusal: 400 commitment_required.
const DAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
const SHORT = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

test('without the commitment: scanning is refused in the screen and by the server (400 commitment_required) with a clear message', async ({ page }, info) => {
  const errors = collectErrors(page)
  const shot = stepper(page, info, 'scan-commitment', 'light')
  await finishClean(page) // commitment NOT ticked
  await page.goto('/scans')
  await expect(page.getByRole('heading', { level: 1 })).toHaveText('Cannot scan yet: confirm the scan scope first')
  await shot('runs')
  const scanNow = page.getByRole('button', { name: /Scan now/ })
  await expect(scanNow).toBeDisabled()
  const body = await page.locator('main').innerText()
  console.log('RUNS TEXT', body.slice(0, 1500))
  await expect(page.getByText('The scan scope commitment is not ticked yet.').first()).toBeVisible()
  await expect(page.getByRole('link', { name: 'Open Scope and sensors' })).toHaveAttribute('href', '/devices/setup') // the way forward
  // the user typed 192.168.10.0/24 during setup: the next screen must not claim no range was entered
  await expect.soft(page.getByText('No network range entered yet.'), 'setup asked for a range but the scan page says none was entered').toHaveCount(0)
  // the server side (mock API): same refusal, status 400, code commitment_required, plain-language message
  const res = await page.evaluate(async () => {
    const r = await fetch('/api/v1/scans/runs', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ targets: ['any'] }) })
    return { status: r.status, json: await r.json().catch(() => null) }
  })
  console.log('API RESULT', JSON.stringify(res))
  expect(res.status).toBe(400)
  expect(res.json.error.code).toBe('commitment_required')
  expect(res.json.error.message).toMatch(/does not scan until the scope commitment is ticked/)
  // schedule tab: enabling a schedule without a commitment says nothing runs
  await page.goto('/scans?tab=safety')
  await shot('safety-clean')
  await expect(page.getByText(/nothing runs until the scan scope commitment is ticked/)).toBeVisible()
  await noHScroll(page, 'scan clean')
  expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
})

for (const theme of THEMES) {
  test(`schedule [${theme}]: weekdays Monday-first (1-7); weekly day select Monday to Sunday saves and the next scan is on that weekday`, async ({ page }, info) => {
    const errors = collectErrors(page)
    const shot = stepper(page, info, 'scan-schedule', theme)
    await begin(page, theme)
    await page.goto('/scans?tab=safety')
    await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
    await shot('safety')
    // window days: checkboxes in order Mon..Sun
    const legend = page.getByText('Days the window starts')
    await expect(legend).toBeVisible()
    const dayLabels = await page.locator('label[for^="day-"]').allTextContents()
    console.log('WINDOW DAYS', JSON.stringify(dayLabels))
    expect(dayLabels).toEqual(SHORT)
    // schedule
    const sw = page.locator('#sch-on')
    if ((await sw.getAttribute('aria-checked')) !== 'true') await sw.click()
    await page.locator('#sch-freq').selectOption('weekly')
    const options = await page.locator('#sch-day option').allTextContents()
    console.log('SCHEDULE DAY OPTIONS', JSON.stringify(options))
    expect(options).toEqual(DAYS)
    const values = await page.locator('#sch-day option').evaluateAll((os) => os.map((o) => (o as HTMLOptionElement).value))
    expect(values).toEqual(['1', '2', '3', '4', '5', '6', '7'])
    // make every weekday part of the window so the next run follows the chosen weekday
    for (let d = 1; d <= 7; d++) { const cb = page.locator(`#day-${d}`); if ((await cb.getAttribute('aria-checked')) !== 'true') await cb.click() }
    for (const [i, day] of DAYS.entries()) {
      await page.locator('#sch-day').selectOption(String(i + 1))
      await page.getByRole('button', { name: 'Save settings' }).click()
      await expect(page.getByText(/Next scan:/)).toBeVisible()
      await page.reload()
      await expect(page.locator('#sch-day')).toHaveValue(String(i + 1)) // saved
      const next = await page.getByText(/Next scan:/).innerText()
      console.log('NEXT', day, next)
      await shot(`day-${i + 1}-${day}`)
      const dateWeekday = await page.evaluate((t) => {
        const m = /(\d{1,2})\/(\d{1,2})\/(\d{4})/.exec(t) // dd/mm/yyyy as the app prints it
        if (!m) return null
        return new Date(Date.UTC(+m[3]!, +m[2]! - 1, +m[1]!)).getUTCDay()
      }, next)
      const weekdayWord = new RegExp(day.slice(0, 3), 'i').test(next)
      // either the text names the weekday, or its date falls on it (JS: Sunday = 0)
      expect(weekdayWord || dateWeekday === ((i + 1) % 7), `next scan text "${next}" should be on ${day}`).toBe(true)
    }
    await noHScroll(page, 'scan safety')
    await expectAccessible(page, 'scan safety')
    expect(errors.filter((e) => !/status of (4|5)\d\d/.test(e))).toEqual([])
  })
}
