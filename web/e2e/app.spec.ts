import { expect, test } from '@playwright/test'
import { axeViolations, collectErrors, expectAccessible, startWithSample } from './helpers'
import { POST_V1_IN_UI } from '../src/lib/postV1'

// Every page in the sidebar plus the main detail pages. Checks: a heading, no console errors, a clean axe run (contrast included).
// A page of a module left out of v1 (MCP server) is not offered while POST_V1_IN_UI is false, so it is not in the list.
const PAGES = [
  '/', '/lookup?q=185.220.101.47', '/cve/CVE-2022-27593', '/findings', '/findings/f-1', '/findings/f-2', '/incidents',
  '/devices', '/devices/a-nas02', '/devices/setup', '/exposure', '/scans', '/honeypot', '/logs', '/assistant', '/reports',
  '/settings/general', '/settings/modules', '/settings/channels', '/settings/ai', '/settings/connections', '/settings/siem', '/settings/users',
  '/settings/audit', '/settings/updates', '/settings/privacy', ...(POST_V1_IN_UI ? ['/settings/mcp'] : []), '/settings/data', '/account', '/honeypot/hits/hit-seed-1', '/incidents/al-4',
]

test('first open: set up with sample data, then the home page', async ({ page, isMobile }) => {
  const errors = collectErrors(page)
  await startWithSample(page)
  // Phones get a list instead of a table (DataTable mobileRow)
  await expect(page.getByRole(isMobile ? 'list' : 'table', { name: 'Newly exploited' })).toBeVisible()
  expect(errors).toEqual([])
})

test('every page opens without errors and is accessible', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  await startWithSample(page)
  const problems: string[] = []
  for (const path of PAGES) {
    await page.goto(path)
    await expect(page.getByRole('heading', { level: 1 }).first(), path).toBeVisible()
    await expect(page.getByRole('status').filter({ hasText: /^Loading$/ }), `${path} still loading`).toHaveCount(0, { timeout: 8000 })
    for (const v of await axeViolations(page)) problems.push(`${path}: ${v}`)
    const text = await page.locator('body').innerText()
    if (/[ăâđêôơưạảấầẩẫậắằẳẵặẹẻẽếềểễệỉịọỏốồổỗộớờởỡợụủứừửữựỳỵỷỹ]/i.test(text)) problems.push(`${path}: Vietnamese text on page`)
  }
  expect(problems, problems.join('\n')).toEqual([])
  expect(errors).toEqual([])
})

test('a user works in the GUI: declares a device, handles a finding, signs out and back in', async ({ page, isMobile }) => {
  test.skip(isMobile, 'the account menu on a phone is checked by a separate test')
  await startWithSample(page)
  // "I have" from the "This week" table adds a hand-declared device
  await page.getByRole('button', { name: 'I have this' }).first().click()
  await expect(page.getByText(/^Done\. This flaw is now a finding/).first()).toBeVisible() // feeds weekly.addedToast
  // A confirmed finding shows the "BYN confirmed" guidance and the FortiGate config snippet
  await page.goto('/findings/f-1')
  await expect(page.getByText('Confirmed by scan', { exact: true }).first()).toBeVisible()
  await expect(page.getByText(/192\.168\.10\.21/).first()).toBeVisible()
  // data is still there after a page reload
  await page.reload()
  await expect(page.getByText('Confirmed by scan', { exact: true }).first()).toBeVisible()
  // sign out, sign in with a view-only account
  await page.goto('/')
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitem', { name: 'Sign out' }).click()
  await expect(page).toHaveURL(/\/login/)
  await page.getByLabel('Email', { exact: true }).fill('director@acme.example')
  await page.getByLabel('Password', { exact: true }).fill('vedette-demo')
  await page.getByRole('button', { name: 'Sign in' }).click()
  await expect(page.getByRole('heading', { level: 1, name: /^Today/ })).toBeVisible()
  await expect(page.getByRole('button', { name: 'I have this' }).first()).toBeDisabled()
})

test('dark theme is readable and accessible', async ({ page, isMobile }) => {
  test.skip(isMobile, 'same as desktop')
  await startWithSample(page)
  await page.getByRole('button', { name: /Account/ }).first().click()
  await page.getByRole('menuitemradio', { name: 'Dark' }).click()
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark')
  await expectAccessible(page, 'home dark')
})

test('phone: open the menu, go to Devices, the table scrolls inside its frame', async ({ page, isMobile }) => {
  test.skip(!isMobile, 'phone only')
  await startWithSample(page)
  await page.getByRole('button', { name: 'Open menu' }).click()
  await page.getByRole('button', { name: /^Assets/ }).click() // docs/UI.md §2: groups start closed except the current page's
  await page.getByRole('link', { name: 'Devices' }).click()
  await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
  expect(overflow, 'the page must not scroll horizontally').toBeLessThanOrEqual(1)
})
