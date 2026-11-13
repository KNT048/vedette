import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { sampleStart } from './clean'

// S-UI-1 / D-464: một khung trang (tiêu đề, dải số, hàng tab ở ?tab=) trên Scans, Response, Reports.
// Chạy: pnpm exec playwright test e2e/qa/frame.spec.ts
test.describe.configure({ timeout: 120_000 })

const PAGES = [
  { path: '/scans', second: 'Auto rescan', id: 'auto', other: 'Probe log' },
  { path: '/response', second: 'Metrics', id: 'metrics', other: 'Rules' },
  { path: '/reports', second: 'Data protection assessment', id: 'pdpl', other: 'Weekly report' },
] as const

const device = (page: Page) => ((page.viewportSize()?.width ?? 1366) < 600 ? 'phone' : 'desktop')
const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${where}: horizontal page scroll`).toBeLessThanOrEqual(1)

test.describe('page frame (S-UI-1)', () => {
  test.beforeEach(async ({ page }) => { await sampleStart(page) })

  for (const p of PAGES) {
    test(`${p.path}: a tab change writes ?tab=, reload keeps it, Back from another page keeps it; no sideways page scroll`, async ({ page }) => {
      const errors = collectErrors(page)
      await page.goto(p.path)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      const tablist = page.getByRole('tablist')
      await expect(tablist).toBeVisible()
      await tablist.getByRole('tab', { name: p.second, exact: true }).click()
      await expect(page).toHaveURL(new RegExp(`\\?tab=${p.id}$`))
      await page.reload()
      await expect(page.getByRole('tab', { name: p.second, exact: true })).toHaveAttribute('aria-selected', 'true')
      await page.goto('/lookup')
      await page.goBack()
      await expect(page).toHaveURL(new RegExp(`\\?tab=${p.id}$`))
      await expect(page.getByRole('tab', { name: p.second, exact: true })).toHaveAttribute('aria-selected', 'true')
      await noHScroll(page, p.path)
      // tab đang mở nằm trong phần thấy được của hàng tab (điện thoại: hàng tab tự cuộn tới nó)
      const inView = await page.evaluate(() => {
        const row = document.querySelector('[role="tablist"]')!.getBoundingClientRect()
        const tab = document.querySelector('[role="tab"][aria-selected="true"]')!.getBoundingClientRect()
        return tab.left >= row.left - 1 && tab.right <= row.right + 1
      })
      expect(inView, `${p.path}: open tab scrolled into the tab row`).toBe(true)
      await shot(page, 'frame', `${p.path.slice(1)}-${device(page)}`)
      await expectAccessible(page, p.path)
      await page.getByRole('tab', { name: p.other, exact: true }).click()
      await expect(page.getByRole('tab', { name: p.other, exact: true })).toHaveAttribute('aria-selected', 'true')
      expect(errors).toEqual([])
    })
  }

  test('old Response #hash links open the tab through ?tab= and keep other parameters', async ({ page }) => {
    await page.goto('/response?incident=al-4#log')
    await expect(page).toHaveURL(/\/response\?incident=al-4&tab=log$/)
    await expect(page.getByRole('tab', { name: 'Log', exact: true })).toHaveAttribute('aria-selected', 'true')
    await page.goto('/response#ai')
    await expect(page).toHaveURL(/\/response\?tab=requests$/)
    await expect(page.getByRole('tab', { name: /^Requests/ })).toHaveAttribute('aria-selected', 'true')
  })

  test('phone: the Scans tab row scrolls inside itself and the deep-linked last tab is in view', async ({ page }) => {
    test.skip(device(page) !== 'phone', 'phone only')
    await page.goto('/scans?tab=credentialed')
    await expect(page.getByRole('tab', { name: 'Credentialed scan' })).toHaveAttribute('aria-selected', 'true')
    const row = await page.getByRole('tablist').evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth, left: el.scrollLeft }))
    expect(row.sw, 'five tabs do not fit a phone, so the row scrolls').toBeGreaterThan(row.cw)
    expect(row.left, 'the row was scrolled to the open tab').toBeGreaterThan(0)
    await noHScroll(page, '/scans?tab=credentialed')
    await shot(page, 'frame', 'scans-credentialed-phone')
  })
})
