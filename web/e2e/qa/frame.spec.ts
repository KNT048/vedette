import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { sampleStart } from './clean'

// S-UI-1 / D-464, D-543: một khung trang (tiêu đề, dải số, hàng tab ở ?tab=) trên Scans, Response, Reports, Honeypot, chi tiết thiết bị.
// Chạy: pnpm exec playwright test e2e/qa/frame.spec.ts
test.describe.configure({ timeout: 120_000 })

const PAGES = [
  { path: '/scans', second: 'Auto rescan', id: 'auto', other: 'Probe log' },
  { path: '/response', second: 'Log', id: 'log', other: 'Rules' },
  { path: '/logs', second: 'Sources', id: 'sources', other: 'Events' },
  { path: '/findings', second: 'Accepted risk', id: 'accepted', other: 'Handled' },
  { path: '/reports', second: 'Data protection assessment', id: 'pdpl', other: 'Weekly report' },
  // D-543: the other Kiên-side pages on the frame
  { path: '/honeypot', second: 'Services', id: 'services', other: 'Tokens' },
  { path: '/incidents', second: 'Resolved', id: 'resolved', other: 'Open' },
  { path: '/devices/a-nas02', second: 'Software', id: 'software', other: 'Observations' },
  // D-519: long Settings sections and the setup page split into tabs
  { path: '/settings/network', second: 'Box address', id: 'box-address', other: 'Time' },
  { path: '/settings/account', second: 'Sessions', id: 'sessions', other: 'Profile' },
  { path: '/devices/setup', second: 'Agents', id: 'agents', other: 'Scope' },
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
      await shot(page, 'frame', `${p.path.slice(1).replaceAll('/', '-')}-${device(page)}`)
      await expectAccessible(page, p.path)
      await page.getByRole('tab', { name: p.other }).click() // not exact: a tab with a badge reads "Open 2 open, high or critical"
      await expect(page.getByRole('tab', { name: p.other })).toHaveAttribute('aria-selected', 'true')
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

  test('old #section links of the D-519 pages open their tab through ?tab= and keep other parameters', async ({ page }) => {
    await page.goto('/devices/setup?from=ways#agents')
    await expect(page).toHaveURL(/\/devices\/setup\?from=ways&tab=agents$/)
    await expect(page.getByRole('tab', { name: 'Agents', exact: true })).toHaveAttribute('aria-selected', 'true')
    await page.goto('/devices/setup#snmp')
    await expect(page.getByRole('tab', { name: 'SNMP', exact: true })).toHaveAttribute('aria-selected', 'true')
    await page.goto('/settings/network#box-address')
    await expect(page).toHaveURL(/\/settings\/network\?tab=box-address$/)
    await page.goto('/account#two-step') // the two-step prompt's old link, through the /account redirect
    await expect(page).toHaveURL(/\/settings\/account\?tab=sign-in$/)
    await expect(page.getByRole('tab', { name: 'Sign-in and two-step' })).toHaveAttribute('aria-selected', 'true')
  })

  // UI-4: on a page longer than the window the menu column keeps its background and rule all the way down (full-page captures included).
  for (const theme of ['light', 'dark'] as const) {
    for (const path of ['/devices/a-nas02', '/settings/data']) {
      test(`the left menu column covers the whole page height on ${path} (${theme})`, async ({ page }) => {
        await page.evaluate((v) => localStorage.setItem('vedette-theme', v), theme)
        if (device(page) === 'phone') {
          // a phone has no side column: the menu is a drawer the height of the screen
          await page.goto(path)
          await page.getByRole('button', { name: 'Open menu' }).click()
          const d = await page.getByRole('dialog').evaluate((el) => ({ h: el.getBoundingClientRect().height, view: innerHeight, bg: getComputedStyle(el).backgroundColor }))
          expect(d.h).toBeGreaterThanOrEqual(d.view - 1)
          expect(d.bg).not.toBe('rgba(0, 0, 0, 0)')
          return
        }
        await page.goto(path)
        await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
        // the grid cell that holds the menu (found from the menu, so the check does not depend on how the column is built)
        const col = await page.getByRole('navigation', { name: 'Main navigation' }).evaluate((nav) => {
          let el = nav as HTMLElement
          while (el.parentElement && getComputedStyle(el.parentElement).display !== 'grid') el = el.parentElement
          // at scroll 0, as a full-page capture (the QA shots, print) renders it: a sticky box one screen high ends there
          window.scrollTo(0, 0)
          const r = el.getBoundingClientRect()
          const painted = [el, ...el.querySelectorAll<HTMLElement>('*')].find((x) => getComputedStyle(x).backgroundColor !== 'rgba(0, 0, 0, 0)' && x.getBoundingClientRect().width >= r.width - 1)
          const p = painted?.getBoundingClientRect()
          return { page: document.documentElement.scrollHeight, view: innerHeight, paintedBottom: p ? p.bottom + scrollY : 0, bg: painted ? getComputedStyle(painted).backgroundColor : '', body: getComputedStyle(document.body).backgroundColor }
        })
        expect(col.page, `${path} must be longer than the window for this check`).toBeGreaterThan(col.view + 200)
        expect(col.paintedBottom, 'menu background reaches the end of the page').toBeGreaterThanOrEqual(col.page - 1)
        expect(col.bg, 'menu background differs from the page background').not.toBe(col.body)
        await shot(page, 'frame', `sidebar-${path.slice(1).replaceAll('/', '-')}-${theme}-${device(page)}`)
      })
    }
  }

  for (const theme of ['light', 'dark'] as const) {
    test(`keyboard focus ring sits inside the tab, so the scrolling row does not clip it (${theme})`, async ({ page }) => {
      await page.evaluate((v) => localStorage.setItem('vedette-theme', v), theme)
      await page.goto('/scans')
      await page.getByRole('tab', { name: 'Scans and history' }).click()
      await page.keyboard.press('ArrowRight')
      const tab = page.getByRole('tab', { name: 'Schedule and safety' })
      await expect(tab).toBeFocused()
      await expect(page).toHaveURL(/\?tab=safety$/)
      const ring = await tab.evaluate((el) => { const s = getComputedStyle(el); return { style: s.outlineStyle, width: s.outlineWidth, offset: s.outlineOffset, scrollbar: getComputedStyle(el.parentElement!).scrollbarWidth } })
      expect(ring).toEqual({ style: 'solid', width: '2px', offset: '-2px', scrollbar: 'none' })
      await page.getByRole('tablist').screenshot({ path: `qa-shots/frame/focus-${theme}-${device(page)}.png` })
    })
  }

  test('phone: the Scans tab row scrolls inside itself and the deep-linked last tab is in view', async ({ page }) => {
    test.skip(device(page) !== 'phone', 'phone only')
    await page.goto('/scans?tab=probes') // the last tab in v1: the credentialed scan is not offered (D-417)
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    const row = await page.getByRole('tablist').evaluate((el) => ({ sw: el.scrollWidth, cw: el.clientWidth, left: el.scrollLeft }))
    expect(row.sw, 'four tabs do not fit a phone, so the row scrolls').toBeGreaterThan(row.cw)
    expect(row.left, 'the row was scrolled to the open tab').toBeGreaterThan(0)
    await noHScroll(page, '/scans?tab=probes')
    await shot(page, 'frame', 'scans-probes-phone')
  })
})
