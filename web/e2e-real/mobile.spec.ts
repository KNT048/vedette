// @mobile smoke on the real backend (WP-30 slice 10): the main screens at phone width (Pixel 7) as the administrator. Each must show its heading,
// throw no script error and not scroll sideways. The 5xx and 404 map of every route is gaps.spec.ts (desktop); this only proves the phone layout.
import { expect, test } from '@playwright/test'
import { authFile } from './box'
import { h1 } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

const ROUTES = ['/', '/devices', '/findings', '/honeypot', '/response', '/logs', '/scans', '/assistant', '/account', '/settings/general', '/settings/users', '/settings/network', '/settings/privacy', '/settings/data']

for (const route of ROUTES) {
  test(`@mobile ${route} fits the phone screen with no script error`, async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto(route)
    await expect(h1(page), `${route} has a heading`).toBeVisible()
    await page.waitForLoadState('networkidle')
    const { scroll, width } = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, width: window.innerWidth }))
    expect(scroll, `${route} scrolls sideways (${scroll}px in a ${width}px screen)`).toBeLessThanOrEqual(width)
    expect(errors.filter((e) => !/status of [45]\d\d/.test(e)), `${route}: script errors`).toEqual([])
  })
}
