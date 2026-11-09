// Helpers for the WP-06 independent UI check (docs/QA.md §3). Not a spec.
import { expect, type Page, type TestInfo } from '@playwright/test'
import { startWithSample } from '../helpers'

export const THEMES = ['light', 'dark'] as const
export type Theme = (typeof THEMES)[number]

/** Sample data, then the chosen theme (kept across reloads). */
export async function begin(page: Page, theme: Theme) {
  await startWithSample(page)
  await page.evaluate((v) => localStorage.setItem('vedette-theme', v), theme)
  await page.reload()
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
}

/** One screenshot per step: web/test-results/qa-wp06/<area>-<project>-<theme>-<NN>-<step>.png (git-ignored). */
export function stepper(page: Page, info: TestInfo, area: string, theme: Theme) {
  let n = 0
  return async (name: string) => {
    n += 1
    await page.screenshot({ path: `test-results/qa-wp06/${area}-${info.project.name}-${theme}-${String(n).padStart(2, '0')}-${name}.png`, fullPage: true })
  }
}

export const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `horizontal scroll: ${where}`).toBeLessThanOrEqual(1)

/** Words that must not appear in the core UI (D-58). Template data and examples are allowed to carry brand names, so callers scope this. */
export const BRANDS = /forti|pfsense|cisco|mikrotik|palo ?alto|juniper|ubiquiti|unifi|aruba|sophos|opnsense|checkpoint|sonicwall|huawei|tp-?link|omada/i
export const VENDOR_PATHS = /\/api\/v2\/cmdb|\/api\/v2\/monitor|cmdb\/firewall|config firewall|ip access-list/i
