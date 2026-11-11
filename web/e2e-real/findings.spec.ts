// The findings and mitigation modules on the real backend, on a box with no internet (S-MIT-1, findings PRE-3, INV-3).
// Tests that need a finding are in findings.global.spec.ts (a finding comes from the cisa-kev mirror address on loopback + a declared device, see findings-seed.ts); this file is what needs none.
// Steps from e2e/qa/findings.spec.ts.
import { expect, test, type Page } from '@playwright/test'
import { api, authFile, uniq } from './box'
import { as, type Row } from './findings-seed'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })

const SEV: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' }
const STATUS: Record<string, string> = { confirmed: 'Confirmed', suspected: 'Suspected', mitigated: 'Mitigated', patched: 'Patched', false_positive: 'False positive', not_relevant: 'Not relevant' }
const BASIS: Record<string, string> = { scan: 'Confirmed by scan', version: 'By version', product: 'Product match only' }
/** The headline of the list, worked out from what the API says now (open = confirmed or suspected). */
async function headlineNow(): Promise<string> {
  const c = await as('viewer')
  try {
    const items = (await api<{ items: Row[] }>(c, 'GET', '/findings')).body.items
    const open = items.filter((i) => i.status === 'confirmed' || i.status === 'suspected').length
    const confirmed = items.filter((i) => i.status === 'confirmed').length
    return open === 0 ? 'No unresolved findings' : `${open} unresolved finding${open === 1 ? '' : 's'}, ${confirmed} confirmed`
  } finally { await c.dispose() }
}
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const table = (page: Page) => page.getByRole('table', { name: 'Findings list' })
const dialog = (page: Page) => page.getByRole('dialog', { name: 'Mark as handled' })
const statusPost = (page: Page, id: string) => page.waitForResponse((r) => r.url().endsWith(`/findings/${id}/status`) && r.request().method() === 'POST')

test.describe('the list with nothing of mine in it (S-MIT-1)', () => {
  test.use({ storageState: authFile('viewer') })

  test('an honest empty state: headline from the data, the way forward, no script error, accessible, English', async ({ page }) => {
    const errors = collectErrors(page)
    const server: string[] = []
    page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) server.push(`${r.url()} ${r.status()}`) })
    await page.goto('/findings')
    await expect(h1(page)).toHaveText(await headlineNow())
    // a CVE nobody has: the empty state says which filter it is, and points at Devices and the scans (the two ways to get a finding)
    await page.goto('/findings?cve=cve-2099-000001')
    await expect(page.getByText('No findings for CVE-2099-000001 in this filter.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Devices' }).first()).toHaveAttribute('href', '/devices')
    await expect(page.getByRole('link', { name: 'Open Vulnerability scans' }).first()).toHaveAttribute('href', '/scans')
    await expect(page.locator('body')).not.toContainText(/undefined|NaN|\[object|1970/)
    await page.getByRole('button', { name: 'Clear CVE-2099-000001 filter' }).click()
    await expect(page).not.toHaveURL(/cve=/)
    await expectAccessible(page, 'findings list')
    await noVietnamese(page, 'findings list')
    await shot(page, 'real', 'findings-list-empty')
    expect(server).toEqual([])
    noErrors(errors)
  })

  test('the API answers an empty or unknown request honestly, never a 5xx (INV-3, PRE-3)', async () => {
    const c = await as('viewer')
    try {
      const all = await api<{ items: unknown[] }>(c, 'GET', '/findings')
      expect(all.status).toBe(200)
      expect(Array.isArray(all.body.items)).toBe(true)
      const none = await api<{ items: unknown[] }>(c, 'GET', `/findings?asset=${uniq('no-such-device')}`)
      expect(none.status).toBe(200)
      expect(none.body.items).toEqual([])
      const missing = await api(c, 'GET', '/findings/does-not-exist')
      expect(missing.status).toBe(404)
      expect(missing.body).toMatchObject({ error: { code: 'not_found' } })
      expect((await api(c, 'GET', `/findings/${'x'.repeat(65)}`)).status).toBe(400) // PRE-3: an id is 1..64 characters
    } finally { await c.dispose() }
  })

  test('a finding that does not exist: the page says so and offers the way back', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/findings/does-not-exist')
    await expect(page.getByRole('alert').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Back to findings' })).toBeVisible()
    await expect(page.locator('body')).not.toContainText(/undefined|\[object|goroutine|sql:/)
    await noVietnamese(page, 'finding not found')
    noErrors(errors, /status of 404/)
  })
})

