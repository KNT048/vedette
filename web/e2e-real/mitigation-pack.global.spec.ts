// A confirmed mitigation pack on the real backend (S-MIT-1): the confirmed view, the firewall guide per vendor, "Applied" writing the log, the
// compromise checklist, and a viewer who may read but not mark. The box cannot load a signed pack (the release key is offline), so each test
// gives its made-up CVE the pack of content/mitigation/testdata through the control route of the box (seedPack, cmd/vedette/e2epack_test.go).
// Steps from e2e/qa/findings-box.spec.ts. Global project: the finding comes from the box-wide CISA mirror address (findings-seed.ts).
import { expect, test, type Page } from '@playwright/test'
import { api, authFile } from './box'
import { as, finding, seed, seedPack, startFeedServer, stopFeedServer, sweep } from './findings-seed'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })
test.beforeAll(startFeedServer)
test.afterAll(stopFeedServer)
test.afterEach(sweep)

const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()

test.describe('a finding with a confirmed pack (S-MIT-1, S-MIT-3, mitigation INV-1)', () => {
  test.use({ storageState: authFile('operator') }) // an operator marks "Applied"; the viewer test makes its own context
  test.use({ storageState: authFile('operator') }) // an operator marks "Applied"; the viewer test makes its own context
  test('the pack says who confirmed it, shows the device address, switches vendor, logs "Applied" once and keeps it after a reload', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const s = await seed()
    await seedPack(s.cve)
    await page.goto(`/findings/${s.findingId}`)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
    await expect(page.getByText(/Photo Station 6\.1\.2/).first()).toBeVisible()
    await expect(page.getByText('No confirmed recommendation yet')).toHaveCount(0)
    for (const placeholder of ['{IP}', '{HOST}']) await expect(page.locator('body')).not.toContainText(placeholder)
    await expect(page.getByText('Have I been hit?')).toBeVisible()
    await expect(page.getByText(/deadbolt/i).first()).toBeVisible()
    await expectAccessible(page, 'finding with a pack')
    await noVietnamese(page, 'finding with a pack')

    // the firewall vendor changes the commands shown, and the device address is in them
    const ip = s.ip.replaceAll('.', '[.]')
    const vendors = [
      { name: /FortiGate/, code: new RegExp(`show firewall vip \\| grep -f ${ip}`), other: 'dst-address=' },
      { name: /MikroTik/, code: new RegExp(`(to-addresses|dst-address)=${ip}`), other: 'show firewall vip' },
      { name: /Other device/, code: null, other: 'show firewall vip' },
    ]
    for (const v of vendors) {
      await page.getByRole('button', { name: v.name }).click()
      await expect(page.getByRole('button', { name: v.name })).toHaveAttribute('aria-pressed', 'true')
      if (v.code) await expect(page.getByText(v.code).first()).toBeVisible()
      await expect(page.getByText(v.other, { exact: false }).first()).toBeHidden()
      await expect(page.locator('body')).not.toContainText('{IP}')
    }

    // "Applied" writes the log entry and never changes the status; a second POST for the same item is not a second row
    await page.getByRole('button', { name: /MikroTik/ }).click()
    const heading = await h1(page).innerText()
    await page.getByRole('button', { name: 'Applied' }).last().click()
    await toast(page, /Logged\. Rescan to confirm/)
    await expect(page.getByText(/Recorded as applied by \S+@\S+/).first()).toBeVisible()
    await page.reload()
    await page.getByRole('button', { name: /MikroTik/ }).click()
    await expect(page.getByText(/Recorded as applied by \S+@\S+/).first()).toBeVisible()
    await expect(h1(page)).toHaveText(heading)
    await expect(page.getByText(/^Applied: /).first()).toBeVisible()

    const op = await as('operator')
    try {
      const d = (await finding(op, s.findingId)).body
      expect(d.status).toBe('suspected')
      expect(d.applied.length).toBe(1)
      const item = (d.applied[0] as { item: string }).item
      expect((await api(op, 'POST', `/findings/${s.findingId}/applied`, { item })).status).toBe(200)
      expect((await finding(op, s.findingId)).body.applied.length).toBe(1)
    } finally { await op.dispose() }
    noErrors(errors)
  })

  test('a viewer reads the pack; every "Applied" button is locked and the API refuses with 403', async ({ browser }) => {
    test.setTimeout(120_000)
    const s = await seed()
    await seedPack(s.cve)
    const ctx = await browser.newContext({ storageState: authFile('viewer') })
    const page = await ctx.newPage()
    try {
      await page.goto(`/findings/${s.findingId}`)
      await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
      for (const b of await page.getByRole('button', { name: 'Applied' }).all()) {
        await expect(b).toBeDisabled()
        await expect(b).toHaveAttribute('title', /Operator/)
      }
      const v = await as('viewer')
      try {
        const r = await api(v, 'POST', `/findings/${s.findingId}/applied`, { item: 'patch' })
        expect(r.status).toBe(403)
        expect((await finding(v, s.findingId)).body.applied).toEqual([])
      } finally { await v.dispose() }
    } finally { await ctx.close() }
  })
})
