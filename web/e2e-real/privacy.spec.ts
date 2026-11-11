// Settings -> Privacy on the real backend (S-CORE-4, D-153, PRIVACY.md): the page lists the twelve flows that leave the box, their state is what
// GET /core/privacy says (flow 2, the anonymous signal, is shown as "Not sent" whatever the API reports: D-153), the one switch of the page
// (flow 6, the update check) is the API's `update_check` and a change survives a reload, and the signal is not offered as a choice.
// Where the backend still disagrees with PRIVACY.md (the signal counts as ON when nothing is stored, and PATCH accepts `telemetry: true`)
// the test is test.fail() with the deferred line that tracks it (D-171): it turns red when the bug is fixed.
import { expect, request, test, type Page } from '@playwright/test'
import { api, authFile, box } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

interface Privacy { flows: { id: number; state: 'on' | 'off' | 'conditional'; control: string }[]; telemetry: { enabled: boolean; last_sent: string | null; payload: object }; update_check: boolean }
const SHOWN = { on: 'Running', off: 'Off', conditional: 'Only if you configure it' } as const
const table = (page: Page) => page.getByRole('table', { name: 'Data flows that leave the box' })
const updateSwitch = (page: Page) => page.getByRole('switch', { name: 'Automatic update check' })

test('the page lists the twelve flows with the state the API reports, and no choice about the anonymous signal', async ({ page }) => {
  const errors = collectErrors(page)
  const got = await api<Privacy>(page.request, 'GET', '/core/privacy')
  expect(got.status).toBe(200)
  expect(got.body.flows.map((f) => f.id), 'the twelve flows of PRIVACY.md, in order').toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
  await page.goto('/settings/privacy')
  await expect(h1(page)).toContainText('connects out only for the flows listed below')
  await expectAccessible(page, 'privacy')
  await expect(table(page).locator('tbody tr')).toHaveCount(12)
  for (const f of got.body.flows) {
    const row = table(page).getByRole('row').filter({ has: page.getByRole('cell', { name: new RegExp(`^${f.id}\\. `) }) })
    await expect(row, `flow ${f.id} has one row`).toHaveCount(1)
    // column 4 is "Now". Flow 2 is never sent (D-82, D-153): the page ignores what the API says for it.
    await expect(row.getByRole('cell').nth(3), `flow ${f.id}`).toHaveText(f.id === 2 ? 'Not sent' : SHOWN[f.state])
  }
  await expect(page.getByText(/Anonymous signal: not sent\./)).toBeVisible()
  await expect(page.getByRole('switch', { name: 'Send anonymous signal' })).toHaveCount(0)
  await expect(page.getByLabel('JSON, exactly what would be sent')).toHaveCount(0)
  await expect(page.getByRole('switch'), 'the update check is the only switch on the page').toHaveCount(1)
  await shot(page, 'real', 'privacy')
  await noVietnamese(page, 'privacy')
  noErrors(errors)
})

test('the update-check switch is the API setting, a change is saved, audited and still there after a reload', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const before = (await api<Privacy>(page.request, 'GET', '/core/privacy')).body.update_check
  const flow6 = () => table(page).getByRole('row').filter({ has: page.getByRole('cell', { name: /^6\. / }) }).getByRole('cell').nth(3)
  try {
    await page.goto('/settings/privacy')
    if (before) await expect(updateSwitch(page)).toBeChecked()
    else await expect(updateSwitch(page)).not.toBeChecked()
    await expect(flow6()).toHaveText(before ? 'Running' : 'Off')
    await updateSwitch(page).click()
    await expect(page.locator('[data-sonner-toast]').filter({ hasText: /Saved/ }).first()).toBeVisible()
    expect((await api<Privacy>(page.request, 'GET', '/core/privacy')).body.update_check).toBe(!before)
    await expect(flow6()).toHaveText(before ? 'Off' : 'Running')
    await page.reload()
    if (before) await expect(updateSwitch(page)).not.toBeChecked()
    else await expect(updateSwitch(page)).toBeChecked()
    await expect(flow6()).toHaveText(before ? 'Off' : 'Running')
    const log = await api<{ items: { action: string; user: string; detail?: string }[] }>(page.request, 'GET', '/core/audit?q=privacy.update_check')
    expect(log.body.items[0]).toMatchObject({ action: 'privacy.update_check', user: 'admin@e2e.test', detail: before ? 'off' : 'on' })
    noErrors(errors)
  } finally {
    await api(page.request, 'PATCH', '/core/privacy', { update_check: before })
  }
})

test('a viewer and an operator read the page and cannot change it', async () => {
  for (const role of ['viewer', 'operator'] as const) {
    const c = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    expect((await api(c, 'GET', '/core/privacy')).status).toBe(200)
    expect((await api(c, 'PATCH', '/core/privacy', { update_check: false })).status).toBe(403)
    await c.dispose()
  }
})

// test.fail (D-171): .ai/deferred/fix-privacy-accuracy.md:2 (before release: report the signal as off, refuse to turn it on).
test('the API reports the anonymous signal as not sent, like PRIVACY.md flow 2 and the page', async ({ page }) => {
  test.fail(true, 'bug: GET /core/privacy reports flow 2 as on until a value is stored (.ai/deferred/fix-privacy-accuracy.md:2)')
  const got = (await api<Privacy>(page.request, 'GET', '/core/privacy')).body
  expect(got.flows.find((f) => f.id === 2)?.state).toBe('off')
  expect(got.telemetry.enabled).toBe(false)
  expect(got.telemetry.last_sent).toBeNull()
})

test('the API refuses to turn the anonymous signal on', async ({ page }) => {
  test.fail(true, 'bug: PATCH /core/privacy accepts telemetry:true and stores it (.ai/deferred/fix-privacy-accuracy.md:2)')
  const r = await api(page.request, 'PATCH', '/core/privacy', { telemetry: true })
  expect(r.status).toBeGreaterThanOrEqual(400)
  expect(r.status).toBeLessThan(500)
})
