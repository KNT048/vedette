// Reports -> the print pages /reports/print/weekly, /weekly/:id and /pdpl opened with real data on the real backend (S-REP-1, S-REP-2).
// The seed makes one real finding (its CVE must be in the weekly tables), a send makes one history row, the assessment is filled and generated.
// Each page: its title, a real row or section, no console error, no "HTTP 4xx/5xx" text. Global project: reports module, schedule, assessment are box-wide; put back at the end.
import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, ensureEmailChannel } from './box'
import { as, seed, startFeedServer, stopFeedServer, sweep } from './findings-seed'
import { collectErrors } from '../e2e/helpers'
import { noErrors } from './ui'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Sched { enabled: boolean; day: number; hour: number; recipients: string[] }
const ORG = 'Print Check Ltd'
let admin: APIRequestContext
let wasOn = false
let original: Sched
let cve = ''
let histId = ''

test.beforeAll(async () => {
  admin = await as('admin')
  const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(admin, 'GET', '/modules')
  wasOn = !!mods.body.modules.find((m) => m.id === 'reports')?.enabled
  if (!wasOn) expect((await api(admin, 'PATCH', '/modules/reports', { enabled: true, with_dependencies: true })).status).toBe(200)
  original = (await api<Sched>(admin, 'GET', '/reports/schedule')).body
  await startFeedServer()
  cve = (await seed()).cve
  await ensureEmailChannel(admin)
  const to = { enabled: false, day: 1, hour: 8, recipients: ['ops@e2e.test'] }
  expect((await api(admin, 'PUT', '/reports/schedule', to)).status).toBe(200)
  const sent = await api<{ id: string }>(admin, 'POST', '/reports/weekly/send')
  expect(sent.status, JSON.stringify(sent.body)).toBeLessThan(300)
  histId = sent.body.id
  const org = { name: ORG, tax_code: '0100000001', address: '1 Test Street', sector: 'retail', employees: 20, data_volume: 'lt1k', size: 'micro', processing_service: false, contact_name: 'Test Owner', contact_email: 'owner@e2e.test', contact_phone: '0900000000', sensitive: false, cross_border: false, processors: false, level: '' }
  expect((await api(admin, 'PUT', '/reports/pdpl/org', org)).status).toBe(200)
  const gen = await api(admin, 'POST', '/reports/pdpl/generate')
  expect(gen.status, JSON.stringify(gen.body)).toBeLessThan(300)
})
test.afterAll(async () => {
  try {
    if (original) await api(admin, 'PUT', '/reports/schedule', { enabled: original.enabled, day: original.day, hour: original.hour, recipients: original.recipients })
    if (!wasOn) await api(admin, 'PATCH', '/modules/reports', { enabled: false })
    await sweep()
  } finally { await stopFeedServer(); await admin.dispose() }
})

const noHttpText = async (page: Page) => expect(await page.locator('body').innerText()).not.toMatch(/HTTP [45]\d\d/)

for (const kind of ['current', 'history'] as const) {
  test(`weekly print page (${kind}): title, the seeded finding in the tables, no error`, async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto(kind === 'current' ? '/reports/print/weekly' : `/reports/print/weekly/${histId}`)
    await expect(page.getByRole('heading', { level: 1, name: 'Weekly report, print view' })).toBeVisible()
    const doc = page.getByRole('article', { name: 'Weekly security report' })
    await expect(doc).toBeVisible()
    await expect(doc.getByRole('cell', { name: cve }).first(), 'the seeded finding is a real row').toBeVisible()
    await noHttpText(page)
    noErrors(errors)
  })
}

test('assessment print page: title, organisation section with the saved name, a measure section, no error', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/reports/print/pdpl')
  await expect(page.getByRole('heading', { level: 1, name: 'Assessment report, print view' })).toBeVisible()
  const doc = page.getByRole('article', { name: 'Information security and personal data assessment report' })
  await expect(doc).toBeVisible()
  await expect(doc.getByText(ORG).first()).toBeVisible()
  await expect(doc.getByRole('heading', { name: '3. Technical protection measures' })).toBeVisible()
  await noHttpText(page)
  noErrors(errors)
})
