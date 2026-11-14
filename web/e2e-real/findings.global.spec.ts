// The findings and mitigation modules with a finding on the box (S-MIT-1, S-INV-2, S-CORE-1, S-CORE-3, findings INV-1..3, INV-4 (product match only), INV-7, mitigation INV-1/3; S-MIT-3 only as "no confirmed exploitation signs", there is no pack).
// Global project: a finding comes from the CISA list, so every test here uses the box-wide mirror address of that feed (findings-seed.ts), and the mitigation
// switch at the end is box-wide too. Every test has a finding of its own (unique vendor, product, device, CVE-2099-*) and removes its device afterwards.
// Steps from e2e/qa/findings.spec.ts.
import { expect, test, type Page } from '@playwright/test'
import { ACCOUNTS, api, authFile, box, uniq } from './box'
import { as, finding, seed, startFeedServer, stopFeedServer, sweep, type Row, type Seed } from './findings-seed'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })
test.beforeAll(startFeedServer)
test.afterAll(stopFeedServer)
test.afterEach(sweep)

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

test.describe('a finding made through the CISA list and a device (S-MIT-1, S-INV-2, INV-1, INV-4 product match)', () => {
  test.use({ storageState: authFile('viewer') })
  let s: Seed

  test('the device gets exactly one suspected finding, matched by product, and the list, filters and row say so', async ({ page }) => {
    test.setTimeout(120_000)
    s = await seed()
    const errors = collectErrors(page)
    const c = await as('viewer')
    let row: Row
    try {
      const items = (await api<{ items: Row[] }>(c, 'GET', `/findings?asset=${s.deviceId}`)).body.items
      expect(items).toHaveLength(1) // INV-1: one finding per (device, CVE)
      row = items[0]!
      expect(row).toMatchObject({ id: s.findingId, asset_id: s.deviceId, cve: s.cve, status: 'suspected', basis: 'product', resolved_by: null, resolution_note: null })
      expect(row.confidence).toBeGreaterThan(0) // INV-2: a number in 0..1, and a product match is not a certainty
      expect(row.confidence).toBeLessThan(0.95)
      expect(row.asset).toMatchObject({ id: s.deviceId, hostname: s.host, ip: s.ip })
      expect(row.kev).toMatchObject({ vendor: s.vendor, product: s.product })
      expect(row.history.map((h) => h.action)).toEqual(['created'])
      expect(row.history[0]!.user).toBe('system')
      // the filter by device returns only this finding; the full list has it too
      expect((await api<{ items: Row[] }>(c, 'GET', '/findings')).body.items.map((i) => i.id)).toContain(row.id)
    } finally { await c.dispose() }

    await page.goto(`/findings?cve=${s.cve.toLowerCase()}`) // the page upper-cases the ?cve filter
    await expect(h1(page)).toHaveText(await headlineNow())
    await expect(table(page).getByRole('row')).toHaveCount(2) // header + the finding
    const line = table(page).getByRole('row').filter({ hasText: s.cve })
    await expect(line).toContainText(s.host)
    await expect(line).toContainText(s.ip)
    await expect(line).toContainText(STATUS[row.status]!)
    await expect(line).toContainText(SEV[row.severity]!)
    await expect(line).toContainText(BASIS[row.basis]!)
    await expect(line.getByRole('link', { name: s.host })).toHaveAttribute('href', `/devices/${s.deviceId}`)
    await expectAccessible(page, 'findings list with a finding')
    await noVietnamese(page, 'findings list with a finding')
    await shot(page, 'real', 'findings-list')

    // the status filters: suspected is unresolved; confirmed and the Handled tab do not have it; all unresolved does
    const filter = (name: string) => page.getByRole('button', { name, exact: true })
    const none = page.getByText(`No findings for ${s.cve} in this filter.`)
    await filter('Confirmed').click()
    await expect(none).toBeVisible()
    await page.getByRole('tab', { name: /^Handled/ }).click()
    await expect(none).toBeVisible()
    await page.getByRole('tab', { name: /^Open/ }).click()
    for (const name of ['Suspected', 'All unresolved']) {
      await filter(name).click()
      await expect(line, name).toBeVisible()
      await expect(none, name).toHaveCount(0)
    }
    // the table's own filter, by device name, and clearing the CVE filter
    await page.getByRole('button', { name: `Clear ${s.cve} filter` }).click()
    await expect(page).not.toHaveURL(/cve=/)
    await page.getByPlaceholder('Filter by device, CVE, product').fill(s.host)
    await expect(table(page).getByRole('row')).toHaveCount(2)
    await page.getByPlaceholder('Filter by device, CVE, product').fill(uniq('nothing-called-this'))
    await expect(table(page).getByRole('row').filter({ hasText: s.cve })).toHaveCount(0)
    // open the finding from the row, and come back
    await page.goto(`/findings?cve=${s.cve}`)
    await table(page).getByRole('link', { name: s.cve }).click()
    await expect(page).toHaveURL(new RegExp(`/findings/${s.findingId}$`))
    await page.goBack()
    await expect(page).toHaveURL(/\/findings\?cve=/)
    noErrors(errors)
  })

  test('the detail page: headline, evidence, history, device link, and the "What to do" panel says there is no confirmed recommendation', async ({ page }) => {
    test.setTimeout(120_000)
    s = await seed()
    const errors = collectErrors(page)
    const c = await as('viewer')
    let d: Awaited<ReturnType<typeof finding>>['body']
    try { d = (await finding(c, s.findingId)).body } finally { await c.dispose() }
    // mitigation INV-2 and the contract: no signed pack is loaded on this box, so pack is null; nothing from the AI; no "applied" entries
    expect(d.pack).toBeNull()
    expect(d.applied).toEqual([])
    expect(d.ai).toEqual({ explain: null, config: null })
    expect(d.ai_available).toEqual({ explain: false, config: false }) // no AI profile on a fresh box (D-29)
    expect(d.kev).not.toBeNull()

    await page.goto(`/findings/${s.findingId}`)
    await expect(h1(page)).toHaveText(`${s.host} may be affected by ${s.cve}: needs checking`)
    await expect(page.getByText(STATUS.suspected!, { exact: true }).first()).toBeVisible()
    await expect(page.getByText(SEV[d.severity]!, { exact: true }).first()).toBeVisible()
    const ev = page.locator('#evidence')
    await expect(ev).toContainText(BASIS.product!)
    await expect(ev).toContainText(new Intl.NumberFormat('en-GB', { style: 'percent', maximumFractionDigits: 0 }).format(d.confidence)) // the page's own fmtPercent(confidence, 0)
    await expect(page.getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', `/scans?target=${s.deviceId}`)
    await expect(page.getByRole('link', { name: `Open ${s.cve} page` })).toHaveAttribute('href', `/cve/${s.cve}`)
    await expect(page.getByRole('link', { name: s.host }).first()).toHaveAttribute('href', `/devices/${s.deviceId}`)
    await expect(page.getByText(s.ip, { exact: true }).first()).toBeVisible()
    // history: created by the system
    const hist = page.getByRole('region', { name: 'History' }).or(page.locator('section[aria-labelledby="hist-title"]'))
    await expect(hist).toContainText('Finding created')
    await expect(hist).toContainText('system')
    // What to do (mitigation): no pack, so it says so instead of inventing steps, and shows the source information (D-21)
    await expect(page.getByText('No confirmed recommendation yet')).toBeVisible()
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true })).toHaveCount(0)
    await expect(page.getByRole('heading', { name: 'Source information' })).toBeVisible()
    await expect(page.getByText(d.kev!.required_action)).toBeVisible() // CISA's own words, in the page's language of origin
    expect(d.kev!.links).toEqual(['https://advisory.example/qa']) // KEV "notes" are links; the page renders each as an anchor (Recommendation.tsx NoPack)
    await expect(page.getByRole('link', { name: 'https://advisory.example/qa' })).toHaveAttribute('href', 'https://advisory.example/qa')
    await expect(page.getByRole('button', { name: 'Applied' })).toHaveCount(0) // no pack, nothing to mark as applied
    await expect(page.getByRole('button', { name: 'Ask my AI' })).toBeDisabled() // no AI profile
    await expect(page.getByText('The AI assistant is off, or no AI profile is assigned to this job.').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open AI assistant settings' }).first()).toHaveAttribute('href', '/settings/ai')
    await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
    // "Have I been hit?" without a pack: the honest sentence
    await expect(page.getByText('No confirmed exploitation signs for this CVE yet.', { exact: false })).toBeVisible()
    await expectAccessible(page, 'finding detail')
    await noVietnamese(page, 'finding detail')
    await shot(page, 'real', 'finding-detail')
    noErrors(errors)
  })

  test('the device removal takes its findings with it (INV-7)', async () => {
    test.setTimeout(120_000)
    s = await seed()
    const admin = await as('admin')
    try {
      expect([200, 204]).toContain((await api(admin, 'DELETE', `/inventory/devices/${s.deviceId}`)).status)
      await expect.poll(async () => (await api<{ items: Row[] }>(admin, 'GET', `/findings?asset=${s.deviceId}`)).body.items.length, { message: 'the finding goes with the device', timeout: 30_000 }).toBe(0)
      expect((await finding(admin, s.findingId)).status).toBe(404)
    } finally { await admin.dispose() }
  })
})

test.describe('status changes as an operator (S-MIT-1, INV-3)', () => {
  test.use({ storageState: authFile('operator') })

  test('false positive needs a reason: the dialog refuses, saves with one, history and list follow, reopen puts it back', async ({ page }) => {
    test.setTimeout(150_000)
    const s = await seed()
    const errors = collectErrors(page)
    const posts: string[] = []
    page.on('request', (r) => { if (r.method() === 'POST' && r.url().includes('/status')) posts.push(r.url()) })
    const operator = ACCOUNTS.operator.email
    await page.goto(`/findings/${s.findingId}`)
    const mark = page.getByRole('button', { name: 'Mark as handled' })
    await expect(mark).toBeEnabled()
    await mark.click()
    const dlg = dialog(page)
    await expect(dlg).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dlg).toHaveCount(0)
    await expect(mark).toBeFocused()
    await mark.click()
    await dlg.getByRole('radio', { name: /^False positive/ }).click()
    await expect(dlg.getByText('Note: why (required)')).toBeVisible()
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    await dlg.getByLabel(/^Note/).fill('ab')
    await dlg.getByRole('button', { name: 'Save status' }).click()
    await expect(dlg.getByLabel(/^Note/)).toHaveAttribute('aria-invalid', 'true') // still refused after the click on "ab"
    await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
    expect(posts, 'a refused form sends nothing').toEqual([])
    const note = `Checked by hand ${uniq('fp')}`
    await dlg.getByLabel(/^Note/).fill(note)
    const saved = statusPost(page, s.findingId)
    await dlg.getByRole('button', { name: 'Save status' }).click()
    expect((await saved).status()).toBe(200)
    await toast(page, /Status updated/)
    await expect(dlg).toHaveCount(0)
    await expect(h1(page)).toHaveText(`${s.host}: ${s.cve} marked as false positive`)
    await expect(page.getByText(note)).toBeVisible()
    await expect(page.getByText('Marked as false positive', { exact: true })).toBeVisible()
    await expect(page.getByText(operator).first()).toBeVisible()
    await expect(page.getByRole('button', { name: 'Reopen finding' })).toBeVisible()
    // the server has the same: status, who, why, one more history row
    const c = await as('viewer')
    try {
      const d = (await finding(c, s.findingId)).body
      expect(d).toMatchObject({ status: 'false_positive', resolved_by: operator, resolution_note: note })
      expect(d.resolved_at).not.toBeNull()
      expect(d.history.map((h) => h.action)).toEqual(['created', 'false_positive'])
      expect(d.history[1]).toMatchObject({ user: operator, note })
    } finally { await c.dispose() }
    await page.reload()
    await expect(h1(page)).toHaveText(`${s.host}: ${s.cve} marked as false positive`)
    // the list: resolved now, so the unresolved view does not have it and the Handled tab does
    await page.goto(`/findings?cve=${s.cve}`)
    await expect(h1(page)).toHaveText(await headlineNow())
    await expect(page.getByText(`No findings for ${s.cve} in this filter.`)).toBeVisible()
    await page.getByRole('tab', { name: /^Handled/ }).click()
    await expect(table(page).getByRole('row').filter({ hasText: s.cve })).toContainText('False positive')
    // reopen
    await page.goto(`/findings/${s.findingId}`)
    const again = statusPost(page, s.findingId)
    await page.getByRole('button', { name: 'Reopen finding' }).click()
    expect((await again).status()).toBe(200)
    await toast(page, /Finding reopened/)
    await expect(h1(page)).toHaveText(`${s.host} may be affected by ${s.cve}: needs checking`)
    const v = await as('viewer')
    try {
      const d = (await finding(v, s.findingId)).body
      expect(d.status).toBe('suspected')
      expect(d.history.map((h) => h.action)).toEqual(['created', 'false_positive', 'reopened']) // append-only history
    } finally { await v.dispose() }
    noErrors(errors)
  })

  test('mitigated without a note, then patched: the headline and the lists follow', async ({ page }) => {
    test.setTimeout(150_000)
    const s = await seed()
    const errors = collectErrors(page)
    await page.goto(`/findings/${s.findingId}`)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await dialog(page).getByRole('radio', { name: /^Mitigated/ }).click()
    const done = statusPost(page, s.findingId)
    await dialog(page).getByRole('button', { name: 'Save status' }).click()
    expect((await done).status()).toBe(200)
    await expect(h1(page)).toHaveText(`${s.host}: ${s.cve} is mitigated, patching is still needed to remove it`)
    // mitigated is resolved in the list (patching is still needed, but it is no longer "unresolved")
    await page.goto(`/findings?cve=${s.cve}`)
    await page.getByRole('tab', { name: /^Handled/ }).click()
    await expect(table(page).getByRole('row').filter({ hasText: s.cve })).toContainText('Mitigated')
    // from mitigated straight to patched is allowed through the dialog of an open finding only after a reopen, so reopen first
    await page.goto(`/findings/${s.findingId}`)
    const r = statusPost(page, s.findingId)
    await page.getByRole('button', { name: 'Reopen finding' }).click()
    expect((await r).status()).toBe(200)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    const p = statusPost(page, s.findingId)
    await dialog(page).getByRole('radio', { name: /^Patched/ }).click()
    await dialog(page).getByRole('button', { name: 'Save status' }).click()
    expect((await p).status()).toBe(200)
    await expect(h1(page)).toHaveText(`${s.host}: ${s.cve} is patched`)
    const v = await as('viewer')
    try {
      const d = (await finding(v, s.findingId)).body
      expect(d.status).toBe('patched')
      expect(d.history.map((h) => h.action)).toEqual(['created', 'mitigated', 'reopened', 'patched'])
    } finally { await v.dispose() }
    noErrors(errors)
  })

  test('the API validates the change: reasons, lengths, unknown action and id, reopen of an open finding; a refusal changes nothing (INV-3)', async () => {
    test.setTimeout(120_000)
    const s = await seed()
    const op = await as('operator')
    const post = (id: string, body: unknown) => api<{ error: { code: string } }>(op, 'POST', `/findings/${id}/status`, body)
    try {
      const before = (await finding(op, s.findingId)).body
      for (const action of ['false_positive', 'not_relevant']) {
        for (const note of ['', 'ab']) {
          const r = await post(s.findingId, { action, note })
          expect(r.status, `${action} with note "${note}"`).toBe(400)
          expect(r.body).toMatchObject({ error: { code: 'note_required' } })
        }
      }
      const r501 = await post(s.findingId, { action: 'mitigated', note: 'x'.repeat(501) })
      expect(r501.status).toBe(400)
      expect(r501.body).toMatchObject({ error: { code: 'invalid' } }) // exact: the OpenAPI schema (maxLength 500) refuses it before the handler, as the "Không khớp" section of findings CONTRACT says; INV-3's `note_too_long` is reachable only for a note of <= 500 characters but > 500 UTF-16 units
      expect((await post(s.findingId, { action: 'delete', note: '' })).status).toBe(400) // an action that does not exist
      expect((await post(s.findingId, { note: 'no action' })).status).toBe(400)
      const open = await post(s.findingId, { action: 'reopen', note: '' })
      expect(open.status).toBe(409)
      expect(open.body).toMatchObject({ error: { code: 'already_open' } })
      const none = await post('does-not-exist', { action: 'patched', note: '' })
      expect(none.status).toBe(404)
      const after = (await finding(op, s.findingId)).body
      expect(after.status, 'every refusal left the finding as it was').toBe('suspected')
      expect(after.history).toEqual(before.history)
      expect(after.last_seen).toBe(before.last_seen)
      // the limits themselves are accepted: 3 characters for a reason, 500 for a note
      const edge = await post(s.findingId, { action: 'not_relevant', note: 'abc' })
      expect(edge.status, JSON.stringify(edge.body)).toBe(200)
      expect((await post(s.findingId, { action: 'reopen', note: '' })).status).toBe(200)
      const long = 'n'.repeat(500)
      expect((await post(s.findingId, { action: 'mitigated', note: long })).status).toBe(200)
      const d = (await finding(op, s.findingId)).body
      expect(d.resolution_note).toBe(long)
      expect(d.history.map((h) => h.action)).toEqual(['created', 'not_relevant', 'reopened', 'mitigated'])
      // a finding that is resolved is not "reopened" twice, and "patched" on a resolved finding is the person's call (it is accepted)
      expect((await post(s.findingId, { action: 'patched', note: '' })).status).toBe(200)
    } finally { await op.dispose() }
  })

  test('mitigation: "Applied" has no pack to mark, and the AI is unavailable, both with a precise refusal and no change (INV-1, INV-3)', async () => {
    test.setTimeout(120_000)
    const s = await seed()
    const op = await as('operator')
    try {
      const before = (await finding(op, s.findingId)).body
      const applied = await api<{ error: { code: string } }>(op, 'POST', `/findings/${s.findingId}/applied`, { item: 'patch' })
      expect(applied.status).toBe(400)
      expect(applied.body).toMatchObject({ error: { code: 'no_pack' } })
      expect((await api(op, 'POST', `/findings/${s.findingId}/applied`, { item: 'nonsense' })).status).toBe(400)
      for (const skill of ['explain', 'mitigation-config']) {
        const ai = await api<{ error: { code: string } }>(op, 'POST', `/findings/${s.findingId}/ai`, { skill })
        expect(ai.status, skill).toBe(409)
        expect(ai.body, skill).toMatchObject({ error: { code: 'ai_unavailable' } })
      }
      expect((await api(op, 'POST', `/findings/${s.findingId}/ai`, { skill: 'delete-everything' })).status).toBe(400)
      const after = (await finding(op, s.findingId)).body
      expect(after.applied).toEqual([])
      expect(after.ai).toEqual({ explain: null, config: null })
      expect(after.history).toEqual(before.history)
    } finally { await op.dispose() }
  })
})

test.describe('roles (S-MIT-1, S-CORE-3)', () => {
  test('a viewer reads everything and changes nothing: controls locked with the reason, the API says 403, the finding stays as it was', async ({ browser }) => {
    test.setTimeout(150_000)
    const s = await seed()
    const context = await browser.newContext({ baseURL: box().base_url, storageState: authFile('viewer'), locale: 'vi-VN' })
    try {
      const page = await context.newPage()
      const errors = collectErrors(page)
      await page.goto(`/findings/${s.findingId}`)
      await expect(h1(page)).toHaveText(`${s.host} may be affected by ${s.cve}: needs checking`)
      const mark = page.getByRole('button', { name: 'Mark as handled' })
      await expect(mark).toBeDisabled()
      await expect(mark).toHaveAttribute('title', 'Requires Operator role')
      await expect(page.getByRole('button', { name: 'Ask my AI' })).toBeDisabled()
      await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
      await expectAccessible(page, 'viewer finding detail')
      await noVietnamese(page, 'viewer finding detail')
      // the server says the same, for every write of both modules
      const c = page.request
      expect((await api(c, 'GET', '/findings')).status).toBe(200)
      expect((await api(c, 'GET', `/findings/${s.findingId}`)).status).toBe(200)
      for (const [method, path, body] of [['POST', `/findings/${s.findingId}/status`, { action: 'patched', note: '' }], ['POST', `/findings/${s.findingId}/applied`, { item: 'patch' }], ['POST', `/findings/${s.findingId}/ai`, { skill: 'explain' }], ['GET', '/core/audit', undefined]] as const) {
        const r = await api<{ error: { code: string } }>(c, method, path, body) // the audit log is the administrator's
        expect(r.status, `${method} ${path}`).toBe(403)
        expect(r.body, `${method} ${path}`).toMatchObject({ error: { code: 'forbidden' } })
      }
      const admin = await as('admin')
      try {
        const d = (await finding(admin, s.findingId)).body
        expect(d.status).toBe('suspected')
        expect(d.history.map((h) => h.action)).toEqual(['created'])
      } finally { await admin.dispose() }
      noErrors(errors) // collectErrors already leaves out the browser's own 4xx lines
    } finally { await context.close() }
  })

  test('an operator changes a status but the audit log stays the administrator\'s; an administrator can change it too, and every change is in the audit log with who, what and why (S-CORE-3)', async () => {
    test.setTimeout(120_000)
    const s = await seed()
    const op = await as('operator'), admin = await as('admin')
    try {
      expect((await api(op, 'GET', '/core/audit')).status).toBe(403)
      const note = `Not a real device ${uniq('nr')}`
      expect((await api(op, 'POST', `/findings/${s.findingId}/status`, { action: 'not_relevant', note })).status).toBe(200)
      expect((await api(admin, 'POST', `/findings/${s.findingId}/status`, { action: 'reopen', note: '' })).status).toBe(200)
      expect((await api(admin, 'POST', `/findings/${s.findingId}/status`, { action: 'patched', note: 'Updated to 2.0' })).status).toBe(200)
      const d = (await finding(admin, s.findingId)).body
      expect(d).toMatchObject({ status: 'patched', resolved_by: ACCOUNTS.admin.email, resolution_note: 'Updated to 2.0' })
      expect(d.history.map((h) => [h.action, h.user])).toEqual([
        ['created', 'system'], ['not_relevant', ACCOUNTS.operator.email], ['reopened', ACCOUNTS.admin.email], ['patched', ACCOUNTS.admin.email],
      ])
      const log = await api<{ items: { action: string; user: string; target: string; detail?: string }[] }>(admin, 'GET', `/core/audit?q=${s.findingId}`)
      expect(log.status).toBe(200)
      const rows = log.body.items.filter((r) => r.target === s.findingId)
      expect(rows.map((r) => [r.action, r.user]).sort()).toEqual([
        ['findings.created', 'system'], ['findings.status', ACCOUNTS.admin.email], ['findings.status', ACCOUNTS.admin.email], ['findings.status', ACCOUNTS.operator.email],
      ])
      expect(rows.map((r) => r.detail)).toEqual(expect.arrayContaining([`${s.cve}: not_relevant: ${note}`, `${s.cve}: reopen`, `${s.cve}: patched: Updated to 2.0`]))
    } finally { await op.dispose(); await admin.dispose() }
  })
})

test.describe('mitigation switch (S-CORE-1)', () => {
  test.use({ storageState: authFile('admin') })
  test('mitigation off: the finding and its status changes stay, "What to do" says the module is off, its routes answer 404; on again brings it back', async ({ page }) => {
    test.setTimeout(150_000)
    const errors = collectErrors(page)
    const s = await seed()
    const admin = await as('admin')
    const state = async () => (await api<{ modules: { id: string; enabled: boolean }[] }>(admin, 'GET', '/modules')).body.modules.find((m) => m.id === 'mitigation')?.enabled
    try {
      expect(await state(), 'mitigation is on (mid-size bundle)').toBe(true)
      expect((await api(admin, 'PATCH', '/modules/mitigation', { enabled: false })).status).toBe(200)
      expect(await state()).toBe(false)
      // the routes of mitigation answer as if they did not exist (SYS-5); findings is untouched
      for (const [path, body] of [[`/findings/${s.findingId}/applied`, { item: 'patch' }], [`/findings/${s.findingId}/ai`, { skill: 'explain' }]] as const) {
        const r = await api(admin, 'POST', path, body)
        expect(r.status, path).toBe(404)
        expect(r.body, path).toMatchObject({ error: { code: 'not_found' } })
      }
      const d = (await finding(admin, s.findingId)).body
      expect(d).toMatchObject({ status: 'suspected', pack: null, compromise: null, applied: [] })
      expect((await api(admin, 'GET', `/findings?asset=${s.deviceId}`)).status).toBe(200)
      await page.goto(`/findings/${s.findingId}`)
      await expect(h1(page)).toHaveText(`${s.host} may be affected by ${s.cve}: needs checking`)
      await expect(page.getByText('Mitigation module is off')).toBeVisible() // S-CORE-1: the page says why the panel is missing
      await expect(page.getByText('No confirmed recommendation yet')).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Mark as handled' })).toBeEnabled() // the status is findings', not mitigation's
      await noVietnamese(page, 'mitigation off')
      const saved = page.waitForResponse((r) => r.url().endsWith(`/findings/${s.findingId}/status`) && r.request().method() === 'POST')
      await page.getByRole('button', { name: 'Mark as handled' }).click()
      await page.getByRole('dialog', { name: 'Mark as handled' }).getByRole('button', { name: 'Save status' }).click()
      expect((await saved).status()).toBe(200)
      await expect(h1(page)).toHaveText(`${s.host}: ${s.cve} is patched`)
      // on again: the panel and the routes are back, the data was kept
      expect((await api(admin, 'PATCH', '/modules/mitigation', { enabled: true })).status).toBe(200)
      expect(await state()).toBe(true)
      const back = await api<{ error: { code: string } }>(admin, 'POST', `/findings/${s.findingId}/applied`, { item: 'patch' })
      expect(back.status).toBe(400)
      expect(back.body).toMatchObject({ error: { code: 'no_pack' } })
      await page.reload()
      await expect(page.getByText('Mitigation module is off')).toHaveCount(0)
      await expect(page.getByText('No confirmed recommendation yet')).toBeVisible()
      expect((await finding(admin, s.findingId)).body.status).toBe('patched')
      noErrors(errors)
    } finally {
      try { if ((await state()) !== true) throw new Error('mitigation is not on') } catch { /* put it back whatever state() said */ }
      const back = await api(admin, 'PATCH', '/modules/mitigation', { enabled: true })
      await admin.dispose()
      expect(back.status, 'mitigation put back on').toBe(200)
    }
  })
})
