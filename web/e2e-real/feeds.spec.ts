// The feeds module on the real backend, on a box with no internet (S-FEED-1..5, D-91, D-92, D-134). Steps from e2e/qa/feeds.spec.ts.
// No test makes the box pull from a public URL: the only pull is of a custom feed pointed at a node `http` server on 127.0.0.1, named e2e-loopback.lan (D-TBD-g10; INV-2
// lets internal hosts use http), so the run needs no network. Entities are per test (uniq names); nothing here changes a built-in feed's state.
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ actionTimeout: 10_000 })

const SETTINGS = '/settings/feeds'
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const feedRow = (page: Page, name: string) => page.locator('tr:visible, li:visible').filter({ hasText: name }).first()
const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
/** Feeds a test made, deleted after it through the API by name whatever the test did (a failed test leaves nothing behind on the box). */
const made: string[] = []
async function sweep() {
  if (!made.length) return
  const admin = await as('admin')
  try {
    const items = (await api<{ items: { id: string; name: string; builtin: boolean }[] }>(admin, 'GET', '/feeds/sources')).body.items
    for (const name of made.splice(0)) {
      const f = items.find((i) => i.name === name && !i.builtin)
      if (f) expect((await api(admin, 'DELETE', `/feeds/custom/${f.id}`)).status, `cleanup of ${name}`).toBe(204)
    }
  } finally { await admin.dispose() }
}
test.afterEach(sweep)
const LINES = { format: 'lines', records_path: '', delimiter: '', has_header: false, fields: { indicator: { source: '', regex: '', trim: true, lowercase: false, date_format: 'auto' } } }
const customBody = (name: string, url = 'http://e2e-loopback.lan:9/x.txt') => ({ name, kind: 'ioc', url, enabled: true, interval_hours: 24, auth: { type: 'none', header_name: null, username: null }, parser: LINES })

test.describe('home and the CISA list on a box with no internet (S-FEED-1, D-134 (4))', () => {
  test.use({ storageState: authFile('viewer') })
  test('Home and the hot table give an honest reason, never a 1970 date or a script error', async ({ page }) => {
    const errors = collectErrors(page)
    const c = await as('viewer')
    const st = (await api<{ generated_at: string; kev: { state: 'loaded' | 'never_loaded' | 'off'; error: string | null } }>(c, 'GET', '/feeds/status')).body
    await c.dispose()
    await page.goto('/')
    await page.waitForLoadState('networkidle')
    await expect(page.getByText(/1970/)).toHaveCount(0)
    await expect(page.locator('body')).not.toContainText(/undefined|NaN|\[object/)
    // the exact title follows kev.state (D-92, D-134): a count only when the CISA list has loaded, else the honest reason
    const never = new Date(st.generated_at).getFullYear() < 2000
    test.info().annotations.push({ type: 'kev-state', description: `${st.kev.state} error=${st.kev.error}` })
    const hot = page.locator('#hot')
    await expect(hot).toBeVisible()
    if (st.kev.state === 'loaded') await expect(h1(page)).toHaveText(/^Today: \d+ vulnerabilit/)
    else if (st.kev.state === 'off') await expect(h1(page)).toContainText('The CISA list is turned off.')
    else if (never && !st.kev.error) await expect(h1(page)).toHaveText('Today: no data yet')
    else await expect(h1(page)).toContainText(`The CISA list could not be fetched yet: ${st.kev.error ?? 'no fetch has finished yet'}`)
    for (const win of ['24 hours', '7 days']) {
      await page.getByRole('button', { name: win }).click()
      await expect(page.getByRole('button', { name: win })).toHaveAttribute('aria-pressed', 'true')
      if (st.kev.state !== 'loaded') await expect(hot).not.toContainText('No newly exploited') // an empty window never reads as "none" without data
    }
    await expectAccessible(page, 'home')
    await noVietnamese(page, 'home')
    await shot(page, 'real', 'feeds-home')
    noErrors(errors)
  })

  test('the API says the same: status and hot answer 200 with no invented data', async () => {
    const c = await as('viewer')
    const st = await api<{ generated_at: string; kev: unknown }>(c, 'GET', '/feeds/status')
    expect(st.status).toBe(200)
    for (const p of ['/feeds/hot?window=24h', '/feeds/hot?window=7d', '/feeds/weekly', '/feeds/sources']) expect((await api(c, 'GET', p)).status, p).toBe(200)
    expect((await api(c, 'GET', '/feeds/hot?window=1y')).status).toBe(400)
    await c.dispose()
  })
})

test.describe('Settings -> Feeds as an administrator (S-FEED-4, S-FEED-5)', () => {
  test.use({ storageState: authFile('admin') })

  test('the built-in list renders with real states', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto(SETTINGS)
    await expect(h1(page)).toContainText('Feeds')
    for (const n of ['CISA KEV', 'FIRST EPSS', 'nuclei-templates', 'IPsum', 'ET Open compromised IPs', 'abuse.ch Feodo Tracker', 'Tor exit list', 'hagezi TIF']) await expect(feedRow(page, n)).toBeVisible()
    await expect(feedRow(page, 'abuse.ch SSLBL')).toHaveCount(0) // D-92
    await expect(page.getByText(/Vedette fetches each feed directly from its source/)).toBeVisible()
    const admin = await as('admin')
    const sources = (await api<{ items: { id: string; name: string; builtin: boolean; status: 'ok' | 'error' | 'never'; error: string | null }[] }>(admin, 'GET', '/feeds/sources')).body.items
    await admin.dispose()
    const builtins = sources.filter((s) => s.builtin)
    expect(builtins.length).toBeGreaterThanOrEqual(8)
    expect(sources.map((s) => s.id)).not.toContain('abusech-sslbl')
    const label = { never: 'Not fetched yet', ok: 'OK', error: 'Error' }
    for (const f of builtins) {
      const row = feedRow(page, f.name)
      await expect(row, f.name).toBeVisible()
      await expect(row, f.name).toContainText(label[f.status])
      for (const other of Object.values(label).filter((l) => l !== label[f.status])) await expect(row, `${f.name} must not say ${other}`).not.toContainText(other)
      expect(await row.innerText(), f.name).not.toMatch(/1970|undefined|dial tcp|goroutine/)
    }
    await expectAccessible(page, 'settings feeds')
    await noVietnamese(page, 'settings feeds')
    await shot(page, 'real', 'feeds-settings')
    noErrors(errors)
  })

  test('a custom feed: the form refuses bad input, then add, edit, delete', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const name = uniq('QA feed')
    made.push(name)
    await page.goto(SETTINGS)
    await page.getByRole('button', { name: 'Add a feed' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a feed' })
    // nothing filled in: focus goes to the name
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.locator('#cf-name')).toBeFocused()
    // a built-in name, any case
    await dlg.locator('#cf-name').fill('cisa kev')
    await dlg.getByLabel('Address').fill('https://feeds.partner.example/ioc.json')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.getByText('A feed with this name already exists.')).toBeVisible()
    // plain http to a public host is refused at the address field
    await dlg.locator('#cf-name').fill(name)
    await dlg.getByLabel('Address').fill('http://feeds.partner.example/ioc.txt')
    await dlg.locator('#pe-format').selectOption('lines')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.locator('#cf-url-error')).toContainText(/https/)
    // a regular expression that does not compile
    await dlg.getByLabel('Address').fill('https://feeds.partner.example/ioc.csv')
    await dlg.locator('#pe-format').selectOption('csv')
    await dlg.locator('#pe-indicator-re').fill('([')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.getByText(/regular expression/i).first()).toBeVisible()
    await expect(page.getByText(name)).toHaveCount(0)
    // the happy path (a name used once; the address is never fetched in this test)
    await dlg.locator('#pe-indicator-re').fill('')
    await dlg.locator('#pe-format').selectOption('lines')
    await dlg.getByLabel('Address').fill('http://feeds.lan/list.txt')
    await dlg.getByRole('button', { name: 'Test on a sample' }).click()
    await expect(dlg.getByRole('status').filter({ hasText: /rows? accepted/ })).toBeVisible()
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await toast(page, new RegExp(`${name} added`))
    await expect(feedRow(page, name)).toContainText(/Not fetched yet|Error/)
    await page.reload()
    await page.getByRole('button', { name: `Edit ${name}` }).click()
    const edit = page.getByRole('dialog', { name: `Edit ${name}` })
    await expect(edit.getByLabel('Address')).toHaveValue('http://feeds.lan/list.txt')
    await edit.getByLabel('Fetch schedule').selectOption('72')
    await edit.getByRole('button', { name: 'Save' }).click()
    await toast(page, new RegExp(`${name} saved`))
    await expect(feedRow(page, name)).toContainText('Every 3 days')
    await page.getByRole('button', { name: `Delete ${name}` }).click()
    await page.getByRole('dialog', { name: `Delete ${name}?` }).getByRole('button', { name: 'Delete' }).click()
    await toast(page, new RegExp(`${name} deleted`))
    await page.reload()
    await expect(page.getByText(name)).toHaveCount(0)
    noErrors(errors, /status of 40[09]/) // the refused submits: 400 invalid, 409 duplicate name
  })

  test('Test on a sample with your own text: accepted and rejected rows with numbers', async ({ page }) => {
    await page.goto(SETTINGS)
    await page.getByRole('button', { name: 'Add a feed' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a feed' })
    await dlg.locator('#pe-format').selectOption('lines')
    await dlg.locator('summary', { hasText: 'Test with your own sample' }).click()
    await dlg.locator('#pe-own').fill('185.220.101.47\nnot an address\n8.8.4.4\n')
    await dlg.getByRole('button', { name: 'Test on a sample' }).click()
    await expect(dlg.getByRole('status')).toContainText('2 rows accepted')
    await expect(dlg.getByRole('status')).toContainText('1 row rejected')
    await expect(dlg.getByText(/First rejected rows \(numbers\): 2/)).toBeVisible()
  })

  test('a built-in feed mirror address: https only (or internal), saved and reset', async ({ page }) => {
    await page.goto(SETTINGS)
    await page.getByRole('button', { name: 'Settings for Tor exit list' }).click()
    const dlg = page.getByRole('dialog', { name: 'Tor exit list settings' })
    await dlg.getByLabel('Address').fill('ftp://mirror.example.net/tor.txt')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.locator('#bf-url-error').or(dlg.getByRole('alert')).first()).toBeVisible()
    await dlg.getByLabel('Address').fill('http://mirror.example.net/tor.txt')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.locator('#bf-url-error')).toContainText(/https/)
    await dlg.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByRole('button', { name: 'Settings for Tor exit list' })).toBeVisible()
  })
})

test.describe('operator and viewer (S-FEED-4)', () => {
  for (const role of ['operator', 'viewer'] as const) {
    test(`${role}: reads the list, every changing control is locked, and the API refuses`, async ({ browser }) => {
      const context = await browser.newContext({ baseURL: box().base_url, storageState: authFile(role), locale: 'vi-VN' })
      const page = await context.newPage()
      const errors = collectErrors(page)
      await page.goto(SETTINGS)
      await expect(feedRow(page, 'CISA KEV')).toBeVisible()
      for (const b of [page.getByRole('button', { name: 'Settings for CISA KEV' }), page.getByRole('button', { name: 'Fetch now: CISA KEV' }), page.getByRole('switch', { name: 'Enable CISA KEV' })]) {
        await expect(b).toBeDisabled()
        await expect(b).toHaveAttribute('title', /Requires .+ role/)
      }
      await expect(page.getByRole('button', { name: 'Add a feed' }).first()).toBeDisabled()
      await expectAccessible(page, `${role} settings feeds`)
      await noVietnamese(page, `${role} settings feeds`)
      noErrors(errors)
      // the server says the same (CONTRACT: PUT/POST/DELETE are the administrator's)
      const c = page.request
      expect((await api(c, 'GET', '/feeds/sources')).status).toBe(200)
      expect((await api(c, 'PUT', '/feeds/sources/cisa-kev', { enabled: false })).status).toBe(403)
      expect((await api(c, 'POST', '/feeds/sources/cisa-kev/fetch')).status).toBe(403)
      expect((await api(c, 'POST', '/feeds/custom', customBody(uniq('nope')))).status).toBe(403)
      expect((await api(c, 'PUT', '/feeds/custom/does-not-exist', customBody(uniq('nope')))).status).toBe(403)
      expect((await api(c, 'DELETE', '/feeds/custom/does-not-exist')).status).toBe(403)
      expect((await api(c, 'POST', '/feeds/parse-test', { kind: 'ioc', parser: LINES })).status).toBe(403)
      // the answer to a weekly item is the operator's, the viewer's is refused
      const w = await api(c, 'POST', '/feeds/weekly/nothing-here', { answer: 'not_relevant' })
      expect(w.status, JSON.stringify(w.body)).toBe(role === 'viewer' ? 403 : 404)
      await context.close()
    })
  }
})

test.describe('lookup and the CVE page with no local data (S-FEED-3)', () => {
  test.use({ storageState: authFile('viewer') })

  test('lookup: CVE, product, clean IP, junk and a long string answer honestly', async ({ page }) => {
    const errors = collectErrors(page)
    const server: string[] = []
    page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) server.push(`${r.url()} ${r.status()}`) })
    await page.goto('/lookup')
    await expect(h1(page)).toContainText('Lookup')
    await expect(page.getByText('Enter what you want to check')).toBeVisible()
    await page.goto('/lookup?q=CVE-1999-0001')
    await expect(page.getByText(/CVE-1999-0001 is not on the exploited list/)).toBeVisible()
    await page.goto('/lookup?q=8.8.4.4')
    await expect(page.getByText(/is not on the bad IP\/domain lists/)).toBeVisible()
    await page.goto(`/lookup?q=${uniq('nosuchproduct')}`)
    await expect(page.getByText(/No exploited vulnerability matches/)).toBeVisible()
    await expectAccessible(page, 'lookup empty')
    for (const q of ['<script>alert(1)</script>', '   ', 'a'.repeat(250), 'cve-2099-99999', '../../etc/passwd', "' OR 1=1 --"]) {
      await page.goto(`/lookup?q=${encodeURIComponent(q)}`)
      await expect(h1(page)).toBeVisible()
      await page.waitForLoadState('networkidle')
    }
    // the search box, as a person types
    await page.goto('/lookup')
    await page.getByPlaceholder('CVE, product, IP or domain').fill('fortigate')
    await page.getByRole('button', { name: 'Look up' }).click()
    await expect(page).toHaveURL(/q=fortigate/)
    await expect(h1(page)).toBeVisible()
    await noVietnamese(page, 'lookup')
    expect(server).toEqual([])
    noErrors(errors, /status of (4\d\d)/)
  })

  test('a CVE page for an ID with no local data says so and offers the lookup', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/cve/CVE-1999-0001')
    await expect(page.getByRole('alert').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Look up this ID' })).toBeVisible()
    await expectAccessible(page, 'cve unknown')
    await noVietnamese(page, 'cve unknown')
    await shot(page, 'real', 'feeds-cve-unknown')
    const r = await api(page.request, 'GET', '/feeds/cve/CVE-1999-0001')
    expect(r.status).toBe(404)
    expect(r.body).toMatchObject({ error: { code: 'not_in_kev' } })
    expect((await api(page.request, 'GET', '/feeds/cve/not-an-id')).status).toBeLessThan(500)
    noErrors(errors, /status of 4\d\d/)
  })
})

// A pull of a custom feed from a loopback server inside this test: INV-2 lets http go to 127/8, and no public address is touched.
// The indicator is a domain built from uniq() under a made-up TLD: normaliseIOC accepts a domain whose TLD is not reserved and not a public
// suffix, and no public list can carry it, so "listed by <feed>" before the delete and "not listed" after it are about this feed only.
test.describe('a feed pull from loopback (S-FEED-4, INV-4, INV-8)', () => {
  test.use({ storageState: authFile('admin') })
  let srv: Server
  let base = ''
  const served: Record<string, { status: number; body: string }> = {}
  test.beforeAll(async () => {
    srv = createServer((req, res) => { const s = served[req.url ?? ''] ?? { status: 404, body: 'no' }; res.writeHead(s.status, { 'Content-Type': 'text/plain' }); res.end(s.body) })
    await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok))
    base = `http://e2e-loopback.lan:${(srv.address() as AddressInfo).port}` // the box sends this name to 127.0.0.1 (e2eOffline): a loopback address is refused at save (D-TBD-g10)
  })
  test.afterAll(async () => { await new Promise((ok) => srv.close(ok)) })

  async function viaApi(c: APIRequestContext, name: string, path: string) {
    made.push(name)
    const r = await api<{ id: string }>(c, 'POST', '/feeds/custom', customBody(name, `${base}${path}`))
    expect(r.status, JSON.stringify(r.body)).toBe(201)
    return r.body.id
  }

  test('Fetch now pulls the list, the row shows the records, Lookup says who lists it, delete removes it', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const name = uniq('Loopback IOC')
    const ioc = `${uniq('ioc')}.zzqx`
    served['/ok.txt'] = { status: 200, body: `# a list\n${ioc}\nnot an address\n` }
    const c = await as('admin')
    try {
      await viaApi(c, name, '/ok.txt')
      await page.goto(SETTINGS)
      await page.getByRole('button', { name: `Fetch now: ${name}` }).click()
      await toast(page, new RegExp(`^Fetched ${name}: 1 records$`)) // the exact toast text of row.fetched
      await expect(feedRow(page, name)).toContainText('OK')
      await expect(feedRow(page, name)).toContainText('1 of 2 rows were rejected.')
      const list = (await api<{ items: { name: string; records: number; status: string }[] }>(c, 'GET', '/feeds/sources')).body.items
      expect(list.find((i) => i.name === name)).toMatchObject({ records: 1, status: 'ok' })
      await page.goto(`/lookup?q=${ioc}`)
      await expect(page.getByText(/is not on the bad IP/)).toHaveCount(0)
      await expect(page.getByText('Sources', { exact: true })).toBeVisible()
      await expect(page.locator('main').getByText(name).first()).toBeVisible() // listed by this feed
      await page.goto(SETTINGS)
      await page.getByRole('button', { name: `Delete ${name}` }).click()
      await page.getByRole('dialog', { name: `Delete ${name}?` }).getByRole('button', { name: 'Delete' }).click()
      await toast(page, new RegExp(`${name} deleted`))
      await page.goto(`/lookup?q=${ioc}`)
      await expect(page.getByText(`${ioc} is not on the bad IP/domain lists`)).toBeVisible() // its records went with it (INV-4)
      await expect(page.locator('main').getByText(name)).toHaveCount(0)
    } finally { await c.dispose() }
    noErrors(errors)
  })

  test('a server that answers 500 ends in a readable error on the row', async ({ page }) => {
    const name = uniq('Loopback 500')
    served['/boom.txt'] = { status: 500, body: 'boom' }
    const c = await as('admin')
    try {
      const id = await viaApi(c, name, '/boom.txt')
      await page.goto(SETTINGS)
      const fetched = page.waitForResponse((r) => r.url().endsWith(`/feeds/sources/${id}/fetch`) && r.request().method() === 'POST')
      await page.getByRole('button', { name: `Fetch now: ${name}` }).click()
      expect((await fetched).status()).toBeLessThan(500)
      await expect(feedRow(page, name)).toContainText('Error')
      expect(await feedRow(page, name).innerText()).not.toMatch(/dial tcp|goroutine|\.go:\d+|panic:|SQLITE|sql:/)
    } finally { await c.dispose() }
  })

  test('a disabled feed refuses Fetch now with 409 feed_disabled (INV-8)', async () => {
    const name = uniq('Loopback off')
    const c = await as('admin')
    try {
      const id = await viaApi(c, name, '/ok.txt')
      expect((await api(c, 'PUT', `/feeds/custom/${id}`, { ...customBody(name, `${base}/ok.txt`), enabled: false })).status).toBe(200)
      const r = await api(c, 'POST', `/feeds/sources/${id}/fetch`)
      expect(r.status).toBe(409)
      expect(r.body).toMatchObject({ error: { code: 'feed_disabled' } })
    } finally { await c.dispose() }
  })
})
