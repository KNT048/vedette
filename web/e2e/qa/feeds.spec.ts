// QA as a real user for the feeds module (S-FEED-1..5): Home (hot board, "This week"), Lookup, CVE page, Settings -> Feeds.
// Runs on the dev server (playwright.qa.config.ts, http://localhost:5173). Two ways to run it:
//   make dev                           every module is the mock;
//   make dev-api REAL=core,feeds      core and feeds are the real Go backend: set the box up first (real /setup with the code from the log),
//                                     create an operator and a viewer, change their passwords; accounts admin@qa.test, op@qa.test, view@qa.test share
//                                     the password in FEEDS_QA_PASSWORD. Only feeds' own built-in feeds should be left on (KEV and EPSS).
// The same steps must pass on both: that is the point. Set FEEDS_REAL=1 when the backend is real (it checks things only a real pull can show);
// FEEDS_EMPTY=1 as well when the box has never fetched anything (a fresh dev-api box).
import { expect, test, type Page } from '@playwright/test'
import { createRequire } from 'node:module'
import { collectErrors, shot, startWithSample } from '../helpers'

const AXE = createRequire(import.meta.url).resolve('axe-core/axe.min.js')

test.describe.configure({ retries: 1 })
const REAL = !!process.env.FEEDS_REAL
const EMPTY = !!process.env.FEEDS_EMPTY
const ORIGIN = 'http://localhost:5173'
const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
type Role = keyof typeof USER

const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }
/** Mock: sample data, then switch the mock session to this role. */
async function asMockRole(page: Page, role: Role) {
  await startWithSample(page)
  await page.evaluate((u) => {
    const k = 'vedette-mock-db-v4'
    const raw = localStorage.getItem(k)
    if (raw) { const db = JSON.parse(raw); db.core_session = { userId: u }; localStorage.setItem(k, JSON.stringify(db)) }
  }, USER[role])
}
/** Real box (make dev-api REAL=core,feeds, set up with admin@qa.test, op@qa.test, view@qa.test; password in FEEDS_QA_PASSWORD): the real login. */
async function login(page: Page, role: Role) {
  await page.goto('/login')
  for (let attempt = 0; attempt < 10; attempt++) { // the box checks one password at a time: busy answers 503
    const r = await page.request.post('/api/v1/auth/login', { data: { email: EMAIL[role], password: process.env.FEEDS_QA_PASSWORD } })
    if (r.status() !== 503) { expect(r.ok(), `login as ${role}: ${r.status()}`).toBe(true); return }
    await page.waitForTimeout(500)
  }
  throw new Error('the box stayed busy')
}
const start = async (page: Page, role: Role = 'admin', path = '/') => {
  if (REAL) await login(page, role)
  else await asMockRole(page, role)
  await page.goto(path)
}
const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const noHorizontalScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)).toBeLessThanOrEqual(1)
/** A table row (desktop) or a mobile card holding the feed; the visible one. */
const feedRow = (page: Page, name: string) => page.locator('tr:visible, li:visible').filter({ hasText: name }).first()
const SETTINGS = '/settings/feeds'

test.describe('feeds: home, lookup, CVE (S-FEED-1, 2, 3)', () => {
  test('the hot board and "This week" show data from the box; an operator hides an item and it stays hidden', async ({ page }, info) => {
    test.skip(EMPTY, 'needs data')
    const errors = collectErrors(page)
    await start(page, 'operator')
    await expect(h1(page)).toContainText(/^Today: \d+ vulnerabilit/)
    await expect(page.getByText(/Data updated .*Sources: CISA KEV/)).toBeVisible()
    await expect(page.getByText(/1970/)).toHaveCount(0)
    await expect(page.locator('#hot a[href^="/cve/"]:visible').first()).toBeVisible()
    await page.getByRole('button', { name: '24 hours' }).click()
    await expect(page.getByRole('button', { name: '24 hours' })).toHaveAttribute('aria-pressed', 'true')
    await expect(page.locator('#hot a[href^="/cve/"]:visible').first().or(page.getByText(/No newly exploited vulnerabilities in the last 24 hours/))).toBeVisible()
    await shot(page, 'feeds', `${info.project.name}-home`)
    const items = page.locator('#weekly li')
    await expect(items.first()).toBeVisible()
    const before = await items.count()
    expect(before).toBeGreaterThan(0)
    const firstText = (await items.first().innerText()).split('\n')[0]!
    await items.first().getByRole('button', { name: 'Not relevant' }).click()
    await toast(page, /Item hidden/)
    await expect(items).toHaveCount(before - 1)
    await page.reload()
    await expect(page.locator('#weekly li')).toHaveCount(before - 1)
    await expect(page.locator('#weekly')).not.toContainText(firstText.slice(0, 40))
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('a viewer reads the board but cannot answer', async ({ page }) => {
    test.skip(EMPTY, 'needs data')
    await start(page, 'viewer')
    await expect(page.locator('#weekly li').first()).toBeVisible()
    await expect(page.locator('#weekly').getByRole('button', { name: 'I have this' }).first()).toBeDisabled()
    await expect(page.locator('#weekly').getByRole('button', { name: 'Not relevant' }).first()).toBeDisabled()
  })

  test('lookup: CVE, product, bad IP, clean IP, clean domain, junk; the CVE page and an unknown CVE', async ({ page }, info) => {
    test.skip(EMPTY, 'needs data')
    const errors = collectErrors(page)
    await start(page, 'viewer', '/')
    // a CVE that is on this box, whatever the data is: the first one of "This week"
    const cveLink = page.locator('#weekly a[href^="/cve/"]').first()
    await expect(cveLink).toBeVisible()
    const id = (await cveLink.getAttribute('href'))!.replace('/cve/', '')
    const vendor = (await page.locator('#weekly li').first().innerText()).split(/\s+/)[0]!.toLowerCase()
    await page.goto(`/lookup?q=${encodeURIComponent(vendor)}`)
    await expect(page.getByRole('link', { name: id }).first()).toBeVisible()
    await shot(page, 'feeds', `${info.project.name}-lookup-text`)
    await page.getByRole('link', { name: id }).first().click()
    await expect(h1(page)).toContainText(id)
    await expect(page.getByText(/Date added/)).toBeVisible()
    await shot(page, 'feeds', `${info.project.name}-cve`)
    if (!REAL) { // the mock ships a few bad addresses; a real box has them only after pulling an IOC feed
      await page.goto('/lookup?q=185.220.101.47')
      await expect(page.getByText('Block', { exact: true })).toBeVisible()
    }
    await page.goto('/lookup?q=8.8.4.4')
    await expect(page.getByText(/is not on the bad IP\/domain lists/)).toBeVisible()
    await page.goto('/lookup?q=CVE-1999-0001')
    await expect(page.getByText(/is not on the exploited list/)).toBeVisible()
    await page.goto(`/lookup?q=${id.toLowerCase()}`)
    await expect(page.getByText(/is on the exploited list/)).toBeVisible()
    for (const q of ['google.com', '<script>alert(1)</script>', '   ', 'a'.repeat(250)]) {
      await page.goto(`/lookup?q=${encodeURIComponent(q)}`)
      await expect(h1(page)).toBeVisible()
    }
    await page.goto(`/cve/${id.toLowerCase()}`) // lower case in the address bar
    await expect(h1(page)).toContainText(id)
    await page.goto('/cve/CVE-1999-0001')
    await expect(page.getByRole('alert').first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Look up this ID' })).toBeVisible()
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('phone: no sideways scroll on Home, Lookup and Settings -> Feeds', async ({ page, isMobile }) => {
    test.skip(!isMobile, 'phone only')
    await start(page, 'admin', '/')
    await expect(h1(page)).toBeVisible()
    await noHorizontalScroll(page)
    await page.goto('/lookup?q=qnap'); await expect(h1(page)).toBeVisible(); await noHorizontalScroll(page)
    await page.goto(SETTINGS); await expect(h1(page)).toBeVisible(); await noHorizontalScroll(page)
  })
})

test('real box: signing in through the sign-in form lands on Home with the feeds data', async ({ page }) => {
  test.skip(!REAL, 'the mock has no real sign-in')
  await page.goto('/login')
  await page.getByLabel('Email').fill(EMAIL.viewer)
  await page.getByLabel('Password').fill(process.env.FEEDS_QA_PASSWORD!)
  for (let i = 0; i < 5 && !(await h1(page).filter({ hasText: /^Today/ }).isVisible()); i++) { // the box checks one password at a time
    await page.getByRole('button', { name: 'Sign in' }).click()
    await page.waitForTimeout(1500)
  }
  await expect(h1(page)).toContainText(/^Today/)
})

test.describe('feeds: a box that has never fetched (real backend only)', () => {
  test('Home says there is no data yet instead of showing a date from 1970', async ({ page }) => {
    test.skip(!EMPTY, 'needs a real box that never fetched, and FEEDS_EMPTY=1')
    await start(page, 'admin', '/')
    await expect(h1(page)).toBeVisible()
    await expect(page.getByText(/1970/)).toHaveCount(0)
    await expect(page.getByText(/not .*fetched yet|No data/i).first()).toBeVisible()
  })
})

test.describe('feeds: Settings -> Feeds (S-FEED-4, S-FEED-5)', () => {
  test('built-in feeds: list, schedule, mirror address with its checks, reset, switch, fetch now', async ({ page }, info) => {
    const errors = collectErrors(page)
    await start(page, 'admin', SETTINGS)
    await expect(h1(page)).toContainText('Feeds')
    for (const n of ['CISA KEV', 'FIRST EPSS', 'nuclei-templates', 'IPsum', 'ET Open compromised IPs', 'abuse.ch Feodo Tracker', 'Tor exit list', 'hagezi TIF']) await expect(feedRow(page, n)).toBeVisible()
    await expect(page.getByText(/Vedette fetches each feed directly from its source/)).toBeVisible()
    await shot(page, 'feeds', `${info.project.name}-settings`)
    if (EMPTY) await expect(feedRow(page, 'IPsum')).toContainText(/Not fetched yet/)

    // schedule + mirror address
    await page.getByRole('button', { name: 'Settings for IPsum' }).click()
    const dlg = page.getByRole('dialog', { name: 'IPsum settings' })
    const defaultUrl = (await dlg.locator('#bf-url').inputValue())
    await dlg.getByLabel('Fetch schedule').selectOption('12')
    await dlg.getByLabel('Address').fill('ftp://mirror.example.net/ipsum.txt')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.getByRole('alert').or(dlg.locator('#bf-url-error'))).toBeVisible()
    await dlg.getByLabel('Address').fill('http://mirror.example.net/ipsum.txt')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.locator('#bf-url-error')).toContainText(/https/)
    await dlg.getByLabel('Address').fill('http://10.1.2.3/ipsum.txt')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await toast(page, /IPsum saved/)
    await expect(feedRow(page, 'IPsum')).toContainText('Every 12 hours')
    await page.reload()
    await expect(feedRow(page, 'IPsum')).toContainText('Every 12 hours')
    await page.getByRole('button', { name: 'Settings for IPsum' }).click()
    await expect(page.getByRole('dialog', { name: 'IPsum settings' }).getByLabel('Address')).toHaveValue('http://10.1.2.3/ipsum.txt')
    await page.getByRole('dialog', { name: 'IPsum settings' }).getByRole('button', { name: 'Reset to default' }).click()
    await page.getByRole('dialog', { name: 'IPsum settings' }).getByRole('button', { name: 'Save' }).click()
    await toast(page, /IPsum saved/)
    await page.getByRole('button', { name: 'Settings for IPsum' }).click()
    await expect(page.getByRole('dialog', { name: 'IPsum settings' }).getByLabel('Address')).toHaveValue(/^https:\/\//)
    await page.getByRole('dialog', { name: 'IPsum settings' }).getByRole('button', { name: 'Cancel' }).click()
    expect(defaultUrl.length).toBeGreaterThan(0)

    // switch off: Fetch now is locked and says why; on again
    const sw = page.getByRole('switch', { name: 'Enable ET Open compromised IPs' })
    const was = await sw.isChecked() // leave the feed as it was: a box pulls whatever is left on
    const fetchBtn = page.getByRole('button', { name: 'Fetch now: ET Open compromised IPs' })
    await sw.click()
    await toast(page, was ? /ET Open compromised IPs is off/ : /ET Open compromised IPs is on/)
    if (was) await expect(fetchBtn).toBeDisabled(); else await expect(fetchBtn).toBeEnabled()
    await expect(sw).toBeChecked({ checked: !was })
    await sw.click()
    await expect(sw).toBeChecked({ checked: was })
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('D-92: with the CISA list turned off, Home does not say 0 newly exploited; its link leads back to the switch', async ({ page }) => {
    test.skip(EMPTY, 'needs data')
    await start(page, 'admin', SETTINGS)
    const sw = page.getByRole('switch', { name: 'Enable CISA KEV' })
    const was = await sw.isChecked()
    if (was) { await sw.click(); await toast(page, /CISA KEV is off/) }
    await page.goto('/')
    await expect(h1(page)).toContainText('The CISA list is turned off.')
    await expect(h1(page)).not.toContainText(/\d+ vulnerabilit/)
    // D-134 (4): the hot board follows the same rule: an empty window never reads as "none" while the list is off.
    for (const win of ['24 hours', '7 days']) {
      await page.getByRole('button', { name: win }).click()
      await expect(page.getByRole('button', { name: win })).toHaveAttribute('aria-pressed', 'true')
      await expect(page.locator('#hot a[href^="/cve/"]:visible').first().or(page.locator('#hot').getByText('The CISA list is turned off.'))).toBeVisible()
      await expect(page.locator('#hot')).not.toContainText('No newly exploited')
    }
    await h1(page).getByRole('link', { name: 'See Settings → Feeds.' }).click()
    await expect(page).toHaveURL(/\/settings\/feeds$/)
    if (was) { await expect(sw).not.toBeChecked(); await sw.click(); await expect(sw).toBeChecked() }
  })

  test('a viewer and an operator read the list; every button that changes something is locked and says who may use it', async ({ page }) => {
    for (const role of ['viewer', 'operator'] as const) {
      await start(page, role, SETTINGS)
      await expect(feedRow(page, 'CISA KEV')).toBeVisible()
      for (const b of [page.getByRole('button', { name: 'Settings for CISA KEV' }), page.getByRole('button', { name: 'Fetch now: CISA KEV' }), page.getByRole('switch', { name: 'Enable CISA KEV' })]) {
        await expect(b).toBeDisabled()
        await expect(b).toHaveAttribute('title', /Requires .+ role/)
      }
      await expect(page.getByRole('button', { name: 'Add a feed' }).first()).toBeDisabled()
    }
  })

  // The form matrix of QA.md section 2: every kind x format, then every authentication type; each created, read back, edited, deleted.
  const MATRIX: { kind: 'IOC' | 'Vulnerabilities'; format: string; shape: string }[] = [
    { kind: 'IOC', format: 'JSON', shape: 'JSON' }, { kind: 'IOC', format: 'CSV', shape: 'CSV' }, { kind: 'IOC', format: 'RSS / Atom', shape: 'RSS' },
    { kind: 'IOC', format: 'STIX 2.1 / TAXII 2.1', shape: 'STIX' }, { kind: 'IOC', format: 'Plain list (one per line)', shape: 'list' },
    { kind: 'Vulnerabilities', format: 'JSON', shape: 'JSON' }, { kind: 'Vulnerabilities', format: 'CSV', shape: 'CSV' }, { kind: 'Vulnerabilities', format: 'RSS / Atom', shape: 'RSS' },
  ]
  const AUTHS = [
    { option: 'None', fill: async () => {}, last4: null },
    { option: 'Custom header', fill: async (d: ReturnType<Page['getByRole']>) => { await d.getByLabel('Header name').fill('X-Feed-Key'); await d.getByLabel('Secret').fill('hdr-secret-4321') }, last4: '4321' },
    { option: 'Bearer token', fill: async (d: ReturnType<Page['getByRole']>) => { await d.getByLabel('Secret').fill('bearer-token-8765') }, last4: '8765' },
    { option: 'Basic (user and password)', fill: async (d: ReturnType<Page['getByRole']>) => { await d.getByLabel('User name').fill('svc-feed'); await d.getByLabel('Password').fill('basic-pass-2468') }, last4: '2468' },
  ]
  const cases = [
    ...MATRIX.map((m) => ({ ...m, auth: AUTHS[0]! })),
    ...AUTHS.slice(1).map((a) => ({ kind: 'IOC' as const, format: 'CSV', shape: 'CSV', auth: a })),
    { kind: 'Vulnerabilities' as const, format: 'JSON', shape: 'JSON', auth: AUTHS[2]! },
  ]
  for (const [i, c] of cases.entries()) {
    test(`custom feed form: ${c.kind} / ${c.format} / ${c.auth.option}`, async ({ page }, info) => {
      const errors = collectErrors(page)
      const name = `QA ${c.kind.slice(0, 3)} ${c.shape} ${i}`
      await start(page, 'admin', SETTINGS)
      await page.getByRole('button', { name: 'Add a feed' }).first().click()
      const dlg = page.getByRole('dialog', { name: 'Add a feed' })
      await dlg.locator('#cf-name').fill(name)
      await dlg.getByRole('button', { name: c.kind, exact: true }).click()
      await dlg.locator('#pe-format').selectOption({ label: c.format })
      await dlg.getByLabel('Address').fill(`http://feeds.lan/${i}.${c.shape === 'JSON' ? 'json' : c.shape === 'CSV' ? 'csv' : 'xml'}`)
      await dlg.getByLabel('Authentication').selectOption({ label: c.auth.option })
      await c.auth.fill(dlg as never)
      await dlg.getByRole('button', { name: 'Test on a sample' }).click()
      await expect(dlg.getByRole('status').filter({ hasText: /rows? accepted/ })).toBeVisible()
      if (i === 0) await shot(page, 'feeds', `${info.project.name}-add-dialog`)
      await dlg.getByRole('button', { name: 'Add feed' }).click()
      await toast(page, new RegExp(`${name} added`))
      await expect(dlg).toBeHidden()
      const row = feedRow(page, name)
      await expect(row).toContainText(c.kind === 'IOC' ? 'IOC' : 'Vulnerabilities')
      await expect(row).toContainText(/Not fetched yet/)
      // read back after a reload: what the server stored is what the form shows
      await page.reload()
      await page.getByRole('button', { name: `Edit ${name}` }).click()
      const edit = page.getByRole('dialog', { name: `Edit ${name}` })
      await expect(edit.locator('#cf-name')).toHaveValue(name)
      await expect(edit.locator('#pe-format')).toHaveValue(c.format === 'JSON' ? 'json' : c.format === 'CSV' ? 'csv' : c.format.startsWith('RSS') ? 'rss' : c.format.startsWith('STIX') ? 'stix' : 'lines')
      await expect(edit.getByLabel('Authentication')).toHaveText(new RegExp(c.auth.option.slice(0, 4)))
      if (c.auth.option === 'Custom header') await expect(edit.getByLabel('Header name')).toHaveValue('X-Feed-Key')
      if (c.auth.option.startsWith('Basic')) await expect(edit.getByLabel('User name')).toHaveValue('svc-feed')
      if (c.auth.last4) await expect(edit.getByText(`A secret ending in ${c.auth.last4} is saved`)).toBeVisible()
      else await expect(edit.getByText(/A secret ending in/)).toHaveCount(0)
      // edit: change the schedule, keep the secret by leaving it empty
      await edit.getByLabel('Fetch schedule').selectOption('72')
      await edit.getByRole('button', { name: 'Save' }).click()
      await toast(page, new RegExp(`${name} saved`))
      await expect(feedRow(page, name)).toContainText('Every 72 hours')
      if (c.auth.last4) {
        await page.getByRole('button', { name: `Edit ${name}` }).click()
        await expect(page.getByRole('dialog', { name: `Edit ${name}` }).getByText(`A secret ending in ${c.auth.last4} is saved`)).toBeVisible()
        await page.getByRole('dialog', { name: `Edit ${name}` }).getByRole('button', { name: 'Cancel' }).click()
      }
      await page.getByRole('button', { name: `Delete ${name}` }).click()
      await page.getByRole('dialog', { name: `Delete ${name}?` }).getByRole('button', { name: 'Delete' }).click()
      await toast(page, new RegExp(`${name} deleted`))
      await expect(page.getByText(name)).toHaveCount(0)
      await page.reload()
      await expect(page.getByText(name)).toHaveCount(0)
      expect(errors, errors.join('\n')).toEqual([])
    })
  }

  test('custom feed form: what the server refuses is shown at the right field and nothing is saved', async ({ page }) => {
    await start(page, 'admin', SETTINGS)
    const open = async () => {
      await page.getByRole('button', { name: 'Add a feed' }).first().click()
      return page.getByRole('dialog', { name: 'Add a feed' })
    }
    // a name that already exists (built-in names count, upper or lower case)
    let dlg = await open()
    await dlg.locator('#cf-name').fill('cisa kev')
    await dlg.getByLabel('Address').fill('https://feeds.partner.example/ioc.json')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.getByText('A feed with this name already exists.')).toBeVisible()
    await expect(dlg.locator('#cf-name')).toHaveAttribute('aria-invalid', 'true')
    // rules the server rejects: a regular expression that does not compile
    await dlg.locator('#cf-name').fill('Bad regex feed')
    await dlg.locator('#pe-format').selectOption('csv')
    await dlg.locator('#pe-indicator-re').fill('([')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.getByText(/regular expression/i).first()).toBeVisible()
    await dlg.getByRole('button', { name: 'Test on a sample' }).click()
    await expect(dlg.getByRole('alert').filter({ hasText: /regular expression/i }).first()).toBeVisible()
    await dlg.getByRole('button', { name: 'Cancel' }).click()
    await expect(page.getByText('Bad regex feed')).toHaveCount(0)
    await expect(page.locator('#feeds-custom')).toBeVisible()
  })

  test('your own feed pointing nowhere: Fetch now ends in a readable error on the row, not a crash', async ({ page }) => {
    test.skip(!REAL, 'the mock never touches a network')
    await start(page, 'admin', SETTINGS)
    await page.getByRole('button', { name: 'Add a feed' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a feed' })
    await dlg.locator('#cf-name').fill('Unreachable partner')
    await dlg.getByLabel('Address').fill('http://127.0.0.1:1/list.txt')
    await dlg.locator('#pe-format').selectOption('lines')
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await toast(page, /Unreachable partner added/)
    await page.getByRole('button', { name: 'Fetch now: Unreachable partner' }).click()
    await toast(page, /Unreachable partner: /)
    const row = feedRow(page, 'Unreachable partner')
    await expect(row).toContainText('Error')
    const text = await row.innerText()
    expect(text).not.toMatch(/dial tcp|goroutine|\.go:\d|sql|panic/i)
    await page.getByRole('button', { name: 'Delete Unreachable partner' }).click()
    await page.getByRole('dialog', { name: 'Delete Unreachable partner?' }).getByRole('button', { name: 'Delete' }).click()
    await toast(page, /Unreachable partner deleted/)
  })

  test('Test on a sample with your own text: accepted and rejected rows, the reasons and row numbers', async ({ page }, info) => {
    await start(page, 'admin', SETTINGS)
    await page.getByRole('button', { name: 'Add a feed' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a feed' })
    await dlg.locator('#pe-format').selectOption('lines')
    await dlg.locator('summary', { hasText: 'Test with your own sample' }).click()
    await dlg.locator('#pe-own').fill('185.220.101.47\nnot an address\n8.8.4.4\n')
    await dlg.getByRole('button', { name: 'Test on a sample' }).click()
    await expect(dlg.getByRole('status')).toContainText('2 rows accepted')
    await expect(dlg.getByRole('status')).toContainText('1 row rejected')
    await expect(dlg.getByText(/First rejected rows \(numbers\): 2/)).toBeVisible()
    await expect(dlg.getByRole('status')).toContainText('Your sample')
    await shot(page, 'feeds', `${info.project.name}-parse-test`)
    await dlg.locator('#pe-own').fill('')
    await dlg.getByRole('button', { name: 'Test on a sample' }).click()
    await expect(dlg.getByRole('status')).not.toContainText('Your sample')
    await expect(dlg.getByRole('status')).toContainText(/rows? accepted/)
  })
})

test.describe('feeds: fixes from the independent QA pass', () => {
  test('phone and desktop: refused submits move focus to the first wrong field, and it is on screen', async ({ page }) => {
    await start(page, 'admin', SETTINGS)
    await page.getByRole('button', { name: 'Add a feed' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a feed' })
    await dlg.getByRole('button', { name: 'Add feed' }).click() // nothing filled in
    await expect(dlg.locator('#cf-name')).toBeFocused()
    await expect(dlg.locator('#cf-name')).toBeInViewport()
    await dlg.locator('#cf-name').fill('cisa kev') // a name the server refuses, address fine
    await dlg.locator('#cf-url').fill('https://feeds.partner.example/ioc.json')
    await dlg.locator('#cf-url').scrollIntoViewIfNeeded()
    await dlg.getByRole('button', { name: 'Add feed' }).click()
    await expect(dlg.getByText('A feed with this name already exists.')).toBeVisible()
    await expect(dlg.locator('#cf-name')).toBeFocused()
    await expect(dlg.locator('#cf-name')).toBeInViewport()
  })

  test('Lookup: 200 characters without a space wrap inside the page', async ({ page }) => {
    await start(page, 'viewer', `/lookup?q=${'x'.repeat(200)}`)
    await expect(page.getByText(/No exploited vulnerability matches/)).toBeVisible()
    await noHorizontalScroll(page)
  })

  test('every Fetch now button names the feed and still contains its visible words; axe is clean, light and dark', async ({ page }) => {
    for (const scheme of ['light', 'dark'] as const) {
      await page.emulateMedia({ colorScheme: scheme })
      await start(page, 'admin', SETTINGS)
      await expect(page.getByRole('button', { name: 'Fetch now: CISA KEV' })).toBeVisible()
      await page.addScriptTag({ path: AXE })
      const bad = await page.evaluate(async () => {
        // @ts-expect-error axe is put on window by addScriptTag
        const r = await window.axe.run(document, { rules: { 'label-content-name-mismatch': { enabled: true } }, resultTypes: ['violations'] })
        return (r.violations as { id: string; impact: string; nodes: { target: string[] }[] }[]).filter((v) => v.impact === 'serious' || v.impact === 'critical').map((v) => `${v.id}: ${v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' | ')}`)
      })
      expect(bad, `${scheme}: ${bad.join('\n')}`).toEqual([])
    }
  })

  test('/cve/hello: plain words, no API wording', async ({ page }) => {
    await start(page, 'viewer', '/cve/hello')
    await expect(page.getByText('\u201chello\u201d is not a CVE ID')).toBeVisible()
    await expect(page.getByText(/CVE IDs look like CVE-2021-44228/)).toBeVisible()
    await expect(page.locator('body')).not.toContainText(/Invalid request|parameter "id"/)
  })

  test('the search box is wide enough for its hint, and dates read as "9 Nov 2026"', async ({ page, isMobile }) => {
    test.skip(EMPTY, 'needs data')
    await start(page, 'viewer', '/')
    const box = page.getByRole('textbox', { name: 'CVE, product, IP or domain' })
    await expect(box).toBeVisible()
    const w = (await box.boundingBox())!.width
    expect(w, `search box is ${w}px wide`).toBeGreaterThanOrEqual(isMobile ? 280 : 260)
    await expect(page.getByText(/Data updated \d{1,2} [A-Z][a-z]{2} 20\d\d, \d\d:\d\d/)).toBeVisible()
    await expect(page.locator('main')).not.toContainText(/\b\d{2}\/\d{2}\/20\d\d\b/)
  })
})
