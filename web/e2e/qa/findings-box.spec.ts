// QA as a real user for findings and mitigation (S-MIT-1, S-MIT-3, S-SCAN-3, S-AI-2): the Findings list, the finding page with its
// "What to do" part, the status dialog, "Applied", the device panel, roles, empty and error states.
// Runs on the dev server (playwright.qa.config.ts, http://localhost:5173). Two ways to run it, with the same steps:
//   make dev                                                      every module is the mock (sample data);
//   make dev-api REAL=core,inventory,feeds,findings,mitigation    the real Go backend: prepare the box once with web/e2e/qa/real-box.mjs
//                                                                 (real /setup, accounts admin@qa.test, op@qa.test, view@qa.test with the password in
//                                                                 FINDINGS_QA_PASSWORD, KEV, three devices) and seed the recommendation pack
//                                                                 (VEDETTE_SEED_PACKS_DB=.dev/vedette.db go test ./modules/mitigation -run TestGUIReal_Seed).
//                                                                 Run with FINDINGS_REAL=1. The box has no AI wired yet: the AI buttons are locked there.
// The spec changes findings (status, "Applied") on the box it runs against and puts the status back to open.
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot, startWithSample } from '../helpers'

test.describe.configure({ retries: 1 })
const REAL = !!process.env.FINDINGS_REAL
const USER = { admin: 'u-admin', operator: 'u-op', viewer: 'u-view' } as const
type Role = keyof typeof USER
const EMAIL: Record<Role, string> = { admin: 'admin@qa.test', operator: 'op@qa.test', viewer: 'view@qa.test' }
const PACK_CVE = 'CVE-2022-27593'
const NAS_IP = '192.168.10.21' // the device the pack finding is on, on the mock and on the box (real-box.mjs)

async function asMockRole(page: Page, role: Role) {
  await startWithSample(page)
  await page.evaluate((u) => {
    const k = 'vedette-mock-db-v4'
    const raw = localStorage.getItem(k)
    if (raw) { const db = JSON.parse(raw); db.core_session = { userId: u }; localStorage.setItem(k, JSON.stringify(db)) }
  }, USER[role])
}
async function login(page: Page, role: Role) {
  await page.goto('/login')
  for (let attempt = 0; attempt < 10; attempt++) { // the box checks one password at a time: busy answers 503
    const r = await page.request.post('/api/v1/auth/login', { data: { email: EMAIL[role], password: process.env.FINDINGS_QA_PASSWORD } })
    if (r.status() !== 503) { expect(r.ok(), `login as ${role}: ${r.status()}`).toBe(true); return }
    await page.waitForTimeout(500)
  }
  throw new Error('the box stayed busy')
}
const start = async (page: Page, role: Role = 'operator', path = '/findings') => {
  if (REAL) await login(page, role)
  else await asMockRole(page, role)
  await page.goto(path)
}
const h1 = (page: Page) => page.getByRole('heading', { level: 1 }).first()
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${where}: horizontal scroll`).toBeLessThanOrEqual(1)
/** Table rows (desktop) or cards (phone) of the findings list, not counting the header row. */
const rowsOf = (page: Page, isMobile: boolean) =>
  isMobile ? page.getByRole('list', { name: 'Findings list' }).getByRole('listitem') : page.getByRole('table', { name: 'Findings list' }).getByRole('row').filter({ hasNot: page.getByRole('columnheader') })

/** The id of the first finding of a CVE (pack) or of any other CVE (no pack), read from the links of the list. */
async function findingId(page: Page, which: 'pack' | 'nopack'): Promise<string> {
  await page.goto(which === 'pack' ? `/findings?cve=${PACK_CVE}` : '/findings')
  await expect(h1(page)).toContainText(/unresolved finding/)
  const links = page.locator('a[href^="/findings/"]:visible')
  await expect(links.first()).toBeVisible()
  for (const a of await links.all()) {
    const isPack = (await a.innerText()).trim() === PACK_CVE
    if ((which === 'pack') === isPack) return (await a.getAttribute('href'))!.replace('/findings/', '')
  }
  throw new Error(`no ${which} finding on the page`)
}
/** Put the finding back to open when a test left it closed. */
async function reopen(page: Page, id: string) {
  await page.goto(`/findings/${id}`)
  const b = page.getByRole('button', { name: 'Reopen finding' })
  if (await b.isVisible()) { await b.click(); await expect(page.getByRole('button', { name: 'Mark as handled' })).toBeVisible() }
}

test.describe('findings: list (S-MIT-1)', () => {
  test('headline, filters, CVE filter, open a row, Back, reload', async ({ page, isMobile }, info) => {
    const errors = collectErrors(page)
    await start(page, 'operator')
    await expect(h1(page)).toContainText(/^\d+ unresolved findings?, \d+ confirmed$/)
    const rows = rowsOf(page, isMobile)
    await expect(rows.first()).toBeVisible()
    await shot(page, 'findings-box', `${info.project.name}-list`)
    await page.getByRole('button', { name: 'Suspected', exact: true }).click()
    await expect(rows.first()).toBeVisible()
    await page.getByRole('button', { name: 'Resolved', exact: true }).click()
    await expect(rows.first().or(page.getByText('No findings in this status.').first()).first()).toBeVisible()
    await page.getByRole('button', { name: 'All', exact: true }).click()
    await expect(rows.first()).toBeVisible()
    await page.goto(`/findings?cve=${PACK_CVE.toLowerCase()}`) // lower case in the address bar
    await expect(page.getByRole('button', { name: new RegExp(`Clear ${PACK_CVE} filter`) })).toBeVisible()
    await expect(rows.first()).toBeVisible()
    for (const a of await page.getByRole('link', { name: PACK_CVE }).all()) await expect(a).toBeVisible()
    await page.getByRole('button', { name: new RegExp(`Clear ${PACK_CVE} filter`) }).click()
    await expect(page.getByRole('button', { name: new RegExp(`Clear ${PACK_CVE} filter`) })).toHaveCount(0)
    await page.goto(`/findings?cve=CVE-1999-0001`)
    await expect(page.getByText(/No findings for CVE-1999-0001/).first()).toBeVisible()
    await page.goto(`/findings?cve=${PACK_CVE}`) // the full list has 195 rows on the box: open the one that matters through the filter
    await page.getByRole('link', { name: PACK_CVE }).first().click()
    await expect(page).toHaveURL(/\/findings\/[^/]+$/)
    await expect(h1(page)).toContainText(PACK_CVE)
    await page.goBack()
    await expect(page).toHaveURL(/\/findings\?cve=/)
    await page.reload()
    await expect(h1(page)).toContainText(/unresolved finding/)
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('a viewer reads the list', async ({ page }) => {
    await start(page, 'viewer')
    await expect(h1(page)).toContainText(/unresolved finding/)
    await expect(page.locator('a[href^="/findings/"]:visible').first()).toBeVisible()
  })

  test('phone: no sideways scroll on the list and on a finding', async ({ page, isMobile }) => {
    test.skip(!isMobile, 'phone only')
    await start(page, 'operator')
    await expect(h1(page)).toContainText(/unresolved finding/)
    await noHScroll(page, 'list')
    const id = await findingId(page, 'pack')
    await page.goto(`/findings/${id}`)
    await expect(h1(page)).toContainText(PACK_CVE)
    await noHScroll(page, 'finding with a pack')
    await page.goto(`/findings/${await findingId(page, 'nopack')}`)
    await expect(h1(page)).toBeVisible()
    await noHScroll(page, 'finding without a pack')
  })
})

test.describe('findings: What to do with a confirmed pack (S-MIT-1)', () => {
  test('the pack names who confirmed it, shows the device IP, switches vendor, logs "Applied" and keeps it after a reload', async ({ page }, info) => {
    const errors = collectErrors(page)
    await start(page, 'operator')
    const id = await findingId(page, 'pack')
    await page.goto(`/findings/${id}`)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
    await expect(page.getByText(/Photo Station 6\.1\.2/).first()).toBeVisible()
    await expect(page.locator('body')).not.toContainText('{IP}')
    await expect(page.locator('body')).not.toContainText('{HOST}')
    await expect(page.locator('body')).not.toContainText('<IP-NAS>')
    await expect(page.getByText('Have I been hit?')).toBeVisible()
    await expect(page.getByText(/deadbolt/i).first()).toBeVisible()
    await shot(page, 'findings-box', `${info.project.name}-pack`)
    const heading = await h1(page).innerText()
    // form matrix: the firewall vendor changes the commands shown
    const vendors = [
      { name: /FortiGate/, code: `show firewall vip | grep -f ${NAS_IP}`, other: ['dst-address='] },
      { name: /MikroTik/, code: new RegExp(`(to-addresses|dst-address)=${NAS_IP.replaceAll('.', '[.]')}`), other: ['show firewall vip'] },
      { name: /Other device/, code: '', other: ['show firewall vip', 'dst-address='] },
    ]
    for (const v of vendors) {
      await page.getByRole('button', { name: v.name }).click()
      await expect(page.getByRole('button', { name: v.name })).toHaveAttribute('aria-pressed', 'true')
      if (v.code) await expect(page.getByText(v.code).first()).toBeVisible()
      for (const o of v.other) await expect(page.getByText(o, { exact: false }).first()).toBeHidden()
      await expect(page.locator('body')).not.toContainText('{IP}')
    }
    // "Applied" only writes a log entry
    await page.getByRole('button', { name: /MikroTik/ }).click()
    const applied = page.getByRole('button', { name: 'Applied' })
    const before = await applied.count()
    if (before > 0) {
      await applied.last().click()
      await toast(page, /Logged\. Rescan to confirm/)
    }
    await expect(page.getByText(/Recorded as applied by \S+@\S+/).first()).toBeVisible()
    await page.reload()
    await page.getByRole('button', { name: /MikroTik/ }).click() // the page opens on the declared vendor
    await expect(page.getByText(/Recorded as applied by \S+@\S+/).first()).toBeVisible()
    await expect(h1(page)).toHaveText(heading) // the status did not change
    await expect(page.getByText(/^Applied: /).first()).toBeVisible() // and the history has it
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('phone: every firewall vendor button is on screen without scrolling, and long commands wrap', async ({ page, isMobile }) => {
    test.skip(!isMobile, 'phone only')
    await start(page, 'operator')
    await page.goto(`/findings/${await findingId(page, 'pack')}`)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
    const group = page.getByRole('group', { name: 'Firewall vendor' })
    await group.scrollIntoViewIfNeeded() // the page may scroll down to the group, never sideways inside it
    const width = page.viewportSize()!.width
    const buttons = await group.getByRole('button').all()
    expect(buttons.length).toBeGreaterThanOrEqual(3)
    for (const b of buttons) { // no click first: a click would scroll the button into view and hide the defect
      const box = (await b.boundingBox())!
      expect(box.x, `${await b.innerText()} starts left of the screen`).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width, `${await b.innerText()} runs past the right edge`).toBeLessThanOrEqual(width)
    }
    await page.getByRole('button', { name: /MikroTik/ }).click()
    for (const pre of await page.locator('section[aria-labelledby="rec-firewall"] pre').all()) {
      const o = await pre.evaluate((e) => e.scrollWidth - e.clientWidth)
      expect(o, `a command box scrolls sideways by ${o}px`).toBeLessThanOrEqual(1)
    }
  })

  test('a viewer reads the pack; every "Applied" button is locked and says who may use it', async ({ page }) => {
    await start(page, 'viewer')
    await page.goto(`/findings/${await findingId(page, 'pack')}`)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
    const mark = page.getByRole('button', { name: /Mark as handled|Reopen finding/ })
    await expect(mark).toBeDisabled()
    await expect(mark).toHaveAttribute('title', /Operator/)
    for (const b of await page.getByRole('button', { name: 'Applied' }).all()) { await expect(b).toBeDisabled(); await expect(b).toHaveAttribute('title', /Operator/) }
  })

  test('links: the device, the CVE page, "Rescan this device"', async ({ page }) => {
    await start(page, 'operator')
    await page.goto(`/findings/${await findingId(page, 'pack')}`)
    await expect(page.getByRole('link', { name: 'Rescan this device' })).toHaveAttribute('href', /^\/scans\?target=.+/)
    await page.getByRole('link', { name: new RegExp(`Open ${PACK_CVE} page`) }).click()
    await expect(page).toHaveURL(new RegExp(`/cve/${PACK_CVE}`))
    await expect(h1(page)).toContainText(PACK_CVE)
  })
})

test.describe('findings: no pack yet, and the AI (S-MIT-1, S-AI-2)', () => {
  test('says there is no confirmed recommendation, shows the CISA source, and the AI buttons say whether they can be used', async ({ page }, info) => {
    const errors = collectErrors(page)
    await start(page, 'operator')
    await page.goto(`/findings/${await findingId(page, 'nopack')}`)
    await expect(page.getByText('No confirmed recommendation yet')).toBeVisible()
    await expect(page.getByText(/CISA's required action when it added this vulnerability on/)).toBeVisible()
    await expect(page.locator('blockquote').first()).not.toBeEmpty()
    await expect(page.locator('main a[target="_blank"]').first()).toBeVisible()
    await expect(page.getByText(/No confirmed exploitation signs/).first()).toBeVisible()
    await shot(page, 'findings-box', `${info.project.name}-nopack`)
    const ask = page.getByRole('button', { name: 'Ask my AI' })
    const explain = page.getByRole('button', { name: 'Explain', exact: true })
    if (REAL) { // no AI is wired to the box yet (mitigation's AI port answers "unavailable")
      await expect(ask).toBeDisabled()
      await expect(explain).toBeDisabled()
      await expect(page.getByText('The AI assistant is off, or no AI profile is assigned to this job.').first()).toBeVisible()
      await expect(page.getByRole('link', { name: 'Open AI assistant settings' }).first()).toHaveAttribute('href', '/settings/ai')
    } else {
      await ask.click()
      await expect(page.getByText(/AI-generated/).first()).toBeVisible()
      await page.reload()
      await expect(page.getByRole('button', { name: /^Ask my AI again$/ })).toHaveCount(1)
    }
    expect(errors, errors.join('\n')).toEqual([])
  })

  test('a viewer cannot ask the AI', async ({ page }) => {
    await start(page, 'viewer')
    await page.goto(`/findings/${await findingId(page, 'nopack')}`)
    await expect(page.getByRole('button', { name: 'Ask my AI' })).toBeDisabled()
    await expect(page.getByRole('button', { name: 'Explain', exact: true })).toBeDisabled()
  })
})

test.describe('findings: status dialog (S-MIT-1)', () => {
  // The form matrix of QA.md section 2: the chosen status decides whether a note is needed; each is saved, shown, kept after a reload, and reopened.
  const ACTIONS = [
    { radio: /^Patched/, headline: /is patched/, note: false },
    { radio: /^Mitigated/, headline: /is mitigated/, note: false },
    { radio: /^False positive/, headline: /marked as false positive/, note: true },
    { radio: /^Not relevant/, headline: /marked as not relevant/, note: true },
  ]
  for (const a of ACTIONS) {
    test(`mark as handled: ${a.radio.source}`, async ({ page }) => {
      const errors = collectErrors(page)
      await start(page, 'operator')
      const id = await findingId(page, 'nopack')
      await reopen(page, id)
      await page.goto(`/findings/${id}`)
      const open = page.getByRole('button', { name: 'Mark as handled' })
      await open.click()
      const dlg = page.getByRole('dialog')
      await expect(dlg.getByLabel(/Note \(optional\)/)).toBeVisible() // Patched is chosen first
      await dlg.getByRole('radio', { name: a.radio }).click()
      await expect(dlg.getByLabel(a.note ? /Note: why \(required\)/ : /Note \(optional\)/)).toBeVisible()
      if (a.note) {
        await dlg.getByRole('button', { name: 'Save status' }).click()
        await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
        await dlg.getByLabel(/Note/).fill('ab')
        await dlg.getByRole('button', { name: 'Save status' }).click()
        await expect(dlg.getByText(/at least 3 characters/)).toBeVisible()
      }
      const note = `checked by hand, ${a.radio.source}`
      await dlg.getByLabel(/Note/).fill(note)
      await dlg.getByRole('button', { name: 'Save status' }).click()
      await toast(page, /Status updated/)
      await expect(dlg).toHaveCount(0)
      await expect(h1(page)).toHaveText(a.headline)
      await expect(page.getByText(note).first()).toBeVisible()
      await page.reload()
      await expect(h1(page)).toHaveText(a.headline)
      await expect(page.getByText(note).first()).toBeVisible()
      await expect(page.getByRole('button', { name: 'Mark as handled' })).toHaveCount(0)
      await page.getByRole('button', { name: 'Reopen finding' }).click()
      await toast(page, /Finding reopened/)
      await expect(h1(page)).toHaveText(/may be affected|has a confirmed vulnerability/)
      await expect(page.getByText('Reopened').first()).toBeVisible()
      expect(errors, errors.join('\n')).toEqual([])
    })
  }

  test('Esc and Cancel close it without a change; a long note stops at 500 characters; the opener gets focus back', async ({ page }) => {
    await start(page, 'operator')
    const id = await findingId(page, 'nopack')
    await reopen(page, id)
    await page.goto(`/findings/${id}`)
    const heading = await h1(page).innerText()
    const btn = page.getByRole('button', { name: 'Mark as handled' })
    await btn.focus()
    await page.keyboard.press('Enter')
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    for (let i = 0; i < 12; i++) await page.keyboard.press('Tab')
    expect(await page.evaluate(() => !!document.activeElement?.closest('[role="dialog"]')), 'focus left the dialog').toBe(true)
    await page.keyboard.press('Escape')
    await expect(dlg).toHaveCount(0)
    await expect(btn).toBeFocused()
    await btn.click()
    await dlg.getByLabel(/Note/).fill('x'.repeat(600))
    expect((await dlg.getByLabel(/Note/).inputValue()).length).toBe(500)
    await dlg.getByRole('button', { name: 'Cancel' }).click()
    await expect(dlg).toHaveCount(0)
    await expect(h1(page)).toHaveText(heading)
  })

  test('a viewer cannot change the status', async ({ page }) => {
    await start(page, 'viewer')
    await page.goto(`/findings/${await findingId(page, 'nopack')}`)
    const mark = page.getByRole('button', { name: /Mark as handled|Reopen finding/ })
    await expect(mark).toBeDisabled()
    await expect(mark).toHaveAttribute('title', /Operator/)
  })
})

test.describe('findings: device panel, missing finding, signed out', () => {
  test('the device page lists the findings of that device and links to them', async ({ page }) => {
    await start(page, 'operator')
    await page.goto(`/findings/${await findingId(page, 'pack')}`)
    const dev = page.locator('section[aria-labelledby="dev-title"]').getByRole('link').first()
    await dev.click()
    await expect(page).toHaveURL(/\/devices\/[^/]+$/)
    const panel = page.getByRole('region', { name: 'Findings on this device' })
    await expect(panel).toBeVisible()
    await panel.getByRole('link', { name: PACK_CVE }).click()
    await expect(page).toHaveURL(/\/findings\/[^/]+$/)
    await expect(h1(page)).toContainText(PACK_CVE)
  })

  test('a finding that does not exist says so and offers the way back', async ({ page }) => {
    await start(page, 'operator', '/findings/does-not-exist')
    await expect(page.getByText(/No such finding/).first()).toBeVisible()
    await expect(page.getByRole('link', { name: 'Back to findings' })).toBeVisible()
    await page.goto(`/findings/${'f'.repeat(80)}`) // longer than any id
    await expect(page.getByText(/No such finding|not valid|invalid/i).first()).toBeVisible()
  })

  test('signed out, the list asks for the sign-in', async ({ page }) => {
    test.skip(!REAL, 'the mock has no real sign-in')
    await page.goto('/login')
    await page.context().clearCookies()
    await page.goto('/findings')
    await expect(page).toHaveURL(/\/login/)
  })

  test('Mitigation turned off: the "What to do" part says so; the finding, its status and the list stay', async ({ page }) => {
    test.skip(!REAL, 'turning a module off is checked on the box; the mock test does it in findings.test.tsx')
    await start(page, 'admin')
    const id = await findingId(page, 'pack')
    // the CSRF header is the value of the CSRF cookie
    const csrf = (await page.context().cookies()).find((c) => c.name === '__Host-vedette_csrf')?.value ?? ''
    const toggle = (on: boolean) => page.request.patch('/api/v1/modules/mitigation', { data: { enabled: on }, headers: { 'X-CSRF-Token': csrf } })
    try {
      expect((await toggle(false)).status()).toBe(200)
      await page.goto(`/findings/${id}`)
      await expect(h1(page)).toContainText(PACK_CVE)
      await expect(page.getByText(/is off/i).first()).toBeVisible()
      await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true })).toHaveCount(0)
      await expect(page.getByRole('button', { name: 'Mark as handled' }).or(page.getByRole('button', { name: 'Reopen finding' }))).toBeVisible()
      await page.goto('/findings')
      await expect(h1(page)).toContainText(/unresolved finding/)
    } finally {
      expect((await toggle(true)).status()).toBe(200)
    }
    await page.goto(`/findings/${id}`)
    await expect(page.getByText('Confirmed by Vedette maintainers', { exact: true }).first()).toBeVisible()
  })
})

test.describe('findings: screenshots and accessibility', () => {
  test('list, finding with a pack, finding without a pack, dialog: no serious axe violations, English only', async ({ page }, info) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    await start(page, 'operator')
    const pack = await findingId(page, 'pack')
    const nopack = await findingId(page, 'nopack')
    const tag = info.project.name
    for (const [path, name] of [['/findings', 'list'], [`/findings/${pack}`, 'pack'], [`/findings/${nopack}`, 'nopack']] as const) {
      await page.goto(path)
      await expect(h1(page)).toBeVisible()
      await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
      await shot(page, 'findings-box', `${name}-${tag}`)
      await noHScroll(page, path)
      await expectAccessible(page, `${path} ${tag}`)
      expect(await page.evaluate(() => document.body.innerText.match(/[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i)?.[0] ?? null), `${path}: Vietnamese text in the UI`).toBeNull()
    }
    await page.goto(`/findings/${nopack}`)
    await reopen(page, nopack)
    await page.getByRole('button', { name: 'Mark as handled' }).click()
    await shot(page, 'findings-box', `dialog-${tag}`)
    await expectAccessible(page, `dialog ${tag}`)
    expect(errors, errors.join('\n')).toEqual([])
  })
})
