// QA như người dùng thật cho module scan (D-23, UI chỉ tiếng Anh D-28), trang Settings › Scanning (#850): IT operator watches and stops scans,
// admin turns engines on and off and sets the shared safety block, director (viewer), clean install. Scan now sits where the person is:
// the Devices list and the device page place it with #849, so a LAN run is started here the way that button starts it (POST /scans/runs).
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/scan.spec.ts
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot, turnOnModules } from '../helpers'

const DB = 'vedette-mock-db-v4'
const DIACRITICS = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i

async function sample(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // D-544: the terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
  await turnOnModules(page, ['Vulnerability scan']) // D-624: a Preview module, off by default
}
/** Cài sạch; `commit` = đánh dấu cam kết quét ở bước mạng (như người dùng thật chọn quét ngay). */
async function clean(page: Page, commit = false) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // D-544: the terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo') // D-75: the code the mock accepts
  await page.getByLabel('Organization name', { exact: true }).fill('Test Company')
  await page.getByLabel('Administrator name', { exact: true }).fill('Test Admin')
  await page.getByLabel('Sign-in email', { exact: true }).fill('admin@test.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password', { exact: true }).fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel(/^Range 1/).fill('10.20.0.0/24')
  if (commit) await page.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }).check()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('radio', { name: /Mid-size business/ }).click()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await turnOnModules(page, ['Vulnerability scan']) // D-624: no bundle turns on the scan module, a preview one
}
async function patchDb(page: Page, patch: Record<string, unknown>) {
  await page.evaluate(([k, p]) => {
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    Object.assign(db, p)
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, patch] as const)
  await page.reload()
}
const loginAs = (page: Page, userId: 'u-admin' | 'u-op' | 'u-view') => patchDb(page, { core_session: { userId } })
async function theme(page: Page, t: 'light' | 'dark') {
  await page.evaluate((v) => localStorage.setItem('vedette-theme', v), t)
  await page.reload()
}
const noHScroll = async (page: Page, where: string) =>
  expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), `${where}: horizontal scroll`).toBeLessThanOrEqual(1)
const english = async (page: Page, where: string) => {
  const text = await page.evaluate(() => document.body.innerText)
  expect(text.match(DIACRITICS)?.[0] ?? null, `${where}: Vietnamese text left in the UI`).toBeNull()
}
/** Bật module scan-credentialed (mặc định tắt) như quản trị làm ở Settings, Modules. */
async function enableCred(page: Page) {
  await page.evaluate((k) => {
    const db = JSON.parse(localStorage.getItem(k) ?? '{}')
    db.core_modules = (db.core_modules ?? []).map((m: { id: string }) => (m.id === 'scan-credentialed' ? { ...m, enabled: true, enabled_at: new Date().toISOString() } : m))
    localStorage.setItem(k, JSON.stringify(db))
  }, DB)
  await page.reload()
}
const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBXAMPLEKEYAMPLEKEYAMPLEKEYAMPLEKEYWXYZ\n-----END OPENSSH PRIVATE KEY-----'

/** Start a LAN run the way ScanNowButton does (the Devices list "Scan selected" and the device page "Check this device now", #849). */
async function startRun(page: Page, targets: string[] | 'lan') {
  await page.goto('/settings/scanning?tab=history') // the app (and its mock API) is up before the request
  await expect(page.getByRole('heading', { level: 1, name: 'Scanning' })).toBeVisible()
  return page.evaluate(async (want) => {
    let ids = want as string[] | 'lan'
    if (ids === 'lan') {
      const t = (await (await fetch('/api/v1/scans/targets')).json()) as { items: { id: string; kind: string; selectable: boolean; pick_only: boolean; box: boolean }[] }
      ids = t.items.filter((x) => x.kind === 'internal' && x.selectable && !x.pick_only && !x.box).map((x) => x.id)
    }
    const r = await fetch('/api/v1/scans/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: ids }) })
    return r.status
  }, targets)
}
const engine = (page: Page, name: RegExp) => page.getByRole('listitem', { name })

test.describe('scan: IT operator', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-op') })

  test('Settings › Scanning: every engine by group, its cost and runs, Preview labels; the menu has no Vulnerability scans', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/settings/scanning')
    await expect(page.getByRole('heading', { level: 1, name: 'Scanning' })).toBeVisible()
    for (const g of ['Discover', 'Identify', 'Check vulnerabilities', 'Traps']) await expect(page.getByRole('heading', { level: 2, name: g })).toBeVisible()
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Preview')).toBeVisible()
    await expect(nuclei.getByText('400 MB memory, medium CPU')).toBeVisible()
    await expect(nuclei.getByText(/devices checked/)).toBeVisible() // the last run, in words
    await expect(nuclei.getByRole('switch')).toBeDisabled() // turning engines on or off is an administrator's
    await expect(page.getByRole('link', { name: /Vulnerability scans/ })).toHaveCount(0)
    await english(page, 'scanning')
    expect(errors.filter((e) => !/status of 404/.test(e))).toEqual([])
  })

  test('old links land on their new place; ?tab= opens the tab; reload keeps it; an unknown tab falls back', async ({ page }) => {
    await page.goto('/scans')
    await expect(page).toHaveURL(/\/settings\/scanning\?tab=engines$/)
    await page.goto('/scans?tab=safety')
    await expect(page.getByRole('tab', { name: 'Safety' })).toHaveAttribute('aria-selected', 'true')
    await page.goto('/scans?target=a-web01')
    await expect(page).toHaveURL(/\/devices\/a-web01$/) // its page has "Check this device now"
    await page.goto('/settings/scanning?tab=probes')
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.reload()
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.getByRole('tab', { name: 'History' }).click()
    await expect(page).toHaveURL(/tab=history/)
    await page.goto('/settings/scanning?tab=nonsense')
    await expect(page.getByRole('tab', { name: 'Engines' })).toHaveAttribute('aria-selected', 'true')
  })

  test.fixme('#849: the Devices list "Scan selected" and "Scan the LAN now", and the device page "Check this device now", start a run and show its progress there', async () => {})

  test('scan one device to the end: progress on the Nuclei card and in History, per-device results, link to the finding', async ({ page }) => {
    expect(await startRun(page, ['a-nas02'])).toBe(201) // fragile: only a person's own pick (the device page's button) scans it (D-126)
    await page.goto('/settings/scanning')
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Running')).toBeVisible()
    await expect(nuclei.getByRole('progressbar').first()).toBeVisible()
    await expect(page.getByRole('link', { name: '1 scan running' }).first()).toBeVisible() // the shell's indicator
    await page.getByRole('tab', { name: 'History' }).click()
    await expect(page.getByRole('heading', { level: 2, name: 'Device 1 of 1' })).toBeVisible()
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await expect(page.getByText(/^Last scan .*: 1 devices? checked/)).toBeVisible({ timeout: 40_000 }) // the dev mock scans a device in 15 s, read every 5 s (#830)
    await page.getByRole('button', { name: /View results of the scan/ }).first().click()
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('CVE-2022-27593: the scan template matches')).toBeVisible()
    await expect(dlg.getByRole('link', { name: 'Open finding' }).first()).toHaveAttribute('href', /\/findings\/f-/)
    await page.keyboard.press('Escape')
    await expect(dlg).toHaveCount(0)
    await page.getByRole('tab', { name: 'Probe log' }).click()
    await expect(page.getByText(/\d+ lines now/)).toBeVisible()
  })

  test('"Stop now": Stopping then Stopped within 5 seconds, unscanned devices untouched, one scan at a time', async ({ page }) => {
    expect(await startRun(page, 'lan')).toBe(201)
    expect(await startRun(page, ['a-nas02'])).toBe(409) // one scan at a time on the box
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.waitForTimeout(2500)
    const t0 = Date.now()
    await page.getByRole('button', { name: 'Stop now' }).click()
    await expect(page.getByText(/^Last scan was stopped/)).toBeVisible({ timeout: 5000 })
    expect(Date.now() - t0, 'stopping must finish in 5 seconds or less').toBeLessThanOrEqual(5000)
    await expect(page.getByText(/You pressed Stop now/).first()).toBeVisible()
    await page.reload()
    await expect(page.getByText(/^Last scan was stopped/)).toBeVisible()
    await page.getByRole('button', { name: /View results of the scan/ }).first().click()
    await expect(page.getByRole('dialog').getByText(/This device was not touched/).first()).toBeVisible()
  })

  test('reload in the middle of a scan still shows progress and Stop now', async ({ page }) => {
    expect(await startRun(page, 'lan')).toBe(201)
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.getByRole('button', { name: 'Stop now' }).click()
    await expect(page.getByText(/^Last scan was stopped/)).toBeVisible({ timeout: 6000 })
  })

  test('probe log: filter, CSV download; the auto rescan switch is admin only', async ({ page }) => {
    await page.goto('/settings/scanning?tab=probes')
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download CSV' }).click()])
    expect(dl.suggestedFilename()).toBe('vedette-probe-log.csv')
    await page.getByLabel('Filter by target, template, result', { exact: true }).fill('nothing-matches-this')
    await expect(page.getByText('No probe requests yet.').first()).toBeVisible()
    await page.goto('/settings/scanning?tab=engines#nuclei')
    await expect(page.getByRole('switch', { name: /Rescan automatically/ })).toBeDisabled()
    await expect(page.getByText(/Requires Admin role/).first()).toBeVisible()
  })

  test('keyboard: the results dialog returns focus to its button on close', async ({ page }) => {
    await page.goto('/settings/scanning?tab=history')
    const btn = page.getByRole('button', { name: /View results of the scan/ }).first()
    await btn.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(btn).toBeFocused()
  })
})

test.describe('scan: admin sets engines and the shared safety block', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-admin') })

  test('turn an engine off and on; turning off a running Nuclei asks, then stops its scan', async ({ page }) => {
    await page.goto('/settings/scanning')
    const versions = engine(page, /Service versions \(nmap\)/)
    await versions.getByRole('switch').click()
    await expect(page.getByText('Service versions (nmap) is off').first()).toBeVisible()
    await expect(versions.getByText('Off').first()).toBeVisible()
    await page.reload()
    await expect(versions.getByRole('switch')).not.toBeChecked()
    await versions.getByRole('switch').click()
    await expect(versions.getByRole('switch')).toBeChecked()
    expect(await startRun(page, 'lan')).toBe(201)
    await page.goto('/settings/scanning')
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Running')).toBeVisible()
    await nuclei.getByRole('switch').click()
    const dlg = page.getByRole('dialog', { name: /Turn off Vulnerability checks \(Nuclei\) and stop its scan\?/ })
    await dlg.getByRole('button', { name: 'Turn off and stop the scan' }).click()
    await page.getByRole('tab', { name: 'History' }).click()
    await expect(page.getByText(/^Last scan was stopped/)).toBeVisible({ timeout: 6000 })
  })

  test('a deep link opens the engine\'s own settings: SNMP credentials, OpenVAS needs', async ({ page }) => {
    await page.goto('/settings/scanning#snmp')
    await expect(engine(page, /SNMP reading/).getByRole('heading', { name: 'SNMP credentials' })).toBeVisible()
    await page.goto('/settings/scanning#openvas')
    await expect(engine(page, /OpenVAS deep scan/).getByText(/Memory of this box/)).toBeVisible()
  })

  test('safety: scope and commitment, fragile devices; bad input shows the error in the right place, typed data kept; good input saves and persists', async ({ page }) => {
    await page.goto('/settings/scanning?tab=safety')
    await expect(page.getByText(/^Confirmed scope: 192\.168\.10\.0\/24/)).toBeVisible()
    await expect(page.getByText(/Scan scope commitment ticked on/)).toBeVisible()
    await expect(page.getByRole('link', { name: /Change ranges or the commitment/ })).toHaveAttribute('href', '/devices/setup')
    await expect(page.getByRole('list', { name: 'Fragile devices' }).getByRole('link', { name: 'NAS-PHOTOS' })).toHaveAttribute('href', '/devices/a-nas02')
    const excl = page.getByLabel('One IP or network per line', { exact: true })
    const save = page.getByRole('button', { name: 'Save settings' })
    await excl.fill('192.168.10.250\nabc\n999.1.1.1')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('Line 2')
    await expect(excl).toHaveValue('192.168.10.250\nabc\n999.1.1.1')
    await excl.fill('192.168.10.250\n192.168.20.0/24')
    await page.getByLabel('From', { exact: true }).fill('05:00')
    await page.getByLabel('Until', { exact: true }).fill('05:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('must differ')
    await page.getByLabel('From', { exact: true }).fill('22:00')
    await page.getByLabel('Until', { exact: true }).fill('05:00')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await save.click()
    await expect(page.getByRole('alert')).toContainText('at least one day')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await page.locator('#rate').selectOption('10')
    await save.click()
    await expect(page.getByText('Scan settings saved').first()).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('One IP or network per line', { exact: true })).toHaveValue('192.168.10.250\n192.168.20.0/24')
    await expect(page.locator('#rate')).toHaveValue('10')
    await expect(page.getByText('No changes, no denial of service')).toBeVisible()
  })

  test('Nuclei schedule: a time outside the shared window is refused in place; a good one saves', async ({ page }) => {
    await page.goto('/settings/scanning?tab=engines#nuclei')
    const save = page.getByRole('button', { name: 'Save the schedule' })
    await page.locator('#sch-at').fill('12:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('is outside')
    await page.locator('#sch-at').fill('23:00')
    await save.click()
    await expect(page.getByText('Scan settings saved').first()).toBeVisible()
    await expect(page.getByText(/Next scan:/)).toBeVisible()
  })

  // D-417: v1 does not offer the credentialed scan (no backend yet); the GUI is kept for post-v1, so the walk is kept, skipped.
  test.skip('credentialed scan: module-off message; then wrong key/port/account show errors in place; the private key never comes back', async ({ page }) => {
    await page.goto('/settings/scanning?tab=credentialed')
    await expect(page.getByText('Credentialed scan module is off')).toBeVisible()
    await enableCred(page)
    await page.goto('/settings/scanning?tab=credentialed')
    const save = page.getByRole('button', { name: 'Save key' })
    await save.click()
    await expect(page.getByRole('alert')).toContainText('Choose the target server')
    // only servers are offered, not cameras, printers or PCs
    const options = await page.getByLabel('Target server', { exact: true }).locator('option').allTextContents()
    expect(options.some((o) => /CAM-|HP-M404|CANON|PC-/.test(o)), options.join(' | ')).toBe(false)
    await page.getByLabel('Target server', { exact: true }).selectOption({ index: 1 })
    await page.getByLabel('SSH port', { exact: true }).fill('99999')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('SSH port')
    await page.getByLabel('SSH port', { exact: true }).fill('22')
    await page.getByRole('textbox', { name: 'Account', exact: true }).fill('Root User')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('account name')
    await page.getByRole('textbox', { name: 'Account', exact: true }).fill('vedette-scan')
    await page.getByLabel('SSH private key', { exact: true }).fill('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample vedette')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('public key')
    await page.getByLabel('SSH private key', { exact: true }).fill('-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('too short')
    await page.getByLabel('SSH private key', { exact: true }).fill(KEY)
    await save.click()
    await expect(page.getByText(/ends with ••••WXYZ/).first()).toBeVisible()
    expect(await page.evaluate((k) => localStorage.getItem(k) ?? '', DB)).not.toContain('EAMPLEKEY')
    expect(await page.content()).not.toContain('AMPLEKEYAMPLEKEY')
    await page.reload()
    await expect(page.getByText(/••••WXYZ/)).toBeVisible()
    await page.getByRole('button', { name: /^Check connection to/ }).click()
    await expect(page.getByText(/Connected|Cannot connect/).first()).toBeVisible()
    await page.getByRole('button', { name: /^Remove the scan account of/ }).click()
    await page.keyboard.press('Escape')
    await expect(page.getByText(/••••WXYZ/)).toBeVisible()
    await page.getByRole('button', { name: /^Remove the scan account of/ }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Remove', exact: true }).click()
    await expect(page.getByText(/••••WXYZ/)).toHaveCount(0)
    await english(page, 'credentialed')
  })
})

test.describe('scan: director (viewer)', () => {
  test('can read engines and history; switches, stop and save are locked with a reason', async ({ page }) => {
    await sample(page)
    await loginAs(page, 'u-view')
    await page.goto('/settings/scanning')
    await expect(engine(page, /Network discovery \(nmap\)/).getByRole('switch')).toBeDisabled()
    await expect(page.getByText('Only an administrator can turn engines on or off.')).toBeVisible()
    await page.goto('/settings/scanning?tab=safety')
    await expect(page.getByText('Only an administrator can change these settings')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Save settings' })).toBeDisabled()
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByRole('heading', { level: 2, name: 'Scan history' })).toBeVisible()
  })
})

test.describe('scan: clean install', () => {
  test('no history or sample numbers; the page says what to set up first: the scope commitment on the Devices setup page', async ({ page }) => {
    const errors = collectErrors(page)
    await clean(page)
    await page.goto('/settings/scanning')
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Needs setup')).toBeVisible()
    await expect(nuclei.getByText(/The scan scope commitment is not ticked yet/)).toBeVisible()
    await page.goto('/settings/scanning?tab=safety')
    await expect(page.getByText('The scan scope commitment is not ticked yet.')).toBeVisible()
    await expect(page.getByRole('link', { name: /Change ranges or the commitment/ })).toHaveAttribute('href', '/devices/setup')
    await expect(page.getByText(/Never plants a file/)).toBeVisible() // the never-do list is shown before anything runs
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByText('No scans yet.').first()).toBeVisible()
    for (const tab of ['engines', 'safety', 'history', 'probes']) {
      await page.goto(`/settings/scanning?tab=${tab}`)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      for (const sample of ['NAS-PHOTOS', 'FW-HQ', 'CVE-2022-27593', '192.168.10.250', '192.168.10.21']) await expect(page.locator('main'), `${tab}: ${sample}`).not.toContainText(sample)
    }
    await page.goto('/settings/scanning?tab=engines#nuclei')
    await expect(page.getByText(/nothing runs until the scan scope commitment is ticked/)).toBeVisible()
    await expect(page.getByText(/Next scan:/)).toHaveCount(0)
    await english(page, 'clean scanning')
    expect(errors.filter((e) => !/status of 404/.test(e))).toEqual([])
  })

  test('with the commitment ticked, a LAN sweep never takes the box itself: the box is scanned only when picked (D-470)', async ({ page }) => {
    await clean(page, true)
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByRole('heading', { level: 1, name: 'Scanning' })).toBeVisible()
    const status = await page.evaluate(async () => {
      const t = (await (await fetch('/api/v1/scans/targets')).json()) as { items: { id: string; box: boolean; pick_only: boolean; selectable: boolean }[] }
      const box = t.items.find((x) => x.box)
      return { box: box ? { pick_only: box.pick_only, selectable: box.selectable } : null }
    })
    expect(status.box).toEqual({ pick_only: true, selectable: true })
  })

  test('when the scanner is not available, the Nuclei card says why', async ({ page }) => {
    await clean(page, true)
    // Set before the app loads: a clean install keeps writing its store (public IP detection), which can overwrite a patch made while it runs.
    await page.addInitScript((k) => {
      const db = JSON.parse(localStorage.getItem(k) ?? '{}')
      db.scan_scanner = { available: false }
      localStorage.setItem(k, JSON.stringify(db))
    }, DB)
    await page.goto('/settings/scanning')
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Error')).toBeVisible()
    await expect(nuclei.getByText(/The vulnerability scanner is not available: the scan container or its scanner is missing/)).toBeVisible()
  })
})

test.describe('scan: screenshots and accessibility', () => {
  for (const t of ['light', 'dark'] as const) {
    test(`screens in ${t}`, async ({ page }, info) => {
      test.setTimeout(150_000)
      const errors = collectErrors(page)
      await sample(page)
      await loginAs(page, 'u-admin')
      await theme(page, t)
      const tag = `${info.project.name}-${t}`
      for (const tab of ['engines', 'safety', 'history', 'probes']) {
        await page.goto(`/settings/scanning?tab=${tab}`)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await shot(page, 'scan', `${tab}-${tag}`)
        await noHScroll(page, `${tab} ${tag}`)
        await english(page, `${tab} ${tag}`)
        await expectAccessible(page, `${tab} ${tag}`)
      }
      // D-417: no Credentialed scan tab in v1, so no shot of it.
      expect(errors.filter((e) => !/status of 404/.test(e))).toEqual([])
    })
  }
})
