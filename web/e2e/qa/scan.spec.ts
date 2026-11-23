// QA as a real user for the scan module (English-only UI), Settings > Scanning page (#850): IT operator watches and stops scans,
// admin turns engines on and off and sets the shared safety block, director (viewer), clean install. Scan now sits where the person is:
// Scan the LAN now is on the Network discovery card and the Devices list; Scan selected on the Devices list; Check this device now and
// Run vulnerability checks now on the device page (slots of #849, filled by features/scanning).
// Run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/scan.spec.ts
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot, turnOnModules } from '../helpers'

const DB = 'vedette-mock-db-v4'
const DIACRITICS = /[àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđ]/i

async function sample(page: Page) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await expect(page).toHaveURL(/\/setup/)
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Use sample data' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
  await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
  await turnOnModules(page, ['Vulnerability scan']) // A Preview module, off by default
}
/** Clean install; `commit` = mark the scan commitment at the network step (as a real user who chooses to scan right away). */
async function clean(page: Page, commit = false) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo') // The code the mock accepts
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
  await turnOnModules(page, ['Vulnerability scan']) // No bundle turns on the scan module, a preview one
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
/** Turn on the scan-credentialed module (off by default) the way an admin does in Settings, Modules. */
async function enableCred(page: Page) {
  await page.evaluate((k) => {
    const db = JSON.parse(localStorage.getItem(k) ?? '{}')
    db.core_modules = (db.core_modules ?? []).map((m: { id: string }) => (m.id === 'scan-credentialed' ? { ...m, enabled: true, enabled_at: new Date().toISOString() } : m))
    localStorage.setItem(k, JSON.stringify(db))
  }, DB)
  await page.reload()
}
const KEY = '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACBXAMPLEKEYAMPLEKEYAMPLEKEYAMPLEKEYWXYZ\n-----END OPENSSH PRIVATE KEY-----'

/** Start a LAN vulnerability check (Nuclei, POST /scans/runs) as its schedule or a KEV rescan would: its history, progress and Stop. */
async function startChecks(page: Page, targets: string[]) {
  await page.goto('/settings/scanning?tab=history') // the app (and its mock API) is up before the request
  await expect(page.getByRole('heading', { level: 1, name: 'Scanning' })).toBeVisible()
  return page.evaluate(async (ids) => (await fetch('/api/v1/scans/runs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ targets: ids }) })).status, targets)
}
const engine = (page: Page, name: RegExp) => page.getByRole('listitem', { name })
/** The only 404 allowed: GET /findings/summary, the shell's nav badges, whose mock comes with #825 (w-summary). Any other 404 fails. */
function notFound(page: Page) {
  const seen: string[] = []
  page.on('response', (r) => { if (r.status() === 404) seen.push(new URL(r.url()).pathname) })
  return () => seen.filter((p) => p !== '/api/v1/findings/summary')
}
const only404Summary = (errors: string[], unexpected: () => string[]) => { expect(unexpected()).toEqual([]); return errors.filter((e) => !/status of 404/.test(e)) }

test.describe('scan: IT operator', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-op') })

  test('Settings › Scanning: every engine by group, its memory and runs, Preview labels; the menu has no Vulnerability scans', async ({ page }) => {
    const errors = collectErrors(page)
    const nf = notFound(page)
    await page.goto('/settings/scanning')
    await expect(page.getByRole('heading', { level: 1, name: 'Scanning' })).toBeVisible()
    for (const g of ['Discover', 'Identify', 'Check vulnerabilities', 'Traps']) await expect(page.getByRole('heading', { level: 2, name: g })).toBeVisible()
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Preview')).toBeVisible()
    await expect(nuclei.getByText(/up to 1\.0 GB while on \(shared scan container\)/)).toBeVisible()
    await expect(nuclei.getByText(/devices checked/)).toBeVisible() // the last run, in words
    await expect(engine(page, /Service versions \(nmap\)/).getByText('Follows Network discovery (nmap)')).toBeVisible()
    await expect(nuclei.getByRole('switch')).toBeDisabled() // turning engines on or off is an administrator's
    await expect(page.getByText('Only an administrator can turn engines on or off.')).toBeVisible()
    await expect(page.getByRole('link', { name: /Vulnerability scans/ })).toHaveCount(0)
    await english(page, 'scanning')
    expect(only404Summary(errors, nf)).toEqual([])
  })

  test('old links land on their new place; ?tab= opens the tab; reload keeps it; an unknown tab falls back', async ({ page }) => {
    await page.goto('/scans')
    await expect(page).toHaveURL(/\/settings\/scanning\?tab=engines$/)
    await page.goto('/scans?tab=safety')
    await expect(page.getByRole('tab', { name: 'Safety' })).toHaveAttribute('aria-selected', 'true')
    await page.goto('/scans?target=a-web01') // an old link: the device page, with its buttons (slot device.actions)
    await expect(page).toHaveURL(/\/devices\/a-web01$/)
    await expect(page.getByRole('button', { name: 'Check this device now' })).toBeVisible()
    await page.goto('/settings/scanning?tab=probes')
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.reload()
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.getByRole('tab', { name: 'History' }).click()
    await expect(page).toHaveURL(/tab=history/)
    await page.goto('/settings/scanning?tab=nonsense')
    await expect(page.getByRole('tab', { name: 'Engines' })).toHaveAttribute('aria-selected', 'true')
  })

  test('the Devices list: "Scan selected" checks the ticked devices and shows the run; the device page has "Check this device now" and "Run vulnerability checks now"', async ({ page }) => {
    await loginAs(page, 'u-admin') // the discovery run is an administrator's (contract)
    await page.goto('/devices')
    await page.getByRole('checkbox', { name: 'Select FW-HQ' }).click()
    await page.getByRole('checkbox', { name: 'Select WEB01' }).click()
    await page.getByRole('button', { name: 'Scan selected (2)' }).click()
    await expect(page.getByText('Check 2 devices')).toBeVisible()
    await expect(page.getByRole('progressbar').first()).toBeVisible()
    await page.goto('/devices/a-nas02') // a device with a finding a vulnerability check can run on
    await expect(page.getByRole('button', { name: 'Check this device now' })).toBeDisabled() // one nmap run at a time
    await expect(page.getByText('Another scan is running.')).toBeVisible()
    await page.getByRole('button', { name: 'Run vulnerability checks now' }).click()
    await expect(page.getByRole('link', { name: 'Open the run' }).first()).toBeVisible()
  })

  test('a vulnerability check to the end: progress on the Nuclei card and in History, the shell indicator, per-device results, link to the finding', async ({ page }) => {
    expect(await startChecks(page, ['a-nas02'])).toBe(201) // fragile: only a person's own pick scans it
    await page.goto('/settings/scanning')
    const nuclei = engine(page, /Vulnerability checks \(Nuclei\)/)
    await expect(nuclei.getByText('Running', { exact: true })).toBeVisible()
    await expect(nuclei.getByRole('progressbar').first()).toBeVisible()
    await expect(page.getByRole('link', { name: '1 scan running' }).first()).toHaveAttribute('href', /\/settings\/scanning\?tab=history&run=/)
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
    expect(await startChecks(page, ['a-web01', 'a-srvad'])).toBe(201)
    expect(await startChecks(page, ['a-nas02'])).toBe(409) // one scan at a time on the box
    await page.goto('/settings/scanning?tab=history')
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.waitForTimeout(2500) // let the first device start, so "untouched" is about the second one
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
    expect(await startChecks(page, ['a-web01', 'a-srvad'])).toBe(201)
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
    await expect(page.getByText('No probe request matches.').first()).toBeVisible()
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

  test('turning off Network discovery names what stops with it; on again from the same switch', async ({ page }) => {
    await page.goto('/settings/scanning')
    const disc = engine(page, /Network discovery \(nmap\)/)
    await disc.getByRole('switch').click()
    const dlg = page.getByRole('dialog', { name: 'Turn off Network discovery (nmap)?' })
    await expect(dlg).toContainText('This also stops: Service versions (nmap), SNMP reading.')
    await dlg.getByRole('button', { name: 'Turn off' }).click()
    await expect(disc.getByRole('switch')).not.toBeChecked()
    await page.reload()
    await expect(disc.getByRole('switch')).not.toBeChecked()
    await disc.getByRole('switch').click()
    await expect(disc.getByRole('switch')).toBeChecked()
  })

  test('Scan the LAN now from the Network discovery card; one at a time: another check is locked with the reason and a link', async ({ page }) => {
    await page.goto('/settings/scanning')
    const disc = engine(page, /Network discovery \(nmap\)/)
    await disc.getByRole('button', { name: 'Scan the LAN now' }).click()
    await expect(disc.getByRole('progressbar').first()).toBeVisible()
    await page.goto('/devices/a-nas02') // a device with a finding a vulnerability check can run on
    await expect(page.getByRole('button', { name: 'Check this device now' })).toBeDisabled()
    await expect(page.getByText('Another scan is running.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open the run' })).toBeVisible()
  })

  test('the box itself is never part of a scan, and an excluded device is refused with the reason', async ({ page }) => {
    await page.goto('/devices/a-box')
    await page.getByRole('button', { name: 'Check this device now' }).click()
    await expect(page.getByText('The Vedette box itself is never part of a scan.').first()).toBeVisible()
  })

  test('a deep link opens the engine\'s own settings: SNMP credentials, OpenVAS needs; OpenVAS also on External exposure', async ({ page }) => {
    await page.goto('/settings/scanning#snmp')
    await expect(engine(page, /SNMP reading/).getByRole('heading', { name: 'SNMP credentials' })).toBeVisible()
    await page.goto('/settings/scanning#openvas')
    await expect(engine(page, /OpenVAS deep scan/).getByText(/Memory of this box/)).toBeVisible()
    await page.goto('/exposure')
    await expect(page.getByRole('button', { name: 'Enable OpenVAS' })).toBeVisible()
  })

  test('safety: scope and commitment, fragile types; bad input shows the error, typed data kept; good input saves and persists', async ({ page }) => {
    await page.goto('/settings/scanning?tab=safety')
    await expect(page.getByLabel('Network ranges, one per line')).toHaveValue(/192\.168\.10\.0\/24/)
    await expect(page.getByText(/^Confirmed on .* by admin@acme\.example\.$/)).toBeVisible()
    await expect(page.getByText(/Scans of your public targets follow their own testing terms and are not covered here yet/)).toBeVisible()
    await expect(page.getByRole('link', { name: /fragile devices? today/ })).toHaveAttribute('href', '/devices?show=fragile')
    const excl = page.getByLabel('One IP or network per line', { exact: true })
    const save = page.getByRole('button', { name: 'Save settings' })
    await excl.fill('192.168.10.250\nabc')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('Exclusion "abc" is not valid')
    await expect(excl).toHaveValue('192.168.10.250\nabc')
    await excl.fill('192.168.10.250\n192.168.20.0/28')
    await page.getByLabel('From', { exact: true }).fill('05:00')
    await page.getByLabel('Until', { exact: true }).fill('05:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('cannot be the same')
    await page.getByLabel('From', { exact: true }).fill('22:00')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await save.click()
    await expect(page.getByRole('alert')).toContainText('at least one day')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await page.locator('#speed-rps').selectOption('10')
    await save.click()
    await expect(page.getByText('Safety settings saved').first()).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('One IP or network per line', { exact: true })).toHaveValue('192.168.10.250\n192.168.20.0/28')
    await expect(page.locator('#speed-rps')).toHaveValue('10')
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

  // V1 does not offer the credentialed scan (no backend yet); the GUI is kept for post-v1, so the test is kept, skipped.
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
  test('no history or sample numbers; what is missing is fixed where it is: the ranges and the commitment in a dialog', async ({ page }) => {
    const errors = collectErrors(page)
    const nf = notFound(page)
    await clean(page)
    await page.goto('/settings/scanning?tab=safety')
    await expect(page.getByText('Not confirmed yet: nothing on the LAN is scanned until you tick it.')).toBeVisible()
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
    await page.goto('/devices')
    await expect(page.getByText('The network ranges are not confirmed yet.')).toBeVisible()
    await page.getByRole('button', { name: 'Set the network ranges' }).click()
    const dlg = page.getByRole('dialog', { name: 'Network ranges you may scan' })
    await expect(dlg.getByRole('list', { name: 'Ranges now' })).toContainText('10.20.0.0/24')
    await dlg.getByRole('checkbox', { name: /I confirm these network ranges belong to my company/ }).click()
    await dlg.getByRole('button', { name: 'Confirm these ranges' }).click()
    await expect(page.getByText('Network ranges saved and confirmed').first()).toBeVisible()
    await english(page, 'clean scanning')
    expect(only404Summary(errors, nf)).toEqual([])
  })

  test('when the scanner is not available, the Nuclei schedule says why nothing runs', async ({ page }) => {
    await clean(page, true)
    // Set before the app loads: a clean install keeps writing its store (public IP detection), which can overwrite a patch made while it runs.
    await page.addInitScript((k) => {
      const db = JSON.parse(localStorage.getItem(k) ?? '{}')
      db.scan_scanner = { available: false }
      localStorage.setItem(k, JSON.stringify(db))
    }, DB)
    await page.goto('/settings/scanning?tab=engines#nuclei')
    await expect(page.getByText(/nothing runs while the vulnerability scanner is not available/)).toBeVisible()
  })
})

test.describe('scan: screenshots and accessibility', () => {
  for (const t of ['light', 'dark'] as const) {
    test(`screens in ${t}`, async ({ page }, info) => {
      test.setTimeout(150_000)
      const errors = collectErrors(page)
      const nf = notFound(page)
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
      // No Credentialed scan tab in v1, so no shot of it.
      expect(only404Summary(errors, nf)).toEqual([])
    })
  }
})
