// QA như người dùng thật cho module scan (D-23, UI chỉ tiếng Anh D-28): IT operator starts/stops scans, admin sets safety and SSH keys, director (viewer), clean install.
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/scan.spec.ts
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { manyAssets } from '../../src/mocks/seed/assets'

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
}
/** Cài sạch; `commit` = đánh dấu cam kết quét ở bước mạng (như người dùng thật chọn quét ngay). */
async function clean(page: Page, commit = false) {
  await page.goto('/setup')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // D-544: the terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code').fill('setup-code-demo') // D-75: the code the mock accepts
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Test Admin')
  await page.getByLabel('Sign-in email').fill('admin@test.example')
  await page.getByLabel('Password', { exact: true }).fill('a-long-test-password-123')
  await page.getByLabel('Repeat password').fill('a-long-test-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel(/^Range 1/).fill('10.20.0.0/24')
  if (commit) await page.getByRole('checkbox', { name: /I confirm these ranges belong to my company/ }).check()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('radio', { name: /Mid-size business/ }).click() // gói nhỏ không có module quét
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page).not.toHaveURL(/\/setup/)
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

test.describe('scan: IT operator', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-op') })

  test('main page: headline, devices with findings preselected, locked devices say why, expired external IP is locked', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/scans')
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Last scan')
    await expect(page.getByRole('checkbox', { name: /NAS-PHOTOS/ })).not.toBeChecked() // fragile: never preselected (D-126)
    await expect(page.getByText('2 selected')).toBeVisible()
    await expect(page.getByText(/Not approved in the inventory, so not scanned/).first()).toBeVisible()
    await expect(page.getByRole('checkbox', { name: /203\.0\.113\.55/ })).toBeDisabled()
    await expect(page.getByText('Verification expired, verify again, so not scanned')).toBeVisible()
    await expect(page.getByText('Vedette is provided as-is. Its author is not responsible for how you use it.')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open External exposure' })).toHaveAttribute('href', '/exposure')
    await page.getByRole('button', { name: 'Clear selection' }).click()
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await expect(page.getByText('Select at least one device.')).toBeVisible()
    await english(page, 'scans')
    expect(errors).toEqual([])
  })

  test('500 devices (D-472): subnet groups and pages, search, the selection survives paging, Select all says what needs your own tick', async ({ page }, info) => {
    const errors = collectErrors(page)
    await page.goto('/scans') // the mock seeds the inventory settings on first read; the patch below keeps them
    await expect(page.getByRole('button', { name: 'Select all' })).toBeVisible()
    await page.evaluate(([k, extra]) => {
      const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
      db.inv_assets = [...(db.inv_assets ?? []), ...(extra as unknown[])]
      db.inv_settings = { ...db.inv_settings, lan_ranges: ['192.168.0.0/16'], scope_confirmed_at: new Date().toISOString(), scope_confirmed_by: 'admin@acme.example' }
      localStorage.setItem(k as string, JSON.stringify(db))
    }, [DB, manyAssets(470)] as const)
    await page.goto('/scans')
    await expect(page.getByText(/^50\d devices in the inventory$/)).toBeVisible()
    await expect(page.getByRole('button', { name: /^192\.168\.10\.0\/24/ })).toBeVisible()
    await expect(page.getByText(/^Page 1 of \d+$/)).toBeVisible()
    await page.getByRole('button', { name: 'Clear selection' }).click()
    await page.getByRole('checkbox', { name: /^SRV-AD / }).click()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.getByRole('button', { name: 'Next' }).click()
    await page.getByRole('searchbox', { name: 'Search devices' }).fill('PC-120')
    await page.getByRole('checkbox', { name: /^PC-120 / }).click()
    await expect(page.getByText('2 selected')).toBeVisible()
    await page.getByRole('button', { name: 'Clear filters' }).first().click()
    await page.getByRole('button', { name: 'Show selected' }).click()
    await expect(page.locator('[id^="tg-"][data-state="checked"]')).toHaveCount(2)
    await page.getByRole('button', { name: 'Show all' }).click()
    await page.getByRole('combobox', { name: 'Subnet' }).selectOption('192.168.40.0/24')
    await page.getByRole('button', { name: 'Select all' }).click()
    const report = page.getByText(/^Selected \d+ devices\./)
    await expect(report).toContainText(/need your own tick \(\d+ fragile, \d+ type unknown, \d+ added by hand\): Show them \d+ cannot be scanned \(\d+ not approved\)/)
    await shot(page, 'scan', `picker-500-${info.project.name}`)
    await noHScroll(page, 'picker 500')
    await expectAccessible(page, 'picker 500')
    await report.getByRole('button', { name: 'Show them' }).click()
    await expect(page.getByRole('combobox', { name: 'Show' })).toHaveValue('pick')
    await expect(page.locator('[id^="tg-"][data-state="checked"]')).toHaveCount(0)
    expect(errors).toEqual([])
  })

  test('?target= preselects one device; ?tab= opens the tab; reload keeps it; an unknown tab falls back', async ({ page }) => {
    await page.goto('/scans?target=a-web01')
    await expect(page.getByText('1 selected')).toBeVisible()
    await page.goto('/scans?tab=probes')
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.reload()
    await expect(page.getByRole('tab', { name: 'Probe log' })).toHaveAttribute('aria-selected', 'true')
    await page.getByRole('tab', { name: 'Auto rescan' }).click()
    await expect(page).toHaveURL(/tab=auto/)
    await page.goto('/scans?tab=nonsense')
    await expect(page.getByRole('tab', { name: 'Scans and history' })).toHaveAttribute('aria-selected', 'true')
  })

  test('scan one device to the end: progress, per-device results, link to the finding, headline updates', async ({ page }) => {
    await page.goto('/scans?target=a-nas02')
    // A fragile device is never ticked for you (D-126): not by the link, not by Select all. Your own tick is the pick.
    const nas = page.getByRole('checkbox', { name: /NAS-PHOTOS/ })
    await expect(nas).not.toBeChecked()
    await expect(page.getByText('Fragile: pick it to scan at a quarter of the speed').first()).toBeVisible()
    await page.getByRole('button', { name: 'Select all' }).click()
    await expect(nas).not.toBeChecked()
    await page.getByRole('button', { name: 'Clear selection' }).click()
    await nas.check()
    await page.getByRole('button', { name: /Scan now \(1\)/ }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Scanning')
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('Last scan', { timeout: 15_000 })
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
    await page.goto('/scans')
    await page.getByRole('button', { name: 'Select all' }).click()
    await page.getByRole('checkbox', { name: /^203\.0\.113\.12 / }).uncheck() // the standby line: the box does not go out through it now, so a run that holds it is refused (ip_not_current)
    await page.getByRole('button', { name: /Scan now/ }).click()
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await expect(page.getByText(/A scan is already running/).first()).toBeVisible()
    await page.waitForTimeout(2500)
    const t0 = Date.now()
    await page.getByRole('button', { name: 'Stop now' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('was stopped', { timeout: 5000 })
    expect(Date.now() - t0, 'stopping must finish in 5 seconds or less').toBeLessThanOrEqual(5000)
    await expect(page.getByText(/You pressed Stop now/).first()).toBeVisible()
    await page.reload()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('was stopped')
    await page.getByRole('button', { name: /View results of the scan/ }).first().click()
    await expect(page.getByRole('dialog').getByText(/This device was not touched/).first()).toBeVisible()
  })

  test('reload in the middle of a scan still shows progress and Stop now', async ({ page }) => {
    await page.goto('/scans')
    await page.getByRole('button', { name: 'Select all' }).click()
    await page.getByRole('checkbox', { name: /^203\.0\.113\.12 / }).uncheck() // the standby line (see above): a run that holds it is refused
    await page.getByRole('button', { name: /Scan now/ }).click()
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.reload()
    await expect(page.getByRole('button', { name: 'Stop now' })).toBeVisible()
    await page.getByRole('button', { name: 'Stop now' }).click()
    await expect(page.getByRole('heading', { level: 1 })).toContainText('was stopped', { timeout: 6000 })
  })

  test('probe log: filter, CSV download; auto rescan switch is admin only', async ({ page }) => {
    await page.goto('/scans?tab=probes')
    const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download CSV' }).click()])
    expect(dl.suggestedFilename()).toBe('vedette-probe-log.csv')
    await page.getByLabel('Filter by target, template, result').fill('nothing-matches-this')
    await expect(page.getByText('No probe requests yet.').first()).toBeVisible()
    await page.goto('/scans?tab=auto')
    await expect(page.getByRole('switch', { name: /Rescan automatically/ })).toBeDisabled()
    await expect(page.getByText(/Requires Admin role/).first()).toBeVisible()
  })

  test('keyboard: the results dialog returns focus to its button on close', async ({ page }) => {
    await page.goto('/scans')
    const btn = page.getByRole('button', { name: /View results of the scan/ }).first()
    await btn.focus()
    await page.keyboard.press('Enter')
    await expect(page.getByRole('dialog')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(btn).toBeFocused()
  })
})

test.describe('scan: admin sets safety', () => {
  test.beforeEach(async ({ page }) => { await sample(page); await loginAs(page, 'u-admin') })

  test('bad input: error in the right place, typed data kept; good input saves and persists', async ({ page }) => {
    await page.goto('/scans?tab=safety')
    const excl = page.getByLabel('One IP or network per line')
    const save = page.getByRole('button', { name: 'Save settings' })
    await excl.fill('192.168.10.250\nabc\n999.1.1.1')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('Line 2')
    await expect(excl).toHaveValue('192.168.10.250\nabc\n999.1.1.1')
    await excl.fill('192.168.10.250\n192.168.20.0/24')
    await page.getByLabel('From', { exact: true }).fill('05:00')
    await page.getByLabel('Until').fill('05:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('must differ')
    await page.getByLabel('From', { exact: true }).fill('22:00')
    await page.getByLabel('Until').fill('05:00')
    await page.locator('#sch-at').fill('12:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('is outside')
    await page.locator('#sch-at').fill('23:00')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await save.click()
    await expect(page.getByRole('alert')).toContainText('at least one day')
    for (const d of [1, 2, 3, 4, 5, 6, 7]) await page.locator(`#day-${d}`).click()
    await page.locator('#rate').selectOption('10')
    await save.click()
    await expect(page.getByText('Scan settings saved').first()).toBeVisible()
    await page.reload()
    await expect(page.getByLabel('One IP or network per line')).toHaveValue('192.168.10.250\n192.168.20.0/24')
    await expect(page.locator('#rate')).toHaveValue('10')
    await expect(page.getByText('No changes, no denial of service')).toBeVisible()
  })

  // D-417: v1 does not offer the credentialed scan (no backend yet); the GUI is kept for post-v1, so the walk is kept, skipped.
  test.skip('credentialed scan: module-off message; then wrong key/port/account show errors in place; the private key never comes back', async ({ page }) => {
    await page.goto('/scans?tab=credentialed')
    await expect(page.getByText('Credentialed scan module is off')).toBeVisible()
    await enableCred(page)
    await page.goto('/scans?tab=credentialed')
    const save = page.getByRole('button', { name: 'Save key' })
    await save.click()
    await expect(page.getByRole('alert')).toContainText('Choose the target server')
    // only servers are offered, not cameras, printers or PCs
    const options = await page.getByLabel('Target server').locator('option').allTextContents()
    expect(options.some((o) => /CAM-|HP-M404|CANON|PC-/.test(o)), options.join(' | ')).toBe(false)
    await page.getByLabel('Target server').selectOption({ index: 1 })
    await page.getByLabel('SSH port').fill('99999')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('SSH port')
    await page.getByLabel('SSH port').fill('22')
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
  test('can read history; scan, stop and save are locked with a reason', async ({ page }) => {
    await sample(page)
    await loginAs(page, 'u-view')
    await page.goto('/scans')
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await expect(page.getByText(/Requires Operator role/).first()).toBeVisible()
    await page.goto('/scans?tab=safety')
    await expect(page.getByText('Only an administrator can change these settings')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Save settings' })).toBeDisabled()
  })
})

test.describe('scan: clean install', () => {
  test('no history or sample numbers; the page says what to set up first: the scope on the Devices setup page (the box itself is already the first approved device, D-53)', async ({ page }) => {
    const errors = collectErrors(page)
    await clean(page)
    await page.goto('/scans')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText('Cannot scan yet: confirm the scan scope first')
    await expect(page.getByText('What to set up before scanning')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Scope and sensors' })).toHaveAttribute('href', '/devices/setup')
    // The box is the first device of every inventory (D-53, S-INV-5), but it is only scanned when picked (D-470), so step 2 is still to do.
    await expect(page.getByText(/2\. At least one approved device inside the scope \(Not done\)/)).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Devices' })).toBeVisible()
    await expect(page.getByRole('checkbox', { name: /^vedette 10\.20\.0\./ })).toBeEnabled() // pickable (D-470); nothing runs before the commitment
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await expect(page.getByText('No scans yet.').first()).toBeVisible()
    for (const tab of ['runs', 'safety', 'auto', 'probes']) {
      await page.goto(`/scans?tab=${tab}`)
      await expect(page.getByRole('heading', { level: 1 })).toBeVisible()
      for (const sample of ['NAS-PHOTOS', 'FW-HQ', 'CVE-2022-27593', '192.168.10.250', '192.168.10.21']) await expect(page.locator('body'), `${tab}: ${sample}`).not.toContainText(sample)
    }
    await page.goto('/scans?tab=safety')
    await expect(page.getByText(/nothing runs until the scan scope commitment is ticked/)).toBeVisible()
    await expect(page.getByText(/Next scan:/)).toHaveCount(0)
    await english(page, 'clean scans')
    expect(errors).toEqual([])
  })

  test('with the commitment ticked, only the devices step is left: the box itself can be picked, never ticked for you (D-470)', async ({ page }) => {
    await clean(page, true)
    await page.goto('/scans')
    await expect(page.getByText('What to set up before scanning')).toBeVisible()
    await expect(page.getByRole('link', { name: 'Open Scope and sensors' })).toHaveCount(0)
    await expect(page.getByRole('link', { name: 'Open Devices' })).toBeVisible()
    const box = page.getByRole('checkbox', { name: /^vedette 10\.20\.0\./ })
    await expect(box).toBeEnabled()
    await expect(page.getByText(/^The Vedette box itself: pick it to scan it from the network/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Select all' }).click()
    await expect(box).not.toBeChecked()
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await box.click()
    await expect(page.getByRole('button', { name: 'Scan now (1)' })).toBeEnabled()
  })

  test('the box public IP is listed as an external target but not scanned yet, and the page says so', async ({ page }) => {
    await clean(page, true)
    await page.goto('/scans')
    const ip = page.getByRole('checkbox', { name: /^203\.0\.113\.10 / })
    await expect(ip).toBeVisible() // the first start of the box found its public IPs by itself
    await expect(ip).toBeDisabled()
    await expect(page.getByText('External targets are not scanned yet').first()).toBeVisible()
    await expect(page.getByText(/This version does not scan external targets for vulnerabilities yet/)).toBeVisible()
  })

  test('when the scanner is not available, Scan now is locked with the reason', async ({ page }) => {
    await clean(page, true)
    // Set before the app loads: a clean install keeps writing its store (public IP detection), which can overwrite a patch made while it runs.
    await page.addInitScript((k) => {
      const db = JSON.parse(localStorage.getItem(k) ?? '{}')
      db.scan_scanner = { available: false }
      localStorage.setItem(k, JSON.stringify(db))
    }, DB)
    await page.goto('/scans')
    await expect(page.getByRole('button', { name: /Scan now/ })).toBeDisabled()
    await expect(page.getByText(/The vulnerability scanner is not available: the scan container or its scanner is missing/).first()).toBeVisible()
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
      for (const tab of ['runs', 'safety', 'auto', 'probes']) {
        await page.goto(`/scans?tab=${tab}`)
        await expect(page.getByRole('heading', { level: 1 }).first()).toBeVisible()
        await expect(page.getByRole('status').filter({ hasText: /^Loading$/ })).toHaveCount(0)
        await shot(page, 'scan', `${tab}-${tag}`)
        await noHScroll(page, `${tab} ${tag}`)
        await english(page, `${tab} ${tag}`)
        await expectAccessible(page, `${tab} ${tag}`)
      }
      // D-417: no Credentialed scan tab in v1, so no shot of it.
      expect(errors).toEqual([])
    })
  }
})
