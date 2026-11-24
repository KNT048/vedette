// Inventory QA (S-INV-1..4) as a real user, English-only UI.
// Run: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/inventory.spec.ts --workers=1
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, sampleStart } from './clean'

const DB = 'vedette-mock-db-v4'
type UserId = 'u-admin' | 'u-op' | 'u-view'
/**
 * Write the mock store BEFORE the page loads (the init script runs once per call), because the open page may overwrite localStorage when it reloads.
 * `patch` merges into the existing table (or `fallback` if the table has not been created).
 */
async function patchDb(page: Page, table: string, patch: Record<string, unknown>, fallback: Record<string, unknown> = {}) {
  const token = `${table}-${Date.now()}-${Math.random()}`
  await page.addInitScript(([k, t, p, f, tok]) => {
    if (sessionStorage.getItem(`__seed_${tok}`)) return
    sessionStorage.setItem(`__seed_${tok}`, '1')
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    db[t as string] = { ...((db[t as string] as object) ?? f as object), ...(p as object) }
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, table, patch, fallback, token] as const)
  await page.reload()
}
/** Switch the signed-in user. */
const loginAs = (page: Page, userId: UserId) => patchDb(page, 'core_session', { userId })
const SETTINGS_FALLBACK = { active: { enabled: false, days: [1, 2, 3, 4, 5, 6, 7], from: '23:00', to: '05:00', rate: 50, exclusions: [] }, fragile_kinds: ['printer'], regular_scan_kinds: [] }
async function setTheme(page: Page, theme: 'light' | 'dark') {
  await page.evaluate((t) => localStorage.setItem('vedette-theme', t), theme)
  await page.reload()
}
const noHScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'page must not scroll sideways').toBeLessThanOrEqual(1)
/** All displayed text is English: no Vietnamese diacritics in the content. */
const expectEnglishOnly = async (page: Page, label: string) => expect(await page.locator('body').innerText(), `${label}: Vietnamese text on the page`).not.toMatch(DIACRITICS)
const h1 = (page: Page) => page.getByRole('heading', { level: 1 })
// the small "N devices, M not added yet" line of the list's toolbar (the title is just "Devices")
const countLine = (page: Page) => page.getByText(/^\d+ devices?, /)
const countOf = async (page: Page) => { await expect(countLine(page)).toHaveText(/^\d+ devices?,/); return Number((await countLine(page).innerText()).match(/^(\d+)/)![1]) }

/** Turn a module on in the mock store (agent-intake is off by default in the sample data), written before the page loads. */
async function enableModule(page: Page, id: string) {
  await page.goto('/devices')
  await expect(countLine(page)).toHaveText(/^\d+ devices?,/) // the module table exists in the mock db once the app has loaded
  const token = `mod-${id}-${Date.now()}`
  await page.addInitScript(([k, m, tok]) => {
    if (sessionStorage.getItem(`__seed_${tok}`)) return
    sessionStorage.setItem(`__seed_${tok}`, '1')
    const db = JSON.parse(localStorage.getItem(k as string) ?? '{}')
    if (Array.isArray(db.core_modules)) db.core_modules = db.core_modules.map((x: { id: string }) => (x.id === m ? { ...x, enabled: true, enabled_at: new Date().toISOString() } : x))
    localStorage.setItem(k as string, JSON.stringify(db))
  }, [DB, id, token] as const)
  await page.reload()
}

/** Clean install through the wizard with the network range the user types (no sample data), then enter the box. */
async function cleanInstall(page: Page, lan: string) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByRole('checkbox', { name: 'I have read, understood and agree to the terms of use' }).click() // The terms of use come first
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByLabel('Setup code', { exact: true }).fill('setup-code-demo') // The code the mock accepts
  await page.getByLabel('Organization name', { exact: true }).fill('Test Company')
  await page.getByLabel('Administrator name', { exact: true }).fill('Alex Admin')
  await page.getByLabel('Sign-in email', { exact: true }).fill('admin@testco.example')
  await page.getByLabel('Password', { exact: true }).fill('a-very-long-password-123')
  await page.getByLabel('Repeat password', { exact: true }).fill('a-very-long-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('textbox', { name: 'Range 1' }).fill(lan)
  await page.getByRole('button', { name: 'Continue' }).click()
}
async function finishWizard(page: Page) {
  await page.getByRole('radio', { name: /Small business/ }).or(page.getByRole('radio').first()).first().click()
  await page.getByRole('button', { name: 'Finish setup' }).click()
  await expect(page).not.toHaveURL(/\/setup/) // the wizard saves the scope before it leaves this page
  await expect(h1(page)).toBeVisible()
}

test.describe('screens (screenshots to look at)', () => {
  for (const theme of ['light', 'dark'] as const) {
    test(`main screens ${theme}`, async ({ page }, info) => {
      const errors = collectErrors(page)
      await sampleStart(page)
      await setTheme(page, theme)
      const tag = `${info.project.name}-${theme}`
      for (const [name, path] of [['list', '/devices'], ['detail', '/devices/a-nas02'], ['setup', '/devices/setup']] as const) {
        await page.goto(path)
        await expect(h1(page)).toBeVisible()
        await page.waitForTimeout(400)
        await shot(page, 'inventory', `${name}-${tag}`)
        await noHScroll(page)
        await expectAccessible(page, `${name} ${tag}`)
        await expectEnglishOnly(page, name)
      }
      expect(errors).toEqual([])
    })
  }
})

test.describe('P2 IT person, day to day: list, add manually, CSV, detail', () => {
  test.beforeEach(async ({ page }) => { await sampleStart(page); await loginAs(page, 'u-op') })

  test('add manually in 3 clicks; Escape in the picker closes only the list; errors keep input; Enter submits', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/devices')
    const before = await countOf(page)
    await page.getByRole('button', { name: 'Add a device' }).click()
    const dialog = page.getByRole('dialog')
    const picker = dialog.getByRole('combobox')
    await picker.focus()
    await expect(dialog.getByRole('listbox')).toHaveCount(0) // no list until the user types: a fixed list on open reads as "only these are supported"
    await picker.fill('forti')
    await expect(dialog.getByRole('listbox')).toBeVisible()
    await shot(page, 'inventory', 'add-dialog-picker')
    await page.keyboard.press('Escape')
    await expect(dialog.getByRole('listbox')).toBeHidden()
    await expect(dialog).toBeVisible() // first Escape only closes the suggestion list
    await picker.press('ArrowDown') // the arrow key opens the list again
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Host name', { exact: true }).fill('Test firewall')
    await dialog.getByLabel('IP address', { exact: true }).fill('192.168.10.1')
    await dialog.getByLabel('IP address', { exact: true }).press('Enter')
    await expect(dialog.getByRole('alert')).toContainText('192.168.10.1')
    await expect(dialog.getByLabel('Host name', { exact: true })).toHaveValue('Test firewall')
    await shot(page, 'inventory', 'add-dialog-error')
    await dialog.getByLabel('IP address', { exact: true }).fill('192.168.10.99') // free in the sample data (.250 is the box itself, other addresses belong to sample devices)
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(countLine(page)).toContainText(String(before + 1))
    // typing shows suggestions; Escape twice closes everything
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByRole('combobox').fill('forti')
    await expect(page.getByRole('dialog').getByRole('listbox')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog').getByRole('listbox')).toBeHidden()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toBeHidden()
    // exactly 3 clicks (plus the typing): open (Manual is chosen), pick the first suggestion, Add
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByLabel('IP address', { exact: true }).fill('192.168.10.98')
    await page.getByRole('dialog').getByRole('combobox').fill('forti')
    await page.getByRole('dialog').getByRole('option').first().click()
    await page.getByRole('dialog').getByRole('button', { name: 'Add', exact: true }).click()
    await expect(page.getByRole('dialog')).toBeHidden()
    await expect(countLine(page)).toContainText(String(before + 2))
    await page.reload()
    await expect(countLine(page)).toContainText(String(before + 2))
    expect(errors).toEqual([])
  })

  test('picker search: model numbers, aliases, vendor, category; badge; many results are capped', async ({ page }) => {
    await page.goto('/devices')
    await page.getByRole('button', { name: 'Add a device' }).click()
    const dialog = page.getByRole('dialog')
    const picker = dialog.getByRole('combobox')
    await picker.fill('fortigate 60f')
    await expect(dialog.getByRole('option').first()).toContainText('FortiGate')
    await expect(dialog.getByRole('option').first()).toContainText(/Exploited in real attacks before: \d+ vulnerabilities/)
    for (const [q, expected] of [['qnap', 'QNAP'], ['synology', 'Synology'], ['exchange', 'Exchange'], ['hikvision', 'Hikvision'], ['printer', 'printer'], ['windows server 2019', 'Windows Server 2019']] as const) {
      await picker.fill(q)
      await expect(dialog.getByRole('option').first()).toContainText(expected)
    }
    await picker.fill('microsoft')
    expect(await dialog.getByRole('option').count()).toBeLessThanOrEqual(30)
    await expect(dialog.getByText(/\d+ more match(es)?\. Keep typing to narrow the list\./)).toBeVisible()
    await shot(page, 'inventory', 'picker-many')
    await expectAccessible(page, 'picker open')
    await picker.fill('zzzzqqq')
    await expect(dialog.getByText(/No matching product/)).toBeVisible()
  })

  test('product not listed: enter maker and product yourself', async ({ page }) => {
    await page.goto('/devices')
    const before = await countOf(page)
    await page.getByRole('button', { name: 'Add a device' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('button', { name: /Can't find it/ }).click()
    await expect(dialog.getByRole('button', { name: 'Add', exact: true })).toBeDisabled()
    await dialog.getByLabel('Maker', { exact: true }).fill('Fortinet')
    await dialog.getByLabel('Product', { exact: true }).fill('FortiGate-Lab')
    await shot(page, 'inventory', 'add-custom')
    await dialog.getByLabel('Host name', { exact: true }).fill('Lab firewall')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(countLine(page)).toContainText(String(before + 1))
    await page.getByRole('link', { name: 'Lab firewall' }).first().click()
    await expect(page.getByText('Fortinet FortiGate-Lab').first()).toBeVisible()
  })

  test('CSV with BOM, semicolons, empty lines; export then re-import creates no duplicates', async ({ page }) => {
    await page.goto('/devices')
    const before = await countOf(page)
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByRole('radio', { name: /^CSV import/ }).click() // #849: CSV import is a method of Add a device
    const csv = '﻿Device name;IP address;Product;Version;Type\r\n\r\nBranch firewall;192.168.77.1;FortiGate;7.2.5;Firewall\r\n\r\nAccounting printer;192.168.77.20;;;Printer\r\n;;;;\r\nBad one;999.1.1.1;;;\r\nWarehouse server;;;;Server\r\n'
    await page.getByLabel('Choose a CSV file', { exact: true }).setInputFiles({ name: 'devices.csv', mimeType: 'text/csv', buffer: Buffer.from(csv, 'utf8') })
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('Added 3 devices, skipped 1 row.')).toBeVisible()
    await expect(dlg.getByText('Line 7:')).toBeVisible()
    await shot(page, 'inventory', 'import-result')
    await dlg.getByRole('button', { name: 'Close', exact: true }).first().click()
    await expect(countLine(page)).toContainText(String(before + 3))
    await expect(page.getByRole('link', { name: 'Branch firewall' }).first()).toBeVisible()
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()])
    const text = (await import('node:fs')).readFileSync((await download.path())!, 'utf8')
    expect(text.charCodeAt(0)).toBe(0xfeff)
    expect(text).toContain('Branch firewall')
    expect(text).toContain('Warehouse server')
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByRole('radio', { name: /^CSV import/ }).click() // #849: CSV import is a method of Add a device
    await page.getByLabel('Choose a CSV file', { exact: true }).setInputFiles({ name: 'export.csv', mimeType: 'text/csv', buffer: Buffer.from(text, 'utf8') })
    await expect(page.getByRole('dialog').getByText(/Added 0 devices/)).toBeVisible()
    await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).first().click()
    await expect(countLine(page)).toContainText(String(before + 3))
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByRole('radio', { name: /^CSV import/ }).click() // #849: CSV import is a method of Add a device
    await page.getByLabel('Choose a CSV file', { exact: true }).setInputFiles({ name: 'empty.csv', mimeType: 'text/csv', buffer: Buffer.from('', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('The file is empty')
    await page.getByLabel('Choose a CSV file', { exact: true }).setInputFiles({ name: 'wrong.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\n1,2\n', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('column headers')
  })

  test('detail: very long name and 20+ observations do not break the layout', async ({ page }) => {
    const errors = collectErrors(page)
    const long = 'Z'.repeat(64)
    await page.goto('/devices')
    await expect(countLine(page)).toHaveText(/^\d+ devices?,/) // mock API ready
    const r = await page.evaluate(async (n) => {
      const res = await fetch('/api/v1/inventory/devices', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ catalog_id: 'synology-nas-dsm', name: n, ip: '192.168.55.5' }) })
      return res.json() as Promise<{ id: string }>
    }, long)
    for (let i = 0; i < 24; i++) await page.evaluate(async ([id, k]) => { await fetch(`/api/v1/inventory/devices/${id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: k }) }) }, [r.id, i % 2 ? 'nas' : 'router'] as const)
    await page.goto(`/devices/${r.id}?tab=observations`)
    await expect(h1(page)).toContainText(long)
    // desktop shows a table, phones show a list: count whichever is visible
    const shown = (await page.getByRole('table', { name: 'Observations for this device' }).getByRole('row').count()) + (await page.getByRole('list', { name: 'Observations for this device' }).getByRole('listitem').count())
    expect(shown).toBeGreaterThan(20)
    await noHScroll(page)
    await shot(page, 'inventory', 'detail-long')
    await expectAccessible(page, 'detail long')
    await page.goBack()
    expect(errors).toEqual([])
  })

  test('add software to a device, then remove it', async ({ page }) => {
    await page.goto('/devices/a-nas02?tab=software')
    await page.getByRole('button', { name: 'Add software' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('combobox').fill('wordpress')
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Version (optional)', { exact: true }).fill('6.5.2')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByText('WordPress').first()).toBeVisible()
    await page.getByRole('button', { name: /^Remove WordPress from the device$/ }).first().click()
    await expect(page.getByRole('button', { name: /^Remove WordPress from the device$/ })).toHaveCount(0)
  })

  test('not added yet: add, flag as unknown; removing a device with findings says so; Escape and Cancel keep it', async ({ page }) => {
    await page.goto('/devices?tab=review') // #849: devices found but not approved are the To review list
    const pending = page.getByRole('list', { name: /new devices not added yet/ })
    await expect(pending.getByRole('listitem')).toHaveCount(2)
    await pending.getByRole('button', { name: 'Mark unknown' }).first().click()
    await expect(pending.getByText('Marked unknown').first()).toBeVisible()
    await pending.getByRole('button', { name: /^Add .+ to your devices$/ }).first().click()
    await expect(countLine(page)).toContainText('1 not added yet')
    await page.goto('/devices/a-nas02')
    await page.getByRole('button', { name: 'Remove from list' }).click()
    const dlg = page.getByRole('dialog')
    // the wording of #836 (on main): the count, and that removing the device removes its findings
    await expect(dlg).toContainText(/This device has \d+ findings?; removing the device removes (it|them) too\./)
    await shot(page, 'inventory', 'delete-with-findings')
    await page.keyboard.press('Escape')
    await expect(dlg).toBeHidden()
    await page.getByRole('button', { name: 'Remove from list' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()
    await expect(page).toHaveURL(/a-nas02/)
    await page.getByRole('button', { name: 'Remove from list' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Remove from list' }).click()
    await expect(page).toHaveURL(/\/devices$/)
    await page.goto('/devices/a-nas02')
    await expect(page.getByText('This device does not exist').first()).toBeVisible()
    const f = await page.evaluate(async () => (await fetch('/api/v1/findings')).text())
    expect(f).not.toContain('a-nas02')
  })
})

test.describe('P1 director, view only', () => {
  test('write buttons are locked with a reason; the setup page says which role is needed', async ({ page }) => {
    await sampleStart(page); await loginAs(page, 'u-view')
    await page.goto('/devices')
    // #849: CSV import is a method inside Add a device, so this one button gates every way to add
    const b = page.getByRole('button', { name: 'Add a device' })
    await expect(b).toBeDisabled()
    await expect(b).toHaveAttribute('title', /Operator/)
    await expect(page.getByRole('button', { name: 'Export CSV' })).toBeEnabled()
    await expect(page.getByRole('link', { name: 'Device discovery settings' })).toHaveCount(0)
    await page.goto('/devices/setup')
    await expect(page.getByText('You do not have access to this page')).toBeVisible()
    await page.goto('/devices/a-nas02')
    await expect(page.getByRole('button', { name: 'Remove from list' })).toBeDisabled()
  })
})

test.describe('Admin: scan scope, sensor, agents', () => {
  test.beforeEach(async ({ page }) => { await sampleStart(page) })

  test('ranges: invalid, public, no prefix, host bits, overlap; add, edit, remove; midnight window; save', async ({ page }) => {
    await page.goto('/devices/setup')
    const input = page.locator('#range-input')
    const err = page.locator('#range-input-error')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    for (const [value, msg] of [['abc', /not a valid range/], ['8.8.8.0/24', /not an internal range/], ['192.168.10.0/25', /overlaps/], ['192.168.10.0/24', /already in the list/]] as const) {
      await input.fill(value); await input.press('Enter')
      await expect(err).toContainText(msg)
    }
    await expect(rows).toHaveCount(2)
    // an address without a prefix length is never guessed: it is refused with a clear message, then accepted once the size is typed
    await input.fill('10.142.0.0'); await input.press('Enter')
    await expect(err).toContainText('"10.142.0.0" has no prefix length. Add it so Vedette scans the right size of network, for example 10.142.0.0/24 or 10.142.0.0/25.')
    await expect(rows).toHaveCount(2)
    await input.fill('10.142.0.0/25'); await input.press('Enter')
    await expect(rows).toHaveCount(3)
    // host bits are cleared (keeping the typed prefix), with a visible note
    await input.fill('192.168.30.77/24'); await input.press('Enter')
    await expect(page.getByRole('status').filter({ hasText: '192.168.30.0/24' })).toBeVisible()
    await expect(rows).toHaveCount(4)
    // edit: the value moves into the input; remove works on every row
    await page.getByRole('button', { name: 'Edit range 192.168.30.0/24' }).click()
    await expect(input).toHaveValue('192.168.30.0/24')
    await expect(rows).toHaveCount(3)
    await input.fill('192.168.31.0/24'); await input.press('Enter')
    await page.getByRole('button', { name: 'Remove range 10.142.0.0/25' }).click()
    await expect(rows).toHaveCount(3)
    await shot(page, 'inventory', 'ranges-edited')
    // scope must be confirmed again after the ranges changed
    await expect(page.getByLabel(/I confirm these network ranges/)).not.toBeChecked()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByRole('alert').filter({ hasText: 'confirmation' })).toBeVisible()
    await page.getByLabel(/I confirm these network ranges/).check()
    await expect(page.getByText(/provided as is/)).toBeVisible()
    await page.locator('#active-to').fill('23:00')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByRole('alert').filter({ hasText: 'cannot be the same' })).toBeVisible()
    await page.locator('#active-from').fill('22:00'); await page.locator('#active-to').fill('06:00')
    await page.locator('#excl-input').fill('192.168.31.0/24'); await page.locator('#excl-input').press('Enter')
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.reload()
    await expect(page.locator('#active-from')).toHaveValue('22:00')
    await expect(rows).toHaveCount(3)
    await expect(h1(page)).toContainText('3 network ranges')
  })

  test('scope confirmation sits above Save; re-tick only when the set of ranges changed; Enter adds a range', async ({ page }) => {
    await page.goto('/devices/setup')
    const bar = page.locator('#scope')
    await expect(bar.getByRole('button', { name: 'Save changes' })).toBeVisible()
    const confirm = bar.getByLabel(/I confirm these network ranges/)
    await expect(confirm).toBeChecked() // the sample scope was confirmed already
    // changing only another setting keeps the existing confirmation and saves at once
    await page.locator('#active-from').fill('21:00')
    await bar.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await expect(page.getByRole('alert')).toHaveCount(0)
    // adding a range (Enter in the field) asks for the confirmation inline, before Save is pressed
    await page.locator('#range-input').fill('192.168.60.0/24')
    await page.locator('#range-input').press('Enter')
    await expect(page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')).toHaveCount(3)
    await expect(confirm).not.toBeChecked()
    await expect(bar.getByRole('status').first()).toContainText('You added or changed ranges. Tick to confirm before saving.')
    await shot(page, 'inventory', 'scope-confirm-inline')
    await confirm.check()
    await bar.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await expect(page.getByRole('alert')).toHaveCount(0)
  })

  test('regression: a range stored without a prefix ("10.142.0.0") shows an error on its row and never blocks add, edit or remove', async ({ page }) => {
    await page.goto('/devices')
    await patchDb(page, 'inv_settings', { lan_ranges: ['10.142.0.0'], scope_confirmed_at: null, scope_confirmed_by: null }, SETTINGS_FALLBACK)
    await page.goto('/devices/setup')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    await expect(rows).toHaveCount(1)
    await expect(rows.first().getByRole('alert')).toContainText('"10.142.0.0" has no prefix length')
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    await page.locator('#range-input').fill('192.168.19.0/24'); await page.locator('#range-input').press('Enter') // adding still works
    await expect(rows).toHaveCount(2)
    await page.getByRole('button', { name: 'Edit range 10.142.0.0' }).click()
    await expect(page.locator('#range-input')).toHaveValue('10.142.0.0')
    await page.locator('#range-input').fill('10.142.0.0/25'); await page.locator('#range-input').press('Enter')
    await expect(page.getByRole('alert').filter({ hasText: 'prefix' })).toHaveCount(0)
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.getByRole('button', { name: 'Remove range 192.168.19.0/24' }).click() // delete after a save works too
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.reload()
    await expect(rows).toHaveText([/^10\.142\.0\.0\/25/])
  })

  test('regression: a truly invalid stored range shows an error on its own row; others stay editable', async ({ page }) => {
    await page.goto('/devices')
    await patchDb(page, 'inv_settings', { lan_ranges: ['not-a-range', '192.168.20.0/24'], scope_confirmed_at: null, scope_confirmed_by: null }, SETTINGS_FALLBACK)
    await page.goto('/devices/setup')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    await expect(rows).toHaveCount(2)
    await expect(rows.first().getByRole('alert')).toContainText('not a valid range')
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    await expect(page.getByText(/Fix or remove the 1 range marked in red/)).toBeVisible()
    await page.locator('#range-input').fill('192.168.40.0/24'); await page.locator('#range-input').press('Enter') // adding still works
    await expect(rows).toHaveCount(3)
    await page.getByRole('button', { name: 'Edit range not-a-range' }).click()
    await expect(page.locator('#range-input')).toHaveValue('not-a-range')
    await page.locator('#range-input').fill('192.168.50.0/24'); await page.locator('#range-input').press('Enter')
    await page.getByLabel(/I confirm these network ranges/).check()
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeEnabled()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
  })

  // The sample box already listens on a SPAN card (eth1): with SPAN hidden for v1 it still shows that state, read-only.
  test('the sensor on this box: shows the SPAN status it already has and links to Settings → Box network; no multi-site controls', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/devices/setup?tab=sensor')
    await expect(page.getByRole('heading', { name: 'Sensor on this box' })).toBeVisible()
    await expect(page.getByRole('button', { name: /another site/ })).toHaveCount(0)
    await expect(page.getByText(/enrol|enroll/i)).toHaveCount(0)
    await page.getByRole('button', { name: 'Configure sensor vedette-hq' }).click()
    const dlg = page.getByRole('dialog')
    // The card and SPAN are set in Settings → Box network; the dialog shows the status and links there (no switch here).
    await expect(dlg.getByText('Receiving')).toBeVisible()
    await expect(dlg.getByText('eth1')).toBeVisible()
    await expect(dlg.getByRole('switch')).toHaveCount(0)
    await shot(page, 'inventory', 'sensor-config')
    await expect(dlg.getByRole('link', { name: /Settings → Box network$/ })).toHaveAttribute('href', '/settings/network') // either text, SPAN shown or hidden
    await page.keyboard.press('Escape')
    await expect(dlg).toBeHidden()
    const row = page.getByRole('table', { name: 'Sensors on this box' }).getByRole('row').nth(1)
    await expect(row).toContainText('eth1')
    await expect(row).toContainText('SPAN')
    await page.reload()
    await expect(page.getByRole('table', { name: 'Sensors on this box' })).toContainText('eth1')
    expect(errors).toEqual([])
  })

  test('osquery: token shown once; one-line install with a SHA-256 that matches the served script; uninstall; manual steps; revoke', async ({ page }) => {
    await enableModule(page, 'agent-intake')
    // item 26b: /devices leads to the setup page, and the packages are on the page itself (step 1) before any token exists
    await page.goto('/devices')
    await page.getByRole('link', { name: 'Device discovery settings' }).click()
    await expect(page).toHaveURL(/\/devices\/setup$/)
    await page.getByRole('tab', { name: 'Agents', exact: true }).click() // agents have their own tab
    await expect(page).toHaveURL(/\/devices\/setup\?tab=agents$/)
    await expect(page.getByText('Use osquery on your Linux and Windows PCs and servers. Already run Wazuh? Connect its API instead.').first()).toBeVisible()
    const pkgTable = page.getByRole('table', { name: 'osquery packages this box serves' })
    await expect(pkgTable.getByRole('link')).toHaveCount(5)
    const msiName = { name: /^Download osquery-[\d.]+\.msi$/ }
    await expect(pkgTable.getByRole('link', msiName)).toHaveAttribute('href', /^\/api\/v1\/install\/osquery\/osquery-[\d.]+\.msi$/)
    await expect(pkgTable.getByRole('row').filter({ has: page.getByRole('link', msiName) })).toContainText('msiexec /i osquery-')
    await expect(page.getByRole('heading', { name: '2. Then create a token so the agent can report to this box' })).toBeVisible()
    await shot(page, 'inventory', 'agent-downloads')
    await expectAccessible(page, 'setup page with the osquery downloads')
    await page.getByRole('button', { name: 'Create agent token' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toContainText('Linux and Windows, on PCs and servers')
    await dlg.getByLabel('Token name', { exact: true }).fill('osquery warehouse')
    await expect(dlg.getByLabel('Token lifetime', { exact: true })).toHaveValue('7')
    await dlg.getByLabel('Token name', { exact: true }).press('Enter')
    const token = (await dlg.getByLabel('Token', { exact: true }).innerText()).trim()
    expect(token).toMatch(/^vdt_osquery_/)
    // Linux: one line, https box address (no localhost / http), expected checksum equals the SHA-256 of the script the box serves
    const linuxLine = await dlg.getByLabel('Linux shell', { exact: true }).first().innerText()
    expect(linuxLine).toContain(`--token ${token}`)
    expect(linuxLine).toMatch(/https:\/\/192\.168\.10\.250:8443\/api\/v1\/install\/osquery\.sh/)
    expect(linuxLine).not.toMatch(/localhost|http:\/\//)
    const sha = (linuxLine.match(/echo "([0-9a-f]{64})  /) ?? [])[1]
    expect(sha).toBeTruthy()
    const served = await page.evaluate(async () => { const t = await (await fetch('/api/v1/install/osquery.sh')).text(); const h = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)); return { hash: Array.from(new Uint8Array(h), (b) => b.toString(16).padStart(2, '0')).join(''), text: t } })
    expect(served.hash).toBe(sha)
    await expect(dlg.getByText(sha!, { exact: true }).first()).toBeVisible()
    expect(served.text).toContain('--config_plugin=tls')
    expect(served.text).toContain('systemctl enable osqueryd')
    await expect(dlg.getByRole('group', { name: 'Operating system' })).toBeVisible()
    await dlg.getByText('What this script does').click()
    await expect(dlg.getByText('Vedette osquery installer for Linux').first()).toBeVisible()
    await shot(page, 'inventory', 'agent-created')
    await expectAccessible(page, 'agent dialog')
    // uninstall one-liner, Windows tab, manual steps
    await expect(dlg.getByText('Remove osquery from the server again')).toBeVisible()
    await dlg.getByRole('button', { name: 'Windows', exact: true }).click()
    const winLine = await dlg.getByLabel('PowerShell (Administrator)', { exact: true }).first().innerText()
    expect(winLine).toContain('Get-FileHash')
    expect(winLine).toContain(`-Token '${token}'`)
    expect(winLine).not.toContain('SkipCertificateCheck') // Windows PowerShell 5.1 has no such option
    await dlg.getByText('Advanced: manual setup', { exact: true }).click()
    await expect(dlg.getByText('manage-osqueryd.ps1', { exact: false }).first()).toBeVisible()
    await expect(dlg.getByText(/Trivy|macOS|Homebrew/i)).toHaveCount(0)
    await dlg.getByRole('button', { name: 'I copied the token' }).click()
    // reopened setup never shows the secret
    await page.getByRole('button', { name: 'Show setup for osquery warehouse' }).click()
    await expect(page.getByRole('dialog').getByText(token)).toHaveCount(0)
    await expect(page.getByRole('dialog').getByText(/<TOKEN>/).first()).toBeVisible()
    await page.keyboard.press('Escape')
    // preview-only sample data: last data received, machines reporting and agent-sourced software appear
    await page.getByRole('button', { name: 'Send sample data for osquery warehouse' }).click()
    await expect(page.getByText(/Sample data received: \d+ devices updated/).first()).toBeVisible()
    const row = page.getByRole('table', { name: 'Enrollment tokens' }).getByRole('row').filter({ hasText: 'osquery warehouse' })
    await expect(row).not.toContainText('No data received')
    await page.getByRole('button', { name: 'Revoke token osquery warehouse' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Revoke', exact: true }).click()
    await expect(page.getByText('Revoked token osquery warehouse.').first()).toBeVisible()
  })

  test('Wazuh: read-only user steps, test connection errors, connect, sample sync, disconnect; nothing installed on agents', async ({ page }) => {
    await enableModule(page, 'agent-intake')
    await page.goto('/devices/setup?tab=agents')
    await expect(page.getByRole('button', { name: 'About Wazuh', exact: true })).toHaveAccessibleDescription(/Nothing is installed on your agent machines/) // #824: behind the section's ⓘ
    await page.getByRole('button', { name: 'Connect Wazuh' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('agent:read', { exact: false }).locator('visible=true').first()).toBeVisible()
    await expect(dlg.getByText('syscollector:read', { exact: false }).locator('visible=true').first()).toBeVisible() // #824: the sentence naming the rights is behind the steps' ⓘ; the policy command shows them
    await shot(page, 'inventory', 'wazuh-connect')
    await dlg.getByLabel('Wazuh server API address', { exact: true }).fill('http://wazuh-manager:55000')
    await dlg.getByLabel('API password', { exact: true }).fill('s3cret-pass')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('starting with https://')
    await dlg.getByLabel('Wazuh server API address', { exact: true }).fill('https://wazuh-manager:55000')
    await dlg.getByLabel('API password', { exact: true }).fill('wrong')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('refused the user name or password')
    await dlg.getByLabel('API password', { exact: true }).fill('s3cret-pass')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('status').filter({ hasText: 'Connected to Wazuh' })).toBeVisible()
    await dlg.getByRole('button', { name: 'Save connection' }).click()
    await expect(dlg).toBeHidden()
    await expect(page.getByText('••••pass')).toBeVisible()
    await expect(page.getByText('s3cret-pass')).toHaveCount(0)
    await page.getByRole('button', { name: 'Send sample data', exact: true }).click()
    await expect(page.getByText(/agents, \d+ packages/)).toBeVisible()
    await page.getByRole('button', { name: 'Disconnect' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Disconnect' }).click()
    await expect(page.getByRole('button', { name: 'Connect Wazuh' })).toBeVisible()
  })
})

test.describe('Clean install: first-time user', () => {
  test('first-run wizard: a bare address is refused (no guessing), then a /24 range works; list holds only the box itself; subnets can be added, edited, deleted', async ({ page }) => {
    const errors = collectErrors(page)
    await cleanInstall(page, '10.142.0.0')
    await expect(page.getByText(/no prefix length/i).first()).toBeVisible() // the wizard keeps the owner on this step with a message
    await page.getByRole('textbox', { name: 'Range 1' }).fill('10.142.0.0/24')
    await page.getByRole('button', { name: 'Continue' }).click()
    await finishWizard(page)
    await page.goto('/devices')
    await expect(h1(page)).toHaveText('Only the Vedette box so far') // only the box itself: it is always the first device (INV-3)
    await expect(page.getByRole('button', { name: 'Add a device' }).last()).toBeEnabled()
    // header + the box on a desktop table; the box alone in the phone list (DataTable mobileRow below 768 px)
    const table = page.getByRole('table', { name: 'Device list' })
    if (await table.count()) await expect(table.getByRole('row')).toHaveCount(2)
    else await expect(page.getByRole('list', { name: 'Device list' }).getByRole('listitem')).toHaveCount(1)
    await shot(page, 'inventory', 'clean-empty')
    await expectAccessible(page, 'clean list')
    await expectEnglishOnly(page, 'clean list')
    await page.goto('/devices/setup')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    await expect(rows).toHaveText([/^10\.142\.0\.0\/24/])
    await page.getByRole('tab', { name: 'Sensor', exact: true }).click() // The sensor has its own tab
    await expect(page.getByRole('table', { name: 'Sensors on this box' }).getByRole('row')).toHaveCount(2)
    await page.getByRole('tab', { name: 'Scope', exact: true }).click()
    await expect(page.locator('main')).not.toContainText('SRV-AD')
    await shot(page, 'inventory', 'clean-setup')
    await expectEnglishOnly(page, 'clean setup')
    await page.locator('#range-input').fill('10.5.0.0/16'); await page.locator('#range-input').press('Enter')
    await page.getByRole('button', { name: 'Remove range 10.142.0.0/24' }).click()
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.reload()
    await expect(rows).toHaveText([/^10\.5\.0\.0\/16/])
    await page.goto('/devices')
    await page.getByRole('button', { name: 'Add a device' }).last().click()
    await page.getByRole('dialog').getByLabel('IP address', { exact: true }).fill('10.5.0.20')
    await page.getByRole('dialog').getByRole('combobox').fill('forti')
    await page.getByRole('dialog').getByRole('option').first().click()
    await page.getByRole('dialog').getByRole('button', { name: 'Add', exact: true }).click()
    await expect(countLine(page)).toContainText('2 devices') // the box and the one just added
    expect(errors).toEqual([])
  })

  test('clean install with a normal CIDR range works the same', async ({ page }) => {
    await cleanInstall(page, '10.142.0.0/24')
    await finishWizard(page)
    await page.goto('/devices/setup')
    await expect(page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')).toHaveText([/^10\.142\.0\.0\/24/])
  })
})
