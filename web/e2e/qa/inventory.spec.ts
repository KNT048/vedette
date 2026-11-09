// QA inventory (S-INV-1..4) như người dùng thật, giao diện chỉ tiếng Anh (D-28).
// Chạy: pnpm exec playwright test -c playwright.qa.config.ts e2e/qa/inventory.spec.ts --workers=1
import { expect, test, type Page } from '@playwright/test'
import { collectErrors, expectAccessible, shot } from '../helpers'
import { DIACRITICS, sampleStart } from './clean'

const DB = 'vedette-mock-db-v4'
type UserId = 'u-admin' | 'u-op' | 'u-view'
/**
 * Ghi kho mock TRƯỚC khi trang tải (init script chạy một lần cho mỗi lần gọi), vì trang đang mở có thể ghi đè localStorage khi tải lại.
 * `patch` trộn vào bảng hiện có (hoặc `fallback` nếu bảng chưa được tạo).
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
/** Đổi người dùng đăng nhập. */
const loginAs = (page: Page, userId: UserId) => patchDb(page, 'core_session', { userId })
const SETTINGS_FALLBACK = { active: { enabled: false, days: [1, 2, 3, 4, 5, 6, 7], from: '23:00', to: '05:00', rate: 50, exclusions: [] }, fragile_kinds: ['printer'] }
async function setTheme(page: Page, theme: 'light' | 'dark') {
  await page.evaluate((t) => localStorage.setItem('vedette-theme', t), theme)
  await page.reload()
}
const noHScroll = async (page: Page) => expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'page must not scroll sideways').toBeLessThanOrEqual(1)
/** Mọi chữ hiển thị là tiếng Anh: không dấu tiếng Việt trong phần nội dung (D-28). */
const expectEnglishOnly = async (page: Page, label: string) => expect(await page.locator('body').innerText(), `${label}: Vietnamese text on the page`).not.toMatch(DIACRITICS)
const h1 = (page: Page) => page.getByRole('heading', { level: 1 })
const countOf = async (page: Page) => { await expect(h1(page)).toHaveText(/^\d+ devices?,/); return Number((await h1(page).innerText()).match(/^(\d+)/)![1]) }

/** Bật module trong kho mock (agent-intake mặc định tắt ở dữ liệu mẫu), ghi trước khi trang tải. */
async function enableModule(page: Page, id: string) {
  await page.goto('/devices')
  await expect(h1(page)).toHaveText(/^\d+ devices?,/) // the module table exists in the mock db once the app has loaded
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

/** Cài sạch qua trình hướng dẫn với dải mạng người dùng gõ (không dữ liệu mẫu), rồi vào hộp. */
async function cleanInstall(page: Page, lan: string) {
  await page.goto('/')
  await page.evaluate(() => localStorage.clear())
  await page.goto('/setup')
  await page.getByLabel('Setup code').fill('setup-code-demo') // D-75: the code the mock accepts
  await page.getByLabel('Organization name').fill('Test Company')
  await page.getByLabel('Administrator name').fill('Alex Admin')
  await page.getByLabel('Sign-in email').fill('admin@testco.example')
  await page.getByLabel('Password', { exact: true }).fill('a-very-long-password-123')
  await page.getByLabel('Repeat password').fill('a-very-long-password-123')
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('textbox', { name: 'Range 1' }).fill(lan)
  await page.getByRole('button', { name: 'Continue' }).click()
}
async function finishWizard(page: Page) {
  await page.getByRole('radio', { name: /Small business/ }).or(page.getByRole('radio').first()).first().click()
  await page.getByRole('button', { name: 'Continue' }).click()
  await page.getByRole('button', { name: 'Skip and finish' }).click()
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

test.describe('P2 IT person, day to day: list, add by hand, CSV, detail', () => {
  test.beforeEach(async ({ page }) => { await sampleStart(page); await loginAs(page, 'u-op') })

  test('add by hand in 3 clicks; Escape in the picker closes only the list; errors keep input; Enter submits', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/devices')
    const before = await countOf(page)
    await page.getByRole('button', { name: 'Add a device' }).click()
    const dialog = page.getByRole('dialog')
    const picker = dialog.getByRole('combobox')
    await picker.focus()
    await expect(dialog.getByRole('listbox')).toBeVisible()
    await shot(page, 'inventory', 'add-dialog-picker')
    await page.keyboard.press('Escape')
    await expect(dialog.getByRole('listbox')).toBeHidden()
    await expect(dialog).toBeVisible() // first Escape only closes the suggestion list
    await picker.fill('forti')
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Name (optional)').fill('Test firewall')
    await dialog.getByLabel('IP address (optional)').fill('192.168.10.1')
    await dialog.getByLabel('IP address (optional)').press('Enter')
    await expect(dialog.getByRole('alert')).toContainText('192.168.10.1')
    await expect(dialog.getByLabel('Name (optional)')).toHaveValue('Test firewall')
    await shot(page, 'inventory', 'add-dialog-error')
    await dialog.getByLabel('IP address (optional)').fill('192.168.10.250')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(h1(page)).toContainText(String(before + 1))
    // opening the dialog shows suggestions at once; Escape twice closes everything
    await page.getByRole('button', { name: 'Add a device' }).click()
    await expect(page.getByRole('dialog').getByRole('listbox')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog').getByRole('listbox')).toBeHidden()
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toBeHidden()
    // exactly 3 clicks: open, pick the first suggestion, Add
    await page.getByRole('button', { name: 'Add a device' }).click()
    await page.getByRole('dialog').getByRole('combobox').focus()
    await page.getByRole('dialog').getByRole('option').first().click()
    await page.getByRole('dialog').getByRole('button', { name: 'Add', exact: true }).click()
    await expect(page.getByRole('dialog')).toBeHidden()
    await expect(h1(page)).toContainText(String(before + 2))
    await page.reload()
    await expect(h1(page)).toContainText(String(before + 2))
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
    await expect(dialog.getByText(/Showing 30 of \d+/)).toBeVisible()
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
    await dialog.getByLabel('Maker').fill('Fortinet')
    await dialog.getByLabel('Product').fill('FortiGate-Lab')
    await shot(page, 'inventory', 'add-custom')
    await dialog.getByLabel('Name (optional)').fill('Lab firewall')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(h1(page)).toContainText(String(before + 1))
    await page.getByRole('link', { name: 'Lab firewall' }).first().click()
    await expect(page.getByText('Fortinet FortiGate-Lab').first()).toBeVisible()
  })

  test('CSV with BOM, semicolons, empty lines; export then re-import creates no duplicates', async ({ page }) => {
    await page.goto('/devices')
    const before = await countOf(page)
    await page.getByRole('button', { name: 'Import CSV' }).click()
    const csv = '﻿Device name;IP address;Product;Version;Type\r\n\r\nBranch firewall;192.168.77.1;FortiGate;7.2.5;Firewall\r\n\r\nAccounting printer;192.168.77.20;;;Printer\r\n;;;;\r\nBad one;999.1.1.1;;;\r\nWarehouse server;;;;Server\r\n'
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'devices.csv', mimeType: 'text/csv', buffer: Buffer.from(csv, 'utf8') })
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('Added 3 devices, skipped 1 rows.')).toBeVisible()
    await expect(dlg.getByText('Line 7:')).toBeVisible()
    await shot(page, 'inventory', 'import-result')
    await dlg.getByRole('button', { name: 'Close', exact: true }).first().click()
    await expect(h1(page)).toContainText(String(before + 3))
    await expect(page.getByRole('link', { name: 'Branch firewall' }).first()).toBeVisible()
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()])
    const text = (await import('node:fs')).readFileSync((await download.path())!, 'utf8')
    expect(text.charCodeAt(0)).toBe(0xfeff)
    expect(text).toContain('Branch firewall')
    expect(text).toContain('Warehouse server')
    await page.getByRole('button', { name: 'Import CSV' }).click()
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'export.csv', mimeType: 'text/csv', buffer: Buffer.from(text, 'utf8') })
    await expect(page.getByRole('dialog').getByText(/Added 0 devices/)).toBeVisible()
    await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).first().click()
    await expect(h1(page)).toContainText(String(before + 3))
    await page.getByRole('button', { name: 'Import CSV' }).click()
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'empty.csv', mimeType: 'text/csv', buffer: Buffer.from('', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('The file is empty')
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'wrong.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\n1,2\n', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('column headers')
  })

  test('detail: very long name and 20+ observations do not break the layout', async ({ page }) => {
    const errors = collectErrors(page)
    const long = 'Z'.repeat(64)
    await page.goto('/devices')
    await expect(h1(page)).toHaveText(/^\d+ devices?,/) // mock API ready
    const r = await page.evaluate(async (n) => {
      const res = await fetch('/api/v1/inventory/devices', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ catalog_id: 'synology-nas-dsm', name: n, ip: '192.168.55.5' }) })
      return res.json() as Promise<{ id: string }>
    }, long)
    for (let i = 0; i < 24; i++) await page.evaluate(async ([id, k]) => { await fetch(`/api/v1/inventory/devices/${id}`, { method: 'PATCH', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ kind: k }) }) }, [r.id, i % 2 ? 'nas' : 'router'] as const)
    await page.goto(`/devices/${r.id}`)
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
    await page.goto('/devices/a-nas02')
    await page.getByRole('button', { name: 'Add software' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('combobox').fill('wordpress')
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Version (optional)').fill('6.5.2')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByText('WordPress').first()).toBeVisible()
    await page.getByRole('button', { name: /^Remove WordPress from the device$/ }).first().click()
    await expect(page.getByRole('button', { name: /^Remove WordPress from the device$/ })).toHaveCount(0)
  })

  test('not approved: approve, flag as unknown; removing a device with findings says so; Escape and Cancel keep it', async ({ page }) => {
    await page.goto('/devices')
    const pending = page.getByRole('list', { name: /new devices not approved/ })
    await expect(pending.getByRole('listitem')).toHaveCount(2)
    await pending.getByRole('button', { name: 'Mark unknown' }).first().click()
    await expect(pending.getByText('Marked unknown').first()).toBeVisible()
    await pending.getByRole('button', { name: 'Approve' }).first().click()
    await expect(h1(page)).toContainText('1 not yet approved')
    await page.goto('/devices/a-nas02')
    await page.getByRole('button', { name: 'Remove from list' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toContainText(/has \d+ findings?\./)
    await expect(dlg).toContainText('also removes')
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
    for (const n of ['Add a device', 'Import CSV']) {
      const b = page.getByRole('button', { name: n })
      await expect(b).toBeDisabled()
      await expect(b).toHaveAttribute('title', /Operator/)
    }
    await expect(page.getByRole('button', { name: 'Export CSV' })).toBeEnabled()
    await expect(page.getByRole('link', { name: 'Scope and sensors' })).toHaveCount(0)
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
    await input.fill('192.168.18.0'); await input.press('Enter')
    await expect(err).toContainText('"192.168.18.0" has no prefix length. Add it so Vedette scans the right size of network, for example 192.168.18.0/24 or 192.168.18.0/25.')
    await expect(rows).toHaveCount(2)
    await input.fill('192.168.18.0/25'); await input.press('Enter')
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
    await page.getByRole('button', { name: 'Remove range 192.168.18.0/25' }).click()
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

  test('regression: a range stored without a prefix ("192.168.18.0") shows an error on its row and never blocks add, edit or remove', async ({ page }) => {
    await page.goto('/devices')
    await patchDb(page, 'inv_settings', { lan_ranges: ['192.168.18.0'], scope_confirmed_at: null, scope_confirmed_by: null }, SETTINGS_FALLBACK)
    await page.goto('/devices/setup')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    await expect(rows).toHaveCount(1)
    await expect(rows.first().getByRole('alert')).toContainText('"192.168.18.0" has no prefix length')
    await expect(page.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    await page.locator('#range-input').fill('192.168.19.0/24'); await page.locator('#range-input').press('Enter') // adding still works
    await expect(rows).toHaveCount(2)
    await page.getByRole('button', { name: 'Edit range 192.168.18.0' }).click()
    await expect(page.locator('#range-input')).toHaveValue('192.168.18.0')
    await page.locator('#range-input').fill('192.168.18.0/25'); await page.locator('#range-input').press('Enter')
    await expect(page.getByRole('alert').filter({ hasText: 'prefix' })).toHaveCount(0)
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.getByRole('button', { name: 'Remove range 192.168.19.0/24' }).click() // delete after a save works too
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.reload()
    await expect(rows).toHaveText([/^192\.168\.18\.0\/25/])
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

  test('the sensor on this box: choose interface and SPAN; no multi-site controls', async ({ page }) => {
    const errors = collectErrors(page)
    await page.goto('/devices/setup')
    await expect(page.getByRole('heading', { name: 'Sensor on this box' })).toBeVisible()
    await expect(page.getByRole('button', { name: /another site/ })).toHaveCount(0)
    await expect(page.getByText(/enrol|enroll/i)).toHaveCount(0)
    await page.getByRole('button', { name: 'Configure sensor vedette-hq' }).click()
    const dlg = page.getByRole('dialog')
    await dlg.getByLabel('Network interface').selectOption('eth1')
    await dlg.getByLabel(/receives a copy of traffic/).check()
    await shot(page, 'inventory', 'sensor-config')
    await dlg.getByRole('button', { name: 'Save', exact: true }).click()
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
    await page.goto('/devices/setup')
    await expect(page.getByText('Use osquery on your Linux and Windows servers. Already run Wazuh? Connect its API instead.').first()).toBeVisible()
    await page.getByRole('button', { name: 'Create agent token' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toContainText('Linux and Windows Server')
    await dlg.getByLabel('Token name').fill('osquery warehouse')
    await expect(dlg.getByLabel('Token lifetime')).toHaveValue('7')
    await dlg.getByLabel('Token name').press('Enter')
    const token = (await dlg.getByLabel('Token', { exact: true }).innerText()).trim()
    expect(token).toMatch(/^vdt_osquery_/)
    // Linux: one line, https box address (no localhost / http), expected checksum equals the SHA-256 of the script the box serves
    const linuxLine = await dlg.getByLabel('Linux shell').first().innerText()
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
    await dlg.getByRole('button', { name: 'Windows Server' }).click()
    const winLine = await dlg.getByLabel('PowerShell (Administrator)').first().innerText()
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
    await page.goto('/devices/setup')
    await expect(page.getByText(/Nothing is installed on your agent machines/).first()).toBeVisible()
    await page.getByRole('button', { name: 'Connect Wazuh' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('agent:read', { exact: false }).first()).toBeVisible()
    await expect(dlg.getByText('syscollector:read', { exact: false }).first()).toBeVisible()
    await shot(page, 'inventory', 'wazuh-connect')
    await dlg.getByLabel('Wazuh server API address').fill('http://wazuh-manager:55000')
    await dlg.getByLabel('API password').fill('s3cret-pass')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('starting with https://')
    await dlg.getByLabel('Wazuh server API address').fill('https://wazuh-manager:55000')
    await dlg.getByLabel('API password').fill('wrong')
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toContainText('refused the user name or password')
    await dlg.getByLabel('API password').fill('s3cret-pass')
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
  test('first-run wizard: a bare address is refused (no guessing), then a /24 range works; list starts empty with a clear first step; subnets can be added, edited, deleted', async ({ page }) => {
    const errors = collectErrors(page)
    await cleanInstall(page, '192.168.18.0')
    await expect(page.getByText(/no prefix length/i).first()).toBeVisible() // the wizard keeps the owner on this step with a message
    await page.getByRole('textbox', { name: 'Range 1' }).fill('192.168.18.0/24')
    await page.getByRole('button', { name: 'Continue' }).click()
    await finishWizard(page)
    await page.goto('/devices')
    await expect(h1(page)).toHaveText('No devices yet')
    await expect(page.getByText(/Plug the box into your LAN/)).toBeVisible()
    await expect(page.getByRole('button', { name: 'Add a device' }).last()).toBeEnabled()
    await expect(page.getByRole('table')).toHaveCount(0)
    await shot(page, 'inventory', 'clean-empty')
    await expectAccessible(page, 'clean list')
    await expectEnglishOnly(page, 'clean list')
    await page.goto('/devices/setup')
    const rows = page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
    await expect(rows).toHaveText([/^192\.168\.18\.0\/24/])
    await expect(page.getByRole('table', { name: 'Sensors on this box' }).getByRole('row')).toHaveCount(2)
    await expect(page.locator('main')).not.toContainText('SRV-AD')
    await shot(page, 'inventory', 'clean-setup')
    await expectEnglishOnly(page, 'clean setup')
    await page.locator('#range-input').fill('10.5.0.0/16'); await page.locator('#range-input').press('Enter')
    await page.getByRole('button', { name: 'Remove range 192.168.18.0/24' }).click()
    await page.getByLabel(/I confirm these network ranges/).check()
    await page.getByRole('button', { name: 'Save changes' }).click()
    await expect(page.getByText('You have unsaved changes.')).toBeHidden()
    await page.reload()
    await expect(rows).toHaveText([/^10\.5\.0\.0\/16/])
    await page.goto('/devices')
    await page.getByRole('button', { name: 'Add a device' }).last().click()
    await page.getByRole('dialog').getByRole('combobox').focus()
    await page.getByRole('dialog').getByRole('option').first().click()
    await page.getByRole('dialog').getByRole('button', { name: 'Add', exact: true }).click()
    await expect(h1(page)).toContainText('1 device')
    expect(errors).toEqual([])
  })

  test('clean install with a normal CIDR range works the same', async ({ page }) => {
    await cleanInstall(page, '192.168.18.0/24')
    await finishWizard(page)
    await page.goto('/devices/setup')
    await expect(page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')).toHaveText([/^192\.168\.18\.0\/24/])
  })
})
