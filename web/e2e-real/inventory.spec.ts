// Devices (Inventory) on the real backend: S-INV-2 (add by hand from the catalog or by typing maker and product), S-INV-5 (the box is device 1 and
// cannot be removed), the CSV round trip (INV-13), software add and remove (INV-10 match), approve / mark unknown (S-INV-3), removing a device
// with its findings (INV-11), and the viewer's locked buttons. The form steps are those of e2e/qa/inventory.spec.ts; what only a real box shows is new:
// the row is in the database after a reload, the audit log has the line, the duplicate IP is a real 409, the CSV that comes back is the real export.
// Every device gets its own name and its own address (D-172), and counts are read as "contains my row", never as a total: other specs add devices too.
// Known gap (S-INV-5): the box has no package list yet (cmd/vedette/inventory.go, ponytail), so no spec asserts one.
import { readFileSync } from 'node:fs'
import { expect, test, type Page } from '@playwright/test'
import { ACCOUNTS, api, authFile, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

interface Dev { id: string; hostname: string | null; ip: string; is_box: boolean; approved: boolean; origin: string; kind: string; software?: { id: string; product?: string; name?: string }[] }

// One address per test run of this file: 10.<run>.<n>.<m>, so no other test of the run (or the box) shares it.
const run = (process.pid + Number(process.env.TEST_PARALLEL_INDEX ?? 0) * 37) % 200 + 20
let ipCounter = 0
const ip = () => `10.${run}.${Math.floor(ipCounter / 250)}.${(ipCounter++ % 250) + 1}`

const devices = async (page: Page) => (await api<{ items: Dev[]; counts: { all: number } }>(page.request, 'GET', '/inventory/devices')).body
const byName = async (page: Page, name: string) => (await devices(page)).items.find((d) => d.hostname === name)
const open = async (page: Page, path = '/devices') => { await page.goto(path); await expect(h1(page)).toBeVisible() }
const addBtn = (page: Page) => page.getByRole('button', { name: 'Add a device' }).first()

test.describe('operator, day to day', () => {
  test.use({ storageState: authFile('operator'), actionTimeout: 10_000 })

  test('the box is the first device and cannot be removed; the list says how many devices there are', async ({ page }) => {
    const errors = collectErrors(page)
    const list = await devices(page)
    const boxDev = list.items.find((d) => d.is_box)
    expect(boxDev, 'the box device').toBeTruthy()
    const gone = await api<{ code?: string }>(page.request, 'DELETE', `/inventory/devices/${boxDev!.id}`)
    expect(gone.status, 'DELETE the box device').toBe(409)
    expect(JSON.stringify(gone.body)).toContain('box_device')
    await open(page)
    await expect(h1(page)).toHaveText(/^\d+ devices?,/)
    await shot(page, 'real-inventory', 'list')
    await page.goto(`/devices/${boxDev!.id}`)
    await expect(page.getByRole('button', { name: 'Remove from list' })).toBeDisabled()
    await expectAccessible(page, 'the box device page')
    await noVietnamese(page, 'devices')
    noErrors(errors, /status of (4|5)\d\d/)
  })

  test('add by hand from the catalog: Escape closes only the list, an error keeps the input, Enter submits, the row is saved', async ({ page }) => {
    const errors = collectErrors(page)
    const name = uniq('fw')
    const addr = ip()
    await open(page)
    await addBtn(page).click()
    const dialog = page.getByRole('dialog')
    const picker = dialog.getByRole('combobox')
    await picker.focus()
    await expect(dialog.getByRole('listbox'), 'no list until the person types').toHaveCount(0)
    await picker.fill('forti')
    await expect(dialog.getByRole('listbox')).toBeVisible()
    await page.keyboard.press('Escape')
    await expect(dialog.getByRole('listbox')).toBeHidden()
    await expect(dialog, 'the first Escape closes only the suggestion list').toBeVisible()
    await picker.fill('fortig') // another text than before: the same text would not open the closed list again
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Name (optional)').fill(name)
    await dialog.getByLabel('IP address (optional)').fill('not-an-ip')
    await dialog.getByLabel('IP address (optional)').press('Enter')
    await expect(dialog.getByRole('alert')).toBeVisible()
    await expect(dialog.getByLabel('Name (optional)')).toHaveValue(name)
    await shot(page, 'real-inventory', 'add-error')
    await dialog.getByLabel('IP address (optional)').fill(addr)
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByRole('link', { name }).first()).toBeVisible()
    const row = await byName(page, name)
    expect(row?.ip).toBe(addr)
    expect(row?.origin).toBe('manual')
    await page.reload()
    await expect(page.getByRole('link', { name }).first()).toBeVisible()
    // the same address twice is refused by the backend, with the existing device named, and nothing is added
    await addBtn(page).click()
    await dialog.getByRole('combobox').fill('forti')
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Name (optional)').fill(uniq('dup'))
    await dialog.getByLabel('IP address (optional)').fill(addr)
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog.getByRole('alert')).toContainText(addr)
    await dialog.getByRole('button', { name: /Cancel|Close/ }).first().click()
    expect((await devices(page)).items.filter((d) => d.ip === addr).length, 'devices with that address').toBe(1)
    noErrors(errors, /status of (4|5)\d\d/)
  })

  test('picker search finds products by model, alias and maker; many results are capped; no match says so', async ({ page }) => {
    await open(page)
    await addBtn(page).click()
    const dialog = page.getByRole('dialog')
    const picker = dialog.getByRole('combobox')
    await picker.fill('fortigate 60f')
    await expect(dialog.getByRole('option').first()).toContainText('FortiGate')
    for (const [q, expected] of [['qnap', 'QNAP'], ['synology', 'Synology'], ['hikvision', 'Hikvision'], ['windows server 2019', 'Windows Server 2019']] as const) {
      await picker.fill(q)
      await expect(dialog.getByRole('option').first(), q).toContainText(expected)
    }
    // a word with more than 30 matches in the real catalog (curated products + the KEV pairs): the list shows 30 and says how many more there are
    let many = ''
    for (const q of ['microsoft', 'windows', 'firewall', 'router', 'camera', 'nas', 'e', 'a', 'o', 'i']) {
      const r = await api<{ total: number }>(page.request, 'GET', `/inventory/catalog?q=${q}`)
      if (r.body.total > 30) { many = q; break }
    }
    expect(many, 'a search word with more than 30 matches in the catalog').not.toBe('')
    await picker.fill(many)
    await expect(dialog.getByRole('option').first()).toBeVisible()
    expect(await dialog.getByRole('option').count()).toBeLessThanOrEqual(30)
    await expect(dialog.getByText(/\d+ more match\. Keep typing to narrow the list\./)).toBeVisible()
    await shot(page, 'real-inventory', 'picker-many')
    await expectAccessible(page, 'picker open')
    await picker.fill('zzzzqqq')
    await expect(dialog.getByText(/No matching product/)).toBeVisible()
  })

  test('a product that is not listed: maker and product typed by hand', async ({ page }) => {
    const name = uniq('lab')
    await open(page)
    await addBtn(page).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('button', { name: /Can't find it/ }).click()
    await expect(dialog.getByRole('button', { name: 'Add', exact: true })).toBeDisabled()
    await dialog.getByLabel('Maker').fill('Fortinet')
    await dialog.getByLabel('Product').fill('FortiGate-Lab')
    await dialog.getByLabel('Name (optional)').fill(name)
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await page.getByRole('link', { name }).first().click()
    await expect(page.getByText('Fortinet FortiGate-Lab').first()).toBeVisible()
  })

  test('CSV with BOM, semicolons, empty lines and a bad address: good rows are added, the bad one is named by line; export then import adds nothing', async ({ page }) => {
    const tag = uniq('csv')
    const [a, b, c] = [`${tag}-fw`, `${tag}-prn`, `${tag}-srv`]
    const [ipA, ipB] = [ip(), ip()]
    await open(page)
    await page.getByRole('button', { name: 'Import CSV' }).first().click()
    const csv = `﻿Device name;IP address;Product;Version;Type\r\n\r\n${a};${ipA};FortiGate;7.2.5;Firewall\r\n\r\n${b};${ipB};;;Printer\r\n;;;;\r\nBad one;999.1.1.1;;;\r\n${c};;;;Server\r\n`
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'devices.csv', mimeType: 'text/csv', buffer: Buffer.from(csv, 'utf8') })
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('Added 3 devices, skipped 1 rows.')).toBeVisible()
    await expect(dlg.getByText('Line 7:')).toBeVisible()
    await shot(page, 'real-inventory', 'import-result')
    await dlg.getByRole('button', { name: 'Close', exact: true }).first().click()
    for (const n of [a, b, c]) await expect(page.getByRole('link', { name: n }).first()).toBeVisible()
    const [download] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Export CSV' }).click()])
    const text = readFileSync((await download.path())!, 'utf8')
    expect(text.charCodeAt(0), 'the export starts with a byte order mark').toBe(0xfeff)
    for (const n of [a, b, c]) expect(text, `${n} in the export`).toContain(n)
    expect(text, 'the bad row is not in the export').not.toContain('999.1.1.1')
    // the export of this test's own rows goes back in: other specs add and remove devices at the same time, so only these three lines are re-imported
    const lines = text.replace(/^\uFEFF/, '').split(/\r?\n/)
    const own = [lines[0]!, ...lines.slice(1).filter((l) => [a, b, c].some((n) => l.includes(n)))].join('\r\n')
    await page.getByRole('button', { name: 'Import CSV' }).first().click()
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'export.csv', mimeType: 'text/csv', buffer: Buffer.from(own, 'utf8') })
    await expect(page.getByRole('dialog').getByText(/Added 0 devices/)).toBeVisible()
    await page.getByRole('dialog').getByRole('button', { name: 'Close', exact: true }).first().click()
    const all = (await devices(page)).items
    for (const n of [a, b, c]) expect(all.filter((d) => d.hostname === n).length, `${n} after the round trip`).toBe(1)
    // an empty file and a file with the wrong columns are refused with the reason
    await page.getByRole('button', { name: 'Import CSV' }).first().click()
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'empty.csv', mimeType: 'text/csv', buffer: Buffer.from('', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('The file is empty')
    await page.getByLabel('Choose a CSV file').setInputFiles({ name: 'wrong.csv', mimeType: 'text/csv', buffer: Buffer.from('a,b\n1,2\n', 'utf8') })
    await expect(page.getByRole('dialog').getByRole('alert')).toContainText('column headers')
  })

  test('a device name that starts with a formula character is exported so a spreadsheet does not run it (CSV injection)', async ({ page }) => {
    const tag = uniq('inj')
    const names = [`=SUM(1)${tag}`, `+1${tag}`, `-2${tag}`, `@x${tag}`]
    const made: string[] = []
    for (const n of names) {
      const r = await api<Dev>(page.request, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name: n, ip: ip() })
      if (r.status === 201) made.push(n)
      else expect(r.status, `a name that starts with ${n[0]} is either stored or refused with 400`).toBe(400)
    }
    const csv = await page.request.get('/api/v1/inventory/export.csv')
    expect(csv.status()).toBe(200)
    const lines = (await csv.text()).split(/\r?\n/).filter((l) => l.includes(tag))
    expect(lines.length, 'exported rows of the stored names').toBe(made.length)
    for (const l of lines) {
      // the cell holding the name must not start with = + - @ unprefixed (a leading apostrophe or tab is the usual neutraliser)
      const cell = l.split(/[;,]/).find((c) => c.includes(tag))!.replace(/^"/, '')
      expect(cell, `the name cell in: ${l}`).not.toMatch(/^[=+\-@]/)
    }
  })

  test('detail: a very long name and many observations do not break the layout', async ({ page }) => {
    const errors = collectErrors(page)
    const long = `${uniq('Z')}${'Z'.repeat(40)}`.slice(0, 64)
    const made = await api<Dev>(page.request, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name: long, ip: ip() })
    expect(made.status, JSON.stringify(made.body)).toBe(201)
    for (let i = 0; i < 24; i++) expect((await api(page.request, 'PATCH', `/inventory/devices/${made.body.id}`, { kind: i % 2 ? 'nas' : 'router' })).status).toBe(200)
    await page.goto(`/devices/${made.body.id}`)
    await expect(h1(page)).toContainText(long)
    const shown = (await page.getByRole('table', { name: 'Observations for this device' }).getByRole('row').count()) + (await page.getByRole('list', { name: 'Observations for this device' }).getByRole('listitem').count())
    expect(shown, 'observation rows (header included) on the page').toBeGreaterThan(2) // the 24 changes are manual observations of one field: the page lists what the backend returns, at most 32 (INV-16)
    expect(await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth), 'sideways scroll').toBeLessThanOrEqual(1)
    await shot(page, 'real-inventory', 'detail-long')
    await expectAccessible(page, 'detail long')
    noErrors(errors, /status of (4|5)\d\d/)
  })

  test('software: add one with a version, it shows on the device and the backend lists it; remove it again', async ({ page }) => {
    const name = uniq('nas')
    const made = await api<Dev>(page.request, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name, ip: ip() })
    expect(made.status).toBe(201)
    await page.goto(`/devices/${made.body.id}`)
    await page.getByRole('button', { name: 'Add software' }).click()
    const dialog = page.getByRole('dialog')
    await dialog.getByRole('combobox').fill('wordpress')
    await dialog.getByRole('option').first().click()
    await dialog.getByLabel('Version (optional)').fill('6.5.2')
    await dialog.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(dialog).toBeHidden()
    await expect(page.getByText('WordPress').first()).toBeVisible()
    const withSw = await api<Dev>(page.request, 'GET', `/inventory/devices/${made.body.id}`)
    expect(JSON.stringify(withSw.body)).toMatch(/wordpress/i)
    await page.getByRole('button', { name: /^Remove WordPress from the device$/ }).first().click()
    await expect(page.getByRole('button', { name: /^Remove WordPress from the device$/ })).toHaveCount(0)
    const without = await api<Dev>(page.request, 'GET', `/inventory/devices/${made.body.id}`)
    expect(JSON.stringify(without.body)).not.toMatch(/wordpress/i)
    // a version with characters outside the allowed set is refused by the backend (INV-4)
    const bad = await api(page.request, 'POST', `/inventory/devices/${made.body.id}/software`, { catalog_id: 'kev:wordpress:wordpress', version: '6.5.2; rm -rf /' })
    expect(bad.status, 'a version with a semicolon').toBe(400)
  })

  test('removing a device asks first; Escape and Cancel keep it; the second confirm removes it and the page then says it does not exist', async ({ page }) => {
    const name = uniq('rm')
    const made = await api<Dev>(page.request, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name, ip: ip() })
    expect(made.status).toBe(201)
    await page.goto(`/devices/${made.body.id}`)
    await page.getByRole('button', { name: 'Remove from list' }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toBeVisible()
    await shot(page, 'real-inventory', 'delete-confirm')
    await page.keyboard.press('Escape')
    await expect(dlg).toBeHidden()
    await page.getByRole('button', { name: 'Remove from list' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel' }).click()
    await expect(page).toHaveURL(new RegExp(made.body.id))
    expect(await byName(page, name), 'still there after Escape and Cancel').toBeTruthy()
    await page.getByRole('button', { name: 'Remove from list' }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Remove from list' }).click()
    await expect(page).toHaveURL(/\/devices$/)
    expect(await byName(page, name), 'gone after the confirm').toBeUndefined()
    await page.goto(`/devices/${made.body.id}`)
    await expect(page.getByText('This device does not exist').first()).toBeVisible()
  })
})

// Not approved devices (S-INV-3: approve, mark unknown) need a device a sensor found; the passive recording can be delivered once per run, so
// they are tested in sensors.global.spec.ts, not here (this project runs in parallel with the others).

test.describe('viewer, read only', () => {
  test.use({ storageState: authFile('viewer'), actionTimeout: 10_000 })

  test('write buttons are locked with the role named; export works; the setup page and the API refuse', async ({ page }) => {
    await open(page)
    for (const n of ['Add a device', 'Import CSV']) {
      const b = page.getByRole('button', { name: n })
      await expect(b).toBeDisabled()
      await expect(b).toHaveAttribute('title', /Operator/)
    }
    await expect(page.getByRole('button', { name: 'Export CSV' })).toBeEnabled()
    await expect(page.getByRole('link', { name: 'Scope and sensors' })).toHaveCount(0)
    await page.goto('/devices/setup')
    await expect(page.getByText('You do not have access to this page')).toBeVisible()
    const list = await devices(page)
    await page.goto(`/devices/${list.items[0]!.id}`)
    await expect(page.getByRole('button', { name: 'Remove from list' })).toBeDisabled()
    // the real backend, not only the buttons
    const post = await api(page.request, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name: uniq('v'), ip: ip() })
    expect(post.status, 'viewer POST /inventory/devices').toBe(403)
    const del = await api(page.request, 'DELETE', `/inventory/devices/${list.items[0]!.id}`)
    expect(del.status, 'viewer DELETE').toBe(403)
    const settings = await api(page.request, 'GET', '/inventory/settings')
    expect(settings.status, 'viewer GET /inventory/settings (admin)').toBe(403)
    expect(ACCOUNTS.viewer.email).toBeTruthy()
  })
})
