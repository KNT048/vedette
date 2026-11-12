import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { server } from '@/test/server'
import { eachOption } from '@/test/formMatrix'
import { assetsStore, auditStore, findingsStore, installStore, modulesStore, sessionStore, usersStore } from '@/mocks/stores'
import kevProducts from '../../../../content/catalog/kev-products.json'
import { linuxOneLiner, OSQUERY_SCHEDULE, osquerySteps, wazuhReaderSteps, windowsOneLiner } from './agentConfig'
import { catalogPath, CATALOG_Q_MAX } from './api'
import { CATALOG, customEntry, findCatalog, searchCatalog } from './catalog'
import { sha256Hex } from './kinds'
import { OSQUERY_VERSION } from './installScripts'
import { BOX_ID, compareObs, ensureBox, inventorySettingsStore, markCurrent, type StoredObs } from './mocks'
import type { OsqueryPackage } from './types'
import { normalizeRange, rangeProblem } from './validate'

vi.setConfig({ testTimeout: 30_000 })
// The box is always the first device; the store gets it on the first inventory call, so counts taken before the page loads need it already there.
beforeEach(() => ensureBox())

const BASE = `${location.origin}/api/v1/inventory`
const T = { timeout: 5000 }
const asAdmin = () => sessionStore.set({ userId: 'u-admin' })
async function call(method: string, path: string, body?: unknown) {
  const res = await fetch(`${BASE}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await res.text()
  let json: unknown = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: res.status, text, json: json as Record<string, any> | null } // eslint-disable-line @typescript-eslint/no-explicit-any
}
const enableModule = (id: string, enabled: boolean) => modulesStore.update((l) => l.map((m) => (m.id === id ? { ...m, enabled } : m)))
const find = (id: string) => assetsStore.get().find((a) => a.id === id)!
const DEVICE_TABLE = 'Device list'
const deviceTable = () => screen.findByRole('table', { name: DEVICE_TABLE }, T)
// Saving the scope: the form re-mounts when the saved settings come back, so wait for its observable result
// (Save disabled again and the "Confirmed by ..." line) instead of the toast; the toast itself is covered by an it.fails test below.
const scopeSaved = () => waitFor(() => {
  expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
  expect(screen.getByText(/^Confirmed by /)).toBeInTheDocument()
}, { timeout: 8000 })
// The setup page re-mounts its sections once right after first paint (a button found at that moment can be detached),
// so click again with a fresh query until the expected effect shows up.
const clickUntil = (user: ReturnType<typeof userEvent.setup>, get: () => HTMLElement, done: () => unknown) =>
  waitFor(async () => { await user.click(get()); done() }, { timeout: 8000 })

describe('inventory: device list (S-INV-1, S-INV-3)', () => {
  it('the first sentence says "N devices, 2 not yet approved", with a table and no a11y violations', async () => {
    renderApp('/devices')
    expect(await screen.findByRole('heading', { level: 1, name: new RegExp(`^${assetsStore.get().length} devices, 2 not yet approved$`) }, T)).toBeInTheDocument()
    const table = await deviceTable()
    expect(within(table).getAllByRole('row').length).toBeGreaterThan(10)
    expect(within(table).getByText('NAS-PHOTOS')).toBeInTheDocument()
    expect((await screen.findAllByText('Sample data', undefined, T)).length).toBeGreaterThan(0)
    await expectNoA11yViolations()
  })

  it('filters Not approved / Fragile / Added by hand', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: /^Not approved \(2\)$/ }))
    let table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getAllByRole('row')).toHaveLength(3) // header + 2 devices
    await user.click(screen.getByRole('button', { name: /^Added by hand \(0\)$/ }))
    table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getByText(/No device added by hand yet/)).toBeInTheDocument()
    const fragile = assetsStore.get().filter((a) => a.fragile).length
    await user.click(screen.getByRole('button', { name: new RegExp(`^Fragile \\(${fragile}\\)$`) }))
    table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getAllByRole('row')).toHaveLength(fragile + 1)
  })

  it('the search box filters by maker', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.type(screen.getByRole('textbox', { name: /Search by name, IP/ }), 'hikvision')
    const table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getAllByRole('row')).toHaveLength(5) // 3 cameras + NVR + header
  })

  it('S-INV-2: declaring by hand: Add a device, type a few letters, pick a suggestion, Add', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' })) // click 1
    await user.type(await screen.findByRole('combobox', { name: 'Product' }), 'fortigate') // the list only appears once the user types
    const option = (await screen.findAllByRole('option', { name: /FortiGate/ }, T))[0]!
    await expectNoA11yViolations() // combobox is open
    await user.click(option) // click 2
    await user.click(screen.getByRole('button', { name: 'Add' })) // click 3
    expect(await screen.findByText(/Added FortiGate/, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get()).toHaveLength(before + 1)
    const a = assetsStore.get()[0]!
    expect(a.origin).toBe('manual')
    expect(a.approved).toBe(true)
    expect(a.ip).toBe('—')
    expect(a.software[0]).toMatchObject({ vendor: 'Fortinet', source: 'manual', confidence: 1 })
    expect(a.software[0]!.kev).toContain('fortinet|fortios')
    expect(auditStore.get().some((e) => e.action === 'inventory.add_manual')).toBe(true)
  })

  it('manual add with version, name and IP; searching with a Vietnamese word without diacritics still suggests a product', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const box = await screen.findByRole('combobox', { name: 'Product' })
    await user.type(box, 'tuong lua')
    expect((await screen.findAllByRole('option', { name: /FortiGate/ }, T)).length).toBeGreaterThan(0)
    await user.keyboard('{ArrowDown}{Enter}') // pick with the keyboard
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Product' })).toHaveAttribute('readonly'))
    await user.type(screen.getByLabelText(/Version/), '7.2.5')
    await user.type(screen.getByLabelText(/^Name/), 'Branch firewall')
    await user.type(screen.getByLabelText(/IP address/), '192.168.30.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(assetsStore.get().find((x) => x.ip === '192.168.30.1')).toBeDefined(), T)
    const a = assetsStore.get().find((x) => x.ip === '192.168.30.1')!
    expect(a.hostname).toBe('Branch firewall')
    expect(a.software[0]!.version).toBe('7.2.5')
  })

  it('manual add: a bad IP and a duplicate IP show an English error and nothing is added', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    await user.type(await screen.findByRole('combobox', { name: 'Product' }), 'mikrotik')
    await user.click((await screen.findAllByRole('option', { name: /MikroTik/ }, T))[0]!)
    await user.type(screen.getByLabelText(/IP address/), '999.1.1.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByRole('alert', undefined, T)).toHaveTextContent('That IP address is not valid')
    await user.clear(screen.getByLabelText(/IP address/))
    await user.type(screen.getByLabelText(/IP address/), '192.168.10.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('is already in the list (FW-HQ)'), T)
    expect(assetsStore.get()).toHaveLength(before)
  })

  it('free entry: "Can\'t find it?" switches to Maker and Product inputs; incomplete input cannot be submitted', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    await user.click(await screen.findByRole('button', { name: "Can't find it? Enter the maker and product yourself" }, T))
    expect(screen.queryByRole('combobox')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Maker'), 'Fortinet')
    expect(screen.getByRole('button', { name: 'Add' })).toBeDisabled() // product is still empty
    await user.type(screen.getByLabelText('Product'), 'FortiGate')
    expect(screen.getByRole('button', { name: 'Add' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/Added Fortinet FortiGate/, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get()).toHaveLength(before + 1)
    const sw = assetsStore.get()[0]!.software[0]!
    expect(sw).toMatchObject({ vendor: 'Fortinet', product: 'FortiGate', source: 'manual' })
    expect(sw.kev.length).toBeGreaterThan(0) // matched by maker
  })

  it('free entry: "Back to the list" returns to the product search', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    await user.click(await screen.findByRole('button', { name: /Can't find it/ }, T))
    await user.click(screen.getByRole('button', { name: 'Back to the list' }))
    expect(await screen.findByRole('combobox', { name: 'Product' }, T)).toBeInTheDocument()
  })

  it('the Add dialog is titled "Add a device"; the first Escape closes only the suggestion list, the second closes the dialog', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByRole('heading', { name: 'Add a device' })).toBeInTheDocument()
    const box = within(dialog).getByRole('combobox', { name: 'Product' })
    await user.click(box)
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument() // empty query: no list, only the hint
    expect(within(dialog).getByText(/Type a product, maker or model, for example fortigate 60f or synology\./)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: "Can't find it? Enter the maker and product yourself" })).toBeInTheDocument()
    await user.type(box, 'forti')
    expect((await screen.findAllByRole('option', undefined, T)).length).toBeGreaterThan(0)
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('listbox')).not.toBeInTheDocument(), T)
    expect(screen.getByRole('dialog')).toBeInTheDocument() // dialog still open
    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument(), T)
  })

  it('the viewer role cannot add; the operator role can', async () => {
    renderApp('/devices', { role: 'viewer' })
    await deviceTable()
    expect(screen.getByRole('button', { name: 'Add a device' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Import CSV' })).toBeDisabled()
    expect(screen.queryByRole('link', { name: 'Scope and sensors' })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: 'Approve' })[0]).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Notify me about new devices' })).toBeDisabled()
  })

  it('the operator role gets the add button enabled and the setup link hidden (admin only)', async () => {
    renderApp('/devices', { role: 'operator' })
    await deviceTable()
    expect(screen.getByRole('button', { name: 'Add a device' })).toBeEnabled()
    expect(screen.queryByRole('link', { name: 'Scope and sensors' })).not.toBeInTheDocument()
  })

  it('the viewer role is refused writes by the API (403), and anonymous gets 401', async () => {
    sessionStore.set({ userId: 'u-view' })
    const r = await call('POST', '/devices', { catalog_id: 'fortigate' })
    expect(r.status).toBe(403)
    expect((await call('GET', '/devices')).status).toBe(200)
    sessionStore.set({ userId: null })
    expect((await call('GET', '/devices')).status).toBe(401)
  })

  it('S-INV-3: approve a pending device', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await screen.findByText('2 new devices not approved', undefined, T)
    await user.click(screen.getAllByRole('button', { name: 'Approve' })[0]!)
    expect(await screen.findByText(/Approved /, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get().filter((a) => !a.approved)).toHaveLength(1)
    expect(await screen.findByRole('heading', { level: 1, name: /1 not yet approved/ }, T)).toBeInTheDocument()
  })

  it('S-INV-3: mark unknown, then remove the mark', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await screen.findByText('2 new devices not approved', undefined, T)
    await user.click(screen.getAllByRole('button', { name: 'Mark unknown' })[0]!)
    expect(await screen.findByText(/as unknown\./, undefined, T)).toBeInTheDocument()
    expect((await screen.findAllByText('Marked unknown', undefined, T)).length).toBeGreaterThan(1) // chip in the table + chip in the pending list
    expect(find('a-unk01').approved).toBe(false)
    await user.click((await screen.findAllByRole('button', { name: 'Remove unknown mark' }, T))[0]!)
    expect(await screen.findByText(/Removed the unknown mark from/, undefined, T)).toBeInTheDocument()
  })

  it('S-INV-3: removing a pending device asks for confirmation', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await screen.findByText('2 new devices not approved', undefined, T)
    await user.click(screen.getAllByRole('button', { name: 'Remove' })[0]!)
    expect(assetsStore.get()).toHaveLength(before) // nothing removed before confirming
    await user.click(await screen.findByRole('button', { name: 'Remove from list' }, T))
    await waitFor(() => expect(assetsStore.get()).toHaveLength(before - 1), T)
    expect(auditStore.get().some((e) => e.action === 'inventory.delete')).toBe(true)
  })

  it('the delete dialog mentions the findings count when the device has findings, and removes them', async () => {
    const user = userEvent.setup()
    const n = findingsStore.get().filter((f) => f.asset_id === 'a-nas02').length
    expect(n).toBeGreaterThan(0)
    renderApp('/devices/a-nas02')
    await user.click(await screen.findByRole('button', { name: 'Remove from list' }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).toHaveTextContent(n === 1 ? 'This device has 1 finding.' : `This device has ${n} findings.`)
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(find('a-nas02' as string)).toBeUndefined(), T)
    expect(findingsStore.get().filter((f) => f.asset_id === 'a-nas02')).toHaveLength(0)
  })

  it('the delete dialog says nothing about findings when the device has none', async () => {
    const user = userEvent.setup()
    expect(findingsStore.get().some((f) => f.asset_id === 'a-pc02')).toBe(false)
    renderApp('/devices/a-pc02')
    await user.click(await screen.findByRole('button', { name: 'Remove from list' }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).not.toHaveTextContent(/This device has \d+ finding/)
  })

  it('the "Notify me about new devices" switch saves, and says so when the Notifications module is off', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    const sw = await screen.findByRole('switch', { name: 'Notify me about new devices' }, T)
    expect(sw).toBeChecked()
    expect(screen.getByText(/Notifications go through the channels/)).toBeInTheDocument()
    await user.click(sw)
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Notify me about new devices' })).not.toBeChecked(), T)
    await user.click(screen.getByRole('switch', { name: 'Notify me about new devices' }))
    enableModule('notify', false)
    renderApp('/devices')
    expect((await screen.findAllByText(/The Notifications module is off/, undefined, T)).length).toBeGreaterThan(0)
  })

  it('Inventory module off: says so and points to where to turn it on', async () => {
    enableModule('inventory', false)
    renderApp('/devices')
    expect(await screen.findByText('Inventory module is off', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'The device list is off' })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Open module settings' })).toBeInTheDocument()
  })

  it('an API error shows the message and a Try again button', async () => {
    server.use(http.get('*/api/v1/inventory/devices', () => HttpResponse.json({ error: { code: 'x', message: 'The box is not responding.' } }, { status: 503 })))
    renderApp('/devices')
    expect(await screen.findByText('The box is not responding.', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('no devices at all: guides the next action', async () => {
    assetsStore.set([])
    renderApp('/devices')
    // Only the box is left (it cannot be deleted): the header and the empty state agree (2026-11-12 walk, S-INV-5).
    expect(await screen.findByRole('heading', { name: 'Only the Vedette box so far' }, T)).toBeInTheDocument()
    expect(screen.getByText('No other devices yet')).toBeInTheDocument()
    expect(screen.queryByText('No devices yet')).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Add a device' }).length).toBeGreaterThan(1)
    expect(await screen.findByText(/Vedette is watching the network ranges you saved/, undefined, T)).toBeInTheDocument() // the mock has ranges saved
    expect(screen.queryByRole('link', { name: "Set the box's network ranges" })).not.toBeInTheDocument()
  })

  it('no devices and no range saved: asks for the ranges', async () => {
    assetsStore.set([])
    server.use(http.get('*/api/v1/inventory/settings', () => HttpResponse.json({ ...inventorySettingsStore.get(), lan_ranges: [] })))
    renderApp('/devices')
    expect(await screen.findByRole('link', { name: "Set the box's network ranges" }, T)).toHaveAttribute('href', '/devices/setup')
  })

  it('the setup page does not ask for agents while agent-intake is off', async () => {
    let asked = 0
    server.use(http.get('*/api/v1/inventory/agents', () => { asked++; return HttpResponse.json({ error: { code: 'module_off', message: 'off' } }, { status: 404 }) }))
    renderApp('/devices/setup')
    expect((await screen.findAllByText(/Agent intake is off/, undefined, T)).length).toBeGreaterThan(0)
    expect(asked).toBe(0)
  })
})

describe('inventory: CSV (S-INV-2)', () => {
  it('exports CSV with a UTF-8 BOM, a header row, and CSV-injection protection', async () => {
    asAdmin()
    await call('POST', '/devices', { catalog_id: 'wordpress', name: '=HYPERLINK("http://x")' })
    const r = await call('GET', '/export.csv')
    expect(r.status).toBe(200)
    const bytes = new Uint8Array(await (await fetch(`${BASE}/export.csv`)).arrayBuffer())
    expect([...bytes.slice(0, 3)]).toEqual([0xef, 0xbb, 0xbf]) // BOM so Excel reads UTF-8
    expect(r.text).toContain('name,ip,mac,kind,vendor,model,os,software,approved,fragile,origin,source,confidence,last_seen')
    expect(r.text).toContain('FW-HQ,192.168.10.1')
    expect(r.text).toContain(`"'=HYPERLINK(""http://x"")"`)
  })

  async function importFile(user: ReturnType<typeof userEvent.setup>, content: string, name = 'devices.csv') {
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Import CSV' }))
    const input = await screen.findByLabelText('Choose a CSV file', undefined, T)
    await user.upload(input, new File([content], name, { type: 'text/csv' }))
  }

  it('reports errors by line; the correct rows are still added', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    await importFile(user, [
      'name,ip,product,version,kind',
      'FW-BR,192.168.30.1,FortiGate,7.2.5,firewall',
      'Company web,,WordPress,6.5.2,web',
      'X,,Khongco,,',
      'Y,999.1.1.1,Synology,,',
      'Z,192.168.30.1,QNAP,,',
      ',,,,',
      'M,,MikroTik,,notakind',
    ].join('\n'))
    expect(await screen.findByText('Added 2 devices, skipped 4 rows.', undefined, T)).toBeInTheDocument()
    expect(screen.getByText('Line 4:').parentElement).toHaveTextContent('Product "Khongco" not recognised')
    expect(screen.getByText('Line 5:').parentElement).toHaveTextContent('That IP address is not valid')
    expect(screen.getByText('Line 6:').parentElement).toHaveTextContent('IP 192.168.30.1 is already in the list')
    expect(screen.getByText('Line 8:').parentElement).toHaveTextContent('Type "notakind" is not valid')
    expect(assetsStore.get()).toHaveLength(before + 2)
    expect(assetsStore.get().find((a) => a.ip === '192.168.30.1')!.software[0]!.version).toBe('7.2.5')
    await expectNoA11yViolations()
  })

  it('understands English header aliases and quoted cells', async () => {
    const user = userEvent.setup()
    await importFile(user, 'device,ip address,software,version,type\n"Storage, floor 2",192.168.40.5,Hikvision,V5.7,Camera\n')
    expect(await screen.findByText('Added 1 device, skipped 0 rows.', undefined, T)).toBeInTheDocument()
    const a = assetsStore.get().find((x) => x.ip === '192.168.40.5')!
    expect(a.hostname).toBe('Storage, floor 2')
    expect(a.kind).toBe('camera')
  })

  it('accepts a semicolon delimiter, a BOM, and kind labels as shown in the UI (Firewall, Wi-Fi (AP))', async () => {
    asAdmin()
    const text = '﻿name;ip;product;version;kind\r\nEdge;192.168.60.1;FortiGate;7.4;Firewall\r\nLobby AP;192.168.60.2;FortiGate;;Wi-Fi (AP)\r\nCam recorder;192.168.60.3;FortiGate;;Camera recorder\r\n'
    const r = await call('POST', '/import', { filename: 'excel.csv', text })
    expect(r.json).toMatchObject({ created: 3, skipped: 0 })
    expect(assetsStore.get().find((a) => a.ip === '192.168.60.1')!.kind).toBe('firewall')
    expect(assetsStore.get().find((a) => a.ip === '192.168.60.2')!.kind).toBe('ap')
    expect(assetsStore.get().find((a) => a.ip === '192.168.60.3')!.kind).toBe('nvr')
  })

  it('a file without a valid header row is rejected with guidance', async () => {
    const user = userEvent.setup()
    await importFile(user, 'foo,bar\n1,2\n')
    expect(await screen.findByRole('alert', undefined, T)).toHaveTextContent('The first row must be column headers')
  })

  it('a mixed-delimiter file, a stray quote and an unknown product are line errors, never a garbage device', async () => {
    asAdmin()
    const before = assetsStore.get().length
    const text = [
      'name;ip;product;version;kind', 'semi,192.168.53.1,Prod,1,server', // line 2: header uses ; but the row uses ,
      'quote"bad;192.168.53.2;;;', // line 3: stray quote
      'dns;192.168.53.3;Dns;;', // line 4: no fuzzy match to D-Link
      'ok;192.168.53.4;FortiGate;;',
    ].join('\n')
    const r = (await call('POST', '/import', { text })).json!
    expect(r).toMatchObject({ created: 1, skipped: 3 })
    expect(r.errors.map((e: { line: number }) => e.line)).toEqual([2, 3, 4])
    expect(r.errors[0].message).toContain('one cell but the header has 5')
    expect(r.errors[1].message).toContain('double quote')
    expect(r.errors[2].message).toContain('Product "Dns" not recognised')
    expect(r.errors[2].message).not.toContain('suggestion box')
    expect(assetsStore.get()).toHaveLength(before + 1)
    expect(findCatalog('Dns')).toBeUndefined()
    // short rows and a trailing separator are fine
    expect((await call('POST', '/import', { text: 'name,ip,product,version,kind\nshort,192.168.54.1\ntrailing,192.168.54.2,FortiGate,,,\n' })).json).toMatchObject({ created: 2, skipped: 0 })
    // a quote that never closes flags its row, not the whole file
    expect((await call('POST', '/import', { text: 'name,ip\n"open,192.168.53.9\n' })).json!.errors[0].message).toContain('never closed')
    expect((await call('POST', '/import', { text: 'name,ip\r\nok,192.168.55.1\r\n\"\r' })).json).toMatchObject({ created: 1, errors: [{ line: 3 }] })
    // header only
    expect((await call('POST', '/import', { text: 'name,ip,product\n' })).json?.error.code).toBe('no_rows')
  })

  it('a public IP or an IP outside the saved ranges is added with a note', async () => {
    asAdmin()
    const r = (await call('POST', '/import', { text: 'name,ip\npub,8.8.8.8\nfar,10.99.99.9\n' })).json!
    expect(r.created).toBe(2)
    expect(r.notes).toHaveLength(2)
    expect(r.notes[0].message).toContain('public address')
    expect(r.notes[1].message).toContain('outside your saved network ranges')
  })

  it('an oversized file is blocked in the browser and never sent', async () => {
    const user = userEvent.setup()
    const called = vi.fn()
    server.use(http.post('*/api/v1/inventory/import', () => { called(); return HttpResponse.json({ created: 0, skipped: 0, errors: [], notes: [] }) }))
    await importFile(user, 'x'.repeat(200_001))
    expect(await screen.findByRole('alert', undefined, T)).toHaveTextContent('The file is larger than 200 KB')
    expect(called).not.toHaveBeenCalled()
  })

  it('the server also limits rows and size', async () => {
    asAdmin()
    const many = `name\n${Array.from({ length: 501 }, (_, i) => `d${i}`).join('\n')}`
    expect((await call('POST', '/import', { text: many })).json?.error.code).toBe('too_many_rows')
    expect((await call('POST', '/import', { text: 'a'.repeat(200_001) })).json?.error.code).toBe('too_large')
    expect((await call('POST', '/import', { text: '' })).json?.error.code).toBe('empty_file')
    expect((await call('POST', '/import', { text: 'foo,bar\n1,2' })).json?.error.code).toBe('bad_header')
  })
})

describe('inventory: device detail (S-INV-1)', () => {
  it('shows every observation with source and confidence, services, and software matched to CVEs; no a11y violations', async () => {
    renderApp('/devices/a-nas02')
    expect(await screen.findByRole('heading', { level: 1, name: /^NAS-PHOTOS: NAS, last seen/ }, T)).toBeInTheDocument()
    const obs = await screen.findByRole('table', { name: 'Observations for this device' }, T)
    expect(within(obs).getByText('QTS 5.0.1')).toBeInTheDocument()
    expect(within(obs).getByText('Unknown OS (guessed from packet TTL)')).toBeInTheDocument() // the older value is kept
    expect(within(obs).getAllByText(/confidence/).length).toBeGreaterThan(3)
    expect(within(obs).getAllByText('In use').length).toBeGreaterThanOrEqual(4)
    expect(within(obs).getAllByText('Kept for comparison').length).toBeGreaterThanOrEqual(1)
    const services = screen.getByRole('table', { name: 'Services open on the device' })
    expect(within(services).getByText('8080/tcp')).toBeInTheDocument()
    const sw = screen.getByRole('table', { name: 'Software on the device' })
    expect(within(sw).getByRole('link', { name: 'CVE-2022-27593' })).toHaveAttribute('href', '/cve/CVE-2022-27593')
    expect(screen.getByRole('switch', { name: 'Fragile device' })).toBeChecked()
    await expectNoA11yViolations()
  })

  it('changing the type adds a manual observation and keeps the old one', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas01')
    const select = await screen.findByRole('combobox', { name: 'Device type' }, T)
    await user.selectOptions(select, 'server')
    expect(await screen.findByText(/Type changed to Server\./, undefined, T)).toBeInTheDocument()
    expect(find('a-nas01').kind).toBe('server')
    const obs = screen.getByRole('table', { name: 'Observations for this device' })
    await waitFor(() => expect(within(obs).getByText('Server')).toBeInTheDocument(), T)
    expect(within(obs).getByText('NAS')).toBeInTheDocument() // old value still there
    expect(within(obs).getByText('Added by hand')).toBeInTheDocument()
    expect(within(obs).getAllByText('In use').length).toBeGreaterThanOrEqual(1)
  })

  it('toggles the fragile flag and saves notes', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-pc01')
    const sw = await screen.findByRole('switch', { name: 'Fragile device' }, T)
    expect(sw).not.toBeChecked()
    await user.click(sw)
    await waitFor(() => expect(find('a-pc01').fragile).toBe(true), T)
    await user.type(screen.getByRole('textbox', { name: 'Notes about the device' }), 'Accounting room')
    await user.click(screen.getByRole('button', { name: 'Save notes' }))
    await waitFor(() => expect(find('a-pc01').notes).toBe('Accounting room'), T)
  })

  it('adds then removes manual software; software seen by a sensor cannot be removed by hand', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-pc01')
    await screen.findByRole('table', { name: 'Software on the device' }, T)
    const before = find('a-pc01').software.length
    await user.click(screen.getByRole('button', { name: 'Add software' }))
    await user.type(await screen.findByRole('combobox', { name: 'Product' }, T), 'wordpress')
    await user.click((await screen.findAllByRole('option', { name: /WordPress/ }, T))[0]!)
    await user.type(screen.getByLabelText(/Version/), '6.5.2')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(find('a-pc01').software).toHaveLength(before + 1), T)
    expect(screen.queryByRole('button', { name: /Remove Windows from/ })).not.toBeInTheDocument()
    const added = find('a-pc01').software.find((s) => s.source === 'manual')!
    await user.click((await screen.findAllByRole('button', { name: `Remove ${added.display} from the device` }, T))[0]!)
    await waitFor(() => expect(find('a-pc01').software).toHaveLength(before), T)
    asAdmin()
    const r = await call('DELETE', `/devices/a-pc01/software/${find('a-pc01').software[0]!.id}`)
    expect(r.json?.error.code).toBe('not_manual')
  })

  it('a pending device has an approval box right on the detail page', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-prn03')
    expect(await screen.findByText('This device is not approved yet', undefined, T)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Approve' }))
    await waitFor(() => expect(screen.queryByText('This device is not approved yet')).not.toBeInTheDocument(), T)
    expect(find('a-prn03').approved).toBe(true)
  })

  it('removing from the detail page goes back to the list', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-pc02')
    await screen.findByRole('table', { name: 'Observations for this device' }, T)
    await user.click(screen.getByRole('button', { name: 'Remove from list' }))
    await user.click(await screen.findByRole('button', { name: 'Remove from list' }, T))
    expect(await screen.findByRole('heading', { level: 1, name: /devices, 2 not yet approved/ }, T)).toBeInTheDocument()
    expect(assetsStore.get().find((a) => a.id === 'a-pc02')).toBeUndefined()
  })

  it('a device that does not exist: says so and offers a way back', async () => {
    renderApp('/devices/a-missing')
    expect(await screen.findByText('This device does not exist', undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Device list' })).toHaveAttribute('href', '/devices')
  })

  it('the viewer role: every write control is locked', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    expect(await screen.findByRole('combobox', { name: 'Device type' }, T)).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Fragile device' })).toBeDisabled()
    expect(screen.getByRole('textbox', { name: 'Notes about the device' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Add software' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Remove from list' })).toBeDisabled()
  })

  it('PATCH validates at the edge', async () => {
    asAdmin()
    expect((await call('PATCH', '/devices/a-pc01', { kind: 'laptop-bay' })).json?.error.code).toBe('bad_kind')
    expect((await call('PATCH', '/devices/a-pc01', { notes: 'x'.repeat(2001) })).json?.error.code).toBe('bad_notes')
    expect((await call('PATCH', '/devices/a-none', { notes: 'x' })).status).toBe(404)
  })

  it('a detail load error shows the error state', async () => {
    server.use(http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the device data.' } }, { status: 500 })))
    renderApp('/devices/a-pc01')
    expect(await screen.findByText('Could not read the device data.', undefined, T)).toBeInTheDocument()
  })
})

describe('inventory: add-device API (catalog id and free entry)', () => {
  it('accepts {vendor, product} without catalog_id and matches by vendor', async () => {
    asAdmin()
    const r = await call('POST', '/devices', { vendor: 'Fortinet', product: 'FortiGate', version: '7.2.5', ip: '192.168.77.1' })
    expect(r.status).toBe(201)
    expect(r.json).toMatchObject({ display: 'Fortinet FortiGate' })
    expect(r.json!.kev_cves).toBeGreaterThan(0)
    const a = find(r.json!.id)
    expect(a.software[0]).toMatchObject({ vendor: 'Fortinet', product: 'FortiGate', version: '7.2.5', source: 'manual' })
    expect(a.software[0]!.kev).toContain('fortinet|fortios')
  })

  it('an unknown vendor still works and uses a CPE-style key', async () => {
    asAdmin()
    const r = await call('POST', '/devices', { vendor: 'Acme Corp', product: 'Router 9' })
    expect(r.status).toBe(201)
    expect(find(r.json!.id).software[0]!.kev).toEqual(['acme corp|router 9'])
  })

  it('incomplete or bad free entry gives an error', async () => {
    asAdmin()
    expect((await call('POST', '/devices', { vendor: 'Fortinet' })).json?.error.code).toBe('incomplete_product')
    expect((await call('POST', '/devices', { product: 'FortiGate' })).json?.error.code).toBe('incomplete_product')
    expect((await call('POST', '/devices', { vendor: '<b>', product: 'x' })).json?.error.code).toBe('bad_product')
    expect((await call('POST', '/devices', { vendor: 'a'.repeat(65), product: 'x' })).json?.error.code).toBe('bad_product')
    expect((await call('POST', '/devices', {})).json?.error.code).toBe('unknown_product')
    expect((await call('POST', '/devices', { catalog_id: 'no-such-product' })).json?.error.code).toBe('unknown_product')
    expect((await call('POST', '/devices', { catalog_id: 'fortigate', version: '<script>' })).json?.error.code).toBe('bad_version')
  })

  it('free entry also works for adding software to a device', async () => {
    asAdmin()
    const r = await call('POST', '/devices/a-pc01/software', { vendor: 'Fortinet', product: 'FortiClient' })
    expect(r.status).toBe(201)
    expect(find('a-pc01').software.some((s) => s.product === 'FortiClient')).toBe(true)
  })
})

describe('inventory: catalog request', () => {
  it('clips a pasted long query to the 80 characters the contract allows, so the backend never answers 400', () => {
    const long = `  ${'forti '.repeat(60)}  `
    const q = decodeURIComponent(catalogPath(long).split('q=')[1] ?? '')
    expect(q.length).toBeLessThanOrEqual(CATALOG_Q_MAX)
    expect(q.startsWith('forti forti')).toBe(true)
    expect(q).toBe(q.trim())
    expect(catalogPath('  FortiGate ')).toBe('/inventory/catalog?q=FortiGate')
    expect(catalogPath('a'.repeat(200)).split('q=')[1]).toHaveLength(CATALOG_Q_MAX)
  })
})

describe('inventory: catalog', () => {
  it('has hundreds of entries: all CISA KEV pairs plus a curated list', () => {
    expect(CATALOG.length).toBeGreaterThan(800)
    expect(CATALOG.filter((e) => e.curated).length).toBeGreaterThan(50)
    expect(new Set(CATALOG.map((e) => e.id)).size).toBe(CATALOG.length) // ids are unique
  })

  it('ranks well: "fortigate 60f" puts FortiGate first; qnap, synology and exchange are found', () => {
    expect(searchCatalog('fortigate 60f').items[0]!.display).toBe('FortiGate')
    expect(searchCatalog('forti').items[0]!.display).toBe('FortiGate')
    const qnap = searchCatalog('qnap').items
    expect(qnap.length).toBeGreaterThan(0)
    expect(qnap.slice(0, 3).every((e) => e.vendor.toLowerCase().includes('qnap'))).toBe(true)
    const nas = searchCatalog('nas synology').items[0]!
    expect(nas.display).toMatch(/Synology/)
    expect(nas.display).toMatch(/NAS/)
    expect(searchCatalog('exchange').items.slice(0, 3).some((e) => /Exchange/.test(e.display))).toBe(true)
    expect(searchCatalog('vmware').items.some((e) => e.display === 'VMware ESXi')).toBe(true)
    expect(searchCatalog('broadcom').items[0]!.vendor).toMatch(/Broadcom/i) // by maker name
    expect(searchCatalog('zzzz-no-such-thing').items).toEqual([])
  })

  it('Vietnamese words without diacritics still work: "tuong lua" finds firewalls, "may in" finds printers', () => {
    const fw = searchCatalog('tuong lua').items
    expect(fw.map((e) => e.display)).toEqual(expect.arrayContaining(['FortiGate']))
    expect(fw.slice(0, 5).some((e) => e.kind === 'firewall')).toBe(true)
    const prn = searchCatalog('may in').items
    expect(prn.length).toBeGreaterThan(0)
    expect(prn.slice(0, 5).some((e) => e.kind === 'printer')).toBe(true)
    expect(searchCatalog('tường lửa').items.map((e) => e.display)).toContain('FortiGate') // with diacritics too
  })

  it('an empty query returns the curated popular list, capped by the limit', () => {
    const r = searchCatalog('', 8)
    expect(r.items).toHaveLength(8)
    expect(r.items.every((e) => e.curated)).toBe(true)
    expect(r.total).toBe(CATALOG.length)
    expect(searchCatalog('').items.length).toBe(30)
  })

  it('every KEV vendor/product pair is selectable (exact key)', () => {
    const keys = new Set(CATALOG.flatMap((e) => e.kev))
    const rows = kevProducts as { vendor: string; product: string }[]
    expect(rows.length).toBeGreaterThan(500)
    const missing = rows.map((r) => `${r.vendor}|${r.product}`.toLowerCase()).filter((k) => !keys.has(k))
    expect(missing).toEqual([])
  })

  it('curated FortiGate maps to the key fortinet|fortios; CSV names resolve to entries', () => {
    const fg = findCatalog('FortiGate')!
    expect(fg.curated).toBe(true)
    expect(fg.kev[0]).toBe('fortinet|fortios')
    expect(findCatalog('Synology')).toBeDefined()
    expect(findCatalog('Khongco')).toBeUndefined()
    expect(customEntry('Fortinet', 'FortiGate').kev.length).toBeGreaterThan(0)
  })

  it('GET /catalog returns at most 30 items plus the total; items have a category and kev_cves', async () => {
    asAdmin()
    for (const q of ['', 'a', 'microsoft']) {
      const r = (await call('GET', `/catalog?q=${encodeURIComponent(q)}`)).json!
      expect(r.items.length).toBeLessThanOrEqual(30)
      expect(r.items.length).toBeGreaterThan(0)
      expect(r.total).toBeGreaterThanOrEqual(r.items.length)
      for (const it of r.items) {
        expect(typeof it.category).toBe('string')
        expect(it.category.length).toBeGreaterThan(0)
        expect(typeof it.kev_cves).toBe('number')
      }
    }
    expect((await call('GET', '/catalog?q=microsoft')).json!.total).toBeGreaterThan(30)
    expect(((await call('GET', '/catalog?q=zzzz-no-such-thing')).json!.items as unknown[])).toEqual([])
  })
})

describe('inventory: range validation helpers', () => {
  it('normalizeRange: only host bits are cleared; a bare address is never guessed', () => {
    expect(normalizeRange('192.168.18.0')).toEqual({ value: '192.168.18.0', note: null }) // no prefix: kept as typed, reported by rangeProblem
    expect(normalizeRange('192.168.18.5')).toEqual({ value: '192.168.18.5', note: null })
    expect(normalizeRange('192.168.18.5/24')).toEqual({ value: '192.168.18.0/24', note: 'network' })
    expect(normalizeRange('  10.0.0.0/8 ')).toEqual({ value: '10.0.0.0/8', note: null })
    expect(normalizeRange('abc')).toEqual({ value: 'abc', note: null })
    expect(normalizeRange('10.0.5.0/99')).toEqual({ value: '10.0.5.0/99', note: null })
  })

  it('rangeProblem: no prefix, format, host bits, not private, overlap, or fine', () => {
    expect(rangeProblem('abc', [])).toBe('format')
    expect(rangeProblem('192.168.18.0', [])).toBe('noPrefix')
    expect(rangeProblem('192.168.18.5/24', [])).toBe('hostBits')
    expect(rangeProblem('8.8.8.0/24', [])).toBe('notPrivate')
    expect(rangeProblem('10.0.0.0/7', [])).toBe('notPrivate')
    expect(rangeProblem('192.168.10.0/25', ['192.168.10.0/24', '192.168.10.0/25'])).toBe('overlap')
    expect(rangeProblem('192.168.10.0/24', ['192.168.10.0/24'])).toBeNull()
    expect(rangeProblem('172.16.0.0/12', [])).toBeNull()
  })
})

describe('inventory: scope and sensors (S-INV-1, admin)', () => {
  it('the page answers in its first line, has the sections, and no a11y violations', async () => {
    renderApp('/devices/setup')
    expect(await screen.findByRole('heading', { level: 1, name: '2 network ranges to watch' }, T)).toBeInTheDocument()
    for (const h of ['LAN ranges', 'Active scanning', 'Device types scanned only once', 'Sensor on this box', 'Agents on servers']) {
      expect(await screen.findByRole('heading', { level: 2, name: h }, T)).toBeInTheDocument()
    }
    expect(screen.getByText(/No exploitation, no denial of service/)).toBeInTheDocument()
    expect((await screen.findAllByText(/Agent intake is off/, undefined, T)).length).toBeGreaterThan(0) // agent-intake is off by default
    await expectNoA11yViolations()
  })

  it('scope confirmation is a single commitment checkbox plus an "as is" line; no consent document', async () => {
    renderApp('/devices/setup')
    const box = await screen.findByRole('checkbox', { name: 'I confirm these network ranges belong to my company and I am allowed to scan them.' }, T)
    expect(box).toBeChecked() // sample data: already confirmed
    expect(screen.getAllByRole('checkbox', { name: /I confirm/ })).toHaveLength(1)
    expect(screen.getByText('Vedette is provided as is. Its author is not responsible for how you use it, including scanning.')).toBeInTheDocument()
    expect(screen.queryByText(/consent/i)).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /consent/i })).not.toBeInTheDocument()
  })

  it('the operator and viewer roles are refused clearly', async () => {
    renderApp('/devices/setup', { role: 'operator' })
    expect(await screen.findByText('You do not have access to this page', undefined, T)).toBeInTheDocument()
    expect(screen.getByText(/The Admin role is needed/)).toBeInTheDocument()
    sessionStore.set({ userId: 'u-op' })
    expect((await call('GET', '/settings')).status).toBe(403)
    expect((await call('GET', '/sensors')).status).toBe(403)
    expect((await call('GET', '/agents')).status).toBe(403)
  })

  it('adding a range: a format error shows in the browser; changing ranges needs the commitment again before saving', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const input = await screen.findByLabelText('Add a network range', undefined, T)
    await user.type(input, '10.0.5.0/99')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText(/is not a valid range/, undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '10.0.5.0/24')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(screen.getByRole('button', { name: 'Remove range 10.0.5.0/24' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect(await screen.findByRole('alert', undefined, T)).toHaveTextContent('Tick the confirmation')
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
    const s = (await call('GET', '/settings')).json!
    expect(s.lan_ranges).toContain('10.0.5.0/24')
    expect(s.scope_confirmed_by).toBe('admin@acme.example')
  })

  it('Add range with the box empty says so under the box', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByLabelText('Add a network range', undefined, T)
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText(/Type a range first/, undefined, T)).toBeInTheDocument()
  })

  it('a bare address is rejected with a clear message, never turned into /24; with the prefix it is added and saved as typed', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const input = await screen.findByLabelText('Add a network range', undefined, T)
    await user.type(input, '192.168.18.0')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText('"192.168.18.0" has no prefix length. Add it so Vedette scans the right size of network, for example 192.168.18.0/24 or 192.168.18.0/25.', undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Remove range 192\.168\.18\.0/ })).not.toBeInTheDocument()
    await user.type(input, '/25')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(screen.getByRole('button', { name: 'Remove range 192.168.18.0/25' })).toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
    expect((await call('GET', '/settings')).json!.lan_ranges).toContain('192.168.18.0/25')
  })

  it('host bits are cut with a visible note and the prefix the user typed is kept', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const input = await screen.findByLabelText('Add a network range', undefined, T)
    await user.type(input, '192.168.30.77/23')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(screen.getByRole('button', { name: 'Remove range 192.168.30.0/23' })).toBeInTheDocument()
    expect(screen.getByText('192.168.30.77/23 was added as 192.168.30.0/23, the first address of its range.')).toBeInTheDocument()
  })

  it('rejects a duplicate, an overlapping range, and a public range in the editor', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const input = await screen.findByLabelText('Add a network range', undefined, T)
    await user.type(input, '192.168.10.0/24')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText('192.168.10.0/24 is already in the list.', undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '192.168.10.0/25')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText(/overlaps 192\.168\.10\.0\/24/, undefined, T)).toBeInTheDocument()
    await user.clear(input)
    await user.type(input, '8.8.8.0/24')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(await screen.findByText(/is not an internal range/, undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Remove range 8.8.8.0/24' })).not.toBeInTheDocument()
  })

  it('every stored range has Edit and Remove; Edit moves it back to the input; Remove drops it', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('button', { name: 'Edit range 192.168.20.0/24' }, T)
    expect(screen.getByRole('button', { name: 'Edit range 192.168.10.0/24' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove range 192.168.10.0/24' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Edit range 192.168.20.0/24' }))
    const input = screen.getByLabelText('Add a network range')
    expect(input).toHaveValue('192.168.20.0/24')
    expect(screen.queryByRole('button', { name: 'Remove range 192.168.20.0/24' })).not.toBeInTheDocument() // taken out of the list while editing
    await user.clear(input)
    await user.type(input, '192.168.20.0/25')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    await user.click(screen.getByRole('button', { name: 'Remove range 192.168.10.0/24' }))
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
    expect((await call('GET', '/settings')).json!.lan_ranges).toEqual(['192.168.20.0/25'])
  })

  it('regression: a range stored without a prefix ("192.168.18.0") shows an error on its row and never blocks add, edit or remove', async () => {
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: ['192.168.18.0'], scope_confirmed_at: null, scope_confirmed_by: null }))
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const row = (await screen.findByRole('button', { name: 'Remove range 192.168.18.0' }, T)).closest('li')!
    expect(within(row).getByRole('alert')).toHaveTextContent('"192.168.18.0" has no prefix length')
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    expect(inventorySettingsStore.get().lan_ranges).toEqual(['192.168.18.0']) // kept as stored, not guessed
    // add another range: allowed
    await user.type(screen.getByLabelText('Add a network range'), '10.9.0.0/16')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    // edit the bad one: it moves to the input, the owner types the size, adds it back
    await user.click(screen.getByRole('button', { name: 'Edit range 192.168.18.0' }))
    const input = screen.getByLabelText('Add a network range')
    expect(input).toHaveValue('192.168.18.0')
    await user.type(input, '/24')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
    expect((await call('GET', '/settings')).json!.lan_ranges).toEqual(['10.9.0.0/16', '192.168.18.0/24'])
  })

  it('the scope confirmation sits right above Save and asks for a tick inline only when the ranges changed', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const input = await screen.findByLabelText('Add a network range', undefined, T)
    const confirm = screen.getByRole('checkbox', { name: /I confirm these network ranges/ })
    expect(confirm).toBeChecked() // sample scope was confirmed already
    expect(confirm.closest('#scope')).toContainElement(screen.getByRole('button', { name: 'Save changes' })) // same bar as the Save button
    await user.type(input, '192.168.60.0/24{Enter}') // Enter adds the range
    expect(screen.getByRole('button', { name: 'Remove range 192.168.60.0/24' })).toBeInTheDocument()
    expect(confirm).not.toBeChecked()
    expect(screen.getByText('You added or changed ranges. Tick to confirm before saving.')).toBeInTheDocument()
    await user.click(confirm)
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
  })

  it('a stored bare range can simply be removed', async () => {
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: ['192.168.18.0', '192.168.20.0/24'] }))
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await user.click(await screen.findByRole('button', { name: 'Remove range 192.168.18.0' }, T))
    expect(screen.getByRole('button', { name: 'Save changes' })).not.toBeDisabled()
  })

  it('PUT rejects a bare address with a clear message, clears host bits and reports it in adjusted', async () => {
    asAdmin()
    const got = (await call('GET', '/settings')).json!
    const { adjusted: _a, ...base } = got
    const bare = await call('PUT', '/settings', { ...base, lan_ranges: ['192.168.18.0'], scope_confirmed: true })
    expect(bare.status).toBe(400)
    expect(bare.json!.error.code).toBe('no_prefix')
    expect(bare.json!.error.message).toBe('"192.168.18.0" has no prefix length. Add it so Vedette scans the right size of network, for example 192.168.18.0/24 or 192.168.18.0/25.')
    const put2 = await call('PUT', '/settings', { ...base, lan_ranges: ['192.168.18.5/24', '192.168.20.0/24'], scope_confirmed: true })
    expect(put2.status).toBe(200)
    expect(put2.json!.lan_ranges).toEqual(['192.168.18.0/24', '192.168.20.0/24'])
    expect(put2.json!.adjusted).toEqual([{ from: '192.168.18.5/24', to: '192.168.18.0/24' }])
    const put3 = await call('PUT', '/settings', { ...base, lan_ranges: ['192.168.18.0/24'], scope_confirmed: true })
    expect(put3.json!.adjusted).toEqual([]) // already normal: nothing adjusted
  })

  it('a stored invalid range shows an error on its own row, blocks Save, and does not block removing or adding others', async () => {
    inventorySettingsStore.update((s) => ({ ...s, lan_ranges: ['192.168.10.0/24', '8.8.8.0/24'] }))
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const bad = (await screen.findByRole('button', { name: 'Remove range 8.8.8.0/24' }, T)).closest('li')!
    expect(within(bad).getByRole('alert')).toHaveTextContent('8.8.8.0/24 is not an internal range')
    const good = screen.getByRole('button', { name: 'Remove range 192.168.10.0/24' }).closest('li')!
    expect(within(good).queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByText('Fix or remove the 1 range marked in red to save.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled()
    // other ranges can still be added
    await user.type(screen.getByLabelText('Add a network range'), '10.1.0.0/16')
    await user.click(screen.getByRole('button', { name: 'Add range' }))
    expect(screen.getByRole('button', { name: 'Remove range 10.1.0.0/16' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeDisabled() // still invalid
    // removing the bad one unblocks Save
    await user.click(screen.getByRole('button', { name: 'Remove range 8.8.8.0/24' }))
    expect(screen.queryByText(/marked in red/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    expect(screen.getByRole('button', { name: 'Save changes' })).toBeEnabled()
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await scopeSaved()
    expect((await call('GET', '/settings')).json!.lan_ranges).toEqual(['192.168.10.0/24', '10.1.0.0/16'])
  })

  it('the server rejects public ranges, bad hours, bad speed, bad exclusions and more', async () => {
    asAdmin()
    const base = (await call('GET', '/settings')).json!
    const put = async (patch: Record<string, unknown>) => (await call('PUT', '/settings', { ...base, scope_confirmed: true, ...patch })).json?.error?.code
    expect(await put({ lan_ranges: ['8.8.8.0/24'] })).toBe('public_range')
    expect(await put({ lan_ranges: ['10.0.0.0/7'] })).toBe('public_range')
    expect(await put({ lan_ranges: ['8.8.8.8'] })).toBe('no_prefix') // a bare address is never guessed
    expect(await put({ lan_ranges: ['abc'] })).toBe('bad_cidr')
    expect(await put({ lan_ranges: ['10.0.0.0/24', '10.0.0.0/25'] })).toBe('overlap_range')
    expect(await put({ lan_ranges: Array.from({ length: 17 }, (_, i) => `10.${i}.0.0/24`) })).toBe('too_many_ranges')
    expect(await put({ lan_ranges: 'not-a-list' })).toBe('bad_ranges')
    expect(await put({ active: { ...base.active, from: '25:00' } })).toBe('bad_time')
    expect(await put({ active: { ...base.active, from: '23:00', to: '23:00' } })).toBe('bad_window')
    expect(await put({ active: { ...base.active, rate: 5000 } })).toBe('bad_rate')
    expect(await put({ active: { ...base.active, days: [] } })).toBe('no_days')
    expect(await put({ active: { ...base.active, exclusions: ['not-an-ip'] } })).toBe('bad_exclusion')
    expect(await put({ lan_ranges: [] })).toBe('no_ranges')
    expect(await put({ scope_confirmed: false })).toBe('scope_not_confirmed')
    expect(await put({ fragile_kinds: ['airplane'] })).toBe('bad_kinds')
    expect(await put({ active: { ...base.active, enabled: false }, lan_ranges: [], scope_confirmed: false })).toBeUndefined() // scanning off: no ranges, no confirmation needed
  })

  it('changing fragile types applies to devices that were not changed individually', async () => {
    asAdmin()
    const base = (await call('GET', '/settings')).json!
    await call('PATCH', '/devices/a-prn02', { fragile: true }) // set individually: kept
    const r = await call('PUT', '/settings', { ...base, scope_confirmed: true, fragile_kinds: ['camera'] })
    expect(r.status).toBe(200)
    expect(find('a-prn01').fragile).toBe(false)
    expect(find('a-prn02').fragile).toBe(true)
    expect(find('a-cam01').fragile).toBe(true)
  })

  it('SPAN settings explain what is read and never mention installing Zeek or Suricata', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findAllByRole('button', { name: 'Configure sensor vedette-hq' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: 'Configure sensor vedette-hq' })[0]!, () => screen.getByRole('dialog'))
    const dlg = screen.getByRole('dialog')
    expect(within(dlg).getByText(/DNS queries, TLS server names, HTTP hosts and connection metadata/)).toHaveTextContent('It does not store packet contents.')
    expect(dlg.textContent).not.toMatch(/zeek|suricata/i)
  })

  it('device detail: fragile device shows first scan date and a regular-scan override that saves', async () => {
    asAdmin()
    const r = (await call('GET', '/devices')).json!.items as { id: string; fragile: boolean; origin: string; first_scan_at: string | null; regular_scan: string }[]
    const f = r.find((x) => x.fragile && x.origin === 'discovered')!
    expect(f.first_scan_at).toBeTruthy()
    expect(f.regular_scan).toBe('follow')
    expect((await call('PATCH', `/devices/${f.id}`, { regular_scan: 'sometimes' })).json?.error.code).toBe('bad_regular_scan')
    expect((await call('PATCH', `/devices/${f.id}`, { regular_scan: 'never' })).status).toBe(200)
    expect((await call('GET', `/devices/${f.id}`)).json!.asset.regular_scan).toBe('never')
  })

  it('the sensor dialog shows the SPAN status and links to Box network; it has no SPAN switch', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findAllByRole('button', { name: 'Configure sensor vedette-hq' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: 'Configure sensor vedette-hq' })[0]!, () => screen.getByRole('dialog'))
    const dlg = screen.getByRole('dialog')
    expect(await within(dlg).findByText('Receiving', undefined, T)).toBeInTheDocument()
    expect(within(dlg).getByText('eth1')).toBeInTheDocument()
    expect(within(dlg).queryByRole('switch')).not.toBeInTheDocument()
    expect(within(dlg).getByRole('link', { name: 'Configure SPAN in Settings → Box network' })).toHaveAttribute('href', '/settings/network')
  })

  it('single-box only: one local sensor, no kind/site/enrollment fields, no "other site" button, no remote-sensor endpoints', async () => {
    asAdmin()
    const list = (await call('GET', '/sensors')).json!.sensors as Record<string, unknown>[]
    expect(list).toHaveLength(1)
    expect(list[0]).toMatchObject({ id: 'sn-local', name: 'vedette-hq', status: 'online' })
    for (const k of ['kind', 'site', 'enrollment', 'waiting']) expect(list[0]).not.toHaveProperty(k)
    expect(JSON.stringify(list)).not.toMatch(/VED-[A-Z0-9]{4}/)

    renderApp('/devices/setup')
    await screen.findAllByRole('button', { name: 'Configure sensor vedette-hq' }, T)
    expect(screen.queryByRole('button', { name: /another site/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /Revoke sensor/i })).not.toBeInTheDocument()
    expect(screen.queryByText(/Waiting to enrol/i)).not.toBeInTheDocument()
  })

  it('the sensor row follows Settings → Box network: SPAN off means the management port, no verdict traffic', async () => {
    asAdmin()
    const sensor = async () => (await call('GET', '/sensors')).json!.sensors.find((x: { id: string }) => x.id === 'sn-local')
    expect(await sensor()).toMatchObject({ interface: 'eth1', span: true, interfaces: ['eth0', 'eth1', 'eth2'], span_status: { verdict: 'ok' } })
    const net = (await (await fetch(`${location.origin}/api/v1/core/network`)).json()) as { span: Record<string, unknown> }
    const r = await fetch(`${location.origin}/api/v1/core/network/span`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...net.span, enabled: false }) })
    expect(r.status).toBe(200)
    expect(await sensor()).toMatchObject({ interface: 'eth0', span: false, span_status: { verdict: 'off' } })
  })

  it('Active sensor module off: the active scanning part says why it is missing', async () => {
    enableModule('sensor-active', false)
    renderApp('/devices/setup')
    expect(await screen.findByText('Active sensor module is off', undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('switch', { name: 'Turn on active scanning' })).not.toBeInTheDocument()
  })

  it('customises the scan window, exclusions and fragile types, then saves', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const from = await screen.findByLabelText('From', undefined, T)
    await user.clear(from)
    await user.type(from, '22:30')
    await user.click(screen.getByRole('checkbox', { name: 'Sunday' }))
    await user.selectOptions(screen.getByRole('combobox', { name: 'Scan speed' }), '10')
    await user.type(screen.getByLabelText('Exclude from scanning'), '192.168.10.10')
    await user.click(screen.getByRole('button', { name: 'Add exclusion' }))
    await user.click(screen.getByRole('checkbox', { name: 'Switch' }))
    await user.click(screen.getByRole('switch', { name: 'Allow regular scans, NAS' }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    await waitFor(async () => expect((await call('GET', '/settings')).json!.active.from).toBe('22:30'), T)
    const s = (await call('GET', '/settings')).json!
    expect(s.active).toMatchObject({ from: '22:30', rate: 10, exclusions: ['192.168.10.10'] })
    expect(s.active.days).not.toContain(7)
    expect(s.fragile_kinds).toContain('switch')
    expect(s.regular_scan_kinds).toEqual(['nas'])
    expect(auditStore.get().some((e) => e.action === 'inventory.settings')).toBe(true)
  })

  // KNOWN PRODUCT BUG (reported): NetworkForm is keyed by the settings (SetupPage.tsx), the mutation's onSuccess in api.ts awaits the refetch,
  // so the form is unmounted before the per-call onSuccess runs and the "Scan scope saved." toast never shows. Remove `.fails` once fixed.
  it('saving the scope shows the "Scan scope saved." toast', async () => {
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await user.type(await screen.findByLabelText('Add a network range', undefined, T), '192.168.61.0/24{Enter}')
    await user.click(screen.getByRole('checkbox', { name: /I confirm these network ranges/ }))
    await user.click(screen.getByRole('button', { name: 'Save changes' }))
    expect((await screen.findAllByText('Scan scope saved.', undefined, { timeout: 3000 })).length).toBeGreaterThan(0)
  })

  it('a settings API error shows the error state', async () => {
    server.use(http.get('*/api/v1/inventory/settings', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the scan settings.' } }, { status: 500 })))
    renderApp('/devices/setup')
    expect(await screen.findByText('Could not read the scan settings.', undefined, T)).toBeInTheDocument()
  })
})

const BOX = 'https://192.168.10.250:8443' // sample mode: box address (boxInfo)
const OSQ = 'osquery on SRV-AD and SRV-FILE' // seeded enrollment token
async function raw(method: string, path: string, headers: Record<string, string> = {}, body?: unknown) {
  const res = await fetch(`${location.origin}/api/v1${path}`, { method, headers: { 'Content-Type': 'application/json', ...headers }, body: body === undefined ? undefined : JSON.stringify(body) })
  const text = await res.text()
  let json: unknown = null
  try { json = JSON.parse(text) } catch { /* not JSON */ }
  return { status: res.status, text, json: json as Record<string, any> | null } // eslint-disable-line @typescript-eslint/no-explicit-any
}
async function newToken(body: Record<string, unknown> = { name: 'osquery test' }) {
  asAdmin()
  const r = await call('POST', '/agents/tokens', body)
  expect(r.status).toBe(201)
  return { secret: r.json!.secret as string, token: r.json!.token as Record<string, any> } // eslint-disable-line @typescript-eslint/no-explicit-any
}
/** Pretend `ms` milliseconds have passed (the mock decides "expired" with Date.now()). */
const fastForward = (ms: number) => { const real = Date.now(); return vi.spyOn(Date, 'now').mockImplementation(() => real + ms) }

describe('inventory: agents (S-INV-4)', () => {
  it('the section has an osquery table and a Wazuh card; the seeded token is listed and masked', async () => {
    enableModule('agent-intake', true)
    renderApp('/devices/setup')
    const table = await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    expect(within(table).getByText(OSQ)).toBeInTheDocument()
    expect(within(table).getByText('••••k3Pq')).toBeInTheDocument()
    expect(screen.getByText('Use osquery on your Linux and Windows servers. Already run Wazuh? Connect its API instead.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Connect Wazuh' })).toBeInTheDocument()
    expect(screen.queryByText(/Trivy/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/macOS/i)).not.toBeInTheDocument()
  })

  it('creates a token: name + lifetime, token and install command shown once; the API never returns the full token again', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Create agent token' }), () => screen.getByRole('dialog'))
    const form = await screen.findByRole('dialog', undefined, T)
    expect(within(form).queryByRole('button', { name: 'Wazuh' })).not.toBeInTheDocument() // no agent type choice any more
    const life = within(form).getByRole('combobox', { name: 'Token lifetime' }) as HTMLSelectElement
    expect(life.value).toBe('7') // default 7 days
    expect([...life.options].map((o) => o.textContent)).toEqual(['1 day', '7 days (recommended)', '30 days', '90 days', 'No expiry (not recommended)'])
    await user.type(within(form).getByLabelText('Token name'), 'osquery accounting PC')
    await user.selectOptions(life, '30')
    await user.click(within(form).getByRole('button', { name: 'Create token' }))
    const dialog = await screen.findByRole('dialog', { name: 'Token for osquery accounting PC' }, T)
    const secret = (await within(dialog).findByText(/^vdt_osquery_[a-z0-9]{32}$/, undefined, T)).textContent!
    expect(within(dialog).getByText(/The token is shown once/)).toBeInTheDocument()
    // Linux is the default platform: one line, hash check, token as an argument, expected SHA-256 shown
    const sha = (await call('GET', '/agents')).json!.install.linux.sha256 as string
    expect(sha).toMatch(/^[0-9a-f]{64}$/)
    expect(within(dialog).getByRole('button', { name: 'Linux' })).toHaveAttribute('aria-pressed', 'true')
    expect(within(dialog).getByText(new RegExp(`sudo sh /tmp/vedette-osquery\\.sh --token ${secret}$`))).toBeInTheDocument()
    expect(within(dialog).getByText('Expected SHA-256 of the script:').parentElement).toHaveTextContent(sha)
    expect(within(dialog).getByText('What this script does')).toBeInTheDocument()
    expect(within(dialog).getByText('Advanced: manual setup')).toBeInTheDocument()
    expect(within(dialog).getByText('Remove osquery from the server again')).toBeInTheDocument()
    // D-404: direct downloads from this origin, one row per Linux package, with what it is for, its size and its SHA-256
    const pkgs = (await call('GET', '/agents')).json!.install.packages as OsqueryPackage[]
    const downloads = () => within(within(dialog).getByRole('table', { name: 'osquery packages this box serves' })).getAllByRole('link')
    expect(downloads().map((a) => [a.getAttribute('href'), a.getAttribute('download')])).toEqual(
      pkgs.filter((p) => p.platform === 'linux').map((p) => [`/api/v1/install/osquery/${p.file}`, p.file]))
    const amd = within(dialog).getByRole('link', { name: `Download osquery_${OSQUERY_VERSION}-1.linux_amd64.deb` }).closest('tr')!
    expect(amd).toHaveTextContent('Debian, Ubuntu · x86_64')
    expect(amd).toHaveTextContent('30.6 MB')
    expect(amd).toHaveTextContent(pkgs[0]!.sha256)
    expect(within(dialog).queryByText(/osquery\.io|choco/)).not.toBeInTheDocument()
    expect(within(dialog).queryByText(/has no copy of the osquery packages/)).not.toBeInTheDocument()
    await user.click(within(dialog).getByRole('button', { name: 'Windows Server' }))
    expect(downloads().map((a) => a.getAttribute('download'))).toEqual([`osquery-${OSQUERY_VERSION}.msi`])
    expect(within(dialog).getByRole('link', { name: `Download osquery-${OSQUERY_VERSION}.msi` }).closest('tr')).toHaveTextContent('Windows Server · x64')
    expect(within(dialog).getByText(new RegExp(`-Token '${secret}'`))).toBeInTheDocument()
    expect(within(dialog).getAllByText(/Get-FileHash \$f -Algorithm SHA256/).length).toBeGreaterThan(0)
    expect(within(dialog).getByText(/curl\.exe -k for that one download only/)).toBeInTheDocument()
    await expectNoA11yViolations()
    await user.click(within(dialog).getByRole('button', { name: 'I copied the token' }))
    const listed = await call('GET', '/agents')
    expect(listed.text).not.toContain(secret)
    const t = (listed.json!.tokens as Record<string, any>[]).find((x) => x.name === 'osquery accounting PC')! // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(t).toMatchObject({ kind: 'osquery', last4: secret.slice(-4), hosts: 0, last_received: null })
    expect(new Date(t.expires_at).getTime() - Date.now()).toBeGreaterThan(29 * 864e5)
    expect((await screen.findAllByText(`••••${secret.slice(-4)}`, undefined, T)).length).toBeGreaterThan(0)
  })

  it('the snippets use the box address (https, never http or localhost) and the dialog is English', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    for (const platform of ['Linux', 'Windows Server']) {
      await user.click(within(dialog).getByRole('button', { name: platform }))
      const text = dialog.textContent ?? ''
      expect(text).toContain(`${BOX}/api/v1/install/osquery.${platform === 'Linux' ? 'sh' : 'ps1'}`)
      expect(text, platform).not.toMatch(/localhost|127\.0\.0\.1/)
      expect(text.replace(/https:\/\//g, ''), `${platform}: only https`).not.toMatch(/http:\/\//)
      expect(text).toMatch(/--cacert|--tls_server_certs/)
    }
  })

  it('a box without the osquery packages says so, offers no download and points nowhere else (D-404)', async () => {
    enableModule('agent-intake', true)
    asAdmin()
    const real = (await call('GET', '/agents')).json!
    server.use(http.get('*/api/v1/inventory/agents', () => HttpResponse.json({ ...real, install: { ...real.install, packages: [] } })))
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    for (const platform of ['Linux', 'Windows Server']) {
      await user.click(within(dialog).getByRole('button', { name: platform }))
      expect(within(dialog).getByText(/This box has no copy of the osquery packages/)).toBeInTheDocument()
      expect(within(dialog).queryByRole('table', { name: 'osquery packages this box serves' })).not.toBeInTheDocument()
      expect(dialog.textContent).not.toMatch(/osquery\.io|choco/)
    }
  })

  it('viewing the setup again uses <TOKEN> instead of exposing the token; the token can be revoked', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: `Set up ${OSQ}` }, T)
    expect(within(dialog).getByText(/sudo sh \/tmp\/vedette-osquery\.sh --token <TOKEN>$/)).toBeInTheDocument()
    expect(dialog.textContent).not.toMatch(/vdt_osquery_[a-z0-9]{32}/)
    await user.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]!)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Revoke token ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    await user.click(await screen.findByRole('button', { name: 'Revoke' }, T))
    expect(await screen.findByText('No enrollment tokens yet', undefined, T)).toBeInTheDocument()
  })

  it('token API: only osquery uses a token; name and lifetime are validated; default 7 days, 0 means never', async () => {
    asAdmin()
    expect((await call('POST', '/agents/tokens', { name: 'x', kind: 'wazuh' })).json?.error.code).toBe('bad_kind') // Wazuh is a connection, not a token
    expect((await call('POST', '/agents/tokens', { name: 'x', kind: 'trivy' })).json?.error.code).toBe('bad_kind')
    expect((await call('POST', '/agents/tokens', { name: '', kind: 'osquery' })).json?.error.code).toBe('bad_name')
    expect((await call('POST', '/agents/tokens', { name: '<x>' })).json?.error.code).toBe('bad_name')
    for (const d of [-1, 366, 1.5, 'x']) expect((await call('POST', '/agents/tokens', { name: 'x', expires_in_days: d })).json?.error.code, String(d)).toBe('bad_expiry')
    const def = (await newToken({ name: 'default', kind: 'osquery' })).token
    expect(new Date(def.expires_at).getTime() - Date.now()).toBeGreaterThan(6.9 * 864e5)
    expect(new Date(def.expires_at).getTime() - Date.now()).toBeLessThan(7.1 * 864e5)
    expect((await newToken({ name: 'forever', expires_in_days: 0 })).token.expires_at).toBeNull()
    sessionStore.set({ userId: 'u-op' })
    expect((await call('POST', '/agents/tokens', { name: 'x' })).status).toBe(403)
    expect((await call('GET', '/agents')).status).toBe(403)
  })

  it('the box serves both install scripts without login; the SHA-256 in the API equals the SHA-256 of the served text', async () => {
    asAdmin()
    const data = (await call('GET', '/agents')).json!
    expect(data.server_url).toBe(BOX)
    sessionStore.set({ userId: null }) // public endpoints: no session needed
    for (const [ext, key] of [['sh', 'linux'], ['ps1', 'windows']] as const) {
      const r = await raw('GET', `/install/osquery.${ext}`)
      expect(r.status).toBe(200)
      expect(await sha256Hex(r.text)).toBe(data.install[key].sha256)
      expect(r.text).toBe(data.install[key].script)
      expect(data.install[key].url).toBe(`${BOX}/api/v1/install/osquery.${ext}`)
      expect(r.text).not.toContain('@@') // placeholders are filled
      expect(r.text).toContain(BOX)
      expect(r.text).toContain('BEGIN CERTIFICATE') // the box CA is embedded, so later downloads verify it
      expect(r.text).not.toMatch(/trivy|macos|vdt_osquery_/i)
      for (const line of ['--config_plugin=tls', '--logger_plugin=tls', 'enroll_secret_path', 'tls_server_certs', 'tls_hostname', '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--logger_tls_endpoint=/api/v1/intake/osquery/log']) expect(r.text, `${ext}: ${line}`).toContain(line)
    }
    const sh = (await raw('GET', '/install/osquery.sh')).text
    expect(sh).toContain('--token')
    expect(sh).toContain('--uninstall')
    expect(sh).toContain('--cacert') // after the CA is saved there is no more -k
    expect((await raw('GET', '/install/osquery.ps1')).text).toContain('-Uninstall')
  })

  // D-399 (2), walk 4: a box opened as localhost only knows no address a server can reach; a command pinned to <VEDETTE_BOX_IP> would pass its
  // hash check and then fail, so the box serves no script and the dialog says how to give the box an address instead of showing one.
  it('no reachable box address: no script is served and the dialog explains instead of showing a command that cannot work', async () => {
    const { setDataMode } = await import('@/mocks/db')
    usersStore.get()
    setDataMode('clean') // clean install with no LAN range: the mock box knows no address
    try {
      enableModule('agent-intake', true)
      asAdmin()
      expect((await call('GET', '/agents')).json!.server_url).toBe('https://<VEDETTE_BOX_IP>:8443')
      for (const ext of ['sh', 'ps1']) {
        const r = await raw('GET', `/install/osquery.${ext}`)
        expect(r.status, ext).toBe(404)
        expect(r.json!.error.code).toBe('no_box_address')
        expect(r.text).not.toContain('BOX=')
      }
      const user = userEvent.setup()
      renderApp('/devices/setup')
      await clickUntil(user, () => screen.getByRole('button', { name: 'Create agent token' }), () => screen.getByRole('dialog'))
      const form = await screen.findByRole('dialog', undefined, T)
      await user.type(within(form).getByLabelText('Token name'), 'osquery lab')
      await user.click(within(form).getByRole('button', { name: 'Create token' }))
      const dialog = await screen.findByRole('dialog', { name: 'Token for osquery lab' }, T)
      expect(await within(dialog).findByText('Servers cannot reach this box at the address you opened it with', undefined, T)).toBeInTheDocument()
      expect(within(dialog).getByText(/Open Vedette at the box's network address/)).toBeInTheDocument()
      expect(dialog.textContent).not.toMatch(/VEDETTE_BOX_IP|curl -fsSLk|Get-FileHash/)
      expect(within(dialog).getByText(/^vdt_osquery_[a-z0-9]{32}$/)).toBeInTheDocument() // the token itself is shown, and stays valid
      await expectNoA11yViolations()
    } finally {
      setDataMode('sample')
    }
  })

  it('the token row counts enrolled machines and the Linux command names both architectures (walk 4)', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    const table = await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    expect(within(table).getByRole('columnheader', { name: /Machines enrolled/ })).toBeInTheDocument()
    expect(within(table).queryByText(/Machines reporting/)).toBeNull()
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByText(/Debian, Ubuntu, RHEL, Rocky, AlmaLinux; x86_64 or arm64/)).toBeInTheDocument()
    const sums = await (await fetch(`${location.origin}/api/v1/install/osquery/SHA256SUMS`)).text()
    for (const n of ['linux_amd64.deb', 'linux.x86_64.rpm', 'linux_arm64.deb', 'linux.aarch64.rpm', '.msi']) expect(sums).toContain(n)
  })

  it('status endpoint: token only in the Authorization header; invalid, missing, URL-borne and expired tokens are refused', async () => {
    const { secret } = await newToken()
    sessionStore.set({ userId: null })
    const ok = await raw('POST', '/intake/osquery/status', { Authorization: `Bearer ${secret}` })
    expect(ok.status).toBe(200)
    expect(ok.json).toEqual({ enrolled: false, hosts: 0 })
    expect((await raw('POST', '/intake/osquery/status')).json?.error.code).toBe('invalid_token')
    expect((await raw('POST', '/intake/osquery/status', { Authorization: 'Bearer vdt_osquery_' + 'a'.repeat(32) })).status).toBe(403)
    expect((await raw('POST', '/intake/osquery/status', { Authorization: 'Bearer nope' })).status).toBe(403)
    expect((await raw('POST', `/intake/osquery/status?token=${secret}`)).json?.error.code).toBe('invalid_token') // a URL token is not accepted
    const spy = fastForward(8 * 864e5)
    try { expect((await raw('POST', '/intake/osquery/status', { Authorization: `Bearer ${secret}` })).json?.error.code).toBe('token_expired') } finally { spy.mockRestore() }
  })

  it('osquery TLS API (D-169): enroll gives a node key for a valid token only, config carries the schedule, every credential failure is 200 + node_invalid', async () => {
    const { secret } = await newToken()
    sessionStore.set({ userId: null })
    const post = (path: string, b: unknown) => fetch(`${location.origin}/api/v1${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
    const en = await (await post('/intake/osquery/enroll', { enroll_secret: secret, host_identifier: 'srv1', host_details: { os_version: { name: 'Ubuntu' } } })).json()
    expect(en).toMatchObject({ node_invalid: false, node_key: expect.stringMatching(/^mock-node-/) })
    for (const bad of [{ enroll_secret: 'nope', host_identifier: 'x' }, { host_identifier: 'x' }, { enroll_secret: 'vdt_osquery_' + 'a'.repeat(32), host_identifier: 'x' }]) {
      const r = await post('/intake/osquery/enroll', bad)
      expect(r.status).toBe(200)
      expect(await r.json()).toEqual({ node_invalid: true })
    }
    const cfg = await (await post('/intake/osquery/config', { node_key: en.node_key })).json()
    expect(Object.keys(cfg.schedule)).toContain('interfaces')
    expect(await (await post('/intake/osquery/config', { node_key: 'bad' })).json()).toEqual({ node_invalid: true })
    expect(await (await post('/intake/osquery/log', { node_key: en.node_key, log_type: 'result', data: [] })).json()).toEqual({ node_invalid: false })
    expect(await (await post('/intake/osquery/log', { node_key: 'bad', log_type: 'status', data: [] })).json()).toEqual({ node_invalid: true })
    expect(await (await fetch(`${location.origin}/api/v1/intake/ca.pem`)).text()).toContain('BEGIN CERTIFICATE')
    expect((await fetch(`${location.origin}/api/v1/install/osquery/SHA256SUMS`)).status).toBe(200)
    expect((await fetch(`${location.origin}/api/v1/install/osquery/..%2Fetc%2Fpasswd`)).status).toBe(404)
  })

  it('sample data (preview build): updates up to 3 server/computer devices with agent software and an agent OS observation', async () => {
    const { token } = await newToken({ name: 'osquery sample' })
    const r = await call('POST', `/agents/tokens/${token.id}/sample-data`)
    expect(r.status).toBe(200)
    expect(r.json!.devices).toBeGreaterThan(0)
    expect(r.json!.devices).toBeLessThanOrEqual(3)
    expect(r.json!.software).toBeGreaterThan(0)
    const updated = assetsStore.get().filter((a) => a.id !== BOX_ID && a.software.some((s) => s.source === 'agent'))
    expect(updated).toHaveLength(r.json!.devices)
    for (const a of updated) {
      expect(a.approved && (a.kind === 'server' || a.kind === 'pc')).toBe(true)
      expect(a.software.find((s) => s.source === 'agent')).toMatchObject({ confidence: 0.95 })
      const obs = ((await call('GET', `/devices/${a.id}`)).json!.observations as { field: string; source: string }[])
      expect(obs.some((o) => o.field === 'os' && o.source === 'agent')).toBe(true)
    }
    const row = ((await call('GET', '/agents')).json!.tokens as Record<string, any>[]).find((x) => x.id === token.id)! // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(row.hosts).toBe(r.json!.devices)
    expect(row.last_received).not.toBeNull()
    expect((await raw('POST', '/intake/osquery/status', { Authorization: `Bearer ${(await newToken({ name: 'other' })).secret}` })).json).toMatchObject({ enrolled: false }) // other tokens untouched
  })

  it('sample data errors: expired token 403, unknown token 404, no matching device 409; sample data is audited as inventory.agent_enroll', async () => {
    const { token } = await newToken({ name: 'osquery sample' })
    expect((await call('POST', '/agents/tokens/tk-none/sample-data')).status).toBe(404)
    assetsStore.update((l) => l.filter((a) => a.kind !== 'server' && a.kind !== 'pc'))
    const none = await call('POST', `/agents/tokens/${token.id}/sample-data`)
    expect(none.status).toBe(409)
    expect(none.json!.error.code).toBe('no_devices')
    const spy = fastForward(8 * 864e5)
    try { expect((await call('POST', `/agents/tokens/${token.id}/sample-data`)).json?.error.code).toBe('token_expired') } finally { spy.mockRestore() }
    expect(auditStore.get().some((e) => e.action === 'inventory.agent_enroll')).toBe(false) // nothing happened, nothing audited
  })

  it('the Send sample data button on a token row pretends the machines reported in', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Send sample data for ${OSQ}` })[0]!, () => expect(assetsStore.get().some((a) => a.software.some((s) => s.source === 'agent'))).toBe(true))
    expect(await screen.findByText(/Sample data received: \d+ devices updated, \d+ software entries added from the agent\./, undefined, T)).toBeInTheDocument()
    expect(auditStore.get().some((e) => e.action === 'inventory.agent_enroll')).toBe(true)
  })

  it('Wazuh is a pull connection: Connect Wazuh opens read-only user steps and the connection form', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Connect Wazuh' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Connect Wazuh' }, T)
    for (const s of ['agent:read', 'syscollector:read', 'agent:id:*']) expect(within(dialog).getAllByText(new RegExp(s.replace('*', '\\*'))).length).toBeGreaterThan(0)
    expect(within(dialog).getByText('1. Create a read-only API user on the Wazuh manager')).toBeInTheDocument()
    for (const l of ['Wazuh server API address', 'API user', 'API password', 'Sync every']) expect(within(dialog).getByLabelText(l)).toBeInTheDocument()
    expect(within(dialog).getByLabelText('API user')).toHaveValue('vedette')
    expect(within(dialog).getByRole('button', { name: 'Test connection' })).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Save connection' })).toBeInTheDocument()
    expect([...(within(dialog).getByLabelText('Sync every') as HTMLSelectElement).options].map((o) => o.textContent)).toEqual(['5 minutes', '15 minutes', '1 hour', '6 hours', '24 hours'])
  })

  it('Wazuh form: refused password, unreachable host and a non-https address show clear errors; a good test shows the version', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Connect Wazuh' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Connect Wazuh' }, T)
    const url = within(dialog).getByLabelText('Wazuh server API address')
    const pass = within(dialog).getByLabelText('API password')
    await user.type(url, 'https://wazuh-manager:55000')
    await user.type(pass, 'wrong')
    await user.click(within(dialog).getByRole('button', { name: 'Test connection' }))
    expect(await within(dialog).findByRole('alert', undefined, T)).toHaveTextContent('Wazuh refused the user name or password')
    await user.clear(url)
    await user.type(url, 'https://wazuh-unreachable:55000')
    await user.click(within(dialog).getByRole('button', { name: 'Test connection' }))
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('Could not reach https://wazuh-unreachable:55000'), T)
    await user.clear(url)
    await user.type(url, 'http://wazuh-manager:55000')
    await user.click(within(dialog).getByRole('button', { name: 'Save connection' }))
    await waitFor(() => expect(within(dialog).getByRole('alert')).toHaveTextContent('starting with https://'), T)
    await user.clear(url)
    await user.type(url, 'https://wazuh-manager:55000')
    await user.clear(pass)
    await user.type(pass, 'S3cret-pass')
    await user.click(within(dialog).getByRole('button', { name: 'Test connection' }))
    expect(await within(dialog).findByText(/Connected to Wazuh 4\.9\.2\. This user can see \d+ agents\./, undefined, T)).toBeInTheDocument()
    expect((await call('GET', '/agents')).json!.wazuh).toBeNull() // testing does not save
  })

  it('Wazuh connect, sync with sample data, and disconnect from the UI; the password is never shown back', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Connect Wazuh' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Connect Wazuh' }, T)
    await user.type(within(dialog).getByLabelText('Wazuh server API address'), 'https://wazuh-manager:55000')
    await user.type(within(dialog).getByLabelText('API password'), 'S3cret-pass')
    await user.selectOptions(within(dialog).getByLabelText('Sync every'), '15')
    await user.click(within(dialog).getByRole('button', { name: 'Save connection' }))
    await waitFor(async () => expect(((await call('GET', '/agents')).json!.wazuh)).toMatchObject({ url: 'https://wazuh-manager:55000', username: 'vedette', password_last4: 'pass', interval_minutes: 15, status: 'never' }), T)
    const got = await call('GET', '/agents')
    expect(got.text).not.toContain('S3cret-pass')
    expect(got.json!.wazuh).not.toHaveProperty('password')
    expect(await screen.findByText('https://wazuh-manager:55000', undefined, T)).toBeInTheDocument()
    expect(screen.getByText(/vedette, ••••pass/)).toBeInTheDocument()
    expect(screen.getByText('Connected, waiting for the first sync')).toBeInTheDocument()
    const flow14 = async () => ((await (await fetch(`${location.origin}/api/v1/core/privacy`)).json()) as { flows: { id: number; state: string }[] }).flows.find((f) => f.id === 14)?.state
    expect(await flow14()).toBe('on') // Settings → Privacy flow 14 while a Wazuh server is saved (D-309)
    await user.click(screen.getByRole('button', { name: 'Send sample data' })) // the card's own button (token rows say "for <name>")
    await waitFor(async () => expect(((await call('GET', '/agents')).json!.wazuh).status).toBe('connected'), T)
    expect((await call('GET', '/agents')).json!.wazuh.agents).toBeGreaterThan(0)
    expect(await screen.findByText(/^Last sync .*\. \d+ agents, \d+ packages$/, undefined, T)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Disconnect' }))
    await user.click(within(await screen.findByRole('dialog', { name: 'Disconnect Wazuh?' }, T)).getByRole('button', { name: 'Disconnect' }))
    await waitFor(async () => expect((await call('GET', '/agents')).json!.wazuh).toBeNull(), T)
    expect(await screen.findByRole('button', { name: 'Connect Wazuh' }, T)).toBeInTheDocument()
    expect(await flow14()).toBe('off')
  })

  it('Wazuh API: validation, test does not store, password kept when left empty, only the last 4 returned, audited without the password', async () => {
    asAdmin()
    const good = { url: 'https://wazuh-manager:55000/', username: 'vedette', password: 'S3cret-pass', interval_minutes: 60 }
    const code = async (patch: Record<string, unknown>) => (await call('PUT', '/agents/wazuh', { ...good, ...patch })).json?.error?.code
    expect(await code({ url: 'http://wazuh-manager:55000' })).toBe('bad_url')
    expect(await code({ url: 'not a url' })).toBe('bad_url')
    expect(await code({ url: 'https://admin:pw@wazuh-manager:55000' })).toBe('bad_url') // no credentials in the address
    expect(await code({ username: 'bad name' })).toBe('bad_username')
    expect(await code({ username: '' })).toBe('bad_username')
    expect(await code({ password: '' })).toBe('password_required') // first time
    expect(await code({ interval_minutes: 7 })).toBe('bad_interval')
    for (const host of ['wazuh-unreachable', 'wazuh.invalid', 'down']) {
      const r = await call('PUT', '/agents/wazuh', { ...good, url: `https://${host}:55000` })
      expect([r.status, r.json?.error.code], host).toEqual([502, 'wazuh_unreachable'])
    }
    const refused = await call('PUT', '/agents/wazuh', { ...good, password: 'wrong' })
    expect([refused.status, refused.json?.error.code]).toEqual([422, 'wazuh_auth'])
    const t = await call('POST', '/agents/wazuh/test', good)
    expect(t.status).toBe(200)
    expect(t.json).toMatchObject({ ok: true, version: '4.9.2' })
    expect(t.json!.agents).toBeGreaterThanOrEqual(1)
    expect((await call('GET', '/agents')).json!.wazuh).toBeNull()
    expect((await call('POST', '/agents/wazuh/sample-data')).status).toBe(404) // not connected yet
    expect((await call('DELETE', '/agents/wazuh')).status).toBe(404)

    const saved = await call('PUT', '/agents/wazuh', good)
    expect(saved.status).toBe(200)
    expect(saved.json).toMatchObject({ url: 'https://wazuh-manager:55000', username: 'vedette', password_last4: 'pass', interval_minutes: 60, status: 'never', last_sync: null })
    expect(saved.text).not.toContain('S3cret-pass')
    const kept = await call('PUT', '/agents/wazuh', { ...good, password: undefined, interval_minutes: 5 }) // empty password keeps the saved one
    expect(kept.json).toMatchObject({ password_last4: 'pass', interval_minutes: 5 })
    const changed = await call('PUT', '/agents/wazuh', { ...good, password: 'another-9999' })
    expect(changed.json!.password_last4).toBe('9999')

    const sync = await call('POST', '/agents/wazuh/sample-data')
    expect(sync.status).toBe(200)
    const w = (await call('GET', '/agents')).json!.wazuh
    expect(w).toMatchObject({ status: 'connected', agents: sync.json!.devices })
    expect(w.last_sync).not.toBeNull()
    expect(w.packages).toBeGreaterThan(0)
    expect((await call('DELETE', '/agents/wazuh')).status).toBe(204)
    expect((await call('GET', '/agents')).json!.wazuh).toBeNull()

    const log = JSON.stringify(auditStore.get())
    for (const a of ['inventory.wazuh_connect', 'inventory.wazuh_sample_data', 'inventory.wazuh_disconnect']) expect(auditStore.get().map((e) => e.action)).toContain(a)
    expect(log).not.toMatch(/S3cret-pass|another-9999/)
    sessionStore.set({ userId: 'u-op' })
    expect((await call('PUT', '/agents/wazuh', good)).status).toBe(403)
    expect((await call('POST', '/agents/wazuh/test', good)).status).toBe(403)
  })

  it('setup text: key lines of the one-liners, the manual steps, the schedule and the Wazuh reader steps', async () => {
    enableModule('agent-intake', true)
    const sha = 'a'.repeat(64)
    const lin = linuxOneLiner(BOX, sha, 'vdt_osquery_x')
    expect(lin).toContain(`curl -fsSLk ${BOX}/api/v1/install/osquery.sh`) // -k exactly once, for the script itself
    expect(lin).toContain(`echo "${sha}  /tmp/vedette-osquery.sh" | sha256sum -c -`)
    expect(lin).toContain('sudo sh /tmp/vedette-osquery.sh --token vdt_osquery_x')
    expect(lin.match(/curl/g)).toHaveLength(1)
    expect(linuxOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).toMatch(/--uninstall$/)
    expect(linuxOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).not.toContain('vdt_osquery_x')
    const win = windowsOneLiner(BOX, sha, 'vdt_osquery_x')
    expect(win).toContain(`curl.exe -fsSLk ${BOX}/api/v1/install/osquery.ps1`)
    expect(win).toContain(`-ieq '${sha}'`)
    expect(win).toContain("-Token 'vdt_osquery_x'")
    expect(win).toContain("throw 'Checksum mismatch: do not run this file'")
    expect(windowsOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).toContain('-Uninstall')
    for (const s of [lin, win]) expect(s).not.toMatch(/http:\/\/|localhost/)

    asAdmin()
    const pkgs = (await call('GET', '/agents')).json!.install.packages as OsqueryPackage[]
    for (const platform of ['linux', 'windows'] as const) {
      const steps = osquerySteps(platform, BOX, '<TOKEN>', pkgs)
      const flags = steps.find((s) => s.key === 'flags')!.code
      for (const f of ['--config_plugin=tls', '--logger_plugin=tls', 'enroll_secret_path', 'tls_server_certs', `--tls_hostname=192.168.10.250:8443`, '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--logger_tls_endpoint=/api/v1/intake/osquery/log']) expect(flags, `${platform}: ${f}`).toContain(f)
      expect(flags).not.toContain('https://') // tls_hostname has the port and no scheme
      expect(steps.find((s) => s.key === 'secret')!.code).toContain('<TOKEN>')
      expect(steps.filter((s) => /-fsSk|-fsSLk/.test(s.code))).toHaveLength(1) // the certificate is fetched with -k once, to be checked by fingerprint
      expect(steps.find((s) => s.key === 'secret')!.code).toContain(platform === 'linux' ? 'openssl x509' : 'certutil -dump') // print the certificate so its fingerprint can be compared
    }
    expect(osquerySteps('linux', BOX, 't', pkgs).map((s) => s.key)).toEqual(['installDeb', 'installRpm', 'secret', 'flags', 'start'])
    expect(osquerySteps('windows', BOX, 't', pkgs).map((s) => s.key)).toEqual(['install', 'secret', 'flags', 'service'])
    // D-404: the box is the only source; each package is checked against the SHA-256 of this page before it is installed
    const all = [...osquerySteps('linux', BOX, 't', pkgs), ...osquerySteps('windows', BOX, 't', pkgs)].map((s) => s.code).join('\n')
    expect(all).not.toMatch(/osquery\.io|choco|yum-config-manager|apt-get/)
    for (const p of pkgs) expect(all).toContain(p.sha256)
    const deb = osquerySteps('linux', BOX, 't', pkgs).find((s) => s.key === 'installDeb')!.code
    expect(deb).toContain(`curl -fSLk ${BOX}/api/v1/install/osquery/$f -o $f && \\`)
    expect(deb).toContain(`grep " $f\\$" | sha256sum -c - && \\\nsudo dpkg -i $f`)
    expect(deb).toContain('linux_$(dpkg --print-architecture).deb')
    expect(osquerySteps('linux', BOX, 't', pkgs).find((s) => s.key === 'installRpm')!.code).toMatch(/linux\.\$\(uname -m\)\.rpm[\s\S]*sudo rpm -Uvh \$f$/)
    const msi = osquerySteps('windows', BOX, 't', pkgs).find((s) => s.key === 'install')!.code
    expect(msi).toContain(`curl.exe -fSLk ${BOX}/api/v1/install/osquery/osquery-${OSQUERY_VERSION}.msi`)
    expect(msi).toMatch(/-ieq '[0-9a-f]{64}'\) \{ Start-Process msiexec\.exe .*\} else \{ throw 'Checksum mismatch: do not install this file' \}$/)
    // no package on the box: no install step at all, never an outside source
    expect(osquerySteps('linux', BOX, 't', []).map((s) => s.key)).toEqual(['secret', 'flags', 'start'])
    expect(osquerySteps('windows', BOX, 't', []).map((s) => s.key)).toEqual(['secret', 'flags', 'service'])

    const sched = JSON.parse(OSQUERY_SCHEDULE).schedule as Record<string, { query: string; platform?: string }>
    expect(Object.keys(sched).sort()).toEqual(['deb_packages', 'interfaces', 'os_version', 'programs', 'rpm_packages', 'system_info']) // D-169 (7): identity query in, unused columns and patches out
    expect(JSON.stringify(sched)).not.toMatch(/cpu_brand|physical_memory|patches/)
    expect(sched.interfaces!.query).toContain('interface_details')
    for (const q of Object.values(sched)) expect(q.query).toMatch(/^SELECT /) // read-only queries
    expect(sched.programs!.platform).toBe('windows')
    expect(sched.deb_packages!.platform).toBe('linux')

    const wz = wazuhReaderSteps()
    expect(wz.map((s) => s.key)).toEqual(['login', 'policy', 'role', 'user', 'link'])
    expect(wz.find((s) => s.key === 'policy')!.code).toMatch(/agent:read.*syscollector:read|syscollector:read.*agent:read/)
    expect(wz.find((s) => s.key === 'policy')!.code).toContain('agent:id:*')
    expect(wz.map((s) => s.code).join('\n')).not.toMatch(/agent:(update|delete|restart|upgrade)|\*:\*/) // read-only
  })
})

describe('inventory: audit log (SYS-3)', () => {
  it('every write goes into the audit log, and no secret, password or full token is in it', async () => {
    asAdmin()
    await call('POST', '/devices', { catalog_id: 'synology-nas-dsm' })
    await call('POST', '/devices/a-prn03/approve')
    await call('POST', '/devices/a-unk01/suspicious', { suspicious: true })
    await call('PUT', '/notify-new', { enabled: false })
    const { secret, token } = await newToken({ name: 'audit token' })
    await call('POST', `/agents/tokens/${token.id}/sample-data`)
    await call('PUT', '/agents/wazuh', { url: 'https://wazuh-manager:55000', username: 'vedette', password: 'Audit-pass-1234', interval_minutes: 60 })
    await call('DELETE', '/agents/wazuh')
    await call('DELETE', `/agents/tokens/${token.id}`)
    const actions = auditStore.get().map((e) => e.action)
    for (const a of ['inventory.add_manual', 'inventory.approve', 'inventory.mark_suspicious', 'inventory.notify_new', 'inventory.agent_token_create', 'inventory.agent_enroll', 'inventory.wazuh_connect', 'inventory.wazuh_disconnect', 'inventory.agent_token_revoke']) expect(actions).toContain(a)
    const log = JSON.stringify(auditStore.get())
    expect(log).not.toContain(secret)
    expect(log).not.toMatch(/vdt_osquery_[a-z0-9]{32}|Audit-pass-1234|Bearer /)
  })
})

describe('inventory: English only', () => {
  const VI = /[ạảãàáâấầẩẫậăắằẳẵặẹẻẽèéêếềểễệỉĩìíịọỏõòóôốồổỗộơớờởỡợụủũùúưứừửữựỳỷỹýđ]/i

  it('the pages /devices, /devices/a-nas02 and /devices/setup contain no Vietnamese diacritics', async () => {
    enableModule('agent-intake', true)
    const checks: [string, () => Promise<unknown>][] = [
      ['/devices', () => deviceTable()],
      ['/devices/a-nas02', () => screen.findByRole('table', { name: 'Observations for this device' }, T)],
      ['/devices/setup', () => screen.findByRole('table', { name: 'Enrollment tokens' }, T)],
    ]
    for (const [path, ready] of checks) {
      const { unmount } = renderApp(path)
      await ready()
      await screen.findAllByText('Sample data', undefined, T)
      const text = document.body.textContent ?? ''
      const hit = text.match(new RegExp(`.{0,30}${VI.source}.{0,30}`, 'i'))
      expect(hit?.[0] ?? null, `${path} has Vietnamese text`).toBeNull()
      unmount()
    }
  })

  it('the open dialogs (add, import, delete, sensor, agent token) and the API error messages are English too', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices/setup')
    await user.click(await screen.findByRole('button', { name: 'Create agent token' }, T))
    expect(within(await screen.findByRole('dialog', undefined, T)).getByText('Create an agent token')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(VI)
    asAdmin()
    const msgs = [
      (await call('POST', '/devices', { vendor: 'Fortinet' })).json?.error.message,
      (await call('POST', '/devices', { catalog_id: 'zzz' })).json?.error.message,
      (await call('PATCH', '/devices/a-none', { notes: 'x' })).json?.error.message,
      (await call('PUT', '/settings', { lan_ranges: ['8.8.8.0/24'] })).json?.error.message,
      (await call('POST', '/import', { text: '' })).json?.error.message,
    ]
    for (const m of msgs) { expect(typeof m).toBe('string'); expect(m).not.toMatch(VI) }
  })
})

describe('inventory: the box is the first device (S-INV-5, D-53)', () => {
  it('sample data: first in the list with a "This box" badge, hostname and IP from the box, Ubuntu, packages at confidence 1.0', async () => {
    asAdmin()
    const r = await call('GET', '/devices')
    const box = (r.json!.items as Record<string, any>[]).find((d) => d.id === BOX_ID)! // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(box).toMatchObject({ is_box: true, hostname: 'vedette-hq', ip: '192.168.10.250', kind: 'server', approved: true })
    expect(box.os.value).toBe('Ubuntu 24.04.3 LTS')
    const d = (await call('GET', `/devices/${BOX_ID}`)).json!.asset
    const names = (d.software as { display: string; confidence: number; source: string }[]).map((s) => s.display)
    for (const n of ['OpenSSH server', 'OpenSSL', 'Linux kernel', 'GNU C Library (libc6)', 'curl', 'Python 3 (OpenCanary)']) expect(names).toContain(n)
    expect((d.software as { confidence: number }[]).every((s) => s.confidence === 1)).toBe(true)
    renderApp('/devices')
    const table = await deviceTable()
    const row = within(table).getByRole('link', { name: 'vedette-hq' }).closest('tr')!
    expect(within(row).getByText('This box')).toBeInTheDocument()
    expect(within(table).getAllByRole('row')[1]).toBe(row) // first row
  })

  it('it is matched against exploited vulnerabilities like any device, and the device page points to the operating system update', async () => {
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText('This is the Vedette box itself', undefined, T)).toBeInTheDocument()
    expect(findingsStore.get().some((f) => f.asset_id === BOX_ID)).toBe(true)
    expect(screen.getByRole('link', { name: 'Fix by updating the operating system' })).toHaveAttribute('href', '/settings/updates')
    const sw = screen.getByRole('table', { name: 'Software on the device' })
    expect(within(sw).getAllByText('This box').length).toBeGreaterThan(5)
    expect(screen.getAllByText('This box').length).toBeGreaterThan(1) // badge and software sources
    await expectNoA11yViolations()
  })

  it('S-CORE-9 G3: on the appliance the box page says its packages are read with dpkg', async () => {
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText(/Its packages are read from the box \(dpkg\)/, undefined, T)).toBeInTheDocument()
  })

  it('S-CORE-9 G3: on a container-only install the box page says there is no package list and never mentions dpkg', async () => {
    installStore.set({ kind: 'container' })
    try {
      renderApp(`/devices/${BOX_ID}`)
      expect(await screen.findByText(/The package list of this machine is not available in a container-only install\./, undefined, T)).toBeInTheDocument()
      expect(screen.queryByText(/dpkg/)).not.toBeInTheDocument()
    } finally { installStore.set({ kind: 'appliance' }) }
  })

  it('it cannot be deleted: the button is disabled with the reason and the server refuses', async () => {
    asAdmin()
    renderApp(`/devices/${BOX_ID}`)
    const btn = await screen.findByRole('button', { name: 'Remove from list' }, T)
    expect(btn).toBeDisabled()
    expect(btn).toHaveAttribute('title', 'The box cannot be removed from the list: Vedette runs on it.')
    const r = await call('DELETE', `/devices/${BOX_ID}`)
    expect(r.status).toBe(409)
    expect(r.json!.error.code).toBe('box_device')
    expect(find(BOX_ID)).toBeDefined()
    expect(auditStore.get().some((a) => a.action === 'inventory.delete' && a.detail?.includes(BOX_ID))).toBe(false)
    // its agent-sourced packages cannot be removed by hand either
    expect((await call('DELETE', `/devices/${BOX_ID}/software/s-box-openssh`)).status).toBe(400)
  })

  it('clean install: the box is the only device; hostname from the box, IP unknown until a range is set; guidance to add the rest', async () => {
    const { setDataMode } = await import('@/mocks/db')
    usersStore.get() // a clean install has no users in the mock; take the sample ones first so the request is allowed
    assetsStore.set([])
    setDataMode('clean')
    asAdmin()
    const r = await call('GET', '/devices')
    expect(r.json!.counts.all).toBe(1)
    expect(r.json!.items[0]).toMatchObject({ id: BOX_ID, is_box: true, hostname: 'vedette', ip: '—' })
    renderApp('/devices')
    expect(await screen.findByText(/Only the Vedette box is on the list so far/, undefined, T)).toBeInTheDocument()
    expect(within(await deviceTable()).getByText('This box')).toBeInTheDocument()
    setDataMode('sample')
  })
})

describe('inventory: form matrix (docs/QA.md §2)', () => {
  it('Add a device: the list and the hand-typed maker each show only their own fields; going back to the list drops what was typed', async () => {
    const user = userEvent.setup()
    asAdmin()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const dlg = await screen.findByRole('dialog')
    const NOT_LISTED = "Can't find it? Enter the maker and product yourself"
    await eachOption([
      { option: 'list', shown: [NOT_LISTED], hidden: ['Maker', 'Back to the list'] },
      { option: 'hand', shown: ['Maker', 'Back to the list'], hidden: [NOT_LISTED] },
      { option: 'list', shown: [NOT_LISTED], hidden: ['Maker'] },
    ], async (o) => {
      if (o === 'hand' && within(dlg).queryByRole('button', { name: NOT_LISTED })) await user.click(within(dlg).getByRole('button', { name: NOT_LISTED }))
      if (o === 'list' && within(dlg).queryByRole('button', { name: 'Back to the list' })) await user.click(within(dlg).getByRole('button', { name: 'Back to the list' }))
    }, dlg)
    await user.click(within(dlg).getByRole('button', { name: NOT_LISTED }))
    await user.type(within(dlg).getByLabelText('Maker'), 'Acme')
    await user.type(within(dlg).getByLabelText('Product'), 'Door lock')
    expect(within(dlg).getByRole('button', { name: 'Add' })).toBeEnabled()
    await user.click(within(dlg).getByRole('button', { name: 'Back to the list' }))
    await user.click(within(dlg).getByRole('button', { name: NOT_LISTED }))
    // the fields do not look filled while the form holds nothing: they start empty, and Add stays locked until both are typed
    expect(within(dlg).getByLabelText('Maker')).toHaveValue('')
    expect(within(dlg).getByLabelText('Product')).toHaveValue('')
    expect(within(dlg).getByRole('button', { name: 'Add' })).toBeDisabled()
  })

  it('Scope and sensors: with active scanning off its window is locked; fragile types offer "scan once a week" only when ticked; the server refuses scanning without the scope confirmation', async () => {
    const user = userEvent.setup()
    asAdmin()
    renderApp('/devices/setup')
    const on = await screen.findByRole('switch', { name: 'Turn on active scanning' }, T)
    if (on.getAttribute('aria-checked') === 'true') await user.click(on)
    for (const l of ['From', 'To', 'Scan speed']) expect(screen.getByLabelText(l)).toBeDisabled()
    expect(screen.getByRole('checkbox', { name: 'Monday' })).toBeDisabled()
    await user.click(on)
    for (const l of ['From', 'To', 'Scan speed']) expect(screen.getByLabelText(l)).toBeEnabled()
    expect(screen.getByRole('checkbox', { name: 'Monday' })).toBeEnabled()
    const cam = screen.getByRole('checkbox', { name: 'Camera' })
    const switchFor = () => screen.queryByRole('switch', { name: 'Allow regular scans, Camera' })
    if (cam.getAttribute('aria-checked') === 'true') await user.click(cam)
    expect(switchFor()).toBeNull()
    await user.click(cam)
    expect(switchFor()).not.toBeNull()
    await user.click(cam)
    expect(switchFor()).toBeNull()
    const cur = (await call('GET', '/settings')).json as Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    const r = await call('PUT', '/settings', { ...cur, active: { ...cur.active, enabled: true }, scope_confirmed: false })
    expect(r.status).toBe(400)
    expect(r.json?.error?.code).toBe('scope_not_confirmed')
  })
})

describe('inventory: merging observations follows the source priority (DATA_MODEL §5.1, WP-06)', () => {
  const T0 = '2026-11-09T01:00:00.000Z'
  const ob = (id: string, source: string, confidence: number, seen_at = T0): StoredObs => ({ id, field: 'os', value: id, source: source as StoredObs['source'], confidence, seen_at })
  const winner = (list: StoredObs[]) => markCurrent(list).find((o) => o.current)!.id

  it('manual > agent > snmp > nmap = scan > passive, whatever the confidence', () => {
    expect(winner([ob('passive', 'passive', 0.99), ob('agent', 'agent', 0.5)])).toBe('agent') // the old mock picked the passive 0.99
    expect(winner([ob('agent', 'agent', 1), ob('manual', 'manual', 0.1)])).toBe('manual')
    expect(winner([ob('nmap', 'nmap', 0.9), ob('snmp', 'snmp', 0.2)])).toBe('snmp')
    expect(winner([ob('passive', 'passive', 0.7), ob('nmap', 'nmap', 0.3)])).toBe('nmap')
  })

  it('nmap and scan rank the same, so confidence decides; then seen_at; then the smaller id', () => {
    expect(winner([ob('nmap', 'nmap', 0.6), ob('scan', 'scan', 0.8)])).toBe('scan')
    expect(winner([ob('scan', 'scan', 0.8), ob('nmap', 'nmap', 0.6)])).toBe('scan')
    expect(winner([ob('old', 'agent', 0.9, '2026-11-01T00:00:00.000Z'), ob('new', 'agent', 0.9, T0)])).toBe('new')
    expect(winner([ob('b', 'agent', 0.9), ob('a', 'agent', 0.9)])).toBe('a')
    expect(winner([ob('a', 'agent', 0.9), ob('b', 'agent', 0.9)])).toBe('a')
    expect(compareObs(ob('a', 'nmap', 0.5), ob('b', 'scan', 0.5))).toBeGreaterThan(0) // the only difference is the id
  })

  it('a weaker observation never changes the current value, and no observation is dropped', () => {
    const base = [ob('agent', 'agent', 0.95)]
    const after = markCurrent([...base, ob('passive', 'passive', 0.99, '2026-11-09T05:00:00.000Z')])
    expect(after).toHaveLength(2)
    expect(after.find((o) => o.current)!.id).toBe('agent')
  })

  it('device page: the sample device with an agent OS keeps it over the older passive guess', async () => {
    asAdmin()
    const a = assetsStore.get().find((x) => x.os && x.os.source !== 'passive' && x.os.source !== 'manual')
    expect(a).toBeTruthy()
    const r = await call('GET', `/devices/${a!.id}`)
    const cur = (r.json!.observations as { field: string; source: string; current: boolean }[]).filter((o) => o.field === 'os' && o.current)
    expect(cur).toHaveLength(1)
    expect(cur[0]!.source).toBe(a!.os!.source)
  })
})
