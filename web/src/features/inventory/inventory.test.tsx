import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { cleanup, fireEvent, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { http, HttpResponse } from 'msw'
import { toggleFilter } from '@/test/filters'
import { renderApp, expectNoA11yViolations } from '@/test/render'
import { fmtRelative } from '@/lib/format'
import { server } from '@/test/server'
import { api } from '@/lib/api'
import { collection } from '@/mocks/db'
import { eachOption } from '@/test/formMatrix'
import { assetsStore, auditStore, findingsStore, installStore, modulesStore, sessionStore, usersStore } from '@/mocks/stores'
import { records } from '@/features/findings/modelMocks'
import kevProducts from '../../../../content/catalog/kev-products.json'
import { linuxOneLiner, OSQUERY_SCHEDULE, osquerySteps, wazuhReaderSteps, windowsOneLiner } from './agentConfig'
import { catalogPath, CATALOG_Q_MAX } from './api'
import { CATALOG, customEntry, findById, findCatalog, searchCatalog } from './catalog'
import { sha256Hex } from './kinds'
import { OSQUERY_VERSION } from './installScripts'
import { BOX_ID, compareObs, ensureBox, inventorySettingsStore, markCurrent, sensorsStore, type StoredObs } from './mocks'
import type { DevicesResponse, OsqueryPackage } from './types'
import { normalizeRange, rangeProblem } from './validate'

vi.setConfig({ testTimeout: 30_000 })
// SPAN is offered (SPAN_IN_UI true); the tests that cover the setting that hides it switch it off for their own run.
const span = vi.hoisted(() => ({ SPAN_IN_UI: true }))
vi.mock('@/lib/span', () => span)
// The box is always the first device; the store gets it on the first inventory call, so counts taken before the page loads need it already there.
beforeEach(() => ensureBox())
afterEach(() => { server.events.removeAllListeners(); span.SPAN_IN_UI = true }) // #849: a failing test never leaks its request listener

const BASE = `${location.origin}/api/v1/inventory`
const T = { timeout: 5000 }
/** The device list's own count line ("34 devices, 2 not added yet"); the pager next to it has a status of its own ("1–34 of 34"). */
const countLine = () => { const l = screen.queryAllByRole('status').filter((s) => /devices/.test(s.textContent ?? '')); expect(l).toHaveLength(1); return l[0] }
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
// The setup page re-mounts its sections once right after first paint (a button found at that moment can be detached),
// so click again with a fresh query until the expected effect shows up.
const clickUntil = (user: ReturnType<typeof userEvent.setup>, get: () => HTMLElement, done: () => unknown) =>
  waitFor(async () => { await user.click(get()); done() }, { timeout: 8000 })

/** Ignore and Remove from list of an approved device live in the "More" menu at the bottom of its page. */
async function moreItem(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.click(await screen.findByRole('button', { name: 'More' }, { timeout: 5000 }))
  return screen.findByRole('menuitem', { name })
}

describe('inventory: device list (S-INV-1, S-INV-3)', () => {
  it('the first sentence says "N devices, 2 not added yet", with a table and no a11y violations', async () => {
    renderApp('/devices')
    expect(await screen.findByRole('heading', { level: 1, name: 'Devices' }, T)).toBeInTheDocument()
    expect(await screen.findByText(`${assetsStore.get().length} devices, 2 not added yet`, undefined, T)).toBeInTheDocument() // the toolbar's small line
    const table = await deviceTable()
    expect(within(table).getAllByRole('row').length).toBeGreaterThan(10)
    expect(within(table).getByText('NAS-PHOTOS')).toBeInTheDocument()
    expect((await screen.findAllByText('Sample data', undefined, T)).length).toBeGreaterThan(0)
    await expectNoA11yViolations()
  })

  it('#849: one search box with tokens and chips, kept in ?q=; the old ?show= links open the same filter', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=all&show=recent') // the KPI link
    let table = await deviceTable()
    const box = screen.getByRole('combobox', { name: 'Search devices' })
    await waitFor(() => expect(box).toHaveValue('approved:24h'), T)
    expect(await within(table).findByText('No rows match these filters.', undefined, T)).toBeInTheDocument() // the list filters a deferred value
    await user.click(within(table).getByRole('button', { name: 'Clear filters' }))
    await waitFor(() => expect(box).toHaveValue(''), T)
    await user.click(screen.getByRole('button', { name: /^Filters/ }))
    expect(screen.queryByRole('menuitemcheckbox', { name: /^Manual/ })).toBeNull() // a filter that would show 0 is left out
    await user.keyboard('{Escape}')
    await user.type(box, 'source:manual ')
    table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(await within(table).findByText('No rows match these filters.', undefined, T)).toBeInTheDocument() // the list filters a deferred value
    await user.click(screen.getByRole('button', { name: 'Remove filter Manual' })) // shown while it is on, so it can be turned off
    const fragile = assetsStore.get().filter((a) => a.fragile && a.approved).length
    await toggleFilter(user, new RegExp(`^Fragile ${fragile}$`))
    table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getAllByRole('row')).toHaveLength(fragile + 1)
    expect(countLine()).toHaveTextContent(`${fragile} of `)
    // a token typed by hand, offered by the list: type: then a value
    await user.clear(box)
    await user.type(box, 'type:')
    const opts = await screen.findAllByRole('option', undefined, T)
    expect(opts.map((o) => o.textContent)).toEqual(expect.arrayContaining([expect.stringMatching(/^type:switch/)]))
    await user.click(screen.getAllByRole('option', { name: /^type:switch/ })[0]!)
    await waitFor(() => expect(box).toHaveValue('type:switch '), T)
    table = screen.getByRole('table', { name: DEVICE_TABLE })
    expect(within(table).getByRole('link', { name: 'SW-CORE' })).toBeInTheDocument()
    expect(within(table).queryByRole('link', { name: 'FW-HQ' })).toBeNull()
    await expectNoA11yViolations()
  })

  it('#849: the two lists: Devices holds the approved, To review the rest; no Software or Add devices tab', async () => {
    renderApp('/devices')
    const table = await deviceTable()
    expect(screen.getAllByRole('tab').map((x) => x.textContent?.trim())).toEqual(['Devices', 'To review 2 not added yet'])
    // The count is a plain grey one, not the red alarm style: pending devices come and go.
    const count = screen.getByRole('tab', { name: /To review/ }).querySelector('span.rounded-full')
    expect(count).toHaveClass('bg-off-soft', 'text-off')
    expect(count).not.toHaveClass('bg-danger')
    expect(within(table).queryByRole('link', { name: 'BROTHER-STORE' })).toBeNull() // not approved
    expect(screen.queryByRole('list', { name: 'Devices at a glance' })).toBeNull() // no KPI links
  })

  it('the search box filters by maker', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'hikvision')
    const table = screen.getByRole('table', { name: DEVICE_TABLE })
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(5), T) // 3 cameras + NVR + header
  })

  it('S-INV-2: adding manually: Add a device (Manual is chosen), the address, a few letters, pick a suggestion, Add', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' })) // click 1
    expect(await screen.findByRole('radio', { name: /^Manual/, checked: true }, T)).toBeInTheDocument()
    await user.type(screen.getByLabelText('IP address'), '192.168.30.9')
    await user.type(await screen.findByRole('combobox', { name: 'Product it runs' }), 'fortigate') // the list only appears once the user types
    const option = (await screen.findAllByRole('option', { name: /FortiGate/ }, T))[0]!
    await expectNoA11yViolations() // combobox is open
    await user.click(option) // click 2
    await user.click(screen.getByRole('button', { name: 'Add' })) // click 3
    expect(await screen.findByText(/^Added 192\.168\.30\.9, running FortiGate/, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get()).toHaveLength(before + 1)
    const a = assetsStore.get()[0]!
    expect(a.origin).toBe('manual')
    expect(a.approved).toBe(true)
    expect(a.ip).toBe('192.168.30.9')
    expect(a.software[0]).toMatchObject({ vendor: 'Fortinet', source: 'manual', confidence: 1 })
    expect(a.software[0]!.kev).toContain('fortinet|fortios')
    expect(auditStore.get().some((e) => e.action === 'inventory.add_manual')).toBe(true)
  })

  it('manual add with version, name and IP; searching with a Vietnamese word without diacritics still suggests a product', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const box = await screen.findByRole('combobox', { name: 'Product it runs' })
    await user.type(box, 'tuong lua')
    expect((await screen.findAllByRole('option', { name: /FortiGate/ }, T)).length).toBeGreaterThan(0)
    await user.keyboard('{ArrowDown}{Enter}') // pick with the keyboard
    await waitFor(() => expect(screen.getByRole('combobox', { name: 'Product it runs' })).toHaveAttribute('readonly'))
    await user.type(screen.getByLabelText(/Version/), '7.2.5')
    await user.type(screen.getByLabelText('Host name'), 'Branch firewall')
    await user.type(screen.getByLabelText(/IP address/), '192.168.30.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(assetsStore.get().find((x) => x.ip === '192.168.30.1')).toBeDefined(), T)
    const a = assetsStore.get().find((x) => x.ip === '192.168.30.1')!
    expect(a.hostname).toBe('Branch firewall')
    expect(a.software[0]!.version).toBe('7.2.5')
  })

  it('manual add: no address, a bad IP and a duplicate IP show an English error on the field and nothing is added (#829 item 2)', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    await user.type(await screen.findByRole('combobox', { name: 'Product it runs' }), 'mikrotik')
    await user.click((await screen.findAllByRole('option', { name: /MikroTik/ }, T))[0]!)
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText('Enter an IP address or a host name, so Vedette knows which device this is.', undefined, T)).toBeInTheDocument()
    expect(screen.getByLabelText(/IP address/)).toHaveAttribute('aria-invalid', 'true')
    await user.type(screen.getByLabelText(/IP address/), '999.1.1.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/^That IP address is not valid/, undefined, T)).toBeInTheDocument()
    await user.clear(screen.getByLabelText(/IP address/))
    await user.type(screen.getByLabelText(/IP address/), '192.168.10.1')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('is already in the list (FW-HQ)'), T)
    expect(assetsStore.get()).toHaveLength(before)
  })

  it('free entry: "Can\'t find it?" switches to Maker and Product inputs; incomplete input says what is missing; the toast names the device', async () => {
    const user = userEvent.setup()
    const before = assetsStore.get().length
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    await user.click(await screen.findByRole('button', { name: "Can't find it? Enter the maker and product yourself" }, T))
    expect(within(screen.getByRole('dialog')).queryByRole('combobox')).not.toBeInTheDocument()
    await user.type(screen.getByLabelText('Host name'), 'branch-fw')
    await user.type(screen.getByLabelText('Maker'), 'Fortinet')
    // Add is never off without a reason: sent with the product still empty, the form says what is missing and adds nothing
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/Pick the product this device runs, or enter its maker and product yourself/, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get()).toHaveLength(before)
    await user.type(screen.getByLabelText('Product'), 'FortiGate')
    await user.click(screen.getByRole('button', { name: 'Add' }))
    expect(await screen.findByText(/^Added branch-fw, running Fortinet FortiGate\./, undefined, T)).toBeInTheDocument()
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
    expect(await screen.findByRole('combobox', { name: 'Product it runs' }, T)).toBeInTheDocument()
  })

  it('the Add dialog is titled "Add a device"; the first Escape closes only the suggestion list, the second closes the dialog', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(within(dialog).getByRole('heading', { name: 'Add a device' })).toBeInTheDocument()
    const box = within(dialog).getByRole('combobox', { name: 'Product it runs' })
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
    renderApp('/devices?tab=review', { role: 'viewer' })
    await screen.findByText('2 new devices not added yet', undefined, T)
    expect(screen.getAllByRole('button', { name: 'Add a device' })[0]).toBeDisabled()
    expect(screen.queryByRole('link', { name: 'Scope, sensors and agents' })).not.toBeInTheDocument()
    expect(screen.queryByRole('link', { name: /sensors/ })).not.toBeInTheDocument()
    expect(screen.getAllByRole('button', { name: /^Add .+ to your devices$/ })[0]).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Notify me about new devices' })).toBeDisabled()
  })

  it('#849: Add a device offers every method in one dialog; each method shows only its own form (form matrix)', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices?tab=add') // the old Add devices tab opens the dialog
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    const methods = within(dlg).getByRole('radiogroup', { name: 'How to add it' })
    expect(within(methods).getAllByRole('radio').map((r) => r.closest('label')?.querySelector('.font-medium')?.textContent)).toEqual(['Manual', 'SNMP', 'osquery', 'Wazuh', 'CSV import'])
    expect(within(dlg).queryByText(/by hand|SSH|API key/)).not.toBeInTheDocument()
    // SNMP has its own form (address and settings); osquery and Wazuh show no field of the other methods
    const own: Record<string, RegExp> = { Manual: /^IP address$/, SNMP: /^IP address or range$/, osquery: /^Token name|^Name/, Wazuh: /Wazuh API address|Server API|^Address/, 'CSV import': /^Choose a CSV file$/ }
    const noForm = ['osquery', 'Wazuh', 'SNMP']
    const snmpOnly = /^Device IP address$/
    for (const [m, field] of Object.entries(own)) {
      await user.click(within(methods).getByRole('radio', { name: new RegExp(`^${m}`) }))
      expect(await within(dlg).findByRole('region', { name: m }, T)).toBeInTheDocument()
      if (!noForm.includes(m)) expect(within(dlg).getByLabelText(field)).toBeInTheDocument()
      for (const [other, f] of Object.entries(own)) if (other !== m && !noForm.includes(other)) expect(within(dlg).queryByLabelText(f)).toBeNull()
    }
    await user.click(within(methods).getByRole('radio', { name: /^SNMP/ }))
    expect(await within(dlg).findByLabelText('Community', undefined, T)).toBeInTheDocument()
    expect(within(dlg).getByLabelText(snmpOnly)).toBeInTheDocument()
    expect(within(dlg).queryByText(/set up on each device's own page|manually first/i)).toBeNull()
    await expectNoA11yViolations()
  })

  it('#849: SNMP, osquery and Wazuh are admin only and say so', async () => {
    renderApp('/devices?add=manual', { role: 'operator' })
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    for (const m of ['SNMP', 'osquery', 'Wazuh']) expect(within(dlg).getByRole('radio', { name: new RegExp(`^${m}`) })).toBeDisabled()
    expect(within(dlg).getAllByText('Admin only').length).toBe(3)
    expect(within(dlg).getByRole('radio', { name: /^CSV import/ })).toBeEnabled()
  })

  it('#849: turning a module on here says which modules it also turns on', async () => {
    enableModule('agent-intake', false)
    enableModule('notify', false)
    modulesStore.update((l) => l.map((m) => (m.id === 'agent-intake' ? { ...m, depends: ['inventory', 'notify'] } : m)))
    renderApp('/devices?add=osquery')
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    expect(await within(dlg).findByText(/also turns on Notifications, which it needs/, undefined, T)).toBeInTheDocument()
  })

  it('a module the method needs is off: the admin turns it on right in the dialog, and the method opens', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', false)
    renderApp('/devices?add=osquery')
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    expect(within(dlg).getByRole('radio', { name: /^osquery/, checked: true })).toBeEnabled()
    await user.click(within(dlg).getByRole('button', { name: 'Turn on Agent intake' }))
    expect(await within(dlg).findByRole('button', { name: 'Linux' }, T)).toBeInTheDocument()
    expect(modulesStore.get().find((m) => m.id === 'agent-intake')?.enabled).toBe(true)
  })

  it('#849: a viewer\'s old ?tab=add link lands on the list, not on a form that ends in 403', async () => {
    renderApp('/devices?tab=add', { role: 'viewer' })
    await deviceTable()
    expect(screen.queryByRole('dialog', { name: 'Add a device' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Add a device' })).toBeDisabled()
  })

  it('#849: with software: the list shows the matched software and its version (the old Software tab)', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=software') // the old tab opens has:software
    const table = await deviceTable()
    const box = screen.getByRole('combobox', { name: 'Search devices' })
    await waitFor(() => expect(box).toHaveValue('has:software'), T)
    await user.clear(box)
    await user.type(box, 'software:photo ')
    await waitFor(() => expect(within(table).getByRole('columnheader', { name: /Matched software/ })).toBeInTheDocument(), T)
    // the server answers software: once the typing pauses
    const row = (await within(table).findByRole('link', { name: 'NAS-PHOTOS' }, T)).closest('tr')!
    expect(row).toHaveTextContent('QNAP Photo Station')
  })


  it('#849: osquery from the dialog: a token, then the one-line install for the server', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices?add=osquery')
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    expect(within(dlg).getByRole('radio', { name: /^osquery/, checked: true })).toBeInTheDocument()
    expect(await within(dlg).findByText(/macOS is not supported/, undefined, T)).toBeInTheDocument()
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    await user.click(await within(dlg).findByRole('button', { name: 'Create install command' }, T))
    expect(await within(dlg).findByText(/^vdt_osquery_/, undefined, T)).toBeInTheDocument()
    expect(within(dlg).queryByRole('radiogroup', { name: 'How to add it' })).toBeNull() // the only copy of the secret stays on screen
    expect(within(dlg).getByRole('button', { name: 'Windows' })).toBeInTheDocument()
  })

  it('osquery: an install command made earlier and never used is said before a new one is made, and can be revoked there', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices?add=osquery')
    const first = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.click(await within(first).findByRole('button', { name: 'Linux' }, T))
    expect(within(first).queryByText(/has no machine yet/)).toBeNull()
    await user.click(within(first).getByRole('button', { name: 'Create install command' }))
    await within(first).findByText(/^vdt_osquery_/, undefined, T)
    await user.click(within(first).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    await user.click(screen.getByRole('button', { name: 'Add a device' }))
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.click(within(dlg).getByRole('radio', { name: /^osquery/ }))
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    expect(within(dlg).getByText(/An install command made .* has no machine yet\./)).toBeInTheDocument()
    await user.click(within(dlg).getByRole('button', { name: 'Revoke it' }))
    expect(await screen.findByText('Unused install command revoked')).toBeInTheDocument()
    await waitFor(() => expect(within(dlg).queryByText(/has no machine yet/)).toBeNull())
  })

  it('osquery: Add a device offers to revoke only the unused install commands it made, never a token made in Settings', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    const token = (id: string, name: string) => ({ id, name, kind: 'osquery', last4: 'abcd', created_at: new Date(Date.now() - 30 * 60_000).toISOString(),
      created_by: 'admin@example.test', last_received: null, hosts: 0, expires_at: new Date(Date.now() + 864e5).toISOString(), device_id: null })
    const tokens = collection<{ id: string }[]>('intake_agent_tokens', () => [])
    tokens.set([token('tk-settings', 'osquery install 2026-11-24'), token('tk-ci', 'build servers'), token('tk-add', 'osquery install 2026-11-24, from Add a device')])
    renderApp('/devices?add=osquery')
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    expect(within(dlg).getByText(/^An install command made .* has no machine yet\.$/)).toBeInTheDocument()
    await user.click(within(dlg).getByRole('button', { name: 'Revoke it' }))
    expect(await screen.findByText('Unused install command revoked')).toBeInTheDocument()
    expect(tokens.get().map((k) => k.id).sort()).toEqual(['tk-ci', 'tk-settings'])
  })

  it('osquery: several unused install commands are counted from the oldest one', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    const ago = (minutes: number) => new Date(Date.now() - minutes * 60_000).toISOString()
    const unused = (id: string, minutes: number) => ({ id, name: `osquery install 2026-11-2${minutes > 60 ? 3 : 4}, from Add a device`, kind: 'osquery', last4: 'abcd', created_at: ago(minutes), created_by: 'admin@example.test',
      last_received: null, hosts: 0, expires_at: new Date(Date.now() + 864e5).toISOString(), device_id: null })
    // the box lists tokens newest first
    collection<unknown[]>('intake_agent_tokens', () => []).set([unused('tk-new', 10), unused('tk-old', 20 * 60)])
    renderApp('/devices?add=osquery')
    const dlg = await screen.findByRole('dialog', { name: 'Add a device' }, T)
    await user.click(await within(dlg).findByRole('button', { name: 'Linux' }, T))
    const line = within(dlg).getByText(/install commands made since .* have no machine yet\./)
    expect(line).toHaveTextContent(`2 install commands made since ${fmtRelative(ago(20 * 60))} have no machine yet.`)
  })

  it('the operator role gets the add button enabled and the setup link hidden (admin only)', async () => {
    renderApp('/devices', { role: 'operator' })
    await deviceTable()
    expect(screen.getByRole('button', { name: 'Add a device' })).toBeEnabled()
    expect(screen.queryByRole('link', { name: /sensors/ })).not.toBeInTheDocument()
  })

  it('old #agents links open their tab; #snmp lands on the SNMP card of Settings › Scanning (#850)', async () => {
    const { unmount } = renderApp('/devices/setup#agents')
    expect(await screen.findByRole('tab', { name: 'Agents', selected: true }, T)).toBeInTheDocument()
    unmount()
    renderApp('/devices/setup#snmp') // #850: the SNMP engine card of Settings › Scanning (SNMP itself is set up per device)
    expect(await screen.findByRole('tab', { name: 'Engines', selected: true }, T)).toBeInTheDocument()
  })

  it('the admin gets a link to the setup page (agents included) next to "Add a device" (item 26b)', async () => {
    renderApp('/devices')
    await deviceTable()
    // the link is named as the page it opens
    const link = screen.getByRole('link', { name: 'Sensor and agents' })
    expect(link).toHaveAttribute('href', '/devices/setup')
    expect(link.nextElementSibling).toBe(screen.getByRole('button', { name: 'Add a device' }))
  })

  it('one toolbar over the list holds the count, Export CSV, Settings and Add a device; Add is the only primary button; the header has no buttons', async () => {
    renderApp('/devices')
    await deviceTable()
    const header = screen.getByRole('heading', { level: 1 }).closest('header')!
    expect(within(header).queryAllByRole('button', { name: /Add a device|Export CSV|Filters/ })).toHaveLength(0)
    expect(within(header).queryAllByRole('link', { name: /settings/i })).toHaveLength(0)
    const add = screen.getByRole('button', { name: 'Add a device' })
    const bar = add.parentElement!.parentElement!.parentElement!
    expect(within(bar).getByRole('combobox', { name: 'Search devices' })).toBeInTheDocument()
    expect(within(bar).getByRole('button', { name: 'Export CSV' })).toBeInTheDocument()
    expect(within(bar).getByRole('link', { name: 'Sensor and agents' })).toBeInTheDocument()
    expect(within(bar).getByText(/not added yet/)).toBeInTheDocument()
    // primary = the accent-filled button; Export, Filters and Settings are quiet or outlined
    const primary = within(bar).getAllByRole('button').filter((b) => b.className.includes('bg-accent text-accent-ink'))
    expect(primary).toEqual([add])
  })

  it('Filters opens the options; picking one adds a removable chip and filters the list; removing the chip clears it', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    const table = await deviceTable()
    const all = within(table).getAllByRole('row').length
    const filters = screen.getByRole('button', { name: 'Filters' })
    expect(screen.queryByRole('menuitemcheckbox')).toBeNull()
    await user.click(filters)
    const names = (await screen.findAllByRole('menuitemcheckbox')).map((x) => x.textContent)
    expect(names).toEqual(expect.arrayContaining([expect.stringMatching(/^Fragile/), expect.stringMatching(/^SNMP/)]))
    await user.keyboard('{Escape}')
    expect(filters).toHaveFocus()
    await toggleFilter(user, /^Fragile/)
    expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('fragile')
    const fragile = assetsStore.get().filter((a) => a.fragile && a.approved).length
    await waitFor(() => expect(within(screen.getByRole('table', { name: DEVICE_TABLE })).getAllByRole('row')).toHaveLength(fragile + 1), T)
    expect(screen.getByRole('button', { name: 'Filters 1' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Remove filter Fragile' }))
    await waitFor(() => expect(within(screen.getByRole('table', { name: DEVICE_TABLE })).getAllByRole('row')).toHaveLength(all), T)
    expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('')
  })

  it('one count line: every device without a search, "N of M shown" for this list with one; one Clear filters clears the whole query', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    const total = assetsStore.get().length
    const approved = assetsStore.get().filter((a) => a.approved).length
    await waitFor(() => expect(countLine()).toHaveTextContent(`${total} devices, 2 not added yet`), T)
    await toggleFilter(user, /^Fragile/)
    const fragile = assetsStore.get().filter((a) => a.fragile && a.approved).length
    await waitFor(() => expect(countLine()).toHaveTextContent(`${fragile} of ${approved} devices shown · 2 not added yet`), T)
    expect(screen.getAllByRole('status').filter((s) => /devices/.test(s.textContent ?? ''))).toHaveLength(1) // the pager's range names rows, not devices
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'zzz')
    await user.click(await screen.findByRole('button', { name: 'Clear filters' }, T))
    expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('')
    expect(screen.queryByRole('button', { name: /^Remove filter/ })).toBeNull()
  })

  it('the Settings button opens the settings page', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    await deviceTable()
    await user.click(screen.getByRole('link', { name: 'Sensor and agents' }))
    expect(await screen.findByRole('tab', { name: /^Sensor/ }, T)).toBeInTheDocument()
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
    renderApp('/devices?tab=review')
    await screen.findByText('2 new devices not added yet', undefined, T)
    const tab = screen.getByRole('tab', { name: /To review 2 not added yet/ })
    expect(tab).toHaveAttribute('aria-selected', 'true')
    const pending = assetsStore.get().filter((a) => !a.approved).map((a) => a.id)
    await user.click(screen.getAllByRole('button', { name: /^Add .+ to your devices$/ })[0]!)
    // the toast's title (its description also says "Approved in the last 24 h"); other tests leave their toasts behind
    const toast = (await screen.findByText(/^Added .+ to your devices\.$/, undefined, T)).closest<HTMLElement>('[data-sonner-toast]')!
    expect(assetsStore.get().filter((a) => !a.approved)).toHaveLength(1)
    expect(await screen.findByText(/1 new device not added yet/, undefined, T)).toBeInTheDocument()
    // The toast says where to find it again and opens the device
    expect(within(toast).getByText('Find it later in Devices.')).toBeInTheDocument()
    const approved = pending.find((id) => find(id).approved)!
    fireEvent.click(within(toast).getByRole('button', { name: 'Open device' })) // no pointer events: sonner's swipe handler needs setPointerCapture, which jsdom lacks
    const crumbs = await screen.findByRole('navigation', { name: 'Breadcrumb' }, T)
    expect(within(crumbs).getByRole('link', { name: 'Devices' })).toHaveAttribute('href', '/devices')
    // ...and it is found again with approved:24h (the old "Approved in the last 24 h" link opens that search)
    renderApp('/devices?tab=all&show=recent')
    const table = await deviceTable()
    await waitFor(() => expect(within(table).getAllByRole('row')).toHaveLength(2), T) // header + the device just approved
    // its first link opens it (a device Vedette knows nothing to check by also has its "Needs your input" badge)
    expect(within(within(table).getAllByRole('row')[1]!).getAllByRole('link')[0]).toHaveAttribute('href', `/devices/${approved}`)
    expect(screen.getByRole('combobox', { name: 'Search devices' })).toHaveValue('approved:24h')
  })

  it('S-INV-3: a To review row offers Add device and Ignore, no Remove; the unknown mark lives on the device page', async () => {
    renderApp('/devices?tab=review')
    const list = await screen.findByRole('list', { name: '2 new devices not added yet' }, T)
    const row = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('192.168.10.157'))!
    expect(within(row).getAllByRole('button').map((b) => b.textContent)).toEqual(['Add device', 'Ignore'])
    // its accessible name says which device it adds: never confused with the toolbar's "Add a device" (a device typed by hand)
    expect(within(row).getByRole('button', { name: /^Add .+ to your devices$/ })).toHaveTextContent('Add device')
    expect(within(list).queryByRole('button', { name: /unknown/ })).toBeNull()
    cleanup()
    // the device page's notice has Add device, Ignore and Remove: no Mark unknown, and no second Remove from list beside it
    renderApp('/devices/a-unk01')
    await screen.findByText('This device is not added yet', undefined, T)
    for (const name of ['Add device', 'Ignore', 'Remove']) expect((await screen.findAllByRole('button', { name }, T))[0]).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /unknown/ })).toBeNull()
    expect(screen.queryByRole('button', { name: 'Remove from list' })).toBeNull()
    expect(find('a-unk01').approved).toBe(false)
  })

  it('Ignore asks first, says what still alerts and that a private MAC may come back; the Ignored tab lists it with Stop ignoring', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=review')
    const list = await screen.findByRole('list', { name: '2 new devices not added yet' }, T)
    const row = within(list).getAllByRole('listitem').find((li) => li.textContent?.includes('192.168.10.157'))!
    await user.click(within(row).getByRole('button', { name: 'Ignore' }))
    expect(auditStore.get().some((e) => e.action === 'inventory.ignore')).toBe(false) // nothing before confirming
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).toHaveTextContent('when it touches a trap or the intrusion detection reports it')
    expect(dialog).toHaveTextContent('It uses a private Wi-Fi address (da:a1:19:5c:77:01).')
    await user.click(within(dialog).getByRole('button', { name: 'Ignore device' }))
    expect(await screen.findByRole('list', { name: '1 new device not added yet' }, T)).toBeInTheDocument()
    expect(auditStore.get().some((e) => e.action === 'inventory.ignore')).toBe(true)
    // the Ignored tab appears with the device and Stop ignoring sends it back to To review
    await user.click(await screen.findByRole('tab', { name: 'Ignored (1)' }, T))
    const ignored = await screen.findByRole('list', { name: 'Ignored devices' }, T)
    const item = within(ignored).getAllByRole('listitem').find((li) => li.textContent?.includes('192.168.10.157'))!
    await user.click(within(item).getByRole('button', { name: 'Stop ignoring' }))
    expect(await screen.findByText(/is back in To review\./, undefined, T)).toBeInTheDocument()
    expect(auditStore.get().some((e) => e.action === 'inventory.unignore')).toBe(true)
    await user.click(await screen.findByRole('tab', { name: /To review/ }, T))
    expect(await screen.findByRole('list', { name: '2 new devices not added yet' }, T)).toBeInTheDocument()
  })

  it('an ignored device is out of Devices by default; its page says so and offers Stop ignoring', async () => {
    const user = userEvent.setup()
    asAdmin()
    const r = await api.post('/inventory/devices/a-nas02/ignore', { ignored: true })
    expect(r).toEqual({ ok: true })
    const all = await api.get<DevicesResponse>('/inventory/devices')
    expect(all.items.some((d) => d.id === 'a-nas02')).toBe(false)
    expect(all.counts.ignored).toBe(1)
    expect((await api.get<DevicesResponse>('/inventory/devices?ignored=true')).items.map((d) => d.id)).toEqual(['a-nas02'])
    // Its open findings are closed with the reason, none deleted, none open
    const mine = findingsStore.get().filter((f) => f.asset_id === 'a-nas02')
    expect(mine.length).toBeGreaterThan(0)
    expect(mine.some((f) => f.status === 'suspected' || f.status === 'confirmed')).toBe(false)
    expect(mine.some((f) => (f.resolution_note ?? '').startsWith('Closed by Vedette: the device was ignored by'))).toBe(true)
    renderApp('/devices/a-nas02')
    expect(await screen.findByText('This device is ignored', undefined, T)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Stop ignoring' }))
    await waitFor(() => expect(find('a-nas02').approved).toBe(false), T) // back through review
  })

  it('S-INV-3: Approve all approves every device in To review in one action', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=review')
    await screen.findByText('2 new devices not added yet', undefined, T)
    await user.click(await screen.findByRole('button', { name: /^Add all \(\d+\)$/ }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    await user.click(within(dialog).getByRole('button', { name: /^Add \d+ devices$/ }))
    expect(await screen.findByText('No new devices waiting', undefined, T)).toBeInTheDocument()
  })

  it('the delete dialog mentions the findings count when the device has findings, and removes them', async () => {
    const user = userEvent.setup()
    const n = findingsStore.get().filter((f) => f.asset_id === 'a-nas02').length
    expect(n).toBeGreaterThan(0)
    renderApp('/devices/a-nas02')
    await user.click(await moreItem(user, 'Remove from list'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).toHaveTextContent(n === 1 ? 'This device has 1 finding; removing the device removes it too.' : `This device has ${n} findings; removing the device removes them too.`)
    await user.click(within(dialog).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(find('a-nas02' as string)).toBeUndefined(), T)
    expect(findingsStore.get().filter((f) => f.asset_id === 'a-nas02')).toHaveLength(0)
  })

  it('the delete dialog says nothing about findings when the device has none', async () => {
    const user = userEvent.setup()
    expect(findingsStore.get().some((f) => f.asset_id === 'a-pc02')).toBe(false)
    renderApp('/devices/a-pc02')
    await user.click(await moreItem(user, 'Remove from list'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).not.toHaveTextContent(/This device has \d+ finding/)
  })

  it('the "Notify me about new devices" switch saves, and says so when the Notifications module is off', async () => {
    const user = userEvent.setup()
    renderApp('/devices?tab=review')
    const sw = await screen.findByRole('switch', { name: 'Notify me about new devices' }, T)
    expect(sw).toBeChecked()
    expect(screen.getByText(/Notifications go through the channels/)).toBeInTheDocument()
    await user.click(sw)
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Notify me about new devices' })).not.toBeChecked(), T)
    await user.click(screen.getByRole('switch', { name: 'Notify me about new devices' }))
    await waitFor(() => expect(screen.getByRole('switch', { name: 'Notify me about new devices' })).toBeChecked(), T)
    enableModule('notify', false)
    renderApp('/devices?tab=review')
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
    // Only the box is left (it cannot be deleted): the page keeps its name and the empty state says so (S-INV-5).
    expect(await screen.findByRole('heading', { level: 1, name: 'Devices' }, T)).toBeInTheDocument()
    expect(await screen.findByText('No other devices yet', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText('No devices yet')).toBeNull()
    expect(screen.getAllByRole('button', { name: 'Add a device' }).length).toBeGreaterThan(1)
    expect(await screen.findByText(/Vedette is watching your saved ranges/, undefined, T)).toBeInTheDocument() // the mock has ranges saved
    expect(screen.queryByRole('link', { name: "Set the box's network ranges" })).not.toBeInTheDocument()
  })

  it('no devices and no range saved: asks for the ranges', async () => {
    assetsStore.set([])
    server.use(http.get('*/api/v1/inventory/settings', () => HttpResponse.json({ ...inventorySettingsStore.get(), lan_ranges: [] })))
    renderApp('/devices')
    expect(await screen.findByRole('link', { name: "Set the box's network ranges" }, T)).toHaveAttribute('href', '/settings/scanning?tab=safety#range-input') // straight to the range field (#842 deep link)
  })

  it('the setup page does not ask for agents while agent-intake is off', async () => {
    let asked = 0
    server.use(http.get('*/api/v1/inventory/agents', () => { asked++; return HttpResponse.json({ error: { code: 'module_off', message: 'off' } }, { status: 404 }) }))
    renderApp('/devices/setup?tab=agents')
    expect((await screen.findAllByText(/Agent intake is off/, undefined, T)).length).toBeGreaterThan(0)
    expect(asked).toBe(0)
  })
})

describe('inventory: device types in two levels', () => {
  it('the list shows category and type, a guess as "likely" with its evidence, and filters by category with type:', async () => {
    const user = userEvent.setup()
    renderApp('/devices')
    const table = await deviceTable()
    const row = within(table).getByRole('link', { name: /192\.168\.10\.251|Fortinet/ }).closest('tr')!
    expect(within(row).getByText('Firewall')).toBeInTheDocument()
    expect(within(row).getByText('likely')).toBeInTheDocument()
    expect(within(row).getByTitle(/^Security: /)).toBeInTheDocument() // #849: one line per desktop row, the category on hover (the phone list and the device page show it)
    expect(within(row).getByTitle(/Fortinet network card and port 22/)).toBeInTheDocument()
    const nas = within(table).getByRole('link', { name: 'NAS-PHOTOS' }).closest('tr')!
    expect(within(nas).getByTitle('Storage')).toBeInTheDocument()
    expect(within(nas).queryByText('likely')).toBeNull()

    // #849: the category is a type: token (the old ?cat= opens it)
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'type:security')
    await waitFor(() => expect(within(table).queryByRole('link', { name: 'NAS-PHOTOS' })).toBeNull(), T)
    expect(within(table).getByRole('link', { name: /192\.168\.10\.251|Fortinet/ })).toBeInTheDocument()
  })

  it('the device page groups the type picker by category and confirms a guess as the person\'s type', async () => {
    const user = userEvent.setup()
    asAdmin()
    renderApp('/devices/a-unk02')
    const box = await screen.findByTestId('kind-guess', undefined, T)
    expect(box).toHaveTextContent('Most likely: Firewall (Security)')
    // the header names the type the list shows: the guess, marked likely, never "Unknown" next to it
    expect(screen.getByText(/^Firewall \(likely\), last seen/)).toBeInTheDocument()
    expect(box).toHaveTextContent('Fortinet network card and port 22 (ssh)')
    expect(box).toHaveTextContent('scans still treat this device as unknown')
    const picker = screen.getByRole('combobox', { name: 'Device type' })
    expect(within(picker).getByRole('group', { name: 'Telephony' })).toBeInTheDocument()
    expect(within(picker).getByRole('option', { name: 'IP phone' })).toBeInTheDocument()
    await user.click(within(box).getByRole('button', { name: 'Confirm: Firewall' }))
    await waitFor(() => expect(find('a-unk02').kind).toBe('firewall'), T)
    await waitFor(() => expect(screen.queryByTestId('kind-guess')).toBeNull(), T)
  })

  it('the guess offers the other types the same signals fit; picking the access point keeps the device fragile (#714)', async () => {
    const user = userEvent.setup()
    asAdmin()
    renderApp('/devices/a-unk02')
    const box = await screen.findByTestId('kind-guess', undefined, T)
    expect(box).toHaveTextContent('The same signals also fit: Wi-Fi (AP), Switch')
    await user.click(within(box).getByRole('button', { name: 'It is a Wi-Fi (AP)' }))
    await waitFor(() => expect(find('a-unk02')).toMatchObject({ kind: 'ap', fragile: true }), T)
  })

  it('the fragile setting still lists the 13 kinds every type acts as; a new type is fragile as the kind it acts as', async () => {
    asAdmin()
    expect((await call('PATCH', '/devices/a-pc01', { kind: 'ip_phone' })).status).toBe(200)
    expect(find('a-pc01').fragile).toBe(true) // an IP phone acts as an IoT device, fragile by default
    expect((await call('PATCH', '/devices/a-pc01', { kind: 'laptop' })).status).toBe(200)
    expect(find('a-pc01').fragile).toBe(false)
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
    renderApp('/devices?add=csv')
    await screen.findByRole('dialog', { name: 'Add a device' }, T)
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
    expect(screen.getByText('Line 8:').parentElement).toHaveTextContent('Type "notakind" is not a device type')
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

  it('a bare "Linux" is several distributions: the row asks for the distribution, a named one imports', async () => {
    asAdmin()
    const r = (await call('POST', '/import', { text: 'name,ip,product,version\nsrv-1,,Linux,12\nsrv-2,,Debian,12\n' })).json!
    expect(r).toMatchObject({ created: 1, skipped: 1 })
    expect(r.errors[0].message).toContain('Name the distribution')
    expect(r.errors[0].message).toContain('Debian Linux')
  })

  it('a public IP or an IP outside the saved ranges is added with a note', async () => {
    asAdmin()
    const r = (await call('POST', '/import', { text: 'name,ip\npub,8.8.8.8\nfar,10.99.99.9\n' })).json!
    expect(r.created).toBe(2)
    expect(r.notes).toHaveLength(2)
    expect(r.notes[0].message).toContain('public address')
    expect(r.notes[1].message).toContain('outside your saved network ranges')
    // like import_test.go: a 100.64/10 device is on a local network (outside the saved ranges here), a 100.128 one is public
    const c = (await call('POST', '/import', { text: 'name,ip\ncgnat,100.66.254.7\npub100,100.128.0.7\n' })).json!
    expect(c.created).toBe(2)
    expect(c.notes).toHaveLength(2)
    expect(c.notes[0].message).toContain('outside your saved network ranges')
    expect(c.notes[1].message).toContain('public address')
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
    const user = userEvent.setup()
    renderApp('/devices/a-nas02')
    expect(await screen.findByRole('heading', { level: 1, name: 'NAS-PHOTOS' }, T)).toBeInTheDocument()
    expect(screen.getByText(/^NAS, last seen/)).toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Fragile device' })).toBeChecked()
    // The page frame: one tab per area of the device, each with its count; Overview opens with the findings line
    expect(await screen.findByRole('tab', { name: /^Findings \d+ open findings$/ }, T)).toBeInTheDocument()
    expect(screen.getAllByRole('tab').map((x) => x.firstChild?.textContent?.trim())).toEqual(['Overview', 'Findings', 'Software', 'Services', 'Observations'])
    expect(screen.getByRole('tab', { name: 'Services 3 open services' })).toBeInTheDocument()
    const line = await screen.findByTestId('device-findings-line', undefined, T)
    expect(within(line).getByRole('link', { name: 'View findings' })).toHaveAttribute('href', '/devices/a-nas02?tab=findings')
    await expectNoA11yViolations()
    await user.click(screen.getByRole('tab', { name: 'Observations' }))
    const obs = await screen.findByRole('table', { name: 'Observations for this device' }, T)
    expect(within(obs).getByText('QTS 5.0.1')).toBeInTheDocument()
    expect(within(obs).getByText('Unknown OS (guessed from packet TTL)')).toBeInTheDocument() // the older value is kept
    expect(within(obs).getAllByText(/confidence/).length).toBeGreaterThan(3)
    expect(within(obs).getAllByText('In use').length).toBeGreaterThanOrEqual(4)
    expect(within(obs).getAllByText('Kept for comparison').length).toBeGreaterThanOrEqual(1)
    await user.click(screen.getByRole('tab', { name: 'Services 3 open services' }))
    const services = await screen.findByRole('table', { name: 'Services open on the device' }, T)
    expect(within(services).getByText('8080/tcp')).toBeInTheDocument()
    // what nmap -sV read is shown per port: service, product and version in their own columns
    expect(within(services).getAllByRole('columnheader').map((h) => h.textContent?.trim())).toEqual(expect.arrayContaining(['Port', 'Service', 'Product', 'Version']))
    const row8080 = within(services).getByText('8080/tcp').closest('tr') as HTMLElement
    expect(within(row8080).getByText('QNAP QTS')).toBeInTheDocument()
    expect(within(row8080).getByText('5.1.0')).toBeInTheDocument()
    await user.click(screen.getByRole('tab', { name: /^Software/ }))
    const sw = await screen.findByRole('table', { name: 'Software on the device' }, T)
    // The row says what it needs: its open findings, as the device's Findings tab lists them
    expect(await within(sw).findByText('1 open finding', undefined, T)).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  // The column agrees with Findings: a CVE shows against a software row only while the device has it open.
  // The row is looked up on every try: the table re-renders when the module list and the findings arrive.
  const photoStation = () => within(screen.getByRole('table', { name: 'Software on the device' })).getByText('QNAP Photo Station').closest('tr')!
  const openSoftwareTab = () => renderApp('/devices/a-nas02?tab=software')
  it('an open finding shows on the software row as what it needs, with its status', async () => {
    openSoftwareTab()
    await waitFor(() => expect(within(photoStation()).getByText('1 open finding')).toBeInTheDocument(), T)
  })

  it('an exploited CVE of the product without an open finding on the device is not shown', async () => {
    records.update((l) => l.map((r) => (r.asset_id === 'a-nas02' ? { ...r, state: 'handled' as const, resolution: 'not_relevant' as const, via: 'person' as const, resolved_by: 'admin@acme.example', resolved_at: r.last_seen } : r)))
    openSoftwareTab()
    await screen.findByRole('table', { name: 'Software on the device' }, T)
    await waitFor(() => expect(screen.queryByText('Checking findings')).toBeNull(), T)
    expect(within(photoStation()).queryByText(/open finding/)).toBeNull() // nothing on a clean row
  })

  it('with findings off the column says so instead of listing the product\'s exploited CVEs', async () => {
    enableModule('findings', false)
    openSoftwareTab()
    await waitFor(() => expect(within(photoStation()).getByText('Findings are off')).toBeInTheDocument(), T)
    expect(within(photoStation()).queryByText(/open finding/)).toBeNull()
  })

  it('INV-41 (6): a row a scan reported is marked Not installed after one confirmation; it shows as the person said, with Clear', async () => {
    const user = userEvent.setup()
    findingsStore.update((l) => l.map((f) => (f.id === 'f-1' ? { ...f, status: 'suspected' as const, basis: 'version' as const } : f)))
    openSoftwareTab()
    await waitFor(() => expect(within(photoStation()).getByText('1 open finding')).toBeInTheDocument(), T) // the row is settled: findings arrived
    // an unmarked row offers the action in its menu; no status text until a person marks it
    expect(within(photoStation()).queryByText(/^Not installed/)).toBeNull()
    await user.click(within(photoStation()).getByRole('button', { name: 'Actions for QNAP Photo Station' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Mark not installed…' }, T))
    const dialog = await screen.findByRole('dialog', undefined, T)
    expect(dialog).toHaveAccessibleName('Is QNAP Photo Station 6.0.20 not installed on NAS-PHOTOS?')
    expect(dialog).toHaveTextContent('Vedette stops matching it and closes the findings only it produced, as long as the scan or agent reads this same version.')
    await user.click(within(dialog).getByRole('button', { name: 'Not installed' }))
    expect(await screen.findByText('QNAP Photo Station 6.0.20 is marked not installed on NAS-PHOTOS. 1 finding closed.', undefined, T)).toBeInTheDocument()
    const f1 = () => findingsStore.get().find((f) => f.id === 'f-1')!
    expect(f1()).toMatchObject({ status: 'not_relevant', resolved_by: 'system' })
    expect(f1().resolution_note).toMatch(/^Closed: a person said the software is not installed\. .* said QNAP Photo Station 6\.0\.20 \(scan\) is not installed on NAS-PHOTOS/)
    // one row: the person's word, with Clear; the reported row it replaces is not listed again
    await waitFor(() => expect(within(screen.getByRole('table', { name: 'Software on the device' })).getAllByText('QNAP Photo Station')).toHaveLength(1), T)
    expect(within(photoStation()).getByText(/^Not installed \(you said, .+\)$/)).toBeInTheDocument()
    expect(within(photoStation()).queryByRole('button', { name: /^Actions for/ })).toBeNull()
    expect(auditStore.get().some((a) => a.action === 'inventory.mark_not_installed')).toBe(true)
    await expectNoA11yViolations()
    await user.click(within(photoStation()).getByRole('button', { name: 'Clear "not installed" for QNAP Photo Station' }))
    expect(await screen.findByText('QNAP Photo Station is back as the scan or agent reads it. Its findings are checked again.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(within(photoStation()).getByRole('button', { name: 'Actions for QNAP Photo Station' })).toBeInTheDocument(), T)
    expect(f1().status).toBe('suspected')
    expect(find('a-nas02').software.some((s) => s.corrects)).toBe(false)
  })

  it('INV-41 (6): the toast says when a finding stays open, and why (a scan confirmed it)', async () => {
    const user = userEvent.setup()
    openSoftwareTab() // f-1 on Photo Station is confirmed by a scan
    await waitFor(() => expect(within(photoStation()).getByText('1 open finding')).toBeInTheDocument(), T)
    await user.click(within(photoStation()).getByRole('button', { name: 'Actions for QNAP Photo Station' }))
    await user.click(await screen.findByRole('menuitem', { name: 'Mark not installed…' }, T))
    await user.click(within(await screen.findByRole('dialog', undefined, T)).getByRole('button', { name: 'Not installed' }))
    expect(await screen.findByText('QNAP Photo Station 6.0.20 is marked not installed on NAS-PHOTOS. 1 stays open: a scan confirmed it.', undefined, T)).toBeInTheDocument()
    expect(findingsStore.get().find((f) => f.id === 'f-1')!.status).toBe('confirmed')
  })

  it('INV-41 (6): a viewer sees Not installed locked; a row a person added is removed, never marked; the API refuses mixing it with a version', async () => {
    renderApp('/devices/a-nas02?tab=software', { role: 'viewer' })
    await waitFor(() => expect(within(photoStation()).getByRole('button', { name: 'Actions for QNAP Photo Station' })).toBeDisabled(), T)
    asAdmin()
    expect((await call('PATCH', '/devices/a-nas02/software/s-nas02-ps', { not_installed: true, version: '6.1' })).json?.error.code).toBe('bad_edit')
    expect((await call('PATCH', '/devices/a-nas02/software/s-nas02-ps', { not_installed: true, vendor: 'QNAP', product: 'QTS' })).json?.error.code).toBe('bad_edit')
    expect((await call('PATCH', `/devices/${BOX_ID}/software/s-box-openssh`, { not_installed: true })).json?.error.code).toBe('box_device')
    // marking the same row again changes nothing and writes no second audit row
    const marks = () => auditStore.get().filter((a) => a.action === 'inventory.mark_not_installed').length
    const n = marks()
    expect((await call('PATCH', '/devices/a-nas02/software/s-nas02-ps', { not_installed: true })).status).toBe(200)
    expect((await call('PATCH', '/devices/a-nas02/software/s-nas02-ps', { not_installed: true })).status).toBe(200)
    expect(marks()).toBe(n + 1)
    const added = await call('POST', '/devices/a-pc01/software', { catalog_id: CATALOG[0]!.id, version: '1.0' })
    expect(added.status).toBe(201)
    const mine = find('a-pc01').software.find((s) => s.source === 'manual')!
    expect((await call('PATCH', `/devices/a-pc01/software/${mine.id}`, { not_installed: true })).json?.error.code).toBe('bad_edit')
  })

  it('changing the type adds a manual observation and keeps the old one', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas01')
    const select = await screen.findByRole('combobox', { name: 'Device type' }, T)
    await user.selectOptions(select, 'server')
    expect(await screen.findByText(/Type changed to Server\./, undefined, T)).toBeInTheDocument()
    expect(find('a-nas01').kind).toBe('server')
    await user.click(screen.getByRole('tab', { name: 'Observations' }))
    const obs = await screen.findByRole('table', { name: 'Observations for this device' }, T)
    await waitFor(() => expect(within(obs).getByText('Server')).toBeInTheDocument(), T)
    expect(within(obs).getByText('NAS')).toBeInTheDocument() // old value still there
    expect(within(obs).getByText('Manual')).toBeInTheDocument()
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
    renderApp('/devices/a-pc01?tab=software')
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
    await user.click((await screen.findAllByRole('button', { name: `Actions for ${added.display}` }, T))[0]!)
    await user.click(await screen.findByRole('menuitem', { name: 'Remove from the device' }, T))
    await waitFor(() => expect(find('a-pc01').software).toHaveLength(before), T)
    asAdmin()
    const r = await call('DELETE', `/devices/a-pc01/software/${find('a-pc01').software[0]!.id}`)
    expect(r.json?.error.code).toBe('not_manual')
  })

  it('a pending device has an approval box right on the detail page', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-prn03')
    expect(await screen.findByText('This device is not added yet', undefined, T)).toBeInTheDocument()
    await user.click(screen.getAllByRole('button', { name: 'Add device' })[0]!) // the notice's; the SNMP source row offers the same action in the same words
    await waitFor(() => expect(screen.queryByText('This device is not added yet')).not.toBeInTheDocument(), T)
    expect(find('a-prn03').approved).toBe(true)
  })

  it('the page header has the name, a Rename device icon and the type line; Ignore and Remove are under More, the checks under Last checks', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02')
    const title = await screen.findByRole('heading', { level: 1 }, T)
    const header = title.parentElement!.parentElement!
    expect(within(header).getAllByRole('button').map((b) => b.getAttribute('aria-label') ?? b.textContent)).toContain('Rename device')
    for (const name of ['Ignore', 'Remove from list', 'Check this device now']) expect(within(header).queryByRole('button', { name })).toBeNull()
    expect(screen.queryByRole('menuitem')).toBeNull()
    await user.click(await moreItem(user, 'Ignore'))
    expect(await screen.findByRole('dialog', undefined, T)).toBeInTheDocument()
  })

  it('a device not approved yet has Ignore and Remove in its notice and no More menu', async () => {
    renderApp('/devices/a-unk01')
    await screen.findByText('This device is not added yet', undefined, T)
    expect(screen.queryByRole('button', { name: 'More' })).toBeNull()
    expect(screen.getByRole('button', { name: 'Ignore' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument()
  })

  it('removing from the detail page goes back to the list', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-pc02')
    await screen.findByRole('switch', { name: 'Fragile device' }, T)
    await user.click(await moreItem(user, 'Remove from list'))
    await user.click(await screen.findByRole('button', { name: 'Remove from list' }, T))
    expect(await screen.findByText(/devices, 2 not added yet/, undefined, T)).toBeInTheDocument()
    expect(assetsStore.get().find((a) => a.id === 'a-pc02')).toBeUndefined()
  })

  it('a device that does not exist: says so and offers a way back', async () => {
    renderApp('/devices/a-missing')
    expect(await screen.findByText('This device does not exist', undefined, T)).toBeInTheDocument()
    expect(within(screen.getByRole('navigation', { name: 'Breadcrumb' })).getByRole('link', { name: 'Devices' })).toHaveAttribute('href', '/devices')
  })

  it('the viewer role: every write control is locked', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    expect(await screen.findByRole('combobox', { name: 'Device type' }, T)).toBeDisabled()
    expect(screen.getByRole('switch', { name: 'Fragile device' })).toBeDisabled()
    expect(screen.getByRole('textbox', { name: 'Notes about the device' })).toBeDisabled()
    expect(await moreItem(userEvent.setup(), 'Remove from list')).toHaveAttribute('aria-disabled', 'true')
    await userEvent.keyboard('{Escape}')
    await userEvent.click(screen.getByRole('tab', { name: /^Software/ }))
    expect(await screen.findByRole('button', { name: 'Add software' }, T)).toBeDisabled()
  })

  it('PATCH validates at the edge', async () => {
    asAdmin()
    expect((await call('PATCH', '/devices/a-pc01', { kind: 'laptop-bay' })).json?.error.code).toBe('bad_kind')
    expect((await call('PATCH', '/devices/a-pc01', { notes: 'x'.repeat(2001) })).json?.error.code).toBe('bad_notes')
    expect((await call('PATCH', '/devices/a-none', { notes: 'x' })).status).toBe(404)
  })

  it('an empty Services tab says who lists the ports: the box itself, an agent, or the scan', async () => {
    asAdmin()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-box' ? { ...a, services: [] } : a)))
    renderApp('/devices/a-box?tab=services')
    expect(await screen.findByText('The box lists the ports it listens on itself, every hour; none has come yet.', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(/active sensor has not scanned/)).not.toBeInTheDocument()
  })

  it('an empty Services tab of a container-only box says it lists none, of an agent device that its agent has not reported yet', async () => {
    asAdmin()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-box' ? { ...a, services: [], model: a.model && { ...a.model, value: 'Security box (container-only)' } } : a)))
    const { unmount } = renderApp('/devices/a-box?tab=services')
    expect(await screen.findByText("A container-only install does not list the box's own ports.", undefined, T)).toBeInTheDocument()
    unmount()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-pc01' ? { ...a, fragile: false, services: [], software: [{ id: 's-agent', display: 'OpenSSH', vendor: 'OpenBSD', product: 'OpenSSH', version: '9.6p1', kev: [], source: 'agent', confidence: 0.95 }] } : a)))
    renderApp('/devices/a-pc01?tab=services')
    expect(await screen.findByText('Its agent lists the ports this machine listens on; none has come yet.', undefined, T)).toBeInTheDocument()
    expect(screen.queryByText(/active sensor has not scanned/)).not.toBeInTheDocument()
  })

  it('a detail load error shows the error state', async () => {
    server.use(http.get('*/api/v1/inventory/devices/:id', () => HttpResponse.json({ error: { code: 'x', message: 'Could not read the device data.' } }, { status: 500 })))
    renderApp('/devices/a-pc01')
    expect(await screen.findByText('Could not read the device data.', undefined, T)).toBeInTheDocument()
  })
})

describe('inventory: add-device API (catalog id and free entry)', () => {
  it('accepts {vendor, product} without catalog_id and matches the product of that name', async () => {
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
    expect(CATALOG.length).toBeGreaterThan(600) // a KEV pair a curated product covers is that product's entry, not a second one
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

  it('a KEV pair a curated product covers is one entry: no second DSM, vCenter or ESXi row', () => {
    for (const q of ['synology diskstation', 'vcenter', 'esxi']) {
      const items = searchCatalog(q).items
      expect(items.filter((e) => e.curated && /DSM|vCenter|ESXi/.test(e.display))).toHaveLength(1)
      expect(items.filter((e) => !e.curated && /diskstation|vcenter|esxi/i.test(e.product))).toEqual([])
    }
    expect(findById('kev:vmware:esxi')?.display).toBe('VMware ESXi')
  })

  it('a product typed by hand is never matched to every product of its vendor, but is the catalogue product of that name', () => {
    // "Red Hat" "OpenJDK" is Java, as the server says, never Red Hat's other products
    const jdk = customEntry('Red Hat', 'OpenJDK')
    expect(jdk.kev.length).toBeGreaterThan(0)
    expect(jdk.kev.every((k) => k.startsWith('oracle|java'))).toBe(true)
    expect(customEntry('Red Hat', 'Some Future Tool').kev).toEqual(['red hat|some future tool'])
    expect(customEntry('Red Hat', 'Some Future Tool').kev_count).toBe(0)
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
    expect(normalizeRange('10.142.0.0')).toEqual({ value: '10.142.0.0', note: null }) // no prefix: kept as typed, reported by rangeProblem
    expect(normalizeRange('10.142.0.5')).toEqual({ value: '10.142.0.5', note: null })
    expect(normalizeRange('10.142.0.5/24')).toEqual({ value: '10.142.0.0/24', note: 'network' })
    expect(normalizeRange('  10.0.0.0/8 ')).toEqual({ value: '10.0.0.0/8', note: null })
    expect(normalizeRange('abc')).toEqual({ value: 'abc', note: null })
    expect(normalizeRange('10.0.5.0/99')).toEqual({ value: '10.0.5.0/99', note: null })
  })

  it('rangeProblem: no prefix, format, host bits, not private, overlap, or fine', () => {
    expect(rangeProblem('abc', [])).toBe('format')
    expect(rangeProblem('10.142.0.0', [])).toBe('noPrefix')
    expect(rangeProblem('10.142.0.5/24', [])).toBe('hostBits')
    expect(rangeProblem('8.8.8.0/24', [])).toBe('notPrivate')
    expect(rangeProblem('10.0.0.0/7', [])).toBe('notPrivate')
    expect(rangeProblem('192.168.10.0/25', ['192.168.10.0/24', '192.168.10.0/25'])).toBe('overlap')
    expect(rangeProblem('192.168.10.0/24', ['192.168.10.0/24'])).toBeNull()
    expect(rangeProblem('172.16.0.0/12', [])).toBeNull()
    // The RFC 6598 shared address space is internal, the rest of 100/8 is not.
    expect(rangeProblem('100.66.254.0/24', [])).toBeNull()
    expect(rangeProblem('100.64.0.0/10', [])).toBeNull()
    expect(rangeProblem('100.128.0.0/24', [])).toBe('notPrivate')
    expect(rangeProblem('100.0.0.0/8', [])).toBe('notPrivate')
  })
})

describe('inventory: sensors (S-INV-1, admin)', () => {
  it('the page has the sensor and agent tabs and a link to the one scan-scope editor; old Scope links land there', async () => {
    const user = userEvent.setup()
    const view = renderApp('/devices/setup')
    expect(await screen.findByRole('heading', { level: 1, name: 'Sensor and agents' }, T)).toBeInTheDocument()
    const tabs = await screen.findByRole('tablist', { name: 'Parts of the setup' }, T)
    expect(within(tabs).getAllByRole('tab').map((x) => x.textContent?.trim())).toEqual(['Sensor', 'Agents', 'Wazuh'])
    expect(screen.getByRole('link', { name: 'Scan scope' })).toHaveAttribute('href', '/settings/scanning?tab=safety#scope')
    expect(await screen.findByRole('region', { name: 'Sensor on this box' }, T)).toBeInTheDocument()
    await expectNoA11yViolations()
    await user.click(screen.getByRole('tab', { name: 'Agents' }))
    expect(await screen.findByRole('region', { name: 'Agents on servers' }, T)).toBeInTheDocument()
    view.unmount()
    renderApp('/devices/setup?tab=scope#range-input')
    expect(await screen.findByRole('button', { name: 'Add range' }, T)).toBeInTheDocument()
    expect(screen.getByRole('tab', { name: 'Safety', selected: true })).toBeInTheDocument()
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

  it('PUT rejects a bare address with a clear message, clears host bits and reports it in adjusted', async () => {
    asAdmin()
    const got = (await call('GET', '/settings')).json!
    const { adjusted: _a, ...base } = got
    const bare = await call('PUT', '/settings', { ...base, lan_ranges: ['10.142.0.0'], scope_confirmed: true })
    expect(bare.status).toBe(400)
    expect(bare.json!.error.code).toBe('no_prefix')
    expect(bare.json!.error.message).toBe('"10.142.0.0" has no prefix length. Add it so Vedette scans the right size of network, for example 10.142.0.0/24 or 10.142.0.0/25.')
    const put2 = await call('PUT', '/settings', { ...base, lan_ranges: ['10.142.0.5/24', '192.168.20.0/24'], scope_confirmed: true })
    expect(put2.status).toBe(200)
    expect(put2.json!.lan_ranges).toEqual(['10.142.0.0/24', '192.168.20.0/24'])
    expect(put2.json!.adjusted).toEqual([{ from: '10.142.0.5/24', to: '10.142.0.0/24' }])
    const put3 = await call('PUT', '/settings', { ...base, lan_ranges: ['10.142.0.0/24'], scope_confirmed: true, version: put2.json!.version })
    expect(put3.json!.adjusted).toEqual([]) // already normal: nothing adjusted
    // #860: the version the page read is checked when it is sent; an older one is 409 safety_changed
    const stale = await call('PUT', '/settings', { ...base, lan_ranges: ['10.142.0.0/24'], scope_confirmed: true })
    expect(stale.status).toBe(409)
    expect(stale.json!.error.code).toBe('safety_changed')
    const { version: _v, ...noVersion } = base
    expect((await call('PUT', '/settings', { ...noVersion, lan_ranges: ['10.142.0.0/24'], scope_confirmed: true })).status).toBe(200) // left out: no check
  })

  it('the server rejects public ranges, bad hours, bad speed, bad exclusions and more', async () => {
    asAdmin()
    const { version: _v, ...base } = (await call('GET', '/settings')).json! // no version: these saves check the rules, not the race
    const put = async (patch: Record<string, unknown>) => (await call('PUT', '/settings', { ...base, scope_confirmed: true, ...patch })).json?.error?.code
    expect(await put({ lan_ranges: ['8.8.8.0/24'] })).toBe('public_range')
    expect(await put({ lan_ranges: ['10.0.0.0/7'] })).toBe('public_range')
    expect(await put({ lan_ranges: ['100.128.0.0/24'] })).toBe('public_range') // only 100.64/10 of 100/8 is internal
    expect((await call('PUT', '/settings', { ...base, scope_confirmed: true, lan_ranges: ['100.63.0.0/16'] })).json?.error?.message).toBe('100.63.0.0/16 is not an internal range (10.x, 172.16-31.x, 192.168.x, 100.64-127.x). To scan public addresses, add them under External exposure after verifying ownership.')
    expect((await call('PUT', '/settings', { ...base, scope_confirmed: true, lan_ranges: ['100.66.254.0/24'] })).json?.error).toBeUndefined()
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
    renderApp('/devices/setup?tab=sensor')
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

  // The sample box already listens on a SPAN card (eth1): with SPAN switched off in the GUI it still shows that state, read-only.
  it('SPAN switched off: the sensor dialog shows the SPAN status a box already has and links to Box network; it has no SPAN switch', async () => {
    span.SPAN_IN_UI = false
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=sensor')
    await screen.findAllByRole('button', { name: 'Configure sensor vedette-hq' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: 'Configure sensor vedette-hq' })[0]!, () => screen.getByRole('dialog'))
    const dlg = screen.getByRole('dialog')
    expect(await within(dlg).findByText('Receiving', undefined, T)).toBeInTheDocument()
    expect(within(dlg).getByText('eth1')).toBeInTheDocument()
    expect(within(dlg).queryByRole('switch')).not.toBeInTheDocument()
    expect(within(dlg).getByRole('link', { name: 'Open Settings → Box network' })).toHaveAttribute('href', '/settings/network')
  })

  it('SPAN switched off: a box without SPAN says the sensor listens on the management port, with no word about SPAN or mirrored traffic', async () => {
    span.SPAN_IN_UI = false
    const user = userEvent.setup()
    asAdmin()
    const r = await fetch(`${location.origin}/api/v1/core/network/interfaces`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ roles: { eth0: 'management', eth1: 'unused', eth2: 'unused' } }) })
    expect(r.status).toBe(200)
    renderApp('/devices/setup?tab=sensor')
    await screen.findAllByRole('button', { name: 'Configure sensor vedette-hq' }, T)
    const sec = document.getElementById('sensors')!
    expect(sec).toHaveTextContent("It listens on the box's management port, set in Settings → Box network.")
    await waitFor(() => expect(within(sec).getByRole('cell', { name: 'eth0' })).toBeInTheDocument(), T)
    expect(sec.textContent).not.toMatch(/SPAN|mirror/i)
    await clickUntil(user, () => screen.getAllByRole('button', { name: 'Configure sensor vedette-hq' })[0]!, () => screen.getByRole('dialog'))
    const dlg = screen.getByRole('dialog')
    expect(dlg).toHaveTextContent("The port the sensor listens on: the box's management port, set in Settings.")
    expect(within(dlg).getByText('eth0')).toBeInTheDocument()
    expect(within(dlg).queryByText('Mirrored traffic')).toBeNull()
    expect(dlg.textContent).not.toMatch(/SPAN|mirror/i)
    expect(within(dlg).getByRole('link', { name: 'Open Settings → Box network' })).toHaveAttribute('href', '/settings/network')
  })

  it('while the box starts the sensor the row says Starting… with why; a sensor the box could not start says what to check', async () => {
    asAdmin()
    sensorsStore.update((l) => l.map((x) => ({ ...x, status: 'starting' as const, last_seen: null, version: null, devices_seen: 0 })))
    const sec = () => document.getElementById('sensors')!
    const first = renderApp('/devices/setup?tab=sensor')
    await waitFor(() => expect(sec()).toHaveTextContent('Starting…'), T)
    expect(sec()).toHaveTextContent('The box is starting the sensor (after setup or after you turned it on).')
    expect(sec()).not.toHaveTextContent('Not connected yet')
    first.unmount()
    sensorsStore.update((l) => l.map((x) => ({ ...x, status: 'never_connected' as const })))
    renderApp('/devices/setup?tab=sensor')
    await waitFor(() => expect(sec()).toHaveTextContent('Not connected yet'), T)
    expect(sec()).toHaveTextContent('The box could not get the sensor running.')
    expect(sec()).toHaveTextContent('Turn Passive sensor off and on in Settings → Modules') // behind the ⓘ next to it (#824)
    expect(sec().textContent).not.toContain('compose.sensors.yaml') // that hint is the container-only one
  })

  it('single-box only: one local sensor, no kind/site/enrollment fields, no "other site" button, no remote-sensor endpoints', async () => {
    asAdmin()
    const list = (await call('GET', '/sensors')).json!.sensors as Record<string, unknown>[]
    expect(list).toHaveLength(1)
    expect(list[0]).toMatchObject({ id: 'sn-local', name: 'vedette-hq', status: 'online' })
    for (const k of ['kind', 'site', 'enrollment', 'waiting']) expect(list[0]).not.toHaveProperty(k)
    expect(JSON.stringify(list)).not.toMatch(/VED-[A-Z0-9]{4}/)

    renderApp('/devices/setup?tab=sensor')
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
  it('the section has the osquery token table and no Wazuh card; the seeded token is listed and masked', async () => {
    enableModule('agent-intake', true)
    renderApp('/devices/setup?tab=agents')
    const table = await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    expect(within(table).getByText(OSQ)).toBeInTheDocument()
    expect(within(table).getByText('••••k3Pq')).toBeInTheDocument()
    expect(screen.queryByText(/Vedette acts as the osquery server/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Connect Wazuh' })).not.toBeInTheDocument() // Wazuh has its own tab
    expect(screen.queryByText(/Trivy/i)).not.toBeInTheDocument()
    expect(screen.queryByText(/macOS/i)).not.toBeInTheDocument()
  })

  it('the osquery packages sit in one folded line at the bottom of the page, without opening a dialog', async () => {
    enableModule('agent-intake', true)
    renderApp('/devices/setup?tab=agents')
    const fold = (await screen.findByText(`Download osquery ${OSQUERY_VERSION}`, undefined, T)).closest('details')!
    expect(fold).not.toHaveAttribute('open')
    fold.open = true
    const table = await screen.findByRole('table', { name: 'osquery packages this box serves' }, T)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    const pkgs = (await call('GET', '/agents')).json!.install.packages as OsqueryPackage[]
    expect(pkgs.map((p) => p.platform)).toEqual(expect.arrayContaining(['linux', 'windows']))
    expect(within(table).getAllByRole('link').map((a) => [a.getAttribute('href'), a.getAttribute('download')])).toEqual(
      pkgs.map((p) => [`/api/v1/install/osquery/${p.file}`, p.file])) // Linux and Windows together, no OS to pick first
    const hint = { deb: 'sudo dpkg -i', rpm: 'sudo rpm -Uvh', msi: 'msiexec /i' } as const
    for (const p of pkgs) {
      const row = within(table).getByRole('link', { name: `Download ${p.file}` }).closest('tr')!
      expect(row).toHaveTextContent(p.sha256)
      expect(row).toHaveTextContent(`${(p.size / 1e6).toFixed(1)} MB`)
      expect(row).toHaveTextContent(`${hint[p.format]} ${p.file}`)
    }
    expect(within(table).getByRole('link', { name: `Download osquery-${OSQUERY_VERSION}.msi` }).closest('tr')).toHaveTextContent('Windows · x64')
    expect(screen.getByText(new RegExp(`official osquery ${OSQUERY_VERSION.replace(/\./g, '\\.')} packages`))).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: 'Enrollment tokens' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create agent token' })).toBeEnabled()
    expect(document.body.textContent).not.toMatch(/osquery\.io|choco/)
    await expectNoA11yViolations()
  })

  it('without the packages the page says so in step 1 and links nowhere else (item 26b)', async () => {
    enableModule('agent-intake', true)
    asAdmin()
    const real = (await call('GET', '/agents')).json!
    server.use(http.get('*/api/v1/inventory/agents', () => HttpResponse.json({ ...real, install: { ...real.install, packages: [] } })))
    renderApp('/devices/setup?tab=agents')
    expect(await screen.findByText(/This box has no copy of the osquery packages\./, undefined, T)).toBeInTheDocument()
    expect(screen.queryByRole('table', { name: 'osquery packages this box serves' })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create agent token' })).toBeInTheDocument()
  })

  it('creates a token on one click: token and install command shown once; the API never returns the full token again', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Create agent token' }), () => screen.getByRole('dialog'))
    const form = await screen.findByRole('dialog', undefined, T)
    expect(within(form).queryByRole('button', { name: 'Wazuh' })).not.toBeInTheDocument() // no agent type choice any more
    expect(within(form).queryByLabelText('Token name')).toBeNull() // one button, no form
    await user.click(await within(form).findByRole('button', { name: 'Create install command' }, T))
    const dialog = await screen.findByRole('dialog', { name: /^Token for osquery install \d{4}-\d{2}-\d{2}$/ }, T)
    const secret = (await within(dialog).findByText(/^vdt_osquery_[a-z0-9]{32}$/, undefined, T)).textContent!
    expect(within(dialog).getByText(/The token is shown once/)).toBeInTheDocument()
    // Linux is the default platform: one line, hash check, token as an argument, expected SHA-256 shown
    const sha = (await call('GET', '/agents')).json!.install.linux.sha256 as string
    expect(sha).toMatch(/^[0-9a-f]{64}$/)
    expect(within(dialog).getByRole('button', { name: 'Linux' })).toHaveAttribute('aria-pressed', 'true')
    expect(within(dialog).getByText(new RegExp(`sudo sh "\\$f" --token ${secret}; r=\\$\\?; rm -f "\\$f"; exit \\$r\\)$`))).toBeInTheDocument()
    expect(within(dialog).getByText('Expected SHA-256 of the script:').parentElement).toHaveTextContent(sha)
    expect(within(dialog).getByText('What this script does')).toBeInTheDocument()
    expect(within(dialog).getByText('Download and install manually')).toBeInTheDocument()
    expect(within(dialog).getByText('Remove osquery later').closest('details')).not.toHaveAttribute('open') // a later job: folded
    // Direct downloads from this origin, one row per Linux package, with what it is for, its size and its SHA-256
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
    await user.click(within(dialog).getByRole('button', { name: 'Windows' }))
    expect(downloads().map((a) => a.getAttribute('download'))).toEqual([`osquery-${OSQUERY_VERSION}.msi`])
    expect(within(dialog).getByRole('link', { name: `Download osquery-${OSQUERY_VERSION}.msi` }).closest('tr')).toHaveTextContent('Windows · x64')
    expect(within(dialog).getByText(new RegExp(`-Token '${secret}'`))).toBeInTheDocument()
    expect(within(dialog).getAllByText(/Get-FileHash \$f -Algorithm SHA256/).length).toBeGreaterThan(0)
    expect(within(dialog).getByText(/curl\.exe -k for that one download only/)).toBeInTheDocument()
    await expectNoA11yViolations()
    await user.click(within(dialog).getByRole('button', { name: 'I copied the token' }))
    const listed = await call('GET', '/agents')
    expect(listed.text).not.toContain(secret)
    const t = (listed.json!.tokens as Record<string, any>[]).find((x) => /^osquery install \d{4}-\d{2}-\d{2}$/.test(x.name))! // eslint-disable-line @typescript-eslint/no-explicit-any
    expect(t).toMatchObject({ kind: 'osquery', last4: secret.slice(-4), hosts: 0, last_received: null })
    expect(new Date(t.expires_at).getTime() - Date.now()).toBeGreaterThan(6 * 864e5)
    expect((await screen.findAllByText(`••••${secret.slice(-4)}`, undefined, T)).length).toBeGreaterThan(0)
  })

  it('the snippets use the box address (https, never http or localhost) and the dialog is English', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    for (const platform of ['Linux', 'Windows']) {
      await user.click(within(dialog).getByRole('button', { name: platform }))
      // the note may name the page's own host (jsdom: localhost) to say agents will NOT use it; every command and script must not
      const text = (dialog.textContent ?? '').replace(/You opened Vedette at [^,]+, but agents will use [^.]+\./, '')
      expect(text).toContain(`${BOX}/api/v1/install/osquery.${platform === 'Linux' ? 'sh' : 'ps1'}`)
      expect(text, platform).not.toMatch(/localhost|127\.0\.0\.1/)
      expect(text.replace(/https:\/\//g, ''), `${platform}: only https`).not.toMatch(/http:\/\//)
      expect(text).toMatch(/--cacert|--tls_server_certs/)
    }
  })

  it('a box without the osquery packages says so, offers no download and points nowhere else', async () => {
    enableModule('agent-intake', true)
    asAdmin()
    const real = (await call('GET', '/agents')).json!
    server.use(http.get('*/api/v1/inventory/agents', () => HttpResponse.json({ ...real, install: { ...real.install, packages: [] } })))
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', undefined, T)
    for (const platform of ['Linux', 'Windows']) {
      await user.click(within(dialog).getByRole('button', { name: platform }))
      expect(within(dialog).getByText(/This box has no copy of the osquery packages/)).toBeInTheDocument()
      expect(within(dialog).queryByRole('table', { name: 'osquery packages this box serves' })).not.toBeInTheDocument()
      expect(dialog.textContent).not.toMatch(/osquery\.io|choco/)
    }
  })

  it('viewing the setup again uses <TOKEN> instead of exposing the token; the token can be revoked', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Show setup for ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: `Set up ${OSQ}` }, T)
    expect(within(dialog).getByText(/sudo sh "\$f" --token <TOKEN>; r=\$\?; rm -f "\$f"; exit \$r\)$/)).toBeInTheDocument()
    expect(dialog.textContent).not.toMatch(/vdt_osquery_[a-z0-9]{32}/)
    await user.click(within(dialog).getAllByRole('button', { name: 'Close' })[0]!)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Revoke token ${OSQ}` })[0]!, () => screen.getByRole('dialog'))
    await user.click(await screen.findByRole('button', { name: 'Revoke' }, T))
    const table = await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await waitFor(() => expect(within(table).queryByText(OSQ)).toBeNull(), T)
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
      for (const line of ['--config_plugin=tls', '--logger_plugin=tls', 'enroll_secret_path', 'tls_server_certs', 'tls_hostname', '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--config_refresh=300', '--logger_tls_endpoint=/api/v1/intake/osquery/log']) expect(r.text, `${ext}: ${line}`).toContain(line)
    }
    const sh = (await raw('GET', '/install/osquery.sh')).text
    expect(sh).toContain('--token')
    expect(sh).toContain('--uninstall')
    expect(sh).toContain('--cacert') // after the CA is saved there is no more -k
    expect((await raw('GET', '/install/osquery.ps1')).text).toContain('-Uninstall')
  })

  // A box opened as localhost only knows no address a server can reach; a command pinned to <VEDETTE_BOX_IP> would pass its
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
      renderApp('/devices/setup?tab=agents')
      await clickUntil(user, () => screen.getByRole('button', { name: 'Create agent token' }), () => screen.getByRole('dialog'))
      const form = await screen.findByRole('dialog', undefined, T)
      await user.click(await within(form).findByRole('button', { name: 'Create install command' }, T))
      const dialog = await screen.findByRole('dialog', { name: /^Token for osquery install / }, T)
      expect(await within(dialog).findByText('Servers cannot reach this box at the address you opened it with', undefined, T)).toBeInTheDocument()
      expect(within(dialog).getByText(/Open Vedette at the box's network address/)).toBeInTheDocument()
      expect(dialog.textContent).not.toMatch(/VEDETTE_BOX_IP|curl -fsSLk|Get-FileHash/)
      expect(within(dialog).getByText(/^vdt_osquery_[a-z0-9]{32}$/)).toBeInTheDocument() // the token itself is shown, and stays valid
      await expectNoA11yViolations()
    } finally {
      setDataMode('sample')
    }
  })

  it('the token row counts enrolled machines and the Linux command names both architectures', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=agents')
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

  it('osquery TLS API: enroll gives a node key for a valid token only, config carries the schedule, every credential failure is 200 + node_invalid', async () => {
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
    const updated = assetsStore.get().filter((a) => a.id !== BOX_ID && a.id !== 'a-fw01' && a.software.some((s) => s.source === 'agent')) // a-fw01 carries an agent row in the sample data already
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
    renderApp('/devices/setup?tab=agents')
    await screen.findByRole('table', { name: 'Enrollment tokens' }, T)
    await clickUntil(user, () => screen.getAllByRole('button', { name: `Send sample data for ${OSQ}` })[0]!, () => expect(assetsStore.get().some((a) => a.software.some((s) => s.source === 'agent'))).toBe(true))
    expect(await screen.findByText(/Sample data received: \d+ devices updated, \d+ software entries added from the agent\./, undefined, T)).toBeInTheDocument()
    expect(auditStore.get().some((e) => e.action === 'inventory.agent_enroll')).toBe(true)
  })

  it('Wazuh is a pull connection: Connect Wazuh opens read-only user steps and the connection form', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=wazuh')
    await screen.findByRole('region', { name: 'Wazuh' }, T)
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
    renderApp('/devices/setup?tab=wazuh')
    await screen.findByRole('region', { name: 'Wazuh' }, T)
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

  it('while Test connection waits on the Wazuh manager, the button is busy and a note says it can take up to 30 seconds', async () => {
    enableModule('agent-intake', true)
    let release = () => {}
    const held = new Promise<void>((r) => { release = r })
    server.use(http.post('*/api/v1/inventory/agents/wazuh/test', async () => { await held; return HttpResponse.json({ version: '4.9.2', agents: 1 }) }))
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=wazuh')
    await screen.findByRole('region', { name: 'Wazuh' }, T)
    await clickUntil(user, () => screen.getByRole('button', { name: 'Connect Wazuh' }), () => screen.getByRole('dialog'))
    const dialog = await screen.findByRole('dialog', { name: 'Connect Wazuh' }, T)
    await user.type(within(dialog).getByLabelText('Wazuh server API address'), 'https://wazuh-manager:55000')
    await user.click(within(dialog).getByRole('button', { name: 'Test connection' }))
    expect(await within(dialog).findByRole('button', { name: 'Testing…' }, T)).toHaveAttribute('aria-busy', 'true')
    expect(within(dialog).getByText(/^Reaching the Wazuh manager… this can take up to 30 seconds\./)).toBeInTheDocument()
    expect(within(dialog).getByRole('button', { name: 'Save connection' })).toBeDisabled()
    release()
    expect(await within(dialog).findByText(/Connected to Wazuh 4\.9\.2/, undefined, T)).toBeInTheDocument()
  })

  it('#847: a Wazuh pull that failed shows why on the card (a password not restored with the backup says to enter it again)', async () => {
    enableModule('agent-intake', true)
    const lost = 'The saved Wazuh password was not restored (the backup was restored without its decryption key, or the box key changed). Open Edit, enter the password again and press Save. Nothing is pulled until then.'
    collection<unknown>('intake_wazuh', () => null).set({ url: 'https://wazuh-manager:55000', username: 'vedette', password: 'x', password_last4: 'pass', interval_minutes: 60, status: 'error', last_sync: null, agents: 0, packages: 0, error: lost })
    renderApp('/devices/setup?tab=wazuh')
    expect(await screen.findByText(lost, undefined, T)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Edit' })).toBeInTheDocument()
  })

  it('Wazuh connect, sync with sample data, and disconnect from the UI; the password is never shown back', async () => {
    enableModule('agent-intake', true)
    const user = userEvent.setup()
    renderApp('/devices/setup?tab=wazuh')
    await screen.findByRole('region', { name: 'Wazuh' }, T)
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
    expect(await flow14()).toBe('on') // Settings → Privacy flow 14 while a Wazuh server is saved
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
    expect(await code({ interval_minutes: 4 })).toBe('bad_interval')
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
    // A new mktemp file every run (a fixed /tmp name left by another user cannot be overwritten), removed afterwards
    expect(lin).toMatch(/^\(command -v sudo >\/dev\/null 2>&1 \|\| sudo\(\) \{ "\$@"; \}; f=\$\(mktemp\) && \{ curl /) // a subshell: the install's exit status survives the cleanup; root without sudo (Alpine) runs the script itself
    // no curl (Alpine): busybox wget downloads the same file, and its checksum is checked all the same
    expect(lin).toContain(`-o "$f" || wget -qO "$f" --no-check-certificate ${BOX}/api/v1/install/osquery.sh; } && echo "${sha}  $f" | sha256sum -c -`)
    expect(lin).toContain('sudo sh "$f" --token vdt_osquery_x; r=$?; rm -f "$f"; exit $r)')
    expect(lin).not.toContain('/tmp/')
    expect(lin.match(/curl/g)).toHaveLength(1)
    expect(linuxOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).toMatch(/sudo sh "\$f" --uninstall; r=\$\?; rm -f "\$f"; exit \$r\)$/)
    expect(linuxOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).not.toContain('vdt_osquery_x')
    const win = windowsOneLiner(BOX, sha, 'vdt_osquery_x')
    expect(win).toContain(`curl.exe -fsSLk ${BOX}/api/v1/install/osquery.ps1`)
    expect(win).toContain(`-ieq '${sha}'`)
    expect(win).toContain("-Token 'vdt_osquery_x'")
    expect(win).toContain("throw 'Checksum mismatch: do not run this file'")
    expect(win).toContain("[guid]::NewGuid()")
    expect(win.match(/Remove-Item -Force \$f/g)).toHaveLength(2)
    expect(windowsOneLiner(BOX, sha, 'vdt_osquery_x', 'uninstall')).toContain('-Uninstall')
    for (const s of [lin, win]) expect(s).not.toMatch(/http:\/\/|localhost/)

    asAdmin()
    const pkgs = (await call('GET', '/agents')).json!.install.packages as OsqueryPackage[]
    for (const platform of ['linux', 'windows'] as const) {
      const steps = osquerySteps(platform, BOX, '<TOKEN>', pkgs)
      const flags = steps.find((s) => s.key === 'flags')!.code
      for (const f of ['--config_plugin=tls', '--logger_plugin=tls', 'enroll_secret_path', 'tls_server_certs', `--tls_hostname=192.168.10.250:8443`, '--enroll_tls_endpoint=/api/v1/intake/osquery/enroll', '--config_tls_endpoint=/api/v1/intake/osquery/config', '--config_refresh=300', '--logger_tls_endpoint=/api/v1/intake/osquery/log']) expect(flags, `${platform}: ${f}`).toContain(f)
      expect(flags).not.toContain('https://') // tls_hostname has the port and no scheme
      expect(steps.find((s) => s.key === 'secret')!.code).toContain('<TOKEN>')
      expect(steps.filter((s) => /-fsSk|-fsSLk/.test(s.code))).toHaveLength(1) // the certificate is fetched with -k once, to be checked by fingerprint
      expect(steps.find((s) => s.key === 'secret')!.code).toContain(platform === 'linux' ? 'openssl x509' : 'certutil -dump') // print the certificate so its fingerprint can be compared
    }
    expect(osquerySteps('linux', BOX, 't', pkgs).map((s) => s.key)).toEqual(['installDeb', 'installRpm', 'secret', 'flags', 'start'])
    expect(osquerySteps('windows', BOX, 't', pkgs).map((s) => s.key)).toEqual(['install', 'secret', 'flags', 'service'])
    // The box is the only source; each package is checked against the SHA-256 of this page before it is installed
    const all = [...osquerySteps('linux', BOX, 't', pkgs), ...osquerySteps('windows', BOX, 't', pkgs)].map((s) => s.code).join('\n')
    expect(all).not.toMatch(/osquery\.io|choco|yum-config-manager|apt-get/)
    for (const p of pkgs) expect(all).toContain(p.sha256)
    const deb = osquerySteps('linux', BOX, 't', pkgs).find((s) => s.key === 'installDeb')!.code
    // three lines that each stand alone (a file copied over skips the download line); the check and the install are one command
    const lines = deb.split('\n')
    expect(lines).toHaveLength(3)
    expect(lines[0]).toBe(`f=osquery_${OSQUERY_VERSION}-1.linux_$(dpkg --print-architecture).deb`)
    expect(lines[1]).toBe(`cd "$(mktemp -d)" && curl -fSLk ${BOX}/api/v1/install/osquery/$f -o $f`)
    // an architecture the box does not serve has no line: grep fails and nothing runs, whatever sha256sum does with empty input
    expect(lines[2]).toMatch(/^s=\$\(printf '%s\\n' ('[0-9a-f]{64} {2}osquery_\S+\.deb' ?){2}\| grep " \$f\\\$"\) && printf '%s\\n' "\$s" \| sha256sum -c - && sudo dpkg -i \$f$/)
    expect(osquerySteps('linux', BOX, 't', pkgs).find((s) => s.key === 'installRpm')!.code).toMatch(/^f=osquery-[\d.]+-1\.linux\.\$\(uname -m\)\.rpm\n[\s\S]*sha256sum -c - && sudo rpm -Uvh \$f$/)
    const msi = osquerySteps('windows', BOX, 't', pkgs).find((s) => s.key === 'install')!.code
    expect(msi).toContain(`curl.exe -fSLk ${BOX}/api/v1/install/osquery/osquery-${OSQUERY_VERSION}.msi`)
    expect(msi).toMatch(/-ieq '[0-9a-f]{64}'\) \{ \$p = Start-Process msiexec\.exe -Wait -PassThru .*-notin 0, 3010.*\} else \{ throw 'Checksum mismatch: do not install this file' \}$/)
    // no package on the box: no install step at all, never an outside source
    expect(osquerySteps('linux', BOX, 't', []).map((s) => s.key)).toEqual(['secret', 'flags', 'start'])
    expect(osquerySteps('windows', BOX, 't', []).map((s) => s.key)).toEqual(['secret', 'flags', 'service'])

    const sched = JSON.parse(OSQUERY_SCHEDULE).schedule as Record<string, { query: string; platform?: string }>
    expect(Object.keys(sched).sort()).toEqual(['deb_packages', 'interfaces', 'kernel_info', 'listening_ports', 'listening_ports_windows', 'os_revision', 'os_version', 'programs', 'rpm_packages', 'system_info']) // Identity query in, unused columns and patches out; INV-22: open ports
    expect(JSON.stringify(sched)).not.toMatch(/cpu_brand|physical_memory|patches/)
    expect(sched.interfaces!.query).toContain('interface_details')
    for (const q of Object.values(sched)) expect(q.query).toMatch(/^SELECT /) // read-only queries
    expect(sched.programs!.platform).toBe('windows')
    expect(sched.deb_packages!.platform).toBe('linux')
    expect(sched.os_revision!.platform).toBe('windows') // Windows's update revision, a Windows-only column of os_version
    expect(sched.os_revision!.query).not.toMatch(/registry/) // the revision comes from os_version, not the registry table
    // The one registry read is each SQL Server instance's PatchLevel, in the Windows programs query
    for (const [name, q] of Object.entries(sched)) if (name !== 'programs') expect(q.query).not.toMatch(/registry/)
    expect(sched.programs!.query).toContain("FROM registry r WHERE r.key LIKE 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQL%\\Setup' AND r.name = 'PatchLevel' UNION ALL")
    expect(sched.programs!.query).toMatch(/FROM programs;$/)

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
      ['/devices/a-nas02?tab=observations', () => screen.findByRole('table', { name: 'Observations for this device' }, T)],
      ['/devices/setup?tab=sensor', () => screen.findByRole('region', { name: 'Sensor on this box' }, T)],
      ['/devices/setup?tab=snmp', () => screen.findByRole('tab', { name: 'Engines', selected: true }, T)],
      ['/devices?add=snmp', () => screen.findByRole('dialog', { name: 'Add a device' }, T)],
      ['/settings/declared-software', () => screen.findByRole('heading', { level: 2, name: 'Declared software' }, T)],
      ['/devices/setup?tab=agents', () => screen.findByRole('table', { name: 'Enrollment tokens' }, T)],
    ]
    for (const [path, ready] of checks) {
      const { unmount } = renderApp(path)
      await ready()
      if (!path.startsWith('/settings')) await screen.findAllByText('Sample data', undefined, T) // Settings pages carry no sample note
      const text = document.body.textContent ?? ''
      const hit = text.match(new RegExp(`.{0,30}${VI.source}.{0,30}`, 'i'))
      expect(hit?.[0] ?? null, `${path} has Vietnamese text`).toBeNull()
      unmount()
    }
  })

  it('the open dialogs (add, import, delete, sensor, agent token) and the API error messages are English too', async () => {
    const user = userEvent.setup()
    enableModule('agent-intake', true)
    renderApp('/devices/setup?tab=agents')
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

describe('inventory: the box is the first device (S-INV-5)', () => {
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

  it('it is matched against exploited vulnerabilities like any device (the fix line: boxNotice.test.tsx)', async () => {
    renderApp(`/devices/${BOX_ID}?tab=software`)
    expect(await screen.findByText('This is the Vedette box itself', undefined, T)).toBeInTheDocument()
    expect(findingsStore.get().some((f) => f.asset_id === BOX_ID)).toBe(true)
    const sw = screen.getByRole('table', { name: 'Software on the device' })
    expect(within(sw).getAllByText('This box').length).toBeGreaterThan(5)
    expect(screen.getAllByText('This box').length).toBeGreaterThan(1) // badge and software sources
    await expectNoA11yViolations()
  })

  it('the box\'s own open services are read by the box itself: "This box", not "Agent"', async () => {
    renderApp(`/devices/${BOX_ID}?tab=services`)
    const table = await screen.findByRole('table', { name: 'Services open on the device' }, T)
    const ssh = within(table).getByText('sshd').closest('tr')!
    expect(within(ssh).getByText('This box')).toBeInTheDocument()
    expect(within(table).queryByText('Agent')).toBeNull()
  })

  it('S-CORE-9: on the appliance the box page says its packages are read with dpkg', async () => {
    renderApp(`/devices/${BOX_ID}`)
    expect(await screen.findByText(/Its packages are read from the box \(dpkg\)/, undefined, T)).toBeInTheDocument()
  })

  it('S-CORE-9: on a container-only install the box page says there is no package list and never mentions dpkg', async () => {
    installStore.set({ kind: 'container' })
    try {
      renderApp(`/devices/${BOX_ID}`)
      expect(await screen.findByText(/The package list of this machine is not available in a container-only install\./, undefined, T)).toBeInTheDocument()
      expect(screen.queryByText(/dpkg/)).not.toBeInTheDocument()
    } finally { installStore.set({ kind: 'appliance' }) }
  })

  it('it cannot be deleted: no Remove is offered (the page says why) and the server refuses', async () => {
    asAdmin()
    renderApp(`/devices/${BOX_ID}`)
    expect((await screen.findAllByText('The box cannot be removed from the list: Vedette runs on it.', undefined, T)).length).toBeGreaterThan(0)
    expect(screen.queryByRole('button', { name: 'More' })).toBeNull()
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
    expect(await screen.findByRole('heading', { level: 1, name: 'Devices' }, T)).toBeInTheDocument()
    expect(await screen.findByText('No other devices yet', undefined, T)).toBeInTheDocument() // the empty state with the next actions
    expect(within(await deviceTable()).getByText('This box')).toBeInTheDocument()
    setDataMode('sample')
  })
})

describe('inventory: form matrix', () => {
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
    // the fields do not look filled while the form holds nothing: they start empty, and Add says a product is missing until both are typed
    expect(within(dlg).getByLabelText('Maker')).toHaveValue('')
    expect(within(dlg).getByLabelText('Product')).toHaveValue('')
    await user.type(within(dlg).getByLabelText('IP address'), '192.0.2.77')
    await user.click(within(dlg).getByRole('button', { name: 'Add' }))
    expect(await within(dlg).findByText(/Pick the product this device runs/, undefined, T)).toBeInTheDocument()
  })

  it('the server refuses active scanning without the scope confirmation', async () => {
    asAdmin()
    const cur = (await call('GET', '/settings')).json as Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any
    const r = await call('PUT', '/settings', { ...cur, active: { ...cur.active, enabled: true }, scope_confirmed: false })
    expect(r.status).toBe(400)
    expect(r.json?.error?.code).toBe('scope_not_confirmed')
  })
})

describe('inventory: merging observations follows the source priority (DATA_MODEL §5.1)', () => {
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

describe('inventory: naming, versions, Software tab (S-INV-2)', () => {
  const addOffice = async (body: Record<string, string> = {}) => {
    asAdmin()
    const r = await call('POST', '/devices', { vendor: 'Microsoft', product: 'Office', ...body })
    expect(r.status).toBe(201)
    return r.json!.id as string
  }

  it('#849: a product declared with no name and no IP is not a device: it reads "<product> (no device)" in Settings › Declared software, not in Devices', async () => {
    const user = userEvent.setup()
    await addOffice()
    const first = renderApp('/devices')
    const table = await deviceTable()
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'office')
    await waitFor(() => expect(within(table).queryByRole('link', { name: 'Microsoft Office (no device)' })).toBeNull(), T)
    expect(screen.getByRole('link', { name: 'Settings, Declared software' })).toHaveAttribute('href', '/settings/declared-software')
    first.unmount()
    renderApp('/settings/declared-software')
    const list = await screen.findByRole('table', { name: 'Declared software' }, T)
    expect(within(list).getByRole('link', { name: 'Microsoft Office' })).toBeInTheDocument()
    await expectNoA11yViolations()
  })

  it('#849: Settings › Declared software adds a product with no device (it still feeds Findings), changes its version, removes it', async () => {
    const user = userEvent.setup()
    asAdmin()
    renderApp('/settings/declared-software')
    await screen.findByRole('heading', { level: 2, name: 'Declared software' }, T)
    await user.click(screen.getAllByRole('button', { name: 'Add software' })[0]!)
    const dlg = await screen.findByRole('dialog', { name: 'Add declared software' }, T)
    expect(within(dlg).queryByLabelText('IP address')).toBeNull()
    await user.type(within(dlg).getByRole('combobox', { name: 'Product' }), 'fortigate')
    await user.click((await screen.findAllByRole('option', { name: /FortiGate/ }, T))[0]!)
    await user.click(within(dlg).getByRole('button', { name: 'Add' }))
    const list = await screen.findByRole('table', { name: 'Declared software' }, T)
    const a = await waitFor(() => { const x = assetsStore.get().find((d) => d.origin === 'manual' && d.ip === '—' && d.software[0]?.vendor === 'Fortinet'); expect(x).toBeDefined(); return x! }, T)
    expect(a.software[0]!.kev).toContain('fortinet|fortios') // matched against exploited CVEs by its product
    const name = a.software[0]!.display
    await user.click(within(list).getByRole('button', { name: `Change the version of ${name}` }))
    const v = await screen.findByRole('dialog', { name: new RegExp(name) }, T)
    await user.type(within(v).getByLabelText(/Version/), '7.0.1')
    await user.click(within(v).getByRole('button', { name: /Save/ }))
    await waitFor(() => expect(find(a.id).software[0]!.version).toBe('7.0.1'), T)
    await user.click(within(list).getByRole('button', { name: `Remove ${name}` }))
    await user.click(within(await screen.findByRole('dialog', undefined, T)).getByRole('button', { name: 'Remove from list' }))
    await waitFor(() => expect(assetsStore.get().find((d) => d.id === a.id)).toBeUndefined(), T)
  })

  it('a typed version and an agent\'s reading of one software are one line: the agent\'s value, the entry listed under it, no notice', async () => {
    const id = await addOffice({ version: '2019', ip: '192.168.10.240' })
    assetsStore.update((l) => l.map((a) => (a.id === id ? { ...a, software: [...a.software, { ...a.software[0]!, id: 'sw-agent-office', version: '2021', source: 'agent' as const, confidence: 0.95 }] } : a)))
    renderApp(`/devices/${id}?tab=software`)
    // the rows render again once the device's other reads arrive: assert on the row in the document, not on the first one found
    await waitFor(() => expect(screen.getByText(/Also seen by: 2019 \(Manual/)).toBeInTheDocument(), T)
    expect(within(screen.getByRole('table', { name: 'Software on the device' })).getAllByText('Microsoft Office')).toHaveLength(1)
    expect(screen.queryByText(/another release/)).not.toBeInTheDocument()
  })

  it('PATCH software version: in place on a declared row, version checked, empty removes it; a reported row gets a correction (INV-41)', async () => {
    const id = await addOffice({ version: '2019' })
    const sid = find(id).software[0]!.id
    expect((await call('PATCH', `/devices/${id}/software/${sid}`, { version: '<b>' })).json!.error.code).toBe('bad_version')
    expect((await call('PATCH', `/devices/${id}/software/${sid}`, { version: '2024' })).status).toBe(200)
    expect(find(id).software[0]!.version).toBe('2024')
    expect((await call('PATCH', `/devices/${id}/software/${sid}`, { version: '' })).status).toBe(200)
    expect(find(id).software[0]!.version).toBeNull()
    const agent = assetsStore.get().find((a) => a.software.some((s) => s.source !== 'manual'))!
    const asid = agent.software.find((s) => s.source !== 'manual')!.id
    expect((await call('PATCH', `/devices/${agent.id}/software/${asid}`, { version: '1' })).status).toBe(200)
    const sw = find(agent.id).software
    expect(sw.find((s) => s.id === asid)!.version).not.toBe('1') // the reported row stays as the source read it
    expect(sw.find((s) => s.corrects === asid)).toMatchObject({ source: 'manual', version: '1' })
    const reported = sw.find((s) => s.id === asid)!
    const lines = (await call('GET', `/devices/${agent.id}`)).json!.asset.software as { product: string; vendor: string; correction?: { set_at: string } }[]
    const mine = lines.filter((l) => l.product === reported.product && l.vendor === reported.vendor)
    expect(mine).toHaveLength(1) // one line of the software, which carries the person's version
    expect(mine[0]!.correction).toBeDefined()
    expect((await call('PATCH', `/devices/${agent.id}/software/${asid}`, {})).json!.error.code).toBe('bad_edit')
    expect((await call('PATCH', `/devices/${agent.id}/software/${asid}`, { pkg_version: '10.2 p1' })).json!.error.code).toBe('bad_pkg_version')
  })
})

describe('inventory: rename a device (S-INV-1)', () => {
  const nas = () => find('a-nas02')

  it('Rename next to the title: Enter saves the name in Vedette, the host name stays apart, empty gives the default name back', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'operator' })
    expect(await screen.findByRole('heading', { level: 1, name: 'NAS-PHOTOS' }, T)).toBeInTheDocument()
    expect(screen.getByTestId('device-hostname')).toHaveTextContent('NAS-PHOTOS')
    await user.click(screen.getByRole('button', { name: 'Rename device' }))
    const field = screen.getByRole('textbox', { name: 'Name in Vedette' })
    expect(field).toHaveFocus()
    expect(field).toHaveValue('')
    expect(field).toHaveAttribute('placeholder', 'NAS-PHOTOS') // what an empty name shows
    expect(screen.getByText(/Leave it empty for the default name, NAS-PHOTOS/)).toBeInTheDocument()
    await expectNoA11yViolations()
    await user.type(field, '  Photo NAS  {Enter}')
    expect(await screen.findByRole('heading', { level: 1, name: 'Photo NAS' }, T)).toBeInTheDocument()
    expect(nas().name).toBe('Photo NAS')
    expect(nas().hostname).toBe('NAS-PHOTOS') // the observed host name is not changed
    expect(screen.getByTestId('device-hostname')).toHaveTextContent('NAS-PHOTOS')
    await waitFor(() => expect(screen.getByRole('button', { name: 'Rename device' })).toHaveFocus(), T)
    expect(auditStore.get().find((e) => e.action === 'inventory.rename')).toMatchObject({ target: 'Photo NAS' })

    // Escape cancels without saving
    await user.click(screen.getByRole('button', { name: 'Rename device' }))
    expect(screen.getByRole('textbox', { name: 'Name in Vedette' })).toHaveValue('Photo NAS')
    await user.type(screen.getByRole('textbox', { name: 'Name in Vedette' }), 'xyz{Escape}')
    expect(screen.queryByRole('textbox', { name: 'Name in Vedette' })).toBeNull()
    expect(nas().name).toBe('Photo NAS')

    // empty + Save: the default name again
    await user.click(screen.getByRole('button', { name: 'Rename device' }))
    await user.clear(screen.getByRole('textbox', { name: 'Name in Vedette' }))
    await user.click(screen.getByRole('button', { name: 'Save' }))
    expect(await screen.findByRole('heading', { level: 1, name: 'NAS-PHOTOS' }, T)).toBeInTheDocument()
    expect(nas().name ?? null).toBeNull()
  })

  it('a name with < or > is refused before it is sent', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'operator' })
    await user.click(await screen.findByRole('button', { name: 'Rename device' }, T))
    await user.type(screen.getByRole('textbox', { name: 'Name in Vedette' }), 'a<b')
    expect(screen.getByText('A name cannot contain < or >, control characters or invisible characters.')).toBeInTheDocument()
    expect(screen.getByRole('dialog', { name: 'Rename device' })).toBeInTheDocument() // a dialog over the page, not a field in the title
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
  })

  it('#929: invisible and bidi characters are refused like < >; a refused save keeps the focus and says why next to the field', async () => {
    const user = userEvent.setup()
    renderApp('/devices/a-nas02', { role: 'operator' })
    await user.click(await screen.findByRole('button', { name: 'Rename device' }, T))
    const field = screen.getByRole('textbox', { name: 'Name in Vedette' })
    fireEvent.change(field, { target: { value: '\u202eresu-lawerif' } })
    expect(screen.getByText(/invisible characters/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    fireEvent.change(field, { target: { value: 'fw\u200bcore' } })
    expect(screen.getByRole('button', { name: 'Save' })).toBeDisabled()
    server.use(http.patch(`${location.origin}/api/v1/inventory/devices/:id`, () => HttpResponse.json({ error: { code: 'forbidden', message: 'You need the operator role.' } }, { status: 403 })))
    await user.clear(field)
    await user.type(field, 'Photo NAS{Enter}')
    expect(await screen.findByText('You need the operator role.', undefined, T)).toBeInTheDocument()
    await waitFor(() => expect(screen.getByRole('textbox', { name: 'Name in Vedette' })).toHaveFocus(), T)
    expect(screen.getByRole('textbox', { name: 'Name in Vedette' })).toHaveAttribute('aria-invalid', 'true')
    expect(nas().name ?? null).toBeNull()
  })

  it('#929: the CSV export keeps the host name and the name in Vedette apart, and import reads both back', async () => {
    asAdmin()
    expect((await call('PATCH', '/devices/a-nas02', { name: 'Photo NAS' })).status).toBe(200)
    const csv = (await call('GET', '/export.csv')).text
    expect(csv).toContain('last_seen,name_in_vedette')
    expect(csv).toMatch(/\r\nNAS-PHOTOS,[^\r]*,Photo NAS,[^,\r]*\r\n/)
    const r = await call('POST', '/import', { filename: 'x.csv', size: 1, sha256: 'x', text: 'name,ip,name_in_vedette\nfw-core,192.168.77.1,Office firewall\n' })
    expect(r.json!.created).toBe(1)
    const a = assetsStore.get().find((x) => x.ip === '192.168.77.1')!
    expect([a.hostname, a.name]).toEqual(['fw-core', 'Office firewall'])
  })

  it('a viewer cannot rename', async () => {
    renderApp('/devices/a-nas02', { role: 'viewer' })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Rename device' })).toBeDisabled(), T)
  })

  it('the Devices list shows the name in Vedette and the search finds it', async () => {
    const user = userEvent.setup()
    assetsStore.update((l) => l.map((a) => (a.id === 'a-nas02' ? { ...a, name: 'Photo NAS' } : a)))
    renderApp('/devices')
    const table = await deviceTable()
    await user.type(screen.getByRole('combobox', { name: 'Search devices' }), 'photo nas')
    expect(await within(table).findByRole('link', { name: 'Photo NAS' }, T)).toHaveAttribute('href', '/devices/a-nas02')
  })

  it('PATCH name: trimmed, at most 64 characters, no < or >, empty clears it', async () => {
    asAdmin()
    expect((await call('PATCH', '/devices/a-nas02', { name: 'a>b' })).json!.error.code).toBe('bad_name')
    expect((await call('PATCH', '/devices/a-nas02', { name: 'x'.repeat(65) })).json!.error.code).toBe('bad_name')
    expect((await call('PATCH', '/devices/a-nas02', { name: ' Photo NAS ' })).status).toBe(200)
    expect((await call('GET', '/devices/a-nas02')).json!.asset.name).toBe('Photo NAS')
    expect((await call('PATCH', '/devices/a-nas02', { name: '' })).status).toBe(200)
    expect((await call('GET', '/devices/a-nas02')).json!.asset.name).toBeNull()
  })
})
