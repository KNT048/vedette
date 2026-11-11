// Devices -> Scope and sensors on the real backend: the scan scope (S-INV-3 notify-new, D-26 confirmation, INV-6 ranges, INV-7 window).
// Steps from e2e/qa/inventory.spec.ts ("Admin: scan scope"). The scope is one setting of the whole box, so this runs in the global project, alone,
// and puts a known scope in place before each test through the API (a precondition, not what is tested). What only a real box shows:
// the real backend refuses the same ranges the form refuses, a save survives a reload, the confirmation (who and when) is stored, and
// the audit log holds the line. The sensor and agent sections are slice 7 and not wired (agent-intake): not covered here.
import { expect, test } from '@playwright/test'
import { ACCOUNTS, api, authFile } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface St { lan_ranges: string[]; active: { enabled: boolean; days: number[]; from: string; to: string; rate: number; exclusions: string[] }; fragile_kinds: string[]; regular_scan_kinds: string[]; scope_confirmed_at: string | null; scope_confirmed_by: string | null }
const BASE = { lan_ranges: ['192.168.10.0/24', '192.168.20.0/24'], active: { enabled: false, days: [1, 2, 3, 4, 5, 6, 7], from: '23:00', to: '05:00', rate: 50, exclusions: [] as string[] } }

let activeWasOn = true
test.beforeEach(async ({ page }) => {
  // The window form belongs to the Active sensor module (it is off until the person turns it on): a precondition here, put back after each test.
  const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(page.request, 'GET', '/modules')
  activeWasOn = !!mods.body.modules.find((m) => m.id === 'sensor-active')?.enabled
  if (!activeWasOn) {
    const on = await api(page.request, 'PATCH', '/modules/sensor-active', { enabled: true, with_dependencies: true })
    expect(on.status, `enable sensor-active: ${JSON.stringify(on.body)}`).toBe(200)
  }
  const cur = await api<St>(page.request, 'GET', '/inventory/settings')
  expect(cur.status).toBe(200)
  const put = await api(page.request, 'PUT', '/inventory/settings', { ...cur.body, ...BASE, scope_confirmed: true })
  expect(put.status, `known scope: ${JSON.stringify(put.body)}`).toBe(200)
})

// Active scanning must never stay on after a test: a sensor of another spec could then scan these ranges. Back to the known scope, switched off.
test.afterEach(async ({ page }) => {
  const cur = await api<St>(page.request, 'GET', '/inventory/settings')
  const back = await api(page.request, 'PUT', '/inventory/settings', { ...cur.body, ...BASE, scope_confirmed: true })
  expect(back.status, `active scanning back off: ${JSON.stringify(back.body)}`).toBe(200)
  if (!activeWasOn) expect((await api(page.request, 'PATCH', '/modules/sensor-active', { enabled: false })).status, 'sensor-active back off').toBe(200)
})

const rows = (page: import('@playwright/test').Page) => page.getByRole('list', { name: 'Ranges added' }).getByRole('listitem')
const save = (page: import('@playwright/test').Page) => page.getByRole('button', { name: 'Save changes' })

test('ranges: invalid, public, overlapping and duplicate ones are refused with the reason; a range with no size is never guessed; host bits are cleared; edit and remove; save survives a reload', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/devices/setup')
  await expect(rows(page)).toHaveCount(2)
  const input = page.locator('#range-input')
  const err = page.locator('#range-input-error')
  for (const [value, msg] of [['abc', /not a valid range/], ['8.8.8.0/24', /not an internal range/], ['192.168.10.0/25', /overlaps/], ['192.168.10.0/24', /already in the list/]] as const) {
    await input.fill(value); await input.press('Enter')
    await expect(err, value).toContainText(msg)
  }
  await expect(rows(page)).toHaveCount(2)
  await input.fill('192.168.18.0'); await input.press('Enter')
  await expect(err).toContainText('has no prefix length')
  await expect(rows(page)).toHaveCount(2)
  await input.fill('192.168.18.0/25'); await input.press('Enter')
  await expect(rows(page)).toHaveCount(3)
  await input.fill('192.168.30.77/24'); await input.press('Enter')
  await expect(page.getByRole('status').filter({ hasText: '192.168.30.0/24' })).toBeVisible()
  await expect(rows(page)).toHaveCount(4)
  await page.getByRole('button', { name: 'Edit range 192.168.30.0/24' }).click()
  await expect(input).toHaveValue('192.168.30.0/24')
  await input.fill('192.168.31.0/24'); await input.press('Enter')
  await page.getByRole('button', { name: 'Remove range 192.168.18.0/25' }).click()
  await expect(rows(page)).toHaveCount(3)
  await shot(page, 'real-scope', 'ranges-edited')
  // the set of ranges changed, so the scope must be confirmed again before Save
  await expect(page.getByLabel(/I confirm these network ranges/)).not.toBeChecked()
  await expect(page.locator('#scope').getByRole('status').first()).toContainText('Tick to confirm before saving.')
  await page.getByLabel(/I confirm these network ranges/).check()
  await page.getByLabel('Turn on active scanning').check()
  await page.locator('#active-to').fill('23:00')
  await save(page).click()
  await expect(page.getByRole('alert').filter({ hasText: 'cannot be the same' })).toBeVisible()
  await page.locator('#active-from').fill('22:00'); await page.locator('#active-to').fill('06:00') // across midnight
  await page.locator('#excl-input').fill('192.168.31.0/24'); await page.locator('#excl-input').press('Enter')
  await save(page).click()
  await expect(page.getByText('You have unsaved changes.')).toBeHidden()
  await page.reload()
  await expect(page.locator('#active-from')).toHaveValue('22:00')
  await expect(rows(page)).toHaveCount(3)
  await expect(h1(page)).toContainText('3 network ranges')
  const st = (await api<St>(page.request, 'GET', '/inventory/settings')).body
  expect(st.lan_ranges.sort()).toEqual(['192.168.10.0/24', '192.168.20.0/24', '192.168.31.0/24'])
  expect(st.active).toMatchObject({ from: '22:00', to: '06:00' })
  expect(st.scope_confirmed_by, 'who confirmed the scope').toBeTruthy()
  expect(st.scope_confirmed_at, 'when').toBeTruthy()
  await noVietnamese(page, 'scope')
  await expectAccessible(page, 'scope')
  noErrors(errors, /status of (4|5)\d\d/)
})

test('the scope is confirmed again only when the set of ranges changed; Enter adds a range', async ({ page }) => {
  await page.goto('/devices/setup')
  const bar = page.locator('#scope')
  const confirm = bar.getByLabel(/I confirm these network ranges/)
  await expect(confirm).toBeChecked() // the known scope was confirmed
  await page.getByLabel('Turn on active scanning').check()
  await page.locator('#active-from').fill('21:00')
  await bar.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('You have unsaved changes.')).toBeHidden()
  await expect(page.getByRole('alert')).toHaveCount(0)
  const before = (await api<St>(page.request, 'GET', '/inventory/settings')).body
  expect(before.active).toMatchObject({ enabled: true, from: '21:00' })
  expect(before.scope_confirmed_at, 'the earlier confirmation stays').toBeTruthy()
  await page.waitForTimeout(1100) // the stored time has one-second resolution and the box has no fake clock
  await page.locator('#range-input').fill('192.168.60.0/24')
  await page.locator('#range-input').press('Enter')
  await expect(rows(page)).toHaveCount(3)
  await expect(confirm).not.toBeChecked()
  await expect(bar.getByRole('status').first()).toContainText('Tick to confirm before saving.')
  await shot(page, 'real-scope', 'confirm-inline')
  await confirm.check()
  await bar.getByRole('button', { name: 'Save changes' }).click()
  await expect(page.getByText('You have unsaved changes.')).toBeHidden()
  const after = (await api<St>(page.request, 'GET', '/inventory/settings')).body
  expect(after.lan_ranges).toContain('192.168.60.0/24')
  expect(after.scope_confirmed_at, 'confirmation time moved with the new range').not.toBe(before.scope_confirmed_at)
})

test('the backend refuses what the form refuses (INV-6, INV-7), and nothing is saved', async ({ page }) => {
  const cur = (await api<St>(page.request, 'GET', '/inventory/settings')).body
  const put = (over: Partial<St> & { scope_confirmed?: boolean; active?: Partial<St['active']> }) =>
    api<{ code?: string }>(page.request, 'PUT', '/inventory/settings', { ...cur, ...over, active: { ...cur.active, ...over.active }, scope_confirmed: over.scope_confirmed ?? true })
  for (const [label, body] of [
    ['a range with no prefix', { lan_ranges: ['192.168.10.0'] }],
    ['a public range', { lan_ranges: ['8.8.8.0/24'] }],
    ['17 ranges', { lan_ranges: Array.from({ length: 17 }, (_, i) => `10.${i}.0.0/24`) }],
    ['active scanning with no confirmation', { active: { enabled: true }, scope_confirmed: false, lan_ranges: ['192.168.99.0/24'] }],
    ['a window from 22:00 to 22:00', { active: { from: '22:00', to: '22:00' } }],
    ['a day outside 1..7', { active: { days: [0] } }],
    ['a rate of 0', { active: { rate: 0 } }],
  ] as const) {
    const r = await put(body as never)
    expect(r.status, `${label}: ${JSON.stringify(r.body)}`).toBe(400)
  }
  const now = (await api<St>(page.request, 'GET', '/inventory/settings')).body
  expect(now, 'nothing saved after the refusals').toEqual(cur)
  // host bits are not an error: the range is cleared to its network, keeping the typed prefix, and the answer says so (the form shows it as a note)
  const bits = await put({ lan_ranges: ['192.168.10.5/24'] })
  expect(bits.status).toBe(200)
  expect(bits.body).toMatchObject({ adjusted: [{ from: '192.168.10.5/24', to: '192.168.10.0/24' }], lan_ranges: ['192.168.10.0/24'] })
})

test('who can read and change the scope: operator and viewer are refused by the backend', async ({ browser }) => {
  for (const role of ['operator', 'viewer'] as const) {
    const ctx = await browser.newContext({ storageState: authFile(role) })
    const g = await api(ctx.request, 'GET', '/inventory/settings')
    expect(g.status, `${ACCOUNTS[role].email} GET /inventory/settings`).toBe(403)
    const p = await api(ctx.request, 'PUT', '/inventory/settings', { ...BASE, fragile_kinds: [], regular_scan_kinds: [], scope_confirmed: true })
    expect(p.status, `${role} PUT /inventory/settings`).toBe(403)
    await ctx.close()
  }
})

test('alert on new devices (S-INV-3): an operator turns it on and off, each change is saved and written to the audit log', async ({ browser, page }) => {
  const op = await browser.newContext({ storageState: authFile('operator') })
  try {
    const auditCount = async () => (await api<{ items: { action: string }[] }>(page.request, 'GET', '/core/audit?q=inventory.notify_new')).body.items.filter((a) => a.action === 'inventory.notify_new').length
    const before = await auditCount()
    for (const enabled of [true, false]) {
      const r = await api<{ enabled: boolean }>(op.request, 'PUT', '/inventory/notify-new', { enabled })
      expect(r.status, `notify-new ${enabled}`).toBe(200)
      expect(r.body.enabled).toBe(enabled)
    }
    expect(await auditCount(), 'audit rows written by the two changes').toBe(before + 2)
  } finally {
    await op.close() // the switch ends off, as the box starts
  }
})

test.fixme('the "new devices not approved" panel shows the alert switch and the approve list', async () => {
  // needs a device the sensors found (approved=false): slice 7 (passive sensor in the box). Copy the panel steps of e2e/qa/inventory.spec.ts then.
})
