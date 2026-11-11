// The exposure module on the real backend: what changes box-wide state (S-EXP-1, exposure INV-5 (20 targets), INV-11 (the settings: interval 1..1440, admin only, audited), PRE-4).
// Global project: the settings are one row for the whole box and the 20-target limit counts every domain, so these tests run one at a time and give the box back as they found it
// (afterEach removes every domain by name and checks the status; afterAll puts the settings back and reads them back).
// NO TEST HERE TURNS AUTO-DETECT ON, presses Detect now or Verify again, or presses the DNS Check: those make the box call the public IP services or real DNS, and the box has no setting
// that points them at a loopback fake. Turning auto-detect on runs a detection in the same request (INV-11). So the settings are changed only with auto-detect OFF, as the seed leaves it,
// and the file refuses to run if it is on. See .ai/deferred/feat-e2e-real-exposure.md.
import { expect, test } from '@playwright/test'
import { ACCOUNTS, api, authFile } from './box'
import { as, audit, auditIds, autoLine, domain, headline, list, made, refused, snapshot, sweep, type ApiErr, type BoxIp } from './exposure-shared'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

let original: BoxIp
test.beforeAll(async () => {
  const c = await as('admin')
  try {
    original = (await list(c)).box_ip
    expect(original.auto, 'this file needs auto-detect OFF (seed.setup.ts turns it off): with it on, the box would call the public IP services').toBe(false)
  } finally { await c.dispose() }
})
test.afterEach(sweep)
/** Gives the box back: the settings the run started with, read back. */
test.afterAll(async () => {
  const c = await as('admin')
  try {
    const put = await api(c, 'PUT', '/exposure/box-ip/settings', { auto: original.auto, interval_min: original.interval_min })
    expect(put.status, 'restoring the settings').toBe(200)
    const after = (await list(c)).box_ip
    expect({ auto: after.auto, interval_min: after.interval_min }, 'the settings are as the run found them').toEqual({ auto: original.auto, interval_min: original.interval_min })
  } finally { await c.dispose() }
})

test('the check interval: 1 to 1440 minutes is saved and audited, anything else is refused with the exact answer and saves nothing (INV-11)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const admin = await as('admin')
  try {
    const before = await snapshot(admin)
    const ids = await auditIds(admin, 'exposure.box_ip_settings')
    const newRows = async () => (await audit(admin, 'exposure.box_ip_settings')).filter((r) => !ids.has(r.id))

    // refused: out of range (a sentence of its own) and not a number of minutes (the schema's)
    const BAD = refused(400, 'bad_interval', 'Choose how often to check: every minute up to every 24 hours (1440 minutes).')
    for (const n of [0, -1, 1441, 100_000]) expect(await api<ApiErr>(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: n }), `interval ${n}`).toMatchObject(BAD)
    for (const body of [{ auto: false, interval_min: 1.5 }, { auto: false, interval_min: '60' }, { auto: false, interval_min: null }, { auto: false }, { interval_min: 15 }, { auto: 'no', interval_min: 15 }]) {
      expect((await api(admin, 'PUT', '/exposure/box-ip/settings', body)).status, JSON.stringify(body)).toBe(400)
    }
    expect(await snapshot(admin), 'a refusal saves nothing').toBe(before)
    expect(await newRows(), 'a refusal is not an audit row').toEqual([])

    // accepted: both ends and two values in between; each answer is what the next read says, and each is one audit row by the administrator
    const steps = [1, 1440, 5, 15]
    for (const n of steps) {
      const put = await api<BoxIp>(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: n })
      expect(put.status, `interval ${n}: ${JSON.stringify(put.body)}`).toBe(200)
      expect(put.body).toEqual({ auto: false, interval_min: n, last_run: original.last_run, retry_in_min: null }) // nothing was detected, so the last run is the one the box had
      expect((await list(admin)).box_ip, `interval ${n} is stored`).toEqual(put.body)
    }
    const rows = await newRows()
    expect(rows.map((r) => [r.action, r.user, r.target, r.detail]).sort()).toEqual(
      steps.map((n) => ['exposure.box_ip_settings', ACCOUNTS.admin.email, 'box', `auto-detect off, every ${n} minutes`]).sort(),
    )
    // the stored interval is untouched by a later refusal
    expect((await api<ApiErr>(admin, 'PUT', '/exposure/box-ip/settings', { auto: false, interval_min: 1441 })).status).toBe(400)
    expect((await list(admin)).box_ip.interval_min).toBe(15)

    // the page, with auto-detect off and 15 minutes stored: it says it is off, offers no interval (nothing runs by itself), and keeps Detect now (not pressed)
    await page.goto('/exposure')
    const box = page.locator('#box-ip')
    const now = await list(admin)
    await expect(h1(page)).toHaveText(headline(now.items))
    await expect(box.getByText(autoLine(now.box_ip), { exact: true })).toBeVisible()
    await expect(box.getByText('Auto-detect is off: the box checks only when you select Detect now.', { exact: true })).toBeVisible()
    await expect(box.getByRole('switch', { name: "Detect the box's public IPs automatically" })).not.toBeChecked()
    await expect(box.getByRole('switch', { name: "Detect the box's public IPs automatically" })).toBeEnabled()
    await expect(box.getByRole('combobox', { name: 'Check every' })).toHaveCount(0)
    await expect(box.getByRole('button', { name: 'Detect now' })).toBeEnabled()
    await expect(box.getByText('Turn it off to add IPs only when you select Detect now. The list below stays as it is.')).toBeVisible()
    await expectAccessible(page, 'exposure with auto-detect off')
    await noVietnamese(page, 'exposure with auto-detect off')
    await shot(page, 'real', 'exposure-auto-off')
    noErrors(errors)
  } finally { await admin.dispose() }
})

test('twenty targets at most: the 21st is refused with the exact answer, in the API and in the form, and nothing is saved (INV-5)', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const admin = await as('admin')
  try {
    const have = (await list(admin)).items.length
    const ids = await auditIds(admin, 'exposure.target_add')
    const values: string[] = []
    for (let i = have; i < 20; i++) {
      const value = domain()
      made.push(value)
      values.push(value)
      const r = await api(admin, 'POST', '/exposure/targets', { value })
      expect(r.status, `target ${i + 1}: ${JSON.stringify(r.body)}`).toBe(201)
    }
    expect(values.length, 'room for at least one domain').toBeGreaterThan(0)
    const all = (await list(admin)).items
    expect(all, 'the box holds exactly 20').toHaveLength(20)
    const domains = all.filter((i) => i.kind === 'domain').length
    const full = await snapshot(admin)
    const TOO_MANY = refused(400, 'too_many', 'At most 20 targets. Delete ones you no longer use.')
    const extra = domain()
    made.push(extra) // removed by the sweep if the box wrongly saved it
    expect(await api<ApiErr>(admin, 'POST', '/exposure/targets', { value: extra })).toMatchObject(TOO_MANY)
    expect(await snapshot(admin), 'the 21st saved nothing').toBe(full)

    await page.goto('/exposure')
    await expect(h1(page)).toHaveText(headline((await list(admin)).items))
    await expect(page.getByRole('table', { name: 'Declared domains' }).getByRole('row')).toHaveCount(domains + 1) // header + the domains
    await page.getByRole('button', { name: 'Add domain' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add a domain' })
    await dlg.getByRole('textbox', { name: 'Domain' }).fill(extra)
    const reply = page.waitForResponse((r) => r.url().endsWith('/api/v1/exposure/targets') && r.request().method() === 'POST')
    await dlg.getByRole('textbox', { name: 'Domain' }).press('Enter')
    expect((await reply).status()).toBe(400)
    await expect(dlg.getByText('At most 20 targets. Delete ones you no longer use.', { exact: true })).toBeVisible()
    await expect(dlg.getByRole('textbox', { name: 'Domain' })).toHaveValue(extra)
    await page.keyboard.press('Escape')
    expect(await snapshot(admin), 'the form saved nothing either').toBe(full)
    // a removed target frees a place: the same 21st name is accepted, then removed again by the sweep
    const first = (await list(admin)).items.find((i) => i.value === values[0])!
    expect((await api(admin, 'DELETE', `/exposure/targets/${first.id}`)).status).toBe(204)
    const ok = await api(admin, 'POST', '/exposure/targets', { value: extra })
    expect(ok.status, JSON.stringify(ok.body)).toBe(201)
    // one audit row per target saved (and none for the refusals)
    const added = (await audit(admin, 'exposure.target_add')).filter((r) => !ids.has(r.id))
    expect(added.map((r) => r.target).sort()).toEqual([...values, extra].sort())
    for (const r of added) expect([r.action, r.user]).toEqual(['exposure.target_add', ACCOUNTS.admin.email])
    await shot(page, 'real', 'exposure-twenty')
    noErrors(errors, /status of 400/)
  } finally { await admin.dispose() }
})
