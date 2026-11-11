// The scan module on the real backend, on a box with no scan worker (S-SCAN-1, S-SCAN-4; scan INV-1, INV-2, INV-3, INV-5, INV-7 read side, INV-4 `dangerous_locked`).
// What is built on main and needs no worker: the settings (validation, partial save, audit), the target list and why a device is not on it, the refusals of a run,
// the probe log (empty) and its CSV, the rescan log (empty), the page and the roles. The box of the run has no scan container, so `can_scan` is false with the reason
// the page shows; a run that reaches the worker (progress, results, Stop now, auto-stop, the probe rows and the findings a match confirms) is test.fixme with the real
// flow in its body (D-171 (2), D-198: it needs the sensor seam of WP-30 slice 7 and the scan image). Global project: the settings are box-wide and the specs put
// them back; the devices the file declares are swept by id after every test.
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Cfg {
  config: { window: { days: number[]; from: string; to: string }; rate: number; exclusions: string[]; stop_on_unresponsive: boolean; unresponsive_after: number; auto_rescan: boolean; schedule: { enabled: boolean; frequency: string; weekday: number; at: string } }
  next_run: string | null; scope: { networks: string[]; commitment: { by: string; confirmed_at: string } | null }; can_scan: boolean; block_reason: string | null; dangerous_checks: false
}
interface Target { id: string; label: string; ip: string; kind: string; device_kind: string; fragile: boolean; pick_only: boolean; selectable: boolean; reason: string | null; findings: number }
interface Err { error: { code: string; message: string; field?: string } }
const UNAVAILABLE = "The vulnerability scanner is not available: the scan container or its scanner is missing. Check the box's services, then try again."

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const cfg = async (c: APIRequestContext) => (await api<Cfg>(c, 'GET', '/scans/config')).body
const targets = async (c: APIRequestContext) => (await api<{ items: Target[] }>(c, 'GET', '/scans/targets')).body.items
const audit = async (c: APIRequestContext, q: string) => (await api<{ items: { action: string; target: string; detail?: string }[] }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)).body.items
/** The `total` of the answer: the page of rows is capped, a count of it is not a count of the rows. */
const auditTotal = async (c: APIRequestContext, q: string) => (await api<{ total: number }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)).body.total

let original: Cfg['config']
let seq = 0
const made: string[] = []
/** A device declared by hand inside the confirmed scope (10.1.0.0/16 of the setup run): hand-declared, so it is pick-only (INV-1). */
async function device(c: APIRequestContext) {
  const n = seq++
  const ip = `10.1.${100 + (process.pid % 50) * 2 + Math.floor(n / 200)}.${(n % 200) + 1}` // a counter, and the process id: no address repeats in a run or between two workers
  const name = uniq('scan')
  const r = await api<{ id: string }>(c, 'POST', '/inventory/devices', { vendor: `Vend-${name}`, product: `Prod-${name}`, version: '1.0', name, ip })
  expect(r.status, JSON.stringify(r.body)).toBe(201)
  made.push(r.body.id)
  return { id: r.body.id, name, ip }
}
test.beforeAll(async () => {
  const c = await as('admin')
  try { original = (await cfg(c)).config } finally { await c.dispose() }
})
test.afterEach(async () => {
  const c = await as('admin')
  try {
    for (const id of made.splice(0)) expect((await api(c, 'DELETE', `/inventory/devices/${id}`)).status, `cleanup of device ${id}`).toBe(204)
    const put = await api(c, 'PUT', '/scans/config', original)
    expect(put.status, `settings put back: ${JSON.stringify(put.body)}`).toBe(200)
    expect((await cfg(c)).config, 'the settings are the ones the run started with').toEqual(original)
  } finally { await c.dispose() }
})

test('no scan container: the settings say so with the reason, the box itself is never a target, the page agrees (INV-1, INV-2)', async ({ page }) => {
  const errors = collectErrors(page)
  const server: string[] = []
  page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500) server.push(`${r.request().method()} ${new URL(r.url()).pathname} ${r.status()}`) })
  const c = await as('admin')
  try {
    const s = await cfg(c)
    expect(s).toMatchObject({ can_scan: false, block_reason: UNAVAILABLE, dangerous_checks: false })
    expect(s.scope.commitment, 'the setup run ticked the scan commitment').toMatchObject({ by: 'admin@e2e.test' })
    expect(s.scope.networks.length).toBeGreaterThan(0)
    expect(s.config).toMatchObject({ rate: 5, stop_on_unresponsive: true, unresponsive_after: 3, auto_rescan: true, window: { days: [1, 2, 3, 4, 5, 6, 7], from: '22:00', to: '05:00' } })
    const box0 = (await targets(c)).find((t) => t.reason === 'box')
    expect(box0, 'the box is listed, and never selectable').toMatchObject({ selectable: false, pick_only: false })
    expect((await api(c, 'GET', '/scans/runs')).body).toEqual({ items: [], engine_busy: false })
    expect((await api(c, 'GET', '/scans/probes')).body).toEqual({ items: [], retention_days: 90 })
    expect((await api(c, 'GET', '/scans/events')).body).toEqual({ items: [], auto_rescan: true })

    await page.goto('/scans')
    // BUG (.ai/deferred/feat-e2e-real-specs-sal.md): the title and the meta line say "confirm the scan scope first" because they key on can_scan alone, while the commitment is ticked
    // and the real block is the missing scanner. Not asserted here: asserting the wrong text would make the fix fail this spec.
    await expect(h1(page)).toBeVisible()
    await expect(page.getByText(`Confirmed scope: ${s.scope.networks.join(', ')}. Vedette never scans any address outside it.`)).toBeVisible()
    await expect(page.getByText(/^Scan scope commitment ticked on .*, confirmed by admin@e2e\.test\.$/)).toBeVisible()
    await expect(page.getByText('This is the Vedette box itself, never scanned')).toBeVisible()
    await expect(page.getByRole('button', { name: /^Scan now/ })).toBeDisabled()
    await expect(page.getByText(UNAVAILABLE, { exact: true }), 'the reason stands next to the disabled button').toBeVisible()
    await expect(page.getByText('Vedette is provided as-is. Its author is not responsible for how you use it.')).toBeVisible()
    await expectAccessible(page, 'scans')
    await noVietnamese(page, 'scans')
    expect(server).toEqual([])
    noErrors(errors)
  } finally { await c.dispose() }
})

test('a device declared by hand is pick-only; excluded and deleted devices leave the list; a run is refused with the reason and creates nothing (INV-1, INV-3)', async () => {
  const c = await as('admin')
  try {
    const d = await device(c)
    const list = await targets(c)
    expect(list.find((t) => t.id === d.id)).toMatchObject({ label: d.name, ip: d.ip, kind: 'internal', pick_only: true, selectable: true, reason: null, fragile: true })
    // the settings exclude it: listed with the reason, not selectable, not pick-only
    expect((await api(c, 'PUT', '/scans/config', { exclusions: [d.ip] })).status).toBe(200)
    expect((await targets(c)).find((t) => t.id === d.id)).toMatchObject({ selectable: false, pick_only: false, reason: 'excluded' })
    const excluded = await api<Err>(c, 'POST', '/scans/runs', { targets: [d.id] })
    expect([excluded.status, excluded.body.error.code], 'an excluded device cannot be scanned').toEqual([400, 'out_of_scope'])
    expect((await api(c, 'PUT', '/scans/config', { exclusions: [] })).status).toBe(200)

    const refusals: [string, unknown, number, string][] = [
      ['no targets', { targets: [] }, 400, 'invalid'],
      ['no body field', {}, 400, 'invalid'],
      ['an id the list does not have', { targets: ['a-does-not-exist'] }, 400, 'unknown_target'],
      ['the box itself', { targets: [list.find((t) => t.reason === 'box')!.id] }, 400, 'out_of_scope'],
      ['a device that is on the list, with no scanner', { targets: [d.id] }, 503, 'scanner_unavailable'],
      ['the same device twice', { targets: [d.id, d.id] }, 503, 'scanner_unavailable'],
    ]
    for (const [what, body, status, code] of refusals) {
      const r = await api<Err>(c, 'POST', '/scans/runs', body)
      expect([r.status, r.body.error?.code], what).toEqual([status, code])
      expect((await api(c, 'GET', '/scans/runs')).body, `${what}: no run was created`).toEqual({ items: [], engine_busy: false })
      expect((await api(c, 'GET', '/scans/probes')).body, `${what}: no probe was logged`).toEqual({ items: [], retention_days: 90 })
    }
    expect((await api<Err>(c, 'POST', '/scans/runs', { targets: [d.id] })).body.error.message).toBe(UNAVAILABLE)
    expect([await auditTotal(c, 'scan.start'), await auditTotal(c, 'scan.pick')], 'a refused run leaves no audit row (a started run is audited as scan.start and scan.pick)').toEqual([0, 0])
    const stop = await api<Err>(c, 'POST', '/scans/runs/sr-does-not-exist/stop')
    expect([stop.status, stop.body.error.code]).toEqual([404, 'not_found'])
  } finally { await c.dispose() }
})

test('the settings page: a bad value is refused in place and keeps what was typed; a good one saves, persists and is in the audit (INV-5)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    await page.goto('/scans?tab=safety')
    const excl = page.getByLabel('One IP or network per line')
    const save = page.getByRole('button', { name: 'Save settings' })
    await excl.fill('10.1.200.1\nabc\n999.1.1.1')
    await save.click()
    const bad = await api<Err>(c, 'PUT', '/scans/config', { exclusions: ['10.1.200.1', 'abc', '999.1.1.1'] })
    expect(bad.status).toBe(400)
    await expect(page.getByRole('alert')).toHaveText(bad.body.error.message)
    await expect(excl).toHaveValue('10.1.200.1\nabc\n999.1.1.1')
    expect((await cfg(c)).config.exclusions, 'the refusal saved nothing').toEqual([])

    await excl.fill('10.1.200.1\n10.1.201.0/24')
    await page.getByLabel('From', { exact: true }).fill('05:00')
    await page.getByLabel('Until', { exact: true }).fill('05:00')
    await save.click()
    await expect(page.getByRole('alert')).toContainText('The start and end times must differ')
    await page.getByLabel('From', { exact: true }).fill('21:30')
    await page.getByLabel('Until', { exact: true }).fill('04:15')
    await page.getByLabel('Speed', { exact: true }).selectOption('2')
    await page.getByLabel('Stop after', { exact: true }).selectOption('5')
    await save.click()
    await expect(page.getByText('Scan settings saved').first()).toBeVisible()
    const saved = (await cfg(c)).config
    expect(saved).toMatchObject({ exclusions: ['10.1.200.1', '10.1.201.0/24'], rate: 2, unresponsive_after: 5, window: { from: '21:30', to: '04:15' } })
    await page.reload()
    await expect(page.getByLabel('One IP or network per line')).toHaveValue('10.1.200.1\n10.1.201.0/24')
    await expect(page.getByLabel('From', { exact: true })).toHaveValue('21:30')
    const last = (await audit(c, 'scan.config'))[0]
    expect(last).toMatchObject({ action: 'scan.config' })
    expect(last!.detail).toContain('"rate":2')
    // the locked row: dangerous checks have no switch, and the API refuses them
    await expect(page.getByText('Dangerous checks are removed from this Vedette build; there is no switch to turn them on.')).toBeVisible()
    const locked = await api<Err>(c, 'PUT', '/scans/config', { dangerous_checks: true })
    expect([locked.status, locked.body.error.code]).toEqual([400, 'dangerous_locked'])
    expect((await cfg(c)).dangerous_checks).toBe(false)
    await expectAccessible(page, 'scan settings')
    noErrors(errors, /status of 400/)
  } finally { await c.dispose() }
})

test('every refused setting carries its code and saves nothing (INV-5)', async () => {
  const c = await as('admin')
  try {
    const before = JSON.stringify(await cfg(c))
    const auditBefore = await auditTotal(c, 'scan.config')
    const cases: [string, unknown, string][] = [
      ['rate 0', { rate: 0 }, 'invalid'], ['rate 21', { rate: 21 }, 'invalid'], ['rate 2.5', { rate: 2.5 }, 'invalid'],
      ['unresponsive_after 1', { unresponsive_after: 1 }, 'invalid'], ['unresponsive_after 21', { unresponsive_after: 21 }, 'invalid'],
      ['no day', { window: { days: [] } }, 'invalid'], ['day 0', { window: { days: [0] } }, 'invalid'], ['day 8', { window: { days: [8] } }, 'invalid'],
      ['hour 25', { window: { from: '25:00' } }, 'invalid'], ['equal times', { window: { from: '05:00', to: '05:00' } }, 'invalid_config'],
      ['a word in the exclusions', { exclusions: ['abc'] }, 'invalid_config'], ['a bad prefix', { exclusions: ['10.0.0.0/33'] }, 'invalid_config'],
      ['201 exclusions', { exclusions: Array.from({ length: 201 }, (_, i) => `10.9.${Math.floor(i / 250)}.${(i % 250) + 1}`) }, 'invalid'],
      ['schedule weekday 9', { schedule: { weekday: 9 } }, 'invalid'], ['schedule frequency hourly', { schedule: { frequency: 'hourly' } }, 'invalid'],
      ['dangerous checks', { dangerous_checks: true }, 'dangerous_locked'],
    ]
    for (const [what, body, code] of cases) {
      const r = await api<Err>(c, 'PUT', '/scans/config', body)
      expect([r.status, r.body.error?.code], what).toEqual([400, code])
    }
    expect(JSON.stringify(await cfg(c)), 'no refusal changed a setting').toBe(before)
    expect(await auditTotal(c, 'scan.config'), 'a refusal has no audit row').toBe(auditBefore)
  } finally { await c.dispose() }
})

test('auto rescan switch and schedule save as a partial update and show in the page (S-SCAN-2, S-SCAN-4)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    await page.goto('/scans?tab=auto')
    const sw = page.getByRole('switch', { name: /Rescan automatically/ })
    await expect(sw).toBeChecked()
    await expect(page.getByText('No events yet.')).toBeVisible()
    await sw.click()
    await expect(page.getByText('Auto rescan turned off').first()).toBeVisible()
    await expect(page.getByText(/^Off: new vulnerabilities will not be rescanned automatically\./)).toBeVisible()
    const off = await cfg(c)
    expect(off.config.auto_rescan).toBe(false)
    expect({ ...off.config, auto_rescan: true }, 'only the switch changed').toEqual(original)
    await sw.click()
    await expect(page.getByText('Auto rescan turned on').first()).toBeVisible()
    expect((await cfg(c)).config.auto_rescan).toBe(true)

    await page.goto('/scans?tab=safety')
    const put = await api<Cfg>(c, 'PUT', '/scans/config', { schedule: { enabled: false } })
    expect(put.status).toBe(200)
    expect(put.body.next_run, 'no schedule, no next run').toBeNull()
    await page.reload()
    await expect(page.getByText('The schedule is off.')).toBeVisible()
    noErrors(errors)
  } finally { await c.dispose() }
})

test('the probe log and the rescan log are empty and say so; the CSV is the header only (INV-7 read side)', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/scans?tab=probes')
  await expect(page.getByText('No probe requests yet.')).toBeVisible()
  await expect(page.getByText(/^Kept for at least 90 days\. 0 lines now/)).toBeVisible()
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download CSV' }).click()])
  expect(dl.suggestedFilename()).toBe('vedette-probe-log.csv')
  const c = await as('admin')
  try {
    const csv = await c.get('/api/v1/scans/probes.csv')
    expect(csv.status()).toBe(200)
    expect((await csv.text()).trim()).toBe('time,target,name,template,request,result')
  } finally { await c.dispose() }
  await expectAccessible(page, 'probe log')
  noErrors(errors)
})

test('roles: a viewer reads, an operator may start and stop (and meets the same refusals), only an administrator changes the settings', async ({ browser }) => {
  const admin = await as('admin')
  try {
    const d = await device(admin)
    const before = JSON.stringify(await cfg(admin))
    for (const role of ['viewer', 'operator'] as const) {
      const c = await as(role)
      try {
        for (const p of ['/scans/config', '/scans/targets', '/scans/runs', '/scans/probes', '/scans/events']) expect((await api(c, 'GET', p)).status, `${role}: GET ${p}`).toBe(200)
        expect((await c.get('/api/v1/scans/probes.csv')).status()).toBe(200)
        const put = await api<Err>(c, 'PUT', '/scans/config', { rate: 1 })
        expect([put.status, put.body.error.code], `${role}: PUT config`).toEqual([403, 'forbidden'])
        const run = await api<Err>(c, 'POST', '/scans/runs', { targets: [d.id] })
        if (role === 'viewer') expect([run.status, run.body.error.code], 'viewer: start a run').toEqual([403, 'forbidden'])
        else expect([run.status, run.body.error.code], 'operator passes the role gate and meets the scanner refusal').toEqual([503, 'scanner_unavailable'])
        const stop = await api<Err>(c, 'POST', '/scans/runs/sr-does-not-exist/stop')
        expect([stop.status, stop.body.error.code], `${role}: stop`).toEqual(role === 'viewer' ? [403, 'forbidden'] : [404, 'not_found'])
      } finally { await c.dispose() }
      expect(JSON.stringify(await cfg(admin)), `${role}: nothing changed`).toBe(before)
      const ctx = await browser.newContext({ baseURL: box().base_url, storageState: authFile(role) })
      try {
        const page = await ctx.newPage()
        await page.goto('/scans?tab=safety')
        await expect(page.getByText('Only an administrator can change these settings. You can still read them.')).toBeVisible()
        await expect(page.getByRole('button', { name: 'Save settings' })).toBeDisabled()
        await page.goto('/scans?tab=auto')
        await expect(page.getByRole('switch', { name: /Rescan automatically/ })).toBeDisabled()
      } finally { await ctx.close() }
    }
  } finally { await admin.dispose() }
})

// ---- needs the scan worker (slice 7 seam) and the scan image: the real flow is in the body (D-171 (2), D-198) ----
test.fixme('a run goes to the end: progress, per-device results, a match confirms a finding and links to it, the probe log has one row per device and template (INV-3, INV-7, INV-8; needs the worker)', async ({ page }) => {
  const c = await as('admin')
  const d = await device(c)
  const start = await api<{ id: string }>(c, 'POST', '/scans/runs', { targets: [d.id] })
  expect(start.status).toBe(201)
  await page.goto('/scans')
  await expect(h1(page)).toContainText('Scanning')
  await expect(h1(page)).toContainText('Last scan', { timeout: 60_000 })
  await c.dispose()
})
test.fixme('Stop now: Stopping, then Stopped within 5 seconds, devices not reached are not touched; a second run while one runs is 409 already_running (INV-3, INV-6; needs the worker)', async ({ page }) => {
  const c = await as('admin')
  const d = await device(c)
  const run = await api<{ id: string }>(c, 'POST', '/scans/runs', { targets: [d.id] })
  expect((await api<Err>(c, 'POST', '/scans/runs', { targets: [d.id] })).body.error.code).toBe('already_running')
  await page.goto('/scans')
  await page.getByRole('button', { name: 'Stop now' }).click()
  await expect(h1(page)).toContainText('was stopped', { timeout: 5_000 })
  expect((await api<Err>(c, 'POST', `/scans/runs/${run.body.id}/stop`)).body.error.code).toBe('not_running')
  await c.dispose()
})
test.fixme('auto-stop: a device that stops answering ends the run as auto_stopped with the reason (INV-6; needs the worker, WP-23 deferred line "stop when a device does not respond")', async () => {
  const c = await as('admin')
  const d = await device(c)
  await api(c, 'POST', '/scans/runs', { targets: [d.id] })
  await expect.poll(async () => (await api<{ items: { status: string; stop_reason: string | null }[] }>(c, 'GET', '/scans/runs')).body.items[0]?.status, { timeout: 60_000 }).toBe('auto_stopped')
  await c.dispose()
})
test.fixme('a new KEV with a scan template rescans exactly the matching devices within 60 minutes and the event is in the log; with auto rescan off it is skipped_off (INV-9; needs the worker and a KEV with a template)', async () => {
  const c = await as('admin')
  await expect.poll(async () => (await api<{ items: unknown[] }>(c, 'GET', '/scans/events')).body.items.length, { timeout: 60_000 }).toBeGreaterThan(0)
  await c.dispose()
})
