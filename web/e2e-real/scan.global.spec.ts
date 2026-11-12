// The scan module on the real backend (S-SCAN-1, S-SCAN-2, S-SCAN-4; scan INV-1, INV-2, INV-3, INV-5, INV-6, INV-7, INV-8, INV-9, INV-4 `dangerous_locked`).
// The first part runs with no scan worker: the settings (validation, partial save, audit), the target list and why a device is not on it, the refusals
// of a run, the probe log (empty) and its CSV, the rescan log (empty), the page and the roles; `can_scan` is false with the reason the page shows.
// The second part (`with the scanner`, D-427) starts the REAL worker of sensor-active in the box process with a FAKE nuclei (cmd/vedette/e2escan_test.go):
// a run to the end with a match, Stop now, auto-stop, and the new-KEV rescan log. Global project: the settings are box-wide and the specs put them back;
// the devices the file declares are swept by id after every test.
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, nucleiRuns, scanWorker, sensorCtl, uniq } from './box'
import { finding, seed, startFeedServer, stopFeedServer, sweep } from './findings-seed'
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
/** An address inside the confirmed scope (10.1.0.0/16 of the setup run): a counter, and the process id: no address repeats in a run or between two workers. */
function nextIp() {
  const n = seq++
  return `10.1.${100 + (process.pid % 50) * 2 + Math.floor(n / 200)}.${(n % 200) + 1}`
}
/** A device declared by hand inside the confirmed scope: hand-declared, so it is pick-only (INV-1). */
async function device(c: APIRequestContext) {
  const ip = nextIp()
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
    await expect(h1(page)).toHaveText('Cannot scan: the vulnerability scanner is not available') // the commitment is ticked: the block is the scanner
    await expect(page.locator('header').getByText(UNAVAILABLE, { exact: true }), 'the reason under the title').toBeVisible()
    await expect(page.getByText(`Confirmed scope: ${s.scope.networks.join(', ')}. Vedette never scans any address outside it.`)).toBeVisible()
    await expect(page.getByText(/^Scan scope commitment ticked on .*, confirmed by admin@e2e\.test\.$/)).toBeVisible()
    await expect(page.getByText('This is the Vedette box itself, never scanned')).toBeVisible()
    await expect(page.getByRole('button', { name: /^Scan now/ })).toBeDisabled()
    await expect(page.getByRole('tabpanel', { name: 'Scans and history' }).getByText(UNAVAILABLE, { exact: true }), 'the reason stands next to the disabled button').toBeVisible()
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

// ---- with the scanner (D-427): the REAL worker of sensor-active in the box process, on the real sensor link, with the committed pack and a FAKE
// nuclei that sends nothing (cmd/vedette/e2escan_test.go). The devices carry a real finding: a KEV entry of a CVE of the pack, for a made-up
// product, pulled through the CISA feed's mirror address (findings-seed.ts); the nuclei-templates feed is pointed at a loopback list of the
// same CVEs first, so the entries have `has_template` and announce a new KEV with a template (INV-9). ----
const PACK_CVES = { match: 'CVE-2002-1131', stop: 'CVE-2005-3128', next: 'CVE-2010-0738', dead: 'CVE-2007-0885', off: 'CVE-2008-2398', pick: 'CVE-2009-0545' } as const
/** The pack path of a CVE's one template (a pack template is http/cves/<year>/<id>.yaml for these). */
const tplPath = (cve: string) => `http/cves/${cve.slice(4, 8)}/${cve}.yaml`
interface Row { target_id: string; label: string; ip: string; template: string | null; result: string; finding_id: string | null; note: string }
interface Run { id: string; trigger: string; status: string; started_by: string; total: number; done: number; current: unknown; results: Row[]; matched: number; stop_reason: string | null }
interface Probe { run_id: string | null; ip: string; template: string; result: string }
interface Ev { cve: string; devices: string[]; run_id: string | null; result: string }
const runs = async (c: APIRequestContext) => (await api<{ items: Run[]; engine_busy: boolean }>(c, 'GET', '/scans/runs')).body
const probesOf = async (c: APIRequestContext, run: string) => (await api<{ items: Probe[] }>(c, 'GET', '/scans/probes')).body.items.filter((p) => p.run_id === run).map((p) => [p.ip, p.template, p.result])
const eventOf = async (c: APIRequestContext, cve: string) => (await api<{ items: Ev[] }>(c, 'GET', '/scans/events')).body.items.find((e) => e.cve === cve)
/** The run once it has ended (the fake answers at once; the engine call may still be returning, so wait for engine_busy too). */
async function ended(c: APIRequestContext, id: string): Promise<Run> {
  let run: Run | undefined
  await expect.poll(async () => { const r = await runs(c); run = r.items.find((x) => x.id === id); return [run?.status, r.engine_busy] }, { message: `run ${id} ends`, timeout: 60_000 })
    .toEqual([expect.stringMatching(/^(done|stopped|auto_stopped)$/), false])
  return run!
}

test.describe('with the scanner', () => {
  let tplServer: Server | undefined
  let inv: { active: { enabled: boolean } } & Record<string, unknown>
  test.beforeAll(async () => {
    test.setTimeout(120_000)
    const a = await as('admin')
    try {
      // the worker sits in the slot of the active sensor: with discovery on and its window open the box would send it sweeps of the scope,
      // which change what the sensors spec sees later (D-427); this block needs no discovery, so it is off while the worker runs
      inv = (await api(a, 'GET', '/inventory/settings')).body
      const off = await api(a, 'PUT', '/inventory/settings', { ...inv, active: { ...inv.active, enabled: false }, scope_confirmed: true })
      expect(off.status, `discovery off: ${JSON.stringify(off.body)}`).toBe(200)
    } finally { await a.dispose() }
    tplServer = createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(Object.values(PACK_CVES).map((id) => JSON.stringify({ ID: id, Info: { Name: id }, file_path: tplPath(id) })).join('\n'))
    })
    await new Promise<void>((ok) => tplServer!.listen(0, '127.0.0.1', ok))
    const c = await as('admin')
    try {
      const url = `http://e2e-loopback.lan:${(tplServer.address() as AddressInfo).port}/cves.json` // the box sends this name to 127.0.0.1 (e2eOffline)
      expect((await api(c, 'PUT', '/feeds/sources/nuclei-templates', { url })).status, 'the template list address').toBe(200)
      const pulled = await api(c, 'POST', '/feeds/sources/nuclei-templates/fetch')
      expect(pulled.status, `templates: ${JSON.stringify(pulled.body)}`).toBe(200)
      const src = (await api<{ items: { id: string; status: string; error: string | null }[] }>(c, 'GET', '/feeds/sources')).body.items.find((i) => i.id === 'nuclei-templates')
      expect(src, 'the template list pulled from the loopback server').toMatchObject({ status: 'ok', error: null })
      await startFeedServer()
      await scanWorker('nomatch')
      await expect.poll(async () => (await cfg(c)).can_scan, { message: 'the worker reports nuclei and the pack core plans with', timeout: 60_000 }).toBe(true)
      expect((await cfg(c)).block_reason).toBeNull()
    } finally { await c.dispose() }
  })
  test.afterEach(sweep)
  test.afterAll(async () => {
    test.setTimeout(240_000)
    await sensorCtl({ stop: 'active' })
    await stopFeedServer()
    const c = await as('admin')
    try {
      expect((await api(c, 'PUT', '/feeds/sources/nuclei-templates', { url: '' })).status, 'reset of the template list address').toBe(200)
      // discovery back on only once the box no longer counts on the stopped worker (its heartbeat is fresh for 90 s): before that a sweep would be
      // queued for it, logged in the probe log, and never run
      await expect.poll(async () => (await cfg(c)).can_scan, { message: 'the box sees the worker gone', timeout: 150_000, intervals: [5_000] }).toBe(false)
      expect((await api(c, 'PUT', '/inventory/settings', { ...inv, scope_confirmed: true })).status, 'discovery as it was').toBe(200)
      expect((await api<typeof inv>(c, 'GET', '/inventory/settings')).body.active).toEqual(inv.active)
    } finally {
      await c.dispose()
      if (tplServer) await new Promise((ok) => tplServer!.close(ok))
    }
  })

  test('a run goes to the end: progress, per-device results, a match confirms the finding and links to it, nuclei gets only that device and its template, one probe row per device and template (INV-3, INV-7, INV-8)', async ({ page }) => {
    test.setTimeout(120_000)
    const errors = collectErrors(page)
    const c = await as('admin')
    try {
      await scanWorker('match')
      const hit = await seed({ cve: PACK_CVES.match, ip: nextIp() })
      const plain = await device(c) // no finding: no template applies, nothing is sent for it
      const sent = (await nucleiRuns()).length
      const start = await api<Run>(c, 'POST', '/scans/runs', { targets: [hit.deviceId, plain.id] })
      expect(start.status, JSON.stringify(start.body)).toBe(201)
      expect(start.body).toMatchObject({ status: 'running', trigger: 'manual', started_by: 'admin@e2e.test', total: 2, done: 0 })
      const run = await ended(c, start.body.id)
      expect(run).toMatchObject({ status: 'done', total: 2, done: 2, matched: 1, stop_reason: null, current: null })
      expect(run.results.find((r) => r.target_id === hit.deviceId)).toMatchObject({ ip: hit.ip, template: tplPath(PACK_CVES.match), result: 'matched', finding_id: hit.findingId })
      expect(run.results.find((r) => r.target_id === plain.id)).toMatchObject({ ip: plain.ip, result: 'not_applicable', finding_id: null, note: 'No scan template applies to the software on this device.' })
      expect((await finding(c, hit.findingId)).body.status, 'the match confirms the finding (INV-8)').toBe('confirmed')

      const lines = (await nucleiRuns()).slice(sent)
      expect(lines, 'one nuclei run: the device with a template').toHaveLength(1)
      expect(lines[0]).toContain(`-t /usr/share/vedette/nuclei-templates/${tplPath(PACK_CVES.match)}`)
      expect(lines[0]).toContain(`-u http://${hit.ip}:80 -u https://${hit.ip}:443`) // no known port: 80 and 443
      expect(lines[0]).not.toContain(plain.ip)
      expect(lines[0].match(/ -t /g), 'only the template of the finding, never the whole pack').toHaveLength(1)
      expect(await probesOf(c, run.id), 'one probe row per device and template, written before the job left and closed with its result (INV-7)').toEqual([[hit.ip, tplPath(PACK_CVES.match), 'matched']])
      expect(await auditTotal(c, 'scan.start')).toBeGreaterThan(0)

      await page.goto('/scans')
      await expect(h1(page)).toContainText('2 devices checked, 1 device matches a vulnerability')
      await page.getByRole('button', { name: /^View results of the scan from/ }).filter({ visible: true }).first().click()
      const table = page.getByRole('table', { name: 'Per-device results' })
      await expect(table.getByRole('row').filter({ hasText: hit.ip })).toContainText('Matches, still vulnerable')
      await expect(table.getByRole('row').filter({ hasText: plain.ip })).toContainText('No template applies')
      await table.getByRole('link', { name: 'Open finding' }).click()
      await expect(page).toHaveURL(new RegExp(`/findings/${hit.findingId}$`))
      noErrors(errors)
    } finally { await c.dispose() }
  })

  test('Stop now: Stopping, then Stopped within 5 seconds; the device on its way is "stopped" in the probe log, the device not reached is not touched; a second run while one runs is 409 already_running (INV-3, INV-6, INV-7)', async ({ page }) => {
    test.setTimeout(120_000)
    const c = await as('admin')
    try {
      await scanWorker('hang')
      const slow = await seed({ cve: PACK_CVES.stop, ip: nextIp() })
      const next = await seed({ cve: PACK_CVES.next, ip: nextIp() }) // a finding with a template: it would be sent one, if it were reached
      const sent = (await nucleiRuns()).length
      const run = await api<Run>(c, 'POST', '/scans/runs', { targets: [slow.deviceId, next.deviceId] })
      expect(run.status, JSON.stringify(run.body)).toBe(201)
      const again = await api<Err>(c, 'POST', '/scans/runs', { targets: [next.deviceId] })
      expect([again.status, again.body.error.code], 'one run at a time').toEqual([409, 'already_running'])
      await expect.poll(async () => (await nucleiRuns()).length, { message: 'nuclei runs on the first device', timeout: 30_000 }).toBe(sent + 1)

      await page.goto('/scans')
      await expect(h1(page)).toContainText('Scanning: 0/2 devices done')
      await expect(page.getByText(`Scanning ${slow.host} (${slow.ip})`)).toBeVisible()
      const t0 = Date.now()
      await page.getByRole('button', { name: 'Stop now' }).click()
      await expect(h1(page)).toContainText('Last scan was stopped', { timeout: 5_000 })
      expect(Date.now() - t0, 'Stopped within 5 seconds').toBeLessThan(5_000)

      const done = await ended(c, run.body.id) // engine_busy false: the worker killed nuclei and answered
      expect(done).toMatchObject({ status: 'stopped', stop_reason: 'You pressed Stop now.' })
      expect(done.results.find((r) => r.target_id === slow.deviceId)).toMatchObject({ result: 'skipped', note: 'Stopped while this device was being scanned: no result. The requests on their way are in the probe log as stopped.' })
      expect(done.results.find((r) => r.target_id === next.deviceId)).toMatchObject({ result: 'skipped', note: 'Not scanned because the scan was stopped. This device was not touched.' })
      expect(await probesOf(c, done.id)).toEqual([[slow.ip, tplPath(PACK_CVES.stop), 'stopped']])
      const lines = (await nucleiRuns()).slice(sent)
      expect(lines, 'nothing was sent for the device not reached').toHaveLength(1)
      expect(lines[0]).not.toContain(next.ip)
      expect((await finding(c, slow.findingId)).body.status, 'a stopped run concludes nothing').toBe('suspected')
      const stop = await api<Err>(c, 'POST', `/scans/runs/${done.id}/stop`)
      expect([stop.status, stop.body.error.code]).toEqual([409, 'not_running'])
    } finally { await c.dispose() }
  })

  test('auto-stop: a device that stops answering ends the run as auto_stopped with the reason; the devices after it are not touched and the finding stays suspected (INV-6)', async ({ page }) => {
    test.setTimeout(120_000)
    const c = await as('admin')
    try {
      await scanWorker('dead')
      const dead = await seed({ cve: PACK_CVES.dead, ip: nextIp() })
      const after = await device(c)
      const label = (await targets(c)).find((t) => t.id === dead.deviceId)!.label
      const start = await api<Run>(c, 'POST', '/scans/runs', { targets: [dead.deviceId, after.id] })
      expect(start.status, JSON.stringify(start.body)).toBe(201)
      const run = await ended(c, start.body.id)
      expect(run).toMatchObject({ status: 'auto_stopped', stop_reason: `${label} (${dead.ip}) stopped responding after 3 failed requests. Vedette stopped so the device is not hung.` })
      expect(run.results.find((r) => r.target_id === dead.deviceId)).toMatchObject({ result: 'no_response', note: 'No response; scanning stopped so the device is not hung.' })
      expect(run.results.find((r) => r.target_id === after.id)).toMatchObject({ result: 'skipped' })
      expect(await probesOf(c, run.id)).toEqual([[dead.ip, tplPath(PACK_CVES.dead), 'no_response']])
      expect((await finding(c, dead.findingId)).body.status, 'no response is never "not vulnerable"').toBe('suspected')

      await page.goto('/scans')
      await expect(h1(page)).toContainText('Last scan was stopped')
      await expect(page.getByRole('table', { name: 'History of scans' }).getByRole('row').nth(1)).toContainText('Auto-stopped')
    } finally { await c.dispose() }
  })

  test('a new KEV with a scan template: with auto rescan off the event is skipped_off; on, a matching device that only a hand pick may scan is pick_only with its name; neither sends anything (INV-9)', async ({ page }) => {
    // A rescan that runs is not here: every device a spec can make is declared by hand (origin manual), which INV-1 keeps out of automatic scans,
    // and a discovered one would change the box the sensors spec counts. TestContract_INV9_RescanAfterANewKEV carries it (D-427).
    test.setTimeout(6 * 60_000)
    const c = await as('admin')
    try {
      await scanWorker('match')
      const sent = (await nucleiRuns()).length
      const before = (await runs(c)).items.length
      expect((await api(c, 'PUT', '/scans/config', { ...original, auto_rescan: false })).status).toBe(200)
      await seed({ cve: PACK_CVES.off, ip: nextIp() })
      // the rescan job looks every minute and waits a minute for the inventory and the findings to catch up
      await expect.poll(async () => (await eventOf(c, PACK_CVES.off))?.result, { message: 'the event is logged as skipped', timeout: 180_000, intervals: [5_000] }).toBe('skipped_off')
      expect((await eventOf(c, PACK_CVES.off))!.run_id).toBeNull()

      expect((await api(c, 'PUT', '/scans/config', { ...original, auto_rescan: true })).status).toBe(200)
      const pick = await seed({ cve: PACK_CVES.pick, ip: nextIp() })
      await expect.poll(async () => (await eventOf(c, PACK_CVES.pick))?.result, { message: 'the event is logged as pick-only', timeout: 180_000, intervals: [5_000] }).toBe('pick_only')
      expect(await eventOf(c, PACK_CVES.pick)).toMatchObject({ devices: [pick.host], run_id: null })
      expect((await runs(c)).items, 'no run was started').toHaveLength(before)
      expect((await nucleiRuns()).length, 'nothing was sent').toBe(sent)

      await page.goto('/scans?tab=auto')
      const log = page.getByRole('table', { name: 'Auto rescan event log' })
      await expect(log.getByRole('row').filter({ hasText: PACK_CVES.pick })).toContainText('Not scanned automatically: 1 device needs a hand pick in Scan now')
      await expect(log.getByRole('row').filter({ hasText: PACK_CVES.off })).toContainText('Skipped: turned off')
    } finally { await c.dispose() }
  })
})
