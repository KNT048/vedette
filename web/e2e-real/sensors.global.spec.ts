// The sensors on the real backend (S-INV-1, S-INV-3, D-80, D-84, D-111 (4)/SYS-5, sensor-passive and sensor-active invariants): the REAL `vedette-sensor` binary, started
// by the box harness (cmd/vedette/e2esensor_test.go), talks to core over the real mutual-TLS sensor link.
//   - passive: replays modules/sensor-passive/testdata/lan-discovery.pcap (the recording stands in for the network; the process needs no capture rights);
//   - active: long-polls jobs and runs a FAKE nmap that scans nothing, appends its argv to a file and answers from the fixtures of modules/sensor-active/testdata by the
//     shape of that argv. What these tests prove is what the BOX decided to send (which addresses, which flags, when) and what it made of the answers.
//     sweep.xml also holds 203.0.113.9, a host outside every private range: it must never reach the inventory.
// One file, one order: core remembers an observation it wrote for 15 minutes (D-80 (1), modules/sensor-passive/repeat.go), so the recording can be delivered once per run, and
// the active tests scan the devices the passive ones made. Global project: devices, scope and window are box-wide; afterAll stops the sensors, removes the devices and puts the
// settings back, checking every status. The window tick is one minute (cmd/vedette/sensoractive.go), so the active waits are 75 s each: the file takes about eight minutes.
// Not proved here: choosing the card and SPAN (network.global.spec.ts), the OUI make (D-83, not built), the passive budget of new devices and the dispatcher's lease, cancel and
// lost-worker paths (Go tests of the two modules), SNMP (D-84 (3): not built), nuclei (scan).
import { expect, test, type Page } from '@playwright/test'
import { api, authFile, nmapRuns, sensorCtl } from './box'
import { as, device, devices, expectNoSensorDevices, giveBack, made, PC, ROUTER, type Dev } from './sensor-shared'
import { expectAccessible, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

type Client = Awaited<ReturnType<typeof as>>
interface Sensor { id: string; status: 'online' | 'offline'; last_seen: string | null; version: string | null; interface: string | null }
const sensor = async (c: Client) => (await api<{ sensors: Sensor[] }>(c, 'GET', '/inventory/sensors')).body.sensors
const sensorRow = (page: Page) => page.getByRole('table', { name: 'Sensors on this box' }).getByRole('row').nth(1)
const wait = (ms: number) => new Promise((ok) => setTimeout(ok, ms))
/** Waits until the devices of the recording are in the inventory and returns them (the sensor batches, the bus is asynchronous). */
async function waitForReplay(c: Client) {
  let got: Dev[] = []
  await expect.poll(async () => { got = made(await devices(c)); return got.map((d) => d.ip).sort() }, { message: 'the devices of the recording appear', timeout: 60_000, intervals: [1000] }).toEqual([ROUTER.ip, PC.ip])
  return { router: got.find((d) => d.ip === ROUTER.ip)!, pc: got.find((d) => d.ip === PC.ip)! }
}

interface Settings { lan_ranges: string[]; active: { enabled: boolean; days: number[]; from: string; to: string; rate: number; exclusions: string[] }; fragile_kinds: string[]; regular_scan_kinds: string[]; scope_confirmed_at: string | null; scope_confirmed_by: string | null }
const TICK = 75_000 // the window tick is one minute; a started sensor is asked for work at the next tick
const ALL_DAYS = [1, 2, 3, 4, 5, 6, 7]
const RANGE = '192.168.10.0/24'
const EXCLUDED = '192.168.10.240/28' // .240-.255: the sweep must leave them out
let original: Settings
let base: Dev[] = [] // the devices of the box when the file starts (the box itself, and whatever other specs left)
let tz = 'UTC'

const settings = async (c: Client) => (await api<Settings>(c, 'GET', '/inventory/settings')).body
async function save(c: Client, over: Partial<Settings['active']>, extra: { lan_ranges?: string[]; confirm?: boolean } = {}) {
  const body = { lan_ranges: extra.lan_ranges ?? [RANGE], active: { enabled: true, days: ALL_DAYS, from: orgClock(-1), to: orgClock(3), rate: 50, exclusions: [EXCLUDED], ...over }, fragile_kinds: ['printer', 'camera'], regular_scan_kinds: [], scope_confirmed: extra.confirm ?? true, scope_confirmed_at: null, scope_confirmed_by: null }
  const r = await api<Settings>(c, 'PUT', '/inventory/settings', body)
  expect(r.status, `PUT /inventory/settings: ${JSON.stringify(r.body)}`).toBe(200)
  return r.body
}
/** HH:MM in the organization time zone, `hours` from now: the window of the box is read in that zone (INV-3). */
const orgClock = (hours: number) => new Intl.DateTimeFormat('en-GB', { timeZone: tz, hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }).format(new Date(Date.now() + hours * 3_600_000))
const shape = (line: string) => (line.includes(' -sn ') ? 'sweep' : line.includes(' -T2 ') ? 'gentle' : 'normal')
const targetsOf = (line: string) => line.slice(line.indexOf('-oX - ') + 6).split(' ')
const GENTLE = '--privileged -sS -n -T2 --max-retries 1 --max-rate 1 --host-timeout 15m --top-ports 100 -oX - '
const NORMAL = '--privileged -sS -sV -O -n --max-rate 50 --top-ports 1000 --host-timeout 30m -oX - '

test.beforeAll(async () => {
  const c = await as('admin')
  try {
    await expectNoSensorDevices(c)
    base = (await devices(c)).items
    expect(base.filter((d) => !d.approved).map((d) => d.ip), 'this file needs a box with no device waiting for approval').toEqual([])
    const list = await sensor(c)
    expect(list.map((s) => s.status), 'one sensor, the one on this box, and nothing started yet').toEqual(['offline'])
    expect(list[0]).toMatchObject({ last_seen: null, version: null })
    original = await settings(c)
    tz = (await api<{ timezone: string }>(c, 'GET', '/core/general')).body.timezone
    expect(original.scope_confirmed_at, 'this file needs a box whose scope was confirmed in the first-run setup').not.toBeNull()
    expect(await nmapRuns(), 'no nmap ran before this file').toEqual([])
  } finally { await c.dispose() }
})
test.afterAll(async () => {
  const c = await as('admin')
  try {
    expect(original, 'beforeAll did not finish: the box was not touched by this file, but check it').toBeDefined()
    if ((await api<{ modules: { id: string; enabled: boolean }[] }>(c, 'GET', '/modules')).body.modules.find((m) => m.id === 'sensor-passive')?.enabled === false) {
      expect((await api(c, 'PATCH', '/modules/sensor-passive', { enabled: true })).status, 'the module is back on').toBe(200)
    }
    await giveBack(c)
    const r = await api<Settings>(c, 'PUT', '/inventory/settings', { ...original, scope_confirmed: true })
    expect(r.status, 'the first-run settings are back').toBe(200)
    expect(await settings(c)).toMatchObject({ lan_ranges: original.lan_ranges, active: original.active, fragile_kinds: original.fragile_kinds, regular_scan_kinds: original.regular_scan_kinds })
  } finally { await c.dispose() }
})

test('a malformed recording makes no device and does not stop the sensor (fail closed)', async () => {
  const c = await as('admin')
  try {
    await sensorCtl({ start: 'passive', replay: 'malformed-pcap' })
    // the sensor's first heartbeat (it left `last_seen` null until now), then a second one half a minute later: it went on after it had read the bad file
    await expect.poll(async () => (await sensor(c))[0]?.last_seen, { message: 'the sensor reports', timeout: 30_000, intervals: [500] }).not.toBeNull()
    const first = (await sensor(c))[0]!.last_seen
    await expect.poll(async () => (await sensor(c))[0]?.last_seen, { message: 'the sensor keeps reporting', timeout: 75_000, intervals: [2000] }).not.toBe(first)
    expect(made(await devices(c)), 'a malformed recording makes no device').toEqual([])
  } finally { await c.dispose() }
})

test('with the module off nothing is recorded and the sensors route is gone; on again the sensor delivers (SYS-5, D-111 (4))', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  let off = false
  try {
    expect((await api(c, 'PATCH', '/modules/sensor-passive', { enabled: false })).status).toBe(200)
    off = true
    const gone = await api<{ error: { code: string } }>(c, 'GET', '/inventory/sensors') // a module that is off answers its routes as if they did not exist (SYS-5)
    expect(gone, 'the sensors route while the module is off').toMatchObject({ status: 404, body: { error: { code: 'not_found' } } })
    await sensorCtl({ start: 'passive', replay: 'lan-discovery' }) // a sensor that connected before (the test above) and is started again while the module is off
    await wait(20_000)
    expect(made(await devices(c)), 'nothing is recorded while the module is off').toEqual([])
    await page.goto('/devices/setup')
    await expect(page.getByText('The passive sensor is off, so Vedette does not discover new devices by itself. Devices you add by hand still work.')).toBeVisible()
    await shot(page, 'real', 'sensor-passive-off')
    expect((await api(c, 'PATCH', '/modules/sensor-passive', { enabled: true })).status).toBe(200)
    off = false
    await sensorCtl({ start: 'passive', replay: 'lan-discovery' }) // a new process reads the recording from its start
    await waitForReplay(c)
    noErrors(errors)
  } finally {
    if (off) expect((await api(c, 'PATCH', '/modules/sensor-passive', { enabled: true })).status, 'the module is back on').toBe(200)
    await c.dispose()
  }
})

test('the recording the real sensor replayed became two devices, not approved, from the passive source (S-INV-1, S-INV-3)', async () => {
  const c = await as('admin')
  try {
    const { router, pc } = await waitForReplay(c)
    expect(router).toMatchObject({ ip: ROUTER.ip, mac: ROUTER.mac, kind: 'router', hostname: null, approved: false, origin: 'discovered', first_scan_at: null, is_box: false })
    expect(router.summary).toMatchObject({ source: 'passive', confidence: 0.5 })
    expect(router.model).toMatchObject({ value: ROUTER.model, source: 'passive', confidence: 0.5 })
    expect(pc).toMatchObject({ ip: PC.ip, mac: PC.mac, kind: 'unknown', hostname: PC.hostname, approved: false, origin: 'discovered', first_scan_at: null, is_box: false })
    // every field of a device keeps its observation, with its source and confidence, and the one in use is marked
    const detail = await device(c, router.id)
    expect(detail.observations.map((o) => [o.field, o.value, o.source, o.confidence, o.current]).sort()).toEqual([
      ['kind', 'router', 'passive', 0.5, true], ['mac', ROUTER.mac, 'passive', 0.5, true], ['model', ROUTER.model, 'passive', 0.5, true],
    ])
    // the box itself is still the one device of its kind (S-INV-5): the sensor does not make a device of its own box
    const all = await devices(c)
    expect(all.items.filter((d) => d.is_box)).toHaveLength(1)
    expect(all.items, 'the box, and the two devices').toHaveLength(base.length + 2)
  } finally { await c.dispose() }
})

test('the new devices wait in the not-approved list; approving one leaves the other waiting (S-INV-3)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const { router, pc } = await waitForReplay(c)
    await page.goto('/devices')
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${base.length + 2} devices, 2 not yet approved`)
    await expect(page.getByRole('heading', { name: '2 new devices not approved' })).toBeVisible()
    const pending = page.getByRole('list', { name: '2 new devices not approved' })
    await expect(pending.getByRole('listitem')).toHaveCount(2)
    await expect(pending.getByRole('listitem').filter({ hasText: `${ROUTER.model}` })).toContainText(`${ROUTER.ip}, ${ROUTER.mac}, Router. First seen`)
    await expect(pending.getByRole('listitem').filter({ hasText: PC.hostname })).toContainText(`${PC.ip}, ${PC.mac}, Unknown. First seen`)
    await expect(page.getByRole('button', { name: 'Not approved (2)' })).toBeVisible()
    await shot(page, 'real', 'sensor-passive-pending')
    await noVietnamese(page, 'devices')
    await expectAccessible(page, 'devices with the sensor devices')
    // the list says where each value came from
    const row = page.getByRole('table', { name: 'Device list' }).getByRole('row').filter({ hasText: ROUTER.ip })
    await expect(row).toContainText('Passive')
    await expect(row).toContainText('medium confidence')
    // approve the PC from the waiting list
    await pending.getByRole('listitem').filter({ hasText: PC.hostname }).getByRole('button', { name: 'Approve' }).click()
    await expect(page.locator('[data-sonner-toast]').filter({ hasText: `Approved ${PC.hostname}.` }).first()).toBeVisible()
    await expect(page.getByRole('heading', { level: 1 })).toHaveText(`${base.length + 2} devices, 1 not yet approved`)
    const left = page.getByRole('list', { name: '1 new device not approved' }) // the list is named after its count
    await expect(left.getByRole('listitem')).toHaveCount(1)
    await expect(left.getByRole('listitem')).toContainText(`${ROUTER.ip}, ${ROUTER.mac}, Router.`)
    expect((await device(c, pc.id)).asset.approved).toBe(true)
    expect((await device(c, router.id)).asset.approved, 'the other device still waits').toBe(false)
    noErrors(errors)
  } finally { await c.dispose() }
})

test('every new device opened one "unknown device" alert (S-INV-3, notify on by default)', async () => {
  const c = await as('admin')
  try {
    expect((await devices(c)).notify_new, 'notify about new devices is on by default').toBe(true)
    const { router, pc } = await waitForReplay(c)
    const list = (await api<{ incidents: { kind: string; title: string; status: string; link: string; devices: { id: string; name: string }[] }[] }>(c, 'GET', '/notify/incidents')).body.incidents
    for (const [d, name] of [[router, ROUTER.ip], [pc, PC.hostname]] as const) {
      const mine = list.filter((i) => i.devices.some((x) => x.id === d.id))
      expect(mine, `alerts for ${name}`).toHaveLength(1)
      expect(mine[0]).toMatchObject({ kind: 'unknown_device', title: `A new unknown device appeared: ${name}`, status: 'new', link: `/devices/${d.id}` })
    }
  } finally { await c.dispose() }
})

test('the Sensors section says the sensor is reporting, with its version, after its first heartbeat', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    await expect.poll(async () => (await sensor(c))[0]?.status, { message: 'the sensor reports', timeout: 75_000, intervals: [2000] }).toBe('online')
    const s = (await sensor(c))[0]!
    expect(s.version).toBe('0.0.0-dev')
    expect(s.last_seen).not.toBeNull()
    expect(Date.now() - Date.parse(s.last_seen!), 'the contact is recent').toBeLessThan(120_000)
    await page.goto('/devices/setup')
    await expect(page.getByRole('heading', { name: 'Sensor on this box' })).toBeVisible()
    await expect(sensorRow(page)).toContainText('Reporting')
    await expect(sensorRow(page)).toContainText('0.0.0-dev')
    await expect(sensorRow(page)).toContainText('Contact')
    await expect(sensorRow(page)).toContainText('ago')
    await expectAccessible(page, 'sensors')
    noErrors(errors)
  } finally { await c.dispose() }
})

test('the sensor started again on the same recording makes no second device and no second value in use (D-80 (1))', async () => {
  const c = await as('admin')
  try {
    const before = made(await devices(c)).map((d) => d.id).sort()
    const seen = (await sensor(c))[0]!.last_seen
    await sensorCtl({ start: 'passive', replay: 'lan-discovery' }) // a new process: its own memory of what it sent is empty; core's filter of the last 15 minutes still holds
    await expect.poll(async () => (await sensor(c))[0]?.last_seen, { message: 'the new process reported', timeout: 30_000, intervals: [500] }).not.toBe(seen)
    await wait(15_000) // time enough for it to read the recording again (the first read delivered within seconds)
    const after = made(await devices(c))
    expect(after.map((d) => d.id).sort(), 'same two devices').toEqual(before)
    expect(new Set(after.map((d) => d.mac)).size, 'one device per MAC').toBe(after.length)
    const router = after.find((d) => d.ip === ROUTER.ip)!
    const obs = (await device(c, router.id)).observations
    expect(obs.filter((o) => o.current).map((o) => o.field).sort(), 'one value in use per field').toEqual(['kind', 'mac', 'model'])
    expect(obs, 'and no observation was added by the second read').toHaveLength(3)
  } finally { await c.dispose() }
})

test('scope that is not attested cannot be saved with scanning on (INV-2): the refusal saves nothing', async () => {
  const c = await as('admin')
  try {
    const before = await settings(c)
    const r = await api<{ error: { code: string } }>(c, 'PUT', '/inventory/settings', { ...before, lan_ranges: [RANGE], active: { ...before.active, enabled: true }, scope_confirmed: false })
    expect(r, 'refused, with the reason').toMatchObject({ status: 400, body: { error: { code: 'scope_not_confirmed' } } })
    expect(await settings(c), 'nothing was saved').toEqual(before)
  } finally { await c.dispose() }
})

test('with the active switch off, or the window closed, the box sends nothing to the sensor (INV-2, INV-3, D-84 (1))', async () => {
  test.setTimeout(240_000)
  const c = await as('admin')
  try {
    expect(made(await devices(c)).map((d) => d.ip).sort(), 'devices to scan exist (from the recording): only the rules keep the box from scanning them').toEqual([ROUTER.ip, PC.ip])
    await save(c, { enabled: false })
    await sensorCtl({ start: 'active' }) // one process for this test and the next: the runs that come when the window opens show it was polling all along
    await wait(TICK)
    expect(await nmapRuns(), 'switch off: no nmap run').toEqual([])
    await save(c, { enabled: true, from: orgClock(2), to: orgClock(3) }) // a window that is not now, in the organization time zone
    await wait(TICK)
    expect(await nmapRuns(), 'window closed: no nmap run, not even the gentle first scan of a new device').toEqual([])
    expect(made(await devices(c)).map((d) => [d.ip, d.first_scan_at]).sort(), 'and no device was scanned').toEqual([[ROUTER.ip, null], [PC.ip, null]])
  } finally { await c.dispose() }
})

test('window open: a sweep of the confirmed range only, then one scan per device in the shapes of INV-5 (D-84, INV-1, INV-4, INV-5)', async () => {
  test.setTimeout(240_000)
  const c = await as('admin')
  try {
    await save(c, {}) // open from an hour ago to three hours ahead (org time zone), every day: no midnight or window start inside the run; rate 50, .240/28 excluded
    let runs: string[] = []
    // the sweep (4 batches of at most 64) and then a scan for each device it queued: .1 (router), .21, .2, .5
    await expect.poll(async () => { runs = await nmapRuns(); return runs.length }, { message: 'the sweep and the device scans ran', timeout: 150_000, intervals: [2000] }).toBe(4 + 4)
    const sweeps = runs.filter((l) => shape(l) === 'sweep')
    expect(sweeps).toHaveLength(4)
    const swept = sweeps.flatMap(targetsOf)
    // INV-1: every address sent is inside the range and outside the exclusion; nothing public, nothing excluded; the whole allowed range was covered, once
    const allowed = Array.from({ length: 254 }, (_, i) => `192.168.10.${i + 1}`).filter((ip) => Number(ip.split('.')[3]) < 240)
    expect(swept.sort((a, b) => Number(a.split('.')[3]) - Number(b.split('.')[3])), 'the sweep covers the range minus the exclusion, once').toEqual(allowed)
    expect(runs.join('\n'), 'no address outside the range is ever an argument').not.toContain('203.0.113.9')
    for (const l of sweeps) expect(l.startsWith('--privileged -sn -n --max-rate 50 -oX - '), `sweep flags: ${l.slice(0, 60)}`).toBe(true)
    // INV-5 / D-84: the unclassified devices got the gentle scan, one target each, no -O, no -sV, no --script; the router (classified) the normal one
    const scans = runs.filter((l) => shape(l) !== 'sweep')
    const gentle = scans.filter((l) => shape(l) === 'gentle')
    expect(gentle.map((l) => l.slice(GENTLE.length)).sort(), 'gentle: the three unclassified devices, each once').toEqual(['192.168.10.2', '192.168.10.21', '192.168.10.5'])
    for (const l of gentle) { expect(l.startsWith(GENTLE), l).toBe(true); expect(l).not.toMatch(/ -O | -sV |--script/) }
    expect(scans.filter((l) => shape(l) === 'normal'), 'normal: the router').toEqual([`${NORMAL}${ROUTER.ip}`])
    // the sweep made two new devices from what answered, and nothing from the host outside the range or the host that was down
    await expect.poll(async () => made(await devices(c)).map((d) => d.ip).sort(), { timeout: 20_000 }).toEqual(['192.168.10.1', '192.168.10.2', '192.168.10.21', '192.168.10.5'])
    const list = made(await devices(c))
    const acme = list.find((d) => d.ip === '192.168.10.2')!
    expect(acme).toMatchObject({ mac: 'aa:bb:cc:00:00:02', approved: false, origin: 'discovered' })
    expect(acme.vendor).toMatchObject({ value: 'Acme Networks', source: 'nmap' })
    expect(acme.vendor!.confidence).toBeLessThan(1) // INV-8: a scan is never certain
    expect(list.find((d) => d.ip === '192.168.10.5')).toMatchObject({ mac: 'aa:bb:cc:00:00:05', approved: false })
    const everything = (await devices(c)).items // not only `made`: the host outside the range must be in no row at all
    expect(everything.map((d) => d.ip), 'the host outside the range is not a device').not.toContain('203.0.113.9')
    expect(everything.map((d) => d.mac), 'nor is its MAC').not.toContain('aa:bb:cc:00:00:99')
    expect(everything.length, 'the box, and the four devices').toBe(base.length + 4)
    // the gentle first scan is recorded for the devices that got it; the router (a known type that is not fragile) had none, only the normal scan
    for (const d of list) {
      if (d.ip === ROUTER.ip) expect(d.first_scan_at, 'the router had no gentle first scan').toBeNull()
      else expect(d.first_scan_at, `${d.ip}: the first scan is recorded`).not.toBeNull()
    }
  } finally { await c.dispose() }
})

test('what the scan found is added beside the passive values, with its source and confidence (D-84, INV-8)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const list = made(await devices(c))
    const router = list.find((d) => d.ip === ROUTER.ip)!
    const d = await device(c, router.id)
    // from the normal scan of the router (device.xml, re-addressed to it): the software its services name (their CPE), the operating system, the name
    const sw = d.asset.software.map((x) => [x.display, x.source]).sort()
    expect(sw).toEqual([['Apache httpd 2.4.52', 'nmap'], ['Linux 5.4 - 5.15', 'nmap'], ['OpenSSH 8.9p1', 'nmap'], ['Squid http proxy 5.7', 'nmap']])
    for (const x of d.asset.software) { expect(x.confidence, `${x.display}: a scan is never certain`).toBeLessThan(1); expect(x.confidence).toBeGreaterThan(0) }
    expect(d.asset.os).toMatchObject({ value: 'Linux 5.4 - 5.15', source: 'nmap' })
    expect(d.asset.os!.confidence).toBeCloseTo(0.96 * 0.95, 3) // INV-8: the OS accuracy x 0.95
    expect(d.asset.hostname).toBe('web01.lan')
    expect(d.observations.find((o) => o.field === 'hostname')).toMatchObject({ value: 'web01.lan', source: 'nmap', current: true })
    // the passive values are still there and still in use: the scan did not contest them (it sent no kind, and its MAC was not the device's)
    expect(d.observations.filter((o) => o.source === 'passive').map((o) => [o.field, o.value, o.current]).sort()).toEqual([['kind', 'router', true], ['mac', ROUTER.mac, true], ['model', ROUTER.model, true]])
    expect(d.asset.kind).toBe('router')
    // the gentle scan of the other devices (the printer fixture: no -sV, so only what the service banner names): one software each, source nmap
    for (const ip of [PC.ip, '192.168.10.2', '192.168.10.5']) {
      const x = list.find((y) => y.ip === ip)!
      const sws = (await device(c, x.id)).asset.software.map((s) => [s.display, s.source])
      expect(sws, `${ip}: software of its gentle scan`).toEqual([['Acme Embedded httpd 1.2', 'nmap']])
    }
    // the page says the same: the software table, and the observation table with the scan beside the passive source
    await page.goto(`/devices/${router.id}`)
    const software = page.getByRole('table', { name: 'Software on the device' })
    for (const name of ['OpenSSH 8.9p1', 'Apache httpd 2.4.52', 'Squid http proxy 5.7']) await expect(software).toContainText(name)
    const obs = page.getByRole('table', { name: 'Observations for this device' })
    await expect(obs.getByRole('row').filter({ hasText: 'web01.lan' })).toContainText('In use')
    await expect(obs.getByRole('row').filter({ hasText: ROUTER.model })).toContainText('In use')
    await shot(page, 'real', 'sensor-active-device')
    await expectAccessible(page, 'a scanned device')
    noErrors(errors)
  } finally { await c.dispose() }
})

// Backend not built (D-171 (2)): nothing writes inv_service, so the "Open services" table of a device stays empty after a scan (the ports of the fixture are in the
// argv-driven answer: 22, 80, 8080). The flow is here for the day it is built. .ai/deferred/feat-e2e-real-sensors.md
test.fixme('the open ports of the scan are listed under Open services (S-INV-1)', async ({ page }) => {
  const c = await as('admin')
  try {
    const router = made(await devices(c)).find((d) => d.ip === ROUTER.ip)!
    await page.goto(`/devices/${router.id}`)
    const services = page.getByRole('table', { name: 'Services open on the device' })
    for (const name of ['OpenSSH 8.9p1', 'Apache httpd 2.4.52', 'Squid http proxy 5.7']) await expect(services).toContainText(name)
    await expect(services.getByRole('row')).toHaveCount(1 + 3)
  } finally { await c.dispose() }
})

test('the probe log has one row per nmap run, written with the shape, the flags and the targets as ranges (INV-9)', async () => {
  const c = await as('admin')
  try {
    const r = await api<{ categories: { scan_probes: { shape: string; rate: number; hosts: number; flags: string; targets: string; result: string; job_id: string }[] } }>(c, 'GET', '/core/logs/export?categories=scan_probes')
    expect(r.status).toBe(200)
    const rows = r.body.categories.scan_probes
    const runs = await nmapRuns()
    expect(rows.map((x) => x.shape), 'one row per nmap run, in order').toEqual(runs.map(shape))
    const sweeps = rows.filter((x) => x.shape === 'sweep')
    // the targets of the sweep are collapsed to ranges, and the hole of the exclusion shows: .240-.255 is in none of them
    expect(sweeps.map((x) => x.targets)).toEqual(['192.168.10.1-192.168.10.64', '192.168.10.65-192.168.10.128', '192.168.10.129-192.168.10.192', '192.168.10.193-192.168.10.239'])
    expect(sweeps.map((x) => x.hosts)).toEqual([64, 64, 64, 47])
    for (const x of sweeps) expect(x).toMatchObject({ rate: 50, flags: '--privileged -sn -n --max-rate 50' })
    for (const x of rows.filter((y) => y.shape === 'gentle')) expect(x).toMatchObject({ rate: 1, hosts: 1, flags: GENTLE.replace(' -oX - ', '').trim() })
    expect(rows.every((x) => x.job_id.startsWith('saj-') && x.result.startsWith('ok')), 'every run ended ok').toBe(true)
    expect(JSON.stringify(rows), 'the public host was never a target').not.toContain('203.0.113.9')
  } finally { await c.dispose() }
})

test('a device scanned once is not scanned again, and the sweep does not repeat on the next tick (INV-5, D-84 (6))', async () => {
  test.setTimeout(150_000)
  const before = await nmapRuns()
  await wait(TICK)
  expect(await nmapRuns(), 'no new nmap run on the next tick').toEqual(before)
})
