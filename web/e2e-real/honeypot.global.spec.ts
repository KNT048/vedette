// Internal traps on the real backend through vedette-host (S-HP-1, S-HP-2, D-102, D-161, D-89, WP-30 slice 8b). The host is the fake machine of
// cmd/vedette/e2ehost_test.go: the real decoy_ip.* and container.* commands of host/ops over a temporary root, with a systemctl and a podman that
// remember what start and stop did. No container runs: the spec plays the container and appends OpenCanary JSON lines to <honeypot_dir>/log/opencanary.jsonl,
// the way the container would (append, newline), and the real run job reads them (poll every 15 s, honeypot.go).
// Global project: the decoy address, the traps, the LAN range and the host's decoys are box-wide state; the last step puts back what it can
// (traps off, tokens and devices deleted, LAN ranges and module switch as they were). Steps from e2e/qa/honeypot.spec.ts, minus the mock-only parts.
// One run on a fresh box (D-172): this spec cannot be re-run on a HOLD=1 box. The secondary IP cannot be cleared once set (so the "clean box" check fails),
// and lines written in the same 10-minute window join the hits of the earlier run instead of making new ones.
// What the GUI does not show: the decoy's MAC (D-102 gives each decoy IP its own MAC, but neither GET /honeypot nor the page carries it), so the MAC
// is checked on the host's side (GET /v1/state/net through the control endpoint) and the page is checked for the IP.
import { appendFileSync, existsSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { expect, request, test, type APIRequestContext, type Locator, type Page } from '@playwright/test'
import { api, authFile, box, hostHoneypot, hostKnob, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

const DECOY_IP = '192.168.1.200'
const DECOY_NAME = 'FILESRV-OLD'
const LAN = '192.168.1.0/24' // the network of the fake host's management card (eth0 192.168.1.50/24): the host refuses a decoy outside it
const SVC = { smb: 'SMB (file sharing)', ssh: 'SSH', http: 'HTTP (fake admin page)' } as const

interface Trap { service: string; port: number; enabled: boolean; state: 'off' | 'listening' | 'conflict'; hits_7d: number }
interface Overview { secondary_ip: string | null; hostname: string; lan: string | null; box: { ip: string | null; name: string }; traps: Trap[]; summary: { today: number; week: number } }
interface Hit { id: string; ts: string; kind: 'service' | 'token' | 'scan'; service: string | null; label: string; port: number | null; src_ip: string; src_asset_id: string | null; src_name: string | null; is_test: boolean; excerpt: string }
interface HitDetail extends Hit { trap_ip: string; trap_hostname: string; events: { text: string; mark: boolean; source: string }[] }
interface Tok { id: string; type: 'file' | 'credential'; name: string; value: string; password: string | null; triggers: number; last_triggered_at: string | null }
interface Incident { id: string; kind: string; title: string; link: string; severity: string; status: string }

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const get = async <T>(c: APIRequestContext, path: string) => { const r = await api<T>(c, 'GET', path); expect(r.status, `GET ${path}: ${JSON.stringify(r.body)}`).toBe(200); return r.body }
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const sw = (page: Page, service: string) => page.getByRole('switch', { name: `Turn on ${service} trap` })
/** 5xx answers of the API that the page saw: a test ends with `expect(server).toEqual([])`. */
function watch5xx(page: Page): string[] {
  const seen: string[] = []
  page.on('response', (r) => { const u = new URL(r.url()); if (u.pathname.startsWith('/api/') && r.status() >= 500) seen.push(`${r.request().method()} ${u.pathname} -> ${r.status()}`) })
  return seen
}
const trapRow =(page: Page, service: string): Locator => page.getByRole('table', { name: 'Traps and their status' }).getByRole('row').filter({ has: sw(page, service) })

// ---- the trap log: what the container would write ----
const logPath = () => join(box().honeypot_dir, 'log', 'opencanary.jsonl')
const confDir = () => join(box().honeypot_dir, 'config')
/** OpenCanary's utc_time: UTC, "YYYY-MM-DD HH:MM:SS.ffffff". */
const utc = () => new Date().toISOString().replace('T', ' ').replace('Z', '000')
/** Appends lines to the log the way the container does: one write per line, newline at the end, the log folder made if the container has not yet. */
function appendLog(...lines: (string | Buffer)[]) {
  mkdirSync(dirname(logPath()), { recursive: true })
  for (const l of lines) appendFileSync(logPath(), Buffer.concat([typeof l === 'string' ? Buffer.from(l) : l, Buffer.from('\n')]), { mode: 0o644 })
}
interface Rec { logtype: number; src: string; srcPort: number; dst?: string; dstPort?: number; data?: Record<string, string> }
const rec = (r: Rec) => JSON.stringify({
  logtype: r.logtype, src_host: r.src, src_port: r.srcPort, ...(r.dst ? { dst_host: r.dst, dst_port: r.dstPort } : {}),
  node_id: 'vedette-honeypot', local_time: utc(), utc_time: utc(), logdata: r.data ?? {},
})

// ---- what the test made, so it can be put back ----
const made = { devices: [] as string[], tokens: [] as string[] }
let originalLan: string[] = []
let lanChanged = false
let originalModule = true
let src: { id: string; ip: string; name: string }
let src2: { id: string; ip: string; name: string }
const tokens: { file?: Tok; cred?: Tok } = {}

test.beforeAll(async () => {
  const admin = await as('admin')
  try {
    const mods = (await get<{ modules: { id: string; enabled: boolean }[] }>(admin, '/modules')).modules
    originalModule = mods.find((m) => m.id === 'honeypot')?.enabled ?? false
    if (!originalModule) {
      const on = await api(admin, 'PATCH', '/modules/honeypot', { enabled: true, with_dependencies: true })
      expect(on.status, `enable honeypot: ${JSON.stringify(on.body)}`).toBe(200)
    }
    // the decoy has to be inside the LAN range the box picks AND inside the network of the host's management card (192.168.1.0/24 on the fake host,
    // which the wizard's ranges do not hold): declare it, as an administrator does under Devices, Scope and sensors; put back at the end
    const cur = await get<Record<string, unknown> & { lan_ranges: string[] }>(admin, '/inventory/settings')
    originalLan = cur.lan_ranges
    lanChanged = true // set before the PUT: afterAll puts the ranges back even if the answer is lost
    const next = { ...cur, lan_ranges: [...cur.lan_ranges, LAN], scope_confirmed: true }
    delete next.adjusted
    const put = await api(admin, 'PUT', '/inventory/settings', next)
    expect(put.status, `declare ${LAN}: ${JSON.stringify(put.body)}`).toBe(200)
    // two devices that are in the inventory: the sources of the real lines
    const mk = async (ip: string) => {
      const name = uniq('hp-src')
      const d = await api<{ id: string }>(admin, 'POST', '/inventory/devices', { vendor: `Vend-${name}`, product: `Laptop-${name}`, version: '1.0', name, ip })
      expect(d.status, `device ${ip}: ${JSON.stringify(d.body)}`).toBe(201)
      made.devices.push(d.body.id)
      return { id: d.body.id, ip, name }
    }
    src = await mk('192.168.1.60')
    src2 = await mk('192.168.1.61')
  } finally { await admin.dispose() }
})

// Every step runs whatever the one before did (a failed delete must not leave the LAN ranges or the module switch changed); what failed is thrown at the end.
test.afterAll(async () => {
  const problems: string[] = []
  const step = async (what: string, fn: () => Promise<unknown>) => { try { await fn() } catch (e) { problems.push(`${what}: ${(e as Error).message.split('\n')[0]}`) } }
  await step('host start knob', () => hostKnob('hp_start', 'ok'))
  const admin = await as('admin')
  try {
    for (const svc of ['smb', 'rdp', 'ssh', 'mssql', 'http']) {
      await step(`trap ${svc} off`, async () => { const r = await api(admin, 'PATCH', `/honeypot/traps/${svc}`, { enabled: false }); expect(r.status, JSON.stringify(r.body)).toBe(200) })
    }
    for (const id of made.tokens) await step(`delete token ${id}`, async () => expect([204, 404]).toContain((await api(admin, 'DELETE', `/honeypot/tokens/${id}`)).status))
    for (const id of made.devices) await step(`delete device ${id}`, async () => expect([200, 204, 404]).toContain((await api(admin, 'DELETE', `/inventory/devices/${id}`)).status))
    if (lanChanged) {
      await step('LAN ranges put back', async () => {
        const cur = await get<Record<string, unknown>>(admin, '/inventory/settings')
        const back = { ...cur, lan_ranges: originalLan, scope_confirmed: true }
        delete back.adjusted
        const r = await api(admin, 'PUT', '/inventory/settings', back)
        expect(r.status, JSON.stringify(r.body)).toBe(200)
      })
    }
    // the host has been told to stop before the module goes off
    await step('host stopped and decoy dropped', () => expect.poll(async () => { const h = await hostHoneypot(); return `${h.unit_state} ${h.decoys.length}` }, { timeout: 45_000 }).toBe('inactive 0'))
    if (!originalModule) await step('honeypot module off', async () => { const r = await api(admin, 'PATCH', '/modules/honeypot', { enabled: false }); expect(r.status, JSON.stringify(r.body)).toBe(200) })
  } finally { await admin.dispose() }
  expect(problems, 'cleanup of the honeypot spec').toEqual([])
})

test('the page starts empty: the three steps, switches locked, and each wrong address says why (S-HP-1, INV-5)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  const admin = await as('admin')
  const o = await get<Overview>(admin, '/honeypot')
  await admin.dispose()
  expect(o.secondary_ip, 'a clean box has no secondary IP').toBeNull()
  expect(o.lan, 'the box network is the one the host management card is on').toBe(LAN)
  expect(o.box.ip, 'the box knows its own address (the fake host card)').toBe('192.168.1.50')
  expect(o.traps.every((t) => !t.enabled)).toBe(true)

  await page.goto('/honeypot')
  await expect(h1(page)).toHaveText(/No traps are on/)
  await expect(page.getByText('Get started with internal traps in three steps')).toBeVisible()
  await expect(page.getByText(DECOY_NAME, { exact: true })).toHaveCount(0)
  await expect(page.getByText(DECOY_IP)).toHaveCount(0)
  await expect(page.getByText(/No trap is on yet, so there is nothing to record/).locator('visible=true').first()).toBeVisible()
  await expect(sw(page, SVC.smb)).toBeDisabled()
  await expect(page.getByRole('button', { name: `Test trap ${SVC.smb}` })).toBeDisabled()
  await shot(page, 'real', 'honeypot-clean')

  const ip = page.getByLabel('Trap secondary IP')
  const host = page.getByLabel('Fake hostname')
  const save = page.getByRole('button', { name: 'Save', exact: true })
  await ip.fill('abc'); await host.fill(DECOY_NAME); await save.click()
  await expect(page.getByText(/is not valid/)).toBeVisible()
  await ip.fill('192.168.1.010'); await save.click()
  await expect(page.getByText(/no leading zeros/)).toBeVisible()
  await ip.fill('10.0.0.5'); await save.click()
  await expect(page.getByText(/must be inside the box's network/)).toBeVisible()
  await ip.fill('192.168.1.50'); await save.click()
  await expect(page.getByText(/the Vedette box's own IP/)).toBeVisible()
  await ip.fill('192.168.1.0'); await save.click()
  await expect(page.getByText(/not the network or broadcast address/)).toBeVisible()
  await ip.fill(src.ip); await save.click()
  await expect(page.locator('#hp-ip-error')).toContainText('belongs to device')
  await ip.fill(DECOY_IP); await host.fill('file.srv_old'); await save.click()
  await expect(page.locator('#hp-host-error')).toContainText('letters, digits and hyphens')
  await expect(page.locator('#hp-ip-error')).toHaveCount(0)
  await expect(host).toBeFocused()
  await host.fill(''); await save.click()
  await expect(page.locator('#hp-host-error')).toContainText('Enter a fake hostname')
  await host.fill(DECOY_NAME); await host.press('Enter')
  await toast(page, /Decoy saved/)
  await expect(page.getByText('Get started with internal traps in three steps')).toHaveCount(0)
  await page.reload()
  await expect(ip).toHaveValue(DECOY_IP)
  await expect(host).toHaveValue(DECOY_NAME)
  // no trap is on: the host holds no decoy and the container is not asked for anything
  expect((await hostHoneypot()).decoys, 'saving the address does not put it on the network').toEqual([])
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

// Issue #270 (fixed, 59da3e7): usable() computed the last address of 192.168.1.0/24 as 192.168.0.255, so the broadcast address was accepted.
test('the broadcast address is refused as the secondary IP, in the page and by the API (INV-5, FORBID-1)', async ({ page }) => {
  await page.goto('/honeypot')
  await page.getByLabel('Trap secondary IP').fill('192.168.1.255')
  await page.getByRole('button', { name: 'Save', exact: true }).click()
  await expect(page.getByText(/not the network or broadcast address/)).toBeVisible()
  const admin = await as('admin')
  const r = await api<{ error: { code: string } }>(admin, 'PUT', '/honeypot/config', { secondary_ip: '192.168.1.255', hostname: DECOY_NAME })
  expect(r).toMatchObject({ status: 400, body: { error: { code: 'ip_outside_lan' } } })
  expect((await get<Overview>(admin, '/honeypot')).secondary_ip, 'the decoy address is unchanged').toBe(DECOY_IP)
  await admin.dispose()
})

test('a host that cannot start the container never makes a trap "Listening"; once it can, the GUI follows the host (S-HP-1, D-161)', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  await hostKnob('hp_start', 'fail')
  const before = (await hostHoneypot()).restarts
  await page.goto('/honeypot')
  const [patched] = await Promise.all([
    page.waitForResponse((r) => r.url().endsWith('/api/v1/honeypot/traps/ssh') && r.request().method() === 'PATCH'),
    sw(page, SVC.ssh).click(),
  ])
  // the answer to the switch and the page right after it never claim "listening": the host has not said so (and cannot)
  const answer = (await patched.json()) as Overview
  expect(answer.traps.find((t) => t.service === 'ssh'), 'the PATCH answer').toMatchObject({ enabled: true, state: 'off' })
  await expect(sw(page, SVC.ssh)).toBeChecked()
  await expect(trapRow(page, SVC.ssh), 'before any reload').not.toContainText('Listening')
  await toast(page, /SSH trap is on/)
  // the module placed the decoy on the host and asked for the container; the host's start failed
  await expect.poll(async () => (await hostHoneypot()).restarts, { message: 'the container was asked to start', timeout: 45_000 }).toBeGreaterThan(before)
  const mid = await hostHoneypot()
  expect(mid.unit_state, 'the failed start left the container down').not.toBe('active')
  await page.reload()
  await expect(sw(page, SVC.ssh)).toBeChecked()
  await expect(trapRow(page, SVC.ssh)).toContainText('Off')
  await expect(page.getByText('Listening')).toHaveCount(0)
  await expect(h1(page)).toHaveText(/trap hit|Traps were hit|No trap was hit/) // a trap is on, so the heading is not "No traps are on"

  // the host can start it again: the next Apply (a second trap switched on kicks it) makes both traps listen, and only then
  await hostKnob('hp_start', 'ok')
  await sw(page, SVC.http).click()
  await expect(sw(page, SVC.http)).toBeChecked()
  await expect(async () => {
    await page.reload()
    await expect(trapRow(page, SVC.ssh)).toContainText('Listening', { timeout: 3_000 })
  }, 'the GUI says Listening after the host started the container').toPass({ timeout: 60_000 })
  const live = await hostHoneypot()
  expect(live.unit_state, 'Listening only when the host runs the container').toBe('active')
  expect(live.decoys.map((d) => d.ip)).toEqual([DECOY_IP])
  await expect(trapRow(page, SVC.http)).toContainText('Listening')
  await expect(page.getByText('Listening').locator('visible=true')).toHaveCount(2)
  await shot(page, 'real', 'honeypot-listening')
  const admin = await as('admin')
  const o = await get<Overview>(admin, '/honeypot')
  await admin.dispose()
  expect(o.traps.filter((t) => t.state === 'listening').map((t) => t.service).sort()).toEqual(['http', 'ssh'])
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

test('the decoy IP and its MAC are on the host, the written files match what the GUI set (D-102, D-89, S-HP-1)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  await page.goto('/honeypot')
  const restartsBefore = (await hostHoneypot()).restarts
  await sw(page, SVC.smb).click()
  await expect(sw(page, SVC.smb)).toBeChecked()
  await expect(async () => {
    await page.reload()
    await expect(trapRow(page, SVC.smb)).toContainText('Listening', { timeout: 3_000 })
  }, 'SMB is Listening once the host restarted the container with the new file').toPass({ timeout: 60_000 })
  // a new configuration file makes a running container restart (D-161): the host was asked once more
  await expect.poll(async () => (await hostHoneypot()).restarts, { message: 'switching SMB on restarted the container' }).toBeGreaterThan(restartsBefore)
  await expect(page.getByLabel('Trap secondary IP')).toHaveValue(DECOY_IP)

  // D-102: one decoy IP, one MAC of its own: locally administered, unicast
  const hs = await hostHoneypot()
  expect(hs.decoys).toHaveLength(1)
  expect(hs.decoys[0].ip).toBe(DECOY_IP)
  expect(hs.decoys[0].mac).toMatch(/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/)
  const first = parseInt(hs.decoys[0].mac.slice(0, 2), 16)
  expect(first & 0x02, 'locally administered bit').toBe(0x02)
  expect(first & 0x01, 'unicast').toBe(0)
  expect(hs.decoys[0].mac, 'not the MAC of the box card (D-102 (7))').not.toBe('02:00:00:00:00:01')

  // the files the container reads (read-only mount in production): core wrote them, in the config folder only
  const conf = () => JSON.parse(readFileSync(join(confDir(), 'opencanary.conf'), 'utf8')) as Record<string, unknown>
  await expect.poll(() => (existsSync(join(confDir(), 'opencanary.conf')) ? conf()['smb.enabled'] : undefined), { message: 'opencanary.conf is written', timeout: 30_000 }).toBe(true)
  const c = conf()
  expect(c['device.node_id']).toBe('vedette-honeypot')
  expect({ ssh: [c['ssh.enabled'], c['ssh.port']], http: [c['http.enabled'], c['http.port']], smb: c['smb.enabled'], rdp: [c['rdp.enabled'], c['rdp.port']], mssql: [c['mssql.enabled'], c['mssql.port']] })
    .toEqual({ ssh: [true, 22], http: [true, 80], smb: true, rdp: [false, 3389], mssql: [false, 1433] })
  for (const off of ['ftp', 'git', 'httpproxy', 'llmnr', 'mysql', 'ntp', 'portscan', 'redis', 'sip', 'snmp', 'tcpbanner', 'telnet', 'tftp', 'vnc']) expect(c[`${off}.enabled`], `${off} stays off (INV-2)`).toBe(false)
  const logger = c.logger as { kwargs: { handlers: { file: { filename: string } } } }
  expect(logger.kwargs.handlers.file.filename, 'the container writes the log in the log folder, not in the config folder').toMatch(/opencanary\.jsonl$/)
  expect(JSON.parse(readFileSync(join(confDir(), 'honeytokens.json'), 'utf8'))).toEqual({ files: [] })
  expect(existsSync(join(confDir(), 'opencanary.jsonl')), 'the log is not in the config folder').toBe(false)
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

test('plant a file token and a credential token, and test them (S-HP-2)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  await page.goto('/honeypot')
  const fileName = uniq('Payroll')
  await page.getByLabel('Token type').selectOption({ label: 'Decoy file' })
  await page.getByLabel('File name', { exact: true }).fill(fileName)
  await page.getByLabel('Where will you plant it?').fill('\\\\SRV-FILE\\HR')
  await page.getByRole('button', { name: 'Create token' }).click()
  await toast(page, /Token created/)
  const credName = uniq('svc-old')
  await page.getByLabel('Token type').selectOption({ label: 'Fake credentials' })
  await page.getByLabel('User name', { exact: true }).fill(credName)
  await page.getByLabel('Where will you plant it?').fill('The IT password manager')
  await page.getByRole('button', { name: 'Create token' }).click()
  await expect(page.getByRole('list', { name: 'Honey tokens' }).getByRole('listitem').filter({ hasText: credName })).toHaveCount(1)

  const admin = await as('admin')
  const list = (await get<{ items: Tok[] }>(admin, '/honeypot/tokens')).items
  tokens.file = list.find((t) => t.type === 'file' && t.name === fileName)
  tokens.cred = list.find((t) => t.type === 'credential' && t.name === credName)
  expect(tokens.file, 'the file token is stored').toBeDefined()
  expect(tokens.cred, 'the credential token is stored').toBeDefined()
  made.tokens.push(tokens.file!.id, tokens.cred!.id)
  expect(tokens.file!.value).toMatch(/\.(xlsx|docx)$/i)
  expect(tokens.cred!.password, 'the decoy password is made for the credential token').toBeTruthy()
  await admin.dispose()

  const li = (name: string) => page.getByRole('list', { name: 'Honey tokens' }).getByRole('listitem').filter({ hasText: name })
  await expect(li(fileName)).toContainText(`Plant at: \\\\SRV-FILE\\HR`)
  await expect(li(fileName)).toContainText('Never triggered')
  await expect(li(credName)).toContainText('The IT password manager')
  await expect(li(credName)).toContainText(`user: ${tokens.cred!.value}`)
  await expectAccessible(page, 'honeypot with tokens')

  // the file token goes into honeytokens.json (names only), the credential token never goes to the shared folder (D-90 (3))
  await expect.poll(() => (JSON.parse(readFileSync(join(confDir(), 'honeytokens.json'), 'utf8')) as { files: string[] }).files, { message: 'honeytokens.json lists the file', timeout: 30_000 }).toEqual([tokens.file!.value])
  const shared = readFileSync(join(confDir(), 'honeytokens.json'), 'utf8') + readFileSync(join(confDir(), 'opencanary.conf'), 'utf8')
  expect(shared, 'no password on the shared folder').not.toContain(tokens.cred!.password!)
  expect(shared.includes(tokens.cred!.value), 'the credential name is not written either').toBe(false)

  // Test token, Test trap: labelled test hits, from the box, no alert
  await page.getByRole('button', { name: `Test token ${fileName}` }).click()
  await toast(page, new RegExp(`Recorded a test trigger for ${fileName}`))
  await page.getByRole('button', { name: `Test trap ${SVC.smb}` }).click()
  await toast(page, /Recorded a test hit on the SMB \(file sharing\) trap/)
  await expect(h1(page), 'a test hit is not a hit').toHaveText(/No trap was hit in the last 7 days/)
  const row = page.locator('tr:visible, li:visible').filter({ hasText: 'Vedette box (test)' }).first()
  await expect(row.getByText('Test', { exact: true })).toBeVisible()
  await row.getByRole('link').first().click()
  await expect(h1(page)).toHaveText(/Test hit on the/)
  await expect(page.getByText('What to do')).toHaveCount(0)
  const c = await as('admin')
  const hits = (await get<{ items: Hit[] }>(c, '/honeypot/hits')).items
  expect(hits.filter((h) => h.is_test).length).toBeGreaterThanOrEqual(2)
  await c.dispose()
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

test('a real log line becomes a hit with the device name, on the timeline, and an incident through notify (S-HP-1, S-HP-2, POST-1/2)', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  const admin = await as('admin')
  const f = tokens.file!, k = tokens.cred!
  const before = (await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.map((h) => h.id)
  // SSH connection and login with the bait account, an HTTP request, and the bait file opened on the SMB share (5000 has no dst_host)
  appendLog(
    rec({ logtype: 4000, src: src.ip, srcPort: 40001, dst: DECOY_IP, dstPort: 22 }),
    rec({ logtype: 4002, src: src.ip, srcPort: 40001, dst: DECOY_IP, dstPort: 22, data: { USERNAME: k.value, PASSWORD: 'hunter2-never-shown' } }),
    rec({ logtype: 3000, src: src.ip, srcPort: 40002, dst: DECOY_IP, dstPort: 80, data: { PATH: '/admin/login.php', USERAGENT: 'curl/8.5.0' } }),
    rec({ logtype: 5000, src: src.ip, srcPort: 40003, data: { FILENAME: `\\\\${DECOY_NAME}\\HR\\${f.value}` } }),
  )
  // one 15 s poll plus slack
  let fresh: Hit[] = []
  await expect.poll(async () => {
    fresh = (await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.filter((h) => !before.includes(h.id) && !h.is_test && h.src_ip === src.ip)
    return fresh.length
  }, { message: 'the hits appear within one poll', timeout: 35_000, intervals: [1_000] }).toBeGreaterThanOrEqual(4)
  const by = (pred: (h: Hit) => boolean) => fresh.find(pred)
  const ssh = by((h) => h.kind === 'service' && h.service === 'ssh')!
  const http = by((h) => h.kind === 'service' && h.service === 'http')!
  const smb = by((h) => h.kind === 'service' && h.service === 'smb')!
  const tokenHits = fresh.filter((h) => h.kind === 'token')
  expect(ssh, 'SSH hit').toBeDefined(); expect(http, 'HTTP hit').toBeDefined(); expect(smb, 'SMB hit').toBeDefined()
  expect(ssh).toMatchObject({ port: 22, src_name: src.name, src_asset_id: src.id, is_test: false })
  expect(http).toMatchObject({ port: 80, src_name: src.name })
  expect(http.excerpt).toContain('GET /admin/login.php')
  expect(smb.port, 'the SMB line has no destination: the service port stands in').toBe(445)
  expect(tokenHits.some((h) => h.label.includes(k.name)), 'a token hit names the bait account').toBe(true)
  expect(tokenHits.some((h) => h.label.includes(f.name)), 'a token hit names the bait file').toBe(true)
  expect(tokenHits.length, 'one hit for the bait account, one for the bait file (a window edge could split one)').toBeGreaterThanOrEqual(2)
  expect(JSON.stringify(fresh), 'a typed password is never stored').not.toContain('hunter2-never-shown')

  // the token counters
  const toks = (await get<{ items: Tok[] }>(admin, '/honeypot/tokens')).items
  expect(toks.find((t) => t.id === k.id)!.triggers).toBeGreaterThanOrEqual(1)
  expect(toks.find((t) => t.id === f.id)!.triggers).toBeGreaterThanOrEqual(1)

  // the page: the heading counts it, the table names the device, the detail shows the timeline
  await page.goto('/honeypot')
  await expect(h1(page)).toHaveText(/trap hits? today|Traps were hit/)
  const row = page.getByRole('table', { name: 'Trap hits' }).getByRole('row').filter({ has: page.locator(`a[href="/honeypot/hits/${ssh.id}"]`) })
  await expect(row).toContainText(src.ip)
  await expect(row.getByRole('link', { name: src.name, exact: true })).toBeVisible()
  await expect(row).toContainText('SSH')
  await expect(page.getByRole('table', { name: 'Trap hits' }).getByText('Token').first()).toBeVisible()
  await shot(page, 'real', 'honeypot-hits')
  await page.goto(`/honeypot/hits/${ssh.id}`)
  await expect(h1(page)).toHaveText(new RegExp(`SSH was hit at .* from ${src.name}`))
  await expect(page.getByRole('table', { name: 'Events around the trap hit' })).toContainText(`SSH trap: ${src.ip} connected to ${DECOY_IP}:22`)
  await expect(page.getByText('What to do')).toBeVisible()
  const detail = await get<HitDetail>(admin, `/honeypot/hits/${ssh.id}`)
  expect(detail).toMatchObject({ trap_ip: DECOY_IP, trap_hostname: DECOY_NAME })
  expect(detail.events.some((e) => e.mark && e.source === 'honeypot' && e.text.includes(`SSH trap: ${src.ip} connected to ${DECOY_IP}:22`))).toBe(true)
  await expectAccessible(page, 'hit detail')
  await page.goto(`/devices/${src.id}`)
  await expect(page.getByRole('heading', { name: 'Internal trap hits' })).toBeVisible()
  await expect(page.getByRole('link', { name: /SSH at / })).toBeVisible()

  // the incident: one per real hit, never one for a test hit (INV-4)
  let incidents: Incident[] = []
  await expect.poll(async () => {
    incidents = (await get<{ incidents: Incident[] }>(admin, '/notify/incidents')).incidents
    return incidents.filter((i) => i.link === `/honeypot/hits/${ssh.id}`).length
  }, { message: 'a trap incident for the SSH hit', timeout: 20_000 }).toBe(1)
  const inc = incidents.find((i) => i.link === `/honeypot/hits/${ssh.id}`)!
  expect(inc).toMatchObject({ kind: 'trap', severity: 'critical', title: `${src.ip} touched the SSH trap` })
  const testIds = (await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.filter((h) => h.is_test).map((h) => h.id)
  expect(incidents.filter((i) => testIds.some((id) => i.link === `/honeypot/hits/${id}`)), 'a test hit opens no incident').toEqual([])
  await admin.dispose()
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

test('hostile lines: a forged source, control characters, an oversized line, garbage: nothing breaks, the text is shown cleaned (SYS-6, INV-12)', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  let dialogs = 0
  page.on('dialog', (d) => { dialogs++; void d.dismiss() })
  const admin = await as('admin')
  const known = new Set((await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.map((h) => h.id))
  const marker = uniq('evil')
  const bytes = (...b: number[]) => String.fromCharCode(...b)
  appendLog(
    // a source forged inside the payload: the strings only carry text, the source stays the one of the line
    JSON.stringify({ logtype: 3000, src_host: src2.ip, src_port: 40010, dst_host: DECOY_IP, dst_port: 80, utc_time: utc(), logdata: { PATH: `/${marker}","src_host":"192.168.1.99`, USERAGENT: '"},{"logtype":4000,"src_host":"10.9.9.9","dst_host":"192.168.1.200' } }),
    // control characters, an escape sequence, bidi and zero-width characters, markup
    JSON.stringify({ logtype: 3000, src_host: src2.ip, src_port: 40011, dst_host: DECOY_IP, dst_port: 80, utc_time: utc(), logdata: { PATH: `/${marker}-ctl${bytes(0)}${bytes(27)}[31mRED${bytes(0x202e)}${bytes(0x200b)}evil\t\r`, USERAGENT: '<script>window.__pwned=1</script><img src=x onerror=window.__pwned=1>' } }),
    // not a JSON line, NUL bytes, a source that is not an IPv4 address, a command in the source, IPv6, no logtype
    `this is not json ${marker}`,
    Buffer.concat([Buffer.from([0, 0, 0, 0]), Buffer.from('{{{'), Buffer.from([0xff, 0xfe, 0xc3])]), // NUL bytes and bytes that are not UTF-8
    JSON.stringify({ logtype: 4000, src_host: '192.168.1.71; touch /tmp/pwned', src_port: 1, dst_host: DECOY_IP, utc_time: utc(), logdata: {} }),
    JSON.stringify({ logtype: 4000, src_host: '$(id)', src_port: 1, dst_host: DECOY_IP, utc_time: utc(), logdata: {} }),
    JSON.stringify({ logtype: 4000, src_host: '::1', src_port: 1, dst_host: DECOY_IP, utc_time: utc(), logdata: {} }),
    JSON.stringify({ src_host: '192.168.1.72', src_port: 1, dst_host: DECOY_IP, utc_time: utc(), logdata: {} }),
    // over the 16 KiB a line may have (INV-12): dropped whole, from a source no device has
    JSON.stringify({ logtype: 3000, src_host: '192.168.1.73', src_port: 40012, dst_host: DECOY_IP, dst_port: 80, utc_time: utc(), logdata: { PATH: `/${marker}-big${'A'.repeat(20_000)}` } }),
    // the sentinel: a good line after all of them, from the second device. When its hit is there the reader has been through everything above
    rec({ logtype: 5000, src: src2.ip, srcPort: 40013, data: { FILENAME: '\\\\FILESRV-OLD\\HR\\not-a-bait.txt' } }),
  )
  // (the hostile HTTP lines come from the second device: a line of the first device would only join its HTTP hit of the same window)
  await expect.poll(async () => (await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.filter((h) => !known.has(h.id) && h.src_ip === src2.ip && h.service === 'smb').length, { message: 'the sentinel hit is read after the hostile lines', timeout: 35_000, intervals: [1_000] }).toBe(1)

  const fresh = (await get<{ items: Hit[] }>(admin, '/honeypot/hits')).items.filter((h) => !known.has(h.id) && !h.is_test)
  const srcs = fresh.map((h) => h.src_ip).sort()
  // (two hits normally: HTTP and SMB; a 10-minute window edge between two lines could make one more, from the same source)
  expect(srcs.length).toBeGreaterThanOrEqual(2)
  expect(srcs.every((s) => s === src2.ip), 'the forged and the malformed sources made no hit').toBe(true)
  for (const bad of ['192.168.1.99', '10.9.9.9', '192.168.1.71', '192.168.1.72', '192.168.1.73']) expect(srcs).not.toContain(bad)
  const hostile = fresh.find((h) => h.service === 'http')!
  expect(hostile, 'the two HTTP lines made one HTTP hit').toBeDefined()
  // one hit per source, service and window: the second line adds to the first (hitWindow); read the whole excerpt through the detail
  const detail = await get<HitDetail>(admin, `/honeypot/hits/${hostile.id}`)
  const shown = `${hostile.excerpt}\n${detail.events.map((e) => e.text).join('\n')}`
  // eslint-disable-next-line no-control-regex
  expect(shown, 'no control character, no bidi mark, no zero-width character is kept').not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f​‪-‮⁦-⁩]/)
  expect(JSON.stringify(detail)).not.toContain('\\u001b')
  expect(shown.length, 'the cuts keep the text short').toBeLessThan(4_000)
  // positive: the text IS there, cleaned (INV-12): control characters became spaces, bidi and zero-width characters were dropped, markup stays text
  expect(shown, 'the control-character line was read, not dropped or cut off').toContain(`${marker}-ctl`)
  expect(shown).toContain('REDevil')
  expect(shown, 'markup is kept as text').toContain('<script>window.__pwned=1</script>')
  expect(shown, 'the forged source stays text inside the path').toContain('"src_host":"192.168.1.99')

  await page.goto(`/honeypot/hits/${hostile.id}`)
  await expect(h1(page)).toBeVisible()
  const text = await page.locator('main').innerText()
  // eslint-disable-next-line no-control-regex
  expect(text).not.toMatch(/[\u0000-\u0008\u000b-\u001f\u007f​‪-‮⁦-⁩]/)
  expect(text, 'the page shows the markup as text').toContain('<script>window.__pwned')
  expect(text).toContain(`${marker}-ctl`)
  await noVietnamese(page, 'hostile hit')
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned), 'markup from the network did not run').toBeUndefined()
  expect(dialogs).toBe(0)
  await page.goto('/honeypot')
  await expect(h1(page)).toBeVisible()
  expect(await page.evaluate(() => (window as unknown as { __pwned?: number }).__pwned)).toBeUndefined()
  await shot(page, 'real', 'honeypot-hostile')
  // nothing was executed on the box, the module still answers, and the box log has no panic
  expect(existsSync('/tmp/pwned'), 'a source with a command in it ran nothing').toBe(false)
  expect((await api(admin, 'GET', '/honeypot')).status).toBe(200)
  const log = join(dirname(process.env.E2E_BOX ?? ''), 'box.log')
  if (existsSync(log)) expect(readFileSync(log, 'utf8'), 'the box log has no panic').not.toMatch(/panic|goroutine \d+ \[/)
  await admin.dispose()
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})

test('switching traps off: the host is told, the container stops with the last trap, and the data is kept (S-HP-1, POST-5)', async ({ page }) => {
  test.setTimeout(150_000)
  const errors = collectErrors(page)
  const server = watch5xx(page)
  const conf = () => JSON.parse(readFileSync(join(confDir(), 'opencanary.conf'), 'utf8')) as Record<string, unknown>
  await page.goto('/honeypot')
  // one trap off: its service closes in the written file, the container is restarted to read it, and the decoy stays
  const restartsBefore = (await hostHoneypot()).restarts
  await sw(page, SVC.smb).click()
  await expect(sw(page, SVC.smb)).not.toBeChecked()
  await toast(page, /SMB \(file sharing\) trap is off/)
  await expect.poll(() => conf()['smb.enabled'], { message: 'opencanary.conf closes SMB', timeout: 30_000 }).toBe(false)
  await expect.poll(async () => (await hostHoneypot()).restarts, { message: 'switching SMB off restarted the container', timeout: 30_000 }).toBeGreaterThan(restartsBefore)
  expect(conf()['ssh.enabled']).toBe(true)
  const mid = await hostHoneypot()
  expect(mid.unit_state).toBe('active')
  expect(mid.decoys.map((d) => d.ip)).toEqual([DECOY_IP])
  // the last two: the host is told to stop the container and to drop the decoy address
  for (const svc of [SVC.ssh, SVC.http]) { await sw(page, svc).click(); await expect(sw(page, svc)).not.toBeChecked() }
  await expect.poll(async () => { const h = await hostHoneypot(); return `${h.unit_state} ${h.decoys.length}` }, { message: 'the host stopped the container and dropped the decoy', timeout: 45_000 }).toBe('inactive 0')
  await expect.poll(() => conf()['ssh.enabled'] === false && conf()['http.enabled'] === false, { message: 'every service is closed in the written file', timeout: 30_000 }).toBe(true)
  await page.reload()
  await expect(h1(page)).toHaveText(/No traps are on/)
  await expect(page.getByText('Listening')).toHaveCount(0)
  // data is kept: the address and the name, the hits, the tokens (and the token file list), the hit detail
  await expect(page.getByLabel('Trap secondary IP')).toHaveValue(DECOY_IP)
  await expect(page.getByLabel('Fake hostname')).toHaveValue(DECOY_NAME)
  await expect(page.getByRole('table', { name: 'Trap hits' }).getByRole('row').filter({ hasText: src.ip }).first()).toBeVisible()
  await expect(page.getByRole('list', { name: 'Honey tokens' }).getByRole('listitem')).toHaveCount(2)
  expect(JSON.parse(readFileSync(join(confDir(), 'honeytokens.json'), 'utf8'))).toEqual({ files: [tokens.file!.value] })
  await shot(page, 'real', 'honeypot-off')
  await noVietnamese(page, 'honeypot off')
  noErrors(errors)
  expect(server, 'the API answered 5xx').toEqual([])
})
