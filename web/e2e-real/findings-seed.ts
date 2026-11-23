// Getting a real finding onto the box through public APIs only, for the specs that need one (mitigation packs, scans, alerts).
// A finding needs version evidence (findings INV-4f: a product name alone is only a question), and it starts from the CISA list: a custom
// vulnerability feed cannot make one. Two built-in feeds each take a mirror address (PUT /feeds/sources/{id} {url}), and a node `http`
// server on 127.0.0.1 (INV-2 of feeds lets internal hosts use http) serves both with no internet: a KEV-format catalog (`cisa-kev`) with one
// entry per test for a made-up vendor and product, and an NVD CVE API 2.0 page (`nvd-kev`) that gives each of those CVEs an affected range
// `< 2.0` for the same product. "Fetch now" pulls both, and a device declared in the inventory with that vendor, product and version 1.0 is
// matched at once (inventory `inventory.match.changed`); the findings module creates the finding (`suspected`, basis `version`: the version
// is a person's typed one, so nothing confirms it until a scan or the device does).
// This is box-wide state (the two feeds' addresses and rows), so the specs that use it are `.global.spec.ts`, and both addresses are reset to
// the default at the end. The CVE-2099-* rows stay until the next successful pull replaces them (or the run ends: the box is thrown away).
// Vendor, product, device, address and CVE are unique per seed (CVE-2099-*, a year no real list has reached), so tests never share a finding.
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, request, test, type APIRequestContext } from '@playwright/test'
import { api, authFile, box, uniq, type Role } from './box'
import type { FindingDetail, FindingRow } from '../src/features/findings/types'

export const as = (role: Role) => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })

// The shapes are the API contract's own (zod-derived), so a change to the findings answer fails tsc here instead of passing silently.
export type Row = FindingRow
export type Detail = FindingDetail
export interface Seed { deviceId: string; host: string; ip: string; cve: string; vendor: string; product: string; findingId: string }

let srv: Server | undefined
let base = ''
let catalog = ''
let nvd = ''
const entries: Record<string, unknown>[] = []
const nvdRecords: Record<string, unknown>[] = []
const PLACEHOLDER = 'CVE-2099-000001' // lets the NVD feed's first pull from the mirror succeed before any test has an entry
const render = () => {
  catalog = JSON.stringify({ title: 'QA catalog', catalogVersion: '2099.11.11', dateReleased: '2026-11-11T00:00:00.000Z', count: entries.length, vulnerabilities: entries })
  nvd = JSON.stringify({ resultsPerPage: nvdRecords.length, startIndex: 0, totalResults: nvdRecords.length, format: 'NVD_CVE', version: '2.0', timestamp: '2026-11-11T00:00:00.000', vulnerabilities: nvdRecords })
}
/** The NVD record of one test CVE: affected `cpe:2.3:a:<vendor>:<product>` below 2.0, published recently (a missing or old date would change the match). */
const nvdRecord = (cve: string, vendor: string, product: string, tag: string) => ({ cve: {
  id: cve, sourceIdentifier: 'qa@example.test', published: '2026-10-20T10:00:00.000', lastModified: '2026-11-01T10:00:00.000', vulnStatus: 'Analyzed',
  descriptions: [{ lang: 'en', value: `QA ${tag} remote code execution in ${product} before 2.0.` }],
  configurations: [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: [{ vulnerable: true, criteria: `cpe:2.3:a:${vendor}:${product}:*:*:*:*:*:*:*:*`, versionEndExcluding: '2.0' }] }] }],
} })
const source = async (admin: APIRequestContext, id: string) => (await api<{ items: { id: string; status: string; error: string | null; url: string }[] }>(admin, 'GET', '/feeds/sources')).body.items.find((i) => i.id === id)

/** "Fetch now" until the feed's own pull from the mirror finished. A pull already running (the box's schedule at its start, asking the real address
 *  with no internet, keeps one feed busy for a few minutes) answers "fetch now" with how far it got, and its result is dropped when the address
 *  changed under it, so the request is repeated until the pull from the mirror is the one that ended. */
async function pullFromMirror(admin: APIRequestContext, id: string, timeout: number) {
  await expect.poll(async () => {
    const pulled = await api(admin, 'POST', `/feeds/sources/${id}/fetch`)
    expect(pulled.status, `fetch ${id}: ${JSON.stringify(pulled.body)}`).toBe(200)
    const row = await source(admin, id)
    expect(row?.status, `the ${id} feed pulled from the loopback mirror: ${row?.error}`).not.toBe('error') // on success `error` may hold a note about the pull
    return row?.status === 'ok' && row.url.startsWith(base)
  }, { message: `the ${id} feed pulled from the loopback mirror`, timeout, intervals: [2_000, 5_000] }).toBe(true)
}

/** Starts the loopback server and points the CISA and NVD feeds' mirror addresses at it (call in beforeAll). */
export async function startFeedServer() {
  render()
  srv = createServer((req, res) => {
    const path = (req.url ?? '').split('?')[0] // the NVD puller adds its own query string to the address
    const body = path === '/kev.json' ? catalog : path === '/nvd.json' ? nvd : undefined
    res.writeHead(body === undefined ? 404 : 200, { 'Content-Type': 'application/json' }); res.end(body ?? '{}')
  })
  await new Promise<void>((ok) => srv!.listen(0, '127.0.0.1', ok))
  base = `http://e2e-loopback.lan:${(srv.address() as AddressInfo).port}` // the box sends this name to 127.0.0.1 (e2eOffline): a loopback address is refused at save
  const admin = await as('admin')
  try {
    const r = await api(admin, 'PUT', '/feeds/sources/cisa-kev', { url: `${base}/kev.json` })
    expect(r.status, `mirror address of the CISA feed: ${JSON.stringify(r.body)}`).toBe(200)
    const n = await api(admin, 'PUT', '/feeds/sources/nvd-kev', { url: `${base}/nvd.json` })
    expect(n.status, `mirror address of the NVD affected versions feed: ${JSON.stringify(n.body)}`).toBe(200)
    test.setTimeout(330_000)
    if (!nvdRecords.length) { entries.push({ cveID: PLACEHOLDER, vendorProject: 'VendQaBase', product: 'WidgetQaBase', vulnerabilityName: 'QA base entry', dateAdded: '2026-11-01', shortDescription: 'QA base entry', requiredAction: 'None.', dueDate: '2099-12-01', knownRansomwareCampaignUse: 'Unknown', notes: '' }); nvdRecords.push(nvdRecord(PLACEHOLDER, 'vendqabase', 'widgetqabase', 'base')); render() }
    await pullFromMirror(admin, 'cisa-kev', 60_000)
    await pullFromMirror(admin, 'nvd-kev', 300_000) // waits out a pull of the real address that the box started by itself
  } finally { await admin.dispose() }
}
/** Gives both feeds their default address back and stops the server (call in afterAll); the server is closed whatever the reset did. */
export async function stopFeedServer() {
  const s = srv; srv = undefined
  const admin = await as('admin')
  try {
    for (const [id, file] of [['cisa-kev', 'kev.json'], ['nvd-kev', 'nvd.json']] as const) {
      expect((await api(admin, 'PUT', `/feeds/sources/${id}`, { url: '' })).status, `reset of the ${id} feed address`).toBe(200)
      const after = await source(admin, id)
      expect(after, `the ${id} feed is listed`).toBeDefined()
      expect(after!.url, `the ${id} feed no longer points at the loopback server`).not.toBe(`${base}/${file}`)
    }
  } finally {
    await admin.dispose()
    if (s) await new Promise((ok) => s.close(ok))
  }
}

/** What a test made and has not removed: swept by id after it, whatever the test did. */
const made = { devices: [] as string[] }
/** Removes the devices of the seeds of the test (their findings go with them), through the API, and checks the status of every delete (404 only
 *  for a device the test itself deleted). The list is cleared once the deletes are checked. Use as `test.afterEach(sweep)`. */
export async function sweep() {
  if (!made.devices.length) return
  const admin = await as('admin')
  try {
    for (const id of [...made.devices]) {
      const st = (await api(admin, 'DELETE', `/inventory/devices/${id}`)).status
      expect([200, 204, 404], `cleanup of device ${id}`).toContain(st)
    }
    made.devices.length = 0
  } finally { await admin.dispose() }
}

let seq = 0
/** A finding on a device of its own: entry served, CISA feed pulled, device declared, finding waited for (the bus is asynchronous).
 *  `cve` and `ip` are for the scan spec (a CVE of the template pack, an address in the scan scope); by default both are made up. */
export async function seed(over: { cve?: string; ip?: string } = {}): Promise<Seed> {
  const admin = await as('admin')
  try {
    const tag = uniq('qa')
    const n = seq++
    const flat = tag.toLowerCase().replace(/[^a-z0-9]/g, '') // a CPE name is lowercase letters and digits here: the device and the NVD record use the same one
    const vendor = `vend${flat}`, product = `widget${flat}`, host = `host-${tag}`
    const cve = over.cve ?? `CVE-2099-${String(100000 + (Date.now() % 800000) + n)}`
    const ip = over.ip ?? `10.231.${Math.floor(n / 250) % 250}.${(n % 250) + 1}` // a counter: this file's addresses never repeat in a run
    entries.push({ cveID: cve, vendorProject: vendor, product, vulnerabilityName: `QA ${tag} remote code execution`, dateAdded: '2026-11-01', shortDescription: `QA entry ${tag}`, requiredAction: `Apply the QA update for ${tag}.`, dueDate: '2099-12-01', knownRansomwareCampaignUse: 'Unknown', notes: 'https://advisory.example/qa' })
    nvdRecords.push(nvdRecord(cve, vendor, product, tag))
    render()
    for (const id of ['cisa-kev', 'nvd-kev']) await pullFromMirror(admin, id, 60_000) // the list first: the NVD pull keeps only the CVEs that are on it
    const dev = await api<{ id: string }>(admin, 'POST', '/inventory/devices', { vendor, product, version: '1.0', name: host, ip })
    expect(dev.status, `device: ${JSON.stringify(dev.body)}`).toBe(201)
    made.devices.push(dev.body.id)
    let row: Row | undefined
    await expect.poll(async () => { row = (await api<{ items: Row[] }>(admin, 'GET', `/findings?asset=${dev.body.id}`)).body.items[0]; return row?.cve }, { message: 'the finding appears', timeout: 45_000 }).toBe(cve)
    return { deviceId: dev.body.id, host, ip, cve, vendor, product, findingId: row!.id }
  } finally { await admin.dispose() }
}

/** Gives a made-up CVE (CVE-2099-*) a confirmed mitigation pack, through the control route of the box (cmd/vedette/e2epack_test.go): the box cannot
 *  load a signed pack (the release key is offline), so the pack of content/mitigation/testdata is written into its database as a developer seed. */
export async function seedPack(cve: string) {
  const b = box()
  const r = await fetch(`${b.control}/packs/seed`, { method: 'POST', headers: { Authorization: `Bearer ${b.control_token}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ cve }) })
  expect(r.status, `pack seed for ${cve}: ${await r.text()}`).toBe(204)
}

export const finding = async (c: APIRequestContext, id: string) => api<Detail>(c, 'GET', `/findings/${id}`)
