// Getting a real finding onto the box through public APIs only (WP-30, D-170), for findings.global.spec.ts.
// A finding is made from the CISA list only (feeds `Store` answers from `cisa-kev` rows: "a custom feed's CVE is not a KEV entry"; inventory and
// findings read nothing else), so a custom vulnerability feed cannot make one. The public path that works with no internet: the built-in CISA
// KEV feed lets an administrator set a mirror address (PUT /feeds/sources/cisa-kev {url}); a node `http` server on 127.0.0.1 (INV-2 of feeds
// lets internal hosts use http) serves a KEV-format catalog with one entry per test for a made-up vendor and product, "Fetch now" pulls it,
// and a device declared in the inventory with that vendor and product is matched at once (inventory INV-10, `inventory.match.changed`); the
// findings module creates the finding (`suspected`, basis `product`: the list has no affected version ranges).
// This is box-wide state (the built-in feed's address and rows), so the specs that use it are `.global.spec.ts`, and the address is reset to
// the default at the end. The CVE-2099-* rows stay until the next successful CISA pull replaces them (or the run ends: the box is thrown away).
// Vendor, product, device, address and CVE are unique per seed (CVE-2099-*, a year no real list has reached), so tests never share a finding.
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { expect, request, type APIRequestContext } from '@playwright/test'
import { api, authFile, box, uniq, type Role } from './box'

export const as = (role: Role) => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })

export interface Row {
  id: string; asset_id: string; cve: string; status: 'confirmed' | 'suspected' | 'mitigated' | 'patched' | 'false_positive' | 'not_relevant'
  severity: string; confidence: number; basis: 'scan' | 'version' | 'product'; first_seen: string; last_seen: string
  resolved_by: string | null; resolved_at: string | null; resolution_note: string | null
  evidence: unknown; history: { ts: string; user: string; action: string; note?: string }[]
  asset: { id: string; hostname: string | null; ip: string; kind: string; display: string } | null
  kev: { name: string; vendor: string; product: string; display: string; required_action: string; links: string[]; date_added: string; due_date: string | null; ransomware: boolean; epss: number | null; has_template: boolean } | null
}
export interface Detail extends Row {
  pack: unknown; compromise: unknown; recheck: { steps: string[] }; applied: unknown[]
  ai: { explain: unknown; config: unknown }; ai_available: { explain: boolean; config: boolean }
}
export interface Seed { deviceId: string; host: string; ip: string; cve: string; vendor: string; product: string; findingId: string }

let srv: Server | undefined
let base = ''
let catalog = ''
const entries: Record<string, unknown>[] = []
const render = () => { catalog = JSON.stringify({ title: 'QA catalog', catalogVersion: '2099.11.11', dateReleased: '2026-11-11T00:00:00.000Z', count: entries.length, vulnerabilities: entries }) }

/** Starts the loopback server and points the CISA feed's mirror address at it (call in beforeAll). */
export async function startFeedServer() {
  render()
  srv = createServer((req, res) => { const ok = req.url === '/kev.json'; res.writeHead(ok ? 200 : 404, { 'Content-Type': 'application/json' }); res.end(ok ? catalog : '{}') })
  await new Promise<void>((ok) => srv!.listen(0, '127.0.0.1', ok))
  base = `http://e2e-loopback.lan:${(srv.address() as AddressInfo).port}` // the box sends this name to 127.0.0.1 (e2eOffline): a loopback address is refused at save (D-420)
  const admin = await as('admin')
  try {
    const r = await api(admin, 'PUT', '/feeds/sources/cisa-kev', { url: `${base}/kev.json` })
    expect(r.status, `mirror address of the CISA feed: ${JSON.stringify(r.body)}`).toBe(200)
  } finally { await admin.dispose() }
}
/** Gives the CISA feed its default address back and stops the server (call in afterAll); the server is closed whatever the reset did. */
export async function stopFeedServer() {
  const s = srv; srv = undefined
  const admin = await as('admin')
  try {
    expect((await api(admin, 'PUT', '/feeds/sources/cisa-kev', { url: '' })).status, 'reset of the CISA feed address').toBe(200)
    const after = (await api<{ items: { id: string; url: string }[] }>(admin, 'GET', '/feeds/sources')).body.items.find((i) => i.id === 'cisa-kev')
    expect(after, 'the CISA feed is listed').toBeDefined()
    expect(after!.url, 'the CISA feed no longer points at the loopback server').not.toBe(`${base}/kev.json`)
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
    const vendor = `Vend-${tag}`, product = `Widget-${tag}`, host = `host-${tag}`
    const cve = over.cve ?? `CVE-2099-${String(100000 + (Date.now() % 800000) + n)}`
    const ip = over.ip ?? `10.231.${Math.floor(n / 250) % 250}.${(n % 250) + 1}` // a counter: this file's addresses never repeat in a run
    entries.push({ cveID: cve, vendorProject: vendor, product, vulnerabilityName: `QA ${tag} remote code execution`, dateAdded: '2026-11-01', shortDescription: `QA entry ${tag}`, requiredAction: `Apply the QA update for ${tag}.`, dueDate: '2099-12-01', knownRansomwareCampaignUse: 'Unknown', notes: 'https://advisory.example/qa' })
    render()
    const pulled = await api(admin, 'POST', '/feeds/sources/cisa-kev/fetch')
    expect(pulled.status, `fetch: ${JSON.stringify(pulled.body)}`).toBe(200)
    const src = (await api<{ items: { id: string; status: string; error: string | null }[] }>(admin, 'GET', '/feeds/sources')).body.items.find((i) => i.id === 'cisa-kev')
    expect(src, 'the CISA feed pulled from the loopback mirror').toMatchObject({ status: 'ok', error: null })
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
