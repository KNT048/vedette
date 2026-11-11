// The logs module on the real backend (S-LOG-1, logs INV-1, INV-3, INV-4, INV-5, INV-12, POST-1, FORBID-5, SYS-5). Global project: the syslog listener,
// the list of sources (one source per sender IP, and the only IP a spec can send from is 127.0.0.1) and the retention are box-wide, so this runs alone and
// every test puts them back. The lines come over the real listener: the box declares a source with sender 127.0.0.1 and the spec sends UDP and TCP to the
// port in ready.json (`syslog_port`, a free port of the run, not 514). What is not built is test.fixme with the real flow in its body (D-171 (2)): SIEM
// forwarding (L5, GET /logs/siem answers 501), the digest's new log types and spikes (a 24 h warm-up a box cannot skip), the TLS listener (D-203).
// Bad connections (L4, INV-7) are real: a custom feed pulled from a loopback server lists a made-up domain, and one FortiGate DNS line from a LAN address is matched.
// Steps from e2e/qa/logs.spec.ts (the mock QA).
import { readFileSync } from 'node:fs'
import { createSocket } from 'node:dgram'
import { createServer } from 'node:http'
import { connect, type AddressInfo } from 'node:net'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Source { id: string; kind: string; name: string; sender_ip: string; proto: string; port: number; state: string; last_received: string | null; lines_per_hour: number }
interface Sources { box: { ip: string | null; lan: string | null }; sources: Source[]; retention_days: number }
interface Ev { id: string; ts: string; source_id: string; source_name: string; line: string }
interface Err { error: { code: string; message: string } }
const SRC = { kind: 'syslog-generic', sender_ip: '127.0.0.1', proto: 'udp', port: 514 }
// C0 and C1 controls, zero-width and bidi marks, line and paragraph separators, the byte order mark
const NOISE = new RegExp('[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069\\ufeff]')
/** The row of a source in the Log sources table (the events table also has the source name in every row). */
const srcRow = (page: Page, name: string) => page.getByRole('table', { name: 'Log sources currently received' }).getByRole('row').filter({ hasText: name })
const port = () => Number(box().syslog_port)

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const sources = async (c: APIRequestContext) => (await api<Sources>(c, 'GET', '/logs/sources')).body
const events = async (c: APIRequestContext, q: Record<string, string>) => (await api<{ events: Ev[]; total: number }>(c, 'GET', `/logs/events?${new URLSearchParams({ window: '24h', ...q })}`)).body
const audit = async (c: APIRequestContext, q: string) => (await api<{ items: { action: string; target: string; detail?: string }[] }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)).body.items

/** How many audit rows match (the `total` of the answer, not the length of its page: a page is capped). */
const auditTotal = async (c: APIRequestContext, q: string) => (await api<{ total: number }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)).body.total

/** One UDP datagram to the listener. */
function sendUdp(text: string | Buffer): Promise<void> {
  return new Promise((ok, bad) => {
    const s = createSocket('udp4')
    s.send(typeof text === 'string' ? Buffer.from(text) : text, port(), '127.0.0.1', (e) => { s.close(); e ? bad(e) : ok() })
  })
}
/** One TCP connection: writes the bytes and closes. */
function sendTcp(bytes: string): Promise<void> {
  return new Promise((ok, bad) => {
    const c = connect(port(), '127.0.0.1')
    c.on('error', bad)
    c.on('close', () => ok())
    c.on('connect', () => { c.write(bytes, () => setTimeout(() => c.end(), 300)) })
  })
}
/** Is a TCP socket open on the syslog port? (a connection is accepted, or refused) */
function tcpState(): Promise<'open' | 'closed'> {
  return new Promise((ok) => {
    const c = connect(port(), '127.0.0.1')
    c.on('error', () => ok('closed'))
    c.on('connect', () => { c.destroy(); ok('open') })
  })
}
/** Is a UDP socket open on the syslog port? A connected UDP socket gets ICMP port-unreachable (ECONNREFUSED) for a closed port, on Linux and macOS. The probe is an
 *  empty datagram, which the listener drops (listen/server.go: an empty message is not a line), so it never counts as a stored line. */
function udpState(): Promise<'open' | 'closed'> {
  return new Promise((ok) => {
    const s = createSocket('udp4')
    let done = false
    const finish = (v: 'open' | 'closed') => { if (!done) { done = true; s.close(); ok(v) } }
    s.on('error', () => finish('closed'))
    s.connect(port(), '127.0.0.1', () => { s.send(Buffer.alloc(0), (e) => { if (e) finish('closed') }); setTimeout(() => finish('open'), 250) })
  })
}
const sockets = (c: 'udp' | 'tcp', want: 'open' | 'closed') =>
  expect.poll(() => (c === 'udp' ? udpState() : tcpState()), { message: `the ${c} socket of the syslog listener is ${want}`, timeout: 40_000 }).toBe(want)


/** The only answer of the real box that is 501 on this page while a source exists: the AI digest panel (module ai, S-AI-4; .ai/deferred of ai). KNOWN_501 only shrinks:
 *  test 4 fails when it answers 200, and any other 5xx fails the test that saw it. */
const AI_DIGEST_501 = 'GET /api/v1/ai/logs/digest'
function watch5xx(page: Page): string[] {
  const seen: string[] = []
  page.on('response', (r) => { const u = new URL(r.url()); if (u.pathname.startsWith('/api/') && r.status() >= 500) seen.push(`${r.request().method()} ${u.pathname} ${r.status()}`) })
  return seen
}
const only501 = (seen: string[]) => expect(seen.filter((k) => k !== `${AI_DIGEST_501} 501`), 'a 5xx other than the known 501').toEqual([])

let original = 30
/** Every source of this file goes, and the listener with it. */
async function clean(c: APIRequestContext) {
  for (const s of (await sources(c)).sources) expect((await api(c, 'DELETE', `/logs/sources/${s.id}`)).status, `delete ${s.name}`).toBe(204)
  expect((await sources(c)).sources).toEqual([])
}
test.beforeAll(async () => {
  const c = await as('admin')
  try {
    const s = await sources(c)
    expect(s.sources, 'no other spec leaves a log source on the box').toEqual([])
    original = s.retention_days
  } finally { await c.dispose() }
})
test.afterEach(async () => {
  const c = await as('admin')
  try { await clean(c) } finally { await c.dispose() }
})
test.afterAll(async () => {
  const c = await as('admin')
  try {
    const put = await api(c, 'PUT', '/logs/retention', { days: original })
    expect(put.status, 'retention put back').toBe(200)
    expect((await sources(c)).retention_days).toBe(original)
    const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(c, 'GET', '/modules')
    expect(mods.body.modules.find((m) => m.id === 'logs')?.enabled, 'the logs module is on again').toBe(true)
  } finally { await c.dispose() }
})

async function add(c: APIRequestContext, over: Partial<typeof SRC> & { name?: string } = {}): Promise<Source> {
  const r = await api<Source>(c, 'POST', '/logs/sources', { ...SRC, name: uniq('lg'), ...over })
  expect(r.status, JSON.stringify(r.body)).toBe(201)
  await sockets(r.body.proto === 'tcp' ? 'tcp' : 'udp', 'open') // the listener opens its socket after the source is saved: a datagram sent before is lost
  return r.body
}
/** The line is in the stored events (the listener batches for up to 2 seconds). */
const stored = (c: APIRequestContext, line: string, sourceId: string) =>
  expect.poll(async () => (await events(c, { source: sourceId })).events.map((e) => e.line), { message: `stored: ${line}`, timeout: 15_000 }).toContain(line)

test('an empty box says what to do first; the page and the API agree; no script error, no 5xx, English only', async ({ page }) => {
  const errors = collectErrors(page)
  const server: string[] = []
  // GET /ai/logs/digest is not built yet and answers 501 (.ai/deferred/feat-ai-activity.md:18): the one answer the page may get
  page.on('response', (r) => { if (r.url().includes('/api/') && r.status() >= 500 && !r.url().endsWith('/api/v1/ai/logs/digest')) server.push(`${r.request().method()} ${new URL(r.url()).pathname} ${r.status()}`) })
  const c = await as('admin')
  try {
    const s = await sources(c)
    expect(s.sources).toEqual([])
    expect(s.retention_days).toBe(original)
    await page.goto('/logs')
    await expect(h1(page)).toHaveText('No device is sending logs to the box yet.')
    await expect(page.getByText('No log sources yet')).toBeVisible()
    await expect(page.getByRole('button', { name: 'Add log source' }).first()).toBeEnabled()
    await expect(page.getByRole('table', { name: 'New log types' })).toHaveCount(0)
    await expect(page.getByLabel('Keep logs for')).toHaveValue(String(original))
    await expectAccessible(page, 'logs, empty')
    await noVietnamese(page, 'logs, empty')
    expect(server).toEqual([])
    noErrors(errors)
  } finally { await c.dispose() }
})

test('add a source in the page: the picker, the setup dialog, the row, a duplicate IP refused with the API message; the source is in the API and the audit', async ({ page }) => {
  const errors = collectErrors(page)
  const five = watch5xx(page)
  const c = await as('admin')
  const name = uniq('lg')
  try {
    await page.goto('/logs')
    await page.getByRole('button', { name: 'Add log source' }).first().click()
    const d = page.getByRole('dialog')
    await expect(d.getByRole('region')).toHaveCount(8)
    expect(await d.getByRole('region').getByRole('button').count(), 'every device type of the catalog is listed').toBe(48)
    await d.getByLabel('Find your device or software').fill('zzzz')
    await expect(d.getByText('Nothing matches "zzzz"')).toBeVisible()
    await d.getByLabel('Find your device or software').fill('standard syslog')
    await d.getByRole('button', { name: /standard syslog/ }).click()
    await expect(d.getByText('Device type: Other device (standard syslog, RFC 3164 / 5424)')).toBeVisible()
    await d.getByLabel('Name').fill(name)
    await d.getByLabel('IP of the sending device').fill('127.0.0.1')
    await d.getByRole('button', { name: 'Add and show setup' }).click()
    const guide = page.getByRole('dialog', { name: `Set up ${name} to send logs to the box` })
    await expect(guide).toBeVisible()
    await expect(guide).toContainText('It only accepts logs from 127.0.0.1.')
    await page.keyboard.press('Escape')
    await expect(guide).toHaveCount(0)
    await page.reload() // a fresh page: the toast of the add has a colour-contrast violation of its own (.ai/deferred/feat-e2e-real-exposure-fakes.md:5)
    await page.getByRole('button', { name: `Device setup for ${name}` }).click()
    await expect(page.getByRole('dialog', { name: `Set up ${name} to send logs to the box` })).toBeVisible()
    await expectAccessible(page, 'the setup dialog')
    await page.keyboard.press('Escape')

    const list = await sources(c)
    expect(list.sources).toHaveLength(1)
    expect(list.sources[0]).toMatchObject({ name, kind: 'syslog-generic', sender_ip: '127.0.0.1', proto: 'udp', state: 'never', last_received: null })
    await expect(srcRow(page, name)).toContainText('Nothing yet')
    expect(await audit(c, name)).toEqual([expect.objectContaining({ action: 'logs.source_add', target: name, detail: 'syslog-generic 127.0.0.1 udp/514' })])

    // a second source for the same IP: refused, nothing saved, the dialog shows the message of the API
    const auditDup = await auditTotal(c, 'logs.')
    const dup = await api<Err>(c, 'POST', '/logs/sources', { ...SRC, kind: 'mikrotik', name: uniq('lg') })
    expect([dup.status, dup.body.error.code]).toEqual([409, 'duplicate'])
    await page.getByRole('button', { name: 'Add log source' }).first().click()
    const d2 = page.getByRole('dialog')
    await d2.getByLabel('Find your device or software').fill('mikrotik')
    await d2.getByRole('button', { name: /MikroTik/ }).click()
    await d2.getByLabel('Name').fill(uniq('lg'))
    await d2.getByLabel('IP of the sending device').fill('127.0.0.1')
    await d2.getByRole('button', { name: 'Add and show setup' }).click()
    await expect(d2.getByRole('alert')).toHaveText(dup.body.error.message)
    await d2.getByRole('button', { name: 'Cancel' }).click()
    expect((await sources(c)).sources, 'the refusal saved nothing').toHaveLength(1)
    expect(await auditTotal(c, 'logs.'), 'the two refusals left no audit row').toBe(auditDup)
    only501(five)
    noErrors(errors, /status of (409|501)/)
  } finally { await c.dispose() }
})

test('every refusal of a source carries its code and saves nothing (INV-3)', async () => {
  const c = await as('admin')
  try {
    const before = JSON.stringify(await sources(c))
    const auditBefore = await auditTotal(c, 'logs.')
    const n = uniq('lg')
    const cases: [string, Record<string, unknown>, number, string][] = [
      ['unknown kind', { ...SRC, kind: 'nope', name: n }, 400, 'invalid'],
      ['name with a space', { ...SRC, name: 'two words' }, 400, 'invalid'],
      ['empty name', { ...SRC, name: '' }, 400, 'invalid'],
      ['IP out of range', { ...SRC, name: n, sender_ip: '999.1.1.1' }, 400, 'invalid'],
      ['IPv6', { ...SRC, name: n, sender_ip: '::1' }, 400, 'invalid'],
      ['IP with a leading zero', { ...SRC, name: n, sender_ip: '010.1.1.1' }, 400, 'invalid'], // bad_ip is only reachable below the schema (service tests)
      ['a protocol the kind cannot send', { ...SRC, name: n, kind: 'mikrotik', proto: 'tcp' }, 400, 'bad_proto'],
      ['TLS, not built (D-203)', { ...SRC, name: n, kind: 'fortigate', proto: 'tls', port: 6514 }, 400, 'tls_unavailable'],
      ['port 0', { ...SRC, name: n, port: 0 }, 400, 'invalid'],
      ['port 70000', { ...SRC, name: n, port: 70000 }, 400, 'invalid'],
    ]
    for (const [what, body, status, code] of cases) {
      const r = await api<Err>(c, 'POST', '/logs/sources', body)
      expect([r.status, r.body.error?.code], what).toEqual([status, code])
      expect(JSON.stringify(await sources(c)), `${what}: nothing was saved`).toBe(before)
    }
    expect(await auditTotal(c, 'logs.'), 'a refusal leaves no audit row').toBe(auditBefore)
    const kept = await add(c)
    const auditKept = await auditTotal(c, 'logs.')
    const edit = await api<Err>(c, 'PUT', `/logs/sources/${kept.id}`, { ...SRC, name: kept.name, kind: 'fortigate', proto: 'tls', port: 6514 })
    expect([edit.status, edit.body.error.code], 'an edit to TLS is refused too').toEqual([400, 'tls_unavailable'])
    expect((await sources(c)).sources[0]).toMatchObject({ proto: 'udp', kind: 'syslog-generic' })
    expect((await api<Err>(c, 'PUT', '/logs/sources/ls-does-not-exist', { ...SRC, name: n })).status).toBe(404)
    expect((await api<Err>(c, 'DELETE', '/logs/sources/ls-does-not-exist')).status).toBe(404)
    expect(await auditTotal(c, 'logs.'), 'the refused edit and the two 404s left no audit row').toBe(auditKept)
  } finally { await c.dispose() }
})

test('lines sent over UDP and TCP are stored exactly, the source turns to Receiving, the digest counts them and the page shows the same numbers (POST-1, INV-5)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const five = watch5xx(page)
  const c = await as('admin')
  try {
    const linesBefore = (await api<{ lines_24h: number }>(c, 'GET', '/logs/digest')).body.lines_24h // lines of a source deleted by an earlier test stay until retention
    const udp = await add(c)
    const tok = uniq('tok')
    const l1 = `<34>Nov 11 12:30:00 gw app[1]: ${tok} udp one`
    const l2 = `<13>Nov 11 12:30:01 gw app[1]: ${tok} udp two`
    await sendUdp(l1)
    await sendUdp(`${l2}\r\n`)
    await stored(c, l1, udp.id)
    await stored(c, l2, udp.id) // the trailing CR LF of a datagram is not part of the line
    // the same sender on TCP: switch the source to tcp (PUT keeps the id), then a newline-framed and an octet-counted message on one connection
    const tcp = await api<Source>(c, 'PUT', `/logs/sources/${udp.id}`, { ...SRC, name: udp.name, proto: 'tcp' })
    expect(tcp.status, JSON.stringify(tcp.body)).toBe(200)
    const l3 = `<34>Nov 11 12:30:02 gw app[1]: ${tok} tcp newline`
    const l4 = `<34>1 2026-11-11T12:30:03Z gw app 1 ID1 - ${tok} tcp counted`
    await sockets('tcp', 'open')
    await sendTcp(`${l3}\n${l4.length} ${l4}`)
    await stored(c, l3, udp.id)
    await stored(c, l4, udp.id)

    const all = await events(c, { q: tok })
    expect(all.total).toBe(4)
    expect(all.events.map((e) => e.line).sort()).toEqual([l1, l2, l3, l4].sort())
    for (const e of all.events) expect([e.source_id, e.source_name], 'every line is tied to its source').toEqual([udp.id, udp.name])
    expect((await events(c, { q: `${tok} tcp` })).total, 'the keyword narrows').toBe(2)
    expect((await events(c, { q: `${tok} nothing like this` })).total).toBe(0)
    expect((await events(c, { source: 'ls-does-not-exist' })).total).toBe(0)

    const src = (await sources(c)).sources[0]!
    expect(src.state).toBe('receiving')
    expect(src.last_received).not.toBeNull()
    const digest = await api<{ lines_24h: number }>(c, 'GET', '/logs/digest')
    expect(digest.body.lines_24h).toBe(linesBefore + 4)

    await page.goto('/logs')
    await expect(h1(page)).toContainText('Today:')
    await expect(srcRow(page, udp.name)).toContainText('Receiving')
    await expect(page.getByText(`From ${linesBefore + 4} log lines in the last 24 hours`)).toBeVisible()
    await page.getByLabel('Keyword').fill(tok)
    await expect(page.getByText('4 of 4 matching lines.')).toBeVisible()
    await page.getByLabel('Keyword').fill(`${tok} tcp counted`)
    await expect(page.getByText('1 of 1 matching lines.')).toBeVisible()
    await expect(page.getByRole('table', { name: 'Log events' }).getByText(l4)).toBeVisible()
    await page.getByLabel('Keyword').fill(`${tok} nothing like this`)
    await expect(page.getByText('No matching line. Try a longer time range or remove the keyword.')).toBeVisible()
    await page.getByLabel('Keyword').fill('')
    await page.getByLabel('Source', { exact: true }).selectOption({ label: udp.name })
    await page.getByRole('button', { name: '1 hour' }).click()
    await expect(page.getByText('4 of 4 matching lines.')).toBeVisible() // this source only: the lines of deleted sources are not in its filter
    await expectAccessible(page, 'logs with lines')
    await noVietnamese(page, 'logs with lines')
    expect(five, 'the AI digest panel is 501 until slice S-AI-4 is built: remove AI_DIGEST_501 when this fails').toContain(`${AI_DIGEST_501} 501`)
    only501(five)
    noErrors(errors, /status of 501/)
  } finally { await c.dispose() }
})

test('what the listener must not trust: another protocol, control characters and an oversize line (INV-1, FORBID-5)', async () => {
  test.setTimeout(90_000)
  const c = await as('admin')
  try {
    const src = await add(c) // udp only
    const tok = uniq('tok')
    // control characters and a bidirectional override come back as spaces; a long line is cut and says so
    await sendUdp(`<34>${tok} a\u0007b\u001b[31mred\u202Eevil\u0000end`)
    await sendUdp(`<34>${tok} long ${'x'.repeat(5000)}`)
    await expect.poll(async () => (await events(c, { q: tok })).total, { timeout: 15_000 }).toBe(2)
    const got = (await events(c, { q: tok })).events.map((e) => e.line)
    const clean = got.find((l) => l.includes('red'))!
    expect(clean, 'each control or format character became one space').toBe(`<34>${tok} a b [31mred evil end`)
    for (const l of got) expect(l, 'no control, format or bidi character is kept').not.toMatch(NOISE)
    const long = got.find((l) => l.includes(' long '))!
    expect(long.endsWith('...[cut]'), 'the long line says it was cut').toBe(true)
    expect(Buffer.byteLength(long)).toBeLessThanOrEqual(2048 + 8)

    // a source that is UDP only has no TCP socket: the connection is refused, nothing is stored
    await sockets('tcp', 'closed')
    await expect(sendTcp(`<34>${tok} wrong protocol\n`)).rejects.toThrow(/ECONNREFUSED/)
    // and the other way round: a TCP source has no UDP socket, so a datagram is lost
    const tcp = await api<Source>(c, 'PUT', `/logs/sources/${src.id}`, { ...SRC, name: src.name, proto: 'tcp' })
    expect(tcp.status, JSON.stringify(tcp.body)).toBe(200)
    await sockets('tcp', 'open')
    await sendTcp(`<34>${tok} right protocol\n`)
    await sockets('udp', 'closed')
    await sendUdp(`<34>${tok} wrong protocol`)
    await new Promise((ok) => setTimeout(ok, 3_000)) // longer than the batch time of the listener
    const all = (await events(c, { q: tok })).events.map((e) => e.line)
    expect(all.filter((l) => l.includes('wrong protocol')), 'a line on the protocol the source was not declared for is never stored').toEqual([])
    expect(all.filter((l) => l.includes('right protocol'))).toEqual([`<34>${tok} right protocol`])
  } finally { await c.dispose() }
})

test('edit and delete a source in the page: Escape deletes nothing, the lines already received stay (INV-4), a deleted source stops being served', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const five = watch5xx(page)
  const c = await as('admin')
  const name = uniq('lg')
  const renamed = uniq('lg')
  try {
    const src = await add(c, { name })
    const tok = uniq('tok')
    const line = `<34>Nov 11 12:31:00 gw app[1]: ${tok} before delete`
    await sendUdp(line)
    await stored(c, line, src.id)
    await page.goto('/logs')
    await page.getByRole('button', { name: `Edit ${name}` }).click()
    const dlg = page.getByRole('dialog')
    await expect(dlg.getByText('Device type: Other device (standard syslog, RFC 3164 / 5424)')).toBeVisible()
    await dlg.getByLabel('Name').fill(renamed)
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Log source saved.').first()).toBeVisible()
    await expect(srcRow(page, renamed)).toBeVisible()
    expect((await sources(c)).sources[0]).toMatchObject({ id: src.id, name: renamed })
    expect(await audit(c, renamed), 'the rename is in the audit').toEqual([expect.objectContaining({ action: 'logs.source_edit', target: renamed })])

    await page.getByRole('button', { name: `Delete ${renamed}` }).click()
    await expect(page.getByRole('dialog')).toContainText(`Delete log source ${renamed}?`)
    await expect(page.getByRole('dialog')).toContainText('Logs already received are kept')
    await page.keyboard.press('Escape')
    expect((await sources(c)).sources, 'Escape deleted nothing').toHaveLength(1)
    await page.getByRole('button', { name: `Delete ${renamed}` }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByText('Log source deleted.').first()).toBeVisible()
    expect((await sources(c)).sources).toEqual([])
    expect(await audit(c, renamed)).toEqual(expect.arrayContaining([expect.objectContaining({ action: 'logs.source_delete', target: renamed })]))

    // the line stays; its source name is the one it had when it arrived, a new datagram is not stored
    const after = await events(c, { q: tok })
    expect(after.events.map((e) => e.line)).toEqual([line])
    await sockets('udp', 'closed')
    await sendUdp(`<34>Nov 11 12:31:01 gw app[1]: ${tok} after delete`)
    await new Promise((ok) => setTimeout(ok, 3_000)) // longer than the batch time of the listener
    expect((await events(c, { q: tok })).total, 'nothing is stored for a sender that is no longer declared').toBe(1)
    only501(five)
    noErrors(errors, /status of 501/)
  } finally { await c.dispose() }
})

test('retention: the page changes it, the API refuses anything but 7, 30, 90, 180, and it is in the audit (INV-4, POST-3)', async ({ page }) => {
  const errors = collectErrors(page)
  const five = watch5xx(page)
  const c = await as('admin')
  try {
    await add(c)
    await page.goto('/logs')
    const target = original === 90 ? '180' : '90'
    await page.getByLabel('Keep logs for').selectOption(target)
    await expect(page.getByText('Log retention saved.').first()).toBeVisible()
    expect((await sources(c)).retention_days).toBe(Number(target))
    await page.reload()
    await expect(page.getByLabel('Keep logs for')).toHaveValue(target)
    expect((await audit(c, 'logs.retention'))[0]).toMatchObject({ action: 'logs.retention', detail: `${target} days` })
    const auditRet = await auditTotal(c, 'logs.')
    for (const days of [0, 45, 365, -1, '30']) {
      const r = await api<Err>(c, 'PUT', '/logs/retention', { days })
      expect([r.status, r.body.error.code], `days=${JSON.stringify(days)}`).toEqual([400, 'invalid'])
    }
    expect((await sources(c)).retention_days, 'the refusals changed nothing').toBe(Number(target))
    expect(await auditTotal(c, 'logs.'), 'the refusals left no audit row').toBe(auditRet)
    const back = await api(c, 'PUT', '/logs/retention', { days: original })
    expect(back.status).toBe(200)
    only501(five)
    noErrors(errors, /status of (400|501)/)
  } finally { await c.dispose() }
})

test('roles: a viewer and an operator read, and every change answers 403 forbidden and saves nothing', async ({ browser }) => {
  const admin = await as('admin')
  try {
    const src = await add(admin)
    const before = JSON.stringify(await sources(admin))
    const auditRoles = await auditTotal(admin, 'logs.')
    for (const role of ['viewer', 'operator'] as const) {
      const c = await as(role)
      try {
        expect((await api(c, 'GET', '/logs/sources')).status, `${role} reads the sources`).toBe(200)
        expect((await api(c, 'GET', '/logs/digest')).status).toBe(200)
        expect((await api(c, 'GET', '/logs/events?window=1h')).status).toBe(200)
        for (const [method, path, body] of [
          ['POST', '/logs/sources', { ...SRC, name: uniq('lg'), sender_ip: '127.0.0.9' }], ['PUT', `/logs/sources/${src.id}`, { ...SRC, name: uniq('lg') }],
          ['DELETE', `/logs/sources/${src.id}`, undefined], ['PUT', '/logs/retention', { days: 7 }], ['GET', '/logs/siem', undefined],
        ] as const) {
          const r = await api<Err>(c, method, path, body)
          expect([r.status, r.body.error.code], `${role}: ${method} ${path}`).toEqual([403, 'forbidden'])
        }
      } finally { await c.dispose() }
      expect(JSON.stringify(await sources(admin)), `${role}: nothing changed`).toBe(before)
      expect(await auditTotal(admin, 'logs.'), `${role}: no audit row`).toBe(auditRoles)
      const ctx = await browser.newContext({ baseURL: box().base_url, storageState: authFile(role) })
      try {
        const page = await ctx.newPage()
        await page.goto('/logs')
        const addBtn = page.getByRole('button', { name: 'Add log source' }).first()
        await expect(addBtn).toBeDisabled()
        await expect(addBtn).toHaveAttribute('title', 'Requires Admin role')
        await expect(page.getByLabel('Keep logs for')).toBeDisabled()
        await expect(page.getByRole('button', { name: `Delete ${src.name}` })).toBeDisabled()
      } finally { await ctx.close() }
    }
  } finally { await admin.dispose() }
})

test('a module that is off has no route and no socket; its lines are kept; on again, the source works (SYS-5, INV-4)', async () => {
  test.setTimeout(90_000)
  const c = await as('admin')
  try {
    const src = await add(c)
    const tok = uniq('tok')
    const kept = `<34>Nov 11 12:32:00 gw app[1]: ${tok} kept`
    await sendUdp(kept)
    await stored(c, kept, src.id)
    const off = await api(c, 'PATCH', '/modules/logs', { enabled: false })
    expect(off.status, JSON.stringify(off.body)).toBe(200)
    try {
      for (const [method, path] of [['GET', '/logs/sources'], ['GET', '/logs/events?window=24h'], ['GET', '/logs/digest']] as const) {
        const r = await api<Err>(c, method, path)
        expect([r.status, r.body.error.code], `${method} ${path} while off`).toEqual([404, 'not_found'])
      }
      await sockets('udp', 'closed') // no socket while the module is off (SYS-5)
      await sendUdp(`<34>Nov 11 12:32:01 gw app[1]: ${tok} while off`) // nobody listens: the datagram is lost, which is the point
    } finally {
      expect((await api(c, 'PATCH', '/modules/logs', { enabled: true })).status).toBe(200)
    }
    const back = await events(c, { q: tok })
    expect(back.events.map((e) => e.line), 'the line from before is kept, the one sent while off was never stored').toEqual([kept])
    expect((await sources(c)).sources.map((s) => s.id)).toEqual([src.id])
    const again = `<34>Nov 11 12:32:02 gw app[1]: ${tok} on again`
    await sockets('udp', 'open')
    await sendUdp(again)
    await stored(c, again, src.id)
  } finally { await c.dispose() }
})

test('digest of a fresh source (INV-6, PRE-3): inside the 24 h warm-up nothing is new or a spike, and an empty bad-connection list says why', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const src = await add(c)
    const tok = uniq('tok')
    for (let i = 0; i < 25; i++) await sendUdp(`<34>Nov 11 12:34:${String(i).padStart(2, '0')} gw app[1]: ${tok} flood ${i}`) // far over the spike floor of 20
    await expect.poll(async () => (await events(c, { q: tok, source: src.id })).total, { timeout: 15_000 }).toBe(25)
    const d = (await api<{ lines_24h: number; baseline_days: number; new: unknown[]; spikes: unknown[]; bad_connections: unknown[] }>(c, 'GET', '/logs/digest')).body
    expect(d.baseline_days).toBe(7)
    expect(d.lines_24h).toBeGreaterThanOrEqual(25)
    expect([d.new, d.spikes, d.bad_connections], 'a source in its first 24 hours has no new log type, no spike and no bad connection').toEqual([[], [], []])
    await page.goto('/logs')
    await expect(h1(page)).toContainText('Today: logs look normal') // titleQuiet: no bad connection, no new type, no spike
    await expect(page.getByText('No new log types compared with 7 days ago.')).toBeVisible()
    await expect(page.getByText('No connection to bad addresses in the last 24 hours.')).toBeVisible()
    await expect(page.getByText(/not switched on yet, so an empty list does not mean the network is clean/)).toBeVisible()
    // Feeds off: the page says that instead (PRE-3); the digest itself keeps working
    const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(c, 'GET', '/modules')
    const feedsWas = mods.body.modules.find((m) => m.id === 'feeds')?.enabled === true
    expect(feedsWas, 'feeds is on at the start of this test').toBe(true)
    expect((await api(c, 'PATCH', '/modules/feeds', { enabled: false })).status).toBe(200)
    try {
      expect((await api(c, 'GET', '/logs/digest')).status).toBe(200)
      await page.reload()
      await expect(page.getByText(/The Feeds module is off, so no connection can be matched/)).toBeVisible()
    } finally { expect((await api(c, 'PATCH', '/modules/feeds', { enabled: feedsWas })).status).toBe(200) }
    await noVietnamese(page, 'logs digest')
    noErrors(errors, /status of (501|404)/)
  } finally { await c.dispose() }
})

// every device type the catalog offers, with every protocol: the ones it can send are saved (UDP and TCP) or refused as not built (TLS, D-203), the others are bad_proto
const KINDS: { id: string; protos: string[] }[] = JSON.parse(readFileSync(new URL('../../content/logs/kinds.json', import.meta.url), 'utf8'))
test('every device type with every protocol on the real backend: allowed UDP/TCP saved, TLS refused, any other combination bad_proto (INV-3, QA row 44)', async () => {
  test.setTimeout(120_000)
  expect(KINDS.length, 'the 48 device types').toBe(48)
  const c = await as('admin')
  try {
    const auditBefore = (await auditTotal(c, 'logs.source_add')) + (await auditTotal(c, 'logs.source_delete'))
    let saved = 0
    for (const k of KINDS) {
      for (const proto of ['udp', 'tcp', 'tls']) {
        const body = { kind: k.id, name: `m-${k.id}-${proto}`, sender_ip: '10.77.7.7', proto, port: proto === 'tls' ? 6514 : 514 }
        const r = await api<Source & Err>(c, 'POST', '/logs/sources', body)
        const want = !k.protos.includes(proto) ? [400, 'bad_proto'] : proto === 'tls' ? [400, 'tls_unavailable'] : [201, undefined]
        expect([r.status, r.body.error?.code], `${k.id} over ${proto}`).toEqual(want)
        if (r.status === 201) {
          saved++
          expect(r.body).toMatchObject({ kind: k.id, proto, port: 514, sender_ip: '10.77.7.7', state: 'never' })
          expect((await api(c, 'DELETE', `/logs/sources/${r.body.id}`)).status).toBe(204)
        }
      }
    }
    expect(saved, 'one saved source per kind and non-TLS protocol it can send').toBe(KINDS.reduce((n, k) => n + k.protos.filter((p) => p !== 'tls').length, 0))
    expect((await sources(c)).sources, 'the matrix left nothing behind').toEqual([])
    expect((await auditTotal(c, 'logs.source_add')) + (await auditTotal(c, 'logs.source_delete')), 'each save and delete is audited, a refusal is not').toBe(auditBefore + saved * 2)
  } finally { await c.dispose() }
})

test('phone width: the Logs page with a source and lines fits a 390 px screen: no horizontal scroll, the add button and the tables are reachable', async ({ browser }) => {
  test.setTimeout(90_000)
  const c = await as('admin')
  const ctx = await browser.newContext({ baseURL: box().base_url, storageState: authFile('admin'), viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })
  try {
    const src = await add(c)
    const tok = uniq('tok')
    const line = `<34>Nov 11 12:35:00 gw app[1]: ${tok} at phone width with a rather long line that must wrap or scroll inside its own table and never push the page wider than the screen`
    await sendUdp(line)
    await stored(c, line, src.id)
    const page = await ctx.newPage()
    const errors = collectErrors(page)
    await page.goto('/logs')
    await expect(h1(page)).toContainText('Today:')
    // at phone width the sources and the events are lists of cards, not tables
    await expect(page.getByRole('list', { name: 'Log sources currently received' }).getByRole('listitem').filter({ hasText: src.name })).toBeVisible()
    await page.getByLabel('Keyword').fill(tok)
    await expect(page.getByText(line)).toBeVisible()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow, 'no horizontal page scroll at 390 px').toBeLessThanOrEqual(0)
    await expect(page.getByRole('button', { name: 'Add log source' }).first()).toBeVisible()
    noErrors(errors, /status of 501/)
  } finally { await ctx.close(); await c.dispose() }
})

// L4: the box matches a connection that a firewall line names against the indicators of the feeds module (S-LOG-2, S-LOG-4, INV-7, POST-2, D-213). No public
// address is touched: the feed is a custom one pulled from a loopback server (like feeds.spec.ts) and lists a domain under a made-up TLD, so only this feed lists
// it; the line is one FortiGate DNS-filter line sent over loopback UDP, from the LAN address 192.168.100.23, which is not in the inventory.
test('bad connections: a LAN device that asks for a domain a feed lists is in the digest and on the page (S-LOG-2, S-LOG-4, INV-7, POST-2)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  const ioc = `${uniq('ioc')}.zzqx`
  const feed = uniq('L4 IOC')
  const srv = createServer((_, res) => { res.writeHead(200, { 'Content-Type': 'text/plain' }); res.end(`# a list\n${ioc}\n`) })
  await new Promise<void>((ok) => srv.listen(0, '127.0.0.1', ok))
  let feedId = ''
  try {
    const url = `http://127.0.0.1:${(srv.address() as AddressInfo).port}/list.txt`
    const lines = { format: 'lines', records_path: '', delimiter: '', has_header: false, fields: { indicator: { source: '', regex: '', trim: true, lowercase: false, date_format: 'auto' } } }
    const made = await api<{ id: string }>(c, 'POST', '/feeds/custom', { name: feed, kind: 'ioc', url, enabled: true, interval_hours: 24, auth: { type: 'none', header_name: null, username: null }, parser: lines })
    expect(made.status, JSON.stringify(made.body)).toBe(201)
    feedId = made.body.id
    expect((await api(c, 'POST', `/feeds/sources/${feedId}/fetch`)).status).toBeLessThan(300)
    await expect.poll(async () => (await api<{ items: { id: string; records: number }[] }>(c, 'GET', '/feeds/sources')).body.items.find((i) => i.id === feedId)?.records, { message: 'the feed holds the indicator', timeout: 30_000 }).toBe(1)

    const src = await add(c, { kind: 'fortigate' })
    const line = `<189>date=2026-11-09 time=10:22:00 devname="FW-E2E" logid="1501054802" type="utm" subtype="dns" level="notice" srcip=192.168.100.23 dstip=192.168.100.1 qname="${ioc}" qtype="A" action="pass"`
    await sendUdp(line)
    await stored(c, line, src.id)
    type Hit = { id: string; src_ip: string; dest: string; dest_kind: string; seen_via: string; feeds: string[]; confidence: number; asset_id: string | null; asset_name: string | null }
    const bad = async () => (await api<{ bad_connections: Hit[] }>(c, 'GET', '/logs/digest')).body.bad_connections
    await expect.poll(async () => (await bad()).map((h) => h.dest), { message: 'the digest lists the connection', timeout: 15_000 }).toContain(ioc)
    const hit = (await bad()).find((h) => h.dest === ioc)!
    expect(hit).toMatchObject({ src_ip: '192.168.100.23', dest_kind: 'domain', seen_via: `syslog:${src.name}`, feeds: [feed], asset_id: null, asset_name: null })
    expect(hit.confidence).toBeGreaterThan(0)
    expect(hit.confidence).toBeLessThanOrEqual(1)
    // the same line again is the same hit (once per device and destination in 24 hours)
    await sendUdp(line)
    await expect.poll(async () => (await events(c, { source: src.id })).total, { timeout: 15_000 }).toBe(2)
    expect((await bad()).filter((h) => h.dest === ioc)).toHaveLength(1)
    await page.goto('/logs')
    const table = page.getByRole('table', { name: 'Connections to bad IPs or domains' })
    await expect(table).toContainText(ioc)
    await expect(table).toContainText('192.168.100.23')
    await expect(page.getByText('None of your devices connected to a listed bad address')).toHaveCount(0)
    noErrors(errors, /status of 501/)
  } finally {
    if (feedId) expect((await api(c, 'DELETE', `/feeds/custom/${feedId}`)).status, 'the feed of this test is deleted').toBe(204)
    await new Promise((ok) => srv.close(ok))
    await c.dispose()
  }
})

// ---- not built yet: the whole flow is in the body (D-171 (2)) ----
test.fixme('SIEM forwarding: save, a failed and a successful test, the key is never returned (S-LOG-3, INV-8..10; L5, GET /logs/siem answers 501 not_implemented)', async ({ page }) => {
  const c = await as('admin')
  const saved = await api<{ secret_last4: string | null }>(c, 'PUT', '/logs/siem', { enabled: false, format: 'json', host: '', port: 514, proto: 'udp', url: 'https://siem.e2e.test/hook', events: ['findings'], secret: 'a-signing-key-of-16+' })
  expect(saved.status).toBe(200)
  expect(JSON.stringify(saved.body)).not.toContain('a-signing-key-of-16+')
  expect(saved.body.secret_last4).toBe('16+')
  await page.goto('/settings/siem')
  await expect(h1(page)).toContainText('Forward to a SIEM')
  await c.dispose()
})
test.fixme('digest: after the 24 h warm-up a log type never seen before is "new" and a flood is a spike (INV-6): a box cannot skip the warm-up, so the Go tests carry it', async () => {
  const c = await as('admin')
  await add(c)
  await sendUdp(`<34>Nov 11 12:33:00 gw app[1]: ${uniq('tok')} a log type with a signature`)
  await expect.poll(async () => (await api<{ new: unknown[] }>(c, 'GET', '/logs/digest')).body.new.length).toBeGreaterThan(0)
  await c.dispose()
})
test.fixme('a TLS source is served on 6514 with the pinned client certificate (POST-1; D-203: tls is refused until the listener exists)', async () => {
  const c = await as('admin')
  const r = await api(c, 'POST', '/logs/sources', { kind: 'fortigate', name: uniq('lg'), sender_ip: '127.0.0.1', proto: 'tls', port: 6514 })
  expect(r.status).toBe(201)
  await c.dispose()
})
