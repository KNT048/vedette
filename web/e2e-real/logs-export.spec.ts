// Download logs on the real backend (S-CORE-6, D-132, core INV-13): days are whole days in the ORGANIZATION time zone, a category whose
// module keeps no log is listed as missing (`missing` in JSON, `(no source)` in CSV) instead of looking empty, and a CSV cell that starts with
// = + - @ cannot run as a formula. The rows come from the real API: accounts whose email starts with those characters, an organization name
// that starts with @ (put back in `finally`), and the audit rows of the run itself.
// The box lets one export start per minute (409 busy / 429 rate_limited), box-wide, so the exports of this file run one after the other and
// wait for the slot: the file takes about two minutes. Nothing else in e2e-real exports logs.
import { readFileSync } from 'node:fs'
import { expect, request, test, type APIRequestContext } from '@playwright/test'
import { api, authFile, box, createUser, uniq } from './box'
import { h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

const CATEGORIES = ['audit', 'ai_activity', 'response', 'scan_probes', 'alerts', 'device_logs', 'known_bad', 'honeypot']
const SLOT_MS = 61_000
let lastStart = 0
/** Waits until the export slot is free (a minute after the previous export started). */
async function slot() {
  const wait = lastStart + SLOT_MS - Date.now()
  if (wait > 0) await new Promise((ok) => setTimeout(ok, wait))
}
interface Envelope {
  format: string; exported_at: string; from: string | null; to: string | null; time_zone: string; verification: string
  missing: string[]; counts: Record<string, number>; chains: Record<string, { anchor: string | null; anchor_kind: string; head_hash: string | null; count: number; complete: boolean }>
  categories: Record<string, Record<string, unknown>[]>
}
/** One export through the API. It waits for the slot first, and records when it started. */
async function exportLogs(c: APIRequestContext, q: Record<string, string>) {
  await slot()
  lastStart = Date.now()
  return api<any>(c, 'GET', `/core/logs/export?${new URLSearchParams(q)}`)
}
const day = (tz: string, offset = 0) => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(Date.now() + offset * 86_400_000))
const orgDayOf = (ts: string, tz: string) => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(ts))

/** RFC 4180 reader, enough for the file: quoted cells, doubled quotes, newlines inside quotes. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = [], cellv = '', quoted = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    if (quoted) {
      if (ch === '"' && text[i + 1] === '"') { cellv += '"'; i++ } else if (ch === '"') quoted = false
      else cellv += ch
    } else if (ch === '"') quoted = true
    else if (ch === ',') { row.push(cellv); cellv = '' }
    else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++
      row.push(cellv); rows.push(row); row = []; cellv = ''
    } else cellv += ch
  }
  if (cellv || row.length) { row.push(cellv); rows.push(row) }
  return rows
}

// What the file must hold for the formula test: one account per leading character, plus an organization name that starts with @.
const lead = uniq('lg').toLowerCase()
const seeded = { '=': `=1+1-${lead}@e2e.test`, '+': `+${lead}@e2e.test`, '-': `-${lead}@e2e.test`, '@': `@org-${lead}` }
let org = { name: '', timezone: 'Asia/Ho_Chi_Minh' }

test.beforeAll(async () => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const tmp = await request.newContext({ baseURL: box().base_url })
  for (const c of ['=', '+', '-'] as const) await createUser(admin, tmp, { name: `Formula ${lead}`, email: seeded[c], role: 'viewer' })
  org = (await api<typeof org>(admin, 'GET', '/core/general')).body
  const renamed = await api(admin, 'PUT', '/core/general', { name: seeded['@'], timezone: org.timezone })
  expect(renamed.status, JSON.stringify(renamed.body)).toBe(200)
  await Promise.all([admin.dispose(), tmp.dispose()])
})
test.afterAll(async () => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  await api(admin, 'PUT', '/core/general', { name: org.name, timezone: org.timezone })
  await admin.dispose()
})

test('a bad request is refused with a code and does not use the export slot', async () => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const bad = async (q: Record<string, string>) => api<{ error: { code: string } }>(admin, 'GET', `/core/logs/export?${new URLSearchParams(q)}`)
  expect((await bad({ categories: '' })).body).toMatchObject({ error: { code: 'invalid_categories' } })
  expect((await bad({ categories: 'audit,nope' })).body).toMatchObject({ error: { code: 'invalid_categories' } })
  expect((await bad({ categories: 'audit', format: 'xml' })).body).toMatchObject({ error: { code: 'invalid_format' } })
  for (const from of ['11/11/2026', '2026-13-40', '1999-12-31', '2101-01-01', '2026-11-11T00:00:00.000Z']) {
    const r = await bad({ categories: 'audit', from })
    expect([r.status, r.body], `from=${from}`).toEqual([400, expect.objectContaining({ error: expect.objectContaining({ code: 'invalid_range' }) })])
  }
  const r = await bad({ categories: 'audit', from: '2026-11-12', to: '2026-11-11' })
  expect([r.status, r.body]).toEqual([400, expect.objectContaining({ error: expect.objectContaining({ code: 'invalid_range' }) })])
  for (const role of ['viewer', 'operator'] as const) {
    const c = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    expect((await api(c, 'GET', '/core/logs/export?categories=audit')).status, `${role}`).toBe(403)
    await c.dispose()
  }
  await admin.dispose()
})

// The Data page sends the day the person picks (YYYY-MM-DD), as the box (D-132) takes it. It runs before the exports so it takes the slot first and the tests after it wait for it.
test('the Data page downloads the days the person picks', async ({ page }) => {
  test.setTimeout(150_000)
  await slot()
  await page.goto('/settings/data')
  await expect(h1(page)).toBeVisible()
  const today = day(org.timezone)
  await page.getByLabel('From', { exact: true }).fill(today)
  await page.getByLabel('To', { exact: true }).fill(today)
  const saved = page.waitForEvent('download', { timeout: 15_000 })
  await page.getByRole('button', { name: 'Download logs' }).click()
  const file = await saved
  expect(file.suggestedFilename()).toMatch(/^vedette-logs-/)
  lastStart = Date.now() // the download used the slot
})

test('JSON: the days are whole days of the organization time zone, missing categories are named, the audit chain says where it starts and ends, and a second download within a minute is refused', async () => {
  test.setTimeout(150_000)
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const tz = org.timezone
  await slot() // wait first: the day is read after the wait, so a wait across midnight in the organization zone cannot skew it
  const today = day(tz)
  const r = await exportLogs(admin, { categories: CATEGORIES.join(','), format: 'json', from: today, to: today })
  expect(r.status, JSON.stringify(r.body).slice(0, 300)).toBe(200)
  const f = r.body as Envelope
  expect(f.format).toBe('vedette-logs/1')
  expect(f.time_zone, 'the file says which zone its days are in').toBe(tz)
  expect(f.verification).toContain('SHA-256')

  // a day is the whole day in the organization zone, the end day included
  const audit = f.categories.audit!
  expect(audit.length, 'the rows of today are in (the last day counts)').toBeGreaterThan(0)
  expect(f.counts.audit).toBe(audit.length)
  for (const row of audit) expect(orgDayOf(String(row.ts), tz), `row ${row.id} ${row.ts}`).toBe(today)
  // consecutive rows link, and the head the file reports is the last row it holds
  for (let i = 1; i < audit.length; i++) expect(audit[i]!.prev_hash, `row ${audit[i]!.id} links to the one before`).toBe(audit[i - 1]!.hash)
  expect(f.chains.audit).toMatchObject({ head_hash: audit.at(-1)!.hash, count: expect.any(Number) })
  expect(f.chains.audit!.count).toBeGreaterThanOrEqual(audit.length)
  expect(['genesis', 'pruned', 'row']).toContain(f.chains.audit!.anchor_kind)
  expect(f.chains.audit!.anchor, 'the anchor is the prev_hash of the first row').toBe(audit[0]!.prev_hash)

  // what the accounts and the organization name looked like when they were written: kept as they are in JSON (the hashes still check)
  const targets = audit.map((a) => a.target)
  for (const v of Object.values(seeded)) expect(targets, `${v} in the audit rows`).toContain(v)

  // a category with no source is listed, not shown as an empty one
  expect(f.missing, 'categories whose module keeps no log yet are named').toEqual(expect.arrayContaining(['ai_activity', 'alerts', 'known_bad']))
  for (const id of ['audit', 'response', 'scan_probes', 'honeypot']) expect(f.missing, `${id} has a source`).not.toContain(id)
  for (const id of f.missing) expect([f.counts[id], f.categories[id]], `${id} is missing and empty`).toEqual([0, []])
  expect(Object.keys(f.categories).sort()).toEqual([...CATEGORIES].sort())
  expect(Object.keys(f.chains).sort(), 'only the hash-chained categories have a chain note').toEqual(['audit', 'response'].filter((id) => !f.missing.includes(id)).sort())

  // the slot: a second download within the minute is refused, and the refusal is in the log
  const second = await api<{ error: { code: string; retry_after?: number } }>(admin, 'GET', '/core/logs/export?categories=audit')
  expect(second.status).toBe(429)
  expect(second.body).toMatchObject({ error: { code: 'rate_limited' } })
  const log = await api<{ items: { action: string; detail?: string }[] }>(admin, 'GET', '/core/audit?q=logs.export')
  expect(log.body.items.some((x) => x.action === 'logs.export_refused' && /rate_limited/.test(x.detail ?? ''))).toBe(true)
  expect(log.body.items.some((x) => x.action === 'logs.export' && (x.detail ?? '').includes(`from ${today}`) && (x.detail ?? '').includes(`to ${today}`))).toBe(true)
  await admin.dispose()
})

test('JSON: a day with no rows gives an empty category, not an error (the day after today in the organization zone)', async () => {
  test.setTimeout(150_000)
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const tomorrow = day(org.timezone, 1)
  const r = await exportLogs(admin, { categories: 'audit,response', format: 'json', from: tomorrow, to: tomorrow })
  expect(r.status, JSON.stringify(r.body).slice(0, 300)).toBe(200)
  const f = r.body as Envelope
  expect(f.counts.audit).toBe(0)
  expect(f.categories.audit).toEqual([])
  await admin.dispose()
})

test('CSV from the Data page: (no source) sections, and no cell that starts with = + - @ can run as a formula', async ({ page }) => {
  test.setTimeout(180_000)
  const errors = collectErrors(page)
  await slot()
  await page.goto('/settings/data')
  await expect(h1(page)).toBeVisible()
  await page.getByLabel('Format').selectOption('csv')
  const saved = page.waitForEvent('download', { timeout: 60_000 })
  lastStart = Date.now()
  await page.getByRole('button', { name: 'Download logs' }).click()
  const file = await saved
  expect(file.suggestedFilename()).toMatch(/^vedette-logs-\d{4}-\d{2}-\d{2}\.csv$/)
  const text = readFileSync((await file.path())!, 'utf8')
  expect(text.charCodeAt(0), 'a UTF-8 byte order mark so a spreadsheet reads the letters right').toBe(0xfeff)
  const lines = text.slice(1).split(/\r?\n/)
  // one section per category, a category with no source says so
  const heads = lines.filter((l) => l.startsWith('# '))
  expect(heads.map((h) => h.replace(/ \(no source\)$/, '').slice(2)).sort(), 'a section for each category').toEqual([...CATEGORIES].sort())
  for (const id of ['ai_activity', 'alerts', 'known_bad']) expect(heads, `${id} says it has no source`).toContain(`# ${id} (no source)`)
  for (const id of ['audit', 'response', 'scan_probes', 'honeypot']) expect(heads, `${id} has a source`).toContain(`# ${id}`)
  await expect(page.locator('[data-sonner-toast]').filter({ hasText: /Downloaded/ }).first()).toBeVisible()

  // formulas: no cell of the whole file starts with = + - @ (tab and CR too), and the account rows are there with an apostrophe in front
  const cells = parseCsv(text.slice(1)).filter((r) => !(r.length === 1 && r[0]!.startsWith('# '))).flat()
  expect(cells.filter((c) => /^[=+\-@\t\r]/.test(c)), 'cells a spreadsheet would run').toEqual([])
  for (const v of Object.values(seeded)) expect(cells, `${v} is in the file, escaped`).toContain(`'${v}`)
  noErrors(errors)
  await noVietnamese(page, 'data')
})
