// The backup download on the real backend through vedette-host (core INV-18 and INV-19, S-CORE-1 data section, D-87): the box writes a snapshot
// WITHOUT its master key, the host packs it, and what the browser saves is a tar.gz that holds no key and no password. The archive is opened
// here, in the test, byte by byte. The host is the fake machine of cmd/vedette/e2ehost_test.go.
// A download is one a minute (429 after that), so the whole spec makes one download through the GUI and checks that file.
// Where the real answer differs from the mock (the mock saves JSON, the real backend sends a tar.gz) the test is test.fail() with the
// issue and the deferred line (D-171).
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { gunzipSync } from 'node:zlib'
import { expect, request, test } from '@playwright/test'
import { api, authFile, box, password, uniq } from './box'
import { h1, noErrors } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

/** The files of a tar archive (ustar and the pax `path` of long names), with their bytes. Enough for what the host writes. */
function tarEntries(tar: Buffer): { name: string; data: Buffer }[] {
  const out: { name: string; data: Buffer }[] = []
  const str = (b: Buffer) => b.toString('utf8').replace(/\0.*$/s, '')
  let pax: string | undefined
  for (let at = 0; at + 512 <= tar.length;) {
    const head = tar.subarray(at, at + 512)
    if (head.every((x) => x === 0)) break
    const size = parseInt(str(head.subarray(124, 136)).trim() || '0', 8)
    const type = String.fromCharCode(head[156])
    const data = tar.subarray(at + 512, at + 512 + size)
    at += 512 + Math.ceil(size / 512) * 512
    if (type === 'x') { pax = /\d+ path=([^\n]*)\n/.exec(data.toString('utf8'))?.[1]; continue }
    if (type === 'g') continue
    const prefix = str(head.subarray(345, 500))
    const name = pax ?? (prefix ? `${prefix}/${str(head.subarray(0, 100))}` : str(head.subarray(0, 100)))
    pax = undefined
    if (type === '0' || type === '\0') out.push({ name, data: Buffer.from(data) })
  }
  return out
}

/** Only the known symptom may satisfy a test.fail: when it is not what the page shows, the expectation is switched off and the test is red. */
const knownSymptom = (known: boolean) => { if (!known) test.fail(false) }

let archive: Buffer
let savedAs: string
let secret: string
let connectionId: string

test.afterAll(async () => {
  if (!connectionId) return
  const c = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  await api(c, 'DELETE', `/core/connections/${connectionId}`)
  await c.dispose()
})

test('the Download backup button saves an archive of the box (a stored secret is on the box when it is taken)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  // A stored secret makes the key matter: it is in the database (encrypted with the key), and neither it nor the key may be in the archive.
  secret = `s3cret-${uniq('bk')}-token-value`
  const made = await api<{ id: string }>(page.request, 'POST', '/core/connections', {
    name: uniq('bk'), kind: 'http', target: 'https://printer.example.com', auth_type: 'token', secret, allow: ['https://printer.example.com/status'], enabled: false,
  })
  expect(made.status, JSON.stringify(made.body)).toBe(201)
  connectionId = made.body.id

  await page.goto('/settings/data')
  await expect(h1(page)).toBeVisible()
  await expect(page.getByText('No AI keys or tokens.')).toBeVisible() // what the page promises about the backup
  const dl = page.waitForEvent('download', { timeout: 60_000 }) // the host makes a full snapshot and a backup first: 10 to 20 s on a busy machine
  await page.getByRole('button', { name: 'Download backup', exact: true }).click()
  const download = await dl
  savedAs = download.suggestedFilename()
  archive = readFileSync((await download.path())!)
  await expect(page.locator('[data-sonner-toast]').filter({ hasText: /Downloaded vedette-backup-/ }).first()).toBeVisible()
  await shot(page, 'real', 'backup-downloaded')
  expect(archive.length).toBeGreaterThan(1000)
  expect(archive.subarray(0, 2).toString('hex'), 'a gzip file').toBe('1f8b')
  noErrors(errors, /status of 4\d\d/)
})

// Issue #232 (fixed in #247): the saved file is named like the tar.gz the backend sends (INV-19).
test('the saved file is named like the archive it is: vedette-backup-<day>.tar.gz', async () => {
  expect(savedAs).toMatch(/^vedette-backup-\d{4}-\d\d-\d\d\.tar\.gz$/)
})

test('the archive holds the database and no master key, no password and no stored secret (INV-18, INV-19)', async () => {
  const entries = tarEntries(gunzipSync(archive))
  const names = entries.map((e) => e.name)
  expect(names.length, `entries: ${names.join(', ')}`).toBeGreaterThan(0)
  // the database is there, whole, and readable: the checks below are not vacuous
  const db = entries.find((e) => /(^|\/)vedette\.db$/.test(e.name))
  expect(db, `no vedette.db in ${names.join(', ')}`).toBeTruthy()
  expect(db!.data.subarray(0, 15).toString('latin1')).toBe('SQLite format 3')
  expect(db!.data.includes(Buffer.from('admin@e2e.test')), 'the control: a plain value of the database is found in the archive').toBe(true)
  // no key file by name
  expect(names.filter((n) => /\.key$|(^|\/)vedette\.key|master|secret/i.test(n)), 'a key file in the archive').toEqual([])
  // no key bytes anywhere in any file or in the raw tar
  const key = readFileSync(join(box().data_dir, 'vedette.key'))
  expect(key.length).toBeGreaterThanOrEqual(16)
  const raw = gunzipSync(archive)
  for (const [label, needle] of [['the master key', key], ['the master key, trimmed', Buffer.from(key.toString('utf8').trim())], ['the master key as hex', Buffer.from(key.toString('hex'))], ['the master key as base64', Buffer.from(key.toString('base64'))]] as const) {
    expect(raw.includes(needle), `${label} is in the archive`).toBe(false)
  }
  // no password, no stored secret in the clear
  expect(raw.includes(Buffer.from(password())), 'a password in the archive').toBe(false)
  expect(raw.includes(Buffer.from(secret)), 'a stored connection secret in the clear').toBe(false)
  // the archive is exactly the manifest and the database (host/ops/backup.go: the key is a third member only for a backup that keeps secrets),
  // and the manifest says it holds no secrets
  expect([...names].sort()).toEqual(['manifest.json', 'vedette.db'])
  const manifest = JSON.parse(entries.find((e) => e.name === 'manifest.json')!.data.toString('utf8'))
  expect(manifest).toMatchObject({ version: 1, includes_secrets: false })
})

test('after the download core has removed its snapshot folder (INV-18)', async () => {
  const dir = join(box().data_dir, 'snapshots')
  await expect.poll(() => (existsSync(dir) ? readdirSync(dir) : []), { timeout: 15_000, message: 'snapshots/ in the data folder' }).toEqual([])
})

test('a real box does not offer to restore sample data', async ({ page }) => {
  await page.goto('/settings/data')
  await expect(h1(page)).toBeVisible()
  knownSymptom(await page.getByRole('button', { name: 'Restore sample data', exact: true }).isVisible())
  await expect(page.getByRole('button', { name: 'Restore sample data', exact: true })).toHaveCount(0)
})

test('the download is audited, a second one inside a minute is refused in words, and only an administrator may ask', async () => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const log = await api<{ items: { action: string; user: string }[] }>(admin, 'GET', '/core/audit?q=data.backup')
  expect(log.body.items.find((i) => i.action === 'data.backup')?.user).toBe('admin@e2e.test')
  const again = await admin.get('/api/v1/core/data/backup', { failOnStatusCode: false })
  expect(again.status()).toBe(429)
  expect((await again.json()).error.code).toBe('rate_limited')
  expect(Number(again.headers()['retry-after'])).toBeGreaterThan(0)
  await admin.dispose()
  for (const role of ['operator', 'viewer'] as const) {
    const c = await request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
    expect((await c.get('/api/v1/core/data/backup', { failOnStatusCode: false })).status(), role).toBe(403)
    await c.dispose()
  }
})
