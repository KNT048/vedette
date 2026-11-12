// The ai module on the real backend (S-AI-1..5, S-AI-7, S-AI-8; ai INV-1..4, INV-6, INV-8..10, INV-12, INV-13, INV-17..20, INV-22, POST-3, POST-5).
// Nothing here configures a real provider: PRIVACY flow 3 lists what an AI call sends, and the box must not send anything out. Every profile the specs create is
// "inside your network" on loopback (kind OpenAI-compatible, a made-up key). The failure paths use a loopback port that resets every connection (deadPort), so the
// activity log records the failure (INV-17), the hash chain verifies (INV-18) and the key shows only its last 4 characters everywhere (INV-1, SYS-4). The success
// paths use a stand-in model on loopback (fake-ai.ts) that answers by what the box asks for: explain with its cache and a fallback profile, Ask your data with
// read-only tools and the hooks, the log digest, memory suggestions and the knowledge base (S-AI-2, S-AI-4, S-AI-5, S-AI-7).
// Hooks, rules, the token level, retention and the profile forms are real and need no provider. Global project: all of it is box-wide, and every test puts it back.
// CVE news fetches NVD, GitHub and blogs from the Internet and the e2e box has no seam for them: the refusals that fetch nothing are tested, the fetch-and-summarise
// path stays test.fixme under D-171 (2), recorded in D-426 (the Go contract tests carry it with a fake transport).
import { createSocket } from 'node:dgram'
import { createServer, type Server } from 'node:net'
import { crc32 } from 'node:zlib'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'
import { FAIL, SAY, fakeAI, type FakeAI } from './fake-ai'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Profile { id: string; name: string; kind: string; api_style: string; base_url: string; model: string; location: string; daily_cap: number; key_last4: string | null; usable: boolean; used_today: number }
interface Entry { id: string; job: string; profile: string; model: string; trigger: string; hooks: unknown[]; tools: unknown[]; input_hash: string; output_hash: string; summary: string; tokens_in: number; tokens_out: number; result: string; prev_hash: string; hash: string; ts: string }
interface Err { error: { code: string; message: string; field?: string } }
const JOBS = ['explain-finding', 'mitigation-config', 'cve-news', 'log-digest', 'log-investigate', 'ask-my-data', 'weekly-report', 'pdpl-assessment', 'translate-advisory', 'response-plan']
const KEY = 'e2e-fake-key-0123456789abcd'
const LAST4 = 'abcd'
const CVE = 'CVE-2026-0001'

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const profiles = async (c: APIRequestContext) => (await api<{ items: Profile[] }>(c, 'GET', '/ai/profiles')).body.items
const activity = async (c: APIRequestContext) => (await api<{ items: Entry[]; total: number; retention_days: number }>(c, 'GET', '/ai/activity')).body
const audit = async (c: APIRequestContext, q: string) => (await api<{ items: { action: string; target: string; detail?: string }[] }>(c, 'GET', `/core/audit?q=${encodeURIComponent(q)}`)).body.items
const rules = async (c: APIRequestContext) => (await api<{ builtin: { id: string; text: string }[]; custom: { id: string; text: string; jobs: string[]; enabled: boolean }[] }>(c, 'GET', '/ai/rules')).body
const hooks = async (c: APIRequestContext) => (await api<{ builtin: { id: string; enabled: boolean; locked: boolean }[]; custom: { id: string; name: string }[] }>(c, 'GET', '/ai/hooks')).body

/** A loopback port that no model listens on. The port stays reserved by a server for the whole test (closed in afterEach), and that server resets every connection at once,
 *  so a profile there can never answer and nothing leaves the machine: a port that was only found free could be taken by another process before the box dials it, and the
 *  prompt and the key would go there. `dials` counts the connections the box made. */
const held: Server[] = []
let dials = 0
async function deadPort(): Promise<number> {
  const s = createServer((sock) => { dials++; sock.destroy() })
  await new Promise<void>((ok) => s.listen(0, '127.0.0.1', ok))
  held.push(s)
  return (s.address() as { port: number }).port
}
const body = (name: string, port: number, over: Record<string, unknown> = {}) => ({
  name, kind: 'openai-compatible', api_style: 'openai', base_url: `http://127.0.0.1:${port}/v1`, model: 'm-e2e', location: 'internal', daily_cap: 5000, api_key: KEY, ...over,
})

/** A stand-in model on loopback (fake-ai.ts), closed in afterEach like the dead ports. */
async function fake(): Promise<FakeAI> {
  const f = await fakeAI()
  held.push(f.server)
  return f
}

interface Memory { suggest_enabled: boolean; items: { id: string; text: string; source: string; enabled: boolean; last_used_at: string | null }[]; suggestions: { id: string; text: string; evidence: string }[] }
interface Doc { id: string; name: string; size: number; status: string; chunks: number | null; jobs: string[] }
const memory = async (c: APIRequestContext) => (await api<Memory>(c, 'GET', '/ai/memory')).body
const skills = async (c: APIRequestContext) => (await api<{ items: { id: string; name: string; enabled: boolean }[] }>(c, 'GET', '/ai/skills')).body.items
const docs = async (c: APIRequestContext) => (await api<{ index_profile: string | null; items: Doc[] }>(c, 'GET', '/ai/knowledge')).body

let tier: { tier: string; daily_cap: number; redact_pii: boolean }
let assignments: unknown
let retention = 365
let suggestAtStart = false
let skillsAtStart: Record<string, boolean> = {}
const logSources: string[] = [] // the log sources a test declared (the logs specs expect none on the box)
test.beforeAll(async () => {
  const c = await as('admin')
  try {
    expect(await profiles(c), 'no profile on the box before this file').toEqual([])
    const mem = await memory(c)
    expect([mem.items, mem.suggestions], 'nothing remembered or suggested before this file').toEqual([[], []])
    suggestAtStart = mem.suggest_enabled
    skillsAtStart = Object.fromEntries((await skills(c)).map((s) => [s.id, s.enabled]))
    expect((await docs(c)).items, 'no knowledge document before this file').toEqual([])
    const cfg = (await api<{ tier: string; daily_cap: number; redact_pii: boolean }>(c, 'GET', '/ai/config')).body
    tier = { tier: cfg.tier, daily_cap: cfg.daily_cap, redact_pii: cfg.redact_pii }
    retention = (await api<{ retention_days: number }>(c, 'GET', '/ai/activity/settings')).body.retention_days
    assignments = (await api(c, 'GET', '/ai/assignments')).body
  } finally { await c.dispose() }
})
test.afterEach(async () => {
  await Promise.all(held.splice(0).map((s) => new Promise((ok) => s.close(ok))))
  const c = await as('admin')
  try {
    for (const id of logSources.splice(0)) expect((await api(c, 'DELETE', `/logs/sources/${id}`)).status, `delete log source ${id}`).toBe(204)
    const mem = await memory(c)
    for (const m of mem.items) expect((await api(c, 'DELETE', `/ai/memory/${m.id}`)).status, `delete memory ${m.text}`).toBe(204)
    for (const m of mem.suggestions) expect((await api(c, 'POST', `/ai/memory/suggestions/${m.id}/reject`)).status, `reject ${m.text}`).toBe(204)
    if (mem.suggest_enabled !== suggestAtStart) expect((await api(c, 'PUT', '/ai/memory/settings', { suggest_enabled: suggestAtStart })).status).toBe(200)
    for (const s of await skills(c)) if (s.enabled !== skillsAtStart[s.id]) expect((await api(c, 'PUT', `/ai/skills/${s.id}`, { enabled: skillsAtStart[s.id] })).status, `skill ${s.id} put back`).toBe(200)
    for (const d of (await docs(c)).items) expect((await api(c, 'DELETE', `/ai/knowledge/${d.id}`)).status, `delete document ${d.name}`).toBe(204)
    for (const p of await profiles(c)) expect((await api(c, 'DELETE', `/ai/profiles/${p.id}`)).status, `delete profile ${p.name}`).toBe(200)
    for (const r of (await rules(c)).custom) expect((await api(c, 'DELETE', `/ai/rules/${r.id}`)).status).toBe(204)
    for (const h of (await hooks(c)).custom) expect((await api(c, 'DELETE', `/ai/hooks/${h.id}`)).status).toBe(204)
    for (const h of (await hooks(c)).builtin.filter((x) => !x.enabled && !x.locked)) expect((await api(c, 'PUT', `/ai/hooks/builtin/${h.id}`, { enabled: true })).status).toBe(200)
    expect((await api(c, 'PUT', '/ai/config', tier)).status, 'token level put back').toBe(200)
    expect((await api(c, 'PUT', '/ai/activity/settings', { retention_days: retention })).status, 'retention put back').toBe(200)
    expect(await profiles(c)).toEqual([])
    const now = (await api(c, 'GET', '/ai/assignments')).body
    if (JSON.stringify(now) !== JSON.stringify(assignments)) await api(c, 'PUT', '/ai/assignments', assignments)
    expect(now, 'the routing is the one the file started with (no profile, every task unassigned)').toEqual(assignments)
  } finally { await c.dispose() }
})

test('a box with no profile: nothing is ready, the meter and the logs are empty, the pages say what to do (S-AI-1)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const cfg = (await api<{ configured: boolean; jobs_ready: Record<string, boolean> }>(c, 'GET', '/ai/config')).body
    expect(cfg.configured).toBe(false)
    expect(Object.keys(cfg.jobs_ready).sort()).toEqual([...JOBS].sort())
    expect(Object.values(cfg.jobs_ready), 'no job is ready without a profile').toEqual(JOBS.map(() => false))
    const asg = (await api<{ internal_only: boolean; jobs: Record<string, { primary: string | null; fallback: string | null }> }>(c, 'GET', '/ai/assignments')).body
    for (const j of JOBS) expect(asg.jobs[j], j).toEqual({ primary: null, fallback: null })
    expect((await api(c, 'GET', '/ai/usage')).body).toMatchObject({ today: { total: 0 }, month: { total: 0 }, by_skill: [], downgrades: [] })
    expect(await api(c, 'GET', '/ai/runs')).toEqual({ status: 200, body: { items: [] } })
    expect((await api(c, 'GET', '/ai/activity/verify')).body).toMatchObject({ ok: true, broken_at: null, entry_id: null })

    await page.goto('/settings/ai')
    await expect(h1(page)).toHaveText('AI assistant')
    await expect(page.getByText('No AI profile yet').first()).toBeVisible()
    await expect(page.getByText('No usable profile to assign')).toBeVisible()
    await expect(page.getByText('No cloud profile is set up, so nothing leaves your network. Profiles inside your network keep data on it.')).toBeVisible()
    await expectAccessible(page, 'ai settings, empty')
    await noVietnamese(page, 'ai settings, empty')
    await page.goto('/assistant')
    await expect(h1(page)).toHaveText('No AI profile yet: add one in Settings to ask your data')
    await expect(page.getByRole('link', { name: 'Open Settings, AI assistant' })).toHaveAttribute('href', /\/settings\/ai/)
    noErrors(errors)
  } finally { await c.dispose() }
})

test('every refusal of a profile carries its code and saves nothing; a cloud profile is never created here (INV-1, PRE-3)', async () => {
  const c = await as('admin')
  try {
    const port = await deadPort()
    const n = uniq('ai')
    const cases: [string, Record<string, unknown>, number, string][] = [
      ['empty name', body('', port), 400, 'invalid'], ['name of 41 characters', body('x'.repeat(41), port), 400, 'invalid'],
      ['cap 999', body(n, port, { daily_cap: 999 }), 400, 'invalid'], ['cap 5000001', body(n, port, { daily_cap: 5_000_001 }), 400, 'invalid'],
      ['unknown provider type', body(n, port, { kind: 'nope' }), 400, 'invalid'],
      ['a cloud profile over plain http', body(n, port, { kind: 'openai-compatible', location: 'cloud' }), 400, 'invalid_base_url'],
      ['a cloud profile with no key', body(n, port, { location: 'cloud', base_url: 'https://llm.e2e.invalid/v1', api_key: undefined }), 400, 'key_required'],
    ]
    for (const [what, b, status, code] of cases) {
      const r = await api<Err>(c, 'POST', '/ai/profiles', b)
      expect(r.status, `${what}: ${JSON.stringify(r.body)}`).toBe(status)
      expect(r.body.error.code, what).toBe(code)
      expect(await profiles(c), `${what}: nothing was saved`).toEqual([])
    }
    expect((await audit(c, n)).filter((a) => a.action.startsWith('ai.profile')), 'a refusal leaves no audit row').toEqual([])
    const ok = await api<Profile>(c, 'POST', '/ai/profiles', body(n, port))
    expect(ok.status, JSON.stringify(ok.body)).toBe(200)
    const dup = await api<Err>(c, 'POST', '/ai/profiles', body(n, port))
    expect([dup.status, dup.body.error.code], 'a second profile with the same name').toEqual([400, 'duplicate_name'])
    expect(await profiles(c)).toHaveLength(1)
  } finally { await c.dispose() }
})

test('add a profile in the page, with the key shown once and never again; the connection test fails honestly; edit keeps the key; a new address needs it again (INV-1, INV-20)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  const port = await deadPort()
  const name = uniq('ai')
  try {
    await page.goto('/settings/ai')
    await page.getByRole('button', { name: 'Add AI profile' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add AI profile' })
    await dlg.getByLabel('Provider type').selectOption('openai-compatible')
    await dlg.getByLabel('Profile name').fill(name)
    await dlg.getByLabel('Server address').fill(`http://127.0.0.1:${port}/v1`)
    await dlg.getByLabel('Model', { exact: true }).fill('m-e2e')
    await dlg.getByRole('radio', { name: /Inside your network/ }).check()
    await dlg.getByLabel('API key').fill(KEY)
    await dlg.getByRole('button', { name: 'Test connection' }).click()
    await expect(dlg.getByRole('alert')).toHaveText(`Could not connect to 127.0.0.1:${port}. Check the address, the box's network and the firewall.`)
    await dlg.getByLabel('Daily token cap for this profile').fill('999')
    await dlg.getByRole('button', { name: 'Add profile' }).click()
    await expect(dlg.getByText('The cap must be a whole number from 1,000 to 5,000,000.')).toBeVisible()
    expect(await profiles(c), 'a refused form saved nothing').toEqual([])
    await dlg.getByLabel('Daily token cap for this profile').fill('5000')
    await dlg.getByLabel('API key').press('Enter')
    await expect(page.getByText('AI profile added').first()).toBeVisible()

    const [saved] = await profiles(c)
    expect(saved).toMatchObject({ name, kind: 'openai-compatible', location: 'internal', model: 'm-e2e', daily_cap: 5000, key_last4: LAST4, usable: true, used_today: 0 })
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText(`Key ends in ${LAST4}`)).toBeVisible()
    await page.reload()
    await expect(page.getByRole('region', { name: 'AI profiles' }).getByText(`Key ends in ${LAST4}`)).toBeVisible()
    expect(await page.content(), 'the key is never in the page').not.toContain(KEY.slice(0, -4))

    // the key is in no answer of the API and in no audit row
    for (const p of ['/ai/profiles', '/ai/config', '/ai/assignments', '/ai/usage', '/ai/runs', '/ai/activity', '/core/audit?q=ai']) expect(JSON.stringify((await api(c, 'GET', p)).body), p).not.toContain(KEY.slice(0, -4))
    const rows = await audit(c, name)
    expect(rows.map((a) => a.action).sort(), 'the add and the failed test of the dialog').toEqual(['ai.profile.add', 'ai.test'])
    expect(rows.find((a) => a.action === 'ai.profile.add')!.detail).toBe(`openai-compatible, internal, model=m-e2e, host=127.0.0.1:${port}, key set`)
    expect(rows.find((a) => a.action === 'ai.test')!.detail).toBe(`model=m-e2e, host=127.0.0.1:${port}, result=failed`)
    expect(JSON.stringify(await audit(c, 'ai.test'))).not.toContain(KEY.slice(0, -4))

    // edit: a blank key keeps the old one; the same address again is fine
    await page.getByRole('button', { name: `Edit ${name}` }).click()
    const ed = page.getByRole('dialog', { name: `Edit ${name}` })
    await expect(ed.getByLabel('API key')).toHaveValue('')
    await ed.getByLabel('Model', { exact: true }).fill('m-e2e-2')
    await ed.getByRole('button', { name: /^(Save|Save profile)$/ }).click()
    await expect(page.getByText('AI profile saved').first()).toBeVisible()
    expect((await profiles(c))[0]).toMatchObject({ model: 'm-e2e-2', key_last4: LAST4 })
    // another address with no key typed: the stored key is NOT carried to the new address (INV-1, M1). A profile inside the network needs no key, so the save
    // goes through without it; a cloud profile would be refused with key_required (tested above, with no key at all).
    const moved = await api<Profile>(c, 'PUT', `/ai/profiles/${saved!.id}`, { ...body(name, port, { base_url: 'http://127.0.0.1:1/v1', api_key: undefined, model: 'm-e2e-2' }), id: saved!.id })
    expect(moved.status, JSON.stringify(moved.body)).toBe(200)
    expect(moved.body, 'the key stayed behind with the old address').toMatchObject({ base_url: 'http://127.0.0.1:1/v1', key_last4: null })
    expect((await profiles(c))[0]).toMatchObject({ base_url: 'http://127.0.0.1:1/v1', key_last4: null })
    await page.reload() // a fresh page: the toast of the save above fades in (axe reads it mid-transition), this checks the page
    await expectAccessible(page, 'ai settings, one profile')
    noErrors(errors, /status of (502|400)/)
  } finally { await c.dispose() }
})

test('routing: the first profile is assigned to every task it may serve, the privacy rule refuses nothing it should allow, deleting names the tasks it clears (INV-2, INV-3, POST-4)', async ({ page }) => {
  const c = await as('admin')
  const port = await deadPort()
  try {
    const p = (await api<Profile>(c, 'POST', '/ai/profiles', body(uniq('ai'), port))).body
    const cfg = (await api<{ configured: boolean; jobs_ready: Record<string, boolean> }>(c, 'GET', '/ai/config')).body
    expect(cfg.configured).toBe(true)
    const asg = (await api<{ internal_only: boolean; jobs: Record<string, { primary: string | null; fallback: string | null }> }>(c, 'GET', '/ai/assignments')).body
    const assigned = JOBS.filter((j) => asg.jobs[j]!.primary === p.id)
    expect(assigned.length, 'the new profile took the tasks that had none').toBeGreaterThan(0)
    for (const j of JOBS) expect(cfg.jobs_ready[j], `${j} is ready exactly when it has a primary`).toBe(asg.jobs[j]!.primary !== null)
    // a primary that does not exist is refused and nothing changes
    const bad = await api<Err>(c, 'PUT', '/ai/assignments', { internal_only: false, jobs: { ...asg.jobs, 'ask-my-data': { primary: 'prof-does-not-exist', fallback: null } } })
    expect([bad.status, bad.body.error.code], JSON.stringify(bad.body)).toEqual([400, 'unknown_profile'])
    expect((await api(c, 'GET', '/ai/assignments')).body).toEqual(asg)
    // the page names the tasks the profile serves when it is removed, and the API clears exactly those
    await page.goto('/settings/ai')
    await page.getByRole('button', { name: new RegExp(`^Remove ${p.name}$`) }).click()
    const dlg = page.getByRole('dialog', { name: `Remove ${p.name}?` })
    await expect(dlg).toContainText('It is assigned to:')
    await page.keyboard.press('Escape')
    expect(await profiles(c), 'Escape removed nothing').toHaveLength(1)
    await page.getByRole('button', { name: new RegExp(`^Remove ${p.name}$`) }).click()
    await dlg.getByRole('button', { name: 'Remove profile' }).click()
    await expect(page.getByText(`${p.name} removed`).first()).toBeVisible()
    expect(await profiles(c)).toEqual([])
    const after = (await api<{ jobs: Record<string, { primary: string | null; fallback: string | null }> }>(c, 'GET', '/ai/assignments')).body.jobs
    for (const j of JOBS) expect(after[j], `${j} after the delete`).toEqual({ primary: null, fallback: null })
    expect((await audit(c, p.name)).map((a) => a.action).sort()).toEqual(['ai.profile.add', 'ai.profile.remove'])
  } finally { await c.dispose() }
})

test('the token level, the shared cap and the personal-data mask save, persist, and refuse values outside the limits (INV-4)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const port = await deadPort()
    await api(c, 'POST', '/ai/profiles', body(uniq('ai'), port))
    for (const [what, b] of [['cap 999', { tier: 'med', daily_cap: 999, redact_pii: true }], ['cap 5000001', { tier: 'med', daily_cap: 5_000_001, redact_pii: true }], ['tier huge', { tier: 'huge', daily_cap: 60000, redact_pii: true }]] as const) {
      const r = await api<Err>(c, 'PUT', '/ai/config', b)
      expect([r.status, r.body.error.code], what).toEqual([400, 'invalid'])
    }
    expect((await api<{ tier: string; daily_cap: number }>(c, 'GET', '/ai/config')).body).toMatchObject(tier)
    await page.goto('/settings/ai')
    await page.getByRole('radio', { name: /Minimum/ }).check()
    await page.getByLabel('Daily token cap for all profiles together').fill('999')
    await page.getByLabel('Daily token cap for all profiles together').press('Enter')
    await expect(page.getByText('The cap must be a whole number from 1,000 to 5,000,000.')).toBeVisible()
    expect((await api(c, 'GET', '/ai/config')).body, 'the refused form saved nothing').toMatchObject(tier)
    await page.getByLabel('Daily token cap for all profiles together').fill('12000')
    await page.getByLabel('Daily token cap for all profiles together').press('Enter')
    await expect(page.getByText('Token level saved').first()).toBeVisible()
    expect((await api(c, 'GET', '/ai/config')).body).toMatchObject({ tier: 'min', daily_cap: 12000 })
    expect((await api(c, 'GET', '/ai/usage')).body).toMatchObject({ tier: 'min', daily_cap: 12000 })
    await page.reload()
    await expect(page.getByLabel('Daily token cap for all profiles together')).toHaveValue('12000')
    // the activity log retention is a form of its own on the same page (INV-19)
    await page.getByLabel('Keep for (days)').fill('30')
    await page.getByLabel('Keep for (days)').press('Enter')
    await expect(page.getByText('Enter a whole number of days, at least 90.')).toBeVisible()
    expect((await api<{ retention_days: number }>(c, 'GET', '/ai/activity/settings')).body.retention_days, 'a refused value saved nothing').toBe(retention)
    await page.getByLabel('Keep for (days)').fill('120')
    await page.getByLabel('Keep for (days)').press('Enter')
    await expect.poll(async () => (await api<{ retention_days: number }>(c, 'GET', '/ai/activity/settings')).body.retention_days).toBe(120)
    noErrors(errors, /status of 400/)
  } finally { await c.dispose() }
})

test('a failed call is in the activity log with hashes and no content, the chain verifies and links, entries cannot be edited or deleted, retention is at least 90 days (INV-17..19, S-AI-8)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const port = await deadPort()
    const p = (await api<Profile>(c, 'POST', '/ai/profiles', body(uniq('ai'), port))).body
    const before = await activity(c)
    // the profile answers nothing (no listener): the call fails, and that is one entry
    const r = await api<Err>(c, 'POST', `/ai/cve/${CVE}/explain`)
    expect([r.status, r.body.error.code]).toEqual([409, 'ai_unavailable'])
    expect(r.body.error.message).toContain(`${p.name}: provider is unreachable`)
    const after = await activity(c)
    expect(after.total, 'exactly one entry for one call').toBe(before.total + 1)
    const e = after.items[0]!
    expect(e).toMatchObject({ job: 'explain-finding', result: 'error', tokens_in: 0, tokens_out: 0, hooks: [], tools: [], trigger: 'user:admin@e2e.test' })
    expect(e.summary).toBe(`No profile answered: ${p.name}: provider is unreachable`)
    expect(e.input_hash).toMatch(/^[0-9a-f]{64}$/)
    expect(e.output_hash, 'nothing came back: the hash of the empty text').toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    expect(JSON.stringify(after), 'the activity log holds no content and no key').not.toMatch(new RegExp(`${CVE}|${KEY.slice(0, -4)}`))
    // every entry links to the one before it, oldest first; the oldest starts the chain
    const chain = [...after.items].reverse()
    for (let i = 1; i < chain.length; i++) expect(chain[i]!.prev_hash, `entry ${chain[i]!.id} links to the one before`).toBe(chain[i - 1]!.hash)
    expect(chain[0]!.prev_hash).toMatch(/^0{64}$/)
    expect((await api(c, 'GET', '/ai/activity/verify')).body).toMatchObject({ ok: true, broken_at: null, count: after.total })
    // no endpoint edits or deletes an entry
    for (const method of ['PUT', 'PATCH', 'DELETE'] as const) {
      const x = await api(c, method, `/ai/activity/${e.id}`, method === 'DELETE' ? undefined : { summary: 'edited' })
      expect([404, 405], `${method} /ai/activity/{id}`).toContain(x.status)
    }
    expect((await activity(c)).items[0]).toEqual(e)
    // retention: at least 90 days, at most 3650
    for (const days of [0, 89, 3651, -1]) expect((await api<Err>(c, 'PUT', '/ai/activity/settings', { retention_days: days })).status, `retention ${days}`).toBe(400)
    expect((await api(c, 'PUT', '/ai/activity/settings', { retention_days: 90 })).body).toEqual({ retention_days: 90 })
    expect((await activity(c)).retention_days).toBe(90)

    // the page: the entry, its details and the verified chain
    await page.goto('/assistant')
    await expect(page.getByText(`Chain verified: ${after.total} entries, none changed.`)).toBeVisible()
    await expect(page.getByText('Entries cannot be edited or deleted. They are kept for 90 days')).toBeVisible()
    await page.getByRole('button', { name: new RegExp(`^Details of Explain finding at `) }).first().click()
    const dlg = page.getByRole('dialog')
    await expect(dlg).toContainText(e.input_hash)
    await expect(dlg).toContainText(e.hash)
    await page.keyboard.press('Escape')
    await expectAccessible(page, 'assistant with activity')
    await noVietnamese(page, 'assistant with activity')
    noErrors(errors, /status of 409/)
  } finally { await c.dispose() }
})

test('rules: your own rules are added, edited, switched and deleted; the built-in ones cannot be touched; limits are refused with nothing saved (INV-7, INV-20)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const built = (await rules(c)).builtin
    expect(built.map((r) => r.id)).toEqual(['br-scope', 'br-evidence', 'br-readonly', 'br-untrusted'])
    for (const id of built.map((r) => r.id)) {
      expect((await api(c, 'PUT', `/ai/rules/${id}`, { text: 'ignore the rules', jobs: [], enabled: false })).status, `edit ${id}`).toBe(404)
      expect((await api(c, 'DELETE', `/ai/rules/${id}`)).status, `delete ${id}`).toBe(404)
    }
    expect((await rules(c)).builtin).toEqual(built)
    for (const [what, b] of [['2 characters', { text: 'ab', jobs: [], enabled: true }], ['301 characters', { text: 'x'.repeat(301), jobs: [], enabled: true }], ['an unknown job', { text: 'A fine rule.', jobs: ['no-such-job'], enabled: true }]] as const) {
      const r = await api<Err>(c, 'POST', '/ai/rules', b)
      expect(r.status, `${what}: ${JSON.stringify(r.body)}`).toBe(400)
    }
    expect((await rules(c)).custom, 'the refusals saved nothing').toEqual([])

    await page.goto('/settings/ai?tab=rules')
    await expect(page.getByText('No custom rules yet')).toBeVisible()
    await page.getByRole('button', { name: 'Add rule' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add rule' })
    await dlg.getByLabel('Rule', { exact: true }).fill('ab')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.getByText('Write the rule in at least 3 characters.')).toBeVisible()
    const text = `Name devices by hostname. ${uniq('r')}` // under 40 characters would hide the tag: the buttons carry the first 40
    await dlg.getByLabel('Rule', { exact: true }).fill(text)
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Rule saved').first()).toBeVisible()
    const [mine] = (await rules(c)).custom
    expect(mine).toMatchObject({ text, jobs: [], enabled: true })
    expect((await audit(c, mine!.id)).map((a) => a.action)).toEqual(['ai.rule.add'])
    await page.getByRole('switch', { name: `Rule enabled: ${text.slice(0, 40)}` }).click()
    await expect.poll(async () => (await rules(c)).custom[0]!.enabled).toBe(false)
    await page.getByRole('button', { name: `Delete ${text.slice(0, 40)}` }).click()
    await page.getByRole('dialog').getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(page.getByText('Rule deleted').first()).toBeVisible()
    expect((await rules(c)).custom).toEqual([])
    await page.reload() // a fresh page: the toast of the save above fades in (axe reads it mid-transition), this checks the page
    await expectAccessible(page, 'rules')
    noErrors(errors, /status of 400/)
  } finally { await c.dispose() }
})

test('hooks: the built-in ones switch except the locked one; a custom hook blocks, masks or holds; the sample box shows what would happen (INV-12, INV-13)', async ({ page }) => {
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const h = await hooks(c)
    expect(h.builtin.map((x) => [x.id, x.locked])).toEqual([['block-pii', false], ['security-only', false], ['write-approval', true]])
    const locked = await api<Err>(c, 'PUT', '/ai/hooks/builtin/write-approval', { enabled: false })
    expect([locked.status, locked.body.error.code], 'the write-approval hook cannot be turned off (SYS-8)').toEqual([400, 'locked'])
    expect((await hooks(c)).builtin.find((x) => x.id === 'write-approval')!.enabled).toBe(true)
    expect((await api(c, 'PUT', '/ai/hooks/builtin/nope', { enabled: false })).status).toBe(404)
    // what the built-in personal-data hook does with a sample, through the API the page uses
    const mask = await api<{ outcome: string; output: string; hits: { id: string }[] }>(c, 'POST', '/ai/hooks/test', { text: 'call me on 0912345678 or an.nguyen@example.com', when: 'before_ai' })
    expect(mask.body).toMatchObject({ outcome: 'masked', output: 'call me on [masked] or [masked]' })
    const blocked = await api<{ outcome: string; output: string }>(c, 'POST', '/ai/hooks/test', { text: 'my id number is 012345678901', when: 'before_ai' })
    expect(blocked.body).toMatchObject({ outcome: 'blocked', output: 'The text contains an ID number. It was not sent to the AI. Remove the number and ask again.' })
    expect((await api(c, 'PUT', '/ai/hooks/builtin/block-pii', { enabled: false })).body).toMatchObject({ enabled: false })
    expect((await api<{ outcome: string }>(c, 'POST', '/ai/hooks/test', { text: 'call me on 0912345678', when: 'before_ai' })).body.outcome, 'switched off, the hook does nothing').toBe('pass')
    expect((await api(c, 'PUT', '/ai/hooks/builtin/block-pii', { enabled: true })).body).toMatchObject({ enabled: true })

    await page.goto('/settings/ai?tab=hooks')
    await expect(page.getByText('Always on').first()).toBeVisible()
    await expect(page.getByRole('switch', { name: 'Hook enabled: Write tools need approval' })).toBeDisabled()
    await page.getByRole('button', { name: 'Add hook' }).first().click()
    const dlg = page.getByRole('dialog', { name: 'Add hook' })
    const name = uniq('hk')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(dlg.getByText('Give the hook a name.')).toBeVisible()
    await dlg.getByLabel('Name', { exact: true }).fill(name)
    await dlg.getByLabel('Keywords').fill('project falcon, salary')
    await dlg.getByLabel('Message shown to the user').fill('A project code name must not leave the network.')
    await dlg.getByRole('button', { name: 'Save' }).click()
    await expect(page.getByText('Hook saved').first()).toBeVisible()
    expect((await hooks(c)).custom.map((x) => x.name)).toEqual([name])
    const hit = await api<{ outcome: string; output: string; hits: { name: string }[] }>(c, 'POST', '/ai/hooks/test', { text: 'what is the salary of the admin', when: 'before_ai' })
    expect(hit.body.outcome).toBe('blocked')
    expect(hit.body.output).toBe('A project code name must not leave the network.')
    expect((await api<{ outcome: string }>(c, 'POST', '/ai/hooks/test', { text: 'what is the salary of the admin', when: 'after_ai' })).body.outcome, 'a before_ai hook does not run after the answer').toBe('pass')
    for (const [what, b] of [['empty pattern', { name: 'x', when: 'before_ai', match: { type: 'keywords', pattern: '' }, action: 'block', message: 'No.', enabled: true }], ['a regex that does not compile', { name: 'x', when: 'before_ai', match: { type: 'regex', pattern: '(' }, action: 'block', message: 'Not allowed.', enabled: true }]] as const) {
      const r = await api<Err>(c, 'POST', '/ai/hooks', b)
      expect(r.status, `${what}: ${JSON.stringify(r.body)}`).toBe(400)
    }
    expect((await hooks(c)).custom, 'the refusals saved nothing').toHaveLength(1)
    expect((await audit(c, name)).map((a) => a.action)).toEqual(['ai.hook.add'])
    await page.reload() // a fresh page: the toast of the save above fades in (axe reads it mid-transition), this checks the page
    await expectAccessible(page, 'hooks')
    noErrors(errors, /status of 400/)
  } finally { await c.dispose() }
})

test('roles: a viewer reads, an operator reads the activity log, only an administrator changes anything or reads rules, hooks and settings (INV-20)', async () => {
  const admin = await as('admin')
  try {
    const port = await deadPort()
    const p = (await api<Profile>(admin, 'POST', '/ai/profiles', body(uniq('ai'), port))).body
    const state = async () => ({ profiles: await profiles(admin), config: (await api(admin, 'GET', '/ai/config')).body, assignments: (await api(admin, 'GET', '/ai/assignments')).body, retention: (await api(admin, 'GET', '/ai/activity/settings')).body, rules: await rules(admin), hooks: await hooks(admin) })
    const before = await state()
    for (const role of ['viewer', 'operator'] as const) {
      const c = await as(role)
      try {
        for (const path of ['/ai/config', '/ai/profiles', '/ai/assignments', '/ai/usage', '/ai/runs']) expect((await api(c, 'GET', path)).status, `${role}: GET ${path}`).toBe(200)
        expect((await api(c, 'GET', '/ai/activity')).status, `${role}: the activity log`).toBe(role === 'viewer' ? 403 : 200)
        for (const [method, path, b] of [
          ['POST', '/ai/profiles', body(uniq('ai'), port)], ['PUT', `/ai/profiles/${p.id}`, { ...body(p.name, port), id: p.id }], ['DELETE', `/ai/profiles/${p.id}`, undefined],
          ['PUT', '/ai/config', { tier: 'min', daily_cap: 2000, redact_pii: false }], ['PUT', '/ai/activity/settings', { retention_days: 90 }],
          ['GET', '/ai/rules', undefined], ['POST', '/ai/rules', { text: 'A rule.', jobs: [], enabled: true }], ['GET', '/ai/hooks', undefined], ['PUT', '/ai/hooks/builtin/block-pii', { enabled: false }],
          ['POST', '/ai/profiles/test', { kind: 'openai-compatible', api_style: 'openai', base_url: `http://127.0.0.1:${port}/v1`, model: 'm', location: 'internal' }],
        ] as const) {
          const r = await api<Err>(c, method, path, b)
          expect([r.status, r.body.error?.code], `${role}: ${method} ${path}`).toEqual([403, 'forbidden'])
        }
        const ex = await api<Err>(c, 'POST', `/ai/cve/${CVE}/explain`)
        expect([ex.status, ex.body.error.code], `${role}: explain`).toEqual(role === 'viewer' ? [403, 'forbidden'] : [409, 'ai_unavailable'])
      } finally { await c.dispose() }
      expect(await state(), `${role}: nothing changed`).toEqual(before)
    }
  } finally { await admin.dispose() }
})


// ---- the success paths, with the stand-in model of fake-ai.ts on loopback ----

/** Today's tokens on the meter. */
const usedToday = async (c: APIRequestContext) => (await api<{ today: { total: number } }>(c, 'GET', '/ai/usage')).body.today.total
/** A company rule for some jobs: the rules are part of the inputs of a cached result, so a rule of this run's own makes its result new on any box. */
async function rule(c: APIRequestContext, jobs: string[]): Promise<string> {
  const text = `Name devices by hostname, run ${uniq('r')}.`
  expect((await api(c, 'POST', '/ai/rules', { text, jobs, enabled: true })).status).toBe(200)
  return text
}
/** A .docx is a zip holding word/document.xml, the one part the box reads (INV-10): one stored entry. */
function docx(text: string): Buffer {
  const name = Buffer.from('word/document.xml')
  const data = Buffer.from(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>${text}</w:t></w:r></w:p></w:body></w:document>`)
  const crc = crc32(data)
  const local = Buffer.alloc(30)
  local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26)
  const central = Buffer.alloc(46)
  central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28)
  const end = Buffer.alloc(22)
  end.writeUInt16LE(1, 8); end.writeUInt16LE(1, 10); end.writeUInt32LE(0x06054b50, 0); end.writeUInt32LE(central.length + name.length, 12); end.writeUInt32LE(local.length + name.length + data.length, 16)
  return Buffer.concat([local, name, data, central, name, end])
}

test('an answer from a model: the primary fails, the fallback explains with the box\'s sources, the second press comes from the cache with no call (S-AI-2, INV-2, INV-6)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const f = await fake()
    const primary = (await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base, model: FAIL })).body
    const fallback = (await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base })).body
    const ruleText = await rule(c, ['explain-finding'])
    const asg = (await api<{ internal_only: boolean; jobs: Record<string, { primary: string | null; fallback: string | null }> }>(c, 'GET', '/ai/assignments')).body
    expect((await api(c, 'PUT', '/ai/assignments', { ...asg, jobs: { ...asg.jobs, 'explain-finding': { primary: primary.id, fallback: fallback.id } } })).status).toBe(200)
    const before = { activity: (await activity(c)).total, tokens: await usedToday(c) }

    const r = await api<{ cached: boolean; why: string; patch_steps: string[]; citations: { title: string }[]; model: string; profile: string; tokens: { input: number; output: number } }>(c, 'POST', `/ai/cve/${CVE}/explain`)
    expect(r.status, JSON.stringify(r.body)).toBe(200)
    expect(r.body).toMatchObject({ cached: false, why: SAY.why, model: 'm-e2e', profile: fallback.name, tokens: { input: 120, output: 40 } })
    expect(r.body.citations.length, 'the box names its sources; the model never supplies a link').toBeGreaterThan(0)
    expect(f.calls.map((x) => [x.model, x.schema]), 'the primary was asked first, then the fallback').toEqual([[FAIL, 'explain_cve'], ['m-e2e', 'explain_cve']])
    for (const x of f.calls) {
      expect(x.auth, 'the key went only where it was saved for').toBe(`Bearer ${KEY}`)
      expect(x.text, 'the CVE and the company rule go with the call').toContain(CVE)
      expect(x.text).toContain(ruleText)
    }
    const e = (await activity(c)).items[0]!
    expect(e).toMatchObject({ job: 'explain-finding', result: 'fallback_used', tokens_in: 120, tokens_out: 40 })
    expect(e.summary).toContain('(answered by the fallback profile)')
    expect((await activity(c)).total, 'one call, one entry').toBe(before.activity + 1)
    expect(await usedToday(c), 'the meter counts the tokens of the answer').toBe(before.tokens + 160)

    // the same inputs: the stored explanation, no call, no tokens (INV-6)
    const again = await api<{ cached: boolean; why: string; profile: string }>(c, 'POST', `/ai/cve/${CVE}/explain`)
    expect(again.body).toMatchObject({ cached: true, why: SAY.why, profile: fallback.name })
    expect(f.calls, 'no second call').toHaveLength(2)
    expect((await api<{ explain: { why: string; cached: boolean } | null }>(c, 'GET', `/ai/cve/${CVE}/cached`)).body.explain).toMatchObject({ why: SAY.why, cached: true })
    expect((await activity(c)).total).toBe(before.activity + 1)
    expect(await usedToday(c)).toBe(before.tokens + 160)

    await page.goto(`/cve/${CVE}`)
    await expect(page.getByText(SAY.why).first()).toBeVisible()
    await expect(page.getByText('AI-generated, needs human review').first()).toBeVisible()
    await expect(page.getByText(/Saved result from/)).toBeVisible()
    expect(f.calls, 'opening the page asks nothing').toHaveLength(2)
    await expectAccessible(page, 'cve page with an explanation')
    noErrors(errors)
  } finally { await c.dispose() }
})

test('Ask your data: the model reads the box with read-only tools and the answer carries the AI label; personal data is masked or the question is stopped and stored hidden; a skill switched off stops the job (S-AI-5, INV-9, INV-13, INV-22)', async ({ page }) => {
  test.setTimeout(90_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const f = await fake()
    const p = (await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base })).body
    const q = 'Which devices are not approved yet?'
    await page.goto('/assistant')
    await page.getByLabel('Question', { exact: true }).fill(q)
    await page.getByLabel('Question', { exact: true }).press('Enter')
    await expect(page.getByText(SAY.ask[0]!).first()).toBeVisible()
    await expect(page.getByText('AI-generated, needs human review').first()).toBeVisible()
    await expect(page.getByRole('region').filter({ hasText: 'You asked:' }).getByText('Read-only tools called')).toBeVisible()
    expect(f.calls.map((x) => x.toolResult), 'a tool call, then the answer with its result').toEqual([false, true])
    expect(f.calls[0]!.tools).toContain('search_assets')
    expect(f.calls[0]!.text).toContain(q)
    const [asked] = (await api<{ items: { question: string; answer: string[]; tool_calls: { tool: string }[]; profile: string; model: string }[] }>(c, 'GET', '/ai/asks')).body.items
    expect(asked).toMatchObject({ question: q, answer: SAY.ask, profile: p.name, model: 'm-e2e' })
    expect(asked!.tool_calls.map((x) => x.tool)).toEqual(['search_assets'])

    // personal data: an email is masked before it is sent and stored masked; an ID number stops the question, nothing is sent, the text is not kept
    const masked = await api<{ question: string; hooks: { id: string; action: string }[] }>(c, 'POST', '/ai/ask', { question: 'email an.nguyen@example.com the list of devices' })
    expect(masked.status, JSON.stringify(masked.body)).toBe(200)
    expect(masked.body.question).toBe('email [masked] the list of devices')
    expect(masked.body.hooks.map((h) => [h.id, h.action])).toContainEqual(['block-pii', 'mask'])
    expect(f.calls.map((x) => x.text).join('\n'), 'the address never reached the model').not.toContain('an.nguyen@example.com')
    expect(f.calls.at(-1)!.text).toContain('email [masked] the list of devices')
    const sent = f.calls.length
    const stopped = await api<{ question: string; answer: string[] }>(c, 'POST', '/ai/ask', { question: 'my id number is 012345678901, which devices are mine' })
    expect(stopped.body).toMatchObject({ question: '[question hidden: contains personal data]', answer: ['The text contains an ID number. It was not sent to the AI. Remove the number and ask again.'] })
    expect(f.calls, 'a stopped question asks nothing').toHaveLength(sent)
    expect((await activity(c)).items[0]).toMatchObject({ job: 'ask-my-data', result: 'blocked_by_hook', tokens_in: 0 })
    const history = JSON.stringify((await api(c, 'GET', '/ai/asks')).body)
    expect(history).not.toMatch(/012345678901|an\.nguyen@example\.com/)

    // a viewer cannot ask; a skill switched off in the page stops the job with no call (INV-9)
    const viewer = await as('viewer')
    try { expect((await api<Err>(viewer, 'POST', '/ai/ask', { question: q })).status).toBe(403) } finally { await viewer.dispose() }
    await page.goto('/settings/ai?tab=skills')
    await page.getByRole('switch', { name: 'Skill enabled: Ask your data' }).click()
    await expect.poll(async () => (await skills(c)).find((s) => s.id === 'ask-my-data')!.enabled).toBe(false)
    const off = await api<Err>(c, 'POST', '/ai/ask', { question: q })
    expect([off.status, off.body.error.code, off.body.error.message]).toEqual([409, 'ai_unavailable', 'The skill "Ask your data" is turned off. An administrator turns it on in Settings, AI assistant, Skills.'])
    expect(f.calls).toHaveLength(sent)
    expect((await audit(c, 'ask-my-data')).map((a) => a.action)).toContain('ai.skill')
    await page.reload()
    await expectAccessible(page, 'skills')
    noErrors(errors, /status of 409/)
  } finally { await c.dispose() }
})

test('the log digest: no log line means no call and no tokens; with lines the AI summarises them once and the same inputs come from the store (S-AI-4, POST-3, INV-6b)', async () => {
  test.setTimeout(90_000)
  const c = await as('admin')
  try {
    const f = await fake()
    const p = (await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base })).body
    await rule(c, ['log-digest', 'log-investigate'])
    type Digest = { digest: { empty: boolean; summary: string; profile: string; tokens: { input: number; output: number } } }
    const before = (await activity(c)).total
    // the logs specs run after this file (alphabetical order of the global project): a fresh box has no line yet
    if ((await api<{ lines_24h: number }>(c, 'GET', '/logs/digest')).body.lines_24h === 0) {
      const none = await api<Digest>(c, 'POST', '/ai/logs/digest')
      expect(none.status, JSON.stringify(none.body)).toBe(200)
      expect(none.body.digest).toMatchObject({ empty: true, profile: '', tokens: { input: 0, output: 0 } })
      expect(f.calls, 'no line, no call').toEqual([])
      expect((await activity(c)).total, 'and no activity entry').toBe(before)
    }
    const src = await api<{ id: string }>(c, 'POST', '/logs/sources', { kind: 'syslog-generic', sender_ip: '127.0.0.1', proto: 'udp', port: 514, name: uniq('lg') })
    expect(src.status, JSON.stringify(src.body)).toBe(201)
    logSources.push(src.body.id)
    const tok = uniq('tok')
    const send = () => new Promise<void>((ok, bad) => { const s = createSocket('udp4'); s.send(`<34>Nov 11 12:34:56 gw app[1]: ${tok} service started`, Number(box().syslog_port), '127.0.0.1', (e) => { s.close(); if (e) bad(e); else ok() }) })
    await expect.poll(async () => { await send(); return (await api<{ total: number }>(c, 'GET', `/logs/events?window=24h&source=${src.body.id}&q=${tok}`)).body.total }, { message: 'a line is stored (the listener opens its socket after the source is saved)', timeout: 30_000 }).toBeGreaterThan(0)

    const made = await api<Digest>(c, 'POST', '/ai/logs/digest')
    expect(made.status, JSON.stringify(made.body)).toBe(200)
    expect(made.body.digest).toMatchObject({ empty: false, summary: SAY.digest, profile: p.name, tokens: { input: 120, output: 40 } })
    expect(f.calls.at(-1)!.schema).toBe('log_digest')
    expect(f.calls.at(-1)!.text).toContain('Lines received')
    const calls = f.calls.length
    expect((await api<Digest>(c, 'GET', '/ai/logs/digest')).body.digest, 'the stored digest is read with no call').toMatchObject({ summary: SAY.digest, profile: p.name })
    expect((await api<Digest>(c, 'POST', '/ai/logs/digest')).body.digest).toMatchObject({ summary: SAY.digest })
    expect(f.calls, 'the same inputs are not asked again').toHaveLength(calls)
    expect((await activity(c)).items[0]).toMatchObject({ result: 'ok', tokens_in: 120 })
  } finally { await c.dispose() }
})

test('CVE news: a CVE the box has no entry for, a malformed ID and a switched-off skill are refused before anything is fetched or asked (S-AI-3, INV-6, INV-9)', async () => {
  const c = await as('admin')
  try {
    const f = await fake()
    await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base })
    const before = (await activity(c)).total
    const unknown = await api<Err>(c, 'POST', '/ai/cve/CVE-2099-0001/news')
    expect([unknown.status, unknown.body.error.code]).toEqual([404, 'unknown_cve'])
    const bad = await api<Err>(c, 'POST', '/ai/cve/not-a-cve/news')
    expect(bad.status).toBe(400)
    expect((await api(c, 'PUT', '/ai/skills/cve-news', { enabled: false })).status).toBe(200)
    const off = await api<Err>(c, 'POST', `/ai/cve/${CVE}/news`)
    expect([off.status, off.body.error.code, off.body.error.message]).toEqual([409, 'ai_unavailable', 'The skill "CVE news" is turned off. An administrator turns it on in Settings, AI assistant, Skills.'])
    expect(f.calls, 'nothing was asked').toEqual([])
    expect((await activity(c)).total, 'and nothing logged').toBe(before)
    expect((await api<{ news: unknown }>(c, 'GET', `/ai/cve/${CVE}/cached`)).body.news, 'no news stored').toBeNull()
    const viewer = await as('viewer')
    try { expect((await api<Err>(viewer, 'POST', `/ai/cve/${CVE}/news`)).status).toBe(403) } finally { await viewer.dispose() }
  } finally { await c.dispose() }
})
// The box fetches NVD, GitHub, the vendor page and six blogs from the Internet: the e2e box has no seam to serve them on loopback, and this run must send
// nothing out. D-426 accepts it under D-171 (2); TestContract_S_AI_3_TheBoxFetchesAndTheAISummarises carries the flow with a fake transport.
test.fixme('CVE news: the box fetches the sources, the AI only summarises them, the second press spends no tokens (S-AI-3, INV-6; needs a news-source seam in the e2e box, D-426)', async () => {
  const c = await as('admin')
  const r = await api<{ lines: unknown[]; sources: unknown[] }>(c, 'POST', `/ai/cve/${CVE}/news`)
  expect(r.status).toBe(200)
  expect((await api<{ news: unknown }>(c, 'GET', `/ai/cve/${CVE}/cached`)).body.news).not.toBeNull()
  await c.dispose()
})

test('memory, skills and the knowledge base: a memory is added, edited, switched and deleted; a suggestion reaches no prompt until it is accepted; a document is indexed and its passage goes with the call (S-AI-7, INV-8..10, INV-22b)', async ({ page }) => {
  test.setTimeout(120_000)
  const errors = collectErrors(page)
  const c = await as('admin')
  try {
    const f = await fake()
    const p = (await api<Profile>(c, 'POST', '/ai/profiles', { ...body(uniq('ai'), 0), base_url: f.base })).body
    const ask = async (question: string) => {
      const r = await api<{ memories_suggested: number }>(c, 'POST', '/ai/ask', { question })
      expect(r.status, JSON.stringify(r.body)).toBe(200)
      return r.body
    }
    const sentLast = () => f.calls.at(-1)!.text // the call that carries the tool result also carries the memory and the passages

    // memory by hand: refused when too short, then added, edited, used in the next call
    expect((await api<Err>(c, 'POST', '/ai/memory', { text: 'ab' })).status).toBe(400)
    const hand = (await api<{ id: string; source: string; enabled: boolean }>(c, 'POST', '/ai/memory', { text: `GW-${uniq('m')} is the office gateway.` })).body
    expect(hand).toMatchObject({ source: 'user', enabled: true })
    const handText = `GW-${uniq('m')} is the gateway of the main office.`
    expect((await api(c, 'PUT', `/ai/memory/${hand.id}`, { text: handText })).body).toMatchObject({ text: handText })

    // a suggestion: the model ends its answer with "Remember:" only while suggestions are on, and only after a tool call (INV-22b)
    expect((await api<Memory>(c, 'PUT', '/ai/memory/settings', { suggest_enabled: true })).body.suggest_enabled).toBe(true)
    const tag = uniq('nas')
    const fact = `${tag} is the NAS that makes the nightly backup.`
    f.remember = fact
    expect((await ask('Which device makes the nightly backup?')).memories_suggested).toBe(1)
    expect(sentLast(), 'an enabled memory goes with the call').toContain(handText)
    let mem = await memory(c)
    expect(mem.suggestions.map((s) => s.text)).toEqual([fact])
    expect(mem.suggestions[0]!.evidence).toContain('From the question "Which device makes the nightly backup?"')
    expect(mem.items.map((m) => m.text)).toEqual([handText])
    f.remember = `${uniq('nas')} keeps the camera recordings.`
    expect((await ask('Which device keeps the recordings?')).memories_suggested).toBe(1)
    expect(sentLast(), 'a waiting suggestion reaches no prompt (INV-8)').not.toContain(tag)
    mem = await memory(c)
    const second = mem.suggestions.find((s) => s.text !== fact)!
    expect((await api(c, 'POST', `/ai/memory/suggestions/${second.id}/reject`)).status).toBe(204)
    f.remember = null

    // accept in the page; the accepted fact goes with the next call, a switched-off memory does not
    await page.goto('/settings/ai?tab=memory')
    await page.getByRole('button', { name: `Accept memory: ${fact.slice(0, 40)}` }).click()
    await expect(page.getByText('Memory added').first()).toBeVisible()
    mem = await memory(c)
    expect(mem.suggestions).toEqual([])
    expect(mem.items.find((m) => m.text === fact)).toMatchObject({ source: 'ai', enabled: true })
    expect((await api(c, 'PUT', `/ai/memory/${hand.id}`, { enabled: false })).body).toMatchObject({ enabled: false })
    await ask('Which device makes the nightly backup?')
    expect(sentLast()).toContain(fact)
    expect(sentLast(), 'a memory switched off stays out').not.toContain(handText)
    expect((await memory(c)).items.find((m) => m.text === fact)!.last_used_at, 'the box notes when a memory was used').not.toBeNull()
    for (const m of (await memory(c)).items) expect((await api(c, 'DELETE', `/ai/memory/${m.id}`)).status).toBe(204)
    expect((await memory(c)).items).toEqual([])
    expect((await audit(c, 'ai.memory')).map((a) => a.action)).toEqual(expect.arrayContaining(['ai.memory.add', 'ai.memory.accept', 'ai.memory.reject', 'ai.memory.remove']))

    // skills: the list is the product's, an unknown one is 404
    expect((await skills(c)).map((s) => s.id)).toEqual(['explain-finding', 'cve-news', 'log-digest', 'log-investigate', 'mitigation-config', 'fingerprint-fallback', 'translate-advisory', 'weekly-report', 'pdpl-assessment', 'ask-my-data', 'response-plan'])
    expect((await api<Err>(c, 'PUT', '/ai/skills/no-such-skill', { enabled: false })).status).toBe(404)

    // knowledge: a profile for the index first; a Markdown file and a Word file are indexed on the box; the passage that matches goes with the call
    const md = Buffer.from(`# Backups\n\nThe nightly backup of the office runs on ${tag} at two in the morning.\n`)
    const add = (name: string, bytes: Buffer, jobs?: string[]) => api<Doc & Err>(c, 'POST', '/ai/knowledge', { name, size: bytes.length, content: bytes.toString('base64'), ...(jobs ? { jobs } : {}) })
    const refused = await add('runbook.md', md)
    expect([refused.status, refused.body.error.code]).toEqual([400, 'no_index_profile'])
    expect((await api(c, 'PUT', '/ai/knowledge/settings', { index_profile: p.id })).body).toMatchObject({ index_profile: p.id })
    expect((await add('tool.exe', md)).body.error.code).toBe('invalid_type')
    const a = await add('runbook.md', md)
    expect(a.status, JSON.stringify(a.body)).toBe(200)
    expect(a.body).toMatchObject({ name: 'runbook.md', size: md.length, jobs: ['explain-finding', 'ask-my-data'] })
    const w = await add('cameras.docx', docx(`The camera recorder ${tag}-nvr keeps thirty days of video.`), ['ask-my-data'])
    expect(w.status, JSON.stringify(w.body)).toBe(200)
    await expect.poll(async () => (await docs(c)).items.map((d) => [d.name, d.status, (d.chunks ?? 0) > 0]).sort(), { message: 'both are indexed', timeout: 30_000 })
      .toEqual([['cameras.docx', 'ready', true], ['runbook.md', 'ready', true]])
    await ask('Where does the nightly backup of the office run?')
    expect(sentLast(), 'the passage of the runbook went with the call').toContain(`The nightly backup of the office runs on ${tag}`)
    await ask('How many days of video does the camera recorder keep?')
    expect(sentLast(), 'the text of the Word file went with the call').toContain(`${tag}-nvr keeps thirty days of video`)
    expect((await api(c, 'PUT', `/ai/knowledge/${a.body.id}`, { jobs: ['explain-finding'] })).body).toMatchObject({ jobs: ['explain-finding'] })
    await ask('Where does the nightly backup of the office run?')
    expect(sentLast(), 'a document not assigned to the job stays out').not.toContain(`runs on ${tag}`)
    await page.goto('/settings/ai?tab=knowledge')
    await expect(page.getByText('runbook.md')).toBeVisible()
    await expect(page.getByText('cameras.docx')).toBeVisible()
    await expectAccessible(page, 'knowledge')
    for (const d of (await docs(c)).items) expect((await api(c, 'DELETE', `/ai/knowledge/${d.id}`)).status).toBe(204)
    expect((await docs(c)).items).toEqual([])
    expect((await audit(c, 'ai.knowledge')).map((x) => x.action)).toEqual(expect.arrayContaining(['ai.knowledge.add', 'ai.knowledge.indexed', 'ai.knowledge.jobs', 'ai.knowledge.remove']))
    noErrors(errors)
  } finally { await c.dispose() }
})
