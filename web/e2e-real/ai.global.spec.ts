// The ai module on the real backend, with NO provider key and no internet (S-AI-1, S-AI-4, S-AI-7, S-AI-8; ai INV-1, INV-3, INV-4, INV-7, INV-12, INV-17..20, POST-5).
// Nothing here configures a real provider: PRIVACY flow 3 lists what an AI call sends, and the box must not send anything out. The one profile the specs create is
// "inside your network" at a loopback port nobody listens on (kind OpenAI-compatible, a made-up key), so a call to it fails at once on this machine and the failure is
// what is checked: the activity log records it (INV-17), the hash chain verifies (INV-18), and the key shows only its last 4 characters everywhere (INV-1, SYS-4).
// Hooks, rules, the token level, retention and the profile forms are real and need no provider. Global project: all of it is box-wide, and every test puts it back.
// Built-but-not-testable-without-a-provider is test.fixme (D-171 (2)): an answer from a model, "Ask your data" (POST /ai/ask answers 501), CVE news and the log digest
// (501), memory, skills and knowledge (501).
import { createServer, type Server } from 'node:net'
import { expect, request, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, box, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors } from '../e2e/helpers'

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

let tier: { tier: string; daily_cap: number; redact_pii: boolean }
let assignments: unknown
let retention = 365
test.beforeAll(async () => {
  const c = await as('admin')
  try {
    expect(await profiles(c), 'no profile on the box before this file').toEqual([])
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
    noErrors(errors, /status of 501/) // GET /ai/asks answers 501 (ask history is not built): see the fixme below
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
    noErrors(errors, /status of (409|501)/)
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

// ---- not built, or not testable without a provider: the real flow is in the body (D-171 (2)) ----
test.fixme('Ask your data: a question is answered from read-only tools with the AI label; a question with personal data is stopped by the hook and stored hidden (S-AI-5, INV-13; POST /ai/ask and GET /ai/asks answer 501 not_implemented)', async ({ page }) => {
  const c = await as('admin')
  const r = await api<{ answer: string; hooks: unknown[] }>(c, 'POST', '/ai/ask', { question: 'Which devices are not approved yet?' })
  expect(r.status).toBe(200)
  const pii = await api<Err>(c, 'POST', '/ai/ask', { question: 'email an.nguyen@example.com the list' })
  expect(pii.status).toBe(200)
  await page.goto('/assistant')
  await expect(page.getByText('AI-generated, needs human review').first()).toBeVisible()
  await c.dispose()
})
test.fixme('an answer from a model: explain a finding with the sources, the cached copy comes back without a call, a fallback profile answers when the primary fails (S-AI-2, INV-2, INV-6; needs a provider)', async () => {
  const c = await as('admin')
  const r = await api<{ affected: string; citations: unknown[] }>(c, 'POST', `/ai/cve/${CVE}/explain`)
  expect(r.status).toBe(200)
  expect((await api<{ explain: unknown }>(c, 'GET', `/ai/cve/${CVE}/cached`)).body.explain).not.toBeNull()
  await c.dispose()
})
test.fixme('CVE news and the log digest: the box fetches the sources, the AI only summarises; no log line means no call and no tokens (S-AI-3, S-AI-4, POST-3; POST /ai/cve/{id}/news and /ai/logs/digest answer 501)', async () => {
  const c = await as('admin')
  expect((await api(c, 'POST', '/ai/logs/digest')).body).toMatchObject({ empty: true })
  expect((await api(c, 'POST', `/ai/cve/${CVE}/news`)).status).toBe(200)
  await c.dispose()
})
test.fixme('memory, skills and the knowledge base: add, edit, switch, delete; a suggestion is not remembered until accepted; a document is indexed (S-AI-7, INV-8..10; GET /ai/memory, /ai/skills and /ai/knowledge answer 501)', async () => {
  const c = await as('admin')
  expect((await api(c, 'GET', '/ai/memory')).status).toBe(200)
  expect((await api(c, 'GET', '/ai/skills')).status).toBe(200)
  expect((await api(c, 'GET', '/ai/knowledge')).status).toBe(200)
  await c.dispose()
})
