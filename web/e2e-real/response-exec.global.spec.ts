// Response actions that change another device, carried out on the real backend (S-RESP-3, S-RESP-2; INV-1, INV-7, INV-8, INV-9, INV-10, INV-13, INV-19; WP-30 slice 9a).
// The device is the HTTP fake of the box (cmd/vedette/e2edevices_test.go, a small firewall with a ban list): the specs read what it RECEIVED, not what
// Vedette says it sent. Flow: a manual rule on a device of the inventory -> a request waits -> with execution off the approval is refused and the device
// saw nothing -> an administrator with two-step sign-in turns execution on (typed phrase) -> an operator approves in the app -> the fake got the exact
// request, the check before and the read-back -> roll back -> the fake got the undo and the read-back no longer holds the address. Then: a check before
// that refuses sends nothing, a never-touch address refuses the run, the emergency stop cancels and opens the breaker, and the response log keeps all
// of it in a chain that verifies and exports.
// Global project: execution, the never-touch list and the breaker are box-wide. The last step puts them back (execution off, breaker closed, list as it was).
import { createHash } from 'node:crypto'
import { expect, request, test, type APIRequestContext, type BrowserContext, type Page } from '@playwright/test'
import { api, authFile, box, createUser, deviceSeen, device, httpState, login, password, uniq } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { totp } from './twofa'
import { collectErrors, shot } from '../e2e/helpers'

test.describe.configure({ mode: 'serial' })
test.use({ actionTimeout: 10_000 })

interface Item { id: string; status: string; result: string | null; verified: { ok: boolean; detail: string } | null; connection: string | null; state_unknown: boolean; change: { rest: { method: string; url: string; body: string | null } | null } }
interface Req { id: string; status: string; rule_id: string | null; asset_id: string | null; items: Item[]; approvals: { name: string; via: string }[]; pre_approved: boolean; note: string | null }
interface Settings { execution: boolean; accepted_by: string | null; breaker_tripped_at: string | null; max_per_hour: number; expiry_min: number; approval_channels: string[]; breaker_max_per_hour: number; multi_target_max: number; maintenance: unknown[]; ai: { triggers: string[]; budget_hour: number; budget_day: number } }
const input = (s: Settings, over: Partial<Settings> = {}) => { const m = { ...s, ...over }; return { max_per_hour: m.max_per_hour, expiry_min: m.expiry_min, approval_channels: m.approval_channels, breaker_max_per_hour: m.breaker_max_per_hour, multi_target_max: m.multi_target_max, maintenance: m.maintenance, ai: { triggers: m.ai.triggers, budget_hour: m.ai.budget_hour, budget_day: m.ai.budget_day } } }
interface Log { id: string; ts: string; kind: string; actor: string; detail: string; prev_hash: string; hash: string }

const PHRASE = 'I ACCEPT THE RISK'
const ZERO = '0'.repeat(64)
const tag = uniq('rx')
const ctx: { bossId?: string; before?: Settings; admin?: APIRequestContext; op?: APIRequestContext; viewer?: APIRequestContext; boss?: APIRequestContext; bossCtx?: BrowserContext; bossKey?: string
  conn?: string; action?: string; rule?: string; devId?: string; devIp?: string; ban?: string[]; allowBefore?: { value: string; label: string }[] } = {}
const ctxs = () => ctx as Required<typeof ctx>

const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const get = async <T>(c: APIRequestContext, path: string) => { const r = await api<T>(c, 'GET', path); expect(r.status, `GET ${path}: ${JSON.stringify(r.body)}`).toBe(200); return r.body }
const requests = async (c: APIRequestContext) => (await get<{ items: Req[] }>(c, '/response/actions')).items.filter((r) => r.rule_id === ctx.rule)
const log = async (c: APIRequestContext) => (await get<{ items: Log[] }>(c, '/response/log')).items
const settings = (c: APIRequestContext) => get<Settings>(c, '/response/settings')
const manual = (c: APIRequestContext) => api<{ matched: number; dry_run: number; requests: number; executed: number; refused: number; deduped: number }>(c, 'POST', `/response/rules/${ctx.rule}/manual`, { asset_id: ctx.devId })
const hits = async (since: number) => ((await deviceSeen('http')).requests ?? []).slice(since)
const seenCount = async () => ((await deviceSeen('http')).requests ?? []).length
const toast = (page: Page, re: RegExp) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const dump = (b: unknown) => JSON.stringify(b)

async function openRequests(page: Page) {
  await page.goto('/response#requests')
  await expect(h1(page)).toHaveText('Response')
  await expect(page.getByRole('tab', { name: /^Requests/ })).toHaveAttribute('aria-selected', 'true')
}
/** The one request of the rule that is waiting, as the box shows it. */
const waiting = async (c: APIRequestContext) => { const r = (await requests(c)).filter((x) => x.status === 'pending'); expect(r, 'one request waits').toHaveLength(1); return r[0]! }

test.beforeAll(async () => {
  ctx.admin = await as('admin'); ctx.op = await as('operator'); ctx.viewer = await as('viewer')
  const on = await api(ctx.admin, 'PATCH', '/modules/response', { enabled: true, with_dependencies: true })
  expect(on.status, dump(on.body)).toBe(200)
})
test.afterAll(async () => {
  // put back what is box-wide: execution off, breaker closed, the never-touch list as it was
  const a = ctx.admin
  if (!a) return
  await api(a, 'POST', '/response/breaker/reset')
  await api(a, 'POST', '/response/execution', { enabled: false })
  if (ctx.allowBefore) await api(a, 'PUT', '/response/allowlist', { items: ctx.allowBefore })
  if (ctx.before) await api(a, 'PUT', '/response/settings', input(ctx.before))
  if (ctx.rule) await api(a, 'DELETE', `/response/rules/${ctx.rule}`)
  if (ctx.action) await api(a, 'DELETE', `/response/catalog/${ctx.action}`)
  if (ctx.devId) await api(a, 'DELETE', `/inventory/devices/${ctx.devId}`)
  if (ctx.conn) await api(a, 'DELETE', `/core/connections/${ctx.conn}`)
  await httpState('ready').catch(() => undefined) // a test that died in maintenance must not leave the device there
  if (ctx.bossId) await api(a, 'PATCH', `/core/users/${ctx.bossId}`, { disabled: true }) // the extra administrator made for two-step sign-in
  await ctx.bossCtx?.close()
  for (const c of [ctx.admin, ctx.op, ctx.viewer, ctx.boss]) await c?.dispose()
})

test('setup: a lab firewall connection, an action with a check before and a read-back, a device, and a manual rule that starts in dry run', async () => {
  const a = ctxs().admin
  const dev = device('http')
  ctx.before = await settings(a)
  // the box approves 3 device actions an hour by default (INV-12); this file approves more than that
  const lim = await api(a, 'PUT', '/response/settings', input(ctx.before, { max_per_hour: 20 }))
  expect(lim.status, dump(lim.body)).toBe(200)
  const made = await api<{ id: string }>(a, 'POST', '/core/connections', { name: `${tag} firewall`, kind: 'http', target: dev.target, auth_type: 'token', secret: dev.secret, allow: [`${dev.target}/`], enabled: true })
  expect(made.status, dump(made.body)).toBe(201)
  ctx.conn = made.body.id
  const on = await api(a, 'PUT', `/core/connections/${ctx.conn}`, { name: `${tag} firewall`, kind: 'http', target: dev.target, auth_type: 'token', secret: dev.secret, allow: [`${dev.target}/`], enabled: true, tools: [{ name: 'send_request', enabled: true }] })
  expect(on.status, dump(on.body)).toBe(200)
  const tested = await api(a, 'POST', `/core/connections/${ctx.conn}/test`) // an action can use a connection only after a test has pinned its certificate
  expect(tested.status, dump(tested.body)).toBe(200)
  const empty = { cli: '', method: '', path: '', body: '', headers: '' }
  const act = await api<{ id: string }>(a, 'POST', '/response/catalog', {
    name: `${tag} ban an address`, description: 'Bans one address on the lab firewall', connection_id: ctx.conn, tool: null, rollback_tool: null, risk: 'medium', enabled: true, ai_may_propose: false,
    run: { ...empty, method: 'POST', path: '/api/e2e/ban', body: '{"ip":"{ip}"}' }, rollback: { ...empty, method: 'POST', path: '/api/e2e/unban', body: '{"ip":"{ip}"}' },
    verify: { ...empty, method: 'GET', path: '/api/e2e/bans', expect: '{ip}' },
    precheck: { ...empty, method: 'GET', path: '/api/e2e/status' }, precheck_refuse: ['maintenance'], precheck_expect: 'ready',
  })
  expect(act.status, dump(act.body)).toBe(201)
  ctx.action = act.body.id
  ctx.devIp = `10.${40 + (Date.now() % 150)}.${Math.floor(Math.random() * 250)}.${1 + Math.floor(Math.random() * 250)}`
  const d = await api<{ id: string }>(a, 'POST', '/inventory/devices', { catalog_id: 'synology-nas-dsm', name: `${tag}-nas`, ip: ctx.devIp })
  expect(d.status, dump(d.body)).toBe(201)
  ctx.devId = d.body.id
  const rule = await api<{ id: string; live: boolean }>(a, 'POST', '/response/rules', {
    name: `${tag} isolate`, enabled: true, live: false, trigger: 'manual', match: 'all', conditions: [], pre_approved: false, max_per_hour: 20, schedule_min: null,
    actions: [{ action_id: ctx.action, params: { ip: '{{trigger.ip}}' }, ttl_min: 60 }],
  })
  expect(rule.status, dump(rule.body)).toBe(201)
  expect(rule.body.live, 'a new rule starts in dry run (INV-3)').toBe(false)
  ctx.rule = rule.body.id
  // dry run: the match is logged, nothing is requested, the device sees nothing
  const base = await seenCount()
  const dry = await manual(ctxs().op)
  expect(dry.status, dump(dry.body)).toBe(200)
  expect(dry.body, dump(dry.body)).toMatchObject({ matched: 1, dry_run: 1, requests: 0, refused: 0 })
  expect(await requests(a)).toEqual([])
  expect(await seenCount(), 'a dry run sends nothing').toBe(base)
  const live = await api(a, 'PUT', `/response/rules/${ctx.rule}`, { name: `${tag} isolate`, enabled: true, live: true, trigger: 'manual', match: 'all', conditions: [], pre_approved: false, max_per_hour: 20, schedule_min: null, actions: [{ action_id: ctx.action, params: { ip: '{{trigger.ip}}' }, ttl_min: 60 }] })
  expect(live.status, dump(live.body)).toBe(200)
})

test('INV-1, INV-9: execution is off by default, so a request waits and an approval is refused; the device saw nothing', async () => {
  const { admin, op, viewer } = ctxs()
  expect((await settings(admin)).execution, 'execution starts off').toBe(false)
  const base = await seenCount()
  const run = await manual(op)
  expect(run.status, dump(run.body)).toBe(200)
  expect(run.body).toMatchObject({ matched: 1, requests: 1, executed: 0 })
  const r = await waiting(admin)
  expect(r.items).toHaveLength(1)
  expect(r.items[0]).toMatchObject({ status: 'pending' })
  expect(r.pre_approved).toBe(false)
  // the same event again does not make a second request (INV-11)
  const again = await manual(op)
  expect(again.body, 'the open request is merged, not repeated').toMatchObject({ requests: 0, deduped: 1 })
  expect(await requests(admin)).toHaveLength(1)
  // a viewer cannot run or approve
  expect((await manual(viewer)).status, 'viewer runs a rule').toBe(403)
  expect((await api(viewer, 'POST', `/response/actions/${r.id}/approve`, {})).status, 'viewer approves').toBe(403)
  const refused = await api<{ error: { code: string } }>(op, 'POST', `/response/actions/${r.id}/approve`, {})
  expect(refused.status, dump(refused.body)).toBe(409)
  expect(refused.body.error.code).toBe('execution_off')
  expect((await waiting(admin)).id, 'still waiting').toBe(r.id)
  expect(await seenCount(), 'nothing reached the device').toBe(base)
})

test('INV-7: only an administrator with two-step sign-in and the exact phrase turns execution on', async ({ browser }) => {
  const { admin, op } = ctxs()
  expect((await api(op, 'POST', '/response/execution', { enabled: true, phrase: PHRASE })).status, 'an operator').toBe(403)
  const noTwo = await api<{ error: { code: string } }>(admin, 'POST', '/response/execution', { enabled: true, phrase: PHRASE })
  expect(noTwo.status, `an administrator without two-step sign-in: ${dump(noTwo.body)}`).toBe(409)
  expect(noTwo.body.error.code).toBe('twofa_required')

  // a second administrator, made the way a person gets one, who then turns two-step sign-in on (authenticator app)
  const who = { name: `Boss ${tag}`, email: `${tag}@e2e.test`, role: 'admin' as const }
  const tmp = await request.newContext({ baseURL: box().base_url })
  await createUser(admin, tmp, who)
  const boss = await request.newContext({ baseURL: box().base_url })
  expect((await login(boss, who.email, password())).status).toBe(200)
  const start = await api<{ secret: string }>(boss, 'POST', '/core/account/2fa/start', { password: password() })
  expect(start.status, dump(start.body)).toBe(200)
  ctx.bossKey = start.body.secret
  const on = await api(boss, 'POST', '/core/account/2fa/confirm', { code: totp(ctx.bossKey) })
  expect(on.status, dump(on.body)).toBe(200)
  ctx.boss = boss
  ctx.bossId = (await api<{ items: { id: string; email: string }[] }>(admin, 'GET', '/core/users')).body.items.find((u) => u.email === who.email)?.id
  await tmp.dispose()
  ctx.bossCtx = await browser.newContext({ baseURL: box().base_url, storageState: await boss.storageState(), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', viewport: { width: 1366, height: 860 } })

  for (const phrase of ['i accept the risk', `${PHRASE} `, 'I ACCEPT', undefined]) {
    const r = await api<{ error: { code: string } }>(boss, 'POST', '/response/execution', { enabled: true, phrase })
    expect(r.status, `phrase ${JSON.stringify(phrase)}: ${dump(r.body)}`).toBe(400)
    expect(r.body.error.code).toBe('phrase_mismatch')
  }
  expect((await settings(admin)).execution, 'still off after every refusal').toBe(false)
  const put = await api(boss, 'PUT', '/response/settings', { ...input(await settings(boss)), execution: true })
  expect(put.status, `PUT /response/settings with an execution field: ${dump(put.body)}`).toBe(400) // the field is not part of the settings: it is refused by name
  expect(dump(put.body)).toContain('"field":"execution"')
  expect((await settings(admin)).execution, 'PUT /response/settings never flips the switch').toBe(false)

  // in the app: the switch asks for the phrase; the button waits for the exact text
  const page = await ctx.bossCtx.newPage()
  const errors = collectErrors(page)
  await page.goto('/settings/response')
  await expect(page.getByRole('heading', { name: 'AI response (high risk)' }).first()).toBeVisible()
  const sw = page.getByRole('switch', { name: 'Let the AI carry out actions I approve' })
  await expect(sw).not.toBeChecked()
  await shot(page, 'real-response-exec', 'switch-off')
  await sw.click()
  const dlg = page.getByRole('dialog', { name: 'Turn on AI execution' })
  await expect(dlg).toContainText('Two-step sign-in on your account:')
  await expect(dlg).toContainText('On')
  const go = dlg.getByRole('button', { name: 'Turn on AI execution' })
  await expect(go).toBeDisabled()
  await dlg.locator('#risk-phrase').fill('I ACCEPT THE RISK.')
  await expect(go).toBeDisabled()
  await dlg.locator('#risk-phrase').fill(PHRASE)
  await shot(page, 'real-response-exec', 'phrase')
  await go.click()
  await toast(page, /AI execution is on/)
  await expect.poll(async () => (await settings(admin)).execution, { message: 'execution on, on the box' }).toBe(true)
  const s = await settings(admin)
  expect(s.accepted_by, 'who accepted the risk is recorded').toBe(who.email)
  await expect(sw).toBeChecked()
  await expect(page.getByText(`accepted by ${who.email}`)).toBeVisible()
  await expect(page.getByRole('button', { name: 'Emergency stop' })).toBeVisible()
  await shot(page, 'real-response-exec', 'switch-on')
  await noVietnamese(page, 'settings/response')
  noErrors(errors, /status of (4|5)\d\d/)
  await page.close()
})

test('S-RESP-3: an operator approves in the app; the device got the check, the exact request and the read-back, and the request shows it verified', async () => {
  const { admin } = ctxs()
  const dev = device('http')
  const opCtx = await ctx.bossCtx!.browser()!.newContext({ baseURL: box().base_url, storageState: authFile('operator'), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', viewport: { width: 1366, height: 860 } })
  const p = await opCtx.newPage()
  const errors = collectErrors(p)
  const r = await waiting(admin)
  const base = await seenCount()
  await openRequests(p)
  const card = p.getByRole('heading', { level: 3, name: `${tag} ban an address: ${ctx.devIp}` }).locator('xpath=ancestor::div[.//button[normalize-space()="Approve"]][1]')
  await expect(card).toContainText(`${tag}-nas`)
  await expect(card).toContainText(`Through ${tag} firewall`)
  await expect(card).toContainText('Undone after 1 h')
  await card.getByText('Exact change and rollback').click()
  await expect(card).toContainText(`"ip":"${ctx.devIp}"`)
  await expect(card).toContainText('/api/e2e/ban')
  await shot(p, 'real-response-exec', 'request-pending')
  await card.getByRole('button', { name: 'Approve', exact: true }).click()
  await toast(p, /Approved\. The action was carried out\./)

  // what the device received, in order: the check before, the read before the write (D-356), the write, the read-back; each with the connection's own sign-in
  const got = await hits(base)
  expect(got.map((q) => `${q.method} ${q.path}`), 'the requests the device got').toEqual(['GET /api/e2e/status', 'GET /api/e2e/bans', 'POST /api/e2e/ban', 'GET /api/e2e/bans'])
  for (const q of got) expect(q.authorization, 'the connection\'s own token on every request').toBe(`Bearer ${dev.secret}`)
  const seen = await deviceSeen('http')
  expect(seen.banned, 'the firewall bans the device').toContain(ctx.devIp)

  const done = (await requests(admin)).find((x) => x.id === r.id)!
  expect(done.status).toBe('executed')
  expect(done.approvals.map((a) => a.via)).toEqual(['app'])
  expect(done.items[0]).toMatchObject({ status: 'executed', result: 'HTTP 200', state_unknown: false })
  expect(done.items[0]!.verified, 'read back from the device').toMatchObject({ ok: true })
  expect(JSON.stringify(done), 'what the device printed is not kept').not.toContain('"banned"')
  await openRequests(p)
  await p.getByRole('button', { name: 'History' }).click()
  await expect(p.getByText('Read back: ok').first()).toBeVisible()
  await shot(p, 'real-response-exec', 'request-executed')
  await expectAccessible(p, 'response requests')
  noErrors(errors, /status of (4|5)\d\d/)
  ctx.ban = seen.banned
  await p.close()
  await opCtx.close()
})

test('INV-13: roll back in the app; the device got the undo and the read-back no longer holds the address', async () => {
  const { admin } = ctxs()
  const r = (await requests(admin)).find((x) => x.status === 'executed')!
  const base = await seenCount()
  const opCtx = await ctx.bossCtx!.browser()!.newContext({ baseURL: box().base_url, storageState: authFile('operator'), locale: 'vi-VN', timezoneId: 'Asia/Ho_Chi_Minh', viewport: { width: 1366, height: 860 } })
  const p = await opCtx.newPage()
  await openRequests(p)
  await p.getByRole('button', { name: 'History' }).click()
  const card = p.getByRole('heading', { level: 3, name: `${tag} ban an address: ${ctx.devIp}` }).locator('xpath=ancestor::div[.//button[normalize-space()="Roll back"]][1]')
  await card.getByRole('button', { name: 'Roll back' }).click()
  await toast(p, /Rolled back/)
  const got = await hits(base)
  expect(got.map((q) => `${q.method} ${q.path}`), 'the undo and its read-back').toEqual(['POST /api/e2e/unban', 'GET /api/e2e/bans'])
  expect((await deviceSeen('http')).banned, 'the firewall no longer holds the device').not.toContain(ctx.devIp)
  const after = (await requests(admin)).find((x) => x.id === r.id)!
  expect(after.status).toBe('rolled_back')
  expect(after.items[0]).toMatchObject({ status: 'rolled_back' })
  expect(after.items[0]!.result).toContain('Read back from the device: the change is gone.')
  await shot(p, 'real-response-exec', 'rolled-back')
  await p.close()
  await opCtx.close()
})

test('INV-13: a check before that refuses sends nothing to the device', async () => {
  const { admin, op } = ctxs()
  await httpState('maintenance')
  try {
    const run = await manual(op)
    expect(run.body).toMatchObject({ requests: 1 })
    const r = await waiting(admin)
    const base = await seenCount()
    const ok = await api(op, 'POST', `/response/actions/${r.id}/approve`, {})
    expect(ok.status, dump(ok.body)).toBe(200)
    const got = await hits(base)
    expect(got.map((q) => `${q.method} ${q.path}`), 'only the check went out').toEqual(['GET /api/e2e/status'])
    const after = (await requests(admin)).find((x) => x.id === r.id)!
    expect(after.items[0]).toMatchObject({ status: 'failed' })
    expect(after.items[0]!.result).toMatch(/Refused by the check before/)
    expect(after.items[0]!.state_unknown, 'nothing was written, so nothing is unknown').toBe(false)
    expect((await deviceSeen('http')).banned).not.toContain(ctx.devIp)
  } finally { await httpState('ready') }
})

test('INV-10: an address on the never-touch list refuses the run and is logged', async () => {
  const { admin, op } = ctxs()
  ctx.allowBefore = (await get<{ items: { value: string; label: string }[] }>(admin, '/response/allowlist')).items
  const put = await api(admin, 'PUT', '/response/allowlist', { items: [...ctx.allowBefore, { value: ctxs().devIp, label: `${tag} protected` }] })
  expect(put.status, dump(put.body)).toBe(200)
  const base = await seenCount()
  const n = (await requests(admin)).length
  const run = await manual(op)
  expect(run.status, dump(run.body)).toBe(200)
  expect(run.body, 'refused, no request').toMatchObject({ requests: 0, refused: 1 })
  expect((await requests(admin)).length).toBe(n)
  expect(await seenCount(), 'nothing reached the device').toBe(base)
  expect((await log(admin)).some((l) => l.kind === 'refused' && l.detail.includes(ctxs().devIp)), 'the refusal is in the log').toBe(true)
  expect((await api(ctxs().viewer, 'PUT', '/response/allowlist', { items: [] })).status, 'a viewer cannot change the list').toBe(403)
  expect((await api(op, 'PUT', '/response/allowlist', { items: [] })).status, 'an operator cannot change the list').toBe(403)
  await api(admin, 'PUT', '/response/allowlist', { items: ctx.allowBefore })
  ctx.allowBefore = undefined
})

// This test reads the effects of the stop in the rule run, the request and the log; the settings and the page are checked in the test after it.
test('INV-8: the emergency stop cancels what waits, holds every rule behind the breaker and is logged; only an administrator resumes', async () => {
  const { admin, op, viewer } = ctxs()
  const run = await manual(op)
  expect(run.body).toMatchObject({ requests: 1 })
  const r = await waiting(admin)
  expect((await api(viewer, 'POST', '/response/emergency-stop')).status, 'a viewer').toBe(403)
  const stop = await api(op, 'POST', '/response/emergency-stop')
  expect(stop.status, dump(stop.body)).toBe(200)
  expect((await requests(admin)).find((x) => x.id === r.id), 'the waiting request is cancelled by the stop').toMatchObject({ status: 'rejected', note: expect.stringContaining('Cancelled by emergency stop') })
  expect((await log(admin)).some((l) => l.kind === 'emergency_stop'), 'in the log').toBe(true)
  // while the breaker is open no rule makes a request
  const base = await seenCount()
  const held = await manual(op)
  expect(held.body, dump(held.body)).toMatchObject({ requests: 0, refused: 1 })
  expect((await log(admin)).some((l) => l.kind === 'refused' && l.detail.startsWith('circuit_open')), 'the refusal says the circuit is open').toBe(true)
  expect(await seenCount(), 'nothing reached the device').toBe(base)
  expect((await api(op, 'POST', '/response/breaker/reset')).status, 'an operator cannot resume').toBe(403)
  const reset = await api(admin, 'POST', '/response/breaker/reset')
  expect(reset.status, dump(reset.body)).toBe(200)
  const s = await settings(admin)
  expect(s.breaker_tripped_at).toBeNull()
  expect(s.execution, 'resuming does not turn execution back on').toBe(false)
  expect((await manual(op)).body, 'after resuming a rule makes its request again').toMatchObject({ requests: 1 })
  // that request waits behind a switch that is off
  expect((await api(op, 'POST', `/response/actions/${(await waiting(admin)).id}/approve`, {})).status).toBe(409)
})

// Issue #302 (fixed): the settings stay readable after an emergency stop, and the page says so and offers Resume.
test('GET /response/settings after an emergency stop answers 200 and the page offers Resume (issue #302)', async ({ page }) => {
  const { admin, op } = ctxs()
  try {
    expect((await api(op, 'POST', '/response/emergency-stop')).status).toBe(200)
    const r = await api(admin, 'GET', '/response/settings')
    expect(r.status, dump(r.body)).toBe(200)
    await page.context().addCookies((await admin.storageState()).cookies)
    await page.goto('/settings/response')
    await expect(page.getByText('The circuit breaker is open.')).toBeVisible()
    await page.getByRole('button', { name: 'Resume' }).click()
  } finally { await api(admin, 'POST', '/response/breaker/reset') }
})

const chainHash = (l: { actor: string; detail: string; id: string; kind: string; ts: string }, prev: string) =>
  createHash('sha256').update(`${prev}\n${JSON.stringify({ actor: l.actor, detail: l.detail, id: l.id, kind: l.kind, prev_hash: prev, ts: l.ts })}`).digest('hex')
/** Walks a chain oldest first: every entry links to the one before and carries the hash of its own content. Returns what is wrong, empty when it verifies. */
function brokenAt(items: Log[]): string[] {
  let prev = ZERO
  const bad: string[] = []
  for (const [i, l] of items.entries()) {
    if (l.prev_hash !== prev) bad.push(`#${i} ${l.id}: prev_hash ${l.prev_hash} is not ${prev}`)
    else if (l.hash !== chainHash(l, prev)) bad.push(`#${i} ${l.id}: hash does not match its content (ts ${l.ts})`)
    prev = l.hash
  }
  return bad
}

test('INV-19: the response log keeps what happened, holds no secret, cannot be edited, and the export is a chain that verifies', async () => {
  const { admin, op, viewer } = ctxs()
  const items = await log(admin)
  expect(items.length).toBeGreaterThan(5)
  const kinds = new Set(items.map((l) => l.kind))
  for (const k of ['dry_run', 'rule_fired', 'request', 'approved', 'executed', 'rolled_back', 'refused', 'emergency_stop', 'settings']) expect(kinds.has(k), `the log holds a "${k}" entry`).toBe(true)
  expect(items.some((l) => l.kind === 'settings' && l.detail.includes('accepted the risk')), 'who accepted the risk').toBe(true)
  const text = JSON.stringify(items)
  expect(text, 'no secret in the log').not.toContain(device('http').secret!)
  expect(text, 'no device output in the log').not.toContain('"banned"')
  expect(items[0]!.prev_hash, 'the first entry starts at the genesis').toBe(ZERO)
  items.reduce((prev, l) => { expect(l.prev_hash, `entry ${l.id} points at the one before`).toBe(prev); return l.hash }, ZERO)
  // there is no way to change or delete a line
  for (const m of ['PUT', 'PATCH', 'DELETE', 'POST'] as const) expect([404, 405], `${m} /response/log`).toContain((await api(admin, m, '/response/log', {})).status)
  expect((await api(viewer, 'GET', '/response/log')).status, 'a viewer').toBe(403)
  expect((await api(op, 'GET', '/response/log')).status, 'an operator reads it').toBe(200)

  // the export of the Data page carries the lines as they are stored, so it verifies offline with the one formula of the chains (D-57)
  const url = '/core/logs/export?categories=response&format=json'
  let ex = await api<{ categories: { response: Log[] }; chains: { response: { complete: boolean; count: number; head_hash: string | null } } }>(admin, 'GET', url)
  for (let i = 0; i < 3 && (ex.status === 409 || ex.status === 429); i++) { await new Promise((ok) => setTimeout(ok, 61_000)); ex = await api(admin, 'GET', url) }
  expect(ex.status, dump(ex.body).slice(0, 300)).toBe(200)
  const rows = ex.body.categories.response
  expect(rows.length).toBeGreaterThanOrEqual(items.length)
  expect(brokenAt(rows), 'the exported chain verifies').toEqual([])
  expect(ex.body.chains.response.complete).toBe(true)
  expect(ex.body.chains.response.head_hash).toBe(rows.at(-1)!.hash)
  expect(rows.map((l) => l.hash).slice(0, items.length), 'the exported lines are the lines of the log').toEqual(items.map((l) => l.hash))
})

// Issue #308 (fixed): GET /response/log serves ts exactly as stored and hashed, so the served chain re-verifies and the page of the log says "Chain verified".
test('the log served by the API and shown on the page verifies by itself (issue #308)', async ({ page }) => {
  const items = await log(ctxs().admin)
  expect(brokenAt(items), 'the served chain verifies').toEqual([])
  await page.context().addCookies((await ctxs().admin.storageState()).cookies)
  await page.goto('/response#log')
  await expect(page.getByText('Chain verified')).toBeVisible()
})

test('after the run: execution is off, the breaker is closed, and the device holds no ban', async () => {
  const { admin } = ctxs()
  const s = await settings(admin)
  expect(s.execution).toBe(false)
  expect(s.breaker_tripped_at).toBeNull()
  expect((await deviceSeen('http')).banned).not.toContain(ctxs().devIp)
})
