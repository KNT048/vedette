// Response chains on the real backend (S-RESP-3, INV-4, INV-17, INV-2; WP-30 slice 9b, D-173). A rule fires, the request goes out by email to a listed approver, the approver decides
// from the link in the mail (the link points at THIS box: the loopback BaseURL seam of cmd/vedette/notify.go) or in the app, the box publishes the address on its block list, and the
// firewall's pull (a plain GET with the token in the URL) shows it. The email is the real one: notify mails it to the box's own SMTP sink (control server of cmd/vedette/e2ebox_test.go).
// The rule uses the `manual` trigger on purpose: it is the one that fires without a sensor or a trap, so the chain after the trigger is what is under test. The trap-hit trigger is its own
// test at the end (`honeypot` -> block the source), and it is a known bug: nothing subscribes to honeypot.hit.created (see the test).
// Not covered: the AI paths of S-RESP-1/2 (Emily's `ai`, no fake model), device actions (response-actions/response-exec, slice 9a), chat buttons (Telegram/Slack/Zalo need the internet).
// Global project: response settings, the email channel, the module switches and the block list are box-wide; afterAll puts back what it can (rules and devices deleted, settings and channel
// as they were, entries rolled back). Approver identity: the operator proves the address with a code mailed to the sink, as in My account (D-191).
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { expect, request, test, type APIRequestContext } from '@playwright/test'
import { ACCOUNTS, api, authFile, box, hostHoneypot, hostKnob, mailbox, uniq } from './box'
import { h1, noErrors } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

type Client = APIRequestContext
const as = (role: 'admin' | 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const get = async <T>(c: Client, path: string) => { const r = await api<T>(c, 'GET', path); expect(r.status, `GET ${path}: ${JSON.stringify(r.body)}`).toBe(200); return r.body }

interface Item { id: string; title: string; status: string; targets: number; connector_id: string | null; change: unknown }
interface Req {
  id: string; title: string; status: string; rule_name: string | null; requires_approvals: number; two_because: string | null; sent_to: string[]
  approvals: { user_id: string; email: string; via: string; items: string[] }[]; items: Item[]
}
interface Rule { id: string; name: string; live: boolean; enabled: boolean; trigger: string; actions: { action_id: string; params: Record<string, string>; ttl_min: number | null }[] }
interface Blocklist { url: string; token_last4: string; entries: { value: string; source: string; reason: string; expires_at: string | null }[] }
interface Settings { max_per_hour: number; expiry_min: number; approval_channels: string[]; breaker_max_per_hour: number; multi_target_max: number; maintenance: unknown[]; ai: { triggers: string[]; budget_hour: number; budget_day: number } }
interface Chan { enabled: boolean; configured: boolean; fields: Record<string, string>; min_severity: string; approvals: boolean; approvers: { user_id: string; address: string }[] }

// documentation addresses: public as far as the block list is concerned (INV-17 lets the three documentation blocks through because the sample data uses them)
const IP1 = '203.0.113.9'
const IP2 = '198.51.100.23'
const IP3 = '198.51.100.24'
const PRIVATE = '10.9.9.9'

const made = { rules: [] as string[], devices: [] as string[], names: new Set<string>() }
let original: { modules: Record<string, boolean>; settings?: Settings; channel?: Chan } = { modules: {} }
let opId = ''
let adminId = ''
let device: { id: string; name: string }
let mailSeen = 0

/** A quoted-printable body decoded: soft line breaks removed, =XX bytes put back (the link of the mail is long enough to be wrapped). */
const qp = (m: string) => m.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))
/** The approval links mailed to `to` after `skip` messages were already in the sink, newest last. */
async function approvalLinks(to: string, skip = 0): Promise<string[]> {
  const out: string[] = []
  for (const m of (await mailbox()).slice(skip)) {
    const text = qp(m)
    if (!text.toLowerCase().includes(`to: ${to.toLowerCase()}`) && !text.toLowerCase().includes(`<${to.toLowerCase()}>`)) continue
    for (const l of text.match(/https?:\/\/[^\s"<>]+\/approve\/[A-Za-z0-9._~%-]+/g) ?? []) out.push(l)
  }
  return out
}
/** Waits for a new approval link mailed to `to`: the request goes out in the same request that made it, so this is short. */
async function nextLink(to: string, skip: number): Promise<string> {
  let links: string[] = []
  await expect.poll(async () => (links = await approvalLinks(to, skip)).length, { message: `an approval link mailed to ${to}`, timeout: 20_000 }).toBeGreaterThan(0)
  return links[links.length - 1]!
}

/** An enabled, live rule with the manual trigger and the given blocklist_add steps (a new rule starts as a dry run, INV-14d: the PUT switches it on). */
async function makeRule(admin: Client, name: string, ips: string[], trigger = 'manual', conditions: unknown[] = [], refusedOk = false): Promise<Rule | null> {
  const body = { name, enabled: true, live: false, trigger, match: 'all', conditions, actions: ips.map((ip) => ({ action_id: 'blocklist_add', params: { ip }, ttl_min: 60 })), pre_approved: false, max_per_hour: 20, schedule_min: null }
  const c = await api<Rule>(admin, 'POST', '/response/rules', body)
  if (refusedOk && c.status === 400) return null // the rule itself is refused: the address never gets as far as a request
  expect(c.status, `create rule: ${JSON.stringify(c.body)}`).toBe(201)
  made.rules.push(c.body.id)
  made.names.add(name)
  const p = await api<Rule>(admin, 'PUT', `/response/rules/${c.body.id}`, { ...body, live: true })
  expect(p.status, `rule live: ${JSON.stringify(p.body)}`).toBe(200)
  expect(p.body).toMatchObject({ enabled: true, live: true })
  return p.body
}
const requests = async (c: Client) => (await get<{ items: Req[] }>(c, '/response/actions')).items
async function requestOf(c: Client, rule: string): Promise<Req> {
  let found: Req | undefined
  await expect.poll(async () => (found = (await requests(c)).find((r) => r.rule_name === rule)) !== undefined, { message: `a request of rule ${rule}`, timeout: 20_000 }).toBe(true)
  return found!
}
/** The block list as the firewall sees it: a GET of the tokenised address with no cookie. */
async function feed(c: Client): Promise<string[]> {
  let bl = await get<Blocklist>(c, '/response/blocklist')
  if (!bl.url) { // the address is made with the first token (admin, S-RESP-3)
    const t = await api<Blocklist>(c, 'POST', '/response/blocklist/token')
    expect(t.status, `POST /response/blocklist/token: ${JSON.stringify(t.body)}`).toBeLessThan(300)
    bl = t.body
  }
  const feedPath = new URL(bl.url, box().base_url).pathname // may be relative: the page joins it to the address it was opened at
  const r = await fetch(box().base_url + feedPath, { signal: AbortSignal.timeout(10_000) })
  expect(r.status, `GET the block list feed (${feedPath.replace(/[^/]*$/, '…')})`).toBe(200)
  return (await r.text()).split('\n').filter((l) => l !== '')
}
const feedIPs = (lines: string[]) => lines.filter((l) => !l.startsWith('#'))

test.beforeAll(async () => {
  test.setTimeout(120_000)
  const admin = await as('admin')
  try {
    const mods = (await get<{ modules: { id: string; enabled: boolean }[] }>(admin, '/modules')).modules
    original.modules = Object.fromEntries(mods.map((m) => [m.id, m.enabled]))
    for (const id of ['notify', 'response']) {
      if (original.modules[id]) continue
      const on = await api(admin, 'PATCH', `/modules/${id}`, { enabled: true, with_dependencies: true })
      expect(on.status, `enable ${id}: ${JSON.stringify(on.body)}`).toBe(200)
    }
    const users = (await get<{ items: { id: string; email: string }[] }>(admin, '/core/users')).items
    opId = users.find((u) => u.email === ACCOUNTS.operator.email)!.id
    adminId = users.find((u) => u.email === ACCOUNTS.admin.email)!.id
    // the email channel through notify's real API, pointed at the sink, with the operator as the one approver (the link goes to the sign-in email of the user)
    original.channel = (await get<{ channels: (Chan & { type: string })[] }>(admin, '/notify/channels')).channels.find((c) => c.type === 'email')
    const saved = await api(admin, 'PUT', '/notify/channels/email', {
      enabled: true, min_severity: 'high', secret: 'relay-secret-for-e2e', approvals: true, approvers: [{ user_id: opId, address: ACCOUNTS.operator.email }],
      fields: { host: '127.0.0.1', port: box().smtp_port, security: 'none', username: 'alerts@e2e.test', from: 'alerts@e2e.test', to: 'it@e2e.test' },
    })
    expect(saved.status, `save the email channel: ${JSON.stringify(saved.body)}`).toBe(200)
    original.settings = await get<Settings>(admin, '/response/settings')
    const s = original.settings
    const put = await api(admin, 'PUT', '/response/settings', { max_per_hour: s.max_per_hour, expiry_min: 30, approval_channels: ['email'], breaker_max_per_hour: s.breaker_max_per_hour, multi_target_max: s.multi_target_max, maintenance: s.maintenance, ai: { triggers: s.ai.triggers, budget_hour: s.ai.budget_hour, budget_day: s.ai.budget_day } })
    expect(put.status, `response settings: ${JSON.stringify(put.body)}`).toBe(200)
    const d = await api<{ id: string }>(admin, 'POST', '/inventory/devices', { vendor: 'Vend-chain', product: 'Laptop-chain', version: '1.0', name: uniq('chain-dev'), ip: '192.168.10.77' })
    expect(d.status, `device: ${JSON.stringify(d.body)}`).toBe(201)
    made.devices.push(d.body.id)
    device = { id: d.body.id, name: 'chain' }
  } finally { await admin.dispose() }
  // the operator proves the address, as in My account: a code mailed to it (D-191). Without this a link of the mail would not count as the operator.
  const op = await as('operator')
  try {
    const before = (await mailbox()).length
    const sent = await api(op, 'POST', '/response/me/identities/email/code')
    expect(sent.status, `send the link code: ${JSON.stringify(sent.body)}`).toBe(200)
    let code = ''
    await expect.poll(async () => { const m = (await mailbox()).slice(before).map(qp).find((t) => /approval code is (\d{6})/.test(t)); code = m ? /approval code is (\d{6})/.exec(m)![1]! : ''; return code }, { message: 'the link code arrives in the sink', timeout: 20_000 }).toMatch(/^\d{6}$/)
    const ok = await api(op, 'POST', '/response/me/identities/email/confirm', { code })
    expect(ok.status, `confirm the address: ${JSON.stringify(ok.body)}`).toBe(200)
    expect(ok.body).toMatchObject({ channel: 'email', linked: true })
  } finally { await op.dispose() }
  mailSeen = (await mailbox()).length
})

test.afterAll(async () => {
  test.setTimeout(120_000)
  const problems: string[] = []
  const step = async (what: string, fn: () => Promise<unknown>) => { try { await fn() } catch (e) { problems.push(`${what}: ${(e as Error).message.split('\n')[0]}`) } }
  const admin = await as('admin')
  const op = await as('operator')
  try {
    for (const r of (await requests(admin).catch(() => [] as Req[])).filter((x) => x.rule_name && made.names.has(x.rule_name))) { // only what this file made
      for (const i of r.items) if (['executed', 'verified'].includes(i.status)) await step(`roll back ${i.title}`, async () => { await api(op, 'POST', `/response/actions/${r.id}/rollback`) })
    }
    for (const id of made.rules) await step(`delete rule ${id}`, async () => expect([200, 204, 404]).toContain((await api(admin, 'DELETE', `/response/rules/${id}`)).status))
    for (const id of made.devices) await step(`delete device ${id}`, async () => expect([200, 204, 404]).toContain((await api(admin, 'DELETE', `/inventory/devices/${id}`)).status))
    if (original.settings) {
      const s = original.settings
      await step('response settings put back', async () => {
        const r = await api(admin, 'PUT', '/response/settings', { max_per_hour: s.max_per_hour, expiry_min: s.expiry_min, approval_channels: s.approval_channels, breaker_max_per_hour: s.breaker_max_per_hour, multi_target_max: s.multi_target_max, maintenance: s.maintenance, ai: { triggers: s.ai.triggers, budget_hour: s.ai.budget_hour, budget_day: s.ai.budget_day } })
        expect(r.status, JSON.stringify(r.body)).toBe(200)
      })
    }
    await step('email channel: approvals off', async () => {
      const c = original.channel
      // what a run before this file left (the box's own sink, set by ensureEmailChannel of the two-step specs) with the approval settings the channel had; the secret cannot be read back, so it is the one the sink setup uses
      const r = await api(admin, 'PUT', '/notify/channels/email', { enabled: c?.enabled ?? false, min_severity: c?.min_severity ?? 'high', secret: 'relay-secret-for-e2e', approvals: c?.approvals ?? false, approvers: c?.approvers ?? [], fields: c?.configured ? c.fields : { host: '127.0.0.1', port: box().smtp_port, security: 'none', username: 'alerts@e2e.test', from: 'alerts@e2e.test', to: 'it@e2e.test' } })
      expect(r.status, JSON.stringify(r.body)).toBe(200)
    })
    for (const id of ['response', 'notify']) {
      if (original.modules[id] === false) await step(`module ${id} off`, async () => expect((await api(admin, 'PATCH', `/modules/${id}`, { enabled: false })).status).toBe(200))
    }
  } finally { await admin.dispose(); await op.dispose() }
  expect(problems, 'cleanup of the response chain spec').toEqual([])
})

test('a rule fires, the approver gets the link by email, opening it changes nothing, approving from it publishes the address on the block list, the link works once, undo removes it (S-RESP-3, INV-4, INV-17)', async ({ browser, page }) => {
  test.setTimeout(120_000)
  const admin = await as('admin')
  const op = await as('operator')
  const name = uniq('Block via mail')
  const rule = (await makeRule(admin, name, [IP1], 'manual'))!
  const skip = mailSeen
  const before = await feed(admin)
  expect(feedIPs(before), 'a clean block list').not.toContain(IP1)

  // the operator runs it on a device: one request, sent to the email channel
  const run = await api<{ matched: number; requests: number }>(op, 'POST', `/response/rules/${rule.id}/manual`, { asset_id: device.id })
  expect(run, JSON.stringify(run.body)).toMatchObject({ status: 200, body: { matched: 1, requests: 1 } })
  const req = await requestOf(admin, name)
  expect(req).toMatchObject({ status: 'pending', requires_approvals: 1, two_because: null })
  expect(req.items).toHaveLength(1)
  expect(req.items[0]).toMatchObject({ connector_id: null, status: 'pending' })

  // the mail: the link points at THIS box (the loopback BaseURL seam), and is the only thing in it that can approve
  const link = await nextLink(ACCOUNTS.operator.email, skip)
  expect(link.startsWith(`${box().base_url}/approve/`), `the link of the mail (${new URL(link).origin}/approve/…)`).toBe(true)
  const token = link.slice(link.lastIndexOf('/') + 1)
  await expect.poll(async () => (await requests(admin)).find((r) => r.id === req.id)?.sent_to, { message: 'the request records that it went to the email channel' }).toContain('Email')

  // INV-4: a GET never decides. The public page is opened with no cookie, as from a mail client
  const anon = await browser.newContext({ baseURL: box().base_url, storageState: { cookies: [], origins: [] } })
  const errors = collectErrors(page)
  try {
    const p = await anon.newPage()
    const pageErrors = collectErrors(p)
    await p.goto(link)
    await expect(p.getByRole('heading', { level: 1, name: /approve/i })).toBeVisible()
    await expect(p.getByText(req.title).first()).toBeVisible()
    await expect(p.getByRole('button', { name: 'Approve', exact: true })).toBeVisible()
    await expect(p.getByRole('button', { name: 'Reject', exact: true })).toBeVisible()
    await shot(p, 'real', 'response-approve-link')
    const view = await fetch(`${box().base_url}/api/v1/response/approve/${token}`)
    expect(await view.json(), 'the view of a ready link').toMatchObject({ state: 'ready', title: req.title })
    expect((await requests(admin)).find((r) => r.id === req.id)?.status, 'opening the link decided nothing').toBe('pending')
    expect(feedIPs(await feed(admin)), 'and published nothing').not.toContain(IP1)

    await p.getByRole('button', { name: 'Approve', exact: true }).click()
    await expect(p.getByRole('status')).toHaveText(/^Approved\. The action is being carried out/)
    noErrors(pageErrors)
  } finally { await anon.close() }
  let done: Req | undefined
  await expect.poll(async () => (done = (await requests(admin)).find((r) => r.id === req.id))?.items[0]?.status, { message: 'the approved item ran', timeout: 20_000 }).toMatch(/executed|verified/)
  expect(done!.approvals).toHaveLength(1)
  expect(done!.approvals[0]).toMatchObject({ user_id: opId, via: 'email' })

  // INV-17: the firewall's pull now lists it, with the three fixed comment lines and nothing else
  const lines = await feed(admin)
  expect(feedIPs(lines)).toContain(IP1)
  const comments = lines.filter((l) => l.startsWith('#'))
  expect(comments, 'exactly the three fixed comment lines: no device, rule or event name').toHaveLength(3)
  expect(comments[0]).toBe('# vedette blocklist')
  expect(comments[1]).toMatch(/^# generated \S+/)
  expect(comments[2]).toMatch(/^# entries \d+$/)
  expect(lines.find((l) => l.startsWith('# entries'))).toBe(`# entries ${feedIPs(lines).length}`)
  const bl = await get<Blocklist>(admin, '/response/blocklist')
  expect(bl.entries.find((e) => e.value === IP1)).toMatchObject({ source: expect.any(String), expires_at: expect.any(String) })

  // one use: the same link again, as approve and as reject, is refused
  for (const decision of ['approve', 'reject']) {
    const again = await fetch(`${box().base_url}/api/v1/response/approve/${token}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision }) })
    expect([409, 403], `${decision} again: ${again.status}`).toContain(again.status)
    expect((await again.json()) as { error: { code: string } }, `${decision} again`).toMatchObject({ error: { code: expect.stringMatching(/used|decided|expired/) } })
  }
  expect((await fetch(`${box().base_url}/api/v1/response/approve/${token}`).then((r) => r.json()) as { state: string }).state).toMatch(/used|decided/)

  // undo (INV-13): the entry leaves the feed
  const back = await api(op, 'POST', `/response/actions/${req.id}/rollback`)
  expect(back.status, `rollback: ${JSON.stringify(back.body)}`).toBe(200)
  await expect.poll(async () => feedIPs(await feed(admin)), { message: 'the address leaves the block list' }).not.toContain(IP1)

  // the page the approver would use in the app shows the decision
  await page.goto('/response')
  await expect(h1(page)).toBeVisible()
  noErrors(errors)
  await admin.dispose(); await op.dispose()
})

test('an address that no firewall should ever be told to block is not published: private, loopback and link-local stay off the list (INV-17)', async () => {
  test.setTimeout(90_000)
  const admin = await as('admin')
  const op = await as('operator')
  try {
    const outcomes: string[] = []
    for (const ip of [PRIVATE, '127.0.0.1', '169.254.10.10']) {
      const name = uniq('Block private')
      const rule = await makeRule(admin, name, [ip], 'manual', [], true)
      if (!rule) { // refused when the rule is saved (loopback is not a valid block-list address): nothing to approve, nothing to publish
        outcomes.push(`${ip}: rule refused`)
        expect(feedIPs(await feed(admin)), `${ip} never reaches the firewall`).not.toContain(ip)
        continue
      }
      const run = await api<{ requests: number; refused: number }>(op, 'POST', `/response/rules/${rule.id}/manual`, { asset_id: device.id })
      expect(run.status, JSON.stringify(run.body)).toBe(200)
      // D-469: refused when it is planned (not_public), so there is nothing to approve and nothing says "Added"
      expect([run.body.requests, run.body.refused], `${ip} is refused when the run plans it`).toEqual([0, 1])
      outcomes.push(`${ip}: refused`)
      expect(feedIPs(await feed(admin)), `${ip} never reaches the firewall`).not.toContain(ip)
    }
    test.info().annotations.push({ type: 'outcomes', description: outcomes.join('; ') })
  } finally { await admin.dispose(); await op.dispose() }
})

test('two actions over the limit need two different approvers: the same person twice, a different selection, and a second email link are refused; the second person in the app completes it (INV-2, D-124)', async () => {
  test.setTimeout(120_000)
  const admin = await as('admin')
  const op = await as('operator')
  const s = original.settings!
  const setLimit = async (n: number) => expect((await api(admin, 'PUT', '/response/settings', { max_per_hour: s.max_per_hour, expiry_min: 30, approval_channels: ['email'], breaker_max_per_hour: s.breaker_max_per_hour, multi_target_max: n, maintenance: s.maintenance, ai: { triggers: s.ai.triggers, budget_hour: s.ai.budget_hour, budget_day: s.ai.budget_day } })).status).toBe(200)
  try {
    await setLimit(1) // two targets in one request: more than one
    const name = uniq('Block two')
    const rule = (await makeRule(admin, name, [IP2, IP3]))!
    const skip = (await mailbox()).length
    expect((await api(op, 'POST', `/response/rules/${rule.id}/manual`, { asset_id: device.id })).status).toBe(200)
    const req = await requestOf(admin, name)
    expect(req).toMatchObject({ status: 'pending', requires_approvals: 2 })
    expect(req.two_because).toMatch(/second approver|two different/i)
    expect(req.items).toHaveLength(2)
    const [i1, i2] = req.items.map((i) => i.id) as [string, string]

    // the first person approves by the link in the mail
    const link = await nextLink(ACCOUNTS.operator.email, skip)
    const token = link.slice(link.lastIndexOf('/') + 1)
    const first = await fetch(`${box().base_url}/api/v1/response/approve/${token}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ decision: 'approve' }) })
    expect(first.status, `first approval by link: ${await first.clone().text()}`).toBe(200)
    let cur = (await requests(admin)).find((r) => r.id === req.id)!
    expect(cur.status, 'one of two: still pending').toBe('pending')
    expect(cur.approvals).toHaveLength(1)
    expect(cur.approvals[0]).toMatchObject({ user_id: opId, via: 'email' })
    expect(feedIPs(await feed(admin)), 'nothing runs with one of two').not.toContain(IP2)

    // the same person again, in the app: refused (a link and a click are one person)
    const same = await api<{ error: { code: string } }>(op, 'POST', `/response/actions/${req.id}/approve`, {})
    expect(same, JSON.stringify(same.body)).toMatchObject({ status: 409, body: { error: { code: 'same_approver' } } })
    // a second person who picks other actions than the first
    const differs = await api<{ error: { code: string } }>(admin, 'POST', `/response/actions/${req.id}/approve`, { items: [i1] })
    expect(differs, JSON.stringify(differs.body)).toMatchObject({ status: 409, body: { error: { code: 'selection_differs' } } })
    expect((await requests(admin)).find((r) => r.id === req.id)!.status).toBe('pending')

    // the second person, in the app, approves the same set
    const second = await api<Req>(admin, 'POST', `/response/actions/${req.id}/approve`, { items: [i1, i2] })
    expect(second.status, JSON.stringify(second.body)).toBe(200)
    await expect.poll(async () => (cur = (await requests(admin)).find((r) => r.id === req.id)!).items.map((i) => i.status).join(), { message: 'both items ran', timeout: 20_000 }).toMatch(/^(executed|verified),(executed|verified)$/)
    expect(cur.approvals.map((a) => `${a.user_id}:${a.via}`).sort()).toEqual([`${adminId}:app`, `${opId}:email`].sort())
    expect(feedIPs(await feed(admin))).toEqual(expect.arrayContaining([IP2, IP3]))
    expect((await api(op, 'POST', `/response/actions/${req.id}/rollback`)).status).toBe(200)
    await expect.poll(async () => feedIPs(await feed(admin))).not.toEqual(expect.arrayContaining([IP2]))
  } finally { await setLimit(s.multi_target_max); await admin.dispose(); await op.dispose() }
})

// A real trap hit fires a live rule with the honeypot trigger (S-RESP-3; issue #304, fixed: response subscribes to honeypot.hit.created).
test('a trap hit fires the honeypot rule and asks to block its source (S-RESP-3)', async () => {
  test.setTimeout(180_000)
  const admin = await as('admin')
  const LAN = '192.168.1.0/24' // the network of the fake host's card (honeypot.global.spec.ts)
  const HIT = '203.0.113.77'
  const mods = (await get<{ modules: { id: string; enabled: boolean }[] }>(admin, '/modules')).modules
  const hpWasOn = mods.find((m) => m.id === 'honeypot')?.enabled ?? false
  let lan: string[] | undefined
  let trapOn = false
  try {
    if (!hpWasOn) expect((await api(admin, 'PATCH', '/modules/honeypot', { enabled: true, with_dependencies: true })).status).toBe(200)
    const cur = await get<Record<string, unknown> & { lan_ranges: string[] }>(admin, '/inventory/settings')
    lan = cur.lan_ranges
    if (!lan.includes(LAN)) {
      const next = { ...cur, lan_ranges: [...lan, LAN], scope_confirmed: true }
      delete next.adjusted
      expect((await api(admin, 'PUT', '/inventory/settings', next)).status).toBe(200)
    }
    let hp = await get<{ secondary_ip: string | null }>(admin, '/honeypot')
    const hadDecoy = !!hp.secondary_ip // the decoy address cannot be cleared once set (honeypot.global.spec.ts), so it is left
    if (!hadDecoy) {
      expect((await api(admin, 'PUT', '/honeypot/config', { secondary_ip: '192.168.1.200', hostname: 'CHAIN-DECOY' })).status).toBe(200)
      hp = await get<{ secondary_ip: string | null }>(admin, '/honeypot')
    }
    await hostKnob('hp_start', 'ok')
    trapOn = true
    expect((await api(admin, 'PATCH', '/honeypot/traps/ssh', { enabled: true })).status).toBe(200)
    const name = uniq('Trap source')
    await makeRule(admin, name, ['{{trigger.source_ip}}'], 'honeypot')

    const log = join(box().honeypot_dir, 'log', 'opencanary.jsonl')
    mkdirSync(dirname(log), { recursive: true })
    const utc = new Date().toISOString().replace('T', ' ').replace('Z', '000')
    appendFileSync(log, JSON.stringify({ logtype: 4000, src_host: HIT, src_port: 40001, dst_host: hp.secondary_ip, dst_port: 22, node_id: 'vedette-honeypot', local_time: utc, utc_time: utc, logdata: {} }) + '\n')
    // precondition: the honeypot read the line (it polls every 15 s) and recorded a hit from that source
    await expect.poll(async () => (await get<{ items: { src_ip: string }[] }>(admin, '/honeypot/hits')).items.some((h) => h.src_ip === HIT), { message: `a hit from ${HIT}`, timeout: 60_000, intervals: [2000] }).toBe(true)

    await expect.poll(async () => (await requests(admin)).some((r) => r.rule_name === name), { message: 'a request to block the source of the hit', timeout: 20_000 }).toBe(true)
  } finally {
    if (trapOn) await api(admin, 'PATCH', '/honeypot/traps/ssh', { enabled: false })
    if (lan && !lan.includes(LAN)) {
      const cur = await get<Record<string, unknown>>(admin, '/inventory/settings')
      const back = { ...cur, lan_ranges: lan, scope_confirmed: true }
      delete back.adjusted
      await api(admin, 'PUT', '/inventory/settings', back)
    }
    if (trapOn) await expect.poll(async () => (await hostHoneypot()).unit_state, { timeout: 45_000 }).toBe('inactive')
    for (const id of made.rules.splice(0)) await api(admin, 'DELETE', `/response/rules/${id}`) // the trap rule must not outlive the test
    if (!hpWasOn) await api(admin, 'PATCH', '/modules/honeypot', { enabled: false })
    await admin.dispose()
  }
})

// The emergency stop sets `stopped_at` in the settings; GET and PUT /response/settings keep answering (issues #302, #305, fixed). Resume (POST /response/breaker/reset) clears it, so this
// test always leaves the box usable.
test('after the emergency stop the settings stay readable, and Resume clears the stop (S-RESP-2)', async () => {
  const admin = await as('admin')
  const op = await as('operator')
  try {
    const stop = await api(op, 'POST', '/response/emergency-stop')
    expect(stop.status, JSON.stringify(stop.body)).toBe(200)
    const s = await api<{ stopped_at: string | null; breaker_tripped_at: string | null }>(admin, 'GET', '/response/settings')
    expect(s.status, `GET /response/settings after the stop: ${JSON.stringify(s.body)}`).toBe(200)
    expect(s.body.stopped_at, 'the stop is in the settings').not.toBeNull()
  } finally {
    const back = await api(admin, 'POST', '/response/breaker/reset')
    expect(back.status, `resume: ${JSON.stringify(back.body)}`).toBe(200)
    await admin.dispose(); await op.dispose()
  }
})

// docs/specs/blocklist-format.md §4: the feed is `text/plain; charset=utf-8` (issue #306, fixed).
test('the block list feed is served as text/plain (blocklist-format.md)', async () => {
  const admin = await as('admin')
  try {
    let bl = await get<Blocklist>(admin, '/response/blocklist')
    if (!bl.url) bl = (await api<Blocklist>(admin, 'POST', '/response/blocklist/token')).body
    const r = await fetch(box().base_url + new URL(bl.url, box().base_url).pathname, { signal: AbortSignal.timeout(10_000) })
    expect(r.status, 'the feed answers').toBe(200)
    expect(r.headers.get('content-type')).toBe('text/plain; charset=utf-8')
  } finally { await admin.dispose() }
})
