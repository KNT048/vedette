// Response actions on the real backend (S-RESP-4, D-93, D-94, D-95, D-97; WP-30 slice 9a): the administrator adds an action of her own for each kind of
// connection. The form matrix is that of e2e/qa/wp06-response-actions.spec.ts (the steps and the selectors are the same: the GUI is the same). What
// only a real box shows is new: the connections are real rows (the loopback devices of the box for HTTP, SSH and MCP), the server refuses `{text}` and
// shell characters whatever the page does, a refused action is not stored, what is saved comes back from GET /response/catalog exactly as typed, the
// check before and the read-back are kept and shown to the approver, and an operator or a viewer cannot add, change or delete an action.
// Entity-scoped (parallel project): every connection and action has a unique name. Nothing here turns execution on (response-exec.global.spec.ts does).
import { expect, request, test, type APIRequestContext, type Locator, type Page } from '@playwright/test'
import { api, authFile, box, device, uniq, type DeviceKind } from './box'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })

const BRANDS = /forti|pfsense|cisco|mikrotik|palo ?alto|juniper|ubiquiti|unifi|aruba|sophos|opnsense|checkpoint|sonicwall|huawei|tp-?link|omada/i
const EMPTY = { cli: '', method: '', path: '', body: '', headers: '' }
interface Tpl { cli: string; method: string; path: string; body: string; headers: string; expect?: string }
interface Act { id: string; name: string; builtin: boolean; connection_id: string | null; run: Tpl; rollback: Tpl; verify: Tpl; precheck: Tpl; precheck_refuse: string[]; precheck_expect: string; params: string[]; enabled: boolean; reversible: boolean; device: boolean }
interface Cat { items: Act[]; connections: { id: string; name: string; write_tools: string[]; read_only: boolean }[] }

const KINDS = [
  { value: 'http', tool: 'send_request', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'ssh', tool: 'run_approved_command', fields: { method: false, path: false, headers: false, body: false, cli: true, tool: false } },
  { value: 'netconf-restconf', tool: 'apply_config', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'automation', tool: 'launch_job', fields: { method: true, path: true, headers: true, body: true, cli: false, tool: false } },
  { value: 'mcp-http', tool: 'run_action', fields: { method: false, path: false, headers: false, body: false, cli: false, tool: true } },
]
const as = (role: 'operator' | 'viewer') => request.newContext({ baseURL: box().base_url, storageState: authFile(role) })
const present = async (l: Locator) => (await l.count()) > 0
const catalog = async (page: Page) => { const r = await api<Cat>(page.request, 'GET', '/response/catalog'); expect(r.status).toBe(200); return r.body }

/** One connection of a kind, with its write tool on (or off), made through the API like the Connections page does. The HTTP, SSH and MCP ones
 *  reach the loopback devices of the box; the other two have a private address nothing is sent to (a connection is only dialled when tested or used). */
async function connect(req: APIRequestContext, kind: string, name: string, writeOn: boolean): Promise<string> {
  const k = KINDS.find((x) => x.value === kind)!
  const dev: Partial<Record<string, DeviceKind>> = { http: 'http', ssh: 'ssh', 'mcp-http': 'mcp' }
  const d = dev[kind] ? device(dev[kind]!) : undefined
  const target = d?.target ?? (kind === 'netconf-restconf' ? 'https://192.168.10.2' : 'https://automation.example.test')
  const auth = kind === 'ssh' || kind === 'netconf-restconf' ? 'basic' : 'token'
  const body = {
    name, kind, target, auth_type: auth, secret: d?.secret ?? 'secret-value-9z9z', ...(auth === 'basic' ? { username: d?.username ?? 'ops' } : {}),
    allow: [kind === 'ssh' ? 'uname -a' : `${target}/`], enabled: true,
  }
  const made = await api<{ id: string }>(req, 'POST', '/core/connections', body)
  expect(made.status, `connect ${kind}: ${JSON.stringify(made.body)}`).toBe(201)
  madeConnections.push(made.body.id)
  if (kind === 'mcp-http') { // the tools of an MCP server are found by a test; a write tool starts off, the administrator turns it on
    const tested = await api(req, 'POST', `/core/connections/${made.body.id}/test`)
    expect(tested.status, `test the MCP connection: ${JSON.stringify(tested.body)}`).toBe(200)
  }
  if (writeOn) {
    const on = await api(req, 'PUT', `/core/connections/${made.body.id}`, { ...body, tools: [{ name: k.tool, enabled: true }] })
    expect(on.status, `turn on ${k.tool}: ${JSON.stringify(on.body)}`).toBe(200)
  }
  return made.body.id
}

// A box holds 20 connections at most and every spec of the run shares the box: what these tests made is removed afterwards (the actions first, then the
// connections), so the specs after them still have room.
const madeConnections: string[] = []
test.afterAll(async () => {
  const admin = await request.newContext({ baseURL: box().base_url, storageState: authFile('admin') })
  const cat = (await api<Cat>(admin, 'GET', '/response/catalog')).body
  for (const a of cat.items.filter((x) => !x.builtin && x.connection_id && madeConnections.includes(x.connection_id))) await api(admin, 'DELETE', `/response/catalog/${a.id}`)
  for (const id of madeConnections) await api(admin, 'DELETE', `/core/connections/${id}`)
  await admin.dispose()
})

const openCatalog = async (page: Page) => { await page.goto('/settings/response'); await expect(page.getByRole('heading', { name: 'Action catalog' })).toBeVisible() }

test('the add-an-action form follows the connection kind, a read-only connection is locked with its reason, and {text} and shell characters are refused', async ({ page }) => {
  const errors = collectErrors(page)
  const tag = uniq('ra')
  const names: Record<string, string> = {}
  for (const k of KINDS) { names[k.value] = `${tag} ${k.value}`; await connect(page.request, k.value, names[k.value]!, true) }
  const ro = `${tag} read-only`
  await connect(page.request, 'http', ro, false)

  await openCatalog(page)
  await shot(page, 'real-response-actions', 'catalog')
  await page.getByRole('button', { name: 'Add a custom action' }).click()
  const dlg = page.getByRole('dialog', { name: 'Add a custom action' })
  await expect(dlg).toBeVisible()
  const opts = await dlg.locator('#ca-conn option').evaluateAll((os) => os.map((o) => ({ v: (o as HTMLOptionElement).value, t: o.textContent ?? '', dis: (o as HTMLOptionElement).disabled })))
  const mine = (n: string) => opts.find((o) => o.t.startsWith(n))
  expect(mine(ro)?.dis, 'the connection without a write tool is locked').toBe(true)
  expect(mine(ro)?.t, 'and says why').toMatch(/Read-only: this connection has no write tools/)
  for (const o of opts.filter((x) => x.dis)) expect(o.t, 'every locked option carries its reason').toMatch(/Read-only: this connection has no write tools/)
  // a brand name belongs to data, never to the chrome of the dialog (the option list is the customers' own connection names)
  const chromeOf = () => dlg.evaluate((el) => { const c = el.cloneNode(true) as HTMLElement; c.querySelectorAll('option').forEach((o) => o.remove()); return c.innerText })
  expect(await chromeOf(), 'brand in the empty dialog').not.toMatch(BRANDS)

  for (const k of KINDS) {
    const o = mine(names[k.value]!)
    expect(o, `${k.value}: the connection is listed`).toBeTruthy()
    expect(o!.dis, `${k.value}: a connection with its write tool on can carry an action`).toBe(false)
    await dlg.locator('#ca-conn').selectOption(o!.v)
    const f = k.fields
    expect(await present(dlg.locator('#ca-run-cli')), `${k.value}: command`).toBe(f.cli)
    expect(await present(dlg.locator('#ca-run-method')), `${k.value}: method`).toBe(f.method)
    expect(await present(dlg.locator('#ca-run-path')), `${k.value}: path`).toBe(f.path)
    expect(await present(dlg.locator('#ca-run-headers')), `${k.value}: headers`).toBe(f.headers)
    expect(await present(dlg.locator('#ca-run-body')), `${k.value}: body`).toBe(f.body)
    expect(await present(dlg.locator('#ca-run-tool')), `${k.value}: tool picker`).toBe(f.tool)
    expect(await present(dlg.locator('#ca-vf-method, #ca-vf-cli')), `${k.value}: read-back`).toBe(!f.tool) // an MCP tool cannot be read back (D-95)
    expect(await present(dlg.locator('#ca-pc-refuse')), `${k.value}: check before`).toBe(!f.tool)
    for (const id of ['cli', 'path', 'headers', 'body']) { const el = dlg.locator(`#ca-run-${id}`); if (await el.count()) await expect(el, `${k.value}: ${id} empty`).toHaveValue('') }
    if (f.method) await expect(dlg.locator('#ca-run-method')).toHaveValue('')
    expect(await chromeOf(), `${k.value}: brand text in the dialog`).not.toMatch(BRANDS)
    if (f.tool) expect((await dlg.locator('#ca-run-tool option').allTextContents()).join('|'), 'the write tool of the MCP server is offered').toContain('run_action')
    await shot(page, 'real-response-actions', `kind-${k.value}`)
  }
  const legend = (await dlg.locator('p').allTextContents()).find((x) => /^Use only these placeholders/.test(x)) ?? ''
  for (const p of ['{ip}', '{cidr}', '{domain}', '{port}', '{mac}', '{vlan}', '{interface}', '{id}', '{name}']) expect(legend, `legend lists ${p}`).toContain(p)
  expect(legend.replace(/\{text\} is for messages only/i, ''), 'the legend offers {text} for commands or API calls').not.toContain('{text}')

  // switching the connection clears what was typed
  await dlg.locator('#ca-conn').selectOption(mine(names['http']!)!.v)
  await dlg.locator('#ca-run-path').fill('/api/block')
  await dlg.locator('#ca-run-body').fill('{"ip":"{ip}"}')
  await dlg.locator('#ca-conn').selectOption(mine(names['mcp-http']!)!.v)
  await expect(dlg.locator('#ca-run-path')).toHaveCount(0)
  await dlg.locator('#ca-conn').selectOption(mine(names['http']!)!.v)
  await expect(dlg.locator('#ca-run-path')).toHaveValue('')
  await expect(dlg.locator('#ca-run-body')).toHaveValue('')

  // "start a job on my automation platform for one named host, with a numeric job id": {id} and {name} are typed; {text} is refused by the server
  const act = `${tag} isolate host`
  await dlg.locator('#ca-conn').selectOption(mine(names['automation']!)!.v)
  await dlg.locator('#ca-name').fill(act)
  await dlg.locator('#ca-desc').fill('Starts the isolate job for one host')
  await dlg.locator('#ca-run-method').selectOption('POST')
  await dlg.locator('#ca-run-path').fill('/api/jobs/{id}/launch')
  await dlg.locator('#ca-run-body').fill('{"limit":"{text}"}')
  await dlg.locator('#ca-pc-method').selectOption('GET') // {id} and {name} need a check before (D-95): the form is complete but for {text}
  await dlg.locator('#ca-pc-path').fill('/api/jobs/{id}')
  await dlg.locator('#ca-pc-refuse').fill('locked')
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg.getByRole('alert')).toBeVisible()
  await expect(dlg.getByRole('alert'), 'the refusal names the placeholder').toContainText('{text}')
  await shot(page, 'real-response-actions', 'text-refused')
  expect((await catalog(page)).items.some((a) => a.name === act), '{text} refused: nothing stored').toBe(false)
  await dlg.locator('#ca-run-body').fill('{"limit":"{name}"}; rm')
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg.getByRole('alert')).toBeVisible()
  await expect(dlg.getByRole('alert'), 'the refusal names the shell character').toContainText(/[;|&$`<>()]|shell/i)
  expect((await catalog(page)).items.some((a) => a.name === act), 'a shell character refused: nothing stored').toBe(false)
  await dlg.locator('#ca-run-body').fill('{"limit":"{name}"}')
  await dlg.locator('#ca-rb-method').selectOption('POST')
  await dlg.locator('#ca-rb-path').fill('/api/jobs/{id}/cancel')
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg).toBeHidden()
  await expect(page.getByText(act).first()).toBeVisible()
  const saved = (await catalog(page)).items.find((a) => a.name === act)
  expect(saved, 'the action is in the catalog').toBeTruthy()
  expect(saved).toMatchObject({ builtin: false, connection_id: expect.any(String), device: true, reversible: true })
  expect(saved!.run).toMatchObject({ method: 'POST', path: '/api/jobs/{id}/launch', body: '{"limit":"{name}"}' })
  expect(saved!.rollback).toMatchObject({ method: 'POST', path: '/api/jobs/{id}/cancel' })
  expect([...saved!.params].sort(), 'the placeholders the templates use').toEqual(['id', 'name'])
  await shot(page, 'real-response-actions', 'saved')

  // the way back: Cancel, and a link to Connections
  await page.getByRole('button', { name: 'Add a custom action' }).click()
  await expect(dlg.getByRole('link', { name: /Connections/ })).toBeVisible()
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(dlg).toBeHidden()
  await noVietnamese(page, 'settings/response')
  await expectAccessible(page, 'settings/response')
  noErrors(errors, /status of (4|5)\d\d/)
})

test('an HTTP action with a check before and a read-back is saved as typed, shown to the approver, and the server refuses what the page cannot see', async ({ page }) => {
  const errors = collectErrors(page)
  const tag = uniq('rb')
  const conn = `${tag} firewall`
  const connId = await connect(page.request, 'http', conn, true)
  const name = `${tag} ban an address`

  await openCatalog(page)
  await page.getByRole('button', { name: 'Add a custom action' }).click()
  const dlg = page.getByRole('dialog', { name: 'Add a custom action' })
  await dlg.locator('#ca-conn').selectOption({ label: conn })
  await dlg.locator('#ca-name').fill(name)
  await dlg.locator('#ca-desc').fill('Bans one address on the lab firewall')
  await dlg.locator('#ca-run-method').selectOption('POST')
  await dlg.locator('#ca-run-path').fill('/api/e2e/ban')
  await dlg.locator('#ca-run-body').fill('{"ip":"{ip}"}')
  await dlg.locator('#ca-rb-method').selectOption('POST')
  await dlg.locator('#ca-rb-path').fill('/api/e2e/unban')
  await dlg.locator('#ca-rb-body').fill('{"ip":"{ip}"}')
  await dlg.locator('#ca-vf-method').selectOption('GET')
  await dlg.locator('#ca-vf-path').fill('/api/e2e/bans')
  await dlg.locator('#ca-vf-expect').fill('{ip}')
  await dlg.locator('#ca-pc-method').selectOption('GET')
  await dlg.locator('#ca-pc-path').fill('/api/e2e/status')
  await dlg.locator('#ca-pc-refuse').fill('maintenance')
  await dlg.locator('#ca-pc-expect').fill('ready')
  await shot(page, 'real-response-actions', 'http-form')
  await dlg.getByRole('button', { name: 'Save' }).click()
  await expect(dlg).toBeHidden()

  const a = (await catalog(page)).items.find((x) => x.name === name)
  expect(a, 'saved').toBeTruthy()
  expect(a).toMatchObject({ connection_id: connId, builtin: false, device: true, reversible: true, precheck_refuse: ['maintenance'], precheck_expect: 'ready', params: ['ip'] })
  expect(a!.run).toMatchObject({ method: 'POST', path: '/api/e2e/ban', body: '{"ip":"{ip}"}' })
  expect(a!.rollback).toMatchObject({ method: 'POST', path: '/api/e2e/unban', body: '{"ip":"{ip}"}' })
  expect(a!.verify).toMatchObject({ method: 'GET', path: '/api/e2e/bans', expect: '{ip}' })
  expect(a!.precheck).toMatchObject({ method: 'GET', path: '/api/e2e/status' })
  // the catalog tells the person what the check does
  await expect(page.getByText('Refuses on: maintenance').first()).toBeVisible() // another action of the box may say the same
  await expect(page.getByText('also requires: ready').first()).toBeVisible()
  await page.reload()
  await expect(page.getByText(name).first()).toBeVisible()
  await shot(page, 'real-response-actions', 'http-saved')

  // the server's own rules (D-95, INV-13), whatever the page lets through
  const base = { name: `${tag} api`, description: 'x', connection_id: connId, tool: null, rollback_tool: null, risk: 'medium', enabled: false, ai_may_propose: false,
    run: { ...EMPTY, method: 'POST', path: '/api/e2e/ban', body: '{"ip":"{ip}"}' }, rollback: { ...EMPTY, method: 'POST', path: '/api/e2e/unban', body: '{"ip":"{ip}"}' }, verify: EMPTY }
  const post = (over: object) => api<{ code?: string; message?: string }>(page.request, 'POST', '/response/catalog', { ...base, ...over })
  const refused = async (label: string, over: object) => { const r = await post(over); expect(r.status, `${label}: ${JSON.stringify(r.body)}`).toBe(400); return r }
  const control = await post({}) // the same body, unchanged, is accepted: the refusals below are about their one change
  expect(control.status, `the control body: ${JSON.stringify(control.body)}`).toBe(201)
  await api(page.request, 'DELETE', `/response/catalog/${(control.body as unknown as { id: string }).id}`)
  await refused('{text} in a call', { run: { ...base.run, body: '{"ip":"{text}"}' } })
  await refused('a shell character in a path', { run: { ...base.run, path: '/api/e2e/ban;id' } })
  await refused('a header the sign-in owns', { run: { ...base.run, headers: 'Authorization: Bearer x' } })
  await refused('a port with no check before', { run: { ...base.run, path: '/api/e2e/port/{port}' }, rollback: { ...base.rollback, path: '/api/e2e/unport/{port}' } })
  await refused('an action with no command and no API call', { run: { ...EMPTY } })
  // nothing of that was stored
  expect((await catalog(page)).items.filter((x) => x.name === `${tag} api`)).toEqual([])

  // who may change the catalog: the administrator only; an operator and a viewer read it
  for (const role of ['operator', 'viewer'] as const) {
    const c = await as(role)
    expect((await api(c, 'GET', '/response/catalog')).status, `${role} reads the catalog`).toBe(200)
    expect((await api(c, 'POST', '/response/catalog', { ...base, name: `${tag} ${role}` })).status, `${role} adds an action`).toBe(403)
    expect((await api(c, 'PUT', `/response/catalog/${a!.id}`, { enabled: true })).status, `${role} changes an action`).toBe(403)
    expect((await api(c, 'DELETE', `/response/catalog/${a!.id}`)).status, `${role} deletes an action`).toBe(403)
    await c.dispose()
  }
  expect((await catalog(page)).items.find((x) => x.id === a!.id)?.enabled, 'still off').toBe(false)

  // the action is off until the administrator allows it: the switch of the catalog turns it on and the server remembers
  await openCatalog(page)
  await page.getByRole('switch', { name: `Allow ${name}` }).click()
  await expect.poll(async () => (await catalog(page)).items.find((x) => x.id === a!.id)?.enabled, { message: 'enabled on the box' }).toBe(true)
  await expect(h1(page)).toBeVisible()
  noErrors(errors, /status of (4|5)\d\d/)
})
