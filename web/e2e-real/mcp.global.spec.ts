// Settings -> MCP server on the real backend (S-MCP-1; mcp-server INV-2, INV-3, INV-4, INV-5, INV-8, INV-9, POST-1..3): turn it on, make a token (shown once), read the
// box with a real MCP client over the loopback port, revoke, turn it off. The MCP client is `fetch` in this runner: the box listens on a free loopback port chosen by the harness
// (cmd/vedette/e2ebox_test.go passes -mcp-listen), and the address comes from GET /core/mcp. Global project: the module is box-wide; it is put back as it was.
import { expect, test, type APIRequestContext, type Page } from '@playwright/test'
import { api, authFile, uniq } from './box'
import { as } from './findings-seed'
import { expectAccessible, h1, noErrors, noVietnamese } from './ui'
import { collectErrors, shot } from '../e2e/helpers'

test.use({ storageState: authFile('admin'), actionTimeout: 10_000 })
test.describe.configure({ mode: 'serial' })

interface Tok { id: string; name: string; scopes: string[]; last4: string; last_used: string | null }
interface State { enabled: boolean; listening: boolean; bind: string; port: number; endpoint: string; tokens: Tok[]; tools: { name: string; scope: string }[]; scopes: string[] }

let admin: APIRequestContext
let wasOn = false
const state = async () => (await api<State>(admin, 'GET', '/core/mcp')).body
const toast = (page: Page, re: RegExp | string) => expect(page.locator('[data-sonner-toast]').filter({ hasText: re }).first()).toBeVisible()
const NAME = uniq('mcp-agent')
let token = ''
let endpoint = ''

/** One JSON-RPC call to the box's MCP port, the way an agent does it (2025-06-18, Streamable HTTP, POST only). */
async function rpc(method: string, params: unknown, bearer: string | null, id = 1) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18' }
  if (bearer) headers.Authorization = `Bearer ${bearer}`
  const r = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id, method, params }), signal: AbortSignal.timeout(10_000) })
  const text = await r.text()
  let body: any = null
  try { body = text ? JSON.parse(text) : null } catch { body = text }
  return { status: r.status, www: r.headers.get('www-authenticate'), body }
}
const INIT = { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'e2e', version: '1' } }

test.beforeAll(async () => {
  admin = await as('admin')
  const mods = await api<{ modules: { id: string; enabled: boolean }[] }>(admin, 'GET', '/modules')
  wasOn = !!mods.body.modules.find((m) => m.id === 'mcp-server')?.enabled
  if (wasOn) { // a box where it is on already: start from off, so the first test sees the switch
    expect((await api(admin, 'PATCH', '/modules/mcp-server', { enabled: false })).status).toBe(200)
  }
})
test.afterAll(async () => {
  try {
    const t = (await state().catch(() => null))?.tokens ?? []
    for (const x of t.filter((x) => x.name === NAME)) await api(admin, 'DELETE', `/core/mcp/tokens/${x.id}`)
    expect((await api(admin, 'PATCH', '/modules/mcp-server', { enabled: wasOn })).status, 'the module is back as it was').toBe(200)
  } finally { await admin.dispose() }
})

test('off: the page says so, the API route is 404, the port is closed; the switch turns it on and the port opens on loopback (POST-1, SYS-5)', async ({ page }) => {
  const errors = collectErrors(page)
  const gone = await api<{ error: { code: string } }>(admin, 'GET', '/core/mcp')
  expect(gone, 'GET /core/mcp while off').toMatchObject({ status: 404, body: { error: { code: 'not_found' } } })
  await page.goto('/settings/mcp')
  await expect(h1(page)).toHaveText('MCP server is off')
  await expect(page.getByText('No port is open. Turn it on to create tokens and connect.')).toBeVisible()
  await expect(page.getByRole('button', { name: 'Create token' })).toHaveCount(0)
  await shot(page, 'real', 'mcp-off')
  await page.getByRole('switch', { name: 'Turn on MCP server' }).click()
  await toast(page, 'MCP server is on.')
  await expect(h1(page)).toHaveText('MCP server is on, read-only, 0 tokens')
  await expect(page.getByText('Listening on this machine only (localhost).')).toBeVisible()
  await expect.poll(async () => (await state()).listening, { message: 'the port opens', timeout: 15_000 }).toBe(true)
  const s = await state()
  expect(s).toMatchObject({ enabled: true, bind: '127.0.0.1', tokens: [] })
  expect(s.tools.map((t) => t.name), 'seven fixed read tools (INV-1)').toEqual(['list_assets', 'get_asset', 'list_findings', 'get_finding', 'lookup_cve', 'lookup_ioc', 'hot_vulnerabilities'])
  expect(s.endpoint).toBe(`http://127.0.0.1:${s.port}/mcp`)
  endpoint = s.endpoint
  await expect(page.getByText(s.endpoint, { exact: true })).toBeVisible()
  await expect(page.getByText('localhost only, not open to the network')).toBeVisible()
  await expectAccessible(page, 'settings mcp on')
  await noVietnamese(page, 'settings mcp')
  noErrors(errors)
})

test('a request with no token or a made-up one is 401 with WWW-Authenticate (INV-4)', async () => {
  for (const bearer of [null, 'vmcp_00000000000000000000000000000000', 'not-a-token']) {
    const r = await rpc('initialize', INIT, bearer)
    expect(r.status, `bearer ${bearer}`).toBe(401)
    expect(r.www, 'WWW-Authenticate').toMatch(/^Bearer/i)
  }
})

test('create a token: the form refuses an empty name and no scope; the token is shown once, the table keeps only the last 4 characters (INV-3, POST-2, INV-8)', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/settings/mcp')
  await expect(h1(page)).toContainText('MCP server is on')
  const create = page.getByRole('button', { name: 'Create token' })
  await create.click()
  await expect(page.getByText('Name the token so you know which one to revoke later.')).toBeVisible()
  await page.getByLabel('Token name').fill(NAME)
  for (const s of ['Devices', 'Findings', 'Vulnerability feeds']) await page.getByLabel(s, { exact: true }).uncheck()
  await create.click()
  await expect(page.getByText('Pick at least one scope.')).toBeVisible()
  expect((await state()).tokens, 'a refused form made nothing').toEqual([])
  await page.getByLabel('Devices', { exact: true }).check()
  await create.click()
  const dlg = page.getByRole('dialog', { name: `Token ${NAME} created` })
  await expect(dlg).toBeVisible()
  token = (await dlg.getByRole('code').textContent())!.trim()
  expect(token, 'vmcp_ and 128 bits of hex').toMatch(/^vmcp_[0-9a-f]{32}$/)
  await shot(page, 'real', 'mcp-token-created')
  await dlg.getByRole('button', { name: 'I have copied it' }).click()
  await expect(dlg).toBeHidden()

  const row = page.getByRole('table', { name: 'Read-only tokens' }).getByRole('row').filter({ hasText: NAME })
  await expect(row).toContainText('Devices')
  await expect(row).toContainText(`…${token.slice(-4)}`)
  await expect(row).toContainText('Never used')
  await page.reload()
  expect(await page.locator('body').innerText(), 'the page never shows the token again').not.toContain(token.slice(5))
  const s = await state()
  expect(JSON.stringify(s), 'GET /core/mcp has no token').not.toContain(token.slice(5))
  expect(s.tokens).toMatchObject([{ name: NAME, scopes: ['assets'], last4: token.slice(-4), last_used: null }])
  const audit = (await api<{ items: { action: string; target: string; detail?: string }[] }>(admin, 'GET', `/core/audit?q=${encodeURIComponent(NAME)}`)).body.items
  const made = audit.find((a) => a.action === 'mcp.token_create')
  expect(made, 'the audit log holds the creation').toMatchObject({ target: NAME })
  expect(JSON.stringify(audit), 'the audit log has no token').not.toContain(token.slice(5))
  noErrors(errors)
})

test('a real MCP client with the token: initialize, tools/list shows only its scope, a tool call returns devices, an out-of-scope call is refused; the call is audited and "last used" moves (INV-1, INV-2, INV-8)', async ({ page }) => {
  const init = await rpc('initialize', INIT, token)
  expect(init.status, JSON.stringify(init.body)).toBe(200)
  expect(init.body.result.serverInfo.name, 'the server names itself').toBeTruthy()
  const list = await rpc('tools/list', {}, token, 2)
  expect(list.status).toBe(200)
  const tools = (list.body.result.tools as { name: string; annotations?: { readOnlyHint?: boolean } }[])
  expect(tools.map((t) => t.name), 'only the tools of the scope "assets"').toEqual(['list_assets', 'get_asset'])
  for (const t of tools) expect(t.annotations?.readOnlyHint, `${t.name} is read-only`).toBe(true)

  const call = await rpc('tools/call', { name: 'list_assets' }, token, 3)
  expect(call.status).toBe(200)
  expect(call.body.result.isError, JSON.stringify(call.body)).toBeFalsy()
  const seen = JSON.stringify(call.body.result.structuredContent)
  const inv = (await api<{ items: { ip: string | null; mac: string | null; is_box: boolean }[] }>(admin, 'GET', '/inventory/devices')).body.items
  expect(inv.length, 'the box has devices to read').toBeGreaterThan(0)
  const got = call.body.result.structuredContent as { items: unknown[] }
  expect(got.items.length, 'list_assets is not empty').toBeGreaterThan(0)
  for (const d of inv) if (d.mac) expect(seen.toLowerCase(), 'a MAC never reaches the agent (INV-7)').not.toContain(d.mac.toLowerCase())

  const out = await rpc('tools/call', { name: 'list_findings', arguments: { status: 'all' } }, token, 4)
  expect(out.body.error?.code ?? out.body.result?.isError, `out of scope: ${JSON.stringify(out.body)}`).toBeTruthy()
  expect(out.body.error?.code, 'JSON-RPC invalid params, no partial answer').toBe(-32602)

  const audit = (await api<{ items: { action: string; target: string; detail?: string }[] }>(admin, 'GET', `/core/audit?q=${encodeURIComponent(NAME)}`)).body.items.filter((a) => a.action === 'mcp.call')
  expect(audit.length, 'one audit row per tools/call that ran').toBeGreaterThanOrEqual(1)
  expect(JSON.stringify(audit), 'the arguments are not logged').not.toContain('"status":"all"')
  expect((await state()).tokens[0]!.last_used, 'last used moved').not.toBeNull()
  await page.goto('/settings/mcp')
  const row = page.getByRole('table', { name: 'Read-only tokens' }).getByRole('row').filter({ hasText: NAME })
  await expect(row).not.toContainText('Never used')
})

test('revoke: Cancel keeps the token; Revoke removes it, and the next request with it is 401 (INV-4)', async ({ page }) => {
  const errors = collectErrors(page)
  await page.goto('/settings/mcp')
  await page.getByRole('button', { name: `Revoke token ${NAME}` }).click()
  const dlg = page.getByRole('dialog', { name: `Revoke token ${NAME}?` })
  await expect(dlg).toContainText('The tool that uses it loses access at once.')
  await shot(page, 'real', 'mcp-revoke-confirm')
  await dlg.getByRole('button', { name: 'Cancel' }).click()
  await expect(dlg).toBeHidden()
  expect((await rpc('tools/list', {}, token, 5)).status, 'still works after Cancel').toBe(200)
  await page.getByRole('button', { name: `Revoke token ${NAME}` }).click()
  await dlg.getByRole('button', { name: 'Revoke', exact: true }).click()
  await toast(page, `Token ${NAME} revoked.`)
  await expect(page.getByText('No tokens yet. Create one so an outside tool can connect.')).toBeVisible()
  const after = await rpc('tools/list', {}, token, 6)
  expect(after.status, 'revoked token').toBe(401)
  expect(after.www).toMatch(/^Bearer/i)
  expect((await state()).tokens).toEqual([])
  const audit = (await api<{ items: { action: string }[] }>(admin, 'GET', `/core/audit?q=${encodeURIComponent(NAME)}`)).body.items
  expect(audit.some((a) => a.action === 'mcp.token_revoke'), 'the audit log holds the revoke').toBe(true)
  noErrors(errors)
})

test('only an administrator reads or changes it; turned off, the port closes and the route is gone again (POST-1)', async ({ browser }) => {
  for (const role of ['operator', 'viewer'] as const) {
    const ctx = await browser.newContext({ storageState: authFile(role) })
    expect((await api(ctx.request, 'GET', '/core/mcp')).status, `${role} GET /core/mcp`).toBe(403)
    expect((await api(ctx.request, 'POST', '/core/mcp/tokens', { name: 'x', scopes: ['assets'] })).status, `${role} POST token`).toBe(403)
    await ctx.close()
  }
  expect((await api(admin, 'PATCH', '/modules/mcp-server', { enabled: false })).status).toBe(200)
  await expect.poll(async () => rpc('initialize', INIT, token).then((r) => r.status).catch(() => 'closed'), { message: 'the port is closed', timeout: 15_000 }).toBe('closed')
  expect((await api(admin, 'GET', '/core/mcp')).status).toBe(404)
})
